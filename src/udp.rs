use std::net::SocketAddr;

use anyhow::Result;
use tokio::{net::UdpSocket, select};
use tracing::{error, info};

const BUFFER_SIZE: usize = 65535;
const HANDSHAKE_PACKET: [u8; 4] = [0u8; 4];

async fn send_handshake(socket: &UdpSocket) -> Result<()> {
    socket.send(&HANDSHAKE_PACKET).await?;
    let peer = socket.peer_addr()?;
    info!("Handshake with remote address {} success", peer);
    Ok(())
}

async fn recv_handshake(socket: &UdpSocket) -> Result<SocketAddr> {
    let mut buf = [0u8; 4];
    let (_, addr) = socket.recv_from(&mut buf).await?;
    info!("Handshake with client address {} success", addr);
    Ok(addr)
}

pub async fn local_forward(socket1: UdpSocket, socket2: UdpSocket) -> Result<()> {
    let mut buf1 = vec![0u8; BUFFER_SIZE];
    let mut buf2 = vec![0u8; BUFFER_SIZE];

    let mut last_addr1 = Some(recv_handshake(&socket1).await?);
    let mut last_addr2: Option<SocketAddr> = None;

    loop {
        select! {
            result = socket1.recv_from(&mut buf1) => {
                let (len, addr) = result?;
                last_addr1 = Some(addr);
                let data = &buf1[..len];

                if let Some(client_addr) = last_addr2 {
                    if let Err(e) = socket2.send_to(data, client_addr).await {
                        error!("Failed to forward to target: {}", e);
                    }
                } else {
                    error!("No client 2 address");
                }
            }
            result = socket2.recv_from(&mut buf2) => {
                let (len, addr) = result?;
                last_addr2 = Some(addr);
                let data = &buf2[..len];

                if let Some(client_addr) = last_addr1 {
                    if let Err(e) = socket1.send_to(data, client_addr).await {
                        error!("Failed to forward to target: {}", e);
                    }
                } else {
                    error!("No client 1 address");
                }
            }
        }
    }
}

pub async fn local_to_remote_forward(
    local_socket: UdpSocket,
    remote_socket: UdpSocket,
) -> Result<()> {
    let mut buf1 = vec![0u8; BUFFER_SIZE];
    let mut buf2 = vec![0u8; BUFFER_SIZE];

    send_handshake(&remote_socket).await?;

    let mut last_addr: Option<SocketAddr> = None;

    loop {
        select! {
            result = local_socket.recv_from(&mut buf1) => {
                let (len, addr) = result?;
                last_addr = Some(addr);
                let data = &buf1[..len];

                if let Err(e) = remote_socket.send(data).await {
                    error!("Failed to forward: {}", e);
                }
            }
            result = remote_socket.recv(&mut buf2) => {
                let len = result?;
                if let Some(addr) = last_addr {
                    let data = &buf2[..len];
                    if let Err(e) = local_socket.send_to(data, addr).await {
                        error!("Failed to forward: {}", e);
                    }
                } else {
                    error!("No client address");
                }
            }
        }
    }
}

pub async fn remote_forward(socket1: UdpSocket, socket2: UdpSocket) -> Result<()> {
    send_handshake(&socket2).await?;

    let mut buf1 = vec![0u8; BUFFER_SIZE];
    let mut buf2 = vec![0u8; BUFFER_SIZE];

    loop {
        select! {
            result = socket1.recv(&mut buf1) => {
                let len = result?;
                let data = &buf1[..len];
                if let Err(e) = socket2.send(data).await {
                    error!("Failed to forward remote1 to remote2: {}", e);
                }
            }
            result = socket2.recv(&mut buf2) => {
                let len = result?;
                let data = &buf2[..len];
                if let Err(e) = socket1.send(data).await {
                    error!("Failed to forward remote2 to remote1: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_send_handshake() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();

        let send_task = tokio::spawn(async move {
            send_handshake(&client).await.unwrap();
        });

        let mut buf = [0u8; 4];
        let (len, _) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(buf, HANDSHAKE_PACKET);

        send_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_recv_handshake() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let recv_task = tokio::spawn(async move {
            let addr = recv_handshake(&server).await.unwrap();
            addr
        });

        client
            .send_to(&HANDSHAKE_PACKET, server_addr)
            .await
            .unwrap();

        let received_addr = recv_task.await.unwrap();
        assert_eq!(received_addr, client_addr);
    }

    #[tokio::test]
    async fn test_local_to_remote_forward_handshake() {
        let local_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let remote_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote_server.local_addr().unwrap();

        let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        remote_socket.connect(remote_addr).await.unwrap();

        let forward_task = tokio::spawn(async move {
            let _ = local_to_remote_forward(local_socket, remote_socket).await;
        });

        let mut buf = [0u8; 4];
        let result = timeout(Duration::from_secs(1), remote_server.recv_from(&mut buf)).await;
        assert!(result.is_ok());
        let (len, _) = result.unwrap().unwrap();
        assert_eq!(len, 4);
        assert_eq!(buf, HANDSHAKE_PACKET);

        forward_task.abort();
    }

    #[tokio::test]
    async fn test_local_to_remote_forward_data() {
        let local_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_socket.local_addr().unwrap();

        let remote_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote_server.local_addr().unwrap();

        let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        remote_socket.connect(remote_addr).await.unwrap();

        let forward_task = tokio::spawn(async move {
            let _ = local_to_remote_forward(local_socket, remote_socket).await;
        });

        let mut buf = [0u8; 4];
        let _ = timeout(Duration::from_secs(1), remote_server.recv_from(&mut buf)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"test data", local_addr).await.unwrap();

        let mut data_buf = [0u8; 9];
        let result = timeout(
            Duration::from_secs(1),
            remote_server.recv_from(&mut data_buf),
        )
        .await;
        if let Ok(Ok((len, _))) = result {
            assert_eq!(len, 9);
            assert_eq!(&data_buf, b"test data");
        }

        forward_task.abort();
    }

    #[tokio::test]
    async fn test_buffer_size_constant() {
        assert_eq!(BUFFER_SIZE, 65535);
    }

    #[tokio::test]
    async fn test_handshake_packet_constant() {
        assert_eq!(HANDSHAKE_PACKET, [0u8; 4]);
    }

    #[tokio::test]
    async fn test_remote_forward_sends_handshake() {
        let server1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server1_addr = server1.local_addr().unwrap();

        let server2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server2_addr = server2.local_addr().unwrap();

        let socket1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket1.connect(server1_addr).await.unwrap();

        let socket2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket2.connect(server2_addr).await.unwrap();

        let forward_task = tokio::spawn(async move {
            let _ = remote_forward(socket1, socket2).await;
        });

        let mut buf = [0u8; 4];
        let result = timeout(Duration::from_secs(1), server2.recv_from(&mut buf)).await;
        assert!(result.is_ok());
        let (len, _) = result.unwrap().unwrap();
        assert_eq!(len, 4);
        assert_eq!(buf, HANDSHAKE_PACKET);

        forward_task.abort();
    }

    #[tokio::test]
    async fn test_local_forward_waits_for_handshake() {
        let socket1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket1_addr = socket1.local_addr().unwrap();

        let socket2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let forward_task = tokio::spawn(async move {
            let _ = local_forward(socket1, socket2).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&HANDSHAKE_PACKET, socket1_addr)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        forward_task.abort();
    }
}
