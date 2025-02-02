use anyhow::Result;
use tokio::{net::UdpSocket, select};
use tracing::{error, info};

const BUFFER_SIZE: usize = 65535;

pub async fn local_forward(socket1: UdpSocket, socket2: UdpSocket) -> Result<()> {
    let mut buf1 = vec![0u8; BUFFER_SIZE];
    let mut buf2 = vec![0u8; BUFFER_SIZE];

    #[allow(unused_assignments)]
    let mut last_addr1 = None;
    let mut last_addr2 = None;

    // handshake to keep the client address
    match socket1.recv_from(&mut [0u8; 4]).await {
        Ok((_, addr)) => {
            last_addr1 = Some(addr);
            info!("Handshake with client address {} success", addr)
        }
        Err(e) => {
            error!("Failed to handshake with client address: {}", e);
            return Err(e.into());
        }
    }

    loop {
        select! {
            Ok((len, addr)) = socket1.recv_from(&mut buf1) => {
                last_addr1 = Some(addr);
                let data = &buf1[..len];

                match last_addr2 {
                    Some(client_addr) => {
                        if let Err(e) = socket2.send_to(data, client_addr).await {
                            error!("Failed to forward to target: {}", e);
                        }
                    }
                    None => error!("No client 2 address"),
                }
            }
            Ok((len, addr)) = socket2.recv_from(&mut buf2) => {
                last_addr2 = Some(addr);
                let data = &buf2[..len];

                match last_addr1 {
                    Some(client_addr) => {
                        if let Err(e) = socket1.send_to(data, client_addr).await {
                            error!("Failed to forward to target: {}", e);
                        }
                    }
                    None => error!("No client 1 address"),
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

    // handshake to keep the client address
    // the unused packet may be sent to the real udp service (which will be forwarded)
    if let Err(e) = remote_socket.send(&[0u8; 4]).await {
        error!("Failed to handshake with remote address: {}", e);
        return Err(e.into());
    } else {
        info!(
            "Handshake with remote address {} success",
            remote_socket.peer_addr().unwrap()
        );
    }

    let mut last_addr = None;

    loop {
        select! {
            Ok((len, addr)) = local_socket.recv_from(&mut buf1) => {
                last_addr = Some(addr);
                let data = &buf1[..len];

                if let Err(e) = remote_socket.send(data).await {
                    error!("Failed to forward: {}", e);
                }
            }
            Ok(len) = remote_socket.recv(&mut buf2) => {
                match last_addr {
                    Some(addr) => {
                        let data = &buf2[..len];

                        if let Err(e) = local_socket.send_to(data, addr).await {
                            error!("Failed to forward: {}", e);
                        }
                    },
                    None => error!("No client address"),
                }
            }
        }
    }
}

pub async fn remote_forward(socket1: UdpSocket, socket2: UdpSocket) -> Result<()> {
    // handshake to keep the client address
    if let Err(e) = socket2.send(&[0u8; 4]).await {
        error!("Failed to handshake with remote address: {}", e);
        return Err(e.into());
    } else {
        info!(
            "Handshake with remote address {} success",
            socket2.peer_addr().unwrap()
        );
    }

    let mut buf1 = vec![0u8; BUFFER_SIZE];
    let mut buf2 = vec![0u8; BUFFER_SIZE];

    loop {
        select! {
            Ok(len) = socket1.recv(&mut buf1) => {
                let data = &buf1[..len];
                if let Err(e) = socket2.send(data).await {
                    error!("Failed to forward remote1 to remote2: {}", e);
                }
            }
            Ok(len) = socket2.recv(&mut buf2) => {
                let data = &buf2[..len];
                if let Err(e) = socket1.send(data).await {
                    error!("Failed to forward remote2 to remote1: {}", e);
                }
            }
        }
    }
}
