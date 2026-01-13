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
