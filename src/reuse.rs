use std::{io::Result, net::SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::tcp;

pub struct Reuse {
    local_addr: String,
    remote_addr: String,
    fallback_addr: String,
    external_ip: String,
}

impl Reuse {
    pub fn new(
        local_addr: String,
        remote_addr: String,
        fallback_addr: String,
        external_ip: String,
    ) -> Self {
        Self {
            local_addr,
            remote_addr,
            fallback_addr,
            external_ip,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let local_addr: SocketAddr = self.local_addr.parse().unwrap();

        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&local_addr.into())?;
        socket.listen(128)?;

        let listener = TcpListener::from_std(socket.into())?;
        info!("Bind to {} success", self.local_addr);

        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            info!("Accepted connection from: {}", client_addr);

            let server_addr = if client_addr.ip().to_string() == self.external_ip {
                info!("Redirecting connection to {}", &self.remote_addr);
                &self.remote_addr
            } else {
                warn!("Invalid external IP, fallback to {}", &self.fallback_addr);
                &self.fallback_addr
            };

            let server_stream = TcpStream::connect(&server_addr).await?;
            info!("Connect to {} success", server_addr);

            tokio::spawn(async move {
                let client_stream = tcp::NetStream::Tcp(client_stream);
                let remote_stream = tcp::NetStream::Tcp(server_stream);

                info!("Open pipe: {} <=> {}", client_addr, local_addr);
                if let Err(e) = tcp::handle_forward(client_stream, remote_stream).await {
                    error!("Failed to forward: {}", e)
                }
                info!("Close pipe: {} <=> {}", client_addr, local_addr);
            });
        }
    }
}
