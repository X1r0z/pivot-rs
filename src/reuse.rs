use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time,
};
use tracing::{error, info, warn};

use crate::tcp::{self, ForwardStream};

pub struct Reuse {
    local: SocketAddr,
    remote: SocketAddr,
    fallback: Option<SocketAddr>,
    external: std::net::IpAddr,
    timeout: Option<Duration>,
}

impl Reuse {
    pub fn new(
        local: String,
        remote: String,
        fallback: Option<String>,
        external: String,
        timeout: Option<u64>,
    ) -> Result<Self> {
        Ok(Self {
            local: local
                .parse()
                .map_err(|e| anyhow!("Invalid local address '{}': {}", local, e))?,
            remote: remote
                .parse()
                .map_err(|e| anyhow!("Invalid remote address '{}': {}", remote, e))?,
            fallback: fallback
                .map(|f| {
                    f.parse()
                        .map_err(|e| anyhow!("Invalid fallback address '{}': {}", f, e))
                })
                .transpose()?,
            external: external
                .parse()
                .map_err(|e| anyhow!("Invalid external address '{}': {}", external, e))?,
            timeout: timeout.map(Duration::from_secs),
        })
    }

    pub async fn start(&self) -> Result<()> {
        self.reuse_tcp().await
    }

    async fn reuse_tcp(&self) -> Result<()> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;

        #[cfg(target_family = "unix")]
        socket.set_reuse_port(true)?;

        socket.set_nonblocking(true)?;
        socket.bind(&self.local.into())?;
        socket.listen(128)?;

        let (tx, mut rx) = mpsc::channel(1);

        let local_addr = self.local;
        let timeout = self.timeout;

        let reuse_future = async move {
            let listener = TcpListener::from_std(socket.into())
                .map_err(|e| anyhow!("Failed to create listener: {}", e))?;
            info!("Bind to {} success", local_addr);

            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("Accepted connection from: {}", addr);
                        if tx.send((stream, addr)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        continue;
                    }
                }
            }

            Ok::<(), anyhow::Error>(())
        };

        match timeout {
            Some(duration) => {
                tokio::spawn(async move {
                    let _ = time::timeout(duration, reuse_future).await;
                });
            }
            None => {
                tokio::spawn(async move {
                    if let Err(e) = reuse_future.await {
                        error!("Reuse listener error: {}", e);
                    }
                });
            }
        }

        let mut alive_tasks = Vec::new();

        while let Some((client_stream, client_addr)) = rx.recv().await {
            let remote_addr = if client_addr.ip() == self.external {
                info!("Redirecting connection to {}", self.remote);
                self.remote
            } else {
                match self.fallback {
                    Some(fallback) => {
                        warn!("Invalid external IP, fallback to {}", fallback);
                        fallback
                    }
                    None => {
                        warn!("Invalid external IP, abort the connection");
                        continue;
                    }
                }
            };

            let remote_stream = match TcpStream::connect(remote_addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to connect to {}: {}", remote_addr, e);
                    continue;
                }
            };
            info!("Connect to {} success", remote_addr);

            let local_addr = self.local;
            let task = tokio::spawn(async move {
                let client_stream = ForwardStream::Tcp(client_stream);
                let remote_stream = ForwardStream::Tcp(remote_stream);

                info!("Open pipe: {} <=> {}", client_addr, local_addr);
                if let Err(e) = tcp::forward(client_stream, remote_stream).await {
                    error!("Failed to forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", client_addr, local_addr);
            });

            alive_tasks.push(task);
        }

        if let Some(duration) = self.timeout {
            info!(
                "Stop accepting new connections after {:?} elapsed, wait for alive tasks",
                duration
            );
        }

        for task in alive_tasks {
            if let Err(e) = task.await {
                error!("Forwarding task failed: {}", e);
            }
        }

        Ok(())
    }
}
