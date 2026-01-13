use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::{
    join,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info};

#[cfg(target_family = "unix")]
use tokio::net::UnixStream;

use crate::{
    crypto,
    tcp::{self, ForwardStream},
    udp,
    util::Endpoint,
    Protocol,
};

pub struct Forward {
    locals: Vec<Endpoint>,
    remotes: Vec<Endpoint>,
    #[cfg(target_family = "unix")]
    socket: Option<String>,
    protocol: Protocol,
    connections: usize,
}

impl Forward {
    pub fn new(
        locals: Vec<Endpoint>,
        remotes: Vec<Endpoint>,
        #[cfg(target_family = "unix")] socket: Option<String>,
        protocol: Protocol,
        connections: usize,
    ) -> Self {
        Self {
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            socket,
            protocol,
            connections,
        }
    }

    pub async fn start(&self) -> Result<()> {
        #[cfg(target_family = "unix")]
        match (self.locals.len(), self.remotes.len(), &self.socket) {
            (2, 0, None) => self.local_to_local().await?,
            (1, 1, None) => self.local_to_remote().await?,
            (0, 2, None) => self.remote_to_remote().await?,
            (1, 0, Some(_)) => self.socket_to_local_tcp().await?,
            (0, 1, Some(_)) => self.socket_to_remote_tcp().await?,
            _ => return Err(anyhow!("Invalid forward parameters")),
        }

        #[cfg(target_family = "windows")]
        match (self.locals.len(), self.remotes.len()) {
            (2, 0) => self.local_to_local().await?,
            (1, 1) => self.local_to_remote().await?,
            (0, 2) => self.remote_to_remote().await?,
            _ => return Err(anyhow!("Invalid forward parameters")),
        }

        Ok(())
    }

    async fn local_to_local(&self) -> Result<()> {
        match self.protocol {
            Protocol::Tcp => self.local_to_local_tcp().await,
            Protocol::Udp => self.local_to_local_udp().await,
        }
    }

    async fn local_to_remote(&self) -> Result<()> {
        match self.protocol {
            Protocol::Tcp => self.local_to_remote_tcp().await,
            Protocol::Udp => self.local_to_remote_udp().await,
        }
    }

    async fn remote_to_remote(&self) -> Result<()> {
        match self.protocol {
            Protocol::Tcp => self.remote_to_remote_tcp().await,
            Protocol::Udp => self.remote_to_remote_udp().await,
        }
    }

    async fn local_to_local_tcp(&self) -> Result<()> {
        let ep1 = &self.locals[0];
        let ep2 = &self.locals[1];

        let listener1 = bind_tcp(&ep1.addr).await?;
        let listener2 = bind_tcp(&ep2.addr).await?;

        let acceptor1 = Arc::new(make_tls_acceptor(ep1)?);
        let acceptor2 = Arc::new(make_tls_acceptor(ep2)?);

        loop {
            let (r1, r2) = join!(listener1.accept(), listener2.accept());

            let (stream1, addr1) = r1?;
            info!("Accept connection from {}", addr1);

            let (stream2, addr2) = r2?;
            info!("Accept connection from {}", addr2);

            let acceptor1 = Arc::clone(&acceptor1);
            let acceptor2 = Arc::clone(&acceptor2);

            tokio::spawn(async move {
                let (stream1, stream2) = match (
                    ForwardStream::server(stream1, acceptor1).await,
                    ForwardStream::server(stream2, acceptor2).await,
                ) {
                    (Ok(s1), Ok(s2)) => (s1, s2),
                    (Err(e), _) | (_, Err(e)) => {
                        error!("TLS accept failed: {}", e);
                        return;
                    }
                };

                info!("Open pipe: {} <=> {}", addr1, addr2);
                if let Err(e) = tcp::forward(stream1, stream2).await {
                    error!("Failed to forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", addr1, addr2);
            });
        }
    }

    async fn local_to_remote_tcp(&self) -> Result<()> {
        let local_ep = &self.locals[0];
        let remote_ep = &self.remotes[0];

        let listener = bind_tcp(&local_ep.addr).await?;

        let acceptor = Arc::new(make_tls_acceptor(local_ep)?);
        let connector = Arc::new(make_tls_connector(remote_ep));
        let remote_addr = remote_ep.addr.clone();

        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            info!("Accept connection from {}", client_addr);

            let remote_stream = TcpStream::connect(&remote_addr).await?;
            let peer_addr = remote_stream.peer_addr()?;
            info!("Connect to {} success", peer_addr);

            let acceptor = Arc::clone(&acceptor);
            let connector = Arc::clone(&connector);

            tokio::spawn(async move {
                let (client_stream, remote_stream) = match (
                    ForwardStream::server(client_stream, acceptor).await,
                    ForwardStream::client(remote_stream, connector).await,
                ) {
                    (Ok(s1), Ok(s2)) => (s1, s2),
                    (Err(e), _) | (_, Err(e)) => {
                        error!("TLS handshake failed: {}", e);
                        return;
                    }
                };

                info!("Open pipe: {} <=> {}", client_addr, peer_addr);
                if let Err(e) = tcp::forward(client_stream, remote_stream).await {
                    error!("Failed to forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", client_addr, peer_addr);
            });
        }
    }

    async fn remote_to_remote_tcp(&self) -> Result<()> {
        let ep1 = &self.remotes[0];
        let ep2 = &self.remotes[1];

        let connector1 = Arc::new(make_tls_connector(ep1));
        let connector2 = Arc::new(make_tls_connector(ep2));
        let addr1 = ep1.addr.clone();
        let addr2 = ep2.addr.clone();

        let semaphore = Arc::new(Semaphore::new(self.connections));

        loop {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| anyhow!("Semaphore closed: {}", e))?;

            let (r1, r2) = join!(TcpStream::connect(&addr1), TcpStream::connect(&addr2));

            let stream1 = r1?;
            let peer1 = stream1.peer_addr()?;
            info!("Connect to {} success", peer1);

            let stream2 = r2?;
            let peer2 = stream2.peer_addr()?;
            info!("Connect to {} success", peer2);

            let connector1 = Arc::clone(&connector1);
            let connector2 = Arc::clone(&connector2);

            tokio::spawn(async move {
                let _permit = permit;

                let (stream1, stream2) = match (
                    ForwardStream::client(stream1, connector1).await,
                    ForwardStream::client(stream2, connector2).await,
                ) {
                    (Ok(s1), Ok(s2)) => (s1, s2),
                    (Err(e), _) | (_, Err(e)) => {
                        error!("TLS connect failed: {}", e);
                        return;
                    }
                };

                info!("Open pipe: {} <=> {}", peer1, peer2);
                if let Err(e) = tcp::forward(stream1, stream2).await {
                    error!("Failed to forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", peer1, peer2);
            });
        }
    }

    #[cfg(target_family = "unix")]
    async fn socket_to_local_tcp(&self) -> Result<()> {
        let ep = &self.locals[0];
        let unix_path = self
            .socket
            .as_ref()
            .ok_or_else(|| anyhow!("Unix socket path is required"))?
            .clone();

        let listener = bind_tcp(&ep.addr).await?;
        let acceptor = Arc::new(make_tls_acceptor(ep)?);

        loop {
            let (tcp_stream, client_addr) = listener.accept().await?;
            info!("Accept connection from {}", client_addr);

            let unix_stream = UnixStream::connect(&unix_path).await?;
            info!("Connect to {} success", unix_path);

            let acceptor = Arc::clone(&acceptor);
            let unix_path = unix_path.clone();

            tokio::spawn(async move {
                let tcp_stream = match ForwardStream::server(tcp_stream, acceptor).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("TLS accept failed: {}", e);
                        return;
                    }
                };
                let unix_stream = ForwardStream::Unix(unix_stream);

                info!("Open pipe: {} <=> {}", unix_path, client_addr);
                if let Err(e) = tcp::forward(tcp_stream, unix_stream).await {
                    error!("Failed to forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", unix_path, client_addr);
            });
        }
    }

    #[cfg(target_family = "unix")]
    async fn socket_to_remote_tcp(&self) -> Result<()> {
        let ep = &self.remotes[0];
        let unix_path = self
            .socket
            .as_ref()
            .ok_or_else(|| anyhow!("Unix socket path is required"))?
            .clone();

        let connector = Arc::new(make_tls_connector(ep));
        let remote_addr = ep.addr.clone();

        let semaphore = Arc::new(Semaphore::new(self.connections));

        loop {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| anyhow!("Semaphore closed: {}", e))?;

            let (r1, r2) = join!(
                UnixStream::connect(&unix_path),
                TcpStream::connect(&remote_addr)
            );

            let unix_stream = r1?;
            info!("Connect to {} success", unix_path);

            let tcp_stream = r2?;
            let peer_addr = tcp_stream.peer_addr()?;
            info!("Connect to {} success", peer_addr);

            let connector = Arc::clone(&connector);
            let unix_path = unix_path.clone();

            tokio::spawn(async move {
                let _permit = permit;

                let unix_stream = ForwardStream::Unix(unix_stream);
                let tcp_stream = match ForwardStream::client(tcp_stream, connector).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("TLS connect failed: {}", e);
                        return;
                    }
                };

                info!("Open pipe: {} <=> {}", unix_path, peer_addr);
                if let Err(e) = tcp::forward(unix_stream, tcp_stream).await {
                    error!("Failed to forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", unix_path, peer_addr);
            });
        }
    }

    async fn local_to_local_udp(&self) -> Result<()> {
        let ep1 = &self.locals[0];
        let ep2 = &self.locals[1];

        let socket1 = bind_udp(&ep1.addr).await?;
        let socket2 = bind_udp(&ep2.addr).await?;

        udp::local_forward(socket1, socket2).await
    }

    async fn local_to_remote_udp(&self) -> Result<()> {
        let local_ep = &self.locals[0];
        let remote_ep = &self.remotes[0];

        let local_socket = bind_udp(&local_ep.addr).await?;
        let remote_socket = UdpSocket::bind("0.0.0.0:0").await?;

        remote_socket.connect(&remote_ep.addr).await?;
        info!("Connect to {} success", remote_ep.addr);

        udp::local_to_remote_forward(local_socket, remote_socket).await
    }

    async fn remote_to_remote_udp(&self) -> Result<()> {
        let ep1 = &self.remotes[0];
        let ep2 = &self.remotes[1];

        let socket1 = UdpSocket::bind("0.0.0.0:0").await?;
        let socket2 = UdpSocket::bind("0.0.0.0:0").await?;

        socket1.connect(&ep1.addr).await?;
        info!("Connect to {} success", ep1.addr);

        socket2.connect(&ep2.addr).await?;
        info!("Connect to {} success", ep2.addr);

        udp::remote_forward(socket1, socket2).await
    }
}

async fn bind_tcp(addr: &str) -> Result<TcpListener> {
    let listener = TcpListener::bind(addr).await?;
    info!("Bind to {} success", listener.local_addr()?);
    Ok(listener)
}

async fn bind_udp(addr: &str) -> Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;
    info!("Bind to {} success", addr);
    Ok(socket)
}

fn make_tls_acceptor(ep: &Endpoint) -> Result<Option<TlsAcceptor>> {
    if ep.tls {
        Ok(Some(crypto::get_tls_acceptor(&ep.addr)?))
    } else {
        Ok(None)
    }
}

fn make_tls_connector(ep: &Endpoint) -> Option<TlsConnector> {
    if ep.tls {
        Some(crypto::get_tls_connector())
    } else {
        None
    }
}
