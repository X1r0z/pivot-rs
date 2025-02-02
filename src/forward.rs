use std::sync::Arc;

use anyhow::Result;
use tokio::{
    join,
    net::{TcpListener, TcpStream, UdpSocket},
    sync,
};
use tracing::{error, info};

#[cfg(target_family = "unix")]
use tokio::net::UnixStream;

use crate::{crypto, tcp, udp, Protocol, MAX_CONNECTIONS};

pub struct Forward {
    locals: Vec<(String, bool)>,
    remotes: Vec<(String, bool)>,
    #[cfg(target_family = "unix")]
    socket: Option<String>,
    protocol: Protocol,
}

impl Forward {
    pub fn new(
        locals: Vec<(String, bool)>,
        remotes: Vec<(String, bool)>,
        #[cfg(target_family = "unix")] socket: Option<String>,
        protocol: Protocol,
    ) -> Self {
        Self {
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            socket,
            protocol,
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
            _ => error!("Invalid forward parameters"),
        }

        #[cfg(target_family = "windows")]
        match (self.locals.len(), self.remotes.len()) {
            (2, 0) => self.local_to_local().await?,
            (1, 1) => self.local_to_remote().await?,
            (0, 2) => self.remote_to_remote().await?,
            _ => error!("Invalid forward parameters"),
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
        let (addr1, ssl1) = &self.locals[0];
        let (addr2, ssl2) = &self.locals[1];

        let listener1 = TcpListener::bind(addr1).await?;
        info!("Bind to {} success", listener1.local_addr()?);

        let listener2 = TcpListener::bind(addr2).await?;
        info!("Bind to {} success", listener2.local_addr()?);

        let acceptor1 = Arc::new(ssl1.then(|| crypto::get_tls_acceptor(addr1)));
        let acceptor2 = Arc::new(ssl2.then(|| crypto::get_tls_acceptor(addr2)));

        loop {
            let (r1, r2) = join!(listener1.accept(), listener2.accept());

            let (stream1, addr1) = r1?;
            info!("Accept connection from {}", addr1);

            let (stream2, addr2) = r2?;
            info!("Accept connection from {}", addr2);

            let acceptor1 = Arc::clone(&acceptor1);
            let acceptor2 = Arc::clone(&acceptor2);

            tokio::spawn(async move {
                let stream1 = tcp::ForwardStream::server(stream1, acceptor1).await;
                let stream2 = tcp::ForwardStream::server(stream2, acceptor2).await;

                info!("Open pipe: {} <=> {}", addr1, addr2);
                if let Err(e) = tcp::forward(stream1, stream2).await {
                    error!("Failed to forward: {}", e)
                }
                info!("Close pipe: {} <=> {}", addr1, addr2);
            });
        }
    }

    async fn local_to_remote_tcp(&self) -> Result<()> {
        let (local_addr, local_ssl) = &self.locals[0];
        let (remote_addr, remote_ssl) = &self.remotes[0];

        let listener = TcpListener::bind(local_addr).await?;
        info!("Bind to {} success", listener.local_addr()?);

        let acceptor = Arc::new(local_ssl.then(|| crypto::get_tls_acceptor(local_addr)));
        let connector = Arc::new(remote_ssl.then(|| crypto::get_tls_connector()));

        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            info!("Accept connection from {}", client_addr);

            let remote_stream = TcpStream::connect(remote_addr).await?;
            let remote_addr = remote_stream.peer_addr()?;
            info!("Connect to {} success", remote_addr);

            let acceptor = Arc::clone(&acceptor);
            let connector = Arc::clone(&connector);

            tokio::spawn(async move {
                let client_stream = tcp::ForwardStream::server(client_stream, acceptor).await;
                let remote_stream = tcp::ForwardStream::client(remote_stream, connector).await;

                info!("Open pipe: {} <=> {}", client_addr, remote_addr);
                if let Err(e) = tcp::forward(client_stream, remote_stream).await {
                    error!("failed to forward: {}", e)
                }
                info!("Close pipe: {} <=> {}", client_addr, remote_addr);
            });
        }
    }

    async fn remote_to_remote_tcp(&self) -> Result<()> {
        let (addr1, ssl1) = &self.remotes[0];
        let (addr2, ssl2) = &self.remotes[1];

        let connector1 = Arc::new(ssl1.then(|| crypto::get_tls_connector()));
        let connector2 = Arc::new(ssl2.then(|| crypto::get_tls_connector()));

        // limit the number of concurrent connections
        let semaphore = Arc::new(sync::Semaphore::new(MAX_CONNECTIONS));

        loop {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

            let (r1, r2) = join!(TcpStream::connect(addr1), TcpStream::connect(addr2));

            let stream1 = r1?;
            let addr1 = stream1.peer_addr()?;
            info!("Connect to {} success", addr1);

            let stream2 = r2?;
            let addr2 = stream2.peer_addr()?;
            info!("Connect to {} success", addr2);

            let connector1 = Arc::clone(&connector1);
            let connector2 = Arc::clone(&connector2);

            tokio::spawn(async move {
                let stream1 = tcp::ForwardStream::client(stream1, connector1).await;
                let stream2 = tcp::ForwardStream::client(stream2, connector2).await;

                info!("Open pipe: {} <=> {}", addr1, addr2);
                if let Err(e) = tcp::forward(stream1, stream2).await {
                    error!("Failed to forward: {}", e)
                }
                info!("Close pipe: {} <=> {}", addr1, addr2);

                // drop the permit to release the semaphore
                drop(permit);
            });
        }
    }

    #[cfg(target_family = "unix")]
    async fn socket_to_local_tcp(&self) -> Result<()> {
        let (addr, ssl) = &self.locals[0];

        let listener = TcpListener::bind(addr).await?;
        info!("Bind to {} success", listener.local_addr()?);

        let acceptor = Arc::new(ssl.then(|| crypto::get_tls_acceptor(addr)));

        loop {
            let (tcp_stream, client_addr) = listener.accept().await?;
            info!("Accept connection from {}", client_addr);

            let unix_socket = self.socket.clone().unwrap();
            let unix_stream = UnixStream::connect(&unix_socket).await?;
            info!("Connect to {} success", unix_socket);

            let acceptor = Arc::clone(&acceptor);

            tokio::spawn(async move {
                let tcp_stream = tcp::ForwardStream::server(tcp_stream, acceptor).await;
                let unix_stream = tcp::ForwardStream::Unix(unix_stream);

                info!("Open pipe: {} <=> {}", unix_socket, client_addr);
                if let Err(e) = tcp::forward(tcp_stream, unix_stream).await {
                    error!("Failed to forward: {}", e)
                }
                info!("Close pipe: {} <=> {}", unix_socket, client_addr);
            });
        }
    }

    #[cfg(target_family = "unix")]
    async fn socket_to_remote_tcp(&self) -> Result<()> {
        let (addr, ssl) = &self.remotes[0];

        let connector = Arc::new(ssl.then(|| crypto::get_tls_connector()));

        // limit the number of concurrent connections
        let semaphore = Arc::new(sync::Semaphore::new(MAX_CONNECTIONS));

        loop {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

            let unix_socket = self.socket.clone().unwrap();
            let addr = addr.clone();

            let (r1, r2) = join!(UnixStream::connect(&unix_socket), TcpStream::connect(&addr));

            let unix_stream = r1?;
            info!("Connect to {} success", unix_socket);

            let tcp_stream = r2?;
            info!("Connect to {} success", addr);

            let connector = Arc::clone(&connector);

            tokio::spawn(async move {
                let unix_stream = tcp::ForwardStream::Unix(unix_stream);
                let tcp_stream = tcp::ForwardStream::client(tcp_stream, connector).await;

                info!("Open pipe: {} <=> {}", unix_socket, addr);
                if let Err(e) = tcp::forward(unix_stream, tcp_stream).await {
                    error!("Failed to forward: {}", e)
                }
                info!("Close pipe: {} <=> {}", unix_socket, addr);

                // drop the permit to release the semaphore
                drop(permit);
            });
        }
    }

    async fn local_to_local_udp(&self) -> Result<()> {
        let (addr1, _) = &self.locals[0];
        let (addr2, _) = &self.locals[1];

        let socket1 = UdpSocket::bind(addr1).await?;
        info!("Bind to {} success", addr1);

        let socket2 = UdpSocket::bind(addr2).await?;
        info!("Bind to {} success", addr2);

        // socket1 will receive the handshake packet to keep client address
        udp::local_forward(socket1, socket2).await
    }

    async fn local_to_remote_udp(&self) -> Result<()> {
        let (local_addr, _) = &self.locals[0];
        let (remote_addr, _) = &self.remotes[0];

        let local_socket = UdpSocket::bind(local_addr).await?;
        let remote_socket = UdpSocket::bind("0.0.0.0:0").await?;

        remote_socket.connect(remote_addr).await?;
        info!("Connect to {} success", remote_addr);

        udp::local_to_remote_forward(local_socket, remote_socket).await
    }

    async fn remote_to_remote_udp(&self) -> Result<()> {
        let (addr1, _) = &self.remotes[0];
        let (addr2, _) = &self.remotes[1];

        let socket1 = UdpSocket::bind("0.0.0.0:0").await?;
        let socket2 = UdpSocket::bind("0.0.0.0:0").await?;

        socket1.connect(addr1).await?;
        info!("Connect to {} success", addr1);

        socket2.connect(addr2).await?;
        info!("Connect to {} success", addr2);

        // socket2 will send the handshake packet to keep client address
        udp::remote_forward(socket1, socket2).await
    }
}
