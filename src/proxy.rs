use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_smux::MuxBuilder;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

use crate::{
    crypto,
    socks::{self, UserPassAuth},
    tcp::{self},
};

pub struct Proxy {
    locals: Vec<(String, bool)>,
    remote: Option<(String, bool)>,
    auth: Option<UserPassAuth>,
    connections: usize,
}

impl Proxy {
    pub fn new(
        locals: Vec<(String, bool)>,
        remote: Option<(String, bool)>,
        auth: Option<UserPassAuth>,
        connections: usize,
    ) -> Self {
        Self {
            locals,
            remote,
            auth,
            connections,
        }
    }

    pub async fn start(&self) -> Result<()> {
        match (self.locals.len(), &self.remote) {
            (1, None) => self.socks_server().await?,
            (2, None) => self.socks_reverse_server().await?,
            (0, Some(_)) => self.socks_reverse_client().await?,
            (1, Some(_)) => self.socks_forward().await?,
            _ => error!("Invalid proxy parameters"),
        }

        Ok(())
    }

    async fn socks_server(&self) -> Result<()> {
        let (addr, ssl) = &self.locals[0];

        let listener = TcpListener::bind(addr).await?;
        info!("Start socks server on {}", listener.local_addr()?);

        let acceptor = Arc::new(ssl.then(|| crypto::get_tls_acceptor(addr)));
        let auth = Arc::new(self.auth.clone());

        loop {
            let (stream, client_addr) = listener.accept().await?;
            info!("Accept connection from {}", client_addr);

            let acceptor = Arc::clone(&acceptor);
            let auth = Arc::clone(&auth);

            tokio::spawn(async move {
                let stream = tcp::ForwardStream::server(stream, acceptor).await;

                if let Err(e) = socks::handle_connection(stream, auth.as_ref()).await {
                    error!("Failed to handle connection: {}", e);
                }
            });
        }
    }

    async fn socks_reverse_client(&self) -> Result<()> {
        let (addr, ssl) = self.remote.as_ref().unwrap();

        let stream = TcpStream::connect(addr).await?;
        info!("Connect to remote {} (Control Address) success", addr);

        let (mux_connector, _, worker) = MuxBuilder::client().with_connection(stream).build();
        tokio::spawn(worker);

        let mux_connector = Arc::new(mux_connector);
        let tls_connector = Arc::new(ssl.then(|| crypto::get_tls_connector()));
        let auth = Arc::new(self.auth.clone());

        // limit the number of concurrent connections
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.connections));

        loop {
            let permit = Arc::clone(&semaphore).acquire_owned().await;

            let mux_connector = Arc::clone(&mux_connector);
            let tls_connector = Arc::clone(&tls_connector);
            let auth = Arc::clone(&auth);

            tokio::spawn(async move {
                let mux_stream = mux_connector.connect().unwrap();
                let mux_stream = tcp::ForwardStream::mux_client(mux_stream, tls_connector).await;

                if let Err(e) = socks::handle_connection(mux_stream, auth.as_ref()).await {
                    error!("Failed to handle connection: {}", e);
                }

                // drop the permit to release the semaphore
                drop(permit);
            });
        }
    }

    async fn socks_reverse_server(&self) -> Result<()> {
        let (mux_addr, mux_ssl) = &self.locals[0];
        let (proxy_addr, ssl) = &self.locals[1];

        let mux_listener = TcpListener::bind(mux_addr).await?;
        info!(
            "Bind to {} (Control Address) success",
            mux_listener.local_addr()?
        );

        let proxy_listener = TcpListener::bind(proxy_addr).await?;
        info!(
            "Bind to {} (Proxy Address) success",
            proxy_listener.local_addr()?
        );

        let mux_tls_acceptor = Arc::new(mux_ssl.then(|| crypto::get_tls_acceptor(mux_addr)));
        let proxy_tls_acceptor = Arc::new(ssl.then(|| crypto::get_tls_acceptor(proxy_addr)));

        let (stream, addr1) = mux_listener.accept().await?;
        info!("Accept connection from {}", addr1);

        let (_, mut mux_acceptor, worker) = MuxBuilder::server().with_connection(stream).build();
        tokio::spawn(worker);

        while let Some(mux_stream) = mux_acceptor.accept().await {
            let (stream, addr2) = proxy_listener.accept().await?;
            info!("Accept connection from {}", addr2);

            let mux_tls_acceptor = Arc::clone(&mux_tls_acceptor);
            let proxy_tls_acceptor = Arc::clone(&proxy_tls_acceptor);

            tokio::spawn(async move {
                let mux_stream = tcp::ForwardStream::mux_server(mux_stream, mux_tls_acceptor).await;
                let proxy_stream = tcp::ForwardStream::server(stream, proxy_tls_acceptor).await;

                info!("Open pipe: {} <=> {}", addr1, addr2);
                if let Err(e) = tcp::forward(mux_stream, proxy_stream).await {
                    error!("Failed to handle forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", addr1, addr2);
            });
        }

        Ok(())
    }

    async fn socks_forward(&self) -> Result<()> {
        let (local_addr, _) = &self.locals[0];
        let (remote_addr, remote_ssl) = self.remote.as_ref().unwrap();

        let Some(auth) = self.auth.clone() else {
            return Err(anyhow!("Username and password are required"));
        };

        let listener = TcpListener::bind(local_addr).await?;
        info!("Bind to {} success", listener.local_addr()?);

        let connector = Arc::new(remote_ssl.then(|| crypto::get_tls_connector()));
        let auth = Arc::new(auth);

        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            info!("Accept connection from {}", client_addr);

            let remote_stream = TcpStream::connect(remote_addr).await?;
            let remote_addr = remote_stream.peer_addr()?;
            info!("Connect to remote {} success", remote_addr);

            let connector = Arc::clone(&connector);
            let auth = Arc::clone(&auth);

            tokio::spawn(async move {
                let client_stream = tcp::ForwardStream::Tcp(client_stream);
                let remote_stream = tcp::ForwardStream::client(remote_stream, connector).await;

                info!("Open pipe: {} <=> {}", client_addr, remote_addr);
                if let Err(e) = socks::handle_forwarding(client_stream, remote_stream, auth).await {
                    error!("Failed to handle forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", client_addr, remote_addr);
            });
        }
    }
}
