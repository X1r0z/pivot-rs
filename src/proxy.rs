use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::{
    join,
    net::{TcpListener, TcpStream},
};
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
}

impl Proxy {
    pub fn new(
        locals: Vec<(String, bool)>,
        remote: Option<(String, bool)>,
        auth: Option<UserPassAuth>,
    ) -> Self {
        Self {
            locals,
            remote,
            auth,
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
                let stream = tcp::ForwardStream::from_acceptor(stream, acceptor).await;

                if let Err(e) = socks::handle_connection(stream, auth.as_ref()).await {
                    error!("Failed to handle connection: {}", e);
                }
            });
        }
    }

    async fn socks_reverse_client(&self) -> Result<()> {
        let (addr, ssl) = self.remote.as_ref().unwrap();

        let connector = Arc::new(ssl.then(|| crypto::get_tls_connector()));
        let auth = Arc::new(self.auth.clone());

        // limit the number of concurrent connections
        let semaphore = Arc::new(tokio::sync::Semaphore::new(32));

        loop {
            let permit = Arc::clone(&semaphore).acquire_owned().await;

            let stream = TcpStream::connect(addr).await?;
            info!("Connect to remote {} success", stream.peer_addr()?);

            let connector = Arc::clone(&connector);
            let auth = Arc::clone(&auth);

            tokio::spawn(async move {
                let stream = tcp::ForwardStream::from_connector(stream, connector).await;

                if let Err(e) = socks::handle_connection(stream, auth.as_ref()).await {
                    error!("Failed to handle connection: {}", e);
                }

                // drop the permit to release the semaphore
                drop(permit);
            });
        }
    }

    async fn socks_reverse_server(&self) -> Result<()> {
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

            let (stream1, client_addr1) = r1?;
            info!("Accept connection from {}", client_addr1);

            let (stream2, client_addr2) = r2?;
            info!("Accept connection from {}", client_addr2);

            let acceptor1 = Arc::clone(&acceptor1);
            let acceptor2 = Arc::clone(&acceptor2);

            tokio::spawn(async move {
                let stream1 = tcp::ForwardStream::from_acceptor(stream1, acceptor1).await;
                let stream2 = tcp::ForwardStream::from_acceptor(stream2, acceptor2).await;

                info!("Open pipe: {} <=> {}", client_addr1, client_addr2);
                if let Err(e) = tcp::forward(stream1, stream2).await {
                    error!("Failed to handle forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", client_addr1, client_addr2);
            });
        }
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
                let remote_stream =
                    tcp::ForwardStream::from_connector(remote_stream, connector).await;

                info!("Open pipe: {} <=> {}", client_addr, remote_addr);
                if let Err(e) = socks::handle_forwarding(client_stream, remote_stream, auth).await {
                    error!("Failed to handle forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", client_addr, remote_addr);
            });
        }
    }
}
