use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_smux::MuxBuilder;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info};

use crate::{
    crypto,
    socks::{self, UserPassAuth},
    tcp::{self, ForwardStream},
    util::Endpoint,
};

pub struct Proxy {
    locals: Vec<Endpoint>,
    remote: Option<Endpoint>,
    auth: Option<UserPassAuth>,
    connections: usize,
}

impl Proxy {
    pub fn new(
        locals: Vec<Endpoint>,
        remote: Option<Endpoint>,
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
            _ => return Err(anyhow!("Invalid proxy parameters")),
        }

        Ok(())
    }

    async fn socks_server(&self) -> Result<()> {
        let ep = &self.locals[0];

        let listener = bind_tcp(&ep.addr).await?;
        info!("Start socks server on {}", listener.local_addr()?);

        let acceptor = Arc::new(make_tls_acceptor(ep)?);
        let auth = Arc::new(self.auth.clone());

        loop {
            let (stream, client_addr) = listener.accept().await?;
            info!("Accept connection from {}", client_addr);

            let acceptor = Arc::clone(&acceptor);
            let auth = Arc::clone(&auth);

            tokio::spawn(async move {
                let stream = match ForwardStream::server(stream, acceptor).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("TLS accept failed: {}", e);
                        return;
                    }
                };

                if let Err(e) = socks::handle_connection(stream, auth.as_ref()).await {
                    error!("Failed to handle connection: {}", e);
                }
            });
        }
    }

    async fn socks_reverse_client(&self) -> Result<()> {
        let ep = self
            .remote
            .as_ref()
            .ok_or_else(|| anyhow!("Remote address is required"))?;

        let stream = TcpStream::connect(&ep.addr).await?;
        info!("Connect to remote {} (Control Address) success", ep.addr);

        let (mux_connector, _, worker) = MuxBuilder::client().with_connection(stream).build();
        tokio::spawn(worker);

        let mux_connector = Arc::new(mux_connector);
        let tls_connector = Arc::new(make_tls_connector(ep));
        let auth = Arc::new(self.auth.clone());

        let semaphore = Arc::new(Semaphore::new(self.connections));

        loop {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| anyhow!("Semaphore closed: {}", e))?;

            let mux_stream = match mux_connector.connect() {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to open mux stream: {}", e);
                    continue;
                }
            };

            let tls_connector = Arc::clone(&tls_connector);
            let auth = Arc::clone(&auth);

            tokio::spawn(async move {
                let _permit = permit;

                let mux_stream = match ForwardStream::mux_client(mux_stream, tls_connector).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("TLS connect failed: {}", e);
                        return;
                    }
                };

                if let Err(e) = socks::handle_connection(mux_stream, auth.as_ref()).await {
                    error!("Failed to handle connection: {}", e);
                }
            });
        }
    }

    async fn socks_reverse_server(&self) -> Result<()> {
        let mux_ep = &self.locals[0];
        let proxy_ep = &self.locals[1];

        let mux_listener = bind_tcp(&mux_ep.addr).await?;
        info!(
            "Bind to {} (Control Address) success",
            mux_listener.local_addr()?
        );

        let proxy_listener = bind_tcp(&proxy_ep.addr).await?;
        info!(
            "Bind to {} (Proxy Address) success",
            proxy_listener.local_addr()?
        );

        let mux_tls_acceptor = Arc::new(make_tls_acceptor(mux_ep)?);
        let proxy_tls_acceptor = Arc::new(make_tls_acceptor(proxy_ep)?);

        let (stream, mux_client_addr) = mux_listener.accept().await?;
        info!("Accept connection from {}", mux_client_addr);

        let (_, mut mux_acceptor, worker) = MuxBuilder::server().with_connection(stream).build();
        tokio::spawn(worker);

        while let Some(mux_stream) = mux_acceptor.accept().await {
            let (stream, proxy_client_addr) = proxy_listener.accept().await?;
            info!("Accept connection from {}", proxy_client_addr);

            let mux_tls_acceptor = Arc::clone(&mux_tls_acceptor);
            let proxy_tls_acceptor = Arc::clone(&proxy_tls_acceptor);

            tokio::spawn(async move {
                let (mux_stream, proxy_stream) = match (
                    ForwardStream::mux_server(mux_stream, mux_tls_acceptor).await,
                    ForwardStream::server(stream, proxy_tls_acceptor).await,
                ) {
                    (Ok(s1), Ok(s2)) => (s1, s2),
                    (Err(e), _) | (_, Err(e)) => {
                        error!("TLS accept failed: {}", e);
                        return;
                    }
                };

                info!(
                    "Open pipe: {} <=> {}",
                    mux_client_addr, proxy_client_addr
                );
                if let Err(e) = tcp::forward(mux_stream, proxy_stream).await {
                    error!("Failed to forward: {}", e);
                }
                info!(
                    "Close pipe: {} <=> {}",
                    mux_client_addr, proxy_client_addr
                );
            });
        }

        Ok(())
    }

    async fn socks_forward(&self) -> Result<()> {
        let local_ep = &self.locals[0];
        let remote_ep = self
            .remote
            .as_ref()
            .ok_or_else(|| anyhow!("Remote address is required"))?;

        let auth = self
            .auth
            .clone()
            .ok_or_else(|| anyhow!("Username and password are required"))?;

        let listener = bind_tcp(&local_ep.addr).await?;
        let connector = Arc::new(make_tls_connector(remote_ep));
        let auth = Arc::new(auth);
        let remote_addr = remote_ep.addr.clone();

        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            info!("Accept connection from {}", client_addr);

            let remote_stream = TcpStream::connect(&remote_addr).await?;
            let peer_addr = remote_stream.peer_addr()?;
            info!("Connect to remote {} success", peer_addr);

            let connector = Arc::clone(&connector);
            let auth = Arc::clone(&auth);

            tokio::spawn(async move {
                let client_stream = ForwardStream::Tcp(client_stream);
                let remote_stream = match ForwardStream::client(remote_stream, connector).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("TLS connect failed: {}", e);
                        return;
                    }
                };

                info!("Open pipe: {} <=> {}", client_addr, peer_addr);
                if let Err(e) =
                    socks::handle_forwarding(client_stream, remote_stream, auth).await
                {
                    error!("Failed to forward: {}", e);
                }
                info!("Close pipe: {} <=> {}", client_addr, peer_addr);
            });
        }
    }
}

async fn bind_tcp(addr: &str) -> Result<TcpListener> {
    let listener = TcpListener::bind(addr).await?;
    Ok(listener)
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
