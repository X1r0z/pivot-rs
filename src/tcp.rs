use std::sync::Arc;

use anyhow::Result;
use async_smux::MuxStream;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{io, net::TcpStream, select};
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};
use tracing::error;

#[cfg(target_family = "unix")]
use tokio::net::UnixStream;

pub enum ForwardStream {
    Tcp(TcpStream),
    ServerTls(server::TlsStream<TcpStream>),
    ClientTls(client::TlsStream<TcpStream>),
    MuxTcp(MuxStream<TcpStream>),
    MuxServerTls(server::TlsStream<MuxStream<TcpStream>>),
    MuxClientTls(client::TlsStream<MuxStream<TcpStream>>),
    #[cfg(target_family = "unix")]
    Unix(UnixStream),
}

impl ForwardStream {
    pub async fn server(stream: TcpStream, acceptor: Arc<Option<TlsAcceptor>>) -> Self {
        match acceptor.as_ref() {
            Some(acceptor) => Self::ServerTls(acceptor.accept(stream).await.unwrap()),
            None => Self::Tcp(stream),
        }
    }

    pub async fn client(stream: TcpStream, connector: Arc<Option<TlsConnector>>) -> Self {
        match connector.as_ref() {
            Some(connector) => Self::ClientTls(
                connector
                    .connect(ServerName::try_from("localhost").unwrap(), stream)
                    .await
                    .unwrap(),
            ),
            None => Self::Tcp(stream),
        }
    }

    pub async fn mux_server(
        mux_stream: MuxStream<TcpStream>,
        acceptor: Arc<Option<TlsAcceptor>>,
    ) -> Self {
        match acceptor.as_ref() {
            Some(acceptor) => Self::MuxServerTls(acceptor.accept(mux_stream).await.unwrap()),
            None => Self::MuxTcp(mux_stream),
        }
    }

    pub async fn mux_client(
        mux_stream: MuxStream<TcpStream>,
        connector: Arc<Option<TlsConnector>>,
    ) -> Self {
        match connector.as_ref() {
            Some(connector) => Self::MuxClientTls(
                connector
                    .connect(ServerName::try_from("localhost").unwrap(), mux_stream)
                    .await
                    .unwrap(),
            ),
            None => Self::MuxTcp(mux_stream),
        }
    }

    pub fn split(
        self,
    ) -> (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ) {
        match self {
            ForwardStream::Tcp(stream) => {
                let (r, w) = io::split(stream);
                (Box::new(r), Box::new(w))
            }
            ForwardStream::ServerTls(stream) => {
                let (r, w) = io::split(stream);
                (Box::new(r), Box::new(w))
            }
            ForwardStream::ClientTls(stream) => {
                let (r, w) = io::split(stream);
                (Box::new(r), Box::new(w))
            }
            ForwardStream::MuxTcp(stream) => {
                let (r, w) = io::split(stream);
                (Box::new(r), Box::new(w))
            }
            ForwardStream::MuxServerTls(stream) => {
                let (r, w) = io::split(stream);
                (Box::new(r), Box::new(w))
            }
            ForwardStream::MuxClientTls(stream) => {
                let (r, w) = io::split(stream);
                (Box::new(r), Box::new(w))
            }
            #[cfg(target_family = "unix")]
            ForwardStream::Unix(stream) => {
                let (r, w) = io::split(stream);
                (Box::new(r), Box::new(w))
            }
        }
    }
}

pub async fn forward(stream1: ForwardStream, stream2: ForwardStream) -> Result<()> {
    let (r1, w1) = stream1.split();
    let (r2, w2) = stream2.split();

    split_forward((r1, w1), (r2, w2)).await
}

pub async fn split_forward(
    (mut r1, mut w1): (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ),
    (mut r2, mut w2): (
        Box<dyn AsyncRead + Unpin + Send>,
        Box<dyn AsyncWrite + Unpin + Send>,
    ),
) -> Result<()> {
    let handle1 = async {
        if let Err(e) = tokio::io::copy(&mut r1, &mut w2).await {
            error!("Failed to copy: {}", e);
        }
    };

    let handle2 = async {
        if let Err(e) = tokio::io::copy(&mut r2, &mut w1).await {
            error!("Failed to copy: {}", e);
        }
    };

    select! {
        _ = handle1 => {},
        _ = handle2 => {},
    }

    Ok(())
}
