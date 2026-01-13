use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::Result;
use async_smux::MuxStream;
use rustls::pki_types::ServerName;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    select,
};
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
    pub async fn server(stream: TcpStream, acceptor: Arc<Option<TlsAcceptor>>) -> Result<Self> {
        match acceptor.as_ref() {
            Some(acceptor) => Ok(Self::ServerTls(acceptor.accept(stream).await?)),
            None => Ok(Self::Tcp(stream)),
        }
    }

    pub async fn client(stream: TcpStream, connector: Arc<Option<TlsConnector>>) -> Result<Self> {
        match connector.as_ref() {
            Some(connector) => {
                let server_name = ServerName::try_from("localhost")?;
                Ok(Self::ClientTls(
                    connector.connect(server_name, stream).await?,
                ))
            }
            None => Ok(Self::Tcp(stream)),
        }
    }

    pub async fn mux_server(
        mux_stream: MuxStream<TcpStream>,
        acceptor: Arc<Option<TlsAcceptor>>,
    ) -> Result<Self> {
        match acceptor.as_ref() {
            Some(acceptor) => Ok(Self::MuxServerTls(acceptor.accept(mux_stream).await?)),
            None => Ok(Self::MuxTcp(mux_stream)),
        }
    }

    pub async fn mux_client(
        mux_stream: MuxStream<TcpStream>,
        connector: Arc<Option<TlsConnector>>,
    ) -> Result<Self> {
        match connector.as_ref() {
            Some(connector) => {
                let server_name = ServerName::try_from("localhost")?;
                Ok(Self::MuxClientTls(
                    connector.connect(server_name, mux_stream).await?,
                ))
            }
            None => Ok(Self::MuxTcp(mux_stream)),
        }
    }
}

impl AsyncRead for ForwardStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ForwardStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            ForwardStream::ServerTls(s) => Pin::new(s).poll_read(cx, buf),
            ForwardStream::ClientTls(s) => Pin::new(s).poll_read(cx, buf),
            ForwardStream::MuxTcp(s) => Pin::new(s).poll_read(cx, buf),
            ForwardStream::MuxServerTls(s) => Pin::new(s).poll_read(cx, buf),
            ForwardStream::MuxClientTls(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(target_family = "unix")]
            ForwardStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ForwardStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ForwardStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            ForwardStream::ServerTls(s) => Pin::new(s).poll_write(cx, buf),
            ForwardStream::ClientTls(s) => Pin::new(s).poll_write(cx, buf),
            ForwardStream::MuxTcp(s) => Pin::new(s).poll_write(cx, buf),
            ForwardStream::MuxServerTls(s) => Pin::new(s).poll_write(cx, buf),
            ForwardStream::MuxClientTls(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(target_family = "unix")]
            ForwardStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ForwardStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            ForwardStream::ServerTls(s) => Pin::new(s).poll_flush(cx),
            ForwardStream::ClientTls(s) => Pin::new(s).poll_flush(cx),
            ForwardStream::MuxTcp(s) => Pin::new(s).poll_flush(cx),
            ForwardStream::MuxServerTls(s) => Pin::new(s).poll_flush(cx),
            ForwardStream::MuxClientTls(s) => Pin::new(s).poll_flush(cx),
            #[cfg(target_family = "unix")]
            ForwardStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ForwardStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            ForwardStream::ServerTls(s) => Pin::new(s).poll_shutdown(cx),
            ForwardStream::ClientTls(s) => Pin::new(s).poll_shutdown(cx),
            ForwardStream::MuxTcp(s) => Pin::new(s).poll_shutdown(cx),
            ForwardStream::MuxServerTls(s) => Pin::new(s).poll_shutdown(cx),
            ForwardStream::MuxClientTls(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(target_family = "unix")]
            ForwardStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub async fn forward<S1, S2>(mut stream1: S1, mut stream2: S2) -> Result<()>
where
    S1: AsyncRead + AsyncWrite + Unpin,
    S2: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r1, mut w1) = io::split(&mut stream1);
    let (mut r2, mut w2) = io::split(&mut stream2);

    let copy1 = async {
        if let Err(e) = io::copy(&mut r1, &mut w2).await {
            error!("Failed to copy: {}", e);
        }
    };

    let copy2 = async {
        if let Err(e) = io::copy(&mut r2, &mut w1).await {
            error!("Failed to copy: {}", e);
        }
    };

    select! {
        _ = copy1 => {},
        _ = copy2 => {},
    }

    Ok(())
}
