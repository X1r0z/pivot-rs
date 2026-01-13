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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_forward_basic() {
        let forward_task = tokio::spawn(async move {
            let (mut c1, s1) = tokio::io::duplex(1024);
            let (mut c2, s2) = tokio::io::duplex(1024);

            let fwd = tokio::spawn(async move {
                forward(s1, s2).await.unwrap();
            });

            c1.write_all(b"hello").await.unwrap();

            let mut buf = [0u8; 5];
            c2.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");

            c2.write_all(b"world").await.unwrap();

            let mut buf = [0u8; 5];
            c1.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"world");

            drop(c1);
            drop(c2);
            let _ = fwd.await;
        });

        forward_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_forward_large_data() {
        let (mut c1, s1) = tokio::io::duplex(65536);
        let (mut c2, s2) = tokio::io::duplex(65536);

        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let data_clone = data.clone();

        let fwd = tokio::spawn(async move {
            let _ = forward(s1, s2).await;
        });

        let writer = tokio::spawn(async move {
            c1.write_all(&data_clone).await.unwrap();
            drop(c1);
        });

        let mut received = vec![0u8; 10000];
        c2.read_exact(&mut received).await.unwrap();
        assert_eq!(received, data);

        writer.await.unwrap();
        drop(c2);
        let _ = fwd.await;
    }

    #[tokio::test]
    async fn test_forward_stream_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let forward_stream = ForwardStream::server(stream, Arc::new(None)).await.unwrap();
            forward_stream
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let client_forward = ForwardStream::client(client_stream, Arc::new(None))
            .await
            .unwrap();

        let server_forward = server.await.unwrap();

        assert!(matches!(client_forward, ForwardStream::Tcp(_)));
        assert!(matches!(server_forward, ForwardStream::Tcp(_)));
    }

    #[tokio::test]
    async fn test_forward_stream_tls() {
        use crate::crypto;

        let acceptor = crypto::get_tls_acceptor("localhost").unwrap();
        let connector = crypto::get_tls_connector();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let acceptor = Arc::new(Some(acceptor));
        let connector = Arc::new(Some(connector));

        let acceptor_clone = Arc::clone(&acceptor);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let forward_stream = ForwardStream::server(stream, acceptor_clone).await.unwrap();
            forward_stream
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let client_forward = ForwardStream::client(client_stream, connector)
            .await
            .unwrap();

        let server_forward = server.await.unwrap();

        assert!(matches!(client_forward, ForwardStream::ClientTls(_)));
        assert!(matches!(server_forward, ForwardStream::ServerTls(_)));
    }

    #[tokio::test]
    async fn test_forward_stream_read_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut forward_stream = ForwardStream::server(stream, Arc::new(None)).await.unwrap();

            let mut buf = [0u8; 5];
            forward_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");

            forward_stream.write_all(b"world").await.unwrap();
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let mut client_forward = ForwardStream::client(client_stream, Arc::new(None))
            .await
            .unwrap();

        client_forward.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 5];
        client_forward.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_forward_bidirectional() {
        let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener1.local_addr().unwrap();

        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();

        let forwarder = tokio::spawn(async move {
            let (stream1, _) = listener1.accept().await.unwrap();
            let (stream2, _) = listener2.accept().await.unwrap();

            let fs1 = ForwardStream::server(stream1, Arc::new(None))
                .await
                .unwrap();
            let fs2 = ForwardStream::server(stream2, Arc::new(None))
                .await
                .unwrap();

            forward(fs1, fs2).await.unwrap();
        });

        let client1 = TcpStream::connect(addr1).await.unwrap();
        let client2 = TcpStream::connect(addr2).await.unwrap();

        let mut client1 = ForwardStream::Tcp(client1);
        let mut client2 = ForwardStream::Tcp(client2);

        client1.write_all(b"from1").await.unwrap();

        let mut buf = [0u8; 5];
        client2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from1");

        client2.write_all(b"from2").await.unwrap();

        let mut buf = [0u8; 5];
        client1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"from2");

        drop(client1);
        drop(client2);
        let _ = forwarder.await;
    }

    #[cfg(target_family = "unix")]
    #[tokio::test]
    async fn test_forward_stream_unix() {
        use tokio::net::{UnixListener, UnixStream};

        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let listener = UnixListener::bind(&socket_path).unwrap();

        let socket_path_clone = socket_path.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut forward_stream = ForwardStream::Unix(stream);

            let mut buf = [0u8; 5];
            forward_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");

            forward_stream.write_all(b"world").await.unwrap();
        });

        let client_stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let mut client_forward = ForwardStream::Unix(client_stream);

        client_forward.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 5];
        client_forward.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        server.await.unwrap();
    }
}
