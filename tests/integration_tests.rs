use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use pivot::forward::Forward;
use pivot::proxy::Proxy;
use pivot::util::{parse_addrs, Endpoint};
use pivot::Protocol;

async fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn get_free_ports(count: usize) -> Vec<u16> {
    let mut ports = Vec::with_capacity(count);
    let mut listeners = Vec::with_capacity(count);

    for _ in 0..count {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        ports.push(listener.local_addr().unwrap().port());
        listeners.push(listener);
    }

    drop(listeners);
    tokio::time::sleep(Duration::from_millis(10)).await;
    ports
}

fn create_endpoints(addrs: Vec<&str>) -> Vec<Endpoint> {
    parse_addrs(addrs.into_iter().map(String::from).collect())
}

async fn start_echo_server(addr: &str) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(addr).await.unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    })
}

mod tcp_forward_tests {
    use super::*;

    #[tokio::test]
    async fn test_local_to_remote_tcp_forward() {
        let ports = get_free_ports(2).await;
        let local_port = ports[0];
        let remote_port = ports[1];

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", remote_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", local_port)]);
        let remotes = create_endpoints(vec![&format!("127.0.0.1:{}", remote_port)]);

        let forward = Forward::new(
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", local_port))
            .await
            .unwrap();

        client.write_all(b"hello world").await.unwrap();

        let mut buf = [0u8; 11];
        let result = timeout(Duration::from_secs(2), client.read_exact(&mut buf)).await;
        assert!(result.is_ok());
        assert_eq!(&buf, b"hello world");

        forward_task.abort();
        echo_server.abort();
    }

    #[tokio::test]
    async fn test_local_to_local_tcp_forward() {
        let ports = get_free_ports(2).await;
        let port1 = ports[0];
        let port2 = ports[1];

        let locals = create_endpoints(vec![
            &format!("127.0.0.1:{}", port1),
            &format!("127.0.0.1:{}", port2),
        ]);

        let forward = Forward::new(
            locals,
            vec![],
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client1_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port1))
                .await
                .unwrap();

            client.write_all(b"from port1").await.unwrap();

            let mut buf = [0u8; 10];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"from port2");
        });

        let client2_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port2))
                .await
                .unwrap();

            let mut buf = [0u8; 10];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"from port1");

            client.write_all(b"from port2").await.unwrap();
        });

        let result = timeout(Duration::from_secs(3), async {
            client1_task.await.unwrap();
            client2_task.await.unwrap();
        })
        .await;

        assert!(result.is_ok());
        forward_task.abort();
    }

    #[tokio::test]
    async fn test_tcp_forward_multiple_connections() {
        let ports = get_free_ports(2).await;
        let local_port = ports[0];
        let remote_port = ports[1];

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", remote_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", local_port)]);
        let remotes = create_endpoints(vec![&format!("127.0.0.1:{}", remote_port)]);

        let forward = Forward::new(
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut tasks = vec![];
        for i in 0..5 {
            let port = local_port;
            tasks.push(tokio::spawn(async move {
                let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                    .await
                    .unwrap();

                let msg = format!("message {}", i);
                client.write_all(msg.as_bytes()).await.unwrap();

                let mut buf = vec![0u8; msg.len()];
                client.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, msg.as_bytes());
            }));
        }

        for task in tasks {
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
        }

        forward_task.abort();
        echo_server.abort();
    }

    #[tokio::test]
    async fn test_tcp_forward_large_data() {
        let ports = get_free_ports(2).await;
        let local_port = ports[0];
        let remote_port = ports[1];

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", remote_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", local_port)]);
        let remotes = create_endpoints(vec![&format!("127.0.0.1:{}", remote_port)]);

        let forward = Forward::new(
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", local_port))
            .await
            .unwrap();

        let large_data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        client.write_all(&large_data).await.unwrap();

        let mut received = vec![0u8; 65536];
        let result = timeout(Duration::from_secs(5), client.read_exact(&mut received)).await;
        assert!(result.is_ok());
        assert_eq!(received, large_data);

        forward_task.abort();
        echo_server.abort();
    }
}

mod tls_forward_tests {
    use super::*;
    use pivot::crypto;

    #[tokio::test]
    async fn test_tls_local_to_remote_forward() {
        let ports = get_free_ports(2).await;
        let local_port = ports[0];
        let remote_port = ports[1];

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", remote_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let locals = create_endpoints(vec![&format!("+127.0.0.1:{}", local_port)]);
        let remotes = create_endpoints(vec![&format!("127.0.0.1:{}", remote_port)]);

        let forward = Forward::new(
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let connector = crypto::get_tls_connector();
        let stream = TcpStream::connect(format!("127.0.0.1:{}", local_port))
            .await
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        tls_stream.write_all(b"hello tls").await.unwrap();

        let mut buf = [0u8; 9];
        let result = timeout(Duration::from_secs(2), tls_stream.read_exact(&mut buf)).await;
        assert!(result.is_ok());
        assert_eq!(&buf, b"hello tls");

        forward_task.abort();
        echo_server.abort();
    }

    #[tokio::test]
    async fn test_tls_local_to_local_forward() {
        let ports = get_free_ports(2).await;
        let port1 = ports[0];
        let port2 = ports[1];

        let locals = create_endpoints(vec![
            &format!("+127.0.0.1:{}", port1),
            &format!("+127.0.0.1:{}", port2),
        ]);

        let forward = Forward::new(
            locals,
            vec![],
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let connector1 = crypto::get_tls_connector();
        let connector2 = crypto::get_tls_connector();

        let client1_task = tokio::spawn(async move {
            let stream = TcpStream::connect(format!("127.0.0.1:{}", port1))
                .await
                .unwrap();
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls_stream = connector1.connect(server_name, stream).await.unwrap();

            tls_stream.write_all(b"tls msg 1").await.unwrap();

            let mut buf = [0u8; 9];
            tls_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"tls msg 2");
        });

        let client2_task = tokio::spawn(async move {
            let stream = TcpStream::connect(format!("127.0.0.1:{}", port2))
                .await
                .unwrap();
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls_stream = connector2.connect(server_name, stream).await.unwrap();

            let mut buf = [0u8; 9];
            tls_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"tls msg 1");

            tls_stream.write_all(b"tls msg 2").await.unwrap();
        });

        let result = timeout(Duration::from_secs(3), async {
            client1_task.await.unwrap();
            client2_task.await.unwrap();
        })
        .await;

        assert!(result.is_ok());
        forward_task.abort();
    }
}

mod udp_forward_tests {
    use super::*;

    async fn start_udp_echo_server(addr: &str) -> (tokio::task::JoinHandle<()>, SocketAddr) {
        let socket = UdpSocket::bind(addr).await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, src)) => {
                        let _ = socket.send_to(&buf[..len], src).await;
                    }
                    Err(_) => break,
                }
            }
        });

        (handle, local_addr)
    }

    #[tokio::test]
    async fn test_udp_local_to_remote_forward() {
        let ports = get_free_ports(2).await;
        let local_port = ports[0];
        let remote_port = ports[1];

        let (echo_server, _) = start_udp_echo_server(&format!("127.0.0.1:{}", remote_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", local_port)]);
        let remotes = create_endpoints(vec![&format!("127.0.0.1:{}", remote_port)]);

        let forward = Forward::new(
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Udp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .connect(format!("127.0.0.1:{}", local_port))
            .await
            .unwrap();

        client.send(b"udp hello").await.unwrap();

        let mut buf = [0u8; 9];
        let result = timeout(Duration::from_secs(2), client.recv(&mut buf)).await;

        if result.is_ok() {
            assert_eq!(&buf, b"udp hello");
        }

        forward_task.abort();
        echo_server.abort();
    }
}

mod socks_proxy_tests {
    use super::*;
    use pivot::socks::UserPassAuth;

    #[tokio::test]
    async fn test_socks_server_basic() {
        let port = get_free_port().await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", port)]);

        let proxy = Proxy::new(locals, None, None, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        let mut response = [0u8; 2];
        let result = timeout(Duration::from_secs(2), client.read_exact(&mut response)).await;
        assert!(result.is_ok());
        assert_eq!(response, [0x05, 0x00]);

        proxy_task.abort();
    }

    #[tokio::test]
    async fn test_socks_server_with_auth() {
        let port = get_free_port().await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", port)]);
        let auth = Some(UserPassAuth::new("testuser:testpass".to_string()));

        let proxy = Proxy::new(locals, None, auth, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x02]);

        let mut auth_req = vec![0x01];
        auth_req.push(8);
        auth_req.extend_from_slice(b"testuser");
        auth_req.push(8);
        auth_req.extend_from_slice(b"testpass");
        client.write_all(&auth_req).await.unwrap();

        let mut auth_response = [0u8; 2];
        let result = timeout(
            Duration::from_secs(2),
            client.read_exact(&mut auth_response),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(auth_response, [0x01, 0x00]);

        proxy_task.abort();
    }

    #[tokio::test]
    async fn test_socks_server_auth_failure() {
        let port = get_free_port().await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", port)]);
        let auth = Some(UserPassAuth::new("testuser:testpass".to_string()));

        let proxy = Proxy::new(locals, None, auth, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();

        let mut auth_req = vec![0x01];
        auth_req.push(8);
        auth_req.extend_from_slice(b"wrongusr");
        auth_req.push(9);
        auth_req.extend_from_slice(b"wrongpass");
        client.write_all(&auth_req).await.unwrap();

        let mut auth_response = [0u8; 2];
        let result = timeout(
            Duration::from_secs(2),
            client.read_exact(&mut auth_response),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(auth_response[1], 0x01);

        proxy_task.abort();
    }

    #[tokio::test]
    async fn test_socks_connect_to_echo_server() {
        let echo_port = get_free_port().await;
        let socks_port = get_free_port().await;

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", echo_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", socks_port)]);
        let proxy = Proxy::new(locals, None, None, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
            .await
            .unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]);

        let ip_bytes: [u8; 4] = [127, 0, 0, 1];
        let port_bytes = (echo_port as u16).to_be_bytes();

        let mut connect_req = vec![0x05, 0x01, 0x00, 0x01];
        connect_req.extend_from_slice(&ip_bytes);
        connect_req.extend_from_slice(&port_bytes);
        client.write_all(&connect_req).await.unwrap();

        let mut connect_response = [0u8; 10];
        let result = timeout(
            Duration::from_secs(2),
            client.read_exact(&mut connect_response),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(connect_response[1], 0x00);

        client.write_all(b"socks test").await.unwrap();

        let mut echo_buf = [0u8; 10];
        let result = timeout(Duration::from_secs(2), client.read_exact(&mut echo_buf)).await;
        assert!(result.is_ok());
        assert_eq!(&echo_buf, b"socks test");

        proxy_task.abort();
        echo_server.abort();
    }
}

mod reuse_tests {
    use super::*;
    use pivot::reuse::Reuse;

    #[tokio::test]
    async fn test_reuse_creation() {
        let reuse = Reuse::new(
            "127.0.0.1:8080".to_string(),
            "127.0.0.1:22".to_string(),
            Some("127.0.0.1:80".to_string()),
            "1.2.3.4".to_string(),
            Some(10),
        );

        assert!(reuse.is_ok());
    }

    #[tokio::test]
    async fn test_reuse_invalid_local_address() {
        let reuse = Reuse::new(
            "invalid:address".to_string(),
            "127.0.0.1:22".to_string(),
            None,
            "1.2.3.4".to_string(),
            None,
        );

        assert!(reuse.is_err());
    }

    #[tokio::test]
    async fn test_reuse_invalid_remote_address() {
        let reuse = Reuse::new(
            "127.0.0.1:8080".to_string(),
            "not-an-address".to_string(),
            None,
            "1.2.3.4".to_string(),
            None,
        );

        assert!(reuse.is_err());
    }

    #[tokio::test]
    async fn test_reuse_invalid_external_address() {
        let reuse = Reuse::new(
            "127.0.0.1:8080".to_string(),
            "127.0.0.1:22".to_string(),
            None,
            "not-an-ip".to_string(),
            None,
        );

        assert!(reuse.is_err());
    }

    #[tokio::test]
    async fn test_reuse_with_timeout() {
        let ports = get_free_ports(2).await;
        let local_port = ports[0];
        let remote_port = ports[1];

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", remote_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reuse = Reuse::new(
            format!("127.0.0.1:{}", local_port),
            format!("127.0.0.1:{}", remote_port),
            None,
            "127.0.0.1".to_string(),
            Some(1),
        )
        .unwrap();

        let reuse_task = tokio::spawn(async move {
            let _ = reuse.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let connect_result = timeout(
            Duration::from_millis(500),
            TcpStream::connect(format!("127.0.0.1:{}", local_port)),
        )
        .await;

        if let Ok(Ok(mut client)) = connect_result {
            client.write_all(b"test").await.unwrap();

            let mut buf = [0u8; 4];
            let read_result = timeout(Duration::from_secs(1), client.read_exact(&mut buf)).await;

            if read_result.is_ok() {
                assert_eq!(&buf, b"test");
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;

        reuse_task.abort();
        echo_server.abort();
    }
}

#[cfg(target_family = "unix")]
mod unix_socket_tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::net::UnixListener;

    async fn start_unix_echo_server(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        })
    }

    #[tokio::test]
    async fn test_unix_socket_to_local_tcp() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        let echo_server = start_unix_echo_server(&socket_path).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let port = get_free_port().await;
        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", port)]);

        let forward = Forward::new(
            locals,
            vec![],
            Some(socket_path.to_string_lossy().to_string()),
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        client.write_all(b"unix test").await.unwrap();

        let mut buf = [0u8; 9];
        let result = timeout(Duration::from_secs(2), client.read_exact(&mut buf)).await;
        assert!(result.is_ok());
        assert_eq!(&buf, b"unix test");

        forward_task.abort();
        echo_server.abort();
    }
}

mod udp_unit_tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_local_to_local_forward() {
        let ports = get_free_ports(2).await;
        let port1 = ports[0];
        let port2 = ports[1];

        let locals = create_endpoints(vec![
            &format!("127.0.0.1:{}", port1),
            &format!("127.0.0.1:{}", port2),
        ]);

        let forward = Forward::new(
            locals,
            vec![],
            #[cfg(target_family = "unix")]
            None,
            Protocol::Udp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client1
            .send_to(&[0u8; 4], format!("127.0.0.1:{}", port1))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        client2
            .send_to(b"from c2", format!("127.0.0.1:{}", port2))
            .await
            .unwrap();

        let mut buf = [0u8; 7];
        let result = timeout(Duration::from_secs(2), client1.recv(&mut buf)).await;
        if result.is_ok() {
            assert_eq!(&buf, b"from c2");
        }

        forward_task.abort();
    }

    #[tokio::test]
    async fn test_udp_remote_to_remote_forward() {
        let ports = get_free_ports(2).await;
        let remote_port1 = ports[0];
        let remote_port2 = ports[1];

        let _server1 = UdpSocket::bind(format!("127.0.0.1:{}", remote_port1))
            .await
            .unwrap();
        let server2 = UdpSocket::bind(format!("127.0.0.1:{}", remote_port2))
            .await
            .unwrap();

        let remotes = create_endpoints(vec![
            &format!("127.0.0.1:{}", remote_port1),
            &format!("127.0.0.1:{}", remote_port2),
        ]);

        let forward = Forward::new(
            vec![],
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Udp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut buf = [0u8; 4];
        let result = timeout(Duration::from_secs(2), server2.recv_from(&mut buf)).await;
        if let Ok(Ok((len, addr))) = result {
            assert_eq!(len, 4);
            server2.send_to(b"reply", addr).await.unwrap();
        }

        forward_task.abort();
    }

    #[tokio::test]
    async fn test_udp_large_packet() {
        let ports = get_free_ports(2).await;
        let local_port = ports[0];
        let remote_port = ports[1];

        let server = UdpSocket::bind(format!("127.0.0.1:{}", remote_port))
            .await
            .unwrap();

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", local_port)]);
        let remotes = create_endpoints(vec![&format!("127.0.0.1:{}", remote_port)]);

        let forward = Forward::new(
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Udp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .connect(format!("127.0.0.1:{}", local_port))
            .await
            .unwrap();

        // Receive and discard handshake packet (4 bytes)
        let mut handshake_buf = [0u8; 4];
        let _ = timeout(Duration::from_secs(2), server.recv_from(&mut handshake_buf)).await;

        let large_data: Vec<u8> = (0..1400).map(|i| (i % 256) as u8).collect();
        client.send(&large_data).await.unwrap();

        let mut buf = vec![0u8; 1400];
        let result = timeout(Duration::from_secs(2), server.recv_from(&mut buf)).await;
        if let Ok(Ok((len, addr))) = result {
            assert_eq!(len, 1400);
            assert_eq!(&buf[..len], &large_data[..]);
            server.send_to(&buf[..len], addr).await.unwrap();

            let mut recv_buf = vec![0u8; 1400];
            let recv_result = timeout(Duration::from_secs(2), client.recv(&mut recv_buf)).await;
            if let Ok(Ok(recv_len)) = recv_result {
                assert_eq!(recv_len, 1400);
            }
        }

        forward_task.abort();
    }
}

mod tcp_remote_to_remote_tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_remote_to_remote_forward() {
        let ports = get_free_ports(2).await;
        let port1 = ports[0];
        let port2 = ports[1];

        let listener1 = TcpListener::bind(format!("127.0.0.1:{}", port1))
            .await
            .unwrap();
        let listener2 = TcpListener::bind(format!("127.0.0.1:{}", port2))
            .await
            .unwrap();

        let remotes = create_endpoints(vec![
            &format!("127.0.0.1:{}", port1),
            &format!("127.0.0.1:{}", port2),
        ]);

        let forward = Forward::new(
            vec![],
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let server1_task = tokio::spawn(async move {
            let (mut stream, _) = listener1.accept().await.unwrap();
            stream.write_all(b"from server1").await.unwrap();
            let mut buf = [0u8; 12];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"from server2");
        });

        let server2_task = tokio::spawn(async move {
            let (mut stream, _) = listener2.accept().await.unwrap();
            let mut buf = [0u8; 12];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"from server1");
            stream.write_all(b"from server2").await.unwrap();
        });

        let result = timeout(Duration::from_secs(3), async {
            server1_task.await.unwrap();
            server2_task.await.unwrap();
        })
        .await;

        assert!(result.is_ok());
        forward_task.abort();
    }

    #[tokio::test]
    async fn test_tcp_remote_to_remote_with_tls() {
        use pivot::crypto;

        let ports = get_free_ports(2).await;
        let port1 = ports[0];
        let port2 = ports[1];

        let acceptor1 = crypto::get_tls_acceptor("localhost").unwrap();
        let acceptor2 = crypto::get_tls_acceptor("localhost").unwrap();

        let listener1 = TcpListener::bind(format!("127.0.0.1:{}", port1))
            .await
            .unwrap();
        let listener2 = TcpListener::bind(format!("127.0.0.1:{}", port2))
            .await
            .unwrap();

        let remotes = create_endpoints(vec![
            &format!("+127.0.0.1:{}", port1),
            &format!("+127.0.0.1:{}", port2),
        ]);

        let forward = Forward::new(
            vec![],
            remotes,
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let server1_task = tokio::spawn(async move {
            let (stream, _) = listener1.accept().await.unwrap();
            let mut tls_stream = acceptor1.accept(stream).await.unwrap();
            tls_stream.write_all(b"tls1").await.unwrap();
            let mut buf = [0u8; 4];
            tls_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"tls2");
        });

        let server2_task = tokio::spawn(async move {
            let (stream, _) = listener2.accept().await.unwrap();
            let mut tls_stream = acceptor2.accept(stream).await.unwrap();
            let mut buf = [0u8; 4];
            tls_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"tls1");
            tls_stream.write_all(b"tls2").await.unwrap();
        });

        let result = timeout(Duration::from_secs(3), async {
            server1_task.await.unwrap();
            server2_task.await.unwrap();
        })
        .await;

        assert!(result.is_ok());
        forward_task.abort();
    }
}

mod socks_advanced_tests {
    use super::*;
    use pivot::socks::UserPassAuth;

    #[tokio::test]
    async fn test_socks_connect_domain() {
        let echo_port = get_free_port().await;
        let socks_port = get_free_port().await;

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", echo_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", socks_port)]);
        let proxy = Proxy::new(locals, None, None, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
            .await
            .unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]);

        let domain = "localhost";
        let port_bytes = (echo_port as u16).to_be_bytes();

        let mut connect_req = vec![0x05, 0x01, 0x00, 0x03];
        connect_req.push(domain.len() as u8);
        connect_req.extend_from_slice(domain.as_bytes());
        connect_req.extend_from_slice(&port_bytes);
        client.write_all(&connect_req).await.unwrap();

        let mut connect_response = [0u8; 10];
        let result = timeout(
            Duration::from_secs(2),
            client.read_exact(&mut connect_response),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(connect_response[1], 0x00);

        client.write_all(b"domain test").await.unwrap();

        let mut echo_buf = [0u8; 11];
        let result = timeout(Duration::from_secs(2), client.read_exact(&mut echo_buf)).await;
        assert!(result.is_ok());
        assert_eq!(&echo_buf, b"domain test");

        proxy_task.abort();
        echo_server.abort();
    }

    #[tokio::test]
    async fn test_socks_no_auth_method_available() {
        let port = get_free_port().await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", port)]);
        let auth = Some(UserPassAuth::new("user:pass".to_string()));

        let proxy = Proxy::new(locals, None, auth, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        let mut response = [0u8; 2];
        let result = timeout(Duration::from_secs(2), client.read_exact(&mut response)).await;
        assert!(result.is_ok());
        assert_eq!(response, [0x05, 0xff]);

        proxy_task.abort();
    }

    #[tokio::test]
    async fn test_socks_with_tls() {
        use pivot::crypto;

        let port = get_free_port().await;

        let locals = create_endpoints(vec![&format!("+127.0.0.1:{}", port)]);
        let proxy = Proxy::new(locals, None, None, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let connector = crypto::get_tls_connector();
        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        tls_stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        let mut response = [0u8; 2];
        let result = timeout(Duration::from_secs(2), tls_stream.read_exact(&mut response)).await;
        assert!(result.is_ok());
        assert_eq!(response, [0x05, 0x00]);

        proxy_task.abort();
    }

    #[tokio::test]
    async fn test_socks_connect_failure() {
        let socks_port = get_free_port().await;
        let nonexistent_port = get_free_port().await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", socks_port)]);
        let proxy = Proxy::new(locals, None, None, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
            .await
            .unwrap();

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();

        let ip_bytes: [u8; 4] = [127, 0, 0, 1];
        let port_bytes = (nonexistent_port as u16).to_be_bytes();

        let mut connect_req = vec![0x05, 0x01, 0x00, 0x01];
        connect_req.extend_from_slice(&ip_bytes);
        connect_req.extend_from_slice(&port_bytes);
        client.write_all(&connect_req).await.unwrap();

        let mut connect_response = [0u8; 10];
        let result = timeout(
            Duration::from_secs(2),
            client.read_exact(&mut connect_response),
        )
        .await;
        if let Ok(Ok(_)) = result {
            assert_ne!(connect_response[1], 0x00);
        }

        proxy_task.abort();
    }

    #[tokio::test]
    async fn test_socks_multiple_connections() {
        let echo_port = get_free_port().await;
        let socks_port = get_free_port().await;

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", echo_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", socks_port)]);
        let proxy = Proxy::new(locals, None, None, 32);

        let proxy_task = tokio::spawn(async move {
            let _ = proxy.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut tasks = vec![];
        for i in 0..3 {
            let socks_port = socks_port;
            let echo_port = echo_port;
            tasks.push(tokio::spawn(async move {
                let mut client = TcpStream::connect(format!("127.0.0.1:{}", socks_port))
                    .await
                    .unwrap();

                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut response = [0u8; 2];
                client.read_exact(&mut response).await.unwrap();

                let ip_bytes: [u8; 4] = [127, 0, 0, 1];
                let port_bytes = (echo_port as u16).to_be_bytes();

                let mut connect_req = vec![0x05, 0x01, 0x00, 0x01];
                connect_req.extend_from_slice(&ip_bytes);
                connect_req.extend_from_slice(&port_bytes);
                client.write_all(&connect_req).await.unwrap();

                let mut connect_response = [0u8; 10];
                client.read_exact(&mut connect_response).await.unwrap();

                let msg = format!("msg{}", i);
                client.write_all(msg.as_bytes()).await.unwrap();

                let mut echo_buf = vec![0u8; msg.len()];
                client.read_exact(&mut echo_buf).await.unwrap();
                assert_eq!(echo_buf, msg.as_bytes());
            }));
        }

        for task in tasks {
            let result = timeout(Duration::from_secs(5), task).await;
            assert!(result.is_ok());
        }

        proxy_task.abort();
        echo_server.abort();
    }
}

mod reuse_advanced_tests {
    use super::*;
    use pivot::reuse::Reuse;

    #[tokio::test]
    async fn test_reuse_with_fallback() {
        let ports = get_free_ports(3).await;
        let local_port = ports[0];
        let remote_port = ports[1];
        let fallback_port = ports[2];

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", remote_port)).await;
        let fallback_server = start_echo_server(&format!("127.0.0.1:{}", fallback_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reuse = Reuse::new(
            format!("127.0.0.1:{}", local_port),
            format!("127.0.0.1:{}", remote_port),
            Some(format!("127.0.0.1:{}", fallback_port)),
            "10.0.0.1".to_string(),
            Some(1),
        )
        .unwrap();

        let reuse_task = tokio::spawn(async move {
            let _ = reuse.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let connect_result = timeout(
            Duration::from_millis(500),
            TcpStream::connect(format!("127.0.0.1:{}", local_port)),
        )
        .await;

        if let Ok(Ok(mut client)) = connect_result {
            client.write_all(b"fallback test").await.unwrap();

            let mut buf = [0u8; 13];
            let read_result = timeout(Duration::from_secs(1), client.read_exact(&mut buf)).await;

            if read_result.is_ok() {
                assert_eq!(&buf, b"fallback test");
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;

        reuse_task.abort();
        echo_server.abort();
        fallback_server.abort();
    }

    #[tokio::test]
    async fn test_reuse_invalid_fallback_address() {
        let reuse = Reuse::new(
            "127.0.0.1:8080".to_string(),
            "127.0.0.1:22".to_string(),
            Some("not-valid".to_string()),
            "1.2.3.4".to_string(),
            None,
        );

        assert!(reuse.is_err());
    }

    #[tokio::test]
    async fn test_reuse_multiple_connections() {
        let ports = get_free_ports(2).await;
        let local_port = ports[0];
        let remote_port = ports[1];

        let echo_server = start_echo_server(&format!("127.0.0.1:{}", remote_port)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let reuse = Reuse::new(
            format!("127.0.0.1:{}", local_port),
            format!("127.0.0.1:{}", remote_port),
            Some(format!("127.0.0.1:{}", remote_port)),
            "10.0.0.1".to_string(),
            Some(2),
        )
        .unwrap();

        let reuse_task = tokio::spawn(async move {
            let _ = reuse.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut tasks = vec![];
        for i in 0..3 {
            let local_port = local_port;
            tasks.push(tokio::spawn(async move {
                let connect_result = timeout(
                    Duration::from_millis(500),
                    TcpStream::connect(format!("127.0.0.1:{}", local_port)),
                )
                .await;

                if let Ok(Ok(mut client)) = connect_result {
                    let msg = format!("msg{}", i);
                    client.write_all(msg.as_bytes()).await.unwrap();

                    let mut buf = vec![0u8; msg.len()];
                    let _ = timeout(Duration::from_secs(1), client.read_exact(&mut buf)).await;
                }
            }));
        }

        for task in tasks {
            let _ = timeout(Duration::from_secs(2), task).await;
        }

        tokio::time::sleep(Duration::from_secs(3)).await;

        reuse_task.abort();
        echo_server.abort();
    }
}

#[cfg(target_family = "unix")]
mod unix_socket_advanced_tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::net::UnixListener;

    async fn start_unix_echo_server(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(path).unwrap();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        })
    }

    #[tokio::test]
    async fn test_unix_socket_to_remote_tcp() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("remote.sock");

        let port = get_free_port().await;

        // Create a TCP listener first to receive the forwarded data
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        // Create a Unix listener that the forward will connect to
        let unix_listener = UnixListener::bind(&socket_path).unwrap();

        let remotes = create_endpoints(vec![&format!("127.0.0.1:{}", port)]);

        let forward = Forward::new(
            vec![],
            remotes,
            Some(socket_path.to_string_lossy().to_string()),
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Accept the connection from the forward on the Unix socket
        let (mut unix_stream, _) = unix_listener.accept().await.unwrap();

        // Spawn task to handle TCP connection
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 11];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"remote test");
            stream.write_all(b"reply").await.unwrap();
        });

        // Send test data through the Unix socket (will be forwarded to TCP)
        unix_stream.write_all(b"remote test").await.unwrap();

        let result = timeout(Duration::from_secs(3), server_task).await;
        assert!(result.is_ok());

        forward_task.abort();
    }

    #[tokio::test]
    async fn test_unix_socket_large_data() {
        let temp_dir = tempdir().unwrap();
        let socket_path = temp_dir.path().join("large.sock");

        let echo_server = start_unix_echo_server(&socket_path).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let port = get_free_port().await;
        let locals = create_endpoints(vec![&format!("127.0.0.1:{}", port)]);

        let forward = Forward::new(
            locals,
            vec![],
            Some(socket_path.to_string_lossy().to_string()),
            Protocol::Tcp,
            32,
        );

        let forward_task = tokio::spawn(async move {
            let _ = forward.start().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        let large_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        client.write_all(&large_data).await.unwrap();

        let mut received = vec![0u8; 8192];
        let result = timeout(Duration::from_secs(5), client.read_exact(&mut received)).await;
        assert!(result.is_ok());
        assert_eq!(received, large_data);

        forward_task.abort();
        echo_server.abort();
    }
}

mod error_handling_tests {
    use super::*;

    #[tokio::test]
    async fn test_forward_invalid_parameters() {
        let locals = create_endpoints(vec!["127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082"]);

        let forward = Forward::new(
            locals,
            vec![],
            #[cfg(target_family = "unix")]
            None,
            Protocol::Tcp,
            32,
        );

        let result = forward.start().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_proxy_invalid_parameters() {
        let locals = create_endpoints(vec!["127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082"]);

        let proxy = Proxy::new(locals, None, None, 32);
        let result = proxy.start().await;
        assert!(result.is_err());
    }
}

mod cli_tests {
    use clap::Parser;
    use pivot::Cli;

    #[test]
    fn test_cli_forward_mode_parsing() {
        let args = vec!["pivot", "fwd", "-l", "8080", "-r", "127.0.0.1:9090"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_forward_mode_with_tls() {
        let args = vec!["pivot", "fwd", "-l", "+8080", "-r", "+127.0.0.1:9090"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_forward_mode_udp() {
        let args = vec![
            "pivot",
            "fwd",
            "-l",
            "8080",
            "-r",
            "127.0.0.1:9090",
            "-p",
            "udp",
        ];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_proxy_mode_basic() {
        let args = vec!["pivot", "proxy", "-l", "1080"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_proxy_mode_with_auth() {
        let args = vec!["pivot", "proxy", "-l", "1080", "-a", "user:pass"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_proxy_mode_reverse() {
        let args = vec!["pivot", "proxy", "-l", "7777", "-l", "8888"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_reuse_mode() {
        let args = vec![
            "pivot",
            "reuse",
            "-l",
            "192.168.1.1:80",
            "-r",
            "127.0.0.1:22",
            "-e",
            "1.2.3.4",
        ];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_reuse_mode_with_fallback() {
        let args = vec![
            "pivot",
            "reuse",
            "-l",
            "192.168.1.1:80",
            "-r",
            "127.0.0.1:22",
            "-f",
            "127.0.0.1:80",
            "-e",
            "1.2.3.4",
        ];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_reuse_mode_with_timeout() {
        let args = vec![
            "pivot",
            "reuse",
            "-l",
            "192.168.1.1:80",
            "-r",
            "127.0.0.1:22",
            "-e",
            "1.2.3.4",
            "-t",
            "30",
        ];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_forward_mode_connections() {
        let args = vec!["pivot", "fwd", "-l", "8080", "-l", "9090", "-c", "64"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cli_invalid_command() {
        let args = vec!["pivot", "invalid"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());
    }
}
