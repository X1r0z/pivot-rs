use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, info};

use crate::{tcp, util};

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;

#[derive(Clone)]
pub struct UserPassAuth {
    user: String,
    pass: String,
}

#[derive(Clone, Copy, Debug)]
enum AddrType {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

impl TryFrom<u8> for AddrType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(AddrType::Ipv4),
            0x03 => Ok(AddrType::Domain),
            0x04 => Ok(AddrType::Ipv6),
            _ => Err(anyhow!("Unsupported address type: {}", value)),
        }
    }
}

#[derive(Debug)]
struct SocksRequest {
    cmd: u8,
    addr_type: AddrType,
    addr: Vec<u8>,
    port: u16,
}

impl UserPassAuth {
    pub fn new(s: String) -> Self {
        let mut split = s.split(':');

        let (user, pass) = match (split.next(), split.next(), split.next()) {
            (Some(user), Some(pass), None) => (user.to_string(), pass.to_string()),
            _ => (
                util::generate_random_string(12),
                util::generate_random_string(12),
            ),
        };

        debug!("user: {} pass: {}", user, pass);
        info!("Authentication enabled");
        Self { user, pass }
    }

    fn verify(&self, user: &str, pass: &str) -> bool {
        self.user == user && self.pass == pass
    }
}

impl SocksRequest {
    fn parse_addr(&self) -> String {
        match self.addr_type {
            AddrType::Ipv4 => {
                format!(
                    "{}:{}",
                    self.addr
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>()
                        .join("."),
                    self.port
                )
            }
            AddrType::Domain => {
                format!("{}:{}", String::from_utf8_lossy(&self.addr[1..]), self.port)
            }
            AddrType::Ipv6 => {
                format!(
                    "[{}]:{}",
                    self.addr
                        .chunks(2)
                        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                        .collect::<Vec<_>>()
                        .join(":"),
                    self.port
                )
            }
        }
    }
}

pub async fn handle_connection<S>(mut stream: S, auth: &Option<UserPassAuth>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let methods = socks_read_handshake(&mut stream).await?;
    socks_authenticate(&mut stream, methods, auth).await?;
    let request = socks_read_request(&mut stream).await?;
    let remote_stream = socks_connect(&mut stream, request.parse_addr()).await?;

    tcp::forward(stream, remote_stream).await
}

pub async fn handle_forwarding<S1, S2>(
    mut client_stream: S1,
    mut remote_stream: S2,
    auth: Arc<UserPassAuth>,
) -> Result<()>
where
    S1: AsyncRead + AsyncWrite + Unpin,
    S2: AsyncRead + AsyncWrite + Unpin,
{
    let methods = socks_read_handshake(&mut client_stream).await?;
    socks_authenticate(&mut client_stream, methods, &None).await?;
    let request = socks_read_request(&mut client_stream).await?;

    socks_send_handshake(&mut remote_stream, &auth).await?;
    socks_send_request(&mut remote_stream, &request).await?;

    let response = socks_read_response(&mut remote_stream).await?;
    client_stream.write_all(&response).await?;

    tcp::forward(client_stream, remote_stream).await
}

async fn socks_connect<S>(stream: &mut S, addr: String) -> Result<tcp::ForwardStream>
where
    S: AsyncWrite + Unpin,
{
    match TcpStream::connect(&addr).await {
        Ok(s) => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            info!("Connect to {} success", addr);
            Ok(tcp::ForwardStream::Tcp(s))
        }
        Err(e) => {
            stream
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Err(e.into())
        }
    }
}

async fn socks_read_handshake<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;

    let [ver, nmethods] = header;

    if ver != SOCKS5_VERSION {
        return Err(anyhow!("Only support SOCKS5 protocol"));
    }

    let mut methods = vec![0u8; nmethods as usize];
    reader.read_exact(&mut methods).await?;

    Ok(methods)
}

async fn socks_authenticate<S>(
    stream: &mut S,
    methods: Vec<u8>,
    auth: &Option<UserPassAuth>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(auth) = auth else {
        stream.write_all(&[SOCKS5_VERSION, 0x00]).await?;
        return Ok(());
    };

    if !methods.contains(&0x02) {
        stream.write_all(&[SOCKS5_VERSION, 0xff]).await?;
        return Err(anyhow!("No supported authentication method"));
    }

    stream.write_all(&[SOCKS5_VERSION, 0x02]).await?;

    let mut auth_buf = [0u8; 2];
    stream.read_exact(&mut auth_buf).await?;

    if auth_buf[0] != AUTH_VERSION {
        return Err(anyhow!("Invalid authentication version"));
    }

    let ulen = auth_buf[1] as usize;
    let mut user = vec![0u8; ulen];
    stream.read_exact(&mut user).await?;

    let plen = stream.read_u8().await? as usize;
    let mut pass = vec![0u8; plen];
    stream.read_exact(&mut pass).await?;

    let user = String::from_utf8_lossy(&user);
    let pass = String::from_utf8_lossy(&pass);

    if auth.verify(&user, &pass) {
        stream.write_all(&[AUTH_VERSION, 0x00]).await?;
        Ok(())
    } else {
        stream.write_all(&[AUTH_VERSION, 0x01]).await?;
        Err(anyhow!("Authentication failed"))
    }
}

async fn socks_read_request<R>(reader: &mut R) -> Result<SocksRequest>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;

    let [ver, cmd, _, atyp] = header;

    if ver != SOCKS5_VERSION {
        return Err(anyhow!("Invalid SOCKS5 version"));
    }

    if cmd != CMD_CONNECT {
        return Err(anyhow!("Only CONNECT command is supported"));
    }

    let addr_type = AddrType::try_from(atyp)?;

    let addr = match addr_type {
        AddrType::Ipv4 => {
            let mut addr = [0u8; 4];
            reader.read_exact(&mut addr).await?;
            addr.to_vec()
        }
        AddrType::Domain => {
            let len = reader.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            reader.read_exact(&mut domain).await?;

            let mut full = vec![len as u8];
            full.extend_from_slice(&domain);
            full
        }
        AddrType::Ipv6 => {
            let mut addr = [0u8; 16];
            reader.read_exact(&mut addr).await?;
            addr.to_vec()
        }
    };

    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(SocksRequest {
        cmd,
        addr_type,
        addr,
        port,
    })
}

async fn socks_send_handshake<S>(stream: &mut S, auth: &UserPassAuth) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&[SOCKS5_VERSION, 0x01, 0x02]).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[0] != SOCKS5_VERSION || response[1] != 0x02 {
        return Err(anyhow!(
            "Remote proxy does not support username/password authentication"
        ));
    }

    let user = auth.user.as_bytes();
    let pass = auth.pass.as_bytes();

    let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
    auth_req.push(AUTH_VERSION);
    auth_req.push(user.len() as u8);
    auth_req.extend_from_slice(user);
    auth_req.push(pass.len() as u8);
    auth_req.extend_from_slice(pass);
    stream.write_all(&auth_req).await?;

    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await?;

    if auth_resp[1] != 0 {
        return Err(anyhow!(
            "Remote proxy username/password authentication failed"
        ));
    }

    Ok(())
}

async fn socks_send_request<W>(writer: &mut W, request: &SocksRequest) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(&[SOCKS5_VERSION, request.cmd, 0x00, request.addr_type as u8])
        .await?;
    writer.write_all(&request.addr).await?;
    writer.write_all(&request.port.to_be_bytes()).await?;
    Ok(())
}

async fn socks_read_response<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut response = Vec::new();

    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    response.extend_from_slice(&header);

    let addr_type = AddrType::try_from(header[3])?;
    let addr_len = match addr_type {
        AddrType::Ipv4 => 4,
        AddrType::Domain => {
            let mut len_buf = [0u8; 1];
            reader.read_exact(&mut len_buf).await?;
            response.push(len_buf[0]);
            len_buf[0] as usize
        }
        AddrType::Ipv6 => 16,
    };

    let mut addr = vec![0u8; addr_len];
    reader.read_exact(&mut addr).await?;
    response.extend_from_slice(&addr);

    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    response.extend_from_slice(&port_buf);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_pass_auth_new_valid() {
        let auth = UserPassAuth::new("admin:password123".to_string());
        assert_eq!(auth.user, "admin");
        assert_eq!(auth.pass, "password123");
    }

    #[test]
    fn test_user_pass_auth_new_random() {
        let auth = UserPassAuth::new("random".to_string());
        assert_eq!(auth.user.len(), 12);
        assert_eq!(auth.pass.len(), 12);
        assert!(auth.user.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(auth.pass.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_user_pass_auth_new_empty() {
        let auth = UserPassAuth::new("".to_string());
        assert_eq!(auth.user.len(), 12);
        assert_eq!(auth.pass.len(), 12);
    }

    #[test]
    fn test_user_pass_auth_new_only_colon() {
        let auth = UserPassAuth::new(":".to_string());
        assert_eq!(auth.user, "");
        assert_eq!(auth.pass, "");
    }

    #[test]
    fn test_user_pass_auth_new_multiple_colons() {
        let auth = UserPassAuth::new("user:pass:extra".to_string());
        assert_eq!(auth.user.len(), 12);
        assert_eq!(auth.pass.len(), 12);
    }

    #[test]
    fn test_user_pass_auth_verify_success() {
        let auth = UserPassAuth::new("testuser:testpass".to_string());
        assert!(auth.verify("testuser", "testpass"));
    }

    #[test]
    fn test_user_pass_auth_verify_wrong_user() {
        let auth = UserPassAuth::new("testuser:testpass".to_string());
        assert!(!auth.verify("wronguser", "testpass"));
    }

    #[test]
    fn test_user_pass_auth_verify_wrong_pass() {
        let auth = UserPassAuth::new("testuser:testpass".to_string());
        assert!(!auth.verify("testuser", "wrongpass"));
    }

    #[test]
    fn test_user_pass_auth_verify_both_wrong() {
        let auth = UserPassAuth::new("testuser:testpass".to_string());
        assert!(!auth.verify("wronguser", "wrongpass"));
    }

    #[test]
    fn test_addr_type_try_from_ipv4() {
        let addr_type = AddrType::try_from(0x01).unwrap();
        assert!(matches!(addr_type, AddrType::Ipv4));
    }

    #[test]
    fn test_addr_type_try_from_domain() {
        let addr_type = AddrType::try_from(0x03).unwrap();
        assert!(matches!(addr_type, AddrType::Domain));
    }

    #[test]
    fn test_addr_type_try_from_ipv6() {
        let addr_type = AddrType::try_from(0x04).unwrap();
        assert!(matches!(addr_type, AddrType::Ipv6));
    }

    #[test]
    fn test_addr_type_try_from_invalid() {
        let result = AddrType::try_from(0x00);
        assert!(result.is_err());

        let result = AddrType::try_from(0x02);
        assert!(result.is_err());

        let result = AddrType::try_from(0x05);
        assert!(result.is_err());

        let result = AddrType::try_from(0xff);
        assert!(result.is_err());
    }

    #[test]
    fn test_socks_request_parse_addr_ipv4() {
        let request = SocksRequest {
            cmd: CMD_CONNECT,
            addr_type: AddrType::Ipv4,
            addr: vec![192, 168, 1, 1],
            port: 8080,
        };
        assert_eq!(request.parse_addr(), "192.168.1.1:8080");
    }

    #[test]
    fn test_socks_request_parse_addr_ipv4_localhost() {
        let request = SocksRequest {
            cmd: CMD_CONNECT,
            addr_type: AddrType::Ipv4,
            addr: vec![127, 0, 0, 1],
            port: 80,
        };
        assert_eq!(request.parse_addr(), "127.0.0.1:80");
    }

    #[test]
    fn test_socks_request_parse_addr_domain() {
        let domain = "example.com";
        let mut addr = vec![domain.len() as u8];
        addr.extend_from_slice(domain.as_bytes());

        let request = SocksRequest {
            cmd: CMD_CONNECT,
            addr_type: AddrType::Domain,
            addr,
            port: 443,
        };
        assert_eq!(request.parse_addr(), "example.com:443");
    }

    #[test]
    fn test_socks_request_parse_addr_domain_subdomain() {
        let domain = "sub.example.com";
        let mut addr = vec![domain.len() as u8];
        addr.extend_from_slice(domain.as_bytes());

        let request = SocksRequest {
            cmd: CMD_CONNECT,
            addr_type: AddrType::Domain,
            addr,
            port: 8443,
        };
        assert_eq!(request.parse_addr(), "sub.example.com:8443");
    }

    #[test]
    fn test_socks_request_parse_addr_ipv6() {
        let request = SocksRequest {
            cmd: CMD_CONNECT,
            addr_type: AddrType::Ipv6,
            addr: vec![
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ],
            port: 80,
        };
        assert_eq!(
            request.parse_addr(),
            "[2001:0db8:0000:0000:0000:0000:0000:0001]:80"
        );
    }

    #[test]
    fn test_socks_request_parse_addr_ipv6_localhost() {
        let request = SocksRequest {
            cmd: CMD_CONNECT,
            addr_type: AddrType::Ipv6,
            addr: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 8080,
        };
        assert_eq!(
            request.parse_addr(),
            "[0000:0000:0000:0000:0000:0000:0000:0001]:8080"
        );
    }

    #[tokio::test]
    async fn test_socks_read_handshake_valid() {
        let data = vec![0x05, 0x02, 0x00, 0x02];
        let mut cursor = std::io::Cursor::new(data);

        let methods = socks_read_handshake(&mut cursor).await.unwrap();
        assert_eq!(methods, vec![0x00, 0x02]);
    }

    #[tokio::test]
    async fn test_socks_read_handshake_single_method() {
        let data = vec![0x05, 0x01, 0x00];
        let mut cursor = std::io::Cursor::new(data);

        let methods = socks_read_handshake(&mut cursor).await.unwrap();
        assert_eq!(methods, vec![0x00]);
    }

    #[tokio::test]
    async fn test_socks_read_handshake_invalid_version() {
        let data = vec![0x04, 0x01, 0x00];
        let mut cursor = std::io::Cursor::new(data);

        let result = socks_read_handshake(&mut cursor).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("SOCKS5"));
    }

    #[tokio::test]
    async fn test_socks_read_request_ipv4() {
        let data = vec![0x05, 0x01, 0x00, 0x01, 192, 168, 1, 100, 0x1F, 0x90];
        let mut cursor = std::io::Cursor::new(data);

        let request = socks_read_request(&mut cursor).await.unwrap();
        assert_eq!(request.cmd, CMD_CONNECT);
        assert!(matches!(request.addr_type, AddrType::Ipv4));
        assert_eq!(request.addr, vec![192, 168, 1, 100]);
        assert_eq!(request.port, 8080);
    }

    #[tokio::test]
    async fn test_socks_read_request_domain() {
        let domain = "test.com";
        let mut data = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        data.extend_from_slice(domain.as_bytes());
        data.extend_from_slice(&[0x00, 0x50]);

        let mut cursor = std::io::Cursor::new(data);

        let request = socks_read_request(&mut cursor).await.unwrap();
        assert_eq!(request.cmd, CMD_CONNECT);
        assert!(matches!(request.addr_type, AddrType::Domain));
        assert_eq!(request.port, 80);
    }

    #[tokio::test]
    async fn test_socks_read_request_ipv6() {
        let mut data = vec![0x05, 0x01, 0x00, 0x04];
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x01, 0xBB]);

        let mut cursor = std::io::Cursor::new(data);

        let request = socks_read_request(&mut cursor).await.unwrap();
        assert_eq!(request.cmd, CMD_CONNECT);
        assert!(matches!(request.addr_type, AddrType::Ipv6));
        assert_eq!(request.port, 443);
    }

    #[tokio::test]
    async fn test_socks_read_request_invalid_version() {
        let data = vec![0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
        let mut cursor = std::io::Cursor::new(data);

        let result = socks_read_request(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_socks_read_request_unsupported_cmd() {
        let data = vec![0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
        let mut cursor = std::io::Cursor::new(data);

        let result = socks_read_request(&mut cursor).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CONNECT"));
    }

    #[tokio::test]
    async fn test_socks_authenticate_no_auth() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let methods = vec![0x00];

        let auth_task = tokio::spawn(async move {
            socks_authenticate(&mut server, methods, &None)
                .await
                .unwrap();
        });

        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x05, 0x00]);

        auth_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks_send_request() {
        let request = SocksRequest {
            cmd: CMD_CONNECT,
            addr_type: AddrType::Ipv4,
            addr: vec![127, 0, 0, 1],
            port: 8080,
        };

        let mut buf = Vec::new();
        socks_send_request(&mut buf, &request).await.unwrap();

        assert_eq!(buf, vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90,]);
    }

    #[tokio::test]
    async fn test_socks_read_response_ipv4() {
        let data = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00];
        let mut cursor = std::io::Cursor::new(data.clone());

        let response = socks_read_response(&mut cursor).await.unwrap();
        assert_eq!(response, data);
    }

    #[tokio::test]
    async fn test_socks_read_response_domain() {
        let domain = "example.com";
        let mut data = vec![0x05, 0x00, 0x00, 0x03, domain.len() as u8];
        data.extend_from_slice(domain.as_bytes());
        data.extend_from_slice(&[0x00, 0x50]);

        let mut cursor = std::io::Cursor::new(data.clone());

        let response = socks_read_response(&mut cursor).await.unwrap();
        assert_eq!(response, data);
    }
}
