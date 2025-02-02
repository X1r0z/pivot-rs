use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tracing::info;

use crate::{
    tcp::{self, ForwardStream},
    util,
};

#[derive(Clone)]
pub struct UserPassAuth {
    user: String,
    pass: String,
}

struct SocksRequest {
    cmd: u8,
    atyp: u8,
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

        info!("user: {} pass: {}", user, pass);
        Self { user, pass }
    }

    fn verfiy(&self, user: &str, pass: &str) -> bool {
        self.user == user && self.pass == pass
    }
}

impl SocksRequest {
    pub fn parse_addr(&self) -> String {
        match self.atyp {
            0x01 => {
                // IPv4
                format!(
                    "{}:{}",
                    self.addr
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<String>>()
                        .join("."),
                    self.port
                )
            }
            0x03 => {
                // domain
                format!("{}:{}", String::from_utf8_lossy(&self.addr[1..]), self.port)
            }
            0x04 => {
                // IPv6
                format!(
                    "{}:{}",
                    self.addr
                        .iter()
                        .map(|x| format!("{:x}", x))
                        .collect::<Vec<String>>()
                        .join(":"),
                    self.port
                )
            }
            _ => unreachable!(),
        }
    }
}

pub async fn handle_connection(
    client_stream: ForwardStream,
    auth: &Option<UserPassAuth>,
) -> Result<()> {
    let (mut cr, mut cw) = client_stream.split();

    // handshake
    let methods = socks_read_handshake(&mut cr).await?;

    // authentication
    socks_authenticate(&mut cr, &mut cw, methods, auth).await?;

    // read socks request
    let request = socks_read_request(&mut cr).await?;

    // connect to the target server
    let remote_stream = socks_connect(&mut cw, request.parse_addr()).await?;

    // forward data
    tcp::split_forward((cr, cw), remote_stream.split()).await
}

pub async fn handle_forwarding(
    client_stream: ForwardStream,
    remote_stream: ForwardStream,
    auth: Arc<UserPassAuth>,
) -> Result<()> {
    let (mut cr, mut cw) = client_stream.split();
    let (mut rr, mut rw) = remote_stream.split();

    // handshake
    let methods = socks_read_handshake(&mut cr).await?;

    // no auth required
    socks_authenticate(&mut cr, &mut cw, methods, &None).await?;

    // read socks message
    let request = socks_read_request(&mut cr).await?;

    // send handshake with remote proxy
    socks_send_handshake(&mut rr, &mut rw, &auth).await?;

    // send request to remote proxy
    socks_send_request(&mut rw, request).await?;

    // read response from remote proxy and send to client
    let response = socks_read_response(&mut rr).await?;
    cw.write_all(&response).await?;

    // forward data
    tcp::split_forward((cr, cw), (rr, rw)).await
}

async fn socks_connect(
    writer: &mut Box<dyn AsyncWrite + Unpin + Send>,
    addr: String,
) -> Result<ForwardStream> {
    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => {
            // send success response
            writer
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            stream
        }
        Err(e) => {
            // send error response
            writer
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(e.into());
        }
    };

    Ok(ForwardStream::Tcp(stream))
}

async fn socks_read_handshake(reader: &mut Box<dyn AsyncRead + Unpin + Send>) -> Result<Vec<u8>> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;

    let [ver, nmethods] = header;

    if ver != 0x05 {
        return Err(anyhow!("Only support SOCKS5 protocol"));
    }

    let mut methods = vec![0u8; nmethods as usize];
    reader.read_exact(&mut methods).await?;

    Ok(methods)
}

async fn socks_authenticate(
    reader: &mut Box<dyn AsyncRead + Unpin + Send>,
    writer: &mut Box<dyn AsyncWrite + Unpin + Send>,
    methods: Vec<u8>,
    auth: &Option<UserPassAuth>,
) -> Result<()> {
    let Some(auth) = auth else {
        // no auth required
        writer.write_all(&[0x05, 0x00]).await?;
        return Ok(());
    };

    if !methods.contains(&0x02) {
        writer.write_all(&[0x05, 0xff]).await?;
        return Err(anyhow!("No supported authentication method"));
    }

    writer.write_all(&[0x05, 0x02]).await?;

    let mut auth_buf = [0u8; 2];
    reader.read_exact(&mut auth_buf).await?;

    if auth_buf[0] != 0x01 {
        return Err(anyhow!("Invalid authentication version"));
    }

    // read user
    let ulen = auth_buf[1] as usize;
    let mut user = vec![0u8; ulen];
    reader.read_exact(&mut user).await?;

    // read pass
    let plen = reader.read_u8().await? as usize;
    let mut pass = vec![0u8; plen];
    reader.read_exact(&mut pass).await?;

    let user = String::from_utf8_lossy(&user);
    let pass = String::from_utf8_lossy(&pass);

    // check user and pass
    if auth.verfiy(&user, &pass) {
        writer.write_all(&[0x01, 0x00]).await?;
    } else {
        writer.write_all(&[0x01, 0x01]).await?;
        return Err(anyhow!("Authentication failed"));
    }

    Ok(())
}

async fn socks_read_request(
    reader: &mut Box<dyn AsyncRead + Unpin + Send>,
) -> Result<SocksRequest> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;

    let [ver, cmd, _, atyp] = header;

    if ver != 0x05 {
        return Err(anyhow!("Invalid SOCKS5 version"));
    }

    if cmd != 0x01 {
        return Err(anyhow!("Only CONNECT command is supported"));
    }

    let addr = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            reader.read_exact(&mut addr).await?;
            addr.to_vec()
        }
        0x03 => {
            // domain
            let len = reader.read_u8().await? as usize;

            let mut domain = vec![0u8; len];
            reader.read_exact(&mut domain).await?;

            let mut full = vec![len as u8];
            full.extend_from_slice(&domain);

            full
        }
        0x04 => {
            let mut addr = [0u8; 16];
            reader.read_exact(&mut addr).await?;
            addr.to_vec()
        }
        _ => {
            return Err(anyhow!("Unsupported address type"));
        }
    };

    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(SocksRequest {
        cmd,
        atyp,
        addr,
        port,
    })
}

async fn socks_send_handshake(
    reader: &mut Box<dyn AsyncRead + Unpin + Send>,
    writer: &mut Box<dyn AsyncWrite + Unpin + Send>,
    auth: &UserPassAuth,
) -> Result<()> {
    // send handshake
    writer.write_all(&[0x05, 0x01, 0x02]).await?;

    let mut response = [0u8; 2];
    reader.read_exact(&mut response).await?;

    if response[0] != 0x05 || response[1] != 0x02 {
        return Err(anyhow!(
            "Remote proxy does not support username/password authentication"
        ));
    }

    // send user/pass authentication
    let user = auth.user.as_bytes();
    let pass = auth.pass.as_bytes();

    let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());

    auth_req.push(0x01);
    auth_req.push(user.len() as u8);
    auth_req.extend_from_slice(user);

    auth_req.push(pass.len() as u8);
    auth_req.extend_from_slice(pass);
    writer.write_all(&auth_req).await?;

    // read authentication response
    let mut auth_resp = [0u8; 2];
    reader.read_exact(&mut auth_resp).await?;

    if auth_resp[1] != 0 {
        return Err(anyhow!(
            "Remote proxy username/password authentication failed"
        ));
    }

    Ok(())
}

async fn socks_send_request(
    writer: &mut Box<dyn AsyncWrite + Unpin + Send>,
    request: SocksRequest,
) -> Result<()> {
    writer
        .write_all(&[0x05, request.cmd, 0x00, request.atyp])
        .await?;
    writer.write_all(&request.addr).await?;
    writer.write_all(&request.port.to_be_bytes()).await?;
    Ok(())
}

async fn socks_read_response(reader: &mut Box<dyn AsyncRead + Unpin + Send>) -> Result<Vec<u8>> {
    let mut response = Vec::new();

    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    response.extend_from_slice(&header);

    let atyp = header[3];
    let addr_len = match atyp {
        0x01 => 4, // IPv4
        0x03 => {
            // domain
            let mut len_buf = [0u8; 1];
            reader.read_exact(&mut len_buf).await?;
            response.push(len_buf[0]);
            len_buf[0] as usize
        }
        0x04 => 16, // IPv6
        _ => {
            return Err(anyhow!("Invalid address type"));
        }
    };

    let mut addr = vec![0u8; addr_len];
    reader.read_exact(&mut addr).await?;
    response.extend_from_slice(&addr);

    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    response.extend_from_slice(&port_buf);

    Ok(response)
}
