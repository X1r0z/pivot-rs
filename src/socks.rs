use std::{
    io::{Error, Result},
    sync::Arc,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tracing::info;

use crate::{
    tcp::{self, NetStream},
    util,
};

#[derive(Clone)]
pub struct SocksAuth {
    pub user: String,
    pub pass: String,
}

struct SocksRequest {
    cmd: u8,
    atyp: u8,
    dest_addr: Vec<u8>,
    dest_port: u16,
}

impl SocksAuth {
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

pub async fn handle_socks_connection(
    client_stream: NetStream,
    auth: &Option<SocksAuth>,
) -> Result<()> {
    let (mut cr, mut cw) = client_stream.split();

    // handshake
    let mut handshake = [0u8; 2];
    cr.read_exact(&mut handshake).await?;

    if handshake[0] != 0x05 {
        return Err(Error::new(
            std::io::ErrorKind::Unsupported,
            "Only support SOCKS5 protocol",
        ));
    }

    let nmethods = handshake[1] as usize;
    let mut methods = vec![0u8; nmethods];
    cr.read_exact(&mut methods).await?;

    match auth {
        Some(auth) => {
            // check username and password authentication
            handle_socks_auth(&mut cr, &mut cw, methods, auth).await?;
        }
        None => {
            // no auth required
            cw.write_all(&[0x05, 0x00]).await?;
        }
    }

    // read socks request
    let request = read_socks_request(&mut cr).await?;
    let addr = format_addr(request.atyp, &request.dest_addr, request.dest_port);

    // connect to the target server
    let remote_stream = NetStream::Tcp(match TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(e) => {
            cw.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(e.into());
        }
    });

    // send success response
    cw.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    let (rr, rw) = remote_stream.split();

    // forward data
    tcp::handle_split_forward((cr, cw), (rr, rw)).await
}

pub async fn handle_socks_forward(
    client_stream: NetStream,
    remote_stream: NetStream,
    auth: Arc<SocksAuth>,
) -> Result<()> {
    let (mut cr, mut cw) = client_stream.split();
    let (mut rr, mut rw) = remote_stream.split();

    // handshake
    let mut handshake = [0u8; 2];
    cr.read_exact(&mut handshake).await?;

    if handshake[0] != 0x05 {
        return Err(Error::new(
            std::io::ErrorKind::Unsupported,
            "Only support SOCKS5 protocol",
        ));
    }

    let nmethods = handshake[1] as usize;
    let mut methods = vec![0u8; nmethods];
    cr.read_exact(&mut methods).await?;

    // no auth required
    cw.write_all(&[0x05, 0x00]).await?;

    // read socks request
    let request = read_socks_request(&mut cr).await?;

    // send handshake with remote proxy
    send_socks_handshake(&mut rr, &mut rw, &auth).await?;

    // send request to remote proxy
    send_socks_request(&mut rw, request).await?;

    // read reply from remote proxy
    let reply = read_socks_reply(&mut rr).await?;

    // send reply to client
    cw.write_all(&reply).await?;

    // forward data
    tcp::handle_split_forward((cr, cw), (rr, rw)).await?;

    Ok(())
}

async fn handle_socks_auth(
    reader: &mut Box<dyn AsyncRead + Unpin + Send>,
    writer: &mut Box<dyn AsyncWrite + Unpin + Send>,
    methods: Vec<u8>,
    auth: &SocksAuth,
) -> Result<()> {
    if !methods.contains(&0x02) {
        writer.write_all(&[0x05, 0xff]).await?;
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "No supported authentication method",
        ));
    }

    writer.write_all(&[0x05, 0x02]).await?;

    let mut auth_buf = [0u8; 2];
    reader.read_exact(&mut auth_buf).await?;

    if auth_buf[0] != 0x01 {
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid authentication version",
        ));
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
        return Err(Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Authentication failed",
        ));
    }

    Ok(())
}

async fn read_socks_request(
    reader: &mut Box<dyn AsyncRead + Unpin + Send>,
) -> Result<SocksRequest> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;

    if header[0] != 0x05 {
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid SOCKS5 request",
        ));
    }

    let cmd = header[1];
    let atyp = header[3];

    if cmd != 0x01 {
        return Err(Error::new(
            std::io::ErrorKind::Unsupported,
            "Only CONNECT command supported",
        ));
    }

    let dest_addr = match atyp {
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
            return Err(Error::new(
                std::io::ErrorKind::Unsupported,
                "Unsupported address type",
            ))
        }
    };

    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    let dest_port = u16::from_be_bytes(port_buf);

    Ok(SocksRequest {
        cmd,
        atyp,
        dest_addr,
        dest_port,
    })
}

async fn send_socks_handshake(
    reader: &mut Box<dyn AsyncRead + Unpin + Send>,
    writer: &mut Box<dyn AsyncWrite + Unpin + Send>,
    auth: &SocksAuth,
) -> Result<()> {
    // send handshake
    writer.write_all(&[0x05, 0x01, 0x02]).await?;

    let mut response = [0u8; 2];
    reader.read_exact(&mut response).await?;

    if response[0] != 0x05 || response[1] != 0x02 {
        return Err(Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Remote proxy does not support username/password authentication",
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
        return Err(Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Remote proxy username/password authentication failed",
        ));
    }

    Ok(())
}

async fn send_socks_request(
    writer: &mut Box<dyn AsyncWrite + Unpin + Send>,
    request: SocksRequest,
) -> Result<()> {
    writer
        .write_all(&[0x05, request.cmd, 0x00, request.atyp])
        .await?;
    writer.write_all(&request.dest_addr).await?;
    writer.write_all(&request.dest_port.to_be_bytes()).await?;
    Ok(())
}

async fn read_socks_reply(reader: &mut Box<dyn AsyncRead + Unpin + Send>) -> Result<Vec<u8>> {
    let mut reply = Vec::new();

    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    reply.extend_from_slice(&header);

    let atyp = header[3];
    let addr_len = match atyp {
        0x01 => 4, // IPv4
        0x03 => {
            // domain
            let mut len_buf = [0u8; 1];
            reader.read_exact(&mut len_buf).await?;
            reply.push(len_buf[0]);
            len_buf[0] as usize
        }
        0x04 => 16, // IPv6
        _ => {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid address type",
            ))
        }
    };

    let mut addr = vec![0u8; addr_len];
    reader.read_exact(&mut addr).await?;
    reply.extend_from_slice(&addr);

    let mut port_buf = [0u8; 2];
    reader.read_exact(&mut port_buf).await?;
    reply.extend_from_slice(&port_buf);

    Ok(reply)
}

fn format_addr(atyp: u8, addr: &[u8], port: u16) -> String {
    match atyp {
        0x01 => {
            // IPv4
            format!(
                "{}:{}",
                format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
                port
            )
        }
        0x03 => {
            // domain
            format!("{}:{}", String::from_utf8_lossy(&addr[1..]), port)
        }
        0x04 => {
            // IPv6
            format!(
                "{}:{}",
                format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ),
                port
            )
        }
        _ => unreachable!(),
    }
}
