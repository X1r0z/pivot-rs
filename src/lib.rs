use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use forward::Forward;
use proxy::Proxy;
use reuse::Reuse;
use tracing::info;

mod crypto;
mod forward;
mod proxy;
mod reuse;
mod socks;
mod tcp;
mod udp;
mod util;

pub const MAX_CONNECTIONS: usize = 32;
pub const MAX_MUX_CONNECTIONS: usize = 128;

#[derive(Parser)]
#[command(author, version, about = "Pivot: Port-Forwarding and Proxy Tool")]
pub struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Port forwarding mode
    #[clap(name = "fwd")]
    Forward {
        /// Local listen IP address, format: [+][IP:]PORT
        #[arg(short, long)]
        locals: Vec<String>,

        /// Remote connect IP address, format: [+]IP:PORT
        #[arg(short, long)]
        remotes: Vec<String>,

        /// Unix domain socket path
        #[cfg(target_family = "unix")]
        #[arg(short, long)]
        socket: Option<String>,

        /// Forward Protocol
        #[arg(short, long)]
        #[clap(value_enum, default_value = "tcp")]
        protocol: Protocol,
    },

    /// Socks proxy mode
    Proxy {
        /// Local listen IP address, format: [+][IP:]PORT
        #[arg(short, long)]
        locals: Vec<String>,

        /// Reverse server IP address, format: [+]IP:PORT
        #[arg(short, long)]
        remote: Option<String>,

        /// Authentication info, format: user:pass (other for random)
        #[arg(short, long)]
        auth: Option<String>,
    },

    /// Port reuse mode
    Reuse {
        /// Local reuse IP address, format: IP:PORT
        #[arg(short, long)]
        local: String,

        /// Remote redirect IP address, format: IP:PORT
        #[arg(short, long)]
        remote: String,

        /// Fallback IP address, format: IP:PORT
        #[arg(short, long)]
        fallback: Option<String>,

        /// External IP address, format: IP
        #[arg(short, long)]
        external: String,

        /// Timeout to stop port reuse
        #[arg(short, long)]
        timeout: Option<u64>,
    },
}

#[derive(Clone, ValueEnum)]
enum Protocol {
    /// TCP Protocol
    Tcp,
    /// UDP Protocol
    Udp,
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.mode {
        Mode::Forward {
            locals,
            remotes,
            #[cfg(target_family = "unix")]
            socket,
            protocol,
        } => {
            info!("Starting forward mode");

            match protocol {
                Protocol::Tcp => info!("Using TCP protocol"),
                Protocol::Udp => info!("Using UDP protocol"),
            }

            let locals = util::parse_addrs(locals);
            let remotes = util::parse_addrs(remotes);

            let forward = Forward::new(
                locals,
                remotes,
                #[cfg(target_family = "unix")]
                socket,
                protocol,
            );

            forward.start().await?;
        }
        Mode::Proxy {
            locals,
            remote,
            auth,
        } => {
            info!("Starting proxy mode");

            let locals = util::parse_addrs(locals);
            let remote = util::parse_addr(remote);
            let auth = auth.map(|v| socks::UserPassAuth::new(v));

            let proxy = Proxy::new(locals, remote, auth);
            proxy.start().await?;
        }
        Mode::Reuse {
            local,
            remote,
            fallback,
            external,
            timeout,
        } => {
            info!("Starting reuse mode");

            let reuse = Reuse::new(local, remote, fallback, external, timeout);
            reuse.start().await?;
        }
    }

    Ok(())
}
