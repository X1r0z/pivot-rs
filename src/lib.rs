use std::io::Result;

use clap::{Parser, Subcommand};
use forward::Forward;
use proxy::Proxy;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use reuse::Reuse;
use tracing::info;

pub mod crypto;
pub mod forward;
pub mod proxy;
pub mod reuse;
pub mod socks;
pub mod tcp;
pub mod udp;

#[derive(Parser)]
#[command(author, version, about = "Pivot: Port-Forwarding and Proxy Tool")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Port forwarding mode
    Fwd {
        /// Local listen IP address, format: [+][IP:]PORT
        #[arg(short, long)]
        local: Vec<String>,

        /// Remote connect IP address, format: [+]IP:PORT
        #[arg(short, long)]
        remote: Vec<String>,

        /// Unix domain socket path
        #[arg(short, long)]
        socket: Option<String>,

        /// Enable UDP forward mode
        #[arg(short, long)]
        udp: bool,
    },

    /// Socks proxy mode
    Proxy {
        /// Local listen IP address, format: [+][IP:]PORT
        #[arg(short, long)]
        local: Vec<String>,

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
        fallback: String,

        /// External IP address, format: IP
        #[arg(short, long)]
        external: String,
    },
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Fwd {
            mut local,
            mut remote,
            socket,
            udp,
        } => {
            info!("Starting forward mode");

            if udp {
                info!("Using UDP protocol");
            } else {
                info!("Using TCP protocol");
            }

            let mut local_opts = Vec::new();
            let mut remote_opts = Vec::new();

            load_opts(&mut local, &mut local_opts);
            load_opts(&mut remote, &mut remote_opts);

            format_addrs(&mut local);

            let forward = Forward::new(local, remote, local_opts, remote_opts, socket, udp);
            forward.start().await?;
        }
        Commands::Proxy {
            mut local,
            remote,
            auth,
        } => {
            info!("Starting proxy mode");

            let mut local_opts = Vec::new();
            let mut remote_opt = false;

            load_opts(&mut local, &mut local_opts);
            format_addrs(&mut local);

            let remote = match remote {
                Some(remote) => Some(if remote.starts_with('+') {
                    remote_opt = true;
                    remote.replace("+", "")
                } else {
                    remote
                }),
                None => None,
            };

            let auth_info = match auth {
                Some(auth) => Some(socks::AuthInfo::new(auth)),
                None => None,
            };

            let proxy = Proxy::new(local, remote, local_opts, remote_opt, auth_info);
            proxy.start().await?;
        }
        Commands::Reuse {
            local,
            remote,
            fallback,
            external,
        } => {
            let reuse = Reuse::new(local, remote, fallback, external);
            reuse.start().await?;
        }
    }

    Ok(())
}

pub fn load_opts(addrs: &mut Vec<String>, opts: &mut Vec<bool>) {
    for addr in addrs {
        if addr.starts_with('+') {
            *addr = addr.replace("+", "");
            opts.push(true);
        } else {
            opts.push(false);
        }
    }
}

pub fn format_addrs(addrs: &mut Vec<String>) {
    for addr in addrs {
        if !addr.contains(":") {
            *addr = "0.0.0.0:".to_string() + addr;
        }
    }
}

pub fn generate_random_string(length: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
