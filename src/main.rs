use anyhow::Result;
use clap::Parser;
use pivot::Cli;
use tracing::error;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    if let Err(e) = pivot::run(cli).await {
        error!("error: {}", e);
    }

    Ok(())
}
