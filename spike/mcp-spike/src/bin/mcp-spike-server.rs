//! Spike server binary.
//!
//!   mcp-spike-server --transport stdio
//!   mcp-spike-server --transport http --bind 127.0.0.1:8765 --token-env SPIKE_TOKEN
//!
//! stdout carries only protocol frames in stdio mode; all logs go to stderr.

use anyhow::{Context, bail};
use mcp_spike::{Shared, SpikeServer, serve_http};
use rmcp::{ServiceExt, transport::stdio};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rmcp=info".into()),
        )
        .init();

    let mut transport = "stdio".to_string();
    let mut bind = "127.0.0.1:0".to_string();
    let mut token_env = "SPIKE_TOKEN".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--transport" => transport = args.next().context("--transport needs a value")?,
            "--bind" => bind = args.next().context("--bind needs a value")?,
            "--token-env" => token_env = args.next().context("--token-env needs a value")?,
            other => bail!("unknown argument {other}"),
        }
    }

    let shared = Shared::new();
    match transport.as_str() {
        "stdio" => {
            tracing::info!(epoch = %shared.epoch, "starting stdio server");
            let running = SpikeServer::new(shared).serve(stdio()).await?;
            running.waiting().await?;
        }
        "http" => {
            let token = std::env::var(&token_env)
                .with_context(|| format!("bearer token must be provided in ${token_env}"))?;
            if token.len() < 16 {
                bail!("token in ${token_env} is shorter than 16 bytes");
            }
            let addr: std::net::SocketAddr = bind.parse().context("--bind must be ip:port")?;
            if !addr.ip().is_loopback() {
                bail!("refusing non-loopback bind {addr} in the spike");
            }
            let listener = tokio::net::TcpListener::bind(addr).await?;
            // Single machine-readable line on stdout so scripts can find the port.
            println!("LISTENING {}", listener.local_addr()?);
            tracing::info!(addr = %listener.local_addr()?, epoch = %shared.epoch, "http server up");
            let ct = CancellationToken::new();
            let ct2 = ct.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                ct2.cancel();
            });
            serve_http(listener, shared, &token, ct).await?;
        }
        other => bail!("unknown transport {other}"),
    }
    Ok(())
}
