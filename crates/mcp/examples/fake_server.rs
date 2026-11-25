//! Test server: serves an in-memory fake agent over stdio or loopback HTTP.
//!
//!   fake_server stdio
//!   FAKE_TOKEN=... fake_server http [127.0.0.1:0]
//!
//! Used by the integration tests to exercise the real stdio process boundary.
//! Sending a message to the echo address makes the fake agent reply, which
//! provokes inbox change hints through the public MCP surface.

#[path = "../tests/common/fake_agent.rs"]
mod fake_agent;

use std::sync::Arc;

use agentnet_mcp::{bind_http, serve_http, serve_stdio, HttpOptions};
use fake_agent::FakeAgent;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // stdout is the protocol channel in stdio mode: logs go to stderr only.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rmcp=info".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "stdio".into());
    let agent = FakeAgent::new();
    let seed: usize = std::env::var("FAKE_SEED_INBOX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    for i in 0..seed {
        agent.push_inbox(fake_agent::BOB, &format!("seed-{i}"), Some("seeded"));
    }
    let api: Arc<dyn agentnet_core::api::AgentApi> = agent;
    match mode.as_str() {
        "stdio" => {
            tracing::info!("starting stdio server");
            serve_stdio(api).await?;
            tracing::info!("stdin closed, exiting");
        }
        "http" => {
            let token = std::env::var("FAKE_TOKEN")?;
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let allow_non_loopback = std::env::var("FAKE_ALLOW_NON_LOOPBACK").is_ok();
            let listener = bind_http(bind.parse()?, allow_non_loopback).await?;
            println!("LISTENING {}", listener.local_addr()?);
            let shutdown = CancellationToken::new();
            let stop = shutdown.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                stop.cancel();
            });
            serve_http(
                listener,
                api,
                HttpOptions::new(token),
                allow_non_loopback,
                shutdown,
            )
            .await?;
        }
        other => return Err(format!("unknown mode {other}").into()),
    }
    Ok(())
}
