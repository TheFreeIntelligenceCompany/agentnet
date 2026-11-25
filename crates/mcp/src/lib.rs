//! AgentNet MCP server: exposes an [`AgentApi`](agentnet_core::api::AgentApi) as
//! MCP tools, resources and resource subscriptions using the official `rmcp` SDK
//! (pinned `=3.11.0`, protocol 2026-07-28 with SDK-provided legacy negotiation).
//!
//! * [`AgentNetMcp`] is the `ServerHandler`.
//! * [`serve_stdio`] / [`serve_io`] serve over stdio (stdout = protocol frames only).
//! * [`http_router`] / [`serve_http`] serve Streamable HTTP with a static bearer
//!   token on loopback (not the MCP OAuth profile).
//!
//! The handler holds no per-connection application state: everything durable
//! lives behind the `AgentApi` handle and is addressed by explicit ids.
//! Resource-update notifications are hints derived from the engine's lossy
//! `changes()` stream; clients reread by cursor to recover.
//!
//! See `docs/mcp-api.md` for the tool contracts and error mapping.

mod error;
mod http;
mod server;
mod shared;
mod stdio;

pub mod dto;
pub mod limits;
pub mod uris;

pub use error::{code_str, ToolFailure};
pub use http::{
    bind_http, http_router, http_router_with_shutdown, serve_http, HttpOptions, MCP_PATH,
    MIN_TOKEN_LEN,
};
pub use server::{AgentNetMcp, McpStats, INSTRUCTIONS, MAX_SUBSCRIPTION_URIS};
pub use stdio::{serve_io, serve_stdio};

/// Failure to start or run a transport.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// A safety check refused the configuration (non-loopback bind, weak token).
    #[error("refused: {0}")]
    Refused(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport error: {0}")]
    Transport(String),
}
