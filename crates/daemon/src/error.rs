//! Daemon error type.

use std::path::PathBuf;

use agentnet_core::api::{ApiError, ErrorCode};

/// Everything that can stop the daemon from starting or running.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// The configuration is invalid (the message names the offending key).
    #[error("invalid configuration: {0}")]
    Config(String),
    /// The data directory is unusable (missing, wrong permissions, ...).
    #[error("data directory: {0}")]
    DataDir(String),
    /// Another daemon (or a CLI maintenance command) holds the data-dir lock.
    #[error(
        "another AgentNet process is using this data directory (lock held on {}); \
         stop it first (one data directory = one agent identity = one process)",
        .0.display()
    )]
    Locked(PathBuf),
    /// An I/O error with context.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Identity file problem.
    #[error("identity: {0}")]
    Identity(String),
    /// The engine refused to open.
    #[error("{0}")]
    Node(#[from] agentnet_core::NodeError),
    /// The transport refused its configuration.
    #[error("transport: {0}")]
    Transport(String),
    /// Webhook setup problem.
    #[error("webhook: {0}")]
    Webhook(String),
    /// HTTP MCP setup problem.
    #[error("mcp_http: {0}")]
    McpHttp(String),
}

impl DaemonError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

impl From<DaemonError> for ApiError {
    fn from(e: DaemonError) -> Self {
        let code = match &e {
            DaemonError::Config(_) => ErrorCode::InvalidArgument,
            DaemonError::Locked(_) => ErrorCode::Conflict,
            _ => ErrorCode::Internal,
        };
        ApiError::new(code, e.to_string())
    }
}
