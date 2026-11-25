//! AgentNet daemon: the persistent service around the engine.
//!
//! * [`config`]: `agentnet.toml` (private by default, fail-closed validation).
//! * [`datadir`]: layout, permissions, exclusive lock, tokens.
//! * [`daemon`]: [`Daemon::start`] / [`Daemon::start_with_transport`], graceful shutdown.
//! * [`server`] + [`proto`]: the control and event socket (`agentnet.sock`).
//! * [`client`]: [`RemoteAgent`] (an `AgentApi` over the socket) and [`EventStream`].
//! * [`webhook`]: optional signed outbound webhook and [`webhook::verify_signature`].
//! * [`offline`]: init / identity export / import / rotation (daemon stopped).
//!
//! See `docs/host-integration.md` and `docs/configuration.md`.

#[cfg(not(unix))]
compile_error!("agentnet-daemon supports Unix only (Unix domain sockets, 0600/0700 permissions)");

pub mod client;
pub mod config;
pub mod daemon;
pub mod datadir;
pub mod error;
pub mod offline;
pub mod proto;
pub mod server;
pub mod webhook;

pub use client::{EventStream, RemoteAgent};
pub use config::{
    render_private_config, sample_private_config, sample_public_config, DaemonConfig, Mode,
};
pub use daemon::{Daemon, RunningDaemon, ShutdownHandle};
pub use datadir::DataDir;
pub use error::DaemonError;
