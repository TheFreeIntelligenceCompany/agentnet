//! AgentNet core. Independent of MCP and of any harness.
//!
//! See `docs/architecture.md` and `docs/protocol.md`.
//!
//! All cryptography sits behind [`crypto`] (`address`, `identity`, `contact`,
//! `envelope` and the [`crypto::MessageProtection`] trait; the old module paths
//! re-export from there). Those modules are pure (no database, no network);
//! only identity file import/export does file IO.
//! The durable engine is [`node::Node`] (SQLite store, retries, dedupe,
//! triggers, events); it implements [`api::AgentApi`].

pub mod api;
mod api_impl;
pub mod clock;
pub mod config;
pub mod crypto;
pub mod cursor;
pub mod error;
pub mod guard;
mod ingest;
pub mod metrics;
pub mod node;
mod send;
pub mod store;
mod system;
mod triggers;

// Stable paths of the pre-`crypto` layout; the modules live in `crypto/`.
pub use crypto::{address, contact, envelope, identity};

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::NodeConfig;
pub use ingest::FrameOutcome;
pub use metrics::NodeMetrics;
pub use node::{Node, NodeError, NodeOptions};
