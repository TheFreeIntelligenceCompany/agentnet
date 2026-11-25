//! AgentNet core. Independent of MCP and of any harness.
//!
//! See `docs/architecture.md` and `docs/protocol.md`.
//!
//! The `address`, `identity`, `contact` and `envelope` modules are pure
//! (no database, no network); only identity file import/export does file IO.
//! The durable engine is [`node::Node`] (SQLite store, retries, dedupe,
//! triggers, events); it implements [`api::AgentApi`].

pub mod address;
pub mod api;
mod api_impl;
pub mod clock;
pub mod config;
pub mod contact;
pub mod cursor;
pub mod envelope;
pub mod error;
pub mod identity;
mod ingest;
pub mod metrics;
pub mod node;
mod send;
pub mod store;
mod triggers;

pub use clock::{Clock, ManualClock, SystemClock};
pub use config::NodeConfig;
pub use ingest::FrameOutcome;
pub use metrics::NodeMetrics;
pub use node::{Node, NodeError};
