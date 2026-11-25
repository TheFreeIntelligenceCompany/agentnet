//! AgentNet core. Independent of MCP and of any harness.
//!
//! See `docs/architecture.md` and `docs/protocol.md`.
//!
//! The `address`, `identity`, `contact` and `envelope` modules are pure
//! (no database, no network); only identity file import/export does file IO.

pub mod address;
pub mod api;
pub mod contact;
pub mod envelope;
pub mod error;
pub mod identity;
