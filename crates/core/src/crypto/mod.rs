//! The cryptographic boundary of AgentNet.
//!
//! Everything that touches `hpke`, `ed25519-dalek` or `age` lives in this
//! module tree (enforced by `tests/architecture.rs`). The rest of the crate,
//! the transport, the MCP server and the daemon use only the stable surface
//! re-exported here:
//!
//! * [`Address`], [`Identity`] (key management: generate, load, save, export,
//!   import, rotate, revoke),
//! * [`SignedContactRecord`] / [`VerifiedContact`],
//! * [`SignedRevocation`] / [`VerifiedRevocation`],
//! * [`SignedAdvert`] / [`VerifiedAdvert`] (optional discovery; a signing domain
//!   only, no new construction),
//! * [`Envelope`] and the [`MessageProtection`] trait, with the current scheme
//!   [`HpkeBaseEd25519`] (suite id 1) and the [`SuiteRegistry`] that dispatches
//!   on the frame's suite and negotiates the sealing suite.
//!
//! See `docs/crypto-interface.md`. This implementation has not been
//! independently reviewed, has no forward secrecy, and must not be described
//! as audited or production-secure.

pub mod address;
pub mod advert;
pub mod contact;
pub mod envelope;
mod hpke_suite;
pub mod identity;
pub mod protection;
pub mod revocation;

pub use address::Address;
pub use advert::{AdvertContent, AdvertLimits, Capability, SignedAdvert, VerifiedAdvert};
pub use contact::{SignedContactRecord, VerifiedContact};
pub use envelope::{Envelope, OpenLimits, OpenedEnvelope, SUITE_ID as SUITE_HPKE_BASE_ED25519};
pub use hpke_suite::HpkeBaseEd25519;
pub use identity::Identity;
pub use protection::{default_protection, MessageProtection, SuiteRegistry};
pub use revocation::{SignedRevocation, VerifiedRevocation};
