//! The cryptographic boundary of AgentNet.
//!
//! Everything that touches `sequoia-openpgp` (and through it OpenSSL) or `age`
//! lives in this module tree (enforced by `tests/architecture.rs`). The rest of
//! the crate, the transport, the MCP server and the daemon use only the stable
//! surface re-exported here:
//!
//! * [`Address`], [`Identity`] (key management: generate, load, save, export,
//!   import, rotate, revoke),
//! * [`ContactRecord`] / [`VerifiedContact`] (an OpenPGP v6 certificate; updates
//!   are merges),
//! * [`SignedRevocation`] / [`VerifiedRevocation`] (a primary-key revocation),
//! * [`SignedAdvert`] / [`VerifiedAdvert`] (optional discovery; OpenPGP signed
//!   messages),
//! * [`Envelope`] and the [`MessageProtection`] trait with its one
//!   implementation [`OpenPgpProtection`] (RFC 9580: anonymous v6 PKESK,
//!   SEIPD v2 AES-256/OCB, signed with an Intended Recipient Fingerprint,
//!   Padding packet).
//!
//! AgentNet defines no cryptographic construction. See `docs/crypto-interface.md`
//! and ADR 0004. This implementation has not been independently reviewed, has
//! no forward secrecy against later compromise of a recipient encryption
//! subkey, and must not be described as audited or production-secure.

pub mod address;
pub mod advert;
pub mod contact;
pub mod envelope;
pub mod identity;
pub mod pgp;
pub mod protection;
pub mod revocation;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod testing;

pub use address::Address;
pub use advert::{AdvertContent, AdvertLimits, Capability, SignedAdvert, VerifiedAdvert};
pub use contact::{ContactRecord, VerifiedContact};
pub use envelope::{Envelope, OpenLimits, OpenedEnvelope, SenderAuth};
pub use identity::Identity;
pub use protection::{
    default_protection, frame_digest, MessageProtection, NoSenders, OpenPgpProtection,
    SenderDirectory,
};
pub use revocation::{SignedRevocation, VerifiedRevocation};
