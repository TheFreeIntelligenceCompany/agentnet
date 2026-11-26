//! The message-protection interface and the suite registry.
//!
//! The engine (`ingest`, `send`, `node`) only ever calls [`MessageProtection`].
//! A different or additional scheme is added by implementing the trait and
//! registering it in a [`SuiteRegistry`]; no engine, transport, MCP or daemon
//! code changes. See `docs/crypto-interface.md`.

use std::sync::Arc;

use super::contact::VerifiedContact;
use super::envelope::{Envelope, OpenLimits, OpenedEnvelope, FRAME_MAGIC, FRAME_VERSION};
use super::hpke_suite::HpkeBaseEd25519;
use super::identity::Identity;
use crate::error::{OpenError, SealError};

/// Seals and opens message frames for one or more cipher suites.
///
/// Contract for implementors:
/// * `seal` must authenticate the sender, bind the recipient, the suite id and
///   the recipient's `key_epoch`, and protect every [`Envelope`] field.
/// * `open` must be a pure function of its inputs (no replay detection; the
///   engine persists `(sender, message_id)`), must never return an envelope
///   whose signature or suite/epoch binding was not verified, and must return
///   [`OpenError::NotForUs`] when no local key opens the frame.
/// * Implementations must not log or return plaintext, keys or attacker
///   controlled strings in errors.
pub trait MessageProtection: Send + Sync {
    /// The suite this object seals with (the highest one for a registry).
    fn suite_id(&self) -> u8;
    /// Every suite id this object can open and seal, ascending.
    fn supported_suites(&self) -> Vec<u8>;
    /// The suites listed in the signed contact record this agent publishes and
    /// that `open` accepts. Defaults to everything supported.
    fn advertised_suites(&self) -> Vec<u8> {
        self.supported_suites()
    }
    /// Seal `envelope` from `sender` to `recipient`.
    fn seal(
        &self,
        sender: &Identity,
        recipient: &VerifiedContact,
        envelope: &Envelope,
        now_ms: i64,
        max_frame_len: usize,
    ) -> Result<Vec<u8>, SealError>;
    /// Open and validate a frame addressed to `recipient`.
    fn open(
        &self,
        recipient: &Identity,
        frame: &[u8],
        now_ms: i64,
        limits: &OpenLimits,
    ) -> Result<OpenedEnvelope, OpenError>;
    /// Largest body (JSON-encoded bytes) that fits in `max_frame_len` given the
    /// other fields of `envelope_without_body`.
    fn max_body_len(&self, max_frame_len: usize, envelope_without_body: &Envelope) -> usize;
}

/// Dispatches `open` on the frame header's suite id and `seal` on the suite
/// negotiated from the recipient's signed contact record.
///
/// * `seal`: the highest suite that is both registered here and listed in
///   `recipient.suites`; [`SealError::NoCommonSuite`] if there is none. It never
///   falls back to a suite the recipient does not list.
/// * `open`: a frame whose suite is not registered is `UnknownSuite`; one that
///   is registered but not in this registry's *advertised* list is
///   `SuiteNotAdvertised` (a downgrade to a suite we do not publish is refused).
#[derive(Clone)]
pub struct SuiteRegistry {
    suites: Vec<Arc<dyn MessageProtection>>,
    advertised: Vec<u8>,
}

impl std::fmt::Debug for SuiteRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuiteRegistry")
            .field("suites", &self.supported_suites())
            .field("advertised", &self.advertised)
            .finish()
    }
}

impl SuiteRegistry {
    /// A registry holding exactly `suites` (each a single-suite implementation),
    /// advertising all of them.
    pub fn new(suites: Vec<Arc<dyn MessageProtection>>) -> Self {
        let mut r = Self {
            suites,
            advertised: Vec::new(),
        };
        r.advertised = r.supported_suites();
        r
    }

    /// The default registry: suite 1 (`HpkeBaseEd25519`) only.
    pub fn with_default_suites() -> Self {
        Self::new(vec![Arc::new(HpkeBaseEd25519)])
    }

    /// Register another suite (advertised too). Replaces a suite with the same id.
    pub fn register(&mut self, suite: Arc<dyn MessageProtection>) {
        self.suites.retain(|s| s.suite_id() != suite.suite_id());
        self.suites.push(suite);
        self.advertised = self.supported_suites();
    }

    /// Restrict the advertised (and accepted) suites to `ids` intersected with
    /// the registered ones.
    pub fn set_advertised(&mut self, ids: &[u8]) {
        let supported = self.supported_suites();
        self.advertised = supported.into_iter().filter(|s| ids.contains(s)).collect();
    }

    fn find(&self, id: u8) -> Option<&Arc<dyn MessageProtection>> {
        self.suites.iter().find(|s| s.suite_id() == id)
    }
}

impl MessageProtection for SuiteRegistry {
    fn suite_id(&self) -> u8 {
        self.supported_suites().last().copied().unwrap_or(0)
    }

    fn supported_suites(&self) -> Vec<u8> {
        let mut v: Vec<u8> = self.suites.iter().map(|s| s.suite_id()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn advertised_suites(&self) -> Vec<u8> {
        self.advertised.clone()
    }

    fn seal(
        &self,
        sender: &Identity,
        recipient: &VerifiedContact,
        envelope: &Envelope,
        now_ms: i64,
        max_frame_len: usize,
    ) -> Result<Vec<u8>, SealError> {
        let chosen = self
            .supported_suites()
            .into_iter()
            .rev()
            .find(|s| recipient.suites.contains(s))
            .ok_or(SealError::NoCommonSuite)?;
        let suite = self.find(chosen).ok_or(SealError::NoCommonSuite)?;
        suite.seal(sender, recipient, envelope, now_ms, max_frame_len)
    }

    fn open(
        &self,
        recipient: &Identity,
        frame: &[u8],
        now_ms: i64,
        limits: &OpenLimits,
    ) -> Result<OpenedEnvelope, OpenError> {
        if frame.len() > limits.max_frame_len {
            return Err(OpenError::FrameTooLarge);
        }
        let header = frame.get(..4).ok_or(OpenError::Truncated)?;
        if header.get(0..2) != Some(&FRAME_MAGIC[..]) {
            return Err(OpenError::BadMagic);
        }
        match header.get(2) {
            Some(&FRAME_VERSION) => {}
            Some(&v) => return Err(OpenError::UnknownFrameVersion(v)),
            None => return Err(OpenError::Truncated),
        }
        let suite_id = *header.get(3).ok_or(OpenError::Truncated)?;
        let suite = self
            .find(suite_id)
            .ok_or(OpenError::UnknownSuite(suite_id))?;
        if !self.advertised.contains(&suite_id) {
            return Err(OpenError::SuiteNotAdvertised(suite_id));
        }
        suite.open(recipient, frame, now_ms, limits)
    }

    fn max_body_len(&self, max_frame_len: usize, envelope_without_body: &Envelope) -> usize {
        match self.find(self.suite_id()) {
            Some(s) => s.max_body_len(max_frame_len, envelope_without_body),
            None => 0,
        }
    }
}

/// The default protection used by `Node::open` and the free `seal`/`open`
/// wrappers: a registry with suite 1 only.
pub fn default_protection() -> Arc<dyn MessageProtection> {
    Arc::new(SuiteRegistry::with_default_suites())
}
