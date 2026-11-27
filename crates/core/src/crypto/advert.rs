//! Signed, expiring capability advertisements (optional discovery feature).
//!
//! An advertisement is a PLAINTEXT, publicly readable statement by an agent:
//! "this address offers these capabilities until this time; here is my current
//! certificate". It is published on a host-authorised discovery content topic,
//! never on an inbox topic. Wire format (normative description in
//! `docs/discovery.md`):
//!
//! * document = base64url of ONE OpenPGP signed (not encrypted) message: a
//!   one-pass signed Literal Data packet and a v6 Ed25519 signature by the
//!   agent's primary key (RFC 9580 section 10.3),
//! * the literal data is the JSON record
//!   `{"v":3,"topic":"<discovery topic name>","address":…,"contact_record":"<certificate document>",
//!   "capabilities":[{"name":…,"description":…}],"display_name":…(optional),
//!   "issued_at":ms,"expires_at":ms,"seq":n}`; the topic is inside the signed content,
//! * frame = `b"AD" || 0x01 || document_bytes`, so an advertisement can never be
//!   mistaken for a sealed message (which starts with an OpenPGP packet tag
//!   byte, high bit set, never `A`).
//!
//! AgentNet defines no signature construction here: the signature is a standard
//! OpenPGP data signature. The identity certificate is used for nothing but
//! AgentNet, so the lack of a signature context string (domain separation) is
//! compensated by the strict JSON schema with its `v` and `topic` fields
//! (`docs/crypto-requirements.md`). A valid advertisement proves that the holder
//! of the address key made the statement; it proves nothing about whether the
//! capabilities are real or the agent is trustworthy. Receiving one never
//! creates a contact.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::address::Address;
use super::contact::VerifiedContact;
use super::identity::Identity;
use super::pgp;
use crate::error::{json_reason, AdvertError};

/// Advertisement format version (version 3: an OpenPGP signed message).
pub const ADVERT_VERSION: u64 = 3;
/// Frame magic of an advertisement frame (sealed message frames use `AN`).
pub const ADVERT_FRAME_MAGIC: [u8; 2] = *b"AD";
/// Frame version byte of an advertisement frame.
pub const ADVERT_FRAME_VERSION: u8 = 1;
/// Length of the frame header (magic + version).
pub const ADVERT_FRAME_HEADER_LEN: usize = 3;
/// Maximum size of the signed record bytes (8 KiB).
pub const MAX_ADVERT_RECORD_LEN: usize = 8192;
/// Maximum size of the document (base64url of a maximal record plus the wrapper).
pub const MAX_ADVERT_DOCUMENT_LEN: usize = 12_288;
/// Maximum size of a whole advertisement frame.
pub const MAX_ADVERT_FRAME_LEN: usize = MAX_ADVERT_DOCUMENT_LEN + ADVERT_FRAME_HEADER_LEN;
/// Longest capability name.
pub const MAX_CAPABILITY_NAME_LEN: usize = 64;
/// Longest capability description (characters).
pub const MAX_CAPABILITY_DESCRIPTION_CHARS: usize = 256;
/// Longest display name (characters).
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
/// Hard upper bound of the number of capabilities (the configured limit is lower or equal).
pub const MAX_CAPABILITIES_HARD: usize = 64;

/// One advertised capability. Both fields are remote-controlled DATA.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    /// `[a-z0-9._-]{1,64}`.
    pub name: String,
    /// Up to 256 characters, no control characters (may be empty).
    #[serde(default)]
    pub description: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdvertV2 {
    v: u64,
    topic: String,
    address: String,
    contact_record: String,
    capabilities: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    issued_at: i64,
    expires_at: i64,
    seq: u64,
}

#[derive(Deserialize)]
struct VersionOnly {
    v: u64,
}

/// Limits applied when verifying an advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvertLimits {
    /// Largest accepted `expires_at - issued_at` (ms).
    pub max_ttl_ms: i64,
    /// Accepted `issued_at` skew into the future (ms).
    pub clock_skew_ms: i64,
    /// Most capabilities accepted.
    pub max_capabilities: usize,
}

/// Valid capability name: `[a-z0-9._-]{1,64}`.
pub fn valid_capability_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_CAPABILITY_NAME_LEN
        && n.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// Valid free text (description or display name): within `max` characters and
/// without control characters.
fn valid_text(s: &str, max: usize) -> bool {
    s.chars().count() <= max && !s.chars().any(char::is_control)
}

/// Check a capability list against the format rules (names unique and valid,
/// descriptions bounded) and `max_capabilities`.
pub fn check_capabilities(caps: &[Capability], max: usize) -> Result<(), AdvertError> {
    if caps.len() > max.min(MAX_CAPABILITIES_HARD) {
        return Err(AdvertError::InvalidCapability("too many capabilities"));
    }
    for (i, c) in caps.iter().enumerate() {
        if !valid_capability_name(&c.name) {
            return Err(AdvertError::InvalidCapability(
                "name must match [a-z0-9._-]{1,64}",
            ));
        }
        if !valid_text(&c.description, MAX_CAPABILITY_DESCRIPTION_CHARS) {
            return Err(AdvertError::InvalidCapability(
                "description must be at most 256 characters without control characters",
            ));
        }
        if caps.iter().take(i).any(|p| p.name == c.name) {
            return Err(AdvertError::InvalidCapability("duplicate capability name"));
        }
    }
    Ok(())
}

fn check_display_name(d: &Option<String>) -> Result<(), AdvertError> {
    match d {
        Some(n) if n.is_empty() || !valid_text(n, MAX_DISPLAY_NAME_CHARS) => {
            Err(AdvertError::InvalidDisplayName)
        }
        _ => Ok(()),
    }
}

/// Wrap a document into an advertisement frame.
pub fn encode_frame(document: &str) -> Vec<u8> {
    let mut f = Vec::with_capacity(ADVERT_FRAME_HEADER_LEN + document.len());
    f.extend_from_slice(&ADVERT_FRAME_MAGIC);
    f.push(ADVERT_FRAME_VERSION);
    f.extend_from_slice(document.as_bytes());
    f
}

/// True if `payload` starts with the advertisement frame magic.
pub fn has_advert_magic(payload: &[u8]) -> bool {
    payload.get(0..2) == Some(&ADVERT_FRAME_MAGIC[..])
}

/// True if `payload` looks like a sealed message: it starts with an OpenPGP
/// packet header (high bit set), which an advertisement frame (`A`) never does.
pub fn has_sealed_magic(payload: &[u8]) -> bool {
    payload.first().is_some_and(|b| b & 0x80 != 0)
}

/// Unwrap an advertisement frame into its document text. Never panics.
pub fn decode_frame(payload: &[u8]) -> Result<&str, AdvertError> {
    if payload.len() > MAX_ADVERT_FRAME_LEN
        || payload.len() < ADVERT_FRAME_HEADER_LEN
        || !has_advert_magic(payload)
        || payload.get(2) != Some(&ADVERT_FRAME_VERSION)
    {
        return Err(AdvertError::BadFrame);
    }
    let body = payload
        .get(ADVERT_FRAME_HEADER_LEN..)
        .ok_or(AdvertError::BadFrame)?;
    std::str::from_utf8(body).map_err(|_| AdvertError::BadFrame)
}

/// A locally created, signed advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAdvert {
    record: Vec<u8>,
    message: Vec<u8>,
}

impl SignedAdvert {
    pub(crate) fn create(
        id: &Identity,
        req: &AdvertContent<'_>,
        limits: &AdvertLimits,
    ) -> Result<Self, AdvertError> {
        check_capabilities(req.capabilities, limits.max_capabilities)?;
        check_display_name(&req.display_name.map(str::to_owned))?;
        if req.issued_at < 0 || req.expires_at <= req.issued_at {
            return Err(AdvertError::InvalidTimestamp);
        }
        if req.expires_at - req.issued_at > limits.max_ttl_ms {
            return Err(AdvertError::TtlTooLong);
        }
        if req.seq > i64::MAX as u64 {
            return Err(AdvertError::InvalidSeq);
        }
        if !crate::config::valid_discovery_topic_name(req.topic) {
            return Err(AdvertError::Malformed("invalid topic name"));
        }
        let rec = AdvertV2 {
            v: ADVERT_VERSION,
            topic: req.topic.to_owned(),
            address: id.address().to_string(),
            contact_record: id.contact_record().to_document(),
            capabilities: req.capabilities.to_vec(),
            display_name: req.display_name.map(str::to_owned),
            issued_at: req.issued_at,
            expires_at: req.expires_at,
            seq: req.seq,
        };
        let record =
            serde_json::to_vec(&rec).map_err(|_| AdvertError::Malformed("serialization"))?;
        if record.len() > MAX_ADVERT_RECORD_LEN {
            return Err(AdvertError::TooLarge);
        }
        let signer = id.signer().ok_or(AdvertError::BadSignature)?;
        let message = pgp::sign_message(signer, &record, req.issued_at)
            .map_err(|_| AdvertError::BadSignature)?;
        Ok(Self { record, message })
    }

    /// The signed JSON content.
    pub fn record_bytes(&self) -> &[u8] {
        &self.record
    }

    /// The shareable document (base64url of the OpenPGP signed message).
    pub fn to_document(&self) -> String {
        B64.encode(&self.message)
    }

    /// The document wrapped in an advertisement frame, ready to publish.
    pub fn to_frame(&self) -> Vec<u8> {
        encode_frame(&self.to_document())
    }
}

/// The content of an advertisement to sign.
#[derive(Clone, Copy, Debug)]
pub struct AdvertContent<'a> {
    /// Discovery topic name the advert is published on (signed; receivers
    /// reject the advert on any other topic).
    pub topic: &'a str,
    /// Capabilities (empty = withdrawal).
    pub capabilities: &'a [Capability],
    /// Optional display name.
    pub display_name: Option<&'a str>,
    /// Issue time (ms).
    pub issued_at: i64,
    /// Expiry (ms).
    pub expires_at: i64,
    /// Sequence number (higher replaces lower).
    pub seq: u64,
}

/// An advertisement whose signature, embedded contact record, timestamps and
/// field rules all verified. Everything in it is a CLAIM by the advertiser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdvert {
    /// The discovery topic name the advertiser signed (equal to the topic the
    /// frame arrived on, checked by `parse_and_verify`).
    pub topic: String,
    /// The advertiser (signature verified under this address).
    pub address: Address,
    /// The advertiser's embedded contact record (verified, same address).
    pub contact: VerifiedContact,
    /// Advertised capabilities; empty means the advertiser withdrew.
    pub capabilities: Vec<Capability>,
    /// Claimed display name.
    pub display_name: Option<String>,
    /// Issue time (ms).
    pub issued_at: i64,
    /// Expiry (ms).
    pub expires_at: i64,
    /// Sequence number.
    pub seq: u64,
    document: String,
}

impl VerifiedAdvert {
    /// Parse and fully verify an advertisement document at `now_ms`, received
    /// on the discovery topic named `expected_topic`. An advert whose signed
    /// topic differs is rejected with [`AdvertError::TopicMismatch`] (after its
    /// signature verified).
    pub fn parse_and_verify(
        doc: &str,
        expected_topic: &str,
        now_ms: i64,
        limits: &AdvertLimits,
    ) -> Result<Self, AdvertError> {
        if doc.len() > MAX_ADVERT_DOCUMENT_LEN {
            return Err(AdvertError::TooLarge);
        }
        let msg = B64
            .decode(doc)
            .map_err(|_| AdvertError::Malformed("document is not base64url"))?;
        // Pass 1: read the content WITHOUT trusting it, to find the certificate to verify with.
        let record = pgp::read_signed_unverified(&msg, MAX_ADVERT_RECORD_LEN)
            .ok_or(AdvertError::BadStructure)?;
        let ver: VersionOnly =
            serde_json::from_slice(&record).map_err(|e| AdvertError::Malformed(json_reason(&e)))?;
        if ver.v != ADVERT_VERSION {
            return Err(AdvertError::UnknownVersion(ver.v));
        }
        let r: AdvertV2 =
            serde_json::from_slice(&record).map_err(|e| AdvertError::Malformed(json_reason(&e)))?;
        let address: Address = r.address.parse().map_err(AdvertError::InvalidAddress)?;
        let contact = VerifiedContact::parse_and_verify(&r.contact_record, now_ms)
            .map_err(AdvertError::BadContact)?;
        if contact.address != address {
            return Err(AdvertError::ContactAddressMismatch);
        }
        // Pass 2: the signature must verify under that certificate, made by its primary key.
        let (content, signer) = pgp::verify_signed_message(
            &msg,
            vec![contact.cert().clone()],
            MAX_ADVERT_RECORD_LEN,
            now_ms.saturating_add(limits.clock_skew_ms),
        )
        .ok_or(AdvertError::BadSignature)?;
        if signer != address || content != record {
            return Err(AdvertError::BadSignature);
        }
        if r.topic != expected_topic {
            return Err(AdvertError::TopicMismatch);
        }
        if r.issued_at < 0 || r.expires_at <= r.issued_at {
            return Err(AdvertError::InvalidTimestamp);
        }
        if r.expires_at <= now_ms {
            return Err(AdvertError::Expired);
        }
        if r.issued_at > now_ms.saturating_add(limits.clock_skew_ms) {
            return Err(AdvertError::FromFuture);
        }
        if r.expires_at.saturating_sub(r.issued_at) > limits.max_ttl_ms {
            return Err(AdvertError::TtlTooLong);
        }
        if r.seq > i64::MAX as u64 {
            return Err(AdvertError::InvalidSeq);
        }
        check_capabilities(&r.capabilities, limits.max_capabilities)?;
        check_display_name(&r.display_name)?;
        Ok(Self {
            topic: r.topic,
            address,
            contact,
            capabilities: r.capabilities,
            display_name: r.display_name,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            seq: r.seq,
            document: doc.to_owned(),
        })
    }

    /// The embedded contact record document (what `add_contact` takes).
    pub fn contact_record(&self) -> &str {
        self.contact.document()
    }

    /// The original signed document.
    pub fn document(&self) -> &str {
        &self.document
    }

    /// True if this is a withdrawal (no capabilities).
    pub fn is_withdrawal(&self) -> bool {
        self.capabilities.is_empty()
    }
}

/// A short, stable label of an [`AdvertError`] for counters.
pub fn error_kind(e: &AdvertError) -> &'static str {
    match e {
        AdvertError::BadFrame => "bad_frame",
        AdvertError::TooLarge => "too_large",
        AdvertError::Malformed(_) => "malformed",
        AdvertError::UnknownVersion(_) => "unknown_version",
        AdvertError::InvalidAddress(_) => "invalid_address",
        AdvertError::BadSignature => "bad_signature",
        AdvertError::BadStructure => "bad_structure",
        AdvertError::TopicMismatch => "topic_mismatch",
        AdvertError::BadContact(_) => "bad_contact",
        AdvertError::ContactAddressMismatch => "contact_address_mismatch",
        AdvertError::InvalidTimestamp => "invalid_timestamp",
        AdvertError::Expired => "expired",
        AdvertError::FromFuture => "from_future",
        AdvertError::TtlTooLong => "ttl_too_long",
        AdvertError::InvalidCapability(_) => "invalid_capability",
        AdvertError::InvalidDisplayName => "invalid_display_name",
        AdvertError::InvalidSeq => "invalid_seq",
    }
}

impl Identity {
    /// Create a signed advertisement for this identity (the current contact
    /// record is embedded). An empty capability list is a withdrawal. This only
    /// builds the document; publishing it is the engine's job.
    pub fn create_advert(
        &self,
        content: &AdvertContent<'_>,
        limits: &AdvertLimits,
    ) -> Result<SignedAdvert, AdvertError> {
        SignedAdvert::create(self, content, limits)
    }
}

/// Builders of forged or malformed advertisements for tests of the engine.
/// Not part of the supported API.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// A document whose signed content is exactly `record`, signed by `signer`
    /// (so anything can be forged, including records naming another address or
    /// embedding another certificate).
    pub fn sign_record_as(signer: &Identity, record: &[u8], now_ms: i64) -> String {
        match signer.signer() {
            Some(kp) => pgp::sign_message(kp, record, now_ms)
                .map(|m| B64.encode(m))
                .unwrap_or_default(),
            None => String::new(),
        }
    }

    /// Decode a document to its OpenPGP message bytes.
    pub fn message_bytes(doc: &str) -> Option<Vec<u8>> {
        B64.decode(doc).ok()
    }

    /// Encode raw message bytes as a document.
    pub fn document_from_bytes(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    /// The JSON content of a signed document (not verified).
    pub fn content_of(doc: &str) -> Option<Vec<u8>> {
        pgp::read_signed_unverified(&B64.decode(doc).ok()?, MAX_ADVERT_RECORD_LEN)
    }
}
