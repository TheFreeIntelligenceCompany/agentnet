//! Contact records: the peer's public OpenPGP (RFC 9580 v6) certificate.
//!
//! A contact record is a certificate, nothing else. First contact pins the
//! primary-key fingerprint (the address; `--expect`); later updates are
//! **merges** of certificates (new encryption subkeys, expiry updates, subkey
//! or primary-key revocation signatures), never replacements, and a merge
//! never admits a different primary key. Local alias and trust level are
//! application data kept outside the certificate.
//!
//! Document form: base64url (no padding) of the binary certificate, at most
//! [`MAX_CERT_LEN`](super::pgp::MAX_CERT_LEN) bytes after sanitizing. ASCII
//! armor is accepted on input. Secret key material is refused.
//!
//! What the code does about hostile packets: `sanitize` keeps only the primary
//! key, the subkeys and the primary's own direct-key, binding and revocation
//! signatures. User IDs, user attributes, third-party certifications,
//! designated-revoker revocations and unknown packets are dropped before
//! anything is stored (certificate-flooding and third-party-certification
//! defence, `docs/threat-model.md`).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::Cert;

use agentnet_transport::ContentTopic;

use super::address::Address;
use super::pgp;
use crate::error::ContactError;

/// Largest accepted document string (base64url of the largest binary certificate,
/// or an ASCII-armored certificate).
pub const MAX_CONTACT_DOCUMENT_LEN: usize = pgp::MAX_CERT_LEN * 2 + 512;
/// Tolerance for a certificate whose signatures lie in the future of the local
/// clock: the default `clock_skew_s` (120 s), the same tolerance the frame
/// freshness check applies. A peer whose clock runs ahead by no more than the
/// permitted skew still gets its fresh certificates (and rotations) accepted; a
/// certificate dated further ahead is refused. It is a constant, not the
/// configured `clock_skew_s`, because the certificate parsers have no access to
/// the node configuration (they are called from the crypto layer, the API and
/// the system-message handlers); raising `clock_skew_s` does not widen it.
pub const MAX_CREATED_AT_FUTURE_MS: i64 = 120 * 1000;

/// The local identity's shareable record (its public certificate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactRecord(Vec<u8>);

impl ContactRecord {
    pub(crate) fn from_cert(cert: &Cert) -> Self {
        Self(cert.to_vec().unwrap_or_default())
    }

    /// The document text (`add_contact` input).
    pub fn to_document(&self) -> String {
        B64.encode(&self.0)
    }

    /// The binary certificate.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A contact certificate that passed [`VerifiedContact::parse_and_verify`].
#[derive(Clone)]
pub struct VerifiedContact {
    pub address: Address,
    /// Time the certificate's primary key was created (Unix ms).
    pub created_at: i64,
    /// Expiry of the live encryption subkey with the latest expiry, if it expires.
    pub kem_expires_at: Option<i64>,
    cert: Cert,
    document: String,
}

impl std::fmt::Debug for VerifiedContact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedContact")
            .field("address", &self.address.to_string())
            .finish_non_exhaustive()
    }
}

impl PartialEq for VerifiedContact {
    fn eq(&self, other: &Self) -> bool {
        self.document == other.document
    }
}
impl Eq for VerifiedContact {}

/// Decode a document (base64url binary or ASCII armor) to bytes.
pub(crate) fn decode_document(doc: &str) -> Result<Vec<u8>, ContactError> {
    if doc.len() > MAX_CONTACT_DOCUMENT_LEN {
        return Err(ContactError::TooLarge);
    }
    let t = doc.trim();
    if t.starts_with("-----BEGIN PGP") {
        return Ok(t.as_bytes().to_vec());
    }
    B64.decode(t)
        .map_err(|_| ContactError::Malformed("document is not base64url"))
}

/// Convenience alias: `parse_and_verify` returns this.
pub fn parse_and_verify(doc: &str, now_ms: i64) -> Result<VerifiedContact, ContactError> {
    VerifiedContact::parse_and_verify(doc, now_ms)
}

impl VerifiedContact {
    /// Parse and verify a contact document at `now_ms`: a v6 Ed25519 primary
    /// key with a valid self-signature, not expired, and (unless the primary
    /// is revoked, which the engine handles separately) at least one live,
    /// non-revoked, non-expired encryption subkey.
    pub fn parse_and_verify(doc: &str, now_ms: i64) -> Result<Self, ContactError> {
        let c = Self::parse_and_verify_allow_expired(doc, now_ms)?;
        if c.revocation(now_ms).is_none() {
            // A certificate (or rotated subkey) made by a peer whose clock runs
            // a little ahead is not "not yet valid".
            let t = pgp::skew_eval_time(&c.cert, now_ms, MAX_CREATED_AT_FUTURE_MS);
            pgp::check_primary_usable(&c.cert, t)?;
            if !pgp::has_live_kem(&c.cert, t) {
                return Err(ContactError::NoEncryptionKey);
            }
        }
        Ok(c)
    }

    /// Like [`Self::parse_and_verify`] but does not require a live encryption
    /// subkey or an unexpired primary. Intended for re-loading persisted
    /// contacts; sealing still refuses expired or revoked recipients.
    pub fn parse_and_verify_allow_expired(doc: &str, now_ms: i64) -> Result<Self, ContactError> {
        let bytes = decode_document(doc)?;
        let cert = pgp::parse_public(&bytes)?;
        Self::from_cert(cert, now_ms)
    }

    pub(crate) fn from_cert(cert: Cert, now_ms: i64) -> Result<Self, ContactError> {
        let cert = pgp::normalize_at(
            cert,
            now_ms.saturating_add(MAX_CREATED_AT_FUTURE_MS),
            now_ms,
        )?;
        let address = pgp::cert_address(&cert)?;
        let bin = cert
            .to_vec()
            .map_err(|_| ContactError::Malformed("serialization"))?;
        let created_at = pgp::ms_of(cert.primary_key().key().creation_time());
        let eval_t = pgp::skew_eval_time(&cert, now_ms, MAX_CREATED_AT_FUTURE_MS);
        Ok(Self {
            address,
            created_at,
            kem_expires_at: pgp::kem_expiry_ms(&cert, eval_t),
            cert,
            document: B64.encode(bin),
        })
    }

    /// Merge `incoming` (another certificate of the same primary key) into this
    /// one. Never replaces: signatures are unioned (revocations accumulate),
    /// a different primary key is refused with [`ContactError::PrimaryMismatch`],
    /// and invalid or unbound subkeys do not survive.
    pub fn merge(&self, incoming: &VerifiedContact, now_ms: i64) -> Result<Self, ContactError> {
        let merged = pgp::merge_at(
            &self.cert,
            &incoming.cert,
            now_ms.saturating_add(MAX_CREATED_AT_FUTURE_MS),
            now_ms,
        )?;
        Self::from_cert(merged, now_ms)
    }

    /// True if both hold the same certificate content.
    pub fn same_record(&self, other: &Self) -> bool {
        self.document == other.document
    }

    /// True if no encryption subkey is live at `now_ms` (all expired, revoked
    /// or unbound).
    pub fn is_kem_expired(&self, now_ms: i64) -> bool {
        !pgp::has_live_kem(&self.cert, now_ms)
    }

    /// `(revoked_at_ms, reason)` when the certificate's primary key is revoked at `now_ms`.
    pub fn revocation(&self, now_ms: i64) -> Option<(i64, String)> {
        pgp::primary_revocation(&self.cert, now_ms)
    }

    /// The recipient's inbox content topic.
    pub fn inbox_topic(&self) -> ContentTopic {
        self.address.inbox_topic()
    }

    /// The normalized certificate document, for persistence.
    pub fn document(&self) -> &str {
        &self.document
    }

    pub(crate) fn cert(&self) -> &Cert {
        &self.cert
    }
}
