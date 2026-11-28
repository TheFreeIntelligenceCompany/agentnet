//! Identity revocation: a standard OpenPGP primary-key revocation.
//!
//! The "tombstone" of the old design is gone. A revoked identity is
//! distributed as its public certificate carrying a key-revocation signature
//! (RFC 9580 section 5.2.1, type 0x20); receivers merge it into the stored
//! contact certificate. The document form is the certificate itself
//! (base64url of the binary certificate). A thief of the primary secret key can
//! issue the same revocation (unchanged property).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::Cert;

use super::address::Address;
use super::contact::{decode_document, MAX_CREATED_AT_FUTURE_MS};
use super::identity::Identity;
use super::pgp;
use crate::error::RevocationError;

/// Longest revocation reason (bytes).
pub const MAX_REASON_LEN: usize = 256;
/// A revocation may be dated at most this far in the future.
pub const MAX_REVOKED_AT_FUTURE_MS: i64 = MAX_CREATED_AT_FUTURE_MS;

/// A locally created revocation document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRevocation {
    cert: Vec<u8>,
}

impl SignedRevocation {
    pub(crate) fn create(
        id: &Identity,
        reason: &str,
        now_ms: i64,
    ) -> Result<Self, RevocationError> {
        if reason.is_empty()
            || reason.len() > MAX_REASON_LEN
            || reason.chars().any(char::is_control)
        {
            return Err(RevocationError::InvalidReason);
        }
        let cert = pgp::revoke_primary(id.cert(), now_ms, reason)
            .map_err(|_| RevocationError::Malformed("could not create the revocation"))?;
        let cert = pgp::sanitize(cert).map_err(|_| RevocationError::Malformed("sanitize"))?;
        Ok(Self {
            cert: cert
                .to_vec()
                .map_err(|_| RevocationError::Malformed("serialization"))?,
        })
    }

    /// The shareable document (the revoked public certificate).
    pub fn to_document(&self) -> String {
        B64.encode(&self.cert)
    }
}

/// A revocation document that verified.
#[derive(Clone)]
pub struct VerifiedRevocation {
    pub address: Address,
    pub revoked_at: i64,
    pub reason: String,
    cert: Cert,
    document: String,
}

impl std::fmt::Debug for VerifiedRevocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedRevocation")
            .field("address", &self.address.to_string())
            .finish_non_exhaustive()
    }
}

fn clean_reason(r: &str) -> String {
    r.chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_LEN)
        .collect()
}

impl VerifiedRevocation {
    /// Parse a revocation document and check it carries a valid primary-key
    /// revocation at `now_ms`.
    pub fn parse_and_verify(doc: &str, now_ms: i64) -> Result<Self, RevocationError> {
        let bytes = decode_document(doc).map_err(|e| match e {
            crate::error::ContactError::TooLarge => RevocationError::TooLarge,
            _ => RevocationError::Malformed("document is not base64url"),
        })?;
        let cert = pgp::parse_public(&bytes)
            .map_err(|_| RevocationError::Malformed("not a public OpenPGP certificate"))?;
        let cert = pgp::normalize_at(
            cert,
            now_ms.saturating_add(MAX_REVOKED_AT_FUTURE_MS),
            now_ms,
        )
        .map_err(|_| RevocationError::Malformed("certificate is not valid"))?;
        let address = pgp::cert_address(&cert)
            .map_err(|_| RevocationError::Malformed("not a v6 Ed25519 certificate"))?;
        let (revoked_at, reason) =
            pgp::primary_revocation(&cert, now_ms).ok_or(RevocationError::NotRevoked)?;
        if revoked_at < 0 || revoked_at > now_ms.saturating_add(MAX_REVOKED_AT_FUTURE_MS) {
            return Err(RevocationError::InvalidTimestamp);
        }
        let bin = cert
            .to_vec()
            .map_err(|_| RevocationError::Malformed("serialization"))?;
        Ok(Self {
            address,
            revoked_at,
            reason: clean_reason(&reason),
            cert,
            document: B64.encode(bin),
        })
    }

    /// The normalized document (the revoked certificate).
    pub fn document(&self) -> &str {
        &self.document
    }

    pub(crate) fn cert(&self) -> &Cert {
        &self.cert
    }
}
