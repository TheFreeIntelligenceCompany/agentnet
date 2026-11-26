//! Signed identity-revocation tombstones.
//!
//! A tombstone states "the signing key behind this address must no longer be
//! trusted". It is self-authenticating: the signature verifies under the very
//! address it names, so any party may carry it. Wire format (same wrapper as a
//! contact record):
//! document = `{"record": b64url(record_bytes), "sig": b64url(sig)}`,
//! `record_bytes = {"v":1,"address":…,"revoked_at":ms,"reason":…}`,
//! `sig = Ed25519(signing_sk, "agentnet/v1/identity-revocation\0" || record_bytes)`.
//!
//! There is no global revocation list: a tombstone only protects peers that
//! receive it. A thief of the signing key can also sign a tombstone (a denial
//! of service for that address, not an impersonation).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use super::address::Address;
use super::identity::Identity;
use crate::error::{json_reason, RevocationError};

/// Domain separation prefix of the tombstone signature.
pub const REVOCATION_DOMAIN: &[u8] = b"agentnet/v1/identity-revocation\0";
/// Maximum accepted size of a revocation document (bytes).
pub const MAX_REVOCATION_DOCUMENT_LEN: usize = 2048;
/// Maximum reason length (bytes).
pub const MAX_REASON_LEN: usize = 256;
/// Tombstone format version.
pub const REVOCATION_VERSION: u64 = 1;
/// A tombstone dated further in the future than this is rejected.
pub const MAX_REVOKED_AT_FUTURE_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TombstoneV1 {
    v: u64,
    address: String,
    revoked_at: i64,
    reason: String,
}

#[derive(Deserialize)]
struct VersionOnly {
    v: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    record: String,
    sig: String,
}

fn valid_reason(r: &str) -> bool {
    !r.is_empty() && r.len() <= MAX_REASON_LEN && !r.chars().any(char::is_control)
}

/// A locally created tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRevocation {
    record: Vec<u8>,
    sig: [u8; 64],
}

impl SignedRevocation {
    pub(crate) fn create(
        id: &Identity,
        reason: &str,
        now_ms: i64,
    ) -> Result<Self, RevocationError> {
        if !valid_reason(reason) {
            return Err(RevocationError::InvalidReason);
        }
        if now_ms < 0 {
            return Err(RevocationError::InvalidTimestamp);
        }
        let t = TombstoneV1 {
            v: REVOCATION_VERSION,
            address: id.address().to_string(),
            revoked_at: now_ms,
            reason: reason.to_owned(),
        };
        let record =
            serde_json::to_vec(&t).map_err(|_| RevocationError::Malformed("serialization"))?;
        let sig = id.sign(REVOCATION_DOMAIN, &record);
        Ok(Self { record, sig })
    }

    /// The exact signed bytes.
    pub fn record_bytes(&self) -> &[u8] {
        &self.record
    }

    /// The shareable JSON document.
    pub fn to_document(&self) -> String {
        let d = Document {
            record: B64.encode(&self.record),
            sig: B64.encode(self.sig),
        };
        serde_json::to_string(&d).unwrap_or_default()
    }
}

/// A tombstone whose signature verified under the address it names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRevocation {
    pub address: Address,
    pub revoked_at: i64,
    pub reason: String,
    document: String,
}

impl VerifiedRevocation {
    /// Parse and verify a tombstone document.
    pub fn parse_and_verify(doc: &str, now_ms: i64) -> Result<Self, RevocationError> {
        if doc.len() > MAX_REVOCATION_DOCUMENT_LEN {
            return Err(RevocationError::TooLarge);
        }
        let d: Document =
            serde_json::from_str(doc).map_err(|e| RevocationError::Malformed(json_reason(&e)))?;
        let record = B64
            .decode(&d.record)
            .map_err(|_| RevocationError::Malformed("record is not base64url"))?;
        let sig_bytes = B64
            .decode(&d.sig)
            .map_err(|_| RevocationError::Malformed("sig is not base64url"))?;
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| RevocationError::Malformed("sig must be 64 bytes"))?;
        let ver: VersionOnly = serde_json::from_slice(&record)
            .map_err(|e| RevocationError::Malformed(json_reason(&e)))?;
        if ver.v != REVOCATION_VERSION {
            return Err(RevocationError::UnknownVersion(ver.v));
        }
        let t: TombstoneV1 = serde_json::from_slice(&record)
            .map_err(|e| RevocationError::Malformed(json_reason(&e)))?;
        let address: Address = t.address.parse().map_err(RevocationError::InvalidAddress)?;
        let mut msg = Vec::with_capacity(REVOCATION_DOMAIN.len() + record.len());
        msg.extend_from_slice(REVOCATION_DOMAIN);
        msg.extend_from_slice(&record);
        address
            .verifying_key()
            .verify_strict(&msg, &Signature::from_bytes(&sig))
            .map_err(|_| RevocationError::BadSignature)?;
        if t.revoked_at < 0 || t.revoked_at > now_ms.saturating_add(MAX_REVOKED_AT_FUTURE_MS) {
            return Err(RevocationError::InvalidTimestamp);
        }
        if !valid_reason(&t.reason) {
            return Err(RevocationError::InvalidReason);
        }
        Ok(Self {
            address,
            revoked_at: t.revoked_at,
            reason: t.reason,
            document: doc.to_owned(),
        })
    }

    /// The original signed document.
    pub fn document(&self) -> &str {
        &self.document
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    #[test]
    fn roundtrip_and_tamper() {
        let id = Identity::generate_default(NOW).unwrap();
        let other = Identity::generate_default(NOW).unwrap();
        let t = id.create_revocation("key stolen", NOW).unwrap();
        let doc = t.to_document();
        let v = VerifiedRevocation::parse_and_verify(&doc, NOW).unwrap();
        assert_eq!(v.address, id.address());
        assert_eq!(v.revoked_at, NOW);
        assert_eq!(v.reason, "key stolen");
        // payload names the address; swapping the address breaks the signature
        let swapped = String::from_utf8(t.record_bytes().to_vec())
            .unwrap()
            .replace(&id.address().to_string(), &other.address().to_string());
        let forged = serde_json::to_string(&Document {
            record: B64.encode(swapped.as_bytes()),
            sig: B64.encode(id.sign(REVOCATION_DOMAIN, t.record_bytes())),
        })
        .unwrap();
        assert_eq!(
            VerifiedRevocation::parse_and_verify(&forged, NOW),
            Err(RevocationError::BadSignature)
        );
        // a contact-record signature domain does not verify as a tombstone
        let wrong_domain = serde_json::to_string(&Document {
            record: B64.encode(t.record_bytes()),
            sig: B64.encode(id.sign(b"agentnet/v1/contact-record\0", t.record_bytes())),
        })
        .unwrap();
        assert_eq!(
            VerifiedRevocation::parse_and_verify(&wrong_domain, NOW),
            Err(RevocationError::BadSignature)
        );
        assert!(id.create_revocation("", NOW).is_err());
        assert!(id.create_revocation("bad\nreason", NOW).is_err());
        assert!(id.create_revocation(&"x".repeat(257), NOW).is_err());
        for bad in ["", "{}", "null", "[]", "{\"record\":\"!\",\"sig\":\"!\"}"] {
            assert!(VerifiedRevocation::parse_and_verify(bad, NOW).is_err());
        }
    }
}
