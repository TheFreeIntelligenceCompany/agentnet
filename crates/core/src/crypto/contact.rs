//! Signed contact records: the public, shareable binding of an address to an
//! HPKE KEM public key and an inbox bucket count.
//!
//! Wire format (normative description in `docs/protocol.md`):
//! document = `{"record": b64url(record_bytes), "sig": b64url(sig)}`,
//! `sig = Ed25519(signing_sk, "agentnet/v1/contact-record\0" || record_bytes)`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::Signature;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeS};
use serde::{Deserialize, Deserializer, Serialize};

use agentnet_transport::ContentTopic;

use super::address::{Address, MAX_INBOX_BUCKETS, MIN_INBOX_BUCKETS};
use super::identity::Identity;
use crate::error::{json_reason, ContactError};

/// Domain separation prefix of the contact record signature.
pub const CONTACT_RECORD_DOMAIN: &[u8] = b"agentnet/v1/contact-record\0";
/// Maximum accepted size of a contact document (bytes).
pub const MAX_CONTACT_DOCUMENT_LEN: usize = 4096;
/// A record whose `created_at` is more than this far in the future is rejected.
pub const MAX_CREATED_AT_FUTURE_MS: i64 = 24 * 60 * 60 * 1000;
/// Contact record format version.
pub const CONTACT_RECORD_VERSION: u64 = 1;

/// Accept only an explicit value (possibly `null`) for an `Option` field.
fn required_option<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordV1 {
    v: u64,
    address: String,
    signing_pk: String,
    kem_pk: String,
    /// Monotonically increasing; starts at 1; every KEM rotation increments it.
    key_epoch: u64,
    /// Key epochs strictly below this value are revoked (1 = none revoked).
    revoked_kem_epochs_below: u64,
    /// Cipher suites the owner accepts, strictly ascending.
    suites: Vec<u8>,
    inbox_buckets: u16,
    created_at: i64,
    #[serde(deserialize_with = "required_option")]
    kem_expires_at: Option<i64>,
}

/// Longest `suites` list accepted in a record.
pub const MAX_SUITES: usize = 16;

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

/// A locally created, signed contact record (not yet verified by anyone else).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedContactRecord {
    record: Vec<u8>,
    sig: [u8; 64],
}

impl SignedContactRecord {
    pub(crate) fn create(id: &Identity, suites: &[u8]) -> Self {
        let address = id.address();
        let rec = RecordV1 {
            v: CONTACT_RECORD_VERSION,
            address: address.to_string(),
            signing_pk: B64.encode(address.as_bytes()),
            kem_pk: B64.encode(id.kem_public_key()),
            key_epoch: id.key_epoch(),
            revoked_kem_epochs_below: id.min_valid_epoch(),
            suites: suites.to_vec(),
            inbox_buckets: id.inbox_buckets(),
            created_at: id.kem_created_at(),
            kem_expires_at: id.kem_expires_at(),
        };
        // Serializing a struct of strings and integers cannot fail.
        let record = serde_json::to_vec(&rec).unwrap_or_default();
        let sig = id.sign(CONTACT_RECORD_DOMAIN, &record);
        Self { record, sig }
    }

    /// The exact signed record bytes.
    pub fn record_bytes(&self) -> &[u8] {
        &self.record
    }

    /// The 64-byte signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.sig
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

/// A contact record that passed [`VerifiedContact::parse_and_verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedContact {
    pub address: Address,
    pub kem_pk: [u8; 32],
    /// Monotonic key epoch of `kem_pk`.
    pub key_epoch: u64,
    /// Epochs strictly below this are revoked by the owner.
    pub revoked_kem_epochs_below: u64,
    /// Suites the owner accepts (ascending).
    pub suites: Vec<u8>,
    pub inbox_buckets: u16,
    pub created_at: i64,
    pub kem_expires_at: Option<i64>,
    document: String,
}

/// Convenience alias: `parse_and_verify` returns this.
pub fn parse_and_verify(doc: &str, now_ms: i64) -> Result<VerifiedContact, ContactError> {
    VerifiedContact::parse_and_verify(doc, now_ms)
}

impl VerifiedContact {
    /// Parse and fully verify a contact document, including that the KEM key
    /// has not expired at `now_ms`.
    pub fn parse_and_verify(doc: &str, now_ms: i64) -> Result<Self, ContactError> {
        let c = Self::parse_and_verify_allow_expired(doc, now_ms)?;
        if c.is_kem_expired(now_ms) {
            return Err(ContactError::KemKeyExpired);
        }
        Ok(c)
    }

    /// Like [`Self::parse_and_verify`] but does not reject an expired KEM key.
    /// Intended for re-loading persisted contacts; [`super::envelope::seal`]
    /// still refuses to seal to an expired key.
    pub fn parse_and_verify_allow_expired(doc: &str, now_ms: i64) -> Result<Self, ContactError> {
        if doc.len() > MAX_CONTACT_DOCUMENT_LEN {
            return Err(ContactError::TooLarge);
        }
        let d: Document = serde_json::from_str(doc)
            .map_err(|e| ContactError::MalformedDocument(json_reason(&e)))?;
        let record = B64
            .decode(&d.record)
            .map_err(|_| ContactError::MalformedDocument("record is not base64url"))?;
        let sig_bytes = B64
            .decode(&d.sig)
            .map_err(|_| ContactError::MalformedDocument("sig is not base64url"))?;
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ContactError::MalformedDocument("sig must be 64 bytes"))?;

        let ver: VersionOnly = serde_json::from_slice(&record)
            .map_err(|e| ContactError::MalformedRecord(json_reason(&e)))?;
        if ver.v != CONTACT_RECORD_VERSION {
            return Err(ContactError::UnknownVersion(ver.v));
        }
        let r: RecordV1 = serde_json::from_slice(&record)
            .map_err(|e| ContactError::MalformedRecord(json_reason(&e)))?;

        let address: Address = r.address.parse().map_err(ContactError::InvalidAddress)?;
        let pk = B64
            .decode(&r.signing_pk)
            .map_err(|_| ContactError::MalformedRecord("signing_pk is not base64url"))?;
        if pk.as_slice() != address.as_bytes() {
            return Err(ContactError::AddressMismatch);
        }

        let mut msg = Vec::with_capacity(CONTACT_RECORD_DOMAIN.len() + record.len());
        msg.extend_from_slice(CONTACT_RECORD_DOMAIN);
        msg.extend_from_slice(&record);
        address
            .verifying_key()
            .verify_strict(&msg, &Signature::from_bytes(&sig))
            .map_err(|_| ContactError::BadSignature)?;

        let kem_b = B64
            .decode(&r.kem_pk)
            .map_err(|_| ContactError::MalformedRecord("kem_pk is not base64url"))?;
        let kem_pk: [u8; 32] = kem_b
            .as_slice()
            .try_into()
            .map_err(|_| ContactError::InvalidKemKey)?;
        check_kem_public_key(&kem_pk)?;

        if r.key_epoch < 1
            || r.revoked_kem_epochs_below < 1
            || r.revoked_kem_epochs_below > r.key_epoch
        {
            return Err(ContactError::InvalidKeyEpoch);
        }
        if r.suites.is_empty()
            || r.suites.len() > MAX_SUITES
            || r.suites.first() == Some(&0)
            || r.suites.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(ContactError::InvalidSuites);
        }
        if !(MIN_INBOX_BUCKETS..=MAX_INBOX_BUCKETS).contains(&r.inbox_buckets) {
            return Err(ContactError::InvalidInboxBuckets);
        }
        if r.created_at < 0 || matches!(r.kem_expires_at, Some(e) if e < 0) {
            return Err(ContactError::InvalidTimestamp);
        }
        if r.created_at > now_ms.saturating_add(MAX_CREATED_AT_FUTURE_MS) {
            return Err(ContactError::CreatedInFuture);
        }

        Ok(Self {
            address,
            kem_pk,
            key_epoch: r.key_epoch,
            revoked_kem_epochs_below: r.revoked_kem_epochs_below,
            suites: r.suites,
            inbox_buckets: r.inbox_buckets,
            created_at: r.created_at,
            kem_expires_at: r.kem_expires_at,
            document: doc.to_owned(),
        })
    }

    /// True if every field of the signed record is equal (the document text,
    /// which may differ in whitespace, is not compared).
    pub fn same_record(&self, other: &Self) -> bool {
        self.address == other.address
            && self.kem_pk == other.kem_pk
            && self.key_epoch == other.key_epoch
            && self.revoked_kem_epochs_below == other.revoked_kem_epochs_below
            && self.suites == other.suites
            && self.inbox_buckets == other.inbox_buckets
            && self.created_at == other.created_at
            && self.kem_expires_at == other.kem_expires_at
    }

    /// True if the advertised KEM key is expired at `now_ms`.
    pub fn is_kem_expired(&self, now_ms: i64) -> bool {
        matches!(self.kem_expires_at, Some(e) if e <= now_ms)
    }

    /// The recipient's inbox content topic.
    pub fn inbox_topic(&self) -> ContentTopic {
        self.address.inbox_topic(self.inbox_buckets)
    }

    /// The original signed document, for persistence and later re-verification.
    pub fn document(&self) -> &str {
        &self.document
    }
}

/// Validate a peer KEM public key.
///
/// `PublicKey::from_bytes` in `hpke` 0.15.1 only checks the length, so this
/// rejects (1) the all-zero key explicitly and (2) every key for which the
/// library's own encapsulation fails. HPKE's DH step rejects an all-zero shared
/// secret, which is what every low-order input point produces, so a trial
/// single-shot seal of an empty message is a complete low-order check.
pub(crate) fn check_kem_public_key(pk: &[u8; 32]) -> Result<(), ContactError> {
    if pk.iter().all(|b| *b == 0) {
        return Err(ContactError::InvalidKemKey);
    }
    let key = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(pk)
        .map_err(|_| ContactError::InvalidKemKey)?;
    hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &key,
        b"",
        b"",
        b"",
    )
    .map(|_| ())
    .map_err(|_| ContactError::InvalidKemKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn id() -> Identity {
        Identity::generate_default(NOW).unwrap()
    }

    #[test]
    fn roundtrip() {
        let id = id();
        let doc = id.contact_record().to_document();
        assert!(doc.len() < MAX_CONTACT_DOCUMENT_LEN);
        let c = VerifiedContact::parse_and_verify(&doc, NOW).unwrap();
        assert_eq!(c.address, id.address());
        assert_eq!(c.kem_pk, id.kem_public_key());
        assert_eq!(c.inbox_buckets, 16);
        assert_eq!(c.created_at, NOW);
        assert_eq!(c.kem_expires_at, None);
        assert_eq!(c.document(), doc);
        assert_eq!(c.inbox_topic(), id.inbox_topic());
        // persisted document re-verifies to the same value
        assert_eq!(
            VerifiedContact::parse_and_verify(c.document(), NOW).unwrap(),
            c
        );
        assert_eq!(parse_and_verify(&doc, NOW).unwrap(), c);
    }

    #[test]
    fn record_layout_is_as_specified() {
        let id = id();
        let rec = id.contact_record();
        let s = std::str::from_utf8(rec.record_bytes()).unwrap();
        let expect = format!(
            "{{\"v\":1,\"address\":\"{}\",\"signing_pk\":\"{}\",\"kem_pk\":\"{}\",\"key_epoch\":1,\"revoked_kem_epochs_below\":1,\"suites\":[1],\"inbox_buckets\":16,\"created_at\":{NOW},\"kem_expires_at\":null}}",
            id.address(),
            B64.encode(id.address().as_bytes()),
            B64.encode(id.kem_public_key())
        );
        assert_eq!(s, expect);
    }

    fn doc_with_record(id: &Identity, record: &[u8], sig_over: &[u8]) -> String {
        let sig = id.sign(CONTACT_RECORD_DOMAIN, sig_over);
        serde_json::to_string(&Document {
            record: B64.encode(record),
            sig: B64.encode(sig),
        })
        .unwrap()
    }

    fn signed_doc(id: &Identity, record: &str) -> String {
        doc_with_record(id, record.as_bytes(), record.as_bytes())
    }

    fn record_json(id: &Identity, tweak: impl Fn(&mut serde_json::Value)) -> String {
        let rec = id.contact_record();
        let mut v: serde_json::Value = serde_json::from_slice(rec.record_bytes()).unwrap();
        tweak(&mut v);
        serde_json::to_string(&v).unwrap()
    }

    #[test]
    fn tampered_fields_rejected() {
        let id = id();
        let other = Identity::generate_default(NOW).unwrap();
        let rec = id.contact_record();
        // each field edited after signing -> signature failure (or address mismatch)
        for (field, newval) in [
            ("inbox_buckets", serde_json::json!(32)),
            ("created_at", serde_json::json!(NOW + 1)),
            ("key_epoch", serde_json::json!(2)),
            ("revoked_kem_epochs_below", serde_json::json!(1)),
            ("suites", serde_json::json!([1, 2])),
            ("kem_expires_at", serde_json::json!(NOW + 100_000)),
            (
                "kem_pk",
                serde_json::json!(B64.encode(other.kem_public_key())),
            ),
        ] {
            let mut v: serde_json::Value = serde_json::from_slice(rec.record_bytes()).unwrap();
            v[field] = newval;
            let edited = serde_json::to_vec(&v).unwrap();
            let d = serde_json::to_string(&Document {
                record: B64.encode(&edited),
                sig: B64.encode(rec.signature()),
            })
            .unwrap();
            assert_eq!(
                VerifiedContact::parse_and_verify(&d, NOW),
                Err(ContactError::BadSignature),
                "field {field}"
            );
        }
        // address replaced: record address != signing_pk
        let mut v: serde_json::Value = serde_json::from_slice(rec.record_bytes()).unwrap();
        v["address"] = serde_json::json!(other.address().to_string());
        let d = signed_doc(&id, &serde_json::to_string(&v).unwrap());
        assert_eq!(
            VerifiedContact::parse_and_verify(&d, NOW),
            Err(ContactError::AddressMismatch)
        );
        // signing_pk replaced by other's, address left: mismatch
        let mut v: serde_json::Value = serde_json::from_slice(rec.record_bytes()).unwrap();
        v["signing_pk"] = serde_json::json!(B64.encode(other.address().as_bytes()));
        let d = signed_doc(&id, &serde_json::to_string(&v).unwrap());
        assert_eq!(
            VerifiedContact::parse_and_verify(&d, NOW),
            Err(ContactError::AddressMismatch)
        );
        // signature bit flip
        let mut sig = *rec.signature();
        sig[0] ^= 1;
        let d = serde_json::to_string(&Document {
            record: B64.encode(rec.record_bytes()),
            sig: B64.encode(sig),
        })
        .unwrap();
        assert_eq!(
            VerifiedContact::parse_and_verify(&d, NOW),
            Err(ContactError::BadSignature)
        );
        // signed by a different key entirely
        let d = doc_with_record(&other, rec.record_bytes(), rec.record_bytes());
        assert_eq!(
            VerifiedContact::parse_and_verify(&d, NOW),
            Err(ContactError::BadSignature)
        );
    }

    #[test]
    fn swapped_kem_key_from_other_identity() {
        let a = id();
        let b = Identity::generate_default(NOW).unwrap();
        // attacker takes A's signature and B's kem key in a re-encoded record
        let recj = record_json(&a, |v| {
            v["kem_pk"] = serde_json::json!(B64.encode(b.kem_public_key()))
        });
        let d = serde_json::to_string(&Document {
            record: B64.encode(recj.as_bytes()),
            sig: B64.encode(a.contact_record().signature()),
        })
        .unwrap();
        assert_eq!(
            VerifiedContact::parse_and_verify(&d, NOW),
            Err(ContactError::BadSignature)
        );
    }

    #[test]
    fn strict_record_validation() {
        let id = id();
        type Tweak = Box<dyn Fn(&mut serde_json::Value)>;
        let cases: Vec<(&str, Tweak, ContactError)> = vec![
            (
                "unknown field",
                Box::new(|v| v["extra"] = serde_json::json!(1)),
                ContactError::MalformedRecord("unknown field"),
            ),
            (
                "missing field",
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("kem_expires_at");
                }),
                ContactError::MalformedRecord("missing field"),
            ),
            (
                "buckets 0",
                Box::new(|v| v["inbox_buckets"] = serde_json::json!(0)),
                ContactError::InvalidInboxBuckets,
            ),
            (
                "buckets 257",
                Box::new(|v| v["inbox_buckets"] = serde_json::json!(257)),
                ContactError::InvalidInboxBuckets,
            ),
            (
                "version 2",
                Box::new(|v| v["v"] = serde_json::json!(2)),
                ContactError::UnknownVersion(2),
            ),
            (
                "kem short",
                Box::new(|v| v["kem_pk"] = serde_json::json!(B64.encode([1u8; 31]))),
                ContactError::InvalidKemKey,
            ),
            (
                "kem zero",
                Box::new(|v| v["kem_pk"] = serde_json::json!(B64.encode([0u8; 32]))),
                ContactError::InvalidKemKey,
            ),
            (
                "future",
                Box::new(|v| {
                    v["created_at"] = serde_json::json!(NOW + MAX_CREATED_AT_FUTURE_MS + 1)
                }),
                ContactError::CreatedInFuture,
            ),
            (
                "negative",
                Box::new(|v| v["created_at"] = serde_json::json!(-1)),
                ContactError::InvalidTimestamp,
            ),
            (
                "epoch 0",
                Box::new(|v| v["key_epoch"] = serde_json::json!(0)),
                ContactError::InvalidKeyEpoch,
            ),
            (
                "floor 0",
                Box::new(|v| v["revoked_kem_epochs_below"] = serde_json::json!(0)),
                ContactError::InvalidKeyEpoch,
            ),
            (
                "floor above epoch",
                Box::new(|v| v["revoked_kem_epochs_below"] = serde_json::json!(2)),
                ContactError::InvalidKeyEpoch,
            ),
            (
                "no suites",
                Box::new(|v| v["suites"] = serde_json::json!([])),
                ContactError::InvalidSuites,
            ),
            (
                "unsorted suites",
                Box::new(|v| v["suites"] = serde_json::json!([2, 1])),
                ContactError::InvalidSuites,
            ),
            (
                "duplicate suites",
                Box::new(|v| v["suites"] = serde_json::json!([1, 1])),
                ContactError::InvalidSuites,
            ),
            (
                "suite zero",
                Box::new(|v| v["suites"] = serde_json::json!([0, 1])),
                ContactError::InvalidSuites,
            ),
            (
                "suite out of range",
                Box::new(|v| v["suites"] = serde_json::json!([1, 256])),
                ContactError::MalformedRecord("invalid field value or type"),
            ),
            (
                "float time",
                Box::new(|v| v["created_at"] = serde_json::json!(1.5)),
                ContactError::MalformedRecord("invalid field value or type"),
            ),
        ];
        for (name, tweak, expected) in cases {
            let d = signed_doc(&id, &record_json(&id, tweak));
            assert_eq!(
                VerifiedContact::parse_and_verify(&d, NOW),
                Err(expected),
                "{name}"
            );
        }
        // exactly at the future boundary is accepted
        let d = signed_doc(
            &id,
            &record_json(&id, |v| {
                v["created_at"] = serde_json::json!(NOW + MAX_CREATED_AT_FUTURE_MS)
            }),
        );
        assert!(VerifiedContact::parse_and_verify(&d, NOW).is_ok());
    }

    #[test]
    fn duplicate_keys_rejected() {
        let id = id();
        let rec = id.contact_record();
        let s = std::str::from_utf8(rec.record_bytes()).unwrap();
        let dup = s.replacen("{\"v\":1,", "{\"v\":1,\"v\":1,", 1);
        assert_eq!(
            VerifiedContact::parse_and_verify(&signed_doc(&id, &dup), NOW),
            Err(ContactError::MalformedRecord("duplicate field"))
        );
        let dup = s.replacen(
            "\"inbox_buckets\":16,",
            "\"inbox_buckets\":16,\"inbox_buckets\":1,",
            1,
        );
        assert!(VerifiedContact::parse_and_verify(&signed_doc(&id, &dup), NOW).is_err());
    }

    #[test]
    fn kem_expiry() {
        let mut id = id();
        id.rotate_kem(NOW, NOW, Some(NOW + 1000)).unwrap();
        let doc = id.contact_record().to_document();
        assert!(VerifiedContact::parse_and_verify(&doc, NOW).is_ok());
        assert!(VerifiedContact::parse_and_verify(&doc, NOW + 999).is_ok());
        assert_eq!(
            VerifiedContact::parse_and_verify(&doc, NOW + 1000),
            Err(ContactError::KemKeyExpired)
        );
        let c = VerifiedContact::parse_and_verify_allow_expired(&doc, NOW + 5000).unwrap();
        assert!(c.is_kem_expired(NOW + 5000));
    }

    #[test]
    fn document_shape_errors() {
        let id = id();
        let doc = id.contact_record().to_document();
        assert_eq!(
            VerifiedContact::parse_and_verify(&"x".repeat(MAX_CONTACT_DOCUMENT_LEN + 1), NOW),
            Err(ContactError::TooLarge)
        );
        for bad in [
            "",
            "{}",
            "[]",
            "null",
            "{\"record\":\"\",\"sig\":\"\"}",
            "{\"record\":\"!!\",\"sig\":\"!!\"}",
        ] {
            assert!(
                VerifiedContact::parse_and_verify(bad, NOW).is_err(),
                "{bad}"
            );
        }
        let extra = doc.replacen('{', "{\"x\":1,", 1);
        assert!(VerifiedContact::parse_and_verify(&extra, NOW).is_err());
        // padded base64 rejected
        let d: Document = serde_json::from_str(&doc).unwrap();
        let padded = serde_json::to_string(&Document {
            record: format!("{}=", d.record),
            sig: d.sig.clone(),
        })
        .unwrap();
        assert!(VerifiedContact::parse_and_verify(&padded, NOW).is_err());
    }

    #[test]
    fn low_order_kem_keys_rejected() {
        // Known small-order points of Curve25519 (little-endian u coordinates).
        let hex = |s: &str| -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, o) in out.iter_mut().enumerate() {
                *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        };
        let pts = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0100000000000000000000000000000000000000000000000000000000000080",
        ];
        for p in pts {
            assert_eq!(
                check_kem_public_key(&hex(p)),
                Err(ContactError::InvalidKemKey),
                "{p}"
            );
        }
        let ok = Identity::generate_default(NOW).unwrap().kem_public_key();
        assert!(check_kem_public_key(&ok).is_ok());
    }
}
