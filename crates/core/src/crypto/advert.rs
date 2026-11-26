//! Signed, expiring capability advertisements (optional discovery feature).
//!
//! An advertisement is a PLAINTEXT, publicly readable statement by an agent:
//! "this address offers these capabilities until this time; here is my current
//! signed contact record". It is published on a host-authorised discovery
//! content topic, never on an inbox topic. Wire format (normative description in
//! `docs/discovery.md`):
//!
//! * document = `{"record": b64url(record_bytes), "sig": b64url(sig)}` (the same
//!   wrapper as contact records and tombstones),
//! * `record_bytes = {"v":1,"address":…,"contact_record":"<document>",
//!   "capabilities":[{"name":…,"description":…}],"display_name":…(optional),
//!   "issued_at":ms,"expires_at":ms,"seq":n}`,
//! * `sig = Ed25519(signing_sk, "agentnet/v1/capability-advert\0" || record_bytes)`,
//! * frame = `b"AD" || 0x01 || document_bytes`, so an advertisement can never be
//!   mistaken for a sealed message frame (`b"AN"`).
//!
//! This adds a signing domain only: no new cryptographic construction. A valid
//! advertisement proves that the holder of the address key made the statement;
//! it proves nothing about whether the capabilities are real or the agent is
//! trustworthy. Receiving one never creates a contact.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use super::address::Address;
use super::contact::VerifiedContact;
use super::identity::Identity;
use crate::error::{json_reason, AdvertError};

/// Domain separation prefix of the advertisement signature.
pub const ADVERT_DOMAIN: &[u8] = b"agentnet/v1/capability-advert\0";
/// Advertisement format version.
pub const ADVERT_VERSION: u64 = 1;
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
struct AdvertV1 {
    v: u64,
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    record: String,
    sig: String,
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

/// True if `payload` starts with the sealed-message frame magic.
pub fn has_sealed_magic(payload: &[u8]) -> bool {
    payload.get(0..2) == Some(&super::envelope::FRAME_MAGIC[..])
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
    sig: [u8; 64],
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
        let rec = AdvertV1 {
            v: ADVERT_VERSION,
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
        let sig = id.sign(ADVERT_DOMAIN, &record);
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

    /// The document wrapped in an advertisement frame, ready to publish.
    pub fn to_frame(&self) -> Vec<u8> {
        encode_frame(&self.to_document())
    }
}

/// The content of an advertisement to sign.
#[derive(Clone, Copy, Debug)]
pub struct AdvertContent<'a> {
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
    /// Parse and fully verify an advertisement document at `now_ms`.
    pub fn parse_and_verify(
        doc: &str,
        now_ms: i64,
        limits: &AdvertLimits,
    ) -> Result<Self, AdvertError> {
        if doc.len() > MAX_ADVERT_DOCUMENT_LEN {
            return Err(AdvertError::TooLarge);
        }
        let d: Document = serde_json::from_str(doc)
            .map_err(|e| AdvertError::Malformed(json_reason(&e)))?;
        let record = B64
            .decode(&d.record)
            .map_err(|_| AdvertError::Malformed("record is not base64url"))?;
        if record.len() > MAX_ADVERT_RECORD_LEN {
            return Err(AdvertError::TooLarge);
        }
        let sig_bytes = B64
            .decode(&d.sig)
            .map_err(|_| AdvertError::Malformed("sig is not base64url"))?;
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AdvertError::Malformed("sig must be 64 bytes"))?;
        let ver: VersionOnly = serde_json::from_slice(&record)
            .map_err(|e| AdvertError::Malformed(json_reason(&e)))?;
        if ver.v != ADVERT_VERSION {
            return Err(AdvertError::UnknownVersion(ver.v));
        }
        let r: AdvertV1 = serde_json::from_slice(&record)
            .map_err(|e| AdvertError::Malformed(json_reason(&e)))?;
        let address: Address = r.address.parse().map_err(AdvertError::InvalidAddress)?;
        let mut msg = Vec::with_capacity(ADVERT_DOMAIN.len() + record.len());
        msg.extend_from_slice(ADVERT_DOMAIN);
        msg.extend_from_slice(&record);
        address
            .verifying_key()
            .verify_strict(&msg, &Signature::from_bytes(&sig))
            .map_err(|_| AdvertError::BadSignature)?;

        let contact = VerifiedContact::parse_and_verify(&r.contact_record, now_ms)
            .map_err(AdvertError::BadContact)?;
        if contact.address != address {
            return Err(AdvertError::ContactAddressMismatch);
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

    /// A document whose record bytes are exactly `record`, signed by `signer`
    /// under the advertisement domain (so anything can be forged, including
    /// records naming another address or embedding another contact record).
    pub fn sign_record_as(signer: &Identity, record: &[u8]) -> String {
        serde_json::to_string(&Document {
            record: B64.encode(record),
            sig: B64.encode(signer.sign(ADVERT_DOMAIN, record)),
        })
        .unwrap_or_default()
    }

    /// A document with an arbitrary record and signature.
    pub fn document(record: &[u8], sig: &[u8; 64]) -> String {
        serde_json::to_string(&Document {
            record: B64.encode(record),
            sig: B64.encode(sig),
        })
        .unwrap_or_default()
    }

    /// Split a document into `(record bytes, signature)`.
    pub fn split(doc: &str) -> Option<(Vec<u8>, [u8; 64])> {
        let d: Document = serde_json::from_str(doc).ok()?;
        let record = B64.decode(&d.record).ok()?;
        let sig: [u8; 64] = B64.decode(&d.sig).ok()?.as_slice().try_into().ok()?;
        Some((record, sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;
    const LIM: AdvertLimits = AdvertLimits {
        max_ttl_ms: 86_400_000,
        clock_skew_ms: 120_000,
        max_capabilities: 16,
    };

    fn cap(n: &str, d: &str) -> Capability {
        Capability {
            name: n.into(),
            description: d.into(),
        }
    }

    fn content<'a>(caps: &'a [Capability], seq: u64) -> AdvertContent<'a> {
        AdvertContent {
            capabilities: caps,
            display_name: Some("Alice"),
            issued_at: NOW,
            expires_at: NOW + 3_600_000,
            seq,
        }
    }

    fn doc_of(_id: &Identity, rec: &serde_json::Value, sign_with: &Identity) -> String {
        let bytes = serde_json::to_vec(rec).unwrap();
        serde_json::to_string(&Document {
            record: B64.encode(&bytes),
            sig: B64.encode(sign_with.sign(ADVERT_DOMAIN, &bytes)),
        })
        .unwrap()
    }

    fn record_value(a: &SignedAdvert) -> serde_json::Value {
        serde_json::from_slice(a.record_bytes()).unwrap()
    }

    #[test]
    fn roundtrip_and_layout() {
        let id = Identity::generate_default(NOW).unwrap();
        let caps = [cap("translate.de", "German to English")];
        let a = id.create_advert(&content(&caps, 3), &LIM).unwrap();
        let s = std::str::from_utf8(a.record_bytes()).unwrap();
        assert!(s.starts_with("{\"v\":1,\"address\":\"an1"));
        assert!(s.contains("\"capabilities\":[{\"name\":\"translate.de\",\"description\":\"German to English\"}],\"display_name\":\"Alice\",\"issued_at\":"));
        assert!(s.ends_with(&format!(
            "\"issued_at\":{NOW},\"expires_at\":{},\"seq\":3}}",
            NOW + 3_600_000
        )));
        let v = VerifiedAdvert::parse_and_verify(&a.to_document(), NOW + 1, &LIM).unwrap();
        assert_eq!(v.address, id.address());
        assert_eq!(v.seq, 3);
        assert_eq!(v.capabilities, caps.to_vec());
        assert_eq!(v.display_name.as_deref(), Some("Alice"));
        assert_eq!(v.contact_record(), id.contact_record().to_document());
        assert!(!v.is_withdrawal());
        // no display name: the field is omitted
        let mut c = content(&caps, 1);
        c.display_name = None;
        let a2 = id.create_advert(&c, &LIM).unwrap();
        assert!(!std::str::from_utf8(a2.record_bytes())
            .unwrap()
            .contains("display_name"));
        let v2 = VerifiedAdvert::parse_and_verify(&a2.to_document(), NOW, &LIM).unwrap();
        assert_eq!(v2.display_name, None);
        // withdrawal
        let w = id.create_advert(&content(&[], 4), &LIM).unwrap();
        assert!(VerifiedAdvert::parse_and_verify(&w.to_document(), NOW, &LIM)
            .unwrap()
            .is_withdrawal());
    }

    #[test]
    fn frame_roundtrip_and_confusion() {
        let id = Identity::generate_default(NOW).unwrap();
        let a = id
            .create_advert(&content(&[cap("x", "")], 1), &LIM)
            .unwrap();
        let f = a.to_frame();
        assert_eq!(&f[..3], b"AD\x01");
        assert_eq!(decode_frame(&f).unwrap(), a.to_document());
        assert!(has_advert_magic(&f) && !has_sealed_magic(&f));
        assert!(has_sealed_magic(b"AN\x01rest") && !has_advert_magic(b"AN\x01rest"));
        for bad in [
            &b""[..],
            b"AD",
            b"AD\x02{}",
            b"AN\x01{}",
            b"AD\x01\xff\xfe",
            b"XX\x01{}",
        ] {
            assert_eq!(decode_frame(bad), Err(AdvertError::BadFrame), "{bad:?}");
        }
        let big = vec![b'a'; MAX_ADVERT_FRAME_LEN + 1];
        assert_eq!(decode_frame(&big), Err(AdvertError::BadFrame));
    }

    #[test]
    fn forgeries_are_rejected() {
        let id = Identity::generate_default(NOW).unwrap();
        let other = Identity::generate_default(NOW).unwrap();
        let caps = [cap("a", "d")];
        let a = id.create_advert(&content(&caps, 1), &LIM).unwrap();
        let rec = record_value(&a);
        let verify = |d: &str| VerifiedAdvert::parse_and_verify(d, NOW, &LIM);
        // signed by another key
        assert_eq!(
            verify(&doc_of(&id, &rec, &other)),
            Err(AdvertError::BadSignature)
        );
        // address swapped to the signer's, record names the victim
        let mut r = rec.clone();
        r["address"] = serde_json::json!(other.address().to_string());
        assert_eq!(verify(&doc_of(&id, &r, &id)), Err(AdvertError::BadSignature));
        // signed by `other` for `other`'s address but embedding id's contact record
        assert_eq!(
            verify(&doc_of(&other, &r, &other)),
            Err(AdvertError::ContactAddressMismatch)
        );
        // embedded contact record of someone else, signed by the advertiser
        let mut r = rec.clone();
        r["contact_record"] = serde_json::json!(other.contact_record().to_document());
        assert_eq!(
            verify(&doc_of(&id, &r, &id)),
            Err(AdvertError::ContactAddressMismatch)
        );
        // tampered capability after signing
        let mut r = rec.clone();
        r["capabilities"][0]["name"] = serde_json::json!("evil");
        let bytes = serde_json::to_vec(&r).unwrap();
        let tampered = serde_json::to_string(&Document {
            record: B64.encode(&bytes),
            sig: B64.encode(id.sign(ADVERT_DOMAIN, a.record_bytes())),
        })
        .unwrap();
        assert_eq!(verify(&tampered), Err(AdvertError::BadSignature));
        // wrong signing domain (contact-record domain)
        let wrong = serde_json::to_string(&Document {
            record: B64.encode(a.record_bytes()),
            sig: B64.encode(id.sign(b"agentnet/v1/contact-record\0", a.record_bytes())),
        })
        .unwrap();
        assert_eq!(verify(&wrong), Err(AdvertError::BadSignature));
        // unknown field in a correctly signed record
        let mut r = rec.clone();
        r["extra"] = serde_json::json!(1);
        assert!(matches!(
            verify(&doc_of(&id, &r, &id)),
            Err(AdvertError::Malformed(_))
        ));
        // unknown version
        let mut r = rec.clone();
        r["v"] = serde_json::json!(2);
        assert_eq!(
            verify(&doc_of(&id, &r, &id)),
            Err(AdvertError::UnknownVersion(2))
        );
        for bad in ["", "{}", "null", "[]", "{\"record\":\"!\",\"sig\":\"!\"}"] {
            assert!(verify(bad).is_err());
        }
    }

    #[test]
    fn time_and_field_rules() {
        let id = Identity::generate_default(NOW).unwrap();
        let caps = [cap("a", "")];
        let sign = |f: &dyn Fn(&mut serde_json::Value)| {
            let a = id.create_advert(&content(&caps, 1), &LIM).unwrap();
            let mut r = record_value(&a);
            f(&mut r);
            doc_of(&id, &r, &id)
        };
        let verify = |d: &str, now: i64| VerifiedAdvert::parse_and_verify(d, now, &LIM);
        let ok = sign(&|_| {});
        assert!(verify(&ok, NOW).is_ok());
        // expired
        assert_eq!(verify(&ok, NOW + 3_600_000), Err(AdvertError::Expired));
        // issued in the future beyond skew
        assert_eq!(
            verify(&ok, NOW - 120_001),
            Err(AdvertError::FromFuture)
        );
        assert!(verify(&ok, NOW - 120_000).is_ok());
        // ttl above the maximum
        let long = sign(&|r| r["expires_at"] = serde_json::json!(NOW + 86_400_001));
        assert_eq!(verify(&long, NOW), Err(AdvertError::TtlTooLong));
        // expires before issued
        let neg = sign(&|r| r["expires_at"] = serde_json::json!(NOW - 1));
        assert_eq!(verify(&neg, NOW), Err(AdvertError::InvalidTimestamp));
        // seq beyond i64
        let big = sign(&|r| r["seq"] = serde_json::json!(u64::MAX));
        assert_eq!(verify(&big, NOW), Err(AdvertError::InvalidSeq));
        // fields
        for (name, desc) in [
            ("UPPER", "d"),
            ("", "d"),
            ("has space", "d"),
            ("ok", "bad\u{7}ctl"),
        ] {
            let d = sign(&|r| {
                r["capabilities"] = serde_json::json!([{"name": name, "description": desc}])
            });
            assert!(
                matches!(verify(&d, NOW), Err(AdvertError::InvalidCapability(_))),
                "{name:?}"
            );
        }
        let d = sign(&|r| {
            r["capabilities"] = serde_json::json!([{"name": "a", "description": "x".repeat(257)}])
        });
        assert!(verify(&d, NOW).is_err());
        let d = sign(&|r| {
            r["capabilities"] = serde_json::json!([
                {"name": "a", "description": ""}, {"name": "a", "description": ""}
            ])
        });
        assert!(verify(&d, NOW).is_err());
        let many: Vec<_> = (0..17)
            .map(|i| serde_json::json!({"name": format!("c{i}"), "description": ""}))
            .collect();
        let d = sign(&|r| r["capabilities"] = serde_json::Value::Array(many.clone()));
        assert!(verify(&d, NOW).is_err());
        let d = sign(&|r| r["display_name"] = serde_json::json!("x".repeat(65)));
        assert_eq!(verify(&d, NOW), Err(AdvertError::InvalidDisplayName));
        let d = sign(&|r| r["display_name"] = serde_json::json!(""));
        assert_eq!(verify(&d, NOW), Err(AdvertError::InvalidDisplayName));
        let d = sign(&|r| r["display_name"] = serde_json::json!("a\nb"));
        assert_eq!(verify(&d, NOW), Err(AdvertError::InvalidDisplayName));
        // display_name: null is the same as absent
        let d = sign(&|r| r["display_name"] = serde_json::Value::Null);
        assert_eq!(verify(&d, NOW).unwrap().display_name, None);
        // creation enforces the same rules
        let mut c = content(&caps, 1);
        c.expires_at = NOW + 86_400_001;
        assert_eq!(
            id.create_advert(&c, &LIM).unwrap_err(),
            AdvertError::TtlTooLong
        );
        assert!(id
            .create_advert(&content(&[cap("BAD", "")], 1), &LIM)
            .is_err());
        // an expired embedded KEM key invalidates the advertisement
        let mut rot = Identity::generate_default(NOW).unwrap();
        rot.rotate_kem(NOW, NOW, Some(NOW + 1000)).unwrap();
        let a = rot.create_advert(&content(&caps, 1), &LIM).unwrap();
        assert!(matches!(
            verify(&a.to_document(), NOW + 2000),
            Err(AdvertError::BadContact(_))
        ));
    }

    #[test]
    fn record_size_is_capped() {
        let id = Identity::generate_default(NOW).unwrap();
        // 64 capabilities of maximal size exceed 8 KiB
        let caps: Vec<_> = (0..64)
            .map(|i| cap(&format!("{:0>64}", i), &"x".repeat(256)))
            .collect();
        let lim = AdvertLimits {
            max_capabilities: 64,
            ..LIM
        };
        assert_eq!(
            id.create_advert(&content(&caps, 1), &lim).unwrap_err(),
            AdvertError::TooLarge
        );
    }

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// The frame and document parsers never panic and never accept noise.
            #[test]
            fn parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
                let _ = decode_frame(&bytes);
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    prop_assert!(VerifiedAdvert::parse_and_verify(s, NOW, &LIM).is_err());
                }
                let mut framed = b"AD\x01".to_vec();
                framed.extend_from_slice(&bytes);
                if let Ok(doc) = decode_frame(&framed) {
                    prop_assert!(VerifiedAdvert::parse_and_verify(doc, NOW, &LIM).is_err());
                }
            }

            /// Structured near-misses (valid JSON wrapper, arbitrary record bytes,
            /// arbitrary signature) are rejected without panicking.
            #[test]
            fn wrapper_with_arbitrary_record_is_rejected(
                record in proptest::collection::vec(any::<u8>(), 0..512),
                sig in proptest::collection::vec(any::<u8>(), 0..80),
            ) {
                let doc = serde_json::to_string(&Document {
                    record: B64.encode(&record),
                    sig: B64.encode(&sig),
                }).unwrap();
                prop_assert!(VerifiedAdvert::parse_and_verify(&doc, NOW, &LIM).is_err());
            }
        }
    }
}
