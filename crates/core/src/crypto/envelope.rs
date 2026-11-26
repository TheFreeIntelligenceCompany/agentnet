//! Sealed envelopes: signed JSON inside a padded HPKE single-shot ciphertext.
//!
//! Frame layout (all offsets in bytes):
//!
//! ```text
//! 0   2  magic "AN"
//! 2   1  frame version (0x01)
//! 3   1  suite id (0x01 = DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305)
//! 4  32  HPKE encapsulated key (enc)
//! 36  n  ciphertext = AEAD(plaintext) || 16-byte tag
//! ```
//!
//! `plaintext = u32_be(inner_len) || inner || zero padding` with
//! `inner = sig(64) || envelope_json`. `info = "agentnet/v1/hpke\0" || recipient_kem_pk`,
//! `aad = frame header (first 4 bytes)`.
//!
//! This module performs **no replay detection**: callers (the engine) must
//! persist `(sender, message_id)` of every accepted envelope and drop repeats.
//! `open` is a pure function of its inputs.

use serde::{Deserialize, Serialize};

use super::address::Address;
use super::contact::VerifiedContact;
use super::hpke_suite::HpkeBaseEd25519;
use super::identity::{random_bytes, Identity};
use super::protection::MessageProtection;
use crate::error::{OpenError, SealError};

/// Domain separation prefix of the envelope signature.
pub const ENVELOPE_DOMAIN: &[u8] = b"agentnet/v1/envelope\0";
/// Domain separation prefix of the HPKE `info` string (followed by the recipient KEM key).
pub const HPKE_INFO_DOMAIN: &[u8] = b"agentnet/v1/hpke\0";

/// Frame magic.
pub const FRAME_MAGIC: [u8; 2] = *b"AN";
/// Frame format version.
pub const FRAME_VERSION: u8 = 1;
/// Suite id 1: DHKEM(X25519,HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
pub const SUITE_ID: u8 = 1;
/// The frame header, also used as HPKE `aad`.
pub const FRAME_HEADER: [u8; 4] = [b'A', b'N', FRAME_VERSION, SUITE_ID];
pub const HEADER_LEN: usize = 4;
/// Length of the HPKE encapsulated key.
pub const ENC_LEN: usize = 32;
/// Length of the AEAD tag.
pub const TAG_LEN: usize = 16;
/// Bytes of a frame that are not plaintext: header + enc + tag.
pub const FRAME_OVERHEAD: usize = HEADER_LEN + ENC_LEN + TAG_LEN;
/// Length of the plaintext length prefix.
pub const LEN_PREFIX_LEN: usize = 4;
/// Length of the Ed25519 signature.
pub const SIG_LEN: usize = 64;
/// Bytes of the plaintext that are not the envelope JSON: length prefix + signature.
pub const PLAINTEXT_OVERHEAD: usize = LEN_PREFIX_LEN + SIG_LEN;
/// Smallest padding bucket (plaintext bytes).
pub const MIN_BUCKET: usize = 512;
/// Offset of the HPKE `enc` within a frame.
pub const ENC_OFFSET: usize = HEADER_LEN;
/// Offset of the ciphertext within a frame.
pub const CIPHERTEXT_OFFSET: usize = HEADER_LEN + ENC_LEN;
/// Default maximum frame size (a 150 KiB limit is typical of Waku nodes; the
/// engine should pass the transport's actual limit).
pub const DEFAULT_MAX_FRAME_LEN: usize = 150 * 1024;
/// Envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

pub const MESSAGE_TYPE_MESSAGE: &str = "message";
pub const MESSAGE_TYPE_ACK_RECEIVED: &str = "ack.received";
pub const MESSAGE_TYPE_TASK_REQUEST: &str = "task.request";
pub const MESSAGE_TYPE_TASK_RESULT: &str = "task.result";
/// Reserved: body is the sender's new signed contact-record document.
pub const MESSAGE_TYPE_CONTACT_UPDATE: &str = "contact.update";
/// Reserved: body is the sender's signed identity-revocation document.
pub const MESSAGE_TYPE_IDENTITY_REVOKED: &str = "identity.revoked";

pub const MAX_MESSAGE_TYPE_LEN: usize = 64;
pub const MAX_ID_LEN: usize = 128;

/// The logical message. Serialized as JSON (field `message_type` is named `type`);
/// the exact serialized bytes are signed and never re-serialized by `open`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u8,
    pub message_id: String,
    pub sender: Address,
    pub recipient: Address,
    /// Suite id the envelope was sealed under (signed; checked against the
    /// frame header on open). Set by `seal`.
    pub suite: u8,
    /// `key_epoch` of the recipient KEM key the envelope was sealed to (signed;
    /// checked against the key that decrypted the frame). Set by `seal`;
    /// epochs start at 1, so 0 marks "not sealed yet".
    pub recipient_key_epoch: u64,
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub body: String,
}

/// Generate a fresh random lowercase UUIDv4 string.
pub fn new_message_id() -> Result<String, SealError> {
    let mut b = [0u8; 16];
    random_bytes(&mut b).map_err(|_| SealError::Crypto("random number generator failed"))?;
    Ok(uuid::Builder::from_random_bytes(b).into_uuid().to_string())
}

fn is_uuid_v4(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    match uuid::Uuid::parse_str(s) {
        Ok(u) => {
            u.get_version_num() == 4
                && u.get_variant() == uuid::Variant::RFC4122
                && u.hyphenated().to_string() == s
        }
        Err(_) => false,
    }
}

fn is_valid_message_type(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_MESSAGE_TYPE_LEN
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

fn is_valid_opt_id(s: &Option<String>) -> bool {
    match s {
        None => true,
        Some(s) => {
            !s.is_empty() && s.len() <= MAX_ID_LEN && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        }
    }
}

impl Envelope {
    /// A new `v=1` envelope with a random message id, `created_at = now_ms`
    /// and `expires_at = now_ms + ttl_ms`.
    pub fn new(
        sender: Address,
        recipient: Address,
        message_type: &str,
        body: String,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<Self, SealError> {
        Ok(Self {
            v: ENVELOPE_VERSION,
            message_id: new_message_id()?,
            sender,
            recipient,
            suite: SUITE_ID,
            recipient_key_epoch: 0,
            message_type: message_type.to_owned(),
            conversation_id: None,
            correlation_id: None,
            created_at: now_ms,
            expires_at: now_ms.saturating_add(ttl_ms),
            body,
        })
    }

    /// Check version, id and type syntax (not times, not addresses).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.v != ENVELOPE_VERSION {
            return Err("v");
        }
        if !is_uuid_v4(&self.message_id) {
            return Err("message_id");
        }
        if !is_valid_message_type(&self.message_type) {
            return Err("type");
        }
        if !is_valid_opt_id(&self.conversation_id) {
            return Err("conversation_id");
        }
        if !is_valid_opt_id(&self.correlation_id) {
            return Err("correlation_id");
        }
        Ok(())
    }
}

/// Largest body (JSON-encoded length in bytes; equal to the UTF-8 length when
/// no escaping is needed) that fits in a frame of at most `max_frame_len`
/// given the other fields of `envelope_without_body` (its `body` is ignored).
/// Quotes, backslashes and control characters expand when JSON-encoded.
pub fn max_body_len(max_frame_len: usize, envelope_without_body: &Envelope) -> usize {
    let mut e = envelope_without_body.clone();
    e.body.clear();
    let base = serde_json::to_vec(&e)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    max_frame_len
        .saturating_sub(FRAME_OVERHEAD + PLAINTEXT_OVERHEAD)
        .saturating_sub(base)
}

/// Padded plaintext length for `min_pt` bytes of `len || sig || envelope`:
/// the smallest power of two >= 512 that fits, unless that makes the frame
/// exceed `max_frame_len`, in which case the largest plaintext that fits.
/// `None` if even unpadded the frame would exceed `max_frame_len`.
pub fn padded_plaintext_len(min_pt: usize, max_frame_len: usize) -> Option<usize> {
    let max_pt = max_frame_len.checked_sub(FRAME_OVERHEAD)?;
    if min_pt > max_pt {
        return None;
    }
    let mut b = MIN_BUCKET;
    while b < min_pt {
        match b.checked_mul(2) {
            Some(n) => b = n,
            None => return Some(max_pt),
        }
    }
    Some(b.min(max_pt))
}

/// Seal with the default suite (suite 1, `HpkeBaseEd25519`). The engine does
/// not call this; it goes through [`MessageProtection`].
pub fn seal(
    sender: &Identity,
    recipient: &VerifiedContact,
    envelope: &Envelope,
    now_ms: i64,
    max_frame_len: usize,
) -> Result<Vec<u8>, SealError> {
    HpkeBaseEd25519.seal(sender, recipient, envelope, now_ms, max_frame_len)
}

/// Limits applied when opening a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenLimits {
    /// `created_at` may be at most this far ahead of the local clock.
    pub clock_skew_ms: i64,
    /// Maximum `expires_at - created_at`.
    pub max_ttl_ms: i64,
    /// Frames longer than this are rejected before any cryptography.
    pub max_frame_len: usize,
}

impl Default for OpenLimits {
    fn default() -> Self {
        Self {
            clock_skew_ms: 120_000,
            max_ttl_ms: 7 * 24 * 60 * 60 * 1000,
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
        }
    }
}

/// A successfully opened and authenticated envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedEnvelope {
    pub envelope: Envelope,
    /// The authenticated sender (equal to `envelope.sender`, whose key verified the signature).
    pub sender: Address,
}

/// Open with the default suite (suite 1). The engine does not call this.
pub fn open(
    recipient: &Identity,
    frame: &[u8],
    now_ms: i64,
    limits: &OpenLimits,
) -> Result<OpenedEnvelope, OpenError> {
    HpkeBaseEd25519.open(recipient, frame, now_ms, limits)
}

/// Helpers for building deliberately malformed or re-targeted frames in tests.
/// Not part of the supported API.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod testing {
    use super::super::hpke_suite::{self, BuildError};
    use super::*;

    /// Sign arbitrary envelope bytes as `signer` (domain-separated like `seal`).
    pub fn sign_envelope_bytes(signer: &Identity, env_bytes: &[u8]) -> [u8; 64] {
        hpke_suite::sign_envelope_bytes(signer, env_bytes)
    }

    /// Frame an existing `(sig, env_bytes)` pair for `kem_pk` with the normal
    /// padding rule. Used for forwarding and forgery tests.
    pub fn seal_presigned(
        kem_pk: &[u8; 32],
        sig: &[u8; 64],
        env_bytes: &[u8],
        max_frame_len: usize,
    ) -> Result<Vec<u8>, SealError> {
        hpke_suite::build_frame(kem_pk, sig, env_bytes, max_frame_len).map_err(|e| match e {
            BuildError::TooLarge => SealError::TooLarge {
                body_len: env_bytes.len(),
                max_body_len_hint: 0,
            },
            BuildError::Crypto(m) => SealError::Crypto(m),
        })
    }

    /// HPKE-seal an arbitrary, caller-built plaintext (no length prefix or
    /// padding is added) so tests can construct authenticated garbage.
    pub fn seal_raw_plaintext(kem_pk: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        hpke_suite::seal_plaintext(kem_pk, plaintext).map_err(|e| match e {
            BuildError::TooLarge => SealError::Crypto("too large"),
            BuildError::Crypto(m) => SealError::Crypto(m),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn pair() -> (Identity, Identity, VerifiedContact) {
        let a = Identity::generate_default(NOW).unwrap();
        let b = Identity::generate_default(NOW).unwrap();
        let c = VerifiedContact::parse_and_verify(&b.contact_record().to_document(), NOW).unwrap();
        (a, b, c)
    }

    fn env(a: &Identity, b: &Identity, body: &str) -> Envelope {
        Envelope::new(
            a.address(),
            b.address(),
            "message",
            body.into(),
            NOW,
            60_000,
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_and_layout() {
        let (a, b, c) = pair();
        let e = env(&a, &b, "hello");
        let frame = seal(&a, &c, &e, NOW, DEFAULT_MAX_FRAME_LEN).unwrap();
        assert_eq!(&frame[..4], b"AN\x01\x01");
        assert_eq!(frame.len(), FRAME_OVERHEAD + 512);
        let o = open(&b, &frame, NOW, &OpenLimits::default()).unwrap();
        // `seal` fills in the signed suite and recipient key epoch
        let mut expected = e.clone();
        expected.suite = SUITE_ID;
        expected.recipient_key_epoch = 1;
        assert_eq!(o.envelope, expected);
        assert_eq!(o.sender, a.address());
    }

    #[test]
    fn padding_rule() {
        let max = 4096;
        assert_eq!(padded_plaintext_len(1, max), Some(512));
        assert_eq!(padded_plaintext_len(512, max + 52), Some(512));
        assert_eq!(padded_plaintext_len(513, max), Some(1024));
        assert_eq!(padded_plaintext_len(1025, max), Some(2048));
        assert_eq!(padded_plaintext_len(2049, max + 52), Some(4096));
        // bucket 4096 would exceed the cap: pad to the largest that fits
        assert_eq!(
            padded_plaintext_len(2049, 3000),
            Some(3000 - FRAME_OVERHEAD)
        );
        assert_eq!(
            padded_plaintext_len(3000 - FRAME_OVERHEAD, 3000),
            Some(3000 - FRAME_OVERHEAD)
        );
        assert_eq!(padded_plaintext_len(3000 - FRAME_OVERHEAD + 1, 3000), None);
        assert_eq!(padded_plaintext_len(10, 10), None);
        assert_eq!(padded_plaintext_len(usize::MAX, usize::MAX), None);
    }

    #[test]
    fn uuid_validation() {
        assert!(is_uuid_v4("123e4567-e89b-42d3-a456-426614174000"));
        assert!(!is_uuid_v4("123E4567-E89B-42D3-A456-426614174000"));
        assert!(!is_uuid_v4("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!is_uuid_v4("123e4567-e89b-42d3-c456-426614174000"));
        assert!(!is_uuid_v4("123e4567e89b42d3a456426614174000"));
        assert!(!is_uuid_v4("{123e4567-e89b-42d3-a456-426614174000}"));
        assert!(!is_uuid_v4(""));
        assert!(is_uuid_v4(&new_message_id().unwrap()));
    }

    #[test]
    fn field_rules() {
        let (a, b, _) = pair();
        let mut e = env(&a, &b, "x");
        assert!(e.validate().is_ok());
        for bad in ["", "Message", "a b", "a/b", &"a".repeat(65)] {
            e.message_type = bad.into();
            assert_eq!(e.validate(), Err("type"), "{bad:?}");
        }
        e.message_type = "task.result-v2_x".into();
        assert!(e.validate().is_ok());
        e.conversation_id = Some("with space".into());
        assert_eq!(e.validate(), Err("conversation_id"));
        e.conversation_id = Some("a".repeat(129));
        assert_eq!(e.validate(), Err("conversation_id"));
        e.conversation_id = Some("a".repeat(128));
        assert!(e.validate().is_ok());
        e.correlation_id = Some("caf\u{e9}".into());
        assert_eq!(e.validate(), Err("correlation_id"));
        e.correlation_id = Some(String::new());
        assert_eq!(e.validate(), Err("correlation_id"));
    }

    #[test]
    fn serde_rejects_duplicates_and_unknown_fields() {
        let (a, b, _) = pair();
        let e = env(&a, &b, "x");
        let s = serde_json::to_string(&e).unwrap();
        assert!(serde_json::from_str::<Envelope>(&s).is_ok());
        let dup = s.replacen("{\"v\":1,", "{\"v\":1,\"v\":1,", 1);
        let err = serde_json::from_str::<Envelope>(&dup).unwrap_err();
        assert!(err.to_string().starts_with("duplicate field"), "{err}");
        let unk = s.replacen("{\"v\":1,", "{\"v\":1,\"zzz\":0,", 1);
        assert!(serde_json::from_str::<Envelope>(&unk)
            .unwrap_err()
            .to_string()
            .starts_with("unknown field"));
    }
}
