//! Suite 1: `HpkeBaseEd25519`.
//!
//! RFC 9180 HPKE, mode Base, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
//! ChaCha20-Poly1305 (single-shot API), with an Ed25519 signature
//! (`verify_strict`) by the sender over the domain-separated envelope bytes
//! (sign-then-encrypt with recipient binding). Normative description:
//! `docs/protocol.md`.
//!
//! Every [`HpkeBaseEd25519::seal`] call performs one single-shot HPKE
//! encapsulation, i.e. it creates a fresh ephemeral X25519 key and a fresh HPKE
//! context. Nothing is cached or reused between messages.

use ed25519_dalek::Signature;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::contact::VerifiedContact;
use super::envelope::{
    max_body_len, padded_plaintext_len, Envelope, OpenLimits, OpenedEnvelope, ENC_LEN,
    ENVELOPE_DOMAIN, ENVELOPE_VERSION, FRAME_HEADER, FRAME_MAGIC, FRAME_VERSION, HEADER_LEN,
    HPKE_INFO_DOMAIN, LEN_PREFIX_LEN, PLAINTEXT_OVERHEAD, SIG_LEN, SUITE_ID, TAG_LEN,
};
use super::identity::Identity;
use super::protection::MessageProtection;
use crate::error::{json_reason, OpenError, SealError};

type Kem = X25519HkdfSha256;
type KemPublicKey = <Kem as hpke::Kem>::PublicKey;
type KemEncapped = <Kem as hpke::Kem>::EncappedKey;

/// The only suite implemented today (suite id 1).
#[derive(Clone, Copy, Debug, Default)]
pub struct HpkeBaseEd25519;

pub(crate) enum BuildError {
    TooLarge,
    Crypto(&'static str),
}

fn hpke_info(kem_pk: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HPKE_INFO_DOMAIN.len() + 32);
    v.extend_from_slice(HPKE_INFO_DOMAIN);
    v.extend_from_slice(kem_pk);
    v
}

/// HPKE single-shot seal of an already padded plaintext; returns the frame.
/// A fresh ephemeral key (and so a fresh HPKE context) is generated per call.
pub(crate) fn seal_plaintext(kem_pk: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, BuildError> {
    let pk = KemPublicKey::from_bytes(kem_pk).map_err(|_| BuildError::Crypto("invalid KEM key"))?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        &hpke_info(kem_pk),
        plaintext,
        &FRAME_HEADER,
    )
    .map_err(|_| BuildError::Crypto("HPKE seal failed"))?;
    let enc_b = enc.to_bytes();
    let mut frame = Vec::with_capacity(HEADER_LEN + enc_b.len() + ct.len());
    frame.extend_from_slice(&FRAME_HEADER);
    frame.extend_from_slice(enc_b.as_slice());
    frame.extend_from_slice(&ct);
    Ok(frame)
}

pub(crate) fn build_frame(
    kem_pk: &[u8; 32],
    sig: &[u8; 64],
    env_bytes: &[u8],
    max_frame_len: usize,
) -> Result<Vec<u8>, BuildError> {
    let inner_len = SIG_LEN
        .checked_add(env_bytes.len())
        .ok_or(BuildError::TooLarge)?;
    let inner_u32 = u32::try_from(inner_len).map_err(|_| BuildError::TooLarge)?;
    let min_pt = LEN_PREFIX_LEN + inner_len;
    let target = padded_plaintext_len(min_pt, max_frame_len).ok_or(BuildError::TooLarge)?;
    let mut pt = Zeroizing::new(Vec::with_capacity(target));
    pt.extend_from_slice(&inner_u32.to_be_bytes());
    pt.extend_from_slice(sig);
    pt.extend_from_slice(env_bytes);
    pt.resize(target, 0);
    seal_plaintext(kem_pk, &pt)
}

/// Sign arbitrary envelope bytes as `signer` (domain-separated like `seal`).
pub(crate) fn sign_envelope_bytes(signer: &Identity, env_bytes: &[u8]) -> [u8; 64] {
    signer.sign(ENVELOPE_DOMAIN, env_bytes)
}

#[derive(Deserialize)]
struct VersionOnly {
    v: u64,
}

impl MessageProtection for HpkeBaseEd25519 {
    fn suite_id(&self) -> u8 {
        SUITE_ID
    }

    fn supported_suites(&self) -> Vec<u8> {
        vec![SUITE_ID]
    }

    /// Seal `envelope` from `sender` to `recipient`.
    ///
    /// `now_ms` is used only to refuse sealing to a KEM key that is already
    /// expired ([`SealError::RecipientKemExpired`]); the envelope's own
    /// `created_at`/`expires_at` are not compared with it (the receiver does that).
    /// The envelope must name `sender` and `recipient` and pass
    /// [`Envelope::validate`]. The signed `suite` and `recipient_key_epoch`
    /// fields are set here (the caller's values are overwritten).
    fn seal(
        &self,
        sender: &Identity,
        recipient: &VerifiedContact,
        envelope: &Envelope,
        now_ms: i64,
        max_frame_len: usize,
    ) -> Result<Vec<u8>, SealError> {
        if envelope.sender != sender.address() {
            return Err(SealError::SenderMismatch);
        }
        if envelope.recipient != recipient.address {
            return Err(SealError::RecipientMismatch);
        }
        if !recipient.suites.contains(&SUITE_ID) {
            return Err(SealError::NoCommonSuite);
        }
        if recipient.is_kem_expired(now_ms) {
            return Err(SealError::RecipientKemExpired);
        }
        let mut envelope = envelope.clone();
        envelope.suite = SUITE_ID;
        envelope.recipient_key_epoch = recipient.key_epoch;
        envelope.validate().map_err(SealError::InvalidField)?;
        if envelope.expires_at <= envelope.created_at {
            return Err(SealError::InvalidField("expires_at"));
        }
        let env_bytes =
            serde_json::to_vec(&envelope).map_err(|_| SealError::InvalidField("body"))?;
        let sig = sign_envelope_bytes(sender, &env_bytes);
        build_frame(&recipient.kem_pk, &sig, &env_bytes, max_frame_len).map_err(|e| match e {
            BuildError::TooLarge => SealError::TooLarge {
                body_len: envelope.body.len(),
                max_body_len_hint: max_body_len(max_frame_len, &envelope),
            },
            BuildError::Crypto(m) => SealError::Crypto(m),
        })
    }

    /// Open and fully validate a frame addressed to `recipient`.
    ///
    /// `NotForUs` is the expected outcome for other agents' frames in a shared
    /// inbox bucket and costs one HPKE decapsulation per usable KEM key. No
    /// logging happens here. No duplicate detection happens here either.
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
        let (header, rest) = frame
            .split_at_checked(HEADER_LEN)
            .ok_or(OpenError::Truncated)?;
        if header.get(0..2) != Some(&FRAME_MAGIC[..]) {
            return Err(OpenError::BadMagic);
        }
        match header.get(2) {
            Some(&FRAME_VERSION) => {}
            Some(&v) => return Err(OpenError::UnknownFrameVersion(v)),
            None => return Err(OpenError::Truncated),
        }
        match header.get(3) {
            Some(&SUITE_ID) => {}
            Some(&s) => return Err(OpenError::UnknownSuite(s)),
            None => return Err(OpenError::Truncated),
        }
        let (enc_b, ct) = rest.split_at_checked(ENC_LEN).ok_or(OpenError::Truncated)?;
        if ct.len() < TAG_LEN + PLAINTEXT_OVERHEAD + 1 {
            return Err(OpenError::Truncated);
        }
        let enc = KemEncapped::from_bytes(enc_b).map_err(|_| OpenError::NotForUs)?;

        let mut plaintext: Option<Zeroizing<Vec<u8>>> = None;
        let mut key_epoch = 0u64;
        for key in recipient.decryption_keys(now_ms) {
            let Some(sk) = key.private_key() else {
                continue;
            };
            if let Ok(pt) = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
                &OpModeR::Base,
                &sk,
                &enc,
                &hpke_info(key.public_key()),
                ct,
                header,
            ) {
                plaintext = Some(Zeroizing::new(pt));
                key_epoch = key.epoch();
                break;
            }
        }
        let plaintext = plaintext.ok_or(OpenError::NotForUs)?;

        // Plaintext structure: u32_be(inner_len) || inner || zero padding.
        let (len_b, after_len) = plaintext
            .split_at_checked(LEN_PREFIX_LEN)
            .ok_or(OpenError::BadLengthPrefix)?;
        let len_arr: [u8; 4] = len_b.try_into().map_err(|_| OpenError::BadLengthPrefix)?;
        let inner_len =
            usize::try_from(u32::from_be_bytes(len_arr)).map_err(|_| OpenError::BadLengthPrefix)?;
        if inner_len <= SIG_LEN {
            return Err(OpenError::BadLengthPrefix);
        }
        let (inner, padding) = after_len
            .split_at_checked(inner_len)
            .ok_or(OpenError::BadLengthPrefix)?;
        if padding.iter().any(|b| *b != 0) {
            return Err(OpenError::NonZeroPadding);
        }
        let (sig_b, env_bytes) = inner
            .split_at_checked(SIG_LEN)
            .ok_or(OpenError::BadLengthPrefix)?;
        let sig_arr: [u8; SIG_LEN] = sig_b.try_into().map_err(|_| OpenError::BadLengthPrefix)?;

        // Envelope parsing: version first so that future versions give a clean error.
        let ver: VersionOnly = serde_json::from_slice(env_bytes)
            .map_err(|e| OpenError::MalformedEnvelope(json_reason(&e)))?;
        if ver.v != u64::from(ENVELOPE_VERSION) {
            return Err(OpenError::UnknownEnvelopeVersion(ver.v));
        }
        let envelope: Envelope = serde_json::from_slice(env_bytes)
            .map_err(|e| OpenError::MalformedEnvelope(json_reason(&e)))?;

        // Signature over the exact received bytes.
        let mut msg = Vec::with_capacity(ENVELOPE_DOMAIN.len() + env_bytes.len());
        msg.extend_from_slice(ENVELOPE_DOMAIN);
        msg.extend_from_slice(env_bytes);
        envelope
            .sender
            .verifying_key()
            .verify_strict(&msg, &Signature::from_bytes(&sig_arr))
            .map_err(|_| OpenError::BadSignature)?;

        if envelope.recipient != recipient.address() {
            return Err(OpenError::WrongRecipient);
        }
        // The signed suite and key epoch must equal what actually opened the
        // frame: an attacker holding an old recipient key cannot re-wrap a
        // message under a different suite or epoch unnoticed.
        if envelope.suite != header[3] {
            return Err(OpenError::SuiteMismatch);
        }
        if envelope.recipient_key_epoch != key_epoch {
            return Err(OpenError::KeyEpochMismatch);
        }
        envelope.validate().map_err(OpenError::InvalidField)?;

        if envelope.created_at > now_ms.saturating_add(limits.clock_skew_ms) {
            return Err(OpenError::FromFuture);
        }
        if envelope.expires_at <= now_ms {
            return Err(OpenError::Expired);
        }
        if envelope.expires_at <= envelope.created_at {
            return Err(OpenError::ExpiresBeforeCreated);
        }
        if envelope.expires_at.saturating_sub(envelope.created_at) > limits.max_ttl_ms {
            return Err(OpenError::TtlTooLong);
        }

        Ok(OpenedEnvelope {
            sender: envelope.sender,
            envelope,
        })
    }

    fn max_body_len(&self, max_frame_len: usize, envelope_without_body: &Envelope) -> usize {
        max_body_len(max_frame_len, envelope_without_body)
    }
}
