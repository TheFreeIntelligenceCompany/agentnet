//! The message-protection interface and its one implementation, RFC 9580 OpenPGP.
//!
//! The engine (`ingest`, `send`, `node`) only ever calls [`MessageProtection`].
//! A message is **one OpenPGP message** (ADR 0004):
//!
//! ```text
//! PKESK v6 (anonymous, X25519)            one per live encryption subkey of the recipient
//! SEIPD v2 (AES-256, OCB) {
//!     One-Pass Signature (v6)
//!     Literal Data           = strict JSON payload (below)
//!     Signature (v6, Ed25519)  with Intended Recipient Fingerprint = recipient's primary key
//!     Padding                  inner packet sequence padded to a power of two
//! }
//! ```
//!
//! AgentNet defines no key derivation, signing prefix, binding scheme or frame
//! header on top of this. `open` enforces the receiver policy of ADR 0004
//! (see `pgp::open_message` and below) and then the application checks.
//!
//! Unknown senders: signature verification needs the sender's certificate. A
//! message from an address that is not a pinned contact carries the sender's
//! public certificate in the (encrypted, signed) payload field `sender_cert`;
//! the signature is verified against it and its fingerprint must equal the
//! claimed sender. The result is "made by the holder of this address", never
//! trust; the engine then applies the unknown-sender policy
//! (`quarantine`/`reject`/`accept`). A pinned contact's certificate always wins
//! over an embedded one.

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use sequoia_openpgp::Cert;
use serde::{Deserialize, Serialize};

use super::address::Address;
use super::contact::VerifiedContact;
use super::envelope::{
    Envelope, OpenLimits, OpenedEnvelope, SenderAuth, ENVELOPE_VERSION, MESSAGE_TYPE_ACK_RECEIVED,
    MESSAGE_TYPE_MESSAGE,
};
use super::identity::Identity;
use super::pgp::{self, BuildOpts};
use crate::error::{json_reason, OpenError, SealError};

/// Looks up the pinned certificate of a sender (the engine's contact store).
pub trait SenderDirectory {
    /// The stored certificate of `address`, if it is a contact.
    fn certificate(&self, address: &Address) -> Option<VerifiedContact>;
}

impl<F: Fn(&Address) -> Option<VerifiedContact>> SenderDirectory for F {
    fn certificate(&self, address: &Address) -> Option<VerifiedContact> {
        self(address)
    }
}

/// A directory with no contacts.
pub struct NoSenders;
impl SenderDirectory for NoSenders {
    fn certificate(&self, _: &Address) -> Option<VerifiedContact> {
        None
    }
}

/// Seals and opens message frames.
///
/// Contract for implementors:
/// * `seal` must authenticate the sender, bind the recipient and protect every
///   [`Envelope`] field; it must refuse recipients whose certificate is revoked
///   or expired and recipients without a live encryption subkey.
/// * `open` must be a pure function of its inputs (no replay detection; the
///   engine persists `(sender, message_id)`), must never return an envelope
///   whose signature or recipient binding was not verified, and must return
///   [`OpenError::NotForUs`] when no local key opens the frame.
/// * Implementations must not log or return plaintext, keys or attacker
///   controlled strings in errors.
pub trait MessageProtection: Send + Sync {
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
        senders: &dyn SenderDirectory,
    ) -> Result<OpenedEnvelope, OpenError>;
    /// Largest body (JSON-encoded bytes) that fits in `max_frame_len` given the
    /// other fields of `envelope_without_body` (an estimate used for error hints).
    fn max_body_len(&self, max_frame_len: usize, envelope_without_body: &Envelope) -> usize;
}

/// The strict JSON payload carried in the Literal Data packet.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Wire {
    /// Payload version (the `agentnet` field of ADR 0004).
    pub agentnet: u8,
    pub message_id: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub sender: Address,
    pub recipient: Address,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub body: String,
    /// The sender's public certificate (base64url), absent in receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_cert: Option<String>,
}

impl Wire {
    fn from_envelope(e: &Envelope, sender_cert: Option<String>) -> Self {
        Self {
            agentnet: e.v,
            message_id: e.message_id.clone(),
            message_type: e.message_type.clone(),
            sender: e.sender,
            recipient: e.recipient,
            created_at: e.created_at,
            expires_at: e.expires_at,
            conversation_id: e.conversation_id.clone(),
            correlation_id: e.correlation_id.clone(),
            body: e.body.clone(),
            sender_cert,
        }
    }

    fn into_envelope(self) -> Envelope {
        Envelope {
            v: self.agentnet,
            message_id: self.message_id,
            sender: self.sender,
            recipient: self.recipient,
            message_type: self.message_type,
            conversation_id: self.conversation_id,
            correlation_id: self.correlation_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            body: self.body,
        }
    }
}

/// Serialize the payload for `envelope` sealed by `sender` (test and engine use).
pub(crate) fn payload_bytes(sender: &Identity, e: &Envelope) -> Result<Vec<u8>, SealError> {
    let cert = (e.message_type != MESSAGE_TYPE_ACK_RECEIVED)
        .then(|| sender.contact_record().to_document());
    serde_json::to_vec(&Wire::from_envelope(e, cert))
        .map_err(|_| SealError::Crypto("payload serialization"))
}

/// Estimated bytes of a frame that are not payload: PKESK, SEIPD framing,
/// signature packets (v6 salt, issuer and recipient fingerprints), padding header.
const FRAME_OVERHEAD_ESTIMATE: usize = 600;
/// Estimated bytes of the embedded sender certificate in the payload (base64).
const SENDER_CERT_ESTIMATE: usize = 700;

/// RFC 9580 OpenPGP message protection (Sequoia, OpenSSL 3 backend).
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenPgpProtection;

impl OpenPgpProtection {
    /// Seal with explicit build options (tests build deliberately weakened
    /// messages through the crate's `testing` module).
    pub(crate) fn seal_with(
        &self,
        sender: &Identity,
        recipient: &VerifiedContact,
        envelope: &Envelope,
        now_ms: i64,
        max_frame_len: usize,
        opts: BuildOpts,
    ) -> Result<Vec<u8>, SealError> {
        if envelope.sender != sender.address() {
            return Err(SealError::SenderMismatch);
        }
        if envelope.recipient != recipient.address {
            return Err(SealError::RecipientMismatch);
        }
        envelope.validate().map_err(SealError::InvalidField)?;
        pgp::check_primary_usable(sender.cert(), now_ms).map_err(|e| match e {
            crate::error::ContactError::Revoked => {
                SealError::SenderNotUsable("the local certificate is revoked")
            }
            crate::error::ContactError::Expired => {
                SealError::SenderNotUsable("the local certificate has expired")
            }
            _ => SealError::SenderNotUsable("the local certificate is not valid"),
        })?;
        let payload = payload_bytes(sender, envelope)?;
        let signer = sender
            .signer()
            .ok_or(SealError::SenderNotUsable("no usable signing key"))?;
        // An ack carries no certificate, so it would be much smaller than any
        // ordinary message and recognisable by size (review finding M3): pad it as if
        // it carried the payload of the smallest ordinary message (body "x") of the
        // same sender, conversation and certificate.
        let pad_floor = if envelope.message_type == MESSAGE_TYPE_ACK_RECEIVED {
            let mut reference = envelope.clone();
            reference.message_type = MESSAGE_TYPE_MESSAGE.to_owned();
            reference.body = "x".to_owned();
            let reference_len = payload_bytes(sender, &reference)?.len();
            reference_len.saturating_sub(payload.len()) as u64
        } else {
            0
        };
        let frame =
            pgp::seal_message(signer, recipient.cert(), &payload, now_ms, &opts, pad_floor)?;
        if frame.len() <= max_frame_len {
            return Ok(frame);
        }
        if opts.pad {
            // the power-of-two size does not fit: fall back to the unpadded frame
            let signer = sender
                .signer()
                .ok_or(SealError::SenderNotUsable("no usable signing key"))?;
            let plain = BuildOpts { pad: false, ..opts };
            let frame = pgp::seal_message(
                signer,
                recipient.cert(),
                &payload,
                now_ms,
                &plain,
                pad_floor,
            )?;
            if frame.len() <= max_frame_len {
                return Ok(frame);
            }
        }
        Err(SealError::TooLarge {
            body_len: envelope.body.len(),
            max_body_len_hint: self.max_body_len(max_frame_len, envelope),
        })
    }
}

fn parse_wire(plain: &[u8]) -> Result<Wire, OpenError> {
    serde_json::from_slice::<Wire>(plain).map_err(|e| {
        let _ = json_reason(&e);
        OpenError::MalformedPayload
    })
}

impl MessageProtection for OpenPgpProtection {
    fn seal(
        &self,
        sender: &Identity,
        recipient: &VerifiedContact,
        envelope: &Envelope,
        now_ms: i64,
        max_frame_len: usize,
    ) -> Result<Vec<u8>, SealError> {
        self.seal_with(
            sender,
            recipient,
            envelope,
            now_ms,
            max_frame_len,
            BuildOpts::default(),
        )
    }

    fn open(
        &self,
        me: &Identity,
        frame: &[u8],
        now_ms: i64,
        limits: &OpenLimits,
        senders: &dyn SenderDirectory,
    ) -> Result<OpenedEnvelope, OpenError> {
        if frame.is_empty() {
            return Err(OpenError::Truncated);
        }
        if frame.len() > limits.max_frame_len {
            return Err(OpenError::FrameTooLarge);
        }
        let my_fp = me.primary_fingerprint();
        // Signature and key times are evaluated at `now + skew`: a sender's clock
        // may run ahead by the permitted skew.
        let vt = now_ms.saturating_add(limits.clock_skew_ms);
        let keys = me.decryption_keypairs(now_ms);
        if keys.is_empty() {
            return Err(OpenError::NotForUs);
        }
        let pinned =
            |a: &Address| -> Option<Cert> { senders.certificate(a).map(|c| c.cert().clone()) };
        let first = pgp::open_message(
            frame,
            keys,
            &my_fp,
            vt,
            limits.max_frame_len,
            &pinned,
            None,
            true,
        )?;
        let (opened, auth) = match first.signer {
            Some(_) => (first, SenderAuth::Pinned),
            None => {
                // The signer is not a contact. Authenticate it with the
                // certificate it carries, if its fingerprint is the claimed sender.
                let w = parse_wire(&first.plaintext)?;
                if !first.issuers.contains(&w.sender) {
                    return Err(OpenError::UnknownSender);
                }
                let doc = w.sender_cert.as_deref().ok_or(OpenError::UnknownSender)?;
                let embedded = VerifiedContact::parse_and_verify_allow_expired(doc, now_ms)
                    .map_err(|_| OpenError::UnknownSender)?;
                if embedded.address != w.sender {
                    return Err(OpenError::UnknownSender);
                }
                let keys = me.decryption_keypairs(now_ms);
                let none = |_: &Address| -> Option<Cert> { None };
                let second = pgp::open_message(
                    frame,
                    keys,
                    &my_fp,
                    vt,
                    limits.max_frame_len,
                    &none,
                    Some(embedded.cert()),
                    false,
                )?;
                (second, SenderAuth::EmbeddedCertificate)
            }
        };
        let signer = opened.signer.ok_or(OpenError::UnknownSender)?;
        let w = parse_wire(&opened.plaintext)?;
        if w.agentnet != ENVELOPE_VERSION {
            return Err(OpenError::UnknownEnvelopeVersion(u64::from(w.agentnet)));
        }
        if w.sender != signer {
            return Err(OpenError::SignerMismatch);
        }
        if w.recipient != me.address() {
            return Err(OpenError::WrongRecipient);
        }
        let env = w.into_envelope();
        env.validate().map_err(OpenError::InvalidField)?;
        if env.expires_at <= env.created_at {
            return Err(OpenError::ExpiresBeforeCreated);
        }
        if env.expires_at - env.created_at > limits.max_ttl_ms {
            return Err(OpenError::TtlTooLong);
        }
        if env.created_at > now_ms.saturating_add(limits.clock_skew_ms) {
            return Err(OpenError::FromFuture);
        }
        if env.expires_at <= now_ms {
            return Err(OpenError::Expired);
        }
        Ok(OpenedEnvelope {
            sender: signer,
            envelope: env,
            auth,
        })
    }

    fn max_body_len(&self, max_frame_len: usize, envelope_without_body: &Envelope) -> usize {
        let mut e = envelope_without_body.clone();
        e.body.clear();
        let base = serde_json::to_vec(&Wire::from_envelope(&e, None))
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        // AEAD adds 16 bytes per 4 KiB chunk.
        let chunks = max_frame_len / 4096 * 16;
        max_frame_len
            .saturating_sub(FRAME_OVERHEAD_ESTIMATE + SENDER_CERT_ESTIMATE + chunks)
            .saturating_sub(base)
    }
}

/// SHA-256 of a frame, used only to tell a byte-identical retry from a
/// byte-different copy of the same message (review finding M3). Not a
/// security mechanism of the message protection.
pub fn frame_digest(frame: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(frame).into()
}

/// Seal with the default protection (convenience for tests and tools).
pub fn seal(
    sender: &Identity,
    recipient: &VerifiedContact,
    envelope: &Envelope,
    now_ms: i64,
    max_frame_len: usize,
) -> Result<Vec<u8>, SealError> {
    OpenPgpProtection.seal(sender, recipient, envelope, now_ms, max_frame_len)
}

/// Open with the default protection and no pinned contacts (convenience).
pub fn open(
    recipient: &Identity,
    frame: &[u8],
    now_ms: i64,
    limits: &OpenLimits,
) -> Result<OpenedEnvelope, OpenError> {
    OpenPgpProtection.open(recipient, frame, now_ms, limits, &NoSenders)
}

/// The default protection used by `Node::open`.
pub fn default_protection() -> Arc<dyn MessageProtection> {
    Arc::new(OpenPgpProtection)
}

/// Encode a base64url document (used by tests).
#[doc(hidden)]
pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
