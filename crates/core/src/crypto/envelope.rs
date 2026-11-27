//! The application payload of a message and the limits applied when opening one.
//!
//! The payload is strict JSON carried in the Literal Data packet of the OpenPGP
//! message, which is signed and encrypted as a whole (see
//! [`super::protection`]). The fields are the application's own; they are
//! cross-checked against the OpenPGP facts (signer, Intended Recipient
//! Fingerprint) by `open`. There is no frame header of AgentNet's own: the
//! frame is the OpenPGP message.
//!
//! This module performs **no replay detection**: callers (the engine) must
//! persist `(sender, message_id)` of every accepted envelope and drop repeats.

use serde::{Deserialize, Serialize};

use super::address::Address;
use super::identity::random_bytes;
use crate::error::SealError;

/// Default maximum frame size (a 150 KiB limit is typical of Waku nodes; the
/// engine should pass the transport's actual limit).
pub const DEFAULT_MAX_FRAME_LEN: usize = 150 * 1024;
/// Payload (envelope) format version: the `agentnet` field of the JSON payload.
pub const ENVELOPE_VERSION: u8 = 2;

pub const MESSAGE_TYPE_MESSAGE: &str = "message";
pub const MESSAGE_TYPE_ACK_RECEIVED: &str = "ack.received";
pub const MESSAGE_TYPE_TASK_REQUEST: &str = "task.request";
pub const MESSAGE_TYPE_TASK_RESULT: &str = "task.result";
/// Reserved: body is the sender's current public certificate (a merge input).
pub const MESSAGE_TYPE_CONTACT_UPDATE: &str = "contact.update";
/// Reserved: body is the sender's revoked public certificate (primary-key revocation).
pub const MESSAGE_TYPE_IDENTITY_REVOKED: &str = "identity.revoked";

pub const MAX_MESSAGE_TYPE_LEN: usize = 64;
pub const MAX_ID_LEN: usize = 128;

/// The logical message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u8,
    pub message_id: String,
    pub sender: Address,
    pub recipient: Address,
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
    /// A new envelope with a random message id, `created_at = now_ms`
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

/// How the sender of an opened message was authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderAuth {
    /// The signature verified against the pinned certificate of a contact.
    Pinned,
    /// The sender is not a contact: the signature verified against the
    /// certificate carried in the payload, whose fingerprint is the claimed
    /// sender. This proves the message was made by the holder of that
    /// address, nothing more (the trust level stays `unknown`).
    EmbeddedCertificate,
}

/// A successfully opened and authenticated envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedEnvelope {
    pub envelope: Envelope,
    /// The authenticated sender (equal to `envelope.sender`, whose primary key made the signature).
    pub sender: Address,
    /// How the signer was identified.
    pub auth: SenderAuth,
}
