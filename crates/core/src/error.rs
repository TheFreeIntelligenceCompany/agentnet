//! Error types for the pure cryptographic modules.
//!
//! Errors never embed plaintext, key material or attacker-controlled strings:
//! reasons are `'static` descriptions.

use std::path::PathBuf;

/// Failure to parse or validate an [`Address`](crate::address::Address).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("address must start with \"an1\"")]
    BadPrefix,
    #[error("address has the wrong length")]
    BadLength,
    #[error("address must be lowercase RFC 4648 base32 without padding")]
    BadEncoding,
    #[error("address checksum mismatch")]
    BadChecksum,
    #[error("address does not contain a valid Ed25519 public key")]
    InvalidKey,
}

/// Failure to parse or verify a signed contact record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContactError {
    #[error("contact document exceeds the size limit")]
    TooLarge,
    #[error("malformed contact document: {0}")]
    MalformedDocument(&'static str),
    #[error("unknown contact record version {0}")]
    UnknownVersion(u64),
    #[error("malformed contact record: {0}")]
    MalformedRecord(&'static str),
    #[error("invalid address in contact record: {0}")]
    InvalidAddress(AddressError),
    #[error("record address does not match record signing key")]
    AddressMismatch,
    #[error("contact record signature does not verify")]
    BadSignature,
    #[error("contact record KEM key is invalid or low-order")]
    InvalidKemKey,
    #[error("inbox_buckets must be in 1..=256")]
    InvalidInboxBuckets,
    #[error("contact record timestamp is invalid")]
    InvalidTimestamp,
    #[error("contact record created_at is too far in the future")]
    CreatedInFuture,
    #[error("contact record KEM key has expired")]
    KemKeyExpired,
    #[error("key_epoch must be at least 1 and revoked_kem_epochs_below must be in 1..=key_epoch")]
    InvalidKeyEpoch,
    #[error("suites must be a non-empty, strictly ascending list of non-zero suite ids")]
    InvalidSuites,
}

/// Failure to parse or verify a signed identity-revocation document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RevocationError {
    #[error("revocation document exceeds the size limit")]
    TooLarge,
    #[error("malformed revocation document: {0}")]
    Malformed(&'static str),
    #[error("unknown revocation version {0}")]
    UnknownVersion(u64),
    #[error("invalid address in revocation: {0}")]
    InvalidAddress(AddressError),
    #[error("revocation signature does not verify under the address it names")]
    BadSignature,
    #[error("revocation timestamp is invalid")]
    InvalidTimestamp,
    #[error("revocation reason is empty, too long or contains control characters")]
    InvalidReason,
}

/// Failure to create, parse or verify a signed capability advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdvertError {
    #[error("advertisement frame is malformed or too large")]
    BadFrame,
    #[error("advertisement document exceeds the size limit")]
    TooLarge,
    #[error("malformed advertisement: {0}")]
    Malformed(&'static str),
    #[error("unknown advertisement version {0}")]
    UnknownVersion(u64),
    #[error("invalid address in advertisement: {0}")]
    InvalidAddress(AddressError),
    #[error("advertisement signature does not verify under the address it names")]
    BadSignature,
    #[error("the embedded contact record is invalid: {0}")]
    BadContact(ContactError),
    #[error("the embedded contact record is for a different address")]
    ContactAddressMismatch,
    #[error("the advertisement was signed for a different discovery topic than it arrived on")]
    TopicMismatch,
    #[error("advertisement timestamps are invalid")]
    InvalidTimestamp,
    #[error("advertisement has expired")]
    Expired,
    #[error("advertisement was issued in the future")]
    FromFuture,
    #[error("advertisement lifetime exceeds the maximum")]
    TtlTooLong,
    #[error("invalid capability: {0}")]
    InvalidCapability(&'static str),
    #[error("invalid display name")]
    InvalidDisplayName,
    #[error("invalid sequence number")]
    InvalidSeq,
}

/// Failure to seal an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("invalid envelope field: {0}")]
    InvalidField(&'static str),
    #[error("envelope sender is not the sealing identity")]
    SenderMismatch,
    #[error("envelope recipient is not the contact's address")]
    RecipientMismatch,
    #[error("recipient KEM key has expired")]
    RecipientKemExpired,
    /// The recipient's signed record lists no suite this node supports.
    #[error("no cipher suite in common with the recipient's signed contact record")]
    NoCommonSuite,
    /// The sealed frame would exceed the maximum frame length.
    /// `max_body_len_hint` is the largest body (in UTF-8 bytes, assuming no JSON
    /// escaping is needed) that would fit with otherwise identical fields.
    #[error("message too large: body is {body_len} bytes, at most about {max_body_len_hint} fit")]
    TooLarge {
        body_len: usize,
        max_body_len_hint: usize,
    },
    #[error("encryption failed: {0}")]
    Crypto(&'static str),
}

/// Failure to open a frame. Carries no plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("frame is truncated")]
    Truncated,
    #[error("frame exceeds the maximum frame length")]
    FrameTooLarge,
    #[error("bad frame magic")]
    BadMagic,
    #[error("unknown frame version {0}")]
    UnknownFrameVersion(u8),
    #[error("unknown cipher suite {0}")]
    UnknownSuite(u8),
    /// A known suite that this agent does not list in its own contact record.
    #[error("cipher suite {0} is not advertised by this agent")]
    SuiteNotAdvertised(u8),
    /// The signed `suite` field differs from the frame header's suite.
    #[error("signed suite does not match the frame suite")]
    SuiteMismatch,
    /// The signed `recipient_key_epoch` differs from the epoch of the key that decrypted.
    #[error("signed recipient key epoch does not match the decrypting key")]
    KeyEpochMismatch,
    /// No local KEM key opened the frame. This is the normal outcome for frames
    /// addressed to other agents sharing the inbox bucket.
    #[error("frame is not for this identity")]
    NotForUs,
    #[error("invalid plaintext length prefix")]
    BadLengthPrefix,
    #[error("padding is not all zero")]
    NonZeroPadding,
    #[error("unknown envelope version {0}")]
    UnknownEnvelopeVersion(u64),
    #[error("malformed envelope: {0}")]
    MalformedEnvelope(&'static str),
    #[error("invalid envelope field: {0}")]
    InvalidField(&'static str),
    #[error("envelope signature does not verify")]
    BadSignature,
    #[error("envelope is addressed to a different recipient")]
    WrongRecipient,
    #[error("envelope created_at is in the future")]
    FromFuture,
    #[error("envelope has expired")]
    Expired,
    #[error("envelope expires_at is not after created_at")]
    ExpiresBeforeCreated,
    #[error("envelope TTL exceeds the maximum")]
    TtlTooLong,
}

/// Failure in identity generation, persistence or export/import.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("i/o error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0} already exists; refusing to overwrite")]
    AlreadyExists(PathBuf),
    #[error(
        "identity file {path} has permissions {mode:04o}; it must not be accessible by group or \
         others. Run: chmod 600 {path}"
    )]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("identity file {0} is not a regular file")]
    NotRegularFile(PathBuf),
    #[error("identity data is too large")]
    TooLarge,
    #[error("malformed identity data: {0}")]
    Malformed(&'static str),
    #[error("unsupported identity format version {0}")]
    UnsupportedVersion(u64),
    #[error("inbox_buckets must be in 1..=256")]
    InvalidInboxBuckets,
    #[error("stored address does not match the stored signing key")]
    AddressMismatch,
    #[error("system random number generator failed")]
    Random,
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    #[error("could not decrypt identity export (wrong passphrase or corrupted data)")]
    Decrypt,
    #[error("could not encrypt identity export")]
    Encrypt,
}

/// Map a serde_json error to a static, plaintext-free reason.
pub(crate) fn json_reason(e: &serde_json::Error) -> &'static str {
    use serde_json::error::Category;
    let m = e.to_string();
    if m.starts_with("unknown field") {
        "unknown field"
    } else if m.starts_with("duplicate field") {
        "duplicate field"
    } else if m.starts_with("missing field") {
        "missing field"
    } else {
        match e.classify() {
            Category::Syntax => "invalid JSON syntax",
            Category::Eof => "unexpected end of JSON",
            Category::Data => "invalid field value or type",
            Category::Io => "i/o error",
        }
    }
}
