//! Error types for the cryptographic modules.
//!
//! Errors never embed plaintext, key material or attacker-controlled strings:
//! reasons are `'static` descriptions.

use std::path::PathBuf;

/// Failure to parse or validate an [`Address`](crate::address::Address).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("address must start with \"an2\" (\"an1\" addresses belong to the retired HPKE format; run `agentnet identity migrate`)")]
    BadPrefix,
    #[error("address has the wrong length")]
    BadLength,
    #[error("address must be lowercase RFC 4648 base32 without padding")]
    BadEncoding,
    #[error("address checksum mismatch")]
    BadChecksum,
}

/// Failure to parse, validate or merge an OpenPGP certificate used as a contact record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ContactError {
    #[error("contact certificate exceeds the size limit")]
    TooLarge,
    #[error("malformed contact certificate: {0}")]
    Malformed(&'static str),
    #[error("invalid address: {0}")]
    InvalidAddress(AddressError),
    /// Not a v6 certificate with an Ed25519 primary key.
    #[error("unsupported certificate: {0}")]
    Unsupported(&'static str),
    /// The document contains secret key material; it is refused, never stored.
    #[error("the document contains secret key material; export the public certificate")]
    ContainsSecretKey,
    #[error("the certificate has no valid self-signature under the policy")]
    NotValid,
    #[error("the certificate's primary key has expired")]
    Expired,
    #[error("the certificate's primary key is revoked")]
    Revoked,
    #[error("the certificate has no live, non-revoked, non-expired encryption subkey")]
    NoEncryptionKey,
    /// A merge was attempted with a certificate of a different primary key.
    #[error("the certificate is for a different primary key; updates are merges only")]
    PrimaryMismatch,
}

/// Failure to parse or verify an identity-revocation document (a certificate
/// carrying a primary-key revocation signature).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RevocationError {
    #[error("revocation document exceeds the size limit")]
    TooLarge,
    #[error("malformed revocation document: {0}")]
    Malformed(&'static str),
    #[error("invalid address in revocation: {0}")]
    InvalidAddress(AddressError),
    #[error("the certificate carries no valid primary-key revocation")]
    NotRevoked,
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
    #[error("advertisement is not a single OpenPGP signed (unencrypted) message")]
    BadStructure,
    #[error("the embedded contact certificate is invalid: {0}")]
    BadContact(ContactError),
    #[error("the embedded contact certificate is for a different address")]
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
    /// The recipient certificate's primary key is revoked (checked at certificate
    /// level: a subkey that still looks usable does not matter).
    #[error("the recipient's certificate is revoked; refusing to encrypt")]
    RecipientRevoked,
    #[error("the recipient's certificate has expired; refusing to encrypt")]
    RecipientExpired,
    /// No live, non-revoked, non-expired encryption subkey with a valid binding.
    #[error("the recipient has no usable encryption subkey (expired, revoked or unbound)")]
    RecipientKemExpired,
    #[error("the sealing identity cannot sign: {0}")]
    SenderNotUsable(&'static str),
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

/// Failure to open a frame. Carries no plaintext. Every OpenPGP policy
/// violation has its own variant (and its own `open_error.*` counter).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    #[error("frame is empty")]
    Truncated,
    #[error("frame exceeds the maximum frame length")]
    FrameTooLarge,
    /// Not parseable as an OpenPGP message (or damaged).
    #[error("frame is not a well-formed OpenPGP message")]
    Malformed,
    /// No local encryption subkey opens the frame. This is the normal outcome
    /// for frames addressed to other agents sharing the inbox bucket.
    #[error("frame is not for this identity")]
    NotForUs,
    #[error("message carries a symmetric-key encrypted session key (SKESK)")]
    SkeskPresent,
    #[error("message carries a PKESK that is not version 6")]
    PkeskNotV6,
    #[error("message is not SEIPD v2 with an AEAD mode")]
    NotAead,
    #[error("message uses an unsupported cipher")]
    UnsupportedCipher,
    #[error("message uses compression")]
    Compressed,
    #[error("message is not encrypted-and-signed in the required structure")]
    BadStructure,
    #[error("message does not carry exactly one signature")]
    WrongSignatureCount,
    #[error("signature is not a v6 Ed25519 binary document signature")]
    UnsupportedSignature,
    #[error("signature does not verify")]
    BadSignature,
    /// The signer is not a pinned contact and the message carries no usable certificate.
    #[error("sender is unknown and cannot be authenticated")]
    UnknownSender,
    #[error("the sender's certificate is revoked")]
    SenderRevoked,
    #[error("the sender's certificate has expired")]
    SenderExpired,
    #[error("the signer is not the sender named in the payload")]
    SignerMismatch,
    /// The signature has no Intended Recipient Fingerprint (surreptitious-forwarding defence).
    #[error("the signature does not carry an Intended Recipient Fingerprint")]
    MissingIntendedRecipient,
    #[error("the signature's Intended Recipient Fingerprint does not name this identity")]
    WrongIntendedRecipient,
    #[error("the payload is not a valid AgentNet payload")]
    MalformedPayload,
    #[error("unknown payload version {0}")]
    UnknownEnvelopeVersion(u64),
    #[error("invalid envelope field: {0}")]
    InvalidField(&'static str),
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
    /// A version 1 file written by the retired HPKE + Ed25519 scheme (ADR 0002).
    #[error("this identity file is in the retired HPKE format (version 1); run `agentnet identity migrate` to create a new OpenPGP identity")]
    LegacyFormat,
    #[error("stored address does not match the stored certificate")]
    AddressMismatch,
    #[error("system random number generator failed")]
    Random,
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    #[error("could not decrypt identity export (wrong passphrase or corrupted data)")]
    Decrypt,
    #[error("could not encrypt identity export")]
    Encrypt,
    #[error("OpenPGP operation failed: {0}")]
    Crypto(&'static str),
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
