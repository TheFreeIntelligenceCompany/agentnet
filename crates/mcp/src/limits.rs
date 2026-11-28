//! Documented input limits enforced at the MCP boundary.
//!
//! These are enforced before any call reaches [`AgentApi`](agentnet_core::api::AgentApi);
//! the engine may enforce stricter limits and report them as `too_large` /
//! `invalid_argument`. All lengths are in UTF-8 bytes unless stated otherwise
//! (the JSON Schema `maxLength` keyword counts characters, which never exceeds
//! the byte count, so the schema bound is never tighter than the runtime bound).

/// Maximum `send_message.body` size in bytes. Equal to the engine's default
/// `delivery.max_body_bytes` (`agentnet_core::config::DeliveryConfig`, 65 536), so the
/// MCP layer is never stricter than a default daemon. The effective limit is the
/// smaller of this cap and the daemon's configured `delivery.max_body_bytes`
/// (the engine answers `too_large` above its own limit).
pub const MAX_BODY_BYTES: usize = 65_536;
/// Address length bounds (`an2` + base32 payload; exact validation is the engine's).
pub const MIN_ADDRESS_LEN: usize = 4;
pub const MAX_ADDRESS_LEN: usize = 128;
/// Maximum length of message, conversation, correlation, trigger and idempotency ids.
pub const MAX_ID_LEN: usize = 128;
/// Maximum opaque cursor length.
pub const MAX_CURSOR_LEN: usize = 512;
/// Page size bounds for `read_inbox` and the `limit` resource query parameter.
pub const MIN_LIMIT: u32 = 1;
pub const MAX_LIMIT: u32 = 200;
/// Default page size when `limit` is omitted.
pub const DEFAULT_LIMIT: u32 = 50;
/// Maximum requested TTL / trigger lifetime: 30 days.
pub const MAX_SECONDS: u64 = 2_592_000;
/// Maximum size of a pasted contact record.
pub const MAX_CONTACT_RECORD_BYTES: usize = 16_384;
/// Maximum contact alias length in characters.
pub const MAX_ALIAS_CHARS: usize = 64;
/// Maximum `target_session` length in bytes (the engine's rule: 1-128 ASCII
/// characters from `!` through `~`).
pub const MAX_SESSION_LEN: usize = 128;
/// Discovery topic name length bounds (`[a-z0-9-]{1,32}`).
pub const MAX_TOPIC_LEN: usize = 32;
/// Capability name length bound (`[a-z0-9._-]{1,64}`).
pub const MAX_CAPABILITY_NAME_LEN: usize = 64;
/// Capability description bound in characters.
pub const MAX_CAPABILITY_DESCRIPTION_CHARS: usize = 256;
/// Display name bound in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 64;
/// Most capabilities one `advertise_agent` call may carry (the host may allow fewer).
pub const MAX_CAPABILITIES: usize = 64;
/// Maximum size of an HTTP request body accepted by the Streamable HTTP endpoint.
pub const MAX_HTTP_BODY_BYTES: usize = 1_048_576;

/// JSON Schema `pattern` for ids (conversation, correlation, message, trigger,
/// idempotency key). Unreserved URI characters only, so an id can be embedded in
/// an `agentnet://conversations/{id}` URI without percent-encoding.
pub const ID_PATTERN: &str = "^[A-Za-z0-9._~-]{1,128}$";
/// JSON Schema `pattern` for `target_session` (ASCII `!` through `~`, no spaces).
pub const SESSION_PATTERN: &str = "^[!-~]{1,128}$";
/// JSON Schema `pattern` for discovery topic names.
pub const TOPIC_PATTERN: &str = "^[a-z0-9-]{1,32}$";
/// JSON Schema `pattern` for capability names.
pub const CAPABILITY_NAME_PATTERN: &str = "^[a-z0-9._-]{1,64}$";
/// JSON Schema `pattern` for message types (`[A-Za-z0-9._-]{1,64}`).
pub const MESSAGE_TYPE_PATTERN: &str = "^[A-Za-z0-9._-]{1,64}$";
/// JSON Schema `pattern` for agent addresses (loose; the engine validates the checksum).
pub const ADDRESS_PATTERN: &str = "^an2[a-z2-7]{1,125}$";

/// True if `s` is a valid `target_session`: 1 to [`MAX_SESSION_LEN`] ASCII
/// characters from `!` through `~` (no spaces), exactly the engine's rule.
pub fn is_valid_session(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SESSION_LEN && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// True if `s` is a syntactically valid id (see [`ID_PATTERN`]).
pub fn is_valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

/// True if `s` looks like an agent address (see [`ADDRESS_PATTERN`]).
pub fn is_valid_address(s: &str) -> bool {
    s.len() >= MIN_ADDRESS_LEN
        && s.len() <= MAX_ADDRESS_LEN
        && s.strip_prefix("an2")
            .is_some_and(|rest| rest.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
}

/// True if `s` is a plausible opaque cursor: 1..=512 visible ASCII bytes.
pub fn is_valid_cursor(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_CURSOR_LEN && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// True if `s` is a valid discovery topic name (see [`TOPIC_PATTERN`]).
pub fn is_valid_topic(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_TOPIC_LEN
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// True if `s` is a valid capability name (see [`CAPABILITY_NAME_PATTERN`]).
pub fn is_valid_capability_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_CAPABILITY_NAME_LEN
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}
