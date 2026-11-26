//! Opaque cursors: `base64url("<kind>:<position>")`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;

use crate::api::ApiError;

/// Kinds of cursor. A cursor of the wrong kind is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorKind {
    /// Inbox sequence.
    Inbox,
    /// Outbox sequence.
    Outbox,
    /// Event sequence.
    Event,
    /// Conversation position `(timestamp, direction, seq)`.
    Conversation,
    /// Discovery result position (advert row id).
    Advert,
}

impl CursorKind {
    fn tag(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Outbox => "outbox",
            Self::Event => "event",
            Self::Conversation => "conv",
            Self::Advert => "advert",
        }
    }
}

const MAX_CURSOR_LEN: usize = 256;

/// Encode a position of the given kind.
pub fn encode(kind: CursorKind, pos: &str) -> String {
    B64.encode(format!("{}:{pos}", kind.tag()))
}

/// Encode a plain sequence number.
pub fn encode_seq(kind: CursorKind, seq: i64) -> String {
    encode(kind, &seq.to_string())
}

fn decode_pos(kind: CursorKind, s: &str) -> Result<String, ApiError> {
    let bad = || ApiError::invalid("invalid cursor");
    if s.len() > MAX_CURSOR_LEN {
        return Err(bad());
    }
    let raw = B64.decode(s).map_err(|_| bad())?;
    let raw = String::from_utf8(raw).map_err(|_| bad())?;
    let (tag, pos) = raw.split_once(':').ok_or_else(bad)?;
    if tag != kind.tag() {
        return Err(ApiError::invalid("cursor is of the wrong kind"));
    }
    Ok(pos.to_owned())
}

/// Decode a sequence cursor of `kind`.
pub fn decode_seq(kind: CursorKind, s: &str) -> Result<i64, ApiError> {
    let pos = decode_pos(kind, s)?;
    let n: i64 = pos
        .parse()
        .map_err(|_| ApiError::invalid("invalid cursor"))?;
    if n < 0 || pos != n.to_string() {
        return Err(ApiError::invalid("invalid cursor"));
    }
    Ok(n)
}

/// A conversation position: ordered by `(ts, dir, seq)`.
pub type ConvPos = (i64, i64, i64);

/// Encode a conversation position.
pub fn encode_conv(p: ConvPos) -> String {
    encode(
        CursorKind::Conversation,
        &format!("{}.{}.{}", p.0, p.1, p.2),
    )
}

/// Decode a conversation cursor.
pub fn decode_conv(s: &str) -> Result<ConvPos, ApiError> {
    let pos = decode_pos(CursorKind::Conversation, s)?;
    let bad = || ApiError::invalid("invalid cursor");
    let mut it = pos.split('.');
    let mut next = || -> Result<i64, ApiError> {
        let n: i64 = it.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
        if n < 0 {
            return Err(bad());
        }
        Ok(n)
    };
    let p = (next()?, next()?, next()?);
    if it.next().is_some() {
        return Err(bad());
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_kind_checks() {
        let c = encode_seq(CursorKind::Inbox, 42);
        assert_eq!(decode_seq(CursorKind::Inbox, &c).unwrap(), 42);
        assert!(decode_seq(CursorKind::Outbox, &c).is_err());
        assert!(decode_seq(CursorKind::Inbox, "").is_err());
        assert!(decode_seq(CursorKind::Inbox, "@@").is_err());
        assert!(decode_seq(CursorKind::Inbox, &encode(CursorKind::Inbox, "-1")).is_err());
        assert!(decode_seq(CursorKind::Inbox, &encode(CursorKind::Inbox, "01")).is_err());
        assert!(decode_seq(CursorKind::Inbox, &"A".repeat(1000)).is_err());
        let p = (5, 1, 9);
        assert_eq!(decode_conv(&encode_conv(p)).unwrap(), p);
        assert!(decode_conv(&encode(CursorKind::Conversation, "1.2")).is_err());
        assert!(decode_conv(&encode(CursorKind::Conversation, "1.2.3.4")).is_err());
        assert!(decode_conv(&c).is_err());
    }
}
