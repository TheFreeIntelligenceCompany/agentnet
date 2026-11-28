//! `agentnet://` resource URIs: parsing, canonical forms and subscription rules.
//!
//! ```text
//! agentnet://identity
//! agentnet://inbox{?cursor,limit}
//! agentnet://outbox{?cursor,limit}
//! agentnet://triggers
//! agentnet://conversations/{id}{?cursor,limit}
//! ```
//!
//! Query values are percent-decoded (`+` is a literal plus, not a space, because
//! cursors may be base64). Unknown or duplicate query parameters are rejected.

use agentnet_core::api::ChangeHint;

use crate::limits::{is_valid_cursor, is_valid_id, MAX_LIMIT, MIN_LIMIT};

pub const IDENTITY_URI: &str = "agentnet://identity";
pub const INBOX_URI: &str = "agentnet://inbox";
pub const OUTBOX_URI: &str = "agentnet://outbox";
pub const TRIGGERS_URI: &str = "agentnet://triggers";
pub const CONVERSATIONS_PREFIX: &str = "agentnet://conversations/";

pub const INBOX_TEMPLATE: &str = "agentnet://inbox{?cursor,limit}";
pub const OUTBOX_TEMPLATE: &str = "agentnet://outbox{?cursor,limit}";
pub const CONVERSATION_TEMPLATE: &str = "agentnet://conversations/{id}{?cursor,limit}";

/// Page parameters carried in a resource URI query.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageParams {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

/// A parsed resource URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceRef {
    Identity,
    Inbox(PageParams),
    Outbox(PageParams),
    Triggers,
    Conversation { id: String, page: PageParams },
}

/// Why a URI did not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    /// Not one of our resources.
    NotFound,
    /// One of our resources, but the query is invalid.
    Invalid(String),
}

pub fn conversation_uri(id: &str) -> String {
    format!("{CONVERSATIONS_PREFIX}{id}")
}

/// Parse a resource URI (with optional query).
pub fn parse(uri: &str) -> Result<ResourceRef, UriError> {
    if uri.contains('#') || !uri.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(UriError::NotFound);
    }
    let (base, query) = match uri.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (uri, None),
    };
    let paged = |build: fn(PageParams) -> ResourceRef| -> Result<ResourceRef, UriError> {
        Ok(build(parse_query(query)?))
    };
    let no_query = |r: ResourceRef| -> Result<ResourceRef, UriError> {
        match query {
            None => Ok(r),
            Some(_) => Err(UriError::Invalid(
                "this resource does not take query parameters".into(),
            )),
        }
    };
    match base {
        IDENTITY_URI => no_query(ResourceRef::Identity),
        TRIGGERS_URI => no_query(ResourceRef::Triggers),
        INBOX_URI => paged(ResourceRef::Inbox),
        OUTBOX_URI => paged(ResourceRef::Outbox),
        other => {
            let id = other
                .strip_prefix(CONVERSATIONS_PREFIX)
                .ok_or(UriError::NotFound)?;
            if !is_valid_id(id) {
                return Err(UriError::NotFound);
            }
            Ok(ResourceRef::Conversation {
                id: id.to_string(),
                page: parse_query(query)?,
            })
        }
    }
}

fn parse_query(query: Option<&str>) -> Result<PageParams, UriError> {
    let mut page = PageParams::default();
    let Some(query) = query else {
        return Ok(page);
    };
    if query.is_empty() {
        return Err(UriError::Invalid("empty query string".into()));
    }
    for pair in query.split('&') {
        if pair.is_empty() {
            return Err(UriError::Invalid("empty query parameter".into()));
        }
        let (key, raw) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(raw)
            .ok_or_else(|| UriError::Invalid(format!("invalid percent-encoding in `{key}`")))?;
        match key {
            "cursor" => {
                if page.cursor.is_some() {
                    return Err(UriError::Invalid("duplicate `cursor` parameter".into()));
                }
                if !is_valid_cursor(&value) {
                    return Err(UriError::Invalid(
                        "`cursor` must be 1 to 512 visible ASCII characters".into(),
                    ));
                }
                page.cursor = Some(value);
            }
            "limit" => {
                if page.limit.is_some() {
                    return Err(UriError::Invalid("duplicate `limit` parameter".into()));
                }
                let n: u32 = value
                    .parse()
                    .map_err(|_| UriError::Invalid("`limit` must be an integer".into()))?;
                if !(MIN_LIMIT..=MAX_LIMIT).contains(&n) {
                    return Err(UriError::Invalid(format!(
                        "`limit` must be between {MIN_LIMIT} and {MAX_LIMIT}"
                    )));
                }
                page.limit = Some(n);
            }
            other => {
                return Err(UriError::Invalid(format!(
                    "unknown query parameter `{}`",
                    other.chars().take(32).collect::<String>()
                )));
            }
        }
    }
    Ok(page)
}

/// Minimal RFC 3986 percent-decoder. `None` on malformed escapes or non-UTF-8.
pub fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex(*bytes.get(i + 1)?)?;
            let lo = hex(*bytes.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-encode everything except RFC 3986 unreserved characters.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// True if `uri` may be subscribed to: exactly one of our base URIs (no query,
/// no fragment) or a conversation instance with a valid id.
pub fn is_subscribable(uri: &str) -> bool {
    matches!(uri, IDENTITY_URI | INBOX_URI | OUTBOX_URI | TRIGGERS_URI)
        || uri
            .strip_prefix(CONVERSATIONS_PREFIX)
            .is_some_and(is_valid_id)
}

/// The resource a change hint refers to. `Events` has no MCP resource.
pub fn hint_uri(hint: &ChangeHint) -> Option<String> {
    match hint {
        ChangeHint::Inbox => Some(INBOX_URI.to_string()),
        ChangeHint::Outbox => Some(OUTBOX_URI.to_string()),
        ChangeHint::Triggers => Some(TRIGGERS_URI.to_string()),
        ChangeHint::Identity => Some(IDENTITY_URI.to_string()),
        ChangeHint::Conversation { conversation_id } => {
            is_valid_id(conversation_id).then(|| conversation_uri(conversation_id))
        }
        ChangeHint::Events => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base_uris() {
        assert_eq!(parse(IDENTITY_URI), Ok(ResourceRef::Identity));
        assert_eq!(parse(TRIGGERS_URI), Ok(ResourceRef::Triggers));
        assert_eq!(
            parse("agentnet://inbox"),
            Ok(ResourceRef::Inbox(PageParams::default()))
        );
    }

    #[test]
    fn parses_query_and_decodes() {
        let r = parse("agentnet://inbox?cursor=a%3Db%2Bc&limit=10").unwrap();
        assert_eq!(
            r,
            ResourceRef::Inbox(PageParams {
                cursor: Some("a=b+c".into()),
                limit: Some(10)
            })
        );
    }

    #[test]
    fn rejects_bad_queries() {
        for bad in [
            "agentnet://inbox?limit=0",
            "agentnet://inbox?limit=201",
            "agentnet://inbox?limit=x",
            "agentnet://inbox?cursor=",
            "agentnet://inbox?cursor=%zz",
            "agentnet://inbox?cursor=a&cursor=b",
            "agentnet://inbox?bogus=1",
            "agentnet://identity?limit=1",
        ] {
            assert!(matches!(parse(bad), Err(UriError::Invalid(_))), "{bad}");
        }
    }

    #[test]
    fn unknown_uris_are_not_found() {
        for bad in [
            "agentnet://",
            "agentnet://nope",
            "agentnet://inbox/",
            "agentnet://conversations/",
            "agentnet://conversations/a/b",
            "agentnet://conversations/a b",
            "agentnet://inbox#frag",
            "file:///etc/passwd",
            "agentnet://conversations/%2e%2e",
        ] {
            assert_eq!(parse(bad), Err(UriError::NotFound), "{bad}");
        }
    }

    #[test]
    fn subscribable_rules() {
        assert!(is_subscribable(INBOX_URI));
        assert!(is_subscribable("agentnet://conversations/abc-1"));
        assert!(!is_subscribable("agentnet://inbox?cursor=x"));
        assert!(!is_subscribable("agentnet://conversations/"));
        assert!(!is_subscribable("agentnet://other"));
    }

    #[test]
    fn hints_map_to_uris() {
        assert_eq!(hint_uri(&ChangeHint::Events), None);
        assert_eq!(hint_uri(&ChangeHint::Inbox).as_deref(), Some(INBOX_URI));
        assert_eq!(
            hint_uri(&ChangeHint::Conversation {
                conversation_id: "c1".into()
            })
            .as_deref(),
            Some("agentnet://conversations/c1")
        );
        assert_eq!(
            hint_uri(&ChangeHint::Conversation {
                conversation_id: "bad id".into()
            }),
            None
        );
    }

    #[test]
    fn percent_roundtrip() {
        let s = "a=b+c/ü";
        assert_eq!(percent_decode(&percent_encode(s)).as_deref(), Some(s));
    }
}
