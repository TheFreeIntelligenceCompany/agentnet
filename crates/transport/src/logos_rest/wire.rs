//! Pure wire-level helpers: hashing, size arithmetic, error mapping and
//! response parsing. Nothing here does I/O, so everything is unit-testable.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::config::{is_private_ipv4, is_private_ipv6, peer_id_of_multiaddr, valid_peer_id};
use crate::{ContentTopic, FrameSource, HistoryPage, InboundFrame, PeerInfo, TransportError};

/// Lower-case hex.
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parses `0x`-prefixed (or bare) 32-byte hex, case-insensitive.
pub(crate) fn parse_hash(s: &str) -> Option<[u8; 32]> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Deterministic Waku message hash (14/WAKU2-MESSAGE):
/// `sha256(pubsubTopic || payload || contentTopic || meta || timestamp_be64)`.
/// Verified against the Store hashes of the pinned v0.39.2 node.
pub fn waku_message_hash(
    pubsub_topic: &str,
    payload: &[u8],
    content_topic: &str,
    meta: &[u8],
    timestamp_ns: i64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(pubsub_topic.as_bytes());
    h.update(payload);
    h.update(content_topic.as_bytes());
    h.update(meta);
    h.update((timestamp_ns as u64).to_be_bytes());
    h.finalize().into()
}

/// Length of the protobuf varint encoding of `v`.
pub(crate) fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Bytes of an encoded WakuMessage that are not payload: field tags and length
/// varints for payload and content topic, the content topic itself (so the total
/// is `payload_len + framing_overhead`), a
/// worst-case (10-byte varint) timestamp, a worst-case `ephemeral` field, plus
/// [`UNMODELED_RESERVE`] and [`SAFETY_MARGIN`].
pub(crate) fn framing_overhead(payload_len: usize, topic_len: usize) -> usize {
    1usize
        .saturating_add(varint_len(payload_len as u64))
        .saturating_add(1)
        .saturating_add(varint_len(topic_len as u64))
        .saturating_add(topic_len)
        .saturating_add(1 + 10)
        .saturating_add(3)
        .saturating_add(UNMODELED_RESERVE)
        .saturating_add(SAFETY_MARGIN)
}

/// Bytes the node counts that we cannot attribute to a WakuMessage field. With
/// the measured acceptance of a 153516-byte payload on a 33-byte topic against
/// the 153600-byte limit (and rejection of 153517), the encoded message plus
/// this reserve is exactly the limit when the other terms are worst-case.
pub(crate) const UNMODELED_RESERVE: usize = 31;
/// Extra slack kept below the measured limit.
pub(crate) const SAFETY_MARGIN: usize = 8;

/// Largest payload for which the node is expected to accept a publish on a
/// topic of `topic_len` bytes, given its `--max-msg-size`.
pub(crate) fn max_payload_for(max_message_bytes: usize, topic_len: usize) -> usize {
    let mut p = max_message_bytes.saturating_sub(topic_len);
    while p > 0 && p.saturating_add(framing_overhead(p, topic_len)) > max_message_bytes {
        p -= 1;
    }
    p
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
pub(crate) fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// At most 200 characters of a response body, control characters replaced, for
/// inclusion in an error message.
pub(crate) fn snippet(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    let mut out: String = s
        .chars()
        .take(200)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if s.chars().count() > 200 {
        out.push_str("...");
    }
    out
}

/// Maps a failed publish response to a [`TransportError`].
pub(crate) fn map_publish_failure(
    status: u16,
    body: &[u8],
    payload_len: usize,
    max: usize,
) -> TransportError {
    let text = String::from_utf8_lossy(body);
    if text.contains("NoPeersToPublish") {
        return TransportError::Unavailable(
            "node reported NoPeersToPublish (no connected peers; the node also returns this \
             for a message just over the size limit or a duplicate publish)"
                .into(),
        );
    }
    if text.contains("size exceeded") {
        return TransportError::TooLarge {
            size: payload_len,
            max,
        };
    }
    if text.contains("while initializing") {
        return TransportError::Unavailable(format!(
            "node is still initializing (HTTP {status}): {}",
            snippet(body)
        ));
    }
    match status {
        503 | 408 | 429 | 500..=599 => {
            TransportError::Unavailable(format!("node answered HTTP {status}: {}", snippet(body)))
        }
        _ => TransportError::Protocol(format!(
            "node rejected publish with HTTP {status}: {}",
            snippet(body)
        )),
    }
}

/// Counters produced while parsing a response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ParseCounts {
    pub malformed: u64,
    pub hash_mismatch: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireMessage {
    payload: String,
    content_topic: String,
    timestamp: i64,
    #[serde(default)]
    meta: Option<String>,
}

struct Decoded {
    payload: Vec<u8>,
    meta: Vec<u8>,
}

fn decode_message(m: &WireMessage, max_bytes: usize) -> Option<Decoded> {
    // Decoded payload can never exceed the node's max message size.
    if m.payload.len() > max_bytes.saturating_mul(2) {
        return None;
    }
    let payload = B64.decode(&m.payload).ok()?;
    if payload.len() > max_bytes {
        return None;
    }
    let meta = match m.meta.as_deref() {
        None | Some("") => Vec::new(),
        Some(s) if s.len() > 88 => return None,
        Some(s) => B64.decode(s).ok().filter(|v| v.len() <= 64)?,
    };
    Some(Decoded { payload, meta })
}

/// Entries the node's REST relay cache can hold at the recommended setting
/// (`--rest-relay-cache-capacity=1000`, docs/relay-setup.md). One poll can return all of them.
pub(crate) const NODE_RELAY_CACHE_ENTRIES: usize = 1000;
/// Maximum number of decoded frames accepted from a single relay poll response
/// (guards against OOM amplification from millions of tiny frames within the byte limit).
pub(crate) const MAX_RELAY_POLL_FRAMES: usize = 4096;
/// Maximum accepted length of a Store pagination cursor (bytes).
const MAX_STORE_CURSOR_LEN: usize = 256;

/// Largest JSON object we accept as ONE relay message, for a node limit of `max_bytes`.
/// A payload of `max_bytes` is `4 * ceil(max_bytes / 3)` Base64 characters; add a 64-byte `meta`
/// (88 characters) and 1 KiB for the envelope (field names, topic, timestamp). Anything larger
/// cannot be a valid message and is skipped without being buffered.
pub(crate) fn max_relay_element_bytes(max_bytes: usize) -> usize {
    max_bytes
        .div_ceil(3)
        .saturating_mul(4)
        .saturating_add(88 + 1024)
}

/// Upper bound on the bytes of one poll response that we will read: the node's whole cache full of
/// maximum-size messages. With the defaults (153,600-byte messages, 1000 entries):
/// 1000 x (204,800 + 1,112 + 1) = about 196 MiB on the wire. That is NOT buffered: elements are
/// parsed as they arrive ([`RelayStream`]), so resident memory is one element (at most about
/// 201 KiB) plus the decoded frames returned (at most 1000 x 150 KiB = 146 MiB, the same bound the
/// node itself holds in its cache).
pub(crate) fn max_relay_response_bytes(max_bytes: usize) -> usize {
    max_relay_element_bytes(max_bytes)
        .saturating_add(1) // separating comma
        .saturating_mul(NODE_RELAY_CACHE_ENTRIES)
        .saturating_add(1024) // brackets and whitespace
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamState {
    /// Before the opening `[`.
    Start,
    /// Between array elements.
    Between,
    /// Inside an element.
    Element,
    /// After the closing `]`.
    Done,
    /// The body is not an array; everything else is ignored.
    Failed,
}

/// Incremental parser for the body of `GET /relay/v1/auto/messages/{topic}`.
///
/// The node drains its cache when it answers, so a frame we fail to hand on is gone from the live
/// path. This parser therefore never rejects a batch as a whole: it splits the JSON array into
/// elements as bytes arrive, buffers at most one element, skips (and counts) an element that is
/// oversized or malformed, and keeps every complete valid frame even if the body later turns out
/// truncated or the connection fails (see [`RelayStream::finish`]).
pub(crate) struct RelayStream<'a> {
    topic: &'a ContentTopic,
    pubsub_topic: &'a str,
    max_bytes: usize,
    max_element: usize,
    state: StreamState,
    buf: Vec<u8>,
    depth: usize,
    in_string: bool,
    escaped: bool,
    scalar: bool,
    overflow: bool,
    frames: Vec<InboundFrame>,
    counts: ParseCounts,
    error: Option<String>,
}

/// Result of [`RelayStream::finish`].
pub(crate) struct RelayParsed {
    pub frames: Vec<InboundFrame>,
    pub counts: ParseCounts,
    /// Set when the body was not a complete JSON array; `frames` still holds every complete
    /// valid frame that preceded the problem.
    pub error: Option<String>,
}

impl<'a> RelayStream<'a> {
    pub(crate) fn new(topic: &'a ContentTopic, pubsub_topic: &'a str, max_bytes: usize) -> Self {
        Self {
            topic,
            pubsub_topic,
            max_bytes,
            max_element: max_relay_element_bytes(max_bytes),
            state: StreamState::Start,
            buf: Vec::new(),
            depth: 0,
            in_string: false,
            escaped: false,
            scalar: false,
            overflow: false,
            frames: Vec::new(),
            counts: ParseCounts::default(),
            error: None,
        }
    }

    /// Bytes currently buffered for the element being parsed (never above the element limit).
    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Consumes the next chunk of the response body.
    pub(crate) fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            match self.state {
                StreamState::Failed | StreamState::Done => return,
                StreamState::Start => {
                    if b == b'[' {
                        self.state = StreamState::Between;
                    } else if !b.is_ascii_whitespace() {
                        self.state = StreamState::Failed;
                        self.error = Some("relay poll response is not a JSON array".into());
                    }
                }
                StreamState::Between => match b {
                    b',' => {}
                    b']' => self.state = StreamState::Done,
                    _ if b.is_ascii_whitespace() => {}
                    _ => self.begin_element(b),
                },
                StreamState::Element => self.element_byte(b),
            }
        }
    }

    fn begin_element(&mut self, b: u8) {
        self.state = StreamState::Element;
        self.buf.clear();
        self.depth = 0;
        self.in_string = false;
        self.escaped = false;
        self.overflow = false;
        self.scalar = !matches!(b, b'{' | b'[' | b'"');
        self.element_byte(b);
    }

    fn element_byte(&mut self, b: u8) {
        if self.scalar && (b == b',' || b == b']' || b.is_ascii_whitespace()) {
            // A bare scalar (number, `null`, ...) ends before its delimiter.
            self.finish_element();
            self.state = if b == b']' {
                StreamState::Done
            } else {
                StreamState::Between
            };
            return;
        }
        let mut end = false;
        if self.in_string {
            if self.escaped {
                self.escaped = false;
            } else if b == b'\\' {
                self.escaped = true;
            } else if b == b'"' {
                self.in_string = false;
                end = self.depth == 0;
            }
        } else {
            match b {
                b'"' => self.in_string = true,
                b'{' | b'[' => self.depth += 1,
                b'}' | b']' => {
                    self.depth = self.depth.saturating_sub(1);
                    end = self.depth == 0;
                }
                _ => {}
            }
        }
        if !self.overflow {
            if self.buf.len() >= self.max_element {
                self.overflow = true;
                self.buf = Vec::new();
            } else {
                self.buf.push(b);
            }
        }
        if end {
            self.finish_element();
            self.state = StreamState::Between;
        }
    }

    fn finish_element(&mut self) {
        let raw = std::mem::take(&mut self.buf);
        if self.overflow {
            self.counts.malformed += 1;
            return;
        }
        let parsed = serde_json::from_slice::<WireMessage>(&raw)
            .ok()
            .filter(|m| m.content_topic == self.topic.as_str())
            .and_then(|m| decode_message(&m, self.max_bytes).map(|d| (m, d)));
        let Some((m, d)) = parsed else {
            self.counts.malformed += 1;
            return;
        };
        if self.frames.len() >= MAX_RELAY_POLL_FRAMES {
            self.state = StreamState::Failed;
            self.error = Some(format!(
                "relay poll response exceeds {MAX_RELAY_POLL_FRAMES} frames"
            ));
            return;
        }
        self.frames.push(InboundFrame {
            topic: self.topic.clone(),
            transport_id: waku_message_hash(
                self.pubsub_topic,
                &d.payload,
                &m.content_topic,
                &d.meta,
                m.timestamp,
            ),
            payload: d.payload,
            timestamp_ns: m.timestamp,
            source: FrameSource::Live,
        });
    }

    /// Ends the body. A body that stops before the closing `]` is reported in `error`; frames
    /// completed before that point are kept.
    pub(crate) fn finish(mut self) -> RelayParsed {
        if self.error.is_none() && self.state != StreamState::Done {
            self.error = Some(match self.state {
                StreamState::Start => "relay poll response is empty".into(),
                _ => "relay poll response is truncated (no closing bracket)".into(),
            });
        }
        RelayParsed {
            frames: self.frames,
            counts: self.counts,
            error: self.error,
        }
    }
}

/// Parses a whole `GET /relay/v1/auto/messages/{topic}` body held in memory (tests; the adapter
/// itself uses [`RelayStream`]). Any structural error is an `Err`.
#[cfg(test)]
pub(crate) fn parse_relay_messages(
    body: &[u8],
    topic: &ContentTopic,
    pubsub_topic: &str,
    max_bytes: usize,
) -> Result<(Vec<InboundFrame>, ParseCounts), TransportError> {
    let mut s = RelayStream::new(topic, pubsub_topic, max_bytes);
    s.feed(body);
    let r = s.finish();
    match r.error {
        Some(e) => Err(TransportError::Protocol(e)),
        None => Ok((r.frames, r.counts)),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoreEntry {
    message_hash: String,
    message: Option<WireMessage>,
    pubsub_topic: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoreResponse {
    status_code: u32,
    status_desc: Option<String>,
    #[serde(default)]
    messages: Option<Vec<Value>>,
    pagination_cursor: Option<String>,
}

/// Why a Store response could not be used.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StoreParseError {
    /// Not the JSON we expect.
    Malformed(String),
    /// The Store answered with a non-200 `statusCode`.
    Status(String),
}

/// Parses the body of `GET /store/v3/messages`. Entries whose recomputed hash
/// differs from `messageHash` are skipped and counted; so are malformed ones.
pub(crate) fn parse_store_page(
    body: &[u8],
    topic: &ContentTopic,
    pubsub_topic: &str,
    max_bytes: usize,
) -> Result<(HistoryPage, ParseCounts), StoreParseError> {
    let resp: StoreResponse = serde_json::from_slice(body).map_err(|_| {
        StoreParseError::Malformed("store response is not the expected JSON".into())
    })?;
    // Check `statusCode` before requiring `messages`, since non-200 Store
    // responses may omit `messages` or return `"messages": null`.
    if resp.status_code != 200 {
        return Err(StoreParseError::Status(format!(
            "store statusCode {}: {}",
            resp.status_code,
            snippet(resp.status_desc.unwrap_or_default().as_bytes())
        )));
    }
    let Some(messages) = resp.messages else {
        return Err(StoreParseError::Malformed(
            "store response is missing messages array".into(),
        ));
    };
    let mut counts = ParseCounts::default();
    let mut frames = Vec::with_capacity(messages.len());
    for v in messages {
        let Ok(entry) = serde_json::from_value::<StoreEntry>(v) else {
            counts.malformed += 1;
            continue;
        };
        let (Some(claimed), Some(m)) = (parse_hash(&entry.message_hash), entry.message.as_ref())
        else {
            counts.malformed += 1;
            continue;
        };
        if m.content_topic != topic.as_str()
            || entry
                .pubsub_topic
                .as_deref()
                .is_some_and(|p| p != pubsub_topic)
        {
            counts.malformed += 1;
            continue;
        }
        let Some(d) = decode_message(m, max_bytes) else {
            counts.malformed += 1;
            continue;
        };
        let id = waku_message_hash(
            pubsub_topic,
            &d.payload,
            &m.content_topic,
            &d.meta,
            m.timestamp,
        );
        if id != claimed {
            counts.hash_mismatch += 1;
            continue;
        }
        frames.push(InboundFrame {
            topic: topic.clone(),
            payload: d.payload,
            timestamp_ns: m.timestamp,
            transport_id: id,
            source: FrameSource::History,
        });
    }
    let next_cursor = match resp.pagination_cursor.filter(|c| !c.is_empty()) {
        Some(c) if c.len() > MAX_STORE_CURSOR_LEN => {
            return Err(StoreParseError::Malformed(
                "store paginationCursor is too large".into(),
            ));
        }
        other => other,
    };
    Ok((
        HistoryPage {
            frames,
            next_cursor,
        },
        counts,
    ))
}

/// One entry of `GET /admin/v1/peers`, reduced to what the audit needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawPeer {
    pub peer_id: Option<String>,
    pub multiaddr: String,
    pub connected: bool,
    pub shards: Vec<u16>,
}

/// Parses `GET /admin/v1/peers`. The pinned node reports no separate peer id:
/// it is the last `/p2p/` segment of `multiaddr`. Every entry must be an object
/// with a string `multiaddr` and a `connected` state that is one of the node's
/// `Connectedness` names (`NotConnected`, `CannotConnect`, `CanConnect`,
/// `Connected`); anything else makes the list unauditable. Only `Connected`
/// counts as connected.
pub(crate) fn parse_peers(body: &[u8]) -> Result<Vec<RawPeer>, String> {
    let items: Vec<Value> =
        serde_json::from_slice(body).map_err(|_| "admin peers response is not a JSON array")?;
    let mut out = Vec::with_capacity(items.len());
    for v in items {
        let Some(multiaddr) = v.get("multiaddr").and_then(Value::as_str) else {
            return Err("admin peers entry has no string multiaddr".into());
        };
        let connected = match v.get("connected").and_then(Value::as_str) {
            Some("Connected") => true,
            Some("NotConnected" | "CannotConnect" | "CanConnect") => false,
            _ => return Err("admin peers entry has a missing or unknown connected state".into()),
        };
        let from_addr = peer_id_of_multiaddr(multiaddr).map(str::to_string);
        let peer_id = match v.get("peerId").and_then(Value::as_str) {
            Some(explicit) => {
                if !valid_peer_id(explicit) {
                    return Err("admin peers entry has an invalid peerId".into());
                }
                if let Some(ref ma_id) = from_addr {
                    if ma_id != explicit {
                        return Err(
                            "admin peers entry peerId disagrees with multiaddr /p2p/ id".into()
                        );
                    }
                }
                Some(explicit.to_string())
            }
            None => from_addr,
        };
        let shards = v
            .get("shards")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_u64().and_then(|n| u16::try_from(n).ok()))
                    .collect()
            })
            .unwrap_or_default();
        out.push(RawPeer {
            peer_id,
            multiaddr: multiaddr.to_string(),
            connected,
            shards,
        });
    }
    Ok(out)
}

/// Checks whether a connected peer's multiaddr violates circuit-relay or
/// private-mode address rules.
fn connected_multiaddr_violation(
    multiaddr: &str,
    require_private_ip: bool,
) -> Option<&'static str> {
    let comps: Vec<&str> = multiaddr.split('/').collect();
    if comps.contains(&"p2p-circuit") {
        return Some("circuit-relayed (/p2p-circuit)");
    }
    if !require_private_ip {
        return None;
    }
    let mut it = comps.into_iter().skip(1);
    let mut saw_ip = false;
    while let Some(seg) = it.next() {
        match seg {
            "dns" | "dns4" | "dns6" | "dnsaddr" => {
                return Some("DNS-addressed in private mode");
            }
            "ip4" => {
                saw_ip = true;
                let ok = it
                    .next()
                    .and_then(|a| a.parse::<std::net::Ipv4Addr>().ok())
                    .is_some_and(is_private_ipv4);
                if !ok {
                    return Some("non-private IPv4 in private mode");
                }
            }
            "ip6" => {
                saw_ip = true;
                let ok = it
                    .next()
                    .and_then(|a| a.parse::<std::net::Ipv6Addr>().ok())
                    .is_some_and(is_private_ipv6);
                if !ok {
                    return Some("non-private IPv6 in private mode");
                }
            }
            _ => {}
        }
    }
    if !saw_ip {
        return Some("missing literal private IP in private mode");
    }
    None
}

/// Result of evaluating a peer list against the allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuditReport {
    pub peers: Vec<PeerInfo>,
    pub violation: Option<String>,
}

/// Audited-mode check: any connected peer outside `allowed` is a violation, as
/// is a connected peer whose id cannot be determined, a connected peer over
/// `/p2p-circuit` (or non-private address when `require_private_ip` is true),
/// and a connected allowed peer that advertises shards but not `shard`.
pub(crate) fn evaluate_peers(
    raw: &[RawPeer],
    allowed: &[String],
    shard: u16,
    require_private_ip: bool,
) -> AuditReport {
    let mut peers = Vec::new();
    let mut foreign = Vec::new();
    let mut bad_addr = Vec::new();
    let mut unknown = 0usize;
    let mut wrong_shard = 0usize;
    for p in raw {
        match &p.peer_id {
            Some(id) => {
                let id_ok = allowed.iter().any(|a| a == id);
                let addr_err = if p.connected {
                    connected_multiaddr_violation(&p.multiaddr, require_private_ip)
                } else {
                    None
                };
                let ok = id_ok && addr_err.is_none();
                if p.connected && !id_ok {
                    foreign.push(snippet(id.as_bytes()).chars().take(64).collect::<String>());
                }
                if let Some(why) = addr_err {
                    bad_addr.push(format!(
                        "{} ({why})",
                        snippet(id.as_bytes()).chars().take(64).collect::<String>()
                    ));
                }
                if p.connected && ok && !p.shards.is_empty() && !p.shards.contains(&shard) {
                    wrong_shard += 1;
                }
                peers.push(PeerInfo {
                    peer_id: id.clone(),
                    connected: p.connected,
                    allowed: ok,
                });
            }
            None if p.connected => unknown += 1,
            None => {}
        }
    }
    let mut reasons = Vec::new();
    if !foreign.is_empty() {
        let shown: Vec<_> = foreign.iter().take(3).cloned().collect();
        reasons.push(format!(
            "node is connected to {} peer(s) not in the allowlist (e.g. {})",
            foreign.len(),
            shown.join(", ")
        ));
    }
    if !bad_addr.is_empty() {
        let shown: Vec<_> = bad_addr.iter().take(3).cloned().collect();
        reasons.push(format!(
            "node is connected to {} peer(s) over a disallowed transport/address (e.g. {})",
            bad_addr.len(),
            shown.join(", ")
        ));
    }
    if unknown > 0 {
        reasons.push(format!(
            "node is connected to {unknown} peer(s) with unidentifiable peer id"
        ));
    }
    if wrong_shard > 0 {
        reasons.push(format!(
            "{wrong_shard} connected peer(s) do not serve configured shard {shard}"
        ));
    }
    AuditReport {
        peers,
        violation: if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBSUB: &str = "/waku/2/rs/66/0";
    const CT: &str = "/agentnet/1/ttest-sample/proto";
    // Captured from a real v0.39.2 Store response (node A, 2026-11-25).
    const REAL_STORE: &str = r#"{"requestId":"e77b4792fc0022b5f38e","statusCode":200,"statusDesc":"OK","messages":[{"messageHash":"0x68cae78abcff26d30ca097f50001104e140669b6bd4241bc1edc9db4830ce4f0","message":{"payload":"aGVsbG8=","contentTopic":"/agentnet/1/ttest-sample/proto","version":0,"timestamp":1795638885000000000,"ephemeral":false},"pubsubTopic":"/waku/2/rs/66/0"}]}"#;
    const REAL_HASH: &str = "0x68cae78abcff26d30ca097f50001104e140669b6bd4241bc1edc9db4830ce4f0";

    fn topic() -> ContentTopic {
        ContentTopic::new(CT).unwrap()
    }

    #[test]
    fn hash_matches_real_node_vector() {
        let h = waku_message_hash(PUBSUB, b"hello", CT, b"", 1_795_638_885_000_000_000);
        assert_eq!(format!("0x{}", hex(&h)), REAL_HASH);
        // every input participates
        assert_ne!(
            h,
            waku_message_hash(
                "/waku/2/rs/66/1",
                b"hello",
                CT,
                b"",
                1_795_638_885_000_000_000
            )
        );
        assert_ne!(
            h,
            waku_message_hash(PUBSUB, b"hellO", CT, b"", 1_795_638_885_000_000_000)
        );
        assert_ne!(
            h,
            waku_message_hash(PUBSUB, b"hello", "/a/1/b/c", b"", 1_795_638_885_000_000_000)
        );
        assert_ne!(
            h,
            waku_message_hash(PUBSUB, b"hello", CT, b"m", 1_795_638_885_000_000_000)
        );
        assert_ne!(
            h,
            waku_message_hash(PUBSUB, b"hello", CT, b"", 1_795_638_885_000_000_001)
        );
    }

    #[test]
    fn parse_hash_forms() {
        assert_eq!(
            parse_hash(REAL_HASH)
                .map(|h| format!("0x{}", hex(&h)))
                .as_deref(),
            Some(REAL_HASH)
        );
        assert!(parse_hash(&REAL_HASH.to_uppercase().replace("0X", "0x")).is_some());
        assert!(parse_hash(&REAL_HASH[2..]).is_some());
        for bad in ["", "0x12", "0xzz", &REAL_HASH[..65], "0x\u{e9}\u{e9}"] {
            assert!(parse_hash(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn store_page_with_real_vector() {
        let (page, counts) =
            parse_store_page(REAL_STORE.as_bytes(), &topic(), PUBSUB, 153_600).unwrap();
        assert_eq!(counts, ParseCounts::default());
        assert_eq!(page.frames.len(), 1);
        assert_eq!(page.frames[0].payload, b"hello");
        assert_eq!(page.frames[0].timestamp_ns, 1_795_638_885_000_000_000);
        assert_eq!(page.frames[0].source, FrameSource::History);
        assert_eq!(
            format!("0x{}", hex(&page.frames[0].transport_id)),
            REAL_HASH
        );
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn store_page_counts_mismatch_and_malformed() {
        let tampered = REAL_STORE.replace("aGVsbG8=", "aGVsbG8h");
        let (page, c) = parse_store_page(tampered.as_bytes(), &topic(), PUBSUB, 153_600).unwrap();
        assert!(page.frames.is_empty());
        assert_eq!(c.hash_mismatch, 1);

        let other_topic = REAL_STORE.replace("/waku/2/rs/66/0\"}]", "/waku/2/rs/66/1\"}]");
        let (page, c) =
            parse_store_page(other_topic.as_bytes(), &topic(), PUBSUB, 153_600).unwrap();
        assert!(page.frames.is_empty());
        assert_eq!(c.malformed, 1);

        let body = r#"{"statusCode":200,"messages":[{"messageHash":"0x00"},{"nope":1},
            {"messageHash":"0x68cae78abcff26d30ca097f50001104e140669b6bd4241bc1edc9db4830ce4f0","message":{"payload":"!!!","contentTopic":"/agentnet/1/ttest-sample/proto","timestamp":1}}
            ],"paginationCursor":"0xabc"}"#;
        let (page, c) = parse_store_page(body.as_bytes(), &topic(), PUBSUB, 153_600).unwrap();
        assert!(page.frames.is_empty());
        assert_eq!(c.malformed, 3);
        assert_eq!(page.next_cursor.as_deref(), Some("0xabc"));
    }

    #[test]
    fn store_page_errors() {
        assert!(matches!(
            parse_store_page(b"not json", &topic(), PUBSUB, 10),
            Err(StoreParseError::Malformed(_))
        ));
        assert!(matches!(
            parse_store_page(
                br#"{"statusCode":503,"statusDesc":"busy","messages":[]}"#,
                &topic(),
                PUBSUB,
                10
            ),
            Err(StoreParseError::Status(_))
        ));
        let (p, _) = parse_store_page(
            br#"{"statusCode":200,"messages":[],"paginationCursor":""}"#,
            &topic(),
            PUBSUB,
            10,
        )
        .unwrap();
        assert!(p.next_cursor.is_none(), "empty cursor means last page");
    }

    #[test]
    fn relay_poll_parsing() {
        let body = r#"[
            {"payload":"aGVsbG8=","contentTopic":"/agentnet/1/ttest-sample/proto","version":0,"timestamp":1795638885000000000,"ephemeral":false,"proof":""},
            {"payload":"%%%","contentTopic":"/agentnet/1/ttest-sample/proto","timestamp":1},
            {"payload":"aGVsbG8=","contentTopic":"/agentnet/1/other/proto","timestamp":1},
            {"payload":"aGVsbG8=","contentTopic":"/agentnet/1/ttest-sample/proto"},
            {"payload":"aGVsbG8=","contentTopic":"/agentnet/1/ttest-sample/proto","timestamp":1,"meta":"@@"},
            42
        ]"#;
        let (frames, c) = parse_relay_messages(body.as_bytes(), &topic(), PUBSUB, 153_600).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(c.malformed, 5);
        assert_eq!(format!("0x{}", hex(&frames[0].transport_id)), REAL_HASH);
        assert_eq!(frames[0].source, FrameSource::Live);
        assert!(parse_relay_messages(b"{}", &topic(), PUBSUB, 10).is_err());
        assert!(parse_relay_messages(b"", &topic(), PUBSUB, 10).is_err());
        let (f, c) = parse_relay_messages(b"[]", &topic(), PUBSUB, 10).unwrap();
        assert!(f.is_empty());
        assert_eq!(c, ParseCounts::default());
    }

    #[test]
    fn relay_poll_meta_participates_in_hash_and_oversize_is_skipped() {
        let body = r#"[{"payload":"aGVsbG8=","contentTopic":"/agentnet/1/ttest-sample/proto","timestamp":5,"meta":"bQ=="}]"#;
        let (f, _) = parse_relay_messages(body.as_bytes(), &topic(), PUBSUB, 153_600).unwrap();
        assert_eq!(
            f[0].transport_id,
            waku_message_hash(PUBSUB, b"hello", CT, b"m", 5)
        );
        let (f, c) = parse_relay_messages(body.as_bytes(), &topic(), PUBSUB, 3).unwrap();
        assert!(f.is_empty());
        assert_eq!(c.malformed, 1);
    }

    #[test]
    fn varints_and_size_arithmetic() {
        for (v, n) in [
            (0u64, 1),
            (127, 1),
            (128, 2),
            (16383, 2),
            (16384, 3),
            (2_097_151, 3),
            (2_097_152, 4),
            (u64::MAX, 10),
        ] {
            assert_eq!(varint_len(v), n, "{v}");
        }
        // Measured on the pinned node: 153516 accepted for a 33-byte topic.
        let t33 = "/agentnet/1/spike-a1-limits/proto".len();
        assert_eq!(t33, 33);
        let m = max_payload_for(153_600, t33);
        assert!(m <= 153_516, "must not exceed the measured acceptance: {m}");
        assert!(m >= 153_516 - 16, "margin should be small: {m}");
        // fits() is the exact boundary of the formula
        let fits = |p: usize| p + framing_overhead(p, t33) <= 153_600;
        assert!(fits(m) && !fits(m + 1));
        // monotonic in topic length, never underflows
        assert!(max_payload_for(153_600, 60) < max_payload_for(153_600, 20));
        assert_eq!(max_payload_for(10, 40), 0);
        assert_eq!(max_payload_for(0, 0), 0);
        // varint boundary: payload length 16384 changes the length varint by one
        let small = max_payload_for(16_500, 30);
        assert!(small + framing_overhead(small, 30) <= 16_500);
    }

    #[test]
    fn publish_error_mapping() {
        let e = map_publish_failure(
            400,
            b"Failed to publish: publish failed in relay: NoPeersToPublish",
            10,
            100,
        );
        assert!(matches!(e, TransportError::Unavailable(_)));
        let e = map_publish_failure(
            400,
            b"Failed to publish: Message size exceeded maximum of 153600 bytes",
            777,
            100,
        );
        assert_eq!(
            e,
            TransportError::TooLarge {
                size: 777,
                max: 100
            }
        );
        assert!(matches!(
            map_publish_failure(503, b"Push request timed out", 1, 1),
            TransportError::Unavailable(_)
        ));
        assert!(matches!(
            map_publish_failure(500, b"", 1, 1),
            TransportError::Unavailable(_)
        ));
        assert!(matches!(
            map_publish_failure(400, b"Invalid content body", 1, 1),
            TransportError::Protocol(_)
        ));
        assert!(matches!(
            map_publish_failure(404, b"", 1, 1),
            TransportError::Protocol(_)
        ));
        let long = vec![b'x'; 5000];
        let msg = map_publish_failure(400, &long, 1, 1).to_string();
        assert!(msg.len() < 300, "{}", msg.len());
        assert!(msg.ends_with("..."));
        assert_eq!(snippet(b"a\nb\x00c"), "a b c");
        assert_eq!(snippet(&[0xff, 0xfe]).chars().count(), 2);
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(
            encode_component("/agentnet/1/x-y_z.w/proto"),
            "%2Fagentnet%2F1%2Fx-y_z.w%2Fproto"
        );
        assert_eq!(encode_component("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(encode_component("é"), "%C3%A9");
    }

    #[test]
    fn peers_parsing_and_audit() {
        let body = r#"[
            {"multiaddr":"/ip4/172.28.66.10/tcp/60000/p2p/RelayOne","protocols":[],"shards":[0],"connected":"Connected","agent":"x","origin":"UnknownOrigin"},
            {"multiaddr":"/ip4/1.2.3.4/tcp/60000/p2p/Stranger","shards":[0],"connected":"CanConnect"},
            {"multiaddr":"garbage","connected":"Connected"}
        ]"#;
        let raw = parse_peers(body.as_bytes()).unwrap();
        assert_eq!(raw.len(), 3);
        assert_eq!(raw[0].peer_id.as_deref(), Some("RelayOne"));
        assert!(raw[0].connected && !raw[1].connected);
        assert_eq!(raw[2].peer_id, None);
        assert!(parse_peers(b"{}").is_err());

        let allowed = vec!["RelayOne".to_string()];
        // unidentifiable connected peer => violation
        let r = evaluate_peers(&raw, &allowed, 0, true);
        assert!(r.violation.as_deref().unwrap().contains("unidentifiable"));
        // a merely known-but-disconnected stranger is not a violation
        let r = evaluate_peers(&raw[..2], &allowed, 0, true);
        assert!(r.violation.is_none(), "{:?}", r.violation);
        assert_eq!(r.peers.len(), 2);
        assert!(r.peers[0].allowed && r.peers[0].connected);
        assert!(!r.peers[1].allowed && !r.peers[1].connected);
        // wrong allowlist => the connected relay is foreign
        let r = evaluate_peers(&raw[..1], &["Other".to_string()], 0, true);
        assert!(r.violation.as_deref().unwrap().contains("RelayOne"));
        // shard mismatch
        let r = evaluate_peers(&raw[..1], &allowed, 3, true);
        assert!(r.violation.as_deref().unwrap().contains("shard"));
        // peers without shard info are not penalised
        let p = [RawPeer {
            peer_id: Some("RelayOne".into()),
            multiaddr: "/ip4/172.28.66.10/tcp/60000/p2p/RelayOne".into(),
            connected: true,
            shards: vec![],
        }];
        assert!(evaluate_peers(&p, &allowed, 0, true).violation.is_none());
        // boolean `connected` is not a state of the pinned node
        assert!(parse_peers(
            br#"[{"multiaddr":"/ip4/1.2.3.4/tcp/1/p2p/RelayOne","connected":true}]"#
        )
        .is_err());
    }

    #[test]
    fn peers_parsing_is_strict() {
        let good = |c: &str| {
            format!(r#"[{{"multiaddr":"/ip4/1.2.3.4/tcp/1/p2p/RelayOne","connected":"{c}"}}]"#)
        };
        for c in ["Connected", "NotConnected", "CannotConnect", "CanConnect"] {
            assert!(parse_peers(good(c).as_bytes()).is_ok(), "{c}");
        }
        assert!(parse_peers(b"[]").unwrap().is_empty());
        for bad in [
            "[null]".to_string(),
            "[1]".to_string(),
            r#"[{"multiaddr":"/ip4/1.2.3.4/tcp/1/p2p/RelayOne"}]"#.to_string(),
            r#"[{"multiaddr":"/ip4/1.2.3.4/tcp/1/p2p/RelayOne","connected":null}]"#.to_string(),
            r#"[{"multiaddr":"/ip4/1.2.3.4/tcp/1/p2p/RelayOne","connected":1}]"#.to_string(),
            good("Dialing"),
            good(""),
            r#"[{"connected":"Connected"}]"#.to_string(),
            r#"[{"multiaddr":7,"connected":"Connected"}]"#.to_string(),
        ] {
            assert!(parse_peers(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn store_envelope_is_required() {
        let t = topic();
        for bad in [
            "{}",
            r#"{"error":"boom"}"#,
            r#"{"statusCode":200}"#,
            r#"{"messages":[]}"#,
            r#"{"statusCode":"200","messages":[]}"#,
            r#"{"statusCode":200,"messages":null}"#,
            r#"{"statusCode":400,"statusDesc":"bad","messages":[]}"#,
            "[]",
        ] {
            assert!(
                parse_store_page(bad.as_bytes(), &t, PUBSUB, 10).is_err(),
                "{bad}"
            );
        }
        let (p, _) = parse_store_page(
            br#"{"requestId":"r","statusCode":200,"statusDesc":"OK","messages":[]}"#,
            &t,
            PUBSUB,
            10,
        )
        .unwrap();
        assert!(p.frames.is_empty() && p.next_cursor.is_none());
    }

    fn entry(len: usize, ts: i64) -> String {
        format!(
            r#"{{"payload":"{}","contentTopic":"{CT}","version":0,"timestamp":{ts}}}"#,
            B64.encode(vec![1u8; len])
        )
    }

    #[test]
    fn relay_stream_bounds_memory_and_survives_odd_chunking() {
        let max = 4096;
        let mut items: Vec<String> = (0..20).map(|i| entry(max, i)).collect();
        items.insert(7, entry(max * 50, 99)); // oversized, ~270 KB
        items.insert(9, r#"{"payload":"\"}]","x":"}"}"#.into()); // braces inside strings
        items.insert(10, "17".into()); // bare scalar
        let body = format!(" [ {} ] ", items.join(" , "));
        let t = topic();
        let mut s = RelayStream::new(&t, PUBSUB, max);
        let mut peak = 0;
        for chunk in body.as_bytes().chunks(7) {
            s.feed(chunk);
            peak = peak.max(s.buffered());
        }
        assert!(peak <= max_relay_element_bytes(max), "peak {peak}");
        let r = s.finish();
        assert!(r.error.is_none(), "{:?}", r.error);
        assert_eq!(r.frames.len(), 20);
        assert_eq!(r.counts.malformed, 3);
    }

    #[test]
    fn relay_stream_truncation_keeps_complete_frames() {
        let body = format!("[{},{},{}", entry(10, 1), entry(10, 2), entry(10, 3));
        let t = topic();
        let mut s = RelayStream::new(&t, PUBSUB, 4096);
        s.feed(&body.as_bytes()[..body.len() - 5]);
        let r = s.finish();
        assert_eq!(r.frames.len(), 2);
        assert!(r.error.unwrap().contains("truncated"));
    }

    #[test]
    fn relay_response_bound_covers_a_full_node_cache() {
        // 1000 maximum-size entries, comma-separated, plus brackets, must fit.
        let max = 153_600;
        let one = max_relay_element_bytes(max);
        assert_eq!(one, 204_800 + 1_112);
        assert!(1000 * (entry(max, 1).len() + 1) + 2 <= max_relay_response_bytes(max));
    }
}
