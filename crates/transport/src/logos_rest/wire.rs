//! Pure wire-level helpers: hashing, size arithmetic, error mapping and
//! response parsing. Nothing here does I/O, so everything is unit-testable.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::config::peer_id_of_multiaddr;
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
    if s.len() != 64 || !s.is_ascii() {
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
    1 + varint_len(payload_len as u64)
        + 1
        + varint_len(topic_len as u64)
        + topic_len
        + (1 + 10)
        + 3
        + UNMODELED_RESERVE
        + SAFETY_MARGIN
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
    while p > 0 && p + framing_overhead(p, topic_len) > max_message_bytes {
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
        Some(s) => B64.decode(s).ok().filter(|v| v.len() <= 64)?,
    };
    Some(Decoded { payload, meta })
}

/// Parses the body of `GET /relay/v1/auto/messages/{topic}`. Malformed entries
/// are skipped and counted. A body that is not a JSON array is a protocol error.
pub(crate) fn parse_relay_messages(
    body: &[u8],
    topic: &ContentTopic,
    pubsub_topic: &str,
    max_bytes: usize,
) -> Result<(Vec<InboundFrame>, ParseCounts), TransportError> {
    let items: Vec<Value> = serde_json::from_slice(body)
        .map_err(|_| TransportError::Protocol("relay poll response is not a JSON array".into()))?;
    let mut counts = ParseCounts::default();
    let mut frames = Vec::with_capacity(items.len());
    for v in items {
        let parsed = serde_json::from_value::<WireMessage>(v)
            .ok()
            .filter(|m| m.content_topic == topic.as_str())
            .and_then(|m| decode_message(&m, max_bytes).map(|d| (m, d)));
        let Some((m, d)) = parsed else {
            counts.malformed += 1;
            continue;
        };
        frames.push(InboundFrame {
            topic: topic.clone(),
            transport_id: waku_message_hash(
                pubsub_topic,
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
    Ok((frames, counts))
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
    status_code: Option<u32>,
    status_desc: Option<String>,
    #[serde(default)]
    messages: Vec<Value>,
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
    if let Some(code) = resp.status_code {
        if code != 200 {
            return Err(StoreParseError::Status(format!(
                "store statusCode {code}: {}",
                snippet(resp.status_desc.unwrap_or_default().as_bytes())
            )));
        }
    }
    let mut counts = ParseCounts::default();
    let mut frames = Vec::with_capacity(resp.messages.len());
    for v in resp.messages {
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
    Ok((
        HistoryPage {
            frames,
            next_cursor: resp.pagination_cursor.filter(|c| !c.is_empty()),
        },
        counts,
    ))
}

/// One entry of `GET /admin/v1/peers`, reduced to what the audit needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawPeer {
    pub peer_id: Option<String>,
    pub connected: bool,
    pub shards: Vec<u16>,
}

/// Parses `GET /admin/v1/peers`. The pinned node reports no separate peer id:
/// it is the last `/p2p/` segment of `multiaddr`. `connected` is the string
/// `"Connected"` for live connections.
pub(crate) fn parse_peers(body: &[u8]) -> Result<Vec<RawPeer>, String> {
    let items: Vec<Value> =
        serde_json::from_slice(body).map_err(|_| "admin peers response is not a JSON array")?;
    let mut out = Vec::with_capacity(items.len());
    for v in items {
        let connected = match v.get("connected") {
            Some(Value::String(s)) => s.eq_ignore_ascii_case("connected"),
            Some(Value::Bool(b)) => *b,
            _ => false,
        };
        let peer_id = v
            .get("peerId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                v.get("multiaddr")
                    .and_then(Value::as_str)
                    .and_then(peer_id_of_multiaddr)
                    .map(str::to_string)
            });
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
            connected,
            shards,
        });
    }
    Ok(out)
}

/// Result of evaluating a peer list against the allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuditReport {
    pub peers: Vec<PeerInfo>,
    pub violation: Option<String>,
}

/// Private-mode audit: any connected peer outside `allowed` is a violation, as
/// is a connected peer whose id cannot be determined, and a connected allowed
/// peer that advertises shards but not `shard`.
pub(crate) fn evaluate_peers(raw: &[RawPeer], allowed: &[String], shard: u16) -> AuditReport {
    let mut peers = Vec::new();
    let mut foreign = Vec::new();
    let mut unknown = 0usize;
    let mut wrong_shard = 0usize;
    for p in raw {
        match &p.peer_id {
            Some(id) => {
                let ok = allowed.iter().any(|a| a == id);
                if p.connected && !ok {
                    foreign.push(id.chars().take(64).collect::<String>());
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
        let r = evaluate_peers(&raw, &allowed, 0);
        assert!(r.violation.as_deref().unwrap().contains("unidentifiable"));
        // a merely known-but-disconnected stranger is not a violation
        let r = evaluate_peers(&raw[..2], &allowed, 0);
        assert!(r.violation.is_none(), "{:?}", r.violation);
        assert_eq!(r.peers.len(), 2);
        assert!(r.peers[0].allowed && r.peers[0].connected);
        assert!(!r.peers[1].allowed && !r.peers[1].connected);
        // wrong allowlist => the connected relay is foreign
        let r = evaluate_peers(&raw[..1], &["Other".to_string()], 0);
        assert!(r.violation.as_deref().unwrap().contains("RelayOne"));
        // shard mismatch
        let r = evaluate_peers(&raw[..1], &allowed, 3);
        assert!(r.violation.as_deref().unwrap().contains("shard"));
        // peers without shard info are not penalised
        let p = [RawPeer {
            peer_id: Some("RelayOne".into()),
            connected: true,
            shards: vec![],
        }];
        assert!(evaluate_peers(&p, &allowed, 0).violation.is_none());
        // boolean `connected` and explicit peerId are tolerated
        let raw = parse_peers(br#"[{"peerId":"RelayOne","connected":true}]"#).unwrap();
        assert!(raw[0].connected && raw[0].peer_id.as_deref() == Some("RelayOne"));
    }
}
