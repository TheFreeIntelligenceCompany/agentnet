//! Shared Waku configuration validation, multiaddr checks, hashing and sizing
//! arithmetic used by both [`crate::logos_rest`] and [`crate::waku_native`].

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

use crate::TransportError;

/// Cluster ids that make a Waku node silently apply a public preset
/// (1 = Waku Network, 2 = logos.test, 3 = logos.dev, 16 = status.prod).
pub const PUBLIC_PRESET_CLUSTER_IDS: [u16; 4] = [1, 2, 3, 16];

/// Largest page a Waku Store v3 server accepts.
pub const MAX_HISTORY_PAGE_SIZE: u32 = 100;

/// Store queries may cover at most 24 hours.
pub const MAX_HISTORY_WINDOW_NS: i64 = 24 * 3600 * 1_000_000_000;

/// Whether the deployment is a closed private cluster or deliberately public.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Fail closed: private literal IPs only, peer allowlist enforced.
    #[default]
    Private,
    /// Explicit public mode: no allowlist enforcement unless
    /// `enforce_peer_allowlist` is set.
    Public,
}

pub(crate) fn de_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Secs(f64),
        Parts { secs: u64, nanos: u32 },
    }
    match Repr::deserialize(d)? {
        Repr::Secs(s) => Duration::try_from_secs_f64(s).map_err(serde::de::Error::custom),
        Repr::Parts { secs, nanos } => {
            let extra = u64::from(nanos / 1_000_000_000);
            let total_secs = secs
                .checked_add(extra)
                .ok_or_else(|| serde::de::Error::custom("duration overflow"))?;
            Ok(Duration::new(total_secs, nanos % 1_000_000_000))
        }
    }
}

/// Is `ip` loopback, RFC 1918 or CGNAT (100.64.0.0/10)?
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
}

/// Is `ip` IPv6 loopback, unique-local (fc00::/7), or an IPv4-mapped private v4?
pub fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(v4);
    }
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

pub(crate) fn valid_peer_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Extracts the last `/p2p/<id>` of a multiaddr.
pub(crate) fn peer_id_of_multiaddr(addr: &str) -> Option<&str> {
    let mut it = addr.split('/');
    let mut last = None;
    while let Some(seg) = it.next() {
        if seg == "p2p" {
            last = it.next();
        }
    }
    last.filter(|s| valid_peer_id(s))
}

pub(crate) fn valid_dns_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// `/.../p2p/<id>` with the peer id as the final segment.
pub(crate) fn static_peer_shape_ok(addr: &str) -> bool {
    addr.len() <= 512
        && addr.starts_with('/')
        && addr.rsplit('/').nth(1) == Some("p2p")
        && peer_id_of_multiaddr(addr).is_some()
}

/// Peer address in private mode: strict allowlist grammar
/// `/(ip4|ip6)/<private-ip>/tcp/<nonzero-port>[/tls][/ws|/wss]/p2p/<allowed-id>`.
/// No DNS, no `/p2p-circuit`, no `/ipfs/` alias, no extra/trailing components.
pub(crate) fn check_peer_addr_private(
    what: &str,
    addr: &str,
    allowed: &[String],
) -> Result<(), TransportError> {
    let iso = |m: &str| TransportError::Isolation(format!("{what} rejected in private mode: {m}"));
    let comps: Vec<&str> = addr.split('/').collect();
    if comps.first() != Some(&"") || addr.len() > 512 {
        return Err(TransportError::Protocol(format!(
            "{what} must be a multiaddr starting with '/'"
        )));
    }
    let mut it = comps.into_iter().skip(1);
    let host_ok = match (it.next(), it.next()) {
        (Some("ip4"), Some(a)) => a.parse::<Ipv4Addr>().map(is_private_ipv4).unwrap_or(false),
        (Some("ip6"), Some(a)) => a.parse::<Ipv6Addr>().map(is_private_ipv6).unwrap_or(false),
        _ => false,
    };
    if !host_ok {
        return Err(iso("address must be a literal private IP"));
    }
    match (it.next(), it.next().map(str::parse::<u16>)) {
        (Some("tcp"), Some(Ok(p))) if p != 0 => {}
        _ => return Err(iso("a /tcp/<port> component must follow the IP")),
    }
    let mut next = it.next();
    if next == Some("tls") {
        next = it.next();
        if next == Some("ws") {
            next = it.next();
        }
    } else if matches!(next, Some("ws" | "wss")) {
        next = it.next();
    }
    if next != Some("p2p") {
        return Err(iso(
            "must be one literal private IP, /tcp/<port> (optional /tls, /ws|/wss) and one /p2p/ peer id",
        ));
    }
    let id = it.next().filter(|i| valid_peer_id(i));
    if id.is_none() || it.next().is_some() {
        return Err(iso("exactly one /p2p/<peerId> must end the address"));
    }
    match id {
        Some(id) if allowed.iter().any(|a| a == id) => Ok(()),
        _ => Err(iso("peer id missing or not in allowed_peer_ids")),
    }
}

/// Peer address in public mode with `enforce_peer_allowlist`: one dialled
/// address `/(ip4|ip6|dns4|dns6)/<host>/tcp/<port>[/tls][/ws|/wss]/p2p/<id>`.
pub(crate) fn check_peer_addr_public_audited(
    what: &str,
    addr: &str,
    allowed: &[String],
) -> Result<(), TransportError> {
    let iso = |m: &str| {
        TransportError::Isolation(format!(
            "{what} rejected (enforce_peer_allowlist): {m}; expected \
             /<ip4|ip6|dns4|dns6>/<host>/tcp/<port>[/tls][/ws|/wss]/p2p/<peerId> \
             (no /p2p-circuit relay hops, no dnsaddr, exactly one /p2p/)"
        ))
    };
    let comps: Vec<&str> = addr.split('/').collect();
    if comps.first() != Some(&"") || addr.len() > 512 {
        return Err(TransportError::Protocol(format!(
            "{what} must be a multiaddr starting with '/'"
        )));
    }
    let mut it = comps.into_iter().skip(1);
    let host_ok = match (it.next(), it.next()) {
        (Some("ip4"), Some(a)) => a.parse::<Ipv4Addr>().is_ok(),
        (Some("ip6"), Some(a)) => a.parse::<Ipv6Addr>().is_ok(),
        (Some("dns4" | "dns6"), Some(n)) => valid_dns_name(n),
        _ => false,
    };
    if !host_ok {
        return Err(iso("bad or unsupported host component"));
    }
    match (it.next(), it.next().map(str::parse::<u16>)) {
        (Some("tcp"), Some(Ok(p))) if p != 0 => {}
        _ => return Err(iso("a /tcp/<port> component must follow the host")),
    }
    let mut next = it.next();
    if next == Some("tls") {
        next = it.next();
        if next == Some("ws") {
            next = it.next();
        }
    } else if matches!(next, Some("ws" | "wss")) {
        next = it.next();
    }
    if next != Some("p2p") {
        return Err(iso("unsupported component between /tcp and /p2p/"));
    }
    let id = it.next().filter(|i| valid_peer_id(i));
    if id.is_none() || it.next().is_some() {
        return Err(iso("exactly one /p2p/<peerId> must end the address"));
    }
    match id {
        Some(id) if allowed.iter().any(|a| a == id) => Ok(()),
        _ => Err(iso("peer id not in allowed_peer_ids")),
    }
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

/// Length of the protobuf varint encoding of `v`.
pub(crate) fn varint_len(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

/// Bytes the node counts that we cannot attribute to a WakuMessage field.
pub(crate) const UNMODELED_RESERVE: usize = 31;
/// Extra slack kept below the measured limit.
pub(crate) const SAFETY_MARGIN: usize = 8;

/// Bytes of an encoded WakuMessage that are not payload.
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

/// Largest payload for which a Waku node is expected to accept a publish on a
/// topic of `topic_len` bytes, given its `--max-msg-size`.
pub(crate) fn max_payload_for(max_message_bytes: usize, topic_len: usize) -> usize {
    let mut p = max_message_bytes.saturating_sub(topic_len);
    while p > 0 && p.saturating_add(framing_overhead(p, topic_len)) > max_message_bytes {
        p -= 1;
    }
    p
}

static LAST_TIMESTAMP_NS: AtomicI64 = AtomicI64::new(0);

/// Wall-clock nanoseconds, strictly increasing within this process.
pub(crate) fn next_timestamp_ns() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .unwrap_or(0);
    let mut last = LAST_TIMESTAMP_NS.load(Ordering::SeqCst);
    loop {
        let next = now.max(last.saturating_add(1));
        match LAST_TIMESTAMP_NS.compare_exchange(last, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(actual) => last = actual,
        }
    }
}
