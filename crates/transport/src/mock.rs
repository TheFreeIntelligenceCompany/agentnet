//! Deterministic in-memory transport for tests of higher layers.
//!
//! A [`MockNetwork`] is a shared hub; every [`MockTransport`] created from it
//! is one "node" (one agent's local Logos Delivery node). Everything is
//! controllable from tests and nothing sleeps or touches the network:
//!
//! * time comes from a manual [`MockClock`];
//! * randomness (reordering) comes from a seeded SplitMix64 generator;
//! * `transport_id` is `SHA-256(topic, payload, timestamp)`, so a frame has the
//!   same id live and in history.
//!
//! The mock mirrors the measured behaviour of the real node where that matters
//! for higher layers: the publisher receives its own frames, the live queue is
//! bounded and drops the oldest frame silently when it overflows, and a frame
//! published while a node is offline is not queued live for it but is in
//! history.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::{
    ContentTopic, FrameSource, HistoryPage, HistoryQuery, InboundFrame, PeerInfo, PublishReceipt,
    Transport, TransportError, TransportStatus,
};

/// Default live queue capacity per endpoint (the real node's REST cache holds 50).
pub const DEFAULT_LIVE_CAPACITY: usize = 50;
/// Default maximum payload accepted by the mock.
pub const DEFAULT_MAX_PAYLOAD: usize = 150_000;
/// Default maximum history window (24 h, like the real Store).
pub const DEFAULT_MAX_HISTORY_WINDOW_NS: i64 = 24 * 3600 * 1_000_000_000;
/// Largest history page the mock returns (like the real Store).
pub const MAX_HISTORY_PAGE: u32 = 100;
/// Default clock start: 2023-11-14T22:13:20Z in nanoseconds.
pub const DEFAULT_CLOCK_START_NS: i64 = 1_700_000_000_000_000_000;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The transport id the mock assigns: SHA-256 over length-prefixed topic,
/// payload and the big-endian timestamp.
pub fn mock_transport_id(topic: &ContentTopic, payload: &[u8], timestamp_ns: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((topic.as_str().len() as u64).to_be_bytes());
    h.update(topic.as_str().as_bytes());
    h.update((payload.len() as u64).to_be_bytes());
    h.update(payload);
    h.update(timestamp_ns.to_be_bytes());
    h.finalize().into()
}

/// A manually advanced clock (nanoseconds since the Unix epoch). Cloning shares
/// the same time source.
#[derive(Clone, Debug)]
pub struct MockClock(Arc<AtomicI64>);

impl Default for MockClock {
    fn default() -> Self {
        Self::new(DEFAULT_CLOCK_START_NS)
    }
}

impl MockClock {
    /// Creates a clock reading `start_ns`.
    pub fn new(start_ns: i64) -> Self {
        Self(Arc::new(AtomicI64::new(start_ns)))
    }
    /// Current time in nanoseconds.
    pub fn now_ns(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
    /// Sets the absolute time.
    pub fn set_ns(&self, ns: i64) {
        self.0.store(ns, Ordering::SeqCst);
    }
    /// Advances the clock by `d` (saturating).
    pub fn advance(&self, d: Duration) {
        self.advance_ns(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
    }
    /// Advances the clock by `ns` nanoseconds (saturating).
    pub fn advance_ns(&self, ns: i64) {
        let _ = self
            .0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(ns))
            });
    }
}

/// Seeded SplitMix64: tiny, deterministic, no external dependency.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn shuffle<T>(items: &mut [T], state: &mut u64) {
    for i in (1..items.len()).rev() {
        let j = (splitmix64(state) % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

/// A frame as published into the network, for assertions and replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedFrame {
    /// Content topic.
    pub topic: ContentTopic,
    /// Payload bytes exactly as handed to the transport.
    pub payload: Vec<u8>,
    /// Timestamp assigned by the mock (strictly increasing per network).
    pub timestamp_ns: i64,
    /// Transport id.
    pub transport_id: [u8; 32],
    /// Index of the publishing endpoint; `None` for [`MockNetwork::inject_raw`].
    pub publisher: Option<usize>,
    /// True when the publish was accepted but silently dropped (fault injection).
    pub lost: bool,
}

#[derive(Clone)]
struct StoredFrame {
    topic: ContentTopic,
    payload: Vec<u8>,
    timestamp_ns: i64,
    id: [u8; 32],
}

struct Endpoint {
    online: bool,
    /// Topics the caller subscribed to through the trait (survives restarts).
    wanted: HashSet<ContentTopic>,
    /// Topics the simulated node currently has subscriptions for.
    active: HashSet<ContentTopic>,
    queue: VecDeque<InboundFrame>,
    held: Vec<InboundFrame>,
    capacity: usize,
    dropped: u64,
    resubscribes: u64,
    drop_next: u32,
    fail_next: u32,
    duplicate: u32,
    reorder_state: Option<u64>,
    delay: bool,
    isolation: Option<String>,
    peers: Vec<PeerInfo>,
}

impl Endpoint {
    fn new() -> Self {
        Self {
            online: true,
            wanted: HashSet::new(),
            active: HashSet::new(),
            queue: VecDeque::new(),
            held: Vec::new(),
            capacity: DEFAULT_LIVE_CAPACITY,
            dropped: 0,
            resubscribes: 0,
            drop_next: 0,
            fail_next: 0,
            duplicate: 1,
            reorder_state: None,
            delay: false,
            isolation: None,
            peers: vec![PeerInfo {
                peer_id: "mock-relay".to_string(),
                connected: true,
                allowed: true,
            }],
        }
    }

    fn enqueue(&mut self, f: InboundFrame) {
        self.queue.push_back(f);
        self.trim();
    }

    fn trim(&mut self) {
        while self.queue.len() > self.capacity {
            self.queue.pop_front();
            self.dropped += 1;
        }
    }
}

struct Inner {
    endpoints: Vec<Endpoint>,
    history: Vec<StoredFrame>,
    history_available: bool,
    retention_ns: Option<i64>,
    history_capacity: Option<usize>,
    published: Vec<PublishedFrame>,
    counts: HashMap<String, u64>,
    last_ts: i64,
    max_payload: usize,
    max_window_ns: i64,
}

impl Inner {
    fn prune_history(&mut self, now: i64) {
        if let Some(r) = self.retention_ns {
            let cutoff = now.saturating_sub(r);
            self.history.retain(|f| f.timestamp_ns >= cutoff);
        }
        if let Some(cap) = self.history_capacity {
            if self.history.len() > cap {
                let excess = self.history.len() - cap;
                self.history.drain(..excess);
            }
        }
    }

    /// Records the frame in history and delivers it to every online endpoint
    /// that has an active subscription for the topic.
    fn deliver(&mut self, now: i64, f: &StoredFrame) {
        self.history.push(f.clone());
        self.prune_history(now);
        for ep in &mut self.endpoints {
            if !ep.online || !ep.active.contains(&f.topic) {
                continue;
            }
            for _ in 0..ep.duplicate.max(1) {
                let frame = InboundFrame {
                    topic: f.topic.clone(),
                    payload: f.payload.clone(),
                    timestamp_ns: f.timestamp_ns,
                    transport_id: f.id,
                    source: FrameSource::Live,
                };
                if ep.delay {
                    ep.held.push(frame);
                } else {
                    ep.enqueue(frame);
                }
            }
        }
    }

    fn next_ts(&mut self, now: i64) -> i64 {
        let ts = now.max(self.last_ts.saturating_add(1));
        self.last_ts = ts;
        ts
    }
}

/// The shared hub. Create with [`MockNetwork::new`], then call
/// [`MockNetwork::endpoint`] once per simulated node.
pub struct MockNetwork {
    inner: Mutex<Inner>,
    clock: MockClock,
}

impl MockNetwork {
    /// New network with a fresh [`MockClock`].
    pub fn new() -> Arc<Self> {
        Self::with_clock(MockClock::default())
    }

    /// New network driven by `clock`.
    pub fn with_clock(clock: MockClock) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                endpoints: Vec::new(),
                history: Vec::new(),
                history_available: true,
                retention_ns: None,
                history_capacity: None,
                published: Vec::new(),
                counts: HashMap::new(),
                last_ts: i64::MIN,
                max_payload: DEFAULT_MAX_PAYLOAD,
                max_window_ns: DEFAULT_MAX_HISTORY_WINDOW_NS,
            }),
            clock,
        })
    }

    /// Creates a new endpoint (node) attached to this network.
    pub fn endpoint(self: &Arc<Self>) -> MockTransport {
        let mut g = lock(&self.inner);
        g.endpoints.push(Endpoint::new());
        MockTransport {
            net: Arc::clone(self),
            id: g.endpoints.len() - 1,
        }
    }

    /// The clock shared by all endpoints.
    pub fn clock(&self) -> &MockClock {
        &self.clock
    }

    /// Sets the largest accepted payload (larger publishes get `TooLarge`).
    pub fn set_max_payload_len(&self, n: usize) {
        lock(&self.inner).max_payload = n;
    }

    /// Sets the largest history window.
    pub fn set_max_history_window_ns(&self, ns: i64) {
        lock(&self.inner).max_window_ns = ns;
    }

    /// Switches the history service on or off. While off, every `history` call
    /// returns `HistoryUnavailable`.
    pub fn set_history_available(&self, available: bool) {
        lock(&self.inner).history_available = available;
    }

    /// Time-based retention: frames older than `retention` (by timestamp,
    /// relative to the mock clock) are dropped on the next insert or query.
    pub fn set_history_retention(&self, retention: Option<Duration>) {
        let mut g = lock(&self.inner);
        g.retention_ns = retention.map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX));
        let now = self.clock.now_ns();
        g.prune_history(now);
    }

    /// Capacity-based retention: at most `cap` frames are kept (oldest dropped).
    pub fn set_history_capacity(&self, cap: Option<usize>) {
        let mut g = lock(&self.inner);
        g.history_capacity = cap;
        let now = self.clock.now_ns();
        g.prune_history(now);
    }

    /// Removes every history frame with a timestamp strictly before `ts_ns`.
    pub fn expire_before(&self, ts_ns: i64) {
        lock(&self.inner)
            .history
            .retain(|f| f.timestamp_ns >= ts_ns);
    }

    /// Number of frames currently held in history.
    pub fn history_len(&self) -> usize {
        lock(&self.inner).history.len()
    }

    /// Every frame ever published (including lost and injected ones), in order.
    pub fn published_frames(&self) -> Vec<PublishedFrame> {
        lock(&self.inner).published.clone()
    }

    /// Accepted publishes (including accepted-but-lost and injected) per topic.
    pub fn publish_count(&self, topic: &ContentTopic) -> u64 {
        lock(&self.inner)
            .counts
            .get(topic.as_str())
            .copied()
            .unwrap_or(0)
    }

    /// Accepted publishes across all topics.
    pub fn total_publish_count(&self) -> u64 {
        lock(&self.inner).counts.values().sum()
    }

    /// Injects a frame as if a third party published it (for replaying or
    /// tampering with a captured frame). No publish fault knob applies; the
    /// frame is stored in history and delivered live under each endpoint's
    /// delivery knobs.
    pub fn inject_raw(&self, topic: &ContentTopic, payload: &[u8]) -> PublishReceipt {
        let now = self.clock.now_ns();
        let mut g = lock(&self.inner);
        let ts = g.next_ts(now);
        let id = mock_transport_id(topic, payload, ts);
        *g.counts.entry(topic.as_str().to_string()).or_insert(0) += 1;
        g.published.push(PublishedFrame {
            topic: topic.clone(),
            payload: payload.to_vec(),
            timestamp_ns: ts,
            transport_id: id,
            publisher: None,
            lost: false,
        });
        let f = StoredFrame {
            topic: topic.clone(),
            payload: payload.to_vec(),
            timestamp_ns: ts,
            id,
        };
        g.deliver(now, &f);
        PublishReceipt {
            transport_id: id,
            timestamp_ns: ts,
        }
    }
}

/// One simulated node. Implements [`Transport`]; the knobs below inject faults.
#[derive(Clone)]
pub struct MockTransport {
    net: Arc<MockNetwork>,
    id: usize,
}

impl MockTransport {
    fn with_ep<R>(&self, f: impl FnOnce(&mut Endpoint) -> R) -> R {
        let mut g = lock(&self.net.inner);
        f(&mut g.endpoints[self.id])
    }

    /// The network this endpoint belongs to.
    pub fn network(&self) -> &Arc<MockNetwork> {
        &self.net
    }

    /// Index of this endpoint (matches [`PublishedFrame::publisher`]).
    pub fn index(&self) -> usize {
        self.id
    }

    /// Takes the node offline or brings it back. While offline, `publish`,
    /// `subscribe` and `poll` return `Unavailable`, `history` returns
    /// `HistoryUnavailable`, and frames published by others are not queued live
    /// (they are still in history).
    pub fn set_online(&self, online: bool) {
        self.with_ep(|e| e.online = online);
    }

    /// Sets the live queue capacity (shared across topics); trims immediately.
    pub fn set_live_capacity(&self, cap: usize) {
        self.with_ep(|e| {
            e.capacity = cap;
            e.trim();
        });
    }

    /// Frames silently dropped from the live queue because of overflow.
    pub fn dropped_count(&self) -> u64 {
        self.with_ep(|e| e.dropped)
    }

    /// The next `n` publishes are accepted (returning `Ok`) but lost: never
    /// delivered and never stored.
    pub fn drop_next_publishes(&self, n: u32) {
        self.with_ep(|e| e.drop_next = n);
    }

    /// The next `n` publishes fail with `Unavailable` and have no effect.
    pub fn fail_next_publishes(&self, n: u32) {
        self.with_ep(|e| e.fail_next = n);
    }

    /// Deliver every frame `k` times to this endpoint (`k = 1` is normal;
    /// `0` is treated as `1`).
    pub fn set_duplicate_delivery(&self, k: u32) {
        self.with_ep(|e| e.duplicate = k.max(1));
    }

    /// With `Some(seed)`, each `poll` returns its frames in a deterministic
    /// pseudo-random order derived from the seed. `None` restores arrival order.
    pub fn set_reorder_seed(&self, seed: Option<u64>) {
        self.with_ep(|e| e.reorder_state = seed);
    }

    /// While on, newly delivered frames are held back until [`release`](Self::release).
    pub fn set_delay_delivery(&self, on: bool) {
        self.with_ep(|e| e.delay = on);
    }

    /// Moves held frames into the live queue (and turns delaying off).
    pub fn release(&self) {
        self.with_ep(|e| {
            e.delay = false;
            let held = std::mem::take(&mut e.held);
            for f in held {
                e.enqueue(f);
            }
        });
    }

    /// Number of frames currently held back by the delay knob.
    pub fn held_len(&self) -> usize {
        self.with_ep(|e| e.held.len())
    }

    /// Number of frames currently waiting in the live queue (all topics).
    pub fn queued_len(&self) -> usize {
        self.with_ep(|e| e.queue.len())
    }

    /// Sets or clears the isolation violation. While set, `publish`, `poll`,
    /// `subscribe` and `history` return `Isolation` and `status` reports it.
    pub fn set_isolation_violation(&self, reason: Option<&str>) {
        self.with_ep(|e| e.isolation = reason.map(str::to_string));
    }

    /// Replaces the peer list reported by `status`.
    pub fn set_peers(&self, peers: Vec<PeerInfo>) {
        self.with_ep(|e| e.peers = peers);
    }

    /// Simulates a node restart: live subscriptions and the live queue are lost.
    /// The next `poll` of a subscribed topic re-subscribes transparently and
    /// returns empty (like the real adapter) and bumps
    /// [`resubscribe_count`](Self::resubscribe_count).
    pub fn simulate_node_restart(&self) {
        self.with_ep(|e| {
            e.active.clear();
            e.queue.clear();
            e.held.clear();
        });
    }

    /// Every topic this endpoint ever subscribed to through the trait (sorted),
    /// for asserting that a node subscribes to nothing it should not.
    pub fn subscribed_topics(&self) -> Vec<ContentTopic> {
        let mut v: Vec<ContentTopic> = self.with_ep(|e| e.wanted.iter().cloned().collect());
        v.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        v
    }

    /// Number of transparent re-subscriptions performed after restarts.
    pub fn resubscribe_count(&self) -> u64 {
        self.with_ep(|e| e.resubscribes)
    }

    fn check_isolation(&self) -> Result<(), TransportError> {
        match self.with_ep(|e| e.isolation.clone()) {
            Some(r) => Err(TransportError::Isolation(r)),
            None => Ok(()),
        }
    }
}

fn parse_cursor(c: &str) -> Option<(i64, [u8; 32])> {
    let (ts, id) = c.split_once(':')?;
    let ts: i64 = ts.parse().ok()?;
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(id.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some((ts, out))
}

#[async_trait]
impl Transport for MockTransport {
    async fn subscribe(&self, topic: &ContentTopic) -> Result<(), TransportError> {
        self.check_isolation()?;
        self.with_ep(|e| {
            if !e.online {
                return Err(TransportError::Unavailable("mock node offline".into()));
            }
            e.wanted.insert(topic.clone());
            e.active.insert(topic.clone());
            Ok(())
        })
    }

    async fn publish(
        &self,
        topic: &ContentTopic,
        payload: &[u8],
    ) -> Result<PublishReceipt, TransportError> {
        self.check_isolation()?;
        let now = self.net.clock.now_ns();
        let mut g = lock(&self.net.inner);
        let max = g.max_payload;
        if payload.len() > max {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                max,
            });
        }
        {
            let ep = &mut g.endpoints[self.id];
            if !ep.online {
                return Err(TransportError::Unavailable("mock node offline".into()));
            }
            if ep.fail_next > 0 {
                ep.fail_next -= 1;
                return Err(TransportError::Unavailable(
                    "injected publish failure".into(),
                ));
            }
        }
        let ts = g.next_ts(now);
        let id = mock_transport_id(topic, payload, ts);
        *g.counts.entry(topic.as_str().to_string()).or_insert(0) += 1;
        let lost = {
            let ep = &mut g.endpoints[self.id];
            if ep.drop_next > 0 {
                ep.drop_next -= 1;
                true
            } else {
                false
            }
        };
        g.published.push(PublishedFrame {
            topic: topic.clone(),
            payload: payload.to_vec(),
            timestamp_ns: ts,
            transport_id: id,
            publisher: Some(self.id),
            lost,
        });
        if !lost {
            let f = StoredFrame {
                topic: topic.clone(),
                payload: payload.to_vec(),
                timestamp_ns: ts,
                id,
            };
            g.deliver(now, &f);
        }
        Ok(PublishReceipt {
            transport_id: id,
            timestamp_ns: ts,
        })
    }

    async fn poll(&self, topic: &ContentTopic) -> Result<Vec<InboundFrame>, TransportError> {
        self.check_isolation()?;
        self.with_ep(|e| {
            if !e.online {
                return Err(TransportError::Unavailable("mock node offline".into()));
            }
            if e.wanted.contains(topic) && !e.active.contains(topic) {
                e.active.insert(topic.clone());
                e.resubscribes += 1;
                return Ok(Vec::new());
            }
            if !e.active.contains(topic) {
                return Ok(Vec::new());
            }
            let mut out = Vec::new();
            let mut rest = VecDeque::with_capacity(e.queue.len());
            for f in e.queue.drain(..) {
                if &f.topic == topic {
                    out.push(f);
                } else {
                    rest.push_back(f);
                }
            }
            e.queue = rest;
            if let Some(mut st) = e.reorder_state {
                shuffle(&mut out, &mut st);
                e.reorder_state = Some(st);
            }
            Ok(out)
        })
    }

    async fn history(&self, query: &HistoryQuery) -> Result<HistoryPage, TransportError> {
        let now = self.net.clock.now_ns();
        let max_window = lock(&self.net.inner).max_window_ns;
        if query.end_ns < query.start_ns {
            return Err(TransportError::Protocol("end before start".into()));
        }
        if query.end_ns.saturating_sub(query.start_ns) > max_window {
            return Err(TransportError::Protocol(
                "history window exceeds maximum".into(),
            ));
        }
        if query.limit == 0 {
            return Err(TransportError::Protocol("limit must be positive".into()));
        }
        let cursor = match &query.cursor {
            Some(c) => {
                Some(parse_cursor(c).ok_or_else(|| TransportError::Protocol("bad cursor".into()))?)
            }
            None => None,
        };
        self.check_isolation()?;
        let mut g = lock(&self.net.inner);
        if !g.endpoints[self.id].online {
            return Err(TransportError::HistoryUnavailable(
                "mock node offline".into(),
            ));
        }
        if !g.history_available {
            return Err(TransportError::HistoryUnavailable(
                "mock history disabled".into(),
            ));
        }
        g.prune_history(now);
        let limit = query.limit.min(MAX_HISTORY_PAGE) as usize;
        let mut matching = g.history.iter().filter(|f| {
            f.topic == query.topic
                && f.timestamp_ns >= query.start_ns
                && f.timestamp_ns <= query.end_ns
                && match &cursor {
                    Some((cts, cid)) => (f.timestamp_ns, f.id) > (*cts, *cid),
                    None => true,
                }
        });
        let frames: Vec<InboundFrame> = matching
            .by_ref()
            .take(limit)
            .map(|f| InboundFrame {
                topic: f.topic.clone(),
                payload: f.payload.clone(),
                timestamp_ns: f.timestamp_ns,
                transport_id: f.id,
                source: FrameSource::History,
            })
            .collect();
        let more = matching.next().is_some();
        let next_cursor = match (more, frames.last()) {
            (true, Some(l)) => Some(format!("{}:{}", l.timestamp_ns, hex(&l.transport_id))),
            _ => None,
        };
        Ok(HistoryPage {
            frames,
            next_cursor,
        })
    }

    async fn status(&self) -> TransportStatus {
        let ep = self.with_ep(|e| (e.online, e.isolation.clone(), e.peers.clone()));
        let (online, isolation, peers) = ep;
        TransportStatus {
            ready: online && isolation.is_none(),
            peers,
            isolation_violation: isolation,
            detail: if online {
                "mock node online".to_string()
            } else {
                "mock node offline".to_string()
            },
        }
    }

    fn max_payload_len(&self, _topic: &ContentTopic) -> usize {
        lock(&self.net.inner).max_payload
    }

    fn max_history_window_ns(&self) -> i64 {
        lock(&self.net.inner).max_window_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Start of every test history window (just before the default clock).
    const START: i64 = DEFAULT_CLOCK_START_NS - 1;

    fn topic(n: &str) -> ContentTopic {
        ContentTopic::new(format!("/agentnet/1/{n}/proto")).unwrap()
    }

    fn q(
        t: &ContentTopic,
        start: i64,
        end: i64,
        cursor: Option<String>,
        limit: u32,
    ) -> HistoryQuery {
        HistoryQuery {
            topic: t.clone(),
            start_ns: start,
            end_ns: end,
            cursor,
            limit,
        }
    }

    async fn pair() -> (Arc<MockNetwork>, MockTransport, MockTransport, ContentTopic) {
        let net = MockNetwork::new();
        let a = net.endpoint();
        let b = net.endpoint();
        let t = topic("x");
        a.subscribe(&t).await.unwrap();
        b.subscribe(&t).await.unwrap();
        (net, a, b, t)
    }

    #[tokio::test]
    async fn publish_delivers_to_all_including_publisher() {
        let (_net, a, b, t) = pair().await;
        let r = a.publish(&t, b"hi").await.unwrap();
        let fa = a.poll(&t).await.unwrap();
        let fb = b.poll(&t).await.unwrap();
        assert_eq!(fa.len(), 1);
        assert_eq!(fb.len(), 1);
        assert_eq!(fa[0].transport_id, r.transport_id);
        assert_eq!(fb[0].transport_id, r.transport_id);
        assert_eq!(fb[0].payload, b"hi");
        assert_eq!(fb[0].source, FrameSource::Live);
        assert!(b.poll(&t).await.unwrap().is_empty(), "poll drains");
    }

    #[tokio::test]
    async fn unsubscribed_endpoint_gets_nothing_live_but_history_has_it() {
        let net = MockNetwork::new();
        let a = net.endpoint();
        let b = net.endpoint();
        let t = topic("x");
        a.subscribe(&t).await.unwrap();
        a.publish(&t, b"m").await.unwrap();
        assert!(b.poll(&t).await.unwrap().is_empty());
        let now = net.clock().now_ns();
        let p = b.history(&q(&t, START, now + 10, None, 10)).await.unwrap();
        assert_eq!(p.frames.len(), 1);
    }

    #[tokio::test]
    async fn topics_are_separated_in_poll() {
        let net = MockNetwork::new();
        let a = net.endpoint();
        let (t1, t2) = (topic("one"), topic("two"));
        a.subscribe(&t1).await.unwrap();
        a.subscribe(&t2).await.unwrap();
        a.publish(&t1, b"1").await.unwrap();
        a.publish(&t2, b"2").await.unwrap();
        assert_eq!(a.poll(&t1).await.unwrap()[0].payload, b"1");
        assert_eq!(a.poll(&t2).await.unwrap()[0].payload, b"2");
    }

    #[tokio::test]
    async fn transport_id_is_deterministic_and_matches_history() {
        let (net, a, _b, t) = pair().await;
        let r = a.publish(&t, b"payload").await.unwrap();
        assert_eq!(
            r.transport_id,
            mock_transport_id(&t, b"payload", r.timestamp_ns)
        );
        let live = a.poll(&t).await.unwrap().remove(0);
        let h = a
            .history(&q(&t, START, net.clock().now_ns() + 1, None, 10))
            .await
            .unwrap()
            .frames
            .remove(0);
        assert_eq!(live.transport_id, h.transport_id);
        assert_eq!(h.source, FrameSource::History);
        assert_eq!(live.timestamp_ns, h.timestamp_ns);
    }

    #[tokio::test]
    async fn timestamps_strictly_increase_even_with_frozen_clock() {
        let (_net, a, _b, t) = pair().await;
        let r1 = a.publish(&t, b"same").await.unwrap();
        let r2 = a.publish(&t, b"same").await.unwrap();
        assert!(r2.timestamp_ns > r1.timestamp_ns);
        assert_ne!(r1.transport_id, r2.transport_id);
    }

    #[tokio::test]
    async fn clock_is_manual() {
        let c = MockClock::new(100);
        assert_eq!(c.now_ns(), 100);
        c.advance(Duration::from_nanos(50));
        assert_eq!(c.now_ns(), 150);
        c.advance_ns(-10);
        assert_eq!(c.now_ns(), 140);
        c.set_ns(5);
        assert_eq!(c.now_ns(), 5);
        let c2 = c.clone();
        c2.advance_ns(1);
        assert_eq!(c.now_ns(), 6, "clones share time");
        c.set_ns(i64::MAX - 1);
        c.advance(Duration::from_secs(10));
        assert_eq!(c.now_ns(), i64::MAX, "saturates");

        let clock = MockClock::new(1_000);
        let net = MockNetwork::with_clock(clock.clone());
        let a = net.endpoint();
        let t = topic("x");
        a.subscribe(&t).await.unwrap();
        clock.advance_ns(500);
        assert_eq!(a.publish(&t, b"x").await.unwrap().timestamp_ns, 1_500);
    }

    #[tokio::test]
    async fn live_queue_overflow_drops_oldest_and_counts() {
        let (_net, a, b, t) = pair().await;
        b.set_live_capacity(3);
        for i in 0..5u8 {
            a.publish(&t, &[i]).await.unwrap();
        }
        let got = b.poll(&t).await.unwrap();
        let payloads: Vec<u8> = got.iter().map(|f| f.payload[0]).collect();
        assert_eq!(payloads, vec![2, 3, 4]);
        assert_eq!(b.dropped_count(), 2);
        assert_eq!(a.dropped_count(), 0);
        // shrinking the capacity trims immediately
        for i in 0..3u8 {
            a.publish(&t, &[i]).await.unwrap();
        }
        b.set_live_capacity(1);
        assert_eq!(b.dropped_count(), 4);
        assert_eq!(b.queued_len(), 1);
    }

    #[tokio::test]
    async fn history_retention_by_time() {
        let (net, a, _b, t) = pair().await;
        net.set_history_retention(Some(Duration::from_secs(60)));
        a.publish(&t, b"old").await.unwrap();
        net.clock().advance(Duration::from_secs(30));
        a.publish(&t, b"mid").await.unwrap();
        net.clock().advance(Duration::from_secs(40));
        // "old" is now 70 s old, "mid" 40 s
        let now = net.clock().now_ns();
        let p = a.history(&q(&t, START, now, None, 10)).await.unwrap();
        let ps: Vec<&[u8]> = p.frames.iter().map(|f| f.payload.as_slice()).collect();
        assert_eq!(ps, vec![b"mid".as_slice()]);
        assert_eq!(net.history_len(), 1);
    }

    #[tokio::test]
    async fn history_retention_by_capacity() {
        let (net, a, _b, t) = pair().await;
        net.set_history_capacity(Some(2));
        for i in 0..4u8 {
            a.publish(&t, &[i]).await.unwrap();
        }
        assert_eq!(net.history_len(), 2);
        let now = net.clock().now_ns() + 10;
        let p = a.history(&q(&t, START, now, None, 10)).await.unwrap();
        let ps: Vec<u8> = p.frames.iter().map(|f| f.payload[0]).collect();
        assert_eq!(ps, vec![2, 3]);
        net.set_history_capacity(Some(1));
        assert_eq!(net.history_len(), 1);
    }

    #[tokio::test]
    async fn expire_before_removes_old_frames() {
        let (net, a, _b, t) = pair().await;
        let r1 = a.publish(&t, b"1").await.unwrap();
        net.clock().advance(Duration::from_secs(1));
        let r2 = a.publish(&t, b"2").await.unwrap();
        net.expire_before(r2.timestamp_ns);
        assert!(r1.timestamp_ns < r2.timestamp_ns);
        assert_eq!(net.history_len(), 1);
        let p = a
            .history(&q(&t, START, net.clock().now_ns() + 1, None, 10))
            .await
            .unwrap();
        assert_eq!(p.frames[0].transport_id, r2.transport_id);
    }

    #[tokio::test]
    async fn history_availability_switch() {
        let (net, a, _b, t) = pair().await;
        net.set_history_available(false);
        let e = a.history(&q(&t, 0, 10, None, 10)).await.unwrap_err();
        assert!(matches!(e, TransportError::HistoryUnavailable(_)));
        net.set_history_available(true);
        assert!(a.history(&q(&t, 0, 10, None, 10)).await.is_ok());
    }

    #[tokio::test]
    async fn history_pagination_and_window() {
        let (net, a, _b, t) = pair().await;
        for i in 0..7u8 {
            a.publish(&t, &[i]).await.unwrap();
        }
        let end = net.clock().now_ns() + 100;
        let mut cursor = None;
        let mut seen = Vec::new();
        let mut pages = 0;
        loop {
            let p = a.history(&q(&t, START, end, cursor, 3)).await.unwrap();
            pages += 1;
            seen.extend(p.frames.iter().map(|f| f.payload[0]));
            cursor = p.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(pages, 3);
        assert_eq!(seen, vec![0, 1, 2, 3, 4, 5, 6]);
        // exact page boundary yields no dangling cursor
        let p = a.history(&q(&t, START, end, None, 7)).await.unwrap();
        assert!(p.next_cursor.is_none());
        // window too large, inverted, bad cursor, zero limit
        let w = a.max_history_window_ns();
        assert!(matches!(
            a.history(&q(&t, 0, w + 1, None, 3)).await,
            Err(TransportError::Protocol(_))
        ));
        assert!(matches!(
            a.history(&q(&t, 5, 4, None, 3)).await,
            Err(TransportError::Protocol(_))
        ));
        assert!(matches!(
            a.history(&q(&t, 0, 4, Some("garbage".into()), 3)).await,
            Err(TransportError::Protocol(_))
        ));
        assert!(matches!(
            a.history(&q(&t, 0, 4, None, 0)).await,
            Err(TransportError::Protocol(_))
        ));
        net.set_max_history_window_ns(10);
        assert_eq!(a.max_history_window_ns(), 10);
        assert!(a.history(&q(&t, 0, 11, None, 3)).await.is_err());
    }

    #[tokio::test]
    async fn offline_endpoint_misses_live_but_has_history() {
        let (net, a, b, t) = pair().await;
        b.set_online(false);
        assert!(matches!(
            b.publish(&t, b"x").await,
            Err(TransportError::Unavailable(_))
        ));
        assert!(matches!(
            b.poll(&t).await,
            Err(TransportError::Unavailable(_))
        ));
        assert!(matches!(
            b.subscribe(&t).await,
            Err(TransportError::Unavailable(_))
        ));
        assert!(matches!(
            b.history(&q(&t, 0, 1, None, 1)).await,
            Err(TransportError::HistoryUnavailable(_))
        ));
        assert!(!b.status().await.ready);
        a.publish(&t, b"while-offline").await.unwrap();
        b.set_online(true);
        assert!(b.poll(&t).await.unwrap().is_empty());
        let p = b
            .history(&q(&t, START, net.clock().now_ns() + 1, None, 10))
            .await
            .unwrap();
        assert_eq!(p.frames.len(), 1);
        assert!(b.status().await.ready);
    }

    #[tokio::test]
    async fn drop_next_publishes_is_accepted_but_lost() {
        let (net, a, b, t) = pair().await;
        a.drop_next_publishes(2);
        a.publish(&t, b"1").await.unwrap();
        a.publish(&t, b"2").await.unwrap();
        a.publish(&t, b"3").await.unwrap();
        let got = b.poll(&t).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload, b"3");
        assert_eq!(net.history_len(), 1, "lost frames are not stored");
        let pf = net.published_frames();
        assert_eq!(pf.len(), 3);
        assert!(pf[0].lost && pf[1].lost && !pf[2].lost);
        assert_eq!(net.publish_count(&t), 3);
    }

    #[tokio::test]
    async fn fail_next_publishes_returns_unavailable_without_effect() {
        let (net, a, b, t) = pair().await;
        a.fail_next_publishes(2);
        for _ in 0..2 {
            assert!(matches!(
                a.publish(&t, b"x").await,
                Err(TransportError::Unavailable(_))
            ));
        }
        assert!(a.publish(&t, b"ok").await.is_ok());
        assert_eq!(b.poll(&t).await.unwrap().len(), 1);
        assert_eq!(net.publish_count(&t), 1);
        assert_eq!(net.total_publish_count(), 1);
    }

    #[tokio::test]
    async fn duplicate_delivery_repeats_frames() {
        let (_net, a, b, t) = pair().await;
        b.set_duplicate_delivery(3);
        let r = a.publish(&t, b"d").await.unwrap();
        let got = b.poll(&t).await.unwrap();
        assert_eq!(got.len(), 3);
        assert!(got.iter().all(|f| f.transport_id == r.transport_id));
        assert_eq!(
            a.poll(&t).await.unwrap().len(),
            1,
            "other endpoints unaffected"
        );
        b.set_duplicate_delivery(0);
        a.publish(&t, b"e").await.unwrap();
        assert_eq!(b.poll(&t).await.unwrap().len(), 1, "0 behaves as 1");
    }

    #[tokio::test]
    async fn reorder_is_seeded_and_deterministic() {
        async fn run(seed: u64) -> Vec<u8> {
            let (_net, a, b, t) = pair().await;
            b.set_reorder_seed(Some(seed));
            for i in 0..12u8 {
                a.publish(&t, &[i]).await.unwrap();
            }
            b.poll(&t)
                .await
                .unwrap()
                .iter()
                .map(|f| f.payload[0])
                .collect()
        }
        let a1 = run(42).await;
        let a2 = run(42).await;
        let b1 = run(43).await;
        assert_eq!(a1, a2, "same seed, same order");
        assert_ne!(a1, (0..12u8).collect::<Vec<_>>(), "actually reordered");
        assert_ne!(a1, b1, "different seed, different order");
        let mut sorted = a1.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..12u8).collect::<Vec<_>>(), "nothing lost");
    }

    #[tokio::test]
    async fn delay_holds_until_release() {
        let (_net, a, b, t) = pair().await;
        b.set_delay_delivery(true);
        a.publish(&t, b"late").await.unwrap();
        assert!(b.poll(&t).await.unwrap().is_empty());
        assert_eq!(b.held_len(), 1);
        b.release();
        assert_eq!(b.held_len(), 0);
        let got = b.poll(&t).await.unwrap();
        assert_eq!(got.len(), 1);
        // delay is off again after release
        a.publish(&t, b"now").await.unwrap();
        assert_eq!(b.poll(&t).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn isolation_violation_blocks_everything_and_is_reported() {
        let (_net, a, _b, t) = pair().await;
        a.set_isolation_violation(Some("unexpected peer"));
        for r in [
            a.publish(&t, b"x").await.map(|_| ()),
            a.poll(&t).await.map(|_| ()),
            a.history(&q(&t, 0, 1, None, 1)).await.map(|_| ()),
            a.subscribe(&t).await,
        ] {
            assert!(matches!(r, Err(TransportError::Isolation(_))), "{r:?}");
        }
        let s = a.status().await;
        assert!(!s.ready);
        assert_eq!(s.isolation_violation.as_deref(), Some("unexpected peer"));
        a.set_isolation_violation(None);
        assert!(a.publish(&t, b"x").await.is_ok());
        assert!(a.status().await.ready);
    }

    #[tokio::test]
    async fn max_payload_enforced() {
        let (net, a, _b, t) = pair().await;
        net.set_max_payload_len(4);
        assert_eq!(a.max_payload_len(&t), 4);
        assert!(a.publish(&t, b"1234").await.is_ok());
        let e = a.publish(&t, b"12345").await.unwrap_err();
        assert_eq!(e, TransportError::TooLarge { size: 5, max: 4 });
        assert_eq!(net.publish_count(&t), 1);
    }

    #[tokio::test]
    async fn inject_raw_is_delivered_stored_and_introspectable() {
        let (net, a, b, t) = pair().await;
        a.publish(&t, b"orig").await.unwrap();
        let captured = net.published_frames().remove(0);
        let mut tampered = captured.payload.clone();
        tampered[0] ^= 1;
        let r = net.inject_raw(&t, &tampered);
        let got = b.poll(&t).await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].payload, tampered);
        assert_eq!(got[1].transport_id, r.transport_id);
        assert_ne!(got[0].transport_id, got[1].transport_id);
        assert_eq!(net.published_frames()[1].publisher, None);
        assert_eq!(net.history_len(), 2);
        assert_eq!(net.publish_count(&t), 2);
        let _ = a;
    }

    #[tokio::test]
    async fn publish_counts_are_per_topic() {
        let net = MockNetwork::new();
        let a = net.endpoint();
        let (t1, t2) = (topic("one"), topic("two"));
        a.publish(&t1, b"1").await.unwrap();
        a.publish(&t1, b"1").await.unwrap();
        a.publish(&t2, b"2").await.unwrap();
        assert_eq!(net.publish_count(&t1), 2);
        assert_eq!(net.publish_count(&t2), 1);
        assert_eq!(net.publish_count(&topic("none")), 0);
        assert_eq!(net.total_publish_count(), 3);
        assert_eq!(a.index(), 0);
        assert_eq!(net.published_frames()[0].publisher, Some(0));
    }

    #[tokio::test]
    async fn node_restart_resubscribes_transparently() {
        let (_net, a, b, t) = pair().await;
        b.simulate_node_restart();
        a.publish(&t, b"lost-in-restart").await.unwrap();
        assert!(
            b.poll(&t).await.unwrap().is_empty(),
            "first poll resubscribes"
        );
        assert_eq!(b.resubscribe_count(), 1);
        a.publish(&t, b"after").await.unwrap();
        let got = b.poll(&t).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload, b"after");
        assert_eq!(b.resubscribe_count(), 1);
    }

    #[tokio::test]
    async fn status_reports_configured_peers() {
        let (_net, a, _b, _t) = pair().await;
        let s = a.status().await;
        assert!(s.ready);
        assert_eq!(s.peers.len(), 1);
        a.set_peers(vec![]);
        assert!(a.status().await.peers.is_empty());
        assert!(a.network().clock().now_ns() > 0);
    }
}
