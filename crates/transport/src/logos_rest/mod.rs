//! Adapter to a separately running Logos Delivery (nwaku) node over its REST API.
//!
//! Receive path: `POST /relay/v1/auto/subscriptions` and destructive polling of
//! `GET /relay/v1/auto/messages/{contentTopic}` (the node keeps a 50-slot
//! in-memory cache, so callers must poll quickly and use `history` to recover).
//! Recovery path: `GET /store/v3/messages`. Publish: `POST /relay/v1/auto/messages`.
//!
//! The REST responses carry no message hash, so `transport_id` is the Waku
//! message hash recomputed locally (verified equal to the Store's hashes).
//! Autosharding is supported only for a single-shard network (`num_shards = 1`,
//! shard 0): that is the only configuration whose pubsub topic could be checked
//! against the node's Store hashes.
//!
//! Private mode fails closed: see [`LogosRestConfig::validate`] and the
//! isolation audit ([`LogosRestTransport::audit`]).

mod config;
mod wire;

use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Mutex as StdMutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use reqwest::Method;
use tokio::sync::Mutex;

pub use config::{
    is_private_host, is_private_ipv4, is_private_ipv6, LogosRestConfig, NetworkMode,
    MAX_HISTORY_PAGE_SIZE, PUBLIC_PRESET_CLUSTER_IDS,
};
pub use wire::waku_message_hash;

use crate::{
    ContentTopic, HistoryPage, HistoryQuery, InboundFrame, PeerInfo, PublishReceipt, Transport,
    TransportError, TransportStatus,
};
use wire::{
    encode_component, evaluate_peers, hex, map_publish_failure, max_payload_for, parse_peers,
    max_relay_response_bytes, parse_store_page, snippet, RelayStream, StoreParseError,
};

/// Store queries may cover at most 24 hours.
pub const MAX_HISTORY_WINDOW_NS: i64 = 24 * 3600 * 1_000_000_000;
/// Upper bound on any response body we are willing to buffer. Relay polls are NOT subject to it:
/// they are parsed incrementally (see `RelayStream`) and bounded by `max_relay_response_bytes`.
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

static LAST_TIMESTAMP_NS: AtomicI64 = AtomicI64::new(0);

/// Wall-clock nanoseconds, strictly increasing within this process.
fn next_timestamp_ns() -> i64 {
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

/// Counters exposed by [`LogosRestTransport::metrics`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogosRestMetrics {
    /// Entries skipped because they could not be parsed (live and history).
    pub malformed_skipped: u64,
    /// Store entries skipped because the recomputed hash differed from the node's.
    pub hash_mismatches: u64,
    /// Subscriptions re-established after the node answered 404 to a poll.
    pub resubscribes: u64,
    /// Isolation audits actually sent to the node.
    pub audits_run: u64,
    /// Redial requests (`POST /admin/v1/peers` with the static peers) sent.
    pub redials: u64,
    /// Polls whose response ended early or broke off mid-body: the complete frames before the
    /// break were still delivered (a poll with no complete frame is an error instead).
    pub partial_polls: u64,
}

#[derive(Default)]
struct Counters {
    malformed: AtomicU64,
    mismatches: AtomicU64,
    resubscribes: AtomicU64,
    audits: AtomicU64,
    redials: AtomicU64,
    partial_polls: AtomicU64,
}

#[derive(Default)]
struct AuditState {
    checked_at: Option<Instant>,
    violation: Option<String>,
    peers: Vec<PeerInfo>,
    last_redial: Option<Instant>,
}

struct Resp {
    status: u16,
    body: Vec<u8>,
}

/// A failure to obtain any HTTP response.
struct NetErr(String);

fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// [`Transport`] over a Logos Delivery node's REST API. See the module docs.
pub struct LogosRestTransport {
    cfg: LogosRestConfig,
    base: String,
    pubsub: String,
    http: reqwest::Client,
    subscribed: StdMutex<HashSet<ContentTopic>>,
    audit: Mutex<AuditState>,
    counters: Counters,
}

impl LogosRestTransport {
    /// Validates `cfg` (failing closed in private mode) and builds the client.
    /// Performs no network I/O.
    pub fn new(cfg: LogosRestConfig) -> Result<Self, TransportError> {
        let url = cfg.validate()?;
        let mut cfg = cfg;
        cfg.allowed_peer_ids = cfg.effective_allowed_peer_ids();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(cfg.request_timeout)
            .connect_timeout(cfg.request_timeout)
            // One TCP connection per request is deliberate, not an oversight: the node's REST
            // server (nim-presto) answers EVERY response with `Connection: close`, even when the
            // request says `Connection: keep-alive` (checked on v0.39.2, results/fixups/
            // keepalive-curl-explicit.txt). A pooled idle connection would always be dead on reuse
            // and cost a failed request, so pooling is disabled. Consequence: roughly one
            // short-lived loopback connection per poll/publish (about 4 per second per topic at the
            // default 250 ms poll interval), visible as many TIME_WAIT sockets on 127.0.0.1.
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|_| TransportError::Protocol("could not initialise HTTP client".into()))?;
        let base = url.as_str().trim_end_matches('/').to_string();
        Ok(Self {
            pubsub: cfg.pubsub_topic(),
            cfg,
            base,
            http,
            subscribed: StdMutex::new(HashSet::new()),
            audit: Mutex::new(AuditState::default()),
            counters: Counters::default(),
        })
    }

    /// The configuration in use.
    pub fn config(&self) -> &LogosRestConfig {
        &self.cfg
    }

    /// The pubsub topic used for transport ids, e.g. `/waku/2/rs/66/0`.
    pub fn pubsub_topic(&self) -> &str {
        &self.pubsub
    }

    /// Snapshot of the counters.
    pub fn metrics(&self) -> LogosRestMetrics {
        LogosRestMetrics {
            malformed_skipped: self.counters.malformed.load(Ordering::Relaxed),
            hash_mismatches: self.counters.mismatches.load(Ordering::Relaxed),
            resubscribes: self.counters.resubscribes.load(Ordering::Relaxed),
            audits_run: self.counters.audits.load(Ordering::Relaxed),
            redials: self.counters.redials.load(Ordering::Relaxed),
            partial_polls: self.counters.partial_polls.load(Ordering::Relaxed),
        }
    }

    // ----- HTTP plumbing -------------------------------------------------

    async fn call(
        &self,
        method: Method,
        path_and_query: &str,
        json_body: Option<Vec<u8>>,
    ) -> Result<Resp, NetErr> {
        let mut resp = self.send(method, path_and_query, json_body).await?;
        let status = resp.status().as_u16();
        let body = Self::read_body(&mut resp).await?;
        Ok(Resp { status, body })
    }

    async fn send(
        &self,
        method: Method,
        path_and_query: &str,
        json_body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, NetErr> {
        let mut req = self
            .http
            .request(method, format!("{}{}", self.base, path_and_query));
        if let Some(b) = json_body {
            req = req.header("content-type", "application/json").body(b);
        }
        req.send().await.map_err(describe_reqwest_error)
    }

    async fn read_body(resp: &mut reqwest::Response) -> Result<Vec<u8>, NetErr> {
        let mut body = Vec::new();
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if body.len() + c.len() > MAX_RESPONSE_BYTES {
                        return Err(NetErr("response body too large".into()));
                    }
                    body.extend_from_slice(&c);
                }
                Ok(None) => return Ok(body),
                Err(e) => return Err(describe_reqwest_error(e)),
            }
        }
    }

    /// `GET` of the relay cache. The node has already DRAINED its cache when it answers, so a
    /// frame dropped here is lost to the live path. The body is therefore parsed as it streams in:
    /// one element is buffered at a time, a bad or oversized element is skipped and counted, and a
    /// body that breaks off (truncated, connection error, size bound) still yields every complete
    /// frame before the break. Only a poll with no frame at all and an error is an `Err`.
    async fn poll_relay(
        &self,
        topic: &ContentTopic,
        path: &str,
    ) -> Result<Result<Vec<InboundFrame>, Resp>, TransportError> {
        let unavailable = |e: NetErr| TransportError::Unavailable(format!("poll failed: {}", e.0));
        let mut resp = self.send(Method::GET, path, None).await.map_err(unavailable)?;
        let status = resp.status().as_u16();
        if status != 200 {
            let body = Self::read_body(&mut resp).await.map_err(unavailable)?;
            return Ok(Err(Resp { status, body }));
        }
        let limit = max_relay_response_bytes(self.cfg.max_message_bytes);
        let mut parser = RelayStream::new(topic, &self.pubsub, self.cfg.max_message_bytes);
        let mut read = 0usize;
        let mut net_err: Option<String> = None;
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    read = read.saturating_add(c.len());
                    if read > limit {
                        net_err = Some(format!("relay poll response exceeds {limit} bytes"));
                        break;
                    }
                    parser.feed(&c);
                }
                Ok(None) => break,
                Err(e) => {
                    net_err = Some(describe_reqwest_error(e).0);
                    break;
                }
            }
        }
        let parsed = parser.finish();
        self.counters
            .malformed
            .fetch_add(parsed.counts.malformed, Ordering::Relaxed);
        let problem = net_err.or(parsed.error);
        match problem {
            None => Ok(Ok(parsed.frames)),
            Some(_) if !parsed.frames.is_empty() => {
                self.counters.partial_polls.fetch_add(1, Ordering::Relaxed);
                Ok(Ok(parsed.frames))
            }
            Some(why) => Err(TransportError::Protocol(why)),
        }
    }

    // ----- isolation audit -----------------------------------------------

    /// Queries `GET /admin/v1/peers` and evaluates the allowlist. Errors mean
    /// the audit could not be performed (fail closed: `Unavailable`).
    async fn fetch_audit(&self) -> Result<(Vec<PeerInfo>, Option<String>), TransportError> {
        self.counters.audits.fetch_add(1, Ordering::Relaxed);
        let fail = |why: String| {
            TransportError::Unavailable(format!(
                "isolation audit could not be completed ({why}); failing closed"
            ))
        };
        let r = self
            .call(Method::GET, "/admin/v1/peers", None)
            .await
            .map_err(|e| fail(e.0))?;
        if r.status != 200 {
            return Err(fail(format!(
                "admin API answered HTTP {} (is --rest-admin enabled?)",
                r.status
            )));
        }
        let raw = parse_peers(&r.body).map_err(fail)?;
        let rep = evaluate_peers(&raw, &self.cfg.allowed_peer_ids, self.cfg.shard);
        Ok((rep.peers, rep.violation))
    }

    async fn refresh_audit(&self, st: &mut AuditState) -> Result<(), TransportError> {
        let r = self.refresh_audit_once(st).await;
        if r.is_ok() && self.redial_wanted(st) && self.redial(st).await {
            // The dial is synchronous on the node; look again.
            return self.refresh_audit_once(st).await;
        }
        r
    }

    async fn refresh_audit_once(&self, st: &mut AuditState) -> Result<(), TransportError> {
        match self.fetch_audit().await {
            Ok((peers, violation)) => {
                st.checked_at = Some(Instant::now());
                st.peers = peers;
                st.violation = violation;
                Ok(())
            }
            Err(e) => {
                st.checked_at = None;
                Err(e)
            }
        }
    }

    /// True when static peers are configured, no allowlisted peer is connected
    /// and the redial rate limit allows another attempt.
    fn redial_wanted(&self, st: &AuditState) -> bool {
        !self.cfg.static_peers.is_empty()
            && st.checked_at.is_some()
            && !st.peers.iter().any(|p| p.connected && p.allowed)
            && st
                .last_redial
                .is_none_or(|t| t.elapsed() >= self.cfg.redial_interval)
    }

    /// Asks the node to dial exactly the configured static peers. Failures are
    /// not fatal (the next audit decides); returns whether the node said OK.
    async fn redial(&self, st: &mut AuditState) -> bool {
        st.last_redial = Some(Instant::now());
        self.counters.redials.fetch_add(1, Ordering::Relaxed);
        let Ok(body) = serde_json::to_vec(&self.cfg.static_peers) else {
            return false;
        };
        matches!(
            self.call(Method::POST, "/admin/v1/peers", Some(body)).await,
            Ok(Resp {
                status: 200..=299,
                ..
            })
        )
    }

    /// Forces an isolation audit now. `Ok` means no violation; a violation is
    /// [`TransportError::Isolation`]; an unreachable or disabled admin API is
    /// [`TransportError::Unavailable`]. A no-op in plain public mode (audited
    /// only with `enforce_peer_allowlist`).
    pub async fn audit(&self) -> Result<(), TransportError> {
        if !self.cfg.audits_peers() {
            return Ok(());
        }
        let mut st = self.audit.lock().await;
        self.refresh_audit(&mut st).await?;
        match &st.violation {
            Some(v) => Err(TransportError::Isolation(v.clone())),
            None => Ok(()),
        }
    }

    /// Runs the audit if never done or older than `audit_interval`. Used by
    /// subscribe, poll and history; `publish` audits uncached (see there).
    async fn ensure_audit(&self) -> Result<(), TransportError> {
        if !self.cfg.audits_peers() {
            return Ok(());
        }
        let mut st = self.audit.lock().await;
        let fresh = st
            .checked_at
            .is_some_and(|t| t.elapsed() < self.cfg.audit_interval);
        if !fresh {
            self.refresh_audit(&mut st).await?;
        } else if self.redial_wanted(&st) && self.redial(&mut st).await {
            // Cached audit says nobody is connected: dial, then re-audit.
            self.refresh_audit_once(&mut st).await?;
        }
        match &st.violation {
            Some(v) => Err(TransportError::Isolation(v.clone())),
            None => Ok(()),
        }
    }

    // ----- subscriptions ---------------------------------------------------

    async fn post_subscribe(&self, topic: &ContentTopic) -> Result<(), TransportError> {
        let body = serde_json::to_vec(&[topic.as_str()])
            .map_err(|_| TransportError::Protocol("could not encode subscribe body".into()))?;
        let r = self
            .call(Method::POST, "/relay/v1/auto/subscriptions", Some(body))
            .await
            .map_err(|e| TransportError::Unavailable(format!("subscribe failed: {}", e.0)))?;
        if (200..300).contains(&r.status) {
            lock(&self.subscribed).insert(topic.clone());
            Ok(())
        } else if r.status >= 500 {
            Err(TransportError::Unavailable(format!(
                "subscribe: node answered HTTP {}: {}",
                r.status,
                snippet(&r.body)
            )))
        } else {
            Err(TransportError::Protocol(format!(
                "subscribe rejected with HTTP {}: {}",
                r.status,
                snippet(&r.body)
            )))
        }
    }
}

fn describe_reqwest_error(e: reqwest::Error) -> NetErr {
    let e = e.without_url();
    NetErr(if e.is_timeout() {
        "request timed out".to_string()
    } else if e.is_connect() {
        "connection failed".to_string()
    } else {
        snippet(e.to_string().as_bytes())
    })
}

#[async_trait]
impl Transport for LogosRestTransport {
    async fn subscribe(&self, topic: &ContentTopic) -> Result<(), TransportError> {
        self.ensure_audit().await?;
        self.post_subscribe(topic).await
    }

    async fn publish(
        &self,
        topic: &ContentTopic,
        payload: &[u8],
    ) -> Result<PublishReceipt, TransportError> {
        let max = self.max_payload_len(topic);
        if payload.len() > max {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                max,
            });
        }
        // Root cause of the real-relay race (results/public-ip-relay/
        // 20261126T211443Z, check 3d): `ensure_audit` trusted a cached "ok" for
        // up to `audit_interval`. A publish therefore audits unconditionally,
        // with no cache: one `GET /admin/v1/peers` right before the publish
        // request. The audit stays detective: a peer that connects between
        // that response and the publish request is not seen, and the node API
        // has no atomic check-and-publish. The window is one REST round trip,
        // not the cache lifetime. Cost: one extra GET per publish.
        self.audit().await?;
        let ts = next_timestamp_ns();
        let body = serde_json::to_vec(&serde_json::json!({
            "payload": B64.encode(payload),
            "contentTopic": topic.as_str(),
            "timestamp": ts,
            "ephemeral": false,
        }))
        .map_err(|_| TransportError::Protocol("could not encode publish body".into()))?;
        let r = self
            .call(Method::POST, "/relay/v1/auto/messages", Some(body))
            .await
            .map_err(|e| TransportError::Unavailable(format!("publish failed: {}", e.0)))?;
        if !(200..300).contains(&r.status) {
            return Err(map_publish_failure(r.status, &r.body, payload.len(), max));
        }
        Ok(PublishReceipt {
            transport_id: waku_message_hash(&self.pubsub, payload, topic.as_str(), &[], ts),
            timestamp_ns: ts,
        })
    }

    async fn poll(&self, topic: &ContentTopic) -> Result<Vec<InboundFrame>, TransportError> {
        self.ensure_audit().await?;
        let known = lock(&self.subscribed).contains(topic);
        if !known {
            self.post_subscribe(topic).await?;
        }
        let path = format!(
            "/relay/v1/auto/messages/{}",
            encode_component(topic.as_str())
        );
        let r = match self.poll_relay(topic, &path).await? {
            Ok(frames) => return Ok(frames),
            Err(r) => r,
        };
        match r.status {
            404 => {
                // The node lost its subscriptions (restart): re-subscribe once.
                self.post_subscribe(topic).await?;
                self.counters.resubscribes.fetch_add(1, Ordering::Relaxed);
                Ok(Vec::new())
            }
            s if s >= 500 => Err(TransportError::Unavailable(format!(
                "poll: node answered HTTP {s}: {}",
                snippet(&r.body)
            ))),
            s => Err(TransportError::Protocol(format!(
                "poll rejected with HTTP {s}: {}",
                snippet(&r.body)
            ))),
        }
    }

    async fn history(&self, query: &HistoryQuery) -> Result<HistoryPage, TransportError> {
        if query.end_ns < query.start_ns {
            return Err(TransportError::Protocol(
                "history window end is before start".into(),
            ));
        }
        if query.end_ns.saturating_sub(query.start_ns) > MAX_HISTORY_WINDOW_NS {
            return Err(TransportError::Protocol(
                "history window exceeds the 24 h limit".into(),
            ));
        }
        if query.limit == 0 {
            return Err(TransportError::Protocol(
                "history limit must be positive".into(),
            ));
        }
        self.ensure_audit().await.map_err(|e| match e {
            TransportError::Unavailable(m) => TransportError::HistoryUnavailable(m),
            other => other,
        })?;
        let page_size = query.limit.clamp(1, self.cfg.history_page_size);
        let mut path = format!(
            "/store/v3/messages?contentTopics={}&includeData=true&ascending=true&pageSize={}&startTime={}&endTime={}",
            encode_component(query.topic.as_str()),
            page_size,
            query.start_ns,
            query.end_ns
        );
        if let Some(c) = &query.cursor {
            path.push_str(&format!("&cursor={}", encode_component(c)));
        }
        if let Some(p) = &self.cfg.store_peer {
            path.push_str(&format!("&peerAddr={}", encode_component(p)));
        }
        let r = self.call(Method::GET, &path, None).await.map_err(|e| {
            TransportError::HistoryUnavailable(format!("store query failed: {}", e.0))
        })?;
        match r.status {
            200..=299 => {}
            404 | 408 | 429 | 500..=599 => {
                return Err(TransportError::HistoryUnavailable(format!(
                    "store: node answered HTTP {}: {}",
                    r.status,
                    snippet(&r.body)
                )))
            }
            s => {
                return Err(TransportError::Protocol(format!(
                    "store query rejected with HTTP {s}: {}",
                    snippet(&r.body)
                )))
            }
        }
        let (page, counts) = parse_store_page(
            &r.body,
            &query.topic,
            &self.pubsub,
            self.cfg.max_message_bytes,
        )
        .map_err(|e| match e {
            StoreParseError::Malformed(m) => TransportError::Protocol(m),
            StoreParseError::Status(m) => TransportError::HistoryUnavailable(m),
        })?;
        self.counters
            .malformed
            .fetch_add(counts.malformed, Ordering::Relaxed);
        self.counters
            .mismatches
            .fetch_add(counts.hash_mismatch, Ordering::Relaxed);
        Ok(page)
    }

    async fn status(&self) -> TransportStatus {
        let health_ok = matches!(
            self.call(Method::GET, "/health", None).await,
            Ok(Resp {
                status: 200..=299,
                ..
            })
        );
        let private = self.cfg.audits_peers();
        let (peers, violation, audit_err) = if private {
            let mut st = self.audit.lock().await;
            match self.refresh_audit(&mut st).await {
                Ok(()) => (st.peers.clone(), st.violation.clone(), None),
                Err(e) => (Vec::new(), None, Some(e)),
            }
        } else {
            match self.fetch_audit_public().await {
                Some(p) => (p, None, None),
                None => (Vec::new(), None, None),
            }
        };
        let connected_allowed = peers.iter().filter(|p| p.connected && p.allowed).count();
        let ready = health_ok
            && violation.is_none()
            && audit_err.is_none()
            && if private || !peers.is_empty() {
                connected_allowed >= 1
            } else {
                true
            };
        let detail = if !health_ok {
            "node REST API not reachable or unhealthy".to_string()
        } else if let Some(v) = &violation {
            format!("isolation violation: {}", snippet(v.as_bytes()))
        } else if audit_err.is_some() {
            "isolation audit unavailable (admin API unreachable or disabled); failing closed"
                .to_string()
        } else if private {
            format!("node reachable; {connected_allowed} connected allowed peer(s)")
        } else {
            format!(
                "node reachable; {connected_allowed} connected peer(s) (public mode: peers not audited)"
            )
        };
        TransportStatus {
            ready,
            peers,
            isolation_violation: violation,
            detail,
        }
    }

    fn max_payload_len(&self, topic: &ContentTopic) -> usize {
        max_payload_for(self.cfg.max_message_bytes, topic.as_str().len())
    }

    fn max_history_window_ns(&self) -> i64 {
        MAX_HISTORY_WINDOW_NS
    }
}

impl LogosRestTransport {
    /// Public mode: best-effort peer list, every peer counts as allowed.
    async fn fetch_audit_public(&self) -> Option<Vec<PeerInfo>> {
        let r = self.call(Method::GET, "/admin/v1/peers", None).await.ok()?;
        if r.status != 200 {
            return None;
        }
        let raw = parse_peers(&r.body).ok()?;
        Some(
            raw.into_iter()
                .filter_map(|p| {
                    p.peer_id.map(|peer_id| PeerInfo {
                        peer_id,
                        connected: p.connected,
                        allowed: true,
                    })
                })
                .collect(),
        )
    }
}

/// Lower-case hex of a transport id, for logs and tests.
pub fn transport_id_hex(id: &[u8; 32]) -> String {
    hex(id)
}

#[cfg(test)]
mod tests;
