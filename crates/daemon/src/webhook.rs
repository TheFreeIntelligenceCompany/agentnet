//! Optional signed outbound webhook.
//!
//! Delivers persisted events (the JSON of `EventRecord`: references only, no
//! plaintext) to the ONE configured URL. A remote sender can never influence
//! the URL: it is parsed once from the local configuration.
//!
//! * Headers: `X-AgentNet-Event-Id`, `X-AgentNet-Timestamp` (unix seconds),
//!   `X-AgentNet-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + body)>`.
//! * At-least-once, `event_id` is the idempotency key. The dispatcher keeps its
//!   own cursor in `webhook.db` (never in the engine's schema), so a restart
//!   resumes where it stopped.
//! * Bounded retries with exponential backoff, then the event is parked
//!   (recorded, counted, surfaced in `daemon.status`) and delivery continues.
//! * SSRF: scheme http/https only, no credentials, literal loopback/private IP
//!   or `localhost` unless `allow_remote`; for names every resolved address is
//!   re-checked against the block list and the connection is pinned to the
//!   checked address; redirects are never followed; proxies are ignored.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentnet_core::api::{AgentApi, EventRecord, EventType, PageRequest};
use agentnet_core::{Clock, Node};
use agentnet_transport::logos_rest::{is_private_ipv4, is_private_ipv6};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::Sha256;
use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::config::WebhookSection;
use crate::datadir::{hex_decode, hex_encode, read_secret_file, DataDir};
use crate::error::DaemonError;

type HmacSha256 = Hmac<Sha256>;

/// Header carrying the event id (the idempotency key).
pub const HEADER_EVENT_ID: &str = "X-AgentNet-Event-Id";
/// Header carrying the unix-seconds timestamp that is part of the signature.
pub const HEADER_TIMESTAMP: &str = "X-AgentNet-Timestamp";
/// Header carrying `v1=<hex hmac>`.
pub const HEADER_SIGNATURE: &str = "X-AgentNet-Signature";
/// Accepted clock difference between sender and receiver.
pub const SIGNATURE_TOLERANCE_S: i64 = 300;
/// Minimum secret length.
pub const MIN_SECRET_LEN: usize = 32;
const EVENT_POLL: Duration = Duration::from_secs(1);

/// Why [`verify_signature`] refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// Timestamp header is not an integer.
    #[error("malformed timestamp")]
    BadTimestamp,
    /// Timestamp is outside the tolerance window (possible replay).
    #[error("timestamp outside the accepted window")]
    Stale,
    /// Signature header is not `v1=<hex>`.
    #[error("malformed signature")]
    BadFormat,
    /// The MAC does not match.
    #[error("signature mismatch")]
    Mismatch,
}

fn mac_for(secret: &[u8], timestamp: &str, body: &[u8]) -> Option<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Some(mac)
}

/// The header value for `body` signed at `timestamp` (unix seconds as text).
pub fn sign(secret: &[u8], timestamp: &str, body: &[u8]) -> String {
    match mac_for(secret, timestamp, body) {
        Some(m) => format!("v1={}", hex_encode(&m.finalize().into_bytes())),
        None => String::new(),
    }
}

/// Verify a delivery: constant-time MAC comparison and a timestamp window of
/// `tolerance_s` seconds around `now_unix`. Replay protection beyond the window
/// is the receiver's job: remember event ids (see `examples/mock_harness.rs`).
pub fn verify_signature(
    secret: &[u8],
    timestamp: &str,
    body: &[u8],
    signature_header: &str,
    now_unix: i64,
    tolerance_s: i64,
) -> Result<(), SignatureError> {
    let ts: i64 = timestamp
        .trim()
        .parse()
        .map_err(|_| SignatureError::BadTimestamp)?;
    let hex = signature_header
        .trim()
        .strip_prefix("v1=")
        .ok_or(SignatureError::BadFormat)?;
    let sig = hex_decode(hex).ok_or(SignatureError::BadFormat)?;
    let mac = mac_for(secret, timestamp.trim(), body).ok_or(SignatureError::Mismatch)?;
    // `verify_slice` compares in constant time.
    mac.verify_slice(&sig)
        .map_err(|_| SignatureError::Mismatch)?;
    if (now_unix - ts).abs() > tolerance_s {
        return Err(SignatureError::Stale);
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// SSRF policy

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_link_local()  // 169.254.0.0/16, includes cloud metadata 169.254.169.254
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.octets()[0] == 0
}

/// Addresses that are never acceptable destinations (link-local/metadata,
/// multicast, unspecified), even with `allow_remote`.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_v4(v4);
            }
            v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TargetHost {
    Ip(IpAddr),
    Name(String),
}

/// The parsed, policy-checked destination.
#[derive(Clone, Debug)]
pub struct WebhookTarget {
    url: Url,
    host: TargetHost,
    port: u16,
    allow_remote: bool,
}

impl WebhookTarget {
    /// Parse and check `url` against the destination policy (no DNS lookups).
    pub fn parse(url: &str, allow_remote: bool) -> Result<Self, String> {
        let url = Url::parse(url).map_err(|_| "webhook.url is not a valid URL".to_owned())?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err("webhook.url scheme must be http or https".into());
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("webhook.url must not contain credentials".into());
        }
        if url.fragment().is_some() {
            return Err("webhook.url must not contain a fragment".into());
        }
        let port = url
            .port_or_known_default()
            .ok_or_else(|| "webhook.url has no port".to_owned())?;
        let host = match url
            .host()
            .ok_or_else(|| "webhook.url has no host".to_owned())?
        {
            Host::Ipv4(ip) => TargetHost::Ip(IpAddr::V4(ip)),
            Host::Ipv6(ip) => TargetHost::Ip(IpAddr::V6(ip)),
            Host::Domain(d) => TargetHost::Name(d.to_ascii_lowercase()),
        };
        match &host {
            TargetHost::Ip(ip) => {
                if is_blocked_ip(*ip) {
                    return Err("webhook.url points at a blocked address (link-local, metadata, multicast or unspecified)".into());
                }
                if !allow_remote && !is_local_ip(*ip) {
                    return Err("webhook.url must be a loopback or private address unless webhook.allow_remote = true".into());
                }
            }
            TargetHost::Name(n) => {
                if !allow_remote && n != "localhost" {
                    return Err("webhook.url host must be a literal loopback/private IP or localhost unless webhook.allow_remote = true".into());
                }
            }
        }
        Ok(Self {
            url,
            host,
            port,
            allow_remote,
        })
    }

    /// The destination URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Resolve a hostname and re-check every address; returns the address to
    /// pin the connection to (`None` for literal IPs, which need no lookup).
    pub async fn resolve_checked(&self) -> Result<Option<SocketAddr>, String> {
        let TargetHost::Name(name) = &self.host else {
            return Ok(None);
        };
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), self.port))
            .await
            .map_err(|_| "webhook host did not resolve".to_owned())?
            .collect();
        if addrs.is_empty() {
            return Err("webhook host did not resolve".into());
        }
        for a in &addrs {
            let ip = a.ip();
            if is_blocked_ip(ip) {
                return Err("webhook host resolves to a blocked address".into());
            }
            if !(self.allow_remote || ip.is_loopback() || is_local_ip(ip)) {
                return Err("webhook host resolves to a public address".into());
            }
        }
        Ok(addrs.first().copied())
    }
}

// ----------------------------------------------------------------------------
// dispatcher

/// Counters surfaced by `daemon.status`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct WebhookStats {
    /// Whether a dispatcher is running.
    pub enabled: bool,
    /// Events accepted by the receiver (2xx).
    pub delivered: u64,
    /// Failed attempts that were retried.
    pub retries: u64,
    /// Events given up on after `max_attempts` (recorded in `webhook.db`).
    pub parked: u64,
    /// Sanitized description of the most recent failure.
    pub last_error: Option<String>,
    /// Cursor up to which the dispatcher has processed events.
    pub cursor: Option<String>,
}

/// The dispatcher. Create with [`Webhook::prepare`], run with [`Webhook::run`].
pub struct Webhook {
    cfg: WebhookSection,
    target: WebhookTarget,
    secret: Vec<u8>,
    db: Mutex<Connection>,
    stats: Mutex<WebhookStats>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook")
            .field("url", &self.target.url.as_str())
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

fn wh_err(m: impl Into<String>) -> DaemonError {
    DaemonError::Webhook(m.into())
}

fn sql_err(e: rusqlite::Error) -> DaemonError {
    DaemonError::Webhook(format!("webhook.db: {e}"))
}

fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(120).collect()
}

impl Webhook {
    /// Validate the destination, read the secret and open `webhook.db`.
    pub fn prepare(
        cfg: &WebhookSection,
        dir: &DataDir,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, DaemonError> {
        let target = WebhookTarget::parse(&cfg.url, cfg.allow_remote).map_err(wh_err)?;
        let secret_path = if Path::new(&cfg.secret_file).is_absolute() {
            Path::new(&cfg.secret_file).to_path_buf()
        } else {
            dir.root().join(&cfg.secret_file)
        };
        let mut secret = read_secret_file(&secret_path)?;
        while matches!(secret.last(), Some(b'\n' | b'\r')) {
            secret.pop();
        }
        if secret.len() < MIN_SECRET_LEN {
            return Err(wh_err(format!(
                "the secret in {} is shorter than {MIN_SECRET_LEN} bytes",
                secret_path.display()
            )));
        }
        let path = dir.webhook_db();
        let db = Connection::open(&path).map_err(sql_err)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS parked (
                event_id TEXT PRIMARY KEY, cursor TEXT NOT NULL, parked_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL, last_error TEXT);",
        )
        .map_err(sql_err)?;
        let parked: i64 = db
            .query_row("SELECT COUNT(*) FROM parked", [], |r| r.get(0))
            .map_err(sql_err)?;
        let stats = WebhookStats {
            enabled: true,
            parked: u64::try_from(parked).unwrap_or(0),
            ..Default::default()
        };
        Ok(Self {
            cfg: cfg.clone(),
            target,
            secret,
            db: Mutex::new(db),
            stats: Mutex::new(stats),
            clock,
        })
    }

    /// Current counters.
    pub fn stats(&self) -> WebhookStats {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn lock_db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn cursor(&self) -> Result<Option<String>, DaemonError> {
        self.lock_db()
            .query_row("SELECT v FROM kv WHERE k='cursor'", [], |r| r.get(0))
            .optional()
            .map_err(sql_err)
    }

    fn set_cursor(&self, c: &str) -> Result<(), DaemonError> {
        self.lock_db()
            .execute(
                "INSERT INTO kv(k,v) VALUES('cursor',?1) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                [c],
            )
            .map_err(sql_err)?;
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).cursor = Some(c.to_owned());
        Ok(())
    }

    /// On the very first start there is no cursor: begin at the current end of
    /// the event log, so enabling the webhook does not replay history. Call
    /// before the engine starts producing events.
    pub async fn init_cursor(&self, node: &Arc<Node>) -> Result<(), DaemonError> {
        if let Some(c) = self.cursor()? {
            self.stats.lock().unwrap_or_else(|e| e.into_inner()).cursor = Some(c);
            return Ok(());
        }
        let mut cur: Option<String> = None;
        loop {
            let page = node
                .read_events(PageRequest {
                    cursor: cur.clone(),
                    limit: Some(200),
                })
                .await
                .map_err(|e| wh_err(e.to_string()))?;
            if let Some(c) = page.next_cursor {
                cur = Some(c);
            }
            if !page.has_more {
                break;
            }
        }
        match cur {
            Some(c) => self.set_cursor(&c),
            None => Ok(()),
        }
    }

    fn wants(&self, t: EventType) -> bool {
        let name = match t {
            EventType::MessageReceived => "message.received",
            EventType::TriggerMatched => "trigger.matched",
        };
        self.cfg.events.iter().any(|e| e == name)
    }

    async fn attempt(&self, ev: &EventRecord, body: &str) -> Result<(), String> {
        let pinned = self.target.resolve_checked().await?;
        let timeout = Duration::from_millis(self.cfg.timeout_ms);
        let mut b = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(timeout)
            .connect_timeout(timeout)
            .user_agent("agentnet-webhook/1");
        if let (Some(addr), Some(host)) = (pinned, self.target.url.host_str()) {
            b = b.resolve(host, addr);
        }
        let client = b
            .build()
            .map_err(|_| "could not build http client".to_owned())?;
        let ts = (self.clock.now_ms() / 1000).to_string();
        let sig = sign(&self.secret, &ts, body.as_bytes());
        let resp = client
            .post(self.target.url.clone())
            .header("Content-Type", "application/json")
            .header(HEADER_EVENT_ID, &ev.event_id)
            .header(HEADER_TIMESTAMP, &ts)
            .header(HEADER_SIGNATURE, sig)
            .body(body.to_owned())
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    "request timed out".to_owned()
                } else if e.is_connect() {
                    "connection failed".to_owned()
                } else {
                    "request failed".to_owned()
                }
            })?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("receiver answered http {}", status.as_u16()))
        }
    }

    /// Deliver one event with bounded retries. `Ok(true)` delivered, `Ok(false)`
    /// parked, `Err(())` interrupted by shutdown (cursor must not advance).
    async fn deliver(&self, ev: &EventRecord, stop: &CancellationToken) -> Result<bool, ()> {
        let Ok(body) = serde_json::to_string(ev) else {
            return Ok(false);
        };
        let max = self.cfg.max_attempts.max(1);
        let mut last = String::new();
        for n in 1..=max {
            if stop.is_cancelled() {
                return Err(());
            }
            match self.attempt(ev, &body).await {
                Ok(()) => {
                    let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
                    s.delivered += 1;
                    return Ok(true);
                }
                Err(e) => {
                    last = sanitize(&e);
                    let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
                    s.last_error = Some(last.clone());
                    if n < max {
                        s.retries += 1;
                    }
                }
            }
            if n < max {
                let shift = (n - 1).min(20);
                let delay = self
                    .cfg
                    .retry_base_ms
                    .saturating_mul(1u64 << shift)
                    .min(self.cfg.retry_max_ms);
                tokio::select! {
                    _ = stop.cancelled() => return Err(()),
                    _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
                }
            }
        }
        let now = self.clock.now_ms();
        let _ = self.lock_db().execute(
            "INSERT OR REPLACE INTO parked(event_id,cursor,parked_at,attempts,last_error)
             VALUES(?1,?2,?3,?4,?5)",
            params![ev.event_id, ev.cursor, now, max, last],
        );
        let mut s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        s.parked += 1;
        tracing::warn!(event_id = %ev.event_id, "webhook: event parked after {max} attempts");
        Ok(false)
    }

    /// Run until `stop` is cancelled.
    pub async fn run(self: Arc<Self>, node: Arc<Node>, stop: CancellationToken) {
        let mut hints = node.changes();
        let mut cursor = self.cursor().ok().flatten();
        loop {
            if stop.is_cancelled() {
                return;
            }
            let page = node
                .read_events(PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(100),
                })
                .await;
            let mut more = false;
            match page {
                Ok(page) => {
                    for ev in &page.events {
                        if self.wants(ev.event_type) {
                            match self.deliver(ev, &stop).await {
                                Ok(_) => {}
                                Err(()) => return,
                            }
                        }
                        if let Err(e) = self.set_cursor(&ev.cursor) {
                            tracing::error!(error = %e, "webhook: cannot persist cursor");
                            tokio::time::sleep(EVENT_POLL).await;
                            break;
                        }
                        cursor = Some(ev.cursor.clone());
                    }
                    more = page.has_more;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "webhook: cannot read events");
                }
            }
            if more {
                continue;
            }
            loop {
                tokio::select! {
                    _ = stop.cancelled() => return,
                    _ = tokio::time::sleep(EVENT_POLL) => break,
                    h = hints.recv() => match h {
                        Ok(agentnet_core::api::ChangeHint::Events) => break,
                        Ok(_) => continue,
                        Err(RecvError::Lagged(_)) => break,
                        Err(RecvError::Closed) => return,
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn signature_round_trip_and_failures() {
        let body = br#"{"event_id":"e1"}"#;
        let sig = sign(SECRET, "1000", body);
        assert!(sig.starts_with("v1="));
        verify_signature(SECRET, "1000", body, &sig, 1000, 300).unwrap();
        verify_signature(SECRET, "1000", body, &sig, 1300, 300).unwrap();
        assert_eq!(
            verify_signature(SECRET, "1000", body, &sig, 1301, 300),
            Err(SignatureError::Stale)
        );
        assert_eq!(
            verify_signature(SECRET, "1000", body, &sig, 699, 300),
            Err(SignatureError::Stale)
        );
        assert_eq!(
            verify_signature(
                b"another-secret-another-secret-0000",
                "1000",
                body,
                &sig,
                1000,
                300
            ),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify_signature(SECRET, "1000", b"tampered", &sig, 1000, 300),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify_signature(SECRET, "1001", body, &sig, 1000, 300),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify_signature(SECRET, "x", body, &sig, 1000, 300),
            Err(SignatureError::BadTimestamp)
        );
        assert_eq!(
            verify_signature(SECRET, "1000", body, "v2=00", 1000, 300),
            Err(SignatureError::BadFormat)
        );
        assert_eq!(
            verify_signature(SECRET, "1000", body, "v1=zz", 1000, 300),
            Err(SignatureError::BadFormat)
        );
        assert_eq!(
            verify_signature(SECRET, "1000", body, "", 1000, 300),
            Err(SignatureError::BadFormat)
        );
    }

    #[test]
    fn blocklist() {
        for ip in [
            "169.254.169.254",
            "169.254.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "fe80::1",
            "ff02::1",
            "::",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_blocked_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "8.8.8.8",
            "::1",
            "fd00::1",
            "2001:db8::1",
        ] {
            assert!(!is_blocked_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn localhost_resolves_to_a_pinned_loopback_address() {
        let t = WebhookTarget::parse("http://localhost:9/x", false).unwrap();
        let a = t.resolve_checked().await.unwrap().unwrap();
        assert!(a.ip().is_loopback());
        let t = WebhookTarget::parse("http://127.0.0.1:9/x", false).unwrap();
        assert!(t.resolve_checked().await.unwrap().is_none());
    }
}
