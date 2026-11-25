//! REST adapter pieces (localhost / container network only): publish, destructive-read pollers, Store query.
use crate::crypto::now_ns;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const NA: &str = "http://127.0.0.1:18641";
pub const NB: &str = "http://127.0.0.1:18642";
pub const R1: &str = "http://127.0.0.1:18640";
pub const PUBSUB: &str = "/waku/2/rs/66/0";

pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RelayMsg {
    pub payload: String,
    pub content_topic: Option<String>,
    pub timestamp: Option<i64>,
}
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StoreMsgInner {
    pub payload: String,
    pub content_topic: String,
    pub timestamp: i64,
    #[serde(default)]
    pub meta: Option<String>,
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub ephemeral: Option<bool>,
}
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StoreEntry {
    pub message_hash: String,
    pub message: Option<StoreMsgInner>,
    pub pubsub_topic: Option<String>,
}
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StoreResp {
    status_code: u32,
    status_desc: String,
    messages: Vec<StoreEntry>,
    pagination_cursor: Option<String>,
}

#[derive(Clone)]
pub struct Api {
    pub http: reqwest::Client,
}
impl Api {
    pub fn new() -> Api {
        Api {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("http client"),
        }
    }
    pub async fn subscribe(&self, node: &str, ct: &str) -> Result<(), String> {
        let r = self
            .http
            .post(format!("{node}/relay/v1/auto/subscriptions"))
            .json(&[ct])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "{} {}",
                r.status(),
                r.text().await.unwrap_or_default()
            ))
        }
    }
    /// Publish a payload; Waku timestamp = now ns, ephemeral=false.
    pub async fn publish(&self, node: &str, ct: &str, payload: &[u8]) -> Result<(), String> {
        let body = serde_json::json!({"payload": B64.encode(payload), "contentTopic": ct, "timestamp": now_ns() as u64, "ephemeral": false});
        let r = self
            .http
            .post(format!("{node}/relay/v1/auto/messages"))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!(
                "HTTP {} {}",
                r.status().as_u16(),
                r.text().await.unwrap_or_default()
            ))
        }
    }
    pub async fn poll(&self, node: &str, ct: &str) -> Result<Vec<RelayMsg>, String> {
        let r = self
            .http
            .get(format!("{node}/relay/v1/auto/messages/{}", enc(ct)))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!(
                "{} {}",
                r.status(),
                r.text().await.unwrap_or_default()
            ));
        }
        r.json().await.map_err(|e| e.to_string())
    }
    /// All Store pages (pageSize 100, ascending) for one content topic in [start_ns, end_ns].
    pub async fn store_all(
        &self,
        node: &str,
        ct: &str,
        start_ns: u128,
        end_ns: u128,
    ) -> Result<Vec<StoreEntry>, String> {
        let mut out = vec![];
        let mut cursor: Option<String> = None;
        for _ in 0..1000 {
            let mut u = format!(
                "{node}/store/v3/messages?contentTopics={}&includeData=true&ascending=true&pageSize=100&startTime={start_ns}&endTime={end_ns}",
                enc(ct)
            );
            if let Some(c) = &cursor {
                u += &format!("&cursor={}", enc(c));
            }
            let r = self.http.get(u).send().await.map_err(|e| e.to_string())?;
            if !r.status().is_success() {
                return Err(format!(
                    "{} {}",
                    r.status(),
                    r.text().await.unwrap_or_default()
                ));
            }
            let p: StoreResp = r.json().await.map_err(|e| e.to_string())?;
            if p.status_code != 200 {
                return Err(format!("store status {} {}", p.status_code, p.status_desc));
            }
            out.extend(p.messages);
            cursor = p.pagination_cursor;
            if cursor.is_none() {
                return Ok(out);
            }
        }
        Err("store pagination did not terminate".into())
    }
    pub async fn connected_peers(&self, node: &str) -> usize {
        match self.http.get(format!("{node}/admin/v1/peers")).send().await {
            Ok(r) => r
                .json::<Vec<serde_json::Value>>()
                .await
                .map(|v| v.iter().filter(|p| p["connected"] == "Connected").count())
                .unwrap_or(0),
            Err(_) => 0,
        }
    }
    /// number of relay mesh peers R1 has on shard 0
    pub async fn r1_mesh_peers(&self) -> usize {
        match self
            .http
            .get(format!("{R1}/admin/v1/peers/mesh"))
            .send()
            .await
        {
            Ok(r) => r
                .json::<Vec<serde_json::Value>>()
                .await
                .map(|v| {
                    v.iter()
                        .map(|s| s["peers"].as_array().map(|p| p.len()).unwrap_or(0))
                        .sum()
                })
                .unwrap_or(0),
            Err(_) => 0,
        }
    }
    pub async fn healthy(&self, node: &str) -> bool {
        self.http
            .get(format!("{node}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

pub fn waku_hash(pubsub: &str, payload: &[u8], ct: &str, ts: i64) -> String {
    let mut h = Sha256::new();
    h.update(pubsub.as_bytes());
    h.update(payload);
    h.update(ct.as_bytes());
    h.update((ts as u64).to_be_bytes());
    format!("0x{}", crate::crypto::hex(h.finalize().as_slice()))
}

#[derive(Clone, Debug)]
pub struct Raw {
    pub payload: Vec<u8>,
    pub recv: Instant,
}
#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct PollStats {
    pub polls: u64,
    pub nonempty: u64,
    pub max_batch: u64,
    pub msgs: u64,
    pub errors: u64,
    pub last_error: String,
}
pub type Callback = Arc<dyn Fn(Raw) + Send + Sync>;
pub struct Poller {
    stop: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<PollStats>,
}
/// One poller per (node, content topic). GET is destructive, so exactly one poller may read a topic on a node;
/// callers fan the messages out to every logical client that shares the topic via `cb`.
pub fn spawn_poller(
    api: Api,
    node: &'static str,
    topic: String,
    every: Duration,
    cb: Callback,
) -> Poller {
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let handle = tokio::spawn(async move {
        let mut st = PollStats::default();
        loop {
            let stopping = s2.load(Ordering::SeqCst);
            match api.poll(node, &topic).await {
                Ok(v) => {
                    let recv = Instant::now();
                    st.polls += 1;
                    if !v.is_empty() {
                        st.nonempty += 1;
                        st.max_batch = st.max_batch.max(v.len() as u64);
                    }
                    for m in v {
                        st.msgs += 1;
                        if let Ok(payload) = B64.decode(&m.payload) {
                            cb(Raw { payload, recv });
                        } else {
                            st.errors += 1;
                            st.last_error = "bad base64 from node".into();
                        }
                    }
                }
                Err(e) => {
                    st.errors += 1;
                    st.last_error = e;
                }
            }
            if stopping {
                break;
            }
            tokio::time::sleep(every).await;
        }
        st
    });
    Poller { stop, handle }
}
impl Poller {
    pub async fn finish(self) -> PollStats {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.await.unwrap_or_default()
    }
}

pub fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted
        .get(rank.min(sorted.len()) - 1)
        .copied()
        .unwrap_or(f64::NAN)
}
pub fn lat_summary(mut v: Vec<f64>) -> serde_json::Value {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    serde_json::json!({"n": v.len(), "p50_ms": r1(pct(&v, 50.0)), "p95_ms": r1(pct(&v, 95.0)), "p99_ms": r1(pct(&v, 99.0)), "max_ms": r1(v.last().copied().unwrap_or(f64::NAN))})
}
fn r1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

pub async fn docker(args: &[&str]) -> (bool, String) {
    match tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
    {
        Ok(o) => (
            o.status.success(),
            String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout),
        ),
        Err(e) => (false, e.to_string()),
    }
}
