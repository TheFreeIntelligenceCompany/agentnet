//! Spike A1 / transport path (3): Rust adapter -> local Logos Delivery node via REST.
//! Everything here targets the localhost-published ports of the docker topology in ../relay (LOCALHOST TEST).
//! Usage: transport-rest-probe <basic|burst|offline|all> [--n 100] [--interval-ms 25] [--poll-ms 25] [--offline-n 20]
//!        [--out DIR] [--no-docker]
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const NA: &str = "http://127.0.0.1:18641";
const NB: &str = "http://127.0.0.1:18642";
const R1: &str = "http://127.0.0.1:18640";
const PUBSUB: &str = "/waku/2/rs/66/0";

fn now_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Body {
    run: String,
    src: String,
    seq: u32,
    sent_ns: u128,
    pad: String,
    sum: String, // sha256(run|src|seq|pad) hex - end-to-end integrity check independent of transport
}
fn body_sum(run: &str, src: &str, seq: u32, pad: &str) -> String {
    hex(&Sha256::digest(format!("{run}|{src}|{seq}|{pad}").as_bytes()))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct RelayMsg {
    payload: String,
    content_topic: Option<String>,
    timestamp: Option<i64>,
    #[serde(default)]
    meta: Option<String>,
}
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StoreMsgInner {
    payload: String,
    content_topic: String,
    timestamp: i64,
    #[serde(default)]
    meta: Option<String>,
}
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StoreEntry {
    message_hash: String,
    message: Option<StoreMsgInner>,
    pubsub_topic: Option<String>,
}
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StoreResp {
    status_code: u32,
    status_desc: String,
    messages: Vec<StoreEntry>,
    pagination_cursor: Option<String>,
}

/// Waku deterministic message hash (14/WAKU2-MESSAGE): sha256(pubsub || payload || contentTopic || meta || ts_be8)
fn waku_hash(pubsub: &str, payload: &[u8], ct: &str, meta: &[u8], ts: i64) -> String {
    let mut h = Sha256::new();
    h.update(pubsub.as_bytes());
    h.update(payload);
    h.update(ct.as_bytes());
    h.update(meta);
    h.update((ts as u64).to_be_bytes());
    format!("0x{}", hex(&h.finalize()))
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

#[derive(Clone)]
struct Api {
    http: reqwest::Client,
}
impl Api {
    async fn subscribe(&self, node: &str, ct: &str) -> Result<(), String> {
        let r = self.http.post(format!("{node}/relay/v1/auto/subscriptions")).json(&[ct]).send().await.map_err(|e| e.to_string())?;
        if r.status().is_success() { Ok(()) } else { Err(format!("{} {}", r.status(), r.text().await.unwrap_or_default())) }
    }
    /// returns (http status, body text, publish latency)
    async fn publish(&self, node: &str, ct: &str, payload: &[u8]) -> (u16, String, Duration) {
        let t = Instant::now();
        let r = self
            .http
            .post(format!("{node}/relay/v1/auto/messages"))
            .json(&serde_json::json!({"payload": B64.encode(payload), "contentTopic": ct, "ephemeral": false}))
            .send()
            .await;
        match r {
            Ok(r) => {
                let s = r.status().as_u16();
                (s, r.text().await.unwrap_or_default(), t.elapsed())
            }
            Err(e) => (0, e.to_string(), t.elapsed()),
        }
    }
    async fn poll(&self, node: &str, ct: &str) -> Result<Vec<RelayMsg>, String> {
        let r = self.http.get(format!("{node}/relay/v1/auto/messages/{}", enc(ct))).send().await.map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!("{} {}", r.status(), r.text().await.unwrap_or_default()));
        }
        r.json().await.map_err(|e| e.to_string())
    }
    async fn store_page(&self, node: &str, ct: &str, start: u128, end: u128, cursor: Option<&str>, page: u32, peer: Option<&str>) -> Result<StoreResp, String> {
        let mut u = format!("{node}/store/v3/messages?contentTopics={}&includeData=true&ascending=true&pageSize={page}&startTime={start}&endTime={end}", enc(ct));
        if let Some(c) = cursor { u += &format!("&cursor={}", enc(c)); }
        if let Some(p) = peer { u += &format!("&peerAddr={}", enc(p)); }
        let r = self.http.get(u).send().await.map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!("{} {}", r.status(), r.text().await.unwrap_or_default()));
        }
        r.json().await.map_err(|e| e.to_string())
    }
    async fn connected_peers(&self, node: &str) -> usize {
        match self.http.get(format!("{node}/admin/v1/peers")).send().await {
            Ok(r) => r.json::<Vec<serde_json::Value>>().await.map(|v| v.iter().filter(|p| p["connected"] == "Connected").count()).unwrap_or(0),
            Err(_) => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Rx {
    node: String,
    id: String, // run:src:seq
    src: String,
    seq: u32,
    recv_ns: u128,
    sent_ns: u128,
    ts: i64,
    hash: String,
    integrity_ok: bool,
}

struct Poller {
    stop: Arc<tokio::sync::Notify>,
    out: Arc<Mutex<Vec<Rx>>>,
    polls: Arc<Mutex<(u64, u64, u64)>>, // polls, non-empty polls, max batch
    handle: tokio::task::JoinHandle<()>,
}
fn spawn_poller(api: Api, node: &'static str, name: &str, ct: String, run: String, every: Duration) -> Poller {
    let stop = Arc::new(tokio::sync::Notify::new());
    let out = Arc::new(Mutex::new(Vec::new()));
    let polls = Arc::new(Mutex::new((0u64, 0u64, 0u64)));
    let (s2, o2, p2, name) = (stop.clone(), out.clone(), polls.clone(), name.to_string());
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = s2.notified() => break,
                _ = tokio::time::sleep(every) => {}
            }
            let recv_ns = now_ns();
            match api.poll(node, &ct).await {
                Ok(v) => {
                    let mut p = p2.lock().await;
                    p.0 += 1;
                    if !v.is_empty() { p.1 += 1; p.2 = p.2.max(v.len() as u64); }
                    drop(p);
                    let mut o = o2.lock().await;
                    for m in v {
                        let raw = B64.decode(&m.payload).unwrap_or_default();
                        let (mut src, mut seq, mut sent, mut ok, mut id) = ("?".to_string(), 0, 0, false, String::new());
                        if let Ok(b) = serde_json::from_slice::<Body>(&raw) {
                            ok = b.sum == body_sum(&b.run, &b.src, b.seq, &b.pad) && b.run == run;
                            src = b.src.clone(); seq = b.seq; sent = b.sent_ns; id = format!("{}:{}:{}", b.run, b.src, b.seq);
                        }
                        let ts = m.timestamp.unwrap_or(0);
                        let meta = m.meta.as_deref().map(|x| B64.decode(x).unwrap_or_default()).unwrap_or_default();
                        let hash = waku_hash(PUBSUB, &raw, m.content_topic.as_deref().unwrap_or(""), &meta, ts);
                        o.push(Rx { node: name.clone(), id, src, seq, recv_ns, sent_ns: sent, ts, hash, integrity_ok: ok });
                    }
                }
                Err(e) => eprintln!("[{name}] poll error: {e}"),
            }
        }
    });
    Poller { stop, out, polls, handle }
}
impl Poller {
    async fn finish(self) -> (Vec<Rx>, (u64, u64, u64)) {
        self.stop.notify_one();
        let _ = self.handle.await;
        let o = self.out.lock().await.clone();
        let p = *self.polls.lock().await;
        (o, p)
    }
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() { return f64::NAN; }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[rank.min(sorted.len()) - 1]
}

#[derive(Serialize)]
struct DirReport {
    direction: String,
    sent: usize,
    publish_http_failures: usize,
    delivered_unique: usize,
    delivery_rate: f64,
    duplicates: usize,
    own_echo_seen_by_sender: usize,
    integrity_failures: usize,
    ordering_violations: usize,
    latency_ms_p50: f64,
    latency_ms_p95: f64,
    latency_ms_p99: f64,
    latency_ms_max: f64,
    publish_call_ms_p50: f64,
    publish_call_ms_p95: f64,
    missing_seqs: Vec<u32>,
    poll_calls_receiver: u64,
    poll_nonempty_receiver: u64,
    max_batch_receiver: u64,
}

fn analyse(dir: &str, src: &str, sent: u32, pub_fail: usize, pub_ms: &mut Vec<f64>, rx: &[Rx], sender_rx: &[Rx], polls: (u64, u64, u64), csv: &mut String, run: &str) -> DirReport {
    let mut seen: HashSet<String> = HashSet::new();
    let (mut dups, mut integ, mut viol) = (0, 0, 0);
    let mut max_seq: i64 = -1;
    let mut lat = vec![];
    for r in rx.iter().filter(|r| r.src == src) {
        let dup = !seen.insert(r.id.clone());
        if dup { dups += 1; }
        if !r.integrity_ok { integ += 1; }
        if (r.seq as i64) < max_seq { viol += 1; }
        max_seq = max_seq.max(r.seq as i64);
        let l = (r.recv_ns.saturating_sub(r.sent_ns)) as f64 / 1e6;
        if !dup { lat.push(l); }
        csv.push_str(&format!("{dir},{},{},{},{},{:.3},{},{},{}\n", r.seq, r.sent_ns, r.recv_ns, l, dup, r.integrity_ok, r.ts, r.hash));
    }
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    pub_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let missing: Vec<u32> = (0..sent).filter(|s| !seen.contains(&format!("{run}:{src}:{s}"))).collect();
    DirReport {
        direction: dir.into(), sent: sent as usize, publish_http_failures: pub_fail,
        delivered_unique: seen.len(), delivery_rate: seen.len() as f64 / sent as f64, duplicates: dups,
        own_echo_seen_by_sender: sender_rx.iter().filter(|r| r.src == src).count(),
        integrity_failures: integ, ordering_violations: viol,
        latency_ms_p50: pct(&lat, 50.0), latency_ms_p95: pct(&lat, 95.0), latency_ms_p99: pct(&lat, 99.0), latency_ms_max: lat.last().copied().unwrap_or(f64::NAN),
        publish_call_ms_p50: pct(pub_ms, 50.0), publish_call_ms_p95: pct(pub_ms, 95.0),
        missing_seqs: missing, poll_calls_receiver: polls.0, poll_nonempty_receiver: polls.1, max_batch_receiver: polls.2,
    }
}

struct Cfg { n: u32, interval: Duration, poll: Duration, offline_n: u32, out: String, docker: bool }

async fn send_stream(api: &Api, node: &str, ct: &str, run: &str, src: &str, n: u32, interval: Duration, pad_len: usize) -> (usize, Vec<f64>, Vec<String>) {
    let mut fails = 0; let mut ms = vec![]; let mut errs = vec![];
    for seq in 0..n {
        let pad = "x".repeat(pad_len);
        let b = Body { run: run.into(), src: src.into(), seq, sent_ns: now_ns(), sum: body_sum(run, src, seq, &pad), pad };
        let (st, body, d) = api.publish(node, ct, &serde_json::to_vec(&b).unwrap()).await;
        ms.push(d.as_secs_f64() * 1e3);
        if st != 200 { fails += 1; errs.push(format!("seq {seq}: {st} {body}")); }
        if !interval.is_zero() { tokio::time::sleep(interval).await; }
    }
    (fails, ms, errs)
}

async fn basic(api: &Api, cfg: &Cfg, run: &str) -> serde_json::Value {
    let ct = format!("/agentnet/1/probe-{run}/proto");
    api.subscribe(NA, &ct).await.unwrap(); api.subscribe(NB, &ct).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await; // let mesh/graft settle
    let pa = spawn_poller(api.clone(), NA, "A", ct.clone(), run.into(), cfg.poll);
    let pb = spawn_poller(api.clone(), NB, "B", ct.clone(), run.into(), cfg.poll);
    let mut csv = String::from("direction,seq,sent_ns,recv_ns,latency_ms,duplicate,integrity_ok,waku_ts,waku_hash\n");
    // A -> B
    let (f1, mut m1, e1) = send_stream(api, NA, &ct, run, "A", cfg.n, cfg.interval, 200).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    // B -> A
    let (f2, mut m2, e2) = send_stream(api, NB, &ct, run, "B", cfg.n, cfg.interval, 200).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (rxa, polls_a) = pa.finish().await;
    let (rxb, polls_b) = pb.finish().await;
    let r_ab = analyse("A->B", "A", cfg.n, f1, &mut m1, &rxb, &rxa, polls_b, &mut csv, run);
    let r_ba = analyse("B->A", "B", cfg.n, f2, &mut m2, &rxa, &rxb, polls_a, &mut csv, run);
    std::fs::write(format!("{}/rust-basic-{run}.csv", cfg.out), &csv).unwrap();
    // cross-check: every relay-observed hash must equal the hash R1's store reports for the same message
    let (s, e) = (rxb.iter().chain(rxa.iter()).map(|r| r.sent_ns).min().unwrap_or(0).saturating_sub(5_000_000_000), now_ns());
    let mut store: HashMap<String, StoreEntry> = HashMap::new();
    let mut cursor: Option<String> = None;
    loop {
        match api.store_page(R1, &ct, s, e, cursor.as_deref(), 100, None).await {
            Ok(p) => { for m in p.messages { store.insert(m.message_hash.clone(), m); } cursor = p.pagination_cursor; if cursor.is_none() { break; } }
            Err(e) => { eprintln!("store: {e}"); break; }
        }
    }
    let relay_hashes: HashSet<String> = rxb.iter().chain(rxa.iter()).map(|r| r.hash.clone()).collect();
    let in_store = relay_hashes.iter().filter(|h| store.contains_key(*h)).count();
    serde_json::json!({
        "content_topic": ct, "n_per_direction": cfg.n, "publish_interval_ms": cfg.interval.as_millis(), "poll_interval_ms": cfg.poll.as_millis(),
        "A_to_B": r_ab, "B_to_A": r_ba, "publish_errors": [e1, e2],
        "hash_crosscheck": {"distinct_relay_observed_hashes": relay_hashes.len(), "found_in_R1_store_with_identical_hash": in_store, "store_total_for_topic": store.len()},
    })
}

/// Publish a burst faster than a slow poller can drain: shows REST cache capacity (50) eviction.
async fn burst(api: &Api, cfg: &Cfg, run: &str) -> serde_json::Value {
    let ct = format!("/agentnet/1/probe-{run}-burst/proto");
    api.subscribe(NA, &ct).await.unwrap(); api.subscribe(NB, &ct).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut out = vec![];
    for (burst_n, poll_ms) in [(40u32, 1500u64), (100, 1500), (100, 100)] {
        let _ = api.poll(NB, &ct).await; // drain
        let pb = spawn_poller(api.clone(), NB, "B", ct.clone(), run.into(), Duration::from_millis(poll_ms));
        let src = format!("A{burst_n}-{poll_ms}");
        let t = Instant::now();
        let (fails, _ms, _e) = send_stream(api, NA, &ct, run, &src, burst_n, Duration::ZERO, 50).await;
        let send_secs = t.elapsed().as_secs_f64();
        tokio::time::sleep(Duration::from_millis(poll_ms * 2 + 500)).await;
        let (rx, polls) = pb.finish().await;
        let got: HashSet<u32> = rx.iter().filter(|r| r.src == src).map(|r| r.seq).collect();
        let missing: Vec<u32> = (0..burst_n).filter(|s| !got.contains(s)).collect();
        out.push(serde_json::json!({"burst": burst_n, "poll_ms": poll_ms, "send_secs": send_secs, "publish_failures": fails, "received": got.len(), "lost": missing.len(), "lost_first": missing.iter().take(5).collect::<Vec<_>>(), "lost_last": missing.iter().rev().take(5).collect::<Vec<_>>(), "max_batch_per_poll": polls.2}));
    }
    serde_json::json!(out)
}

async fn docker(args: &[&str]) -> (bool, String) {
    let o = tokio::process::Command::new("docker").args(args).output().await;
    match o { Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout)), Err(e) => (false, e.to_string()) }
}

async fn offline(api: &Api, cfg: &Cfg, run: &str) -> serde_json::Value {
    let ct = format!("/agentnet/1/probe-{run}-offline/proto");
    api.subscribe(NA, &ct).await.unwrap(); api.subscribe(NB, &ct).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    // one live message first so we know B is receiving
    let pb = spawn_poller(api.clone(), NB, "B", ct.clone(), run.into(), cfg.poll);
    send_stream(api, NA, &ct, run, "A-live", 1, Duration::ZERO, 20).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (live_rx, _) = pb.finish().await;
    let t_offline = now_ns();
    let t_stop = Instant::now();
    let (ok, o) = docker(&["stop", "-t", "10", "an-nb"]).await;
    let stop_secs = t_stop.elapsed().as_secs_f64();
    assert!(ok, "docker stop failed: {o}");
    let (fails, _m, errs) = send_stream(api, NA, &ct, run, "A-off", cfg.offline_n, Duration::from_millis(50), 200).await;
    let t_pub_done = now_ns();
    // B comes back
    let t_start = Instant::now();
    let (ok, o) = docker(&["start", "an-nb"]).await;
    assert!(ok, "docker start failed: {o}");
    let mut t_rest_up = None;
    for _ in 0..600 {
        if api.http.get(format!("{NB}/health")).send().await.map(|r| r.status().is_success()).unwrap_or(false) { t_rest_up = Some(t_start.elapsed().as_secs_f64()); break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut t_peer = None;
    for _ in 0..1200 {
        if api.connected_peers(NB).await >= 1 { t_peer = Some(t_start.elapsed().as_secs_f64()); break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // restart loses in-memory REST subscriptions: check what NB's relay cache says before we resubscribe
    let poll_before_resub = api.poll(NB, &ct).await.map(|v| v.len().to_string()).unwrap_or_else(|e| e);
    let _ = api.subscribe(NB, &ct).await;
    // recover via store, using the NB's own store client (storenode configured) - no peerAddr given
    let t_q0 = Instant::now();
    let mut got: Vec<StoreEntry> = vec![];
    let mut pages = 0; let mut cursor: Option<String> = None; let mut errs2 = vec![];
    let end = now_ns();
    loop {
        match api.store_page(NB, &ct, t_offline.saturating_sub(1_000_000_000), end, cursor.as_deref(), 7, None).await {
            Ok(p) => { pages += 1; got.extend(p.messages); cursor = p.pagination_cursor; if cursor.is_none() { break; } }
            Err(e) => { errs2.push(e); tokio::time::sleep(Duration::from_millis(500)).await; if errs2.len() > 20 { break; } }
        }
    }
    let recover_secs = t_q0.elapsed().as_secs_f64();
    let mut ids = HashSet::new(); let mut bad = 0; let mut seqs = vec![]; let mut hash_ok = 0;
    for e in &got {
        if let Some(m) = &e.message {
            let raw = B64.decode(&m.payload).unwrap_or_default();
            if let Ok(b) = serde_json::from_slice::<Body>(&raw) {
                if b.sum != body_sum(&b.run, &b.src, b.seq, &b.pad) { bad += 1; }
                if b.src == "A-off" { ids.insert(b.seq); seqs.push(b.seq); }
            }
            let meta = m.meta.as_deref().map(|x| B64.decode(x).unwrap_or_default()).unwrap_or_default();
            if waku_hash(e.pubsub_topic.as_deref().unwrap_or(PUBSUB), &raw, &m.content_topic, &meta, m.timestamp) == e.message_hash { hash_ok += 1; }
        }
    }
    let in_order = seqs.windows(2).all(|w| w[0] < w[1]);
    // idempotency: second identical query returns the same hashes
    let mut got2 = 0;
    let mut c2: Option<String> = None;
    loop {
        match api.store_page(NB, &ct, t_offline.saturating_sub(1_000_000_000), end, c2.as_deref(), 100, None).await {
            Ok(p) => { got2 += p.messages.len(); c2 = p.pagination_cursor; if c2.is_none() { break; } }
            Err(_) => break,
        }
    }
    let missing: Vec<u32> = (0..cfg.offline_n).filter(|s| !ids.contains(s)).collect();
    let _ = (t_pub_done, live_rx.len());
    serde_json::json!({
        "content_topic": ct, "offline_messages": cfg.offline_n, "publish_failures_while_B_down": fails, "publish_errors": errs,
        "docker_stop_secs": stop_secs, "B_rest_healthy_after_secs": t_rest_up, "B_connected_to_R1_after_secs": t_peer,
        "B_relay_cache_after_restart_before_resubscribe": poll_before_resub,
        "store_query_via_B_pageSize7": {"pages": pages, "entries": got.len(), "unique_offline_seqs": ids.len(), "missing": missing, "in_ascending_order": in_order,
            "integrity_failures": bad, "entries_whose_hash_matches_local_recompute": hash_ok, "total_secs": recover_secs, "errors": errs2},
        "second_identical_query_entries": got2,
    })
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a.get(1).cloned().unwrap_or_else(|| "all".into());
    let get = |k: &str, d: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).cloned().unwrap_or_else(|| d.into());
    let cfg = Cfg {
        n: get("--n", "100").parse().unwrap(), interval: Duration::from_millis(get("--interval-ms", "25").parse().unwrap()),
        poll: Duration::from_millis(get("--poll-ms", "25").parse().unwrap()), offline_n: get("--offline-n", "20").parse().unwrap(),
        out: get("--out", "../../results/a1-daemon"), docker: !a.contains(&"--no-docker".to_string()),
    };
    let _ = cfg.docker;
    std::fs::create_dir_all(&cfg.out).unwrap();
    let api = Api { http: reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap() };
    let run = format!("{:x}", now_ns() / 1_000_000 % 0xfffffff);
    let mut report = serde_json::json!({"run": run, "mode": mode, "note": "LOCALHOST/container-network test; synthetic payloads", "started_ns": now_ns().to_string()});
    if mode == "basic" || mode == "all" { report["basic"] = basic(&api, &cfg, &run).await; }
    if mode == "burst" || mode == "all" { report["burst"] = burst(&api, &cfg, &run).await; }
    if mode == "offline" || mode == "all" { report["offline"] = offline(&api, &cfg, &run).await; }
    let path = format!("{}/rust-probe-{mode}-{run}.json", cfg.out);
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    eprintln!("wrote {path}");
}
