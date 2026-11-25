//! Integration tests against the real spike topology in `spike/relay`
//! (R1 service node + clients A=18641 and B=18642). LOCALHOST / container-network
//! tests only.
//!
//! Gated: every test returns early (printing "skipped") unless the environment
//! variable `AGENTNET_RELAY_TESTS=1` is set. Tests that disturb the topology
//! (`#[ignore]`) additionally need `--ignored` and `AGENTNET_RELAY_DISRUPTIVE=1`.
#![cfg(feature = "logos-rest")]

use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentnet_transport::logos_rest::{LogosRestConfig, LogosRestTransport, NetworkMode};
use agentnet_transport::{
    ContentTopic, FrameSource, HistoryQuery, InboundFrame, Transport, TransportError,
};
use base64::Engine;

const NODE_A: &str = "http://127.0.0.1:18641";
const NODE_B: &str = "http://127.0.0.1:18642";
const R1_MULTIADDR_PREFIX: &str = "/ip4/172.28.66.10/tcp/60000/p2p/";

/// The tests share two nodes with 50-slot caches: run them one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn enabled() -> bool {
    if std::env::var("AGENTNET_RELAY_TESTS").as_deref() == Ok("1") {
        true
    } else {
        println!("skipped (set AGENTNET_RELAY_TESTS=1 to run against the spike relay)");
        false
    }
}

fn r1_peer_id() -> String {
    if let Ok(v) = std::env::var("AGENTNET_R1_PEER_ID") {
        return v;
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spike/relay/.env");
    let text = std::fs::read_to_string(path).expect("spike/relay/.env readable");
    text.lines()
        .find_map(|l| l.strip_prefix("R1_PEER_ID="))
        .expect("R1_PEER_ID in .env")
        .trim()
        .to_string()
}

fn now_ns() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap()
}

fn unique_topic() -> ContentTopic {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    ContentTopic::new(format!(
        "/agentnet/1/ttest-{:x}{:02x}/proto",
        (now_ns() / 1000) & 0xffff_ffff_ffff,
        n
    ))
    .unwrap()
}

fn config(url: &str, allowed: Vec<String>) -> LogosRestConfig {
    LogosRestConfig {
        node_url: url.into(),
        mode: NetworkMode::Private,
        allowed_peer_ids: allowed,
        cluster_id: 66,
        shard: 0,
        num_shards: 1,
        request_timeout: Duration::from_secs(8),
        // Short so a wrong allowlist is noticed quickly in the disruptive tests.
        audit_interval: Duration::from_secs(2),
        ..Default::default()
    }
}

fn adapter(url: &str) -> LogosRestTransport {
    LogosRestTransport::new(config(url, vec![r1_peer_id()])).unwrap()
}

/// Retries `Unavailable` (another agent may be restarting containers).
async fn retry<T, F, Fut>(what: &str, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, TransportError>>,
{
    let mut last = None;
    for _ in 0..40 {
        match f().await {
            Ok(v) => return v,
            Err(e) if e.is_retryable() && !matches!(e, TransportError::Isolation(_)) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("{what}: non-retryable error: {e}"),
        }
    }
    panic!("{what}: still failing after retries: {last:?}");
}

/// Polls fast until `want` frames arrived or `within` elapsed.
async fn collect(
    t: &LogosRestTransport,
    topic: &ContentTopic,
    want: usize,
    within: Duration,
) -> Vec<InboundFrame> {
    let deadline = Instant::now() + within;
    let mut got = Vec::new();
    while got.len() < want && Instant::now() < deadline {
        match t.poll(topic).await {
            Ok(mut v) => got.append(&mut v),
            Err(e) if e.is_retryable() => {}
            Err(e) => panic!("poll: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    got
}

async fn history_all(
    t: &LogosRestTransport,
    topic: &ContentTopic,
    start: i64,
    limit: u32,
) -> (Vec<InboundFrame>, usize) {
    let mut cursor = None;
    let mut frames = Vec::new();
    let mut pages = 0;
    loop {
        let q = HistoryQuery {
            topic: topic.clone(),
            start_ns: start,
            end_ns: now_ns() + 2_000_000_000,
            cursor: cursor.clone(),
            limit,
        };
        let page = retry("history", || t.history(&q)).await;
        pages += 1;
        frames.extend(page.frames);
        cursor = page.next_cursor;
        if cursor.is_none() || pages > 50 {
            return (frames, pages);
        }
    }
}

/// History is archived asynchronously by R1: wait until `want` ids are visible.
async fn history_until(
    t: &LogosRestTransport,
    topic: &ContentTopic,
    start: i64,
    limit: u32,
    want: usize,
) -> (Vec<InboundFrame>, usize) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let (f, p) = history_all(t, topic, start, limit).await;
        let uniq: HashSet<_> = f.iter().map(|x| x.transport_id).collect();
        if uniq.len() >= want || Instant::now() > deadline {
            return (f, p);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn subscribe_both(a: &LogosRestTransport, b: &LogosRestTransport, topic: &ContentTopic) {
    retry("subscribe a", || a.subscribe(topic)).await;
    retry("subscribe b", || b.subscribe(topic)).await;
    // let the gossipsub mesh graft (the spike used 3 s)
    tokio::time::sleep(Duration::from_secs(3)).await;
}

#[tokio::test]
async fn a_to_b_and_b_to_a_with_identical_ids_in_live_and_history() {
    if !enabled() {
        return;
    }
    let _g = SERIAL.lock().await;
    let (a, b) = (adapter(NODE_A), adapter(NODE_B));
    let topic = unique_topic();
    let start = now_ns() - 2_000_000_000;
    subscribe_both(&a, &b, &topic).await;

    // A -> B
    let r1 = retry("publish a", || a.publish(&topic, b"hello from A")).await;
    let at_b = collect(&b, &topic, 1, Duration::from_secs(10)).await;
    assert_eq!(at_b.len(), 1, "B should receive exactly one frame");
    assert_eq!(at_b[0].payload, b"hello from A");
    assert_eq!(
        at_b[0].transport_id, r1.transport_id,
        "same id at receiver as at publisher"
    );
    assert_eq!(at_b[0].timestamp_ns, r1.timestamp_ns);
    assert_eq!(at_b[0].source, FrameSource::Live);
    // the real node echoes the publisher's own frame
    let at_a = collect(&a, &topic, 1, Duration::from_secs(5)).await;
    assert_eq!(at_a.len(), 1, "publisher sees its own frame");
    assert_eq!(at_a[0].transport_id, r1.transport_id);

    // B -> A
    let r2 = retry("publish b", || b.publish(&topic, b"hello from B")).await;
    let at_a = collect(&a, &topic, 1, Duration::from_secs(10)).await;
    assert_eq!(at_a.len(), 1);
    assert_eq!(at_a[0].payload, b"hello from B");
    assert_eq!(at_a[0].transport_id, r2.transport_id);
    let _ = collect(&b, &topic, 1, Duration::from_secs(3)).await; // drain own echo
    assert_ne!(r1.transport_id, r2.transport_id);

    // history through both nodes' store clients carries the same ids
    for (name, t) in [("A", &a), ("B", &b)] {
        let (frames, _) = history_until(t, &topic, start, 100, 2).await;
        let ids: BTreeSet<[u8; 32]> = frames.iter().map(|f| f.transport_id).collect();
        assert_eq!(
            ids,
            BTreeSet::from([r1.transport_id, r2.transport_id]),
            "history via {name}"
        );
        assert!(frames.iter().all(|f| f.source == FrameSource::History));
        let first = frames
            .iter()
            .find(|f| f.transport_id == r1.transport_id)
            .unwrap();
        assert_eq!(first.payload, b"hello from A");
        assert_eq!(first.timestamp_ns, r1.timestamp_ns);
    }
    let m = a.metrics();
    assert_eq!(m.hash_mismatches, 0, "local hash must equal the Store's");
    assert_eq!(b.metrics().hash_mismatches, 0);

    // second poll is empty (destructive read)
    assert!(a.poll(&topic).await.unwrap().is_empty());
}

#[tokio::test]
async fn history_paginates_across_pages_and_dedupes_against_live() {
    if !enabled() {
        return;
    }
    let _g = SERIAL.lock().await;
    let (a, b) = (adapter(NODE_A), adapter(NODE_B));
    let topic = unique_topic();
    let start = now_ns() - 2_000_000_000;
    subscribe_both(&a, &b, &topic).await;

    const N: usize = 12;
    let mut sent = BTreeSet::new();
    for i in 0..N {
        let body = format!("msg-{i:02}").into_bytes();
        let r = retry("publish", || a.publish(&topic, &body)).await;
        sent.insert(r.transport_id);
    }
    let live = collect(&b, &topic, N, Duration::from_secs(15)).await;
    let live_ids: BTreeSet<[u8; 32]> = live.iter().map(|f| f.transport_id).collect();
    // Live delivery is best effort (observed to lose frames occasionally when the
    // shared nodes are loaded); History is the recovery path and the authority.
    println!("live frames received by B: {}/{N}", live_ids.len());
    assert!(live_ids.is_subset(&sent), "live frames must all be ours");
    assert!(
        live_ids.len() + 4 >= N,
        "live delivery far worse than expected"
    );

    let (frames, pages) = history_until(&b, &topic, start, 5, N).await;
    assert!(
        pages >= 3,
        "limit 5 over {N} frames needs >= 3 pages, got {pages}"
    );
    let history_ids: BTreeSet<[u8; 32]> = frames.iter().map(|f| f.transport_id).collect();
    assert_eq!(history_ids, sent);
    // pages are ascending by timestamp
    assert!(frames
        .windows(2)
        .all(|w| w[0].timestamp_ns <= w[1].timestamp_ns));
    // dedupe by transport_id: live ∪ history is exactly the sent set
    let mut seen: HashSet<[u8; 32]> = live.iter().map(|f| f.transport_id).collect();
    let new_from_history = frames
        .iter()
        .filter(|f| seen.insert(f.transport_id))
        .count();
    assert_eq!(
        new_from_history,
        N - live_ids.len(),
        "history only adds what live missed"
    );
    assert_eq!(seen.len(), N);

    // explicit store peer (private address, allow-listed id) works too
    let mut cfg = config(NODE_B, vec![r1_peer_id()]);
    cfg.store_peer = Some(format!("{R1_MULTIADDR_PREFIX}{}", r1_peer_id()));
    let b2 = LogosRestTransport::new(cfg).unwrap();
    let (f2, _) = history_until(&b2, &topic, start, 100, N).await;
    assert_eq!(f2.len(), N);
    let _ = collect(&a, &topic, N, Duration::from_secs(3)).await; // drain A's echo cache
}

fn payload_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn max_payload_len_is_accepted_and_delivered_and_one_more_is_rejected_locally() {
    if !enabled() {
        return;
    }
    let _g = SERIAL.lock().await;
    let (a, b) = (adapter(NODE_A), adapter(NODE_B));
    let topic = unique_topic();
    subscribe_both(&a, &b, &topic).await;

    let max = a.max_payload_len(&topic);
    println!("max_payload_len({}) = {max}", topic.as_str());
    let payload = payload_of(max);
    let r = retry("publish max", || a.publish(&topic, &payload)).await;
    let mut got = collect(&b, &topic, 1, Duration::from_secs(15)).await;
    if got.is_empty() {
        // Live relay delivery is best effort; fall back to the Store and say so.
        println!("NOTE: exact-max frame not received live within 15 s; checking history");
        let (h, _) = history_until(&b, &topic, now_ns() - 60_000_000_000, 100, 1).await;
        got = h;
    }
    assert_eq!(
        got.len(),
        1,
        "exact-max payload must be delivered (live or history)"
    );
    assert_eq!(got[0].payload.len(), max);
    assert_eq!(got[0].payload, payload);
    assert_eq!(got[0].transport_id, r.transport_id);
    let _ = collect(&a, &topic, 1, Duration::from_secs(3)).await;

    let e = a.publish(&topic, &payload_of(max + 1)).await.unwrap_err();
    assert_eq!(e, TransportError::TooLarge { size: max + 1, max });

    // Diagnostic (printed, asserted only loosely): where does the real node's
    // boundary lie relative to our formula? Raw publishes bypass the pre-check.
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let raw = |len: usize| {
        let (http, topic) = (http.clone(), topic.clone());
        async move {
            let body = serde_json::json!({
                "payload": base64::engine::general_purpose::STANDARD.encode(payload_of(len)),
                "contentTopic": topic.as_str(),
                "timestamp": now_ns(),
                "ephemeral": false,
            });
            let r = http
                .post(format!("{NODE_A}/relay/v1/auto/messages"))
                .header("content-type", "application/json")
                .body(body.to_string())
                .send()
                .await
                .unwrap();
            r.status().as_u16() == 200
        }
    };
    let (mut lo, mut hi) = (max, max + 80); // lo accepted (proved above), hi expected rejected
    assert!(
        !raw(hi).await,
        "payload {hi} should be rejected by the node"
    );
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if raw(mid).await {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    println!(
        "measured node boundary for topic of {} bytes: largest accepted payload = {lo}; our max_payload_len = {max}; slack = {}",
        topic.as_str().len(),
        lo - max
    );
    assert!(lo >= max, "node must accept at least our computed max");
    let _ = collect(&a, &topic, 100, Duration::from_millis(500)).await;
    let _ = collect(&b, &topic, 100, Duration::from_millis(500)).await;
}

#[tokio::test]
async fn isolation_audit_passes_with_right_allowlist_and_fails_closed_with_wrong_one() {
    if !enabled() {
        return;
    }
    let _g = SERIAL.lock().await;
    let topic = unique_topic();
    let good = adapter(NODE_A);
    retry("audit", || good.audit()).await;
    let s = good.status().await;
    println!("status: {s:?}");
    assert!(s.isolation_violation.is_none());
    assert!(s
        .peers
        .iter()
        .any(|p| p.connected && p.allowed && p.peer_id == r1_peer_id()));
    assert!(
        s.ready || !s.peers.iter().any(|p| p.connected),
        "ready iff connected to R1"
    );

    let bad = LogosRestTransport::new(config(
        NODE_A,
        vec!["16Uiu2HAmWrongWrongWrongWrongWrongWrongWrongWrong1".into()],
    ))
    .unwrap();
    let q = HistoryQuery {
        topic: topic.clone(),
        start_ns: now_ns() - 1_000_000_000,
        end_ns: now_ns(),
        cursor: None,
        limit: 10,
    };
    let mut isolation_errors = 0;
    for _ in 0..40 {
        // R1 might be reconnecting; wait until it is connected so the audit has something to reject
        let r = bad.publish(&topic, b"must not leave").await;
        match r {
            Err(TransportError::Isolation(_)) => {
                isolation_errors += 1;
                break;
            }
            Err(TransportError::Unavailable(_)) => {
                tokio::time::sleep(Duration::from_millis(500)).await
            }
            other => panic!("expected Isolation, got {other:?}"),
        }
    }
    assert_eq!(
        isolation_errors, 1,
        "publish must fail closed with Isolation"
    );
    assert!(matches!(
        bad.poll(&topic).await,
        Err(TransportError::Isolation(_))
    ));
    assert!(matches!(
        bad.history(&q).await,
        Err(TransportError::Isolation(_))
    ));
    assert!(matches!(
        bad.subscribe(&topic).await,
        Err(TransportError::Isolation(_))
    ));
    let s = bad.status().await;
    assert!(!s.ready);
    assert!(s.isolation_violation.is_some());
    assert!(s.peers.iter().any(|p| p.connected && !p.allowed));
    println!("violation text: {:?}", s.isolation_violation);

    // nothing was published: the topic is empty in history
    let reader = adapter(NODE_B);
    let (frames, _) = history_all(&reader, &topic, now_ns() - 5_000_000_000, 100).await;
    assert!(
        frames.is_empty(),
        "the blocked publish must not have reached the network"
    );
}

#[tokio::test]
async fn private_mode_config_rejects_public_ip_and_hostnames() {
    // Not gated: needs no network at all.
    for url in [
        "http://8.8.8.8:8645",
        "http://93.184.216.34:8645",
        "http://example.com:8645",
        "http://node.internal.example:8645",
        "https://example.com",
    ] {
        let r = LogosRestTransport::new(config(url, vec![r1_peer_id_or_dummy()]));
        assert!(
            matches!(r.as_ref().err(), Some(TransportError::Isolation(_))),
            "{url}: {:?}",
            r.err()
        );
    }
}

fn r1_peer_id_or_dummy() -> String {
    std::env::var("AGENTNET_R1_PEER_ID").unwrap_or_else(|_| "16Uiu2HAmDummy".to_string())
}

// ---------------------------------------------------------------------------
// Disruptive tests: restart containers of the spike topology. #[ignore]d; run
// last, only when nobody else is using the topology.
// ---------------------------------------------------------------------------

fn docker(args: &[&str]) {
    let out = std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker");
    assert!(
        out.status.success(),
        "docker {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn disruptive_enabled() -> bool {
    if enabled() && std::env::var("AGENTNET_RELAY_DISRUPTIVE").as_deref() == Ok("1") {
        true
    } else {
        println!("skipped (needs AGENTNET_RELAY_TESTS=1 and AGENTNET_RELAY_DISRUPTIVE=1)");
        false
    }
}

/// Waits until `t` reports ready (connected to R1); can take about two minutes.
async fn wait_ready(t: &LogosRestTransport) {
    let deadline = Instant::now() + Duration::from_secs(240);
    while Instant::now() < deadline {
        if t.status().await.ready {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!("node did not become ready again");
}

#[tokio::test]
#[ignore = "restarts container an-na; run last with AGENTNET_RELAY_DISRUPTIVE=1 -- --ignored"]
async fn node_restart_triggers_transparent_resubscribe() {
    if !disruptive_enabled() {
        return;
    }
    let _g = SERIAL.lock().await;
    let (a, b) = (adapter(NODE_A), adapter(NODE_B));
    let topic = unique_topic();
    subscribe_both(&a, &b, &topic).await;
    docker(&["restart", "an-na"]);
    wait_ready(&a).await;
    // first poll after the restart sees 404, resubscribes, returns empty
    let mut resub = 0;
    for _ in 0..40 {
        if a.poll(&topic).await.is_ok() {
            resub = a.metrics().resubscribes;
            if resub > 0 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(resub, 1, "exactly one transparent resubscribe");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let r = retry("publish b", || b.publish(&topic, b"after restart")).await;
    let got = collect(&a, &topic, 1, Duration::from_secs(10)).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].transport_id, r.transport_id);
}

#[tokio::test]
#[ignore = "stops container an-r1; run last with AGENTNET_RELAY_DISRUPTIVE=1 -- --ignored"]
async fn r1_down_gives_unavailable_and_history_unavailable() {
    if !disruptive_enabled() {
        return;
    }
    let _g = SERIAL.lock().await;
    let a = adapter(NODE_A);
    let topic = unique_topic();
    retry("subscribe", || a.subscribe(&topic)).await;
    docker(&["stop", "-t", "5", "an-r1"]);
    let outcome = async {
        // wait until the node notices the peer is gone
        let mut publish_err = None;
        for _ in 0..30 {
            match a.publish(&topic, b"nobody home").await {
                Err(e) => {
                    publish_err = Some(e);
                    break;
                }
                Ok(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
        let e = publish_err.expect("publish should fail while R1 is down");
        assert!(matches!(e, TransportError::Unavailable(_)), "{e:?}");
        let q = HistoryQuery {
            topic: topic.clone(),
            start_ns: now_ns() - 1_000_000_000,
            end_ns: now_ns(),
            cursor: None,
            limit: 10,
        };
        let e = a.history(&q).await.unwrap_err();
        assert!(matches!(e, TransportError::HistoryUnavailable(_)), "{e:?}");
        assert!(!a.status().await.ready);
    }
    .await;
    // restore: R1 first, then wait until the client reconnects
    docker(&["start", "an-r1"]);
    wait_ready(&a).await;
    outcome
}
