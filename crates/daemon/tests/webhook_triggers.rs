mod common;

use std::collections::{HashMap, HashSet};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentnet_core::api::*;
use agentnet_daemon::webhook::{
    verify_signature, HEADER_EVENT_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, SIGNATURE_TOLERANCE_S,
};
use agentnet_daemon::{DaemonConfig, EventStream};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use common::*;

const SECRET: &str = "0123456789abcdef0123456789abcdef-test-secret";

#[derive(Clone, Debug)]
struct Delivery {
    event_id: String,
    ts: String,
    sig: String,
    body: Vec<u8>,
}

#[derive(Default)]
struct Rx {
    calls: Mutex<Vec<Delivery>>,
    /// Number of initial calls that answer 500.
    fail_first: AtomicU32,
    /// Always answer 500.
    always_fail: std::sync::atomic::AtomicBool,
    landing_hits: AtomicU32,
}

async fn hook(State(rx): State<Arc<Rx>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let n = {
        let mut c = rx.calls.lock().unwrap();
        c.push(Delivery {
            event_id: h(HEADER_EVENT_ID),
            ts: h(HEADER_TIMESTAMP),
            sig: h(HEADER_SIGNATURE),
            body: body.to_vec(),
        });
        c.len() as u32
    };
    if rx.always_fail.load(Ordering::SeqCst) || n <= rx.fail_first.load(Ordering::SeqCst) {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    }
}

async fn redirect() -> (StatusCode, [(&'static str, &'static str); 1]) {
    (StatusCode::FOUND, [("Location", "/landing")])
}

async fn landing(State(rx): State<Arc<Rx>>) -> StatusCode {
    rx.landing_hits.fetch_add(1, Ordering::SeqCst);
    StatusCode::OK
}

async fn receiver() -> (Arc<Rx>, std::net::SocketAddr) {
    let rx = Arc::new(Rx::default());
    let app = Router::new()
        .route("/hook", post(hook))
        .route("/redirect", post(redirect))
        .route("/landing", post(landing).get(landing))
        .with_state(rx.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await });
    (rx, addr)
}

fn write_secret(dir: &std::path::Path, content: &str, mode: u32) {
    let p = dir.join("webhook.secret");
    let _ = std::fs::remove_file(&p);
    std::fs::write(&p, content).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn wh_cfg(addr: std::net::SocketAddr, path: &str, max_attempts: u32) -> DaemonConfig {
    let mut c = cfg();
    c.webhook.enabled = true;
    c.webhook.url = format!("http://{addr}{path}");
    c.webhook.secret_file = "webhook.secret".into();
    c.webhook.max_attempts = max_attempts;
    c.webhook.retry_base_ms = 10;
    c.webhook.retry_max_ms = 40;
    c.webhook.timeout_ms = 2000;
    c
}

async fn trigger(b: &Agent, a: &Agent, once: bool) -> TriggerInfo {
    b.remote
        .create_trigger(CreateTriggerRequest {
            sender: Some(a.address.clone()),
            target_session: "s1".into(),
            once: Some(once),
            expires_in_seconds: Some(3600),
            ..Default::default()
        })
        .await
        .unwrap()
}

async fn setup(w: &World, addr: std::net::SocketAddr, path: &str, attempts: u32) -> (Agent, Agent) {
    let (pb, addr_b, rec_b) = w.init("b");
    write_secret(&pb, SECRET, 0o600);
    let a = Agent::new(w, "a", cfg()).await;
    let daemon_b = w.start(&pb, wh_cfg(addr, path, attempts)).await;
    let b = Agent {
        remote: agentnet_daemon::RemoteAgent::new(&pb),
        path: pb,
        address: addr_b,
        record: rec_b,
        daemon: Some(daemon_b),
    };
    a.add_contact_of(&b).await;
    b.add_contact_of(&a).await;
    (a, b)
}

#[tokio::test]
async fn signed_delivery_verifies_and_carries_no_plaintext() {
    let w = World::new();
    let (rx, addr) = receiver().await;
    let (a, b) = setup(&w, addr, "/hook", 3).await;
    trigger(&b, &a, true).await;
    let mid = a.send(&b, "TOP-SECRET-PLAINTEXT").await;
    wait_until("webhook call", || async {
        !rx.calls.lock().unwrap().is_empty()
    })
    .await;
    let d = rx.calls.lock().unwrap()[0].clone();
    let now = w.clock.now_ns() / 1_000_000_000;
    verify_signature(
        SECRET.as_bytes(),
        &d.ts,
        &d.body,
        &d.sig,
        now,
        SIGNATURE_TOLERANCE_S,
    )
    .unwrap();
    assert!(verify_signature(
        b"wrong-secret-wrong-secret-wrong-secret",
        &d.ts,
        &d.body,
        &d.sig,
        now,
        SIGNATURE_TOLERANCE_S
    )
    .is_err());
    // Stale timestamp (replay outside the window) fails even with a right MAC.
    assert!(verify_signature(
        SECRET.as_bytes(),
        &d.ts,
        &d.body,
        &d.sig,
        now + 301,
        SIGNATURE_TOLERANCE_S
    )
    .is_err());
    // Tampered body fails.
    let mut t = d.body.clone();
    t.push(b' ');
    assert!(verify_signature(
        SECRET.as_bytes(),
        &d.ts,
        &t,
        &d.sig,
        now,
        SIGNATURE_TOLERANCE_S
    )
    .is_err());

    let ev: EventRecord = serde_json::from_slice(&d.body).unwrap();
    assert_eq!(ev.event_type, EventType::TriggerMatched);
    assert_eq!(ev.message_id, mid);
    assert_eq!(ev.target_session.as_deref(), Some("s1"));
    assert_eq!(ev.event_id, d.event_id);
    assert!(!String::from_utf8_lossy(&d.body).contains("TOP-SECRET"));
    // message.received is not sent unless configured.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rx.calls.lock().unwrap().len(), 1);
    let st = b.d().webhook_stats().unwrap();
    assert_eq!((st.delivered, st.parked), (1, 0));
    let status = b.remote.daemon_status().await.unwrap();
    assert_eq!(status["webhook"]["delivered"], 1);
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn retries_on_500_then_succeeds_with_one_effect_per_event_id() {
    let w = World::new();
    let (rx, addr) = receiver().await;
    rx.fail_first.store(2, Ordering::SeqCst);
    let (a, b) = setup(&w, addr, "/hook", 5).await;
    trigger(&b, &a, true).await;
    a.send(&b, "x").await;
    wait_until("3 calls", || async { rx.calls.lock().unwrap().len() >= 3 }).await;
    wait_until("delivered", || async {
        b.d().webhook_stats().unwrap().delivered == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let calls = rx.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3, "two failures + one success, nothing more");
    // The receiver dedupes by event id: one logical effect.
    let ids: HashSet<_> = calls.iter().map(|c| c.event_id.clone()).collect();
    assert_eq!(ids.len(), 1);
    let st = b.d().webhook_stats().unwrap();
    assert_eq!((st.delivered, st.retries, st.parked), (1, 2, 0));
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn parks_after_max_attempts_and_continues_with_the_next_event() {
    let w = World::new();
    let (rx, addr) = receiver().await;
    rx.always_fail.store(true, Ordering::SeqCst);
    let (a, b) = setup(&w, addr, "/hook", 3).await;
    trigger(&b, &a, false).await;
    a.send(&b, "one").await;
    wait_until("parked", || async {
        b.d().webhook_stats().unwrap().parked == 1
    })
    .await;
    assert_eq!(rx.calls.lock().unwrap().len(), 3);
    let st = b.d().webhook_stats().unwrap();
    assert!(st.last_error.as_deref().unwrap_or("").contains("500"));
    // The receiver recovers; the next event is delivered, the parked one is not resent.
    rx.always_fail.store(false, Ordering::SeqCst);
    a.send(&b, "two").await;
    wait_until("second delivered", || async {
        b.d().webhook_stats().unwrap().delivered == 1
    })
    .await;
    let calls = rx.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 4);
    let by_id: HashMap<_, u32> = calls.iter().fold(HashMap::new(), |mut m, c| {
        *m.entry(c.event_id.clone()).or_default() += 1;
        m
    });
    let mut counts: Vec<u32> = by_id.values().copied().collect();
    counts.sort();
    assert_eq!(counts, vec![1, 3]);
    // Parked events are recorded durably.
    let db = rusqlite::Connection::open(b.path.join("webhook.db")).unwrap();
    let n: i64 = db
        .query_row("SELECT COUNT(*) FROM parked", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let w = World::new();
    let (rx, addr) = receiver().await;
    let (a, b) = setup(&w, addr, "/redirect", 2).await;
    trigger(&b, &a, true).await;
    a.send(&b, "x").await;
    wait_until("parked", || async {
        b.d().webhook_stats().unwrap().parked == 1
    })
    .await;
    assert_eq!(
        rx.landing_hits.load(Ordering::SeqCst),
        0,
        "redirect target must never be contacted"
    );
    assert!(b
        .d()
        .webhook_stats()
        .unwrap()
        .last_error
        .unwrap()
        .contains("302"));
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn resumes_from_its_cursor_after_a_restart_without_loss_or_repeat() {
    let w = World::new();
    let (rx, addr) = receiver().await;
    let (a, mut b) = setup(&w, addr, "/hook", 3).await;
    trigger(&b, &a, false).await;
    let m1 = a.send(&b, "one").await;
    wait_until("first delivered", || async {
        rx.calls.lock().unwrap().len() == 1
    })
    .await;
    wait_until("cursor persisted", || async {
        b.d().webhook_stats().unwrap().cursor.is_some()
    })
    .await;
    b.daemon.take().unwrap().shutdown().await;

    // An event is created while the daemon is down (catch-up via history on restart).
    let m2 = a.send(&b, "two while down").await;
    b.daemon = Some(w.start(&b.path, wh_cfg(addr, "/hook", 3)).await);
    // The trigger survived the restart; B recovers m2 from history.
    wait_until("second delivered", || async {
        rx.calls.lock().unwrap().len() == 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let calls = rx.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2, "event 1 must not be resent after restart");
    let ids: Vec<String> = calls
        .iter()
        .map(|c| {
            serde_json::from_slice::<EventRecord>(&c.body)
                .unwrap()
                .message_id
        })
        .collect();
    assert_eq!(ids, vec![m1, m2]);
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn message_received_can_be_enabled_and_disabled_per_config() {
    let w = World::new();
    let (rx, addr) = receiver().await;
    let (pb, addr_b, rec_b) = w.init("b");
    write_secret(&pb, SECRET, 0o600);
    let mut c = wh_cfg(addr, "/hook", 3);
    c.webhook.events = vec!["message.received".into()];
    let d = w.start(&pb, c).await;
    let b = Agent {
        remote: agentnet_daemon::RemoteAgent::new(&pb),
        path: pb,
        address: addr_b,
        record: rec_b,
        daemon: Some(d),
    };
    let a = Agent::new(&w, "a", cfg()).await;
    a.add_contact_of(&b).await;
    b.add_contact_of(&a).await;
    a.send(&b, "hello").await;
    wait_until("received event posted", || async {
        !rx.calls.lock().unwrap().is_empty()
    })
    .await;
    let ev: EventRecord = serde_json::from_slice(&rx.calls.lock().unwrap()[0].body).unwrap();
    assert_eq!(ev.event_type, EventType::MessageReceived);
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn startup_rejects_unsafe_webhook_setups() {
    let w = World::new();
    let (pb, _, _) = w.init("b");
    let try_start = |c: DaemonConfig| {
        let w = &w;
        let pb = pb.clone();
        async move {
            let r = agentnet_daemon::Daemon::start_with_transport(
                &pb,
                c,
                Arc::new(w.net.endpoint()),
                Arc::new(w.clock.clone()),
            )
            .await;
            r.err().map(|e| e.to_string())
        }
    };
    let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    // Public, link-local/metadata, hostname URLs: rejected at config time.
    for url in [
        "http://8.8.8.8/h",
        "http://169.254.169.254/latest",
        "http://example.com/h",
        "http://[fe80::1]/h",
        "ftp://127.0.0.1/h",
    ] {
        let mut c = wh_cfg(addr, "/hook", 3);
        c.webhook.url = url.into();
        let e = try_start(c).await.expect(url);
        assert!(e.contains("webhook"), "{url}: {e}");
    }
    // Secret file problems.
    write_secret(&pb, SECRET, 0o644);
    let e = try_start(wh_cfg(addr, "/hook", 3)).await.unwrap();
    assert!(e.contains("mode 644"), "{e}");
    write_secret(&pb, "too short", 0o600);
    let e = try_start(wh_cfg(addr, "/hook", 3)).await.unwrap();
    assert!(e.contains("shorter than 32"), "{e}");
    let _ = std::fs::remove_file(pb.join("webhook.secret"));
    assert!(try_start(wh_cfg(addr, "/hook", 3)).await.is_some());
    // A good setup starts (and a failed start left the lock free).
    write_secret(&pb, &format!("{SECRET}\n"), 0o600);
    let started = try_start(wh_cfg(addr, "/hook", 3)).await;
    assert!(started.is_none(), "a valid setup must start: {started:?}");
}

// ------------------------------------------------------------------ trigger end to end

#[tokio::test]
async fn one_shot_trigger_yields_exactly_one_event_despite_duplicate_deliveries() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    // B's endpoint delivers every frame three times.
    let (pb, addr_b, rec_b) = w.init("b");
    let tb = w.net.endpoint();
    tb.set_duplicate_delivery(3);
    let d = w.start_on(&pb, cfg(), tb).await;
    let b = Agent {
        remote: agentnet_daemon::RemoteAgent::new(&pb),
        path: pb,
        address: addr_b,
        record: rec_b,
        daemon: Some(d),
    };
    a.add_contact_of(&b).await;
    b.add_contact_of(&a).await;

    // Harness side: subscribe before the trigger exists.
    let mut s = EventStream::connect(&b.path, None).await.unwrap();
    let t = trigger(&b, &a, true).await;
    let m1 = a.send(&b, "match me").await;
    let m2 = a.send(&b, "second, trigger already consumed").await;
    wait_until("both messages", || async { b.inbox_len().await == 2 }).await;

    let mut events = Vec::new();
    while let Ok(Ok(Some(ev))) = tokio::time::timeout(Duration::from_millis(700), s.next()).await {
        events.push(ev);
    }
    let matched: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::TriggerMatched)
        .collect();
    assert_eq!(matched.len(), 1, "exactly one trigger.matched: {events:?}");
    assert_eq!(matched[0].message_id, m1);
    assert_eq!(
        matched[0].trigger_id.as_deref(),
        Some(t.trigger_id.as_str())
    );
    let received: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == EventType::MessageReceived)
        .map(|e| e.message_id.clone())
        .collect();
    assert_eq!(
        received.len(),
        2,
        "one message.received per message, not per delivery"
    );
    assert!(received.contains(&m1) && received.contains(&m2));
    assert_eq!(b.inbox_len().await, 2);
    let tr = b.remote.list_triggers(true).await.unwrap();
    assert_eq!(tr[0].state, TriggerState::Consumed);
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn unauthorized_senders_never_produce_trigger_events() {
    let w = World::new();
    let b = Agent::new(&w, "b", cfg()).await;
    let a = Agent::new(&w, "a", cfg()).await; // trusted peer used to define the filter
    let c = Agent::new(&w, "c", cfg()).await; // unknown to B
    let u = Agent::new(&w, "u", cfg()).await; // known to B but untrusted
    for x in [&a, &c, &u] {
        x.add_contact_of(&b).await;
    }
    b.add_contact_of(&a).await;
    b.add_contact_of(&u).await;
    b.remote
        .set_contact_trust(&u.address, Trust::Untrusted)
        .await
        .unwrap();

    let mut s = EventStream::connect(&b.path, None).await.unwrap();
    // A trigger without a sender filter still only ever matches trusted senders.
    b.remote
        .create_trigger(CreateTriggerRequest {
            target_session: "s1".into(),
            once: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    c.send(&b, "from an unknown sender").await;
    u.send(&b, "from an untrusted sender").await;
    wait_until("quarantine filled", || async {
        b.remote.list_quarantined().await.unwrap().len() == 2
    })
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), s.next())
            .await
            .is_err(),
        "no events for unauthorized senders"
    );
    assert_eq!(
        b.remote
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        0
    );

    // The trusted sender does match.
    let m = a.send(&b, "ok").await;
    let mut got = Vec::new();
    while let Ok(Ok(Some(ev))) = tokio::time::timeout(Duration::from_millis(800), s.next()).await {
        got.push(ev);
    }
    assert!(got
        .iter()
        .any(|e| e.event_type == EventType::TriggerMatched && e.message_id == m));
    assert!(got.iter().all(|e| e.message_id == m));
    for x in [a, b, c, u] {
        x.daemon.unwrap().shutdown().await;
    }
}

#[tokio::test]
async fn triggers_are_off_by_default() {
    let w = World::new();
    let mut c = cfg();
    c.policy.auto_trigger = false;
    let a = Agent::new(&w, "a", c).await;
    let e = a
        .remote
        .create_trigger(CreateTriggerRequest {
            target_session: "s1".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    a.daemon.unwrap().shutdown().await;
}
