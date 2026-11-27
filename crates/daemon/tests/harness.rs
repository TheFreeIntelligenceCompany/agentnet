//! The mock harness example (no LLM, no Pi) against real in-process daemons.

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use agentnet_core::api::*;
use agentnet_daemon::webhook::{sign, HEADER_EVENT_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP};
use common::*;

const SECRET: &str = "0123456789abcdef0123456789abcdef-harness-secret";

fn example(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    // target/<profile>/deps/<test> -> target/<profile>/examples/<name>
    let p = exe
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("examples")
        .join(name);
    assert!(
        p.exists(),
        "{p:?} missing: build with `cargo build -p agentnet-daemon --examples`"
    );
    p
}

fn lines(p: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn harness(
    dir: &std::path::Path,
    out: &std::path::Path,
    state: &std::path::Path,
    extra: &[&str],
) -> std::process::Output {
    let (dir, out, state) = (dir.to_owned(), out.to_owned(), state.to_owned());
    let extra: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        Command::new(example("mock_harness"))
            .arg("--data-dir")
            .arg(dir)
            .arg("--out")
            .arg(out)
            .arg("--state")
            .arg(state)
            .args(extra)
            .stdout(Stdio::null())
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

async fn trigger_pair(
    w: &World,
    cfg_b: agentnet_daemon::DaemonConfig,
) -> (Agent, Agent, TriggerInfo) {
    let (a, b) = pair(w, cfg(), cfg_b).await;
    let t = b
        .remote
        .create_trigger(CreateTriggerRequest {
            sender: Some(a.address.clone()),
            target_session: "s1".into(),
            once: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    (a, b, t)
}

#[tokio::test]
async fn socket_mode_records_one_turn_per_event_and_resumes_from_its_cursor() {
    let w = World::new();
    let (a, b, t) = trigger_pair(&w, cfg()).await;
    let m1 = a.send(&b, "one").await;
    wait_until("b has the message", || async { b.inbox_len().await == 1 }).await;
    let out = w.tmp.path().join("turns.jsonl");
    let state = w.tmp.path().join("state.json");
    let o = harness(&b.path, &out, &state, &["--max-events", "1"]).await;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let l = lines(&out);
    assert_eq!(l.len(), 1);
    assert_eq!(l[0]["message_id"], m1.as_str());
    assert_eq!(l[0]["trigger_id"], t.trigger_id.as_str());
    assert_eq!(l[0]["target_session"], "s1");
    assert_eq!(l[0]["simulated_turn"], 1);
    assert!(l[0]["event_id"].is_string());
    // The event was acknowledged (cursor persisted + ack).
    assert_eq!(
        b.remote
            .network_status(false)
            .await
            .unwrap()
            .queue
            .events_unacked,
        0
    );

    // A second event arrives while the harness is down; a restart resumes from
    // the persisted cursor: the first event is not replayed.
    let m2 = a.send(&b, "two").await;
    wait_until("second message", || async { b.inbox_len().await == 2 }).await;
    let o = harness(
        &b.path,
        &out,
        &state,
        &["--max-events", "2", "--idle-exit-ms", "3000"],
    )
    .await;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let l = lines(&out);
    assert_eq!(l.len(), 2, "{l:?}");
    assert_eq!(l[1]["message_id"], m2.as_str());
    assert_eq!(l[1]["simulated_turn"], 2);

    // Persisted de-duplication: with the cursor lost but the seen-set kept, a
    // full replay records nothing new.
    let mut st: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    st["cursor"] = serde_json::Value::Null;
    std::fs::write(&state, serde_json::to_vec(&st).unwrap()).unwrap();
    let o = harness(
        &b.path,
        &out,
        &state,
        &["--include-received", "--idle-exit-ms", "1500"],
    )
    .await;
    assert!(o.status.success());
    let l = lines(&out);
    // include-received adds the two message.received events (new ids), but the
    // two trigger.matched events are not repeated.
    let matched: Vec<_> = l.iter().filter(|x| !x["trigger_id"].is_null()).collect();
    assert_eq!(matched.len(), 2, "{l:?}");
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn webhook_mode_verifies_signatures_and_dedupes() {
    let w = World::new();
    // Pick a free loopback port for the harness.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (pb, addr_b, rec_b) = w.init("b");
    let secret_path = pb.join("webhook.secret");
    std::fs::write(&secret_path, SECRET).unwrap();
    std::os::unix::fs::PermissionsExt::set_mode(
        &mut std::fs::metadata(&secret_path).unwrap().permissions(),
        0o600,
    );
    std::fs::set_permissions(
        &secret_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();

    let out = w.tmp.path().join("turns.jsonl");
    let state = w.tmp.path().join("state.json");
    let mut child = Command::new(example("mock_harness"))
        .args(["--webhook", &format!("127.0.0.1:{port}"), "--secret-file"])
        .arg(&secret_path)
        .arg("--out")
        .arg(&out)
        .arg("--state")
        .arg(&state)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_until("harness listening", || async move {
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
    })
    .await;

    // Direct posts: bad signature is refused, a good one recorded once.
    let now = w.clock.now_ns() / 1_000_000_000;
    let ev = EventRecord {
        event_id: "11111111-1111-4111-8111-111111111111".into(),
        cursor: "c".into(),
        event_type: EventType::TriggerMatched,
        agent_id: "an2x".into(),
        message_id: "m-direct".into(),
        trigger_id: Some("t".into()),
        target_session: Some("s1".into()),
        timestamp: 1,
    };
    let body = serde_json::to_string(&ev).unwrap();
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let _ = now;
    let post = |ts: u64, sig: String, body: String| async move {
        let c = reqwest_client();
        c.post(format!("http://127.0.0.1:{port}/hook"))
            .header(HEADER_EVENT_ID, "11111111-1111-4111-8111-111111111111")
            .header(HEADER_TIMESTAMP, ts.to_string())
            .header(HEADER_SIGNATURE, sig)
            .body(body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    assert_eq!(post(real_now, "v1=00".into(), body.clone()).await, 401);
    assert_eq!(
        post(
            real_now,
            sign(
                b"some-other-secret-some-other-secret!",
                &real_now.to_string(),
                body.as_bytes()
            ),
            body.clone()
        )
        .await,
        401
    );
    let stale = real_now - 1000;
    assert_eq!(
        post(
            stale,
            sign(SECRET.as_bytes(), &stale.to_string(), body.as_bytes()),
            body.clone()
        )
        .await,
        401,
        "stale timestamp"
    );
    let good = sign(SECRET.as_bytes(), &real_now.to_string(), body.as_bytes());
    assert_eq!(post(real_now, good.clone(), body.clone()).await, 200);
    assert_eq!(
        post(real_now, good, body.clone()).await,
        200,
        "duplicate is acknowledged"
    );
    wait_until("one line", || async { lines(&out).len() == 1 }).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        lines(&out).len(),
        1,
        "duplicate must not record a second turn"
    );

    // And through a real daemon: B posts trigger.matched to the harness. The
    // daemon's timestamps come from the mock clock, which started at wall time.
    let mut cb = cfg();
    cb.webhook.enabled = true;
    cb.webhook.url = format!("http://127.0.0.1:{port}/hook");
    cb.webhook.secret_file = "webhook.secret".into();
    cb.webhook.retry_base_ms = 20;
    let d = w.start(&pb, cb).await;
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
    b.remote
        .create_trigger(CreateTriggerRequest {
            sender: Some(a.address.clone()),
            target_session: "s1".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mid = a.send(&b, "via webhook").await;
    wait_until("second line", || async { lines(&out).len() == 2 }).await;
    let l = lines(&out);
    assert_eq!(l[1]["message_id"], mid.as_str());
    assert_eq!(l[1]["simulated_turn"], 2);
    let _ = child.kill();
    let _ = child.wait();
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

fn reqwest_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test]
async fn embed_example_runs() {
    let o = tokio::task::spawn_blocking(|| Command::new(example("embed")).output().unwrap())
        .await
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        o.status.success(),
        "{}\n{}",
        out,
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(out.contains("bob received"), "{out}");
    assert!(out.contains("Delivered"), "{out}");
}

#[test]
fn documented_sample_configs_match_the_code() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples");
    let want = [
        ("private.toml", agentnet_daemon::sample_private_config()),
        ("public.toml", agentnet_daemon::sample_public_config()),
    ];
    for (name, text) in want {
        let p = root.join(name);
        if std::env::var("AGENTNET_REGEN_EXAMPLES").as_deref() == Ok("1") {
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(&p, &text).unwrap();
        }
        let have = std::fs::read_to_string(&p).unwrap_or_default();
        assert_eq!(have, text, "{name} is stale; regenerate with AGENTNET_REGEN_EXAMPLES=1 cargo test -p agentnet-daemon --test harness documented_sample");
    }
}

/// The documented receive flow: event -> get_message(message_id) -> handle -> ack.
#[tokio::test]
async fn fetch_mode_resolves_the_event_message_id_with_get_message_then_acknowledges() {
    let w = World::new();
    let (a, b) = pair(&w, cfg(), cfg()).await;
    let m1 = a.send(&b, "fetch me").await;
    wait_until("b has the message", || async { b.inbox_len().await == 1 }).await;
    let out = w.tmp.path().join("turns.jsonl");
    let state = w.tmp.path().join("state.json");
    let o = harness(
        &b.path,
        &out,
        &state,
        &["--include-received", "--fetch", "--max-events", "1"],
    )
    .await;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let l = lines(&out);
    assert_eq!(l.len(), 1, "{l:?}");
    assert_eq!(l[0]["message_id"], m1.as_str());
    assert_eq!(l[0]["fetched"]["sender"], a.address.as_str());
    assert_eq!(l[0]["fetched"]["body_bytes"], "fetch me".len());
    let inbox = b
        .remote
        .read_inbox(agentnet_core::api::ReadInboxRequest::default())
        .await
        .unwrap();
    assert!(inbox.records[0].acknowledged, "acknowledged after handling");
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}
