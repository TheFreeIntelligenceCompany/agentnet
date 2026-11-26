//! Relay-gated end-to-end test: two real `agentnet serve` processes against the
//! local relay topology in `spike/relay` (nodes na/nb on 127.0.0.1:18641/18642,
//! service node R1, cluster 66).
//!
//! `#[ignore]`d (a plain `cargo test` reports it as ignored, not passed). Run with:
//! `AGENTNET_RELAY_TESTS=1 cargo test -p agentnet-cli --test relay_e2e -- --ignored --nocapture`
//! (start the topology first: `cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh`).
//! Run with `--ignored` but without the environment variable it FAILS with a clear message.
//!
//! LOCALHOST / CONTAINER-NETWORK test: both agents and both Logos Delivery
//! client nodes run on this one host; the relay is a container on a docker
//! bridge. It is not a cross-machine test.

mod common;

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use serde_json::json;

const R1: &str =
    "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV";

macro_rules! log {
    ($($t:tt)*) => {{
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        println!("[{ts}] {}", format!($($t)*));
    }};
}

fn health(url: &str) -> bool {
    Command::new("curl")
        .args([
            "-s",
            "-m",
            "5",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            &format!("{url}/health"),
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "200")
        .unwrap_or(false)
}

fn wait_for<F: FnMut() -> bool>(what: &str, secs: u64, mut f: F) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            log!("ok: {what}");
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("timed out after {secs}s waiting for: {what}");
}

fn spawn_serve(dir: &std::path::Path, log_path: &std::path::Path) -> Child {
    Command::new(BIN)
        .arg("--data-dir")
        .arg(dir)
        .arg("serve")
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(log_path).unwrap())
        .spawn()
        .expect("spawn serve")
}

fn ready(dir: &std::path::Path) -> bool {
    let o = agentnet(dir, &["--json", "network", "status"]);
    if !o.status.success() {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(stdout(&o).trim())
        .map(|v| v["network"]["ready"] == true)
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the local relay topology: run with AGENTNET_RELAY_TESTS=1 -- --ignored"]
async fn two_agentnet_serve_processes_exchange_messages_over_the_private_relay() {
    assert!(
        std::env::var("AGENTNET_RELAY_TESTS").as_deref() == Ok("1"),
        "this test needs the local relay topology (spike/relay, `DNS_NS=127.0.0.1 ./scripts/up.sh`): \
         run with AGENTNET_RELAY_TESTS=1 cargo test -p agentnet-cli --test relay_e2e -- --ignored"
    );
    log!("relay e2e: topology = spike/relay (localhost / docker bridge, NOT cross-machine)");
    let (url_a, url_b) = ("http://127.0.0.1:18641", "http://127.0.0.1:18642");
    wait_for("node A health", 120, || health(url_a));
    wait_for("node B health", 120, || health(url_b));

    let t = tempfile::tempdir().unwrap();
    let mk = |name: &str, url: &str| {
        let p = t.path().join(name);
        let o = agentnet(&p, &["--json", "init", "--node-url", url, "--peer", R1]);
        assert!(o.status.success(), "{}", stderr(&o));
        let v: serde_json::Value = serde_json::from_str(stdout(&o).trim()).unwrap();
        (p, v["address"].as_str().unwrap().to_owned())
    };
    let (a, addr_a) = mk("a", url_a);
    let (b, addr_b) = mk("b", url_b);
    log!("A = {addr_a}");
    log!("B = {addr_b}");

    let (la, lb) = (t.path().join("a.log"), t.path().join("b.log"));
    let mut sa = spawn_serve(&a, &la);
    let mut sb = spawn_serve(&b, &lb);
    // Run the scenario on its own task so a failure can be observed while we
    // still stop both daemons and inspect their logs.
    let (pa, pb, aa, ab) = (a.clone(), b.clone(), addr_a.clone(), addr_b.clone());
    let r = tokio::spawn(async move { run(&pa, &pb, &aa, &ab).await }).await;
    for (name, child, path) in [("A", &mut sa, &la), ("B", &mut sb, &lb)] {
        kill_term(child.id());
        let st = child.wait().unwrap();
        log!("serve {name} exited: {st}");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        // The daemon's own log must not contain secrets.
        let token = std::fs::read_to_string(if name == "A" {
            a.join("control.token")
        } else {
            b.join("control.token")
        })
        .unwrap_or_default();
        assert!(
            !text.contains(token.trim()),
            "control token leaked into the log"
        );
        let n = text.lines().count();
        log!("serve {name} log: {n} lines (stderr, RUST_LOG=info)");
    }
    if let Err(e) = r {
        std::panic::resume_unwind(e.into_panic());
    }
}

async fn run(a: &std::path::Path, b: &std::path::Path, addr_a: &str, addr_b: &str) {
    wait_for(
        "serve A ready (node reachable, peer connected)",
        240,
        || ready(a),
    );
    wait_for("serve B ready", 240, || ready(b));
    let st = json_ok(a, &["network", "status", "--verbose"]);
    log!("A network status: {}", st);

    // contacts exchanged via the CLI
    let (ra, rb) = (contact_record(a), contact_record(b));
    let (fa, fb) = (
        write_file(a, "peer.json", &rb),
        write_file(b, "peer.json", &ra),
    );
    ok(
        a,
        &[
            "contact",
            "add",
            &format!("@{}", fa.display()),
            "--expect",
            addr_b,
            "--alias",
            "b",
        ],
    );
    ok(
        b,
        &[
            "contact",
            "add",
            &format!("@{}", fb.display()),
            "--expect",
            addr_a,
            "--alias",
            "a",
        ],
    );
    log!("contacts exchanged: {}", ok(a, &["contact", "list"]).trim());

    // ---- CLI path: A -> B
    let sent = json_ok(
        a,
        &[
            "send",
            addr_b,
            "hello over the relay (cli)",
            "--conversation",
            "relay-e2e",
        ],
    );
    let mid = sent["message_id"].as_str().unwrap().to_owned();
    log!("A sent {mid} state={}", sent["status"]);
    let started = Instant::now();
    wait_for("B inbox shows the message", 120, || {
        let v = json_ok(b, &["inbox"]);
        v["records"].as_array().is_some_and(|r| {
            r.iter().any(|m| {
                m["message_id"] == mid.as_str()
                    && m["body"] == "hello over the relay (cli)"
                    && m["sender"] == addr_a
            })
        })
    });
    log!("B inbox: {}", json_ok(b, &["inbox"]));
    wait_for("A status delivered", 120, || {
        json_ok(a, &["status", &mid])["state"] == "delivered"
    });
    log!(
        "A status: {} (end to end {:?})",
        json_ok(a, &["status", &mid]),
        started.elapsed()
    );

    // ---- MCP path: A's agentnet mcp sends, B's agentnet mcp reads and is notified
    let ca = mcp_client(a, &[]).await.expect("mcp A");
    let cb = mcp_client(b, &[]).await.expect("mcp B");
    let idb = structured(&call(&cb, "get_identity", json!({})).await);
    assert_eq!(idb["agent_id"], addr_b);
    let mut sub = cb
        .listen(sub_filter(&["agentnet://inbox"]))
        .await
        .expect("listen");
    log!("B subscribed to agentnet://inbox");
    let sent = structured(
        &call(
            &ca,
            "send_message",
            json!({"recipient": addr_b, "body": "hello over the relay (mcp)"}),
        )
        .await,
    );
    let mid2 = sent["message_id"].as_str().unwrap().to_owned();
    log!("A mcp send_message -> {sent}");
    let upd = tokio::time::timeout(Duration::from_secs(120), sub.next())
        .await
        .expect("no resource update within 120s")
        .unwrap();
    log!("B received a subscription update: {upd:?}");
    assert!(format!("{upd:?}").contains("agentnet://inbox"));
    let inbox = structured(&call(&cb, "read_inbox", json!({})).await);
    let bodies: Vec<String> = inbox["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["body"].as_str().unwrap().to_owned())
        .collect();
    log!("B mcp read_inbox bodies: {bodies:?}");
    assert!(bodies.contains(&"hello over the relay (mcp)".to_owned()));
    let end = Instant::now() + Duration::from_secs(120);
    loop {
        let st = structured(&call(&ca, "get_message_status", json!({"message_id": mid2})).await);
        if st["state"] == "delivered" {
            log!("A mcp get_message_status: {st}");
            break;
        }
        assert!(Instant::now() < end, "mcp message never delivered: {st}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _ = sub.cancel().await;
    ca.cancel().await.unwrap();
    cb.cancel().await.unwrap();

    // ---- diagnostics against the live setup (informational)
    let doc = agentnet(a, &["doctor"]);
    log!("doctor (A) exit={:?}\n{}", doc.status.code(), stdout(&doc));
    assert!(
        stdout(&doc).contains("[ok  ] local inbox database"),
        "local inbox database check must pass with the daemon running"
    );
    let ready = agentnet(a, &["doctor", "--ready"]);
    log!(
        "doctor --ready (A) exit={:?}\n{}",
        ready.status.code(),
        stderr(&ready)
    );
    assert_eq!(
        ready.status.code(),
        Some(0),
        "doctor --ready must pass against the live setup: {}",
        stderr(&ready)
    );
}
