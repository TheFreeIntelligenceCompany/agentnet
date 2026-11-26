//! Relay-gated test of the optional signed capability discovery feature
//! (`[discovery]`, docs/discovery.md) over the local relay topology in `spike/relay`
//! (nodes na/nb on 127.0.0.1:18641/18642, service node R1, cluster 66).
//!
//! `#[ignore]`d. Run with:
//! `AGENTNET_RELAY_TESTS=1 cargo test -p agentnet-cli --locked --test relay_discovery -- --ignored --nocapture`
//! Run with `--ignored` but without the environment variable it FAILS with a clear message.
//!
//! LOCALHOST / CONTAINER-NETWORK test: both agents and both nodes run on one host;
//! the relay is a container on a docker bridge. Not a cross-machine test.
//! Every run uses fresh topic names and capability names, so reruns do not collide with
//! Store history.

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use common::*;
use serde_json::{json, Value};

const R1: &str =
    "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV";
const URL_A: &str = "http://127.0.0.1:18641";
const URL_B: &str = "http://127.0.0.1:18642";

macro_rules! log {
    ($($t:tt)*) => {{
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        println!("[{ts}] {}", format!($($t)*));
    }};
}

fn curl(args: &[&str]) -> String {
    let o = Command::new("curl")
        .args(["-s", "-m", "20"])
        .args(args)
        .output()
        .expect("curl");
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn health(url: &str) -> bool {
    curl(&[
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        &format!("{url}/health"),
    ])
    .trim()
        == "200"
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

fn spawn_serve(dir: &Path, log_path: &Path) -> Child {
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

fn ready(dir: &Path) -> bool {
    let o = agentnet(dir, &["--json", "network", "status"]);
    o.status.success()
        && serde_json::from_str::<Value>(stdout(&o).trim())
            .map(|v| v["network"]["ready"] == true)
            .unwrap_or(false)
}

fn stop(child: &mut Child) {
    kill_term(child.id());
    let _ = child.wait();
}

fn set_discovery(dir: &Path, enabled: bool, topics: &[&str]) {
    let p = dir.join("agentnet.toml");
    let text = std::fs::read_to_string(&p).unwrap();
    let t = topics
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = Vec::new();
    let mut in_disc = false;
    let mut hit = (false, false);
    for line in text.lines() {
        if line.starts_with('[') {
            in_disc = line.trim() == "[discovery]";
        }
        if in_disc && line.starts_with("enabled") {
            out.push(format!("enabled = {enabled}"));
            hit.0 = true;
        } else if in_disc && line.starts_with("topics") {
            out.push(format!("topics = [{t}]"));
            hit.1 = true;
        } else {
            out.push(line.to_owned());
        }
    }
    assert!(
        hit.0 && hit.1,
        "[discovery] keys not found in agentnet.toml"
    );
    std::fs::write(&p, out.join("\n") + "\n").unwrap();
}

fn content_topic(name: &str) -> String {
    format!("/agentnet/1/discovery-{name}/proto")
}

/// Query the relay Store (through node A's REST API) for the frames on a discovery topic.
fn store_frames(name: &str) -> Vec<Vec<u8>> {
    let ct = content_topic(name).replace('/', "%2F");
    let url = format!(
        "{URL_A}/store/v3/messages?contentTopics={ct}&includeData=true&ascending=true&pageSize=50&peerAddr={}",
        R1.replace('/', "%2F")
    );
    let v: Value = serde_json::from_str(&curl(&[&url])).unwrap_or(Value::Null);
    v["messages"]
        .as_array()
        .map(|m| {
            m.iter()
                .filter_map(|e| e["message"]["payload"].as_str())
                .filter_map(|p| {
                    base64::engine::general_purpose::STANDARD
                        .decode(p)
                        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(p))
                        .ok()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Publish a raw frame on a discovery topic through node A's REST API (bypasses AgentNet).
fn inject(name: &str, payload: &[u8]) {
    let body = json!({
        "payload": base64::engine::general_purpose::STANDARD.encode(payload),
        "contentTopic": content_topic(name),
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64,
        "ephemeral": false,
    })
    .to_string();
    let out = curl(&[
        "-X",
        "POST",
        "-H",
        "content-type: application/json",
        "-d",
        &body,
        &format!("{URL_A}/relay/v1/auto/messages"),
    ]);
    log!("inject on {name}: node answered {out:?}");
}

fn listed(dir: &Path, topic: &str) -> Vec<Value> {
    let o = agentnet(dir, &["--json", "discovery", "list", "--topic", topic]);
    if !o.status.success() {
        return vec![];
    }
    serde_json::from_str::<Value>(stdout(&o).trim())
        .ok()
        .and_then(|v| v["agents"].as_array().cloned())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the local relay topology: run with AGENTNET_RELAY_TESTS=1 -- --ignored"]
async fn signed_capability_discovery_works_over_the_private_relay() {
    assert!(
        std::env::var("AGENTNET_RELAY_TESTS").as_deref() == Ok("1"),
        "this test needs the local relay topology (spike/relay): \
         run with AGENTNET_RELAY_TESTS=1 cargo test -p agentnet-cli --test relay_discovery -- --ignored"
    );
    log!("relay discovery: topology = spike/relay (localhost / docker bridge, NOT cross-machine)");
    wait_for("node A health", 120, || health(URL_A));
    wait_for("node B health", 120, || health(URL_B));

    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let main_topic = format!("rd{run}");
    let tamper_topic = format!("rd{run}-tamper");
    let ctrl_topic = format!("rd{run}-ctrl");
    let cap = format!("relay-cap-{run}");
    let all = [
        main_topic.as_str(),
        tamper_topic.as_str(),
        ctrl_topic.as_str(),
    ];

    let t = tempfile::tempdir().unwrap();
    let mk = |name: &str, url: &str| {
        let p = t.path().join(name);
        let o = agentnet(&p, &["--json", "init", "--node-url", url, "--peer", R1]);
        assert!(o.status.success(), "{}", stderr(&o));
        let v: Value = serde_json::from_str(stdout(&o).trim()).unwrap();
        (p, v["address"].as_str().unwrap().to_owned())
    };
    let (a, addr_a) = mk("a", URL_A);
    let (b, addr_b) = mk("b", URL_B);
    log!("A = {addr_a}\nB = {addr_b}\ntopics = {all:?} capability = {cap}");
    set_discovery(&a, true, &all);
    set_discovery(&b, true, &all);

    let (la, lb) = (t.path().join("a.log"), t.path().join("b.log"));
    let mut sa = spawn_serve(&a, &la);
    let mut sb = spawn_serve(&b, &lb);

    let (pa, pb, aa, ab) = (a.clone(), b.clone(), addr_a.clone(), addr_b.clone());
    let (mt, tt, ct, cp) = (main_topic.clone(), tamper_topic, ctrl_topic, cap.clone());
    let r1 = tokio::spawn(async move {
        phase_enabled(&pa, &pb, &aa, &ab, &mt, &tt, &ct, &cp).await;
    })
    .await;
    stop(&mut sa);
    let mut r2 = Ok(());
    if r1.is_ok() {
        // ---- phase 2: discovery disabled on A (restart A with enabled = false)
        set_discovery(&a, false, &[]);
        let log_a2 = t.path().join("a2.log");
        let mut sa2 = spawn_serve(&a, &log_a2);
        let (pa, mt, cp) = (a.clone(), main_topic, cap);
        r2 = tokio::spawn(async move { phase_disabled(&pa, &mt, &cp).await }).await;
        stop(&mut sa2);
    }
    stop(&mut sb);
    for (n, path) in [("A", &la), ("B", &lb)] {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        log!("serve {n} log: {} lines", text.lines().count());
    }
    if let Err(e) = r1 {
        std::panic::resume_unwind(e.into_panic());
    }
    if let Err(e) = r2 {
        std::panic::resume_unwind(e.into_panic());
    }
}

#[allow(clippy::too_many_arguments)]
async fn phase_enabled(
    a: &Path,
    b: &Path,
    addr_a: &str,
    addr_b: &str,
    topic: &str,
    tamper_topic: &str,
    ctrl_topic: &str,
    cap: &str,
) {
    wait_for("serve A ready", 240, || ready(a));
    wait_for("serve B ready", 240, || ready(b));

    // ---- advertise on A; B lists it
    let started = Instant::now();
    let adv = json_ok(
        a,
        &[
            "discovery",
            "advertise",
            "--topic",
            topic,
            "--capability",
            &format!("{cap}:relay discovery test"),
            "--display-name",
            "Relay Tester",
            "--ttl",
            "1800",
        ],
    );
    log!("A advertise: {adv}");
    assert_eq!(adv["seq"], 1);
    wait_for("B lists A's advert (CLI)", 240, || {
        listed(b, topic)
            .iter()
            .any(|x| x["address"] == addr_a && x["capabilities"][0]["name"] == cap)
    });
    log!("advert visible at B after {:?}", started.elapsed());
    let agents = listed(b, topic);
    log!("B list: {}", json!(agents));
    assert_eq!(agents.len(), 1);
    let ag = &agents[0];
    assert_eq!(ag["address"], addr_a);
    assert_eq!(ag["display_name"], "Relay Tester");
    assert_eq!(ag["is_contact"], false);
    // The engine accepts an advert only after `verify_strict` of the signature and of the
    // embedded contact record, both bound to the same address; adding the returned
    // contact record with --expect proves it names A.
    let rec = ag["contact_record"].as_str().unwrap();
    let f = write_file(b, "found.json", rec);
    let added = json_ok(
        b,
        &[
            "contact",
            "add",
            &format!("@{}", f.display()),
            "--expect",
            addr_a,
            "--alias",
            "a",
        ],
    );
    assert_eq!(added["address"], addr_a);
    log!("B added the discovered contact_record with --expect {addr_a}: ok");
    let f1 = json_ok(
        b,
        &["discovery", "list", "--topic", topic, "--capability", cap],
    );
    assert_eq!(f1["agents"].as_array().unwrap().len(), 1);
    let f0 = json_ok(
        b,
        &[
            "discovery",
            "list",
            "--topic",
            topic,
            "--capability",
            "nope",
        ],
    );
    assert!(f0["agents"].as_array().unwrap().is_empty());

    // ---- MCP discover_agents on B
    let cb = mcp_client(b, &[]).await.expect("mcp B");
    let r = structured(
        &call(
            &cb,
            "discover_agents",
            json!({"topic": topic, "capability": cap}),
        )
        .await,
    );
    log!("B mcp discover_agents: {r}");
    assert_eq!(r["agents"].as_array().unwrap().len(), 1);
    assert_eq!(r["agents"][0]["address"], addr_a);
    assert_eq!(r["agents"][0]["is_contact"], true, "added above");
    let denied = call(&cb, "discover_agents", json!({"topic": "not-configured"})).await;
    let e = error_json(&denied);
    log!("B mcp discover_agents unknown topic: {e}");
    cb.cancel().await.unwrap();

    // ---- tamper: take A's real frame from the relay Store
    let mut frames = Vec::new();
    wait_for("advert frame in the relay Store", 120, || {
        frames = store_frames(topic);
        !frames.is_empty()
    });
    let frame = frames[0].clone();
    log!(
        "store frame: {} bytes, prefix {:02x?}",
        frame.len(),
        &frame[..3]
    );
    assert_eq!(&frame[..3], b"AD\x01");
    // cross-topic replay: the unmodified frame, republished on another configured topic,
    // must NOT be listed (the topic is part of the signed record).
    inject(ctrl_topic, &frame);
    // tampered: flip one character in the middle of the signature (base64url) field
    let mut bad = frame.clone();
    let s = String::from_utf8(frame[3..].to_vec()).unwrap();
    let sig_at = s.find("\"sig\":\"").unwrap() + 7 + 20;
    let pos = 3 + sig_at;
    bad[pos] = if bad[pos] == b'A' { b'B' } else { b'A' };
    assert_ne!(bad, frame);
    inject(tamper_topic, &bad);
    // same-topic replay (positive control for the injection path): accepted as a duplicate
    // of the live advert, so the listing stays at exactly one entry.
    inject(topic, &frame);
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert!(
        listed(b, ctrl_topic).is_empty(),
        "an advert replayed onto another topic must not be listed (topic is signed)"
    );
    assert!(
        listed(b, tamper_topic).is_empty(),
        "tampered advert must not be listed"
    );
    assert_eq!(
        listed(b, topic).len(),
        1,
        "same-topic replay changes nothing"
    );
    // positive control on the second topic: a genuine advert signed FOR that topic is
    // listed there (different capability name, so it cannot be the replayed frame).
    let ctrl_cap = format!("{cap}-ctrl");
    let adv2 = json_ok(
        a,
        &[
            "discovery",
            "advertise",
            "--topic",
            ctrl_topic,
            "--capability",
            &ctrl_cap,
            "--ttl",
            "1800",
        ],
    );
    assert_eq!(adv2["seq"], 1);
    wait_for(
        "B lists A's genuine advert on the second topic",
        240,
        || {
            listed(b, ctrl_topic).iter().any(|x| {
                x["address"] == addr_a && x["capabilities"][0]["name"] == ctrl_cap.as_str()
            })
        },
    );
    assert_eq!(listed(b, ctrl_topic).len(), 1);
    let counters = ok(b, &["network", "status", "--verbose"]);
    log!("B network status --verbose after injection:\n{counters}");

    // ---- ordinary private messaging alongside discovery (A -> B)
    let fa = write_file(a, "peer.json", &contact_record(b));
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
    let sent = json_ok(
        a,
        &[
            "send",
            addr_b,
            "hello alongside discovery",
            "--conversation",
            "relay-disc",
        ],
    );
    let mid = sent["message_id"].as_str().unwrap().to_owned();
    wait_for("B inbox has the message", 180, || {
        json_ok(b, &["inbox"])["records"]
            .as_array()
            .is_some_and(|r| {
                r.iter().any(|m| {
                    m["message_id"] == mid.as_str()
                        && m["body"] == "hello alongside discovery"
                        && m["sender"] == addr_a
                })
            })
    });
    wait_for("A status delivered", 180, || {
        json_ok(a, &["status", &mid])["state"] == "delivered"
    });

    // ---- withdraw
    let w = json_ok(a, &["discovery", "withdraw", "--topic", topic]);
    log!("A withdraw: {w}");
    assert_eq!(w["withdrawn"], true);
    wait_for("B no longer lists A's advert", 240, || {
        listed(b, topic).is_empty()
    });
    log!("withdraw visible at B");
}

async fn phase_disabled(a: &Path, topic: &str, cap: &str) {
    let before = store_frames(topic).len();
    log!("frames on the discovery topic before the disabled phase: {before}");
    assert!(before >= 2, "advert and withdrawal frames expected");
    wait_for("serve A (discovery disabled) ready", 240, || ready(a));
    for args in [
        vec![
            "discovery",
            "advertise",
            "--topic",
            topic,
            "--capability",
            cap,
        ],
        vec!["discovery", "withdraw", "--topic", topic],
        vec!["--json", "discovery", "list", "--topic", topic],
    ] {
        let o = agentnet(a, &args);
        log!(
            "disabled: {args:?} -> exit {:?} stderr {}",
            o.status.code(),
            stderr(&o).trim()
        );
        assert_eq!(o.status.code(), Some(6), "{}", stderr(&o));
        assert!(
            stderr(&o).contains("disabled by host policy"),
            "{}",
            stderr(&o)
        );
    }
    let mcp = mcp_client(a, &[]).await.expect("mcp A");
    let e = error_json(
        &call(
            &mcp,
            "advertise_agent",
            json!({"topic": topic, "capabilities": [{"name": cap}]}),
        )
        .await,
    );
    log!("disabled mcp advertise_agent: {e}");
    assert!(e.to_string().contains("policy_denied"), "{e}");
    mcp.cancel().await.unwrap();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let after = store_frames(topic).len();
    log!("frames on the discovery topic after the disabled phase: {after}");
    assert_eq!(before, after, "nothing may be published while disabled");
}
