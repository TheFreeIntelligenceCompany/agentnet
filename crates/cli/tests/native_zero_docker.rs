//! End-to-end zero-Docker integration test for the native pure-Rust Waku v2
//! transport and standalone relay (`agentnet relay serve` + `agentnet init --native`
//! + `agentnet serve` + full OpenPGP E2E messaging + offline Store v3 recovery).

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::*;

#[test]
fn zero_docker_native_relay_and_two_agents_end_to_end_with_offline_recovery() {
    let t = tempfile::tempdir().unwrap();
    let relay_dir = t.path().join("relay");

    // 1. Start the standalone pure-Rust Waku v2 relay + Store v3 on an ephemeral port.
    let mut relay = Command::new(BIN)
        .args([
            "--json",
            "relay",
            "serve",
            "--listen",
            "/ip4/127.0.0.1/tcp/0",
            "--relay-dir",
            relay_dir.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentnet relay serve");

    let mut relay_stdout = BufReader::new(relay.stdout.take().unwrap());
    let mut first_line = String::new();
    relay_stdout
        .read_line(&mut first_line)
        .expect("read relay startup json");
    let relay_info: serde_json::Value =
        serde_json::from_str(first_line.trim()).expect("valid relay json");
    let relay_maddr = relay_info["multiaddrs"][0]
        .as_str()
        .expect("relay multiaddr")
        .to_owned();
    assert!(
        relay_maddr.starts_with("/ip4/127.0.0.1/tcp/") && relay_maddr.contains("/p2p/16Uiu2HA"),
        "unexpected relay multiaddr: {relay_maddr}"
    );

    // 2. Initialize two agents in native mode (zero Docker).
    let a = t.path().join("a");
    let b = t.path().join("b");
    let init_a = json_ok(&a, &["init", "--native", "--peer", &relay_maddr]);
    let init_b = json_ok(&b, &["init", "--native", "--peer", &relay_maddr]);
    assert_eq!(init_a["backend"], "native");
    assert_eq!(init_b["backend"], "native");
    let addr_a = init_a["address"].as_str().unwrap().to_owned();
    let addr_b = init_b["address"].as_str().unwrap().to_owned();

    // 3. Start both real `agentnet serve` daemons.
    let mut serve_a = Command::new(BIN)
        .arg("--data-dir")
        .arg(&a)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut serve_b = Command::new(BIN)
        .arg("--data-dir")
        .arg(&b)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // 4. Wait until both pass `doctor --ready --wait 20` (no sidecar node!).
    let doc_a = agentnet(&a, &["doctor", "--ready", "--wait", "20"]);
    assert_eq!(
        doc_a.status.code(),
        Some(0),
        "A doctor failed:\n{}\n{}",
        stdout(&doc_a),
        stderr(&doc_a)
    );
    assert!(
        stdout(&doc_a).contains("embedded native libp2p"),
        "{}",
        stdout(&doc_a)
    );
    let doc_b = agentnet(&b, &["doctor", "--ready", "--wait", "20"]);
    assert_eq!(
        doc_b.status.code(),
        Some(0),
        "B doctor failed:\n{}\n{}",
        stdout(&doc_b),
        stderr(&doc_b)
    );

    // 5. Exchange and verify OpenPGP public certificates.
    let cert_a = ok(&a, &["identity", "show", "--cert-only"]);
    let cert_b = ok(&b, &["identity", "show", "--cert-only"]);
    let fa = write_file(t.path(), "a.cert", cert_a.trim());
    let fb = write_file(t.path(), "b.cert", cert_b.trim());
    ok(
        &a,
        &[
            "contact",
            "add",
            &format!("@{}", fb.display()),
            "--expect",
            &addr_b,
            "--alias",
            "b",
        ],
    );
    ok(
        &b,
        &[
            "contact",
            "add",
            &format!("@{}", fa.display()),
            "--expect",
            &addr_a,
            "--alias",
            "a",
        ],
    );

    // Give GossipSub mesh heartbeat a brief moment before first send.
    std::thread::sleep(Duration::from_millis(600));

    // 6. Live A -> B encrypted OpenPGP delivery + authenticated receipt.
    let sent1 = json_ok(&a, &["send", &addr_b, "hello zero-docker world"]);
    let mid1 = sent1["message_id"].as_str().unwrap().to_owned();
    let start = Instant::now();
    loop {
        let inbox = json_ok(&b, &["inbox"]);
        if inbox["records"]
            .as_array()
            .is_some_and(|r| r.iter().any(|m| m["message_id"] == mid1.as_str()))
        {
            assert_eq!(inbox["records"][0]["body"], "hello zero-docker world");
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "B never got live msg"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    loop {
        let st = json_ok(&a, &["status", &mid1]);
        if st["state"] == "delivered" {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "A never got receipt: {st}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // 7. Stop B completely, send an offline message from A, then restart B and
    //    verify B recovers it via Store v3 and A receives the authenticated receipt.
    ok(&b, &["stop"]);
    assert!(serve_b.wait().unwrap().success());

    let sent2 = json_ok(&a, &["send", &addr_b, "sent while B was offline"]);
    let mid2 = sent2["message_id"].as_str().unwrap().to_owned();
    // Wait until A has published to the relay (state == sent).
    let start2 = Instant::now();
    loop {
        let st = json_ok(&a, &["status", &mid2]);
        if st["state"] == "sent" {
            break;
        }
        assert!(
            start2.elapsed() < Duration::from_secs(15),
            "offline msg not sent: {st}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(400));

    // Restart B.
    let mut serve_b2 = Command::new(BIN)
        .arg("--data-dir")
        .arg(&b)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let doc_b2 = agentnet(&b, &["doctor", "--ready", "--wait", "20"]);
    assert_eq!(doc_b2.status.code(), Some(0), "{}", stderr(&doc_b2));

    let start3 = Instant::now();
    loop {
        let inbox = json_ok(&b, &["inbox"]);
        if let Some(rec) = inbox["records"]
            .as_array()
            .and_then(|r| r.iter().find(|m| m["message_id"] == mid2.as_str()))
        {
            assert_eq!(rec["body"], "sent while B was offline");
            break;
        }
        assert!(
            start3.elapsed() < Duration::from_secs(30),
            "B never recovered offline msg from native Store v3"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    loop {
        let st = json_ok(&a, &["status", &mid2]);
        if st["state"] == "delivered" {
            break;
        }
        assert!(
            start3.elapsed() < Duration::from_secs(30),
            "A never got offline receipt: {st}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // 8. Clean shutdown of daemons and native relay.
    ok(&a, &["stop"]);
    ok(&b, &["stop"]);
    assert!(serve_a.wait().unwrap().success());
    assert!(serve_b2.wait().unwrap().success());
    kill_term(relay.id());
    assert!(relay.wait().unwrap().success());
}
