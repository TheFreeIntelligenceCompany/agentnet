mod common;

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use agentnet_core::api::ReadInboxRequest;
use agentnet_daemon::{Daemon, DaemonConfig};
use agentnet_transport::mock::{MockClock, MockNetwork};
use common::*;
use serde_json::json;

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn init_creates_private_files_and_refuses_to_overwrite() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("home");
    let out = agentnet(&dir, &["--json", "init", "--peer", PEER]);
    assert!(out.status.success(), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert!(v["address"].as_str().unwrap().starts_with("an1"));
    assert!(v["contact_record"].as_str().unwrap().contains("\"sig\""));
    assert_eq!(v["peers_configured"], true);
    assert_eq!(mode(&dir), 0o700);
    for f in [
        "identity.json",
        "agentnet.toml",
        "control.token",
        "mcp-http.token",
        "lock",
    ] {
        assert_eq!(mode(&dir.join(f)), 0o600, "{f}");
    }
    // secrets are not printed
    let secret = std::fs::read_to_string(dir.join("identity.json")).unwrap();
    let key: serde_json::Value = serde_json::from_str(&secret).unwrap();
    for k in ["signing_sk", "kem_sk"] {
        assert!(
            !stdout(&out).contains(key[k].as_str().unwrap()),
            "{k} leaked"
        );
    }
    let token = std::fs::read_to_string(dir.join("control.token")).unwrap();
    assert!(!stdout(&out).contains(token.trim()) && !stderr(&out).contains(token.trim()));

    // second init refuses and leaves the identity untouched
    let again = agentnet(&dir, &["init"]);
    assert_eq!(again.status.code(), Some(1));
    assert!(
        stderr(&again).contains("refusing to overwrite"),
        "{}",
        stderr(&again)
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("identity.json")).unwrap(),
        secret
    );

    // `identity show` agrees and the config is valid for doctor's config check
    let shown = json_ok(&dir, &["identity", "show"]);
    assert_eq!(shown["agent_id"], v["address"]);
    let cfg = agentnet_daemon::DaemonConfig::load(&dir.join("agentnet.toml")).unwrap();
    assert_eq!(cfg.network.peers, vec![PEER.to_owned()]);
}

#[test]
fn printed_next_steps_keep_the_data_dir_shell_quoted() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("my agent");
    let out = agentnet(&dir, &["init", "--peer", PEER]);
    assert!(out.status.success(), "{}", stderr(&out));
    let want = format!("Next: agentnet --data-dir '{}' serve", dir.display());
    assert!(stdout(&out).contains(&want), "{}", stdout(&out));
    // no peers: the warning names the config file in that directory
    let dir2 = t.path().join("b");
    let out = agentnet(&dir2, &["init"]);
    assert!(
        stdout(&out).contains(&format!("{}", dir2.join("agentnet.toml").display())),
        "{}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains(&format!(
            "Next: agentnet --data-dir {} serve",
            dir2.display()
        )),
        "{}",
        stdout(&out)
    );
}

#[test]
fn missing_daemon_error_names_the_data_dir() {
    let t = tempfile::tempdir().unwrap();
    let a = t.path().join("my agent");
    ok(&a, &["init", "--peer", PEER]);
    let o = agentnet(&a, &["inbox"]);
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    let want = format!("`agentnet --data-dir '{}' serve`", a.display());
    assert!(stderr(&o).contains(&want), "{}", stderr(&o));
}

#[tokio::test]
async fn sending_to_an_unknown_recipient_prescribes_the_cli_command() {
    let t = tempfile::tempdir().unwrap();
    let (a, _) = init(t.path(), "a");
    let (_, addr_b) = init(t.path(), "b");
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    let clock = MockClock::new(now_ns);
    let net = MockNetwork::with_clock(clock.clone());
    let cfg = DaemonConfig::load(&a.join("agentnet.toml")).unwrap();
    let d = Daemon::start_with_transport(&a, cfg, Arc::new(net.endpoint()), Arc::new(clock))
        .await
        .unwrap();
    let (a2, to) = (a.clone(), addr_b.clone());
    let o = tokio::task::spawn_blocking(move || agentnet(&a2, &["send", &to, "hi"]))
        .await
        .unwrap();
    assert_eq!(o.status.code(), Some(5), "{}", stderr(&o));
    assert!(
        stderr(&o).contains(&format!(
            "error: Recipient is not a known contact. Add their signed record with `agentnet --data-dir {} contact add @<file> --expect <address>`.",
            a.display()
        )),
        "{}",
        stderr(&o)
    );
    assert!(!stderr(&o).contains("add_contact"), "{}", stderr(&o));
    d.shutdown().await;
}

#[test]
fn init_without_peers_warns_and_serve_refuses_until_configured() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("home");
    let out = agentnet(&dir, &["init"]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no peers configured"));
    let serve = agentnet(&dir, &["serve"]);
    assert_eq!(serve.status.code(), Some(4), "{}", stderr(&serve));
    assert!(stderr(&serve).contains("network.peers"));
}

#[test]
fn identity_export_import_round_trip_gives_the_same_address() {
    let t = tempfile::tempdir().unwrap();
    let (a, addr) = init(t.path(), "a");
    let pw = write_file(t.path(), "pw", "correct horse battery staple\n");
    let export = t.path().join("export.age");
    let out = agentnet(
        &a,
        &[
            "identity",
            "export",
            "--out",
            export.to_str().unwrap(),
            "--passphrase-file",
            pw.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(mode(&export), 0o600);
    assert!(!stdout(&out).contains("signing_sk"));
    // never overwrites
    let again = agentnet(
        &a,
        &[
            "identity",
            "export",
            "--out",
            export.to_str().unwrap(),
            "--passphrase-file",
            pw.to_str().unwrap(),
        ],
    );
    assert!(!again.status.success());

    // import into a new data dir
    let b = t.path().join("b");
    let imp = agentnet(
        &b,
        &[
            "--json",
            "identity",
            "import",
            "--in",
            export.to_str().unwrap(),
            "--passphrase-file",
            pw.to_str().unwrap(),
            "--peer",
            PEER,
        ],
    );
    assert!(imp.status.success(), "{}", stderr(&imp));
    let shown = json_ok(&b, &["identity", "show"]);
    assert_eq!(shown["agent_id"], addr.as_str());
    assert_eq!(mode(&b.join("identity.json")), 0o600);
    // identical contact record
    assert_eq!(contact_record(&a), contact_record(&b));
    // import refuses an existing identity
    let imp2 = agentnet(
        &b,
        &[
            "identity",
            "import",
            "--in",
            export.to_str().unwrap(),
            "--passphrase-file",
            pw.to_str().unwrap(),
        ],
    );
    assert!(!imp2.status.success());
    // wrong passphrase
    let bad = write_file(t.path(), "bad", "wrong\n");
    let c = t.path().join("c");
    let imp3 = agentnet(
        &c,
        &[
            "identity",
            "import",
            "--in",
            export.to_str().unwrap(),
            "--passphrase-file",
            bad.to_str().unwrap(),
        ],
    );
    assert!(!imp3.status.success());
    // insecure passphrase file permissions are refused
    std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o644)).unwrap();
    let d = t.path().join("d");
    let imp4 = agentnet(
        &d,
        &[
            "identity",
            "import",
            "--in",
            export.to_str().unwrap(),
            "--passphrase-file",
            pw.to_str().unwrap(),
        ],
    );
    assert!(!imp4.status.success());
}

#[test]
fn rotate_kem_keeps_the_address_and_changes_the_record() {
    let t = tempfile::tempdir().unwrap();
    let (a, addr) = init(t.path(), "a");
    let before = contact_record(&a);
    let v = json_ok(&a, &["identity", "rotate-kem", "--keep-hours", "1"]);
    assert_eq!(v["agent_id"], addr.as_str());
    assert_ne!(v["contact_record"].as_str().unwrap(), before);
    assert_eq!(contact_record(&a), v["contact_record"].as_str().unwrap());
}

#[test]
fn every_command_has_help_and_the_top_level_documents_exit_codes() {
    let t = tempfile::tempdir().unwrap();
    let top = agentnet(t.path(), &["--help"]);
    assert!(top.status.success());
    assert!(stdout(&top).contains("EXIT CODES"));
    let cmds: &[&[&str]] = &[
        &["init"],
        &["serve"],
        &["mcp"],
        &["identity"],
        &["identity", "show"],
        &["identity", "export"],
        &["identity", "import"],
        &["identity", "rotate-kem"],
        &["contact"],
        &["contact", "add"],
        &["contact", "list"],
        &["contact", "trust"],
        &["contact", "remove"],
        &["quarantine"],
        &["quarantine", "list"],
        &["quarantine", "release"],
        &["send"],
        &["inbox"],
        &["ack"],
        &["status"],
        &["outbox"],
        &["trigger"],
        &["trigger", "create"],
        &["trigger", "list"],
        &["trigger", "delete"],
        &["events"],
        &["events", "tail"],
        &["network"],
        &["network", "status"],
        &["doctor"],
        &["relay"],
        &["relay", "print-config"],
    ];
    for c in cmds {
        let mut a: Vec<&str> = c.to_vec();
        a.push("--help");
        let o = agentnet(t.path(), &a);
        assert!(o.status.success(), "{c:?}: {}", stderr(&o));
        assert!(stdout(&o).contains("Usage"), "{c:?}");
    }
    let bad = agentnet(t.path(), &["frobnicate"]);
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn relay_print_config_has_the_verified_flags_and_marks_tailscale_untested() {
    let t = tempfile::tempdir().unwrap();
    let o = agentnet(
        t.path(),
        &[
            "relay",
            "print-config",
            "--ip",
            "10.0.0.5",
            "--peer-id",
            "16Uiu2HAmTEST",
            "--client-ip",
            "10.0.0.6",
        ],
    );
    assert!(o.status.success());
    let s = stdout(&o);
    for flag in [
        "--discv5-discovery=false",
        "--peer-exchange=false",
        "--relay-peer-exchange=false",
        "--rendezvous=false",
        "--enable-kad-discovery=false",
        "--quic-support=false",
        "--mix=false",
        "--rln-relay=false",
        "--dns-addrs-name-server=127.0.0.1",
        "--nat=extip:10.0.0.5",
        "--nat=extip:10.0.0.6",
        "--cluster-id=66",
        "--num-shards-in-network=1",
        "--shard=0",
        "--staticnode=/ip4/10.0.0.5/tcp/60000/p2p/16Uiu2HAmTEST",
        "--store=true",
        "--store=false",
        "wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73",
    ] {
        assert!(s.contains(flag), "missing {flag}");
    }
    // retention: 7 days (the daemon's default recovery horizon), not the 1 h spike test default
    assert!(s.contains("--store-message-retention-policy=time:604800;capacity:100000"));
    assert!(!s.contains("--store-message-retention-policy=time:3600"));
    // receive-cache capacity raised from the node default of 50 on both flags
    assert!(s.contains("--rest-relay-cache-capacity=1000"));
    assert!(s.contains("--rest-messaging-cache-capacity=1000"));
    // the bridge snippet publishes REST on the host loopback only, and the host-network snippet keeps REST on 127.0.0.1
    assert!(s.contains("\"127.0.0.1:18640:8645\""));
    assert!(s.contains("safe only with the 127.0.0.1: port mapping"));
    let host = s
        .split("## docker-compose: relay node, host network")
        .nth(1)
        .and_then(|t| t.split("## agentnet.toml").next())
        .expect("host-network compose snippet");
    assert!(host.contains("network_mode: host"));
    assert!(host.contains("--rest-address=127.0.0.1"));
    assert!(!host.contains("--rest-address=0.0.0.0"));
    assert!(!host.contains("ports:"));
    assert!(s.contains("ONE Logos Delivery client node PER AGENT"));
    assert!(s.contains("Tailscale variant (UNTESTED)"));
    assert!(s.contains("UNTESTED - not run"));
    // relay-side half-open socket mitigation (results/reconnect): bridge compose sets the sysctl, host-network compose says to set it on the host
    assert!(s.contains("sysctls: {net.ipv4.tcp_retries2: \"6\"}"));
    assert!(s.contains("sysctl -w net.ipv4.tcp_retries2=6"));
    assert!(s.contains("half-open"));
    let j = json_ok(t.path(), &["relay", "print-config"]);
    assert!(j["relay_flags"].as_array().unwrap().len() > 20);
}

#[test]
fn doctor_reports_problems_with_actions_and_exit_code_7() {
    let t = tempfile::tempdir().unwrap();
    let (a, _) = init(t.path(), "a");
    let o = agentnet(&a, &["doctor"]);
    // no node and no daemon in this test
    assert_eq!(o.status.code(), Some(7), "{}", stdout(&o));
    let s = stdout(&o);
    assert!(s.contains("[ok  ] data dir permissions"), "{s}");
    assert!(s.contains("[ok  ] config"), "{s}");
    assert!(s.contains("[FAIL] node reachable"), "{s}");
    assert!(s.contains("--data-dir") && s.contains(" serve`"), "{s}");
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o755)).unwrap();
    let o = agentnet(&a, &["doctor"]);
    assert!(stdout(&o).contains("[FAIL] data dir permissions"));
    std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o700)).unwrap();
    let o = agentnet(&a, &["--json", "doctor"]);
    assert_eq!(o.status.code(), Some(7));
    let j: serde_json::Value = serde_json::from_str(stdout(&o).trim()).unwrap();
    assert!(j
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "config" && c["level"] == "ok"));
}

/// A node stand-in that answers every request with `200 OK` (doctor's /health probe).
fn fake_node() -> String {
    use std::io::{Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        }
    });
    url
}

#[test]
fn doctor_exit_zero_with_the_daemon_down_but_ready_mode_fails_and_says_why() {
    let t = tempfile::tempdir().unwrap();
    let a = t.path().join("a");
    let node = fake_node();
    ok(&a, &["init", "--peer", PEER, "--node-url", &node]);
    // default mode: the unavailable daemon is only a warning
    let o = agentnet(&a, &["doctor"]);
    assert_eq!(o.status.code(), Some(0), "{}{}", stdout(&o), stderr(&o));
    assert!(
        stdout(&o).contains("[warn] daemon socket"),
        "{}",
        stdout(&o)
    );
    assert!(stdout(&o).contains("[skip] isolation"), "{}", stdout(&o));
    // readiness mode: same stdout, exit 7, reasons on stderr
    let r = agentnet(&a, &["doctor", "--ready"]);
    assert_eq!(r.status.code(), Some(7), "{}{}", stdout(&r), stderr(&r));
    assert_eq!(stdout(&r), stdout(&o));
    let e = stderr(&r);
    assert!(e.contains("NOT READY"), "{e}");
    assert!(e.contains("daemon socket: warning"), "{e}");
    assert!(e.contains("isolation: skipped"), "{e}");
    assert!(e.contains("transport ready: not run"), "{e}");
}

#[tokio::test]
async fn doctor_ready_mode_passes_for_a_running_daemon_with_a_ready_transport() {
    let t = tempfile::tempdir().unwrap();
    let a = t.path().join("a");
    let node = fake_node();
    ok(&a, &["init", "--peer", PEER, "--node-url", &node]);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    let clock = MockClock::new(now_ns);
    let net = MockNetwork::with_clock(clock.clone());
    let cfg = DaemonConfig::load(&a.join("agentnet.toml")).unwrap();
    let d =
        Daemon::start_with_transport(&a, cfg, Arc::new(net.endpoint()), Arc::new(clock.clone()))
            .await
            .unwrap();
    let a2 = a.clone();
    let r = tokio::task::spawn_blocking(move || agentnet(&a2, &["doctor", "--ready"]))
        .await
        .unwrap();
    assert_eq!(r.status.code(), Some(0), "{}{}", stdout(&r), stderr(&r));
    assert!(
        stdout(&r).contains("[ok  ] daemon socket"),
        "{}",
        stdout(&r)
    );
    assert!(
        stdout(&r).contains("[ok  ] transport ready"),
        "{}",
        stdout(&r)
    );
    assert!(
        stdout(&r).contains("[ok  ] local inbox database"),
        "{}",
        stdout(&r)
    );
    assert!(stdout(&r).contains("history sync"), "{}", stdout(&r));
    assert!(stderr(&r).contains("ready:"), "{}", stderr(&r));
    d.shutdown().await;
}

#[test]
fn doctor_ready_mode_with_a_failing_check_still_exits_7_and_json_stays_a_check_array() {
    let t = tempfile::tempdir().unwrap();
    let (a, _) = init(t.path(), "a");
    let r = agentnet(&a, &["--json", "doctor", "--ready"]);
    assert_eq!(r.status.code(), Some(7));
    let j: serde_json::Value = serde_json::from_str(stdout(&r).trim()).unwrap();
    assert!(j.as_array().unwrap().iter().any(|c| c["name"] == "config"));
    assert!(stderr(&r).contains("NOT READY"), "{}", stderr(&r));
}

#[test]
fn serve_runs_rejects_a_second_instance_and_stops_cleanly_on_sigterm() {
    let t = tempfile::tempdir().unwrap();
    let (a, addr) = init(t.path(), "a");
    let mut child = Command::new(BIN)
        .arg("--data-dir")
        .arg(&a)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let sock = a.join("agentnet.sock");
    let start = std::time::Instant::now();
    while !sock.exists() && start.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(sock.exists(), "daemon did not start");
    assert_eq!(mode(&sock), 0o600);

    // a second daemon exits with a clear error
    let second = agentnet(&a, &["serve"]);
    assert_eq!(second.status.code(), Some(1));
    assert!(
        stderr(&second).contains("another AgentNet process"),
        "{}",
        stderr(&second)
    );
    // maintenance commands that need the lock refuse too
    let rot = agentnet(&a, &["identity", "rotate-kem"]);
    assert!(!rot.status.success());
    assert!(stderr(&rot).contains("another AgentNet process"));

    // CLI talks to the daemon: the node is not running, so status is not ready
    let st = json_ok(&a, &["network", "status"]);
    assert_eq!(st["network"]["mode"], "private");
    assert_eq!(st["network"]["ready"], false);
    assert_eq!(st["daemon"]["agent_id"], addr.as_str());
    let ob = json_ok(&a, &["outbox"]);
    assert_eq!(ob["records"].as_array().unwrap().len(), 0);
    // an unknown recipient is a clean error with the right exit code
    let (_, stranger) = init(t.path(), "z");
    let send = agentnet(&a, &["send", &stranger, "hi"]);
    assert_eq!(send.status.code(), Some(5), "{}", stderr(&send));

    kill_term(child.id());
    let status = child.wait().unwrap();
    assert!(status.success(), "serve must exit 0 on SIGTERM: {status:?}");
    assert!(!sock.exists(), "socket must be removed on shutdown");
}

// ------------------------------------------------------------------ mcp

#[tokio::test]
async fn mcp_without_a_daemon_starts_and_every_tool_says_unavailable() {
    let t = tempfile::tempdir().unwrap();
    let (a, _) = init(t.path(), "a");
    let c = mcp_client(&a, &[])
        .await
        .expect("mcp must start without a daemon");
    let tools = c.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 15);
    for (tool, args) in [
        ("get_identity", json!({})),
        ("read_inbox", json!({})),
        ("network_status", json!({})),
        (
            "send_message",
            json!({"recipient": "an1xxxxxxxx", "body": "x"}),
        ),
    ] {
        let r = call(&c, tool, args).await;
        let e = error_json(&r);
        assert_eq!(e["error"]["code"], "unavailable", "{tool}: {e}");
        assert!(
            e["error"]["message"].as_str().unwrap().contains(" serve`"),
            "{tool}: {e}"
        );
    }
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn mcp_stdio_is_a_thin_client_of_a_running_daemon() {
    // Two daemons in this process on a mock network; `agentnet mcp` (a child
    // process) is the thin client of A.
    let t = tempfile::tempdir().unwrap();
    let (a, addr_a) = init(t.path(), "a");
    let (b, addr_b) = init(t.path(), "b");
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    let clock = MockClock::new(now_ns);
    let net = MockNetwork::with_clock(clock.clone());
    let mut cfg = DaemonConfig::load(&a.join("agentnet.toml")).unwrap();
    cfg.delivery.poll_interval_ms = 20;
    let da = Daemon::start_with_transport(
        &a,
        cfg.clone(),
        Arc::new(net.endpoint()),
        Arc::new(clock.clone()),
    )
    .await
    .unwrap();
    let db =
        Daemon::start_with_transport(&b, cfg, Arc::new(net.endpoint()), Arc::new(clock.clone()))
            .await
            .unwrap();
    // contacts via the CLI (blocking commands run on a blocking thread)
    let (ra, rb) = (contact_record(&a), contact_record(&b));
    let (a2, b2, addr_b2) = (a.clone(), b.clone(), addr_b.clone());
    tokio::task::spawn_blocking(move || {
        let fa = write_file(&a2, "peer.json", &rb);
        let fb = write_file(&b2, "peer.json", &ra);
        ok(
            &a2,
            &[
                "contact",
                "add",
                &format!("@{}", fa.display()),
                "--expect",
                &addr_b2,
            ],
        );
        ok(&b2, &["contact", "add", &format!("@{}", fb.display())]);
    })
    .await
    .unwrap();

    let c = mcp_client(&a, &[]).await.unwrap();
    let id = call(&c, "get_identity", json!({})).await;
    assert_eq!(structured(&id)["agent_id"], addr_a.as_str());
    let sent = call(
        &c,
        "send_message",
        json!({"recipient": addr_b, "body": "via mcp stdio"}),
    )
    .await;
    let mid = structured(&sent)["message_id"].as_str().unwrap().to_owned();

    // B's own API sees it; A's MCP status reaches delivered
    let bapi = db.api();
    let start = std::time::Instant::now();
    loop {
        let inbox = bapi.read_inbox(ReadInboxRequest::default()).await.unwrap();
        if inbox.records.len() == 1 {
            assert_eq!(inbox.records[0].body, "via mcp stdio");
            // `inbox --message-id` fetches exactly the message an event names.
            let (b3, mid3) = (b.clone(), mid.clone());
            let (one, nf, conflicting) = tokio::task::spawn_blocking(move || {
                let one = json_ok(&b3, &["inbox", "--message-id", &mid3]);
                let nf = agentnet(&b3, &["inbox", "--message-id", "no-such-id"]);
                let conflicting = agentnet(&b3, &["inbox", "--message-id", &mid3, "--limit", "1"]);
                (one, nf, conflicting)
            })
            .await
            .unwrap();
            assert_eq!(one["message_id"], mid.as_str());
            assert_eq!(one["body"], "via mcp stdio");
            assert_eq!(one["sender"], addr_a.as_str());
            assert!(!nf.status.success());
            assert!(
                stderr(&nf).to_lowercase().contains("no such message"),
                "{}",
                stderr(&nf)
            );
            assert!(
                !conflicting.status.success(),
                "--message-id excludes paging flags"
            );
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "message did not arrive"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    loop {
        let st = structured(&call(&c, "get_message_status", json!({"message_id": mid})).await);
        if st["state"] == "delivered" {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "never delivered: {st}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // subscriptions/listen on the inbox sees B's reply arrive in A
    let mut sub = c.listen(sub_filter(&["agentnet://inbox"])).await.unwrap();
    let ba = b.clone();
    let addr_a2 = addr_a.clone();
    tokio::task::spawn_blocking(move || {
        ok(&ba, &["send", &addr_a2, "reply"]);
    })
    .await
    .unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(15), sub.next())
        .await
        .expect("no update")
        .unwrap();
    assert!(format!("{ev:?}").contains("agentnet://inbox"), "{ev:?}");
    let inbox = structured(&call(&c, "read_inbox", json!({})).await);
    assert_eq!(inbox["records"][0]["body"], "reply");
    c.cancel().await.unwrap();
    da.shutdown().await;
    db.shutdown().await;
}

#[tokio::test]
async fn mcp_embedded_runs_the_daemon_in_process_and_holds_the_lock() {
    let t = tempfile::tempdir().unwrap();
    let (a, addr) = init(t.path(), "a");
    let c = mcp_client(&a, &["--embedded"])
        .await
        .expect("embedded mcp starts");
    let id = call(&c, "get_identity", json!({})).await;
    assert_eq!(structured(&id)["agent_id"], addr.as_str());
    // The embedded process owns the data-directory lock: no second daemon.
    let a2 = a.clone();
    let second = tokio::task::spawn_blocking(move || agentnet(&a2, &["serve"]))
        .await
        .unwrap();
    assert_eq!(second.status.code(), Some(1));
    assert!(
        stderr(&second).contains("another AgentNet process"),
        "{}",
        stderr(&second)
    );
    c.cancel().await.unwrap();
}

// ----------------------------------------------- hardening: rotation, revocation, replay guard

#[test]
fn rotate_kem_with_revoke_previous_destroys_old_keys_and_bumps_the_epoch() {
    let t = tempfile::tempdir().unwrap();
    let (a, addr) = init(t.path(), "a");
    // plain rotation: epoch 2, one retired key kept
    let v = json_ok(&a, &["identity", "rotate-kem", "--keep-hours", "1"]);
    assert_eq!(v["key_epoch"], 2);
    let id: serde_json::Value =
        serde_json::from_slice(&std::fs::read(a.join("identity.json")).unwrap()).unwrap();
    assert_eq!(id["previous_kems"].as_array().unwrap().len(), 1);
    // revoking rotation: epoch 3, no retired keys left on disk, floor signed in the record
    let v = json_ok(&a, &["identity", "rotate-kem", "--revoke-previous"]);
    assert_eq!(v["agent_id"], addr.as_str());
    assert_eq!(v["key_epoch"], 3);
    let id: serde_json::Value =
        serde_json::from_slice(&std::fs::read(a.join("identity.json")).unwrap()).unwrap();
    assert_eq!(id["previous_kems"].as_array().unwrap().len(), 0);
    assert_eq!(id["min_valid_epoch"], 3);
    let rec = agentnet_core::crypto::VerifiedContact::parse_and_verify(
        v["contact_record"].as_str().unwrap(),
        i64::MAX / 2,
    )
    .unwrap();
    assert_eq!(rec.key_epoch, 3);
    assert_eq!(rec.revoked_kem_epochs_below, 3);
    assert_eq!(rec.suites, vec![1]);
}

#[test]
fn identity_revoke_writes_a_signed_tombstone_and_blocks_further_changes() {
    let t = tempfile::tempdir().unwrap();
    let (a, addr) = init(t.path(), "a");
    let o = agentnet(&a, &["identity", "show-revocation"]);
    assert_eq!(o.status.code(), Some(5), "not revoked yet: {}", stderr(&o));
    let bad = agentnet(&a, &["identity", "revoke", "--reason", ""]);
    assert!(!bad.status.success());
    assert!(!a.join("revocation.json").exists());

    let v = json_ok(&a, &["identity", "revoke", "--reason", "key stolen"]);
    assert_eq!(v["address"], addr.as_str());
    let doc = v["revocation"].as_str().unwrap().to_owned();
    assert_eq!(mode(&a.join("revocation.json")), 0o600);
    // the printed document verifies and names this address
    let rev =
        agentnet_core::crypto::VerifiedRevocation::parse_and_verify(&doc, i64::MAX / 2).unwrap();
    assert_eq!(rev.address.to_string(), addr);
    assert_eq!(rev.reason, "key stolen");
    // show-revocation prints the same document; identity show reports it
    let s = json_ok(&a, &["identity", "show-revocation"]);
    assert_eq!(s["revocation"].as_str().unwrap(), doc);
    assert_eq!(json_ok(&a, &["identity", "show"])["revoked"], true);
    // irreversible and not repeatable; rotating is refused
    assert!(!agentnet(&a, &["identity", "revoke", "--reason", "again"])
        .status
        .success());
    assert!(!agentnet(&a, &["identity", "rotate-kem"]).status.success());
    // doctor says so
    let d = stdout(&agentnet(&a, &["doctor"]));
    assert!(d.contains("[warn] identity revoked"), "{d}");
}

#[test]
fn identity_import_starts_in_replay_guard_mode_unless_told_otherwise() {
    let t = tempfile::tempdir().unwrap();
    let (a, addr) = init(t.path(), "a");
    let pw = write_file(t.path(), "pw", "correct horse battery staple\n");
    let export = t.path().join("export.age");
    ok(
        &a,
        &[
            "identity",
            "export",
            "--out",
            export.to_str().unwrap(),
            "--passphrase-file",
            pw.to_str().unwrap(),
        ],
    );
    let args = |extra: &[&'static str]| {
        let mut v = vec![
            "identity",
            "import",
            "--in",
            export.to_str().unwrap(),
            "--passphrase-file",
            pw.to_str().unwrap(),
            "--peer",
            PEER,
        ];
        v.extend_from_slice(extra);
        v.into_iter().map(str::to_owned).collect::<Vec<_>>()
    };
    let run = |dir: &std::path::Path, extra: &[&'static str]| {
        let a = args(extra);
        let r: Vec<&str> = a.iter().map(String::as_str).collect();
        json_ok(dir, &r)
    };
    let guarded = t.path().join("guarded");
    let v = run(&guarded, &[]);
    assert_eq!(v["address"], addr.as_str());
    assert_eq!(v["replay_guard"], true);
    let sidecar = std::fs::read_to_string(guarded.join("agentnet.generation")).unwrap();
    assert!(sidecar.contains("\"guard\":\"imported\""), "{sidecar}");
    let d = stdout(&agentnet(&guarded, &["doctor"]));
    assert!(d.contains("[warn] replay guard"), "{d}");

    let open = t.path().join("open");
    let v = run(&open, &["--no-replay-guard"]);
    assert_eq!(v["replay_guard"], false);
    assert!(!open.join("agentnet.generation").exists());
    let d = stdout(&agentnet(&open, &["doctor"]));
    assert!(d.contains("[ok  ] replay guard"), "{d}");

    // `doctor --accept-rollback` drops the import marker (daemon stopped)
    let o = agentnet(&guarded, &["doctor", "--accept-rollback"]);
    assert!(stderr(&o).contains("accepted"), "{}", stderr(&o));
    let sidecar = std::fs::read_to_string(guarded.join("agentnet.generation")).unwrap();
    assert!(sidecar.contains("\"guard\":null"), "{sidecar}");
    let d = stdout(&agentnet(&guarded, &["doctor"]));
    assert!(d.contains("[ok  ] replay guard"), "{d}");
    // nothing left to accept
    let o = agentnet(&guarded, &["doctor", "--accept-rollback"]);
    assert!(stderr(&o).contains("nothing to accept"), "{}", stderr(&o));
}

#[test]
fn doctor_always_warns_that_a_second_instance_of_the_identity_cannot_be_detected() {
    let t = tempfile::tempdir().unwrap();
    let (a, _) = init(t.path(), "a");
    let d = stdout(&agentnet(&a, &["doctor"]));
    assert!(d.contains("[warn] single instance"), "{d}");
}

#[tokio::test]
async fn contact_revoke_imports_a_tombstone_into_a_running_daemon() {
    let t = tempfile::tempdir().unwrap();
    let (a, _addr_a) = init(t.path(), "a");
    let (b, addr_b) = init(t.path(), "b");
    // B is revoked (daemon stopped) and its notice is carried out of band
    let rev = json_ok(&b, &["identity", "revoke", "--reason", "retired"])["revocation"]
        .as_str()
        .unwrap()
        .to_owned();
    let record_b = contact_record(&b);
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;
    let clock = MockClock::new(now_ns);
    let net = MockNetwork::with_clock(clock.clone());
    let cfg = DaemonConfig::load(&a.join("agentnet.toml")).unwrap();
    let da = Daemon::start_with_transport(&a, cfg, Arc::new(net.endpoint()), Arc::new(clock))
        .await
        .unwrap();
    let (a2, addr_b2) = (a.clone(), addr_b.clone());
    let out = tokio::task::spawn_blocking(move || {
        let fr = write_file(&a2, "peer.json", &record_b);
        ok(&a2, &["contact", "add", &format!("@{}", fr.display())]);
        let ft = write_file(&a2, "tomb.json", &rev);
        let first = json_ok(&a2, &["contact", "revoke", &format!("@{}", ft.display())]);
        let again = json_ok(&a2, &["contact", "revoke", &format!("@{}", ft.display())]);
        let list = json_ok(&a2, &["contact", "list"]);
        // re-adding / re-trusting a revoked address is refused (exit 6)
        let readd = agentnet(&a2, &["contact", "add", &format!("@{}", fr.display())]);
        let retrust = agentnet(&a2, &["contact", "trust", &addr_b2, "trusted"]);
        let garbage = agentnet(&a2, &["contact", "revoke", "not a document"]);
        (
            first,
            again,
            list,
            readd.status.code(),
            retrust.status.code(),
            garbage.status.code(),
        )
    })
    .await
    .unwrap();
    let (first, again, list, readd, retrust, garbage) = out;
    assert_eq!(first["newly_revoked"], true);
    assert_eq!(first["address"], addr_b.as_str());
    assert_eq!(again["newly_revoked"], false);
    assert_eq!(list[0]["revoked"], true);
    assert_eq!(list[0]["trust"], "blocked");
    assert_eq!(readd, Some(6));
    assert_eq!(retrust, Some(6));
    assert_eq!(garbage, Some(4));
    da.shutdown().await;
}

#[test]
fn top_level_help_says_the_cryptography_is_not_audited() {
    let t = tempfile::tempdir().unwrap();
    let h = stdout(&agentnet(t.path(), &["--help"]));
    assert!(h.contains("NOT AUDITED"), "{h}");
    assert!(h.contains("independent cryptographic review"), "{h}");
}

#[tokio::test]
async fn discovery_commands_are_denied_by_default() {
    let t = tempfile::tempdir().unwrap();
    let (a, _) = init(t.path(), "a");
    let clock = MockClock::new(wall_ns());
    let net = MockNetwork::with_clock(clock.clone());
    let cfg = DaemonConfig::load(&a.join("agentnet.toml")).unwrap();
    assert!(!cfg.discovery.enabled, "init must write discovery off");
    let da = Daemon::start_with_transport(&a, cfg, Arc::new(net.endpoint()), Arc::new(clock))
        .await
        .unwrap();
    let a2 = a.clone();
    let outs = tokio::task::spawn_blocking(move || {
        vec![
            agentnet(
                &a2,
                &[
                    "discovery",
                    "advertise",
                    "--topic",
                    "general",
                    "--capability",
                    "x",
                ],
            ),
            agentnet(&a2, &["discovery", "withdraw", "--topic", "general"]),
            agentnet(&a2, &["--json", "discovery", "list", "--topic", "general"]),
        ]
    })
    .await
    .unwrap();
    for o in &outs {
        assert_eq!(o.status.code(), Some(6), "{}", stderr(o));
        assert!(
            stderr(o).contains("disabled by host policy"),
            "{}",
            stderr(o)
        );
    }
    assert!(stdout(&outs[2]).contains("policy_denied"));
    assert_eq!(net.total_publish_count(), 0);
    da.shutdown().await;
}

#[tokio::test]
async fn discovery_advertise_list_add_contact_and_withdraw_via_the_cli() {
    let t = tempfile::tempdir().unwrap();
    let (a, addr_a) = init(t.path(), "a");
    let (b, _) = init(t.path(), "b");
    let clock = MockClock::new(wall_ns());
    let net = MockNetwork::with_clock(clock.clone());
    let mut cfg = DaemonConfig::load(&a.join("agentnet.toml")).unwrap();
    cfg.delivery.poll_interval_ms = 20;
    cfg.discovery.enabled = true;
    cfg.discovery.topics = vec!["general".into()];
    let da = Daemon::start_with_transport(
        &a,
        cfg.clone(),
        Arc::new(net.endpoint()),
        Arc::new(clock.clone()),
    )
    .await
    .unwrap();
    let db = Daemon::start_with_transport(&b, cfg, Arc::new(net.endpoint()), Arc::new(clock))
        .await
        .unwrap();
    let (a2, b2, addr_a2) = (a.clone(), b.clone(), addr_a.clone());
    let out = tokio::task::spawn_blocking(move || {
        let adv = json_ok(
            &a2,
            &[
                "discovery",
                "advertise",
                "--topic",
                "general",
                "--capability",
                "translate.de:German to English",
                "--capability",
                "summarize",
                "--display-name",
                "Translator",
                "--ttl",
                "600",
            ],
        );
        // wait until B has received it
        let mut listed = serde_json::Value::Null;
        for _ in 0..200 {
            listed = json_ok(&b2, &["discovery", "list", "--topic", "general"]);
            if !listed["agents"].as_array().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let human = ok(&b2, &["discovery", "list", "--topic", "general"]);
        let filtered = json_ok(
            &b2,
            &[
                "discovery",
                "list",
                "--topic",
                "general",
                "--capability",
                "summarize",
            ],
        );
        let none = json_ok(
            &b2,
            &[
                "discovery",
                "list",
                "--topic",
                "general",
                "--capability",
                "nothing",
            ],
        );
        let before = json_ok(&b2, &["contact", "list"]);
        let record = listed["agents"][0]["contact_record"]
            .as_str()
            .unwrap()
            .to_owned();
        let f = write_file(&b2, "found.json", &record);
        let added = json_ok(
            &b2,
            &[
                "contact",
                "add",
                &format!("@{}", f.display()),
                "--expect",
                &addr_a2,
            ],
        );
        let wrong_topic = agentnet(&b2, &["discovery", "list", "--topic", "elsewhere"]);
        let withdrawn = json_ok(&a2, &["discovery", "withdraw", "--topic", "general"]);
        let again = json_ok(&a2, &["discovery", "withdraw", "--topic", "general"]);
        let mut after = serde_json::Value::Null;
        for _ in 0..200 {
            after = json_ok(&b2, &["discovery", "list", "--topic", "general"]);
            if after["agents"].as_array().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        (
            adv,
            listed,
            human,
            filtered,
            none,
            before,
            added,
            wrong_topic.status.code(),
            withdrawn,
            again,
            after,
        )
    })
    .await
    .unwrap();
    let (adv, listed, human, filtered, none, before, added, wrong, withdrawn, again, after) = out;
    assert_eq!(adv["seq"], 1);
    assert_eq!(adv["capabilities"][0]["description"], "German to English");
    assert_eq!(adv["capabilities"][1]["description"], "");
    assert_eq!(listed["agents"][0]["address"], addr_a.as_str());
    assert_eq!(listed["agents"][0]["display_name"], "Translator");
    assert_eq!(listed["agents"][0]["is_contact"], false);
    assert!(
        human.contains("claims capability translate.de: German to English"),
        "{human}"
    );
    assert!(human.contains("unverified claims"), "{human}");
    assert_eq!(filtered["agents"].as_array().unwrap().len(), 1);
    assert!(none["agents"].as_array().unwrap().is_empty());
    assert!(
        before.as_array().unwrap().is_empty(),
        "discovery adds no contact"
    );
    assert_eq!(added["address"], addr_a.as_str());
    assert_eq!(wrong, Some(6));
    assert_eq!(withdrawn["withdrawn"], true);
    assert_eq!(again["withdrawn"], false);
    assert!(after["agents"].as_array().unwrap().is_empty());
    da.shutdown().await;
    db.shutdown().await;
}

#[test]
fn discovery_help_warns_that_adverts_are_public() {
    let t = tempfile::tempdir().unwrap();
    let h = stdout(&agentnet(t.path(), &["discovery", "--help"]));
    assert!(h.contains("PLAINTEXT"), "{h}");
    assert!(h.contains("not a global directory"), "{h}");
    let h = stdout(&agentnet(t.path(), &["discovery", "advertise", "--help"]));
    assert!(h.contains("NAME[:DESCRIPTION]"), "{h}");
}

/// Identities are created with the wall clock, so mock-network tests start there.
fn wall_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64
}
