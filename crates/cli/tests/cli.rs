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
    assert!(s.contains("Tailscale variant (UNTESTED)"));
    assert!(s.contains("UNTESTED - not run"));
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
    assert!(s.contains("agentnet serve"), "{s}");
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
    assert_eq!(tools.len(), 10);
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
            e["error"]["message"]
                .as_str()
                .unwrap()
                .contains("agentnet serve"),
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
