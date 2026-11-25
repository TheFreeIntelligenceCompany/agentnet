//! Test 7: identity persistence, store recovery after restart, migration, concurrent-writer lock.
//! Child subcommands run as separate OS processes of this same binary and print exactly one JSON line.
use crate::crypto::*;
use crate::net::*;
use crate::suite::{send_env, Ep};
use crate::{log, Checker, Ctx, TestResult};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn flag(a: &[String], k: &str) -> Option<String> {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1))
        .cloned()
}

pub async fn child_main(cmd: &str, a: &[String]) -> i32 {
    let Some(dir) = flag(a, "--dir").map(PathBuf::from) else {
        eprintln!("--dir required");
        return 2;
    };
    let _lock = match DirLock::acquire(&dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("LOCKED: {e}");
            return 3;
        }
    };
    let id = match Identity::load(&dir.join("identity.json")) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("IDENTITY: {e}");
            return 4;
        }
    };
    let addr = id.address();
    match cmd {
        "child-show" => {
            println!("{}", json!({"address": addr, "topic": id.topic()}));
            0
        }
        "child-hold" => {
            let ms: u64 = flag(a, "--ms").and_then(|x| x.parse().ok()).unwrap_or(3000);
            println!("{}", json!({"address": addr, "holding_ms": ms}));
            tokio::time::sleep(Duration::from_millis(ms)).await;
            0
        }
        "child-recover" => {
            let node: &str = match flag(a, "--node").as_deref() {
                Some("NB") => NB,
                Some("NA") => NA,
                _ => R1,
            };
            let start: u128 = flag(a, "--start").and_then(|x| x.parse().ok()).unwrap_or(0);
            let end: u128 = flag(a, "--end").and_then(|x| x.parse().ok()).unwrap_or(0);
            let mut dd = match Dedupe::open(&dir.join("dedupe.txt")) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("DEDUPE: {e}");
                    return 5;
                }
            };
            let loaded = dd.len();
            let api = Api::new();
            let mut entries = Err("no attempt".to_string());
            for _ in 0..40 {
                entries = api.store_all(node, &id.topic(), start, end).await;
                if entries.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let entries = match entries {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("STORE: {e}");
                    return 6;
                }
            };
            let (mut ok_ids, mut errs): (Vec<String>, BTreeMap<String, u64>) =
                (vec![], BTreeMap::new());
            for en in &entries {
                if let Some(m) = &en.message {
                    let p = B64.decode(&m.payload).unwrap_or_default();
                    match open_frame(&id, &addr, &p, now_ms(), &mut dd) {
                        Ok(o) => ok_ids.push(o.env.message_id),
                        Err(e) => *errs.entry(e.kind().into()).or_default() += 1,
                    }
                }
            }
            println!(
                "{}",
                json!({"address": addr, "store_entries": entries.len(), "dedupe_entries_loaded": loaded, "accepted": ok_ids.len(), "accepted_ids": ok_ids, "rejected": errs})
            );
            0
        }
        _ => 2,
    }
}

struct Child {
    code: i32,
    out: Value,
    err: String,
}
async fn run_child(args: &[&str]) -> Child {
    let exe = std::env::current_exe().unwrap_or_default();
    match tokio::process::Command::new(exe).args(args).output().await {
        Ok(o) => Child {
            code: o.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&o.stdout)
                .lines()
                .last()
                .and_then(|l| serde_json::from_str(l).ok())
                .unwrap_or(Value::Null),
            err: String::from_utf8_lossy(&o.stderr).trim().to_string(),
        },
        Err(e) => Child {
            code: -2,
            out: Value::Null,
            err: e.to_string(),
        },
    }
}
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0)
}
fn set_mode(p: &Path, m: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(m));
}

async fn restore_nb(api: &Api) -> (bool, f64) {
    let t = std::time::Instant::now();
    let _ = docker(&["start", "an-nb"]).await;
    let mut healthy = false;
    for _ in 0..1800 {
        if api.healthy(NB).await && api.connected_peers(NB).await >= 1 {
            healthy = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (healthy, t.elapsed().as_secs_f64())
}

pub async fn persistence(ctx: &Ctx) -> TestResult {
    let mut ck = Checker::default();
    let base = ctx.work.join(format!("persist-{}", now_ms()));
    let (d1, d2) = (base.join("B1"), base.join("B2-migrated"));
    let _ = std::fs::create_dir_all(&d1);
    let (d1s, d2s) = (d1.display().to_string(), d2.display().to_string());
    // --- create + save durable identity for B
    let b = Identity::generate(16);
    {
        let _l = DirLock::acquire(&d1);
        if let Err(e) = b.save(&d1.join("identity.json")) {
            ck.check(false, format!("save identity: {e}"));
        }
    }
    let idp = d1.join("identity.json");
    ck.check(
        mode(&idp) == 0o600,
        format!("identity file mode {:o} == 600", mode(&idp)),
    );
    let (b_addr, b_topic) = (b.address(), b.topic());
    log!(
        "B address {b_addr} topic {b_topic} identity file {}",
        idp.display()
    );
    // --- restart (new process) -> same address
    let s1 = run_child(&["child-show", "--dir", &d1s]).await;
    ck.check(
        s1.code == 0 && s1.out["address"] == b_addr.as_str(),
        format!(
            "new process loads identity: address {} == {b_addr}",
            s1.out["address"]
        ),
    );
    // --- insecure permissions refused
    set_mode(&idp, 0o644);
    let s2 = run_child(&["child-show", "--dir", &d1s]).await;
    ck.check(
        s2.code == 4 && s2.err.contains("refusing"),
        format!(
            "identity file with mode 644 refused (exit {}: {})",
            s2.code, s2.err
        ),
    );
    set_mode(&idp, 0o600);
    // --- exclusive lock: parent holds it, then two child processes
    let lock_results;
    {
        let held = DirLock::acquire(&d1);
        ck.check(held.is_ok(), "parent acquired exclusive lock");
        let s3 = run_child(&["child-show", "--dir", &d1s]).await;
        ck.check(
            s3.code == 3 && s3.err.contains("locked"),
            format!(
                "second instance refused while parent holds lock (exit {}: {})",
                s3.code, s3.err
            ),
        );
        let inproc = DirLock::acquire(&d1);
        ck.check(
            inproc.is_err(),
            format!("second in-process acquire refused: {:?}", inproc.err()),
        );
        lock_results = json!({"child_exit": s3.code, "child_stderr": s3.err});
    }
    let hold = tokio::spawn({
        let d = d1s.clone();
        async move { run_child(&["child-hold", "--dir", &d, "--ms", "2500"]).await }
    });
    tokio::time::sleep(Duration::from_millis(800)).await;
    let s4 = run_child(&["child-show", "--dir", &d1s]).await;
    ck.check(
        s4.code == 3,
        format!(
            "child B refused while child A holds lock (exit {}: {})",
            s4.code, s4.err
        ),
    );
    let h = hold.await.unwrap_or(Child {
        code: -9,
        out: Value::Null,
        err: "join".into(),
    });
    ck.check(h.code == 0, "holder child exited cleanly");
    let s5 = run_child(&["child-show", "--dir", &d1s]).await;
    ck.check(
        s5.code == 0,
        "lock released after holder exit: new instance starts",
    );

    // --- seal 20 messages while NB (B's node) is stopped; B's process is not running at all
    let a = Ep::new(16);
    let bc = b.contact();
    crate::suite::ensure_mesh(ctx).await;
    let t0 = now_ns();
    let (ok, o) = docker(&["stop", "-t", "10", "an-nb"]).await;
    ck.check(ok, format!("docker stop an-nb: {o}"));
    let mut sent_ids = vec![];
    let mut perr = vec![];
    for i in 0..20u32 {
        let e = Envelope::new(&a.addr, &b_addr, "chat", format!("offline-{i}"), 3_600_000);
        match send_env(ctx, NA, &a.id, &bc, &e, PadPolicy::Pow2, None).await {
            Ok(_) => sent_ids.push(e.message_id),
            Err(er) => perr.push(format!("{i}: {er}")),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ck.check(
        sent_ids.len() == 20,
        format!("A published 20 while NB down (errors {perr:?})"),
    );
    let (healthy, secs) = restore_nb(&ctx.api).await;
    ck.check(
        healthy,
        format!("an-nb restarted, REST healthy and connected to R1 after {secs:.1}s"),
    );
    crate::suite::ensure_mesh(ctx).await;
    let end = now_ns();
    let (st, en) = (
        t0.saturating_sub(1_000_000_000).to_string(),
        end.to_string(),
    );
    // --- recover in a NEW process through NB's own store client
    let r1 = run_child(&[
        "child-recover",
        "--dir",
        &d1s,
        "--node",
        "NB",
        "--start",
        &st,
        "--end",
        &en,
    ])
    .await;
    let got: HashSet<String> = r1.out["accepted_ids"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let want: HashSet<String> = sent_ids.iter().cloned().collect();
    log!("recover#1 exit {} out {} err {}", r1.code, r1.out, r1.err);
    ck.check(
        r1.code == 0 && got == want && r1.out["accepted"] == 20,
        format!(
            "recover #1 (new process, store via NB after restart): {}/20 accepted, ids match: {}",
            got.len(),
            got == want
        ),
    );
    // --- second recovery run (another process): dedupe persisted on disk -> nothing processed twice
    let r2 = run_child(&[
        "child-recover",
        "--dir",
        &d1s,
        "--node",
        "NB",
        "--start",
        &st,
        "--end",
        &en,
    ])
    .await;
    log!("recover#2 exit {} out {} err {}", r2.code, r2.out, r2.err);
    ck.check(
        r2.code == 0 && r2.out["accepted"] == 0 && r2.out["rejected"]["replay"] == 20,
        format!(
            "recover #2: 0 reprocessed, 20 rejected as replay (loaded {} dedupe entries from disk)",
            r2.out["dedupe_entries_loaded"]
        ),
    );
    // --- migration: copy identity file only into another directory, different process
    let _ = std::fs::create_dir_all(&d2);
    let copied = std::fs::copy(&idp, d2.join("identity.json"));
    ck.check(
        copied.is_ok() && mode(&d2.join("identity.json")) == 0o600,
        format!(
            "identity copied (mode {:o})",
            mode(&d2.join("identity.json"))
        ),
    );
    let m1 = run_child(&["child-show", "--dir", &d2s]).await;
    ck.check(
        m1.out["address"] == b_addr.as_str(),
        "migrated copy has same address",
    );
    let m2 = run_child(&[
        "child-recover",
        "--dir",
        &d2s,
        "--node",
        "NB",
        "--start",
        &st,
        "--end",
        &en,
    ])
    .await;
    let got2: HashSet<String> = m2.out["accepted_ids"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    log!(
        "migrated recover exit {} out {} err {}",
        m2.code,
        m2.out,
        m2.err
    );
    ck.check(
        m2.code == 0 && got2 == want,
        format!(
            "migrated identity (fresh dedupe) decrypts {}/20",
            got2.len()
        ),
    );
    // --- final health of topology
    let peers: Vec<usize> = vec![
        ctx.api.connected_peers(R1).await,
        ctx.api.connected_peers(NA).await,
        ctx.api.connected_peers(NB).await,
    ];
    ck.check(
        peers.iter().all(|p| *p >= 1),
        format!("topology healthy after test, connected peers R1/NA/NB = {peers:?}"),
    );
    let data = json!({"b_address": b_addr, "b_topic": b_topic, "identity_file": idp.display().to_string(), "identity_mode_octal": format!("{:o}", mode(&idp)),
        "nb_restart": {"healthy": healthy, "secs_to_healthy_and_connected": secs}, "lock_tests": lock_results, "child_while_child_holds": {"exit": s4.code, "stderr": s4.err},
        "insecure_perms": {"exit": s2.code, "stderr": s2.err}, "recover_1": r1.out, "recover_2": r2.out, "migrated_recover": m2.out,
        "stderr": [r1.err, r2.err, m2.err], "connected_peers_after": peers});
    ck.done("persistence", data)
}
