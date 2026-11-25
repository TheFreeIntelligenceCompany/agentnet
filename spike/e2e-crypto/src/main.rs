//! Spike A2/B1: bidirectional ENCRYPTED messaging + durable identity + security rejections over the real
//! local relay (docker topology in ../relay). LOCALHOST / container network only; amd64 node image under qemu.
//!
//! Usage: e2e-crypto <all|roundtrip|wrong-recipient|forgery|tamper|replay|expiry|persistence|boundaries|load|metadata|bench>
//!        [--out DIR] [--work DIR] [--poll-ms N]
mod crypto;
mod load;
mod net;
mod persist;
mod suite;

use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

static LOG: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();
pub fn log_line(s: &str) {
    println!("{s}");
    if let Some(m) = LOG.get() {
        if let Some(f) = lk(m).as_mut() {
            let _ = writeln!(f, "{s}");
        }
    }
}
#[macro_export]
macro_rules! log {
    ($($a:tt)*) => { $crate::log_line(&format!($($a)*)) };
}
pub fn lk<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct Ctx {
    pub api: net::Api,
    pub out: PathBuf,
    pub work: PathBuf,
    pub poll_ms: u64,
    pub load_runs: Vec<(usize, u64)>,
    pub pub_conc: usize,
}
pub struct TestResult {
    pub name: &'static str,
    pub pass: bool,
    pub data: Value,
    pub failures: Vec<String>,
}
#[derive(Default)]
pub struct Checker {
    pub failures: Vec<String>,
}
impl Checker {
    pub fn check(&mut self, cond: bool, msg: impl Into<String>) {
        let m = msg.into();
        if !cond {
            log!("  CHECK FAILED: {m}");
            self.failures.push(m);
        } else {
            log!("  ok: {m}");
        }
    }
    pub fn done(self, name: &'static str, data: Value) -> TestResult {
        TestResult {
            name,
            pass: self.failures.is_empty(),
            data,
            failures: self.failures,
        }
    }
}

fn arg(a: &[String], k: &str, d: &str) -> String {
    a.iter()
        .position(|x| x == k)
        .and_then(|i| a.get(i + 1))
        .cloned()
        .unwrap_or_else(|| d.into())
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let cmd = a.get(1).cloned().unwrap_or_else(|| "all".into());
    // child subcommands used by the persistence test (separate OS processes); they print one JSON line and nothing else
    if cmd.starts_with("child-") {
        std::process::exit(persist::child_main(&cmd, &a).await);
    }
    let out = PathBuf::from(arg(&a, "--out", "../../results/a2-e2e-crypto"));
    let work = PathBuf::from(arg(&a, "--work", "../../results/a2-e2e-crypto/work"));
    let poll_ms: u64 = arg(&a, "--poll-ms", "25").parse().unwrap_or(25);
    let _ = std::fs::create_dir_all(&out);
    let _ = std::fs::create_dir_all(&work);
    let stamp = crypto::now_ms();
    let logpath = out.join(format!("run-{cmd}-{stamp}.log"));
    let _ = LOG.set(Mutex::new(std::fs::File::create(&logpath).ok()));
    let load_runs: Vec<(usize, u64)> = arg(&a, "--load-runs", "1:50,10:50,100:50,100:200,100:1000")
        .split(',')
        .filter_map(|x| {
            let (n, p) = x.split_once(':')?;
            Some((n.parse().ok()?, p.parse().ok()?))
        })
        .collect();
    let pub_conc: usize = arg(&a, "--pub-conc", "2").parse().unwrap_or(8);
    let ctx = Ctx {
        api: net::Api::new(),
        out: out.clone(),
        work,
        poll_ms,
        load_runs,
        pub_conc,
    };
    log!("e2e-crypto {cmd} started at unix_ms={stamp}; LOCALHOST/container network; relay nodes NA={} NB={} R1={}", net::NA, net::NB, net::R1);
    let order = [
        "roundtrip",
        "wrong-recipient",
        "forgery",
        "tamper",
        "replay",
        "expiry",
        "boundaries",
        "metadata",
        "bench",
        "load",
        "persistence",
    ];
    let todo: Vec<&str> = if cmd == "all" {
        order.to_vec()
    } else {
        vec![cmd.as_str()]
    };
    let mut results = vec![];
    for t in todo {
        log!("\n=== TEST {t} ===");
        let r = match t {
            "roundtrip" => suite::roundtrip(&ctx).await,
            "wrong-recipient" => suite::wrong_recipient(&ctx).await,
            "forgery" => suite::forgery(&ctx).await,
            "tamper" => suite::tamper(&ctx).await,
            "replay" => suite::replay(&ctx).await,
            "expiry" => suite::expiry(&ctx).await,
            "boundaries" => suite::boundaries(&ctx).await,
            "metadata" => suite::metadata(&ctx).await,
            "bench" => suite::bench(&ctx).await,
            "load" => load::load(&ctx).await,
            "persistence" => persist::persistence(&ctx).await,
            other => {
                eprintln!("unknown subcommand {other}");
                std::process::exit(2);
            }
        };
        log!(
            "=== {} : {} ===",
            r.name,
            if r.pass { "PASS" } else { "FAIL" }
        );
        for f in &r.failures {
            log!("  failure: {f}");
        }
        let _ = std::fs::write(
            out.join(format!("{}-{stamp}.json", r.name)),
            serde_json::to_string_pretty(&r.data).unwrap_or_default(),
        );
        results.push(r);
    }
    let summary = json!({
        "note": "LOCALHOST/container-network test (amd64 nwaku image under qemu on arm64 host); synthetic identities",
        "started_unix_ms": stamp,
        "tests": results.iter().map(|r| json!({"name": r.name, "pass": r.pass, "failures": r.failures, "data": r.data})).collect::<Vec<_>>(),
    });
    let sp = out.join(format!("summary-{cmd}-{stamp}.json"));
    let _ = std::fs::write(
        &sp,
        serde_json::to_string_pretty(&summary).unwrap_or_default(),
    );
    log!("\nSUMMARY:");
    for r in &results {
        log!("  {:<16} {}", r.name, if r.pass { "PASS" } else { "FAIL" });
    }
    log!("wrote {} and {}", sp.display(), logpath.display());
    if results.iter().any(|r| !r.pass) {
        std::process::exit(1);
    }
}
