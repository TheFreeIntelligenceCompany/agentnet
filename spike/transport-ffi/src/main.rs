//! Disposable A1 spike binary: exercises the `logos-delivery` Rust crate (native liblogosdelivery).
//!
//! Subcommands (all output is one JSON object per line on stdout; diagnostics on stderr):
//!   lifecycle [--iters N] [--port P] [--mode shutdown|drop]   start/stop a node N times in one process
//!   peer --name NAME --port P [--addr-file F] [--connect-file F --connect-host H]
//!        [--count N] [--interval-ms MS] [--payload-bytes B] [--drain-ms MS] [--linger-ms MS]
//!        [--queue-cap C] [--slow-consumer-ms MS]
//!
//! JSON results go to STDERR as lines starting with '{' (the native library logs to STDOUT).
//!
//! Private network only: cluster id 7777, no preset, discv5/dns discovery/peer-exchange off, static dial.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use logos_delivery::{DeliveryConfig, DeliveryEvent, DeliveryNode};
use serde_json::json;
use tokio::sync::{broadcast, mpsc};

const TOPIC: &str = "/agentnet-spike/1/bench/proto";
const CLUSTER_ID: u32 = 7777;

fn cfg(port: u16, storage: &str) -> DeliveryConfig {
    DeliveryConfig::default()
        .no_preset() // no public bootstrap / preset
        .tcp_port(port)
        .discv5_udp_port(port + 1000)
        .log_level("ERROR")
        .call_timeout(Duration::from_secs(30))
        .option("clusterId", CLUSTER_ID)
        .option("numShardsInNetwork", 8)
        .option("shards", (0..8).collect::<Vec<_>>())
        .option("discv5Discovery", false)
        .option("dnsDiscovery", false)
        .option("peerExchange", false)
        .option("nat", "none")
        .option("localStoragePath", storage)
}

macro_rules! emit { ($($a:tt)*) => { eprintln!($($a)*) }; }

fn now_ns() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

fn proc_status(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}
fn rss_kb() -> u64 {
    proc_status("VmRSS:")
}
fn threads() -> u64 {
    proc_status("Threads:")
}
fn fds() -> u64 {
    std::fs::read_dir("/proc/self/fd").map(|d| d.count() as u64).unwrap_or(0)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}
fn arg_or<T: std::str::FromStr>(args: &[String], name: &str, d: T) -> T {
    arg(args, name).and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("lifecycle") => lifecycle(&args[2..]).await,
        Some("peer") => peer(&args[2..]).await,
        _ => {
            eprintln!("usage: ffi-spike lifecycle|peer ...");
            std::process::exit(64);
        }
    }
}

async fn guard<T>(what: &str, d: Duration, f: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(d, f).await {
        Ok(v) => v,
        Err(_) => {
            emit!("{}", json!({"event":"HANG","what":what,"after_s":d.as_secs()}));
            std::process::exit(2);
        }
    }
}

async fn lifecycle(args: &[String]) {
    let iters: u32 = arg_or(args, "--iters", 20);
    let port: u16 = arg_or(args, "--port", 20110);
    let mode = arg(args, "--mode").unwrap_or_else(|| "shutdown".into());
    let settle = Duration::from_millis(arg_or(args, "--settle-ms", 1500));
    let storage = "/tmp/ffi-lifecycle";
    emit!(
        "{}",
        json!({"event":"begin","iters":iters,"port":port,"mode":mode,
               "rss_kb":rss_kb(),"threads":threads(),"fds":fds()})
    );
    for i in 0..iters {
        let t0 = Instant::now();
        let node = guard("start", Duration::from_secs(90), DeliveryNode::start(cfg(port, storage)))
            .await
            .unwrap_or_else(|e| {
                emit!("{}", json!({"event":"START_ERR","iter":i,"err":e.to_string()}));
                std::process::exit(3);
            });
        let start_ms = t0.elapsed().as_secs_f64() * 1e3;
        let t1 = Instant::now();
        let sub = node.subscribe(TOPIC).await.map_err(|e| e.to_string());
        let addrs = node.listen_addresses().await.map(|a| a.len()).unwrap_or(0);
        let mut shutdown_ms = f64::NAN;
        if mode == "shutdown" {
            let t2 = Instant::now();
            let r = guard("shutdown", Duration::from_secs(90), node.shutdown()).await;
            shutdown_ms = t2.elapsed().as_secs_f64() * 1e3;
            if let Err(e) = r {
                emit!("{}", json!({"event":"SHUTDOWN_ERR","iter":i,"err":e.to_string()}));
            }
        }
        let t3 = Instant::now();
        drop(node); // Inner::drop spawns a cleanup thread (destroy ctx) when inside a runtime
        let drop_ms = t3.elapsed().as_secs_f64() * 1e3;
        // let the cleanup thread run to completion before sampling resources
        tokio::time::sleep(settle).await;
        emit!(
            "{}",
            json!({"event":"iter","i":i,"start_ms":start_ms,"sub_ok":sub.is_ok(),"sub_err":sub.err(),
                   "listen_addrs":addrs,"op_ms":t1.elapsed().as_secs_f64()*1e3,
                   "shutdown_ms":shutdown_ms,"drop_ms":drop_ms,
                   "rss_kb":rss_kb(),"threads":threads(),"fds":fds()})
        );
    }
    emit!("{}", json!({"event":"end","rss_kb":rss_kb(),"threads":threads(),"fds":fds()}));
}

#[derive(Default)]
struct Shared {
    peer_seen: AtomicBool,
    queue_dropped: AtomicU64,
    bcast_lagged: AtomicU64,
    ev_sent: AtomicU64,
    ev_propagated: AtomicU64,
    ev_error: AtomicU64,
    ev_queued: AtomicU64,
    ev_other: AtomicU64,
}

async fn peer(args: &[String]) {
    let name = arg(args, "--name").expect("--name");
    let port: u16 = arg_or(args, "--port", 20001);
    let count: u32 = arg_or(args, "--count", 100);
    let interval = Duration::from_millis(arg_or(args, "--interval-ms", 50));
    let pad: usize = arg_or(args, "--payload-bytes", 64);
    let drain = Duration::from_millis(arg_or(args, "--drain-ms", 10_000));
    let linger = Duration::from_millis(arg_or(args, "--linger-ms", 5_000));
    let qcap: usize = arg_or(args, "--queue-cap", 256);
    let slow = Duration::from_millis(arg_or(args, "--slow-consumer-ms", 0));
    let addr_file = arg(args, "--addr-file");
    let connect_file = arg(args, "--connect-file");
    let connect_host = arg(args, "--connect-host");
    let storage = format!("/tmp/ffi-peer-{name}");
    let rss0 = rss_kb();

    let t0 = Instant::now();
    let node = DeliveryNode::start(cfg(port, &storage)).await.unwrap_or_else(|e| {
        emit!("{}", json!({"event":"START_ERR","err":e.to_string()}));
        std::process::exit(3);
    });
    let startup_ms = t0.elapsed().as_secs_f64() * 1e3;
    node.subscribe(TOPIC).await.expect("subscribe");
    let addrs = node.listen_addresses().await.expect("listen addrs");
    eprintln!("[{name}] listen addrs: {addrs:?}");
    if let Some(f) = &addr_file {
        std::fs::write(f, addrs.join("\n")).expect("write addr file");
    }

    // ---- FFI event callback -> (crate's tokio broadcast) -> bounded mpsc, never blocking
    let sh = Arc::new(Shared::default());
    let (tx, mut mrx) = mpsc::channel::<DeliveryEvent>(qcap);
    {
        let mut rx = node.events();
        let sh = sh.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if tx.try_send(ev).is_err() {
                            sh.queue_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        sh.bcast_lagged.fetch_add(n, Ordering::Relaxed);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
    // consumer: classify events, record received messages
    #[derive(Default)]
    struct Rx {
        seen: HashMap<(String, u32), f64>, // (from,seq) -> latency ms (first delivery)
        dup: u64,
        selfecho: u64,
        malformed: u64,
        last_data: Option<Instant>,
    }
    let rxstate = Arc::new(std::sync::Mutex::new(Rx::default()));
    {
        let sh = sh.clone();
        let rxstate = rxstate.clone();
        let me = name.clone();
        tokio::spawn(async move {
            while let Some(ev) = mrx.recv().await {
                if !slow.is_zero() {
                    tokio::time::sleep(slow).await;
                }
                match ev {
                    DeliveryEvent::MessageReceived { message, .. } => {
                        let t = now_ns();
                        let s = String::from_utf8_lossy(&message.payload).to_string();
                        let f: Vec<&str> = s.splitn(5, '|').collect();
                        if f.len() < 4 || (f[0] != "D" && f[0] != "H") {
                            rxstate.lock().unwrap().malformed += 1;
                            continue;
                        }
                        let from = f[1].to_string();
                        if from == me {
                            rxstate.lock().unwrap().selfecho += 1;
                            continue;
                        }
                        sh.peer_seen.store(true, Ordering::Relaxed);
                        if f[0] == "D" {
                            let seq: u32 = f[2].parse().unwrap_or(u32::MAX);
                            let ts: u128 = f[3].parse().unwrap_or(0);
                            let lat = (t.saturating_sub(ts)) as f64 / 1e6;
                            let mut g = rxstate.lock().unwrap();
                            g.last_data = Some(Instant::now());
                            if g.seen.contains_key(&(from.clone(), seq)) {
                                g.dup += 1;
                            } else {
                                g.seen.insert((from, seq), lat);
                            }
                        }
                    }
                    DeliveryEvent::MessageSent { .. } => {
                        sh.ev_sent.fetch_add(1, Ordering::Relaxed);
                    }
                    DeliveryEvent::MessagePropagated { .. } => {
                        sh.ev_propagated.fetch_add(1, Ordering::Relaxed);
                    }
                    DeliveryEvent::MessageError { error, .. } => {
                        let _ = &error;
                        sh.ev_error.fetch_add(1, Ordering::Relaxed);
                    }
                    DeliveryEvent::MessageQueued { .. } => {
                        sh.ev_queued.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        sh.ev_other.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    // ---- static dial of the other node (private network, no discovery)
    let mut connect_ms = f64::NAN;
    let mut connect_api_ok_but_no_peer = 0u32;
    if let Some(cf) = &connect_file {
        let deadline = Instant::now() + Duration::from_secs(60);
        let addrs_txt = loop {
            if let Ok(t) = std::fs::read_to_string(cf) {
                if !t.trim().is_empty() {
                    break t;
                }
            }
            if Instant::now() > deadline {
                emit!("{}", json!({"event":"NO_ADDR_FILE"}));
                std::process::exit(4);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        let a = addrs_txt
            .lines()
            .find(|l| l.contains("/tcp/") && l.contains("/p2p/") && !l.contains("/quic"))
            .expect("tcp addr");
        // dial exactly the address the other node reported (container IP on the private docker net)
        let dial = match &connect_host {
            Some(h) => {
                let parts: Vec<&str> = a.split('/').collect();
                let port_i = parts.iter().position(|p| *p == "tcp").unwrap() + 1;
                let id_i = parts.iter().position(|p| *p == "p2p").unwrap() + 1;
                format!("/dns4/{}/tcp/{}/p2p/{}", h, parts[port_i], parts[id_i])
            }
            None => a.to_string(),
        };
        eprintln!("[{name}] dialing {dial}");
        let t = Instant::now();
        let mut ok = false;
        for attempt in 0..10 {
            let r = node.connect(&dial, Duration::from_secs(15)).await;
            // connect() may return Ok even when the dial failed: verify with the peer table
            let peers = node.connected_peers_info().await.map(|m| m.len()).unwrap_or(0);
            match r {
                Ok(()) if peers > 0 => {
                    ok = true;
                    break;
                }
                Ok(()) => {
                    connect_api_ok_but_no_peer += 1;
                    eprintln!("[{name}] connect attempt {attempt}: API Ok but 0 connected peers");
                }
                Err(e) => eprintln!("[{name}] connect attempt {attempt} failed: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        connect_ms = t.elapsed().as_secs_f64() * 1e3;
        if !ok {
            emit!("{}", json!({"event":"CONNECT_FAILED","api_ok_but_no_peer":connect_api_ok_but_no_peer}));
            std::process::exit(5);
        }
    }

    // ---- hello barrier: publish hellos until the other side is heard
    let barrier_t = Instant::now();
    let mut hello_n = 0u32;
    while !sh.peer_seen.load(Ordering::Relaxed) {
        if barrier_t.elapsed() > Duration::from_secs(90) {
            emit!("{}", json!({"event":"BARRIER_TIMEOUT"}));
            break;
        }
        let p = format!("H|{name}|{hello_n}|{}|", now_ns());
        let _ = node.publish(TOPIC, p.as_bytes()).await; // errors expected until mesh forms
        hello_n += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let barrier_ms = barrier_t.elapsed().as_secs_f64() * 1e3;
    tokio::time::sleep(Duration::from_millis(2000)).await; // let the other side's barrier clear

    // ---- send N numbered messages
    let mut rss_peak = rss_kb();
    let mut sent_ok = 0u32;
    let mut sent_err: Vec<String> = vec![];
    let mut pub_ms: Vec<f64> = vec![];
    let send_t = Instant::now();
    let padding = "x".repeat(pad);
    for seq in 0..count {
        let p = format!("D|{name}|{seq}|{}|{padding}", now_ns());
        let t = Instant::now();
        match node.publish(TOPIC, p.as_bytes()).await {
            Ok(_) => sent_ok += 1,
            Err(e) => sent_err.push(format!("{seq}: {e}")),
        }
        pub_ms.push(t.elapsed().as_secs_f64() * 1e3);
        rss_peak = rss_peak.max(rss_kb());
        tokio::time::sleep(interval).await;
    }
    let send_s = send_t.elapsed().as_secs_f64();

    // ---- drain: wait until `count` unique from the peer, or idle for `drain`
    let drain_start = Instant::now();
    loop {
        let (n, last) = {
            let g = rxstate.lock().unwrap();
            (g.seen.len() as u32, g.last_data)
        };
        if n >= count {
            break;
        }
        let idle_since = last.unwrap_or(drain_start).max(drain_start);
        if idle_since.elapsed() > drain {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(linger).await; // keep serving so the peer can finish receiving
    rss_peak = rss_peak.max(rss_kb());
    let rss_end = rss_kb();

    let (recv_unique, dup, selfecho, malformed, mut lats, missing) = {
        let g = rxstate.lock().unwrap();
        let mut l: Vec<f64> = g.seen.values().cloned().collect();
        l.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let got: HashSet<u32> = g.seen.keys().map(|k| k.1).collect();
        let missing: Vec<u32> = (0..count).filter(|s| !got.contains(s)).collect();
        (g.seen.len(), g.dup, g.selfecho, g.malformed, l, missing)
    };
    lats.shrink_to_fit();
    pub_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let t = Instant::now();
    let sd = node.shutdown().await;
    let shutdown_ms = t.elapsed().as_secs_f64() * 1e3;
    drop(node);
    tokio::time::sleep(Duration::from_millis(1000)).await;

    emit!(
        "{}",
        json!({
            "event":"summary","name":name,"arch":std::env::consts::ARCH,
            "count":count,"interval_ms":interval.as_millis(),"payload_pad_bytes":pad,
            "sent_ok":sent_ok,"sent_err_n":sent_err.len(),"sent_err_first":sent_err.iter().take(3).collect::<Vec<_>>(),
            "send_s":send_s,
            "recv_unique":recv_unique,"recv_dup":dup,"recv_selfecho":selfecho,"recv_malformed":malformed,
            "missing_n":missing.len(),"missing_first":missing.iter().take(20).collect::<Vec<_>>(),
            "lat_ms":{"min":lats.first(),"p50":pct(&lats,0.5),"p95":pct(&lats,0.95),"p99":pct(&lats,0.99),"max":lats.last()},
            "publish_call_ms":{"p50":pct(&pub_ms,0.5),"p95":pct(&pub_ms,0.95),"max":pub_ms.last()},
            "events":{"queued":sh.ev_queued.load(Ordering::Relaxed),"sent":sh.ev_sent.load(Ordering::Relaxed),
                      "propagated":sh.ev_propagated.load(Ordering::Relaxed),"error":sh.ev_error.load(Ordering::Relaxed),
                      "other":sh.ev_other.load(Ordering::Relaxed)},
            "queue_cap":qcap,"queue_dropped":sh.queue_dropped.load(Ordering::Relaxed),
            "bcast_lagged":sh.bcast_lagged.load(Ordering::Relaxed),
            "startup_ms":startup_ms,"connect_ms":connect_ms,"connect_api_ok_but_no_peer":connect_api_ok_but_no_peer,"barrier_ms":barrier_ms,"hellos_sent":hello_n,
            "shutdown_ms":shutdown_ms,"shutdown_err":sd.err().map(|e| e.to_string()),
            "rss_kb":{"before_start":rss0,"peak":rss_peak,"end":rss_end},
            "threads":threads(),"fds":fds()
        })
    );
}
