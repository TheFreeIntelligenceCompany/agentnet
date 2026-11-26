//! Driver for `scripts/acceptance.sh`. Everything here talks to already
//! running `agentnet serve` daemons: through `agentnet mcp` stdio child
//! processes (rmcp client, protocol 2026-07-28 discovery) or through the
//! daemon crate's socket client (`RemoteAgent`, `EventStream`).
//!
//! Sub-commands print one JSON document on stdout; progress goes to stderr.
//!
//! ```text
//! agentnet-acceptance mcp-call     --bin B --data-dir D --tool T [--args JSON]
//! agentnet-acceptance step2        --bin B --a D --b D --b-addr X --out F
//! agentnet-acceptance dump         --data-dir D [--idle-ms N]
//! agentnet-acceptance bench        --a D --b D --a-addr X --b-addr X --n N --out F
//! agentnet-acceptance config-check --config FILE --server NAME --expect-address X
//! ```
//!
//! LOCALHOST / docker-bridge acceptance tooling. Not a cross-machine test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use agentnet_core::api::{
    AgentApi, DeliveryState, EventType, PageRequest, ReadInboxRequest, SendMessageRequest,
};
use agentnet_daemon::{EventStream, RemoteAgent};
use anyhow::{anyhow, bail, Context, Result};
use rmcp::{
    model::*,
    service::RunningService,
    transport::{ConfigureCommandExt, TokioChildProcess},
    ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient,
};
use serde_json::{json, Value};

#[derive(Clone)]
struct Collector;
impl ClientHandler for Collector {
    fn get_info(&self) -> ClientConfig {
        let mut c = ClientConfig::default();
        c.client_info = Implementation::new("agentnet-acceptance", "0.1.0");
        c
    }
}
type Client = RunningService<RoleClient, Collector>;

struct Args(Vec<String>);
impl Args {
    fn get(&self, name: &str) -> Option<String> {
        self.0
            .iter()
            .position(|a| a == name)
            .and_then(|i| self.0.get(i + 1).cloned())
    }
    fn req(&self, name: &str) -> Result<String> {
        self.get(name).ok_or_else(|| anyhow!("missing {name}"))
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

async fn mcp_client(bin: &Path, dir: &Path) -> Result<Client> {
    let (bin, dir) = (bin.to_owned(), dir.to_owned());
    let cmd = tokio::process::Command::new(&bin).configure(move |c| {
        c.arg("--data-dir").arg(&dir).arg("mcp");
        c.env_remove("RUST_LOG");
    });
    spawn_client(cmd).await
}

async fn spawn_client(cmd: tokio::process::Command) -> Result<Client> {
    let (transport, _stderr) = TokioChildProcess::builder(cmd)
        .stderr(Stdio::null())
        .spawn()
        .context("spawn mcp child")?;
    let client = Collector
        .serve_with_lifecycle(
            transport,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .context("MCP handshake")?;
    Ok(client)
}

fn protocol_of(c: &Client) -> Value {
    match c.peer_info() {
        Some(info) => {
            let v = serde_json::to_value(&*info).unwrap_or(Value::Null);
            json!({
                "negotiated_protocol_version": v.get("protocolVersion").or_else(|| v.get("protocol_version")).cloned().unwrap_or(Value::Null),
                "server_info": v.get("serverInfo").or_else(|| v.get("server_info")).cloned().unwrap_or(Value::Null),
            })
        }
        None => json!({"negotiated_protocol_version": null}),
    }
}

/// Returns (is_error, json payload).
async fn call(c: &Client, name: &str, args: Value) -> Result<(bool, Value)> {
    let mut p = CallToolRequestParams::new(name.to_string());
    if let Some(o) = args.as_object() {
        p = p.with_arguments(o.clone());
    }
    let r = c
        .peer()
        .call_tool(p)
        .await
        .context("tool call (protocol error)")?;
    let is_err = r.is_error == Some(true);
    let payload = if is_err {
        let block = serde_json::to_value(r.content.first()).unwrap_or(Value::Null);
        match block.get("text").and_then(|t| t.as_str()) {
            Some(t) => serde_json::from_str(t).unwrap_or_else(|_| json!({"text": t})),
            None => block,
        }
    } else {
        r.structured_content.clone().unwrap_or(Value::Null)
    };
    Ok((is_err, payload))
}

async fn call_ok(c: &Client, name: &str, args: Value) -> Result<Value> {
    let (e, v) = call(c, name, args).await?;
    if e {
        bail!("tool {name} returned an error: {v}");
    }
    Ok(v)
}

fn filter(uris: &[&str]) -> SubscriptionFilter {
    SubscriptionFilter::builder()
        .resource_subscriptions(uris.iter().map(|u| u.to_string()))
        .build()
}

// ---------------------------------------------------------------- mcp-call

async fn cmd_mcp_call(a: &Args) -> Result<Value> {
    let bin = PathBuf::from(a.req("--bin")?);
    let dir = PathBuf::from(a.req("--data-dir")?);
    let tool = a.req("--tool")?;
    let args: Value = serde_json::from_str(&a.get("--args").unwrap_or_else(|| "{}".into()))?;
    let t0 = Instant::now();
    let c = mcp_client(&bin, &dir).await?;
    let proto = protocol_of(&c);
    let (is_error, result) = call(&c, &tool, args).await?;
    let elapsed = t0.elapsed().as_millis() as u64;
    let _ = c.cancel().await;
    Ok(
        json!({"tool": tool, "protocol": proto, "is_error": is_error, "result": result, "elapsed_ms": elapsed}),
    )
}

// ------------------------------------------------------------------- step2

async fn cmd_step2(a: &Args) -> Result<Value> {
    let bin = PathBuf::from(a.req("--bin")?);
    let (da, db) = (PathBuf::from(a.req("--a")?), PathBuf::from(a.req("--b")?));
    let b_addr = a.req("--b-addr")?;
    let timeout_s: u64 = a
        .get("--timeout")
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(180);
    let ca = mcp_client(&bin, &da).await?;
    let cb = mcp_client(&bin, &db).await?;
    let id_a = call_ok(&ca, "get_identity", json!({})).await?;
    let id_b = call_ok(&cb, "get_identity", json!({})).await?;
    let a_addr = id_a["agent_id"].as_str().unwrap_or_default().to_owned();
    if id_b["agent_id"] != b_addr.as_str() {
        bail!("B identity mismatch");
    }
    let mut sub = cb
        .listen(filter(&["agentnet://inbox"]))
        .await
        .context("subscriptions/listen on B")?;
    eprintln!("B listening on agentnet://inbox");
    let marker = format!("ACCEPTANCE-STEP2-PLAINTEXT-MARKER-{}", now_ms());
    let t0 = Instant::now();
    let t0_wall = now_ms();
    let sent = call_ok(
        &ca,
        "send_message",
        json!({"recipient": b_addr, "body": marker, "conversation_id": "acc-step2"}),
    )
    .await?;
    let t_send = t0.elapsed().as_millis() as u64;
    let mid = sent["message_id"].as_str().unwrap_or_default().to_owned();
    let mut timeline =
        vec![json!({"state": sent["status"], "t_ms": t_send, "source": "send_message response"})];

    // Concurrently: wait for the subscription notification, poll status.
    let notify = async {
        let n = tokio::time::timeout(Duration::from_secs(timeout_s), sub.next())
            .await
            .map_err(|_| anyhow!("no resource notification within {timeout_s}s"))??;
        Ok::<_, anyhow::Error>((t0.elapsed().as_millis() as u64, format!("{n:?}")))
    };
    let status_poll = async {
        let mut last = String::new();
        let end = Instant::now() + Duration::from_secs(timeout_s);
        let mut tl = vec![];
        loop {
            let st = call_ok(&ca, "get_message_status", json!({"message_id": mid})).await?;
            let s = st["state"].as_str().unwrap_or("").to_owned();
            if s != last {
                tl.push(json!({"state": s, "t_ms": t0.elapsed().as_millis() as u64, "source": "get_message_status", "attempts": st["attempts"]}));
                last = s.clone();
            }
            if s == "delivered" {
                return Ok::<_, anyhow::Error>((tl, st));
            }
            if Instant::now() > end {
                bail!("never delivered; last status {st}");
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    };
    let (n, st) = tokio::join!(notify, status_poll);
    let (t_notify, notification) = n?;
    let (tl, final_status) = st?;
    timeline.extend(tl);
    // B's read_inbox shows the message.
    let inbox = call_ok(&cb, "read_inbox", json!({"conversation_id": "acc-step2"})).await?;
    let t_read = t0.elapsed().as_millis() as u64;
    let rec = inbox["records"]
        .as_array()
        .and_then(|r| r.iter().find(|m| m["message_id"] == mid.as_str()))
        .cloned()
        .ok_or_else(|| anyhow!("message not in B's read_inbox: {inbox}"))?;
    if rec["sender"] != a_addr.as_str() {
        bail!("sender not authenticated as A: {rec}");
    }
    if rec["body"] != marker.as_str() {
        bail!("body mismatch");
    }
    let delivered_ms = timeline
        .iter()
        .find(|e| e["state"] == "delivered")
        .and_then(|e| e["t_ms"].as_u64());
    let _ = sub.cancel().await;
    let proto_a = protocol_of(&ca);
    let proto_b = protocol_of(&cb);
    let _ = ca.cancel().await;
    let _ = cb.cancel().await;
    Ok(json!({
        "ok": true,
        "protocol_client_A": proto_a,
        "protocol_client_B": proto_b,
        "a_addr": a_addr,
        "b_addr": b_addr,
        "message_id": mid,
        "body_marker": marker,
        "send_wall_clock_ms": t0_wall,
        "latency_ms": {
            "send_message_returned": t_send,
            "B_resource_notification": t_notify,
            "B_read_inbox_returned": t_read,
            "A_status_delivered": delivered_ms,
        },
        "notification": notification,
        "A_status_timeline": timeline,
        "A_final_status": final_status,
        "B_inbox_record": rec,
    }))
}

// -------------------------------------------------------------------- dump

fn count_by<'a>(it: impl Iterator<Item = &'a str>) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for k in it {
        *m.entry(k.to_owned()).or_insert(0) += 1;
    }
    m
}

async fn cmd_dump(a: &Args) -> Result<Value> {
    let dir = PathBuf::from(a.req("--data-dir")?);
    let idle = Duration::from_millis(
        a.get("--idle-ms")
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(1500),
    );
    let agent = RemoteAgent::new(&dir);
    // inbox (incl. quarantined)
    let mut inbox = vec![];
    let mut cursor = None;
    loop {
        let p = agent
            .read_inbox(ReadInboxRequest {
                cursor: cursor.clone(),
                limit: Some(200),
                include_quarantined: true,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("read_inbox: {e}"))?;
        let more = p.has_more;
        inbox.extend(p.records);
        cursor = p.next_cursor;
        if !more {
            break;
        }
    }
    let mut outbox = vec![];
    let mut cursor = None;
    loop {
        let p = agent
            .read_outbox(PageRequest {
                cursor: cursor.clone(),
                limit: Some(200),
            })
            .await
            .map_err(|e| anyhow!("read_outbox: {e}"))?;
        let more = p.has_more;
        outbox.extend(p.records);
        cursor = p.next_cursor;
        if !more {
            break;
        }
    }
    // events through EventStream: replay everything retained, stop when idle.
    let mut events = vec![];
    let mut s = EventStream::connect(&dir, None)
        .await
        .map_err(|e| anyhow!("EventStream: {e}"))?;
    loop {
        match tokio::time::timeout(idle, s.next()).await {
            Err(_) => break,
            Ok(Ok(Some(ev))) => events.push(ev),
            Ok(Ok(None)) => break,
            Ok(Err(e)) => bail!("event stream: {e}"),
        }
    }
    let mut ids: Vec<&str> = events.iter().map(|e| e.event_id.as_str()).collect();
    ids.sort();
    let total_ev = ids.len();
    ids.dedup();
    let mut mids: Vec<&str> = inbox.iter().map(|r| r.message_id.as_str()).collect();
    mids.sort();
    let rows = mids.len();
    mids.dedup();
    let by_type = count_by(events.iter().map(|e| match e.event_type {
        EventType::MessageReceived => "message.received",
        EventType::TriggerMatched => "trigger.matched",
    }));
    // per-message count of message.received events (must be <= 1)
    let mut recv_per_msg: BTreeMap<&str, u64> = BTreeMap::new();
    for e in &events {
        if e.event_type == EventType::MessageReceived {
            *recv_per_msg.entry(e.message_id.as_str()).or_insert(0) += 1;
        }
    }
    let dup_received_events = recv_per_msg.values().filter(|&&n| n > 1).count();
    let out_states = count_by(outbox.iter().map(|r| match r.status.state {
        DeliveryState::Queued => "queued",
        DeliveryState::Sent => "sent",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Failed => "failed",
        DeliveryState::Expired => "expired",
    }));
    Ok(json!({
        "inbox": {
            "rows": rows,
            "unique_message_ids": mids.len(),
            "quarantined": inbox.iter().filter(|r| r.quarantined).count(),
            "records": inbox.iter().map(|r| json!({
                "message_id": r.message_id, "sender": r.sender, "body": r.body,
                "conversation_id": r.conversation_id, "quarantined": r.quarantined,
                "created_at": r.created_at, "received_at": r.received_at, "cursor": r.cursor,
                "message_type": r.message_type,
            })).collect::<Vec<_>>(),
        },
        "outbox": {
            "rows": outbox.len(),
            "by_state": out_states,
            "records": outbox.iter().map(|r| json!({
                "message_id": r.status.message_id, "state": r.status.state, "attempts": r.status.attempts,
                "body": r.body, "conversation_id": r.status.conversation_id, "recipient": r.status.recipient,
                "created_at": r.status.created_at, "sent_at": r.status.sent_at,
                "delivered_at": r.status.delivered_at, "expires_at": r.status.expires_at,
                "last_error": r.status.last_error,
            })).collect::<Vec<_>>(),
        },
        "events": {
            "total": total_ev,
            "unique_event_ids": ids.len(),
            "by_type": by_type,
            "duplicate_message_received_events": dup_received_events,
            "records": events,
        },
    }))
}

// ------------------------------------------------------------------- bench

fn pct(sorted: &[i64], p: f64) -> Option<i64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil().max(1.0) as usize;
    Some(sorted[rank.min(sorted.len()) - 1])
}

async fn bench_dir(
    from: PathBuf,
    to_addr: String,
    tag: String,
    n: usize,
    timeout_s: u64,
    pace_ms: u64,
) -> Result<Value> {
    let agent = RemoteAgent::new(&from);
    let t0 = Instant::now();
    let mut ids = vec![];
    let mut send_fail = 0u32;
    for i in 0..n {
        let r = agent
            .send_message(SendMessageRequest {
                recipient: to_addr.clone(),
                body: format!("{tag}-{i:04}"),
                conversation_id: Some(tag.clone()),
                ..Default::default()
            })
            .await;
        match r {
            Ok(r) => ids.push(r.message_id),
            Err(e) => {
                eprintln!("send {i} failed: {e}");
                send_fail += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(pace_ms)).await;
    }
    let send_phase_ms = t0.elapsed().as_millis() as u64;
    let end = Instant::now() + Duration::from_secs(timeout_s);
    let mut lat: Vec<i64> = vec![];
    let mut pending: Vec<String> = ids.clone();
    let mut other: BTreeMap<String, u64> = BTreeMap::new();
    while !pending.is_empty() && Instant::now() < end {
        let mut still = vec![];
        for id in pending {
            match agent.get_message_status(id.clone()).await {
                Ok(st) => match st.state {
                    DeliveryState::Delivered => {
                        lat.push(st.delivered_at.unwrap_or(0) - st.created_at)
                    }
                    DeliveryState::Failed | DeliveryState::Expired => {
                        *other
                            .entry(format!("{:?}", st.state).to_lowercase())
                            .or_insert(0) += 1
                    }
                    _ => still.push(id),
                },
                Err(_) => still.push(id),
            }
        }
        pending = still;
        if !pending.is_empty() {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    let total_ms = t0.elapsed().as_millis() as u64;
    lat.sort();
    Ok(json!({
        "tag": tag, "sent": ids.len(), "send_failures": send_fail,
        "delivered": lat.len(), "not_delivered_at_timeout": pending.len(),
        "terminal_other": other,
        "send_phase_ms": send_phase_ms, "total_ms": total_ms,
        "latency_ms_send_to_delivered": {
            "definition": "delivered_at - created_at from the sender's own outbox row (same host clock)",
            "min": lat.first(), "p50": pct(&lat, 50.0), "p95": pct(&lat, 95.0), "p99": pct(&lat, 99.0), "max": lat.last(),
            "samples": lat.len(),
        },
        "raw_latencies_ms": lat,
    }))
}

async fn cmd_bench(a: &Args) -> Result<Value> {
    let (da, db) = (PathBuf::from(a.req("--a")?), PathBuf::from(a.req("--b")?));
    let (aa, ba) = (a.req("--a-addr")?, a.req("--b-addr")?);
    let n: usize = a.get("--n").map(|s| s.parse()).transpose()?.unwrap_or(100);
    let timeout: u64 = a
        .get("--timeout")
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(300);
    let tag = a.get("--tag").unwrap_or_else(|| "bench".into());
    let pace: u64 = a
        .get("--pace-ms")
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(25);
    let (r1, r2) = tokio::join!(
        bench_dir(da, ba, format!("{tag}-a2b"), n, timeout, pace),
        bench_dir(db, aa, format!("{tag}-b2a"), n, timeout, pace)
    );
    Ok(
        json!({"a_to_b": r1?, "b_to_a": r2?, "n_per_direction": n, "direction_mode": format!("both directions concurrently, {pace} ms pacing")}),
    )
}

// ------------------------------------------------------------ config-check

async fn cmd_config_check(a: &Args) -> Result<Value> {
    let cfg: Value = serde_json::from_str(&std::fs::read_to_string(a.req("--config")?)?)?;
    let name = a.req("--server")?;
    let expect = a.req("--expect-address")?;
    let s = cfg["mcpServers"][&name].clone();
    let command = s["command"]
        .as_str()
        .ok_or_else(|| anyhow!("no command"))?
        .to_owned();
    let args: Vec<String> = s["args"]
        .as_array()
        .ok_or_else(|| anyhow!("no args"))?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_owned())
        .collect();
    // Exactly the configured command line, nothing added.
    let cmd = tokio::process::Command::new(&command).configure(move |c| {
        c.args(&args);
    });
    let c = spawn_client(cmd).await?;
    let proto = protocol_of(&c);
    let tools = c
        .peer()
        .list_tools(Default::default())
        .await
        .context("tools/list")?;
    let names: Vec<String> = tools.tools.iter().map(|t| t.name.to_string()).collect();
    let id = call_ok(&c, "get_identity", json!({})).await?;
    let _ = c.cancel().await;
    let ok = id["agent_id"] == expect.as_str();
    Ok(
        json!({"ok": ok, "command": command, "args": s["args"], "protocol": proto, "tools": names, "get_identity": id}),
    )
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().cloned() else {
        eprintln!("usage: agentnet-acceptance <mcp-call|step2|dump|bench|config-check> ...");
        std::process::exit(2);
    };
    let a = Args(argv[1..].to_vec());
    let r = match cmd.as_str() {
        "mcp-call" => cmd_mcp_call(&a).await,
        "step2" => cmd_step2(&a).await,
        "dump" => cmd_dump(&a).await,
        "bench" => cmd_bench(&a).await,
        "config-check" => cmd_config_check(&a).await,
        other => Err(anyhow!("unknown command {other}")),
    };
    match r {
        Ok(v) => {
            let ok = v.get("ok").map(|o| o == &Value::Bool(true)).unwrap_or(true);
            let text = serde_json::to_string_pretty(&v).unwrap_or_default();
            if let Some(out) = a.get("--out") {
                let _ = std::fs::write(out, &text);
            }
            println!("{text}");
            std::process::exit(if ok { 0 } else { 1 });
        }
        Err(e) => {
            let v = json!({"ok": false, "error": format!("{e:#}")});
            if let Some(out) = a.get("--out") {
                let _ = std::fs::write(out, serde_json::to_string_pretty(&v).unwrap_or_default());
            }
            println!("{v}");
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}
