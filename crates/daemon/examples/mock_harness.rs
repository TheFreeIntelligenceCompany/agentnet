//! A tiny mock "harness": consumes AgentNet events and records a *simulated*
//! turn for each one. No LLM, no Pi, no inference of any kind.
//!
//! The service emits events; the harness decides what to do with them. This
//! one just appends a JSON line per `trigger.matched` event (and optionally per
//! `message.received`):
//!
//! ```text
//! {"event_id":"...","trigger_id":"...","target_session":"...","message_id":"...","simulated_turn":3}
//! ```
//!
//! Two modes:
//!
//! * socket (default): subscribe to `<data dir>/agentnet.sock` from a persisted
//!   cursor, process, then acknowledge (`events.ack`). Reconnects with backoff.
//!   ```text
//!   cargo run --example mock_harness -- --data-dir ~/.agentnet --out turns.jsonl --state harness-state.json
//!   ```
//! * webhook: serve an HTTP endpoint that verifies the signature and timestamp
//!   (`X-AgentNet-Signature`, tolerance +-300 s), de-duplicates by event id and
//!   records the turn.
//!   ```text
//!   cargo run --example mock_harness -- --webhook 127.0.0.1:9000 --secret-file webhook.secret \
//!       --out turns.jsonl --state harness-state.json
//!   ```
//!
//! With `--fetch` (socket mode) the harness shows the whole receive flow for
//! `message.received` events (use with `--include-received`): event ->
//! `get_message(message_id)` -> handle -> `acknowledge_message`. The event
//! cursor is NOT an inbox cursor; `get_message` is how an event's `message_id`
//! is resolved. The turn line then also carries `"fetched"` (`sender` and
//! `body_bytes`, or an error code such as `NotFound` for a quarantined or
//! unknown message). The body is untrusted data: this mock only measures it
//! and never acts on it.
//!
//! Delivery is at-least-once, so the harness keeps the ids of events it has
//! already handled in `--state` and ignores repeats (the idempotency key is the
//! `event_id`). Other options: `--include-received`, `--max-events N` (exit
//! after N recorded turns), `--idle-exit-ms N` (socket mode: exit after the
//! stream was idle that long).
//!
//! Crash window: the turn line is appended before the state file is updated, so
//! a crash between the two can record one turn twice. A real harness should
//! make its side effect idempotent on `event_id` (for example by using the id as
//! a primary key); it is the receiver's job.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentnet_core::api::{AgentApi, EventRecord, EventType, GetMessageRequest};
use agentnet_daemon::webhook::{
    verify_signature, HEADER_SIGNATURE, HEADER_TIMESTAMP, SIGNATURE_TOLERANCE_S,
};
use agentnet_daemon::{EventStream, RemoteAgent};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
struct State_ {
    cursor: Option<String>,
    seen: BTreeSet<String>,
    turns: u64,
}

struct Opts {
    data_dir: PathBuf,
    out: PathBuf,
    state: PathBuf,
    include_received: bool,
    fetch: bool,
    max_events: Option<u64>,
    idle_exit: Option<Duration>,
    webhook: Option<String>,
    secret_file: Option<PathBuf>,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts {
        data_dir: PathBuf::from(std::env::var("AGENTNET_HOME").unwrap_or_else(|_| {
            format!("{}/.agentnet", std::env::var("HOME").unwrap_or_default())
        })),
        out: PathBuf::from("turns.jsonl"),
        state: PathBuf::from("harness-state.json"),
        include_received: false,
        fetch: false,
        max_events: None,
        idle_exit: None,
        webhook: None,
        secret_file: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = |n: &str| it.next().ok_or_else(|| format!("{n} needs a value"));
        match a.as_str() {
            "--data-dir" => o.data_dir = val("--data-dir")?.into(),
            "--out" => o.out = val("--out")?.into(),
            "--state" => o.state = val("--state")?.into(),
            "--include-received" => o.include_received = true,
            "--fetch" => o.fetch = true,
            "--max-events" => {
                o.max_events = Some(val("--max-events")?.parse().map_err(|_| "bad number")?)
            }
            "--idle-exit-ms" => {
                o.idle_exit = Some(Duration::from_millis(
                    val("--idle-exit-ms")?.parse().map_err(|_| "bad number")?,
                ))
            }
            "--webhook" => o.webhook = Some(val("--webhook")?),
            "--secret-file" => o.secret_file = Some(val("--secret-file")?.into()),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(o)
}

fn load_state(p: &PathBuf) -> State_ {
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_state(p: &PathBuf, s: &State_) -> std::io::Result<()> {
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(s)?)?;
    std::fs::rename(tmp, p)
}

struct Harness {
    out: PathBuf,
    state_path: PathBuf,
    include_received: bool,
    state: Mutex<State_>,
}

impl Harness {
    fn wants(&self, ev: &EventRecord) -> bool {
        match ev.event_type {
            EventType::TriggerMatched => true,
            EventType::MessageReceived => self.include_received,
        }
    }

    /// Handle one event idempotently. Returns true when a turn was recorded.
    fn handle(
        &self,
        ev: &EventRecord,
        advance_cursor: bool,
        fetched: Option<serde_json::Value>,
    ) -> std::io::Result<bool> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut recorded = false;
        if self.wants(ev) && !st.seen.contains(&ev.event_id) {
            st.turns += 1;
            let mut line = serde_json::json!({
                "event_id": ev.event_id,
                "trigger_id": ev.trigger_id,
                "target_session": ev.target_session,
                "message_id": ev.message_id,
                "simulated_turn": st.turns,
            });
            if let Some(f) = fetched {
                line["fetched"] = f;
            }
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.out)?;
            writeln!(f, "{line}")?;
            f.sync_all()?;
            st.seen.insert(ev.event_id.clone());
            recorded = true;
        }
        if advance_cursor {
            st.cursor = Some(ev.cursor.clone());
        }
        save_state(&self.state_path, &st)?;
        Ok(recorded)
    }

    fn turns(&self) -> u64 {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).turns
    }
}

async fn run_socket(o: &Opts, h: Arc<Harness>) -> Result<(), String> {
    let mut backoff = Duration::from_millis(200);
    loop {
        let cursor = h
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cursor
            .clone();
        let agent = RemoteAgent::new(&o.data_dir);
        match EventStream::connect(&o.data_dir, cursor).await {
            Ok(mut s) => {
                backoff = Duration::from_millis(200);
                loop {
                    let next = match o.idle_exit {
                        Some(d) => match tokio::time::timeout(d, s.next()).await {
                            Ok(r) => r,
                            Err(_) => return Ok(()),
                        },
                        None => s.next().await,
                    };
                    match next {
                        Ok(Some(ev)) => {
                            // receive event -> get_message -> handle -> ack.
                            let fetched = if o.fetch && ev.event_type == EventType::MessageReceived
                            {
                                Some(
                                    match agent
                                        .get_message(GetMessageRequest {
                                            message_id: ev.message_id.clone(),
                                            sender: None,
                                        })
                                        .await
                                    {
                                        Ok(m) => serde_json::json!({
                                            "sender": m.sender,
                                            "body_bytes": m.body.len(),
                                        }),
                                        Err(e) => serde_json::json!(format!("{:?}", e.code)),
                                    },
                                )
                            } else {
                                None
                            };
                            h.handle(&ev, true, fetched.clone())
                                .map_err(|e| e.to_string())?;
                            if fetched.as_ref().is_some_and(|f| f.is_object()) {
                                // Local processing state only; idempotent.
                                if let Err(e) =
                                    agent.acknowledge_message(ev.message_id.clone()).await
                                {
                                    eprintln!("acknowledge failed: {e}");
                                }
                            }
                            // Ack only after the turn and the cursor are durable.
                            if let Err(e) = s.ack(&ev.cursor).await {
                                eprintln!("ack failed: {e}");
                                break;
                            }
                            if o.max_events.is_some_and(|m| h.turns() >= m) {
                                return Ok(());
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("stream error: {e}");
                            break;
                        }
                    }
                }
            }
            Err(e) => eprintln!("cannot subscribe ({e}); retrying"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

#[derive(Clone)]
struct WebhookState {
    h: Arc<Harness>,
    secret: Arc<Vec<u8>>,
}

async fn receive(State(s): State<WebhookState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let hv = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0);
    if verify_signature(
        &s.secret,
        hv(HEADER_TIMESTAMP),
        &body,
        hv(HEADER_SIGNATURE),
        now,
        SIGNATURE_TOLERANCE_S,
    )
    .is_err()
    {
        return StatusCode::UNAUTHORIZED;
    }
    let Ok(ev) = serde_json::from_slice::<EventRecord>(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    // Replay / duplicate protection: `handle` ignores event ids it has seen and
    // still answers 200 so the sender stops retrying.
    match s.h.handle(&ev, false, None) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn run_webhook(o: &Opts, h: Arc<Harness>, bind: &str) -> Result<(), String> {
    let path = o
        .secret_file
        .as_ref()
        .ok_or("--secret-file is required with --webhook")?;
    let mut secret = std::fs::read(path).map_err(|e| format!("secret file: {e}"))?;
    while matches!(secret.last(), Some(b'\n' | b'\r')) {
        secret.pop();
    }
    let app = Router::new()
        .route("/", post(receive))
        .route("/hook", post(receive))
        .with_state(WebhookState {
            h: h.clone(),
            secret: Arc::new(secret),
        });
    let l = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!(
        "mock harness: webhook receiver on http://{}",
        l.local_addr().map_err(|e| e.to_string())?
    );
    let max = o.max_events;
    let hh = h.clone();
    let server = axum::serve(l, app);
    tokio::select! {
        r = server => r.map_err(|e| e.to_string()),
        _ = async move {
            loop {
                if max.is_some_and(|m| hh.turns() >= m) { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        } => Ok(()),
    }
}

#[tokio::main]
async fn main() {
    let o = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let h = Arc::new(Harness {
        out: o.out.clone(),
        state_path: o.state.clone(),
        include_received: o.include_received,
        state: Mutex::new(load_state(&o.state)),
    });
    let r = match o.webhook.clone() {
        Some(bind) => run_webhook(&o, h, &bind).await,
        None => run_socket(&o, h).await,
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
