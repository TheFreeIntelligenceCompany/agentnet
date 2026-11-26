//! The control and event socket server.

use std::sync::Arc;
use std::time::Duration;

use agentnet_core::api::{
    AddContactRequest, AdvertiseRequest, AgentApi, ApiError, ChangeHint, CreateTriggerRequest,
    DiscoverRequest, ErrorCode, GetMessageRequest, PageRequest, ReadInboxRequest,
    SendMessageRequest, Trust,
};
use agentnet_core::Node;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::proto::{
    all_hints, change_line, err_line, event_line, ok_line, read_line, HelloFrame, Line, Request,
    MAX_HELLO_LINE, MAX_REQUEST_LINE, MAX_RESPONSE_LINE, PROTOCOL_VERSION,
};

/// Time a new connection has to send its hello line.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum simultaneous connections.
pub const MAX_CONNECTIONS: usize = 64;
/// Requests handled concurrently per connection.
const MAX_INFLIGHT_PER_CONN: usize = 32;
/// A write that makes no progress for this long closes the connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Event stream fallback poll period (hints are only an accelerator).
const EVENT_POLL: Duration = Duration::from_secs(1);
const EVENT_PAGE: u32 = 100;

/// Produces the JSON answered by `daemon.status`.
pub type StatusFn = Arc<dyn Fn() -> Value + Send + Sync>;

/// Everything a connection handler needs.
#[derive(Clone)]
pub struct ServerCtx {
    /// The engine.
    pub node: Arc<Node>,
    /// Expected token (hex text of `control.token`).
    pub token: Arc<Vec<u8>>,
    /// Cancelled to stop accepting and end all connections.
    pub stop: CancellationToken,
    /// Cancelled by the `shutdown` method (observed by the daemon owner).
    pub shutdown_request: CancellationToken,
    /// `daemon.status` provider.
    pub status: StatusFn,
    /// Hello timeout (tests shorten it).
    pub hello_timeout: Duration,
}

/// Accept connections until `ctx.stop` is cancelled, then wait (bounded) for
/// the connection tasks to end.
pub async fn serve(listener: UnixListener, ctx: ServerCtx) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut conns: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            _ = ctx.stop.cancelled() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((s, _)) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "control socket accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                match permits.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let ctx = ctx.clone();
                        conns.spawn(async move {
                            handle_conn(stream, ctx).await;
                            drop(permit);
                        });
                    }
                    Err(_) => {
                        conns.spawn(async move { refuse(stream).await });
                    }
                }
            }
        }
    }
    drop(listener);
    let drain = async { while conns.join_next().await.is_some() {} };
    if timeout(Duration::from_secs(3), drain).await.is_err() {
        conns.abort_all();
    }
}

async fn refuse(mut stream: UnixStream) {
    let line = err_line(None, &ApiError::unavailable("too many connections"));
    let _ = timeout(Duration::from_secs(1), async {
        stream.write_all(line.as_bytes()).await?;
        stream.write_all(b"\n").await
    })
    .await;
}

async fn handle_conn(stream: UnixStream, ctx: ServerCtx) {
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);

    // ---- hello
    let first = timeout(ctx.hello_timeout, read_line(&mut rd, MAX_HELLO_LINE)).await;
    let denied = |m: &str| ApiError::policy(m.to_owned());
    let bytes = match first {
        Ok(Ok(Line::Line(b))) => b,
        Ok(Ok(Line::TooLong)) => {
            tracing::debug!("control: oversize hello");
            let line = err_line(None, &denied("hello line too long"));
            let _ = wr.write_all(format!("{line}\n").as_bytes()).await;
            return;
        }
        Ok(_) => return,
        Err(_) => {
            tracing::debug!("control: hello timeout");
            let line = err_line(None, &denied("hello timeout"));
            let _ = wr.write_all(format!("{line}\n").as_bytes()).await;
            return;
        }
    };
    let authed = match serde_json::from_slice::<HelloFrame>(&bytes) {
        Ok(h) => {
            let presented = h.hello.token.as_bytes();
            let expected: &[u8] = ctx.token.as_slice();
            presented.len() == expected.len() && bool::from(presented.ct_eq(expected))
        }
        Err(_) => false,
    };
    if !authed {
        tracing::warn!("control: connection rejected (bad or missing hello token)");
        let line = err_line(None, &denied("authentication failed"));
        let _ = wr.write_all(format!("{line}\n").as_bytes()).await;
        return;
    }
    let hello_ok = json!({"hello": {"ok": true, "protocol": PROTOCOL_VERSION, "agent_id": ctx.node.address()}});
    if wr
        .write_all(format!("{hello_ok}\n").as_bytes())
        .await
        .is_err()
    {
        return;
    }

    // ---- writer task: the single owner of the write half
    let conn = ctx.stop.child_token();
    let (out_tx, mut out_rx) = mpsc::channel::<String>(256);
    let writer_conn = conn.clone();
    let writer = tokio::spawn(async move {
        while let Some(mut line) = out_rx.recv().await {
            line.push('\n');
            match timeout(WRITE_TIMEOUT, wr.write_all(line.as_bytes())).await {
                Ok(Ok(())) => {}
                _ => break,
            }
        }
        writer_conn.cancel();
    });

    // ---- request loop
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_PER_CONN));
    let mut events_started = false;
    let mut changes_started = false;
    loop {
        let line = tokio::select! {
            _ = conn.cancelled() => break,
            l = read_line(&mut rd, MAX_REQUEST_LINE) => l,
        };
        let bytes = match line {
            Ok(Line::Line(b)) => b,
            Ok(Line::Eof) | Err(_) => break,
            Ok(Line::TooLong) => {
                let _ = out_tx
                    .send(err_line(
                        None,
                        &ApiError::new(ErrorCode::TooLarge, "request line too long"),
                    ))
                    .await;
                break;
            }
        };
        let req: Request = match serde_json::from_slice(&bytes) {
            Ok(r) => r,
            Err(_) => {
                let _ = out_tx
                    .send(err_line(None, &ApiError::invalid("malformed request")))
                    .await;
                break;
            }
        };
        match req.method.as_str() {
            "events.subscribe" => {
                let resp = if events_started {
                    err_line(
                        Some(req.id),
                        &ApiError::new(
                            ErrorCode::Conflict,
                            "already subscribed on this connection",
                        ),
                    )
                } else {
                    match start_events(&ctx.node, req.params, out_tx.clone(), conn.clone()).await {
                        Ok(()) => {
                            events_started = true;
                            ok_line(req.id, json!({"subscribed": true}))
                        }
                        Err(e) => err_line(Some(req.id), &e),
                    }
                };
                if out_tx.send(resp).await.is_err() {
                    break;
                }
            }
            "changes.subscribe" => {
                let resp = if changes_started {
                    err_line(
                        Some(req.id),
                        &ApiError::new(
                            ErrorCode::Conflict,
                            "already subscribed on this connection",
                        ),
                    )
                } else {
                    changes_started = true;
                    start_changes(ctx.node.clone(), out_tx.clone(), conn.clone());
                    ok_line(req.id, json!({"subscribed": true}))
                };
                if out_tx.send(resp).await.is_err() {
                    break;
                }
            }
            _ => {
                let Ok(permit) = inflight.clone().acquire_owned().await else {
                    break;
                };
                let ctx = ctx.clone();
                let out = out_tx.clone();
                tokio::spawn(async move {
                    let line = match dispatch(&ctx, &req.method, req.params).await {
                        Ok(v) => ok_line(req.id, v),
                        Err(e) => err_line(Some(req.id), &e),
                    };
                    // An over-long line would make every client drop the whole
                    // multiplexed connection: answer this request with an error.
                    let line = if line.len() > MAX_RESPONSE_LINE {
                        err_line(
                            Some(req.id),
                            &ApiError::new(
                                ErrorCode::TooLarge,
                                "the response is too large; use a smaller page (limit/cursor)",
                            ),
                        )
                    } else {
                        line
                    };
                    let _ = out.send(line).await;
                    drop(permit);
                });
            }
        }
    }
    conn.cancel();
    drop(out_tx);
    // Let queued responses flush briefly, then make sure the writer ends.
    if timeout(Duration::from_secs(1), writer).await.is_err() {
        tracing::debug!("control: writer did not finish in time");
    }
}

fn params<T: DeserializeOwned>(v: Value) -> Result<T, ApiError> {
    let v = if v.is_null() { json!({}) } else { v };
    serde_json::from_value(v).map_err(|e| ApiError::invalid(format!("invalid params: {e}")))
}

fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ApiError> {
    serde_json::to_value(v).map_err(|_| ApiError::internal("could not encode result"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentParams {
    document: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TopicParams {
    topic: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageIdParams {
    message_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TriggerIdParams {
    trigger_id: String,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct StatusParams {
    verbose: bool,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct ListTriggersParams {
    include_inactive: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversationParams {
    conversation_id: String,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckParams {
    cursor: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustParams {
    address: String,
    trust: Trust,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressParams {
    address: String,
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct SubscribeParams {
    since_cursor: Option<String>,
}

async fn dispatch(ctx: &ServerCtx, method: &str, p: Value) -> Result<Value, ApiError> {
    let n = &ctx.node;
    match method {
        "get_identity" => to_value(n.get_identity().await?),
        "send_message" => to_value(n.send_message(params::<SendMessageRequest>(p)?).await?),
        "read_inbox" => to_value(n.read_inbox(params::<ReadInboxRequest>(p)?).await?),
        "get_message" => to_value(n.get_message(params::<GetMessageRequest>(p)?).await?),
        "acknowledge_message" => {
            let a: MessageIdParams = params(p)?;
            to_value(n.acknowledge_message(a.message_id).await?)
        }
        "get_message_status" => {
            let a: MessageIdParams = params(p)?;
            to_value(n.get_message_status(a.message_id).await?)
        }
        "add_contact" => to_value(n.add_contact(params::<AddContactRequest>(p)?).await?),
        "list_contacts" => to_value(n.list_contacts().await?),
        "network_status" => {
            let a: StatusParams = params(p)?;
            to_value(n.network_status(a.verbose).await?)
        }
        "create_trigger" => to_value(n.create_trigger(params::<CreateTriggerRequest>(p)?).await?),
        "list_triggers" => {
            let a: ListTriggersParams = params(p)?;
            to_value(n.list_triggers(a.include_inactive).await?)
        }
        "delete_trigger" => {
            let a: TriggerIdParams = params(p)?;
            to_value(n.delete_trigger(a.trigger_id).await?)
        }
        "read_outbox" => to_value(n.read_outbox(params::<PageRequest>(p)?).await?),
        "read_conversation" => {
            let a: ConversationParams = params(p)?;
            let page = PageRequest {
                cursor: a.cursor,
                limit: a.limit,
            };
            to_value(n.read_conversation(a.conversation_id, page).await?)
        }
        "read_events" => to_value(n.read_events(params::<PageRequest>(p)?).await?),
        // ---- optional discovery (policy_denied unless the host enabled it)
        "advertise_agent" => to_value(n.advertise_agent(params::<AdvertiseRequest>(p)?).await?),
        "withdraw_advert" => {
            let a: TopicParams = params(p)?;
            to_value(n.withdraw_advert(a.topic).await?)
        }
        "discover_agents" => to_value(n.discover_agents(params::<DiscoverRequest>(p)?).await?),
        "events.ack" | "ack_events" => {
            let a: AckParams = params(p)?;
            to_value(n.ack_events(a.cursor).await?)
        }
        // ---- administration
        "contacts.set_trust" => {
            let a: TrustParams = params(p)?;
            to_value(n.set_contact_trust(&a.address, a.trust)?)
        }
        "contacts.remove" => {
            let a: AddressParams = params(p)?;
            Ok(json!({"removed": n.remove_contact(&a.address)?}))
        }
        "contacts.import_revocation" => {
            let a: DocumentParams = params(p)?;
            to_value(n.import_revocation(&a.document)?)
        }
        "quarantine.list" => to_value(n.list_quarantined_page(params::<PageRequest>(p)?)?),
        "quarantine.release" => {
            let a: MessageIdParams = params(p)?;
            Ok(json!({"released": n.release_quarantined(&a.message_id)?}))
        }
        "metrics" => to_value(n.metrics()),
        "daemon.status" => Ok((ctx.status)()),
        "shutdown" => {
            ctx.shutdown_request.cancel();
            Ok(json!({"stopping": true}))
        }
        _ => Err(ApiError::invalid("unknown method")),
    }
}

/// Validate the cursor, then spawn the replay-then-live stream.
async fn start_events(
    node: &Arc<Node>,
    p: Value,
    out: mpsc::Sender<String>,
    conn: CancellationToken,
) -> Result<(), ApiError> {
    let a: SubscribeParams = params(p)?;
    // Subscribe to hints before the first read so nothing slips between the
    // replay and the live phase; reading is always by cursor anyway.
    let hints = node.changes();
    node.read_events(PageRequest {
        cursor: a.since_cursor.clone(),
        limit: Some(1),
    })
    .await?;
    let node = node.clone();
    tokio::spawn(stream_events(node, a.since_cursor, hints, out, conn));
    Ok(())
}

async fn stream_events(
    node: Arc<Node>,
    mut cursor: Option<String>,
    mut hints: tokio::sync::broadcast::Receiver<ChangeHint>,
    out: mpsc::Sender<String>,
    conn: CancellationToken,
) {
    loop {
        let page = match node
            .read_events(PageRequest {
                cursor: cursor.clone(),
                limit: Some(EVENT_PAGE),
            })
            .await
        {
            Ok(p) => p,
            Err(e) => {
                let _ = out.send(err_line(None, &e)).await;
                return;
            }
        };
        for ev in &page.events {
            tokio::select! {
                _ = conn.cancelled() => return,
                r = out.send(event_line(ev)) => if r.is_err() { return },
            }
        }
        if let Some(c) = page.next_cursor {
            cursor = Some(c);
        }
        if page.has_more {
            continue;
        }
        loop {
            tokio::select! {
                _ = conn.cancelled() => return,
                _ = tokio::time::sleep(EVENT_POLL) => break,
                h = hints.recv() => match h {
                    Ok(ChangeHint::Events) => break,
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
            }
        }
    }
}

fn start_changes(node: Arc<Node>, out: mpsc::Sender<String>, conn: CancellationToken) {
    let mut rx = node.changes();
    tokio::spawn(async move {
        loop {
            let lines: Vec<String> = tokio::select! {
                _ = conn.cancelled() => return,
                r = rx.recv() => match r {
                    Ok(h) => vec![change_line(&h)],
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        all_hints().iter().map(change_line).collect()
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
            };
            for l in lines {
                tokio::select! {
                    _ = conn.cancelled() => return,
                    r = out.send(l) => if r.is_err() { return },
                }
            }
        }
    });
}
