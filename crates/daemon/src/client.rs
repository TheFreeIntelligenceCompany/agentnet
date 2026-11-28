//! Clients of the control and event socket: [`RemoteAgent`] implements
//! [`AgentApi`] over the socket, [`EventStream`] consumes `events.subscribe`.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use agentnet_core::api::*;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::datadir::{read_secret_file, DataDir};
use crate::proto::{all_hints, read_line, Line, MAX_RESPONSE_LINE};

/// Default time a single request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Quote `s` for a POSIX shell: unchanged when it only has safe characters,
/// otherwise single-quoted.
pub fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:=@%,".contains(c));
    if safe {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// `agentnet --data-dir <dir> <rest>` with the directory shell-quoted, so a
/// printed next step targets the same identity.
pub fn agentnet_command(dir: &Path, rest: &str) -> String {
    format!(
        "agentnet --data-dir {} {rest}",
        shell_quote(&dir.to_string_lossy())
    )
}

fn unavailable_not_running(sock: &Path) -> ApiError {
    // The socket is `<data dir>/agentnet.sock`.
    let start = match sock.parent() {
        Some(dir) => agentnet_command(dir, "serve"),
        None => "agentnet serve".to_owned(),
    };
    ApiError::unavailable(format!(
        "the AgentNet daemon is not running (cannot connect to {}); start it with `{start}`",
        sock.display()
    ))
}

fn lost() -> ApiError {
    ApiError::unavailable(
        "the connection to the AgentNet daemon was lost; if it stopped, start it again with `agentnet serve` on the same data directory",
    )
}

/// An authenticated connection that has completed the hello exchange.
struct RawConn {
    rd: BufReader<OwnedReadHalf>,
    wr: OwnedWriteHalf,
    next_id: u64,
    /// Lines read while waiting for a response (events, hints).
    side: VecDeque<Value>,
}

async fn open_raw(socket: &Path, token_path: &Path, client: &str) -> ApiResult<RawConn> {
    let token = match read_secret_file(token_path) {
        Ok(t) => t,
        Err(e) => {
            return Err(ApiError::unavailable(format!(
                "cannot read the control token ({e}); is --data-dir right and has `agentnet init` been run for it?"
            )))
        }
    };
    let token =
        String::from_utf8(token).map_err(|_| ApiError::unavailable("control token is not text"))?;
    let stream = match timeout(CONNECT_TIMEOUT, UnixStream::connect(socket)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(match e.kind() {
                std::io::ErrorKind::PermissionDenied => ApiError::unavailable(format!(
                "permission denied connecting to {}; run as the user that owns the data directory",
                socket.display()
            )),
                _ => unavailable_not_running(socket),
            })
        }
        Err(_) => return Err(unavailable_not_running(socket)),
    };
    let (rd, mut wr) = stream.into_split();
    let mut rd = BufReader::new(rd);
    let hello = json!({"hello": {"token": token.trim(), "client": client}}).to_string();
    wr.write_all(format!("{hello}\n").as_bytes())
        .await
        .map_err(|_| lost())?;
    let reply = match timeout(CONNECT_TIMEOUT, read_line(&mut rd, MAX_RESPONSE_LINE)).await {
        Ok(Ok(Line::Line(b))) => b,
        _ => return Err(lost()),
    };
    let v: Value = serde_json::from_slice(&reply).map_err(|_| lost())?;
    if v["hello"]["ok"] == json!(true) {
        return Ok(RawConn {
            rd,
            wr,
            next_id: 1,
            side: VecDeque::new(),
        });
    }
    match serde_json::from_value::<ApiError>(v["error"].clone()) {
        Ok(e) => Err(e),
        Err(_) => Err(lost()),
    }
}

impl RawConn {
    /// Next JSON line (buffered side lines first). `None` on clean EOF.
    async fn recv(&mut self) -> ApiResult<Option<Value>> {
        if let Some(v) = self.side.pop_front() {
            return Ok(Some(v));
        }
        self.recv_wire().await
    }

    async fn recv_wire(&mut self) -> ApiResult<Option<Value>> {
        match read_line(&mut self.rd, MAX_RESPONSE_LINE).await {
            Ok(Line::Line(b)) => serde_json::from_slice(&b)
                .map(Some)
                .map_err(|_| ApiError::internal("daemon sent a malformed line")),
            Ok(Line::Eof) | Err(_) => Ok(None),
            Ok(Line::TooLong) => Err(ApiError::internal("daemon sent an oversize line")),
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> ApiResult<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({"id": id, "method": method, "params": params}).to_string();
        if line.len() > crate::proto::MAX_REQUEST_LINE {
            return Err(ApiError::new(
                agentnet_core::api::ErrorCode::TooLarge,
                "request exceeds maximum control-socket line length",
            ));
        }
        timeout(
            REQUEST_TIMEOUT,
            self.wr.write_all(format!("{line}\n").as_bytes()),
        )
        .await
        .map_err(|_| ApiError::unavailable("timed out writing request to the AgentNet daemon"))?
        .map_err(|_| lost())?;
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            let Some(v) = tokio::time::timeout_at(deadline, self.recv_wire())
                .await
                .map_err(|_| {
                    ApiError::unavailable("the AgentNet daemon did not answer in time")
                })??
            else {
                return Err(lost());
            };
            if v.get("id") == Some(&json!(id)) {
                return response_to_result(v);
            }
            if v.get("id").is_some_and(Value::is_null) && v.get("error").is_some() {
                return response_to_result(v);
            }
            if self.side.len() >= 10_000 {
                return Err(ApiError::internal(
                    "too many unsolicited daemon frames buffered while awaiting reply",
                ));
            }
            self.side.push_back(v);
        }
    }
}

fn response_to_result(mut v: Value) -> ApiResult<Value> {
    if let Some(e) = v.get_mut("error") {
        let e: ApiError = serde_json::from_value(e.take())
            .map_err(|_| ApiError::internal("daemon sent a malformed error"))?;
        return Err(e);
    }
    Ok(v.get_mut("result").map(Value::take).unwrap_or(Value::Null))
}

// --------------------------------------------------------------------------
// multiplexed request connection

struct PendingState {
    alive: bool,
    waiters: HashMap<u64, oneshot::Sender<ApiResult<Value>>>,
}

type Pending = Arc<StdMutex<PendingState>>;

struct Conn {
    write_tx: tokio::sync::mpsc::Sender<(u64, String)>,
    pending: Pending,
    next_id: AtomicU64,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

enum ReqErr {
    /// Nothing was sent; safe to retry on a fresh connection.
    NotSent,
    Failed(ApiError),
}

impl Conn {
    fn new(raw: RawConn) -> Self {
        let RawConn { rd, mut wr, .. } = raw;
        let pending: Pending = Arc::new(StdMutex::new(PendingState {
            alive: true,
            waiters: HashMap::new(),
        }));
        let (write_tx, mut write_rx) = tokio::sync::mpsc::channel::<(u64, String)>(64);
        let p_wr = pending.clone();
        let writer = tokio::spawn(async move {
            while let Some((id, line)) = write_rx.recv().await {
                let ok = matches!(
                    timeout(REQUEST_TIMEOUT, wr.write_all(line.as_bytes())).await,
                    Ok(Ok(()))
                );
                if !ok {
                    let drained: Vec<_> = {
                        let mut st = p_wr.lock().unwrap_or_else(|e| e.into_inner());
                        st.alive = false;
                        st.waiters.remove(&id);
                        st.waiters.drain().map(|(_, tx)| tx).collect()
                    };
                    for tx in drained {
                        let _ = tx.send(Err(lost()));
                    }
                    break;
                }
            }
        });
        let p = pending.clone();
        let reader = tokio::spawn(async move {
            let mut rd = rd;
            let mut fatal_err: Option<ApiError> = None;
            loop {
                let line = read_line(&mut rd, MAX_RESPONSE_LINE).await;
                let Ok(Line::Line(b)) = line else { break };
                let Ok(v) = serde_json::from_slice::<Value>(&b) else {
                    break;
                };
                if v.get("id").is_some_and(Value::is_null) && v.get("error").is_some() {
                    if let Err(e) = response_to_result(v) {
                        fatal_err = Some(e);
                    }
                    break;
                }
                let Some(id) = v.get("id").and_then(Value::as_u64) else {
                    continue;
                };
                let tx = p
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .waiters
                    .remove(&id);
                if let Some(tx) = tx {
                    let _ = tx.send(response_to_result(v));
                }
            }
            let drained: Vec<_> = {
                let mut st = p.lock().unwrap_or_else(|e| e.into_inner());
                st.alive = false;
                st.waiters.drain().map(|(_, tx)| tx).collect()
            };
            for tx in drained {
                let _ = tx.send(Err(fatal_err.clone().unwrap_or_else(lost)));
            }
        });
        Self {
            write_tx,
            pending,
            next_id: AtomicU64::new(1),
            reader,
            writer,
        }
    }

    fn is_alive(&self) -> bool {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).alive
    }

    async fn request(&self, method: &str, params: Value, limit: Duration) -> Result<Value, ReqErr> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let line = format!(
            "{}\n",
            json!({"id": id, "method": method, "params": params})
        );
        if line.len() > crate::proto::MAX_REQUEST_LINE + 1 {
            return Err(ReqErr::Failed(ApiError::new(
                agentnet_core::api::ErrorCode::TooLarge,
                "request exceeds maximum control-socket line length",
            )));
        }
        let (tx, rx) = oneshot::channel();
        {
            let mut st = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if !st.alive {
                return Err(ReqErr::NotSent);
            }
            st.waiters.insert(id, tx);
        }
        let sent = timeout(limit, self.write_tx.send((id, line))).await;
        if !matches!(sent, Ok(Ok(()))) {
            let mut st = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            st.waiters.remove(&id);
            st.alive = false;
            return Err(ReqErr::NotSent);
        }
        match timeout(limit, rx).await {
            Ok(Ok(r)) => r.map_err(ReqErr::Failed),
            Ok(Err(_)) => Err(ReqErr::Failed(lost())),
            Err(_) => {
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .waiters
                    .remove(&id);
                Err(ReqErr::Failed(ApiError::unavailable(
                    "the AgentNet daemon did not answer in time",
                )))
            }
        }
    }
}

struct Inner {
    socket: PathBuf,
    token_path: PathBuf,
    client: String,
    request_timeout: Duration,
    conn: Mutex<Option<Arc<Conn>>>,
    changes_tx: broadcast::Sender<ChangeHint>,
    changes_started: AtomicBool,
    cancel: CancellationToken,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// [`AgentApi`] over the daemon's control socket.
///
/// Connects lazily, multiplexes requests over one connection and reconnects
/// when the daemon restarts. While the daemon is down every call fails with
/// [`ErrorCode::Unavailable`] and a message telling the user to start it.
/// `changes()` is fed by a background `changes.subscribe` connection that is
/// re-established with backoff; after every reconnect a synthetic burst of all
/// hint kinds is emitted because hints may have been missed.
#[derive(Clone)]
pub struct RemoteAgent {
    inner: Arc<Inner>,
}

impl RemoteAgent {
    /// Client for the daemon of `data_dir`.
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let d = DataDir::new(data_dir.as_ref());
        Self::with_paths(d.socket(), d.control_token(), "agentnet-remote")
    }

    /// Client with explicit socket and token paths.
    pub fn with_paths(socket: PathBuf, token_path: PathBuf, client: &str) -> Self {
        let (changes_tx, _) = broadcast::channel(256);
        Self {
            inner: Arc::new(Inner {
                socket,
                token_path,
                client: client.to_owned(),
                request_timeout: REQUEST_TIMEOUT,
                conn: Mutex::new(None),
                changes_tx,
                changes_started: AtomicBool::new(false),
                cancel: CancellationToken::new(),
            }),
        }
    }

    /// Path of the socket this client talks to.
    pub fn socket_path(&self) -> &Path {
        &self.inner.socket
    }

    async fn get_conn(&self) -> ApiResult<Arc<Conn>> {
        let mut g = self.inner.conn.lock().await;
        if let Some(c) = g.as_ref() {
            if c.is_alive() {
                return Ok(c.clone());
            }
        }
        let raw = open_raw(
            &self.inner.socket,
            &self.inner.token_path,
            &self.inner.client,
        )
        .await?;
        let c = Arc::new(Conn::new(raw));
        *g = Some(c.clone());
        Ok(c)
    }

    /// Send one request and return the raw JSON result.
    pub async fn call_value(&self, method: &str, params: Value) -> ApiResult<Value> {
        for attempt in 0..2 {
            let conn = self.get_conn().await?;
            match conn
                .request(method, params.clone(), self.inner.request_timeout)
                .await
            {
                Ok(v) => return Ok(v),
                Err(ReqErr::NotSent) if attempt == 0 => {
                    let mut g = self.inner.conn.lock().await;
                    if g.as_ref().is_some_and(|c| Arc::ptr_eq(c, &conn)) {
                        *g = None;
                    }
                }
                Err(ReqErr::NotSent) => return Err(lost()),
                Err(ReqErr::Failed(e)) => return Err(e),
            }
        }
        Err(lost())
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
    ) -> ApiResult<T> {
        let p = serde_json::to_value(params)
            .map_err(|_| ApiError::internal("could not encode request"))?;
        let v = self.call_value(method, p).await?;
        serde_json::from_value(v)
            .map_err(|_| ApiError::internal("daemon sent an unexpected result"))
    }

    // ---- administration (not part of AgentApi)

    /// `contacts.set_trust`
    pub async fn set_contact_trust(&self, address: &str, trust: Trust) -> ApiResult<ContactInfo> {
        self.call(
            "contacts.set_trust",
            json!({"address": address, "trust": trust}),
        )
        .await
    }
    /// `contacts.import_revocation`: import a signed identity-revocation
    /// tombstone obtained out of band.
    pub async fn import_revocation(
        &self,
        document: &str,
    ) -> ApiResult<agentnet_core::api::RevocationInfo> {
        self.call("contacts.import_revocation", json!({"document": document}))
            .await
    }
    /// `contacts.remove`; returns whether the contact existed.
    pub async fn remove_contact(&self, address: &str) -> ApiResult<bool> {
        let v: Value = self
            .call("contacts.remove", json!({"address": address}))
            .await?;
        Ok(v["removed"].as_bool().unwrap_or(false))
    }
    /// `quarantine.list`: one page (see `Node::list_quarantined_page`).
    pub async fn list_quarantined_page(&self, req: PageRequest) -> ApiResult<ReadInboxResponse> {
        self.call("quarantine.list", req).await
    }
    /// Every quarantined message, fetched page by page.
    pub async fn list_quarantined(&self) -> ApiResult<Vec<InboxRecord>> {
        let mut all = Vec::new();
        let mut cursor = None;
        loop {
            let page = self
                .list_quarantined_page(PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(200),
                })
                .await?;
            all.extend(page.records);
            if !page.has_more || page.next_cursor == cursor {
                return Ok(all);
            }
            cursor = page.next_cursor;
        }
    }
    /// `quarantine.release`; returns the number of messages released.
    pub async fn release_quarantined(&self, message_id: &str) -> ApiResult<u64> {
        let v: Value = self
            .call("quarantine.release", json!({"message_id": message_id}))
            .await?;
        Ok(v["released"].as_u64().unwrap_or(0))
    }
    /// `metrics`
    pub async fn metrics(&self) -> ApiResult<agentnet_core::NodeMetrics> {
        self.call("metrics", json!({})).await
    }
    /// `daemon.status` (version, uptime, webhook state).
    pub async fn daemon_status(&self) -> ApiResult<Value> {
        self.call_value("daemon.status", json!({})).await
    }
    /// Ask the daemon to shut down gracefully.
    pub async fn shutdown(&self) -> ApiResult<()> {
        self.call_value("shutdown", json!({})).await.map(|_| ())
    }

    fn ensure_changes_task(&self) {
        if self
            .inner
            .changes_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // No runtime yet: try again on the next `changes()` call.
            self.inner.changes_started.store(false, Ordering::SeqCst);
            return;
        };
        let (socket, token, tx, cancel) = (
            self.inner.socket.clone(),
            self.inner.token_path.clone(),
            self.inner.changes_tx.clone(),
            self.inner.cancel.clone(),
        );
        handle.spawn(changes_loop(socket, token, tx, cancel));
    }
}

async fn changes_loop(
    socket: PathBuf,
    token: PathBuf,
    tx: broadcast::Sender<ChangeHint>,
    cancel: CancellationToken,
) {
    let mut backoff = Duration::from_millis(100);
    let mut missed = false;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let attempt = async {
            let mut raw = open_raw(&socket, &token, "agentnet-remote-changes").await?;
            raw.request("changes.subscribe", json!({})).await?;
            ApiResult::Ok(raw)
        };
        let conn = tokio::select! {
            _ = cancel.cancelled() => return,
            r = attempt => r,
        };
        match conn {
            Ok(mut raw) => {
                backoff = Duration::from_millis(100);
                if missed {
                    for h in all_hints() {
                        let _ = tx.send(h);
                    }
                }
                loop {
                    let next = tokio::select! {
                        _ = cancel.cancelled() => return,
                        r = raw.recv() => r,
                    };
                    match next {
                        Ok(Some(v)) => {
                            if let Some(h) = v.get("change") {
                                if let Ok(h) = serde_json::from_value::<ChangeHint>(h.clone()) {
                                    let _ = tx.send(h);
                                }
                            }
                        }
                        _ => break,
                    }
                }
                missed = true;
            }
            Err(e) => {
                tracing::debug!(error = %e, "changes connection failed; retrying");
                missed = true;
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(5));
    }
}

#[async_trait]
impl AgentApi for RemoteAgent {
    async fn get_identity(&self) -> ApiResult<IdentityInfo> {
        self.call("get_identity", json!({})).await
    }
    async fn send_message(&self, req: SendMessageRequest) -> ApiResult<SendMessageResponse> {
        self.call("send_message", req).await
    }
    async fn read_inbox(&self, req: ReadInboxRequest) -> ApiResult<ReadInboxResponse> {
        self.call("read_inbox", req).await
    }
    async fn get_message(&self, req: GetMessageRequest) -> ApiResult<InboxRecord> {
        self.call("get_message", req).await
    }
    async fn acknowledge_message(&self, message_id: String) -> ApiResult<AcknowledgeResponse> {
        self.call("acknowledge_message", json!({"message_id": message_id}))
            .await
    }
    async fn get_message_status(&self, message_id: String) -> ApiResult<MessageStatus> {
        self.call("get_message_status", json!({"message_id": message_id}))
            .await
    }
    async fn add_contact(&self, req: AddContactRequest) -> ApiResult<ContactInfo> {
        self.call("add_contact", req).await
    }
    async fn list_contacts(&self) -> ApiResult<Vec<ContactInfo>> {
        self.call("list_contacts", json!({})).await
    }
    async fn network_status(&self, verbose: bool) -> ApiResult<NetworkStatus> {
        self.call("network_status", json!({"verbose": verbose}))
            .await
    }
    async fn create_trigger(&self, req: CreateTriggerRequest) -> ApiResult<TriggerInfo> {
        self.call("create_trigger", req).await
    }
    async fn list_triggers(&self, include_inactive: bool) -> ApiResult<Vec<TriggerInfo>> {
        self.call(
            "list_triggers",
            json!({"include_inactive": include_inactive}),
        )
        .await
    }
    async fn delete_trigger(&self, trigger_id: String) -> ApiResult<DeleteTriggerResponse> {
        self.call("delete_trigger", json!({"trigger_id": trigger_id}))
            .await
    }
    async fn read_outbox(&self, req: PageRequest) -> ApiResult<OutboxPage> {
        self.call("read_outbox", req).await
    }
    async fn read_conversation(
        &self,
        conversation_id: String,
        req: PageRequest,
    ) -> ApiResult<ConversationPage> {
        self.call(
            "read_conversation",
            json!({"conversation_id": conversation_id, "cursor": req.cursor, "limit": req.limit}),
        )
        .await
    }
    async fn read_events(&self, req: PageRequest) -> ApiResult<EventPage> {
        self.call("read_events", req).await
    }
    async fn ack_events(&self, cursor: String) -> ApiResult<()> {
        self.call_value("events.ack", json!({"cursor": cursor}))
            .await
            .map(|_| ())
    }
    async fn advertise_agent(&self, req: AdvertiseRequest) -> ApiResult<AdvertInfo> {
        self.call("advertise_agent", req).await
    }
    async fn withdraw_advert(&self, topic: String) -> ApiResult<WithdrawInfo> {
        self.call("withdraw_advert", json!({"topic": topic})).await
    }
    async fn discover_agents(&self, req: DiscoverRequest) -> ApiResult<DiscoverPage> {
        self.call("discover_agents", req).await
    }
    fn changes(&self) -> broadcast::Receiver<ChangeHint> {
        let rx = self.inner.changes_tx.subscribe();
        self.ensure_changes_task();
        rx
    }
}

/// A live `events.subscribe` connection: replay after a cursor, then live
/// events, with at-least-once delivery (see `docs/host-integration.md`).
pub struct EventStream {
    conn: RawConn,
}

impl EventStream {
    /// Subscribe on the daemon of `data_dir`. `since_cursor = None` replays all
    /// retained events; pass the cursor of the last event you fully handled.
    pub async fn connect(
        data_dir: impl AsRef<Path>,
        since_cursor: Option<String>,
    ) -> ApiResult<Self> {
        let d = DataDir::new(data_dir.as_ref());
        Self::connect_with(
            &d.socket(),
            &d.control_token(),
            "agentnet-events",
            since_cursor,
        )
        .await
    }

    /// Subscribe with explicit paths and client name.
    pub async fn connect_with(
        socket: &Path,
        token_path: &Path,
        client: &str,
        since_cursor: Option<String>,
    ) -> ApiResult<Self> {
        let mut conn = open_raw(socket, token_path, client).await?;
        conn.request("events.subscribe", json!({"since_cursor": since_cursor}))
            .await?;
        Ok(Self { conn })
    }

    /// The next event; `Ok(None)` when the daemon closed the stream (reconnect
    /// with your persisted cursor).
    pub async fn next(&mut self) -> ApiResult<Option<EventRecord>> {
        loop {
            let Some(v) = self.conn.recv().await? else {
                return Ok(None);
            };
            if let Some(ev) = v.get("event") {
                return serde_json::from_value(ev.clone())
                    .map(Some)
                    .map_err(|_| ApiError::internal("daemon sent a malformed event"));
            }
            if v.get("error").is_some() {
                return Err(response_to_result(v).err().unwrap_or_else(lost));
            }
        }
    }

    /// Acknowledge every event up to and including `cursor` (also acceptable
    /// from another connection via [`RemoteAgent::ack_events`]).
    pub async fn ack(&mut self, cursor: &str) -> ApiResult<()> {
        self.conn
            .request("events.ack", json!({"cursor": cursor}))
            .await
            .map(|_| ())
    }
}
