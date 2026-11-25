//! MCP spike: one tool (`echo_send`), one resource (`spike://inbox`), change notifications.
//!
//! Server state is a process-wide [`Shared`] captured by the handler factory, because in the
//! 2026-07-28 stateless model `StreamableHttpService` builds a fresh handler per request.

use std::{
    borrow::Cow,
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rmcp::{
    ErrorData as McpError, Json, Peer, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars::{self, JsonSchema},
    service::{RequestContext, SubscriptionContext},
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

pub const INBOX_URI: &str = "spike://inbox";
pub const INBOX_TEMPLATE: &str = "spike://inbox{?cursor,limit}";
pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 100;
pub const MAX_BODY_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Record {
    /// Monotonic per-epoch sequence number (1-based).
    pub seq: u64,
    pub id: String,
    pub sender: String,
    pub body: String,
    pub conversation_id: Option<String>,
    pub received_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct EchoSendInput {
    /// Logical sender name.
    pub sender: String,
    /// Message body (max 4096 bytes).
    pub body: String,
    /// Optional conversation identifier.
    pub conversation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct EchoSendOutput {
    pub id: String,
    pub seq: u64,
    /// Cursor positioned immediately after this record.
    pub cursor: String,
}

/// JSON body of `resources/read` for `spike://inbox{?cursor,limit}`.
#[derive(Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct InboxPage {
    pub epoch: String,
    pub records: Vec<Record>,
    /// Resume point: pass as `cursor` to receive only records after this page.
    pub cursor: String,
    /// Present only if more records already exist beyond this page.
    pub next_cursor: Option<String>,
}

struct LegacySub {
    peer: Mutex<Option<Peer<RoleServer>>>,
    uris: Mutex<HashSet<String>>,
    registered: AtomicBool,
}

/// Process-wide state shared by every handler instance and every transport.
pub struct Shared {
    pub epoch: String,
    records: Mutex<Vec<Record>>,
    updates: broadcast::Sender<()>,
    legacy: Mutex<Vec<Arc<LegacySub>>>,
    /// `subscriptions/listen` requests currently running (for tests).
    pub active_listeners: AtomicUsize,
    /// `subscriptions/listen` requests ever started (for tests).
    pub total_listeners: AtomicUsize,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let (updates, _) = broadcast::channel(16);
        Arc::new(Self {
            epoch: format!("{:x}{:x}", nanos as u64, std::process::id()),
            records: Mutex::new(Vec::new()),
            updates,
            legacy: Mutex::new(Vec::new()),
            active_listeners: AtomicUsize::new(0),
            total_listeners: AtomicUsize::new(0),
        })
    }

    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn cursor_after(&self, seq: u64) -> String {
        format!("{}:{}", self.epoch, seq)
    }

    /// Persist (in memory) first, then notify. Notifications are hints, never the queue.
    pub fn append(self: &Arc<Self>, input: EchoSendInput) -> Record {
        let record = {
            let mut records = self.records.lock().unwrap();
            let seq = records.len() as u64 + 1;
            let record = Record {
                seq,
                id: format!("{}-{}", self.epoch, seq),
                sender: input.sender,
                body: input.body,
                conversation_id: input.conversation_id,
                received_at_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or_default(),
            };
            records.push(record.clone());
            record
        };
        // 2026-07-28 listeners: every running `listen` task has a receiver; it decides per
        // subscription whether the URI was requested. Lagged receivers coalesce (fine for hints).
        let _ = self.updates.send(());
        // Legacy (initialize-era) subscribers: push through the stored peer.
        let subs: Vec<Arc<LegacySub>> = self.legacy.lock().unwrap().clone();
        for sub in subs {
            if !sub.uris.lock().unwrap().contains(INBOX_URI) {
                continue;
            }
            let Some(peer) = sub.peer.lock().unwrap().clone() else {
                continue;
            };
            tokio::spawn(async move {
                let _ = peer
                    .notify_resource_updated(ResourceUpdatedNotificationParam::new(INBOX_URI))
                    .await;
            });
        }
        record
    }

    pub fn read_page(&self, cursor: Option<&str>, limit: usize) -> Result<InboxPage, McpError> {
        let after = match cursor {
            None | Some("") => 0,
            Some(c) => {
                let (epoch, seq) = c.split_once(':').ok_or_else(|| {
                    McpError::invalid_params("malformed cursor (expected <epoch>:<seq>)", None)
                })?;
                if epoch != self.epoch {
                    return Err(McpError::invalid_params(
                        "cursor belongs to a different server epoch (server restarted); re-read from the beginning",
                        Some(
                            serde_json::json!({"cursor_epoch": epoch, "server_epoch": self.epoch}),
                        ),
                    ));
                }
                seq.parse::<u64>()
                    .map_err(|_| McpError::invalid_params("malformed cursor sequence", None))?
            }
        };
        let limit = limit.clamp(1, MAX_LIMIT);
        let records = self.records.lock().unwrap();
        let start = (after as usize).min(records.len());
        let end = (start + limit).min(records.len());
        let page: Vec<Record> = records[start..end].to_vec();
        let last_seq = page.last().map(|r| r.seq).unwrap_or(after);
        let cursor = self.cursor_after(last_seq);
        let next_cursor = (end < records.len()).then(|| cursor.clone());
        Ok(InboxPage {
            epoch: self.epoch.clone(),
            records: page,
            cursor,
            next_cursor,
        })
    }
}

#[derive(Clone)]
pub struct SpikeServer {
    shared: Arc<Shared>,
    legacy: Arc<LegacySub>,
    tool_router: ToolRouter<Self>,
}

struct ListenGuard(Arc<Shared>);
impl Drop for ListenGuard {
    fn drop(&mut self) {
        self.0.active_listeners.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tool_router]
impl SpikeServer {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            legacy: Arc::new(LegacySub {
                peer: Mutex::new(None),
                uris: Mutex::new(HashSet::new()),
                registered: AtomicBool::new(false),
            }),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        name = "echo_send",
        description = "Append a record to the in-memory inbox and notify subscribers of spike://inbox"
    )]
    async fn echo_send(
        &self,
        Parameters(input): Parameters<EchoSendInput>,
    ) -> Result<Json<EchoSendOutput>, String> {
        if input.body.len() > MAX_BODY_BYTES {
            return Err(format!("body exceeds {MAX_BODY_BYTES} bytes"));
        }
        let record = self.shared.append(input);
        Ok(Json(EchoSendOutput {
            cursor: self.shared.cursor_after(record.seq),
            id: record.id,
            seq: record.seq,
        }))
    }
}

fn parse_inbox_uri(uri: &str) -> Option<(Option<String>, Option<usize>)> {
    let rest = uri.strip_prefix(INBOX_URI)?;
    if rest.is_empty() {
        return Some((None, None));
    }
    let query = rest.strip_prefix('?')?;
    let (mut cursor, mut limit) = (None, None);
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "cursor" => cursor = Some(v.to_string()),
            "limit" => limit = v.parse::<usize>().ok().or(Some(0)),
            _ => {}
        }
    }
    Some((cursor, limit))
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SpikeServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_resources_subscribe()
                .build(),
        )
        .with_server_info(Implementation::new("mcp-spike", "0.0.0"))
        .with_instructions("Spike server: call echo_send; read/subscribe spike://inbox.")
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(
            ListResourcesResult::with_all_items(vec![Resource::new(INBOX_URI, "inbox")])
                .with_ttl_ms(60_000)
                .with_cache_scope(CacheScope::Private),
        )
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(
            ListResourceTemplatesResult::with_all_items(vec![ResourceTemplate::new(
                INBOX_TEMPLATE,
                "inbox-page",
            )])
            .with_ttl_ms(60_000)
            .with_cache_scope(CacheScope::Private),
        )
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        let Some((cursor, limit)) = parse_inbox_uri(&request.uri) else {
            return Err(McpError::resource_not_found(
                "resource_not_found",
                Some(serde_json::json!({ "uri": request.uri })),
            ));
        };
        if limit == Some(0) {
            return Err(McpError::invalid_params(
                "limit must be a positive integer",
                None,
            ));
        }
        let page = self
            .shared
            .read_page(cursor.as_deref(), limit.unwrap_or(DEFAULT_LIMIT))?;
        let json = serde_json::to_string(&page)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        // ttlMs = 0: the inbox must never be served from a client cache (SEP-2549).
        Ok(ReadResourceResult::new(vec![
            ResourceContents::text(json, &request.uri).with_mime_type("application/json"),
        ])
        .with_ttl_ms(0)
        .with_cache_scope(CacheScope::Private)
        .into())
    }

    // ---- 2026-07-28: subscriptions/listen ----

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        let mut accepted = requested.supported_by(&self.get_info().capabilities);
        accepted.resource_subscriptions = accepted
            .resource_subscriptions
            .map(|uris| uris.into_iter().filter(|u| u == INBOX_URI).collect());
        Some(accepted)
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), McpError> {
        self.shared.total_listeners.fetch_add(1, Ordering::SeqCst);
        self.shared.active_listeners.fetch_add(1, Ordering::SeqCst);
        let _guard = ListenGuard(self.shared.clone());
        let wants_inbox = context
            .accepted()
            .resource_subscriptions
            .as_ref()
            .is_some_and(|uris| uris.iter().any(|u| u == INBOX_URI));
        let mut rx = self.shared.updates.subscribe();
        loop {
            tokio::select! {
                () = context.cancelled() => return Ok(()),
                event = rx.recv() => match event {
                    Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        if wants_inbox {
                            context
                                .sink()
                                .notify_resource_updated(INBOX_URI)
                                .await
                                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }

    // ---- legacy (initialize-era) resources/subscribe ----

    #[allow(deprecated)]
    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        if request.uri != INBOX_URI {
            return Err(McpError::resource_not_found(
                "resource_not_found",
                Some(serde_json::json!({ "uri": request.uri })),
            ));
        }
        *self.legacy.peer.lock().unwrap() = Some(context.peer.clone());
        self.legacy.uris.lock().unwrap().insert(request.uri);
        if !self.legacy.registered.swap(true, Ordering::SeqCst) {
            self.shared.legacy.lock().unwrap().push(self.legacy.clone());
        }
        Ok(())
    }

    #[allow(deprecated)]
    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.legacy.uris.lock().unwrap().remove(&request.uri);
        Ok(())
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::KNOWN_VERSIONS)
    }
}

// ---------------- Streamable HTTP + bearer auth ----------------

#[derive(Clone)]
struct AuthState {
    token: Arc<str>,
}

async fn require_bearer(State(auth): State<AuthState>, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|presented| bool::from(presented.as_bytes().ct_eq(auth.token.as_bytes())));
    if ok {
        return next.run(req).await;
    }
    let mut resp = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

pub fn http_router(shared: Arc<Shared>, token: &str, ct: CancellationToken) -> Router {
    let config = StreamableHttpServerConfig::default()
        // Host header allowlist: default is localhost / 127.0.0.1 / ::1.
        // Origin: present-and-not-allowlisted is rejected with 403 (allowlist empty = reject all).
        .enforce_origin_validation()
        .with_sse_keep_alive(Some(Duration::from_secs(15)))
        .with_cancellation_token(ct.child_token());
    let service: StreamableHttpService<SpikeServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(SpikeServer::new(shared.clone())),
            Default::default(),
            config,
        );
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(
            AuthState {
                token: token.into(),
            },
            require_bearer,
        ))
}

/// Serve on an already-bound listener until `ct` is cancelled.
pub async fn serve_http(
    listener: tokio::net::TcpListener,
    shared: Arc<Shared>,
    token: &str,
    ct: CancellationToken,
) -> anyhow::Result<()> {
    let router = http_router(shared, token, ct.clone());
    axum::serve(listener, router)
        .with_graceful_shutdown(async move { ct.cancelled().await })
        .await?;
    Ok(())
}
