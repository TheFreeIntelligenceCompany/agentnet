//! Streamable HTTP transport with a static bearer token.
//!
//! **This is not the MCP OAuth profile.** The 2026-07-28 authorization page says
//! HTTP implementations SHOULD follow OAuth 2.1 / RFC 9728; a static shared secret
//! on a loopback (or otherwise private) listener is a local gate only. Exposing
//! this endpoint to untrusted networks would require the OAuth profile (or a
//! front proxy that terminates it) and is out of scope: [`serve_http`] and
//! [`bind_http`] refuse non-loopback addresses unless `allow_non_loopback` is
//! passed explicitly.
//!
//! Checks, in order: bearer token (401 + `WWW-Authenticate: Bearer`), then rmcp's
//! `Host` allowlist (403) and `Origin` validation (403; always on, so any request
//! carrying an `Origin` header is rejected unless it is in `allowed_origins`).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use agentnet_core::api::AgentApi;
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::{limits::MAX_HTTP_BODY_BYTES, AgentNetMcp, ServeError};

/// Path of the MCP endpoint.
pub const MCP_PATH: &str = "/mcp";
/// Shortest accepted bearer token, in bytes.
pub const MIN_TOKEN_LEN: usize = 16;
/// How long open streams get to close after shutdown before serving stops anyway.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Configuration of the HTTP endpoint.
#[derive(Clone)]
pub struct HttpOptions {
    /// Required bearer token (at least [`MIN_TOKEN_LEN`] bytes). Treated as a secret.
    pub bearer_token: String,
    /// Accepted `Host` header values (host part only, port ignored). Empty means
    /// the default loopback names: `localhost`, `127.0.0.1`, `::1`.
    pub allowed_hosts: Vec<String>,
    /// Accepted `Origin` header values (exact match). Requests without an
    /// `Origin` header (non-browser clients) are unaffected; requests with one
    /// that is not listed get 403. Empty means no browser origin is accepted.
    pub allowed_origins: Vec<String>,
}

impl HttpOptions {
    /// Loopback defaults with the given token.
    pub fn new(bearer_token: impl Into<String>) -> Self {
        Self {
            bearer_token: bearer_token.into(),
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
        }
    }

    fn token_usable(token: &str) -> bool {
        token.len() >= MIN_TOKEN_LEN && token.bytes().all(|b| (0x21..=0x7e).contains(&b))
    }

    /// Check the options are usable. [`serve_http`] calls this; [`http_router`]
    /// instead fails closed (rejects every request) on an invalid token.
    pub fn validate(&self) -> Result<(), ServeError> {
        if !Self::token_usable(&self.bearer_token) {
            return Err(ServeError::Refused(format!(
                "bearer token must be at least {MIN_TOKEN_LEN} visible ASCII bytes (no spaces or control characters)"
            )));
        }
        Ok(())
    }
}

impl std::fmt::Debug for HttpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOptions")
            .field("bearer_token", &"<redacted>")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .finish()
    }
}

#[derive(Clone)]
struct AuthState {
    /// `None` when the configured token is unusable: every request is refused.
    token: Option<Arc<[u8]>>,
}

async fn require_bearer(State(auth): State<AuthState>, req: Request, next: Next) -> Response {
    let authorized = match &auth.token {
        None => false,
        Some(expected) => {
            let mut hdrs = req.headers().get_all(header::AUTHORIZATION).iter();
            match (hdrs.next(), hdrs.next()) {
                (Some(v), None) => v
                    .to_str()
                    .ok()
                    .and_then(|v| {
                        let (scheme, rest) = v.split_once(' ')?;
                        scheme.eq_ignore_ascii_case("bearer").then_some(rest)
                    })
                    .is_some_and(|presented| bool::from(presented.as_bytes().ct_eq(expected))),
                _ => false,
            }
        }
    };
    if authorized {
        return next.run(req).await;
    }
    let mut resp = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    resp.headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    resp
}

/// Router serving MCP at [`MCP_PATH`]. Subscription streams end when `shutdown`
/// is cancelled. An unusable token (shorter than [`MIN_TOKEN_LEN`]) makes every
/// request fail with 401; use [`HttpOptions::validate`] to detect that up front.
pub fn http_router_with_shutdown(
    api: Arc<dyn AgentApi>,
    options: HttpOptions,
    shutdown: CancellationToken,
) -> Router {
    let handler = AgentNetMcp::with_shutdown(api, shutdown.clone());
    let token_ok = HttpOptions::token_usable(&options.bearer_token);
    if !token_ok {
        tracing::error!(
            "http bearer token is invalid or shorter than {MIN_TOKEN_LEN} bytes: refusing all requests"
        );
    }
    let hosts = if options.allowed_hosts.is_empty() {
        vec!["localhost".to_string(), "127.0.0.1".into(), "::1".into()]
    } else {
        options.allowed_hosts
    };
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(hosts)
        .with_allowed_origins(options.allowed_origins)
        // Origin validation stays on even with an empty allowlist.
        .enforce_origin_validation()
        .with_max_request_body_bytes(MAX_HTTP_BODY_BYTES)
        .with_sse_keep_alive(Some(Duration::from_secs(15)))
        .with_cancellation_token(shutdown.child_token());
    let service: StreamableHttpService<AgentNetMcp, LocalSessionManager> =
        StreamableHttpService::new(move || Ok(handler.session()), Default::default(), config);
    let auth = AuthState {
        token: token_ok.then(|| Arc::from(options.bearer_token.into_bytes())),
    };
    Router::new()
        .route_service(MCP_PATH, service)
        .layer(middleware::from_fn_with_state(auth, require_bearer))
}

/// [`http_router_with_shutdown`] with a shutdown token that is never cancelled:
/// open `subscriptions/listen` streams then end only when the client leaves.
/// Prefer [`http_router_with_shutdown`] (or [`serve_http`]) when you control
/// shutdown.
pub fn http_router(api: Arc<dyn AgentApi>, options: HttpOptions) -> Router {
    http_router_with_shutdown(api, options, CancellationToken::new())
}

/// Bind `addr`, refusing non-loopback addresses unless `allow_non_loopback`.
pub async fn bind_http(
    addr: SocketAddr,
    allow_non_loopback: bool,
) -> Result<TcpListener, ServeError> {
    check_loopback(addr, allow_non_loopback)?;
    Ok(TcpListener::bind(addr).await?)
}

fn check_loopback(addr: SocketAddr, allow_non_loopback: bool) -> Result<(), ServeError> {
    if addr.ip().is_loopback() || allow_non_loopback {
        if !addr.ip().is_loopback() {
            tracing::warn!(
                %addr,
                "serving MCP on a non-loopback address with a static bearer token; \
                 this is not the MCP OAuth profile"
            );
        }
        Ok(())
    } else {
        Err(ServeError::Refused(format!(
            "refusing to serve MCP on non-loopback address {addr}: remote exposure needs the \
             MCP OAuth profile, which is not implemented"
        )))
    }
}

/// Serve on an already-bound listener until `shutdown` is cancelled.
///
/// Refuses (before serving) a non-loopback listener unless `allow_non_loopback`,
/// and a bearer token shorter than [`MIN_TOKEN_LEN`].
pub async fn serve_http(
    listener: TcpListener,
    api: Arc<dyn AgentApi>,
    options: HttpOptions,
    allow_non_loopback: bool,
    shutdown: CancellationToken,
) -> Result<(), ServeError> {
    options.validate()?;
    check_loopback(listener.local_addr()?, allow_non_loopback)?;
    let router = http_router_with_shutdown(api, options, shutdown.clone());
    let stop = shutdown.clone();
    let server =
        axum::serve(listener, router).with_graceful_shutdown(async move { stop.cancelled().await });
    tokio::select! {
        result = server => result.map_err(ServeError::from),
        () = async {
            shutdown.cancelled().await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => {
            tracing::warn!("open connections did not close within the shutdown grace period");
            Ok(())
        }
    }
}
