//! stdio transport.
//!
//! stdout carries protocol frames only. Nothing in this crate prints to stdout;
//! diagnostics go through `tracing`, and the embedding binary must route its
//! subscriber to stderr.
//!
//! rmcp 3.11.0 drains in-flight handler tasks for up to 5 s after stdin closes,
//! and an open `subscriptions/listen` never ends by itself (observed in the A3
//! spike). We therefore watch the reader: when it reports EOF (or an error) the
//! server's shutdown token fires, all listen loops end at once, and the service
//! exits within a short grace period.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use agentnet_core::api::AgentApi;
use rmcp::{service::ServerInitializeError, ServiceExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use crate::{AgentNetMcp, ServeError};

/// How long in-flight requests get to finish after the client closed its end.
const EOF_GRACE: Duration = Duration::from_millis(300);
/// Extra time after cancelling the service before giving up on a clean drain.
///
/// rmcp 3.11.0 can stall its own 5 s response drain when a
/// `subscriptions/listen` request races with stdin EOF: the handler is still
/// sending its acknowledgment through a loop that already stopped, and only the
/// drain timeout releases it. Stdin is gone, so nobody can read those responses;
/// we return instead of waiting.
const CANCEL_GRACE: Duration = Duration::from_millis(200);

/// Reader wrapper that cancels a token when the inner reader hits EOF or fails.
struct EofWatch<R> {
    inner: R,
    on_eof: CancellationToken,
}

impl<R: AsyncRead + Unpin> AsyncRead for EofWatch<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let had_room = buf.remaining() > 0;
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(result) = &poll {
            if result.is_err() || (had_room && buf.filled().len() == before) {
                tracing::debug!("stdin EOF/error: cancelling shutdown token");
                self.on_eof.cancel();
            }
        }
        poll
    }
}

/// Serve MCP on this process's stdin/stdout until stdin closes.
pub async fn serve_stdio(api: Arc<dyn AgentApi>) -> Result<(), ServeError> {
    serve_io(api, tokio::io::stdin(), tokio::io::stdout()).await
}

/// Serve MCP over any reader/writer pair until the reader closes. Used by
/// [`serve_stdio`] and by in-process tests.
pub async fn serve_io<R, W>(api: Arc<dyn AgentApi>, reader: R, writer: W) -> Result<(), ServeError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let shutdown = CancellationToken::new();
    let handler = AgentNetMcp::with_shutdown(api, shutdown.clone());
    let reader = EofWatch {
        inner: reader,
        on_eof: shutdown.clone(),
    };
    let running = match handler.serve((reader, writer)).await {
        Ok(running) => running,
        // The client went away before sending a first request that starts a
        // session (for example a probe that sent `server/discover` and left).
        Err(ServerInitializeError::ConnectionClosed(stage)) => {
            tracing::debug!(%stage, "client closed the connection before the session started");
            return Ok(());
        }
        Err(e) => return Err(ServeError::Transport(e.to_string())),
    };
    let cancel = running.cancellation_token();
    let waiting = running.waiting();
    tokio::pin!(waiting);
    let outcome = tokio::select! {
        result = &mut waiting => Some(result),
        () = shutdown.cancelled() => None,
    };
    let result = match outcome {
        Some(result) => result,
        None => match tokio::time::timeout(EOF_GRACE, &mut waiting).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!("in-flight requests did not finish after stdin closed; cancelling");
                cancel.cancel();
                match tokio::time::timeout(CANCEL_GRACE, &mut waiting).await {
                    Ok(result) => result,
                    Err(_) => return Ok(()),
                }
            }
        },
    };
    shutdown.cancel();
    result
        .map(|reason| tracing::debug!(?reason, "mcp stdio server stopped"))
        .map_err(|e| ServeError::Transport(e.to_string()))
}
