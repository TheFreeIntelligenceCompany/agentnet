//! Wiring: lock, identity, engine, control socket, webhook, HTTP MCP, shutdown.

use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentnet_core::api::AgentApi;
use agentnet_core::identity::Identity;
use agentnet_core::{Clock, Node, NodeOptions, SystemClock};
use agentnet_mcp::{bind_http, serve_http, HttpOptions};
use agentnet_transport::logos_rest::LogosRestTransport;
use agentnet_transport::waku_native::NativeWakuTransport;
use agentnet_transport::Transport;
use serde_json::{json, Value};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{DaemonConfig, TransportBackend};
use crate::datadir::{ensure_token, read_secret_file, DataDir, DataDirLock, MAX_SOCKET_PATH};
use crate::error::DaemonError;
use crate::server::{self, ServerCtx, StatusFn, HELLO_TIMEOUT};
use crate::webhook::{Webhook, WebhookStats};

/// Upper bound of a graceful shutdown.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Entry points to start the daemon.
pub struct Daemon;

impl Daemon {
    /// Start the daemon of `data_dir`: lock, load `agentnet.toml` and the
    /// identity, build the configured transport (`logos_rest` or `native`),
    /// open the engine and the sockets.
    pub async fn start(data_dir: impl AsRef<Path>) -> Result<RunningDaemon, DaemonError> {
        let dir = DataDir::new(data_dir.as_ref());
        dir.check_dir_perms()?;
        let lock = dir.acquire_lock()?;
        let config = DaemonConfig::load(&dir.config())?;
        let transport: Arc<dyn Transport> = match config.network.backend {
            TransportBackend::LogosRest => Arc::new(
                LogosRestTransport::new(config.to_logos_config())
                    .map_err(|e| DaemonError::Transport(e.to_string()))?,
            ),
            TransportBackend::Native => {
                let node_key_hex = match &config.network.node_key_file {
                    Some(rel) => {
                        let p = Path::new(rel);
                        let resolved = if p.is_absolute() {
                            p.to_path_buf()
                        } else {
                            dir.root().join(p)
                        };
                        let bytes = read_secret_file(&resolved)?;
                        let s = String::from_utf8(bytes).map_err(|_| {
                            DaemonError::Config("network.node_key_file is not valid UTF-8".into())
                        })?;
                        Some(s.trim().to_owned())
                    }
                    None => None,
                };
                Arc::new(
                    NativeWakuTransport::start(config.to_native_config(node_key_hex))
                        .map_err(|e| DaemonError::Transport(e.to_string()))?,
                )
            }
        };
        start_locked(dir, lock, config, transport, Arc::new(SystemClock)).await
    }

    /// Start with an injected transport and clock (tests, embedding). The
    /// configuration is still validated in full.
    pub async fn start_with_transport(
        data_dir: impl AsRef<Path>,
        config: DaemonConfig,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
    ) -> Result<RunningDaemon, DaemonError> {
        let dir = DataDir::new(data_dir.as_ref());
        dir.check_dir_perms()?;
        let lock = dir.acquire_lock()?;
        config.validate()?;
        start_locked(dir, lock, config, transport, clock).await
    }
}

/// Asks a running daemon to shut down (the owner of [`RunningDaemon`] performs it).
#[derive(Clone, Debug)]
pub struct ShutdownHandle(CancellationToken);

impl ShutdownHandle {
    /// Request shutdown. Idempotent.
    pub fn shutdown(&self) {
        self.0.cancel();
    }
}

/// A started daemon. Dropping it without [`RunningDaemon::shutdown`] behaves
/// like a crash: tasks are aborted, the lock is released, the socket file stays
/// behind (the next start removes it while holding the lock).
pub struct RunningDaemon {
    dir: DataDir,
    config: DaemonConfig,
    node: Arc<Node>,
    lock: Option<DataDirLock>,
    stop: CancellationToken,
    node_cancel: CancellationToken,
    shutdown_request: CancellationToken,
    node_task: Option<JoinHandle<()>>,
    tasks: Vec<JoinHandle<()>>,
    http_addr: Option<SocketAddr>,
    webhook: Option<Arc<Webhook>>,
    finished: bool,
}

fn restrict(path: &Path) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

fn prepare_socket(path: &Path) -> Result<UnixListener, DaemonError> {
    if path.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(DaemonError::DataDir(format!(
            "socket path {} is too long for a Unix socket ({} bytes max); use a shorter --data-dir",
            path.display(),
            MAX_SOCKET_PATH
        )));
    }
    // We hold the data-dir lock, so any existing socket is stale.
    match std::fs::symlink_metadata(path) {
        Ok(md) => {
            if !md.file_type().is_socket() {
                return Err(DaemonError::DataDir(format!(
                    "{} exists and is not a socket; refusing to remove it",
                    path.display()
                )));
            }
            std::fs::remove_file(path)
                .map_err(|e| DaemonError::io(format!("removing stale {}", path.display()), e))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(DaemonError::io(format!("checking {}", path.display()), e)),
    }
    // Bind under a short sibling temporary name (shorter than `agentnet.sock`
    // so paths near `MAX_SOCKET_PATH` never overflow `sun_path`), restrict it,
    // then rename it into place so `agentnet.sock` never exists with the
    // umask-derived mode. Safe without a PID suffix because we hold `DataDirLock`.
    let tmp = path
        .parent()
        .map(|p| p.join(".s.tmp"))
        .unwrap_or_else(|| PathBuf::from(".s.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp)
        .map_err(|e| DaemonError::io(format!("binding {}", tmp.display()), e))?;
    let finish = || -> Result<(), DaemonError> {
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| DaemonError::io(format!("chmod {}", tmp.display()), e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| DaemonError::io(format!("renaming into {}", path.display()), e))
    };
    if let Err(e) = finish() {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(listener)
}

async fn start_locked(
    dir: DataDir,
    lock: DataDirLock,
    config: DaemonConfig,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
) -> Result<RunningDaemon, DaemonError> {
    let identity =
        Identity::load(&dir.identity()).map_err(|e| DaemonError::Identity(e.to_string()))?;
    // A revoked identity carries its signed tombstone next to the identity file.
    let local_revocation = match std::fs::read_to_string(dir.revocation()) {
        Ok(doc) => Some(doc),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(DaemonError::io(
                format!("reading {}", dir.revocation().display()),
                e,
            ))
        }
    };
    if local_revocation.is_some() {
        tracing::warn!(
            "this identity has been REVOKED: it will only deliver its revocation notice"
        );
    }
    let node = Node::open_with(
        identity,
        &dir.db(),
        transport,
        config.to_node_config(),
        clock.clone(),
        NodeOptions {
            local_revocation,
            ..Default::default()
        },
    )?;
    for suffix in ["", "-wal", "-shm"] {
        let mut p = dir.db().into_os_string();
        p.push(suffix);
        restrict(&PathBuf::from(p));
    }
    let token = ensure_token(&dir.control_token())?;

    // Everything that can fail is set up before any task is spawned.
    let webhook = if config.webhook.enabled {
        let w = Webhook::prepare(&config.webhook, &dir, clock.clone())?;
        w.init_cursor(&node).await?;
        Some(Arc::new(w))
    } else {
        None
    };
    let mut http = None;
    if config.mcp_http.enabled {
        let addr: SocketAddr = config
            .mcp_http
            .bind
            .parse()
            .map_err(|_| DaemonError::McpHttp("invalid bind address".into()))?;
        let bearer = ensure_token(&dir.mcp_token())?;
        let l = bind_http(addr, false)
            .await
            .map_err(|e| DaemonError::McpHttp(e.to_string()))?;
        let local = l
            .local_addr()
            .map_err(|e| DaemonError::io("mcp_http local_addr", e))?;
        http = Some((l, local, bearer));
    }
    let listener = prepare_socket(&dir.socket())?;

    let stop = CancellationToken::new();
    let node_cancel = CancellationToken::new();
    let shutdown_request = CancellationToken::new();
    let started = Instant::now();
    let http_addr = http.as_ref().map(|(_, a, _)| *a);

    let status: StatusFn = {
        let node = node.clone();
        let webhook = webhook.clone();
        let mode = config.network.mode.as_str();
        let backend = config.network.backend.as_str();
        Arc::new(move || -> Value {
            let wh: WebhookStats = webhook.as_ref().map(|w| w.stats()).unwrap_or_default();
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "protocol": crate::proto::PROTOCOL_VERSION,
                "agent_id": node.address(),
                "mode": mode,
                "backend": backend,
                "uptime_s": started.elapsed().as_secs(),
                "mcp_http": {"enabled": http_addr.is_some(), "addr": http_addr.map(|a| a.to_string())},
                "webhook": wh,
            })
        })
    };

    let mut tasks = Vec::new();
    let n = node.clone();
    let nc = node_cancel.clone();
    let node_task = tokio::spawn(async move { n.run(nc).await });
    let ctx = ServerCtx {
        node: node.clone(),
        token: Arc::new(token.trim().as_bytes().to_vec()),
        stop: stop.clone(),
        shutdown_request: shutdown_request.clone(),
        status,
        hello_timeout: HELLO_TIMEOUT,
    };
    tasks.push(tokio::spawn(server::serve(listener, ctx)));
    if let Some(w) = &webhook {
        tasks.push(tokio::spawn(
            w.clone().run(node.clone(), stop.child_token()),
        ));
    }
    if let Some((l, _, bearer)) = http {
        let api: Arc<dyn AgentApi> = node.clone();
        let sd = stop.child_token();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = serve_http(l, api, HttpOptions::new(bearer), false, sd).await {
                tracing::error!(error = %e, "http mcp server stopped");
            }
        }));
    }
    tracing::info!(agent = %node.address(), socket = %dir.socket().display(), "agentnet daemon started");
    Ok(RunningDaemon {
        dir,
        config,
        node,
        lock: Some(lock),
        stop,
        node_cancel,
        shutdown_request,
        node_task: Some(node_task),
        tasks,
        http_addr,
        webhook,
        finished: false,
    })
}

impl RunningDaemon {
    /// The engine (also usable directly, in-process).
    pub fn node(&self) -> &Arc<Node> {
        &self.node
    }
    /// The engine as the API trait object.
    pub fn api(&self) -> Arc<dyn AgentApi> {
        self.node.clone()
    }
    /// The effective configuration.
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }
    /// The data directory.
    pub fn data_dir(&self) -> &DataDir {
        &self.dir
    }
    /// Path of the control socket.
    pub fn socket_path(&self) -> PathBuf {
        self.dir.socket()
    }
    /// Bound address of the HTTP MCP endpoint, if enabled.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }
    /// Webhook counters, if the webhook is enabled.
    pub fn webhook_stats(&self) -> Option<WebhookStats> {
        self.webhook.as_ref().map(|w| w.stats())
    }
    /// A handle that requests shutdown (also triggered by the `shutdown` method).
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle(self.shutdown_request.clone())
    }

    /// Resolves when shutdown was requested through a handle or the socket.
    pub async fn shutdown_requested(&self) {
        self.shutdown_request.cancelled().await;
    }

    /// Wait for SIGINT, SIGTERM or a shutdown request, then shut down.
    pub async fn run_until_signal(self) -> Result<(), DaemonError> {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())
            .map_err(|e| DaemonError::io("installing SIGTERM handler", e))?;
        let mut int = signal(SignalKind::interrupt())
            .map_err(|e| DaemonError::io("installing SIGINT handler", e))?;
        tokio::select! {
            _ = term.recv() => tracing::info!("SIGTERM received"),
            _ = int.recv() => tracing::info!("SIGINT received"),
            _ = self.shutdown_request.cancelled() => tracing::info!("shutdown requested"),
        }
        self.shutdown().await;
        Ok(())
    }

    /// Graceful shutdown: stop accepting, end connections, stop the engine
    /// (checkpoints and closes the store), remove the socket, release the lock.
    /// Bounded by [`SHUTDOWN_TIMEOUT`]; stragglers are aborted.
    pub async fn shutdown(mut self) {
        self.stop.cancel();
        let half = SHUTDOWN_TIMEOUT / 2;
        let tasks_deadline = tokio::time::Instant::now() + half;
        for mut t in std::mem::take(&mut self.tasks) {
            if tokio::time::timeout_at(tasks_deadline, &mut t)
                .await
                .is_err()
            {
                tracing::warn!("a daemon task did not stop in time; aborting it");
                t.abort();
                let _ = tokio::time::timeout(Duration::from_millis(200), t).await;
            }
        }
        self.node_cancel.cancel();
        if let Some(mut t) = self.node_task.take() {
            if tokio::time::timeout(half, &mut t).await.is_err() {
                tracing::warn!("the engine did not stop in time; aborting it");
                t.abort();
                let _ = tokio::time::timeout(Duration::from_millis(200), t).await;
            }
        }
        self.node.close();
        let _ = std::fs::remove_file(self.dir.socket());
        self.lock.take();
        self.finished = true;
        tracing::info!("agentnet daemon stopped");
    }
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.stop.cancel();
        self.node_cancel.cancel();
        for t in &self.tasks {
            t.abort();
        }
        if let Some(t) = &self.node_task {
            t.abort();
        }
        // `lock` is released when the field drops; the socket file is left
        // behind exactly as after a crash.
    }
}
