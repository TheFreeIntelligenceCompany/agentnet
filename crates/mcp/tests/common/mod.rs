#![allow(dead_code)]

pub mod fake_agent;

use std::{
    path::PathBuf,
    process::Stdio,
    sync::{Arc, OnceLock},
    time::Duration,
};

use agentnet_mcp::{serve_http, AgentNetMcp, HttpOptions};
use fake_agent::FakeAgent;
use rmcp::{
    model::*,
    service::{NotificationContext, Peer, RunningService, ServiceError},
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, ConfigureCommandExt,
        StreamableHttpClientTransport, TokioChildProcess,
    },
    ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient, ServiceExt,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;

pub const TOKEN: &str = "agentnet-test-token-0123456789abcdef";
pub const WAIT: Duration = Duration::from_secs(5);
pub const QUIET: Duration = Duration::from_millis(500);

/// How the client opens the connection.
#[derive(Clone, Debug)]
pub enum Mode {
    /// 2026-07-28: `server/discover` + per-request `_meta`.
    Discover,
    /// Legacy `initialize` offering exactly this protocol version.
    Initialize(ProtocolVersion),
}

/// Client handler that records legacy `notifications/resources/updated`.
#[derive(Clone)]
pub struct Collector {
    version: Option<ProtocolVersion>,
    tx: UnboundedSender<String>,
}

impl ClientHandler for Collector {
    fn get_info(&self) -> ClientConfig {
        let mut config = ClientConfig::default();
        if let Some(v) = &self.version {
            config.protocol_version = v.clone();
        }
        config.client_info = Implementation::new("agentnet-mcp-test-client", "0.0.0");
        config
    }

    async fn on_resource_updated(
        &self,
        params: ResourceUpdatedNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        let _ = self.tx.send(params.uri);
    }
}

pub type Client = RunningService<RoleClient, Collector>;
pub type Updates = UnboundedReceiver<String>;

fn collector(mode: &Mode) -> (Collector, Updates, ClientLifecycleMode) {
    let (tx, rx) = unbounded_channel();
    let (version, lifecycle) = match mode {
        Mode::Discover => (
            None,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        ),
        Mode::Initialize(v) => (Some(v.clone()), ClientLifecycleMode::Initialize),
    };
    (Collector { version, tx }, rx, lifecycle)
}

pub fn negotiated(client: &Client) -> String {
    client
        .peer_info()
        .map(|i| i.protocol_version.to_string())
        .unwrap_or_else(|| "<none>".into())
}

// ---------------------------------------------------------------- in-process (duplex)

pub struct Duplex {
    pub client: Client,
    pub updates: Updates,
    pub agent: Arc<FakeAgent>,
    pub mcp: AgentNetMcp,
    pub shutdown: CancellationToken,
}

impl Duplex {
    pub async fn start(mode: Mode) -> Self {
        Self::start_with(FakeAgent::new(), mode).await
    }

    pub async fn start_with(agent: Arc<FakeAgent>, mode: Mode) -> Self {
        let shutdown = CancellationToken::new();
        let mcp = AgentNetMcp::with_shutdown(agent.clone(), shutdown.clone());
        let (c, s) = tokio::io::duplex(1 << 20);
        let server = mcp.session();
        tokio::spawn(async move {
            if let Ok(running) = server.serve(s).await {
                let _ = running.waiting().await;
            }
        });
        let (handler, updates, lifecycle) = collector(&mode);
        let client = handler
            .serve_with_lifecycle(c, lifecycle)
            .await
            .expect("client handshake");
        Self {
            client,
            updates,
            agent,
            mcp,
            shutdown,
        }
    }

    pub fn peer(&self) -> &Peer<RoleClient> {
        self.client.peer()
    }
}

/// Like [`Duplex`] but served by the public `serve_io` entry point (the stdio
/// code path), so the EOF/shutdown behaviour of `serve_stdio` is exercised.
pub struct DuplexIo {
    pub client: Client,
    pub updates: Updates,
    pub agent: Arc<FakeAgent>,
    pub server: tokio::task::JoinHandle<Result<(), agentnet_mcp::ServeError>>,
}

impl DuplexIo {
    pub async fn start(agent: Arc<FakeAgent>, mode: Mode) -> Self {
        let (c, s) = tokio::io::duplex(1 << 20);
        let (sr, sw) = tokio::io::split(s);
        let a = agent.clone();
        let server = tokio::spawn(async move { agentnet_mcp::serve_io(a, sr, sw).await });
        let (handler, updates, lifecycle) = collector(&mode);
        let client = handler
            .serve_with_lifecycle(c, lifecycle)
            .await
            .expect("client handshake");
        Self {
            client,
            updates,
            agent,
            server,
        }
    }
}

// ---------------------------------------------------------------- HTTP (in-process server)

pub struct HttpServer {
    pub addr: std::net::SocketAddr,
    pub agent: Arc<FakeAgent>,
    pub shutdown: CancellationToken,
    pub task: tokio::task::JoinHandle<Result<(), agentnet_mcp::ServeError>>,
}

impl HttpServer {
    pub async fn start() -> Self {
        Self::start_with(FakeAgent::new()).await
    }

    pub async fn start_with(agent: Arc<FakeAgent>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let (a, s) = (agent.clone(), shutdown.clone());
        let task = tokio::spawn(async move {
            serve_http(listener, a, HttpOptions::new(TOKEN), false, s).await
        });
        Self {
            addr,
            agent,
            shutdown,
            task,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }

    pub async fn connect(&self, mode: Mode) -> anyhow::Result<(Client, Updates)> {
        self.connect_with_token(mode, TOKEN).await
    }

    pub async fn connect_with_token(
        &self,
        mode: Mode,
        token: &str,
    ) -> anyhow::Result<(Client, Updates)> {
        let (handler, rx, lifecycle) = collector(&mode);
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(self.url()).auth_header(token),
        );
        let client = handler.serve_with_lifecycle(transport, lifecycle).await?;
        Ok((client, rx))
    }
}

// ---------------------------------------------------------------- stdio child process

/// Path of the compiled `fake_server` example, (re)built if needed.
pub fn fake_server_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let exe = std::env::current_exe().expect("current_exe");
        // target/<profile>/deps/<test-binary>  ->  target/<profile>/examples/fake_server
        let profile_dir = exe.parent().and_then(|p| p.parent()).expect("profile dir");
        let path = profile_dir.join("examples").join(if cfg!(windows) {
            "fake_server.exe"
        } else {
            "fake_server"
        });
        // `cargo test --test x` does not rebuild examples: always make sure the
        // example matches the library (a no-op when it is already fresh).
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = std::process::Command::new(cargo)
            .args(["build", "-p", "agentnet-mcp", "--example", "fake_server"])
            .status()
            .expect("run cargo build --example fake_server");
        assert!(status.success(), "building fake_server example failed");
        assert!(path.exists(), "fake_server not found at {path:?}");
        path
    })
    .clone()
}

/// `fake_server stdio` as an rmcp client transport. stderr is discarded.
pub async fn connect_stdio(mode: Mode) -> anyhow::Result<(Client, Updates)> {
    connect_stdio_env(mode, &[]).await
}

pub async fn connect_stdio_env(
    mode: Mode,
    env: &[(&str, &str)],
) -> anyhow::Result<(Client, Updates)> {
    let (handler, rx, lifecycle) = collector(&mode);
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let cmd = tokio::process::Command::new(fake_server_path()).configure(move |c| {
        c.arg("stdio");
        for (k, v) in &env {
            c.env(k, v);
        }
    });
    let (transport, _stderr) = TokioChildProcess::builder(cmd)
        .stderr(Stdio::null())
        .spawn()?;
    let client = handler.serve_with_lifecycle(transport, lifecycle).await?;
    Ok((client, rx))
}

/// A raw child process speaking newline-delimited JSON-RPC.
pub struct RawStdio {
    pub child: tokio::process::Child,
    pub stdin: Option<tokio::process::ChildStdin>,
    pub lines: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
    pub stderr_path: PathBuf,
}

impl RawStdio {
    pub async fn spawn() -> Self {
        let stderr_path = std::env::temp_dir().join(format!(
            "agentnet-mcp-stderr-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let stderr = std::fs::File::create(&stderr_path).unwrap();
        let mut child = tokio::process::Command::new(fake_server_path())
            .arg("stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()
            .expect("spawn fake_server");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(stdout));
        Self {
            child,
            stdin,
            lines,
            stderr_path,
        }
    }

    pub async fn send(&mut self, value: Value) {
        use tokio::io::AsyncWriteExt;
        let stdin = self.stdin.as_mut().expect("stdin open");
        let mut line = value.to_string();
        line.push('\n');
        stdin.write_all(line.as_bytes()).await.unwrap();
        stdin.flush().await.unwrap();
    }

    /// Next stdout line parsed as JSON; asserts it is a JSON-RPC 2.0 frame.
    pub async fn recv(&mut self) -> Value {
        let line = tokio::time::timeout(WAIT, self.lines.next_line())
            .await
            .expect("timed out waiting for stdout line")
            .expect("read stdout")
            .expect("stdout closed");
        let v: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line:?}"));
        assert_eq!(v["jsonrpc"], "2.0", "not a JSON-RPC frame: {line}");
        v
    }

    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }
}

impl Drop for RawStdio {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.stderr_path);
    }
}

/// Modern (2026-07-28) request frame.
pub fn modern_request(id: u64, method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "raw", "version": "0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

// ---------------------------------------------------------------- tool helpers

pub async fn call(
    peer: &Peer<RoleClient>,
    name: &str,
    args: Value,
) -> Result<CallToolResult, ServiceError> {
    let mut params = CallToolRequestParams::new(name.to_string());
    if let Some(obj) = args.as_object() {
        params = params.with_arguments(obj.clone());
    }
    peer.call_tool(params).await
}

/// Call a tool and require a successful structured result.
pub async fn call_ok<T: DeserializeOwned>(peer: &Peer<RoleClient>, name: &str, args: Value) -> T {
    let result = call(peer, name, args).await.expect("protocol error");
    assert_ne!(
        result.is_error,
        Some(true),
        "tool error: {:?}",
        result.content
    );
    serde_json::from_value(result.structured_content.expect("structuredContent"))
        .expect("structured output deserializes")
}

/// First text block of a result, parsed as JSON.
pub fn text_json(result: &CallToolResult) -> Value {
    let block = serde_json::to_value(&result.content[0]).unwrap();
    assert_eq!(block["type"], "text");
    serde_json::from_str(block["text"].as_str().unwrap()).unwrap_or(Value::Null)
}

/// Assert `result` is an `isError: true` tool result and return `error.code`.
pub fn error_code(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "expected isError: {result:?}");
    let v = text_json(result);
    v["error"]["code"].as_str().expect("error.code").to_string()
}

pub async fn read_json(peer: &Peer<RoleClient>, uri: &str) -> Result<Value, ServiceError> {
    let result = peer
        .read_resource(ReadResourceRequestParams::new(uri.to_string()))
        .await?;
    match result.contents.first() {
        Some(ResourceContents::TextResourceContents { text, .. }) => {
            Ok(serde_json::from_str(text).expect("resource is JSON"))
        }
        other => panic!("unexpected resource contents: {other:?}"),
    }
}

pub async fn wait_until(mut f: impl FnMut() -> bool, what: &str) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

pub fn sub_filter(uris: &[&str]) -> SubscriptionFilter {
    SubscriptionFilter::builder()
        .resource_subscriptions(uris.iter().map(|u| u.to_string()))
        .build()
}
