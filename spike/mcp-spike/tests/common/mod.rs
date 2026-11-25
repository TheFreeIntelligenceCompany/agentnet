#![allow(dead_code)]

use std::{process::Stdio, sync::Arc, time::Duration};

use mcp_spike::{EchoSendOutput, INBOX_URI, InboxPage, Shared, serve_http};
use rmcp::{
    ClientHandler, ClientLifecycleMode, ClientServiceExt, RoleClient,
    model::*,
    service::{NotificationContext, Peer, RunningService},
    transport::{
        ConfigureCommandExt, StreamableHttpClientTransport, TokioChildProcess,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio_util::sync::CancellationToken;

pub const TOKEN: &str = "spike-test-token-0123456789abcdef";

/// How the client opens the connection.
#[derive(Clone, Debug)]
pub enum Mode {
    /// 2026-07-28: `server/discover` + per-request `_meta`.
    Discover,
    /// `ClientLifecycleMode::Auto` (probe discover, fall back to initialize).
    Auto,
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
        config.client_info = Implementation::new("mcp-spike-test-client", "0.0.0");
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

fn collector(mode: &Mode) -> (Collector, UnboundedReceiver<String>, ClientLifecycleMode) {
    let (tx, rx) = unbounded_channel();
    let (version, lifecycle) = match mode {
        Mode::Discover => (
            None,
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        ),
        Mode::Auto => (
            None,
            ClientLifecycleMode::Auto {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                legacy_version: Some(ProtocolVersion::V_2025_11_25),
            },
        ),
        Mode::Initialize(v) => (Some(v.clone()), ClientLifecycleMode::Initialize),
    };
    (Collector { version, tx }, rx, lifecycle)
}

pub fn server_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mcp-spike-server")
}

pub async fn connect_stdio(mode: Mode) -> anyhow::Result<(Client, UnboundedReceiver<String>)> {
    let (handler, rx, lifecycle) = collector(&mode);
    let cmd = tokio::process::Command::new(server_bin()).configure(|c| {
        c.arg("--transport").arg("stdio");
    });
    let (transport, _stderr) = TokioChildProcess::builder(cmd)
        .stderr(Stdio::null())
        .spawn()?;
    let client = handler.serve_with_lifecycle(transport, lifecycle).await?;
    Ok((client, rx))
}

pub struct HttpServer {
    pub addr: std::net::SocketAddr,
    pub shared: Arc<Shared>,
    pub ct: CancellationToken,
}

impl HttpServer {
    pub async fn start() -> Self {
        Self::start_with(Shared::new()).await
    }

    pub async fn start_with(shared: Arc<Shared>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ct = CancellationToken::new();
        let (s, c) = (shared.clone(), ct.clone());
        tokio::spawn(async move {
            serve_http(listener, s, TOKEN, c).await.unwrap();
        });
        Self { addr, shared, ct }
    }

    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }

    pub async fn connect(&self, mode: Mode) -> anyhow::Result<(Client, UnboundedReceiver<String>)> {
        self.connect_with_token(mode, TOKEN).await
    }

    pub async fn connect_with_token(
        &self,
        mode: Mode,
        token: &str,
    ) -> anyhow::Result<(Client, UnboundedReceiver<String>)> {
        let (handler, rx, lifecycle) = collector(&mode);
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(self.url()).auth_header(token),
        );
        let client = handler.serve_with_lifecycle(transport, lifecycle).await?;
        Ok((client, rx))
    }
}

pub fn negotiated(client: &Client) -> String {
    client
        .peer_info()
        .map(|i| i.protocol_version.to_string())
        .unwrap_or_else(|| "<none>".into())
}

pub async fn echo(
    peer: &Peer<RoleClient>,
    sender: &str,
    body: &str,
) -> anyhow::Result<EchoSendOutput> {
    let args = serde_json::json!({"sender": sender, "body": body});
    let result = peer
        .call_tool(
            CallToolRequestParams::new("echo_send")
                .with_arguments(args.as_object().unwrap().clone()),
        )
        .await?;
    anyhow::ensure!(
        result.is_error != Some(true),
        "tool returned isError: {:?}",
        result.content
    );
    let structured = result
        .structured_content
        .ok_or_else(|| anyhow::anyhow!("no structuredContent"))?;
    Ok(serde_json::from_value(structured)?)
}

pub async fn read_inbox(
    peer: &Peer<RoleClient>,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> anyhow::Result<InboxPage> {
    let mut uri = INBOX_URI.to_string();
    let mut q = vec![];
    if let Some(c) = cursor {
        q.push(format!("cursor={c}"));
    }
    if let Some(l) = limit {
        q.push(format!("limit={l}"));
    }
    if !q.is_empty() {
        uri = format!("{uri}?{}", q.join("&"));
    }
    let result = peer
        .read_resource(ReadResourceRequestParams::new(uri))
        .await?;
    match result.contents.first() {
        Some(ResourceContents::TextResourceContents { text, .. }) => {
            Ok(serde_json::from_str(text)?)
        }
        other => anyhow::bail!("unexpected contents: {other:?}"),
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

/// Log helper: flushes immediately so `--nocapture` output is ordered.
#[macro_export]
macro_rules! log {
    ($($t:tt)*) => {{
        println!("[{}] {}", $crate::common::ts(), format!($($t)*));
    }};
}

pub fn ts() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    format!("{}.{:03}", d.as_secs(), d.subsec_millis())
}
