mod common;

use std::time::{Duration, Instant};

use agentnet_mcp::dto::SendMessageOutput;
use agentnet_mcp::{bind_http, http_router, serve_http, HttpOptions, ServeError};
use common::{
    fake_agent::{FakeAgent, BOB, ECHO_ADDRESS},
    HttpServer, Mode, RawStdio, *,
};
use rmcp::model::*;
use serde_json::{json, Value};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const LEGACY_VERSIONS: [ProtocolVersion; 4] = [
    ProtocolVersion::V_2025_11_25,
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_03_26,
    ProtocolVersion::V_2024_11_05,
];

macro_rules! log {
    ($($t:tt)*) => { println!($($t)*) };
}

// ---------------------------------------------------------------- version negotiation

#[tokio::test]
async fn stdio_version_negotiation_table() {
    let (c, _rx) = connect_stdio(Mode::Discover).await.unwrap();
    let v = negotiated(&c);
    log!("VERSION transport=stdio lifecycle=discover offered=2026-07-28 negotiated={v}");
    assert_eq!(v, "2026-07-28");
    let id: Value = call_ok(c.peer(), "get_identity", json!({})).await;
    assert!(id["agent_id"].is_string());
    c.cancel().await.unwrap();

    // `initialize` offering the newest version: server answers with the newest
    // handshake-era version.
    let (c, _rx) = connect_stdio(Mode::Initialize(ProtocolVersion::LATEST))
        .await
        .unwrap();
    let v = negotiated(&c);
    log!("VERSION transport=stdio lifecycle=initialize offered=2026-07-28 negotiated={v}");
    assert_eq!(v, "2025-11-25");
    c.cancel().await.unwrap();

    for offered in LEGACY_VERSIONS {
        let (c, _rx) = connect_stdio(Mode::Initialize(offered.clone()))
            .await
            .unwrap();
        let v = negotiated(&c);
        log!("VERSION transport=stdio lifecycle=initialize offered={offered} negotiated={v}");
        assert_eq!(v, offered.to_string());
        let out: Value = call_ok(c.peer(), "get_identity", json!({})).await;
        assert!(out["agent_id"].is_string(), "{offered}");
        assert_eq!(c.list_all_tools().await.unwrap().len(), 15, "{offered}");
        c.cancel().await.unwrap();
    }
}

#[tokio::test]
async fn http_version_negotiation_table() {
    let server = HttpServer::start().await;
    let (c, _rx) = server.connect(Mode::Discover).await.unwrap();
    let v = negotiated(&c);
    log!("VERSION transport=http lifecycle=discover offered=2026-07-28 negotiated={v}");
    assert_eq!(v, "2026-07-28");
    assert_eq!(c.list_all_tools().await.unwrap().len(), 15);
    c.cancel().await.unwrap();

    let (c, _rx) = server
        .connect(Mode::Initialize(ProtocolVersion::LATEST))
        .await
        .unwrap();
    let v = negotiated(&c);
    log!("VERSION transport=http lifecycle=initialize offered=2026-07-28 negotiated={v}");
    assert_eq!(v, "2025-11-25");
    c.cancel().await.unwrap();

    for offered in LEGACY_VERSIONS {
        let (c, _rx) = server
            .connect(Mode::Initialize(offered.clone()))
            .await
            .unwrap();
        let v = negotiated(&c);
        log!("VERSION transport=http lifecycle=initialize offered={offered} negotiated={v}");
        assert_eq!(v, offered.to_string());
        let out: Value = call_ok(c.peer(), "get_identity", json!({})).await;
        assert!(out["agent_id"].is_string(), "{offered}");
        c.cancel().await.unwrap();
    }
    server.shutdown.cancel();
}

#[tokio::test]
async fn stdio_raw_discover_and_unsupported_versions() {
    let mut p = RawStdio::spawn().await;
    p.send(modern_request(1, "server/discover", json!({})))
        .await;
    let r = p.recv().await;
    let result = &r["result"];
    log!("DISCOVER supportedVersions={}", result["supportedVersions"]);
    let supported: Vec<&str> = result["supportedVersions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        supported.contains(&"2026-07-28") && supported.contains(&"2024-11-05"),
        "{supported:?}"
    );
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "agentnet"
    );
    assert!(result["capabilities"]["tools"].is_object());
    assert!(result["instructions"]
        .as_str()
        .unwrap()
        .contains("UNTRUSTED"));

    // Unsupported protocol version in _meta -> -32022 UnsupportedProtocolVersion.
    let mut bad = modern_request(2, "tools/list", json!({}));
    bad["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("1900-01-01");
    p.send(bad).await;
    let r = p.recv().await;
    assert_eq!(r["error"]["code"], -32022, "{r}");

    // Missing _meta -> -32602.
    p.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}))
        .await;
    let r = p.recv().await;
    assert_eq!(r["error"]["code"], -32602, "{r}");
}

// ---------------------------------------------------------------- stdio process behaviour

#[tokio::test]
async fn stdio_stdout_carries_only_protocol_frames() {
    let mut p = RawStdio::spawn().await;
    let mut frames: Vec<Value> = Vec::new();

    p.send(modern_request(1, "server/discover", json!({})))
        .await;
    frames.push(p.recv().await);
    p.send(modern_request(2, "tools/list", json!({}))).await;
    frames.push(p.recv().await);
    p.send(modern_request(
        3,
        "tools/call",
        json!({"name": "get_identity", "arguments": {}}),
    ))
    .await;
    frames.push(p.recv().await);
    p.send(modern_request(
        4,
        "resources/read",
        json!({"uri": "agentnet://inbox"}),
    ))
    .await;
    frames.push(p.recv().await);
    p.send(modern_request(
        5,
        "resources/read",
        json!({"uri": "agentnet://bogus"}),
    ))
    .await;
    frames.push(p.recv().await);
    p.send(modern_request(
        6,
        "subscriptions/listen",
        json!({"notifications": {"resourceSubscriptions": ["agentnet://outbox"]}}),
    ))
    .await;
    let ack = p.recv().await;
    assert_eq!(
        ack["method"], "notifications/subscriptions/acknowledged",
        "{ack}"
    );
    frames.push(ack);
    p.send(modern_request(
        7,
        "tools/call",
        json!({"name": "send_message", "arguments": {"recipient": BOB, "body": "hi"}}),
    ))
    .await;
    // Response to 7 and the resources/updated notification arrive in either order.
    let a = p.recv().await;
    let b = p.recv().await;
    let methods: Vec<_> = [&a, &b]
        .iter()
        .map(|f| f["method"].as_str().unwrap_or("response").to_string())
        .collect();
    assert!(
        methods.contains(&"notifications/resources/updated".to_string()),
        "{methods:?}"
    );
    assert!(methods.contains(&"response".to_string()), "{methods:?}");
    frames.push(a);
    frames.push(b);
    // Protocol-level failure frames are also valid JSON-RPC on stdout.
    p.send(modern_request(8, "no/such/method", json!({}))).await;
    frames.push(p.recv().await);

    p.close_stdin();
    let status = timeout(Duration::from_secs(3), p.child.wait())
        .await
        .expect("exit")
        .unwrap();
    assert!(status.success(), "{status}");
    // Whatever else was written to stdout before exit (the server completes open
    // listen requests when shutting down) is also a protocol frame.
    while let Some(line) = timeout(Duration::from_secs(1), p.lines.next_line())
        .await
        .unwrap()
        .unwrap()
    {
        let v: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("non-JSON on stdout ({e}): {line:?}"));
        assert_eq!(v["jsonrpc"], "2.0", "{line}");
        frames.push(v);
    }

    for f in &frames {
        assert_eq!(f["jsonrpc"], "2.0");
        assert!(f.get("id").is_some() || f.get("method").is_some(), "{f}");
    }
    // Logs went to stderr (and are not protocol frames).
    let stderr = std::fs::read_to_string(&p.stderr_path).unwrap();
    assert!(stderr.contains("starting stdio server"), "stderr: {stderr}");
    assert!(
        !stderr
            .lines()
            .any(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| v["jsonrpc"] == "2.0")),
        "protocol frames leaked to stderr"
    );
}

#[tokio::test]
async fn stdio_exits_promptly_on_eof_with_an_active_listener() {
    let mut p = RawStdio::spawn().await;
    p.send(modern_request(1, "subscriptions/listen", json!({"notifications": {"resourceSubscriptions": ["agentnet://inbox", "agentnet://outbox"]}}))).await;
    let ack = p.recv().await;
    assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
    p.send(modern_request(
        2,
        "subscriptions/listen",
        json!({"notifications": {"resourceSubscriptions": ["agentnet://inbox"]}}),
    ))
    .await;
    let ack = p.recv().await;
    assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");

    let start = Instant::now();
    p.close_stdin();
    let status = timeout(Duration::from_millis(1500), p.child.wait())
        .await
        .expect("server did not exit within 1.5 s of stdin EOF with active listeners")
        .unwrap();
    let elapsed = start.elapsed();
    log!("STDIN-EOF exit with 2 active listeners: {elapsed:?} status={status}");
    assert!(status.success());
    assert!(elapsed < Duration::from_millis(1500));
}

#[tokio::test]
async fn stdio_exits_promptly_on_eof_without_listeners() {
    let mut p = RawStdio::spawn().await;
    p.send(modern_request(1, "server/discover", json!({})))
        .await;
    p.recv().await;
    let start = Instant::now();
    p.close_stdin();
    let status = timeout(Duration::from_millis(1500), p.child.wait())
        .await
        .expect("exit")
        .unwrap();
    log!("STDIN-EOF exit without listeners: {:?}", start.elapsed());
    assert!(status.success());
}

#[tokio::test]
async fn stdio_listen_and_legacy_subscribe_end_to_end() {
    // 2026-07-28 subscriptions/listen through the real process.
    let (c, _rx) = connect_stdio(Mode::Discover).await.unwrap();
    let mut sub = c.listen(sub_filter(&["agentnet://inbox"])).await.unwrap();
    // send_message emits Outbox + Conversation hints (not subscribed), then the
    // echo peer's reply persists and emits Inbox 50 ms later (subscribed).
    let sent: SendMessageOutput = call_ok(
        c.peer(),
        "send_message",
        json!({"recipient": ECHO_ADDRESS, "body": "ping", "conversation_id": "e2e"}),
    )
    .await;
    match timeout(WAIT, sub.next())
        .await
        .expect("no notification")
        .unwrap()
    {
        Some(ServerNotification::ResourceUpdatedNotification(n)) => {
            assert_eq!(n.params.uri, "agentnet://inbox")
        }
        other => panic!("{other:?}"),
    }
    let page = read_json(c.peer(), "agentnet://inbox").await.unwrap();
    assert_eq!(page["records"][0]["body"], "echo: ping");
    assert_eq!(page["records"][0]["conversation_id"], "e2e");
    assert_ne!(sent.message_id, "");
    // Cancel: no more notifications.
    sub.cancel().await.unwrap();
    call_ok::<SendMessageOutput>(
        c.peer(),
        "send_message",
        json!({"recipient": ECHO_ADDRESS, "body": "pong"}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(timeout(QUIET, sub.next())
        .await
        .is_ok_and(|r| matches!(r, Ok(None))));
    c.cancel().await.unwrap();

    // Legacy resources/subscribe through the real process.
    #[allow(deprecated)]
    {
        let (c, mut rx) = connect_stdio(Mode::Initialize(ProtocolVersion::V_2025_11_25))
            .await
            .unwrap();
        c.subscribe(SubscribeRequestParams::new("agentnet://inbox"))
            .await
            .unwrap();
        call_ok::<SendMessageOutput>(
            c.peer(),
            "send_message",
            json!({"recipient": ECHO_ADDRESS, "body": "legacy"}),
        )
        .await;
        assert_eq!(
            timeout(WAIT, rx.recv()).await.unwrap().unwrap(),
            "agentnet://inbox"
        );
        c.unsubscribe(UnsubscribeRequestParams::new("agentnet://inbox"))
            .await
            .unwrap();
        call_ok::<SendMessageOutput>(
            c.peer(),
            "send_message",
            json!({"recipient": ECHO_ADDRESS, "body": "legacy2"}),
        )
        .await;
        assert!(timeout(Duration::from_millis(400), rx.recv())
            .await
            .is_err());
        c.cancel().await.unwrap();
    }
}

#[tokio::test]
async fn stdio_seeded_pagination_through_the_process() {
    let (c, _rx) = connect_stdio_env(Mode::Discover, &[("FAKE_SEED_INBOX", "25")])
        .await
        .unwrap();
    let mut cursor: Option<String> = None;
    let mut seen = 0;
    let mut pages = 0;
    loop {
        let args = match &cursor {
            Some(cur) => json!({"limit": 10, "cursor": cur}),
            None => json!({"limit": 10}),
        };
        let page: Value = call_ok(c.peer(), "read_inbox", args).await;
        pages += 1;
        seen += page["records"].as_array().unwrap().len();
        if !page["has_more"].as_bool().unwrap() {
            break;
        }
        cursor = page["next_cursor"].as_str().map(str::to_string);
    }
    assert_eq!((pages, seen), (3, 25));
    c.cancel().await.unwrap();
}

// ---------------------------------------------------------------- concurrency

async fn fifty_concurrent_sends(peer: rmcp::service::Peer<rmcp::RoleClient>) {
    let start = Instant::now();
    let mut tasks = vec![];
    for i in 0..50 {
        let peer = peer.clone();
        tasks.push(tokio::spawn(async move {
            let out: SendMessageOutput = call_ok(
                &peer,
                "send_message",
                json!({"recipient": BOB, "body": format!("concurrent-{i}")}),
            )
            .await;
            out.message_id
        }));
    }
    let mut ids = vec![];
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    log!("CONCURRENT 50 send_message calls in {:?}", start.elapsed());
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 50, "message ids must be unique");
    let outbox = read_json(&peer, "agentnet://outbox?limit=200")
        .await
        .unwrap();
    let mut bodies: Vec<String> = outbox["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["body"].as_str().unwrap().to_string())
        .collect();
    bodies.sort();
    bodies.dedup();
    assert_eq!(bodies.len(), 50);
}

#[tokio::test]
async fn fifty_concurrent_tool_calls_over_stdio() {
    let (c, _rx) = connect_stdio(Mode::Discover).await.unwrap();
    fifty_concurrent_sends(c.peer().clone()).await;
    c.cancel().await.unwrap();
}

#[tokio::test]
async fn fifty_concurrent_tool_calls_over_http() {
    let server = HttpServer::start().await;
    let (c, _rx) = server.connect(Mode::Discover).await.unwrap();
    fifty_concurrent_sends(c.peer().clone()).await;
    c.cancel().await.unwrap();
    server.shutdown.cancel();
}

#[tokio::test]
async fn tools_and_resources_over_http() {
    let server = HttpServer::start().await;
    for mode in [
        Mode::Discover,
        Mode::Initialize(ProtocolVersion::V_2025_11_25),
    ] {
        let (c, _rx) = server.connect(mode).await.unwrap();
        let id: Value = call_ok(c.peer(), "get_identity", json!({})).await;
        assert!(id["agent_id"].is_string());
        server.agent.push_inbox(BOB, "over http", None);
        let page = read_json(c.peer(), "agentnet://inbox").await.unwrap();
        assert!(!page["records"].as_array().unwrap().is_empty());
        let err = c
            .read_resource(ReadResourceRequestParams::new("agentnet://nope"))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("-3260") || err.to_string().contains("-32002"),
            "{err}"
        );
        c.cancel().await.unwrap();
    }
    server.shutdown.cancel();
}

// ---------------------------------------------------------------- HTTP auth, Origin, Host

fn discover_body() -> Value {
    json!({
        "jsonrpc":"2.0","id":1,"method":"server/discover",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientInfo":{"name":"raw","version":"0"},
            "io.modelcontextprotocol/clientCapabilities":{}}}
    })
}

struct Probe {
    status: u16,
    www_authenticate: Option<String>,
    body: String,
}

async fn probe(url: &str, auth: Option<&str>, origin: Option<&str>, host: Option<&str>) -> Probe {
    let mut r = reqwest::Client::new()
        .post(url)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "server/discover")
        .json(&discover_body());
    if let Some(a) = auth {
        r = r.header("Authorization", a);
    }
    if let Some(o) = origin {
        r = r.header("Origin", o);
    }
    if let Some(h) = host {
        r = r.header("Host", h);
    }
    let resp = r.send().await.unwrap();
    Probe {
        status: resp.status().as_u16(),
        www_authenticate: resp
            .headers()
            .get("www-authenticate")
            .map(|v| v.to_str().unwrap().to_string()),
        body: resp.text().await.unwrap(),
    }
}

#[tokio::test]
async fn http_auth_origin_and_host_rules() {
    let server = HttpServer::start().await;
    let url = server.url();
    let good = format!("Bearer {TOKEN}");

    let p = probe(&url, None, None, None).await;
    log!(
        "HTTP no token -> {} www-authenticate={:?}",
        p.status,
        p.www_authenticate
    );
    assert_eq!(p.status, 401);
    assert_eq!(p.www_authenticate.as_deref(), Some("Bearer"));

    for (name, auth) in [
        ("wrong token", "Bearer wrong-wrong-wrong-wrong"),
        ("token prefix", &good[..good.len() - 1]),
        ("token plus suffix", &format!("{good}x")),
        ("Basic scheme", "Basic dXNlcjpwYXNz"),
        ("bare token", TOKEN),
        ("empty bearer", "Bearer "),
        ("bearer without value", "Bearer"),
    ] {
        let p = probe(&url, Some(auth), None, None).await;
        log!("HTTP {name} -> {}", p.status);
        assert_eq!(p.status, 401, "{name}");
        assert_eq!(p.www_authenticate.as_deref(), Some("Bearer"), "{name}");
        assert!(!p.body.contains(TOKEN));
    }

    let p = probe(&url, Some(&good), None, None).await;
    assert_eq!(p.status, 200, "{}", p.body);
    assert!(p.body.contains("supportedVersions"), "{}", p.body);
    // Scheme matching is case-insensitive (RFC 7235).
    assert_eq!(
        probe(&url, Some(&format!("bearer {TOKEN}")), None, None)
            .await
            .status,
        200
    );

    let p = probe(&url, Some(&good), Some("http://evil.example"), None).await;
    log!("HTTP bad Origin -> {} {}", p.status, p.body);
    assert_eq!(p.status, 403);
    let p = probe(&url, Some(&good), Some("null"), None).await;
    assert_eq!(p.status, 403, "Origin: null must be rejected");
    let p = probe(&url, Some(&good), None, Some("evil.example")).await;
    log!("HTTP bad Host -> {} {}", p.status, p.body);
    assert_eq!(p.status, 403);
    let p = probe(&url, Some(&good), None, Some("evil.example:8080")).await;
    assert_eq!(p.status, 403);
    // Loopback Host values (with port) are accepted.
    let p = probe(
        &url,
        Some(&good),
        None,
        Some(&format!("127.0.0.1:{}", server.addr.port())),
    )
    .await;
    assert_eq!(p.status, 200);
    let p = probe(
        &url,
        Some(&good),
        None,
        Some(&format!("localhost:{}", server.addr.port())),
    )
    .await;
    assert_eq!(p.status, 200);
    // Wrong token with a bad Origin: still refused (401 first).
    let p = probe(&url, Some("Bearer nope"), Some("http://evil.example"), None).await;
    assert!(matches!(p.status, 401 | 403));

    // rmcp client with the wrong token fails to connect.
    assert!(server
        .connect_with_token(Mode::Discover, "wrong-token-wrong-token")
        .await
        .is_err());
    assert!(server
        .connect_with_token(Mode::Initialize(ProtocolVersion::V_2025_11_25), "")
        .await
        .is_err());
    server.shutdown.cancel();
}

#[tokio::test]
async fn http_configured_origins_and_hosts_are_honoured() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let options = HttpOptions {
        bearer_token: TOKEN.into(),
        allowed_hosts: vec!["agentnet.internal".into(), "127.0.0.1".into()],
        allowed_origins: vec!["http://app.internal".into()],
    };
    let (a, s) = (FakeAgent::new(), shutdown.clone());
    let task = tokio::spawn(async move { serve_http(listener, a, options, false, s).await });
    let url = format!("http://{addr}/mcp");
    let good = format!("Bearer {TOKEN}");
    assert_eq!(
        probe(&url, Some(&good), Some("http://app.internal"), None)
            .await
            .status,
        200
    );
    assert_eq!(
        probe(&url, Some(&good), Some("http://other.internal"), None)
            .await
            .status,
        403
    );
    assert_eq!(
        probe(&url, Some(&good), None, Some("agentnet.internal"))
            .await
            .status,
        200
    );
    // `localhost` was not in the configured list, so it is now refused.
    assert_eq!(
        probe(&url, Some(&good), None, Some("localhost"))
            .await
            .status,
        403
    );
    shutdown.cancel();
    timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn router_fails_closed_with_an_unusable_token() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = http_router(FakeAgent::new(), HttpOptions::new("short"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    let url = format!("http://{addr}/mcp");
    for auth in ["Bearer short", "Bearer ", "Bearer"] {
        assert_eq!(
            probe(&url, Some(auth), None, None).await.status,
            401,
            "{auth}"
        );
    }
    assert_eq!(probe(&url, None, None, None).await.status, 401);
}

#[tokio::test]
async fn serve_http_refuses_unsafe_configuration() {
    // Weak token.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let r = serve_http(
        listener,
        FakeAgent::new(),
        HttpOptions::new("short"),
        false,
        CancellationToken::new(),
    )
    .await;
    assert!(
        matches!(r, Err(ServeError::Refused(ref m)) if m.contains("token")),
        "{r:?}"
    );

    // Non-loopback bind is refused by bind_http before anything is bound...
    for addr in ["0.0.0.0:0", "[::]:0", "192.168.1.10:0", "10.0.0.1:0"] {
        let r = bind_http(addr.parse().unwrap(), false).await;
        assert!(
            matches!(r, Err(ServeError::Refused(ref m)) if m.contains("non-loopback")),
            "{addr}: {r:?}"
        );
    }
    // ...and by serve_http for an already-bound listener.
    let wide = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let r = serve_http(
        wide,
        FakeAgent::new(),
        HttpOptions::new(TOKEN),
        false,
        CancellationToken::new(),
    )
    .await;
    assert!(
        matches!(r, Err(ServeError::Refused(ref m)) if m.contains("non-loopback")),
        "{r:?}"
    );

    // Loopback binds work; `allow_non_loopback` is an explicit opt-in.
    assert!(bind_http("127.0.0.1:0".parse().unwrap(), false)
        .await
        .is_ok());
    let _ = bind_http("[::1]:0".parse().unwrap(), false).await; // IPv6 may be unavailable
    let wide = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let stop = CancellationToken::new();
    stop.cancel();
    let r = serve_http(wide, FakeAgent::new(), HttpOptions::new(TOKEN), true, stop).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test]
async fn http_binary_refuses_non_loopback_and_serves_loopback() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    // Refusal at the process level.
    let out = tokio::process::Command::new(fake_server_path())
        .args(["http", "0.0.0.0:0"])
        .env("FAKE_TOKEN", TOKEN)
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "stdout must stay clean on refusal"
    );

    // Loopback works end to end.
    let mut child = tokio::process::Command::new(fake_server_path())
        .arg("http")
        .env("FAKE_TOKEN", TOKEN)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = timeout(WAIT, lines.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let addr = line.strip_prefix("LISTENING ").expect("LISTENING line");
    let url = format!("http://{addr}/mcp");
    assert_eq!(probe(&url, None, None, None).await.status, 401);
    assert_eq!(
        probe(&url, Some(&format!("Bearer {TOKEN}")), None, None)
            .await
            .status,
        200
    );
    child.start_kill().unwrap();
    let _ = child.wait().await;
}

#[test]
fn http_options_debug_redacts_the_token() {
    let shown = format!("{:?}", HttpOptions::new(TOKEN));
    assert!(!shown.contains(TOKEN), "{shown}");
}
