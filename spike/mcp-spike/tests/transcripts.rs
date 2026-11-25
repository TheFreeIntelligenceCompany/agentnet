//! Raw JSON-RPC / HTTP transcripts written to results/a3-mcp/.
//! These tests do not use the rmcp client: every frame is hand-written.

mod common;

use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{atomic::Ordering, mpsc},
    time::{Duration, Instant},
};

use common::*;
use mcp_spike::INBOX_URI;
use serde_json::{Value, json};

fn results_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../results/a3-mcp");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Transcript {
    lines: Vec<String>,
    t0: Instant,
}

impl Transcript {
    fn new(title: &str) -> Self {
        Self {
            lines: vec![format!("# {title}")],
            t0: Instant::now(),
        }
    }
    fn note(&mut self, text: &str) {
        self.lines.push(format!("# {text}"));
    }
    fn push(&mut self, dir: &str, text: &str) {
        self.lines.push(format!(
            "[+{:>6}ms] {dir} {text}",
            self.t0.elapsed().as_millis()
        ));
    }
    fn save(&self, name: &str) {
        std::fs::write(results_dir().join(name), self.lines.join("\n") + "\n").unwrap();
    }
}

const META: &str = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"raw-stdio","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}"#;

fn modern(id: Value, method: &str, params_extra: &str) -> String {
    let extra = if params_extra.is_empty() {
        String::new()
    } else {
        format!(",{params_extra}")
    };
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{{META}{extra}}}}}"#)
}

struct RawStdio {
    child: Child,
    rx: mpsc::Receiver<String>,
    tr: Transcript,
    bad_stdout_lines: Vec<String>,
}

impl RawStdio {
    fn spawn(title: &str, stderr_file: &str) -> Self {
        let stderr = std::fs::File::create(results_dir().join(stderr_file)).unwrap();
        let mut child = Command::new(server_bin())
            .args(["--transport", "stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(l) => {
                        let _ = tx.send(l);
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            child,
            rx,
            tr: Transcript::new(title),
            bad_stdout_lines: vec![],
        }
    }

    fn send(&mut self, line: &str) {
        assert!(!line.contains('\n'));
        self.tr.push("->", line);
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    fn recv(&mut self, wait: Duration) -> Option<Value> {
        let line = self.rx.recv_timeout(wait).ok()?;
        self.tr.push("<-", &line);
        match serde_json::from_str::<Value>(&line) {
            Ok(v) => Some(v),
            Err(_) => {
                self.bad_stdout_lines.push(line);
                None
            }
        }
    }

    /// Read until a message with this id arrives (collecting everything else seen).
    fn recv_id(&mut self, id: i64) -> (Value, Vec<Value>) {
        let mut others = vec![];
        loop {
            let v = self
                .recv(Duration::from_secs(5))
                .unwrap_or_else(|| panic!("timeout waiting for id {id}"));
            if v.get("id") == Some(&json!(id)) {
                return (v, others);
            }
            others.push(v);
        }
    }

    fn quiet(&mut self, wait: Duration) -> Vec<Value> {
        let mut seen = vec![];
        while let Some(v) = self.recv(wait) {
            seen.push(v);
        }
        seen
    }

    fn finish(mut self, file: &str) {
        drop(self.child.stdin.take());
        let t = Instant::now();
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break format!("{s}");
            }
            if t.elapsed() > Duration::from_secs(10) {
                self.child.kill().unwrap();
                break "KILLED after 10s without exiting on stdin EOF".into();
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        self.tr.note(&format!(
            "stdin closed; server exit after {}ms: {status}",
            t.elapsed().as_millis()
        ));
        assert!(
            self.bad_stdout_lines.is_empty(),
            "non-JSON on stdout: {:?}",
            self.bad_stdout_lines
        );
        self.tr
            .note("every stdout line parsed as JSON (stdout carries protocol frames only)");
        self.tr.save(file);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_stdio_modern_2026_07_28() {
    tokio::task::spawn_blocking(|| {
        let mut s = RawStdio::spawn("stdio, protocol 2026-07-28 (no initialize)", "stdio-modern.server.stderr.log");
        s.send(&modern(json!(1), "server/discover", ""));
        let (r, _) = s.recv_id(1);
        assert_eq!(r["result"]["supportedVersions"].as_array().unwrap().last().unwrap(), "2026-07-28");
        assert!(r["result"]["ttlMs"].is_number());

        s.send(&modern(json!(2), "tools/call", r#""name":"echo_send","arguments":{"sender":"raw","body":"first"}"#));
        let (r, _) = s.recv_id(2);
        assert_eq!(r["result"]["structuredContent"]["seq"], 1);
        let cursor1 = r["result"]["structuredContent"]["cursor"].as_str().unwrap().to_string();

        s.send(&modern(json!(3), "subscriptions/listen", &format!(r#""notifications":{{"resourceSubscriptions":["{INBOX_URI}"]}}"#)));
        let ack = s.recv(Duration::from_secs(5)).unwrap();
        assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
        assert_eq!(ack["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], 3);

        s.send(&modern(json!(4), "tools/call", r#""name":"echo_send","arguments":{"sender":"raw","body":"second"}"#));
        let (r, others) = s.recv_id(4);
        assert_eq!(r["result"]["structuredContent"]["seq"], 2);
        let mut notes = others;
        if notes.is_empty() {
            notes = s.quiet(Duration::from_millis(500));
        }
        let n = notes
            .iter()
            .find(|v| v["method"] == "notifications/resources/updated")
            .expect("resources/updated");
        assert_eq!(n["params"]["uri"], INBOX_URI);
        assert_eq!(n["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], 3);

        s.tr.note("client cancels subscription 3 with notifications/cancelled");
        s.send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3,"reason":"raw test"}}"#);
        let after_cancel = s.quiet(Duration::from_millis(300));
        s.tr.note(&format!("frames received right after cancel: {}", after_cancel.len()));

        s.send(&modern(json!(5), "tools/call", r#""name":"echo_send","arguments":{"sender":"raw","body":"third (after cancel)"}"#));
        let (_r, others) = s.recv_id(5);
        let mut stray: Vec<_> = others;
        stray.extend(s.quiet(Duration::from_millis(500)));
        let n_updates = stray.iter().filter(|v| v["method"] == "notifications/resources/updated").count();
        s.tr.note(&format!("resources/updated notifications after cancel: {n_updates} (expected 0)"));
        assert_eq!(n_updates, 0);

        s.send(&modern(json!(6), "resources/read", &format!(r#""uri":"{INBOX_URI}?cursor={cursor1}&limit=10""#)));
        let (r, _) = s.recv_id(6);
        let page: Value = serde_json::from_str(r["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(page["records"].as_array().unwrap().len(), 2);
        assert_eq!(r["result"]["ttlMs"], 0);

        s.tr.note("request declaring an unsupported protocol version");
        s.send(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01","io.modelcontextprotocol/clientInfo":{"name":"raw","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}}}"#);
        let (r, _) = s.recv_id(7);
        assert_eq!(r["error"]["code"], -32022);

        s.tr.note("request without any _meta (neither initialize nor per-request metadata)");
        s.send(r#"{"jsonrpc":"2.0","id":8,"method":"tools/list"}"#);
        let (_r, _) = s.recv_id(8);

        s.tr.note("legacy initialize offering 2026-07-28 (which has no initialize)");
        s.send(r#"{"jsonrpc":"2.0","id":9,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}"#);
        let (r, _) = s.recv_id(9);
        assert_eq!(r["result"]["protocolVersion"], "2025-11-25");
        s.finish("transcript-stdio-modern.txt");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_stdio_legacy_versions() {
    tokio::task::spawn_blocking(|| {
        let mut all = Transcript::new("stdio, legacy `initialize` offers (one fresh server process per offer)");
        for offered in ["2025-11-25", "2025-06-18", "2024-11-05", "2025-03-26", "1900-01-01"] {
            let mut s = RawStdio::spawn(offered, &format!("stdio-legacy-{offered}.server.stderr.log"));
            s.tr.note(&format!("--- client offers protocolVersion {offered}"));
            s.send(&format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{offered}","capabilities":{{}},"clientInfo":{{"name":"raw-legacy","version":"0"}}}}}}"#
            ));
            let (r, _) = s.recv_id(1);
            let negotiated = r["result"]["protocolVersion"].as_str().unwrap().to_string();
            s.tr.note(&format!("server negotiated {negotiated}"));
            s.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
            if offered == "2025-11-25" {
                // Full legacy flow incl. resources/subscribe + notification + unsubscribe.
                s.send(&format!(r#"{{"jsonrpc":"2.0","id":2,"method":"resources/subscribe","params":{{"uri":"{INBOX_URI}"}}}}"#));
                s.recv_id(2);
                s.send(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo_send","arguments":{"sender":"legacy","body":"hello"}}}"#);
                let (r, mut others) = s.recv_id(3);
                assert!(r["result"]["structuredContent"]["seq"] == 1);
                if others.is_empty() {
                    others = s.quiet(Duration::from_millis(500));
                }
                assert!(others.iter().any(|v| v["method"] == "notifications/resources/updated"), "legacy notification missing: {others:?}");
                s.send(&format!(r#"{{"jsonrpc":"2.0","id":4,"method":"resources/unsubscribe","params":{{"uri":"{INBOX_URI}"}}}}"#));
                s.recv_id(4);
                s.send(r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo_send","arguments":{"sender":"legacy","body":"after unsubscribe"}}}"#);
                let (_r, mut others) = s.recv_id(5);
                others.extend(s.quiet(Duration::from_millis(500)));
                assert!(!others.iter().any(|v| v["method"] == "notifications/resources/updated"));
                s.tr.note("no resources/updated after resources/unsubscribe");
                s.send(&modern(json!(6), "subscriptions/listen", r#""notifications":{"resourceSubscriptions":["spike://inbox"]}"#));
                // A request carrying modern per-request `_meta` is served modern even on a
                // process that already ran `initialize` (dual-era, spec: versioning.mdx).
                let ack = s.recv(Duration::from_secs(5)).unwrap();
                assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
                s.send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":6}}"#);
            }
            let tr_lines = s.tr.lines.clone();
            s.finish(&format!("transcript-stdio-legacy-{offered}.txt"));
            all.lines.extend(tr_lines);
            all.lines.push(String::new());
        }
        all.save("transcript-stdio-legacy-all.txt");
    })
    .await
    .unwrap();
}

// ------------------------------------------------------------------ HTTP

struct Http {
    client: reqwest::Client,
    url: String,
    tr: Transcript,
}

impl Http {
    async fn post(
        &mut self,
        label: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> reqwest::Response {
        self.tr.note(label);
        let mut req = self.client.post(&self.url).body(body.to_string());
        let mut shown = String::from("POST /mcp");
        for (k, v) in headers {
            req = req.header(*k, *v);
            let v = if k.eq_ignore_ascii_case("authorization") {
                "Bearer <redacted>"
            } else {
                v
            };
            shown.push_str(&format!("\n      {k}: {v}"));
        }
        self.tr.push("->", &format!("{shown}\n      {body}"));
        let resp = req.send().await.unwrap();
        self.tr.push(
            "<-",
            &format!("HTTP {} {}", resp.status().as_u16(), headers_line(&resp)),
        );
        resp
    }

    async fn body(&mut self, resp: reqwest::Response) -> String {
        let text = resp.text().await.unwrap();
        self.tr.push("<-", &format!("body: {}", text.trim_end()));
        text
    }
}

fn headers_line(resp: &reqwest::Response) -> String {
    resp.headers()
        .iter()
        .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("?")))
        .collect::<Vec<_>>()
        .join("; ")
}

fn std_headers<'a>(
    auth: &'a str,
    method: &'a str,
    name: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut h = vec![
        ("Authorization", auth),
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", method),
    ];
    if let Some(n) = name {
        h.push(("Mcp-Name", n));
    }
    h
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_http_modern_and_legacy() {
    let server = HttpServer::start().await;
    let auth = format!("Bearer {TOKEN}");
    let mut h = Http {
        client: reqwest::Client::new(),
        url: server.url(),
        tr: Transcript::new("Streamable HTTP on 127.0.0.1 (bearer token redacted)"),
    };

    // --- modern
    let r = h
        .post(
            "modern: server/discover",
            &std_headers(&auth, "server/discover", None),
            &modern(json!(1), "server/discover", ""),
        )
        .await;
    assert_eq!(r.status(), 200);
    let t = h.body(r).await;
    assert!(t.contains("supportedVersions"));

    let r = h
        .post(
            "modern: tools/call",
            &std_headers(&auth, "tools/call", Some("echo_send")),
            &modern(
                json!(2),
                "tools/call",
                r#""name":"echo_send","arguments":{"sender":"raw","body":"first"}"#,
            ),
        )
        .await;
    assert_eq!(r.status(), 200);
    assert!(
        r.headers().get("mcp-session-id").is_none(),
        "modern response must not mint a session id"
    );
    h.body(r).await;

    // subscriptions/listen = long-lived POST response stream
    let mut listen = h
        .post(
            "modern: subscriptions/listen (response stream stays open)",
            &std_headers(&auth, "subscriptions/listen", None),
            &modern(
                json!(3),
                "subscriptions/listen",
                &format!(r#""notifications":{{"resourceSubscriptions":["{INBOX_URI}"]}}"#),
            ),
        )
        .await;
    assert_eq!(listen.status(), 200);
    let mut sse = String::new();
    let mut read_until = async |h: &mut Http, needle: &str, sse: &mut String| {
        let end = Instant::now() + Duration::from_secs(5);
        while !sse.contains(needle) {
            let left = end.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, listen.chunk()).await {
                Ok(Ok(Some(c))) => {
                    let s = String::from_utf8_lossy(&c).to_string();
                    h.tr.push(
                        "<-",
                        &format!("SSE chunk: {}", s.trim_end().replace('\n', "\\n")),
                    );
                    sse.push_str(&s);
                }
                other => panic!("stream ended/timeout before {needle:?}: {other:?}"),
            }
        }
    };
    read_until(&mut h, "notifications/subscriptions/acknowledged", &mut sse).await;
    wait_until(
        || server.shared.active_listeners.load(Ordering::SeqCst) == 1,
        "listener",
    )
    .await;

    let r = h
        .post(
            "modern: tools/call while listen stream is open",
            &std_headers(&auth, "tools/call", Some("echo_send")),
            &modern(
                json!(4),
                "tools/call",
                r#""name":"echo_send","arguments":{"sender":"raw","body":"second"}"#,
            ),
        )
        .await;
    h.body(r).await;
    read_until(&mut h, "notifications/resources/updated", &mut sse).await;
    assert!(sse.contains(&format!(r#""uri":"{INBOX_URI}""#)));

    h.tr.note("client closes the SSE response stream = cancellation");
    drop(listen);
    wait_until(
        || server.shared.active_listeners.load(Ordering::SeqCst) == 0,
        "server drops listener after stream close",
    )
    .await;
    h.tr.note("server-side active listeners now 0");

    let r = h
        .post(
            "modern: resources/read with cursor",
            &std_headers(&auth, "resources/read", Some("spike://inbox?limit=1")),
            &modern(
                json!(5),
                "resources/read",
                &format!(r#""uri":"{INBOX_URI}?limit=1""#),
            ),
        )
        .await;
    h.body(r).await;

    // --- negative cases
    let r = h
        .post(
            "negative: no Authorization",
            &[
                ("Content-Type", "application/json"),
                ("Accept", "application/json, text/event-stream"),
                ("MCP-Protocol-Version", "2026-07-28"),
                ("Mcp-Method", "tools/list"),
            ],
            &modern(json!(6), "tools/list", ""),
        )
        .await;
    assert_eq!(r.status(), 401);
    h.body(r).await;

    let mut hdrs = std_headers(&auth, "tools/list", None);
    hdrs.push(("Origin", "http://evil.example"));
    let r = h
        .post(
            "negative: valid token, Origin: http://evil.example",
            &hdrs,
            &modern(json!(7), "tools/list", ""),
        )
        .await;
    assert_eq!(r.status(), 403);
    h.body(r).await;

    let mut hdrs = std_headers(&auth, "tools/list", None);
    hdrs.push(("Host", "evil.example"));
    let r = h
        .post(
            "negative: valid token, Host: evil.example (DNS rebinding)",
            &hdrs,
            &modern(json!(8), "tools/list", ""),
        )
        .await;
    assert_eq!(r.status(), 403);
    h.body(r).await;

    let r = h
        .post(
            "negative: header/body mismatch (Mcp-Method: tools/list, body tools/call)",
            &std_headers(&auth, "tools/list", None),
            &modern(
                json!(9),
                "tools/call",
                r#""name":"echo_send","arguments":{"sender":"x","body":"y"}"#,
            ),
        )
        .await;
    let st = r.status().as_u16();
    h.body(r).await;
    h.tr.note(&format!(
        "=> status {st} (spec: 400 + HeaderMismatch -32020)"
    ));

    let hdrs: Vec<_> = std_headers(&auth, "tools/list", None)
        .into_iter()
        .filter(|(k, _)| *k != "MCP-Protocol-Version")
        .collect();
    let r = h
        .post(
            "negative: modern body but MCP-Protocol-Version header omitted",
            &hdrs,
            &modern(json!(10), "tools/list", ""),
        )
        .await;
    let st = r.status().as_u16();
    h.body(r).await;
    h.tr.note(&format!(
        "=> status {st} (spec: server MUST reject, or MAY treat as 2025-03-26)"
    ));

    let mut hdrs = std_headers(&auth, "tools/list", None);
    hdrs.retain(|(k, _)| *k != "MCP-Protocol-Version");
    hdrs.push(("MCP-Protocol-Version", "1900-01-01"));
    let r = h
        .post(
            "negative: unsupported version 1900-01-01 (header and body)",
            &hdrs,
            &modern(json!(11), "tools/list", "").replace("2026-07-28", "1900-01-01"),
        )
        .await;
    let st = r.status().as_u16();
    h.body(r).await;
    h.tr.note(&format!(
        "=> status {st} (spec: 400 + UnsupportedProtocolVersion -32022)"
    ));

    for (label, req) in [
        (
            "negative: GET /mcp without session (removed in 2026-07-28)",
            h.client.get(&h.url),
        ),
        (
            "negative: DELETE /mcp (removed in 2026-07-28)",
            h.client.delete(&h.url),
        ),
    ] {
        let resp = req
            .header("Authorization", &auth)
            .header("Accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        let line = format!("HTTP {} {}", resp.status().as_u16(), headers_line(&resp));
        h.tr.note(label);
        h.tr.push("<-", &line);
        let b = resp.text().await.unwrap();
        h.tr.push("<-", &format!("body: {b}"));
    }

    // --- legacy sessions (2025-11-25)
    h.tr.note("=== legacy client: 2025-11-25 initialize over Streamable HTTP (sessions) ===");
    let legacy_hdrs = |sid: Option<&str>| -> Vec<(String, String)> {
        let mut v = vec![
            ("Authorization".to_string(), auth.clone()),
            ("Content-Type".into(), "application/json".into()),
            (
                "Accept".into(),
                "application/json, text/event-stream".into(),
            ),
        ];
        if let Some(s) = sid {
            v.push(("Mcp-Session-Id".into(), s.into()));
            v.push(("MCP-Protocol-Version".into(), "2025-11-25".into()));
        }
        v
    };
    let post_legacy = async |h: &mut Http, label: &str, sid: Option<&str>, body: &str| {
        let hs = legacy_hdrs(sid);
        let refs: Vec<(&str, &str)> = hs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        h.post(label, &refs, body).await
    };
    let r = post_legacy(&mut h, "legacy: initialize", None, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw-legacy","version":"0"}}}"#).await;
    assert_eq!(r.status(), 200);
    let sid = r
        .headers()
        .get("mcp-session-id")
        .expect("legacy session id")
        .to_str()
        .unwrap()
        .to_string();
    h.body(r).await;
    let r = post_legacy(
        &mut h,
        "legacy: notifications/initialized",
        Some(&sid),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;
    assert_eq!(r.status(), 202);
    h.body(r).await;
    let r = post_legacy(&mut h, "legacy: resources/subscribe", Some(&sid), &format!(r#"{{"jsonrpc":"2.0","id":2,"method":"resources/subscribe","params":{{"uri":"{INBOX_URI}"}}}}"#)).await;
    h.body(r).await;
    // standalone GET stream (legacy server->client channel)
    h.tr.note("legacy: GET /mcp (standalone SSE stream, session-bound)");
    let mut get = h
        .client
        .get(&h.url)
        .header("Authorization", &auth)
        .header("Accept", "text/event-stream")
        .header("Mcp-Session-Id", &sid)
        .header("MCP-Protocol-Version", "2025-11-25")
        .send()
        .await
        .unwrap();
    h.tr.push(
        "<-",
        &format!("HTTP {} {}", get.status().as_u16(), headers_line(&get)),
    );
    assert_eq!(get.status(), 200);
    let r = post_legacy(&mut h, "legacy: tools/call", Some(&sid), r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo_send","arguments":{"sender":"legacy","body":"hello"}}}"#).await;
    h.body(r).await;
    let mut got = String::new();
    let end = Instant::now() + Duration::from_secs(5);
    while !got.contains("notifications/resources/updated") {
        let left = end.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, get.chunk()).await {
            Ok(Ok(Some(c))) => {
                let s = String::from_utf8_lossy(&c).to_string();
                h.tr.push(
                    "<-",
                    &format!("GET-stream chunk: {}", s.trim_end().replace('\n', "\\n")),
                );
                got.push_str(&s);
            }
            other => panic!("legacy GET stream gave no notification: {other:?}"),
        }
    }
    drop(get);
    let r = h
        .client
        .delete(&h.url)
        .header("Authorization", &auth)
        .header("Mcp-Session-Id", &sid)
        .header("MCP-Protocol-Version", "2025-11-25")
        .send()
        .await
        .unwrap();
    h.tr.note("legacy: DELETE session");
    h.tr.push("<-", &format!("HTTP {}", r.status().as_u16()));

    h.tr.save("transcript-http.txt");
    server.ct.cancel();
}

#[tokio::test(flavor = "multi_thread")]
async fn stdio_shutdown_with_active_listener() {
    // Measures how long the server takes to exit on stdin EOF when a subscriptions/listen is open.
    tokio::task::spawn_blocking(|| {
        let mut s = RawStdio::spawn(
            "stdio EOF with an active listen",
            "stdio-eof-active-listen.server.stderr.log",
        );
        s.send(&modern(
            json!(1),
            "subscriptions/listen",
            &format!(r#""notifications":{{"resourceSubscriptions":["{INBOX_URI}"]}}"#),
        ));
        let ack = s.recv(Duration::from_secs(5)).unwrap();
        assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
        s.finish("transcript-stdio-eof-active-listen.txt");
    })
    .await
    .unwrap();
}
