mod common;

use std::{sync::atomic::Ordering, time::Duration};

use common::*;
use mcp_spike::{INBOX_URI, Shared};
use rmcp::model::*;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(700);

fn inbox_filter() -> SubscriptionFilter {
    SubscriptionFilter::builder()
        .resource_subscription(INBOX_URI)
        .build()
}

// ---------------------------------------------------------------- (1) initialize / negotiation

#[tokio::test]
async fn t1_negotiated_versions_stdio_and_http() {
    let server = HttpServer::start().await;
    for (label, mode, expect) in [
        ("discover", Mode::Discover, "2026-07-28"),
        ("auto", Mode::Auto, "2026-07-28"),
        // `ClientConfig::default()` offers LATEST (2026-07-28) over `initialize`:
        (
            "initialize(default=LATEST)",
            Mode::Initialize(ProtocolVersion::LATEST),
            "2025-11-25",
        ),
    ] {
        let (c, _rx) = connect_stdio(mode.clone()).await.unwrap();
        let v = negotiated(&c);
        log!("T1 transport=stdio mode={label} negotiated={v}");
        assert_eq!(v, expect, "stdio {label}");
        c.cancel().await.unwrap();

        let (c, _rx) = server.connect(mode).await.unwrap();
        let v = negotiated(&c);
        log!("T1 transport=http  mode={label} negotiated={v}");
        assert_eq!(v, expect, "http {label}");
        c.cancel().await.unwrap();
    }
}

// ---------------------------------------------------------------- (2) tool over stdio

#[tokio::test]
async fn t2_tool_call_over_stdio() {
    let (c, _rx) = connect_stdio(Mode::Discover).await.unwrap();
    let tools = c.list_all_tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    log!(
        "T2 tool schema: {}",
        serde_json::to_string(&tools[0]).unwrap()
    );
    let out = echo(c.peer(), "alice", "hello over stdio").await.unwrap();
    log!("T2 echo_send -> {out:?}");
    assert_eq!(out.seq, 1);
    let page = read_inbox(c.peer(), None, None).await.unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].body, "hello over stdio");
    // Unknown tool and invalid args produce errors, not panics.
    let err = c
        .call_tool(CallToolRequestParams::new("nope"))
        .await
        .unwrap_err();
    log!("T2 unknown tool error: {err}");
    let res = c
        .call_tool(
            CallToolRequestParams::new("echo_send").with_arguments(
                serde_json::json!({"sender": 1})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await;
    log!("T2 bad args -> {res:?}");
    c.cancel().await.unwrap();
}

// ---------------------------------------------------------------- (3) tool over HTTP + auth

#[tokio::test]
async fn t3_tool_call_over_http_and_auth() {
    let server = HttpServer::start().await;
    let (c, _rx) = server.connect(Mode::Discover).await.unwrap();
    let out = echo(c.peer(), "bob", "hello over http").await.unwrap();
    log!("T3 echo_send over http -> {out:?}");
    assert_eq!(server.shared.len(), 1);
    c.cancel().await.unwrap();

    // rmcp client with wrong token / no token fails to start.
    let wrong = server
        .connect_with_token(Mode::Discover, "wrong-token-wrong-token")
        .await;
    log!(
        "T3 rmcp client wrong token -> {:?}",
        wrong.as_ref().err().map(|e| e.to_string())
    );
    assert!(wrong.is_err());
    let legacy_wrong = server
        .connect_with_token(Mode::Initialize(ProtocolVersion::V_2025_11_25), "")
        .await;
    log!(
        "T3 rmcp legacy client empty token -> {:?}",
        legacy_wrong.as_ref().err().map(|e| e.to_string())
    );
    assert!(legacy_wrong.is_err());

    // Raw HTTP: status codes.
    let http = reqwest::Client::new();
    let body = serde_json::json!({
        "jsonrpc":"2.0","id":1,"method":"server/discover",
        "params":{"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientInfo":{"name":"raw","version":"0"},
            "io.modelcontextprotocol/clientCapabilities":{}}}
    });
    let post = |auth: Option<&str>, origin: Option<&str>, host: Option<&str>| {
        let mut r = http
            .post(server.url())
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "server/discover")
            .json(&body);
        if let Some(a) = auth {
            r = r.header("Authorization", a);
        }
        if let Some(o) = origin {
            r = r.header("Origin", o);
        }
        if let Some(h) = host {
            r = r.header("Host", h);
        }
        r
    };
    let good = format!("Bearer {TOKEN}");
    #[allow(clippy::type_complexity)]
    let cases: [(&str, Option<&str>, Option<&str>, Option<&str>, u16); 6] = [
        ("no Authorization", None, None, None, 401),
        (
            "wrong token",
            Some("Bearer nope-nope-nope-nope"),
            None,
            None,
            401,
        ),
        ("Basic scheme", Some("Basic abc"), None, None, 401),
        ("valid token", Some(&good), None, None, 200),
        (
            "valid token + Origin: http://evil.example",
            Some(&good),
            Some("http://evil.example"),
            None,
            403,
        ),
        (
            "valid token + Host: evil.example",
            Some(&good),
            None,
            Some("evil.example"),
            403,
        ),
    ];
    for (name, auth, origin, host, expect) in cases {
        let resp = post(auth, origin, host).send().await.unwrap();
        let status = resp.status().as_u16();
        let www = resp
            .headers()
            .get("www-authenticate")
            .map(|v| v.to_str().unwrap().to_string());
        let text = resp.text().await.unwrap();
        log!(
            "T3 raw http [{name}] -> {status} www-authenticate={www:?} body={}",
            text.chars().take(200).collect::<String>()
        );
        assert_eq!(status, expect, "{name}");
    }
    server.ct.cancel();
}

// ---------------------------------------------------------------- (4) subscribe -> notify -> re-read

#[tokio::test]
async fn t4_subscribe_notify_reread_http_and_stdio() {
    for transport in ["http", "stdio"] {
        let server = HttpServer::start().await;
        let (c, _rx) = if transport == "http" {
            server.connect(Mode::Discover).await.unwrap()
        } else {
            connect_stdio(Mode::Discover).await.unwrap()
        };
        // Request two URIs; the server only honours spike://inbox.
        let filter = SubscriptionFilter::builder()
            .resource_subscription(INBOX_URI)
            .resource_subscription("spike://not-offered")
            .build();
        let mut sub = c.listen(filter).await.unwrap();
        log!(
            "T4 [{transport}] requested=[inbox, not-offered] acknowledged={:?}",
            sub.acknowledged()
        );
        assert_eq!(
            sub.acknowledged().resource_subscriptions.as_deref(),
            Some(&[INBOX_URI.to_string()][..])
        );

        let first = echo(c.peer(), "a", "one").await.unwrap();
        let n = timeout(WAIT, sub.next())
            .await
            .expect("no notification")
            .unwrap();
        log!("T4 [{transport}] notification after echo #1: {n:?}");
        assert!(matches!(
            n,
            Some(ServerNotification::ResourceUpdatedNotification(ref u)) if u.params.uri == INBOX_URI
        ));
        // Re-read from empty cursor, then incrementally from the saved cursor.
        let page = read_inbox(c.peer(), None, None).await.unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.cursor, first.cursor);
        echo(c.peer(), "a", "two").await.unwrap();
        echo(c.peer(), "a", "three").await.unwrap();
        // Notifications are hints: at least one arrives, but count is not guaranteed.
        let n2 = timeout(WAIT, sub.next())
            .await
            .expect("no 2nd notification")
            .unwrap();
        assert!(n2.is_some());
        let page2 = read_inbox(c.peer(), Some(&page.cursor), None)
            .await
            .unwrap();
        log!(
            "T4 [{transport}] re-read from cursor {} -> {:?}",
            page.cursor,
            page2
                .records
                .iter()
                .map(|r| r.body.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            page2
                .records
                .iter()
                .map(|r| r.body.as_str())
                .collect::<Vec<_>>(),
            ["two", "three"]
        );
        sub.cancel().await.unwrap();
        c.cancel().await.unwrap();
        server.ct.cancel();
    }
}

/// Legacy `resources/subscribe` over `initialize` (2025-11-25), stdio and HTTP (session mode).
#[tokio::test]
async fn t4b_legacy_resources_subscribe_and_unsubscribe() {
    let server = HttpServer::start().await;
    for transport in ["stdio", "http"] {
        let mode = Mode::Initialize(ProtocolVersion::V_2025_11_25);
        let (c, mut rx) = if transport == "http" {
            server.connect(mode).await.unwrap()
        } else {
            connect_stdio(mode).await.unwrap()
        };
        assert_eq!(negotiated(&c), "2025-11-25");
        #[allow(deprecated)]
        c.subscribe(SubscribeRequestParams::new(INBOX_URI))
            .await
            .unwrap();
        echo(c.peer(), "legacy", "x").await.unwrap();
        let uri = timeout(WAIT, rx.recv())
            .await
            .expect("no legacy notification")
            .unwrap();
        log!("T4b [{transport}] legacy notifications/resources/updated uri={uri}");
        assert_eq!(uri, INBOX_URI);
        // (5, legacy) unsubscribe -> no more.
        #[allow(deprecated)]
        c.unsubscribe(UnsubscribeRequestParams::new(INBOX_URI))
            .await
            .unwrap();
        echo(c.peer(), "legacy", "y").await.unwrap();
        let none = timeout(QUIET, rx.recv()).await;
        log!(
            "T4b [{transport}] after unsubscribe, notification within {QUIET:?}: {}",
            if none.is_err() {
                "none (pass)"
            } else {
                "RECEIVED (fail)"
            }
        );
        assert!(none.is_err());
        // And a 2026-style listen on a legacy session is rejected:
        let e = c.listen(inbox_filter()).await.err();
        log!(
            "T4b [{transport}] listen() on legacy-negotiated session -> {:?}",
            e.map(|e| e.to_string())
        );
        c.cancel().await.unwrap();
    }
    server.ct.cancel();
}

// ---------------------------------------------------------------- (5) cancel -> no more notifications

#[tokio::test]
async fn t5_cancel_stops_notifications() {
    let server = HttpServer::start().await;
    let (c, _rx) = server.connect(Mode::Discover).await.unwrap();
    let mut cancelled = c.listen(inbox_filter()).await.unwrap();
    let mut control = c.listen(inbox_filter()).await.unwrap();
    wait_until(
        || server.shared.active_listeners.load(Ordering::SeqCst) == 2,
        "2 listeners",
    )
    .await;
    echo(c.peer(), "x", "before cancel").await.unwrap();
    assert!(
        timeout(WAIT, cancelled.next())
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    assert!(
        timeout(WAIT, control.next())
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );

    cancelled.cancel().await.unwrap();
    wait_until(
        || server.shared.active_listeners.load(Ordering::SeqCst) == 1,
        "server to drop cancelled listener",
    )
    .await;
    log!(
        "T5 http: server-side active listeners after cancel = {}",
        server.shared.active_listeners.load(Ordering::SeqCst)
    );
    echo(c.peer(), "x", "after cancel").await.unwrap();
    // control still receives; cancelled does not.
    assert!(
        timeout(WAIT, control.next())
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    let after = cancelled.next().await.unwrap();
    log!(
        "T5 http: cancelled.next() = {after:?}, end={:?}",
        cancelled.end()
    );
    assert!(after.is_none());
    c.cancel().await.unwrap();
    server.ct.cancel();

    // stdio: same over one process (cancel = notifications/cancelled).
    let (c, _rx) = connect_stdio(Mode::Discover).await.unwrap();
    let mut cancelled = c.listen(inbox_filter()).await.unwrap();
    let mut control = c.listen(inbox_filter()).await.unwrap();
    echo(c.peer(), "x", "1").await.unwrap();
    assert!(
        timeout(WAIT, cancelled.next())
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    assert!(
        timeout(WAIT, control.next())
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    cancelled.cancel().await.unwrap();
    echo(c.peer(), "x", "2").await.unwrap();
    assert!(
        timeout(WAIT, control.next())
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    let after = timeout(QUIET, cancelled.next()).await;
    log!(
        "T5 stdio: cancelled.next() = {after:?}, end={:?}",
        cancelled.end()
    );
    assert!(matches!(after, Ok(Ok(None))));
    c.cancel().await.unwrap();
}

// ---------------------------------------------------------------- (6) disconnect / reconnect, lost notifications

#[tokio::test]
async fn t6_reconnect_loses_notifications_client_recovers_from_cursor() {
    let server = HttpServer::start().await;
    let (c1, _rx1) = server.connect(Mode::Discover).await.unwrap();
    let mut sub = c1.listen(inbox_filter()).await.unwrap();
    echo(c1.peer(), "writer", "m1").await.unwrap();
    assert!(timeout(WAIT, sub.next()).await.unwrap().unwrap().is_some());
    let page = read_inbox(c1.peer(), None, None).await.unwrap();
    let saved_cursor = page.cursor.clone();
    log!(
        "T6 client#1 consumed {} record(s); saved cursor {saved_cursor}",
        page.records.len()
    );

    // Disconnect client #1 (drops the listen stream).
    drop(sub);
    c1.cancel().await.unwrap();
    wait_until(
        || server.shared.active_listeners.load(Ordering::SeqCst) == 0,
        "listener teardown",
    )
    .await;

    // Gap: another client appends while nobody is subscribed.
    let (writer, _w) = server.connect(Mode::Discover).await.unwrap();
    for i in 2..=4 {
        echo(writer.peer(), "writer", &format!("m{i}"))
            .await
            .unwrap();
    }
    writer.cancel().await.unwrap();
    log!(
        "T6 3 records appended during the gap; active listeners = {}",
        server.shared.active_listeners.load(Ordering::SeqCst)
    );

    // Reconnect: new connection, new listen. No replay of the gap notifications.
    let (c2, _rx2) = server.connect(Mode::Discover).await.unwrap();
    let mut sub2 = c2.listen(inbox_filter()).await.unwrap();
    let replay = timeout(QUIET, sub2.next()).await;
    log!(
        "T6 after reconnect, notification replayed within {QUIET:?}: {}",
        if replay.is_err() {
            "NONE (gap notifications lost, as designed)"
        } else {
            "unexpected"
        }
    );
    assert!(replay.is_err());
    // Recover by reading from the saved cursor.
    let recovered = read_inbox(c2.peer(), Some(&saved_cursor), None)
        .await
        .unwrap();
    let bodies: Vec<_> = recovered.records.iter().map(|r| r.body.clone()).collect();
    log!("T6 recovered from cursor {saved_cursor}: {bodies:?}");
    assert_eq!(bodies, ["m2", "m3", "m4"]);
    // New appends flow again.
    echo(c2.peer(), "writer", "m5").await.unwrap();
    assert!(timeout(WAIT, sub2.next()).await.unwrap().unwrap().is_some());
    c2.cancel().await.unwrap();

    // Server restart => new epoch; the old cursor is rejected instead of silently wrong.
    let server2 = HttpServer::start_with(Shared::new()).await;
    let (c3, _rx3) = server2.connect(Mode::Discover).await.unwrap();
    let err = read_inbox(c3.peer(), Some(&saved_cursor), None)
        .await
        .unwrap_err();
    log!("T6 stale-epoch cursor against restarted server -> {err}");
    assert!(err.to_string().contains("different server epoch"));
    c3.cancel().await.unwrap();
    server.ct.cancel();
    server2.ct.cancel();
}

// ---------------------------------------------------------------- (7) pagination

#[tokio::test]
async fn t7_pagination_over_multiple_pages() {
    for transport in ["stdio", "http"] {
        let server = HttpServer::start().await;
        let (c, _rx) = if transport == "http" {
            server.connect(Mode::Discover).await.unwrap()
        } else {
            connect_stdio(Mode::Discover).await.unwrap()
        };
        for i in 1..=25 {
            echo(c.peer(), "p", &format!("msg-{i:02}")).await.unwrap();
        }
        let mut cursor: Option<String> = None;
        let mut seen = vec![];
        let mut pages = 0;
        loop {
            let page = read_inbox(c.peer(), cursor.as_deref(), Some(10))
                .await
                .unwrap();
            pages += 1;
            log!(
                "T7 [{transport}] page {pages}: {} records, next_cursor={:?}",
                page.records.len(),
                page.next_cursor
            );
            seen.extend(page.records.iter().map(|r| r.body.clone()));
            match page.next_cursor {
                Some(n) => cursor = Some(n),
                None => break,
            }
        }
        assert_eq!(pages, 3);
        let expected: Vec<String> = (1..=25).map(|i| format!("msg-{i:02}")).collect();
        assert_eq!(seen, expected);

        let templates = c.list_all_resource_templates().await.unwrap();
        log!(
            "T7 [{transport}] templates: {}",
            serde_json::to_string(&templates).unwrap()
        );
        let resources = c.list_all_resources().await.unwrap();
        log!(
            "T7 [{transport}] resources: {}",
            serde_json::to_string(&resources).unwrap()
        );
        for bad in [
            "spike://inbox?cursor=garbage",
            "spike://inbox?limit=0",
            "spike://other",
        ] {
            let e = c
                .read_resource(ReadResourceRequestParams::new(bad))
                .await
                .unwrap_err();
            log!("T7 [{transport}] read {bad} -> {e}");
        }
        c.cancel().await.unwrap();
        server.ct.cancel();
    }
}

// ---------------------------------------------------------------- (8) concurrency

#[tokio::test]
async fn t8_fifty_concurrent_tool_calls() {
    for transport in ["stdio", "http"] {
        let server = HttpServer::start().await;
        let (c, _rx) = if transport == "http" {
            server.connect(Mode::Discover).await.unwrap()
        } else {
            connect_stdio(Mode::Discover).await.unwrap()
        };
        let before = read_inbox(c.peer(), None, Some(1))
            .await
            .unwrap()
            .records
            .len();
        let start = std::time::Instant::now();
        let mut tasks = vec![];
        for i in 0..50 {
            let peer = c.peer().clone();
            tasks.push(tokio::spawn(async move {
                echo(&peer, &format!("w{i}"), &format!("concurrent-{i}")).await
            }));
        }
        let mut seqs = vec![];
        for t in tasks {
            seqs.push(t.await.unwrap().unwrap().seq);
        }
        seqs.sort();
        let elapsed = start.elapsed();
        let all = read_inbox(c.peer(), None, Some(100)).await.unwrap();
        log!(
            "T8 [{transport}] 50 concurrent calls ok in {elapsed:?}; inbox before={before} after={} seqs {}..={} unique={}",
            all.records.len(),
            seqs[0],
            seqs[49],
            {
                let mut s = seqs.clone();
                s.dedup();
                s.len()
            }
        );
        assert_eq!(all.records.len(), before + 50);
        let mut bodies: Vec<_> = all.records.iter().map(|r| r.body.clone()).collect();
        bodies.sort();
        bodies.dedup();
        assert_eq!(bodies.len(), 50);
        assert_eq!(seqs, (1..=50).collect::<Vec<u64>>());
        c.cancel().await.unwrap();
        server.ct.cancel();
    }
}

// ---------------------------------------------------------------- (9) legacy protocol versions

#[tokio::test]
async fn t9_legacy_versions_negotiation() {
    let server = HttpServer::start().await;
    for v in [
        ProtocolVersion::V_2025_11_25,
        ProtocolVersion::V_2025_06_18,
        ProtocolVersion::V_2025_03_26,
        ProtocolVersion::V_2024_11_05,
    ] {
        for transport in ["stdio", "http"] {
            let mode = Mode::Initialize(v.clone());
            let r = if transport == "http" {
                server.connect(mode).await
            } else {
                connect_stdio(mode).await
            };
            match r {
                Ok((c, _rx)) => {
                    let got = negotiated(&c);
                    let out = echo(c.peer(), "legacy", "hi").await;
                    log!(
                        "T9 offered={v} transport={transport} negotiated={got} tool_call_ok={}",
                        out.is_ok()
                    );
                    assert_eq!(got, v.to_string());
                    assert!(out.is_ok());
                    c.cancel().await.unwrap();
                }
                Err(e) => {
                    log!("T9 offered={v} transport={transport} FAILED: {e}");
                    panic!("legacy {v} over {transport} failed: {e}");
                }
            }
        }
    }
    server.ct.cancel();
}
