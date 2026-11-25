//! Adapter tests against a tiny hand-rolled local HTTP stub (no network).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::FrameSource;

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    body: Vec<u8>,
}

struct Reply {
    status: u16,
    body: String,
    delay: Duration,
}

fn ok(body: &str) -> Reply {
    Reply {
        status: 200,
        body: body.into(),
        delay: Duration::ZERO,
    }
}
fn status(status: u16, body: &str) -> Reply {
    Reply {
        status,
        body: body.into(),
        delay: Duration::ZERO,
    }
}

struct Stub {
    url: String,
    hits: Arc<Mutex<Vec<Req>>>,
}

impl Stub {
    fn hits(&self) -> Vec<Req> {
        self.hits.lock().unwrap().clone()
    }
    fn count(&self, prefix: &str) -> usize {
        self.hits()
            .iter()
            .filter(|r| r.path.starts_with(prefix))
            .count()
    }
}

async fn spawn_stub(handler: impl Fn(&Req) -> Reply + Send + Sync + 'static) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(Mutex::new(Vec::new()));
    let h2 = hits.clone();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let hits = h2.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let mut lines = head.lines();
                let first = lines.next().unwrap_or("").to_string();
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();
                let clen = lines
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while buf.len() < header_end + clen {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let req = Req {
                    method,
                    path,
                    body: buf[header_end..].to_vec(),
                };
                hits.lock().unwrap().push(req.clone());
                let reply = handler(&req);
                if !reply.delay.is_zero() {
                    tokio::time::sleep(reply.delay).await;
                }
                // For 3xx replies the body doubles as the Location header.
                let (extra, body) = if (300..400).contains(&reply.status) {
                    (format!("location: {}\r\n", reply.body), String::new())
                } else {
                    (String::new(), reply.body.clone())
                };
                let resp = format!(
                    "HTTP/1.1 {} X\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    reply.status,
                    body.len(),
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Stub { url, hits }
}

const RELAY: &str = "16Uiu2HAmRelayOne";
const PEERS_OK: &str = r#"[{"multiaddr":"/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmRelayOne","protocols":[],"shards":[0],"connected":"Connected","agent":"x","origin":"UnknownOrigin"}]"#;
const PEERS_FOREIGN: &str = r#"[{"multiaddr":"/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmRelayOne","shards":[0],"connected":"Connected"},{"multiaddr":"/ip4/8.8.8.8/tcp/60000/p2p/16Uiu2HAmStranger","shards":[0],"connected":"Connected"}]"#;

fn cfg(url: &str) -> LogosRestConfig {
    LogosRestConfig {
        node_url: url.into(),
        allowed_peer_ids: vec![RELAY.into()],
        request_timeout: Duration::from_secs(2),
        ..Default::default()
    }
}

fn topic() -> ContentTopic {
    ContentTopic::new("/agentnet/1/ttest-unit/proto").unwrap()
}

/// Default node behaviour: healthy admin API, publish/subscribe accepted.
fn healthy(req: &Req) -> Reply {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/admin/v1/peers") => ok(PEERS_OK),
        ("GET", "/health") => ok(r#"{"nodeHealth":"READY"}"#),
        ("POST", "/relay/v1/auto/subscriptions") => ok("OK"),
        ("POST", "/relay/v1/auto/messages") => ok("OK"),
        _ => status(404, ""),
    }
}

#[tokio::test]
async fn new_rejects_public_hosts_and_bad_config() {
    for u in [
        "http://8.8.8.8:8645",
        "http://example.com",
        "http://localhost.evil.test",
    ] {
        let e = LogosRestTransport::new(cfg(u)).err().expect("must fail");
        assert!(matches!(e, TransportError::Isolation(_)), "{u}");
    }
    let mut c = cfg("http://127.0.0.1:1");
    c.allowed_peer_ids.clear();
    assert!(LogosRestTransport::new(c).is_err());
    assert!(LogosRestTransport::new(cfg("http://127.0.0.1:1")).is_ok());
}

#[tokio::test]
async fn publish_sends_expected_request_and_returns_local_hash() {
    let stub = spawn_stub(healthy).await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    let r1 = t.publish(&topic(), b"hello").await.unwrap();
    let r2 = t.publish(&topic(), b"hello").await.unwrap();
    assert!(r2.timestamp_ns > r1.timestamp_ns, "strictly increasing");
    assert_ne!(r1.transport_id, r2.transport_id);
    assert_eq!(
        r1.transport_id,
        waku_message_hash(
            "/waku/2/rs/66/0",
            b"hello",
            topic().as_str(),
            &[],
            r1.timestamp_ns
        )
    );
    let pubs: Vec<Req> = stub
        .hits()
        .into_iter()
        .filter(|r| r.path == "/relay/v1/auto/messages")
        .collect();
    assert_eq!(pubs.len(), 2);
    let v: serde_json::Value = serde_json::from_slice(&pubs[0].body).unwrap();
    assert_eq!(v["payload"], "aGVsbG8=");
    assert_eq!(v["contentTopic"], topic().as_str());
    assert_eq!(v["ephemeral"], false);
    assert_eq!(v["timestamp"], r1.timestamp_ns);
    assert!(v.get("meta").is_none());
    assert_eq!(
        stub.count("/admin/v1/peers"),
        1,
        "audit cached across publishes"
    );
}

#[tokio::test]
async fn timestamps_are_unique_under_concurrency() {
    let mut seen = HashSet::new();
    let handles: Vec<_> = (0..8)
        .map(|_| tokio::spawn(async { (0..200).map(|_| next_timestamp_ns()).collect::<Vec<_>>() }))
        .collect();
    for h in handles {
        for ts in h.await.unwrap() {
            assert!(seen.insert(ts), "duplicate timestamp {ts}");
        }
    }
}

#[tokio::test]
async fn too_large_is_rejected_locally_without_touching_the_node() {
    let stub = spawn_stub(healthy).await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    let max = t.max_payload_len(&topic());
    assert!(max > 150_000 && max < 153_600);
    let e = t.publish(&topic(), &vec![0u8; max + 1]).await.unwrap_err();
    assert_eq!(e, TransportError::TooLarge { size: max + 1, max });
    assert!(
        stub.hits().is_empty(),
        "no request at all, not even the audit"
    );
    assert!(t.publish(&topic(), &vec![0u8; max]).await.is_ok());
}

#[tokio::test]
async fn publish_error_mapping_end_to_end() {
    let cases: Vec<(Reply, &str)> = vec![
        (
            status(
                400,
                "Failed to publish: publish failed in relay: NoPeersToPublish",
            ),
            "unavailable",
        ),
        (status(503, "Push request timed out"), "unavailable"),
        (status(500, "boom"), "unavailable"),
        (
            status(
                400,
                "Failed to publish: Message size exceeded maximum of 153600 bytes",
            ),
            "toolarge",
        ),
        (
            status(400, "Invalid content body, could not decode"),
            "protocol",
        ),
        (status(404, ""), "protocol"),
    ];
    for (reply, want) in cases {
        let reply = Arc::new(Mutex::new(Some(reply)));
        let stub = spawn_stub(move |req| {
            if req.path == "/admin/v1/peers" {
                return ok(PEERS_OK);
            }
            reply
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| status(500, "x"))
        })
        .await;
        let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
        let e = t.publish(&topic(), b"x").await.unwrap_err();
        let got = match e {
            TransportError::Unavailable(_) => "unavailable",
            TransportError::TooLarge { .. } => "toolarge",
            TransportError::Protocol(_) => "protocol",
            ref other => panic!("{other:?}"),
        };
        assert_eq!(got, want, "{e:?}");
    }
}

#[tokio::test]
async fn long_error_bodies_are_truncated() {
    let stub = spawn_stub(|req| {
        if req.path == "/admin/v1/peers" {
            ok(PEERS_OK)
        } else {
            status(400, &"y".repeat(5000))
        }
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    let msg = t.publish(&topic(), b"x").await.unwrap_err().to_string();
    assert!(msg.len() < 320, "{}", msg.len());
}

#[tokio::test]
async fn connection_refused_and_timeout_are_unavailable() {
    // refused: bind then drop the listener to get a closed port
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    let t = LogosRestTransport::new(cfg(&url)).unwrap();
    assert!(matches!(
        t.publish(&topic(), b"x").await,
        Err(TransportError::Unavailable(_))
    ));
    assert!(matches!(
        t.poll(&topic()).await,
        Err(TransportError::Unavailable(_))
    ));
    let q = HistoryQuery {
        topic: topic(),
        start_ns: 0,
        end_ns: 1,
        cursor: None,
        limit: 10,
    };
    assert!(matches!(
        t.history(&q).await,
        Err(TransportError::HistoryUnavailable(_))
    ));
    let s = t.status().await;
    assert!(!s.ready);

    // timeout
    let stub = spawn_stub(|req| {
        if req.path == "/admin/v1/peers" {
            ok(PEERS_OK)
        } else {
            Reply {
                status: 200,
                body: "OK".into(),
                delay: Duration::from_secs(3),
            }
        }
    })
    .await;
    let mut c = cfg(&stub.url);
    c.request_timeout = Duration::from_millis(300);
    let t = LogosRestTransport::new(c).unwrap();
    let started = Instant::now();
    assert!(matches!(
        t.publish(&topic(), b"x").await,
        Err(TransportError::Unavailable(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn foreign_connected_peer_fails_closed_everywhere() {
    let stub = spawn_stub(|req| match req.path.as_str() {
        "/admin/v1/peers" => ok(PEERS_FOREIGN),
        _ => ok("OK"),
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    let q = HistoryQuery {
        topic: topic(),
        start_ns: 0,
        end_ns: 1,
        cursor: None,
        limit: 10,
    };
    assert!(matches!(
        t.publish(&topic(), b"x").await,
        Err(TransportError::Isolation(_))
    ));
    assert!(matches!(
        t.poll(&topic()).await,
        Err(TransportError::Isolation(_))
    ));
    assert!(matches!(
        t.history(&q).await,
        Err(TransportError::Isolation(_))
    ));
    assert!(matches!(
        t.subscribe(&topic()).await,
        Err(TransportError::Isolation(_))
    ));
    assert!(matches!(t.audit().await, Err(TransportError::Isolation(_))));
    assert_eq!(stub.count("/relay/"), 0);
    assert_eq!(stub.count("/store/"), 0);
    let s = t.status().await;
    assert!(!s.ready);
    let v = s.isolation_violation.unwrap();
    assert!(v.contains("16Uiu2HAmStranger"));
    assert!(
        !v.contains("8.8.8.8"),
        "no third-party addresses in reasons"
    );
    assert!(s.peers.iter().any(|p| !p.allowed && p.connected));
}

#[tokio::test]
async fn wrong_allowlist_is_a_violation() {
    let stub = spawn_stub(healthy).await;
    let mut c = cfg(&stub.url);
    c.allowed_peer_ids = vec!["16Uiu2HAmSomeoneElse".into()];
    let t = LogosRestTransport::new(c).unwrap();
    assert!(matches!(
        t.publish(&topic(), b"x").await,
        Err(TransportError::Isolation(_))
    ));
}

#[tokio::test]
async fn admin_unavailable_fails_closed_as_unavailable() {
    for reply in [
        status(404, "not found"),
        status(503, ""),
        ok("not json"),
        ok("{}"),
    ] {
        let reply = Arc::new(reply_clone(&reply));
        let stub = spawn_stub(move |req| {
            if req.path == "/admin/v1/peers" {
                status(reply.status, &reply.body)
            } else {
                ok("OK")
            }
        })
        .await;
        let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
        assert!(matches!(
            t.publish(&topic(), b"x").await,
            Err(TransportError::Unavailable(_))
        ));
        assert!(matches!(
            t.poll(&topic()).await,
            Err(TransportError::Unavailable(_))
        ));
        assert_eq!(
            stub.count("/relay/"),
            0,
            "nothing sent without a successful audit"
        );
        let s = t.status().await;
        assert!(!s.ready);
        assert!(s.isolation_violation.is_none());
        assert!(s.detail.contains("audit"));
    }
}

fn reply_clone(r: &Reply) -> Reply {
    Reply {
        status: r.status,
        body: r.body.clone(),
        delay: r.delay,
    }
}

#[tokio::test]
async fn audit_is_cached_then_refreshed_after_interval() {
    let stub = spawn_stub(healthy).await;
    let mut c = cfg(&stub.url);
    c.audit_interval = Duration::from_millis(150);
    let t = LogosRestTransport::new(c).unwrap();
    t.publish(&topic(), b"1").await.unwrap();
    t.publish(&topic(), b"2").await.unwrap();
    assert_eq!(stub.count("/admin/v1/peers"), 1);
    tokio::time::sleep(Duration::from_millis(250)).await;
    t.publish(&topic(), b"3").await.unwrap();
    assert_eq!(stub.count("/admin/v1/peers"), 2);
    assert_eq!(t.metrics().audits_run, 2);
}

#[tokio::test]
async fn violation_clears_when_peers_recover_after_interval() {
    let bad = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let b2 = bad.clone();
    let stub = spawn_stub(move |req| {
        if req.path == "/admin/v1/peers" {
            ok(if b2.load(Ordering::SeqCst) {
                PEERS_FOREIGN
            } else {
                PEERS_OK
            })
        } else {
            ok("OK")
        }
    })
    .await;
    let mut c = cfg(&stub.url);
    c.audit_interval = Duration::from_millis(100);
    let t = LogosRestTransport::new(c).unwrap();
    assert!(matches!(
        t.publish(&topic(), b"x").await,
        Err(TransportError::Isolation(_))
    ));
    bad.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(t.publish(&topic(), b"x").await.is_ok());
}

#[tokio::test]
async fn public_mode_skips_the_audit() {
    let stub = spawn_stub(|req| {
        if req.path == "/admin/v1/peers" {
            ok(PEERS_FOREIGN)
        } else {
            ok("OK")
        }
    })
    .await;
    let c = LogosRestConfig {
        node_url: stub.url.clone(),
        mode: NetworkMode::Public,
        cluster_id: 1,
        ..Default::default()
    };
    let t = LogosRestTransport::new(c).unwrap();
    assert!(t.publish(&topic(), b"x").await.is_ok());
    assert_eq!(stub.count("/admin/v1/peers"), 0);
}

#[tokio::test]
async fn subscribe_and_poll_with_resubscribe_on_404() {
    let polls = Arc::new(Mutex::new(0u32));
    let p2 = polls.clone();
    let body = r#"[{"payload":"aGVsbG8=","contentTopic":"/agentnet/1/ttest-unit/proto","timestamp":7,"ephemeral":false},{"payload":"!!","contentTopic":"/agentnet/1/ttest-unit/proto","timestamp":8}]"#;
    let stub = spawn_stub(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/admin/v1/peers") => ok(PEERS_OK),
        ("POST", "/relay/v1/auto/subscriptions") => ok("OK"),
        ("GET", p) if p.starts_with("/relay/v1/auto/messages/") => {
            let mut n = p2.lock().unwrap();
            *n += 1;
            match *n {
                1 => ok(body),
                2 => status(404, "not subscribed"),
                _ => ok("[]"),
            }
        }
        _ => status(500, ""),
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    t.subscribe(&topic()).await.unwrap();
    t.subscribe(&topic()).await.unwrap();
    let sub = stub
        .hits()
        .into_iter()
        .find(|r| r.path == "/relay/v1/auto/subscriptions")
        .unwrap();
    assert_eq!(sub.body, br#"["/agentnet/1/ttest-unit/proto"]"#);

    let frames = t.poll(&topic()).await.unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].payload, b"hello");
    assert_eq!(frames[0].source, FrameSource::Live);
    assert_eq!(t.metrics().malformed_skipped, 1);
    // the URL-encoded topic is used
    assert!(stub
        .hits()
        .iter()
        .any(|r| r.path == "/relay/v1/auto/messages/%2Fagentnet%2F1%2Fttest-unit%2Fproto"));

    assert!(
        t.poll(&topic()).await.unwrap().is_empty(),
        "404 -> resubscribe, return empty"
    );
    assert_eq!(t.metrics().resubscribes, 1);
    assert_eq!(stub.count("/relay/v1/auto/subscriptions"), 3);
    assert!(t.poll(&topic()).await.unwrap().is_empty());
    assert_eq!(t.metrics().resubscribes, 1);
}

#[tokio::test]
async fn poll_subscribes_lazily_and_maps_errors() {
    let stub = spawn_stub(|req| match req.path.as_str() {
        "/admin/v1/peers" => ok(PEERS_OK),
        "/relay/v1/auto/subscriptions" => ok("OK"),
        p if p.starts_with("/relay/v1/auto/messages/") => status(500, "oops"),
        _ => status(404, ""),
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    assert!(matches!(
        t.poll(&topic()).await,
        Err(TransportError::Unavailable(_))
    ));
    assert_eq!(stub.count("/relay/v1/auto/subscriptions"), 1);

    let stub = spawn_stub(|req| match req.path.as_str() {
        "/admin/v1/peers" => ok(PEERS_OK),
        "/relay/v1/auto/subscriptions" => status(500, "Subscribe failed"),
        _ => ok("[]"),
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    assert!(matches!(
        t.subscribe(&topic()).await,
        Err(TransportError::Unavailable(_))
    ));

    let stub = spawn_stub(|req| match req.path.as_str() {
        "/admin/v1/peers" => ok(PEERS_OK),
        "/relay/v1/auto/subscriptions" => status(400, "bad"),
        _ => ok("[]"),
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    assert!(matches!(
        t.subscribe(&topic()).await,
        Err(TransportError::Protocol(_))
    ));

    let stub = spawn_stub(|req| match req.path.as_str() {
        "/admin/v1/peers" => ok(PEERS_OK),
        "/relay/v1/auto/subscriptions" => ok("OK"),
        _ => ok("{\"not\":\"an array\"}"),
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    assert!(matches!(
        t.poll(&topic()).await,
        Err(TransportError::Protocol(_))
    ));
}

const STORE_BODY: &str = r#"{"requestId":"r","statusCode":200,"statusDesc":"OK","messages":[{"messageHash":"0x68cae78abcff26d30ca097f50001104e140669b6bd4241bc1edc9db4830ce4f0","message":{"payload":"aGVsbG8=","contentTopic":"/agentnet/1/ttest-sample/proto","version":0,"timestamp":1795638885000000000,"ephemeral":false},"pubsubTopic":"/waku/2/rs/66/0"},{"messageHash":"0x0000000000000000000000000000000000000000000000000000000000000000","message":{"payload":"aGVsbG8=","contentTopic":"/agentnet/1/ttest-sample/proto","version":0,"timestamp":1795638885000000001,"ephemeral":false},"pubsubTopic":"/waku/2/rs/66/0"}],"paginationCursor":"0xfeed"}"#;

#[tokio::test]
async fn history_request_shape_and_hash_verification() {
    let stub = spawn_stub(|req| match req.path.as_str() {
        "/admin/v1/peers" => ok(PEERS_OK),
        p if p.starts_with("/store/v3/messages") => ok(STORE_BODY),
        _ => status(404, ""),
    })
    .await;
    let mut c = cfg(&stub.url);
    c.store_peer = Some("/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmRelayOne".into());
    c.history_page_size = 50;
    let t = LogosRestTransport::new(c).unwrap();
    let sample = ContentTopic::new("/agentnet/1/ttest-sample/proto").unwrap();
    let q = HistoryQuery {
        topic: sample.clone(),
        start_ns: 1000,
        end_ns: 2000,
        cursor: Some("0xabc".into()),
        limit: 500,
    };
    let page = t.history(&q).await.unwrap();
    assert_eq!(page.frames.len(), 1, "forged-hash entry skipped");
    assert_eq!(page.next_cursor.as_deref(), Some("0xfeed"));
    assert_eq!(page.frames[0].source, FrameSource::History);
    assert_eq!(t.metrics().hash_mismatches, 1);
    let req = stub
        .hits()
        .into_iter()
        .find(|r| r.path.starts_with("/store/"))
        .unwrap();
    for part in [
        "contentTopics=%2Fagentnet%2F1%2Fttest-sample%2Fproto",
        "includeData=true",
        "ascending=true",
        "pageSize=50",
        "startTime=1000",
        "endTime=2000",
        "cursor=0xabc",
        "peerAddr=%2Fip4%2F172.28.66.10%2Ftcp%2F60000%2Fp2p%2F16Uiu2HAmRelayOne",
    ] {
        assert!(req.path.contains(part), "{part} missing in {}", req.path);
    }
}

#[tokio::test]
async fn history_window_and_error_mapping() {
    let reply = Arc::new(Mutex::new(status(
        500,
        "No history response received (timeout)",
    )));
    let r2 = reply.clone();
    let stub = spawn_stub(move |req| {
        if req.path == "/admin/v1/peers" {
            ok(PEERS_OK)
        } else {
            let r = r2.lock().unwrap();
            reply_clone(&r)
        }
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    let mk = |s, e| HistoryQuery {
        topic: topic(),
        start_ns: s,
        end_ns: e,
        cursor: None,
        limit: 10,
    };

    // client-side window enforcement, no request made
    let e = t
        .history(&mk(0, MAX_HISTORY_WINDOW_NS + 1))
        .await
        .unwrap_err();
    assert!(matches!(e, TransportError::Protocol(_)));
    assert!(matches!(
        t.history(&mk(5, 4)).await,
        Err(TransportError::Protocol(_))
    ));
    assert_eq!(stub.hits().len(), 0);
    assert_eq!(t.max_history_window_ns(), MAX_HISTORY_WINDOW_NS);

    // exactly 24 h is allowed; 500 -> HistoryUnavailable
    assert!(matches!(
        t.history(&mk(0, MAX_HISTORY_WINDOW_NS)).await,
        Err(TransportError::HistoryUnavailable(_))
    ));
    *reply.lock().unwrap() = status(400, "time range exceeds 24h");
    assert!(matches!(
        t.history(&mk(0, 10)).await,
        Err(TransportError::Protocol(_))
    ));
    *reply.lock().unwrap() = ok(r#"{"statusCode":503,"statusDesc":"busy","messages":[]}"#);
    assert!(matches!(
        t.history(&mk(0, 10)).await,
        Err(TransportError::HistoryUnavailable(_))
    ));
    *reply.lock().unwrap() = ok("garbage");
    assert!(matches!(
        t.history(&mk(0, 10)).await,
        Err(TransportError::Protocol(_))
    ));
    *reply.lock().unwrap() = ok(r#"{"statusCode":200,"messages":[]}"#);
    let p = t.history(&mk(0, 10)).await.unwrap();
    assert!(p.frames.is_empty() && p.next_cursor.is_none());
    let mut zero = mk(0, 10);
    zero.limit = 0;
    assert!(t.history(&zero).await.is_err());
}

#[tokio::test]
async fn status_reports_peers_and_readiness() {
    let stub = spawn_stub(healthy).await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    let s = t.status().await;
    assert!(s.ready, "{s:?}");
    assert_eq!(s.peers.len(), 1);
    assert!(s.peers[0].allowed && s.peers[0].connected);
    assert!(s.isolation_violation.is_none());
    assert!(!s.detail.contains(&stub.url));

    // healthy node but no connected peer -> not ready
    let stub = spawn_stub(|req| match req.path.as_str() {
        "/admin/v1/peers" => ok(r#"[{"multiaddr":"/ip4/10.0.0.1/tcp/1/p2p/16Uiu2HAmRelayOne","connected":"CanConnect"}]"#),
        _ => ok("{}"),
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    let s = t.status().await;
    assert!(!s.ready);
    assert!(s.isolation_violation.is_none());
}

#[tokio::test]
async fn no_redirects_and_no_proxy_env() {
    // A redirect to a different host must not be followed.
    let target = spawn_stub(|_| ok("[]")).await;
    let location = format!("{}/admin/v1/peers", target.url);
    let stub = spawn_stub(move |req| {
        if req.path == "/admin/v1/peers" {
            Reply {
                status: 302,
                body: location.clone(),
                delay: Duration::ZERO,
            }
        } else {
            ok("OK")
        }
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    // 302 on the admin endpoint is not a 200 -> fail closed
    assert!(matches!(
        t.publish(&topic(), b"x").await,
        Err(TransportError::Unavailable(_))
    ));
    assert_eq!(target.hits().len(), 0);
}

const PEERS_DOWN: &str = r#"[{"multiaddr":"/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmRelayOne","shards":[0],"connected":"CannotConnect"}]"#;
const STATIC: &str = "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmRelayOne";

fn redial_cfg(url: &str) -> LogosRestConfig {
    LogosRestConfig {
        node_url: url.into(),
        static_peers: vec![STATIC.into()],
        request_timeout: Duration::from_secs(2),
        ..Default::default()
    }
}

/// Node whose peer is disconnected until it receives a dial.
async fn redial_stub(dial_works: bool) -> Stub {
    let dialled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    spawn_stub(move |req| match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/admin/v1/peers") => ok(if dialled.load(Ordering::SeqCst) {
            PEERS_OK
        } else {
            PEERS_DOWN
        }),
        ("POST", "/admin/v1/peers") => {
            if dial_works {
                dialled.store(true, Ordering::SeqCst);
                ok("OK")
            } else {
                status(500, "dial failed")
            }
        }
        _ => ok("OK"),
    })
    .await
}

fn dials(stub: &Stub) -> Vec<Req> {
    stub.hits()
        .into_iter()
        .filter(|r| r.method == "POST" && r.path == "/admin/v1/peers")
        .collect()
}

#[tokio::test]
async fn redial_issued_when_disconnected_and_only_static_peers_in_body() {
    let stub = redial_stub(true).await;
    let t = LogosRestTransport::new(redial_cfg(&stub.url)).unwrap();
    assert_eq!(
        t.config().allowed_peer_ids,
        vec![RELAY.to_string()],
        "derived"
    );
    t.publish(&topic(), b"x").await.unwrap();
    let d = dials(&stub);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].body, format!("[\"{STATIC}\"]").into_bytes());
    assert_eq!(t.metrics().redials, 1);
    // connected now: no further dials
    t.publish(&topic(), b"y").await.unwrap();
    assert!(t.status().await.ready);
    assert_eq!(dials(&stub).len(), 1);
}

#[tokio::test]
async fn no_dial_when_peer_already_connected_or_no_static_peers() {
    let stub = spawn_stub(healthy).await;
    let t = LogosRestTransport::new(redial_cfg(&stub.url)).unwrap();
    t.publish(&topic(), b"x").await.unwrap();
    assert!(dials(&stub).is_empty());
    // disconnected but nothing configured to dial
    let stub = spawn_stub(|req| {
        if req.path == "/admin/v1/peers" {
            ok(PEERS_DOWN)
        } else {
            ok("OK")
        }
    })
    .await;
    let t = LogosRestTransport::new(cfg(&stub.url)).unwrap();
    let _ = t.publish(&topic(), b"x").await;
    let _ = t.status().await;
    assert!(dials(&stub).is_empty());
    assert_eq!(t.metrics().redials, 0);
}

#[tokio::test]
async fn redial_is_rate_limited_and_failures_are_not_fatal() {
    let stub = redial_stub(false).await;
    let mut c = redial_cfg(&stub.url);
    c.redial_interval = Duration::from_millis(300);
    c.audit_interval = Duration::ZERO;
    let t = LogosRestTransport::new(c).unwrap();
    for _ in 0..5 {
        // audit passes (no violation); node merely has no connected peer
        assert!(t.publish(&topic(), b"x").await.is_ok());
        let _ = t.status().await;
    }
    assert_eq!(dials(&stub).len(), 1, "rate limited within the interval");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let _ = t.status().await;
    assert_eq!(dials(&stub).len(), 2);
    assert_eq!(t.metrics().redials, 2);
    assert!(
        !t.status().await.ready,
        "failed dial leaves the node not ready"
    );
}

#[tokio::test]
async fn redial_also_runs_from_poll_and_history_with_cached_audit() {
    let stub = redial_stub(true).await;
    let mut c = redial_cfg(&stub.url);
    c.audit_interval = Duration::from_secs(60);
    let t = LogosRestTransport::new(c).unwrap();
    // first call audits (not fresh) and redials
    let _ = t.poll(&topic()).await;
    assert_eq!(dials(&stub).len(), 1);
    assert_eq!(t.metrics().audits_run, 2, "audit, dial, re-audit");
}
