mod common;

use std::time::{Duration, Instant};

use agentnet_core::api::ChangeHint;
use agentnet_mcp::dto::SendMessageOutput;
use common::{
    fake_agent::{FakeAgent, BOB},
    Duplex, DuplexIo, HttpServer, Mode, *,
};
use rmcp::{model::*, service::Subscription};
use serde_json::json;
use tokio::time::timeout;

const INBOX: &str = "agentnet://inbox";
const OUTBOX: &str = "agentnet://outbox";
const CONV1: &str = "agentnet://conversations/c1";

/// Next resource-updated URI on a 2026 subscription, or panic after `WAIT`.
async fn next_uri(sub: &mut Subscription) -> String {
    match timeout(WAIT, sub.next())
        .await
        .expect("no notification within WAIT")
    {
        Ok(Some(ServerNotification::ResourceUpdatedNotification(n))) => n.params.uri,
        other => panic!("unexpected subscription event: {other:?}"),
    }
}

async fn assert_quiet(sub: &mut Subscription) {
    if let Ok(event) = timeout(QUIET, sub.next()).await {
        panic!("unexpected notification: {event:?}");
    }
}

async fn assert_quiet_legacy(rx: &mut Updates) {
    if let Ok(uri) = timeout(QUIET, rx.recv()).await {
        panic!("unexpected legacy notification: {uri:?}");
    }
}

#[tokio::test]
async fn listen_notifies_only_for_the_subscribed_uri() {
    let d = Duplex::start(Mode::Discover).await;
    let mut sub = d.client.listen(sub_filter(&[INBOX])).await.unwrap();
    assert_eq!(
        sub.acknowledged().resource_subscriptions.as_deref(),
        Some(&[INBOX.to_string()][..])
    );

    for other in [
        ChangeHint::Outbox,
        ChangeHint::Triggers,
        ChangeHint::Identity,
        ChangeHint::Events,
        ChangeHint::Conversation {
            conversation_id: "c1".into(),
        },
    ] {
        d.agent.emit(other);
    }
    assert_quiet(&mut sub).await;

    d.agent.emit(ChangeHint::Inbox);
    assert_eq!(next_uri(&mut sub).await, INBOX);
    assert_quiet(&mut sub).await;

    // The notification is a hint; the data is reread from the resource.
    d.agent.push_inbox(BOB, "hello", None);
    assert_eq!(next_uri(&mut sub).await, INBOX);
    let page = read_json(d.peer(), INBOX).await.unwrap();
    assert_eq!(page["records"][0]["body"], "hello");
    sub.cancel().await.unwrap();
}

#[tokio::test]
async fn each_hint_kind_maps_to_its_uri() {
    let d = Duplex::start(Mode::Discover).await;
    let all = [
        "agentnet://identity",
        INBOX,
        OUTBOX,
        "agentnet://triggers",
        CONV1,
    ];
    let mut sub = d.client.listen(sub_filter(&all)).await.unwrap();
    for (hint, uri) in [
        (ChangeHint::Identity, "agentnet://identity"),
        (ChangeHint::Inbox, INBOX),
        (ChangeHint::Outbox, OUTBOX),
        (ChangeHint::Triggers, "agentnet://triggers"),
        (
            ChangeHint::Conversation {
                conversation_id: "c1".into(),
            },
            CONV1,
        ),
    ] {
        d.agent.emit(hint);
        assert_eq!(next_uri(&mut sub).await, uri);
    }
    d.agent.emit(ChangeHint::Events);
    assert_quiet(&mut sub).await;
    sub.cancel().await.unwrap();
}

#[tokio::test]
async fn only_known_uris_are_accepted() {
    let d = Duplex::start(Mode::Discover).await;
    let filter = SubscriptionFilter::builder()
        .tools_list_changed()
        .resources_list_changed()
        .resource_subscriptions([
            INBOX,
            "agentnet://nope",
            "agentnet://inbox?cursor=c1",
            "agentnet://conversations/",
            "agentnet://conversations/has space",
            "file:///etc/passwd",
            CONV1,
            INBOX,
        ])
        .build();
    let mut sub = d.client.listen(filter).await.unwrap();
    let ack = sub.acknowledged();
    let mut accepted = ack.resource_subscriptions.clone().unwrap();
    accepted.sort();
    accepted.dedup(); // rmcp 3.11.0 echoes a duplicated request URI twice in the intersection
    assert_eq!(accepted, [CONV1.to_string(), INBOX.to_string()]);
    // We never emit list-changed notifications, so we must not acknowledge them.
    assert_ne!(ack.tools_list_changed, Some(true));
    assert_ne!(ack.resources_list_changed, Some(true));
    sub.cancel().await.unwrap();
}

#[tokio::test]
async fn conversation_template_instances_are_subscribable() {
    let d = Duplex::start(Mode::Discover).await;
    let mut sub = d.client.listen(sub_filter(&[CONV1])).await.unwrap();
    d.agent.emit(ChangeHint::Conversation {
        conversation_id: "c2".into(),
    });
    d.agent.emit(ChangeHint::Inbox);
    d.agent.emit(ChangeHint::Outbox);
    assert_quiet(&mut sub).await;
    // A send into c1 produces Outbox + Conversation{c1} hints; only the latter matches.
    let _: SendMessageOutput = call_ok(
        d.peer(),
        "send_message",
        json!({"recipient": BOB, "body": "x", "conversation_id": "c1"}),
    )
    .await;
    assert_eq!(next_uri(&mut sub).await, CONV1);
    assert_quiet(&mut sub).await;
    sub.cancel().await.unwrap();
}

#[tokio::test]
async fn cancel_stops_notifications_and_releases_resources() {
    let d = Duplex::start(Mode::Discover).await;
    let mut cancelled = d.client.listen(sub_filter(&[INBOX])).await.unwrap();
    let mut control = d.client.listen(sub_filter(&[INBOX])).await.unwrap();
    assert_eq!(d.mcp.stats().active_listeners, 2);
    assert_eq!(d.agent.receiver_count(), 2);

    d.agent.emit(ChangeHint::Inbox);
    next_uri(&mut cancelled).await;
    next_uri(&mut control).await;

    cancelled.cancel().await.unwrap();
    wait_until(
        || d.mcp.stats().active_listeners == 1,
        "cancelled listener to end",
    )
    .await;
    assert_eq!(d.agent.receiver_count(), 1);

    d.agent.emit(ChangeHint::Inbox);
    assert_eq!(next_uri(&mut control).await, INBOX);
    assert!(matches!(
        timeout(QUIET, cancelled.next()).await,
        Ok(Ok(None))
    ));

    control.cancel().await.unwrap();
    wait_until(
        || d.mcp.stats().active_listeners == 0,
        "last listener to end",
    )
    .await;
    assert_eq!(d.agent.receiver_count(), 0, "no receivers leaked");
    assert_eq!(d.mcp.stats().total_listeners, 2);
}

#[tokio::test]
async fn many_listens_open_and_close_without_leaks() {
    let d = Duplex::start(Mode::Discover).await;
    let mut subs = Vec::new();
    for _ in 0..40 {
        subs.push(d.client.listen(sub_filter(&[INBOX, OUTBOX])).await.unwrap());
    }
    assert_eq!(d.mcp.stats().active_listeners, 40);
    assert_eq!(d.agent.receiver_count(), 40);
    for mut s in subs {
        s.cancel().await.unwrap();
    }
    wait_until(
        || d.mcp.stats().active_listeners == 0,
        "all listeners to end",
    )
    .await;
    assert_eq!(d.agent.receiver_count(), 0);
    // A listen whose filter ends up empty parks no receiver and holds no receiver.
    let mut sub = d
        .client
        .listen(sub_filter(&["agentnet://nope"]))
        .await
        .unwrap();
    assert_eq!(d.agent.receiver_count(), 0);
    sub.cancel().await.unwrap();
}

#[tokio::test]
async fn hint_right_after_acknowledgment_is_not_lost() {
    // The receiver is created before the SDK acknowledges the subscription, so a
    // change made the instant the client sees the acknowledgment is delivered.
    let d = Duplex::start(Mode::Discover).await;
    for i in 0..100 {
        let mut sub = d.client.listen(sub_filter(&[INBOX])).await.unwrap();
        d.agent.emit(ChangeHint::Inbox);
        let uri = timeout(WAIT, next_uri(&mut sub))
            .await
            .unwrap_or_else(|_| panic!("lost hint on iteration {i}"));
        assert_eq!(uri, INBOX);
        sub.cancel().await.unwrap();
    }
    wait_until(|| d.mcp.stats().active_listeners == 0, "listeners to end").await;
    assert_eq!(d.agent.receiver_count(), 0);
}

#[tokio::test]
async fn lagged_receiver_notifies_every_subscribed_uri_once() {
    // Capacity 4 and a synchronous burst larger than that: the listener's receiver
    // lags (hints are lost) while the test task holds the (single) runtime thread.
    let agent = FakeAgent::with_capacity(4);
    let d = Duplex::start_with(agent.clone(), Mode::Discover).await;
    let mut sub = d
        .client
        .listen(sub_filter(&[INBOX, OUTBOX, "agentnet://triggers"]))
        .await
        .unwrap();
    for _ in 0..50 {
        agent.emit(ChangeHint::Identity); // not subscribed, only makes the receiver lag
    }
    let mut got = vec![
        next_uri(&mut sub).await,
        next_uri(&mut sub).await,
        next_uri(&mut sub).await,
    ];
    got.sort();
    assert_eq!(
        got,
        [
            "agentnet://inbox",
            "agentnet://outbox",
            "agentnet://triggers"
        ]
    );
    assert_quiet(&mut sub).await;

    // Lag does not break the stream: later hints still arrive, and only for the right URI.
    agent.emit(ChangeHint::Outbox);
    assert_eq!(next_uri(&mut sub).await, OUTBOX);
    assert_quiet(&mut sub).await;

    // Recovery contract: after a lag notification the client rereads by cursor.
    agent.push_inbox(BOB, "after-lag", None);
    let page = read_json(d.peer(), INBOX).await.unwrap();
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
    sub.cancel().await.unwrap();
}

#[tokio::test]
async fn bursts_under_capacity_are_coalesced() {
    let d = Duplex::start(Mode::Discover).await;
    let mut sub = d.client.listen(sub_filter(&[INBOX])).await.unwrap();
    for _ in 0..30 {
        d.agent.emit(ChangeHint::Inbox);
    }
    assert_eq!(next_uri(&mut sub).await, INBOX);
    // Far fewer than 30 notifications (hints are not a queue).
    let mut extra = 0;
    while timeout(Duration::from_millis(200), sub.next())
        .await
        .is_ok()
    {
        extra += 1;
    }
    assert!(
        extra < 5,
        "expected coalescing, got {extra} extra notifications"
    );
    sub.cancel().await.unwrap();
}

#[tokio::test]
async fn server_shutdown_token_ends_listens() {
    let d = Duplex::start(Mode::Discover).await;
    let mut sub = d.client.listen(sub_filter(&[INBOX])).await.unwrap();
    d.shutdown.cancel();
    wait_until(
        || d.mcp.stats().active_listeners == 0,
        "listener to end on shutdown",
    )
    .await;
    assert_eq!(d.agent.receiver_count(), 0);
    // The stream ends cleanly (server completes the listen request).
    assert!(matches!(timeout(WAIT, sub.next()).await, Ok(Ok(None))));
}

#[tokio::test]
async fn client_disconnect_ends_listens_promptly_on_the_stdio_code_path() {
    let agent = FakeAgent::new();
    let d = DuplexIo::start(agent.clone(), Mode::Discover).await;
    let _sub = d.client.listen(sub_filter(&[INBOX, OUTBOX])).await.unwrap();
    let _sub2 = d.client.listen(sub_filter(&[INBOX])).await.unwrap();
    assert_eq!(agent.receiver_count(), 2);
    let started = Instant::now();
    d.client.cancel().await.unwrap();
    let result = timeout(Duration::from_millis(1500), d.server)
        .await
        .expect("serve_io did not return within 1.5s after the client closed");
    result.unwrap().unwrap();
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert_eq!(
        agent.receiver_count(),
        0,
        "listen receivers leaked after disconnect"
    );
}

// ---------------------------------------------------------------- legacy resources/subscribe

#[allow(deprecated)]
#[tokio::test]
async fn legacy_subscribe_and_unsubscribe() {
    for version in [
        ProtocolVersion::V_2025_11_25,
        ProtocolVersion::V_2025_06_18,
        ProtocolVersion::V_2024_11_05,
    ] {
        let mut d = Duplex::start(Mode::Initialize(version.clone())).await;
        assert_eq!(negotiated(&d.client), version.to_string());
        d.client
            .subscribe(SubscribeRequestParams::new(INBOX))
            .await
            .unwrap();
        d.client
            .subscribe(SubscribeRequestParams::new(CONV1))
            .await
            .unwrap();
        assert_eq!(
            d.mcp.stats().active_legacy_tasks,
            1,
            "{version}: one pump per session"
        );
        assert_eq!(d.agent.receiver_count(), 1);

        d.agent.emit(ChangeHint::Outbox);
        d.agent.emit(ChangeHint::Triggers);
        assert_quiet_legacy(&mut d.updates).await;

        d.agent.emit(ChangeHint::Inbox);
        assert_eq!(
            timeout(WAIT, d.updates.recv()).await.unwrap().unwrap(),
            INBOX
        );
        d.agent.emit(ChangeHint::Conversation {
            conversation_id: "c1".into(),
        });
        assert_eq!(
            timeout(WAIT, d.updates.recv()).await.unwrap().unwrap(),
            CONV1
        );

        d.client
            .unsubscribe(UnsubscribeRequestParams::new(INBOX))
            .await
            .unwrap();
        d.agent.emit(ChangeHint::Inbox);
        assert_quiet_legacy(&mut d.updates).await;
        d.agent.emit(ChangeHint::Conversation {
            conversation_id: "c1".into(),
        });
        assert_eq!(
            timeout(WAIT, d.updates.recv()).await.unwrap().unwrap(),
            CONV1
        );

        d.client
            .unsubscribe(UnsubscribeRequestParams::new(CONV1))
            .await
            .unwrap();
        wait_until(
            || d.mcp.stats().active_legacy_tasks == 0,
            "legacy pump to stop",
        )
        .await;
        assert_eq!(d.agent.receiver_count(), 0, "{version}");
        d.agent.emit(ChangeHint::Conversation {
            conversation_id: "c1".into(),
        });
        assert_quiet_legacy(&mut d.updates).await;

        // Idempotent re-unsubscribe, and re-subscribe works again.
        d.client
            .unsubscribe(UnsubscribeRequestParams::new(CONV1))
            .await
            .unwrap();
        d.client
            .subscribe(SubscribeRequestParams::new(INBOX))
            .await
            .unwrap();
        d.agent.emit(ChangeHint::Inbox);
        assert_eq!(
            timeout(WAIT, d.updates.recv()).await.unwrap().unwrap(),
            INBOX
        );
    }
}

#[allow(deprecated)]
#[tokio::test]
async fn legacy_subscribe_rejects_unknown_uris_and_2026_listen_is_unavailable() {
    let d = Duplex::start(Mode::Initialize(ProtocolVersion::V_2025_11_25)).await;
    for bad in ["agentnet://nope", "agentnet://inbox?cursor=c1", "file:///x"] {
        let err = d
            .client
            .subscribe(SubscribeRequestParams::new(bad))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("-32002"), "{bad}: {err}");
    }
    assert_eq!(d.agent.receiver_count(), 0);
    // `subscriptions/listen` does not exist in the legacy lifecycle.
    let err = d
        .client
        .listen(sub_filter(&[INBOX]))
        .await
        .map(|_| ())
        .expect_err("listen must fail");
    assert!(err.to_string().contains("-32601"), "{err}");
}

#[allow(deprecated)]
#[tokio::test]
async fn legacy_lagged_receiver_notifies_all_subscribed_uris() {
    let agent = FakeAgent::with_capacity(4);
    let mut d = Duplex::start_with(
        agent.clone(),
        Mode::Initialize(ProtocolVersion::V_2025_11_25),
    )
    .await;
    d.client
        .subscribe(SubscribeRequestParams::new(INBOX))
        .await
        .unwrap();
    d.client
        .subscribe(SubscribeRequestParams::new(OUTBOX))
        .await
        .unwrap();
    for _ in 0..50 {
        agent.emit(ChangeHint::Identity);
    }
    let mut got = vec![
        timeout(WAIT, d.updates.recv()).await.unwrap().unwrap(),
        timeout(WAIT, d.updates.recv()).await.unwrap().unwrap(),
    ];
    got.sort();
    assert_eq!(got, [INBOX, OUTBOX]);
    assert_quiet_legacy(&mut d.updates).await;
}

#[allow(deprecated)]
#[tokio::test]
async fn legacy_pump_ends_when_session_ends() {
    let agent = FakeAgent::new();
    let d = DuplexIo::start(
        agent.clone(),
        Mode::Initialize(ProtocolVersion::V_2025_11_25),
    )
    .await;
    d.client
        .subscribe(SubscribeRequestParams::new(INBOX))
        .await
        .unwrap();
    assert_eq!(agent.receiver_count(), 1);
    d.client.cancel().await.unwrap();
    timeout(Duration::from_millis(1500), d.server)
        .await
        .expect("server exit")
        .unwrap()
        .unwrap();
    assert_eq!(agent.receiver_count(), 0, "legacy pump leaked");

    // And over HTTP: the session's pump stops when the session is closed.
    let server = HttpServer::start().await;
    let (c, mut rx) = server
        .connect(Mode::Initialize(ProtocolVersion::V_2025_11_25))
        .await
        .unwrap();
    c.subscribe(SubscribeRequestParams::new(INBOX))
        .await
        .unwrap();
    server.agent.emit(ChangeHint::Inbox);
    assert_eq!(timeout(WAIT, rx.recv()).await.unwrap().unwrap(), INBOX);
    c.cancel().await.unwrap();
    wait_until(
        || server.agent.receiver_count() == 0,
        "http legacy pump to stop",
    )
    .await;
    server.shutdown.cancel();
}

// ---------------------------------------------------------------- listen over HTTP

#[tokio::test]
async fn http_listen_filters_cancels_and_cleans_up() {
    let server = HttpServer::start().await;
    let (c, _rx) = server.connect(Mode::Discover).await.unwrap();
    let mut sub = c.listen(sub_filter(&[INBOX])).await.unwrap();
    server.agent.emit(ChangeHint::Outbox);
    assert_quiet(&mut sub).await;
    server.agent.emit(ChangeHint::Inbox);
    assert_eq!(next_uri(&mut sub).await, INBOX);
    assert_eq!(server.agent.receiver_count(), 1);
    sub.cancel().await.unwrap();
    wait_until(
        || server.agent.receiver_count() == 0,
        "http listener to end",
    )
    .await;
    c.cancel().await.unwrap();

    // Disconnect without an explicit cancel also releases the listener.
    let (c, _rx) = server.connect(Mode::Discover).await.unwrap();
    let sub = c.listen(sub_filter(&[INBOX])).await.unwrap();
    assert_eq!(server.agent.receiver_count(), 1);
    drop(sub);
    c.cancel().await.unwrap();
    wait_until(
        || server.agent.receiver_count() == 0,
        "listener to end after disconnect",
    )
    .await;
    server.shutdown.cancel();
}

#[tokio::test]
async fn http_shutdown_ends_open_streams_promptly() {
    let server = HttpServer::start().await;
    let (c, _rx) = server.connect(Mode::Discover).await.unwrap();
    let _sub = c.listen(sub_filter(&[INBOX])).await.unwrap();
    let started = Instant::now();
    server.shutdown.cancel();
    let result = timeout(Duration::from_secs(4), server.task)
        .await
        .expect("serve_http did not stop");
    result.unwrap().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(server.agent.receiver_count(), 0);
}
