//! `run()` with real tokio timers: smoke, graceful shutdown, readiness-triggered
//! history sync and inbound backpressure. Conditions are polled with a few-ms
//! sleep; nothing depends on wall-clock durations beyond generous timeouts.

mod common;

use std::time::Duration;

use agentnet_core::api::*;
use agentnet_core::NodeConfig;
use common::*;
use tokio_util::sync::CancellationToken;

fn fast(c: &mut NodeConfig) {
    c.delivery.poll_interval_ms = 5;
    c.delivery.history_sync_interval_s = 3600;
}

async fn until<F: std::future::Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if f().await {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
}

fn spawn_run(a: &Agent, t: &CancellationToken) -> tokio::task::JoinHandle<()> {
    let n = a.node.clone();
    let t = t.clone();
    tokio::spawn(async move { n.run(t).await })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_smoke_delivers_and_shuts_down_promptly() {
    let w = World::new();
    let a = w.agent("a", cfg_with(fast));
    let b = w.agent("b", cfg_with(fast));
    exchange(&a, &b).await;
    // Subscribe both inboxes before the run loops start: `run` subscribes in
    // its receive task, and a frame published before the recipient's first
    // poll is only recoverable through history (disabled here) or a retry
    // (the mock clock is frozen). This was an intermittent failure.
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    let tok = CancellationToken::new();
    let (ha, hb) = (spawn_run(&a, &tok), spawn_run(&b, &tok));
    let r = a.send(&b, "via run").await;
    until("delivered", || async {
        a.state(&r.message_id).await == DeliveryState::Delivered
    })
    .await;
    assert_eq!(b.inbox().await.len(), 1);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        1
    );
    let t0 = tokio::time::Instant::now();
    tok.cancel();
    tokio::time::timeout(Duration::from_secs(2), async {
        ha.await.unwrap();
        hb.await.unwrap();
    })
    .await
    .expect("run must stop promptly");
    assert!(t0.elapsed() < Duration::from_secs(2));
    // the store is closed after run: further calls fail cleanly instead of hanging
    let e = a
        .node
        .get_message_status(r.message_id.clone())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    // and the data survives a reopen
    let a = w.reopen(a, cfg());
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_recovers_via_history_when_transport_comes_back() {
    let w = World::new();
    let a = w.agent("a", cfg_with(fast));
    let b = w.agent("b", cfg_with(fast));
    exchange(&a, &b).await;
    let tok = CancellationToken::new();
    let (ha, hb) = (spawn_run(&a, &tok), spawn_run(&b, &tok));
    // let B's initial history sync and subscription happen first
    until("b polled", || async {
        b.node
            .network_status(false)
            .await
            .unwrap()
            .last_live_poll_at
            .is_some()
    })
    .await;
    b.transport.set_online(false);
    tokio::time::sleep(Duration::from_millis(20)).await; // a few failed polls
    let r = a.send(&b, "while down").await;
    until("a published", || async {
        a.state(&r.message_id).await == DeliveryState::Sent
    })
    .await;
    w.advance(5_000); // history window now covers the frame (ms precision)
    assert_eq!(b.n("inbox"), 0);
    b.transport.set_online(true); // false -> true flips readiness: history sync, interval is 1 h
    until("recovered", || async { b.n("inbox") == 1 }).await;
    until("delivered", || async {
        a.state(&r.message_id).await == DeliveryState::Delivered
    })
    .await;
    tok.cancel();
    ha.await.unwrap();
    hb.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_channel_applies_backpressure_and_loses_nothing() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent(
        "b",
        cfg_with(|c| {
            fast(c);
            c.delivery.inbound_channel_capacity = 2;
        }),
    );
    exchange(&a, &b).await;
    b.node.step_receive().await.unwrap(); // subscribe
    b.transport.set_live_capacity(1000);
    b.node.set_processing_paused(true);
    // history sync processes frames inline (it is itself sequential and bounded);
    // switch it off so this test observes only the live path.
    w.net.set_history_available(false);
    for i in 0..30 {
        a.send(&b, &format!("first-{i}")).await;
    }
    a.node.step_send().await.unwrap();
    assert_eq!(b.transport.queued_len(), 30);
    let tok = CancellationToken::new();
    let hb = spawn_run(&b, &tok);
    // the receive loop drains one poll batch, fills the channel (2) and then blocks in send()
    until("first batch pulled", || async {
        b.transport.queued_len() == 0
    })
    .await;
    // more frames arrive; the blocked receive loop must NOT poll them away
    for i in 0..20 {
        a.send(&b, &format!("second-{i}")).await;
    }
    a.node.step_send().await.unwrap();
    assert_eq!(b.transport.queued_len(), 20);
    tokio::time::sleep(Duration::from_millis(60)).await; // ~12 poll ticks
    assert_eq!(
        b.transport.queued_len(),
        20,
        "backpressure: nothing more was polled"
    );
    assert_eq!(b.n("inbox"), 0, "processing is paused");
    // resume: everything is processed exactly once
    b.node.set_processing_paused(false);
    until("all 50 persisted", || async { b.n("inbox") == 50 }).await;
    assert_eq!(b.transport.dropped_count(), 0);
    assert_eq!(
        b.node
            .read_events(PageRequest {
                limit: Some(200),
                ..Default::default()
            })
            .await
            .unwrap()
            .events
            .len(),
        50
    );
    // shutdown while paused again still completes promptly
    b.node.set_processing_paused(true);
    for i in 0..10 {
        a.send(&b, &format!("third-{i}")).await;
    }
    a.node.step_send().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    tok.cancel();
    tokio::time::timeout(Duration::from_secs(2), hb)
        .await
        .expect("prompt shutdown")
        .unwrap();
}
