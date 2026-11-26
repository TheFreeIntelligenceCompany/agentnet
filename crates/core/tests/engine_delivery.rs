//! Delivery: happy path, retries, loss, duplication, offline recovery, crash
//! recovery, TTL, idempotency, saturation, isolation, identity, disk failure.

mod common;

use agentnet_core::api::*;
use agentnet_core::config::NodeConfig;
use agentnet_core::identity::Identity;
use agentnet_core::{Node, NodeError};
use agentnet_transport::mock::MockNetwork;
use agentnet_transport::Transport;
use common::*;
use std::sync::Arc;

async fn pair(w: &World) -> (Agent, Agent) {
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    exchange(&a, &b).await;
    // subscribe both before anything is published
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    (a, b)
}

#[tokio::test]
async fn a_to_b_message_ack_status_hints_and_event() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let mut hints = b.node.changes();
    let r = a.send(&b, "hello").await;
    assert_eq!(r.status, DeliveryState::Queued);
    assert!(!r.deduplicated);
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Queued);

    let rep = a.node.step_send().await.unwrap();
    assert_eq!(rep.published, 1);
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Sent);

    // B persists, then hints.
    assert!(hints.try_recv().is_err());
    b.node.step_receive().await.unwrap();
    let inbox = b.inbox().await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "hello");
    assert_eq!(inbox[0].sender, a.addr);
    assert_eq!(inbox[0].sender_trust, Trust::Trusted);
    assert!(!inbox[0].quarantined && !inbox[0].acknowledged);
    let mut kinds = vec![];
    while let Ok(h) = hints.try_recv() {
        kinds.push(h);
    }
    assert!(kinds.contains(&ChangeHint::Inbox));
    assert!(kinds.contains(&ChangeHint::Events));
    assert!(kinds.contains(&ChangeHint::Conversation {
        conversation_id: r.conversation_id.clone()
    }));

    let ev = b.node.read_events(PageRequest::default()).await.unwrap();
    assert_eq!(ev.events.len(), 1);
    assert_eq!(ev.events[0].event_type, EventType::MessageReceived);
    assert_eq!(ev.events[0].message_id, r.message_id);
    assert_eq!(ev.events[0].agent_id, b.addr);

    // ack goes back; A sees delivered
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Sent);
    b.node.step_send().await.unwrap();
    a.node.step_receive().await.unwrap();
    let st = a
        .node
        .get_message_status(r.message_id.clone())
        .await
        .unwrap();
    assert_eq!(st.state, DeliveryState::Delivered);
    assert_eq!(st.attempts, 1);
    assert!(st.delivered_at.is_some() && st.sent_at.is_some());
    // acks do not appear in the inbox or events
    assert!(a.inbox().await.is_empty());
    assert_eq!(
        a.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        0
    );
    // conversation shows both directions' real messages only
    let conv = b
        .node
        .read_conversation(r.conversation_id.clone(), PageRequest::default())
        .await
        .unwrap();
    assert_eq!(conv.entries.len(), 1);
}

#[tokio::test]
async fn lost_publish_retries_with_backoff_bounds_then_delivers() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let r = a.send(&b, "x").await;
    a.transport.drop_next_publishes(2);
    let mut last_next = w.now_ms();
    for n in 1..=3u32 {
        let rep = a.node.step_send().await.unwrap();
        assert_eq!(rep.published, 1, "attempt {n}");
        let st = a
            .node
            .get_message_status(r.message_id.clone())
            .await
            .unwrap();
        assert_eq!(st.attempts, n);
        let delay = st.next_attempt_at.unwrap() - w.now_ms();
        let ceiling = (2000i64 << (n - 1)).min(300_000);
        assert!(
            (1..=ceiling).contains(&delay),
            "attempt {n}: delay {delay} ceiling {ceiling}"
        );
        // not due before next_attempt_at
        assert_eq!(a.node.step_send().await.unwrap().published, 0);
        w.advance(st.next_attempt_at.unwrap() - w.now_ms());
        last_next = st.next_attempt_at.unwrap();
        if n < 3 {
            assert_eq!(b.node.step_receive().await.unwrap().polled, 0);
        }
    }
    assert_eq!(last_next, w.now_ms());
    // third publish was delivered; B has one row; ack closes the loop
    settle(&[&a, &b]).await;
    assert_eq!(b.inbox().await.len(), 1);
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
}

#[tokio::test]
async fn backoff_ceiling_caps_and_is_seed_deterministic() {
    let run = || async {
        let w = World::new();
        let a = w.agent(
            "a",
            cfg_with(|c| {
                c.delivery.retry_max_ms = 10_000;
                c.delivery.max_attempts = 12;
            }),
        );
        let b = w.agent("b", cfg());
        exchange(&a, &b).await;
        let r = a.send(&b, "x").await;
        let mut delays = vec![];
        for n in 1..=8u32 {
            a.node.step_send().await.unwrap();
            let st = a
                .node
                .get_message_status(r.message_id.clone())
                .await
                .unwrap();
            let d = st.next_attempt_at.unwrap() - w.now_ms();
            let ceiling = (2000i64 << (n - 1)).min(10_000);
            assert!((1..=ceiling).contains(&d), "n={n} d={d}");
            delays.push(d);
            w.advance(d);
        }
        delays
    };
    let one = run().await;
    // same seed (7) in a fresh world gives the same schedule
    // (note: world clocks start equal, ids differ but jitter depends only on the RNG)
    assert_eq!(one, run().await);
}

#[tokio::test]
async fn duplicates_reordering_and_lost_ack() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    b.transport.set_duplicate_delivery(4);
    b.transport.set_reorder_seed(Some(99));
    let mut ids = vec![];
    for i in 0..6 {
        ids.push(a.send(&b, &format!("m{i}")).await.message_id);
    }
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    assert_eq!(b.inbox().await.len(), 6);
    assert_eq!(b.n("inbox"), 6);
    let evs = b
        .node
        .read_events(PageRequest::default())
        .await
        .unwrap()
        .events;
    assert_eq!(evs.len(), 6, "one event per message despite 4x delivery");
    assert!(b.metric("frame.transport_seen") >= 18);

    // B's acks are lost
    b.transport.drop_next_publishes(6);
    b.node.step_send().await.unwrap();
    a.node.step_receive().await.unwrap();
    for id in &ids {
        assert_eq!(a.state(id).await, DeliveryState::Sent);
    }
    // A retries; B sees duplicates but rate-limits re-acks for 30 s
    b.transport.set_duplicate_delivery(1);
    w.advance(10_000);
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    assert_eq!(b.inbox().await.len(), 6);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        6
    );
    assert!(b.metric("ack.reack_rate_limited") > 0);
    // after the interval a retry produces a re-ack and A converges
    w.advance(40_000);
    for _ in 0..4 {
        a.node.step_send().await.unwrap();
        b.node.step_receive().await.unwrap();
        b.node.step_send().await.unwrap();
        a.node.step_receive().await.unwrap();
        w.advance(60_000);
    }
    for id in &ids {
        assert_eq!(a.state(id).await, DeliveryState::Delivered);
    }
    assert!(b.metric("ack.requeued") >= 6);
    assert_eq!(b.n("inbox"), 6);
}

#[tokio::test]
async fn offline_recipient_recovers_20_via_history() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let b_id = b.id_path.clone();
    b.transport.set_online(false);
    let b = w.reopen(b, cfg()); // stop B
    let mut ids = vec![];
    for i in 0..20 {
        ids.push(a.send(&b, &format!("off{i}")).await.message_id);
    }
    a.node.step_send().await.unwrap();
    assert_eq!(
        b.transport.queued_len(),
        0,
        "offline node queued nothing live"
    );
    w.advance(5_000);
    b.transport.set_online(true);
    let _ = b_id;
    let rep = b.node.step_history_sync().await.unwrap();
    assert!(rep.completed);
    assert_eq!(b.inbox().await.len(), 20);
    assert_eq!(b.n("inbox"), 20);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        20
    );
    // acks were queued and go out; a second sync adds nothing
    b.node.step_send().await.unwrap();
    a.node.step_receive().await.unwrap();
    for id in &ids {
        assert_eq!(a.state(id).await, DeliveryState::Delivered);
    }
    assert!(b.node.step_history_sync().await.unwrap().completed);
    assert_eq!(b.n("inbox"), 20);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        20
    );
}

#[tokio::test]
async fn history_unavailable_keeps_watermark_and_recovers_later() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    assert!(b.node.step_history_sync().await.unwrap().completed);
    let wm0 = b.node.debug_history_watermark().unwrap();
    b.transport.set_online(false);
    let r = a.send(&b, "while-down").await;
    a.node.step_send().await.unwrap();
    w.advance(60_000);
    b.transport.set_online(true);
    w.net.set_history_available(false);
    let rep = b.node.step_history_sync().await.unwrap();
    assert!(!rep.completed);
    assert!(rep.error.is_some());
    assert_eq!(
        b.node.debug_history_watermark().unwrap(),
        wm0,
        "watermark untouched"
    );
    assert_eq!(b.inbox().await.len(), 0);
    w.net.set_history_available(true);
    assert!(b.node.step_history_sync().await.unwrap().completed);
    assert!(b.node.debug_history_watermark().unwrap() > wm0);
    let inbox = b.inbox().await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].message_id, r.message_id);
}

#[tokio::test]
async fn history_past_retention_is_not_recovered_and_sender_expires() {
    // Documented behaviour: if the relay's history no longer holds a frame, the
    // recipient cannot recover it; the sender keeps its row until the TTL passes
    // and then reports `expired` (never `delivered`).
    let w = World::new();
    let a = w.agent("a", cfg_with(|c| c.delivery.max_attempts = 1));
    let b = w.agent("b", cfg());
    exchange(&a, &b).await;
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    w.net
        .set_history_retention(Some(std::time::Duration::from_secs(600)));
    b.transport.set_online(false);
    let r = a
        .node
        .send_message(SendMessageRequest {
            recipient: b.addr.clone(),
            body: "lost to retention".into(),
            ttl_seconds: Some(3600),
            ..Default::default()
        })
        .await
        .unwrap();
    a.node.step_send().await.unwrap();
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Sent);
    w.advance(2 * 3600 * 1000); // past relay retention and past the TTL
    b.transport.set_online(true);
    assert!(b.node.step_history_sync().await.unwrap().completed);
    assert_eq!(b.inbox().await.len(), 0);
    assert_eq!(
        a.node.step_send().await.unwrap().published,
        0,
        "max_attempts reached: no more publishes"
    );
    a.node.step_maintenance().unwrap();
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Expired);
}

#[tokio::test]
async fn crash_between_send_message_and_step_send() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let r = a.send(&b, "survives").await;
    let a = w.reopen(a, cfg()); // "crash": drop without ever stepping
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Queued);
    a.node.step_receive().await.unwrap();
    settle(&[&a, &b]).await;
    assert_eq!(b.inbox().await.len(), 1);
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
    assert_eq!(b.n("inbox"), 1);
}

#[tokio::test]
async fn crash_receiver_mid_stream_no_duplicate_processing() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    for i in 0..5 {
        a.send(&b, &format!("p{i}")).await;
    }
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    assert_eq!(b.n("inbox"), 5);
    let b = w.reopen(b, cfg());
    // everything is re-presented through history after the restart
    w.advance(1000);
    assert!(b.node.step_history_sync().await.unwrap().completed);
    assert_eq!(b.n("inbox"), 5);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        5
    );
    assert!(b.metric("frame.transport_seen") + b.metric("message.duplicate") >= 5);
}

#[tokio::test]
async fn crash_between_inbox_commit_and_ack_publish_ack_still_goes_out() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let r = a.send(&b, "needs ack").await;
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap(); // committed, ack row queued, NOT published
    assert_eq!(b.n("outbox"), 1);
    let b = w.reopen(b, cfg());
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Sent);
    b.node.step_send().await.unwrap();
    a.node.step_receive().await.unwrap();
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
    assert_eq!(b.n("inbox"), 1);
}

#[tokio::test]
async fn ttl_expiry_of_outbox_and_cap() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    b.transport.set_online(false);
    a.transport.set_online(false); // publishes fail
    let r = a
        .node
        .send_message(SendMessageRequest {
            recipient: b.addr.clone(),
            body: "x".into(),
            ttl_seconds: Some(30),
            ..Default::default()
        })
        .await
        .unwrap();
    let rep = a.node.step_send().await.unwrap();
    assert!(rep.deferred);
    let st = a
        .node
        .get_message_status(r.message_id.clone())
        .await
        .unwrap();
    assert_eq!(st.state, DeliveryState::Queued);
    assert_eq!(st.attempts, 0);
    assert!(st.last_error.is_some());
    w.advance(31_000);
    assert_eq!(a.node.step_send().await.unwrap().expired, 1);
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Expired);
    // ttl above the maximum is capped
    let r2 = a
        .node
        .send_message(SendMessageRequest {
            recipient: b.addr.clone(),
            body: "y".into(),
            ttl_seconds: Some(10_000_000),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(r2.expires_at - w.now_ms(), 604_800_000);
}

#[tokio::test]
async fn late_ack_after_expiry_still_marks_delivered() {
    // An ack's own expiry never exceeds the original message's, so with a monotonic
    // clock a row cannot be `expired` while its ack is still openable. The path is
    // reachable after a clock correction, which this test simulates by rewinding.
    let w = World::new();
    let (a, b) = pair(&w).await;
    let send = |body: &'static str| {
        let (a, bb) = (&a, b.addr.clone());
        async move {
            a.node
                .send_message(SendMessageRequest {
                    recipient: bb,
                    body: body.into(),
                    ttl_seconds: Some(60),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };
    let r = send("x").await;
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    a.transport.set_delay_delivery(true); // the ack is held in the network
    b.node.step_send().await.unwrap();
    let t0 = w.clock.now_ns();
    w.advance(61_000);
    a.node.step_maintenance().unwrap();
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Expired);
    w.clock.set_ns(t0 + 50_000_000_000); // clock corrected backwards
    a.transport.release();
    a.node.step_receive().await.unwrap();
    let st = a
        .node
        .get_message_status(r.message_id.clone())
        .await
        .unwrap();
    assert_eq!(st.state, DeliveryState::Delivered);
    assert!(st.delivered_at.is_some());

    // With a monotonic clock an expired ack is simply rejected by `open`.
    let r2 = send("z").await;
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    a.transport.set_delay_delivery(true);
    b.node.step_send().await.unwrap();
    w.advance(61_000);
    a.node.step_maintenance().unwrap();
    a.transport.release();
    a.node.step_receive().await.unwrap();
    assert_eq!(a.state(&r2.message_id).await, DeliveryState::Expired);
    assert_eq!(a.metric("open_error.expired"), 1);
}

#[tokio::test]
async fn idempotency_key_semantics() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let req = |body: &str, to: &Agent| SendMessageRequest {
        recipient: to.addr.clone(),
        body: body.into(),
        idempotency_key: Some("k-1".into()),
        ..Default::default()
    };
    let r1 = a.node.send_message(req("same", &b)).await.unwrap();
    let r2 = a.node.send_message(req("same", &b)).await.unwrap();
    assert!(!r1.deduplicated && r2.deduplicated);
    assert_eq!(r1.message_id, r2.message_id);
    assert_eq!(r1.conversation_id, r2.conversation_id);
    assert_eq!(a.n("outbox"), 1);
    assert_eq!(
        a.send_err(req("different", &b)).await.code,
        ErrorCode::Conflict
    );
    let c = w.agent("c", cfg());
    a.add(&c).await;
    assert_eq!(a.send_err(req("same", &c)).await.code, ErrorCode::Conflict);
    // status of the duplicate reflects the original
    settle(&[&a, &b]).await;
    let r3 = a.node.send_message(req("same", &b)).await.unwrap();
    assert_eq!(r3.status, DeliveryState::Delivered);
    assert_eq!(b.inbox().await.len(), 1);
    assert_eq!(
        a.send_err(SendMessageRequest {
            idempotency_key: Some(String::new()),
            recipient: b.addr.clone(),
            ..Default::default()
        })
        .await
        .code,
        ErrorCode::InvalidArgument
    );
}

#[tokio::test]
async fn send_validation() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let base = SendMessageRequest {
        recipient: b.addr.clone(),
        body: "x".into(),
        ..Default::default()
    };
    let with = |f: &dyn Fn(&mut SendMessageRequest)| {
        let mut r = base.clone();
        f(&mut r);
        r
    };
    assert_eq!(
        a.send_err(with(&|r| r.recipient = "nonsense".into()))
            .await
            .code,
        ErrorCode::InvalidArgument
    );
    let stranger = Identity::generate_default(w.now_ms()).unwrap();
    assert_eq!(
        a.send_err(with(&|r| r.recipient = stranger.address().to_string()))
            .await
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        a.send_err(with(&|r| r.message_type = Some("ack.received".into())))
            .await
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        a.send_err(with(&|r| r.message_type = Some("bogus".into())))
            .await
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        a.send_err(with(&|r| r.ttl_seconds = Some(0))).await.code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        a.send_err(with(&|r| r.conversation_id = Some("has space".into())))
            .await
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        a.send_err(with(&|r| r.body = "x".repeat(65_537)))
            .await
            .code,
        ErrorCode::TooLarge
    );
    // fits max_body_bytes but not the transport frame
    w.net.set_max_payload_len(2000);
    let a2 = w.agent("a2", cfg());
    a2.add(&b).await;
    let e = a2.send_err(with(&|r| r.body = "x".repeat(5000))).await;
    assert_eq!(e.code, ErrorCode::TooLarge);
    assert!(e.message.contains("at most about"));
    // blocked recipient
    a.node.set_contact_trust(&b.addr, Trust::Blocked).unwrap();
    assert_eq!(a.send_err(base.clone()).await.code, ErrorCode::PolicyDenied);
    a.node.set_contact_trust(&b.addr, Trust::Trusted).unwrap();
    for t in ["message", "task.request", "task.result"] {
        a.node
            .send_message(with(&|r| r.message_type = Some(t.into())))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn expired_recipient_kem_key_is_refused_with_clear_error() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let mut id = Identity::generate_default(w.now_ms()).unwrap();
    id.rotate_kem(w.now_ms(), w.now_ms() + 1000, Some(w.now_ms() + 60_000))
        .unwrap();
    let rec = id.contact_record().to_document();
    a.node
        .add_contact(AddContactRequest {
            contact_record: rec,
            ..Default::default()
        })
        .await
        .unwrap();
    w.advance(61_000);
    let e = a
        .send_err(SendMessageRequest {
            recipient: id.address().to_string(),
            body: "x".into(),
            ..Default::default()
        })
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(e.message.contains("fresh record"));
    // importing an already expired record is refused up front
    let e = a
        .node
        .add_contact(AddContactRequest {
            contact_record: id.contact_record().to_document(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn outbox_saturation_returns_unavailable() {
    let w = World::new();
    let a = w.agent("a", cfg_with(|c| c.delivery.max_outbox_pending = 3));
    let b = w.agent("b", cfg());
    exchange(&a, &b).await;
    for _ in 0..3 {
        a.send(&b, "x").await;
    }
    assert_eq!(
        a.send_err(SendMessageRequest {
            recipient: b.addr.clone(),
            body: "x".into(),
            ..Default::default()
        })
        .await
        .code,
        ErrorCode::Unavailable
    );
    // delivered rows no longer count
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    settle(&[&a, &b]).await;
    a.send(&b, "after").await;
}

#[tokio::test]
async fn inbox_saturation_not_acked_then_accepted_after_space_frees() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg_with(|c| c.storage.max_inbox_records = 2));
    exchange(&a, &b).await;
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    let ids: Vec<_> = {
        let mut v = vec![];
        for i in 0..3 {
            v.push(a.send(&b, &format!("s{i}")).await.message_id);
        }
        v
    };
    settle(&[&a, &b]).await;
    assert_eq!(b.n("inbox"), 2);
    assert!(b.metric("inbox.full_refused") >= 1);
    let delivered = {
        let mut n = 0;
        for id in &ids {
            if a.state(id).await == DeliveryState::Delivered {
                n += 1;
            }
        }
        n
    };
    assert_eq!(delivered, 2, "the refused message is not acked");
    let st = b.node.network_status(false).await.unwrap();
    assert!(st.detail.contains("inbox saturated"));
    // free space: acknowledge does not free; prune frees via retention
    w.advance(169 * 3600 * 1000 - 1000); // beyond retention for old rows, message TTL (1 day) has passed too
                                         // new message from a: TTL is fresh
    b.node.step_maintenance().unwrap();
    assert_eq!(b.n("inbox"), 0);
    let late = a.send(&b, "late").await;
    settle(&[&a, &b]).await;
    assert_eq!(a.state(&late.message_id).await, DeliveryState::Delivered);
    assert_eq!(b.n("inbox"), 1);
}

#[tokio::test]
async fn isolation_violation_blocks_everything_until_cleared() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let r = a.send(&b, "held").await;
    a.transport
        .set_isolation_violation(Some("peer outside allowlist"));
    let rep = a.node.step_send().await.unwrap();
    assert_eq!(rep.published, 0);
    assert!(rep.deferred);
    assert!(a.node.step_receive().await.is_err());
    let st = a.node.network_status(false).await.unwrap();
    assert!(st.isolation_violation.is_some());
    assert!(!st.ready);
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Queued);
    assert_eq!(w.net.total_publish_count(), 0);
    a.transport.set_isolation_violation(None);
    // not penalized with backoff: goes out immediately
    assert_eq!(a.node.step_send().await.unwrap().published, 1);
    settle(&[&a, &b]).await;
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
    // history sync is blocked as well
    b.transport.set_isolation_violation(Some("x"));
    let rep = b.node.step_history_sync().await.unwrap();
    assert!(!rep.completed);
}

#[tokio::test]
async fn opening_store_with_different_identity_is_refused() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let path = a.store_path.clone();
    a.node.close();
    let other = Identity::generate_default(w.now_ms()).unwrap();
    let err = Node::open(
        other,
        &path,
        Arc::new(w.net.endpoint()),
        cfg(),
        Arc::new(w.clock.clone()),
    )
    .unwrap_err();
    match err {
        NodeError::IdentityMismatch { stored, .. } => assert_eq!(stored, a.addr),
        e => panic!("unexpected {e:?}"),
    }
    assert!(err_text(&path, &w).contains("refusing to run"));
    // the right identity opens
    let id = Identity::load(&a.id_path).unwrap();
    Node::open(
        id,
        &path,
        Arc::new(w.net.endpoint()),
        cfg(),
        Arc::new(w.clock.clone()),
    )
    .unwrap();
}

fn err_text(path: &std::path::Path, w: &World) -> String {
    let other = Identity::generate_default(w.now_ms()).unwrap();
    Node::open(
        other,
        path,
        Arc::new(w.net.endpoint()),
        cfg(),
        Arc::new(w.clock.clone()),
    )
    .unwrap_err()
    .to_string()
}

#[tokio::test]
async fn invalid_config_is_refused() {
    let w = World::new();
    let mut c = NodeConfig::default();
    c.delivery.retry_max_ms = 1;
    let id = Identity::generate_default(w.now_ms()).unwrap();
    let e = Node::open(
        id,
        &w.dir.path().join("x.sqlite"),
        Arc::new(w.net.endpoint()),
        c,
        Arc::new(w.clock.clone()),
    )
    .unwrap_err();
    assert!(matches!(e, NodeError::Config(_)));
    assert!(serde_json::from_str::<NodeConfig>(r#"{"bogus":1}"#).is_err());
    assert!(
        serde_json::from_str::<NodeConfig>(r#"{"policy":{"unknown_senders":"reject"}}"#).is_ok()
    );
}

#[tokio::test]
async fn disk_failure_inbound_not_acked_then_recovered() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    let r = a.send(&b, "disk").await;
    a.node.step_send().await.unwrap();
    let mut hints = b.node.changes();
    b.node.inject_store_failures(1);
    let rep = b.node.step_receive().await.unwrap();
    assert_eq!(rep.polled, 1);
    assert_eq!(rep.store_failures, 1);
    assert!(
        hints.try_recv().is_err(),
        "no notification without persistence"
    );
    assert_eq!(b.n("inbox"), 0);
    assert_eq!(b.n("outbox"), 0, "no ack queued");
    // API calls fail with a sanitized Internal error while the disk is bad
    b.node.inject_store_failures(1);
    let e = b
        .node
        .acknowledge_message("whatever".into())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Internal);
    assert_eq!(e.message, "storage error");
    let e = a_send_to(&b, &w).await;
    assert_eq!(e.code, ErrorCode::Internal);
    b.node.inject_store_failures(0);
    // the live frame is gone from the queue; history recovers it
    w.advance(1000);
    let rep = b.node.step_history_sync().await.unwrap();
    assert!(rep.completed);
    assert_eq!(b.inbox().await.len(), 1);
    settle(&[&a, &b]).await;
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
    // a failure during history leaves the watermark alone
    let wm = b.node.debug_history_watermark().unwrap();
    a.send(&b, "again").await;
    a.node.step_send().await.unwrap();
    w.advance(1000);
    b.node.inject_store_failures(1);
    let rep = b.node.step_history_sync().await.unwrap();
    assert!(!rep.completed);
    assert_eq!(b.node.debug_history_watermark().unwrap(), wm);
}

async fn a_send_to(b: &Agent, w: &World) -> ApiError {
    // b sends to itself-less stranger path: use a contact that exists
    let c = w.agent("c-disk", cfg());
    b.add(&c).await;
    b.node.inject_store_failures(1);
    b.send_err(SendMessageRequest {
        recipient: c.addr.clone(),
        body: "x".into(),
        ..Default::default()
    })
    .await
}

#[tokio::test]
async fn self_send_works_through_relay_echo() {
    let w = World::new();
    let a = w.agent("a", cfg());
    a.node.step_receive().await.unwrap();
    let r = a.send(a_as_target(&a), "note to self").await;
    settle(&[&a]).await;
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
    let inbox = a.inbox().await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].sender, a.addr);
}

fn a_as_target(a: &Agent) -> &Agent {
    a
}

#[tokio::test]
async fn contact_management() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    let info = a
        .node
        .add_contact(AddContactRequest {
            contact_record: b.record.clone(),
            expected_address: Some(b.addr.clone()),
            alias: Some("bee".into()),
            trust: None,
        })
        .await
        .unwrap();
    assert_eq!(info.trust, Trust::Trusted);
    assert!(!info.updated);
    // same record again: no change
    let again = a
        .node
        .add_contact(AddContactRequest {
            contact_record: b.record.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!again.updated);
    assert_eq!(again.alias.as_deref(), Some("bee"));
    // wrong expected address
    let c = w.agent("c", cfg());
    let e = a
        .node
        .add_contact(AddContactRequest {
            contact_record: c.record.clone(),
            expected_address: Some(b.addr.clone()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    // garbage and tampered record
    assert!(a
        .node
        .add_contact(AddContactRequest {
            contact_record: "{}".into(),
            ..Default::default()
        })
        .await
        .is_err());
    let tampered = b.record.replacen("sig\":\"", "sig\":\"A", 1);
    assert!(a
        .node
        .add_contact(AddContactRequest {
            contact_record: tampered,
            ..Default::default()
        })
        .await
        .is_err());
    // own record refused
    assert!(a
        .node
        .add_contact(AddContactRequest {
            contact_record: a.record.clone(),
            ..Default::default()
        })
        .await
        .is_err());
    // newer record replaces; older refused
    let mut id = Identity::load(&b.id_path).unwrap();
    w.advance(10_000);
    id.rotate_kem(w.now_ms(), w.now_ms() + 3_600_000, None)
        .unwrap();
    let newer = id.contact_record().to_document();
    let up = a
        .node
        .add_contact(AddContactRequest {
            contact_record: newer,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(up.updated);
    let e = a
        .node
        .add_contact(AddContactRequest {
            contact_record: b.record.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    assert_eq!(a.node.list_contacts().await.unwrap().len(), 1);
    assert_eq!(
        a.node
            .set_contact_trust(&b.addr, Trust::Unknown)
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        a.node
            .set_contact_trust(&c.addr, Trust::Blocked)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert!(a.node.remove_contact(&b.addr).unwrap());
    assert!(!a.node.remove_contact(&b.addr).unwrap());
    // identity api
    let idn = a.node.get_identity().await.unwrap();
    assert_eq!(idn.agent_id, a.addr);
    assert_eq!(idn.contact_record, a.record);
}

/// Review finding 4: published acks (and re-acks) are terminal and must be
/// pruned after the retention window instead of staying `sent` forever.
#[tokio::test]
async fn published_acks_and_reacks_are_pruned_after_retention() {
    let w = World::new();
    let (a, b) = pair(&w).await;
    a.send(&b, "hello").await;
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    // the first ack is lost, so A retries and B re-acks once the interval passed
    b.transport.drop_next_publishes(1);
    b.node.step_send().await.unwrap();
    w.advance(40_000);
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    b.node.step_send().await.unwrap();
    assert!(b.metric("ack.requeued") >= 1);
    assert_eq!(b.n("outbox"), 2, "ack and re-ack rows exist");

    // well past the retention window (and every TTL)
    w.advance(200 * 3_600_000);
    b.node.step_maintenance().unwrap();
    assert_eq!(b.n("outbox"), 0, "published acks must be pruned");
}

#[allow(dead_code)]
fn _t(_: &MockNetwork, _: &dyn Transport) {}
