//! Replay, forgery, tampering, shared-bucket frames, sender policy and ack rules.

mod common;

use agentnet_core::api::*;
use agentnet_core::config::UnknownSenders;
use agentnet_core::contact::VerifiedContact;
use agentnet_core::crypto::protection::seal;
use agentnet_core::crypto::testing as t;
use agentnet_core::envelope::{Envelope, MESSAGE_TYPE_ACK_RECEIVED, MESSAGE_TYPE_MESSAGE};
use agentnet_core::identity::Identity;
use agentnet_core::FrameOutcome;
use agentnet_transport::{ContentTopic, FrameSource, InboundFrame};
use common::*;

struct Forge<'a> {
    w: &'a World,
}

impl Forge<'_> {
    fn envelope(&self, from: &Identity, to: &Agent, ty: &str, body: &str, ttl_ms: i64) -> Envelope {
        let vc = VerifiedContact::parse_and_verify(&to.record, self.w.now_ms()).unwrap();
        Envelope::new(
            from.address(),
            vc.address,
            ty,
            body.into(),
            self.w.now_ms(),
            ttl_ms,
        )
        .unwrap()
    }
    fn seal(&self, from: &Identity, to: &Agent, env: &Envelope) -> Vec<u8> {
        let vc = VerifiedContact::parse_and_verify(&to.record, self.w.now_ms()).unwrap();
        seal(from, &vc, env, self.w.now_ms(), 150_000).unwrap()
    }
    fn topic(&self, to: &Agent) -> ContentTopic {
        VerifiedContact::parse_and_verify(&to.record, self.w.now_ms())
            .unwrap()
            .inbox_topic()
    }
    fn inject(&self, to: &Agent, frame: &[u8]) {
        self.w.net.inject_raw(&self.topic(to), frame);
    }
    fn message(&self, from: &Identity, to: &Agent, body: &str) -> Vec<u8> {
        let env = self.envelope(from, to, MESSAGE_TYPE_MESSAGE, body, 3_600_000);
        self.seal(from, to, &env)
    }
}

fn frame(payload: Vec<u8>, id: u8) -> InboundFrame {
    InboundFrame {
        topic: ContentTopic::new("/agentnet/1/inbox-00/proto").unwrap(),
        payload,
        timestamp_ns: 1,
        transport_id: [id; 32],
        source: FrameSource::Live,
    }
}

async fn started(w: &World, names: &[&str]) -> Vec<Agent> {
    let mut v = vec![];
    for n in names {
        v.push(w.agent(n, cfg()));
    }
    for a in &v {
        a.node.step_receive().await.unwrap();
    }
    v
}

#[tokio::test]
async fn replay_now_and_after_dedupe_pruning() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    let r = a
        .node
        .send_message(SendMessageRequest {
            recipient: b.addr.clone(),
            body: "once".into(),
            ttl_seconds: Some(60),
            ..Default::default()
        })
        .await
        .unwrap();
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    assert_eq!(b.n("inbox"), 1);
    let captured = w
        .net
        .published_frames()
        .into_iter()
        .find(|f| f.publisher == Some(a.transport.index()))
        .unwrap();
    let topic = captured.topic.clone();

    // replay now: re-injected (new transport id) -> duplicate, nothing new
    w.net.inject_raw(&topic, &captured.payload);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.n("inbox"), 1);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        1
    );
    assert!(b.metric("message.duplicate") >= 1);

    // after expiry + skew the `seen` row is pruned...
    assert_eq!(b.n("seen"), 1);
    w.advance(60_000 + 120_000 - 1);
    b.node.step_maintenance().unwrap();
    assert_eq!(b.n("seen"), 1, "kept until expires_at + clock_skew");
    w.advance(2);
    b.node.step_maintenance().unwrap();
    assert_eq!(b.n("seen"), 0, "pruned after expires_at + clock_skew");
    // ...and a replay is still rejected: by the time check in `open`.
    let before = b.n("inbox");
    w.net.inject_raw(&topic, &captured.payload);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.n("inbox"), before);
    assert_eq!(b.metric("open_error.expired"), 1);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        1
    );
    let _ = r;
}

#[tokio::test]
async fn tampered_foreign_forged_and_forwarded_frames_create_nothing() {
    let w = World::new();
    // everybody shares one topic and trial-decrypts everything
    let a = w.agent("a", cfg());
    let b = w.agent_sharing_topic("b", cfg(), &a);
    let c = w.agent_sharing_topic("c", cfg(), &a);
    for x in [&a, &b, &c] {
        x.node.step_receive().await.unwrap();
    }
    exchange(&a, &b).await;
    exchange(&a, &c).await;
    exchange(&b, &c).await;
    let f = Forge { w: &w };
    let a_id = Identity::load(&a.id_path).unwrap();
    let mallory = Identity::generate(w.now_ms()).unwrap();

    // frame for another agent in the same bucket: NotForUs, counted, nothing stored
    a.send(&c, "for c only").await;
    a.node.step_send().await.unwrap();
    let rep = b.node.step_receive().await.unwrap();
    assert_eq!(rep.polled, 1);
    assert_eq!(b.metric("frame.not_for_us"), 1);
    assert_eq!((b.n("inbox"), b.n("seen"), b.n("events")), (0, 0, 0));
    c.node.step_receive().await.unwrap();
    assert_eq!(c.n("inbox"), 1);

    // tampered ciphertext: AEAD fails -> NotForUs-class rejection, nothing stored
    let good = f.message(&a_id, &b, "tamper me");
    for pos in [1usize, 2, 3, 10, 40, 100, good.len() - 1] {
        let mut bad = good.clone();
        bad[pos] ^= 0x01;
        f.inject(&b, &bad);
    }
    b.node.step_receive().await.unwrap();
    assert_eq!((b.n("inbox"), b.n("events"), b.n("outbox")), (0, 0, 0));
    // every flipped frame is rejected by one counter or another (the first
    // not_for_us is c's frame above)
    let rejected: u64 = [
        "frame.not_for_us",
        "open_error.malformed",
        "open_error.truncated",
        "open_error.bad_structure",
        "open_error.bad_signature",
        "open_error.not_aead",
        "open_error.pkesk_not_v6",
        "open_error.malformed_payload",
        "open_error.unknown_sender",
    ]
    .iter()
    .map(|k| b.metric(k))
    .sum();
    assert!(rejected >= 8, "rejected {rejected}");

    // forged sender: the payload says A, the message is signed by Mallory (unknown to B)
    let mut env = f.envelope(&a_id, &b, MESSAGE_TYPE_MESSAGE, "forged", 3_600_000);
    env.sender = a_id.address();
    let vb = VerifiedContact::parse_and_verify(&b.record, w.now_ms()).unwrap();
    let forged = t::seal_payload(
        &mallory,
        &vb,
        &t::payload_for(&a_id, &env),
        w.now_ms(),
        t::BuildOpts::default(),
    )
    .unwrap();
    f.inject(&b, &forged);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.metric("open_error.unknown_sender"), 1);
    assert_eq!((b.n("inbox"), b.n("events")), (0, 0));

    // surreptitious forwarding: a message A signed for B, re-encrypted to C by B
    let to_b = f.message(&a_id, &b, "meant for b");
    let b_id = Identity::load(&b.id_path).unwrap();
    let vc = VerifiedContact::parse_and_verify(&c.record, w.now_ms()).unwrap();
    f.inject(&c, &t::forward(&b_id, &to_b, &vc, w.now_ms()).unwrap());
    let before = c.n("inbox");
    c.node.step_receive().await.unwrap();
    assert_eq!(c.metric("open_error.wrong_intended_recipient"), 1);
    assert_eq!(c.n("inbox"), before);
    assert_eq!(
        c.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        1
    );

    // garbage payloads
    for junk in [
        vec![],
        vec![0u8; 3],
        b"AN\x01\x01".to_vec(),
        vec![0xffu8; 700],
        vec![b'A', b'N', 1, 1]
            .into_iter()
            .chain(vec![7u8; 200])
            .collect(),
    ] {
        f.inject(&b, &junk);
    }
    b.node.step_receive().await.unwrap();
    assert_eq!(
        (b.n("inbox"), b.n("events"), b.n("outbox"), b.n("seen")),
        (0, 0, 0, 0)
    );
}

#[tokio::test]
async fn time_checks_skew_expiry_ttl() {
    let w = World::new();
    let b = started(&w, &["b"]).await.pop().unwrap();
    let f = Forge { w: &w };
    let m = Identity::generate_default(w.now_ms()).unwrap();
    let mid = b.node.set_contact_trust("an1x", Trust::Trusted).is_err();
    assert!(mid);
    b.node
        .add_contact(AddContactRequest {
            contact_record: m.contact_record().to_document(),
            ..Default::default()
        })
        .await
        .unwrap();
    let now = w.now_ms();
    let mk = |created: i64, expires: i64| {
        let mut e = f.envelope(&m, &b, MESSAGE_TYPE_MESSAGE, "t", 1000);
        e.created_at = created;
        e.expires_at = expires;
        f.seal(&m, &b, &e)
    };
    // already expired
    b.node.ingest_frame(&frame(mk(now - 10_000, now - 1), 1));
    assert_eq!(b.metric("open_error.expired"), 1);
    // within skew: accepted
    assert_eq!(
        b.node
            .ingest_frame(&frame(mk(now + 100_000, now + 200_000), 2)),
        FrameOutcome::Accepted
    );
    // beyond skew: deferred, not marked seen, accepted once time catches up
    let late = frame(mk(now + 600_000, now + 900_000), 3);
    assert_eq!(b.node.ingest_frame(&late), FrameOutcome::Deferred);
    assert_eq!(
        b.n("transport_seen"),
        1 /* only the expired one */ + 1 /* accepted */
    );
    w.advance(500_000);
    assert_eq!(b.node.ingest_frame(&late), FrameOutcome::Accepted);
    // TTL above the maximum
    let now = w.now_ms();
    assert_eq!(
        b.node
            .ingest_frame(&frame(mk(now, now + 8 * 86_400_000), 4)),
        FrameOutcome::Invalid
    );
    assert_eq!(b.metric("open_error.ttl_too_long"), 1);
    assert_eq!(b.n("inbox"), 2);
}

async fn unknown_sender_setup(
    policy: UnknownSenders,
    extra: impl FnOnce(&mut agentnet_core::NodeConfig),
) -> (World, Agent, Agent) {
    let w = World::new();
    let x = w.agent("x", cfg());
    let b = w.agent(
        "b",
        cfg_with(|c| {
            c.policy.unknown_senders = policy;
            extra(c);
        }),
    );
    x.add(&b).await; // X knows B; B does not know X
    x.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    (w, x, b)
}

#[tokio::test]
async fn quarantine_hides_message_and_emits_nothing() {
    let (w, x, b) = unknown_sender_setup(UnknownSenders::Quarantine, |_| {}).await;
    b.node
        .create_trigger(CreateTriggerRequest {
            target_session: "s1".into(),
            once: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    let r = x.send(&b, "hi from stranger").await;
    settle(&[&x, &b]).await;
    assert!(b.inbox().await.is_empty());
    assert_eq!(b.n("inbox"), 1);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        0
    );
    assert_eq!(b.n("outbox"), 0, "no ack");
    assert_eq!(x.state(&r.message_id).await, DeliveryState::Sent);
    let all = b
        .node
        .read_inbox(ReadInboxRequest {
            include_quarantined: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(all.records.len(), 1);
    assert!(all.records[0].quarantined);
    assert_eq!(all.records[0].sender_trust, Trust::Unknown);
    assert_eq!(
        b.node
            .network_status(false)
            .await
            .unwrap()
            .queue
            .inbox_quarantined,
        1
    );
    assert_eq!(b.node.list_quarantined().unwrap().len(), 1);
    assert_eq!(b.node.list_triggers(false).await.unwrap()[0].match_count, 0);
    // reading the conversation does not leak it
    assert!(b
        .node
        .read_conversation(r.conversation_id.clone(), PageRequest::default())
        .await
        .unwrap()
        .entries
        .is_empty());
    assert_eq!(
        b.node
            .acknowledge_message(r.message_id.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    // release requires trust first
    assert_eq!(
        b.node.release_quarantined(&r.message_id).unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        b.node.release_quarantined("nope").unwrap_err().code,
        ErrorCode::NotFound
    );
    b.add(&x).await;
    assert_eq!(b.node.release_quarantined(&r.message_id).unwrap(), 1);
    assert_eq!(b.inbox().await.len(), 1);
    assert_eq!(b.inbox().await[0].sender_trust, Trust::Trusted);
    let ev = b
        .node
        .read_events(PageRequest::default())
        .await
        .unwrap()
        .events;
    assert_eq!(
        ev.len(),
        1,
        "message.received at release, no retroactive trigger match"
    );
    assert_eq!(ev[0].event_type, EventType::MessageReceived);
    // ack flows after release; the sender's retry is a duplicate that is re-acked
    w.advance(10_000);
    settle(&[&x, &b]).await;
    assert_eq!(x.state(&r.message_id).await, DeliveryState::Delivered);
    assert_eq!(b.inbox().await.len(), 1);
}

#[tokio::test]
async fn reject_blocked_accept_untrusted_and_quarantine_cap() {
    // reject
    let (_w, x, b) = unknown_sender_setup(UnknownSenders::Reject, |_| {}).await;
    x.send(&b, "r").await;
    settle(&[&x, &b]).await;
    assert_eq!(
        (b.n("inbox"), b.n("events"), b.n("outbox"), b.n("seen")),
        (0, 0, 0, 0)
    );
    assert_eq!(b.metric("drop.rejected_unknown_sender"), 1);

    // accept: stored normally, trust recorded unknown, event, but no ack (no contact record)
    let (_w, x, b) = unknown_sender_setup(UnknownSenders::Accept, |_| {}).await;
    let r = x.send(&b, "a").await;
    settle(&[&x, &b]).await;
    let inbox = b.inbox().await;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].sender_trust, Trust::Unknown);
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        1
    );
    assert_eq!(b.n("outbox"), 0);
    assert_eq!(x.state(&r.message_id).await, DeliveryState::Sent);
    assert_eq!(b.metric("ack.no_contact"), 1);
    // an accepted-unknown sender never matches triggers
    b.node
        .create_trigger(CreateTriggerRequest {
            target_session: "s1".into(),
            once: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    x.send(&b, "a2").await;
    settle(&[&x, &b]).await;
    assert_eq!(
        b.node
            .read_events(PageRequest::default())
            .await
            .unwrap()
            .events
            .len(),
        2
    );

    // blocked
    let w = World::new();
    let (x, b) = (w.agent("x", cfg()), w.agent("b", cfg()));
    exchange(&x, &b).await;
    x.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    b.node.set_contact_trust(&x.addr, Trust::Blocked).unwrap();
    x.send(&b, "blocked").await;
    settle(&[&x, &b]).await;
    assert_eq!((b.n("inbox"), b.n("events"), b.n("outbox")), (0, 0, 0));
    assert_eq!(b.metric("drop.blocked"), 1);

    // untrusted contact: quarantine under default policy, normal (and acked) under accept
    b.node.set_contact_trust(&x.addr, Trust::Untrusted).unwrap();
    x.send(&b, "untrusted").await;
    w.advance(5_000);
    settle(&[&x, &b]).await;
    // (the sender's retry of the earlier, blocked message is quarantined too: the
    // block-time drop was final for that frame, not for its retries)
    assert_eq!(b.n("inbox"), 2);
    assert!(b.inbox().await.is_empty());
    let ev = b
        .node
        .read_events(PageRequest::default())
        .await
        .unwrap()
        .events;
    assert!(ev.is_empty());
    let q = b.node.list_quarantined().unwrap();
    assert_eq!(q[0].sender_trust, Trust::Untrusted);

    let (_w2, x2, b2) = unknown_sender_setup(UnknownSenders::Accept, |_| {}).await;
    b2.add(&x2).await;
    b2.node
        .set_contact_trust(&x2.addr, Trust::Untrusted)
        .unwrap();
    let r = x2.send(&b2, "u").await;
    settle(&[&x2, &b2]).await;
    assert_eq!(b2.inbox().await[0].sender_trust, Trust::Untrusted);
    assert_eq!(
        x2.state(&r.message_id).await,
        DeliveryState::Delivered,
        "contact held -> acked"
    );

    // quarantine cap
    let (_w, x, b) = unknown_sender_setup(UnknownSenders::Quarantine, |c| {
        c.storage.max_quarantined = 2
    })
    .await;
    for i in 0..3 {
        x.send(&b, &format!("q{i}")).await;
    }
    settle(&[&x, &b]).await;
    assert_eq!(b.n("inbox"), 2);
    assert_eq!(b.metric("drop.quarantine_full"), 1);
}

#[tokio::test]
async fn ack_rules_wrong_party_unknown_id_untrusted_and_no_ping_pong() {
    let w = World::new();
    let mut v = started(&w, &["a", "b", "c"]).await;
    let (c, b, a) = (v.pop().unwrap(), v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    exchange(&a, &c).await;
    let f = Forge { w: &w };
    let c_id = Identity::load(&c.id_path).unwrap();
    let r = a.send(&b, "to b").await;
    a.node.step_send().await.unwrap();

    let ack_from = |who: &Identity, corr: &str| {
        let mut e = f.envelope(who, &a, MESSAGE_TYPE_ACK_RECEIVED, "", 3_600_000);
        e.correlation_id = Some(corr.into());
        f.seal(who, &a, &e)
    };
    // C (trusted by A) acks a message that was sent to B: wrong party
    f.inject(&a, &ack_from(&c_id, &r.message_id));
    // B acks an id A never sent
    let b_id = Identity::load(&b.id_path).unwrap();
    f.inject(&a, &ack_from(&b_id, "11111111-1111-4111-8111-111111111111"));
    // a stranger acks (not a contact)
    let stranger = Identity::generate_default(w.now_ms()).unwrap();
    f.inject(&a, &ack_from(&stranger, &r.message_id));
    a.node.step_receive().await.unwrap();
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Sent);
    assert_eq!(a.metric("ack.ignored_wrong_party"), 1);
    assert_eq!(a.metric("ack.ignored_unknown_id"), 1);
    // a receipt from a stranger carries no certificate: it cannot be authenticated at all
    assert_eq!(a.metric("open_error.unknown_sender"), 1);
    assert_eq!(a.n("inbox"), 0, "acks never enter the inbox");
    assert_eq!(a.n("events"), 0);

    // a Blocked sender's ack is dropped too
    a.node.set_contact_trust(&c.addr, Trust::Blocked).unwrap();
    f.inject(&a, &ack_from(&c_id, &r.message_id));
    a.node.step_receive().await.unwrap();
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Sent);
    a.node.set_contact_trust(&c.addr, Trust::Trusted).unwrap();

    // the real ack works and converges; afterwards no further publishes ever happen
    let base = w.net.total_publish_count();
    settle(&[&a, &b, &c]).await;
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
    let settled = w.net.total_publish_count();
    assert_eq!(
        settled,
        base + 1,
        "exactly one ack was published after the message"
    );
    for _ in 0..10 {
        w.advance(120_000);
        settle(&[&a, &b, &c]).await;
        a.node.step_maintenance().unwrap();
        b.node.step_maintenance().unwrap();
    }
    assert_eq!(
        w.net.total_publish_count(),
        settled,
        "no ack ping-pong, no retries after delivery"
    );
    // the ack is not acked: A queued nothing for it
    assert_eq!(a.n("outbox"), 1);
    // idempotent: re-injecting the captured real ack changes nothing
    let ack = w
        .net
        .published_frames()
        .into_iter()
        .find(|p| p.publisher == Some(b.transport.index()))
        .unwrap();
    w.net.inject_raw(&ack.topic, &ack.payload);
    a.node.step_receive().await.unwrap();
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Delivered);
    assert_eq!(a.metric("ack.applied"), 1);
}

#[tokio::test]
async fn max_attempts_stops_publishing_until_expiry() {
    let w = World::new();
    let a = w.agent("a", cfg_with(|c| c.delivery.max_attempts = 3));
    let b = w.agent("b", cfg());
    exchange(&a, &b).await;
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    b.transport.set_online(false);
    let r = a
        .node
        .send_message(SendMessageRequest {
            recipient: b.addr.clone(),
            body: "x".into(),
            ttl_seconds: Some(3600),
            ..Default::default()
        })
        .await
        .unwrap();
    for _ in 0..10 {
        a.node.step_send().await.unwrap();
        w.advance(60_000);
    }
    let st = a
        .node
        .get_message_status(r.message_id.clone())
        .await
        .unwrap();
    assert_eq!(st.attempts, 3);
    assert_eq!(st.state, DeliveryState::Sent);
    assert_eq!(st.next_attempt_at, None);
    assert_eq!(w.net.total_publish_count(), 3);
    w.advance(3_600_000);
    a.node.step_maintenance().unwrap();
    assert_eq!(a.state(&r.message_id).await, DeliveryState::Expired);
}

#[tokio::test]
async fn too_large_publish_is_permanent_failure() {
    let w = World::new();
    let (a, b) = (w.agent("a", cfg()), w.agent("b", cfg()));
    exchange(&a, &b).await;
    let r = a.send(&b, "x").await;
    w.net.set_max_payload_len(10); // the relay now refuses what was sealed earlier
    a.node.step_send().await.unwrap();
    let st = a.node.get_message_status(r.message_id).await.unwrap();
    assert_eq!(st.state, DeliveryState::Failed);
    assert!(st.last_error.is_some());
}

/// Review finding 5: a quarantine full of heavily escaped bodies is listed in
/// pages whose serialized size stays under the byte budget (the unpaged
/// response of 1000 such messages is about 80 MB, above the 64 MiB socket line
/// limit; 200 of them were measured at 16.1 MB).
#[tokio::test]
async fn quarantine_listing_is_paged_within_a_byte_budget() {
    let (_w, x, b) = unknown_sender_setup(UnknownSenders::Quarantine, |_| {}).await;
    let body = "\"".repeat(60_000);
    b.transport.set_live_capacity(1000);
    let total = 80usize;
    for _ in 0..total {
        x.send(&b, &body).await;
    }
    for _ in 0..10 {
        x.node.step_send().await.unwrap();
        b.node.step_receive().await.unwrap();
    }
    assert_eq!(b.n("inbox"), total as u64);
    let mut seen = std::collections::HashSet::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let page = b
            .node
            .list_quarantined_page(PageRequest {
                cursor: cursor.clone(),
                limit: Some(200),
            })
            .unwrap();
        let bytes = serde_json::to_vec(&page).unwrap().len();
        assert!(
            bytes <= agentnet_core::api::MAX_QUARANTINE_PAGE_BYTES + 4096,
            "page of {bytes} bytes exceeds the budget"
        );
        assert!(!page.records.is_empty());
        pages += 1;
        for r in &page.records {
            assert!(seen.insert(r.message_id.clone()), "no record twice");
        }
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(seen.len(), total);
    assert!(pages >= 2, "the byte budget must split the listing");
    // a small limit pages too and a bad cursor is refused
    let p = b
        .node
        .list_quarantined_page(PageRequest {
            cursor: None,
            limit: Some(7),
        })
        .unwrap();
    assert_eq!(p.records.len(), 7);
    assert!(p.has_more);
    assert!(b
        .node
        .list_quarantined_page(PageRequest {
            cursor: Some("zz".into()),
            limit: None,
        })
        .is_err());
}

const SHARED_ID: &str = "22222222-2222-4222-8222-222222222222";

#[tokio::test]
async fn get_message_follows_inbox_visibility_and_disambiguates_senders() {
    let w = World::new();
    let mut v = started(&w, &["a", "b", "c"]).await;
    let (c, b, a) = (v.pop().unwrap(), v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    exchange(&a, &c).await;
    let r = b.send(&a, "hello a").await;
    settle(&[&a, &b, &c]).await;

    // Found by the id an event carries; fetching does not acknowledge.
    let ev = a
        .node
        .read_events(PageRequest::default())
        .await
        .unwrap()
        .events;
    assert_eq!(ev[0].message_id, r.message_id);
    let rec = a
        .node
        .get_message(GetMessageRequest {
            message_id: ev[0].message_id.clone(),
            sender: None,
        })
        .await
        .unwrap();
    assert_eq!(
        (rec.body.as_str(), rec.sender.as_str()),
        ("hello a", b.addr.as_str())
    );
    assert!(!rec.acknowledged && !rec.quarantined);
    let by_sender = a
        .node
        .get_message(GetMessageRequest {
            message_id: r.message_id.clone(),
            sender: Some(b.addr.clone()),
        })
        .await
        .unwrap();
    assert_eq!(by_sender, rec);

    // Not found, and the wrong sender is not found.
    let req = |id: &str, sender: Option<&str>| GetMessageRequest {
        message_id: id.into(),
        sender: sender.map(str::to_string),
    };
    assert_eq!(
        a.node
            .get_message(req("nope", None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        a.node
            .get_message(req(&r.message_id, Some(&c.addr)))
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    // Two senders that chose the same message id: ambiguous without `sender`.
    let f = Forge { w: &w };
    let (b_id, c_id) = (
        Identity::load(&b.id_path).unwrap(),
        Identity::load(&c.id_path).unwrap(),
    );
    for (who, body) in [(&b_id, "from b"), (&c_id, "from c")] {
        let mut e = f.envelope(who, &a, MESSAGE_TYPE_MESSAGE, body, 3_600_000);
        e.message_id = SHARED_ID.into();
        f.inject(&a, &f.seal(who, &a, &e));
    }
    a.node.step_receive().await.unwrap();
    assert_eq!(
        a.node
            .get_message(req(SHARED_ID, None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let got = a
        .node
        .get_message(req(SHARED_ID, Some(&c.addr)))
        .await
        .unwrap();
    assert_eq!(got.body, "from c");
}

#[tokio::test]
async fn get_message_never_returns_quarantined_content() {
    let (_w, x, b) = unknown_sender_setup(UnknownSenders::Quarantine, |_| {}).await;
    let r = x.send(&b, "hi from stranger").await;
    settle(&[&x, &b]).await;
    assert_eq!(b.n("inbox"), 1);
    for sender in [None, Some(x.addr.clone())] {
        let e = b
            .node
            .get_message(GetMessageRequest {
                message_id: r.message_id.clone(),
                sender,
            })
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound, "quarantined is not visible");
        assert!(!e.message.contains("stranger"));
    }
    // Once the sender is trusted and the message released it is visible.
    b.add(&x).await;
    b.node.release_quarantined(&r.message_id).unwrap();
    let rec = b
        .node
        .get_message(GetMessageRequest {
            message_id: r.message_id.clone(),
            sender: None,
        })
        .await
        .unwrap();
    assert_eq!(rec.body, "hi from stranger");
}
