//! The optional discovery feature on the engine: policy gating, signed adverts,
//! sequence rules, caps, forgeries, topic confusion, history sync and schedule.

mod common;

use agentnet_core::api::*;
use agentnet_core::contact::VerifiedContact;
use agentnet_core::crypto::advert::{self, testing as advert_testing};
use agentnet_core::identity::Identity;
use agentnet_core::{FrameOutcome, NodeConfig, NodeOptions};
use agentnet_transport::{ContentTopic, FrameSource, InboundFrame};
use common::*;
use serde_json::json;

const TOPIC: &str = "general";

fn dcfg() -> NodeConfig {
    cfg_with(|c| {
        c.discovery.enabled = true;
        c.discovery.topics = vec![TOPIC.into(), "other".into()];
    })
}

fn dtopic(name: &str) -> ContentTopic {
    ContentTopic::new(format!("/agentnet/1/discovery-{name}/proto")).unwrap()
}

fn cap(name: &str, description: &str) -> Capability {
    Capability {
        name: name.into(),
        description: description.into(),
    }
}

fn adv(topic: &str, names: &[&str]) -> AdvertiseRequest {
    AdvertiseRequest {
        topic: topic.into(),
        capabilities: names.iter().map(|n| cap(n, "does a thing")).collect(),
        display_name: Some("Test Agent".into()),
        ttl_seconds: None,
    }
}

fn disc(topic: &str) -> DiscoverRequest {
    DiscoverRequest {
        topic: topic.into(),
        ..Default::default()
    }
}

/// An agent that has subscribed (so it receives live frames from now on).
async fn start(w: &World, name: &str, config: NodeConfig) -> Agent {
    let a = w.agent(name, config);
    a.node.step_receive().await.unwrap();
    a
}

/// Publish what is due and receive, a few rounds, for every agent.
async fn pump(agents: &[&Agent]) {
    for _ in 0..3 {
        for a in agents {
            a.node.step_adverts().await.unwrap();
            a.node.step_receive().await.unwrap();
        }
    }
}

fn identity(a: &Agent) -> Identity {
    Identity::load(&a.id_path).unwrap()
}

fn raw_frame(topic: &ContentTopic, payload: Vec<u8>, id: u8) -> InboundFrame {
    InboundFrame {
        topic: topic.clone(),
        payload,
        timestamp_ns: 1,
        transport_id: [id; 32],
        source: FrameSource::Live,
    }
}

/// Advert frames published on `topic`, oldest first.
fn published_adverts(w: &World, topic: &ContentTopic) -> Vec<Vec<u8>> {
    w.net
        .published_frames()
        .into_iter()
        .filter(|f| f.topic == *topic)
        .map(|f| f.payload)
        .collect()
}

fn record_json(
    address: &str,
    contact_record: &str,
    caps: serde_json::Value,
    seq: u64,
    now: i64,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "v": 3,
        "topic": TOPIC,
        "address": address,
        "contact_record": contact_record,
        "capabilities": caps,
        "display_name": "Forged",
        "issued_at": now,
        "expires_at": now + 3_600_000,
        "seq": seq,
    }))
    .unwrap()
}

// ---------------------------------------------------------------- policy

#[tokio::test]
async fn disabled_by_default_subscribes_to_nothing_and_denies_the_tools() {
    let w = World::new();
    let a = start(&w, "a", cfg()).await;
    assert!(!a.node.address().is_empty());
    for _ in 0..3 {
        a.node.step_receive().await.unwrap();
        a.node.step_history_sync().await.unwrap();
        a.node.step_adverts().await.unwrap();
    }
    // only the inbox topic is subscribed; nothing was published
    assert_eq!(a.transport.subscribed_topics().len(), 1);
    assert!(a.transport.subscribed_topics()[0]
        .as_str()
        .contains("inbox"));
    assert_eq!(w.net.total_publish_count(), 0);

    let e = a
        .node
        .advertise_agent(adv(TOPIC, &["x"]))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(
        e.message.contains("disabled by host policy"),
        "{}",
        e.message
    );
    let e = a.node.discover_agents(disc(TOPIC)).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(e.message.contains("disabled by host policy"));
    let e = a.node.withdraw_advert(TOPIC.into()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert_eq!(a.n("adverts"), 0);
    assert_eq!(w.net.total_publish_count(), 0);
}

#[tokio::test]
async fn enabled_subscribes_to_exactly_the_listed_topics() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let subs: Vec<String> = a
        .transport
        .subscribed_topics()
        .iter()
        .map(|t| t.to_string())
        .collect();
    assert_eq!(subs.len(), 3, "{subs:?}");
    assert!(subs.contains(&dtopic(TOPIC).to_string()));
    assert!(subs.contains(&dtopic("other").to_string()));
    assert!(subs.iter().any(|s| s.contains("inbox")));
}

#[tokio::test]
async fn a_topic_outside_the_host_list_is_denied() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let e = a
        .node
        .advertise_agent(adv("unlisted", &["x"]))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(e.message.contains("not an authorized discovery topic"));
    assert_eq!(
        a.node
            .discover_agents(disc("unlisted"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        a.node
            .withdraw_advert("unlisted".into())
            .await
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
    // a syntactically invalid name is an argument error
    assert_eq!(
        a.node
            .advertise_agent(adv("Bad Name", &["x"]))
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(w.net.total_publish_count(), 0);
}

#[tokio::test]
async fn request_validation() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let bad = |r: AdvertiseRequest| {
        let a = &a;
        async move { a.node.advertise_agent(r).await.unwrap_err().code }
    };
    assert_eq!(bad(adv(TOPIC, &[])).await, ErrorCode::InvalidArgument);
    assert_eq!(bad(adv(TOPIC, &["BAD"])).await, ErrorCode::InvalidArgument);
    assert_eq!(
        bad(adv(TOPIC, &["a", "a"])).await,
        ErrorCode::InvalidArgument
    );
    let many: Vec<String> = (0..17).map(|i| format!("c{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(bad(adv(TOPIC, &many)).await, ErrorCode::InvalidArgument);
    let mut r = adv(TOPIC, &["a"]);
    r.capabilities[0].description = "x".repeat(257);
    assert_eq!(bad(r).await, ErrorCode::InvalidArgument);
    let mut r = adv(TOPIC, &["a"]);
    r.display_name = Some("x".repeat(65));
    assert_eq!(bad(r).await, ErrorCode::InvalidArgument);
    let mut r = adv(TOPIC, &["a"]);
    r.ttl_seconds = Some(0);
    assert_eq!(bad(r).await, ErrorCode::InvalidArgument);
    let mut r = disc(TOPIC);
    r.capability = Some("Not Valid".into());
    assert_eq!(
        a.node.discover_agents(r).await.unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let mut r = disc(TOPIC);
    r.cursor = Some("garbage".into());
    assert_eq!(
        a.node.discover_agents(r).await.unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(w.net.total_publish_count(), 0);
}

#[tokio::test]
async fn ttl_is_defaulted_and_capped() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let r = a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    assert_eq!(r.expires_at - r.issued_at, 3_600_000);
    let mut req = adv(TOPIC, &["x"]);
    req.ttl_seconds = Some(10 * 86_400);
    let r = a.node.advertise_agent(req).await.unwrap();
    assert_eq!(r.expires_at - r.issued_at, 86_400_000);
    let mut req = adv(TOPIC, &["x"]);
    req.ttl_seconds = Some(120);
    let r = a.node.advertise_agent(req).await.unwrap();
    assert_eq!(r.expires_at - r.issued_at, 120_000);
    assert_eq!(r.seq, 3);
}

// ------------------------------------------------------------- the happy path

#[tokio::test]
async fn advertise_then_another_node_discovers_it_and_can_add_the_contact() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    let info = a
        .node
        .advertise_agent(adv(TOPIC, &["translate.de", "summarize"]))
        .await
        .unwrap();
    assert_eq!(info.seq, 1);
    // nothing is published until the engine's send step runs
    assert_eq!(w.net.publish_count(&dtopic(TOPIC)), 0);
    pump(&[&a, &b]).await;
    assert_eq!(w.net.publish_count(&dtopic(TOPIC)), 1);

    // the frame is plaintext and carries the AD magic, never the sealed one
    let frames = published_adverts(&w, &dtopic(TOPIC));
    assert_eq!(&frames[0][..3], b"AD\x01");
    let doc = advert::decode_frame(&frames[0]).unwrap();
    let record = advert_testing::content_of(doc).unwrap();
    assert!(String::from_utf8(record).unwrap().contains("translate.de"));

    let page = b.node.discover_agents(disc(TOPIC)).await.unwrap();
    assert_eq!(page.agents.len(), 1);
    assert!(!page.has_more);
    let d = &page.agents[0];
    assert_eq!(d.address, a.addr);
    assert_eq!(d.display_name.as_deref(), Some("Test Agent"));
    assert_eq!(
        d.capabilities
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        ["translate.de", "summarize"]
    );
    assert_eq!(d.expires_at, info.expires_at);
    assert!(!d.is_contact);
    assert_eq!(d.trust, Trust::Unknown);
    assert_eq!(d.contact_record, a.record);

    // the advertiser sees nobody else, and not itself
    assert!(a
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .is_empty());
    // another topic is separate
    assert!(b
        .node
        .discover_agents(disc("other"))
        .await
        .unwrap()
        .agents
        .is_empty());

    // the embedded contact record is valid and add_contact accepts it
    let c = b
        .node
        .add_contact(AddContactRequest {
            contact_record: d.contact_record.clone(),
            expected_address: Some(d.address.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(c.address, a.addr);
    let after = b.node.discover_agents(disc(TOPIC)).await.unwrap();
    assert!(after.agents[0].is_contact);
    assert_eq!(after.agents[0].trust, Trust::Trusted);
}

#[tokio::test]
async fn receiving_adverts_has_no_side_effects_on_contacts_events_or_triggers() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    pump(&[&a, &b]).await;
    assert_eq!(b.n("adverts"), 1);
    assert_eq!(b.n("contacts"), 0);
    assert_eq!(b.n("inbox"), 0);
    assert_eq!(b.n("events"), 0);
    assert_eq!(b.n("triggers"), 0);
    assert!(b.node.list_contacts().await.unwrap().is_empty());
    assert!(b
        .node
        .read_events(PageRequest::default())
        .await
        .unwrap()
        .events
        .is_empty());
    let mut hints = b.node.changes();
    pump(&[&a, &b]).await;
    assert!(
        hints.try_recv().is_err(),
        "an advert must emit no change hint"
    );

    // a discovered-but-not-added agent that messages us is an unknown sender:
    // the existing quarantine policy applies.
    a.add(&b).await;
    a.send(&b, "hello from a stranger").await;
    settle(&[&a, &b]).await;
    assert!(b.inbox().await.is_empty());
    assert_eq!(b.n("inbox"), 1);
    assert_eq!(b.metric("message.quarantined"), 1);
    assert_eq!(b.n("events"), 0);
}

#[tokio::test]
async fn own_publication_coming_back_is_ignored() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    pump(&[&a]).await;
    assert_eq!(a.metric("advert.ignored_own"), 1);
    assert_eq!(a.n("adverts"), 0);
}

#[tokio::test]
async fn capability_filter_is_an_exact_match_and_results_paginate() {
    let w = World::new();
    let obs = start(&w, "obs", dcfg()).await;
    let mut agents = Vec::new();
    for i in 0..5 {
        agents.push(start(&w, &format!("a{i}"), dcfg()).await);
    }
    let sets: [&[&str]; 5] = [
        &["translate"],
        &["translate.de", "code"],
        &["code"],
        &["translate", "code"],
        &["other-thing"],
    ];
    for (a, set) in agents.iter().zip(sets) {
        a.node.advertise_agent(adv(TOPIC, set)).await.unwrap();
    }
    let mut all: Vec<&Agent> = agents.iter().collect();
    all.push(&obs);
    pump(&all).await;
    assert_eq!(obs.n("adverts"), 5);

    let by_cap = |c: &str| {
        let mut r = disc(TOPIC);
        r.capability = Some(c.into());
        r
    };
    let addrs = |p: &DiscoverPage| {
        let mut v: Vec<String> = p.agents.iter().map(|a| a.address.clone()).collect();
        v.sort();
        v
    };
    let want = |idx: &[usize]| {
        let mut v: Vec<String> = idx.iter().map(|i| agents[*i].addr.clone()).collect();
        v.sort();
        v
    };
    let p = obs.node.discover_agents(by_cap("translate")).await.unwrap();
    assert_eq!(addrs(&p), want(&[0, 3]), "exact name, not a prefix");
    let p = obs.node.discover_agents(by_cap("code")).await.unwrap();
    assert_eq!(addrs(&p), want(&[1, 2, 3]));
    let p = obs
        .node
        .discover_agents(by_cap("translate.de"))
        .await
        .unwrap();
    assert_eq!(addrs(&p), want(&[1]));
    let p = obs.node.discover_agents(by_cap("nothing")).await.unwrap();
    assert!(p.agents.is_empty() && !p.has_more);

    // pagination: 2 per page covers all 5 exactly once
    let mut seen = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let mut r = disc(TOPIC);
        r.limit = Some(2);
        r.cursor = cursor.clone();
        let p = obs.node.discover_agents(r).await.unwrap();
        assert!(p.agents.len() <= 2);
        seen.extend(p.agents.iter().map(|a| a.address.clone()));
        cursor = p.next_cursor.clone();
        pages += 1;
        if !p.has_more {
            break;
        }
        assert!(pages < 10);
    }
    assert_eq!(pages, 3);
    seen.sort();
    assert_eq!(seen, want(&[0, 1, 2, 3, 4]));
    // a cursor from the last page yields nothing more
    let mut r = disc(TOPIC);
    r.cursor = cursor;
    assert!(obs.node.discover_agents(r).await.unwrap().agents.is_empty());
}

// ---------------------------------------------------------------- lifetime

#[tokio::test]
async fn expired_adverts_are_not_returned_and_are_pruned() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    let mut req = adv(TOPIC, &["x"]);
    req.ttl_seconds = Some(60);
    a.node.advertise_agent(req).await.unwrap();
    pump(&[&a, &b]).await;
    assert_eq!(
        b.node
            .discover_agents(disc(TOPIC))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );
    w.advance(59_000);
    assert_eq!(
        b.node
            .discover_agents(disc(TOPIC))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );
    w.advance(1_000);
    assert!(b
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .is_empty());
    assert_eq!(b.n("adverts"), 1, "still stored until maintenance runs");
    let rep = b.node.step_maintenance().unwrap();
    assert!(rep.pruned_rows >= 1);
    assert_eq!(b.n("adverts"), 0);
    // an expired advert replayed later is refused outright
    let old = published_adverts(&w, &dtopic(TOPIC)).remove(0);
    w.net.inject_raw(&dtopic(TOPIC), &old);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.n("adverts"), 0);
    assert_eq!(b.metric("advert.ignored_expired"), 1);
}

#[tokio::test]
async fn a_higher_seq_replaces_and_a_replay_of_an_older_one_is_ignored() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    a.node
        .advertise_agent(adv(TOPIC, &["old-cap"]))
        .await
        .unwrap();
    pump(&[&a, &b]).await;
    let first = published_adverts(&w, &dtopic(TOPIC)).remove(0);
    let second = a
        .node
        .advertise_agent(adv(TOPIC, &["new-cap"]))
        .await
        .unwrap();
    assert_eq!(second.seq, 2);
    pump(&[&a, &b]).await;
    let p = b.node.discover_agents(disc(TOPIC)).await.unwrap();
    assert_eq!(p.agents.len(), 1);
    assert_eq!(p.agents[0].capabilities[0].name, "new-cap");
    assert_eq!(b.n("adverts"), 1);
    assert_eq!(b.metric("advert.replaced"), 1);

    // replay of seq 1, and a repeat of seq 2: both ignored
    w.net.inject_raw(&dtopic(TOPIC), &first);
    let second_frame = published_adverts(&w, &dtopic(TOPIC)).pop().unwrap();
    w.net.inject_raw(&dtopic(TOPIC), &second_frame);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.metric("advert.ignored_stale"), 2);
    let p = b.node.discover_agents(disc(TOPIC)).await.unwrap();
    assert_eq!(p.agents[0].capabilities[0].name, "new-cap");
    assert_eq!(
        b.node
            .discover_agents({
                let mut r = disc(TOPIC);
                r.capability = Some("old-cap".into());
                r
            })
            .await
            .unwrap()
            .agents
            .len(),
        0
    );
}

#[tokio::test]
async fn withdrawal_removes_the_advert_and_blocks_a_replay() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    pump(&[&a, &b]).await;
    let old = published_adverts(&w, &dtopic(TOPIC)).remove(0);
    assert_eq!(
        b.node
            .discover_agents(disc(TOPIC))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );

    let r = a.node.withdraw_advert(TOPIC.into()).await.unwrap();
    assert!(r.withdrawn);
    pump(&[&a, &b]).await;
    assert!(b
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .is_empty());
    assert_eq!(b.metric("advert.withdrawal_applied"), 1);
    // the tombstone row stays so that the old advert cannot come back
    assert_eq!(b.n("adverts"), 1);
    w.net.inject_raw(&dtopic(TOPIC), &old);
    b.node.step_receive().await.unwrap();
    assert!(b
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .is_empty());
    assert_eq!(b.metric("advert.ignored_stale"), 1);

    // idempotent; and nothing is published any more
    let again = a.node.withdraw_advert(TOPIC.into()).await.unwrap();
    assert!(!again.withdrawn);
    let before = w.net.publish_count(&dtopic(TOPIC));
    w.advance(3_000_000);
    pump(&[&a, &b]).await;
    assert_eq!(w.net.publish_count(&dtopic(TOPIC)), before);

    // advertising again continues the sequence and is visible again
    let r = a.node.advertise_agent(adv(TOPIC, &["y"])).await.unwrap();
    assert_eq!(r.seq, 3);
    pump(&[&a, &b]).await;
    assert_eq!(
        b.node
            .discover_agents(disc(TOPIC))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );
    // withdrawing something never advertised is a no-op
    assert!(
        !a.node
            .withdraw_advert("other".into())
            .await
            .unwrap()
            .withdrawn
    );
}

#[tokio::test]
async fn the_sequence_number_survives_a_restart() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    assert_eq!(
        a.node
            .advertise_agent(adv(TOPIC, &["x"]))
            .await
            .unwrap()
            .seq,
        1
    );
    assert_eq!(
        a.node
            .advertise_agent(adv(TOPIC, &["x"]))
            .await
            .unwrap()
            .seq,
        2
    );
    let a = w.reopen(a, dcfg());
    assert_eq!(
        a.node
            .advertise_agent(adv(TOPIC, &["x"]))
            .await
            .unwrap()
            .seq,
        3
    );
    assert_eq!(
        a.node
            .advertise_agent(adv("other", &["x"]))
            .await
            .unwrap()
            .seq,
        1
    );
}

#[tokio::test]
async fn republish_schedule_follows_the_interval_until_expiry() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let t = dtopic(TOPIC);
    let mut req = adv(TOPIC, &["x"]);
    req.ttl_seconds = Some(2400);
    a.node.advertise_agent(req).await.unwrap();
    assert_eq!(a.node.step_adverts().await.unwrap(), 1);
    assert_eq!(w.net.publish_count(&t), 1);
    assert_eq!(a.node.step_adverts().await.unwrap(), 0);
    w.advance(899_000);
    assert_eq!(a.node.step_adverts().await.unwrap(), 0);
    w.advance(1_000);
    assert_eq!(a.node.step_adverts().await.unwrap(), 1);
    assert_eq!(w.net.publish_count(&t), 2);
    w.advance(900_000);
    assert_eq!(a.node.step_adverts().await.unwrap(), 1);
    assert_eq!(w.net.publish_count(&t), 3);
    // t = 1800 s; the advert expires at 2400 s, before the next due time (2700 s)
    w.advance(900_000);
    assert_eq!(a.node.step_adverts().await.unwrap(), 0, "expired: no more");
    w.advance(10_000_000);
    assert_eq!(a.node.step_adverts().await.unwrap(), 0);
    assert_eq!(w.net.publish_count(&t), 3);
}

#[tokio::test]
async fn a_failed_publish_is_retried_soon() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    a.transport.fail_next_publishes(1);
    assert_eq!(a.node.step_adverts().await.unwrap(), 0);
    assert_eq!(a.metric("advert.publish_error"), 1);
    assert_eq!(a.node.step_adverts().await.unwrap(), 0, "retry is delayed");
    w.advance(30_000);
    assert_eq!(a.node.step_adverts().await.unwrap(), 1);
}

// ---------------------------------------------------------------- forgeries

#[tokio::test]
async fn forged_adverts_are_rejected_and_counted() {
    let w = World::new();
    let victim = start(&w, "victim", dcfg()).await;
    let evil = start(&w, "evil", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    let now = w.now_ms();
    let vid = identity(&victim);
    let eid = identity(&evil);
    let caps = json!([{"name": "steal", "description": "d"}]);
    let inject = |doc: String| {
        w.net
            .inject_raw(&dtopic(TOPIC), &advert::encode_frame(&doc));
    };

    // 1. victim's address + record, signed by the attacker's key
    inject(advert_testing::sign_record_as(
        &eid,
        &record_json(&victim.addr, &victim.record, caps.clone(), 1, now),
        now,
    ));
    // 2. attacker's own address but embedding the victim's contact record
    inject(advert_testing::sign_record_as(
        &eid,
        &record_json(&evil.addr, &victim.record, caps.clone(), 1, now),
        now,
    ));
    // 3. victim's address, attacker's contact record (and attacker's signature)
    inject(advert_testing::sign_record_as(
        &eid,
        &record_json(&victim.addr, &evil.record, caps.clone(), 1, now),
        now,
    ));
    // 4. a genuine advert with a tampered capability and the original signature
    let honest = vid
        .create_advert(
            &advert::AdvertContent {
                topic: TOPIC,
                capabilities: &[cap("honest", "d")],
                display_name: None,
                issued_at: now,
                expires_at: now + 60_000,
                seq: 9,
            },
            &agentnet_core::crypto::AdvertLimits {
                max_ttl_ms: 86_400_000,
                clock_skew_ms: 120_000,
                max_capabilities: 16,
            },
        )
        .unwrap();
    // flip one byte inside the signed message
    let mut msg = advert_testing::message_bytes(&honest.to_document()).unwrap();
    let mid = msg.len() / 2;
    msg[mid] ^= 0x01;
    inject(advert_testing::document_from_bytes(&msg));
    // 5. a signed message whose content is a different record than the one it was made for
    //    (an unrelated, valid signed message by the attacker is no advertisement of the victim)
    inject(advert_testing::sign_record_as(
        &eid,
        b"{\"v\":3,\"hello\":true}",
        now,
    ));
    // 6. an unsigned-looking structure and a version from the future
    inject("AAAA".into());
    inject(advert_testing::sign_record_as(
        &vid,
        &serde_json::to_vec(&json!({"v": 4})).unwrap(),
        now,
    ));

    b.node.step_receive().await.unwrap();
    assert_eq!(b.n("adverts"), 0);
    assert!(b
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .is_empty());
    assert_eq!(b.metric("advert.received"), 7);
    // every forgery is rejected by some check; the counters add up to the 7 frames
    let invalid: u64 = [
        "bad_signature",
        "contact_address_mismatch",
        "bad_structure",
        "malformed",
        "unknown_version",
        "bad_contact",
        "topic_mismatch",
    ]
    .iter()
    .map(|k| b.metric(&format!("advert.invalid.{k}")))
    .sum();
    assert_eq!(invalid, 7);
    assert!(
        b.metric("advert.invalid.bad_signature") >= 1,
        "{:?}",
        b.node.metrics()
    );
    assert!(b.metric("advert.invalid.contact_address_mismatch") >= 1);
    assert_eq!(b.metric("advert.invalid.malformed"), 1);
    assert_eq!(b.metric("advert.invalid.unknown_version"), 1);
    assert_eq!(b.metric("advert.applied"), 0);
}

#[tokio::test]
async fn an_advert_replayed_onto_another_enabled_topic_is_rejected() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    pump(&[&a, &b]).await;
    assert_eq!(
        b.node
            .discover_agents(disc(TOPIC))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );
    let frame = published_adverts(&w, &dtopic(TOPIC)).remove(0);

    // an observer re-publishes the genuine frame on the other enabled topic
    w.net.inject_raw(&dtopic("other"), &frame);
    b.node.step_receive().await.unwrap();
    assert!(b
        .node
        .discover_agents(disc("other"))
        .await
        .unwrap()
        .agents
        .is_empty());
    assert_eq!(b.metric("advert.invalid.topic_mismatch"), 1);
    assert_eq!(b.metric("advert.applied"), 1);
    // the original listing is untouched, and a same-topic replay is just stale
    assert_eq!(
        b.node
            .discover_agents(disc(TOPIC))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );
    w.net.inject_raw(&dtopic(TOPIC), &frame);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.metric("advert.invalid.topic_mismatch"), 1);
    assert_eq!(b.metric("advert.ignored_stale"), 1);
}

#[tokio::test]
async fn a_withdrawal_replayed_onto_another_topic_does_not_remove_the_advert_there() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    a.node.advertise_agent(adv("other", &["y"])).await.unwrap();
    pump(&[&a, &b]).await;
    for t in [TOPIC, "other"] {
        assert_eq!(
            b.node.discover_agents(disc(t)).await.unwrap().agents.len(),
            1,
            "{t}"
        );
    }
    assert!(
        a.node
            .withdraw_advert(TOPIC.into())
            .await
            .unwrap()
            .withdrawn
    );
    let frames = published_adverts(&w, &dtopic(TOPIC));
    let withdrawal = frames.last().unwrap().clone();
    // deliver the withdrawal to B only on the topic it was signed for ...
    pump(&[&a, &b]).await;
    assert!(b
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .is_empty());
    assert_eq!(
        b.node
            .discover_agents(disc("other"))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );
    // ... and replay it onto the other topic: the advert there survives
    w.net.inject_raw(&dtopic("other"), &withdrawal);
    b.node.step_receive().await.unwrap();
    assert_eq!(
        b.node
            .discover_agents(disc("other"))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );
    assert_eq!(b.metric("advert.invalid.topic_mismatch"), 1);
    assert_eq!(b.metric("advert.withdrawal_applied"), 1);
}

#[tokio::test]
async fn a_topic_less_version_1_advert_is_rejected_not_accepted_for_any_topic() {
    let w = World::new();
    let victim = start(&w, "victim", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    let now = w.now_ms();
    let vid = identity(&victim);
    let old = serde_json::to_vec(&json!({
        "v": 1,
        "address": victim.addr,
        "contact_record": victim.record,
        "capabilities": [{"name": "x", "description": ""}],
        "issued_at": now,
        "expires_at": now + 3_600_000,
        "seq": 1,
    }))
    .unwrap();
    let doc = advert_testing::sign_record_as(&vid, &old, now);
    w.net
        .inject_raw(&dtopic(TOPIC), &advert::encode_frame(&doc));
    b.node.step_receive().await.unwrap();
    assert_eq!(b.metric("advert.invalid.unknown_version"), 1);
    assert_eq!(b.n("adverts"), 0);
}

#[tokio::test]
async fn garbage_oversize_and_malformed_frames_do_not_panic() {
    let w = World::new();
    let b = start(&w, "b", dcfg()).await;
    let t = dtopic(TOPIC);
    let mut payloads: Vec<Vec<u8>> = vec![
        vec![],
        b"A".to_vec(),
        b"AD".to_vec(),
        b"AD\x01".to_vec(),
        b"AD\x01{}".to_vec(),
        b"AD\x01null".to_vec(),
        b"AD\x02{\"record\":\"\",\"sig\":\"\"}".to_vec(),
        b"AD\x01\xff\xfe\xfd".to_vec(),
        b"AD\x01{\"record\":\"AAAA\",\"sig\":\"AAAA\"}".to_vec(),
        vec![0u8; 100],
        vec![b'{'; 100_000],
        [b"AD\x01".as_slice(), &vec![b'a'; 20_000]].concat(),
    ];
    for i in 0..64u8 {
        payloads.push((0..i).map(|j| j.wrapping_mul(31)).collect());
    }
    for (i, p) in payloads.iter().enumerate() {
        let f = raw_frame(&t, p.clone(), i as u8 + 1);
        let o = b.node.ingest_frame(&f);
        assert!(
            matches!(o, FrameOutcome::AdvertInvalid | FrameOutcome::Dropped),
            "{i}: {o:?}"
        );
    }
    assert_eq!(b.n("adverts"), 0);
    assert_eq!(b.metric("advert.applied"), 0);
}

#[tokio::test]
async fn adverts_and_sealed_frames_never_cross_topics() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    exchange(&a, &b).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    a.node.step_adverts().await.unwrap();
    let advert_frame = published_adverts(&w, &dtopic(TOPIC)).remove(0);
    a.send(&b, "sealed hello").await;
    a.node.step_send().await.unwrap();
    let sealed = w
        .net
        .published_frames()
        .into_iter()
        .find(|f| f.payload.first().is_some_and(|b| b & 0x80 != 0))
        .unwrap()
        .payload;
    let inbox_topic = ContentTopic::new(identity(&b).inbox_topic().to_string()).unwrap();

    // an advert frame on B's inbox topic
    let o = b
        .node
        .ingest_frame(&raw_frame(&inbox_topic, advert_frame.clone(), 1));
    assert_eq!(o, FrameOutcome::Dropped);
    assert_eq!(b.metric("advert.cross_topic.advert_on_inbox"), 1);
    // a sealed frame on a discovery topic
    let o = b
        .node
        .ingest_frame(&raw_frame(&dtopic(TOPIC), sealed.clone(), 2));
    assert_eq!(o, FrameOutcome::Dropped);
    assert_eq!(b.metric("advert.cross_topic.sealed_on_discovery"), 1);
    assert_eq!(b.n("adverts"), 0);
    assert_eq!(b.n("inbox"), 0);
    // neither dropped frame was misread as the other kind
    assert_eq!(b.metric("advert.invalid.bad_frame"), 0);
    // both in the live paths as well: inject through the network
    w.net.inject_raw(&dtopic(TOPIC), &sealed);
    w.net.inject_raw(&inbox_topic, &advert_frame);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.metric("advert.cross_topic.sealed_on_discovery"), 2);
    assert_eq!(b.metric("advert.cross_topic.advert_on_inbox"), 2);
    // the only stored advert is A's genuine one from its own topic
    assert_eq!(b.n("adverts"), 1);
    // and the real sealed message still arrives normally on the inbox topic
    settle(&[&a, &b]).await;
    assert_eq!(b.inbox().await.len(), 1);
}

// ------------------------------------------------------------------ limits

#[tokio::test]
async fn the_table_is_capped_by_evicting_the_soonest_expiring() {
    let w = World::new();
    let mut c = dcfg();
    c.discovery.max_records = 3;
    let obs = start(&w, "obs", c).await;
    let mut agents = Vec::new();
    for (i, ttl) in [100u64, 200, 300, 400, 50].into_iter().enumerate() {
        let a = start(&w, &format!("a{i}"), dcfg()).await;
        let mut r = adv(TOPIC, &["x"]);
        r.ttl_seconds = Some(ttl);
        a.node.advertise_agent(r).await.unwrap();
        a.node.step_adverts().await.unwrap();
        obs.node.step_receive().await.unwrap();
        agents.push(a);
    }
    // after a0..a2 the table is full; a3 (400 s) evicted a0 (100 s); a4 (50 s)
    // would expire before everything stored, so it is the one dropped.
    assert_eq!(obs.n("adverts"), 3);
    assert_eq!(obs.metric("advert.evicted"), 1);
    assert_eq!(obs.metric("advert.dropped_full"), 1);
    let found: Vec<String> = obs
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .into_iter()
        .map(|a| a.address)
        .collect();
    assert!(!found.contains(&agents[0].addr));
    assert!(!found.contains(&agents[4].addr));
    for i in [1, 2, 3] {
        assert!(found.contains(&agents[i].addr), "a{i}");
    }
    // a replacement from a stored address needs no room
    agents[1]
        .node
        .advertise_agent(adv(TOPIC, &["y"]))
        .await
        .unwrap();
    agents[1].node.step_adverts().await.unwrap();
    obs.node.step_receive().await.unwrap();
    assert_eq!(obs.n("adverts"), 3);
    assert_eq!(obs.metric("advert.evicted"), 1);
}

#[tokio::test]
async fn blocked_and_revoked_advertisers_are_dropped_purged_and_never_evict() {
    let w = World::new();
    let mut c = dcfg();
    c.discovery.max_records = 2;
    let obs = start(&w, "obs", c).await;
    let good1 = start(&w, "g1", dcfg()).await;
    let good2 = start(&w, "g2", dcfg()).await;
    let blocked = start(&w, "blk", dcfg()).await;
    let revoked = start(&w, "rev", dcfg()).await;
    for a in [&good1, &good2, &blocked, &revoked] {
        a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    }
    // block one advertiser before its advert arrives
    obs.node
        .add_contact(AddContactRequest {
            contact_record: blocked.record.clone(),
            trust: Some(Trust::Blocked),
            ..Default::default()
        })
        .await
        .unwrap();
    // import the tombstone of another
    let tomb = identity(&revoked)
        .create_revocation("key lost", w.now_ms())
        .unwrap()
        .to_document();
    obs.node.import_revocation(&tomb).unwrap();

    pump(&[&good1, &good2, &blocked, &revoked, &obs]).await;
    assert_eq!(obs.n("adverts"), 2, "only the two good ones");
    assert_eq!(obs.metric("advert.dropped_blocked"), 2);
    assert_eq!(obs.metric("advert.evicted"), 0);
    assert_eq!(obs.metric("advert.dropped_full"), 0);

    // later blocking purges what is stored, and discovery excludes it
    let before = obs
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .len();
    assert_eq!(before, 2);
    obs.node
        .add_contact(AddContactRequest {
            contact_record: good1.record.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    obs.node
        .set_contact_trust(&good1.addr, Trust::Blocked)
        .unwrap();
    assert_eq!(obs.n("adverts"), 1);
    let p = obs.node.discover_agents(disc(TOPIC)).await.unwrap();
    assert_eq!(p.agents.len(), 1);
    assert_eq!(p.agents[0].address, good2.addr);

    // a tombstone received after the advert purges it
    let tomb2 = identity(&good2)
        .create_revocation("rotated away", w.now_ms())
        .unwrap()
        .to_document();
    obs.node.import_revocation(&tomb2).unwrap();
    assert_eq!(obs.n("adverts"), 0);
    assert!(obs
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .is_empty());
}

// --------------------------------------------------- local identity events

#[tokio::test]
async fn a_new_kem_key_re_issues_the_advert_with_the_current_contact_record() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    let info = a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    pump(&[&a, &b]).await;
    let d = &b.node.discover_agents(disc(TOPIC)).await.unwrap().agents[0].clone();
    let record_before = d.contact_record.clone();

    // rotate the KEM key while the daemon is "stopped", then restart
    let mut id = identity(&a);
    id.rotate_kem(w.now_ms(), w.now_ms() + 3_600_000, None)
        .unwrap();
    id.save(&a.id_path, true).unwrap();
    let a = w.reopen(a, dcfg());
    assert_eq!(a.metric("advert.reissued"), 1);
    a.node.step_receive().await.unwrap();
    pump(&[&a, &b]).await;
    let page = b.node.discover_agents(disc(TOPIC)).await.unwrap();
    assert_eq!(page.agents.len(), 1);
    VerifiedContact::parse_and_verify(&page.agents[0].contact_record, w.now_ms()).unwrap();
    assert_ne!(page.agents[0].contact_record, record_before);
    // same capabilities and expiry, a higher sequence number
    assert_eq!(page.agents[0].capabilities, info.capabilities);
    assert_eq!(page.agents[0].expires_at, info.expires_at);
    assert_eq!(b.metric("advert.replaced"), 1);
    // and the new record is accepted by add_contact
    b.node
        .add_contact(AddContactRequest {
            contact_record: page.agents[0].contact_record.clone(),
            expected_address: Some(a.addr.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    // restarting again without a rotation re-issues nothing
    let a = w.reopen(a, dcfg());
    assert_eq!(a.metric("advert.reissued"), 0);
}

#[tokio::test]
async fn a_revoked_local_identity_advertises_nothing() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    // revoke before anything was published, then restart
    let tomb = identity(&a)
        .create_revocation("compromised", w.now_ms())
        .unwrap()
        .to_document();
    let a = w.reopen_with(
        a,
        dcfg(),
        NodeOptions {
            local_revocation: Some(tomb),
            ..Default::default()
        },
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.node.step_adverts().await.unwrap(), 0);
    assert_eq!(w.net.publish_count(&dtopic(TOPIC)), 0);
    assert_eq!(
        a.node
            .advertise_agent(adv(TOPIC, &["x"]))
            .await
            .unwrap_err()
            .code,
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        a.node.withdraw_advert(TOPIC.into()).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    w.advance(10_000_000);
    pump(&[&a, &b]).await;
    assert_eq!(w.net.publish_count(&dtopic(TOPIC)), 0);
    assert_eq!(b.n("adverts"), 0);
}

// ----------------------------------------------------------- history sync

#[tokio::test]
async fn a_late_starting_node_learns_live_adverts_through_history_sync() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let old = start(&w, "old", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    pump(&[&a, &old]).await;
    w.advance(120_000);
    // an advert that expired in the meantime must not come back
    let mut short = adv(TOPIC, &["short"]);
    short.ttl_seconds = Some(10);
    let a2 = start(&w, "a2", dcfg()).await;
    a2.node.advertise_agent(short).await.unwrap();
    pump(&[&a2]).await;
    w.advance(60_000);

    // the late node: nothing live, then history
    let late = start(&w, "late", dcfg()).await;
    late.node.step_receive().await.unwrap();
    assert!(late
        .node
        .discover_agents(disc(TOPIC))
        .await
        .unwrap()
        .agents
        .is_empty());
    let rep = late.node.step_history_sync().await.unwrap();
    assert!(rep.completed, "{rep:?}");
    let page = late.node.discover_agents(disc(TOPIC)).await.unwrap();
    assert_eq!(page.agents.len(), 1);
    assert_eq!(page.agents[0].address, a.addr);
    assert_eq!(late.metric("advert.ignored_expired"), 1);

    // a node with discovery disabled does not ingest them even if it syncs
    let off = start(&w, "off", cfg()).await;
    off.node.step_history_sync().await.unwrap();
    assert_eq!(off.n("adverts"), 0);
}

#[tokio::test]
async fn republished_frames_deduplicate_and_a_live_plus_history_copy_is_one_row() {
    let w = World::new();
    let a = start(&w, "a", dcfg()).await;
    let b = start(&w, "b", dcfg()).await;
    a.node.advertise_agent(adv(TOPIC, &["x"])).await.unwrap();
    pump(&[&a, &b]).await;
    w.advance(901_000);
    pump(&[&a, &b]).await;
    b.node.step_history_sync().await.unwrap();
    assert_eq!(b.n("adverts"), 1);
    assert_eq!(
        b.node
            .discover_agents(disc(TOPIC))
            .await
            .unwrap()
            .agents
            .len(),
        1
    );
    assert!(b.metric("advert.ignored_stale") >= 1);
}
