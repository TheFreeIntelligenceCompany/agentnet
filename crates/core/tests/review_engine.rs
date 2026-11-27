//! Engine-level tests for the findings of the adversarial review of 2026-11-27
//! (`results/review/fable-crypto-review.md`); each test names its finding.

mod common;

use agentnet_core::api::DeliveryState;
use agentnet_core::config::UnknownSenders;
use agentnet_core::crypto::envelope::{Envelope, MESSAGE_TYPE_IDENTITY_REVOKED};
use agentnet_core::crypto::protection::seal;
use agentnet_core::crypto::{Identity, VerifiedContact};
use agentnet_transport::ContentTopic;
use common::*;

const TTL: i64 = 3_600_000;

fn load(a: &Agent) -> Identity {
    Identity::load(&a.id_path).unwrap()
}

fn topic_of(record: &str) -> ContentTopic {
    VerifiedContact::parse_and_verify_allow_expired(record, 1_700_000_000_000)
        .unwrap()
        .inbox_topic()
}

/// A frame signed by `from` (loaded from its identity file) to `to`.
fn forge(w: &World, from: &Agent, to: &Agent, mtype: &str, body: &str) -> Vec<u8> {
    let id = load(from);
    let vc = VerifiedContact::parse_and_verify(&to.record, w.now_ms()).unwrap();
    let env = Envelope::new(
        id.address(),
        vc.address,
        mtype,
        body.to_owned(),
        w.now_ms(),
        TTL,
    )
    .unwrap();
    seal(&id, &vc, &env, w.now_ms(), 150_000).unwrap()
}

fn inject(w: &World, to: &Agent, frame: &[u8]) {
    w.net.inject_raw(&topic_of(&to.record), frame);
}

fn tombstone(w: &World, a: &Agent, reason: &str) -> String {
    load(a)
        .create_revocation(reason, w.now_ms())
        .unwrap()
        .to_document()
}

// ------------------------------------------------------------------- M2

/// M2: frames from throwaway identities that revoke themselves must not grow
/// the `revocations` table, whatever the unknown-sender policy says.
async fn strangers_cannot_grow_the_revocation_table(policy: UnknownSenders) {
    let w = World::new();
    let a = w.agent(
        "a",
        cfg_with(|c| {
            c.policy.unknown_senders = policy;
        }),
    );
    a.node.step_receive().await.unwrap();
    for i in 0..5 {
        let z = w.agent(&format!("z{i}"), cfg());
        let t = tombstone(&w, &z, "throwaway");
        inject(
            &w,
            &a,
            &forge(&w, &z, &a, MESSAGE_TYPE_IDENTITY_REVOKED, &t),
        );
        a.node.step_receive().await.unwrap();
    }
    assert_eq!(a.n("revocations"), 0, "{policy:?}");
    assert_eq!(
        a.n("seen"),
        0,
        "{policy:?}: nothing is remembered about strangers' revocations"
    );
    assert!(a.inbox().await.is_empty());
}

#[tokio::test]
async fn m2_strangers_cannot_grow_the_revocation_table_under_reject() {
    strangers_cannot_grow_the_revocation_table(UnknownSenders::Reject).await;
}

#[tokio::test]
async fn m2_strangers_cannot_grow_the_revocation_table_under_quarantine() {
    strangers_cannot_grow_the_revocation_table(UnknownSenders::Quarantine).await;
}

#[tokio::test]
async fn m2_a_contacts_own_revocation_is_still_applied_and_counted_per_contact() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    exchange(&a, &b).await;
    let t = tombstone(&w, &b, "b stolen");
    inject(
        &w,
        &a,
        &forge(&w, &b, &a, MESSAGE_TYPE_IDENTITY_REVOKED, &t),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.n("revocations"), 1);
}

// ------------------------------------------------------------------- M3

fn published_by(w: &World, from: &Agent) -> Vec<agentnet_transport::mock::PublishedFrame> {
    w.net
        .published_frames()
        .into_iter()
        .filter(|f| f.publisher == Some(from.transport.index()))
        .collect()
}

async fn delivered_pair(w: &World) -> (Agent, Agent, Vec<u8>) {
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    exchange(&a, &b).await;
    a.send(&b, "hello").await;
    a.node.step_send().await.unwrap();
    let frame = published_by(w, &a)[0].payload.clone();
    b.node.step_receive().await.unwrap();
    assert_eq!(b.inbox().await.len(), 1);
    // the first ack is published and lost
    b.transport.drop_next_publishes(1);
    b.node.step_send().await.unwrap();
    (a, b, frame)
}

/// M3 (b): a byte-different copy of an already seen frame (an extra PKESK, the
/// kind of mutation a relay participant can make) does not make B publish
/// another ack while the first ack row still exists.
#[tokio::test]
async fn m3_a_mutated_duplicate_is_not_re_acked_but_a_byte_identical_retry_is() {
    let w = World::new();
    let (a, b, frame) = delivered_pair(&w).await;
    let acks_before = b.n("outbox");
    w.advance(40_000); // past the 30 s re-ack interval

    let mutated = agentnet_core::crypto::testing::prepend_foreign_pkesks(&frame, 1);
    assert_ne!(mutated, frame);
    inject(&w, &b, &mutated);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.metric("ack.reack_suppressed_mutated"), 1);
    assert_eq!(b.metric("ack.requeued"), 0);
    assert_eq!(b.n("outbox"), acks_before, "no new ack row");

    // the sender's own retry is byte-identical: it is re-acked, after a random delay
    inject(&w, &b, &frame);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.metric("ack.requeued"), 1);
    let before = published_by(&w, &b).len();
    b.node.step_send().await.unwrap();
    assert_eq!(
        published_by(&w, &b).len(),
        before,
        "the re-ack is not published immediately (random delay)"
    );
    w.advance(6_000);
    b.node.step_send().await.unwrap();
    assert_eq!(published_by(&w, &b).len(), before + 1);
    a.node.step_receive().await.unwrap();
}

// ------------------------------------------------------------------- L1

/// L1 at engine level: a frame signed 10 minutes ahead is deferred (not marked
/// seen, no `bad_signature` count) and accepted once the clock has caught up.
#[tokio::test]
async fn l1_a_frame_signed_in_the_future_is_deferred_then_accepted() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    exchange(&a, &b).await;
    let id = load(&a);
    let vc = VerifiedContact::parse_and_verify(&b.record, w.now_ms()).unwrap();
    let env = Envelope::new(
        id.address(),
        vc.address,
        "message",
        "from the future".to_owned(),
        w.now_ms(),
        TTL,
    )
    .unwrap();
    let ahead = 600_000;
    let frame = seal(&id, &vc, &env, w.now_ms() + ahead, 150_000).unwrap();
    inject(&w, &b, &frame);
    let seen_before = b.n("transport_seen");
    b.node.step_receive().await.unwrap();
    assert_eq!(b.metric("open_error.from_future"), 1);
    assert_eq!(b.metric("open_error.bad_signature"), 0);
    assert_eq!(
        b.n("transport_seen"),
        seen_before,
        "a deferred frame is not marked seen"
    );
    assert!(b.inbox().await.is_empty());
    // the history sync (or a re-poll) offers it again after the clock caught up
    w.advance(ahead);
    inject(&w, &b, &frame);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.inbox().await.len(), 1);
}

// ------------------------------------------------------------------- L5

/// L5: when the sender directory cannot answer (here: the stored contact record
/// of the sender is corrupt), the open fails as a store failure: the frame is not
/// marked seen and no second-pass authentication with the embedded certificate
/// is attempted (it used to be treated as "not a contact").
#[tokio::test]
async fn l5_a_directory_failure_fails_the_open_with_a_store_error() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    exchange(&a, &b).await;
    // corrupt B's record in A's store
    {
        let c = rusqlite::Connection::open(&a.store_path).unwrap();
        c.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
        c.execute("UPDATE contacts SET document = 'garbage'", [])
            .unwrap();
    }
    b.send(&a, "hello").await;
    b.node.step_send().await.unwrap();
    let seen_before = a.n("transport_seen");
    let r = a.node.step_receive().await.unwrap();
    assert_eq!(r.store_failures, 1);
    assert_eq!(a.metric("open.directory_failed"), 1);
    assert_eq!(
        a.n("transport_seen"),
        seen_before,
        "not marked seen: it will be retried"
    );
    assert_eq!(a.n("inbox"), 0);
}

// ------------------------------------------------------------------- L6

/// L6 (a): a primary-key revocation that arrives inside a `contact.update` takes
/// the same path as `identity.revoked`: revocation row, pending sends failed.
#[tokio::test]
async fn l6_a_revocation_through_contact_update_is_applied_like_identity_revoked() {
    use agentnet_core::crypto::envelope::MESSAGE_TYPE_CONTACT_UPDATE;
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    exchange(&a, &b).await;
    // a message to B is pending (not yet published)
    let m = a.send(&b, "pending").await;
    // B's revoked certificate arrives as a contact.update from B itself
    let revoked = tombstone(&w, &b, "b stolen");
    inject(
        &w,
        &a,
        &forge(&w, &b, &a, MESSAGE_TYPE_CONTACT_UPDATE, &revoked),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.n("revocations"), 1);
    assert_eq!(a.state(&m.message_id).await, DeliveryState::Failed);
    // and nothing is published to B any more
    let before = published_by(&w, &a).len();
    a.node.step_send().await.unwrap();
    assert_eq!(published_by(&w, &a).len(), before);
}

/// L6 (b): a frame sealed to a subkey that has since expired is not published
/// again: it is re-sealed to a live subkey or, with none, failed.
#[tokio::test]
async fn l6_a_frame_sealed_to_an_expired_subkey_is_not_republished() {
    use std::time::Duration;
    let w = World::new();
    let a = w.agent("a", cfg());
    let idb = Identity::generate_with(w.now_ms(), Some(Duration::from_secs(600))).unwrap();
    let b = w.agent_with("b", cfg(), idb);
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    exchange(&a, &b).await;
    let m = a.send(&b, "hello").await;
    a.node.step_send().await.unwrap();
    assert_eq!(published_by(&w, &a).len(), 1);
    // B stays offline past the subkey's expiry; A's retry comes due
    w.advance(11 * 60_000);
    a.node.step_send().await.unwrap();
    assert_eq!(
        published_by(&w, &a).len(),
        1,
        "nothing sealed to an expired subkey is published again"
    );
    assert_eq!(a.state(&m.message_id).await, DeliveryState::Failed);
}

// ------------------------------------------------------------------- M1

/// M1 through the engine: B rotates with `--revoke-previous` twelve times, each
/// time announcing the new certificate with a `contact.update`; B's ORIGINAL
/// certificate then arrives again as a stale `contact.update`. A message A
/// sends afterwards must not open with the first subkey's secret.
#[tokio::test]
async fn m1_a_stale_contact_update_does_not_resurrect_a_revoked_subkey() {
    use agentnet_core::crypto::{
        Address, MessageProtection, OpenLimits, OpenPgpProtection, SenderDirectory,
    };
    use agentnet_core::error::OpenError;
    struct Pinned(Vec<VerifiedContact>);
    impl SenderDirectory for Pinned {
        fn certificate(&self, a: &Address) -> Option<VerifiedContact> {
            self.0.iter().find(|c| c.address == *a).cloned()
        }
    }
    let w = World::new();
    let a = w.agent("a", cfg());
    let mut b = w.agent("b", cfg());
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    exchange(&a, &b).await;
    let original = b.record.clone();
    let compromised = load(&b); // holds only the first subkey's secret
    for _ in 0..12 {
        w.advance(10_000);
        let mut id = load(&b);
        id.rotate_kem_with(w.now_ms(), w.now_ms() + 7 * 24 * 3_600_000, None, true)
            .unwrap();
        id.save(&b.id_path, true).unwrap();
        b = w.reopen(b, cfg());
        settle(&[&a, &b]).await;
    }
    assert!(a.metric("contact_update.applied") >= 12);
    // the stale original certificate is "announced" again
    inject(
        &w,
        &a,
        &forge(
            &w,
            &b,
            &a,
            agentnet_core::crypto::envelope::MESSAGE_TYPE_CONTACT_UPDATE,
            &original,
        ),
    );
    a.node.step_receive().await.unwrap();
    let before = published_by(&w, &a).len();
    a.send(&b, "after compromise").await;
    a.node.step_send().await.unwrap();
    let frames: Vec<Vec<u8>> = published_by(&w, &a)[before..]
        .iter()
        .map(|f| f.payload.clone())
        .collect();
    let now = w.now_ms();
    let lim = OpenLimits {
        clock_skew_ms: 120_000,
        max_ttl_ms: 7 * 24 * 3600 * 1000,
        max_frame_len: 153_600,
    };
    let dir = Pinned(vec![
        VerifiedContact::parse_and_verify(&a.record, now).unwrap()
    ]);
    let current = load(&b);
    let mut opened = 0;
    for frame in &frames {
        assert_eq!(
            OpenPgpProtection
                .open(&compromised, frame, now, &lim, &dir)
                .unwrap_err(),
            OpenError::NotForUs
        );
        if let Ok(o) = OpenPgpProtection.open(&current, frame, now, &lim, &dir) {
            // acks of B's contact updates open too; count only the message
            if o.envelope.body == "after compromise" {
                opened += 1;
            }
        }
    }
    assert_eq!(opened, 1);
}

// ------------------------------------------------------------------- L9

/// L9: a first contact without `expected_address` is not trusted and says how
/// to verify it; `trusted` needs `expected_address`.
#[tokio::test]
async fn l9_first_contact_without_expected_address_is_untrusted() {
    use agentnet_core::api::ErrorCode;
    use agentnet_core::api::{AddContactRequest, AgentApi, Trust};
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    let c = w.agent("c", cfg());
    let d = w.agent("d", cfg());
    let req = |x: &Agent, expected: bool, trust: Option<Trust>| AddContactRequest {
        contact_record: x.record.clone(),
        expected_address: expected.then(|| x.addr.clone()),
        trust,
        ..Default::default()
    };
    // no expectation: untrusted, with a warning naming the address and the way up
    let info = a.node.add_contact(req(&b, false, None)).await.unwrap();
    assert_eq!(info.trust, Trust::Untrusted);
    let warning = info.warning.unwrap();
    assert!(
        warning.contains(&b.addr) && warning.contains("--expect"),
        "{warning}"
    );
    // asking for trusted without the expectation is refused, nothing is stored
    let e = a
        .node
        .add_contact(req(&c, false, Some(Trust::Trusted)))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(a.n("contacts"), 1);
    // with it: trusted, no warning
    let info = a.node.add_contact(req(&d, true, None)).await.unwrap();
    assert_eq!(info.trust, Trust::Trusted);
    assert!(info.warning.is_none());
    // re-adding the first contact with the expectation does not downgrade or
    // upgrade by itself; trust is raised explicitly
    let again = a
        .node
        .add_contact(req(&b, true, Some(Trust::Trusted)))
        .await
        .unwrap();
    assert_eq!(again.trust, Trust::Trusted);
}
