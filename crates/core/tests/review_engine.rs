//! Engine-level tests for the findings of the adversarial review of 2026-11-27
//! (`results/review/fable-crypto-review.md`); each test names its finding.

mod common;

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
        inject(&w, &a, &forge(&w, &z, &a, MESSAGE_TYPE_IDENTITY_REVOKED, &t));
        a.node.step_receive().await.unwrap();
    }
    assert_eq!(a.n("revocations"), 0, "{policy:?}");
    assert_eq!(a.n("seen"), 0, "{policy:?}: nothing is remembered about strangers' revocations");
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
    inject(&w, &a, &forge(&w, &b, &a, MESSAGE_TYPE_IDENTITY_REVOKED, &t));
    a.node.step_receive().await.unwrap();
    assert_eq!(a.n("revocations"), 1);
}
