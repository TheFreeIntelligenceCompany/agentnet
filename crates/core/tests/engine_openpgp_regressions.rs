//! Owner-required regression tests of ADR 0004, through the normal send and
//! receive paths of the engine (`AgentApi::send_message`, the receive step) on
//! the mock transport, not just the crypto module:
//!
//! (a) sending to a contact whose certificate has a REVOKED PRIMARY key is
//!     refused even though its encryption subkey looks usable; nothing is
//!     published and the error says why;
//! (b) a received message whose signature LACKS the Intended Recipient
//!     Fingerprint is rejected (not delivered, not acknowledged, no trigger),
//!     counted with a distinct metric.

mod common;

use agentnet_core::api::*;
use agentnet_core::contact::VerifiedContact;
use agentnet_core::crypto::testing as t;
use agentnet_core::envelope::{Envelope, MESSAGE_TYPE_MESSAGE};
use agentnet_core::identity::Identity;
use common::*;

async fn started(w: &World, names: &[&str]) -> Vec<Agent> {
    let v: Vec<Agent> = names.iter().map(|n| w.agent(n, cfg())).collect();
    for a in &v {
        a.node.step_receive().await.unwrap();
    }
    v
}

/// (a) The Sequoia foot-gun: key-level filters (`.revoked(false)`) do not see a
/// revoked primary key; the engine must refuse at certificate level.
#[tokio::test]
async fn send_to_a_contact_with_a_revoked_primary_key_is_refused_and_nothing_is_published() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    // a message to B works before the revocation
    a.send(&b, "before").await;
    settle(&[&a, &b]).await;
    assert_eq!(b.n("inbox"), 1);
    let published_before = w.net.total_publish_count();
    let outbox_before = a.n("outbox");

    // A is handed B's certificate with the PRIMARY key revoked (the encryption
    // subkey is untouched and still valid)
    let b_id = Identity::load(&b.id_path).unwrap();
    let doc = t::public_cert_primary_revoked(&b_id, w.now_ms());
    let info = a
        .node
        .add_contact(AddContactRequest {
            contact_record: doc,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(info.revoked, "the revoked primary is recognised");
    assert!(
        info.kem_expires_at.is_some(),
        "the encryption subkey still looks usable at key level"
    );

    let e = a
        .send_err(SendMessageRequest {
            recipient: b.addr.clone(),
            body: "must not be encrypted to a revoked key".into(),
            ..Default::default()
        })
        .await;
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(
        e.message.contains("revoked") && e.message.contains("primary"),
        "{}",
        e.message
    );
    // nothing was queued and nothing was published
    assert_eq!(a.n("outbox"), outbox_before);
    a.node.step_send().await.unwrap();
    assert_eq!(w.net.total_publish_count(), published_before);
}

/// (b) The frame is built with Sequoia's lower-level API (`crypto::testing`),
/// signed by the real contact with every other property correct, but without
/// the Intended Recipient Fingerprint subpacket.
#[tokio::test]
async fn a_message_without_the_intended_recipient_fingerprint_is_rejected_by_the_receive_step() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    // a trigger on B that would fire on any message from A
    b.node
        .create_trigger(CreateTriggerRequest {
            sender: Some(a.addr.clone()),
            target_session: "s1".into(),
            once: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    let a_id = Identity::load(&a.id_path).unwrap();
    let vb = VerifiedContact::parse_and_verify(&b.record, w.now_ms()).unwrap();
    let env = Envelope::new(
        a_id.address(),
        vb.address,
        MESSAGE_TYPE_MESSAGE,
        "no intended recipient".into(),
        w.now_ms(),
        3_600_000,
    )
    .unwrap();
    let weak = t::BuildOpts {
        intended_recipient: false,
        ..t::BuildOpts::default()
    };
    let frame = t::seal_with(&a_id, &vb, &env, w.now_ms(), weak).unwrap();
    w.net.inject_raw(&vb.inbox_topic(), &frame);
    let before_events = b.n("events");
    b.node.step_receive().await.unwrap();
    b.node.step_send().await.unwrap();
    a.node.step_receive().await.unwrap();

    assert_eq!(b.metric("open_error.missing_intended_recipient"), 1);
    assert_eq!(b.n("inbox"), 0, "not delivered");
    assert_eq!(b.n("outbox"), 0, "not acknowledged");
    assert_eq!(b.n("seen"), 0);
    assert_eq!(
        b.n("events"),
        before_events,
        "no message.received / trigger.matched event"
    );
    let triggers = b.node.list_triggers(false).await.unwrap();
    assert_eq!(triggers.len(), 1);
    assert_eq!(triggers[0].match_count, 0, "the trigger did not fire");
    assert_eq!(b.metric("message.accepted"), 0);

    // control: the same message with the Intended Recipient Fingerprint is delivered and acked
    let good = t::seal_with(&a_id, &vb, &env, w.now_ms(), t::BuildOpts::default()).unwrap();
    w.net.inject_raw(&vb.inbox_topic(), &good);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.n("inbox"), 1);
    assert_eq!(b.metric("message.accepted"), 1);
    assert_eq!(b.n("outbox"), 1, "the receipt is queued");
}
