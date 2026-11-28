//! Re-adding an existing contact with the address verified out of band.

mod common;

use agentnet_core::api::*;
use common::*;

fn req(b: &Agent, expect: bool, trust: Option<Trust>) -> AddContactRequest {
    AddContactRequest {
        contact_record: b.record.clone(),
        expected_address: expect.then(|| b.addr.clone()),
        trust,
        ..Default::default()
    }
}

#[tokio::test]
async fn readding_an_untrusted_contact_with_the_matching_expect_raises_it_to_trusted() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    let first = a.node.add_contact(req(&b, false, None)).await.unwrap();
    assert_eq!(first.trust, Trust::Untrusted);
    assert!(!first.trust_changed);
    // without --expect nothing changes, however often it is repeated
    let same = a.node.add_contact(req(&b, false, None)).await.unwrap();
    assert_eq!(same.trust, Trust::Untrusted);
    assert!(!same.trust_changed);
    // with the verified address: raised, and the result says so
    let raised = a.node.add_contact(req(&b, true, None)).await.unwrap();
    assert_eq!(raised.trust, Trust::Trusted);
    assert!(raised.trust_changed);
    assert_eq!(
        a.node.list_contacts().await.unwrap()[0].trust,
        Trust::Trusted
    );
    // already trusted: no change reported
    let again = a.node.add_contact(req(&b, true, None)).await.unwrap();
    assert_eq!(again.trust, Trust::Trusted);
    assert!(!again.trust_changed);
}

#[tokio::test]
async fn readding_with_expect_never_overrides_blocked_or_a_wrong_address() {
    let w = World::new();
    let a = w.agent("a", cfg());
    let b = w.agent("b", cfg());
    let c = w.agent("c", cfg());
    a.node.add_contact(req(&b, false, None)).await.unwrap();
    a.node.set_contact_trust(&b.addr, Trust::Blocked).unwrap();
    let r = a.node.add_contact(req(&b, true, None)).await.unwrap();
    assert_eq!(r.trust, Trust::Blocked);
    assert!(!r.trust_changed);
    assert!(r.warning.as_deref().unwrap().contains("blocked"));
    // a mismatching --expect is still rejected
    let mut bad = req(&b, true, None);
    bad.expected_address = Some(c.addr.clone());
    assert_eq!(
        code(&a.node.add_contact(bad).await.unwrap_err()),
        ErrorCode::InvalidArgument
    );
}
