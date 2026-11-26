//! Daemon wiring of key rotation, identity revocation and the replay guard:
//! offline commands (daemon stopped) followed by a restart.

mod common;

use agentnet_core::api::*;
use agentnet_daemon::offline;
use common::*;

async fn contact_of(a: &Agent, b: &Agent) -> ContactInfo {
    a.remote
        .list_contacts()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.address == b.address)
        .unwrap()
}

#[tokio::test]
async fn offline_rotation_with_revoke_is_announced_at_the_next_start() {
    let w = World::new();
    let (a, mut b) = pair(&w, cfg(), cfg()).await;
    // let both daemons run once so the engine records the announced epoch
    let m0 = a.send(&b, "before").await;
    wait_until("first delivery", || async {
        a.remote.get_message_status(m0.clone()).await.unwrap().state == DeliveryState::Delivered
    })
    .await;

    b.daemon.take().unwrap().shutdown().await;
    let info = offline::rotate_kem(&b.path, Some(1), true).unwrap();
    assert_eq!(info.key_epoch, 2);
    b.daemon = Some(w.start(&b.path, cfg()).await);

    wait_until("A learned B's new record", || async {
        contact_of(&a, &b).await.key_epoch == 2
    })
    .await;
    let m1 = a.send(&b, "after").await;
    wait_until("delivery to the rotated key", || async {
        a.remote.get_message_status(m1.clone()).await.unwrap().state == DeliveryState::Delivered
    })
    .await;
    assert_eq!(b.inbox_len().await, 2);
    // the announcement is invisible in the user outbox
    assert!(b
        .remote
        .read_outbox(PageRequest::default())
        .await
        .unwrap()
        .records
        .is_empty());
}

#[tokio::test]
async fn a_revoked_identity_only_delivers_its_tombstone() {
    let w = World::new();
    let (a, mut b) = pair(&w, cfg(), cfg()).await;
    let m0 = a.send(&b, "before").await;
    wait_until("first delivery", || async {
        a.remote.get_message_status(m0.clone()).await.unwrap().state == DeliveryState::Delivered
    })
    .await;

    b.daemon.take().unwrap().shutdown().await;
    let rep = offline::revoke_identity(&b.path, "retired").unwrap();
    assert!(rep.identity.revoked);
    assert!(offline::revoke_identity(&b.path, "twice").is_err());
    assert_eq!(
        offline::show_revocation(&b.path).unwrap().as_deref(),
        Some(rep.document.as_str())
    );
    assert!(offline::rotate_kem(&b.path, None, false).is_err());
    b.daemon = Some(w.start(&b.path, cfg()).await);

    // B reports it and refuses to send
    assert!(b.remote.get_identity().await.unwrap().revoked);
    assert!(
        b.remote
            .network_status(false)
            .await
            .unwrap()
            .identity_revoked
    );
    let e = b
        .remote
        .send_message(SendMessageRequest {
            recipient: a.address.clone(),
            body: "x".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    // A receives the tombstone and blocks B
    wait_until("A applied the tombstone", || async {
        contact_of(&a, &b).await.revoked
    })
    .await;
    let e = a
        .remote
        .send_message(SendMessageRequest {
            recipient: b.address.clone(),
            body: "x".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert_eq!(
        a.inbox_len().await,
        0,
        "the tombstone is not a user message"
    );
}

#[tokio::test]
async fn accept_rollback_is_a_no_op_on_a_healthy_store_and_needs_the_lock() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    // refused while the daemon holds the data-dir lock
    assert!(offline::accept_rollback(&a.path).is_err());
    let path = a.path.clone();
    a.daemon.unwrap().shutdown().await;
    assert!(!offline::accept_rollback(&path).unwrap());
}
