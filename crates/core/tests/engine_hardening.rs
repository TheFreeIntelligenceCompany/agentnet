//! Owner conditions 5, 6 and 7 at engine level on the MockNetwork: key
//! rotation and revocation, contact updates, identity tombstones, durable
//! replay protection (restart, rollback, migration, concurrent identity) and
//! the replay guard. Real SQLite files in temp dirs.

mod common;

use agentnet_core::api::*;
use agentnet_core::crypto::envelope::{
    seal, Envelope, MESSAGE_TYPE_CONTACT_UPDATE, MESSAGE_TYPE_IDENTITY_REVOKED,
    MESSAGE_TYPE_MESSAGE,
};
use agentnet_core::crypto::{Identity, VerifiedContact};
use agentnet_core::guard;
use agentnet_core::NodeOptions;
use agentnet_transport::ContentTopic;
use common::*;

const TTL: i64 = 3_600_000;

fn load(a: &Agent) -> Identity {
    Identity::load(&a.id_path).unwrap()
}

/// Rotate `a`'s KEM key on disk (the daemon is "stopped"); returns the new record.
fn rotate(w: &World, a: &Agent, revoke: bool) -> String {
    let mut id = load(a);
    id.rotate_kem_with(w.now_ms(), w.now_ms() + 7 * 24 * 3_600_000, None, revoke)
        .unwrap();
    id.save(&a.id_path, true).unwrap();
    id.contact_record().to_document()
}

fn topic_of(record: &str) -> ContentTopic {
    VerifiedContact::parse_and_verify(record, i64::MAX / 2)
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

async fn started(w: &World, names: &[&str]) -> Vec<Agent> {
    let v: Vec<Agent> = names.iter().map(|n| w.agent(n, cfg())).collect();
    for a in &v {
        a.node.step_receive().await.unwrap();
    }
    v
}

async fn contact(a: &Agent, b: &Agent) -> ContactInfo {
    a.node
        .list_contacts()
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.address == b.addr)
        .unwrap()
}

// ------------------------------------------------------------- rotation

#[tokio::test]
async fn rotation_with_overlap_keeps_old_frames_openable_and_announces_the_new_record() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    // sealed to B's epoch-1 key and already on the network
    let m1 = a.send(&b, "before rotation").await;
    a.node.step_send().await.unwrap();

    rotate(&w, &b, false);
    let b = w.reopen(b, cfg());
    settle(&[&a, &b]).await;

    // the old frame opened through the retention overlap
    assert_eq!(a.state(&m1.message_id).await, DeliveryState::Delivered);
    assert_eq!(b.inbox().await.len(), 1);
    // the contact.update told A about epoch 2 ...
    assert_eq!(contact(&a, &b).await.key_epoch, 2);
    assert_eq!(a.metric("contact_update.applied"), 1);
    // ... so new messages are sealed to it
    let m2 = a.send(&b, "after rotation").await;
    settle(&[&a, &b]).await;
    assert_eq!(a.state(&m2.message_id).await, DeliveryState::Delivered);
    assert_eq!(b.inbox().await.len(), 2);
    // system messages are hidden from the user-facing outbox and reserved
    assert!(b
        .node
        .read_outbox(PageRequest::default())
        .await
        .unwrap()
        .records
        .is_empty());
    assert!(
        b.n("outbox") >= 1,
        "hidden contact.update and ack rows exist"
    );
    for t in [MESSAGE_TYPE_CONTACT_UPDATE, MESSAGE_TYPE_IDENTITY_REVOKED] {
        let e = b
            .send_err(SendMessageRequest {
                recipient: a.addr.clone(),
                body: "x".into(),
                message_type: Some(t.into()),
                ..Default::default()
            })
            .await;
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{t}");
    }
}

#[tokio::test]
async fn rotation_with_revoke_reseals_pending_messages_after_contact_update() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    // m1 is on the network sealed to the epoch-1 key; m2 is still queued
    let m1 = a.send(&b, "in flight").await;
    a.node.step_send().await.unwrap();
    let m2 = a.send(&b, "queued").await;

    rotate(&w, &b, true);
    let b = w.reopen(b, cfg());
    settle(&[&a, &b]).await;

    // the revoked key cannot open the old frame ...
    assert!(b.metric("frame.not_for_us") >= 1);
    // ... but both messages arrive after A applied the contact.update and re-sealed
    assert_eq!(a.state(&m1.message_id).await, DeliveryState::Delivered);
    assert_eq!(a.state(&m2.message_id).await, DeliveryState::Delivered);
    assert_eq!(b.inbox().await.len(), 2);
    assert!(a.metric("outbox.resealed") >= 1);
    assert!(
        a.node
            .get_message_status(m1.message_id.clone())
            .await
            .unwrap()
            .attempts
            >= 2
    );
    // same message ids (re-sealed, not re-created)
    let ids: Vec<String> = b.inbox().await.into_iter().map(|r| r.message_id).collect();
    assert!(ids.contains(&m1.message_id) && ids.contains(&m2.message_id));
    let c = contact(&a, &b).await;
    assert_eq!(c.key_epoch, 2);
}

#[tokio::test]
async fn stale_and_conflicting_contact_records_are_rejected() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    a.add(&b).await;
    let epoch1 = b.record.clone();

    // two different rotations of the same identity both claim epoch 2
    let mut id_x = load(&b);
    id_x.rotate_kem_with(w.now_ms(), w.now_ms() + TTL, None, false)
        .unwrap();
    let rec_x = id_x.contact_record().to_document();
    let mut id_y = load(&b);
    id_y.rotate_kem_with(w.now_ms() + 5, w.now_ms() + TTL, None, false)
        .unwrap();
    let rec_y = id_y.contact_record().to_document();

    let add = |doc: String| {
        let n = a.node.clone();
        async move {
            n.add_contact(AddContactRequest {
                contact_record: doc,
                ..Default::default()
            })
            .await
        }
    };
    let up = add(rec_x.clone()).await.unwrap();
    assert!(up.updated && up.key_epoch == 2);
    // idempotent re-import of the same record
    let again = add(rec_x.clone()).await.unwrap();
    assert!(!again.updated);
    // older epoch: stale; same epoch, different bytes: conflicting
    let e = add(epoch1).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    assert!(e.message.contains("stale"), "{}", e.message);
    let e = add(rec_y).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    assert!(e.message.contains("conflicting"), "{}", e.message);
    // the stored record is untouched
    assert_eq!(contact(&a, &b).await.key_epoch, 2);
}

#[tokio::test]
async fn contact_updates_from_wrong_untrusted_or_replayed_sources_are_not_applied() {
    let w = World::new();
    let mut v = started(&w, &["a", "b", "c", "d"]).await;
    let (d, c, b, a) = (
        v.pop().unwrap(),
        v.pop().unwrap(),
        v.pop().unwrap(),
        v.pop().unwrap(),
    );
    exchange(&a, &b).await;
    exchange(&a, &c).await;
    let rec_b2 = rotate(&w, &b, false);
    let rec_d2 = {
        let mut id = load(&d);
        id.rotate_kem(w.now_ms(), w.now_ms() + TTL, None).unwrap();
        id.contact_record().to_document()
    };

    // (a) a Trusted contact (C) pushes someone else's (B's) new record
    inject(
        &w,
        &a,
        &forge(&w, &c, &a, MESSAGE_TYPE_CONTACT_UPDATE, &rec_b2),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("contact_update.ignored_wrong_address"), 1);
    assert_eq!(contact(&a, &b).await.key_epoch, 1);

    // (b) B is known but Untrusted: B's own valid update is stored under the
    // quarantine policy, never applied
    a.node.set_contact_trust(&b.addr, Trust::Untrusted).unwrap();
    inject(
        &w,
        &a,
        &forge(&w, &b, &a, MESSAGE_TYPE_CONTACT_UPDATE, &rec_b2),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(contact(&a, &b).await.key_epoch, 1);
    assert_eq!(a.metric("contact_update.applied"), 0);
    assert_eq!(a.metric("message.quarantined"), 1);
    a.node.set_contact_trust(&b.addr, Trust::Trusted).unwrap();

    // (c) a stranger (D, not a contact) sends its own record: no contact appears
    inject(
        &w,
        &a,
        &forge(&w, &d, &a, MESSAGE_TYPE_CONTACT_UPDATE, &rec_d2),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.node.list_contacts().await.unwrap().len(), 2);
    assert_eq!(a.metric("contact_update.applied"), 0);

    // (d) a valid update from the Trusted contact is applied ...
    let f = forge(&w, &b, &a, MESSAGE_TYPE_CONTACT_UPDATE, &rec_b2);
    inject(&w, &a, &f);
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("contact_update.applied"), 1);
    assert_eq!(contact(&a, &b).await.key_epoch, 2);
    // ... an exact replay is a duplicate ...
    inject(&w, &a, &f);
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("contact_update.applied"), 1);
    // ... and a replayed OLD record (fresh message id) cannot roll it back
    inject(
        &w,
        &a,
        &forge(&w, &b, &a, MESSAGE_TYPE_CONTACT_UPDATE, &b.record),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("contact_update.ignored_stale"), 1);
    assert_eq!(contact(&a, &b).await.key_epoch, 2);
    // garbage body from a Trusted contact is ignored
    inject(
        &w,
        &a,
        &forge(&w, &b, &a, MESSAGE_TYPE_CONTACT_UPDATE, "not a record"),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("contact_update.ignored_invalid"), 1);
    // none of these reached the user inbox
    assert!(a.inbox().await.is_empty());
}

// ------------------------------------------------------------ tombstones

fn tombstone(w: &World, a: &Agent, reason: &str) -> String {
    load(a)
        .create_revocation(reason, w.now_ms())
        .unwrap()
        .to_document()
}

#[tokio::test]
async fn identity_revocation_propagates_and_blocks_the_revoked_contact() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    // B had a message queued when it was revoked: it must never be sent
    b.send(&a, "queued before revocation").await;
    // A has one queued to B too: it is failed when the tombstone arrives
    let to_b = a.send(&b, "to the soon revoked").await;

    let doc = tombstone(&w, &b, "key stolen");
    let b = w.reopen_with(
        b,
        cfg(),
        NodeOptions {
            local_revocation: Some(doc.clone()),
            ..Default::default()
        },
    );
    // the revoked identity reports it and refuses to send
    assert!(b.node.get_identity().await.unwrap().revoked);
    assert!(b.node.network_status(false).await.unwrap().identity_revoked);
    let e = b
        .send_err(SendMessageRequest {
            recipient: a.addr.clone(),
            body: "hi".into(),
            ..Default::default()
        })
        .await;
    assert_eq!(e.code, ErrorCode::PolicyDenied);

    settle(&[&a, &b]).await;
    // only the tombstone was delivered
    assert!(a.inbox().await.is_empty());
    assert_eq!(a.metric("identity_revoked.applied"), 1);
    let c = contact(&a, &b).await;
    assert!(c.revoked);
    assert_eq!(c.trust, Trust::Blocked);
    assert_eq!(a.state(&to_b.message_id).await, DeliveryState::Failed);
    // sends to it are refused with a clear error
    let e = a
        .send_err(SendMessageRequest {
            recipient: b.addr.clone(),
            body: "x".into(),
            ..Default::default()
        })
        .await;
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(e.message.contains("revoked"));
    // cannot be re-trusted or replaced by a new record
    let e = a
        .node
        .set_contact_trust(&b.addr, Trust::Trusted)
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    let e = a
        .node
        .add_contact(AddContactRequest {
            contact_record: rotate(&w, &b, false),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
    // inbound frames from the revoked identity are dropped as blocked
    let f = forge(&w, &b, &a, MESSAGE_TYPE_MESSAGE, "from a thief");
    inject(&w, &a, &f);
    a.node.step_receive().await.unwrap();
    assert!(a.inbox().await.is_empty());
    assert_eq!(a.metric("drop.blocked"), 1);
    // idempotent: importing the same tombstone again is not "new"
    assert!(!a.node.import_revocation(&doc).unwrap().newly_revoked);
}

#[tokio::test]
async fn forged_tombstones_are_rejected_and_out_of_band_import_works() {
    let w = World::new();
    let mut v = started(&w, &["a", "b", "x"]).await;
    let (x, b, a) = (v.pop().unwrap(), v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;

    let good = tombstone(&w, &b, "retired");
    // edited reason, truncated, someone else's signature over B's address
    let edited = {
        let v: serde_json::Value = serde_json::from_str(&good).unwrap();
        let rec = v["record"].as_str().unwrap().to_owned();
        let sig = v["sig"].as_str().unwrap().to_owned();
        let mut bytes = rec.into_bytes();
        let n = bytes.len() / 2;
        bytes[n] = if bytes[n] == b'A' { b'B' } else { b'A' };
        serde_json::json!({"record": String::from_utf8(bytes).unwrap(), "sig": sig}).to_string()
    };
    let by_x = {
        // X signs a tombstone naming X; relabelling it as B's is a bad signature
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine as _;
        let t: serde_json::Value = serde_json::from_str(&tombstone(&w, &x, "x")).unwrap();
        let rec = String::from_utf8(B64.decode(t["record"].as_str().unwrap()).unwrap()).unwrap();
        let rec = rec.replace(&x.addr, &b.addr);
        serde_json::json!({"record": B64.encode(rec), "sig": t["sig"]}).to_string()
    };
    for bad in [edited.as_str(), "{}", "garbage", by_x.as_str()] {
        let e = a.node.import_revocation(bad).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{bad}");
    }
    assert!(!contact(&a, &b).await.revoked);
    // a tombstone naming the local identity is refused (operator action only)
    assert!(a.node.import_revocation(&tombstone(&w, &a, "me")).is_err());

    // out of band, for an address that is not even a contact yet
    let info = a
        .node
        .import_revocation(&tombstone(&w, &x, "gone"))
        .unwrap();
    assert!(info.newly_revoked);
    let e = a
        .node
        .add_contact(AddContactRequest {
            contact_record: x.record.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Conflict);
}

#[tokio::test]
async fn tombstones_delivered_in_envelopes_are_applied_only_when_relevant() {
    let w = World::new();
    let mut v = started(&w, &["a", "b", "c", "z"]).await;
    let (z, c, b, a) = (
        v.pop().unwrap(),
        v.pop().unwrap(),
        v.pop().unwrap(),
        v.pop().unwrap(),
    );
    exchange(&a, &b).await;
    exchange(&a, &c).await;
    // a stranger (Z, no contact) forwards B's tombstone: B is a contact -> applied
    // (self-authenticating, so any trust level may deliver it)
    let tb = tombstone(&w, &b, "b stolen");
    inject(
        &w,
        &a,
        &forge(&w, &z, &a, MESSAGE_TYPE_IDENTITY_REVOKED, &tb),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("identity_revoked.applied"), 1);
    assert!(contact(&a, &b).await.revoked);
    // a tombstone for an address that is neither the sender nor a contact is ignored
    let tz = tombstone(&w, &z, "z");
    inject(
        &w,
        &a,
        &forge(&w, &c, &a, MESSAGE_TYPE_IDENTITY_REVOKED, &tz),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("identity_revoked.ignored_unrelated"), 1);
    // ... but Z announcing its own tombstone is applied (names the sender)
    inject(
        &w,
        &a,
        &forge(&w, &z, &a, MESSAGE_TYPE_IDENTITY_REVOKED, &tz),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("identity_revoked.applied"), 2);
    // a forged body is ignored
    inject(
        &w,
        &a,
        &forge(&w, &c, &a, MESSAGE_TYPE_IDENTITY_REVOKED, "nope"),
    );
    a.node.step_receive().await.unwrap();
    assert_eq!(a.metric("identity_revoked.ignored_invalid"), 1);
    assert!(!contact(&a, &c).await.revoked);
    assert!(a.inbox().await.is_empty());
}

// ---------------------------------------------------- replay protection

/// The first frame `from` published (the message under test).
fn captured(w: &World, from: &Agent) -> agentnet_transport::mock::PublishedFrame {
    w.net
        .published_frames()
        .into_iter()
        .find(|f| f.publisher == Some(from.transport.index()))
        .unwrap()
}

fn copy_store(from: &Agent, to: &std::path::Path) {
    std::fs::copy(&from.store_path, to).unwrap();
}

fn restore_store(a: &Agent, backup: &std::path::Path) {
    for ext in ["sqlite-wal", "sqlite-shm"] {
        let _ = std::fs::remove_file(a.store_path.with_extension(ext));
    }
    std::fs::copy(backup, &a.store_path).unwrap();
}

async fn status(a: &Agent) -> NetworkStatus {
    a.node.network_status(false).await.unwrap()
}

/// Scenario 1 (restart): replay after reopening the same store is rejected.
/// (The expiry/pruning variant is `engine_security::replay_now_and_after_dedupe_pruning`.)
#[tokio::test]
async fn replay_after_restart_is_rejected() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    a.send(&b, "once").await;
    settle(&[&a, &b]).await;
    assert_eq!(b.inbox().await.len(), 1);
    let f = captured(&w, &a);
    let b = w.reopen(b, cfg());
    inject(&w, &b, &f.payload);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.inbox().await.len(), 1);
    assert!(b.metric("message.duplicate") >= 1);
    assert!(
        status(&b).await.replay_guard.is_none(),
        "no guard after a clean restart"
    );
}

/// Scenario 2 (rollback): the guard holds pre-rollback messages instead of
/// delivering the replay; it lapses by itself or is accepted by the operator.
#[tokio::test]
async fn rollback_enters_the_replay_guard_and_holds_replayed_frames() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    let backup = w.dir.path().join("b-backup.sqlite");
    b.node.close();
    copy_store(&b, &backup);
    let b = w.reopen(b, cfg());

    a.send(&b, "received before the rollback").await;
    settle(&[&a, &b]).await;
    assert_eq!(b.inbox().await.len(), 1);
    let f = captured(&w, &a);
    let gen_after = match guard::read_sidecar(&guard::sidecar_path(&b.store_path)) {
        guard::SidecarState::Present(s) => s.generation,
        other => panic!("{other:?}"),
    };
    assert!(gen_after >= 1);

    // restore the OLD copy of the database (sidecar stays newer)
    b.node.close();
    restore_store(&b, &backup);
    w.advance(5_000);
    let b = w.reopen(b, cfg());
    let g = status(&b).await.replay_guard.expect("guard must be active");
    assert_eq!(g.reason, "rollback");
    assert_eq!(b.inbox().await.len(), 0, "the rollback lost the message");

    // the replayed frame is held: not delivered, not acked, no trigger/event
    let outbox_rows = b.n("outbox");
    inject(&w, &b, &f.payload);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.inbox().await.len(), 0);
    assert_eq!(b.metric("guard.held"), 1);
    assert_eq!(b.n("outbox"), outbox_rows, "no ack queued");
    assert_eq!(b.n("events"), 0);
    assert_eq!(status(&b).await.replay_guard.unwrap().held, 1);
    // a message created after the guard start plus the skew is delivered normally
    w.advance(121_000);
    a.send(&b, "after the rollback").await;
    settle(&[&a, &b]).await;
    assert_eq!(b.inbox().await.len(), 1);
    assert_eq!(b.inbox().await[0].body, "after the rollback");

    // the guard persists across a restart ...
    let b = w.reopen(b, cfg());
    assert!(status(&b).await.replay_guard.is_some());
    // ... and lapses by itself after max_ttl + clock_skew; held rows are expired by then
    w.advance(g.until - w.now_ms() + 1);
    b.node.step_maintenance().unwrap();
    assert!(status(&b).await.replay_guard.is_none());
    assert!(
        b.inbox()
            .await
            .iter()
            .all(|r| r.body != "received before the rollback"),
        "the held replay was discarded as expired"
    );
}

/// Review finding 1: a trusted sender whose clock runs ahead (within the
/// allowed skew) creates a frame that opens fine; replaying it after a restore
/// must still be held, because its signed `created_at` is later than the guard
/// start but not later than guard start + skew.
#[tokio::test]
async fn rollback_guard_holds_replays_from_a_sender_clock_ahead_within_the_skew() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    let backup = w.dir.path().join("b-backup.sqlite");
    b.node.close();
    copy_store(&b, &backup);
    let b = w.reopen(b, cfg());

    // A's clock is 60 s ahead (allowed skew is 120 s).
    let ahead = w.now_ms() + 60_000;
    let id = load(&a);
    let vc = VerifiedContact::parse_and_verify(&b.record, w.now_ms()).unwrap();
    let env = Envelope::new(
        id.address(),
        vc.address,
        MESSAGE_TYPE_MESSAGE,
        "from the future".to_owned(),
        ahead,
        TTL,
    )
    .unwrap();
    let frame = seal(&id, &vc, &env, w.now_ms(), 150_000).unwrap();
    inject(&w, &b, &frame);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.inbox().await.len(), 1, "accepted within the skew");

    b.node.close();
    restore_store(&b, &backup);
    w.advance(5_000);
    let b = w.reopen(b, cfg());
    assert!(status(&b).await.replay_guard.is_some());
    let outbox_rows = b.n("outbox");
    inject(&w, &b, &frame);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.inbox().await.len(), 0, "replay must not be delivered");
    assert_eq!(b.metric("guard.held"), 1);
    assert_eq!(b.n("outbox"), outbox_rows, "no ack queued");
    assert_eq!(b.n("events"), 0);
}

#[tokio::test]
async fn accept_rollback_releases_unexpired_held_messages() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    let backup = w.dir.path().join("b-backup.sqlite");
    b.node.close();
    copy_store(&b, &backup);
    let b = w.reopen(b, cfg());
    a.send(&b, "m").await;
    settle(&[&a, &b]).await;
    let f = captured(&w, &a);
    b.node.close();
    restore_store(&b, &backup);
    w.advance(1_000);
    let b = w.reopen(b, cfg());
    inject(&w, &b, &f.payload);
    b.node.step_receive().await.unwrap();
    assert_eq!(b.n("inbox"), 1, "held row stored");
    assert_eq!(b.inbox().await.len(), 0);

    // operator: `agentnet doctor --accept-rollback` (daemon stopped)
    b.node.close();
    assert!(guard::accept_rollback(&b.store_path).unwrap());
    let b = w.reopen(b, cfg());
    assert!(status(&b).await.replay_guard.is_none());
    // the held message is released (documented: this accepts the replay
    // exposure for messages that were genuinely received before the rollback)
    assert_eq!(b.inbox().await.len(), 1);
    assert_eq!(b.metric("guard.released"), 1);
    settle(&[&a, &b]).await;
    // and now it is acked, so the sender sees delivery
    assert_eq!(
        a.state(
            &a.node
                .read_outbox(PageRequest::default())
                .await
                .unwrap()
                .records[0]
                .status
                .message_id
        )
        .await,
        DeliveryState::Delivered
    );
    // accepting again is a no-op
    b.node.close();
    assert!(!guard::accept_rollback(&b.store_path).unwrap());
}

#[tokio::test]
async fn missing_sidecar_next_to_a_database_means_unknown_history() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    a.send(&b, "m").await;
    settle(&[&a, &b]).await;
    b.node.close();
    std::fs::remove_file(guard::sidecar_path(&b.store_path)).unwrap();
    let b = w.reopen(b, cfg());
    assert_eq!(
        status(&b).await.replay_guard.unwrap().reason,
        "unknown_history"
    );
    // a brand new agent (fresh store, no sidecar) is NOT guarded
    let c = w.agent("c", cfg());
    assert!(status(&c).await.replay_guard.is_none());
}

/// Scenario 3 (migration): a new data dir for an imported identity starts in
/// guard mode by default; `--no-replay-guard` skips it (exposed); copying the
/// store + sidecar preserves the dedupe history.
#[tokio::test]
async fn migration_guard_by_default_and_full_state_copy_keeps_history() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    a.send(&b, "m").await;
    settle(&[&a, &b]).await;
    let f = captured(&w, &a);
    b.node.close();

    let open_new = |name: &str, mark: bool, copy_from: Option<&Agent>| {
        let store = w.dir.path().join(format!("{name}.sqlite"));
        if let Some(src) = copy_from {
            std::fs::copy(&src.store_path, &store).unwrap();
            std::fs::copy(
                guard::sidecar_path(&src.store_path),
                guard::sidecar_path(&store),
            )
            .unwrap();
        } else if mark {
            guard::mark_imported(&store).unwrap();
        }
        let id = Identity::load(&b.id_path).unwrap();
        agentnet_core::Node::open(
            id,
            &store,
            std::sync::Arc::new(w.net.endpoint()),
            cfg(),
            std::sync::Arc::new(w.clock.clone()),
        )
        .unwrap()
    };
    w.advance(2_000);

    // identity import into a new dir, default: guard (replay held)
    let guarded = open_new("guarded", true, None);
    assert_eq!(
        guarded
            .network_status(false)
            .await
            .unwrap()
            .replay_guard
            .unwrap()
            .reason,
        "imported"
    );
    // `--no-replay-guard`: no guard, no dedupe history: the replay is delivered
    let open = open_new("unguarded", false, None);
    assert!(open
        .network_status(false)
        .await
        .unwrap()
        .replay_guard
        .is_none());
    // full-state copy: history preserved, replay is a duplicate, no guard
    let copy = open_new("copied", false, Some(&b));
    assert!(copy
        .network_status(false)
        .await
        .unwrap()
        .replay_guard
        .is_none());

    let topic = topic_of(&b.record);
    for n in [&guarded, &open, &copy] {
        n.step_receive().await.unwrap(); // subscribe
                                         // (a no-op for the copy, which carried its contacts over)
        let _ = n
            .add_contact(AddContactRequest {
                contact_record: a.record.clone(),
                ..Default::default()
            })
            .await;
    }
    w.net.inject_raw(&topic, &f.payload);
    for n in [&guarded, &open, &copy] {
        n.step_receive().await.unwrap();
    }
    let inbox = |n: &std::sync::Arc<agentnet_core::Node>| n.debug_table_count("inbox");
    assert_eq!(inbox(&guarded), 1, "stored, but held");
    assert_eq!(guarded.metrics().get("guard.held"), 1);
    assert_eq!(
        inbox(&open),
        1,
        "no history and no guard: replay accepted (documented exposure)"
    );
    assert_eq!(open.metrics().get("guard.held"), 0);
    assert_eq!(
        copy.metrics().get("message.duplicate"),
        1,
        "history carried over"
    );
    assert_eq!(inbox(&copy), 1);
    for n in [&guarded, &open, &copy] {
        n.close();
    }
}

/// Scenario 4 (concurrent identity): the same identity live in two data dirs.
#[tokio::test]
async fn concurrent_identity_in_two_data_dirs_is_not_prevented() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b1, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b1).await;
    // second instance of B's identity in another data dir, same network
    let id2 = w.dir.path().join("b2.identity.json");
    std::fs::copy(&b1.id_path, &id2).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&id2, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let node2 = agentnet_core::Node::open(
        Identity::load(&id2).unwrap(),
        &w.dir.path().join("b2.sqlite"),
        std::sync::Arc::new(w.net.endpoint()),
        cfg(),
        std::sync::Arc::new(w.clock.clone()),
    )
    .unwrap();
    node2.step_receive().await.unwrap();
    node2
        .add_contact(AddContactRequest {
            contact_record: a.record.clone(),
            ..Default::default()
        })
        .await
        .unwrap();

    let m = a.send(&b1, "to the shared identity").await;
    a.node.step_send().await.unwrap();
    b1.node.step_receive().await.unwrap();
    node2.step_receive().await.unwrap();
    // each instance persists the message once, independently
    assert_eq!(b1.inbox().await.len(), 1);
    assert_eq!(node2.debug_table_count("inbox"), 1);
    // both ack; A marks it delivered on the first ack and ignores the second
    b1.node.step_send().await.unwrap();
    node2.step_send().await.unwrap();
    a.node.step_receive().await.unwrap();
    assert_eq!(a.state(&m.message_id).await, DeliveryState::Delivered);
    assert_eq!(a.metric("ack.applied"), 1);
    assert_eq!(a.metric("ack.ignored_already_delivered"), 1);
    // nothing in either instance can tell it is not alone (no sound detection)
    assert!(status(&b1).await.replay_guard.is_none());
    node2.close();
}

/// Scenario 5: replay across a KEM revocation, and after dedupe pruning.
#[tokio::test]
async fn replay_across_kem_revocation_and_after_pruning() {
    let w = World::new();
    let mut v = started(&w, &["a", "b"]).await;
    let (b, a) = (v.pop().unwrap(), v.pop().unwrap());
    exchange(&a, &b).await;
    a.send(&b, "once").await;
    settle(&[&a, &b]).await;
    let f = captured(&w, &a);
    rotate(&w, &b, true);
    let b = w.reopen(b, cfg());
    let nfu = b.metric("frame.not_for_us");
    inject(&w, &b, &f.payload);
    b.node.step_receive().await.unwrap();
    // frames sealed to a revoked epoch can no longer be opened at all
    assert_eq!(b.metric("frame.not_for_us"), nfu + 1);
    // the pruning case is engine_security::replay_now_and_after_dedupe_pruning
    assert_eq!(b.inbox().await.len(), 1, "only the original, from before");
}

// ------------------------------------------- concurrent send vs. revocation

/// Review finding 2: while the first publish of a batch awaits, a tombstone for
/// a later recipient of the same batch is applied. The later (cached) frame must
/// never reach the transport.
#[tokio::test]
async fn revocation_during_a_pending_publish_stops_later_frames_of_the_batch() {
    let w = World::new();
    let (s, gate) = w.agent_gated("s", cfg());
    let mut v = started(&w, &["r1", "r2"]).await;
    let (r2, r1) = (v.pop().unwrap(), v.pop().unwrap());
    s.node.step_receive().await.unwrap();
    s.add(&r1).await;
    s.add(&r2).await;
    let m1 = s.send(&r1, "first").await;
    let m2 = s.send(&r2, "second").await;

    gate.arm();
    let n = s.node.clone();
    let task = tokio::spawn(async move { n.step_send().await.unwrap() });
    gate.wait_reached().await;
    // the tombstone arrives while m1's publish is awaiting
    s.node
        .import_revocation(&tombstone(&w, &r2, "gone"))
        .unwrap();
    gate.release();
    task.await.unwrap();

    assert_eq!(s.state(&m2.message_id).await, DeliveryState::Failed);
    let to_r2 = topic_of(&r2.record);
    assert_eq!(
        w.net.publish_count(&to_r2),
        0,
        "a revoked recipient's frame must not be published"
    );
    assert_eq!(w.net.publish_count(&topic_of(&r1.record)), 1);
    assert_ne!(s.state(&m1.message_id).await, DeliveryState::Failed);
}

/// Review finding 2 (rotation): the re-sealed frame, not the cached old-key
/// frame, is what a later batch entry publishes.
#[tokio::test]
async fn key_update_during_a_pending_publish_publishes_the_resealed_frame() {
    let w = World::new();
    let (s, gate) = w.agent_gated("s", cfg());
    let mut v = started(&w, &["r1", "r2"]).await;
    let (r2, r1) = (v.pop().unwrap(), v.pop().unwrap());
    s.node.step_receive().await.unwrap();
    s.add(&r1).await;
    s.add(&r2).await;
    // R2 also knows S so it can send the contact.update
    r2.add(&s).await;
    s.send(&r1, "first").await;
    let m2 = s.send(&r2, "second").await;
    let old_frame: Vec<u8> = {
        let c = rusqlite::Connection::open(&s.store_path).unwrap();
        c.query_row(
            "SELECT frame FROM outbox WHERE message_id = ?1",
            [&m2.message_id],
            |r| r.get(0),
        )
        .unwrap()
    };

    // R2 rotates (old key revoked) and announces it, but S has not seen it yet
    rotate(&w, &r2, true);
    let r2 = w.reopen(r2, cfg());

    gate.arm();
    let n = s.node.clone();
    let task = tokio::spawn(async move { n.step_send().await.unwrap() });
    gate.wait_reached().await;
    // R2 publishes its contact.update; S applies it and re-seals m2
    r2.node.step_send().await.unwrap();
    s.node.step_receive().await.unwrap();
    assert!(s.metric("outbox.resealed") >= 1);
    gate.release();
    task.await.unwrap();

    let to_r2 = topic_of(&r2.record);
    let frames: Vec<_> = w
        .net
        .published_frames()
        .into_iter()
        .filter(|f| f.topic == to_r2 && f.publisher == Some(s.transport.index()))
        .collect();
    assert!(
        frames.iter().all(|f| f.payload != old_frame),
        "the obsolete old-key frame must never be published"
    );
}
