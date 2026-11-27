//! `identity migrate` (store side) against a fixture written by the retired
//! ADR 0002 code (`tests/fixtures/legacy-v3`, see its README): an `an1` identity,
//! one contact, one inbox message and its dedupe row, one queued and two sent
//! outbox rows (user message, receipt), schema `user_version` 3.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use agentnet_core::api::*;
use agentnet_core::crypto::Identity;
use agentnet_core::migrate::{legacy_contacts, migrate_store, MIGRATION_FAILED_REASON};
use agentnet_core::store::SCHEMA_VERSION;
use agentnet_core::Node;
use agentnet_transport::mock::MockNetwork;
use agentnet_transport::Transport;
use common::cfg;

/// The fixture database is a binary that `.gitignore` would drop by its `*.db`
/// rule (a negation rule keeps it). Fail with a clear message if it is missing.
fn assert_fixture_present(dir: &std::path::Path) {
    for f in ["agentnet.db", "identity.json", "manifest.json", "README.md"] {
        assert!(
            dir.join(f).is_file(),
            "legacy-v3 fixture file {f} is missing from {}: it must be committed (the database needs \
             `git add -f` unless .gitignore has the negation rule); regenerate it as described in \
             tests/fixtures/legacy-v3/README.md",
            dir.display()
        );
    }
}

#[test]
fn the_legacy_fixture_files_are_all_present() {
    assert_fixture_present(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-v3"),
    );
}

fn fixture() -> (tempfile::TempDir, PathBuf, serde_json::Value) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-v3");
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("agentnet.db");
    assert_fixture_present(&src);
    std::fs::copy(src.join("agentnet.db"), &db).unwrap();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(src.join("manifest.json")).unwrap()).unwrap();
    (dir, db, manifest)
}

#[test]
fn the_fixture_is_an_old_format_database() {
    let (_d, db, m) = fixture();
    let c = rusqlite::Connection::open(&db).unwrap();
    let v: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 3);
    let own: String = c
        .query_row("SELECT value FROM kv WHERE key='own_address'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(own.starts_with("an1"));
    assert_eq!(own, m["owner_address"].as_str().unwrap());
}

#[tokio::test]
async fn migration_keeps_history_fails_pending_rows_and_keeps_old_contacts_unusable() {
    let (dir, db, m) = fixture();
    let id = Identity::generate(1_700_000_000_000).unwrap();
    let rep = migrate_store(&db, &id.address().to_string(), 1_700_000_000_000).unwrap();

    // pending user messages are listed and failed with a reason that says to re-send
    let mut ids: Vec<&str> = rep
        .failed_outbox
        .iter()
        .map(|r| r.message_id.as_str())
        .collect();
    ids.sort();
    let mut want = vec![
        m["outbound_sent_message_id"].as_str().unwrap(),
        m["outbound_queued_message_id"].as_str().unwrap(),
    ];
    want.sort();
    assert_eq!(ids, want);
    assert_eq!(rep.failed_hidden_rows, 1, "the pending receipt");
    assert!(MIGRATION_FAILED_REASON.contains("re-send"));
    // history and dedupe state are kept
    assert_eq!((rep.inbox_rows, rep.seen_rows), (1, 1));
    // the old contact is a legacy entry
    assert_eq!(rep.legacy_contacts.len(), 1);
    assert_eq!(
        rep.legacy_contacts[0].address,
        m["peer_address"].as_str().unwrap()
    );
    assert_eq!(legacy_contacts(&db).unwrap(), rep.legacy_contacts);
    assert_eq!(rep.old_address.as_deref(), m["owner_address"].as_str());

    // the database is at the current schema and no pending row is left
    let c = rusqlite::Connection::open(&db).unwrap();
    let v: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, SCHEMA_VERSION);
    let pending: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM outbox WHERE state IN ('queued','sent')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0);
    let reason: String = c
        .query_row(
            "SELECT last_error FROM outbox WHERE message_id=?1",
            [m["outbound_queued_message_id"].as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reason, MIGRATION_FAILED_REASON);
    drop(c);

    // a node on the migrated store runs under the new identity, serves the old inbox, and
    // cannot send to the old contact (an1 address) nor does it list it as a contact
    let net = MockNetwork::new();
    let t: Arc<dyn Transport> = Arc::new(net.endpoint());
    let node = Node::open(id, &db, t, cfg(), Arc::new(agentnet_core::SystemClock)).unwrap();
    let inbox = node
        .read_inbox(ReadInboxRequest::default())
        .await
        .unwrap()
        .records;
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].body, "legacy inbound hello");
    assert_eq!(
        inbox[0].message_id,
        m["inbound_message_id"].as_str().unwrap()
    );
    assert!(node.list_contacts().await.unwrap().is_empty());
    let e = node
        .send_message(SendMessageRequest {
            recipient: m["peer_address"].as_str().unwrap().to_owned(),
            body: "x".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(e.message.contains("contact add --expect"), "{}", e.message);
    // the failed rows are visible as failed
    let st = node
        .get_message_status(m["outbound_queued_message_id"].as_str().unwrap().to_owned())
        .await
        .unwrap();
    assert_eq!(st.state, DeliveryState::Failed);
    assert!(st.last_error.unwrap().contains("re-send"));
    drop(dir);
}

#[test]
fn a_second_migration_finds_nothing_left_to_convert() {
    let (_d, db, _m) = fixture();
    let id = Identity::generate(1_700_000_000_000).unwrap();
    migrate_store(&db, &id.address().to_string(), 1).unwrap();
    let again = migrate_store(&db, &id.address().to_string(), 2).unwrap();
    assert!(again.failed_outbox.is_empty());
    assert!(again.legacy_contacts.is_empty());
    assert_eq!(again.inbox_rows, 1);
    // legacy entries from the first run are still there
    assert_eq!(legacy_contacts(&db).unwrap().len(), 1);
}
