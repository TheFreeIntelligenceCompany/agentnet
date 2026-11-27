//! `agentnet identity migrate` on a data directory written by the retired
//! HPKE format (fixture in `crates/core/tests/fixtures/legacy-v3`).

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use agentnet_core::identity::Identity;
use agentnet_daemon::offline;

fn legacy_dir() -> (tempfile::TempDir, PathBuf) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures/legacy-v3");
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("home");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    for f in ["identity.json", "agentnet.db"] {
        std::fs::copy(src.join(f), root.join(f)).unwrap();
        std::fs::set_permissions(root.join(f), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(
        root.join("agentnet.toml"),
        "[network]\nmode = \"private\"\n",
    )
    .unwrap();
    (t, root)
}

#[test]
fn an_unmigrated_data_directory_is_refused_with_the_command_to_run() {
    let (_t, root) = legacy_dir();
    let e = offline::show_identity(&root).unwrap_err().to_string();
    assert!(e.contains("agentnet identity migrate"), "{e}");
    let e = Identity::load(&root.join("identity.json"))
        .unwrap_err()
        .to_string();
    assert!(e.contains("agentnet identity migrate"), "{e}");
}

#[test]
fn migrate_creates_a_fresh_identity_and_keeps_the_history() {
    let (_t, root) = legacy_dir();
    let old: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("identity.json")).unwrap()).unwrap();
    let rep = offline::migrate_data_dir(&root).unwrap();
    assert!(rep.identity.agent_id.starts_with("an2"));
    assert_ne!(rep.identity.agent_id, old["address"].as_str().unwrap());
    // the retired file is kept aside (0600), the new identity loads
    let legacy = root.join("identity.json.legacy-v1");
    assert_eq!(rep.legacy_identity_file, legacy);
    assert_eq!(
        std::fs::metadata(&legacy).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let id = Identity::load(&root.join("identity.json")).unwrap();
    assert_eq!(id.address().to_string(), rep.identity.agent_id);
    let st = rep.store.unwrap();
    assert_eq!(st.failed_outbox.len(), 2);
    assert_eq!(st.legacy_contacts.len(), 1);
    assert_eq!((st.inbox_rows, st.seen_rows), (1, 1));
    // not repeatable
    assert!(offline::migrate_data_dir(&root).is_err());
    // show works now
    assert_eq!(
        offline::show_identity(&root).unwrap().agent_id,
        rep.identity.agent_id
    );
}
