//! Operations on a data directory while no daemon runs: init, identity
//! export/import/rotation. Everything that rewrites secrets takes the
//! data-dir lock, so it fails while a daemon is running.

use std::path::Path;

use agentnet_core::api::IdentityInfo;
use agentnet_core::crypto::VerifiedRevocation;
use agentnet_core::identity::Identity;
use agentnet_core::{guard, Clock, SystemClock};

use crate::config::{render_init_config, render_private_config, DaemonConfig};
use crate::datadir::{create_secret_file, ensure_token, DataDir};
use crate::error::DaemonError;

fn ident_err(e: impl std::fmt::Display) -> DaemonError {
    DaemonError::Identity(e.to_string())
}

/// What `init` created.
#[derive(Clone, Debug)]
pub struct InitReport {
    /// Public identity (address, contact record).
    pub identity: IdentityInfo,
    /// True when the config has no peers yet (the daemon will refuse to start).
    pub peers_missing: bool,
}

/// Public information of an identity.
pub fn identity_info(id: &Identity) -> IdentityInfo {
    IdentityInfo {
        agent_id: id.address().to_string(),
        contact_record: id.contact_record().to_document(),
        inbox_topic: id.inbox_topic().to_string(),
        created_at: id.created_at(),
        kem_expires_at: id.kem_expires_at(),
        key_epoch: id.key_epoch(),
        revoked: false,
    }
}

/// Public identity of a data directory, including whether it was revoked.
fn identity_info_of(dir: &DataDir, id: &Identity) -> IdentityInfo {
    let mut i = identity_info(id);
    i.revoked = dir.revocation().exists();
    i
}

fn refuse_existing(dir: &DataDir) -> Result<(), DaemonError> {
    for p in [dir.identity(), dir.config(), dir.db()] {
        if p.exists() {
            return Err(DaemonError::DataDir(format!(
                "{} already exists; refusing to overwrite an existing agent \
                 (choose another --data-dir)",
                p.display()
            )));
        }
    }
    Ok(())
}

fn write_support_files(
    dir: &DataDir,
    config_text: &str,
    peers_missing: bool,
) -> Result<bool, DaemonError> {
    create_secret_file(&dir.config(), config_text.as_bytes())?;
    ensure_token(&dir.control_token())?;
    ensure_token(&dir.mcp_token())?;
    Ok(peers_missing)
}

/// Create a data directory with a fresh identity, a private-mode config and
/// tokens. Refuses to touch an existing agent.
pub fn init_data_dir(
    root: &Path,
    node_url: &str,
    peers: &[String],
    inbox_buckets: u16,
    public_relay: bool,
) -> Result<InitReport, DaemonError> {
    // Validate before anything is created: a rejected peer writes nothing.
    let config_text = render_init_config(node_url, peers, public_relay)?;
    let dir = DataDir::new(root);
    dir.create_private()?;
    let _lock = dir.acquire_lock()?;
    refuse_existing(&dir)?;
    let id = Identity::generate(inbox_buckets, SystemClock.now_ms()).map_err(ident_err)?;
    id.save(&dir.identity(), false).map_err(ident_err)?;
    let peers_missing = write_support_files(&dir, &config_text, peers.is_empty())?;
    Ok(InitReport {
        identity: identity_info(&id),
        peers_missing,
    })
}

/// Public identity of the data directory (no lock needed, nothing secret returned).
pub fn show_identity(root: &Path) -> Result<IdentityInfo, DaemonError> {
    let dir = DataDir::new(root);
    dir.check_dir_perms()?;
    let id = Identity::load(&dir.identity()).map_err(ident_err)?;
    Ok(identity_info_of(&dir, &id))
}

/// Write a passphrase-encrypted export of the identity to `out` (mode 0600,
/// never overwrites). Requires the daemon to be stopped.
pub fn export_identity(
    root: &Path,
    out: &Path,
    passphrase: &str,
) -> Result<IdentityInfo, DaemonError> {
    let dir = DataDir::new(root);
    dir.check_dir_perms()?;
    let _lock = dir.acquire_lock()?;
    let id = Identity::load(&dir.identity()).map_err(ident_err)?;
    let bytes = id.export_encrypted(passphrase).map_err(ident_err)?;
    create_secret_file(out, &bytes)?;
    Ok(identity_info_of(&dir, &id))
}

/// Restore an exported identity into a data directory that has none. Creates
/// the directory, a private-mode config and tokens as `init` does.
///
/// With `replay_guard` (the CLI default) the new store starts in replay-guard
/// mode: the new directory has no dedupe history, so messages created before the
/// first start are held instead of delivered until `max_ttl + clock_skew` has
/// passed or `agentnet doctor --accept-rollback` is run. Pass `false`
/// (`--no-replay-guard`) to skip it, accepting that frames captured before the
/// import can be accepted again within their TTL. Copying `agentnet.db` and
/// `agentnet.generation` (daemon stopped) instead preserves the history.
pub fn import_identity(
    root: &Path,
    encrypted: &[u8],
    passphrase: &str,
    node_url: &str,
    peers: &[String],
    replay_guard: bool,
) -> Result<InitReport, DaemonError> {
    let dir = DataDir::new(root);
    dir.create_private()?;
    let _lock = dir.acquire_lock()?;
    refuse_existing(&dir)?;
    let id = Identity::import_encrypted(encrypted, passphrase).map_err(ident_err)?;
    id.save(&dir.identity(), false).map_err(ident_err)?;
    let peers_missing = write_support_files(
        &dir,
        &render_private_config(node_url, peers),
        peers.is_empty(),
    )?;
    if replay_guard {
        guard::mark_imported(&dir.db())
            .map_err(|e| DaemonError::io("writing the generation sidecar", e))?;
    }
    Ok(InitReport {
        identity: identity_info(&id),
        peers_missing,
    })
}

/// Generate a new agreement key and increment the key epoch.
///
/// Without `revoke_previous` the previous key keeps decrypting for `keep_hours`
/// (default: `storage.retention_hours` of the config). With it, every earlier
/// KEM secret key is destroyed at once and the new record carries
/// `revoked_kem_epochs_below`; messages already sealed to the old key are lost
/// unless the sender re-seals them after learning the new record. At the next
/// daemon start the engine sends a `contact.update` to every Trusted contact.
/// Returns the new public identity.
pub fn rotate_kem(
    root: &Path,
    keep_hours: Option<u64>,
    revoke_previous: bool,
) -> Result<IdentityInfo, DaemonError> {
    let dir = DataDir::new(root);
    dir.check_dir_perms()?;
    let _lock = dir.acquire_lock()?;
    let hours = match keep_hours {
        Some(h) => h,
        None => DaemonConfig::load(&dir.config())
            .map(|c| c.storage.retention_hours)
            .unwrap_or(168),
    };
    let mut id = Identity::load(&dir.identity()).map_err(ident_err)?;
    let now = SystemClock.now_ms();
    let keep_until =
        now.saturating_add(i64::try_from(hours.saturating_mul(3_600_000)).unwrap_or(i64::MAX / 2));
    if dir.revocation().exists() {
        return Err(DaemonError::Identity(
            "this identity has been revoked; rotate-kem is pointless (use a new identity)".into(),
        ));
    }
    id.rotate_kem_with(now, keep_until, None, revoke_previous)
        .map_err(ident_err)?;
    id.save(&dir.identity(), true).map_err(ident_err)?;
    Ok(identity_info_of(&dir, &id))
}

/// Result of `identity revoke`.
#[derive(Clone, Debug)]
pub struct RevokeReport {
    /// Public identity (with `revoked = true`).
    pub identity: IdentityInfo,
    /// The signed tombstone document to distribute out of band.
    pub document: String,
}

/// Revoke the signing identity: create a signed tombstone, write it next to the
/// identity (`revocation.json`, mode 0600, never overwritten) and thereby mark
/// the local identity revoked. The next daemon start only delivers the
/// tombstone (to Trusted contacts) and sends nothing else. Requires the daemon
/// to be stopped. This is irreversible for this address.
pub fn revoke_identity(root: &Path, reason: &str) -> Result<RevokeReport, DaemonError> {
    let dir = DataDir::new(root);
    dir.check_dir_perms()?;
    let _lock = dir.acquire_lock()?;
    if dir.revocation().exists() {
        return Err(DaemonError::Identity(format!(
            "{} already exists: this identity is already revoked",
            dir.revocation().display()
        )));
    }
    let id = Identity::load(&dir.identity()).map_err(ident_err)?;
    let t = id
        .create_revocation(reason, SystemClock.now_ms())
        .map_err(ident_err)?;
    let doc = t.to_document();
    create_secret_file(&dir.revocation(), doc.as_bytes())?;
    let mut info = identity_info(&id);
    info.revoked = true;
    Ok(RevokeReport {
        identity: info,
        document: doc,
    })
}

/// The stored tombstone of a revoked identity (for out-of-band distribution).
pub fn show_revocation(root: &Path) -> Result<Option<String>, DaemonError> {
    let dir = DataDir::new(root);
    dir.check_dir_perms()?;
    let id = Identity::load(&dir.identity()).map_err(ident_err)?;
    match std::fs::read_to_string(dir.revocation()) {
        Ok(doc) => {
            let v = VerifiedRevocation::parse_and_verify(&doc, SystemClock.now_ms())
                .map_err(ident_err)?;
            if v.address != id.address() {
                return Err(DaemonError::Identity(
                    "revocation.json names a different address than identity.json".into(),
                ));
            }
            Ok(Some(doc))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(DaemonError::io("reading revocation.json", e)),
    }
}

/// `agentnet doctor --accept-rollback`: accept a detected store rollback,
/// unknown store history or imported identity so the next start does not hold
/// older messages (and releases the held ones). Requires the daemon to be
/// stopped. Returns whether there was anything to accept.
pub fn accept_rollback(root: &Path) -> Result<bool, DaemonError> {
    let dir = DataDir::new(root);
    dir.check_dir_perms()?;
    let _lock = dir.acquire_lock()?;
    guard::accept_rollback(&dir.db()).map_err(|e| DaemonError::Identity(e.to_string()))
}
