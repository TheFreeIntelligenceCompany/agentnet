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
    public_relay: bool,
) -> Result<InitReport, DaemonError> {
    // Validate before anything is created: a rejected peer writes nothing.
    let config_text = render_init_config(node_url, peers, public_relay)?;
    let dir = DataDir::new(root);
    dir.create_private()?;
    let _lock = dir.acquire_lock()?;
    refuse_existing(&dir)?;
    let id = Identity::generate(SystemClock.now_ms()).map_err(ident_err)?;
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

/// Add a new encryption subkey (with an expiry of `expires_in_days`, default
/// 365) and retire the previous one with a standard subkey revocation.
///
/// Without `revoke_previous` the previous subkey keeps decrypting for
/// `keep_hours` (default: `storage.retention_hours` of the config). With it,
/// every earlier encryption subkey is revoked as compromised and its secret key
/// destroyed at once; messages already sealed to it are lost unless the sender
/// re-seals them after merging the new certificate. At the next daemon start
/// the engine sends a `contact.update` (the new certificate, a merge input) to
/// every Trusted contact. Returns the new public identity.
pub fn rotate_kem(
    root: &Path,
    keep_hours: Option<u64>,
    revoke_previous: bool,
    expires_in_days: Option<u64>,
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
    let days = expires_in_days.unwrap_or(agentnet_core::identity::DEFAULT_KEM_VALIDITY_DAYS);
    let expiry = now.saturating_add(i64::try_from(days.saturating_mul(86_400_000)).unwrap_or(i64::MAX / 2));
    id.rotate_kem_with(now, keep_until, Some(expiry), revoke_previous)
        .map_err(ident_err)?;
    id.save(&dir.identity(), true).map_err(ident_err)?;
    Ok(identity_info_of(&dir, &id))
}

/// Result of `identity revoke`.
#[derive(Clone, Debug)]
pub struct RevokeReport {
    /// Public identity (with `revoked = true`).
    pub identity: IdentityInfo,
    /// The revocation document (the revoked public certificate) to distribute out of band.
    pub document: String,
}

/// Revoke the identity: create a primary-key revocation (a standard OpenPGP key
/// revocation signature, distributed as the revoked public certificate), write
/// it next to the identity (`revocation.json`, mode 0600, never overwritten)
/// and thereby mark the local identity revoked. The next daemon start only
/// delivers the revocation (to Trusted contacts) and sends nothing else.
/// Requires the daemon to be stopped. This is irreversible for this address.
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

/// The stored revocation of a revoked identity (for out-of-band distribution).
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

/// Result of `identity migrate`.
#[derive(Clone, Debug)]
pub struct MigrateReport {
    /// The new public identity (fresh OpenPGP certificate).
    pub identity: IdentityInfo,
    /// What happened to the store (None when the data directory had no store yet).
    pub store: Option<agentnet_core::migrate::MigrationReport>,
    /// Where the retired identity file was moved (kept for rollback; it holds secrets).
    pub legacy_identity_file: std::path::PathBuf,
}

/// `agentnet identity migrate` (ADR 0004, lead decision 2): explicit, never run
/// by `serve`. Generates a fresh OpenPGP identity (an old Ed25519 key is never
/// reused), moves the retired `identity.json` (and `revocation.json`) aside as
/// `*.legacy-v1`, and migrates the store (see `agentnet_core::migrate`):
/// pending old-format messages are failed and listed, old contacts become
/// unverified legacy entries, inbox history and dedupe state are kept. Requires
/// the daemon to be stopped. Refuses a data directory that is already migrated.
pub fn migrate_data_dir(root: &Path) -> Result<MigrateReport, DaemonError> {
    use agentnet_core::error::IdentityError;
    let dir = DataDir::new(root);
    dir.check_dir_perms()?;
    let _lock = dir.acquire_lock()?;
    match Identity::load(&dir.identity()) {
        Err(IdentityError::LegacyFormat) => {}
        Ok(_) => {
            return Err(DaemonError::Identity(
                "this data directory already uses the OpenPGP format; nothing to migrate".into(),
            ))
        }
        Err(e) => return Err(ident_err(e)),
    }
    let legacy = dir.root().join("identity.json.legacy-v1");
    if legacy.exists() {
        return Err(DaemonError::DataDir(format!(
            "{} already exists; move it away before migrating",
            legacy.display()
        )));
    }
    let now = SystemClock.now_ms();
    let id = Identity::generate(now).map_err(ident_err)?;
    let tmp = dir.root().join("identity.json.new");
    let _ = std::fs::remove_file(&tmp);
    id.save(&tmp, false).map_err(ident_err)?;
    let store = if dir.db().exists() {
        Some(
            agentnet_core::migrate::migrate_store(&dir.db(), &id.address().to_string(), now)
                .map_err(|e| DaemonError::Identity(format!("migrating the store: {e}")))?,
        )
    } else {
        None
    };
    std::fs::rename(dir.identity(), &legacy)
        .map_err(|e| DaemonError::io("moving the old identity aside", e))?;
    if dir.revocation().exists() {
        let rev_legacy = dir.root().join("revocation.json.legacy-v1");
        std::fs::rename(dir.revocation(), rev_legacy)
            .map_err(|e| DaemonError::io("moving the old revocation aside", e))?;
    }
    std::fs::rename(&tmp, dir.identity())
        .map_err(|e| DaemonError::io("installing the new identity", e))?;
    Ok(MigrateReport {
        identity: identity_info(&id),
        store,
        legacy_identity_file: legacy,
    })
}
