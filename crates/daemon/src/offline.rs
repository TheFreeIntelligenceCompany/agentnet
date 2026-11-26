//! Operations on a data directory while no daemon runs: init, identity
//! export/import/rotation. Everything that rewrites secrets takes the
//! data-dir lock, so it fails while a daemon is running.

use std::path::Path;

use agentnet_core::api::IdentityInfo;
use agentnet_core::identity::Identity;
use agentnet_core::{Clock, SystemClock};

use crate::config::{render_private_config, DaemonConfig};
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
    node_url: &str,
    peers: &[String],
) -> Result<bool, DaemonError> {
    create_secret_file(
        &dir.config(),
        render_private_config(node_url, peers).as_bytes(),
    )?;
    ensure_token(&dir.control_token())?;
    ensure_token(&dir.mcp_token())?;
    Ok(peers.is_empty())
}

/// Create a data directory with a fresh identity, a private-mode config and
/// tokens. Refuses to touch an existing agent.
pub fn init_data_dir(
    root: &Path,
    node_url: &str,
    peers: &[String],
    inbox_buckets: u16,
) -> Result<InitReport, DaemonError> {
    let dir = DataDir::new(root);
    dir.create_private()?;
    let _lock = dir.acquire_lock()?;
    refuse_existing(&dir)?;
    let id = Identity::generate(inbox_buckets, SystemClock.now_ms()).map_err(ident_err)?;
    id.save(&dir.identity(), false).map_err(ident_err)?;
    let peers_missing = write_support_files(&dir, node_url, peers)?;
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
    Ok(identity_info(&id))
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
    Ok(identity_info(&id))
}

/// Restore an exported identity into a data directory that has none. Creates
/// the directory, a private-mode config and tokens as `init` does.
pub fn import_identity(
    root: &Path,
    encrypted: &[u8],
    passphrase: &str,
    node_url: &str,
    peers: &[String],
) -> Result<InitReport, DaemonError> {
    let dir = DataDir::new(root);
    dir.create_private()?;
    let _lock = dir.acquire_lock()?;
    refuse_existing(&dir)?;
    let id = Identity::import_encrypted(encrypted, passphrase).map_err(ident_err)?;
    id.save(&dir.identity(), false).map_err(ident_err)?;
    let peers_missing = write_support_files(&dir, node_url, peers)?;
    Ok(InitReport {
        identity: identity_info(&id),
        peers_missing,
    })
}

/// Generate a new agreement key; the previous one keeps decrypting for
/// `keep_hours` (default: `storage.retention_hours` of the config). Returns the
/// new public identity (give the new contact record to your peers).
pub fn rotate_kem(root: &Path, keep_hours: Option<u64>) -> Result<IdentityInfo, DaemonError> {
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
    id.rotate_kem(now, keep_until, None).map_err(ident_err)?;
    id.save(&dir.identity(), true).map_err(ident_err)?;
    Ok(identity_info(&id))
}
