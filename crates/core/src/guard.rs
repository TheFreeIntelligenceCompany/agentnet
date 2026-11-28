//! Store generation counter, rollback sidecar and the replay guard.
//!
//! The engine's duplicate detection is the persisted `(sender, message_id)`
//! set. If the SQLite file is replaced by an older copy (backup restore, VM
//! snapshot, disk image) or a fresh store is created for an imported identity,
//! that history is gone and a captured frame could be accepted again within its
//! TTL. The cheap, sound mitigation:
//!
//! * the store keeps a monotonically increasing `store_generation` (bumped in
//!   every transaction that records a received message), mirrored after the
//!   commit in a sidecar file `<store>.generation` (written atomically and
//!   fsynced);
//! * on open, a DB generation *lower* than the sidecar's means the store was
//!   rolled back; a missing/unreadable sidecar next to a non-empty DB means the
//!   history is unknown; an `imported` marker (written by `identity import`)
//!   means a new data directory. All three enter **guard mode**;
//! * in guard mode inbound messages whose `created_at` is at or before the guard
//!   start plus `clock_skew` are held (quarantined, reason `replay_guard`, no
//!   ack, no trigger) until `max_ttl + clock_skew` has elapsed (they are all expired by
//!   then) or the operator accepts the rollback.
//!
//! What this does not do: it cannot recover messages that were received and
//! acknowledged between the restored copy and the rollback, and an attacker who
//! can also roll back the sidecar (or delete it together with the database and
//! the identity's data directory marker) defeats it. See `docs/protocol.md`.

use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::store::{kv_get, kv_set, Store, StoreError};

pub(crate) const KV_GENERATION: &str = "store_generation";
pub(crate) const KV_GUARD_REASON: &str = "replay_guard_reason";
pub(crate) const KV_GUARD_SINCE: &str = "replay_guard_since";
pub(crate) const KV_GUARD_UNTIL: &str = "replay_guard_until";
pub(crate) const KV_GUARD_CLEAR: &str = "replay_guard_clear_request";

/// Value of `inbox.hold_reason` for messages held by the guard.
pub(crate) const HOLD_REPLAY_GUARD: &str = "replay_guard";

/// Reason strings (stable; shown by `network status` and `doctor`).
pub const REASON_ROLLBACK: &str = "rollback";
/// See [`REASON_ROLLBACK`].
pub const REASON_UNKNOWN_HISTORY: &str = "unknown_history";
/// See [`REASON_ROLLBACK`].
pub const REASON_IMPORTED: &str = "imported";

/// Sidecar path for a store file: `agentnet.db` -> `agentnet.generation`.
pub fn sidecar_path(store_path: &Path) -> PathBuf {
    store_path.with_extension("generation")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarFile {
    v: u64,
    generation: u64,
    /// `Some("imported")` when written by `identity import`.
    #[serde(default)]
    guard: Option<String>,
}

/// Parsed sidecar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sidecar {
    /// Highest generation the store ever reported.
    pub generation: u64,
    /// Guard marker requested by an importer.
    pub guard: Option<String>,
}

/// Result of reading the sidecar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidecarState {
    /// No file.
    Missing,
    /// Present but unreadable or malformed.
    Unreadable,
    /// Parsed.
    Present(Sidecar),
}

/// Read the sidecar at `path`.
pub fn read_sidecar(path: &Path) -> SidecarState {
    match std::fs::read(path) {
        Ok(b) => match serde_json::from_slice::<SidecarFile>(&b) {
            Ok(f) if f.v == 1 => SidecarState::Present(Sidecar {
                generation: f.generation,
                guard: f.guard,
            }),
            _ => SidecarState::Unreadable,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SidecarState::Missing,
        Err(_) => SidecarState::Unreadable,
    }
}

/// Write the sidecar atomically (temp file, fsync, rename, fsync of the directory).
pub fn write_sidecar(path: &Path, s: &Sidecar) -> std::io::Result<()> {
    let body = serde_json::to_vec(&SidecarFile {
        v: 1,
        generation: s.generation,
        guard: s.guard.clone(),
    })
    .map_err(std::io::Error::other)?;
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "generation".into());
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| std::io::Error::other("randomness failed"))?;
    let tmp = dir.join(format!(
        ".{name}.tmp-{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let res = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res?;
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// An active guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardState {
    /// Why the guard was entered.
    pub reason: String,
    /// When it started (Unix ms). Messages created before this are held.
    pub since: i64,
    /// When it lapses by itself (Unix ms).
    pub until: i64,
}

pub(crate) fn load_guard(conn: &Connection) -> Result<Option<GuardState>, StoreError> {
    let Some(reason) = kv_get(conn, KV_GUARD_REASON)? else {
        return Ok(None);
    };
    let since = kv_get(conn, KV_GUARD_SINCE)?.and_then(|s| s.parse().ok());
    let until = kv_get(conn, KV_GUARD_UNTIL)?.and_then(|s| s.parse().ok());
    match (since, until) {
        (Some(since), Some(until)) => Ok(Some(GuardState {
            reason,
            since,
            until,
        })),
        _ => Err(StoreError::Corrupt("replay guard state")),
    }
}

pub(crate) fn save_guard(conn: &Connection, g: &GuardState) -> Result<(), StoreError> {
    kv_set(conn, KV_GUARD_REASON, &g.reason)?;
    kv_set(conn, KV_GUARD_SINCE, &g.since.to_string())?;
    kv_set(conn, KV_GUARD_UNTIL, &g.until.to_string())?;
    Ok(())
}

pub(crate) fn delete_guard(conn: &Connection) -> Result<(), StoreError> {
    conn.execute(
        "DELETE FROM kv WHERE key IN (?1, ?2, ?3, ?4)",
        [
            KV_GUARD_REASON,
            KV_GUARD_SINCE,
            KV_GUARD_UNTIL,
            KV_GUARD_CLEAR,
        ],
    )?;
    Ok(())
}

pub(crate) fn db_generation(conn: &Connection) -> Result<u64, StoreError> {
    match kv_get(conn, KV_GENERATION)? {
        None => Ok(0),
        Some(s) => s
            .parse()
            .map_err(|_| StoreError::Corrupt("store generation")),
    }
}

/// Increment the stored generation inside the caller's transaction.
pub(crate) fn bump_generation(conn: &Connection) -> Result<u64, StoreError> {
    let g = db_generation(conn)?.saturating_add(1);
    kv_set(conn, KV_GENERATION, &g.to_string())?;
    Ok(g)
}

/// Read-only summary for `doctor` (daemon stopped or running; nothing is changed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardReport {
    /// The database file exists.
    pub db_exists: bool,
    /// Generation recorded in the database.
    pub db_generation: Option<u64>,
    /// The sidecar as read.
    pub sidecar: SidecarState,
    /// The database is older than the sidecar (a rollback would be detected at start).
    pub rollback_suspected: bool,
    /// The sidecar is missing/unreadable next to an existing non-empty database.
    pub unknown_history: bool,
    /// Guard currently persisted in the database.
    pub active: Option<GuardState>,
    /// Messages currently held by the guard.
    pub held: u64,
}

/// Inspect `store_path` without modifying it.
pub fn inspect(store_path: &Path) -> Result<GuardReport, StoreError> {
    let sidecar = read_sidecar(&sidecar_path(store_path));
    if !store_path.exists() {
        return Ok(GuardReport {
            db_exists: false,
            db_generation: None,
            sidecar,
            rollback_suspected: false,
            unknown_history: false,
            active: None,
            held: 0,
        });
    }
    let conn = Connection::open_with_flags(
        store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let has_kv: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='kv'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);
    if !has_kv {
        return Ok(GuardReport {
            db_exists: true,
            db_generation: None,
            sidecar,
            rollback_suspected: false,
            unknown_history: false,
            active: None,
            held: 0,
        });
    }
    let non_empty = kv_get(&conn, "own_address")?.is_some();
    let generation = db_generation(&conn)?;
    let active = load_guard(&conn)?;
    let held: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM inbox WHERE hold_reason IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let (rollback_suspected, unknown_history) = match &sidecar {
        SidecarState::Present(s) => (s.generation > generation, false),
        _ => (false, non_empty),
    };
    Ok(GuardReport {
        db_exists: true,
        db_generation: Some(generation),
        sidecar,
        rollback_suspected,
        unknown_history,
        active,
        held: u64::try_from(held).unwrap_or(0),
    })
}

/// Accept a rollback / unknown history (`agentnet doctor --accept-rollback`).
///
/// Run with the daemon stopped. Records the request in the database and
/// re-synchronises the sidecar, so the next start does not enter (or leaves)
/// guard mode and releases messages held by an earlier guard. Returns whether
/// there was anything to accept.
pub fn accept_rollback(store_path: &Path) -> Result<bool, StoreError> {
    let report = inspect(store_path)?;
    let needed = report.active.is_some()
        || report.rollback_suspected
        || report.unknown_history
        || matches!(&report.sidecar, SidecarState::Present(s) if s.guard.is_some());
    if !needed {
        return Ok(false);
    }
    if !report.db_exists {
        // Nothing stored yet: only drop an `imported` marker.
        let sp = sidecar_path(store_path);
        if let SidecarState::Present(s) = &report.sidecar {
            if s.guard.is_some() {
                write_sidecar(
                    &sp,
                    &Sidecar {
                        generation: s.generation,
                        guard: None,
                    },
                )
                .map_err(|_| StoreError::Corrupt("could not write the generation sidecar"))?;
                return Ok(true);
            }
        }
        return Ok(false);
    }
    let store = Store::open(store_path)?;
    let sc_gen = match &report.sidecar {
        SidecarState::Present(s) => s.generation,
        _ => 0,
    };
    let g = store.tx(|tx| {
        let g = db_generation(tx)?.max(sc_gen);
        kv_set(tx, KV_GENERATION, &g.to_string())?;
        kv_set(tx, KV_GUARD_CLEAR, "1")?;
        Ok(g)
    })?;
    store.close();
    write_sidecar(
        &sidecar_path(store_path),
        &Sidecar {
            generation: g,
            guard: None,
        },
    )
    .map_err(|_| StoreError::Corrupt("could not write the generation sidecar"))?;
    Ok(needed)
}

/// Create or update the sidecar of a data directory in guard mode (`identity import`
/// without `--no-replay-guard`). Preserves an existing generation counter and
/// leaves an existing guard marker intact.
pub fn mark_imported(store_path: &Path) -> std::io::Result<()> {
    let sp = sidecar_path(store_path);
    let generation = match read_sidecar(&sp) {
        SidecarState::Present(s) if s.guard.is_some() => return Ok(()),
        SidecarState::Present(s) => s.generation,
        SidecarState::Missing | SidecarState::Unreadable => 0,
    };
    write_sidecar(
        &sp,
        &Sidecar {
            generation,
            guard: Some(REASON_IMPORTED.to_owned()),
        },
    )
}
