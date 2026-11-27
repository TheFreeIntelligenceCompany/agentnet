//! Store side of `agentnet identity migrate` (ADR 0004, lead decision 2).
//!
//! The retired HPKE + Ed25519 format (`an1` addresses, ADR 0002) is not converted
//! silently. Migration is explicit and changes the database in one transaction:
//!
//! * every old contact moves to `legacy_contacts` (kept as an *unverified legacy
//!   entry*: it cannot be sent to and sends nothing until the contact's new
//!   certificate is added with `contact add --expect <new address>`),
//! * every pending (`queued` or `sent`) outbox row is marked `failed` with a
//!   reason that says to re-send, and every such user message is listed in the
//!   report (acks and hidden system rows are failed too, silently),
//! * inbox history, the `(sender, message_id)` dedupe state and the history
//!   watermark are kept untouched,
//! * old adverts, announcement markers and the local revocation marker are removed,
//! * the stored own address becomes the new one.
//!
//! This module contains no cryptography: it only rewrites rows.

use std::path::Path;

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::store::{kv_get, kv_set, Store, StoreError};

/// The reason stored in `outbox.last_error` of a pending message that was not converted.
pub const MIGRATION_FAILED_REASON: &str =
    "legacy HPKE format: not converted by `agentnet identity migrate`; re-send after adding the recipient's new certificate";

/// A pending outbound message that was failed by the migration (re-send it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailedOutboxRow {
    pub message_id: String,
    pub recipient: String,
    pub message_type: String,
    pub state_before: String,
    pub created_at: i64,
}

/// An old contact kept as an unverified legacy entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyContact {
    pub address: String,
    pub alias: Option<String>,
    pub trust: String,
    pub added_at: i64,
}

/// What a store migration did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// The own address recorded in the store before (an `an1` address), if any.
    pub old_address: Option<String>,
    /// The new own address.
    pub new_address: String,
    /// Pending user messages failed with [`MIGRATION_FAILED_REASON`]: re-send them.
    pub failed_outbox: Vec<FailedOutboxRow>,
    /// Pending receipts and system messages that were failed (not listed individually).
    pub failed_hidden_rows: u64,
    /// Contacts kept as unverified legacy entries.
    pub legacy_contacts: Vec<LegacyContact>,
    /// Inbox rows preserved.
    pub inbox_rows: u64,
    /// `(sender, message_id)` dedupe rows preserved.
    pub seen_rows: u64,
}

/// Migrate the store at `path` to `new_address` (see the module documentation).
/// Safe to run again: a second run finds nothing left to convert.
pub fn migrate_store(
    path: &Path,
    new_address: &str,
    now_ms: i64,
) -> Result<MigrationReport, StoreError> {
    let store = Store::open(path)?;
    let report = store.tx(|tx| {
        let mut rep = MigrationReport {
            new_address: new_address.to_owned(),
            old_address: kv_get(tx, "own_address")?,
            ..Default::default()
        };
        // 1. contacts -> legacy entries
        {
            let mut st =
                tx.prepare("SELECT address, document, alias, trust, added_at FROM contacts")?;
            let rows: Vec<(String, String, Option<String>, String, i64)> = st
                .query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<Result<_, _>>()?;
            for (address, document, alias, trust, added_at) in rows {
                tx.execute(
                    "INSERT OR REPLACE INTO legacy_contacts (address, document, alias, trust, added_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![address, document, alias, trust, added_at],
                )?;
                rep.legacy_contacts.push(LegacyContact {
                    address,
                    alias,
                    trust,
                    added_at,
                });
            }
            tx.execute("DELETE FROM contacts", [])?;
        }
        // 2. pending outbox rows -> failed, listed
        {
            let mut st = tx.prepare(
                "SELECT message_id, recipient, type, state, created_at, is_ack, hidden
                 FROM outbox WHERE state IN ('queued','sent') ORDER BY seq",
            )?;
            let rows: Vec<(String, String, String, String, i64, i64, i64)> = st
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?
                .collect::<Result<_, _>>()?;
            for (message_id, recipient, ty, state, created_at, is_ack, hidden) in rows {
                if is_ack != 0 || hidden != 0 {
                    rep.failed_hidden_rows += 1;
                } else {
                    rep.failed_outbox.push(FailedOutboxRow {
                        message_id,
                        recipient,
                        message_type: ty,
                        state_before: state,
                        created_at,
                    });
                }
            }
            tx.execute(
                "UPDATE outbox SET state='failed', next_attempt_at=NULL, last_error=?1
                 WHERE state IN ('queued','sent')",
                [MIGRATION_FAILED_REASON],
            )?;
        }
        // 3. things that only make sense for the old identity
        tx.execute("DELETE FROM adverts", [])?;
        tx.execute("DELETE FROM kv WHERE key LIKE 'advert.%'", [])?;
        for k in [
            "announced_key_epoch",
            "announced_cert_id",
            "announced_revocation",
            "local_revocation",
        ] {
            tx.execute("DELETE FROM kv WHERE key = ?1", [k])?;
        }
        // 4. counts of what is preserved
        rep.inbox_rows = u64::try_from(tx.query_row("SELECT COUNT(*) FROM inbox", [], |r| {
            r.get::<_, i64>(0)
        })?)
        .unwrap_or(0);
        rep.seen_rows = u64::try_from(tx.query_row("SELECT COUNT(*) FROM seen", [], |r| {
            r.get::<_, i64>(0)
        })?)
        .unwrap_or(0);
        // 5. the new identity owns the store from now on
        kv_set(tx, "own_address", new_address)?;
        kv_set(tx, "migrated_at", &now_ms.to_string())?;
        Ok(rep)
    });
    store.close();
    report
}

/// The legacy contacts of the store at `path` (read-only).
pub fn legacy_contacts(path: &Path) -> Result<Vec<LegacyContact>, StoreError> {
    let store = Store::open(path)?;
    let r = store.read(|c| {
        let mut st = c.prepare(
            "SELECT address, alias, trust, added_at FROM legacy_contacts ORDER BY added_at, address",
        )?;
        let v = st
            .query_map([], |r| {
                Ok(LegacyContact {
                    address: r.get(0)?,
                    alias: r.get(1)?,
                    trust: r.get(2)?,
                    added_at: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(v)
    });
    store.close();
    r
}
