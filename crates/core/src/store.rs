//! SQLite store: schema, migrations and the transaction primitive.
//!
//! One connection behind a `std::sync::Mutex`. Every call is a short
//! statement or a short transaction and the mutex is never held across an
//! `.await`, so the engine runs the SQL inline instead of through
//! `spawn_blocking` (a thread hop per statement would cost more than the
//! statements). `synchronous=FULL` is used on purpose: an `ack.received` tells
//! the sender "your message is durably persisted", and with WAL + `NORMAL` the
//! last commits can be lost on power failure after the ack was already sent.
//! The cost is one fsync per transaction, acceptable at agent message rates.

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::api::ApiError;

/// Current schema version (`PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 2;

/// Failure of a store operation. `Display` never contains row contents.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite reported an error.
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The store was closed.
    #[error("store is closed")]
    Closed,
    /// A test-injected failure.
    #[error("injected store failure")]
    Injected,
    /// A domain error raised inside a transaction (rolls it back).
    #[error("{0}")]
    Api(ApiError),
    /// Stored data failed validation.
    #[error("corrupt stored data: {0}")]
    Corrupt(&'static str),
}

impl From<ApiError> for StoreError {
    fn from(e: ApiError) -> Self {
        Self::Api(e)
    }
}

impl StoreError {
    /// Map to the sanitized API error.
    pub fn to_api(&self) -> ApiError {
        match self {
            Self::Api(e) => e.clone(),
            Self::Closed => ApiError::unavailable("node is shut down"),
            _ => ApiError::internal("storage error"),
        }
    }
}

const SCHEMA_V1: &str = "
CREATE TABLE kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE contacts (
  address    TEXT PRIMARY KEY,
  document   TEXT NOT NULL,
  alias      TEXT,
  trust      TEXT NOT NULL CHECK (trust IN ('trusted','untrusted','blocked')),
  added_at   INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE outbox (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id      TEXT NOT NULL UNIQUE,
  recipient       TEXT NOT NULL,
  topic           TEXT NOT NULL,
  type            TEXT NOT NULL,
  conversation_id TEXT,
  correlation_id  TEXT,
  body            TEXT NOT NULL,
  frame           BLOB NOT NULL,
  state           TEXT NOT NULL CHECK (state IN ('queued','sent','delivered','failed','expired')),
  attempts        INTEGER NOT NULL DEFAULT 0,
  failures        INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  last_attempt_at INTEGER,
  next_attempt_at INTEGER,
  sent_at         INTEGER,
  delivered_at    INTEGER,
  last_error      TEXT,
  idempotency_key TEXT UNIQUE,
  is_ack          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX outbox_due ON outbox (next_attempt_at) WHERE state IN ('queued','sent');
CREATE INDEX outbox_conv ON outbox (conversation_id);

CREATE TABLE inbox (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id      TEXT NOT NULL,
  sender          TEXT NOT NULL,
  type            TEXT NOT NULL,
  conversation_id TEXT,
  correlation_id  TEXT,
  body            TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  received_at     INTEGER NOT NULL,
  acknowledged_at INTEGER,
  quarantined     INTEGER NOT NULL DEFAULT 0,
  sender_trust    TEXT NOT NULL CHECK (sender_trust IN ('trusted','untrusted','unknown')),
  UNIQUE (sender, message_id)
);
CREATE INDEX inbox_conv ON inbox (conversation_id);
CREATE INDEX inbox_msg ON inbox (message_id);

CREATE TABLE seen (
  sender        TEXT NOT NULL,
  message_id    TEXT NOT NULL,
  expires_at    INTEGER NOT NULL,
  last_reack_at INTEGER,
  PRIMARY KEY (sender, message_id)
) WITHOUT ROWID;
CREATE INDEX seen_expiry ON seen (expires_at);

CREATE TABLE transport_seen (
  transport_id BLOB PRIMARY KEY,
  first_seen   INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX transport_seen_age ON transport_seen (first_seen);

CREATE TABLE triggers (
  id              TEXT PRIMARY KEY,
  sender          TEXT,
  type            TEXT,
  conversation_id TEXT,
  correlation_id  TEXT,
  target_session  TEXT NOT NULL,
  once            INTEGER NOT NULL,
  state           TEXT NOT NULL CHECK (state IN ('active','consumed','expired','deleted')),
  match_count     INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE events (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id       TEXT NOT NULL UNIQUE,
  type           TEXT NOT NULL CHECK (type IN ('message.received','trigger.matched')),
  message_id     TEXT NOT NULL,
  trigger_id     TEXT,
  target_session TEXT,
  timestamp      INTEGER NOT NULL,
  acked          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX events_budget ON events (type, timestamp);
";

/// v1 -> v2: hidden (system) outbox rows, replay-guard holds on inbox rows and
/// the identity-revocation table.
const SCHEMA_V2: &str = "
ALTER TABLE outbox ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0;
ALTER TABLE inbox ADD COLUMN hold_reason TEXT;
CREATE TABLE revocations (
  address     TEXT PRIMARY KEY,
  document    TEXT NOT NULL,
  revoked_at  INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  source      TEXT NOT NULL
) WITHOUT ROWID;
";

/// The SQLite store.
pub struct Store {
    conn: Mutex<Option<Connection>>,
    fail_next: AtomicU32,
}

impl Store {
    /// Open (creating if needed) and migrate the database at `path`.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    fn init(mut conn: Connection) -> Result<Self, StoreError> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if v > SCHEMA_VERSION {
            return Err(StoreError::Corrupt(
                "database was written by a newer version",
            ));
        }
        if v < 1 {
            let tx = conn.transaction()?;
            tx.execute_batch(SCHEMA_V1)?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
        }
        if v < 2 {
            let tx = conn.transaction()?;
            tx.execute_batch(SCHEMA_V2)?;
            tx.pragma_update(None, "user_version", 2)?;
            tx.commit()?;
        }
        Ok(Self {
            conn: Mutex::new(Some(conn)),
            fail_next: AtomicU32::new(0),
        })
    }

    /// Make the next `n` transactions fail (test hook simulating a disk error).
    pub fn inject_failures(&self, n: u32) {
        self.fail_next.store(n, Ordering::SeqCst);
    }

    /// Run `f` in one immediate transaction; commit on `Ok`, roll back on `Err`.
    pub fn tx<R>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let mut g = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let conn = g.as_mut().ok_or(StoreError::Closed)?;
        if self
            .fail_next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(StoreError::Injected);
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let r = f(&tx)?;
        tx.commit()?;
        Ok(r)
    }

    /// Run a read-only closure on the connection.
    pub fn read<R>(
        &self,
        f: impl FnOnce(&Connection) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let g = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let conn = g.as_ref().ok_or(StoreError::Closed)?;
        f(conn)
    }

    /// Checkpoint the WAL and close the connection. Later calls fail with `Closed`.
    pub fn close(&self) {
        let mut g = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(conn) = g.take() {
            let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
            let _ = conn.close();
        }
    }
}

/// Read a kv value.
pub fn kv_get(conn: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    Ok(conn
        .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
        .optional()?)
}

/// Write a kv value.
pub fn kv_set(conn: &Connection, key: &str, value: &str) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO kv (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database created by the v1 code path (the v1 schema, user_version 1,
    /// with rows in every table that v2 touches) migrates to v2 in place.
    #[test]
    fn migrates_a_v1_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO outbox (message_id, recipient, topic, type, body, frame, state, created_at, expires_at)
                 VALUES ('m1','an1x','/t','message','b',x'00','queued',1,2)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO inbox (message_id, sender, type, body, created_at, expires_at, received_at, sender_trust)
                 VALUES ('m2','an1y','message','b',1,2,3,'trusted')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO kv (key, value) VALUES ('own_address','an1z')",
                [],
            )
            .unwrap();
        }
        let store = Store::open(&path).unwrap();
        store
            .read(|c| {
                let v: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
                assert_eq!(v, SCHEMA_VERSION);
                let hidden: i64 =
                    c.query_row("SELECT hidden FROM outbox WHERE message_id='m1'", [], |r| {
                        r.get(0)
                    })?;
                assert_eq!(hidden, 0);
                let hold: Option<String> = c.query_row(
                    "SELECT hold_reason FROM inbox WHERE message_id='m2'",
                    [],
                    |r| r.get(0),
                )?;
                assert_eq!(hold, None);
                let n: i64 = c.query_row("SELECT COUNT(*) FROM revocations", [], |r| r.get(0))?;
                assert_eq!(n, 0);
                assert_eq!(kv_get(c, "own_address")?.as_deref(), Some("an1z"));
                Ok(())
            })
            .unwrap();
        store.close();
        // reopening a v2 database is a no-op
        let store = Store::open(&path).unwrap();
        store.close();
    }

    #[test]
    fn refuses_a_newer_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        assert!(matches!(Store::open(&path), Err(StoreError::Corrupt(_))));
    }
}
