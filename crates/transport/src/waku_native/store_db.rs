//! Pure-Rust SQLite Store v3 archive for [`super::NativeWakuRelay`].
//!
//! Archives non-ephemeral Waku messages indexed by `(pubsub_topic, content_topic,
//! timestamp_ns, message_hash)`, enforces clock-skew and retention limits, and
//! answers `/vac/waku/store-query/3.0.0` requests with cursor pagination.

use std::path::Path;

use prost::Message;
use rusqlite::{params, Connection, OptionalExtension};

use super::proto::{StoreQueryRequest, StoreQueryResponse, WakuMessage, WakuMessageKeyValue};
use crate::waku_common::MAX_HISTORY_PAGE_SIZE;
use crate::TransportError;

const DEFAULT_STORE_PAGE_LIMIT: u64 = 20;

type StoreQueryResult = Result<(Vec<WakuMessageKeyValue>, Option<Vec<u8>>), (u32, String)>;

/// Retention and archive limits for [`StoreDb`].
#[derive(Clone, Debug)]
pub struct StoreDbLimits {
    /// Maximum age of archived messages in seconds.
    pub retention_seconds: u64,
    /// Maximum number of archived frames kept.
    pub retention_capacity: usize,
    /// Maximum allowed absolute difference between message timestamp and relay
    /// wall clock in seconds (nwaku default: 20 s).
    pub max_clock_skew_seconds: i64,
}

impl Default for StoreDbLimits {
    fn default() -> Self {
        Self {
            retention_seconds: 604_800, // 7 days
            retention_capacity: 100_000,
            max_clock_skew_seconds: 20,
        }
    }
}

/// SQLite-backed Waku Store v3 archive.
pub struct StoreDb {
    conn: Connection,
    limits: StoreDbLimits,
}

impl StoreDb {
    /// Opens an in-memory SQLite Store archive (for `--memory-only` and tests).
    pub fn open_in_memory(limits: StoreDbLimits) -> Result<Self, TransportError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| TransportError::Protocol(format!("opening in-memory store db: {e}")))?;
        Self::init(conn, limits)
    }

    /// Opens a persistent SQLite Store archive at `path`.
    pub fn open_file(path: &Path, limits: StoreDbLimits) -> Result<Self, TransportError> {
        let conn = Connection::open(path).map_err(|e| {
            TransportError::Protocol(format!("opening store db {}: {e}", path.display()))
        })?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.pragma_update(None, "synchronous", "NORMAL");
        Self::init(conn, limits)
    }

    fn init(conn: Connection, limits: StoreDbLimits) -> Result<Self, TransportError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS waku_messages (
                message_hash  BLOB PRIMARY KEY,
                pubsub_topic  TEXT NOT NULL,
                content_topic TEXT NOT NULL,
                timestamp_ns  INTEGER NOT NULL,
                raw_message   BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_waku_store_lookup
                ON waku_messages (pubsub_topic, timestamp_ns, message_hash);
            CREATE INDEX IF NOT EXISTS idx_waku_store_topic_time
                ON waku_messages (pubsub_topic, content_topic, timestamp_ns, message_hash);
            CREATE INDEX IF NOT EXISTS idx_waku_store_time
                ON waku_messages (timestamp_ns, message_hash);",
        )
        .map_err(|e| TransportError::Protocol(format!("initialising store schema: {e}")))?;
        Ok(Self { conn, limits })
    }

    /// Archives a validated message unless it is ephemeral or outside the clock
    /// skew window. Returns `true` if a new row was inserted.
    pub fn insert(
        &self,
        pubsub_topic: &str,
        message_hash: &[u8; 32],
        msg: &WakuMessage,
        raw_message: &[u8],
        now_ns: i64,
    ) -> Result<bool, TransportError> {
        if msg.ephemeral == Some(true) {
            return Ok(false);
        }
        let ts = msg.timestamp.unwrap_or(0);
        if ts <= 0 {
            return Ok(false);
        }
        let max_skew_ns = self
            .limits
            .max_clock_skew_seconds
            .saturating_mul(1_000_000_000);
        if (ts - now_ns).abs() > max_skew_ns {
            return Ok(false);
        }
        let changed = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO waku_messages
                 (message_hash, pubsub_topic, content_topic, timestamp_ns, raw_message)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    message_hash.as_slice(),
                    pubsub_topic,
                    &msg.content_topic,
                    ts,
                    raw_message,
                ],
            )
            .map_err(|e| TransportError::Protocol(format!("store insert: {e}")))?;
        if changed > 0 {
            self.enforce_capacity()?;
        }
        Ok(changed > 0)
    }

    /// Removes messages older than `retention_seconds` and enforces capacity.
    pub fn prune(&self, now_ns: i64) -> Result<usize, TransportError> {
        let retention_ns = i64::try_from(self.limits.retention_seconds)
            .unwrap_or(i64::MAX / 1_000_000_000)
            .saturating_mul(1_000_000_000);
        let cutoff = now_ns.saturating_sub(retention_ns);
        let removed_age = self
            .conn
            .execute(
                "DELETE FROM waku_messages WHERE timestamp_ns < ?1",
                params![cutoff],
            )
            .map_err(|e| TransportError::Protocol(format!("store age prune: {e}")))?;
        let removed_cap = self.enforce_capacity()?;
        Ok(removed_age + removed_cap)
    }

    fn enforce_capacity(&self) -> Result<usize, TransportError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM waku_messages", [], |r| r.get(0))
            .map_err(|e| TransportError::Protocol(format!("store count: {e}")))?;
        let cap = i64::try_from(self.limits.retention_capacity).unwrap_or(i64::MAX);
        if count <= cap {
            return Ok(0);
        }
        let excess = count - cap;
        let removed = self
            .conn
            .execute(
                "DELETE FROM waku_messages WHERE rowid IN (
                    SELECT rowid FROM waku_messages
                    ORDER BY timestamp_ns ASC, message_hash ASC
                    LIMIT ?1
                 )",
                params![excess],
            )
            .map_err(|e| TransportError::Protocol(format!("store capacity prune: {e}")))?;
        Ok(removed)
    }

    /// Total number of messages currently stored.
    pub fn count(&self) -> Result<usize, TransportError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM waku_messages", [], |r| r.get(0))
            .map_err(|e| TransportError::Protocol(format!("store count: {e}")))?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Executes a Waku Store v3 query.
    pub fn query(&self, req: &StoreQueryRequest) -> StoreQueryResponse {
        match self.query_inner(req) {
            Ok((messages, cursor)) => StoreQueryResponse {
                request_id: req.request_id.clone(),
                status_code: Some(200),
                status_desc: Some("OK".into()),
                messages,
                pagination_cursor: cursor,
            },
            Err((code, desc)) => StoreQueryResponse {
                request_id: req.request_id.clone(),
                status_code: Some(code),
                status_desc: Some(desc),
                messages: Vec::new(),
                pagination_cursor: None,
            },
        }
    }

    fn query_inner(&self, req: &StoreQueryRequest) -> StoreQueryResult {
        if let (Some(start), Some(end)) = (req.time_start, req.time_end) {
            if start > end {
                return Err((400, "time_start must be <= time_end".into()));
            }
        }
        let limit = req
            .pagination_limit
            .unwrap_or(DEFAULT_STORE_PAGE_LIMIT)
            .clamp(1, u64::from(MAX_HISTORY_PAGE_SIZE)) as usize;

        let cursor_anchor: Option<(i64, Vec<u8>)> = match &req.pagination_cursor {
            Some(c) if !c.is_empty() => {
                if c.len() != 32 {
                    return Err((400, "pagination_cursor must be 32 bytes".into()));
                }
                let found: Option<i64> = self
                    .conn
                    .query_row(
                        "SELECT timestamp_ns FROM waku_messages WHERE message_hash = ?1",
                        params![c.as_slice()],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| (500, format!("cursor lookup failed: {e}")))?;
                match found {
                    Some(ts) => Some((ts, c.clone())),
                    None => return Ok((Vec::new(), None)),
                }
            }
            _ => None,
        };

        let mut sql = String::from(
            "SELECT message_hash, pubsub_topic, raw_message FROM waku_messages WHERE 1=1",
        );
        let mut binds: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(ps) = &req.pubsub_topic {
            sql.push_str(" AND pubsub_topic = ?");
            binds.push(rusqlite::types::Value::Text(ps.clone()));
        }
        if !req.content_topics.is_empty() {
            if req.content_topics.len() > 64 {
                return Err((400, "too many content_topics (max 64)".into()));
            }
            sql.push_str(" AND content_topic IN (");
            for (i, ct) in req.content_topics.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push('?');
                binds.push(rusqlite::types::Value::Text(ct.clone()));
            }
            sql.push(')');
        }
        if let Some(start) = req.time_start {
            sql.push_str(" AND timestamp_ns >= ?");
            binds.push(rusqlite::types::Value::Integer(start));
        }
        if let Some(end) = req.time_end {
            sql.push_str(" AND timestamp_ns <= ?");
            binds.push(rusqlite::types::Value::Integer(end));
        }
        if !req.message_hashes.is_empty() {
            if req.message_hashes.len() > 100 {
                return Err((400, "too many message_hashes (max 100)".into()));
            }
            sql.push_str(" AND message_hash IN (");
            for (i, mh) in req.message_hashes.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push('?');
                binds.push(rusqlite::types::Value::Blob(mh.clone()));
            }
            sql.push(')');
        }
        if let Some((cts, chash)) = cursor_anchor {
            if req.pagination_forward {
                sql.push_str(" AND (timestamp_ns > ? OR (timestamp_ns = ? AND message_hash > ?))");
            } else {
                sql.push_str(" AND (timestamp_ns < ? OR (timestamp_ns = ? AND message_hash < ?))");
            }
            binds.push(rusqlite::types::Value::Integer(cts));
            binds.push(rusqlite::types::Value::Integer(cts));
            binds.push(rusqlite::types::Value::Blob(chash));
        }
        if req.pagination_forward {
            sql.push_str(" ORDER BY timestamp_ns ASC, message_hash ASC LIMIT ?");
        } else {
            sql.push_str(" ORDER BY timestamp_ns DESC, message_hash DESC LIMIT ?");
        }
        binds.push(rusqlite::types::Value::Integer((limit + 1) as i64));

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| (500, format!("store prepare: {e}")))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(binds), |r| {
                let hash: Vec<u8> = r.get(0)?;
                let pubsub: String = r.get(1)?;
                let raw: Vec<u8> = r.get(2)?;
                Ok((hash, pubsub, raw))
            })
            .map_err(|e| (500, format!("store query: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            let (hash, pubsub, raw) = row.map_err(|e| (500, format!("store row: {e}")))?;
            let message = if req.include_data {
                WakuMessage::decode(raw.as_slice()).ok()
            } else {
                None
            };
            out.push(WakuMessageKeyValue {
                message_hash: hash,
                message,
                pubsub_topic: Some(pubsub),
            });
        }
        let has_more = out.len() > limit;
        out.truncate(limit);
        let next_cursor = if has_more {
            out.last().map(|kv| kv.message_hash.clone())
        } else {
            None
        };
        Ok((out, next_cursor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waku_common::waku_message_hash;

    fn make_msg(
        topic: &str,
        body: &[u8],
        ts: i64,
        ephemeral: bool,
    ) -> ([u8; 32], WakuMessage, Vec<u8>) {
        let msg = WakuMessage {
            payload: body.to_vec(),
            content_topic: topic.into(),
            version: Some(0),
            timestamp: Some(ts),
            meta: None,
            proof: None,
            ephemeral: if ephemeral { Some(true) } else { None },
        };
        let raw = msg.encode_to_vec();
        let hash = waku_message_hash("/waku/2/rs/66/0", &msg.payload, &msg.content_topic, &[], ts);
        (hash, msg, raw)
    }

    #[test]
    fn insert_paginate_and_prune() {
        let limits = StoreDbLimits {
            retention_seconds: 100,
            retention_capacity: 50,
            max_clock_skew_seconds: 20,
        };
        let db = StoreDb::open_in_memory(limits).unwrap();
        let base = 1_700_000_000_000_000_000i64;

        // Ephemeral and skewed messages are silently skipped.
        let (h_eph, m_eph, r_eph) = make_msg("/a/1/x/proto", b"eph", base, true);
        assert!(!db
            .insert("/waku/2/rs/66/0", &h_eph, &m_eph, &r_eph, base)
            .unwrap());
        let (h_skew, m_skew, r_skew) =
            make_msg("/a/1/x/proto", b"skew", base + 25_000_000_000, false);
        assert!(!db
            .insert("/waku/2/rs/66/0", &h_skew, &m_skew, &r_skew, base)
            .unwrap());

        for i in 0..5i64 {
            let ts = base + i * 1_000_000_000;
            let (h, m, r) = make_msg("/a/1/x/proto", format!("m{i}").as_bytes(), ts, false);
            assert!(db.insert("/waku/2/rs/66/0", &h, &m, &r, ts).unwrap());
        }
        assert_eq!(db.count().unwrap(), 5);

        // Forward pagination, 2 per page.
        let mut cursor = None;
        let mut seen = Vec::new();
        loop {
            let resp = db.query(&StoreQueryRequest {
                request_id: "r1".into(),
                include_data: true,
                pubsub_topic: Some("/waku/2/rs/66/0".into()),
                content_topics: vec!["/a/1/x/proto".into()],
                time_start: Some(base),
                time_end: Some(base + 10_000_000_000),
                message_hashes: vec![],
                pagination_cursor: cursor.clone(),
                pagination_forward: true,
                pagination_limit: Some(2),
            });
            assert_eq!(resp.status_code, Some(200));
            for kv in &resp.messages {
                seen.push(String::from_utf8(kv.message.as_ref().unwrap().payload.clone()).unwrap());
            }
            if resp.pagination_cursor.is_none() {
                break;
            }
            cursor = resp.pagination_cursor;
        }
        assert_eq!(seen, vec!["m0", "m1", "m2", "m3", "m4"]);

        // Age prune removes old records.
        let pruned = db.prune(base + 103_000_000_000).unwrap();
        assert_eq!(pruned, 3);
        assert_eq!(db.count().unwrap(), 2);
    }
}
