//! `impl AgentApi for Node` and the inherent administration methods.

use async_trait::async_trait;
use rusqlite::{params, OptionalExtension, Row};
use tokio::sync::broadcast;

use crate::address::Address;
use crate::api::{
    AcknowledgeResponse, AddContactRequest, AgentApi, ApiError, ApiResult, ChangeHint, ContactInfo,
    ConversationEntry, ConversationPage, CreateTriggerRequest, DeleteTriggerResponse, Direction,
    EventPage, IdentityInfo, InboxRecord, MessageStatus, NetworkStatus, OutboxPage, OutboxRecord,
    PageRequest, QueueHealth, ReadInboxRequest, ReadInboxResponse, SendMessageRequest,
    SendMessageResponse, TriggerInfo, Trust,
};
use crate::contact::VerifiedContact;
use crate::cursor::{decode_conv, decode_seq, encode_conv, encode_seq, CursorKind};
use crate::envelope::Envelope;
use crate::node::{state_from_db, trust_from_db, trust_to_db, Node};
use crate::store::{kv_get, StoreError};
use crate::triggers::clamp_limit;

const MAX_ALIAS_LEN: usize = 64;

const STATUS_COLS: &str = "message_id, recipient, type, conversation_id, state, attempts, created_at, expires_at, last_attempt_at, next_attempt_at, sent_at, delivered_at, last_error";

fn status_from_row(r: &Row<'_>) -> rusqlite::Result<MessageStatus> {
    let state: String = r.get(4)?;
    Ok(MessageStatus {
        message_id: r.get(0)?,
        recipient: r.get(1)?,
        message_type: r.get(2)?,
        conversation_id: r.get(3)?,
        state: state_from_db(&state),
        attempts: r.get(5)?,
        created_at: r.get(6)?,
        expires_at: r.get(7)?,
        last_attempt_at: r.get(8)?,
        next_attempt_at: r.get(9)?,
        sent_at: r.get(10)?,
        delivered_at: r.get(11)?,
        last_error: r.get(12)?,
    })
}

const INBOX_COLS: &str = "seq, message_id, sender, sender_trust, type, conversation_id, correlation_id, created_at, expires_at, received_at, body, acknowledged_at, quarantined";

fn inbox_from_row(r: &Row<'_>) -> rusqlite::Result<InboxRecord> {
    let trust: String = r.get(3)?;
    Ok(InboxRecord {
        cursor: encode_seq(CursorKind::Inbox, r.get(0)?),
        message_id: r.get(1)?,
        sender: r.get(2)?,
        sender_trust: trust_from_db(&trust),
        message_type: r.get(4)?,
        conversation_id: r.get(5)?,
        correlation_id: r.get(6)?,
        created_at: r.get(7)?,
        expires_at: r.get(8)?,
        received_at: r.get(9)?,
        body: r.get(10)?,
        acknowledged: r.get::<_, Option<i64>>(11)?.is_some(),
        quarantined: r.get::<_, i64>(12)? != 0,
    })
}

fn count(c: &rusqlite::Connection, sql: &str, p: impl rusqlite::Params) -> Result<u64, StoreError> {
    let n: i64 = c.query_row(sql, p, |r| r.get(0))?;
    Ok(u64::try_from(n).unwrap_or(0))
}

impl Node {
    /// Public identity information (same as `get_identity`).
    pub fn identity_info(&self) -> IdentityInfo {
        IdentityInfo {
            agent_id: self.own_str.clone(),
            contact_record: self.identity.contact_record().to_document(),
            inbox_topic: self.topic.to_string(),
            created_at: self.identity.created_at(),
            kem_expires_at: self.identity.kem_expires_at(),
        }
    }

    fn contact_info(row: &crate::node::ContactRow, updated: bool) -> ContactInfo {
        ContactInfo {
            address: row.contact.address.to_string(),
            alias: row.alias.clone(),
            trust: row.trust,
            inbox_topic: row.contact.inbox_topic().to_string(),
            added_at: row.added_at,
            kem_expires_at: row.contact.kem_expires_at,
            updated,
        }
    }

    /// Change the trust decision of an existing contact.
    pub fn set_contact_trust(&self, address: &str, trust: Trust) -> ApiResult<ContactInfo> {
        if trust == Trust::Unknown {
            return Err(ApiError::invalid(
                "trust must be trusted, untrusted or blocked",
            ));
        }
        let addr: Address = address
            .parse()
            .map_err(|_| ApiError::invalid("invalid address"))?;
        let now = self.now();
        self.store
            .tx(|tx| {
                let n = tx.execute(
                    "UPDATE contacts SET trust = ?2, updated_at = ?3 WHERE address = ?1",
                    params![addr.to_string(), trust_to_db(trust), now],
                )?;
                if n == 0 {
                    return Err(ApiError::not_found("no such contact").into());
                }
                let row = self
                    .load_contact(tx, &addr)?
                    .ok_or(StoreError::Corrupt("contact vanished"))?;
                Ok(Self::contact_info(&row, false))
            })
            .map_err(|e| e.to_api())
    }

    /// Delete a contact. Returns whether it existed. Queued outbox rows keep their
    /// sealed frames and are still sent.
    pub fn remove_contact(&self, address: &str) -> ApiResult<bool> {
        let addr: Address = address
            .parse()
            .map_err(|_| ApiError::invalid("invalid address"))?;
        self.store
            .tx(|tx| {
                Ok(tx.execute(
                    "DELETE FROM contacts WHERE address = ?1",
                    [addr.to_string()],
                )? > 0)
            })
            .map_err(|e| e.to_api())
    }

    /// Quarantined messages (oldest first, at most 1000).
    pub fn list_quarantined(&self) -> ApiResult<Vec<InboxRecord>> {
        self.store
            .read(|c| {
                let mut st = c.prepare(&format!(
                    "SELECT {INBOX_COLS} FROM inbox WHERE quarantined = 1 ORDER BY seq LIMIT 1000"
                ))?;
                let rows = st.query_map([], inbox_from_row)?;
                let mut v = Vec::new();
                for r in rows {
                    v.push(r?);
                }
                Ok(v)
            })
            .map_err(|e| e.to_api())
    }

    /// Move quarantined message(s) with `message_id` into the normal inbox. The
    /// sender must be a Trusted contact by now. The `message.received` event is
    /// emitted at release, an ack is queued, and triggers are *not* matched
    /// retroactively (use `since_cursor`). Returns the number released.
    pub fn release_quarantined(&self, message_id: &str) -> ApiResult<usize> {
        let now = self.now();
        let released = self
            .store
            .tx(|tx| {
                type Q = (i64, String, String, Option<String>, Option<String>, String, i64, i64);
                let mut st = tx.prepare(
                    "SELECT seq, sender, type, conversation_id, correlation_id, body, created_at, expires_at
                     FROM inbox WHERE message_id = ?1 AND quarantined = 1 ORDER BY seq",
                )?;
                let rows: Vec<Q> = st
                    .query_map([message_id], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
                    })?
                    .collect::<Result<_, _>>()?;
                drop(st);
                if rows.is_empty() {
                    return Err(ApiError::not_found("no such quarantined message").into());
                }
                let mut n = 0usize;
                let mut convs = Vec::new();
                for (seq, sender, ty, conv, corr, body, created, expires) in rows {
                    let Ok(addr) = sender.parse::<Address>() else { continue };
                    let trusted = self
                        .load_contact(tx, &addr)?
                        .is_some_and(|r| r.trust == Trust::Trusted);
                    if !trusted {
                        continue;
                    }
                    let live = count(tx, "SELECT COUNT(*) FROM inbox WHERE quarantined = 0", [])?;
                    if live >= self.config.storage.max_inbox_records {
                        return Err(ApiError::unavailable("inbox is full").into());
                    }
                    tx.execute(
                        "UPDATE inbox SET quarantined = 0, sender_trust = 'trusted' WHERE seq = ?1",
                        [seq],
                    )?;
                    self.insert_event(tx, "message.received", message_id, None, None, now)?;
                    let orig = Envelope {
                        v: 1,
                        message_id: message_id.to_owned(),
                        sender: addr,
                        recipient: self.own,
                        message_type: ty,
                        conversation_id: conv.clone(),
                        correlation_id: corr,
                        created_at: created,
                        expires_at: expires,
                        body,
                    };
                    if self.queue_ack(tx, &orig, now)? {
                        tx.execute(
                            "UPDATE seen SET last_reack_at = ?3 WHERE sender = ?1 AND message_id = ?2",
                            params![sender, message_id, now],
                        )?;
                    }
                    convs.extend(conv);
                    n += 1;
                }
                if n == 0 {
                    return Err(ApiError::policy("the sender is not a trusted contact; trust them first").into());
                }
                Ok((n, convs))
            })
            .map_err(|e| e.to_api())?;
        self.metrics.add("quarantine.released", released.0 as u64);
        self.hint(ChangeHint::Inbox);
        self.hint(ChangeHint::Events);
        for c in released.1 {
            self.hint(ChangeHint::Conversation { conversation_id: c });
        }
        self.send_nudge.notify_one();
        Ok(released.0)
    }

    fn queue_health(&self, c: &rusqlite::Connection) -> Result<QueueHealth, StoreError> {
        let now = self.now();
        Ok(QueueHealth {
            outbox_queued: count(
                c,
                "SELECT COUNT(*) FROM outbox WHERE is_ack=0 AND state='queued'",
                [],
            )?,
            outbox_sent_unacked: count(
                c,
                "SELECT COUNT(*) FROM outbox WHERE is_ack=0 AND state='sent'",
                [],
            )?,
            inbox_unread: count(
                c,
                "SELECT COUNT(*) FROM inbox WHERE quarantined=0 AND acknowledged_at IS NULL",
                [],
            )?,
            inbox_quarantined: count(c, "SELECT COUNT(*) FROM inbox WHERE quarantined=1", [])?,
            events_unacked: count(c, "SELECT COUNT(*) FROM events WHERE acked=0", [])?,
            active_triggers: count(
                c,
                "SELECT COUNT(*) FROM triggers WHERE state='active' AND expires_at > ?1",
                [now],
            )?,
        })
    }
}

#[async_trait]
impl AgentApi for Node {
    async fn get_identity(&self) -> ApiResult<IdentityInfo> {
        Ok(self.identity_info())
    }

    async fn send_message(&self, req: SendMessageRequest) -> ApiResult<SendMessageResponse> {
        self.send_message_impl(req)
    }

    async fn read_inbox(&self, req: ReadInboxRequest) -> ApiResult<ReadInboxResponse> {
        let after = match &req.cursor {
            Some(c) => decode_seq(CursorKind::Inbox, c)?,
            None => 0,
        };
        let limit = clamp_limit(req.limit);
        self.store
            .read(|c| {
                let mut st = c.prepare(&format!(
                    "SELECT {INBOX_COLS} FROM inbox
                     WHERE seq > ?1 AND (?2 = 1 OR quarantined = 0)
                       AND (?3 = 0 OR acknowledged_at IS NULL)
                       AND (?4 IS NULL OR conversation_id = ?4)
                     ORDER BY seq LIMIT ?5"
                ))?;
                let rows = st.query_map(
                    params![
                        after,
                        i64::from(req.include_quarantined),
                        i64::from(req.unread_only),
                        req.conversation_id,
                        i64::try_from(limit + 1).unwrap_or(i64::MAX)
                    ],
                    inbox_from_row,
                )?;
                let mut records = Vec::new();
                for r in rows {
                    records.push(r?);
                }
                let has_more = records.len() > limit;
                records.truncate(limit);
                let next_cursor = Some(match records.last() {
                    Some(r) => r.cursor.clone(),
                    None => req
                        .cursor
                        .clone()
                        .unwrap_or_else(|| encode_seq(CursorKind::Inbox, 0)),
                });
                Ok(ReadInboxResponse {
                    records,
                    next_cursor,
                    has_more,
                })
            })
            .map_err(|e| e.to_api())
    }

    /// Acknowledges every non-quarantined inbox row with this `message_id`
    /// (ids are sender-chosen, so two senders may use the same id; all are
    /// acknowledged together).
    async fn acknowledge_message(&self, message_id: String) -> ApiResult<AcknowledgeResponse> {
        let now = self.now();
        self.store
            .tx(|tx| {
                let n = tx.execute(
                    "UPDATE inbox SET acknowledged_at = ?2
                     WHERE message_id = ?1 AND quarantined = 0 AND acknowledged_at IS NULL",
                    params![message_id, now],
                )?;
                if n > 0 {
                    return Ok(true);
                }
                let exists = count(
                    tx,
                    "SELECT COUNT(*) FROM inbox WHERE message_id = ?1 AND quarantined = 0",
                    [&message_id],
                )? > 0;
                if exists {
                    Ok(false)
                } else {
                    Err(ApiError::not_found("no such message").into())
                }
            })
            .map(|newly| AcknowledgeResponse {
                message_id: message_id.clone(),
                newly_acknowledged: newly,
            })
            .map_err(|e| e.to_api())
    }

    async fn get_message_status(&self, message_id: String) -> ApiResult<MessageStatus> {
        self.store
            .read(|c| {
                Ok(c.query_row(
                    &format!(
                        "SELECT {STATUS_COLS} FROM outbox WHERE message_id = ?1 AND is_ack = 0"
                    ),
                    [&message_id],
                    status_from_row,
                )
                .optional()?)
            })
            .map_err(|e| e.to_api())?
            .ok_or_else(|| ApiError::not_found("no such outbound message"))
    }

    /// A newer record for a known address replaces the stored one; an older one
    /// is refused. If `trust` is absent, a new contact is `trusted` and an
    /// existing contact keeps its current trust.
    async fn add_contact(&self, req: AddContactRequest) -> ApiResult<ContactInfo> {
        let now = self.now();
        let vc = VerifiedContact::parse_and_verify(&req.contact_record, now)
            .map_err(|e| ApiError::invalid(format!("invalid contact record: {e}")))?;
        if let Some(exp) = &req.expected_address {
            if *exp != vc.address.to_string() {
                return Err(ApiError::invalid(
                    "contact record is not for the expected address",
                ));
            }
        }
        if vc.address == self.own {
            return Err(ApiError::invalid(
                "cannot add this agent's own address as a contact",
            ));
        }
        if req.trust == Some(Trust::Unknown) {
            return Err(ApiError::invalid(
                "trust must be trusted, untrusted or blocked",
            ));
        }
        if let Some(a) = &req.alias {
            if a.is_empty() || a.len() > MAX_ALIAS_LEN || a.chars().any(char::is_control) {
                return Err(ApiError::invalid(
                    "alias must be 1..=64 characters without control characters",
                ));
            }
        }
        let addr = vc.address;
        let res = self.store.tx(|tx| {
            let old = self.load_contact(tx, &addr)?;
            let (updated, trust, alias, added_at) = match &old {
                Some(o) => {
                    if vc.created_at < o.contact.created_at {
                        return Err(ApiError::invalid("an older contact record cannot replace the stored one").into());
                    }
                    (
                        o.contact.document() != vc.document(),
                        req.trust.unwrap_or(o.trust),
                        req.alias.clone().or_else(|| o.alias.clone()),
                        o.added_at,
                    )
                }
                None => (false, req.trust.unwrap_or(Trust::Trusted), req.alias.clone(), now),
            };
            tx.execute(
                "INSERT INTO contacts (address, document, alias, trust, added_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(address) DO UPDATE SET document = excluded.document,
                   alias = excluded.alias, trust = excluded.trust, updated_at = excluded.updated_at",
                params![addr.to_string(), vc.document(), alias, trust_to_db(trust), added_at],
            )?;
            let row = crate::node::ContactRow { contact: vc.clone(), trust, alias, added_at };
            Ok(Self::contact_info(&row, updated))
        });
        res.map_err(|e| e.to_api())
    }

    async fn list_contacts(&self) -> ApiResult<Vec<ContactInfo>> {
        self.store
            .read(|c| {
                let mut st =
                    c.prepare("SELECT address FROM contacts ORDER BY added_at, address")?;
                let addrs: Vec<String> =
                    st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
                let mut out = Vec::new();
                for a in addrs {
                    let addr: Address = a
                        .parse()
                        .map_err(|_| StoreError::Corrupt("stored address"))?;
                    if let Some(row) = self.load_contact(c, &addr)? {
                        out.push(Self::contact_info(&row, false));
                    }
                }
                Ok(out)
            })
            .map_err(|e| e.to_api())
    }

    async fn network_status(&self, verbose: bool) -> ApiResult<NetworkStatus> {
        let ts = self.transport.status().await;
        let (queue, watermark) = self
            .store
            .read(|c| {
                Ok((
                    self.queue_health(c)?,
                    kv_get(c, crate::node::KV_HISTORY_WATERMARK)?
                        .and_then(|s| s.parse::<i64>().ok()),
                ))
            })
            .map_err(|e| e.to_api())?;
        let m = self.metrics.snapshot();
        let mut detail = ts.detail.clone();
        let refused = m.get("inbox.full_refused");
        if refused > 0 {
            detail.push_str(&format!(
                "; inbox saturated: {refused} inbound messages refused (not acked)"
            ));
        }
        if self.history_pending() {
            detail.push_str("; history recovery pending");
        }
        let live = self.last_live_poll();
        Ok(NetworkStatus {
            mode: self.config.network_mode.clone(),
            ready: ts.ready,
            connected_peers: u32::try_from(ts.peers.iter().filter(|p| p.connected).count())
                .unwrap_or(u32::MAX),
            isolation_violation: ts.isolation_violation,
            queue,
            last_live_poll_at: live,
            last_history_sync_at: watermark,
            detail,
            peers: verbose.then(|| ts.peers.iter().map(|p| p.peer_id.clone()).collect()),
        })
    }

    async fn create_trigger(&self, req: CreateTriggerRequest) -> ApiResult<TriggerInfo> {
        self.create_trigger_impl(req)
    }

    async fn list_triggers(&self, include_inactive: bool) -> ApiResult<Vec<TriggerInfo>> {
        self.list_triggers_impl(include_inactive)
    }

    async fn delete_trigger(&self, trigger_id: String) -> ApiResult<DeleteTriggerResponse> {
        self.delete_trigger_impl(trigger_id)
    }

    async fn read_outbox(&self, req: PageRequest) -> ApiResult<OutboxPage> {
        let after = match &req.cursor {
            Some(c) => decode_seq(CursorKind::Outbox, c)?,
            None => 0,
        };
        let limit = clamp_limit(req.limit);
        self.store
            .read(|c| {
                let mut st = c.prepare(&format!(
                    "SELECT {STATUS_COLS}, body, seq FROM outbox WHERE is_ack = 0 AND seq > ?1 ORDER BY seq LIMIT ?2"
                ))?;
                let rows = st.query_map(params![after, i64::try_from(limit + 1).unwrap_or(i64::MAX)], |r| {
                    Ok(OutboxRecord {
                        status: status_from_row(r)?,
                        body: r.get(13)?,
                        cursor: encode_seq(CursorKind::Outbox, r.get(14)?),
                    })
                })?;
                let mut records = Vec::new();
                for r in rows {
                    records.push(r?);
                }
                let has_more = records.len() > limit;
                records.truncate(limit);
                let next_cursor = Some(match records.last() {
                    Some(r) => r.cursor.clone(),
                    None => req.cursor.clone().unwrap_or_else(|| encode_seq(CursorKind::Outbox, 0)),
                });
                Ok(OutboxPage { records, next_cursor, has_more })
            })
            .map_err(|e| e.to_api())
    }

    /// Entries are ordered by local time: `received_at` for inbound and
    /// `created_at` for outbound (both local clock), then direction, then
    /// sequence. A new entry therefore always sorts after any cursor handed out
    /// earlier (given a monotonic clock), so paging never skips late arrivals.
    /// Quarantined messages and acks are excluded. An unknown conversation id
    /// yields an empty page.
    async fn read_conversation(
        &self,
        conversation_id: String,
        req: PageRequest,
    ) -> ApiResult<ConversationPage> {
        if conversation_id.is_empty() || conversation_id.len() > crate::envelope::MAX_ID_LEN {
            return Err(ApiError::invalid("invalid conversation_id"));
        }
        let after = match &req.cursor {
            Some(c) => decode_conv(c)?,
            None => (0, 0, 0),
        };
        let limit = clamp_limit(req.limit);
        self.store
            .read(|c| {
                let mut st = c.prepare(
                    "SELECT ts, d, seq, peer, type, corr, created, body, state, message_id FROM (
                       SELECT received_at AS ts, 0 AS d, seq, sender AS peer, type, correlation_id AS corr,
                              created_at AS created, body, NULL AS state, message_id
                         FROM inbox WHERE conversation_id = ?1 AND quarantined = 0
                       UNION ALL
                       SELECT created_at, 1, seq, recipient, type, correlation_id,
                              created_at, body, state, message_id
                         FROM outbox WHERE conversation_id = ?1 AND is_ack = 0
                     ) WHERE (ts, d, seq) > (?2, ?3, ?4) ORDER BY ts, d, seq LIMIT ?5",
                )?;
                let rows = st.query_map(
                    params![conversation_id, after.0, after.1, after.2, i64::try_from(limit + 1).unwrap_or(i64::MAX)],
                    |r| {
                        let d: i64 = r.get(1)?;
                        let state: Option<String> = r.get(8)?;
                        Ok(ConversationEntry {
                            cursor: encode_conv((r.get(0)?, d, r.get(2)?)),
                            direction: if d == 0 { Direction::Inbound } else { Direction::Outbound },
                            message_id: r.get(9)?,
                            peer: r.get(3)?,
                            message_type: r.get(4)?,
                            correlation_id: r.get(5)?,
                            created_at: r.get(6)?,
                            body: r.get(7)?,
                            state: state.as_deref().map(state_from_db),
                        })
                    },
                )?;
                let mut entries = Vec::new();
                for r in rows {
                    entries.push(r?);
                }
                let has_more = entries.len() > limit;
                entries.truncate(limit);
                let next_cursor = Some(match entries.last() {
                    Some(e) => e.cursor.clone(),
                    None => req.cursor.clone().unwrap_or_else(|| encode_conv((0, 0, 0))),
                });
                Ok(ConversationPage { conversation_id: conversation_id.clone(), entries, next_cursor, has_more })
            })
            .map_err(|e| e.to_api())
    }

    async fn read_events(&self, req: PageRequest) -> ApiResult<EventPage> {
        self.read_events_impl(req)
    }

    async fn ack_events(&self, cursor: String) -> ApiResult<()> {
        self.ack_events_impl(cursor)
    }

    fn changes(&self) -> broadcast::Receiver<ChangeHint> {
        self.changes.subscribe()
    }
}
