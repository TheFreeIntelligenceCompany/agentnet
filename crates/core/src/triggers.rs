//! Triggers (durable predicates over authenticated inbound messages) and the
//! host-facing event log.

use rusqlite::{params, Row, Transaction};

use crate::address::Address;
use crate::api::{
    ApiError, ApiResult, ChangeHint, CreateTriggerRequest, DeleteTriggerResponse, EventPage,
    EventRecord, EventType, PageRequest, TriggerInfo, TriggerState, Trust,
};
use crate::cursor::{decode_seq, encode_seq, CursorKind};
use crate::envelope::{new_message_id, Envelope};
use crate::node::{Node, KV_EVENTS_ACK};
use crate::store::{kv_get, kv_set, StoreError};

pub(crate) const DEFAULT_PAGE: u32 = 50;
pub(crate) const MAX_PAGE: u32 = 200;
const MAX_SESSION_LEN: usize = 128;

/// The fields of an authenticated, persisted message that triggers match on.
pub(crate) struct Candidate<'a> {
    pub message_id: &'a str,
    pub sender: &'a str,
    pub message_type: &'a str,
    pub conversation_id: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
}

#[derive(Default)]
pub(crate) struct Fired {
    pub events: u32,
    pub consumed: u32,
}

pub(crate) fn new_uuid() -> Result<String, StoreError> {
    new_message_id().map_err(|_| StoreError::Corrupt("random number generator failed"))
}

pub(crate) fn clamp_limit(l: Option<u32>) -> usize {
    l.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize
}

fn trigger_from_row(r: &Row<'_>, now: i64) -> rusqlite::Result<TriggerInfo> {
    let state: String = r.get(7)?;
    let expires_at: i64 = r.get(10)?;
    let mut st = match state.as_str() {
        "consumed" => TriggerState::Consumed,
        "expired" => TriggerState::Expired,
        "deleted" => TriggerState::Deleted,
        _ => TriggerState::Active,
    };
    if st == TriggerState::Active && expires_at <= now {
        st = TriggerState::Expired;
    }
    Ok(TriggerInfo {
        trigger_id: r.get(0)?,
        sender: r.get(1)?,
        message_type: r.get(2)?,
        conversation_id: r.get(3)?,
        correlation_id: r.get(4)?,
        target_session: r.get(5)?,
        once: r.get::<_, i64>(6)? != 0,
        state: st,
        match_count: u64::try_from(r.get::<_, i64>(8)?).unwrap_or(0),
        created_at: r.get(9)?,
        expires_at,
    })
}

const TRIGGER_COLS: &str = "id, sender, type, conversation_id, correlation_id, target_session, once, state, match_count, created_at, expires_at";

impl Node {
    pub(crate) fn insert_event(
        &self,
        tx: &Transaction<'_>,
        kind: &str,
        message_id: &str,
        trigger_id: Option<&str>,
        target_session: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError> {
        tx.execute(
            "INSERT INTO events (event_id, type, message_id, trigger_id, target_session, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                new_uuid()?,
                kind,
                message_id,
                trigger_id,
                target_session,
                now
            ],
        )?;
        Ok(())
    }

    /// Match `cand` against active triggers (all, or only `only`). Matching is
    /// inside the caller's transaction. A once-trigger is consumed by an
    /// `UPDATE ... WHERE state='active'` whose row count decides who wins, so two
    /// messages can never both match one. Over the per-minute budget the match
    /// is not recorded and the trigger is not consumed.
    pub(crate) fn fire_triggers(
        &self,
        tx: &Transaction<'_>,
        cand: &Candidate<'_>,
        now: i64,
        only: Option<&str>,
    ) -> Result<Fired, StoreError> {
        let mut st = tx.prepare(
            "SELECT id, target_session, once FROM triggers
             WHERE state = 'active' AND expires_at > ?1
               AND (sender IS NULL OR sender = ?2)
               AND (type IS NULL OR type = ?3)
               AND (conversation_id IS NULL OR conversation_id = ?4)
               AND (correlation_id IS NULL OR correlation_id = ?5)
               AND (?6 IS NULL OR id = ?6)
             ORDER BY created_at, id",
        )?;
        let hits: Vec<(String, String, bool)> = st
            .query_map(
                params![
                    now,
                    cand.sender,
                    cand.message_type,
                    cand.conversation_id,
                    cand.correlation_id,
                    only
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0)),
            )?
            .collect::<Result<_, _>>()?;
        drop(st);
        let mut fired = Fired::default();
        let budget = i64::from(self.config.triggers.max_matches_per_minute);
        for (id, session, once) in hits {
            let used: i64 = tx.query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'trigger.matched' AND timestamp > ?1",
                [now.saturating_sub(60_000)],
                |r| r.get(0),
            )?;
            if used >= budget {
                self.metrics.inc("trigger.budget_exceeded");
                continue;
            }
            let n = tx.execute(
                "UPDATE triggers SET match_count = match_count + 1,
                        state = CASE WHEN once = 1 THEN 'consumed' ELSE state END
                 WHERE id = ?1 AND state = 'active'",
                [&id],
            )?;
            if n == 1 {
                self.insert_event(
                    tx,
                    "trigger.matched",
                    cand.message_id,
                    Some(&id),
                    Some(&session),
                    now,
                )?;
                fired.events += 1;
                if once {
                    fired.consumed += 1;
                }
                self.metrics.inc("trigger.matched");
            }
        }
        Ok(fired)
    }

    pub(crate) fn create_trigger_impl(&self, req: CreateTriggerRequest) -> ApiResult<TriggerInfo> {
        let tcfg = &self.config.triggers;
        if !self.config.policy.auto_trigger {
            return Err(ApiError::policy(
                "triggers are disabled by host policy (policy.auto_trigger = false)",
            ));
        }
        let session = req.target_session.as_str();
        if session.is_empty()
            || session.len() > MAX_SESSION_LEN
            || !session.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(ApiError::invalid(
                "target_session must be 1..=128 printable ASCII characters",
            ));
        }
        if !tcfg.allowed_sessions.iter().any(|s| s == session) {
            return Err(ApiError::policy(
                "target_session is not allowlisted by host policy",
            ));
        }
        let max_life_s = tcfg.max_lifetime_hours.saturating_mul(3600);
        let life_s = match req.expires_in_seconds {
            Some(0) => {
                return Err(ApiError::invalid(
                    "expires_in_seconds must be greater than zero",
                ))
            }
            Some(s) => s,
            None => tcfg.default_lifetime_s,
        };
        if life_s > max_life_s {
            return Err(ApiError::policy(format!(
                "trigger lifetime exceeds the host maximum of {} hours",
                tcfg.max_lifetime_hours
            )));
        }
        // Syntax checks reuse the envelope field rules.
        let probe = Envelope {
            v: 1,
            message_id: "00000000-0000-4000-8000-000000000000".into(),
            sender: self.own,
            recipient: self.own,
            suite: crate::crypto::envelope::SUITE_ID,
            recipient_key_epoch: 0,
            message_type: req.message_type.clone().unwrap_or_else(|| "message".into()),
            conversation_id: req.conversation_id.clone(),
            correlation_id: req.correlation_id.clone(),
            created_at: 0,
            expires_at: 1,
            body: String::new(),
        };
        probe
            .validate()
            .map_err(|f| ApiError::invalid(format!("invalid filter field: {f}")))?;
        let sender: Option<Address> = match &req.sender {
            Some(s) => Some(
                s.parse()
                    .map_err(|_| ApiError::invalid("sender is not a valid address"))?,
            ),
            None => None,
        };
        let since: Option<i64> = match &req.since_cursor {
            Some(c) => Some(decode_seq(CursorKind::Inbox, c)?),
            None => None,
        };
        let once = req.once.unwrap_or(true);
        let now = self.now();
        let expires_at =
            now.saturating_add(i64::try_from(life_s.saturating_mul(1000)).unwrap_or(i64::MAX));

        let (info, events, consumed) = self
            .store
            .tx(|tx| {
                if let Some(a) = &sender {
                    let trusted = self
                        .load_contact(tx, a)?
                        .is_some_and(|r| r.trust == Trust::Trusted);
                    if !trusted {
                        return Err(
                            ApiError::policy("sender filter must be a trusted contact").into()
                        );
                    }
                }
                let active: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM triggers WHERE state='active' AND expires_at > ?1",
                    [now],
                    |r| r.get(0),
                )?;
                if u64::try_from(active).unwrap_or(u64::MAX) >= u64::from(tcfg.max_active) {
                    return Err(ApiError::policy("too many active triggers").into());
                }
                let id = new_uuid()?;
                tx.execute(
                    "INSERT INTO triggers (id, sender, type, conversation_id, correlation_id,
                        target_session, once, state, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9)",
                    params![
                        id,
                        sender.map(|a| a.to_string()),
                        req.message_type,
                        req.conversation_id,
                        req.correlation_id,
                        session,
                        i64::from(once),
                        now,
                        expires_at,
                    ],
                )?;
                let mut events = 0u32;
                let mut consumed = 0u32;
                if let Some(after) = since {
                    type Msg = (String, String, String, Option<String>, Option<String>);
                    let mut st = tx.prepare(
                        "SELECT message_id, sender, type, conversation_id, correlation_id FROM inbox
                         WHERE seq > ?1 AND quarantined = 0 AND sender_trust = 'trusted'
                         ORDER BY seq",
                    )?;
                    let msgs: Vec<Msg> = st
                        .query_map([after], |r| {
                            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                        })?
                        .collect::<Result<_, _>>()?;
                    drop(st);
                    for (mid, snd, ty, conv, corr) in msgs {
                        let cand = Candidate {
                            message_id: &mid,
                            sender: &snd,
                            message_type: &ty,
                            conversation_id: conv.as_deref(),
                            correlation_id: corr.as_deref(),
                        };
                        let f = self.fire_triggers(tx, &cand, now, Some(&id))?;
                        events += f.events;
                        consumed += f.consumed;
                        if consumed > 0 {
                            break;
                        }
                    }
                }
                let info = tx.query_row(
                    &format!("SELECT {TRIGGER_COLS} FROM triggers WHERE id = ?1"),
                    [&id],
                    |r| trigger_from_row(r, now),
                )?;
                Ok((info, events, consumed))
            })
            .map_err(|e| e.to_api())?;
        let _ = consumed;
        self.hint(ChangeHint::Triggers);
        if events > 0 {
            self.hint(ChangeHint::Events);
        }
        Ok(info)
    }

    pub(crate) fn list_triggers_impl(&self, include_inactive: bool) -> ApiResult<Vec<TriggerInfo>> {
        let now = self.now();
        self.store
            .read(|c| {
                let mut st = c.prepare(&format!(
                    "SELECT {TRIGGER_COLS} FROM triggers ORDER BY created_at, id"
                ))?;
                let rows = st.query_map([], |r| trigger_from_row(r, now))?;
                let mut out = Vec::new();
                for r in rows {
                    let t = r?;
                    if include_inactive || t.state == TriggerState::Active {
                        out.push(t);
                    }
                }
                Ok(out)
            })
            .map_err(|e| e.to_api())
    }

    pub(crate) fn delete_trigger_impl(
        &self,
        trigger_id: String,
    ) -> ApiResult<DeleteTriggerResponse> {
        let n = self
            .store
            .tx(|tx| {
                Ok(tx.execute(
                    "UPDATE triggers SET state='deleted' WHERE id = ?1 AND state != 'deleted'",
                    [&trigger_id],
                )?)
            })
            .map_err(|e| e.to_api())?;
        if n > 0 {
            self.hint(ChangeHint::Triggers);
        }
        Ok(DeleteTriggerResponse {
            trigger_id,
            deleted: n > 0,
        })
    }

    pub(crate) fn read_events_impl(&self, req: PageRequest) -> ApiResult<EventPage> {
        let after = match &req.cursor {
            Some(c) => decode_seq(CursorKind::Event, c)?,
            None => 0,
        };
        let limit = clamp_limit(req.limit);
        let agent = self.own_str.clone();
        self.store
            .read(|c| {
                let mut st = c.prepare(
                    "SELECT seq, event_id, type, message_id, trigger_id, target_session, timestamp
                     FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2",
                )?;
                let rows = st.query_map(
                    params![after, i64::try_from(limit + 1).unwrap_or(i64::MAX)],
                    |r| {
                        let ty: String = r.get(2)?;
                        Ok(EventRecord {
                            cursor: encode_seq(CursorKind::Event, r.get(0)?),
                            event_id: r.get(1)?,
                            event_type: if ty == "trigger.matched" {
                                EventType::TriggerMatched
                            } else {
                                EventType::MessageReceived
                            },
                            agent_id: agent.clone(),
                            message_id: r.get(3)?,
                            trigger_id: r.get(4)?,
                            target_session: r.get(5)?,
                            timestamp: r.get(6)?,
                        })
                    },
                )?;
                let mut events: Vec<EventRecord> = Vec::new();
                for r in rows {
                    events.push(r?);
                }
                let has_more = events.len() > limit;
                events.truncate(limit);
                let next_cursor = Some(match events.last() {
                    Some(e) => e.cursor.clone(),
                    None => req
                        .cursor
                        .clone()
                        .unwrap_or_else(|| encode_seq(CursorKind::Event, 0)),
                });
                Ok(EventPage {
                    events,
                    next_cursor,
                    has_more,
                })
            })
            .map_err(|e| e.to_api())
    }

    pub(crate) fn ack_events_impl(&self, cursor: String) -> ApiResult<()> {
        let c = decode_seq(CursorKind::Event, &cursor)?;
        self.store
            .tx(|tx| {
                let max: i64 =
                    tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM events", [], |r| r.get(0))?;
                let prior: i64 = kv_get(tx, KV_EVENTS_ACK)?
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                // Never acknowledge events that do not exist yet.
                let new = prior.max(c.min(max));
                tx.execute(
                    "UPDATE events SET acked = 1 WHERE seq <= ?1 AND acked = 0",
                    [new],
                )?;
                kv_set(tx, KV_EVENTS_ACK, &new.to_string())?;
                Ok(())
            })
            .map_err(|e| e.to_api())
    }
}
