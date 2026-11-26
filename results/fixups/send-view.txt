//! Outbound path: validation + seal + durable enqueue, and the retry loop step.

use agentnet_transport::{ContentTopic, TransportError};
use rusqlite::{params, OptionalExtension, Transaction};

use crate::address::Address;
use crate::api::{
    ApiError, ApiResult, ChangeHint, DeliveryState, ErrorCode, SendMessageRequest,
    SendMessageResponse, Trust,
};
use crate::envelope::{
    self, new_message_id, Envelope, MESSAGE_TYPE_ACK_RECEIVED, MESSAGE_TYPE_MESSAGE,
    MESSAGE_TYPE_TASK_REQUEST, MESSAGE_TYPE_TASK_RESULT,
};
use crate::error::SealError;
use crate::node::{sanitize, state_from_db, Node, NodeError, SendReport};
use crate::store::StoreError;

const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;

/// Everything needed to enqueue one sealed frame.
#[derive(Clone, Copy)]
pub(crate) struct OutboxInsert<'a> {
    pub env: &'a Envelope,
    pub topic: &'a str,
    pub frame: &'a [u8],
    pub is_ack: bool,
    pub idempotency_key: Option<&'a str>,
}

type IdemRow = (String, String, String, String, Option<String>, String, i64);

impl Node {
    /// Insert a sealed frame into the outbox in state `queued`, due now.
    pub(crate) fn insert_outbox_row(
        &self,
        tx: &Transaction<'_>,
        row: &OutboxInsert<'_>,
        now: i64,
    ) -> Result<(), StoreError> {
        let OutboxInsert {
            env,
            topic,
            frame,
            is_ack,
            idempotency_key,
        } = *row;
        tx.execute(
            "INSERT INTO outbox (message_id, recipient, topic, type, conversation_id, correlation_id,
                                 body, frame, state, created_at, expires_at, next_attempt_at,
                                 idempotency_key, is_ack)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9, ?10, ?9, ?11, ?12)",
            params![
                env.message_id,
                env.recipient.to_string(),
                topic,
                env.message_type,
                env.conversation_id,
                env.correlation_id,
                env.body,
                frame,
                now,
                env.expires_at,
                idempotency_key,
                i64::from(is_ack),
            ],
        )?;
        Ok(())
    }

    pub(crate) fn send_message_impl(
        &self,
        req: SendMessageRequest,
    ) -> ApiResult<SendMessageResponse> {
        let recipient: Address = req
            .recipient
            .parse()
            .map_err(|_| ApiError::invalid("recipient is not a valid agent address"))?;
        let mtype = req.message_type.as_deref().unwrap_or(MESSAGE_TYPE_MESSAGE);
        match mtype {
            MESSAGE_TYPE_MESSAGE | MESSAGE_TYPE_TASK_REQUEST | MESSAGE_TYPE_TASK_RESULT => {}
            MESSAGE_TYPE_ACK_RECEIVED => {
                return Err(ApiError::invalid(
                    "message type ack.received is reserved for the engine",
                ))
            }
            _ => {
                return Err(ApiError::invalid(
                    "message_type must be one of: message, task.request, task.result",
                ))
            }
        }
        let d = &self.config.delivery;
        if req.body.len() > d.max_body_bytes {
            return Err(ApiError::new(
                ErrorCode::TooLarge,
                format!(
                    "body is {} bytes; the maximum is {}",
                    req.body.len(),
                    d.max_body_bytes
                ),
            ));
        }
        if let Some(k) = &req.idempotency_key {
            if k.is_empty()
                || k.len() > MAX_IDEMPOTENCY_KEY_LEN
                || !k.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return Err(ApiError::invalid(
                    "idempotency_key must be 1..=128 printable ASCII characters",
                ));
            }
        }
        let ttl_s = match req.ttl_seconds {
            Some(0) => return Err(ApiError::invalid("ttl_seconds must be greater than zero")),
            Some(t) => t.min(d.max_ttl_s),
            None => d.default_ttl_s,
        };
        let ttl_ms = i64::try_from(ttl_s.saturating_mul(1000)).unwrap_or(i64::MAX);
        let conversation_id = match &req.conversation_id {
            Some(c) => c.clone(),
            None => new_message_id()
                .map_err(|_| ApiError::internal("random number generator failed"))?,
        };
        let now = self.now();

        let res = self.store.tx(|tx| {
            if let Some(k) = &req.idempotency_key {
                let old: Option<IdemRow> = tx
                    .query_row(
                        "SELECT message_id, recipient, type, body, conversation_id, state, expires_at
                         FROM outbox WHERE idempotency_key = ?1",
                        [k],
                        |r| {
                            Ok((
                                r.get(0)?,
                                r.get(1)?,
                                r.get(2)?,
                                r.get(3)?,
                                r.get(4)?,
                                r.get(5)?,
                                r.get(6)?,
                            ))
                        },
                    )
                    .optional()?;
                if let Some((id, rcpt, ty, body, conv, state, exp)) = old {
                    if rcpt != req.recipient || ty != mtype || body != req.body {
                        return Err(ApiError::new(
                            ErrorCode::Conflict,
                            "idempotency_key was already used for a different message",
                        )
                        .into());
                    }
                    return Ok(SendMessageResponse {
                        message_id: id,
                        status: state_from_db(&state),
                        conversation_id: conv.unwrap_or_default(),
                        expires_at: exp,
                        deduplicated: true,
                    });
                }
            }
            let row = self
                .load_contact(tx, &recipient)?
                .ok_or_else(|| ApiError::not_found("recipient is not a known contact; add_contact first"))?;
            if row.trust == Trust::Blocked {
                return Err(ApiError::policy("recipient is blocked").into());
            }
            if row.contact.is_kem_expired(now) {
                return Err(ApiError::invalid(
                    "the recipient's contact record has an expired encryption key; ask them for a fresh record and import it with add_contact",
                )
                .into());
            }
            let pending: i64 = tx.query_row(
                "SELECT COUNT(*) FROM outbox WHERE is_ack = 0 AND state IN ('queued','sent')",
                [],
                |r| r.get(0),
            )?;
            if u64::try_from(pending).unwrap_or(u64::MAX) >= d.max_outbox_pending {
                return Err(ApiError::unavailable("outbox is full; try again later").into());
            }
            let mut env = Envelope::new(self.own, recipient, mtype, req.body.clone(), now, ttl_ms)
                .map_err(|_| ApiError::internal("random number generator failed"))?;
            env.conversation_id = Some(conversation_id.clone());
            env.correlation_id = req.correlation_id.clone();
            env.validate()
                .map_err(|f| ApiError::invalid(format!("invalid field: {f}")))?;
            let frame = envelope::seal(&self.identity, &row.contact, &env, now, self.max_frame_len)
                .map_err(|e| match e {
                    SealError::TooLarge { max_body_len_hint, .. } => ApiError::new(
                        ErrorCode::TooLarge,
                        format!("message does not fit in one frame; at most about {max_body_len_hint} bytes of body fit"),
                    ),
                    SealError::RecipientKemExpired => ApiError::invalid(
                        "the recipient's encryption key has expired; import a fresh contact record",
                    ),
                    SealError::InvalidField(f) => ApiError::invalid(format!("invalid field: {f}")),
                    _ => ApiError::internal("could not seal message"),
                })?;
            self.insert_outbox_row(
                tx,
                &OutboxInsert {
                    env: &env,
                    topic: &row.contact.inbox_topic().to_string(),
                    frame: &frame,
                    is_ack: false,
                    idempotency_key: req.idempotency_key.as_deref(),
                },
                now,
            )?;
            Ok(SendMessageResponse {
                message_id: env.message_id,
                status: DeliveryState::Queued,
                conversation_id,
                expires_at: env.expires_at,
                deduplicated: false,
            })
        });
        let resp = res.map_err(|e| e.to_api())?;
        if !resp.deduplicated {
            self.metrics.inc("outbox.queued");
            self.hint(ChangeHint::Outbox);
            self.hint(ChangeHint::Conversation {
                conversation_id: resp.conversation_id.clone(),
            });
            self.send_nudge.notify_one();
        }
        Ok(resp)
    }

    /// Publish every due outbox row (bounded by `delivery.send_batch`).
    ///
    /// Retry schedule: after the n-th accepted publish of a non-ack row the next
    /// attempt is `now + U[1, min(retry_max, retry_base * 2^(n-1))]` ms. After
    /// `max_attempts` accepted publishes no more are made (the row stays `sent`
    /// until it is acked or expires). Retryable transport errors keep the state
    /// and back off by the same schedule using a separate failure counter.
    pub async fn step_send(&self) -> Result<SendReport, NodeError> {
        type Due = (String, String, Vec<u8>, i64, u32, u32, bool);
        let now = self.now();
        let batch = i64::from(self.config.delivery.send_batch);
        let due: Vec<Due> = self.store.read(|c| {
            let mut st = c.prepare(
                "SELECT message_id, topic, frame, expires_at, attempts, failures, is_ack
                 FROM outbox
                 WHERE state IN ('queued','sent') AND next_attempt_at IS NOT NULL AND next_attempt_at <= ?1
                 ORDER BY next_attempt_at, seq LIMIT ?2",
            )?;
            let rows = st.query_map(params![now, batch], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get::<_, i64>(6)? != 0,
                ))
            })?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r?);
            }
            Ok(v)
        })?;
        let mut rep = SendReport::default();
        let max_attempts = self.config.delivery.max_attempts;
        for (id, topic, frame, expires_at, attempts, failures, is_ack) in due {
            let now = self.now();
            if now >= expires_at {
                let n = self.store.tx(|tx| {
                    Ok(tx.execute(
                        "UPDATE outbox SET state='expired', next_attempt_at=NULL
                         WHERE message_id=?1 AND state IN ('queued','sent')",
                        [&id],
                    )?)
                })?;
                if n > 0 {
                    rep.expired += 1;
                    self.metrics.inc("outbox.expired");
                    if !is_ack {
                        self.hint(ChangeHint::Outbox);
                    }
                }
                continue;
            }
            let Ok(topic) = ContentTopic::new(topic) else {
                self.fail_row(&id, "invalid stored topic", is_ack)?;
                rep.failed += 1;
                continue;
            };
            match self.transport.publish(&topic, &frame).await {
                Ok(_) => {
                    let new_attempts = attempts.saturating_add(1);
                    let next: Option<i64> = if is_ack || new_attempts >= max_attempts {
                        None
                    } else {
                        Some(now.saturating_add(self.backoff_ms(new_attempts)))
                    };
                    let n = self.store.tx(|tx| {
                        Ok(tx.execute(
                            "UPDATE outbox SET state='sent', attempts=attempts+1, failures=0,
                               last_attempt_at=?2, sent_at=COALESCE(sent_at, ?2), last_error=NULL,
                               next_attempt_at=?3
                             WHERE message_id=?1 AND state IN ('queued','sent')",
                            params![id, now, next],
                        )?)
                    })?;
                    rep.published += 1;
                    self.metrics.inc("publish.ok");
                    if n > 0 && !is_ack && attempts == 0 {
                        self.hint(ChangeHint::Outbox);
                    }
                }
                Err(TransportError::TooLarge { .. }) => {
                    self.fail_row(&id, "frame too large for the transport", is_ack)?;
                    rep.failed += 1;
                    self.metrics.inc("publish.too_large");
                }
                Err(TransportError::Isolation(_)) => {
                    // Fail closed: nothing is sent, nothing is backed off; rows stay due
                    // and go out as soon as the violation clears.
                    self.store.tx(|tx| {
                        tx.execute(
                            "UPDATE outbox SET last_error=?2 WHERE message_id=?1 AND state IN ('queued','sent')",
                            params![id, "transport isolation violation"],
                        )?;
                        Ok(())
                    })?;
                    self.metrics.inc("publish.isolation_blocked");
                    rep.failed += 1;
                    rep.deferred = true;
                    break;
                }
                Err(e) => {
                    let new_failures = failures.saturating_add(1);
                    let next = now.saturating_add(self.backoff_ms(new_failures));
                    let msg = sanitize(&e.to_string());
                    self.store.tx(|tx| {
                        tx.execute(
                            "UPDATE outbox SET failures=?2, last_attempt_at=?3, next_attempt_at=?4, last_error=?5
                             WHERE message_id=?1 AND state IN ('queued','sent')",
                            params![id, new_failures, now, next, msg],
                        )?;
                        Ok(())
                    })?;
                    self.metrics.inc("publish.error");
                    rep.failed += 1;
                    if e.is_retryable() {
                        rep.deferred = true;
                        break;
                    }
                }
            }
        }
        Ok(rep)
    }

    fn fail_row(&self, id: &str, why: &str, is_ack: bool) -> Result<(), StoreError> {
        self.store.tx(|tx| {
            tx.execute(
                "UPDATE outbox SET state='failed', next_attempt_at=NULL, last_error=?2
                 WHERE message_id=?1 AND state IN ('queued','sent')",
                params![id, why],
            )?;
            Ok(())
        })?;
        if !is_ack {
            self.hint(ChangeHint::Outbox);
        }
        Ok(())
    }
}
