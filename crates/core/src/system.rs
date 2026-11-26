//! System messages and the state transitions behind them.
//!
//! * `contact.update`: a Trusted contact tells us its new signed contact record
//!   after a KEM rotation; applied only if it verifies, names the authenticated
//!   sender and has a strictly higher `key_epoch`. Pending outbox rows to that
//!   contact are re-sealed to the new key in the same transaction.
//! * `identity.revoked`: a self-authenticating tombstone; the named address is
//!   marked revoked (blocked, no sends, cannot be re-added or re-trusted).
//! * announcements at start (`contact.update` after a local rotation,
//!   `identity.revoked` after a local revocation), hidden from the user outbox.
//! * release of messages held by the replay guard.
//!
//! None of this adds cryptography: records are verified by `crypto`, frames are
//! sealed by [`crate::crypto::MessageProtection`].

use agentnet_transport::InboundFrame;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::api::{ApiError, ApiResult, ChangeHint, RevocationInfo, Trust};
use crate::config::UnknownSenders;
use crate::crypto::envelope::{
    Envelope, MESSAGE_TYPE_CONTACT_UPDATE, MESSAGE_TYPE_IDENTITY_REVOKED, SUITE_ID,
};
use crate::crypto::{Address, VerifiedContact, VerifiedRevocation};
use crate::guard;
use crate::ingest::FrameOutcome;
use crate::node::{
    trust_to_db, ContactRow, Node, NodeError, KV_ANNOUNCED_EPOCH, KV_ANNOUNCED_REVOCATION,
};
use crate::send::OutboxInsert;
use crate::store::{kv_get, kv_set, StoreError};

enum SysTx {
    Duplicate {
        reacked: bool,
    },
    Handled {
        applied: bool,
        resealed: usize,
        why: &'static str,
    },
}

impl Node {
    // ------------------------------------------------------------ inbound

    /// `contact.update` from a Trusted contact.
    pub(crate) fn ingest_contact_update(
        &self,
        frame: &InboundFrame,
        env: &Envelope,
    ) -> FrameOutcome {
        let now = self.now();
        let sender = env.sender.to_string();
        let res = self.store.tx(|tx| {
            let seen: Option<Option<i64>> = tx
                .query_row(
                    "SELECT last_reack_at FROM seen WHERE sender = ?1 AND message_id = ?2",
                    params![sender, env.message_id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(last) = seen {
                let reacked = self.reack_if_due(tx, env, last, now)?;
                return Ok(SysTx::Duplicate { reacked });
            }
            tx.execute(
                "INSERT INTO seen (sender, message_id, expires_at) VALUES (?1, ?2, ?3)",
                params![sender, env.message_id, env.expires_at],
            )?;
            guard::bump_generation(tx)?;
            let (applied, resealed, why) = self.apply_contact_update(tx, env, now)?;
            // Acked after the update so the ack is sealed to the new key.
            if self.queue_ack(tx, env, now)? {
                tx.execute(
                    "UPDATE seen SET last_reack_at = ?3 WHERE sender = ?1 AND message_id = ?2",
                    params![sender, env.message_id, now],
                )?;
            }
            Ok(SysTx::Handled {
                applied,
                resealed,
                why,
            })
        });
        self.finish_system(frame, res, "contact_update")
    }

    /// `identity.revoked` from any non-blocked sender.
    pub(crate) fn ingest_identity_revoked(
        &self,
        frame: &InboundFrame,
        env: &Envelope,
    ) -> FrameOutcome {
        let now = self.now();
        let sender = env.sender.to_string();
        let res = self.store.tx(|tx| {
            let seen: Option<Option<i64>> = tx
                .query_row(
                    "SELECT last_reack_at FROM seen WHERE sender = ?1 AND message_id = ?2",
                    params![sender, env.message_id],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(last) = seen {
                let reacked = if Self::is_revoked(tx, &env.sender)? {
                    false
                } else {
                    self.reack_if_due(tx, env, last, now)?
                };
                return Ok(SysTx::Duplicate { reacked });
            }
            tx.execute(
                "INSERT INTO seen (sender, message_id, expires_at) VALUES (?1, ?2, ?3)",
                params![sender, env.message_id, env.expires_at],
            )?;
            guard::bump_generation(tx)?;
            let (applied, failed, why) = self.apply_received_revocation(tx, env, now)?;
            if !Self::is_revoked(tx, &env.sender)? && self.queue_ack(tx, env, now)? {
                tx.execute(
                    "UPDATE seen SET last_reack_at = ?3 WHERE sender = ?1 AND message_id = ?2",
                    params![sender, env.message_id, now],
                )?;
            }
            Ok(SysTx::Handled {
                applied,
                resealed: failed,
                why,
            })
        });
        self.finish_system(frame, res, "identity_revoked")
    }

    fn finish_system(
        &self,
        frame: &InboundFrame,
        res: Result<SysTx, StoreError>,
        kind: &str,
    ) -> FrameOutcome {
        let res = match res {
            Ok(r) => r,
            Err(_) => return self.store_failure(),
        };
        self.publish_generation();
        self.mark_transport_seen(frame);
        match res {
            SysTx::Duplicate { reacked } => {
                self.metrics.inc("message.duplicate");
                if reacked {
                    self.metrics.inc("ack.requeued");
                    self.send_nudge.notify_one();
                }
                FrameOutcome::Duplicate { reacked }
            }
            SysTx::Handled {
                applied,
                resealed,
                why,
            } => {
                if applied {
                    self.metrics.inc(&format!("{kind}.applied"));
                    tracing::info!(kind, "system message applied");
                } else {
                    self.metrics.inc(&format!("{kind}.ignored_{why}"));
                    tracing::info!(kind, why, "system message ignored");
                }
                if resealed > 0 {
                    self.hint(ChangeHint::Outbox);
                }
                self.send_nudge.notify_one();
                FrameOutcome::SystemHandled { applied }
            }
        }
    }

    /// Apply a `contact.update` body. Returns `(applied, resealed rows, why not)`.
    fn apply_contact_update(
        &self,
        tx: &Transaction<'_>,
        env: &Envelope,
        now: i64,
    ) -> Result<(bool, usize, &'static str), StoreError> {
        let Ok(vc) = VerifiedContact::parse_and_verify(&env.body, now) else {
            return Ok((false, 0, "invalid"));
        };
        if vc.address != env.sender {
            // Someone else's record, even from a Trusted contact: never applied.
            return Ok((false, 0, "wrong_address"));
        }
        let Some(stored) = self.load_contact(tx, &env.sender)? else {
            return Ok((false, 0, "no_contact"));
        };
        if stored.revoked {
            return Ok((false, 0, "revoked"));
        }
        if stored.trust != Trust::Trusted {
            return Ok((false, 0, "untrusted"));
        }
        match vc.key_epoch.cmp(&stored.contact.key_epoch) {
            std::cmp::Ordering::Less => return Ok((false, 0, "stale")),
            std::cmp::Ordering::Equal => {
                return Ok((
                    false,
                    0,
                    if vc.same_record(&stored.contact) {
                        "same"
                    } else {
                        "conflict"
                    },
                ))
            }
            std::cmp::Ordering::Greater => {}
        }
        tx.execute(
            "UPDATE contacts SET document = ?2, updated_at = ?3 WHERE address = ?1",
            params![env.sender.to_string(), vc.document(), now],
        )?;
        let row = ContactRow {
            contact: vc,
            trust: stored.trust,
            alias: stored.alias,
            added_at: stored.added_at,
            revoked: false,
        };
        let resealed = self.reseal_outbox(tx, &row, now)?;
        Ok((true, resealed, ""))
    }

    /// Apply a tombstone that arrived in an envelope. Applicable if it names
    /// the authenticated sender or an existing contact.
    fn apply_received_revocation(
        &self,
        tx: &Transaction<'_>,
        env: &Envelope,
        now: i64,
    ) -> Result<(bool, usize, &'static str), StoreError> {
        let Ok(rev) = VerifiedRevocation::parse_and_verify(&env.body, now) else {
            return Ok((false, 0, "invalid"));
        };
        if rev.address == self.own {
            // A tombstone about ourselves is never applied to ourselves
            // (local revocation is an operator action).
            return Ok((false, 0, "about_self"));
        }
        let applicable =
            rev.address == env.sender || self.load_contact(tx, &rev.address)?.is_some();
        if !applicable {
            return Ok((false, 0, "unrelated"));
        }
        let (newly, failed) = self.apply_revocation(tx, &rev, "received", now)?;
        Ok((newly, failed, "already"))
    }

    /// Record a verified tombstone and fail pending sends to the address.
    /// Returns `(newly revoked, outbox rows failed)`.
    pub(crate) fn apply_revocation(
        &self,
        tx: &Transaction<'_>,
        rev: &VerifiedRevocation,
        source: &str,
        now: i64,
    ) -> Result<(bool, usize), StoreError> {
        // A revoked identity's advertisements are removed and refused from now on.
        Self::purge_adverts(tx, &rev.address)?;
        let n = tx.execute(
            "INSERT OR IGNORE INTO revocations (address, document, revoked_at, received_at, source)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                rev.address.to_string(),
                rev.document(),
                rev.revoked_at,
                now,
                source
            ],
        )?;
        let failed = tx.execute(
            "UPDATE outbox SET state='failed', next_attempt_at=NULL, last_error='recipient identity revoked'
             WHERE recipient = ?1 AND state IN ('queued','sent')",
            [rev.address.to_string()],
        )?;
        Ok((n > 0, failed))
    }

    /// Import a tombstone obtained out of band (`agentnet contact revoke`).
    pub fn import_revocation(&self, document: &str) -> ApiResult<RevocationInfo> {
        let now = self.now();
        let rev = VerifiedRevocation::parse_and_verify(document, now)
            .map_err(|e| ApiError::invalid(format!("invalid revocation document: {e}")))?;
        if rev.address == self.own {
            return Err(ApiError::invalid(
                "this is the local identity's own tombstone; use `agentnet identity revoke`",
            ));
        }
        let (newly, failed) = self
            .store
            .tx(|tx| self.apply_revocation(tx, &rev, "imported", now))
            .map_err(|e| e.to_api())?;
        if newly {
            self.metrics.inc("identity_revoked.imported");
        }
        if failed > 0 {
            self.hint(ChangeHint::Outbox);
        }
        Ok(RevocationInfo {
            address: rev.address.to_string(),
            revoked_at: rev.revoked_at,
            reason: rev.reason.clone(),
            newly_revoked: newly,
        })
    }

    // ------------------------------------------------------------ outbound

    /// Re-seal every undelivered outbox row to `row.contact` (same envelope,
    /// same message id, new frame). Returns the number of rows re-sealed.
    pub(crate) fn reseal_outbox(
        &self,
        tx: &Transaction<'_>,
        row: &ContactRow,
        now: i64,
    ) -> Result<usize, StoreError> {
        type R = (
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            i64,
            i64,
        );
        let rows: Vec<R> = {
            let mut st = tx.prepare(
                "SELECT message_id, type, conversation_id, correlation_id, body, created_at, expires_at
                 FROM outbox
                 WHERE recipient = ?1 AND state IN ('queued','sent') AND expires_at > ?2
                   AND NOT (is_ack = 1 AND state = 'sent')",
            )?;
            let it = st.query_map(params![row.contact.address.to_string(), now], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?;
            it.collect::<Result<_, _>>()?
        };
        let mut n = 0;
        for (message_id, ty, conv, corr, body, created, expires) in rows {
            let env = Envelope {
                v: 1,
                message_id: message_id.clone(),
                sender: self.own,
                recipient: row.contact.address,
                suite: SUITE_ID,
                recipient_key_epoch: 0,
                message_type: ty,
                conversation_id: conv,
                correlation_id: corr,
                created_at: created,
                expires_at: expires,
                body,
            };
            match self
                .protection
                .seal(&self.identity, &row.contact, &env, now, self.max_frame_len)
            {
                Ok(frame) => {
                    tx.execute(
                        "UPDATE outbox SET frame = ?2, next_attempt_at = ?3 WHERE message_id = ?1",
                        params![message_id, frame, now],
                    )?;
                    n += 1;
                }
                Err(_) => self.metrics.inc("reseal.failed"),
            }
        }
        if n > 0 {
            self.metrics.add("outbox.resealed", n as u64);
        }
        Ok(n)
    }

    /// Seal and queue a hidden system message to `row`'s contact.
    fn queue_system_message(
        &self,
        tx: &Transaction<'_>,
        row: &ContactRow,
        message_type: &str,
        body: &str,
        now: i64,
    ) -> Result<bool, StoreError> {
        let d = &self.config.delivery;
        let ttl_ms = i64::try_from(d.default_ttl_s.min(d.max_ttl_s).saturating_mul(1000))
            .unwrap_or(i64::MAX);
        let Ok(env) = Envelope::new(
            self.own,
            row.contact.address,
            message_type,
            body.to_owned(),
            now,
            ttl_ms,
        ) else {
            return Err(StoreError::Corrupt("random number generator failed"));
        };
        let frame =
            match self
                .protection
                .seal(&self.identity, &row.contact, &env, now, self.max_frame_len)
            {
                Ok(f) => f,
                Err(_) => {
                    self.metrics.inc("system.seal_failed");
                    return Ok(false);
                }
            };
        self.insert_outbox_row(
            tx,
            &OutboxInsert {
                env: &env,
                topic: &row.contact.inbox_topic().to_string(),
                frame: &frame,
                is_ack: false,
                hidden: true,
                idempotency_key: None,
            },
            now,
        )?;
        self.metrics.inc("system.queued");
        Ok(true)
    }

    fn trusted_contacts(&self, tx: &Transaction<'_>) -> Result<Vec<ContactRow>, StoreError> {
        let addrs: Vec<String> = {
            let mut st = tx.prepare(
                "SELECT address FROM contacts WHERE trust = 'trusted' ORDER BY added_at, address",
            )?;
            let it = st.query_map([], |r| r.get(0))?;
            it.collect::<Result<_, _>>()?
        };
        let mut out = Vec::new();
        for a in addrs {
            let addr: Address = a
                .parse()
                .map_err(|_| StoreError::Corrupt("stored address"))?;
            if let Some(row) = self.load_contact(tx, &addr)? {
                if !row.revoked && row.trust == Trust::Trusted {
                    out.push(row);
                }
            }
        }
        Ok(out)
    }

    /// At start: tell every Trusted contact about a KEM rotation done while
    /// the daemon was stopped (`contact.update`), and about a local identity
    /// revocation (`identity.revoked`). Idempotent via kv markers.
    pub(crate) fn announce_changes(&self, now: i64) -> Result<(), NodeError> {
        let queued = self.store.tx(|tx| {
            let mut queued = 0usize;
            let cur = self.identity.key_epoch();
            let announced: Option<u64> =
                kv_get(tx, KV_ANNOUNCED_EPOCH)?.and_then(|s| s.parse().ok());
            match announced {
                None => kv_set(tx, KV_ANNOUNCED_EPOCH, &cur.to_string())?,
                Some(a) if cur > a && self.local_revocation.is_none() => {
                    let doc = self.identity.contact_record().to_document();
                    for row in self.trusted_contacts(tx)? {
                        if self.queue_system_message(
                            tx,
                            &row,
                            MESSAGE_TYPE_CONTACT_UPDATE,
                            &doc,
                            now,
                        )? {
                            queued += 1;
                        }
                    }
                    kv_set(tx, KV_ANNOUNCED_EPOCH, &cur.to_string())?;
                }
                Some(_) => {}
            }
            if let Some(rev) = &self.local_revocation {
                if kv_get(tx, KV_ANNOUNCED_REVOCATION)?.is_none() {
                    for row in self.trusted_contacts(tx)? {
                        if self.queue_system_message(
                            tx,
                            &row,
                            MESSAGE_TYPE_IDENTITY_REVOKED,
                            rev.document(),
                            now,
                        )? {
                            queued += 1;
                        }
                    }
                    kv_set(tx, KV_ANNOUNCED_REVOCATION, "1")?;
                }
            }
            Ok(queued)
        })?;
        if queued > 0 {
            self.metrics.add("system.announced", queued as u64);
            self.send_nudge.notify_one();
        }
        Ok(())
    }

    // --------------------------------------------------------- replay guard

    /// Release messages held by the replay guard (after the guard was cleared
    /// or accepted): expired ones are discarded; unexpired ones are judged by the
    /// sender's current standing like a new frame (blocked or revoked: dropped;
    /// unknown or untrusted: per `unknown_senders`) and otherwise become normal
    /// inbox messages (event + ack, no trigger matching).
    pub(crate) fn release_held(&self, now: i64) -> Result<(), StoreError> {
        let any: i64 = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM inbox WHERE hold_reason IS NOT NULL",
                [],
                |r| r.get(0),
            )?)
        })?;
        if any == 0 {
            return Ok(());
        }
        let (released, convs) = self.store.tx(|tx| {
            type Q = (i64, String, String, String, Option<String>, Option<String>, String, i64, i64);
            let rows: Vec<Q> = {
                let mut st = tx.prepare(
                    "SELECT seq, message_id, sender, type, conversation_id, correlation_id, body, created_at, expires_at
                     FROM inbox WHERE hold_reason IS NOT NULL ORDER BY seq",
                )?;
                let it = st.query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                })?;
                it.collect::<Result<_, _>>()?
            };
            let mut released = 0usize;
            let mut convs = Vec::new();
            for (seq, message_id, sender, ty, conv, corr, body, created, expires) in rows {
                if expires <= now {
                    tx.execute("DELETE FROM inbox WHERE seq = ?1", [seq])?;
                    continue;
                }
                let Ok(addr) = sender.parse::<Address>() else {
                    continue;
                };
                // Re-apply the sender's *current* standing, as ingest would for a
                // new frame: the sender may have been blocked, revoked or
                // distrusted while the message was held.
                let trust = match self.load_contact(tx, &addr)? {
                    Some(r) => r.trust,
                    None if Self::is_revoked(tx, &addr)? => Trust::Blocked,
                    None => Trust::Unknown,
                };
                let policy = self.config.policy.unknown_senders;
                if trust == Trust::Blocked
                    || (trust != Trust::Trusted && policy == UnknownSenders::Reject)
                {
                    tx.execute("DELETE FROM inbox WHERE seq = ?1", [seq])?;
                    self.metrics.inc("guard.release_dropped");
                    continue;
                }
                if trust != Trust::Trusted && policy == UnknownSenders::Quarantine {
                    tx.execute(
                        "UPDATE inbox SET hold_reason = NULL, sender_trust = ?2 WHERE seq = ?1",
                        params![seq, trust_to_db(trust)],
                    )?;
                    self.metrics.inc("guard.release_quarantined");
                    continue;
                }
                tx.execute(
                    "UPDATE inbox SET quarantined = 0, hold_reason = NULL, sender_trust = ?2 WHERE seq = ?1",
                    params![seq, trust_to_db(trust)],
                )?;
                self.insert_event(tx, "message.received", &message_id, None, None, now)?;
                let orig = Envelope {
                    v: 1,
                    message_id: message_id.clone(),
                    sender: addr,
                    recipient: self.own,
                    suite: SUITE_ID,
                    recipient_key_epoch: 0,
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
                released += 1;
            }
            Ok((released, convs))
        })?;
        if released > 0 {
            self.metrics.add("guard.released", released as u64);
            self.hint(ChangeHint::Inbox);
            self.hint(ChangeHint::Events);
            for c in convs {
                self.hint(ChangeHint::Conversation { conversation_id: c });
            }
            self.send_nudge.notify_one();
        }
        Ok(())
    }
}
