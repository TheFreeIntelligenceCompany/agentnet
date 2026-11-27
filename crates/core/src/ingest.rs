//! Inbound frame processing, in exactly this order:
//! transport dedupe -> `open` -> trust -> (ack handling | policy + one
//! transaction that persists the message, events, trigger matches and the ack)
//! -> only then `transport_seen` and change hints.

use agentnet_transport::InboundFrame;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::api::{ChangeHint, Trust};
use crate::config::UnknownSenders;
use crate::crypto::envelope::{
    Envelope, MESSAGE_TYPE_ACK_RECEIVED, MESSAGE_TYPE_CONTACT_UPDATE, MESSAGE_TYPE_IDENTITY_REVOKED,
};
use crate::crypto::{SenderAuth, VerifiedRevocation};
use crate::error::OpenError;
use crate::guard::{self, HOLD_REPLAY_GUARD};
use crate::node::{trust_to_db, Node};
use crate::send::OutboxInsert;
use crate::store::StoreError;
use crate::triggers::Candidate;

/// What happened to one inbound frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameOutcome {
    /// The transport id was already processed.
    AlreadySeen,
    /// Another agent's frame in a shared bucket.
    NotForUs,
    /// `open` rejected the frame (counted by kind).
    Invalid,
    /// `created_at` too far in the future; not marked seen, may be valid later.
    Deferred,
    /// Sender is blocked.
    Blocked,
    /// Policy `reject` dropped it.
    Rejected,
    /// Stored quarantined.
    Quarantined,
    /// Quarantine is full; dropped.
    QuarantineFull,
    /// Inbox is full; refused and not acked (the sender keeps retrying).
    InboxFull,
    /// New message persisted.
    Accepted,
    /// Already persisted; `reacked` tells whether an ack was re-queued.
    Duplicate {
        /// An ack was queued again.
        reacked: bool,
    },
    /// A valid ack updated an outbox row.
    AckApplied,
    /// A reserved system message (`contact.update`, `identity.revoked`) was
    /// processed; `applied` tells whether it changed local state.
    SystemHandled {
        /// The message changed the contact/revocation state.
        applied: bool,
    },
    /// Held by the replay guard (older than the guard start; no ack, no trigger).
    HeldByGuard,
    /// An ack that was ignored (wrong party, unknown id, untrusted, duplicate).
    AckIgnored,
    /// A valid advertisement was stored, replaced an older one or recorded a
    /// withdrawal (discovery topics only).
    AdvertApplied,
    /// A valid advertisement that changed nothing (stale or repeated sequence
    /// number, expired, or our own).
    AdvertIgnored,
    /// A discovery-topic frame that is not a valid advertisement (counted by kind).
    AdvertInvalid,
    /// Dropped without being stored: an advertisement frame on an inbox topic, a
    /// sealed frame on a discovery topic, an advertiser that is blocked or
    /// revoked, or a full advert table.
    Dropped,
    /// The database failed; nothing was recorded, the frame is not marked seen.
    StoreFailure,
}

impl FrameOutcome {
    /// True for [`FrameOutcome::StoreFailure`].
    pub fn is_store_failure(&self) -> bool {
        matches!(self, Self::StoreFailure)
    }
}

fn open_error_kind(e: &OpenError) -> &'static str {
    match e {
        OpenError::Truncated => "truncated",
        OpenError::FrameTooLarge => "frame_too_large",
        OpenError::Malformed => "malformed",
        OpenError::NotForUs => "not_for_us",
        OpenError::SkeskPresent => "skesk_present",
        OpenError::PkeskNotV6 => "pkesk_not_v6",
        OpenError::NotAead => "not_aead",
        OpenError::UnsupportedCipher => "unsupported_cipher",
        OpenError::Compressed => "compressed",
        OpenError::BadStructure => "bad_structure",
        OpenError::WrongSignatureCount => "wrong_signature_count",
        OpenError::UnsupportedSignature => "unsupported_signature",
        OpenError::BadSignature => "bad_signature",
        OpenError::UnknownSender => "unknown_sender",
        OpenError::SenderRevoked => "sender_revoked",
        OpenError::SenderExpired => "sender_expired",
        OpenError::SignerMismatch => "signer_mismatch",
        OpenError::MissingIntendedRecipient => "missing_intended_recipient",
        OpenError::WrongIntendedRecipient => "wrong_intended_recipient",
        OpenError::MalformedPayload => "malformed_payload",
        OpenError::UnknownEnvelopeVersion(_) => "unknown_envelope_version",
        OpenError::InvalidField(_) => "invalid_field",
        OpenError::WrongRecipient => "wrong_recipient",
        OpenError::FromFuture => "from_future",
        OpenError::Expired => "expired",
        OpenError::ExpiresBeforeCreated => "expires_before_created",
        OpenError::TtlTooLong => "ttl_too_long",
    }
}

/// Longest random delay before a re-ack is first published (ms).
const REACK_DELAY_MAX_MS: i64 = 5_000;

enum MsgTx {
    Duplicate {
        reacked: bool,
    },
    Accepted {
        acked: bool,
        consumed: bool,
        quarantined: bool,
        held: bool,
    },
    InboxFull,
    QuarantineFull,
}

enum AckTx {
    Applied { conversation_id: Option<String> },
    Ignored(&'static str),
}

impl Node {
    pub(crate) fn mark_transport_seen(&self, frame: &InboundFrame) {
        let now = self.now();
        let r = self.store.tx(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO transport_seen (transport_id, first_seen) VALUES (?1, ?2)",
                params![frame.transport_id.as_slice(), now],
            )?;
            Ok(())
        });
        if r.is_err() {
            self.metrics.inc("store.transport_seen_error");
        }
    }

    /// Process one frame from the transport (live or history).
    pub fn ingest_frame(&self, frame: &InboundFrame) -> FrameOutcome {
        self.metrics.inc("frame.received");
        // 1. transport-level dedupe
        match self.store.read(|c| {
            Ok(c.query_row(
                "SELECT 1 FROM transport_seen WHERE transport_id = ?1",
                [frame.transport_id.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
        }) {
            Ok(true) => {
                self.metrics.inc("frame.transport_seen");
                return FrameOutcome::AlreadySeen;
            }
            Ok(false) => {}
            Err(_) => return self.store_failure(),
        }
        // 1b. route by topic: discovery topics carry plaintext advertisement
        // frames only; every other topic carries sealed frames only.
        if let Some(name) = self.discovery_name(&frame.topic) {
            return self.ingest_advert_frame(frame, &name);
        }
        if crate::crypto::advert::has_advert_magic(&frame.payload) {
            self.metrics.inc("advert.cross_topic.advert_on_inbox");
            self.mark_transport_seen(frame);
            return FrameOutcome::Dropped;
        }
        // 2. open
        let now = self.now();
        let auth: SenderAuth;
        // The sender directory is fallible (review finding L5): a lookup that
        // fails is remembered and fails the whole open as a store failure; the
        // frame is not marked seen and will be seen again.
        let dir_failed = std::cell::Cell::new(false);
        let dir = |a: &crate::crypto::Address| match self.pinned_certificate(a) {
            Ok(c) => c,
            Err(_) => {
                dir_failed.set(true);
                None
            }
        };
        let opened =
            self.protection
                .open(&self.identity, &frame.payload, now, &self.open_limits, &dir);
        if dir_failed.get() {
            self.metrics.inc("open.directory_failed");
            return self.store_failure();
        }
        let env =
            match opened {
                Ok(o) => {
                    self.metrics.inc(match o.auth {
                        SenderAuth::Pinned => "open.auth_pinned",
                        SenderAuth::EmbeddedCertificate => "open.auth_embedded",
                    });
                    auth = o.auth;
                    o.envelope
                }
                Err(OpenError::SenderRevoked) => {
                    // A revoked identity's messages are dropped like a blocked sender's.
                    self.metrics.inc("drop.blocked");
                    self.metrics.inc("open_error.sender_revoked");
                    self.mark_transport_seen(frame);
                    return FrameOutcome::Blocked;
                }
                Err(OpenError::NotForUs) => {
                    self.metrics.inc("frame.not_for_us");
                    self.mark_transport_seen(frame);
                    return FrameOutcome::NotForUs;
                }
                Err(OpenError::FromFuture) => {
                    self.metrics.inc("open_error.from_future");
                    return FrameOutcome::Deferred;
                }
                Err(e) => {
                    self.metrics
                        .inc(&format!("open_error.{}", open_error_kind(&e)));
                    self.mark_transport_seen(frame);
                    return FrameOutcome::Invalid;
                }
            };
        let digest = crate::crypto::frame_digest(&frame.payload);
        // 3. trust
        let mut sender_is_contact = false;
        let trust = match self.store.read(|c| self.load_contact(c, &env.sender)) {
            Ok(Some(row)) => {
                sender_is_contact = true;
                row.trust
            }
            Ok(None) => {
                // A tombstone may exist for an address that is not a contact
                // (imported out of band).
                match self.store.read(|c| Self::is_revoked(c, &env.sender)) {
                    Ok(true) => Trust::Blocked,
                    Ok(false) => Trust::Unknown,
                    Err(_) => return self.store_failure(),
                }
            }
            Err(_) => return self.store_failure(),
        };
        // A sender that IS a contact must have been authenticated against its
        // pinned certificate. An embedded-certificate authentication for a contact
        // means the directory and the contact table disagree (a race or a failure):
        // treat it like a store failure and see the frame again.
        if sender_is_contact && auth == SenderAuth::EmbeddedCertificate {
            self.metrics.inc("open.auth_mismatch");
            return self.store_failure();
        }
        if trust == Trust::Blocked {
            self.metrics.inc("drop.blocked");
            self.mark_transport_seen(frame);
            return FrameOutcome::Blocked;
        }
        // 4. acks (never subject to quarantine policy; never stored in the inbox)
        if env.message_type == MESSAGE_TYPE_ACK_RECEIVED {
            return self.ingest_ack(frame, &env, trust);
        }
        // Reserved system messages. A tombstone is self-authenticating, so any
        // non-blocked sender may deliver one; a contact update is applied only
        // from a Trusted contact (other senders' copies are stored like any
        // other message, under the quarantine policy, and never applied).
        if env.message_type == MESSAGE_TYPE_IDENTITY_REVOKED {
            if !sender_is_contact {
                // Review finding M2: a stranger's frame must not grow any table.
                // The unknown-sender policy runs first; then only a revocation
                // that names an existing contact is considered at all.
                if self.config.policy.unknown_senders == UnknownSenders::Reject {
                    self.metrics.inc("drop.rejected_unknown_sender");
                    self.mark_transport_seen(frame);
                    return FrameOutcome::Rejected;
                }
                let names_a_contact = VerifiedRevocation::parse_and_verify(&env.body, now)
                    .ok()
                    .map(|rev| self.store.read(|c| self.load_contact(c, &rev.address)))
                    .transpose();
                match names_a_contact {
                    Err(_) => return self.store_failure(),
                    Ok(Some(Some(_))) => {}
                    Ok(_) => {
                        self.metrics.inc("identity_revoked.dropped_non_contact");
                        self.mark_transport_seen(frame);
                        return FrameOutcome::SystemHandled { applied: false };
                    }
                }
            }
            return self.ingest_identity_revoked(frame, &env, &digest);
        }
        if env.message_type == MESSAGE_TYPE_CONTACT_UPDATE && trust == Trust::Trusted {
            return self.ingest_contact_update(frame, &env, &digest);
        }
        let policy = self.config.policy.unknown_senders;
        if trust != Trust::Trusted && policy == UnknownSenders::Reject {
            self.metrics.inc("drop.rejected_unknown_sender");
            self.mark_transport_seen(frame);
            return FrameOutcome::Rejected;
        }
        let quarantine = trust != Trust::Trusted && policy == UnknownSenders::Quarantine;
        // Replay guard: after a store rollback / import, messages created up to
        // the guard start plus the permitted clock skew are held instead of
        // delivered (a message accepted before the rollback may have been
        // created that far ahead of the local clock; the bound is inclusive).
        let skew = self.open_limits.clock_skew_ms;
        let hold = !quarantine
            && self
                .guard_state()
                .is_some_and(|g| env.created_at <= g.since.saturating_add(skew));
        // 5. one transaction
        let res = self
            .store
            .tx(|tx| self.persist_message(tx, &env, trust, quarantine, hold, now, &digest));
        let res = match res {
            Ok(r) => r,
            Err(_) => return self.store_failure(),
        };
        self.publish_generation();
        match res {
            MsgTx::InboxFull => {
                self.metrics.inc("inbox.full_refused");
                FrameOutcome::InboxFull
            }
            MsgTx::QuarantineFull => {
                self.metrics.inc("drop.quarantine_full");
                FrameOutcome::QuarantineFull
            }
            MsgTx::Duplicate { reacked } => {
                self.metrics.inc("message.duplicate");
                self.mark_transport_seen(frame);
                if reacked {
                    self.metrics.inc("ack.requeued");
                    self.send_nudge.notify_one();
                }
                FrameOutcome::Duplicate { reacked }
            }
            MsgTx::Accepted {
                acked,
                consumed,
                quarantined,
                held,
            } => {
                self.mark_transport_seen(frame);
                if held {
                    self.metrics.inc("guard.held");
                    return FrameOutcome::HeldByGuard;
                }
                if quarantined {
                    self.metrics.inc("message.quarantined");
                    return FrameOutcome::Quarantined;
                }
                self.metrics.inc("message.accepted");
                self.hint(ChangeHint::Inbox);
                if let Some(c) = env.conversation_id.clone() {
                    self.hint(ChangeHint::Conversation { conversation_id: c });
                }
                self.hint(ChangeHint::Events);
                if consumed {
                    self.hint(ChangeHint::Triggers);
                }
                if acked {
                    self.send_nudge.notify_one();
                }
                FrameOutcome::Accepted
            }
        }
    }

    pub(crate) fn store_failure(&self) -> FrameOutcome {
        self.metrics.inc("store.error");
        FrameOutcome::StoreFailure
    }

    fn persist_message(
        &self,
        tx: &Transaction<'_>,
        env: &Envelope,
        trust: Trust,
        quarantine: bool,
        hold: bool,
        now: i64,
        digest: &[u8; 32],
    ) -> Result<MsgTx, StoreError> {
        let quarantine_slot = quarantine || hold;
        let sender = env.sender.to_string();
        let seen: Option<Option<i64>> = tx
            .query_row(
                "SELECT last_reack_at FROM seen WHERE sender = ?1 AND message_id = ?2",
                params![sender, env.message_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(last) = seen {
            // Duplicate: no inbox row, no event, no trigger. Maybe re-ack.
            let stored_q: Option<i64> = tx
                .query_row(
                    "SELECT quarantined FROM inbox WHERE sender = ?1 AND message_id = ?2",
                    params![sender, env.message_id],
                    |r| r.get(0),
                )
                .optional()?;
            let mut reacked = false;
            if stored_q == Some(0) {
                reacked = self.reack_if_due(tx, env, last, now, digest)?;
            }
            return Ok(MsgTx::Duplicate { reacked });
        }
        if quarantine_slot {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM inbox WHERE quarantined = 1",
                [],
                |r| r.get(0),
            )?;
            if u64::try_from(n).unwrap_or(u64::MAX) >= self.config.storage.max_quarantined {
                return Ok(MsgTx::QuarantineFull);
            }
        } else {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM inbox WHERE quarantined = 0",
                [],
                |r| r.get(0),
            )?;
            if u64::try_from(n).unwrap_or(u64::MAX) >= self.config.storage.max_inbox_records {
                return Ok(MsgTx::InboxFull);
            }
        }
        tx.execute(
            "INSERT INTO seen (sender, message_id, expires_at, frame_digest) VALUES (?1, ?2, ?3, ?4)",
            params![sender, env.message_id, env.expires_at, digest.as_slice()],
        )?;
        guard::bump_generation(tx)?;
        tx.execute(
            "INSERT INTO inbox (message_id, sender, type, conversation_id, correlation_id, body,
                                created_at, expires_at, received_at, quarantined, sender_trust,
                                hold_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                env.message_id,
                sender,
                env.message_type,
                env.conversation_id,
                env.correlation_id,
                env.body,
                env.created_at,
                env.expires_at,
                now,
                i64::from(quarantine_slot),
                trust_to_db(trust),
                hold.then_some(HOLD_REPLAY_GUARD),
            ],
        )?;
        if quarantine_slot {
            return Ok(MsgTx::Accepted {
                acked: false,
                consumed: false,
                quarantined: true,
                held: hold,
            });
        }
        self.insert_event(tx, "message.received", &env.message_id, None, None, now)?;
        let mut consumed = false;
        if trust == Trust::Trusted {
            let cand = Candidate {
                message_id: &env.message_id,
                sender: &sender,
                message_type: &env.message_type,
                conversation_id: env.conversation_id.as_deref(),
                correlation_id: env.correlation_id.as_deref(),
            };
            consumed = self.fire_triggers(tx, &cand, now, None)?.consumed > 0;
        }
        let acked = self.queue_ack(tx, env, now)?;
        if acked {
            tx.execute(
                "UPDATE seen SET last_reack_at = ?3 WHERE sender = ?1 AND message_id = ?2",
                params![sender, env.message_id, now],
            )?;
        }
        Ok(MsgTx::Accepted {
            acked,
            consumed,
            quarantined: false,
            held: false,
        })
    }

    /// Re-queue an ack for an already stored message if the re-ack interval
    /// has passed. Returns whether an ack was queued.
    pub(crate) fn reack_if_due(
        &self,
        tx: &Transaction<'_>,
        env: &Envelope,
        last: Option<i64>,
        now: i64,
        digest: &[u8; 32],
    ) -> Result<bool, StoreError> {
        // Review finding M3: only a copy that is byte-identical to the first one
        // seen is a sender retry (the sender re-publishes the stored frame). A
        // byte-different copy (an extra PKESK, ...) is what a relay participant
        // can make from a captured frame to watch for the ack. It is not re-acked
        // while the first ack is still stored. Trade-off: after a key update the
        // sender re-seals (new bytes) and its retry is not re-acked until the
        // stored ack has been pruned; the sender retries until the message expires.
        let stored: Option<Vec<u8>> = tx
            .query_row(
                "SELECT frame_digest FROM seen WHERE sender = ?1 AND message_id = ?2",
                params![env.sender.to_string(), env.message_id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let identical = stored.as_deref().is_none_or(|d| d == digest.as_slice());
        if !identical {
            let ack_stored = tx
                .query_row(
                    "SELECT 1 FROM outbox WHERE is_ack = 1 AND recipient = ?1 AND correlation_id = ?2",
                    params![env.sender.to_string(), env.message_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if ack_stored {
                self.metrics.inc("ack.reack_suppressed_mutated");
                return Ok(false);
            }
        }
        let min = i64::try_from(
            self.config
                .delivery
                .reack_min_interval_s
                .saturating_mul(1000),
        )
        .unwrap_or(i64::MAX);
        if last.is_none_or(|l| now.saturating_sub(l) >= min) {
            if self.queue_ack_delayed(tx, env, now, self.reack_delay_ms())? {
                tx.execute(
                    "UPDATE seen SET last_reack_at = ?3 WHERE sender = ?1 AND message_id = ?2",
                    params![env.sender.to_string(), env.message_id, now],
                )?;
                return Ok(true);
            }
        } else {
            self.metrics.inc("ack.reack_rate_limited");
        }
        Ok(false)
    }

    /// Seal an `ack.received` for `orig` and insert it into the outbox. Needs the
    /// sender's contact record; without one (accept-policy unknown sender) no
    /// ack is possible and `false` is returned.
    pub(crate) fn queue_ack(
        &self,
        tx: &Transaction<'_>,
        orig: &Envelope,
        now: i64,
    ) -> Result<bool, StoreError> {
        self.queue_ack_delayed(tx, orig, now, 0)
    }

    /// A random delay in `1..=REACK_DELAY_MAX_MS` for re-acks, so the time of a
    /// re-ack does not follow the triggering frame exactly (review finding M3).
    pub(crate) fn reack_delay_ms(&self) -> i64 {
        let r = {
            let mut g = self.rng.lock().unwrap_or_else(|e| e.into_inner());
            crate::node::splitmix(&mut g)
        };
        1 + i64::try_from(r % REACK_DELAY_MAX_MS as u64).unwrap_or(0)
    }

    /// [`Self::queue_ack`] with the first attempt delayed by `delay_ms`.
    pub(crate) fn queue_ack_delayed(
        &self,
        tx: &Transaction<'_>,
        orig: &Envelope,
        now: i64,
        delay_ms: i64,
    ) -> Result<bool, StoreError> {
        if self.local_revocation.is_some() {
            // A revoked identity sends nothing except its tombstone.
            self.metrics.inc("ack.suppressed_revoked");
            return Ok(false);
        }
        let Some(row) = self.load_contact(tx, &orig.sender)? else {
            self.metrics.inc("ack.no_contact");
            return Ok(false);
        };
        let default_ttl = i64::try_from(self.config.delivery.default_ttl_s.saturating_mul(1000))
            .unwrap_or(i64::MAX);
        let ttl = orig.expires_at.saturating_sub(now).min(default_ttl);
        if ttl <= 0 {
            return Ok(false);
        }
        let Ok(mut env) = Envelope::new(
            self.own,
            orig.sender,
            MESSAGE_TYPE_ACK_RECEIVED,
            String::new(),
            now,
            ttl,
        ) else {
            return Err(StoreError::Corrupt("random number generator failed"));
        };
        env.conversation_id = orig.conversation_id.clone();
        env.correlation_id = Some(orig.message_id.clone());
        let frame =
            match self
                .protection
                .seal(&self.identity, &row.contact, &env, now, self.max_frame_len)
            {
                Ok(f) => f,
                Err(_) => {
                    self.metrics.inc("ack.seal_failed");
                    return Ok(false);
                }
            };
        self.insert_outbox_row(
            tx,
            &OutboxInsert {
                env: &env,
                topic: &row.contact.inbox_topic().to_string(),
                frame: &frame,
                is_ack: true,
                hidden: false,
                idempotency_key: None,
                delay_ms,
            },
            now,
        )?;
        self.metrics.inc("ack.queued");
        Ok(true)
    }

    fn ingest_ack(&self, frame: &InboundFrame, env: &Envelope, trust: Trust) -> FrameOutcome {
        if trust != Trust::Trusted {
            self.metrics.inc("ack.ignored_untrusted");
            self.mark_transport_seen(frame);
            return FrameOutcome::AckIgnored;
        }
        let now = self.now();
        let sender = env.sender.to_string();
        let res = self.store.tx(|tx| {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO seen (sender, message_id, expires_at) VALUES (?1, ?2, ?3)",
                params![sender, env.message_id, env.expires_at],
            )?;
            if inserted == 0 {
                return Ok(AckTx::Ignored("duplicate"));
            }
            guard::bump_generation(tx)?;
            let Some(corr) = env.correlation_id.as_deref() else {
                return Ok(AckTx::Ignored("no_correlation"));
            };
            let row: Option<(String, i64, String, Option<String>)> = tx
                .query_row(
                    "SELECT recipient, is_ack, state, conversation_id FROM outbox WHERE message_id = ?1",
                    [corr],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let Some((recipient, is_ack, state, conv)) = row else {
                return Ok(AckTx::Ignored("unknown_id"));
            };
            if is_ack != 0 {
                return Ok(AckTx::Ignored("ack_for_ack"));
            }
            if recipient != sender {
                return Ok(AckTx::Ignored("wrong_party"));
            }
            if state == "delivered" {
                return Ok(AckTx::Ignored("already_delivered"));
            }
            // A late ack after `expired` (or even `failed`) still proves delivery.
            tx.execute(
                "UPDATE outbox SET state='delivered', delivered_at=?2, next_attempt_at=NULL
                 WHERE message_id=?1",
                params![corr, now],
            )?;
            Ok(AckTx::Applied { conversation_id: conv })
        });
        if res.is_ok() {
            self.publish_generation();
        }
        match res {
            Err(_) => self.store_failure(),
            Ok(AckTx::Ignored(why)) => {
                self.metrics.inc(&format!("ack.ignored_{why}"));
                self.mark_transport_seen(frame);
                FrameOutcome::AckIgnored
            }
            Ok(AckTx::Applied { conversation_id }) => {
                self.metrics.inc("ack.applied");
                self.mark_transport_seen(frame);
                self.hint(ChangeHint::Outbox);
                if let Some(c) = conversation_id {
                    self.hint(ChangeHint::Conversation { conversation_id: c });
                }
                FrameOutcome::AckApplied
            }
        }
    }
}
