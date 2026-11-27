//! Optional capability discovery (see `docs/discovery.md`).
//!
//! * Off by default (`[discovery] enabled = false`): nothing is subscribed or
//!   published and the three API methods return `policy_denied`.
//! * Own advertisement: one signed, expiring record per authorised topic, kept in
//!   `kv` (`advert.<topic>`) together with its sequence number; re-published
//!   every `republish_interval_s` until it expires or is withdrawn, re-issued
//!   (new sequence number) when the KEM key was rotated, never published by a
//!   revoked identity.
//! * Received advertisements: verified, sequence-ordered, capped and stored in
//!   the `adverts` table. Receiving one never creates a contact, changes trust,
//!   matches a trigger or emits a host event.

use agentnet_transport::InboundFrame;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::api::{
    AdvertInfo, AdvertiseRequest, ApiError, ApiResult, DiscoverPage, DiscoverRequest,
    DiscoveredAgent, ErrorCode, Trust, WithdrawInfo,
};
use crate::config::valid_discovery_topic_name;
use crate::crypto::advert::{
    check_capabilities, decode_frame, encode_frame, error_kind, has_sealed_magic,
    valid_capability_name, AdvertContent, Capability, SignedAdvert, VerifiedAdvert,
};
use crate::crypto::Address;
use crate::cursor::{decode_seq, encode_seq, CursorKind};
use crate::error::AdvertError;
use crate::ingest::FrameOutcome;
use crate::node::{Node, NodeError};
use crate::store::{kv_get, kv_set, StoreError};
use crate::triggers::clamp_limit;

/// Delay before a failed publish is retried (bounded by the republish interval).
const PUBLISH_RETRY_MS: i64 = 30_000;

/// The local identity's own advertisement state for one topic.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct OwnAdvert {
    /// Highest sequence number ever signed for this topic (never decreases).
    seq: u64,
    /// The signed document currently in force (an advertisement or, once
    /// `withdrawn`, the withdrawal).
    document: String,
    withdrawn: bool,
    capabilities: Vec<Capability>,
    display_name: Option<String>,
    issued_at: i64,
    expires_at: i64,
    /// Identifier of the certificate embedded in `document` (see `Node::cert_id`).
    #[serde(default)]
    cert_id: u64,
    /// When the document is due for (re-)publication; `None` = nothing to publish.
    next_publish_at: Option<i64>,
}

fn own_key(name: &str) -> String {
    format!("advert.{name}")
}

fn load_own(conn: &Connection, name: &str) -> Result<Option<OwnAdvert>, StoreError> {
    match kv_get(conn, &own_key(name))? {
        None => Ok(None),
        Some(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|_| StoreError::Corrupt("stored own advertisement")),
    }
}

fn save_own(conn: &Connection, name: &str, st: &OwnAdvert) -> Result<(), StoreError> {
    let s = serde_json::to_string(st).map_err(|_| StoreError::Corrupt("own advertisement"))?;
    kv_set(conn, &own_key(name), &s)
}

fn advert_api_err(e: AdvertError) -> ApiError {
    match e {
        AdvertError::TooLarge => ApiError::new(
            ErrorCode::TooLarge,
            "the advertisement is too large (at most 8 KiB); use fewer or shorter capabilities",
        ),
        other => ApiError::invalid(other.to_string()),
    }
}

fn ms(seconds: u64) -> i64 {
    i64::try_from(seconds.saturating_mul(1000)).unwrap_or(i64::MAX)
}

impl Node {
    /// The discovery topic name of a content topic, if it is an authorised one.
    pub(crate) fn discovery_name(
        &self,
        topic: &agentnet_transport::ContentTopic,
    ) -> Option<String> {
        self.disc_topics
            .iter()
            .find(|(_, t)| t == topic)
            .map(|(n, _)| n.clone())
    }

    /// Host policy gate shared by the three API methods.
    fn require_discovery(&self, topic: &str) -> ApiResult<()> {
        let c = &self.config.discovery;
        if !c.enabled {
            return Err(ApiError::policy(
                "discovery is disabled by host policy ([discovery] enabled = false in agentnet.toml)",
            ));
        }
        if !valid_discovery_topic_name(topic) {
            return Err(ApiError::invalid(
                "topic must be 1 to 32 characters from a-z 0-9 -",
            ));
        }
        if !c.topics.iter().any(|t| t == topic) {
            return Err(ApiError::policy(format!(
                "topic {topic:?} is not an authorized discovery topic (host policy: discovery.topics)"
            )));
        }
        Ok(())
    }

    fn sign_own(
        &self,
        topic: &str,
        capabilities: &[Capability],
        display_name: Option<&str>,
        issued_at: i64,
        expires_at: i64,
        seq: u64,
    ) -> ApiResult<SignedAdvert> {
        self.identity
            .create_advert(
                &AdvertContent {
                    topic,
                    capabilities,
                    display_name,
                    issued_at,
                    expires_at,
                    seq,
                },
                &self.advert_limits,
            )
            .map_err(advert_api_err)
    }

    /// Latest allowed expiry given the agreement key's own expiry: the embedded
    /// contact record stops verifying when the KEM key expires.
    fn clamp_to_kem(&self, expires_at: i64) -> i64 {
        match self.identity.kem_expires_at() {
            Some(k) => expires_at.min(k),
            None => expires_at,
        }
    }

    // ------------------------------------------------------------ own advert

    pub(crate) fn advertise_impl(&self, req: AdvertiseRequest) -> ApiResult<AdvertInfo> {
        self.require_discovery(&req.topic)?;
        if self.local_revocation.is_some() {
            return Err(ApiError::policy(
                "this identity has been revoked; it publishes nothing",
            ));
        }
        if req.capabilities.is_empty() {
            return Err(ApiError::invalid(
                "capabilities must list at least one capability (use withdraw_advert to stop advertising)",
            ));
        }
        let dc = &self.config.discovery;
        check_capabilities(&req.capabilities, dc.max_capabilities).map_err(advert_api_err)?;
        let ttl_s = match req.ttl_seconds {
            Some(0) => return Err(ApiError::invalid("ttl_seconds must be greater than zero")),
            Some(t) => t.min(dc.max_advert_ttl_s),
            None => dc.default_advert_ttl_s,
        };
        let now = self.now();
        let expires_at = self.clamp_to_kem(now.saturating_add(ms(ttl_s)));
        if expires_at <= now {
            return Err(ApiError::invalid(
                "this agent's encryption key has expired; rotate it before advertising",
            ));
        }
        let topic = self
            .disc_topics
            .iter()
            .find(|(n, _)| *n == req.topic)
            .map(|(_, t)| t.clone())
            .ok_or_else(|| ApiError::internal("discovery topic is not configured"))?;
        let info = self
            .store
            .tx(|tx| {
                let prev = load_own(tx, &req.topic)?;
                let seq = match &prev {
                    Some(p) => p
                        .seq
                        .checked_add(1)
                        .ok_or_else(|| ApiError::internal("sequence number exhausted"))?,
                    None => 1,
                };
                let signed = self.sign_own(
                    &req.topic,
                    &req.capabilities,
                    req.display_name.as_deref(),
                    now,
                    expires_at,
                    seq,
                )?;
                let document = signed.to_document();
                if document.len() + crate::crypto::advert::ADVERT_FRAME_HEADER_LEN
                    > self.transport.max_payload_len(&topic)
                {
                    return Err(ApiError::new(
                        ErrorCode::TooLarge,
                        "the advertisement does not fit in one transport frame",
                    )
                    .into());
                }
                save_own(
                    tx,
                    &req.topic,
                    &OwnAdvert {
                        seq,
                        document,
                        withdrawn: false,
                        capabilities: req.capabilities.clone(),
                        display_name: req.display_name.clone(),
                        issued_at: now,
                        expires_at,
                        cert_id: self.cert_id(),
                        next_publish_at: Some(now),
                    },
                )?;
                Ok(AdvertInfo {
                    topic: req.topic.clone(),
                    seq,
                    issued_at: now,
                    expires_at,
                    capabilities: req.capabilities.clone(),
                })
            })
            .map_err(|e| e.to_api())?;
        self.metrics.inc("advert.issued");
        self.send_nudge.notify_one();
        Ok(info)
    }

    pub(crate) fn withdraw_impl(&self, topic: String) -> ApiResult<WithdrawInfo> {
        self.require_discovery(&topic)?;
        if self.local_revocation.is_some() {
            return Err(ApiError::policy(
                "this identity has been revoked; it publishes nothing",
            ));
        }
        let now = self.now();
        let max_ttl = self.advert_limits.max_ttl_ms;
        let withdrawn = self
            .store
            .tx(|tx| {
                let Some(mut st) = load_own(tx, &topic)? else {
                    return Ok(false);
                };
                if st.withdrawn {
                    return Ok(false);
                }
                if st.expires_at <= now {
                    // Expired by itself: nothing in force, nothing to tell anyone.
                    st.withdrawn = true;
                    st.next_publish_at = None;
                    save_own(tx, &topic, &st)?;
                    return Ok(false);
                }
                let seq = st
                    .seq
                    .checked_add(1)
                    .ok_or_else(|| ApiError::internal("sequence number exhausted"))?;
                // The tombstone must outlive the advertisement it replaces so that a
                // replay of the old one is ignored by everyone who saw the withdrawal.
                let expires_at = self
                    .clamp_to_kem(st.expires_at.min(now.saturating_add(max_ttl)))
                    .max(now.saturating_add(1));
                let signed = self.sign_own(&topic, &[], None, now, expires_at, seq)?;
                st.seq = seq;
                st.document = signed.to_document();
                st.withdrawn = true;
                st.capabilities = Vec::new();
                st.issued_at = now;
                st.expires_at = expires_at;
                st.cert_id = self.cert_id();
                st.next_publish_at = Some(now);
                save_own(tx, &topic, &st)?;
                Ok(true)
            })
            .map_err(|e| e.to_api())?;
        if withdrawn {
            self.metrics.inc("advert.withdrawn");
            self.send_nudge.notify_one();
        }
        Ok(WithdrawInfo { topic, withdrawn })
    }

    /// Publish every own advertisement (or withdrawal) that is due. Returns the
    /// number of frames the transport accepted. Does nothing when discovery is
    /// disabled or the local identity is revoked.
    pub async fn step_adverts(&self) -> Result<usize, NodeError> {
        if self.disc_topics.is_empty() || self.local_revocation.is_some() {
            return Ok(0);
        }
        let interval = ms(self.config.discovery.republish_interval_s);
        let mut published = 0;
        for (name, topic) in &self.disc_topics {
            let Some(st) = self.store.read(|c| load_own(c, name))? else {
                continue;
            };
            let now = self.now();
            if !matches!(st.next_publish_at, Some(t) if now >= t) {
                continue;
            }
            let next = if now >= st.expires_at {
                None
            } else {
                match self
                    .transport
                    .publish(topic, &encode_frame(&st.document))
                    .await
                {
                    Ok(_) => {
                        published += 1;
                        self.metrics.inc("advert.published");
                        if st.withdrawn {
                            None
                        } else {
                            Some(now.saturating_add(interval))
                        }
                    }
                    Err(e) => {
                        self.metrics.inc("advert.publish_error");
                        let retry = Some(now.saturating_add(PUBLISH_RETRY_MS.min(interval)));
                        if matches!(e, agentnet_transport::TransportError::Isolation(_)) {
                            self.finish_publish(name, st.seq, retry)?;
                            break;
                        }
                        retry
                    }
                }
            };
            self.finish_publish(name, st.seq, next)?;
        }
        Ok(published)
    }

    /// Record the next publish time unless a newer advertisement replaced the one
    /// that was just published.
    fn finish_publish(&self, name: &str, seq: u64, next: Option<i64>) -> Result<(), NodeError> {
        self.store.tx(|tx| {
            if let Some(mut st) = load_own(tx, name)? {
                if st.seq == seq {
                    st.next_publish_at = next;
                    save_own(tx, name, &st)?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }

    /// At start: re-issue every live own advertisement whose embedded contact
    /// record is stale because the KEM key was rotated while the daemon was
    /// stopped (new sequence number, same capabilities and expiry).
    pub(crate) fn reissue_own_adverts(&self, now: i64) -> Result<(), NodeError> {
        if self.disc_topics.is_empty() || self.local_revocation.is_some() {
            return Ok(());
        }
        let epoch = self.cert_id();
        let n = self.store.tx(|tx| {
            let mut n = 0usize;
            for (name, _) in &self.disc_topics {
                let Some(mut st) = load_own(tx, name)? else {
                    continue;
                };
                if st.withdrawn || st.expires_at <= now || st.cert_id == epoch {
                    continue;
                }
                let seq = st
                    .seq
                    .checked_add(1)
                    .ok_or(StoreError::Corrupt("sequence number exhausted"))?;
                let expires_at = self.clamp_to_kem(st.expires_at);
                if expires_at <= now {
                    continue;
                }
                let signed = self
                    .sign_own(
                        name,
                        &st.capabilities,
                        st.display_name.as_deref(),
                        now,
                        expires_at,
                        seq,
                    )
                    .map_err(StoreError::Api)?;
                st.seq = seq;
                st.document = signed.to_document();
                st.issued_at = now;
                st.expires_at = expires_at;
                st.cert_id = epoch;
                st.next_publish_at = Some(now);
                save_own(tx, name, &st)?;
                n += 1;
            }
            Ok(n)
        })?;
        if n > 0 {
            self.metrics.add("advert.reissued", n as u64);
            self.send_nudge.notify_one();
        }
        Ok(())
    }

    // ---------------------------------------------------------- received ones

    /// Process one frame received on a discovery topic.
    pub(crate) fn ingest_advert_frame(&self, frame: &InboundFrame, name: &str) -> FrameOutcome {
        self.metrics.inc("advert.received");
        if has_sealed_magic(&frame.payload) {
            self.metrics.inc("advert.cross_topic.sealed_on_discovery");
            self.mark_transport_seen(frame);
            return FrameOutcome::Dropped;
        }
        let now = self.now();
        let verified = decode_frame(&frame.payload)
            .and_then(|doc| VerifiedAdvert::parse_and_verify(doc, name, now, &self.advert_limits));
        let v = match verified {
            Ok(v) => v,
            Err(AdvertError::FromFuture) => {
                // Not marked seen: it may be valid once our clock catches up.
                self.metrics.inc("advert.invalid.from_future");
                return FrameOutcome::Deferred;
            }
            Err(AdvertError::Expired) => {
                self.metrics.inc("advert.ignored_expired");
                self.mark_transport_seen(frame);
                return FrameOutcome::AdvertIgnored;
            }
            Err(e) => {
                self.metrics
                    .inc(&format!("advert.invalid.{}", error_kind(&e)));
                self.mark_transport_seen(frame);
                return FrameOutcome::AdvertInvalid;
            }
        };
        if v.address == self.own {
            // Our own publication coming back (we subscribe to the topic too).
            self.metrics.inc("advert.ignored_own");
            self.mark_transport_seen(frame);
            return FrameOutcome::AdvertIgnored;
        }
        let res = self.store.tx(|tx| self.store_advert(tx, name, &v, now));
        let outcome = match res {
            Ok(o) => o,
            Err(_) => return self.store_failure(),
        };
        self.mark_transport_seen(frame);
        match outcome {
            Stored::Applied {
                replaced,
                withdrawal,
            } => {
                self.metrics.inc("advert.applied");
                if replaced {
                    self.metrics.inc("advert.replaced");
                }
                if withdrawal {
                    self.metrics.inc("advert.withdrawal_applied");
                }
                FrameOutcome::AdvertApplied
            }
            Stored::Stale => {
                self.metrics.inc("advert.ignored_stale");
                FrameOutcome::AdvertIgnored
            }
            Stored::Blocked => {
                self.metrics.inc("advert.dropped_blocked");
                FrameOutcome::Dropped
            }
            Stored::Full => {
                self.metrics.inc("advert.dropped_full");
                FrameOutcome::Dropped
            }
        }
    }

    fn store_advert(
        &self,
        tx: &Transaction<'_>,
        topic: &str,
        v: &VerifiedAdvert,
        now: i64,
    ) -> Result<Stored, StoreError> {
        // Blocked contacts and revoked identities are never stored and never
        // cause an eviction.
        let blocked = Self::is_revoked(tx, &v.address)?
            || self
                .load_contact(tx, &v.address)?
                .is_some_and(|r| r.trust == Trust::Blocked);
        if blocked {
            return Ok(Stored::Blocked);
        }
        let addr = v.address.to_string();
        tx.execute("DELETE FROM adverts WHERE expires_at <= ?1", [now])?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT seq FROM adverts WHERE topic = ?1 AND address = ?2",
                params![topic, addr],
                |r| r.get(0),
            )
            .optional()?;
        // `seq` is validated to fit an i64.
        let seq = i64::try_from(v.seq).map_err(|_| StoreError::Corrupt("advert seq"))?;
        if let Some(old) = existing {
            if old >= seq {
                return Ok(Stored::Stale);
            }
        } else {
            let n: i64 = tx.query_row("SELECT COUNT(*) FROM adverts", [], |r| r.get(0))?;
            if u64::try_from(n).unwrap_or(u64::MAX) >= self.config.discovery.max_records {
                // Evict the soonest-expiring record, unless the newcomer would
                // expire even sooner (then the newcomer is the one dropped).
                let victim: Option<(i64, i64)> = tx
                    .query_row(
                        "SELECT rid, expires_at FROM adverts ORDER BY expires_at, rid LIMIT 1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                match victim {
                    Some((rid, exp)) if exp <= v.expires_at => {
                        tx.execute("DELETE FROM adverts WHERE rid = ?1", [rid])?;
                        self.metrics.inc("advert.evicted");
                    }
                    _ => return Ok(Stored::Full),
                }
            }
        }
        // The old row (if any) goes first so the replacement gets a new, later
        // row id: paging clients see updated records again.
        tx.execute(
            "DELETE FROM adverts WHERE topic = ?1 AND address = ?2",
            params![topic, addr],
        )?;
        let caps = serde_json::to_string(&v.capabilities)
            .map_err(|_| StoreError::Corrupt("advert capabilities"))?;
        let cap_names = if v.capabilities.is_empty() {
            String::new()
        } else {
            format!(
                ",{},",
                v.capabilities
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        tx.execute(
            "INSERT INTO adverts (topic, address, document, contact_record, display_name,
                                  capabilities, cap_names, seq, issued_at, expires_at,
                                  kem_expires_at, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                topic,
                addr,
                v.document(),
                v.contact_record(),
                v.display_name,
                caps,
                cap_names,
                seq,
                v.issued_at,
                v.expires_at,
                v.contact.kem_expires_at,
                now
            ],
        )?;
        Ok(Stored::Applied {
            replaced: existing.is_some(),
            withdrawal: v.is_withdrawal(),
        })
    }

    /// Remove every stored advertisement of `addr` (blocked or revoked).
    pub(crate) fn purge_adverts(tx: &Transaction<'_>, addr: &Address) -> Result<usize, StoreError> {
        Ok(tx.execute("DELETE FROM adverts WHERE address = ?1", [addr.to_string()])?)
    }

    /// Maintenance: drop expired records (replaying an expired advertisement is
    /// rejected by its own expiry, so removal is replay-safe) and enforce
    /// `max_records` after a configuration change.
    pub(crate) fn prune_adverts(
        &self,
        tx: &Transaction<'_>,
        now: i64,
    ) -> Result<usize, StoreError> {
        let mut n = tx.execute("DELETE FROM adverts WHERE expires_at <= ?1", [now])?;
        n += tx.execute(
            "DELETE FROM adverts WHERE rid NOT IN
               (SELECT rid FROM adverts ORDER BY expires_at DESC, rid DESC LIMIT ?1)",
            [i64::try_from(self.config.discovery.max_records).unwrap_or(i64::MAX)],
        )?;
        Ok(n)
    }

    // ------------------------------------------------------------- discovery

    pub(crate) fn discover_impl(&self, req: DiscoverRequest) -> ApiResult<DiscoverPage> {
        self.require_discovery(&req.topic)?;
        if let Some(c) = &req.capability {
            if !valid_capability_name(c) {
                return Err(ApiError::invalid("capability must match [a-z0-9._-]{1,64}"));
            }
        }
        let after = match &req.cursor {
            Some(c) => decode_seq(CursorKind::Advert, c)?,
            None => 0,
        };
        let limit = clamp_limit(req.limit);
        let now = self.now();
        self.store
            .read(|c| {
                let mut st = c.prepare(
                    "SELECT rid, address, display_name, capabilities, contact_record, issued_at,
                            expires_at
                     FROM adverts
                     WHERE topic = ?1 AND rid > ?2 AND expires_at > ?3 AND cap_names <> ''
                       AND (kem_expires_at IS NULL OR kem_expires_at > ?3)
                       AND (?4 IS NULL OR instr(cap_names, ',' || ?4 || ',') > 0)
                       AND address NOT IN (SELECT address FROM contacts WHERE trust = 'blocked')
                       AND address NOT IN (SELECT address FROM revocations)
                     ORDER BY rid LIMIT ?5",
                )?;
                type Row = (i64, String, Option<String>, String, String, i64, i64);
                let rows: Vec<Row> = st
                    .query_map(
                        params![
                            req.topic,
                            after,
                            now,
                            req.capability,
                            i64::try_from(limit + 1).unwrap_or(i64::MAX)
                        ],
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
                    )?
                    .collect::<Result<_, _>>()?;
                let has_more = rows.len() > limit;
                let mut agents = Vec::new();
                let mut last_rid = None;
                for (rid, address, display_name, caps, contact_record, issued_at, expires_at) in
                    rows.into_iter().take(limit)
                {
                    last_rid = Some(rid);
                    let capabilities: Vec<Capability> = serde_json::from_str(&caps)
                        .map_err(|_| StoreError::Corrupt("stored advert capabilities"))?;
                    let addr: Address = address
                        .parse()
                        .map_err(|_| StoreError::Corrupt("stored advert address"))?;
                    let (is_contact, trust) = match self.load_contact(c, &addr)? {
                        Some(row) => (true, row.trust),
                        None => (false, Trust::Unknown),
                    };
                    agents.push(DiscoveredAgent {
                        address,
                        display_name,
                        capabilities,
                        contact_record,
                        issued_at,
                        expires_at,
                        is_contact,
                        trust,
                    });
                }
                let next_cursor = Some(match last_rid {
                    Some(rid) => encode_seq(CursorKind::Advert, rid),
                    None => req
                        .cursor
                        .clone()
                        .unwrap_or_else(|| encode_seq(CursorKind::Advert, 0)),
                });
                Ok(DiscoverPage {
                    agents,
                    next_cursor,
                    has_more,
                })
            })
            .map_err(|e| e.to_api())
    }
}

enum Stored {
    Applied { replaced: bool, withdrawal: bool },
    Stale,
    Blocked,
    Full,
}
