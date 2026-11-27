//! The durable engine. See the module docs of [`crate`] and `docs/protocol.md`
//! ("Delivery, retries and receipts").
//!
//! Layout: this file holds the struct, construction, the deterministic step
//! functions and `run`. Inbound processing is in `ingest`, the outbound path in
//! `send`, triggers/events in `triggers`, and the `AgentApi` implementation in
//! `api_impl`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentnet_transport::{ContentTopic, HistoryQuery, InboundFrame, Transport, TransportError};
use rusqlite::OptionalExtension;
use tokio::sync::{broadcast, mpsc, watch, Notify};
use tokio_util::sync::CancellationToken;

use crate::api::{ApiError, ChangeHint, DeliveryState, Trust};
use crate::clock::Clock;
use crate::config::NodeConfig;
use crate::crypto::advert::AdvertLimits;
use crate::crypto::envelope::OpenLimits;
use crate::crypto::{
    default_protection, Address, Identity, MessageProtection, VerifiedContact, VerifiedRevocation,
};
use crate::guard::{self, GuardState, Sidecar, SidecarState};
use crate::metrics::{Metrics, NodeMetrics};
use crate::store::{kv_get, kv_set, Store, StoreError};

const KV_OWN_ADDRESS: &str = "own_address";
pub(crate) const KV_ANNOUNCED_CERT: &str = "announced_cert_id";
pub(crate) const KV_ANNOUNCED_REVOCATION: &str = "announced_revocation";
pub(crate) const KV_LOCAL_REVOCATION: &str = "local_revocation";
pub(crate) const KV_HISTORY_WATERMARK: &str = "history_watermark_ms";
pub(crate) const KV_EVENTS_ACK: &str = "events_ack_seq";
const HISTORY_PAGE_LIMIT: u32 = 100;
const MAX_HISTORY_PAGES: usize = 100_000;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);
const TRANSPORT_SEEN_CAP: i64 = 200_000;
const MAX_LAST_ERROR_LEN: usize = 120;

/// Errors from constructing or stepping a [`Node`].
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    Config(String),
    /// The store failed.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// The data directory belongs to a different identity.
    #[error(
        "this store was created by identity {stored} but the supplied identity is {given}; \
         refusing to run (wrong identity file, or the identity was lost and regenerated)"
    )]
    IdentityMismatch {
        /// Address recorded in the store.
        stored: String,
        /// Address of the supplied identity.
        given: String,
    },
    /// The transport failed.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

/// Result of one [`Node::step_receive`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiveReport {
    /// Frames returned by the transport.
    pub polled: usize,
    /// Frames that were processed (all of them unless a store failure occurred).
    pub processed: usize,
    /// Frames whose processing failed on a store error.
    pub store_failures: usize,
}

/// Result of one [`Node::step_send`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendReport {
    /// Frames the transport accepted.
    pub published: usize,
    /// Publish attempts that failed (retryable or permanent).
    pub failed: usize,
    /// Rows moved to `expired`.
    pub expired: usize,
    /// The step stopped early because the transport is unavailable/isolated.
    pub deferred: bool,
}

/// Result of one [`Node::step_history_sync`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryReport {
    /// True when the pass finished and the watermark was advanced.
    pub completed: bool,
    /// Frames returned by history (including repeats).
    pub frames: usize,
    /// Why the pass did not complete (sanitized).
    pub error: Option<String>,
}

/// Result of one [`Node::step_maintenance`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    /// Outbox rows moved to `expired`.
    pub outbox_expired: usize,
    /// Triggers moved to `expired`.
    pub triggers_expired: usize,
    /// Rows deleted across all pruned tables.
    pub pruned_rows: usize,
}

/// Optional construction parameters of a [`Node`].
#[derive(Clone, Default)]
pub struct NodeOptions {
    /// The message-protection scheme (default: [`default_protection`], RFC 9580 OpenPGP).
    pub protection: Option<Arc<dyn MessageProtection>>,
    /// The local identity's signed revocation tombstone, if it was revoked
    /// (the daemon reads it from the data directory). A revoked identity sends
    /// nothing except its own tombstone.
    pub local_revocation: Option<String>,
    /// Override of the generation sidecar path (default: next to the store).
    pub generation_sidecar: Option<PathBuf>,
}

/// The agent engine. Create with [`Node::open`].
pub struct Node {
    pub(crate) identity: Identity,
    pub(crate) protection: Arc<dyn MessageProtection>,
    pub(crate) local_revocation: Option<VerifiedRevocation>,
    pub(crate) guard: Mutex<Option<GuardState>>,
    pub(crate) sidecar_path: PathBuf,
    pub(crate) published_generation: AtomicU64,
    /// Serializes read-compare-write of the generation sidecar.
    pub(crate) sidecar_lock: std::sync::Mutex<()>,
    pub(crate) own: Address,
    pub(crate) own_str: String,
    pub(crate) topic: ContentTopic,
    pub(crate) store: Store,
    pub(crate) transport: Arc<dyn Transport>,
    pub(crate) config: NodeConfig,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) rng: Mutex<u64>,
    pub(crate) changes: broadcast::Sender<ChangeHint>,
    pub(crate) metrics: Metrics,
    pub(crate) send_nudge: Notify,
    pub(crate) history_kick: Notify,
    pub(crate) max_frame_len: usize,
    pub(crate) open_limits: OpenLimits,
    /// Authorised discovery topics (name, content topic); empty unless
    /// `discovery.enabled`.
    pub(crate) disc_topics: Vec<(String, ContentTopic)>,
    pub(crate) advert_limits: AdvertLimits,
    disc_subscribed: Mutex<HashSet<ContentTopic>>,
    subscribed: AtomicBool,
    last_live_poll_at: AtomicI64,
    transport_was_ok: AtomicBool,
    history_needed: AtomicBool,
    pause: watch::Sender<bool>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("address", &self.own_str)
            .finish_non_exhaustive()
    }
}

pub(crate) fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Truncate and strip control characters so an error string is safe to store.
pub(crate) fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_LAST_ERROR_LEN)
        .collect()
}

pub(crate) fn trust_to_db(t: Trust) -> &'static str {
    match t {
        Trust::Trusted => "trusted",
        Trust::Untrusted => "untrusted",
        Trust::Blocked => "blocked",
        Trust::Unknown => "unknown",
    }
}

pub(crate) fn trust_from_db(s: &str) -> Trust {
    match s {
        "trusted" => Trust::Trusted,
        "blocked" => Trust::Blocked,
        "untrusted" => Trust::Untrusted,
        _ => Trust::Unknown,
    }
}

pub(crate) fn state_from_db(s: &str) -> DeliveryState {
    match s {
        "sent" => DeliveryState::Sent,
        "delivered" => DeliveryState::Delivered,
        "failed" => DeliveryState::Failed,
        "expired" => DeliveryState::Expired,
        _ => DeliveryState::Queued,
    }
}

/// A stored contact.
pub(crate) struct ContactRow {
    pub contact: VerifiedContact,
    pub trust: Trust,
    pub alias: Option<String>,
    pub added_at: i64,
    /// The address has a verified identity-revocation tombstone; `trust` is
    /// reported as `Blocked` and cannot be changed.
    pub revoked: bool,
}

impl Node {
    /// Open the engine on the store at `store_path`.
    ///
    /// The caller (the daemon) owns the data-directory lock and has loaded the
    /// identity file. Fails with [`NodeError::IdentityMismatch`] if the store
    /// was created by a different identity.
    pub fn open(
        identity: Identity,
        store_path: &Path,
        transport: Arc<dyn Transport>,
        config: NodeConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Arc<Self>, NodeError> {
        Self::open_with(
            identity,
            store_path,
            transport,
            config,
            clock,
            NodeOptions::default(),
        )
    }

    /// [`Node::open`] with explicit [`NodeOptions`].
    pub fn open_with(
        identity: Identity,
        store_path: &Path,
        transport: Arc<dyn Transport>,
        config: NodeConfig,
        clock: Arc<dyn Clock>,
        options: NodeOptions,
    ) -> Result<Arc<Self>, NodeError> {
        config.validate().map_err(NodeError::Config)?;
        let protection = options.protection.unwrap_or_else(default_protection);
        let now0 = clock.now_ms();
        let local_revocation = match &options.local_revocation {
            Some(doc) => {
                let r = VerifiedRevocation::parse_and_verify(doc, now0)
                    .map_err(|e| NodeError::Config(format!("local revocation: {e}")))?;
                if r.address != identity.address() {
                    return Err(NodeError::Config(
                        "local revocation names a different address".into(),
                    ));
                }
                Some(r)
            }
            None => None,
        };
        let store = Store::open(store_path)?;
        let own = identity.address();
        let own_str = own.to_string();
        let fresh = store
            .tx(|tx| match kv_get(tx, KV_OWN_ADDRESS)? {
                Some(stored) if stored != own_str => {
                    Err(StoreError::Api(ApiError::internal(stored)))
                }
                Some(_) => Ok(false),
                None => {
                    kv_set(tx, KV_OWN_ADDRESS, &own_str)?;
                    Ok(true)
                }
            })
            .map_err(|e| match e {
                StoreError::Api(a) => NodeError::IdentityMismatch {
                    stored: a.message,
                    given: own_str.clone(),
                },
                other => NodeError::Store(other),
            })?;
        let topic = identity.inbox_topic();
        let max_frame_len = transport.max_payload_len(&topic);
        let d = &config.delivery;
        let seed = match d.jitter_seed {
            Some(s) => s,
            None => {
                let mut b = [0u8; 8];
                let _ = getrandom::fill(&mut b);
                u64::from_le_bytes(b)
            }
        };
        let open_limits = OpenLimits {
            clock_skew_ms: i64::try_from(d.clock_skew_s.saturating_mul(1000)).unwrap_or(i64::MAX),
            max_ttl_ms: i64::try_from(d.max_ttl_s.saturating_mul(1000)).unwrap_or(i64::MAX),
            max_frame_len,
        };
        let dc = &config.discovery;
        let disc_topics: Vec<(String, ContentTopic)> = if dc.enabled {
            dc.topics
                .iter()
                .map(|n| {
                    ContentTopic::new(crate::config::discovery_content_topic(n))
                        .map(|t| (n.clone(), t))
                        .map_err(|e| NodeError::Config(e.to_string()))
                })
                .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };
        let advert_limits = AdvertLimits {
            max_ttl_ms: i64::try_from(dc.max_advert_ttl_s.saturating_mul(1000)).unwrap_or(i64::MAX),
            clock_skew_ms: open_limits.clock_skew_ms,
            max_capabilities: dc.max_capabilities,
        };
        let (changes, _) = broadcast::channel(256);
        let (pause, _) = watch::channel(false);
        let sidecar_path = options
            .generation_sidecar
            .unwrap_or_else(|| guard::sidecar_path(store_path));
        let guard_ttl = open_limits
            .max_ttl_ms
            .saturating_add(open_limits.clock_skew_ms);
        let (guard_state, generation) =
            Self::evaluate_guard(&store, &sidecar_path, fresh, now0, guard_ttl)?;
        let node = Arc::new(Self {
            protection,
            local_revocation,
            guard: Mutex::new(guard_state),
            sidecar_path,
            published_generation: AtomicU64::new(generation),
            sidecar_lock: std::sync::Mutex::new(()),
            identity,
            own,
            own_str,
            topic,
            store,
            transport,
            config,
            clock,
            rng: Mutex::new(seed),
            changes,
            metrics: Metrics::default(),
            send_nudge: Notify::new(),
            history_kick: Notify::new(),
            max_frame_len,
            open_limits,
            disc_topics,
            advert_limits,
            disc_subscribed: Mutex::new(HashSet::new()),
            subscribed: AtomicBool::new(false),
            last_live_poll_at: AtomicI64::new(0),
            transport_was_ok: AtomicBool::new(true),
            history_needed: AtomicBool::new(false),
            pause,
        });
        node.after_open()?;
        Ok(node)
    }

    /// Decide whether the replay guard must be active (see `guard.rs`),
    /// persist the decision and re-synchronise the sidecar. Returns the active
    /// guard and the current generation.
    fn evaluate_guard(
        store: &Store,
        sidecar_path: &Path,
        fresh: bool,
        now: i64,
        guard_ttl_ms: i64,
    ) -> Result<(Option<GuardState>, u64), NodeError> {
        let sidecar = guard::read_sidecar(sidecar_path);
        let (state, generation, sidecar_out) = store.tx(|tx| {
            let db_gen = guard::db_generation(tx)?;
            let clear = kv_get(tx, guard::KV_GUARD_CLEAR)?.is_some();
            let existing = guard::load_guard(tx)?;
            let mut reason: Option<&'static str> = None;
            match &sidecar {
                SidecarState::Present(s) => {
                    if s.guard.is_some() {
                        reason = Some(guard::REASON_IMPORTED);
                    } else if s.generation > db_gen {
                        reason = Some(guard::REASON_ROLLBACK);
                    }
                }
                SidecarState::Missing | SidecarState::Unreadable => {
                    if !fresh {
                        reason = Some(guard::REASON_UNKNOWN_HISTORY);
                    }
                }
            }
            let sc_gen = match &sidecar {
                SidecarState::Present(s) => s.generation,
                _ => 0,
            };
            let generation = db_gen.max(sc_gen);
            kv_set(tx, guard::KV_GENERATION, &generation.to_string())?;
            let state = if clear {
                guard::delete_guard(tx)?;
                None
            } else if let Some(g) = existing {
                Some(g)
            } else if let Some(r) = reason {
                let g = GuardState {
                    reason: r.to_owned(),
                    since: now,
                    until: now.saturating_add(guard_ttl_ms),
                };
                guard::save_guard(tx, &g)?;
                Some(g)
            } else {
                None
            };
            Ok((
                state,
                generation,
                Sidecar {
                    generation,
                    guard: None,
                },
            ))
        })?;
        if let Err(e) = guard::write_sidecar(sidecar_path, &sidecar_out) {
            tracing::warn!(error = %e, "could not write the store generation sidecar");
        }
        Ok((state, generation))
    }

    /// Work that needs the finished node: release messages held by an accepted
    /// guard, persist the local revocation, queue announcements.
    fn after_open(&self) -> Result<(), NodeError> {
        let now = self.now();
        if self.guard_state().is_none() {
            self.release_held(now)?;
        } else {
            self.metrics.inc("guard.active_at_start");
        }
        if let Some(r) = &self.local_revocation {
            self.store
                .tx(|tx| kv_set(tx, KV_LOCAL_REVOCATION, r.document()))?;
        }
        self.announce_changes(now)?;
        self.reissue_own_adverts(now)?;
        Ok(())
    }

    /// The active replay guard, lapsing it first if its time has passed.
    pub(crate) fn guard_state(&self) -> Option<GuardState> {
        let g = self
            .guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        if self.now() >= g.until {
            // All held messages are expired by now; this only cleans up.
            if self.clear_guard().is_ok() {
                return None;
            }
        }
        Some(g)
    }

    /// Drop the guard and release (or discard, when expired) held messages.
    pub(crate) fn clear_guard(&self) -> Result<(), StoreError> {
        self.store.tx(|tx| guard::delete_guard(tx))?;
        *self.guard.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.release_held(self.now())?;
        self.metrics.inc("guard.cleared");
        Ok(())
    }

    /// True when the local identity has been revoked.
    pub fn identity_revoked(&self) -> bool {
        self.local_revocation.is_some()
    }

    /// Publish the DB generation to the sidecar (after a commit that bumped it).
    ///
    /// The generation is read, compared and written under a lock: two threads
    /// calling this concurrently (library users driving one [`Node`] from several
    /// tasks) could otherwise write an older generation over a newer one.
    pub(crate) fn publish_generation(&self) {
        let _serialized = self
            .sidecar_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let g = match self.store.read(guard::db_generation) {
            Ok(g) => g,
            Err(_) => return,
        };
        if g <= self.published_generation.load(Ordering::SeqCst) {
            return;
        }
        match guard::write_sidecar(
            &self.sidecar_path,
            &Sidecar {
                generation: g,
                guard: None,
            },
        ) {
            Ok(()) => self.published_generation.store(g, Ordering::SeqCst),
            Err(_) => self.metrics.inc("guard.sidecar_error"),
        }
    }

    /// The agent's address string.
    pub fn address(&self) -> &str {
        &self.own_str
    }

    /// Snapshot of the counters.
    pub fn metrics(&self) -> NodeMetrics {
        self.metrics.snapshot()
    }

    pub(crate) fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    pub(crate) fn hint(&self, h: ChangeHint) {
        let _ = self.changes.send(h);
    }

    pub(crate) fn history_pending(&self) -> bool {
        self.history_needed.load(Ordering::SeqCst)
    }

    pub(crate) fn last_live_poll(&self) -> Option<i64> {
        match self.last_live_poll_at.load(Ordering::SeqCst) {
            0 => None,
            t => Some(t),
        }
    }

    /// Test hook: row count of one of the engine's tables.
    #[doc(hidden)]
    pub fn debug_table_count(&self, table: &str) -> u64 {
        const TABLES: [&str; 11] = [
            "revocations",
            "adverts",
            "contacts",
            "outbox",
            "inbox",
            "seen",
            "transport_seen",
            "triggers",
            "events",
            "kv",
            "sqlite_master",
        ];
        if !TABLES.contains(&table) {
            return 0;
        }
        self.store
            .read(|c| {
                let n: i64 =
                    c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
                Ok(u64::try_from(n).unwrap_or(0))
            })
            .unwrap_or(0)
    }

    /// Test hook: the stored history watermark (Unix ms).
    #[doc(hidden)]
    pub fn debug_history_watermark(&self) -> Option<i64> {
        self.store
            .read(|c| kv_get(c, KV_HISTORY_WATERMARK))
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
    }

    /// Test hook: make the next `n` store transactions fail (simulated disk error).
    #[doc(hidden)]
    pub fn inject_store_failures(&self, n: u32) {
        self.store.inject_failures(n);
    }

    /// Test hook: pause or resume the processing stage of [`Node::run`].
    #[doc(hidden)]
    pub fn set_processing_paused(&self, paused: bool) {
        self.pause.send_replace(paused);
    }

    /// Checkpoint and close the database. Later calls fail with `Unavailable`.
    pub fn close(&self) {
        self.store.close();
    }

    /// Equal-jitter exponential backoff after `n >= 1` completed attempts:
    /// with `c = min(retry_max, retry_base * 2^(n-1))`, uniform in
    /// `[c/2, c]` milliseconds (never below 1). The floor matters: with full
    /// jitter a share of messages was re-published within milliseconds of the
    /// first publish, before any receipt could exist
    /// (`results/fixups/burst-latency.md`).
    pub(crate) fn backoff_ms(&self, n: u32) -> i64 {
        let d = &self.config.delivery;
        let shift = n.saturating_sub(1).min(32);
        let ceiling = d
            .retry_base_ms
            .saturating_mul(1u64 << shift)
            .min(d.retry_max_ms)
            .max(1);
        let r = {
            let mut g = self.rng.lock().unwrap_or_else(|e| e.into_inner());
            splitmix(&mut g)
        };
        let half = ceiling / 2;
        let span = ceiling - half + 1;
        i64::try_from((half + r % span).max(1)).unwrap_or(i64::MAX)
    }

    /// Load a contact (or synthesize our own record for self-addressed mail).
    pub(crate) fn load_contact(
        &self,
        conn: &rusqlite::Connection,
        addr: &Address,
    ) -> Result<Option<ContactRow>, StoreError> {
        let now = self.now();
        if *addr == self.own {
            let doc = self.identity.contact_record().to_document();
            let contact = VerifiedContact::parse_and_verify_allow_expired(&doc, now)
                .map_err(|_| StoreError::Corrupt("own contact record"))?;
            return Ok(Some(ContactRow {
                contact,
                trust: Trust::Trusted,
                alias: Some("self".into()),
                added_at: self.identity.created_at(),
                revoked: false,
            }));
        }
        let row: Option<(String, Option<String>, String, i64)> = conn
            .query_row(
                "SELECT document, alias, trust, added_at FROM contacts WHERE address = ?1",
                [addr.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((doc, alias, trust, added_at)) = row else {
            return Ok(None);
        };
        let contact = VerifiedContact::parse_and_verify_allow_expired(&doc, now)
            .map_err(|_| StoreError::Corrupt("stored contact record failed verification"))?;
        if contact.address != *addr {
            return Err(StoreError::Corrupt("stored contact address mismatch"));
        }
        let revoked = Self::is_revoked(conn, addr)? || contact.revocation(now).is_some();
        Ok(Some(ContactRow {
            contact,
            trust: if revoked {
                Trust::Blocked
            } else {
                trust_from_db(&trust)
            },
            alias,
            added_at,
            revoked,
        }))
    }

    /// A short identifier of the current public certificate (changes when the
    /// certificate changes: rotation, revocation). Not a security mechanism.
    pub(crate) fn cert_id(&self) -> u64 {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(self.identity.contact_record().as_bytes());
        u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]) >> 1
    }

    /// The pinned certificate of `addr`, for verifying a received message. A store
    /// or parse failure is an error, never "not a contact" (review finding L5).
    pub(crate) fn pinned_certificate(
        &self,
        addr: &Address,
    ) -> Result<Option<VerifiedContact>, StoreError> {
        Ok(self
            .store
            .read(|c| self.load_contact(c, addr))?
            .map(|r| r.contact))
    }

    /// True if a verified identity revocation is stored for `addr`.
    pub(crate) fn is_revoked(
        conn: &rusqlite::Connection,
        addr: &Address,
    ) -> Result<bool, StoreError> {
        Ok(conn
            .query_row(
                "SELECT 1 FROM revocations WHERE address = ?1",
                [addr.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    // ------------------------------------------------------------------ steps

    async fn poll_frames(&self) -> Result<Vec<InboundFrame>, TransportError> {
        if !self.subscribed.load(Ordering::SeqCst) {
            self.transport.subscribe(&self.topic).await?;
            self.subscribed.store(true, Ordering::SeqCst);
        }
        let frames = self.transport.poll(&self.topic).await;
        match &frames {
            Ok(_) => {
                self.last_live_poll_at.store(self.now(), Ordering::SeqCst);
                if !self.transport_was_ok.swap(true, Ordering::SeqCst) {
                    self.metrics.inc("transport.recovered");
                    self.history_kick.notify_one();
                }
            }
            Err(_) => {
                self.transport_was_ok.store(false, Ordering::SeqCst);
                self.metrics.inc("transport.poll_error");
            }
        }
        let mut frames = frames?;
        // Discovery topics (opt-in; empty unless `discovery.enabled`). A failure
        // here never affects message delivery: history sync recovers adverts.
        for (_, t) in &self.disc_topics {
            let known = self
                .disc_subscribed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(t);
            if !known {
                if self.transport.subscribe(t).await.is_err() {
                    self.metrics.inc("advert.subscribe_error");
                    continue;
                }
                self.disc_subscribed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(t.clone());
            }
            match self.transport.poll(t).await {
                Ok(f) => frames.extend(f),
                Err(_) => self.metrics.inc("advert.poll_error"),
            }
        }
        Ok(frames)
    }

    /// Poll the live queue once and process every frame returned.
    pub async fn step_receive(&self) -> Result<ReceiveReport, NodeError> {
        let frames = self.poll_frames().await?;
        let mut rep = ReceiveReport {
            polled: frames.len(),
            ..Default::default()
        };
        for f in &frames {
            if self.ingest_frame(f).is_store_failure() {
                rep.store_failures += 1;
            } else {
                rep.processed += 1;
            }
        }
        if rep.store_failures > 0 {
            self.note_live_loss();
        }
        Ok(rep)
    }

    /// A live frame could not be persisted: it will not be polled again, so
    /// ask for a history pass to recover it.
    fn note_live_loss(&self) {
        self.history_needed.store(true, Ordering::SeqCst);
        self.history_kick.notify_one();
    }

    /// Catch up from the transport's history (see module docs). The watermark
    /// advances only after a pass that processed every page without a store
    /// failure; `HistoryUnavailable` and other transport errors leave it as is.
    pub async fn step_history_sync(&self) -> Result<HistoryReport, NodeError> {
        let now = self.now();
        let d = &self.config.delivery;
        let retention_ms = i64::try_from(
            self.config
                .storage
                .retention_hours
                .saturating_mul(3_600_000),
        )
        .unwrap_or(i64::MAX);
        let overlap_ms =
            i64::try_from(d.history_overlap_s.saturating_mul(1000)).unwrap_or(i64::MAX);
        let wm: Option<i64> = self
            .store
            .read(|c| kv_get(c, KV_HISTORY_WATERMARK))?
            .and_then(|s| s.parse().ok());
        let floor = now.saturating_sub(retention_ms);
        let start_ms = match wm {
            Some(w) => w.saturating_sub(overlap_ms).max(floor),
            None => floor,
        };
        let start_ns = start_ms.saturating_mul(1_000_000);
        // Sender timestamps may run ahead of our clock by up to the accepted skew.
        let end_ns = now
            .saturating_add(self.open_limits.clock_skew_ms)
            .saturating_mul(1_000_000);
        let max_window = self.transport.max_history_window_ns().max(1);
        let mut rep = HistoryReport::default();
        // The inbox topic first, then the discovery topics (only when enabled).
        // Older adverts than `max_advert_ttl + skew` are expired anyway, so the
        // discovery windows start no earlier than that.
        let mut targets: Vec<(ContentTopic, i64)> = vec![(self.topic.clone(), start_ns)];
        if !self.disc_topics.is_empty() {
            let advert_floor = now
                .saturating_sub(self.advert_limits.max_ttl_ms)
                .saturating_sub(self.advert_limits.clock_skew_ms);
            let d_start = start_ms.max(advert_floor).saturating_mul(1_000_000);
            for (_, t) in &self.disc_topics {
                targets.push((t.clone(), d_start));
            }
        }
        let mut pages = 0usize;
        for (topic, topic_start_ns) in targets {
            let mut ws = topic_start_ns;
            loop {
                let we = ws.saturating_add(max_window).min(end_ns);
                let mut cursor: Option<String> = None;
                let mut seen_cursors: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                loop {
                    pages += 1;
                    if pages > MAX_HISTORY_PAGES {
                        rep.error = Some("too many history pages".into());
                        return Ok(rep);
                    }
                    let q = HistoryQuery {
                        topic: topic.clone(),
                        start_ns: ws,
                        end_ns: we,
                        cursor: cursor.clone(),
                        limit: HISTORY_PAGE_LIMIT,
                    };
                    let page = match self.transport.history(&q).await {
                        Ok(p) => p,
                        Err(e) => {
                            self.metrics.inc(match e {
                                TransportError::HistoryUnavailable(_) => "history.unavailable",
                                TransportError::Isolation(_) => "history.isolation",
                                _ => "history.error",
                            });
                            rep.error = Some(sanitize(&e.to_string()));
                            return Ok(rep);
                        }
                    };
                    for f in &page.frames {
                        rep.frames += 1;
                        if self.ingest_frame(f).is_store_failure() {
                            rep.error = Some("storage error while processing history".into());
                            return Ok(rep);
                        }
                    }
                    match page.next_cursor {
                        None => break,
                        // A cursor that was already used means the service is not
                        // making progress: the rest of the window was not read, so
                        // this is a failed pass (the watermark must not advance).
                        Some(c) if !seen_cursors.insert(c.clone()) => {
                            self.metrics.inc("history.cursor_repeated");
                            rep.error = Some("history pagination cursor repeated".into());
                            return Ok(rep);
                        }
                        Some(c) => cursor = Some(c),
                    }
                }
                if we >= end_ns {
                    break;
                }
                ws = we;
            }
        }
        self.store
            .tx(|tx| kv_set(tx, KV_HISTORY_WATERMARK, &now.to_string()))?;
        self.history_needed.store(false, Ordering::SeqCst);
        self.metrics.inc("history.completed");
        rep.completed = true;
        Ok(rep)
    }

    /// Expire and prune (see `docs/protocol.md`).
    pub fn step_maintenance(&self) -> Result<MaintenanceReport, NodeError> {
        let now = self.now();
        let _ = self.guard_state();
        let c = &self.config;
        let hours = |h: u64| i64::try_from(h.saturating_mul(3_600_000)).unwrap_or(i64::MAX);
        let skew_ms = self.open_limits.clock_skew_ms;
        let retention = now.saturating_sub(hours(c.storage.retention_hours));
        let ev_ret = now.saturating_sub(hours(c.storage.event_retention_hours));
        let ev_max = now.saturating_sub(hours(c.storage.event_max_age_hours));
        let ts_ttl = now.saturating_sub(
            i64::try_from(c.delivery.transport_seen_ttl_s.saturating_mul(1000)).unwrap_or(i64::MAX),
        );
        let (rep, expired_msgs) = self.store.tx(|tx| {
            let mut rep = MaintenanceReport::default();
            let mut expired: Vec<(Option<String>, bool)> = Vec::new();
            {
                let mut st = tx.prepare(
                    "UPDATE outbox SET state='expired', next_attempt_at=NULL
                     WHERE expires_at <= ?1 AND (state='queued' OR (state='sent' AND is_ack=0))
                     RETURNING conversation_id, (is_ack OR hidden)",
                )?;
                let rows = st.query_map([now], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, i64>(1)? != 0)))?;
                for r in rows {
                    expired.push(r?);
                }
            }
            rep.outbox_expired = expired.len();
            rep.triggers_expired = tx.execute(
                "UPDATE triggers SET state='expired' WHERE state='active' AND expires_at <= ?1",
                [now],
            )?;
            // `seen` rows are kept until expires_at + clock_skew: an envelope
            // that expired is rejected by `open` anyway, so pruning then is replay-safe.
            let mut pruned = 0;
            pruned += tx.execute(
                "DELETE FROM seen WHERE expires_at < ?1",
                [now.saturating_sub(skew_ms)],
            )?;
            pruned += tx.execute("DELETE FROM transport_seen WHERE first_seen < ?1", [ts_ttl])?;
            pruned += tx.execute(
                "DELETE FROM transport_seen WHERE transport_id NOT IN
                 (SELECT transport_id FROM transport_seen ORDER BY first_seen DESC LIMIT ?1)",
                [TRANSPORT_SEEN_CAP],
            )?;
            pruned += tx.execute(
                "DELETE FROM events WHERE (acked=1 AND timestamp < ?1) OR (acked=0 AND timestamp < ?2)",
                [ev_ret, ev_max],
            )?;
            pruned += tx.execute("DELETE FROM inbox WHERE received_at < ?1", [retention])?;
            pruned += tx.execute(
                "DELETE FROM outbox WHERE state IN ('delivered','failed','expired')
                 AND created_at < ?1",
                [retention],
            )?;
            // An ack is never acknowledged itself: once published (`sent`, no
            // further attempt) it is terminal, so it ages out like the rest.
            pruned += tx.execute(
                "DELETE FROM outbox WHERE is_ack = 1 AND state = 'sent' AND created_at < ?1",
                [retention],
            )?;
            pruned += tx.execute(
                "DELETE FROM triggers WHERE state != 'active' AND created_at < ?1",
                [ev_ret],
            )?;
            pruned += self.prune_adverts(tx, now)?;
            rep.pruned_rows = pruned;
            Ok((rep, expired))
        })?;
        if !expired_msgs.is_empty() {
            self.metrics
                .add("outbox.expired", expired_msgs.len() as u64);
            if expired_msgs.iter().any(|(_, ack)| !ack) {
                self.hint(ChangeHint::Outbox);
            }
            for (cid, ack) in expired_msgs {
                if let (Some(cid), false) = (cid, ack) {
                    self.hint(ChangeHint::Conversation {
                        conversation_id: cid,
                    });
                }
            }
        }
        if rep.triggers_expired > 0 {
            self.hint(ChangeHint::Triggers);
        }
        Ok(rep)
    }

    // -------------------------------------------------------------------- run

    async fn wait_unpaused(&self) {
        let mut rx = self.pause.subscribe();
        while *rx.borrow() {
            if rx.changed().await.is_err() {
                break;
            }
        }
    }

    /// Drive the engine until `shutdown` is cancelled, then close the store.
    ///
    /// Tasks: a receive loop feeding a bounded channel (capacity
    /// `inbound_channel_capacity`; when full the receive loop awaits, so the
    /// transport's queue absorbs the backlog and nothing is dropped or grows
    /// without bound apart from the one poll batch the receive loop holds), a
    /// processing stage that persists frames, a send loop, a history loop (at
    /// start, after the transport recovers, on a persistence failure and every
    /// `history_sync_interval_s`) and a maintenance loop. On shutdown the loops
    /// stop, the frame being processed finishes, buffered unprocessed frames are
    /// left to history recovery, and the database is checkpointed and closed.
    pub async fn run(self: &Arc<Self>, shutdown: CancellationToken) {
        let cap = self.config.delivery.inbound_channel_capacity;
        let (tx, mut rx) = mpsc::channel::<InboundFrame>(cap);
        let poll_every = Duration::from_millis(self.config.delivery.poll_interval_ms);
        let hist_every = Duration::from_secs(self.config.delivery.history_sync_interval_s);

        let receive = async {
            let mut tick = tokio::time::interval(poll_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tick.tick() => {}
                }
                let frames = match self.poll_frames().await {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                for f in frames {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        r = tx.send(f) => if r.is_err() { return },
                    }
                }
            }
        };
        let process = async {
            loop {
                let f = tokio::select! {
                    _ = shutdown.cancelled() => return,
                    f = rx.recv() => match f { Some(f) => f, None => return },
                };
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = self.wait_unpaused() => {}
                }
                if self.ingest_frame(&f).is_store_failure() {
                    self.note_live_loss();
                }
            }
        };
        let send = async {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = async {
                        let _ = self.step_send().await;
                        let _ = self.step_adverts().await;
                    } => {}
                }
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = self.send_nudge.notified() => {}
                    _ = tokio::time::sleep(poll_every) => {}
                }
            }
        };
        let history = async {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = self.step_history_sync() => {}
                }
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = self.history_kick.notified() => {}
                    _ = tokio::time::sleep(hist_every) => {}
                }
            }
        };
        let maintenance = async {
            loop {
                let _ = self.step_maintenance();
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = tokio::time::sleep(MAINTENANCE_INTERVAL) => {}
                }
            }
        };
        tokio::join!(receive, process, send, history, maintenance);
        self.store.close();
    }
}
