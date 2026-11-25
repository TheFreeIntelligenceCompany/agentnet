//! State shared by every handler instance of one server, and the notification
//! pump that turns lossy [`ChangeHint`]s into `notifications/resources/updated`.
//!
//! In the 2026-07-28 stateless model `StreamableHttpService` builds a fresh
//! handler per request, so nothing here may live in the handler itself.

use std::{
    collections::{HashSet, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use agentnet_core::api::{AgentApi, ChangeHint};
use rmcp::model::SubscriptionFilter;
use tokio::sync::broadcast::{self, error::RecvError, error::TryRecvError};
use tokio_util::sync::CancellationToken;

use crate::uris::hint_uri;

/// Receivers created in `accepted_subscription_filter` (before the SDK sends the
/// acknowledgment) and claimed by `listen`, so hints emitted between the
/// acknowledgment and the start of the listen loop are not lost.
const MAX_PENDING: usize = 32;

/// Counters exposed for tests and diagnostics (see [`McpStats`]).
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub active_listeners: AtomicUsize,
    pub total_listeners: AtomicUsize,
    pub active_legacy_tasks: AtomicUsize,
}

pub(crate) struct Shared {
    pub api: Arc<dyn AgentApi>,
    pub shutdown: CancellationToken,
    pub counters: Counters,
    pending: Mutex<VecDeque<(Vec<String>, broadcast::Receiver<ChangeHint>)>>,
}

impl Shared {
    pub fn new(api: Arc<dyn AgentApi>, shutdown: CancellationToken) -> Self {
        Self {
            api,
            shutdown,
            counters: Counters::default(),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    /// Subscribe to engine hints now and park the receiver for `listen`.
    pub fn park_receiver(&self, accepted: &SubscriptionFilter) {
        let key = filter_key(accepted);
        if key.is_empty() {
            return;
        }
        let rx = self.api.changes();
        let mut pending = lock(&self.pending);
        if pending.len() >= MAX_PENDING {
            pending.pop_front();
        }
        pending.push_back((key, rx));
    }

    /// Claim the receiver parked for this accepted filter, or subscribe fresh.
    pub fn claim_receiver(&self, accepted: &SubscriptionFilter) -> broadcast::Receiver<ChangeHint> {
        let key = filter_key(accepted);
        let mut pending = lock(&self.pending);
        if let Some(pos) = pending.iter().position(|(k, _)| *k == key) {
            if let Some((_, rx)) = pending.remove(pos) {
                return rx;
            }
        }
        drop(pending);
        self.api.changes()
    }
}

/// Order-insensitive identity of a filter's resource URIs.
fn filter_key(filter: &SubscriptionFilter) -> Vec<String> {
    let mut key: Vec<String> = filter
        .resource_subscriptions
        .iter()
        .flatten()
        .cloned()
        .collect();
    key.sort();
    key.dedup();
    key
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A poisoned lock only means another task panicked while holding it; the
    // protected data (plain collections) stays structurally valid.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Decrements a counter on drop (also when a task is aborted).
pub(crate) struct CountGuard<'a>(&'a AtomicUsize);

impl<'a> CountGuard<'a> {
    pub fn new(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Owned variant for spawned tasks.
pub(crate) struct OwnedCountGuard(pub Arc<Shared>);

impl OwnedCountGuard {
    pub fn new(shared: Arc<Shared>) -> Self {
        shared
            .counters
            .active_legacy_tasks
            .fetch_add(1, Ordering::SeqCst);
        Self(shared)
    }
}

impl Drop for OwnedCountGuard {
    fn drop(&mut self) {
        self.0
            .counters
            .active_legacy_tasks
            .fetch_sub(1, Ordering::SeqCst);
    }
}

/// What the pump should do after one receive.
pub(crate) enum Next {
    /// Send `notifications/resources/updated` for each URI, then continue.
    Notify(Vec<String>),
    /// Hint was for nobody here; continue.
    Skip,
    /// The hint stream ended.
    Stop,
}

/// Wait for the next batch of hints and decide which of `interest` to notify.
///
/// * Hints are batched: everything already queued is coalesced into one
///   notification per distinct URI (notifications are hints, not a queue).
/// * `Lagged` means hints were dropped: notify every URI in `interest` once;
///   the client rereads by cursor.
/// * Only URIs in `interest` are ever returned.
pub(crate) async fn next_batch(
    rx: &mut broadcast::Receiver<ChangeHint>,
    interest: impl Fn() -> HashSet<String>,
) -> Next {
    let first = rx.recv().await;
    // Evaluated after the wait so subscriptions changed meanwhile are honoured.
    let interest = interest();
    let mut lagged = false;
    let mut closed = false;
    let mut uris: Vec<String> = Vec::new();
    let mut absorb = |hint: ChangeHint| {
        if let Some(uri) = hint_uri(&hint) {
            if interest.contains(&uri) && !uris.contains(&uri) {
                uris.push(uri);
            }
        }
    };
    match first {
        Ok(h) => absorb(h),
        Err(RecvError::Lagged(_)) => lagged = true,
        Err(RecvError::Closed) => closed = true,
    }
    if !closed {
        loop {
            match rx.try_recv() {
                Ok(h) => absorb(h),
                Err(TryRecvError::Lagged(_)) => lagged = true,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Closed) => {
                    closed = true;
                    break;
                }
            }
        }
    }
    if lagged {
        let mut all: Vec<String> = interest.iter().cloned().collect();
        all.sort();
        return Next::Notify(all);
    }
    if !uris.is_empty() {
        return Next::Notify(uris);
    }
    if closed {
        Next::Stop
    } else {
        Next::Skip
    }
}
