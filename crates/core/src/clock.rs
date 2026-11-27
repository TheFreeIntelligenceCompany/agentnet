//! Time source abstraction so the engine can be driven deterministically.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of "now" in Unix milliseconds.
pub trait Clock: Send + Sync + 'static {
    /// Current time, Unix milliseconds (UTC).
    fn now_ms(&self) -> i64;
}

/// Wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

/// Wall-clock time now, Unix milliseconds.
pub fn system_now_ms() -> i64 {
    SystemClock.now_ms()
}

/// A manually advanced clock. Cloning shares the same time.
#[derive(Clone, Debug)]
pub struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    /// New clock reading `start_ms`.
    pub fn new(start_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(start_ms)))
    }
    /// Sets the absolute time.
    pub fn set_ms(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }
    /// Advances the clock.
    pub fn advance_ms(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The transport crate's mock clock (nanoseconds) can drive the engine too, so
/// one clock drives both the mock network and the nodes in tests.
impl Clock for agentnet_transport::mock::MockClock {
    fn now_ms(&self) -> i64 {
        self.now_ns() / 1_000_000
    }
}
