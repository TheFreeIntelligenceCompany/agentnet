//! Plain counters. Names are stable strings; none carries payload content.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// A snapshot of the engine's counters (by name, e.g. `drop.blocked`,
/// `open_error.bad_signature`, `inbox.full_refused`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMetrics {
    /// Counter name -> value.
    pub counters: BTreeMap<String, u64>,
}

impl NodeMetrics {
    /// Value of a counter (0 if never incremented).
    pub fn get(&self, name: &str) -> u64 {
        self.counters.get(name).copied().unwrap_or(0)
    }
}

#[derive(Default)]
pub(crate) struct Metrics(Mutex<BTreeMap<String, u64>>);

impl Metrics {
    pub(crate) fn inc(&self, name: &str) {
        self.add(name, 1);
    }
    pub(crate) fn add(&self, name: &str, n: u64) {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let e = g.entry(name.to_owned()).or_insert(0);
        *e = e.saturating_add(n);
    }
    pub(crate) fn snapshot(&self) -> NodeMetrics {
        NodeMetrics {
            counters: self.0.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        }
    }
}
