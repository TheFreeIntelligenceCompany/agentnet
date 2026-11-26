//! Node configuration. All sections have defaults; unknown keys are rejected.

use serde::{Deserialize, Serialize};

/// What to do with messages from senders that are not Trusted contacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownSenders {
    /// Store with `quarantined = 1` (no ack, no event, no trigger).
    Quarantine,
    /// Drop.
    Reject,
    /// Treat as normal (trust is recorded as unknown/untrusted; triggers never match).
    Accept,
}

/// `[policy]`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyConfig {
    /// Handling of non-trusted senders.
    pub unknown_senders: UnknownSenders,
    /// Whether `create_trigger` is allowed at all.
    pub auto_trigger: bool,
}
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            unknown_senders: UnknownSenders::Quarantine,
            auto_trigger: false,
        }
    }
}

/// `[triggers]`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TriggerConfig {
    /// Host-approved `target_session` values.
    pub allowed_sessions: Vec<String>,
    /// Maximum simultaneously active triggers.
    pub max_active: u32,
    /// Sliding-minute budget of `trigger.matched` events across all triggers.
    pub max_matches_per_minute: u32,
    /// Lifetime used when the request gives none.
    pub default_lifetime_s: u64,
    /// Upper bound of a trigger's lifetime.
    pub max_lifetime_hours: u64,
}
impl Default for TriggerConfig {
    fn default() -> Self {
        Self {
            allowed_sessions: Vec::new(),
            max_active: 32,
            max_matches_per_minute: 60,
            default_lifetime_s: 3600,
            max_lifetime_hours: 24,
        }
    }
}

/// `[delivery]`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeliveryConfig {
    /// Default message TTL.
    pub default_ttl_s: u64,
    /// Largest accepted TTL (requests above are capped; inbound above are rejected).
    pub max_ttl_s: u64,
    /// First retry ceiling.
    pub retry_base_ms: u64,
    /// Retry ceiling cap.
    pub retry_max_ms: u64,
    /// Accepted publishes after which a never-acked message is no longer re-published.
    pub max_attempts: u32,
    /// Live poll interval used by `run`.
    pub poll_interval_ms: u64,
    /// History sync period used by `run`.
    pub history_sync_interval_s: u64,
    /// History queries start this far before the watermark.
    pub history_overlap_s: u64,
    /// Accepted `created_at` skew into the future; also the `seen` prune margin.
    pub clock_skew_s: u64,
    /// Largest accepted message body (bytes).
    pub max_body_bytes: usize,
    /// Maximum non-ack outbox rows in state queued/sent.
    pub max_outbox_pending: u64,
    /// Capacity of the receive -> process channel in `run`.
    pub inbound_channel_capacity: usize,
    /// Minimum interval between re-acks of the same duplicate message.
    pub reack_min_interval_s: u64,
    /// Rows handled per `step_send`.
    pub send_batch: u32,
    /// Age after which `transport_seen` entries are pruned.
    pub transport_seen_ttl_s: u64,
    /// Seed for retry jitter; `None` seeds from the OS.
    pub jitter_seed: Option<u64>,
}
impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            default_ttl_s: 86_400,
            max_ttl_s: 604_800,
            retry_base_ms: 2000,
            retry_max_ms: 300_000,
            max_attempts: 20,
            poll_interval_ms: 250,
            history_sync_interval_s: 15,
            history_overlap_s: 30,
            clock_skew_s: 120,
            max_body_bytes: 65_536,
            max_outbox_pending: 1000,
            inbound_channel_capacity: 256,
            reack_min_interval_s: 30,
            send_batch: 64,
            transport_seen_ttl_s: 86_400,
            jitter_seed: None,
        }
    }
}

/// `[storage]`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    /// How long inbox/outbox rows are kept and how far back history sync reaches.
    pub retention_hours: u64,
    /// Maximum non-quarantined inbox rows; beyond it messages are refused (not acked).
    pub max_inbox_records: u64,
    /// Maximum quarantined rows; beyond it quarantined messages are dropped.
    pub max_quarantined: u64,
    /// Acked events are kept this long.
    pub event_retention_hours: u64,
    /// Unacked events older than this are dropped (TTL).
    pub event_max_age_hours: u64,
}
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            retention_hours: 168,
            max_inbox_records: 100_000,
            max_quarantined: 1000,
            event_retention_hours: 168,
            event_max_age_hours: 720,
        }
    }
}

/// `[discovery]` (optional, opt-in; see `docs/discovery.md`).
///
/// Discovery is OFF by default. When on, the node subscribes to the listed
/// discovery content topics and publishes signed capability advertisements to
/// them. Advertisements are PLAINTEXT: every node on the relay can read them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DiscoveryConfig {
    /// Master switch. With `false` nothing is subscribed or published and the
    /// discovery tools return `policy_denied`.
    pub enabled: bool,
    /// The authorised discovery topic names (`[a-z0-9-]{1,32}`); each maps to
    /// the content topic `/agentnet/1/discovery-<name>/proto`.
    pub topics: Vec<String>,
    /// Most stored advertisements across all topics.
    pub max_records: u64,
    /// Longest accepted (and issued) advertisement lifetime.
    pub max_advert_ttl_s: u64,
    /// Lifetime used when an `advertise_agent` request gives none.
    pub default_advert_ttl_s: u64,
    /// How often the own advertisement is published again.
    pub republish_interval_s: u64,
    /// Most capabilities in one advertisement (also the limit for received ones).
    pub max_capabilities: usize,
}
impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            topics: Vec::new(),
            max_records: 500,
            max_advert_ttl_s: 86_400,
            default_advert_ttl_s: 3600,
            republish_interval_s: 900,
            max_capabilities: 16,
        }
    }
}

/// Valid discovery topic name: `[a-z0-9-]{1,32}`.
pub fn valid_discovery_topic_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 32
        && n.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// The content topic of a discovery topic name.
pub fn discovery_content_topic(name: &str) -> String {
    format!("/agentnet/1/discovery-{name}/proto")
}

/// The complete engine configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NodeConfig {
    /// `[policy]`
    pub policy: PolicyConfig,
    /// `[triggers]`
    pub triggers: TriggerConfig,
    /// `[delivery]`
    pub delivery: DeliveryConfig,
    /// `[storage]`
    pub storage: StorageConfig,
    /// `[discovery]`
    pub discovery: DiscoveryConfig,
    /// Label reported by `network_status` (`private` / `public`).
    pub network_mode: String,
}
impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            policy: PolicyConfig::default(),
            triggers: TriggerConfig::default(),
            delivery: DeliveryConfig::default(),
            storage: StorageConfig::default(),
            discovery: DiscoveryConfig::default(),
            network_mode: "private".to_owned(),
        }
    }
}

impl NodeConfig {
    /// Check internal consistency.
    pub fn validate(&self) -> Result<(), String> {
        let d = &self.delivery;
        let s = &self.storage;
        let t = &self.triggers;
        let checks: [(bool, &str); 18] = [
            (d.default_ttl_s > 0, "delivery.default_ttl_s must be > 0"),
            (
                d.max_ttl_s >= d.default_ttl_s,
                "delivery.max_ttl_s must be >= default_ttl_s",
            ),
            (d.retry_base_ms > 0, "delivery.retry_base_ms must be > 0"),
            (
                d.retry_max_ms >= d.retry_base_ms,
                "delivery.retry_max_ms must be >= retry_base_ms",
            ),
            (d.max_attempts > 0, "delivery.max_attempts must be > 0"),
            (
                d.poll_interval_ms > 0,
                "delivery.poll_interval_ms must be > 0",
            ),
            (
                d.history_sync_interval_s > 0,
                "delivery.history_sync_interval_s must be > 0",
            ),
            (d.max_body_bytes > 0, "delivery.max_body_bytes must be > 0"),
            (
                d.inbound_channel_capacity > 0,
                "delivery.inbound_channel_capacity must be > 0",
            ),
            (d.send_batch > 0, "delivery.send_batch must be > 0"),
            (
                d.max_outbox_pending > 0,
                "delivery.max_outbox_pending must be > 0",
            ),
            (s.retention_hours > 0, "storage.retention_hours must be > 0"),
            (
                s.max_inbox_records > 0,
                "storage.max_inbox_records must be > 0",
            ),
            (
                s.event_retention_hours > 0 && s.event_max_age_hours > 0,
                "storage.event_*_hours must be > 0",
            ),
            (t.max_active > 0, "triggers.max_active must be > 0"),
            (
                t.max_matches_per_minute > 0,
                "triggers.max_matches_per_minute must be > 0",
            ),
            (
                t.default_lifetime_s > 0
                    && t.default_lifetime_s <= t.max_lifetime_hours.saturating_mul(3600),
                "triggers.default_lifetime_s must be > 0 and <= max_lifetime_hours",
            ),
            (
                matches!(self.network_mode.as_str(), "private" | "public"),
                "network_mode must be \"private\" or \"public\"",
            ),
        ];
        for (ok, msg) in checks {
            if !ok {
                return Err(msg.to_owned());
            }
        }
        self.validate_discovery()?;
        // Retries must not outlive what the receiver would accept.
        if d.max_ttl_s > i64::MAX as u64 / 2000 {
            return Err("delivery.max_ttl_s is unreasonably large".into());
        }
        Ok(())
    }
}

impl NodeConfig {
    fn validate_discovery(&self) -> Result<(), String> {
        let c = &self.discovery;
        let checks: [(bool, &str); 6] = [
            (c.max_records > 0, "discovery.max_records must be > 0"),
            (
                c.max_advert_ttl_s > 0 && c.max_advert_ttl_s <= 7 * 86_400,
                "discovery.max_advert_ttl_s must be in 1..=604800",
            ),
            (
                c.default_advert_ttl_s > 0 && c.default_advert_ttl_s <= c.max_advert_ttl_s,
                "discovery.default_advert_ttl_s must be > 0 and <= max_advert_ttl_s",
            ),
            (
                c.republish_interval_s > 0,
                "discovery.republish_interval_s must be > 0",
            ),
            (
                (1..=crate::crypto::advert::MAX_CAPABILITIES_HARD).contains(&c.max_capabilities),
                "discovery.max_capabilities must be in 1..=64",
            ),
            (c.topics.len() <= 16, "discovery.topics lists at most 16 topics"),
        ];
        for (ok, msg) in checks {
            if !ok {
                return Err(msg.to_owned());
            }
        }
        for (i, t) in c.topics.iter().enumerate() {
            if !valid_discovery_topic_name(t) {
                return Err(format!(
                    "discovery.topics: {t:?} is not a valid topic name ([a-z0-9-]{{1,32}})"
                ));
            }
            if c.topics.iter().take(i).any(|p| p == t) {
                return Err(format!("discovery.topics lists {t:?} twice"));
            }
        }
        if c.enabled && c.topics.is_empty() {
            return Err(
                "discovery.enabled = true requires at least one name in discovery.topics".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_match_the_documented_values() {
        let c = NodeConfig::default();
        assert!(c.validate().is_ok());
        assert_eq!(c.policy.unknown_senders, UnknownSenders::Quarantine);
        assert!(!c.policy.auto_trigger);
        assert_eq!(c.delivery.retry_base_ms, 2000);
        assert_eq!(c.delivery.retry_max_ms, 300_000);
        assert_eq!(c.storage.retention_hours, 168);
        let d = &c.discovery;
        assert!(!d.enabled && d.topics.is_empty());
        assert_eq!(
            (
                d.max_records,
                d.max_advert_ttl_s,
                d.default_advert_ttl_s,
                d.republish_interval_s,
                d.max_capabilities
            ),
            (500, 86_400, 3600, 900, 16)
        );
    }

    #[test]
    fn discovery_validation() {
        let mut c = NodeConfig::default();
        c.discovery.enabled = true;
        assert!(c.validate().is_err(), "enabled without topics");
        c.discovery.topics = vec!["general".into(), "team-1".into()];
        assert!(c.validate().is_ok());
        for bad in ["", "UP", "a b", "a/b", &"x".repeat(33)] {
            let mut b = c.clone();
            b.discovery.topics = vec![bad.to_owned()];
            assert!(b.validate().is_err(), "{bad:?}");
        }
        let mut b = c.clone();
        b.discovery.topics = vec!["a".into(), "a".into()];
        assert!(b.validate().is_err());
        let mut b = c.clone();
        b.discovery.default_advert_ttl_s = b.discovery.max_advert_ttl_s + 1;
        assert!(b.validate().is_err());
        assert_eq!(
            discovery_content_topic("general"),
            "/agentnet/1/discovery-general/proto"
        );
        assert!(serde_json::from_str::<NodeConfig>(r#"{"discovery":{"nope":1}}"#).is_err());
    }

    #[test]
    fn partial_toml_like_json_and_unknown_keys() {
        let c: NodeConfig = serde_json::from_str(r#"{"delivery":{"max_attempts":3}}"#).unwrap();
        assert_eq!(c.delivery.max_attempts, 3);
        assert_eq!(c.delivery.poll_interval_ms, 250);
        assert!(serde_json::from_str::<NodeConfig>(r#"{"delivery":{"nope":1}}"#).is_err());
        let mut bad = NodeConfig::default();
        bad.triggers.default_lifetime_s = 10 * 3600 * 24;
        assert!(bad.validate().is_err());
        bad = NodeConfig::default();
        bad.network_mode = "mesh".into();
        assert!(bad.validate().is_err());
    }
}
