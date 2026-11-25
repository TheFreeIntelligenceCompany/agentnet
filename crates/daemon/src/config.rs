//! `agentnet.toml`: the daemon configuration.
//!
//! The file has one section per concern. Identity and contact policy
//! (`[policy]`, `[triggers]`, `[storage]`, `[delivery]`) are kept apart from
//! networking (`[network]`) and from the host integration surfaces
//! (`[mcp_http]`, `[webhook]`). Unknown keys are errors, every default is the
//! safe one, and [`DaemonConfig::validate`] fails closed.
//!
//! The daemon does not duplicate the validation of the engine or of the
//! transport: [`DaemonConfig::to_node_config`] and
//! [`DaemonConfig::to_logos_config`] build their configurations and surface
//! their errors verbatim.

use std::net::SocketAddr;

use agentnet_core::config::{
    DeliveryConfig, NodeConfig, PolicyConfig, StorageConfig, TriggerConfig,
};
use agentnet_transport::logos_rest::{LogosRestConfig, NetworkMode};
use serde::{Deserialize, Serialize};

use crate::error::DaemonError;
use crate::webhook::WebhookTarget;

/// Largest accepted `agentnet.toml`.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// `network.mode`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Closed deployment: static peers only, fail closed (default).
    #[default]
    Private,
    /// Explicit opt-in. UNTESTED against any public network.
    Public,
}

impl Mode {
    /// The label used by `network_status`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Private => "private",
            Mode::Public => "public",
        }
    }
}

/// `[network]`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkSection {
    /// `private` (default) or `public` (needs `i_understand_public = true`).
    pub mode: Mode,
    /// REST endpoint of the local Logos Delivery node (loopback / private only in private mode).
    pub node_url: String,
    /// Static peers (multiaddrs ending in `/p2p/<peerId>`). Required in private
    /// mode; the node must be connected to nothing else.
    pub peers: Vec<String>,
    /// Waku cluster id (must not be a public preset id in private mode).
    pub cluster_id: u16,
    /// Must be false in private mode. The daemon never enables discovery itself;
    /// this flag only records intent and is rejected where it would contradict
    /// the isolation guarantees.
    pub public_discovery: bool,
    /// Always an error when true: there is no public fallback.
    pub public_fallback: bool,
    /// Required for `mode = "public"`.
    pub i_understand_public: bool,
    /// Optional explicit Store peer (multiaddr) passed to the node.
    pub store_peer: Option<String>,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            mode: Mode::Private,
            node_url: "http://127.0.0.1:8645".to_owned(),
            peers: Vec::new(),
            cluster_id: 66,
            public_discovery: false,
            public_fallback: false,
            i_understand_public: false,
            store_peer: None,
        }
    }
}

/// `[mcp_http]`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct McpHttpSection {
    /// Serve authenticated Streamable HTTP MCP from the daemon.
    pub enabled: bool,
    /// Bind address; must be loopback. The bearer token is `mcp-http.token`.
    pub bind: String,
}

impl Default for McpHttpSection {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8650".to_owned(),
        }
    }
}

/// `[webhook]`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebhookSection {
    /// Deliver events to `url` (off by default).
    pub enabled: bool,
    /// The one destination. Loopback / private literal IP or `localhost`
    /// unless `allow_remote`.
    pub url: String,
    /// File holding the shared HMAC secret (>= 32 bytes, mode 0600). Relative
    /// paths are relative to the data directory.
    pub secret_file: String,
    /// Allow public destinations (hostnames and public IPs). Link-local,
    /// metadata, multicast and unspecified addresses stay blocked regardless.
    pub allow_remote: bool,
    /// Per-attempt timeout.
    pub timeout_ms: u64,
    /// Attempts per event before it is parked.
    pub max_attempts: u32,
    /// Event types to deliver (`trigger.matched`, `message.received`).
    pub events: Vec<String>,
    /// First retry delay; doubles per attempt up to `retry_max_ms`.
    pub retry_base_ms: u64,
    /// Upper bound of the retry delay.
    pub retry_max_ms: u64,
}

impl Default for WebhookSection {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            secret_file: String::new(),
            allow_remote: false,
            timeout_ms: 5000,
            max_attempts: 5,
            events: vec!["trigger.matched".to_owned()],
            retry_base_ms: 500,
            retry_max_ms: 30_000,
        }
    }
}

/// The whole `agentnet.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonConfig {
    /// `[network]`
    pub network: NetworkSection,
    /// `[storage]`
    pub storage: StorageConfig,
    /// `[policy]`
    pub policy: PolicyConfig,
    /// `[triggers]`
    pub triggers: TriggerConfig,
    /// `[delivery]`
    pub delivery: DeliveryConfig,
    /// `[mcp_http]`
    pub mcp_http: McpHttpSection,
    /// `[webhook]`
    pub webhook: WebhookSection,
}

fn cfg_err(m: impl Into<String>) -> DaemonError {
    DaemonError::Config(m.into())
}

impl DaemonConfig {
    /// Parse TOML text (no validation beyond the schema).
    pub fn parse(text: &str) -> Result<Self, DaemonError> {
        toml::from_str(text).map_err(|e| cfg_err(e.to_string()))
    }

    /// Parse and validate.
    pub fn parse_validated(text: &str) -> Result<Self, DaemonError> {
        let c = Self::parse(text)?;
        c.validate()?;
        Ok(c)
    }

    /// Read `path` (size-limited, regular file), parse and validate.
    pub fn load(path: &std::path::Path) -> Result<Self, DaemonError> {
        let md = std::fs::metadata(path)
            .map_err(|e| DaemonError::io(format!("reading {}", path.display()), e))?;
        if !md.is_file() {
            return Err(cfg_err(format!("{} is not a regular file", path.display())));
        }
        if md.len() > MAX_CONFIG_BYTES {
            return Err(cfg_err(format!("{} is too large", path.display())));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| DaemonError::io(format!("reading {}", path.display()), e))?;
        Self::parse_validated(&text)
    }

    /// Engine configuration derived from this file.
    pub fn to_node_config(&self) -> NodeConfig {
        NodeConfig {
            policy: self.policy.clone(),
            triggers: self.triggers.clone(),
            delivery: self.delivery.clone(),
            storage: self.storage.clone(),
            network_mode: self.network.mode.as_str().to_owned(),
        }
    }

    /// Transport configuration derived from this file. `static_peers` carries
    /// the configured peers; the allowlist is derived from them by the transport.
    pub fn to_logos_config(&self) -> LogosRestConfig {
        LogosRestConfig {
            node_url: self.network.node_url.clone(),
            mode: match self.network.mode {
                Mode::Private => NetworkMode::Private,
                Mode::Public => NetworkMode::Public,
            },
            cluster_id: self.network.cluster_id,
            static_peers: self.network.peers.clone(),
            store_peer: self.network.store_peer.clone(),
            ..LogosRestConfig::default()
        }
    }

    /// Fail-closed validation of every section.
    pub fn validate(&self) -> Result<(), DaemonError> {
        let n = &self.network;
        if n.public_fallback {
            return Err(cfg_err(
                "network.public_fallback = true is never allowed: there is no public fallback",
            ));
        }
        match n.mode {
            Mode::Private => {
                if n.public_discovery {
                    return Err(cfg_err(
                        "network.public_discovery = true is not allowed in private mode",
                    ));
                }
                if n.peers.is_empty() {
                    return Err(cfg_err(
                        "network.peers must list at least one static peer in private mode \
                         (multiaddr ending in /p2p/<peerId>)",
                    ));
                }
            }
            Mode::Public => {
                if !n.i_understand_public {
                    return Err(cfg_err(
                        "network.mode = \"public\" requires network.i_understand_public = true",
                    ));
                }
            }
        }
        self.validate_mcp_http()?;
        self.validate_webhook()?;
        self.to_node_config()
            .validate()
            .map_err(|e| cfg_err(format!("engine: {e}")))?;
        self.to_logos_config()
            .validate()
            .map_err(|e| cfg_err(format!("network: {e}")))?;
        Ok(())
    }

    fn validate_mcp_http(&self) -> Result<(), DaemonError> {
        let addr: SocketAddr = self
            .mcp_http
            .bind
            .parse()
            .map_err(|_| cfg_err("mcp_http.bind must be an IP:port such as 127.0.0.1:8650"))?;
        if !addr.ip().is_loopback() {
            return Err(cfg_err(
                "mcp_http.bind must be a loopback address: remote MCP exposure needs the MCP \
                 OAuth profile, which is not implemented",
            ));
        }
        Ok(())
    }

    fn validate_webhook(&self) -> Result<(), DaemonError> {
        let w = &self.webhook;
        if !w.enabled {
            return Ok(());
        }
        if w.secret_file.trim().is_empty() {
            return Err(cfg_err(
                "webhook.secret_file is required when the webhook is enabled",
            ));
        }
        if w.timeout_ms == 0 || w.timeout_ms > 60_000 {
            return Err(cfg_err("webhook.timeout_ms must be 1..=60000"));
        }
        if w.max_attempts == 0 || w.max_attempts > 20 {
            return Err(cfg_err("webhook.max_attempts must be 1..=20"));
        }
        if w.retry_base_ms == 0 || w.retry_max_ms < w.retry_base_ms {
            return Err(cfg_err(
                "webhook.retry_base_ms must be > 0 and <= retry_max_ms",
            ));
        }
        if w.events.is_empty()
            || w.events
                .iter()
                .any(|e| e != "trigger.matched" && e != "message.received")
        {
            return Err(cfg_err(
                "webhook.events must be a non-empty subset of [\"trigger.matched\", \"message.received\"]",
            ));
        }
        WebhookTarget::parse(&w.url, w.allow_remote).map_err(cfg_err)?;
        Ok(())
    }
}

/// The private-mode sample used by `agentnet init` and `docs/examples/private.toml`.
/// The peer is the R1 service node of the repository's local test topology.
pub fn sample_private_config() -> String {
    render_private_config(
        "http://127.0.0.1:8645",
        &[
            "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV"
                .to_owned(),
        ],
    )
}

/// Render the private-mode sample with the given node URL and peers. With no
/// peers the file is written with `peers = []` and `serve` refuses to start
/// until one is added (fail closed).
pub fn render_private_config(node_url: &str, peers: &[String]) -> String {
    let peers_line = if peers.is_empty() {
        "peers = []   # REQUIRED in private mode: add your relay's multiaddr, e.g. \"/ip4/10.0.0.5/tcp/60000/p2p/16Uiu2HAm...\"".to_owned()
    } else {
        let items: Vec<String> = peers.iter().map(|p| format!("{p:?}")).collect();
        format!("peers = [{}]", items.join(", "))
    };
    format!(
        r#"# agentnet.toml -- PRIVATE mode (the default). See docs/configuration.md.
#
# Private mode fails closed: the Logos Delivery node must be on a loopback or
# private address, connected only to the peers listed here, and on a private
# cluster id. Discovery and public fallback do not exist.

[network]
mode = "private"
# REST endpoint of YOUR local Logos Delivery node (loopback / RFC1918 / 100.64.0.0/10 only).
node_url = {node_url:?}
# Static peers: multiaddrs of your own relay/store node(s), ending in /p2p/<peerId>.
{peers_line}
# Cluster ids 1, 2, 3 and 16 select public presets and are rejected.
cluster_id = 66
public_discovery = false   # true is a config error in private mode
public_fallback = false    # true is always a config error
i_understand_public = false

[storage]
retention_hours = 168

[policy]
unknown_senders = "quarantine"   # quarantine | reject | accept
auto_trigger = false             # triggers are off until the host enables them

[triggers]
allowed_sessions = []            # host-approved target_session values
max_active = 32
max_matches_per_minute = 60
default_lifetime_s = 3600
max_lifetime_hours = 24

[mcp_http]
enabled = false
bind = "127.0.0.1:8650"          # loopback only; bearer token in <data dir>/mcp-http.token

[webhook]
enabled = false
url = ""                         # the ONE destination; loopback/private unless allow_remote
secret_file = ""                 # >= 32 bytes, mode 0600
allow_remote = false
timeout_ms = 5000
max_attempts = 5
events = ["trigger.matched"]
"#
    )
}

/// The public-mode sample (`docs/examples/public.toml`). UNTESTED against any
/// public network.
pub fn sample_public_config() -> String {
    r#"# agentnet.toml -- PUBLIC mode. UNTESTED against any public network.
#
# Public mode must be chosen explicitly. It skips the peer allowlist audit, so
# the node may be connected to anyone. Public and private traffic are never
# bridged: one daemon talks to exactly one node in exactly one mode. The daemon
# cannot configure the node: discovery, bootstrap nodes, RLN and rate limits are
# flags of the Logos Delivery node you run yourself.
#
# Known limitation: the REST adapter supports only single-shard networks
# (num_shards = 1, shard 0), which the shared public networks are not.

[network]
mode = "public"
i_understand_public = true
node_url = "http://127.0.0.1:8645"
peers = []                       # optional in public mode
cluster_id = 1                   # the node must be started with the matching preset
public_discovery = false
public_fallback = false          # always an error when true

[storage]
retention_hours = 168

[policy]
unknown_senders = "quarantine"
auto_trigger = false

[mcp_http]
enabled = false
bind = "127.0.0.1:8650"

[webhook]
enabled = false
"#
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str =
        "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV";

    fn private() -> DaemonConfig {
        let mut c = DaemonConfig::default();
        c.network.peers = vec![PEER.into()];
        c
    }

    fn err(c: &DaemonConfig) -> String {
        c.validate().unwrap_err().to_string()
    }

    #[test]
    fn defaults_are_private_and_need_peers() {
        let d = DaemonConfig::default();
        assert_eq!(d.network.mode, Mode::Private);
        assert!(!d.network.public_discovery && !d.network.public_fallback);
        assert!(!d.policy.auto_trigger);
        assert!(!d.mcp_http.enabled && !d.webhook.enabled);
        assert!(err(&d).contains("network.peers"));
        private().validate().unwrap();
    }

    #[test]
    fn public_requires_the_flag_and_flags_are_checked() {
        let mut c = private();
        c.network.mode = Mode::Public;
        assert!(err(&c).contains("i_understand_public"));
        c.network.i_understand_public = true;
        c.validate().unwrap();
        c.network.public_fallback = true;
        assert!(err(&c).contains("public_fallback"));
        let mut p = private();
        p.network.public_discovery = true;
        assert!(err(&p).contains("public_discovery"));
        p.network.public_fallback = true;
        assert!(err(&p).contains("public_fallback"));
    }

    #[test]
    fn private_mode_surfaces_transport_errors() {
        let mut c = private();
        c.network.node_url = "http://8.8.8.8:8645".into();
        assert!(err(&c).contains("network:"));
        let mut c = private();
        c.network.cluster_id = 1;
        assert!(err(&c).contains("public preset"));
        let mut c = private();
        c.network.peers = vec!["/ip4/8.8.8.8/tcp/60000/p2p/16Uiu2HAmX".into()];
        assert!(err(&c).contains("network:"));
        let mut c = private();
        c.network.peers = vec!["not-a-multiaddr".into()];
        assert!(err(&c).contains("network:"));
    }

    #[test]
    fn engine_errors_are_surfaced() {
        let mut c = private();
        c.delivery.max_attempts = 0;
        assert!(err(&c).contains("engine:") && err(&c).contains("max_attempts"));
    }

    #[test]
    fn mcp_http_bind_must_be_loopback() {
        let mut c = private();
        for bad in [
            "0.0.0.0:8650",
            "192.168.1.5:8650",
            "10.0.0.1:1",
            "[::]:8650",
            "nonsense",
        ] {
            c.mcp_http.bind = bad.into();
            assert!(err(&c).contains("mcp_http.bind"), "{bad}");
        }
        for ok in ["127.0.0.1:0", "127.0.0.1:8650", "[::1]:8650"] {
            c.mcp_http.bind = ok.into();
            c.validate().unwrap();
        }
    }

    #[test]
    fn webhook_matrix() {
        let mut c = private();
        c.webhook.enabled = true;
        c.webhook.secret_file = "webhook.secret".into();
        c.webhook.url = "http://127.0.0.1:9000/hook".into();
        c.validate().unwrap();
        for bad in [
            "http://8.8.8.8/hook",
            "http://example.com/hook",
            "http://169.254.169.254/latest/meta-data",
            "http://[fe80::1]/x",
            "http://0.0.0.0/x",
            "http://224.0.0.1/x",
            "ftp://127.0.0.1/x",
            "file:///etc/passwd",
            "http://user:pw@127.0.0.1/x",
            "",
            "garbage",
        ] {
            c.webhook.url = bad.into();
            assert!(c.validate().is_err(), "{bad}");
        }
        // allow_remote opens public names/IPs but never link-local or metadata.
        c.webhook.allow_remote = true;
        for ok in ["https://example.com/hook", "http://8.8.8.8/hook"] {
            c.webhook.url = ok.into();
            c.validate().unwrap();
        }
        for bad in [
            "http://169.254.169.254/x",
            "http://[fe80::1]/x",
            "http://0.0.0.0/x",
        ] {
            c.webhook.url = bad.into();
            assert!(c.validate().is_err(), "{bad}");
        }
        c.webhook.url = "http://127.0.0.1/x".into();
        c.webhook.secret_file.clear();
        assert!(err(&c).contains("secret_file"));
        c.webhook.secret_file = "s".into();
        c.webhook.events = vec!["bogus".into()];
        assert!(err(&c).contains("events"));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(DaemonConfig::parse("[network]\nnope = 1\n").is_err());
        assert!(DaemonConfig::parse("[mystery]\nx = 1\n").is_err());
        assert!(DaemonConfig::parse("[policy]\nunknown_senders = \"maybe\"\n").is_err());
        assert!(DaemonConfig::parse("[network]\nmode = \"hybrid\"\n").is_err());
    }

    #[test]
    fn samples_parse_and_validate() {
        DaemonConfig::parse_validated(&sample_private_config()).unwrap();
        DaemonConfig::parse_validated(&sample_public_config()).unwrap();
        let empty = render_private_config("http://127.0.0.1:8645", &[]);
        let c = DaemonConfig::parse(&empty).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn mapping_to_node_and_transport_configs() {
        let mut c = private();
        c.policy.auto_trigger = true;
        let n = c.to_node_config();
        assert!(n.policy.auto_trigger);
        assert_eq!(n.network_mode, "private");
        let t = c.to_logos_config();
        assert_eq!(t.static_peers, vec![PEER.to_owned()]);
        assert_eq!(t.cluster_id, 66);
        assert_eq!(t.effective_allowed_peer_ids().len(), 1);
    }
}
