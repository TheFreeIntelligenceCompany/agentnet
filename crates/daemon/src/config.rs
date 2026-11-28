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
    DeliveryConfig, DiscoveryConfig, NodeConfig, PolicyConfig, StorageConfig, TriggerConfig,
};
use agentnet_transport::logos_rest::{LogosRestConfig, NetworkMode};
use agentnet_transport::waku_native::NativeWakuConfig;
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

/// `network.backend`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportBackend {
    /// Talk to an external Logos Delivery (`nwaku`) sidecar node over REST (default).
    #[default]
    LogosRest,
    /// Embedded pure-Rust `libp2p` Waku v2 transport (zero Docker sidecar required).
    Native,
}

impl TransportBackend {
    /// Human-readable backend identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            TransportBackend::LogosRest => "logos_rest",
            TransportBackend::Native => "native",
        }
    }
}

/// `[network]`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkSection {
    /// Transport backend: `logos_rest` (external sidecar, default) or `native`
    /// (embedded pure-Rust libp2p Waku v2).
    pub backend: TransportBackend,
    /// `private` (default) or `public` (needs `i_understand_public = true`).
    pub mode: Mode,
    /// REST endpoint of the local Logos Delivery node (used only with
    /// `backend = "logos_rest"`; loopback / private only in private mode).
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
    /// Only with `mode = "public"`: keep the peer-id allowlist audit for your
    /// own relay on a public address (peers may be public IPs or dns4/dns6
    /// names). Needs `peers`. Private mode always audits and rejects this key.
    pub enforce_peer_allowlist: bool,
    /// Optional libp2p listen multiaddrs when `backend = "native"` (default:
    /// outbound-only client).
    pub listen_addrs: Vec<String>,
    /// Optional path to a mode-0600 file holding a 64-hex secp256k1 node key
    /// when `backend = "native"` (relative paths are relative to the data dir).
    pub node_key_file: Option<String>,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            backend: TransportBackend::LogosRest,
            mode: Mode::Private,
            node_url: "http://127.0.0.1:8645".to_owned(),
            peers: Vec::new(),
            cluster_id: 66,
            public_discovery: false,
            public_fallback: false,
            i_understand_public: false,
            store_peer: None,
            enforce_peer_allowlist: false,
            listen_addrs: Vec::new(),
            node_key_file: None,
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
    /// `[discovery]` (opt-in, off by default)
    pub discovery: DiscoveryConfig,
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
        use std::io::Read;
        let io = |e| DaemonError::io(format!("reading {}", path.display()), e);
        let mut f = std::fs::File::open(path).map_err(io)?;
        let md = f.metadata().map_err(io)?;
        if !md.is_file() {
            return Err(cfg_err(format!("{} is not a regular file", path.display())));
        }
        if md.len() > MAX_CONFIG_BYTES {
            return Err(cfg_err(format!("{} is too large", path.display())));
        }
        let mut buf = Vec::new();
        (&mut f)
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(io)?;
        if buf.len() as u64 > MAX_CONFIG_BYTES {
            return Err(cfg_err(format!("{} is too large", path.display())));
        }
        let text = String::from_utf8(buf)
            .map_err(|_| cfg_err(format!("{} is not valid UTF-8", path.display())))?;
        Self::parse_validated(&text)
    }

    /// Engine configuration derived from this file.
    pub fn to_node_config(&self) -> NodeConfig {
        NodeConfig {
            policy: self.policy.clone(),
            triggers: self.triggers.clone(),
            delivery: self.delivery.clone(),
            storage: self.storage.clone(),
            discovery: self.discovery.clone(),
            network_mode: self.network.mode.as_str().to_owned(),
            isolation_audited: self.network.mode == Mode::Private
                || self.network.enforce_peer_allowlist,
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
            enforce_peer_allowlist: self.network.enforce_peer_allowlist,
            ..LogosRestConfig::default()
        }
    }

    /// Native libp2p Waku v2 transport configuration derived from this file.
    pub fn to_native_config(&self, node_key_hex: Option<String>) -> NativeWakuConfig {
        NativeWakuConfig {
            mode: match self.network.mode {
                Mode::Private => NetworkMode::Private,
                Mode::Public => NetworkMode::Public,
            },
            cluster_id: self.network.cluster_id,
            static_peers: self.network.peers.clone(),
            store_peer: self.network.store_peer.clone(),
            enforce_peer_allowlist: self.network.enforce_peer_allowlist,
            listen_addrs: self.network.listen_addrs.clone(),
            node_key_hex,
            ..NativeWakuConfig::default()
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
                if n.enforce_peer_allowlist {
                    return Err(cfg_err(
                        "network.enforce_peer_allowlist is only valid with mode = \"public\": \
                         private mode always audits the allowlist and accepts only literal \
                         private IPs. To use your own relay on a public address, set \
                         mode = \"public\", i_understand_public = true and \
                         enforce_peer_allowlist = true",
                    ));
                }
            }
            Mode::Public => {
                if !n.i_understand_public {
                    return Err(cfg_err(
                        "network.mode = \"public\" requires network.i_understand_public = true",
                    ));
                }
                if n.enforce_peer_allowlist && n.public_discovery {
                    return Err(cfg_err(
                        "network.public_discovery = true is not allowed with enforce_peer_allowlist = true",
                    ));
                }
                if n.enforce_peer_allowlist && n.peers.is_empty() {
                    return Err(cfg_err(
                        "network.enforce_peer_allowlist = true needs network.peers: the \
                         allowlist is the peer ids of the listed peers (multiaddrs such as \
                         /dns4/<host>/tcp/443/wss/p2p/<peerId>)",
                    ));
                }
            }
        }
        self.validate_mcp_http()?;
        self.validate_webhook()?;
        self.to_node_config()
            .validate()
            .map_err(|e| cfg_err(format!("engine: {e}")))?;
        match n.backend {
            TransportBackend::LogosRest => {
                if !n.listen_addrs.is_empty() || n.node_key_file.is_some() {
                    return Err(cfg_err(
                        "network.listen_addrs and network.node_key_file are only valid with \
                         network.backend = \"native\"",
                    ));
                }
                self.to_logos_config()
                    .validate()
                    .map_err(|e| cfg_err(format!("network: {e}")))?;
            }
            TransportBackend::Native => {
                self.to_native_config(None)
                    .validate()
                    .map_err(|e| cfg_err(format!("network: {e}")))?;
            }
        }
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
        const MAX_RETRY_MS: u64 = 3_600_000;
        if w.retry_base_ms == 0 || w.retry_max_ms < w.retry_base_ms || w.retry_max_ms > MAX_RETRY_MS
        {
            return Err(cfg_err(
                "webhook.retry_base_ms must be > 0 and <= retry_max_ms <= 3600000",
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

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

fn render_config_body(node_url: &str, peers: &[String], public_relay: bool) -> String {
    let header = if public_relay {
        "# agentnet.toml -- PUBLIC mode with the peer allowlist audit kept (own relay on a\n\
         # public address or wss edge). See docs/configuration.md and docs/relay-setup.md.\n\
         #\n\
         # The peer allowlist audit is detective, not preventive; the relay's firewall or\n\
         # TLS edge is the access control. Public peer discovery and public fallback stay\n\
         # off. (The optional [discovery] section below is something else: it lists\n\
         # capability adverts on YOUR relay, off by default.)"
    } else {
        "# agentnet.toml -- PRIVATE mode (the default). See docs/configuration.md.\n\
         #\n\
         # Private mode fails closed: the Logos Delivery node must be on a loopback or\n\
         # private address, connected only to the peers listed here, and on a private\n\
         # cluster id. Public peer discovery and public fallback do not exist. (The\n\
         # optional [discovery] section below is something else: it lists capability\n\
         # adverts on YOUR relay, off by default.)"
    };
    let mode = if public_relay { "public" } else { "private" };
    let public_flags = if public_relay {
        "i_understand_public = true     # you chose public mode (init --public-relay)\n\
         enforce_peer_allowlist = true  # audit the node's peers against the ids in `peers`"
    } else {
        "i_understand_public = false"
    };
    let node_url_toml = toml_str(node_url);
    let peers_line = if peers.is_empty() {
        "peers = []   # REQUIRED in private mode: add your relay's multiaddr, e.g. \"/ip4/10.0.0.5/tcp/60000/p2p/16Uiu2HAm...\"".to_owned()
    } else {
        let items: Vec<String> = peers.iter().map(|p| toml_str(p)).collect();
        format!("peers = [{}]", items.join(", "))
    };
    format!(
        r#"{header}

[network]
mode = "{mode}"
# REST endpoint of YOUR local Logos Delivery node (loopback / RFC1918 / 100.64.0.0/10 only).
node_url = {node_url_toml}
# Static peers: multiaddrs of your own relay/store node(s), ending in /p2p/<peerId>.
{peers_line}
# Cluster ids 1, 2, 3 and 16 select public presets and are rejected.
cluster_id = 66
public_discovery = false   # true is a config error in private mode
public_fallback = false    # true is always a config error
{public_flags}

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

# Optional capability discovery (docs/discovery.md). OFF by default: nothing is
# subscribed or published and the discovery tools return policy_denied.
# Advertisements are PLAINTEXT: every node on your relay can read them. Only
# the topic names listed here can be used; the topics exist only on this relay.
[discovery]
enabled = false
topics = []                      # e.g. ["general"]; names are [a-z0-9-]{{1,32}}
max_records = 500
max_advert_ttl_s = 86400
default_advert_ttl_s = 3600
republish_interval_s = 900
max_capabilities = 16

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

/// The audited public-relay sample (`docs/examples/public-relay.toml`, matching
/// `agentnet init --public-relay`).
pub fn sample_public_relay_config() -> String {
    render_public_relay_config(
        "http://127.0.0.1:8645",
        &[
            "/dns4/relay.example.org/tcp/443/wss/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV"
                .to_owned(),
        ],
    )
}

/// Render the private-mode sample with the given node URL and peers. With no
/// peers the file is written with `peers = []` and `serve` refuses to start
/// until one is added (fail closed).
pub fn render_private_config(node_url: &str, peers: &[String]) -> String {
    render_config_body(node_url, peers, false)
}

/// Render the audited public-mode config for your own relay on a public address
/// or a wss/TLS edge (`agentnet init --public-relay`): `mode = "public"`,
/// `i_understand_public = true`, `enforce_peer_allowlist = true`.
pub fn render_public_relay_config(node_url: &str, peers: &[String]) -> String {
    render_config_body(node_url, peers, true)
}

/// Render the native pure-Rust libp2p Waku v2 config (`agentnet init --native`).
pub fn render_native_config(peers: &[String], public_relay: bool) -> String {
    let header = if public_relay {
        "# agentnet.toml -- NATIVE Rust libp2p Waku v2 transport (PUBLIC audited mode).\n\
         # Zero Docker sidecar required. See docs/adr/0005-native-waku-transport.md."
    } else {
        "# agentnet.toml -- NATIVE Rust libp2p Waku v2 transport (PRIVATE mode).\n\
         # Zero Docker sidecar required: embedded libp2p with preventive peer allowlist\n\
         # and zero DNS egress. See docs/adr/0005-native-waku-transport.md."
    };
    let mode = if public_relay { "public" } else { "private" };
    let public_flags = if public_relay {
        "i_understand_public = true     # you chose public mode (init --public-relay)\n\
         enforce_peer_allowlist = true  # preventively enforce the peer allowlist from `peers`"
    } else {
        "i_understand_public = false"
    };
    let peers_line = if peers.is_empty() {
        "peers = []   # REQUIRED in private mode: add your relay's multiaddr (e.g. from `agentnet relay serve`)".to_owned()
    } else {
        let items: Vec<String> = peers.iter().map(|p| toml_str(p)).collect();
        format!("peers = [{}]", items.join(", "))
    };
    format!(
        r#"{header}

[network]
backend = "native"
mode = "{mode}"
# Static peers: multiaddrs of your own relay/store node(s), ending in /p2p/<peerId>.
{peers_line}
# Cluster ids 1, 2, 3 and 16 select public presets and are rejected.
cluster_id = 66
public_discovery = false
public_fallback = false
{public_flags}

[storage]
retention_hours = 168

[policy]
unknown_senders = "quarantine"
auto_trigger = false

[triggers]
allowed_sessions = []
max_active = 32
max_matches_per_minute = 60
default_lifetime_s = 3600
max_lifetime_hours = 24

[discovery]
enabled = false
topics = []
max_records = 500
max_advert_ttl_s = 86400
default_advert_ttl_s = 3600
republish_interval_s = 900
max_capabilities = 16

[mcp_http]
enabled = false
bind = "127.0.0.1:8650"

[webhook]
enabled = false
url = ""
secret_file = ""
allow_remote = false
timeout_ms = 5000
max_attempts = 5
events = ["trigger.matched"]
"#
    )
}

/// Render and validate the config `agentnet init` is about to write, supporting
/// both `logos_rest` (default) and `native` backends.
pub fn render_init_config_with_backend(
    node_url: &str,
    peers: &[String],
    public_relay: bool,
    native: bool,
) -> Result<String, DaemonError> {
    if !native {
        return render_init_config(node_url, peers, public_relay);
    }
    if public_relay {
        if peers.is_empty() {
            return Err(cfg_err(
                "--public-relay needs at least one --peer (the relay's multiaddr ending in \
                 /p2p/<peerId>): the allowlist is the peer ids of the listed peers",
            ));
        }
        let text = render_native_config(peers, true);
        DaemonConfig::parse_validated(&text)?;
        return Ok(text);
    }
    let text = render_native_config(peers, false);
    if !peers.is_empty() {
        if let Err(DaemonError::Config(why)) = DaemonConfig::parse_validated(&text) {
            return Err(cfg_err(format!(
                "this configuration is not acceptable in private mode ({why}). Choose one: \
                 (1) use a relay on a private address (loopback, RFC 1918, 100.64.0.0/10, e.g. \
                 --peer /ip4/127.0.0.1/tcp/60000/p2p/<peerId>), or (2) re-run with --public-relay \
                 for your own relay on a public address"
            )));
        }
    }
    Ok(text)
}

/// Render and validate the config `agentnet init` is about to write. With no
/// peers the `node_url` is still validated against private mode, while the
/// intentionally incomplete `peers = []` file is written for the operator to
/// fill in. A peer that private mode rejects fails here, before anything is
/// written, naming both ways forward; the mode is never switched silently.
pub fn render_init_config(
    node_url: &str,
    peers: &[String],
    public_relay: bool,
) -> Result<String, DaemonError> {
    if public_relay {
        if peers.is_empty() {
            return Err(cfg_err(
                "--public-relay needs at least one --peer (the relay's multiaddr ending in \
                 /p2p/<peerId>): the allowlist is the peer ids of the listed peers",
            ));
        }
        let text = render_public_relay_config(node_url, peers);
        DaemonConfig::parse_validated(&text)?;
        return Ok(text);
    }
    let text = render_private_config(node_url, peers);
    if peers.is_empty() {
        // Still validate `node_url` in private mode using a dummy private peer.
        let probe = render_private_config(
            node_url,
            &[
                "/ip4/127.0.0.1/tcp/60000/p2p/16Uiu2HAmPlaceholderPeerId1111111111111111111111"
                    .to_owned(),
            ],
        );
        DaemonConfig::parse_validated(&probe)?;
    } else if let Err(DaemonError::Config(why)) = DaemonConfig::parse_validated(&text) {
        return Err(cfg_err(format!(
            "this configuration is not acceptable in private mode ({why}). Choose one: \
             (1) use a relay on a private address (loopback, RFC 1918, 100.64.0.0/10, e.g. \
             --peer /ip4/10.0.0.5/tcp/60000/p2p/<peerId>), or (2) your relay is reached \
             over a public IP or DNS name: re-run with --public-relay to write the audited \
             public mode (mode = \"public\", i_understand_public = true, \
             enforce_peer_allowlist = true; docs/relay-setup.md, \"Your own relay on a \
             public address\")"
        )));
    }
    Ok(text)
}

/// The public-mode sample (`docs/examples/public.toml`). UNTESTED against any
/// public network.
pub fn sample_public_config() -> String {
    r#"# agentnet.toml -- PUBLIC mode. UNTESTED against any public network.
#
# Public mode must be chosen explicitly. It skips the peer allowlist audit, so
# the node may be connected to anyone. (To keep the audit for your OWN relay on
# a public address, set enforce_peer_allowlist = true and list the relay in
# peers; see docs/relay-setup.md.) Public and private traffic are never
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
enforce_peer_allowlist = false   # true: audit peers against the ids in `peers` (needs peers)

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
        DaemonConfig::parse_validated(&sample_public_relay_config()).unwrap();
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
        assert!(!t.enforce_peer_allowlist);
    }

    const WSS: &str = "/dns4/relay.example.com/tcp/443/wss/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV";

    fn audited_public() -> DaemonConfig {
        let mut c = DaemonConfig::default();
        c.network.mode = Mode::Public;
        c.network.i_understand_public = true;
        c.network.enforce_peer_allowlist = true;
        c.network.cluster_id = 66;
        c.network.peers = vec![WSS.into()];
        c
    }

    #[test]
    fn node_config_reports_whether_isolation_is_audited() {
        assert!(private().to_node_config().isolation_audited);
        assert!(audited_public().to_node_config().isolation_audited);
        let mut plain = audited_public();
        plain.network.enforce_peer_allowlist = false;
        assert!(!plain.to_node_config().isolation_audited);
    }

    #[test]
    fn enforce_peer_allowlist_with_a_public_wss_relay() {
        let c = audited_public();
        c.validate().unwrap();
        let t = c.to_logos_config();
        assert!(t.enforce_peer_allowlist && t.audits_peers());
        assert_eq!(t.effective_allowed_peer_ids().len(), 1);
        let parsed = DaemonConfig::parse_validated(&format!(
            "[network]\nmode = \"public\"\ni_understand_public = true\nenforce_peer_allowlist = true\ncluster_id = 66\npeers = [\"{WSS}\"]\n"
        ))
        .unwrap();
        assert!(parsed.network.enforce_peer_allowlist);
    }

    #[test]
    fn enforce_peer_allowlist_rejections_are_actionable() {
        let mut c = private();
        c.network.enforce_peer_allowlist = true;
        let e = err(&c);
        assert!(
            e.contains("only valid with mode") && e.contains("i_understand_public"),
            "{e}"
        );
        let mut c = audited_public();
        c.network.peers.clear();
        assert!(err(&c).contains("needs network.peers"));
        let mut c = audited_public();
        c.network.peers = vec!["/dns4/r.example.com/tcp/443/p2p-circuit/p2p/16Uiu2HAmX".into()];
        assert!(err(&c).contains("network:"));
        let mut c = audited_public();
        c.network.cluster_id = 1;
        assert!(err(&c).contains("public preset"));
        // plain public mode keeps accepting the same peer without auditing it
        let mut c = audited_public();
        c.network.enforce_peer_allowlist = false;
        c.validate().unwrap();
        assert!(!c.to_logos_config().audits_peers());
        // private mode with a wss peer is still refused
        let mut c = private();
        c.network.peers = vec![WSS.into()];
        assert!(err(&c).contains("network:"));
    }
}
