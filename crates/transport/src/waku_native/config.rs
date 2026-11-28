//! Configuration and fail-closed validation for [`super::NativeWakuTransport`]
//! and [`super::NativeWakuRelay`].

use std::path::PathBuf;
use std::time::Duration;

use libp2p::identity::{self, Keypair};
use libp2p::{Multiaddr, PeerId};
use serde::Deserialize;

use crate::waku_common::{
    check_peer_addr_private, check_peer_addr_public_audited, de_duration, peer_id_of_multiaddr,
    static_peer_shape_ok, valid_peer_id, NetworkMode, MAX_HISTORY_PAGE_SIZE,
    PUBLIC_PRESET_CLUSTER_IDS,
};
use crate::TransportError;

fn protocol(msg: impl Into<String>) -> TransportError {
    TransportError::Protocol(msg.into())
}

/// Parses a 32-byte hex-encoded secp256k1 private key (compatible with nwaku's
/// `--nodekey`), or generates an ephemeral keypair when `None`.
pub fn keypair_from_hex_or_random(hex_key: Option<&str>) -> Result<Keypair, TransportError> {
    match hex_key {
        None => Ok(Keypair::generate_secp256k1()),
        Some(h) => {
            let s = h.trim().strip_prefix("0x").unwrap_or(h.trim());
            if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(protocol(
                    "node_key_hex must be 64 hexadecimal characters (32-byte secp256k1 key)",
                ));
            }
            let mut raw = [0u8; 32];
            for (i, b) in raw.iter_mut().enumerate() {
                *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                    .map_err(|_| protocol("invalid hex in node_key_hex"))?;
            }
            let sk = identity::secp256k1::SecretKey::try_from_bytes(raw)
                .map_err(|e| protocol(format!("invalid secp256k1 node key: {e}")))?;
            Ok(Keypair::from(identity::secp256k1::Keypair::from(sk)))
        }
    }
}

/// Generates a fresh 32-byte secp256k1 node key and returns `(hex_key, peer_id)`.
pub fn generate_node_key() -> (String, PeerId) {
    let kp = identity::secp256k1::Keypair::generate();
    let bytes = kp.secret().to_bytes();
    let hex_key = crate::waku_common::hex(&bytes);
    let peer_id = PeerId::from(Keypair::from(kp).public());
    (hex_key, peer_id)
}

/// Parsed and validated peer address + libp2p [`PeerId`].
#[derive(Clone, Debug)]
pub(crate) struct ValidatedPeer {
    pub peer_id: PeerId,
    pub dial_addr: Multiaddr,
}

/// Configuration for [`super::NativeWakuTransport`].
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NativeWakuConfig {
    /// Private (default, fail closed) or public.
    pub mode: NetworkMode,
    /// Private mode: peer IDs the client may connect to. Derived from
    /// `static_peers` when empty.
    pub allowed_peer_ids: Vec<String>,
    /// Waku cluster id of the deployment.
    pub cluster_id: u16,
    /// Shard index (only 0 is supported).
    pub shard: u16,
    /// Number of shards (only 1 is supported).
    pub num_shards: u16,
    /// Static peer multiaddrs ending in `/p2p/<peerId>`.
    pub static_peers: Vec<String>,
    /// Optional explicit Store peer multiaddr.
    pub store_peer: Option<String>,
    /// Only valid with `mode = public`: enforce the peer allowlist preventively.
    pub enforce_peer_allowlist: bool,
    /// Optional local listen multiaddrs for this client (default: outbound-only).
    pub listen_addrs: Vec<String>,
    /// Optional 64-hex-char secp256k1 node key (ephemeral random key if unset).
    pub node_key_hex: Option<String>,
    /// Timeout for Store v3 / control RPC requests.
    #[serde(deserialize_with = "de_duration")]
    pub request_timeout: Duration,
    /// Store page size (1..=100).
    pub history_page_size: u32,
    /// Maximum encoded WakuMessage size in bytes (default 153600).
    pub max_message_bytes: usize,
    /// Interval between redial attempts to disconnected static peers.
    #[serde(deserialize_with = "de_duration")]
    pub redial_interval: Duration,
    /// Maximum queued live inbound frames per subscribed content topic.
    pub max_topic_queue: usize,
}

impl Default for NativeWakuConfig {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Private,
            allowed_peer_ids: Vec::new(),
            cluster_id: 66,
            shard: 0,
            num_shards: 1,
            static_peers: Vec::new(),
            store_peer: None,
            enforce_peer_allowlist: false,
            listen_addrs: Vec::new(),
            node_key_hex: None,
            request_timeout: Duration::from_secs(5),
            history_page_size: MAX_HISTORY_PAGE_SIZE,
            max_message_bytes: 153_600,
            redial_interval: Duration::from_secs(3),
            max_topic_queue: 2048,
        }
    }
}

pub(crate) struct ValidatedNativeConfig {
    pub allowed_peers: Vec<PeerId>,
    pub static_peers: Vec<ValidatedPeer>,
    pub store_peer: Option<ValidatedPeer>,
    pub listen_addrs: Vec<Multiaddr>,
}

fn parse_peer_multiaddr(s: &str) -> Result<ValidatedPeer, TransportError> {
    let full: Multiaddr = s
        .parse()
        .map_err(|e| protocol(format!("invalid peer multiaddr {s:?}: {e}")))?;
    let mut dial_addr = Multiaddr::empty();
    let mut peer_id = None;
    for proto in full.iter() {
        match proto {
            libp2p::multiaddr::Protocol::P2p(id) => {
                if peer_id.is_some() {
                    return Err(protocol("multiaddr must contain at most one /p2p/<peerId>"));
                }
                peer_id = Some(id);
            }
            other => dial_addr.push(other),
        }
    }
    let peer_id = peer_id.ok_or_else(|| protocol("peer multiaddr must end in /p2p/<peerId>"))?;
    Ok(ValidatedPeer { peer_id, dial_addr })
}

impl NativeWakuConfig {
    /// The allowlist in force: `allowed_peer_ids`, or when empty, the peer ids
    /// of `static_peers`.
    pub fn effective_allowed_peer_ids(&self) -> Vec<String> {
        if self.allowed_peer_ids.is_empty() {
            self.static_peers
                .iter()
                .filter_map(|p| peer_id_of_multiaddr(p).map(str::to_string))
                .collect()
        } else {
            self.allowed_peer_ids.clone()
        }
    }

    /// True when the peer-id allowlist is enforced: always in private mode, and
    /// in public mode when `enforce_peer_allowlist` is true.
    pub fn audits_peers(&self) -> bool {
        self.mode == NetworkMode::Private || self.enforce_peer_allowlist
    }

    /// Pubsub topic `/waku/2/rs/<cluster_id>/<shard>`.
    pub fn pubsub_topic(&self) -> String {
        format!("/waku/2/rs/{}/{}", self.cluster_id, self.shard)
    }

    /// Validates configuration fail-closed and parses multiaddrs / peer IDs.
    pub fn validate(&self) -> Result<(), TransportError> {
        self.validate_parsed().map(|_| ())
    }

    pub(crate) fn validate_parsed(&self) -> Result<ValidatedNativeConfig, TransportError> {
        if self.mode == NetworkMode::Private && self.enforce_peer_allowlist {
            return Err(protocol(
                "enforce_peer_allowlist is only valid with mode = public: private mode \
                 always enforces the allowlist (remove the setting)",
            ));
        }
        match self.mode {
            NetworkMode::Private => {
                if PUBLIC_PRESET_CLUSTER_IDS.contains(&self.cluster_id) {
                    return Err(TransportError::Isolation(format!(
                        "private mode: cluster id {} selects a public preset",
                        self.cluster_id
                    )));
                }
                let allowed = self.effective_allowed_peer_ids();
                if allowed.is_empty() {
                    return Err(TransportError::Isolation(
                        "private mode requires a non-empty allowed_peer_ids (or static_peers)"
                            .into(),
                    ));
                }
                if let Some(bad) = allowed.iter().find(|p| !valid_peer_id(p)) {
                    return Err(protocol(format!(
                        "invalid peer id in allowed_peer_ids: {:?}",
                        bad.chars().take(40).collect::<String>()
                    )));
                }
                if let Some(sp) = &self.store_peer {
                    check_peer_addr_private("store_peer", sp, &allowed)?;
                }
                for sp in &self.static_peers {
                    if !static_peer_shape_ok(sp) {
                        return Err(protocol(
                            "static_peers must be multiaddrs ending in /p2p/<id>",
                        ));
                    }
                    check_peer_addr_private("static_peers entry", sp, &allowed)?;
                }
            }
            NetworkMode::Public if self.enforce_peer_allowlist => {
                if PUBLIC_PRESET_CLUSTER_IDS.contains(&self.cluster_id) {
                    return Err(TransportError::Isolation(format!(
                        "enforce_peer_allowlist: cluster id {} selects a public preset",
                        self.cluster_id
                    )));
                }
                let allowed = self.effective_allowed_peer_ids();
                if allowed.is_empty() {
                    return Err(TransportError::Isolation(
                        "enforce_peer_allowlist needs at least one peer".into(),
                    ));
                }
                if let Some(sp) = &self.store_peer {
                    check_peer_addr_public_audited("store_peer", sp, &allowed)?;
                }
                for sp in &self.static_peers {
                    if !static_peer_shape_ok(sp) {
                        return Err(protocol(
                            "static_peers must be multiaddrs ending in /p2p/<id>",
                        ));
                    }
                    check_peer_addr_public_audited("static_peers entry", sp, &allowed)?;
                }
            }
            NetworkMode::Public => {
                if !self.allowed_peer_ids.is_empty() {
                    return Err(protocol(
                        "allowed_peer_ids is set in public mode without enforce_peer_allowlist = true",
                    ));
                }
                if self.static_peers.iter().any(|p| !static_peer_shape_ok(p)) {
                    return Err(protocol(
                        "static_peers must be multiaddrs ending in /p2p/<id>",
                    ));
                }
            }
        }
        if self.num_shards != 1 || self.shard != 0 {
            return Err(protocol(
                "only a single-shard network (num_shards = 1, shard = 0) is supported",
            ));
        }
        if self.history_page_size == 0 || self.history_page_size > MAX_HISTORY_PAGE_SIZE {
            return Err(protocol("history_page_size must be 1..=100"));
        }
        if self.request_timeout.is_zero() {
            return Err(protocol("request_timeout must be positive"));
        }
        if self.max_message_bytes < 1024 || self.max_message_bytes > 16 * 1024 * 1024 {
            return Err(protocol(
                "max_message_bytes must be between 1024 and 16777216",
            ));
        }
        if self.max_topic_queue == 0 {
            return Err(protocol("max_topic_queue must be positive"));
        }
        // Validate node_key_hex if present.
        if let Some(h) = &self.node_key_hex {
            let _ = keypair_from_hex_or_random(Some(h))?;
        }
        let mut allowed_peers = Vec::new();
        for id_str in self.effective_allowed_peer_ids() {
            let pid: PeerId = id_str
                .parse()
                .map_err(|e| protocol(format!("invalid libp2p peer id {id_str:?}: {e}")))?;
            if !allowed_peers.contains(&pid) {
                allowed_peers.push(pid);
            }
        }
        let mut static_peers = Vec::with_capacity(self.static_peers.len());
        for sp in &self.static_peers {
            static_peers.push(parse_peer_multiaddr(sp)?);
        }
        let store_peer = match &self.store_peer {
            Some(sp) => Some(parse_peer_multiaddr(sp)?),
            None => None,
        };
        let mut listen_addrs = Vec::with_capacity(self.listen_addrs.len());
        for la in &self.listen_addrs {
            let ma: Multiaddr = la
                .parse()
                .map_err(|e| protocol(format!("invalid listen multiaddr {la:?}: {e}")))?;
            listen_addrs.push(ma);
        }
        Ok(ValidatedNativeConfig {
            allowed_peers,
            static_peers,
            store_peer,
            listen_addrs,
        })
    }
}

/// Configuration for [`super::NativeWakuRelay`], the standalone pure-Rust Waku v2
/// Relay + Store v3 server.
#[derive(Clone, Debug)]
pub struct NativeRelayConfig {
    /// Listen multiaddrs (default `["/ip4/127.0.0.1/tcp/60000"]`).
    pub listen_addrs: Vec<String>,
    /// Waku cluster id (default 66).
    pub cluster_id: u16,
    /// Waku shard index (default 0).
    pub shard: u16,
    /// Optional 64-hex-char secp256k1 node key (ephemeral random key if unset).
    pub node_key_hex: Option<String>,
    /// Optional preventive peer-ID allowlist (empty = admit any peer that passes
    /// Metadata validation; non-empty = only listed peer IDs may connect).
    pub allowed_peer_ids: Vec<String>,
    /// SQLite database path for Store v3 persistence; `None` uses in-memory SQLite.
    pub store_db_path: Option<PathBuf>,
    /// Store retention horizon in seconds (default 7 days = 604800).
    pub retention_seconds: u64,
    /// Maximum stored frames (default 100000).
    pub retention_capacity: usize,
    /// Maximum accepted encoded WakuMessage size in bytes (default 153600).
    pub max_message_bytes: usize,
    /// Maximum allowed absolute clock skew for Store archiving (default 20 s).
    pub max_clock_skew_seconds: i64,
}

impl Default for NativeRelayConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/60000".to_owned()],
            cluster_id: 66,
            shard: 0,
            node_key_hex: None,
            allowed_peer_ids: Vec::new(),
            store_db_path: None,
            retention_seconds: 604_800,
            retention_capacity: 100_000,
            max_message_bytes: 153_600,
            max_clock_skew_seconds: 20,
        }
    }
}

impl NativeRelayConfig {
    /// Pubsub topic `/waku/2/rs/<cluster_id>/<shard>`.
    pub fn pubsub_topic(&self) -> String {
        format!("/waku/2/rs/{}/{}", self.cluster_id, self.shard)
    }

    /// Validates the relay configuration.
    pub fn validate(&self) -> Result<(Vec<Multiaddr>, Vec<PeerId>), TransportError> {
        if self.listen_addrs.is_empty() {
            return Err(protocol("relay requires at least one listen address"));
        }
        let mut addrs = Vec::with_capacity(self.listen_addrs.len());
        for a in &self.listen_addrs {
            addrs.push(
                a.parse::<Multiaddr>()
                    .map_err(|e| protocol(format!("invalid listen_addr {a:?}: {e}")))?,
            );
        }
        let mut allowed = Vec::with_capacity(self.allowed_peer_ids.len());
        for p in &self.allowed_peer_ids {
            allowed.push(
                p.parse::<PeerId>()
                    .map_err(|e| protocol(format!("invalid allowed peer id {p:?}: {e}")))?,
            );
        }
        if self.max_message_bytes < 1024 || self.max_message_bytes > 16 * 1024 * 1024 {
            return Err(protocol(
                "max_message_bytes must be between 1024 and 16777216",
            ));
        }
        Ok((addrs, allowed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_mode_fails_closed_on_public_ip_dns_or_empty_peers() {
        let (_, pid) = generate_node_key();
        let pid_s = pid.to_string();
        assert!(NativeWakuConfig::default().validate().is_err());
        for bad in [
            format!("/ip4/8.8.8.8/tcp/60000/p2p/{pid_s}"),
            format!("/dns4/relay.example.com/tcp/60000/p2p/{pid_s}"),
            "/ip4/127.0.0.1/tcp/60000".into(),
        ] {
            let c = NativeWakuConfig {
                static_peers: vec![bad.clone()],
                ..Default::default()
            };
            assert!(c.validate().is_err(), "{bad}");
        }
        let ok = NativeWakuConfig {
            static_peers: vec![format!("/ip4/127.0.0.1/tcp/60000/p2p/{pid_s}")],
            ..Default::default()
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn keypair_hex_roundtrip_gives_same_peer_id() {
        let (hex, pid) = generate_node_key();
        let kp = keypair_from_hex_or_random(Some(&hex)).unwrap();
        assert_eq!(PeerId::from(kp.public()), pid);
        assert!(pid.to_string().starts_with("16Uiu2HA"), "{pid}");
    }
}
