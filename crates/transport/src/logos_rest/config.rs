//! Configuration and fail-closed validation for [`super::LogosRestTransport`].

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Deserializer};
use url::{Host, Url};

use crate::TransportError;

/// Cluster ids that make the node silently apply a public preset
/// (1 = Waku Network, 2 = logos.test, 3 = logos.dev, 16 = status.prod).
pub const PUBLIC_PRESET_CLUSTER_IDS: [u16; 4] = [1, 2, 3, 16];

/// Largest page the Store accepts.
pub const MAX_HISTORY_PAGE_SIZE: u32 = 100;

/// Whether the deployment is a closed private cluster or deliberately public.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Fail closed: loopback/private node URL, peer allowlist audited at runtime.
    #[default]
    Private,
    /// Explicit public mode: no allowlist audit. UNTESTED against any public network.
    Public,
}

fn de_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Secs(f64),
        Parts { secs: u64, nanos: u32 },
    }
    match Repr::deserialize(d)? {
        Repr::Secs(s) => Duration::try_from_secs_f64(s).map_err(serde::de::Error::custom),
        Repr::Parts { secs, nanos } => Ok(Duration::new(secs, nanos)),
    }
}

/// Configuration of the REST adapter. Durations deserialize from a number of
/// seconds (or a `{secs, nanos}` table).
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogosRestConfig {
    /// Base URL of the node's REST server, e.g. `http://127.0.0.1:8645`.
    pub node_url: String,
    /// Private (default, fail closed) or public.
    pub mode: NetworkMode,
    /// Private mode: peer IDs the node may be connected to. Must be non-empty.
    pub allowed_peer_ids: Vec<String>,
    /// Waku cluster id of the deployment.
    pub cluster_id: u16,
    /// Shard index. Only shard 0 of a single-shard network is supported.
    pub shard: u16,
    /// Number of shards in the network. Only 1 is supported (see crate docs).
    pub num_shards: u16,
    /// Timeout of every single HTTP request.
    #[serde(deserialize_with = "de_duration")]
    pub request_timeout: Duration,
    /// Store page size (1..=100).
    pub history_page_size: u32,
    /// Explicit Store peer multiaddr passed as `peerAddr` (private mode: must
    /// be a private IP and carry an allowlisted `/p2p/` id).
    pub store_peer: Option<String>,
    /// The node's `--max-msg-size` (default 153600).
    pub max_message_bytes: usize,
    /// Maximum age of a cached isolation audit.
    #[serde(deserialize_with = "de_duration")]
    pub audit_interval: Duration,
    /// Static peer multiaddrs (each ending in `/p2p/<id>`) that the adapter may
    /// ask the node to dial when no allowlisted peer is connected. In private
    /// mode each must be a literal private IP with an allowlisted id; if
    /// `allowed_peer_ids` is empty it is derived from these.
    pub static_peers: Vec<String>,
    /// Minimum time between redial attempts.
    #[serde(deserialize_with = "de_duration")]
    pub redial_interval: Duration,
}

impl Default for LogosRestConfig {
    fn default() -> Self {
        Self {
            node_url: "http://127.0.0.1:8645".to_string(),
            mode: NetworkMode::Private,
            allowed_peer_ids: Vec::new(),
            cluster_id: 66,
            shard: 0,
            num_shards: 1,
            request_timeout: Duration::from_secs(5),
            history_page_size: MAX_HISTORY_PAGE_SIZE,
            store_peer: None,
            max_message_bytes: 153_600,
            audit_interval: Duration::from_secs(15),
            static_peers: Vec::new(),
            redial_interval: Duration::from_secs(10),
        }
    }
}

/// Is `ip` loopback, RFC 1918 or CGNAT (100.64.0.0/10)?
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
}

/// Is `ip` IPv6 loopback, unique-local (fc00::/7), or an IPv4-mapped private v4?
pub fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(v4);
    }
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Is this URL host an address we accept in private mode? Names are never
/// resolved: only the literal `localhost` is accepted.
pub fn is_private_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(ip) => is_private_ipv4(*ip),
        Host::Ipv6(ip) => is_private_ipv6(*ip),
    }
}

fn protocol(msg: impl Into<String>) -> TransportError {
    TransportError::Protocol(msg.into())
}

fn valid_peer_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Extracts the last `/p2p/<id>` of a multiaddr.
pub(crate) fn peer_id_of_multiaddr(addr: &str) -> Option<&str> {
    let mut it = addr.split('/');
    let mut last = None;
    while let Some(seg) = it.next() {
        if seg == "p2p" {
            last = it.next();
        }
    }
    last.filter(|s| valid_peer_id(s))
}

fn check_peer_addr_private(
    what: &str,
    addr: &str,
    allowed: &[String],
) -> Result<(), TransportError> {
    let iso = |m: &str| TransportError::Isolation(format!("{what} rejected in private mode: {m}"));
    let mut segs = addr.split('/');
    if segs.next() != Some("") {
        return Err(protocol(format!(
            "{what} must be a multiaddr starting with '/'"
        )));
    }
    let ok = match (segs.next(), segs.next()) {
        (Some("ip4"), Some(a)) => a.parse::<Ipv4Addr>().map(is_private_ipv4).unwrap_or(false),
        (Some("ip6"), Some(a)) => a.parse::<Ipv6Addr>().map(is_private_ipv6).unwrap_or(false),
        _ => false,
    };
    if !ok {
        return Err(iso("address must be a literal private IP"));
    }
    match peer_id_of_multiaddr(addr) {
        Some(id) if allowed.iter().any(|a| a == id) => Ok(()),
        _ => Err(iso("peer id missing or not in allowed_peer_ids")),
    }
}

/// `/.../p2p/<id>` with the peer id as the final segment.
fn static_peer_shape_ok(addr: &str) -> bool {
    addr.len() <= 512
        && addr.starts_with('/')
        && addr.rsplit('/').nth(1) == Some("p2p")
        && peer_id_of_multiaddr(addr).is_some()
}

impl LogosRestConfig {
    /// The allowlist in force: `allowed_peer_ids`, or, when that is empty, the
    /// peer ids of `static_peers`.
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

    /// Validates the configuration and returns the parsed node URL.
    ///
    /// Isolation failures (public host, preset cluster id, empty allowlist,
    /// public store peer) are [`TransportError::Isolation`]; everything else is
    /// [`TransportError::Protocol`].
    pub fn validate(&self) -> Result<Url, TransportError> {
        let url = Url::parse(&self.node_url).map_err(|e| protocol(format!("bad node_url: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(protocol("node_url scheme must be http or https"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(protocol("node_url must not contain credentials"));
        }
        if url.query().is_some() || url.fragment().is_some() || url.path() != "/" {
            return Err(protocol(
                "node_url must be a bare origin (no path, query or fragment)",
            ));
        }
        let host = url.host().ok_or_else(|| protocol("node_url has no host"))?;
        let private = is_private_host(&host);
        match self.mode {
            NetworkMode::Private => {
                if !private {
                    return Err(TransportError::Isolation(
                        "private mode: node_url host must be loopback, RFC1918, 100.64.0.0/10, \
                         IPv6 loopback/ULA or the literal 'localhost' (names are not resolved)"
                            .into(),
                    ));
                }
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
            NetworkMode::Public => {
                if self.static_peers.iter().any(|p| !static_peer_shape_ok(p)) {
                    return Err(protocol(
                        "static_peers must be multiaddrs ending in /p2p/<id>",
                    ));
                }
                if url.scheme() == "http" && !private {
                    return Err(protocol(
                        "plain http is only accepted for private/loopback hosts (the node has no TLS)",
                    ));
                }
                if let Some(sp) = &self.store_peer {
                    if !sp.starts_with('/') || sp.len() > 512 {
                        return Err(protocol("store_peer must be a multiaddr starting with '/'"));
                    }
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
        if self.max_message_bytes < 1024 {
            return Err(protocol("max_message_bytes is implausibly small"));
        }
        Ok(url)
    }

    /// The pubsub topic derived for this cluster and shard.
    pub fn pubsub_topic(&self) -> String {
        format!("/waku/2/rs/{}/{}", self.cluster_id, self.shard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str) -> LogosRestConfig {
        LogosRestConfig {
            node_url: url.into(),
            allowed_peer_ids: vec!["16Uiu2HAmPeerA".into()],
            ..Default::default()
        }
    }

    #[test]
    fn accepts_private_hosts() {
        for u in [
            "http://127.0.0.1:8645",
            "http://127.5.5.5:1",
            "http://localhost:8645",
            "http://LOCALHOST:8645",
            "http://10.1.2.3:8645",
            "http://172.16.0.1:8645",
            "http://172.31.255.255:8645",
            "http://192.168.1.2:8645",
            "http://100.64.0.1:8645",
            "http://100.127.255.255:8645",
            "http://[::1]:8645",
            "http://[fd00::1]:8645",
            "http://[fc12::1]:8645",
            "http://[::ffff:10.0.0.1]:8645",
        ] {
            cfg(u).validate().unwrap_or_else(|e| panic!("{u}: {e}"));
        }
    }

    #[test]
    fn rejects_public_hosts_in_private_mode() {
        for u in [
            "http://8.8.8.8:8645",
            "http://1.1.1.1",
            "http://172.15.0.1",
            "http://172.32.0.1",
            "http://100.63.255.255",
            "http://100.128.0.1",
            "http://192.169.0.1",
            "http://11.0.0.1",
            "http://[2001:db8::1]:8645",
            "http://[fe80::1]:8645",
            "http://[::ffff:8.8.8.8]:8645",
            "http://example.com:8645",
            "http://node.local:8645",
            "http://localhost.evil.com:8645",
            "https://example.com",
            "http://127.0.0.1.nip.io:8645",
        ] {
            let e = cfg(u).validate().unwrap_err();
            assert!(matches!(e, TransportError::Isolation(_)), "{u}: {e:?}");
        }
    }

    #[test]
    fn rejects_malformed_urls() {
        for u in [
            "",
            "not a url",
            "ftp://127.0.0.1",
            "http://user:pw@127.0.0.1:8645",
            "http://127.0.0.1:8645/prefix",
            "http://127.0.0.1:8645/?q=1",
            "http://127.0.0.1:8645/#f",
            "file:///etc/passwd",
        ] {
            assert!(cfg(u).validate().is_err(), "{u:?}");
        }
    }

    #[test]
    fn private_mode_rejects_preset_clusters_and_empty_allowlist() {
        for id in PUBLIC_PRESET_CLUSTER_IDS {
            let mut c = cfg("http://127.0.0.1:1");
            c.cluster_id = id;
            assert!(
                matches!(c.validate(), Err(TransportError::Isolation(_))),
                "{id}"
            );
        }
        for id in [0u16, 4, 15, 17, 66, 65535] {
            let mut c = cfg("http://127.0.0.1:1");
            c.cluster_id = id;
            assert!(c.validate().is_ok(), "{id}");
        }
        let mut c = cfg("http://127.0.0.1:1");
        c.allowed_peer_ids.clear();
        assert!(matches!(c.validate(), Err(TransportError::Isolation(_))));
        c.allowed_peer_ids = vec!["bad id!".into()];
        assert!(matches!(c.validate(), Err(TransportError::Protocol(_))));
        c.allowed_peer_ids = vec![String::new()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn public_mode_rules() {
        let mut c = LogosRestConfig {
            node_url: "https://node.example.com".into(),
            mode: NetworkMode::Public,
            cluster_id: 1,
            ..Default::default()
        };
        assert!(c.validate().is_ok());
        c.node_url = "http://node.example.com".into();
        assert!(matches!(c.validate(), Err(TransportError::Protocol(_))));
        c.node_url = "http://127.0.0.1:8645".into();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn shard_and_numeric_limits() {
        let mut c = cfg("http://127.0.0.1:1");
        c.num_shards = 8;
        assert!(c.validate().is_err());
        c.num_shards = 1;
        c.shard = 1;
        assert!(c.validate().is_err());
        c.shard = 0;
        c.history_page_size = 0;
        assert!(c.validate().is_err());
        c.history_page_size = 101;
        assert!(c.validate().is_err());
        c.history_page_size = 100;
        c.request_timeout = Duration::ZERO;
        assert!(c.validate().is_err());
        c.request_timeout = Duration::from_secs(1);
        c.max_message_bytes = 10;
        assert!(c.validate().is_err());
        c.max_message_bytes = 153_600;
        assert!(c.validate().is_ok());
        assert_eq!(c.pubsub_topic(), "/waku/2/rs/66/0");
    }

    #[test]
    fn store_peer_must_be_private_and_allowlisted() {
        let mut c = cfg("http://127.0.0.1:1");
        let ok = "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmPeerA";
        c.store_peer = Some(ok.into());
        assert!(c.validate().is_ok());
        for bad in [
            "/ip4/8.8.8.8/tcp/60000/p2p/16Uiu2HAmPeerA",
            "/dns4/store.example.com/tcp/60000/p2p/16Uiu2HAmPeerA",
            "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmOther",
            "/ip4/172.28.66.10/tcp/60000",
            "ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmPeerA",
        ] {
            c.store_peer = Some(bad.into());
            assert!(c.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn deserializes_with_defaults_and_durations() {
        let c: LogosRestConfig = serde_json::from_str(
            r#"{"node_url":"http://10.0.0.5:8645","allowed_peer_ids":["A1"],"request_timeout":2.5,
                "audit_interval":{"secs":30,"nanos":0},"mode":"private"}"#,
        )
        .unwrap();
        assert_eq!(c.request_timeout, Duration::from_millis(2500));
        assert_eq!(c.audit_interval, Duration::from_secs(30));
        assert_eq!(c.history_page_size, 100);
        assert_eq!(c.max_message_bytes, 153_600);
        assert!(c.validate().is_ok());
        assert!(serde_json::from_str::<LogosRestConfig>(r#"{"bogus":1}"#).is_err());
        assert!(serde_json::from_str::<LogosRestConfig>(r#"{"request_timeout":-1}"#).is_err());
        let d = LogosRestConfig::default();
        assert_eq!(d.request_timeout, Duration::from_secs(5));
        assert_eq!(d.audit_interval, Duration::from_secs(15));
        assert!(
            d.validate().is_err(),
            "default has no allowlist: fails closed"
        );
    }

    #[test]
    fn static_peers_validation_and_derived_allowlist() {
        let sp = "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmPeerA";
        let mut c = cfg("http://127.0.0.1:1");
        c.static_peers = vec![sp.into()];
        assert!(c.validate().is_ok());
        // derived allowlist
        c.allowed_peer_ids.clear();
        assert!(c.validate().is_ok());
        assert_eq!(
            c.effective_allowed_peer_ids(),
            vec!["16Uiu2HAmPeerA".to_string()]
        );
        // id not in explicit allowlist
        c.allowed_peer_ids = vec!["16Uiu2HAmPeerB".into()];
        assert!(matches!(c.validate(), Err(TransportError::Isolation(_))));
        c.allowed_peer_ids = vec!["16Uiu2HAmPeerA".into()];
        for bad in [
            "/ip4/8.8.8.8/tcp/60000/p2p/16Uiu2HAmPeerA",
            "/dns4/x.example.com/tcp/60000/p2p/16Uiu2HAmPeerA",
            "/ip4/172.28.66.10/tcp/60000",
            "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmPeerA/p2p-circuit",
            "172.28.66.10",
            "",
        ] {
            c.static_peers = vec![bad.into()];
            assert!(c.validate().is_err(), "{bad}");
        }
        assert_eq!(
            LogosRestConfig::default().redial_interval,
            Duration::from_secs(10)
        );
    }

    #[test]
    fn multiaddr_peer_id_extraction() {
        assert_eq!(
            peer_id_of_multiaddr("/ip4/1.2.3.4/tcp/1/p2p/AbC1"),
            Some("AbC1")
        );
        assert_eq!(
            peer_id_of_multiaddr("/ip4/1.2.3.4/tcp/1/p2p/Relay1/p2p-circuit/p2p/Dest2"),
            Some("Dest2")
        );
        assert_eq!(peer_id_of_multiaddr("/ip4/1.2.3.4/tcp/1"), None);
        assert_eq!(peer_id_of_multiaddr("/p2p/"), None);
    }
}
