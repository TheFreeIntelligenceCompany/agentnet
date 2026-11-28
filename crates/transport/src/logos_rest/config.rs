//! Configuration and fail-closed validation for [`super::LogosRestTransport`].

use std::time::Duration;

use serde::Deserialize;
use url::{Host, Url};

pub(crate) use crate::waku_common::{
    check_peer_addr_private, check_peer_addr_public_audited, de_duration, peer_id_of_multiaddr,
    static_peer_shape_ok, valid_peer_id,
};
pub use crate::waku_common::{
    is_private_ipv4, is_private_ipv6, NetworkMode, MAX_HISTORY_PAGE_SIZE, PUBLIC_PRESET_CLUSTER_IDS,
};
use crate::TransportError;

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
    /// Only valid with `mode = public`: keep the peer-id allowlist audit for a
    /// user-owned relay on a public address. Peers may then be public IPs or
    /// dns4/dns6 names (tcp, optional tls/ws/wss, one /p2p/ id, no relay hops).
    /// Private mode always audits and rejects this flag. UNTESTED against a
    /// real public relay.
    pub enforce_peer_allowlist: bool,
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
            enforce_peer_allowlist: false,
        }
    }
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

    /// True when the peer-id allowlist is audited: always in private mode, and
    /// in public mode only with `enforce_peer_allowlist`.
    pub fn audits_peers(&self) -> bool {
        self.mode == NetworkMode::Private || self.enforce_peer_allowlist
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
        if self.mode == NetworkMode::Private && self.enforce_peer_allowlist {
            return Err(protocol(
                "enforce_peer_allowlist is only valid with mode = public: private mode \
                 always audits the allowlist (remove the setting)",
            ));
        }
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
            NetworkMode::Public if self.enforce_peer_allowlist => {
                if url.scheme() == "http" && !private {
                    return Err(protocol(
                        "plain http is only accepted for private/loopback hosts (the node has no TLS)",
                    ));
                }
                if PUBLIC_PRESET_CLUSTER_IDS.contains(&self.cluster_id) {
                    return Err(TransportError::Isolation(format!(
                        "enforce_peer_allowlist: cluster id {} selects a public preset; use your \
                         own relay's cluster id",
                        self.cluster_id
                    )));
                }
                let allowed = self.effective_allowed_peer_ids();
                if allowed.is_empty() {
                    return Err(TransportError::Isolation(
                        "enforce_peer_allowlist needs at least one peer (network.peers / \
                         static_peers or allowed_peer_ids): the allowlist is derived from them"
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
                        "allowed_peer_ids is set in public mode without enforce_peer_allowlist = true; \
                         set enforce_peer_allowlist = true to audit peers, or clear allowed_peer_ids",
                    ));
                }
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
        if self.max_message_bytes < 1024 || self.max_message_bytes > 16 * 1024 * 1024 {
            return Err(protocol(
                "max_message_bytes must be between 1024 and 16777216",
            ));
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
    fn private_peer_addrs_reject_relay_hops_and_extra_components() {
        let relay = "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAmRelay";
        let dest = "/p2p-circuit/p2p/16Uiu2HAmPeerA";
        for bad in [
            format!("{relay}{dest}"),
            "/ip4/172.28.66.10/tcp/1/p2p/16Uiu2HAmRelay/p2p/16Uiu2HAmPeerA".to_string(),
            "/ip4/172.28.66.10/dns4/relay.example.com/tcp/1/p2p/16Uiu2HAmPeerA".to_string(),
            "/ip4/172.28.66.10/tcp/1/ip4/8.8.8.8/tcp/1/p2p/16Uiu2HAmPeerA".to_string(),
        ] {
            for private in [true, false] {
                let mut c = cfg("http://127.0.0.1:1");
                c.allowed_peer_ids = vec!["16Uiu2HAmPeerA".into()];
                if private {
                    c.store_peer = Some(bad.clone());
                } else {
                    c.static_peers = vec![bad.clone()];
                }
                assert!(
                    matches!(c.validate(), Err(TransportError::Isolation(_))),
                    "{bad}"
                );
            }
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

    fn audited(peer: &str) -> LogosRestConfig {
        LogosRestConfig {
            node_url: "http://127.0.0.1:8645".into(),
            mode: NetworkMode::Public,
            enforce_peer_allowlist: true,
            static_peers: vec![peer.into()],
            ..Default::default()
        }
    }

    #[test]
    fn enforced_public_mode_accepts_public_ip_and_dns_forms() {
        for ok in [
            "/ip4/203.0.113.7/tcp/60000/p2p/16Uiu2HAmRelay",
            "/ip4/10.0.0.5/tcp/60000/p2p/16Uiu2HAmRelay",
            "/ip6/2001:db8::1/tcp/60000/p2p/16Uiu2HAmRelay",
            "/dns4/relay.example.com/tcp/60000/p2p/16Uiu2HAmRelay",
            "/dns6/relay.example.com/tcp/60000/p2p/16Uiu2HAmRelay",
            "/dns4/relay.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay",
            "/dns4/relay.example.com/tcp/443/tls/ws/p2p/16Uiu2HAmRelay",
            "/dns4/relay.example.com/tcp/8000/ws/p2p/16Uiu2HAmRelay",
            "/dns4/relay.example.com/tcp/443/tls/p2p/16Uiu2HAmRelay",
        ] {
            let c = audited(ok);
            c.validate().unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert_eq!(
                c.effective_allowed_peer_ids(),
                vec!["16Uiu2HAmRelay".to_string()]
            );
        }
        let mut c = audited("/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay");
        c.store_peer = Some("/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay".into());
        c.validate().unwrap();
    }

    #[test]
    fn enforced_public_mode_rejects_bad_forms() {
        for bad in [
            "/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay/p2p-circuit/p2p/16Uiu2HAmRelay",
            "/dns4/r.example.com/tcp/443/p2p/16Uiu2HAmRelay/p2p/16Uiu2HAmRelay",
            "/dnsaddr/r.example.com/p2p/16Uiu2HAmRelay",
            "/dns/r.example.com/tcp/443/p2p/16Uiu2HAmRelay",
            "/dns4/r.example.com/tcp/443/wss",
            "/dns4/r.example.com/tcp/0/p2p/16Uiu2HAmRelay",
            "/dns4/r.example.com/tcp/99999/p2p/16Uiu2HAmRelay",
            "/dns4/r.example.com/udp/443/p2p/16Uiu2HAmRelay",
            "/dns4/bad_name.example.com/tcp/443/p2p/16Uiu2HAmRelay",
            "/dns4/-x.example.com/tcp/443/p2p/16Uiu2HAmRelay",
            "/ip4/999.1.1.1/tcp/443/p2p/16Uiu2HAmRelay",
            "/ip4/1.2.3.4/dns4/r.example.com/tcp/443/p2p/16Uiu2HAmRelay",
            "/dns4/r.example.com/tcp/443/quic/p2p/16Uiu2HAmRelay",
            "/dns4/r.example.com/tcp/443/p2p/16Uiu2HAmRelay/ws",
            "dns4/r.example.com/tcp/443/p2p/16Uiu2HAmRelay",
            "",
        ] {
            assert!(audited(bad).validate().is_err(), "{bad}");
        }
        // peer id not in an explicit allowlist
        let mut c = audited("/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay");
        c.allowed_peer_ids = vec!["16Uiu2HAmOther".into()];
        assert!(matches!(c.validate(), Err(TransportError::Isolation(_))));
        // store peer outside the allowlist
        let mut c = audited("/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay");
        c.store_peer = Some("/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmOther".into());
        assert!(c.validate().is_err());
    }

    #[test]
    fn enforced_public_mode_needs_peers_and_a_private_cluster() {
        let mut c = audited("/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay");
        c.static_peers.clear();
        assert!(matches!(c.validate(), Err(TransportError::Isolation(_))));
        let mut c = audited("/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay");
        c.cluster_id = 1;
        assert!(matches!(c.validate(), Err(TransportError::Isolation(_))));
        // plain http to a public node_url is still refused
        let mut c = audited("/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay");
        c.node_url = "http://node.example.com".into();
        assert!(c.validate().is_err());
        assert!(c.audits_peers());
    }

    #[test]
    fn enforce_flag_is_rejected_in_private_mode_and_plain_public_is_unchanged() {
        let mut c = cfg("http://127.0.0.1:1");
        c.enforce_peer_allowlist = true;
        let e = c.validate().unwrap_err();
        assert!(
            e.to_string().contains("only valid with mode = public"),
            "{e}"
        );
        // Private mode keeps rejecting public forms.
        let mut c = cfg("http://127.0.0.1:1");
        for bad in [
            "/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmPeerA",
            "/ip4/203.0.113.7/tcp/60000/p2p/16Uiu2HAmPeerA",
        ] {
            c.static_peers = vec![bad.into()];
            assert!(matches!(c.validate(), Err(TransportError::Isolation(_))));
        }
        assert!(!c.enforce_peer_allowlist && c.audits_peers());
        // Plain public mode: no audit, no address rules beyond the shape.
        let p = LogosRestConfig {
            node_url: "http://127.0.0.1:8645".into(),
            mode: NetworkMode::Public,
            cluster_id: 1,
            static_peers: vec!["/dns4/r.example.com/tcp/443/wss/p2p/16Uiu2HAmRelay".into()],
            ..Default::default()
        };
        p.validate().unwrap();
        assert!(!p.audits_peers());
    }
}
