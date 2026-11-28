//! Combined `libp2p` [`NetworkBehaviour`] and swarm builder for Waku v2.

use std::iter;
use std::time::Duration;

use libp2p::gossipsub;
use libp2p::identify;
use libp2p::identity::Keypair;
use libp2p::noise;
use libp2p::ping;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::tcp;
use libp2p::yamux;
use libp2p::{PeerId, StreamProtocol, Swarm, SwarmBuilder};
use libp2p_allow_block_list::{AllowedPeers, Behaviour as AllowBlockBehaviour};

use super::proto::{
    gossipsub_message_id, MetadataCodec, StoreCodec, METADATA_PROTOCOL, RELAY_PROTOCOL,
    STORE_PROTOCOL,
};
use crate::TransportError;

/// Preventive connection gate: `Toggle(Some(AllowedPeers))` when peer allowlist
/// is enforced (private mode, audited public mode, or relay with `--allow-peer`),
/// or `Toggle(None)` when open (plain public mode / open relay).
pub(crate) type GateBehaviour = Toggle<AllowBlockBehaviour<AllowedPeers>>;

/// Composed Waku v2 libp2p behaviour: preventive peer allowlist, Ping
/// keepalive, Identify, Waku Relay (GossipSub on `/vac/waku/relay/2.0.0`),
/// Waku Metadata (`/vac/waku/metadata/1.0.0`), and Waku Store v3
/// (`/vac/waku/store-query/3.0.0`).
#[derive(NetworkBehaviour)]
pub(crate) struct WakuBehaviour {
    pub gate: GateBehaviour,
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub metadata: request_response::Behaviour<MetadataCodec>,
    pub store: request_response::Behaviour<StoreCodec>,
}

pub(crate) fn build_behaviour(
    keypair: &Keypair,
    allowed_peers: Option<&[PeerId]>,
    max_message_bytes: usize,
    request_timeout: Duration,
    is_relay: bool,
) -> Result<WakuBehaviour, TransportError> {
    let gate = match allowed_peers {
        Some(list) => {
            let mut b = AllowBlockBehaviour::<AllowedPeers>::default();
            for pid in list {
                b.allow_peer(*pid);
            }
            Toggle::from(Some(b))
        }
        None => Toggle::from(None),
    };

    // Active Ping keepalive detects silently dropped / half-open TCP paths in
    // ~30 s, avoiding nwaku's idle stale-socket lockout.
    let ping = ping::Behaviour::new(
        ping::Config::new()
            .with_interval(Duration::from_secs(15))
            .with_timeout(Duration::from_secs(10)),
    );

    let agent_version = if is_relay {
        concat!("agentnet-native-relay/", env!("CARGO_PKG_VERSION"))
    } else {
        concat!("agentnet-native-client/", env!("CARGO_PKG_VERSION"))
    };
    let identify = identify::Behaviour::new(
        identify::Config::new("/ipfs/id/1.0.0".into(), keypair.public())
            .with_agent_version(agent_version.into()),
    );

    // GossipSub configured to Waku Relay 2.0.0 wire spec:
    // - exact protocol ID `/vac/waku/relay/2.0.0` (NOT `protocol_id_prefix`,
    //   which would append `/1.1.0`)
    // - Anonymous messages (no libp2p from/seqno/signature; matches nwaku)
    // - flood_publish(true) for immediate delivery on small private meshes
    // - message_id_fn = SHA-256(message.data) matching waku_relay/message_id.nim
    // - max_transmit_size has room for protobuf overhead above max_message_bytes
    let max_transmit = max_message_bytes.saturating_add(64 * 1024).max(256 * 1024);
    let gs_cfg = gossipsub::ConfigBuilder::default()
        .protocol_id(RELAY_PROTOCOL, gossipsub::Version::V1_1)
        .validation_mode(gossipsub::ValidationMode::Anonymous)
        .message_id_fn(gossipsub_message_id)
        .flood_publish(true)
        .max_transmit_size(max_transmit)
        .heartbeat_interval(Duration::from_millis(500))
        .mesh_n_low(1)
        .mesh_n(2)
        .mesh_n_high(12)
        .mesh_outbound_min(0)
        .build()
        .map_err(|e| TransportError::Protocol(format!("gossipsub config: {e}")))?;

    let gossipsub = gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Anonymous, gs_cfg)
        .map_err(|e| TransportError::Protocol(format!("gossipsub init: {e}")))?;

    let metadata = request_response::Behaviour::new(
        iter::once((
            StreamProtocol::new(METADATA_PROTOCOL),
            ProtocolSupport::Full,
        )),
        request_response::Config::default().with_request_timeout(request_timeout),
    );

    let store_support = if is_relay {
        ProtocolSupport::Full
    } else {
        ProtocolSupport::Outbound
    };
    let store = request_response::Behaviour::new(
        iter::once((StreamProtocol::new(STORE_PROTOCOL), store_support)),
        request_response::Config::default().with_request_timeout(request_timeout),
    );

    Ok(WakuBehaviour {
        gate,
        ping,
        identify,
        gossipsub,
        metadata,
        store,
    })
}

/// Builds a `libp2p::Swarm<WakuBehaviour>`.
///
/// When `enable_dns` is `false` (private mode), `libp2p-dns` is NOT wired into
/// the transport stack, guaranteeing zero DNS egress by construction.
pub(crate) fn build_swarm(
    keypair: Keypair,
    behaviour: WakuBehaviour,
    enable_dns: bool,
) -> Result<Swarm<WakuBehaviour>, TransportError> {
    let tcp_cfg = tcp::Config::default().nodelay(true);
    let swarm = if enable_dns {
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(tcp_cfg, noise::Config::new, yamux::Config::default)
            .map_err(|e| TransportError::Protocol(format!("libp2p tcp init: {e}")))?
            .with_dns()
            .map_err(|e| TransportError::Protocol(format!("libp2p dns init: {e}")))?
            .with_behaviour(|_| behaviour)
            .expect("infallible behaviour closure")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    } else {
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(tcp_cfg, noise::Config::new, yamux::Config::default)
            .map_err(|e| TransportError::Protocol(format!("libp2p tcp init: {e}")))?
            .with_behaviour(|_| behaviour)
            .expect("infallible behaviour closure")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    };
    Ok(swarm)
}
