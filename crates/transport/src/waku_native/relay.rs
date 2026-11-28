//! Standalone pure-Rust Waku v2 Relay + Store v3 server (`NativeWakuRelay`).
//!
//! Runs with zero Docker: listens on TCP (`Noise` + `Yamux`), relays GossipSub
//! frames on `/vac/waku/relay/2.0.0`, responds to `/vac/waku/metadata/1.0.0`,
//! archives non-ephemeral messages in SQLite (or RAM for `--memory-only`), and
//! serves `/vac/waku/store-query/3.0.0`.

use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub;
use libp2p::request_response;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use prost::Message;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::behaviour::{build_behaviour, build_swarm, WakuBehaviourEvent};
use super::config::{keypair_from_hex_or_random, NativeRelayConfig};
use super::proto::{WakuMessage, WakuMetadataMessage};
use super::store_db::{StoreDb, StoreDbLimits};
use crate::waku_common::{next_timestamp_ns, waku_message_hash};
use crate::TransportError;

/// A running pure-Rust Waku v2 Relay + Store v3 server.
pub struct NativeWakuRelay {
    peer_id: PeerId,
    listen_addrs: Vec<Multiaddr>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl NativeWakuRelay {
    /// Starts the relay + Store v3 server and waits until all configured listen
    /// addresses are bound (so ephemeral `/tcp/0` ports are immediately known).
    pub async fn start(cfg: NativeRelayConfig) -> Result<Self, TransportError> {
        let (listen_addrs_cfg, allowed_peers) = cfg.validate()?;
        let keypair = keypair_from_hex_or_random(cfg.node_key_hex.as_deref())?;
        let peer_id = PeerId::from(keypair.public());

        let limits = StoreDbLimits {
            retention_seconds: cfg.retention_seconds,
            retention_capacity: cfg.retention_capacity,
            max_clock_skew_seconds: cfg.max_clock_skew_seconds,
        };
        let store_db = match &cfg.store_db_path {
            Some(path) => StoreDb::open_file(path, limits)?,
            None => StoreDb::open_in_memory(limits)?,
        };

        let gate = if allowed_peers.is_empty() {
            None
        } else {
            Some(allowed_peers.as_slice())
        };
        let behaviour = build_behaviour(
            &keypair,
            gate,
            cfg.max_message_bytes,
            Duration::from_secs(10),
            true,
        )?;
        let mut swarm = build_swarm(keypair, behaviour, false)?;

        let pubsub_topic_str = cfg.pubsub_topic();
        let gs_topic = gossipsub::IdentTopic::new(pubsub_topic_str.clone());
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gs_topic)
            .map_err(|e| TransportError::Protocol(format!("relay subscribe failed: {e}")))?;

        let expected_listeners = listen_addrs_cfg.len();
        for addr in listen_addrs_cfg {
            swarm
                .listen_on(addr.clone())
                .map_err(|e| TransportError::Unavailable(format!("listen on {addr}: {e}")))?;
        }

        let cancel = CancellationToken::new();
        let loop_cancel = cancel.clone();
        let (ready_tx, ready_rx) = oneshot::channel::<Result<Vec<Multiaddr>, TransportError>>();
        let cluster_id = cfg.cluster_id;
        let shard = cfg.shard;
        let max_msg_bytes = cfg.max_message_bytes;

        let task = tokio::spawn(async move {
            let mut bound: Vec<Multiaddr> = Vec::new();
            let mut ready_tx = Some(ready_tx);
            let mut prune_tick = tokio::time::interval(Duration::from_secs(300));
            prune_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            prune_tick.tick().await; // skip immediate first tick

            loop {
                tokio::select! {
                    _ = loop_cancel.cancelled() => {
                        tracing::info!(%peer_id, "native Waku relay shutting down");
                        break;
                    }
                    _ = prune_tick.tick() => {
                        if let Err(e) = store_db.prune(next_timestamp_ns()) {
                            tracing::warn!(error = %e, "relay store prune failed");
                        }
                    }
                    event = swarm.select_next_some() => {
                        match event {
                            SwarmEvent::NewListenAddr { address, .. } => {
                                tracing::info!(%peer_id, %address, "native Waku relay listening");
                                bound.push(address);
                                if bound.len() >= expected_listeners {
                                    if let Some(tx) = ready_tx.take() {
                                        let _ = tx.send(Ok(bound.clone()));
                                    }
                                }
                            }
                            SwarmEvent::ListenerClosed { reason, .. } => {
                                if let Some(tx) = ready_tx.take() {
                                    let _ = tx.send(Err(TransportError::Unavailable(
                                        format!("relay listener closed: {reason:?}")
                                    )));
                                    break;
                                }
                            }
                            SwarmEvent::ConnectionEstablished { peer_id: remote, .. } => {
                                tracing::debug!(%remote, "relay accepted connection");
                                swarm.behaviour_mut().metadata.send_request(
                                    &remote,
                                    WakuMetadataMessage::single(cluster_id, shard),
                                );
                            }
                            SwarmEvent::Behaviour(WakuBehaviourEvent::Metadata(
                                request_response::Event::Message { peer, message, .. }
                            )) => {
                                match message {
                                    request_response::Message::Request { request, channel, .. } => {
                                        let ok = request.supports(cluster_id, shard);
                                        let _ = swarm.behaviour_mut().metadata.send_response(
                                            channel,
                                            WakuMetadataMessage::single(cluster_id, shard),
                                        );
                                        if !ok {
                                            tracing::warn!(
                                                %peer,
                                                remote_cluster = ?request.cluster_id,
                                                "disconnecting peer with mismatched Waku cluster/shard"
                                            );
                                            let _ = swarm.disconnect_peer_id(peer);
                                        }
                                    }
                                    request_response::Message::Response { response, .. } => {
                                        if !response.supports(cluster_id, shard) {
                                            tracing::warn!(
                                                %peer,
                                                remote_cluster = ?response.cluster_id,
                                                "disconnecting peer with mismatched Waku cluster/shard"
                                            );
                                            let _ = swarm.disconnect_peer_id(peer);
                                        }
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(WakuBehaviourEvent::Gossipsub(
                                gossipsub::Event::Message { message, .. }
                            )) => {
                                if message.topic.as_str() != pubsub_topic_str {
                                    continue;
                                }
                                if message.data.len() > max_msg_bytes {
                                    continue;
                                }
                                if let Ok(wmsg) = WakuMessage::decode(message.data.as_slice()) {
                                    let ts = wmsg.timestamp.unwrap_or(0);
                                    let hash = waku_message_hash(
                                        &pubsub_topic_str,
                                        &wmsg.payload,
                                        &wmsg.content_topic,
                                        wmsg.meta.as_deref().unwrap_or(&[]),
                                        ts,
                                    );
                                    let now = next_timestamp_ns();
                                    if let Err(e) = store_db.insert(
                                        &pubsub_topic_str,
                                        &hash,
                                        &wmsg,
                                        &message.data,
                                        now,
                                    ) {
                                        tracing::warn!(error = %e, "failed to archive Waku message");
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(WakuBehaviourEvent::Store(
                                request_response::Event::Message {
                                    message: request_response::Message::Request {
                                        request,
                                        channel,
                                        ..
                                    },
                                    ..
                                }
                            )) => {
                                let resp = store_db.query(&request);
                                let _ = swarm.behaviour_mut().store.send_response(channel, resp);
                            }
                            _ => {}
                        }
                    }
                }
            }
        });

        let listen_addrs = tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .map_err(|_| TransportError::Unavailable("timed out binding relay listener".into()))?
            .map_err(|_| {
                TransportError::Unavailable("relay task exited during startup".into())
            })??;

        Ok(Self {
            peer_id,
            listen_addrs,
            cancel,
            task: Some(task),
        })
    }

    /// The relay's libp2p [`PeerId`].
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Bound listen multiaddrs without the `/p2p/<peer_id>` suffix.
    pub fn listen_addrs(&self) -> &[Multiaddr] {
        &self.listen_addrs
    }

    /// Full dialable multiaddrs including `/p2p/<peer_id>` (ready for
    /// `agentnet init --native --peer <MULTIADDR>`).
    pub fn multiaddrs(&self) -> Vec<String> {
        self.listen_addrs
            .iter()
            .map(|a| format!("{a}/p2p/{}", self.peer_id))
            .collect()
    }

    /// Shuts down the relay cleanly.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}

impl Drop for NativeWakuRelay {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
