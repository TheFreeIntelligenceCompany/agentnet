//! Pure-Rust libp2p Waku v2 client transport and standalone relay (no Docker).
//!
//! Implements [`crate::Transport`] directly over `rust-libp2p` using the Waku v2
//! wire protocols:
//! - `/vac/waku/relay/2.0.0` (GossipSub v1.1, Anonymous, SHA-256 message IDs)
//! - `/vac/waku/metadata/1.0.0` (cluster/shard handshake)
//! - `/vac/waku/store-query/3.0.0` (history recovery)
//!
//! Security properties:
//! - In private mode, `libp2p-dns` is not wired into the transport stack (zero
//!   DNS egress by construction) and `libp2p-allow-block-list` enforces the peer
//!   allowlist **preventively** at connection admission.
//! - Active `/ipfs/ping/1.0.0` keepalives detect half-open TCP paths.
//! - No REST polling, no 50-slot destructive receive cache, no Docker sidecar.

mod behaviour;
mod config;
pub mod proto;
mod relay;
pub mod store_db;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use libp2p::gossipsub;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::SwarmEvent;
use libp2p::PeerId;
use prost::Message;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub use config::{
    generate_node_key, keypair_from_hex_or_random, NativeRelayConfig, NativeWakuConfig,
};
pub use relay::NativeWakuRelay;

use behaviour::{build_behaviour, build_swarm, WakuBehaviourEvent};
use config::ValidatedPeer;
use proto::{StoreQueryRequest, StoreQueryResponse, WakuMessage, WakuMetadataMessage};

use crate::waku_common::{
    hex, max_payload_for, next_timestamp_ns, parse_hash, waku_message_hash, NetworkMode,
    MAX_HISTORY_WINDOW_NS,
};
use crate::{
    ContentTopic, FrameSource, HistoryPage, HistoryQuery, InboundFrame, PeerInfo, PublishReceipt,
    Transport, TransportError, TransportStatus,
};

enum Cmd {
    Publish {
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), TransportError>>,
    },
    StoreQuery {
        peer: Option<PeerId>,
        request: Box<StoreQueryRequest>,
        reply: oneshot::Sender<Result<StoreQueryResponse, TransportError>>,
    },
    Status {
        reply: oneshot::Sender<TransportStatus>,
    },
}

#[derive(Default)]
struct SharedQueues {
    subscribed: HashSet<ContentTopic>,
    queues: HashMap<ContentTopic, VecDeque<InboundFrame>>,
}

/// Counters exposed by [`NativeWakuTransport::metrics`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeWakuMetrics {
    /// Frames dropped because a per-topic queue hit `max_topic_queue`.
    pub queue_dropped: u64,
    /// Store entries skipped because the recomputed hash differed from the relay's.
    pub hash_mismatches: u64,
    /// Malformed protobuf frames ignored.
    pub malformed_skipped: u64,
    /// Dial / redial attempts issued to static peers.
    pub dials: u64,
}

#[derive(Default)]
struct Counters {
    queue_dropped: AtomicU64,
    hash_mismatches: AtomicU64,
    malformed_skipped: AtomicU64,
    dials: AtomicU64,
}

/// Pure-Rust libp2p Waku v2 [`Transport`] implementation (zero Docker).
pub struct NativeWakuTransport {
    cfg: NativeWakuConfig,
    peer_id: PeerId,
    pubsub: String,
    cmd_tx: mpsc::Sender<Cmd>,
    shared: Arc<StdMutex<SharedQueues>>,
    counters: Arc<Counters>,
    req_seq: AtomicU64,
    cancel: CancellationToken,
    _task: JoinHandle<()>,
}

impl NativeWakuTransport {
    /// Validates `cfg` (failing closed in private mode) and starts the embedded
    /// libp2p Swarm background task. Must be called inside a Tokio runtime.
    pub fn start(cfg: NativeWakuConfig) -> Result<Self, TransportError> {
        let parsed = cfg.validate_parsed()?;
        let keypair = keypair_from_hex_or_random(cfg.node_key_hex.as_deref())?;
        let peer_id = PeerId::from(keypair.public());

        let allowed_slice = if cfg.audits_peers() {
            Some(parsed.allowed_peers.as_slice())
        } else {
            None
        };
        let behaviour = build_behaviour(
            &keypair,
            allowed_slice,
            cfg.max_message_bytes,
            cfg.request_timeout,
            false,
        )?;
        // Private mode builds the transport WITHOUT libp2p-dns (zero DNS egress).
        let enable_dns = cfg.mode == NetworkMode::Public;
        let mut swarm = build_swarm(keypair, behaviour, enable_dns)?;

        let pubsub = cfg.pubsub_topic();
        let gs_topic = gossipsub::IdentTopic::new(pubsub.clone());
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gs_topic)
            .map_err(|e| TransportError::Protocol(format!("gossipsub subscribe: {e}")))?;

        for la in &parsed.listen_addrs {
            swarm
                .listen_on(la.clone())
                .map_err(|e| TransportError::Unavailable(format!("listen on {la}: {e}")))?;
        }

        let shared = Arc::new(StdMutex::new(SharedQueues::default()));
        let counters = Arc::new(Counters::default());
        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(256);
        let cancel = CancellationToken::new();

        let task = tokio::spawn(run_swarm_loop(SwarmCtx {
            swarm,
            cfg: cfg.clone(),
            pubsub: pubsub.clone(),
            gs_topic,
            allowed_peers: parsed.allowed_peers.into_iter().collect(),
            static_peers: parsed.static_peers,
            store_peer: parsed.store_peer,
            cmd_rx,
            shared: shared.clone(),
            counters: counters.clone(),
            cancel: cancel.clone(),
        }));

        Ok(Self {
            cfg,
            peer_id,
            pubsub,
            cmd_tx,
            shared,
            counters,
            req_seq: AtomicU64::new(1),
            cancel,
            _task: task,
        })
    }

    /// This client node's libp2p [`PeerId`].
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The configuration in use.
    pub fn config(&self) -> &NativeWakuConfig {
        &self.cfg
    }

    /// The pubsub topic `/waku/2/rs/<cluster>/<shard>`.
    pub fn pubsub_topic(&self) -> &str {
        &self.pubsub
    }

    /// Snapshot of transport counters.
    pub fn metrics(&self) -> NativeWakuMetrics {
        NativeWakuMetrics {
            queue_dropped: self.counters.queue_dropped.load(Ordering::Relaxed),
            hash_mismatches: self.counters.hash_mismatches.load(Ordering::Relaxed),
            malformed_skipped: self.counters.malformed_skipped.load(Ordering::Relaxed),
            dials: self.counters.dials.load(Ordering::Relaxed),
        }
    }
}

impl Drop for NativeWakuTransport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct SwarmCtx {
    swarm: libp2p::Swarm<behaviour::WakuBehaviour>,
    cfg: NativeWakuConfig,
    pubsub: String,
    gs_topic: gossipsub::IdentTopic,
    allowed_peers: HashSet<PeerId>,
    static_peers: Vec<ValidatedPeer>,
    store_peer: Option<ValidatedPeer>,
    cmd_rx: mpsc::Receiver<Cmd>,
    shared: Arc<StdMutex<SharedQueues>>,
    counters: Arc<Counters>,
    cancel: CancellationToken,
}

fn push_frame(
    shared: &StdMutex<SharedQueues>,
    counters: &Counters,
    max_queue: usize,
    frame: InboundFrame,
) {
    let mut g = shared.lock().unwrap_or_else(|e| e.into_inner());
    if !g.subscribed.contains(&frame.topic) {
        return;
    }
    let q = g.queues.entry(frame.topic.clone()).or_default();
    if q.len() >= max_queue {
        q.pop_front();
        counters.queue_dropped.fetch_add(1, Ordering::Relaxed);
    }
    q.push_back(frame);
}

fn dial_static_peers(ctx: &mut SwarmCtx, connected: &HashSet<PeerId>) {
    let mut targets: Vec<&ValidatedPeer> = ctx.static_peers.iter().collect();
    if let Some(sp) = &ctx.store_peer {
        if !targets.iter().any(|t| t.peer_id == sp.peer_id) {
            targets.push(sp);
        }
    }
    for peer in targets {
        if connected.contains(&peer.peer_id) {
            continue;
        }
        ctx.swarm
            .add_peer_address(peer.peer_id, peer.dial_addr.clone());
        let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer.peer_id)
            .addresses(vec![peer.dial_addr.clone()])
            .condition(libp2p::swarm::dial_opts::PeerCondition::Disconnected)
            .build();
        if ctx.swarm.dial(opts).is_ok() {
            ctx.counters.dials.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn run_swarm_loop(mut ctx: SwarmCtx) {
    let mut connected: HashSet<PeerId> = HashSet::new();
    let mut verified_peers: HashSet<PeerId> = HashSet::new();
    let mut pending_store: HashMap<
        OutboundRequestId,
        oneshot::Sender<Result<StoreQueryResponse, TransportError>>,
    > = HashMap::new();

    // Dial immediately on startup.
    dial_static_peers(&mut ctx, &connected);

    let mut redial_tick = tokio::time::interval(ctx.cfg.redial_interval);
    redial_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    redial_tick.tick().await;

    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => {
                break;
            }
            _ = redial_tick.tick() => {
                dial_static_peers(&mut ctx, &connected);
            }
            cmd = ctx.cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    Cmd::Publish { data, reply } => {
                        if connected.is_empty() {
                            let _ = reply.send(Err(TransportError::Unavailable(
                                "no connected relay peers".into()
                            )));
                            continue;
                        }
                        let res = ctx.swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(ctx.gs_topic.clone(), data)
                            .map(|_| ())
                            .map_err(|e| match e {
                                gossipsub::PublishError::Duplicate => {
                                    // Identical frame already seen in mesh; treat as accepted.
                                    TransportError::Protocol("duplicate".into())
                                }
                                gossipsub::PublishError::NoPeersSubscribedToTopic => {
                                    TransportError::Unavailable(
                                        "no mesh peers subscribed to Waku pubsub topic yet".into()
                                    )
                                }
                                other => TransportError::Unavailable(format!("gossipsub publish: {other}")),
                            });
                        let res = match res {
                            Err(TransportError::Protocol(ref s)) if s == "duplicate" => Ok(()),
                            other => other,
                        };
                        let _ = reply.send(res);
                    }
                    Cmd::StoreQuery { peer, request, reply } => {
                        let target = peer
                            .or_else(|| ctx.store_peer.as_ref().map(|p| p.peer_id))
                            .or_else(|| {
                                ctx.static_peers
                                    .iter()
                                    .find(|p| connected.contains(&p.peer_id))
                                    .map(|p| p.peer_id)
                            })
                            .or_else(|| connected.iter().next().copied());
                        match target {
                            Some(pid) if connected.contains(&pid) => {
                                let id = ctx.swarm
                                    .behaviour_mut()
                                    .store
                                    .send_request(&pid, *request);
                                pending_store.insert(id, reply);
                            }
                            _ => {
                                let _ = reply.send(Err(TransportError::HistoryUnavailable(
                                    "no connected Store peer".into()
                                )));
                            }
                        }
                    }
                    Cmd::Status { reply } => {
                        let audits = ctx.cfg.audits_peers();
                        let mut known: HashSet<PeerId> = connected.clone();
                        for sp in &ctx.static_peers {
                            known.insert(sp.peer_id);
                        }
                        let mut peers: Vec<PeerInfo> = known
                            .into_iter()
                            .map(|pid| PeerInfo {
                                peer_id: pid.to_string(),
                                connected: connected.contains(&pid),
                                allowed: !audits || ctx.allowed_peers.contains(&pid),
                            })
                            .collect();
                        peers.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
                        let foreign = peers.iter().any(|p| p.connected && !p.allowed);
                        let isolation_violation = if foreign {
                            Some("connected peer outside allowlist".into())
                        } else {
                            None
                        };
                        let ready = isolation_violation.is_none()
                            && !connected.is_empty()
                            && !verified_peers.is_empty();
                        let detail = if let Some(ref v) = isolation_violation {
                            format!("native libp2p isolation violation: {v}")
                        } else if ready {
                            format!(
                                "native libp2p ready ({} connected peer(s), {})",
                                connected.len(),
                                ctx.pubsub
                            )
                        } else if !connected.is_empty() {
                            "native libp2p connected; awaiting Waku metadata handshake".into()
                        } else {
                            "native libp2p waiting for relay peer connection".into()
                        };
                        let _ = reply.send(TransportStatus {
                            ready,
                            peers,
                            isolation_violation,
                            detail,
                        });
                    }
                }
            }
            event = ctx.swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        connected.insert(peer_id);
                        ctx.swarm.behaviour_mut().metadata.send_request(
                            &peer_id,
                            WakuMetadataMessage::single(ctx.cfg.cluster_id, ctx.cfg.shard),
                        );
                    }
                    SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                        if num_established == 0 {
                            connected.remove(&peer_id);
                            verified_peers.remove(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(WakuBehaviourEvent::Metadata(
                        request_response::Event::Message { peer, message, .. }
                    )) => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                let ok = request.supports(ctx.cfg.cluster_id, ctx.cfg.shard);
                                let _ = ctx.swarm.behaviour_mut().metadata.send_response(
                                    channel,
                                    WakuMetadataMessage::single(ctx.cfg.cluster_id, ctx.cfg.shard),
                                );
                                if ok {
                                    verified_peers.insert(peer);
                                } else {
                                    tracing::warn!(%peer, "disconnecting peer with mismatched Waku cluster/shard");
                                    let _ = ctx.swarm.disconnect_peer_id(peer);
                                }
                            }
                            request_response::Message::Response { response, .. } => {
                                if response.supports(ctx.cfg.cluster_id, ctx.cfg.shard) {
                                    verified_peers.insert(peer);
                                } else {
                                    tracing::warn!(%peer, "disconnecting peer with mismatched Waku cluster/shard");
                                    let _ = ctx.swarm.disconnect_peer_id(peer);
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(WakuBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. }
                    )) => {
                        if message.topic.as_str() != ctx.pubsub {
                            continue;
                        }
                        if message.data.len() > ctx.cfg.max_message_bytes {
                            ctx.counters.malformed_skipped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        match WakuMessage::decode(message.data.as_slice()) {
                            Ok(wmsg) => {
                                let Ok(topic) = ContentTopic::new(wmsg.content_topic.clone()) else {
                                    ctx.counters.malformed_skipped.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                };
                                let ts = wmsg.timestamp.unwrap_or(0);
                                let tid = waku_message_hash(
                                    &ctx.pubsub,
                                    &wmsg.payload,
                                    topic.as_str(),
                                    wmsg.meta.as_deref().unwrap_or(&[]),
                                    ts,
                                );
                                push_frame(
                                    &ctx.shared,
                                    &ctx.counters,
                                    ctx.cfg.max_topic_queue,
                                    InboundFrame {
                                        topic,
                                        payload: wmsg.payload,
                                        timestamp_ns: ts,
                                        transport_id: tid,
                                        source: FrameSource::Live,
                                    },
                                );
                            }
                            Err(_) => {
                                ctx.counters.malformed_skipped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(WakuBehaviourEvent::Store(
                        request_response::Event::Message {
                            message: request_response::Message::Response { request_id, response },
                            ..
                        }
                    )) => {
                        if let Some(tx) = pending_store.remove(&request_id) {
                            let _ = tx.send(Ok(response));
                        }
                    }
                    SwarmEvent::Behaviour(WakuBehaviourEvent::Store(
                        request_response::Event::OutboundFailure { request_id, error, .. }
                    )) => {
                        if let Some(tx) = pending_store.remove(&request_id) {
                            let _ = tx.send(Err(TransportError::HistoryUnavailable(
                                format!("store query failed: {error}")
                            )));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[async_trait]
impl Transport for NativeWakuTransport {
    async fn subscribe(&self, topic: &ContentTopic) -> Result<(), TransportError> {
        let mut g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        g.subscribed.insert(topic.clone());
        g.queues.entry(topic.clone()).or_default();
        Ok(())
    }

    async fn publish(
        &self,
        topic: &ContentTopic,
        payload: &[u8],
    ) -> Result<PublishReceipt, TransportError> {
        let max = self.max_payload_len(topic);
        if payload.len() > max {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                max,
            });
        }
        let timestamp_ns = next_timestamp_ns();
        let wmsg = WakuMessage {
            payload: payload.to_vec(),
            content_topic: topic.as_str().to_owned(),
            version: Some(0),
            timestamp: Some(timestamp_ns),
            meta: None,
            proof: None,
            ephemeral: Some(false),
        };
        let encoded = wmsg.encode_to_vec();
        let transport_id =
            waku_message_hash(&self.pubsub, payload, topic.as_str(), &[], timestamp_ns);

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Publish {
                data: encoded,
                reply: tx,
            })
            .await
            .map_err(|_| TransportError::Unavailable("native transport task stopped".into()))?;
        tokio::time::timeout(self.cfg.request_timeout, rx)
            .await
            .map_err(|_| TransportError::Unavailable("publish timed out".into()))?
            .map_err(|_| {
                TransportError::Unavailable("native transport task dropped reply".into())
            })??;

        // Match LogosRestTransport / MockTransport self-delivery echo contract:
        // if this client is subscribed to `topic`, deliver the frame locally too.
        push_frame(
            &self.shared,
            &self.counters,
            self.cfg.max_topic_queue,
            InboundFrame {
                topic: topic.clone(),
                payload: payload.to_vec(),
                timestamp_ns,
                transport_id,
                source: FrameSource::Live,
            },
        );

        Ok(PublishReceipt {
            transport_id,
            timestamp_ns,
        })
    }

    async fn poll(&self, topic: &ContentTopic) -> Result<Vec<InboundFrame>, TransportError> {
        let mut g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        let out = match g.queues.get_mut(topic) {
            Some(q) => q.drain(..).collect(),
            None => Vec::new(),
        };
        Ok(out)
    }

    async fn history(&self, query: &HistoryQuery) -> Result<HistoryPage, TransportError> {
        if query.start_ns > query.end_ns {
            return Err(TransportError::Protocol(
                "history query start_ns > end_ns".into(),
            ));
        }
        if query.end_ns.saturating_sub(query.start_ns) > MAX_HISTORY_WINDOW_NS {
            return Err(TransportError::Protocol(
                "history query window exceeds 24 hours".into(),
            ));
        }
        let cursor_bytes = match &query.cursor {
            Some(c) => {
                let h = parse_hash(c)
                    .ok_or_else(|| TransportError::Protocol("invalid history cursor".into()))?;
                Some(h.to_vec())
            }
            None => None,
        };
        let limit = u64::from(query.limit.clamp(1, self.cfg.history_page_size));
        let req_id = format!("an-{}", self.req_seq.fetch_add(1, Ordering::Relaxed));
        let request = StoreQueryRequest {
            request_id: req_id,
            include_data: true,
            pubsub_topic: Some(self.pubsub.clone()),
            content_topics: vec![query.topic.as_str().to_owned()],
            time_start: Some(query.start_ns),
            time_end: Some(query.end_ns),
            message_hashes: Vec::new(),
            pagination_cursor: cursor_bytes,
            pagination_forward: true,
            pagination_limit: Some(limit),
        };

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::StoreQuery {
                peer: None,
                request: Box::new(request),
                reply: tx,
            })
            .await
            .map_err(|_| {
                TransportError::HistoryUnavailable("native transport task stopped".into())
            })?;
        let resp = tokio::time::timeout(self.cfg.request_timeout, rx)
            .await
            .map_err(|_| TransportError::HistoryUnavailable("store query timed out".into()))?
            .map_err(|_| {
                TransportError::HistoryUnavailable("native transport task dropped reply".into())
            })??;

        let code = resp.status_code.unwrap_or(500);
        if code != 200 {
            return Err(TransportError::HistoryUnavailable(format!(
                "store returned status {code}: {}",
                resp.status_desc.unwrap_or_default()
            )));
        }

        let mut frames = Vec::with_capacity(resp.messages.len());
        for kv in resp.messages {
            let Some(wmsg) = kv.message else {
                self.counters
                    .malformed_skipped
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let Ok(topic) = ContentTopic::new(wmsg.content_topic.clone()) else {
                self.counters
                    .malformed_skipped
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let ts = wmsg.timestamp.unwrap_or(0);
            let recomputed = waku_message_hash(
                &self.pubsub,
                &wmsg.payload,
                topic.as_str(),
                wmsg.meta.as_deref().unwrap_or(&[]),
                ts,
            );
            if kv.message_hash.as_slice() != recomputed.as_slice() {
                self.counters
                    .hash_mismatches
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            frames.push(InboundFrame {
                topic,
                payload: wmsg.payload,
                timestamp_ns: ts,
                transport_id: recomputed,
                source: FrameSource::History,
            });
        }

        let next_cursor = resp
            .pagination_cursor
            .filter(|c| c.len() == 32)
            .map(|c| hex(&c));

        Ok(HistoryPage {
            frames,
            next_cursor,
        })
    }

    async fn status(&self) -> TransportStatus {
        let (tx, rx) = oneshot::channel();
        if self.cmd_tx.send(Cmd::Status { reply: tx }).await.is_err() {
            return TransportStatus {
                ready: false,
                detail: "native transport task stopped".into(),
                ..Default::default()
            };
        }
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_else(|| TransportStatus {
                ready: false,
                detail: "native transport status timed out".into(),
                ..Default::default()
            })
    }

    fn max_payload_len(&self, topic: &ContentTopic) -> usize {
        max_payload_for(self.cfg.max_message_bytes, topic.as_str().len())
    }

    fn max_history_window_ns(&self) -> i64 {
        MAX_HISTORY_WINDOW_NS
    }
}
