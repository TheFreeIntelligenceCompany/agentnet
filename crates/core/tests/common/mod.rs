//! Shared harness for the engine tests: agents on one MockNetwork, one manual
//! clock driving both the network and every node, temp-dir stores.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use agentnet_core::api::{
    AddContactRequest, AgentApi, ApiError, ErrorCode, ReadInboxRequest, SendMessageRequest,
    SendMessageResponse,
};
use agentnet_core::config::{NodeConfig, UnknownSenders};
use agentnet_core::identity::Identity;
use agentnet_core::{Clock, Node, NodeOptions};
use agentnet_transport::mock::{MockClock, MockNetwork, MockTransport};
use agentnet_transport::{
    ContentTopic, HistoryPage, HistoryQuery, InboundFrame, PublishReceipt, Transport,
    TransportError, TransportStatus,
};
use async_trait::async_trait;
use tokio::sync::Notify;

pub const MS: i64 = 1_000;

pub struct World {
    pub net: Arc<MockNetwork>,
    pub clock: MockClock,
    pub dir: tempfile::TempDir,
}

pub struct Agent {
    pub name: String,
    pub node: Arc<Node>,
    pub transport: MockTransport,
    pub addr: String,
    pub record: String,
    pub store_path: PathBuf,
    pub id_path: PathBuf,
}

pub fn cfg() -> NodeConfig {
    let mut c = NodeConfig::default();
    c.policy.auto_trigger = true;
    c.triggers.allowed_sessions = vec!["s1".into(), "s2".into()];
    c.delivery.jitter_seed = Some(7);
    c
}

pub fn cfg_with(f: impl FnOnce(&mut NodeConfig)) -> NodeConfig {
    let mut c = cfg();
    f(&mut c);
    c
}

impl World {
    pub fn new() -> Self {
        let clock = MockClock::default();
        Self {
            net: MockNetwork::with_clock(clock.clone()),
            clock,
            dir: tempfile::tempdir().unwrap(),
        }
    }

    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    pub fn advance(&self, ms: i64) {
        self.clock.advance_ns(ms * 1_000_000);
    }

    pub fn agent(&self, name: &str, config: NodeConfig) -> Agent {
        self.agent_buckets(name, config, 16)
    }

    pub fn agent_buckets(&self, name: &str, config: NodeConfig, buckets: u16) -> Agent {
        let id = Identity::generate(buckets, self.now_ms()).unwrap();
        let id_path = self.dir.path().join(format!("{name}.identity.json"));
        id.save(&id_path, false).unwrap();
        let transport = self.net.endpoint();
        let dynt: Arc<dyn Transport> = Arc::new(transport.clone());
        self.open_agent(
            name,
            config,
            transport,
            dynt,
            id_path,
            NodeOptions::default(),
        )
    }

    /// An agent whose next publish can be paused with the returned [`Gate`].
    pub fn agent_gated(&self, name: &str, config: NodeConfig) -> (Agent, Arc<Gate>) {
        let id = Identity::generate(16, self.now_ms()).unwrap();
        let id_path = self.dir.path().join(format!("{name}.identity.json"));
        id.save(&id_path, false).unwrap();
        let transport = self.net.endpoint();
        let gate = Arc::new(Gate::default());
        let dynt: Arc<dyn Transport> = Arc::new(GateTransport {
            inner: transport.clone(),
            gate: gate.clone(),
        });
        let a = self.open_agent(
            name,
            config,
            transport,
            dynt,
            id_path,
            NodeOptions::default(),
        );
        (a, gate)
    }

    /// An agent whose history queries can be made to paginate in a loop
    /// (see [`HistoryLoop`]).
    pub fn agent_history_loop(&self, name: &str, config: NodeConfig) -> (Agent, Arc<HistoryLoop>) {
        let id = Identity::generate(16, self.now_ms()).unwrap();
        let id_path = self.dir.path().join(format!("{name}.identity.json"));
        id.save(&id_path, false).unwrap();
        let transport = self.net.endpoint();
        let hl = Arc::new(HistoryLoop::default());
        let dynt: Arc<dyn Transport> = Arc::new(HistoryLoopTransport {
            inner: transport.clone(),
            ctl: hl.clone(),
        });
        let a = self.open_agent(
            name,
            config,
            transport,
            dynt,
            id_path,
            NodeOptions::default(),
        );
        (a, hl)
    }

    fn open_agent(
        &self,
        name: &str,
        config: NodeConfig,
        transport: MockTransport,
        node_transport: Arc<dyn Transport>,
        id_path: PathBuf,
        options: NodeOptions,
    ) -> Agent {
        let id = Identity::load(&id_path).unwrap();
        let record = id.contact_record().to_document();
        let addr = id.address().to_string();
        let store_path = self.dir.path().join(format!("{name}.sqlite"));
        let node = Node::open_with(
            id,
            &store_path,
            node_transport,
            config,
            Arc::new(self.clock.clone()),
            options,
        )
        .unwrap();
        Agent {
            name: name.into(),
            node,
            transport,
            addr,
            record,
            store_path,
            id_path,
        }
    }

    /// Drop the old node (without any shutdown) and open a new one on the same
    /// store, identity and transport endpoint.
    pub fn reopen(&self, old: Agent, config: NodeConfig) -> Agent {
        self.reopen_with(old, config, NodeOptions::default())
    }

    /// [`World::reopen`] with explicit node options (protection, local revocation).
    pub fn reopen_with(&self, old: Agent, config: NodeConfig, options: NodeOptions) -> Agent {
        let Agent {
            name,
            transport,
            id_path,
            node,
            ..
        } = old;
        node.close();
        drop(node);
        let dynt: Arc<dyn Transport> = Arc::new(transport.clone());
        self.open_agent(&name, config, transport, dynt, id_path, options)
    }
}

impl Agent {
    pub async fn add(&self, other: &Agent) {
        self.node
            .add_contact(AddContactRequest {
                contact_record: other.record.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    pub async fn send(&self, to: &Agent, body: &str) -> SendMessageResponse {
        self.node
            .send_message(SendMessageRequest {
                recipient: to.addr.clone(),
                body: body.into(),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    pub async fn send_err(&self, req: SendMessageRequest) -> ApiError {
        self.node.send_message(req).await.unwrap_err()
    }

    pub async fn inbox(&self) -> Vec<agentnet_core::api::InboxRecord> {
        self.node
            .read_inbox(ReadInboxRequest {
                limit: Some(200),
                ..Default::default()
            })
            .await
            .unwrap()
            .records
    }

    pub async fn state(&self, id: &str) -> agentnet_core::api::DeliveryState {
        self.node.get_message_status(id.into()).await.unwrap().state
    }

    pub fn n(&self, table: &str) -> u64 {
        self.node.debug_table_count(table)
    }

    pub fn metric(&self, name: &str) -> u64 {
        self.node.metrics().get(name)
    }
}

pub async fn exchange(a: &Agent, b: &Agent) {
    a.add(b).await;
    b.add(a).await;
}

/// One receive + send step for every agent, repeated until a round does
/// nothing (bounded). Never sleeps; time only moves when the test advances it.
pub async fn settle(agents: &[&Agent]) {
    for _ in 0..30 {
        let mut activity = 0;
        for a in agents {
            let r = a.node.step_receive().await.unwrap();
            let s = a.node.step_send().await.unwrap();
            activity += r.polled + s.published;
        }
        if activity == 0 {
            return;
        }
    }
    panic!("settle did not converge");
}

pub fn code(e: &ApiError) -> ErrorCode {
    e.code
}

pub fn quarantine_cfg() -> NodeConfig {
    cfg_with(|c| c.policy.unknown_senders = UnknownSenders::Quarantine)
}

/// Pauses the next `publish` of a [`GateTransport`] until released.
#[derive(Default)]
pub struct Gate {
    reached: Notify,
    release: Notify,
    armed: std::sync::atomic::AtomicBool,
}

impl Gate {
    /// Arm the gate: the next publish blocks.
    pub fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// Wait until a publish is blocked at the gate.
    pub async fn wait_reached(&self) {
        self.reached.notified().await;
    }
    /// Let the blocked publish continue.
    pub fn release(&self) {
        self.release.notify_one();
    }
}

pub struct GateTransport {
    inner: MockTransport,
    gate: Arc<Gate>,
}

#[async_trait]
impl Transport for GateTransport {
    async fn subscribe(&self, topic: &ContentTopic) -> Result<(), TransportError> {
        self.inner.subscribe(topic).await
    }
    async fn publish(
        &self,
        topic: &ContentTopic,
        payload: &[u8],
    ) -> Result<PublishReceipt, TransportError> {
        if self
            .gate
            .armed
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.gate.reached.notify_one();
            self.gate.release.notified().await;
        }
        self.inner.publish(topic, payload).await
    }
    async fn poll(&self, topic: &ContentTopic) -> Result<Vec<InboundFrame>, TransportError> {
        self.inner.poll(topic).await
    }
    async fn history(&self, query: &HistoryQuery) -> Result<HistoryPage, TransportError> {
        self.inner.history(query).await
    }
    async fn status(&self) -> TransportStatus {
        self.inner.status().await
    }
    fn max_payload_len(&self, topic: &ContentTopic) -> usize {
        self.inner.max_payload_len(topic)
    }
    fn max_history_window_ns(&self) -> i64 {
        self.inner.max_history_window_ns()
    }
}

/// Controls a [`HistoryLoopTransport`]: while `mode` is non-zero every history
/// query answers an empty page whose cursor repeats (mode 1: `x` -> `x`) or
/// cycles (mode 2: `x` -> `y` -> `x`). `starts` records every query start.
#[derive(Default)]
pub struct HistoryLoop {
    pub mode: std::sync::atomic::AtomicU8,
    pub starts: std::sync::Mutex<Vec<i64>>,
}

pub struct HistoryLoopTransport {
    inner: MockTransport,
    ctl: Arc<HistoryLoop>,
}

#[async_trait]
impl Transport for HistoryLoopTransport {
    async fn subscribe(&self, topic: &ContentTopic) -> Result<(), TransportError> {
        self.inner.subscribe(topic).await
    }
    async fn publish(
        &self,
        topic: &ContentTopic,
        payload: &[u8],
    ) -> Result<PublishReceipt, TransportError> {
        self.inner.publish(topic, payload).await
    }
    async fn poll(&self, topic: &ContentTopic) -> Result<Vec<InboundFrame>, TransportError> {
        self.inner.poll(topic).await
    }
    async fn history(&self, query: &HistoryQuery) -> Result<HistoryPage, TransportError> {
        self.ctl.starts.lock().unwrap().push(query.start_ns);
        match self.ctl.mode.load(std::sync::atomic::Ordering::SeqCst) {
            0 => self.inner.history(query).await,
            1 => Ok(HistoryPage {
                frames: vec![],
                next_cursor: Some("x".into()),
            }),
            _ => Ok(HistoryPage {
                frames: vec![],
                next_cursor: Some(if query.cursor.as_deref() == Some("x") {
                    "y".into()
                } else {
                    "x".into()
                }),
            }),
        }
    }
    async fn status(&self) -> TransportStatus {
        self.inner.status().await
    }
    fn max_payload_len(&self, topic: &ContentTopic) -> usize {
        self.inner.max_payload_len(topic)
    }
    fn max_history_window_ns(&self) -> i64 {
        self.inner.max_history_window_ns()
    }
}
