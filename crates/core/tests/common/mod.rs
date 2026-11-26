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
        self.open_agent(name, config, transport, id_path, NodeOptions::default())
    }

    fn open_agent(
        &self,
        name: &str,
        config: NodeConfig,
        transport: MockTransport,
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
            Arc::new(transport.clone()),
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
        self.open_agent(&name, config, transport, id_path, options)
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
