//! Shared harness: daemons on one MockNetwork with one manual clock.
#![allow(dead_code)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentnet_core::api::{AddContactRequest, AgentApi, ReadInboxRequest, SendMessageRequest};
use agentnet_daemon::offline::init_data_dir;
use agentnet_daemon::{Daemon, DaemonConfig, RemoteAgent, RunningDaemon};
use agentnet_transport::mock::{MockClock, MockNetwork};

pub const PEER: &str =
    "/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV";

pub fn cfg() -> DaemonConfig {
    let mut c = DaemonConfig::default();
    c.network.peers = vec![PEER.into()];
    c.policy.auto_trigger = true;
    c.triggers.allowed_sessions = vec!["s1".into(), "s2".into()];
    c.delivery.poll_interval_ms = 20;
    c.delivery.jitter_seed = Some(1);
    c
}

pub struct World {
    pub net: Arc<MockNetwork>,
    pub clock: MockClock,
    pub tmp: tempfile::TempDir,
}

impl World {
    pub fn new() -> Self {
        // Identities are created by `init` with the wall clock, so start there.
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_nanos()).unwrap_or(0))
            .unwrap_or(0);
        // A little ahead of the wall clock: certificates created by `init` after this point
        // (up to seconds later under load) must not lie in the future of the mock clock.
        let clock = MockClock::new(now_ns + 60_000_000_000);
        Self {
            net: MockNetwork::with_clock(clock.clone()),
            clock,
            tmp: tempfile::tempdir().unwrap(),
        }
    }

    /// Initialise a data dir (exercises `init`) and return its path, address and contact record.
    pub fn init(&self, name: &str) -> (PathBuf, String, String) {
        let path = self.tmp.path().join(name);
        let rep = init_data_dir(&path, "http://127.0.0.1:8645", &[PEER.to_owned()], false).unwrap();
        (path, rep.identity.agent_id, rep.identity.contact_record)
    }

    pub async fn start(&self, path: &Path, config: DaemonConfig) -> RunningDaemon {
        Daemon::start_with_transport(
            path,
            config,
            Arc::new(self.net.endpoint()),
            Arc::new(self.clock.clone()),
        )
        .await
        .unwrap()
    }
}

impl World {
    pub async fn start_on(
        &self,
        path: &Path,
        config: DaemonConfig,
        transport: agentnet_transport::mock::MockTransport,
    ) -> RunningDaemon {
        Daemon::start_with_transport(
            path,
            config,
            Arc::new(transport),
            Arc::new(self.clock.clone()),
        )
        .await
        .unwrap()
    }
}

pub struct Agent {
    pub path: PathBuf,
    pub address: String,
    pub record: String,
    pub daemon: Option<RunningDaemon>,
    pub remote: RemoteAgent,
}

impl Agent {
    pub async fn new(w: &World, name: &str, config: DaemonConfig) -> Self {
        let (path, address, record) = w.init(name);
        let daemon = w.start(&path, config).await;
        let remote = RemoteAgent::new(&path);
        Self {
            path,
            address,
            record,
            daemon: Some(daemon),
            remote,
        }
    }

    pub fn d(&self) -> &RunningDaemon {
        self.daemon.as_ref().unwrap()
    }

    pub async fn add_contact_of(&self, other: &Agent) {
        self.remote
            .add_contact(AddContactRequest {
                contact_record: other.record.clone(),
                expected_address: Some(other.address.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    pub async fn send(&self, to: &Agent, body: &str) -> String {
        self.remote
            .send_message(SendMessageRequest {
                recipient: to.address.clone(),
                body: body.into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .message_id
    }

    pub async fn inbox_len(&self) -> usize {
        self.remote
            .read_inbox(ReadInboxRequest::default())
            .await
            .unwrap()
            .records
            .len()
    }
}

/// Two agents that know each other.
pub async fn pair(w: &World, cfg_a: DaemonConfig, cfg_b: DaemonConfig) -> (Agent, Agent) {
    let a = Agent::new(w, "a", cfg_a).await;
    let b = Agent::new(w, "b", cfg_b).await;
    a.add_contact_of(&b).await;
    b.add_contact_of(&a).await;
    (a, b)
}

pub async fn wait_until<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if f().await {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
