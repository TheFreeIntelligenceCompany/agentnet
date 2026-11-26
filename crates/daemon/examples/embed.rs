//! Rust embedding example: two AgentNet engines in one process exchange a
//! message through the `AgentApi` trait. Run with
//! `cargo run -p agentnet-daemon --example embed`.
//!
//! IMPORTANT: this example embeds the *engine* (`agentnet_core::Node`: identity,
//! sealed envelopes, SQLite inbox/outbox, retries, triggers, events) on the
//! deterministic in-memory `MockNetwork`. FULL embedding of the *node* is NOT
//! available: the selected transport (ADR 0001) is an adapter to a separately
//! running Logos Delivery node, i.e. a sidecar process that must be started next
//! to the harness (`agentnet relay print-config` prints its flags). Embedding
//! the node itself would need the native FFI path, which remains a future option
//! behind the same `Transport` trait.
//!
//! Swapping the mock for the real transport is a two-line change:
//!
//! ```ignore
//! use agentnet_daemon::DaemonConfig;
//! let cfg = DaemonConfig::load(&data_dir.join("agentnet.toml"))?;   // validated, fail closed
//! let transport = agentnet_transport::logos_rest::LogosRestTransport::new(cfg.to_logos_config())?;
//! let node = Node::open(identity, &store_path, Arc::new(transport), cfg.to_node_config(), Arc::new(SystemClock))?;
//! ```
//!
//! Everything after `Node::open` (the `AgentApi` calls, `Node::run`) is identical.
//! A harness that wants the daemon's lock, sockets and webhook instead of
//! managing them itself can call `agentnet_daemon::Daemon::start(data_dir)` and
//! use `RunningDaemon::api()`.

use std::sync::Arc;
use std::time::Duration;

use agentnet_core::api::{
    AddContactRequest, AgentApi, DeliveryState, ReadInboxRequest, SendMessageRequest,
};
use agentnet_core::config::NodeConfig;
use agentnet_core::identity::Identity;
use agentnet_core::{Clock, Node};
use agentnet_transport::mock::{MockClock, MockNetwork};
use tokio_util::sync::CancellationToken;

fn open(
    dir: &std::path::Path,
    name: &str,
    net: &Arc<MockNetwork>,
    clock: &MockClock,
) -> Result<Arc<Node>, Box<dyn std::error::Error>> {
    let identity = Identity::generate_default(clock.now_ms())?;
    let mut cfg = NodeConfig::default();
    cfg.delivery.poll_interval_ms = 20;
    let node = Node::open(
        identity,
        &dir.join(format!("{name}.db")),
        // Swap point: LogosRestTransport::new(...) in a real deployment.
        Arc::new(net.endpoint()),
        cfg,
        Arc::new(clock.clone()),
    )?;
    Ok(node)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("agentnet-embed-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    // One manual clock drives the mock network and both engines (deterministic).
    // With the real transport use `SystemClock` instead.
    let clock = MockClock::default();
    let net = MockNetwork::with_clock(clock.clone());
    let alice = open(&dir, "alice", &net, &clock)?;
    let bob = open(&dir, "bob", &net, &clock)?;

    // Exchange verified contact records (in a real deployment: out of band).
    let (ia, ib) = (alice.get_identity().await?, bob.get_identity().await?);
    alice
        .add_contact(AddContactRequest {
            contact_record: ib.contact_record.clone(),
            expected_address: Some(ib.agent_id.clone()),
            ..Default::default()
        })
        .await?;
    bob.add_contact(AddContactRequest {
        contact_record: ia.contact_record.clone(),
        expected_address: Some(ia.agent_id.clone()),
        ..Default::default()
    })
    .await?;

    // Subscribe both engines BEFORE anything is published. The first
    // `step_receive` subscribes the content topic (then polls an empty queue).
    // Without this, `Node::run` subscribes lazily inside its receive task, so
    // the spawned tasks race the `send_message` below: a frame published
    // before the recipient is subscribed is accepted by the network but never
    // reaches its live queue ("accepted but lost"). Recovery then needs either
    // a retry (backoff elapses only when the clock advances, and this example's
    // `MockClock` is frozen) or a history pass (every `history_sync_interval_s`
    // of real time), so the example would sporadically time out. A real
    // deployment avoids the race the same way: start the daemon, wait for its
    // first successful poll, then send.
    alice.step_receive().await?;
    bob.step_receive().await?;

    // Drive both engines (receive loop, send/retry loop, history, maintenance).
    let stop = CancellationToken::new();
    let (a, b) = (alice.clone(), bob.clone());
    let (s1, s2) = (stop.clone(), stop.clone());
    let t1 = tokio::spawn(async move { a.run(s1).await });
    let t2 = tokio::spawn(async move { b.run(s2).await });

    let sent = alice
        .send_message(SendMessageRequest {
            recipient: ib.agent_id.clone(),
            body: "hello from an embedded engine".into(),
            ..Default::default()
        })
        .await?;
    println!("alice queued {} ({:?})", sent.message_id, sent.status);

    // Poll (or use `changes()` hints) until it arrives and the receipt comes back.
    for _ in 0..200 {
        let inbox = bob.read_inbox(ReadInboxRequest::default()).await?;
        let status = alice.get_message_status(sent.message_id.clone()).await?;
        if let Some(m) = inbox.records.first() {
            if status.state == DeliveryState::Delivered {
                println!("bob received {:?} from {}", m.body, m.sender);
                println!(
                    "alice's status is now {:?} (authenticated ack)",
                    status.state
                );
                stop.cancel();
                let _ = tokio::join!(t1, t2);
                std::fs::remove_dir_all(&dir).ok();
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    stop.cancel();
    Err("the message was not delivered in time".into())
}
