//! Discovery through the daemon: configuration, the control socket and the
//! running engine (publish loop, receive loop) on one mock network.

mod common;

use agentnet_core::api::*;
use agentnet_daemon::DaemonConfig;
use common::*;
use serde_json::json;

fn dcfg() -> DaemonConfig {
    let mut c = cfg();
    c.discovery.enabled = true;
    c.discovery.topics = vec!["general".into()];
    c.discovery.republish_interval_s = 1;
    c
}

fn adv() -> AdvertiseRequest {
    AdvertiseRequest {
        topic: "general".into(),
        capabilities: vec![Capability {
            name: "translate.de".into(),
            description: "German to English".into(),
        }],
        display_name: Some("Translator".into()),
        ttl_seconds: Some(600),
    }
}

fn disc() -> DiscoverRequest {
    DiscoverRequest {
        topic: "general".into(),
        ..Default::default()
    }
}

#[test]
fn discovery_config_is_off_by_default_and_parses() {
    let c = DaemonConfig::default();
    assert!(!c.discovery.enabled && c.discovery.topics.is_empty());
    assert!(!c.to_node_config().discovery.enabled);
    let c = DaemonConfig::parse(
        "[discovery]\nenabled = true\ntopics = [\"general\", \"team-1\"]\nmax_records = 10\n",
    )
    .unwrap();
    assert!(c.discovery.enabled);
    assert_eq!(c.discovery.max_records, 10);
    assert_eq!(c.to_node_config().discovery.topics, ["general", "team-1"]);
    assert!(DaemonConfig::parse("[discovery]\nnope = 1\n").is_err());
    // validation happens in the engine's config check
    let mut bad = cfg();
    bad.discovery.enabled = true;
    assert!(bad.validate().is_err(), "enabled without topics");
    bad.discovery.topics = vec!["Not Valid".into()];
    assert!(bad.validate().is_err());
    bad.discovery.topics = vec!["ok".into()];
    assert!(bad.validate().is_ok());
}

#[tokio::test]
async fn disabled_daemon_denies_over_the_socket_and_stays_off_the_wire() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    for e in [
        a.remote.advertise_agent(adv()).await.unwrap_err(),
        a.remote.discover_agents(disc()).await.unwrap_err(),
        a.remote.withdraw_advert("general".into()).await.unwrap_err(),
    ] {
        assert_eq!(e.code, ErrorCode::PolicyDenied);
        assert!(e.message.contains("disabled by host policy"), "{}", e.message);
    }
    // raw socket: malformed params are invalid_argument
    let v = a
        .remote
        .call_value("advertise_agent", json!({"topic": 5}))
        .await
        .unwrap_err();
    assert_eq!(v.code, ErrorCode::InvalidArgument);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(w.net.total_publish_count(), 0);
}

#[tokio::test]
async fn advertise_and_discover_end_to_end_through_two_daemons() {
    let w = World::new();
    let a = Agent::new(&w, "a", dcfg()).await;
    let b = Agent::new(&w, "b", dcfg()).await;
    let info = a.remote.advertise_agent(adv()).await.unwrap();
    assert_eq!(info.seq, 1);
    assert_eq!(info.capabilities.len(), 1);

    wait_until("B discovers A", || async {
        b.remote
            .discover_agents(disc())
            .await
            .map(|p| !p.agents.is_empty())
            .unwrap_or(false)
    })
    .await;
    let page = b.remote.discover_agents(disc()).await.unwrap();
    assert_eq!(page.agents.len(), 1);
    let d = &page.agents[0];
    assert_eq!(d.address, a.address);
    assert_eq!(d.display_name.as_deref(), Some("Translator"));
    assert!(!d.is_contact);
    // a capability filter over the socket
    let mut r = disc();
    r.capability = Some("nothing".into());
    assert!(b.remote.discover_agents(r).await.unwrap().agents.is_empty());
    // topic outside the host list
    let mut r = disc();
    r.topic = "elsewhere".into();
    assert_eq!(
        b.remote.discover_agents(r).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );

    // the embedded record is accepted by add_contact, discovery itself never added it
    assert!(b.remote.list_contacts().await.unwrap().is_empty());
    b.remote
        .add_contact(AddContactRequest {
            contact_record: d.contact_record.clone(),
            expected_address: Some(d.address.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    let after = b.remote.discover_agents(disc()).await.unwrap();
    assert!(after.agents[0].is_contact);

    // the running engine republishes on the manual clock, and withdraws
    let before = w.net.publish_count(
        &agentnet_transport::ContentTopic::new("/agentnet/1/discovery-general/proto").unwrap(),
    );
    w.clock.advance(std::time::Duration::from_secs(2));
    wait_until("republish", || async {
        w.net.publish_count(
            &agentnet_transport::ContentTopic::new("/agentnet/1/discovery-general/proto")
                .unwrap(),
        ) > before
    })
    .await;
    assert!(a.remote.withdraw_advert("general".into()).await.unwrap().withdrawn);
    wait_until("B sees the withdrawal", || async {
        b.remote
            .discover_agents(disc())
            .await
            .map(|p| p.agents.is_empty())
            .unwrap_or(false)
    })
    .await;
    assert!(!a.remote.withdraw_advert("general".into()).await.unwrap().withdrawn);
}
