#![cfg(feature = "waku-native")]

use std::time::{Duration, Instant};

use agentnet_transport::waku_common::MAX_HISTORY_WINDOW_NS;
use agentnet_transport::waku_native::{
    generate_node_key, NativeRelayConfig, NativeWakuConfig, NativeWakuRelay, NativeWakuTransport,
};
use agentnet_transport::{ContentTopic, FrameSource, HistoryQuery, Transport, TransportError};

async fn wait_ready(t: &NativeWakuTransport, timeout: Duration) {
    let start = Instant::now();
    loop {
        let st = t.status().await;
        if st.ready {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "transport never became ready (last status: {st:?})"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn poll_until(
    t: &NativeWakuTransport,
    topic: &ContentTopic,
    want: usize,
    timeout: Duration,
) -> Vec<agentnet_transport::InboundFrame> {
    let start = Instant::now();
    let mut got = Vec::new();
    while got.len() < want {
        got.extend(t.poll(topic).await.unwrap());
        if got.len() >= want {
            break;
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for {want} frame(s), got {}",
            got.len()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    got
}

fn client_cfg(relay_maddr: &str) -> NativeWakuConfig {
    NativeWakuConfig {
        static_peers: vec![relay_maddr.to_owned()],
        redial_interval: Duration::from_millis(250),
        ..Default::default()
    }
}

#[tokio::test]
async fn live_roundtrip_and_self_echo_over_native_relay() {
    let relay = NativeWakuRelay::start(NativeRelayConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
        ..Default::default()
    })
    .await
    .unwrap();
    let relay_maddr = relay.multiaddrs()[0].clone();

    let a = NativeWakuTransport::start(client_cfg(&relay_maddr)).unwrap();
    let b = NativeWakuTransport::start(client_cfg(&relay_maddr)).unwrap();
    wait_ready(&a, Duration::from_secs(10)).await;
    wait_ready(&b, Duration::from_secs(10)).await;
    // Allow GossipSub mesh graft heartbeat to settle.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let topic_a = ContentTopic::new("/agentnet/1/inbox-0a/proto").unwrap();
    let topic_b = ContentTopic::new("/agentnet/1/inbox-0b/proto").unwrap();
    a.subscribe(&topic_a).await.unwrap();
    b.subscribe(&topic_b).await.unwrap();

    let rec_ab = a.publish(&topic_b, b"hello from A").await.unwrap();
    let got_b = poll_until(&b, &topic_b, 1, Duration::from_secs(10)).await;
    assert_eq!(got_b[0].payload, b"hello from A");
    assert_eq!(got_b[0].transport_id, rec_ab.transport_id);
    assert_eq!(got_b[0].source, FrameSource::Live);

    // Self-delivery echo on subscribed topic.
    let rec_self = a.publish(&topic_a, b"note to self").await.unwrap();
    let got_self = poll_until(&a, &topic_a, 1, Duration::from_secs(5)).await;
    assert_eq!(got_self[0].payload, b"note to self");
    assert_eq!(got_self[0].transport_id, rec_self.transport_id);

    // Reply B -> A.
    let rec_ba = b.publish(&topic_a, b"reply from B").await.unwrap();
    let got_a = poll_until(&a, &topic_a, 1, Duration::from_secs(10)).await;
    assert_eq!(got_a[0].payload, b"reply from B");
    assert_eq!(got_a[0].transport_id, rec_ba.transport_id);

    relay.shutdown().await;
}

#[tokio::test]
async fn offline_recipient_recovers_from_native_store_v3_with_pagination() {
    let relay = NativeWakuRelay::start(NativeRelayConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
        ..Default::default()
    })
    .await
    .unwrap();
    let relay_maddr = relay.multiaddrs()[0].clone();

    let a = NativeWakuTransport::start(client_cfg(&relay_maddr)).unwrap();
    wait_ready(&a, Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(700)).await;

    let topic_b = ContentTopic::new("/agentnet/1/inbox-0c/proto").unwrap();
    let mut expected_ids = Vec::new();
    let mut min_ts = i64::MAX;
    let mut max_ts = i64::MIN;
    for i in 0..12u32 {
        let rec = a
            .publish(&topic_b, format!("offline-msg-{i}").as_bytes())
            .await
            .unwrap();
        min_ts = min_ts.min(rec.timestamp_ns);
        max_ts = max_ts.max(rec.timestamp_ns);
        expected_ids.push(rec.transport_id);
    }
    // Give the relay a brief moment to ingest all 12 frames into SQLite.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // B starts AFTER all 12 messages were published.
    let b = NativeWakuTransport::start(client_cfg(&relay_maddr)).unwrap();
    wait_ready(&b, Duration::from_secs(10)).await;

    let mut cursor = None;
    let mut recovered = Vec::new();
    let mut pages = 0usize;
    loop {
        let page = b
            .history(&HistoryQuery {
                topic: topic_b.clone(),
                start_ns: min_ts - 1_000_000_000,
                end_ns: max_ts + 1_000_000_000,
                cursor: cursor.clone(),
                limit: 5,
            })
            .await
            .unwrap();
        pages += 1;
        for f in page.frames {
            assert_eq!(f.source, FrameSource::History);
            recovered.push(f);
        }
        if page.next_cursor.is_none() {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(pages, 3);
    assert_eq!(recovered.len(), 12);
    for (i, f) in recovered.iter().enumerate() {
        assert_eq!(f.payload, format!("offline-msg-{i}").as_bytes());
        assert_eq!(f.transport_id, expected_ids[i]);
    }
    assert_eq!(b.metrics().hash_mismatches, 0);
    assert_eq!(b.max_history_window_ns(), MAX_HISTORY_WINDOW_NS);

    relay.shutdown().await;
}

#[tokio::test]
async fn relay_restart_preserves_store_and_clients_redial_automatically() {
    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("relay-store.sqlite3");
    let (relay_key, _) = generate_node_key();

    let relay1 = NativeWakuRelay::start(NativeRelayConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
        node_key_hex: Some(relay_key.clone()),
        store_db_path: Some(db_path.clone()),
        ..Default::default()
    })
    .await
    .unwrap();
    let bound_addr = relay1.listen_addrs()[0].to_string();
    let relay_maddr = relay1.multiaddrs()[0].clone();

    let a = NativeWakuTransport::start(client_cfg(&relay_maddr)).unwrap();
    wait_ready(&a, Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(700)).await;

    let topic = ContentTopic::new("/agentnet/1/inbox-0d/proto").unwrap();
    let rec1 = a.publish(&topic, b"before restart").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Stop the relay completely.
    relay1.shutdown().await;
    // Wait until A notices disconnect.
    let start = Instant::now();
    while a.status().await.ready && start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!a.status().await.ready);

    // Restart the relay on the same port, key, and SQLite DB.
    let relay2 = NativeWakuRelay::start(NativeRelayConfig {
        listen_addrs: vec![bound_addr],
        node_key_hex: Some(relay_key),
        store_db_path: Some(db_path),
        ..Default::default()
    })
    .await
    .unwrap();

    // A redials automatically and recovers the pre-restart message from Store.
    wait_ready(&a, Duration::from_secs(10)).await;
    let page = a
        .history(&HistoryQuery {
            topic: topic.clone(),
            start_ns: rec1.timestamp_ns - 5_000_000_000,
            end_ns: rec1.timestamp_ns + 5_000_000_000,
            cursor: None,
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(page.frames.len(), 1);
    assert_eq!(page.frames[0].payload, b"before restart");
    assert_eq!(page.frames[0].transport_id, rec1.transport_id);

    relay2.shutdown().await;
}

#[tokio::test]
async fn preventive_allowlist_and_cluster_mismatch_reject_peers() {
    let (key_a, pid_a) = generate_node_key();
    let (key_intruder, _) = generate_node_key();

    // Relay only allows `pid_a`.
    let relay = NativeWakuRelay::start(NativeRelayConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
        cluster_id: 66,
        allowed_peer_ids: vec![pid_a.to_string()],
        ..Default::default()
    })
    .await
    .unwrap();
    let relay_maddr = relay.multiaddrs()[0].clone();

    // Authorized client A connects and becomes ready.
    let mut cfg_a = client_cfg(&relay_maddr);
    cfg_a.node_key_hex = Some(key_a);
    let a = NativeWakuTransport::start(cfg_a).unwrap();
    wait_ready(&a, Duration::from_secs(10)).await;

    // Unauthorized client C is rejected at admission by allow_block_list.
    let mut cfg_c = client_cfg(&relay_maddr);
    cfg_c.node_key_hex = Some(key_intruder);
    let c = NativeWakuTransport::start(cfg_c).unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(!c.status().await.ready, "uninvited peer must not be ready");

    // Client on wrong cluster_id (67 vs 66) is disconnected after Metadata handshake.
    let relay_open = NativeWakuRelay::start(NativeRelayConfig {
        listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".into()],
        cluster_id: 66,
        ..Default::default()
    })
    .await
    .unwrap();
    let mut wrong_cluster = client_cfg(&relay_open.multiaddrs()[0]);
    wrong_cluster.cluster_id = 67;
    let d = NativeWakuTransport::start(wrong_cluster).unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        !d.status().await.ready,
        "wrong cluster_id peer must be disconnected"
    );

    // Oversize payload rejected locally without touching the network.
    let topic = ContentTopic::new("/agentnet/1/inbox-01/proto").unwrap();
    let max = a.max_payload_len(&topic);
    let err = a.publish(&topic, &vec![0u8; max + 1]).await.unwrap_err();
    assert!(matches!(err, TransportError::TooLarge { .. }), "{err:?}");

    relay.shutdown().await;
    relay_open.shutdown().await;
}
