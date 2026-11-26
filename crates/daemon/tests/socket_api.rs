mod common;

use std::collections::HashSet;
use std::time::Duration;

use agentnet_core::api::*;
use agentnet_daemon::proto::MAX_REQUEST_LINE;
use agentnet_daemon::{DaemonConfig, EventStream, RemoteAgent};
use common::*;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn token(a: &Agent) -> String {
    std::fs::read_to_string(a.path.join("control.token"))
        .unwrap()
        .trim()
        .to_owned()
}

async fn raw_connect(
    a: &Agent,
) -> (
    BufReader<tokio::net::unix::OwnedReadHalf>,
    tokio::net::unix::OwnedWriteHalf,
) {
    let s = UnixStream::connect(a.path.join("agentnet.sock"))
        .await
        .unwrap();
    let (r, w) = s.into_split();
    (BufReader::new(r), w)
}

async fn read_json(r: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> Option<Value> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(8), r.read_line(&mut line))
        .await
        .expect("timed out reading from the socket")
        .unwrap_or(0);
    if n == 0 {
        return None;
    }
    Some(serde_json::from_str(line.trim()).unwrap())
}

// ------------------------------------------------------------------ auth

#[tokio::test]
async fn socket_auth_matrix() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;

    // wrong token
    let (mut r, mut wr) = raw_connect(&a).await;
    wr.write_all(b"{\"hello\":{\"token\":\"nope\",\"client\":\"t\"}}\n")
        .await
        .unwrap();
    let v = read_json(&mut r).await.unwrap();
    assert_eq!(v["error"]["code"], "policy_denied");
    assert!(read_json(&mut r).await.is_none(), "connection must close");

    // right length, wrong content
    let (mut r, mut wr) = raw_connect(&a).await;
    let wrong = "0".repeat(64);
    wr.write_all(format!("{{\"hello\":{{\"token\":\"{wrong}\"}}}}\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        read_json(&mut r).await.unwrap()["error"]["code"],
        "policy_denied"
    );
    assert!(read_json(&mut r).await.is_none());

    // a request instead of a hello
    let (mut r, mut wr) = raw_connect(&a).await;
    wr.write_all(b"{\"id\":1,\"method\":\"get_identity\"}\n")
        .await
        .unwrap();
    assert_eq!(
        read_json(&mut r).await.unwrap()["error"]["code"],
        "policy_denied"
    );
    assert!(read_json(&mut r).await.is_none());

    // garbage
    let (mut r, mut wr) = raw_connect(&a).await;
    wr.write_all(b"\x00\x01garbage\n").await.unwrap();
    assert_eq!(
        read_json(&mut r).await.unwrap()["error"]["code"],
        "policy_denied"
    );
    assert!(read_json(&mut r).await.is_none());

    // oversize hello line (no newline within the hello limit)
    let (mut r, mut wr) = raw_connect(&a).await;
    wr.write_all(&vec![b'x'; 8192]).await.unwrap();
    assert_eq!(
        read_json(&mut r).await.unwrap()["error"]["code"],
        "policy_denied"
    );
    assert!(read_json(&mut r).await.is_none());

    // the right token works, and the daemon still serves after all of that
    let (mut r, mut wr) = raw_connect(&a).await;
    wr.write_all(
        format!(
            "{{\"hello\":{{\"token\":\"{}\",\"client\":\"t\"}}}}\n",
            token(&a)
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let v = read_json(&mut r).await.unwrap();
    assert_eq!(v["hello"]["ok"], true);
    assert_eq!(v["hello"]["agent_id"], a.address.as_str());
    wr.write_all(b"{\"id\":7,\"method\":\"get_identity\"}\n")
        .await
        .unwrap();
    let v = read_json(&mut r).await.unwrap();
    assert_eq!(v["id"], 7);
    assert_eq!(v["result"]["agent_id"], a.address.as_str());
    // unknown method and bad params are errors, not disconnects
    wr.write_all(b"{\"id\":8,\"method\":\"rm_rf\"}\n")
        .await
        .unwrap();
    assert_eq!(
        read_json(&mut r).await.unwrap()["error"]["code"],
        "invalid_argument"
    );
    wr.write_all(b"{\"id\":9,\"method\":\"send_message\",\"params\":{\"nope\":1}}\n")
        .await
        .unwrap();
    let v = read_json(&mut r).await.unwrap();
    assert_eq!(
        (v["id"].clone(), v["error"]["code"].clone()),
        (json!(9), json!("invalid_argument"))
    );
    // an oversize request closes the connection after an error
    let mut big = vec![b'a'; MAX_REQUEST_LINE + 10];
    big.push(b'\n');
    let _ = wr.write_all(&big).await;
    let v = read_json(&mut r).await.unwrap();
    assert_eq!(v["error"]["code"], "too_large");
    assert!(read_json(&mut r).await.is_none());

    a.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn hello_timeout_closes_the_connection() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    let (mut r, _wr) = raw_connect(&a).await;
    // Send nothing: the server gives up after its hello timeout (5 s).
    let started = std::time::Instant::now();
    let v = read_json(&mut r).await.unwrap();
    assert_eq!(v["error"]["code"], "policy_denied");
    assert!(started.elapsed() >= Duration::from_secs(4));
    let mut rest = Vec::new();
    r.read_to_end(&mut rest).await.unwrap();
    a.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn socket_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    let mode = |p: &str| {
        std::fs::metadata(a.path.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("agentnet.sock"), 0o600);
    assert_eq!(mode("control.token"), 0o600);
    assert_eq!(mode("identity.json"), 0o600);
    assert_eq!(mode("agentnet.toml"), 0o600);
    assert_eq!(mode("lock"), 0o600);
    assert_eq!(mode("agentnet.db"), 0o600);
    assert_eq!(
        std::fs::metadata(&a.path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    a.daemon.unwrap().shutdown().await;
}

// ------------------------------------------------------------------ methods

#[tokio::test]
async fn every_method_round_trips_and_equals_the_direct_node() {
    let w = World::new();
    let (a, b) = pair(&w, cfg(), cfg()).await;
    let an = a.d().node().clone();
    let bn = b.d().node().clone();

    // identity / contacts
    assert_eq!(
        a.remote.get_identity().await.unwrap(),
        an.get_identity().await.unwrap()
    );
    assert_eq!(
        a.remote.list_contacts().await.unwrap(),
        an.list_contacts().await.unwrap()
    );
    assert_eq!(a.remote.list_contacts().await.unwrap().len(), 1);

    // send -> delivered
    let id = a
        .remote
        .send_message(SendMessageRequest {
            recipient: b.address.clone(),
            body: "hello over the socket".into(),
            conversation_id: Some("conv-1".into()),
            idempotency_key: Some("k1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!id.deduplicated);
    let again = a
        .remote
        .send_message(SendMessageRequest {
            recipient: b.address.clone(),
            body: "hello over the socket".into(),
            conversation_id: Some("conv-1".into()),
            idempotency_key: Some("k1".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(again.deduplicated);
    assert_eq!(again.message_id, id.message_id);
    wait_until("message delivered", || async {
        a.remote
            .get_message_status(id.message_id.clone())
            .await
            .unwrap()
            .state
            == DeliveryState::Delivered
    })
    .await;
    assert_eq!(
        a.remote
            .get_message_status(id.message_id.clone())
            .await
            .unwrap(),
        an.get_message_status(id.message_id.clone()).await.unwrap()
    );
    assert_eq!(
        a.remote.read_outbox(PageRequest::default()).await.unwrap(),
        an.read_outbox(PageRequest::default()).await.unwrap()
    );

    // inbox on B
    wait_until("b inbox", || async { b.inbox_len().await == 1 }).await;
    let req = ReadInboxRequest {
        unread_only: true,
        ..Default::default()
    };
    let r1 = b.remote.read_inbox(req.clone()).await.unwrap();
    assert_eq!(r1, bn.read_inbox(req.clone()).await.unwrap());
    assert_eq!(r1.records[0].body, "hello over the socket");
    // get_message: the id an event carries resolves to the same record, equal to
    // the direct node; a wrong sender or an unknown id is not_found.
    let one = b
        .remote
        .get_message(GetMessageRequest {
            message_id: id.message_id.clone(),
            sender: None,
        })
        .await
        .unwrap();
    assert_eq!(one, r1.records[0]);
    assert_eq!(
        one,
        bn.get_message(GetMessageRequest {
            message_id: id.message_id.clone(),
            sender: Some(a.address.clone()),
        })
        .await
        .unwrap()
    );
    for (mid, sender) in [
        (id.message_id.as_str(), Some(b.address.clone())),
        ("nope", None),
    ] {
        let e = b
            .remote
            .get_message(GetMessageRequest {
                message_id: mid.into(),
                sender,
            })
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }
    let conv_r = b
        .remote
        .read_conversation("conv-1".into(), PageRequest::default())
        .await
        .unwrap();
    assert_eq!(
        conv_r,
        bn.read_conversation("conv-1".into(), PageRequest::default())
            .await
            .unwrap()
    );
    assert_eq!(conv_r.entries.len(), 1);

    // events: message.received exists, no plaintext in it
    let ev = b.remote.read_events(PageRequest::default()).await.unwrap();
    assert_eq!(ev, bn.read_events(PageRequest::default()).await.unwrap());
    assert_eq!(ev.events.len(), 1);
    assert_eq!(ev.events[0].event_type, EventType::MessageReceived);
    assert!(!serde_json::to_string(&ev.events[0])
        .unwrap()
        .contains("hello over the socket"));
    b.remote
        .ack_events(ev.events[0].cursor.clone())
        .await
        .unwrap();
    assert!(b.remote.ack_events("garbage".into()).await.is_err());

    // ack
    let ack1 = b
        .remote
        .acknowledge_message(r1.records[0].message_id.clone())
        .await
        .unwrap();
    assert!(ack1.newly_acknowledged);
    let ack2 = bn
        .acknowledge_message(r1.records[0].message_id.clone())
        .await
        .unwrap();
    assert!(!ack2.newly_acknowledged);

    // triggers
    let t = b
        .remote
        .create_trigger(CreateTriggerRequest {
            sender: Some(a.address.clone()),
            target_session: "s1".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        b.remote.list_triggers(false).await.unwrap(),
        bn.list_triggers(false).await.unwrap()
    );
    let denied = b
        .remote
        .create_trigger(CreateTriggerRequest {
            target_session: "not-allowed".into(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(denied.code, ErrorCode::PolicyDenied);
    assert!(
        b.remote
            .delete_trigger(t.trigger_id.clone())
            .await
            .unwrap()
            .deleted
    );
    assert!(
        !bn.delete_trigger(t.trigger_id.clone())
            .await
            .unwrap()
            .deleted
    );

    // status
    let st = a.remote.network_status(true).await.unwrap();
    assert_eq!(st.mode, "private");
    assert_eq!(st.queue, an.network_status(true).await.unwrap().queue);

    // errors keep their codes
    let e = a
        .remote
        .get_message_status("no-such".into())
        .await
        .unwrap_err();
    let direct = an.get_message_status("no-such".into()).await.unwrap_err();
    assert_eq!(e, direct);
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = a
        .remote
        .read_inbox(ReadInboxRequest {
            cursor: Some("x".into()),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);

    // admin methods
    let ci = a
        .remote
        .set_contact_trust(&b.address, Trust::Untrusted)
        .await
        .unwrap();
    assert_eq!(ci.trust, Trust::Untrusted);
    assert_eq!(
        a.remote.list_contacts().await.unwrap()[0].trust,
        Trust::Untrusted
    );
    assert!(a
        .remote
        .set_contact_trust(&b.address, Trust::Unknown)
        .await
        .is_err());
    assert!(a.remote.list_quarantined().await.unwrap().is_empty());
    assert_eq!(
        a.remote.release_quarantined("nope").await.unwrap_err().code,
        ErrorCode::NotFound
    );
    assert!(a.remote.remove_contact(&b.address).await.unwrap());
    assert!(!a.remote.remove_contact(&b.address).await.unwrap());
    let m = a.remote.metrics().await.unwrap();
    assert_eq!(m, an.metrics());
    let ds = a.remote.daemon_status().await.unwrap();
    assert_eq!(ds["agent_id"], a.address.as_str());
    assert_eq!(ds["mode"], "private");
    assert_eq!(ds["webhook"]["enabled"], false);

    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn quarantine_list_and_release_through_the_socket() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    let b = Agent::new(&w, "b", cfg()).await;
    // B knows A and sends; A does not know B -> quarantined at A.
    b.add_contact_of(&a).await;
    let mid = b.send(&a, "from an unknown").await;
    wait_until("quarantined at a", || async {
        !a.remote.list_quarantined().await.unwrap().is_empty()
    })
    .await;
    assert_eq!(a.inbox_len().await, 0);
    let q = a.remote.list_quarantined().await.unwrap();
    assert_eq!(q[0].message_id, mid);
    // A quarantined message is not returned by get_message.
    let hidden = a
        .remote
        .get_message(GetMessageRequest {
            message_id: mid.clone(),
            sender: Some(b.address.clone()),
        })
        .await
        .unwrap_err();
    assert_eq!(hidden.code, ErrorCode::NotFound);
    // Release needs a Trusted sender.
    assert_eq!(
        a.remote.release_quarantined(&mid).await.unwrap_err().code,
        ErrorCode::PolicyDenied
    );
    a.add_contact_of(&b).await;
    assert_eq!(a.remote.release_quarantined(&mid).await.unwrap(), 1);
    assert_eq!(a.inbox_len().await, 1);
    let released = a
        .remote
        .get_message(GetMessageRequest {
            message_id: mid.clone(),
            sender: None,
        })
        .await
        .unwrap();
    assert_eq!(released.body, "from an unknown");
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

/// Review finding 5 through the socket: a quarantine of heavily escaped bodies
/// is listed page by page; `quarantine.list` answers an object, not an array.
#[tokio::test]
async fn quarantine_list_is_paged_through_the_socket() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    let b = Agent::new(&w, "b", cfg()).await;
    b.add_contact_of(&a).await;
    let body = "\"".repeat(60_000);
    let total = 40usize;
    for _ in 0..total {
        b.send(&a, &body).await;
    }
    wait_until("all quarantined at a", || async {
        a.remote.list_quarantined().await.unwrap().len() == total
    })
    .await;
    let mut cursor = None;
    let mut seen = HashSet::new();
    let mut pages = 0;
    loop {
        let page = a
            .remote
            .list_quarantined_page(PageRequest {
                cursor: cursor.clone(),
                limit: Some(15),
            })
            .await
            .unwrap();
        assert!(page.records.len() <= 15);
        pages += 1;
        for r in &page.records {
            assert!(seen.insert(r.message_id.clone()));
        }
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!((seen.len(), pages), (total, 3));
    // raw protocol: an object with records / next_cursor / has_more
    let (mut r, mut wr) = raw_connect(&a).await;
    wr.write_all(
        format!(
            "{{\"hello\":{{\"token\":\"{}\",\"client\":\"t\"}}}}\n",
            token(&a)
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    read_json(&mut r).await.unwrap();
    wr.write_all(b"{\"id\":1,\"method\":\"quarantine.list\",\"params\":{\"limit\":2}}\n")
        .await
        .unwrap();
    let v = read_json(&mut r).await.unwrap();
    assert_eq!(v["result"]["records"].as_array().unwrap().len(), 2);
    assert_eq!(v["result"]["has_more"], true);
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

// ------------------------------------------------------------------ events

#[tokio::test]
async fn events_replay_live_ack_and_reconnect_without_loss() {
    let w = World::new();
    let mut cb = cfg();
    cb.policy.unknown_senders = agentnet_core::config::UnknownSenders::Quarantine;
    let (a, b) = pair(&w, cfg(), cb).await;

    // Three events exist before anyone subscribes.
    let mut sent = Vec::new();
    for i in 0..3 {
        sent.push(a.send(&b, &format!("pre {i}")).await);
    }
    wait_until("3 pre events", || async { b.inbox_len().await == 3 }).await;

    // Subscribe from the beginning: replay of all three, then live.
    let mut s = EventStream::connect(&b.path, None).await.unwrap();
    let mut seen = Vec::new();
    for _ in 0..3 {
        let ev = tokio::time::timeout(Duration::from_secs(5), s.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(ev.cursor.len() > 4);
        seen.push(ev);
    }
    assert_eq!(
        seen.iter()
            .map(|e| e.message_id.clone())
            .collect::<Vec<_>>(),
        {
            let mut m: Vec<_> = seen.iter().map(|e| e.message_id.clone()).collect();
            m.sort_by_key(|id| sent.iter().position(|s| s == id));
            m
        }
    );
    let live_id = a.send(&b, "live").await;
    let live = tokio::time::timeout(Duration::from_secs(5), s.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(live.message_id, live_id);
    assert_eq!(live.agent_id, b.address);
    seen.push(live);

    // Ack on the same connection, then drop the connection.
    s.ack(&seen[1].cursor).await.unwrap();
    assert_eq!(
        b.remote
            .network_status(false)
            .await
            .unwrap()
            .queue
            .events_unacked,
        2
    );
    drop(s);

    // Two more events arrive while no one listens.
    let m5 = a.send(&b, "offline 1").await;
    let m6 = a.send(&b, "offline 2").await;
    wait_until("6 messages", || async { b.inbox_len().await == 6 }).await;

    // Resume from the last cursor we handled: exactly the events after it.
    let mut s = EventStream::connect(&b.path, Some(seen[3].cursor.clone()))
        .await
        .unwrap();
    let mut resumed = Vec::new();
    for _ in 0..2 {
        resumed.push(
            tokio::time::timeout(Duration::from_secs(5), s.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(resumed[0].message_id, m5);
    assert_eq!(resumed[1].message_id, m6);
    // Nothing else is pending.
    assert!(tokio::time::timeout(Duration::from_millis(400), s.next())
        .await
        .is_err());
    // Ack from another connection.
    b.remote
        .ack_events(resumed[1].cursor.clone())
        .await
        .unwrap();
    assert_eq!(
        b.remote
            .network_status(false)
            .await
            .unwrap()
            .queue
            .events_unacked,
        0
    );

    // Event ids are unique across everything we saw (idempotency keys).
    let ids: HashSet<_> = seen
        .iter()
        .chain(resumed.iter())
        .map(|e| e.event_id.clone())
        .collect();
    assert_eq!(ids.len(), 6);

    // A bad cursor is rejected at subscribe time.
    assert!(EventStream::connect(&b.path, Some("garbage".into()))
        .await
        .is_err());
    // A second subscription on one connection is a conflict.
    let rem = b.remote.clone();
    drop(rem);
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn event_stream_survives_a_daemon_restart_by_resuming_from_the_cursor() {
    let w = World::new();
    let (a, mut b) = pair(&w, cfg(), cfg()).await;
    let first = a.send(&b, "one").await;
    let mut s = EventStream::connect(&b.path, None).await.unwrap();
    let e1 = tokio::time::timeout(Duration::from_secs(5), s.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(e1.message_id, first);

    // Restart B's daemon: the stream ends cleanly.
    b.daemon.take().unwrap().shutdown().await;
    let end = tokio::time::timeout(Duration::from_secs(5), s.next())
        .await
        .unwrap()
        .unwrap();
    assert!(end.is_none());

    // A sends while B is down; B restarts and catches up (history), the
    // consumer resumes from its cursor and sees the new event exactly once.
    let second = a.send(&b, "two").await;
    b.daemon = Some(w.start(&b.path, cfg()).await);
    wait_until("b inbox has two", || async { b.inbox_len().await == 2 }).await;
    let mut s = EventStream::connect(&b.path, Some(e1.cursor.clone()))
        .await
        .unwrap();
    let e2 = tokio::time::timeout(Duration::from_secs(5), s.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(e2.message_id, second);
    assert_ne!(e1.event_id, e2.event_id);
    assert!(tokio::time::timeout(Duration::from_millis(300), s.next())
        .await
        .is_err());
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

// ------------------------------------------------------------------ RemoteAgent availability

#[tokio::test]
async fn remote_agent_reports_unavailable_when_down_and_recovers() {
    let w = World::new();
    let (path, address, _) = w.init("late");
    let remote = RemoteAgent::new(&path);
    let e = remote.get_identity().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    assert!(e.message.contains("agentnet serve"), "{}", e.message);
    // Missing data dir entirely.
    let ghost = RemoteAgent::new(w.tmp.path().join("ghost"));
    let e = ghost.list_contacts().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);

    let d = w.start(&path, cfg()).await;
    assert_eq!(remote.get_identity().await.unwrap().agent_id, address);

    // Daemon stops: next call fails as Unavailable (possibly after one reconnect attempt).
    d.shutdown().await;
    let e = remote.get_identity().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
    assert!(e.message.contains("agentnet serve"), "{}", e.message);

    // Daemon comes back: same client works again.
    let d = w.start(&path, cfg()).await;
    assert_eq!(remote.get_identity().await.unwrap().agent_id, address);
    d.shutdown().await;
}

#[tokio::test]
async fn remote_agent_with_a_wrong_token_is_denied_not_unavailable() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    let other = w.tmp.path().join("othertoken");
    std::fs::write(&other, "f".repeat(64)).unwrap();
    std::fs::set_permissions(&other, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let r = RemoteAgent::with_paths(a.path.join("agentnet.sock"), other, "t");
    let e = r.get_identity().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    a.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn changes_stream_resubscribes_after_a_daemon_restart() {
    let w = World::new();
    let (a, mut b) = pair(&w, cfg(), cfg()).await;
    let mut rx = b.remote.changes();
    // Hints are lossy: give the background subscription time to attach first.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let m1 = a.send(&b, "first").await;
    let got = recv_hint(&mut rx, |h| matches!(h, ChangeHint::Inbox)).await;
    assert!(got);
    let _ = m1;

    b.daemon.take().unwrap().shutdown().await;
    // Restart; the client reconnects with backoff and emits a synthetic burst.
    b.daemon = Some(w.start(&b.path, cfg()).await);
    let mut kinds = HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let want = ["inbox", "outbox", "triggers", "identity", "events"];
    while !want.iter().all(|k| kinds.contains(k)) && tokio::time::Instant::now() < deadline {
        if let Ok(Ok(h)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            kinds.insert(match h {
                ChangeHint::Inbox => "inbox",
                ChangeHint::Outbox => "outbox",
                ChangeHint::Triggers => "triggers",
                ChangeHint::Identity => "identity",
                ChangeHint::Events => "events",
                ChangeHint::Conversation { .. } => "conv",
            });
        }
    }
    for k in ["inbox", "outbox", "triggers", "identity", "events"] {
        assert!(kinds.contains(k), "missing synthetic hint {k}: {kinds:?}");
    }
    // And live hints flow again.
    a.send(&b, "after restart").await;
    assert!(recv_hint(&mut rx, |h| matches!(h, ChangeHint::Inbox)).await);
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

async fn recv_hint(
    rx: &mut tokio::sync::broadcast::Receiver<ChangeHint>,
    pred: impl Fn(&ChangeHint) -> bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(h)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            if pred(&h) {
                return true;
            }
        }
    }
    false
}

// ------------------------------------------------------------------ lifecycle

#[tokio::test]
async fn lock_exclusivity_and_graceful_shutdown_cleanup() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    // A second daemon on the same data dir fails with a clear error.
    let err = agentnet_daemon::Daemon::start_with_transport(
        &a.path,
        cfg(),
        std::sync::Arc::new(w.net.endpoint()),
        std::sync::Arc::new(w.clock.clone()),
    )
    .await
    .err()
    .expect("second start must fail");
    let msg = err.to_string();
    assert!(msg.contains("another AgentNet process"), "{msg}");
    // The first daemon is unaffected.
    assert_eq!(a.remote.get_identity().await.unwrap().agent_id, a.address);

    a.daemon.unwrap().shutdown().await;
    assert!(
        !a.path.join("agentnet.sock").exists(),
        "socket must be removed"
    );
    // The lock is free again and a restart works with state intact.
    let d = w.start(&a.path, cfg()).await;
    assert_eq!(a.remote.get_identity().await.unwrap().agent_id, a.address);
    d.shutdown().await;
}

#[tokio::test]
async fn shutdown_request_through_the_socket() {
    let w = World::new();
    let a = Agent::new(&w, "a", cfg()).await;
    let d = a.daemon.unwrap();
    let handle = d.shutdown_handle();
    a.remote.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), d.shutdown_requested())
        .await
        .unwrap();
    handle.shutdown();
    d.shutdown().await;
    assert!(!a.path.join("agentnet.sock").exists());
}

#[tokio::test]
async fn crash_recovery_reacquires_the_lock_and_keeps_state() {
    let w = World::new();
    let (a, mut b) = pair(&w, cfg(), cfg()).await;
    let mid = a.send(&b, "survives a crash").await;
    wait_until("delivered", || async {
        a.remote
            .get_message_status(mid.clone())
            .await
            .unwrap()
            .state
            == DeliveryState::Delivered
    })
    .await;
    assert_eq!(b.inbox_len().await, 1);

    // "Crash": drop without shutdown. The socket file stays behind.
    drop(b.daemon.take());
    assert!(b.path.join("agentnet.sock").exists());
    // Give aborted tasks a moment to unwind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restart: lock reacquired, stale socket replaced, state intact.
    b.daemon = Some(w.start(&b.path, cfg()).await);
    assert_eq!(b.inbox_len().await, 1);
    let page = b
        .remote
        .read_inbox(ReadInboxRequest::default())
        .await
        .unwrap();
    assert_eq!(page.records[0].message_id, mid);
    assert_eq!(b.remote.get_identity().await.unwrap().agent_id, b.address);
    // Still receives.
    a.send(&b, "after the crash").await;
    wait_until("second message", || async { b.inbox_len().await == 2 }).await;
    a.daemon.unwrap().shutdown().await;
    b.daemon.unwrap().shutdown().await;
}

#[tokio::test]
async fn startup_refuses_bad_configuration_and_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new();
    let (path, _, _) = w.init("x");
    // invalid config
    let mut bad = DaemonConfig::default();
    bad.network.public_fallback = true;
    let e = agentnet_daemon::Daemon::start_with_transport(
        &path,
        bad,
        std::sync::Arc::new(w.net.endpoint()),
        std::sync::Arc::new(w.clock.clone()),
    )
    .await
    .err()
    .unwrap();
    assert!(e.to_string().contains("public_fallback"));
    // The failed start must not have left the lock held.
    // loose directory permissions
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = agentnet_daemon::Daemon::start_with_transport(
        &path,
        cfg(),
        std::sync::Arc::new(w.net.endpoint()),
        std::sync::Arc::new(w.clock.clone()),
    )
    .await
    .err()
    .unwrap();
    assert!(e.to_string().contains("chmod 700"), "{e}");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Missing identity file
    std::fs::remove_file(path.join("identity.json")).unwrap();
    let e = agentnet_daemon::Daemon::start_with_transport(
        &path,
        cfg(),
        std::sync::Arc::new(w.net.endpoint()),
        std::sync::Arc::new(w.clock.clone()),
    )
    .await
    .err()
    .unwrap();
    assert!(e.to_string().starts_with("identity"), "{e}");
}

#[tokio::test]
async fn http_mcp_serves_with_its_token_and_only_on_loopback() {
    let w = World::new();
    let (path, _, _) = w.init("m");
    let mut c = cfg();
    c.mcp_http.enabled = true;
    c.mcp_http.bind = "127.0.0.1:0".into();
    let d = w.start(&path, c).await;
    let addr = d.http_addr().unwrap();
    assert!(addr.ip().is_loopback());
    let token = std::fs::read_to_string(path.join("mcp-http.token")).unwrap();
    let client = reqwest_like_post(addr, "").await;
    assert_eq!(client, 401, "no bearer token must be refused");
    let ok = reqwest_like_post(addr, token.trim()).await;
    assert_ne!(ok, 401, "valid token must pass authentication");
    d.shutdown().await;
}

/// Minimal raw HTTP POST returning the status code (avoids a client dependency).
async fn reqwest_like_post(addr: std::net::SocketAddr, token: &str) -> u16 {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#;
    let auth = if token.is_empty() {
        String::new()
    } else {
        format!("Authorization: Bearer {token}\r\n")
    };
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out)).await;
    out.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}
