//! Triggers, events and cursor pagination.

mod common;

use agentnet_core::api::*;
use agentnet_core::config::UnknownSenders;
use agentnet_core::NodeConfig;
use common::*;

async fn pair_with(w: &World, bcfg: NodeConfig) -> (Agent, Agent) {
    let a = w.agent("a", cfg());
    let b = w.agent("b", bcfg);
    exchange(&a, &b).await;
    a.node.step_receive().await.unwrap();
    b.node.step_receive().await.unwrap();
    (a, b)
}

fn trig(sess: &str) -> CreateTriggerRequest {
    CreateTriggerRequest {
        target_session: sess.into(),
        ..Default::default()
    }
}

async fn send_full(
    a: &Agent,
    to: &Agent,
    body: &str,
    conv: Option<&str>,
    corr: Option<&str>,
    ty: Option<&str>,
) -> SendMessageResponse {
    a.node
        .send_message(SendMessageRequest {
            recipient: to.addr.clone(),
            body: body.into(),
            conversation_id: conv.map(Into::into),
            correlation_id: corr.map(Into::into),
            message_type: ty.map(Into::into),
            ..Default::default()
        })
        .await
        .unwrap()
}

async fn events(b: &Agent) -> Vec<EventRecord> {
    b.node
        .read_events(PageRequest {
            limit: Some(200),
            ..Default::default()
        })
        .await
        .unwrap()
        .events
}

fn matched(evs: &[EventRecord]) -> Vec<&EventRecord> {
    evs.iter()
        .filter(|e| e.event_type == EventType::TriggerMatched)
        .collect()
}

#[tokio::test]
async fn policy_gates_on_create_trigger() {
    let w = World::new();
    // disabled by default
    let (a, b) = pair_with(&w, NodeConfig::default()).await;
    let e = b.node.create_trigger(trig("s1")).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PolicyDenied);
    assert!(e.message.contains("disabled"));
    drop((a, b));

    let w = World::new();
    let (a, b) = pair_with(
        &w,
        cfg_with(|c| {
            c.triggers.max_active = 2;
            c.triggers.max_lifetime_hours = 1;
            c.triggers.default_lifetime_s = 600;
        }),
    )
    .await;
    let code = |r: Result<TriggerInfo, ApiError>| r.unwrap_err().code;
    assert_eq!(
        code(b.node.create_trigger(trig("not-allowed")).await),
        ErrorCode::PolicyDenied
    );
    assert_eq!(
        code(b.node.create_trigger(trig("")).await),
        ErrorCode::InvalidArgument
    );
    let mut r = trig("s1");
    r.expires_in_seconds = Some(3601);
    assert_eq!(
        code(b.node.create_trigger(r).await),
        ErrorCode::PolicyDenied
    );
    let mut r = trig("s1");
    r.expires_in_seconds = Some(0);
    assert_eq!(
        code(b.node.create_trigger(r).await),
        ErrorCode::InvalidArgument
    );
    let stranger = w.agent("z", cfg());
    let mut r = trig("s1");
    r.sender = Some(stranger.addr.clone());
    assert_eq!(
        code(b.node.create_trigger(r).await),
        ErrorCode::PolicyDenied,
        "sender must be a trusted contact"
    );
    b.node
        .add_contact(AddContactRequest {
            contact_record: stranger.record.clone(),
            trust: Some(Trust::Untrusted),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut r = trig("s1");
    r.sender = Some(stranger.addr.clone());
    assert_eq!(
        code(b.node.create_trigger(r).await),
        ErrorCode::PolicyDenied,
        "untrusted contact is not enough"
    );
    let mut r = trig("s1");
    r.sender = Some("garbage".into());
    assert_eq!(
        code(b.node.create_trigger(r).await),
        ErrorCode::InvalidArgument
    );
    let mut r = trig("s1");
    r.message_type = Some("Bad Type".into());
    assert_eq!(
        code(b.node.create_trigger(r).await),
        ErrorCode::InvalidArgument
    );
    let mut r = trig("s1");
    r.since_cursor = Some("garbage".into());
    assert_eq!(
        code(b.node.create_trigger(r).await),
        ErrorCode::InvalidArgument
    );
    // defaults
    let t = b.node.create_trigger(trig("s1")).await.unwrap();
    assert!(t.once);
    assert_eq!(t.state, TriggerState::Active);
    assert_eq!(t.expires_at - t.created_at, 600_000);
    b.node.create_trigger(trig("s2")).await.unwrap();
    assert_eq!(
        code(b.node.create_trigger(trig("s1")).await),
        ErrorCode::PolicyDenied,
        "max_active"
    );
    let _ = a;
}

#[tokio::test]
async fn once_trigger_consumed_exactly_once_under_duplicates_and_two_messages() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg()).await;
    let t = b
        .node
        .create_trigger(CreateTriggerRequest {
            sender: Some(a.addr.clone()),
            ..trig("s1")
        })
        .await
        .unwrap();
    b.transport.set_duplicate_delivery(5);
    let m1 = a.send(&b, "one").await;
    let m2 = a.send(&b, "two").await;
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    let evs = events(&b).await;
    assert_eq!(
        evs.iter()
            .filter(|e| e.event_type == EventType::MessageReceived)
            .count(),
        2
    );
    let m = matched(&evs);
    assert_eq!(
        m.len(),
        1,
        "two distinct matching messages, one once-trigger"
    );
    assert_eq!(m[0].trigger_id.as_deref(), Some(t.trigger_id.as_str()));
    assert_eq!(m[0].target_session.as_deref(), Some("s1"));
    assert_eq!(
        m[0].message_id, m1.message_id,
        "first persisted message wins"
    );
    assert_ne!(m[0].message_id, m2.message_id);
    let tl = b.node.list_triggers(true).await.unwrap();
    assert_eq!(tl[0].state, TriggerState::Consumed);
    assert_eq!(tl[0].match_count, 1);
    assert!(b.node.list_triggers(false).await.unwrap().is_empty());
    // re-delivery of the same message (history) never yields a second event
    w.advance(1000);
    b.node.step_history_sync().await.unwrap();
    b.transport.set_duplicate_delivery(1);
    let evs = events(&b).await;
    assert_eq!(matched(&evs).len(), 1);
    assert_eq!(evs.len(), 3);
}

#[tokio::test]
async fn unauthorized_senders_never_match() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg()).await;
    let x = w.agent("x", cfg());
    x.add(&b).await;
    x.node.step_receive().await.unwrap();
    let u = w.agent("u", cfg());
    u.add(&b).await;
    u.node.step_receive().await.unwrap();
    b.node
        .add_contact(AddContactRequest {
            contact_record: u.record.clone(),
            trust: Some(Trust::Untrusted),
            ..Default::default()
        })
        .await
        .unwrap();
    b.node
        .create_trigger(CreateTriggerRequest {
            once: Some(false),
            ..trig("s1")
        })
        .await
        .unwrap();
    x.send(&b, "unknown").await;
    u.send(&b, "untrusted").await;
    settle(&[&x, &u, &b]).await;
    assert_eq!(events(&b).await.len(), 0);
    assert_eq!(b.n("inbox"), 2);
    // a trusted sender does match the same trigger
    a.send(&b, "trusted").await;
    settle(&[&a, &b]).await;
    assert_eq!(matched(&events(&b).await).len(), 1);
    // accept policy: unknown sender is delivered but still never matches
    let w2 = World::new();
    let (_, b2) = pair_with(
        &w2,
        cfg_with(|c| c.policy.unknown_senders = UnknownSenders::Accept),
    )
    .await;
    let x2 = w2.agent("x", cfg());
    x2.add(&b2).await;
    x2.node.step_receive().await.unwrap();
    b2.node
        .create_trigger(CreateTriggerRequest {
            once: Some(false),
            ..trig("s1")
        })
        .await
        .unwrap();
    x2.send(&b2, "hi").await;
    settle(&[&x2, &b2]).await;
    let evs = events(&b2).await;
    assert_eq!((evs.len(), matched(&evs).len()), (1, 0));
}

#[tokio::test]
async fn filter_combinations() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg()).await;
    let c = w.agent("c", cfg());
    exchange(&c, &b).await;
    c.node.step_receive().await.unwrap();
    let mk = |f: &dyn Fn(&mut CreateTriggerRequest)| {
        let mut r = CreateTriggerRequest {
            once: Some(false),
            ..trig("s1")
        };
        f(&mut r);
        r
    };
    let t_any = b.node.create_trigger(mk(&|_| {})).await.unwrap();
    let t_sender = b
        .node
        .create_trigger(mk(&|r| r.sender = Some(c.addr.clone())))
        .await
        .unwrap();
    let t_type = b
        .node
        .create_trigger(mk(&|r| r.message_type = Some("task.result".into())))
        .await
        .unwrap();
    let t_conv = b
        .node
        .create_trigger(mk(&|r| r.conversation_id = Some("conv-1".into())))
        .await
        .unwrap();
    let t_corr = b
        .node
        .create_trigger(mk(&|r| r.correlation_id = Some("corr-1".into())))
        .await
        .unwrap();
    let t_all = b
        .node
        .create_trigger(mk(&|r| {
            r.sender = Some(a.addr.clone());
            r.message_type = Some("task.result".into());
            r.conversation_id = Some("conv-1".into());
            r.correlation_id = Some("corr-1".into());
        }))
        .await
        .unwrap();
    a.node.step_receive().await.unwrap();
    // 1: plain message from a, no conv/corr
    let m1 = send_full(&a, &b, "1", None, None, None).await;
    // 2: task.result from a, conv-1, corr-1: matches any, type, conv, corr, all
    let m2 = send_full(
        &a,
        &b,
        "2",
        Some("conv-1"),
        Some("corr-1"),
        Some("task.result"),
    )
    .await;
    // 3: message from c in conv-1: matches any, sender(c), conv
    let m3 = send_full(&c, &b, "3", Some("conv-1"), None, None).await;
    settle(&[&a, &c, &b]).await;
    let evs = events(&b).await;
    let by_trigger = |t: &TriggerInfo| -> Vec<String> {
        matched(&evs)
            .iter()
            .filter(|e| e.trigger_id.as_deref() == Some(&t.trigger_id))
            .map(|e| e.message_id.clone())
            .collect()
    };
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    assert_eq!(
        sorted(by_trigger(&t_any)),
        sorted(vec![
            m1.message_id.clone(),
            m2.message_id.clone(),
            m3.message_id.clone()
        ])
    );
    assert_eq!(by_trigger(&t_sender), vec![m3.message_id.clone()]);
    assert_eq!(by_trigger(&t_type), vec![m2.message_id.clone()]);
    assert_eq!(
        sorted(by_trigger(&t_conv)),
        sorted(vec![m2.message_id.clone(), m3.message_id.clone()])
    );
    assert_eq!(by_trigger(&t_corr), vec![m2.message_id.clone()]);
    assert_eq!(by_trigger(&t_all), vec![m2.message_id.clone()]);
    let list = b.node.list_triggers(false).await.unwrap();
    assert_eq!(list.len(), 6);
    assert_eq!(
        list.iter()
            .find(|t| t.trigger_id == t_any.trigger_id)
            .unwrap()
            .match_count,
        3
    );
    // events carry references only: serialize and make sure no body leaks
    let json = serde_json::to_string(&evs).unwrap();
    assert!(!json.contains("\"body\""));
}

#[tokio::test]
async fn trigger_expiry() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg()).await;
    let t = b
        .node
        .create_trigger(CreateTriggerRequest {
            expires_in_seconds: Some(10),
            ..trig("s1")
        })
        .await
        .unwrap();
    w.advance(11_000);
    // expired by time even before maintenance runs
    assert_eq!(
        b.node.list_triggers(true).await.unwrap()[0].state,
        TriggerState::Expired
    );
    a.send(&b, "late").await;
    settle(&[&a, &b]).await;
    assert_eq!(matched(&events(&b).await).len(), 0);
    assert_eq!(b.node.step_maintenance().unwrap().triggers_expired, 1);
    assert_eq!(
        b.node.list_triggers(true).await.unwrap()[0].state,
        TriggerState::Expired
    );
    assert!(b.node.list_triggers(false).await.unwrap().is_empty());
    let _ = t;
}

#[tokio::test]
async fn since_cursor_closes_reply_before_trigger_race() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg()).await;
    // 1. take a tail cursor from an EMPTY inbox
    let tail = b
        .node
        .read_inbox(ReadInboxRequest::default())
        .await
        .unwrap()
        .next_cursor
        .expect("always a cursor");
    // 2. the reply arrives before the trigger exists
    let reply = a.send(&b, "reply").await;
    settle(&[&a, &b]).await;
    assert_eq!(events(&b).await.len(), 1);
    // 3. trigger created with since_cursor still matches, exactly once, immediately
    let t = b
        .node
        .create_trigger(CreateTriggerRequest {
            since_cursor: Some(tail.clone()),
            sender: Some(a.addr.clone()),
            ..trig("s1")
        })
        .await
        .unwrap();
    assert_eq!(t.state, TriggerState::Consumed);
    assert_eq!(t.match_count, 1);
    let m = events(&b).await;
    assert_eq!(matched(&m).len(), 1);
    assert_eq!(matched(&m)[0].message_id, reply.message_id);
    // later messages do not match the consumed trigger
    a.send(&b, "later").await;
    settle(&[&a, &b]).await;
    assert_eq!(matched(&events(&b).await).len(), 1);
    // a cursor after the message does not match it
    let after = b
        .node
        .read_inbox(ReadInboxRequest::default())
        .await
        .unwrap()
        .next_cursor
        .unwrap();
    let t2 = b
        .node
        .create_trigger(CreateTriggerRequest {
            since_cursor: Some(after),
            ..trig("s1")
        })
        .await
        .unwrap();
    assert_eq!(t2.state, TriggerState::Active);
    assert_eq!(t2.match_count, 0);
    // quarantined and untrusted rows are skipped by the scan
    let x = w.agent("x", cfg());
    x.add(&b).await;
    x.node.step_receive().await.unwrap();
    x.send(&b, "stranger").await;
    settle(&[&x, &b]).await;
    let t3 = b
        .node
        .create_trigger(CreateTriggerRequest {
            since_cursor: Some(tail),
            once: Some(false),
            ..trig("s2")
        })
        .await
        .unwrap();
    assert_eq!(
        t3.match_count, 2,
        "both trusted rows match; the quarantined stranger row is skipped"
    );
}

#[tokio::test]
async fn rate_budget_blocks_recording_and_does_not_consume_once_triggers() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg_with(|c| c.triggers.max_matches_per_minute = 1)).await;
    let burn = b
        .node
        .create_trigger(CreateTriggerRequest {
            once: Some(false),
            conversation_id: Some("c1".into()),
            ..trig("s1")
        })
        .await
        .unwrap();
    let once = b
        .node
        .create_trigger(CreateTriggerRequest {
            conversation_id: Some("c2".into()),
            ..trig("s2")
        })
        .await
        .unwrap();
    send_full(&a, &b, "burn", Some("c1"), None, None).await;
    send_full(&a, &b, "blocked", Some("c2"), None, None).await;
    settle(&[&a, &b]).await;
    let evs = events(&b).await;
    assert_eq!(matched(&evs).len(), 1);
    assert_eq!(
        matched(&evs)[0].trigger_id.as_deref(),
        Some(burn.trigger_id.as_str())
    );
    assert_eq!(b.metric("trigger.budget_exceeded"), 1);
    let tl = b.node.list_triggers(true).await.unwrap();
    let t = tl.iter().find(|t| t.trigger_id == once.trigger_id).unwrap();
    assert_eq!(
        (t.state, t.match_count),
        (TriggerState::Active, 0),
        "not consumed when over budget"
    );
    // the message itself was still delivered and has its message.received event
    assert_eq!(
        evs.iter()
            .filter(|e| e.event_type == EventType::MessageReceived)
            .count(),
        2
    );
    // the sliding minute passes; the next matching message fires the once-trigger
    w.advance(61_000);
    send_full(&a, &b, "ok", Some("c2"), None, None).await;
    settle(&[&a, &b]).await;
    let tl = b.node.list_triggers(true).await.unwrap();
    assert_eq!(
        tl.iter()
            .find(|t| t.trigger_id == once.trigger_id)
            .unwrap()
            .state,
        TriggerState::Consumed
    );
}

#[tokio::test]
async fn delete_trigger_is_idempotent() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg()).await;
    let t = b.node.create_trigger(trig("s1")).await.unwrap();
    let mut hints = b.node.changes();
    assert!(
        b.node
            .delete_trigger(t.trigger_id.clone())
            .await
            .unwrap()
            .deleted
    );
    assert_eq!(hints.try_recv().unwrap(), ChangeHint::Triggers);
    assert!(
        !b.node
            .delete_trigger(t.trigger_id.clone())
            .await
            .unwrap()
            .deleted
    );
    assert!(
        !b.node
            .delete_trigger("no-such".into())
            .await
            .unwrap()
            .deleted
    );
    a.send(&b, "x").await;
    settle(&[&a, &b]).await;
    assert_eq!(matched(&events(&b).await).len(), 0);
    assert_eq!(
        b.node.list_triggers(true).await.unwrap()[0].state,
        TriggerState::Deleted
    );
    assert!(b.node.list_triggers(false).await.unwrap().is_empty());
    // a deleted trigger frees its slot
}

#[tokio::test]
async fn events_replay_ack_and_pruning() {
    let w = World::new();
    let (a, b) = pair_with(
        &w,
        cfg_with(|c| {
            c.storage.event_retention_hours = 1;
            c.storage.event_max_age_hours = 3;
        }),
    )
    .await;
    for i in 0..5 {
        a.send(&b, &format!("e{i}")).await;
    }
    settle(&[&a, &b]).await;
    let all = events(&b).await;
    assert_eq!(all.len(), 5);
    // paging with cursors, strictly after
    let p1 = b
        .node
        .read_events(PageRequest {
            limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(p1.events.len(), 2);
    assert!(p1.has_more);
    let p2 = b
        .node
        .read_events(PageRequest {
            cursor: p1.next_cursor.clone(),
            limit: Some(2),
        })
        .await
        .unwrap();
    let p3 = b
        .node
        .read_events(PageRequest {
            cursor: p2.next_cursor.clone(),
            limit: Some(2),
        })
        .await
        .unwrap();
    assert_eq!(
        (p2.events.len(), p3.events.len(), p3.has_more),
        (2, 1, false)
    );
    let ids: Vec<_> = p1
        .events
        .iter()
        .chain(&p2.events)
        .chain(&p3.events)
        .map(|e| e.event_id.clone())
        .collect();
    assert_eq!(
        ids,
        all.iter().map(|e| e.event_id.clone()).collect::<Vec<_>>()
    );
    // nothing new: next_cursor echoes the request cursor
    let p4 = b
        .node
        .read_events(PageRequest {
            cursor: p3.next_cursor.clone(),
            limit: Some(2),
        })
        .await
        .unwrap();
    assert!(p4.events.is_empty() && !p4.has_more);
    assert_eq!(p4.next_cursor, p3.next_cursor);
    // ack: idempotent and monotonic
    assert_eq!(
        b.node
            .network_status(false)
            .await
            .unwrap()
            .queue
            .events_unacked,
        5
    );
    b.node.ack_events(all[2].cursor.clone()).await.unwrap();
    assert_eq!(
        b.node
            .network_status(false)
            .await
            .unwrap()
            .queue
            .events_unacked,
        2
    );
    b.node.ack_events(all[2].cursor.clone()).await.unwrap();
    b.node.ack_events(all[0].cursor.clone()).await.unwrap();
    assert_eq!(
        b.node
            .network_status(false)
            .await
            .unwrap()
            .queue
            .events_unacked,
        2,
        "ack never goes backwards"
    );
    // acknowledging beyond the last event does not pre-ack future events
    let far = agentnet_core::cursor::encode_seq(agentnet_core::cursor::CursorKind::Event, 10_000);
    b.node.ack_events(far).await.unwrap();
    assert_eq!(
        b.node
            .network_status(false)
            .await
            .unwrap()
            .queue
            .events_unacked,
        0
    );
    a.send(&b, "future").await;
    settle(&[&a, &b]).await;
    assert_eq!(
        b.node
            .network_status(false)
            .await
            .unwrap()
            .queue
            .events_unacked,
        1
    );
    // pruning: acked events go after event_retention_hours, unacked after event_max_age_hours
    assert_eq!(events(&b).await.len(), 6);
    w.advance(3_600_000 + 1000);
    b.node.step_maintenance().unwrap();
    let left = events(&b).await;
    assert_eq!(left.len(), 1, "5 acked events pruned, the unacked one kept");
    w.advance(2 * 3_600_000 + 1000);
    b.node.step_maintenance().unwrap();
    assert_eq!(
        events(&b).await.len(),
        0,
        "unacked events expire after the TTL"
    );
    // wrong-kind / garbage cursors
    assert_eq!(
        b.node.ack_events("!!".into()).await.unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[tokio::test]
async fn pagination_cursors_for_inbox_outbox_conversation() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg()).await;
    // empty tables: every read returns a usable position-zero cursor; unknown conversation is empty
    let i = b
        .node
        .read_inbox(ReadInboxRequest::default())
        .await
        .unwrap();
    let o = b.node.read_outbox(PageRequest::default()).await.unwrap();
    let e = b.node.read_events(PageRequest::default()).await.unwrap();
    let c = b
        .node
        .read_conversation("nothing-here".into(), PageRequest::default())
        .await
        .unwrap();
    assert!(
        i.records.is_empty() && o.records.is_empty() && e.events.is_empty() && c.entries.is_empty()
    );
    for cur in [
        &i.next_cursor,
        &o.next_cursor,
        &e.next_cursor,
        &c.next_cursor,
    ] {
        assert!(cur.is_some());
    }
    // ...and echoing a cursor when nothing is new
    let again = b
        .node
        .read_inbox(ReadInboxRequest {
            cursor: i.next_cursor.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(again.next_cursor, i.next_cursor);
    let cc = b
        .node
        .read_conversation(
            "nothing-here".into(),
            PageRequest {
                cursor: c.next_cursor.clone(),
                limit: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(cc.next_cursor, c.next_cursor);

    // 7 messages a->b in one conversation, 3 replies b->a
    let mut ids = vec![];
    for i in 0..7 {
        ids.push(
            send_full(&a, &b, &format!("m{i}"), Some("cv"), None, None)
                .await
                .message_id,
        );
        w.advance(10);
    }
    settle(&[&a, &b]).await;
    for i in 0..3 {
        send_full(&b, &a, &format!("r{i}"), Some("cv"), None, None).await;
        w.advance(10);
    }
    settle(&[&a, &b]).await;

    // inbox paging
    let mut seen = vec![];
    let mut cur = None;
    loop {
        let p = b
            .node
            .read_inbox(ReadInboxRequest {
                cursor: cur.clone(),
                limit: Some(3),
                ..Default::default()
            })
            .await
            .unwrap();
        seen.extend(p.records.iter().map(|r| r.message_id.clone()));
        cur = p.next_cursor.clone();
        if !p.has_more {
            break;
        }
    }
    assert_eq!(seen, ids);
    assert!(
        b.node
            .read_inbox(ReadInboxRequest {
                limit: Some(0),
                ..Default::default()
            })
            .await
            .unwrap()
            .records
            .len()
            <= 1
    );
    // conversation filter
    let f = b
        .node
        .read_inbox(ReadInboxRequest {
            conversation_id: Some("zzz".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(f.records.is_empty());
    // unread_only + acknowledge idempotency
    assert_eq!(
        b.node
            .read_inbox(ReadInboxRequest {
                unread_only: true,
                limit: Some(200),
                ..Default::default()
            })
            .await
            .unwrap()
            .records
            .len(),
        7
    );
    let ack1 = b.node.acknowledge_message(ids[0].clone()).await.unwrap();
    let ack2 = b.node.acknowledge_message(ids[0].clone()).await.unwrap();
    assert!(ack1.newly_acknowledged && !ack2.newly_acknowledged);
    let unread = b
        .node
        .read_inbox(ReadInboxRequest {
            unread_only: true,
            limit: Some(200),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(unread.records.len(), 6);
    assert!(b.inbox().await[0].acknowledged);
    assert_eq!(
        b.node
            .acknowledge_message("missing".into())
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    // outbox paging (replies only; acks are not listed)
    let op = b
        .node
        .read_outbox(PageRequest {
            limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!((op.records.len(), op.has_more), (2, true));
    let op2 = b
        .node
        .read_outbox(PageRequest {
            cursor: op.next_cursor,
            limit: Some(5),
        })
        .await
        .unwrap();
    assert_eq!((op2.records.len(), op2.has_more), (1, false));
    assert_eq!(op2.records[0].status.state, DeliveryState::Delivered);
    // conversation: merged, both directions, stable composite cursor
    let mut entries = vec![];
    let mut cur = None;
    loop {
        let p = b
            .node
            .read_conversation(
                "cv".into(),
                PageRequest {
                    cursor: cur.clone(),
                    limit: Some(4),
                },
            )
            .await
            .unwrap();
        entries.extend(p.entries.clone());
        cur = p.next_cursor.clone();
        if !p.has_more {
            break;
        }
    }
    assert_eq!(entries.len(), 10);
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.direction == Direction::Inbound)
            .count(),
        7
    );
    assert!(entries
        .iter()
        .filter(|e| e.direction == Direction::Outbound)
        .all(|e| e.state.is_some()));
    // a late arrival after the last cursor shows up on the next page
    send_full(&a, &b, "late", Some("cv"), None, None).await;
    settle(&[&a, &b]).await;
    let more = b
        .node
        .read_conversation(
            "cv".into(),
            PageRequest {
                cursor: cur,
                limit: Some(10),
            },
        )
        .await
        .unwrap();
    assert_eq!(more.entries.len(), 1);
    assert_eq!(more.entries[0].body, "late");

    // wrong-kind and garbage cursors
    let inbox_cur = i.next_cursor.clone().unwrap();
    let outbox_cur = o.next_cursor.clone().unwrap();
    let event_cur = e.next_cursor.clone().unwrap();
    let conv_cur = c.next_cursor.clone().unwrap();
    for bad in ["", "garbage", "!!!", "aW5ib3g6", "bm9wZTox"] {
        assert_eq!(
            b.node
                .read_inbox(ReadInboxRequest {
                    cursor: Some(bad.into()),
                    ..Default::default()
                })
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument,
            "{bad}"
        );
        assert_eq!(
            b.node
                .read_outbox(PageRequest {
                    cursor: Some(bad.into()),
                    limit: None
                })
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            b.node
                .read_events(PageRequest {
                    cursor: Some(bad.into()),
                    limit: None
                })
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            b.node
                .read_conversation(
                    "cv".into(),
                    PageRequest {
                        cursor: Some(bad.into()),
                        limit: None
                    }
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    let wrong = |k: &str| -> String {
        match k {
            "inbox" => inbox_cur.clone(),
            "outbox" => outbox_cur.clone(),
            "event" => event_cur.clone(),
            _ => conv_cur.clone(),
        }
    };
    assert_eq!(
        b.node
            .read_inbox(ReadInboxRequest {
                cursor: Some(wrong("outbox")),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        b.node
            .read_outbox(PageRequest {
                cursor: Some(wrong("event")),
                limit: None
            })
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        b.node
            .read_events(PageRequest {
                cursor: Some(wrong("inbox")),
                limit: None
            })
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        b.node
            .read_conversation(
                "cv".into(),
                PageRequest {
                    cursor: Some(wrong("inbox")),
                    limit: None
                }
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        b.node
            .create_trigger(CreateTriggerRequest {
                since_cursor: Some(wrong("event")),
                ..trig("s1")
            })
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        b.node.ack_events(wrong("inbox")).await.unwrap_err().code,
        ErrorCode::InvalidArgument
    );
}

#[tokio::test]
async fn limit_defaults_and_caps() {
    let w = World::new();
    let (a, b) = pair_with(&w, cfg()).await;
    for i in 0..60 {
        a.send(&b, &format!("{i}")).await;
    }
    a.node.step_send().await.unwrap();
    b.node.step_receive().await.unwrap();
    // mock live queue holds 50 by default; recover the rest through history
    w.advance(1000);
    b.node.step_history_sync().await.unwrap();
    assert_eq!(b.n("inbox"), 60);
    let d = b
        .node
        .read_inbox(ReadInboxRequest::default())
        .await
        .unwrap();
    assert_eq!((d.records.len(), d.has_more), (50, true));
    let big = b
        .node
        .read_inbox(ReadInboxRequest {
            limit: Some(10_000),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(big.records.len(), 60);
}
