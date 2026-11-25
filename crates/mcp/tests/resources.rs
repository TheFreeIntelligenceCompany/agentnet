mod common;

use agentnet_core::api::{ApiError, ErrorCode};
use agentnet_mcp::{dto::*, uris::percent_encode};
use common::{
    fake_agent::{BOB, ECHO_ADDRESS, SELF_ADDRESS},
    Duplex, Mode, *,
};
use rmcp::{model::*, service::ServiceError};
use serde_json::{json, Value};

fn rpc(err: &ServiceError) -> (i32, Value) {
    match err {
        ServiceError::McpError(d) => (d.code.0, d.data.clone().unwrap_or(Value::Null)),
        other => panic!("expected JSON-RPC error, got {other:?}"),
    }
}

#[tokio::test]
async fn lists_resources_and_templates() {
    let d = Duplex::start(Mode::Discover).await;
    let resources = d.client.list_all_resources().await.unwrap();
    let mut uris: Vec<_> = resources.iter().map(|r| r.uri.as_str()).collect();
    uris.sort_unstable();
    assert_eq!(
        uris,
        [
            "agentnet://identity",
            "agentnet://inbox",
            "agentnet://outbox",
            "agentnet://triggers"
        ]
    );
    for r in &resources {
        assert_eq!(r.mime_type.as_deref(), Some("application/json"));
        assert!(r.description.as_deref().is_some_and(|d| !d.is_empty()));
    }
    let templates = d.client.list_all_resource_templates().await.unwrap();
    let t: Vec<_> = templates.iter().map(|t| t.uri_template.as_str()).collect();
    assert!(
        t.contains(&"agentnet://conversations/{id}{?cursor,limit}"),
        "{t:?}"
    );
    assert!(t.contains(&"agentnet://inbox{?cursor,limit}"));
    assert!(t.contains(&"agentnet://outbox{?cursor,limit}"));
}

#[tokio::test]
async fn reads_are_uncacheable_json_documents() {
    let d = Duplex::start(Mode::Discover).await;
    d.agent.push_inbox(BOB, "hello", Some("c1"));
    for uri in [
        "agentnet://identity",
        "agentnet://inbox",
        "agentnet://outbox",
        "agentnet://triggers",
        "agentnet://conversations/c1",
    ] {
        let result = d
            .peer()
            .read_resource(ReadResourceRequestParams::new(uri))
            .await
            .unwrap();
        let raw = serde_json::to_value(&result).unwrap();
        assert_eq!(raw["ttlMs"], 0, "{uri}: must not be cacheable");
        assert_eq!(raw["cacheScope"], "private", "{uri}");
        assert_eq!(result.contents.len(), 1);
        match &result.contents[0] {
            ResourceContents::TextResourceContents {
                uri: u,
                mime_type,
                text,
                ..
            } => {
                assert_eq!(u, uri);
                assert_eq!(mime_type.as_deref(), Some("application/json"));
                serde_json::from_str::<Value>(text).expect("valid JSON");
            }
            other => panic!("unexpected contents {other:?}"),
        }
    }
}

#[tokio::test]
async fn resource_documents_have_the_documented_shape() {
    let d = Duplex::start(Mode::Discover).await;
    let peer = d.peer();
    let id: IdentityOutput =
        serde_json::from_value(read_json(peer, "agentnet://identity").await.unwrap()).unwrap();
    assert_eq!(id.agent_id, SELF_ADDRESS);

    d.agent.push_inbox(BOB, "in-1", Some("conv-x"));
    let sent: SendMessageOutput = call_ok(
        peer,
        "send_message",
        json!({"recipient": BOB, "body": "out-1", "conversation_id": "conv-x"}),
    )
    .await;

    let inbox: ReadInboxOutput =
        serde_json::from_value(read_json(peer, "agentnet://inbox").await.unwrap()).unwrap();
    assert_eq!(inbox.records.len(), 1);
    assert_eq!(inbox.records[0].body, "in-1");
    assert!(inbox.next_cursor.is_some());

    let outbox: OutboxPageOutput =
        serde_json::from_value(read_json(peer, "agentnet://outbox").await.unwrap()).unwrap();
    assert_eq!(outbox.records.len(), 1);
    assert_eq!(outbox.records[0].status.message_id, sent.message_id);
    assert_eq!(outbox.records[0].body, "out-1");

    let conv: ConversationPageOutput = serde_json::from_value(
        read_json(peer, "agentnet://conversations/conv-x")
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(conv.conversation_id, "conv-x");
    assert_eq!(conv.entries.len(), 2);
    assert_eq!(conv.entries[0].direction, Direction::Inbound);
    assert_eq!(conv.entries[1].direction, Direction::Outbound);
    assert_eq!(conv.entries[1].state, Some(DeliveryState::Queued));

    call_ok::<TriggerOutput>(peer, "create_trigger", json!({"target_session": "s1"})).await;
    let triggers: ListTriggersOutput =
        serde_json::from_value(read_json(peer, "agentnet://triggers").await.unwrap()).unwrap();
    assert_eq!(triggers.triggers.len(), 1);
}

#[tokio::test]
async fn inbox_pagination_by_cursor_in_the_uri() {
    let d = Duplex::start(Mode::Discover).await;
    for i in 0..25 {
        d.agent.push_inbox(BOB, &format!("m{i:02}"), None);
    }
    let mut cursor: Option<String> = None;
    let mut seen = vec![];
    let mut pages = 0;
    loop {
        let uri = match &cursor {
            None => "agentnet://inbox?limit=10".to_string(),
            Some(c) => format!("agentnet://inbox?cursor={}&limit=10", percent_encode(c)),
        };
        let page: ReadInboxOutput =
            serde_json::from_value(read_json(d.peer(), &uri).await.unwrap()).unwrap();
        pages += 1;
        seen.extend(page.records.iter().map(|r| r.body.clone()));
        if !page.has_more {
            // Last page: next_cursor still resumes after the final record.
            assert_eq!(
                page.next_cursor.as_deref(),
                page.records.last().map(|r| r.cursor.as_str())
            );
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(pages, 3);
    assert_eq!(
        seen,
        (0..25).map(|i| format!("m{i:02}")).collect::<Vec<_>>()
    );

    // Resuming from the last cursor yields only newer records.
    let last = read_json(d.peer(), "agentnet://inbox?limit=200")
        .await
        .unwrap();
    let resume = last["next_cursor"].as_str().unwrap().to_string();
    d.agent.push_inbox(BOB, "late", None);
    let after = read_json(
        d.peer(),
        &format!("agentnet://inbox?cursor={}", percent_encode(&resume)),
    )
    .await
    .unwrap();
    let bodies: Vec<_> = after["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["body"].as_str().unwrap())
        .collect();
    assert_eq!(bodies, ["late"]);
}

#[tokio::test]
async fn outbox_and_conversation_pagination() {
    let d = Duplex::start(Mode::Discover).await;
    let peer = d.peer();
    for i in 0..5 {
        call_ok::<SendMessageOutput>(
            peer,
            "send_message",
            json!({"recipient": BOB, "body": format!("o{i}"), "conversation_id": "cv"}),
        )
        .await;
    }
    let p1 = read_json(peer, "agentnet://outbox?limit=2").await.unwrap();
    assert_eq!(p1["records"].as_array().unwrap().len(), 2);
    assert_eq!(p1["has_more"], true);
    let c = percent_encode(p1["next_cursor"].as_str().unwrap());
    let p2 = read_json(peer, &format!("agentnet://outbox?limit=2&cursor={c}"))
        .await
        .unwrap();
    assert_eq!(p2["records"][0]["body"], "o2");

    let p1 = read_json(peer, "agentnet://conversations/cv?limit=3")
        .await
        .unwrap();
    assert_eq!(p1["entries"].as_array().unwrap().len(), 3);
    assert_eq!(p1["has_more"], true);
    let c = percent_encode(p1["next_cursor"].as_str().unwrap());
    let p2 = read_json(
        peer,
        &format!("agentnet://conversations/cv?limit=3&cursor={c}"),
    )
    .await
    .unwrap();
    assert_eq!(p2["entries"].as_array().unwrap().len(), 2);
    assert_eq!(p2["has_more"], false);
}

#[tokio::test]
async fn unknown_uri_is_the_standard_not_found_error() {
    let d = Duplex::start(Mode::Discover).await;
    for uri in [
        "agentnet://nope",
        "agentnet://inbox/",
        "agentnet://conversations/",
        "agentnet://conversations/a%20b",
        "agentnet://conversations/a/b",
        "file:///etc/passwd",
        "other://inbox",
    ] {
        let err = d
            .peer()
            .read_resource(ReadResourceRequestParams::new(uri))
            .await
            .unwrap_err();
        let (code, data) = rpc(&err);
        // 2026-07-28 resources.mdx: not-found is -32602 (Invalid Params).
        assert_eq!(code, -32602, "{uri}: {err}");
        assert_eq!(data["uri"], uri);
        assert_eq!(data["code"], "not_found");
    }
    // A conversation the engine does not know is also not-found.
    let err = d
        .peer()
        .read_resource(ReadResourceRequestParams::new(
            "agentnet://conversations/ghost",
        ))
        .await
        .unwrap_err();
    assert_eq!(rpc(&err).0, -32602);
    assert_eq!(rpc(&err).1["code"], "not_found");
}

#[tokio::test]
async fn legacy_clients_get_the_legacy_not_found_code() {
    let d = Duplex::start(Mode::Initialize(ProtocolVersion::V_2025_11_25)).await;
    let err = d
        .peer()
        .read_resource(ReadResourceRequestParams::new("agentnet://nope"))
        .await
        .unwrap_err();
    // Pre-2026-07-28 revisions defined resource-not-found as -32002.
    assert_eq!(rpc(&err).0, -32002, "{err}");
}

#[tokio::test]
async fn invalid_query_arguments_are_invalid_params() {
    let d = Duplex::start(Mode::Discover).await;
    for uri in [
        "agentnet://inbox?limit=0",
        "agentnet://inbox?limit=201",
        "agentnet://inbox?limit=ten",
        "agentnet://inbox?cursor=",
        "agentnet://inbox?cursor=a%ZZ",
        "agentnet://inbox?cursor=a&cursor=b",
        "agentnet://inbox?unknown=1",
        "agentnet://identity?limit=1",
        "agentnet://conversations/x?limit=0",
        // Engine-side cursor parse failure (fake: not `c<seq>`).
        "agentnet://inbox?cursor=garbage",
        "agentnet://outbox?cursor=garbage",
    ] {
        let err = d
            .peer()
            .read_resource(ReadResourceRequestParams::new(uri))
            .await
            .unwrap_err();
        let (code, data) = rpc(&err);
        assert_eq!(code, -32602, "{uri}: {err}");
        assert_eq!(data["code"], "invalid_argument", "{uri}");
    }
}

#[tokio::test]
async fn engine_errors_on_resource_reads_map_to_standard_codes() {
    let d = Duplex::start(Mode::Discover).await;
    for (code, expect_rpc, expect_code) in [
        (ErrorCode::Unavailable, -32603, "unavailable"),
        (ErrorCode::Internal, -32603, "internal"),
        (ErrorCode::PolicyDenied, -32602, "policy_denied"),
        (ErrorCode::TooLarge, -32602, "too_large"),
        (ErrorCode::Conflict, -32602, "conflict"),
        (ErrorCode::InvalidArgument, -32602, "invalid_argument"),
        (ErrorCode::NotFound, -32602, "not_found"),
    ] {
        d.agent
            .set_failure(Some(ApiError::new(code, "sanitized message")));
        let err = d
            .peer()
            .read_resource(ReadResourceRequestParams::new("agentnet://inbox"))
            .await
            .unwrap_err();
        let (rpc_code, data) = rpc(&err);
        assert_eq!(rpc_code, expect_rpc, "{code:?}");
        assert_eq!(data["code"], expect_code, "{code:?}");
    }
}

#[tokio::test]
async fn capabilities_and_server_info() {
    let d = Duplex::start(Mode::Discover).await;
    let info = d.client.peer_info().expect("server info");
    let v = serde_json::to_value(&*info).unwrap();
    assert_eq!(v["serverInfo"]["name"], "agentnet");
    assert_eq!(v["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    let caps = &v["capabilities"];
    assert!(caps["tools"].is_object(), "{caps}");
    assert_eq!(caps["resources"]["subscribe"], true, "{caps}");
    assert!(caps.get("prompts").is_none_or(Value::is_null), "{caps}");
    assert!(caps.get("logging").is_none_or(Value::is_null), "{caps}");
    let instructions = v["instructions"].as_str().unwrap();
    for must in [
        "UNTRUSTED",
        "NOT receipt",
        "local processing state",
        "policy",
    ] {
        assert!(
            instructions.contains(must),
            "instructions lack {must:?}: {instructions}"
        );
    }
    let _ = ECHO_ADDRESS;
}
