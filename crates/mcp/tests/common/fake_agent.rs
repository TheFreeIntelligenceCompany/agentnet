//! In-memory `AgentApi` used by the integration tests and by `examples/fake_server.rs`.
//!
//! Cursors are `c<seq>`. Contact records are the string `record:<address>`.
//! Sending to [`ECHO_ADDRESS`] makes the fake "receive" a reply 50 ms later
//! (inbox record + `Inbox` and `Conversation` hints), which lets out-of-process
//! tests provoke inbox changes through the public MCP surface only.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use agentnet_core::api::*;
use async_trait::async_trait;
use tokio::sync::broadcast;

pub const SELF_ADDRESS: &str = "an2selfselfselfselfselfselfselfselfselfselfselfselfselfself";
pub const BOB: &str = "an2bobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbobbob";
pub const ECHO_ADDRESS: &str = "an2echoechoechoechoechoechoechoechoechoechoechoechoechoecho";

#[derive(Default)]
struct State {
    seq: u64,
    inbox: Vec<InboxRecord>,
    outbox: Vec<OutboxRecord>,
    triggers: Vec<TriggerInfo>,
    contacts: HashMap<String, ContactInfo>,
    idempotency: HashMap<String, SendMessageResponse>,
    conversation_of: HashMap<String, String>,
    /// When set, every API call fails with this error.
    failure: Option<ApiError>,
    triggers_disabled: bool,
    discovery_disabled: bool,
    /// Own advertisements by topic: (last seq, current info; None = withdrawn).
    adverts: HashMap<String, (u64, Option<AdvertInfo>)>,
    /// What "other agents" advertised (all topics, filtered by `topic` on read).
    discovered: Vec<(String, DiscoveredAgent)>,
}

/// Topics the fake host authorizes for discovery.
pub const DISCOVERY_TOPICS: [&str; 2] = ["general", "team-1"];

pub struct FakeAgent {
    state: Mutex<State>,
    tx: broadcast::Sender<ChangeHint>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn cursor(seq: u64) -> String {
    format!("c{seq}")
}

fn parse_cursor(c: &Option<String>) -> ApiResult<u64> {
    match c {
        None => Ok(0),
        Some(c) => c
            .strip_prefix('c')
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| ApiError::invalid("unparsable cursor")),
    }
}

fn page_limit(limit: Option<u32>) -> ApiResult<usize> {
    match limit {
        None => Ok(50),
        Some(0) => Err(ApiError::invalid("limit must be at least 1")),
        Some(n) => Ok(n.min(200) as usize),
    }
}

impl FakeAgent {
    /// Hint channel with the default capacity (256).
    pub fn new() -> std::sync::Arc<Self> {
        Self::with_capacity(256)
    }

    pub fn with_capacity(capacity: usize) -> std::sync::Arc<Self> {
        let (tx, _) = broadcast::channel(capacity);
        std::sync::Arc::new(Self {
            state: Mutex::new(State::default()),
            tx,
        })
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn check(&self) -> ApiResult<()> {
        match &self.st().failure {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    // ---- test controls ----

    /// Make every subsequent API call fail with `error` (None clears).
    pub fn set_failure(&self, error: Option<ApiError>) {
        self.st().failure = error;
    }

    /// Turn the discovery feature off (every discovery call is `policy_denied`).
    pub fn set_discovery_disabled(&self, disabled: bool) {
        self.st().discovery_disabled = disabled;
    }

    /// Make an advertisement from another agent visible to `discover_agents`.
    pub fn add_discovered(&self, topic: &str, agent: DiscoveredAgent) {
        self.st().discovered.push((topic.to_owned(), agent));
    }

    pub fn set_triggers_disabled(&self, disabled: bool) {
        self.st().triggers_disabled = disabled;
    }

    /// Emit a hint without changing any state.
    pub fn emit(&self, hint: ChangeHint) {
        let _ = self.tx.send(hint);
    }

    /// Number of live hint receivers (listen loops, legacy pumps, parked ones).
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Persist an inbound message, then emit `Inbox` (and `Conversation`) hints.
    pub fn push_inbox(&self, sender: &str, body: &str, conversation_id: Option<&str>) -> String {
        let (c, conv) = {
            let mut s = self.st();
            s.seq += 1;
            let seq = s.seq;
            let record = InboxRecord {
                cursor: cursor(seq),
                message_id: format!("in{seq}"),
                sender: sender.to_string(),
                sender_trust: Trust::Trusted,
                message_type: "message".into(),
                conversation_id: conversation_id.map(str::to_string),
                correlation_id: None,
                created_at: now(),
                expires_at: now() + 3_600_000,
                received_at: now(),
                body: body.to_string(),
                acknowledged: false,
                quarantined: false,
            };
            let c = record.cursor.clone();
            s.inbox.push(record);
            (c, conversation_id.map(str::to_string))
        };
        self.emit(ChangeHint::Inbox);
        if let Some(conversation_id) = conv {
            self.emit(ChangeHint::Conversation { conversation_id });
        }
        c
    }

    /// Persist an inbound record with an explicit id and quarantine flag (no hints).
    pub fn push_raw(&self, sender: &str, message_id: &str, body: &str, quarantined: bool) {
        let mut s = self.st();
        s.seq += 1;
        let seq = s.seq;
        s.inbox.push(InboxRecord {
            cursor: cursor(seq),
            message_id: message_id.to_string(),
            sender: sender.to_string(),
            sender_trust: if quarantined {
                Trust::Unknown
            } else {
                Trust::Trusted
            },
            message_type: "message".into(),
            conversation_id: None,
            correlation_id: None,
            created_at: now(),
            expires_at: now() + 3_600_000,
            received_at: now(),
            body: body.to_string(),
            acknowledged: false,
            quarantined,
        });
    }

    pub fn inbox_len(&self) -> usize {
        self.st().inbox.len()
    }

    fn gate(s: &State, topic: &str) -> ApiResult<()> {
        if s.discovery_disabled {
            return Err(ApiError::policy(
                "discovery is disabled by host policy ([discovery] enabled = false in agentnet.toml)",
            ));
        }
        if !DISCOVERY_TOPICS.contains(&topic) {
            return Err(ApiError::policy(format!(
                "topic {topic:?} is not an authorized discovery topic (host policy: discovery.topics)"
            )));
        }
        Ok(())
    }

    fn status_of(r: &OutboxRecord) -> MessageStatus {
        r.status.clone()
    }
}

#[async_trait]
impl AgentApi for FakeAgent {
    async fn get_identity(&self) -> ApiResult<IdentityInfo> {
        self.check()?;
        Ok(IdentityInfo {
            agent_id: SELF_ADDRESS.into(),
            contact_record: format!("record:{SELF_ADDRESS}"),
            inbox_topic: "/agentnet/1/inbox-03/proto".into(),
            created_at: 1_700_000_000_000,
            kem_expires_at: Some(1_800_000_000_000),
            revoked: false,
        })
    }

    async fn send_message(&self, req: SendMessageRequest) -> ApiResult<SendMessageResponse> {
        self.check()?;
        let echo = req.recipient == ECHO_ADDRESS;
        let (response, conv) = {
            let mut s = self.st();
            if let Some(key) = &req.idempotency_key {
                if let Some(prev) = s.idempotency.get(key) {
                    let mut again = prev.clone();
                    again.deduplicated = true;
                    return Ok(again);
                }
            }
            if req.body.len() > 65_536 {
                return Err(ApiError::new(ErrorCode::TooLarge, "message too large"));
            }
            if !s.contacts.contains_key(&req.recipient) && !echo && req.recipient != BOB {
                return Err(ApiError::not_found("no contact for recipient"));
            }
            s.seq += 1;
            let seq = s.seq;
            let conversation_id = req
                .conversation_id
                .clone()
                .unwrap_or_else(|| format!("conv-{seq}"));
            let created = now();
            let ttl = req.ttl_seconds.unwrap_or(3600) as i64;
            let status = MessageStatus {
                message_id: format!("out{seq}"),
                recipient: req.recipient.clone(),
                message_type: "message".into(),
                conversation_id: Some(conversation_id.clone()),
                state: DeliveryState::Queued,
                attempts: 0,
                created_at: created,
                expires_at: created + ttl * 1000,
                last_attempt_at: None,
                next_attempt_at: None,
                sent_at: None,
                delivered_at: None,
                last_error: None,
            };
            s.conversation_of
                .insert(status.message_id.clone(), conversation_id.clone());
            s.outbox.push(OutboxRecord {
                cursor: cursor(seq),
                status: status.clone(),
                body: req.body.clone(),
            });
            let response = SendMessageResponse {
                message_id: status.message_id.clone(),
                status: DeliveryState::Queued,
                conversation_id: conversation_id.clone(),
                expires_at: status.expires_at,
                deduplicated: false,
            };
            if let Some(key) = req.idempotency_key {
                s.idempotency.insert(key, response.clone());
            }
            (response, conversation_id)
        };
        self.emit(ChangeHint::Outbox);
        self.emit(ChangeHint::Conversation {
            conversation_id: conv.clone(),
        });
        if echo {
            let body = format!("echo: {}", req.body);
            self.schedule_reply(body, conv);
        }
        Ok(response)
    }

    async fn read_inbox(&self, req: ReadInboxRequest) -> ApiResult<ReadInboxResponse> {
        self.check()?;
        let after = parse_cursor(&req.cursor)?;
        let limit = page_limit(req.limit)?;
        let s = self.st();
        let matching: Vec<&InboxRecord> = s
            .inbox
            .iter()
            .filter(|r| r.cursor[1..].parse::<u64>().unwrap_or(0) > after)
            .filter(|r| !req.unread_only || !r.acknowledged)
            .filter(|r| req.include_quarantined || !r.quarantined)
            .filter(|r| {
                req.conversation_id
                    .as_ref()
                    .is_none_or(|c| r.conversation_id.as_ref() == Some(c))
            })
            .collect();
        let records: Vec<InboxRecord> = matching.iter().take(limit).map(|r| (*r).clone()).collect();
        let has_more = matching.len() > records.len();
        let next_cursor = records
            .last()
            .map(|r| r.cursor.clone())
            .or_else(|| req.cursor.clone());
        Ok(ReadInboxResponse {
            records,
            next_cursor,
            has_more,
        })
    }

    async fn get_message(&self, req: GetMessageRequest) -> ApiResult<InboxRecord> {
        self.check()?;
        let s = self.st();
        let mut hits = s.inbox.iter().filter(|r| {
            r.message_id == req.message_id
                && !r.quarantined
                && req.sender.as_ref().is_none_or(|x| &r.sender == x)
        });
        let first = hits
            .next()
            .ok_or_else(|| ApiError::not_found("no such message"))?;
        if hits.next().is_some() {
            return Err(ApiError::new(ErrorCode::Conflict, "pass `sender`"));
        }
        Ok(first.clone())
    }

    async fn acknowledge_message(&self, message_id: String) -> ApiResult<AcknowledgeResponse> {
        self.check()?;
        let newly = {
            let mut s = self.st();
            let record = s
                .inbox
                .iter_mut()
                .find(|r| r.message_id == message_id)
                .ok_or_else(|| ApiError::not_found("no such inbox message"))?;
            let newly = !record.acknowledged;
            record.acknowledged = true;
            newly
        };
        self.emit(ChangeHint::Inbox);
        Ok(AcknowledgeResponse {
            message_id,
            newly_acknowledged: newly,
        })
    }

    async fn get_message_status(&self, message_id: String) -> ApiResult<MessageStatus> {
        self.check()?;
        self.st()
            .outbox
            .iter()
            .find(|r| r.status.message_id == message_id)
            .map(Self::status_of)
            .ok_or_else(|| ApiError::not_found("no such message"))
    }

    async fn add_contact(&self, req: AddContactRequest) -> ApiResult<ContactInfo> {
        self.check()?;
        let address = req
            .contact_record
            .strip_prefix("record:")
            .ok_or_else(|| ApiError::invalid("contact record signature invalid"))?
            .to_string();
        if let Some(expected) = &req.expected_address {
            if *expected != address {
                return Err(ApiError::invalid(
                    "contact record is for a different address",
                ));
            }
        }
        let mut s = self.st();
        let updated = s.contacts.contains_key(&address);
        let info = ContactInfo {
            address: address.clone(),
            alias: req.alias,
            trust: req.trust.unwrap_or(Trust::Trusted),
            inbox_topic: "/agentnet/1/inbox-05/proto".into(),
            added_at: now(),
            kem_expires_at: None,
            updated,
            revoked: false,
            warning: None,
        };
        s.contacts.insert(address, info.clone());
        Ok(info)
    }

    async fn list_contacts(&self) -> ApiResult<Vec<ContactInfo>> {
        self.check()?;
        Ok(self.st().contacts.values().cloned().collect())
    }

    async fn network_status(&self, verbose: bool) -> ApiResult<NetworkStatus> {
        self.check()?;
        let s = self.st();
        Ok(NetworkStatus {
            mode: "private".into(),
            ready: true,
            connected_peers: 2,
            isolation_violation: None,
            isolation_audited: true,
            queue: QueueHealth {
                outbox_queued: s.outbox.len() as u64,
                inbox_unread: s.inbox.iter().filter(|r| !r.acknowledged).count() as u64,
                active_triggers: s.triggers.len() as u64,
                ..Default::default()
            },
            last_live_poll_at: Some(now()),
            last_history_sync_at: None,
            detail: "ok".into(),
            peers: verbose.then(|| vec!["16Uiu2HAmFakePeerA".into(), "16Uiu2HAmFakePeerB".into()]),
            replay_guard: None,
            identity_revoked: false,
        })
    }

    async fn create_trigger(&self, req: CreateTriggerRequest) -> ApiResult<TriggerInfo> {
        self.check()?;
        let info = {
            let mut s = self.st();
            if s.triggers_disabled {
                return Err(ApiError::policy("triggers are disabled by host policy"));
            }
            s.seq += 1;
            let info = TriggerInfo {
                trigger_id: format!("trg{}", s.seq),
                sender: req.sender,
                message_type: req.message_type,
                conversation_id: req.conversation_id,
                correlation_id: req.correlation_id,
                target_session: req.target_session,
                once: req.once.unwrap_or(true),
                state: TriggerState::Active,
                match_count: 0,
                created_at: now(),
                expires_at: now() + req.expires_in_seconds.unwrap_or(3600) as i64 * 1000,
            };
            s.triggers.push(info.clone());
            info
        };
        self.emit(ChangeHint::Triggers);
        Ok(info)
    }

    async fn list_triggers(&self, include_inactive: bool) -> ApiResult<Vec<TriggerInfo>> {
        self.check()?;
        Ok(self
            .st()
            .triggers
            .iter()
            .filter(|t| include_inactive || t.state == TriggerState::Active)
            .cloned()
            .collect())
    }

    async fn delete_trigger(&self, trigger_id: String) -> ApiResult<DeleteTriggerResponse> {
        self.check()?;
        let deleted = {
            let mut s = self.st();
            match s
                .triggers
                .iter_mut()
                .find(|t| t.trigger_id == trigger_id && t.state != TriggerState::Deleted)
            {
                Some(t) => {
                    t.state = TriggerState::Deleted;
                    true
                }
                None => false,
            }
        };
        if deleted {
            self.emit(ChangeHint::Triggers);
        }
        Ok(DeleteTriggerResponse {
            trigger_id,
            deleted,
        })
    }

    async fn read_outbox(&self, req: PageRequest) -> ApiResult<OutboxPage> {
        self.check()?;
        let after = parse_cursor(&req.cursor)?;
        let limit = page_limit(req.limit)?;
        let s = self.st();
        let matching: Vec<&OutboxRecord> = s
            .outbox
            .iter()
            .filter(|r| r.cursor[1..].parse::<u64>().unwrap_or(0) > after)
            .collect();
        let records: Vec<OutboxRecord> =
            matching.iter().take(limit).map(|r| (*r).clone()).collect();
        Ok(OutboxPage {
            has_more: matching.len() > records.len(),
            next_cursor: records
                .last()
                .map(|r| r.cursor.clone())
                .or_else(|| req.cursor.clone()),
            records,
        })
    }

    async fn read_conversation(
        &self,
        conversation_id: String,
        req: PageRequest,
    ) -> ApiResult<ConversationPage> {
        self.check()?;
        let after = parse_cursor(&req.cursor)?;
        let limit = page_limit(req.limit)?;
        let s = self.st();
        let mut entries: Vec<(u64, ConversationEntry)> = Vec::new();
        for r in &s.inbox {
            if r.conversation_id.as_deref() == Some(conversation_id.as_str()) {
                entries.push((
                    r.cursor[1..].parse().unwrap_or(0),
                    ConversationEntry {
                        cursor: r.cursor.clone(),
                        direction: Direction::Inbound,
                        message_id: r.message_id.clone(),
                        peer: r.sender.clone(),
                        message_type: r.message_type.clone(),
                        correlation_id: r.correlation_id.clone(),
                        created_at: r.created_at,
                        body: r.body.clone(),
                        state: None,
                    },
                ));
            }
        }
        for r in &s.outbox {
            if r.status.conversation_id.as_deref() == Some(conversation_id.as_str()) {
                entries.push((
                    r.cursor[1..].parse().unwrap_or(0),
                    ConversationEntry {
                        cursor: r.cursor.clone(),
                        direction: Direction::Outbound,
                        message_id: r.status.message_id.clone(),
                        peer: r.status.recipient.clone(),
                        message_type: r.status.message_type.clone(),
                        correlation_id: None,
                        created_at: r.status.created_at,
                        body: r.body.clone(),
                        state: Some(r.status.state),
                    },
                ));
            }
        }
        if entries.is_empty() {
            return Err(ApiError::not_found("no such conversation"));
        }
        entries.sort_by_key(|(seq, _)| *seq);
        let matching: Vec<ConversationEntry> = entries
            .into_iter()
            .filter(|(seq, _)| *seq > after)
            .map(|(_, e)| e)
            .collect();
        let page: Vec<ConversationEntry> = matching.iter().take(limit).cloned().collect();
        Ok(ConversationPage {
            conversation_id,
            has_more: matching.len() > page.len(),
            next_cursor: page
                .last()
                .map(|e| e.cursor.clone())
                .or_else(|| req.cursor.clone()),
            entries: page,
        })
    }

    async fn read_events(&self, _req: PageRequest) -> ApiResult<EventPage> {
        self.check()?;
        Ok(EventPage {
            events: vec![],
            next_cursor: None,
            has_more: false,
        })
    }

    async fn ack_events(&self, _cursor: String) -> ApiResult<()> {
        self.check()
    }

    async fn advertise_agent(&self, req: AdvertiseRequest) -> ApiResult<AdvertInfo> {
        self.check()?;
        let mut s = self.st();
        Self::gate(&s, &req.topic)?;
        if req.capabilities.is_empty() {
            return Err(ApiError::invalid("capabilities must not be empty"));
        }
        let seq = s.adverts.get(&req.topic).map_or(0, |(q, _)| *q) + 1;
        let ttl = req.ttl_seconds.unwrap_or(3600).min(86_400) as i64 * 1000;
        let info = AdvertInfo {
            topic: req.topic.clone(),
            seq,
            issued_at: now(),
            expires_at: now() + ttl,
            capabilities: req.capabilities,
        };
        s.adverts.insert(req.topic, (seq, Some(info.clone())));
        Ok(info)
    }

    async fn withdraw_advert(&self, topic: String) -> ApiResult<WithdrawInfo> {
        self.check()?;
        let mut s = self.st();
        Self::gate(&s, &topic)?;
        let withdrawn = match s.adverts.get_mut(&topic) {
            Some((seq, cur @ Some(_))) => {
                *seq += 1;
                *cur = None;
                true
            }
            _ => false,
        };
        Ok(WithdrawInfo { topic, withdrawn })
    }

    async fn discover_agents(&self, req: DiscoverRequest) -> ApiResult<DiscoverPage> {
        self.check()?;
        let s = self.st();
        Self::gate(&s, &req.topic)?;
        let after = parse_cursor(&req.cursor)? as usize;
        let limit = page_limit(req.limit)?;
        let matching: Vec<(usize, &DiscoveredAgent)> = s
            .discovered
            .iter()
            .filter(|(t, _)| *t == req.topic)
            .map(|(_, a)| a)
            .filter(|a| {
                req.capability
                    .as_ref()
                    .is_none_or(|c| a.capabilities.iter().any(|x| x.name == *c))
            })
            .enumerate()
            .map(|(i, a)| (i + 1, a))
            .filter(|(i, _)| *i > after)
            .collect();
        let page: Vec<&(usize, &DiscoveredAgent)> = matching.iter().take(limit).collect();
        Ok(DiscoverPage {
            has_more: matching.len() > page.len(),
            next_cursor: Some(cursor(page.last().map_or(after as u64, |(i, _)| *i as u64))),
            agents: page.iter().map(|(_, a)| (*a).clone()).collect(),
        })
    }

    fn changes(&self) -> broadcast::Receiver<ChangeHint> {
        self.tx.subscribe()
    }
}

impl FakeAgent {
    /// The echo "remote" answers 50 ms after a send to [`ECHO_ADDRESS`].
    fn schedule_reply(&self, body: String, conversation_id: String) {
        let handle = ReplyHandle {
            tx: self.tx.clone(),
        };
        let reply = {
            let mut s = self.st();
            s.seq += 1;
            let seq = s.seq;
            InboxRecord {
                cursor: cursor(seq),
                message_id: format!("in{seq}"),
                sender: ECHO_ADDRESS.to_string(),
                sender_trust: Trust::Trusted,
                message_type: "message".into(),
                conversation_id: Some(conversation_id.clone()),
                correlation_id: None,
                created_at: now(),
                expires_at: now() + 3_600_000,
                received_at: now(),
                body,
                acknowledged: false,
                quarantined: false,
            }
        };
        // Persist first (visible to readers immediately), notify after the delay:
        // notifications are hints that may trail the durable state.
        self.st().inbox.push(reply);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = handle.tx.send(ChangeHint::Inbox);
            let _ = handle.tx.send(ChangeHint::Conversation { conversation_id });
        });
    }
}

struct ReplyHandle {
    tx: broadcast::Sender<ChangeHint>,
}
