//! The application-facing API of one AgentNet agent.
//!
//! [`AgentApi`] is the single seam between the engine and its front ends. The
//! in-process engine implements it; the daemon's socket client implements it
//! for thin clients such as `agentnet mcp`; the MCP server and embedders consume
//! it as `Arc<dyn AgentApi>`. Every type here is plain serde data so it can
//! cross a process boundary unchanged.
//!
//! Rules for implementations:
//! * No method returns private key material.
//! * Message bodies are untrusted data from remote parties. They are returned
//!   verbatim and never interpreted.
//! * Timestamps are Unix milliseconds (UTC).
//! * Cursors are opaque strings. Passing a cursor back returns records strictly
//!   after it. An unparsable cursor is `InvalidArgument`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

pub type ApiResult<T> = Result<T, ApiError>;

/// Stable, machine-readable error classes. `message` is sanitized: no keys, no
/// file paths outside the data directory, no raw remote payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidArgument,
    NotFound,
    /// Refused by host policy (e.g. triggers disabled, session not allowlisted,
    /// budget exhausted).
    PolicyDenied,
    /// Temporarily impossible (queue full, daemon unreachable).
    Unavailable,
    TooLarge,
    Conflict,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }
    pub fn policy(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::PolicyDenied, message)
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unavailable, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
}

/// Public identity of this agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityInfo {
    /// The agent address (`an1…`). This is the agent ID everywhere in the API.
    pub agent_id: String,
    /// The signed public contact record as a JSON document string; give this to
    /// peers so they can `add_contact`.
    pub contact_record: String,
    /// Content topic this agent's inbox listens on.
    pub inbox_topic: String,
    pub created_at: i64,
    /// Expiry of the current agreement key, if one is set.
    pub kem_expires_at: Option<i64>,
    /// Epoch of the current agreement key (starts at 1; +1 per rotation).
    #[serde(default)]
    pub key_epoch: u64,
    /// The identity has been revoked (signed tombstone): it only delivers the
    /// tombstone and sends nothing else.
    #[serde(default)]
    pub revoked: bool,
}

/// Lifecycle of an outbound message. `Sent` means the local node accepted it;
/// only `Delivered` means the recipient persisted it (authenticated ack).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    Queued,
    Sent,
    Delivered,
    Failed,
    Expired,
}

/// Local trust decision about a peer address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Verified contact: messages are accepted and may match triggers.
    Trusted,
    /// Known but not trusted: handled like an unknown sender.
    Untrusted,
    /// Messages are dropped.
    Blocked,
    /// No contact entry (only appears on inbox records).
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessageRequest {
    /// Recipient address. A verified contact record for it must exist.
    pub recipient: String,
    pub body: String,
    /// `message` (default), `task.request` or `task.result`. `ack.received` is
    /// reserved for the engine.
    #[serde(default)]
    pub message_type: Option<String>,
    /// Defaults to a fresh conversation ID.
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// Defaults to the configured TTL; capped at the configured maximum.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    /// Repeating a request with the same key returns the original message
    /// instead of sending a second one.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub message_id: String,
    pub status: DeliveryState,
    pub conversation_id: String,
    pub expires_at: i64,
    /// True when an earlier request with the same idempotency key was returned.
    pub deduplicated: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadInboxRequest {
    #[serde(default)]
    pub cursor: Option<String>,
    /// Default 50, maximum 200.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Only messages not yet acknowledged with `acknowledge_message`.
    #[serde(default)]
    pub unread_only: bool,
    #[serde(default)]
    pub conversation_id: Option<String>,
    /// Include quarantined messages from unknown/untrusted senders.
    #[serde(default)]
    pub include_quarantined: bool,
}

/// `get_message` request. Inbox rows are keyed by `(sender, message_id)`; a
/// `message.received` event carries only the `message_id`, so `sender` is
/// optional and needed only when two senders used the same id.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetMessageRequest {
    pub message_id: String,
    /// Authenticated sender address. Required to disambiguate when more than
    /// one sender used `message_id` (the call is then `conflict`).
    #[serde(default)]
    pub sender: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRecord {
    /// Cursor positioned at this record.
    pub cursor: String,
    pub message_id: String,
    /// Authenticated sender address.
    pub sender: String,
    pub sender_trust: Trust,
    pub message_type: String,
    pub conversation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub received_at: i64,
    /// Untrusted remote content.
    pub body: String,
    pub acknowledged: bool,
    pub quarantined: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadInboxResponse {
    pub records: Vec<InboxRecord>,
    /// Pass back to continue after the last returned record. Present whenever
    /// the request can be continued (equals the request cursor if nothing new).
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcknowledgeResponse {
    pub message_id: String,
    /// False when it was already acknowledged (the call is idempotent).
    pub newly_acknowledged: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageStatus {
    pub message_id: String,
    pub recipient: String,
    pub message_type: String,
    pub conversation_id: Option<String>,
    pub state: DeliveryState,
    pub attempts: u32,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_attempt_at: Option<i64>,
    pub next_attempt_at: Option<i64>,
    pub sent_at: Option<i64>,
    pub delivered_at: Option<i64>,
    /// Sanitized description of the last failure, if any.
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddContactRequest {
    /// The peer's signed contact record (JSON document string).
    pub contact_record: String,
    /// If set, the record must be for exactly this address (obtained out of
    /// band); a mismatch is rejected.
    #[serde(default)]
    pub expected_address: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    /// Defaults to `trusted`.
    #[serde(default)]
    pub trust: Option<Trust>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactInfo {
    pub address: String,
    pub alias: Option<String>,
    pub trust: Trust,
    pub inbox_topic: String,
    pub added_at: i64,
    pub kem_expires_at: Option<i64>,
    /// True when an existing contact was replaced by a newer record.
    pub updated: bool,
    /// Key epoch of the stored contact record.
    #[serde(default)]
    pub key_epoch: u64,
    /// A verified identity-revocation tombstone exists for this address; the
    /// contact is blocked and cannot be re-trusted or replaced.
    #[serde(default)]
    pub revoked: bool,
}

/// Result of importing an identity-revocation tombstone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationInfo {
    pub address: String,
    pub revoked_at: i64,
    pub reason: String,
    /// False when the same address was already revoked.
    pub newly_revoked: bool,
}

/// The replay guard (see `docs/protocol.md`): entered after a store rollback,
/// an unknown store history or an identity import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayGuardInfo {
    /// `rollback`, `unknown_history` or `imported`.
    pub reason: String,
    /// Messages created before this are held (Unix ms).
    pub since: i64,
    /// The guard lapses by itself at this time (Unix ms).
    pub until: i64,
    /// Messages currently held.
    pub held: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueHealth {
    pub outbox_queued: u64,
    pub outbox_sent_unacked: u64,
    pub inbox_unread: u64,
    pub inbox_quarantined: u64,
    pub events_unacked: u64,
    pub active_triggers: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStatus {
    /// `private` or `public`.
    pub mode: String,
    pub ready: bool,
    pub connected_peers: u32,
    pub isolation_violation: Option<String>,
    /// Whether the node's peers are audited at all (private mode, or public
    /// mode with `enforce_peer_allowlist`). `false` means `isolation_violation`
    /// being absent says nothing. Defaults to `false` when a peer predates the field.
    #[serde(default)]
    pub isolation_audited: bool,
    pub queue: QueueHealth,
    pub last_live_poll_at: Option<i64>,
    pub last_history_sync_at: Option<i64>,
    /// Sanitized detail; peer IDs only when `verbose` was requested.
    pub detail: String,
    pub peers: Option<Vec<String>>,
    /// Present while the replay guard is active.
    #[serde(default)]
    pub replay_guard: Option<ReplayGuardInfo>,
    /// The local identity has been revoked.
    #[serde(default)]
    pub identity_revoked: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTriggerRequest {
    /// Match only this authenticated sender address.
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub message_type: Option<String>,
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    /// Opaque host session reference; must be allowlisted by host policy.
    pub target_session: String,
    /// Default true: consumed atomically by the first match.
    #[serde(default)]
    pub once: Option<bool>,
    /// Default and maximum come from host policy.
    #[serde(default)]
    pub expires_in_seconds: Option<u64>,
    /// Also match already-persisted inbox records after this inbox cursor
    /// (closes the race where the reply arrives before the trigger exists).
    #[serde(default)]
    pub since_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerState {
    Active,
    Consumed,
    Expired,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerInfo {
    pub trigger_id: String,
    pub sender: Option<String>,
    pub message_type: Option<String>,
    pub conversation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub target_session: String,
    pub once: bool,
    pub state: TriggerState,
    pub match_count: u64,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteTriggerResponse {
    pub trigger_id: String,
    /// False when it did not exist or was already deleted (idempotent).
    pub deleted: bool,
}

/// Upper bound on the serialized size of the records in one quarantine page
/// (JSON, as sent over the control socket, whose line limit is 64 MiB). A page
/// always holds at least one record, so a single record is the only thing that
/// can exceed it; a record is bounded by the frame size limit.
pub const MAX_QUARANTINE_PAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxRecord {
    pub cursor: String,
    #[serde(flatten)]
    pub status: MessageStatus,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxPage {
    pub records: Vec<OutboxRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationEntry {
    pub cursor: String,
    pub direction: Direction,
    pub message_id: String,
    /// The other party's address.
    pub peer: String,
    pub message_type: String,
    pub correlation_id: Option<String>,
    pub created_at: i64,
    pub body: String,
    /// Present for outbound entries.
    pub state: Option<DeliveryState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationPage {
    pub conversation_id: String,
    pub entries: Vec<ConversationEntry>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    #[serde(rename = "message.received")]
    MessageReceived,
    #[serde(rename = "trigger.matched")]
    TriggerMatched,
}

/// A durable host-facing event. Carries references, never message plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_id: String,
    /// Cursor positioned at this event.
    pub cursor: String,
    pub event_type: EventType,
    pub agent_id: String,
    pub message_id: String,
    pub trigger_id: Option<String>,
    pub target_session: Option<String>,
    pub timestamp: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPage {
    pub events: Vec<EventRecord>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

// ------------------------------------------------------------------ discovery

/// One advertised capability. Both fields are claims by the advertiser: DATA, never
/// instructions.
pub use crate::crypto::advert::Capability;

/// `advertise_agent` request. Adverts are PLAINTEXT and readable by every node on
/// the relay: never put secrets or private capabilities in them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertiseRequest {
    /// Discovery topic name (must be in the host's `discovery.topics`).
    pub topic: String,
    /// 1 to `discovery.max_capabilities` capabilities.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    /// Optional display name, at most 64 characters.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Lifetime; defaults to `discovery.default_advert_ttl_s`, capped at
    /// `discovery.max_advert_ttl_s`.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// The advertisement now in force on a topic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertInfo {
    pub topic: String,
    /// Sequence number of the signed advertisement (strictly increasing per topic).
    pub seq: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub capabilities: Vec<Capability>,
}

/// Result of `withdraw_advert`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawInfo {
    pub topic: String,
    /// False when there was nothing to withdraw (the call is idempotent).
    pub withdrawn: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverRequest {
    /// Discovery topic name (must be in the host's `discovery.topics`).
    pub topic: String,
    /// Exact capability name to filter by.
    #[serde(default)]
    pub capability: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
    /// Default 50, maximum 200.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// A candidate found by discovery. EVERY field except `address`, `is_contact`
/// and `trust` is an unauthenticated CLAIM by the advertiser (the signature only
/// proves the address key made the statement).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAgent {
    pub address: String,
    pub display_name: Option<String>,
    pub capabilities: Vec<Capability>,
    /// The advertiser's signed contact record, usable with `add_contact`
    /// (together with `expected_address` obtained out of band).
    pub contact_record: String,
    pub issued_at: i64,
    pub expires_at: i64,
    /// This agent is already a local contact.
    pub is_contact: bool,
    /// Local trust decision (`unknown` when not a contact).
    pub trust: Trust,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverPage {
    pub agents: Vec<DiscoveredAgent>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// A hint that something changed. Hints are lossy: receivers reread using
/// their cursor. Sent only after the change is durable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChangeHint {
    Inbox,
    Outbox,
    Triggers,
    Identity,
    Conversation {
        conversation_id: String,
    },
    /// New host-facing events are available from `read_events`.
    Events,
}

#[async_trait]
pub trait AgentApi: Send + Sync + 'static {
    async fn get_identity(&self) -> ApiResult<IdentityInfo>;
    async fn send_message(&self, req: SendMessageRequest) -> ApiResult<SendMessageResponse>;
    async fn read_inbox(&self, req: ReadInboxRequest) -> ApiResult<ReadInboxResponse>;
    /// Fetch one received message by id (the id a `message.received` event
    /// carries). Same visibility as `read_inbox` without `include_quarantined`:
    /// quarantined and replay-guard-held messages are `not_found`. A message id
    /// is sender-chosen; if several senders used it and `sender` is absent the
    /// call fails with `conflict`. Does not acknowledge the message.
    async fn get_message(&self, req: GetMessageRequest) -> ApiResult<InboxRecord>;
    /// Marks a message as processed locally. Unrelated to the transport-level
    /// `ack.received` receipt, which the engine sends on persistence.
    async fn acknowledge_message(&self, message_id: String) -> ApiResult<AcknowledgeResponse>;
    async fn get_message_status(&self, message_id: String) -> ApiResult<MessageStatus>;
    async fn add_contact(&self, req: AddContactRequest) -> ApiResult<ContactInfo>;
    async fn list_contacts(&self) -> ApiResult<Vec<ContactInfo>>;
    async fn network_status(&self, verbose: bool) -> ApiResult<NetworkStatus>;
    async fn create_trigger(&self, req: CreateTriggerRequest) -> ApiResult<TriggerInfo>;
    async fn list_triggers(&self, include_inactive: bool) -> ApiResult<Vec<TriggerInfo>>;
    async fn delete_trigger(&self, trigger_id: String) -> ApiResult<DeleteTriggerResponse>;
    async fn read_outbox(&self, req: PageRequest) -> ApiResult<OutboxPage>;
    async fn read_conversation(
        &self,
        conversation_id: String,
        req: PageRequest,
    ) -> ApiResult<ConversationPage>;
    /// Replay host-facing events strictly after `req.cursor` (from the
    /// beginning of retained events when absent).
    async fn read_events(&self, req: PageRequest) -> ApiResult<EventPage>;
    /// Acknowledge all events up to and including `cursor`. Idempotent.
    async fn ack_events(&self, cursor: String) -> ApiResult<()>;
    /// Publish (or replace) this agent's signed capability advertisement on a
    /// host-authorised discovery topic. Opt-in (`policy_denied` unless the host
    /// enabled discovery and listed the topic). The advertisement is PLAINTEXT,
    /// readable by every node on the relay, and is re-published until it expires
    /// or is withdrawn.
    async fn advertise_agent(&self, req: AdvertiseRequest) -> ApiResult<AdvertInfo>;
    /// Withdraw the advertisement on `topic` (idempotent).
    async fn withdraw_advert(&self, topic: String) -> ApiResult<WithdrawInfo>;
    /// List unexpired advertisements received on `topic` (best effort, not a
    /// directory). Never adds a contact; results are untrusted claims.
    async fn discover_agents(&self, req: DiscoverRequest) -> ApiResult<DiscoverPage>;
    /// Lossy stream of change hints.
    fn changes(&self) -> broadcast::Receiver<ChangeHint>;
}
