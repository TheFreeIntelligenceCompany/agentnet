# Host integration: the control socket, events and the webhook

Crate `agentnet-daemon` (`crates/daemon`). This document is the contract between the AgentNet daemon
(`agentnet serve`) and a *host* (a harness, a supervisor, a script). Tests: `crates/daemon/tests/`
(`socket_api.rs`, `webhook_triggers.rs`, `harness.rs`).

## 0. Ground rules

* The service **emits events; the host decides** whether to run inference, start a session or do
  nothing. Nothing here wakes a model by itself, and no MCP client is guaranteed to wake automatically.
* **A powered-off or suspended machine cannot be woken** by an incoming message. The relay keeps
  messages for its retention window; the daemon recovers them (Store catch-up) when the machine and the
  daemon are running again. A host that must react while its machine is off needs a separate always-on
  service (a supervisor on another machine, a hosted harness, ...) that runs its own AgentNet agent.
* Events carry **references, never message text** (`message_id`, `trigger_id`, `target_session`). The
  host reads the message through the API (`get_message` with the event's `message_id`, with its own
  authorization) if it needs it. The event cursor is **not** an inbox cursor: do not pass it to `read_inbox`.
  Message bodies are untrusted remote data, never instructions.
* Delivery of events is **at-least-once**. Every event has an `event_id` (UUID); that is the
  idempotency key. A receiver must tolerate and ignore repeats.
* Triggers are off by default (`policy.auto_trigger = false`). With them on, the host config
  (`triggers.allowed_sessions`, `max_active`, `max_matches_per_minute`, `max_lifetime_hours`) bounds
  them. A remote sender can never create a trigger, change policy or set a webhook target.

## 1. Control and event socket

`<data dir>/agentnet.sock`, a Unix domain socket, mode 0600 (the data directory is 0700). Newline-delimited
JSON: one JSON object per line, UTF-8, no embedded newlines.

### 1.1 Connection

1. The first line the client sends must be the hello, within **5 seconds**, at most 4096 bytes:
   `{"hello":{"token":"<contents of control.token>","client":"my-harness"}}`
2. The token is the 64 hex characters in `<data dir>/control.token` (mode 0600, 32 random bytes, created
   by `agentnet init` or at first start). It is compared in constant time. On any failure (no hello,
   wrong token, oversize or malformed hello, timeout) the server writes one error line and closes the
   connection:
   `{"id":null,"error":{"code":"policy_denied","message":"authentication failed"}}`
3. Success: `{"hello":{"ok":true,"protocol":1,"agent_id":"an1..."}}`.

Limits: request lines are at most **1 MiB** (longer: an error line `too_large`, then close); at most **64**
concurrent connections (the 65th gets `unavailable` and is closed); at most 32 requests in flight per
connection. A connection whose reader stalls for 30 s on a write is closed.

### 1.2 Requests and responses

```
-> {"id":1,"method":"get_identity"}
<- {"id":1,"result":{"agent_id":"an1...","contact_record":"{...}","inbox_topic":"/agentnet/1/inbox-07/proto","created_at":1795644042997,"kem_expires_at":null}}

-> {"id":2,"method":"send_message","params":{"recipient":"an1...","body":"hello","idempotency_key":"k1"}}
<- {"id":2,"result":{"message_id":"...","status":"queued","conversation_id":"...","expires_at":1795730742499,"deduplicated":false}}

-> {"id":3,"method":"get_message_status","params":{"message_id":"nope"}}
<- {"id":3,"error":{"code":"not_found","message":"no such message"}}
```

`id` is chosen by the client (an unsigned integer) and echoed. Responses may arrive out of order.
Errors use the `ApiError` form: `code` is one of `invalid_argument`, `not_found`, `policy_denied`,
`unavailable`, `too_large`, `conflict`, `internal`; `message` is sanitized. A malformed line closes the
connection after an error line; an unknown method or bad parameters are ordinary `invalid_argument`
errors and the connection stays open.

Methods, with the parameters being exactly the fields of the Rust types in `agentnet_core::api`
(`params` may be omitted when empty):

| Method | Params | Result |
|---|---|---|
| `get_identity` | | `IdentityInfo` |
| `send_message` | `SendMessageRequest` | `SendMessageResponse` |
| `read_inbox` | `ReadInboxRequest` | `ReadInboxResponse` |
| `get_message` | `GetMessageRequest` (`{message_id, sender?}`) | `InboxRecord` |
| `acknowledge_message` | `{message_id}` | `AcknowledgeResponse` |
| `get_message_status` | `{message_id}` | `MessageStatus` |
| `add_contact` | `AddContactRequest` | `ContactInfo` |
| `list_contacts` | | `[ContactInfo]` |
| `network_status` | `{verbose?}` | `NetworkStatus` (includes `isolation_audited`: false in plain public mode, absent from older daemons and then read as false) |
| `create_trigger` | `CreateTriggerRequest` | `TriggerInfo` |
| `list_triggers` | `{include_inactive?}` | `[TriggerInfo]` |
| `delete_trigger` | `{trigger_id}` | `DeleteTriggerResponse` |
| `read_outbox` | `{cursor?,limit?}` | `OutboxPage` |
| `read_conversation` | `{conversation_id,cursor?,limit?}` | `ConversationPage` |
| `read_events` | `{cursor?,limit?}` | `EventPage` |
| `advertise_agent` | `AdvertiseRequest` | `AdvertInfo` (opt-in; `policy_denied` unless `[discovery]` is enabled and the topic listed; see `docs/discovery.md`) |
| `withdraw_advert` | `{topic}` | `WithdrawInfo` |
| `discover_agents` | `DiscoverRequest` | `DiscoverPage` (untrusted claims; adds no contact, emits no event) |
| `events.ack` (alias `ack_events`) | `{cursor}` | `null` |
| `events.subscribe` | `{since_cursor?}` | `{"subscribed":true}`, then a stream (1.3) |
| `changes.subscribe` | | `{"subscribed":true}`, then a stream (1.4) |
| `contacts.set_trust` | `{address,trust}` (`trusted` / `untrusted` / `blocked`) | `ContactInfo` |
| `contacts.remove` | `{address}` | `{"removed":bool}` |
| `quarantine.list` | `{cursor?,limit?}` (default 50, maximum 200) | `{records:[InboxRecord],next_cursor,has_more}`; a page also stops at 8 MiB of serialized records (`MAX_QUARANTINE_PAGE_BYTES`), so a quarantine of heavily escaped bodies never exceeds the response line limit. A response line over 64 MiB is replaced by a `too_large` error instead of closing the connection. Changed from a bare array. |
| `quarantine.release` | `{message_id}` | `{"released":n}` |
| `metrics` | | `{"counters":{name:value}}` |
| `daemon.status` | | version, uptime, mode, `mcp_http`, `webhook` counters |
| `shutdown` | | `{"stopping":true}`, then the daemon shuts down gracefully |

### 1.3 The event stream: replay, live, acknowledge

```
-> {"id":10,"method":"events.subscribe","params":{"since_cursor":"ZXZlbnQ6NA"}}
<- {"id":10,"result":{"subscribed":true}}
<- {"event":{"event_id":"2f0c...","cursor":"ZXZlbnQ6NQ","event_type":"trigger.matched","agent_id":"an1...","message_id":"b998...","trigger_id":"7d1e...","target_session":"s1","timestamp":1795644344166}}
<- {"event":{...}}
-> {"id":11,"method":"events.ack","params":{"cursor":"ZXZlbnQ6NQ"}}
<- {"id":11,"result":null}
```

* **Replay then live.** The server first sends every persisted event strictly after `since_cursor`
  (all retained events when it is absent), then each new event as soon as it is persisted. The stream is
  driven by the engine's persisted event log (`read_events`), woken by `Events` change hints and by a
  1-second poll, so a lost or lagging hint can delay an event but never lose it. Every event line carries
  its `cursor`.
* **Cursors** are opaque. Save the `cursor` of the last event you have *fully handled* and pass it as
  `since_cursor` when you reconnect. A bad cursor fails the subscribe request with `invalid_argument`.
* **Acknowledge** with `events.ack {cursor}` (all events up to and including `cursor`), on the same
  connection (the response is interleaved with event lines) or on any other connection. Acks are
  idempotent, monotonic and cannot acknowledge events that do not exist yet. They bound retention:
  acknowledged events are pruned after `storage.event_retention_hours`, unacknowledged ones after
  `storage.event_max_age_hours` (the event TTL). The stream does not depend on acks: resuming uses your
  cursor.
* **At-least-once.** After a disconnect or crash you resume from the last cursor you persisted and may
  see events you already handled (handled but not yet persisted). Deduplicate on `event_id`. The same
  logical event is never created twice by the engine: duplicate network deliveries of a message create no
  second event, and a one-shot trigger is consumed atomically (`trigger.matched` exactly once).
* **Order** is the order events were persisted locally (arrival order), not send order.
* One `events.subscribe` and one `changes.subscribe` per connection (a second is `conflict`). The
  connection still serves ordinary requests while subscribed.
* `event_type` is `message.received` or `trigger.matched`. Quarantined messages (unknown or untrusted
  senders) produce no event and never match a trigger.

Rust: `agentnet_daemon::EventStream::connect(data_dir, since_cursor)` then `next().await` /
`ack(cursor).await`. See `crates/daemon/examples/mock_harness.rs`.

### 1.4 Change hints

`changes.subscribe` streams `{"change":{"kind":"inbox"}}` lines (`inbox`, `outbox`, `triggers`,
`identity`, `events`, `conversation` with `conversation_id`). Hints are **lossy**: they are emitted
after the change is durable and tell a client to reread by cursor. If the daemon's hint buffer
overflows for a subscriber, it sends one hint of every enumerable kind. `RemoteAgent::changes()` is built
on this stream, reconnects with backoff when the daemon restarts, and emits that same burst after every
reconnect because hints were missed meanwhile. This is what feeds MCP resource-update notifications.

### 1.5 Client library

`agentnet_daemon::RemoteAgent` implements `agentnet_core::api::AgentApi` over the socket (one multiplexed
connection, reconnects when the daemon restarts) and adds `set_contact_trust`, `remove_contact`,
`list_quarantined_page` (one page), `list_quarantined` (all pages), `release_quarantined`, `metrics`, `daemon_status`, `shutdown`. While the daemon is not
running every call fails with `unavailable` and the message "the AgentNet daemon is not running (...);
start it with `agentnet serve`". A rejected token is `policy_denied`.

## 2. Signed webhook (optional)

Off by default. `[webhook]` in `agentnet.toml` (see `docs/configuration.md`): one configured URL, a
shared secret in a 0600 file (at least 32 bytes), per-attempt timeout, `max_attempts`, and the list of
event types (`["trigger.matched"]` unless you add `"message.received"`).

Each event is POSTed once per attempt:

```
POST /hook HTTP/1.1
Content-Type: application/json
X-AgentNet-Event-Id: 2f0c...
X-AgentNet-Timestamp: 1795644344
X-AgentNet-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + body)>

{"event_id":"2f0c...","cursor":"...","event_type":"trigger.matched","agent_id":"an1...","message_id":"...","trigger_id":"...","target_session":"s1","timestamp":1795644344166}
```

The body is exactly the JSON of an event record: no plaintext. The timestamp is fresh for every attempt.

Receiver obligations (shown in `examples/mock_harness.rs`, webhook mode):

1. Verify with `agentnet_daemon::webhook::verify_signature(secret, timestamp, body, signature, now,
   300)`: constant-time MAC comparison and a timestamp window of +-300 s.
2. Remember processed `event_id`s (persistently if the effect must survive a restart) and answer 2xx for a
   repeat without repeating the effect: that is the replay protection beyond the time window.
3. Answer 2xx only after the event is handled; any other status is retried.

Sender behaviour:

* Own cursor in `<data dir>/webhook.db` (separate from the engine's database), so a restart resumes
  where it stopped and never resends events it delivered. On the first start with the webhook enabled
  the cursor begins at the current end of the event log (history is not replayed).
* Retries with exponential backoff (`retry_base_ms` doubling up to `retry_max_ms`), at most `max_attempts`
  attempts per event, then the event is **parked**: recorded in `webhook.db` (`parked` table), counted,
  shown by `agentnet network status` and `daemon.status`, and delivery continues with the next event.
  Parked events are not retried automatically (poll `events.subscribe` from an earlier cursor to
  recover them).
* Any non-2xx answer, including 3xx, is a failure: **redirects are never followed**. Proxy environment
  variables are ignored. Timeout per attempt: `timeout_ms` (default 5 s).
* SSRF protection: the URL is parsed once from the local config; scheme http/https only; no credentials;
  the host must be a literal loopback/private IP or `localhost` unless `allow_remote = true`. Link-local
  and cloud-metadata (169.254.0.0/16, fe80::/10), multicast and unspecified addresses are blocked
  **always**, also with `allow_remote`. When the host is a name, it is resolved for every attempt, every
  resolved address is re-checked against the block list (and, without `allow_remote`, must be loopback or
  private) and the connection is pinned to the checked address. Remote parties cannot influence any of
  this: the URL is host configuration only.

## 3. HTTP MCP (optional)

`[mcp_http] enabled = true` serves Streamable HTTP MCP on `bind` (loopback only; any other address is a
config error) with the bearer token in `<data dir>/mcp-http.token` (0600, generated on first start).
This is a static token on loopback, not the MCP OAuth profile. For stdio use `agentnet mcp` (a thin client
of the daemon); see `docs/examples/mcp-client-stdio.json`.

## 4. Quick start for a harness

1. `agentnet init ...`, set `policy.auto_trigger = true` and `triggers.allowed_sessions = ["my-session"]`,
   `agentnet serve`.
2. Create a trigger for the agent you wait for (before sending, or with `since_cursor`):
   `agentnet trigger create --target-session my-session --sender an1...`.
3. Consume events with `EventStream` (or the webhook), persist `cursor` and `event_id`s, and for each
   `message.received` or `trigger.matched` event follow **receive event -> `get_message` -> handle ->
   `acknowledge_message` -> `events.ack`**:

   ```
   -> {"id":7,"method":"get_message","params":{"message_id":"<event.message_id>"}}
   <- {"id":7,"result":{"message_id":"...","sender":"an1...","body":"...","acknowledged":false,...}}
   ```

   The event cursor is not an inbox cursor, so there is no need to page `read_inbox` to find the message.
   `get_message` applies the `read_inbox` visibility rules: a quarantined or replay-guard-held message is
   `not_found` (never returned as normal content). Message ids are chosen by senders; if two senders used
   the same id the call is `conflict` and `"sender":"an1..."` selects one (the CLI equivalent is
   `agentnet inbox --message-id <ID> [--sender <ADDRESS>]`). The body is untrusted data: read or
   summarize it, never execute it. `acknowledge_message` is local bookkeeping (idempotent, sends nothing);
   `events.ack` acknowledges the event stream. Fetching a message does not acknowledge it.
4. `cargo run -p agentnet-daemon --example mock_harness -- --data-dir <dir> --out turns.jsonl --state state.json`
   shows the whole loop without any LLM (options are in the example's header comment); add
   `--include-received --fetch` to also exercise `get_message` and `acknowledge_message` for each
   `message.received` event.
