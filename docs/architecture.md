# AgentNet MVP architecture

Status: blueprint for Phase B, written by the lead after the Phase A spikes.
Evidence for each decision lives in `docs/spike/` and `docs/adr/`. Where this
document and the code disagree after implementation, the code plus
`docs/protocol.md` win and this file must be corrected.

## 1. Decisions carried over from the spike

| Area | Decision | Evidence |
|---|---|---|
| Transport | Adapter to a separately running Logos Delivery node over its local REST API (relay publish + poll, Store v3 for recovery). Native FFI embedding is a future option behind the same trait. | `docs/spike/notes-daemon-rest.md`, `docs/spike/notes-ffi-bindings.md`, ADR 0001 |
| E2E encryption | HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305, with an inner Ed25519 signature bound to the recipient. libchat rejected. | `docs/spike/notes-libchat-and-crypto.md`, `docs/spike/notes-e2e-crypto.md`, ADR 0002 |
| MCP | `rmcp = "=3.11.0"`, protocol 2026-07-28 (`server/discover`, `subscriptions/listen`) with SDK-provided legacy negotiation down to 2024-11-05. | `docs/spike/notes-mcp.md` |
| Storage | SQLite (`rusqlite`, bundled), WAL, every state transition in a transaction. | this document |

## 2. Process model

```
 MCP host ──stdio──> agentnet mcp ──┐ (thin client)
 MCP host ──HTTP (loopback, bearer)─┤
 harness  ──event stream (UDS)──────┤
                                    v
                         agentnet serve  (daemon; single writer; owns identity + SQLite)
                                    │ REST (loopback / private address only)
                                    v
                       Logos Delivery node (sidecar, user-run)
                                    │ libp2p, static peers only in private mode
                                    v
                         user-owned relay / store node(s)
```

* One data directory = one agent identity = at most one running daemon
  (exclusive advisory lock on `<data_dir>/lock`; a second instance exits with an
  error).
* Process lifecycle is not agent identity: `agentnet mcp` processes come and go;
  the identity, inbox, outbox, triggers and events live in the daemon's SQLite.
* The daemon never opens network connections other than: the configured node
  REST endpoint, and (optionally) the configured webhook URL.

## 3. Workspace

```
crates/transport/   agentnet-transport  Transport trait, MockTransport, LogosRestTransport (feature "logos-rest")
crates/core/        agentnet-core       identity, contact records, envelope crypto, SQLite store, Node engine, triggers, events, AgentApi trait
crates/mcp/         agentnet-mcp        rmcp server over `Arc<dyn AgentApi>`
crates/daemon/      agentnet-daemon     config, lock, wiring, control+event socket (server and client), webhook, HTTP MCP
crates/cli/         agentnet-cli        the `agentnet` binary
examples/           mock harness, embedding example
tests/              acceptance driver + scripts
```

Dependency direction: `transport` <- `core` <- `mcp` <- `daemon` <- `cli`.
`core` depends on `transport` with `default-features = false` (trait + mock only),
and never on `rmcp`, `reqwest` or any harness.

## 4. Identity and addresses

* Signing key: Ed25519. Agreement key: independent X25519 key used as an HPKE
  recipient key. The two are never derived from one another.
* Address: `an1` + lowercase RFC 4648 base32 (no padding) of
  `signing_pk (32 bytes) || checksum (4 bytes)`, where
  `checksum = SHA-256("agentnet/v1/address-checksum" || signing_pk)[0..4]`.
  The checksum catches typos; it is not a security mechanism. The address *is*
  the signing public key, so an address authenticates a contact record without
  any directory.
* Contact record (public, shareable): a JSON document
  `{"record": "<base64url of record bytes>", "sig": "<base64url of 64-byte signature>"}`
  where the record bytes are JSON
  `{"v":1,"address":…,"signing_pk":…,"kem_pk":…,"key_epoch":1,"revoked_kem_epochs_below":1,"suites":[1],"inbox_buckets":16,"created_at":<unix ms>,"kem_expires_at":<unix ms or null>}`
  and `sig = Ed25519(signing_sk, "agentnet/v1/contact-record\0" || record_bytes)`.
  Verification: address decodes and checksums, equals the record's
  `address`/`signing_pk`, signature verifies. The signature is what binds the
  agreement key to the signing key.
* Persistence: `<data_dir>/identity.json`, mode 0600, directory mode 0700.
  Secrets are zeroized in memory on drop.
* Export / import: `agentnet identity export` writes an `age`
  passphrase-encrypted file (scrypt recipient); `import` restores it into an
  empty data dir. Migration = export, import, start. Running the same identity
  in two places at once is not supported (each would ack and dedupe
  independently); the lock only protects one data directory.
* Rotation and revocation (details and limits: `docs/protocol.md` section 9):
  `agentnet identity rotate-kem` generates a new agreement key and increments
  `key_epoch`; by default the previous key keeps decrypting until
  `retention_hours` have passed, with `--revoke-previous` every earlier agreement
  key is destroyed at once. At the next start the daemon sends the new signed
  record to every Trusted contact (`contact.update`) and the contacts re-seal
  their pending messages. `agentnet identity revoke` writes a signed tombstone
  and the daemon then only delivers it (`identity.revoked`). There is no
  directory and no global revocation list: revocation reaches only peers that
  receive the notice.
* The cryptography sits behind `agentnet_core::crypto` and the
  `MessageProtection` trait (`docs/crypto-interface.md`); the engine, transport,
  MCP server and daemon do not touch the cryptographic crates.

## 5. Message protocol

Specified normatively in `docs/protocol.md`. Summary:

* Envelope (JSON, the exact bytes are signed and are never re-serialized):
  `v, message_id (UUIDv4), sender, recipient, type, conversation_id?,
  correlation_id?, created_at, expires_at, body`.
* Types: `message`, `ack.received`, `task.request`, `task.result`. Unknown types
  are stored as data with their type string; unknown `v` is rejected.
* Seal: `sig = Ed25519(sender_sk, "agentnet/v1/envelope\0" || envelope)`;
  `plaintext = u32_be(len) || sig || envelope || zero padding` to a power-of-two
  bucket (min 512 B, capped so the encoded Waku message stays under the node
  limit); HPKE single-shot seal with `info = "agentnet/v1/hpke\0" || recipient_kem_pk`
  and `aad = frame header`; frame = `"AN" || version || suite || enc || ciphertext`.
* Open: strict header parse, HPKE open, length check, signature check under the
  sender address, `recipient == self`, time window (`created_at` not more than
  `clock_skew` in the future, `expires_at` not passed, TTL not above the maximum),
  then dedupe on `(sender, message_id)`.
* Sender identity, type and all correlation data are inside the ciphertext.
  Visible to relays: content topic (inbox bucket), time, padded size, the
  publishing node's peer ID/IP.
* Inbox topic: `/agentnet/1/inbox-<hh>/proto`, bucket =
  `u16_be(SHA-256("agentnet/v1/inbox-topic" || signing_pk)[0..2]) % inbox_buckets`.
  All agents of a bucket share a topic and trial-decrypt (k-anonymity within the
  deployment; bandwidth grows with bucket population). `inbox_buckets` is part of
  the signed contact record so senders cannot guess wrong.

### Delivery semantics

At-least-once delivery attempts with idempotent receipt; no global ordering.

Outbox states: `queued` -> `sent` (the local node accepted the publish — this is
*not* receipt) -> `delivered` (an authenticated `ack.received` from the recipient
arrived). Terminal alternatives: `failed` (permanent error such as oversize or
unknown recipient key), `expired` (TTL passed without ack).

* Retry: while not delivered and not expired, re-publish with exponential backoff
  (base 2 s, factor 2, cap 5 min, equal jitter: uniform in [c/2, c]), fresh Waku timestamp each time.
  Bounded by `expires_at` and `max_attempts`.
* Receive: live poll of the node's relay cache every `poll_interval_ms`, plus a
  Store catch-up at start, after reconnect and every `store_sync_interval_s`,
  covering `[last_sync - overlap, now]` in <= 24 h windows back to
  `retention_hours`. Both paths feed one bounded channel; a transport-hash cache
  drops repeats before decryption.
* An accepted inbound message is persisted (inbox row + dedupe row + event rows +
  trigger consumption, one transaction) **before** any notification and before the
  ack is queued. Acks are ordinary sealed envelopes of type `ack.received` with
  `correlation_id = message_id`; acks are never acked. A duplicate of an already
  persisted message re-queues the ack (the first may have been lost) but creates
  no inbox row and no event.
* Unknown senders: `policy.unknown_senders = "quarantine"` (default) stores the
  message with `quarantined = true`; it is not returned by default reads, never
  matches triggers, emits no `message.received` event, and is not acked.
  `"reject"` drops it; `"accept"` treats it as normal.
* Read cursors are opaque strings wrapping a monotonically increasing local
  sequence number. Notifications are hints; clients recover by rereading from
  their cursor.

## 6. Networking modes

`[network] mode = "private"` is the default and fails closed:

* `node_url` must be loopback, RFC 1918, CGNAT/Tailscale (100.64.0.0/10) or a
  unix-local name; anything else is a startup error.
* `peers` (static multiaddrs with peer IDs) is required. At start and
  periodically the daemon reads the node's peer list and **refuses to send or
  receive** (status `isolated_violation`) if the node is connected to any peer ID
  outside the allowlist, or if the node's cluster is a known public preset
  (1, 2, 3, 16).
* `public_discovery` and `public_fallback` must be false; setting either to true
  in private mode is a config error. There is no code path that adds peers.
* The daemon cannot set the node's flags. `agentnet relay print-config` emits the
  verified flag set (all discovery off, `--dns-addrs-name-server`,
  `--nat=extip`, cluster/shard) and a compose file; the peer audit above is the
  runtime check that the operator followed it.

`mode = "public"` must be chosen explicitly, requires `i_understand_public = true`,
skips the peer allowlist audit and is otherwise identical. It is UNTESTED against
any public network. Public and private traffic are never bridged: one daemon has
exactly one node and one mode.

## 7. Host integration (events and triggers)

* Control/event socket: `<data_dir>/agentnet.sock` (mode 0600), newline-delimited
  JSON. Every connection starts with `hello {token}`; the token is
  `<data_dir>/control.token` (0600, random 32 bytes). Methods mirror `AgentApi`,
  plus `events.subscribe {since_cursor}` (replay then live stream),
  `events.ack {cursor}` and `changes.subscribe` (resource-change hints used by
  `agentnet mcp`).
* Event record: `event_id` (UUID), `cursor`, `event_type`
  (`message.received` | `trigger.matched`), `agent_id`, `message_id`,
  `trigger_id?`, `target_session?`, `timestamp`. No plaintext.
* Triggers are durable predicates: `sender?`, `type?`, `conversation_id?`,
  `correlation_id?`, `target_session`, `once`, `expires_at`, `since_cursor?`.
  Evaluated inside the inbox-insert transaction against authenticated,
  non-quarantined messages only; a `once` trigger is consumed atomically.
  `since_cursor` makes creation match already-persisted messages, closing the
  reply-before-trigger race.
* Off by default: `policy.auto_trigger = false` makes `create_trigger` fail with
  a policy error. When enabled the host config supplies
  `triggers.allowed_sessions`, `max_active`, `max_matches_per_minute` and
  `max_lifetime_hours`. Remote messages can never create triggers, change policy
  or set webhook targets.
* Optional webhook: one preconfigured URL, HMAC-SHA256 over
  `timestamp + "." + body` with a shared secret, `event_id` as idempotency key,
  5 s timeout, no redirects, bounded retries with backoff, loopback/private
  destinations only unless `allow_remote = true`.
* The daemon emits events. Whether to run inference is the harness's decision.

## 8. MCP surface

Tools: `get_identity`, `send_message`, `read_inbox`, `acknowledge_message`,
`get_message_status`, `add_contact`, `network_status`, `create_trigger`,
`list_triggers`, `delete_trigger`. Resources: `agentnet://identity`,
`agentnet://inbox`, `agentnet://outbox`, `agentnet://conversations/{id}`
(template), `agentnet://triggers`. Updates are sent only to listeners that asked
for the URI, only after persistence. stdio first; Streamable HTTP on loopback
with a bearer token, Host allowlist and Origin validation. A static bearer token
on loopback is not the MCP OAuth profile; remote HTTP exposure is out of scope
and refused by config.

## 9. Explicit non-goals for the MVP

Groups, multi-device, forward secrecy, discovery/advertisement, task delegation
tools, hybrid public/private gateways, a single static binary including the
node, Windows.
