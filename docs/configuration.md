# Configuration (`agentnet.toml`)

The file lives in the data directory (`$AGENTNET_HOME`, default `~/.agentnet`, or `--data-dir`).
`agentnet init` writes a private-mode file. Unknown keys and unknown values are errors. Every section is
optional; an omitted key takes the default shown. The daemon validates the file at start and refuses to run
on any error (fail closed). `agentnet doctor` checks it too. Examples: `docs/examples/private.toml`,
`docs/examples/public.toml` (generated from `agentnet_daemon::sample_private_config()` /
`sample_public_config()` and checked by a test).

Code: `crates/daemon/src/config.rs`. The `[storage]`, `[policy]`, `[triggers]` and `[delivery]` sections
are the engine's own configuration (`agentnet_core::config`), validated by the engine; the network
section is validated by the REST transport (`agentnet_transport::logos_rest::LogosRestConfig::validate`).
The daemon surfaces their error messages and does not duplicate their rules.

## Data directory layout

| Path | Mode | Purpose |
|---|---|---|
| `.` | 0700 | The daemon refuses to start if group/others have any access |
| `identity.json` | 0600 | Secret keys; loading refuses looser permissions |
| `revocation.json` | 0600 | Signed identity-revocation tombstone; exists only after `agentnet identity revoke`. A revoked identity sends nothing except this notice |
| `agentnet.generation` | 0600 | Sidecar of the store generation (JSON `{"v":1,"generation":N,"guard":null}`), rewritten and fsynced after every committed receive. A database *older* than this file means the store was rolled back and starts the replay guard; a missing sidecar next to an existing database does too. Copy it together with `agentnet.db` to migrate with dedupe history. `identity import` creates it with an `imported` marker (guard on the first start) unless `--no-replay-guard` is given. Nothing to configure: `agentnet doctor` reports it and `agentnet doctor --accept-rollback` (daemon stopped) accepts a rollback |
| `agentnet.toml` | 0600 | This file |
| `agentnet.db` (+ `-wal`, `-shm`) | 0600 | Engine store (SQLite, WAL) |
| `webhook.db` | 0600 | Webhook dispatcher cursor and parked events |
| `lock` | 0600 | Exclusive advisory lock held for the daemon's life |
| `agentnet.sock` | 0600 | Control and event socket (removed on shutdown; a stale one is replaced while holding the lock) |
| `control.token` | 0600 | Socket token (64 hex chars) |
| `mcp-http.token` | 0600 | Bearer token for `[mcp_http]` |

One data directory is one agent identity and at most one process: a second `agentnet serve` (or an
`identity export|import|rotate-kem|revoke`, `doctor --accept-rollback`) on the same directory fails with "another AgentNet process is using
this data directory". The socket path must fit a Unix socket (about 100 bytes): use a short `--data-dir`.

## `[network]`

| Key | Default | Meaning |
|---|---|---|
| `mode` | `"private"` | `"private"` or `"public"` |
| `node_url` | `"http://127.0.0.1:8645"` | REST endpoint of your Logos Delivery node. Private mode: loopback, RFC 1918, 100.64.0.0/10 (Tailscale), IPv6 loopback/ULA, or the literal `localhost`; names are never resolved. |
| `peers` | `[]` | Static peers: multiaddrs ending in `/p2p/<peerId>` (private IP literal). **Required (non-empty) in private mode.** The allowlist of peer ids is derived from them. |
| `cluster_id` | `66` | Waku cluster id. Private mode rejects the public preset ids 1, 2, 3 and 16. Cluster/shard separation is not access control. |
| `public_discovery` | `false` | `true` is a config error in private mode. The daemon cannot switch discovery on the node; this key only records intent in public mode. |
| `public_fallback` | `false` | `true` is **always** a config error: there is no public fallback and no code path that adds peers. |
| `i_understand_public` | `false` | Must be `true` for `mode = "public"` |
| `store_peer` | unset | Optional explicit Store peer multiaddr (private mode: private IP + allowlisted peer id) |

### Private mode (default)

Fails closed. Startup is refused unless `node_url` is local/private, `peers` is non-empty and valid,
`cluster_id` is not a public preset and both `public_*` flags are false. At runtime the transport audits the
node's peer list and **refuses to send or receive** (`isolation_violation` in `network status`) if the node
is connected to any peer outside the allowlist. The daemon cannot set the node's flags: `agentnet relay
print-config` prints the verified flag set (all discovery off, `--dns-addrs-name-server=127.0.0.1`,
`--nat=extip:<ip>`, cluster 66 / shard 0, `--rln-relay=false`, REST on loopback) and the audit is the
runtime check that the operator followed it.

### Public mode

Explicit opt-in (`mode = "public"` and `i_understand_public = true`), skips the peer allowlist audit,
otherwise identical. **UNTESTED against any public network.** Known limitation: the REST adapter supports
only single-shard networks (shard 0), which the shared public networks are not. Public and private
traffic are never bridged: one daemon talks to one node in one mode.

## `[storage]`

| Key | Default | Meaning |
|---|---|---|
| `retention_hours` | `168` | Inbox/outbox retention and how far back history sync reaches |
| `max_inbox_records` | `100000` | Beyond this new messages are refused (not acked) |
| `max_quarantined` | `1000` | Beyond this quarantined messages are dropped |
| `event_retention_hours` | `168` | Acknowledged events are kept this long |
| `event_max_age_hours` | `720` | Unacknowledged events older than this are dropped (event TTL) |

## `[policy]`

| Key | Default | Meaning |
|---|---|---|
| `unknown_senders` | `"quarantine"` | `quarantine` (stored, no ack/event/trigger), `reject` (dropped), `accept` (stored, never matches triggers, never acked) |
| `auto_trigger` | `false` | `false` makes `create_trigger` fail with `policy_denied` |

## `[triggers]`

| Key | Default | Meaning |
|---|---|---|
| `allowed_sessions` | `[]` | Host-approved `target_session` values; empty means no trigger can be created |
| `max_active` | `32` | Simultaneously active triggers |
| `max_matches_per_minute` | `60` | Sliding-minute budget of `trigger.matched` events |
| `default_lifetime_s` | `3600` | Lifetime when a request gives none |
| `max_lifetime_hours` | `24` | Upper bound of a trigger's lifetime |

## `[delivery]`

Engine tuning; defaults are in `docs/protocol.md` section 8 and `crates/core/src/config.rs`:
`default_ttl_s` (86400), `max_ttl_s` (604800), `retry_base_ms` (2000), `retry_max_ms` (300000),
`max_attempts` (20), `poll_interval_ms` (250), `history_sync_interval_s` (15), `history_overlap_s` (30),
`clock_skew_s` (120), `max_body_bytes` (65536), `max_outbox_pending` (1000), `inbound_channel_capacity`
(256), `reack_min_interval_s` (30), `send_batch` (64), `transport_seen_ttl_s` (86400), `jitter_seed`
(unset; tests only).

## `[mcp_http]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve Streamable HTTP MCP from the daemon |
| `bind` | `"127.0.0.1:8650"` | `IP:port`; **must be loopback** (a non-loopback address is a config error even when disabled). Bearer token: `mcp-http.token`. Static bearer on loopback is not the MCP OAuth profile. |

## `[webhook]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Deliver events to `url` |
| `url` | `""` | The one destination. http/https, no credentials. Host: literal loopback/private IP or `localhost`, unless `allow_remote`. Link-local/metadata (169.254.0.0/16, fe80::/10), multicast and unspecified addresses are always rejected. |
| `secret_file` | `""` | Shared HMAC secret, at least 32 bytes (a trailing newline is ignored), mode 0600; relative paths are relative to the data directory. Required when enabled. |
| `allow_remote` | `false` | Permit public IPs and hostnames (resolved per attempt, every address re-checked, connection pinned) |
| `timeout_ms` | `5000` | Per attempt, 1..=60000 |
| `max_attempts` | `5` | 1..=20; then the event is parked |
| `events` | `["trigger.matched"]` | Subset of `trigger.matched`, `message.received` |
| `retry_base_ms` | `500` | First retry delay (doubles) |
| `retry_max_ms` | `30000` | Retry delay cap |

Protocol, signature scheme and receiver duties: `docs/host-integration.md`.

## Validation matrix (tested in `crates/daemon/src/config.rs`)

| Setting | Result |
|---|---|
| defaults without `peers` | error: `network.peers` required |
| `mode = "public"` without `i_understand_public` | error |
| `public_fallback = true` (any mode) | error |
| `public_discovery = true` in private mode | error |
| `node_url` public host, preset `cluster_id`, public/invalid peer multiaddr | error from the transport validation (`network: ...`) |
| `mcp_http.bind` not loopback / not an `IP:port` | error |
| webhook URL public, hostname, link-local, metadata, multicast, unspecified, credentials, non-http(s) | error (hostnames and public IPs allowed only with `allow_remote`; link-local etc. never) |
| unknown key or enum value anywhere | error |
