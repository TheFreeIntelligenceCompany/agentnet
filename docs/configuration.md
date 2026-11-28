# Configuration (`agentnet.toml`)

The file lives in the data directory (`$AGENTNET_HOME`, default `~/.agentnet`, or `--data-dir`).
`agentnet init` writes a private-mode file (`agentnet init --public-relay --peer <multiaddr>` writes the audited public mode below instead; `init` validates the file before writing anything and fails, naming both choices, when a `--peer` is not acceptable in private mode, e.g. a public IP or DNS name; it never switches mode silently). Unknown keys and unknown values are errors.

Omitted keys use defaults, but private mode requires at least one relay address in `[network].peers`. A minimal runnable file:

```toml
[network]
node_url = "http://127.0.0.1:8645"
peers = ["/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV"]
```

(`node_url` is your own Logos Delivery node; `peers` is your own relay's multiaddr; the values above are the local spike topology's. Everything
else takes the default shown in the tables below. `agentnet init --node-url <url> --peer <multiaddr>` writes the full file for you.)

Every section is optional; an omitted key takes the default shown. The daemon validates the file at start and refuses to run
on any error (fail closed). `agentnet doctor` checks it too. Examples: `docs/examples/private.toml`,
`docs/examples/public-relay.toml`, and `docs/examples/public.toml` (generated from `agentnet_daemon::sample_private_config()` /
`sample_public_relay_config()` / `sample_public_config()` and checked by a test).

Code: `crates/daemon/src/config.rs`. The `[storage]`, `[policy]`, `[triggers]` and `[delivery]` sections
are the engine's own configuration (`agentnet_core::config`), validated by the engine; the network
section is validated by the REST transport (`agentnet_transport::logos_rest::LogosRestConfig::validate`).
The daemon surfaces their error messages and does not duplicate their rules.

## Data directory layout

| Path | Mode | Purpose |
|---|---|---|
| `.` | 0700 | The daemon refuses to start if group/others have any access |
| `identity.json` | 0600 | Secret keys; loading refuses looser permissions |
| `revocation.json` | 0600 | Revoked public certificate (the identity revocation); exists only after `agentnet identity revoke`. A revoked identity sends nothing except this notice |
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
| `peers` | `[]` | Static peers: multiaddrs ending in `/p2p/<peerId>` (exactly one private IP literal and one `/p2p/` peer id; `/p2p-circuit` relay hops, DNS components and a second `/p2p/` are rejected in private mode; runtime behaviour of the node with such addresses is UNTESTED). **Required (non-empty) in private mode.** The allowlist of peer ids is derived from them. |
| `cluster_id` | `66` | Waku cluster id. Private mode rejects the public preset ids 1, 2, 3 and 16. Cluster/shard separation is not access control. |
| `public_discovery` | `false` | `true` is a config error in private mode. The daemon cannot switch discovery on the node; this key only records intent in public mode. |
| `public_fallback` | `false` | `true` is **always** a config error: there is no public fallback and no code path that adds peers. |
| `i_understand_public` | `false` | Must be `true` for `mode = "public"` |
| `enforce_peer_allowlist` | `false` | Only valid with `mode = "public"` (a config error in private mode, which always audits). Keeps the peer-id allowlist audit for **your own relay on a public address**; needs `peers`. See "Public mode with the allowlist audit kept" below. |
| `store_peer` | unset | Optional explicit Store peer multiaddr (private mode: private IP + allowlisted peer id; with `enforce_peer_allowlist`: the same address forms as `peers`) |

### Private mode (default)

Fails closed. Startup is refused unless `node_url` is local/private, `peers` is non-empty and valid,
`cluster_id` is not a public preset and both `public_*` flags are false. At runtime the transport audits the
node's peer list and **refuses to send or receive** (`isolation_violation` in `network status`) if the node
is connected to any peer outside the allowlist. The daemon cannot set the node's flags: `agentnet relay
print-config` prints the verified flag set (all discovery off, `--dns-addrs-name-server=127.0.0.1`,
`--nat=extip:<ip>`, cluster 66 / shard 0, `--rln-relay=false`, REST on loopback) and the audit is the
runtime check that the operator followed it. A peer list the transport cannot parse strictly (an entry that is not an object with a string `multiaddr` and a `connected` state of `Connected`, `NotConnected`, `CannotConnect` or `CanConnect`) makes the node unauditable, which also refuses sends and receives.

### Public mode

Explicit opt-in (`mode = "public"` and `i_understand_public = true`), skips the peer allowlist audit,
otherwise identical. **UNTESTED against any public network.** Known limitation: the REST adapter supports
only single-shard networks (shard 0), which the shared public networks are not. Public and private
traffic are never bridged: one daemon talks to one node in one mode.

Which mode to pick:

| Mode | Peers accepted | Allowlist audit | `doctor` isolation line |
|---|---|---|---|
| `private` (default) | one literal private-range IP, tcp, one `/p2p/` id; no DNS, no relay hops | yes, fail closed | `[ok]` / `[FAIL]` |
| `public` + `enforce_peer_allowlist = true` | public or private IP, or dns4/dns6; tcp; optional `tls`, `ws`, `wss`; exactly one `/p2p/` id; no `/p2p-circuit`, no `dnsaddr` | yes, fail closed | `[ok]` / `[FAIL]` |
| `public` (plain) | any multiaddr ending in `/p2p/<id>` | **no** | `[skip] not audited in public mode` |

In plain public mode `network status` and `doctor` do not call peers "allowed" (nothing is audited), and
`doctor --ready` still reports ready when the transport is ready: the `isolation` line stays a skip that
says "not audited", it is never reported `[ok]`.

### Public mode with the allowlist audit kept (`enforce_peer_allowlist`)

For a relay that you run yourself but that is reached over a public address (a public IP, or a DNS name,
possibly behind a TLS/WebSocket front end). Set `mode = "public"`, `i_understand_public = true` and
`enforce_peer_allowlist = true` (`agentnet init --public-relay --peer <multiaddr>` writes exactly this). Then:

* `peers` (and `store_peer`) may be `/ip4|ip6|dns4|dns6/<host>/tcp/<port>[/tls][/ws|/wss]/p2p/<peerId>`.
  `/p2p-circuit` relay hops, `dnsaddr`, any other component and a second `/p2p/` are rejected.
* The allowlist is derived exactly as in private mode: the peer ids of `peers`. `peers` must not be empty.
* The node's peer list is audited every `audit_interval` (15 s) for status, subscribe, poll and history, and
  **again, uncached, immediately before every publish** (one extra `GET /admin/v1/peers` per publish). A connected peer outside the allowlist, or an
  unauditable node, sets `isolation_violation`, the transport is not ready and sends are not published
  (same fail-closed behaviour as private mode). The adapter redials the configured peers as in private mode.
* `cluster_id` must still not be a public preset (1, 2, 3, 16); `node_url` plain http is still only for
  loopback/private hosts.

```toml
[network]
mode = "public"
i_understand_public = true
enforce_peer_allowlist = true
node_url = "http://127.0.0.1:8645"
cluster_id = 66
peers = ["/dns4/relay.example.org/tcp/443/wss/p2p/16Uiu2HAm..."]
```

What this does **not** give you: the node itself may resolve names through a public DNS resolver
(`--dns-addrs-name-server` cannot be loopback when it has to resolve your relay's name), so "zero public
egress" no longer holds; the relay endpoint is reachable by anyone, and cluster/shard ids are not access
control (`docs/threat-model.md` T13), so strangers can join your relay and read ciphertext and metadata.
It only guarantees that this agent's node is not meshed with peers outside `peers`; like the private-mode
audit it is detective, not preventive. Validated on the OpenPGP tree in single runs against a real public-IPv4 relay (`results/public-ip-relay/20261127T215151Z/`, 19 PASS: 6 of 6 sends issued right after a foreign peer joined stayed queued) and a `wss` TLS edge (`results/public-relay/20261127T215957Z/`, 14 PASS). **Detective only:** a peer that connects between the uncached pre-publish audit response and the publish request can still get one message, so the window is one REST round trip. **UNTESTED:** more than one client, long runs, millisecond-scale publish races.

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

## `[discovery]`

Optional capability discovery; **off by default**. Full description: `docs/discovery.md`.
This is not the node's peer discovery (`network.public_discovery`, which stays forbidden in
private mode): adverts are signed statements on content topics of the same relay.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | With `false` the daemon subscribes to nothing, publishes nothing and the discovery tools return `policy_denied` |
| `topics` | `[]` | Authorized topic names, each `[a-z0-9-]{1,32}` (at most 16, no duplicates); required (non-empty) when `enabled`. A name maps to `/agentnet/1/discovery-<name>/proto`. Tool calls naming another topic are `policy_denied` |
| `max_records` | `500` | Stored advertisements across all topics; when full the soonest-expiring is evicted (never for a blocked or revoked advertiser) |
| `max_advert_ttl_s` | `86400` | Longest accepted and issued lifetime, 1..=604800 |
| `default_advert_ttl_s` | `3600` | Lifetime when a request gives none; `<= max_advert_ttl_s` |
| `republish_interval_s` | `900` | How often our own advertisement is published again |
| `max_capabilities` | `16` | Per advertisement, issued and accepted; 1..=64 |

Advertisements are PLAINTEXT and readable by every node on the relay. In private mode they stay on the same
private node and relay; nothing new is contacted.

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
| `enforce_peer_allowlist = true` in private mode | error (says to use `mode = "public"`) |
| `enforce_peer_allowlist = true` with empty `peers` | error |
| `enforce_peer_allowlist = true` with `/p2p-circuit`, `dnsaddr`, a second `/p2p/`, a bad port or host, or a preset `cluster_id` | error (`network: ...`) |
| `public_fallback = true` (any mode) | error |
| `public_discovery = true` in private mode | error |
| `discovery.enabled = true` without `topics`; invalid or duplicate topic name; `default_advert_ttl_s > max_advert_ttl_s`; `max_capabilities` outside 1..=64 | error (`engine: ...`) |
| `node_url` public host, preset `cluster_id`, public/invalid peer multiaddr | error from the transport validation (`network: ...`) |
| `mcp_http.bind` not loopback / not an `IP:port` | error |
| webhook URL public, hostname, link-local, metadata, multicast, unspecified, credentials, non-http(s) | error (hostnames and public IPs allowed only with `allow_remote`; link-local etc. never) |
| unknown key or enum value anywhere | error |
