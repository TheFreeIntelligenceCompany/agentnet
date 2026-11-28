# ADR 0005 — Native Pure-Rust libp2p Waku v2 Transport & Standalone Relay (Zero Docker)

- **Status:** Experimental branch (`feat/native-rust-waku-transport`)
- **Date:** 2026-11-28
- **Related:** [ADR 0001 — Transport](0001-transport.md), [ADR 0004 — OpenPGP Message Protection](0004-openpgp-message-protection.md)

## Context

ADR 0001 selected a separately running Logos Delivery (`wakuorg/nwaku` v0.39.2) container over HTTP REST (`LogosRestTransport`) for the MVP. While that validated the Waku v2 protocol, running Docker carries heavy operational costs for lightweight sandboxes and developer machines:

1. **Docker requirement:** sandboxes, CI runners, and constrained containers often lack a Docker daemon.
2. **Architecture penalty:** `wakuorg/nwaku` publishes `linux/amd64` images only (requiring QEMU emulation on Apple Silicon / ARM64).
3. **Sidecar lifecycle & REST caveats:** one container per agent, unauthenticated loopback REST, destructive 50-slot receive cache, `Connection: close` polling churn, ~62 s cold mesh warmup, and idle half-open TCP lockouts on the relay.

`AGENTS.md` prohibits silently substituting a centralized broker for the validated decentralized transport. To eliminate Docker honestly, AgentNet needs a genuine `libp2p` Waku v2 implementation in pure Rust.

## Decision

Add an opt-in pure-Rust `waku-native` transport backend (`crates/transport/src/waku_native/`) using `rust-libp2p` (`0.57.1`) and `prost` (`0.14.6`), implementing the Waku v2 wire protocols directly inside the `agentnet` binary:

1. **Transport & Security:** TCP + Noise XX + Yamux + Identify (`/ipfs/id/1.0.0`) + active Ping (`/ipfs/ping/1.0.0`).
   - In **private mode**, `libp2p-dns` is omitted from the transport stack entirely (zero DNS egress by construction).
   - **Preventive peer allowlist:** `libp2p-allow-block-list` (`AllowedPeers`) enforces the peer allowlist at connection admission rather than detective 15 s REST polling.
   - **Active Ping keepalive:** 15 s interval / 10 s timeout detects silently dropped / half-open TCP paths without needing a relay-side `ss -K` watchdog.
2. **Waku Metadata (`/vac/waku/metadata/1.0.0`):** varint length-prefixed protobuf handshake verifying matching `cluster_id` and `shard` (disconnects mismatched peers).
3. **Waku Relay (`/vac/waku/relay/2.0.0`):** `libp2p-gossipsub` v1.1 with exact protocol ID `/vac/waku/relay/2.0.0`, `MessageAuthenticity::Anonymous`, `ValidationMode::Anonymous`, `flood_publish(true)`, and `SHA-256(message.data)` deduplication IDs matching `nwaku`'s `waku_relay/message_id.nim`.
4. **Waku Store v3 (`/vac/waku/store-query/3.0.0`):** varint length-prefixed protobuf request/response queries with `waku_message_hash` verification and cursor pagination.
5. **Standalone Pure-Rust Relay (`NativeWakuRelay` / `agentnet relay serve`):** listens on TCP, relays GossipSub frames, validates Metadata, archives non-ephemeral messages in bundled SQLite (or `:memory:` via `--memory-only`) with retention and clock-skew enforcement, and serves Store v3 queries.
6. **Configuration & CLI:**
   - `[network] backend = "logos_rest" | "native"` (defaults to `"logos_rest"` for full backwards compatibility).
   - `agentnet init --native --peer <MULTIADDR>` and `agentnet identity import --native ...`.
   - `agentnet relay serve [--listen ...] [--relay-dir ... | --memory-only] [--allow-peer ...]` and `agentnet relay keygen`.

## Quickstart (Zero Docker / Lightweight Sandbox)

```sh
# Terminal 1: start the pure-Rust Waku v2 relay + Store v3 (in-memory or persistent --relay-dir)
agentnet relay serve --listen /ip4/127.0.0.1/tcp/60000 --memory-only
# -> prints: /ip4/127.0.0.1/tcp/60000/p2p/16Uiu2HAm...

# Terminal 2: initialize and run two agents with zero Docker
RELAY=/ip4/127.0.0.1/tcp/60000/p2p/<PEER_ID_FROM_ABOVE>
agentnet --data-dir /tmp/an-a init --native --peer "$RELAY"
agentnet --data-dir /tmp/an-b init --native --peer "$RELAY"
agentnet --data-dir /tmp/an-a serve &
agentnet --data-dir /tmp/an-b serve &
agentnet --data-dir /tmp/an-a doctor --ready --wait 30
agentnet --data-dir /tmp/an-b doctor --ready --wait 30
```

## Verification & Current Status

- **Tested (zero Docker, macOS arm64):**
  - Protobuf wire encoding/decoding (`WakuMessage`, `WakuMetadataMessage`, `StoreQueryRequest`/`Response`, varint length-prefix bounds).
  - SQLite Store v3 insertion, clock-skew rejection, ephemeral skip, cursor pagination, and age/capacity pruning.
  - Native transport integration tests: live A↔B messaging, self-delivery echo, offline Store v3 paginated recovery, relay restart with persistent SQLite Store + automatic client redial, preventive allowlist blocking an unauthorized peer, cluster mismatch rejection, oversize frame rejection.
  - Full zero-Docker end-to-end CLI + Daemon + OpenPGP E2E test (`crates/cli/tests/native_zero_docker.rs`): `agentnet relay serve` + two `agentnet serve` daemons (`backend = "native"`) + `doctor --ready` + contact verification + encrypted A↔B messaging + authenticated delivery receipts + offline recovery + `agentnet stop`.
  - Architecture test (`crates/core/tests/architecture.rs`) and workspace `unsafe_code = "forbid"`.
- **UNTESTED (explicitly not claimed):**
  - Live wire interoperability between `NativeWakuTransport` / `NativeWakuRelay` and the Dockerized Nim `wakuorg/nwaku` v0.39.2 binary (wire formats were derived directly from `upstream/logos-delivery-v0.39.2`, but live cross-implementation testing has not been run yet).
  - WebSocket (`ws`/`wss`) transport dialing in `waku-native` (current build wires TCP + Noise + Yamux; DNS is enabled in public mode only).
  - Cross-machine WAN/NAT/Tailscale runs and high-throughput load testing.
  - `cargo-deny` CI run on the new `libp2p`/`prost` dependency graph (metadata license and banned-crate check passed locally).
