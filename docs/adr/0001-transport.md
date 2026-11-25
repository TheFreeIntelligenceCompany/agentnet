# ADR 0001 — Transport: REST adapter to a sidecar Logos Delivery node

Status: accepted (2026-11-25). Owner: lead agent.

## Context

`goal.md` A1 asks for a comparison of three paths before committing:
(1) Rust FFI bindings to native Logos Delivery, (2) libchat on top of Delivery,
(3) a Rust adapter talking to a separately running node over its local API.
It prefers native integration "if reliable" and the daemon adapter "if native
packaging/ABI is a blocker". Raw rust-libp2p was not evaluated (it needs
separate approval and is not Waku-compatible by assumption).

All measurements below are from one host: containers on a private docker bridge
inside a colima VM on an arm64 Mac. Nothing here is a cross-machine or NAT test.

## Evidence

### Path 3 — sidecar node over REST (`docs/spike/notes-daemon-rest.md`, `results/a1-daemon/`, `results/b-transport/`)

* Pinned image `wakuorg/nwaku@sha256:cb4d14a2…` (v0.39.2, linux/amd64 only;
  runs under qemu here). No v0.40.0 image was pullable from Docker Hub.
* Private cluster 66, RLN off, every discovery mechanism off, static peers:
  relay publish/receive, Store v3 recovery, filter and lightpush all worked.
* Rust probe: 100/100 messages each way, 0 duplicates; 20/20 recovered through
  Store after the recipient node was down (lead re-ran:
  `results/a1-daemon/rust-probe-all-465aad5.json`).
* With `--dns-addrs-name-server=127.0.0.1` a 100 s capture showed 0 packets
  outside the private subnet; with the default, every node queried 1.1.1.1
  every 5 s.
* Weak points, all measured: REST receive is a destructive 50-slot in-memory
  cache with no hashes; a client that loses its only peer never redials under
  the zero-egress DNS setting; after a relay restart live delivery stayed
  degraded for about 9 minutes although peers were connected (cause unknown);
  unsubscribing a topic drops the node from the mesh; several misleading error
  codes; Store silently refuses messages whose timestamp is more than 20 s off;
  one `--storenode`, no failover; the REST API has no authentication.

### Path 1 — native FFI bindings (`docs/spike/notes-ffi-bindings.md`, `results/a1-ffi/`, `spike/transport-ffi/`)

* Canonical repo `logos-messaging/logos-delivery-rust-bindings` @ `d60fcfd`;
  the new async crate `logos-delivery 0.1.0` is not on crates.io; the legacy
  `waku-bindings 0.6.0` on crates.io no longer resolves (yanked dependency).
  The bindings pin native v0.39.1.
* It builds on linux/arm64 only with a workaround: nimble downloads an x86-64
  Nim on aarch64, which segfaults under emulation; building Nim 2.2.6 from
  source fixes it. About 2 h wall on this VM. Library 295 MB unstripped / 57 MB
  stripped; needs `libgomp1`, `cmake`.
* Two nodes, private bridge: 100/100 each way, 0 duplicates, p50 ≈ 6 ms (lead
  re-ran from the kept image: `results/a1-ffi/run-lead-verify-2node/`).
* Problems: ≈ 24.5 MB RSS and 4 fds leaked per in-process start/stop cycle;
  library logs to **stdout** at TRACE unless built with `LOG_LEVEL=ERROR`
  (would corrupt MCP stdio framing); `connect()` returned `Ok` on a failed dial;
  no `catch_unwind` in callbacks; no application-level backpressure; store,
  filter and lightpush not reachable from the new crate's stable tier.
* UNTESTED on this path: Store/offline recovery, reconnect, payload limits,
  packet capture, linux/amd64, macOS native.

### Path 2 — libchat

Rejected as the encryption/identity layer (ADR 0002); as a transport it only
wraps path 1 with a hardcoded public preset.

## Decision

Use path 3: `LogosRestTransport` (`crates/transport/src/logos_rest/`) talking
to a user-run Logos Delivery node bound to loopback or a private interface.
Everything above the `Transport` trait is independent of this choice.

The adapter compensates for the measured weaknesses: fast polling plus periodic
Store catch-up; locally computed Waku hashes for dedupe; never unsubscribing;
automatic redial of allowlisted static peers; a peer-allowlist audit that fails
closed in private mode; sender-side retry until an authenticated receipt.

## Consequences

* AgentNet is not a single binary: it requires a sidecar node (a container
  today; amd64-only upstream image). This is a disclosed native dependency.
* Recovery of missed messages is bounded by the relay's Store retention, the
  message TTL, and clock agreement within 20 s.
* The node's REST API is unauthenticated: any local process that can reach it
  can publish and read ciphertext. It must stay on loopback/private interfaces.
* Private isolation rests partly on operator-set node flags and firewalling;
  AgentNet enforces what it can observe (peer allowlist) and refuses otherwise.
* Native embedding stays a future option behind the same trait. Minimum bar
  before adopting it: a published crate or stable pin, the arm64 build fixed
  upstream, stdout logging off by default, the lifecycle leak understood, Store
  access from the stable API, and a packet capture proving no public contact.

## Not validated

Cross-machine and NAT operation, Tailscale, any public network, native
linux/amd64 for either path, sustained operation over hours.
