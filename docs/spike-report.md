# AgentNet Phase A spike report

Status: evidence-based report written by a contributor for the owner to fact-check. Date of the work: 2026-11-25.
Rule used throughout (goal.md section 7): a claim either cites a file in this repository, cites an upstream source, or carries an
explicit **UNTESTED** label. A README is never taken as proof that something works. Nothing in this report is marked as passing unless a log in the
repository shows it passing; where the lead re-ran something, the git commit message says so and this report repeats only what the commit says.

Sources of numbers: the notes `docs/spike/notes-*.md` (each point back to raw files in `results/`), the raw files themselves, and runs made while writing this report
(`results/audit/`). Where a note and a raw file disagree this report says so in section 15.

**Headline limits, stated first.**

* **Every network experiment was single-host.** One macOS arm64 laptop; the Logos Delivery nodes are containers on a colima Linux VM; the node image is
  linux/amd64 and ran under qemu emulation. No second physical host and no public network was involved; NAT and WireGuard were only simulated on one host (`docs/network-simulations.md`). **Cross-machine, NAT and Tailscale are UNTESTED.**
* The host was heavily shared while the spikes ran (load average 259 during the crypto spike, `docs/spike/notes-e2e-crypto.md` header; 497 while this report's builds ran).
  All latency and CPU numbers are upper bounds and noisy.
* The cryptographic composition is not independently reviewed (ADR 0002).

## 1. Scope and method

goal.md Phase A asks for: a build and integration audit of three transport paths (A1), network experiments (A2), an MCP spike (A3), and decision gates (A4).
Phase B (the MVP in `crates/`) was also built; its test results are cited where they bear on a Phase A question.

Method: each question was answered by a disposable spike crate under `spike/` (standalone workspaces with committed `Cargo.lock`; excluded from the main workspace, `Cargo.toml`
`exclude = ["spike", "upstream"]`), scripts under `spike/relay/scripts/`, and raw outputs in `results/`. Upstream sources were cloned (gitignored) under `upstream/`.
Synthetic messages and disposable keys only (`spike/relay/.env` holds disposable node keys, committed on purpose).

| Spike | Directory | Notes | Raw results |
|---|---|---|---|
| A1 path (3): REST adapter to a separate node | `spike/relay`, `spike/transport-rest` | `docs/spike/notes-daemon-rest.md` | `results/a1-daemon/` |
| A1 path (1): native FFI bindings | `spike/transport-ffi` | `docs/spike/notes-ffi-bindings.md` | `results/a1-ffi/` (section 5) |
| A1 path (2): libchat | `spike/libchat-eval` | `docs/spike/notes-libchat-and-crypto.md` | `results/a1-libchat/` |
| A2 encrypted exchange over the local relay | `spike/e2e-crypto` | `docs/spike/notes-e2e-crypto.md` | `results/a2-e2e-crypto/` |
| A3 MCP | `spike/mcp-spike` | `docs/spike/notes-mcp.md` | `results/a3-mcp/` |
| Phase B tests | `crates/*/tests` | `docs/architecture.md` | `results/b-core`, `b-daemon`, `b-mcp`, `b-transport` |
| This report's own runs | `results/audit/` | this document | `results/audit/*` |

## 2. Environment

| Item | Value | Source |
|---|---|---|
| Host | macOS 26.6.2 (Darwin 25.6.0, kernel `RELEASE_ARM64_T6000`), arm64; exact machine model not recorded | `sw_vers`/`uname` at report time; `results/a1-daemon/toolchain.txt` |
| Rust toolchain on host | `rustc 1.92.0 (ded5c06cf 2025-12-08)`, `cargo 1.92.0 (344c4567c 2025-10-21)` | `results/a1-daemon/toolchain.txt`, `results/a3-mcp/env.txt`, `results/a1-libchat/toolchain.txt` |
| Docker | client 29.8.1, server 29.5.2; Compose plugin 5.6.0 reported by `docker version`, but `docker compose` failed in the spike (standalone `docker-compose` used) | `results/a1-daemon/toolchain.txt`, `docs/spike/notes-daemon-rest.md` s3 item 13 |
| Container VM | colima 0.10.3, runtime docker, Ubuntu 24.04.4 LTS aarch64, 6 CPUs, 10.4 GB (`mem=10403803136`) | `results/a1-daemon/toolchain.txt` |
| Node image | `wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73` (v0.39.2), linux/amd64, run under qemu on the arm64 VM | `spike/relay/docker-compose.yml`, `results/a1-daemon/pull_v0.39.2.txt` |
| Linux arm64 build container | `rust:1.92-bookworm` (rustc 1.92.0, gcc 12.2.0, **no cmake installed**) | `results/audit/linux-arm64-build.log` |
| Native FFI audit container | Debian 12.13 aarch64, gcc/g++ 12.2.0, cmake 3.25.1, GNU Make 4.3, git 2.39.5, Nim 2.2.6 (built natively), nimble 0.26.0, kernel 6.8.0-117 | `results/a1-ffi/toolchain-versions.log` |
| libchat build toolchain | rustc 1.100.0 (isolated `RUSTUP_HOME`; host 1.92 cannot build it) | `docs/spike/notes-libchat-and-crypto.md` s1.2 |
| Linux x86_64 (native) | **UNTESTED** (no x86_64 Linux host; goal.md asks to build there first) | - |

## 3. Upstream versions, pins, licences, maintenance (checked 2026-11-25)

"Pinned" means the exact thing this repository depends on or evaluated. Dates are commit or publish dates as recorded in the cited file.

| Component | Pinned / evaluated | Latest seen | Licence | Maintenance signal | Source |
|---|---|---|---|---|---|
| logos-delivery (Nim reference node; formerly nwaku, wakunode2) | tag `v0.39.2` = `fd07b72c370a6b39c69870c087cc0d928d485327` (2026-10-13); image digest above | master `88bd0e5c...` (2026-11-24); release `v0.40.0` (2026-11-13); pre-releases `v0.41.0-rc.0/1/2` (rc.2 2026-11-24); rolling `nightly` | `LICENSE-MIT` + `LICENSE-APACHE` (nimble: "MIT or Apache License 2.0"; GitHub reports Apache-2.0). Licences of vendored Nim dependencies **not audited** | Very active (last push 2026-11-25T18:11Z), not archived. REST/messaging API still moving (`/messaging/v1/events/send/{requestId}` -> `{messageHash}` between v0.39.2 and master) | `docs/spike/notes-daemon-rest.md` s1; `results/a1-ffi/audit-meta.log` |
| Docker Hub `wakuorg/nwaku` | `v0.39.2` | tags only up to `v0.39.2`; `latest` = nightly (`nightly-1-g39eda310`, 2026-11-09); **no v0.40.0** tag; **amd64 only** | image carries the node's licences | lags upstream releases; `harbor.status.im` and `ghcr.io/logos-messaging/logos-delivery` refuse anonymous access | `results/a1-daemon/manifest_*.json`, `images.txt` |
| logos-delivery-rust-bindings | `d60fcfd40f2b860000c4df8db4f2f95a6c6f1fad` (2026-11-20, "switch to the new logos nix cache public key (#136)"); workspace members `waku-bindings`, `waku-sys`, `logos-delivery`, `examples/basic`; file `LOGOS_DELIVERY_REV` = `0f2188c09779cc84116db344bbb43ccfe6a27c35` (logos-delivery commit of 2026-10-06, "docs: changelog for v0.39.1") | master at audit time was 188 commits ahead of that pinned rev | `LICENSE-MIT` + `LICENSE-APACHE` in the clone; crates.io metadata MIT OR Apache-2.0 | recent commits and green CI, but `release.yml` failed on 2026-11-24 and 2026-11-20; open issues #128/#130/#131 (prebuilt libwaku artifacts, hermetic Nix builds, idiomatic generated API) | `results/a1-ffi/audit-meta.log`, `spike/transport-ffi/Cargo.toml`, `upstream/logos-delivery-rust-bindings/LOGOS_DELIVERY_REV` |
| crates.io `waku-bindings` / `waku-sys` | 0.6.0 (2024-02-19) | same | MIT OR Apache-2.0 | stale since 2024-02; **does not resolve today**: `core2 0.4.0` (via `multihash 0.17` <- `multiaddr 0.17`) is yanked | `results/a1-ffi/waku-bindings-0.6.0-resolve.log` |
| crates.io `logos-delivery` (the new bindings crate) | **not published** ("crate `logos-delivery` does not exist"); used by git rev only | - | - | - | `results/a1-ffi/audit-meta.log` |
| libchat (renamed logos-chat) | `c7c0c1ba50566ecbcbef12958ee9795bdb22db09` (2026-11-25, "fix(group-v3): accept a Welcome after being removed from the group (#370)") | same | MIT OR Apache-2.0 | 214 commits, 45 in the last 30 days, 14 contributors; **no tags, no releases, not on crates.io**; README "pre-1.0, ... breaking changes expected"; no audit found; needs rustc 1.95 (`de-mls` 4.0.0) | `docs/spike/notes-libchat-and-crypto.md` s1.1; `results/a1-libchat/gh-repo.json` |
| rmcp (official Rust MCP SDK) | `=3.11.0` (2026-11-17, MSRV 1.88, not yanked) | main `d6c3e2c` (2026-11-25) has 11 small post-release diffs | Apache-2.0 | very active; open issues that touch us listed in `docs/spike/notes-mcp.md` s5 item 10 | `results/audit/crates-io-versions.txt`; `docs/spike/notes-mcp.md` s2 |
| MCP specification | 2026-07-28 (stable; the `latest` URL redirects to it); spec repo `2bbace5` (2026-11-24) | `draft` accumulating | spec licence **not checked** | tested versions 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28 (section 9) | `docs/spike/notes-mcp.md` s1 |
| hpke (rozbb) | `=0.15.1` (2026-10-28, MSRV 1.87) | same | MIT/Apache-2.0 | README: Cloudflare internal review of an old version, "not yet being formally audited" | `results/audit/crates-io-versions.txt`; notes-libchat s2 |
| ed25519-dalek | 3.0.0 (2026-07-06, MSRV 1.85) | same | BSD-3-Clause | - | `results/audit/crates-io-versions.txt` |
| age | 0.12.1 (2026-07-14, MSRV 1.74) | same | MIT OR Apache-2.0 | no audit found (UNVERIFIED) | same |
| rusqlite / libsqlite3-sys | 0.42.0 (2026-11-11, **declares MSRV 1.89.0**) / 0.40.0 (MSRV 1.88.0), bundled SQLite C source | same | MIT | - | same; `cargo metadata` of `Cargo.lock` |
| vodozemac (documented upgrade path) | 0.11.2 (2026-11-05, MSRV 1.89, Least Authority audit per README) | same | Apache-2.0 | compiled only, **never run** | notes-libchat s2.2, s2.7 |
| Tailscale | not used (UNTESTED) | - | - | - | - |

## 4. A1: the three transport paths compared

| | (1) Official Rust bindings to native liblogosdelivery | (2) libchat on Delivery | (3) Rust adapter to a separate node over REST (**chosen**) |
|---|---|---|---|
| What was built | `spike/transport-ffi` against `liblogosdelivery.so` built from source on Linux arm64 | `spike/libchat-eval` (in-process hub transport, no sockets) | `spike/relay` topology + `spike/transport-rest` probe; then `crates/transport` `LogosRestTransport` |
| Builds on macOS arm64 | crate `cargo check` ok (`results/a1-ffi/macos-cargo-check.log`, 4m13s); **the native library was not built on macOS** | libchat does not build on rustc 1.92 (needs 1.95); builds and passes tests on 1.100.0 | yes (host build and tests, `results/b-daemon/workspace-tests.log`) |
| Builds on Linux arm64 | yes, only with a native-Nim workaround (section 5) | not attempted | see section 4.1 and `docs/compatibility-matrix.md` |
| Builds on Linux x86_64 | **UNTESTED** | **UNTESTED** | **UNTESTED** |
| Runtime shape | one process; `liblogosdelivery.so` 295-304 MB unstripped, ~57 MB stripped | library only | AgentNet process + node sidecar (94.7 MB image, 44-53 MiB RSS idle per node) |
| Persistence/identity | library gives libp2p identity only | **MLS state in memory only**; restart loses conversations (T6 FAIL) | application identity is AgentNet's (`crates/core`) |
| Private-network support | config knobs exist (spike used cluster 7777, discovery off); packet-level public contact **not captured** (config-level only) | embedded transport hardcodes the public `logos.test` preset; bootstrap via hosted registry | all discovery flags off, static peers, `--dns-addrs-name-server=127.0.0.1`; egress capture clean (section 7 row 3) |
| Verdict | viable later; blocked today by packaging (crate not on crates.io, no prebuilt artifacts, about 2 h build with an arm64 Nim workaround), TRACE logging on stdout, a leak of about 24.5 MB + 4 fds per in-process start/stop, and no Store/Filter/Light Push in the stable API | no-go for MVP | used |

### 4.1 Path (3) in detail

Evidence: `docs/spike/notes-daemon-rest.md`, `results/a1-daemon/`. Working topology: R1 service node (relay + Store on SQLite + Filter + Light Push), NA and NB clients with `--staticnode` R1
only, private cluster id 66, one autoshard `/waku/2/rs/66/0`, all discovery off, no RLN. **Everything worked on this single host without RLN** for relay, Store, Filter and Light Push (E1-E4, E9).
Full REST route inventory with source file names is `docs/spike/notes-daemon-rest.md` s1.1; the flag inventory is s1.2.

Facts that shaped the adapter (all from the note, each with raw evidence there): the REST receive model is a **destructive-read in-memory cache of 50 messages** shared across topics; relay REST
responses have **no message hash** (the Waku hash `sha256(pubsubTopic || payload || contentTopic || meta || timestamp_be64)` was recomputed and matched Store's for 200/200 messages,
`results/a1-daemon/rust-probe-basic-45bea17.json`); the publisher also receives its own messages; Store is the recovery path (24 h query cap, page size max 100).

### 4.2 Path (2) libchat (summary)

No-go for the MVP. Reasons with evidence: MLS group state and key-package private keys are **memory-only** (`core/conversations/src/inbox_v2/mls_provider.rs:16-26` at the pinned commit; upstream issue #112 open);
in-process tests after restart **fail** (T6), a recipient restarting during an invite fails (T7b), and one injected corrupted ciphertext makes the genuine message undecryptable (T3b)
(`results/a1-libchat/spike-run-release.txt`); needs rustc >= 1.95 (host has 1.92); unpublished, untagged, unaudited, pre-1.0; the bundled bootstrap is a hosted HTTP key-package registry and the embedded transport
hardcodes the public `logos.test` preset. In debug builds a tampered ciphertext panics the receiver's worker thread (`openmls-0.8.1/src/framing/private_message_in.rs:136`). Details: `docs/spike/notes-libchat-and-crypto.md` s1.
Not evaluated (and recorded as such there): real registry and account-log servers, update-commit/key rotation, multi-device, concurrent writers, group membership beyond reading the code.

## 5. Native FFI path (1)

Source: `docs/spike/notes-ffi-bindings.md` (the FFI audit's own notes, committed by the lead), `results/a1-ffi/`, `spike/transport-ffi/`; decision: [ADR 0001](adr/0001-transport.md). All runs: linux/arm64 containers in the colima VM (no qemu for the final result), one host. I summarise those notes; where I give a number it is theirs.

* **Bindings.** Canonical repo `logos-messaging/logos-delivery-rust-bindings` @ `d60fcfd` (see section 3). The new async crate `logos-delivery 0.1.0` is **not on crates.io** (git rev only); the legacy `waku-bindings 0.6.0` on crates.io **does not resolve** (yanked `core2 0.4.0`, `results/a1-ffi/waku-bindings-0.6.0-resolve.log`). The bindings pin native logos-delivery v0.39.1 (`LOGOS_DELIVERY_REV` `0f2188c0`).
* **Build.** It builds on linux/arm64 **only with a workaround**: nimble 0.26.0 downloads an x86-64 Nim on aarch64 which segfaults under emulation (`lib-build-4-FAILED-nimscript-segv.log`); building Nim 2.2.6 natively from source fixes it (attempts 1, 2 and 4 failed, 5 and 6 succeeded). Wall time from nothing to a runnable image about **2 h** on this VM (native Nim 14 m 15 s contended, `make liblogosdelivery` 26 m 19 s, `lib` stage 58 m 24 s, plus Docker layer-commit overhead); the CPU-bound part is about 45-50 min (`notes-ffi-bindings.md` s6.2). Needs `cmake` and `libgomp1`. Library 295,115,696 B unstripped / 57,006,712 B stripped (an earlier TRACE-log build 304,304,536 B); `ffi-spike` release binary 1,978,352 B. **macOS arm64 native library build and linux/amd64: UNTESTED.**
* **Two nodes** (private bridge, cluster 7777, no preset, discovery off, `nat=none`, static dial; `results/a1-ffi/run-final-2node-100/`): **100/100 each direction, 0 duplicates, 0 missing**; latency p50 6.4 ms, p99 132.2 ms (A) and 110.8 ms (B); a 500-message burst each way delivered 500/500. The lead re-ran this from the kept image: `results/a1-ffi/run-lead-verify-2node/`. Each node receives its own messages (filter by sender). Same host, **n = 100 per direction, one run**. (The earlier dev runs `run-dev1`/`run-dev2` are superseded by these.)
* **Lifecycle:** 20 start/stop cycles in one process: no crash, but **about 24.5 MB RSS and 4 file descriptors leaked per cycle** (RSS 77.6 -> 544.0 MB, fds 21 -> 97; `results/a1-ffi/run-final-lifecycle/`). Root cause not found. The only safe lifecycle today is one node per process.
* **Logging:** the library logs to **stdout at TRACE** unless built with `LOG_LEVEL=ERROR` (compile-time), which would corrupt MCP stdio framing.
* **API coverage:** Store, Filter and Light Push are **not reachable from the new crate's stable tier**; `connect()` returned `Ok` on a failed dial; no `catch_unwind` in callbacks; no application-level backpressure (with a slow consumer 16-29 of 300 messages reached the application). The useful kernel API is "may change at any time" upstream.
* **Not run on this path (UNTESTED):** Store/offline recovery, reconnect, payload limits, packet capture of public contact (config-level only), linux/amd64, macOS native.

Consequence: the FFI path is **technically reachable on Linux arm64 but not suitable as the MVP's primary path**; the REST adapter keeps native embedding open behind the same `Transport` trait (ADR 0001 lists the bar for adopting it).

## 6. libchat and the cryptographic fallback

* libchat: section 4.2.
* Chosen construction (ADR 0002): RFC 9180 HPKE base mode (X25519/HKDF-SHA256/ChaCha20-Poly1305, `hpke =0.15.1`) with an inner Ed25519 signature (`verify_strict`) over a domain-separated envelope that names the recipient;
  independent signing and agreement keys bound by a self-signed contact record; the address is the signing key. Spec: `docs/protocol.md`.
* **Tension with goal.md section 1 ("do not ... invent a cryptographic protocol") and A4 ("evaluate an established audited messaging library/protocol").** The construction is a composition of reviewed primitives, documented in an ADR (not silent), but it is an application-level protocol
  and neither `hpke` nor the composition has an independent audit. ADR 0002 states this ("A cryptographic review is required before any production use"). The audited alternative that was evaluated, `vodozemac` (Olm), was **compiled only, never run** (`results/a1-libchat/fallback-probe-build.txt`, 33.5 s on rustc 1.92). The owner should decide explicitly whether the composition is acceptable for the MVP.
* Properties that were tested (spike and `crates/core` tests): wrong recipient, forged sender, surreptitious forwarding, every single-bit flip of a 564-byte frame, every truncation, replay, expiry, skew, unknown versions
  (`results/a2-e2e-crypto/`, `results/b-core/crypto-tests.log`). Properties not provided: forward secrecy, post-compromise security, deniability, revocation (`docs/protocol.md` s7).

## 7. A2: network experiments (every row of the goal.md table)

Status vocabulary: **DEMONSTRATED-LOCAL** = shown on the single-host container topology; **PARTIAL** = some of the required evidence exists; **UNTESTED** = not run. None of the rows is "DEMONSTRATED" in the goal.md sense of real separate hosts.
Topology for all rows unless stated: `spike/relay` (R1 service node 172.28.66.10, NA .21, NB .22 on a Docker bridge in a colima VM, amd64 under qemu), cluster 66, no RLN.

| # | Experiment (goal.md) | Status | What exactly was shown | Numbers (sample, topology) | Evidence |
|---|---|---|---|---|---|
| 1 | Basic messaging | **DEMONSTRATED-LOCAL** | A->B and B->A with unique ids and payload integrity over the real relay: at transport level (E1/E11), with the HPKE+Ed25519 envelope (A2 test 1), and with two real `agentnet serve` processes via CLI and MCP (relay e2e test) | Transport probe: 100/100 each direction, 0 dups, 0 integrity failures. Crypto spike: 100/100 each way, wire dups 0, app dups 0, integrity failures 0. CLI e2e: n = 2 messages (1 via CLI, 1 via MCP), both `delivered` | `results/a1-daemon/rust-probe-basic-*.json`; `results/a2-e2e-crypto/roundtrip-1795640646489.json`; `results/b-daemon/relay-e2e.log` |
| 2 | Cross-machine / NAT | **UNTESTED** | Nothing. No second host, no NAT. The "outbound-only client, no public client listener" property is a design property: clients dial the service node (`--staticnode`) and need no inbound port; this was not verified from a separate network. Simulated only: two docker LANs behind iptables MASQUERADE gateways on one host (`docs/network-simulations.md`, `results/network-sim/nat/20261126T041425Z`, `20261126T050510Z`): outbound-only clients with no inbound path exchanged 20 messages each way with receipts; R saw them at the gateways' addresses. This is not a separate-host or real-NAT test. | - | Reproduce: two hosts, service node on a reachable address (`docs/relay-setup.md` sections 3-4, 8), client hosts behind NAT with no inbound rule, `agentnet doctor` on both, exchange a message, capture on the client with `tcpdump` to confirm no inbound listener use and no public destinations |
| 3 | Private network | **PARTIAL** (strong locally) | Static peer config, all discovery off, no `--entry-node`, `--dns-addrs-name-server=127.0.0.1`: capture on the Docker bridge, whole stack restarted inside the capture. With the default DNS server every node queried `one.one.one.one` at 1.1.1.1 every 5 s (the only external destination). With `127.0.0.1`: 1175 packets in 100 s, 0 with an endpoint outside 172.28.66.0/24. An `internal: true` network works only with a local DNS stub. AgentNet side: config fails closed, runtime peer audit refuses traffic on violation (live: fails closed with a wrong allowlist). "No public fallback" by absence of any code path that adds peers | capture 150 s (default DNS) and 100 s (localhost DNS), three nodes; audit test n = 1 live; **no packet capture was taken during the relay-failure runs** and none of the AgentNet daemon's own sockets was captured | `results/a1-daemon/e7a-*.txt`, `e7b-*.txt`, `egress-*.egress.txt`, `egress-*.pcap`, `e8a-*`, `e8b-*`; `results/b-transport/relay-tests.log` (`isolation_audit_passes_with_right_allowlist_and_fails_closed_with_wrong_one`) |
| 4 | Tailscale | **UNTESTED** | Nothing run. Steps: `docs/relay-setup.md` section 10 (marked UNTESTED). One hazard found by reading the printed snippet: `--rest-address=0.0.0.0` with host networking would expose the REST API on the tailnet. Not Tailscale: a kernel-WireGuard overlay between containers on one host with a firewall admitting tcp/60000 only on wg0 (`results/network-sim/wireguard/20261126T033513Z`, `20261126T034919Z`; 2 runs, 35/35 PASS) showed only WireGuard UDP on the underlay and no frames for a key-less intruder (control with the rule removed: it saw ciphertext frames). No coordination server, ACLs or DERP were involved. | - | - |
| 5 | Offline recipient | **PARTIAL** | B stopped, A sent 20, B restarted, recovered 20/20 from Store without duplicate processing; second process with the persisted dedupe: 0 accepted, 20 replays. Store unavailable: node returns 500 after 5 s; adapter reports `HistoryUnavailable` and recovers when the node returns (mock and live). Expired history: node returns 200 with an empty list; engine marks the sender's row `expired` (mock). **Not run: an end-to-end AgentNet daemon recovery against the real relay with a stopped recipient daemon, and expiry against the real Store with AgentNet** | n = 20 offline messages, 1 relay. Store query 3 pages, 21 entries, 48 ms. Node restart: REST healthy 1.3 s, connected 1.5 s (A1) / 4.7 s (A2) | `results/a1-daemon/rust-probe-offline-45d196c.json`; `results/a2-e2e-crypto/persistence-1795640646489.json`; `results/a1-daemon/e5-r1-down.txt`, `e6-retention.txt`; `results/b-core/engine-tests.log` (`offline_recipient_recovers_20_via_history`, `history_past_retention_is_not_recovered_and_sender_expires`) |
| 6 | Publisher / relay failures | **PARTIAL** | Relay (R1) stopped and restarted: client reconnect needs an explicit dial with the required DNS setting; adapter redial restores the connection in 11.4 s; client node restart ready in 3.4 s; **live mesh stayed broken about 9 minutes after the relay restart** (cause not found). Retries with backoff, duplicates, reordering and crash points are covered deterministically on a mock network (random schedules converge exactly once). Publisher crash between send and publish: mock only. **Not done: injected packet loss/connection drops (tc/netem), killing the publisher daemon mid-send against the real relay** | relay restart: 1 run measured 11.4 s (4 redials); client restart: 3.4 s (0 redials); mesh gap: 1 observation (~9 min); first disruptive run failed after 261 s before the redial was added | `results/b-transport/relay-disruptive-tests.log`; `results/a1-daemon/e5-r1-down.txt`; `results/b-core/engine-tests.log` (`random_schedules_converge_exactly_once`, `lost_publish_retries_with_backoff_bounds_then_delivers`, `duplicates_reordering_and_lost_ack`, `crash_*`) |
| 7 | Identity persistence | **DEMONSTRATED-LOCAL** | Restart: same address; migration by copying only `identity.json` to another directory: same address, 20/20 decrypted; wrong permissions refused; second process on the same data dir refused (exclusive lock). `agentnet` daemon: crash recovery reacquires the lock and keeps state. Age-encrypted export/import: unit test. **Competing instances on different data directories with the same identity are not detected** (T23) | n = 20 messages; one migration | `results/a2-e2e-crypto/persistence-1795640646489.json`; `results/b-daemon/daemon-tests.log` (`crash_recovery_reacquires_the_lock_and_keeps_state`, `lock_exclusivity_and_graceful_shutdown_cleanup`); `results/b-core/crypto-tests.log` (`encrypted_export_import`) |
| 8 | Security | **DEMONSTRATED-LOCAL** (relay-level IP/subscription metadata UNTESTED) | Wrong recipient cannot open (10/10 failures at C, same bucket); forged sender -> `bad_signature`; re-sealed to a third party -> `wrong_recipient`; every single-bit flip (4512 flips on 564 B) and every truncation rejected; 1000 random frames and 1000 authenticated garbage plaintexts: 0 panics; replay: second delivery rejected, also after reload from disk. Relay-visible fields enumerated from the Store output (section 8 of `notes-e2e-crypto.md`). **Not run: observation of subscriber/publisher peer IDs and IPs at libp2p level; a malicious relay that drops, delays or reorders** | n = 10 (wrong recipient), 1 (forgery), 4512 flips, 564 truncations | `results/a2-e2e-crypto/{wrong-recipient,forgery,tamper,replay,metadata}-1795640646489.json` |
| 9 | Payload boundaries | **DEMONSTRATED-LOCAL** | Node limit 153,600 B: largest accepted payload 153,523 B for a 26-char topic (formula `153600 - (len(topic)+51)`), just-over gives the misleading `NoPeersToPublish`, clearly over gives `Message size exceeded`; max AgentNet body 130,718 B with pure power-of-two padding / 153,117 B with the cap rule, over rejected locally; malformed frames, truncation, extension; skew +-120 s boundaries; expired; Unicode (ZWJ emoji, RTL, U+202E, NUL, BOM) byte-exact; unknown envelope `v`, frame version, suite rejected | 20 expiry/skew/version cases, 1 relay | `results/a2-e2e-crypto/boundaries-1795640646489.json`, `expiry-1795640646489.json`; `results/a1-daemon/e3-probes.json` |
| 10 | Load (1/10/100 logical clients) | **PARTIAL** | 1, 10 and 100 **logical** clients in **one process** over the two client nodes, 10 messages per client, 16 buckets, trial decryption by every client of a bucket. 100% delivered at 1 and 10 clients and at 100 clients with a 50 ms poll; loss appears with slower polling or higher publish concurrency because of the 50-slot destructive node cache. Bounded queue/back-pressure tested on a mock transport. **Not run: separate processes per client, memory/CPU of the `agentnet` daemon under load, hostile flood** | table in section 8.4 | `results/a2-e2e-crypto/load-1795640646489.json`, `load-1795641030155.json`, `load-stress-conc8-stdout.txt`; `results/b-core/engine-tests.log` (`inbound_channel_applies_backpressure_and_loses_nothing`, `outbox_saturation_returns_unavailable`) |

## 8. Measurements

All on the single-host topology. "n" is the sample size.

### 8.1 Latency, delivery, duplicates

Latency definitions differ by experiment and include the poll interval and qemu emulation, so they are upper bounds for the transport.

| Experiment | n | Poll | Delivered | Dups | Latency p50 / p95 / p99 (ms) | Evidence |
|---|---|---|---|---|---|---|
| Transport probe A->B | 100 | 25 ms | 100/100 | 0 | 52 / 169 / 198 | `results/a1-daemon/rust-probe-basic-45bea17.json` |
| Transport probe B->A | 100 | 25 ms | 100/100 | 0 | 88 / 203 / 347 | same |
| Transport probe A->B | 100 | 250 ms | 100/100 | 0 | 135 / 252 / 262 | `rust-probe-basic-462f247.json` |
| Transport probe B->A | 100 | 250 ms | 100/100 | 0 | 148 / 262 / 370 | same |
| Encrypted envelope A->B | 100 | 25 ms | 100/100 | 0 (wire 0, app 0) | 24.6 / 39.8 / 50.3 (max 52.1) | `results/a2-e2e-crypto/roundtrip-1795640646489.json` |
| Encrypted envelope B->A | 100 | 25 ms | 100/100 | 0 | 28.0 / 239.2 / 325.7 (max 326.7) | same |
| Native FFI two-node | 100 per side | n/a (callbacks) | 100/100 each | 0 | p50 6.4, p99 132.2 (A); p50 6.4, p99 110.8 (B) (p95 63.0 / 51.9) | `results/a1-ffi/run-final-2node-100/`; lead re-run `run-lead-verify-2node/` |

Publish call latency p50: 3.8 ms (crypto spike, p95 9.8, p99 16.7) and 33-53 ms (transport probe, p95 75-133 ms): the two spikes ran at different host loads.
The goal.md baseline "100 numbered messages each direction, plus 20 offline messages and deliberate duplicate/reconnect tests" is met for rows 1 and 5-6 at the sample sizes above; the "deliberate duplicate" test is the replay test (n = 1) and the Store-versus-live overlap test.

### 8.2 Recovery latency

| Event | Measured | n | Evidence |
|---|---|---|---|
| Client node restart: REST healthy / connected to R1 | 1.3 s / 1.5 s (A1); 4.7 s (A2 persistence run) | 1 each | `results/a1-daemon/rust-probe-offline-45d196c.json`; persistence json |
| Store recovery of 20 offline messages (3 pages) | 48 ms | 1 | same |
| Client reconnect to a restarted R1 with the node's own logic | 113 s (default DNS); > 240 s and not recovered (`127.0.0.1` DNS) | 1 each | `results/a1-daemon/e5-r1-down.txt`; `relay-disruptive-tests.log` (first run) |
| Same with AgentNet adapter redial | 11.4 s (4 redials); client-node restart 3.4 s (0 redials) | 1 each | `results/b-transport/relay-disruptive-tests.log` |
| Live relay delivery usable again after R1 restart | about 9 min | 1 | `docs/spike/notes-daemon-rest.md` E12 |
| Mesh includes a restarted client node again | 62.8 s, 67.7 s | 2 | `docs/spike/notes-e2e-crypto.md` s4 |

### 8.3 Memory, CPU, startup, shutdown

| Item | Value | Evidence |
|---|---|---|
| Node image | 94.7 MB (v0.39.2); 1 process, 2 PIDs | `results/a1-daemon/image-size.txt`, `docker-stats-idle.txt` |
| Node idle snapshot (qemu amd64, 6 CPU / 9.7 GiB VM) | R1 44.4 MiB, 1.70 % CPU; NA 52.8 MiB, 0.78 %; NB 53.4 MiB, 0.22 % (one snapshot) | `results/a1-daemon/docker-stats-idle.txt` |
| Node under load (100 logical clients) | R1 105 %, NA 125 % CPU 1.2 s into the send phase (conc 2); 111-202 % in the stress variant | `results/a2-e2e-crypto/load-1795640646489.json`, `load-stress-conc8-stdout.txt` |
| Node startup to REST healthy / `docker stop` | ~1.3 s / ~1.2 s | `docs/spike/notes-daemon-rest.md` s2 E1, resource use |
| `agentnet` daemon memory / CPU / startup / shutdown | **UNTESTED** (not measured). Qualitative: MCP stdio process exits in 1-20 ms on EOF, up to ~0.55 s with an active listener (tests bound it at 1.5 s) | `docs/mcp-api.md` s6 |
| Release binary `agentnet` (macOS arm64, `lto = "thin"`) | 18,919,008 B (15,731,872 B after `strip`); dynamic libs: `libiconv.2.dylib`, `libSystem.B.dylib` only | `results/audit/release-binary.txt` |
| Native FFI node | RSS about 82 MB steady in the two-node run; startup 1.3-2.9 s, shutdown 1.3-1.4 s; +24.5 MB RSS and +4 fds per in-process start/stop cycle | `notes-ffi-bindings.md` s7; section 5 |

### 8.4 Load, trial decryption, sustainable rate

Crypto spike load test (`results/a2-e2e-crypto/load-1795640646489.json`; one process, 16 buckets, 10 messages per client, per-client pacing 20 ms, publish concurrency 2). Rate = sent / `send_phase_secs` (derived).

| Logical clients | Poll | Sent | Delivered | Rate | Offered rate (msg/s, derived) | Failed trial decryptions (observed / expected) | Latency p50 / p95 / p99 (ms) |
|---|---|---|---|---|---|---|---|
| 1 | 50 ms | 10 | 10 | 100 % | 13.9 | 0 / 0 | 112 / 241 / 241 |
| 10 | 50 ms | 100 | 100 | 100 % | 32.6 | 72 / 72 | 404 / 1939 / 2703 |
| 100 | 50 ms | 1000 | 1000 | 100 % | 34.5 | 6695 / 6695 | 141 / 468 / 783 |
| 100 | 200 ms | 1000 | 995 | 99.5 % | 71.9 | 5515 / 5532 | 343 / 5984 / 6832 |
| 100 | 1000 ms | 1000 | 879 | 87.9 % | 63.1 | 5067 / 5801 | 963 / 11777 / 13701 |

Stress variant (publish concurrency 8): 84.8 % (50 ms), 65.3 % (200 ms), 40.8 % (1000 ms) delivered with 20-33 s tails (`load-1795641030155.json`). Interpretation in the note: loss at slow polls matches eviction from the 50-slot cache; loss at fast polls coincides with node CPU saturation on a loaded host (inferred, not proven).

* **Sustainable message rate: UNTESTED.** No rate sweep was run; the offered rates above are data points of one workload on one loaded machine, not a capacity figure.
* **Idle bandwidth: UNTESTED.** Not measured (the poll rate of the adapter is 4 REST GET/s per subscribed topic at the 250 ms default; `docs/spike/notes-e2e-crypto.md` s7 calls polling 32 topics every 50 ms about 640 GET/s).
* Trial-decryption cost (macOS arm64, release, 10 000 ops per batch, 20 batches, three runs, minimum batch): failed open by a non-recipient 52.5 / 54.3 / 58.7 us; full open with Ed25519 verify 97.1-102.0 us; seal 80.8-94.8 us (`results/a2-e2e-crypto/bench-standalone-{1,2,3}.txt`; median-batch values 63.9-117.1 us show host noise).

## 9. A3: MCP spike

Evidence: `docs/spike/notes-mcp.md`, `results/a3-mcp/`, then `crates/mcp` and `docs/mcp-api.md` (`results/b-mcp/cargo-test.log`, 62 tests).

| Required | Result | Evidence |
|---|---|---|
| Tiny rmcp server, one tool, one inbox resource | built (`spike/mcp-spike`) | notes-mcp s3 |
| Tool call over stdio | pass | `results/a3-mcp/transcript-stdio-modern.txt` |
| Tool call over Streamable HTTP on loopback | pass; bearer required, wrong token 401, bad Origin 403, bad Host 403 | `transcript-http.txt`, `http-binary-smoke.txt` |
| Subscription to resource changes under 2026-07-28 | pass via `subscriptions/listen`: acknowledgment first, then `notifications/resources/updated` carrying the subscription id; cancel stops notifications | `transcript-stdio-modern.txt` |
| Negotiated version verified | `server/discover` -> 2026-07-28; default rmcp client using `initialize` -> 2025-11-25 | notes-mcp s4 (1); `docs/mcp-api.md` s2 |
| Legacy clients | `initialize` with 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05 negotiate as offered on stdio and HTTP; offering 2026-07-28 or an unknown version to `initialize` -> server answers 2025-11-25 | `transcript-stdio-legacy-*.txt` |
| Subscribe / cancel / reconnect / lost notifications | pass; gap notifications are not replayed; clients re-read from a cursor | notes-mcp s4 (6) |
| Pagination | 25 records in pages of 10/10/5 over stdio and HTTP | notes-mcp s4 (7) |
| Concurrent calls | 50 concurrent calls: stdio 22 ms, HTTP 128 ms, sequence numbers exactly 1..50 | notes-mcp s4 (8) |
| Fourteen spike tests | pass (lead re-ran: `cargo fmt --check`, `clippy -D warnings`, `cargo test --locked`, macOS arm64, rustc 1.92) | commit `6f40b3f`; `results/a3-mcp/cargo-test.log` |
| MVP MCP crate | 10 tools, 5 resources (+ templates), 62 tests recorded | `docs/mcp-api.md`; `results/b-mcp/cargo-test.log` |

Not done (recorded in the notes): third-party MCP hosts (Claude Code, MCP Inspector), the Tasks extension, rmcp's `auth` feature, OAuth profile for HTTP, Linux and Windows builds of the MCP crates (Linux arm64 build result in `docs/compatibility-matrix.md`).
No MCP wake-agent RPC was invented and sampling is not used.

## 10. A4: decision gates, one by one

Transport decision: [ADR 0001](adr/0001-transport.md) (REST adapter to a sidecar node); encryption: [ADR 0002](adr/0002-end-to-end-encryption.md); MCP: [ADR 0003](adr/0003-mcp-sdk-and-protocol-version.md).

Gate text is goal.md A4 "Go". Verdicts are about the **evidence in this repository**, not about production readiness.

| # | Gate | Verdict | Justification |
|---|---|---|---|
| G1 | Reproducible Rust build with at least one viable Delivery path | **GO (macOS arm64); Linux arm64: see result below; Linux x86_64 UNTESTED** | Path (3) builds and its tests pass on macOS arm64 (`results/b-daemon/workspace-tests.log`, lead re-ran per commit `0eb3d35`). Linux arm64 clean-checkout build and test: **OK** (`cargo build --workspace --locked` exit 0, 45m58s; `cargo test --workspace --locked` exit 0, 308 passed / 0 failed / 2 ignored in 25 suites, `results/audit/linux-arm64-build.log`; relay-gated tests skipped there). Clean checkout reproduction: the Linux run unpacks `git archive HEAD`, not the working tree. goal.md asks for Linux x86_64 first: not available (amd64 build under qemu: **not attempted**, UNTESTED) |
| G2 | Bidirectional encrypted messaging | **GO (single host)** | 100/100 each way with the HPKE+Ed25519 envelope; two `agentnet serve` processes exchange messages with authenticated receipts (`results/b-daemon/relay-e2e.log`, passes in the lead's re-run per commit `0eb3d35`) |
| G3 | Private isolation demonstrated on controlled infrastructure | **GO with caveats (single host)** | Capture shows no destination outside the subnet once the DNS setting is changed; AgentNet audits peers and fails closed. Caveats: capture only on the VM bridge, none during failure runs, none of the daemon's own sockets; the isolation depends on node flags AgentNet cannot set; the relay accepts any peer that knows cluster 66 (T13); not shown on separate hosts |
| G4 | Durable identity | **GO** | Restart, file migration, exclusive lock, export/import unit test. Competing instances on two directories are not detected (documented gap) |
| G5 | Offline/retry semantics understood | **GO, with a stated gap** | Store recovery 20/20, retry/backoff/dedupe semantics tested deterministically, retention and the +-20 s archive rule measured. The earlier gap (end-to-end daemon recovery with a stopped recipient daemon against the real relay) is closed by acceptance step 3: 20/20 recovered, 0 duplicates, in four runs (`docs/acceptance.md`), and the verified relay retention is only 1 hour |
| G6 | Standard MCP tool call and resource-change notification demonstrated | **GO** | Spike and MVP, stdio and HTTP, 2026-07-28 and legacy; the relay e2e test shows `B received a subscription update` for `agentnet://inbox` (`results/b-daemon/relay-e2e.log`). Only the rmcp client was used |
| G7 | Real Tailscale run and public interop | **DEFERRED, infrastructure unavailable, explicitly recorded** | Not validated. Not claimed anywhere |
| G8 | "If libchat is unsuitable, evaluate an established audited messaging library/protocol ... do not hand-roll encryption" | **Evaluated; decision accepted by the owner with conditions** | libchat evaluated and rejected with evidence. The fallback evaluated on paper (`vodozemac`, audited) was not run; the chosen path is a composition of unaudited-library primitives (section 6). Documented, but needs the owner's explicit acceptance and an external review **Update:** `vodozemac` was subsequently run (`docs/spike/notes-vodozemac.md`) and the repository owner accepted HPKE + Ed25519 for the MVP with 13 conditions (ADR 0002, `docs/crypto-requirements.md`). The library and the composition remain without an independent audit; review before production use is a standing requirement. |
| G9 | "If no safe encrypted transport or private isolation works, stop" | not triggered | - |
| G10 | "If native bindings fail but a local daemon works, use the adapter and keep native embedding as a future option" | **applied** ([ADR 0001](adr/0001-transport.md)) | The native path builds on linux/arm64 only with a native-Nim workaround (about 2 h), crate not on crates.io, in-process lifecycle leaks, stdout TRACE logging, no Store/Filter/Light Push in the stable API; it did deliver 100/100 messages between two nodes. Adapter used. |

## 11. Upstream bugs and edge cases found (with evidence and workaround)

1. **Default DNS online-monitor egress.** Every node queries `one.one.one.one` via 1.1.1.1 every 5 s even with all discovery off. Evidence: `results/a1-daemon/egress-default-dns.egress.txt`. Workaround: `--dns-addrs-name-server=127.0.0.1` (verified clean capture) or an internal resolver.
2. **No redial without DNS.** With that workaround a client that loses its only peer is marked offline and never redials its `--staticnode` (still `CannotConnect` after > 240 s): `results/b-transport/relay-disruptive-tests.log`, first run. Workaround implemented in the adapter: POST the configured static peers to `/admin/v1/peers` (11.4 s). On a no-egress network with the default DNS a client never connects at all (`results/a1-daemon/e8a-internal-net-default-dns.txt`).
3. **Mesh not re-forming about 9 minutes after a relay restart** although peers show `Connected` (empty or flapping gossipsub mesh); cause not found: `docs/spike/notes-daemon-rest.md` E12. Workaround: Store catch-up (not separately tested for that gap).
4. **Unsubscribing one content topic drops the node from the relay mesh** even if another topic of the shard stays subscribed (`results/a2-e2e-crypto/unsub-experiment.txt`: R1 mesh peers 2 -> 1 for 8+ s, re-POST restored). Workaround: never unsubscribe.
5. **Misleading `NoPeersToPublish`**: returned for no peers, for payloads 1-20 B over the limit, and for a duplicate publish (same timestamp/hash) (`results/a1-daemon/e3-probes.json`, `e5-r1-down.txt`). Workaround: size check locally, treat the error as ambiguous.
6. **Silent drop for `meta` > 64 B**: publish returns 200 and the message never arrives (`e3-probes.json`). Workaround: do not use `meta`.
7. **Archive +-20 s timestamp rule**: the Store silently refuses messages whose publisher timestamp is more than 20 s from its own clock while the relay still delivers them (`waku_archive/archive.nim:36`; E3). Workaround: NTP everywhere.
8. **50-slot destructive REST relay cache**, shared by all topics, drops the oldest silently, returns out of chronological order after any eviction, and is lost on node restart; a static-pubsub subscription caches every content topic on the shard; publishers receive their own messages. Evidence: E3 and `rust-probe-burst-45cd130.json` (100 messages in ~1 s polled every 1.5 s: 50 received, seq 0..49 lost; polled every 100 ms: 0 lost). Workaround: poll every 250 ms or faster, persist what is read, Store reconciliation.
9. **Cluster ids 1 and 2 silently apply public presets** (TWN with RLN and public bootstrap; logos.dev), 3 and 16 are presets too (`tools/confutils/cli_args.nim:1073-1087`). Workaround: private mode rejects ids 1, 2, 3, 16.
10. **Docker image is linux/amd64 only**, Docker Hub lags releases (no v0.40.0 tag, `latest` is a nightly), binary renamed `wakunode2` -> `logosdeliverynode`. Workaround: pin by digest; run under qemu on arm64 (adds latency).
11. **Messaging API churn**: `/messaging/v1/events/send/{requestId}` became `{messageHash}` between v0.39.2 and master; subscriptions in memory; history backfill returns already-seen messages (5 delivered including 2 duplicates). Workaround: not used by the adapter.
12. **No Store failover**: one `--storenode`; without an explicit `peerAddr` a query to a stopped Store fails after 5 s; a returning service node does not backfill (`e9-two-service-nodes.txt`).
13. **Retention policy applied only at start and every 30 minutes**; expired history is indistinguishable from "never existed" (`e6-retention.txt`).
14. **Ephemeral messages are relayed but never stored.**
15. **Duplicate node keys are not detected loudly** (second node stays `CannotConnect`, E10 note).
16. **Subscribe with an invalid content topic returns HTTP 500**, bad base64 returns an empty 400 body, unsubscribed-topic publish error text varies (`e3-probes.json`).
17. **Node REST has no authentication or TLS; `--rest-admin` exposes peer dial and filter listing.**
18. **rmcp items** (`docs/spike/notes-mcp.md` s5, `docs/mcp-api.md` s9): default `ClientConfig::serve` lands on 2025-11-25 not 2026-07-28; upstream README does not compile against 3.11.0 for resources; **stdio shutdown with an open `subscriptions/listen` takes about 5 s** (worked around: 300 ms + 200 ms guard, worst case 0.55 s measured); GET/DELETE on a stateless endpoint answer 400 not 405; modern HTTP responses default to SSE; Origin validation is off unless enabled (the crate turns it on); a fabricated `initialize` log line for modern requests (upstream #1425); duplicate URI echoed twice in the acknowledged filter; open upstream issues #1395, #1325, #1347, #1482, #1492, #1469 (`chrono` flagged unmaintained, RUSTSEC-2026-0543, listed by upstream; see `docs/dependency-audit.md` for this workspace's advisory results).
19. **libchat items** (section 4.2): memory-only MLS state; one corrupted copy kills the genuine message; debug builds panic on tampered ciphertext; last-resort key packages reused; conversation id in clear and stable per-installation inbox address; hosted default registry; needs rustc 1.95; `README`/ADR 0002 describe storage that is not wired.
20. **native bindings items** (`docs/spike/notes-ffi-bindings.md` s8): crates.io crates stale and unresolvable (legacy) or absent (new); no prebuilt library; nimble downloads an x86-64 Nim on aarch64 (segfault); about 2 h build; about 24.5 MB + 4 fds leaked per in-process start/stop; stdout TRACE logging unless `LOG_LEVEL=ERROR`; `connect()` `Ok` on a failed dial; no `catch_unwind` in callbacks; no backpressure.
21. **Declared MSRV not achievable** (this repository, not upstream): `Cargo.toml` declares `rust-version = "1.88"` but the locked `rusqlite 0.42.0` and `uuid 1.29.3` declare 1.89.0 (`cargo metadata`). Verified by running `cargo check --workspace --locked` with rustc 1.88.0 in a container: exit 101, "rustc 1.88.0 is not supported by the following packages: rusqlite@0.42.0 requires rustc 1.89.0, uuid@1.29.3 requires rustc 1.89.0" (`results/audit/msrv-1.88-check.log`).

## 12. Maintenance risks

* Upstream node API and naming are in motion (nwaku -> logos-delivery; wakunode2 -> logosdeliverynode; messaging API changes between releases); the adapter is pinned to the v0.39.2 REST shape and will need work for v0.40+ (**UNTESTED against any newer node**).
* The image distribution is thin: amd64 only, Docker Hub lagging, unsigned (as far as verified), anonymous access denied on the other registries.
* The node's behavioural defects (items 1-4, 7, 8) are reproducible but unfixed upstream as far as checked; some are in the peer manager and gossipsub paths we cannot change.
* `hpke` and the composition have no external review; `rmcp` is on a fast cadence (3.0.0 on 2026-07-28, 3.11.0 on 2026-11-17: eleven minor releases in under four months); pinned exactly.
* Two `hpke` versions are present (0.15.1 direct, 0.12.0 via `age`), plus parallel RustCrypto generations (`docs/dependency-audit.md`).
* The Nim toolchain for native builds (nimble/Nim download behaviour) is brittle on arm64.
* libchat is a moving target; revisit conditions are listed in `docs/spike/notes-libchat-and-crypto.md` s1.12.

## 13. Remaining unknowns

Cross-machine and NAT behaviour; Tailscale; public network connectivity, interop and RLN requirements; behaviour of the node on native x86_64 or native arm64 (the spike ran amd64 under qemu); `--store-sync`/`--store-resume`; Postgres Store; `--rate-limit`; RLN-enabled private clusters;
UPnP/PMP/QUIC/websocket egress behaviour of the default NAT settings; clock skew behaviour end to end; duration soak tests; hostile flood against a bucket; third-party MCP hosts; MCP Tasks extension and OAuth profile;
second-instance (split-brain) detection; whether the verified retention (1 h) is acceptable; licence audit of the node's vendored Nim dependencies; image signature/provenance; the native FFI path (see section 5); cause of the 9-minute mesh gap; cause of `run-dev1` total loss in the FFI spike.

## 14. Name and licence availability (facts only, 2026-11-25; no legal conclusions)

Raw output: `results/audit/name-availability.log`, `results/audit/name-availability-2.log`.

* crates.io: `agentnet`, `agentnet-core`, `agentnet-cli`, `agentnet-mcp`, `agentnet-daemon`, `agentnet-transport` each return HTTP 404 "does not exist" from the crates.io API; `cargo info agentnet` says "could not find `agentnet` in registry"; the crates.io search for `agentnet` returns `total: 0`. (`cargo search agentnet --limit 20` printed no results.)
* GitHub (`gh search repos agentnet --limit 20`, authenticated): 20 repositories returned, none obviously the same product; examples with the same name: `yandexdataschool/AgentNet` (archived deep-learning library), `zoe-yyx/AgentNet`, `raihankhan-rk/AgentNet`, `IQCoreTeam/AgentNet`, `KarolisMart/AgentNet`, `nokpil/AgentNet`, `misunders2d/agentnet` ("Secure, self-hosted communication network for verified agents and humans"), `oxgeneral/agentnet` ("agent-to-agent referral network ... MCP server and HTTP API"), `0xbyt4/agentnet` ("Social network relay for Hermes agents - Ed25519 signed events"), `MFS-code/agentnet-code`, `smartpricing/agentnet` (archived), `TheAgent-net/agentnet-cli`. Several describe agent-communication projects with similar wording.
* GitHub organisation `agentnet` exists (created 2023-09-26, 0 public repositories, type Organization); no user named `agentnet`.
* Licence: `Cargo.toml` declares `MIT OR Apache-2.0`; `LICENSE-MIT` and `LICENSE-APACHE` were added (copyright holder "AgentNet contributors"; the Apache text is identical to the standard text and to the copy in `upstream/libchat/LICENSE-APACHE`). Trademark searches were **not** done. The name and the licence choice are provisional and need the owner's confirmation before publication. The repository URL in `Cargo.toml` is a placeholder (`https://example.invalid/agentnet`).

## 15. Inconsistencies found between documents, code and evidence

Listed here so that this report is self-contained; further platform-specific findings are in `docs/compatibility-matrix.md`.

1. ~~`docs/architecture.md` and `embed.rs` cite ADR 0001 and `notes-ffi-bindings.md`~~: both files now exist (added by the lead after my first pass); no inconsistency remains.
2. `Cargo.toml` `rust-version = "1.88"` versus locked crates declaring 1.89.0 (item 21 above). README prerequisites in this repository say 1.89 for that reason (see the check in `docs/compatibility-matrix.md`). **Fixed in working tree:** `rust-version = "1.89"`; build with a real 1.89.0 toolchain in `results/fixups/msrv-1.89-build.log`; CI has an `msrv` job. README still mentions 1.88 (outside this change's scope, to be updated by the lead).
3. `cargo test --workspace --locked` reports the relay-gated tests as **passed** when the environment variable is unset: they return early. `results/b-daemon/workspace-tests.log` shows `relay_e2e ... 1 passed ... finished in 0.00s` and `logos_rest_relay ... 6 passed; 2 ignored ... 0.00s`. Real relay results are only in `results/b-daemon/relay-e2e.log` and `results/b-transport/relay-tests.log`. **Fixed in working tree:** the relay-gated tests are `#[ignore]`d and fail (not pass) when run with `--ignored` without `AGENTNET_RELAY_TESTS=1`; run them with `AGENTNET_RELAY_TESTS=1 cargo test --workspace --locked -- --ignored` (logs in `results/fixups/`).
4. `docs/mcp-api.md` limits `body` to 32768 B while the engine allows `max_body_bytes` = 65536 and the frame fits up to about 130 KiB (`docs/protocol.md`, `docs/spike/notes-e2e-crypto.md` s5): three different limits for the same field; the MCP layer is the strictest. **Fixed in working tree:** the MCP cap is now 65536 B, equal to the engine default; the effective limit is the smaller of the MCP cap and the daemon's `delivery.max_body_bytes` (`docs/mcp-api.md`). The frame-size ceiling (about 130 KiB of body) is unchanged.
5. `spike/relay/docker-compose.yml` defaults `DNS_NS` to `1.1.1.1`, `agentnet relay print-config`, `docs/configuration.md` and the relay tests require `127.0.0.1`. `./scripts/up.sh` without `DNS_NS` starts a topology that contacts 1.1.1.1. **Fixed in working tree:** the compose files now default `DNS_NS` to `127.0.0.1`; `spike/relay/scripts/egress-capture.sh` sets `DNS_NS=1.1.1.1` explicitly for the upstream-default capture.
6. `docs/mcp-api.md` s8 shows `"args": ["mcp", "--data-dir", ...]` while `docs/examples/mcp-client-stdio.json` has `["--data-dir", ..., "mcp"]` (both forms are accepted by the CLI parser as far as exercised in this report's quickstart run for the second form only; see the transcript).
7. `docs/spike/notes-e2e-crypto.md` s1 says the spike's frame cap is 160 KiB and a "no max-TTL rule is implemented"; `docs/protocol.md` has a 150 KiB library default and a 7-day max TTL: the spike and the MVP differ by design; not an error, but numbers from the spike do not describe the MVP.
8. The verified relay flag set has a 1-hour Store retention, while `docs/configuration.md` and the README default `retention_hours = 168` suggest week-long recovery; the 168 h is only the client side bound (`docs/relay-setup.md` section 6). **Fixed in working tree:** `agentnet relay print-config` and `docs/relay-setup.md` now recommend `time:604800;capacity:100000` (7 days) for the service node and explain that the recovery window is the minimum of relay retention, message TTL and the daemon's retention; the spike compose default stays at one hour on purpose (a comment says so). The 7-day value has been started and exercised only as described in `results/fixups/` (see `docs/relay-setup.md` section 6).
9. `docs/threat-model.md` and goal.md B2 call for "restrict binding/egress"; the code restricts the **node REST URL** and audits peers, but nothing restricts the node's own bind/egress; that is the operator's (section 5 of `docs/threat-model.md`).

## 16. Status after the spike (added by the lead, 2026-11-25)

* The MVP was built on the validated foundations: `crates/{transport,core,mcp,daemon,cli}`.
* Lead's last full run on the merged tree (git `7b74ba4`): `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets --all-features -- -D warnings`, `cargo test --workspace --locked` (348 passed, 6 ignored relay-gated), the 6
  relay-gated tests against the live topology, and `scripts/acceptance.sh` (52 PASS, 0 FAIL, Tailscale UNTESTED;
  `results/acceptance/20261126T014245Z/`). The Linux arm64 figure in section 2/G1 (308 passed) is from an earlier commit and
  was not repeated after the merge: Linux on the final tree is **UNTESTED**.
* Items in section 15 marked "fixed in working tree" are committed (`5e66954`, `e250186`).
* Still not validated anywhere: cross-machine and NAT operation, Tailscale, public networks, Linux x86_64, third-party MCP
  hosts, operation over hours or days, and any independent security review.
