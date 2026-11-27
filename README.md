# AgentNet

AgentNet is a Rust service that gives an autonomous agent a durable cryptographic address and lets agents on different machines exchange encrypted, asynchronous messages through relays the user chooses.
It runs as a local daemon (`agentnet serve`) next to a Logos Delivery (Waku) node that carries the messages; recipients that are offline can fetch messages from the relay's Store within its retention window.

It exposes an MCP server (stdio and loopback HTTP) so an MCP client can send, read and discover messages and subscribe to changes, and a separate local event socket and optional signed webhook so a host (harness) can decide whether to wake an agent.
The service never runs a model and never executes message content; a message body is untrusted data.

> **Status:** Experimental MVP; message protection is RFC 9580 OpenPGP (`sequoia-openpgp` 2.5.0, OpenSSL 3 backend, [ADR 0004](docs/adr/0004-openpgp-message-protection.md)). `main` is the OpenPGP tree. Validated mostly on one host; the earlier single runs on real hosts (SSH tunnel, tailnet, public IP, public wss endpoint) used the retired HPKE + Ed25519 scheme and are **UNTESTED** on the OpenPGP tree. Requires a Logos Delivery sidecar for each agent. Not independently audited; NAT traversal between clients and more than two hosts remain unvalidated. Details: [Status and limitations](#status-and-limitations).

**Start here**

* **Run the local demo:** `scripts/demo.sh` runs two agents against a local relay and prints a delivered message and its receipt ([Quickstart](#quickstart-single-machine-two-agents-local-relay)).
* **Operate a deployment:** [docs/runbook.md](docs/runbook.md) (checks, restarts, incident playbooks) and [docs/relay-setup.md](docs/relay-setup.md) (your own relay and Store node).
* **Connect a harness:** [docs/mcp-api.md](docs/mcp-api.md) (MCP over stdio or loopback HTTP) and [docs/host-integration.md](docs/host-integration.md) (event socket, webhook).

## Architecture

```
 MCP host --stdio--> agentnet mcp --+                                 (thin client of the daemon)
 MCP host --HTTP (loopback, bearer)-+
 harness --unix socket / webhook----+
                                    v
                       agentnet serve   identity, SQLite inbox/outbox, triggers, events
                                    | REST, loopback only, no authentication
                                    v
                    Logos Delivery node (sidecar container, you run it)
                                    | libp2p, static peers only in private mode
                                    v
                    your relay + Store node(s)    <---- the other agents' nodes
```

Details: [docs/architecture.md](docs/architecture.md), wire protocol [docs/protocol.md](docs/protocol.md).

## Prerequisites

* Rust **1.89 or newer** (the workspace declares `rust-version = "1.89"`; built with rustc 1.89.0 in a container, `results/fixups/msrv-1.89-build.log`; developed on 1.92).
  The host used for all tests has rustc 1.92.0.
* Docker, to run the Logos Delivery node sidecar. The pinned image is **linux/amd64 only**; on arm64 hosts it runs under emulation (works on the test host, slower).
  The helper script `spike/relay/scripts/up.sh` calls the standalone `docker-compose` binary, not `docker compose`.
* Python 3 (used by the relay start helper). `spike/relay/scripts/up.sh` checks for `docker-compose`, `curl` and `python3` first and exits with an error naming any that is missing; it also exits non-zero if a node does not answer `/health` within 60 s.
* `jq` (used by the commands below, not by `up.sh`) and `curl`.
* Unix (macOS, Linux). Windows is not supported.
* A C compiler: `rusqlite` builds SQLite from bundled C source and `ring` (via rustls) compiles C/asm.
* **OpenSSL 3 development files** (headers and libraries) and `libclang`: the OpenPGP library (`sequoia-openpgp` 2.5.0, `crypto-openssl` backend) links OpenSSL and its build scripts use `bindgen`. Build with `OPENSSL_DIR` pointing at the installation (macOS Homebrew: `export OPENSSL_DIR=$(brew --prefix openssl@3)`; Debian/Ubuntu: `apt install libssl-dev libclang-dev clang pkg-config`). The Nettle backend and the pure-Rust backend are not used. The OpenSSL path is not hard-coded in the repository; Also needed: `pkg-config` and `clang` on Linux. Locked builds and tests on the OpenPGP tree: macOS arm64 (`results/final/host-checks-adr0004.txt`), Linux arm64 container (`results/final/linux-arm64-adr0004.txt`) and Linux x86_64 on a native cloud VM (`results/final/linux-x86_64-adr0004.txt`).

## Quickstart (single machine, two agents, local relay)

### Fastest path: the demo script

```sh
scripts/demo.sh
```

The script checks the prerequisites, builds `target/release/agentnet` if it is missing, starts the local relay topology **only if it is not already running** (an already-running topology is reused and never stopped), creates two agents in a fresh temporary directory, starts two daemons, exchanges signed contacts, sends A to B and a reply back, waits (with time limits) for readiness and delivery, prints the delivered status and the receipt, and on exit stops its daemons and removes its temporary directory. It exits non-zero with an explanation if anything fails. Set `DEMO_KEEP=1` to keep the directory for inspection.
It exercises the software on one host (a service node and two client nodes in Docker on 172.28.66.0/24, cluster id 66); it is not a cross-machine test. Runs and timings: `results/demo/`.

### The same steps by hand

The rest of this section is the explanation of what the script does. **Run these commands in the same shell**, in order: later steps use variables (`A`, `B`, `PID_A`, ...) set by earlier ones. Let each wait loop finish before the next step.

**1. Build.**

```sh
cargo build --release --locked -p agentnet-cli
export PATH="$PWD/target/release:$PATH"
agentnet --version
```

**2. Start the local relay topology** (service node first, then the two client nodes; REST ports 18641 and 18642 on 127.0.0.1). `DNS_NS=127.0.0.1` matters: the node's default DNS server is 1.1.1.1 and it would contact it every 5 s even in private mode (see [docs/relay-setup.md](docs/relay-setup.md) section 5).

```sh
(cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh)
```

The output ends with one line per node listing its connected peers (`[True]` or `[True, True]`). If you see empty lists or errors, check `docker ps` and `docker logs an-r1`: the helper script does not stop on a failed start.

**3. Create two agents.** Keep the data directories short (the control socket path must fit a Unix socket, about 100 bytes).

```sh
R1=/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV
A=$(mktemp -d /tmp/an-a.XXXXXX); B=$(mktemp -d /tmp/an-b.XXXXXX)
agentnet --data-dir $A init --node-url http://127.0.0.1:18641 --peer $R1
agentnet --data-dir $B init --node-url http://127.0.0.1:18642 --peer $R1
```

`init` writes a private-mode `agentnet.toml`, a new identity (`identity.json`, mode 0600) and access tokens, and prints the address and the signed contact record.

**4. Start both daemons, wait until they are ready, then check them.** The daemons run in the background of this shell; each needs a moment to connect its node to the relay, so wait for readiness before running other commands.

```sh
agentnet --data-dir $A serve 2>$A.log & PID_A=$!
agentnet --data-dir $B serve 2>$B.log & PID_B=$!
until agentnet --data-dir $A --json network status 2>/dev/null | jq -e '.network.ready' >/dev/null; do sleep 2; done
until agentnet --data-dir $B --json network status 2>/dev/null | jq -e '.network.ready' >/dev/null; do sleep 2; done
agentnet --data-dir $A doctor           # expect zero failing checks; the single-instance warning is expected; exit 7 if any check fails. Exit 0 alone does not mean messaging works (a stopped daemon is only a warning): for readiness use `agentnet doctor --ready`
agentnet --data-dir $A network status
```

The loops wait indefinitely if the relay is unreachable: press Ctrl-C and read `$A.log`. Right after a node or relay restart, readiness can take about a minute or more.

**5. Exchange and verify contact records.** In real use the address must reach you over a channel you trust; `--expect` makes `add` fail unless the record is for exactly that address.

```sh
A_ADDR=$(agentnet --data-dir $A identity show --json | jq -r .agent_id)
B_ADDR=$(agentnet --data-dir $B identity show --json | jq -r .agent_id)
agentnet --data-dir $A identity show --json | jq -r .contact_record > $A/self-record.json
agentnet --data-dir $B identity show --json | jq -r .contact_record > $B/self-record.json
agentnet --data-dir $A contact add @$B/self-record.json --expect $B_ADDR --alias b
agentnet --data-dir $B contact add @$A/self-record.json --expect $A_ADDR --alias a
agentnet --data-dir $A contact list
```

**6. Send, read, check status.** `queued` and `sent` are **not** receipt; only `delivered` (an authenticated acknowledgement from the recipient) is. Delivery usually takes a few seconds; live delivery on this topology occasionally needs the next history sync (15 s by default), so the loops below wait for it.

```sh
agentnet --data-dir $A send $B_ADDR 'hello from A' --json | tee $A/send.json
MID=$(jq -r .message_id $A/send.json)
until agentnet --data-dir $B --json inbox | jq -e --arg id "$MID" '.records[] | select(.message_id==$id)' >/dev/null; do sleep 2; done
agentnet --data-dir $B inbox
until agentnet --data-dir $A --json status $MID | jq -e '.state=="delivered"' >/dev/null; do sleep 2; done
agentnet --data-dir $A status $MID      # state: delivered, with the authenticated receipt time
agentnet --data-dir $B ack $MID         # local "processed" mark; sends nothing
```

**That is the first-message success point.** Everything below is optional.

**7. (Optional) MCP over stdio.** The daemon must be running. Print a client configuration that uses the real binary path and this agent's data directory, and paste it into any MCP client's configuration (a static template is in [docs/examples/mcp-client-stdio.json](docs/examples/mcp-client-stdio.json)):

```sh
cat <<EOF
{
  "mcpServers": {
    "agentnet": {
      "command": "$(command -v agentnet)",
      "args": ["--data-dir", "$A", "mcp"]
    }
  }
}
EOF
```

This demo directory is temporary; for a long-lived agent use a persistent directory (the default is `~/.agentnet`).
Fifteen tools (`get_identity`, `send_message`, `read_inbox`, `get_message`, `acknowledge_message`, `get_message_status`, `list_contacts`, `add_contact`, `network_status`, `create_trigger`, `list_triggers`, `delete_trigger`, and the opt-in `advertise_agent`, `withdraw_advert`, `discover_agents`) and five resources; see [docs/mcp-api.md](docs/mcp-api.md).
Only the `rmcp` test client was used against it; **third-party MCP hosts are UNTESTED**. Loopback HTTP MCP (`[mcp_http] enabled = true`) uses a static bearer token, which is **not** the MCP OAuth profile.

**8. (Optional) Triggers and the mock harness.** Triggers are off by default. Enable them for one allow-listed session on agent B, restart B, create a one-shot trigger, run the mock harness (it records a simulated turn; there is no model), and have A send a matching message.

```sh
kill -TERM $PID_B; wait $PID_B
sed -i.bak -e 's/^auto_trigger = false/auto_trigger = true/' \
           -e 's/^allowed_sessions = \[\]/allowed_sessions = ["demo-session"]/' $B/agentnet.toml
agentnet --data-dir $B serve 2>$B.log & PID_B=$!
until agentnet --data-dir $B --json network status 2>/dev/null | jq -e '.network.ready' >/dev/null; do sleep 2; done
agentnet --data-dir $B trigger create --target-session demo-session --sender $A_ADDR
cargo run -p agentnet-daemon --example mock_harness -- \
    --data-dir $B --out $B/turns.jsonl --state $B/harness-state.json --max-events 1 --idle-exit-ms 150000 &
agentnet --data-dir $A send $B_ADDR 'wake up' --json
until [ -s $B/turns.jsonl ]; do sleep 2; done   # the harness may first have to compile; then it records the turn
cat $B/turns.jsonl                      # one line per recorded simulated turn
```

The harness consumes the event stream (or a signed webhook), de-duplicates on `event_id` and decides what to do; see [docs/host-integration.md](docs/host-integration.md). A message from a sender the trigger does not name, or from an untrusted contact, produces no event.

**9. Stop and clean up.** SIGTERM or Ctrl-C shuts a daemon down cleanly. The relay containers keep running; `cd spike/relay && docker-compose down` stops them.

```sh
kill -TERM $PID_A $PID_B; wait $PID_A $PID_B
rm -rf $A $B $A.log $B.log
```

Verification status of this quickstart: see "Quickstart verification" in the last section of this file.

## Private mode and public mode

* **private** (default, the only mode that was tested). `agentnet.toml` must name your own static peers (`/ip4/<private ip>/tcp/60000/p2p/<peerId>`), a private `cluster_id` (not 1, 2, 3 or 16, which select public presets), and a local or private `node_url`.
  Public peer discovery and public fallback do not exist (`public_fallback = true` is always an error). At runtime the daemon audits the node's peer list every 15 s and **refuses to send or receive** if the node is connected to any peer outside the allowlist.
  The daemon cannot set the node's own flags: whether the node itself contacts public infrastructure depends on how you start it ([docs/relay-setup.md](docs/relay-setup.md)). Cluster and shard ids are not access control.
* **public** requires `mode = "public"` and `i_understand_public = true`, skips the peer audit unless `enforce_peer_allowlist = true` (tested once against a real public-IP relay over raw tcp, `results/public-ip-relay/20261126T211443Z/`; wss/DNS endpoints with it are UNTESTED) (own relay on a public address; unit tests only, **UNTESTED** on a real relay), and was run only against your own relays on public addresses (`results/public-ip-relay/20261126T204713Z/`, `results/public-relay/20261126T203405Z/`), **not** against the shared public Waku/Logos network (UNTESTED). The REST adapter supports only single-shard networks, which the shared public networks are not. No bridging between modes: one daemon talks to one node in one mode.

Reference configs: [docs/examples/private.toml](docs/examples/private.toml), [docs/examples/public.toml](docs/examples/public.toml); all keys: [docs/configuration.md](docs/configuration.md).

## Running your own relay and Store node

`agentnet relay print-config --ip <relay ip> --peer-id <relay peer id> --client-ip <client ip>` prints the verified flag set and compose snippets. Firewall guidance, nodekey and peer-ID handling, retention, clock requirements, two service nodes and an **UNTESTED** Tailscale deployment are in [docs/relay-setup.md](docs/relay-setup.md).

## Security summary

* Each message is one **RFC 9580 OpenPGP** message ([ADR 0004](docs/adr/0004-openpgp-message-protection.md)): encrypted to an anonymous v6 PKESK of the recipient's X25519 subkey (SEIPD v2, AES-256, OCB), signed inside the encryption with an Intended Recipient Fingerprint, padded with a standard Padding packet. AgentNet defines no cryptographic construction of its own; the library is `sequoia-openpgp` 2.5.0 with the OpenSSL 3 backend. Sender, type, ids and body are inside the ciphertext. Relays see the recipient's inbox bucket (1 of 16), time, and padded size.
* **No forward secrecy (in particular none against a later compromise of a recipient encryption subkey), no post-compromise security, no deniability.** Subkey rotation (with optional destruction of earlier subkeys) and a standard key revocation exist, but there is no directory and no global revocation list: they reach only peers that receive the notice ([docs/protocol.md](docs/protocol.md) section 9). Secret keys are stored in a mode-0600 file; exports are passphrase-encrypted with `age`.
* Cryptography sits behind one module boundary (`agentnet_core::crypto`, [docs/crypto-interface.md](docs/crypto-interface.md)); the owner's acceptance conditions restated for OpenPGP are in [docs/crypto-requirements.md](docs/crypto-requirements.md). The receiver accepts only the fixed OpenPGP profile (no downgrade), requires the Intended Recipient Fingerprint, refuses to encrypt to a revoked or expired certificate, and applies certificate updates as merges only.
* Replay protection survives restarts and detects a rolled-back store (replay guard); it cannot detect the same identity running in two data directories.
* Remote message bodies are data. Nothing executes them; remote senders cannot create triggers, change policy or set webhook targets. Unknown senders are quarantined by default.
* **Unaudited**: the composition (not just the code) needs an **independent cryptographic review before production use involving sensitive information**; neither `sequoia-openpgp` 2.5.0 nor the OpenSSL backend is audited at the pinned version, and both shipped security fixes in November 2026. Do not describe this implementation as audited, production-secure or forward-secret.

Full analysis: [docs/threat-model.md](docs/threat-model.md). ADR: [docs/adr/0004-openpgp-message-protection.md](docs/adr/0004-openpgp-message-protection.md) (supersedes ADR 0002).

## Status and limitations

Read these before relying on anything here.

* **Experimental MVP; not audited; provisional name.** The cryptographic composition has had no independent review: **an independent cryptographic review is required before any production use involving sensitive information.** The scheme is **not audited, not production-secure and not forward-secret.** The name "AgentNet" is provisional; the licence is MIT (see Licence below).
* **Mostly single-host validation; real-host runs are single runs.** Apart from the GitHub Actions x86_64 runs described below, all tests ran on one macOS arm64 machine; containers on one VM; the node image under CPU emulation. Beyond the real-host runs below, NAT traversal between clients, hosted-Tailscale ACLs and more than three hosts are **UNTESTED**; WireGuard-overlay and NAT-gateway **simulations on one host** are in docs/network-simulations.md. One run crossed **two real hosts** (a Mac behind a home NAT and a cloud VM) with an outbound-only client and no public listener, through an SSH tunnel (`results/cross-machine/20261126T190328Z/`); raw libp2p over the public internet was tested separately (below). Tailscale was tested across **two real hosts on a real tailnet** (direct path): relay reachable only at its tailnet address and firewalled to one client (`results/tailscale-cross-machine/20261126T192147Z/`). Restriction by tailnet tag policy was verified on a self-hosted Headscale tailnet (`results/tailnet-acl/20261126T215842Z/`); hosted-Tailscale ACL syntax, key expiry and steady-state DERP-relayed operation are **UNTESTED**. Two **public-internet runs** (single runs, a Mac behind a home NAT as outbound-only client, agent B on the relay host): a relay on its own public IPv4 behind a cloud firewall (`results/public-ip-relay/20261126T204713Z/`, 18 PASS, 2 UNTESTED) and a relay behind a provider's public wss/TLS edge (`results/public-relay/20261126T203405Z/`, 17 PASS). They needed `mode = "public"`; the firewall or edge is the only access control (a stranger with the cluster id joined the wss endpoint and read ciphertext and Store metadata); a client dialling by DNS name used public DNS. Not tested: NAT hole punching between clients, the shared public Waku/Logos network, `enforce_peer_allowlist` against a real relay. **Real-host, network-simulation, reconnect/watchdog and benchmark results above and below were recorded with the retired ADR 0002 scheme (HPKE + Ed25519) and were not re-run on the OpenPGP tree: UNTESTED there.** GitHub Actions CI has not run on the OpenPGP tree (branch unpublished); the CI runs cited earlier describe the pre-cutover tree. OpenPGP tree at local commit `9a9af9d` (see [docs/compatibility-matrix.md](docs/compatibility-matrix.md)): macOS arm64 (rustc 1.92, Homebrew OpenSSL 3): fmt, clippy, 436 tests passed, 0 failed, 7 relay-gated ignored (`results/final/host-checks-adr0004.txt`); Linux arm64 container (rustc 1.89.0, OpenSSL 3.0.22): locked build, 436 passed, 0 failed (`results/final/linux-arm64-adr0004.txt`); Linux x86_64 native cloud VM (rustc 1.89.0, OpenSSL 3.5.9): fmt, locked build, clippy, 436 passed, 0 failed, plus the rPGP interop crate 4 passed (`results/final/linux-x86_64-adr0004.txt`; an emulated attempt failed because gcc crashed under qemu, `results/final/linux-x86_64-adr0004-attempt1-gcc-segv.txt`); the 7 relay-gated tests pass against the local relay with the node (amd64) under qemu (`results/final/relay-gated-adr0004.txt`, `results/final/relay-discovery-adr0004.txt`); the private-relay acceptance script on one host: 52 PASS, 0 FAIL, 1 UNTESTED (`results/acceptance/20261127T042942Z/`); cargo-deny, MSRV 1.89 build and the rPGP interop run: `results/adr0004/cargo-deny.txt`, `results/adr0004/msrv-1.89-build.txt`, `results/adr0004/interop-rpgp.txt`.
* **A node sidecar is required.** There is no single static binary and no embedded node. Native FFI embedding was only partially explored and is not part of the MVP ([docs/spike-report.md](docs/spike-report.md) section 5, [ADR 0001](docs/adr/0001-transport.md)).
* **The node image is linux/amd64 only**, unsigned as far as verified, pinned by digest, and runs as root in its container. It is `v0.39.2`; newer node releases are untested with the adapter.
* **No forward secrecy, no post-compromise security, no deniability; no global revocation.** Later compromise of a recipient encryption subkey exposes every stored ciphertext addressed to it. Unaudited cryptographic composition. A forward-secret scheme (vodozemac, MLS) is a documented upgrade path that is **not implemented** ([docs/crypto-interface.md](docs/crypto-interface.md)).
* **Revocation is best effort.** Subkey rotation/revocation and identity revocations reach only contacts that are reachable within the TTL/retry limits or receive the document out of band; messages sealed to a destroyed subkey are lost unless re-sealed by their senders. A thief of the primary key can impersonate the owner until peers learn of the tombstone and can issue the tombstone itself.
* **Restoring an old database or importing an identity into a new data directory starts the replay guard**: older messages are held until `max_ttl + clock_skew` has passed or `agentnet doctor --accept-rollback` is run; messages received between the restored copy and the rollback are lost.
* **No groups, no multi-device, no task-delegation tools. Capability discovery is optional and public.** `[discovery]` is off by default; when enabled, agents publish signed capability adverts as **plaintext readable by every node on the relay** on host-authorized topics (best effort, not a global directory, no reputation, results are unverified claims and never add contacts); see [docs/discovery.md](docs/discovery.md). Exercised on the local relay topology (one host, 3 of 3 runs; `results/discovery-relay/`), not cross-machine. One data directory is one identity; the same identity in two places is not detected and would split state.
* **Recovery is bounded** by the relay's Store retention (the verified relay flags keep **1 hour**; the client's 168 h does not extend it), by the message TTL (default 24 h, max 7 d) and by a 20 s clock-skew rule in the Store. After a relay restart live delivery degraded for about 9 minutes in the one observation (cause not found); recovery then relies on Store catch-up. A separate slow reconnect after a silent path loss (the relay keeps a half-open TCP socket for about 22 minutes) has a root cause and a relay-side fix, `net.ipv4.tcp_retries2=6` printed by `agentnet relay print-config`; evidence is single-host simulation only (`results/reconnect/20261126T065412Z/SUMMARY.md`, [docs/network-simulations.md](docs/network-simulations.md)).
* **External review was automated, not human.** Two model-run reviews (`results/review/codex-astra-review.md`, 7 findings, all fixed with tests; `results/review/codex-astra-usability-review.md`, 14 findings, all addressed) were **not** an independent human cryptographic review; that requirement remains open ([docs/crypto-requirements.md](docs/crypto-requirements.md)).
* **REST cache polling model.** The node's relay cache holds 50 messages shared across topics and is read destructively; the daemon polls every 250 ms and loses live frames if it cannot keep up (Store catch-up then recovers within retention). Observed delivery in a 100-client single-process load test ranged from 40.8 % to 100 % depending on poll interval and publish concurrency.
* **Privacy**: relays and observers see the bucket, timing, size, and publisher/subscriber network identity. A bucket's anonymity set is the number of agents sharing it in your deployment.
* **Anyone who can reach the relay's libp2p port and knows the cluster id can join it.** Use a firewall or tailnet policy; the relay has no RLN and no rate limiting.
* **HTTP MCP uses a static bearer token on loopback**, not the MCP OAuth profile; remote exposure is refused by configuration.
* **The node REST API has no authentication**; keep it on loopback. Any local process of any user can reach loopback ports.
* **Unix only.** No Windows. IPv6 loopback paths are not asserted by tests.
* **No third-party MCP host has been tested**, nor the MCP Tasks extension.
* **Hostile load is untested** (flood of a bucket topic, quarantine/inbox saturation under attack at rate); no fuzzing campaign was run beyond property tests.
* The relay-gated tests silently pass when their environment variable is unset (see below).
* Release binary: 18.9 MB (macOS arm64); idle/steady daemon memory and CPU, startup and shutdown times, idle bandwidth and sustainable message rate were **not measured**.

## Running the tests

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked
```

* The relay-gated tests need the local relay topology and are `#[ignore]`d in a plain `cargo test` run (shown as ignored, not passed). To run them against the topology started in quickstart step 2 (or by `scripts/demo.sh`):
  `AGENTNET_RELAY_TESTS=1 cargo test --workspace --locked -- --ignored` (these tests are `#[ignore]`d in a plain run; the
  container-restarting ones additionally need `AGENTNET_RELAY_DISRUPTIVE=1 cargo test -p agentnet-transport --features disruptive-tests --test logos_rest_relay -- --ignored --test-threads=1`).
  Run the disruptive ones last; they restart `an-na` and stop `an-r1`.
  Note: the topology is shared state; do not run them while something else uses the same containers.
* The acceptance script (`scripts/acceptance.sh`) and its results are documented in [docs/acceptance.md](docs/acceptance.md) ("see acceptance results").
* CI: [.github/workflows/ci.yml](.github/workflows/ci.yml) (format, clippy, tests, MSRV 1.89 build, `cargo deny`; plus a manual relay-gated job). The workflow runs on GitHub Actions (`ubuntu-latest`, x86_64) on every push ([latest runs](https://github.com/TheFreeIntelligenceCompany/agentnet/actions)); the manual relay-gated job passed in [run 45846705416](https://github.com/TheFreeIntelligenceCompany/agentnet/actions/runs/45846705416) (6 relay tests, `76e797d`). Those CI runs are of the pre-cutover tree; CI on the OpenPGP tree is **UNTESTED** (branch unpublished). `cargo deny` 0.22.1 on the OpenPGP tree: `results/adr0004/cargo-deny.txt`; inventory in [docs/dependency-audit.md](docs/dependency-audit.md).

## Repository layout

| Path | Contents |
|---|---|
| `crates/core` | identity, addresses, contact records, sealed envelopes, SQLite store, delivery engine, triggers, events, `AgentApi` trait |
| `crates/transport` | `Transport` trait, deterministic mock network, Logos Delivery REST adapter |
| `crates/mcp` | rmcp 3.11.0 server over `AgentApi` (tools, resources, subscriptions, stdio and loopback HTTP) |
| `crates/daemon` | config, data-dir lock, control and event socket, webhook, HTTP MCP, mock harness and embedding examples |
| `crates/cli` | the `agentnet` binary |
| `spike/` | disposable Phase A spikes (own workspaces): `relay` (topology and scripts), `transport-rest`, `transport-ffi`, `libchat-eval`, `e2e-crypto`, `mcp-spike` |
| `results/` | raw evidence: `a1-*`, `a2-*`, `a3-mcp`, `b-*`, `audit/` |
| `docs/` | documentation (below); `docs/spike/` holds the spike notes |
| `upstream/` | local clones of upstream repositories (gitignored) |
| `deny.toml`, `.github/workflows/ci.yml` | dependency policy and CI |
| `goal.md`, `AGENTS.md` | the project brief and working rules |

## Documentation index

| Document | Subject |
|---|---|
| [docs/spike-report.md](docs/spike-report.md) | Phase A evidence report, decision gates, upstream bugs |
| [docs/compatibility-matrix.md](docs/compatibility-matrix.md) | platform, protocol, feature and toolchain matrices |
| [docs/threat-model.md](docs/threat-model.md) | assets, adversaries, mitigations, residual risk, not-claimed list |
| [docs/dependency-audit.md](docs/dependency-audit.md) | dependencies, licences, advisories, native code |
| [docs/architecture.md](docs/architecture.md) | MVP architecture |
| [docs/protocol.md](docs/protocol.md) | normative wire protocol (not yet frozen), delivery semantics, rotation/revocation, replay protection |
| [docs/crypto-interface.md](docs/crypto-interface.md) | the cryptographic module boundary and what a replacement scheme must provide |
| [docs/crypto-requirements.md](docs/crypto-requirements.md) | the owner's 13 conditions on ADR 0002: how each is met, tests, residual gaps |
| [docs/mcp-api.md](docs/mcp-api.md) | MCP tools, resources, versions, limits |
| [docs/host-integration.md](docs/host-integration.md) | control socket, events, webhook |
| [docs/configuration.md](docs/configuration.md) | every `agentnet.toml` key |
| [docs/discovery.md](docs/discovery.md) | optional capability discovery: design, wire format, what relays see, limits, non-goals |
| [docs/runbook.md](docs/runbook.md) | Operations runbook: routine checks, restarts, incident playbooks, backup |
| [docs/network-simulations.md](docs/network-simulations.md) | WireGuard-overlay and NAT simulations (single host), with pointers to the real-host runs |
| [docs/relay-setup.md](docs/relay-setup.md) | running your own relay, Store and client nodes; Tailscale (UNTESTED) |
| [docs/cli-help.txt](docs/cli-help.txt) | generated CLI help |
| [docs/adr/](docs/adr/) | decisions: [0001 transport](docs/adr/0001-transport.md), 0002 encryption, 0003 MCP SDK and version |
| [docs/spike/](docs/spike/) | spike notes: daemon-rest, libchat-and-crypto, e2e-crypto, mcp |
| [docs/acceptance.md](docs/acceptance.md) | acceptance results (written by the acceptance run) |

## Licence

MIT ([LICENSE](LICENSE)), as declared in `Cargo.toml`. The owner chose MIT and open-source publication on 2026-11-26. No trademark search was done for the name "AgentNet".
Name availability facts (crates.io and GitHub) are in [docs/spike-report.md](docs/spike-report.md) section 14; no legal conclusion is drawn there.
Third-party licences: [docs/dependency-audit.md](docs/dependency-audit.md).

### Licensing

The OpenPGP library `sequoia-openpgp` (and `buffered-reader`) is **LGPL-2.0-or-later** and is linked into the `agentnet` binary; it needs OpenSSL 3 (Apache-2.0, a system library) at build and run time. How a distributed binary satisfies the LGPL, what a release must ship, and the maintainers' caveats (not legal advice): [docs/licensing.md](docs/licensing.md) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Quickstart verification

> The runs below were made before the OpenPGP cutover (ADR 0002 scheme). On the OpenPGP tree the full private-relay acceptance script passed once (`results/acceptance/20261127T042942Z/`); `scripts/demo.sh` and the manual quickstart steps were not re-run there (**UNTESTED**).

`scripts/demo.sh` (the first quickstart path) was run three times against the already-running local relay topology on 2026-11-26 (macOS arm64, single host, node image amd64 under qemu, heavily loaded machine): all three exited 0 in 6 to 9 s with readiness in 0 to 2 s and each delivery in 2 to 3 s; the nodes were already warm, so these are not cold-start numbers. A forced readiness timeout exercised the failure path (non-zero exit, daemons stopped, temp directory removed, relay untouched). Starting the relay from cold through the script, and the missing-prerequisite messages, were **not exercised**. Evidence: `results/demo/20261126T152305Z/`.

The manual steps as now worded (explicit wait loops, carried variables, generated MCP configuration) were not re-run as one transcript from step 1. Steps 3 to 6 were extracted from this file and executed as written in one bash shell on 2026-11-26 against the running topology (exit 0, doctor `0 failing, 1 warning(s)`, message `delivered`; `results/demo/20261126T152305Z/manual-steps-3-to-6*`); steps 1 and 2 are unchanged; steps 7 (config printing) and 8 (triggers with the explicit loops) are **UNTESTED in this wording**. The previous wording of every command of the Quickstart was executed against the local relay topology on 2026-11-25 (macOS arm64, rustc 1.92.0, single host) with the script `results/audit/readme-quickstart.sh`; the transcript is `results/audit/readme-quickstart-transcript.log` (`failed steps: 0`: both agents `doctor` all `[ok]`, contacts exchanged, message delivered with an authenticated receipt, MCP `server/discover` over stdio in both argument orders, one-shot trigger consumed once and one simulated turn recorded, daemons stopped). Step 1 (build) is in `results/audit/readme-step1-build.log`.
Deviations from a user's shell: the binary and the harness build used scratch `--target-dir`s because other contributors were building in `./target`; the harness ran from a `git archive HEAD` export; `wait_until` loops stood in for "repeat until it shows". Observed timings in that run: message visible in B's inbox after 2 s, receipt after the next poll, trigger turn recorded after 6 s. An earlier run of the same script (also `failed steps: 0`) took up to 5 s for the inbox. Single run each: not a latency measurement.
