# AgentNet

AgentNet is a Rust service that gives an autonomous agent a durable cryptographic address and lets agents on different machines exchange encrypted, asynchronous messages through relays the user chooses.
It runs as a local daemon (`agentnet serve`) next to a Logos Delivery (Waku) node that carries the messages; recipients that are offline can fetch messages from the relay's Store within its retention window.

It exposes an MCP server (stdio and loopback HTTP) so an MCP client can send, read and discover messages and subscribe to changes, and a separate local event socket and optional signed webhook so a host (harness) can decide whether to wake an agent.
The service never runs a model and never executes message content; a message body is untrusted data.

> **Status:** Experimental MVP, validated on one host. Requires a Logos Delivery sidecar for each agent. Not independently audited; cross-machine operation remains unvalidated. Details: [Status and limitations](#status-and-limitations).

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
* Python 3 (used by the relay start helper).
* `jq` and `curl` for the commands below.
* Unix (macOS, Linux). Windows is not supported.
* A C compiler: `rusqlite` builds SQLite from bundled C source and `ring` (via rustls) compiles C/asm.

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
agentnet --data-dir $A doctor           # expect zero failing checks; the single-instance warning is expected; exit code 7 if any check fails
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
Thirteen tools (`get_identity`, `send_message`, `read_inbox`, `acknowledge_message`, `get_message_status`, `add_contact`, `network_status`, `create_trigger`, `list_triggers`, `delete_trigger`, and the opt-in `advertise_agent`, `withdraw_advert`, `discover_agents`) and five resources; see [docs/mcp-api.md](docs/mcp-api.md).
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
* **public** requires `mode = "public"` and `i_understand_public = true`, skips the peer audit, and is **UNTESTED against any public network**. The REST adapter supports only single-shard networks, which the shared public networks are not. No bridging between modes: one daemon talks to one node in one mode.

Reference configs: [docs/examples/private.toml](docs/examples/private.toml), [docs/examples/public.toml](docs/examples/public.toml); all keys: [docs/configuration.md](docs/configuration.md).

## Running your own relay and Store node

`agentnet relay print-config --ip <relay ip> --peer-id <relay peer id> --client-ip <client ip>` prints the verified flag set and compose snippets. Firewall guidance, nodekey and peer-ID handling, retention, clock requirements, two service nodes and an **UNTESTED** Tailscale deployment are in [docs/relay-setup.md](docs/relay-setup.md).

## Security summary

* Each message is sealed with HPKE (RFC 9180 base mode, X25519 / HKDF-SHA256 / ChaCha20-Poly1305) to the recipient's key and carries an inner Ed25519 signature that names the recipient; sender, type, ids and body are inside the ciphertext. Relays see the recipient's inbox bucket (1 of 16 by default), time, and padded size.
* **No forward secrecy, no post-compromise security, no deniability.** Key rotation (with optional destruction of earlier KEM keys) and a signed identity tombstone exist, but there is no directory and no global revocation list: they reach only peers that receive the notice ([docs/protocol.md](docs/protocol.md) section 9). Secrets are stored in a mode-0600 plaintext file; a compromised host loses everything. No anonymity is claimed.
* Cryptography sits behind one module boundary (`agentnet_core::crypto`, [docs/crypto-interface.md](docs/crypto-interface.md)); the owner's acceptance conditions and their status are in [docs/crypto-requirements.md](docs/crypto-requirements.md). The cipher-suite list is signed into contact records (no silent downgrade), every cryptographic dependency is exact-pinned, and the primitives are checked against published RFC test vectors.
* Replay protection survives restarts and detects a rolled-back store (replay guard); it cannot detect the same identity running in two data directories.
* Remote message bodies are data. Nothing executes them; remote senders cannot create triggers, change policy or set webhook targets. Unknown senders are quarantined by default.
* **Unaudited**: the composition (not just the code) needs an **independent cryptographic review before production use involving sensitive information**; `hpke` has no public third-party audit. Do not describe this implementation as audited, production-secure or forward-secret.

Full analysis: [docs/threat-model.md](docs/threat-model.md). ADR: [docs/adr/0002-end-to-end-encryption.md](docs/adr/0002-end-to-end-encryption.md).

## Status and limitations

Read these before relying on anything here.

* **Experimental MVP; not audited; provisional name.** The cryptographic composition has had no independent review: **an independent cryptographic review is required before any production use involving sensitive information.** The scheme is **not audited, not production-secure and not forward-secret.** The name "AgentNet" is provisional; the licence is MIT (see Licence below).
* **Single-host validation only.** All tests ran on one macOS arm64 machine; containers on one VM; the node image under CPU emulation. Cross-machine, real-NAT, Tailscale and public-network behaviour are **UNTESTED**; WireGuard-overlay and NAT-gateway **simulations on one host** are in docs/network-simulations.md. The relay and clients were also exercised on a real tailnet address on a single host (spike/relay-tailscale); multi-machine, ACL and DERP behaviour is **UNTESTED**. Linux builds: see [docs/compatibility-matrix.md](docs/compatibility-matrix.md) (Linux x86_64: the Rust build and tests passed natively on GitHub Actions `ubuntu-latest` for `76e797d`; the node and relay-gated tests there are UNTESTED).
* **A node sidecar is required.** There is no single static binary and no embedded node. Native FFI embedding was only partially explored and is not part of the MVP ([docs/spike-report.md](docs/spike-report.md) section 5, [ADR 0001](docs/adr/0001-transport.md)).
* **The node image is linux/amd64 only**, unsigned as far as verified, pinned by digest, and runs as root in its container. It is `v0.39.2`; newer node releases are untested with the adapter.
* **No forward secrecy, no post-compromise security, no deniability; no global revocation.** Unaudited cryptographic composition. A forward-secret scheme (vodozemac, MLS) is a documented upgrade path that is **not implemented** ([docs/crypto-interface.md](docs/crypto-interface.md)).
* **Revocation is best effort.** KEM rotation/revocation and identity tombstones reach only contacts that are reachable within the TTL/retry limits or receive the document out of band; messages sealed to a destroyed KEM key are lost unless re-sealed by their senders. A thief of the signing key can impersonate the owner until peers learn of the tombstone and can issue the tombstone itself.
* **Restoring an old database or importing an identity into a new data directory starts the replay guard**: older messages are held until `max_ttl + clock_skew` has passed or `agentnet doctor --accept-rollback` is run; messages received between the restored copy and the rollback are lost.
* **No groups, no multi-device, no task-delegation tools. Capability discovery is optional and public.** `[discovery]` is off by default; when enabled, agents publish signed capability adverts as **plaintext readable by every node on the relay** on host-authorized topics (best effort, not a global directory, no reputation, results are unverified claims and never add contacts); see [docs/discovery.md](docs/discovery.md). Untested on a real relay. One data directory is one identity; the same identity in two places is not detected and would split state.
* **Recovery is bounded** by the relay's Store retention (the verified relay flags keep **1 hour**; the client's 168 h does not extend it), by the message TTL (default 24 h, max 7 d) and by a 20 s clock-skew rule in the Store. After a relay restart live delivery degraded for about 9 minutes in the one observation; recovery then relies on Store catch-up.
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
* CI: [.github/workflows/ci.yml](.github/workflows/ci.yml) (format, clippy, tests, MSRV 1.89 build, `cargo deny`; plus a manual relay-gated job that has not been run on GitHub). The workflow ran on GitHub Actions (`ubuntu-latest`, x86_64) and passed for commit `76e797d`: [run 45845088419](https://github.com/TheFreeIntelligenceCompany/agentnet/actions/runs/45845088419). `cargo deny` was also run in a container and results are in [docs/dependency-audit.md](docs/dependency-audit.md).

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
| [docs/network-simulations.md](docs/network-simulations.md) | WireGuard-overlay and NAT simulations (single host), results, UNTESTED real-run steps |
| [docs/relay-setup.md](docs/relay-setup.md) | running your own relay, Store and client nodes; Tailscale (UNTESTED) |
| [docs/cli-help.txt](docs/cli-help.txt) | generated CLI help |
| [docs/adr/](docs/adr/) | decisions: [0001 transport](docs/adr/0001-transport.md), 0002 encryption, 0003 MCP SDK and version |
| [docs/spike/](docs/spike/) | spike notes: daemon-rest, libchat-and-crypto, e2e-crypto, mcp |
| [docs/acceptance.md](docs/acceptance.md) | acceptance results (written by the acceptance run) |

## Licence

MIT ([LICENSE](LICENSE)), as declared in `Cargo.toml`. The owner chose MIT and open-source publication on 2026-11-26. No trademark search was done for the name "AgentNet".
Name availability facts (crates.io and GitHub) are in [docs/spike-report.md](docs/spike-report.md) section 14; no legal conclusion is drawn there.
Third-party licences: [docs/dependency-audit.md](docs/dependency-audit.md).

## Quickstart verification

`scripts/demo.sh` (the first quickstart path) was run three times against the already-running local relay topology on 2026-11-26 (macOS arm64, single host, node image amd64 under qemu, heavily loaded machine): all three exited 0 in 6 to 9 s with readiness in 0 to 2 s and each delivery in 2 to 3 s; the nodes were already warm, so these are not cold-start numbers. A forced readiness timeout exercised the failure path (non-zero exit, daemons stopped, temp directory removed, relay untouched). Starting the relay from cold through the script, and the missing-prerequisite messages, were **not exercised**. Evidence: `results/demo/20261126T152305Z/`.

The manual steps as now worded (explicit wait loops, carried variables, generated MCP configuration) were not re-run as one transcript from step 1. Steps 3 to 6 were extracted from this file and executed as written in one bash shell on 2026-11-26 against the running topology (exit 0, doctor `0 failing, 1 warning(s)`, message `delivered`; `results/demo/20261126T152305Z/manual-steps-3-to-6*`); steps 1 and 2 are unchanged; steps 7 (config printing) and 8 (triggers with the explicit loops) are **UNTESTED in this wording**. The previous wording of every command of the Quickstart was executed against the local relay topology on 2026-11-25 (macOS arm64, rustc 1.92.0, single host) with the script `results/audit/readme-quickstart.sh`; the transcript is `results/audit/readme-quickstart-transcript.log` (`failed steps: 0`: both agents `doctor` all `[ok]`, contacts exchanged, message delivered with an authenticated receipt, MCP `server/discover` over stdio in both argument orders, one-shot trigger consumed once and one simulated turn recorded, daemons stopped). Step 1 (build) is in `results/audit/readme-step1-build.log`.
Deviations from a user's shell: the binary and the harness build used scratch `--target-dir`s because other contributors were building in `./target`; the harness ran from a `git archive HEAD` export; `wait_until` loops stood in for "repeat until it shows". Observed timings in that run: message visible in B's inbox after 2 s, receipt after the next poll, trigger turn recorded after 6 s. An earlier run of the same script (also `failed steps: 0`) took up to 5 s for the inbox. Single run each: not a latency measurement.
