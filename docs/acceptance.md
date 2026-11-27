# Acceptance demonstration (goal.md section 5)

**Scope, stated once and true for every number in this file: this is a single-host docker-bridge test.** The relay/service
node R1 and the two client nodes NA/NB are amd64 `nwaku v0.39.2` containers run under qemu on an arm64 Mac, on one docker
bridge (172.28.66.0/24, colima). The AgentNet processes run on the host and reach their node through published
loopback ports (127.0.0.1:18641 / 18642). It is **not** a cross-machine, NAT or Tailscale test, and nothing here shows how the
system behaves over a real WAN.

Everything is produced by one script, `scripts/acceptance.sh`, plus the Rust driver `tests/acceptance`
(package `agentnet-acceptance`: rmcp client over `agentnet mcp` stdio children, the daemon crate's `RemoteAgent` and `EventStream`).

## Latest result

> **Note (2026-11-26, ADR 0004).** Message protection changed on 2026-11-26 from HPKE + Ed25519 (ADR 0002, `an1` addresses) to RFC 9580 OpenPGP (ADR 0004, `an2` addresses). All runs recorded in this file (runs 1 to 7, addresses such as `an1...`) were made on the ADR 0002 tree and are kept as dated records. The acceptance script was **not re-run on the OpenPGP tree** (UNTESTED there until a new run is recorded).

Run 7 (`results/acceptance/20261126T180008Z/SUMMARY.md`), executed by the lead on the final tree (git `0d3258f` plus the
script fix described under run 5: both external reviews' fixes, signed advert topics, relay `tcp_retries2=6`),
`FRESH_TOPOLOGY=1`: **52 PASS, 0 FAIL, 1 UNTESTED (Tailscale: this script only looks for a local `tailscale` CLI; the
single-host tailnet-address run is separate, `results/tailscale/20261126T142752Z`).** The figures quoted below are from run 4;
run 7's own numbers are in its SUMMARY.md.

Run 4 (`results/acceptance/20261126T014245Z/SUMMARY.md`), executed by the lead on the merged code at that time: steps 1 to 6 and the
extras PASS (52 checks), Tailscale UNTESTED (not installed, no second host). Selected numbers from that run: 100 messages
each direction at 25 ms pacing were all delivered with 0 duplicate rows or events, send-to-receipt p50/p95/p99 =
12.7 / 13.8 / 13.8 s (A to B) and 5.4 / 11.6 / 13.3 s (B to A); paced at 400 ms: 0.78 / 1.28 / 2.13 s and 0.85 / 1.35 / 1.52 s.
The burst figures are dominated by the relay-mesh warm-up after node recreation and by serial REST publishes
(`results/fixups/burst-latency.md`); they are not typical latencies and not a service level.

## How to run

```
cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh      # optional: the script starts/repairs the topology itself
cd ../.. && scripts/acceptance.sh                        # about 45-50 minutes
STEPS="1 2" scripts/acceptance.sh                        # subset (step 1 always runs)
FRESH_TOPOLOGY=1 scripts/acceptance.sh                   # docker-compose down -v first: wipes R1's store
SKIP_BUILD=1 scripts/acceptance.sh                       # reuse target/release
```

The relay-gated cargo tests are separate and `#[ignore]`d, so a plain `cargo test --workspace --locked` shows them as **ignored**, never as passed. Run them against the live topology with

```
cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh
AGENTNET_RELAY_TESTS=1 cargo test --workspace --locked -- --ignored          # only the relay-gated tests are #[ignore]d in this workspace
# running them with --ignored but without AGENTNET_RELAY_TESTS=1 FAILS with a message; it never passes silently
# the tests that restart/stop containers are not compiled by default; run them last, alone:
AGENTNET_RELAY_TESTS=1 AGENTNET_RELAY_DISRUPTIVE=1 cargo test -p agentnet-transport --features disruptive-tests --test logos_rest_relay -- --ignored --test-threads=1
```

Logs of the last such runs: `results/fixups/test-plain.log` (ignored count visible) and `results/fixups/test-relay-ignored.log`.

Needs docker + standalone `docker-compose`, colima, cargo, `jq`, `curl`, `python3`, `openssl`, `lsof`, `perl`. The script
builds `agentnet`, `agentnet-acceptance` and the daemon examples in release mode, creates data dirs under
`/tmp/an-acc.XXXXXX` (unix socket paths must be short), writes everything to `results/acceptance/<UTC timestamp>/`
(`SUMMARY.md`, `summary.json`, `checks.jsonl`, `logs/`, `evidence/`, `daemon-logs/` with 64-hex strings redacted, `pcap/`,
`net/`), kills its own processes and removes its temp dirs on exit, and leaves R1 with its normal retention and all three
containers running. Exit status is 1 if any check FAILs (UNTESTED does not fail the run). Only containers `an-r1`,
`an-na`, `an-nb` and `an-acc-cap` are touched.

## What it covers

| goal.md section 5 | Script step | What is demonstrated |
|---|---|---|
| 1 | step 1 | relay + two release-mode `agentnet serve` (A on NA, B on NB, private mode, static peer R1, cluster 66), init, contact exchange with `contact add --expect`, `doctor`, `network status --verbose`; negative: tampered record, wrong `--expect` |
| 2 | step 2 | MCP `send_message` (rmcp over stdio, negotiated version recorded), B's `subscriptions/listen` on `agentnet://inbox`, B `read_inbox`, A `get_message_status` timeline to `delivered`, what R1's store saw (topic, size, hash, no plaintext) |
| 3 | step 3 | B daemon and node stopped, 20 messages, recovery via Store with no duplicate rows/events, forced duplicate re-publication; failure cases (a) TTL expiry, (b) relay retention, (c) Store unavailable; E12 measurement |
| 4 | step 4 | `create_trigger` refused when disabled / not allowlisted; one-shot trigger and the mock harness with exactly one simulated turn despite forced duplicates and a harness restart; consumed trigger; unknown sender quarantined; `since_cursor` race; signed webhook mode |
| 5 | step 5 | private-mode config, 125 s tcpdump on the bridge, host-side socket snapshots, relay failure without public fallback, isolation fail-closed, rejected configs, Tailscale (UNTESTED) |
| 6 | step 6 | stdio MCP client configuration launched as written; Rust `embed` example and why the node is a sidecar |
| extras | step X | second `serve` refused, 100 messages each direction with latency percentiles, RSS/CPU, startup/shutdown times, identity export/import migration |

## Runs kept

| Run | Directory | Notes |
|---|---|---|
| 1 | `results/acceptance/20261125T232522Z` | `FRESH_TOPOLOGY=1`. All steps PASS except 6.embed (FAIL, flaky example) |
| 2 | `results/acceptance/20261125T235510Z` | Re-run on the same topology without a reset. **Steps 1 and 6 FAIL** (see "Flakiness") |
| 3 | `results/acceptance/20261126T001904Z` | `FRESH_TOPOLOGY=1`, after a script fix. Final run, table below. Only 6.embed FAIL and the optional Tailscale UNTESTED |
| 4 | `results/acceptance/20261126T014245Z` | Run by the lead on the merged tree (git `7b74ba4`: crypto hardening, retry floor, 15 s history sync, fixed `embed`), `FRESH_TOPOLOGY=1`. **52 PASS, 0 FAIL, 1 UNTESTED (Tailscale).** Step 6 including `embed` (5/5) passes. The per-check table below is still run 3; run 4's own table is its `SUMMARY.md`. |
| 5 | `results/acceptance/20261126T174121Z` | Final tree, `FRESH_TOPOLOGY=1`. 51 PASS, **1 FAIL (4.unknown)**, 1 UNTESTED. The failure was in the script: it parsed `quarantine list --json` as a bare array, and the review fix made that output a paged object (`records`, `next_cursor`). The product behaved correctly (not in the default inbox, harness not woken, no receipt for the sender) |
| 6 | `results/acceptance/20261126T175828Z` | `STEPS="1 4"` after fixing the script: 17 PASS, 0 FAIL |
| 7 | `results/acceptance/20261126T180008Z` | **Latest; run by the lead** on the final tree, `FRESH_TOPOLOGY=1`: **52 PASS, 0 FAIL, 1 UNTESTED (Tailscale)** |
| 8 | `results/acceptance/20261127T042942Z` | **First run on the OpenPGP tree** (ADR 0004: RFC 9580 via Sequoia 2.5.0 + OpenSSL 3; local branch `adr-0004-openpgp`), run by the lead, `FRESH_TOPOLOGY=1`: **52 PASS, 0 FAIL, 1 UNTESTED (Tailscale CLI check)**. Runs 1 to 7 used the retired ADR 0002 scheme |
| 9 | `results/acceptance/20261127T164601Z` | **After the crypto-review fixes** (main at `b3362cc` plus the script change below), run by the lead on a **native Linux x86_64 cloud VM** (the node is not emulated there), `FRESH_TOPOLOGY=1`: **51 PASS, 0 FAIL, 2 UNTESTED** (Tailscale CLI check; `5.host_connections`, whose once-a-second per-process socket snapshot only works on macOS and is recorded as untested on Linux with the reason). A first run on that host failed that one check for the same reason. Not run on macOS for this tree: the Mac had no disk space left to build |

(Three runs rather than two: run 2 exposed a test-hygiene problem in my own script, fixed before run 3. The failing log of run 2 is kept.)

## Results of the final run (run 3)

Step status: 1 PASS, 2 PASS, 3 PASS, 4 PASS, 5 PASS, **6 FAIL** (embed example flaky), extras PASS (all 6 extras checks PASS; `summary.json` of runs 1-3 labels step X UNTESTED only because all its checks are optional and a script quirk, since fixed in the jq, treated an all-optional step as untested; Tailscale, UNTESTED, is part of step 5 and
marked optional). Totals: PASS 51, FAIL 1, UNTESTED 1. Details per check (full text, exact commands: `SUMMARY.md` and `summary.json` in the run directory):

| Check | Status | Detail |
|---|---|---|
| 1.topology | PASS | R1 (an-r1), NA (an-na), NB (an-nb) healthy; NA and NB connected to R1 only; compose project agentnet-relay, DNS_NS=127.0.0.1 |
| 1.serve | PASS | two release-mode 'agentnet serve' processes (A -> NA http://127.0.0.1:18641, B -> NB http://127.0.0.1:18642), private mode, static peer R1, cluster 66; A=an15qfdijdtobcuaqe2gfcx5pbnfxzrwz5ufxqopv7p2aqax3msbmuq66nk7i B=an1sxspj65l64oxixusnqjsibkawn5buhj2gmft6p7zd2zch3rskorbo4yl3i |
| 1.contacts | PASS | contact records exchanged with 'contact add @record --expect <address>' in both directions |
| 1.doctor.a | PASS | agentnet doctor exit 0 (see logs/step1-doctor-a.log) |
| 1.netstatus.a | PASS | network status --verbose: private, ready, no isolation violation, exactly one peer = R1 (16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV) |
| 1.doctor.b | PASS | agentnet doctor exit 0 (see logs/step1-doctor-b.log) |
| 1.netstatus.b | PASS | network status --verbose: private, ready, no isolation violation, exactly one peer = R1 (16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV) |
| 1.neg.tamper | PASS | tampered contact record rejected, exit 4: error: invalid contact record: contact record signature does not verify; contact list unchanged |
| 1.neg.expect | PASS | genuine record presented with the wrong --expect address rejected, exit 4: error: contact record is not for the expected address; contact list unchanged |
| 2.send | PASS | send_message via MCP returned message_id dc83f290-b5f8-463e-9121-728f2ee42758 in 1 ms; negotiated protocol A: 2026-07-28, B: 2026-07-28 |
| 2.notify | PASS | B's subscriptions/listen on agentnet://inbox received a notification 227 ms after send: Some(ResourceUpdatedNotification(Notification { method: ResourceUpdatedNotificationMethod, params: ResourceUpdatedNotificationParam { uri: "agentnet://inbox", meta: None }, extensions: Extensions })) |
| 2.inbox | PASS | B read_inbox shows the message; sender authenticated as A (an15qfdijdtobcuaqe2gfcx5pbnfxzrwz5ufxqopv7p2aqax3msbmuq66nk7i); body matches; read at +509 ms |
| 2.delivered | PASS | A get_message_status timeline: [{"state":"queued","t_ms":1},{"state":"queued","t_ms":1},{"state":"sent","t_ms":43},{"state":"delivered","t_ms":509}]; authenticated receipt (delivered) at +509 ms |
| 2.relay_view | PASS | R1 store holds 3 frame(s) for this exchange: topics ["/agentnet/1/inbox-0a/proto","/agentnet/1/inbox-0c/proto"], payload sizes [564,564,564] bytes; the plaintext marker, message id and both addresses do NOT occur in any stored payload |
| 3.recover | PASS | B recovered all 20 eligible messages via Store within 585 ms of starting the node-up + daemon (R1 held 100 frame(s) for B's topic since test start, i.e. including A's sender retries and the expiring one); inbox rows=20 unique=20 |
| 3.no_dup_events | PASS | B's event log (EventStream replay) has exactly 20 message.received events for the 20 messages, 0 messages with more than one event |
| 3.dup_resend | PASS | re-published every R1-held frame of B's topic 4x with fresh timestamps (ok=100 in last batch; see logs/republish.log): inbox rows stayed 20, event count stayed 21 |
| 3.delivered | PASS | A's 20 statuses reached delivered (took 208 ms after B's inbox was complete) |
| 3.fail.a_ttl | PASS | message sent with --ttl 15 while B was down: A status = expired, B never shows it (0 inbox rows incl. quarantine) |
| 3.fail.b_retention | PASS | history gone: R1 had 3 frame(s), 0 after the retention restart; B (up, history sync running 90 s) recovered 0 of 3. After A's daemon restarted, the sender retry path delivered: B inbox=3/3, A states: delivered=3 , 684 ms after A's daemon start (delivered=1) |
| 3.fail.c_store_down | PASS | R1 down while B came back: B network ready=false, recovered 0/2 during 60 s; after R1 returned B recovered 2/2 (no duplicates, rows=2) 60366 ms after R1's /health, B ready after 6155 ms, A delivered after 60412 ms |
| 3.e12 | PASS | live relay delivery between NA and NB resumed 9212 ms after R1 /health (probe #3); AgentNet delivered after 60412 ms |
| 3.restored | PASS | topology restored: R1 default retention, an-nb running, NA and NB connected to R1 |
| 4.policy.disabled | PASS | create_trigger on A (policy.auto_trigger=false): isError, code policy_denied: triggers are disabled by host policy (policy.auto_trigger = false) |
| 4.policy.allowlist | PASS | create_trigger on B for a non-allowlisted session: isError, policy_denied: target_session is not allowlisted by host policy |
| 4.create | PASS | B create_trigger via MCP: trigger e287675e-be0f-4fd7-b035-cd4f4cbc294f (sender A, session demo-session, once=true, state active); negotiated protocol 2026-07-28 |
| 4.one_shot | PASS | exactly ONE simulated turn (harness out file: 1 line) and one trigger.matched event, one inbox row, after 3 republish rounds (each stored frame re-published with fresh timestamps, 5 rounds-of-frames total) and a harness restart mid-way; first turn 593 ms after send |
| 4.consumed | PASS | second matching message (25f3a05d-f136-4bb5-997b-e9f5d5794066) arrived and is in B's inbox, but the consumed trigger did not fire: turns=1, trigger.matched=1, trigger state consumed |
| 4.unknown | PASS | message from unknown identity C (an1shdt4uypj6whiz22g3t7sfbz4hvexv4lyz4eljg7vm4dzyrqjpnycja6wy) is quarantined on B (not in the default inbox), no ack (C's state: sent), harness turns still 1, and a wildcard trigger (no sender filter) stayed active |
| 4.since_cursor | PASS | reply persisted BEFORE the trigger existed; trigger created with since_cursor fired exactly once (harness turns 1 -> 2, trigger.matched events for it: 1), also after a duplicate republish |
| 4.webhook | PASS | signed delivery from the daemon verified and recorded (1 turn); wrong-secret request -> HTTP 401; stale-timestamp request -> 401; validly signed replay of the delivered event -> 200 with no second turn (1) |
| 5.config | PASS | both agents: mode=private, public_discovery=false, public_fallback=false, cluster_id=66, static peer R1 only (evidence/config-*-excerpt.toml); node flags: all discovery off, --dns-addrs-name-server=127.0.0.1, --nat=extip (spike/relay/docker-compose.yml) |
| 5.node_flags | PASS | R1/NA/NB run with discv5/peer-exchange/rendezvous/kad off, DNS server 127.0.0.1, no dns-discovery-url / entry-node (evidence/node-flags.txt) |
| 5.egress | PASS | tcpdump on the docker bridge, 125 s, whole exchange (A->B and B->A, 12 rounds): 14300 packets, 0 with any IP endpoint outside 172.28.66.0/24 (no DNS to 1.1.1.1 etc.; evidence pcap/egress-exchange.*). Messages: delivered=6  |
| 5.host_connections | PASS | netstat -anv snapshots (every ~1 s for 125 s, TCP+UDP, filtered to the two 'agentnet serve' pids): 6325 socket lines, every remote endpoint is 127.0.0.1 (node REST http://127.0.0.1:18641 / http://127.0.0.1:18642), 0 non-loopback; remote hosts: 6325 127.0.0.1  (net/netstat-*.txt; lsof cross-check in net/lsof-*.txt saw no sockets  |
| 5.relay_failure | PASS | R1 stopped: A's message stayed 'queued' (not delivered), A network status ready=false (node reachable; 0 connected allowed peer(s)), B received 0; capture of the whole outage+recovery: 0 packets with an endpoint outside 172.28.66.0/24 (no fallback destination appeared) |
| 5.relay_failure_no_new_dest | PASS | relay-failure capture: 0 packets with an endpoint outside 172.28.66.0/24 (pcap/egress-relay-failure.egress.txt) |
| 5.relay_recovery | PASS | R1 restarted: the queued message was delivered 7523 ms after R1 /health (E12: live relay can lag after an R1 restart; the sender retry/history path delivered) |
| 5.isolation | PASS | daemon whose only allowlisted peer is a WRONG peer id (16Uiu2HAmHGZ74cqntxJ27NBVKP9BSqKk3A691AxEvWTcWiqGaZtW): network status ready=false, isolation_violation="node is connected to 1 peer(s) not in the allowlist (e.g. 16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV)"; its send stayed 'queued' and B received 0; B's message  |
| 5.reject.public_discovery | PASS | startup refused, exit 4: error: invalid configuration: network.public_discovery = true is not allowed in private mode |
| 5.reject.public_fallback | PASS | startup refused, exit 4: error: invalid configuration: network.public_fallback = true is never allowed: there is no public fallback |
| 5.reject.public_node_url | PASS | startup refused, exit 4: error: invalid configuration: network: isolation violation: private mode: node_url host must be loopback, RFC1918, 100.64.0.0/10, IPv6 loopback/ULA or the literal 'localhost' (names are not resolved) |
| 5.reject.cluster_id_1 | PASS | startup refused, exit 4: error: invalid configuration: network: isolation violation: private mode: cluster id 1 selects a public preset |
| 5.tailscale (optional) | UNTESTED | tailscale not installed on this host (command -v tailscale: not found); no tailnet, no second host. Reproducible steps below. Nothing is claimed to work. |
| 6.mcp_config | PASS | stdio MCP client configuration emitted (evidence/mcp-client-config.json, template in .template.json); launched exactly its command+args with an rmcp client, negotiated 2026-07-28, tools/list = 10 tools, get_identity returned A's address |
| 6.embed | FAIL | embed example (release build) succeeded only 0/5 times; failure text: 'the message was not delivered in time' (the debug build passes). Product bug candidate, not worked around: evidence/step6-embed-output.txt |
| 6.embed_statement | PASS | statement why the adapter cannot be fully embedded (the node is a sidecar) saved to evidence/step6-embedding-statement.txt and quoted in SUMMARY.md |
| X.second_serve (optional) | PASS | second 'agentnet serve' on A's data dir refused, exit 1: error: another AgentNet process is using this data directory (lock held on /tmp/an-acc.QyyNfM/a/lock); stop it first (one data directory = one agent identity = one process) |
| X.bench100 (optional) | PASS | 100 messages each direction (concurrent, 25 ms pacing, full stack): A->B delivered 100/100 p50/p95/p99 = 30648/31899/32007 ms; B->A delivered 100/100 p50/p95/p99 = 10050/21414/24750 ms; receiver rows A->B 100 (unique 100), B->A 100 (unique 100), duplicate message.received events 0. Latency = delivered_at - created_at in the send |
| X.resources (optional) | PASS | daemon RSS after bench: A 9296 KiB, B 8496 KiB; peak sampled %CPU during bench (ps pcpu, 2 s samples): 7.6; raw: evidence/ps-*.txt. Idle/before snapshot:   6736   0.1;  6384   0.1; |
| X.bench100_paced (optional) | PASS | same workload paced at 400 ms per send per direction: A->B delivered 100/100 p50/p95/p99 = 387/499/508 ms; B->A delivered 100/100 p50/p95/p99 = 386/500/508 ms |
| X.startup_shutdown (optional) | PASS | daemon startup (spawn -> network ready) and SIGTERM -> exit times: evidence/startup-times.tsv, evidence/shutdown-times.tsv; first-start times: a=119ms b=163ms c=49ms b=48ms b=48ms  |
| X.migrate (optional) | PASS | identity exported (age passphrase file) with the daemon stopped, imported into a fresh data dir: same address (an15fdtczaydonoiim62v5wncmefiabxprtlw3fs7c7gcb2l2qbsobsb3gotu); a message A sent after the old instance stopped and before the import was recovered from Store and decrypted by the NEW instance with sender authenticated  |

Evidence index (run 3): step 2 `evidence/step2-mcp.json`, `evidence/r1-relay-view.json`; step 3 `evidence/step3-b-dump*.json`,
`step3-retention.json`, `step3c-store-unavailable.json`, `step3c-live-relay-resume.json`, `step3c-b-network-status-r1-down.json`;
step 4 `evidence/harness-turns-*.jsonl`, `step4-*.json`; step 5 `pcap/egress-*.{pcap,egress.txt,flows.txt,dns.txt,packets.txt}`,
`net/netstat-*.txt`, `evidence/step5-*.json`; step 6 `evidence/mcp-client-config.json`, `step6-embed-output.txt`; extras
`evidence/bench-100*.json`, `ps-*.txt`, `migration.json`, `startup-times.tsv`, `shutdown-times.tsv`. All under
`results/acceptance/20261126T001904Z/`.

## Measured numbers (single host, qemu, loopback + bridge)

Latencies include qemu emulation of the node and the daemon's 250 ms poll interval. Sample sizes are 1 per cell unless noted.

| Quantity | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| step 2: send_message returned / B notification / B read_inbox / A `delivered` (ms) | 11 / 943 / 1161 / 1157 | 3 / 209 / 470 / 469 | 1 / 227 / 509 / 509 |
| 3 main: B inbox complete after node+daemon start (ms) | 62222 | 56087 | 585 |
| 3(b): frames in R1 for B's topic before / after retention restart; B recovered while A down; A daemon start to all delivered (ms) | 4 / 0; 0/3; 5994 | 3 / 0; 0/3; 1893 | 3 / 0; 0/3; 684 |
| 3(c): R1 /health to B ready / B has both / A delivered (ms) | 5858 / 31884 / 31971 | 2086 / 59496 / 59524 | 6155 / 60366 / 60412 |
| E12 raw relay path NA to NB resumed after R1 /health (ms, probes every 3 s) | 11254 | 9432 | 9212 |
| 5: message queued during R1 outage, delivered after R1 /health (ms) | 22439 | 64327 | 7523 |
| 5: bridge packets in the 125 s exchange capture / outside 172.28.66.0/24 | 15130 / 0 | 13492 / 0 | 14300 / 0 |
| 100 per direction, burst (25 ms pacing, both directions concurrently): p50 / p95 / p99 ms A to B | 25544 / 76261 / 76964 | 237 / 386 / 492 | 30648 / 31899 / 32007 |
| same, B to A | 23627 / 37336 / 41704 | 339 / 447 / 478 | 10050 / 21414 / 24750 |
| 100 per direction, paced 400 ms: p50 / p95 / p99 ms A to B | 326 / 9988 / 34086 | 219 / 331 / 418 | 387 / 499 / 508 |
| same, B to A | 360 / 11101 / 46636 | 317 / 432 / 448 | 386 / 500 / 508 |
| daemon startup to ready, ms (first start of A / B) | 867 / 1066 | 639 / 695 | 119 / 163 |
| daemon shutdown after SIGTERM, ms | 119 to 252 | 12 to 153 | 11 to 130 |
| daemon RSS after the benchmark (KiB) | 8144 / 9152 | 8768 / 8944 | 9136 / 8320 |

All 100/100 delivered, 0 duplicate inbox rows, 0 duplicate `message.received` events in every run. Peak sampled CPU of a daemon during the
benchmark: 2.5 to 25 % (one `ps -o pcpu` sample, 2 s interval; run 3 peak 25.3 %). Latency = `delivered_at - created_at` in the sender's own outbox
row (send to authenticated receipt). The "R1 held 100 frames" figure in 3.recover is a floor: the Store query page size is 100 and A's retries
(base 2 s, doubling) re-publish each message repeatedly, so R1 holds many copies of the 21 messages; B still ends with 20 rows and 20 events.

## Failure cases, explained (step 3)

**(a) TTL expiry.** A message sent with `--ttl 15` while B was down was still in R1's store when B came back (R1 keeps frames for an hour), but B refuses an
envelope whose signed `expires_at` has passed, and the sender, which never got an authenticated receipt, marks it `expired` once `expires_at` passes.
Outcome in all three runs: A `expired`, B has no row for it (not even quarantined), no event.

**(b) Relay retention.** R1 was recreated with `R1_RETENTION=time:30` after A's three messages were stored and aged 40 s (pruning only runs at start and
every 30 min, `spike/relay/scripts/demo-retention.sh`). R1 then held 0 frames for B's topic. With A's daemon stopped (no sender retries), B came up and ran
history sync for 90 s (longer than the 60 s sync interval) and recovered 0 of 3: **history outside relay retention is not recoverable from Store**. When A's
daemon was started again, its durable outbox retried the three messages (still inside their 24 h TTL), they were re-published, B received 3/3 and A ended
`delivered` 0.7 to 6 s after A's daemon was ready. So what actually happens is: Store gives nothing, the sender's retry still delivers within TTL.
A message whose TTL has also passed, or whose sender has lost its outbox, would be lost; AgentNet promises recovery only within relay retention and sender TTL.
R1 was recreated again with the default retention immediately afterwards.

**(c) Store unavailable.** With the two messages already stored in R1 and B (daemon and node) down, R1 was stopped, then B's node and daemon were started. For 60 s B
reported `ready=false` ("node reachable; 0 connected allowed peer(s)"), recovered 0 of 2, and nothing was delivered. After R1 returned, B was ready after 2 to 6 s
but received the messages only 31.9 s, 59.5 s and 60.4 s after R1's /health (runs 1 to 3), and A reported `delivered` within about 0.1 s after that.
The 60 s values coincide with the `history_sync_interval_s = 60` that was the default when these runs were made (the current default is 15 s), i.e. B's periodic Store sync, not live relay; run 1's 31.9 s is presumably a sender retry
landing earlier. I did not instrument which path delivered it, so that attribution is an inference.

**E12 (live relay after an R1 restart).** Measured independently of AgentNet with a probe frame published on NA every 3 s and polled on NB: live relay between NA and NB
resumed 9.2 to 11.3 s after R1's /health in all three runs (3 probes). That is much shorter than the "several minutes" recorded in E12, which was measured with
earlier, differently-driven restarts; here the adapter's redial brought the clients back in seconds and the mesh was usable almost immediately. I cannot say why
E12 saw minutes; do not conclude from three runs that the problem is gone. Even so, in this test delivery of the queued messages took 7.5 s to 64 s after R1's return (step 5) and
31.9 to 60.4 s (step 3c), so sender retries plus history sync, not live relay, determined the delivery time.

## Tailscale (UNTESTED)

`command -v tailscale` finds nothing on this host, and there is no second host or tailnet. **Not tested; nothing is claimed.** Reproduction steps: (1) join the relay host to the
tailnet and tag it `tag:agentnet-relay`; (2) start R1 with `--nat=extip:<relay 100.x.y.z>` and every discovery flag off (`agentnet relay print-config --ip <100.x> --peer-id <R1 id>` prints
the flags and a compose file, itself marked UNTESTED); (3) tailnet ACL `{"acls":[{"action":"accept","src":["tag:agentnet-agent"],"dst":["tag:agentnet-relay:60000"]}]}` so only tagged agent hosts reach
tcp/60000 and the node REST port is never exposed; (4) each agent host runs a client node with `--staticnode=/ip4/<100.x>/tcp/60000/p2p/<R1 id>` and `agentnet init --node-url http://127.0.0.1:8645 --peer
/ip4/<100.x>/tcp/60000/p2p/<R1 id>` (private mode accepts 100.64.0.0/10); (5) repeat steps 1, 2, 3 by hand. The script has **no** `RELAY_HOST` override (it hard-codes the local topology), so
the instruction in the task to run the same script against a tailnet is not implemented. Tailscale provides encrypted transport and machine-level ACLs only; its coordination service sees metadata.

## Step 6: why the node cannot be embedded

The selected transport is an adapter to a separately running Logos Delivery (nwaku) node over its REST API (ADR 0001): a Nim program that must run as a sidecar next to the harness.
The Rust engine (identity, envelopes, SQLite inbox/outbox, retries, triggers, events, `AgentApi`) can be embedded, which the `embed` example does on the in-memory `MockNetwork`;
swapping in `LogosRestTransport` is a two-line change but still needs the sidecar. Embedding the node itself needs native FFI bindings, which remain a future option behind the same `Transport` trait.

## FAIL, UNTESTED and flakiness (candid)

* **6.embed FAIL: fixed in working tree.** Root cause (in the example, not in `crates/core`): `embed` spawned the two `Node::run` loops and sent immediately. `Node::run` subscribes lazily inside its receive task,
  so a frame published before the recipient's first poll is accepted by the (mock) network but never reaches its live queue ("accepted but lost"), and recovery needs a retry (the backoff never elapses: the example's `MockClock` is frozen) or a
  history pass (every `history_sync_interval_s` of real time): the release build, which starts the tasks fast enough to lose the race, failed most runs; the debug build mostly won it. Fix: call `step_receive()` once on both engines (which subscribes) before
  spawning `run` and sending. Evidence: the old variant without it passed 12/20 in release; the fixed example passes 50/50 in release and 50/50 in debug (`results/fixups/embed-loop.log`).
* **Run 2, step 1 FAIL (my script, fixed).** Run 2 reused the topology after run 1's isolation test. That test points a daemon at a wrong peer id; the adapter POSTs the configured static peer to the shared
  node NA, whose peer store then kept a `CannotConnect` entry (`/ip4/172.28.66.10/tcp/60000/p2p/<R2 id>`). In run 2 agent A's `doctor` therefore failed `peers == allowlist` (exit 7) and
  `network status` listed two peers. Fix in the script: restart `an-na`/`an-nb` after the isolation test and before a run if a node knows any peer other than R1. Logs: run 2 `logs/step1-doctor-a.log`, `evidence/network-status-a.json`.
  Product-side observation: a daemon whose config lists a peer pollutes the shared node's peer store; a second agent on the same node then sees that peer. This is why sharing one node between agents is unsupported (**one node per agent**, `docs/relay-setup.md` sections 1 and 4a): the same cache and peer set are shared, and two daemons whose inbox buckets collide on one node drain each other's frames from the destructive REST cache (delayed delivery through history sync, not loss). `doctor`'s `peers == allowlist` check should flag only *connected* non-allowlisted peers as failures (the adapter's audit already does) and list not-connected unknown entries as a warning: a change in `crates/cli/src/doctor.rs`, pending.
* **Burst latency is bimodal: explained, see `results/fixups/burst-latency.md`.** The bimodality (p50 0.2 to 0.5 s versus 24 to 31 s, p95/p99 about 60 s) is a warm versus a recently restarted topology: after a client node is
  (re)created, live relay between client nodes does not work for about 62 s (3 of 3 trials), so a burst in that window is delivered only by sender retries or by the recipient's history sync (60 s when measured; the default is now 15 s). The 50-slot node cache
  overflows when 100 frames arrive between polls (30 to 50 survive in a node-level probe) and was raised to 1000, but it was a secondary cause. `history_sync_interval_s = 10` brought the cold-start p50 from 59.5 s to 10 to 19 s.
  All 100/100 were delivered in every run. The percentiles in the table above are therefore "cold topology" in runs 1 and 3 and "warm" in run 2; do not quote any of them as typical.
* **Host-side evidence.** `lsof -nP -i -a -p <pid>` shows nothing for the daemons: their loopback connections are short-lived (the REST adapter opened a new TCP connection per request, thousands of TIME_WAIT sockets per
  run on 127.0.0.1:18641/18642). The script therefore uses `netstat -anv -p tcp|udp`, which names the owning process, sampled about every second (5000+ socket lines per run, all 127.0.0.1); `lsof` snapshots are kept in `net/lsof-*.txt` as the empty cross-check.
  Daemons only prove their own sockets; the node containers' egress is covered by the bridge capture (0 packets outside 172.28.66.0/24, 0 DNS queries, with `DNS_NS=127.0.0.1`).
* **Capture limits.** tcpdump runs on the docker bridge inside the colima VM; it cannot see traffic that leaves the VM by another interface. Snaplen 128. The "0 packets" claim is about that bridge only.
* Step 3 recovery time ranges from 0.6 s to 66 s for the same action across runs (node start-up and connection to R1 under qemu); do not read one value as typical.
* Not tested at all: public network, public mode, Tailscale, a second service node, cross-machine/NAT, Linux or Windows hosts, third-party MCP hosts (rmcp client only), Streamable HTTP MCP (not part of this script).
