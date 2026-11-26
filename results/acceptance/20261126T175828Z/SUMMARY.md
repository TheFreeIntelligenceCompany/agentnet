# AgentNet acceptance run 20261126T175828Z

> **Scope: single-host docker-bridge test** (amd64 Logos Delivery node image under qemu on an arm64 Mac;
> relay and both client nodes on one docker bridge, 172.28.66.0/24; agents on the host). It is **NOT** a
> cross-machine, NAT or Tailscale test. Same statement applies to every number below.

Environment: Darwin 25.6.0 arm64; git 0d3258f; rustc 1.92.0 (ded5c06cf 2025-12-08)

Totals: PASS 17, FAIL 0, UNTESTED 0

| Step | Status | Title |
|---|---|---|
| 1 | PASS | Relay/service node, two independent instances, identities, verified contacts |
| 4 | PASS | Authorized one-shot trigger, mock harness, unauthorized senders |

## Step 1: Relay/service node, two independent instances, identities, verified contacts

| Check | Status | Detail |
|---|---|---|
| 1.topology | PASS | R1 (an-r1), NA (an-na), NB (an-nb) healthy; NA and NB connected to R1 only; compose project agentnet-relay, DNS_NS=127.0.0.1 |
| 1.serve | PASS | two release-mode 'agentnet serve' processes (A -> NA http://127.0.0.1:18641, B -> NB http://127.0.0.1:18642), private mode, static peer R1, cluster 66; A=an1qy5hvyaicvltpllirthzvlj4mo3swwzdzxvjs53s5qo6mezo4m4sasmnya B=an1g3lvjuofemuwqfukxmgozwpy4eq6gltku7coz4tb7icwynlbrjysdscr6e |
| 1.contacts | PASS | contact records exchanged with 'contact add @record --expect <address>' in both directions |
| 1.doctor.a | PASS | agentnet doctor exit 0 (see logs/step1-doctor-a.log) |
| 1.netstatus.a | PASS | network status --verbose: private, ready, no isolation violation, exactly one peer = R1 (16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV) |
| 1.doctor.b | PASS | agentnet doctor exit 0 (see logs/step1-doctor-b.log) |
| 1.netstatus.b | PASS | network status --verbose: private, ready, no isolation violation, exactly one peer = R1 (16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV) |
| 1.neg.tamper | PASS | tampered contact record rejected, exit 4: error: invalid contact record: contact record signature does not verify; contact list unchanged |
| 1.neg.expect | PASS | genuine record presented with the wrong --expect address rejected, exit 4: error: contact record is not for the expected address; contact list unchanged |

Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):

```
# 1.topology
cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh   # R1 first, then na+nb
# 1.serve
agentnet --data-dir $A init --node-url http://127.0.0.1:18641 --peer /ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV; agentnet --data-dir $B init --node-url http://127.0.0.1:18642 --peer /ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV; agentnet --data-dir $X serve
# 1.contacts
agentnet --data-dir $A contact add @b.record --expect an1g3lvjuofemuwqfukxmgozwpy4eq6gltku7coz4tb7icwynlbrjysdscr6e; agentnet --data-dir $B contact add @a.record --expect an1qy5hvyaicvltpllirthzvlj4mo3swwzdzxvjs53s5qo6mezo4m4sasmnya
# 1.doctor.a
agentnet --data-dir $A doctor
# 1.netstatus.a
agentnet --json --data-dir $X network status --verbose
# 1.doctor.b
agentnet --data-dir $B doctor
# 1.netstatus.b
agentnet --json --data-dir $X network status --verbose
# 1.neg.tamper
agentnet contact add @tampered.json --expect <B>
# 1.neg.expect
agentnet contact add @b.record --expect <A's address>
```

## Step 4: Authorized one-shot trigger, mock harness, unauthorized senders

| Check | Status | Detail |
|---|---|---|
| 4.policy.disabled | PASS | create_trigger on A (policy.auto_trigger=false): isError, code policy_denied: triggers are disabled by host policy (policy.auto_trigger = false) |
| 4.policy.allowlist | PASS | create_trigger on B for a non-allowlisted session: isError, policy_denied: target_session is not allowlisted by host policy |
| 4.create | PASS | B create_trigger via MCP: trigger fd23765b-fda6-4f8b-b09f-89d672ccd07e (sender A, session demo-session, once=true, state active); negotiated protocol 2026-07-28 |
| 4.one_shot | PASS | exactly ONE simulated turn (harness out file: 1 line) and one trigger.matched event, one inbox row, after 3 republish rounds (each stored frame re-published with fresh timestamps, 5 rounds-of-frames total) and a harness restart mid-way; first turn 599 ms after send |
| 4.consumed | PASS | second matching message (73049283-5229-4b78-8e8b-d8b733d5810f) arrived and is in B's inbox, but the consumed trigger did not fire: turns=1, trigger.matched=1, trigger state consumed |
| 4.unknown | PASS | message from unknown identity C (an1pfjopei2wznrzbm6texrfr5okylwsekwvskgo4jhvjtdbctbmnh4vxlyca) is quarantined on B (not in the default inbox), no ack (C's state: sent), harness turns still 1, and a wildcard trigger (no sender filter) stayed active |
| 4.since_cursor | PASS | reply persisted BEFORE the trigger existed; trigger created with since_cursor fired exactly once (harness turns 1 -> 2, trigger.matched events for it: 1), also after a duplicate republish |
| 4.webhook | PASS | signed delivery from the daemon verified and recorded (1 turn); wrong-secret request -> HTTP 401; stale-timestamp request -> 401; validly signed replay of the delivered event -> 200 with no second turn (1) |

Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):

```
# 4.policy.disabled
agentnet-acceptance mcp-call --data-dir $A --tool create_trigger --args '{"target_session":"demo-session"}'
# 4.policy.allowlist
agentnet-acceptance mcp-call --data-dir $B --tool create_trigger --args '{"target_session":"not-allowed-session",...}'
# 4.create
agentnet-acceptance mcp-call --data-dir $B --tool create_trigger --args '{"target_session":"demo-session","sender":"<A>"}'
# 4.one_shot
mock_harness --data-dir $B --out turns.jsonl --state state.json; agentnet send <B>; curl store + POST relay (x5); kill+restart mock_harness
# 4.consumed
agentnet send <B> trigger-test-2; mcp list_triggers
# 4.unknown
agentnet send <B> (from C, not in B's contacts); agentnet quarantine list; mcp list_triggers
# 4.since_cursor
agentnet send <B>; mcp create_trigger {...,"since_cursor":"<cursor before send>"}
# 4.webhook
mock_harness --webhook 127.0.0.1:19090 --secret-file S; agentnet serve with [webhook] enabled; curl -X POST with X-AgentNet-Signature variants
```

## Evidence index

- `summary.json` (machine readable), `checks.jsonl`, `run.log`
- `logs/` per-step command logs, `evidence/` JSON evidence, `daemon-logs/` redacted daemon stderr (64-hex strings replaced), `pcap/` + `net/` packet captures and summaries
- startup/shutdown times: `evidence/startup-times.tsv`, `evidence/shutdown-times.tsv`
