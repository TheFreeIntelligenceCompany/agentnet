# AgentNet acceptance run 20261127T164601Z

> **Scope: single-host docker-bridge test** (amd64 Logos Delivery node image under qemu on an arm64 Mac;
> relay and both client nodes on one docker bridge, 172.28.66.0/24; agents on the host). It is **NOT** a
> cross-machine, NAT or Tailscale test. Same statement applies to every number below.

Environment: Linux 6.18.60-instabox x86_64; git none; rustc 1.92.0 (ded5c06cf 2025-12-08)

Totals: PASS 51, FAIL 0, UNTESTED 2

| Step | Status | Title |
|---|---|---|
| 1 | PASS | Relay/service node, two independent instances, identities, verified contacts |
| 2 | PASS | MCP send_message, subscription notification, authenticated receipt |
| 3 | PASS | Recipient offline: Store recovery, no duplicates, failure cases |
| 4 | PASS | Authorized one-shot trigger, mock harness, unauthorized senders |
| 5 | PASS | Private network: egress, relay failure without fallback, isolation, Tailscale |
| 6 | PASS | Generic MCP client configuration and Rust embedding |
| X | PASS | Extras (not part of goal.md section 5) |

## Step 1: Relay/service node, two independent instances, identities, verified contacts

| Check | Status | Detail |
|---|---|---|
| 1.topology | PASS | R1 (an-r1), NA (an-na), NB (an-nb) healthy; NA and NB connected to R1 only; compose project agentnet-relay, DNS_NS=127.0.0.1 |
| 1.serve | PASS | two release-mode 'agentnet serve' processes (A -> NA http://127.0.0.1:18641, B -> NB http://127.0.0.1:18642), private mode, static peer R1, cluster 66; A=an2awqdofzne6dsx37qibbhq2i4pyp3h6e7a725than23uymhlkjelpcvo45m B=an2zutsuetgzbdg54sxu7zvki57xwwwpfok5esasrs263rtx6th23szulrurq |
| 1.contacts | PASS | contact records exchanged with 'contact add @record --expect <address>' in both directions |
| 1.doctor.a | PASS | agentnet doctor exit 0 (see logs/step1-doctor-a.log) |
| 1.netstatus.a | PASS | network status --verbose: private, ready, no isolation violation, exactly one peer = R1 (16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV) |
| 1.doctor.b | PASS | agentnet doctor exit 0 (see logs/step1-doctor-b.log) |
| 1.netstatus.b | PASS | network status --verbose: private, ready, no isolation violation, exactly one peer = R1 (16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV) |
| 1.neg.tamper | PASS | tampered contact record rejected, exit 4: error: invalid contact certificate: the certificate has no valid self-signature under the policy; contact list unchanged |
| 1.neg.expect | PASS | genuine record presented with the wrong --expect address rejected, exit 4: error: contact certificate is not for the expected address; contact list unchanged |

Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):

```
# 1.topology
cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh   # R1 first, then na+nb
# 1.serve
agentnet --data-dir $A init --node-url http://127.0.0.1:18641 --peer /ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV; agentnet --data-dir $B init --node-url http://127.0.0.1:18642 --peer /ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV; agentnet --data-dir $X serve
# 1.contacts
agentnet --data-dir $A contact add @b.record --expect an2zutsuetgzbdg54sxu7zvki57xwwwpfok5esasrs263rtx6th23szulrurq; agentnet --data-dir $B contact add @a.record --expect an2awqdofzne6dsx37qibbhq2i4pyp3h6e7a725than23uymhlkjelpcvo45m
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

## Step 2: MCP send_message, subscription notification, authenticated receipt

| Check | Status | Detail |
|---|---|---|
| 2.send | PASS | send_message via MCP returned message_id 881b362a-034a-46e8-aaae-d3843f41e256 in 2 ms; negotiated protocol A: 2026-07-28, B: 2026-07-28 |
| 2.notify | PASS | B's subscriptions/listen on agentnet://inbox received a notification 92 ms after send: Some(ResourceUpdatedNotification(Notification { method: ResourceUpdatedNotificationMethod, params: ResourceUpdatedNotificationParam { uri: "agentnet://inbox", meta: None }, extensions: Extensions })) |
| 2.inbox | PASS | B read_inbox shows the message; sender authenticated as A (an2awqdofzne6dsx37qibbhq2i4pyp3h6e7a725than23uymhlkjelpcvo45m); body matches; read at +352 ms |
| 2.delivered | PASS | A get_message_status timeline: [{"state":"queued","t_ms":2},{"state":"queued","t_ms":3},{"state":"sent","t_ms":46},{"state":"delivered","t_ms":351}]; authenticated receipt (delivered) at +351 ms |
| 2.relay_view | PASS | R1 store holds 2 frame(s) for this exchange: topics ["/agentnet/1/inbox-00/proto","/agentnet/1/inbox-07/proto"], payload sizes [2197,2197] bytes; the plaintext marker, message id and both addresses do NOT occur in any stored payload |

Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):

```
# 2.send
agentnet-acceptance step2 --a $A --b $B --b-addr an2zutsuetgzbdg54sxu7zvki57xwwwpfok5esasrs263rtx6th23szulrurq   # rmcp client over 'agentnet mcp' stdio: get_identity, B subscriptions/listen agentnet://inbox, A send_message, B read_inbox, A get_message_status
# 2.notify
agentnet-acceptance step2 --a $A --b $B --b-addr an2zutsuetgzbdg54sxu7zvki57xwwwpfok5esasrs263rtx6th23szulrurq   # rmcp client over 'agentnet mcp' stdio: get_identity, B subscriptions/listen agentnet://inbox, A send_message, B read_inbox, A get_message_status
# 2.inbox
agentnet-acceptance step2 --a $A --b $B --b-addr an2zutsuetgzbdg54sxu7zvki57xwwwpfok5esasrs263rtx6th23szulrurq   # rmcp client over 'agentnet mcp' stdio: get_identity, B subscriptions/listen agentnet://inbox, A send_message, B read_inbox, A get_message_status
# 2.delivered
agentnet-acceptance step2 --a $A --b $B --b-addr an2zutsuetgzbdg54sxu7zvki57xwwwpfok5esasrs263rtx6th23szulrurq   # rmcp client over 'agentnet mcp' stdio: get_identity, B subscriptions/listen agentnet://inbox, A send_message, B read_inbox, A get_message_status
# 2.relay_view
curl 'http://127.0.0.1:18640/store/v3/messages?contentTopics=<B inbox topic>&includeData=true&startTime=<ns>' | base64-decode payloads, search for the marker (evidence/r1-relay-view.json)
```

## Step 3: Recipient offline: Store recovery, no duplicates, failure cases

| Check | Status | Detail |
|---|---|---|
| 3.recover | PASS | B recovered all 20 eligible messages via Store within 556 ms of starting the node-up + daemon (R1 held 100 frame(s) for B's topic since test start, i.e. including A's sender retries and the expiring one); inbox rows=20 unique=20 |
| 3.no_dup_events | PASS | B's event log (EventStream replay) has exactly 20 message.received events for the 20 messages, 0 messages with more than one event |
| 3.dup_resend | PASS | re-published every R1-held frame of B's topic 4x with fresh timestamps (ok=100 in last batch; see logs/republish.log): inbox rows stayed 20, event count stayed 21 |
| 3.delivered | PASS | A's 20 statuses reached delivered (took 217 ms after B's inbox was complete) |
| 3.fail.a_ttl | PASS | message sent with --ttl 15 while B was down: A status = expired, B never shows it (0 inbox rows incl. quarantine) |
| 3.fail.b_retention | PASS | history gone: R1 had 3 frame(s), 0 after the retention restart; B (up, history sync running 90 s) recovered 0 of 3. After A's daemon restarted, the sender retry path delivered: B inbox=3/3, A states: delivered=3 , 1163 ms after A's daemon start (delivered=1) |
| 3.fail.c_store_down | PASS | R1 down while B came back: B network ready=false, recovered 0/2 during 60 s; after R1 returned B recovered 2/2 (no duplicates, rows=2) 10245 ms after R1's /health, B ready after 8184 ms, A delivered after 10278 ms |
| 3.e12 | PASS | live relay delivery between NA and NB resumed 15233 ms after R1 /health (probe #5); AgentNet delivered after 10278 ms |
| 3.restored | PASS | topology restored: R1 default retention, an-nb running, NA and NB connected to R1 |

Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):

```
# 3.recover
docker stop an-nb; agentnet send x20 (A); docker start an-nb; agentnet serve (B); agentnet-acceptance dump --data-dir $B
# 3.no_dup_events
agentnet-acceptance dump (EventStream)
# 3.dup_resend
curl store v3 | POST http://127.0.0.1:18642/relay/v1/auto/messages (fresh timestamp) x4
# 3.delivered
agentnet --json status <id> (x20)
# 3.fail.a_ttl
agentnet send <B> s3-ttl-expiring --ttl 15 (B down for >25 s)
# 3.fail.b_retention
docker-compose up -d --force-recreate r1 with R1_RETENTION=time:30 (A daemon stopped, B down); start B; wait 90 s; start A
# 3.fail.c_store_down
docker stop an-r1; docker start an-nb; agentnet serve (B); wait 60 s; docker start an-r1; poll
# 3.e12
evidence/step3c-live-relay-resume.json (probe loop in scripts/acceptance.sh: measure_live_resume)
# 3.restored
docker-compose up -d --force-recreate r1 (default env)
```

**Note (3.main).** While B (daemon and node an-nb) was down A sent 20 messages (conversation s3) and one with --ttl 15. A's states right after sending: sent=21 .

**Note (3.fail.a_ttl).** (a) TTL expiry: the frame was still in R1's store when B came back (retention 1 h >> 15 s TTL), but B's receive path rejects an envelope whose signed expires_at has passed; the sender, which never got an authenticated receipt, moves it to `expired` after expires_at instead of retrying forever. Recipient and sender agree: the message was not delivered and is not visible.

**Note (3.fail.b_retention).** (b) R1 recreated with R1_RETENTION=time:30 (pruning runs at start and every 30 min only, see spike/relay/scripts/demo-retention.sh): frames of B's topic in R1 since the test began: before=3, after the restart=0. A's three messages were in state 'sent=3 ' and A's daemon was stopped so that no sender retry could refill the store.

**Note (3.fail.b_retention).** (b) Outside relay retention the recipient cannot recover from Store: with the sender not running B got 0/3. The sender keeps the message in its durable outbox and retries until `expires_at` (default TTL 24 h, max 20 attempts, backoff cap 5 min), so once A was running again the messages were re-published and B received 3/3; A ended as: delivered=3 . A message whose TTL has also run out, or whose sender is gone, would be lost: AgentNet promises recovery only within relay retention AND sender TTL, not unlimited offline delivery. R1 was recreated again with the default retention right after this.

**Note (3.fail.c_store_down).** (c) With R1 down B's node cannot be queried for history and no relay path exists, so nothing is recovered and `network status` reports the degraded state (evidence/step3c-b-network-status-r1-down.json). Nothing was lost: A's messages were already in R1's persistent store (sqlite volume) and in A's outbox. After R1 returned they reached B after 10245 ms (via A's retry and/or B's periodic history sync, whichever fired first) and A's status reached delivered after 10278 ms.

**Note (3.fail.c_store_down).** E12 measurement (raw relay path, independent of AgentNet: a probe frame published every 3 s on NA, polled on NB): live relay delivery between NA and NB resumed 15233 ms after R1 /health (probe #5). AgentNet-level: B had both messages after 10245 ms, A delivered after 10278 ms, i.e. sender retries and history sync did deliver regardless of the live path.


## Step 4: Authorized one-shot trigger, mock harness, unauthorized senders

| Check | Status | Detail |
|---|---|---|
| 4.policy.disabled | PASS | create_trigger on A (policy.auto_trigger=false): isError, code policy_denied: triggers are disabled by host policy (policy.auto_trigger = false) |
| 4.policy.allowlist | PASS | create_trigger on B for a non-allowlisted session: isError, policy_denied: target_session is not allowlisted by host policy |
| 4.create | PASS | B create_trigger via MCP: trigger 3fccf9f6-99c2-4af1-8c30-f4dea4e159b2 (sender A, session demo-session, once=true, state active); negotiated protocol 2026-07-28 |
| 4.one_shot | PASS | exactly ONE simulated turn (harness out file: 1 line) and one trigger.matched event, one inbox row, after 3 republish rounds (each stored frame re-published with fresh timestamps, 5 rounds-of-frames total) and a harness restart mid-way; first turn 546 ms after send |
| 4.consumed | PASS | second matching message (9eab7ec6-0de5-46bb-86fb-08cc599526b8) arrived and is in B's inbox, but the consumed trigger did not fire: turns=1, trigger.matched=1, trigger state consumed |
| 4.unknown | PASS | message from unknown identity C (an2me7rvxipo6sttvhphsvqghphnj25cbuq44vqr4hskxikeqxwphl7o2uriy) is quarantined on B (not in the default inbox), no ack (C's state: sent), harness turns still 1, and a wildcard trigger (no sender filter) stayed active |
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

## Step 5: Private network: egress, relay failure without fallback, isolation, Tailscale

| Check | Status | Detail |
|---|---|---|
| 5.config | PASS | both agents: mode=private, public_discovery=false, public_fallback=false, cluster_id=66, static peer R1 only (evidence/config-*-excerpt.toml); node flags: all discovery off, --dns-addrs-name-server=127.0.0.1, --nat=extip (spike/relay/docker-compose.yml) |
| 5.node_flags | PASS | R1/NA/NB run with discv5/peer-exchange/rendezvous/kad off, DNS server 127.0.0.1, no dns-discovery-url / entry-node (evidence/node-flags.txt) |
| 5.egress | PASS | tcpdump on the docker bridge, 125 s, whole exchange (A->B and B->A, 12 rounds): 14635 packets, 0 with any IP endpoint outside 172.28.66.0/24 (no DNS to 1.1.1.1 etc.; evidence pcap/egress-exchange.*). Messages: delivered=6  |
| 5.host_connections (optional) | UNTESTED | Linux: 1 s Netid State Recv-Q Send-Q                                                                      Local Address:Port   Peer Address:Port   u_str ESTAB 0      0                                                             /run/dbus/system_bus_socket 5683              * 1443   u_dgr ESTAB 0      0                                                                                       * 1457              * 4375   u_str ESTAB 0      0                                                                                       * 234409            * 236027 u_str ESTAB 0      0                                                             /run/systemd/journal/stdout 6333              * 3376   u_dgr ESTAB 0      0                                                                                       * 4357              * 4358   u_dgr ESTAB 0      0                                                                                       * 1204              * 1205   u_str ESTAB 0      0                                                             /run/systemd/journal/stdout 7288              * 5266   u_dgr ESTAB 0      0                                                                                       * 4358              * 4357   u_str ESTAB 0      0                                                                                       * 7438              * 6587   u_dgr ESTAB 0      0                                                                     /run/systemd/notify 4352              * 0      u_dgr ESTAB 0      0                                                                                       * 1530              * 1531   u_str ESTAB 0      0                                                                                       * 4641              * 6589   u_dgr ESTAB 0      0                                                            /run/systemd/journal/dev-log 4374              * 0      u_dgr ESTAB 0      0                                                             /run/systemd/journal/socket 4375              * 0      u_str ESTAB 0      0                                                   /run/containerd/containerd.sock.ttrpc 253716            * 254616 u_dgr ESTAB 0      0                                                                                       * 6576              * 4352   u_str ESTAB 0      0                                                                                       * 1194              * 6220   u_dgr ESTAB 0      0                                                                                       * 4354              * 4353   u_str ESTAB 0      0                                                                                       * 249739            * 249738 u_dgr ESTAB 0      0                                                                                       * 4355              * 4356   u_str ESTAB 0      0                                                             /run/systemd/journal/stdout 3459              * 2959   u_str ESTAB 0      0                                                                                       * 233397            * 237041 u_str ESTAB 0      0                                                                                       * 254616            * 253716 u_str ESTAB 0      0                                                             /run/dbus/system_bus_socket 5686              * 7499   u_str ESTAB 0      0                                                                                       * 257091            * 251617 u_str ESTAB 0      0                                                                                       * 5680              * 5681   u_str ESTAB 0      0                                                                                       * 5681              * 5680   u_str ESTAB 0      0                                                             /run/systemd/journal/stdout 1495              * 394    u_dgr ESTAB 0      0                                                                                       * 1531              * 1530   u_dgr ESTAB 0      0                                                                                       * 1532              * 1533   u_str ESTAB 0      0                                                             /run/systemd/journal/stdout 6589              * 4641   u_dgr ESTAB 0      0                                                                                       * 7490              * 4375   u_str ESTAB 0      0                                                         /run/containerd/containerd.sock 7327              * 278    u_str ESTAB 0      0      /run/containerd/s/a03b8dd582574e7c4a2f8aeb7b4234eb2ebbc2c31009463b7720f8a52916cfd7 251617            * 257091 u_str ESTAB 0      0                                                             /run/systemd/journal/stdout 6587              * 7438   u_str ESTAB 0      0                                                                                       * 254365            * 255229 u_str ESTAB 0      0                                                             /run/systemd/journal/stdout 6584              * 5672   u_dgr ESTAB 0      0                                                                                       * 1534              * 1535   u_str ESTAB 0      0                                                         /run/containerd/containerd.sock 2978              * 3467   u_str ESTAB 0      0                                                                                       * 278               * 7327   u_dgr ESTAB 0      0                                                                                       * 403               * 4374   u_dgr ESTAB 0      0                                                                                       * 1535              * 1534   u_dgr ESTAB 0      0                                                                                       * 4356              * 4355   u_str ESTAB 0      0                                                   /run/containerd/containerd.sock.ttrpc 237041            * 233397 u_str ESTAB 0      0                                                                        /run/docker.sock 277569            * 0      u_str ESTAB 0      0      /run/containerd/s/cc269b970b6aeb79f92b17436db101251d619a34c95903af19509623eed7cd4e 252665            * 254600 u_str ESTAB 0      0                                                                                       * 3376              * 6333   u_str ESTAB 0      0                                                                                       * 260841            * 260840 u_dgr ESTAB 0      0                                                                                       * 1205              * 1204   u_str ESTAB 0      0                                                   /run/containerd/containerd.sock.ttrpc 255229            * 254365 u_str ESTAB 0      0                                                                                       * 254600            * 252665 u_str ESTAB 0      0                                                             /run/dbus/system_bus_socket 407               * 1537   u_dgr ESTAB 0      0                                                                                       * 1203              * 4375   u_dgr ESTAB 0      0                                                                                       * 1533              * 1532   u_str ESTAB 0      0                                                             /run/systemd/journal/stdout 6220              * 1194   u_str ESTAB 0      0                                                                                       * 394               * 1495   u_str ESTAB 0      0                                                                                       * 2959              * 3459   u_str ESTAB 0      0                                                                                       * 5266              * 7288   u_str ESTAB 0      0                                                                                       * 3467              * 2978   u_dgr ESTAB 0      0                                                                                       * 1510              * 4375   u_str ESTAB 0      0                                                                                       * 260840            * 260841 u_str ESTAB 0      0                                                                                       * 249738            * 249739 u_str ESTAB 0      0      /run/containerd/s/2a63b9261c79a69220deb000f44f8352a0b7580d3559cb254fa0849683be51cb 236027            * 234409 u_dgr ESTAB 0      0                                                                                       * 4353              * 4354   u_str ESTAB 0      0                                                                                       * 5672              * 6584   u_str ESTAB 0      0                                            @d6116f58e1c87a17/bus/systemd/bus-api-system 1443              * 5683   u_str ESTAB 0      0                                                @9a25fa37ba838ea2/bus/systemd/bus-system 1537              * 407    u_str ESTAB 0      0                                             @1efdde9028d6097b/bus/systemd-logind/system 7499              * 5686   snapshots caught only 1 socket lines of the daemons' short-lived loopback connections (0 non-loopback among them); the per-process socket snapshot is only meaningful on macOS. Zero public egress is covered by the bridge capture checks of this step |
| 5.relay_failure | PASS | R1 stopped: A's message stayed 'queued' (not delivered), A network status ready=false (node reachable; 0 connected allowed peer(s)), B received 0; capture of the whole outage+recovery: 0 packets with an endpoint outside 172.28.66.0/24 (no fallback destination appeared) |
| 5.relay_failure_no_new_dest | PASS | relay-failure capture: 0 packets with an endpoint outside 172.28.66.0/24 (pcap/egress-relay-failure.egress.txt) |
| 5.relay_recovery | PASS | R1 restarted: the queued message was delivered 23695 ms after R1 /health (E12: live relay can lag after an R1 restart; the sender retry/history path delivered) |
| 5.isolation | PASS | daemon whose only allowlisted peer is a WRONG peer id (16Uiu2HAmHGZ74cqntxJ27NBVKP9BSqKk3A691AxEvWTcWiqGaZtW): network status ready=false, isolation_violation="node is connected to 1 peer(s) not in the allowlist (e.g. 16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV)"; its send stayed 'queued' and B received 0; B's message to it stayed 'sent' and it received 0 |
| 5.reject.public_discovery | PASS | startup refused, exit 4: error: invalid configuration: network.public_discovery = true is not allowed in private mode |
| 5.reject.public_fallback | PASS | startup refused, exit 4: error: invalid configuration: network.public_fallback = true is never allowed: there is no public fallback |
| 5.reject.public_node_url | PASS | startup refused, exit 4: error: invalid configuration: network: isolation violation: private mode: node_url host must be loopback, RFC1918, 100.64.0.0/10, IPv6 loopback/ULA or the literal 'localhost' (names are not resolved) |
| 5.reject.cluster_id_1 | PASS | startup refused, exit 4: error: invalid configuration: network: isolation violation: private mode: cluster id 1 selects a public preset |
| 5.tailscale (optional) | UNTESTED | tailscale not installed on this host (command -v tailscale: not found); no tailnet, no second host. Reproducible steps below. Nothing is claimed to work. |

Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):

```
# 5.config
grep -E 'mode|public_|cluster_id' $A/agentnet.toml
# 5.node_flags
docker inspect an-r1 an-na an-nb --format '{{.Name}} {{join .Args " "}}'
# 5.egress
docker run --net host --cap-add NET_RAW nicolaka/netshoot tcpdump -i br-<net> -w egress-exchange.pcap (colima VM netns); then read back with 'ip and not (src net 172.28.66.0/24 and dst net 172.28.66.0/24)'
# 5.host_connections
ss -H -tunap | grep pid=<pid>
# 5.relay_failure
docker stop an-r1; agentnet send <B>; sleep 75; agentnet network status; tcpdump capture (pcap/egress-relay-failure.*)
# 5.relay_failure_no_new_dest
tcpdump
# 5.relay_recovery
docker start an-r1; agentnet --json status <id>
# 5.isolation
agentnet init --peer /ip4/172.28.66.10/tcp/60000/p2p/<R2 id> ; agentnet serve ; agentnet network status --verbose
# 5.reject.public_discovery
agentnet --data-dir <dir with [network] public_discovery = true> serve
# 5.reject.public_fallback
agentnet --data-dir <dir with [network] public_fallback = true> serve
# 5.reject.public_node_url
agentnet --data-dir <dir with [network] node_url = "http://8.8.8.8:8645"> serve
# 5.reject.cluster_id_1
agentnet --data-dir <dir with [network] cluster_id = 1> serve
# 5.tailscale
command -v tailscale
```

**Note (5.tailscale).** Tailscale run: UNTESTED. To reproduce: (1) on the relay host install Tailscale, join the tailnet and tag it (e.g. `tag:agentnet-relay`); (2) start R1 with `--nat=extip:<relay tailnet 100.x.y.z>` `--listen-address=<tailnet ip or 0.0.0.0>` and every discovery flag off (`agentnet relay print-config --ip <tailnet ip> --peer-id <R1 peer id>` prints the flag set and a compose file, marked UNTESTED); (3) ACL in the tailnet policy file: `{"acls":[{"action":"accept","src":["tag:agentnet-agent"],"dst":["tag:agentnet-relay:60000"]}]}` so only tagged agent hosts reach tcp/60000, and nothing else (the node REST port stays on loopback, never on the tailnet); (4) on each agent host run a client node with `--staticnode=/ip4/<relay tailnet ip>/tcp/60000/p2p/<R1 peer id>` and `agentnet init --node-url http://127.0.0.1:8645 --peer /ip4/<relay tailnet ip>/tcp/60000/p2p/<R1 peer id>` (private mode accepts 100.64.0.0/10); (5) run this script against that topology with the relay host overridden (the script currently hard-codes the local topology: `RELAY_HOST` support is NOT implemented here, so the steps must be run by hand: contact exchange, send, status, inbox). Tailscale gives encrypted transport and machine-level ACLs only; the coordination service sees metadata; AgentNet still provides the end-to-end encryption and identity.


## Step 6: Generic MCP client configuration and Rust embedding

| Check | Status | Detail |
|---|---|---|
| 6.mcp_config | PASS | stdio MCP client configuration emitted (evidence/mcp-client-config.json, template in .template.json); launched exactly its command+args with an rmcp client, negotiated 2026-07-28, tools/list = 15 tools, get_identity returned A's address |
| 6.embed | PASS | Rust embedding example (MockNetwork, in-process engines) ran 5/5 times, exit 0 (evidence/step6-embed-output.txt) |
| 6.embed_statement | PASS | statement why the adapter cannot be fully embedded (the node is a sidecar) saved to evidence/step6-embedding-statement.txt and quoted in SUMMARY.md |

Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):

```
# 6.mcp_config
agentnet-acceptance config-check --config mcp-client-config.json --server agentnet --expect-address <A>   # spawns: /data/home/main/target/release/agentnet mcp --data-dir $A
# 6.embed
target/release/examples/embed   # cargo run --release -p agentnet-daemon --example embed
# 6.embed_statement
n/a
```

**Note (6.embed_statement).** Why the selected adapter cannot be fully embedded (ADR 0001, docs/architecture.md section 1): the transport is an adapter to a separately running Logos Delivery (nwaku) node over its local REST API. That node is a Nim program shipped as a separate executable/container: a sidecar that must run next to the harness. The Rust engine (identity, envelopes, SQLite inbox/outbox, retries, triggers, events, the AgentApi trait) CAN be embedded in a Rust harness, and the embed example does exactly that on the deterministic in-memory MockNetwork; swapping in LogosRestTransport is a two-line change but still needs the sidecar node. Embedding the node itself needs native FFI bindings (waku-sys), which is a future option behind the same Transport trait and was not selected. 


## Step X: Extras (not part of goal.md section 5)

| Check | Status | Detail |
|---|---|---|
| X.second_serve (optional) | PASS | second 'agentnet serve' on A's data dir refused, exit 1: error: another AgentNet process is using this data directory (lock held on /tmp/an-acc.YxIkRd/a/lock); stop it first (one data directory = one agent identity = one process) |
| X.bench100 (optional) | PASS | 100 messages each direction (concurrent, 25 ms pacing, full stack): A->B delivered 100/100 p50/p95/p99 = 12069/13683/13796 ms; B->A delivered 100/100 p50/p95/p99 = 6170/12009/13246 ms; receiver rows A->B 100 (unique 100), B->A 100 (unique 100), duplicate message.received events 0. Latency = delivered_at - created_at in the sender's outbox (send -> authenticated receipt), includes qemu and the 250 ms poll interval |
| X.resources (optional) | PASS | daemon RSS after bench: A 26692 KiB, B 27072 KiB; peak sampled %CPU during bench (ps pcpu, 2 s samples): 0.7; raw: evidence/ps-*.txt. Idle/before snapshot: 23456  0.4;23920  0.4; |
| X.bench100_paced (optional) | PASS | same workload paced at 400 ms per send per direction: A->B delivered 100/100 p50/p95/p99 = 503/1012/1051 ms; B->A delivered 100/100 p50/p95/p99 = 658/1178/1217 ms |
| X.startup_shutdown (optional) | PASS | daemon startup (spawn -> network ready) and SIGTERM -> exit times: evidence/startup-times.tsv, evidence/shutdown-times.tsv; first-start times: a=37ms b=68ms c=31ms b=31ms b=32ms  |
| X.migrate (optional) | PASS | identity exported (age passphrase file) with the daemon stopped, imported into a fresh data dir: same address (an2tpqyphhpe55eqlfih27jeerbj3clk4wjszjmx7mjnae6t4vfuxlal4t22q); a message A sent after the old instance stopped and before the import was recovered from Store and decrypted by the NEW instance with sender authenticated as A (quarantined=true: contacts are not part of the export, so the new data dir learns A's contact record after start and a message processed before that is quarantined, after that it is accepted; both outcomes show it decrypted) |

Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):

```
# X.second_serve
agentnet --data-dir $A serve   # while A's daemon runs
# X.bench100
agentnet-acceptance bench --a $A --b $B --n 100
# X.resources
ps -o rss,pcpu -p <pid>
# X.bench100_paced
agentnet-acceptance bench --n 100 --pace-ms 400
# X.startup_shutdown
see TSVs
# X.migrate
agentnet identity export --out F --passphrase-file P (daemon stopped); agentnet --data-dir new identity import --in F --passphrase-file P; agentnet serve; agentnet inbox --include-quarantined
```

## Evidence index

- `summary.json` (machine readable), `checks.jsonl`, `run.log`
- `logs/` per-step command logs, `evidence/` JSON evidence, `daemon-logs/` redacted daemon stderr (64-hex strings replaced), `pcap/` + `net/` packet captures and summaries
- startup/shutdown times: `evidence/startup-times.tsv`, `evidence/shutdown-times.tsv`
