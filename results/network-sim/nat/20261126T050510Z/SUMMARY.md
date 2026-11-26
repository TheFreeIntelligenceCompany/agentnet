# AgentNet outbound-only clients behind simulated NAT run 20261126T050510Z

> **Scope: SIMULATION on ONE host.** Two docker "LAN" bridges, each behind a NAT gateway container (iptables MASQUERADE + stateful forwarding), and a "public" bridge with the relay; amd64 Logos Delivery nodes under qemu on an arm64 Mac. The Linux conntrack/MASQUERADE behaviour is **not** the endpoint-independent mapping of real home routers or CGNAT, hole punching is neither needed nor tested (clients only dial the relay), and these are **not separate physical hosts**. Every number below inherits that.

Environment: {"host":"Darwin 25.6.0 arm64","colima_vm_kernel":"6.8.0-117-generic","agentnet":"agentnet 0.1.0","nat":"iptables MASQUERADE in containers (Linux conntrack), simulated","node_image":"wakuorg/nwaku@sha256:cb4d14a2... v0.39.2 linux/amd64 under qemu","topology":"public 172.30.80.0/24 (R .10, gw-a .21, gw-b .22); LAN-A 192.168.101.0/24 (gw .2, client .10); LAN-B 192.168.102.0/24; agents on the host via 127.0.0.1 REST ports"}

Totals: PASS 15, FAIL 0, UNTESTED 0

| Step | Status | Title |
|---|---|---|
| 1 | PASS | Topology, reachability matrix (outbound-only), what the relay sees |
| 2 | PASS | 20 messages each way, offline recovery |
| 3 | PASS | NAT mapping loss: conntrack flush, RST variant, gateway restart |
| 4 | PASS | Idle keepalive with a short conntrack established timeout |

## Step 1: Topology, reachability matrix (outbound-only), what the relay sees

| Check | Status | Detail |
|---|---|---|
| 1.topology | PASS | R (public 172.30.80.10), gw-a (LAN-A .2 / public 172.30.80.21), gw-b, client nodes A (192.168.101.10) and B (192.168.102.10) behind them; each client node lists exactly one peer, R (172.30.80.10:60000) (connected after 267 / 131 ms); client containers publish only REST on host 127.0.0.1 (evidence/published-ports.txt), no 60000 |
| 1.r_view | PASS | R's /admin/v1/peers lists exactly two Connected peers, at the GATEWAY public addresses: A as /ip4/172.30.80.21/tcp/42252/p2p/16Uiu2HAkuphLW4nxq7bQSa26uu5g98FBpVUdyyib9oNB33waFd3g, B as /ip4/172.30.80.22/tcp/56754/p2p/16Uiu2HAmGEWUVPGaZZQcoBZSQbdfj8keefjpP6Zbmd7rXxGg7JaF (source NAT visible; neither LAN address appears). tcpdump: on LAN-A the client sends from 192.168.101.10 (62 packets to R:60000), on the public bridge the same flow comes from 172.30.80.21 (62 packets), and 0 packets on the public bridge carry any 192.168.x.x address. conntrack on gw-a: tcp 6 431992 ESTABLISHED src=192.168.101.10 dst=172.30.80.10 sport=42252 dport=60000 src=172.30.80.10 dst=172.30.80.21 sport=60000 dport=42252 [ASSURED] mark=0 use=1 |
| 1.matrix | PASS | outbound-only proven: A and B reach R:60000; R, the other LAN and the other gateway cannot reach either client's tcp/60000 (LAN address or gateway public address) although the client node DOES listen on its LAN (gw-a reaches it from the LAN side). 8 of 11 probes failed as expected (failure mode of each in the table). Full table: evidence/reachability-matrix.txt. NOTE: the 'no route' part rests on docker's isolation between user-defined bridges plus the gateways' stateful forwarding; it is a property of this simulation |

Exact commands:

```
# 1.topology
docker-compose up (spike/relay-nat/docker-compose.yml); curl http://127.0.0.1:18661/admin/v1/peers ; docker port an-nat-a-net
# 1.r_view
curl http://127.0.0.1:18660/admin/v1/peers ; tcpdump on an-nat-pub and an-nat-lana ; docker exec an-nat-gw-a conntrack -L
# 1.matrix
docker run --rm --net container:<vantage> an-net-tools nc -zv -w 4 <host> <port>
```

**Note (1.r_view).** R announces extip 172.30.80.10; the clients run --nat=none so they announce no address of their own. What R 'believes' about a client is the observed remote address of the TCP connection, i.e. the gateway's public address plus the translated source port. Observed mapping: tcp 6 431992 ESTABLISHED src=192.168.101.10 dst=172.30.80.10 sport=42252 dport=60000 src=172.30.80.10 dst=172.30.80.21 sport=60000 dport=42252 [ASSURED] mark=0 use=1 (full conntrack in evidence/conntrack-initial.txt).


## Step 2: 20 messages each way, offline recovery

| Check | Status | Detail |
|---|---|---|
| 2.serve | PASS | two release-mode 'agentnet serve' (A -> http://127.0.0.1:18661 behind NAT-A, B -> http://127.0.0.1:18662 behind NAT-B), private mode, static peer /ip4/172.30.80.10/tcp/60000/p2p/16Uiu2HAmVitzJmX2TE13WjQai4xtWmPRcgGRJmG1PEH37kbgdtTE; A=an1v2fkagwmutxe6kl6n6rs4jywynrpmuihtn53zczpcgic6iycex2ugbzyey B=an12cl75r35vvdd72iawkpb5mqna4lllthza2yudqlqug4tx6ev5mdneborm4 |
| 2.contacts | PASS | contact records exchanged with --expect, both ways |
| 2.first | PASS | first A -> B message delivered (authenticated receipt) after 756 ms on a fresh topology |
| 2.bench.a_to_b | PASS | a -> b: delivered 20/20 with authenticated receipts, send->receipt p50/p95/p99 = 401/506/507 ms (min 273, max 507), paced 400 ms, both directions concurrently; both clients behind NAT |
| 2.bench.b_to_a | PASS | b -> a: delivered 20/20 with authenticated receipts, send->receipt p50/p95/p99 = 382/499/502 ms (min 271, max 502), paced 400 ms, both directions concurrently; both clients behind NAT |
| 2.duplicates | PASS | receiver rows A->B 20 (unique 20), B->A 20 (unique 20); duplicate message.received events: 0 |
| 2.offline | PASS | B's node and daemon stopped, A sent 5 (A states while B down: sent=5 ); B restarted: inbox complete (5 rows, 5 unique) 973 ms after the daemon start, A's 5 receipts (delivered) 1544 ms after it; recovered via the relay's Store and/or sender retries (not instrumented which) |

Exact commands:

```
# 2.serve
agentnet --data-dir $A init --node-url http://127.0.0.1:18661 --peer /ip4/172.30.80.10/tcp/60000/p2p/16Uiu2HAmVitzJmX2TE13WjQai4xtWmPRcgGRJmG1PEH37kbgdtTE; agentnet serve (x2)
# 2.contacts
agentnet contact add @record --expect <address>
# 2.first
agentnet send; agentnet status
# 2.bench.a_to_b
agentnet-acceptance bench --n 20 --pace-ms 400 --tag n
# 2.bench.b_to_a
agentnet-acceptance bench --n 20 --pace-ms 400 --tag n
# 2.duplicates
agentnet-acceptance dump
# 2.offline
docker stop an-nat-b-node; agentnet send x5; docker start an-nat-b-node; agentnet serve (B)
```

## Step 3: NAT mapping loss: conntrack flush, RST variant, gateway restart

| Check | Status | Detail |
|---|---|---|
| 3.flush | PASS | conntrack -F on gw-a at T0 (mid-stream packets then dropped silently, like a router that lost its state; R's peer entries before/after: evidence/s3a-r-peers-*.txt): A's node noticed after 52704 ms (-1 = never), A's daemon not-ready after -1 ms, A's node connected again after 54950 ms, daemon ready again after -1 ms; the A->B message sent right after the disruption was delivered after 57541 ms and a B->A message after 69136 ms (timeline: evidence/s3a-flush-timeline.tsv) |
| 3.flush_rst | PASS | same flush, but gw-a now answers mid-stream packets with a TCP RST (some real devices do): A's node noticed after 860 ms (-1 = never), A's daemon not-ready after 860 ms, A's node connected again after 42031 ms, daemon ready again after 963638 ms; the A->B message sent right after the disruption was delivered after 1096211 ms and a B->A message after 972780 ms (timeline: evidence/s3b-flush-rst-timeline.tsv) |
| 3.gw_restart | PASS | docker restart an-nat-gw-a at T0 (fresh conntrack, rules re-applied, same addresses; mid-stream packets dropped silently): A's node noticed after 50553 ms (-1 = never), A's daemon not-ready after -1 ms, A's node connected again after 53118 ms, daemon ready again after -1 ms; the A->B message sent right after the disruption was delivered after 109366 ms and a B->A message after 53118 ms (timeline: evidence/s3c-gw-restart-timeline.tsv) |

Exact commands:

```
# 3.flush
docker exec an-nat-gw-a conntrack -F ; agentnet send (A->B and B->A) ; poll node peers / daemon status / message status every 2 s
# 3.flush_rst
iptables -I FORWARD 1 ... -j REJECT --reject-with tcp-reset ; docker exec an-nat-gw-a conntrack -F
# 3.gw_restart
docker restart an-nat-gw-a ; agentnet send ; poll
```

## Step 4: Idle keepalive with a short conntrack established timeout

| Check | Status | Detail |
|---|---|---|
| 4.idle_with_daemons | PASS | both sides idle 600s (daemons running, conntrack established timeout 120s on both gateways): nodes still Connected to R after idle=1, R's peer entries (incl. translated source ports) unchanged=1; flow gw-a<->R packet gaps: {"packets": 3021, "max_gap_s": 9.33, "gaps_over_60s": 0, "gaps_over_100s": 0}; then one message each way delivered with receipts after 22017 ms (A->B) and 23165 ms (B->A, measured from the same start) |
| 4.idle_nodes_only | PASS | daemons stopped (no Store sync), nodes idle 600s with conntrack established timeout 120s: before restarting the daemons the nodes were still Connected to R: A=1 B=1, R's peer entries unchanged=1; flow gw-a<->R packet gaps: {"packets": 2091, "max_gap_s": 8.97, "gaps_over_60s": 0, "gaps_over_100s": 0}. After restarting the daemons one message each way: delivered after 13971 ms (A->B) / 32410 ms (B->A) counted from the daemon restart |

Exact commands:

```
# 4.idle_with_daemons
set nf_conntrack_tcp_timeout_established=120 on gw-a/gw-b; no traffic for 600s; agentnet send (each way)
# 4.idle_nodes_only
stop both daemons; no traffic 600s; start daemons; agentnet send (each way)
```

**Note (4.idle_with_daemons).** The daemons are not silent while 'idle': each runs a Store history sync every history_sync_interval_s (default 15 s), a Store query to R over the existing libp2p connection, so the connection carries packets at least that often and the mapping never ages out. This phase therefore does NOT show whether libp2p itself keeps a mapping alive; the node-only phase does.


## Evidence index

- `summary.json` (machine readable), `checks.jsonl`, `run.log`
- `logs/` per-step command logs, `evidence/` JSON/text evidence, `daemon-logs/` redacted daemon stderr, `pcap/` captures and the filter outputs derived from them
