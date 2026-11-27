# AgentNet WireGuard-overlay simulation run 20261127T231045Z

> **Scope: SIMULATION on ONE host.** Kernel WireGuard (module loaded in the colima VM) between three containers on one docker bridge; amd64 Logos Delivery nodes under qemu on an arm64 Mac. It demonstrates the overlay + firewall + static-peer configuration and AgentNet's behaviour on it. It is **NOT Tailscale** (no coordination server, no ACLs, no MagicDNS, no DERP relays), **NOT NAT traversal**, and **NOT separate physical hosts**. Every number below inherits that.

Environment: {"stale_watchdog_sidecar":"1","relay_tcp_retries2":"6","host":"Darwin 25.6.0 arm64","colima_vm_kernel":"6.8.0-117-generic","agentnet":"agentnet 0.1.0","wireguard":"kernel module (not userspace)","node_image":"wakuorg/nwaku@sha256:cb4d14a2... v0.39.2 linux/amd64 under qemu","topology":"underlay 172.29.70.0/24, overlay 10.66.0.0/24, machines R/A/B (+ intruder), agents on the host via 127.0.0.1 REST ports"}

Totals: PASS 21, FAIL 0, UNTESTED 0

| Step | Status | Title |
|---|---|---|
| 1 | PASS | Tunnel up, nodes connected only over the overlay, firewall |
| 2 | PASS | End to end: contacts, send/reply (CLI and MCP), 20 messages each way |
| 5 | PASS | Peer removal on the relay's WireGuard config |

## Step 1: Tunnel up, nodes connected only over the overlay, firewall

| Check | Status | Detail |
|---|---|---|
| 1.kernel | PASS | wg0 on r, a, b is a KERNEL WireGuard link (ip -d link: kind wireguard; module in the colima VM: 6.8.0-117-generic, wireguard             110592  0;nf_conntrack          204800  5 xt_conntrack,nf_nat,xt_nat,nf_conntrack_netlink,xt_MASQUERADE;nf_tables             352256  127 nft_compat,nft_chain_nat;). No userspace fallback was used or implemented. |
| 1.handshakes | PASS | every WireGuard peer on r (a, b), a (r) and b (r) has a non-zero latest handshake (evidence/wg-show-initial.txt) |
| 1.nodes_connected | PASS | A's node lists exactly one peer, R, as /ip4/10.66.0.1/tcp/60000 (connected after 184 ms from node-a start-wait); B's node likewise (102 ms). R's node lists: [{"multiaddr":"/ip4/10.66.0.3/tcp/41394/p2p/16Uiu2HAm261k2WWdCg1QtoLMx7ULATXuA1XJvgo1FKnVBcThtMjc","connected":"Connected"},{"multiaddr":"/ip4/10.66.0.2/tcp/50542/p2p/16Uiu2HAm5m1YoqMz9kdRZa9KwExbAvsBeF1b6Tr4NAYjXGSpsKRe","connected":"Connected"}] |
| 1.r_peers_overlay_only | PASS | every peer R's node lists has an overlay (10.66.0.0/24) address |
| 1.firewall | PASS | R: INPUT policy DROP; tcp/60000 accepted only on wg0 from 10.66.0.2 and 10.66.0.3; tcp/60000 on eth0 (underlay) dropped by an explicit rule placed before the established-accept (evidence/firewall-r-initial.txt) |

Exact commands:

```
# 1.kernel
docker exec an-wg-<m> ip -d link show wg0; colima ssh -- lsmod
# 1.handshakes
docker exec an-wg-<m> wg show wg0 latest-handshakes
# 1.nodes_connected
curl http://127.0.0.1:28651/admin/v1/peers ; :28652 ; :28650
# 1.r_peers_overlay_only
curl http://127.0.0.1:28650/admin/v1/peers
# 1.firewall
docker exec an-wg-r iptables -S
```

## Step 2: End to end: contacts, send/reply (CLI and MCP), 20 messages each way

| Check | Status | Detail |
|---|---|---|
| 2.serve | PASS | two release-mode 'agentnet serve' (A -> http://127.0.0.1:28651, B -> http://127.0.0.1:28652), private mode, static peer = R's OVERLAY multiaddr /ip4/10.66.0.1/tcp/60000/p2p/16Uiu2HAmNj8VjdNLpEUynHeGDQzHAwAn2SpgBCPZzcaPqLtsXFGM, cluster 66; A=an2nkyrhjnx6ysgdqkcmvukodvfgqv62hjjcihm533q7xhktscrcna6y2snxe B=an2efqsaz6rzopmflkucqubfzwxrz42ww2gbbb4fx2bejuyjp52rxko4cqjva; ready after A 261 ms / B 376 ms |
| 2.contacts | PASS | contact records exchanged with 'contact add @record --expect <address>' both ways |
| 2.netstatus.a | PASS | doctor exit 0; network status: private, ready, no isolation violation, exactly one peer = R (16Uiu2HAmNj8VjdNLpEUynHeGDQzHAwAn2SpgBCPZzcaPqLtsXFGM) |
| 2.netstatus.b | PASS | doctor exit 0; network status: private, ready, no isolation violation, exactly one peer = R (16Uiu2HAmNj8VjdNLpEUynHeGDQzHAwAn2SpgBCPZzcaPqLtsXFGM) |
| 2.cli_send | PASS | A -> B via 'agentnet send': delivered (authenticated receipt) after 727 ms (FIRST message on a fresh topology: includes the relay-mesh warm-up of up to ~60 s, not a typical latency) |
| 2.inbox_auth | PASS | B's inbox holds the message, sender authenticated as A (an2nkyrhjnx6ysgdqkcmvukodvfgqv62hjjcihm533q7xhktscrcna6y2snxe), body intact |
| 2.reply | PASS | B -> A reply delivered (receipt after 652 ms) and present in A's inbox |
| 2.mcp | PASS | A -> B via MCP send_message (rmcp over stdio, negotiated 2026-07-28): B's subscriptions/listen notified after 200 ms, B read_inbox at +463 ms, A status delivered at +462 ms |
| 2.bench.a_to_b | PASS | a -> b: delivered 20/20 (authenticated receipts), send->receipt latency p50/p95/p99 = 415/543/554 ms (min 285, max 554), paced 400 ms per send, both directions concurrently; qemu nodes, poll interval 250 ms, includes WireGuard + relay hop |
| 2.bench.b_to_a | PASS | b -> a: delivered 20/20 (authenticated receipts), send->receipt latency p50/p95/p99 = 416/538/553 ms (min 287, max 553), paced 400 ms per send, both directions concurrently; qemu nodes, poll interval 250 ms, includes WireGuard + relay hop |
| 2.duplicates | PASS | receiver inbox rows A->B 20 (unique 20), B->A 20 (unique 20); duplicate message.received events: 0 |

Exact commands:

```
# 2.serve
agentnet --data-dir $A init --node-url http://127.0.0.1:28651 --peer /ip4/10.66.0.1/tcp/60000/p2p/16Uiu2HAmNj8VjdNLpEUynHeGDQzHAwAn2SpgBCPZzcaPqLtsXFGM; agentnet --data-dir $B init --node-url http://127.0.0.1:28652 --peer /ip4/10.66.0.1/tcp/60000/p2p/16Uiu2HAmNj8VjdNLpEUynHeGDQzHAwAn2SpgBCPZzcaPqLtsXFGM; agentnet serve (x2)
# 2.contacts
agentnet contact add @b.record --expect <B>; agentnet contact add @a.record --expect <A>
# 2.netstatus.a
agentnet doctor; agentnet --json network status --verbose
# 2.netstatus.b
agentnet doctor; agentnet --json network status --verbose
# 2.cli_send
agentnet --json send <B> w-first-cli; agentnet --json status <id>
# 2.inbox_auth
agentnet --json inbox --conversation w-first
# 2.reply
agentnet send <A> w-reply-cli (from B)
# 2.mcp
agentnet-acceptance step2 --bin agentnet --a $A --b $B --b-addr <B>
# 2.bench.a_to_b
agentnet-acceptance bench --n 20 --pace-ms 400 --tag w
# 2.bench.b_to_a
agentnet-acceptance bench --n 20 --pace-ms 400 --tag w
# 2.duplicates
agentnet-acceptance dump --data-dir $B / $A
```

## Step 5: Peer removal on the relay's WireGuard config

| Check | Status | Detail |
|---|---|---|
| 5.undelivered | PASS | after R dropped B's WireGuard peer, A's message to B stayed 'sent' for the whole observation (92 s) and B's inbox has 0 rows for it (A's own path to R is intact, so the frame is accepted by R but cannot reach B) |
| 5.b_node_loses_r | PASS | B's node stopped listing R as Connected 56577 ms after the peer removal (note: removal drops packets silently, so the node learns it only by its own timeouts) |
| 5.b_daemon_not_ready | PASS | B's daemon reported network.ready=false 61621 ms after the removal |
| 5.recovery | PASS | after re-adding B's peer on R: WireGuard handshake after 5399 ms, B's node lists R after 5430 ms, B's daemon ready after 5477 ms, A's queued message delivered (authenticated receipt) after 9713 ms |
| 5.no_fallback | PASS | captures during the removal window and the re-add window: only WireGuard UDP on the underlay; no tcp/60000, no cleartext, nothing outside the underlay subnet. Removal window: 11072 packets total; WireGuard UDP/51820 between underlay addresses: 1139; UDP other than 51820: 0; TCP between the machines (excluding the docker host's REST connections): 0; tcp/60000 (excluding the docker host and the intruder): 0; IP packets with an endpoint outside 172.29.70.0/24: 0; packets carrying an overlay 10.66.0.0/24 address: 0; non-multicast IPv6: 0; packets containing the ASCII strings 'multistream' / 'agentnet': 0 / 0; (REST between the host and the nodes via the docker gateway, cleartext by design, loopback in a real deployment: 9917). Re-add window: 1717 packets total; WireGuard UDP/51820 between underlay addresses: 375; UDP other than 51820: 0; TCP between the machines (excluding the docker host's REST connections): 0; tcp/60000 (excluding the docker host and the intruder): 0; IP packets with an endpoint outside 172.29.70.0/24: 0; packets carrying an overlay 10.66.0.0/24 address: 0; non-multicast IPv6: 0; packets containing the ASCII strings 'multistream' / 'agentnet': 0 / 0; (REST between the host and the nodes via the docker gateway, cleartext by design, loopback in a real deployment: 1338) |

Exact commands:

```
# 5.undelivered
docker exec an-wg-r wg set wg0 peer <B pub> remove ; agentnet send ; agentnet status
# 5.b_node_loses_r
curl http://127.0.0.1:28652/admin/v1/peers
# 5.b_daemon_not_ready
agentnet --json network status (B)
# 5.recovery
docker exec an-wg-r wg set wg0 peer <B pub> allowed-ips 10.66.0.3/32
# 5.no_fallback
tcpdump read-back filters (evidence/u-s5-summary.json, u-s5b-summary.json)
```

## Evidence index

- `summary.json` (machine readable), `checks.jsonl`, `run.log`
- `logs/` per-step command logs, `evidence/` JSON/text evidence, `daemon-logs/` redacted daemon stderr, `pcap/` captures and the filter outputs derived from them

## Run context (added by the operator after the run)

- Commit: scripts at 481eb15 plus uncommitted script edits listed in the lead's report; agentnet release binaries built from 481eb15 (run 20261127T194713Z: from 4b08e58). Message protection: RFC 9580 OpenPGP (addresses an2..., contact records are certificates, contacts added with --expect so they are trusted).
- Scope: SINGLE-HOST SIMULATION on one colima VM (linux/arm64, nodes amd64 under qemu). NOT Tailscale, NOT real NAT/NAT traversal from a consumer router, NOT separate physical hosts. Latencies inherit qemu emulation.
- Load caveat: the Mac was shared with other contributors' containers (an-x-*, an-do-*) and heavily loaded (load average 313 at the start of the first run 20261127T194713Z, about 40 later). Timings, especially in this run, are not clean measurements.
- Variant: STEPS="1 2 5" recovery trial 2, WATCHDOG=1, tcp_retries2=6: recovery to delivery 9713 ms (handshake 5399 ms, node 5430 ms).
- Keys: DISPOSABLE, generated into the gitignored .run/ and deleted at exit. The macOS username and home paths were replaced by <user>.
