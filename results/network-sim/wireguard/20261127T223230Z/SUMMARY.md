# AgentNet WireGuard-overlay simulation run 20261127T223230Z

> **Scope: SIMULATION on ONE host.** Kernel WireGuard (module loaded in the colima VM) between three containers on one docker bridge; amd64 Logos Delivery nodes under qemu on an arm64 Mac. It demonstrates the overlay + firewall + static-peer configuration and AgentNet's behaviour on it. It is **NOT Tailscale** (no coordination server, no ACLs, no MagicDNS, no DERP relays), **NOT NAT traversal**, and **NOT separate physical hosts**. Every number below inherits that.

Environment: {"stale_watchdog_sidecar":"1","relay_tcp_retries2":"6","host":"Darwin 25.6.0 arm64","colima_vm_kernel":"6.8.0-117-generic","agentnet":"agentnet 0.1.0","wireguard":"kernel module (not userspace)","node_image":"wakuorg/nwaku@sha256:cb4d14a2... v0.39.2 linux/amd64 under qemu","topology":"underlay 172.29.70.0/24, overlay 10.66.0.0/24, machines R/A/B (+ intruder), agents on the host via 127.0.0.1 REST ports"}

Totals: PASS 36, FAIL 0, UNTESTED 0

| Step | Status | Title |
|---|---|---|
| 1 | PASS | Tunnel up, nodes connected only over the overlay, firewall |
| 2 | PASS | End to end: contacts, send/reply (CLI and MCP), 20 messages each way |
| 3 | PASS | Packet proof on the underlay: only WireGuard UDP |
| 4 | PASS | Access restriction: key-less intruder on the underlay, plus control |
| 5 | PASS | Peer removal on the relay's WireGuard config |
| 6 | PASS | Relay node down inside the overlay |

## Step 1: Tunnel up, nodes connected only over the overlay, firewall

| Check | Status | Detail |
|---|---|---|
| 1.kernel | PASS | wg0 on r, a, b is a KERNEL WireGuard link (ip -d link: kind wireguard; module in the colima VM: 6.8.0-117-generic, wireguard             110592  0;nf_conntrack          204800  5 xt_conntrack,nf_nat,xt_nat,nf_conntrack_netlink,xt_MASQUERADE;nf_tables             352256  127 nft_compat,nft_chain_nat;). No userspace fallback was used or implemented. |
| 1.handshakes | PASS | every WireGuard peer on r (a, b), a (r) and b (r) has a non-zero latest handshake (evidence/wg-show-initial.txt) |
| 1.nodes_connected | PASS | A's node lists exactly one peer, R, as /ip4/10.66.0.1/tcp/60000 (connected after 588 ms from node-a start-wait); B's node likewise (246 ms). R's node lists: [{"multiaddr":"/ip4/10.66.0.3/tcp/54484/p2p/16Uiu2HAmGYm6uFC8uEvTEyr8z9powjTK5QGaWoG4j7p3FKQFUWfT","connected":"Connected"},{"multiaddr":"/ip4/10.66.0.2/tcp/58726/p2p/16Uiu2HAkx7SoNP9fxshcKVDzDYHUJvPAgWpbuU9cDb5GeMkwapJh","connected":"Connected"}] |
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
| 2.serve | PASS | two release-mode 'agentnet serve' (A -> http://127.0.0.1:28651, B -> http://127.0.0.1:28652), private mode, static peer = R's OVERLAY multiaddr /ip4/10.66.0.1/tcp/60000/p2p/16Uiu2HAmNXeK89spfK1NqtZDD14k4yCezwqKChPGPXn72sCZStgG, cluster 66; A=an2npto22f4f2g5bmcpyy3vpmpnooegwiujunvyt4bqkmzv5tkhzx42wwqg3y B=an2dw6qvti3cqkpj2xvxb5ieivm2dk2o4zdwueixvzold2jcujd7cxhjtvwl4; ready after A 794 ms / B 1222 ms |
| 2.contacts | PASS | contact records exchanged with 'contact add @record --expect <address>' both ways |
| 2.netstatus.a | PASS | doctor exit 0; network status: private, ready, no isolation violation, exactly one peer = R (16Uiu2HAmNXeK89spfK1NqtZDD14k4yCezwqKChPGPXn72sCZStgG) |
| 2.netstatus.b | PASS | doctor exit 0; network status: private, ready, no isolation violation, exactly one peer = R (16Uiu2HAmNXeK89spfK1NqtZDD14k4yCezwqKChPGPXn72sCZStgG) |
| 2.cli_send | PASS | A -> B via 'agentnet send': delivered (authenticated receipt) after 978 ms (FIRST message on a fresh topology: includes the relay-mesh warm-up of up to ~60 s, not a typical latency) |
| 2.inbox_auth | PASS | B's inbox holds the message, sender authenticated as A (an2npto22f4f2g5bmcpyy3vpmpnooegwiujunvyt4bqkmzv5tkhzx42wwqg3y), body intact |
| 2.reply | PASS | B -> A reply delivered (receipt after 753 ms) and present in A's inbox |
| 2.mcp | PASS | A -> B via MCP send_message (rmcp over stdio, negotiated 2026-07-28): B's subscriptions/listen notified after 364 ms, B read_inbox at +574 ms, A status delivered at +571 ms |
| 2.bench.a_to_b | PASS | a -> b: delivered 20/20 (authenticated receipts), send->receipt latency p50/p95/p99 = 1424/2030/2213 ms (min 695, max 2213), paced 400 ms per send, both directions concurrently; qemu nodes, poll interval 250 ms, includes WireGuard + relay hop |
| 2.bench.b_to_a | PASS | b -> a: delivered 20/20 (authenticated receipts), send->receipt latency p50/p95/p99 = 1485/2402/2418 ms (min 516, max 2418), paced 400 ms per send, both directions concurrently; qemu nodes, poll interval 250 ms, includes WireGuard + relay hop |
| 2.duplicates | PASS | receiver inbox rows A->B 20 (unique 20), B->A 20 (unique 20); duplicate message.received events: 0 |

Exact commands:

```
# 2.serve
agentnet --data-dir $A init --node-url http://127.0.0.1:28651 --peer /ip4/10.66.0.1/tcp/60000/p2p/16Uiu2HAmNXeK89spfK1NqtZDD14k4yCezwqKChPGPXn72sCZStgG; agentnet --data-dir $B init --node-url http://127.0.0.1:28652 --peer /ip4/10.66.0.1/tcp/60000/p2p/16Uiu2HAmNXeK89spfK1NqtZDD14k4yCezwqKChPGPXn72sCZStgG; agentnet serve (x2)
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

## Step 3: Packet proof on the underlay: only WireGuard UDP

| Check | Status | Detail |
|---|---|---|
| 3.underlay_only_wg | PASS | capture 'main' (from before the first handshake through bring-up, contacts, CLI+MCP messages and 2x20 paced messages): 6359 packets total; WireGuard UDP/51820 between underlay addresses: 1749; UDP other than 51820: 0; TCP between the machines (excluding the docker host's REST connections): 0; tcp/60000 (excluding the docker host and the intruder): 0; IP packets with an endpoint outside 172.29.70.0/24: 0; packets carrying an overlay 10.66.0.0/24 address: 0; non-multicast IPv6: 0; packets containing the ASCII strings 'multistream' / 'agentnet': 0 / 0; (REST between the host and the nodes via the docker gateway, cleartext by design, loopback in a real deployment: 4568) |
| 3.no_cleartext | PASS | no packet on the underlay carries the ASCII strings 'multistream' (libp2p protocol negotiation, cleartext inside TCP) or 'agentnet' (content topic /agentnet/1/...); positive control for the string search is check 4.control_cleartext, where the same strings DO appear when the firewall is opened |
| 3.paths_unguarded | PASS | from A's namespace (a keyed machine): R's UNDERLAY address 172.29.70.10:60000 fails (exit 1, timed out: the SYNs reached R and were dropped, 5 on the wire); B's overlay address 10.66.0.3:60000 fails (exit 1; A's only WireGuard peer is R) BUT 3 SYN packets for the overlay address were sent out of eth0 in cleartext via the default route (evidence/paths-unguarded-overlay-addr-packets.txt): WireGuard AllowedIPs does not stop a host from sending overlay-prefix traffic elsewhere. AgentNet never does (its only destination is R's configured address); a hardened client needs the OUTPUT guard of 3.paths_guarded. R's overlay address succeeds ( Connection to 10.66.0.1 60000 port [tcp/*] succeeded! ). |
| 3.paths_guarded | PASS | with 'iptables -I OUTPUT -d 10.66.0.0/24 ! -o wg0 -j REJECT' on every machine the same probes give: underlay R:60000 fails (exit 1), B's overlay address fails immediately (exit 1:  nc: connect to 10.66.0.3 port 60000 (tcp) failed: Connection refused ) with 0 packets for overlay addresses on the underlay, R's overlay address succeeds |

Exact commands:

```
# 3.underlay_only_wg
tcpdump -i an-wg-br0 -nn -s 0 -w main-an-wg-br0.pcap (docker run --net host in the colima VM); read back with the filters in evidence/u-main-summary.json
# 3.no_cleartext
tcpdump -nn -A -r main-an-wg-br0.pcap | grep -a -c multistream
# 3.paths_unguarded
docker exec an-wg-a nc -zv -w 5 172.29.70.10 60000 ; nc -zv 10.66.0.3 60000 ; nc -zv 10.66.0.1 60000 (tcpdump on an-wg-br0)
# 3.paths_guarded
iptables -I OUTPUT -d 10.66.0.0/24 ! -o wg0 -j REJECT ; nc -zv ...
```

## Step 4: Access restriction: key-less intruder on the underlay, plus control

| Check | Status | Detail |
|---|---|---|
| 4.nc_blocked | PASS | intruder (underlay 172.29.70.66, no WireGuard key): nc to R 172.29.70.10:60000 -> exit 1 ( nc: connect to 172.29.70.10 port 60000 (tcp) timed out: Operation in progress ); to A 172.29.70.21:60000 -> exit 1; to R's REST port 8645 -> exit 1 (only the docker host may); R's underlay-drop rule counter went 10 -> 15 packets, so the SYNs arrived and were dropped, not lost. UDP 51820 'connect' (connectionless, so exit 0 proves nothing) is open by design: unauthenticated WireGuard packets get no reply. |
| 4.intruder_not_peer | PASS | intruder node (--staticnode = R's UNDERLAY multiaddr, cluster 66, shard 0, two explicit dials): its peer list [{"multiaddr":"/ip4/172.29.70.10/tcp/60000/p2p/16Uiu2HAmNXeK89spfK1NqtZDD14k4yCezwqKChPGPXn72sCZStgG","connected":"CannotConnect"}], none Connected. R's connected peers unchanged: before [16Uiu2HAkx7SoNP9fxshcKVDzDYHUJvPAgWpbuU9cDb5GeMkwapJh,16Uiu2HAmGYm6uFC8uEvTEyr8z9powjTK5QGaWoG4j7p3FKQFUWfT] = during [16Uiu2HAkx7SoNP9fxshcKVDzDYHUJvPAgWpbuU9cDb5GeMkwapJh,16Uiu2HAmGYm6uFC8uEvTEyr8z9powjTK5QGaWoG4j7p3FKQFUWfT] (R sees only A and B) |
| 4.intruder_no_frames | PASS | while A sent 5 messages to B (all delivered with receipts) the intruder, subscribed to B's and A's inbox content topics, polled 0 frames on B's topic and 0 on A's topic (empty arrays: evidence/intruder-poll-*-blocked.json) |
| 4.control_connects | PASS | CONTROL (drop rule removed, accept rule inserted): the same intruder became a Connected peer of R after 9534 ms; R's peer list now contains [{"multiaddr":"/ip4/172.29.70.66/tcp/38782/p2p/16Uiu2HAmHGxftPfS85G2o2UX5cwyunBcu5XmaEQE5PN7dhjgNMKV","connected":"Connected"}]. So the test CAN fail: the firewall rule is what kept it out. |
| 4.control_sees_frames | PASS | CONTROL: with the firewall open the intruder received 2 live frame(s) on B's inbox topic and 1 on A's topic via relay (first within 7161 ms of the rule change, after 1 sends), and its Store query against R returned 20 stored frame(s) for B's topic. Cluster/shard separation is NOT access control. |
| 4.control_ciphertext_only | PASS | the 23 frame(s) the intruder obtained contain no plaintext marker or address (payload sizes [2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197,2197]): ciphertext only. That is the application-layer E2E encryption working, and exactly why cluster/shard separation is not access control: the intruder still learns topics, timing, sizes and sees the traffic of everyone on the shard. |
| 4.control_cleartext | PASS | CONTROL capture: 199 tcp/60000 packets between the intruder and R on the underlay, 4 contain the cleartext libp2p 'multistream' negotiation (and 0 the ASCII 'agentnet'): the string search of check 3.no_cleartext can detect cleartext when it exists |
| 4.restored | PASS | drop rule restored (evidence/firewall-r-restored.txt); a fresh nc from the intruder to R:60000 fails again (exit 1); A's and B's nodes still Connected to R; an A->B message sent after the restore was delivered (5470 ms). Note: removing the accept rule alone does not evict an established flow; the drop rule is placed before the established-accept so it cuts it, and the intruder node was stopped as well. |

Exact commands:

```
# 4.nc_blocked
docker exec an-wg-intruder nc -zv -w 5 172.29.70.10 60000 ; docker exec an-wg-r iptables -vnxL INPUT
# 4.intruder_not_peer
curl http://127.0.0.1:28653/admin/v1/peers ; POST http://127.0.0.1:28653/admin/v1/peers [R underlay multiaddr] ; curl http://127.0.0.1:28650/admin/v1/peers
# 4.intruder_no_frames
POST http://127.0.0.1:28653/relay/v1/auto/subscriptions [topic] ; GET http://127.0.0.1:28653/relay/v1/auto/messages/<topic>
# 4.control_connects
iptables -D INPUT -i eth0 -p tcp --dport 60000 -m comment --comment wgsim-underlay-libp2p-drop -j DROP ; iptables -I INPUT 2 -i eth0 -p tcp --dport 60000 -j ACCEPT ; POST http://127.0.0.1:28653/admin/v1/peers
# 4.control_sees_frames
GET http://127.0.0.1:28653/relay/v1/auto/messages/<B topic> ; GET http://127.0.0.1:28653/store/v3/messages?peerAddr=<R>&contentTopics=<B topic>
# 4.control_ciphertext_only
evidence/intruder-frames-analysis.json
# 4.control_cleartext
tcpdump -nn -A -r s4b-an-wg-br0.pcap | grep -a -c multistream
# 4.restored
iptables -D (control accept) ; iptables -I INPUT 2 (drop) ; nc -zv
```

## Step 5: Peer removal on the relay's WireGuard config

| Check | Status | Detail |
|---|---|---|
| 5.undelivered | PASS | after R dropped B's WireGuard peer, A's message to B stayed 'sent' for the whole observation (160 s) and B's inbox has 0 rows for it (A's own path to R is intact, so the frame is accepted by R but cannot reach B) |
| 5.b_node_loses_r | PASS | B's node stopped listing R as Connected 80220 ms after the peer removal (note: removal drops packets silently, so the node learns it only by its own timeouts) |
| 5.b_daemon_not_ready | PASS | B's daemon reported network.ready=false 87126 ms after the removal |
| 5.recovery | PASS | after re-adding B's peer on R: WireGuard handshake after 218946 ms, B's node lists R after 220058 ms, B's daemon ready after 221105 ms, A's queued message delivered (authenticated receipt) after 230363 ms |
| 5.no_fallback | PASS | captures during the removal window and the re-add window: only WireGuard UDP on the underlay; no tcp/60000, no cleartext, nothing outside the underlay subnet. Removal window: 6081 packets total; WireGuard UDP/51820 between underlay addresses: 1078; UDP other than 51820: 0; TCP between the machines (excluding the docker host's REST connections): 0; tcp/60000 (excluding the docker host and the intruder): 0; IP packets with an endpoint outside 172.29.70.0/24: 0; packets carrying an overlay 10.66.0.0/24 address: 0; non-multicast IPv6: 0; packets containing the ASCII strings 'multistream' / 'agentnet': 0 / 0; (REST between the host and the nodes via the docker gateway, cleartext by design, loopback in a real deployment: 4981). Re-add window: 9606 packets total; WireGuard UDP/51820 between underlay addresses: 1991; UDP other than 51820: 0; TCP between the machines (excluding the docker host's REST connections): 0; tcp/60000 (excluding the docker host and the intruder): 0; IP packets with an endpoint outside 172.29.70.0/24: 0; packets carrying an overlay 10.66.0.0/24 address: 0; non-multicast IPv6: 0; packets containing the ASCII strings 'multistream' / 'agentnet': 0 / 0; (REST between the host and the nodes via the docker gateway, cleartext by design, loopback in a real deployment: 7581) |

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

## Step 6: Relay node down inside the overlay

| Check | Status | Detail |
|---|---|---|
| 6.queued | PASS | R's node stopped (tunnel and R's wg0 still up): A's message is 'queued' after 60 s, A's network status ready=false (node reachable; 0 connected allowed peer(s)), B received 0 |
| 6.recovery | PASS | R's node restarted (REST healthy 62716 ms after the stop command): A ready after 8520 ms, the queued message delivered (authenticated receipt) 45915 ms after R's /health (sender retries / history sync; E12: live relay may lag) |
| 6.no_fallback | PASS | capture of the whole outage and recovery: 12654 packets total; WireGuard UDP/51820 between underlay addresses: 763; UDP other than 51820: 0; TCP between the machines (excluding the docker host's REST connections): 0; tcp/60000 (excluding the docker host and the intruder): 0; IP packets with an endpoint outside 172.29.70.0/24: 0; packets carrying an overlay 10.66.0.0/24 address: 0; non-multicast IPv6: 0; packets containing the ASCII strings 'multistream' / 'agentnet': 0 / 0; (REST between the host and the nodes via the docker gateway, cleartext by design, loopback in a real deployment: 11863) |

Exact commands:

```
# 6.queued
docker stop an-wg-r-node ; agentnet send ; agentnet network status
# 6.recovery
docker start an-wg-r-node
# 6.no_fallback
tcpdump read-back filters (evidence/u-s6-summary.json)
```

## Evidence index

- `summary.json` (machine readable), `checks.jsonl`, `run.log`
- `logs/` per-step command logs, `evidence/` JSON/text evidence, `daemon-logs/` redacted daemon stderr, `pcap/` captures and the filter outputs derived from them

## Run context (added by the operator after the run)

- Commit: scripts at 481eb15 plus uncommitted script edits listed in the lead's report; agentnet release binaries built from 481eb15 (run 20261127T194713Z: from 4b08e58). Message protection: RFC 9580 OpenPGP (addresses an2..., contact records are certificates, contacts added with --expect so they are trusted).
- Scope: SINGLE-HOST SIMULATION on one colima VM (linux/arm64, nodes amd64 under qemu). NOT Tailscale, NOT real NAT/NAT traversal from a consumer router, NOT separate physical hosts. Latencies inherit qemu emulation.
- Load caveat: the Mac was shared with other contributors' containers (an-x-*, an-do-*) and heavily loaded (load average 313 at the start of the first run 20261127T194713Z, about 40 later). Timings, especially in this run, are not clean measurements.
- Variant: WATCHDOG=1 (stale-watchdog sidecar on R), tcp_retries2=6. Watchdog log: one idle socket destroyed (10.66.0.3:54484, 64 s idle) during step 5. Recovery 5.recovery took 230363 ms to delivery because the WireGuard handshake itself came 218946 ms after re-adding the peer (WG handshake back-off under load; node reconnect followed within 1.1 s); below the 600 s limit. Intruder frames: 23, all 2197 bytes.
- Keys: DISPOSABLE, generated into the gitignored .run/ and deleted at exit. The macOS username and home paths were replaced by <user>.
