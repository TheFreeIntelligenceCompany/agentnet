# AgentNet single-host Tailscale-address run run 20261126T142752Z

> **Scope: ONE HOST, real tailnet address.** This run proves configuration with a real tailnet address and that the relay port is bound to the tailnet interface only. It does **NOT** prove cross-machine transport, Tailscale ACLs, DERP relays or NAT traversal (all **UNTESTED**), and client-to-relay packets on one host do **not** cross a WireGuard tunnel (same-host delivery). Amd64 Logos Delivery nodes under qemu in a colima VM on an arm64 Mac. Tailnet IPv4 is shown as `<TS_IP>`, device names as `<host-a>`, `<host-b>`, ...

Environment: {"host":"Darwin 25.6.0 arm64","agentnet":"agentnet 0.1.0","node_image":"wakuorg/nwaku@sha256:cb4d14a2... v0.39.2 linux/amd64 under qemu in colima (linux/arm64 VM)","topology":"R + A + B nodes in colima; R announces and is dialled on the host tailnet IPv4 <TS_IP>:60000 (host forwarder bound to that address only); agents on the host via 127.0.0.1 REST ports 18671-18673","caveat":"other docker work (an-wg*, rust build) was running concurrently on the same VM: latencies are not clean"}

Totals: PASS 17, FAIL 0, UNTESTED 4

| Step | Status | Title |
|---|---|---|
| 1 | PASS | Binding, nodes connected to R on the tailnet address |
| 2 | PASS | End to end: contacts, send/reply (CLI and MCP), 20 messages each way |
| 3 | PASS | Reachability matrix of the relay port from the host |
| 4 | PASS | Tailnet status |
| 5 | PASS | Path honesty and what is not tested |

## Step 1: Binding, nodes connected to R on the tailnet address

| Check | Status | Detail |
|---|---|---|
| 1.bind_tailnet_ip_in_vm | PASS | docker (inside the colima VM) CANNOT publish a port on the host's tailnet IPv4: 'failed to bind host port <TS_IP>:60999/tcp: cannot assign requested address'. The VM's own addresses (evidence/colima-vm-addresses.txt) do not include the tailnet address; docker binds in the VM, not on the macOS host. Workaround used (no colima restart or reconfiguration): R's port is published on the VM loopback, colima forwards it to host 127.0.0.1:61000, and spike/relay-tailscale/tcp-forward.py listens ONLY on <TS_IP>:60000 and forwards to it. |
| 1.nodes_connected | PASS | A's node lists exactly one peer, R, as /ip4/<TS_IP>/tcp/60000 (connected after 50 ms from the wait start); B's node likewise (62 ms). R's node lists: [{"multiaddr":"/ip4/172.19.0.1/tcp/48010/p2p/16Uiu2HAmS42wRSBMbvtgNznedfCn86mM6GmCpLyKGLZgNRx33bSJ","connected":"Connected"},{"multiaddr":"/ip4/172.19.0.1/tcp/48018/p2p/16Uiu2HAkzTjXgTfsBcK1g6KV8qHZZVbpj5DrYYcP7qTvqL83yw4M","connected":"Connected"}] |

Exact commands:

```
# 1.bind_tailnet_ip_in_vm
docker run -p <TS_IP>:60999:60999 an-net-tools:local ; colima ssh -- ip -4 -o addr
# 1.nodes_connected
curl http://127.0.0.1:18672/admin/v1/peers ; :18673 ; :18671
```

## Step 2: End to end: contacts, send/reply (CLI and MCP), 20 messages each way

| Check | Status | Detail |
|---|---|---|
| 2.serve | PASS | two release-mode 'agentnet serve' (A -> http://127.0.0.1:18672, B -> http://127.0.0.1:18673), private mode, peer allowlist = R only (/ip4/<TS_IP>/tcp/60000/p2p/16Uiu2HAmTbwAkPeWE5fXqBcyKYifdKauFHZzCmCxzq9SbhVaQTpT), cluster 66; A=an1h6q62o7kogx2oqvo32l5ygnqytdh3llleim7ynmkdyxbgk57fg3zveypom B=an1lx5csmd5anhif543bzybdp2w3axvmcwjv3xk7mmpzuiavu3c4zbookk7fy; ready after A 189 ms / B 292 ms (qemu nodes, concurrent docker load) |
| 2.contacts | PASS | contact records exchanged with 'contact add @record --expect <address>' both ways |
| 2.netstatus.a | PASS | agentnet doctor exit 0 (clean); network status: private, ready, no isolation violation, exactly one peer = R (16Uiu2HAmTbwAkPeWE5fXqBcyKYifdKauFHZzCmCxzq9SbhVaQTpT) |
| 2.netstatus.b | PASS | agentnet doctor exit 0 (clean); network status: private, ready, no isolation violation, exactly one peer = R (16Uiu2HAmTbwAkPeWE5fXqBcyKYifdKauFHZzCmCxzq9SbhVaQTpT) |
| 2.cli_send | PASS | A -> B via 'agentnet send': delivered (authenticated receipt) after 584 ms (FIRST message on a fresh topology: includes relay-mesh warm-up, not a typical latency) |
| 2.inbox_auth | PASS | B's inbox holds the message, sender authenticated as A (an1h6q62o7kogx2oqvo32l5ygnqytdh3llleim7ynmkdyxbgk57fg3zveypom), body intact |
| 2.reply | PASS | B -> A reply delivered (receipt after 631 ms) and present in A's inbox |
| 2.mcp | PASS | A -> B via MCP send_message (rmcp over stdio, negotiated 2026-07-28): B's subscriptions/listen notified after 143 ms, B read_inbox at +424 ms, A status delivered at +422 ms |
| 2.bench.a_to_b | PASS | a -> b: delivered 20/20 (authenticated receipts), send->receipt latency p50/p95/p99 = 443/638/647 ms (min 321, max 647), paced 400 ms, both directions concurrently; qemu nodes, other docker work running concurrently |
| 2.bench.b_to_a | PASS | b -> a: delivered 20/20 (authenticated receipts), send->receipt latency p50/p95/p99 = 474/647/675 ms (min 318, max 675), paced 400 ms, both directions concurrently; qemu nodes, other docker work running concurrently |
| 2.duplicates | PASS | receiver inbox rows A->B 20 (unique 20), B->A 20 (unique 20); duplicate message.received events: 0 |

Exact commands:

```
# 2.serve
agentnet --data-dir $A init --node-url http://127.0.0.1:18672 --peer /ip4/<TS_IP>/tcp/60000/p2p/16Uiu2HAmTbwAkPeWE5fXqBcyKYifdKauFHZzCmCxzq9SbhVaQTpT; agentnet --data-dir $B init --node-url http://127.0.0.1:18673 --peer /ip4/<TS_IP>/tcp/60000/p2p/16Uiu2HAmTbwAkPeWE5fXqBcyKYifdKauFHZzCmCxzq9SbhVaQTpT; agentnet serve (x2)
# 2.contacts
agentnet contact add @b.record --expect <B>; agentnet contact add @a.record --expect <A>
# 2.netstatus.a
agentnet doctor; agentnet --json network status --verbose
# 2.netstatus.b
agentnet doctor; agentnet --json network status --verbose
# 2.cli_send
agentnet --json send <B> t-first-cli; agentnet --json status <id>
# 2.inbox_auth
agentnet --json inbox --conversation t-first
# 2.reply
agentnet send <A> t-reply-cli (from B)
# 2.mcp
agentnet-acceptance step2 --bin agentnet --a $A --b $B --b-addr <B>
# 2.bench.a_to_b
agentnet-acceptance bench --n 20 --pace-ms 400 --tag t
# 2.bench.b_to_a
agentnet-acceptance bench --n 20 --pace-ms 400 --tag t
# 2.duplicates
agentnet-acceptance dump --data-dir $B / $A
```

## Step 3: Reachability matrix of the relay port from the host

| Check | Status | Detail |
|---|---|---|
| 3.reachability | PASS | tcp/60000: answers on <TS_IP> ONLY; no answer on 127.0.0.1 nor on the host's LAN IPv4(s) (matrix: 127.0.0.1:60000 no answer (nc exit 1: );<LAN_IP>:60000 no answer (nc exit 1: );<TS_IP>:60000 answers;127.0.0.1:60000 no answer (nc exit 1: ) (loopback checked explicitly);127.0.0.1:61000 answers (colima's forward of the VM-loopback publish; loopback only; see README);<LAN_IP>:61000 no answer (nc exit 1: );<LAN_IP>:18671 (R REST) no answer (nc exit 1: );<TS_IP>:18671 (R REST) no answer (nc exit 1: );). Listener on 60000 per lsof: [exit  ;Python <TS_IP>:60000 (LISTEN);. Residual: colima's forwarder listens on 127.0.0.1:61000 (loopback only). |
| 3.listener | PASS | lsof shows the only listener on tcp/60000 is bound to <TS_IP>:60000 (no wildcard, no loopback, no LAN) |

Exact commands:

```
# 3.reachability
lsof -nP -iTCP:60000 -sTCP:LISTEN ; nc -z -w 3 <each host IPv4> 60000 ; nc -z 127.0.0.1 60000
# 3.listener
lsof -nP -iTCP:60000 -sTCP:LISTEN
```

## Step 4: Tailnet status

| Check | Status | Detail |
|---|---|---|
| 4.tailnet_up | PASS | tailscale status lists this host and 7 other device(s) (not stopped / not logged out); this host's tailnet IPv4 is <TS_IP> (evidence/tailscale-status.txt, scrubbed: device names -> <host-*>, logins -> <user>). Read-only commands only: 'tailscale status', 'tailscale ip -4'. |

Exact commands:

```
# 4.tailnet_up
tailscale status ; tailscale ip -4
```

## Step 5: Path honesty and what is not tested

| Check | Status | Detail |
|---|---|---|
| 5.path_recorded | PASS | recorded, NOT claimed as a tunnel proof: route to <TS_IP> uses interface utun4 (LOCAL host route); utun4 idle 10 s delta 148099 bytes vs 21168 bytes (packets in +38 / out +38) around 3 delivered messages. Connections to <TS_IP>:60000 are host-local (lsof: both ends <TS_IP>). Same-host delivery: no WireGuard tunnel to another machine was crossed. |
| 5.cross_machine | UNTESTED | client on a DIFFERENT tailnet machine reaching R over WireGuard: not run (needs a second machine; kit is spike/relay-tailscale/remote-client.sh + remote-check.sh) |
| 5.acl | UNTESTED | Tailscale ACL / grants restricting tcp/60000 to tagged clients: not run; no policy was read or changed |
| 5.derp_nat | UNTESTED | DERP relayed path, NAT traversal / hole punching, tailscale ping path type: not run |
| 5.key_expiry | UNTESTED | node key expiry or ACL change effect on a live connection: not run |

Exact commands:

```
# 5.path_recorded
route -n get <TS_IP> ; netstat -I utun4 -b (idle, before, after) ; lsof -nP -iTCP -sTCP:ESTABLISHED
```

**Note (5.path).** route to the tailnet address from this host: interface <b>utun4</b> (flags LOCAL: it is this host's own address). utun4 counters (Ibytes+Obytes): idle 10 s delta 148099 bytes; during 3 delivered messages (window = send + wait for receipts) delta 21168 bytes, packets in +38 / out +38. The client containers sit in a VM behind the host and reach the relay through the host's own tailnet address, so the traffic is a LOCAL loop (relay forwarder and colima's forwarder both on this host, see evidence/lsof-established-60000.txt: source and destination are both <TS_IP>); whether it is looped through the tailscale TUN device or short-circuited is read here only from the counters and is not proof of either. No packet is shown to leave this machine, and no WireGuard tunnel to another machine is involved.


## Evidence index

- `summary.json` (machine readable), `checks.jsonl`, `run.log`
- `logs/` per-step command logs, `evidence/` JSON/text evidence, `daemon-logs/` redacted daemon stderr, `pcap/` captures and the filter outputs derived from them
