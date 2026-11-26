# Network simulations: WireGuard overlay and outbound-only clients behind simulated NAT

**Read this first.** Everything in this file was run on **one macOS arm64 host**, with containers in one colima VM (Ubuntu, kernel
6.8.0-117-generic), the amd64 `wakuorg/nwaku@sha256:cb4d14a2...` (v0.39.2) image under qemu. These are **simulations of properties**,
not tests of the real systems:

* Experiment W uses **kernel WireGuard** (the `wireguard` module of the colima VM, loaded with `modprobe`; no userspace fallback was
  needed or implemented) between containers on one docker bridge. It is **not Tailscale** (no coordination server, no ACLs, no MagicDNS, no
  DERP relays, no key distribution), **not NAT traversal**, and **not separate physical hosts**.
* Experiment N uses iptables MASQUERADE in gateway containers. It is **not** the endpoint-independent mapping of real home routers or CGNAT,
  there is **no hole punching** (clients only dial the relay, so none is needed), and it is **not separate physical hosts**.
* The goal.md rows "Cross-machine / NAT" (two actual separate hosts) and "Tailscale" (relay reachable by tailnet address) remain **UNTESTED**.
  What these runs add is bounded evidence for the properties those rows rely on. Instructions for the real runs are in the last section,
  clearly marked UNTESTED.

Reproduce: `spike/relay-wireguard/run.sh` and `spike/relay-nat/run.sh` (READMEs next to them). Both need the release binaries
(`cargo build --release --locked -p agentnet-cli -p agentnet-acceptance`, or `BIN_DIR=`). The binaries used for every run below were built
from a pristine `git archive HEAD` export (HEAD `1b77240`), independent of the working tree.

> **Real two-host run (2026-11-26):** besides the simulations below, one run used two real hosts (`results/cross-machine/20261126T190328Z/`): a Mac behind a home NAT and a cloud VM, joined by an SSH port-forward. Killing an SSH forward closes the connection cleanly, so the relay noticed within 10 s and held no stale socket; `tcp_retries2` was not exercised. After a 123 s outage the client re-listed the relay Connected in 4.2 s and a queued message was delivered in 49.5 s (single trial). A silent packet blackhole across real hosts was not tested.

> **Real public-internet runs (2026-11-26):** a relay on its own public IPv4 behind a cloud firewall (`results/public-ip-relay/20261126T204713Z/`) and a relay behind a provider's public wss/TLS edge (`results/public-relay/20261126T203405Z/`), each with a Mac client behind a home NAT, single runs. Summary in `docs/spike-report.md` section 7 row 2a and `docs/relay-setup.md` ("Your own relay on a public address"). They do not test NAT hole punching between clients.
>
> **Real Tailscale run (2026-11-26):** `results/tailscale-cross-machine/20261126T192147Z/` repeated the path-loss experiment on two real hosts over a real tailnet (one trial): with a 120 s silent drop the client noticed after 47.4 s, the relay's half-open socket ended about 48 s into the drop with `tcp_retries2=6`, the client was Connected 3.5 s after the path returned and the queued message was delivered after 33.4 s. **A second, accidental 82 s block showed a case the setting does not fix:** the relay was left with an *idle* stale socket (nothing to retransmit, so `tcp_retries2` never applies), closed every new connection from the client, and the client could not reconnect for 7 min 25 s; the stale socket disappeared 8 min after the client closed (cause UNTESTED). No fix for the idle case has been tested.

## Experiment W: relay reachable only over WireGuard

Topology (`spike/relay-wireguard/README.md`): underlay docker bridge `172.29.70.0/24` (the only thing the three "machines" share); WireGuard
overlay `10.66.0.0/24`, hub and spoke (R 10.66.0.1; A .2 and B .3 have R as their only peer, `AllowedIPs = 10.66.0.1/32`). Each machine is a
sidecar that owns `wg0` and the iptables, plus a Logos Delivery node sharing its namespace. R's node announces `--nat=extip:10.66.0.1`,
clients use `--staticnode=/ip4/10.66.0.1/tcp/60000/p2p/<R>`, discovery off, `--dns-addrs-name-server=127.0.0.1`, cluster 66. R's firewall:
INPUT policy DROP, tcp/60000 accepted only on `wg0` from 10.66.0.2 and .3, tcp/60000 on the underlay dropped by an explicit rule. Two
`agentnet serve` daemons on the host (private mode, static peer = R's overlay multiaddr) talk to the nodes' REST ports published on the docker
host's 127.0.0.1 (in a real deployment each agent runs next to its own node, loopback). WireGuard and node keys are generated per run into a
gitignored `.run/` and deleted on exit.

Runs kept (both from clean, 35 PASS, 0 FAIL, 0 UNTESTED each): `results/network-sim/wireguard/20261126T033513Z/` and
`results/network-sim/wireguard/20261126T034919Z/` (`SUMMARY.md`, `checks.jsonl`, `summary.json`, `evidence/`, `pcap/`). A third, development
run was discarded (it exposed two script bugs, fixed: a test conversation that was shared between two probes, and a packet filter that
counted a stale flow). Per-check results:

| Check | Result | Key numbers (run 1 / run 2) |
|---|---|---|
| 1.kernel | PASS | `ip -d link`: kind `wireguard` on r, a, b |
| 1.handshakes | PASS | non-zero latest handshake on all three (`evidence/wg-show-initial.txt`) |
| 1.nodes_connected | PASS | A's and B's node each list only R, as `/ip4/10.66.0.1/tcp/60000`; R lists A and B at their overlay addresses 10.66.0.2 / .3 |
| 1.firewall | PASS | rules in `evidence/firewall-r-initial.txt` |
| 2.serve, 2.contacts, 2.netstatus | PASS | `doctor` exit 0; `network status`: private, ready, one peer = R |
| 2.cli_send, 2.inbox_auth, 2.reply | PASS | first A->B message delivered with receipt after 562 / 546 ms; sender authenticated at B; B->A reply delivered |
| 2.mcp | PASS | MCP `send_message`, negotiated 2026-07-28; B notified after 153 / 38 ms; A status `delivered` at +391 / +297 ms |
| 2.bench (20 each way, 400 ms pacing) | PASS | A->B 20/20, p50/p95/p99 = 391/518/608 and 375/487/500 ms; B->A 20/20, 406/533/615 and 401/509/524 ms; 0 duplicate rows, 0 duplicate events |
| 3.underlay_only_wg | PASS | main capture 4542 / 4470 packets: WireGuard UDP/51820 1014 / 994; UDP not 51820: 0; TCP between the machines: 0; tcp/60000: 0; IP packets with an endpoint outside 172.29.70.0/24: 0; packets with an overlay address: 0; non-multicast IPv6: 0 |
| 3.no_cleartext | PASS | 0 packets contain the ASCII `multistream` or `agentnet` (REST via the docker gateway excluded) |
| 3.paths_unguarded | PASS (with a finding) | from A: R's underlay address:60000 times out (5 SYNs on the wire, dropped by R's rule); B's overlay address times out BUT 3 SYNs for 10.66.0.3 left eth0 in cleartext via the default route (see Findings) |
| 3.paths_guarded | PASS | with `iptables -I OUTPUT -d 10.66.0.0/24 ! -o wg0 -j REJECT` the same probe is refused at once, 0 overlay-address packets on the underlay |
| 4.nc_blocked | PASS | key-less intruder on the underlay: nc to R:60000 timed out, A:60000 failed, R's REST failed; R's drop-rule counter 10 -> 15 (SYNs arrived and were dropped) |
| 4.intruder_not_peer | PASS | intruder node (`--staticnode` = R's underlay address, cluster 66, shard 0, two explicit dials): `CannotConnect`; R's connected peers unchanged (A and B only) |
| 4.intruder_no_frames | PASS | while A sent 5 messages to B (delivered) the intruder, subscribed to both inbox content topics, polled 0 / 0 frames |
| 4.control_connects | PASS | CONTROL: drop rule removed, accept inserted: the same intruder Connected to R after 122 / 470 ms |
| 4.control_sees_frames | PASS | intruder received live frames on B's and A's topics (first after ~4.1 s) and its Store query to R returned 20 frames |
| 4.control_ciphertext_only | PASS | 22 frames obtained, 564 bytes each, no plaintext marker or address in any payload |
| 4.control_cleartext | PASS | control capture: ~131 tcp/60000 packets intruder<->R, 2 with cleartext `multistream` (positive control for the string search) |
| 4.restored | PASS | rule restored, fresh nc blocked again, A and B still connected, a message sent after the restore delivered (~0.55 s) |
| 5.undelivered | PASS | after `wg set wg0 peer <B> remove` on R, A's message to B stayed `sent` for the 92 s observation, 0 rows at B |
| 5.b_node_loses_r | PASS | B's node stopped listing R after 47.4 / 48.5 s (node health monitor: `Too many consecutive ping failures ... Killing all connections`, `evidence/container-logs/an-wg-b-node.log`) |
| 5.b_daemon_not_ready | PASS | B's daemon `ready=false` after 52.5 / 53.6 s |
| 5.recovery | PASS | after re-adding the peer: WireGuard handshake after 6.2 / 5.5 s; **B's node lists R again only after 363 s / 163 s**; B's daemon ready after 363 s / 338 s; A's message delivered after 375 s / 338 s (see Findings) |
| 5.no_fallback | PASS | captures of the removal and re-add windows: only WireGuard UDP on the underlay, nothing else, nothing outside the subnet |
| 6.queued | PASS | R's node stopped, tunnel up: A's message `queued` after 60 s, A `ready=false`, B received 0 |
| 6.recovery | PASS | after R's node restarted: A ready after 4.1 / 2.1 s, message delivered 32.6 / 44.9 s after R's `/health` |
| 6.no_fallback | PASS | capture of the whole outage and recovery: only WireGuard UDP on the underlay |

What this shows: the relay can be reached only through the WireGuard interface when the firewall says so; clients that hold the overlay
configuration exchange authenticated messages through it; on the underlay the only traffic between the machines is WireGuard UDP; a peer that
is not in R's WireGuard config cannot reach tcp/60000 and sees no frames; and with the tunnel or the relay node gone nothing falls back to the
underlay (the daemons only ever know the configured overlay address).

What it does not show: anything about Tailscale (coordination, ACL semantics, key expiry, DERP/relay paths, MagicDNS), real network latency or
loss, NAT traversal, or separate hosts. The underlay is a docker bridge with ~1 ms RTT. The REST connections between the host and the nodes
are cleartext on that bridge by construction of the simulation.

## Experiment N: outbound-only clients behind simulated NAT

Topology (`spike/relay-nat/README.md`): public bridge `172.30.80.0/24` (R .10, gateway public sides .21/.22), LAN-A `192.168.101.0/24` and
LAN-B `192.168.102.0/24`, each with a gateway container (default route of the client; MASQUERADE; FORWARD default DROP, inbound only for
established flows, mid-stream packets without a mapping dropped) and one client node (`--nat=none`, no published libp2p port). R announces
`--nat=extip:172.30.80.10`. REST of each client node is published to the docker host's 127.0.0.1 for its agent (in reality co-located).

Runs kept: `results/network-sim/nat/20261126T041425Z/` and `results/network-sim/nat/20261126T050510Z/` (15 checks each, 15 PASS, 0 FAIL, 0 UNTESTED in both). A development run that wrote its packet
captures to a path the colima VM cannot see was discarded and replaced by these.

| Check | Result | Key numbers |
|---|---|---|
| 1.topology | PASS | each client node lists exactly one peer, R; client containers publish only REST (`evidence/published-ports.txt`) |
| 1.matrix | PASS | A and B reach R:60000; R, the other LAN and the other gateway cannot reach either client's tcp/60000 (all 8 negative probes time out) although the node listens on its LAN (gw-a reaches it from the LAN side). `evidence/reachability-matrix.txt` |
| 1.r_view | PASS | R's `/admin/v1/peers` lists A as `/ip4/172.30.80.21/tcp/<port>` and B as `/ip4/172.30.80.22/tcp/<port>` (the gateways' public addresses and translated ports); 0 packets on the public bridge carry a 192.168.x.x address; conntrack shows `src=192.168.101.10 ... sport=P` -> `dst=172.30.80.21 dport=P` (MASQUERADE kept the source port) |
| 2.bench (20 each way) | PASS | run 1 / run 2: A->B 20/20, p50/p95/p99 = 383/489/491 and 401/506/507 ms; B->A 20/20, 402/506/536 and 382/499/502 ms; 0 duplicate rows or events |
| 2.offline | PASS | B's node+daemon stopped, 5 sent (A: `sent`), B back: inbox complete (5 unique) 600 ms after the daemon start in run 1, A's 5 receipts 660 ms after (run 2: see its SUMMARY) |
| 3.flush | PASS (slow, variable) | `conntrack -F` on gw-a, mid-stream packets then silently dropped. Run 1 / run 2: A's node noticed after 48.2 / 52.7 s (health monitor kills the connection after 3 failed pings); A's node listed R again after **654.8 / 55.0 s**; the A->B message sent right after the flush was delivered after **835.9 / 57.5 s** |
| 3.flush_rst | PASS (slow, variable) | same flush, gateway answers with TCP RST: A's node noticed after 65 ms / 860 ms; listed R again after 466 / 42 s; **daemon ready again after 397 / 964 s**; message delivered after 684 / 1096 s |
| 3.gw_restart | PASS | `docker restart an-nat-gw-a`: A's node noticed after 47.8 / 50.6 s, listed R again after 66.6 / 53.1 s, A->B message delivered after 81 / 109 s |
| 4.idle_with_daemons | PASS | 600 s idle, conntrack established timeout 120 s on both gateways: both nodes still Connected, R's peer entries (incl. translated ports) unchanged; largest silent gap on the A<->R flow 5.2 / 9.3 s; one message each way afterwards delivered after 16.4 / 22.0 s (A->B) and 16.4 / 23.2 s (B->A) |
| 4.idle_nodes_only | PASS | daemons stopped (no Store sync): same, largest gap 6.0 / 9.0 s; after restarting the daemons one message each way delivered after 30.6 / 14.0 s (A->B) and 30.7 / 32.4 s (B->A), counted from the daemon restart |

The same action gives very different times between runs (e.g. 55 s versus 655 s to reconnect after the same flush); there are only two runs of
each; the W-topology spread was explained afterwards by a half-open socket on the relay (Findings 1, `results/reconnect/20261126T065412Z/SUMMARY.md`). That the N runs had the same cause was not checked (UNTESTED).

What this shows: two clients with no inbound path (verified from R, from the other LAN and from the other gateway) exchange authenticated
messages and recover offline messages through a relay that sees them at their gateways' addresses; with conntrack timeout 120 s a 10-minute
idle period did not break the connection because the nodes themselves emit a packet at least every ~9 s (libp2p/gossipsub traffic), with or
without the daemons.

What it does not show: real NAT behaviour (port-restricted/symmetric mappings, short UDP-style timeouts on idle TCP, CGNAT), carrier/ISP
middleboxes, real latency, hole punching (not needed), or separate hosts. Because the nodes' own traffic keeps the mapping alive, the idle test
does **not** tell what happens with a NAT whose timeout is shorter than the ~9 s packet spacing.

## Findings, failures and surprises

1. **A silently dropped path takes about 48 to 53 s to be noticed; recovery after the path is back is slow and highly variable.** Both W
   (peer removal) and N (mapping loss) show the same pattern: the nwaku health monitor logs `Too many consecutive ping failures, node likely
   disconnected. Killing all connections` after ~48 s (W: 47.4 / 48.5 s; N flush: 48.2 / 52.7 s), and the AgentNet daemon then reports
   `ready=false` within ~5 s in W (in N flush run 2 it never observed `ready=false` because the node was back within 2 s of noticing). With a
   RST the node notices within 0.1 to 0.9 s. What is slow is the way back: with the path restored (WireGuard handshake after ~6 s, or a fresh
   SYN allowed by the gateway) the node listed R again after **163 s and 363 s** (W, two runs), **655 s and 55 s** (N flush, two runs) and
   **466 s and 42 s** (N RST variant); after the RST flush of run 2 the daemon was ready again only after **964 s**, and the messages queued
   meanwhile were delivered after up to **1096 s**. **Cause isolated afterwards** (`results/reconnect/20261126T065412Z/SUMMARY.md`, W topology, single host): the node kills its
   own connections after ~48 s but the close never reaches the relay. nwaku pings only peers it dialled, so the relay never notices and its
   kernel keeps a half-open tcp socket to the client, retransmitting. When the path is back, the client's default-deny firewall drops those
   retransmits silently (no reset), so the socket lives until the relay's `tcp_retries2` is exhausted (15 by default: 21.8 min in the one trial that measured it, the "up to 16
   minutes" above). While it exists every redial completes tcp and the security handshake and is then closed by the relay (tcpdump on B's
   `wg0`), so the adapter's 10 s redial cannot help; it does reconnect within seconds once the socket is gone, and without any redial the
   node did not reconnect on its own (the earlier suspects, peer-manager backoff and the online monitor, are not what delays it).
   In 4 of 4 fresh-topology trials with the relay holding that socket at the restore point, the client had not reconnected after 300 s; with `net.ipv4.tcp_retries2=6` on the
   relay the stale socket died 31 to 32 s after the path was lost and the client was back 3.4 to 9.5 s after the path returned (4 of 4);
   with a tcp-reset REJECT rule on the client for stale relay segments, 2.3 to 9.7 s (4 of 4). Why the relay closes the new connection
   (probably one connection per peer id) is UNTESTED, as are real Tailscale and NAT devices.
   **Idle variant** (`results/reconnect-idle/20261126T233013Z/SUMMARY.md`): when the relay's socket has nothing in flight, `tcp_retries2` never applies; reproduced deterministically (B's FIN lost, R idle): refused for 401 s and 496 s. A relay-side watchdog destroying sockets with no data received for 60 s (`spike/relay-wireguard/scripts/stale-watchdog.sh`) recovered 3 of 3 (2.4 s after the path returned).
   This is the same family as E12 in
   `docs/spike/notes-daemon-rest.md` (a client that loses its relay does not simply reconnect). It is the realistic failure for outbound-only
   clients: expect anywhere from under a minute to a quarter of an hour after a NAT mapping loss or a tunnel interruption. Messages were
   not lost: every one was delivered, within its TTL, from the sender's queue and Store. Reconnect after a gateway restart (53 to 67 s) and
   the relay-node restart in W (A ready after 2 to 4 s, message after 33 to 45 s) were much faster, so the slowness is specific to a
   connection that died by silence or RST while the node still believed it had been online.
2. **Messages after a long idle period were delayed by 14 to 32 s** in all four cases (idle with daemons: 16.4 and 22.0 s; nodes only: 30.6
   and 14.0 s for A->B, 30.7 and 32.4 s for B->A), although the TCP connection had survived untouched and the largest silent gap was 9.3 s.
   Not investigated; candidates are the gossipsub mesh state after 10 minutes without application traffic and the history-sync interval
   (15 s). Reported, not explained. (Fresh-topology and warm-topology deliveries in the same runs take about 0.4 to 0.6 s.)
3. **WireGuard `AllowedIPs` does not stop a host from sending overlay-prefix packets out of the underlay interface.** From A, a connection to
   the unpeered overlay address 10.66.0.3 produced 3 cleartext SYNs on the underlay via the default route (`3.paths_unguarded`). AgentNet
   itself never does this (its only destination is the configured peer), but a hardened client should add the OUTPUT guard of `3.paths_guarded`
   (or run the node in a namespace whose only route to the overlay prefix is `wg0`). The run scripts apply the guard from that point on.
4. **Cluster/shard separation is not access control, demonstrated:** with the firewall rule removed the intruder joined R's mesh in 122 to
   470 ms and received live frames on both inbox topics within about 4 s, and its Store query returned 20 stored frames. It saw only
   564-byte ciphertext frames (E2E encryption held, no plaintext found), but it learns topics, timing and sizes. Removing an accept rule does
   not evict an established flow; the drop rule is therefore placed before the established-accept rule.
5. **A node's REST answers `404 relay endpoints are not available while initializing`** for ~10 s after `/health` is 200 on a node that has no
   peer (the intruder). A subscription POSTed too early fails silently; the script retries until HTTP 200.
6. **Mid-run edits of a running bash script crashed a run** (my own mistake; the run was discarded). Not a product issue.
7. Not found: any AgentNet product bug. The delays in 1 and 2 are node/adapter behaviour under a silent path loss; no incorrect state
   (duplicate, lost-after-TTL, wrong sender) was observed: every message was delivered once with an authenticated receipt.

## Limits shared by both experiments

Single host and single VM; qemu-emulated amd64 nodes (latencies include emulation and the daemons' 250 ms poll); sample sizes: 20 messages per
direction per run, 2 runs per experiment; REST between host and node is cleartext on the simulation bridges; captures are taken on the docker
bridges from the VM netns (snaplen unlimited) and cannot see traffic that leaves the VM another way; the "0 packets outside" claims are about
those bridges only.

## What a real Tailscale run would need: UNTESTED

None of this was run. It needs a tailnet account, an auth key, and at least two machines (relay host + one client host; two client hosts for
the full exchange).

1. Tailnet policy file: tag owners and an ACL that admits only tagged clients to the relay port, nothing else.

   ```json
   {
     "tagOwners": {"tag:agentnet-relay": ["autogroup:admin"], "tag:agentnet-client": ["autogroup:admin"]},
     "acls": [
       {"action": "accept", "src": ["tag:agentnet-client"], "dst": ["tag:agentnet-relay:60000"]}
     ]
   }
   ```

   (Tailscale ACLs are default-deny; the REST port 8645 is deliberately not listed, it stays on loopback.)
2. Join each host with a tagged, pre-authorised, ideally ephemeral key: `tailscale up --auth-key=tskey-auth-... --advertise-tags=tag:agentnet-relay`
   (or `tag:agentnet-client`). Note `tailscale ip -4` (100.x.y.z) of the relay.
3. Start the relay from `spike/relay-wireguard/docker-compose.yml` ideas, with the overlay IP swapped for the tailnet IP: `--nat=extip:<relay 100.x>`,
   `--listen-address=<relay 100.x>` (or 0.0.0.0 with host firewall), host networking so the node sees `tailscale0`
   (`agentnet relay print-config --ip <100.x> --peer-id <id>` prints the flag set and a host-network compose snippet, itself UNTESTED).
   Clients: `--staticnode=/ip4/<relay 100.x>/tcp/60000/p2p/<id>` and `agentnet init --node-url http://127.0.0.1:8645 --peer /ip4/<relay 100.x>/tcp/60000/p2p/<id>`
   (private mode accepts 100.64.0.0/10).
4. What a real run must show (none shown here): `nc -vz <relay 100.x> 60000` fails from an untagged tailnet node and from the public internet,
   succeeds from a tagged client; `agentnet doctor` all `[ok]`; `network status --verbose` lists exactly the relay; an exchange between two
   clients on different hosts reaches `delivered`; `tcpdump -i <physical iface>` on a client shows only WireGuard/DERP/STUN traffic and
   coordination-server HTTPS, nothing to 1.1.1.1 or other peers; the unguarded-overlay-prefix finding above does not apply the same way
   (Tailscale installs its own routes and firewall marks) but should be checked; DERP-relayed versus direct path should be recorded
   (`tailscale status`, `tailscale ping`); key expiry and ACL change effects on a live connection should be tried (the removal test above is
   only an analogue).

## What a real two-host run would need: UNTESTED

Two (better three) physical or cloud hosts on different networks, the relay on a host with a reachable address (public IP or port-forward),
clients behind real NAT with no inbound port. Use the compose files of `spike/relay` (relay on one host with `--nat=extip:<public IP>`,
`docker-compose.yml` ports `60000:60000` restricted by the host firewall to the client addresses; on each client host a client node with
`--staticnode` = the relay's address) and the steps of `docs/acceptance.md`, recording: the topology and addresses, `ss -tn`/`tcpdump` on
the clients showing only outbound connections to the relay, R's `/admin/v1/peers` showing the clients' NATed public addresses, the same 20/20
exchange, offline recovery, a deliberate NAT-mapping loss (router reboot or `conntrack -F` on a Linux router) and an idle test across the
router's real timeout. Compare the silent-path-loss recovery times of finding 1 with the real ones.

## Evidence index

`results/network-sim/wireguard/<ts>/` and `results/network-sim/nat/<ts>/`: `SUMMARY.md` (per-check detail and exact commands), `checks.jsonl`,
`summary.json`, `run.log`, `logs/`, `evidence/` (JSON and text; `u-*-summary.json` and `*-flows.txt` are the packet summaries with the exact
filters), `pcap/*.pcap` (full captures, readable with tcpdump), `daemon-logs/` (redacted), `evidence/container-logs/`.
