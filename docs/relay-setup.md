# Running your own relay, Store node and client node

Scope: how to run a user-owned Logos Delivery **service node** (relay + Store, optionally Filter and Light Push) and a
**client node** that `agentnet serve` talks to, for private mode. Every flag below is the set that was run in
`spike/relay/docker-compose.yml` and that `agentnet relay print-config` prints (full output saved in
`results/audit/relay-print-config.txt`). **All of it was run on one macOS arm64 host, with containers on a colima VM,
the amd64 image under qemu.** Nothing here was tested across machines, behind NAT, over Tailscale or against a public
network (see section 9 and `docs/spike-report.md`).

## 1. Topology

```
  agentnet serve  --REST (loopback only, no auth)-->  client node  --libp2p tcp/60000-->  service node (relay+store)
  (identity, SQLite)                                  (relay client, static peer = service node)
```

* The **client node** is a Logos Delivery node next to each `agentnet serve`. AgentNet is not a single static binary:
  the node is a separate process (a container here). There is no embedded node (`docs/spike-report.md`, native FFI section).
* The **service node** is reachable by all clients, relays frames between them and stores them for later retrieval.
  Clients dial it; clients need no inbound port (this is the design; **cross-machine/NAT outbound-only operation is UNTESTED** (simulated on one host: `docs/network-simulations.md`)).
* AgentNet talks only to the **client** node's REST API (`network.node_url`), never to the service node.
* **Hard rule: one Logos Delivery client node per agent (one `agentnet serve` per node). Sharing a node between agents is unsupported.**
  The node's REST receive path is a single in-memory cache per node and `GET` is destructive (returns *and deletes*). Two daemons
  polling one node therefore drain each other's frames: if their inbox buckets (16 by default, `docs/protocol.md` section 3) are
  the same, they poll the same content topic and each message is delivered to whichever daemon polls first, the other never sees
  it live; even with different buckets they share the 50-slot cache, the node's peer list and its subscriptions. What the user sees
  is **delayed delivery, not loss**: the starved recipient only gets the frame through the next history sync (up to
  `history_sync_interval_s` (default 15 s; 60 s when the measurements in this document were taken), from the service node's Store) or the sender's retry. The acceptance script
  (`scripts/acceptance.sh`, `new_agent`) had to re-draw identities until their buckets differed to keep two test agents on one node apart;
  that is a test workaround, not a supported deployment. A wrongly configured daemon also leaves its peer in the shared node (section 4a).

## 2. Image

`wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73` (tag `v0.39.2`, binary
`/usr/bin/logosdeliverynode`, 94.7 MB, Alpine, runs as root inside the container; `results/a1-daemon/pull_v0.39.2.txt`,
`rootfs-info.txt`, `image-size.txt`).

* **linux/amd64 only.** Docker Hub publishes no arm64 image. On arm64 hosts it runs under qemu (works on the test host,
  adds latency; every latency figure in the spike report includes that). A native arm64 build of the reference node from source is
  not part of the verified set; the FFI audit built `liblogosdelivery.so` natively on Linux arm64 (`docs/spike-report.md` section 5, ADR 0001), which is a library, not this image.
* Docker Hub lags upstream: `v0.40.0` (2026-11-13) is not published there; `latest` is a nightly build
  (`results/a1-daemon/manifest_wakuorg_nwaku_*.json`). The pin is by digest. The image is **not signature-verified**
  (UNTESTED).
* The compose plugin (`docker compose`) is not installed on the test host; the standalone `docker-compose` v5.6.0 was used and
  `spike/relay/scripts/up.sh` calls `docker-compose`.

## 3. Flags (verified set)

Service node (from `agentnet relay print-config`; replace the placeholders):

```
--nodekey=<64 hex>             # fixes the libp2p peer id (section 4)
--nat=extip:<service node IP>  # the address clients dial; avoids UPnP/PMP probing
--relay=true --store=true --filter=true --lightpush=true
--store-message-db-url=sqlite:///data/store.sqlite3
--store-message-retention-policy=time:604800;capacity:100000   # 7 days; see section 6
--cluster-id=66 --num-shards-in-network=1 --shard=0
--discv5-discovery=false --peer-exchange=false --relay-peer-exchange=false --rendezvous=false
--enable-kad-discovery=false --quic-support=false --mix=false --rln-relay=false
--dns-addrs-name-server=127.0.0.1                           # section 5
--listen-address=0.0.0.0 --tcp-port=60000 --peer-persistence=false --metrics-server=false
--max-msg-size=150KiB --rest=true --rest-admin=true --rest-address=127.0.0.1 --rest-port=8645
--rest-relay-cache-capacity=1000 --rest-messaging-cache-capacity=1000                 # section 3a
--local-storage-path=/data --log-level=INFO
```

Client node: the same common flags, plus `--store=false --filter=false --lightpush=false`, `--nat=extip:<client IP>`, and

```
--staticnode=/ip4/<service IP>/tcp/60000/p2p/<service peer id>
--storenode=<same multiaddr>   --filternode=<same>   --lightpushnode=<same>
```

and `agentnet.toml`: `node_url = "http://127.0.0.1:<client REST port>"`, `peers = ["<same multiaddr>"]`, `cluster_id = 66`.

Notes grounded in the spike (`docs/spike/notes-daemon-rest.md` s1.2):

* **Cluster ids 1, 2, 3 and 16 are public presets** (`--cluster-id=1` silently applies the TWN preset with public bootstrap nodes and
  RLN). AgentNet's private mode rejects them; do not use them on the node either.
* Service protocols default to ON for Filter and Light Push on every node; clients set them false explicitly (done above).
* `--rest-admin=true` is needed on the **client** node: AgentNet's isolation audit reads `GET /admin/v1/peers` and its redial uses
  `POST /admin/v1/peers`. On the **service** node AgentNet does not use REST at all; the verified topology enabled admin there for
  diagnostics. Disabling it on the service node is expected to be safe but was **not tested**.
* REST has **no authentication**. `--rest-address=127.0.0.1` is the right setting when the node runs on the host. In the compose
  snippets the in-container address is `0.0.0.0` and the published port is bound to the host loopback
  (`127.0.0.1:<port>:8645`); keep it that way.
* Receive path limits that shape sizing: the node's REST relay cache is 50 slots by default, shared by all topics, and `GET` is destructive
  (`--rest-relay-cache-capacity`); AgentNet polls every 250 ms by default (`delivery.poll_interval_ms`) and uses Store for recovery.
  The recommended value is **1000** (section 3a).
* **Connection churn is expected.** The node's REST server (nim-presto) answers every request with `Connection: close`, even when the
  request asks for `keep-alive` (`results/fixups/keepalive-curl-explicit.txt`), so the adapter cannot reuse connections: it deliberately
  disables pooling (`pool_max_idle_per_host(0)`, commented in `crates/transport/src/logos_rest/mod.rs`) and opens one short-lived loopback
  connection per poll or publish (about 4 polls per second per daemon plus publishes). Thousands of `TIME_WAIT` sockets on
  `127.0.0.1:<REST port>` after a busy run are normal, not a leak. If it matters (very high rates), shorten
  `net.inet.tcp.msl` on macOS or `tcp_tw_reuse` on Linux; do not poll slower than the cache can absorb.

### 3a. REST cache capacity and burst latency (measured)

The measurements are in `results/fixups/burst-latency.md` (single host, amd64 nodes under qemu; **not representative of a real network**).

* `--rest-relay-cache-capacity` (and `--rest-messaging-cache-capacity`, unused by AgentNet) is recommended at **1000** instead of the node default 50.
  The cache is volatile, destructive on read and silently evicts the oldest entries when full. Measured on the client node without AgentNet:
  100 messages published back to back reached a single poll as only 30 to 50 entries with the default capacity
  (`results/fixups/node-cache-probe-cap50.txt`). Memory worst case is capacity x `--max-msg-size` (1000 x 150 KiB = 150 MiB), typical use is far less.
  This is cheap insurance for the moments a daemon cannot poll (restart, stall, a long SQLite transaction), not the main cause of slow bursts.
* **The dominant cause of a slow burst on the test topology was not the cache: it was a cold relay mesh.** After a client node is (re)created, live relay between
  two client nodes did not work until about **62 s** after the node reported itself connected to the service node, 3 of 3 trials
  (`results/fixups/mesh-warmup.txt`; mechanism not verified, consistent with libp2p gossipsub's 60 s prune backoff and with E12). A message sent during that window is accepted by the node
  (`publish` returns 200) and then never reaches the recipient's live queue; it arrives through the sender's retries (first retry delay uniform in
  [1 s, 2 s] since the retry-floor fix (it was [1 ms, 2 s] when measured), doubling) or, at the latest, the recipient's next history sync, up to `history_sync_interval_s` (default 15 s; 60 s when the measurements in this document were taken) later. That is the 24 to 31 s p50
  (and about 60 s p95/p99) seen in two of three acceptance runs, and the 0.3 s in the third is the same burst on a node that was already warm.
* Operational consequence: **after restarting a client node or the service node, expect up to about a minute in which delivery depends on retries and Store**
  (messages are delayed, not lost, inside the retention and TTL windows). Do not restart nodes casually while agents are exchanging time-critical traffic.
  A shorter `delivery.history_sync_interval_s` on the recipient (for example 10 to 15 s) shortens that tail at the cost of one Store query per interval
  (measured effect in `results/fixups/burst-latency.md`).

## 4. Static peer identities (nodekey to peer ID)

1. Generate one key per node: `openssl rand -hex 32` (`agentnet relay print-config` notes say the same). Keep it secret; anyone with it can run a
   node with that peer id. Never reuse a key on two nodes (the second node stayed `CannotConnect` in E10 with no loud error).
2. Start the node with `--nodekey=<hex>`. Its peer id is deterministic. Read it from the running node:
   `curl http://127.0.0.1:<rest port>/info` returns `{"listenAddresses":["/ip4/<ip>/tcp/60000/p2p/<peerId>"],...}`
   (checked against the running spike R1: `/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV`).
   The `/p2p/<peerId>` part is what goes into `--staticnode`, `--storenode` and `peers = [...]`.
3. `agentnet.toml` `peers` must be **literal private IPs** with the peer id (private mode rejects hostnames and public IPs,
   `docs/configuration.md`). The allowlist of peer ids used by the runtime audit is derived from them.
4. Order of start: service node, then client node, then `agentnet serve`. A client that starts before the service node is listening
   waits for its peer manager's backoff (about 2 minutes observed in E5/E8); AgentNet's redial shortens this (section 5).

## 4a. A wrong static peer pollutes the node (and `doctor` of whoever shares it)

On startup and whenever no allowlisted peer is connected, the adapter POSTs exactly its configured `peers` to the node's `/admin/v1/peers`
(only after the configuration passed validation: private literal IP, peer id in the allowlist; a rejected configuration never touches the node,
`rejected_config_never_contacts_the_node_or_dials` in `crates/transport/src/logos_rest/tests.rs`). A configuration that is valid but names the
**wrong peer id** (the acceptance run's isolation test) is therefore dialled: the node remembers that peer as `CannotConnect` (peers are not
persisted: `--peer-persistence=false`, so restarting the client node clears it). Another agent's `agentnet doctor` on the same node then reports
`peers == allowlist` as failed, although the adapter's isolation audit, which only considers **connected** peers, is satisfied.
This is one more reason for the one-node-per-agent rule in section 1. If it happens: `docker restart <client node>`.

## 5. The DNS online-monitor setting (E7, E8, E12)

With every discovery option disabled the node still resolves `one.one.one.one` via **1.1.1.1 every 5 seconds** (its "am I online" check,
`waku/node/health_monitor/online_monitor.nim`); that was the only external destination in the capture
(`results/a1-daemon/egress-default-dns.egress.txt`, 150 s capture of three nodes, whole stack restarted inside the capture).

* `--dns-addrs-name-server=127.0.0.1` removes that contact: 1175 packets in 100 s, **0 with an endpoint outside the container subnet**
  (`results/a1-daemon/e7b-egress-dns-localhost-run.txt`), and relay/Store still worked (`e7b-functional-check-dns-localhost.txt`).
* Consequence on a network without egress: the online monitor marks the node offline when it has no connected peers and the DNS
  check fails, and the peer manager does not dial while offline. With the default 1.1.1.1 on an `internal: true` network a client **never connected**
  (> 5 min, `results/a1-daemon/e8a-internal-net-default-dns.txt`); with a DNS stub inside the network it connected after 2 s (`e8b-...`).
* With `127.0.0.1`, a client that **loses its only peer never redials its `--staticnode`** (E12: still disconnected after > 240 s).
  AgentNet's adapter therefore POSTs exactly its configured `peers` to `/admin/v1/peers` when no allowlisted peer is connected
  (rate limit 10 s). Measured: service node stop -> start -> client ready again after **11.4 s** (4 redial attempts); client node restart ->
  ready after 3.4 s (`results/b-transport/relay-disruptive-tests.log`).
* **Reconnecting is not the mesh being usable.** After that service-node restart live relay delivery stayed broken for about 9 minutes
  (empty or flapping gossipsub mesh; cause not found, E12). AgentNet recovers those messages through Store catch-up (up to
  `history_sync_interval_s` (default 15 s; 60 s when the measurements in this document were taken) later) **if the Store holds them**. History during that specific gap was not separately tested.
* The spike compose files now default `DNS_NS` to `127.0.0.1` (`${DNS_NS:-127.0.0.1}`), matching `agentnet relay print-config`; they used to
  default to the upstream `1.1.1.1`. `DNS_NS=1.1.1.1` can still be set explicitly to reproduce the upstream behaviour
  (`spike/relay/scripts/egress-capture.sh` does, to document it); `DNS_NS=127.0.0.1 ./scripts/up.sh` remains valid.

## 6. Retention and what it means for offline delivery

* Store retention is set on the **service node**: `--store-message-retention-policy=time:<seconds>;capacity:<n>` (node default
  `time:172800`). **Recommended for a real deployment: `time:604800;capacity:100000` (7 days)**, which is what `agentnet relay print-config` prints. It matches the
  daemon's default `storage.retention_hours = 168` and the maximum message TTL (7 days). `capacity` counts frames (every message and every receipt is one frame, so 100000 frames are
  roughly 50000 delivered messages); bodies are padded and a stored frame may be up to `--max-msg-size`, so check disk use if your agents send large bodies.
  `spike/relay` keeps the SHORT `time:3600;capacity:5000` as its test default on purpose (the retention experiments and a small store; a comment in the compose file says so).
  The 7-day value was started on the test topology as described in `results/fixups/retention-7d-check.txt`; long-term behaviour (pruning at 7 days) was **not** exercised.
* **What is actually recoverable is the MINIMUM of three windows**: the relay's Store retention, the message TTL (`delivery.default_ttl_s`, default 24 h, at most `max_ttl_s` = 7 days) and the daemon's own
  `storage.retention_hours` (default 168), which bounds the client's database and how far back its history sync asks. Raising one of them alone changes nothing:
  with the old one-hour relay retention, `retention_hours = 168` still only recovered one hour from Store. A recipient that is offline longer than that window loses the message unless the sender is still retrying (sender retries
  republish with a fresh timestamp up to `max_attempts` = 20 over a bounded backoff, `docs/protocol.md` s8.2).
* The node applies the policy **only at start and then every 30 minutes** (hardcoded): measured, `time:60` pruned nothing 70 s later
  without a restart (`results/a1-daemon/e6-retention.txt`). Expired history returns `200` with an empty list; there is no "expired" indicator.
* Store data persists across restarts only if `/data` is a volume (the SQLite file). Messages published with `ephemeral:true` are never stored.
* Store queries have a 24 h time-range cap (`time range exceeds 24h`); AgentNet windows its history queries accordingly.
* Recovery measured: 20 offline messages recovered 20/20 from Store in 48 ms after the recipient node restarted
  (`results/a1-daemon/rust-probe-offline-45d196c.json`); 20/20 through the full AgentNet crypto path
  (`results/a2-e2e-crypto/persistence-1795640646489.json`). Single host, small sample.

## 7. Clock synchronisation

* **Run NTP on the service node and every client host.** The Store node's archive silently refuses messages whose publisher timestamp
  differs from the **store node's** clock by more than **20 s** (`waku_archive/archive.nim:36`), while relay delivery still works
  (`docs/spike/notes-daemon-rest.md` E3: 60 s past/future timestamps were relayed and **not archived**). With clock skew > 20 s offline
  recovery silently fails with no publish error.
* AgentNet itself accepts `created_at` up to `delivery.clock_skew_s` = 120 s in the future. `agentnet doctor` compares the host clock
  to the node's (`clock: within 1 s of the node's clock`).

## 8. Firewall guidance

| Port | Where | Rule |
|---|---|---|
| tcp/60000 (libp2p) | service node | Allow **only from the known client addresses**. Cluster/shard ids are **not access control**: anyone who can reach this port and knows cluster 66 / shard 0 can join the mesh, subscribe to every bucket topic and publish (`docs/threat-model.md` T13). Verified in the WireGuard simulation: with the rule in place a key-less peer on the same network could not connect; with it removed the same peer joined the mesh and read ciphertext frames and Store history. |
| tcp/60000 | client node | No inbound rule is needed for the design (clients dial out). The compose snippet publishes `60000` only for the service node. |
| REST (8645 in container) | every node | **Never expose.** Publish only on host loopback (`127.0.0.1:<port>:8645`). No authentication; `--rest-admin=true` allows dialling arbitrary peers. |
| udp (QUIC), 9000, 30303, websockets | all | Not used; `--quic-support=false`, discovery off. |
| Egress | client nodes | With `--dns-addrs-name-server=127.0.0.1` and static peers the only observed destination was the service node. A default-deny egress rule with an allow for the service node is a reasonable additional control; it was **tested only as an `internal: true` Docker network** (E8), not as a host firewall. |

Also: if the compose snippet is used as printed, `ports: ["60000:60000", ...]` binds tcp/60000 on **all host interfaces**; restrict with the host firewall or bind to
a specific address (`"<ip>:60000:60000"`).

## 9. Two service nodes (E9): no automatic Store failover

`spike/relay/docker-compose.r2.yml` + `./scripts/up.sh r2` add R2. Clients list both service nodes as `--staticnode` (and AgentNet `peers`), R2 peers with R1.
Measured (`results/a1-daemon/e9-two-service-nodes.txt`): with R1 stopped, live relay delivery continued through R2 and R2's Store held the messages; a Store query **without an explicit `peerAddr` uses the single configured
`--storenode` (R1) and failed after a 5 s timeout**. AgentNet's `network.store_peer` can name one explicit Store peer (private IP + allowlisted id); it does not fail over either.
After R1 returned its Store had only the pre-outage message (`R1=1, R2=4`): service nodes do not backfill each other unless `--store-sync/--store-resume` (UNTESTED).
Plan for this: point `--storenode` at the more available node, accept that the second is relay redundancy rather than Store redundancy, and test your own failure
drill. Not tested: more than two service nodes, partitions between them.

## 10. Tailscale deployment: UNTESTED

**Everything in this section is UNTESTED with Tailscale itself. A WireGuard-overlay simulation of the same firewall and static-peer configuration (one host, kernel WireGuard) passed 2 of 2 runs; see `docs/network-simulations.md`.** No tailnet, no second host and no real Tailscale client was available; none of these steps was run. The text below is
what `agentnet relay print-config` prints, expanded with what the code accepts (`100.64.0.0/10` passes the private-address check: `docs/configuration.md`).

What Tailscale does and does not provide:

* It provides **encrypted machine-to-machine connectivity** (WireGuard) and **machine-level access policy** (ACLs/grants, tags).
* It does **not** provide application identity (who is the agent behind a message) or message encryption between agents; AgentNet's end-to-end encryption and contact
  verification are what do that, and they are the same with or without Tailscale.
* Its **coordination service sees metadata** (which devices exist, when online, connection information). The relay still sees AgentNet's
  topic/timing/size metadata (`docs/threat-model.md` section 4). Tailscale does not hide the bucket from the relay operator.
* A device that is compromised or has its Tailscale key stolen can reach whatever the ACL allows.

Reproducible steps (to be executed and verified by whoever has the hosts):

1. On the service host and each client host: install Tailscale, `tailscale up`. Note each tailnet IPv4: `tailscale ip -4` (100.x.y.z).
2. Tag the machines in the admin console, for example `tag:agentnet-relay` and `tag:agentnet-client`.
3. Service node: the flags of section 3 but `--listen-address=<service tailnet IP> --nat=extip:<service tailnet IP>`. Run it with host networking so the
   container sees the tailnet interface (`network_mode: host`). **`agentnet relay print-config` prints a separate "docker-compose: relay node, host network" snippet for this**
   with `--rest-address=127.0.0.1` and no `ports:`: with host networking, `0.0.0.0` would bind the unauthenticated REST API on **every host interface, including the tailnet**.
   The ordinary (bridge-network) snippet uses `--rest-address=0.0.0.0` *inside the container*, which is safe **only because** its REST port is published as
   `"127.0.0.1:<host port>:8645"`: the container's `0.0.0.0` is its own namespace, and Docker forwards only the host's loopback to it. Remove the `127.0.0.1:` prefix and the REST API is
   reachable from your network. (The host-network snippet was generated and read, not run: UNTESTED.)
4. Client node: the client flags with `--staticnode/--storenode/--filternode/--lightpushnode=/ip4/<service tailnet IP>/tcp/60000/p2p/<service peer id>` and
   `--nat=extip:<client tailnet IP>`.
5. `agentnet.toml`: `node_url = "http://127.0.0.1:<client REST>"`, `peers = ["/ip4/<service tailnet IP>/tcp/60000/p2p/<service peer id>"]`, `cluster_id = 66`.
6. ACL: allow only clients to the relay port, deny everything else, for example
   `{"acls": [{"action": "accept", "src": ["tag:agentnet-client"], "dst": ["tag:agentnet-relay:60000"]}]}`.
7. Verify (what a real run must show, none of it done here): from a machine **without** the client tag, `nc -vz <service tailnet IP> 60000` fails; from a client,
   `agentnet doctor` is all `[ok]`; `agentnet network status --verbose` lists exactly the service node's peer id; an exchange between agents on two different hosts completes
   with state `delivered`; `tcpdump` on a client shows only tailnet-interface traffic to the service node and no traffic to `1.1.1.1` or other public hosts.
8. Record the result in `docs/spike-report.md` section 7 (row "Tailscale").

Recovery note: after a silently dropped connection the node noticed after about 48 s and took between 42 s and 16 min to reconnect even with the path restored (simulations, `docs/network-simulations.md`).

## 11. Checklist before trusting a deployment

- [ ] Both nodes started with the flag set of section 3 and `--dns-addrs-name-server=127.0.0.1` (or an internal resolver).
- [ ] REST ports reachable only from the local host; service tcp/60000 reachable only from known clients.
- [ ] `agentnet doctor` on each client: `0 failing`, `peers == allowlist: ... all in the allowlist`.
- [ ] NTP running everywhere; `doctor` clock check ok.
- [ ] Store retention chosen deliberately and communicated (recommended 7 days, `time:604800;capacity:100000`; the spike test default is 1 hour). Remember the recovery window is the minimum of relay retention, message TTL and `storage.retention_hours`.
- [ ] One client node per agent; `--rest-relay-cache-capacity=1000`.
- [ ] You know that restarting the service node causes minutes of degraded live delivery and that recovery depends on Store.
- [ ] You accept that all of this was only tested on a single host.
