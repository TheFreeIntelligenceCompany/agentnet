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
  Clients dial it; clients need no inbound port (this is the design; **cross-machine/NAT outbound-only operation is UNTESTED**).
* AgentNet talks only to the **client** node's REST API (`network.node_url`), never to the service node.

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
--store-message-retention-policy=time:3600;capacity:5000    # see section 6
--cluster-id=66 --num-shards-in-network=1 --shard=0
--discv5-discovery=false --peer-exchange=false --relay-peer-exchange=false --rendezvous=false
--enable-kad-discovery=false --quic-support=false --mix=false --rln-relay=false
--dns-addrs-name-server=127.0.0.1                           # section 5
--listen-address=0.0.0.0 --tcp-port=60000 --peer-persistence=false --metrics-server=false
--max-msg-size=150KiB --rest=true --rest-admin=true --rest-address=127.0.0.1 --rest-port=8645
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
* Receive path limits that shape sizing: the node's REST relay cache is 50 slots shared by all topics and `GET` is destructive
  (`--rest-relay-cache-capacity`); AgentNet polls every 250 ms by default (`delivery.poll_interval_ms`) and uses Store for recovery.

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
  `history_sync_interval_s` = 60 s later) **if the Store holds them**. History during that specific gap was not separately tested.
* **The spike compose file defaults `DNS_NS` to `1.1.1.1`** (`spike/relay/docker-compose.yml`, `${DNS_NS:-1.1.1.1}`), while
  `agentnet relay print-config` prints `127.0.0.1`. Start the spike topology with `DNS_NS=127.0.0.1 ./scripts/up.sh`.

## 6. Retention and what it means for offline delivery

* Store retention is set on the **service node**: `--store-message-retention-policy=time:<seconds>;capacity:<n>` (node default
  `time:172800`). **The verified flag set uses `time:3600;capacity:5000`: one hour, 5000 messages.** AgentNet's own
  `storage.retention_hours` (default 168) only bounds the client's database and how far back its history sync asks; it cannot extend the relay's retention.
  A recipient that is offline longer than the Store retention loses the message unless the sender is still retrying (sender retries
  republish with a fresh timestamp up to `max_attempts` = 20 over a bounded backoff, `docs/protocol.md` s8.2).
  Other retention values were **not tested** (`print-config` says the same).
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
| tcp/60000 (libp2p) | service node | Allow **only from the known client addresses**. Cluster/shard ids are **not access control**: anyone who can reach this port and knows cluster 66 / shard 0 can join the mesh, subscribe to every bucket topic and publish (`docs/threat-model.md` T13). |
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

**Everything in this section is UNTESTED.** No tailnet, no second host and no real Tailscale client was available; none of these steps was run. The text below is
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
   container sees the tailnet interface (`network_mode: host`). **Caution:** the compose snippet printed by `print-config` sets
   `--rest-address=0.0.0.0` (needed for port publishing). With host networking that would bind the unauthenticated REST API on **every host interface, including the tailnet**.
   Use `--rest-address=127.0.0.1` instead when using host networking. (This is a hazard found by reading the snippet; it was not exercised.)
4. Client node: the client flags with `--staticnode/--storenode/--filternode/--lightpushnode=/ip4/<service tailnet IP>/tcp/60000/p2p/<service peer id>` and
   `--nat=extip:<client tailnet IP>`.
5. `agentnet.toml`: `node_url = "http://127.0.0.1:<client REST>"`, `peers = ["/ip4/<service tailnet IP>/tcp/60000/p2p/<service peer id>"]`, `cluster_id = 66`.
6. ACL: allow only clients to the relay port, deny everything else, for example
   `{"acls": [{"action": "accept", "src": ["tag:agentnet-client"], "dst": ["tag:agentnet-relay:60000"]}]}`.
7. Verify (what a real run must show, none of it done here): from a machine **without** the client tag, `nc -vz <service tailnet IP> 60000` fails; from a client,
   `agentnet doctor` is all `[ok]`; `agentnet network status --verbose` lists exactly the service node's peer id; an exchange between agents on two different hosts completes
   with state `delivered`; `tcpdump` on a client shows only tailnet-interface traffic to the service node and no traffic to `1.1.1.1` or other public hosts.
8. Record the result in `docs/spike-report.md` section 7 (row "Tailscale").

## 11. Checklist before trusting a deployment

- [ ] Both nodes started with the flag set of section 3 and `--dns-addrs-name-server=127.0.0.1` (or an internal resolver).
- [ ] REST ports reachable only from the local host; service tcp/60000 reachable only from known clients.
- [ ] `agentnet doctor` on each client: `0 failing`, `peers == allowlist: ... all in the allowlist`.
- [ ] NTP running everywhere; `doctor` clock check ok.
- [ ] Store retention chosen deliberately and communicated (the verified default is 1 hour).
- [ ] You know that restarting the service node causes minutes of degraded live delivery and that recovery depends on Store.
- [ ] You accept that all of this was only tested on a single host.
