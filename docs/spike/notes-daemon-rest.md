# Spike A1, transport path (3): Rust adapter -> separately running Logos Delivery node via REST

Author: contributor agent. Date of work: 2026-11-25. Status: discovery spike notes, evidence-linked.
All experiments are LOCALHOST / CONTAINER-NETWORK tests on one macOS arm64 host (colima VM, amd64 image under qemu). No
cross-machine, NAT, Tailscale or public-network run was done. Raw evidence: `results/a1-daemon/` (paths below relative to it).
Reproducible assets: `spike/relay/` (compose, scripts, README) and `spike/transport-rest/` (Rust probe).

## 1. Upstream inventory

| item | finding | evidence |
|---|---|---|
| canonical repo | `github.com/logos-messaging/logos-delivery` (Nim, "Logos Messaging protocols implemented in Nim"). `waku-org/nwaku` resolves to the same repo (`gh api repos/waku-org/nwaku` returns `full_name = logos-messaging/logos-delivery`). Not archived. | `gh api` output, this session |
| commit inspected (master) | `88bd0e5c2578db179b74fb078b1a4ec5fdadd066` (2026-11-24, "fix(messaging): don't retry a failed mix send every second (#4844)"), shallow clone at `upstream/logos-delivery`. Last push seen 2026-11-25T18:11Z: very active. | `git log -1` |
| commit the pinned image was built from | tag `v0.39.2` = `fd07b72c370a6b39c69870c087cc0d928d485327` (2026-10-13), worktree `upstream/logos-delivery-v0.39.2`. Image label `commit` = same sha. | `inspect_v0.39.2.txt` |
| latest stable release | `v0.40.0` (2026-11-13). Pre-releases `v0.41.0-rc.0/1/2` (rc.2 2026-11-24) and a rolling `nightly`. | `gh api .../releases` |
| licence | Dual `LICENSE-MIT` + `LICENSE-APACHE` (nimble: "MIT or Apache License 2.0"; GitHub reports Apache-2.0). Vendored Nim dependency licences NOT audited (UNTESTED). | repo root, `logos_delivery.nimble` |
| Docker images | Docker Hub `wakuorg/nwaku`: tags up to `v0.39.2` (2026-10-13) plus `latest` (2026-11-09; it is a NIGHTLY build `nightly-1-g39eda310`, not a release). **No `v0.40.0` or `v0.41.0-rc.*` tag exists on Docker Hub** (`docker manifest inspect wakuorg/nwaku:v0.40.0` -> "no such manifest"). `wakuorg/logosdelivery` and `wakuorg/nwaku-pr` not found on Hub. `harbor.status.im/wakuorg/{nwaku,logosdelivery}` and `ghcr.io/logos-messaging/logos-delivery`: anonymous access denied (UNTESTED beyond that). **Hub images are linux/amd64 only** (Hub API `images[].architecture` = amd64 for every tag). No arm64 image found. | `manifest_*.json`, `pull_*.txt`, `images.txt` |
| image pinned | `wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73` (tag v0.39.2, created 2026-10-13T19:01Z, 94.7 MB, Alpine 3.18.12, musl, entrypoint `/usr/bin/logosdeliverynode`, runs as root, deps libstdc++/libgcc only) | `pull_v0.39.2.txt`, `rootfs-info.txt` |
| native arm64 | Build from source (Nim, submodules) NOT attempted: UNTESTED. Anything on arm64 hosts here runs amd64 under qemu (works; adds latency, see s4). | |

Naming: the binary is `logosdeliverynode` (was `wakunode2`; `--version` prints `version / git commit hash: "v0.39.2"`). `docker run ... wakunode2` does not exist in this image.

### 1.1 REST API inventory (from v0.39.2 source; master differs only in file layout, see note)

Server: `logos_delivery/waku/rest_api/endpoint/server.nim`, `builder.nim`. **No authentication of any kind**; CORS only via `--rest-allow-origin`. Default bind 127.0.0.1:8645; max request body default 16 MiB. Admin routes need `--rest-admin=true`. Every `GET` on a message cache is **destructive** (clears what it returns).

| area | route | request / response | source file (under `logos_delivery/waku/rest_api/endpoint/`) |
|---|---|---|---|
| health | `GET /health` | `{nodeHealth, connectionStatus, protocolsHealth:[{Relay:READY},...]}` | `health/handlers.nim` |
| info | `GET /info` (alias `/debug/v1/info`) -> `{listenAddresses:[".../p2p/<peerId>"], enrUri}`; `GET /version` (alias `/debug/v1/version`) -> text | `debug/handlers.nim` |
| relay, static pubsub | `POST/DELETE /relay/v1/subscriptions` body `["/waku/2/rs/66/0"]`; `GET /relay/v1/messages/{pubsubTopic}` (url-encoded) -> `[{payload(b64), contentTopic, version, timestamp(ns), meta?, ephemeral, proof}]`; `POST /relay/v1/messages/{pubsubTopic}` body = same message object, requires prior subscription of that pubsub topic on this node | `relay/handlers.nim`, `relay/types.nim` |
| relay, autosharding | `POST/DELETE /relay/v1/auto/subscriptions` body `["<contentTopic>"]`; `GET /relay/v1/auto/messages/{contentTopic}`; `POST /relay/v1/auto/messages` (message object, `contentTopic` required; shard derived by hashing, needs `--num-shards-in-network>0`) | same |
| filter v2 (client side REST) | `POST/PUT/DELETE /filter/v2/subscriptions` body `{requestId, contentFilters:[ct], pubsubTopic?}` -> `{requestId, statusDesc}`; `DELETE /filter/v2/subscriptions/all`; `GET /filter/v2/subscriptions/{requestId}` (ping); `GET /filter/v2/messages/{contentTopic}` (drain) | `filter/handlers.nim`, `filter/types.nim` |
| lightpush v3 | `POST /lightpush/v3/message` body `{pubsubTopic?, message:{...}}` -> `{relayPeerCount}` (503 `Push request timed out` on failure) | `lightpush/handlers.nim` |
| lightpush legacy | `POST /lightpush/v1/message` same body -> `OK` | `legacy_lightpush/handlers.nim` |
| store v3 | `GET /store/v3/messages?peerAddr=&includeData=&pubsubTopic=&contentTopics=a,b&startTime=&endTime=&hashes=&cursor=&ascending=&pageSize=` -> `{requestId,statusCode,statusDesc,messages:[{messageHash,message?,pubsubTopic?}],paginationCursor?}`. pageSize default 20, hard max 100. Time range max 24 h (`time range exceeds 24h`, HTTP 400). Message-hash lookup cannot combine with other filters. No peerAddr: self store if the node is a store node, else the `--storenode` peer. Query timeout 5 s. | `store/handlers.nim`; limits in `waku_store/common.nim` |
| admin | `GET /admin/v1/peers` (+ `/peers/service`, `/peers/connected`, `/peers/connected/on/{shardId}`, `/peers/relay`, `/peers/relay/on/{shardId}`, `/peers/mesh`, `/peers/mesh/on/{shardId}`, `/peers/stats`, `/peer/{peerId}`); `POST /admin/v1/peers` body `["<multiaddr>"]` (dial); `GET /admin/v1/filter/subscriptions`; `POST /admin/v1/log-level/{level}` (503 unless built with runtime filtering) | `admin/handlers.nim`, `admin/types.nim` |
| messaging layer (`--entry-layer=messaging\|channels`) | `GET/POST/DELETE /messaging/v1/subscriptions` (content topics); `POST /messaging/v1/messages` body `{payload, contentTopic, ephemeral?, meta?}` -> `{requestId}` (429 + Retry-After when send queue full); `GET /messaging/v1/events/send` (+ `/{requestId}`) -> `[{requestId, events:[{kind: sent|queued|propagated|error, messageHash, error, timestamp}]}]`; `GET /messaging/v1/events/received` -> `[{seq, messageHash, message, source: live|history}]`. Evict-after-poll, cap `--rest-messaging-cache-capacity` (default 50). | `messaging/rest_api/handlers.nim`, `types.nim`, `event_cache.nim` |

Note on master (`88bd0e5`): REST code moved to top-level `rest/` (`rest/kernel_api/*`, `rest/messaging_api/*`). Diff of the route-constant lists between v0.39.2 and master: only change is `/messaging/v1/events/send/{requestId}` -> `/messaging/v1/events/send/{messageHash}`. The messaging API is therefore still moving.

Message model (relay/filter REST): `payload` base64, `contentTopic`, `version` (default 0), `timestamp` ns (filled by the publishing node's clock if 0/absent), `meta` base64, `ephemeral`, `proof` (RLN). **Relay/filter REST responses carry no message hash and no pubsub topic.** Waku hash = `sha256(pubsubTopic || payload || contentTopic || meta || timestamp_be64)` (`waku_core/message/digest.nim`); the Rust probe recomputed it and matched R1's store hash for 200/200 messages (`rust-probe-basic-45bea17.json: hash_crosscheck`). Store responses and the messaging API return `messageHash` (0x-hex).

Receive model: REST receive is **polling a per-node in-memory cache** (`waku/rest_api/message_cache.nim`): capacity `--rest-relay-cache-capacity` (default 50) shared across all subscribed topics of that node; `GET` returns and deletes; structurally identical messages are deduplicated on insert; eviction drops the oldest by sender timestamp **silently** and the swap-delete implementation returns messages **out of chronological order after any eviction**; subscriptions and cache are lost on node restart (404 for a topic until re-subscribed).

### 1.2 Flags relevant to private isolation (from `--help`, `help_v0.39.2.txt`, and source)

| purpose | flag | default / note |
|---|---|---|
| static peers | `--staticnode=<multiaddr>` (repeatable) | dialled directly; used. `--entry-node` also feeds static/discv5/DNS lists: avoid. |
| service peers for client protocols | `--storenode`, `--filternode`, `--lightpushnode` (single value each) | no automatic failover to a second store node (E9) |
| discovery off | `--discv5-discovery=false` (default TRUE), `--peer-exchange=false` (default true), `--relay-peer-exchange=false` (default false), `--rendezvous=false` (default true), `--enable-kad-discovery=false` (default off), `--dns-discovery-url` (no default; unset), `--mix=false` | all set false in the topology |
| cluster / shards | `--cluster-id` (default 0), `--num-shards-in-network=N` (>0 enables autosharding; 0 = static), `--shard=i` (repeatable) | used `66 / 1 / 0`. **`--cluster-id=1` silently applies the TWN preset (RLN on, public entry nodes `*.status.im`); `--cluster-id=2` applies logos.dev** (`tools/confutils/cli_args.nim:1073-1087`). Presets: `twn`(1), `logos.test`(2), `logos.dev`(3), `status.prod`(16). Never use ids 1-3, 16. |
| protocols | `--relay` (default true), `--filter` (true), `--lightpush` (true), `--store` (false), `--relay-client` | note service protocols default ON: clients set `--filter=false --lightpush=false` explicitly |
| store | `--store`, `--store-message-db-url` (default `sqlite://store.sqlite3`; `sqlite:///data/x.sqlite3` worked), `--store-message-retention-policy` (`time:<s>;capacity:<n>;size:<xMB>`; default `time:172800`), `--store-message-db-vacuum`, `--store-resume`, `--store-sync`(+interval/range) | `--store-resume`/`--store-sync` UNTESTED |
| RLN | `--rln-relay` (default false) + `--rln-relay-*` | **not required on a private cluster**: cluster 66 with `--rln-relay=false` relays, stores, filters, lightpushes (all experiments). Without RLN there is no rate limiting except `--rate-limit`. |
| size | `--max-msg-size` (default 150KiB = 153600 B) | see E3 |
| identity | `--nodekey=<64 hex>` | gives static peer id: R1 = `16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV` |
| network binding | `--listen-address` (0.0.0.0), `--tcp-port` (60000), `--nat` (default `any` = tries UPnP/PMP; set `extip:<ip>` or `none`), `--quic-support` (default TRUE, UDP), `--websocket-support` (false), `--ext-multiaddr`, `--ports-shift` | used `--nat=extip:<own ip> --quic-support=false` |
| REST | `--rest`, `--rest-address` (127.0.0.1), `--rest-port` (8645), `--rest-admin`, `--rest-allow-origin`, `--rest-relay-cache-capacity` (50), `--rest-messaging-cache-capacity` (50) | |
| misc | `--peer-persistence` (false), `--max-connections` (150), `--rate-limit proto:vol/period`, `--dns-addrs-name-server` (default `1.1.1.1,1.0.0.1`), `--entry-layer` (kernel/messaging/channels), `--mode Edge/Core`, `--reliability` | |

**Defaults that cause public contact** (source/help only; NOT run against the public network): `--discv5-discovery` default true; `--peer-exchange` true; `--rendezvous` true; `--nat any`; `--quic-support` true; `--cluster-id 1|2` -> preset with public bootstrap hosts; any `--preset`. **One public contact remains even with every discovery option off: see E7.**

## 2. Experiments

Topology: `spike/relay/docker-compose.yml`. R1 service node (relay+store sqlite+filter+lightpush), NA and NB (relay + filter/lightpush/store clients, `--staticnode` R1 only), cluster 66, 1 autoshard, content topic `/agentnet/1/<name>/proto`, pubsub `/waku/2/rs/66/0`. R1 `172.28.66.10`, NA `.21`, NB `.22`, REST on host loopback 18640/18641/18642. Working flag set (identical for the three, role flags aside):

```
--cluster-id=66 --num-shards-in-network=1 --shard=0 --discv5-discovery=false --peer-exchange=false --relay-peer-exchange=false
--rendezvous=false --enable-kad-discovery=false --quic-support=false --mix=false --rln-relay=false --nat=extip:<own ip>
--listen-address=0.0.0.0 --tcp-port=60000 --dns-addrs-name-server=<see E7> --peer-persistence=false --metrics-server=false
--rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-admin=true --nodekey=<hex>
R1: --relay=true --store=true --store-message-db-url=sqlite:///data/r1-store.sqlite3 --store-message-retention-policy=time:3600;capacity:5000 --filter=true --lightpush=true
NA/NB: --relay=true --store=false --filter=false --lightpush=false --staticnode=<R1 maddr> --storenode=<R1 maddr> --filternode=<R1 maddr> --lightpushnode=<R1 maddr>
```
R1 multiaddr: `/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV`. Toolchain: `toolchain.txt`.

### E1 basic send/receive/reply (`scripts/demo-basic.sh` -> `e1-basic.txt`)
NA publishes via `POST /relay/v1/auto/messages`, NB polls `GET /relay/v1/auto/messages/{ct}` and receives it; second poll `[]`; NB replies, NA receives. **Result: works. Surprise: the publisher's own poll also returns its own published message** (NA's cache held both A->B and the reply), so an adapter must filter self-messages by an in-payload sender id. Startup to REST healthy ~1.3 s (log: `Node setup complete` 0.9 s after process start).

### E2 store API (`scripts/demo-store.sh` -> `e2-store-api.txt`)
6 messages on a fresh topic (5 persistent, 1 `ephemeral:true`). Results: R1 store held exactly the 5 persistent ones (**ephemeral relayed but not stored**; NB's relay cache did receive the ephemeral one). Default order ascending; `pageSize=2` returns 2 messages + `paginationCursor` = hash of the last returned message (cursor absent on the last page); `includeData=false` returns hashes only; `startTime/endTime` in nanoseconds; `startTime=1,endTime=now` -> 400 `time range exceeds 24h`; no-filter query accepted; `pageSize=1000` capped (5 returned of 5, cap 100 in source). NB query with and without `peerAddr` works through NB's own store client (`requestId` populated; self-query has empty requestId). Stored message objects omit `meta`/`proof` fields.

### E3 limits and malformed input (`scripts/probes.py`, `probes2.py` -> `e3-probes.json`, `e3b-probes.json`)
Max message size 153600 B (150 KiB, configured default).
- Payload at limit: largest accepted payload was 153516 B with topic `/agentnet/1/spike-a1-limits/proto` (the limit covers the whole encoded WakuMessage: payload + topic + timestamp + framing); the receiver got it (response body 204827 chars = base64 of ~153.5 KB).
- **Just over the limit gives a misleading error**: payloads 153517..~153530 B -> HTTP 400 `Failed to publish: publish failed in relay: NoPeersToPublish` (gossipsub rejects before the Waku size validator); payloads >= ~153560 B and the 2 MB test -> HTTP 400 `Failed to publish: Message size exceeded maximum of 153600 bytes`. Same `NoPeersToPublish` text is returned when a node truly has no peers (E5) and when an identical message (same timestamp/hash) is published twice (`identical_ts_publish_twice`): the second publish returns 400 even though the first was delivered. Treat `NoPeersToPublish` as ambiguous.
- Malformed base64 -> HTTP 400 with EMPTY body. Missing/empty payload, missing contentTopic, empty contentTopic string, invalid JSON, unknown extra JSON field -> 400 `Invalid content body, could not decode: Unable to deserialize data: ` (no field name).
- Content topic: `foo` -> 400 `...content-topic 'foo' must start with slash`; `/a/1/b` -> 400 `Invalid content topic structure. Expected either /<application>/<version>/<topic-name>/<encoding> or /<gen>/<application>/<version>/<topic-name>/<encoding>`; generation `/1/...` -> 400 `Generation > 0 are not supported yet`; unknown encoding, unicode name, 1000-char name, generation-0 prefix `/0/...`: accepted (200). Subscribe with bad topic -> **500** (not 400) `Subscribe failed:...`. Publishing to a content topic the node has not subscribed on REST succeeds (autoshard publish needs no subscription).
- `meta` > 64 bytes: publish returns **200 OK but the message is silently dropped** (never reaches NB); 0/32/64 bytes delivered. `version:1` accepted and delivered.
- Timestamps: relay accepts and delivers messages with timestamp 60 s in the past, 60 s in the future and negative; **R1's store did not archive them** (archive validator allows +-20 s drift, `waku_archive/archive.nim:36`; rejection is silent). Clock skew > 20 s therefore breaks Store recovery without any publish error.
- Static pubsub: `subscribe` with `/waku/2/rs/1/0` (other cluster) and `/waku/2/rs/66/5` (non-existent shard) are accepted with 200 (format-only validation); `/waku/2/default-waku/proto` -> 400. Publish to a pubsub topic not subscribed on that node -> 400 `Node not subscribed to topic`. A static-pubsub subscription caches **all** content topics on that shard in the same 50-slot cache (NB's cache collected every earlier message).
- Cache overflow (`probes2.py`, Rust `burst`): 70 messages into capacity 50 without polling -> 50 retained, oldest 20 lost, returned order scrambled (`cap-049, cap-050, ... cap-047, cap-048, cap-069`). Rust burst: 100 messages published in ~1 s with poll every 1.5 s -> **received 50, lost seq 0..49** (`rust-probe-burst-45cd130.json`); same burst polled every 100 ms -> 0 lost.

### E4 filter and lightpush (`scripts/demo-filter-lightpush.sh` -> `e4-filter-lightpush.txt`)
NB `POST /filter/v2/subscriptions` -> `{"requestId":"req-1","statusDesc":"OK"}`; R1 `GET /admin/v1/filter/subscriptions` lists NB's peer id and criteria; NA relay publish delivered to NB through filter push and `GET /filter/v2/messages/{ct}`; second GET `[]`. Lightpush v3 from NB (with and without `pubsubTopic`) -> `{"relayPeerCount":2}`; legacy v1 -> `OK`; all three reached NB's filter cache and R1's store (the `ephemeral:true` one not stored). Filter subscriptions are soft state (`--filter-subscription-timeout` default 300 s unless pinged) and are not persisted by the client REST layer.

### E5 service node down (`scripts/demo-failure.sh` -> `e5-r1-down.txt`)
R1 stopped: peer state `CanConnect`; NB store query -> HTTP 500 `No history response received (timeout)` after 5.0 s; NA relay publish -> 400 `NoPeersToPublish`; NB lightpush -> 503 `{"statusDesc":"Push request timed out"}`; filter ping -> 500 `failed to dialPeer: Future operation cancelled!`; `/health` `connectionStatus: Disconnected`, `Relay NOT_READY No connected peers`. **After R1 restarted, NB took 113 s to reconnect** (peer-manager backoff; poll #54 at 2 s). Messages then flowed again. Store data persisted across restart (sqlite volume).

### E6 retention (`scripts/demo-retention.sh` -> `e6-retention.txt`)
Policy runs once at start and then every 30 min (hardcoded, `waku_archive/archive.nim:29`), so pruning is observed only after a restart. `capacity:8`: 12 stored -> after restart 9 remain (policy keeps capacity + half the 30 % overflow window, `retention_policy_capacity.nim`). `time:60`: 70 s later without restart nothing pruned (21 stored); after restart 0 remain, so a store query after expiry returns `statusCode 200` with empty `messages` (no "expired" indicator).

### E7 what does an all-discovery-off node talk to? (`scripts/egress-capture.sh`; `e7a-*`, `e7b-*`, `egress-*.pcap/.egress.txt/.flows.txt`)
tcpdump in a sidecar on the docker bridge (VM netns), 150 s, whole stack restarted inside the capture, traffic generated.
- **Default `--dns-addrs-name-server` (1.1.1.1): every node (R1, NA, NB) sent DNS A+AAAA queries for `one.one.one.one` to 1.1.1.1:53 every 5 s for the whole run** (`egress-default-dns.egress.txt`, 297 lines). Cause: `waku/node/health_monitor/online_monitor.nim` resolves that name every 5 s as an "am I online" check. It was the ONLY non-internal destination; no TCP/UDP to any other external address and nothing on 9000/udp or 30303. (An unrelated IPv6 multicast listener report comes from the VM.)
- With `--dns-addrs-name-server=127.0.0.1` on a normal bridge network: 1175 packets in 100 s, **0 with any endpoint outside 172.28.66.0/24** (`e7b-egress-dns-localhost-run.txt`), and relay/store worked (`e7b-functional-check-dns-localhost.txt`).
- Internal peers observed: libp2p TCP 60000 between R1 and NA/NB only; no NA<->NB connection (they meet through R1's gossipsub mesh). `admin/v1/peers` on each client lists only R1 (`origin: UnknownOrigin`).
- Not covered by this capture: UPnP/PMP (avoided with `--nat=extip`), QUIC (disabled), websockets (off).

### E8 `internal: true` docker network, no egress (`scripts/internal-net.sh`; `e8a-*`, `e8b-*`)
Docker does not publish ports of internal networks, so the client is a sidecar on the network; egress sanity `nc 1.1.1.1:53/443` -> `Network unreachable`.
- **Default DNS server (1.1.1.1): FAILED.** NA connected to R1 but NB stayed `CannotConnect` / `Disconnected` for > 5 min; `NoPeersToPublish` on B->A (`e8a-internal-net-default-dns.txt`). Mechanism confirmed in source: the online monitor marks the node offline when no peers are connected and the DNS check fails, and the peer manager skips connection attempts while offline (`peer_manager.nim:665`, `:1037`). A node that misses its initial dial on a no-egress network never retries.
- **With a stub DNS answering `one.one.one.one` inside the network (`scripts/dns-stub.py` at 172.28.66.53, `--dns-addrs-name-server=172.28.66.53`): works.** NA/NB connected after 2 s even with all nodes started simultaneously; A->B, reply, store query all OK (`e8b-internal-net-stub-dns.txt`). Note that `--dns-addrs-name-server=127.0.0.1` on an internal network was not tested (the node would be offline until some peer connects; start R1 first, `scripts/up.sh`).

### E9 second service node (`docker-compose.r2.yml`, `scripts/demo-r2.sh` -> `e9-two-service-nodes.txt`)
NA/NB `--staticnode` R1 and R2 (R2 also dials R1). R1 stopped: NA publishes 3 messages (200), NB receives them via R2 on relay; R2 store holds them (count 4); NB store query with explicit `peerAddr=<R2>` works; **without `peerAddr` it uses the single `--storenode` (R1) and fails with 500 timeout** (no store failover). After R1 returns its store has only the pre-outage message (`R1=1, R2=4`; `--store-sync/--store-resume` not tried). R2's `admin/v1/peers` showed an extra `CannotConnect` entry that was not investigated.

### E10 messaging layer (`docker-compose.messaging.yml`, `scripts/demo-messaging.sh` -> `e10-messaging-api.txt`) (extra, experimental)
`--entry-layer=messaging` with `--mode=Core` (ma) and `--mode=Edge` (mb; mounts only filter/lightpush/store clients, no relay) against the same R1. `POST /messaging/v1/messages` -> `{requestId}`; `events/send` -> `kind: propagated` + `messageHash`; `events/received` -> `{seq, messageHash, message, source: "live"}`. Edge node sent via lightpush and received via filter. After stopping mb, sending 3 messages and restarting mb: subscriptions were empty (in-memory), and after re-subscribe `events/received` delivered **5 messages with `source:"history"`, including 2 that mb had already seen live** (store backfill on subscribe; consumer must dedupe by `messageHash`). Error shapes: bad base64 -> 400 `Invalid message: Incorrect base64 string`; bad topic -> 400 with reason. Backfill window length and `--reliability` semantics UNTESTED.

### E11 Rust probe (`spike/transport-rest`, release build) -> `rust-probe-*.json`, `rust-basic-*.csv`
Standalone crate (own `[workspace]`, tokio 1.54.1, reqwest 0.12.28 rustls-tls, serde 1.0.229, serde_json 1.0.154, sha2 0.10.9, base64 0.22.1; `Cargo.lock` present). Receive = per-node poller of `GET /relay/v1/auto/messages/{ct}`; payload = JSON with run id, sender, seq, sent_ns, 200-byte pad and sha256 self-check.
| run | poll interval | direction | delivered/sent | dups | ordering violations | integrity failures | latency p50 / p95 / p99 (ms) |
|---|---|---|---|---|---|---|---|
| `rust-probe-basic-45bea17.json` | 25 ms | A->B | 100/100 | 0 | 0 | 0 | 52 / 169 / 198 |
| | | B->A | 100/100 | 0 | 0 | 0 | 88 / 203 / 347 |
| `rust-probe-basic-462f247.json` | 250 ms | A->B | 100/100 | 0 | 0 | 0 | 135 / 252 / 262 |
| | | B->A | 100/100 | 0 | 0 | 0 | 148 / 262 / 370 |
Publish pacing 25 ms; latency = poller receive time minus sender timestamp in payload, same host clock, includes qemu emulation and the poll interval (so it is an upper bound for the transport itself). Publisher's own echo seen by sender 100/100 in both directions. Publish API call p50 33-53 ms, p95 75-133 ms. 200/200 relay-observed hashes recomputed locally equal the hashes in R1's store.
Offline/Store recovery (`rust-probe-offline-45d196c.json`): NB container stopped (1.2 s), NA published 20 numbered messages (0 failures), NB restarted: REST healthy after 1.3 s, connected to R1 after 1.5 s, relay cache for the topic gone (404 until re-subscribe). Recovery through NB's own store client (no `peerAddr`), page size 7: 3 pages, 21 entries (20 offline + 1 earlier live message inside the 1 s lookback window), 20/20 unique, ascending, 0 integrity failures, 21/21 hashes match local recompute, 48 ms total; the same query repeated returns the same 21 (idempotent, so Store replay needs client-side dedupe by hash against messages already seen live).

### E12 reconnect after relay restart needs an explicit dial (`results/b-transport/relay-disruptive-tests.log`)
With the required `--dns-addrs-name-server=127.0.0.1` (no public egress, E7/E8) a client node that loses its only peer (R1 stopped/restarted) is marked offline by its online monitor and **never redials its `--staticnode`**: after `docker start an-r1`, `GET /admin/v1/peers` on the clients stayed `CannotConnect` for > 240 s (first run of `r1_down_gives_unavailable_and_history_unavailable`: "node did not become ready again"; `an-nb` log: `Node is offline` and `totalConnections=0/150` repeating). `POST /admin/v1/peers` with body `["/ip4/172.28.66.10/tcp/60000/p2p/<R1 id>"]` on the client's REST returns `OK` and the peer is `Connected` immediately (an-nb stuck for minutes, `LogosRestTransport` status() redial -> Connected in 0.5 s). The adapter therefore takes `static_peers` and POSTs exactly those (never anything else) when no allowlisted peer is connected, rate limited by `redial_interval` (default 10 s). Measured with the adapter redial (LOCALHOST, amd64 under qemu): R1 stop -> start -> client ready again after **11.4 s** (4 redial attempts, the early ones failing while R1 was down; first attempt after R1 was back succeeded); client-node restart (`an-na`) -> ready in 3.4 s with 0 redials (the restarted node dials its static peer itself). Caveat: reconnecting is not the same as the relay mesh being usable. After this R1 restart (R1 started 21:27:48Z, clients `Connected` within seconds to ~1 min) all three nodes reported an empty or flapping (0/1 peers) gossipsub mesh (`/admin/v1/peers/mesh`) and live A<->B delivery failed (both directions, `GET /relay/v1/auto/messages` on the receiver stayed `[]`) until about 21:37Z, i.e. roughly 9 minutes; the cause (gossipsub backoff/score after the restart) was not investigated. Callers should expect live gaps after a relay restart and rely on Store catch-up (History during the gap was not separately tested).

### Resource use (`docker-stats-idle.txt`, `image-size.txt`)
Idle snapshot (qemu amd64 on arm64 colima, 6 CPUs / 9.7 GiB VM): R1 44 MiB RSS-ish / 1.7 % CPU, NA 53 MiB / 0.8 %, NB 53 MiB / 0.2 %, 2 PIDs each. Image 94.7 MB. Startup to REST healthy ~1.3 s. Graceful `docker stop` ~1.2 s. No load test beyond 100-message bursts.

## 3. Surprises, bugs, limitations

1. Public contact with discovery off: DNS to `1.1.1.1` for `one.one.one.one` every 5 s from every node (E7). Mitigation `--dns-addrs-name-server=<non-routable or internal stub>`.
2. That same online monitor makes a no-egress deployment fragile: with unreachable DNS a node that is not yet connected never dials static peers (E8). Static-peer reconnect after a service-node restart takes ~2 min (E5). Start the service node first (`scripts/up.sh`).
3. `--cluster-id=1`/`2` silently switch on the public TWN / logos.dev presets (public bootstrap, RLN).
4. REST has no authentication/TLS; bind only to loopback or a private interface; `--rest-admin` exposes peer dial and filter listing.
5. REST receive = destructive-read in-memory cache of 50 messages (configurable), shared by all topics; overflow drops oldest silently, returns out-of-order, loses everything on restart; a static-pubsub subscription caches every content topic on the shard; publishers see their own messages. A durable adapter must poll fast (or raise capacity), persist what it reads, and treat Store as the recovery path.
6. Relay/filter REST give no message hash; compute it (formula above) or use Store / `/messaging/v1`.
7. Ambiguous/misleading errors: `NoPeersToPublish` (no peers, just-over-size, or duplicate publish); 200 OK with silent drop for `meta` > 64 B; oversize error text depends on how far over; empty 400 body for bad base64; 500 for bad content topic on subscribe.
8. Archive silently refuses messages whose sender timestamp is >20 s from the store node's clock while relay still delivers them; retention is enforced only at start and every 30 min; expired history is indistinguishable from "never existed".
9. Single `--storenode`; no automatic store failover; a restarted/late service node does not backfill unless `--store-sync/--store-resume` (UNTESTED).
10. Subscriptions (relay, filter, messaging) live in memory; after a client daemon restart they must be re-registered.
11. Ephemeral messages are relayed but never stored.
12. Only linux/amd64 images are published on Docker Hub; Docker Hub lags releases (no v0.40.0); `latest` is a nightly. Tag renamed binary (`wakunode2` -> `logosdeliverynode`). The `/messaging/v1` API changed between v0.39.2 and master (events by `requestId` -> by `messageHash`).
13. Compose plugin absent on this host (`docker compose` fails); standalone `docker-compose` v5.6.0 used.
14. Same nodekey used by two containers made the second one stay `CannotConnect` (my mistake during E10, then fixed with separate keys): duplicate peer IDs are not detected loudly.

## 4. UNTESTED

- Real cross-machine/NAT run, outbound-only clients on separate hosts; Tailscale/WireGuard (steps: bind R1 `--nat=extip:<tailnet ip>`, restrict with tailnet ACLs; not run).
- Native arm64 build of logos-delivery; Linux x86_64 native; clean-checkout rebuild; vendored dependency licences.
- Packet capture on a host with a non-colima network stack; UPnP/PMP behaviour of the default `--nat any`; QUIC/websocket paths.
- Behaviour of the documented defaults against the public network (deliberately not run).
- `--store-resume`, `--store-sync`, postgres store backend, `--rate-limit`, RLN-enabled private cluster, `--protected-shard`, `--peer-persistence`, `--max-connections` pressure.
- Concurrent writers / identity persistence (this layer has no application identity; the nodekey only fixes the libp2p peer id), tamper/replay/forgery and wrong-recipient decryption (Waku v0 messages here are plaintext; any encryption is the adapter's job), clock-skew beyond the +-20 s archive window on the recipient side, unknown payload versions beyond `version:1` accepted.
- 1/10/100 logical-client load, sustained rate, idle bandwidth numbers, sustained reception over hours, publisher/relay failure retry matrix beyond E5/E9.
- `/messaging/v1`: `--reliability`, history window, queue-full 429, channels layer (`--entry-layer=channels`).
- Authenticated registry pulls (`harbor.status.im`, `ghcr.io`) and image signature/provenance.

## 5. Assessment for the adapter design (evidence only)
Path (3) is workable with the pinned amd64 image: private cluster, static peers, relay + store + filter + lightpush all functioned with no RLN and one controlled public-contact leak that is removable by flag. The REST receive model is the weak point (volatile 50-slot destructive cache, no hashes, self-echo); the `/messaging/v1` layer addresses hashes/history/send status but is unstable across versions and was only smoke-tested. Any confidentiality, sender authentication and replay protection are absent at this layer and must come from the application protocol.
