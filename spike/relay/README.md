# spike/relay: local Logos Delivery (nwaku) topology for transport path (3)

LOCALHOST / CONTAINER-NETWORK TEST ONLY. No public Waku network is contacted by design (one exception, see
`docs/spike/notes-daemon-rest.md`: the node's upstream default online-monitor DNS lookup to 1.1.1.1 every 5 s; these compose
files now default `DNS_NS` to `127.0.0.1`, which removes it. Set `DNS_NS=1.1.1.1` explicitly to reproduce the upstream behaviour).
Keys in `.env` are disposable test keys.

Image: `wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73` (tag v0.39.2,
binary `logosdeliverynode`, linux/amd64 only; runs under qemu on arm64 hosts).

## Topology (docker network `agentnet-relay_relaynet`, 172.28.66.0/24)

| node | role | ip | REST on host | notes |
|---|---|---|---|---|
| r1 | service: relay+store(sqlite)+filter+lightpush | 172.28.66.10 | 127.0.0.1:18640 | fixed nodekey, peer id `16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV` |
| na | client A: relay + filter/lightpush/store *clients* | .21 | 127.0.0.1:18641 | `--staticnode` R1 only |
| nb | client B | .22 | 127.0.0.1:18642 | `--staticnode` R1 only |
| r2 (variant) | second service node | .11 | 127.0.0.1:18643 | `docker-compose.r2.yml` |

Private cluster id 66, autosharding with 1 shard (`/waku/2/rs/66/0`), content topics like `/agentnet/1/<name>/proto`.
All discovery off: `--discv5-discovery=false --peer-exchange=false --relay-peer-exchange=false --rendezvous=false
--enable-kad-discovery=false --quic-support=false --mix=false`, no `--dns-discovery-url`, no `--entry-node`,
`--nat=extip:<own ip>` (no UPnP/PMP probing).

## Run

```
cd spike/relay
./scripts/up.sh            # r1 first, then na+nb (order matters, see notes)   | ./scripts/up.sh r2  for the 2-service variant
./scripts/demo-basic.sh    # E1 publish/receive/reply + store query
./scripts/demo-store.sh    # E2 store API: pagination, time range, hashes, ephemeral
./scripts/probes.py OUT.json ; ./scripts/probes2.py OUT.json   # E3 limits / malformed input / cache overflow
./scripts/demo-filter-lightpush.sh   # E4
./scripts/demo-failure.sh  # E5 R1 down (takes ~4 min: waits for client reconnect)
./scripts/demo-retention.sh # E6 retention (recreates r1)
./scripts/egress-capture.sh 150 # E7 tcpdump on the docker bridge from the colima VM netns (uses DNS_NS=1.1.1.1 unless you set it: shows the upstream default)
./scripts/internal-net.sh [DNS_NS]  # E8 `internal: true` network (sidecar client; docker does not publish ports there)
(cd ../transport-rest && cargo run --release -- all)   # Rust probe: basic, burst, offline
docker-compose down        # stop (named volumes keep R1's sqlite store; add -v to wipe)
```

Compose is the standalone `docker-compose` binary here (`docker compose` plugin is not installed on this host).
Env knobs: `R1_RETENTION` (default `time:3600;capacity:5000`: deliberately SHORT for tests; a real deployment recommends
`time:604800;capacity:100000`, see `docs/relay-setup.md`), `MAX_MSG_SIZE`, `CLIENT_CACHE` (REST relay cache capacity of
clients and `--rest-messaging-cache-capacity` of the service node; default **1000**; the node's own default is 50, and
`probes2.py`'s "70 messages into a 50-slot cache" experiment needs `CLIENT_CACHE=50`), `NET_INTERNAL`, `DNS_NS` (default `127.0.0.1`: no external DNS contact; `1.1.1.1` is the upstream default and leaks one lookup every 5 s).

Raw outputs live in `results/a1-daemon/`. Findings: `docs/spike/notes-daemon-rest.md`.
