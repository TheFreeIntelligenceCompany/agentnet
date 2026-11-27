#!/usr/bin/env bash
# Run ON the droplet. Relay R (libp2p tcp/60000 published on the droplet's PUBLIC IPv4) + client node B. REST loopback only.
set -euo pipefail
PUB_IP_R="$1"
IMG='wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73'
R1_KEY=${R1_KEY:?}
NB_KEY=${NB_KEY:?}
COMMON=(--max-msg-size=150KiB --cluster-id=66 --num-shards-in-network=1 --shard=0 --discv5-discovery=false --peer-exchange=false
 --relay-peer-exchange=false --rendezvous=false --enable-kad-discovery=false --quic-support=false --mix=false --rln-relay=false
 --listen-address=0.0.0.0 --dns-addrs-name-server=127.0.0.1 --tcp-port=60000 --metrics-server=false --peer-persistence=false
 --local-storage-path=/data --log-level=INFO --rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-admin=true
 --rest-relay-cache-capacity=1000 --rest-messaging-cache-capacity=1000)
docker rm -f an-r1 an-nb >/dev/null 2>&1 || true
docker network rm ants >/dev/null 2>&1 || true
docker network create --subnet 172.28.66.0/24 ants >/dev/null
docker run -d --name an-r1 --network ants --ip 172.28.66.10 --sysctl net.ipv4.tcp_retries2=6 \
  -p "$PUB_IP_R:60000:60000" -p 127.0.0.1:18640:8645 -v r1data:/data "$IMG" \
  --nodekey=$R1_KEY --nat=extip:$PUB_IP_R --relay=true --store=true --store-message-db-url=sqlite:///data/r1-store.sqlite3 \
  --store-message-retention-policy='time:604800;capacity:100000' --filter=true --lightpush=true "${COMMON[@]}" >/dev/null
for i in $(seq 1 30); do R1_PEER_ID=$(curl -s http://127.0.0.1:18640/debug/v1/info | jq -r '.listenAddresses[0]' 2>/dev/null | sed 's#.*/p2p/##'); [ -n "$R1_PEER_ID" ] && [ "$R1_PEER_ID" != null ] && break; sleep 1; done
PEER="/ip4/$PUB_IP_R/tcp/60000/p2p/$R1_PEER_ID"
docker run -d --name an-nb --network ants --ip 172.28.66.22 -p 127.0.0.1:18642:8645 "$IMG" \
  --nodekey=$NB_KEY --nat=extip:172.28.66.22 --relay=true --store=false --filter=false --lightpush=false \
  --staticnode=$PEER --storenode=$PEER --filternode=$PEER --lightpushnode=$PEER "${COMMON[@]}" >/dev/null
docker ps --format '{{.Names}} {{.Ports}}'
echo "$PEER" > ~/relay-peer.txt
