#!/usr/bin/env bash
# Run ON box 1. Starts relay R (libp2p tcp/60000 published ONLY on the tailnet IPv4) and client node B (same host).
# NO host firewall rule is added: access control is the tailnet policy alone.
set -euo pipefail
TS_IP_R="$(tailscale ip -4)"
IMG='wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73'
R1_KEY=e83105f9fe35cdb5cd2eadeaae4604f8f3c8fb23bca46c13be280c2856ebd1c7
NB_KEY=398d445e449874cee2d4394bb41285dd4fd296d96829f825b86aa55543b58134
R1_PEER_ID=16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV
COMMON=(--max-msg-size=150KiB --cluster-id=66 --num-shards-in-network=1 --shard=0 --discv5-discovery=false --peer-exchange=false
 --relay-peer-exchange=false --rendezvous=false --enable-kad-discovery=false --quic-support=false --mix=false --rln-relay=false
 --listen-address=0.0.0.0 --dns-addrs-name-server=127.0.0.1 --tcp-port=60000 --metrics-server=false --peer-persistence=false
 --local-storage-path=/data --log-level=INFO --rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-admin=true
 --rest-relay-cache-capacity=1000 --rest-messaging-cache-capacity=1000)
docker rm -f an-r1 an-nb >/dev/null 2>&1 || true
docker network rm ants >/dev/null 2>&1 || true
docker network create --subnet 172.28.66.0/24 ants >/dev/null
docker run -d --name an-r1 --network ants --ip 172.28.66.10 --platform linux/amd64 --sysctl net.ipv4.tcp_retries2=6 \
  -p "$TS_IP_R:60000:60000" -p 127.0.0.1:18640:8645 -v r1data:/data "$IMG" \
  --nodekey=$R1_KEY --nat=extip:$TS_IP_R --relay=true --store=true --store-message-db-url=sqlite:///data/r1-store.sqlite3 \
  --store-message-retention-policy='time:604800;capacity:100000' --filter=true --lightpush=true "${COMMON[@]}" >/dev/null
PEER="/ip4/$TS_IP_R/tcp/60000/p2p/$R1_PEER_ID"
docker run -d --name an-nb --network ants --ip 172.28.66.22 --platform linux/amd64 -p 127.0.0.1:18642:8645 "$IMG" \
  --nodekey=$NB_KEY --nat=extip:172.28.66.22 --relay=true --store=false --filter=false --lightpush=false \
  --staticnode=$PEER --storenode=$PEER --filternode=$PEER --lightpushnode=$PEER "${COMMON[@]}" >/dev/null
docker ps --format '{{.Names}} {{.Ports}}'
echo "$PEER" > ~/relay-peer.txt
