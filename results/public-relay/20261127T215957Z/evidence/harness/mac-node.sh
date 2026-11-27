#!/usr/bin/env bash
# usage: mac-node.sh NAME NODEKEY RESTPORT DNS_NS [extra flags...]   (Mac, colima, linux/amd64 via qemu). libp2p port NOT published.
set -euo pipefail
NAME=$1; KEY=$2; REST=$3; NS=$4; shift 4
IMG='wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73'
R1_PEER_ID=16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV
PUB_HOST=${PUB_HOST:?}
PEER="/dns4/$PUB_HOST/tcp/443/wss/p2p/$R1_PEER_ID"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --platform linux/amd64 -p 127.0.0.1:$REST:8645 "$IMG" \
  --nodekey=$KEY --relay=true --store=false --filter=false --lightpush=false \
  --websocket-support=true --websocket-port=8000 \
  --staticnode=$PEER --storenode=$PEER --filternode=$PEER --lightpushnode=$PEER \
  --max-msg-size=150KiB --cluster-id=66 --num-shards-in-network=1 --shard=0 --discv5-discovery=false --peer-exchange=false \
  --relay-peer-exchange=false --rendezvous=false --enable-kad-discovery=false --quic-support=false --mix=false --rln-relay=false \
  --listen-address=0.0.0.0 --dns-addrs-name-server=$NS --tcp-port=60000 --metrics-server=false --peer-persistence=false \
  --local-storage-path=/data --log-level=INFO --rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-admin=true \
  --rest-relay-cache-capacity=1000 --rest-messaging-cache-capacity=1000 "$@"
