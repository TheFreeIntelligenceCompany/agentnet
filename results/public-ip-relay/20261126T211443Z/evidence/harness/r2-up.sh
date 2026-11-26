#!/usr/bin/env bash
# Run ON the droplet: foreign node R2 (different disposable nodekey, same cluster 66 / shard 0, libp2p tcp/60001 published on the public IP), REST on 127.0.0.1:18641.
set -euo pipefail
PUB_IP_R="$1"; KEY="$2"
IMG='wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73'
docker rm -f an-r2 >/dev/null 2>&1 || true
docker run -d --name an-r2 --network ants --ip 172.28.66.30 -p "$PUB_IP_R:60001:60001" -p 127.0.0.1:18641:8645 "$IMG" \
  --nodekey=$KEY --nat=extip:$PUB_IP_R --relay=true --store=false --filter=false --lightpush=false \
  --max-msg-size=150KiB --cluster-id=66 --num-shards-in-network=1 --shard=0 --discv5-discovery=false --peer-exchange=false \
  --relay-peer-exchange=false --rendezvous=false --enable-kad-discovery=false --quic-support=false --mix=false --rln-relay=false \
  --listen-address=0.0.0.0 --dns-addrs-name-server=127.0.0.1 --tcp-port=60001 --metrics-server=false --peer-persistence=false \
  --local-storage-path=/data --log-level=INFO --rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-admin=true \
  --rest-relay-cache-capacity=1000 --rest-messaging-cache-capacity=1000 >/dev/null
