#!/bin/bash
# Mac node A. $1 = static peer multiaddr
PEER=$1
docker rm -f an-do-node-a >/dev/null 2>&1
docker run -d --name an-do-node-a --platform linux/amd64 -p 127.0.0.1:18690:8645 wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73  --nodekey=${A_KEY:?} --nat=none --relay=true --store=false --filter=false --lightpush=false --staticnode=$PEER --storenode=$PEER --filternode=$PEER --lightpushnode=$PEER  --max-msg-size=150KiB --cluster-id=66 --num-shards-in-network=1 --shard=0 --discv5-discovery=false --peer-exchange=false --relay-peer-exchange=false --rendezvous=false --enable-kad-discovery=false --quic-support=false --mix=false --rln-relay=false --listen-address=0.0.0.0 --dns-addrs-name-server=127.0.0.1 --tcp-port=60000 --metrics-server=false --peer-persistence=false --local-storage-path=/data --log-level=INFO --rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-admin=true --rest-relay-cache-capacity=1000 --rest-messaging-cache-capacity=1000
