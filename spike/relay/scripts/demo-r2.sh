#!/usr/bin/env bash
# Experiment E9: two service nodes. NA/NB dial R1 and R2. Stop R1: relay delivery A->B continues through R2, store query
# via R2 (peerAddr) still works; messages published while R1 was down are in R2's store but not R1's.
set -u; . "$(dirname "$0")/common.sh"; cd "$(dirname "$0")/.."
R2=http://127.0.0.1:18643; R2_PEER_ID=$(grep '^R2_PEER_ID=' .env | cut -d= -f2); R2_MADDR=/ip4/172.28.66.11/tcp/60000/p2p/$R2_PEER_ID
enc() { python3 -I -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
CT9=/agentnet/1/spike-a1-r2/proto; CT9E=$(enc $CT9); PEER2=$(enc "$R2_MADDR")
cnt() { curl -s "$1/store/v3/messages?contentTopics=$CT9E&includeData=false&pageSize=100" | python3 -I -c "import json,sys;d=json.load(sys.stdin);print(len(d.get('messages',[])),d.get('statusDesc'))" 2>&1; }
for n in $NA $NB; do req POST $n/relay/v1/auto/subscriptions "[\"$CT9\"]" >/dev/null; done; sleep 3
echo "NA peers: $(curl -s $NA/admin/v1/peers | python3 -I -c "import json,sys;print([(p['multiaddr'].split('/')[2],p['connected']) for p in json.load(sys.stdin)])")"
pub $NA $CT9 "both-up-1" >/dev/null; sleep 2
echo "store counts both up: R1=$(cnt $R1)  R2=$(cnt $R2)"
echo "### stop R1"; docker stop an-r1 >/dev/null; sleep 2
echo "### NA publishes 3 with R1 down"; for i in 1 2 3; do pub $NA $CT9 "r1-down-$i" | tr '\n' ' '; sleep 0.5; done; echo
sleep 2; echo "### NB relay poll:"; req GET $NB/relay/v1/auto/messages/$CT9E | cut -c1-400
echo "store count R2=$(cnt $R2)"
echo "### NB store query via explicit peerAddr=R2:"; req GET "$NB/store/v3/messages?peerAddr=$PEER2&contentTopics=$CT9E&includeData=false&pageSize=100" | cut -c1-500
echo "### NB store query w/o peerAddr (configured --storenode=R1, down):"; req GET "$NB/store/v3/messages?contentTopics=$CT9E&includeData=false&pageSize=100" | cut -c1-300
echo "### start R1 again; wait 15s; R1 store only has pre-outage message(s):"; docker start an-r1 >/dev/null; sleep 15
echo "store counts: R1=$(cnt $R1)  R2=$(cnt $R2)"
