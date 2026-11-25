#!/usr/bin/env bash
# Experiment E2: store query API shape: pagination, time range, hashes, ephemeral, from a client node via peerAddr.
set -u; . "$(dirname "$0")/common.sh"
enc() { python3 -I -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
CTE=$(enc "$CT"); PUBE=$(enc "$PUBSUB"); PEER=$(enc "$R1_MADDR")
CT2=/agentnet/1/spike-a1-store/proto; CT2E=$(enc "$CT2")
req POST $NA/relay/v1/auto/subscriptions "[\"$CT2\"]"
echo "### publish 5 persistent + 1 ephemeral on $CT2 from NA"
START=$(now_ns)
for i in 1 2 3 4 5; do pub $NA $CT2 "store-msg-$i"; sleep 0.3; done
pub $NA $CT2 "EPHEMERAL-msg" '"ephemeral":true'
sleep 2; END=$(now_ns)
echo "### store query via R1 self (no peerAddr), page size 2 (descending default?)"
req GET "$R1/store/v3/messages?contentTopics=$CT2E&includeData=true&pageSize=2"
echo "### same from NB via peerAddr=R1, ascending=true pageSize=2"
req GET "$NB/store/v3/messages?peerAddr=$PEER&contentTopics=$CT2E&includeData=true&pageSize=2&ascending=true"
echo "### same from NB WITHOUT peerAddr (uses --storenode peer selection)"
req GET "$NB/store/v3/messages?contentTopics=$CT2E&includeData=true&pageSize=2&ascending=true"
echo "### time range [START,END] includeData=false (hashes only)"
req GET "$R1/store/v3/messages?contentTopics=$CT2E&startTime=$START&endTime=$END&includeData=false&pageSize=100&ascending=true"
echo "### pubsubTopic only filter (no content topic)"
req GET "$R1/store/v3/messages?pubsubTopic=$PUBE&includeData=false&pageSize=100&ascending=true"
echo "### time range > 24h"
req GET "$R1/store/v3/messages?contentTopics=$CT2E&startTime=1&endTime=$END&pageSize=2"
echo "### no filters at all"
req GET "$R1/store/v3/messages?pageSize=3&includeData=false"
echo "### pageSize 1000 (cap?)"
req GET "$R1/store/v3/messages?contentTopics=$CT2E&pageSize=1000&includeData=false"
