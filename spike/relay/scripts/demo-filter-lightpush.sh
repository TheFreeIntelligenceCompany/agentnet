#!/usr/bin/env bash
# Experiment E4: filter v2 subscribe + lightpush v3 and legacy v1 via client nodes -> R1 service node.
set -u; . "$(dirname "$0")/common.sh"
enc() { python3 -I -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
CT3=/agentnet/1/spike-a1-filter/proto; CT3E=$(enc $CT3)
echo "### NB filter subscribe (NB is NOT relay-REST-subscribed to $CT3)"
req POST $NB/filter/v2/subscriptions "{\"requestId\":\"req-1\",\"contentFilters\":[\"$CT3\"],\"pubsubTopic\":\"$PUBSUB\"}"
echo "### NB filter ping"
req GET $NB/filter/v2/subscriptions/req-1
echo "### R1 admin view of filter subscriptions"
req GET $R1/admin/v1/filter/subscriptions
echo "### NA relay publish on $CT3 (NA also relay-subscribed? no)"
pub $NA $CT3 "via-relay-A-to-filter-B"
sleep 2
echo "### NB filter poll"
req GET $NB/filter/v2/messages/$CT3E
echo "### NB filter poll again (expect empty, destructive)"
req GET $NB/filter/v2/messages/$CT3E
echo "### lightpush v3 from NB (NB -> R1 -> relay), pubsubTopic given"
P=$(b64 "lightpush-v3-from-B")
req POST $NB/lightpush/v3/message "{\"pubsubTopic\":\"$PUBSUB\",\"message\":{\"payload\":\"$P\",\"contentTopic\":\"$CT3\"}}"
echo "### lightpush v3 without pubsubTopic (autosharding)"
req POST $NB/lightpush/v3/message "{\"message\":{\"payload\":\"$P\",\"contentTopic\":\"$CT3\",\"ephemeral\":true}}"
echo "### lightpush legacy v1"
req POST $NB/lightpush/v1/message "{\"pubsubTopic\":\"$PUBSUB\",\"message\":{\"payload\":\"$P\",\"contentTopic\":\"$CT3\"}}"
sleep 2
echo "### NB filter poll (should hold lightpush-delivered msgs)"
req GET $NB/filter/v2/messages/$CT3E
echo "### filter unsubscribe"
req DELETE $NB/filter/v2/subscriptions "{\"requestId\":\"req-2\",\"contentFilters\":[\"$CT3\"],\"pubsubTopic\":\"$PUBSUB\"}"
echo "### R1 admin filter subs after"
req GET $R1/admin/v1/filter/subscriptions
echo "### R1 store contents of $CT3"
req GET "$R1/store/v3/messages?contentTopics=$CT3E&includeData=true"
