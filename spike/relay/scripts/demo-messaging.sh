#!/usr/bin/env bash
# Experiment E10 (extra): the higher-level /messaging/v1 REST API (--entry-layer=messaging). ma=Core(18651), mb=Edge(18652).
set -u; . "$(dirname "$0")/common.sh"
MA=http://127.0.0.1:18651; MB=http://127.0.0.1:18652; CTM=/agentnet/1/spike-a1-messaging/proto
m() { req POST "$1/messaging/v1/messages" "{\"payload\":\"$(b64 "$2")\",\"contentTopic\":\"$CTM\"}"; }
echo "### subscribe"; req POST $MA/messaging/v1/subscriptions "[\"$CTM\"]"; req POST $MB/messaging/v1/subscriptions "[\"$CTM\"]"; req GET $MB/messaging/v1/subscriptions
sleep 3
echo "### ma (Core) send"; m $MA "msg-1-from-core"
sleep 3
echo "### ma send events"; req GET $MA/messaging/v1/events/send
echo "### mb received events"; req GET $MB/messaging/v1/events/received
echo "### mb (Edge) send reply"; m $MB "reply-from-edge"
sleep 3
echo "### mb send events"; req GET $MB/messaging/v1/events/send
echo "### ma received events"; req GET $MA/messaging/v1/events/received
echo "### offline: stop mb, ma sends 3, start mb"
docker stop an-mb >/dev/null; for i in 1 2 3; do m $MA "while-mb-down-$i" | tr '\n' ' '; sleep 0.3; done; echo
docker start an-mb >/dev/null; for i in $(seq 1 40); do curl -s -m 2 $MB/health >/dev/null && break; sleep 1; done; sleep 4
echo "### mb after restart: subscriptions (in-memory, lost?)"; req GET $MB/messaging/v1/subscriptions
req POST $MB/messaging/v1/subscriptions "[\"$CTM\"]"; sleep 10
echo "### mb received events after resubscribe (any source=history?)"; req GET $MB/messaging/v1/events/received
echo "### errors"
req POST $MA/messaging/v1/messages '{"payload":"!!","contentTopic":"/a/1/b/proto"}'
req POST $MA/messaging/v1/messages "{\"payload\":\"$(b64 x)\",\"contentTopic\":\"bad\"}"
