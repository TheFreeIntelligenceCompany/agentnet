#!/usr/bin/env bash
# Experiment: does DELETE /relay/v1/auto/subscriptions of ONE content topic drop the node's shard-0 relay mesh membership?
mesh() { curl -s -m 3 http://127.0.0.1:18640/admin/v1/peers/mesh | python3 -I -c "import json,sys;d=json.load(sys.stdin);print(sum(len(s['peers']) for s in d))"; }
for n in 18641 18642; do
  curl -s -X POST -H 'content-type: application/json' -d '["/agentnet/1/keeper/proto","/agentnet/1/inbox-0f/proto"]' http://127.0.0.1:$n/relay/v1/auto/subscriptions; echo " subscribed $n"
done
for i in $(seq 1 30); do [ "$(mesh)" = 2 ] && break; sleep 1; done
echo "T+0 R1 mesh peers before DELETE: $(mesh)"
curl -s -X DELETE -H 'content-type: application/json' -d '["/agentnet/1/inbox-0f/proto"]' http://127.0.0.1:18641/relay/v1/auto/subscriptions; echo " DELETE inbox-0f on NA (keeper topic still subscribed)"
for s in 1 2 3 5 8; do sleep $s; echo "after +${s}s more: R1 mesh peers = $(mesh)"; done
for n in 18641 18642; do curl -s -X POST -H 'content-type: application/json' -d '["/agentnet/1/keeper/proto","/agentnet/1/inbox-0f/proto"]' http://127.0.0.1:$n/relay/v1/auto/subscriptions >/dev/null; done
t=0; while [ "$(mesh)" != 2 ] && [ $t -lt 60 ]; do sleep 1; t=$((t+1)); done
echo "re-subscribed: mesh back to $(mesh) after ${t}s"
