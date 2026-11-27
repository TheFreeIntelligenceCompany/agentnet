#!/usr/bin/env bash
# Mac side: N race rounds. Each: start R2 (droplet), subscribe R2's relay REST cache to B's inbox content topic, wait for A clean, race (connect + immediate send), then stop R2 and wait for delivery.
for r in $(seq $1 $2); do
  echo "=================== ROUND $r  $(date -u +%T)Z"
  $SSHS 'docker start an-r2 >/dev/null; sleep 7; curl -s -o /dev/null -w "R2 subscribe http=%{http_code}\n" -X POST -H "content-type: application/json" -d "[\"/agentnet/1/inbox-0a/proto\"]" http://127.0.0.1:18641/relay/v1/auto/subscriptions'
  for k in $(seq 1 20); do $AN --json --data-dir $W/a network status | python3 -c 'import json,sys;d=json.load(sys.stdin)["network"];sys.exit(0 if d["ready"] and d["connected_peers"]==1 else 1)' && break; sleep 1; done
  CONV=$(python3 -c 'import uuid;print(uuid.uuid4())'); echo "conversation $CONV"
  bash $W/harness/race.sh $r $CONV; MID=$(sed 's/MID=//' $W/mid.race$r)
  echo "--- recovery (stop R2)"; bash $W/harness/recover.sh $MID | grep -v "^\[ok\|^\[warn\|^  *->"
  echo "B inbox count for conversation after recovery: $($SSHS "/root/an/target/release/agentnet --json --data-dir /root/b inbox --conversation $CONV" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["records"]))')"
done
