#!/usr/bin/env bash
# Mac side. usage: race.sh ROUND CONVID. Env: AN, W, SSHS (ssh wrapper), R2ADDR.
# R2 must be subscribed to B inbox content topic (driver does it): its relay REST cache is the evidence of what R2 received.
# Precondition: R2 container up, node A clean. Connect node A to R2 via A's own REST admin API and send IMMEDIATELY: no status/doctor call in between.
R=$1; CONV=$2; B=$(cat $W/baddr); BIN=/root/an/target/release/agentnet
ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
T0=$(ms); rel() { python3 -c "print(round(($(ms)-$T0)/1000,2))"; }
# precondition check (before the race, not between connect and send)
$AN --json --data-dir $W/a network status | python3 -c 'import json,sys;d=json.load(sys.stdin)["network"];print("[pre] ready=%s connected=%s violation=%s"%(d["ready"],d["connected_peers"],d["isolation_violation"]))'
curl -s -o /dev/null -w "[t+$(rel)] POST peers http=%{http_code} time=%{time_total}s\n" -X POST -H 'content-type: application/json' -d "[\"$R2ADDR\"]" http://127.0.0.1:18690/admin/v1/peers
S=$($AN --json --data-dir $W/a send --conversation $CONV $B "synthetic race round $R")
MID=$(echo "$S" | python3 -c 'import json,sys;print(json.load(sys.stdin)["message_id"])'); echo "[t+$(rel)] send returned message_id=$MID"
for i in $(seq 1 12); do echo "[t+$(rel)] $($AN --json --data-dir $W/a status $MID | python3 -c 'import json,sys;d=json.load(sys.stdin);print("state=%s attempts=%s sent_at=%s last_error=%s"%(d["state"],d["attempts"],d["sent_at"],d["last_error"]))')"; sleep 1; done
echo "[t+$(rel)] node A peers (REST):"; curl -s http://127.0.0.1:18690/admin/v1/peers | python3 -c 'import json,sys;[print("   ",p["multiaddr"].split("/p2p/")[1][-8:],p["connected"]) for p in json.load(sys.stdin)]'
echo "[t+$(rel)] network status now: $($AN --json --data-dir $W/a network status | python3 -c 'import json,sys;d=json.load(sys.stdin)["network"];print("ready=%s connected=%s violation=%s"%(d["ready"],d["connected_peers"],d["isolation_violation"]))')"
echo "[t+$(rel)] B inbox count for conversation: $($SSHS "$BIN --json --data-dir /root/b inbox --conversation $CONV" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["records"]))')"
echo "[t+$(rel)] R2 relay cache for B's inbox content topic (messages R2 received): $($SSHS "curl -s http://127.0.0.1:18641/relay/v1/auto/messages/%2Fagentnet%2F1%2Finbox-0a%2Fproto" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')"
echo "[t+$(rel)] state at end of window: $($AN --json --data-dir $W/a status $MID | python3 -c 'import json,sys;d=json.load(sys.stdin);print("state=%s attempts=%s last_error=%s"%(d["state"],d["attempts"],d["last_error"]))')"
echo "MID=$MID" > $W/mid.race$R
