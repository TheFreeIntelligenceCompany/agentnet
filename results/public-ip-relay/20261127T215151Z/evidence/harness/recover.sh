#!/usr/bin/env bash
# Mac side: stop R2 (droplet) and watch violation clear + queued message $1 get published and delivered. Env AN W SSHS
MID=$1; ms() { python3 -c 'import time;print(int(time.time()*1000))'; }; T0=$(ms); rel() { python3 -c "print(round(($(ms)-$T0)/1000,1))"; }
$SSHS 'docker stop an-r2 >/dev/null'; echo "[t+$(rel)] docker stop an-r2 returned"
for i in $(seq 1 40); do
 s=$($AN --json --data-dir $W/a network status | python3 -c 'import json,sys;d=json.load(sys.stdin)["network"];print("ready=%s connected=%s violation=%s"%(d["ready"],d["connected_peers"],d["isolation_violation"]))')
 m=$($AN --json --data-dir $W/a status $MID | python3 -c 'import json,sys;d=json.load(sys.stdin);print("state=%s attempts=%s last_error=%s"%(d["state"],d["attempts"],d["last_error"]))')
 echo "[t+$(rel)] $s | $m"; echo "$m" | grep -q "state=delivered" && break; sleep 1; done
echo "[t+$(rel)] doctor --ready:"; $AN --data-dir $W/a doctor --ready 2>&1 | grep -v -e 'single instance' -e 'run each identity'; echo "rc=${PIPESTATUS[0]}"
