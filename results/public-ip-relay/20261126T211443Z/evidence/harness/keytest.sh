#!/usr/bin/env bash
# Mac side. usage: keytest.sh MODE(audited|plain) CONVID R2ADDR. Env: AN BIN, W work dir, SSH script.
# 1) connect node A to the foreign node R2 via A's own REST admin API  2) poll `network status`  3) send a message  4) stop R2, observe recovery
MODE=$1; CONV=$2; R2ADDR=$3; AN=${AN:?}; W=${W:?}; B=$(cat $W/baddr)
now() { python3 -c 'import time;print(int(time.time()*1000))'; }
T0=$(now); rel() { python3 -c "print(round(($(now)-$T0)/1000,1))"; }
st() { $AN --json --data-dir $W/a network status | python3 -c 'import json,sys;d=json.load(sys.stdin)["network"];print("ready=%s connected=%s violation=%s detail=%s"%(d["ready"],d["connected_peers"],d["isolation_violation"],d["detail"]))'; }
echo "[t+0.0] POST /admin/v1/peers [R2] on node A REST (127.0.0.1:18690)"
curl -s -o /dev/null -w "http=%{http_code}\n" -X POST -H 'content-type: application/json' -d "[\"$R2ADDR\"]" http://127.0.0.1:18690/admin/v1/peers
echo "[t+$(rel)] node A peers:"; curl -s http://127.0.0.1:18690/admin/v1/peers | python3 -c 'import json,sys;[print("   ",p["multiaddr"],p["connected"]) for p in json.load(sys.stdin)]'
DET=""
for i in $(seq 1 50); do s=$(st); echo "[t+$(rel)] $s"; if [ "$MODE" = audited ] && echo "$s" | grep -q 'ready=False'; then DET=1; break; fi; sleep 1; done
echo "[t+$(rel)] doctor --ready:"; $AN --data-dir $W/a doctor --ready 2>&1 | grep -v -e 'single instance' -e 'run each identity'; echo "doctor --ready rc=${PIPESTATUS[0]}"
echo "[t+$(rel)] network status (human):"; $AN --data-dir $W/a network status; echo "rc=$?"
echo "[t+$(rel)] SEND message in conversation $CONV"
MID=$($AN --json --data-dir $W/a send --conversation $CONV $B "synthetic key-test $MODE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["message_id"])'); echo "message_id=$MID"
for i in $(seq 1 16); do echo "[t+$(rel)] $($AN --json --data-dir $W/a status $MID | python3 -c 'import json,sys;d=json.load(sys.stdin);print("state=%s attempts=%s sent_at=%s last_error=%s"%(d["state"],d["attempts"],d["sent_at"],d["last_error"]))')"; sleep 3; done
echo "[t+$(rel)] B inbox for conversation (count):"; $W/ssh.sh "/root/an/target/release/agentnet --json --data-dir /root/b inbox --conversation $CONV" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["records"]))'
echo "[t+$(rel)] node A peers now:"; curl -s http://127.0.0.1:18690/admin/v1/peers | python3 -c 'import json,sys;[print("   ",p["multiaddr"],p["connected"]) for p in json.load(sys.stdin)]'
echo "MID=$MID" > $W/mid.$MODE
