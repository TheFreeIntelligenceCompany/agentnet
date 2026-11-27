#!/usr/bin/env bash
# Mac side, single trial. Remove the Mac's tcp/60000 inbound rule, restart node A (so it must dial anew), queue a message, verify A cannot connect, restore the rule, time Connected and delivery.
W=<workdir>; AN=<repo>/target/release/agentnet; AD=$W/a
FID=$(awk '{print $1}' $W/fw.txt); A=$(cat $W/myip); R=$(awk '{print $2}' $W/drop.txt); BA=$(cat $W/baddr)
ts() { python3 -c 'import datetime;print(datetime.datetime.now(datetime.UTC).strftime("%T.%f")[:-3]+"Z")'; }
fwwait() { for i in $(seq 1 30); do st=$(doctl compute firewall get $FID --format Status --no-header); [ "$st" = succeeded ] && { echo "$(ts) firewall status succeeded"; return; }; sleep 1; done; }
peerst() { curl -s -m 3 http://127.0.0.1:18690/admin/v1/peers | python3 -c 'import json,sys;print([p["connected"] for p in json.load(sys.stdin)])' 2>&1; }
echo "$(ts) remove inbound rule tcp/60000 for the Mac (tcp/22 kept)"; doctl compute firewall remove-rules $FID --inbound-rules "protocol:tcp,ports:60000,address:$A/32"; echo "$(ts) remove-rules returned"; fwwait
echo "$(ts) docker restart an-do-node-a (kills the established flow)"; docker restart an-do-node-a >/dev/null; echo "$(ts) node A restarted"
sleep 15; M=$($AN --json --data-dir $AD send $BA "synthetic fw-trial queued message"); MID=$(echo "$M" | python3 -c 'import json,sys;print(json.load(sys.stdin)["message_id"])'); echo "$(ts) message queued during block: $MID"
sleep 45
echo "$(ts) nc from Mac to R:60000 during block:"; nc -vz -G 5 $R 60000 2>&1
echo "$(ts) node A peers: $(peerst)"
echo "$(ts) agent A network status:"; $AN --data-dir $AD network status 2>&1 | head -n 4
echo "$(ts) message: $($AN --json --data-dir $AD status $MID | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["state"],d["attempts"],d["last_error"])')"
echo "$(ts) tcp/22 still works: $($W/ssh.sh 'echo yes')"
echo "$(ts) add rule back"; doctl compute firewall add-rules $FID --inbound-rules "protocol:tcp,ports:60000,address:$A/32"; echo "$(ts) add-rules returned"; fwwait
T=0; for i in $(seq 1 120); do p=$(peerst); echo "$(ts) peers=$p msg=$($AN --json --data-dir $AD status $MID | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["state"],d["attempts"])')"; echo "$p" | grep -q "'Connected'" && ! echo "$p" | grep -q CannotConnect && [ -z "$C" ] && { C=1; echo "$(ts) >>> node A Connected"; }; $AN --json --data-dir $AD status $MID | python3 -c 'import json,sys;sys.exit(0 if json.load(sys.stdin)["state"]=="delivered" else 1)' && { echo "$(ts) >>> message delivered"; break; }; sleep 2; done
