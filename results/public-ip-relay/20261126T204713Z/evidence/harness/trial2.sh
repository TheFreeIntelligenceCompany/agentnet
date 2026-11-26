#!/usr/bin/env bash
S=<scratch> W=$S/w; AN=/Users/<user>/develop/FIC-elipsis/target/release/agentnet; AD=<datadir>/a
FID=$(cat $W/fid); A=$(cat $W/pubA); R=$(cat $W/pubR); AB=$(cat $W/addrB)
ts() { python3 -c 'import datetime;print(datetime.datetime.now(datetime.UTC).strftime("%T.%f")[:-3]+"Z")'; }
fwwait() { for i in $(seq 1 30); do st=$(doctl compute firewall get $FID --format Status --no-header); [ "$st" = succeeded ] && { echo "$(ts) firewall status succeeded"; return; }; sleep 1; done; }
ssh -i $S/key/k root@$R 'pkill -f sampler-box.py; nohup python3 /root/sampler-box.py 420 > /root/sampler2-box.jsonl 2>&1 &' 
python3 -I $W/sampler-mac.py 400 $AN $AD $W/drop-msg.id > $W/sampler2-mac.jsonl 2>&1 &
sleep 10
echo "$(ts) remove inbound rule tcp/60000 (keep tcp/22)"; doctl compute firewall remove-rules $FID --inbound-rules "protocol:tcp,ports:60000,address:$A/32"; echo "$(ts) remove-rules returned"; fwwait
echo "$(ts) restart node A (docker restart an-do-node-a): kills the established flow so the node must dial anew"; docker restart an-do-node-a >/dev/null; echo "$(ts) node A restarted"
sleep 20; M=$($AN --json --data-dir $AD send $AB "synthetic drop-trial2 queued message"); echo "$M" | jq -r .message_id > $W/drop-msg.id; echo "$(ts) message queued during block: $(cat $W/drop-msg.id)"
sleep 90; echo "$(ts) nc from Mac during block 60000:"; nc -vz -w 5 $R 60000 2>&1; echo "$(ts) agent A network status:"; $AN --data-dir $AD network status 2>&1
echo "$(ts) add rule back"; doctl compute firewall add-rules $FID --inbound-rules "protocol:tcp,ports:60000,address:$A/32"; echo "$(ts) add-rules returned"; fwwait
for i in $(seq 1 120); do sleep 3; $AN --json --data-dir $AD status $(cat $W/drop-msg.id) | jq -e '.state=="delivered"' >/dev/null && { echo "$(ts) message delivered"; break; }; done
echo "$(ts) done waiting"
