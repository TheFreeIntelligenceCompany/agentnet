#!/usr/bin/env bash
cd "$(dirname "$0")"; AN=/Users/<user>/develop/FIC-elipsis/target/release/agentnet; A=$(cat adir); TSA=$(cat tsa); rm -f drop-msg.id
ts() { python3 -c 'import time;print("%s.%03dZ"%(time.strftime("%H:%M:%S",time.gmtime()),int(time.time()*1000)%1000))'; }
echo "$(ts) start samplers (420 s)"
instabox exec --background agentnet-ts -- "python3 ~/sampler-box.py 420 > ~/sampler-box.jsonl 2>&1" > /dev/null 2>&1
python3 -I sampler-mac.py 420 $AN $A drop-msg.id > sampler-mac.jsonl 2>&1 &
sleep 15
echo "$(ts) BLOCK (raw PREROUTING DROP for Mac tailnet IP -> tcp/60000), 120 s"
instabox exec agentnet-ts -- "./box-fw.sh raw-block $TSA >/dev/null; sudo iptables -t raw -L PREROUTING -nvx | sed -n 3,5p" 2>/dev/null | tee fw-block.txt; TB=$(date +%s)
sleep 10
M=$($AN --json --data-dir $A send $(cat addrB) "drop-trial queued message"); echo "$M" | jq -r .message_id > drop-msg.id; echo "$(ts) message queued during the blackhole: $(cat drop-msg.id)"
while [ $(( $(date +%s) - TB )) -lt 120 ]; do sleep 1; done
instabox exec agentnet-ts -- "./box-fw.sh raw-allow $TSA >/dev/null; sudo iptables -t raw -L PREROUTING -nvx | sed -n 3,5p" 2>/dev/null | tee fw-restore.txt; echo "$(ts) RESTORED"
for i in $(seq 1 200); do sleep 2; $AN --json --data-dir $A status $(cat drop-msg.id) | jq -e '.state=="delivered"' >/dev/null && { echo "$(ts) message delivered"; break; }; done
echo "$(ts) done waiting"; sleep 20; kill %1 2>/dev/null; wait
