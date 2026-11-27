#!/usr/bin/env bash
# trial.sh TAG BLOCK_S QUEUE(0|1) SAMPLE_S : silent path loss trial. Drops (raw PREROUTING DROP, no reject) all tcp/60000 from the Mac's tailnet IP at the box
# for BLOCK_S seconds. QUEUE=1 sends one message A->B 10 s into the block; at restore a probe message A->B is queued (QUEUE=0) to time delivery.
. /private/tmp/claude-501/tsx/env.sh
TAG=$1; BLK=$2; Q=$3; DUR=$4; D=$E/trial-$TAG; mkdir -p $D; rm -f $X/trial-msg.id
instabox exec --background agentnet-ts -- "python3 -I ~/sampler-box.py $DUR > ~/sampler-box-$TAG.jsonl 2>&1" > /dev/null 2>&1
python3 -I $H/sampler-mac.py $DUR $AN $A $X/trial-msg.id > $D/sampler-mac.jsonl 2>&1 &
SP=$!
sleep 15
echo "$(ts) BLOCK start (raw PREROUTING DROP for Mac tailnet IP -> tcp/60000), ${BLK} s"
bx "./box-fw.sh raw-block $TSA >/dev/null; sudo iptables -t raw -L PREROUTING -nvx | sed -n 3,5p" | tee $D/fw-block.txt; TB=$(date +%s)
echo "$(ts) block rule installed (box clock at command return)"
if [ "$Q" = 1 ]; then sleep 10; M=$($AN --json --data-dir $A send $(cat $X/addrB) "trial $TAG queued message"); echo "$M" | jq -r .message_id > $X/trial-msg.id; echo "$(ts) message queued during the blackhole: $(cat $X/trial-msg.id)"; fi
while [ $(( $(date +%s) - TB )) -lt $BLK ]; do sleep 1; done
bx "./box-fw.sh raw-allow $TSA >/dev/null; sudo iptables -t raw -L PREROUTING -nvx | sed -n 3,5p" | tee $D/fw-restore.txt; echo "$(ts) RESTORED"
if [ "$Q" = 0 ]; then M=$($AN --json --data-dir $A send $(cat $X/addrB) "trial $TAG probe after restore"); echo "$M" | jq -r .message_id > $X/trial-msg.id; echo "$(ts) probe message queued right after restore: $(cat $X/trial-msg.id)"; fi
for i in $(seq 1 $(( (DUR - BLK - 40) / 2 ))); do sleep 2; $AN --json --data-dir $A status $(cat $X/trial-msg.id) | jq -e '.state=="delivered"' >/dev/null && { echo "$(ts) message delivered"; break; }; done
echo "$(ts) done waiting"; wait $SP; echo "$(ts) mac sampler done"
