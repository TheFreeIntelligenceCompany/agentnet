#!/usr/bin/env bash
# trial2.sh TAG BLOCK1_S GAP_S BLOCK2_S DUR : block1, restore, wait GAP_S, block2 (75 s-class), restore, then queue one probe message A->B and time its delivery.
# Nothing is sent toward A by us during either block. Same samplers as trial.sh.
. /private/tmp/claude-501/tsx/env.sh
TAG=$1; B1=$2; GAP=$3; B2=$4; DUR=$5; D=$E/trial-$TAG; mkdir -p $D; rm -f $X/trial-msg.id
instabox exec --background agentnet-ts -- "python3 -I ~/sampler-box.py $DUR > ~/sampler-box-$TAG.jsonl 2>&1" > /dev/null 2>&1
python3 -I $H/sampler-mac.py $DUR $AN $A $X/trial-msg.id > $D/sampler-mac.jsonl 2>&1 &
SP=$!
sleep 15
blk() { echo "$(ts) BLOCK $1 start ($2 s)"; bx "./box-fw.sh raw-block $TSA >/dev/null; echo done" >/dev/null; echo "$(ts) block rule installed (command returned)"; TB=$(date +%s); while [ $(( $(date +%s) - TB )) -lt $2 ]; do sleep 1; done
      bx "./box-fw.sh raw-allow $TSA >/dev/null; echo done" >/dev/null; echo "$(ts) RESTORED $1 (command returned)"; }
blk 1 $B1; sleep $GAP; blk 2 $B2
M=$($AN --json --data-dir $A send $(cat $X/addrB) "trial $TAG probe after restore"); echo "$M" | jq -r .message_id > $X/trial-msg.id; echo "$(ts) probe message queued right after restore 2: $(cat $X/trial-msg.id)"
for i in $(seq 1 $(( (DUR - B1 - GAP - B2 - 60) / 2 ))); do sleep 2; $AN --json --data-dir $A status $(cat $X/trial-msg.id) | jq -e '.state=="delivered"' >/dev/null && { echo "$(ts) message delivered"; break; }; done
echo "$(ts) done waiting"; wait $SP; echo "$(ts) mac sampler done"
