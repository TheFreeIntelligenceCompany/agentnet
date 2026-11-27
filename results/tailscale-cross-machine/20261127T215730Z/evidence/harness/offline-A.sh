#!/usr/bin/env bash
# A's node offline (docker stop an-tsx-node-a), B sends 5, restart node A, poll receipts on B.
. /private/tmp/claude-501/tsx/env.sh
echo "$(ts) stop node A"; docker stop an-tsx-node-a >/dev/null
bx "ids=''; for i in 1 2 3 4 5; do ids=\"\$ids \$($BAN --json --data-dir $BD send $(cat $X/addrA) \"offA \$i\" | jq -r .message_id)\"; done; echo \$ids > ~/offA.ids; echo ok" > /dev/null
echo "$(ts) 5 queued on B while A node is down"; sleep 12
bx 'for id in $(cat ~/offA.ids); do ~/an/target/release/agentnet --json --data-dir ~/b status $id | jq -c "{state,attempts,last_error}"; done'
T0=$(date +%s); echo "$(ts) start node A"; docker start an-tsx-node-a >/dev/null
for k in $(seq 1 90); do r=$(bx 'n=0; for id in $(cat ~/offA.ids); do [ "$(~/an/target/release/agentnet --json --data-dir ~/b status $id | jq -r .state)" = delivered ] && n=$((n+1)); done; echo $n'); echo "$(ts) delivered=$r/5"; [ "$r" = 5 ] && break; sleep 2; done
bx 'for id in $(cat ~/offA.ids); do ~/an/target/release/agentnet --json --data-dir ~/b status $id | jq -c --argjson t0 '$T0' "{state,attempts,delivered_s_after_start_issued:((.delivered_at/1000)-\$t0)}"; done'
