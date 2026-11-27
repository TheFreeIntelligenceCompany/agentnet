#!/usr/bin/env bash
# B's node offline (docker stop an-nb), A sends 5, restart node B, poll receipts on A. Needs env.sh (anA, bx, ts, X).
. /private/tmp/claude-501/tsx/env.sh
echo "$(ts) stop node B"; bx "docker stop an-nb >/dev/null; echo stopped"
IDS=(); for i in 1 2 3 4 5; do IDS+=($(anA --json send $(cat $X/addrB) "offB $i" | jq -r .message_id)); done
echo "$(ts) 5 queued while B node is down"; sleep 12
for id in "${IDS[@]}"; do anA --json status $id | jq -c '{state,attempts,last_error}'; done
T0=$(date +%s); echo "$(ts) start node B"; bx "docker start an-nb >/dev/null; echo started"; T1=$(date +%s)
for k in $(seq 1 180); do n=0; for id in "${IDS[@]}"; do anA --json status $id | jq -e '.state=="delivered"' >/dev/null && n=$((n+1)); done; echo "$(ts) delivered=$n/5"; [ $n = 5 ] && break; sleep 2; done
for id in "${IDS[@]}"; do anA --json status $id | jq -c --argjson t0 $T0 '{state,attempts,delivered_s_after_start_issued:((.delivered_at/1000)-$t0)}'; done
