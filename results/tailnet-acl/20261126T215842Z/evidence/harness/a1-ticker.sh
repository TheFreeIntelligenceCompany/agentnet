#!/bin/bash
# a1-ticker.sh B_ADDR SECONDS : A1 sends one message to B every 30 s and logs when each is delivered
END=$(( $(date +%s) + $2 )); i=0
while [ $(date +%s) -lt $END ]; do i=$((i+1)); id=$(~/agentnet --data-dir ~/a1 --json send $1 "tick $i" | jq -r .message_id); echo "$(date -u +%T) sent tick $i $id"; sleep 30; done
