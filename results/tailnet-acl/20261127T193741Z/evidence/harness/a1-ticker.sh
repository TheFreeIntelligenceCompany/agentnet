#!/bin/bash
# a1-ticker.sh B_ADDR SECONDS INTERVAL : A1 sends one message to B every INTERVAL s (bodies of 1, 100, 1000 bytes in rotation) and logs the send time and message id
END=$(( $(date +%s) + $2 )); i=0
while [ $(date +%s) -lt $END ]; do i=$((i+1)); case $((i%3)) in 1) b=x;; 2) b=$(head -c 100 /dev/zero | tr '\0' y);; 0) b=$(head -c 1000 /dev/zero | tr '\0' z);; esac
  id=$(~/agentnet --data-dir ~/a1 --json send $1 "$b" | jq -r .message_id); echo "$(date -u +%T.%3N) sent tick $i body_bytes=${#b} $id"; sleep $3; done
