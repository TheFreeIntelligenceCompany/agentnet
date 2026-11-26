#!/bin/bash
# sampler3.sh SECONDS : on the denied/guest box, every 2 s: node A2 peer state, kernel socket to R:60000 (state, queues, timer),
# cumulative count of frames seen in A2's relay cache for B's inbox topic (the REST cache is destructive, so counted cumulatively),
# every 10 s a NEW tcp connection attempt (nc -z -w 2) and tailscale route/peer status.
END=$(( $(date +%s) + $1 )); frames=0; k=0
while [ $(date +%s) -lt $END ]; do
  now=$(date -u +%T.%3N)
  st=$(curl -s -m 2 127.0.0.1:18660/admin/v1/peers | jq -r '.[0].connected // "none"')
  n=$(curl -s -m 2 127.0.0.1:18660/relay/v1/auto/messages/%2Fagentnet%2F1%2Finbox-0c%2Fproto | jq 'length' 2>/dev/null); frames=$(( frames + ${n:-0} ))
  sock=$(ss -tno dst <TS_IP_R>:60000 2>/dev/null | awk 'NR>1{print $1" sendq="$3" "$6$7}' | tr '\n' ';')
  new=""; if [ $((k % 5)) = 0 ]; then timeout 4 nc -z -w 2 <TS_IP_R> 60000 >/dev/null 2>&1; new=" new_conn_rc=$?"; route=$(ip route get <TS_IP_R> | awk 'NR==1{print $3,$4,$5}'); new="$new route=[$route]"; fi
  echo "$now peer=$st frames_total=$frames sock=[$sock]$new"
  k=$((k+1)); sleep 2
done
