#!/bin/bash
# sampler4.sh SECONDS TOPIC_B TOPIC_A1 : on the guest box, every 2 s: node A2 peer state, new frames in A2's relay cache for B's and A1's inbox topics
# (the REST cache is destructive, so counted cumulatively; each new frame is logged with its decoded payload size in bytes),
# every 10 s a NEW tcp connection attempt (nc -z -w 2) and the route to R.
END=$(( $(date +%s) + $1 )); frames=0; k=0
enc(){ python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
TB=$(enc "$2"); TA=$(enc "$3")
while [ $(date +%s) -lt $END ]; do
  now=$(date -u +%T.%3N)
  st=$(curl -s -m 2 127.0.0.1:18660/admin/v1/peers | jq -r '.[0].connected // "none"')
  sizes=""
  for t in "B:$TB" "A1:$TA"; do
    nm=${t%%:*}; tp=${t#*:}
    j=$(curl -s -m 2 127.0.0.1:18660/relay/v1/auto/messages/$tp)
    n=$(echo "$j" | jq 'length' 2>/dev/null || echo 0); n=${n:-0}
    if [ "$n" -gt 0 ]; then frames=$((frames+n)); sizes="$sizes $nm:[$(echo "$j" | jq -r '[.[]|(.payload|@base64d|length)]|join(",")')]"; fi
  done
  new=""; if [ $((k % 5)) = 0 ]; then timeout 4 nc -z -w 2 <TS_IP> 60000 >/dev/null 2>&1; new=" new_conn_rc=$?"; route=$(ip route get <TS_IP> | awk 'NR==1{print $3,$4,$5}'); new="$new route=[$route]"; fi
  echo "$now peer=$st frames_total=$frames${sizes:+ frame_payload_bytes=$sizes}$new"
  k=$((k+1)); sleep 2
done
