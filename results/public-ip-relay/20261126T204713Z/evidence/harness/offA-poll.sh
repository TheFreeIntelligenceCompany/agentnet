#!/usr/bin/env bash
AN=/root/an/target/release/agentnet
for k in $(seq 1 90); do n=0; for id in $(cat /root/offA.ids); do [ "$($AN --json --data-dir /root/b status $id | jq -r .state)" = delivered ] && n=$((n+1)); done; echo "$(date -u +%T.%3NZ) delivered=$n/5"; [ $n = 5 ] && break; sleep 2; done
for id in $(cat /root/offA.ids); do $AN --json --data-dir /root/b status $id | jq -c '{state,attempts,delivered_at}'; done
