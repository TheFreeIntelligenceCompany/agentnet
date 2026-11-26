#!/usr/bin/env bash
AN=~/an/target/release/agentnet; T0=$1
for k in $(seq 1 40); do n=0; for id in $(cat ~/offA.ids); do [ "$($AN --json --data-dir ~/b status $id | jq -r .state)" = delivered ] && n=$((n+1)); done; echo "$(date -u +%T) delivered=$n/5"; [ $n = 5 ] && break; sleep 2; done
for id in $(cat ~/offA.ids); do $AN --json --data-dir ~/b status $id | jq -c --argjson t0 $T0 '{state,attempts,delivered_s_after_A_restart:((.delivered_at/1000)-$t0)}'; done
