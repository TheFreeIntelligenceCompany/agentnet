#!/usr/bin/env bash
# Experiment E6: retention policy behaviour on R1 (capacity and time) + store durability across container recreate.
# Policy runs at start and every 30 min (hardcoded), so we restart R1 to trigger it. Publishes go through R1's own REST.
set -u; . "$(dirname "$0")/common.sh"; cd "$(dirname "$0")/.."
enc() { python3 -I -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
CTR=/agentnet/1/spike-a1-retention/proto; CTRE=$(enc $CTR)
count() { curl -s "$R1/store/v3/messages?contentTopics=$CTRE&includeData=false&pageSize=100" | python3 -I -c "import json,sys;print(len(json.load(sys.stdin)['messages']))"; }
waitr1() { for i in $(seq 1 60); do curl -s -m 2 $R1/health >/dev/null && return; sleep 1; done; }
round() { # $1 policy $2 wait-before-restart-seconds
  echo "=== policy '$1'"; R1_RETENTION="$1" docker-compose up -d --force-recreate r1 >/dev/null 2>&1; waitr1; sleep 2
  req POST $R1/relay/v1/auto/subscriptions "[\"$CTR\"]" >/dev/null
  for i in $(seq 1 12); do pub $R1 $CTR "ret-$i" >/dev/null; sleep 0.2; done
  sleep 2; echo "stored right after publishing 12: $(count)"
  sleep "$2"
  echo "stored after ${2}s wait, no restart (policy only runs every 30min): $(count)"
  docker restart an-r1 >/dev/null; waitr1; sleep 2
  echo "stored after restart (policy executes at start): $(count)"
  docker logs an-r1 2>&1 | grep -i "retention\|Deleted\|pruned" | sed 's/^/  log: /'
}
round 'capacity:8' 0
round 'time:60' 70
echo "=== restore default policy"; docker-compose up -d --force-recreate r1 >/dev/null 2>&1; waitr1
