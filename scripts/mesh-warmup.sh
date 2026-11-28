#!/usr/bin/env bash
# How long after (re)creating the two client nodes does LIVE relay between them start to work?
# (independent of AgentNet; uses scripts/relay-live-probe.py). Usage: mesh-warmup.sh [TRIALS=3]
# For each trial: recreate an-na/an-nb, wait until both are healthy and connected to R1 (the point at which
# `agentnet doctor` / `network status` call a node ready), then probe NA->NB every ~2 s (one frame, 2 s window)
# until one arrives. Prints one JSON line per trial: seconds from "connected to R1" to first live frame.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRIALS="${1:-3}"; NA=http://127.0.0.1:18641; NB=http://127.0.0.1:18642
now() { perl -MTime::HiRes=time -e 'printf "%.1f\n", time'; }
ok() { [ "$(curl -s -m 4 -o /dev/null -w '%{http_code}' "$1/health")" = 200 ] && curl -s -m 4 "$1/admin/v1/peers" | jq -e 'any(.[]; .connected=="Connected")' >/dev/null; }
for t in $(seq 1 "$TRIALS"); do
  ( cd "$ROOT/spike/relay" && DNS_NS=127.0.0.1 docker-compose up -d --force-recreate na nb ) >/dev/null 2>&1
  # A freshly started node does not always dial its --staticnode by itself (observed: still disconnected after 12 min with no
  # daemon running); the agentnet adapter fixes that by POSTing its static peer, so do the same, every 10 s, as the adapter does.
  R1_PEER_ID="$(grep '^R1_PEER_ID=' "$ROOT/spike/relay/.env" | cut -d= -f2)"
  n=0
  until ok $NA && ok $NB; do
    if [ "$n" -ge 360 ]; then
      echo "client nodes did not connect to R1 within 180 s" >&2
      exit 1
    fi
    if [ $((n % 20)) = 19 ]; then
      for u in $NA $NB; do ok $u || curl -s -m 10 -X POST -H 'content-type: application/json' \
        -d "[\"/ip4/172.28.66.10/tcp/60000/p2p/$R1_PEER_ID\"]" $u/admin/v1/peers >/dev/null || true; done
    fi
    n=$((n+1)); sleep 0.5
  done
  t0=$(now); first=null
  while :; do
    r=$(python3 "$ROOT/scripts/relay-live-probe.py" 2 "$NA" "$NB" 2>/dev/null || echo '{"na_to_nb_ms":null}')
    if [ "$(echo "$r" | jq .na_to_nb_ms 2>/dev/null || echo null)" != null ]; then first=$(perl -e "printf '%.1f', $(now) - $t0"); break; fi
    [ "$(perl -e "print $(now) - $t0 > 300 ? 1 : 0")" = 1 ] && break
  done
  echo "{\"trial\":$t,\"seconds_from_connected_to_first_live_frame\":$first}"
done
