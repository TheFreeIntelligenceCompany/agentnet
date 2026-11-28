#!/usr/bin/env bash
# Burst-latency experiment on the local relay topology (spike/relay: an-r1, an-na, an-nb).
#
#   CACHE=50   RUNS=3 scripts/burst-bench.sh     # client nodes with --rest-relay-cache-capacity=50
#   CACHE=1000 RUNS=3 scripts/burst-bench.sh
# Env: CACHE (client relay cache capacity, default 50), RUNS (3), N (messages per direction, 100),
#      PACE_MS (25), HIST_S (daemon delivery.history_sync_interval_s, default: the daemon default 60), NOPROBE=1 (skip the 20 s live-relay probe before each run), COLD=1 (recreate an-na/an-nb before every run: measures a freshly started mesh), OUT (output dir, default results/fixups/burst-<cache>-<UTC>), TIMEOUT_S (600).
# Per run: fresh agents A (on NA) and B (on NB), two daemons, 100 messages each way concurrently via
# `agentnet-acceptance bench`, then the daemons' `metrics` (engine counters) are saved.
# Needs target/release/{agentnet,agentnet-acceptance}, docker-compose, jq, curl, python3.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT/spike/relay"
BIN="$ROOT/target/release/agentnet"
DRV="$ROOT/target/release/agentnet-acceptance"
CACHE="${CACHE:-50}"; RUNS="${RUNS:-3}"; N="${N:-100}"; PACE_MS="${PACE_MS:-25}"; TIMEOUT_S="${TIMEOUT_S:-600}"
OUT="${OUT:-$ROOT/results/fixups/burst-cache${CACHE}-$(date -u +%Y%m%dT%H%M%SZ)}"
NA=http://127.0.0.1:18641; NB=http://127.0.0.1:18642
R1_PEER_ID="$(grep '^R1_PEER_ID=' "$RELAY_DIR/.env" | cut -d= -f2)"
R1_MADDR="/ip4/172.28.66.10/tcp/60000/p2p/$R1_PEER_ID"
WORK="$(mktemp -d /tmp/an-burst.XXXXXX)"
mkdir -p "$OUT"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -TERM "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }
health() { [ "$(curl -s -m 4 -o /dev/null -w '%{http_code}' "$1/health")" = 200 ]; }
node_has_r1() { curl -s -m 4 "$1/admin/v1/peers" | jq -e 'any(.[]; .connected=="Connected")' >/dev/null; }
wait_for() { local end=$(( $(now_ms) + $1 * 1000 )); shift; while [ "$(now_ms)" -lt "$end" ]; do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }
cache_of() { docker inspect "$1" --format '{{join .Args " "}}' | tr ' ' '\n' | sed -n 's/^--rest-relay-cache-capacity=//p'; }

# A freshly (re)created client node does not always dial its --staticnode by itself (seen: disconnected for 12 min with no
# daemon). The agentnet adapter POSTs its static peer in that case, so do the same here.
dial_r1() { curl -s -m 10 -X POST -H 'content-type: application/json' -d "[\"$R1_MADDR\"]" "$1/admin/v1/peers" >/dev/null || true; }
recreate_clients() {
  ( cd "$RELAY_DIR" && CLIENT_CACHE="$CACHE" DNS_NS=127.0.0.1 docker-compose up -d --force-recreate na nb ) >> "$OUT/docker.log" 2>&1
  wait_for 180 health $NA && wait_for 180 health $NB || { log "client nodes not healthy"; exit 1; }
  for _ in $(seq 1 30); do
    node_has_r1 $NA && node_has_r1 $NB && return 0
    node_has_r1 $NA || dial_r1 $NA; node_has_r1 $NB || dial_r1 $NB; sleep 3
  done
  log "client nodes not connected to R1"; exit 1
}

# 1. client nodes with the requested cache capacity (recreating also clears stale peers/caches)
if [ "$(cache_of an-na)" != "$CACHE" ] || [ "$(cache_of an-nb)" != "$CACHE" ]; then
  log "recreating an-na/an-nb with --rest-relay-cache-capacity=$CACHE"
  recreate_clients
fi
wait_for 180 health $NA && wait_for 180 health $NB && wait_for 180 node_has_r1 $NA && wait_for 180 node_has_r1 $NB \
  || { log "client nodes not healthy"; exit 1; }
echo "cache capacity: na=$(cache_of an-na) nb=$(cache_of an-nb)" | tee "$OUT/nodes.txt" >&2

for run in $(seq 1 "$RUNS"); do
  R="$OUT/run$run"; mkdir -p "$R"
  [ "${COLD:-0}" = 1 ] && [ "$run" -gt 1 ] && recreate_clients
  # is live relay between the two client nodes working right now? (independent of AgentNet)
  if [ "${NOPROBE:-0}" = 1 ]; then echo null > "$R/live-probe-before.json"; else
    python3 "$ROOT/scripts/relay-live-probe.py" 20 > "$R/live-probe-before.json" 2>"$R/live-probe-before.stderr" || echo null > "$R/live-probe-before.json"; fi
  log "live relay probe before run $run: $(cat "$R/live-probe-before.json")"
  for x in a b; do
    url=$NA; [ $x = b ] && url=$NB
    "$BIN" --json --data-dir "$WORK/$x" init --node-url "$url" --peer "$R1_MADDR" > "$WORK/$x.init.json"
    jq -r .address "$WORK/$x.init.json" > "$WORK/$x.addr"
    if [ -n "${HIST_S:-}" ]; then
      if grep -q '^history_sync_interval_s *=' "$WORK/$x/agentnet.toml"; then
        sed -i.bak "s/^history_sync_interval_s *=.*/history_sync_interval_s = $HIST_S/" "$WORK/$x/agentnet.toml"
        rm -f "$WORK/$x/agentnet.toml.bak"
      elif grep -q '^\[delivery\]' "$WORK/$x/agentnet.toml"; then
        sed -i.bak "/^\[delivery\]/a\\
history_sync_interval_s = $HIST_S
" "$WORK/$x/agentnet.toml"
        rm -f "$WORK/$x/agentnet.toml.bak"
      else printf '\n[delivery]\nhistory_sync_interval_s = %s\n' "$HIST_S" >> "$WORK/$x/agentnet.toml"; fi
    fi
    "$BIN" --json --data-dir "$WORK/$x" identity show | jq -r .contact_record > "$WORK/$x.record"
    RUST_LOG=info "$BIN" --data-dir "$WORK/$x" serve >/dev/null 2>"$R/daemon-$x.log" &
    PIDS+=($!)
    echo $! > "$WORK/$x.pid"
  done
  for x in a b; do
    wait_for 120 bash -c '"$1" --json --data-dir "$2" network status | jq -e ".network.ready==true"' _ "$BIN" "$WORK/$x" || { log "daemon $x not ready"; exit 1; }
  done
  "$BIN" --data-dir "$WORK/a" contact add "@$WORK/b.record" --expect "$(cat "$WORK/b.addr")" --alias b >/dev/null
  "$BIN" --data-dir "$WORK/b" contact add "@$WORK/a.record" --expect "$(cat "$WORK/a.addr")" --alias a >/dev/null
  log "run $run: burst N=$N pace=${PACE_MS}ms cache=$CACHE"
  "$DRV" bench --a "$WORK/a" --b "$WORK/b" --a-addr "$(cat "$WORK/a.addr")" --b-addr "$(cat "$WORK/b.addr")" \
     --n "$N" --timeout "$TIMEOUT_S" --pace-ms "$PACE_MS" --out "$R/bench.json" > "$R/bench.stdout" 2> "$R/bench.stderr" || true
  for x in a b; do python3 "$ROOT/scripts/an-metrics.py" "$WORK/$x" metrics > "$R/metrics-$x.json" 2>/dev/null || true; done
  probe_json="$(jq -c . "$R/live-probe-before.json" 2>/dev/null || echo null)"
  jq -c --argjson run "$run" --argjson probe "$probe_json" \
    '{run:$run, probe:$probe, a_to_b:.a_to_b.latency_ms_send_to_delivered|{p50,p95,p99,max,samples}, b_to_a:.b_to_a.latency_ms_send_to_delivered|{p50,p95,p99,max,samples}}' \
    "$R/bench.json" | tee -a "$OUT/summary.jsonl" >&2
  for x in a b; do kill -TERM "$(cat "$WORK/$x.pid")" 2>/dev/null || true; done
  sleep 3
  for x in a b; do kill -KILL "$(cat "$WORK/$x.pid")" 2>/dev/null || true; done
  PIDS=()
  rm -rf "${WORK:?}/a" "${WORK:?}/b"
done
log "done: $OUT"
