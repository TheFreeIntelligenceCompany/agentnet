#!/usr/bin/env bash
# AgentNet automated acceptance demonstration (goal.md section 5, items 1-6, plus extras).
#
#   scripts/acceptance.sh                 # whole run, results in results/acceptance/<UTC timestamp>/
#   STEPS="1 2" scripts/acceptance.sh     # subset (step 1 is always run: it creates the agents)
#   FRESH_TOPOLOGY=1 scripts/acceptance.sh   # docker-compose down -v + up first (wipes R1's store)
#   SKIP_BUILD=1 ...                      # reuse target/release binaries
#
# WHAT THIS IS: a single-host test. The relay and both client nodes are amd64 containers (qemu on an
# arm64 Mac) on one docker bridge (172.28.66.0/24); the AgentNet processes run on the host and talk to the
# nodes' REST ports on 127.0.0.1. It is NOT a cross-machine / NAT / Tailscale test.
#
# Needs: docker + standalone docker-compose, colima VM (tcpdump runs in the VM netns through the
# nicolaka/netshoot image), cargo, jq, curl, python3, openssl, lsof, perl. The relay topology of
# spike/relay must be startable (done here if it is not already healthy). Only containers an-r1, an-na,
# an-nb and an-acc-cap are touched; nothing else on the docker host.
#
# Exit status: 0 when no check FAILed, 1 otherwise (UNTESTED does not fail the run, it is reported).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT/spike/relay"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="${RESULTS_DIR:-$ROOT/results/acceptance/$TS}"
WORK="$(mktemp -d /tmp/an-acc.XXXXXX)"      # short path: unix socket paths are limited to ~100 bytes
BIN="$ROOT/target/release/agentnet"
DRV="$ROOT/target/release/agentnet-acceptance"
HARNESS="$ROOT/target/release/examples/mock_harness"
EMBED="$ROOT/target/release/examples/embed"
STEPS="${STEPS:-1 2 3 4 5 6 X}"
export DNS_NS=127.0.0.1                     # never let compose fall back to the 1.1.1.1 default (E7)
unset AGENTNET_HOME RUST_LOG R1_RETENTION || true

R1=http://127.0.0.1:18640
NA=http://127.0.0.1:18641
NB=http://127.0.0.1:18642
R1_PEER_ID="$(grep '^R1_PEER_ID=' "$RELAY_DIR/.env" | cut -d= -f2)"
R2_PEER_ID="$(grep '^R2_PEER_ID=' "$RELAY_DIR/.env" | cut -d= -f2)"
R1_MADDR="/ip4/172.28.66.10/tcp/60000/p2p/$R1_PEER_ID"
BRIDGE_NET=agentnet-relay_relaynet
CAP=an-acc-cap

mkdir -p "$RES"/{logs,evidence,daemon-logs,pcap,net} "$WORK/pids"
: > "$RES/checks.jsonl"; : > "$RES/notes.txt"; : > "$RES/run.log"
RC=0; OUT=""; ERR=""
R1_SHORT=0

# ------------------------------------------------------------------ helpers
now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }
now_ns() { perl -MTime::HiRes=time -e 'printf "%.0f\n", time*1e9'; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RES/run.log" >&2; }
note() { printf '%s\t%s\n' "$1" "$2" >> "$RES/notes.txt"; }

# check ID STATUS DETAIL [COMMAND] [optional]
check() {
  jq -nc --arg id "$1" --arg s "$2" --arg d "$3" --arg c "${4:-}" --arg o "${5:-false}" --arg t "$(date -u +%FT%TZ)" \
    '{id:$id,status:$s,detail:$d,command:$c,optional:($o=="true"),at:$t}' >> "$RES/checks.jsonl"
  log "CHECK $1 $2 - $3"
}
pass() { check "$1" PASS "$2" "${3:-}" "${4:-false}"; }
fail() { check "$1" FAIL "$2" "${3:-}" "${4:-false}"; }
untested() { check "$1" UNTESTED "$2" "${3:-}" "${4:-false}"; }
# verdict ID "detail" COMMAND <test command...>: PASS if the command succeeds, else FAIL
verdict() { local id=$1 d=$2 c=$3; shift 3; if "$@"; then pass "$id" "$d" "$c"; else fail "$id" "$d" "$c"; fi; }

# q LOGNAME cmd... : run, capture stdout in $OUT, stderr in $ERR, exit code in $RC; everything appended to logs/LOGNAME.log
q() {
  local lf="$RES/logs/$1.log"; shift
  printf '$ %s\n' "$*" >> "$lf"
  OUT="$("$@" 2>"$WORK/q.err")" && RC=0 || RC=$?
  ERR="$(cat "$WORK/q.err")"
  printf '%s\n' "$OUT" >> "$lf"
  [ -z "$ERR" ] || printf '[stderr] %s\n' "$ERR" >> "$lf"
  printf '[exit %d]\n' "$RC" >> "$lf"
  return 0
}
an() { local d=$1; shift; "$BIN" --data-dir "$WORK/$d" "$@"; }
anj() { local d=$1; shift; "$BIN" --json --data-dir "$WORK/$d" "$@"; }
addr_of() { cat "$WORK/$1.addr"; }

wait_for() { # secs desc cmd...  -> 0/1; sets WAITED_MS
  local secs=$1 desc=$2; shift 2
  local t0 end; t0=$(now_ms); end=$((t0 + secs * 1000))
  while [ "$(now_ms)" -lt "$end" ]; do
    if "$@" >/dev/null 2>&1; then WAITED_MS=$(( $(now_ms) - t0 )); return 0; fi
    sleep 0.5
  done
  WAITED_MS=$(( $(now_ms) - t0 )); log "timeout after ${secs}s waiting for: $desc"; return 1
}

health() { [ "$(curl -s -m 4 -o /dev/null -w '%{http_code}' "$1/health")" = 200 ]; }
node_only_r1() { curl -s -m 4 "$1/admin/v1/peers" | jq -e --arg id "$R1_PEER_ID" 'length==1 and (.[0].multiaddr|endswith($id))' >/dev/null; }
node_has_r1() { curl -s -m 4 "$1/admin/v1/peers" | jq -e --arg id "$R1_PEER_ID" 'any(.[]; (.multiaddr|endswith($id)) and .connected=="Connected")' >/dev/null; }

redact() { sed -E 's/[0-9a-fA-F]{64}/<redacted-64hex>/g'; }
save_daemon_log() { # name
  [ -f "$WORK/$1.stderr" ] && redact < "$WORK/$1.stderr" > "$RES/daemon-logs/$1.log" || true
}

# ------------------------------------------------------------------ agents and daemons
set_toml() { # file section key value-literal
  python3 -I - "$@" <<'PY'
import re, sys
f, sec, key, val = sys.argv[1:5]
out, cur, done = [], None, False
for l in open(f).read().split('\n'):
    m = re.match(r'\s*\[(.+)\]\s*$', l)
    if m: cur = m.group(1)
    if cur == sec and not done and re.match(r'\s*' + re.escape(key) + r'\s*=', l):
        l = f'{key} = {val}'; done = True
    out.append(l)
if not done: sys.exit(f'key not found: [{sec}] {key}')
open(f, 'w').write('\n'.join(out))
PY
}

# new_agent NAME NODE_URL [PEER_MADDR]: init with a fresh identity whose inbox bucket does not collide with an
# agent on the same node (two daemons polling one content topic on one node would steal each other's messages).
new_agent() {
  local n=$1 url=$2 peer=${3:-$R1_MADDR} try topic other collide f
  for try in $(seq 1 60); do
    rm -rf "${WORK:?}/$n"
    "$BIN" --json --data-dir "$WORK/$n" init --node-url "$url" --peer "$peer" > "$WORK/$n.init.json" 2>"$WORK/$n.init.err" || { cat "$WORK/$n.init.err" >&2; return 1; }
    topic="$(anj "$n" identity show | jq -r .inbox_topic)"
    collide=0
    for f in "$WORK"/*.node; do
      [ -e "$f" ] || continue
      other="$(basename "$f" .node)"
      [ "$other" = "$n" ] && continue
      if [ "$(cat "$f")" = "$url" ] && [ "$(cat "$WORK/$other.topic")" = "$topic" ]; then collide=1; fi
    done
    [ $collide = 0 ] && break
  done
  [ $collide = 0 ] || { log "could not find a non-colliding inbox bucket for $n"; return 1; }
  echo "$topic" > "$WORK/$n.topic"; echo "$url" > "$WORK/$n.node"
  jq -r .address "$WORK/$n.init.json" > "$WORK/$n.addr"
  anj "$n" identity show | jq -r .contact_record > "$WORK/$n.record"
  log "agent $n: $(addr_of "$n") node=$url topic=$topic (init attempts: $try)"
}

net_ready() { anj "$1" network status 2>/dev/null | jq -e '.network.ready==true' >/dev/null; }

# start_daemon NAME [nowait]; sets STARTUP_MS (spawn -> network.ready)
start_daemon() {
  local n=$1 t0; t0=$(now_ms)
  RUST_LOG=info "$BIN" --data-dir "$WORK/$n" serve >/dev/null 2>>"$WORK/$n.stderr" &
  echo $! > "$WORK/pids/$n"; echo "$t0" > "$WORK/$n.t0"
  if [ "${2:-}" = nowait ]; then STARTUP_MS=-1; return 0; fi
  if wait_for 300 "daemon $n ready" net_ready "$n"; then
    STARTUP_MS=$(( $(now_ms) - t0 )); printf '%s\t%s\t%s\n' "$n" "$(date -u +%FT%TZ)" "$STARTUP_MS" >> "$RES/evidence/startup-times.tsv"; return 0
  fi
  STARTUP_MS=-1; return 1
}
ready_wait() { # name [secs]: wait for ready after a nowait start and record time-to-ready since spawn
  local n=$1
  if wait_for "${2:-300}" "daemon $n ready" net_ready "$n"; then
    STARTUP_MS=$(( $(now_ms) - $(cat "$WORK/$n.t0") )); printf '%s\t%s\t%s\n' "$n" "$(date -u +%FT%TZ)" "$STARTUP_MS" >> "$RES/evidence/startup-times.tsv"; return 0
  fi
  return 1
}
daemon_pid() { cat "$WORK/pids/$1" 2>/dev/null || true; }
stop_daemon() { # name; sets SHUTDOWN_MS
  local n=$1 pid t0 i; pid="$(daemon_pid "$n")"; SHUTDOWN_MS=-1
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    t0=$(now_ms); kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 400); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then log "daemon $n did not exit in 40 s, SIGKILL"; kill -KILL "$pid" 2>/dev/null || true; fi
    SHUTDOWN_MS=$(( $(now_ms) - t0 ))
    printf '%s\t%s\t%s\n' "$n" "$(date -u +%FT%TZ)" "$SHUTDOWN_MS" >> "$RES/evidence/shutdown-times.tsv"
  fi
  rm -f "$WORK/pids/$n"; save_daemon_log "$n"
}
daemon_alive() { local p; p="$(daemon_pid "$1")"; [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }

contact_exchange() { # X Y: X learns Y (verified against Y's address out of band)
  q "contacts" "$BIN" --json --data-dir "$WORK/$1" contact add "@$WORK/$2.record" --expect "$(addr_of "$2")" --alias "$2"
  [ "$RC" = 0 ]
}

send() { # from to body [extra args...] -> prints message id
  local f=$1 t=$2 b=$3; shift 3
  anj "$f" send "$(addr_of "$t")" "$b" "$@" | jq -r .message_id
}
mstate() { anj "$1" status "$2" 2>/dev/null | jq -r .state; }
all_in_state() { # dir state ids...
  local d=$1 s=$2 id; shift 2
  for id in "$@"; do [ "$(mstate "$d" "$id")" = "$s" ] || return 1; done
}
count_states() { # dir ids... -> "delivered=3 sent=1"
  local d=$1 id; shift
  for id in "$@"; do mstate "$d" "$id"; done | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}'
}
inbox_count() { # dir conversation
  anj "$1" inbox --conversation "$2" --limit 200 | jq '.records|length'
}
state_is() { [ "$(mstate "$1" "$2")" = "$3" ]; }
inbox_is() { [ "$(inbox_count "$1" "$2")" = "$3" ]; }
lines_ge() { [ -f "$1" ] && [ "$(wc -l < "$1" | tr -d ' ')" -ge "$2" ]; }
quar_has() { [ "$(anj "$1" quarantine list | jq --arg m "$2" '[.records[]|select(.message_id==$m)]|length')" = 1 ]; }
inbox_any_q() { [ "$(anj "$1" inbox --include-quarantined --conversation "$2" --limit 50 | jq '.records|length')" -ge 1 ]; }
mcp() { # dir tool [args-json]
  "$DRV" mcp-call --bin "$BIN" --data-dir "$WORK/$1" --tool "$2" --args "${3:-{\}}"
}

# ------------------------------------------------------------------ docker / topology
dc() { ( cd "$RELAY_DIR" && DNS_NS=127.0.0.1 docker-compose "$@" ); }
topology_ok() {
  health "$R1" && health "$NA" && health "$NB" && node_has_r1 "$NA" && node_has_r1 "$NB"
}
# A client node that knows a peer other than R1 (left over from the isolation test of a previous run, which makes the adapter
# POST a wrong static peer to the node) would make 'doctor' fail its peers==allowlist check. node peers are not persisted
# (--peer-persistence=false), so restarting the client node clears it.
clean_client_nodes() {
  local c u
  for c in "an-na $NA" "an-nb $NB"; do
    set -- $c
    if health "$2" && ! node_only_r1 "$2"; then
      log "node $1 knows peers other than R1 (stale entry from an earlier isolation test): restarting it"
      docker restart "$1" >> "$RES/logs/docker.log" 2>&1; wait_for 120 "$1 health" health "$2"; wait_for 120 "$1 connected to R1" node_has_r1 "$2"
    fi
  done
}
ensure_topology() {
  if [ "${FRESH_TOPOLOGY:-0}" = 1 ]; then
    log "FRESH_TOPOLOGY=1: docker-compose down -v, up.sh"
    dc down -v >/dev/null 2>&1 || true
    ( cd "$RELAY_DIR" && DNS_NS=127.0.0.1 ./scripts/up.sh ) > "$RES/logs/topology-up.log" 2>&1 || true
  fi
  clean_client_nodes
  if ! topology_ok; then
    log "topology not healthy, running up.sh"
    ( cd "$RELAY_DIR" && DNS_NS=127.0.0.1 ./scripts/up.sh ) >> "$RES/logs/topology-up.log" 2>&1 || true
    wait_for 240 "topology healthy" topology_ok || return 1
  fi
}
r1_recreate() { # [retention]  (empty = compose default)
  if [ -n "${1:-}" ]; then R1_SHORT=1; ( cd "$RELAY_DIR" && R1_RETENTION="$1" DNS_NS=127.0.0.1 docker-compose up -d --force-recreate r1 ) >> "$RES/logs/docker.log" 2>&1
  else R1_SHORT=0; ( cd "$RELAY_DIR" && unset R1_RETENTION; DNS_NS=127.0.0.1 docker-compose up -d --force-recreate r1 ) >> "$RES/logs/docker.log" 2>&1; fi
  wait_for 120 "R1 health" health "$R1"
}
node_stop() { docker stop "$1" >> "$RES/logs/docker.log" 2>&1; }
node_start() { # container url
  docker start "$1" >> "$RES/logs/docker.log" 2>&1; wait_for 120 "$1 health" health "$2"
}
r1_store_count() { # topic start_ns
  store_q "$1" "${2:-1}" | jq '.messages|length' 2>/dev/null || echo -1
}
store_q() { # topic start_ns
  local ct; ct="$(jq -rn --arg t "$1" '$t|@uri')"
  curl -s -m 20 "$R1/store/v3/messages?contentTopics=$ct&includeData=true&pageSize=100&ascending=true&startTime=${2:-1}"
}
# republish node_url topic start_ns times: re-publish every stored frame of the topic with a fresh timestamp
republish() {
  local url=$1 topic=$2 start=$3 times=$4 i p ok=0 bad=0 code json
  json="$(store_q "$topic" "$start")"
  for i in $(seq 1 "$times"); do
    while read -r p; do
      [ -n "$p" ] || continue
      code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
        -d "{\"payload\":\"$p\",\"contentTopic\":\"$topic\",\"timestamp\":$(now_ns)}" "$url/relay/v1/auto/messages") || code=000
      if [ "$code" = 200 ]; then ok=$((ok+1)); else bad=$((bad+1)); fi
      sleep 0.05
    done < <(printf '%s' "$json" | jq -r '.messages[]?|.message.payload')
  done
  REPUB_OK=$ok; REPUB_BAD=$bad
  echo "republished frames via $url: ok=$ok failed=$bad" >> "$RES/logs/republish.log"
}

# ------------------------------------------------------------------ cleanup / summary
cleanup() {
  local rc=$? n capd
  set +e +u
  log "cleanup (exit status of script body: $rc)"
  for n in $(ls "$WORK/pids" 2>/dev/null); do stop_daemon "$n"; done
  [ -f "$WORK/harness.pid" ] && kill "$(cat "$WORK/harness.pid")" 2>/dev/null
  [ -f "$WORK/sampler.pid" ] && kill "$(cat "$WORK/sampler.pid")" 2>/dev/null
  docker rm -f "$CAP" >/dev/null 2>&1
  # tcpdump runs as root in the container: if the host cannot remove its files, remove them from inside a container
  capd="$ROOT/results/acceptance/.cap.$$"
  if [ -d "$capd" ]; then
    rm -rf "$capd" 2>/dev/null
    [ -d "$capd" ] && docker run --rm -v "$capd":/out nicolaka/netshoot sh -c 'rm -rf /out/* /out/.[!.]*' >/dev/null 2>&1
    [ -d "$capd" ] && rm -rf "$capd" 2>/dev/null
    [ -d "$capd" ] && log "WARNING: could not remove $capd"
  fi
  for n in "$WORK"/*.stderr; do [ -e "$n" ] && save_daemon_log "$(basename "$n" .stderr)"; done
  # leave the topology healthy, normal retention, R1 first
  if [ "$R1_SHORT" = 1 ] || ! docker ps --format '{{.Names}}' | grep -qx an-r1; then r1_recreate ""; fi
  docker ps --format '{{.Names}}' | grep -qx an-nb || node_start an-nb "$NB"
  docker ps --format '{{.Names}}' | grep -qx an-na || node_start an-na "$NA"
  for n in 1 2 3; do topology_ok && break; ( cd "$RELAY_DIR" && DNS_NS=127.0.0.1 ./scripts/up.sh ) >> "$RES/logs/topology-up.log" 2>&1; done
  if topology_ok; then log "topology healthy at exit"; else log "WARNING: topology NOT healthy at exit"; fi
  topology_ok && echo healthy > "$RES/evidence/topology-at-exit.txt" || echo UNHEALTHY > "$RES/evidence/topology-at-exit.txt"
  write_summary
  rm -rf "$WORK"
  if jq -e -s 'any(.[]; .status=="FAIL")' "$RES/checks.jsonl" >/dev/null 2>&1; then exit 1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'log "interrupted"; exit 130' INT TERM

step_title() {
  case $1 in
    1) echo "Relay/service node, two independent instances, identities, verified contacts";;
    2) echo "MCP send_message, subscription notification, authenticated receipt";;
    3) echo "Recipient offline: Store recovery, no duplicates, failure cases";;
    4) echo "Authorized one-shot trigger, mock harness, unauthorized senders";;
    5) echo "Private network: egress, relay failure without fallback, isolation, Tailscale";;
    6) echo "Generic MCP client configuration and Rust embedding";;
    X) echo "Extras (not part of goal.md section 5)";;
  esac
}

write_summary() {
  local f="$RES/summary.json" md="$RES/SUMMARY.md" s
  local env_json
  env_json="$(jq -nc --arg host "$(uname -srm)" --arg git "$(cd "$ROOT" && git rev-parse --short HEAD 2>/dev/null || echo none)" \
    --arg rust "$(rustc --version 2>/dev/null || true)" --arg img "wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73 (v0.39.2, linux/amd64 under qemu)" \
    '{host:$host, git:$git, rustc:$rust, node_image:$img, topology:"single host, docker bridge 172.28.66.0/24, R1 + NA + NB containers, agents on the host via 127.0.0.1 REST ports",
      scope:"SINGLE-HOST DOCKER-BRIDGE TEST (amd64 node image under qemu on an arm64 Mac). NOT a cross-machine / NAT / Tailscale test."}')"
  jq -s --argjson env "$env_json" --arg ts "$TS" --arg steps "$STEPS" '
    def worst(c): if any(c[]; .status=="FAIL") then "FAIL"
                  elif (c|length)==0 then "UNTESTED"
                  elif all(c[]; .status=="UNTESTED") then "UNTESTED"
                  else "PASS" end;
    . as $all
    | ($all | map(select(.optional|not))) as $core
    | {run_timestamp:$ts, environment:$env, steps_requested:($steps|split(" ")),
       steps: ([$all[]|.id|split(".")[0]] | unique | map(. as $s |
          {step:$s, status: (([$core[]|select((.id|split(".")[0])==$s)]) as $c | if ($c|length)==0 then worst([$all[]|select((.id|split(".")[0])==$s)]) else worst($c) end),
           checks: [$all[]|select((.id|split(".")[0])==$s)]})),
       totals: {PASS:([$all[]|select(.status=="PASS")]|length), FAIL:([$all[]|select(.status=="FAIL")]|length), UNTESTED:([$all[]|select(.status=="UNTESTED")]|length)}}
  ' "$RES/checks.jsonl" > "$f" 2>/dev/null || echo '{"error":"summary generation failed"}' > "$f"
  {
    echo "# AgentNet acceptance run $TS"
    echo
    echo "> **Scope: single-host docker-bridge test** (amd64 Logos Delivery node image under qemu on an arm64 Mac;"
    echo "> relay and both client nodes on one docker bridge, 172.28.66.0/24; agents on the host). It is **NOT** a"
    echo "> cross-machine, NAT or Tailscale test. Same statement applies to every number below."
    echo
    echo "Environment: $(jq -r '.environment|"\(.host); git \(.git); \(.rustc)"' "$f" 2>/dev/null)"
    echo
    echo "Totals: $(jq -r '.totals|"PASS \(.PASS), FAIL \(.FAIL), UNTESTED \(.UNTESTED)"' "$f" 2>/dev/null)"
    echo
    echo "| Step | Status | Title |"
    echo "|---|---|---|"
    for s in $(jq -r '.steps[].step' "$f" 2>/dev/null); do
      echo "| $s | $(jq -r --arg s "$s" '.steps[]|select(.step==$s)|.status' "$f") | $(step_title "$s") |"
    done
    for s in $(jq -r '.steps[].step' "$f" 2>/dev/null); do
      echo
      echo "## Step $s: $(step_title "$s")"
      echo
      echo "| Check | Status | Detail |"
      echo "|---|---|---|"
      jq -r --arg s "$s" '.steps[]|select(.step==$s)|.checks[]|"| \(.id)\(if .optional then " (optional)" else "" end) | \(.status) | \(.detail|gsub("\\|";"/")|gsub("\n";" ")) |"' "$f"
      echo
      echo "Exact commands (binary paths shortened; data dirs are /tmp/an-acc.XXXXXX/<agent>):"
      echo
      echo '```'
      jq -r --arg s "$s" '.steps[]|select(.step==$s)|.checks[]|select(.command!="")|"# \(.id)\n\(.command)"' "$f"
      echo '```'
      if grep -q "^$s[.]" "$RES/notes.txt" 2>/dev/null; then
        echo
        grep "^$s[.]" "$RES/notes.txt" | while IFS=$'\t' read -r id text; do
          echo "**Note ($id).** $(printf '%b' "$text")"
          echo
        done
      fi
    done
    echo
    echo "## Evidence index"
    echo
    echo "- \`summary.json\` (machine readable), \`checks.jsonl\`, \`run.log\`"
    echo "- \`logs/\` per-step command logs, \`evidence/\` JSON evidence, \`daemon-logs/\` redacted daemon stderr (64-hex strings replaced), \`pcap/\` + \`net/\` packet captures and summaries"
    echo "- startup/shutdown times: \`evidence/startup-times.tsv\`, \`evidence/shutdown-times.tsv\`"
  } > "$md"
}

# ------------------------------------------------------------------ prerequisites + build
for t in docker docker-compose jq curl python3 openssl lsof perl cargo; do
  command -v "$t" >/dev/null || { echo "missing prerequisite: $t" >&2; exit 2; }
done
log "results: $RES   work dir: $WORK"
log "SCOPE: single-host docker-bridge test, amd64 node image under qemu on arm64 Mac. NOT cross-machine/NAT."
if [ "${SKIP_BUILD:-0}" != 1 ]; then
  log "building release binaries"
  ( cd "$ROOT" && cargo build --release -p agentnet-cli -p agentnet-acceptance && cargo build --release -p agentnet-daemon --examples ) > "$RES/logs/build.log" 2>&1 \
    || { log "BUILD FAILED, see logs/build.log"; fail "1.build" "release build failed" "cargo build --release -p agentnet-cli -p agentnet-acceptance"; exit 1; }
fi
for f in "$BIN" "$DRV" "$HARNESS" "$EMBED"; do [ -x "$f" ] || { log "missing $f"; exit 2; }; done
"$BIN" --version > "$RES/evidence/versions.txt" 2>&1 || true
{ rustc --version; cargo --version; docker --version; docker-compose --version; uname -a; jq --version; } >> "$RES/evidence/versions.txt" 2>&1 || true
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' >> "$RES/evidence/versions.txt" 2>&1 || true

# ================================================================== STEP 1
step1() {
  log "=== STEP 1: relay + two instances, identities, contacts"
  if ensure_topology; then
    pass "1.topology" "R1 (an-r1), NA (an-na), NB (an-nb) healthy; NA and NB connected to R1 only; compose project agentnet-relay, DNS_NS=127.0.0.1" \
      "cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh   # R1 first, then na+nb"
  else fail "1.topology" "relay topology could not be brought up" "cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh"; return 1; fi
  docker ps --format '{{.Names}} {{.Image}} {{.Status}}' > "$RES/evidence/containers-start.txt"
  curl -s "$R1/info" > "$RES/evidence/r1-info.json"
  curl -s "$NA/admin/v1/peers" > "$RES/evidence/na-peers-start.json"; curl -s "$NB/admin/v1/peers" > "$RES/evidence/nb-peers-start.json"

  new_agent a "$NA"; new_agent b "$NB"
  set_toml "$WORK/b/agentnet.toml" policy auto_trigger true
  set_toml "$WORK/b/agentnet.toml" triggers allowed_sessions '["demo-session"]'
  grep -E 'mode|node_url|peers|cluster_id|public_|auto_trigger|allowed_sessions' "$WORK/a/agentnet.toml" > "$RES/evidence/config-a-excerpt.toml"
  grep -E 'mode|node_url|peers|cluster_id|public_|auto_trigger|allowed_sessions' "$WORK/b/agentnet.toml" > "$RES/evidence/config-b-excerpt.toml"
  start_daemon a nowait; start_daemon b nowait
  local ok=1
  ready_wait a || ok=0
  ready_wait b || ok=0
  if [ $ok = 1 ]; then
    pass "1.serve" "two release-mode 'agentnet serve' processes (A -> NA $NA, B -> NB $NB), private mode, static peer R1, cluster 66; A=$(addr_of a) B=$(addr_of b)" \
      "agentnet --data-dir \$A init --node-url $NA --peer $R1_MADDR; agentnet --data-dir \$B init --node-url $NB --peer $R1_MADDR; agentnet --data-dir \$X serve"
  else fail "1.serve" "a daemon did not become ready" "agentnet serve"; return 1; fi

  # contacts with --expect
  local okc=1
  contact_exchange a b || okc=0
  contact_exchange b a || okc=0
  anj a contact list > "$RES/evidence/contacts-a.json"; anj b contact list > "$RES/evidence/contacts-b.json"
  if [ $okc = 1 ]; then pass "1.contacts" "contact records exchanged with 'contact add @record --expect <address>' in both directions" \
      "agentnet --data-dir \$A contact add @b.record --expect $(addr_of b); agentnet --data-dir \$B contact add @a.record --expect $(addr_of a)"
  else fail "1.contacts" "contact add failed: $ERR" "agentnet contact add"; fi

  # doctor and network status
  local d
  for d in a b; do
    q "step1-doctor-$d" "$BIN" --data-dir "$WORK/$d" doctor
    if [ "$RC" = 0 ]; then pass "1.doctor.$d" "agentnet doctor exit 0 (see logs/step1-doctor-$d.log)" "agentnet --data-dir \$$(echo $d | tr a-z A-Z) doctor"
    else fail "1.doctor.$d" "agentnet doctor exit $RC (see logs/step1-doctor-$d.log)" "agentnet --data-dir \$X doctor"; fi
    q "step1-netstatus-$d" "$BIN" --data-dir "$WORK/$d" network status --verbose
    q "step1-netstatus-$d" "$BIN" --json --data-dir "$WORK/$d" network status --verbose
    printf '%s\n' "$OUT" > "$RES/evidence/network-status-$d.json"
    if printf '%s' "$OUT" | jq -e --arg id "$R1_PEER_ID" '.network.ready==true and .network.mode=="private" and (.network.isolation_violation==null) and ((.network.peers//[])|length==1) and ((.network.peers//[])[0]|contains($id))' >/dev/null; then
      pass "1.netstatus.$d" "network status --verbose: private, ready, no isolation violation, exactly one peer = R1 ($R1_PEER_ID)" "agentnet --json --data-dir \$X network status --verbose"
    else fail "1.netstatus.$d" "unexpected network status: $(printf '%s' "$OUT" | jq -c .network 2>/dev/null)" "agentnet network status --verbose"; fi
  done

  # negative: tampered record
  python3 -I - "$WORK/b.record" > "$WORK/b.tampered" <<'PY'
import sys
t = open(sys.argv[1]).read().strip()      # base64url of the binary OpenPGP certificate
i = len(t) // 2
print(t[:i] + ("B" if t[i] == "A" else "A") + t[i + 1:])   # one flipped character: the self-signature or packet no longer verifies
PY
  local before after
  before="$(anj a contact list | jq -c '[.[]|.address]|sort')"
  q "step1-negative" "$BIN" --json --data-dir "$WORK/a" contact add "@$WORK/b.tampered" --expect "$(addr_of b)" --alias tampered
  after="$(anj a contact list | jq -c '[.[]|.address]|sort')"
  printf '{"exit":%s,"stdout":%s,"stderr":%s}\n' "$RC" "$(printf '%s' "$OUT" | jq -Rs .)" "$(printf '%s' "$ERR" | jq -Rs .)" > "$RES/evidence/negative-tampered-record.json"
  if [ "$RC" != 0 ] && [ "$before" = "$after" ]; then pass "1.neg.tamper" "tampered contact record rejected, exit $RC: $ERR; contact list unchanged" "agentnet contact add @tampered.json --expect <B>"
  else fail "1.neg.tamper" "tampered record NOT rejected (exit $RC) or contacts changed" "agentnet contact add @tampered.json --expect <B>"; fi
  q "step1-negative" "$BIN" --json --data-dir "$WORK/a" contact add "@$WORK/b.record" --expect "$(addr_of a)" --alias wrong
  printf '{"exit":%s,"stdout":%s,"stderr":%s}\n' "$RC" "$(printf '%s' "$OUT" | jq -Rs .)" "$(printf '%s' "$ERR" | jq -Rs .)" > "$RES/evidence/negative-wrong-expect.json"
  after="$(anj a contact list | jq -c '[.[]|.address]|sort')"
  if [ "$RC" != 0 ] && [ "$before" = "$after" ]; then pass "1.neg.expect" "genuine record presented with the wrong --expect address rejected, exit $RC: $ERR; contact list unchanged" "agentnet contact add @b.record --expect <A's address>"
  else fail "1.neg.expect" "wrong --expect NOT rejected (exit $RC)" "agentnet contact add @b.record --expect <wrong>"; fi
}

# ================================================================== STEP 2
step2() {
  log "=== STEP 2: MCP send / subscription / receipt"
  local t0ns r
  t0ns=$(now_ns)
  q step2 "$DRV" step2 --bin "$BIN" --a "$WORK/a" --b "$WORK/b" --b-addr "$(addr_of b)" --out "$RES/evidence/step2-mcp.json"
  local cmd="agentnet-acceptance step2 --a \$A --b \$B --b-addr $(addr_of b)   # rmcp client over 'agentnet mcp' stdio: get_identity, B subscriptions/listen agentnet://inbox, A send_message, B read_inbox, A get_message_status"
  if [ "$RC" != 0 ]; then fail "2.mcp" "step2 driver failed: $(printf '%s' "$OUT" | jq -r .error 2>/dev/null)" "$cmd"; return 1; fi
  r="$RES/evidence/step2-mcp.json"
  local pv; pv="$(jq -r '"A: \(.protocol_client_A.negotiated_protocol_version), B: \(.protocol_client_B.negotiated_protocol_version)"' "$r")"
  pass "2.send" "send_message via MCP returned message_id $(jq -r .message_id "$r") in $(jq -r .latency_ms.send_message_returned "$r") ms; negotiated protocol $pv" "$cmd"
  pass "2.notify" "B's subscriptions/listen on agentnet://inbox received a notification $(jq -r .latency_ms.B_resource_notification "$r") ms after send: $(jq -r .notification "$r" | cut -c1-200)" "$cmd"
  pass "2.inbox" "B read_inbox shows the message; sender authenticated as A ($(jq -r .a_addr "$r")); body matches; read at +$(jq -r .latency_ms.B_read_inbox_returned "$r") ms" "$cmd"
  pass "2.delivered" "A get_message_status timeline: $(jq -c '[.A_status_timeline[]|{state,t_ms}]' "$r"); authenticated receipt (delivered) at +$(jq -r .latency_ms.A_status_delivered "$r") ms" "$cmd"
  # what did the relay see?
  sleep 3
  local mid marker topic start_ns btopic atopic
  mid="$(jq -r .message_id "$r")"; marker="$(jq -r .body_marker "$r")"
  btopic="$(cat "$WORK/b.topic")"; atopic="$(cat "$WORK/a.topic")"
  start_ns=$(( $(jq -r .send_wall_clock_ms "$r") * 1000000 - 5000000000 ))
  store_q "$btopic" "$start_ns" > "$RES/evidence/r1-store-b-topic.json"
  store_q "$atopic" "$start_ns" > "$RES/evidence/r1-store-a-topic.json"
  python3 -I - "$RES/evidence/r1-store-b-topic.json" "$RES/evidence/r1-store-a-topic.json" "$marker" "$mid" "$(addr_of a)" "$(addr_of b)" > "$RES/evidence/r1-relay-view.json" <<'PY'
import json, sys, base64
fb, fa, marker, mid, addr_a, addr_b = sys.argv[1:7]
out = {"what_R1_stored": [], "plaintext_leak_check": {}}
leak = False
for label, f in (("B inbox topic (the message)", fb), ("A inbox topic (the ack)", fa)):
    d = json.load(open(f))
    for m in d.get("messages", []):
        msg = m["message"]; raw = base64.b64decode(msg["payload"])
        hits = {"marker": marker.encode() in raw, "message_id": mid.encode() in raw, "sender_addr": addr_a.encode() in raw, "recipient_addr": addr_b.encode() in raw, "plaintext_word_ACCEPTANCE": b"ACCEPTANCE" in raw}
        leak = leak or any(hits.values())
        out["what_R1_stored"].append({"which": label, "messageHash": m["messageHash"], "contentTopic": msg["contentTopic"],
            "pubsubTopic": m.get("pubsubTopic"), "payload_bytes": len(raw), "timestamp_ns": msg["timestamp"],
            "frame_header_hex": raw[:8].hex(), "plaintext_found_in_payload": hits})
out["plaintext_leak_check"] = {"leak_detected": leak, "marker": marker,
    "note": "R1 sees: content topic (shared inbox bucket), time, padded payload length, hash, publisher peer. It does not see sender, recipient address, message id, type or body."}
print(json.dumps(out, indent=1))
PY
  local n leak
  n="$(jq '.what_R1_stored|length' "$RES/evidence/r1-relay-view.json")"; leak="$(jq .plaintext_leak_check.leak_detected "$RES/evidence/r1-relay-view.json")"
  if [ "$n" -ge 1 ] && [ "$leak" = false ]; then
    pass "2.relay_view" "R1 store holds $n frame(s) for this exchange: topics $(jq -c '[.what_R1_stored[].contentTopic]|unique' "$RES/evidence/r1-relay-view.json"), payload sizes $(jq -c '[.what_R1_stored[].payload_bytes]' "$RES/evidence/r1-relay-view.json") bytes; the plaintext marker, message id and both addresses do NOT occur in any stored payload" \
      "curl '$R1/store/v3/messages?contentTopics=<B inbox topic>&includeData=true&startTime=<ns>' | base64-decode payloads, search for the marker (evidence/r1-relay-view.json)"
  else fail "2.relay_view" "frames found=$n leak_detected=$leak" "curl $R1/store/v3/messages ..."; fi
}

# ================================================================== STEP 3
b_inbox_dump() { "$DRV" dump --data-dir "$WORK/b" --idle-ms 1500; }

step3() {
  log "=== STEP 3: recipient offline recovery"
  local btopic; btopic="$(cat "$WORK/b.topic")"
  local t_start_ns; t_start_ns=$(now_ns)
  # ---- main: 20 offline messages + 1 short-TTL message, B daemon AND node an-nb stopped
  stop_daemon b; node_stop an-nb
  log "B daemon + an-nb stopped (daemon stop took ${SHUTDOWN_MS} ms)"
  local ids="" i id ttl_id t_ttl_sent
  ttl_id="$(send a b "s3-ttl-expiring" --ttl 15 --conversation s3-ttl)"; t_ttl_sent=$(now_ms)
  for i in $(seq 1 20); do id="$(send a b "s3-offline-$i" --conversation s3)"; ids="$ids $id"; done
  echo "$ids" > "$WORK/s3.ids"
  # shellcheck disable=SC2086
  wait_for 120 "A: all 20 messages sent" all_in_state a sent $ids || \
    log "note: not every message reached 'sent' on A: $(count_states a $ids $ttl_id)"
  log "A sent 21 messages while B is down: $(count_states a $ids $ttl_id)"
  note 3.main "While B (daemon and node an-nb) was down A sent 20 messages (conversation s3) and one with --ttl 15. A's states right after sending: $(count_states a $ids $ttl_id)."
  # let the 15 s TTL pass while B is still down
  while [ $(( $(now_ms) - t_ttl_sent )) -lt 25000 ]; do sleep 1; done
  local r1_frames; r1_frames="$(r1_store_count "$btopic" "$t_start_ns")"
  node_start an-nb "$NB"
  local t_b_start; t_b_start=$(now_ms)
  start_daemon b nowait
  # recovery latency: spawn -> all 20 present in B's inbox
  local ok=1
  wait_for 300 "B inbox has all 20 offline messages" inbox_is b s3 20 || ok=0
  local rec_ms=$(( $(now_ms) - t_b_start ))
  net_ready b >/dev/null 2>&1; wait_for 120 "B ready" net_ready b || true
  b_inbox_dump > "$RES/evidence/step3-b-dump.json" 2>/dev/null || true
  local rows uniq recv_events ttl_rows
  rows="$(jq '[.inbox.records[]|select(.conversation_id=="s3")]|length' "$RES/evidence/step3-b-dump.json")"
  uniq="$(jq '[.inbox.records[]|select(.conversation_id=="s3")|.message_id]|unique|length' "$RES/evidence/step3-b-dump.json")"
  ttl_rows="$(jq '[.inbox.records[]|select(.conversation_id=="s3-ttl")]|length' "$RES/evidence/step3-b-dump.json")"
  recv_events="$(jq --argjson ids "$(printf '%s\n' $ids | jq -R . | jq -sc .)" '[.events.records[]|select(.event_type=="message.received" and (.message_id as $m|$ids|index($m)))]|length' "$RES/evidence/step3-b-dump.json")"
  if [ "$ok" = 1 ] && [ "$rows" = 20 ] && [ "$uniq" = 20 ]; then
    pass "3.recover" "B recovered all 20 eligible messages via Store within $rec_ms ms of starting the node-up + daemon (R1 held $r1_frames frame(s) for B's topic since test start, i.e. including A's sender retries and the expiring one); inbox rows=$rows unique=$uniq" \
      "docker stop an-nb; agentnet send x20 (A); docker start an-nb; agentnet serve (B); agentnet-acceptance dump --data-dir \$B"
  else fail "3.recover" "inbox rows=$rows unique=$uniq (expected 20/20), recovered-in-time=$ok" "agentnet-acceptance dump"; fi
  if [ "$recv_events" = 20 ] && [ "$(jq .events.duplicate_message_received_events "$RES/evidence/step3-b-dump.json")" = 0 ]; then
    pass "3.no_dup_events" "B's event log (EventStream replay) has exactly 20 message.received events for the 20 messages, 0 messages with more than one event" "agentnet-acceptance dump (EventStream)"
  else fail "3.no_dup_events" "message.received events for the 20 ids = $recv_events; duplicates=$(jq .events.duplicate_message_received_events "$RES/evidence/step3-b-dump.json")" "agentnet-acceptance dump"; fi
  # deliberate duplicates: re-publish everything R1 holds for B's topic, three times, fresh timestamps
  local pre_rows="$rows" pre_ev; pre_ev="$(jq '.events.total' "$RES/evidence/step3-b-dump.json")"
  republish "$NB" "$btopic" "$t_start_ns" 3
  republish "$NA" "$btopic" "$t_start_ns" 1
  sleep 20
  b_inbox_dump > "$RES/evidence/step3-b-dump-after-dups.json" 2>/dev/null || true
  rows="$(jq '[.inbox.records[]|select(.conversation_id=="s3")]|length' "$RES/evidence/step3-b-dump-after-dups.json")"
  local ev2; ev2="$(jq '.events.total' "$RES/evidence/step3-b-dump-after-dups.json")"
  if [ "$rows" = "$pre_rows" ] && [ "$ev2" = "$pre_ev" ]; then
    pass "3.dup_resend" "re-published every R1-held frame of B's topic 4x with fresh timestamps (ok=$REPUB_OK in last batch; see logs/republish.log): inbox rows stayed $rows, event count stayed $ev2" "curl store v3 | POST $NB/relay/v1/auto/messages (fresh timestamp) x4"
  else fail "3.dup_resend" "after duplicates inbox rows $pre_rows -> $rows, events $pre_ev -> $ev2" "republish"; fi
  # A's statuses
  # shellcheck disable=SC2086
  if wait_for 240 "A: all 20 delivered" all_in_state a delivered $ids; then
    pass "3.delivered" "A's 20 statuses reached delivered (took $WAITED_MS ms after B's inbox was complete)" "agentnet --json status <id> (x20)"
  else fail "3.delivered" "A's states: $(count_states a $ids)" "agentnet status"; fi

  # ---- (a) TTL expiry
  # shellcheck disable=SC2086
  wait_for 180 "A: ttl message expired" state_is a "$ttl_id" expired || true
  local ttl_state; ttl_state="$(mstate a "$ttl_id")"
  if [ "$ttl_state" = expired ] && [ "$ttl_rows" = 0 ] && [ "$(b_inbox_dump | jq '[.inbox.records[]|select(.conversation_id=="s3-ttl")]|length')" = 0 ]; then
    pass "3.fail.a_ttl" "message sent with --ttl 15 while B was down: A status = $ttl_state, B never shows it (0 inbox rows incl. quarantine)" "agentnet send <B> s3-ttl-expiring --ttl 15 (B down for >25 s)"
  else fail "3.fail.a_ttl" "A state=$ttl_state, B rows=$ttl_rows" "agentnet send --ttl 15"; fi
  jq -nc --arg id "$ttl_id" --arg st "$ttl_state" --argjson rows "${ttl_rows:--1}" '{message_id:$id, sender_state:$st, recipient_rows:$rows}' > "$RES/evidence/step3-a-ttl.json"
  note 3.fail.a_ttl "(a) TTL expiry: the frame was still in R1's store when B came back (retention 1 h >> 15 s TTL), but B's receive path rejects an envelope whose signed expires_at has passed; the sender, which never got an authenticated receipt, moves it to \`expired\` after expires_at instead of retrying forever. Recipient and sender agree: the message was not delivered and is not visible."

  # ---- (b) retention variant: history gone from R1
  log "--- (b) retention variant"
  local bids="" btag="s3b"
  stop_daemon b; node_stop an-nb
  local t_b_ns; t_b_ns=$(now_ns)
  for i in 1 2 3; do id="$(send a b "s3b-$i" --conversation $btag)"; bids="$bids $id"; done
  # shellcheck disable=SC2086
  wait_for 120 "A: 3 sent" all_in_state a sent $bids || true
  local a_pre_states; a_pre_states="$(count_states a $bids)"
  stop_daemon a          # no sender retries while retention is cut; restarted below
  local frames_before; frames_before="$(r1_store_count "$btopic" "$t_b_ns")"
  sleep 40               # make the frames older than the 30 s retention window
  r1_recreate "time:30"; sleep 3
  local frames_after; frames_after="$(r1_store_count "$btopic" "$t_b_ns")"
  note 3.fail.b_retention "(b) R1 recreated with R1_RETENTION=time:30 (pruning runs at start and every 30 min only, see spike/relay/scripts/demo-retention.sh): frames of B's topic in R1 since the test began: before=$frames_before, after the restart=$frames_after. A's three messages were in state '$a_pre_states' and A's daemon was stopped so that no sender retry could refill the store."
  node_start an-nb "$NB"; start_daemon b nowait
  wait_for 300 "B ready (retention variant)" net_ready b || true
  local t_b_ready=$(now_ms)
  sleep 90               # >= one history sync interval (60 s) + overlap
  local b_got; b_got="$(inbox_count b $btag)"
  start_daemon a nowait; local t_a_start; t_a_start=$(now_ms)
  wait_for 300 "A ready" net_ready a || true
  local a_ready_ms=$(( $(now_ms) - t_a_start ))
  # shellcheck disable=SC2086
  local deliv=0; wait_for 600 "A: s3b delivered" all_in_state a delivered $bids && deliv=1
  local deliv_ms=$(( $(now_ms) - t_a_start ))
  local b_got2; b_got2="$(inbox_count b $btag)"
  jq -nc --argjson fb "$frames_before" --argjson fa "$frames_after" --argjson bg "$b_got" --argjson bg2 "$b_got2" --arg st "$(count_states a $bids)" \
     --argjson dm "$deliv_ms" --argjson ar "$a_ready_ms" '{r1_frames_before:$fb, r1_frames_after_restart:$fa, b_inbox_while_sender_daemon_down:$bg, b_inbox_after_sender_restart:$bg2, a_states_final:$st, ms_from_A_daemon_start_to_last_delivered:$dm, a_ready_ms:$ar}' > "$RES/evidence/step3-retention.json"
  if [ "$frames_after" = 0 ] && [ "$b_got" = 0 ]; then
    pass "3.fail.b_retention" "history gone: R1 had $frames_before frame(s), 0 after the retention restart; B (up, history sync running 90 s) recovered $b_got of 3. After A's daemon restarted, the sender retry path delivered: B inbox=$b_got2/3, A states: $(count_states a $bids), $deliv_ms ms after A's daemon start (delivered=$deliv)" \
      "docker-compose up -d --force-recreate r1 with R1_RETENTION=time:30 (A daemon stopped, B down); start B; wait 90 s; start A"
  else fail "3.fail.b_retention" "expected frames_after=0 and B=0 while sender down; got frames_after=$frames_after B=$b_got (details evidence/step3-retention.json)" "retention variant"; fi
  note 3.fail.b_retention "(b) Outside relay retention the recipient cannot recover from Store: with the sender not running B got $b_got/3. The sender keeps the message in its durable outbox and retries until \`expires_at\` (default TTL 24 h, max 20 attempts, backoff cap 5 min), so once A was running again the messages were re-published and B received $b_got2/3; A ended as: $(count_states a $bids). A message whose TTL has also run out, or whose sender is gone, would be lost: AgentNet promises recovery only within relay retention AND sender TTL, not unlimited offline delivery. R1 was recreated again with the default retention right after this."

  # ---- (c) Store unavailable (R1 down) while B comes back
  log "--- (c) store unavailable"
  local cids="" ctag="s3c"
  stop_daemon b; node_stop an-nb
  r1_recreate ""        # back to the default retention first (R1 up, store retained)
  wait_for 120 "A ready" net_ready a || true
  local t_c_ns; t_c_ns=$(now_ns)
  for i in 1 2; do id="$(send a b "s3c-$i" --conversation $ctag)"; cids="$cids $id"; done
  # shellcheck disable=SC2086
  wait_for 120 "A: 2 sent" all_in_state a sent $cids || true
  local r1_has; r1_has="$(r1_store_count "$btopic" "$t_c_ns")"
  node_stop an-r1
  local t_r1_down; t_r1_down=$(now_ms)
  node_start an-nb "$NB"; start_daemon b nowait
  sleep 60
  q step3c-b-down "$BIN" --json --data-dir "$WORK/b" network status
  printf '%s\n' "$OUT" > "$RES/evidence/step3c-b-network-status-r1-down.json"
  q step3c-b-down "$BIN" --data-dir "$WORK/b" doctor
  local b_ready_down b_got_down
  b_ready_down="$(printf '%s' "$(cat "$RES/evidence/step3c-b-network-status-r1-down.json")" | jq -r .network.ready 2>/dev/null)"
  b_got_down="$(inbox_count b $ctag 2>/dev/null || echo "n/a")"
  log "R1 down, B back for 60 s: ready=$b_ready_down inbox=$b_got_down A states: $(count_states a $cids)"
  # R1 returns; measure
  ( cd "$RELAY_DIR" && DNS_NS=127.0.0.1 docker-compose start r1 ) >> "$RES/logs/docker.log" 2>&1 || docker start an-r1 >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "R1 health" health "$R1" || true
  local t_r1_up; t_r1_up=$(now_ms)
  echo "$t_r1_up" > "$WORK/t_r1_up"
  measure_live_resume "$t_r1_up" > "$RES/evidence/step3c-live-relay-resume.json" &
  local probe_pid=$!
  local t_ready="" t_got="" t_deliv=""
  local end=$(( t_r1_up + 900000 ))
  while [ "$(now_ms)" -lt "$end" ]; do
    [ -z "$t_ready" ] && net_ready b >/dev/null 2>&1 && t_ready=$(( $(now_ms) - t_r1_up ))
    [ -z "$t_got" ] && [ "$(inbox_count b $ctag 2>/dev/null || echo 0)" = 2 ] && t_got=$(( $(now_ms) - t_r1_up ))
    # shellcheck disable=SC2086
    if [ -z "$t_deliv" ] && all_in_state a delivered $cids; then t_deliv=$(( $(now_ms) - t_r1_up )); fi
    [ -n "$t_got" ] && [ -n "$t_deliv" ] && break
    sleep 2
  done
  wait "$probe_pid" 2>/dev/null || true
  b_inbox_dump > "$RES/evidence/step3c-b-dump.json" 2>/dev/null || true
  local c_rows c_uniq; c_rows="$(jq '[.inbox.records[]|select(.conversation_id=="s3c")]|length' "$RES/evidence/step3c-b-dump.json")"
  c_uniq="$(jq '[.inbox.records[]|select(.conversation_id=="s3c")|.message_id]|unique|length' "$RES/evidence/step3c-b-dump.json")"
  jq -nc --argjson ready "$b_ready_down" --arg got "$b_got_down" --argjson r1has "${r1_has:--1}" --arg tr "${t_ready:--1}" --arg tg "${t_got:--1}" --arg td "${t_deliv:--1}" --arg astate "$(count_states a $cids)" \
    '{r1_frames_stored_before_outage:$r1has, b_network_ready_while_r1_down:$ready, b_inbox_rows_while_r1_down:$got, ms_after_r1_health_until_b_ready:($tr|tonumber), ms_after_r1_health_until_b_has_both:($tg|tonumber), ms_after_r1_health_until_a_delivered:($td|tonumber), a_states_at_end:$astate}' > "$RES/evidence/step3c-store-unavailable.json"
  if [ "$b_got_down" = 0 ] && [ -n "$t_got" ] && [ "$c_rows" = 2 ] && [ "$c_uniq" = 2 ]; then
    pass "3.fail.c_store_down" "R1 down while B came back: B network ready=$b_ready_down, recovered $b_got_down/2 during 60 s; after R1 returned B recovered 2/2 (no duplicates, rows=$c_rows) $t_got ms after R1's /health, B ready after ${t_ready:-?} ms, A delivered after ${t_deliv:-never} ms" \
      "docker stop an-r1; docker start an-nb; agentnet serve (B); wait 60 s; docker start an-r1; poll"
  else fail "3.fail.c_store_down" "b_got_down=$b_got_down t_got=${t_got:-none} rows=$c_rows" "store unavailable variant"; fi
  note 3.fail.c_store_down "(c) With R1 down B's node cannot be queried for history and no relay path exists, so nothing is recovered and \`network status\` reports the degraded state (evidence/step3c-b-network-status-r1-down.json). Nothing was lost: A's messages were already in R1's persistent store (sqlite volume) and in A's outbox. After R1 returned they reached B after ${t_got:-n/a} ms (via A's retry and/or B's periodic history sync, whichever fired first) and A's status reached delivered after ${t_deliv:-n/a} ms."
  # E12: live relay resume
  local live; live="$(jq -r 'if .resumed then "live relay delivery between NA and NB resumed \(.resumed_after_ms) ms after R1 /health (probe #\(.probes_sent))" else "live relay delivery did NOT resume within \(.waited_ms) ms (\(.probes_sent) probes)" end' "$RES/evidence/step3c-live-relay-resume.json" 2>/dev/null)"
  note 3.fail.c_store_down "E12 measurement (raw relay path, independent of AgentNet: a probe frame published every 3 s on NA, polled on NB): $live. AgentNet-level: B had both messages after ${t_got:-n/a} ms, A delivered after ${t_deliv:-n/a} ms, i.e. sender retries and history sync $( [ -n "$t_got" ] && echo 'did deliver' || echo 'did NOT deliver within 15 min' ) regardless of the live path."
  if [ -n "$t_deliv" ]; then pass "3.e12" "$live; AgentNet delivered after ${t_deliv} ms" "evidence/step3c-live-relay-resume.json (probe loop in scripts/acceptance.sh: measure_live_resume)"
  else fail "3.e12" "$live; AgentNet did NOT deliver within 15 min of R1's return" "measure_live_resume"; fi
  topology_ok && pass "3.restored" "topology restored: R1 default retention, an-nb running, NA and NB connected to R1" "docker-compose up -d --force-recreate r1 (default env)" \
    || fail "3.restored" "topology not healthy after step 3" "docker ps"
}

# raw relay-path probe: publish on NA every 3 s, look for it on NB's relay cache; prints JSON
measure_live_resume() {
  local t0=$1 ct="/agentnet/1/acc-probe/proto" i=0 got=0 now res
  curl -s -m 5 -X POST -H 'content-type: application/json' -d "[\"$ct\"]" "$NA/relay/v1/auto/subscriptions" >/dev/null
  curl -s -m 5 -X POST -H 'content-type: application/json' -d "[\"$ct\"]" "$NB/relay/v1/auto/subscriptions" >/dev/null
  while [ $(( $(now_ms) - t0 )) -lt 900000 ]; do
    i=$((i+1))
    curl -s -m 8 -o /dev/null -X POST -H 'content-type: application/json' \
      -d "{\"payload\":\"$(printf 'probe-%s' "$i" | base64)\",\"contentTopic\":\"$ct\"}" "$NA/relay/v1/auto/messages"
    sleep 3
    res="$(curl -s -m 8 "$NB/relay/v1/auto/messages/$(jq -rn --arg t "$ct" '$t|@uri')")"
    if [ "$(printf '%s' "$res" | jq 'if type=="array" then length else 0 end' 2>/dev/null || echo 0)" -gt 0 ]; then got=1; break; fi
  done
  now=$(now_ms)
  jq -nc --argjson g "$got" --argjson t "$(( now - t0 ))" --argjson i "$i" '{resumed:($g==1), resumed_after_ms:(if $g==1 then $t else null end), waited_ms:$t, probes_sent:$i, method:"POST NA /relay/v1/auto/messages every 3 s; GET NB /relay/v1/auto/messages/<ct>"}'
}

# ================================================================== STEP 4
run_harness() { # out state [extra args]
  local out=$1 st=$2; shift 2
  "$HARNESS" --data-dir "$WORK/b" --out "$out" --state "$st" "$@" >> "$WORK/harness.stderr" 2>&1 &
  echo $! > "$WORK/harness.pid"
}
stop_harness() { [ -f "$WORK/harness.pid" ] && { kill -TERM "$(cat "$WORK/harness.pid")" 2>/dev/null || true; sleep 1; kill -KILL "$(cat "$WORK/harness.pid")" 2>/dev/null || true; rm -f "$WORK/harness.pid"; }; }
turns() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
trig_matched() { # count trigger.matched events on B for a trigger id
  b_inbox_dump 2>/dev/null | jq --arg t "$1" '[.events.records[]|select(.event_type=="trigger.matched" and .trigger_id==$t)]|length'
}

step4() {
  log "=== STEP 4: triggers"
  local btopic out st t_ns; btopic="$(cat "$WORK/b.topic")"
  out="$RES/evidence/harness-turns.jsonl"; st="$WORK/harness-state.json"; : > "$out"
  t_ns=$(now_ns)
  # policy refusals
  local r
  r="$(mcp a create_trigger '{"target_session":"demo-session"}')"; echo "$r" > "$RES/evidence/step4-create-trigger-disabled-A.json"
  if [ "$(echo "$r" | jq -r '.is_error')" = true ] && [ "$(echo "$r" | jq -r '.result.error.code')" = policy_denied ]; then
    pass "4.policy.disabled" "create_trigger on A (policy.auto_trigger=false): isError, code policy_denied: $(echo "$r" | jq -r '.result.error.message')" "agentnet-acceptance mcp-call --data-dir \$A --tool create_trigger --args '{\"target_session\":\"demo-session\"}'"
  else fail "4.policy.disabled" "unexpected: $(echo "$r" | jq -c .result)" "mcp create_trigger on A"; fi
  r="$(mcp b create_trigger '{"target_session":"not-allowed-session","sender":"'"$(addr_of a)"'"}')"; echo "$r" > "$RES/evidence/step4-create-trigger-not-allowlisted.json"
  if [ "$(echo "$r" | jq -r '.is_error')" = true ] && [ "$(echo "$r" | jq -r '.result.error.code')" = policy_denied ]; then
    pass "4.policy.allowlist" "create_trigger on B for a non-allowlisted session: isError, policy_denied: $(echo "$r" | jq -r '.result.error.message')" "agentnet-acceptance mcp-call --data-dir \$B --tool create_trigger --args '{\"target_session\":\"not-allowed-session\",...}'"
  else fail "4.policy.allowlist" "unexpected: $(echo "$r" | jq -c .result)" "mcp create_trigger non-allowlisted"; fi

  run_harness "$out" "$st"
  sleep 1
  # trigger 1 (one-shot, sender A)
  r="$(mcp b create_trigger '{"target_session":"demo-session","sender":"'"$(addr_of a)"'"}')"; echo "$r" > "$RES/evidence/step4-create-trigger-B.json"
  local trig; trig="$(echo "$r" | jq -r '.result.trigger_id // empty')"
  if [ -n "$trig" ] && [ "$(echo "$r" | jq -r '.result.once')" = true ]; then
    pass "4.create" "B create_trigger via MCP: trigger $trig (sender A, session demo-session, once=true, state $(echo "$r" | jq -r .result.state)); negotiated protocol $(echo "$r" | jq -r .protocol.negotiated_protocol_version)" \
      "agentnet-acceptance mcp-call --data-dir \$B --tool create_trigger --args '{\"target_session\":\"demo-session\",\"sender\":\"<A>\"}'"
  else fail "4.create" "create_trigger failed: $(echo "$r" | jq -c .result)" "mcp create_trigger"; return 1; fi
  local m1; m1="$(send a b "trigger-test-1" --conversation s4)"
  if wait_for 180 "harness turn" lines_ge "$out" 1; then log "first turn recorded after $WAITED_MS ms"; else log "no turn recorded"; fi
  local lat1=$WAITED_MS
  # forced duplicates and a harness restart in the middle
  republish "$NB" "$btopic" "$t_ns" 2
  stop_harness; sleep 1; run_harness "$out" "$st"
  republish "$NA" "$btopic" "$t_ns" 2
  republish "$NB" "$btopic" "$t_ns" 2
  sleep 20
  local nt; nt="$(turns "$out")"
  local tm; tm="$(trig_matched "$trig")"
  local rows1; rows1="$(b_inbox_dump | jq --arg m "$m1" '[.inbox.records[]|select(.message_id==$m)]|length')"
  jq -nc --arg t "$trig" --arg m "$m1" --argjson nt "$nt" --argjson tm "$tm" --argjson rows "$rows1" --argjson lat "$lat1" --argjson rep "${REPUB_OK:-0}" \
    '{trigger_id:$t, message_id:$m, harness_turn_lines:$nt, trigger_matched_events:$tm, inbox_rows_for_message:$rows, first_turn_after_ms:$lat, last_republish_batch_ok:$rep}' > "$RES/evidence/step4-one-shot.json"
  if [ "$nt" = 1 ] && [ "$tm" = 1 ] && [ "$rows1" = 1 ]; then
    pass "4.one_shot" "exactly ONE simulated turn (harness out file: $nt line) and one trigger.matched event, one inbox row, after 3 republish rounds (each stored frame re-published with fresh timestamps, 5 rounds-of-frames total) and a harness restart mid-way; first turn $lat1 ms after send" \
      "mock_harness --data-dir \$B --out turns.jsonl --state state.json; agentnet send <B>; curl store + POST relay (x5); kill+restart mock_harness"
  else fail "4.one_shot" "turn lines=$nt trigger.matched=$tm inbox rows=$rows1 (all expected 1)" "mock_harness"; fi
  cat "$out" > "$RES/evidence/harness-turns-after-first.jsonl"

  # second matching message must not fire the consumed trigger
  local m2; m2="$(send a b "trigger-test-2" --conversation s4)"
  wait_for 120 "B has m2" inbox_is b s4 2 || true
  sleep 15
  nt="$(turns "$out")"; tm="$(trig_matched "$trig")"
  if [ "$nt" = 1 ] && [ "$tm" = 1 ] && [ "$(mcp b list_triggers '{"include_inactive":true}' | jq -r --arg t "$trig" '.result.triggers[]|select(.trigger_id==$t)|.state')" = consumed ]; then
    pass "4.consumed" "second matching message ($m2) arrived and is in B's inbox, but the consumed trigger did not fire: turns=$nt, trigger.matched=$tm, trigger state consumed" "agentnet send <B> trigger-test-2; mcp list_triggers"
  else fail "4.consumed" "turns=$nt trigger.matched=$tm" "second matching message"; fi

  # unknown identity C: quarantined, does not wake the harness (a wildcard trigger exists so a match would fire)
  new_agent c "$NA"; set_toml "$WORK/c/agentnet.toml" policy unknown_senders '"quarantine"' || true
  start_daemon c
  contact_exchange c b || true      # C knows B; B does NOT know C
  r="$(mcp b create_trigger '{"target_session":"demo-session"}')"; local wtrig; wtrig="$(echo "$r" | jq -r '.result.trigger_id // empty')"
  local mc; mc="$(send c b "unknown-sender-should-not-wake" --conversation s4c)"
  wait_for 120 "B quarantined C's message" quar_has b "$mc" || true
  sleep 15
  local quar inbox_vis nt2 cstate; quar="$(anj b quarantine list | jq --arg m "$mc" '[.records[]|select(.message_id==$m)]|length')"
  inbox_vis="$(anj b inbox --conversation s4c --limit 50 | jq '.records|length')"
  nt2="$(turns "$out")"; cstate="$(mstate c "$mc")"
  local wstate; wstate="$(mcp b list_triggers '{}' | jq -r --arg t "$wtrig" '.result.triggers[]|select(.trigger_id==$t)|.state')"
  jq -nc --arg m "$mc" --argjson q "$quar" --argjson v "$inbox_vis" --argjson t "$nt2" --arg cs "$cstate" --arg ws "$wstate" --arg wt "$wtrig" \
    '{message_id:$m, in_quarantine_list:$q, visible_in_default_inbox:$v, harness_turns:$t, sender_state_C:$cs, wildcard_trigger:$wt, wildcard_trigger_state:$ws}' > "$RES/evidence/step4-unknown-sender.json"
  if [ "$quar" = 1 ] && [ "$inbox_vis" = 0 ] && [ "$nt2" = 1 ] && [ "$wstate" = active ] && [ "$cstate" != delivered ]; then
    pass "4.unknown" "message from unknown identity C ($(addr_of c)) is quarantined on B (not in the default inbox), no ack (C's state: $cstate), harness turns still $nt2, and a wildcard trigger (no sender filter) stayed $wstate" \
      "agentnet send <B> (from C, not in B's contacts); agentnet quarantine list; mcp list_triggers"
  else fail "4.unknown" "quarantined=$quar visible=$inbox_vis turns=$nt2 wildcard=$wstate C state=$cstate" "unknown sender"; fi
  mcp b delete_trigger '{"trigger_id":"'"$wtrig"'"}' > "$RES/evidence/step4-delete-wildcard.json" || true
  stop_daemon c

  # since_cursor race
  local cur; cur="$(anj b inbox --limit 200 | jq -r .next_cursor)"
  local mr; mr="$(send a b "reply-before-trigger" --conversation s4r)"
  wait_for 120 "B has race message" inbox_is b s4r 1 || true
  sleep 3
  local pre_turns; pre_turns="$(turns "$out")"
  r="$(mcp b create_trigger '{"target_session":"demo-session","sender":"'"$(addr_of a)"'","since_cursor":"'"$cur"'"}')"; echo "$r" > "$RES/evidence/step4-create-trigger-since-cursor.json"
  local rtrig; rtrig="$(echo "$r" | jq -r '.result.trigger_id // empty')"
  wait_for 60 "race turn" lines_ge "$out" $((pre_turns + 1)) || true
  republish "$NB" "$btopic" "$t_ns" 1
  sleep 10
  local nt3 tm3; nt3="$(turns "$out")"; tm3="$(trig_matched "$rtrig")"
  if [ "$pre_turns" = 1 ] && [ "$nt3" = 2 ] && [ "$tm3" = 1 ]; then
    pass "4.since_cursor" "reply persisted BEFORE the trigger existed; trigger created with since_cursor fired exactly once (harness turns $pre_turns -> $nt3, trigger.matched events for it: $tm3), also after a duplicate republish" \
      "agentnet send <B>; mcp create_trigger {...,\"since_cursor\":\"<cursor before send>\"}"
  else fail "4.since_cursor" "turns before=$pre_turns after=$nt3 trigger.matched=$tm3" "since_cursor race"; fi
  stop_harness
  cp "$out" "$RES/evidence/harness-turns-final.jsonl"

  # ---- webhook mode
  log "--- webhook mode"
  stop_daemon b
  local secret="$WORK/b/webhook.secret"
  ( umask 077; openssl rand -hex 32 | tr -d '\n' > "$secret" )
  chmod 600 "$secret"
  set_toml "$WORK/b/agentnet.toml" webhook enabled true
  set_toml "$WORK/b/agentnet.toml" webhook url '"http://127.0.0.1:19090/hook"'
  set_toml "$WORK/b/agentnet.toml" webhook secret_file "\"$secret\""
  start_daemon b || true
  local wout="$RES/evidence/harness-webhook-turns.jsonl"; : > "$wout"
  "$HARNESS" --data-dir "$WORK/b" --webhook 127.0.0.1:19090 --secret-file "$secret" --out "$wout" --state "$WORK/harness-webhook-state.json" >> "$WORK/harness.stderr" 2>&1 &
  echo $! > "$WORK/harness.pid"; sleep 1
  r="$(mcp b create_trigger '{"target_session":"demo-session","sender":"'"$(addr_of a)"'"}')"; local wh; wh="$(echo "$r" | jq -r '.result.trigger_id // empty')"
  local mw; mw="$(send a b "webhook-trigger-test" --conversation s4w)"
  wait_for 180 "webhook turn" lines_ge "$wout" 1 || true
  sleep 3
  local wn; wn="$(turns "$wout")"
  local ev; ev="$(b_inbox_dump | jq -c --arg t "$wh" '[.events.records[]|select(.event_type=="trigger.matched" and .trigger_id==$t)][0]')"
  local ts body sigok sigbad stale replay
  body="$ev"; ts=$(date +%s)
  sign() { printf '%s.%s' "$1" "$2" | openssl dgst -sha256 -hmac "$3" -hex | awk '{print $NF}'; }
  post() { curl -s -m 8 -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -H "X-AgentNet-Timestamp: $1" -H "X-AgentNet-Signature: v1=$2" -H "X-AgentNet-Event-Id: x" -d "$3" http://127.0.0.1:19090/hook; }
  sigbad="$(post "$ts" "$(sign "$ts" "$body" wrong-secret-wrong-secret-wrong-secret-0123456789)" "$body")"
  stale="$(post "$((ts - 4000))" "$(sign "$((ts - 4000))" "$body" "$(cat "$secret")")" "$body")"
  replay="$(post "$ts" "$(sign "$ts" "$body" "$(cat "$secret")")" "$body")"
  local wn2; wn2="$(turns "$wout")"
  jq -nc --argjson wn "$wn" --argjson wn2 "$wn2" --arg bad "$sigbad" --arg stale "$stale" --arg replay "$replay" --arg ev "$ev" \
    '{turns_after_signed_delivery:$wn, wrong_secret_http:$bad, stale_timestamp_http:$stale, valid_replay_of_delivered_event_http:$replay, turns_after_probes:$wn2, event:($ev|fromjson)}' > "$RES/evidence/step4-webhook.json"
  if [ "$wn" = 1 ] && [ "$sigbad" = 401 ] && [ "$stale" = 401 ] && [ "$replay" = 200 ] && [ "$wn2" = 1 ]; then
    pass "4.webhook" "signed delivery from the daemon verified and recorded (1 turn); wrong-secret request -> HTTP $sigbad; stale-timestamp request -> $stale; validly signed replay of the delivered event -> $replay with no second turn ($wn2)" \
      "mock_harness --webhook 127.0.0.1:19090 --secret-file S; agentnet serve with [webhook] enabled; curl -X POST with X-AgentNet-Signature variants"
  else fail "4.webhook" "turns=$wn wrong-secret=$sigbad stale=$stale replay=$replay turns-after=$wn2" "webhook mode"; fi
  stop_harness
  # restore B to the socket-only config
  stop_daemon b
  set_toml "$WORK/b/agentnet.toml" webhook enabled false
  start_daemon b || true
}

# ================================================================== STEP 5
lsof_snap() { # label. lsof misses the daemon's short-lived loopback connections, so netstat (which names the owning
  # process) is the primary evidence; lsof is kept as a cross-check.
  local n pid
  for n in a b; do
    pid="$(daemon_pid "$n")"; [ -n "$pid" ] || continue
    { echo "### $(date -u +%FT%TZ) $1 daemon $n pid $pid"; lsof -nP -i -a -p "$pid" 2>&1 || true; } >> "$RES/net/lsof-$n.txt"
    if [ "$(uname -s)" = Linux ]; then
      # Linux: netstat has no per-process output; ss names the owning pid. Emit the same columns the
      # macOS branch produces (proto recvq sendq local remote, addresses as ip.port, "*.*" for wildcards).
      { echo "### $(date -u +%FT%TZ) $1"; ss -H -tunap 2>/dev/null | grep -E "pid=$pid[,)]" | awk '
          function conv(a,   i) { if (a ~ /:\*$/ || a == "*:*") return "*.*"; i = match(a, /:[0-9]+$/); if (i == 0) return a; a = substr(a, 1, i-1) "." substr(a, i+1); gsub(/^\[|\]/, "", a); return a }
          { print $1 "4 0 0 " conv($5) " " conv($6) " " $2 }' || true; } >> "$RES/net/netstat-$n.txt"
    else
      { echo "### $(date -u +%FT%TZ) $1"; { netstat -anv -p tcp; netstat -anv -p udp; } 2>/dev/null | grep -E "agentnet:$pid( |$)" || true; } >> "$RES/net/netstat-$n.txt"
    fi
  done
}
start_capture() { # name
  local netid br
  netid="$(docker network inspect "$BRIDGE_NET" --format '{{.Id}}')"; br="br-${netid:0:12}"
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  CAPDIR="$ROOT/results/acceptance/.cap.$$"; mkdir -p "$CAPDIR"   # must live under /Users: that is what the colima VM mounts
  docker run -d --name "$CAP" --net host --cap-add NET_RAW --cap-add NET_ADMIN -v "$CAPDIR":/out nicolaka/netshoot \
    sh -c "exec tcpdump -i $br -nn -s 128 -U -w /out/$1.pcap" >> "$RES/logs/docker.log" 2>&1
  echo "$br" > "$WORK/bridge"
  sleep 3
}
stop_capture() { # name
  docker stop -t 10 "$CAP" >> "$RES/logs/docker.log" 2>&1 || true
  docker rm -f "$CAP" >/dev/null 2>&1 || true
  docker run --rm -v "$CAPDIR":/out nicolaka/netshoot sh -c "
    tcpdump -nn -q -r /out/$1.pcap 2>/dev/null | wc -l > /out/$1.packets.txt
    echo '--- IP/IPv6 packets with an endpoint outside 172.28.66.0/24 (candidate egress):' > /out/$1.egress.txt
    tcpdump -nn -r /out/$1.pcap 'ip and not (src net 172.28.66.0/24 and dst net 172.28.66.0/24)' 2>/dev/null >> /out/$1.egress.txt
    tcpdump -nn -r /out/$1.pcap 'ip6' 2>/dev/null | grep -v 'ff02::' >> /out/$1.egress.txt
    echo '--- all distinct (src, dst:port) pairs' > /out/$1.flows.txt
    tcpdump -nn -q -r /out/$1.pcap 'ip' 2>/dev/null | awk '{print \$3, \$5}' | sed 's/:\$//' | sort | uniq -c | sort -rn >> /out/$1.flows.txt
    echo '--- DNS queries seen' > /out/$1.dns.txt
    tcpdump -nn -r /out/$1.pcap 'port 53' 2>/dev/null >> /out/$1.dns.txt" >> "$RES/logs/docker.log" 2>&1 || true
  cp "$CAPDIR"/"$1".* "$RES/pcap/" 2>/dev/null || true
}
egress_count() { local n; n="$(grep -vc '^---' "$RES/pcap/$1.egress.txt" 2>/dev/null || true)"; echo "${n:--1}"; }

step5() {
  log "=== STEP 5: private network"
  local d
  # 5.config
  for d in a b; do
    q step5-config "$BIN" --json --data-dir "$WORK/$d" network status
    printf '%s\n' "$OUT" > "$RES/evidence/step5-network-status-$d.json"
  done
  if grep -q 'public_discovery = false' "$WORK/a/agentnet.toml" && grep -q 'public_fallback = false' "$WORK/a/agentnet.toml" && grep -q 'mode = "private"' "$WORK/a/agentnet.toml" \
     && grep -q 'public_discovery = false' "$WORK/b/agentnet.toml" && grep -q 'cluster_id = 66' "$WORK/b/agentnet.toml" \
     && [ "$(jq -r .network.mode "$RES/evidence/step5-network-status-a.json")" = private ]; then
    pass "5.config" "both agents: mode=private, public_discovery=false, public_fallback=false, cluster_id=66, static peer R1 only (evidence/config-*-excerpt.toml); node flags: all discovery off, --dns-addrs-name-server=127.0.0.1, --nat=extip (spike/relay/docker-compose.yml)" "grep -E 'mode|public_|cluster_id' \$A/agentnet.toml"
  else fail "5.config" "config does not look private" "grep config"; fi
  docker inspect an-r1 an-na an-nb --format '{{.Name}} {{join .Args " "}}' > "$RES/evidence/node-flags.txt" 2>&1 || true
  if grep -q -- '--discv5-discovery=false' "$RES/evidence/node-flags.txt" && grep -q -- '--dns-addrs-name-server=127.0.0.1' "$RES/evidence/node-flags.txt" && ! grep -q -- 'dns-discovery-url\|entry-node' "$RES/evidence/node-flags.txt"; then
    pass "5.node_flags" "R1/NA/NB run with discv5/peer-exchange/rendezvous/kad off, DNS server 127.0.0.1, no dns-discovery-url / entry-node (evidence/node-flags.txt)" "docker inspect an-r1 an-na an-nb --format '{{.Name}} {{join .Args \" \"}}'"
  else fail "5.node_flags" "node flags unexpected (see evidence/node-flags.txt); containers probably started without DNS_NS=127.0.0.1" "docker inspect"; fi

  # 5.egress: 120 s capture, fresh exchange both directions, lsof snapshots
  : > "$RES/net/lsof-a.txt"; : > "$RES/net/lsof-b.txt"; : > "$RES/net/netstat-a.txt"; : > "$RES/net/netstat-b.txt"
  start_capture egress-exchange
  local t0 t_end ids="" k=0 id
  t0=$(date +%s); t_end=$((t0 + 125))
  while [ "$(date +%s)" -lt "$t_end" ]; do
    for sub in 1 2 3 4 5; do lsof_snap "t+$(( $(date +%s) - t0 ))s"; sleep 1; done
    if [ $(( k % 2 )) = 0 ]; then
      id="$(send a b "egress-a2b-$k" --conversation s5)"; ids="$ids $id"
      [ $((k % 4)) = 2 ] && { id="$(send b a "egress-b2a-$k" --conversation s5)"; }
    fi
    k=$((k+1)); sleep 5
  done
  # shellcheck disable=SC2086
  wait_for 60 "s5 delivered" all_in_state a delivered $ids || true
  local s5states; s5states="$(count_states a $ids)"
  stop_capture egress-exchange
  local pk ec; pk="$(cat "$RES/pcap/egress-exchange.packets.txt" 2>/dev/null | tr -d ' ')"; ec="$(egress_count egress-exchange)"
  local dests; dests="$(grep -h -o '\->[ ]*[0-9.]*:[0-9]*\|-> [0-9.]*:[0-9]*' "$RES/net/lsof-a.txt" "$RES/net/lsof-b.txt" 2>/dev/null | sort -u | tr '\n' ' ')"
  # all remote endpoints of the daemons (from lsof "->host:port") must be 127.0.0.1
  local nonlocal nsamples remotes
  nonlocal="$(grep -hv '^###' "$RES/net/netstat-a.txt" "$RES/net/netstat-b.txt" | awk '{print $5}' | grep -v -E '^127\.0\.0\.1\.|^\*\.\*$|^::1\.' | wc -l | tr -d ' ')"
  nsamples="$(grep -hv '^###' "$RES/net/netstat-a.txt" "$RES/net/netstat-b.txt" | wc -l | tr -d ' ')"
  remotes="$(grep -hv '^###' "$RES/net/netstat-a.txt" "$RES/net/netstat-b.txt" | awk '{print $5}' | sed -E 's/\.[0-9]+$//' | sort | uniq -c | tr '\n' ' ')"
  echo "remote hosts seen for the two daemons: $remotes" > "$RES/net/remote-hosts-summary.txt"
  jq -nc --argjson pk "${pk:-0}" --argjson ec "$ec" --arg s "$s5states" --argjson nl "$nonlocal" --arg dests "$dests" \
    '{packets_on_bridge:$pk, packets_with_endpoint_outside_172_28_66_0_24:$ec, a_messages_states:$s, host_daemon_nonloopback_connections_in_lsof_snapshots:$nl, host_daemon_remote_endpoints:$dests}' > "$RES/evidence/step5-egress.json"
  if [ "${ec:--1}" = 0 ] && [ "${pk:-0}" -gt 100 ]; then
    pass "5.egress" "tcpdump on the docker bridge, 125 s, whole exchange (A->B and B->A, $k rounds): $pk packets, 0 with any IP endpoint outside 172.28.66.0/24 (no DNS to 1.1.1.1 etc.; evidence pcap/egress-exchange.*). Messages: $s5states" \
      "docker run --net host --cap-add NET_RAW nicolaka/netshoot tcpdump -i br-<net> -w egress-exchange.pcap (colima VM netns); then read back with 'ip and not (src net 172.28.66.0/24 and dst net 172.28.66.0/24)'"
  else fail "5.egress" "bridge packets=$pk, packets outside 172.28.66.0/24=$ec: see pcap/egress-exchange.egress.txt" "tcpdump"; fi
  if [ "$(uname -s)" = Linux ] && [ "${nsamples:-0}" -le 20 ]; then
    # The daemon's REST connections are short-lived (the node answers `Connection: close`). macOS `netstat -anv`
    # keeps showing them long enough to sample once a second; Linux `ss` does not, so there is nothing to judge.
    untested "5.host_connections" "Linux: 1 s \`ss\` snapshots caught only $nsamples socket lines of the daemons' short-lived loopback connections (0 non-loopback among them); the per-process socket snapshot is only meaningful on macOS. Zero public egress is covered by the bridge capture checks of this step" "ss -H -tunap | grep pid=<pid>" true
  elif [ "$nonlocal" = 0 ] && [ "${nsamples:-0}" -gt 20 ] && grep -q '127\.0\.0\.1\.1864' "$RES/net/netstat-a.txt"; then
    pass "5.host_connections" "netstat -anv snapshots (every ~1 s for 125 s, TCP+UDP, filtered to the two 'agentnet serve' pids): $nsamples socket lines, every remote endpoint is 127.0.0.1 (node REST $NA / $NB), 0 non-loopback; remote hosts: $remotes (net/netstat-*.txt; lsof cross-check in net/lsof-*.txt saw no sockets because the connections are short-lived)" "netstat -anv -p tcp | grep agentnet:<pid>   (sampled every second); lsof -nP -i -a -p <pid>"
  else fail "5.host_connections" "non-loopback connections seen: $nonlocal, samples=$nsamples (see net/netstat-*.txt)" "netstat -anv | grep agentnet:<pid>"; fi

  # 5.relay_failure
  log "--- relay failure without public fallback"
  start_capture egress-relay-failure
  local t_down; node_stop an-r1; t_down=$(now_ms)
  local fid; fid="$(send a b "relay-down-msg" --conversation s5f)"
  sleep 75
  local st_down ready_down viol bin_cnt
  st_down="$(mstate a "$fid")"; q step5-relay "$BIN" --json --data-dir "$WORK/a" network status
  printf '%s\n' "$OUT" > "$RES/evidence/step5-relay-down-network-status-a.json"
  ready_down="$(echo "$OUT" | jq -r .network.ready)"; bin_cnt="$(inbox_count b s5f)"
  local detail_down; detail_down="$(echo "$OUT" | jq -r .network.detail)"
  q step5-relay "$BIN" --data-dir "$WORK/a" network status
  node_start an-r1 "$R1" 2>/dev/null || { docker start an-r1 >/dev/null 2>&1; wait_for 120 "R1" health "$R1"; }
  local t_up; t_up=$(now_ms)
  local dok=0; wait_for 900 "relay-down message delivered" state_is a "$fid" delivered && dok=1
  local dms=$(( $(now_ms) - t_up ))
  sleep 5
  stop_capture egress-relay-failure
  local ec2; ec2="$(egress_count egress-relay-failure)"
  jq -nc --arg st "$st_down" --arg rd "$ready_down" --argjson bi "$bin_cnt" --argjson ec "$ec2" --argjson dms "$dms" --argjson dok "$dok" --arg det "$detail_down" \
    '{a_state_while_R1_down:$st, a_network_ready_while_R1_down:$rd, a_network_detail:$det, b_inbox_rows_for_message_while_down:$bi, packets_outside_172_28_66_0_24_in_capture:$ec, ms_from_R1_start_to_delivered:$dms, delivered:($dok==1)}' > "$RES/evidence/step5-relay-failure.json"
  if { [ "$st_down" = queued ] || [ "$st_down" = sent ]; } && [ "$ready_down" = false ] && [ "$bin_cnt" = 0 ]; then
    pass "5.relay_failure" "R1 stopped: A's message stayed '$st_down' (not delivered), A network status ready=$ready_down ($detail_down), B received $bin_cnt; capture of the whole outage+recovery: $ec2 packets with an endpoint outside 172.28.66.0/24 (no fallback destination appeared)" \
      "docker stop an-r1; agentnet send <B>; sleep 75; agentnet network status; tcpdump capture (pcap/egress-relay-failure.*)"
  else fail "5.relay_failure" "state=$st_down ready=$ready_down B rows=$bin_cnt" "relay failure"; fi
  if [ "$ec2" = 0 ]; then pass "5.relay_failure_no_new_dest" "relay-failure capture: 0 packets with an endpoint outside 172.28.66.0/24 (pcap/egress-relay-failure.egress.txt)" "tcpdump"
  else fail "5.relay_failure_no_new_dest" "$ec2 external packets, see pcap/egress-relay-failure.egress.txt" "tcpdump"; fi
  if [ "$dok" = 1 ]; then pass "5.relay_recovery" "R1 restarted: the queued message was delivered $dms ms after R1 /health (E12: live relay can lag after an R1 restart; the sender retry/history path delivered)" "docker start an-r1; agentnet --json status <id>"
  else fail "5.relay_recovery" "message still not delivered 15 min after R1 returned (state $(mstate a "$fid"))" "docker start an-r1"; fi

  # 5.isolation: wrong peer id
  log "--- isolation fail-closed"
  new_agent w "$NA" "/ip4/172.28.66.10/tcp/60000/p2p/$R2_PEER_ID"
  start_daemon w nowait; sleep 25
  q step5-isolation "$BIN" --json --data-dir "$WORK/w" network status --verbose
  printf '%s\n' "$OUT" > "$RES/evidence/step5-isolation-network-status.json"
  local viol_txt ready_w; viol_txt="$(echo "$OUT" | jq -r '.network.isolation_violation // empty')"; ready_w="$(echo "$OUT" | jq -r .network.ready)"
  contact_exchange w b || true; contact_exchange b w || true
  local wm bm; wm="$(send w b "from-isolated-w" --conversation s5w)"; bm="$(send b w "to-isolated-w" --conversation s5w)"
  sleep 45
  local wst bst w_in b_in; wst="$(mstate w "$wm")"; bst="$(mstate b "$bm")"; w_in="$(inbox_count w s5w)"; b_in="$(inbox_count b s5w)"
  q step5-isolation "$BIN" --data-dir "$WORK/w" doctor
  jq -nc --arg v "$viol_txt" --arg r "$ready_w" --arg wst "$wst" --arg bst "$bst" --argjson wi "$w_in" --argjson bi "$b_in" \
    '{isolation_violation:$v, ready:$r, W_send_state:$wst, B_send_state_to_W:$bst, W_inbox_rows:$wi, B_inbox_rows_from_W:$bi}' > "$RES/evidence/step5-isolation.json"
  if [ -n "$viol_txt" ] && [ "$ready_w" = false ] && [ "$w_in" = 0 ] && [ "$b_in" = 0 ] && [ "$wst" != delivered ] && [ "$bst" != delivered ]; then
    pass "5.isolation" "daemon whose only allowlisted peer is a WRONG peer id ($R2_PEER_ID): network status ready=false, isolation_violation=\"$viol_txt\"; its send stayed '$wst' and B received $b_in; B's message to it stayed '$bst' and it received $w_in" \
      "agentnet init --peer /ip4/172.28.66.10/tcp/60000/p2p/<R2 id> ; agentnet serve ; agentnet network status --verbose"
  else fail "5.isolation" "violation='$viol_txt' ready=$ready_w W state=$wst B state=$bst W inbox=$w_in B inbox=$b_in" "isolation"; fi
  stop_daemon w
  clean_client_nodes    # W's wrong static peer was POSTed to NA's peer store: drop it so later runs/steps see only R1

  # 5.rejected configs
  log "--- rejected configs"
  local v name key val sec rc out
  for v in "public_discovery|network|public_discovery|true" "public_fallback|network|public_fallback|true" "public_node_url|network|node_url|\"http://8.8.8.8:8645\"" "cluster_id_1|network|cluster_id|1"; do
    name="${v%%|*}"; rest="${v#*|}"; sec="${rest%%|*}"; rest="${rest#*|}"; key="${rest%%|*}"; val="${rest#*|}"
    "$BIN" --data-dir "$WORK/bad-$name" init --node-url "$NA" --peer "$R1_MADDR" >/dev/null 2>&1 || true
    set_toml "$WORK/bad-$name/agentnet.toml" "$sec" "$key" "$val"
    if command -v timeout >/dev/null 2>&1; then
      q "step5-badconfig" timeout 30 "$BIN" --data-dir "$WORK/bad-$name" serve
    elif command -v gtimeout >/dev/null 2>&1; then
      q "step5-badconfig" gtimeout 30 "$BIN" --data-dir "$WORK/bad-$name" serve
    else
      q "step5-badconfig" perl -e 'alarm 30; exec @ARGV' "$BIN" --data-dir "$WORK/bad-$name" serve
    fi
    rc=$RC
    printf '{"case":"%s","setting":"[%s] %s = %s","exit_code":%s,"stderr":%s}\n' "$name" "$sec" "$key" "$(printf '%s' "$val" | sed 's/"/\\"/g')" "$rc" "$(printf '%s' "$ERR" | jq -Rs .)" > "$RES/evidence/step5-rejected-$name.json"
    if [ "$rc" = 4 ] && [ -n "$ERR" ]; then pass "5.reject.$name" "startup refused, exit 4: $(printf '%s' "$ERR" | cut -c1-300)" "agentnet --data-dir <dir with [$sec] $key = $val> serve"
    else fail "5.reject.$name" "exit $rc (expected 4): $ERR" "agentnet serve with $key=$val"; fi
  done

  # 5.tailscale
  if command -v tailscale >/dev/null 2>&1; then
    untested "5.tailscale" "tailscale binary present ($(command -v tailscale)) but this script does not drive a tailnet run (needs a second host and ACLs); see the manual steps in SUMMARY.md" "command -v tailscale" true
  else
    untested "5.tailscale" "tailscale not installed on this host (command -v tailscale: not found); no tailnet, no second host. Reproducible steps below. Nothing is claimed to work." "command -v tailscale" true
  fi
  note 5.tailscale 'Tailscale run: UNTESTED. To reproduce: (1) on the relay host install Tailscale, join the tailnet and tag it (e.g. `tag:agentnet-relay`); (2) start R1 with `--nat=extip:<relay tailnet 100.x.y.z>` `--listen-address=<tailnet ip or 0.0.0.0>` and every discovery flag off (`agentnet relay print-config --ip <tailnet ip> --peer-id <R1 peer id>` prints the flag set and a compose file, marked UNTESTED); (3) ACL in the tailnet policy file: `{"acls":[{"action":"accept","src":["tag:agentnet-agent"],"dst":["tag:agentnet-relay:60000"]}]}` so only tagged agent hosts reach tcp/60000, and nothing else (the node REST port stays on loopback, never on the tailnet); (4) on each agent host run a client node with `--staticnode=/ip4/<relay tailnet ip>/tcp/60000/p2p/<R1 peer id>` and `agentnet init --node-url http://127.0.0.1:8645 --peer /ip4/<relay tailnet ip>/tcp/60000/p2p/<R1 peer id>` (private mode accepts 100.64.0.0/10); (5) run this script against that topology with the relay host overridden (the script currently hard-codes the local topology: `RELAY_HOST` support is NOT implemented here, so the steps must be run by hand: contact exchange, send, status, inbox). Tailscale gives encrypted transport and machine-level ACLs only; the coordination service sees metadata; AgentNet still provides the end-to-end encryption and identity.'
}

# ================================================================== STEP 6
step6() {
  log "=== STEP 6: MCP client config + embedding"
  local cfg="$RES/evidence/mcp-client-config.json"
  jq -n --arg bin "$BIN" --arg dir "$WORK/a" '{mcpServers:{agentnet:{command:$bin, args:["mcp","--data-dir",$dir]}}}' > "$cfg"
  jq -n '{mcpServers:{agentnet:{command:"/path/to/agentnet", args:["mcp","--data-dir","/home/me/.agentnet"]}}}' > "$RES/evidence/mcp-client-config.template.json"
  q step6 "$DRV" config-check --config "$cfg" --server agentnet --expect-address "$(addr_of a)" --out "$RES/evidence/step6-config-check.json"
  if [ "$RC" = 0 ]; then
    pass "6.mcp_config" "stdio MCP client configuration emitted (evidence/mcp-client-config.json, template in .template.json); launched exactly its command+args with an rmcp client, negotiated $(jq -r .protocol.negotiated_protocol_version "$RES/evidence/step6-config-check.json"), tools/list = $(jq -c '.tools|length' "$RES/evidence/step6-config-check.json") tools, get_identity returned A's address" \
      "agentnet-acceptance config-check --config mcp-client-config.json --server agentnet --expect-address <A>   # spawns: $BIN mcp --data-dir \$A"
  else fail "6.mcp_config" "config-check failed: $(cat "$RES/evidence/step6-config-check.json" 2>/dev/null | jq -r .error 2>/dev/null)" "config-check"; fi
  local okc=0 i
  : > "$RES/evidence/step6-embed-output.txt"
  for i in 1 2 3 4 5; do
    q step6-embed "$EMBED"
    { echo "=== attempt $i exit $RC"; echo "$OUT"; [ -z "$ERR" ] || echo "[stderr] $ERR"; } >> "$RES/evidence/step6-embed-output.txt"
    [ "$RC" = 0 ] && okc=$((okc+1))
  done
  if [ "$okc" = 5 ]; then
    pass "6.embed" "Rust embedding example (MockNetwork, in-process engines) ran 5/5 times, exit 0 (evidence/step6-embed-output.txt)" "target/release/examples/embed   # cargo run --release -p agentnet-daemon --example embed"
  else fail "6.embed" "embed example (release build) succeeded only $okc/5 times; failure text: 'the message was not delivered in time' (the debug build passes). Product bug candidate, not worked around: evidence/step6-embed-output.txt" "target/release/examples/embed x5"; fi
  cat > "$RES/evidence/step6-embedding-statement.txt" <<'EOF'
Why the selected adapter cannot be fully embedded (ADR 0001, docs/architecture.md section 1):
the transport is an adapter to a separately running Logos Delivery (nwaku) node over its local REST API.
That node is a Nim program shipped as a separate executable/container: a sidecar that must run next to
the harness. The Rust engine (identity, envelopes, SQLite inbox/outbox, retries, triggers, events,
the AgentApi trait) CAN be embedded in a Rust harness, and the embed example does exactly that on the
deterministic in-memory MockNetwork; swapping in LogosRestTransport is a two-line change but still needs the
sidecar node. Embedding the node itself needs native FFI bindings (waku-sys), which is a future option
behind the same Transport trait and was not selected.
EOF
  pass "6.embed_statement" "statement why the adapter cannot be fully embedded (the node is a sidecar) saved to evidence/step6-embedding-statement.txt and quoted in SUMMARY.md" "n/a"
  note 6.embed_statement "$(tr '\n' ' ' < "$RES/evidence/step6-embedding-statement.txt")"
}

# ================================================================== EXTRAS
stepX() {
  log "=== EXTRAS"
  local out i
  # second serve on the same data dir
  q stepX-lock "$BIN" --data-dir "$WORK/a" serve
  if [ "$RC" = 1 ] && printf '%s' "$ERR" | grep -qi 'another AgentNet process'; then
    pass "X.second_serve" "second 'agentnet serve' on A's data dir refused, exit $RC: $ERR" "agentnet --data-dir \$A serve   # while A's daemon runs" true
  else fail "X.second_serve" "exit $RC: $ERR" "second serve" true; fi

  # 100 each direction
  log "--- bench 100 x 2"
  local cpu0; cpu0="$(ps -o rss=,pcpu= -p "$(daemon_pid a)" "$(daemon_pid b)" 2>/dev/null | tr '\n' ';')"
  ps -o pid=,rss=,pcpu=,etime=,command= -p "$(daemon_pid a)" "$(daemon_pid b)" > "$RES/evidence/ps-idle.txt" 2>&1 || true
  local bench_pid_stats="$WORK/ps-bench.txt"; : > "$bench_pid_stats"
  ( while true; do ps -o pid=,rss=,pcpu= -p "$(daemon_pid a)" "$(daemon_pid b)" >> "$bench_pid_stats" 2>/dev/null; echo "--" >> "$bench_pid_stats"; sleep 2; done ) &
  local sampler=$!
  echo "$sampler" > "$WORK/sampler.pid"
  q stepX-bench "$DRV" bench --a "$WORK/a" --b "$WORK/b" --a-addr "$(addr_of a)" --b-addr "$(addr_of b)" --n 100 --timeout 600 --pace-ms 25 --out "$RES/evidence/bench-100.json"
  kill "$sampler" 2>/dev/null || true; wait "$sampler" 2>/dev/null || true
  rm -f "$WORK/sampler.pid"
  cp "$bench_pid_stats" "$RES/evidence/ps-during-bench.txt"
  ps -o pid=,rss=,pcpu=,etime=,command= -p "$(daemon_pid a)" "$(daemon_pid b)" > "$RES/evidence/ps-after-bench.txt" 2>&1 || true
  sleep 5
  b_inbox_dump > "$RES/evidence/bench-b-dump.json" 2>/dev/null || true
  "$DRV" dump --data-dir "$WORK/a" --idle-ms 1500 > "$RES/evidence/bench-a-dump.json" 2>/dev/null || true
  local ab ba ab_rows ba_rows ab_u ba_u dupev
  ab="$(jq -c '.a_to_b' "$RES/evidence/bench-100.json")"; ba="$(jq -c '.b_to_a' "$RES/evidence/bench-100.json")"
  ab_rows="$(jq '[.inbox.records[]|select(.conversation_id=="bench-a2b")]|length' "$RES/evidence/bench-b-dump.json")"
  ab_u="$(jq '[.inbox.records[]|select(.conversation_id=="bench-a2b")|.message_id]|unique|length' "$RES/evidence/bench-b-dump.json")"
  ba_rows="$(jq '[.inbox.records[]|select(.conversation_id=="bench-b2a")]|length' "$RES/evidence/bench-a-dump.json")"
  ba_u="$(jq '[.inbox.records[]|select(.conversation_id=="bench-b2a")|.message_id]|unique|length' "$RES/evidence/bench-a-dump.json")"
  dupev=$(( $(jq .events.duplicate_message_received_events "$RES/evidence/bench-b-dump.json") + $(jq .events.duplicate_message_received_events "$RES/evidence/bench-a-dump.json") ))
  local summ; summ="A->B delivered $(echo "$ab" | jq '.delivered')/100 p50/p95/p99 = $(echo "$ab" | jq -r '.latency_ms_send_to_delivered|"\(.p50)/\(.p95)/\(.p99)"') ms; B->A delivered $(echo "$ba" | jq '.delivered')/100 p50/p95/p99 = $(echo "$ba" | jq -r '.latency_ms_send_to_delivered|"\(.p50)/\(.p95)/\(.p99)"') ms; receiver rows A->B $ab_rows (unique $ab_u), B->A $ba_rows (unique $ba_u), duplicate message.received events $dupev"
  if [ "$(echo "$ab" | jq .delivered)" = 100 ] && [ "$(echo "$ba" | jq .delivered)" = 100 ] && [ "$ab_rows" = 100 ] && [ "$ab_u" = 100 ] && [ "$ba_rows" = 100 ] && [ "$ba_u" = 100 ] && [ "$dupev" = 0 ]; then
    pass "X.bench100" "100 messages each direction (concurrent, 25 ms pacing, full stack): $summ. Latency = delivered_at - created_at in the sender's outbox (send -> authenticated receipt), includes qemu and the 250 ms poll interval" "agentnet-acceptance bench --a \$A --b \$B --n 100" true
  else fail "X.bench100" "$summ" "bench" true; fi
  local rss_a rss_b cpu_peak
  rss_a="$(ps -o rss= -p "$(daemon_pid a)" | tr -d ' ')"; rss_b="$(ps -o rss= -p "$(daemon_pid b)" | tr -d ' ')"
  cpu_peak="$(grep -v -- '--' "$bench_pid_stats" | awk '{ if ($3+0>m) m=$3+0 } END {print m+0}')"
  pass "X.resources" "daemon RSS after bench: A ${rss_a} KiB, B ${rss_b} KiB; peak sampled %CPU during bench (ps pcpu, 2 s samples): ${cpu_peak}; raw: evidence/ps-*.txt. Idle/before snapshot: ${cpu0}" "ps -o rss,pcpu -p <pid>" true
  # paced variant: 400 ms between sends per direction (about 5 msg/s total) to separate burst effects from steady state
  q stepX-bench-paced "$DRV" bench --a "$WORK/a" --b "$WORK/b" --a-addr "$(addr_of a)" --b-addr "$(addr_of b)" --n 100 --timeout 600 --pace-ms 400 --tag paced --out "$RES/evidence/bench-100-paced.json"
  pass "X.bench100_paced" "same workload paced at 400 ms per send per direction: A->B delivered $(jq '.a_to_b.delivered' "$RES/evidence/bench-100-paced.json")/100 p50/p95/p99 = $(jq -r '.a_to_b.latency_ms_send_to_delivered|"\(.p50)/\(.p95)/\(.p99)"' "$RES/evidence/bench-100-paced.json") ms; B->A delivered $(jq '.b_to_a.delivered' "$RES/evidence/bench-100-paced.json")/100 p50/p95/p99 = $(jq -r '.b_to_a.latency_ms_send_to_delivered|"\(.p50)/\(.p95)/\(.p99)"' "$RES/evidence/bench-100-paced.json") ms" "agentnet-acceptance bench --n 100 --pace-ms 400" true
  # startup / shutdown
  pass "X.startup_shutdown" "daemon startup (spawn -> network ready) and SIGTERM -> exit times: evidence/startup-times.tsv, evidence/shutdown-times.tsv; first-start times: $(awk '{printf "%s=%sms ", $1, $3}' "$RES/evidence/startup-times.tsv")" "see TSVs" true

  # identity migration
  log "--- identity export/import"
  new_agent m "$NB"
  start_daemon m
  contact_exchange m a || true; contact_exchange a m || true
  local pre_id; pre_id="$(send a m "before-migration-secret-body" --conversation xm)"
  wait_for 120 "M got it" inbox_is m xm 1 || true
  local pre_cnt; pre_cnt="$(inbox_count m xm)"
  stop_daemon m
  # message sent AFTER the daemon stopped and BEFORE the migration
  local mid2; mid2="$(send a m "sent-while-old-instance-was-down" --conversation xm2)"
  sleep 8
  ( umask 077; echo "acceptance-test-passphrase-not-a-secret" > "$WORK/pass.txt" ); chmod 600 "$WORK/pass.txt"
  rm -f "$WORK/m.export"
  q stepX-migrate "$BIN" --json --data-dir "$WORK/m" identity export --out "$WORK/m.export" --passphrase-file "$WORK/pass.txt"
  local exp_rc=$RC
  q stepX-migrate "$BIN" --json --data-dir "$WORK/m2" identity import --in "$WORK/m.export" --passphrase-file "$WORK/pass.txt" --node-url "$NB" --peer "$R1_MADDR"
  local imp_rc=$RC addr2; addr2="$(echo "$OUT" | jq -r .address)"
  # old data dir is not run again (competing writers are unsupported); new dir takes over
  mv "$WORK/m" "$WORK/m-retired"; cp -R "$WORK/m2" "$WORK/m2.keep" 2>/dev/null || true
  start_daemon m2 nowait
  wait_for 300 "m2 ready" net_ready m2 || true
  # contact record of A for the new instance (contacts are not part of the identity export)
  q stepX-migrate "$BIN" --json --data-dir "$WORK/m2" contact add "@$WORK/a.record" --expect "$(addr_of a)" --alias a
  sleep 5
  wait_for 240 "M2 sees the pre-migration message" inbox_any_q m2 xm2 || true
  local rec; rec="$("$BIN" --json --data-dir "$WORK/m2" inbox --include-quarantined --conversation xm2 --limit 50 | jq -c '.records[0] // {}')"
  jq -nc --arg a1 "$(addr_of m)" --arg a2 "$addr2" --argjson rec "$rec" --argjson e "$exp_rc" --argjson i "$imp_rc" '{old_address:$a1, new_address:$a2, export_exit:$e, import_exit:$i, pre_migration_message_as_seen_by_new_instance:$rec}' > "$RES/evidence/migration.json"
  if [ "$exp_rc" = 0 ] && [ "$imp_rc" = 0 ] && [ "$addr2" = "$(addr_of m)" ] && [ "$(echo "$rec" | jq -r .body)" = "sent-while-old-instance-was-down" ] && [ "$(echo "$rec" | jq -r .sender)" = "$(addr_of a)" ]; then
    pass "X.migrate" "identity exported (age passphrase file) with the daemon stopped, imported into a fresh data dir: same address ($addr2); a message A sent after the old instance stopped and before the import was recovered from Store and decrypted by the NEW instance with sender authenticated as A (quarantined=$(echo "$rec" | jq -r .quarantined): contacts are not part of the export, so the new data dir learns A's contact record after start and a message processed before that is quarantined, after that it is accepted; both outcomes show it decrypted)" \
      "agentnet identity export --out F --passphrase-file P (daemon stopped); agentnet --data-dir new identity import --in F --passphrase-file P; agentnet serve; agentnet inbox --include-quarantined" true
  else fail "X.migrate" "export=$exp_rc import=$imp_rc addr=$addr2 expected=$(addr_of m) record=$rec" "identity export/import" true; fi
  stop_daemon m2
}

# ================================================================== main
for s in $STEPS; do
  case " $STEPS " in *" 1 "*) ;; *) STEPS="1 $STEPS";; esac
done
for s in $STEPS; do
  case $s in
    1) step1 || { log "step 1 failed; later steps need it"; break; };;
    2) step2 || true;;
    3) step3 || true;;
    4) step4 || true;;
    5) step5 || true;;
    6) step6 || true;;
    X) stepX || true;;
  esac
done
log "done; results in $RES"
