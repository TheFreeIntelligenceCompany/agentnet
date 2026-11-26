#!/usr/bin/env bash
# Shared helpers for the network SIMULATIONS (spike/relay-wireguard/run.sh, spike/relay-nat/run.sh). Source me.
#
# Everything here is a single-host simulation (containers on one colima VM); see the README of each simulation for what it does
# and does not show. Process handling is cribbed from scripts/acceptance.sh.
#
# The caller sets before sourcing: SIM (short name, e.g. wireguard), RES (results directory), ROOT (repo root),
# CAP_PREFIX (container name prefix for tcpdump sidecars, e.g. an-wg-cap), TOOLS_IMG (default an-net-tools:local).

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BIN_DIR="${BIN_DIR:-$ROOT/target/release}"
BIN="$BIN_DIR/agentnet"
DRV="$BIN_DIR/agentnet-acceptance"
TOOLS_IMG="${TOOLS_IMG:-an-net-tools:local}"
WORK="${WORK:-$(mktemp -d /tmp/an-net.XXXXXX)}"      # short path: unix socket paths are limited to ~100 bytes
mkdir -p "$WORK/pids" "$RES"/{logs,evidence,daemon-logs,pcap}
: > "$RES/checks.jsonl"; : > "$RES/notes.txt"; : > "$RES/run.log"
RC=0; OUT=""; ERR=""; WAITED_MS=0

now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }
now_ns() { perl -MTime::HiRes=time -e 'printf "%.0f\n", time*1e9'; }
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$RES/run.log" >&2; }
note() { printf '%s\t%s\n' "$1" "$2" >> "$RES/notes.txt"; }

# check ID STATUS DETAIL [COMMAND]
check() {
  jq -nc --arg id "$1" --arg s "$2" --arg d "$3" --arg c "${4:-}" --arg t "$(date -u +%FT%TZ)" \
    '{id:$id,status:$s,detail:$d,command:$c,at:$t}' >> "$RES/checks.jsonl"
  log "CHECK $1 $2 - $3"
}
pass() { check "$1" PASS "$2" "${3:-}"; }
fail() { check "$1" FAIL "$2" "${3:-}"; }
untested() { check "$1" UNTESTED "$2" "${3:-}"; }

# q LOGNAME cmd... : run, capture stdout in $OUT, stderr in $ERR, exit code in $RC; appended to logs/LOGNAME.log
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
peers_json() { curl -s -m 5 "$1/admin/v1/peers"; }
# connected_ids URL -> sorted peer ids that are Connected
connected_ids() { peers_json "$1" | jq -r '[.[]|select(.connected=="Connected")|.multiaddr|split("/p2p/")[-1]]|sort|join(",")'; }
peer_connected() { peers_json "$1" | jq -e --arg id "$2" 'any(.[]; (.multiaddr|endswith($id)) and .connected=="Connected")' >/dev/null; }

redact() { sed -E 's/[0-9a-fA-F]{64}/<redacted-64hex>/g'; }
save_daemon_log() { [ -f "$WORK/$1.stderr" ] && redact < "$WORK/$1.stderr" > "$RES/daemon-logs/$1.log" || true; }

# ------------------------------------------------------------------ agents and daemons (one node per agent)
an() { local d=$1; shift; "$BIN" --data-dir "$WORK/$d" "$@"; }
anj() { local d=$1; shift; "$BIN" --json --data-dir "$WORK/$d" "$@"; }
addr_of() { cat "$WORK/$1.addr"; }

# new_agent NAME NODE_URL PEER_MADDR
new_agent() {
  local n=$1 url=$2 peer=$3
  rm -rf "${WORK:?}/$n"
  "$BIN" --json --data-dir "$WORK/$n" init --node-url "$url" --peer "$peer" > "$WORK/$n.init.json" 2>"$WORK/$n.init.err" || { cat "$WORK/$n.init.err" >&2; return 1; }
  jq -r .address "$WORK/$n.init.json" > "$WORK/$n.addr"
  anj "$n" identity show | jq -r .contact_record > "$WORK/$n.record"
  anj "$n" identity show | jq -r .inbox_topic > "$WORK/$n.topic"
  log "agent $n: $(addr_of "$n") node=$url inbox_topic=$(cat "$WORK/$n.topic")"
}
net_ready() { anj "$1" network status 2>/dev/null | jq -e '.network.ready==true' >/dev/null; }
start_daemon() { # NAME [nowait]; sets STARTUP_MS
  local n=$1 t0; t0=$(now_ms)
  RUST_LOG=info "$BIN" --data-dir "$WORK/$n" serve >/dev/null 2>>"$WORK/$n.stderr" &
  echo $! > "$WORK/pids/$n"; echo "$t0" > "$WORK/$n.t0"
  if [ "${2:-}" = nowait ]; then STARTUP_MS=-1; return 0; fi
  if wait_for 300 "daemon $n ready" net_ready "$n"; then
    STARTUP_MS=$(( $(now_ms) - t0 )); printf '%s\t%s\t%s\n' "$n" "$(date -u +%FT%TZ)" "$STARTUP_MS" >> "$RES/evidence/startup-times.tsv"; return 0
  fi
  STARTUP_MS=-1; return 1
}
ready_wait() { # name [secs]: wait for ready after a nowait start; sets STARTUP_MS = spawn -> ready
  local n=$1
  if wait_for "${2:-300}" "daemon $n ready" net_ready "$n"; then
    STARTUP_MS=$(( $(now_ms) - $(cat "$WORK/$n.t0") )); printf '%s\t%s\t%s\n' "$n" "$(date -u +%FT%TZ)" "$STARTUP_MS" >> "$RES/evidence/startup-times.tsv"; return 0
  fi
  return 1
}
daemon_pid() { cat "$WORK/pids/$1" 2>/dev/null || true; }
stop_daemon() {
  local n=$1 pid i; pid="$(daemon_pid "$n")"
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 400); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then log "daemon $n did not exit in 40 s, SIGKILL"; kill -KILL "$pid" 2>/dev/null || true; fi
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
all_in_state() { local d=$1 s=$2 id; shift 2; for id in "$@"; do [ "$(mstate "$d" "$id")" = "$s" ] || return 1; done; }
count_states() { local d=$1 id; shift; for id in "$@"; do mstate "$d" "$id"; done | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}'; }
state_is() { [ "$(mstate "$1" "$2")" = "$3" ]; }
inbox_count() { anj "$1" inbox --conversation "$2" --limit 200 | jq '.records|length'; }
inbox_is() { [ "$(inbox_count "$1" "$2")" = "$3" ]; }
inbox_dump() { "$DRV" dump --data-dir "$WORK/$1" --idle-ms 1500; }
mcp() { "$DRV" mcp-call --bin "$BIN" --data-dir "$WORK/$1" --tool "$2" --args "${3:-{\}}"; }

# ------------------------------------------------------------------ packet capture (tcpdump on a docker bridge, run from the colima VM netns)
# cap_start TAG BRIDGE : file $RES/pcap/TAG-BRIDGE.pcap, container ${CAP_PREFIX}-TAG-BRIDGE
cap_start() {
  local tag=$1 br=$2
  docker rm -f "${CAP_PREFIX}-$tag-$br" >/dev/null 2>&1 || true
  docker run -d --name "${CAP_PREFIX}-$tag-$br" --net host --cap-add NET_RAW --cap-add NET_ADMIN -v "$RES/pcap":/out "$TOOLS_IMG" \
    sh -c "exec tcpdump -i $br -nn -s 0 -U -w /out/$tag-$br.pcap" >> "$RES/logs/docker.log" 2>&1
}
cap_stop() {
  local tag=$1 br=$2
  sleep 1
  docker stop -t 10 "${CAP_PREFIX}-$tag-$br" >> "$RES/logs/docker.log" 2>&1 || true
  docker rm -f "${CAP_PREFIX}-$tag-$br" >/dev/null 2>&1 || true
}
cap_cleanup() { local c; for c in $(docker ps -a --format '{{.Names}}' | grep "^${CAP_PREFIX}-" || true); do docker rm -f "$c" >/dev/null 2>&1; done; }
# cap_count FILE "bpf" -> number of packets in the pcap matching the filter (stdout); the exact filter is the caller's evidence
cap_count() {
  docker run --rm -v "$RES/pcap":/out "$TOOLS_IMG" sh -c "tcpdump -nn -r /out/$1 '$2' 2>/dev/null | wc -l" | tr -d ' \r'
}
# cap_list FILE "bpf" OUTFILE : write the matching packets (one line each) for the record
cap_list() {
  docker run --rm -v "$RES/pcap":/out "$TOOLS_IMG" sh -c "tcpdump -nn -r /out/$1 '$2' 2>/dev/null" > "$3" 2>&1 || true
}
# cap_flows FILE OUTFILE : distinct (src ip, dst ip:port) with packet counts; ephemeral ports (>=32768) are collapsed to *
cap_flows() {
  docker run --rm -v "$RES/pcap":/out "$TOOLS_IMG" sh -c "tcpdump -nn -q -r /out/$1 'ip' 2>/dev/null | awk '{print \$3, \$4, \$5}' | sed -E 's/:\$//; s/^([0-9.]+)\.[0-9]+ >/\1 >/; s/ ([0-9.]+)\.([0-9]+)\$/ \1:\2/; s/:(3[2-9][0-9]{3}|[4-6][0-9]{4})\$/:*/' | sort | uniq -c | sort -rn" > "$2" 2>&1 || true
}
# cap_grep FILE STRING [bpf] -> number of packets (matching the optional bpf) whose payload contains STRING (ascii dump)
cap_grep() {
  docker run --rm -v "$RES/pcap":/out "$TOOLS_IMG" sh -c "tcpdump -nn -A -r /out/$1 ${3:+'$3'} 2>/dev/null | grep -a -c -- '$2' || true" | tr -d ' \r'
}
# fix ownership of root-written capture files if the host cannot read them
cap_fix_perms() { docker run --rm -v "$RES/pcap":/out "$TOOLS_IMG" sh -c 'chmod -R a+rwX /out' >/dev/null 2>&1 || true; }

# ------------------------------------------------------------------ summary
# The caller defines: SIM_TITLE, SCOPE_BANNER (markdown paragraph), step_title ID, ENV_JSON (json object string)
write_summary() {
  local f="$RES/summary.json" md="$RES/SUMMARY.md" s
  jq -s --argjson env "${ENV_JSON:-{\}}" --arg ts "${TS:-}" '
    def worst(c): if any(c[]; .status=="FAIL") then "FAIL" elif (c|length)==0 then "UNTESTED" elif all(c[]; .status=="UNTESTED") then "UNTESTED" else "PASS" end;
    . as $all
    | {run_timestamp:$ts, environment:$env,
       steps: ([$all[]|.id|split(".")[0]] | unique | map(. as $s | {step:$s, status: worst([$all[]|select((.id|split(".")[0])==$s)]), checks: [$all[]|select((.id|split(".")[0])==$s)]})),
       totals: {PASS:([$all[]|select(.status=="PASS")]|length), FAIL:([$all[]|select(.status=="FAIL")]|length), UNTESTED:([$all[]|select(.status=="UNTESTED")]|length)}}
  ' "$RES/checks.jsonl" > "$f" 2>/dev/null || echo '{"error":"summary generation failed"}' > "$f"
  {
    echo "# ${SIM_TITLE:-Network simulation} run ${TS:-}"
    echo
    echo "${SCOPE_BANNER:-}"
    echo
    echo "Environment: $(jq -c '.environment' "$f" 2>/dev/null)"
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
      jq -r --arg s "$s" '.steps[]|select(.step==$s)|.checks[]|"| \(.id) | \(.status) | \(.detail|gsub("\\|";"/")|gsub("\n";" ")) |"' "$f"
      echo
      echo "Exact commands:"
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
    echo "- \`logs/\` per-step command logs, \`evidence/\` JSON/text evidence, \`daemon-logs/\` redacted daemon stderr, \`pcap/\` captures and the filter outputs derived from them"
  } > "$md"
}
