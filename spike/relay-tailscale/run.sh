#!/usr/bin/env bash
# Experiment T1: Logos Delivery relay announced and dialled on this host's REAL Tailscale address (SINGLE HOST).
#
#   ./run.sh                 # results in results/tailscale/<UTC timestamp>/
#   BIN_DIR=/path/to/target/release ./run.sh
#   KEEP_UP=1 ./run.sh       # leave containers + forwarder running (default: everything removed)
#   N_MSGS=20 ./run.sh
#
# WHAT THIS PROVES: the relay can be configured with a real tailnet address (--nat=extip:<ts ip>), reachable on that address and NOT
# on 127.0.0.1 / the LAN address, clients dial it, AgentNet works on it. WHAT IT DOES NOT PROVE: cross-machine transport, ACLs, DERP,
# NAT traversal, key expiry. On one host, client->relay packets do not cross a WireGuard tunnel. Those rows stay UNTESTED.
#
# Read-only Tailscale commands only (status, ip, netcheck is not used). It never changes Tailscale settings.
# Touches only containers/networks/volumes named an-ts*. Evidence is scrubbed (tailnet IPs, device names, user names) at the end.
set -uo pipefail

SIM=tailscale
SIMDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SIMDIR/../.." && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="${RESULTS_DIR:-$ROOT/results/tailscale/$TS}"
CAP_PREFIX=an-ts-cap
SIM_TITLE="AgentNet single-host Tailscale-address run"
SCOPE_BANNER='> **Scope: ONE HOST, real tailnet address.** This run proves configuration with a real tailnet address and that the relay port is bound to the tailnet interface only. It does **NOT** prove cross-machine transport, Tailscale ACLs, DERP relays or NAT traversal (all **UNTESTED**), and client-to-relay packets on one host do **not** cross a WireGuard tunnel (same-host delivery). Amd64 Logos Delivery nodes under qemu in a colima VM on an arm64 Mac. Tailnet IPv4 is shown as `<TS_IP>`, device names as `<host-a>`, `<host-b>`, ...'
N_MSGS="${N_MSGS:-20}"
RELAY_FWD_PORT="${RELAY_FWD_PORT:-61000}"
TSCLI=/Applications/Tailscale.app/Contents/MacOS/Tailscale
export DNS_NS=127.0.0.1
unset AGENTNET_HOME RUST_LOG || true
. "$SIMDIR/../netsim-lib.sh"

R=http://127.0.0.1:18671; NA=http://127.0.0.1:18672; NB=http://127.0.0.1:18673
RID=""; FWD_PID=""; TS_IP=""
compose() { ( cd "$SIMDIR" && docker-compose --env-file .run/env "$@" ); }
step_title() {
  case $1 in
    1) echo "Binding, nodes connected to R on the tailnet address";;
    2) echo "End to end: contacts, send/reply (CLI and MCP), 20 messages each way";;
    3) echo "Reachability matrix of the relay port from the host";;
    4) echo "Tailnet status";;
    5) echo "Path honesty and what is not tested";;
  esac
}

# ------------------------------------------------------------------ scrub (evidence is committed to a PUBLIC repo)
scrub_tree() {
  local d=$1 f ip i=0 sed1="$WORK/scrub.sed"
  local letters=(b c d e f g h i j k l m n o p)
  : > "$sed1"
  # 1. device names (this host -> <host-a>, others -> <host-b>, ...) and logins, read in memory from the tailnet status, never written out
  while read -r a b c _; do
    case "$a" in 100.*)
      [ -n "$b" ] || continue
      if [ "$a" = "$TS_IP" ]; then echo "s/$b/<host-a>/g" >> "$sed1"; else echo "s/$b/<host-${letters[$i]:-z}>/g" >> "$sed1"; i=$((i+1)); fi
      [ -n "$c" ] && echo "s/${c%@}/<user>/g" >> "$WORK/scrub-users.sed";;
    esac
  done < <("$TSCLI" status 2>/dev/null)
  echo "s/$(hostname -s)/<host-a>/g" >> "$sed1"
  # 2. addresses: tailnet IPs, LAN addresses
  for ip in $("$TSCLI" status 2>/dev/null | awk '$1 ~ /^100\./ {print $1}'); do
    if [ "$ip" = "$TS_IP" ]; then echo "s/${ip//./\\.}/<TS_IP>/g" >> "$sed1"; else echo "s/${ip//./\\.}/<peer-ip>/g" >> "$sed1"; fi
  done
  for ip in $(ifconfig | awk '/inet / && $2 !~ /^127\./ && $2 !~ /^100\./ {print $2}'); do echo "s/${ip//./\\.}/<LAN_IP>/g" >> "$sed1"; done
  # 3. user / login names last (device names above may contain them)
  [ -f "$WORK/scrub-users.sed" ] && sort -u "$WORK/scrub-users.sed" >> "$sed1"
  echo "s#/Users/$(id -un)#/Users/<user>#g; s/$(id -un)/<user>/g" >> "$sed1"
  grep -rIl . "$d" 2>/dev/null | while read -r f; do sed -i.bak -f "$sed1" "$f" && rm -f "$f.bak"; done
}
scrub_verify() { # exit 0 when no forbidden string remains under $1
  local d=$1 bad=0 s
  : > "$WORK/forbidden.txt"
  [ -n "$TS_IP" ] && echo "$TS_IP" >> "$WORK/forbidden.txt"
  "$TSCLI" status 2>/dev/null | awk '$1 ~ /^100\./ {print $1; print $2; sub(/@$/,"",$3); print $3}' >> "$WORK/forbidden.txt"
  ifconfig | awk '/inet / && $2 !~ /^127\./ {print $2}' >> "$WORK/forbidden.txt"
  id -un >> "$WORK/forbidden.txt"; hostname -s >> "$WORK/forbidden.txt"
  while read -r s; do
    [ -n "$s" ] || continue
    if grep -rIFl -- "$s" "$d" > "$WORK/hit.txt" 2>/dev/null && [ -s "$WORK/hit.txt" ]; then bad=1; log "SCRUB: forbidden string found in: $(tr '\n' ' ' < "$WORK/hit.txt")"; fi
  done < <(sort -u "$WORK/forbidden.txt")
  return $bad
}

# ------------------------------------------------------------------ cleanup
cleanup() {
  local rc=$? n
  set +e +u
  log "cleanup (exit status of script body: $rc)"
  for n in $(ls "$WORK/pids" 2>/dev/null); do stop_daemon "$n"; done
  for n in "$WORK"/*.stderr; do [ -e "$n" ] && save_daemon_log "$(basename "$n" .stderr)"; done
  mkdir -p "$RES/evidence/container-logs"
  for n in an-ts-r-node an-ts-a-node an-ts-b-node; do docker logs "$n" 2>&1 | redact > "$RES/evidence/container-logs/$n.log" 2>/dev/null; done
  if [ "${KEEP_UP:-0}" != 1 ]; then
    [ -n "$FWD_PID" ] && kill "$FWD_PID" 2>/dev/null
    compose down -v >> "$RES/logs/docker.log" 2>&1
    docker ps -a --format '{{.Names}}' | grep '^an-ts' | while read -r c; do log "WARNING: leftover container $c"; done
    docker network ls --format '{{.Name}}' | grep '^an-ts' | while read -r c; do log "WARNING: leftover network $c"; done
    docker volume ls --format '{{.Name}}' | grep '^an-ts' | while read -r c; do log "WARNING: leftover volume $c"; done
  fi
  [ "${KEEP_RUN:-0}" = 1 ] || { [ -d "$SIMDIR/.run" ] && rm -f "$SIMDIR"/.run/*; }
  ENV_JSON="$(jq -nc --arg host "$(uname -srm)" --arg bin "$("$BIN" --version 2>&1)" \
    '{host:$host, agentnet:$bin, node_image:"wakuorg/nwaku@sha256:cb4d14a2... v0.39.2 linux/amd64 under qemu in colima (linux/arm64 VM)", topology:"R + A + B nodes in colima; R announces and is dialled on the host tailnet IPv4 <TS_IP>:60000 (host forwarder bound to that address only); agents on the host via 127.0.0.1 REST ports 18671-18673", caveat:"other docker work (an-wg*, rust build) was running concurrently on the same VM: latencies are not clean"}')"
  write_summary
  scrub_tree "$RES"
  if scrub_verify "$RES"; then log "scrub verification: clean"; else log "scrub verification: FAILED"; echo SCRUB_FAILED > "$RES/SCRUB_FAILED"; fi
  rm -rf "${WORK:?}"
  if jq -e -s 'any(.[]; .status=="FAIL")' "$RES/checks.jsonl" >/dev/null 2>&1; then exit 1; fi
  exit 0
}
trap cleanup EXIT
trap 'log "interrupted"; exit 130' INT TERM

# ------------------------------------------------------------------ prerequisites
for t in docker docker-compose jq curl python3 openssl perl colima lsof nc; do command -v "$t" >/dev/null || { echo "missing prerequisite: $t" >&2; exit 2; }; done
for f in "$BIN" "$DRV" "$TSCLI"; do [ -x "$f" ] || { echo "missing $f" >&2; exit 2; }; done
TS_IP="$("$TSCLI" ip -4 2>/dev/null)"
[ -n "$TS_IP" ] || { echo "no tailnet IPv4 (is Tailscale up?)" >&2; exit 2; }
log "results: $RES   work dir: $WORK"
log "SCOPE: ONE HOST with a real tailnet address. NOT cross-machine, NOT ACLs, NOT DERP, NOT NAT traversal."
"$BIN" --version > "$RES/evidence/versions.txt" 2>&1
{ docker --version; docker-compose --version; uname -a; jq --version; } >> "$RES/evidence/versions.txt" 2>&1
mkdir -p "$SIMDIR/.run"; chmod 700 "$SIMDIR/.run"; printf "R_KEY=0\nA_KEY=0\nB_KEY=0\nR_PEER_ID=0\nTS_IP=$TS_IP\nRELAY_FWD_PORT=$RELAY_FWD_PORT\n" > "$SIMDIR/.run/env"
compose down -v >> "$RES/logs/docker.log" 2>&1 || true

# ================================================================== STEP 1
step1() {
  log "=== STEP 1: bind, bring up"
  local e="$RES/evidence"
  # ---- binding findings (facts, not a pass/fail of the product)
  docker run -d --rm --name an-ts-probe -p "$TS_IP:60999:60999" an-net-tools:local sleep 30 > "$e/bind-probe-tailnet-ip.txt" 2>&1; echo "[exit $?]" >> "$e/bind-probe-tailnet-ip.txt"
  docker rm -f an-ts-probe >/dev/null 2>&1
  colima ssh -- ip -4 -o addr > "$e/colima-vm-addresses.txt" 2>&1
  ifconfig | awk '/^[a-z0-9]+:/ {i=$1} /inet / {print i, $2}' > "$e/host-interfaces.txt"
  if grep -q 'cannot assign requested address' "$e/bind-probe-tailnet-ip.txt" && ! grep -q "$TS_IP" "$e/colima-vm-addresses.txt"; then
    pass "1.bind_tailnet_ip_in_vm" "docker (inside the colima VM) CANNOT publish a port on the host's tailnet IPv4: 'failed to bind host port <TS_IP>:60999/tcp: cannot assign requested address'. The VM's own addresses (evidence/colima-vm-addresses.txt) do not include the tailnet address; docker binds in the VM, not on the macOS host. Workaround used (no colima restart or reconfiguration): R's port is published on the VM loopback, colima forwards it to host 127.0.0.1:$RELAY_FWD_PORT, and spike/relay-tailscale/tcp-forward.py listens ONLY on <TS_IP>:60000 and forwards to it." "docker run -p <TS_IP>:60999:60999 an-net-tools:local ; colima ssh -- ip -4 -o addr"
  else
    fail "1.bind_tailnet_ip_in_vm" "unexpected result of the bind probe (evidence/bind-probe-tailnet-ip.txt): colima/docker may now bind the tailnet address directly; revisit the workaround"
  fi
  # ---- keys
  { echo "R_KEY=$(openssl rand -hex 32)"; echo "A_KEY=$(openssl rand -hex 32)"; echo "B_KEY=$(openssl rand -hex 32)"
    echo "R_PEER_ID=pending"; echo "TS_IP=$TS_IP"; echo "RELAY_FWD_PORT=$RELAY_FWD_PORT"; } > "$SIMDIR/.run/env"; chmod 600 "$SIMDIR/.run/env"
  compose up -d node-r >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "R node health" health "$R" || { fail "1.setup" "R's node did not become healthy"; return 1; }
  RID="$(curl -s -m 5 "$R/info" | jq -r '.listenAddresses[0]|split("/p2p/")[1]')"
  echo "$RID" > "$e/r-peer-id.txt"
  sed -i.bak "s/^R_PEER_ID=.*/R_PEER_ID=$RID/" "$SIMDIR/.run/env" && rm -f "$SIMDIR/.run/env.bak"
  curl -s "$R/info" | jq 'del(.enrUri)' > "$e/r-info.json"
  # ---- the host-side forwarder bound ONLY to the tailnet address
  python3 -I "$SIMDIR/tcp-forward.py" "$TS_IP" 60000 "$RELAY_FWD_PORT" > "$WORK/fwd.log" 2>&1 &
  FWD_PID=$!; sleep 2
  kill -0 "$FWD_PID" 2>/dev/null || { fail "1.setup" "forwarder did not start: $(cat "$WORK/fwd.log")"; return 1; }
  compose up -d node-a node-b >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "A node health" health "$NA"; wait_for 120 "B node health" health "$NB"
  wait_for 240 "A connected to R" peer_connected "$NA" "$RID"; local ta=$WAITED_MS
  wait_for 240 "B connected to R" peer_connected "$NB" "$RID"; local tb=$WAITED_MS
  docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | grep '^an-ts' > "$e/containers.txt"
  peers_json "$NA" > "$e/peers-a-initial.json"; peers_json "$NB" > "$e/peers-b-initial.json"; peers_json "$R" > "$e/peers-r-initial.json"
  local want pa pb
  want="[\"/ip4/$TS_IP/tcp/60000/p2p/$RID\"]"
  pa="$(jq -c '[.[]|select(.connected=="Connected")]|map(.multiaddr)' "$e/peers-a-initial.json")"
  pb="$(jq -c '[.[]|select(.connected=="Connected")]|map(.multiaddr)' "$e/peers-b-initial.json")"
  if [ "$pa" = "$want" ] && [ "$pb" = "$want" ] && [ "$(jq length "$e/peers-a-initial.json")" = 1 ] && [ "$(jq length "$e/peers-b-initial.json")" = 1 ]; then
    pass "1.nodes_connected" "A's node lists exactly one peer, R, as /ip4/<TS_IP>/tcp/60000 (connected after ${ta} ms from the wait start); B's node likewise (${tb} ms). R's node lists: $(jq -c '[.[]|{multiaddr,connected}]' "$e/peers-r-initial.json")" "curl http://127.0.0.1:18672/admin/v1/peers ; :18673 ; :18671"
  else fail "1.nodes_connected" "A: $pa  B: $pb (want $want; evidence/peers-*-initial.json)" "curl .../admin/v1/peers"; fi
}

# ================================================================== STEP 2
step2() {
  log "=== STEP 2: agents, contacts, messaging"
  local peer="/ip4/$TS_IP/tcp/60000/p2p/$RID"
  new_agent a "$NA" "$peer"; new_agent b "$NB" "$peer"
  start_daemon a nowait; start_daemon b nowait
  local ok=1; ready_wait a || ok=0; ready_wait b || ok=0
  if [ $ok = 1 ]; then pass "2.serve" "two release-mode 'agentnet serve' (A -> $NA, B -> $NB), private mode, peer allowlist = R only ($peer), cluster 66; A=$(addr_of a) B=$(addr_of b); ready after A $(tail -n 2 "$RES/evidence/startup-times.tsv" | head -n 1 | cut -f3) ms / B $(tail -n 1 "$RES/evidence/startup-times.tsv" | cut -f3) ms (qemu nodes, concurrent docker load)" \
    "agentnet --data-dir \$A init --node-url $NA --peer $peer; agentnet --data-dir \$B init --node-url $NB --peer $peer; agentnet serve (x2)"
  else fail "2.serve" "a daemon did not become ready"; return 1; fi
  contact_exchange a b && contact_exchange b a && pass "2.contacts" "contact records exchanged with 'contact add @record --expect <address>' both ways" "agentnet contact add @b.record --expect <B>; agentnet contact add @a.record --expect <A>" \
    || fail "2.contacts" "contact add failed: $ERR"
  local d
  for d in a b; do
    q step2-doctor "$BIN" --data-dir "$WORK/$d" doctor; local drc=$RC
    cp "$RES/logs/step2-doctor.log" "$RES/evidence/doctor-$d.txt"
    q step2-netstatus "$BIN" --json --data-dir "$WORK/$d" network status --verbose; printf '%s\n' "$OUT" > "$RES/evidence/network-status-$d.json"
    if printf '%s' "$OUT" | jq -e --arg id "$RID" '.network.ready==true and .network.mode=="private" and (.network.isolation_violation==null) and ((.network.peers//[])|length==1) and ((.network.peers//[])[0]|contains($id))' >/dev/null && [ "$drc" = 0 ]; then
      pass "2.netstatus.$d" "agentnet doctor exit 0 (clean); network status: private, ready, no isolation violation, exactly one peer = R ($RID)" "agentnet doctor; agentnet --json network status --verbose"
    else fail "2.netstatus.$d" "doctor exit $drc; network: $(printf '%s' "$OUT" | jq -c .network 2>/dev/null)" "agentnet doctor; network status --verbose"; fi
  done
  local t0 id1; t0=$(now_ms); id1="$(send a b "t-first-cli" --conversation t-first)"
  if wait_for 300 "first message delivered" state_is a "$id1" delivered; then
    pass "2.cli_send" "A -> B via 'agentnet send': delivered (authenticated receipt) after $WAITED_MS ms (FIRST message on a fresh topology: includes relay-mesh warm-up, not a typical latency)" "agentnet --json send <B> t-first-cli; agentnet --json status <id>"
  else fail "2.cli_send" "not delivered within 300 s; state $(mstate a "$id1")" "agentnet send"; fi
  local rb; rb="$(anj b inbox --conversation t-first --limit 10)"; echo "$rb" > "$RES/evidence/b-inbox-first.json"
  if [ "$(echo "$rb" | jq '.records|length')" = 1 ] && [ "$(echo "$rb" | jq -r '.records[0].sender')" = "$(addr_of a)" ] && [ "$(echo "$rb" | jq -r '.records[0].body')" = "t-first-cli" ]; then
    pass "2.inbox_auth" "B's inbox holds the message, sender authenticated as A ($(addr_of a)), body intact" "agentnet --json inbox --conversation t-first"
  else fail "2.inbox_auth" "B inbox: $(echo "$rb" | jq -c '.records')" "agentnet inbox"; fi
  local idr; idr="$(send b a "t-reply-cli" --conversation t-first)"
  if wait_for 120 "reply delivered" state_is b "$idr" delivered && [ "$(anj a inbox --conversation t-first --limit 10 | jq -r '[.records[]|select(.body=="t-reply-cli")]|length')" = 1 ]; then
    pass "2.reply" "B -> A reply delivered (receipt after $WAITED_MS ms) and present in A's inbox" "agentnet send <A> t-reply-cli (from B)"
  else fail "2.reply" "reply state $(mstate b "$idr")" "agentnet send (B->A)"; fi
  q step2-mcp "$DRV" step2 --bin "$BIN" --a "$WORK/a" --b "$WORK/b" --b-addr "$(addr_of b)" --out "$RES/evidence/step2-mcp.json"
  if [ "$RC" = 0 ] && [ "$(jq -r '.A_status_timeline[-1].state' "$RES/evidence/step2-mcp.json")" = delivered ]; then
    pass "2.mcp" "A -> B via MCP send_message (rmcp over stdio, negotiated $(jq -r '.protocol_client_A.negotiated_protocol_version' "$RES/evidence/step2-mcp.json")): B's subscriptions/listen notified after $(jq -r .latency_ms.B_resource_notification "$RES/evidence/step2-mcp.json") ms, B read_inbox at +$(jq -r .latency_ms.B_read_inbox_returned "$RES/evidence/step2-mcp.json") ms, A status delivered at +$(jq -r .latency_ms.A_status_delivered "$RES/evidence/step2-mcp.json") ms" "agentnet-acceptance step2 --bin agentnet --a \$A --b \$B --b-addr <B>"
  else fail "2.mcp" "step2 driver failed (exit $RC): $(printf '%s' "$OUT" | jq -r .error 2>/dev/null)" "agentnet-acceptance step2"; fi
  q step2-bench "$DRV" bench --a "$WORK/a" --b "$WORK/b" --a-addr "$(addr_of a)" --b-addr "$(addr_of b)" --n "$N_MSGS" --timeout 600 --pace-ms 400 --tag t --out "$RES/evidence/bench.json"
  sleep 5
  inbox_dump b > "$RES/evidence/b-dump.json" 2>/dev/null; inbox_dump a > "$RES/evidence/a-dump.json" 2>/dev/null
  local ab_rows ab_u ba_rows ba_u dupev dir lbl dl
  ab_rows="$(jq '[.inbox.records[]|select(.conversation_id=="t-a2b")]|length' "$RES/evidence/b-dump.json")"; ab_u="$(jq '[.inbox.records[]|select(.conversation_id=="t-a2b")|.message_id]|unique|length' "$RES/evidence/b-dump.json")"
  ba_rows="$(jq '[.inbox.records[]|select(.conversation_id=="t-b2a")]|length' "$RES/evidence/a-dump.json")"; ba_u="$(jq '[.inbox.records[]|select(.conversation_id=="t-b2a")|.message_id]|unique|length' "$RES/evidence/a-dump.json")"
  dupev=$(( $(jq .events.duplicate_message_received_events "$RES/evidence/b-dump.json") + $(jq .events.duplicate_message_received_events "$RES/evidence/a-dump.json") ))
  for dir in a_to_b b_to_a; do
    lbl="${dir//_to_/ -> }"; dl="$(jq ".$dir.delivered" "$RES/evidence/bench.json")"
    if [ "$dl" = "$N_MSGS" ]; then
      pass "2.bench.$dir" "$lbl: delivered $dl/$N_MSGS (authenticated receipts), send->receipt latency p50/p95/p99 = $(jq -r ".$dir.latency_ms_send_to_delivered|\"\(.p50)/\(.p95)/\(.p99)\"" "$RES/evidence/bench.json") ms (min $(jq ".$dir.latency_ms_send_to_delivered.min" "$RES/evidence/bench.json"), max $(jq ".$dir.latency_ms_send_to_delivered.max" "$RES/evidence/bench.json")), paced 400 ms, both directions concurrently; qemu nodes, other docker work running concurrently" "agentnet-acceptance bench --n $N_MSGS --pace-ms 400 --tag t"
    else fail "2.bench.$dir" "$lbl delivered $dl/$N_MSGS (see evidence/bench.json)" "agentnet-acceptance bench"; fi
  done
  if [ "$ab_rows" = "$N_MSGS" ] && [ "$ab_u" = "$N_MSGS" ] && [ "$ba_rows" = "$N_MSGS" ] && [ "$ba_u" = "$N_MSGS" ] && [ "$dupev" = 0 ]; then
    pass "2.duplicates" "receiver inbox rows A->B $ab_rows (unique $ab_u), B->A $ba_rows (unique $ba_u); duplicate message.received events: $dupev" "agentnet-acceptance dump --data-dir \$B / \$A"
  else fail "2.duplicates" "rows A->B $ab_rows/$ab_u, B->A $ba_rows/$ba_u, duplicate events $dupev" "agentnet-acceptance dump"; fi
}

# ================================================================== STEP 3
probe() { # ip port -> prints "answers" or "no answer (exit N)"
  local out rc; out="$(nc -z -w 3 "$1" "$2" 2>&1)"; rc=$?
  if [ $rc = 0 ]; then echo "answers"; else echo "no answer (nc exit $rc: $out)"; fi
}
step3() {
  log "=== STEP 3: reachability matrix"
  local e="$RES/evidence" lan ips line ok=1 detail="" ip
  lsof -nP -iTCP:60000 -sTCP:LISTEN > "$e/lsof-60000.txt" 2>&1; echo "[exit $?]" >> "$e/lsof-60000.txt"
  lsof -nP -iTCP:"$RELAY_FWD_PORT" -sTCP:LISTEN > "$e/lsof-$RELAY_FWD_PORT.txt" 2>&1; echo "[exit $?]" >> "$e/lsof-$RELAY_FWD_PORT.txt"
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR==1 || /:(18671|18672|18673|60000|61000) /' > "$e/lsof-all-an-ts-listeners.txt"
  ips="$(ifconfig | awk '/inet / {print $2}')"
  : > "$e/reachability-matrix.txt"
  local want_ans="$TS_IP"
  for ip in $ips; do
    line="$(probe "$ip" 60000)"; echo "$ip:60000 $line" >> "$e/reachability-matrix.txt"
    if [ "$ip" = "$want_ans" ]; then [ "$line" = answers ] || ok=0; else [ "$line" = answers ] && ok=0; fi
  done
  line="$(probe 127.0.0.1 60000)"; echo "127.0.0.1:60000 $line (loopback checked explicitly)" >> "$e/reachability-matrix.txt"
  [ "$line" = answers ] && ok=0
  # the forwarder's target port on the loopback: documented residual exposure, loopback only
  line="$(probe 127.0.0.1 "$RELAY_FWD_PORT")"; echo "127.0.0.1:$RELAY_FWD_PORT $line (colima's forward of the VM-loopback publish; loopback only; see README)" >> "$e/reachability-matrix.txt"
  # non-tailnet, non-loopback host addresses on the forwarder's target port and R's REST: must not answer either
  local lanip; for lanip in $(ifconfig | awk '/inet / && $2 !~ /^127\./ && $2 !~ /^100\./ {print $2}'); do
    echo "$lanip:$RELAY_FWD_PORT $(probe "$lanip" "$RELAY_FWD_PORT")" >> "$e/reachability-matrix.txt"
    echo "$lanip:18671 (R REST) $(probe "$lanip" 18671)" >> "$e/reachability-matrix.txt"
  done
  echo "$TS_IP:18671 (R REST) $(probe "$TS_IP" 18671)" >> "$e/reachability-matrix.txt"
  if [ $ok = 1 ] && ! grep -E "^[0-9.]+:($RELAY_FWD_PORT|18671) " "$e/reachability-matrix.txt" | grep -v '^127\.0\.0\.1' | grep -q ' answers'; then
    pass "3.reachability" "tcp/60000: answers on <TS_IP> ONLY; no answer on 127.0.0.1 nor on the host's LAN IPv4(s) (matrix: $(tr '\n' ';' < "$e/reachability-matrix.txt")). Listener on 60000 per lsof: $(awk 'NR>1 {print $1, $9, $10}' "$e/lsof-60000.txt" | sort -u | tr '\n' ';'). Residual: colima's forwarder listens on 127.0.0.1:$RELAY_FWD_PORT (loopback only)." "lsof -nP -iTCP:60000 -sTCP:LISTEN ; nc -z -w 3 <each host IPv4> 60000 ; nc -z 127.0.0.1 60000"
  else fail "3.reachability" "matrix: $(tr '\n' ';' < "$e/reachability-matrix.txt") (evidence/reachability-matrix.txt, lsof-*.txt)" "nc -z -w 3 <ip> 60000"; fi
  if awk 'NR>1 {print $9}' "$e/lsof-60000.txt" | grep -q "^$TS_IP:60000\$" && [ "$(awk 'NR>1' "$e/lsof-60000.txt" | grep -vc "$TS_IP:60000")" = 1 ]; then
    : # the final "[exit N]" line is the only other line
    pass "3.listener" "lsof shows the only listener on tcp/60000 is bound to <TS_IP>:60000 (no wildcard, no loopback, no LAN)" "lsof -nP -iTCP:60000 -sTCP:LISTEN"
  else fail "3.listener" "unexpected listeners (evidence/lsof-60000.txt): $(awk 'NR>1 {print $1, $9}' "$e/lsof-60000.txt" | tr '\n' ';')" "lsof -nP -iTCP:60000 -sTCP:LISTEN"; fi
  # live connections: who is connected to the forwarder (clients come from the colima gateway path, not from utun)
  lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR==1 || /->'"$TS_IP"':60000|'"$TS_IP"':60000->/' > "$e/lsof-established-60000.txt"
}

# ================================================================== STEP 4
step4() {
  log "=== STEP 4: tailnet status (read-only)"
  local e="$RES/evidence" n
  "$TSCLI" status > "$WORK/ts-status.txt" 2>&1; echo "[exit $?]" >> "$WORK/ts-status.txt"
  n="$(awk '$1 ~ /^100\./' "$WORK/ts-status.txt" | wc -l | tr -d ' ')"
  cp "$WORK/ts-status.txt" "$e/tailscale-status.txt"      # scrubbed with the rest of the tree at exit
  "$TSCLI" ip -4 > "$e/tailscale-ip-4.txt" 2>&1
  if [ -n "$TS_IP" ] && awk -v ip="$TS_IP" '$1==ip {f=1} END {exit !f}' "$WORK/ts-status.txt" && ! grep -qiE 'stopped|logged out|NeedsLogin|Tailscale is stopped' "$WORK/ts-status.txt"; then
    pass "4.tailnet_up" "tailscale status lists this host and $((n-1)) other device(s) (not stopped / not logged out); this host's tailnet IPv4 is <TS_IP> (evidence/tailscale-status.txt, scrubbed: device names -> <host-*>, logins -> <user>). Read-only commands only: 'tailscale status', 'tailscale ip -4'." "tailscale status ; tailscale ip -4"
  else fail "4.tailnet_up" "tailscale status did not show an up tailnet (evidence/tailscale-status.txt)" "tailscale status"; fi
}

# ================================================================== STEP 5
step5() {
  log "=== STEP 5: path honesty"
  local e="$RES/evidence" utun
  route -n get "$TS_IP" > "$e/route-get-ts-ip.txt" 2>&1
  utun="$(awk '/interface:/ {print $2}' "$e/route-get-ts-ip.txt")"
  echo "route to <TS_IP> from this host: interface $utun" >> "$e/route-get-ts-ip.txt"
  local tsif; tsif="$(ifconfig | awk -v ip="$TS_IP" '/^[a-z0-9]+:/ {i=$1} index($0, "inet " ip) {sub(":","",i); print i}')"
  ifconfig "$tsif" 2>&1 | awk 'NR==1' > "$e/tailscale-interface.txt"   # first line only: the rest carries tailnet IPv6 identifiers
  # netstat prints one row per address of the interface (truncated names/IPs): keep only the header and the link row
  nsc() { netstat -I "$tsif" -b 2>&1 | awk 'NR<=2'; }
  nsc > "$WORK/ns-idle0.txt"; sleep 10; nsc > "$WORK/ns-idle1.txt"          # 10 s idle baseline
  nsc > "$WORK/ns-before.txt"
  # drive traffic client -> relay through the dialled address and compare the tailnet interface's counters
  local i id ids=""; for i in 1 2 3; do id="$(send a b "t-path-probe-$i" --conversation t-path)"; ids="$ids $id"; sleep 1; done
  # shellcheck disable=SC2086
  wait_for 240 "path probes delivered" all_in_state a delivered $ids
  nsc > "$WORK/ns-after.txt"
  { echo "### idle 10 s: start"; cat "$WORK/ns-idle0.txt"; echo "### idle 10 s: end"; cat "$WORK/ns-idle1.txt"; echo "### before 3 messages"; cat "$WORK/ns-before.txt"; echo "### after 3 messages"; cat "$WORK/ns-after.txt"; } > "$e/tailnet-iface-counters.txt"
  # link row columns: Name Mtu Network Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
  local ib ob ip_i ip_o b a
  ib="$(awk 'NR==2 {print $6+$9}' "$WORK/ns-idle0.txt")"; ob="$(awk 'NR==2 {print $6+$9}' "$WORK/ns-idle1.txt")"
  b="$(awk 'NR==2 {print $6+$9}' "$WORK/ns-before.txt")"; a="$(awk 'NR==2 {print $6+$9}' "$WORK/ns-after.txt")"
  ip_i=$(( $(awk 'NR==2 {print $4}' "$WORK/ns-after.txt") - $(awk 'NR==2 {print $4}' "$WORK/ns-before.txt") ))
  ip_o=$(( $(awk 'NR==2 {print $7}' "$WORK/ns-after.txt") - $(awk 'NR==2 {print $7}' "$WORK/ns-before.txt") ))
  note "5.path" "route to the tailnet address from this host: interface <b>$utun</b> (flags LOCAL: it is this host's own address). $tsif counters (Ibytes+Obytes): idle 10 s delta $(( ${ob:-0} - ${ib:-0} )) bytes; during 3 delivered messages (window = send + wait for receipts) delta $(( ${a:-0} - ${b:-0} )) bytes, packets in +$ip_i / out +$ip_o. The client containers sit in a VM behind the host and reach the relay through the host's own tailnet address, so the traffic is a LOCAL loop (relay forwarder and colima's forwarder both on this host, see evidence/lsof-established-60000.txt: source and destination are both <TS_IP>); whether it is looped through the tailscale TUN device or short-circuited is read here only from the counters and is not proof of either. No packet is shown to leave this machine, and no WireGuard tunnel to another machine is involved."
  pass "5.path_recorded" "recorded, NOT claimed as a tunnel proof: route to <TS_IP> uses interface $utun (LOCAL host route); $tsif idle 10 s delta $(( ${ob:-0} - ${ib:-0} )) bytes vs $(( ${a:-0} - ${b:-0} )) bytes (packets in +$ip_i / out +$ip_o) around 3 delivered messages. Connections to <TS_IP>:60000 are host-local (lsof: both ends <TS_IP>). Same-host delivery: no WireGuard tunnel to another machine was crossed." "route -n get <TS_IP> ; netstat -I $tsif -b (idle, before, after) ; lsof -nP -iTCP -sTCP:ESTABLISHED"
  untested "5.cross_machine" "client on a DIFFERENT tailnet machine reaching R over WireGuard: not run (needs a second machine; kit is spike/relay-tailscale/remote-client.sh + remote-check.sh)"
  untested "5.acl" "Tailscale ACL / grants restricting tcp/60000 to tagged clients: not run; no policy was read or changed"
  untested "5.derp_nat" "DERP relayed path, NAT traversal / hole punching, tailscale ping path type: not run"
  untested "5.key_expiry" "node key expiry or ACL change effect on a live connection: not run"
}

for s in 1 2 3 4 5; do
  case " ${STEPS:-1 2 3 4 5} " in *" $s "*) "step$s" || { log "step $s aborted"; [ "$s" = 1 ] && break; };; esac
done
log "done; results in $RES"
