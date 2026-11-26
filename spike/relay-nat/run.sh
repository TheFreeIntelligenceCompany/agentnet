#!/usr/bin/env bash
# Experiment N: outbound-only clients behind (simulated) NAT (SIMULATION on one host).
#
#   ./run.sh                       # whole experiment (about 60 min, dominated by the 2x10 min idle test and the mapping-loss waits)
#   BIN_DIR=/path/to/target/release ./run.sh      # use these agentnet / agentnet-acceptance binaries (default: <repo>/target/release)
#   STEPS="1 2 3" ./run.sh         # subset (1 always runs)
#   KEEP_UP=1 ./run.sh             # leave the containers running afterwards
#   KEEP_RUN=1 ./run.sh            # keep .run/ (disposable node keys, gitignored)
#   N_MSGS=20 IDLE_S=600 MAPLOSS_TIMEOUT=1500 CT_IDLE=120 ./run.sh      # knobs
#
# WHAT THIS IS: two "LAN" docker bridges, each with a NAT gateway container (iptables MASQUERADE, stateful forwarding) and one client
# node behind it; a "public" bridge with the relay. Clients dial out only. It is a SIMULATION: Linux source NAT in containers on one
# host. Endpoint-independent mapping, hairpinning, UPnP, CGNAT port-block allocation and real ISP middlebox behaviour are NOT modelled.
# No hole punching is needed or tested (clients only dial the relay). NOT separate physical hosts.
set -uo pipefail

SIM=nat
SIMDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SIMDIR/../.." && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="${RESULTS_DIR:-$ROOT/results/network-sim/nat/$TS}"
CAP_PREFIX=an-nat-cap
SIM_TITLE="AgentNet outbound-only clients behind simulated NAT"
SCOPE_BANNER='> **Scope: SIMULATION on ONE host.** Two docker "LAN" bridges, each behind a NAT gateway container (iptables MASQUERADE + stateful forwarding), and a "public" bridge with the relay; amd64 Logos Delivery nodes under qemu on an arm64 Mac. The Linux conntrack/MASQUERADE behaviour is **not** the endpoint-independent mapping of real home routers or CGNAT, hole punching is neither needed nor tested (clients only dial the relay), and these are **not separate physical hosts**. Every number below inherits that.'
N_MSGS="${N_MSGS:-20}"
IDLE_S="${IDLE_S:-600}"
CT_IDLE="${CT_IDLE:-120}"
MAPLOSS_TIMEOUT="${MAPLOSS_TIMEOUT:-1500}"
STEPS="${STEPS:-1 2 3 4}"
export DNS_NS=127.0.0.1
unset AGENTNET_HOME RUST_LOG || true
. "$SIMDIR/../netsim-lib.sh"

R=http://127.0.0.1:18660; NA=http://127.0.0.1:18661; NB=http://127.0.0.1:18662
PUB=an-nat-pub; LANA=an-nat-lana; LANB=an-nat-lanb
IP_R=172.30.80.10; GWA_PUB=172.30.80.21; GWB_PUB=172.30.80.22; CA=192.168.101.10; CB=192.168.102.10
RID=""
compose() { ( cd "$SIMDIR" && docker-compose --env-file .run/env "$@" ); }
dx() { local c=$1; shift; docker exec "$c" "$@"; }
# probe VANTAGE-CONTAINER HOST PORT: nc from inside that container's network namespace (a throwaway tools container joins its netns)
probe() { docker run --rm --net "container:$1" "$TOOLS_IMG" nc -zv -w 4 "$2" "$3" 2>&1; }
set_ct() { # gateway-container seconds : lower/raise the established-TCP conntrack timeout of that gateway's netns (privileged helper shares the netns)
  docker run --rm --privileged --net "container:$1" "$TOOLS_IMG" sysctl -w "net.netfilter.nf_conntrack_tcp_timeout_established=$2" 2>&1
}
step_title() {
  case $1 in
    1) echo "Topology, reachability matrix (outbound-only), what the relay sees";;
    2) echo "20 messages each way, offline recovery";;
    3) echo "NAT mapping loss: conntrack flush, RST variant, gateway restart";;
    4) echo "Idle keepalive with a short conntrack established timeout";;
  esac
}

cleanup() {
  local rc=$? n
  set +e +u
  log "cleanup (exit status of script body: $rc)"
  for n in $(ls "$WORK/pids" 2>/dev/null); do stop_daemon "$n"; done
  for n in "$WORK"/*.stderr; do [ -e "$n" ] && save_daemon_log "$(basename "$n" .stderr)"; done
  cap_cleanup
  mkdir -p "$RES/evidence/container-logs"
  for n in an-nat-r an-nat-a-node an-nat-b-node an-nat-gw-a an-nat-gw-b; do docker logs "$n" 2>&1 | redact > "$RES/evidence/container-logs/$n.log" 2>/dev/null; done
  cap_fix_perms
  if [ "${KEEP_UP:-0}" != 1 ]; then
    compose down -v >> "$RES/logs/docker.log" 2>&1
    docker ps -a --format '{{.Names}}' | grep '^an-nat' | while read -r c; do log "WARNING: leftover container $c"; done
  fi
  [ "${KEEP_RUN:-0}" = 1 ] || { [ -d "$SIMDIR/.run" ] && rm -f "$SIMDIR"/.run/*; }
  ENV_JSON="$(jq -nc --arg host "$(uname -srm)" --arg kern "$(cat "$RES/evidence/vm-kernel.txt" 2>/dev/null)" --arg bin "$("$BIN" --version 2>&1)" \
    '{host:$host, colima_vm_kernel:$kern, agentnet:$bin, nat:"iptables MASQUERADE in containers (Linux conntrack), simulated", node_image:"wakuorg/nwaku@sha256:cb4d14a2... v0.39.2 linux/amd64 under qemu", topology:"public 172.30.80.0/24 (R .10, gw-a .21, gw-b .22); LAN-A 192.168.101.0/24 (gw .2, client .10); LAN-B 192.168.102.0/24; agents on the host via 127.0.0.1 REST ports"}')"
  write_summary
  rm -rf "${WORK:?}"
  if jq -e -s 'any(.[]; .status=="FAIL")' "$RES/checks.jsonl" >/dev/null 2>&1; then exit 1; fi
  exit 0
}
trap cleanup EXIT
trap 'log "interrupted"; exit 130' INT TERM

for t in docker docker-compose jq curl python3 openssl perl colima; do command -v "$t" >/dev/null || { echo "missing prerequisite: $t" >&2; exit 2; }; done
for f in "$BIN" "$DRV"; do [ -x "$f" ] || { echo "missing $f (build: cargo build --release --locked -p agentnet-cli -p agentnet-acceptance, or set BIN_DIR)" >&2; exit 2; }; done
log "results: $RES   work dir: $WORK"
log "SCOPE: SIMULATION, iptables MASQUERADE gateways in containers on one host. NOT real NAT/CGNAT, NOT separate hosts."
colima ssh -- uname -r > "$RES/evidence/vm-kernel.txt" 2>&1
"$BIN" --version > "$RES/evidence/versions.txt" 2>&1
{ docker --version; docker-compose --version; uname -a; jq --version; } >> "$RES/evidence/versions.txt" 2>&1
docker image inspect "$TOOLS_IMG" >/dev/null 2>&1 || docker build -t "$TOOLS_IMG" "$ROOT/spike/relay-wireguard/image" >> "$RES/logs/docker.log" 2>&1
docker run --rm "$TOOLS_IMG" sh -c 'iptables -V; tcpdump --version 2>&1; conntrack -V' >> "$RES/evidence/versions.txt" 2>&1
compose down -v >> "$RES/logs/docker.log" 2>&1 || true
cap_cleanup

peer_of_gw() { peers_json "$R" | jq -r --arg ip "$1" '[.[]|select(.multiaddr|contains("/ip4/"+$ip+"/"))|.multiaddr][0] // empty'; }
r_connected_gws() { peers_json "$R" | jq -r '[.[]|select(.connected=="Connected")|.multiaddr|split("/")[2]]|sort|join(",")'; }
conn_ids() { peers_json "$R" | jq -r '[.[]|select(.connected=="Connected")|.multiaddr]|sort|join(" ")'; }

# ================================================================== STEP 1
step1() {
  log "=== STEP 1: topology and reachability matrix"
  local e="$RES/evidence"
  mkdir -p "$SIMDIR/.run"; chmod 700 "$SIMDIR/.run"; rm -f "$SIMDIR"/.run/*
  { echo "R_KEY=$(openssl rand -hex 32)"; echo "A_KEY=$(openssl rand -hex 32)"; echo "B_KEY=$(openssl rand -hex 32)"; echo "R_PEER_ID=pending"; echo "CT_EST=432000"; } > "$SIMDIR/.run/env"; chmod 600 "$SIMDIR/.run/env"
  compose up --no-start node-r gw-a gw-b >> "$RES/logs/docker.log" 2>&1
  cap_start main "$PUB"; cap_start main "$LANA"; cap_start main "$LANB"; sleep 3
  compose up -d node-r >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "R health" health "$R" || { fail "1.topology" "R's node did not become healthy"; return 1; }
  RID="$(curl -s -m 5 "$R/info" | jq -r '.listenAddresses[0]|split("/p2p/")[1]')"; echo "$RID" > "$e/r-peer-id.txt"
  sed -i.bak "s/^R_PEER_ID=.*/R_PEER_ID=$RID/" "$SIMDIR/.run/env" && rm -f "$SIMDIR/.run/env.bak"
  compose up -d gw-a gw-b client-a client-b node-a node-b >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "A node health" health "$NA"; wait_for 120 "B node health" health "$NB"
  wait_for 180 "A connected to R" peer_connected "$NA" "$RID"; local ta=$WAITED_MS
  wait_for 180 "B connected to R" peer_connected "$NB" "$RID"; local tb=$WAITED_MS
  sleep 5
  docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' | grep '^an-nat' > "$e/containers.txt"
  for c in an-nat-a-net an-nat-b-net an-nat-r an-nat-gw-a an-nat-gw-b; do { echo "### $c published ports"; docker port "$c"; } >> "$e/published-ports.txt" 2>&1; done
  { echo "### R: ip route"; dx an-nat-r ip route; echo "### client A: ip route"; dx an-nat-a-net ip route; echo "### client B: ip route"; dx an-nat-b-net ip route; echo "### gw-a: ip route"; dx an-nat-gw-a ip route; echo "### gw-a: iptables -t nat -S; iptables -S"; dx an-nat-gw-a iptables -t nat -S; dx an-nat-gw-a iptables -S; echo "### gw-a conntrack timeout est"; dx an-nat-gw-a cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established; } > "$e/routes-and-rules.txt" 2>&1
  peers_json "$NA" > "$e/peers-a-initial.json"; peers_json "$NB" > "$e/peers-b-initial.json"; peers_json "$R" > "$e/peers-r-initial.json"
  { echo "### gw-a conntrack -L"; dx an-nat-gw-a conntrack -L; echo "### gw-b conntrack -L"; dx an-nat-gw-b conntrack -L; } > "$e/conntrack-initial.txt" 2>&1
  # 1.topology
  local pa pb
  pa="$(jq -c '[.[]|select(.connected=="Connected")|.multiaddr]' "$e/peers-a-initial.json")"; pb="$(jq -c '[.[]|select(.connected=="Connected")|.multiaddr]' "$e/peers-b-initial.json")"
  if [ "$pa" = "[\"/ip4/$IP_R/tcp/60000/p2p/$RID\"]" ] && [ "$pb" = "$pa" ] && [ "$(jq length "$e/peers-a-initial.json")" = 1 ] && [ "$(jq length "$e/peers-b-initial.json")" = 1 ]; then
    pass "1.topology" "R (public $IP_R), gw-a (LAN-A .2 / public $GWA_PUB), gw-b, client nodes A ($CA) and B ($CB) behind them; each client node lists exactly one peer, R ($IP_R:60000) (connected after ${ta} / ${tb} ms); client containers publish only REST on host 127.0.0.1 (evidence/published-ports.txt), no 60000" "docker-compose up (spike/relay-nat/docker-compose.yml); curl $NA/admin/v1/peers ; docker port an-nat-a-net"
  else fail "1.topology" "A: $pa B: $pb" "curl admin/v1/peers"; fi
  # 1.r_view
  sleep 3; cap_stop main "$PUB"; cap_stop main "$LANA"; cap_stop main "$LANB"
  local gws pr_a pr_b nat_a nat_b ct_a leak_pub
  gws="$(r_connected_gws)"; pr_a="$(peer_of_gw "$GWA_PUB")"; pr_b="$(peer_of_gw "$GWB_PUB")"
  { echo "### R /admin/v1/peers"; jq -c '.[]' "$e/peers-r-initial.json"; echo "### R node log lines mentioning a remote address (grep 172.30.80.2 / 192.168)"; docker logs an-nat-r 2>&1 | grep -E '172\.30\.80\.2[12]|192\.168\.10' | redact | tail -n 20; } > "$e/r-view-of-clients.txt" 2>&1
  nat_a="$(grep -E "$CA" "$e/conntrack-initial.txt" | grep 60000 | head -n 1)"; ct_a="$(echo "$nat_a" | tr -s ' ')"
  leak_pub="$(cap_count "main-$PUB.pcap" 'net 192.168.0.0/16')"
  local lan_a_pk pub_a_pk
  lan_a_pk="$(cap_count "main-$LANA.pcap" "src host $CA and dst host $IP_R and tcp port 60000")"; pub_a_pk="$(cap_count "main-$PUB.pcap" "src host $GWA_PUB and dst host $IP_R and tcp port 60000")"
  cap_list "main-$PUB.pcap" "tcp port 60000 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0" "$e/public-bridge-syns.txt"
  cap_list "main-$LANA.pcap" "tcp port 60000 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0" "$e/lan-a-bridge-syns.txt"
  if [ "$gws" = "$GWA_PUB,$GWB_PUB" ] && [ -n "$pr_a" ] && [ -n "$pr_b" ] && [ "$leak_pub" = 0 ] && [ "${lan_a_pk:-0}" -gt 0 ] && [ "${pub_a_pk:-0}" -gt 0 ]; then
    pass "1.r_view" "R's /admin/v1/peers lists exactly two Connected peers, at the GATEWAY public addresses: A as $pr_a, B as $pr_b (source NAT visible; neither LAN address appears). tcpdump: on LAN-A the client sends from $CA ($lan_a_pk packets to R:60000), on the public bridge the same flow comes from $GWA_PUB ($pub_a_pk packets), and 0 packets on the public bridge carry any 192.168.x.x address. conntrack on gw-a: $ct_a" "curl $R/admin/v1/peers ; tcpdump on $PUB and $LANA ; docker exec an-nat-gw-a conntrack -L"
  else fail "1.r_view" "R connected gateways [$gws] A-entry='$pr_a' B-entry='$pr_b' 192.168-on-public=$leak_pub lan-a packets=$lan_a_pk public packets=$pub_a_pk" "curl $R/admin/v1/peers"; fi
  note 1.r_view "R announces extip $IP_R; the clients run --nat=none so they announce no address of their own. What R 'believes' about a client is the observed remote address of the TCP connection, i.e. the gateway's public address plus the translated source port. Observed mapping: $ct_a (full conntrack in evidence/conntrack-initial.txt)."
  # 1.matrix
  cap_start matrix "$PUB"; cap_start matrix "$LANA"; cap_start matrix "$LANB"; sleep 2
  local m="$e/reachability-matrix.txt" okall=1 line rc
  : > "$m"
  mx() { # label expect(ok|fail) vantage host port
    local out; out="$(probe "$3" "$4" "$5")"; rc=$?
    local got=fail; [ $rc = 0 ] && got=ok
    printf '%-52s expect=%-4s got=%-4s | %s\n' "$1" "$2" "$got" "$(echo "$out" | tr '\n' ' ')" >> "$m"
    [ "$got" = "$2" ] || okall=0
  }
  mx "client A -> R tcp/60000 (outbound)"                ok   an-nat-a-net "$IP_R" 60000
  mx "client B -> R tcp/60000 (outbound)"                ok   an-nat-b-net "$IP_R" 60000
  mx "gw-a (LAN side) -> client A tcp/60000 (sanity: it listens on its LAN)" ok an-nat-gw-a "$CA" 60000
  mx "R -> client A LAN address $CA:60000"               fail an-nat-r "$CA" 60000
  mx "R -> client B LAN address $CB:60000"               fail an-nat-r "$CB" 60000
  mx "R -> gw-a public address $GWA_PUB:60000"           fail an-nat-r "$GWA_PUB" 60000
  mx "R -> gw-b public address $GWB_PUB:60000"           fail an-nat-r "$GWB_PUB" 60000
  mx "client B -> client A LAN address (other LAN)"      fail an-nat-b-net "$CA" 60000
  mx "client A -> client B LAN address (other LAN)"      fail an-nat-a-net "$CB" 60000
  mx "gw-b (public side) -> client A LAN address"        fail an-nat-gw-b "$CA" 60000
  mx "gw-a (public side) -> client B LAN address"        fail an-nat-gw-a "$CB" 60000
  if [ $okall = 1 ]; then pass "1.matrix" "outbound-only proven: A and B reach R:60000; R, the other LAN and the other gateway cannot reach either client's tcp/60000 (LAN address or gateway public address) although the client node DOES listen on its LAN (gw-a reaches it from the LAN side). $(grep -c 'got=fail' "$m") of 11 probes failed as expected (failure mode of each in the table). Full table: evidence/reachability-matrix.txt. NOTE: the 'no route' part rests on docker's isolation between user-defined bridges plus the gateways' stateful forwarding; it is a property of this simulation" "docker run --rm --net container:<vantage> an-net-tools nc -zv -w 4 <host> <port>"
  else fail "1.matrix" "unexpected result in evidence/reachability-matrix.txt: $(grep -v 'expect=\(ok  *got=ok\|fail got=fail\)' "$m" | tr '\n' ';')" "nc -zv probes"; fi
  sleep 2; cap_stop matrix "$PUB"; cap_stop matrix "$LANA"; cap_stop matrix "$LANB"
  cap_list "matrix-$PUB.pcap" "tcp port 60000" "$e/matrix-public-bridge-tcp60000.txt"
}

# ================================================================== STEP 2
step2() {
  log "=== STEP 2: messaging and offline recovery"
  local e="$RES/evidence" peer="/ip4/$IP_R/tcp/60000/p2p/$RID"
  new_agent a "$NA" "$peer"; new_agent b "$NB" "$peer"
  start_daemon a nowait; start_daemon b nowait
  local ok=1; ready_wait a || ok=0; ready_wait b || ok=0
  if [ $ok = 1 ]; then pass "2.serve" "two release-mode 'agentnet serve' (A -> $NA behind NAT-A, B -> $NB behind NAT-B), private mode, static peer $peer; A=$(addr_of a) B=$(addr_of b)" "agentnet --data-dir \$A init --node-url $NA --peer $peer; agentnet serve (x2)"
  else fail "2.serve" "a daemon did not become ready"; return 1; fi
  contact_exchange a b && contact_exchange b a && pass "2.contacts" "contact records exchanged with --expect, both ways" "agentnet contact add @record --expect <address>" || fail "2.contacts" "contact add failed: $ERR"
  local id1; id1="$(send a b "n-first" --conversation n-first)"
  if wait_for 300 "first delivered" state_is a "$id1" delivered; then pass "2.first" "first A -> B message delivered (authenticated receipt) after $WAITED_MS ms on a fresh topology" "agentnet send; agentnet status"
  else fail "2.first" "first message state $(mstate a "$id1") after 300 s" "agentnet send"; fi
  q n-bench "$DRV" bench --a "$WORK/a" --b "$WORK/b" --a-addr "$(addr_of a)" --b-addr "$(addr_of b)" --n "$N_MSGS" --timeout 600 --pace-ms 400 --tag n --out "$e/bench.json"
  sleep 5
  inbox_dump b > "$e/b-dump.json" 2>/dev/null; inbox_dump a > "$e/a-dump.json" 2>/dev/null
  local ab_rows ab_u ba_rows ba_u dupev dir lbl dl
  ab_rows="$(jq '[.inbox.records[]|select(.conversation_id=="n-a2b")]|length' "$e/b-dump.json")"; ab_u="$(jq '[.inbox.records[]|select(.conversation_id=="n-a2b")|.message_id]|unique|length' "$e/b-dump.json")"
  ba_rows="$(jq '[.inbox.records[]|select(.conversation_id=="n-b2a")]|length' "$e/a-dump.json")"; ba_u="$(jq '[.inbox.records[]|select(.conversation_id=="n-b2a")|.message_id]|unique|length' "$e/a-dump.json")"
  dupev=$(( $(jq .events.duplicate_message_received_events "$e/b-dump.json") + $(jq .events.duplicate_message_received_events "$e/a-dump.json") ))
  for dir in a_to_b b_to_a; do
    lbl="${dir//_to_/ -> }"; dl="$(jq ".$dir.delivered" "$e/bench.json")"
    if [ "$dl" = "$N_MSGS" ]; then pass "2.bench.$dir" "$lbl: delivered $dl/$N_MSGS with authenticated receipts, send->receipt p50/p95/p99 = $(jq -r ".$dir.latency_ms_send_to_delivered|\"\(.p50)/\(.p95)/\(.p99)\"" "$e/bench.json") ms (min $(jq ".$dir.latency_ms_send_to_delivered.min" "$e/bench.json"), max $(jq ".$dir.latency_ms_send_to_delivered.max" "$e/bench.json")), paced 400 ms, both directions concurrently; both clients behind NAT" "agentnet-acceptance bench --n $N_MSGS --pace-ms 400 --tag n"
    else fail "2.bench.$dir" "$lbl delivered $dl/$N_MSGS (evidence/bench.json)" "agentnet-acceptance bench"; fi
  done
  if [ "$ab_rows" = "$N_MSGS" ] && [ "$ab_u" = "$N_MSGS" ] && [ "$ba_rows" = "$N_MSGS" ] && [ "$ba_u" = "$N_MSGS" ] && [ "$dupev" = 0 ]; then
    pass "2.duplicates" "receiver rows A->B $ab_rows (unique $ab_u), B->A $ba_rows (unique $ba_u); duplicate message.received events: $dupev" "agentnet-acceptance dump"
  else fail "2.duplicates" "rows A->B $ab_rows/$ab_u, B->A $ba_rows/$ba_u, dup events $dupev" "agentnet-acceptance dump"; fi
  # offline recovery: B's node AND daemon down, A sends 5, B comes back
  log "--- offline recovery"
  stop_daemon b; docker stop an-nat-b-node >> "$RES/logs/docker.log" 2>&1
  local ids="" i id
  for i in 1 2 3 4 5; do id="$(send a b "n-offline-$i" --conversation n-off)"; ids="$ids $id"; done
  # shellcheck disable=SC2086
  wait_for 120 "A: 5 sent" all_in_state a sent $ids || log "A states: $(count_states a $ids)"
  local pre; pre="$(count_states a $ids)"
  sleep 10
  docker start an-nat-b-node >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "B node health" health "$NB"
  local t_b; t_b=$(now_ms); start_daemon b nowait
  local rec=1; wait_for 300 "B inbox has 5" inbox_is b n-off 5 || rec=0
  local rec_ms=$(( $(now_ms) - t_b ))
  # shellcheck disable=SC2086
  wait_for 120 "A: 5 delivered" all_in_state a delivered $ids; local dl_ms=$(( $(now_ms) - t_b ))
  inbox_dump b > "$e/b-dump-after-offline.json" 2>/dev/null
  local rows uniq evs
  rows="$(jq '[.inbox.records[]|select(.conversation_id=="n-off")]|length' "$e/b-dump-after-offline.json")"; uniq="$(jq '[.inbox.records[]|select(.conversation_id=="n-off")|.message_id]|unique|length' "$e/b-dump-after-offline.json")"
  # shellcheck disable=SC2086
  if [ "$rec" = 1 ] && [ "$rows" = 5 ] && [ "$uniq" = 5 ] && all_in_state a delivered $ids; then
    pass "2.offline" "B's node and daemon stopped, A sent 5 (A states while B down: $pre); B restarted: inbox complete (5 rows, 5 unique) $rec_ms ms after the daemon start, A's 5 receipts (delivered) $dl_ms ms after it; recovered via the relay's Store and/or sender retries (not instrumented which)" "docker stop an-nat-b-node; agentnet send x5; docker start an-nat-b-node; agentnet serve (B)"
  else fail "2.offline" "rows=$rows unique=$uniq recovered=$rec A states: $(count_states a $ids)" "offline recovery"; fi
}

# ------------------------------------------------------------------ recovery observation
# watch_recovery LABEL TIMEOUT_S MSGID_A2B MSGID_B2A : poll every 2 s after a disruption started at T0 (set by the caller)
watch_recovery() {
  local label=$1 to=$2 m1=$3 m2=$4 t_lost="" t_rdy_lost="" t_back="" t_rdy_back="" t_d1="" t_d2="" end now
  end=$(( T0 + to * 1000 ))
  local conn_before; conn_before="$(connected_ids "$NA")"
  : > "$RES/evidence/$label-timeline.tsv"
  while [ "$(now_ms)" -lt "$end" ]; do
    now=$(( $(now_ms) - T0 ))
    local nc=1 rd=1 s1 s2
    peer_connected "$NA" "$RID" || nc=0
    net_ready a || rd=0
    s1="$(mstate a "$m1")"; s2="$(mstate b "$m2")"
    printf '%s\t%s\t%s\t%s\t%s\n' "$now" "$nc" "$rd" "$s1" "$s2" >> "$RES/evidence/$label-timeline.tsv"
    [ -z "$t_lost" ] && [ $nc = 0 ] && t_lost=$now
    [ -z "$t_rdy_lost" ] && [ $rd = 0 ] && t_rdy_lost=$now
    [ -n "$t_lost" ] && [ -z "$t_back" ] && [ $nc = 1 ] && t_back=$now
    [ -n "$t_rdy_lost" ] && [ -z "$t_rdy_back" ] && [ $rd = 1 ] && t_rdy_back=$now
    [ -z "$t_d1" ] && [ "$s1" = delivered ] && t_d1=$now
    [ -z "$t_d2" ] && [ "$s2" = delivered ] && t_d2=$now
    [ -n "$t_d1" ] && [ -n "$t_d2" ] && { [ -z "$t_lost" ] || [ -n "$t_back" ]; } && break
    sleep 2
  done
  jq -nc --arg l "$label" --argjson lost "${t_lost:--1}" --argjson rl "${t_rdy_lost:--1}" --argjson back "${t_back:--1}" --argjson rb "${t_rdy_back:--1}" --argjson d1 "${t_d1:--1}" --argjson d2 "${t_d2:--1}" --argjson to "$to" \
    '{trial:$l, ms_until_A_node_stops_listing_R_connected:$lost, ms_until_A_daemon_not_ready:$rl, ms_until_A_node_lists_R_connected_again:$back, ms_until_A_daemon_ready_again:$rb, ms_until_A_to_B_message_delivered:$d1, ms_until_B_to_A_message_delivered:$d2, window_s:$to, minus_one_means:"never within the window"}' > "$RES/evidence/$label.json"
}
maploss_check() { # id label description
  local id=$1 label=$2 desc=$3 j="$RES/evidence/$2.json"
  local lost back d1 d2 rl rb; lost=$(jq .ms_until_A_node_stops_listing_R_connected "$j"); back=$(jq .ms_until_A_node_lists_R_connected_again "$j"); d1=$(jq .ms_until_A_to_B_message_delivered "$j"); d2=$(jq .ms_until_B_to_A_message_delivered "$j")
  rl=$(jq .ms_until_A_daemon_not_ready "$j"); rb=$(jq .ms_until_A_daemon_ready_again "$j")
  if [ "$d1" -ge 0 ] && [ "$d2" -ge 0 ]; then
    pass "$id" "$desc: A's node noticed after $lost ms (-1 = never), A's daemon not-ready after $rl ms, A's node connected again after $back ms, daemon ready again after $rb ms; the A->B message sent right after the disruption was delivered after $d1 ms and a B->A message after $d2 ms (timeline: evidence/$label-timeline.tsv)" "$4"
  else fail "$id" "$desc: NOT recovered within $(jq .window_s "$j") s: node noticed after $lost ms, daemon not-ready after $rl ms, node reconnected after $back ms, A->B delivered after $d1 ms, B->A after $d2 ms (-1 = never)" "$4"; fi
}

# ================================================================== STEP 3
step3() {
  log "=== STEP 3: NAT mapping loss"
  local e="$RES/evidence" m1 m2
  wait_for 120 "A connected" peer_connected "$NA" "$RID"; wait_for 120 "B connected" peer_connected "$NB" "$RID"; wait_for 120 "A ready" net_ready a; wait_for 120 "B ready" net_ready b
  # ---- (a) conntrack flush, mid-stream packets silently dropped (the gateway forgets the mapping)
  log "--- (a) conntrack flush on gw-a (unknown packets dropped silently)"
  cap_start s3a "$PUB"; sleep 1
  { echo "### before flush"; dx an-nat-gw-a conntrack -L; } > "$e/s3a-conntrack-before.txt" 2>&1
  conn_ids > "$e/s3a-r-peers-before.txt"
  dx an-nat-gw-a conntrack -F >> "$e/s3a-conntrack-before.txt" 2>&1; T0=$(now_ms)
  { echo "### right after flush"; dx an-nat-gw-a conntrack -L; } > "$e/s3a-conntrack-after-flush.txt" 2>&1
  m1="$(send a b "n-s3a-a2b" --conversation s3a)"; m2="$(send b a "n-s3a-b2a" --conversation s3a)"
  watch_recovery s3a-flush "$MAPLOSS_TIMEOUT" "$m1" "$m2"
  { echo "### conntrack after recovery"; dx an-nat-gw-a conntrack -L; } > "$e/s3a-conntrack-after.txt" 2>&1
  conn_ids > "$e/s3a-r-peers-after.txt"
  cap_stop s3a "$PUB"
  maploss_check "3.flush" s3a-flush "conntrack -F on gw-a at T0 (mid-stream packets then dropped silently, like a router that lost its state; R's peer entries before/after: evidence/s3a-r-peers-*.txt)" "docker exec an-nat-gw-a conntrack -F ; agentnet send (A->B and B->A) ; poll node peers / daemon status / message status every 2 s"
  # ---- (b) same, but the gateway answers unmapped packets with TCP RST
  log "--- (b) conntrack flush, unknown packets answered with RST"
  local lan_if pub_if
  lan_if="$(dx an-nat-gw-a sh -c "ip -o -4 addr show | awk '/ 192\\.168\\.10[12]\\./ {print \$2}' | head -n 1")"; pub_if="$(dx an-nat-gw-a sh -c "ip -o -4 addr show | awk '/ 172\\.30\\.80\\./ {print \$2}' | head -n 1")"
  dx an-nat-gw-a iptables -D FORWARD -i "$lan_if" -o "$pub_if" -p tcp '!' --syn -m conntrack --ctstate NEW -m comment --comment natsim-no-midstream -j DROP >> "$RES/logs/docker.log" 2>&1
  dx an-nat-gw-a iptables -I FORWARD 1 -i "$lan_if" -o "$pub_if" -p tcp '!' --syn -m conntrack --ctstate NEW -m comment --comment natsim-no-midstream-RST -j REJECT --reject-with tcp-reset
  dx an-nat-gw-a iptables -S FORWARD > "$e/s3b-gw-a-forward-rules.txt" 2>&1
  wait_for 600 "A connected again" peer_connected "$NA" "$RID"; wait_for 600 "A ready" net_ready a
  sleep 5
  cap_start s3b "$PUB"; sleep 1
  dx an-nat-gw-a conntrack -F >> "$e/s3b-conntrack.txt" 2>&1; T0=$(now_ms)
  m1="$(send a b "n-s3b-a2b" --conversation s3b)"; m2="$(send b a "n-s3b-b2a" --conversation s3b)"
  watch_recovery s3b-flush-rst "$MAPLOSS_TIMEOUT" "$m1" "$m2"
  cap_stop s3b "$PUB"
  maploss_check "3.flush_rst" s3b-flush-rst "same flush, but gw-a now answers mid-stream packets with a TCP RST (some real devices do)" "iptables -I FORWARD 1 ... -j REJECT --reject-with tcp-reset ; docker exec an-nat-gw-a conntrack -F"
  # restore the drop behaviour
  dx an-nat-gw-a iptables -D FORWARD -i "$lan_if" -o "$pub_if" -p tcp '!' --syn -m conntrack --ctstate NEW -m comment --comment natsim-no-midstream-RST -j REJECT --reject-with tcp-reset >> "$RES/logs/docker.log" 2>&1
  dx an-nat-gw-a iptables -I FORWARD 1 -i "$lan_if" -o "$pub_if" -p tcp '!' --syn -m conntrack --ctstate NEW -m comment --comment natsim-no-midstream -j DROP
  # ---- (c) restart the gateway container
  log "--- (c) gateway container restart"
  wait_for 600 "A connected" peer_connected "$NA" "$RID"; wait_for 600 "A ready" net_ready a; sleep 5
  cap_start s3c "$PUB"; sleep 1
  docker restart an-nat-gw-a >> "$RES/logs/docker.log" 2>&1; T0=$(now_ms)
  m1="$(send a b "n-s3c-a2b" --conversation s3c)"; m2="$(send b a "n-s3c-b2a" --conversation s3c)"
  watch_recovery s3c-gw-restart "$MAPLOSS_TIMEOUT" "$m1" "$m2"
  cap_stop s3c "$PUB"
  maploss_check "3.gw_restart" s3c-gw-restart "docker restart an-nat-gw-a at T0 (fresh conntrack, rules re-applied, same addresses; mid-stream packets dropped silently)" "docker restart an-nat-gw-a ; agentnet send ; poll"
}

# ================================================================== STEP 4
idle_phase() { # label with_daemons(1|0)
  local label=$1 withd=$2 e="$RES/evidence"
  wait_for 600 "A connected" peer_connected "$NA" "$RID"; wait_for 600 "B connected" peer_connected "$NB" "$RID"
  [ "$withd" = 1 ] && { wait_for 300 "A ready" net_ready a; wait_for 300 "B ready" net_ready b; }
  sleep 5
  conn_ids > "$e/$label-r-peers-before.txt"
  { echo "### gw-a conntrack -L before idle"; dx an-nat-gw-a conntrack -L; echo "### gw-b"; dx an-nat-gw-b conntrack -L; } > "$e/$label-conntrack-before.txt" 2>&1
  cap_start "$label" "$PUB"; sleep 1
  local t0 now; t0=$(now_ms); : > "$e/$label-conntrack-samples.txt"
  while [ $(( $(now_ms) - t0 )) -lt $(( IDLE_S * 1000 )) ]; do
    { echo "### t+$(( ($(now_ms) - t0) / 1000 )) s gw-a conntrack entries to R:60000"; dx an-nat-gw-a conntrack -L -p tcp --dport 60000; } >> "$e/$label-conntrack-samples.txt" 2>&1
    sleep 30
  done
  { echo "### gw-a conntrack -L after idle"; dx an-nat-gw-a conntrack -L; echo "### gw-b"; dx an-nat-gw-b conntrack -L; } > "$e/$label-conntrack-after.txt" 2>&1
  conn_ids > "$e/$label-r-peers-after.txt"
  cap_stop "$label" "$PUB"
  # largest silent gap on gw-a's flow to R, from the public-bridge capture
  cap_list "$label-$PUB.pcap" "tcp and host $GWA_PUB and host $IP_R" "$e/$label-flow-a-packets.txt"
  python3 -I - "$e/$label-flow-a-packets.txt" > "$e/$label-flow-a-gaps.json" <<'PY'
import sys, json, re
ts = []
for l in open(sys.argv[1]):
    m = re.match(r'(\d+):(\d+):(\d+\.\d+) ', l)
    if m: ts.append(int(m.group(1))*3600 + int(m.group(2))*60 + float(m.group(3)))
gaps = [b-a for a, b in zip(ts, ts[1:])]
print(json.dumps({"packets": len(ts), "max_gap_s": round(max(gaps), 2) if gaps else None, "gaps_over_60s": sum(1 for g in gaps if g > 60), "gaps_over_100s": sum(1 for g in gaps if g > 100)}))
PY
}
step4() {
  log "=== STEP 4: idle keepalive (conntrack established timeout $CT_IDLE s, idle $IDLE_S s)"
  local e="$RES/evidence" r1 r2
  set_ct an-nat-gw-a "$CT_IDLE" > "$e/ct-set-a.txt"; set_ct an-nat-gw-b "$CT_IDLE" > "$e/ct-set-b.txt"
  if [ "$(dx an-nat-gw-a cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established)" != "$CT_IDLE" ]; then fail "4.setup" "could not set nf_conntrack_tcp_timeout_established=$CT_IDLE on the gateways ($(cat "$e/ct-set-a.txt"))"; return 1; fi
  # ---- I1: daemons running (history sync etc. are part of the product)
  log "--- idle 1: daemons running"
  idle_phase idle1-with-daemons 1
  local same1; same1=0; [ "$(cat "$e/idle1-with-daemons-r-peers-before.txt")" = "$(cat "$e/idle1-with-daemons-r-peers-after.txt")" ] && same1=1
  local ok1=1; peer_connected "$NA" "$RID" || ok1=0; peer_connected "$NB" "$RID" || ok1=0; net_ready a || ok1=0; net_ready b || ok1=0
  local m1 m2; m1="$(send a b "n-after-idle1-a2b" --conversation idle1)"; m2="$(send b a "n-after-idle1-b2a" --conversation idle1)"
  local t0; t0=$(now_ms)
  wait_for 600 "idle1 delivered a2b" state_is a "$m1" delivered; local d1=$WAITED_MS
  wait_for 600 "idle1 delivered b2a" state_is b "$m2" delivered; local d2=$(( $(now_ms) - t0 ))
  local gaps; gaps="$(cat "$e/idle1-with-daemons-flow-a-gaps.json")"
  if [ "$(state_is a "$m1" delivered && echo y)" = y ] && [ "$(state_is b "$m2" delivered && echo y)" = y ]; then
    pass "4.idle_with_daemons" "both sides idle ${IDLE_S}s (daemons running, conntrack established timeout ${CT_IDLE}s on both gateways): nodes still Connected to R after idle=$ok1, R's peer entries (incl. translated source ports) unchanged=$same1; flow gw-a<->R packet gaps: $gaps; then one message each way delivered with receipts after ${d1} ms (A->B) and ${d2} ms (B->A, measured from the same start)" "set nf_conntrack_tcp_timeout_established=$CT_IDLE on gw-a/gw-b; no traffic for ${IDLE_S}s; agentnet send (each way)"
  else fail "4.idle_with_daemons" "after idle: nodes connected=$ok1 peers-unchanged=$same1 gaps=$gaps; A->B state $(mstate a "$m1"), B->A state $(mstate b "$m2")" "idle test"; fi
  note 4.idle_with_daemons "The daemons are not silent while 'idle': each runs a Store history sync every history_sync_interval_s (default 15 s), a Store query to R over the existing libp2p connection, so the connection carries packets at least that often and the mapping never ages out. This phase therefore does NOT show whether libp2p itself keeps a mapping alive; the node-only phase does."
  # ---- I2: nodes only
  log "--- idle 2: nodes only (daemons stopped, no store sync)"
  stop_daemon a; stop_daemon b
  idle_phase idle2-nodes-only 0
  gaps="$(cat "$e/idle2-nodes-only-flow-a-gaps.json")"
  local same2=0; [ "$(cat "$e/idle2-nodes-only-r-peers-before.txt")" = "$(cat "$e/idle2-nodes-only-r-peers-after.txt")" ] && same2=1
  local still_a=0 still_b=0; peer_connected "$NA" "$RID" && still_a=1; peer_connected "$NB" "$RID" && still_b=1
  start_daemon a nowait; start_daemon b nowait
  T0=$(now_ms)
  ready_wait a 300; ready_wait b 300
  m1="$(send a b "n-after-idle2-a2b" --conversation idle2)"; m2="$(send b a "n-after-idle2-b2a" --conversation idle2)"
  wait_for 900 "idle2 delivered a2b" state_is a "$m1" delivered; d1=$(( $(now_ms) - T0 ))
  wait_for 900 "idle2 delivered b2a" state_is b "$m2" delivered; d2=$(( $(now_ms) - T0 ))
  if state_is a "$m1" delivered && state_is b "$m2" delivered; then
    pass "4.idle_nodes_only" "daemons stopped (no Store sync), nodes idle ${IDLE_S}s with conntrack established timeout ${CT_IDLE}s: before restarting the daemons the nodes were still Connected to R: A=$still_a B=$still_b, R's peer entries unchanged=$same2; flow gw-a<->R packet gaps: $gaps. After restarting the daemons one message each way: delivered after ${d1} ms (A->B) / ${d2} ms (B->A) counted from the daemon restart" "stop both daemons; no traffic ${IDLE_S}s; start daemons; agentnet send (each way)"
  else fail "4.idle_nodes_only" "after idle: A=$still_a B=$still_b peers-unchanged=$same2 gaps=$gaps; A->B $(mstate a "$m1"), B->A $(mstate b "$m2")" "idle test"; fi
  set_ct an-nat-gw-a 432000 > /dev/null; set_ct an-nat-gw-b 432000 > /dev/null
}

case " $STEPS " in *" 1 "*) ;; *) STEPS="1 $STEPS";; esac
case " $STEPS " in *" 2 "*) ;; *) case " $STEPS " in *" 3 "*|*" 4 "*) STEPS="1 2 $STEPS";; esac;; esac
for s in $STEPS; do
  case $s in
    1) step1 || { log "step 1 failed; later steps need it"; break; };;
    2) step2 || { log "step 2 failed; later steps need it"; break; };;
    3) step3;;
    4) step4;;
  esac
done
log "done; results in $RES"
