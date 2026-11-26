#!/usr/bin/env bash
# Experiment W: Logos Delivery relay reachable ONLY over WireGuard (SIMULATION on one host).
#
#   ./run.sh                       # whole experiment, results in results/network-sim/wireguard/<UTC timestamp>/
#   BIN_DIR=/path/to/target/release ./run.sh      # use these agentnet / agentnet-acceptance binaries (default: <repo>/target/release)
#   STEPS="1 2 3" ./run.sh         # subset (1 and 2 always run; 3 needs the main capture from 1+2)
#   KEEP_UP=1 ./run.sh             # leave the containers running afterwards (default: everything is removed)
#   KEEP_RUN=1 ./run.sh            # keep .run/ (WireGuard + node keys, DISPOSABLE, gitignored)
#   N_MSGS=20 PEER_LOSS_TIMEOUT=600 RELAY_DOWN_TIMEOUT=900 CONTROL_TIMEOUT=240   # knobs
#
# WHAT THIS IS: kernel WireGuard (module in the colima VM) between three containers on ONE docker host; a firewall on the relay
# machine that admits libp2p tcp/60000 only from the WireGuard interface; two `agentnet serve` daemons on the host. It is NOT
# Tailscale (no coordination server, no ACLs, no MagicDNS, no DERP), NOT NAT traversal, NOT separate physical hosts.
#
# Needs: docker + standalone docker-compose, colima (tcpdump runs in the VM netns), jq, curl, python3, openssl, perl,
# and built release binaries agentnet + agentnet-acceptance. Touches only containers/networks/volumes named an-wg*.
set -uo pipefail

SIM=wireguard
SIMDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SIMDIR/../.." && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
RES="${RESULTS_DIR:-$ROOT/results/network-sim/wireguard/$TS}"
CAP_PREFIX=an-wg-cap
SIM_TITLE="AgentNet WireGuard-overlay simulation"
SCOPE_BANNER='> **Scope: SIMULATION on ONE host.** Kernel WireGuard (module loaded in the colima VM) between three containers on one docker bridge; amd64 Logos Delivery nodes under qemu on an arm64 Mac. It demonstrates the overlay + firewall + static-peer configuration and AgentNet'"'"'s behaviour on it. It is **NOT Tailscale** (no coordination server, no ACLs, no MagicDNS, no DERP relays), **NOT NAT traversal**, and **NOT separate physical hosts**. Every number below inherits that.'
N_MSGS="${N_MSGS:-20}"
PEER_LOSS_TIMEOUT="${PEER_LOSS_TIMEOUT:-600}"
RELAY_DOWN_TIMEOUT="${RELAY_DOWN_TIMEOUT:-900}"
CONTROL_TIMEOUT="${CONTROL_TIMEOUT:-240}"
STEPS="${STEPS:-1 2 3 4 5 6}"
export DNS_NS=127.0.0.1
unset AGENTNET_HOME RUST_LOG || true
. "$SIMDIR/../netsim-lib.sh"

R=http://127.0.0.1:18650; NA=http://127.0.0.1:18651; NB=http://127.0.0.1:18652; NI=http://127.0.0.1:18653
BR=an-wg-br0
UL=172.29.70.0/24; OVL=10.66.0.0/24
IP_R=172.29.70.10; IP_A=172.29.70.21; IP_B=172.29.70.22; IP_I=172.29.70.66; IP_GW=172.29.70.1
RID=""
compose() { ( cd "$SIMDIR" && docker-compose --env-file .run/env "$@" ); }
wx() { local m=$1; shift; docker exec "an-wg-$m" "$@"; }                       # exec in a machine's sidecar (its netns)
fw_rule_drop='INPUT -i eth0 -p tcp --dport 60000 -m comment --comment wgsim-underlay-libp2p-drop -j DROP'
enc() { jq -rn --arg t "$1" '$t|@uri'; }
step_title() {
  case $1 in
    1) echo "Tunnel up, nodes connected only over the overlay, firewall";;
    2) echo "End to end: contacts, send/reply (CLI and MCP), 20 messages each way";;
    3) echo "Packet proof on the underlay: only WireGuard UDP";;
    4) echo "Access restriction: key-less intruder on the underlay, plus control";;
    5) echo "Peer removal on the relay's WireGuard config";;
    6) echo "Relay node down inside the overlay";;
  esac
}

# ------------------------------------------------------------------ cleanup
cleanup() {
  local rc=$? n
  set +e +u
  log "cleanup (exit status of script body: $rc)"
  for n in $(ls "$WORK/pids" 2>/dev/null); do stop_daemon "$n"; done
  for n in "$WORK"/*.stderr; do [ -e "$n" ] && save_daemon_log "$(basename "$n" .stderr)"; done
  cap_cleanup
  mkdir -p "$RES/evidence/container-logs"
  for n in an-wg-r-node an-wg-a-node an-wg-b-node an-wg-intruder-node; do docker logs "$n" 2>&1 | redact > "$RES/evidence/container-logs/$n.log" 2>/dev/null; done
  cap_fix_perms
  if [ "${KEEP_UP:-0}" != 1 ]; then
    compose --profile intruder down -v >> "$RES/logs/docker.log" 2>&1
    docker ps -a --format '{{.Names}}' | grep '^an-wg' | while read -r c; do log "WARNING: leftover container $c"; done
  fi
  [ "${KEEP_RUN:-0}" = 1 ] || { [ -d "$SIMDIR/.run" ] && rm -f "$SIMDIR"/.run/*; }
  ENV_JSON="$(jq -nc --arg host "$(uname -srm)" --arg kern "$(cat "$RES/evidence/vm-kernel.txt" 2>/dev/null)" --arg bin "$("$BIN" --version 2>&1)" \
    '{host:$host, colima_vm_kernel:$kern, agentnet:$bin, wireguard:"kernel module (not userspace)", node_image:"wakuorg/nwaku@sha256:cb4d14a2... v0.39.2 linux/amd64 under qemu", topology:"underlay 172.29.70.0/24, overlay 10.66.0.0/24, machines R/A/B (+ intruder), agents on the host via 127.0.0.1 REST ports"}')"
  write_summary
  rm -rf "${WORK:?}"
  if jq -e -s 'any(.[]; .status=="FAIL")' "$RES/checks.jsonl" >/dev/null 2>&1; then exit 1; fi
  exit 0
}
trap cleanup EXIT
trap 'log "interrupted"; exit 130' INT TERM

# ------------------------------------------------------------------ prerequisites
for t in docker docker-compose jq curl python3 openssl perl colima; do command -v "$t" >/dev/null || { echo "missing prerequisite: $t" >&2; exit 2; }; done
for f in "$BIN" "$DRV"; do [ -x "$f" ] || { echo "missing $f (build: cargo build --release --locked -p agentnet-cli -p agentnet-acceptance, or set BIN_DIR)" >&2; exit 2; }; done
log "results: $RES   work dir: $WORK"
log "SCOPE: SIMULATION, kernel WireGuard between containers on one host. NOT Tailscale, NOT NAT traversal, NOT separate hosts."
colima ssh -- sudo modprobe wireguard >> "$RES/logs/docker.log" 2>&1
colima ssh -- uname -r > "$RES/evidence/vm-kernel.txt" 2>&1
colima ssh -- lsmod 2>/dev/null | grep -E '^(wireguard|nf_conntrack|nf_tables) ' > "$RES/evidence/vm-modules.txt"
"$BIN" --version > "$RES/evidence/versions.txt" 2>&1
{ docker --version; docker-compose --version; uname -a; jq --version; } >> "$RES/evidence/versions.txt" 2>&1
docker image inspect "$TOOLS_IMG" >/dev/null 2>&1 || docker build -t "$TOOLS_IMG" "$SIMDIR/image" >> "$RES/logs/docker.log" 2>&1
docker run --rm "$TOOLS_IMG" sh -c 'wg --version; iptables -V; tcpdump --version 2>&1; conntrack -V' >> "$RES/evidence/versions.txt" 2>&1
# idempotent: remove anything of an earlier (possibly aborted) run of THIS simulation
compose --profile intruder down -v >> "$RES/logs/docker.log" 2>&1 || true
cap_cleanup

# ================================================================== STEP 1
step1() {
  log "=== STEP 1: bring up the three machines"
  "$SIMDIR/scripts/gen-keys.sh" >> "$RES/logs/setup.log" 2>&1 || { fail "1.setup" "key generation failed (see logs/setup.log)"; return 1; }
  compose up --no-start wg-r wg-a wg-b node-r >> "$RES/logs/docker.log" 2>&1
  # capture from before the first WireGuard handshake
  cap_start main "$BR"; sleep 3
  compose up -d wg-r wg-a wg-b >> "$RES/logs/docker.log" 2>&1
  compose up -d node-r >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "R node health" health "$R" || { fail "1.setup" "R's node did not become healthy"; return 1; }
  RID="$(curl -s -m 5 "$R/info" | jq -r '.listenAddresses[0]|split("/p2p/")[1]')"
  echo "$RID" > "$RES/evidence/r-peer-id.txt"
  sed -i.bak "s/^R_PEER_ID=.*/R_PEER_ID=$RID/" "$SIMDIR/.run/env" && rm -f "$SIMDIR/.run/env.bak"
  curl -s "$R/info" | jq 'del(.enrUri)' > "$RES/evidence/r-info.json"
  compose up -d node-a node-b >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "A node health" health "$NA"; wait_for 120 "B node health" health "$NB"
  wait_for 180 "A connected to R" peer_connected "$NA" "$RID"; local ta=$WAITED_MS
  wait_for 180 "B connected to R" peer_connected "$NB" "$RID"; local tb=$WAITED_MS
  docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep '^an-wg' > "$RES/evidence/containers.txt"

  # 1.kernel
  local kinds; kinds=""
  for m in r a b; do kinds="$kinds $m=$(wx $m ip -d link show wg0 | grep -o 'wireguard' | head -n 1)"; done
  wx r ip -d link show wg0 > "$RES/evidence/wg0-link-r.txt" 2>&1
  if [ "$(echo "$kinds" | grep -o 'wireguard' | wc -l | tr -d ' ')" = 3 ]; then
    pass "1.kernel" "wg0 on r, a, b is a KERNEL WireGuard link (ip -d link: kind wireguard; module in the colima VM: $(cat "$RES/evidence/vm-kernel.txt"), $(tr '\n' ';' < "$RES/evidence/vm-modules.txt")). No userspace fallback was used or implemented." "docker exec an-wg-<m> ip -d link show wg0; colima ssh -- lsmod"
  else fail "1.kernel" "wg0 is not a kernel wireguard link on every machine: $kinds" "ip -d link show wg0"; fi
  # 1.handshakes
  local hs ok=1; : > "$RES/evidence/wg-show-initial.txt"
  for m in r a b; do
    { echo "### an-wg-$m: wg show wg0 (private key hidden by wg)"; wx $m wg show wg0; echo; echo "### latest-handshakes (epoch s)"; wx $m wg show wg0 latest-handshakes; } >> "$RES/evidence/wg-show-initial.txt" 2>&1
    hs="$(wx $m wg show wg0 latest-handshakes | awk '{ if ($2+0==0) bad=1 } END {print bad+0}')"
    [ "$hs" = 0 ] || ok=0
  done
  if [ $ok = 1 ]; then pass "1.handshakes" "every WireGuard peer on r (a, b), a (r) and b (r) has a non-zero latest handshake (evidence/wg-show-initial.txt)" "docker exec an-wg-<m> wg show wg0 latest-handshakes"
  else fail "1.handshakes" "a peer has no handshake (evidence/wg-show-initial.txt)" "wg show wg0 latest-handshakes"; fi
  # 1.nodes_connected
  peers_json "$NA" > "$RES/evidence/peers-a-initial.json"; peers_json "$NB" > "$RES/evidence/peers-b-initial.json"; peers_json "$R" > "$RES/evidence/peers-r-initial.json"
  local pa pb
  pa="$(jq -c --arg id "$RID" '[.[]|select(.connected=="Connected")]|map(.multiaddr)' "$RES/evidence/peers-a-initial.json")"
  pb="$(jq -c --arg id "$RID" '[.[]|select(.connected=="Connected")]|map(.multiaddr)' "$RES/evidence/peers-b-initial.json")"
  if [ "$pa" = "[\"/ip4/10.66.0.1/tcp/60000/p2p/$RID\"]" ] && [ "$pb" = "[\"/ip4/10.66.0.1/tcp/60000/p2p/$RID\"]" ] && [ "$(jq 'length' "$RES/evidence/peers-a-initial.json")" = 1 ] && [ "$(jq 'length' "$RES/evidence/peers-b-initial.json")" = 1 ]; then
    pass "1.nodes_connected" "A's node lists exactly one peer, R, as /ip4/10.66.0.1/tcp/60000 (connected after ${ta} ms from node-a start-wait); B's node likewise (${tb} ms). R's node lists: $(jq -c '[.[]|{multiaddr,connected}]' "$RES/evidence/peers-r-initial.json")" "curl http://127.0.0.1:18651/admin/v1/peers ; :18652 ; :18650"
  else fail "1.nodes_connected" "A: $pa  B: $pb (see evidence/peers-*-initial.json)" "curl .../admin/v1/peers"; fi
  # 1.firewall evidence
  for m in r a b; do { echo "### an-wg-$m iptables -S"; wx $m iptables -S; echo; echo "### iptables -vnxL INPUT"; wx $m iptables -vnxL INPUT; } > "$RES/evidence/firewall-$m-initial.txt" 2>&1; done
  if grep -q -- '-A INPUT -i eth0 -p tcp -m tcp --dport 60000 -m comment --comment wgsim-underlay-libp2p-drop -j DROP' "$RES/evidence/firewall-r-initial.txt" \
     && grep -q -- '-s 10.66.0.2/32 -i wg0 -p tcp -m tcp --dport 60000' "$RES/evidence/firewall-r-initial.txt" && grep -q -- '-s 10.66.0.3/32 -i wg0 -p tcp -m tcp --dport 60000' "$RES/evidence/firewall-r-initial.txt" \
     && grep -q -- '-P INPUT DROP' "$RES/evidence/firewall-r-initial.txt"; then
    pass "1.firewall" "R: INPUT policy DROP; tcp/60000 accepted only on wg0 from 10.66.0.2 and 10.66.0.3; tcp/60000 on eth0 (underlay) dropped by an explicit rule placed before the established-accept (evidence/firewall-r-initial.txt)" "docker exec an-wg-r iptables -S"
  else fail "1.firewall" "expected rules missing (evidence/firewall-r-initial.txt)" "iptables -S"; fi
}

# ================================================================== STEP 2
step2() {
  log "=== STEP 2: agents, contacts, messaging"
  local peer="/ip4/10.66.0.1/tcp/60000/p2p/$RID"
  new_agent a "$NA" "$peer"; new_agent b "$NB" "$peer"
  start_daemon a nowait; start_daemon b nowait
  local ok=1; ready_wait a || ok=0; ready_wait b || ok=0
  if [ $ok = 1 ]; then pass "2.serve" "two release-mode 'agentnet serve' (A -> $NA, B -> $NB), private mode, static peer = R's OVERLAY multiaddr $peer, cluster 66; A=$(addr_of a) B=$(addr_of b); ready after A $(tail -n 2 "$RES/evidence/startup-times.tsv" | head -n 1 | cut -f3) ms / B $(tail -n 1 "$RES/evidence/startup-times.tsv" | cut -f3) ms" \
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
      pass "2.netstatus.$d" "doctor exit 0; network status: private, ready, no isolation violation, exactly one peer = R ($RID)" "agentnet doctor; agentnet --json network status --verbose"
    else fail "2.netstatus.$d" "doctor exit $drc; network: $(printf '%s' "$OUT" | jq -c .network 2>/dev/null)" "agentnet doctor; network status --verbose"; fi
  done
  # first message: cold mesh is expected to be slow (docs/relay-setup.md 3a); record it separately
  local t0 id1; t0=$(now_ms); id1="$(send a b "w-first-cli" --conversation w-first)"
  if wait_for 300 "first message delivered" state_is a "$id1" delivered; then
    pass "2.cli_send" "A -> B via 'agentnet send': delivered (authenticated receipt) after $WAITED_MS ms (FIRST message on a fresh topology: includes the relay-mesh warm-up of up to ~60 s, not a typical latency)" "agentnet --json send <B> w-first-cli; agentnet --json status <id>"
  else fail "2.cli_send" "not delivered within 300 s; state $(mstate a "$id1")" "agentnet send"; fi
  local rb; rb="$(anj b inbox --conversation w-first --limit 10)"
  echo "$rb" > "$RES/evidence/b-inbox-first.json"
  if [ "$(echo "$rb" | jq '.records|length')" = 1 ] && [ "$(echo "$rb" | jq -r '.records[0].sender')" = "$(addr_of a)" ] && [ "$(echo "$rb" | jq -r '.records[0].body')" = "w-first-cli" ]; then
    pass "2.inbox_auth" "B's inbox holds the message, sender authenticated as A ($(addr_of a)), body intact" "agentnet --json inbox --conversation w-first"
  else fail "2.inbox_auth" "B inbox: $(echo "$rb" | jq -c '.records')" "agentnet inbox"; fi
  local idr; idr="$(send b a "w-reply-cli" --conversation w-first)"
  if wait_for 120 "reply delivered" state_is b "$idr" delivered && [ "$(anj a inbox --conversation w-first --limit 10 | jq -r '[.records[]|select(.body=="w-reply-cli")]|length')" = 1 ]; then
    pass "2.reply" "B -> A reply delivered (receipt after $WAITED_MS ms) and present in A's inbox" "agentnet send <A> w-reply-cli (from B)"
  else fail "2.reply" "reply state $(mstate b "$idr")" "agentnet send (B->A)"; fi
  # MCP path
  q step2-mcp "$DRV" step2 --bin "$BIN" --a "$WORK/a" --b "$WORK/b" --b-addr "$(addr_of b)" --out "$RES/evidence/step2-mcp.json"
  if [ "$RC" = 0 ] && [ "$(jq -r '.A_status_timeline[-1].state' "$RES/evidence/step2-mcp.json")" = delivered ]; then
    pass "2.mcp" "A -> B via MCP send_message (rmcp over stdio, negotiated $(jq -r '.protocol_client_A.negotiated_protocol_version' "$RES/evidence/step2-mcp.json")): B's subscriptions/listen notified after $(jq -r .latency_ms.B_resource_notification "$RES/evidence/step2-mcp.json") ms, B read_inbox at +$(jq -r .latency_ms.B_read_inbox_returned "$RES/evidence/step2-mcp.json") ms, A status delivered at +$(jq -r .latency_ms.A_status_delivered "$RES/evidence/step2-mcp.json") ms" "agentnet-acceptance step2 --bin agentnet --a \$A --b \$B --b-addr <B>"
  else fail "2.mcp" "step2 driver failed (exit $RC): $(printf '%s' "$OUT" | jq -r .error 2>/dev/null)" "agentnet-acceptance step2"; fi
  # N messages each way, paced
  q step2-bench "$DRV" bench --a "$WORK/a" --b "$WORK/b" --a-addr "$(addr_of a)" --b-addr "$(addr_of b)" --n "$N_MSGS" --timeout 600 --pace-ms 400 --tag w --out "$RES/evidence/bench.json"
  sleep 5
  inbox_dump b > "$RES/evidence/b-dump.json" 2>/dev/null; inbox_dump a > "$RES/evidence/a-dump.json" 2>/dev/null
  local ab_rows ab_u ba_rows ba_u dupev
  ab_rows="$(jq '[.inbox.records[]|select(.conversation_id=="w-a2b")]|length' "$RES/evidence/b-dump.json")"; ab_u="$(jq '[.inbox.records[]|select(.conversation_id=="w-a2b")|.message_id]|unique|length' "$RES/evidence/b-dump.json")"
  ba_rows="$(jq '[.inbox.records[]|select(.conversation_id=="w-b2a")]|length' "$RES/evidence/a-dump.json")"; ba_u="$(jq '[.inbox.records[]|select(.conversation_id=="w-b2a")|.message_id]|unique|length' "$RES/evidence/a-dump.json")"
  dupev=$(( $(jq .events.duplicate_message_received_events "$RES/evidence/b-dump.json") + $(jq .events.duplicate_message_received_events "$RES/evidence/a-dump.json") ))
  local dir lbl
  for dir in a_to_b b_to_a; do
    lbl="${dir//_to_/ -> }"
    local dl; dl="$(jq ".$dir.delivered" "$RES/evidence/bench.json")"
    if [ "$dl" = "$N_MSGS" ]; then
      pass "2.bench.$dir" "$lbl: delivered $dl/$N_MSGS (authenticated receipts), send->receipt latency p50/p95/p99 = $(jq -r ".$dir.latency_ms_send_to_delivered|\"\(.p50)/\(.p95)/\(.p99)\"" "$RES/evidence/bench.json") ms (min $(jq ".$dir.latency_ms_send_to_delivered.min" "$RES/evidence/bench.json"), max $(jq ".$dir.latency_ms_send_to_delivered.max" "$RES/evidence/bench.json")), paced 400 ms per send, both directions concurrently; qemu nodes, poll interval 250 ms, includes WireGuard + relay hop" "agentnet-acceptance bench --n $N_MSGS --pace-ms 400 --tag w"
    else fail "2.bench.$dir" "$lbl delivered $dl/$N_MSGS (see evidence/bench.json)" "agentnet-acceptance bench"; fi
  done
  if [ "$ab_rows" = "$N_MSGS" ] && [ "$ab_u" = "$N_MSGS" ] && [ "$ba_rows" = "$N_MSGS" ] && [ "$ba_u" = "$N_MSGS" ] && [ "$dupev" = 0 ]; then
    pass "2.duplicates" "receiver inbox rows A->B $ab_rows (unique $ab_u), B->A $ba_rows (unique $ba_u); duplicate message.received events: $dupev" "agentnet-acceptance dump --data-dir \$B / \$A"
  else fail "2.duplicates" "rows A->B $ab_rows/$ab_u, B->A $ba_rows/$ba_u, duplicate events $dupev" "agentnet-acceptance dump"; fi
}

# ------------------------------------------------------------------ packet analysis of an underlay capture
# analyze_underlay FILE PREFIX : writes evidence/PREFIX-*.txt, sets U_* counters
analyze_underlay() {
  local f=$1 p=$2 e="$RES/evidence"
  U_TOTAL="$(cap_count "$f" 'ip or ip6 or arp')"
  U_WG="$(cap_count "$f" "udp and port 51820 and src net $UL and dst net $UL")"
  U_NONWG_UDP="$(cap_count "$f" 'udp and not port 51820')"
  U_TCP_M="$(cap_count "$f" "tcp and not host $IP_GW and not host $IP_I")"
  U_TCP_60000="$(cap_count "$f" "tcp port 60000 and not host $IP_GW and not host $IP_I")"
  U_OUTSIDE="$(cap_count "$f" "ip and not (src net $UL and dst net $UL)")"
  U_OVERLAY="$(cap_count "$f" "net $OVL")"
  U_IP6="$(cap_count "$f" 'ip6 and not dst net ff02::/16')"
  U_REST="$(cap_count "$f" "tcp and host $IP_GW")"
  U_MULTISTREAM="$(cap_grep "$f" 'multistream' "not host $IP_GW")"
  U_AGENTNET="$(cap_grep "$f" 'agentnet' "not host $IP_GW")"
  cap_list "$f" "ip and not (src net $UL and dst net $UL)" "$e/$p-outside-subnets.txt"
  cap_list "$f" "tcp and not host $IP_GW and not host $IP_I" "$e/$p-tcp-between-machines.txt"
  cap_list "$f" "udp and not port 51820" "$e/$p-non-wireguard-udp.txt"
  cap_flows "$f" "$e/$p-flows.txt"
  jq -nc --arg f "$f" --argjson total "${U_TOTAL:-0}" --argjson wg "${U_WG:-0}" --argjson nonwg "${U_NONWG_UDP:--1}" --argjson tcpm "${U_TCP_M:--1}" --argjson t60 "${U_TCP_60000:--1}" \
    --argjson out "${U_OUTSIDE:--1}" --argjson ov "${U_OVERLAY:--1}" --argjson ip6 "${U_IP6:--1}" --argjson rest "${U_REST:--1}" --argjson ms "${U_MULTISTREAM:--1}" --argjson an "${U_AGENTNET:--1}" \
    '{pcap:$f, packets_ip_ip6_arp:$total, wireguard_udp_51820_between_underlay_addresses:$wg, udp_not_51820:$nonwg, tcp_not_involving_docker_host_or_intruder:$tcpm, tcp_port_60000:$t60,
      ip_packets_with_an_endpoint_outside_underlay_subnet:$out, packets_with_an_overlay_10_66_0_0_24_address_on_the_underlay:$ov, ip6_non_multicast_listener:$ip6,
      tcp_to_or_from_docker_host_gateway_REST_agent_to_node:$rest, packets_containing_ascii_multistream:$ms, packets_containing_ascii_agentnet:$an,
      filters:{wg:"udp and port 51820 and src net 172.29.70.0/24 and dst net 172.29.70.0/24", nonwg_udp:"udp and not port 51820", tcp_between_machines:"tcp and not host 172.29.70.1 and not host 172.29.70.66", tcp_60000:"tcp port 60000 and not host 172.29.70.1 and not host 172.29.70.66", outside:"ip and not (src net 172.29.70.0/24 and dst net 172.29.70.0/24)", overlay:"net 10.66.0.0/24", ip6:"ip6 and not dst net ff02::/16", rest:"tcp and host 172.29.70.1"}}' > "$e/$p-summary.json"
}
underlay_clean() { [ "${U_WG:-0}" -gt 0 ] && [ "$U_NONWG_UDP" = 0 ] && [ "$U_TCP_M" = 0 ] && [ "$U_TCP_60000" = 0 ] && [ "$U_OUTSIDE" = 0 ] && [ "$U_OVERLAY" = 0 ] && [ "$U_IP6" = 0 ]; }
underlay_text() { echo "$U_TOTAL packets total; WireGuard UDP/51820 between underlay addresses: $U_WG; UDP other than 51820: $U_NONWG_UDP; TCP between the machines (excluding the docker host's REST connections): $U_TCP_M; tcp/60000 (excluding the docker host and the intruder): $U_TCP_60000; IP packets with an endpoint outside 172.29.70.0/24: $U_OUTSIDE; packets carrying an overlay 10.66.0.0/24 address: $U_OVERLAY; non-multicast IPv6: $U_IP6; packets containing the ASCII strings 'multistream' / 'agentnet': $U_MULTISTREAM / $U_AGENTNET; (REST between the host and the nodes via the docker gateway, cleartext by design, loopback in a real deployment: $U_REST)"; }

# ================================================================== STEP 3
step3() {
  log "=== STEP 3: packet proof (main capture, bring-up through step 2)"
  cap_stop main "$BR"
  analyze_underlay "main-$BR.pcap" u-main
  if underlay_clean; then
    pass "3.underlay_only_wg" "capture 'main' (from before the first handshake through bring-up, contacts, CLI+MCP messages and 2x$N_MSGS paced messages): $(underlay_text)" "tcpdump -i $BR -nn -s 0 -w main-$BR.pcap (docker run --net host in the colima VM); read back with the filters in evidence/u-main-summary.json"
  else fail "3.underlay_only_wg" "$(underlay_text) (see evidence/u-main-*.txt)" "tcpdump read-back filters"; fi
  if [ "$U_MULTISTREAM" = 0 ] && [ "$U_AGENTNET" = 0 ]; then
    pass "3.no_cleartext" "no packet on the underlay carries the ASCII strings 'multistream' (libp2p protocol negotiation, cleartext inside TCP) or 'agentnet' (content topic /agentnet/1/...); positive control for the string search is check 4.control_cleartext, where the same strings DO appear when the firewall is opened" "tcpdump -nn -A -r main-$BR.pcap | grep -a -c multistream"
  else fail "3.no_cleartext" "multistream=$U_MULTISTREAM agentnet=$U_AGENTNET" "tcpdump -A | grep"; fi
  # ---- 3.paths: probes from a keyed machine (own captures, so they do not contaminate the 'main' capture)
  local pr
  for pr in unguarded guarded; do
    if [ $pr = guarded ]; then
      for m in r a b; do wx $m iptables -I OUTPUT -d 10.66.0.0/24 ! -o wg0 -m comment --comment wgsim-no-overlay-prefix-off-tunnel -j REJECT; done
    fi
    cap_start "paths-$pr" "$BR"; sleep 2
    q step3-paths docker exec an-wg-a nc -zv -w 5 "$IP_R" 60000
    local rc_ul=$RC out_ul="$OUT $ERR"
    q step3-paths docker exec an-wg-a nc -zv -w 3 10.66.0.3 60000
    local rc_ab=$RC out_ab="$OUT $ERR"
    q step3-paths docker exec an-wg-a nc -zv -w 5 10.66.0.1 60000
    local rc_ov=$RC out_ov="$OUT $ERR"
    cap_stop "paths-$pr" "$BR"
    local leak syn_ul; leak="$(cap_count "paths-$pr-$BR.pcap" "net $OVL and not (src net $OVL and dst net $OVL)")"; syn_ul="$(cap_count "paths-$pr-$BR.pcap" "tcp port 60000 and dst host $IP_R")"
    echo "$pr: A->R underlay:60000 rc=$rc_ul [$out_ul]; A->10.66.0.3:60000 rc=$rc_ab [$out_ab]; A->10.66.0.1:60000 rc=$rc_ov [$out_ov]; underlay packets to an overlay address: $leak; SYNs to R:60000 on the underlay: $syn_ul" > "$RES/evidence/paths-$pr.txt"
    cap_list "paths-$pr-$BR.pcap" "net $OVL" "$RES/evidence/paths-$pr-overlay-addr-packets.txt"
    if [ "$rc_ul" != 0 ] && [ "$rc_ab" != 0 ] && [ "$rc_ov" = 0 ]; then
      if [ $pr = unguarded ]; then
        pass "3.paths_unguarded" "from A's namespace (a keyed machine): R's UNDERLAY address $IP_R:60000 fails (exit $rc_ul, timed out: the SYNs reached R and were dropped, $syn_ul on the wire); B's overlay address 10.66.0.3:60000 fails (exit $rc_ab; A's only WireGuard peer is R) BUT $leak SYN packets for the overlay address were sent out of eth0 in cleartext via the default route (evidence/paths-unguarded-overlay-addr-packets.txt): WireGuard AllowedIPs does not stop a host from sending overlay-prefix traffic elsewhere. AgentNet never does (its only destination is R's configured address); a hardened client needs the OUTPUT guard of 3.paths_guarded. R's overlay address succeeds ($(echo "$out_ov" | tr '\n' ' '))." "docker exec an-wg-a nc -zv -w 5 172.29.70.10 60000 ; nc -zv 10.66.0.3 60000 ; nc -zv 10.66.0.1 60000 (tcpdump on $BR)"
      else
        if [ "$leak" = 0 ]; then
          pass "3.paths_guarded" "with 'iptables -I OUTPUT -d 10.66.0.0/24 ! -o wg0 -j REJECT' on every machine the same probes give: underlay R:60000 fails (exit $rc_ul), B's overlay address fails immediately (exit $rc_ab: $(echo "$out_ab" | tr '\n' ' ')) with 0 packets for overlay addresses on the underlay, R's overlay address succeeds" "iptables -I OUTPUT -d 10.66.0.0/24 ! -o wg0 -j REJECT ; nc -zv ..."
        else fail "3.paths_guarded" "guard rule present but $leak overlay-address packets still appeared on the underlay" "nc"; fi
      fi
    else fail "3.paths_$pr" "$(cat "$RES/evidence/paths-$pr.txt")" "nc -zv"; fi
  done

}

# ------------------------------------------------------------------ step 4 helpers
r_connected() { connected_ids "$R"; }
poll_topic() { # node-url content-topic -> JSON array text
  curl -s -m 8 "$1/relay/v1/auto/messages/$(enc "$2")"
}
intruder_sub() { # subscribe the intruder's node to a content topic
  curl -s -m 8 -X POST -H 'content-type: application/json' -d "[\"$1\"]" "$NI/relay/v1/auto/subscriptions" -w ' HTTP %{http_code}'
}
R_MADDR_UL() { echo "/ip4/$IP_R/tcp/60000/p2p/$RID"; }

step4() {
  log "=== STEP 4: intruder"
  local ct_b ct_a; ct_b="$(cat "$WORK/b.topic")"; ct_a="$(cat "$WORK/a.topic")"
  local e="$RES/evidence"
  # ---- 4a blocked
  cap_start s4a "$BR"; sleep 2
  r_connected > "$e/r-connected-before-intruder.txt"; peers_json "$R" > "$e/peers-r-before-intruder.json"
  wx r iptables -vnxL INPUT > "$e/firewall-r-counters-before-intruder.txt"
  compose --profile intruder up -d intruder >> "$RES/logs/docker.log" 2>&1
  sleep 2
  q step4-nc docker exec an-wg-intruder nc -zv -w 5 "$IP_R" 60000; local rc1=$RC o1="$OUT $ERR"
  q step4-nc docker exec an-wg-intruder nc -zv -w 5 "$IP_A" 60000; local rc2=$RC o2="$OUT $ERR"
  q step4-nc docker exec an-wg-intruder nc -zv -w 5 "$IP_R" 8645; local rc3=$RC o3="$OUT $ERR"
  q step4-nc docker exec an-wg-intruder nc -zvu -w 3 "$IP_R" 51820; local rc4=$RC o4="$OUT $ERR"
  wx r iptables -vnxL INPUT > "$e/firewall-r-counters-after-nc.txt"
  local drops_before drops_after
  drops_before="$(grep wgsim-underlay-libp2p-drop "$e/firewall-r-counters-before-intruder.txt" | awk '{print $1}')"
  drops_after="$(grep wgsim-underlay-libp2p-drop "$e/firewall-r-counters-after-nc.txt" | awk '{print $1}')"
  { echo "intruder -> R:60000 (underlay): rc=$rc1 $o1"; echo "intruder -> A:60000 (underlay): rc=$rc2 $o2"; echo "intruder -> R:8645 REST (underlay): rc=$rc3 $o3"; echo "intruder -> R:51820/udp (underlay): rc=$rc4 $o4"; echo "R drop-rule packet counter: $drops_before -> $drops_after"; } > "$e/intruder-nc.txt"
  if [ "$rc1" != 0 ] && [ "$rc2" != 0 ] && [ "$rc3" != 0 ] && [ "${drops_after:-0}" -gt "${drops_before:-0}" ]; then
    pass "4.nc_blocked" "intruder (underlay $IP_I, no WireGuard key): nc to R $IP_R:60000 -> exit $rc1 ($(echo "$o1" | tr '\n' ' ')); to A $IP_A:60000 -> exit $rc2; to R's REST port 8645 -> exit $rc3 (only the docker host may); R's underlay-drop rule counter went $drops_before -> $drops_after packets, so the SYNs arrived and were dropped, not lost. UDP 51820 'connect' (connectionless, so exit $rc4 proves nothing) is open by design: unauthenticated WireGuard packets get no reply." "docker exec an-wg-intruder nc -zv -w 5 172.29.70.10 60000 ; docker exec an-wg-r iptables -vnxL INPUT"
  else fail "4.nc_blocked" "$(cat "$e/intruder-nc.txt" | tr '\n' ' ')" "nc -zv"; fi
  # intruder node
  compose --profile intruder up -d intruder-node >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "intruder node health" health "$NI"
  # the node's REST answers 404 "relay endpoints are not available while initializing" for a while; retry until the subscription is accepted
  local ts0 tries=0 sub_ok=0; ts0=$(now_ms); : > "$e/intruder-subscribe.txt"
  while [ $(( $(now_ms) - ts0 )) -lt 240000 ]; do
    tries=$((tries+1)); local c1 c2
    c1="$(curl -s -o /dev/null -m 8 -X POST -H 'content-type: application/json' -d "[\"$ct_b\"]" "$NI/relay/v1/auto/subscriptions" -w '%{http_code}')"
    c2="$(curl -s -o /dev/null -m 8 -X POST -H 'content-type: application/json' -d "[\"$ct_a\"]" "$NI/relay/v1/auto/subscriptions" -w '%{http_code}')"
    echo "try $tries at +$(( $(now_ms) - ts0 )) ms: subscribe B-topic HTTP $c1, A-topic HTTP $c2" >> "$e/intruder-subscribe.txt"
    [ "$c1" = 200 ] && [ "$c2" = 200 ] && { sub_ok=1; break; }
    sleep 3
  done
  log "intruder subscription accepted=$sub_ok after $(( $(now_ms) - ts0 )) ms ($tries tries)"
  curl -s -m 8 -X POST -H 'content-type: application/json' -d "[\"$(R_MADDR_UL)\"]" "$NI/admin/v1/peers" -w ' HTTP %{http_code}\n' > "$e/intruder-dial-1.txt" 2>&1   # what the adapter does: explicit dial
  sleep 45
  curl -s -m 8 -X POST -H 'content-type: application/json' -d "[\"$(R_MADDR_UL)\"]" "$NI/admin/v1/peers" -w ' HTTP %{http_code}\n' > "$e/intruder-dial-2.txt" 2>&1
  # legitimate traffic during the intruder's presence
  local ids="" i id
  for i in 1 2 3 4 5; do id="$(send a b "w-while-intruder-blocked-$i" --conversation s4a)"; ids="$ids $id"; sleep 2; done
  # shellcheck disable=SC2086
  wait_for 300 "s4a delivered" all_in_state a delivered $ids; local s4a_ms=$WAITED_MS
  sleep 10
  peers_json "$NI" > "$e/peers-intruder-blocked.json"; peers_json "$R" > "$e/peers-r-during-intruder-blocked.json"; r_connected > "$e/r-connected-during-intruder-blocked.txt"
  poll_topic "$NI" "$ct_b" > "$e/intruder-poll-b-topic-blocked.json"; poll_topic "$NI" "$ct_a" > "$e/intruder-poll-a-topic-blocked.json"
  local nb na cnt_i st_i
  nb="$(jq 'if type=="array" then length else -1 end' "$e/intruder-poll-b-topic-blocked.json" 2>/dev/null || echo -1)"
  na="$(jq 'if type=="array" then length else -1 end' "$e/intruder-poll-a-topic-blocked.json" 2>/dev/null || echo -1)"
  st_i="$(jq -c '[.[]|{multiaddr,connected}]' "$e/peers-intruder-blocked.json")"
  if [ "$(cat "$e/r-connected-before-intruder.txt")" = "$(cat "$e/r-connected-during-intruder-blocked.txt")" ] && ! jq -e 'any(.[]; .connected=="Connected")' "$e/peers-intruder-blocked.json" >/dev/null; then
    pass "4.intruder_not_peer" "intruder node (--staticnode = R's UNDERLAY multiaddr, cluster 66, shard 0, two explicit dials): its peer list $st_i, none Connected. R's connected peers unchanged: before [$(cat "$e/r-connected-before-intruder.txt")] = during [$(cat "$e/r-connected-during-intruder-blocked.txt")] (R sees only A and B)" "curl $NI/admin/v1/peers ; POST $NI/admin/v1/peers [R underlay multiaddr] ; curl $R/admin/v1/peers"
  else fail "4.intruder_not_peer" "intruder peers $st_i; R connected before [$(cat "$e/r-connected-before-intruder.txt")] during [$(cat "$e/r-connected-during-intruder-blocked.txt")]" "curl admin/v1/peers"; fi
  if [ "$nb" = 0 ] && [ "$na" = 0 ]; then
    pass "4.intruder_no_frames" "while A sent 5 messages to B (all delivered with receipts) the intruder, subscribed to B's and A's inbox content topics, polled $nb frames on B's topic and $na on A's topic (empty arrays: evidence/intruder-poll-*-blocked.json)" "POST $NI/relay/v1/auto/subscriptions [topic] ; GET $NI/relay/v1/auto/messages/<topic>"
  else fail "4.intruder_no_frames" "intruder polled b-topic=$nb a-topic=$na frames" "GET relay/v1/auto/messages"; fi
  cap_stop s4a "$BR"
  # ---- 4b CONTROL: open the firewall
  log "--- control: opening the firewall for the underlay"
  cap_start s4b "$BR"; sleep 2
  wx r iptables -D $fw_rule_drop
  wx r iptables -I INPUT 2 -i eth0 -p tcp --dport 60000 -m comment --comment wgsim-CONTROL-underlay-libp2p-accept -j ACCEPT
  wx r iptables -S INPUT > "$e/firewall-r-control.txt"
  local tc0; tc0=$(now_ms)
  curl -s -m 8 -X POST -H 'content-type: application/json' -d "[\"$(R_MADDR_UL)\"]" "$NI/admin/v1/peers" > /dev/null
  local connected=0
  for i in $(seq 1 30); do peer_connected "$NI" "$RID" && { connected=1; break; }; curl -s -m 8 -X POST -H 'content-type: application/json' -d "[\"$(R_MADDR_UL)\"]" "$NI/admin/v1/peers" >/dev/null; sleep 2; done
  local t_conn=$(( $(now_ms) - tc0 ))
  peers_json "$R" > "$e/peers-r-control.json"; peers_json "$NI" > "$e/peers-intruder-control.json"
  if [ $connected = 1 ] && jq -e --arg ip "$IP_I" 'any(.[]; (.multiaddr|contains($ip)) and .connected=="Connected")' "$e/peers-r-control.json" >/dev/null; then
    pass "4.control_connects" "CONTROL (drop rule removed, accept rule inserted): the same intruder became a Connected peer of R after $t_conn ms; R's peer list now contains $(jq -c --arg ip "$IP_I" '[.[]|select(.multiaddr|contains($ip))|{multiaddr,connected}]' "$e/peers-r-control.json"). So the test CAN fail: the firewall rule is what kept it out." "iptables -D $fw_rule_drop ; iptables -I INPUT 2 -i eth0 -p tcp --dport 60000 -j ACCEPT ; POST $NI/admin/v1/peers"
  else fail "4.control_connects" "intruder did not connect to R even with the firewall open (connected=$connected, $t_conn ms): the control did not work; evidence/peers-*-control.json" "iptables control"; fi
  # frames seen by the intruder: keep sending until it sees one on B's topic (mesh warm-up takes up to ~60 s) or timeout
  local got_b=0 got_a=0 tstart sent=0 cids=""; tstart=$(now_ms)
  : > "$e/intruder-frames-control.jsonl"
  while [ $(( $(now_ms) - tstart )) -lt $(( CONTROL_TIMEOUT * 1000 )) ]; do
    id="$(send a b "w-CONTROL-marker-plaintext-$sent" --conversation s4b)"; cids="$cids $id"; sent=$((sent+1))
    sleep 4
    poll_topic "$NI" "$ct_b" > "$WORK/pb.json"; poll_topic "$NI" "$ct_a" > "$WORK/pa.json"
    jq -c '.[]?' "$WORK/pb.json" >> "$e/intruder-frames-control.jsonl" 2>/dev/null; jq -c '.[]?' "$WORK/pa.json" >> "$e/intruder-frames-control.jsonl" 2>/dev/null
    got_b="$(jq -s --arg t "$ct_b" '[.[]|select(.contentTopic==$t)]|length' "$e/intruder-frames-control.jsonl")"
    got_a="$(jq -s --arg t "$ct_a" '[.[]|select(.contentTopic==$t)]|length' "$e/intruder-frames-control.jsonl")"
    [ "$got_b" -ge 1 ] && break
  done
  local t_frames=$(( $(now_ms) - tstart ))
  # Store query by the intruder against R (R's store answers any peer that can reach it)
  local sq; sq="$(curl -s -m 20 "$NI/store/v3/messages?peerAddr=$(enc "$(R_MADDR_UL)")&contentTopics=$(enc "$ct_b")&includeData=true&pageSize=20&ascending=true&startTime=1")"
  echo "$sq" > "$e/intruder-store-query-control.json"
  local sq_n; sq_n="$(echo "$sq" | jq '.messages|length' 2>/dev/null || echo -1)"
  if [ "$got_b" -ge 1 ] || [ "${sq_n:--1}" -ge 1 ]; then
    pass "4.control_sees_frames" "CONTROL: with the firewall open the intruder received $got_b live frame(s) on B's inbox topic and $got_a on A's topic via relay (first within $t_frames ms of the rule change, after $sent sends), and its Store query against R returned $sq_n stored frame(s) for B's topic. Cluster/shard separation is NOT access control." "GET $NI/relay/v1/auto/messages/<B topic> ; GET $NI/store/v3/messages?peerAddr=<R>&contentTopics=<B topic>"
  else fail "4.control_sees_frames" "intruder saw 0 frames live and $sq_n via Store within ${CONTROL_TIMEOUT}s even with the firewall open ($sent messages sent)" "GET relay messages / store"; fi
  # ciphertext only
  python3 -I - "$e/intruder-frames-control.jsonl" "$e/intruder-store-query-control.json" > "$e/intruder-frames-analysis.json" <<'PY'
import json, sys, base64
frames = []
for l in open(sys.argv[1]):
    l = l.strip()
    if l: frames.append(json.loads(l))
try:
    for m in json.load(open(sys.argv[2])).get("messages", []):
        frames.append(m["message"])
except Exception: pass
out = {"frames_examined": len(frames), "frames": []}
leak = False
for f in frames:
    raw = base64.b64decode(f.get("payload", ""))
    hit = any(s in raw for s in (b"CONTROL", b"marker", b"plaintext", b"w-CONTROL", b"an1"))
    leak = leak or hit
    out["frames"].append({"contentTopic": f.get("contentTopic"), "payload_bytes": len(raw), "first_8_bytes_hex": raw[:8].hex(), "plaintext_marker_or_address_found": hit})
out["any_plaintext_found"] = leak
out["note"] = "The intruder holds no AgentNet identity key: it sees ciphertext frames (padded length, topic, time). It is NOT shown here that decryption is impossible beyond the absence of plaintext in the payload; the wrong-recipient test is results/a2-e2e-crypto."
print(json.dumps(out, indent=1))
PY
  if [ "$(jq .frames_examined "$e/intruder-frames-analysis.json")" -ge 1 ] && [ "$(jq .any_plaintext_found "$e/intruder-frames-analysis.json")" = false ]; then
    pass "4.control_ciphertext_only" "the $(jq .frames_examined "$e/intruder-frames-analysis.json") frame(s) the intruder obtained contain no plaintext marker or address (payload sizes $(jq -c '[.frames[].payload_bytes]' "$e/intruder-frames-analysis.json")): ciphertext only. That is the application-layer E2E encryption working, and exactly why cluster/shard separation is not access control: the intruder still learns topics, timing, sizes and sees the traffic of everyone on the shard." "evidence/intruder-frames-analysis.json"
  else fail "4.control_ciphertext_only" "frames=$(jq .frames_examined "$e/intruder-frames-analysis.json") plaintext=$(jq .any_plaintext_found "$e/intruder-frames-analysis.json")" "analysis"; fi
  cap_stop s4b "$BR"
  U_MULTISTREAM="$(cap_grep "s4b-$BR.pcap" 'multistream' "not host $IP_GW")"; local t60; t60="$(cap_count "s4b-$BR.pcap" "tcp port 60000 and host $IP_I")"; local u_ag; u_ag="$(cap_grep "s4b-$BR.pcap" 'agentnet' "not host $IP_GW")"
  if [ "${t60:-0}" -gt 0 ] && [ "${U_MULTISTREAM:-0}" -gt 0 ]; then
    pass "4.control_cleartext" "CONTROL capture: $t60 tcp/60000 packets between the intruder and R on the underlay, $U_MULTISTREAM contain the cleartext libp2p 'multistream' negotiation (and $u_ag the ASCII 'agentnet'): the string search of check 3.no_cleartext can detect cleartext when it exists" "tcpdump -nn -A -r s4b-$BR.pcap | grep -a -c multistream"
  else fail "4.control_cleartext" "tcp60000 packets=$t60 multistream=$U_MULTISTREAM" "tcpdump"; fi
  # ---- 4c restore
  log "--- restore the firewall rule"
  cap_start s4c "$BR"; sleep 2
  wx r iptables -D INPUT -i eth0 -p tcp --dport 60000 -m comment --comment wgsim-CONTROL-underlay-libp2p-accept -j ACCEPT
  wx r iptables -I INPUT 2 -i eth0 -p tcp --dport 60000 -m comment --comment wgsim-underlay-libp2p-drop -j DROP
  wx r iptables -S INPUT > "$e/firewall-r-restored.txt"
  compose --profile intruder stop intruder-node >> "$RES/logs/docker.log" 2>&1
  sleep 5
  q step4-nc docker exec an-wg-intruder nc -zv -w 5 "$IP_R" 60000; local rc5=$RC
  # the nodes of A and B must still be connected through the overlay
  local still_a=0 still_b=0; peer_connected "$NA" "$RID" && still_a=1; peer_connected "$NB" "$RID" && still_b=1
  local idr; idr="$(send a b "w-after-restore" --conversation s4c)"
  wait_for 180 "post-restore delivery" state_is a "$idr" delivered; local ms_r=$WAITED_MS
  cap_stop s4c "$BR"
  analyze_underlay "s4c-$BR.pcap" u-s4c
  if [ "$rc5" != 0 ] && grep -q wgsim-underlay-libp2p-drop "$e/firewall-r-restored.txt" && ! grep -q CONTROL "$e/firewall-r-restored.txt" && [ $still_a = 1 ] && [ $still_b = 1 ] && state_is a "$idr" delivered; then
    pass "4.restored" "drop rule restored (evidence/firewall-r-restored.txt); a fresh nc from the intruder to R:60000 fails again (exit $rc5); A's and B's nodes still Connected to R; an A->B message sent after the restore was delivered ($ms_r ms). Note: removing the accept rule alone does not evict an established flow; the drop rule is placed before the established-accept so it cuts it, and the intruder node was stopped as well." "iptables -D (control accept) ; iptables -I INPUT 2 (drop) ; nc -zv"
  else fail "4.restored" "nc rc=$rc5 still_a=$still_a still_b=$still_b state=$(mstate a "$idr")" "restore"; fi
  compose --profile intruder rm -sf intruder-node intruder >> "$RES/logs/docker.log" 2>&1
}

# ================================================================== STEP 5
step5() {
  log "=== STEP 5: remove B's WireGuard peer on R"
  local e="$RES/evidence" bpub; bpub="$(cat "$SIMDIR/.run/b.pub")"
  # make sure the topology is healthy again after step 4 (a stopped intruder leaves entries only on R)
  wait_for 120 "B connected" peer_connected "$NB" "$RID"; wait_for 120 "B ready" net_ready b
  cap_start s5 "$BR"; sleep 2
  local base; base="$(send a b "w-s5-baseline" --conversation s5base)"
  wait_for 120 "baseline delivered" state_is a "$base" delivered || log "baseline not delivered"
  local t0; t0=$(now_ms)
  wx r wg set wg0 peer "$bpub" remove
  wx r wg show wg0 > "$e/wg-show-r-after-remove.txt" 2>&1
  local mid; mid="$(send a b "w-s5-while-b-removed" --conversation s5)"
  # poll
  local t_node="" t_ready="" st="" end=$(( t0 + PEER_LOSS_TIMEOUT * 1000 )) delivered_early=0
  while [ "$(now_ms)" -lt "$end" ]; do
    [ -z "$t_node" ] && ! peer_connected "$NB" "$RID" && t_node=$(( $(now_ms) - t0 ))
    [ -z "$t_ready" ] && ! net_ready b && t_ready=$(( $(now_ms) - t0 ))
    st="$(mstate a "$mid")"; [ "$st" = delivered ] && { delivered_early=1; break; }
    [ -n "$t_node" ] && [ -n "$t_ready" ] && [ $(( $(now_ms) - t0 )) -gt 90000 ] && break
    sleep 2
  done
  local st_end; st_end="$(mstate a "$mid")"; local b_in; b_in="$(inbox_count b s5)"
  q step5-ss docker exec an-wg-b ss -tn state established
  cp "$RES/logs/step5-ss.log" "$e/b-established-tcp-after-remove.txt"
  wx b wg show wg0 > "$e/wg-show-b-after-remove.txt" 2>&1
  q step5-b-status "$BIN" --json --data-dir "$WORK/b" network status; printf '%s\n' "$OUT" > "$e/network-status-b-peer-removed.json"
  jq -nc --argjson tn "${t_node:--1}" --argjson tr "${t_ready:--1}" --arg st "$st_end" --argjson bin "$b_in" --argjson to "$PEER_LOSS_TIMEOUT" '{ms_until_B_node_stops_listing_R_as_connected:$tn, ms_until_B_daemon_not_ready:$tr, A_state_of_message_sent_after_removal:$st, B_inbox_rows_for_it:$bin, observation_window_s_max:$to}' > "$e/peer-removal-times.json"
  if [ "$delivered_early" = 0 ] && [ "$b_in" = 0 ]; then
    pass "5.undelivered" "after R dropped B's WireGuard peer, A's message to B stayed '$st_end' for the whole observation ($(( ($(now_ms) - t0) / 1000 )) s) and B's inbox has 0 rows for it (A's own path to R is intact, so the frame is accepted by R but cannot reach B)" "docker exec an-wg-r wg set wg0 peer <B pub> remove ; agentnet send ; agentnet status"
  else fail "5.undelivered" "state=$st_end B rows=$b_in delivered_early=$delivered_early" "peer remove"; fi
  if [ -n "$t_node" ]; then pass "5.b_node_loses_r" "B's node stopped listing R as Connected $t_node ms after the peer removal (note: removal drops packets silently, so the node learns it only by its own timeouts)" "curl $NB/admin/v1/peers"
  else fail "5.b_node_loses_r" "B's node STILL listed R as Connected ${PEER_LOSS_TIMEOUT}s after all its packets to R were being dropped (a zombie TCP connection; kernel retransmission, not libp2p, decides when it ends). evidence/b-established-tcp-after-remove.txt" "curl $NB/admin/v1/peers"; fi
  if [ -n "$t_ready" ]; then pass "5.b_daemon_not_ready" "B's daemon reported network.ready=false $t_ready ms after the removal" "agentnet --json network status (B)"
  else fail "5.b_daemon_not_ready" "B's daemon still reported ready=true after the observation window (it trusts the node's peer list, see 5.b_node_loses_r): $(jq -c .network "$e/network-status-b-peer-removed.json")" "agentnet --json network status (B)"; fi
  # capture so far: nothing but WireGuard on the underlay; B's attempts continue
  sleep 2; cap_stop s5 "$BR" ; cap_start s5b "$BR"; sleep 1
  # re-add
  local t1; t1=$(now_ms)
  wx r wg set wg0 peer "$bpub" allowed-ips 10.66.0.3/32
  local t_hs="" t_nodeback="" t_rdy="" t_del=""
  end=$(( t1 + 600000 ))
  while [ "$(now_ms)" -lt "$end" ]; do
    [ -z "$t_hs" ] && [ "$(wx r wg show wg0 latest-handshakes | grep "$bpub" | awk '{print $2}')" -gt "$(( t1 / 1000 - 1 ))" ] 2>/dev/null && t_hs=$(( $(now_ms) - t1 ))
    [ -z "$t_nodeback" ] && peer_connected "$NB" "$RID" && t_nodeback=$(( $(now_ms) - t1 ))
    [ -z "$t_rdy" ] && net_ready b && t_rdy=$(( $(now_ms) - t1 ))
    [ -z "$t_del" ] && [ "$(mstate a "$mid")" = delivered ] && t_del=$(( $(now_ms) - t1 ))
    [ -n "$t_del" ] && [ -n "$t_rdy" ] && break
    sleep 1
  done
  wx r wg show wg0 > "$e/wg-show-r-after-readd.txt" 2>&1
  sleep 3; cap_stop s5b "$BR"
  jq -nc --argjson hs "${t_hs:--1}" --argjson nb "${t_nodeback:--1}" --argjson rd "${t_rdy:--1}" --argjson dl "${t_del:--1}" '{ms_after_readd_until_wg_handshake:$hs, until_B_node_lists_R_connected:$nb, until_B_daemon_ready:$rd, until_A_message_delivered:$dl}' > "$e/peer-readd-times.json"
  if [ -n "$t_del" ]; then pass "5.recovery" "after re-adding B's peer on R: WireGuard handshake after ${t_hs:-?} ms, B's node lists R after ${t_nodeback:-?} ms, B's daemon ready after ${t_rdy:-?} ms, A's queued message delivered (authenticated receipt) after $t_del ms" "docker exec an-wg-r wg set wg0 peer <B pub> allowed-ips 10.66.0.3/32"
  else fail "5.recovery" "message not delivered within 600 s of re-adding the peer (state $(mstate a "$mid"); times $(cat "$e/peer-readd-times.json"))" "wg set ... allowed-ips"; fi
  analyze_underlay "s5-$BR.pcap" u-s5
  local s5_clean=0; underlay_clean && s5_clean=1; local s5txt; s5txt="$(underlay_text)"
  analyze_underlay "s5b-$BR.pcap" u-s5b
  if [ $s5_clean = 1 ] && underlay_clean; then
    pass "5.no_fallback" "captures during the removal window and the re-add window: only WireGuard UDP on the underlay; no tcp/60000, no cleartext, nothing outside the underlay subnet. Removal window: $s5txt. Re-add window: $(underlay_text)" "tcpdump read-back filters (evidence/u-s5-summary.json, u-s5b-summary.json)"
  else fail "5.no_fallback" "removal window: $s5txt; re-add window: $(underlay_text)" "tcpdump filters"; fi
}

# ================================================================== STEP 6
step6() {
  log "=== STEP 6: relay node down, tunnel up"
  local e="$RES/evidence"
  wait_for 120 "B ready" net_ready b; wait_for 120 "A ready" net_ready a
  cap_start s6 "$BR"; sleep 2
  docker stop an-wg-r-node >> "$RES/logs/docker.log" 2>&1
  local t0; t0=$(now_ms)
  local mid; mid="$(send a b "w-s6-relay-down" --conversation s6)"
  sleep 60
  local st rd det; st="$(mstate a "$mid")"
  q step6-status "$BIN" --json --data-dir "$WORK/a" network status; printf '%s\n' "$OUT" > "$e/network-status-a-relay-down.json"
  rd="$(echo "$OUT" | jq -r .network.ready)"; det="$(echo "$OUT" | jq -r .network.detail)"
  local hs; hs="$(wx a wg show wg0 latest-handshakes | awk '{print $2}')"
  local b_in; b_in="$(inbox_count b s6)"
  echo "A wg latest handshake epoch: $hs; now: $(date +%s)" > "$e/s6-wg-still-up.txt"
  if { [ "$st" = queued ] || [ "$st" = sent ]; } && [ "$b_in" = 0 ] && [ "$rd" = false ]; then
    pass "6.queued" "R's node stopped (tunnel and R's wg0 still up): A's message is '$st' after 60 s, A's network status ready=$rd ($det), B received $b_in" "docker stop an-wg-r-node ; agentnet send ; agentnet network status"
  else fail "6.queued" "state=$st ready=$rd B rows=$b_in" "relay down"; fi
  docker start an-wg-r-node >> "$RES/logs/docker.log" 2>&1
  wait_for 120 "R health" health "$R"; local t_h=$(( $(now_ms) - t0 )); local t1; t1=$(now_ms)
  local t_rdy="" t_del="" end=$(( t1 + RELAY_DOWN_TIMEOUT * 1000 ))
  while [ "$(now_ms)" -lt "$end" ]; do
    [ -z "$t_rdy" ] && net_ready a && t_rdy=$(( $(now_ms) - t1 ))
    [ -z "$t_del" ] && [ "$(mstate a "$mid")" = delivered ] && t_del=$(( $(now_ms) - t1 ))
    [ -n "$t_del" ] && [ -n "$t_rdy" ] && break
    sleep 2
  done
  sleep 3; cap_stop s6 "$BR"
  jq -nc --argjson h "$t_h" --argjson rd "${t_rdy:--1}" --argjson dl "${t_del:--1}" --argjson to "$RELAY_DOWN_TIMEOUT" '{ms_from_node_stop_to_R_health_after_restart:$h, ms_after_R_health_until_A_ready:$rd, ms_after_R_health_until_A_message_delivered:$dl, window_s:$to}' > "$e/relay-down-times.json"
  if [ -n "$t_del" ]; then pass "6.recovery" "R's node restarted (REST healthy ${t_h} ms after the stop command): A ready after ${t_rdy:-?} ms, the queued message delivered (authenticated receipt) ${t_del} ms after R's /health (sender retries / history sync; E12: live relay may lag)" "docker start an-wg-r-node"
  else fail "6.recovery" "not delivered within ${RELAY_DOWN_TIMEOUT}s of R's return (state $(mstate a "$mid"))" "docker start an-wg-r-node"; fi
  analyze_underlay "s6-$BR.pcap" u-s6
  if underlay_clean; then pass "6.no_fallback" "capture of the whole outage and recovery: $(underlay_text)" "tcpdump read-back filters (evidence/u-s6-summary.json)"
  else fail "6.no_fallback" "$(underlay_text)" "tcpdump read-back filters"; fi
}

# ------------------------------------------------------------------ main
case " $STEPS " in *" 1 "*) ;; *) STEPS="1 $STEPS";; esac
case " $STEPS " in *" 2 "*) ;; *) STEPS="1 2 $STEPS";; esac
for s in $STEPS; do
  case $s in
    1) step1 || { log "step 1 failed; later steps need it"; break; };;
    2) step2 || { log "step 2 failed; later steps need it"; break; };;
    3) step3;;
    4) step4;;
    5) step5;;
    6) step6;;
  esac
done
log "done; results in $RES"
