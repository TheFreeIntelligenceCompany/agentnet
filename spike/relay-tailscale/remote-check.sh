#!/usr/bin/env bash
# UNTESTED: written for the second-machine Tailscale run, never executed.
#
# Run on HOST A after the relay and agent A are up and the second machine ran `remote-client.sh up`. Interactive: steps that must happen
# on the second machine are printed and wait for Enter. Arguments only.
#
#   remote-check.sh --a-dir DIR_OF_AGENT_A --b-address ADDRESS_OF_B --b-record RECORD_FILE_OF_B --relay-tailnet-ip IP [--lan-ip HOST_A_LAN_IP] [--out DIR]
#
# Agent A's daemon must be serving (`agentnet --data-dir DIR serve`) against the relay. Checks (PASS/FAIL/UNTESTED lines + checks.jsonl):
#   x1 contact import (A learns B) and the instructions for B to learn A
#   x2 A -> B delivered with receipt          x3 B -> A reply delivered (B sends on the second machine)
#   x4 B offline: A sends while B's daemon is stopped, B restarts, message reaches delivered (recovery time recorded)
#   x5 reachability: from the second machine, tcp/60000 does not answer on host A's LAN IP (run remote-client.sh probe-lan there)
set -uo pipefail
AGENTNET="${AGENTNET:-agentnet}"; OUT="./remote-check-$(date -u +%Y%m%dT%H%M%SZ)"; ADIR=""; BADDR=""; BREC=""; RIP=""; LANIP=""
while [ $# -gt 0 ]; do case "$1" in
  --a-dir) ADIR="$2"; shift 2;; --b-address) BADDR="$2"; shift 2;; --b-record) BREC="$2"; shift 2;;
  --relay-tailnet-ip) RIP="$2"; shift 2;; --lan-ip) LANIP="$2"; shift 2;; --out) OUT="$2"; shift 2;;
  *) sed -n 2,16p "$0"; exit 2;; esac; done
[ -n "$ADIR" ] && [ -n "$BADDR" ] && [ -n "$BREC" ] && [ -n "$RIP" ] || { sed -n 2,16p "$0"; exit 2; }
mkdir -p "$OUT"; : > "$OUT/checks.jsonl"
an() { "$AGENTNET" --json --data-dir "$ADIR" "$@"; }
now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }
chk() { jq -nc --arg id "$1" --arg s "$2" --arg d "$3" '{id:$id,status:$s,detail:$d}' >> "$OUT/checks.jsonl"; echo "$2 $1 - $3"; }
wait_state() { local id=$1 want=$2 secs=$3 t0; t0=$(now_ms); while [ $(( $(now_ms) - t0 )) -lt $((secs*1000)) ]; do
  [ "$(an status "$id" | jq -r .state)" = "$want" ] && { WAITED=$(( $(now_ms) - t0 )); return 0; }; sleep 1; done; WAITED=$(( $(now_ms) - t0 )); return 1; }
pause() { echo; echo ">>> ON THE SECOND MACHINE: $1"; read -r -p "    press Enter when done " _; }
AADDR="$(an identity show | jq -r .agent_id)"

# x1
nc -z -w 5 "$RIP" 60000 && chk x0.relay_tailnet "PASS" "relay answers on its tailnet address from host A" || chk x0.relay_tailnet "FAIL" "relay does not answer"
an contact add "@$BREC" --expect "$BADDR" --alias remote-b > "$OUT/contact-add.json" 2>&1 && chk x1.contact_import "PASS" "A imported B's contact, verified against B's address" || chk x1.contact_import "FAIL" "contact add failed (see contact-add.json)"
echo "agent A address: $AADDR"
pause "run: remote-client.sh add-contact <A's contact record file, copied over> $AADDR   (A's record: agentnet --data-dir $ADIR identity show | jq -r .contact_record)"
# x2
ID="$(an send "$BADDR" "x2-a-to-b" --conversation x2 | jq -r .message_id)"
wait_state "$ID" delivered 600 && chk x2.a_to_b "PASS" "A -> B delivered with authenticated receipt after $WAITED ms (first message includes mesh warm-up)" || chk x2.a_to_b "FAIL" "not delivered in 600 s; state $(an status "$ID" | jq -r .state)"
# x3
pause "run: remote-client.sh send $AADDR x3-b-to-a    then wait until 'agentnet status <id>' on B says delivered"
N=$(an inbox --conversation "" --limit 50 2>/dev/null | jq -r '[.records[]?|select(.body=="x3-b-to-a")]|length' 2>/dev/null)
[ "${N:-0}" -ge 1 ] && chk x3.b_to_a "PASS" "B's message is in A's inbox with an authenticated sender" || chk x3.b_to_a "FAIL" "message x3-b-to-a not found in A's inbox (inbox query may need the conversation id B used; check manually: agentnet inbox)"
# x4
pause "stop B's daemon: remote-client.sh down   (this also stops B's node)"
ID4="$(an send "$BADDR" "x4-while-b-offline" --conversation x4 | jq -r .message_id)"; sleep 20
chk x4.pending_while_offline "$([ "$(an status "$ID4" | jq -r .state)" != delivered ] && echo PASS || echo FAIL)" "state while B is offline: $(an status "$ID4" | jq -r .state) (must not be delivered)"
pause "bring B back: remote-client.sh up <relay multiaddr>   (same --data-dir; a recreated node needs about 1 minute to rejoin, longer after relay restarts)"
T0=$(now_ms)
wait_state "$ID4" delivered 1200 && chk x4.recovery "PASS" "message sent while B was offline reached delivered ${WAITED} ms after B's restart" || chk x4.recovery "FAIL" "not delivered within 1200 s after B restart; state $(an status "$ID4" | jq -r .state)"
# x5
if [ -n "$LANIP" ]; then
  pause "run: remote-client.sh probe-lan $LANIP    (expect PASS: does not answer)"
  read -r -p "    did it print PASS? [y/N] " yn; [ "$yn" = y ] && chk x5.lan_unreachable "PASS" "from the second machine tcp/60000 does not answer on host A's LAN address" || chk x5.lan_unreachable "FAIL" "operator reported the LAN address answers"
else chk x5.lan_unreachable "UNTESTED" "no --lan-ip given"; fi
chk x6.acl "UNTESTED" "ACL/grants: from an UNTAGGED third tailnet machine nc -z <relay tailnet ip> 60000 must fail; from a tagged client it must succeed (README ACL snippet, not applied by any script)"
chk x7.path "UNTESTED" "direct vs DERP path: record 'tailscale status' / 'tailscale ping <relay>' on the second machine"
echo; echo "results in $OUT"
