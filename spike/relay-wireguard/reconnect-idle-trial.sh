#!/usr/bin/env bash
# Idle-stale-socket reconnect experiment on the running an-wg topology (reconnect-up.sh brings it up).
# Silent path loss between B and R is made with iptables DROP in R's namespace on wg0 both ways (nothing is delivered, no ICMP, no RST).
# Block lasts BLOCK_S s (default 70: B's node gives up and closes its socket after ~48-53 s; its FIN is dropped). The harness sends no
# traffic towards B during the block, so R's socket normally has nothing in flight (idle) when the path returns.
# Per trial it records every 2 s: B's view of R, R's `ss -tion` for B's sockets (timers/unacked/keepalive), and POSTs the static peer
# to B every REDIAL_S s from the start of the block while R is not Connected (the adapter's redial). Recovery clock starts at path restore.
#   BLOCK_S  REDIAL_S  MAXWAIT  OUTDIR  VARIANT(label)  N
#   HOOK_DURING="cmd"   run once at DURING_AT seconds after the block started (e.g. a candidate)
#   HOOK_AFTER="cmd"    run once when the path is restored   |  SETUP / TEARDOWN: run once before / after all trials
#   RESET=restart|wait  clear R's stale socket from the previous trial by restarting R's node (default) or only if B is not connected
set -uo pipefail
VARIANT=${VARIANT:-base}; N=${N:-1}; BLOCK_S=${BLOCK_S:-70}; MAXWAIT=${MAXWAIT:-600}; REDIAL_S=${REDIAL_S:-10}; OUTDIR=${OUTDIR:?}
DURING_AT=${DURING_AT:-30}
NB=http://127.0.0.1:18652; RUNDIR="$(cd "$(dirname "$0")" && pwd)/.run"
RID=$(grep '^R_PEER_ID=' "$RUNDIR/env" | cut -d= -f2); ADDR="/ip4/10.66.0.1/tcp/60000/p2p/$RID"
now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
connected() { curl -s -m 3 "$NB/admin/v1/peers" | jq -e --arg id "$RID" '[.[]|select(.connected=="Connected" and (.multiaddr|contains($id)))]|length>0' >/dev/null 2>&1; }
rss() { docker exec an-wg-r ss -tion state established '( sport = :60000 )' dst 10.66.0.3 2>/dev/null | awk 'NR>1 && /^[0-9]/ {if (l) print l; l=$0; next} NR>1 {l=l" "$0} END{if (l) print l}' | tr -s ' \t' ' '; }
block()   { docker exec an-wg-r sh -c 'iptables -I INPUT 1 -i wg0 -s 10.66.0.3 -j DROP; iptables -I OUTPUT 1 -o wg0 -d 10.66.0.3 -j DROP'; }
unblock() { docker exec an-wg-r sh -c 'iptables -D INPUT -i wg0 -s 10.66.0.3 -j DROP; iptables -D OUTPUT -o wg0 -d 10.66.0.3 -j DROP' >/dev/null 2>&1; }
[ -n "${SETUP:-}" ] && bash -c "$SETUP"
trap 'unblock; [ -n "${TEARDOWN:-}" ] && bash -c "$TEARDOWN"' EXIT
for i in $(seq 1 "$N"); do
  D="$OUTDIR/$VARIANT-$i"; mkdir -p "$D"; unblock
  if [ "${RESET:-restart}" = restart ] || ! connected; then
    docker restart an-wg-r-node >/dev/null; sleep 15
    for k in $(seq 1 40); do connected && break; curl -s -m 30 -X POST -H 'content-type: application/json' -d "[\"$ADDR\"]" "$NB/admin/v1/peers" >/dev/null; sleep 4; done
  fi
  connected || { echo "trial $i: B never connected, abort" >&2; exit 1; }
  sleep 20
  echo "R sockets to B before block: $(rss | cut -c1-60)" > "$D/setup.txt"
  T0=$(now_ms); LOGSINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf 't_ms\tphase\tB_view_of_R\tR_sockets_to_B\n' > "$D/timeline.tsv"; : > "$D/ss.log"; printf 't_ms\tevent\tdetail\n' > "$D/events.tsv"
  block; echo -e "0\tblock_start" >> "$D/events.tsv"
  RESTORED=0; TR=0; TREC=-1; last=-100000; nred=0; during=0; after=0; TBCLOSE=-1
  while :; do
    t=$(( $(now_ms) - T0 ))
    if [ $RESTORED = 0 ] && [ $t -ge $((BLOCK_S*1000)) ]; then
      unblock; RESTORED=1; TR=$t; echo -e "$t\tblock_end" >> "$D/events.tsv"
      echo "R at restore: $(rss | cut -c1-400)" >> "$D/setup.txt"
      if [ -n "${HOOK_AFTER:-}" ] && [ $after = 0 ]; then after=1; s=$(now_ms); o=$(bash -c "$HOOK_AFTER" 2>&1); echo -e "$t\thook_after\t$(( $(now_ms)-s ))ms $(echo "$o" | tr '\n\t' '  ' | cut -c1-300)" >> "$D/events.tsv"; fi
    fi
    if [ $RESTORED = 0 ] && [ -n "${HOOK_DURING:-}" ] && [ $during = 0 ] && [ $t -ge $((DURING_AT*1000)) ]; then
      during=1; s=$(now_ms); o=$(bash -c "$HOOK_DURING" 2>&1); echo -e "$t\thook_during\t$(( $(now_ms)-s ))ms $(echo "$o" | tr '\n\t' '  ' | cut -c1-300)" >> "$D/events.tsv"
    fi
    st=$(curl -s -m 3 "$NB/admin/v1/peers" | jq -r --arg id "$RID" '[.[]|select(.multiaddr|contains($id))|.connected]|join(",")' 2>/dev/null)
    s=$(rss); n=$(printf '%s' "$s" | grep -c .)
    { echo "== t=$t ms"; echo "$s"; } >> "$D/ss.log"
    { echo "== t=$t ms"; docker exec an-wg-b ss -tan 2>/dev/null | grep -F ":60000"; } >> "$D/b-ss.log"
    ph=block; [ $RESTORED = 1 ] && ph=restored
    echo -e "$t\t$ph\t${st:-none}\t$n" >> "$D/timeline.tsv"
    if [ $TBCLOSE -lt 0 ] && [ "${st:-none}" != Connected ]; then TBCLOSE=$t; echo -e "$t\tB_lists_R_not_connected\t$st" >> "$D/events.tsv"; fi
    if [ $RESTORED = 1 ] && [ "$st" = Connected ]; then TREC=$((t-TR)); break; fi
    if [ $RESTORED = 1 ] && [ $((t-TR)) -ge $((MAXWAIT*1000)) ]; then break; fi
    if [ "$st" != Connected ] && [ $((t-last)) -ge $((REDIAL_S*1000)) ]; then
      last=$t; nred=$((nred+1)); s0=$(now_ms)
      resp=$(curl -s -m 30 -w '\n%{http_code}' -X POST -H 'content-type: application/json' -d "[\"$ADDR\"]" "$NB/admin/v1/peers" 2>&1)
      echo -e "$t\tredial\thttp=${resp##*$'\n'} dur=$(( $(now_ms)-s0 ))ms" >> "$D/events.tsv"
    fi
    sleep 2
  done
  docker logs --since "$LOGSINCE" an-wg-b-node > "$D/b-node.log" 2>&1; docker logs --since "$LOGSINCE" an-wg-r-node > "$D/r-node.log" 2>&1
  jq -nc --arg v "$VARIANT" --argjson n "$i" --argjson blk "$BLOCK_S" --argjson tr "$TR" --argjson rec "$TREC" --argjson nr "$nred" --argjson tb "$TBCLOSE" \
    '{variant:$v,trial:$n,block_s:$blk,b_not_connected_at_ms:$tb,restored_at_ms:$tr,recovery_ms_after_restore:$rec,redials:$nr}' | tee "$D/summary.json"
done
