#!/usr/bin/env bash
# FORCED stale-half-open-socket reconnect experiment on the running an-wg topology (bring it up as described in README.md).
#
# How the stale socket is forced deterministically (no reliance on timing luck):
#   1. B's firewall OUTPUT drops every tcp packet to R:60000, then B's node container is restarted. The old process dies, B's kernel
#      closes the socket but its FIN/RST never leaves the machine, so R keeps an ESTABLISHED socket to B's old ephemeral port
#      (exactly what a node kill during a silent outage, a laptop sleep or a lost NAT mapping leaves behind).
#   2. B's conntrack table is flushed (stands in for an expired firewall/NAT mapping), then the drop rule is removed once B's REST is up (T0). B's new node must now reconnect to R while R still holds the stale socket.
#      R's later retransmits to the old port hit B, whose firewall (INPUT DROP policy) silently discards them: no RST.
# Per tick it records B's view of R (GET /admin/v1/peers) and whether R still holds a socket to B (ss on R), and, for VARIANT=redial,
# does what the old adapter did: POST /admin/v1/peers with the static peer every REDIAL_S s while R is not Connected.
#   VARIANT=redial|none   N=trials   MAXWAIT=s   OUTDIR=dir   SETUP/TEARDOWN=shell run before/after all trials
set -uo pipefail
VARIANT=${VARIANT:-redial}; N=${N:-3}; MAXWAIT=${MAXWAIT:-1200}; REDIAL_S=${REDIAL_S:-10}; OUTDIR=${OUTDIR:?}
NB=http://127.0.0.1:28652; RUNDIR="$(cd "$(dirname "$0")" && pwd)/.run"
RID=$(grep '^R_PEER_ID=' "$RUNDIR/env" | cut -d= -f2); BPUB=$(cat "$RUNDIR/b.pub"); ADDR="/ip4/10.66.0.1/tcp/60000/p2p/$RID"
now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
connected() { curl -s -m 3 "$NB/admin/v1/peers" | jq -e --arg id "$RID" '[.[]|select(.connected=="Connected" and (.multiaddr|contains($id)))]|length>0' >/dev/null 2>&1; }
rsock() { docker exec an-wg-r ss -tno state established '( sport = :60000 )' 2>/dev/null | grep -F "10.66.0.3:" | tr -s ' ' | cut -c1-120; }
post() { curl -s -m 30 -w '\n%{http_code}' -X POST -H 'content-type: application/json' -d "[\"$ADDR\"]" "$NB/admin/v1/peers" 2>&1; }
DROP='-d 10.66.0.1 -p tcp --dport 60000 -j DROP'
[ -n "${SETUP:-}" ] && bash -c "$SETUP"
trap '[ -n "${TEARDOWN:-}" ] && bash -c "$TEARDOWN"; docker exec an-wg-b iptables -D OUTPUT $DROP 2>/dev/null' EXIT
for i in $(seq 1 "$N"); do
  D="$OUTDIR/$VARIANT-$i"; mkdir -p "$D"
  docker exec an-wg-r wg set wg0 peer "$BPUB" allowed-ips 10.66.0.3/32
  w=0; until connected && [ -n "$(rsock)" ]; do
    sleep 2; w=$((w+2))
    if [ $w -ge 60 ]; then   # reset: restart R's node (closes R's stale socket) and dial from B
      echo "pre-trial reset (B not connected / no socket on R after 60 s): restarting an-wg-r-node" | tee "$D/reset.txt" >&2
      docker restart an-wg-r-node >/dev/null; sleep 20
      for k in $(seq 1 30); do connected && break; post >/dev/null; sleep 5; done; w=0
    fi
  done
  sleep 5
  echo "R socket to B before: $(rsock)" > "$D/setup.txt"
  docker exec an-wg-b iptables -I OUTPUT $DROP
  docker restart an-wg-b-node >/dev/null
  until curl -sf -m 2 "$NB/health" >/dev/null 2>&1; do sleep 1; done
  docker exec an-wg-b conntrack -F >/dev/null 2>&1   # forget the old flow: R's retransmits become INVALID and hit INPUT DROP (no RST), like an expired NAT/firewall mapping
  docker exec an-wg-b iptables -D OUTPUT $DROP
  T0=$(now_ms); LOGSINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  STALE0=$(rsock); [ -n "$STALE0" ] && STALE=true || STALE=false
  echo "R socket to B at T0 (stale if non-empty): ${STALE0:-<none>}" >> "$D/setup.txt"
  echo -e "t_ms\tB_view_of_R\tR_holds_socket_to_B\tR_ss" > "$D/timeline.tsv"; echo -e "t_ms\thttp\tdur_ms\tbody" > "$D/redials.tsv"
  last=-100000; TREC=-1; TSDIE=-1; nred=0
  while :; do
    t=$(( $(now_ms) - T0 ))
    st=$(curl -s -m 3 "$NB/admin/v1/peers" | jq -r --arg id "$RID" '[.[]|select(.multiaddr|contains($id))|.connected]|join(",")' 2>/dev/null)
    rs=$(rsock); [ -n "$rs" ] && h=1 || h=0
    [ "$STALE" = true ] && [ "$TSDIE" -lt 0 ] && [ -z "$rs" ] && TSDIE=$t
    echo -e "$t\t${st:-none}\t$h\t$rs" >> "$D/timeline.tsv"
    if [ "$st" = Connected ]; then TREC=$t; break; fi
    [ $t -ge $((MAXWAIT*1000)) ] && break
    if [ "$VARIANT" = redial ] && [ $(( t - last )) -ge $((REDIAL_S*1000)) ]; then
      last=$t; nred=$((nred+1)); s=$(now_ms); resp=$(post); code=${resp##*$'\n'}; body=${resp%$'\n'*}
      echo -e "$t\t$code\t$(( $(now_ms) - s ))\t$(echo "$body" | tr '\n\t' '  ' | cut -c1-120)" >> "$D/redials.tsv"
    fi
    sleep 2
  done
  docker logs --since "$LOGSINCE" an-wg-b-node > "$D/node.log" 2>&1
  jq -nc --arg v "$VARIANT" --argjson n "$i" --argjson stale "$STALE" --argjson rec "$TREC" --argjson die "$TSDIE" --argjson nr "$nred" \
    '{variant:$v,trial:$n,r_held_stale_socket_at_t0:$stale,reconnect_ms_after_b_node_up:$rec,ms_until_stale_socket_gone_on_R:$die,redials:$nr}' | tee "$D/summary.json"
  sleep 15
done
