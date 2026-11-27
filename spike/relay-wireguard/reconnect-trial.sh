#!/usr/bin/env bash
# Reconnect experiment on the already-running an-wg topology (see README.md; bring it up with KEEP_UP=1 / KEEP_RUN=1).
# Drops B's WireGuard peer on R for OUT seconds, restores it, and records how long B's node takes to list R as Connected again.
#   VARIANT=none               client does nothing (the node's own behaviour)
#   VARIANT=redial             client POSTs the static peer to /admin/v1/peers every REDIAL_S s while R is not Connected,
#                              from the moment the path is removed (what the adapter did before the fix)
#   VARIANT=redial_after       as `redial` but only once the path is restored
#   VARIANT=cmd                after the path is restored, run $CMD_AFTER once (a candidate action), then poll
#   SETUP / TEARDOWN: shell run once before / after all trials (e.g. firewall or sysctl changes under test)
# Output: $OUTDIR/<variant>-<n>/{timeline.tsv,redials.tsv,node.log,summary.json}
set -uo pipefail
VARIANT=${VARIANT:-none}; N=${N:-1}; OUT=${OUT:-60}; MAXWAIT=${MAXWAIT:-300}; REDIAL_S=${REDIAL_S:-10}; OUTDIR=${OUTDIR:?}
NB=http://127.0.0.1:28652; RUNDIR="$(cd "$(dirname "$0")" && pwd)/.run"
RID=$(grep '^R_PEER_ID=' "$RUNDIR/env" | cut -d= -f2); BPUB=$(cat "$RUNDIR/b.pub")
ADDR="/ip4/10.66.0.1/tcp/60000/p2p/$RID"
now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
connected() { curl -s -m 3 "$NB/admin/v1/peers" | jq -e --arg id "$RID" '[.[]|select(.connected=="Connected" and (.multiaddr|contains($id)))]|length>0' >/dev/null 2>&1; }
[ "${FRESH:-0}" = 1 ] || { [ -n "${SETUP:-}" ] && bash -c "$SETUP"; }
trap '[ -n "${TEARDOWN:-}" ] && bash -c "$TEARDOWN"' EXIT
for i in $(seq 1 "$N"); do
  D="$OUTDIR/$VARIANT-$i"; mkdir -p "$D"
  if [ "${FRESH:-0}" = 1 ]; then "$(dirname "$0")/reconnect-up.sh" > "$D.up.txt" 2>&1; [ -n "${SETUP:-}" ] && bash -c "$SETUP"; fi
  # Pre-trial reset. If B is not connected (R may still hold the previous trial's half-open socket for up to ~15 min) we restart
  # R's NODE container (closes R's stale socket) and POST the static peer to B until it is connected. Recorded in reset.txt.
  w=0
  until connected; do
    sleep 2; w=$((w+2))
    if [ $w -ge 60 ]; then
      echo "pre-trial reset: B not connected after 60 s; restarting an-wg-r-node" | tee "$D/reset.txt" >&2
      docker restart an-wg-r-node >/dev/null; sleep 20
      for k in $(seq 1 30); do connected && break; curl -s -m 30 -X POST -H 'content-type: application/json' -d "[\"$ADDR\"]" "$NB/admin/v1/peers" >/dev/null; sleep 5; done
      w=0
    fi
  done
  sleep 10
  T0=$(now_ms); LOGSINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo -e "t_ms\tR_state_in_B_peers\tR_tcp_socket_to_B(ss on R)" > "$D/timeline.tsv"
  echo -e "t_ms\tevent\tdetail" > "$D/redials.tsv"
  docker exec an-wg-r wg set wg0 peer "$BPUB" remove
  echo -e "0\tpath_removed" >> "$D/redials.tsv"
  RESTORED=0; TR=0; TREC=-1; lastredial=-100000; nredial=0; cmddone=0; RS_RESTORE=-1
  while :; do
    t=$(( $(now_ms) - T0 ))
    if [ $RESTORED = 0 ] && [ "$t" -ge $((OUT*1000)) ]; then
      docker exec an-wg-r wg set wg0 peer "$BPUB" allowed-ips 10.66.0.3/32
      RESTORED=1; TR=$(( $(now_ms) - T0 )); RS_RESTORE=$(docker exec an-wg-r ss -tn state established 2>/dev/null | grep -c "10.66.0.3:"); echo -e "$TR\tpath_restored" >> "$D/redials.tsv"
    fi
    st=$(curl -s -m 3 "$NB/admin/v1/peers" | jq -r --arg id "$RID" '[.[]|select(.multiaddr|contains($id))|.connected]|join(",")' 2>/dev/null)
    rs=$(docker exec an-wg-r ss -tn state established 2>/dev/null | grep -c "10.66.0.3:") ; echo -e "$t\t${st:-none}\t$rs" >> "$D/timeline.tsv"
    if [ $RESTORED = 1 ] && [ "$st" = Connected ]; then TREC=$(( $(now_ms) - T0 - TR )); break; fi
    if [ $RESTORED = 1 ] && [ $(( t - TR )) -ge $((MAXWAIT*1000)) ]; then break; fi
    if [ "$VARIANT" = cmd ] && [ $RESTORED = 1 ] && [ $cmddone = 0 ]; then
      cmddone=1; s=$(now_ms); out=$(bash -c "$CMD_AFTER" 2>&1); echo -e "$t\tcmd\tdur_ms=$(( $(now_ms) - s )) out=$(echo "$out" | tr '\n\t' '  ' | cut -c1-300)" >> "$D/redials.tsv"
    fi
    if { [ "$VARIANT" = redial ] || { [ "$VARIANT" = redial_after ] && [ $RESTORED = 1 ]; }; } && [ "$st" != Connected ] && [ $(( t - lastredial )) -ge $((REDIAL_S*1000)) ]; then
      lastredial=$t; nredial=$((nredial+1)); s=$(now_ms)
      resp=$(curl -s -m 30 -w '\n%{http_code}' -X POST -H 'content-type: application/json' -d "[\"$ADDR\"]" "$NB/admin/v1/peers" 2>&1)
      code=${resp##*$'\n'}; body=${resp%$'\n'*}
      echo -e "$t\tredial\thttp=$code dur_ms=$(( $(now_ms) - s )) body=$(echo "$body" | tr '\n\t' '  ')" >> "$D/redials.tsv"
    fi
    sleep 2
  done
  docker logs --since "$LOGSINCE" an-wg-b-node > "$D/node.log" 2>&1
  jq -nc --arg v "$VARIANT" --argjson n "$i" --argjson out "$OUT" --argjson tr "$TR" --argjson rec "$TREC" --argjson nr "$nredial" --argjson rs "${RS_RESTORE:--1}" \
    '{variant:$v,trial:$n,outage_s:$out,restored_at_ms:$tr,recovery_ms_after_restore:$rec,redials:$nr,r_sockets_to_B_at_restore:$rs}' | tee "$D/summary.json"
  sleep 20
done
