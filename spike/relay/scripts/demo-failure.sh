#!/usr/bin/env bash
# Experiment E5: R1 (store/service node) down: what do clients see; reconnect timing after R1 restart.
set -u; . "$(dirname "$0")/common.sh"
cd "$(dirname "$0")/.."
enc() { python3 -I -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }
CTE=$(enc "$CT")
npeers() { curl -s -m 5 $1/admin/v1/peers | python3 -I -c "import json,sys;d=json.load(sys.stdin);print(len(d),[p['connected'] for p in d])"; }
echo "### baseline peers NB: $(npeers $NB)"
echo "### stop R1 at $(date -u +%T)"; docker-compose stop r1 >/dev/null 2>&1; sleep 3
echo "peers NB: $(npeers $NB)"
echo "### NB store query with R1 down"; time req GET "$NB/store/v3/messages?contentTopics=$CTE&includeData=false"
echo "### NA publish with R1 down"; pub $NA $CT "while-r1-down"
echo "### NB lightpush with R1 down"; req POST $NB/lightpush/v3/message "{\"message\":{\"payload\":\"$(b64 x)\",\"contentTopic\":\"$CT\"}}"
echo "### NB filter ping with R1 down"; req GET $NB/filter/v2/subscriptions/req-9
echo "### NB health"; curl -s $NB/health; echo
echo "### start R1 at $(date -u +%T) and poll NB peers until connected"
docker-compose start r1 >/dev/null 2>&1
T0=$(date +%s)
for i in $(seq 1 120); do
  n=$(curl -s -m 3 $NB/admin/v1/peers | python3 -I -c "import json,sys;d=json.load(sys.stdin);print(sum(1 for p in d if p['connected']=='Connected'))" 2>/dev/null)
  if [ "${n:-0}" -ge 1 ]; then echo "NB reconnected to R1 after $(( $(date +%s) - T0 ))s (poll #$i)"; break; fi; sleep 2
done
echo "### NA publish after R1 back (relay mesh formed?)"; sleep 5; pub $NA $CT "after-r1-back"; sleep 2; req GET $NB/relay/v1/auto/messages/$CTE
