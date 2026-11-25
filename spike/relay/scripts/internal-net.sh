#!/usr/bin/env bash
# Experiment E8: run the topology on an `internal: true` docker network (no egress; docker also does NOT publish ports
# of internal networks to the host, so the test client runs as a sidecar container on that network).
# Usage: internal-net.sh [DNS_NS]   (default DNS_NS=1.1.1.1 = upstream default)
set -u; cd "$(dirname "$0")/.."; . scripts/common.sh
export NET_INTERNAL=true; export DNS_NS=${1:-1.1.1.1}
OUTD=${OUT:-/Users/dennison/develop/FIC-elipsis/results/a1-daemon}
docker rm -f an-dns >/dev/null 2>&1
docker-compose down >/dev/null 2>&1
if [ "$DNS_NS" = 172.28.66.53 ]; then  # start the stub resolver on the internal net first
  docker-compose up --no-start r1 >/dev/null 2>&1   # creates the network
  docker run -d --name an-dns --network agentnet-relay_relaynet --ip 172.28.66.53 -v "$PWD/scripts/dns-stub.py":/dns.py:ro nicolaka/netshoot python3 /dns.py >/dev/null
fi
docker-compose up -d >/dev/null 2>&1
echo "network internal flag: $(docker network inspect agentnet-relay_relaynet --format '{{.Internal}}'), DNS_NS=$DNS_NS; host-published port reachable? $(curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:18641/health)"
inet() { docker run --rm --network agentnet-relay_relaynet -v "$PWD/scripts":/w:ro -e R1_PEER_ID=$R1_PEER_ID -e R1=http://172.28.66.10:8645 -e NA=http://172.28.66.21:8645 -e NB=http://172.28.66.22:8645 nicolaka/netshoot "$@"; }
echo "### egress sanity from inside the network (expect failure):"
inet sh -c 'nc -zv -w 3 1.1.1.1 53; echo rc=$?; nc -zv -w 3 1.1.1.1 443; echo rc=$?'
echo "### wait for NA/NB to connect to R1"
T0=$(date +%s)
for i in $(seq 1 90); do
  n=$(inet sh -c 'for u in $NA $NB; do curl -s -m 3 $u/admin/v1/peers; echo; done' 2>/dev/null | grep -c '"connected":"Connected"')
  [ "$n" -ge 2 ] && { echo "NA,NB both connected after $(( $(date +%s)-T0 ))s"; break; }; sleep 2; done
echo "### demo-basic from inside the internal network"
inet bash /w/demo-basic.sh
echo "### health NB"; inet sh -c 'curl -s $NB/health'; echo
echo "### R1 log lines mentioning offline/online"; docker logs an-r1 2>&1 | grep -i "offline\|online" | sed 's/^/  /'
