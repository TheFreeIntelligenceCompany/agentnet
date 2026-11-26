#!/usr/bin/env bash
# Experiment E7: what does a node with ALL discovery disabled actually talk to? Capture on the docker bridge from the VM
# netns (--net host inside the colima VM) while the whole stack is (re)started and exercised for DUR seconds.
# Usage: [DNS_NS=...] egress-capture.sh [DUR=150]. Writes pcap + summaries to $OUT.
# DNS_NS defaults to 1.1.1.1 HERE ON PURPOSE: this experiment documents the upstream default behaviour (the node's online
# monitor contacts 1.1.1.1 every 5 s). The compose files themselves default to 127.0.0.1 (no external contact); run with
# DNS_NS=127.0.0.1 to capture the hardened configuration instead (expected: 0 packets outside 172.28.66.0/24).
set -u; . "$(dirname "$0")/common.sh"; cd "$(dirname "$0")/.."
export DNS_NS="${DNS_NS:-1.1.1.1}"
echo "DNS_NS=$DNS_NS"
DUR=${1:-150}; TAG=${TAG:-egress}
NETID=$(docker network inspect agentnet-relay_relaynet --format '{{.Id}}'); BR=br-${NETID:0:12}
echo "bridge=$BR dur=$DUR"
docker rm -f an-cap >/dev/null 2>&1
docker run -d --name an-cap --net host --cap-add NET_RAW --cap-add NET_ADMIN -v "$OUT":/out nicolaka/netshoot \
  sh -c "timeout $DUR tcpdump -i $BR -nn -s 128 -w /out/$TAG.pcap" >/dev/null
sleep 3
docker-compose stop >/dev/null 2>&1; ./scripts/up.sh >/dev/null 2>&1   # stop (not down) so the bridge keeps its name; up.sh orders r1 first
echo "stack restarted at $(date -u +%T)"
# exercise: subscribe + publish + store query every 20s
sleep 20
for n in $NA $NB; do req POST $n/relay/v1/auto/subscriptions "[\"$CT\"]" >/dev/null; done
t_end=$(( $(date +%s) + DUR - 30 ))
while [ $(date +%s) -lt $t_end ]; do pub $NA $CT "egress-$(date +%s)" >/dev/null; sleep 10; done
docker wait an-cap >/dev/null
# summaries (inside netshoot, offline read of the pcap)
docker run --rm -v "$OUT":/out nicolaka/netshoot sh -c "
  tcpdump -nn -q -r /out/$TAG.pcap 2>/dev/null | wc -l > /out/$TAG.packets.txt
  echo '--- packets NOT entirely inside 172.28.66.0/24 (candidate egress):' > /out/$TAG.egress.txt
  tcpdump -nn -r /out/$TAG.pcap 'not (src net 172.28.66.0/24 and dst net 172.28.66.0/24)' 2>/dev/null >> /out/$TAG.egress.txt
  echo '--- all distinct (src ip, dst ip:port) pairs' > /out/$TAG.flows.txt
  tcpdump -nn -q -r /out/$TAG.pcap 2>/dev/null | awk '{print \$3, \$5}' | sed 's/:\$//' | sort | uniq -c | sort -rn >> /out/$TAG.flows.txt"
echo "total packets on bridge: $(cat "$OUT/$TAG.packets.txt")"
echo "packets with an endpoint outside 172.28.66.0/24 (excluding IPv6 multicast listener reports from the VM): $(grep -v 'ff02::16\|^---' "$OUT/$TAG.egress.txt" | wc -l)"
echo "distinct external endpoints:"; grep -v 'ff02::16\|^---' "$OUT/$TAG.egress.txt" | grep -o '> [0-9.]*\.[0-9]*:\|> [0-9.]*:' | sort | uniq -c
echo "(ip:port pairs, external side)"; grep -v 'ff02::16\|^---' "$OUT/$TAG.egress.txt" | awk '{print $3,$5}' | grep -v '^172\.28\.66\.[0-9]*\.[0-9]* 172\.28' | sed -E 's/^[0-9.]+\.[0-9]+ //; s/:$//' | sort | uniq -c
