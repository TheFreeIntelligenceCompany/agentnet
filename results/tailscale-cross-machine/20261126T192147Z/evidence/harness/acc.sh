#!/usr/bin/env bash
TSB=$(cat tsb)
to() { perl -e 'alarm shift; exec @ARGV' "$@"; }
echo "# $(date -u +%FT%TZ) (a) from the Mac: nc -z -w 5 <TS_IP_B> 60000"; nc -z -w 5 $TSB 60000; echo "rc=$?"
echo "# (a') from the Mac to the box's public addresses = from the open Internet side (expected: no answer)"
to 10 nc -z -w 6 <box-public-ipv4> 60000; echo "public-ipv4 60000 rc=$?"
V6=$(instabox exec agentnet-ts -- "ip -6 -br addr show eth0 | awk '{print \$3}' | cut -d/ -f1" 2>/dev/null)
to 10 nc -6 -z -w 6 $V6 60000; echo "public-ipv6 60000 rc=$?"
echo "# (b) on the box"
instabox exec agentnet-ts -- 'echo "## ss -ltnp (all TCP listeners)"; sudo ss -ltnp; echo "## docker port an-r1"; docker port an-r1; echo "## docker ps"; docker ps --format "{{.Names}}  {{.Ports}}"; echo "## addresses"; ip -br addr; V6=$(ip -6 -br addr show eth0 | awk "{print \$3}" | cut -d/ -f1); for t in "$(sudo tailscale ip -4)" 127.0.0.1 172.16.0.2 172.28.66.1 172.17.0.1 $V6; do timeout 6 nc -z -w 4 $t 60000 >/dev/null 2>&1; echo "nc -z $t 60000 rc=$?"; done; echo "## throw-away container on R network with a non-allowed source ip (172.28.66.99)"; docker run --rm --network ants --ip 172.28.66.99 alpine sh -c "nc -z -w 3 '"$TSB"' 60000; echo rc=\$?" 2>&1 | grep rc=; echo "## raw PREROUTING counters"; sudo iptables -t raw -L PREROUTING -nvx --line-numbers' 2>&1
echo "# (e) instabox port ls"; instabox port ls agentnet-ts 2>&1
