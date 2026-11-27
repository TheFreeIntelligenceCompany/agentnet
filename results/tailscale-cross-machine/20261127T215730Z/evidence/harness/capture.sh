#!/usr/bin/env bash
# capture on the box: tailscale0 and eth0 (tcp/60000 + udp wireguard) while A sends 3 one-char messages to B spaced 6 s apart
. /private/tmp/claude-501/tsx/env.sh
bx "sudo rm -f /tmp/ts0.pcap /tmp/eth0.pcap; (sudo timeout 40 tcpdump -nn -tt -i tailscale0 -w /tmp/ts0.pcap 'tcp port 60000' >/tmp/ts0.log 2>&1 &); (sudo timeout 40 tcpdump -nn -tt -i eth0 -w /tmp/eth0.pcap 'tcp port 60000 or udp port 41641' >/tmp/eth0.log 2>&1 &); sleep 2; echo started"
sleep 5
for i in 1 2 3; do echo "$(date +%s.%N | cut -c1-14) send A->B x$i"; anA --json send $(cat $X/addrB) "x" > /dev/null; sleep 6; done
echo "$(date +%s.%N | cut -c1-14) send B->A (1 char)"; bx "$BAN --json --data-dir $BD send $(cat $X/addrA) y >/dev/null; echo sent"
sleep 14
bx "sleep 12; sudo tcpdump -nn -tt -r /tmp/ts0.pcap 2>/dev/null > /tmp/ts0.txt; sudo tcpdump -nn -r /tmp/eth0.pcap 'tcp port 60000' 2>/dev/null > /tmp/eth0-tcp60000.txt; sudo tcpdump -nn -r /tmp/eth0.pcap 'udp port 41641' 2>/dev/null > /tmp/eth0-udp.txt; wc -l /tmp/ts0.txt /tmp/eth0-tcp60000.txt /tmp/eth0-udp.txt; cat /tmp/ts0.log /tmp/eth0.log"
