#!/usr/bin/env bash
# Run ON the droplet. $1 = Mac public IP, $2 = droplet public IP. Capture: tcpdump -i eth0 -n -s 0 -w /root/pub.pcap 'tcp port 60000'
MY=$1; R=$2; P=/root/pub.pcap
echo "packets total: $(tcpdump -nn -r $P 2>/dev/null | wc -l)"
echo "--- distinct SOURCE addresses of packets to <PUB_IP_R>:60000"; tcpdump -nn -r $P "dst host $R and dst port 60000" 2>/dev/null | awk '{split($3,a,".");print a[1]"."a[2]"."a[3]"."a[4]}' | sort | uniq -c
echo "--- src/dst pairs"; tcpdump -nn -r $P 2>/dev/null | awk '{print $3,">",$5}' | sed 's/:$//' | sort | uniq -c | sort -rn
echo "--- body grep (raw packet bytes, count of hits per known synthetic string)"
for s in "synthetic" "benchA" "benchB" "tiny synthetic body" "first message" "offB" "offA" "from untrusted sender" "race round" "fw-trial" "key-test" "mcp send_message" "BEGIN PGP" "an2"; do printf "%-26s %s\n" "$s" "$(strings -a $P | grep -c -F "$s")"; done
echo "--- noise / multistream strings (control)"; strings -a $P | grep -c "/noise"; strings -a $P | grep -c "/multistream/1.0.0"
echo "--- first payload packets of the first connection"; tcpdump -nn -X -r $P "tcp and src host $MY" 2>/dev/null | grep -m6 -A3 "length [1-9]" | cut -c1-90
