#!/bin/sh
# NAT gateway of one simulated LAN (a "home router"): MASQUERADE on the public side, stateful forwarding.
# SIMULATION: iptables source NAT in a container. Endpoint-independent mapping behaviour of real CGNAT / home routers is NOT modelled
# (Linux MASQUERADE keeps the source port when free and has symmetric-ish, address-dependent filtering through conntrack).
set -eu
PUB_IF=$(ip -o -4 addr show | awk '/ 172\.30\.80\./ {print $2}' | head -n 1)
LAN_IF=$(ip -o -4 addr show | awk '/ 192\.168\.10[12]\./ {print $2}' | head -n 1)
LAN_NET=$1
ip route replace default via 172.30.80.1 dev "$PUB_IF"
iptables -t nat -A POSTROUTING -o "$PUB_IF" -s "$LAN_NET" -j MASQUERADE
iptables -P FORWARD DROP
# a LAN host may open outbound TCP only with a SYN: a mid-stream packet without a conntrack entry (mapping lost) is dropped silently
iptables -A FORWARD -i "$LAN_IF" -o "$PUB_IF" -p tcp ! --syn -m conntrack --ctstate NEW -m comment --comment natsim-no-midstream -j DROP
iptables -A FORWARD -i "$LAN_IF" -o "$PUB_IF" -j ACCEPT
iptables -A FORWARD -i "$PUB_IF" -o "$LAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# the gateway itself: reachable from the LAN, nothing new from the public side
iptables -P INPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i "$LAN_IF" -j ACCEPT
touch /tmp/ready
echo "gateway up: pub=$PUB_IF lan=$LAN_IF lan_net=$LAN_NET est-timeout=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established)"
exec sleep infinity
