#!/bin/sh
# Entry point of a WireGuard "machine" sidecar: kernel WireGuard interface wg0 + the machine's firewall. Role: r | a | b.
# SIMULATION: this is WireGuard between containers on one host; it is not Tailscale.
set -eu
ROLE=$1
GW=172.29.70.1                       # docker bridge gateway = the docker host (REST publishing arrives from here)
case $ROLE in r) OV=10.66.0.1;; a) OV=10.66.0.2;; b) OV=10.66.0.3;; esac

ip link add wg0 type wireguard       # kernel module; if this fails the run aborts (no userspace fallback implemented)
wg setconf wg0 "/cfg/wg-$ROLE.conf"
if [ "$ROLE" = r ]; then
  ip addr add 10.66.0.1/24 dev wg0
else
  ip addr add "$OV/32" dev wg0
fi
ip link set wg0 mtu 1380 up
[ "$ROLE" = r ] || ip route add 10.66.0.1/32 dev wg0 src "$OV"

# ---- firewall (iptables, nft backend). Default DROP on INPUT and FORWARD; OUTPUT left open on purpose so that any attempted
# egress shows up in the packet capture instead of being silently blocked.
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
# libp2p tcp/60000 arriving on the underlay is dropped BEFORE the established-accept rule so it also cuts established flows
iptables -A INPUT -i eth0 -p tcp --dport 60000 -m comment --comment "wgsim-underlay-libp2p-drop" -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i eth0 -p udp --dport 51820 -m comment --comment "wgsim-wireguard-udp" -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 8645 -s "$GW" -m comment --comment "wgsim-rest-from-docker-host-only" -j ACCEPT
if [ "$ROLE" = r ]; then
  iptables -A INPUT -i wg0 -p tcp --dport 60000 -s 10.66.0.2 -m comment --comment "wgsim-libp2p-from-A" -j ACCEPT
  iptables -A INPUT -i wg0 -p tcp --dport 60000 -s 10.66.0.3 -m comment --comment "wgsim-libp2p-from-B" -j ACCEPT
else
  iptables -A INPUT -i wg0 -p tcp --dport 60000 -s 10.66.0.1 -m comment --comment "wgsim-libp2p-from-R" -j ACCEPT
fi
iptables -A INPUT -i wg0 -p icmp -j ACCEPT
touch /tmp/ready
echo "machine $ROLE up: overlay $OV, kernel WireGuard"
exec sleep infinity
