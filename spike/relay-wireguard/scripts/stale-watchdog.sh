#!/bin/sh
# Relay-side watchdog for IDLE stale tcp sockets (results/reconnect-idle/*/SUMMARY.md).
# The Logos Delivery node sets no SO_KEEPALIVE and never pings its INBOUND peers, so when a client vanishes silently and its FIN/RST is
# lost, the relay keeps an ESTABLISHED socket with nothing in flight: tcp_retries2 never applies, and the relay refuses every new
# connection from that peer id until the node itself drops the connection (measured ~8.5-9.5 min here, 7.5-8 min on real hosts).
# A healthy libp2p connection carries traffic every few seconds in both directions (client keepalive ping every 10 s, gossipsub), so an
# established socket that has received nothing for IDLE seconds is dead. This destroys it (`ss -K`: the kernel sends a RST and the node
# sees the close). Needs CAP_NET_ADMIN in the relay's network namespace and a kernel with CONFIG_INET_DIAG_DESTROY (checked on the colima VM).
# usage: stale-watchdog.sh [port=60000] [idle_s=60] [every_s=10]
PORT=${1:-60000}; IDLE=${2:-60}; EVERY=${3:-10}
while :; do
  ss -tino state established "( sport = :$PORT )" 2>/dev/null | awk -v idle="$IDLE" '
    /^[0-9]/ { peer = $4; next }
    { if (match($0, /lastrcv:[0-9]+/)) { v = substr($0, RSTART + 8, RLENGTH - 8) + 0; if (v / 1000 > idle) print peer, v } }' |
  while read -r peer ms; do
    ip=${peer%:*}; p=${peer##*:}
    ss -K state established "( sport = :$PORT and dst $ip and dport = :$p )" >/dev/null 2>&1
    echo "$(date -u +%FT%TZ) stale-watchdog: destroyed idle socket from $peer (no data received for ${ms} ms)"
  done
  sleep "$EVERY"
done
