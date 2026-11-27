#!/bin/sh
# Relay-side watchdog for IDLE stale tcp sockets (results/reconnect-idle/*/SUMMARY.md).
# The Logos Delivery node sets no SO_KEEPALIVE and never pings its INBOUND peers, so when a client vanishes silently and its FIN/RST is
# lost, the relay keeps an ESTABLISHED socket with nothing in flight: tcp_retries2 never applies, and the relay refuses every new
# connection from that peer id until the node itself drops the connection (measured ~8.5-9.5 min here, 7.5-8 min on real hosts).
# A healthy libp2p connection carries traffic every few seconds in both directions (client keepalive ping every 10 s, gossipsub), so an
# established socket that has received nothing for IDLE seconds is dead. This destroys it (`ss -K`: the kernel sends a RST and the node
# sees the close). Needs CAP_NET_ADMIN in the relay's network namespace and a kernel with CONFIG_INET_DIAG_DESTROY (checked on the colima VM).
#
# It never claims a destroy it did not verify: a socket is reported destroyed only after `ss -K` exited 0 AND a re-check shows the socket
# gone. A failing `ss -K` (permission denied, kernel without INET_DIAG_DESTROY) is logged with ss's own diagnostic. At startup `ss -K` is
# probed (exit status, stderr, and the NET_ADMIN bit of CapEff); if it is unusable the script exits 2 so a sidecar visibly fails. The probe
# cannot prove kernel support (a filter that matches nothing destroys nothing), so after STRIKES consecutive passes whose destroys all
# failed the script exits 1 as well.
#
# usage: stale-watchdog.sh [port=60000] [idle_s=60] [every_s=10]
# env (for tests): SS=ss  WATCHDOG_ONCE=1 (one pass, then exit)  RECHECK_DELAY_S=1  STRIKES=3  CAPEFF_FILE=/proc/self/status
PORT=${1:-60000}; IDLE=${2:-60}; EVERY=${3:-10}
SS=${SS:-ss}; RECHECK_DELAY_S=${RECHECK_DELAY_S:-1}; STRIKES=${STRIKES:-3}; CAPEFF_FILE=${CAPEFF_FILE:-/proc/self/status}
ts() { date -u +%FT%TZ; }
# PATCH (tailscale run 20261127T215730Z): iproute2-6.15 / kernel 6.18 print "RTNETLINK answers: Invalid argument" on stderr with exit 0 even when ss -K works; treat that exact line as benign. Success is still verified by the socket re-check.
benign() { [ -z "$1" ] || [ "$1" = "RTNETLINK answers: Invalid argument" ]; }

# True when the NET_ADMIN bit (12) is absent from CapEff; unknown (no file) counts as present.
lacks_net_admin() {
  hex=$(sed -n 's/^CapEff:[[:space:]]*//p' "$CAPEFF_FILE" 2>/dev/null)
  [ -n "$hex" ] || return 1
  [ $(( 0x$hex >> 12 & 1 )) -eq 0 ]
}

probe() {
  if lacks_net_admin; then
    echo "$(ts) stale-watchdog: FATAL: CAP_NET_ADMIN is not in the effective capability set; ss -K cannot destroy sockets (add cap_add: [NET_ADMIN] or run as root in the relay's network namespace)" >&2
    return 1
  fi
  # A filter that matches no socket: only exit status and stderr of the option itself are exercised.
  out=$("$SS" -K state established "( sport = :$PORT and dport = :0 )" 2>&1 >/dev/null); rc=$?
  if [ "$rc" -ne 0 ] || ! benign "$out"; then
    echo "$(ts) stale-watchdog: FATAL: 'ss -K' is not usable here (exit $rc): ${out:-no diagnostic}" >&2
    return 1
  fi
  return 0
}

# The established sockets on PORT that received nothing for more than IDLE seconds: "peer lastrcv_ms" lines.
idle_peers() {
  "$SS" -tino state established "( sport = :$PORT )" 2>/dev/null | awk -v idle="$IDLE" '
    /^[0-9]/ { peer = $4; next }
    { if (match($0, /lastrcv:[0-9]+/)) { v = substr($0, RSTART + 8, RLENGTH - 8) + 0; if (v / 1000 > idle) print peer, v } }'
}

socket_present() { # $1 ip, $2 port
  [ -n "$("$SS" -tn state established "( sport = :$PORT and dst $1 and dport = :$2 )" 2>/dev/null | awk '/^[0-9]/')" ]
}

# Destroys one socket; returns 0 only when ss -K succeeded and the socket is gone.
destroy() { # $1 peer, $2 lastrcv_ms
  ip=${1%:*}; p=${1##*:}
  err=$("$SS" -K state established "( sport = :$PORT and dst $ip and dport = :$p )" 2>&1 >/dev/null); rc=$?
  if [ "$rc" -ne 0 ] || ! benign "$err"; then
    echo "$(ts) stale-watchdog: FAILED to destroy idle socket from $1 (ss -K exit $rc): ${err:-no diagnostic}" >&2
    return 1
  fi
  sleep "$RECHECK_DELAY_S"
  if socket_present "$ip" "$p"; then
    echo "$(ts) stale-watchdog: FAILED: ss -K exited 0 but the socket from $1 is still established (kernel without INET_DIAG_DESTROY?)" >&2
    return 1
  fi
  echo "$(ts) stale-watchdog: destroyed idle socket from $1 (no data received for ${2} ms)"
}

probe || exit 2
strikes=0
while :; do
  found=0; failed=0
  list=$(idle_peers)
  while read -r peer ms; do
    [ -n "$peer" ] || continue
    found=$((found + 1))
    destroy "$peer" "$ms" || failed=$((failed + 1))
  done <<EOF
$list
EOF
  if [ "$found" -gt 0 ] && [ "$failed" -eq "$found" ]; then strikes=$((strikes + 1)); else strikes=0; fi
  if [ "$strikes" -ge "$STRIKES" ]; then
    echo "$(ts) stale-watchdog: FATAL: every destroy failed in $strikes consecutive passes; exiting" >&2
    exit 1
  fi
  if [ -n "$WATCHDOG_ONCE" ]; then [ "$failed" -eq 0 ]; exit; fi
  sleep "$EVERY"
done
