#!/usr/bin/env bash
# Runs the reconnect variants (see reconnect-trial.sh) against the running an-wg topology.
#   OUTROOT=<dir> [N=3 OUT=120 MAXWAIT=240] spike/relay-wireguard/reconnect-matrix.sh
# Variants: baseline-redial (old adapter behaviour), baseline-none (client does nothing), b-rst-rule (B host firewall answers stale
# relay segments with a TCP reset), r-retries2 (relay netns net.ipv4.tcp_retries2=6), plus any extra VARIANTS_EXTRA lines.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; T="$HERE/reconnect-trial.sh"; O=${OUTROOT:?}
export N=${N:-4} OUT=${OUT:-120} MAXWAIT=${MAXWAIT:-300} FRESH=${FRESH:-1}
RST='docker exec an-wg-b iptables -A INPUT -i wg0 -s 10.66.0.1/32 -p tcp -j REJECT --reject-with tcp-reset'
RSTD='docker exec an-wg-b iptables -D INPUT -i wg0 -s 10.66.0.1/32 -p tcp -j REJECT --reject-with tcp-reset'
mkdir -p "$O/baseline-redial" "$O/baseline-none" "$O/b-rst-rule" "$O/r-retries2"
OUTDIR=$O/baseline-redial VARIANT=redial "$T" > "$O/A-redial.out" 2>&1
[ "${WITH_NONE:-0}" = 1 ] && OUTDIR=$O/baseline-none VARIANT=none "$T" > "$O/B-none.out" 2>&1
OUTDIR=$O/b-rst-rule VARIANT=redial SETUP="$RST" TEARDOWN="$RSTD" "$T" > "$O/C-redial-b-rst-rule.out" 2>&1
OUTDIR=$O/r-retries2 VARIANT=redial SETUP='docker exec an-wg-r sysctl -w net.ipv4.tcp_retries2=6' TEARDOWN='docker exec an-wg-r sysctl -w net.ipv4.tcp_retries2=15' "$T" > "$O/D-redial-r-retries2.out" 2>&1
echo done > "$O/DRIVER_DONE"
