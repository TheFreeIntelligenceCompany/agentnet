#!/bin/sh
# Tests for stale-watchdog.sh with a stubbed `ss` on PATH (no docker, no root, no real sockets).
# Run:  sh spike/relay-wireguard/scripts/test-stale-watchdog.sh        (exit 0 = all passed)
# Not wired into CI or any other script. Cases: probe fails (permission denied), kill succeeds and
# the socket is gone, kill "succeeds" but the socket is still present, destroy fails after a good probe.
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1 (expected '$3', got '$2')"; fail=1; fi; }
has() { case "$2" in *"$3"*) echo "ok   $1";; *) echo "FAIL $1 (missing '$3' in: $2)"; fail=1;; esac; }
hasnt() { case "$2" in *"$3"*) echo "FAIL $1 (unexpected '$3' in: $2)"; fail=1;; *) echo "ok   $1";; esac; }

mkdir "$tmp/bin"
cat >"$tmp/bin/ss" <<'EOF'
#!/bin/sh
# Stub. STUB_MODE: denied | gone | present | probe_ok_kill_denied. STUB_DIR holds the "killed" flag.
args="$*"
case "$args" in
  *-K*dport\ =\ :0*)  # startup probe: matches nothing
    [ "$STUB_MODE" = denied ] && { echo "RTNETLINK answers: Operation not permitted" >&2; exit 1; }
    exit 0;;
  *-K*)
    case "$STUB_MODE" in
      denied|probe_ok_kill_denied) echo "RTNETLINK answers: Operation not permitted" >&2; exit 1;;
    esac
    touch "$STUB_DIR/killed"; exit 0;;
  *-tino*)
    printf 'Recv-Q Send-Q Local:Port Peer:Port\n'
    printf '0 0 10.0.0.1:60000 10.0.0.9:51234\n\t cubic lastrcv:90000 lastack:90000\n'
    exit 0;;
  *-tn*)
    if [ "$STUB_MODE" = gone ] && [ -f "$STUB_DIR/killed" ]; then printf 'Recv-Q Send-Q Local:Port Peer:Port\n'
    else printf 'Recv-Q Send-Q Local:Port Peer:Port\n0 0 10.0.0.1:60000 10.0.0.9:51234\n'; fi
    exit 0;;
esac
EOF
chmod +x "$tmp/bin/ss"

# $1 mode; sets OUT (stdout+stderr) and RC
run() {
  rm -f "$tmp/killed"
  OUT=$(PATH="$tmp/bin:$PATH" STUB_MODE=$1 STUB_DIR=$tmp WATCHDOG_ONCE=1 RECHECK_DELAY_S=0 \
        CAPEFF_FILE=/nonexistent sh "$here/stale-watchdog.sh" 60000 60 1 2>&1); RC=$?
}

run denied
check "denied: exits 2 at startup" "$RC" 2
has   "denied: clear message" "$OUT" "'ss -K' is not usable here"
has   "denied: shows ss diagnostic" "$OUT" "Operation not permitted"
hasnt "denied: never claims success" "$OUT" "destroyed idle socket"

run gone
check "gone: exits 0" "$RC" 0
has   "gone: logs destroyed" "$OUT" "destroyed idle socket from 10.0.0.9:51234"

run present
check "present: exits 1" "$RC" 1
has   "present: logs the failure" "$OUT" "still established"
hasnt "present: never claims success" "$OUT" "destroyed idle socket"

run probe_ok_kill_denied
check "kill denied after good probe: exits 1" "$RC" 1
has   "kill denied: logs diagnostic" "$OUT" "FAILED to destroy idle socket from 10.0.0.9:51234"
hasnt "kill denied: never claims success" "$OUT" "destroyed idle socket"

# CapEff without NET_ADMIN (bit 12) is refused at startup; with it the probe passes.
printf 'CapEff:\t0000000000000000\n' >"$tmp/nocap"; printf 'CapEff:\t0000000000001000\n' >"$tmp/cap"
OUT=$(PATH="$tmp/bin:$PATH" STUB_MODE=gone STUB_DIR=$tmp WATCHDOG_ONCE=1 RECHECK_DELAY_S=0 CAPEFF_FILE="$tmp/nocap" sh "$here/stale-watchdog.sh" 2>&1); RC=$?
check "no NET_ADMIN: exits 2" "$RC" 2
has   "no NET_ADMIN: message" "$OUT" "CAP_NET_ADMIN"
rm -f "$tmp/killed"
OUT=$(PATH="$tmp/bin:$PATH" STUB_MODE=gone STUB_DIR=$tmp WATCHDOG_ONCE=1 RECHECK_DELAY_S=0 CAPEFF_FILE="$tmp/cap" sh "$here/stale-watchdog.sh" 2>&1); RC=$?
check "with NET_ADMIN: exits 0" "$RC" 0

exit "$fail"
