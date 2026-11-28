#!/usr/bin/env bash
# Two-agent local demo: agent A sends a message to agent B through the local relay topology
# (spike/relay: one service node and two client nodes in Docker), B replies, and the script
# prints the delivered status and the authenticated receipt.
#
# Single host, loopback and a Docker bridge network. This is NOT a cross-machine test.
#
# What it does:
#   1. checks prerequisites (docker with a reachable daemon, docker-compose, curl, jq, python3, cargo)
#   2. builds target/release/agentnet if it is missing
#   3. starts the relay topology ONLY if it is not already up (reuses a running one),
#      and tears down only what it started itself
#   4. creates two agents in a fresh temp directory, starts two daemons, exchanges signed contacts
#   5. waits (bounded) for readiness and delivery, sends A -> B and a reply B -> A
#   6. on exit (success, failure or Ctrl-C) stops its daemons and removes its temp directory
#
# Usage:   scripts/demo.sh
# Env:     AGENTNET_BIN         use this agentnet binary instead of target/release/agentnet
#          DEMO_READY_TIMEOUT   seconds to wait for each daemon to become ready (default 300)
#          DEMO_DELIVERY_TIMEOUT seconds to wait for each delivery step (default 240)
#          DEMO_KEEP=1          keep the temp directory (and print its path) on exit
# Exit:    0 on success; non-zero with an explanation on any failure.

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELAY_DIR="$ROOT/spike/relay"
BIN="${AGENTNET_BIN:-$ROOT/target/release/agentnet}"
READY_TIMEOUT="${DEMO_READY_TIMEOUT:-300}"
DELIVERY_TIMEOUT="${DEMO_DELIVERY_TIMEOUT:-240}"
# The service node's static address in the local topology (see spike/relay/.env).
R1=/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV
NODE_URL_A=http://127.0.0.1:18641
NODE_URL_B=http://127.0.0.1:18642

WORK=""
PID_A=""
PID_B=""
STARTED_SERVICES=""   # relay compose services this script started (and will stop)
STARTED_ALL=0
RELAY_STEP_REACHED=0   # set once the relay step runs; before that no relay state is known
STAGE="starting"
OK=0

log() { printf '[demo %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

cleanup() {
  local rc=$?
  trap - EXIT INT TERM
  if [ "$OK" -ne 1 ] && [ -n "$WORK" ] && [ -d "$WORK" ]; then
    for f in "$WORK"/a.serve.log "$WORK"/b.serve.log; do
      if [ -s "$f" ]; then
        echo "---- $(basename "$f") (stderr of the daemon) ----" >&2
        cat "$f" >&2
      fi
    done
  fi
  for pid in "$PID_A" "$PID_B"; do
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
  done
  for pid in "$PID_A" "$PID_B"; do
    [ -z "$pid" ] && continue
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
  done
  if [ -n "$STARTED_SERVICES" ]; then
    log "stopping the relay containers this script started:$STARTED_SERVICES"
    if [ "$STARTED_ALL" -eq 1 ]; then
      (cd "$RELAY_DIR" && docker-compose -f docker-compose.yml down >/dev/null 2>&1)
    else
      # shellcheck disable=SC2086
      (cd "$RELAY_DIR" && docker-compose -f docker-compose.yml stop $STARTED_SERVICES >/dev/null 2>&1 \
        && docker-compose -f docker-compose.yml rm -f $STARTED_SERVICES >/dev/null 2>&1)
    fi
  elif [ "$RELAY_STEP_REACHED" -eq 1 ]; then
    log "relay containers were already running before this script: left untouched"
  fi
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    if [ "${DEMO_KEEP:-0}" = 1 ]; then
      log "kept $WORK (contains secret keys of the disposable demo agents)"
    else
      rm -rf "$WORK"
    fi
  fi
  if [ "$OK" -eq 1 ]; then
    log "done"
    exit 0
  fi
  [ "$rc" -eq 0 ] && rc=1
  exit "$rc"
}
trap cleanup EXIT
trap 'echo "interrupted" >&2; exit 130' INT TERM

die() {
  echo >&2
  echo "DEMO FAILED during: $STAGE" >&2
  echo "  $*" >&2
  exit 1
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing prerequisite '$1': $2"; }

# wait_for DESCRIPTION TIMEOUT_SECONDS COMMAND...  (polls every 2 s, bounded)
wait_for() {
  local desc=$1 limit=$2
  shift 2
  local start=$SECONDS
  while [ $((SECONDS - start)) -lt "$limit" ]; do
    if "$@" >/dev/null 2>&1; then
      log "ok: $desc (after $((SECONDS - start)) s)"
      return 0
    fi
    # fail early if a daemon died
    for pid in "$PID_A" "$PID_B"; do
      if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
        die "a daemon process exited while waiting for: $desc (see its log above; common causes: an unreadable config, another daemon using the data directory)"
      fi
    done
    sleep 2
  done
  return 1
}

ag() { local dir=$1; shift; "$BIN" --data-dir "$dir" "$@"; }

ready() { ag "$1" --json network status 2>/dev/null | jq -e '.network.ready == true' >/dev/null; }
health() { [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$1/health")" = 200 ]; }
inbox_has() { ag "$1" --json inbox 2>/dev/null | jq -e --arg id "$2" '.records[] | select(.message_id == $id)' >/dev/null; }
is_delivered() { ag "$1" --json status "$2" 2>/dev/null | jq -e '.state == "delivered"' >/dev/null; }

# ---------------------------------------------------------------- 1. prerequisites
STAGE="prerequisite checks"
log "checking prerequisites"
need docker "install Docker (or colima) and make sure 'docker' is on PATH"
need docker-compose "install the standalone docker-compose binary (the relay helper uses 'docker-compose', not 'docker compose')"
need curl "install curl"
need jq "install jq (for example 'brew install jq' or 'apt install jq')"
need python3 "install Python 3 (the relay start helper uses it to print peer lists)"
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable: start Docker Desktop or 'colima start' and retry"
[ -f "$RELAY_DIR/scripts/up.sh" ] || die "cannot find $RELAY_DIR/scripts/up.sh: run this script from a checkout of the repository"
case "$(uname -s)" in Darwin | Linux) ;; *) die "unsupported OS $(uname -s): macOS and Linux only" ;; esac

# ---------------------------------------------------------------- 2. binary
STAGE="building the agentnet binary"
if [ ! -x "$BIN" ]; then
  need cargo "install Rust 1.89 or newer (https://rustup.rs) and a C compiler"
  log "building the release binary (first build takes several minutes): cargo build --release --locked -p agentnet-cli"
  (cd "$ROOT" && cargo build --release --locked -p agentnet-cli) || die "cargo build failed: see the compiler output above"
  [ -x "$BIN" ] || die "the build finished but $BIN does not exist"
fi
log "using $("$BIN" --version) at $BIN"

# ---------------------------------------------------------------- 3. relay topology
STAGE="starting the local relay topology"
RELAY_STEP_REACHED=1
running_services=""
for s in r1:an-r1 na:an-na nb:an-nb; do
  if [ "$(docker inspect -f '{{.State.Running}}' "${s#*:}" 2>/dev/null)" = true ]; then
    running_services="$running_services ${s%%:*}"
  fi
done
if [ -n "$running_services" ] && health http://127.0.0.1:18640 && health "$NODE_URL_A" && health "$NODE_URL_B"; then
  log "relay topology is already up (reusing it; it will not be touched):$running_services"
else
  log "starting the relay topology (spike/relay/scripts/up.sh; first start pulls the node image and can take minutes)"
  if [ -z "$running_services" ]; then
    STARTED_ALL=1
  fi
  for s in r1 na nb; do
    case " $running_services " in *" $s "*) ;; *) STARTED_SERVICES="$STARTED_SERVICES $s" ;; esac
  done
  (cd "$RELAY_DIR" && DNS_NS=127.0.0.1 ./scripts/up.sh) || die "spike/relay/scripts/up.sh failed (is the docker-compose binary working?)"
  for url in http://127.0.0.1:18640 "$NODE_URL_A" "$NODE_URL_B"; do
    wait_for "node health $url" 180 health "$url" ||
      die "node at $url did not answer /health within 180 s: check 'docker ps' and 'docker logs an-r1' ('an-na', 'an-nb'); the image is linux/amd64 and is slow under emulation"
  done
fi

# ---------------------------------------------------------------- 4. agents and daemons
STAGE="creating two agents"
# Short path: the control socket path must fit a Unix socket (about 100 bytes).
WORK="$(mktemp -d /tmp/an-demo.XXXXXX)" || die "cannot create a temp directory under /tmp"
A="$WORK/a"
B="$WORK/b"
log "temp directory: $WORK"
ag "$A" init --node-url "$NODE_URL_A" --peer "$R1" >/dev/null || die "agentnet init failed for agent A"
ag "$B" init --node-url "$NODE_URL_B" --peer "$R1" >/dev/null || die "agentnet init failed for agent B"
A_ADDR=$(ag "$A" identity show --json | jq -r .agent_id)
B_ADDR=$(ag "$B" identity show --json | jq -r .agent_id)
[ -n "$A_ADDR" ] && [ "$A_ADDR" != null ] && [ -n "$B_ADDR" ] && [ "$B_ADDR" != null ] || die "could not read the agent addresses"
log "agent A = $A_ADDR"
log "agent B = $B_ADDR"

STAGE="starting the daemons"
RUST_LOG=info "$BIN" --data-dir "$A" serve >/dev/null 2>"$WORK/a.serve.log" &
PID_A=$!
RUST_LOG=info "$BIN" --data-dir "$B" serve >/dev/null 2>"$WORK/b.serve.log" &
PID_B=$!
disown "$PID_A" "$PID_B" 2>/dev/null # no job-control "Terminated" noise at cleanup
log "daemons started: A pid $PID_A, B pid $PID_B"

STAGE="waiting for both daemons to become ready (node reachable, relay peer connected)"
wait_for "daemon A ready" "$READY_TIMEOUT" ready "$A" ||
  die "daemon A was not ready after ${READY_TIMEOUT} s. Run 'agentnet --data-dir <dir> network status' (use DEMO_KEEP=1 to keep the directory). A node that was just (re)created can take about a minute to reach the relay."
wait_for "daemon B ready" "$READY_TIMEOUT" ready "$B" ||
  die "daemon B was not ready after ${READY_TIMEOUT} s (same checks as for A)"

# ---------------------------------------------------------------- 5. contacts
STAGE="exchanging signed contact records"
# In real use the address must reach you over a channel you trust; --expect makes 'contact add'
# fail unless the signed record belongs to exactly that address.
ag "$A" identity show --json | jq -r .contact_record >"$WORK/a-record.json"
ag "$B" identity show --json | jq -r .contact_record >"$WORK/b-record.json"
ag "$A" contact add "@$WORK/b-record.json" --expect "$B_ADDR" --alias b >/dev/null || die "A could not add B's contact record"
ag "$B" contact add "@$WORK/a-record.json" --expect "$A_ADDR" --alias a >/dev/null || die "B could not add A's contact record"
log "contacts exchanged and verified"

# ---------------------------------------------------------------- 6. A -> B
STAGE="sending A -> B"
T0=$SECONDS
MID1=$(ag "$A" send "$B_ADDR" 'hello from A' --json | jq -r .message_id) || die "send failed"
[ -n "$MID1" ] && [ "$MID1" != null ] || die "send returned no message id"
log "A sent $MID1 (queued/sent is not receipt)"
STAGE="waiting for B to receive the message"
wait_for "message visible in B's inbox" "$DELIVERY_TIMEOUT" inbox_has "$B" "$MID1" ||
  die "B's inbox did not show $MID1 within ${DELIVERY_TIMEOUT} s. Live delivery sometimes needs the next history sync (15 s) and can take minutes after a node restart; rerun, or inspect 'agentnet --data-dir <dir> status $MID1' with DEMO_KEEP=1."
STAGE="waiting for A's delivery receipt"
wait_for "A has the authenticated receipt (state delivered)" "$DELIVERY_TIMEOUT" is_delivered "$A" "$MID1" ||
  die "A did not see state=delivered for $MID1 within ${DELIVERY_TIMEOUT} s (the message reached B, but B's acknowledgement has not come back yet)"
log "A -> B delivered in $((SECONDS - T0)) s"

# ---------------------------------------------------------------- 7. reply B -> A
STAGE="sending the reply B -> A"
T1=$SECONDS
MID2=$(ag "$B" send "$A_ADDR" 'reply from B' --json | jq -r .message_id) || die "reply send failed"
[ -n "$MID2" ] && [ "$MID2" != null ] || die "reply send returned no message id"
log "B sent $MID2"
STAGE="waiting for A to receive the reply"
wait_for "reply visible in A's inbox" "$DELIVERY_TIMEOUT" inbox_has "$A" "$MID2" ||
  die "A's inbox did not show the reply $MID2 within ${DELIVERY_TIMEOUT} s"
STAGE="waiting for B's delivery receipt"
wait_for "B has the authenticated receipt (state delivered)" "$DELIVERY_TIMEOUT" is_delivered "$B" "$MID2" ||
  die "B did not see state=delivered for $MID2 within ${DELIVERY_TIMEOUT} s"
log "B -> A delivered in $((SECONDS - T1)) s"

# ---------------------------------------------------------------- 8. show the result
STAGE="printing the result"
echo
echo "=== A's inbox (the reply) ==="
ag "$A" inbox
echo
echo "=== B's inbox (the first message) ==="
ag "$B" inbox
echo
echo "=== status of A -> B ($MID1) ==="
ag "$A" status "$MID1"
echo
echo "=== status of B -> A ($MID2) ==="
ag "$B" status "$MID2"
echo
echo "=== receipt for A -> B (JSON) ==="
ag "$A" --json status "$MID1" | jq .
echo
OK=1
log "success: two agents exchanged a message and a reply over the local relay (single host, not a cross-machine test); total ${SECONDS} s"
