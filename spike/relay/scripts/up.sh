#!/usr/bin/env bash
# Start the topology in the right order: R1 first (clients dial it once at start; if R1 is not listening yet the
# client's peer manager backs off ~2 minutes before retrying - observed in E5/E8). Usage: up.sh [r2]
# Needs: docker compose (v2 plugin) or standalone docker-compose with a running Docker daemon, curl, python3.
# Exits non-zero, with a message on stderr, when a prerequisite is missing, compose fails or a node never answers /health.
set -u; cd "$(dirname "$0")/.." || exit 1

die() { echo "up.sh: error: $*" >&2; exit 1; }

COMPOSE_CMD=()
if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
else
  die "missing required program: install 'docker compose' (v2 plugin) or standalone 'docker-compose' and retry."
fi

missing=""
for tool in curl python3 grep cut sleep; do
  command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
[ -z "$missing" ] || die "missing required program(s):$missing. Install them and retry."

R2=""; [ "${1:-}" = r2 ] && R2=1
FILES=(-f docker-compose.yml); [ -n "$R2" ] && FILES+=(-f docker-compose.r2.yml)
if [ -n "$R2" ]; then
  export R2_PEER_ID=${R2_PEER_ID:-$(grep '^R2_PEER_ID=' .env | cut -d= -f2)}
  export R2_STATIC=/ip4/172.28.66.11/tcp/60000/p2p/$R2_PEER_ID
fi

# compose: stdout is progress noise, stderr (missing images, daemon not running, bad compose file) stays visible.
compose_up() { "${COMPOSE_CMD[@]}" "${FILES[@]}" up -d "$@" >/dev/null || die "${COMPOSE_CMD[*]} up -d $* failed (see the error above)"; }

# wait_health PORT NAME: poll the node's /health for up to 60 s.
wait_health() {
  local port=$1 name=$2 i
  for ((i = 0; i < 60; i++)); do
    curl -s -m 2 "http://127.0.0.1:$port/health" >/dev/null && return 0
    sleep 1
  done
  die "$name (http://127.0.0.1:$port/health) did not answer within 60 s; check '${COMPOSE_CMD[*]} ${FILES[*]} ps' and '${COMPOSE_CMD[*]} ${FILES[*]} logs $name'"
}

compose_up r1
[ -n "$R2" ] && compose_up r2
wait_health 18640 r1
[ -n "$R2" ] && wait_health 18643 r2
sleep 2
compose_up na nb
wait_health 18641 na
wait_health 18642 nb
sleep 3
for p in 18640 18641 18642 ${R2:+18643}; do echo "$p peers: $(curl -s -m 3 http://127.0.0.1:"$p"/admin/v1/peers | python3 -I -c "import json,sys;print([p['connected'] for p in json.load(sys.stdin)])")"; done
