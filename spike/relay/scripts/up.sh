#!/usr/bin/env bash
# Start the topology in the right order: R1 first (clients dial it once at start; if R1 is not listening yet the
# client's peer manager backs off ~2 minutes before retrying - observed in E5/E8). Usage: up.sh [r2]
set -u; cd "$(dirname "$0")/.."
FILES="-f docker-compose.yml"; [ "${1:-}" = r2 ] && FILES="$FILES -f docker-compose.r2.yml"
if [ "${1:-}" = r2 ]; then
  export R2_PEER_ID=${R2_PEER_ID:-$(grep '^R2_PEER_ID=' .env | cut -d= -f2)}
  export R2_STATIC=/ip4/172.28.66.11/tcp/60000/p2p/$R2_PEER_ID
fi
docker-compose $FILES up -d r1 >/dev/null 2>&1
[ "${1:-}" = r2 ] && docker-compose $FILES up -d r2 >/dev/null 2>&1
for i in $(seq 1 60); do curl -s -m 2 http://127.0.0.1:18640/health >/dev/null && break; sleep 1; done
[ "${1:-}" = r2 ] && for i in $(seq 1 60); do curl -s -m 2 http://127.0.0.1:18643/health >/dev/null && break; sleep 1; done
sleep 2
docker-compose $FILES up -d na nb >/dev/null 2>&1
for p in 18641 18642; do for i in $(seq 1 60); do curl -s -m 2 http://127.0.0.1:$p/health >/dev/null && break; sleep 1; done; done
sleep 3
for p in 18640 18641 18642 ${1:+18643}; do echo "$p peers: $(curl -s -m 3 http://127.0.0.1:$p/admin/v1/peers | python3 -I -c "import json,sys;print([p['connected'] for p in json.load(sys.stdin)])")"; done
