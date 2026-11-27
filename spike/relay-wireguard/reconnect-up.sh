#!/usr/bin/env bash
# (Re)create the an-wg topology from scratch for the reconnect experiments (keys in .run/ are reused; generate with scripts/gen-keys.sh).
# R, A and B are all brought up fresh, then waits until A and B list R as Connected.
set -uo pipefail
cd "$(dirname "$0")"
export R_TCP_RETRIES2=${R_TCP_RETRIES2:-15}   # experiments start from the kernel default; the r-retries2 variant lowers it afterwards
C="docker-compose --env-file .run/env"
$C --profile intruder down -v >/dev/null 2>&1
colima ssh -- sudo modprobe wireguard >/dev/null 2>&1
$C up -d wg-r wg-a wg-b node-r >/dev/null 2>&1
for i in $(seq 1 60); do curl -sf -m 3 http://127.0.0.1:28650/health >/dev/null && break; sleep 3; done
RID=$(curl -s http://127.0.0.1:28650/info | jq -r '.listenAddresses[0]|split("/p2p/")[1]')
[ "$RID" = "$(grep '^R_PEER_ID=' .run/env | cut -d= -f2)" ] || { sed -i.bak "s/^R_PEER_ID=.*/R_PEER_ID=$RID/" .run/env; rm -f .run/env.bak; }
$C up -d node-a node-b >/dev/null 2>&1
for p in 28651 28652; do
  for i in $(seq 1 60); do curl -s -m 3 "http://127.0.0.1:$p/admin/v1/peers" | grep -q '"Connected"' && break; sleep 3; done
done
sleep 10
echo "up: A $(curl -s http://127.0.0.1:28651/admin/v1/peers | jq -c '[.[].connected]') B $(curl -s http://127.0.0.1:28652/admin/v1/peers | jq -c '[.[].connected]')"
