#!/usr/bin/env bash
# Run ON the droplet: agent B in the audited public mode via init --public-relay. $1 = relay peer multiaddr
PEER="$1"; AN=/root/an/target/release/agentnet
$AN --version
$AN --data-dir /root/b init --public-relay --node-url http://127.0.0.1:18642 --peer "$PEER" > /root/b-init.txt 2>&1; echo init rc=$?
nohup $AN --data-dir /root/b serve > /root/b.log 2>&1 &
sleep 12
$AN --data-dir /root/b doctor; echo doctor rc=$?
$AN --data-dir /root/b doctor --ready; echo doctor-ready rc=$?
$AN --data-dir /root/b network status
$AN --json --data-dir /root/b network status
$AN --json --data-dir /root/b identity show > /root/b-id.json
