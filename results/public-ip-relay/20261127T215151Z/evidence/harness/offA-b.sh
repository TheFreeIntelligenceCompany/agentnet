#!/usr/bin/env bash
# Run ON the droplet: 5 messages from B to A (A's node is down), then poll for receipts. $1 = A address, $2 = T0 file (epoch of A-node start, written by the Mac side via ssh)
AN=/root/an/target/release/agentnet; : > /root/offA.ids
for i in 1 2 3 4 5; do $AN --json --data-dir /root/b send "$1" "synthetic offA $i" | jq -r .message_id >> /root/offA.ids; done
date -u +%T.%3NZ; echo "5 sent from B while A offline"
