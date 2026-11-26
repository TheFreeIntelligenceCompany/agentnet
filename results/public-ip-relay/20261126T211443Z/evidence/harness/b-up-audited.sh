#!/usr/bin/env bash
# Run ON the droplet: agent B in public mode WITH enforce_peer_allowlist = true.
PEER="$1"; AN=/root/an/target/release/agentnet
$AN --version
$AN --data-dir /root/b init --node-url http://127.0.0.1:18642 --peer "$PEER" > /root/b-init.txt 2>&1
sed -i -e 's/^mode = "private"/mode = "public"/' -e 's/^i_understand_public = false/i_understand_public = true\nenforce_peer_allowlist = true/' /root/b/agentnet.toml
nohup $AN --data-dir /root/b serve > /root/b.log 2>&1 &
sleep 12
$AN --data-dir /root/b doctor --ready; echo rc=$?
$AN --data-dir /root/b network status
$AN --json --data-dir /root/b identity show > /root/b-id.json
