#!/usr/bin/env bash
# agent-up.sh DIR RESTPORT PEER : init + serve one agent (private mode, peer allowlist = R). OpenPGP tree: identity show --json -> agent_id, contact_record
set -u
D=$1; REST=$2; PEER=$3
AN=~/agentnet
$AN --json --data-dir $D init --node-url http://127.0.0.1:$REST --peer "$PEER" > $D.init.json; echo "init rc=$?"
grep -n -E '^mode|^peers|^node_url' $D/agentnet.toml
setsid nohup $AN --data-dir $D serve > $D.serve.log 2>&1 < /dev/null &
sleep 5
$AN --json --data-dir $D identity show | jq -r .agent_id > $D.addr; $AN --json --data-dir $D identity show | jq -r .contact_record > $D.record
cat $D.addr
