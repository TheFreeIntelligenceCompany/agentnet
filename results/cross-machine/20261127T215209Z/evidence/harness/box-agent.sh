#!/usr/bin/env bash
# Run ON the box: agent B in private mode against R over the docker bridge (172.28.66.10); node B REST 127.0.0.1:18642.
# usage: box-agent.sh   (R's peer id is public: derived from the disposable key in spike/relay/.env)
set -euo pipefail
BIN=~/an/target/release/agentnet; B=~/agent-b; P=16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV
rm -rf $B
$BIN --data-dir $B --json init --node-url http://127.0.0.1:18642 --peer /ip4/172.28.66.10/tcp/60000/p2p/$P > ~/agent-b.init.json
nohup $BIN --data-dir $B serve > ~/agent-b.serve.log 2>&1 &
echo $! > ~/agent-b.pid
