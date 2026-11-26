#!/usr/bin/env bash
# Executes the README "Quickstart" literally against the local relay topology (spike/relay) and prints a transcript.
# Differences from a user's shell, all environmental and listed here so the transcript can be audited:
#  * AGENTNET_BIN_DIR: directory holding the `agentnet` binary built by `cargo build --release -p agentnet-cli`
#    (built with --target-dir in the agent scratchpad because other agents were building in ./target).
#  * HARNESS_DIR / CARGO_TARGET_DIR: the mock harness is run from a `git archive HEAD` export (a clean checkout)
#    with its own target dir, for the same reason.
#  * `wait_until` loops stand in for "repeat the command until it shows the result" in the README.
# Usage: AGENTNET_BIN_DIR=... HARNESS_DIR=... CARGO_TARGET_DIR=... readme-quickstart.sh
set -u
export PATH="${AGENTNET_BIN_DIR:?}:$PATH"
FAILS=0
say() { printf '\n### %s\n' "$*"; }
run() { printf '$ %s\n' "$*"; eval "$@"; local rc=$?; [ $rc -ne 0 ] && { echo "[exit $rc]"; FAILS=$((FAILS+1)); }; return $rc; }
wait_until() { # description timeout_s command...
  local d=$1 t=$2; shift 2; local end=$((SECONDS+t))
  while [ $SECONDS -lt $end ]; do if "$@" >/dev/null 2>&1; then echo "[ok] $d (after $((SECONDS-end+t)) s)"; return 0; fi; sleep 2; done
  echo "[FAIL] timed out after ${t}s: $d"; FAILS=$((FAILS+1)); return 1
}
echo "# README quickstart transcript, started $(date -u +%FT%TZ)"
echo "# host: $(uname -srm); agentnet: $(agentnet --version)"

say "Step 2: local relay topology (idempotent if already up)"
run '(cd spike/relay && DNS_NS=127.0.0.1 ./scripts/up.sh)'

say "Step 3: create two agents (short data dirs: Unix socket path limit)"
export R1=/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV
echo '$ A=$(mktemp -d); B=$(mktemp -d)'
A=$(mktemp -d); B=$(mktemp -d); echo "A=$A"; echo "B=$B"
run "agentnet --data-dir $A init --node-url http://127.0.0.1:18641 --peer $R1 >/dev/null && echo 'A initialised'"
run "agentnet --data-dir $B init --node-url http://127.0.0.1:18642 --peer $R1 >/dev/null && echo 'B initialised'"

say "Step 4: start both daemons"
(agentnet --data-dir $A serve 2>$A.serve.log &) ; (agentnet --data-dir $B serve 2>$B.serve.log &)
echo '$ agentnet --data-dir $A serve &   # and the same for $B'
wait_until "A doctor passes" 60 agentnet --data-dir $A doctor
wait_until "B doctor passes" 60 agentnet --data-dir $B doctor
run "agentnet --data-dir $A doctor"
run "agentnet --data-dir $A network status"

say "Step 5: exchange and verify contact records"
A_ADDR=$(agentnet --data-dir $A identity show --json | jq -r .agent_id)
B_ADDR=$(agentnet --data-dir $B identity show --json | jq -r .agent_id)
run "agentnet --data-dir $A identity show --json | jq -r .contact_record > $A/self-record.json"
run "agentnet --data-dir $B identity show --json | jq -r .contact_record > $B/self-record.json"
run "agentnet --data-dir $A contact add @$B/self-record.json --expect $B_ADDR --alias b"
run "agentnet --data-dir $B contact add @$A/self-record.json --expect $A_ADDR --alias a"
run "agentnet --data-dir $A contact list"

say "Step 6: send, read inbox, check delivery status"
run "agentnet --data-dir $A send $B_ADDR 'hello from A' --json | tee $A/send.json"
MID=$(jq -r .message_id $A/send.json)
inbox_has() { agentnet --data-dir $B inbox --json | jq -e '.records[] | select(.body=="hello from A")'; }
wait_until "B inbox shows the message" 150 inbox_has
run "agentnet --data-dir $B inbox"
delivered() { agentnet --data-dir $A status $MID --json | jq -e '.state=="delivered"'; }
wait_until "A sees authenticated receipt (state delivered)" 150 delivered
run "agentnet --data-dir $A status $MID"
run "agentnet --data-dir $B ack $MID"
run "agentnet --data-dir $B network status"

say "Step 7: MCP stdio client config (sample file) and a real stdio session"
run "cat docs/examples/mcp-client-stdio.json"
# a minimal raw MCP stdio exchange (2026-07-28 server/discover), exactly what a client does first
run "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}' | agentnet --data-dir $A mcp | jq -c '.result.supportedVersions'"
run "printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}' | agentnet mcp --data-dir $A | jq -c '.result.supportedVersions'"

say "Step 8: triggers + mock harness (B enables auto_trigger for one allowlisted session)"
run "pkill -f 'agentnet --data-dir $B serve'; sleep 2"
run "sed -i.bak -e 's/^auto_trigger = false/auto_trigger = true/' -e 's/^allowed_sessions = \[\]/allowed_sessions = [\"demo-session\"]/' $B/agentnet.toml && grep -E '^(auto_trigger|allowed_sessions)' $B/agentnet.toml"
(agentnet --data-dir $B serve 2>$B.serve2.log &)
wait_until "B doctor passes after restart" 60 agentnet --data-dir $B doctor
run "agentnet --data-dir $B trigger create --target-session demo-session --sender $A_ADDR"
(cd "${HARNESS_DIR:?}" && cargo run --locked -q -p agentnet-daemon --example mock_harness -- --data-dir $B --out $B/turns.jsonl --state $B/harness-state.json --max-events 1 --idle-exit-ms 150000 > $B.harness.log 2>&1 &)
echo '$ cargo run -p agentnet-daemon --example mock_harness -- --data-dir $B --out $B/turns.jsonl --state $B/harness-state.json --max-events 1 &'
run "agentnet --data-dir $A send $B_ADDR 'wake up' --json | tee $A/send2.json"
has_turn() { [ -s $B/turns.jsonl ]; }
wait_until "harness recorded a simulated turn" 240 has_turn
run "cat $B/turns.jsonl"
run "wc -l < $B/turns.jsonl"
run "agentnet --data-dir $B trigger list --all"
run "( agentnet --data-dir $B events tail --all --json --ack & p=\$!; sleep 3; kill \$p 2>/dev/null; wait \$p 2>/dev/null; true )"

say "Step 9: stop daemons (SIGTERM), clean up"
run "pkill -TERM -f 'agentnet --data-dir $A serve'; pkill -TERM -f 'agentnet --data-dir $B serve'; sleep 2; pgrep -fl \"agentnet --data-dir ($A|$B) serve\" || echo 'no daemons of this transcript left'"
run "cat $A.serve.log | wc -l"
echo; echo "# serve A log:"; cat $A.serve.log; echo "# serve B log:"; cat $B.serve.log $B.serve2.log
run "rm -rf $A $B $A.* $B.*"
echo; echo "# finished $(date -u +%FT%TZ); failed steps: $FAILS"
exit $FAILS
