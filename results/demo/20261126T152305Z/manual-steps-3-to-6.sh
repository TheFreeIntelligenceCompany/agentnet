set -u
export PATH="/Users/dennison/develop/FIC-elipsis/.claude/worktrees/agent-ad50c699d08456f4b/target/release:$PATH"
R1=/ip4/172.28.66.10/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV
A=$(mktemp -d /tmp/an-a.XXXXXX); B=$(mktemp -d /tmp/an-b.XXXXXX)
agentnet --data-dir $A init --node-url http://127.0.0.1:18641 --peer $R1
agentnet --data-dir $B init --node-url http://127.0.0.1:18642 --peer $R1

agentnet --data-dir $A serve 2>$A.log & PID_A=$!
agentnet --data-dir $B serve 2>$B.log & PID_B=$!
until agentnet --data-dir $A --json network status 2>/dev/null | jq -e '.network.ready' >/dev/null; do sleep 2; done
until agentnet --data-dir $B --json network status 2>/dev/null | jq -e '.network.ready' >/dev/null; do sleep 2; done
agentnet --data-dir $A doctor           # expect zero failing checks; the single-instance warning is expected; exit code 7 if any check fails
agentnet --data-dir $A network status

A_ADDR=$(agentnet --data-dir $A identity show --json | jq -r .agent_id)
B_ADDR=$(agentnet --data-dir $B identity show --json | jq -r .agent_id)
agentnet --data-dir $A identity show --json | jq -r .contact_record > $A/self-record.json
agentnet --data-dir $B identity show --json | jq -r .contact_record > $B/self-record.json
agentnet --data-dir $A contact add @$B/self-record.json --expect $B_ADDR --alias b
agentnet --data-dir $B contact add @$A/self-record.json --expect $A_ADDR --alias a
agentnet --data-dir $A contact list

agentnet --data-dir $A send $B_ADDR 'hello from A' --json | tee $A/send.json
MID=$(jq -r .message_id $A/send.json)
until agentnet --data-dir $B --json inbox | jq -e --arg id "$MID" '.records[] | select(.message_id==$id)' >/dev/null; do sleep 2; done
agentnet --data-dir $B inbox
until agentnet --data-dir $A --json status $MID | jq -e '.state=="delivered"' >/dev/null; do sleep 2; done
agentnet --data-dir $A status $MID      # state: delivered, with the authenticated receipt time
agentnet --data-dir $B ack $MID         # local "processed" mark; sends nothing

kill -TERM $PID_A $PID_B; wait $PID_A $PID_B
echo DONE; rm -rf $A $B $A.log $B.log
