#!/usr/bin/env bash
AN=~/an/target/release/agentnet; : > ~/offA.ids
for i in 1 2 3 4 5; do $AN --json --data-dir ~/b send "$(cat ~/addrA)" "offA $i" | jq -r .message_id >> ~/offA.ids; done
sleep 12; for id in $(cat ~/offA.ids); do $AN --json --data-dir ~/b status $id | jq -c '{state,attempts,last_error}'; done
