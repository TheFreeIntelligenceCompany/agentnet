#!/usr/bin/env bash
# Experiment E1: A publishes, B receives (relay), B replies, A receives. Then store query on R1.
set -u; . "$(dirname "$0")/common.sh"
echo "### subscribe NA, NB (content topic $CT)"
for n in $NA $NB; do req POST $n/relay/v1/auto/subscriptions "[\"$CT\"]"; done
sleep 3
echo "### A -> B"
T0=$(now_ns); pub $NA $CT "hello from A $T0"; 
sleep 2
echo "### NB poll"; req GET $NB/relay/v1/auto/messages/$(python3 -I -c "import urllib.parse,sys;print(urllib.parse.quote('$CT',safe=''))")
echo "### NB poll again (expect empty: destructive read)"; req GET $NB/relay/v1/auto/messages/$(python3 -I -c "import urllib.parse;print(urllib.parse.quote('$CT',safe=''))")
echo "### B -> A reply"; pub $NB $CT "reply from B"; sleep 2
echo "### NA poll (own msg A->B may also appear? reply should)"; req GET $NA/relay/v1/auto/messages/$(python3 -I -c "import urllib.parse;print(urllib.parse.quote('$CT',safe=''))")
echo "### Store query on R1 (self store) include data"
req GET "$R1/store/v3/messages?contentTopics=$(python3 -I -c "import urllib.parse;print(urllib.parse.quote('$CT',safe=''))")&includeData=true&pageSize=10"
