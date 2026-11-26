#!/bin/bash
# policy-apply.sh FILE : copy FILE over ~/hs/policy.hujson, validate, and reload headscale (SIGHUP)
set -e
cd ~/hs
./headscale -c config.yaml policy check -f "$1" 2>&1 || true
cp "$1" policy.hujson
echo "applied $(date -u +%FT%T.%3NZ) sha256=$(sha256sum policy.hujson | cut -c1-16)"
pkill -HUP -x headscale
sleep 2
grep -i -E "polic|reload|SIGHUP" hs.log | tail -n 3
