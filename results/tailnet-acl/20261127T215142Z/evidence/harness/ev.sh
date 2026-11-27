#!/bin/bash
# ev.sh FILE BOX 'cmd'  : run cmd on box, append scrubbed header+output to evidence/FILE
SP=<scratch>
D=<repo>/results/tailnet-acl/20261127T215142Z/evidence
F=$1; B=$2; C=$3
{ echo "# $(date -u +%FT%TZ) box$B: $C"; instabox exec agentnet-acl-$B -- "$C" 2>&1 | grep -v "is outdated"; echo "[rc=${PIPESTATUS[0]}]"; echo; } | python3 -I $SP/scrub.py | tee -a $D/$F
