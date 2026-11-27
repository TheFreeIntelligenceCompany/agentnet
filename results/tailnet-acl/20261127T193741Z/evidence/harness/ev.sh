#!/bin/bash
# ev.sh FILE BOX 'cmd'  : run cmd on box, append scrubbed header+output to evidence/FILE
SP=/private/tmp/claude-501/-Users-<user>-develop-FIC-elipsis/c4ddce9a-8e98-4449-9cd9-e1fc59613e1d/scratchpad
D=/Users/<user>/develop/FIC-elipsis/results/tailnet-acl/20261127T193741Z/evidence
F=$1; B=$2; C=$3
{ echo "# $(date -u +%FT%TZ) box$B: $C"; instabox exec agentnet-acl-$B -- "$C" 2>&1 | grep -v "is outdated"; echo "[rc=${PIPESTATUS[0]}]"; echo; } | python3 -I $SP/scrub.py | tee -a $D/$F
