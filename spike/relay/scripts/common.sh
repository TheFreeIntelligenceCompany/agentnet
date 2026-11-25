# shared helpers; source me. LOCALHOST/container-network test only.
R1=${R1:-http://127.0.0.1:18640}
NA=${NA:-http://127.0.0.1:18641}
NB=${NB:-http://127.0.0.1:18642}
CT=${CT:-/agentnet/1/spike-a1/proto}
PUBSUB=/waku/2/rs/66/0
OUT=${OUT:-/Users/dennison/develop/FIC-elipsis/results/a1-daemon}
R1_PEER_ID=${R1_PEER_ID:-$(grep "^R1_PEER_ID=" "$(dirname "${BASH_SOURCE[0]}")/../.env" | cut -d= -f2)}
R1_MADDR=/ip4/172.28.66.10/tcp/60000/p2p/$R1_PEER_ID
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
now_ns() { python3 -I -c 'import time;print(time.time_ns())'; }
# req METHOD URL [BODY] -> prints "HTTP <code>\n<body>"
req() { local m=$1 u=$2 b=${3-}; if [ -n "$b" ]; then curl -s -m 20 -X "$m" -H 'content-type: application/json' -d "$b" -w '\nHTTP %{http_code}\n' "$u"; else curl -s -m 20 -X "$m" -w '\nHTTP %{http_code}\n' "$u"; fi; }
# pub NODE CONTENT_TOPIC PAYLOAD_TEXT [extra json fields]
pub() { req POST "$1/relay/v1/auto/messages" "{\"payload\":\"$(b64 "$3")\",\"contentTopic\":\"$2\"${4:+,$4}}"; }
