#!/usr/bin/env bash
# UNTESTED: written for the second-machine Tailscale run, never executed.
#
# Run on the SECOND tailnet machine (macOS or Linux with docker, the agentnet binary, curl, jq, nc) to become agent B against the
# relay R that host A runs (spike/relay-tailscale/run.sh with KEEP_UP=1 KEEP_RUN=1, or any relay announced on its tailnet address).
# Arguments only; nothing is hard-coded.
#
#   remote-client.sh up    RELAY_MULTIADDR [--data-dir DIR] [--rest-port 8645] [--name an-ts-remote]
#        RELAY_MULTIADDR = /ip4/<relay tailnet ip>/tcp/60000/p2p/<relay peer id>   (host A prints it: see README)
#        starts ONE client node container (static peer = R), waits until it is connected to R, runs `agentnet init` with the peer
#        allowlist = R, starts `agentnet serve` in the background, prints this agent's ADDRESS and writes CONTACT_RECORD to DIR/contact.record
#   remote-client.sh add-contact RECORD_FILE ADDRESS [--data-dir DIR]     import the other agent's contact, verified against its address
#   remote-client.sh send   ADDRESS BODY [--data-dir DIR]                 send and print the message id; then: agentnet status <id>
#   remote-client.sh probe-lan LAN_IP [--port 60000]                      expect NO answer: the relay port must not be reachable via host A's LAN address
#   remote-client.sh probe-relay RELAY_TAILNET_IP [--port 60000]          expect an answer
#   remote-client.sh down   [--data-dir DIR] [--name an-ts-remote]        stop daemon + node, remove container
set -uo pipefail
NODE_IMAGE='wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73'   # v0.39.2 (amd64; qemu on arm64 hosts)
AGENTNET="${AGENTNET:-agentnet}"
cmd="${1:-}"; [ $# -gt 0 ] && shift
DIR="${HOME}/.agentnet-ts-remote"; REST=8645; NAME=an-ts-remote; PORT=60000; POS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --data-dir) DIR="$2"; shift 2;; --rest-port) REST="$2"; shift 2;; --name) NAME="$2"; shift 2;; --port) PORT="$2"; shift 2;;
    *) POS+=("$1"); shift;;
  esac
done
for t in docker curl jq nc "$AGENTNET"; do command -v "$t" >/dev/null || { echo "missing prerequisite: $t" >&2; exit 2; }; done
an() { "$AGENTNET" --data-dir "$DIR" "$@"; }

case "$cmd" in
  up)
    PEER="${POS[0]:?usage: remote-client.sh up /ip4/<relay tailnet ip>/tcp/60000/p2p/<id>}"
    case "$PEER" in /ip4/100.*/tcp/*/p2p/*) ;; *) echo "RELAY_MULTIADDR must be /ip4/<100.x tailnet address>/tcp/<port>/p2p/<id>" >&2; exit 2;; esac
    RIP="$(echo "$PEER" | cut -d/ -f3)"; RPORT="$(echo "$PEER" | cut -d/ -f5)"
    nc -z -w 5 "$RIP" "$RPORT" || { echo "relay $RIP:$RPORT is not reachable over the tailnet from this machine (tailscale up? ACL grants tcp/$RPORT to this machine's tag?)" >&2; exit 1; }
    mkdir -p "$DIR"; chmod 700 "$DIR"
    docker rm -f "$NAME" >/dev/null 2>&1
    docker run -d --name "$NAME" --platform linux/amd64 -p "127.0.0.1:$REST:8645" "$NODE_IMAGE" \
      --nodekey="$(openssl rand -hex 32)" --nat=none --relay=true --store=false --filter=false --lightpush=false \
      --staticnode="$PEER" --storenode="$PEER" --filternode="$PEER" --lightpushnode="$PEER" \
      --rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-admin=true --rest-relay-cache-capacity=1000 --rest-messaging-cache-capacity=1000 \
      --max-msg-size=150KiB --cluster-id=66 --num-shards-in-network=1 --shard=0 \
      --discv5-discovery=false --peer-exchange=false --relay-peer-exchange=false --rendezvous=false --enable-kad-discovery=false \
      --quic-support=false --mix=false --rln-relay=false --listen-address=0.0.0.0 --dns-addrs-name-server=127.0.0.1 --tcp-port=60000 \
      --metrics-server=false --peer-persistence=false --local-storage-path=/data --log-level=INFO >/dev/null || exit 1
    for i in $(seq 1 120); do [ "$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$REST/health")" = 200 ] && break; sleep 1; done
    RID="${PEER##*/p2p/}"
    for i in $(seq 1 240); do
      curl -s -m 5 "http://127.0.0.1:$REST/admin/v1/peers" | jq -e --arg id "$RID" 'any(.[]; (.multiaddr|endswith($id)) and .connected=="Connected")' >/dev/null 2>&1 && { echo "node connected to the relay"; break; }
      sleep 1
    done
    curl -s -m 5 "http://127.0.0.1:$REST/admin/v1/peers" | jq -r '.[]|"\(.multiaddr) \(.connected)"'
    [ -f "$DIR/config.toml" ] || "$AGENTNET" --json --data-dir "$DIR" init --node-url "http://127.0.0.1:$REST" --peer "$PEER" > "$DIR/init.json" || exit 1
    an --json identity show | jq -r .contact_record > "$DIR/contact.record"
    an --json identity show | jq -r .agent_id > "$DIR/address.txt"
    nohup "$AGENTNET" --data-dir "$DIR" serve >/dev/null 2> "$DIR/serve.stderr" & echo $! > "$DIR/serve.pid"
    sleep 3
    an doctor
    echo
    echo "ADDRESS:        $(cat "$DIR/address.txt")"
    echo "CONTACT RECORD: $DIR/contact.record  (copy this file and the address to host A; this is public contact data, not a secret)"
    ;;
  add-contact)
    REC="${POS[0]:?record file}"; ADDR="${POS[1]:?address}"
    an --json contact add "@$REC" --expect "$ADDR" --alias peer ;;
  send)
    an --json send "${POS[0]:?address}" "${POS[1]:?body}" | jq -r .message_id ;;
  probe-lan)
    IP="${POS[0]:?LAN ip of host A}"
    if nc -z -w 5 "$IP" "$PORT"; then echo "FAIL: $IP:$PORT ANSWERS (the relay port is exposed on the LAN address)"; exit 1; else echo "PASS: $IP:$PORT does not answer from this machine"; fi ;;
  probe-relay)
    IP="${POS[0]:?relay tailnet ip}"
    if nc -z -w 5 "$IP" "$PORT"; then echo "PASS: $IP:$PORT answers over the tailnet"; else echo "FAIL: $IP:$PORT does not answer"; exit 1; fi ;;
  down)
    [ -f "$DIR/serve.pid" ] && kill "$(cat "$DIR/serve.pid")" 2>/dev/null; rm -f "$DIR/serve.pid"
    docker rm -f "$NAME" >/dev/null 2>&1; echo "stopped" ;;
  *) sed -n 2,22p "$0"; exit 2;;
esac
