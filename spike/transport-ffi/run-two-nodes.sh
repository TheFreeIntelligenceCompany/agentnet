#!/usr/bin/env bash
# Two-node private-network test: containers ffi-a (listener) and ffi-b (dialer) on docker network ffi-net.
# usage: run-two-nodes.sh <image> <bin-dir|-> <result-dir> [peer args...]
#   <bin-dir> "-" uses /opt/ffi inside <image> (the Dockerfile "run" stage image, e.g. ffi-spike:pinned);
#   otherwise <bin-dir> is bind-mounted read-only at /opt/ffi (dev use).
# Discovery is disabled in the spike binary (cluster 7777, no preset, nat none); network is a private docker bridge.
set -euo pipefail
BASE_IMAGE=$1; BIN_DIR=$2; RES=$3; shift 3
EXTRA="$*"
mkdir -p "$RES"; rm -f "$RES"/a.addr "$RES"/*.log "$RES"/*.jsonl
docker network inspect ffi-net >/dev/null 2>&1 || docker network create ffi-net >/dev/null
docker rm -f ffi-a ffi-b >/dev/null 2>&1 || true
run() { # name, extra-args
  local mount=(); [ "$BIN_DIR" != "-" ] && mount=(-v "$BIN_DIR":/opt/ffi:ro)
  docker run -d --name "$1" --network ffi-net --platform linux/arm64 --entrypoint bash \
    ${mount[@]+"${mount[@]}"} -v "$RES":/shared "$BASE_IMAGE" \
    -c "cd /opt/ffi && ./ffi-spike peer --name $2 --port 20001 $3 $EXTRA > /shared/$2.stdout.log 2> /shared/$2.result.jsonl" >/dev/null
}
run ffi-a A "--addr-file /shared/a.addr"
run ffi-b B "--connect-file /shared/a.addr"
for i in $(seq 1 120); do
  [ -z "$(docker ps -q --filter name=ffi-a --filter name=ffi-b)" ] && break
  sleep 5
done
docker inspect -f '{{.Name}} exit={{.State.ExitCode}} started={{.State.StartedAt}} finished={{.State.FinishedAt}}' ffi-a ffi-b > "$RES/containers.txt"
docker rm -f ffi-a ffi-b >/dev/null 2>&1 || true
