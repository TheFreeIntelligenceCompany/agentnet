#!/usr/bin/env bash
# Reproduces every A3 result. Raw outputs land in ../../results/a3-mcp/.
set -u
cd "$(dirname "$0")"
OUT=../../results/a3-mcp
mkdir -p "$OUT"
{ rustc --version; cargo --version; uname -srm; date -u +%FT%TZ; cargo tree -i rmcp; } > "$OUT/env.txt" 2>&1
cargo fmt --check > "$OUT/fmt-check.txt" 2>&1; echo "cargo fmt --check rc=$?"
cargo clippy --all-targets --locked -- -D warnings > "$OUT/clippy.txt" 2>&1; echo "clippy rc=$?"
cargo test --locked -- --nocapture --test-threads=1 > "$OUT/cargo-test.log" 2>&1; echo "cargo test rc=$?"

# Smoke test of the real HTTP binary (loopback, bearer token).
cargo build --locked --bin mcp-spike-server > /dev/null 2>&1
export SPIKE_TOKEN=smoke-token-0123456789abcdef
BIN=target/debug/mcp-spike-server
$BIN --transport http --bind 127.0.0.1:0 > "$OUT/http-binary.stdout" 2> "$OUT/http-binary.stderr" &
PID=$!
for _ in $(seq 1 50); do grep -q LISTENING "$OUT/http-binary.stdout" && break; sleep 0.1; done
ADDR=$(sed -n 's/^LISTENING //p' "$OUT/http-binary.stdout")
BODY='{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
{
  echo "# server bound: $ADDR"
  echo "# no token:";    curl -s -i -X POST "http://$ADDR/mcp" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: server/discover' -d "$BODY"; echo
  echo "# good token:";  curl -s -i -X POST "http://$ADDR/mcp" -H "Authorization: Bearer $SPIKE_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: server/discover' -d "$BODY"; echo
} > "$OUT/http-binary-smoke.txt" 2>&1
kill $PID 2>/dev/null; wait $PID 2>/dev/null
# Refuse non-loopback bind / short token:
{ $BIN --transport http --bind 0.0.0.0:0; echo "rc=$?"; SPIKE_TOKEN=short $BIN --transport http; echo "rc=$?"; } > "$OUT/http-binary-refusals.txt" 2>&1
echo done
