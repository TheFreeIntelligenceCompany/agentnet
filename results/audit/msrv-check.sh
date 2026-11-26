#!/usr/bin/env bash
# Inside rust:1.88-bookworm: does the locked workspace build with the declared MSRV (rust-version = "1.88")?
set -u
echo "== start $(date -u +%FT%TZ)"; rustc -V; cargo -V
mkdir -p /work && tar -xf - -C /work && cd /work
export CARGO_TARGET_DIR=/work/target CARGO_TERM_COLOR=never
cargo check --workspace --locked 2>&1 | grep -v -E '^\s+(Downloaded|Downloading|Compiling|Checking)' ; echo "CHECK_EXIT=${PIPESTATUS[0]}"
echo "== end $(date -u +%FT%TZ)"
