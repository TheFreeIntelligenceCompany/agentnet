#!/usr/bin/env bash
# Runs inside rust:1.92-bookworm (linux/arm64). The committed tree (git archive HEAD) is streamed in on stdin
# and unpacked to the container-local /work, so the host checkout and its target/ are untouched.
set -u
echo "== start $(date -u +%FT%TZ)"
uname -a; rustc -V; cargo -V; gcc --version | sed -n 1p; command -v cmake >/dev/null && cmake --version | sed -n 1p || echo "cmake: not installed"
mkdir -p /work && tar -xf - -C /work
cd /work && ls && grep -n '^members' Cargo.toml
export CARGO_TARGET_DIR=/work/target CARGO_TERM_COLOR=never
echo "== cargo build --workspace --locked  $(date -u +%FT%TZ)"
time cargo build --workspace --locked; echo "BUILD_EXIT=$?"
echo "== cargo test --workspace --locked  $(date -u +%FT%TZ)"
time cargo test --workspace --locked; echo "TEST_EXIT=$?"
echo "== end $(date -u +%FT%TZ)"
