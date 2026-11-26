#!/usr/bin/env bash
# Inside rust:1.92-bookworm (linux/amd64, emulated by qemu on the arm64 VM): build only. The committed tree is streamed on stdin.
set -u
echo "== start $(date -u +%FT%TZ)"
uname -a; rustc -V; cargo -V
mkdir -p /work && tar -xf - -C /work && cd /work
export CARGO_TARGET_DIR=/work/target CARGO_TERM_COLOR=never
echo "== cargo build --workspace --locked  $(date -u +%FT%TZ)"
time cargo build --workspace --locked; echo "BUILD_EXIT=$?"
echo "== end $(date -u +%FT%TZ)"
