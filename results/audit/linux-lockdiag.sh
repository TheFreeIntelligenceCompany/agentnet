#!/usr/bin/env bash
# Diagnose why `cargo build --locked` wanted to change Cargo.lock inside the container.
set -u
mkdir -p /work && cd /repo && tar --exclude=./target --exclude=./upstream --exclude=./.git --exclude='./spike/*/target' --exclude=./results -cf - . | tar -xf - -C /work
cd /work && cp Cargo.lock /tmp/Cargo.lock.orig
cargo metadata --format-version 1 >/dev/null 2>/tmp/meta.err; echo "metadata (no --locked) rc=$?"; cat /tmp/meta.err
diff -u /tmp/Cargo.lock.orig Cargo.lock; echo "diff rc=$?"
