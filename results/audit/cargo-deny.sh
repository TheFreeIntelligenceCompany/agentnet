#!/usr/bin/env bash
# Runs inside rust:bookworm (latest stable at the time, linux/arm64). The committed tree is streamed in on stdin;
# deny.toml is bind-mounted at /deny.toml. CARGO_HOME is a named docker volume so the install is cached.
set -u
echo "== start $(date -u +%FT%TZ)"; rustc -V; cargo -V
export CARGO_HOME=/cargohome PATH=/cargohome/bin:$PATH CARGO_TERM_COLOR=never
if ! command -v cargo-deny >/dev/null; then
  echo "== cargo install cargo-deny --locked  $(date -u +%FT%TZ)"
  cargo install cargo-deny --locked; echo "INSTALL_EXIT=$?"
fi
cargo-deny --version
mkdir -p /work && tar -xf - -C /work && cd /work
for sub in "check" "list"; do :; done
echo "== cargo deny --workspace --locked check (all)  $(date -u +%FT%TZ)"
cargo deny --locked --manifest-path /work/Cargo.toml --config /deny.toml check 2>&1; echo "DENY_EXIT=$?"
echo "== per-check exit codes"
for c in advisories bans licenses sources; do cargo deny --locked --manifest-path /work/Cargo.toml --config /deny.toml check $c >/tmp/$c.out 2>&1; echo "$c exit=$?"; done
echo "== licenses summary"
cargo deny --locked --manifest-path /work/Cargo.toml --config /deny.toml list --format human 2>&1
echo "== end $(date -u +%FT%TZ)"
