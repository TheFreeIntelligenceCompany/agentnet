# openpgp-eval: RFC 9580 OpenPGP interoperability spike (A2)

Standalone crate (empty `[workspace]`, not a member of the AgentNet workspace, committed `Cargo.lock`).
Disposable spike code: nothing here is a candidate implementation and nothing touches `crates/`.
Findings: `docs/spike/notes-openpgp.md`. Raw evidence: `results/a2-openpgp/`.
Draft decision: `docs/adr/0004-openpgp-message-protection.md` (Proposed).

Two independent implementations, one binary each, same command line:

| Binary | Implementation | Notes |
|---|---|---|
| `target/debug/seq` | Sequoia `sequoia-openpgp =2.5.0` (LGPL-2.0-or-later) | crypto backend chosen by a cargo feature |
| `target/debug/rpgp` | rPGP `pgp =0.21.1` plus the `rpgpie =0.12.1` OpenPGP-semantics layer (MIT OR Apache-2.0, pure Rust) | rPGP alone does not evaluate expiry, revocation or key flags |

Both are local, in-process, no network. Keys are disposable and are generated on every run; secret keys are
written only to the `<work-dir>` you pass (keep it outside the repository). Public certificates and
messages are copied to `results/a2-openpgp/artifacts/`.

## Build

Disk: the debug `target/` is about 1.3 GB. It is ignored by the repository `.gitignore` (`target/` matches at any depth).
Delete it when finished: `rm -rf spike/openpgp-eval/target`.

Sequoia needs exactly one crypto backend feature:

```sh
cd spike/openpgp-eval
export CARGO_TARGET_DIR=$PWD/target

# 1. OpenSSL backend (what the committed results use). Needs OpenSSL 3 headers:
#    macOS (Homebrew): export OPENSSL_DIR=$(brew --prefix openssl@3)
cargo build --no-default-features --features seq-openssl

# 2. Pure-Rust (RustCrypto) backend. Sequoia flags it "not production ready" and "not constant time"
#    (build.rs of sequoia-openpgp 2.5.0); the two opt-in features are enabled by `seq-rust`.
cargo build --no-default-features --features seq-rust

# 3. Nettle backend (Sequoia's default). FAILS on this host: Homebrew nettle 4.0 has no <nettle/pgp.h>,
#    nettle-sys 2.3.2 cannot generate bindings (results/a2-openpgp/build-seq-nettle-default-FAILED.txt).
cargo build        # default feature = seq-nettle
```

## Run everything (G3, G4, G5)

```sh
cd spike/openpgp-eval
WORK=$(mktemp -d)        # secret keys land here, not in the repo
./run-all.sh ../../results/a2-openpgp "$WORK"
cat ../../results/a2-openpgp/g3-summary.txt        # PASS=88 FAIL=0 on the committed run
rm -rf "$WORK"
```

`run-all.sh` writes `g3-matrix.txt` (every command and its output), `g3-summary.txt`, `g3-tamper-scan.txt`,
`g4-sizes-timings.txt`, `g5-packet-dumps.txt`, `g5-linkability.txt`, `certs-info.txt`, `rotation-cert-info.txt`.

RFC 9580 Appendix A vectors (taken from the downloaded RFC text, not from memory):

```sh
curl -sSL https://www.rfc-editor.org/rfc/rfc9580.txt -o /path/outside/repo/rfc9580.txt
python3 -I extract-rfc-vectors.py /path/outside/repo/rfc9580.txt ../../results/a2-openpgp/rfc9580-vectors
target/debug/seq  rfc-vectors --dir ../../results/a2-openpgp/rfc9580-vectors
target/debug/rpgp rfc-vectors --dir ../../results/a2-openpgp/rfc9580-vectors
```

Licence summary of the dependency graph per backend (approximation of `cargo deny check licenses` against
the repo `deny.toml` allow list; `cargo-deny` is not installed on this host):

```sh
for f in seq-nettle seq-openssl seq-rust; do
  cargo tree --no-default-features --features $f --prefix none -e normal -f '{p}|{l}' > ../../results/a2-openpgp/cargo-tree-$f.txt
done
python3 -I licence-summary.py ../../results/a2-openpgp seq-nettle seq-openssl seq-rust
```

## Command line (both binaries)

```
gen --name N --out DIR [--enc-validity-days D --created-days-ago A]  v6 cert: Ed25519 primary (certify+sign), X25519 encryption subkey
seal --from SEC --to PUB --body LEN|--payload FILE --out FILE [--pad none|pow2] [--no-intended] [--named-recipient] [--unsigned]
open --me SEC --sender PUB --in FILE [--allow-no-intended] [--crypto-only]
dump --in FILE [--me SEC]            packet structure (what an observer sees; with --me what the recipient sees, seq only)
scan --me SEC --sender PUB --in FILE every single-byte flip and every truncation
bench --alice-sec A --bob-sec B      sizes and timings
rfc-vectors --dir DIR
seq only: cert revoke-cert|revoke-subkey|rotate|strip-binding|graft|merge|info, forward
```

`open` performs: SEIPDv2 required, exactly one signature, signer certificate == the claimed sender certificate,
an Intended Recipient Fingerprint naming the receiver's primary key (unless `--allow-no-intended`), then the
application checks (`payload.sender == verified signer`, `payload.recipient == me`, TTL) unless `--crypto-only`.
