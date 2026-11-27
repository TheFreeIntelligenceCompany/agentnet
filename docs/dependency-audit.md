# Dependency audit

Status: facts from `cargo metadata`, `cargo tree` and `cargo deny` for the tree after ADR 0004 (OpenPGP cutover; `Cargo.lock` of
474 packages), run on 2026-11-26 on a macOS arm64 host. Nothing here is a security review of the dependencies; it is an inventory plus
the output of the automated checks. Raw files: `results/adr0004/cargo-deny.txt`, `results/adr0004/msrv-1.89-build.txt`,
`results/adr0004/interop-rpgp.txt`; older evidence in `results/audit/` describes the HPKE-era tree and is kept only as history.
Licence obligations of the new set (LGPL, OpenSSL) are in `docs/licensing.md`.

**UNTESTED on GitHub:** `.github/workflows/ci.yml` (native-package install step, the new `interop` job, the `--locked` flags and the
`deny` job) and `deny.toml` under the GitHub cargo-deny action have never run on GitHub Actions. They were validated locally only
(YAML parsed with Ruby `YAML.load_file`; `cargo-deny 0.22.1` run locally; the interop crate and the MSRV build run on macOS arm64). Linux
x86_64/arm64 builds with OpenSSL 3 are UNTESTED in this document.

## 0. What changed with ADR 0004, and how the policy files follow

* `crates/core/Cargo.toml`: removed `hpke =0.15.1` and `ed25519-dalek =3.0.0`; added `sequoia-openpgp =2.5.0` with
  `default-features = false, features = ["crypto-openssl"]` (no Nettle, not the experimental pure-Rust backend, no compression).
  `hpke 0.12.0` remains only as a transitive dependency of `age 0.12.1` (post-quantum and plugin recipients); AgentNet code does not use it.
* **Native prerequisites** (build): OpenSSL 3 headers and libraries (`OPENSSL_DIR`; Homebrew `openssl@3`; Debian/Ubuntu `libssl-dev`),
  `pkg-config`, a C toolchain and **libclang**: `openssl-sys 0.9.118` has its `bindgen` feature enabled by `ossl 1.5.5`
  (`cargo tree -i bindgen -e all`: `bindgen` is a build-dependency of `openssl-sys` and `ossl`), and `sequoia-openpgp` has `lalrpop 0.23.2` as
  a build-dependency. Run time: the OpenSSL 3 shared libraries (macOS check: `otool -L target/debug/agentnet` lists
  `/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib` and `libcrypto.3.dylib`). Vendored/static OpenSSL (`openssl-src`) is UNTESTED.
* **What the policy changes are** (all in `deny.toml`, each narrow; verified by running `cargo-deny 0.22.1`):

| Change | Why | Scope |
|---|---|---|
| `[[licenses.exceptions]] crate = "sequoia-openpgp@2.5.0", allow = ["LGPL-2.0-or-later"]` | declared licence is LGPL-2.0-or-later, not in the allow list | that crate at that exact version |
| `[[licenses.exceptions]] crate = "buffered-reader@1.4.1", allow = ["LGPL-2.0-or-later"]` | same; it is Sequoia's dependency | that crate at that exact version |
| `{ crate = "openssl-sys", wrappers = ["ossl", "sequoia-openpgp"] }` instead of an unconditional ban | the OpenSSL backend of Sequoia requires it; the first run reported `openssl-sys v0.9.118 <- ossl v1.5.5 <- sequoia-openpgp` and `openssl-sys <- sequoia-openpgp` as its direct dependents | allowed only if the direct dependent is `ossl` or `sequoia-openpgp`; `openssl` and `native-tls` stay banned |
| comment of the `RUSTSEC-2026-0387` ignore | referred to `hpke =0.15.1`, which AgentNet no longer uses | text only; the ignore itself is unchanged |

* **Corrections to the cutover hand-off list.** It said `jiff`, `jiff-core`, `jiff-static`, `portable-atomic` and `portable-atomic-util`
  have no licence field. In this lock file they do: `jiff 1.0.3`, `jiff-core 1.0.2`, `jiff-static 1.0.3` are `Unlicense OR MIT`
  (files `COPYING`, `LICENSE-MIT`, `UNLICENSE` present in the registry sources), `portable-atomic 1.15.0` and
  `portable-atomic-util 0.2.8` are `Apache-2.0 OR MIT` (`LICENSE-APACHE`, `LICENSE-MIT` present). `cargo deny` accepted them without a
  `[[licenses.clarify]]`. No clarification was needed. The build-time crates (`bindgen 0.72.1` BSD-3-Clause, `clang-sys 1.9.1` Apache-2.0,
  `lalrpop 0.23.2` Apache-2.0 OR MIT, `libloading 0.8.9` ISC, `foldhash` Zlib, `xxhash-rust 0.8.21` BSL-1.0, `memsec 0.7.0` MIT,
  `sha1collisiondetection 0.3.4` MIT, `ossl 1.5.5` Apache-2.0, `openssl-sys 0.9.118` MIT) are all already in the allow list.
* Crates added at run time by Sequoia: `sequoia-openpgp`, `buffered-reader`, `ossl`, `openssl-sys`, `argon2 0.5.3`, `blake2 0.10.6`, `base64ct`,
  `password-hash`, `sha3`, `keccak`, `sha1collisiondetection`, `memsec`, `xxhash-rust`, `ctor`, `link-section`, `linktime-proc-macro`, `sponge-cursor`.
  Build-time only: `bindgen`, `clang-sys`, `libloading`, `cexpr`, `shlex`, `prettyplease`, `lalrpop`, `lalrpop-util`, `ena`, `petgraph`, `fixedbitset`,
  `ascii-canvas`, `term`, `string_cache`, `phf_shared`, `new_debug_unreachable`, `precomputed-hash`, `siphasher`, `annotate-snippets`, `unicode-width`,
  `unicode-xid`, `nom 7.1.3`, `minimal-lexical`, `itertools`, `either`, `glob` (from the cutover hand-off list; not re-derived here).

## 1. Counts

| Measure | Value | How obtained |
|---|---|---|
| Packages in `Cargo.lock` | **474** | `grep -c '^\[\[package\]\]' Cargo.lock` |
| External crates in the resolved graph for `aarch64-apple-darwin` (all dependency kinds) | **399** (405 packages with the 6 workspace members) | `cargo metadata --locked --filter-platform aarch64-apple-darwin` |
| Name+version pairs, normal + build dependencies, all workspace members | **340** | `cargo tree --locked -e normal,build --prefix none --workspace`, de-duplicated |
| Crate names with more than one version (`cargo deny`, three targets, all features) | 25 | section 4 |
| Direct external dependencies of the workspace crates | 33 name+version pairs | section 2 |
| Licence expressions | 30 distinct strings across the 399 external crates | section 3 |


## 2. Direct dependencies

MSRV note: the highest declared `rust-version` among the 405 packages of the resolved graph is **1.89.0** (`rusqlite 0.42.0`, `uuid 1.29.3`); the workspace `rust-version` is **1.89**. `sequoia-openpgp 2.5.0` and `buffered-reader 1.4.1` declare 1.85, `openssl-sys 0.9.118` 1.80, `lalrpop 0.23.2` 1.86, `bindgen 0.72.1` 1.70 (`cargo metadata`). 95 packages declare no `rust-version`, so the declaration alone proves nothing for them: a real `cargo build --workspace --locked` with rustc **1.89.0** succeeded (exit 0, 345 crates compiled; `results/adr0004/msrv-1.89-build.txt`; built, not run). **The MSRV of 1.89 still holds with the new dependency set.**

Resolved version, licence as declared in the crate's metadata (SPDX-like strings are as the crates wrote them, e.g. `MIT/Apache-2.0`), declared MSRV, and which workspace crate uses it. "dev" = dev-dependency only.

| Crate | Version | Licence (crate metadata) | Declared MSRV | Used by (kind) |
|---|---|---|---|---|
| `age` | 0.12.1 | MIT OR Apache-2.0 | 1.74 | core (normal) |
| `anyhow` | 1.0.105 | MIT OR Apache-2.0 | 1.68 | cli (dev), mcp (dev) |
| `async-trait` | 0.1.92 | MIT OR Apache-2.0 | 1.71 | core (normal), daemon (normal), mcp (dev), transport (normal) |
| `axum` | 0.8.9 | MIT | 1.80 | daemon (dev), mcp (normal) |
| `base64` | 0.22.1 | MIT OR Apache-2.0 | 1.48.0 | core (normal), transport (dev/normal) |
| `clap` | 4.6.10 | MIT OR Apache-2.0 | 1.85 | cli (normal) |
| `data-encoding` | 2.11.1 | MIT | 1.48 | core (normal) |
| `fs4` | 0.13.1 | MIT OR Apache-2.0 | 1.75.0 | daemon (normal) |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 | 1.85 | core (normal), daemon (normal) |
| `hmac` | 0.12.1 | MIT OR Apache-2.0 | - | daemon (normal) |
| `sequoia-openpgp` | 2.5.0 | LGPL-2.0-or-later | 1.85 | core (normal) |
| `jsonschema` | 0.63.1 | MIT | 1.85.0 | mcp (dev) |
| `proptest` | 1.12.0 | MIT OR Apache-2.0 | 1.88 | core (dev) |
| `reqwest` | 0.12.28 | MIT OR Apache-2.0 | 1.64.0 | cli (normal), daemon (normal), transport (dev/normal) |
| `reqwest` | 0.13.5 | MIT OR Apache-2.0 | 1.85.0 | mcp (dev) |
| `rmcp` | 3.11.0 | Apache-2.0 | 1.88 | cli (dev), mcp (dev/normal) |
| `rpassword` | 7.5.5 | Apache-2.0 | 1.85 | cli (normal) |
| `rusqlite` | 0.42.0 | MIT | 1.89.0 | core (normal), daemon (normal) |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | 1.56 | cli (normal), core (normal), daemon (normal), mcp (normal), transport (normal) |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | 1.71 | cli (normal), core (normal), daemon (normal), mcp (normal), transport (dev/normal) |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | - | core (normal), daemon (normal), transport (normal) |
| `subtle` | 2.6.1 | BSD-3-Clause | - | daemon (normal), mcp (normal) |
| `tempfile` | 3.27.0 | MIT OR Apache-2.0 | 1.63 | cli (dev), core (dev), daemon (dev) |
| `thiserror` | 2.0.21 | MIT OR Apache-2.0 | 1.77 | core (normal), daemon (normal), mcp (normal), transport (normal) |
| `tokio` | 1.54.1 | MIT | 1.85 | cli (normal), core (normal), daemon (normal), mcp (normal), transport (dev/normal) |
| `tokio-util` | 0.7.20 | MIT | 1.85 | cli (normal), core (normal), daemon (normal), mcp (normal) |
| `toml` | 0.9.12+spec-1.1.0 | MIT OR Apache-2.0 | 1.76 | daemon (normal) |
| `tracing` | 0.1.44 | MIT | 1.65.0 | cli (normal), core (normal), daemon (normal), mcp (normal) |
| `tracing-subscriber` | 0.3.23 | MIT | 1.65.0 | cli (normal), mcp (dev) |
| `url` | 2.5.9 | MIT OR Apache-2.0 | 1.63 | daemon (normal), transport (normal) |
| `uuid` | 1.29.3 | Apache-2.0 OR MIT | 1.89.0 | core (normal) |
| `zeroize` | 1.9.2 | Apache-2.0 OR MIT | 1.85 | core (normal) |

Workspace crates themselves: `agentnet-core`, `agentnet-transport`, `agentnet-mcp`, `agentnet-daemon`, `agentnet-cli`, all `0.1.0`, licence `MIT`, `publish = false`, `unsafe_code = "forbid"` (`Cargo.toml` `workspace.lints.rust`).
Cryptography in the workspace: `sequoia-openpgp =2.5.0` (OpenPGP, RFC 9580; backend `crypto-openssl`: OpenSSL 3 through `ossl 1.5.5`/`openssl-sys 0.9.118`), `sha2 0.10.9`, `hmac 0.12.1` (webhook), `subtle 2.6.1`, `age 0.12.1` (identity export file), `zeroize 1.9.2`, `getrandom 0.4.3`. TLS to the local node and the optional webhook uses rustls (`ring`), not OpenSSL. `openssl-sys` is present (via Sequoia only; `cargo tree -i openssl-sys` lists `ossl` and `sequoia-openpgp` as its dependents); the `openssl` and `native-tls` crates are **absent** and still banned by `deny.toml`.

## 3. Licences

Licence expressions over the 399 external crates of the `aarch64-apple-darwin` resolved graph (`cargo metadata`, as declared):

| Licence expression (as declared) | Crates |
|---|---|
| `MIT OR Apache-2.0` | 190 |
| `MIT` | 74 |
| `Apache-2.0 OR MIT` | 53 |
| `Unicode-3.0` | 18 |
| `MIT/Apache-2.0` | 17 |
| `Apache-2.0` | 9 |
| `Apache-2.0/MIT` | 4 |
| `BSD-3-Clause` | 4 |
| `ISC` | 3 |
| **`LGPL-2.0-or-later`** | **2** (`sequoia-openpgp 2.5.0`, `buffered-reader 1.4.1`) |
| `Unlicense OR MIT`, `Unlicense/MIT`, `Zlib`, `Apache-2.0 OR ISC OR MIT`, `(MIT OR Apache-2.0) AND Unicode-3.0` | 2 each |
| 15 other expressions (`MIT-0`, `BSL-1.0`, `CDLA-Permissive-2.0`, `Apache-2.0 OR GPL-2.0-only`, `Apache-2.0 AND ISC`, ...) | 1 each |

Command: `cargo metadata --format-version 1 --locked --filter-platform aarch64-apple-darwin`, counting `license` of packages with a registry `source`.

**`cargo deny check licenses`: ok** with cargo-deny 0.22.1, `deny.toml` allow list (MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception,
BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, CDLA-Permissive-2.0, Unlicense, MIT-0, CC0-1.0, BSL-1.0; confidence threshold 0.9) plus
**exactly two exceptions**, `sequoia-openpgp@2.5.0` and `buffered-reader@1.4.1` for `LGPL-2.0-or-later`. Without them the check failed on
exactly those two crates (first run, exit 6). Dual-licensed crates with a copyleft alternative (`... OR LGPL-2.1-or-later`,
`Apache-2.0 OR GPL-2.0-only`) are satisfied by their permissive option; `CDLA-Permissive-2.0` (root-certificate data) is a data licence
allowed on purpose. What the LGPL means for a distributed binary: `docs/licensing.md` (maintainers' reading, not legal advice).

The workspace is MIT. The interoperability crate `tests/interop-rpgp` (rPGP `pgp 0.21.1`, `rpgpie 0.12.1`, both `MIT OR Apache-2.0`) is
excluded from the workspace, has its own `Cargo.lock` and is not linked into any shipped binary; `cargo deny` does not check it.

## 4. Duplicate versions

`cargo deny` reports 25 crate names with more than one version (warnings only, three targets, all features; list in
`results/adr0004/cargo-deny.txt`): `base64`, `block-buffer`, `chacha20`, `const-oid`, `cpufeatures`, `crypto-common`, `digest`, `foldhash`, `getrandom`,
`hashbrown`, `hybrid-array`, `itertools`, `keccak`, `nom`, `rand`, `rand_core`, `reqwest`, `sha2`, `sha3`, `shlex`, `syn`, `thiserror`,
`thiserror-impl`, `toml`, `winnow`. Causes known from the earlier tree and still applicable: `age 0.12.1` pulls older RustCrypto generations
(`digest 0.10`, `sha2 0.10`), `rand 0.8`, `thiserror 1`, `toml 0.5` and its own `hpke 0.12.0`; `rmcp` pulls the newer ones; `reqwest 0.12.28`
(workspace, rustls) versus `reqwest 0.13.5` (dev-only, MCP tests). There is no longer a second HPKE: only `age`'s `hpke 0.12.0` remains.
`age` is a heavy dependency for one feature (passphrase export); an alternative export format would shrink the graph (owner's decision).

## 5. Native / C code and `unsafe`

| Crate | Native code | In the release `agentnet` binary graph (normal + build)? | Evidence |
|---|---|---|---|
| **OpenSSL 3** (system library) via `openssl-sys 0.9.118` and `ossl 1.5.5` (FFI bindings generated by `bindgen` at build time) | C library (`libssl`, `libcrypto`), **dynamically linked** | **Yes**, through `sequoia-openpgp`; all OpenPGP primitives (Ed25519, X25519, AES-OCB, SHA-2/3) run in OpenSSL | `otool -L` (section 0); `cargo tree -i openssl-sys` |
| `libsqlite3-sys 0.40.0` via `rusqlite 0.42.0` (feature `bundled`) | bundled SQLite 3.54.1 C source compiled by `cc` | Yes | `results/audit/cargo-tree-inverse.txt` (HPKE-era, unchanged by ADR 0004) |
| `ring 0.17.14` | C and assembly, via `rustls 0.23.46` <- `reqwest 0.12.28` | Yes | `cargo tree -i ring -e normal` |
| `aws-lc-sys` / `aws-lc-rs` | C | **No** in normal+build (`cargo tree -i aws-lc-sys -e normal,build`: "nothing to print"); dev-dependency graphs only | as before |
| `sequoia-openpgp 2.5.0`, `buffered-reader`, `memsec 0.7.0` | Rust with `unsafe` (memory locking/zeroing, FFI to OpenSSL); not audited here | Yes | not reviewed |

`unsafe_code = "forbid"` applies to the workspace crates only. Dependencies contain `unsafe` as usual, and the OpenSSL backend adds FFI `unsafe` and
non-Rust memory to the process. The pure-Rust Sequoia backend (`crypto-rust`) was rejected by ADR 0004 because Sequoia flags it not production-ready and not
constant-time (`docs/spike/notes-openpgp.md` 2.3). TLS root certificates come from `webpki-roots` (CDLA-Permissive-2.0).

## 6. Advisories

`cargo-deny 0.22.1 --locked check` on 2026-11-26 (RustSec database fetched at run time; macOS arm64): **`advisories ok, bans ok, licenses ok, sources ok`**, exit 0
(`results/adr0004/cargo-deny.txt`). The tool and its build directory were installed in a throwaway `--root` outside the repository (not on the host's global
cargo path); cargo-deny 0.22.1 needs rustc 1.95, so a temporary rustup home was used for that build only.

* **Ignored (1):** `RUSTSEC-2026-0387` "Multiple timing variability issues in operations intended to be constant-time", `crypto-bigint 0.5.5`, path
  `crypto-bigint <- elliptic-curve 0.13.8 <- p256 0.13.2 <- age 0.12.1 and hpke 0.12.0 (via age)`. No semver-compatible fix is reachable
  (`elliptic-curve 0.13.8` requires `crypto-bigint ^0.5`). Justification: reachable only through `age`, which AgentNet uses for the scrypt-passphrase identity
  export; message protection no longer uses HPKE or P-256. That the P-256 code is unreachable from the scrypt path was **read, not tested**. Revisit when `age` updates.
* **New advisories against Sequoia and its dependencies in this run: none reported.** The RustSec database does contain advisories for the crates involved; none
  applies to the locked versions (each is patched at or below the locked version, per the database entries read in
  `~/.cargo/advisory-dbs`): `sequoia-openpgp` RUSTSEC-2023-0038 (out-of-bounds array index panic; patched >= 1.16.0), RUSTSEC-2024-0345 (low-severity DoS; patched >= 1.21.0),
  RUSTSEC-2025-0136 ("Underflow in aes_key_unwrap function"; patched >= 2.1.0); `buffered-reader` RUSTSEC-2023-0039 (same out-of-bounds panic; patched >= 1.2.0);
  `pgp` (rPGP) RUSTSEC-2024-0447 ("Panics on Malformed Untrusted Input"; patched >= 0.14.1). The `openssl` *crate* has eight 2026 advisories (RUSTSEC-2026-0463, 0473 to 0479;
  patched >= 0.10.78 to 0.10.80); that crate is not in the graph (only `openssl-sys`). Advisories that exist only as GitHub advisories (for example rPGP's, listed in
  `docs/spike/notes-openpgp.md` 2.5) are not covered by `cargo deny` and were not re-checked. The OpenSSL C library itself has its own advisories (a system
  package, not tracked by `cargo deny`); the deployed OpenSSL 3 version must be kept patched.
* `sequoia-openpgp 2.5.0` was released 2026-11-25 with seven CVE-labelled fixes (`docs/spike/notes-openpgp.md` 2.5): review the pin on every advisory.

**Audit facts (no audit of the shipped versions is claimed).** Sequoia: no third-party audit was found (searched; absence of evidence is UNVERIFIED); the 2.5.0 `NEWS` lists
seven CVE-labelled fixes in validation paths. rPGP (used only in the interoperability test): Radically Open Security "NLnet Security Evaluation rPGP" report v1.0
(December 2024), limited review and fuzzing, 3 days testing, on code at about v0.14.x; the version used here is 0.21.1 and was **not** audited; ten GitHub advisories
exist, four published 2026-11-11. Sources and details: `docs/spike/notes-openpgp.md` 2.5. OpenSSL: this document makes no claim about its audits. The AgentNet
composition has had no independent review (README).

## 7. Bans and sources

* `deny.toml` `[bans]`: `openssl` and `native-tls` denied; `openssl-sys` denied unless its direct dependent is `ossl` or `sequoia-openpgp` (section 0); wildcards denied
  (path dependencies allowed); duplicate versions warn only.
* `[sources]`: crates.io only; `grep -c 'source = "git' Cargo.lock` should be 0 (not re-run here; `cargo deny` reports `sources ok`). `unknown-git = "deny"`.
* Result: `bans ok` (25 duplicate warnings), `sources ok`.

## 8. Interoperability check (independent implementation)

`tests/interop-rpgp` (workspace-excluded, own lock file; `pgp =0.21.1` + `rpgpie =0.12.1`) opens AgentNet-sealed frames with rPGP, makes messages with rPGP that
AgentNet opens, and checks negatives; 4 tests passed on macOS arm64 (`results/adr0004/interop-rpgp.txt`). CI job `interop` runs it (UNTESTED on GitHub).

## 9. How to reproduce

```sh
# cargo-deny 0.22.1 needs rustc >= 1.95. Install it outside the repository and outside the global cargo path:
cargo install --locked --root /some/scratch/dir/cargo-deny cargo-deny@0.22.1     # with a rustc >= 1.95 toolchain
/some/scratch/dir/cargo-deny/bin/cargo-deny --locked check                          # from the repository root
# MSRV check, interop check:
export OPENSSL_DIR=$(brew --prefix openssl@3)                                       # macOS; Debian/Ubuntu: apt install libssl-dev libclang-dev pkg-config
cargo +1.89.0 build --workspace --locked
cargo test --locked --manifest-path tests/interop-rpgp/Cargo.toml -- --nocapture --test-threads=1
```

In CI the same checks are jobs `msrv`, `deny` and `interop` (`.github/workflows/ci.yml`; UNTESTED on GitHub since the ADR 0004 edits; an earlier version of the
`deny` job ran on GitHub Actions for the HPKE-era commit `76e797d`, run 45845088419).
