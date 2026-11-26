# Dependency audit

Status: facts from `cargo metadata`, `cargo tree` and `cargo deny` at the committed tree (`git archive HEAD`, commit `0eb3d35`, `Cargo.lock` of 439 packages) on 2026-11-25. Nothing here is a security review of the dependencies; it is an inventory plus the
output of the automated checks. Raw files: `results/audit/cargo-deny.log`, `cargo-tree-*.txt`, `crates-io-versions.txt`. Note: the working tree later gained a sixth workspace member (`tests/acceptance`, written by another contributor); this document describes the committed five-crate workspace.

## 1. Counts

| Measure | Value | How obtained |
|---|---|---|
| Packages in `Cargo.lock` | **439** = 5 workspace crates + **434** external crates (all targets, including Windows, wasm, Android-only crates) | `cargo metadata --locked`; `grep -c '^\[\[package\]\]' Cargo.lock` |
| External crates in the build graph of the macOS arm64 host, normal + build dependencies | **301** name+version pairs (273 distinct names) | `cargo tree --workspace --locked -e normal,build --prefix none`, de-duplicated (`results/audit/cargo-tree-normal-build-unique.txt`) |
| ... including dev-dependencies (test builds) | **358** (327 distinct names) | `-e normal,build,dev` (`cargo-tree-all-unique.txt`) |
| Crates with more than one version in the host graph (normal + build) | 28 | section 4 |
| Direct external dependencies of the workspace crates | 33 name+version pairs | section 2 |
| Licence expressions | 30 distinct strings across the 434 external crates (section 3) | `cargo metadata` |

## 2. Direct dependencies

MSRV note: the highest declared MSRV among the locked crates is **1.89.0** (`rusqlite 0.42.0`, `uuid 1.29.3`; most others 1.88 or lower). The workspace `rust-version` was 1.88 and is now **1.89** (fixed in working tree; evidence `results/audit/msrv-1.88-check.log` for the failure and `results/fixups/msrv-1.89-build.log` for the 1.89.0 build; CI builds with 1.89.0 in its `msrv` job).

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
| `ed25519-dalek` | 3.0.0 | BSD-3-Clause | 1.85 | core (normal) |
| `fs4` | 0.13.1 | MIT OR Apache-2.0 | 1.75.0 | daemon (normal) |
| `getrandom` | 0.4.3 | MIT OR Apache-2.0 | 1.85 | core (normal), daemon (normal) |
| `hmac` | 0.12.1 | MIT OR Apache-2.0 | - | daemon (normal) |
| `hpke` | 0.15.1 | MIT/Apache-2.0 | 1.87 | core (normal) |
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
Cryptography in the workspace: `hpke =0.15.1` (features `alloc, getrandom, x25519, chacha` only), `ed25519-dalek 3.0.0`, `sha2 0.10.9`, `hmac 0.12.1` (webhook), `subtle 2.6.1`, `age 0.12.1` (export file), `zeroize 1.9.2`, `getrandom 0.4.3`. No OpenSSL: `openssl`, `openssl-sys` and `native-tls` are **absent** from the dependency graph (`cargo tree -i` answers "did not match any packages"; `results/audit/cargo-tree-inverse.txt`), and `deny.toml` bans them.

## 3. Licences

Counts of licence expressions over the 434 external crates in `Cargo.lock` (all targets; `cargo metadata`):

| Licence expression (as declared) | Crates |
|---|---|
| `MIT OR Apache-2.0` | 220 |
| `MIT` | 73 |
| `Apache-2.0 OR MIT` | 53 |
| `MIT/Apache-2.0` | 18 |
| `Unicode-3.0` | 18 |
| `Apache-2.0` | 7 |
| `BSD-3-Clause` | 6 |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 5 |
| `Apache-2.0 OR ISC OR MIT` | 3 |
| `Unlicense OR MIT` | 3 |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 2 |
| `Apache-2.0/MIT` | 2 |
| `BSD-2-Clause OR Apache-2.0 OR MIT` | 2 |
| `CDLA-Permissive-2.0` | 2 |
| `ISC` | 2 |
| `MIT OR Apache-2.0 OR BSD-1-Clause` | 2 |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 2 |
| `Unlicense/MIT` | 2 |
| `Apache-2.0 / MIT` | 1 |
| `Apache-2.0 AND ISC` | 1 |
| `Apache-2.0 OR BSL-1.0` | 1 |
| `Apache-2.0 OR GPL-2.0-only` | 1 |
| `CC0-1.0 OR MIT-0 OR Apache-2.0` | 1 |
| `ISC AND (Apache-2.0 OR ISC)` | 1 |
| `ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)` | 1 |
| `MIT AND BSD-3-Clause` | 1 |
| `MIT OR Apache-2.0 OR Zlib` | 1 |
| `MIT-0` | 1 |
| `Zlib` | 1 |
| `Zlib OR Apache-2.0 OR MIT` | 1 |

`cargo deny` evaluates only the three Unix targets listed in `deny.toml` (`aarch64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`), so Windows-only and wasm-only crates in the lockfile are not part of the verdict.

**`cargo deny check licenses` result: ok** (cargo-deny 0.22.1, `deny.toml` allow list: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, CDLA-Permissive-2.0, Unlicense, MIT-0, CC0-1.0, BSL-1.0; confidence threshold 0.9). **No licence exceptions were needed.** Every crate offers at least one permissive alternative in its expression, including the ones with a copyleft alternative: `MIT OR Apache-2.0 OR LGPL-2.1-or-later` (2 crates) and `Apache-2.0 OR GPL-2.0-only` (1 crate) are satisfied by the MIT/Apache option; `CDLA-Permissive-2.0` (2 crates, root-certificate data) is permissive but is a data licence, listed in the allow list on purpose. The workspace `MIT OR Apache-2.0` declaration is not contradicted by any dependency licence found; that is not a legal conclusion.

## 4. Duplicate versions (host build graph, normal + build dependencies)

28 crate names appear in more than one version (`results/audit/cargo-tree-duplicates.txt`). The ones that matter:

| Duplicate | Versions | Why |
|---|---|---|
| **`hpke`** | **0.12.0** and **0.15.1** | 0.15.1 is the direct, pinned (`=0.15.1`) dependency used for message encryption. 0.12.0 comes in through **`age 0.12.1` and `age-core 0.12.0`** (age uses HPKE for its post-quantum and plugin recipient types). The workspace only uses age's scrypt passphrase recipient for the identity export file; the 0.12.0 code is compiled in anyway. Two independent HPKE implementations of different ages sit in the binary. |
| RustCrypto generations | `aead` 0.5.2/0.6.1, `chacha20poly1305` 0.10.1/0.11.0, `chacha20` 0.9.1/0.10.2, `poly1305` 0.8.0/0.9.1, `cipher` 0.4.4/0.5.2, `digest` 0.10.7/0.11.3, `crypto-common` 0.1.7/0.2.2, `block-buffer`, `hkdf` 0.12.4/0.13.0, `hmac` 0.12.1/0.13.0, `sha2` 0.10.9/0.11.2, `curve25519-dalek` 4.1.3/5.0.0, `x25519-dalek` 2.0.1/3.0.0, `hybrid-array`, `const-oid`, `universal-hash` | `age`/`hpke 0.12.0` still use the older (0.10/0.12 generation) crates; `hpke 0.15.1`, `ed25519-dalek 3`, `rmcp` use the newer ones. Both generations of the primitive crates are linked into one binary. |
| `rand` | 0.8.8 (via `age`) and 0.10.4 (via `rmcp`) | and `rand_core` 0.6.4 / 0.10.1, `getrandom` 0.2.17 / 0.4.3 |
| `thiserror` | 1.0.69 (via `i18n-embed` <- `age`) and 2.0.21 | |
| `toml` | 0.5.11 (via `find-crate` <- `i18n-embed-*` <- `age`) and 0.9.12 | |
| `syn` | 2.0.119 and 3.0.10 | proc-macro build-time only |
| `base64` | 0.22.1 and 0.23.1 (via `hyper-util`/`rmcp`) | |
| `reqwest` | 0.12.28 (workspace, `rustls-tls`) and 0.13.5 (dev-only: `agentnet-mcp` tests, and `rmcp`'s client features) | not in the release binary's graph |
| `winnow`, `cpufeatures`, `getrandom`, `r-efi`, `windows-sys` ... | various | platform/parser plumbing |

Observation: **`age` is a heavy dependency for one feature** (passphrase export): it drags in `i18n-embed`/`fluent`/`rust-embed`, older RustCrypto generations, `rand 0.8`, `thiserror 1`, `toml 0.5` and a second `hpke`. An alternative export format would shrink the graph; that is a decision for the owner, not a finding of a defect.

## 5. Native / C code

From `cargo metadata` (`links` and build-script `cc`/`cmake`/`bindgen`/`pkg-config` build-dependencies) and `cargo tree -i`:

| Crate | Native code | In the release `agentnet` binary graph (host, normal + build)? | Evidence |
|---|---|---|---|
| `libsqlite3-sys 0.40.0` via `rusqlite 0.42.0` (feature `bundled`) | **Bundled SQLite C source compiled by `cc`** (`links = "sqlite3"`) | **Yes**: `agentnet-core` and `agentnet-daemon` | `results/audit/cargo-tree-inverse.txt` |
| `ring 0.17.14` | C and assembly (`links = ring_core_0_17_14_`), via `rustls 0.23.46` <- `reqwest 0.12.28` (`rustls-tls`) | **Yes**: `agentnet-cli`, `agentnet-daemon`, `agentnet-transport` | same |
| `aws-lc-sys 0.47.0` / `aws-lc-rs 1.19.0` | C (`cmake`, `bindgen`, `cc` as build-dependencies) | **No**: reachable only through dev-dependencies (`reqwest 0.13.5` with `rustls` in `agentnet-mcp` tests; feature unification then enables `aws-lc-rs` on the shared `rustls 0.23.46` in **test builds**) (`cargo tree -i aws-lc-sys -e normal,build` prints "nothing to print"; with `-e normal,build,dev` it is reachable). A Linux arm64 container **without cmake** compiled it fine during `cargo test` (`results/audit/linux-arm64-build.log`) | `cargo-tree-inverse.txt` |
| `iana-time-zone-haiku`, `sqlite-wasm-rs`, `wasm-bindgen-shared` | build-script C or link names for Haiku/wasm | No (other targets) | `cargo metadata` |

`unsafe_code = "forbid"` applies to the workspace crates only; the dependency tree contains `unsafe` as usual (not audited here). TLS is used only by the REST client to the **local** node and the optional webhook client; root certificates come from `webpki-roots` (Mozilla bundle, licence CDLA-Permissive-2.0) and `rustls-native-certs`/`rustls-platform-verifier` appear in the lockfile (dev/other-feature graphs).

## 6. Advisories

`cargo deny check advisories` (RustSec database fetched at run time inside the container, 2026-11-25):

| Advisory | Crate | Result | Path | Treatment |
|---|---|---|---|---|
| **RUSTSEC-2026-0387** "Multiple timing variability issues in operations intended to be constant-time" | `crypto-bigint 0.5.5` | **error** (first run: `advisories FAILED`, exit 1; `results/audit/cargo-deny-run1-before-ignore.log`) | `crypto-bigint` <- `elliptic-curve 0.13.8` <- `p256 0.13.2` <- `age 0.12.1` and `hpke 0.12.0` (the HPKE pulled in by age). Upstream says upgrade to crypto-bigint 0.7.6; `elliptic-curve 0.13.8` requires `^0.5`, so **no semver-compatible fix is reachable** from this workspace | **Ignored in `deny.toml` with a written reason.** Justification: reachable only through `age`; AgentNet uses age only for the scrypt-passphrase identity export, and its message encryption uses `hpke =0.15.1` with X25519 (no P-256, no crypto-bigint). That the P-256 code is not reachable from the scrypt export path was **read, not tested**; the advisory is about secret-dependent timing on secret integers, which matters for a local attacker able to time the export. Revisit when `age` moves to newer RustCrypto crates |

No other advisory (vulnerability, unmaintained, unsound, notice) and no yanked crate was reported. After adding the ignore: `advisories ok, bans ok, licenses ok, sources ok`, exit 0 (`results/audit/cargo-deny.log`). Note for the spike notes: `docs/spike/notes-mcp.md` s5 item 10 mentions RUSTSEC-2026-0543 (`chrono`) from upstream's issue tracker; cargo-deny did **not** report it for this workspace (the lockfile contains `chrono 0.4.45`, only in non-targeted or dev graphs, or the advisory is not in the database snapshot used: not investigated).

## 7. Bans and sources

* `deny.toml` `[bans]`: `openssl`, `openssl-sys`, `native-tls` denied (absent from the graph), wildcards denied (path dependencies allowed), duplicate versions warn only.
* `[sources]`: crates.io registry only; no git dependencies in `Cargo.lock` (`grep -c 'source = "git' Cargo.lock` = 0). `unknown-git = "deny"`.
* Result: `bans ok`; 29 `duplicate` warnings (as section 4, for all features and the three targets; warnings only). `sources ok`.
* Unused licence-allow entries and the exact `cargo-deny` output are in `results/audit/cargo-deny.log`. Tool versions: cargo-deny 0.22.1 installed with `cargo install cargo-deny --locked` in `rust:bookworm` (rustc 1.100.0, the stable current at the time) with a named Docker volume as `CARGO_HOME`; nothing was installed on the host.

## 8. How to reproduce

```sh
# cargo-deny is not installed on the host. Run it in a container with a named volume for CARGO_HOME:
git archive HEAD | docker run -i --rm -v agentnet-audit-cargohome:/cargohome \
   -v "$PWD/results/audit/cargo-deny.sh:/cargo-deny.sh:ro" -v "$PWD/deny.toml:/deny.toml:ro" rust:bookworm bash /cargo-deny.sh
```

(`results/audit/cargo-deny.sh` installs `cargo-deny` with `cargo install cargo-deny --locked` inside the container, then runs `cargo deny check` and per-check runs.) In CI the official action is used (`.github/workflows/ci.yml`; UNTESTED on GitHub).
