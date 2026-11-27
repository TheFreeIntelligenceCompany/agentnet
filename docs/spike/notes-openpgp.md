# OpenPGP (RFC 9580) as AgentNet message protection: spike notes

Date: 2026-11-26. Spike crate: `spike/openpgp-eval/` (standalone, committed `Cargo.lock`, README with exact commands).
Evidence: `results/a2-openpgp/` (every number below points to a file there). Host: macOS arm64 (Apple M1 Pro), rustc 1.92.0, debug builds, everything
in-process on localhost, no network, disposable keys. **Nothing in `crates/` or any existing doc was changed.**
Context: the repository holder ruled that ADR 0002 (HPKE base mode + Ed25519 signature, AgentNet's own envelope, recipient binding, key epochs,
signed contact records, wire format) violates the "no hand-rolled cryptography" requirement at the protocol level. This spike tests whether
RFC 9580 OpenPGP can replace it. It does not decide; the draft ADR is `docs/adr/0004-openpgp-message-protection.md` (Proposed).

## 0. Verdict

**GO-WITH-CONDITIONS.** Technically the standard does what AgentNet needs: stateless sign-and-encrypt with recipient binding, hidden recipient,
subkey binding, expiry, revocation, padding, all implemented by two unrelated codebases that interoperate in both directions and refuse the same
bad inputs (88/88 checks pass on both of Sequoia's relevant backends). The conditions are not about the protocol:

1. **Implementation and licence decision by the repository holder (blocker for Sequoia).** Sequoia is LGPL-2.0-or-later and its production-grade
   crypto backends are C libraries (Nettle, OpenSSL); the repo's `deny.toml` bans `openssl-sys` and allows only permissive licences. The
   permissive alternative (rPGP + rpgpie) is pure Rust but its OpenPGP-semantics layer is explicitly experimental. Section 2.
2. **A small, security-critical application policy layer remains** (require the Intended Recipient subpacket, v6 + SEIPDv2 + AEAD only, no
   compression, certificate acceptance/merge rules, replay, domain separation of the signed context). It is not a cryptographic construction but
   it is exactly what an independent review must read. Section 6. **The goal "no AgentNet-defined cryptographic construction left" is reachable;
   the goal "nothing security-relevant is AgentNet-defined" is not.**
3. **Neither library is audited at the version that would ship** (section 2.5). Both had security fixes this month. The existing
   condition 11 (independent review before sensitive use) stays open and now covers library choice plus glue.
4. No forward secrecy against later compromise of a recipient's encryption subkey: the accepted limitation is unchanged.

| Gate | Result | Evidence |
|---|---|---|
| G1 standard coverage | **GO** (gaps listed, section 1) | RFC 9580 section numbers below; `results/a2-openpgp/rfc9580-vectors/` |
| G2 implementation and audit facts | **GO-WITH-CONDITIONS** (licence/backend decision, no audit) | section 2; `upstream-facts/`, `cargo-tree-*.txt`, `licence-summary.txt`, `build-*.txt` |
| G3 interop round trip, negative tests | **GO** | `g3-summary.txt` (PASS=88 FAIL=0), `g3-matrix.txt`, `g3-tamper-scan.txt`, `crypto-rust-backend/` |
| G4 operating-model fit | **GO** (padding is a measured cost, rPGP cannot send padding) | `g4-sizes-timings.txt`, `g4-size-comparison.txt`, `rotation-cert-info.txt` |
| G5 metadata on a shared relay | **GO** | `g5-packet-dumps.txt`, `g5-linkability.txt` |
| G6 what remains custom | **GO-WITH-CONDITIONS** (section 6) | this file |

## 1. G1: what RFC 9580 replaces (text fetched from https://www.rfc-editor.org/rfc/rfc9580.txt, sha256 in `versions.txt`)

| RFC 9580 mechanism | Section | What it replaces in AgentNet |
|---|---|---|
| Signed-and-encrypted message in one standard structure: `ESK, SEIPD(OPS, Literal, Signature [, Padding])` (sign-then-encrypt, signature inside the encryption) | 10.3, 5.4, 5.9, 5.13 | the "inner = sig(64) \|\| env_bytes, then HPKE seal" construction and the frame layout |
| Intended Recipient Fingerprint subpacket (primary-key fingerprint, "SHOULD" be generated for signed+encrypted messages; v6 "SHOULD be critical") | 5.2.3.36, 13.12 | `envelope.recipient` inside the signature plus HPKE `info` recipient key (surreptitious forwarding defence) |
| Subkey Binding signature (0x18), Primary Key Binding (0x19), Key Flags | 5.2.1, 5.2.3.29 | the self-signed contact record binding `kem_pk` to the address key |
| Key Expiration Time | 5.2.3.13 | `kem_expires_at` |
| Key Revocation (0x20), Subkey Revocation (0x28), Reason for Revocation; escrowed revocation signatures | 5.2.1, 5.2.3.31, 13.9 | `revoked_kem_epochs_below`, the signed identity tombstone (and adds pre-generated revocations) |
| v6 key packet and 32-byte SHA2-256 fingerprint | 5.5.2.3, 5.5.4.3 | the address as identity (what the address encodes changes, see G4) |
| PKESK v6 with X25519, SEIPD v2 with AEAD (OCB/EAX/GCM), per-message ephemeral key and 32-byte salt, header authenticated as AEAD additional data | 5.1.2, 5.1.6, 5.13.2, 9.1 (alg 25 X25519, 27 Ed25519), 9.6 | HPKE base mode, fresh context per message, `aad` over the frame header |
| Hidden / anonymous recipient: v6 PKESK with zero-length key field, or all-zero Key ID in v3 | 5.1.2, 5.1.8 | (new: AgentNet had no recipient hiding beyond the bucket topic) |
| Padding packet, valid inside SEIPD v2 as last packet; "traffic analysis" guidance | 5.14, 13.11 | the home-grown `u32 len \|\| inner \|\| zeros` power-of-two padding (the *policy* stays ours) |
| Signature Creation Time / Signature Expiration Time (hashed, signed) | 5.2.3.11, 5.2.3.18 | could carry `created_at`/`expires_at`; **not exercised here** (UNTESTED), the spike keeps them in the JSON |
| Features (SEIPDv2), Preferred AEAD Ciphersuites | 5.2.3.32, 5.2.3.15 | partly `suites` (algorithm preference signed in the cert) |
| Packet version rules (v6 key requires v6 signature, v6 PKESK requires SEIPD v2) | 5.2, 10.3.2.1, 10.3.2.2 | no mixing of versions, so the "downgrade" surface is the cert's declared features, not a frame byte |
| Secret-key protection with Argon2 S2K + AEAD | 3.7, 5.5.3 | would replace the `age` passphrase export; **UNTESTED** |

AgentNet element by element (list from `docs/protocol.md`):

| AgentNet element | Disposition |
|---|---|
| Address `an1` + Ed25519 pk + checksum | **Stays application-level** (encoding and typo checksum); content changes to the v6 fingerprint. Gap: a fingerprint is a hash of the primary key *packet* (includes creation time), so it pins a cert but cannot by itself verify anything (G4). |
| Contact record: address, signing_pk, kem_pk, binding signature | **Replaced** by the v6 certificate (primary key, subkey, binding signatures). |
| `key_epoch` (monotonic order of records, stale/conflicting record rules) | **Gap**: OpenPGP has no epoch; merging certificates is a union of signatures and revocations only accumulate. Rollback to an older cert is possible at first contact; policy "merge, never replace" is application-level. |
| `revoked_kem_epochs_below` | **Replaced** by subkey revocation signatures (tested, REV1). |
| `suites`, no silent downgrade | **Partly replaced**: Features and Preferred AEAD in the signed cert; the receiver-side allow-list (v6, SEIPDv2, AEAD only) is application policy. |
| `inbox_buckets` (signed, so senders cannot pick the wrong topic) | **Gap**: no native field. Options: protocol constant, or a signed Notation Data subpacket (5.2.3.24, UNTESTED). Privacy-relevant only. |
| `created_at` of record, `kem_expires_at` | **Replaced** (key creation time, Key Expiration Time). |
| Envelope `v` | **Stays** (payload `v`); packet versions are standard. |
| `message_id`, `type`, `conversation_id`, `correlation_id`, `body` | **Stays application-level** (JSON payload inside the Literal Data packet). |
| `sender` | **Replaced** by the verified signer (Issuer Fingerprint 5.2.3.35 plus signature check); the JSON field becomes redundant and should be dropped or cross-checked. |
| `recipient` | **Replaced** by the Intended Recipient Fingerprint. **Note:** both libraries accept a signature that has no such subpacket; the receiver must require it (tested, N2b/N2c). |
| `suite`, `recipient_key_epoch` in the signed envelope | **Replaced**: algorithm ids and the decrypting subkey are bound by the packet formats and the AEAD additional data (5.13.2); no epoch. |
| `created_at`, `expires_at` and the time checks (skew, max TTL) | **Stays application-level** in the spike (could move to signature subpackets, UNTESTED). |
| Signing, `verify_strict`, domain string `agentnet/v1/envelope\0` | **Replaced** by OpenPGP data signatures (salted v6 signatures). **Gap:** the AgentNet-specific domain separation disappears from the signed bytes (section 6). |
| HPKE seal, fresh ephemeral per message, frame header `AN`, version, suite | **Replaced**. A first byte of `0xC1` (new-format PKESK tag) versus `AN` makes dispatch between legacy and OpenPGP frames possible. |
| Power-of-two padding | **Mechanism replaced** (Padding packet), **policy stays**. |
| Dedupe `(sender, message_id)`, replay guard, rollback guard, concurrent identity | **Stays application-level and security-critical.** OpenPGP has no replay protection (REPLAY test: the same message opens again). |
| `ack.received`, delivery state machine, retries, re-seal on contact update | **Stays** (re-seal is still possible: sealing is stateless). |
| `contact.update`, `identity.revoked` message types | **Stay as transport**: the body becomes a certificate or a revocation signature; verification is the library's merge. |
| Identity tombstone | **Replaced** by a key revocation signature; the "thief can issue it" property is unchanged. |
| Trust levels, `--expect` pinning, quarantine policy | **Stays application-level and security-critical** (OpenPGP defines no trust model; Sequoia README says the same). |
| Inbox topic derivation | **Stays**, input changes to the fingerprint. |

## 2. G2: implementation choice and audit facts

Sources: crates.io API (`results/a2-openpgp/upstream-facts/v-*.json`, `d-*.json`), the crate sources downloaded from crates.io (sha256 in `versions.txt`),
GitHub advisories page for rPGP, rPGP's own `docs/SECURITY_STATUS.md`, the ROS report (copied as text).

### 2.1 Versions

| | Sequoia `sequoia-openpgp` | rPGP `pgp` | rpgpie (semantics layer on rPGP) |
|---|---|---|---|
| Latest release, date | **2.5.0**, published 2026-11-25 14:42 UTC (one day before this spike) | **0.21.1**, published 2026-11-11 | 0.12.1, published 2026-10-26 |
| MSRV (crates.io `rust_version`) | **1.85** (the crate README still says 1.67, stale) | **1.88** | none declared |
| Workspace rust-version | 1.89: compatible | compatible | compatible |
| Licence | **LGPL-2.0-or-later** | MIT OR Apache-2.0 | MIT OR Apache-2.0 |
| RFC 9580 (v6 keys, SEIPDv2, v6 PKESK) | Added in 2.0.0 (2025-03-04, `NEWS`); exercised here | README, `docs/IMPL_STATUS.md`; exercised here | via rPGP |
| RFC 9580 Appendix A vectors (A.3 fingerprint, A.4 key, A.7 inline-signed, A.8.5 encrypted) | all pass | all pass | `rfc9580-vectors/results.txt` |

### 2.2 Licence: **flag for the repository holder**

* `sequoia-openpgp 2.5.0` and its dependency `buffered-reader 1.4.1` are `LGPL-2.0-or-later`. The shipped `LICENSE.txt` is the GNU **Library**
  General Public License v2 with the "or any later version" grant.
* The AgentNet source tree stays MIT: Sequoia would be a Cargo dependency, not copied code. The *distributed binary* is different. Cargo links Rust
  dependencies statically, so the `agentnet` binary is a "work that uses the Library" combined with it. Reading LGPL-2.0 sections 5 and 6 of that
  file: the work may be distributed under terms of the distributor's choice **provided** those terms permit modification of the work for the
  customer's own use and reverse engineering for debugging it; each copy must carry a prominent notice and the licence text; and the distributor
  must accompany it with the Library source plus the work in a form (object code or source) that lets the user relink with a modified Library, or a
  written offer for it (6a/6b), or offer equivalent access from a designated place (6c). For an open MIT repository with a committed `Cargo.lock`
  this is probably satisfiable by pointing at the repository, but static linking and Rust's lack of a stable ABI make "relinkable" a legal
  interpretation question. **This is my reading of the licence text, not legal advice; the repository holder (and counsel if the binary is
  distributed commercially) must decide.** Container images and release binaries each carry the notice/offer obligation.
* "or later" lets the distributor elect a later LGPL version; version 3 adds installation-information duties for consumer products, so electing
  2.x terms is the lighter option (not analysed further).
* `deny.toml` consequence: `cargo deny check licenses` fails on exactly these two crates (`licence-summary.txt`, approximation because
  `cargo-deny` is not installed here). Do not add LGPL to the global `allow`; a per-crate exception would be needed (syntax of cargo-deny's
  `exceptions` is from its documentation, **UNVERIFIED on this host**), and `docs/dependency-audit.md` must be updated in the same commit
  (`deny.toml` says the two must stay in sync). `all-features = true` in `deny.toml` applies to workspace crates' features, not to a dependency's backend
  features, so only the selected backend enters the graph.
* The Nettle backend adds `nettle`/`nettle-sys` (`LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`) and the system libnettle (its own licence was not
  checked here).
* rPGP and rpgpie are MIT OR Apache-2.0; every other crate in all three graphs passes the allow list (`licence-summary.txt`). Duplicate versions
  appear (`ed25519-dalek 2.2.0`, `curve25519-dalek 4.1.3` under rPGP versus 3.0.0 in the workspace; `cargo-tree-duplicates.txt`); `deny.toml` only warns.

### 2.3 Sequoia crypto backends (Sequoia's own flags are in `build.rs`; README section "Crypto backends")

| Backend | Sequoia says | Build needs | Observed here |
|---|---|---|---|
| Nettle (default feature) | `production_ready: true`, `constant_time: true` | libnettle + libhogweed (+gmp) found by pkg-config, `bindgen` with libclang, headers incl. `nettle/pgp.h`; Linux x86_64: **UNTESTED** | **Build fails on macOS arm64** with Homebrew nettle 4.0: `bindgen-wrapper.h: fatal error: 'nettle/pgp.h' file not found` in `nettle-sys 2.3.2` (`build-seq-nettle-default-FAILED.txt`). A moving system dependency. |
| OpenSSL (`crypto-openssl`) | `production_ready: true`, `constant_time: true` | OpenSSL 3 headers/libs (`OPENSSL_DIR`), C toolchain; Linux x86_64: **UNTESTED** | Builds (20 s) with `OPENSSL_DIR=$(brew --prefix openssl@3)`; links `libssl.3.dylib`/`libcrypto.3.dylib` (`otool -L`). **Conflicts with `deny.toml`** (`openssl-sys` is banned: "must not link OpenSSL"). |
| RustCrypto (`crypto-rust`) | `production_ready: false`, `constant_time: false`; build fails unless `allow-experimental-crypto` **and** `allow-variable-time-crypto` are set; README: "not recommended for general use" | pure Rust, no C | Builds (21 s), links only libSystem/libiconv, 88/88 pass (`crypto-rust-backend/`). |

Effect on workspace assumptions: `unsafe_code = "forbid"` is a lint on the workspace's own crates and is not affected by any dependency (Sequoia
and RustCrypto contain `unsafe`, e.g. `src/crypto/backend/rust/symmetric.rs:475`). A C backend does bring in a C toolchain/system library,
FFI `unsafe` inside dependencies and non-Rust memory in the process, which the current "pure Rust, rustls, bundled SQLite" dependency story avoids.
**So every Sequoia backend that Sequoia itself calls production-ready contradicts a current repo constraint; the only backend that fits the
constraints is the one Sequoia calls experimental and variable-time.**

### 2.4 rPGP

Pure Rust (RustCrypto and dalek crates), MIT OR Apache-2.0, MSRV 1.88, `bzip2` is an optional default feature (disabled in the spike).
It is "a low-level OpenPGP library": its README says it does not deal with OpenPGP semantics (expiration, revocation, key flags) and "do not claim
that using them is secure". Those come from **rpgpie**, "an experimental wrapping API ... Use with caution!", API unstable, hosted on codeberg,
which was the layer used in the spike (`Checked`, `valid_encryption_capable_component_keys`, `unpack`). rpgpie's `encrypt` does not set an Intended
Recipient and neither rPGP nor rpgpie evaluates one on receive; the spike does both in a few lines of glue. rPGP 0.21.1's `MessageBuilder` cannot
emit a Padding packet (the parser accepts it). The dependency tree includes `rsa 0.9.10` (rPGP's `SECURITY_STATUS.md` lists a known Marvin-attack
issue in that crate; whether it is reachable from the X25519/Ed25519 path was **not tested**), `dsa`, and old algorithms.

### 2.5 Audit coverage (cited, not from memory)

* **Sequoia:** no third-party audit found. Searched `sequoia-pgp.org` (front page, WebFetch) and the web; the only hit was a 2020 LWN remark that the
  code "still needs to be audited". Absence of evidence: **UNVERIFIED** that none exists. The 2.5.0 `NEWS` (copied to `upstream-facts/`)
  lists seven CVE-labelled fixes in this release, among them "Ed25519 identity and other low-order public keys are accepted for signature
  verification", "Argon2 string-to-key parameters are not limited by StandardPolicy" and "Tolerant ASCII armor parsing can select a different block
  than a strict parser". That is active maintenance and also evidence of bugs in exactly the validation paths AgentNet would rely on.
* **rPGP:** `docs/SECURITY_STATUS.md` (copied) lists: Radically Open Security "NLnet Security Evaluation rPGP", report v1.0, December 2024
  (https://github.com/rpgp/docs/blob/main/audits/NGI%20Core%20rPGP%20penetration%20test%20report%202024%201.0.pdf, sha256 in `versions.txt`);
  a 2019 assessment for Delta Chat / Open Tech Fund; and a 2024-03 analysis by ETH researchers. The 2024 report states: reviewed commit
  `3a1bb5cb5ba88370a6966c7f5d4a48e2dd839001` "shortly after the v0.14.0 stable release", retest applies to v0.14.2; scope was a **limited code
  review and fuzzing, 3 days testing, 9 days total effort**, and "non-constant time computation and other side channels are out of scope". The
  version proposed here (0.21.1) is seven minor releases later and was **not** audited. GitHub shows ten advisories
  (https://github.com/rpgp/rpgp/security/advisories), four of them published on 2026-11-11, the day 0.21.1 was released; I read two in full:
  GHSA-c7ph-f7jm-xv4w (SEIPD integrity-protection failure not always reported, versions 0.16.0-alpha.0 up to 0.19.0, fixed in 0.19.0, Moderate) and
  GHSA-h834-358q-rx97 (`Message::verify` accepted any signature type, <= 0.21.0, fixed in 0.21.1, Moderate). The others (RSA PKESK crash, high;
  recursion in embedded signatures; short X25519 PKESK input panic; decompression amplification) I only know by title and date from the list page.
  The tamper scans in G3 ran under `catch_unwind` and no panic occurred on any of the 3,136 mutated inputs per consumer (`g3-tamper-scan.txt`), which is a very small
  sample, not fuzzing.
* **Neither** can be described as audited at the proposed version. Both are young for the v6/SEIPDv2 code path.

### 2.6 Recommendation (judgement, reversible)

Because the wire format is the standard and both implementations interoperate, **the implementation can be changed later without a protocol
change**; that is the main benefit of this route. For the first implementation I recommend **rPGP 0.21.1 + rpgpie 0.12.1** as the shipping
candidate and **Sequoia 2.5.0 as the independent cross-check** in tests/CI (and as a drop-in if the holder accepts LGPL), because:

1. licence and build policy: rPGP/rpgpie fit `deny.toml`, `unsafe_code = "forbid"` hygiene and "no C toolchain" without exceptions; every
   production-grade Sequoia backend needs an exception or a policy change (section 2.2/2.3);
2. both passed the identical 88 checks, so the semantics rpgpie provides (binding, expiry, revocation, key flags) behaved correctly in these cases;
3. a second, unrelated implementation in CI is the strongest practical defence against a single-library validation bug (Sequoia 2.5.0 and rPGP
   0.21.1 both just fixed signature-validation bugs).

Against it: rpgpie is experimental and single-maintainer; Sequoia's semantics layer is more mature (it caught what rPGP could not, e.g. the
Sequoia-side foot-gun below was in *my* use of its low-level iterators, not its verifier), and has an installed base in Debian/Arch packaging. If
the holder accepts the LGPL consequences and an OpenSSL or Nettle dependency (policy change), Sequoia is the stronger semantic implementation. The
holder, not this spike, should make that call.

## 3. G3: interoperability round trip (built and run)

Setup (`spike/openpgp-eval`, `run-all.sh`): two certificates sets, one generated by each implementation: v6, Ed25519 primary with Certify+Sign,
one X25519 encryption subkey, no User ID (a v6 direct-key cert; note `gpg 2.5.24` refuses to import it: "no user ID",
`gnupg-v6-check.txt`; GnuPG 2.5.24 parses the v6 PKESK/SEIPDv2 packets but prints the algorithm as `ietf25`, and decryption there was inconclusive
because the agent socket path was too long (UNTESTED); GnuPG is not needed). Message: one `ESK(v6 anonymous PKESK, X25519), SEIPD v2 (AES-256, OCB,
4 KiB chunks) { One-Pass Signature, Literal Data (JSON payload), Signature v6 with Intended Recipient Fingerprint [, Padding] }`. Payload JSON:
`{v, message_id, sender, recipient, created_at, ttl_s, type, body}` with fingerprints in hex.

| Check | Result |
|---|---|
| X seals, X opens; X seals, Y opens; Y seals, X opens; Y seals, Y opens; each with X-generated and Y-generated certs (8 cases, 16 commands) | all PASS. Y signs with an X-generated secret key and X decrypts, so key and message formats interoperate in both directions. |
| Wrong recipient (Carol cannot open Alice-to-Bob) | rejected by both |
| Surreptitious forwarding: Bob re-encrypts the *same signed inner packets* to Carol | both reject with the Intended Recipient check (crypto-layer only: Sequoia "Not an intended recipient", Y via my glue) |
| **Control**: same forward when the original signature had no Intended Recipient subpacket | **accepted by both at the crypto layer** (attack works); a strict receiver that *requires* the subpacket rejects; JSON `payload.recipient` also stops it. Hence: the subpacket must be mandatory. |
| Signature by a different key (Mallory to Bob, verified against Alice's cert) | rejected by both |
| Mallory signs a payload claiming `sender = Alice` | rejected by both; if opened "as Mallory" the payload `sender` cross-check rejects |
| Encrypted but unsigned message | rejected by both |
| Revoked signing certificate (Alice's cert with a key-revocation signature merged) when Bob verifies an older message | rejected by both |
| Seal to a revoked encryption subkey / revoked certificate / expired subkey / stripped binding signature / foreign subkey grafted under the victim's primary | all refused by both implementations as senders |
| Every single-byte flip (800 and 768 offsets) and every truncation of an X-made and a Y-made message, opened by both | 0 of 3,136 accepted per consumer (1,568 byte flips + 1,568 truncations); no panics |
| Re-run on Sequoia's pure-Rust backend | PASS=88 FAIL=0 (`crypto-rust-backend/g3-summary.txt`) |

Findings worth recording:

* **Sequoia foot-gun, caught by the spike.** The first run had 4 failures (`g3-summary-run1-4-fails.txt`): sealing to a certificate whose *primary*
  was revoked succeeded, because the key-level iterator filter `.revoked(false)` does not see a revocation of the primary key; a cert-level
  `with_policy(...)?.revocation_status()` check is needed (added to the harness; run 2 passes). The verifier path (opening) does catch a revoked
  signer. So with Sequoia the sender side must validate the certificate, not just iterate keys.
* rpgpie's `Checked` handled all the encryption-side cases, including the revoked certificate, without extra code.
* rPGP does not evaluate the Intended Recipient on receive and rpgpie's `encrypt` never sets it; Sequoia evaluates it only if the decrypt helper
  returns the recipient certificate and only if the subpacket is present. Sequoia marks the subpacket non-critical, rPGP (spike code) marked it
  critical; RFC 5.2.3.36 says v6 signatures SHOULD mark it critical.
* Not tested: an expired *signing* key (the identity key was generated without expiry), a signature made before a key's expiry, clock skew
  boundaries, multiple signatures, malformed-but-parseable certificates, compressed messages (compression was compiled out of Sequoia), a
  malicious Notation Data / unknown critical subpacket.

## 4. G4: fit with AgentNet's operating model

**Stateless.** Every `seal`/`open` is a fresh process that reads only certificate files. `RESTART_open_in_fresh_dir` opens a message in a new
directory containing only the secret key file and the sender's cert (both implementations); nothing is per-conversation. The same message
opens twice (`REPLAY_...`): replay protection remains the engine's job, as today.

**Size on the wire** (binary, anonymous recipient, intended recipient set; `g4-sizes-timings.txt`; current numbers computed from the formulas in
`docs/protocol.md`, **not** measured from the code, `g4-size-comparison.txt`):

| body bytes | AgentNet now (power-of-two, computed) | OpenPGP unpadded | OpenPGP pow2 padded | rPGP unpadded |
|---|---|---|---|---|
| 0 | 564 | 700 | 1173 | 668 |
| 100 | 564 | 800 | 1173 | 768 |
| 1024 | 2100 | 1724 | 2197 | 1692 |
| 16384 | 32820 | 17154 | 33032 | 17122 |
| 65536 | 131124 | 66498 | 131720 | 66466 |

Fixed overhead is about 419 B (Sequoia) / 387 B (rPGP) for small messages (anonymous PKESK about 78 B, SEIPDv2 header and tags about 70 B,
OPS + Literal + v6 signature with 32-byte salt, creation time, issuer and intended-recipient fingerprints about 270 B), plus 16 B per 4 KiB AEAD
chunk (64 KiB: 681 B). The v6 signature overhead makes the smallest bucket 1024 B of inner data (the 281-byte empty-body payload plus about 270 B
of packets is already over 512), so tiny messages cost about 600 B more than today with padding on, but a 1 KiB or larger body costs about the same
or less. The largest case, 131,720 B, is under the 153,600 B relay limit; since the maximum body is 64 KiB (JSON-encoded), the padded size never
reaches the limit, so no cap policy is needed (a body that JSON-escapes to more than 64 KiB is already refused today).

**Padding with the standard Padding packet.** Sequoia's `Padder` emits it inside the encryption container after the signature (structure
`(encryption (ops literal signature padding))`, as its docs and RFC 5.14/10.3 describe); the spike's policy hits exact powers of two for the inner
packet sequence. Both implementations **accept** padded messages (`PAD_*_open_[S]`/`[R]`, 20 cases). rPGP 0.21.1 **cannot send** padding
(`MessageBuilder` has no Padding API; the harness refuses `--pad` for it). The padding packet is *not* signed, so a relay cannot strip it without
breaking the AEAD, but the sender-chosen length is only a policy.

**Time per message** (debug build, 20 iterations, Apple M1 Pro; the C-backed Sequoia and the unoptimised pure-Rust code are not comparable;
release-mode numbers were not taken): Sequoia/OpenSSL seal 0.26-0.96 ms, open 0.26-2.2 ms (0 B to 64 KiB, with and without padding); rPGP seal 1.7-37.6 ms,
open 2.4-34.0 ms. Sequoia on its pure-Rust backend in debug: 4.5-211 ms (noisy, host was loaded). All are far below AgentNet's network latencies.

**Certificates** (`g4-sizes-timings.txt`): binary public cert 419 B (Sequoia-made) / 401 B (rPGP-made); armored 732 / 618 chars; secret key
485 B binary. A cert after one rotation (second subkey and new expiry signatures) is 789 B. Everything fits the 4096-byte contact-document limit
many times over; the armored form is about ten lines of text and fits in a QR code by size (**QR round trip UNTESTED**).

**Rotation and revocation as standard certificate updates** (`rotation-cert-info.txt`, ROT*/REV* checks, all PASS on both): `cert rotate` adds a
new X25519 subkey with a 90-day binding expiry and gives the old subkey an expiry at "now"; the owner still opens messages sealed to the old
subkey with the rotated secret (ROT1), senders holding the *stale* cert keep sealing to the old subkey (ROT2: the old one is still valid for them
until they get the update), a sender who **merges** the new public cert into the stored one seals only to the new subkey (ROT3) and the
old-key-only secret cannot open it (ROT5). Subkey revocation and whole-certificate revocation, merged into the stored contact, make both
implementations refuse to seal (REV1, REV2). The contact update is therefore "send the merged public certificate" in a `contact.update` message
body; the receiver must check the primary fingerprint equals the pinned one and use the library's merge (Sequoia `merge_public` was used; rpgpie
has a `merge` module, **not exercised**).

**What identifies an agent.** The v6 fingerprint, 32 bytes (SHA2-256 over the primary key packet, RFC 5.5.4.3). Today's address is `an1` + base32
of (32-byte Ed25519 key + 4-byte checksum) = 61 characters; a fingerprint-based address `an2` + base32(32 + 4 bytes) would be exactly the same shape
and length. Differences: the fingerprint hashes the key packet including its creation time, so it cannot be recomputed from an Ed25519 key alone,
and it cannot verify signatures by itself; the contact certificate (419 B) is needed anyway for the encryption subkey, and the address
pins it (`fingerprint(cert) == address`), which is the same trust structure as today ("the address authenticates the contact record"). The inbox
bucket is `SHA-256(domain || fingerprint)[0..2] mod buckets`: same function, new input. Where `inbox_buckets` lives is the open question in section 1.

## 5. G5: metadata on a shared relay (`g5-packet-dumps.txt`, `g5-linkability.txt`)

For a message with an anonymous recipient, an observer who can read the bytes (as a Logos relay or a peer on the same bucket topic can) sees
only: a v6 PKESK with **no recipient fingerprint** (Sequoia: `recipient=<none>`; rPGP: `fingerprint: None`), the public-key algorithm (X25519),
the 32-byte ephemeral public key and the wrapped session key (random-looking); a SEIPD v2 packet with cipher AES-256, AEAD OCB, chunk size 4 KiB, a
32-byte random salt and the total length. **No key ID or fingerprint of the sender or the recipient appears**; the issuer fingerprint,
intended-recipient fingerprint, signature, signature time and payload (with the sender's address) are all inside the encrypted part. The
control with a named recipient shows the *encryption subkey* fingerprint in the PKESK (`DF6AF6AE...`), which is why anonymous mode is used.
Linkability test: 20 messages Alice to Bob and 20 Alice to Carol, same sender and size: only 13 byte offsets are constant within a group, and
the same 13 offsets with the same values are constant in both groups (packet tags and lengths, v6 PKESK header, SEIPD version/cipher/AEAD/chunk
bytes), so the bytes do not distinguish recipients; padded messages all have the same length (1173 B). Still visible, as today: the content topic
(bucket), timing, the padded length class, the publisher's network identity, and the fact that it is an OpenPGP v6/SEIPDv2/AES-256/OCB message
(a distinguisher against non-OpenPGP traffic, not between agents). The cost of anonymity is trial decryption by every agent on the bucket: one X25519
operation per candidate subkey per frame, the same order as today's HPKE trial decapsulation.

## 6. G6: what remains custom after the switch

| Element | Security-critical? | Note |
|---|---|---|
| Algorithm policy: accept only v6 keys/signatures, X25519 + Ed25519, SEIPDv2 + AEAD (OCB), no SEIPDv1/SED, no compression, no SKESK, no PKESK v3, cap packet sizes | **Yes** (downgrade, DoS) | Configuration of the library's policy object; must be tested negatively (only partly done here: SEIPDv2 required by the spike's `open`). |
| Require the Intended Recipient subpacket naming the receiver's primary key; reject signatures lacking it | **Yes** | Both libraries accept signatures without it (control N2b); in rPGP the whole check is application code. |
| Require exactly one signature, signer cert == pinned sender cert, encrypted-and-signed structure | **Yes** | Spike glue (Sequoia `check`, rpgpie `Verified`). |
| Certificate acceptance: pin by fingerprint, `merge` only (never replace), same primary, size cap, only accept updates that the library validates, track that revocations are never dropped | **Yes** | Replaces the `key_epoch` rules. Rollback at first contact (stale cert without a newer revocation) remains a trust-bootstrap problem, as today. |
| Which subkeys to encrypt to (all valid vs newest), retention of expired subkeys for decryption, when to delete old secret subkeys | **Yes** (confidentiality of in-flight messages vs revocation semantics) | The spike encrypts to all valid subkeys and decrypts with any local secret subkey. |
| **Domain separation of the signed context** | **Yes, and a regression** | Today a signature only verifies as "agentnet/v1/envelope". An OpenPGP data signature has no application context: the same key signing other OpenPGP data (git commit, email, file) could be replayed as an AgentNet message if the bytes parse as the payload. Mitigations to be reviewed: dedicated AgentNet certificate that never signs anything else, strict payload schema with `v`, a critical Notation Data subpacket naming the protocol (UNTESTED). rPGP's GHSA-h834 (signature-type confusion in `Message::verify`) is a live example of this class. |
| Payload JSON schema, size limits, `message_id`, `type`, conversation/correlation ids | No (parsing robustness yes) | Remote content stays untrusted data. |
| Dedupe `(sender, message_id)`, replay and rollback guard, TTL/clock checks | **Yes** | OpenPGP provides none. |
| Address encoding of a fingerprint and checksum | No | Typo protection only. |
| Inbox topic derivation and `inbox_buckets` placement | No (privacy, availability) | |
| Receipts (`ack.received`), delivery state, retries, re-seal | No for confidentiality; yes for the "delivered" claim | Authenticated by the same signature. |
| Contact trust levels, `--expect`, quarantine | **Yes** | OpenPGP defines no trust model. |
| Padding policy (power of two) | No (privacy) | Mechanism is the Padding packet. |
| Identity file / export protection | Yes (secrets at rest) | Today: file mode 0600 and age scrypt. OpenPGP secret-key S2K + AEAD protection exists (UNTESTED). |
| Choice, pinning and update policy of the library; advisory monitoring | **Yes** | Both libraries shipped security fixes in November 2026. |

**Is "no AgentNet-defined cryptographic construction" reachable?** Yes for the cryptography: key agreement, encryption, signature, key binding,
expiry, revocation, hidden recipient and padding are all RFC 9580 constructions in an existing library, and AgentNet would define no KDF, no
signing prefix, no envelope-binding scheme, no key-epoch scheme. **No** for "everything security-relevant comes from the standard": the table
shows about eight security-critical items that remain ours, as *policy and glue* rather than cryptography. The domain-separation row is a real
loss relative to ADR 0002 and must go to the reviewer. The current protocol's custom parts that vanish: HPKE `info`/`aad` construction, envelope
signing domain, signed-envelope binding of suite/epoch, record signing, tombstone signing, discovery-advert signing domain (the optional
`agentnet/v1/capability-advert\0` advert is a separate signing use of the Ed25519 key and would need the same treatment or a separate key).

## 7. Not verified / untested (consolidated)

* Linux x86_64 builds of any backend; Nettle 3.x on macOS; OpenSSL on Linux. `cargo-deny` itself (not installed; licence check is an approximation).
* Release-mode timings; pure-Rust backend timings were taken on a loaded host.
* Signature Expiration Time as TTL, Notation Data for `inbox_buckets` or a protocol tag, secret-key passphrase protection, expired signing key,
  signature-before-expiry semantics, clock skew, compression, rpgpie's `merge`, QR encoding.
* GnuPG decryption (socket path), other implementations (`sqop`, `rsop`, `gosop`, OpenPGP.js, GopenPGP were not installed/tried).
* Whether `rsa`/Marvin or any other unused-algorithm code is reachable from the X25519/Ed25519 path in rPGP.
* Legal reading of LGPL for a statically linked Rust binary (my reading only).
* Absence of a third-party Sequoia audit (searched, not proven).
* Contents of five rPGP advisories beyond their titles.

## 8. Open questions for the repository holder

1. Accept LGPL-2.0-or-later (Sequoia) with its C backend or the "experimental" Rust backend, or take rPGP + rpgpie? (section 2.6)
2. Reuse existing Ed25519 identities as v6 primary keys, or generate fresh keys? (ADR 0004 recommends fresh keys; there are no released peers.)
3. Where do `inbox_buckets` and the protocol-context tag live: constant, notation subpacket, or outside the cert?
4. Are TTL/creation time moved into signature subpackets (library-enforced) or kept in the JSON?
5. Keep suite 1 (HPKE) registered for how long, and is the optional discovery advert re-based on OpenPGP signatures or left as is?
