# libchat audit and established-crypto fallbacks (spike notes)

Author: contributor agent (claim to be verified by lead). Date of work: 2026-11-25.
Host: macOS arm64 (Darwin 25.6.0). Evidence under `results/a1-libchat/`. Upstream clone: `upstream/libchat` (gitignored).
All upstream line citations are against commit `c7c0c1ba50566ecbcbef12958ee9795bdb22db09`.

## 0. Verdict

**libchat: NO-GO as the MVP end-to-end encryption/identity layer today. Revisit later (watch items in section 1.12).**
It is not a "Signal-like 1:1 library". Current main is an OpenMLS-based group stack in which every conversation, including a DM, is an MLS group, and **MLS group state and key-package private keys are held in memory only and are lost on process restart** (evidence in 1.7 and 1.13).

Fallback recommendation (section 2): primary = **HPKE Base mode (`hpke` 0.15.1) + Ed25519 signature inside, recipient/sender/epoch bound ("sign-then-encrypt")** with envelope-layer replay rejection; alternative = **`vodozemac` 0.11.2 (Olm)** where forward secrecy/PCS is wanted.

## 1. Part 1: libchat audit

### 1.1 Provenance and maturity
| Item | Finding | Evidence |
|---|---|---|
| Canonical location | `https://github.com/logos-messaging/libchat` redirects; API reports `nameWithOwner = logos-messaging/logos-chat` (renamed). README title is "logos-chat"; the core crate is still named `libchat` | `results/a1-libchat/gh-repo.json`; `upstream/libchat/README.md:1`, `core/conversations/Cargo.toml` |
| Commit inspected | `c7c0c1ba50566ecbcbef12958ee9795bdb22db09`, 2026-11-25 16:02 +0100, "fix(group-v3): accept a Welcome after being removed from the group (#370)" | `git log` (results/a1-libchat/clone.txt for clone; log output reproduced by `git -C upstream/libchat log -n 1`) |
| Activity | 214 commits total, 45 commits in the 30 days before 2026-11-25, 14 contributors, very high churn (group_v1/v2/v3 all co-exist) | `git rev-list --count HEAD`; `gh api .../contributors` |
| Tags / releases | None. `git tag` empty; `gh release list` empty | commands run in session |
| crates.io | `libchat` and `logos-chat` are **not published** (crates.io API: "crate `libchat` does not exist"). Its git dependency `de-mls` rev `4d85a02` is separate; `de-mls` 4.1.0 is on crates.io, MSRV 1.95 | `curl https://crates.io/api/v1/crates/libchat` |
| License | MIT OR Apache-2.0 | `Cargo.toml` `[workspace.package]`; `LICENSE-MIT`, `LICENSE-APACHE` |
| Stated maturity | "Project_Status Preview" badge; "Status: pre-1.0, and moving. Every crate is 0.1.0, the protocol is not frozen... some breaking changes are expected." | `README.md:5,14-16` |
| Audit | None found: no SECURITY.md, no audit mention in README/docs. `isSecurityPolicyEnabled` not confirmed. Treat as **unaudited** | grep of README/docs; `ls -a` |
| CI | `.github/workflows/ci.yml`: build, test, clippy `-D warnings`, fmt, cargo-deny, nix smoketest on ubuntu+macos; nightly cron. Embedded-delivery crates are excluded from the plain cargo job | `.github/workflows/ci.yml:1-60` |
| Toolchain | `rust_toolchain.toml` says `stable`; de-mls 4.0.0 requires rustc 1.95 | see 1.2 |

### 1.2 Build and tests on macOS arm64
- Host rustc/cargo 1.92.0 (`results/a1-libchat/toolchain.txt`).
- `cargo build --locked` on rustc 1.92 **fails** in 1m35s:
  `error: rustc 1.92.0 is not supported by the following packages: de-mls@4.0.0 requires rustc 1.95`
  (`results/a1-libchat/cargo-build-summary.txt`). Note the resolution step also does a git fetch of `logos-delivery-rust-bindings` and prints "Updating git submodule ... nim-*" lines, because the workspace-level git dep is resolved even for default members (`Cargo.toml` workspace deps; see `cargo-build.txt`).
- I installed a second toolchain in an isolated `RUSTUP_HOME` (scratchpad `rustup-home`), stable = rustc 1.100.0 (2026-11-09). Caveat: `rustup toolchain install` printed "downloading self-update"; it may have updated the host `rustup` binary itself (not checked).
- `cargo build --locked` (rustc 1.100.0): **success**, 2m30s wall (`cargo-build-rust1100.txt`, `-summary.txt`). Only warnings: unused dependency `hkdf` in `core/crypto/Cargo.toml:13`, future-incompat `proc-macro-error2 v2.0.1`.
- `cargo test --locked` (rustc 1.100.0): **all pass**, 2m29s wall; test-result lines are all `ok`, 0 failed (largest suite 116 passed) (`cargo-test-rust1100.txt`).
- Not built: `logos-chat`, `chat-cli`, `embedded-logos-delivery` (need native `liblogosdelivery` via Nix, README "Building"). **UNTESTED**: any real Logos Delivery path.
- Default members (`Cargo.toml` `default-members`) cover core, crypto, generic-chat, sqlite, message-store only.

### 1.3 Architecture and public API
- Layers: `core/conversations` (crate `libchat`, synchronous, no threads), `crates/generic-chat` (`logos-generic-chat`: `ChatClient`, generic over `Transport`, `RegistrationService`, `AuthService`, store), `crates/logos-chat` (opinionated Logos stack) (`README.md` repo map).
- The Rust API is public Rust (rlib), not primarily FFI: `Core` (`core/conversations/src/core.rs:36`), `ChatClientBuilder` (`crates/generic-chat/src/builder.rs`). Not published, so use only by git rev; workspace-internal crates (`crypto`, `components`, `account`) must also be taken by git rev. I verified this works: `spike/libchat-eval/Cargo.toml` depends by exact rev and builds (`results/a1-libchat/spike-build.txt`; 2m32s debug).
- The `ChatClient` runs a background worker thread and a `parking_lot::Mutex<Core>`; events come on a crossbeam channel (`crates/generic-chat/src/client.rs` struct docs, `worker_loop`).

### 1.4 Encryption model as implemented
- Everything is **OpenMLS 0.8.1** (`core/conversations/Cargo.toml`: `openmls = { version = "0.8.1", features = ["libcrux-provider"] }`, `openmls_libcrux_crypto 0.3.1`).
- Ciphersuite: `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (`core/conversations/src/inbox_v2.rs:31-32`): hybrid X-Wing (ML-KEM-768 + X25519) HPKE, ChaCha20-Poly1305, SHA-256, Ed25519 signatures. This is a **post-quantum hybrid** suite, but the X-Wing MLS suite is non-standard/draft (UNVERIFIED: registration status of that ciphersuite id).
- Not X3DH, not Noise, not a standalone double ratchet. Forward secrecy comes from the MLS secret-tree per-message ratchet and epoch updates.
- A "DM" (`DirectV1Convo`) is a 2-member `GroupV1Convo` (`core/conversations/src/conversation/direct_v1.rs:12-34`). Welcome for a new conversation is sent to the invitee's InboxV2 address (`inbox_v2.rs:35-42, 183-193`).
- **de-MLS status**: `GroupV2` (de-mls, with `hashgraph-like-consensus` voting) and `GroupV3` exist. `GroupV2` per ADR 0002 code sample cannot even be reloaded after restart: "de-mls offers no way to resume a conversation from it yet" (`docs/adr/0002-storage-architecture.md`, Decision 3 snippet). Moving fast; `create_group_convo` -> `create_group_convo_v2` (`core.rs:180-185`). Not evaluated beyond reading (UNTESTED).
- Payload wrapper: MLS bytes are wrapped in a protobuf `EncryptedPayload::Plaintext(Plaintext{payload})` -- the variant is *named* Plaintext but carries the MLS PrivateMessage (`group_v1.rs:236-243`). Plaintext leak test below found no marker in wire bytes (T2a).

### 1.5 Identity and authenticated contact bootstrap
- Identity = an *installation* Ed25519 signing key endorsed by an *account* Ed25519 key (`ADR 0003`; `crates/generic-chat/src/installation.rs`). Address = account public key (hex, 32 bytes) (observed in spike: 64 hex chars).
- Installation record stored as `version || 32-byte seed || account` (`installation.rs:~150`, `Installation::encode`), i.e. the **signing seed is stored in the sqlite store**; encrypted only if `StorageConfig::EncryptedWithKey` (SQLCipher) is used (`installation.rs` save doc).
- "Intro bundle" is an **MLS KeyPackage** (`inbox_v2.rs:253-275`, `create_keypackage`) published to a `RegistrationService` registry. Real implementation `ContactRegistry` = **central HTTP "keypackage store"** (default `https://devnet.chat-kc.logos.co`, `crates/logos-chat/src/logos.rs:37`; `extensions/components/src/contact_registry/store.rs`). This is a hosted centralized service, which conflicts with the AGENTS.md no-silent-centralized-broker / private-by-default rules unless self-hosted (server code not in this repo; UNTESTED).
- Authentication of the bundle: the KeyPackage is signed by the installation key; the credential (participant id) is checked via `AuthService::validate_signer` (`service_traits.rs:92-100`). The real `AuthService` (`extensions/components/src/http_auth_client.rs`) queries an account-log service (signed append-only log, `account/account-log`). In tests the only implementation is `AcceptAllAuth` ("Test-only: asserts nothing" `core/integration_tests_core/src/test_ident.rs`). My spike wrote a stricter in-memory `Auth`. **The account-endorsement chain was therefore only simulated**; the real chain was UNTESTED.
- Offline (asynchronous) establishment: designed for it via the registry key package. **One key package per installation, marked last-resort**; the code says one-time key packages and pop/claim semantics are not implemented (`inbox_v2.rs:137-143` TODO, issue #169). Consequence: no one-time prekeys, hence no exhaustion behaviour; a last-resort KP init key is reused for every inviting group (weaker FS for the Welcome).
- Key rotation: no rotation API found for installation/account keys beyond MLS epoch commits; UNVERIFIED for update commits.

### 1.6 FS / PCS claims versus implementation
- Inherited from MLS (epoch commits, secret tree). However ADR/README make no explicit claims; no FS/PCS statement found in docs. Group epochs only advance on commit; in a 2-member DM no periodic update commit was observed in the code I read (UNVERIFIED -- not searched exhaustively).
- Spike: "The requested secret was deleted to preserve forward secrecy." observed for already-consumed message keys (T4).

### 1.7 State persistence (critical)
- Code: `MlsEphemeralPqProvider` is "a Post-Quantum based MLS provider with **in memory storage**" using `openmls_memory_storage::MemoryStorage` (`core/conversations/src/inbox_v2/mls_provider.rs:16-26, 65`), created in `Core::assemble` (`core.rs:108`). `causal_history.rs:25-26`: "State is in-memory and session-scoped, matching the crate's current in-memory MLS state."
- Issue #112 "Expose and Implement MLS Storage" is still **OPEN**: "Libchat uses an in MemoryStore so data is not persisted" (`results/a1-libchat/issue112.json`).
- ADR 0002 (status Accepted) describes a transactional KV store, and `extensions/sqlite` implements `KvStore`, but **nothing in core uses `KvTransaction`/`ScopedKvStore`** (grep: only `kv.rs`, `storage*.rs`, `extensions/sqlite/src/{common,kv}.rs` mention them). The sqlite store persists: the installation (identity seed) and a list of conversation ids/kinds only (`extensions/sqlite/src/lib.rs`, `identity.rs`). `ConversationKind` only has `GroupV1` (`core/conversations/src/storage.rs:93-96`).
- Result: after restart the conversation id is listed but the MLS group is gone (T6). Also the key-package private init key is in the same memory store, so Welcomes created while the recipient was down cannot be accepted after it restarts (T7b).
- Encrypted at rest: SQLCipher (key supplied by the app) for what is stored (`extensions/sqlite/src/common.rs`); key-vault example stores raw seeds **unencrypted** (`extensions/components/src/key_vault/basic_file_key_vault.rs:1-10`).
- Crash safety: ADR 0002 decision 5 says state commits before frames are published, but that applies to the (unwired) KV path; I did not find the same guarantee for MLS state (it is memory only). Backup/restore/export: no API found. Multi-device: designed as multiple installations per account; each installation is its own MLS leaf. Concurrent instances with same identity: no guard found (UNTESTED).

### 1.8 Replay / out-of-order
- OpenMLS secret tree rejects reuse: replay returns error, no second delivery (T4). Out-of-order tolerance fixed at 32 (`mls_groups.rs:66-70, 96-98`: `OUT_OF_ORDER_TOLERANCE = 32`; maximum forward distance left at openmls default). Beyond it: "Generation is too old to be processed" (T5b: 8 of 40 lost when newest delivered first).
- Gap detection via SDS causal history (`causal_history.rs:1-30`) -- detection only, no retransmit.

### 1.9 Transport coupling and metadata
- Core is **transport-agnostic**: `DeliveryService` trait with `publish(AddressedEnvelope{delivery_address, data})`, `subscribe(delivery_address)`, `fetch_messages` (`service_traits.rs:30-52`; `types.rs:10-33`). Caller ships bytes. Works with private relays by implementing `Transport` (proved in-process with my `Hub`).
- Bundled `embedded-logos-delivery` hardcodes preset `"logos.test"` (public test network) in `P2pConfig::default` (`extensions/embedded-logos-delivery/src/lib.rs:59-71`), content topic `/logos-chat/1/{delivery_address}/proto` (`lib.rs:42,53`). Private mode would need a different preset/peer config; UNTESTED (needs native lib).
- Relay-visible metadata (observed in spike T2): `delivery_address` = 12 hex chars derived by blake2b of ids (conversation address) and for invites `blake2b("InboxV2|delivery_address|"+signer_key)` (`inbox_v2.rs:34-37`) -- a **stable per-installation inbox address**, so a relay can link all invites to one recipient and see invite timing; a protobuf `EnvelopeV1.conversation_hint` carries the **conversation id in clear** ("TODO: conversation_id should be obscured", `types.rs:20`; spike T2b: conversation id appears as ASCII in wire bytes). Envelope sizes visible (1747 B for a small message).

### 1.10 Payload model
- Arbitrary bytes in; `send_message(convo_id, &[u8])` (`client.rs:398-409`). Binary 256 B and 1000 B round-trip exactly; empty payload delivered (T1). No machine-readable event types beyond chat events (`event.rs`): `MessageReceived{content: Vec<u8>, sender: AuthenticatedSigner, message_id}`, `MessageAcked`, `MessageMissing`, `InboundError`. Optional `message-types` extension defines chat frames (not examined).
- Size: sizes 16 KiB .. **1 MiB all sent and delivered** in the spike (T1d); commit a74ad35 "pin sds-rs at its 128 KiB content cap" is not enforced in this path (observed; the cap may apply elsewhere/transport). No documented maximum; Waku's own message size cap is UNTESTED.
- Task semantics (ack, correlation, TTL) are not provided; `MessageAcked` is causal-history based and only arrives when the peer speaks next (`causal_history.rs:19-23`).

### 1.11 In-process security tests (spike)
Program: `spike/libchat-eval/` (`Cargo.toml` pins rev c7c0c1ba..., own `[workspace]`; `src/main.rs`). Custom `Hub` Transport (no sockets) records envelopes and lets the test deliver, withhold, tamper, replay and reorder bytes. Commands:
`cd spike/libchat-eval && RUSTUP_HOME=<isolated> cargo run --release --quiet` -> `results/a1-libchat/spike-run-release.txt` (also a debug-profile run: `spike-run-debug.txt`). Release build 4m wall including compile.

| Test | Result (release) | Detail |
|---|---|---|
| T0 contact establishment A->B | PASS | Welcome via registry key package; both sides same convo id |
| T1 binary A->B, B->A, empty | PASS | byte-exact |
| T1d sizes 16 KiB..1 MiB | observed OK | no limit hit |
| T2 plaintext not in wire bytes | PASS | marker absent |
| T2 wrong recipient C | PASS (weak) | C received 0 events and 0 errors: the payload is silently dropped because C holds no group; C is a legitimate account but a non-member. Not tested: a *member* of another group. |
| T2d intended recipient decrypts same bytes | PASS | |
| T3 tampered variants | rejected (0 plaintext) | header byte flip silent; middle flip: `generic: An error occurred during AEAD decryption.`; last byte: `generic: The requested secret was deleted to preserve forward secrecy.`; truncation: `EnvelopeV1.payload: buffer underflow` |
| **T3b original after tamper** | **FAIL** | After one corrupted copy failed AEAD, the genuine message could not be decrypted ("secret was deleted"). One injected corrupted copy permanently kills that message (OpenMLS consumes the per-message key before authentication). Anyone able to inject on the delivery address (relay, other subscriber) can censor individual messages. |
| T4 replay x2 | PASS | rejected with "secret was deleted to preserve forward secrecy"; no duplicate event |
| T5a order 3,1,2 | PASS | all 3 decrypt |
| T5b 40 msgs, newest first | observed | 32 decrypted, oldest 8 lost: "Generation is too old to be processed." (tolerance 32) |
| T6 restart (same sqlcipher db and installation) | **FAIL** | `list_all_conversations` = 1 before and after, but `can_send=false`; message sent after restart silently dropped (received 0, errors []); `send_message` -> `Err("convo with id: mls group not found was not found")` |
| T7a recipient process alive, offline from network, Welcome delivered later | PASS | |
| T7b recipient restarts while sender invites it | **FAIL** | `generic: No matching key package was found in the key store.` Registry still serves the dead KP; sender gets `Ok` from `create_direct_conversation` and no error |

Debug-profile finding: in debug builds a tampered ciphertext **panics the receiver's worker thread** (`openmls-0.8.1/src/framing/private_message_in.rs:136`, `debug_assert!(false, "Ciphertext decryption failed")`), killing all later processing (see `spike-run-debug.txt`, T3b/T4/T5 invalid there). Release builds return an error instead. Upstream sets `panic = "abort"` for release (`Cargo.toml` `[profile.release]`), so a debug build would abort the process on a forged packet. Do not run debug builds with untrusted input.
Not tested: concurrency with real network, wrong-recipient *within another valid group*, A-side restart, impersonation by a registered-but-unendorsed key, long-running ratchet, forged sender (credential mismatch).

### 1.12 Suitability against AgentNet requirements
1. Persistence: MLS state in memory => violates "restart/migration safe" (1.7, T6, T7b). Blocking.
2. Maturity: unpublished, untagged, unaudited, pre-1.0 with breaking changes expected (1.1).
3. Wrong abstraction: group MLS with PQ suite and heavy churn (V1/V2/V3) for what is a 1:1 mailbox; DM = 2-member group (1.4).
4. Centralized key-package registry and account-log HTTP services are the real bootstrap path (1.5); self-hosting protocol undocumented in repo.
5. Message-level DoS via one injected corrupted copy (T3b); plus conversation id in clear and a stable inbox address (1.9).
Watch: closing of issue #112 and wiring of `KvStore` into the MLS provider; one-time key packages (#169); crates.io release.

### 1.13 Items I did not verify
Native Logos Delivery path; real registry/account-log servers; exact MLS cipher-suite registration; update-commit/key-rotation behavior; multi-device; concurrent writers; Nix build.

## 2. Part 2: established fallbacks (desk evaluation plus compile check)

Crate data from crates.io API (2026-11-25; saved responses in scratchpad `cr/`). "Pure Rust" = no C dependency required.

| Option | Version (latest) | License | MSRV | Audit | Pure Rust | Async-offline recipient |
|---|---|---|---|---|---|---|
| `hpke` (rozbb) | 0.15.1 (2026-10-28) | MIT/Apache-2.0 | 1.87 | No paid audit; README: Cloudflare internal review of v0.8 only, "not yet being formally audited" (https://github.com/rozbb/rust-hpke) | yes | yes (one-shot encryption to static recipient key) |
| `vodozemac` | 0.11.2 (2026-11-05) | Apache-2.0 | 1.89 | Least Authority audit, "no significant findings" per README: https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf (date not shown in what I fetched) | yes | yes via Olm one-time/fallback keys |
| `openmls` | 0.9.2 stable (MSRV 1.91), 0.10.0-rc.1 (1.94) | MIT | 1.91+ | No audit link on repo page I fetched (UNVERIFIED whether any exists) | libcrux/rust-crypto providers | needs KeyPackages + external storage you write |
| `snow` | 0.10.0 (2025-07-19) | Apache-2.0 OR MIT | 1.85 | none known (UNVERIFIED) | yes | only one-way N/K/X patterns |
| `crypto_box` | 0.9.1 (2023); 0.10.0-pre.0 (2025-10) | Apache-2.0 OR MIT | 1.60 / 1.85 | none known | yes | yes, but no sender-authenticating protocol beyond static DH |
| `age` | 0.12.1 (2026-07-14) | MIT OR Apache-2.0 | 1.74 | none (UNVERIFIED) | yes | X25519 file encryption; no sender authentication |
| libsignal | upstream not on crates.io as a usable crate (`libsignal-protocol` 0.1.0 is an unrelated 2019 crate) | AGPL-3.0 | -- | extensive academic analysis | Rust core with other deps | AGPL implies network-copyleft obligations for AgentNet; not acceptable without legal sign-off (UNVERIFIED licensing details; not fetched) |

### 2.1 HPKE (RFC 9180) via `hpke` 0.15.1
Modes (README benchmark list; RFC 9180): Base, PSK, Auth, AuthPSK. Suites chosen at compile time; KEMs incl. DHKEM(X25519), P-256, ML-KEM, X-Wing; AEAD AES-GCM/ChaCha20Poly1305; KDF HKDF/SHAKE.
- Auth mode gives sender authentication via the sender's static KEM key, but: (a) **key-compromise impersonation**: whoever has the *recipient's* private key can forge messages "from" any sender to that recipient (RFC 9180 section 9.1.1 security considerations; UNVERIFIED section number, I did not fetch the RFC); (b) forward secrecy only against *ephemeral sender* compromise; **no forward secrecy against recipient long-term key compromise**: all past messages decryptable; (c) no replay protection, no ordering; (d) need static X25519 key bound to identity.
- Standard construction for AgentNet: HPKE **Base** mode, `info` = domain-separation string || sender id || recipient id || protocol version, `aad` = canonical header (message_id, created_at, expires_at, type), plaintext = {sender Ed25519 signature over (domain || recipient contact-id || enc || message_id || ... || payload hash)} || payload. This gives sender authentication that does not suffer KCI (signature key is separate and not held by recipient), bound to the recipient. Deniability is lost (signatures are transferable). Binding Ed25519 signing key and X25519 agreement key requires a **self-signed contact record** (Ed25519 signs the X25519 public key, with domain separation); that is app-level protocol composition of reviewed primitives, not new cryptography, but it must be specified and reviewed.
- Does NOT provide: forward secrecy vs recipient key compromise (unless recipient rotates keys frequently, e.g. signed prekeys/epochs in the contact record), PCS, replay rejection (add message_id dedup + expiry in the envelope; an AgentNet requirement anyway), deniability (if signed), KCI-resistance only if signature is used.
- Persistence: stateless per message, keys only: trivially restart/migration safe. Recipient offline: fine.

### 2.2 `vodozemac` (Olm)
- Account has Curve25519 identity key + Ed25519 signing key, one-time keys and fallback key; `Account::generate_one_time_keys` (src/olm/account/mod.rs:338), `generate_fallback_key` (:372), `mark_keys_as_published` (:398), `create_outbound_session` (:193), `create_inbound_session` (:251); `Account::pickle` (:405), `Session::pickle`/`from_pickle` (session/mod.rs:463,473); pickles can be encrypted with a 32-byte key (`encrypt(self, pickle_key)` session/mod.rs:656 region; check which type). Citations are into `vodozemac-0.11.2` extracted under `~/.cargo/registry/src/*/`.
- Gives: double ratchet FS and PCS per session; asynchronous establishment with one-time keys. The caller must authenticate the bundle (identity key, signing key, signed OTK) -- a signed-bundle format like Matrix's is application-defined; same binding issue as HPKE.
- Limits: one-time keys exhaust -> fallback key (reused; weaker FS for first flight); **state is mutable per message** so crash safety, concurrent instances and backup/restore are the application's problem (pickle must be persisted before releasing ciphertext, one writer only); out-of-order tolerance bounded (skipped keys cap); no built-in replay protection beyond ratchet; deniable (Olm is MAC-based, not signed) but no sender signature on payloads.
- Pulls `hpke 0.14.1` and `ed25519-dalek 3.0.0`, `curve25519-dalek 5.0.0`, `chacha20poly1305 0.11.0` (lockfile in `results/a1-libchat/fallback-probe-Cargo.lock`).

### 2.3 OpenMLS
Audit not found; heavier (group state machine, storage provider you must implement); same persistence burden as libchat's gap; pick only if groups are required. 0.10.0-rc.1 needs rustc 1.94. Not recommended for MVP.

### 2.4 `snow` (Noise)
Noise interactive patterns (XX, IK, NK...) need a live responder handshake, so they do not fit an offline mailbox. One-way patterns N (anonymous sender), K, X (sender static key transmitted/authenticated) fit store-and-forward: X gives sender authentication using DH (KCI-susceptible like HPKE Auth); N gives none. Snow supports one-way patterns (UNVERIFIED: the exact patterns `Noise_X_25519_ChaChaPoly_SHA256` in snow 0.10 not compile-tested). No sessions/ratchet, no audit link found.

### 2.5 `age` / `crypto_box`
`crypto_box` (NaCl box/sealed box) and `age` give recipient-keyed encryption of a blob with no ratchet; `age` has no sender authentication; `crypto_box` authenticates the sender only via static-static DH (KCI-susceptible, deterministic shared key, no FS). Both are strictly weaker/less structured than HPKE for this use; `crypto_box` stable is old (0.9.1, 2023) with 0.10 still pre-release.

### 2.6 Recommendation
- **Primary: HPKE Base (`hpke` 0.15.1, X25519/HKDF-SHA256/ChaCha20-Poly1305) + inner Ed25519 signature (`ed25519-dalek` 3.0.0) over a domain-separated, recipient-bound transcript; contact record = self-signed bundle {ed25519 pubkey, x25519 pubkey, epoch/expiry, version}.** Pros: tiny dependency surface, stateless (restart/migration safe), offline recipient native, replay handled by the envelope layer (message_id dedup table + expires_at). Cons: no forward secrecy against recipient key compromise (mitigate with periodic recipient key rotation published in the contact record; old keys retained for decryption window), no PCS, signatures not deniable, `hpke` has no formal audit (Cloudflare internal review of v0.8 only).
- **Alternative: `vodozemac` 0.11.2 (Olm)** with one-time keys signed by the Ed25519 key, if FS/PCS are required. Pros: audited, ratchet; cons: stateful (must persist pickle atomically before sending, single writer), bundle authentication and replay/ordering layer still to be built, OTK exhaustion handling.
- Both require writing a thin composition layer (contact record, envelope, replay table); the cryptographic primitives are reviewed library calls. A review of the composition by the lead/an external reviewer is recommended before MVP release.

### 2.7 Compile check
Throwaway crate (scratchpad `.../scratchpad/cc/probe`, copy of manifests in `results/a1-libchat/fallback-probe-Cargo.{toml,lock}`, output `fallback-probe-build.txt`): dependencies `hpke = "=0.15.1"`, `vodozemac = "=0.11.2"`, rustc 1.92.0 (host default). Result: **`cargo build` succeeded in 33.5 s**, "Locking 91 packages to latest Rust 1.92.0 compatible versions"; no MSRV problem (hpke 1.87, vodozemac 1.89 <= 1.92). Only compiled, did not exercise functionally (UNTESTED at runtime). `ed25519-dalek` 3.0.0 resolved transitively and compiles; not directly compiled as a direct dependency (it is part of vodozemac's graph).

## 3. Reproduction
- Clone and pin: `git clone https://github.com/logos-messaging/libchat upstream/libchat` at `c7c0c1ba50566ecbcbef12958ee9795bdb22db09`.
- Build needs rustc >= 1.95 (used 1.100.0 via isolated RUSTUP_HOME).
- Spike: `cd spike/libchat-eval && cargo run --release`.
