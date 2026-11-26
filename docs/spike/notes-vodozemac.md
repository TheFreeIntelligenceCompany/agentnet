# vodozemac (Olm) runtime evaluation (spike notes)

Date: 2026-11-25. Spike crate: `spike/vodozemac-eval/` (standalone, empty `[workspace]`, committed `Cargo.lock`).
Output: `results/a1-vodozemac/` (`run-release.txt` = human log, `results.json` = machine results, plus `cargo-tree*.txt`,
`cold-build.txt`, `clippy.txt`, `fmt-check.txt`, `audit-facts.txt`). Re-run: `cd spike/vodozemac-eval && cargo run --release --locked`.
Replaces the "UNTESTED" status of vodozemac in ADR 0002 and in `notes-libchat-and-crypto.md` section 2.2 (that section was a desk
evaluation plus compile check; this is the runtime evidence). Nothing here changes `crates/`; the decision is the lead's.

## 0. Summary

* `vodozemac = "=0.11.2"` is still the newest release on crates.io (checked 2026-11-25; 0.11.2 published 2026-11-05, 0.11.1
  2026-09-30, 0.11.0 2026-09-11). Host: rustc 1.92.0, macOS arm64. Everything runs in-process, no network.
* The cryptographic behaviour is as advertised: offline establishment works, tampering and wrong recipients are rejected, a rejected
  tampered copy does **not** poison the genuine message (the libchat T3b failure mode does not occur), forward secrecy and
  post-compromise security are demonstrable.
* The hazards are all in **state handling**, and the library gives no protection against them: rolling back a pickle reuses message
  keys and silently loses a message (send side) or re-accepts a replay (receive side); two live copies of one state split-brain
  permanently; a static contact-record bundle cannot make one-time keys single-use.
* Verdict convention used below (also in `results.json`): PASS = property held / behaviour safe; FAIL = property did not hold or a
  hazard was confirmed that an application must compensate for (it does not mean the library malfunctioned); NOT EXPRESSIBLE =
  cannot be exercised through the public API.

## 1. Construction as exercised (exact API calls, vodozemac 0.11.2, `SessionConfig::version_1()`)

| Step | Calls |
|---|---|
| Identity | `Account::new()`; `identity_keys()` -> `IdentityKeys { curve25519, ed25519 }` |
| Publish | `generate_one_time_keys(n)`, `generate_fallback_key()`, `one_time_keys()` / `fallback_key()` (UNPUBLISHED keys only), sign each with `Account::sign(msg)`, then `mark_keys_as_published()` |
| Bundle (ours, not the library's) | JSON `{v, ed25519, curve25519, identity_sig, otks:[{key,sig}], fallback:{key,sig}}`; `identity_sig = sign("agentnet-olm-eval/v1/identity\0" \|\| ed25519 \|\| curve25519)`, each key signed over `label \|\| 0 \|\| identity curve25519 \|\| key`; verified with `Ed25519PublicKey::verify` (it is `verify_strict`) |
| Sender | `Account::create_outbound_session(SessionConfig::version_1(), their_identity_curve25519, their_otk_or_fallback)`; `Session::encrypt(&[u8])` -> `OlmMessage::{PreKey, Normal}`; wire form `OlmMessage::to_parts()` / `from_parts(type, bytes)` |
| Receiver | `Account::create_inbound_session(cfg, their_identity_key, &PreKeyMessage)` -> `InboundCreationResult { session, plaintext }` (OTK removed only after the inner message decrypted); then `Session::decrypt(&OlmMessage)` |
| Persistence | `Account::pickle().encrypt(&[u8; 32])` / `AccountPickle::from_encrypted(&str, &key)` / `Account::from_pickle`; same for `Session::pickle()` / `SessionPickle` |
| Identification | `PreKeyMessage::identity_key()`, `session_id()`, `Session::session_keys()` |

Olm messages are a type tag (0 pre-key, 1 normal) plus protobuf bytes; in `version_1` the HMAC-SHA256 tag is truncated to 8 bytes.

## 2. Tests (evidence: `results/a1-vodozemac/run-release.txt`, `results.json`)

| # | Overall | Result detail |
|---|---|---|
| 1 | FAIL (1 limitation) | PASS: bundle built and verified (4 OTKs + fallback + identity self-signature, 991 B JSON); substituted OTK rejected; substituted Curve25519 identity key rejected; an attacker's own self-consistent bundle verifies on its own and is rejected only because the address pin (expected Ed25519 key) does not match. FAIL: after `mark_keys_as_published()` the Account no longer lists the public keys it published (`one_time_keys()`/`fallback_key()` return unpublished ones only; `stored_one_time_key_count()` returns a count), so the application must keep its own copy of published public keys. |
| 2 | PASS | B published a bundle, was pickled and dropped; A built an outbound session from the verified bundle and sent 3 pre-key messages (0 B, 1 KiB, 100 KiB random binary); B restored from the encrypted pickle, `create_inbound_session` from the first message, decrypted all three byte-exact (session ids equal); B replied with the same three sizes, A decrypted byte-exact; A's next message is a normal message (type 1). |
| 3 | FAIL (hazards) | 2 OTKs + fallback, 4 senders (claiming each OTK once): senders 0,1 use the OTKs, senders 2,3 use the fallback key; all four establish (`stored_one_time_key_count` 2 -> 0). Forward secrecy lost: a captured first-flight pre-key message sent to an OTK **cannot** be re-established from a later copy of B's account (`MissingOneTimeKey`), but one sent to the fallback key **can** (the fallback private key stays in the account, current + previous, and is not removed on use); a replayed fallback pre-key message also creates a second session. Static bundle without claiming (what a contact record is): two senders choosing the same OTK both build sessions, the second is rejected by B with `The pre-key message contained an unknown one-time key: <key>` (`MissingOneTimeKey`), and the sender gets no signal. Without a fallback there is no sender-side "out of keys" error at all (the sender just needs a key from somewhere). Fallback rotation: the account keeps current + previous only: a flight to the fallback key from before 1 rotation is accepted, from before 2 rotations is rejected with the same `MissingOneTimeKey`. Limits: `max_number_of_one_time_keys()` = 50; internal store 5000 (oldest silently dropped, reported in `OneTimeKeyGenerationResult::removed`). |
| 4 | FAIL (hazards confirmed) | PASS: encrypted pickles (account A 608 chars, session ~1.5-2.9 k chars) restored after dropping every object; the conversation continued in both directions plus another ratchet turn; wrong key or a corrupted body is rejected (`The pickle couldn't be decrypted: The MAC of the ciphertext didn't pass validation`). **Send-side crash** (encrypt, release ciphertext, do not persist, reload old pickle, encrypt again): the second ciphertext has the **same ratchet key and same chain index** (`chain_index=1` both) and shares a 32-byte identical ciphertext prefix when the plaintexts share a prefix, i.e. the same AES key and IV encrypted two different plaintexts; a peer that already accepted C1 rejects C2 with `The message key with the given key can't be created, message index: 1 [MissingMessageKey(1)]`; the session is not desynchronised (the next message at index 2 is accepted), exactly one message is lost; if C2 happens to arrive first the peer accepts C2 and rejects C1, so which authentic message is delivered depends on arrival order. Persist-before-release (encrypt, persist, release, crash, reload) works: the next message uses a fresh key and is accepted. **Receive-side crash** (decrypt, do not persist, reload the old pickle, receive the same message again): the replay is **accepted again**; with the state persisted it is rejected (`MissingMessageKey`). Converse hazard (not run separately, follows from the persisted case): state persisted but plaintext not stored => redelivery is rejected and the content is lost. |
| 5 | PASS | Same ciphertext twice: second rejected with `MissingMessageKey(0)`, with and without a pickle round trip between; first pre-key message redelivered to the existing session: `MissingMessageKey(0)`; as a new inbound session: `MissingOneTimeKey` (OTK consumed). Out of order 5,3,4,1,2 within a chain: all decrypt. 2500 messages in one chain: (i) #1..#2499 in order then #0 last: #0 **decrypts** (only one key was ever skipped, so it was kept); (ii) #2499 first: `The message gap was too big, got 2499, max allowed 2000 [TooBigMessageGap(2499, 2000)]`, state untouched (#0 still decrypts); (iii) #2000 first (gap 2000) accepted, then #0 and #1959 fail with `MissingMessageKey`, #1960 and #1999 decrypt (only the last 40 skipped keys are kept per chain); (iv) #2001 first: `TooBigMessageGap(2001, 2000)`; reorder window exactly 40 (#40 first then #0 works; #41 first evicts #0, #1 works). Across ratchet turns: a message delayed while the peers complete k round trips decrypts for k <= 5 and fails for k >= 6 with `Failed decrypting Olm message, invalid MAC` (the receiver keeps 5 receiving chains; the failure is a MAC error, not a "missing key" error). Constants (source): `MAX_MESSAGE_GAP = 2000`, `MAX_MESSAGE_KEYS = 40`, `MAX_RECEIVING_CHAINS = 5`, not configurable. |
| 6 | FAIL (1 property) | PASS: a pre-key message for B offered to C: `MissingOneTimeKey`; a normal message for B offered to C's unrelated session: `invalid MAC`. Normal message (95 B), all 760 single-bit flips: 43 `DecodeError`, 714 `InvalidMAC`, **3 accepted with the identical plaintext** (byte offset 35, a protobuf field-tag byte); pre-key message (184 B), all 1472 flips: 115 `DecodeError`, 1096 `Decryption(InvalidMAC)`, 255 `MissingOneTimeKey`, **6 accepted with identical plaintext** (offsets 34, 68, 102, 140). No flip produced a different plaintext. So the wire encoding is malleable (the MAC covers the re-encoded protobuf fields, not the received bytes): a relay can mint different byte strings for one message; delivered first, the variant decrypts correctly and the genuine bytes are then rejected as a replay. Consequence: never dedupe on a ciphertext hash; the content cannot be changed. **libchat failure mode**: all 757 rejected tampered copies, all truncations and a +8 byte extension fed to the same live `Session` object, then the genuine message: **decrypts**. Same for pre-key: 1351 rejected tampered pre-key messages fed to one live `Account`, then the genuine one establishes (OTK not burned; this is audit Issue G, resolved). |
| 7 | PASS (1 not expressible) | The recipient learns exactly one thing about the sender from a pre-key message: its Curve25519 identity key (`PreKeyMessage::identity_key()`, stored in `Session::session_keys()`); no Ed25519 key, address or signature; a normal message carries nothing about the sender (the receiver finds the session by trial decryption). M's pre-key message with the identity-key field rewritten to A's key: `The message that was used to establish the Session couldn't be decrypted [Decryption(InvalidMAC)]` (the 3DH secret includes DH(sender identity secret, OTK)); the failed attempt did not burn the OTK. Application step demonstrated: the sender puts its signed bundle in the first flight and the receiver checks `bundle.curve25519 == pre_key.identity_key()` and `bundle.ed25519 == address`; M replaying A's genuine bundle inside her own session is caught by that comparison only (the library alone would accept M's session as a valid session with M). NOT EXPRESSIBLE: key-compromise impersonation (forging "A -> B" with B's secrets): needs the 3DH secret computed from B's secrets and A's public key, which the public API does not offer; by design Olm authentication is DH-based and deniable, so it is not KCI-resistant and offers no transferable proof of authorship. |
| 8 | FAIL (1 hazard) | Captured ciphertexts (3 messages decrypted by B, B replied, A sent a fourth): a fresh unpickle of B's **later** state cannot decrypt any of them (`MissingMessageKey(0..2)`), nor B's own reply (`invalid MAC`); the original pre-key message cannot re-establish from the later account (`MissingOneTimeKey`; contrast T3 for the fallback key). Hazard: a message that had been **skipped** (not yet delivered) when the state was stolen **is** decryptable from it (up to 40 per chain, 5 chains). PCS: attacker with a stolen state mirroring the traffic passively decrypts round 1, and is locked out from round 2 on (the first full round trip in which B generates a fresh ratchet key after the theft). Contrast: with HPKE base mode (ADR 0002) a later compromise of the recipient KEM key (or a retained previous key) decrypts every recorded frame sealed to it. |
| 9 | FAIL (hazards confirmed) | Same state loaded in two instances. (a) Both send from the same chain position: same ratchet key and index; the peer accepts the first arrival (`OK`), rejects the other with `MissingMessageKey(1)`; two plaintexts used one message key. (b) Both decrypt the same incoming message (no uniqueness, so the application sees it twice). Each then performs its own DH ratchet step with a fresh random ratchet key; the peer follows whichever reply arrives first (its root key advances), the other instance's reply fails with `invalid MAC`; the peer's next message is readable by **one** instance only (`OK` vs `invalid MAC`); the loser did not recover over 3 further rounds while the peer follows the other instance. (c) Two copies of the same Account both accept the same pre-key message and consume their own copy of the OTK (two independent sessions with the same session id). No fencing, epoch or owner marker exists in the pickle. Safe migration = quiesce, final persist, copy, start the new instance, never run both; restoring a backup behaves like the T4 rollbacks. |
| 10 | PASS (measured) | See section 3. |

## 3. Costs (release build, this host; `results.json` has the raw numbers)

| Item | Value |
|---|---|
| Normal message overhead | 59-65 B over plaintext (63 B for an empty plaintext; AES-CBC pads to 16 B); e.g. 100 B -> 159 B, 1 KiB -> 1088 B, 100 KiB -> 102465 B |
| Pre-key message overhead | 165-172 B (168 B for empty; 100 B -> 265 B, 1 KiB -> 1194 B, 100 KiB -> 102572 B) |
| Comparison | current frame = 52 B + padding to >= 512 B plaintext (smallest frame 564 B, `docs/protocol.md` section 4); Olm does no length hiding beyond 16 B blocks, so padding would still have to be added by the application |
| Pickle sizes (encrypted, base64 chars) | account: 587 fresh, 1419 with 2 OTKs + fallback, 16907 with 50 OTKs + fallback; session: ~1.6 k (A) / 1.9 k (B) established, 9.2 k with 40 skipped keys |
| Bundle JSON | 991 B for 4 OTKs + fallback (about 170 B per signed key); a 4096 B contact document would hold roughly 20 OTKs and nothing else |
| Encrypt (10 000 iterations) | 14.3 us (100 B), 16.2 us (1 KiB) |
| Decrypt (10 000 iterations) | 1.9 us (100 B), 2.7 us (1 KiB); encrypt being ~7x slower than decrypt was not investigated |
| Ping-pong (every message a DH ratchet step) | 90 us per message |
| Session creation (1000 iterations) | outbound 122 us, inbound 110 us (including the first decrypt) |
| Failed trial decrypt on a non-matching session | 37.6 us (a DH step, then MAC failure); a receiver with N peers pays up to N of these per normal message because the message names no sender |
| Dependencies | `cargo tree -p vodozemac -e normal`: 73 crates besides vodozemac (74 crate versions); `Cargo.lock` has 80 packages for the spike (adds serde/serde_json). `results/a1-vodozemac/cargo-tree.txt` |
| Second `hpke`? | **Yes**: vodozemac depends on `hpke 0.14.1` unconditionally (its own `ecies`/`pk_encryption`/`hpke` modules), while ADR 0002 pins `hpke =0.15.1`. Both would be in one lockfile; `cargo tree -d` also shows `syn` 2 and 3. It also brings `ed25519-dalek 3.0.0`, `curve25519-dalek 5.0.0`, `chacha20poly1305 0.11.0`, `aes 0.9.4`, `cbc`, `matrix-pickle`, `prost`. |
| Cold build | 31.9 s wall (release, `--locked`, fresh target dir; `cold-build.txt`) |
| MSRV | declared `rust-version = "1.89"` in vodozemac's manifest; built here with 1.92.0; **not** verified with a 1.89 toolchain (not installed) |

## 4. Audit facts (verified by fetching the report; details in `results/a1-vodozemac/audit-facts.txt`)

* Link from vodozemac 0.11.2's README: `https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf`.
  Retrieved (HTTP 200, 274277 bytes, sha256 `6d4bb516...cacba98`). Title: "vodozemac Security Audit Report - Matrix"
  (PDF metadata: `220330_Matrix_Vodozemac_Final Audit Report`), **Final Audit Report 30 March 2022**, Least Authority TFA GmbH, 22 pages.
* Audited revisions: initial `7c11a501bc316a0bf92a5fe06fee8582aad24897`, verification `57d8d87a747653d6d7b7a53acb9a8d8f8de48285`
  (committed 2022-03-02). The GitHub compare API shows tag 0.11.2 **530 commits ahead** of the verification revision. The report
  covers the code as of 2022, not 0.11.2.
* Out of scope per the report: bindings, dependencies/third-party code, higher-level applications, and the cryptographic design of
  Olm/Megolm (presumed sound; separate analysis recommended).
* Findings: Issues A-J and Suggestions 1-8. Resolved at verification: A-H and Suggestions 1-7. Unresolved: Issue I (keys in memory
  not protected against swap/side channels), **Issue J (HMAC tag truncated to 8 bytes; inherited from libolm)**, Suggestion 8
  (configurable skipped-key limits). Issue G (invalid inbound session could burn a one-time key) is the one T6/T7 exercised; it holds
  in 0.11.2. Issue J is still present: `SessionConfig::version_1()` is the only non-experimental config in 0.11.2 (the full-MAC
  `version_2` is behind the `experimental-session-config` feature), and the spike runs v1.
* The README says "one security audit by Least Authority, with no significant findings". The report itself has no severity ratings
  and does not use that phrase; I only verified the list above.
* Not verified: any audit covering the `hpke`/`ecies`/`pk_encryption` modules or the changes since 2022 (none found; not searched beyond the README and the report).

## 5. Comparison with the current design (HPKE base + inner Ed25519 signature, stateless; ADR 0002, `docs/protocol.md`)

| Aspect | Current (HPKE base + Ed25519) | vodozemac (Olm) as measured |
|---|---|---|
| Forward secrecy | none against recipient KEM-key compromise (rotation limits future exposure; previous keys retained) | yes per ratchet step, except stored skipped keys, and weakened for first flights that used the fallback key (T3, T8) |
| Post-compromise security | none | yes after the next fresh DH round trip (T8: locked out from round 2) |
| Sender authentication | transferable Ed25519 signature, "address X wrote this to Y", KCI-resistant | session-bound, deniable, not KCI-resistant; "holder of Curve25519 key K"; address binding only via an application-signed bundle (T7) |
| Recipient binding | signature covers recipient; HPKE `info` covers KEM key | implicit (only the holder of the OTK/identity secrets can establish) |
| State | none; `open` is a pure function; safe to copy/restore/migrate | mutable per-peer ratchet state changing on every send and receive |
| Persist-before-send rule | n/a | mandatory; violation = lost message + key/IV reuse (T4) |
| Persist-with-receive rule | engine persists `(sender,message_id)` only | ratchet state, plaintext and dedupe id must commit atomically (T4) |
| Multi-writer / migration | trivial | split brain unless a single writer is enforced (T9); backups are rollbacks |
| Key publication | self-signed contact record, static | needs one-time keys and a fallback key; AgentNet has no directory/server to claim OTKs from, so a static contact-record bundle makes OTKs collide (T3) and in practice only the fallback key is usable, which keeps first-flight forward secrecy weak until it is rotated; replenishment = re-issuing the contact record out of band (record is limited to 4096 B) |
| Offline recipient | native | native via OTK/fallback (T2) |
| Replay | engine dedupe + time window | inherent per message key within the window, but a rollback re-accepts (T4); engine dedupe still needed; a duplicated delivery shows up as a decrypt **error**, not as a no-op |
| Ordering window | none needed | 40 skipped keys per chain, gap <= 2000, 5 chains; messages later than that are lost (T5) |
| Unknown sender | topic bucket + trial decryption with the current/retired KEM keys | trial decryption over all sessions, ~38 us per non-matching session, plus pre-key attempts |
| Integrity | every bit flip rejected | every flip rejected or decrypts to the identical plaintext (malleable encoding, T6); 8-byte MAC (audit Issue J) |
| Length hiding | power-of-two buckets | 16 B blocks only; padding would still be needed |
| Audit status | `hpke` crate not audited; composition not reviewed (ADR 0002) | one 2022 audit of an earlier revision (530 commits before 0.11.2), 2 unresolved issues incl. the 8-byte MAC; design of Olm out of that audit's scope |
| Dependencies | `hpke 0.15.1`, `ed25519-dalek` | 73 crates, including a second `hpke` (0.14.1) |
| Deniability | none (signatures) | yes |

## 6. What adopting vodozemac would require in AgentNet

* **Contact record format** (new version): Curve25519 identity key, a signed fallback key (and optionally a few signed OTKs, which
  only help if each is used by at most one sender, which a static record cannot guarantee), a validity/rotation counter, all signed by
  the address key; the identity self-signature as in T1; a plan for rotating the fallback key and re-distributing the record (current
  + previous key only are accepted by the account).
* **Envelope/protocol**: decide whether to keep the inner Ed25519 signature and recipient binding (needed to keep non-repudiation
  and today's KCI argument; adds 64 B); a pre-key flight that carries the sender's signed bundle (T7); padding; versioned frame type;
  `docs/protocol.md` sections 4, 5 and 7 and the "open is a pure function" statement change.
* **Engine state transitions**: per-peer session table (none / pre-key phase until the first reply / established), session-id
  dedupe for replayed pre-key flights, a send path `encrypt -> persist -> release` where the outbox stores the exact ciphertext
  and retries resend the same bytes (re-encrypting on retry would burn keys), a receive path with one atomic commit of
  {session pickle, message, dedupe id} before the ack, classification of decrypt errors (a duplicate looks like `MissingMessageKey`),
  acks as ordinary Olm messages (each ack triggers ratchet steps).
* **Storage**: transactional store for pickles with the 32-byte pickle key kept separately; account pickle with the published
  public-key list the Account does not keep; backup/restore and export/migration procedures that quiesce first; a single-writer lock
  (file lock or lease with epoch) because the library offers no fencing.
* **Tests**: port T1-T9 as engine-level tests, plus crash-injection at every persistence point, a two-instance guard test, a
  bucket-sharing trial-decryption test, pickle format/version migration, and a cryptographic review of the composition (bundle format,
  address binding, retained signature).
* **Dependencies/MSRV**: 73 crates, second `hpke`, MSRV 1.89, `deny.toml`/audit updates (`docs/dependency-audit.md`).

## 7. Recommendation (the decision is the lead's)

Keep HPKE base + Ed25519 for the MVP: the evidence shows vodozemac works as documented and removes the two stated limitations (no
forward secrecy, no post-compromise security), but the price is exactly the per-peer mutable state, persist-before-send/atomic-receive
rule and single-writer discipline that the current stateless design avoids, and in AgentNet's directory-less setting the first
flight would run on a reusable fallback key, so the forward secrecy gained applies from the first ratchet turn rather than from
the first message. Treat vodozemac as the documented upgrade path, to be adopted only if (a) FS/PCS become a requirement, (b) the
engine gets a transactional store with enforced single-writer ownership and crash-injection tests, (c) the weaker first-flight
property of a fallback-key-only contact record and the unresolved 8-byte-MAC audit issue (J) are accepted, and (d) the composition
is reviewed. Re-evaluate against a newer vodozemac if a release makes the full-MAC session config non-experimental.

## 8. Not verified / limits of this spike

* Pickle compatibility across vodozemac versions; behaviour of `experimental-session-config` (v2); `low-level-api`.
* MSRV 1.89 (not installed); timing is single-run wall clock on one machine (encrypt-vs-decrypt asymmetry not investigated).
* Multi-device, group (Megolm), libolm interop, memory zeroization claims (audit Issue I), side channels.
* The converse receive-side hazard (state persisted, plaintext not stored) is argued from the persisted-state rejection, not run as a separate crash experiment.
* KCI forgery (T7) is not exercised.
* "Offline", "crash" and "two processes" are simulated by dropping/duplicating objects and pickles in one process; no real process kill or disk fsync was involved.

## 9. Reproduction

```
cd spike/vodozemac-eval
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo run --release --locked > ../../results/a1-vodozemac/run-release.txt
cargo tree --locked -p vodozemac -e normal --prefix none    # dependency count
```
Random keys differ per run; verdicts and error texts do not (timings vary by machine).
