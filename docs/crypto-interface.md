# The cryptographic interface

Owner condition 12 (ADR 0002): the cryptographic implementation sits behind a
narrow, well-defined interface so that replacing or extending the scheme requires
no change to the Waku transport, the MCP server or the harness integration.

This document describes that boundary as implemented, what a replacement scheme
must provide, and what adopting a stateful forward-secret scheme would
**additionally** require. **None of the forward-secret machinery in section 4 is
implemented.** The current scheme (suite 1, HPKE Base + Ed25519) is **not
audited, not production-secure and not forward-secret**; an independent
cryptographic review is required before any production use involving sensitive
information.

## 1. The boundary

Everything that touches `hpke`, `ed25519-dalek` or `age` lives in
`crates/core/src/crypto/`. The rest of `agentnet-core` (the engine: `ingest`,
`send`, `system`, `node`, `api_impl`, `store`, `guard`), `agentnet-transport`,
`agentnet-mcp`, `agentnet-daemon` and `agentnet-cli` reference only the types
below. This is enforced by `crates/core/tests/architecture.rs`:

* no source file outside `crates/core/src/crypto/` (and the published-vector
  test `crates/core/tests/vectors.rs`) mentions `hpke::`, `ed25519_dalek::` or
  `age::`;
* the manifests of `transport`, `mcp`, `daemon` and `cli` do not list those
  crates (the transport does not even depend on `agentnet-core`);
* `ingest.rs`, `send.rs`, `system.rs`, `node.rs` and `api_impl.rs` do not call the
  free `envelope::seal`/`open` wrappers or name `HpkeBaseEd25519`; they go through
  the trait.

Public surface of `agentnet_core::crypto` (the older paths `agentnet_core::{address,
identity, contact, envelope}` re-export from it):

| Item | Role |
|---|---|
| `Address` | the agent address (the Ed25519 public key plus checksum), inbox topic derivation |
| `Identity` | key management: `generate`, `load`, `save`, `export_encrypted`, `import_encrypted`, `rotate_kem` / `rotate_kem_with(.., revoke_previous)`, `create_revocation`, `contact_record` |
| `SignedContactRecord`, `VerifiedContact` | the signed public record (address, KEM key, `key_epoch`, `revoked_kem_epochs_below`, `suites`, buckets, times) and its verifier |
| `SignedRevocation`, `VerifiedRevocation` | the signed identity tombstone and its verifier |
| `Envelope` (+ `OpenLimits`, `OpenedEnvelope`) | the logical message, including the signed `suite` and `recipient_key_epoch` |
| `trait MessageProtection` | `suite_id()`, `supported_suites()`, `advertised_suites()`, `seal(sender, recipient, envelope, now_ms, max_frame_len) -> Result<Vec<u8>, SealError>`, `open(recipient, frame, now_ms, limits) -> Result<OpenedEnvelope, OpenError>`, `max_body_len(max_frame_len, envelope_without_body)` |
| `HpkeBaseEd25519` | suite id 1: HPKE Base (DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305) + Ed25519 `verify_strict` |
| `SuiteRegistry` | implements `MessageProtection` over several suites: `open` dispatches on the frame's (version, suite) header and refuses suites it does not advertise; `seal` picks the highest suite that both the registry and the recipient's *signed* record list, and returns `NoCommonSuite` instead of falling back |
| `default_protection()` | a registry with suite 1 only |

`Node::open` uses `default_protection()`; `Node::open_with(.., NodeOptions {
protection: Some(arc), .. })` injects another `Arc<dyn MessageProtection>` (or a
`SuiteRegistry`). `Node::open_with` also sets the suites listed in the contact
record the node publishes from `protection.advertised_suites()`. The engine never
looks inside a frame: it hands the bytes to `open` and the bytes from `seal` to
the transport.

## 2. What a replacement or additional scheme must provide

An implementation of `MessageProtection` (one suite, or a registry of several)
MUST:

1. **Authenticate the sender** to the recipient: an envelope returned by `open` was
   created by the holder of the key behind `envelope.sender` (the address is the
   identity; the engine trusts `OpenedEnvelope.sender`).
2. **Bind the recipient**, the suite id and the recipient key epoch (`recipient_key_epoch`)
   into authenticated data, and protect every `Envelope` field (see the field audit
   in `docs/protocol.md` section 4). `seal` sets `envelope.suite` and
   `envelope.recipient_key_epoch`; `open` verifies both against what actually opened
   the frame.
3. **Never downgrade silently**: use a suite only if the recipient's signed
   `VerifiedContact.suites` lists it; refuse suites it does not itself advertise.
4. **Use a fresh context per message** for a stateless scheme (fresh ephemeral key
   per `seal`); no cached or reused AEAD contexts or nonces.
5. **Be a pure function of its inputs for replay purposes**: `open` performs no
   duplicate detection (the engine persists `(sender, message_id)`), may be called
   repeatedly with the same frame, and returns `OpenError::NotForUs` when no local
   key opens the frame (other agents' frames share the bucket). Errors carry no
   plaintext, keys or attacker-controlled strings.
6. **Honour `max_frame_len`** (the transport's limit) and report `TooLarge` with a
   body-size hint; implement `max_body_len` consistently.
7. **Frame header**: start frames with `"AN" || frame_version || suite_id` so the
   registry can dispatch. A new frame layout gets a new frame version.
8. **Key material** stays inside `Identity` (and, for a new scheme, new fields of
   the contact record and identity file); the contact record is the only public
   key-binding artefact and stays self-signed by the address key.
9. **Tests**: published vectors for every primitive, a frozen known-answer test of
   the formats, tamper/truncation/forgery/wrong-recipient tests (see
   `crates/core/tests/crypto.rs`, `vectors.rs`) and an entry in the architecture
   test's allow-list for any new cryptographic crate (all of them live under
   `crates/core/src/crypto/`).

To add a stateless suite: implement the trait under `crypto/`, add its id to the
contact record's `suites`, register it in the `SuiteRegistry` the daemon builds.
Nothing in `ingest`, `send`, `transport`, `mcp` or the daemon's socket/webhook
code changes. A test in `crates/core/tests/crypto.rs` (`mod hardening`) registers a
second, test-only suite in a registry to show the routing, negotiation and
rejection paths; it is not cryptography and no second real suite exists.

## 3. What this interface does not abstract (honest limits)

* `Identity` is one concrete type holding an Ed25519 key and X25519 KEM keys; a
  scheme needing a different key shape (an MLS credential, a vodozemac account)
  needs `Identity` and the contact record extended inside `crypto/`, plus a new
  identity-file version. The engine reads only `address()`, `key_epoch()`,
  `contact_record()`, `inbox_topic()` and `created_at()`.
* The `suites` list and `key_epoch` are fields of the contact record format
  (`crypto/contact.rs`), which the engine also reads (`VerifiedContact`).
* `MessageProtection::seal` is synchronous and takes `&self`, with no handle to a
  database transaction. A scheme with per-peer mutable state needs the changes in
  section 4; today there is no way to pass the transaction in.
* The engine stores one sealed `frame` per outbox row and re-seals rows when a
  recipient's record changes (section 8.2 of `docs/protocol.md`); a stateful scheme
  cannot re-seal (section 4).

## 4. Adopting a stateful forward-secret scheme (vodozemac / MLS): additional requirements

**Status: not implemented.** The following is what the spike
`docs/spike/notes-vodozemac.md` (runtime evaluation of vodozemac 0.11.2, results in
`results/a1-vodozemac/`) found would be needed, in addition to everything above.
The libchat/MLS candidate is covered in `docs/spike/notes-libchat-and-crypto.md`
(state lost on restart, key-package bootstrap needing a server).

1. **Per-peer session state persisted in the same transaction as the row it
   belongs to.** A ratchet advances on every encrypt and decrypt. Sending must be
   `encrypt -> persist (new state + the exact ciphertext in the outbox row) ->
   release`, in one SQLite transaction; receiving must commit
   `{session pickle, plaintext/inbox row, dedupe id, ack row}` atomically before the
   ack is released (notes section 6, tests T4/T6). The `MessageProtection` trait
   would need a transactional handle (`seal(&self, tx, ..)`/`open(&self, tx, ..)`)
   and a way to return updated state to persist. **Not implemented.**
2. **No re-sealing.** A ratchet message key is used once, so the engine's current
   "re-seal pending rows to the recipient's new key" (section 8.2) cannot work;
   pending messages must be encrypted exactly once and retried as the same bytes,
   and a recipient rotation must start a new session. **Not implemented** (and the
   `contact.update` re-seal logic would have to be disabled per suite).
3. **Single-writer fencing.** Two live copies of one session state diverge: the
   same message key is reused or state is overwritten (test T9). Today's data-dir
   `flock` covers one directory only. A forward-secret scheme needs a *fenced*
   single writer for the identity (a lease/epoch stored with the state and checked
   on every commit), a refusal to start from a restored/rolled-back copy (the replay
   guard in `docs/protocol.md` section 10 is only a partial, detective measure), and
   quiescing procedures for backup, migration and `identity export/import` (a
   backup of a ratchet is a rollback: a send after restore reuses a message key).
   **Not implemented.**
4. **One-time-key and fallback-key publication.** Offline first contact needs
   one-time (and fallback) pre-keys from the recipient. AgentNet has no directory
   or server to hand out single-use keys, so a static signed contact record can
   only carry a *fallback* key (reusable, weaker forward secrecy for the first
   flight); real one-time keys need a claim mechanism with single-use semantics
   (notes section 5, key publication; test T3). The contact record would carry the
   identity key, a signed fallback key and a list of one-time keys with replenishment
   through `contact.update`-like messages. **Not implemented.**
5. **Replay and duplicate semantics change**: a duplicated delivery shows up as a
   decrypt *error* (`MissingMessageKey`), not as a clean duplicate; the engine must
   classify errors and keep its own `(sender, message_id)` dedupe (notes T5), and
   decryption failure of one frame must not poison the genuine one (the libchat
   failure, notes T3b).
6. **Out-of-order and loss handling**: skipped-message-key limits, lost-state
   recovery (a lost pickle is a broken conversation, not a restart), bucket-sharing
   trial decryption over many sessions, and pickle format/version migration.
7. **A second `hpke` in the lock file**: vodozemac pulls `hpke 0.14.1` next to the
   pinned `=0.15.1` (notes section 3); the pinning/deny policy and the architecture
   test would need to cover it.
8. **Tests and review**: port T1-T9 of the spike as engine tests, add
   crash-injection at every persistence point, a two-instance guard test and a
   cryptographic review of the composition (notes section 6). Honest statement: the
   current stateless design was chosen precisely to avoid this per-peer mutable
   state, at the price of no forward secrecy (ADR 0002, owner acceptance).

Until those are done the project must not claim forward secrecy, and the
`suite_id` space (1 = HPKE Base + Ed25519) and `suites` list are the only
preparation: they let a new suite coexist with suite 1 without a flag day.
