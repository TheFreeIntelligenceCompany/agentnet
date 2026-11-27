# The cryptographic interface

Owner condition 12 (ADR 0002, kept by ADR 0004): the cryptographic implementation sits
behind a narrow, well-defined interface so that replacing it requires no change to the
Waku transport, the MCP server or the harness integration. ADR 0004 replaced the scheme
behind it by a profile of **RFC 9580 OpenPGP** (`sequoia-openpgp` 2.5.0, OpenSSL 3 backend);
the interface is reshaped where it leaked HPKE concepts (no suites, no key epochs).

The current scheme is **not audited, not production-secure and not forward-secret** (no
forward secrecy against later compromise of a recipient encryption subkey); an independent
cryptographic review is required before any production use involving sensitive information.
**None of the forward-secret machinery in section 4 is implemented.**

## 1. The boundary

Everything that touches `sequoia-openpgp`, `openssl` (through it) or `age` lives in
`crates/core/src/crypto/`. The rest of `agentnet-core` (`ingest`, `send`, `system`, `node`,
`api_impl`, `store`, `guard`, `migrate`), `agentnet-transport`, `agentnet-mcp`, `agentnet-daemon`
and `agentnet-cli` reference only the types below. Enforced by `crates/core/tests/architecture.rs`:

* no source file outside `crates/core/src/crypto/` (and the published-vector test
  `crates/core/tests/vectors.rs`) mentions `sequoia_openpgp::`, `openssl::`, `openssl_sys::` or `age::`;
* the manifests of `transport`, `mcp`, `daemon` and `cli` do not list those crates;
* the engine files do not call the free `protection::seal`/`open` wrappers or name
  `OpenPgpProtection`; they go through the trait.

Public surface of `agentnet_core::crypto`:

| Item | Role |
|---|---|
| `Address` | `an2` + base32(v6 fingerprint, checksum); inbox topic from the fingerprint |
| `Identity` | one v6 certificate with its secrets: `generate`, `load`, `save`, `export_encrypted`, `import_encrypted`, `rotate_kem` / `rotate_kem_with(.., revoke_previous)`, `prune_retired`, `create_revocation`, `contact_record` |
| `ContactRecord`, `VerifiedContact` | the public certificate and its parser: sanitize, validity, `merge` (merge only, never replace), `revocation`, `is_kem_expired` |
| `SignedRevocation`, `VerifiedRevocation` | a primary-key revocation, distributed as the revoked certificate |
| `Envelope` (+ `OpenLimits`, `OpenedEnvelope`, `SenderAuth`) | the application payload and the open result (`Pinned` or `EmbeddedCertificate`) |
| `trait MessageProtection` | `seal(sender, recipient, envelope, now_ms, max_frame_len)`, `open(recipient, frame, now_ms, limits, senders: &dyn SenderDirectory)`, `max_body_len(..)` |
| `SenderDirectory` | looks up the pinned certificate of a sender (the engine's contact store); `NoSenders` is the empty one |
| `OpenPgpProtection` | the implementation (policy of `docs/protocol.md` section 5) |
| `SignedAdvert`, `VerifiedAdvert` | discovery adverts: OpenPGP signed (not encrypted) messages |

`Node::open` uses `default_protection()`; `Node::open_with(.., NodeOptions { protection: Some(arc), .. })`
injects another `Arc<dyn MessageProtection>`. The engine never looks inside a frame.

## 2. What a replacement scheme must provide

An implementation of `MessageProtection` MUST:

1. **Authenticate the sender**: an envelope returned by `open` was created by the holder of the key
   behind `envelope.sender`; for an unknown sender the proof is self-certification only, and the
   result says so (`SenderAuth`).
2. **Bind the recipient** and protect every `Envelope` field; refuse recipients that are revoked,
   expired or without a usable encryption key, **checking the certificate, not only the keys**.
3. **Never downgrade silently**: accept only the policy it documents, with a distinct error per violation.
4. **Use fresh key material per message** (stateless scheme).
5. **Be a pure function of its inputs for replay purposes**: no duplicate detection (the engine persists
   `(sender, message_id)`), `NotForUs` when no local key opens the frame, no plaintext, keys or
   attacker-controlled strings in errors.
6. **Honour `max_frame_len`** and report `TooLarge` with a body-size hint.
7. **Tests**: published vectors, tamper/truncation/forgery/wrong-recipient tests, the policy rejections,
   and an architecture-test entry for any new cryptographic crate.

## 3. What this interface does not abstract (honest limits)

* `Identity` and `VerifiedContact` are OpenPGP certificates; a scheme with another key shape (an MLS
  credential, a vodozemac account) needs them extended inside `crypto/` plus a new identity-file version.
* `MessageProtection::seal` is synchronous with no handle to a database transaction; a scheme with
  per-peer mutable state needs section 4.
* The engine stores one sealed `frame` per outbox row and re-seals rows when a recipient's certificate
  changes (section 9.4 of `docs/protocol.md`); a stateful scheme cannot re-seal.
* `crypto::pgp` is the only module that talks to Sequoia; swapping the library for another OpenPGP
  implementation (the wire format is the standard) is a change inside `crypto/pgp.rs`.

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
7. **Another set of crypto crates in the lock file** (vodozemac pulls its own `hpke`); the pinning/deny policy and the architecture
   test would need to cover it.
8. **Tests and review**: port T1-T9 of the spike as engine tests, add
   crash-injection at every persistence point, a two-instance guard test and a
   cryptographic review of the composition (notes section 6). Honest statement: the
   current stateless design was chosen precisely to avoid this per-peer mutable
   state, at the price of no forward secrecy (ADR 0002, owner acceptance).

Until those are done the project must not claim forward secrecy, and the
only preparation is the `MessageProtection` seam. ADR 0004 removed the suite registry and
the frame-header suite id: a second scheme would need a new dispatch (an OpenPGP message
starts with a packet tag byte, so a new frame magic can coexist).
