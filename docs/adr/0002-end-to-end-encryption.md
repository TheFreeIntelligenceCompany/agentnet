# ADR 0002 — End-to-end encryption: HPKE base mode with an inner Ed25519 signature

Status: **accepted by the repository owner on 2026-11-25, with conditions** (see "Owner acceptance and conditions"). Owner of the code: lead agent.

## Context

`goal.md` asks for authenticated, encrypted agent-to-agent messages with an
offline-capable recipient, durable identity that survives restart and
migration, and forbids home-grown cryptography. The brief's first candidate was
Logos Chat's `libchat`.

## Evidence

* libchat at `c7c0c1b` (`docs/spike/notes-libchat-and-crypto.md`,
  `results/a1-libchat/spike-run-release.txt`):
  * MLS state is held in memory only; after a restart a conversation can neither
    send nor receive (test T6 FAIL; upstream issue #112 open).
  * A recipient that restarts while being invited cannot join (T7b FAIL).
  * One injected corrupted ciphertext makes the genuine message undecryptable
    (T3b FAIL).
  * Needs rustc >= 1.95 (host: 1.92), no tags, no releases, not on crates.io,
    README says pre-1.0 with breaking changes expected; no audit found.
  * Key-package bootstrap defaults to a hosted registry and the embedded
    transport hardcodes a public network preset.
* HPKE + Ed25519 construction over the real local relay
  (`docs/spike/notes-e2e-crypto.md`, `results/a2-e2e-crypto/`): round trip
  100/100 each way; wrong recipient, forged sender, surreptitious forwarding,
  every single-bit flip, every truncation, replay, expiry and skew cases
  rejected; identity survives restart and file migration. Lead re-ran roundtrip,
  tamper, forgery and wrong-recipient.
* `hpke 0.15.1` and `ed25519-dalek 3.0.0` build on rustc 1.92 (MSRV 1.87).

## Decision

Use RFC 9180 HPKE, mode Base, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
ChaCha20-Poly1305 via the `hpke` crate (exact pin `=0.15.1`), with the sender's
Ed25519 signature (ed25519-dalek, `verify_strict`) over a domain-separated
envelope that names the recipient, carried inside the ciphertext
(sign-then-encrypt with recipient binding). Signing and agreement keys are
independent; a self-signed contact record binds the agreement key to the signing
key, and the address is the signing key. The construction is specified in
`docs/protocol.md` and implemented in `crates/core/src/envelope.rs`.

HPKE Auth mode was not used: it would tie sender authentication to the
agreement key and is exposed to key-compromise impersonation; a signature gives
a cleaner statement ("the holder of address X wrote this to Y").

## Consequences

Provided: confidentiality to the holder of the recipient agreement key, sender
authentication, recipient binding, integrity, stateless operation (nothing to
lose on restart, safe to migrate), offline recipients. Replay rejection is done
by the engine with a persisted `(sender, message_id)` set bounded by message
expiry.

Not provided, and stated as limitations:

* No forward secrecy against later compromise of the recipient agreement key
  (mitigation: `rotate-kem` with a retention overlap; not automatic).
* No post-compromise security, no deniability (signatures are transferable).
* The `hpke` crate has no public third-party audit (its README mentions an
  internal Cloudflare review of an old version). The composition here has not
  been independently reviewed. **A cryptographic review is required before any
  production use.**
* RFC 9180 section 8.1 notes that applications using only the single-shot API
  should not rely on both `info` and `aad`; we use `info` for the domain and
  recipient key and `aad` for the 4-byte frame header. Flagged for the review.
* No revocation channel; signing-key compromise means a new address.

## Alternatives

* `vodozemac` 0.11.2 (Olm; Apache-2.0) — **evaluated at runtime** after the
  first version of this ADR (`docs/spike/notes-vodozemac.md`,
  `spike/vodozemac-eval/`, `results/a1-vodozemac/`; lead re-ran the spike):
  * It works as documented: offline establishment from a signed key bundle,
    byte-exact payloads up to 100 KiB, replay rejected, out-of-order delivery
    within limits, wrong recipient and tampered copies rejected, and a rejected
    tampered copy does **not** poison the genuine message (the libchat failure).
    Old ciphertexts are not decryptable from a later stolen state (forward
    secrecy), and a passive attacker is locked out after a ratchet round trip.
  * Costs confirmed by experiment: a send after a state rollback reuses the
    same message key (one message lost, key/IV reuse); a receive without
    persisting accepts the replay again; two live copies of one state diverge
    permanently with no fencing. The application must persist before releasing
    ciphertext, commit receives atomically and enforce a single writer.
  * AgentNet has no directory to publish one-time keys to. With contact records
    exchanged out of band, first messages would ride a reusable fallback key,
    which loses forward secrecy for the first flight; two senders using the
    same static bundle collide on a one-time key.
  * The Least Authority audit (final report 30 March 2022) covers revisions
    530 commits behind 0.11.2, excludes the Olm design and dependencies, and
    left the 8-byte MAC truncation unresolved (still present in the v1 session
    config). It also pulls its own `hpke` 0.14.1.
  * Conclusion: "audited" is weaker than it sounds for the version on
    crates.io, and the stateful design trades restart/migration safety — a
    stated requirement — for forward secrecy. Kept as the upgrade path if
    forward secrecy becomes a requirement.
* libchat: revisit when MLS storage (#112) and one-time key packages (#169)
  land and a tagged release exists.
* OpenMLS, Noise (`snow`), `crypto_box`, `age`, libsignal: rejected for the
  reasons in the notes (persistence burden, interactive handshakes, no sender
  authentication, AGPL).

## Owner acceptance and conditions

The repository owner accepted HPKE + Ed25519 for the MVP on 2026-11-25, on the
grounds that asynchronous communication, offline first contact, frequent
restarts, ephemeral execution environments and identity portability are the
primary requirements, and that stateless per-message encryption fits them
better than a stateful ratchet at this stage. The owner explicitly accepted the
absence of forward secrecy against recipient key compromise **for the MVP only**:
it is a documented limitation, not a permanent assumption for every deployment.

Conditions attached to the acceptance (status of each is tracked in
`docs/crypto-requirements.md`):

1. A fresh HPKE context for each message.
2. Separate signing and encryption keys with cryptographically authenticated
   key bindings.
3. All security-relevant envelope metadata authenticated.
4. Protocol versioning and domain separation.
5. Durable replay protection, with tests for rollback, restart, migration and
   concurrent-identity scenarios.
6. Encryption key rotation **and revocation**.
7. No silent cryptographic downgrade.
8. Pinned dependency versions and tests against published cryptographic test
   vectors.
9. A complete threat model and list of remaining limitations.
10. A preserved upgrade path to vodozemac, MLS or another reviewed
    forward-secret protocol.
11. Independent cryptographic review before production use involving sensitive
    information.
12. The cryptographic implementation sits behind a narrow, well-defined
    interface so that replacing or extending the scheme requires no change to
    the Waku transport, the MCP server or the harness integration.
13. The implementation is never described as audited, production-secure or
    forward-secret.
