# ADR 0002 — End-to-end encryption: HPKE base mode with an inner Ed25519 signature

Status: accepted (2026-11-25). Owner: lead agent.

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

* `vodozemac` 0.11.2 (Olm; Apache-2.0; Least Authority audit): gives forward
  secrecy and post-compromise security, at the price of per-message mutable
  ratchet state that must be persisted before ciphertext release and a
  single-writer rule. Kept as the documented upgrade path. Compiles on the host
  (`results/a1-libchat/fallback-probe-build.txt`); never exercised at runtime —
  UNTESTED.
* libchat: revisit when MLS storage (#112) and one-time key packages (#169)
  land and a tagged release exists.
* OpenMLS, Noise (`snow`), `crypto_box`, `age`, libsignal: rejected for the
  reasons in the notes (persistence burden, interactive handshakes, no sender
  authentication, AGPL).
