# ADR 0004: Message protection with RFC 9580 OpenPGP

Status: **Accepted by the repository owner on 2026-11-26**, with the library choice and conditions recorded in "Owner decision" below.
It **supersedes ADR 0002** (`docs/adr/0002-end-to-end-encryption.md`) for message protection. Drafted by a subagent from the spike
(`docs/spike/notes-openpgp.md`); the lead agent owns the code and the open-question decisions below. Authorizing principal: the repository holder.

## Context

The repository holder ruled that ADR 0002's construction (RFC 9180 HPKE base mode, an inner Ed25519 signature, AgentNet's own envelope,
recipient binding, key epochs, signed contact records and frame format) is hand-rolled cryptography at the protocol level, which `goal.md` forbids
("Use an established cryptographic protocol and library ... never use home-grown cryptography"). The primitives were standard; the composition
was ours. ADR 0002's requirements stay: asynchronous delivery, offline first contact, frequent restarts, ephemeral execution environments and
identity portability (hence stateless sends and no per-conversation state), plus separate signing/encryption keys with authenticated binding,
rotation and revocation, no silent downgrade, and an independent cryptographic review before sensitive use (`docs/crypto-requirements.md`).

## Evidence

`docs/spike/notes-openpgp.md` and `results/a2-openpgp/` (local, in-process, disposable keys, debug builds, macOS arm64):

* Two unrelated implementations, Sequoia `sequoia-openpgp 2.5.0` and rPGP `pgp 0.21.1` with `rpgpie 0.12.1`, generated v6 certificates
  (Ed25519 primary, X25519 encryption subkey), produced and consumed signed-and-encrypted messages in both directions (8 cases), and passed the
  published RFC 9580 Appendix A vectors (A.3, A.4, A.7, A.8.5). 88 of 88 checks pass for both, on Sequoia's OpenSSL and pure-Rust backends.
* Refused by both: wrong recipient, surreptitious forwarding (Intended Recipient Fingerprint), tampered or truncated ciphertext (0 of 3,136
  mutations per consumer accepted), signature by another key, unsigned message, revoked signer, and sealing to a revoked, expired, unbound or
  foreign-grafted encryption subkey or a revoked certificate. A forward of a signature without the Intended Recipient subpacket is accepted by
  both at the crypto layer, so the subpacket must be required.
* The message hides both parties: with an anonymous v6 PKESK no key ID or fingerprint is visible; sender, signature and payload are inside the
  encryption (`g5-packet-dumps.txt`).
* Sizes are comparable to the current frame (`g4-size-comparison.txt`); the standard Padding packet pads to a power of two and both
  implementations accept it (rPGP cannot yet send it).
* Neither library is audited at the proposed version; both shipped security fixes in November 2026; Sequoia is LGPL-2.0-or-later and its
  production-grade backends are C libraries (one banned by `deny.toml`); rPGP's semantics layer (rpgpie) is explicitly experimental.

## Decision (proposed)

1. **Message protection is an OpenPGP message as profiled by RFC 9580**: v6 keys and signatures, public-key algorithms Ed25519 (certification and
   signing) and X25519 (encryption subkey), PKESK v6 to an **anonymous recipient** (no recipient fingerprint), SEIPD v2 with AES-256 and OCB, a one-pass
   signed Literal Data packet carrying the application payload, a v6 data signature with the **Intended Recipient Fingerprint** of the recipient's
   primary key, and an optional trailing Padding packet. AgentNet defines **no** cryptographic construction on top: no KDF, no signing prefix, no
   envelope-binding scheme, no key-epoch scheme.
2. **Identity and contact record are the v6 certificate.** The agent's identity is the 32-byte v6 fingerprint of its primary key. A contact is the
   certificate; first contact pins the fingerprint (`--expect`), later updates are certificate merges (new subkeys, expiry, subkey or key
   revocation signatures), never replacements. A new versioned address (`an2` + base32 of fingerprint and 4-byte checksum, 61 characters like
   `an1`) names the certificate.
3. **Receiver policy is fixed and minimal** (the glue that stays ours, to be reviewed): accept only v6, Ed25519/X25519, SEIPD v2 with AEAD, no
   compression, no SKESK, no PKESK v3; require encrypted-and-signed structure, exactly one valid signature, signer equal to the pinned sender
   certificate and an Intended Recipient Fingerprint naming the receiver's primary key; then the existing application checks (payload schema,
   TTL, dedupe, replay guard, trust level).
4. **Domain separation moves out of the signature.** Because an OpenPGP data signature has no application context, the AgentNet identity
   certificate must not be used for any other OpenPGP signing, and the payload carries a strict `v`/schema (a signed notation naming the protocol
   is an open option, UNTESTED).
5. **Implementation is behind the existing `MessageProtection` trait** (`crates/core/src/crypto/`, the only place a
   crypto crate may be imported). As built there is a single scheme: no suite id and no first-byte dispatch; the hard cutover (decision 1 below)
   removed the `AN` frame, and the receiver recognises a frame by parsing the OpenPGP packet grammar (canonical form enforced since the review of 2026-11-27,
   `docs/protocol.md` section 5). The library is a pinned
   exact version. **Which library (rPGP + rpgpie, or Sequoia) is the repository holder's decision**: spike recommendation rPGP + rpgpie as the shipping
   candidate and Sequoia as a CI cross-check, or Sequoia if the LGPL and backend consequences (section 2.2/2.3 of the notes) are accepted. The
   wire format is identical either way.
6. Padding policy: pad the inner packet sequence to a power of two (minimum 1024 B in practice) with a Padding packet; the relay limit
   (153,600 B) is not reached for a 64 KiB body (131,720 B measured, also with a maximal sender certificate).

Not decided here and left open (notes section 8): where `inbox_buckets` and the protocol tag live, whether TTL moves into signature subpackets,
whether to reuse existing Ed25519 identities, the discovery-advert signing, and the `deny.toml` policy for LGPL or OpenSSL.

## Owner decision (2026-11-26)

The owner ruled that the HPKE + Ed25519 scheme of ADR 0002 fails the "no hand-rolled cryptography" requirement at the protocol level, and chose:

* **Sequoia (`sequoia-openpgp` 2.5.0) with the OpenSSL 3 backend is the shipping implementation.** The native dependency and the LGPL packaging
  obligations are accepted. Dependency-policy exceptions are scoped to the crates Sequoia requires, and `docs/licensing.md` states how release
  binaries satisfy the licence.
* **rPGP is kept as the independent interoperability check in CI**, outside the shipped binary.
* **Anonymous recipients and standard OpenPGP padding are preserved.**
* Two regression tests run through AgentNet's normal send and receive paths: refuse to encrypt to a certificate whose **primary key is revoked**
  even when a subkey looks usable; reject a message whose signature **lacks the Intended Recipient Fingerprint**.
* The locked build is verified on macOS arm64, Linux arm64 and Linux x86_64; the workspace and private-relay acceptance tests are run and recorded.
* Authorized: implementation and local testing. **Publication, deployment and spending need separate approval.** The independent cryptographic
  review remains required before production use with sensitive information.

## Lead decisions on the questions the draft left open

1. **One suite, hard cutover.** No peers have been released, so the HPKE suite is removed, not kept alongside: the `hpke` and `ed25519-dalek`
   dependencies and the suite-1 code leave the tree. This replaces items 3 and 5 of the migration outline below (no dual-suite period).
2. **Migration is explicit** (`agentnet identity migrate`): it generates a fresh v6 certificate, keeps the inbox history and dedupe state, lists every
   pending old-format outbox message and marks it failed with a reason that says to re-send, keeps old contacts as *unverified legacy entries*
   that cannot be sent to until the contact's new certificate is added with `--expect`, and prints the new address. Nothing is converted silently;
   an old data directory is refused by `serve` with a message naming the command.
3. **Fresh keys.** An existing Ed25519 identity key is never reused in the certificate.
4. **Application fields stay in the signed, encrypted payload:** protocol version (`agentnet`: 2), message id, type, sender and recipient
   fingerprints (cross-checked against the signature and the Intended Recipient Fingerprint), created-at, TTL, conversation id, body. TTL is not
   moved into signature subpackets. No notation data is used; the identity certificate is used for nothing but AgentNet.
5. **Inbox topic.** The bucket is taken from the leading byte(s) of the v6 fingerprint (which is already a SHA-256 output); no extra hash or
   domain string.
6. **Contact record = the certificate** (binary, base64 for transport; at most 8192 B since the review of 2026-11-27, `docs/protocol.md` section 3), with local-only alias and trust level. Updates are merges.
   Rotation is a new encryption subkey with expiry; revocation is a standard subkey or key revocation signature; a revoked identity is distributed
   as the merged certificate.
7. **Discovery adverts** are OpenPGP signed messages made by the identity certificate (signed, not encrypted), with the topic inside the signed
   content; no AgentNet-defined signature construction remains.
8. **Identity export** keeps the `age` passphrase file around the secret key material (an existing tool, not a construction of ours).
9. **Dependency policy:** `deny.toml` gets licence exceptions for exactly the LGPL crates Sequoia requires and lifts the `openssl-sys` ban only for
   the crates that need it (wrappers); everything else stays as it is.

## Consequences

Provided (from the standard and an existing library): confidentiality to the holders of the recipient's encryption subkeys; sender authentication
inside the encryption; recipient binding by the Intended Recipient Fingerprint; key binding by subkey binding signatures; expiry; subkey and key
revocation, including pre-generated revocation signatures; hidden recipient; standard padding; stateless sending, offline first contact and
restart-safe operation (nothing but certificates, shown by the RESTART test); an implementation that can be swapped without changing the wire
format, and a second implementation available as a cross-check.

Changed or lost relative to ADR 0002:

* **No forward secrecy against later compromise of a recipient encryption subkey: unchanged limitation, same accepted risk.** Rotation limits future exposure only;
  old subkeys retained for decryption stay exposed. No post-compromise security. No deniability (signatures are transferable). The implementation
  is **not** described as audited, production-secure or forward-secret.
* The domain-separated signature (`agentnet/v1/envelope\0`) is gone; see decision 4. This is a reduction in defence in depth that the reviewer
  must evaluate.
* `key_epoch` ordering and "conflicting record" rules disappear; revocations accumulate on merge, but first contact with a stale certificate stays
  a trust-bootstrap problem (as with the old contact record).
* Fixed overhead is about 420 B per message plus padding (smallest padded message 2,197 B with the embedded 419 B sender certificate as built, versus 564 B for ADR 0002; measured sizes in `docs/protocol.md` section 5); AEAD adds 16 B per 4 KiB chunk.
* Receiver-side checks that the libraries do not do (Intended Recipient required; rPGP does not evaluate it at all) are application code and
  security-critical. Sequoia's low-level key iteration does not see a revoked primary key: sender code must check certificate validity (found and fixed
  in the spike).
* Dependencies: either a new LGPL dependency and a C or "experimental" crypto backend (Sequoia), or an experimental semantics crate (rpgpie).
  Both new dependency sets must be added to `docs/dependency-audit.md`/`deny.toml` deliberately. Both libraries have had recent security fixes;
  an advisory-monitoring and pin-update routine becomes part of the security posture.
* The independent review, which could not be closed from inside the repository for ADR 0002, remains required (below).

## Migration outline (no peers have been released; the formats are explicitly not frozen, so this protects test deployments only)

1. **Versioned address and contact format.** New addresses `an2…` for v6 fingerprints; contact documents become a certificate (armored or binary,
   at most 4096 B for now). `an1` addresses keep parsing; the contact store records the suite family per contact.
2. **Existing contacts re-verify.** An `an1` Ed25519 key cannot be turned into a v6 fingerprint (the fingerprint hashes a key packet with its
   creation time), and using one Ed25519 key in two protocols is avoided: generate fresh v6 keys. The old identity may send an
   `identity.migrated` message (legacy suite) carrying the new certificate to Trusted contacts, but it is only a hint: each contact must confirm the
   new fingerprint out of band (`--expect`) before trusting it, because the old key might be stolen.
3. **Pending old-format outbox messages.** The engine already re-seals queued and sent rows when a contact's record changes (`docs/protocol.md`
   8.2 and 9.4). Rows for a recipient who gains an OpenPGP certificate are re-sealed under suite 2 with the same `message_id`; rows for recipients
   who stay on `an1` continue under suite 1 until expiry. Suite 1 stays registered for opening for at least one maximum TTL (7 days) plus
   `retention_hours`.
4. **Inbox history is preserved.** Received messages are stored as plaintext rows with their original sender address; nothing is re-encrypted.
   `seen` dedupe state keyed by `(sender, message_id)` is kept for both address families. Retired HPKE KEM keys stay until their `retire_at`.
5. **Removal.** Delete suite 1 only after a release in which both suites ran, with a note in `docs/crypto-requirements.md` (this ADR replaces
   conditions 1 to 4, 6 and 7's mechanism, and reduces 8 to library pinning plus RFC 9580 Appendix A vectors; conditions 5, 9 to 13 remain).

## What the independent cryptographic review would then cover

1. The choice, version and backend of the OpenPGP library, its advisory history, and whether the pinned version has been reviewed by anyone else.
2. The application glue enumerated in the notes section 6: algorithm and packet policy (downgrade and DoS), required Intended Recipient and the
   one-signature rule, certificate acceptance and merge rules, subkey selection and retention, domain separation of the signed context, payload
   schema, replay/rollback guards, trust and pinning, padding policy, secret-key storage.
3. OpenPGP-specific hazards: signature-type and context confusion, cross-use of the identity key, unknown critical subpackets, expiry edge cases and clock
   skew, certificate flooding and third-party certifications, malformed-packet resource use.
4. That no AgentNet-defined cryptographic construction remains (the claim this ADR makes), and that the accepted limitations are documented honestly.

The review is **not** replaced by this spike, by interoperability tests, or by any third-party library audit; no audit is claimed for either
library at the proposed version.
