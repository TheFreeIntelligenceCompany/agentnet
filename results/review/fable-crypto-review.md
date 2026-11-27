# Adversarial review of the OpenPGP message protection (main at 7285c67)

Automated model review (Claude Fable subagent, read-only), run on 2026-11-27 at
the owner's request. **It is not the independent human cryptographic review that
`docs/crypto-requirements.md` condition 11 requires, and does not close it.**
Recorded by the lead from the reviewer's report. "EXECUTED" means the reviewer
ran the case in a throwaway crate against `agentnet-core`; otherwise the finding
rests on reading the code and the vendored `sequoia-openpgp` 2.5.0 source.

Result: no critical or high-severity break of sender authentication, recipient
binding or confidentiality. Three medium findings, eleven low, stale or
overclaiming documentation, and test gaps.

## Medium

**M1. A revoked encryption subkey comes back after the 4096-byte trim (EXECUTED).**
`pgp.rs` `normalize` drops the oldest revoked-or-expired subkey together with its
revocation when a certificate exceeds the size cap (`identity.rs` trims the
published record the same way). After 9 rotations with `--revoke-previous` the
oldest hard-revoked subkey and its revocation are gone; merging the original
certificate back in changes the record, and a new message sealed to the merged
contact was opened with only the first, "compromised" subkey secret. Attacker:
holds a compromised old subkey secret and gets a stale certificate merged at a
sender (e.g. through `add_contact`). Falsifies "revocations accumulate and are
never dropped". Fix: only trim subkeys whose authenticated expiry has passed, or
fail with `TooLarge` / raise the cap, or persist a per-contact floor.

**M2. Any stranger can grow the `revocations` table without bound (code trace).**
`ingest.rs` dispatches `identity.revoked` for any non-blocked sender before the
unknown-sender policy; `system.rs` inserts a row when the revocation names its
own sender; the table has no cap and is never pruned. Each frame can use a fresh
throwaway identity that revokes itself. Bypasses `max_quarantined` and
`unknown_senders = reject`. Fix: apply only when it names an existing contact.

**M3. The hidden recipient is not hidden from an active relay participant
(components EXECUTED).** An `ack.received` frame is 1173 B and the smallest
ordinary message is 2197 B (every non-ack carries `sender_cert`). Frames are
malleable outside the AEAD: a prepended or appended Marker packet, an appended
outer Padding packet, a prepended foreign PKESK and ASCII armor all open, each
with a new relay hash. Duplicates trigger a re-ack (once per 30 s). So a relay
participant can re-publish a mutated copy of a captured frame and watch who
publishes a 1173 B frame on which bucket, for the frame's TTL; the passive
version works on every first delivery. Also: the embedded certificate grows with
rotations, and the PKESK count reveals the number of live recipient subkeys.
Fix: pad acks to the common minimum class; do not re-ack mutated duplicates;
reject non-canonical frames.

## Low

* **L1 (EXECUTED).** A sender whose clock is ahead gets `BadSignature`, not the
  from-the-future handling: Sequoia's signature-liveness check fires first. The
  frame is marked seen; the time tests forge only `created_at`.
* **L2 (partly EXECUTED).** The accepted grammar is wider than documented: armor,
  markers, outer padding, extra PKESKs; AES-128/192 and any AEAD mode; armored
  and cleartext-signed adverts.
* **L3 (EXECUTED).** `sanitize` keeps unhashed subpacket areas and invalid
  signatures that claim the primary as issuer: a certificate copy can be bloated
  to the cap, after which a legitimate rotation update fails.
* **L4 (EXECUTED).** Padding gap: for deficits of 194, 8387, 8388 or 8389 bytes
  the padding body is empty (body length 712 gives 2005 B, all others 0 to 904
  give 2197 B).
* **L5 (code trace).** `pinned_certificate` turns a store or parse error into
  "not a contact" (fails open); a second check in ingest currently catches it.
* **L6 (code trace).** A primary revocation arriving through `contact.update`
  does not fail pending outbox rows, write a revocation row or purge adverts.
* **L7 (suspected).** Evicting a retained subkey entry (more than 32) leaves its
  secret in the certificate, usable indefinitely.
* **L8 (design).** A store rollback also rolls back contact certificates and the
  revocations table; not stated in the threat model.
* **L9 (confirmed).** First contact defaults to Trusted without `--expect`; the
  migration text says legacy contacts need `--expect`, nothing enforces it.
* **L10 (suspected).** A discovery withdrawal tombstone can be evicted by
  flooding, resurrecting the withdrawn advert; adverts replay onto another
  deployment with the same topic name.
* **L11 (bounded).** For a non-contact sender, `open` decrypts twice and
  canonicalises an attacker-chosen certificate several times before policy runs;
  `load_contact` re-parses the pinned certificate several times per frame.

## Informational

* No custom KDF, MAC or signature framing was found in `crypto/`. The glue that
  carries a security argument: the padding arithmetic, the two-pass in-band
  certificate authentication of unknown senders, the payload/signature
  cross-checks, the replay scheme, the unauthenticated generation sidecar.
* `crates/daemon` defines an HMAC over `timestamp.body` for webhooks (not
  reviewed); AGENTS.md says daemon webhook code must not import crypto crates.
* Domain separation: wrapping a signed advert into an encrypted frame fails
  (`MissingIntendedRecipient`, EXECUTED); a message's signed part reused as an
  advert fails the advert schema; re-encryption to a third party and reflection
  fail the recipient check. Residual risk: the identity key used elsewhere.
* `identity.json.legacy-v1` keeps the retired secret key on disk after migration;
  zeroisation is best-effort.
* Stale documentation: HPKE-era frame sizes and wording in the threat model
  (T3, T5, T7, T12, T13, T33, section 4), the `system.rs` header, ADR "suite id 2"
  and first-byte dispatch not in the code.

## Test gaps

Subkey-revocation persistence across the size cap; sender clock skew with a real
signature time; non-canonical encodings; ciphers other than AES-256/OCB;
`WrongSignatureCount`, nested or multiple signatures, more than 8 PKESKs; a
signature by a signing subkey; unhashed or invalid-signature junk in
certificates; padding over every size in a bucket; ack-versus-message size;
`identity.revoked` from unknown senders; revocation through `contact.update`;
directory failure during open; tombstone eviction in discovery.

## Checked and found sound

Signature policy (primary key of a v6 Ed25519 certificate, v6 binary signature,
exactly one); mandatory Intended Recipient check on the hashed area; unknown
senders cannot impersonate a pinned contact; no encryption downgrade through
recipient preferences; revoked or expired primary checked before sealing and on
receive; designated-revoker and third-party signatures have no effect; secret
keys refused as contacts; merge refuses a different primary; anonymous PKESK;
receipts authenticated and bound to the outbox row; `contact.update` only from a
Trusted contact about itself; dedupe pruning replay-safe; identity file
permissions and atomic write; `age` export unchanged; migration trusts nothing
from the old identity.

## Not reviewed

Sequoia, OpenSSL and `age` internals beyond the cited functions; `crates/mcp`,
the control socket, the webhook, the transport, `triggers.rs`; most of
`send.rs`, `node.rs`, `discovery.rs`, `api_impl.rs` outside the cited parts;
most of the test suites; no timing measurements, no fuzzing; Linux and other
OpenSSL versions not exercised.
