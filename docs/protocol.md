# AgentNet wire protocol, version 2 (RFC 9580 OpenPGP profile)

Status: normative for the MVP, **not yet frozen**. ADR 0004 (accepted by the
repository owner) replaced the hand-rolled scheme of ADR 0002 (HPKE base mode,
AgentNet's own envelope signature, key epochs, signed contact records) by a
**profile of RFC 9580 OpenPGP**; ADR 0002's wire format no longer exists in the
tree (hard cutover, `agentnet identity migrate`). There are no released peers,
so the format may still change without a version bump. Nothing here has been
independently reviewed: this is **not an audited, not a production-secure and
not a forward-secret protocol** (section 7); an independent cryptographic review
is required before any production use involving sensitive information.

AgentNet defines **no cryptographic construction**: key agreement, encryption,
signatures, key binding, expiry, revocation, the hidden recipient and padding are
RFC 9580 constructions implemented by `sequoia-openpgp` 2.5.0 (OpenSSL 3
backend). What AgentNet adds is policy and glue (which packets to accept, how
certificates are merged, payload schema, replay and trust), enumerated in
`docs/crypto-requirements.md`. Implemented by `crates/core` behind the `crypto`
module (`crypto::{address, contact, envelope, identity, revocation, advert, pgp,
protection}` and the `MessageProtection` trait; see `docs/crypto-interface.md`).
Evidence for the choice: `docs/adr/0004-openpgp-message-protection.md`,
`docs/spike/notes-openpgp.md`, `results/a2-openpgp/`.

Conventions: "MUST", "MUST NOT" and "SHOULD" are used as in RFC 2119. All
timestamps in application payloads are Unix time in milliseconds (UTC), signed
64-bit. "Reject" means: stop processing, return an error that carries no
plaintext, and do not act on the input. RFC 9580 section numbers are from the
RFC text fetched from rfc-editor.org (`results/a2-openpgp/versions.txt`).

## 1. Primitives

| Purpose | Mechanism | RFC 9580 |
|---|---|---|
| Identity and contact record | v6 certificate: Ed25519 primary key (certify + sign, no expiry), X25519 encryption subkey with an expiry, subkey binding signatures | 5.5, 5.2.1, 5.2.3.13, 9.1 |
| Address | `an2` + base32(fingerprint ‖ 4-byte checksum); the fingerprint is the SHA2-256 v6 fingerprint of the primary key | 5.5.4.3 |
| Encryption | PKESK v6 to an **anonymous** recipient (no fingerprint), X25519; SEIPD v2 with AES-256 and OCB (4 KiB chunks, per-message salt) | 5.1, 5.13.2, 9.6 |
| Sender authentication | One-pass signed Literal Data, v6 Ed25519 data signature inside the encryption | 10.3, 5.2 |
| Recipient binding | Intended Recipient Fingerprint subpacket naming the recipient's PRIMARY key; mandatory on receive | 5.2.3.36 |
| Padding | standard Padding packet as the last packet of the SEIPD v2 payload | 5.14 |
| Rotation | new encryption subkey; the old one retired by a standard subkey revocation ("key retired") | 5.2.3.31 |
| Revocation | standard subkey or primary-key revocation signatures, distributed as the merged certificate | 5.2.1 |
| Identity file export | `age` passphrase (scrypt) file around the secret certificate (an existing tool; no AgentNet construction) | n/a |
| Address checksum, ids | SHA-256 typo checksum, UUIDv4 message ids, JSON | RFC 6234, 4648 |

Policy object: `StandardPolicy` plus the explicit receiver rules of section 5.
There are no other algorithms: no compression (compiled out), no SKESK, no
PKESK v3, no SEIPD v1, no RSA or ECDSA keys in AgentNet's use.

## 2. Addresses

`an2` + lowercase RFC 4648 base32 (no padding) of `fingerprint(32) ‖ checksum(4)`,
61 characters; `checksum = SHA-256("agentnet/v2/address-checksum" ‖ fingerprint)[0..4]`
(a typo guard, not a security mechanism). Parsing is strict (case, length, alphabet,
trailing bits, checksum). `an1` addresses (retired format) fail with a message that
names `agentnet identity migrate`. A fingerprint hashes the primary key packet
(including its creation time), so it pins a certificate; it cannot verify
anything by itself. Obtain the address over a channel separate from the
certificate; `contact add --expect <address>` binds them.

## 3. Contact record: the certificate

A contact record is the peer's **public OpenPGP certificate**, document form
base64url (no padding) of the binary certificate, at most 8192 bytes after
sanitizing (ASCII armor is accepted on input; secret key material is refused
with `ContactError::ContainsSecretKey`). Alias and trust level are local
application data.

Acceptance (`crypto::contact`, `crypto::pgp`):

1. Parse; refuse secret keys; require a v6 Ed25519 primary key.
2. **Sanitize**: keep only the primary key, the subkeys, and the primary's own
   direct-key and key-revocation signatures and the subkeys' own binding and
   revocation signatures, **each verified against the primary key** (invalid
   signatures are dropped). User IDs, user attributes, **third-party
   certifications**, designated-revoker revocations, unknown packets, markers
   and every unhashed subpacket area are dropped before anything is stored, so
   the stored form of a bloated certificate is byte-identical to a clean one.
3. Require a valid self-signature under the policy; drop subkeys without a
   valid binding signature. If the result exceeds 8192 bytes (`MAX_CERT_LEN`),
   drop only subkeys whose authenticated **expiry has passed**; a revoked but
   unexpired subkey is never dropped together with its revocation (an expired
   subkey that is merged again stays unusable). If it still exceeds the cap the
   certificate is refused (`TooLarge`), and a local rotation that would exceed it
   is refused with `CertificateTooLarge` and changes nothing. Arithmetic: a
   fresh certificate is 419 B and every rotation with `--revoke-previous` adds
   369 B, so (8192 - 419) / 369 = 21 revoking rotations per subkey validity
   period (default 365 days, about one every 17 days); wait for old subkeys to
   expire, rotate without `--revoke-previous` less often, or create a new
   identity. The record is also embedded in adverts (8192 B record limit), so a
   certificate above about 5 KiB cannot advertise.
4. For a new contact: the primary must be alive and not revoked and at least one
   encryption subkey must be live (bound, not expired, not revoked, v6 X25519).
5. A certificate whose **primary key is revoked** is still parsed (it is how a
   revocation travels); it is treated as a revocation of that address, not as a
   usable contact, and revocations made by designated revokers are ignored.
6. **Future-dated certificates.** Signatures dated ahead of the local clock are
   accepted only up to `MAX_CREATED_AT_FUTURE_MS` (`crypto/contact.rs`), 120 s:
   the default `clock_skew_s`, the same tolerance the frame freshness check
   applies, so a peer whose clock runs ahead by no more than the permitted skew
   can still rotate. It is a constant and not the configured `clock_skew_s`
   because the certificate parsers have no access to the node configuration
   (raising `clock_skew_s` does not widen it). Before 2026-11-26 it was 24 h.

**Updates are merges, never replacements** (`VerifiedContact::merge`): the
incoming certificate must have the same primary key (otherwise
`ContactError::PrimaryMismatch`; a different primary is a different address); the
signatures are unioned (so revocations accumulate and are never dropped, and an
older certificate cannot roll a newer one back); the result is sanitized again,
so a stripped or forged subkey binding adds nothing. The first contact still
rests on the out-of-band address (`--expect`); a stale certificate presented at
first contact is a trust-bootstrap problem, as before.

### Inbox topic

`/agentnet/1/inbox-<hh>/proto` with `hh` = two lowercase hex digits of
`u16_be(fingerprint[0..2]) mod 16`. The number of buckets (16) is a protocol
constant: it is no longer a per-agent field. The fingerprint is already a hash
output, so no extra hash or domain string is used. All agents with the same
bucket share a topic and trial-decrypt every frame on it; the topic is a public
function of the address.

## 4. Payload (the signed, encrypted application content)

Strict JSON (UTF-8, unknown and duplicate fields rejected) in the Literal Data
packet (`crypto::protection::Wire`):

```
{"agentnet":2,"message_id":"<uuid v4>","type":"message","sender":"an2…","recipient":"an2…",
 "created_at":<ms>,"expires_at":<ms>,"conversation_id":"…"?,"correlation_id":"…"?,
 "body":"…","sender_cert":"<base64url certificate>"?}
```

* `agentnet` is the payload version (2). Types: `message`, `task.request`,
  `task.result`, `ack.received`, and the reserved `contact.update` (body: the
  sender's current public certificate; applied as a MERGE) and `identity.revoked`
  (body: the sender's revoked public certificate). The remaining field rules are
  those of ADR 0002: UUIDv4 ids, type `[a-z0-9._-]{1,64}`, optional ids of
  1..=128 printable ASCII characters, body at most `max_body_bytes` (65,536).
* TTL is not moved into signature subpackets: it stays here (lead decision 4).
* `sender` and `recipient` are the fingerprints (addresses) and are
  **cross-checked** against the verified signer and against the signature's
  Intended Recipient Fingerprint.
* `sender_cert` (absent in receipts) is how an **unknown sender** is
  authenticated (section 5, item 8): it is ignored whenever the sender is a
  pinned contact.
* Dedupe key `(sender, message_id)`; there is no replay protection in OpenPGP:
  the engine's dedupe, replay guard and rollback guard (sections 8 and 10) are
  unchanged and security-critical.
* No notation data is used and the identity certificate is used for nothing but
  AgentNet. **Domain separation is weaker than in ADR 0002**: an OpenPGP data
  signature has no application context string, so the defence is the strict
  payload schema (`agentnet`, `type`, both fingerprints) and the rule above,
  not a signature prefix (`docs/threat-model.md`).

### Time checks (at open)

`created_at` at most `clock_skew_s` (120 s) ahead of the local clock (else
`FromFuture`, deferred and not marked seen); `expires_at > created_at`;
`expires_at - created_at <= max_ttl_s`; `expires_at > now` (else `Expired`).
Boundaries are exact and tested. OpenPGP signature and key times are evaluated
at `now + clock_skew`.

## 5. Message (frame) and receiver policy

A frame is **one OpenPGP message** (binary, no AgentNet header, no suite or
version byte: the receiver recognises it by parsing the packet grammar):

```
PKESK v6 (anonymous, X25519)       one per live encryption subkey of the recipient
SEIPD v2 (AES-256, OCB) {
    One-Pass Signature v6
    Literal Data           = payload (section 4)
    Signature v6 (Ed25519) with Intended Recipient Fingerprint = recipient primary key
    Padding                = inner packet sequence padded to a power of two (>= 1024 B)
}
```

**Sealing** (`MessageProtection::seal`): the sender first validates the
recipient certificate **at certificate level** (primary key valid, not
revoked, not expired: Sequoia's key-level filters such as `.revoked(false)` do
not see a revoked primary key, a hazard found by the spike and covered by
`sealing_to_a_certificate_with_a_revoked_primary_is_refused` and the engine
regression test), then encrypts to every live encryption subkey. Errors:
`RecipientRevoked`, `RecipientExpired`, `RecipientKemExpired` (no usable subkey).
If the power-of-two size would exceed the transport limit the unpadded frame is
used; if that still does not fit, `TooLarge` with a body-size hint.

**Opening** (`MessageProtection::open`, all in `crypto`, fail closed, one error
variant and one `open_error.*` counter each):

0. **Canonical grammar** (L2), checked with Sequoia's packet parser and
   `Dearmor::Disabled`, never by byte heuristics: the outer sequence must be
   exactly PKESK v6 (1 to 8) then one SEIPD v2 with AES-256 and OCB, nothing
   before, between or after (no armor, Marker, outer Padding or trailing data);
   after decryption the inner sequence must be exactly one-pass signature,
   Literal Data, Signature and at most one Padding. Adverts are exactly one-pass
   signature, Literal Data, Signature (no armor, cleartext signature or
   prefix-signature form). The accepted cipher is pinned to what AgentNet sends
   (AES-256/OCB), which is also all that rPGP 0.21.1 emits (`tests/interop-rpgp`);
1. size: empty (`Truncated`), longer than `max_payload_len` (`FrameTooLarge`);
2. not an OpenPGP message / damaged (`Malformed`);
3. trial decryption: the recipient is anonymous, so every PKESK is tried with
   each of the agent's live and retained encryption subkeys; no match is
   `NotForUs` (normal for a shared bucket, counted as `frame.not_for_us`, not
   logged); at most 8 PKESKs per frame;
4. no SKESK (`SkeskPresent`), every PKESK v6 (`PkeskNotV6`), SEIPD v2 with AEAD
   (`NotAead`), AES cipher (`UnsupportedCipher`), no compression (`Compressed`);
5. structure exactly `encryption { signature group }` (`BadStructure`, also for
   unsigned messages), exactly one signature (`WrongSignatureCount`), a v6
   Ed25519 binary signature made by a primary key (`UnsupportedSignature`);
6. the signature verifies against the **pinned certificate** of the signer
   (`BadSignature`); a signer whose certificate is revoked or expired is
   `SenderRevoked` / `SenderExpired` (the engine treats the former like a
   blocked sender);
7. the signature MUST carry an Intended Recipient Fingerprint equal to the
   receiver's own primary fingerprint: absent is `MissingIntendedRecipient`,
   another one `WrongIntendedRecipient` (surreptitious-forwarding defence; both
   libraries accept signatures without it, so this is ours);
8. **unknown sender decision**: verification needs the sender's certificate. If
   the signer is not a pinned contact, the payload's `sender_cert` is used: it
   must parse, its fingerprint must equal the payload `sender` and the
   signature's issuer, and the signature must verify against it (second pass).
   The message is then authenticated as "made by the holder of this address"
   and nothing more: trust stays `unknown` and the unknown-sender policy
   (`quarantine`/`reject`/`accept`) applies, as before. Without a usable
   certificate (receipts carry none) it is `UnknownSender` and is dropped.
   The embedded certificate is never stored or merged. A pinned certificate
   always wins over an embedded one;
9. payload: strict schema (`MalformedPayload`), version (`UnknownEnvelopeVersion`),
   `sender` equals the verified signer (`SignerMismatch`), `recipient` equals this
   agent (`WrongRecipient`), field rules (`InvalidField`), time rules.

Then the engine's checks: trust, quarantine policy, dedupe, replay guard.

### Size and padding

Padding is a standard Padding packet. The inner length is padded to a power of
two of at least 1 KiB; a class whose target no Padding packet can hit exactly is
skipped for the next one (L4), so every body length of a class gives the same
frame length. **Acks** carry no certificate and are padded as if they carried the
payload of the smallest ordinary message (body `x`) of the same sender, so an
ack has the length of the smallest message (M3). A duplicate that arrives
byte-different is not re-acked while the first ack row is stored
(`seen.frame_digest`, schema v5), and every re-ack waits a random 1 to 5000 ms; a
sender that re-seals a pending message after a key update therefore gets no
re-ack until the stored ack is pruned and retries until expiry (trade-off).

Fixed overhead: about 420 B (PKESK, SEIPD framing, signature packets) plus
the embedded sender certificate (419 B binary, about 560 B base64, for a fresh
identity; up to 8,192 B binary, 10.9 KiB base64, at the cap) plus 16 B per 4 KiB
AEAD chunk. Measured after the review fixes (Linux x86_64, debug build,
`crates/core/tests/review_crypto.rs::frame_sizes_with_a_fresh_and_a_maximal_sender_certificate_fit_the_transport_limit`):

| Body | fresh certificate | maximal certificate (8,168 B) |
|---|---|---|
| 0 B | 2,197 B | 16,584 B |
| 1,024 B | 4,245 B | 16,584 B |
| 65,536 B | 131,720 B | 131,720 B |
| 65,536 quote characters (worst JSON expansion, unpadded) | 132,881 B | 143,245 B |
| ack | 2,197 B | 16,584 B |

All are below the Logos limit of 153,600 B (asserted by the test), so the 64 KiB
body limit is unchanged. Within a bucket all frames have
the same length; the smallest bucket is 1,024 B of inner packets.

## 6. Identity file and export

`identity.json` (mode 0600, written atomically, never overwritten without
`--overwrite`-class operations): `{"v":2,"address","created_at","kem_expires_at",
"certificate": base64url(transferable secret key), "retained_subkeys":
[{"fingerprint","retire_at"}]}`. Version 1 (HPKE) files are refused with a message
naming `agentnet identity migrate`. The export is an ASCII-armored `age` file
(scrypt passphrase) of the same JSON. Secret key material lives in Sequoia's
protected memory and is never printed (`Debug` shows the address only; tested).

## 7. Security properties and limits

* Confidentiality of the payload to the holders of the recipient's encryption
  subkeys; sender authentication inside the encryption (sign-then-encrypt);
  recipient binding by the Intended Recipient Fingerprint; hidden recipient
  (an anonymous v6 PKESK shows no key id or fingerprint); standard padding;
  key binding, expiry and revocation by the standard signatures.
* **No forward secrecy against later compromise of a recipient encryption
  subkey.** Rotation limits future exposure only; retired subkeys that are still
  held stay exposed until `retire_at` and pruning. No post-compromise security.
  No deniability (signatures are transferable).
* Not audited at the pinned versions (neither Sequoia nor this glue); an
  independent review is required (`docs/crypto-requirements.md`, condition 11).
* Metadata: relays see the content topic (inbox bucket), timing, the padded
  length class (which includes the sender certificate, so it reveals certificate
  growth from rotations), the number of PKESKs (the recipient's live encryption
  subkeys, at most 8), the publisher's network identity, and that the payload is
  an OpenPGP v6 SEIPD v2 / AES-256 / OCB message. They do not see sender,
  recipient fingerprint, key ids or payload, and cannot tell an ack from the
  smallest message by size. Anyone on a bucket sees every frame addressed to it
  and trial-decrypts them (`docs/threat-model.md` section 4).
* A revoked encryption subkey stays revoked: no later merge of an older
  certificate makes it usable for sealing again (M1). With `--revoke-previous`
  the secrets of all earlier subkeys, including merely retired ones, are
  destroyed.
* Replay, rollback and concurrent-identity limits are those of section 10.

## 8. Delivery, retries and receipts

Implemented by `crates/core` (`node`, `ingest`, `send`, `triggers`, `store`).
Defaults are those of `NodeConfig`; every number below is configurable unless
marked fixed. Tested deterministically (mock network, manual clock, seeded
jitter) in `crates/core/tests/engine_*.rs`.

### 8.1 Outbound states

| State | Meaning |
|---|---|
| `queued` | Sealed once and stored (one transaction); not yet accepted by the local node. |
| `sent` | The local node accepted a publish at least once. This is **not** receipt. |
| `delivered` | An authenticated `ack.received` from the recipient arrived. |
| `failed` | Permanent: the transport said the frame can never be accepted (`TooLarge`). |
| `expired` | `expires_at` passed without an ack. |

`send_message` validates (identity not revoked; known, non-blocked, non-revoked
recipient whose certificate has a live encryption subkey (checked at
certificate level: a revoked primary refuses even if a subkey looks usable); type in `message`, `task.request`, `task.result`; body <=
`max_body_bytes` and fits one frame; TTL defaulted and capped at `max_ttl_s`;
fewer than `max_outbox_pending` non-ack rows in `queued`/`sent`), seals the
frame **once**, and inserts the row in one transaction. Retries re-publish the
identical stored frame (so the same `message_id`, signature and ciphertext);
only the Waku timestamp differs. A message whose recipient record is later
deleted is still sent from its stored frame.
`idempotency_key` is unique: repeating a request with the same key and the same
recipient/type/body returns the original (`deduplicated = true`, current state);
a different recipient, type or body is `Conflict`. Sending to our own address
works through the relay echo (the engine synthesizes our own contact record).

### 8.2 Retry schedule

* A row is due when `next_attempt_at <= now` and its state is `queued` or `sent`
  (`ack.received` rows: `queued` only).
* After the n-th **accepted** publish (n >= 1) of a non-ack row:
  `next_attempt_at = now + d`, with `c = min(retry_max_ms, retry_base_ms * 2^(n-1))`, `d` uniform in `[c/2, c]`
  milliseconds (equal jitter; defaults 2000 / 300000; seedable via
  `delivery.jitter_seed`).
* System rows (`contact.update`, `identity.revoked`) are ordinary outbox rows
  (retried, acked, expired like user messages) with `hidden = 1`: they are
  excluded from `read_outbox`, `get_message_status`, `read_conversation`,
  queue counts and the pending limit.
* After `max_attempts` (20) accepted publishes the row is no longer published;
  it stays `sent` until it is acked or expires. Consequence: a recipient that
  stays unreachable for longer than the retry budget, or whose ack is lost for
  all later retries, is reported `sent` and finally `expired` although the
  recipient may have the message.
* Retryable transport errors (`Unavailable`, ...) keep the state, store a
  sanitized, truncated `last_error` (no payload), and back off with the same
  formula using a separate failure counter; the step stops early. They do not
  consume `max_attempts`.
* `Isolation` errors: nothing is published and no backoff is applied; rows stay
  due and go out immediately after the violation clears.
* `ack.received` rows are sent once (`sent` is final for them; they are never
  retried). A lost ack is repaired by the sender's retry (below).
* A step handles at most `send_batch` (64) rows. A row past `expires_at` becomes
  `expired` (also done by maintenance).
* An authenticated ack moves any non-`delivered` row (including `expired` and
  `failed`) to `delivered`. Because an ack's `expires_at` never exceeds the
  original's, a post-expiry ack can only be processed after a backwards clock
  correction; the code path exists and is tested that way.

A revoked local identity publishes only rows of type `identity.revoked`.
When a merge changes a recipient's certificate (an imported certificate
or a `contact.update`), every `queued` or `sent` row for that recipient
whose TTL has not passed is **re-sealed** in the same transaction (same
envelope fields and `message_id`, fresh signature and ciphertext for the new
key, `next_attempt_at = now`), so pending messages survive the recipient's key
rotation. A revocation of the recipient fails all its pending rows
(`recipient identity revoked`).

### 8.3 What an ack proves

`ack.received` (sealed, signed by the recipient, `correlation_id` = original
`message_id`, same `conversation_id`, TTL = min(remaining TTL of the original,
`default_ttl_s`)) is queued in the **same transaction** that persists the inbox
row. It proves: the recipient's engine durably committed the message
(`synchronous=FULL`, WAL) under that `message_id`, and the sender key signed the
ack. It does **not** prove the message was read, understood, acted on, that the
recipient's agent is running, or that the recipient *trusts* the content.

The sender accepts an ack only if: the ack's sender is a **Trusted** contact;
`correlation_id` is the `message_id` of one of our non-ack outbox rows; that
row's recipient equals the ack's authenticated sender. Anything else is counted
(`ack.ignored_*`) and ignored. Acks are never stored in the inbox, never
generate events or triggers, and are never acknowledged (no ping-pong). An ack
needs the sender's contact record, so a message accepted from an *unknown*
sender under `unknown_senders = "accept"` is stored but **never acked**
(`ack.no_contact`); quarantined messages are not acked until released.

### 8.4 Inbound processing and dedupe

Order for each frame (live or history): skip if `transport_id` is in
`transport_seen`; `open` through the `MessageProtection` trait (with the contact store as sender directory) (limits from
config; `NotForUs` is silent and counted); trust lookup (`Blocked` dropped, which
includes an address with a verified revocation, also when it is not a contact; an
ack from a non-Trusted sender is ignored, never quarantined); reserved system
types (`identity.revoked` from any non-blocked sender, `contact.update` from a
Trusted sender only; section 9) are handled in their own transaction and never
stored in the inbox; `unknown_senders` policy for non-Trusted senders
(`quarantine`: stored with `quarantined=1` up to `max_quarantined`, then dropped,
no ack/event/trigger; `reject`: dropped; `accept`: normal, trust recorded as
`unknown`/`untrusted`, triggers never match); then **one transaction**: insert
`seen`, the inbox row, a `message.received` event, trigger matches, and the ack
row. Only after commit are `transport_seen` marked and change hints broadcast.
If the transaction fails, nothing is acked, notified or marked seen; a live frame
cannot be polled again, so a history pass is requested (the watermark does not
advance on a failed pass).

* **Dedupe key**: `(sender, message_id)` in `seen`, kept until
  `expires_at + clock_skew_s`. Pruning then is replay-safe because `open`
  rejects `expires_at <= now` (tested: a replay after pruning is `Expired`).
  `transport_seen` (SHA-based transport id) is only an optimization, pruned after
  `transport_seen_ttl_s` (24 h) or when it exceeds 200 000 rows.
* **Duplicates** create no inbox row, event or trigger match. A duplicate of a
  non-quarantined message re-queues a fresh ack (new ack `message_id`) if we
  hold the sender's contact, at most once per `reack_min_interval_s` (30) per
  message. (Deviation from "acked before": a never-acked message whose sender
  became a known contact is acked on its next retry.)
* **Inbox capacity**: with `max_inbox_records` non-quarantined rows, new messages
  are refused: not stored, not acked, not marked seen. The sender keeps retrying
  until its TTL/`max_attempts`; once space frees (retention pruning) a retry is
  accepted. Counted as `inbox.full_refused` and shown in `network_status.detail`.
* **Time**: `created_at` more than `clock_skew_s` (120) ahead is deferred (not
  marked seen; history can deliver it later); expired and over-`max_ttl_s`
  frames are rejected.

### 8.5 Receiving paths and recovery

Live poll every `poll_interval_ms` (250) plus history sync. History sync runs at
start, after the transport becomes ready again, after a persistence failure, and
every `history_sync_interval_s` (15). A pass queries
`[max(watermark - history_overlap_s, now - retention_hours), now + clock_skew]`
in windows of at most the transport's `max_history_window_ns`, following page
cursors (a cursor that repeats, or cycles back to an earlier one, is a failed pass: the
watermark stays and the same interval is read again next time), and advances the watermark to the pass's start time only if every page
was processed without a store failure. `HistoryUnavailable`, isolation and
other transport errors leave the watermark untouched. In `run`, a bounded
channel (`inbound_channel_capacity`, 256) sits between the receive loop and
the persisting stage; when full the receive loop waits, so backlog stays in the
transport's own queue. Memory is bounded by the channel plus the one poll batch
the receive loop holds. History frames are processed inline and sequentially.

Recovery limits: a message is recoverable only while the relay's history holds
it (relay retention) **and** it is within `retention_hours` **and** its TTL has
not passed. Otherwise the recipient never sees it; the sender's row ends
`expired` (or `sent` if it was still retrying). Because the sender keeps
re-publishing with fresh timestamps until `max_attempts`, a message can also
arrive late through a retry.

### 8.6 Ordering

None guaranteed. Frames can arrive duplicated, reordered or not at all.
`read_inbox`/`read_outbox`/`read_events` order by local insertion sequence
(arrival order, not send order). `read_conversation` merges inbox and outbox by
local time (`received_at` for inbound, `created_at` for outbound), then
direction, then sequence. All cursors are opaque; a cursor of the wrong kind or
garbage is `InvalidArgument`; every list call returns a `next_cursor`
(a position-zero cursor for an empty table, the request cursor if nothing is
new) so an empty tail can be used as `since_cursor` for a trigger. The cursor
encodes a position, never a value that could be skipped by later arrivals.

### 8.7 Triggers and events

Disabled unless `policy.auto_trigger`. Creation requires an allowlisted
`target_session`, fewer than `triggers.max_active` active triggers, a lifetime
<= `max_lifetime_hours`, and a Trusted contact if `sender` is filtered. Matching
happens inside the inbox-insert transaction against non-quarantined messages
from Trusted senders (acks excluded); all present filters must equal. A
`once` trigger is consumed by a conditional `UPDATE ... WHERE state='active'`
whose row count decides the winner. At most `max_matches_per_minute`
`trigger.matched` events are recorded per sliding minute across all triggers;
over budget the match is not recorded and a once-trigger is not consumed.
`since_cursor` scans persisted trusted inbox rows after the cursor in the same
transaction as trigger creation. Events hold references only (ids, session,
timestamp). Events are pruned when acked and older than `event_retention_hours`,
or unacked and older than `event_max_age_hours`; `ack_events` is idempotent,
monotonic and cannot acknowledge events that do not yet exist.

### 8.8 Retention and limits

| Item | Rule |
|---|---|
| Inbox, outbox terminal rows (including published `ack.received` rows, which are never acknowledged themselves) | pruned after `retention_hours` (168) by maintenance (unread rows included) |
| `seen` | until `expires_at + clock_skew_s` |
| Events | see 8.7 |
| Body | `max_body_bytes` (65536) and one frame (`transport.max_payload_len`) |
| Outbox | `max_outbox_pending` (1000) non-ack rows in `queued`/`sent` |
| Quarantine | `max_quarantined` (1000) |
| Storage | SQLite WAL, `synchronous=FULL`, one connection, every state change one transaction |

A store opened with a different identity than the one that created it is
refused (`NodeError::IdentityMismatch`). The engine trusts its local clock for
TTL, retry and pruning decisions; a wrong clock accepts or rejects messages
accordingly.

## 9. Rotation, revocation and certificate updates

There are no key epochs and no signed contact records any more; the standard
certificate machinery does the work and the application merges.

### 9.1 Rotation

`agentnet identity rotate-kem [--expires-in-days N] [--keep-hours H]`
(daemon stopped) adds a new X25519 encryption subkey (binding signature with an
expiry, default 365 days) and **retires** the previous live subkey with a standard
subkey revocation, reason "key retired" (soft: it is not used for new messages
from the revocation time on). The old secret subkey is kept for decryption until
`retire_at` (`keep_hours`, default `storage.retention_hours`) and destroyed by
`prune_retired`. The address does not change. The identity file records the
retired subkeys in `retained_subkeys`.

### 9.2 Compromise of an encryption subkey

`--revoke-previous` hard-revokes ("key compromised") every earlier encryption
subkey and destroys its secret key at once. Messages already sealed to it are
lost unless their senders merge the new certificate and re-seal (9.4). There is
no forward secrecy: a subkey that was not destroyed in time exposes every
message sealed to it.

### 9.3 Propagation without a directory: `contact.update`

At the next `serve`, if the certificate changed since the last announcement
(`announced_cert_id` in `kv`), the engine sends a hidden `contact.update` whose
body is the current public certificate to every Trusted contact. A receiver
applies it only from a Trusted contact, for the sender's own address, as a
**merge** (section 3): `contact_update.applied` when the stored certificate
changed, `ignored_same` when it did not, `ignored_wrong_address`,
`ignored_untrusted`, `ignored_invalid` otherwise. It can also be given out of
band (`contact add` merges it).

### 9.4 Re-seal on contact update

When a merge changes a contact's certificate (an imported certificate or a
`contact.update`), every undelivered outbox row to it (`queued`, or `sent` and
not an ack) is re-sealed to the merged certificate in the same transaction, with
the same `message_id`, and is due again immediately. Rows that cannot be sealed
(for example the recipient is now revoked) count as `reseal.failed`.

### 9.5 Identity (primary key) revocation

`agentnet identity revoke --reason TEXT` creates a standard key-revocation
signature, writes the **revoked public certificate** to `revocation.json`, and marks
the local identity revoked: the daemon sends nothing except `identity.revoked`
(body: that certificate) to every Trusted contact. A receiver accepts
`identity.revoked` from any non-blocked sender when it names the sender or a
contact, merges it into the stored certificate (revocations accumulate), records
it in `revocations` (source `received`, `imported` or merge), blocks the contact,
fails its pending rows with `recipient identity revoked`, removes its adverts and
refuses to re-trust or re-add it. `contact revoke @file` imports one out of band,
also for an address that is not a contact. A message signed by a revoked
certificate is `SenderRevoked` and counted as `drop.blocked`. Unchanged
property: a thief of the primary secret key can issue the same revocation (denial
of service only), and there is no global revocation list; only designated-revoker
revocations are ignored (sanitized away).

## 10. Replay protection: what is and is not guaranteed

Replay protection is the engine's persisted set of `(sender, message_id)`
(table `seen`, kept until `expires_at + clock_skew`) on top of the time checks
in `open`. Outcomes by scenario (tests in `crates/core/tests/engine_hardening.rs`
unless noted):

| Scenario | Outcome | Test |
|---|---|---|
| Replay in the same process | `message.duplicate`; no inbox row, event or trigger; a re-ack is queued at most every `reack_min_interval_s` | `engine_security::replay_now_and_after_dedupe_pruning` |
| Replay after a restart (same store reopened) | rejected as duplicate: `seen` is durable | `replay_after_restart_is_rejected` |
| Replay after `seen` pruning | rejected by `open` as `Expired` (pruning is delayed to `expires_at + skew`) | `engine_security::replay_now_and_after_dedupe_pruning` |
| Replay of a frame sealed to a revoked encryption subkey | cannot be opened at all (`NotForUs`) | `replay_across_kem_revocation_and_after_pruning` |
| **Store rolled back** (older SQLite copy restored) | **guard mode**, below | `rollback_enters_the_replay_guard_and_holds_replayed_frames`, `accept_rollback_releases_unexpired_held_messages` |
| **Sidecar missing next to a non-empty store** | unknown history: guard mode | `missing_sidecar_next_to_a_database_means_unknown_history` |
| **Identity imported into a new data dir** | no dedupe history; guard mode by default, none with `--no-replay-guard` | `migration_guard_by_default_and_full_state_copy_keeps_history`, CLI `identity_import_starts_in_replay_guard_mode_unless_told_otherwise` |
| Full-state migration (copy `agentnet.db` + `agentnet.generation`, daemon stopped) | history preserved, no guard | same engine test |
| **Same identity live in two data dirs** | **not preventable, not detected** | `concurrent_identity_in_two_data_dirs_is_not_prevented` |
| Two daemons on one data dir | second refused by the lock | `daemon/tests/socket_api.rs::lock_exclusivity_and_graceful_shutdown_cleanup` |

### 10.1 Rollback guard

The store keeps a monotonically increasing `store_generation` in its `kv` table,
incremented in every transaction that records a received message or ack
(`seen` insert). After the commit the engine rewrites the sidecar
`<store>.generation` (`agentnet.generation` next to `agentnet.db`; JSON
`{"v":1,"generation":N,"guard":null}`; temp file, fsync, rename, directory fsync).
On open:

* sidecar generation **greater** than the database's: the database is older than
  something this installation has seen: **rollback**;
* sidecar missing/unreadable but the database already belonged to an identity:
  **unknown history** (this includes a data directory from before the sidecar
  existed: it is guarded once on the first start after upgrade);
* sidecar carries `"guard":"imported"` (written by `identity import`): **imported**;
* a brand-new database with no sidecar is a fresh install: no guard.

In guard mode (persisted in the database, so it survives restarts) an inbound
message whose `created_at` is **at or before the moment the guard started plus
`clock_skew`** (a message accepted before the rollback may have been created that
far ahead of the local clock) and
that would otherwise be delivered is *held*: stored in the inbox as quarantined
with `hold_reason = replay_guard`, **not acknowledged, no event, no trigger**,
counted (`guard.held`), and shown by `network status` (reason, held count,
deadline) and `agentnet doctor`. Messages created after that cutoff are
delivered normally; a legitimate message created within `clock_skew` after the
guard started is held too and is released only by accepting the rollback. The guard ends when `max_ttl + clock_skew` has elapsed (every
held message has expired by then and is discarded) or when the operator runs
`agentnet doctor --accept-rollback` (daemon stopped); at the next start the held
messages that have not expired are released like quarantined ones, but only after
the sender's *current* standing is re-checked as for a new frame (a sender blocked
or revoked in the meantime has its held messages dropped; an untrusted or unknown
one follows `unknown_senders`) (event + ack,
no trigger matching). The sender keeps retrying a held message (it is not acked),
so a message that was genuinely sent before the rollback and not yet received is
held, not lost, until the guard ends or is accepted; acceptance, however, also
releases any held *replay*, which is the exposure the operator accepts.

What the guard cannot do: recover messages that were received and acknowledged
between the restored copy and the rollback (the sender believes them delivered;
they are gone); stop an attacker who can also roll back or delete the sidecar and
the data-directory markers together with the database; or protect `ack.received`,
`contact.update` and `identity.revoked` replays (these are idempotent by their own
rules: an ack for a delivered row is ignored, an older certificate merges to no
change, a revocation is idempotent). Held messages from non-trusted senders are
subject to the quarantine policy instead.

### 10.2 Concurrent identity

The same identity (OpenPGP certificate with its secret keys) running in two data directories
cannot be prevented cryptographically in a stateless design, and no sound local
detection exists (an own-address frame that this instance did not produce could
equally come from a pruned outbox, a restored backup or the other instance).
Observed behaviour: both instances receive and persist each message once each,
both acknowledge, the sender marks the message delivered on the first ack and
ignores the second (`ack.ignored_already_delivered`), each instance's replay
state is independent (so a replay is accepted once per instance), and triggers
may fire on both. `agentnet doctor` always prints this limitation. The data-dir
lock covers only one directory on one host.

## 11. Advertisement frames (optional discovery)

Off by default; full description in `docs/discovery.md`. This section records only what
touches the wire protocol.

* A second frame kind exists, used **only on host-configured discovery content topics**
  (`/agentnet/1/discovery-<name>/proto`): `b"AD" || 0x01 || document_bytes`. It is
  PLAINTEXT. The document is base64url of ONE OpenPGP **signed (not encrypted) message** made by the
  agent's primary key (one-pass signed Literal Data + v6 Ed25519 signature, RFC 9580 section 10.3);
  the literal data is the JSON record of `docs/discovery.md` section 3 (`v` 3). The record carries
  the discovery topic name it is published on, inside the signed content, so the signature binds
  the topic; a receiver drops an advert (or withdrawal) whose signed topic differs from the topic
  it arrived on (`advert.invalid.topic_mismatch`). It embeds the advertiser's current certificate
  and is accepted only when that certificate belongs to the same address and verifies the
  signature (read once without trust to find the certificate, then verified against it).
* A sealed frame (section 5) starts with an OpenPGP packet tag byte (high bit set), an advert frame
  with `A`; the engine routes by topic: an `AD` frame on an inbox topic and a sealed frame on a
  discovery topic are dropped and counted, never parsed as the other kind.
* A higher `seq` from the same address on the same topic replaces a lower one; equal or lower is
  ignored; an empty capability list with a higher `seq` is a withdrawal (kept as a hidden
  tombstone until its expiry so the replaced advert cannot be replayed).
* No AgentNet-defined signature construction: it is a standard OpenPGP data signature. The
  context-string domain separation of ADR 0002 (`agentnet/v1/capability-advert\0`) is gone; see the
  domain-separation note in section 4.
