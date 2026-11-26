# AgentNet wire protocol, version 1

Status: normative for the MVP, **not yet frozen**. There are no released peers,
so the version numbers below (`v: 1`, frame version 1, suite id 1) were kept
while the format changed during the cryptographic hardening that followed the
owner's conditions on ADR 0002 (new contact-record fields `key_epoch`,
`revoked_kem_epochs_below`, `suites`; new signed envelope fields `suite` and
`recipient_key_epoch`; reserved message types `contact.update` and
`identity.revoked`). Until a first release the wire format may still change
without a version bump. Nothing here has been independently reviewed: this is
**not an audited, not a production-secure and not a forward-secret protocol**
(section 7); an independent cryptographic review is required before any
production use involving sensitive information. Implemented by `crates/core`
behind the `crypto` module (`crypto::{address, contact, envelope, identity,
revocation}` and the `MessageProtection` trait; see `docs/crypto-interface.md`).
Design rationale is in
`docs/architecture.md` sections 4 and 5; why HPKE is used rather than a
messaging library is in `docs/spike/notes-libchat-and-crypto.md`. RFC 9180
(HPKE) section numbers below were checked against the RFC text.

Conventions: "MUST", "MUST NOT" and "SHOULD" are used as in RFC 2119. All
integers in binary structures are big-endian. All timestamps are Unix time in
milliseconds (UTC), signed 64-bit. "Reject" means: stop processing, return an
error that carries no plaintext, and do not act on the input.

## 1. Primitives

| Purpose | Primitive | Library (exact pins in `Cargo.lock`) |
|---|---|---|
| Signatures | Ed25519, verified with the *strict* rules (`verify_strict`: rejects small-order keys and non-canonical signatures) | `ed25519-dalek` =3.0.0 |
| Hash | SHA-256 | `sha2` =0.10.9 |
| Encryption | HPKE (RFC 9180) Base mode, DHKEM(X25519, HKDF-SHA256) = 0x0020, HKDF-SHA256 = 0x0001, ChaCha20-Poly1305 = 0x0003 (RFC 9180 section 7.1, 7.2, 7.3) | `hpke` =0.15.1 |
| Passphrase export | age (scrypt recipient), ASCII armor | `age` =0.12.1 |

Every direct dependency on the cryptographic path (`hpke`, `ed25519-dalek`,
`sha2`, `age`, `getrandom`, `zeroize`, `data-encoding`, `base64`, `uuid`) is
pinned with an exact `=x.y.z` requirement; the transitive cryptographic crates
(`curve25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, ...) are pinned
by the committed `Cargo.lock` (CI builds with `--locked`). The suite is checked
against published vectors (RFC 9180 Appendix A.2.1, RFC 8032 section 7.1,
RFC 6234, RFC 4648; `crates/core/tests/vectors.rs`).

There is no hand-written cryptography. The Ed25519 signing key and the X25519
KEM key are generated independently; neither is derived from the other.

All domain-separation strings are ASCII and are used byte-exactly:

| String | Used for |
|---|---|
| `agentnet/v1/address-checksum` | address checksum hash input prefix |
| `agentnet/v1/inbox-topic` | inbox bucket hash input prefix |
| `agentnet/v1/contact-record\0` | contact record signature input prefix |
| `agentnet/v1/envelope\0` | envelope signature input prefix |
| `agentnet/v1/identity-revocation\0` | identity-revocation tombstone signature input prefix |
| `agentnet/v1/capability-advert\0` | capability advertisement signature input prefix (optional discovery, `docs/discovery.md`) |
| `agentnet/v1/hpke\0` | HPKE `info` prefix |

(`\0` is a single NUL byte.)

## 2. Addresses

An address is the agent's Ed25519 public key `pk` (32 bytes) plus a typo
checksum.

```
checksum = SHA-256("agentnet/v1/address-checksum" || pk)[0..4]
address  = "an1" || lowercase(base32_rfc4648_nopad(pk || checksum))
```

The base32 part is 58 characters, so an address is exactly 61 characters.
Example (seed `[7; 32]`):
`an15jfgyy7ctrjavpxvkb5rglwf7gkuo5vox27hxescd3vgsfcg2iwicroqze`.

Parsing is strict and MUST reject: a wrong prefix; a length other than 61;
any character outside `a-z2-7` (so uppercase and padding are rejected);
non-zero trailing base32 bits; a checksum mismatch; a `pk` that is not a
canonical encoding of a curve point; and a `pk` that is a weak (small-order)
key, i.e. one `verify_strict` would refuse. The checksum catches typos; it is
not a security mechanism. The address *is* the signing key, so an address
authenticates a contact record without any directory.

Addresses order and hash by their 32 key bytes.

## 3. Contact record

A contact record is the public, shareable binding of an address to its HPKE
KEM public key. It is the only thing that binds the KEM key to the signing
key.

Record bytes are UTF-8 JSON with exactly these fields, in this order, no
whitespace:

```json
{"v":1,"address":"an1…","signing_pk":"<b64url>","kem_pk":"<b64url>","key_epoch":1,"revoked_kem_epochs_below":1,"suites":[1],"inbox_buckets":16,"created_at":1700000000000,"kem_expires_at":null}
```

* `b64url` is RFC 4648 section 5 base64url without padding; decoders MUST reject padding and non-canonical trailing bits.
* `signing_pk`: 32 bytes. `kem_pk`: 32-byte X25519 public key.
* `key_epoch`: integer >= 1, starts at 1, incremented by every KEM rotation. This (not `created_at`) orders records of one address (section 9).
* `revoked_kem_epochs_below`: integer in 1..=`key_epoch`. KEM key epochs strictly below it are revoked by the owner (1 = nothing revoked). A rotation with revocation sets it to the new `key_epoch`.
* `suites`: the cipher suite ids the owner accepts, a non-empty strictly ascending list of 1..=255, at most 16 entries (today `[1]`). A sender seals only to a suite in this signed list (section 5, "No silent downgrade").
* `inbox_buckets`: integer in 1..=256 (default 16).
* `created_at`: when this record (this KEM key) was created, for information only; ordering uses `key_epoch`.
* `kem_expires_at`: Unix ms or `null`. Senders MUST NOT seal to a key at or after this time.

Signature: `sig = Ed25519(signing_sk, "agentnet/v1/contact-record\0" || record_bytes)`.

Document (what is exchanged): `{"record":"<b64url(record_bytes)>","sig":"<b64url(sig, 64 bytes)>"}`.

Verification (`parse_and_verify(doc, now_ms)`), in this order. Any failure rejects:

1. Document length <= 4096 bytes.
2. Document is JSON with exactly the fields `record` and `sig` (unknown fields and duplicate keys rejected); both decode as base64url; `sig` is 64 bytes.
3. Record is JSON; its `v` is read first: `v != 1` is `UnknownVersion` (so a future version produces that error and not a field error). A v1 record has exactly the fields above: unknown, duplicate and missing fields are rejected (`kem_expires_at` must be present, possibly `null`).
4. `address` parses (section 2) and equals the address derived from `signing_pk`.
5. The signature verifies with `verify_strict` under the address's key over the domain-prefixed record bytes.
6. `kem_pk` is 32 bytes, is not the all-zero value, and is not a low-order point (see below).
7. `key_epoch >= 1` and `1 <= revoked_kem_epochs_below <= key_epoch` (`InvalidKeyEpoch`); `suites` non-empty, strictly ascending, no zero, at most 16 (`InvalidSuites`).
8. `inbox_buckets` in 1..=256; `created_at` and `kem_expires_at` non-negative; `created_at` not more than 24 h after `now_ms`.
9. `kem_expires_at`, if present, is greater than `now_ms`; otherwise `KemKeyExpired`. (Re-loading a persisted contact may use the variant that skips this check; sealing then re-checks it.)

KEM key validation. In `hpke` 0.15.1, `PublicKey::from_bytes` for X25519 only
checks the length, so validation is explicit: the all-zero key is rejected
directly, and then a trial HPKE seal of an empty message to the key is
performed; HPKE aborts if the Diffie-Hellman output is all-zero, which is what
every low-order input point produces (RFC 9180 section 7.1.4, which requires
this check for X25519 and refers to RFC 7748). A key that fails is rejected.

The verified contact exposes the original signed document so that it can be
persisted and re-verified later.

### Inbox topic

```
bucket = u16_be(SHA-256("agentnet/v1/inbox-topic" || signing_pk)[0..2]) mod inbox_buckets
topic  = "/agentnet/1/inbox-" || lowercase_hex2(bucket) || "/proto"
```

`inbox_buckets <= 256` guarantees two hex digits. All agents with the same
bucket share a topic and trial-decrypt every frame on it. `inbox_buckets` is
inside the signed record so senders cannot pick the wrong topic. Example:
the address above with 16 buckets is `/agentnet/1/inbox-06/proto`, with 256
buckets `/agentnet/1/inbox-c6/proto`.

Rotation, revocation and their limits are specified in section 9.

## 4. Envelope

The envelope is the logical message. It is serialized as JSON; the exact
serialized bytes are what is signed, and the receiver verifies and parses the
exact received bytes (nothing is re-serialized).

| Field | Type | Rule |
|---|---|---|
| `v` | integer | MUST be 1 |
| `message_id` | string | lowercase hyphenated UUIDv4 (version 4, RFC 4122 variant) |
| `sender` | string | address (section 2) |
| `recipient` | string | address (section 2) |
| `suite` | integer | the suite id the envelope was sealed under; MUST equal the frame header's suite byte |
| `recipient_key_epoch` | integer | the `key_epoch` of the recipient KEM key the frame was sealed to; MUST equal the epoch of the key that actually decrypted it |
| `type` | string | 1..=64 characters of `[a-z0-9._-]` |
| `conversation_id` | string, optional | 1..=128 printable ASCII characters 0x21..0x7e (no spaces); omitted when absent |
| `correlation_id` | string, optional | same rule |
| `created_at` | integer | Unix ms |
| `expires_at` | integer | Unix ms |
| `body` | string | any valid JSON string (UTF-8; includes empty, emoji, RTL text, `\u0000`) |

Senders serialize with fields in the order above and omit absent optional
fields. Receivers accept an absent or `null` optional field as "none". An
envelope is rejected if it has unknown fields, duplicate keys, missing
required fields, wrong types, trailing non-whitespace bytes, or invalid
UTF-8 (serde_json's derive-generated parser rejects duplicate and unknown
fields; this is covered by tests). Envelope `v` is read first with a minimal
parser: `v != 1` yields `UnknownEnvelopeVersion(v)` regardless of other
content.

### Message types

Unknown but syntactically valid `type` strings are accepted and stored as
data with their type string; they never receive special handling.

* `message`: ordinary message. Receipt is acknowledged with `ack.received`.
* `ack.received`: authenticated receipt acknowledgement. It is an ordinary sealed envelope from the recipient of the original message back to its sender, with `correlation_id` = the original `message_id` (and normally the original `conversation_id`). It means "the recipient's engine durably persisted the message with that id", sent only after persistence (`docs/architecture.md` section 5). Acks are never acknowledged. It is *not* evidence the message was read or acted on, and a transport accepting a publish is not receipt.
* `task.request`, `task.result`: request and response correlated by `correlation_id`. Their bodies are untrusted data like every other body; a receiver never executes them as code or instructions.
* `contact.update` (reserved, engine only): body is the sender's new signed contact-record document (section 9.3).
* `identity.revoked` (reserved, engine only): body is the sender's, or a contact's, signed identity-revocation tombstone (section 9.5).

`ack.received`, `contact.update` and `identity.revoked` cannot be sent through `send_message`; the engine creates them.

### Dedupe

Duplicate and replay detection is **not** part of `seal`/`open`. `open` is a
pure function; the same valid frame opens every time it is presented until it
expires. The engine MUST persist `(sender, message_id)` of every accepted
envelope and drop repeats (a repeat of an already-persisted message re-queues
the ack but creates no new message).

### Signing

```
env_bytes = JSON(envelope)
sig       = Ed25519(sender_sk, "agentnet/v1/envelope\0" || env_bytes)
inner     = sig(64) || env_bytes
```

The signature is inside the ciphertext. The receiver verifies with
`verify_strict` under the key of `envelope.sender`, and checks
`envelope.recipient` equals its own address. Because the recipient is inside
the signed bytes, a recipient cannot re-seal a message it received to a third
party and have it accepted there (surreptitious forwarding): the third party
sees `WrongRecipient`.

### Field protection audit: field -> protected by

Checked by the authors against `crypto/hpke_suite.rs` (this is not an independent audit): the signature is over the exact
serialized envelope (every envelope field), and the 4-byte frame header is
HPKE `aad`.

| Field / data | Protected by |
|---|---|
| frame magic, frame version, suite byte (header) | HPKE `aad`: any change makes the AEAD tag fail; the suite is additionally signed (`envelope.suite`) and compared with the header |
| `enc` (HPKE encapsulated key) | HPKE key schedule: a changed `enc` yields a different key, so the AEAD fails |
| ciphertext, length prefix, padding | AEAD tag (ChaCha20-Poly1305); after decryption the prefix is range-checked and padding must be all zero |
| recipient KEM key | HPKE `info` = `"agentnet/v1/hpke\0" \|\| recipient_kem_pk` |
| `v` (envelope version) | signature (and read first by a minimal parser) |
| `message_id` | signature |
| `sender` | signature (the verifying key is the one named by this field; `verify_strict`) |
| `recipient` | signature; compared with the receiver's own address (`WrongRecipient`) |
| `suite` | signature; compared with the frame header suite (`SuiteMismatch`) |
| `recipient_key_epoch` | signature; compared with the epoch of the KEM key that decrypted (`KeyEpochMismatch`) |
| `type`, `conversation_id`, `correlation_id` | signature |
| `created_at`, `expires_at` | signature; time checks at open |
| `body` | signature |
| contact record: `address`, `signing_pk`, `kem_pk`, `key_epoch`, `revoked_kem_epochs_below`, `suites`, `inbox_buckets`, `created_at`, `kem_expires_at` | signature by the address key (`agentnet/v1/contact-record\0`) |
| tombstone: `v`, `address`, `revoked_at`, `reason` | signature by the address key (`agentnet/v1/identity-revocation\0`) |

Not protected by any key and therefore untrusted: the content topic a frame
arrives on (a sender derives it from the signed `inbox_buckets`, but a relay or
attacker can republish a frame anywhere, which at worst makes it undeliverable),
the transport's timestamp, transport id and publisher identity. The engine never
relies on them for a security decision.

### Padding

```
plaintext = u32_be(len(inner)) || inner || 0x00 * pad
```

`len(plaintext)` is the smallest value in {512, 1024, 2048, ... (powers of
two)} that is at least `4 + len(inner)`, **except** when the resulting frame
would exceed `max_frame_len` (the transport's limit): then `len(plaintext)` is
`max_frame_len - 52`, the largest that fits. If `4 + len(inner) + 52 >
max_frame_len` the message does not fit and sealing fails with `TooLarge`
(reporting the body length and a hint of the maximum body length, counted as
JSON-encoded bytes, so quotes, backslashes and control characters count
more than once). At open, the length prefix must satisfy `64 < n <=` the
remaining plaintext length and every byte after `inner` must be `0x00`.

Fixed overhead: a frame is `52` bytes larger than its plaintext (header 4 +
enc 32 + AEAD tag 16); the plaintext holds `68` bytes (length 4 + signature
64) plus the envelope JSON. A minimal envelope (empty body, `message` type)
is about 289 bytes of JSON, so the smallest bucket (512) leaves about 155
bytes of body, and a smallest frame is 564 bytes.

### Time checks (at open)

With `now`, `skew` (default 120 000 ms) and `max_ttl` (default 7 days), in this order:

1. `created_at <= now + skew`, else `FromFuture`.
2. `expires_at > now`, else `Expired`.
3. `expires_at > created_at`, else `ExpiresBeforeCreated`.
4. `expires_at - created_at <= max_ttl`, else `TtlTooLong`.

Arithmetic saturates; there is no overflow path.

## 5. Frame

```
offset  len  field
0       2    magic            "AN" (0x41 0x4e)
2       1    frame version    0x01
3       1    suite id         0x01 = DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305
4       32   enc              HPKE encapsulated key
36      n    ciphertext       AEAD ciphertext of `plaintext` followed by the 16-byte tag
```

HPKE parameters (RFC 9180 section 5.1.1 for Setup in Base mode and section 6.1
for the single-shot API): mode Base, `pkR` = the recipient's KEM public key
from the verified contact record,

```
info = "agentnet/v1/hpke\0" || recipient_kem_pk (32 bytes)
aad  = header = 0x41 0x4e 0x01 0x01          (the first 4 bytes of the frame)
```

`info` binds the ciphertext to the specific recipient key and to this
protocol; `aad` authenticates the magic, version and suite, so they cannot be
altered or downgraded without the AEAD failing. (RFC 9180 section 8.1
recommends single-shot-only APIs use `info` for application data and not
`aad`. The `hpke` crate exposes both and uses them correctly; we use `aad`
for the header because it is per-message data.)

Open order (each failure rejects without further work):

1. `len(frame) <= max_frame_len`, else `FrameTooLarge`. Fewer than 4 bytes: `Truncated`.
2. Magic (`BadMagic`), frame version (`UnknownFrameVersion(v)`), suite: not registered `UnknownSuite(s)`; registered but not in this agent's own advertised `suites` list `SuiteNotAdvertised(s)`; fewer than 36 + 16 + 69 bytes: `Truncated`.
3. HPKE open with the current KEM key, then with every retired key whose `retire_at` is still in the future and whose epoch is not below `revoked_kem_epochs_below`. If none opens it: `NotForUs`. This is the normal outcome for other agents' frames sharing the bucket; it costs one decapsulation per candidate key and MUST NOT be logged above debug level. The epoch of the key that opened the frame is remembered.
4. Length prefix and zero-padding check (section 4).
5. Parse the envelope (version first, then strict).
6. Verify the signature under `envelope.sender`, then `recipient == self` (`WrongRecipient`), then `envelope.suite == header suite` (`SuiteMismatch`) and `envelope.recipient_key_epoch == epoch of the decrypting key` (`KeyEpochMismatch`), then field validation, then the time checks.
7. (Engine, outside `open`) dedupe on `(sender, message_id)`.

Every `seal` performs one HPKE single-shot encapsulation, which generates a
**fresh ephemeral X25519 key and a fresh HPKE context per message**; nothing is
cached or reused, and the sequence number is never advanced beyond 0. Tested:
two seals of the same envelope to the same recipient differ in `enc` and in
ciphertext, and 64 seals never repeat an `enc`
(`crates/core/tests/crypto.rs`, module `hardening`).

A frame that is "for us" but fails after step 3 is authentic-ciphertext
garbage: only the sender (or someone holding the recipient's public KEM key,
which is public) can produce it, so it is rejected without being stored.

### Versioning

Unknown frame version, suite, envelope version or contact record version are
rejected with a distinct error and are never partially processed. A new
cipher suite or format gets a new frame version or suite id.

#### No silent downgrade

There is no in-band negotiation; the suite choice comes from signed data:

* The recipient's signed contact record lists its `suites`. The sender chooses
  the highest suite that it supports and the record lists
  (`SuiteRegistry::seal`); if there is none, sealing fails with `NoCommonSuite`
  and the engine reports an error to the caller. It never falls back to a suite
  the record does not list, and a record cannot be edited without breaking its
  signature.
* The frame header (magic, frame version, suite) is HPKE `aad`, so altering any
  of those bytes makes the AEAD fail (tested bit by bit,
  `frame_version_and_suite_bytes_are_authenticated_as_aad`).
* The suite and the recipient key epoch are also inside the signed envelope and
  are checked against the frame header and the decrypting key (steps 6 above):
  an attacker that holds an old recipient key cannot re-wrap a message into a
  different suite or epoch unnoticed.
* The receiver rejects frames whose suite is not in its *own* currently
  advertised list (`SuiteNotAdvertised`), so a suite that was removed from the
  record is not accepted any more (tested with a second, test-only suite
  registered in a `SuiteRegistry`; no second real suite exists yet).

RFC 9180 section 9.7.2 notes that HPKE itself gives no downgrade prevention;
the measures above are the application-level answer. They are only as strong as
the integrity of the contact record the sender holds (section 9).

### Size limits

| Item | Limit |
|---|---|
| Contact document | 4096 bytes |
| Address | 61 characters |
| `type` | 64 characters |
| `conversation_id`, `correlation_id` | 128 characters |
| Frame | `max_frame_len`, supplied by the caller from the transport (library default 150 KiB) |
| Identity file / export | 256 KiB |
| TTL | `max_ttl` (default 7 days) |

## 6. Identity file and export

`identity.json` (mode 0600; the library creates it with that mode, writes a
temp file in the same directory, fsyncs, then renames; it refuses to replace
an existing file unless asked) is JSON
`{"v":1,"address","signing_sk","kem_sk","kem_created_at","inbox_buckets","created_at","kem_expires_at","previous_kems":[{"kem_sk","created_at","retire_at","epoch"}],"kem_epoch","min_valid_epoch"}`
with base64url secrets. `kem_epoch`, `min_valid_epoch` and each previous key's `epoch` are optional when reading (files written before epochs existed: retired keys are numbered 1..n, the current key n+1, `min_valid_epoch` 1). A rotation with revocation writes an empty `previous_kems`. A revoked identity additionally has `revocation.json` (the tombstone) next to it. On unix, load refuses a file readable by group or
others. Load validates everything (keys parse, the stored address equals the
address derived from the signing key). An export is the same JSON encrypted
with age's scrypt passphrase recipient and ASCII-armored; a wrong passphrase
and corruption are not distinguished.

## 7. Security properties

Provided, assuming the implementation and the endpoint hosts are not
compromised:

* **Confidentiality** of the envelope (including sender identity, type, ids and body) against anyone who does not hold a KEM private key that the sender sealed to: HPKE Base mode with ChaCha20-Poly1305 (RFC 9180 section 9.1, message secrecy against chosen-ciphertext attackers).
* **Sender authentication**: an envelope that opens successfully was signed by the holder of the Ed25519 key behind `envelope.sender`. HPKE Base mode itself authenticates nobody (anyone can encrypt to a public KEM key); authentication is the inner signature, which `verify_strict` checks.
* **Recipient binding**: the signature covers `recipient`, and HPKE `info` covers the recipient's KEM key, so a message cannot be redirected to another recipient.
* **Integrity**: any bit change anywhere in a frame is rejected (header by AEAD aad, the rest by the AEAD tag); tested exhaustively on a 564-byte frame.
* **Key binding**: a peer's KEM key is trusted only through a contact record signed by the address key.
* **Length hiding** within power-of-two buckets (RFC 9180 section 9.7.6 notes HPKE alone does not hide length).
* **Replay rejection**: *not* done here. HPKE provides none (RFC 9180 section 9.7.3); the time window bounds it and the engine's persisted `(sender, message_id)` set removes it, with the limits listed in section 10.

Not provided:

* **Forward secrecy** with respect to recipient compromise: anyone who obtains a recipient KEM private key (current or retained previous keys) can decrypt every past frame sealed to it that they have recorded (RFC 9180 section 9.7.4). Rotation limits future exposure only, and previous keys are retained for `retention` hours on purpose. Forward secrecy with respect to sender compromise holds for the ciphertext (ephemeral sender key).
* **Post-compromise security**: there is no ratchet. After a KEM key compromise, only rotation helps, and only for future messages.
* **Deniability**: every message carries a non-repudiable Ed25519 signature by the sender, verifiable by the recipient and, if the recipient reveals the plaintext, by anyone. This is deliberate (it provides sender authentication) and is the opposite of deniable authentication.
* **Metadata privacy** beyond bucket k-anonymity: relays see the content topic (the inbox bucket, hence "this recipient is one of the agents sharing bucket N"), timing, the padded frame size (power-of-two buckets, so sizes leak roughly log2 of the length), and the publishing node's network identity. The sender and recipient addresses are inside the ciphertext. Anyone watching a bucket sees every frame addressed to it, and bandwidth and trial-decryption cost grow with the bucket population. Bucket assignment is a public function of the address, so a third party who knows an address knows its bucket. The recipient's KEM key and address are not hidden from anyone who has the contact record.
* **Key-compromise impersonation**: RFC 9180 section 9.1.1 notes that HPKE messages can be forged "from" a sender by anyone who knows the recipient's private key unless the application adds a signature (it suggests one over `(enc, ct)`). Here the sender's Ed25519 signature covers the envelope bytes (not `enc`/`ct`), so holding a recipient's KEM key does not let an attacker create a *new* envelope that verifies as coming from the sender. It does let them re-seal an envelope the sender really signed (same bytes, same recipient field) to that recipient; the time window and the engine's dedupe bound that. Compromise of the recipient's KEM key still reveals content, and compromise of a sender's signing key allows impersonating that sender to everyone.
* **Protection against a compromised host**: secrets are stored unencrypted in `identity.json` (protected only by file mode 0600) and live in process memory; zeroization on drop is best-effort (copies made by the allocator, the OS, serde buffers or the HPKE library's temporaries are not tracked). Malware or a root user on the host can read them. The passphrase export protects the exported file only.
* **Revocation**: only what section 9 describes: KEM-key revocation propagated to contacts that are reachable (or that import the signed record), and a signed identity tombstone that reaches only the contacts that receive it. There is no directory, no global revocation list and no way to force a peer to learn of a revocation; a revoked-but-not-yet-informed peer keeps trusting the old keys. A thief of the signing key can impersonate the owner until peers learn of the tombstone and can issue the tombstone itself (denial of service).
* **Availability and ordering**: no ordering, no delivery guarantee; at-least-once delivery attempts by the engine.
* **Clock security**: time checks rely on the local clock, with a configurable skew. A host with a wrong clock may accept expired messages or reject valid ones.
* **Random number generation**: HPKE seal uses the operating system RNG (`getrandom`); if it is subverted or broken, confidentiality of Base mode can be lost completely (RFC 9180 section 9.7.5).
* **Post-quantum security**: X25519 and Ed25519 offer none.

Remote message content is untrusted data. Nothing in this protocol authorizes
a sender to cause code execution on the recipient.

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
recipient whose KEM key is not expired and whose signed record shares a suite
with us; type in `message`, `task.request`, `task.result`; body <=
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
When a recipient's contact record is replaced by a newer epoch (an imported
record or a `contact.update`), every `queued` or `sent` row for that recipient
whose TTL has not passed is **re-sealed** in the same transaction (same
envelope fields and `message_id`, fresh signature and ciphertext for the new
key, `next_attempt_at = now`), so pending messages survive the recipient's key
rotation. A tombstone for the recipient fails all its pending rows
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
`transport_seen`; `open` through the `MessageProtection` registry (limits from
config; `NotForUs` is silent and counted); trust lookup (`Blocked` dropped, which
includes an address with a verified tombstone, also when it is not a contact; an
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

## 9. Key epochs, rotation and revocation

No new cryptography is involved: only the existing Ed25519 signature with new
domain-separation strings, and ordinary sealed envelopes. Implemented in
`crates/core/src/crypto/{identity,contact,revocation}.rs` and
`crates/core/src/system.rs`; tested in `crates/core/tests/engine_hardening.rs`
and the `hardening` module of `crates/core/tests/crypto.rs`.

### 9.1 Epochs

`key_epoch` starts at 1 and each KEM rotation adds 1. For an address already in
the contact store:

| New record | Result |
|---|---|
| `key_epoch` lower than stored | rejected: `Conflict` "stale contact record"; the stored record is never replaced by an older one |
| equal, same signed content | accepted, no change (idempotent) |
| equal, different content | rejected: `Conflict` "conflicting contact record" |
| higher | replaces the stored record (trust and alias are kept) and re-seals pending outbox rows (section 8.2) |

`created_at` is informational. This replaces the earlier "older `created_at`
cannot replace a newer record" rule.

### 9.2 KEM rotation and KEM revocation

`agentnet identity rotate-kem` (daemon stopped, it takes the data-dir lock)
generates a new X25519 key, increments `key_epoch` and, by default, keeps the old
secret key for decryption until `retire_at` (overlap). With `--revoke-previous`
(`Identity::rotate_kem_with(.., revoke_previous = true)`) **every earlier KEM
secret key is destroyed immediately** (dropped and zeroized, not written to the
identity file) and the new record carries `revoked_kem_epochs_below = key_epoch`.
Consequences, stated plainly:

* Frames already sealed to a revoked epoch can never be opened again, including
  undelivered ones in transit or in a peer's outbox. They are lost unless the
  sender re-seals them after learning the new record (section 9.3, 9.4).
* A receiver that sees a record with `revoked_kem_epochs_below = N` keeps only
  records with `key_epoch >= N` (it discards older ones by the rule in 9.1) and
  never seals to an epoch below `N`.
* Revocation protects the future only: whoever already holds an old KEM secret
  key can still read what was sealed to it earlier. Destroying the key on the
  owner's side does not remove copies an attacker made.

### 9.3 Propagation without a directory: `contact.update`

At the next daemon start after a rotation (the engine compares
`identity.key_epoch` with the `announced_key_epoch` it stored) it queues a hidden
`contact.update` to every Trusted contact, sealed with the normal scheme, with
the new signed contact-record document as body. The sender is acked like any
message. A receiver applies it only if **all** hold: the sender is a Trusted,
non-revoked contact; the body verifies as a contact record; its address equals
the authenticated envelope sender (a Trusted contact cannot push someone else's
record); and its `key_epoch` is strictly higher than the stored one (a replayed
older update cannot roll a contact back; equal epochs with different content are
ignored as conflicting). Otherwise it is ignored and counted
(`contact_update.ignored_{invalid,wrong_address,stale,same,conflict,untrusted,no_contact,revoked}`).
A `contact.update` from an Unknown or Untrusted sender is stored like any other
message under the quarantine policy and is **not applied**. It is not stored in
the user inbox of a Trusted receiver, creates no event, and cannot be sent via
`send_message`.

A contact that was offline when the update was sent, or whose retries ran out
(section 8.2), never learns the new record this way and must be given the record
out of band (`agentnet contact add`); until then their messages are sealed to the
old epoch and, after `--revoke-previous`, are lost.

### 9.4 Re-seal on contact update

See section 8.2. The envelope (same `message_id`, `created_at`, `expires_at`,
body) is signed again with the new `recipient_key_epoch` and sealed to the new
key; the row's `frame` is replaced in the same transaction that replaces the
contact.

The send loop selects a batch of due rows and publishes them one after another
while a publish may take seconds. Immediately before each publish it therefore
re-reads the row (state, topic, frame) and skips it if a tombstone made it
unpublishable; the frame it publishes is always
the current one. The result of a publish is recorded only if the stored frame
is still the one that was published, so a re-seal that raced with a publish
leaves the row due for an immediate re-publish. A publish that is already in
flight when the tombstone or key update is applied cannot be recalled (tests
`revocation_during_a_pending_publish_stops_later_frames_of_the_batch`,
`key_update_during_a_pending_publish_publishes_the_resealed_frame`).

### 9.5 Identity (signing key) revocation

`agentnet identity revoke --reason <text>` (daemon stopped) creates the
tombstone and writes it to `revocation.json`:

```
record = {"v":1,"address":"an1…","revoked_at":<unix ms>,"reason":"<1..256 bytes, no control chars>"}
sig    = Ed25519(signing_sk, "agentnet/v1/identity-revocation\0" || record_bytes)
document = {"record":"<b64url(record_bytes)>","sig":"<b64url(sig)>"}      (at most 2048 bytes)
```

The tombstone is self-authenticating: the signature must verify under the very
address it names, so any party may carry it.

* **Local effect**: the identity is marked revoked. The daemon refuses
  `send_message` (`PolicyDenied`), queues no acks and publishes nothing except
  `identity.revoked` rows; `get_identity.revoked` and
  `network_status.identity_revoked` report it. Pending outbox rows are not
  sent. Revocation is irreversible for the address.
* **Delivery**: at the next start the engine sends `identity.revoked` (body = the
  tombstone) to every Trusted contact; `agentnet identity show-revocation`
  prints it for distribution out of band, and `agentnet contact revoke <@file>`
  imports one.
* **Receipt**: an `identity.revoked` envelope from any non-blocked sender is
  applied if the tombstone verifies and names the envelope sender **or** an
  existing contact (so a Trusted contact can forward someone else's tombstone,
  and a stranger can deliver only its own). A tombstone naming the receiving
  identity itself is never applied to it. An imported tombstone (out of band)
  needs no contact.
* **Effect on the revoked address**: stored in the `revocations` table; the
  contact is reported `Blocked` (inbound dropped as `drop.blocked`), sends to it
  fail with `PolicyDenied`, pending sends fail, it cannot be re-trusted
  (`set_contact_trust` -> `Conflict`) and `add_contact` for the address is
  refused (`Conflict`).

Honest limits: revocation reaches only contacts that are reachable within the
TTL and retry limits, or that obtain the document out of band; there is no
global revocation list and no way to find out who has not heard. Until a peer
learns of it, a thief of the signing key can impersonate the owner. A thief can
also issue a tombstone for the address, which is a denial of service (the owner
cannot un-revoke); that is accepted as the safer failure.

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
| Replay of a frame sealed to a revoked KEM epoch | cannot be opened at all (`NotForUs`) | `replay_across_kem_revocation_and_after_pruning` |
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
rules: an ack for a delivered row is ignored, an old record loses to a newer
epoch, a tombstone is idempotent). Held messages from non-trusted senders are
subject to the quarantine policy instead.

### 10.2 Concurrent identity

The same identity (signing key and KEM keys) running in two data directories
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
  PLAINTEXT. The document is `{"record": b64url, "sig": b64url}` over the record described in
  `docs/discovery.md` section 3, signed by the address key with the domain
  `agentnet/v1/capability-advert\0`. The record is `v` 2 and carries the discovery topic name it
  is published on, so the signature binds the topic; a receiver drops an advert (or withdrawal)
  whose signed topic differs from the topic it arrived on (`advert.invalid.topic_mismatch`) and
  refuses the earlier topic-less `v` 1. It embeds the advertiser's current signed contact record
  and is accepted only when that record verifies for the same address.
* The sealed frame (section 5) starts with `b"AN"`; the two magics differ so that a frame of one
  kind can never parse as the other. The engine routes by topic: an `AD` frame on an inbox topic
  and a sealed frame on a discovery topic are dropped and counted, never parsed as the other kind.
* A higher `seq` from the same address on the same topic replaces a lower one; equal or lower is
  ignored; an empty capability list with a higher `seq` is a withdrawal (kept as a hidden
  tombstone until its expiry so the replaced advert cannot be replayed).
* No new cryptographic construction: the only addition is the signing domain above (condition 4
  of `docs/crypto-requirements.md`).
