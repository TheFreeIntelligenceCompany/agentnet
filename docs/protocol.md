# AgentNet wire protocol, version 1

Status: normative for the MVP. Implemented by `crates/core` (`address`,
`contact`, `identity`, `envelope`). Design rationale is in
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
| Signatures | Ed25519, verified with the *strict* rules (`verify_strict`: rejects small-order keys and non-canonical signatures) | `ed25519-dalek` 3.x |
| Hash | SHA-256 | `sha2` |
| Encryption | HPKE (RFC 9180) Base mode, DHKEM(X25519, HKDF-SHA256) = 0x0020, HKDF-SHA256 = 0x0001, ChaCha20-Poly1305 = 0x0003 (RFC 9180 section 7.1, 7.2, 7.3) | `hpke` =0.15.1 |
| Passphrase export | age (scrypt recipient), ASCII armor | `age` 0.12 |

There is no hand-written cryptography. The Ed25519 signing key and the X25519
KEM key are generated independently; neither is derived from the other.

All domain-separation strings are ASCII and are used byte-exactly:

| String | Used for |
|---|---|
| `agentnet/v1/address-checksum` | address checksum hash input prefix |
| `agentnet/v1/inbox-topic` | inbox bucket hash input prefix |
| `agentnet/v1/contact-record\0` | contact record signature input prefix |
| `agentnet/v1/envelope\0` | envelope signature input prefix |
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
{"v":1,"address":"an1…","signing_pk":"<b64url>","kem_pk":"<b64url>","inbox_buckets":16,"created_at":1700000000000,"kem_expires_at":null}
```

* `b64url` is RFC 4648 section 5 base64url without padding; decoders MUST reject padding and non-canonical trailing bits.
* `signing_pk`: 32 bytes. `kem_pk`: 32-byte X25519 public key.
* `inbox_buckets`: integer in 1..=256 (default 16).
* `created_at`: when this record (this KEM key) was created. After a KEM rotation the record's `created_at` is the rotation time, so a newer record for the same address has a larger `created_at`.
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
7. `inbox_buckets` in 1..=256; `created_at` and `kem_expires_at` non-negative; `created_at` not more than 24 h after `now_ms`.
8. `kem_expires_at`, if present, is greater than `now_ms`; otherwise `KemKeyExpired`. (Re-loading a persisted contact may use the variant that skips this check; sealing then re-checks it.)

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

### Rotation and revocation limits

`rotate-kem` creates a new KEM key under the same address and issues a new
contact record. The old key remains usable for decryption until a configured
`retire_at`; after that (or after pruning) frames sealed to it can no longer
be opened. Peers must obtain and import the new record; there is no
push-update channel. There is **no revocation**: if the signing key is
compromised the address is compromised and a new identity (new address) is
required. Compromise of a KEM key is repaired only by rotation; frames sealed
to it before rotation stay readable to whoever holds it.

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
2. Magic (`BadMagic`), frame version (`UnknownFrameVersion(v)`), suite (`UnknownSuite(s)`); fewer than 36 + 16 + 69 bytes: `Truncated`.
3. HPKE open with the current KEM key, then with every retired key whose `retire_at` is still in the future. If none opens it: `NotForUs`. This is the normal outcome for other agents' frames sharing the bucket; it costs one decapsulation per candidate key and MUST NOT be logged above debug level.
4. Length prefix and zero-padding check (section 4).
5. Parse the envelope (version first, then strict).
6. Verify the signature under `envelope.sender`, then `recipient == self` (`WrongRecipient`), then field validation, then the time checks.
7. (Engine, outside `open`) dedupe on `(sender, message_id)`.

A frame that is "for us" but fails after step 3 is authentic-ciphertext
garbage: only the sender (or someone holding the recipient's public KEM key,
which is public) can produce it, so it is rejected without being stored.

### Versioning

Unknown frame version, suite, envelope version or contact record version are
rejected with a distinct error and are never partially processed. A new
cipher suite or format gets a new frame version or suite id; there is no
in-band negotiation (RFC 9180 section 9.7.2 notes HPKE gives no downgrade
prevention; here the suite is fixed per frame version and authenticated in
`aad`).

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
`{"v":1,"address","signing_sk","kem_sk","kem_created_at","inbox_buckets","created_at","kem_expires_at","previous_kems":[{"kem_sk","created_at","retire_at"}]}`
with base64url secrets. On unix, load refuses a file readable by group or
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
* **Replay rejection**: *not* done here. HPKE provides none (RFC 9180 section 9.7.3); the time window bounds it and the engine's persisted `(sender, message_id)` set removes it.

Not provided:

* **Forward secrecy** with respect to recipient compromise: anyone who obtains a recipient KEM private key (current or retained previous keys) can decrypt every past frame sealed to it that they have recorded (RFC 9180 section 9.7.4). Rotation limits future exposure only, and previous keys are retained for `retention` hours on purpose. Forward secrecy with respect to sender compromise holds for the ciphertext (ephemeral sender key).
* **Post-compromise security**: there is no ratchet. After a KEM key compromise, only rotation helps, and only for future messages.
* **Deniability**: every message carries a non-repudiable Ed25519 signature by the sender, verifiable by the recipient and, if the recipient reveals the plaintext, by anyone. This is deliberate (it provides sender authentication) and is the opposite of deniable authentication.
* **Metadata privacy** beyond bucket k-anonymity: relays see the content topic (the inbox bucket, hence "this recipient is one of the agents sharing bucket N"), timing, the padded frame size (power-of-two buckets, so sizes leak roughly log2 of the length), and the publishing node's network identity. The sender and recipient addresses are inside the ciphertext. Anyone watching a bucket sees every frame addressed to it, and bandwidth and trial-decryption cost grow with the bucket population. Bucket assignment is a public function of the address, so a third party who knows an address knows its bucket. The recipient's KEM key and address are not hidden from anyone who has the contact record.
* **Key-compromise impersonation**: RFC 9180 section 9.1.1 notes that HPKE messages can be forged "from" a sender by anyone who knows the recipient's private key unless the application adds a signature (it suggests one over `(enc, ct)`). Here the sender's Ed25519 signature covers the envelope bytes (not `enc`/`ct`), so holding a recipient's KEM key does not let an attacker create a *new* envelope that verifies as coming from the sender. It does let them re-seal an envelope the sender really signed (same bytes, same recipient field) to that recipient; the time window and the engine's dedupe bound that. Compromise of the recipient's KEM key still reveals content, and compromise of a sender's signing key allows impersonating that sender to everyone.
* **Protection against a compromised host**: secrets are stored unencrypted in `identity.json` (protected only by file mode 0600) and live in process memory; zeroization on drop is best-effort (copies made by the allocator, the OS, serde buffers or the HPKE library's temporaries are not tracked). Malware or a root user on the host can read them. The passphrase export protects the exported file only.
* **Revocation**: none (section 3).
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

`send_message` validates (known, non-blocked recipient whose KEM key is not
expired; type in `message`, `task.request`, `task.result`; body <=
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
  `next_attempt_at = now + d`, `d` uniform in `[1, min(retry_max_ms, retry_base_ms * 2^(n-1))]`
  milliseconds (full jitter; defaults 2000 / 300000; seedable via
  `delivery.jitter_seed`).
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
`transport_seen`; `open` (limits from config; `NotForUs` is silent and counted);
trust lookup (`Blocked` dropped; an ack from a non-Trusted sender is ignored,
never quarantined); `unknown_senders` policy for non-Trusted senders
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
every `history_sync_interval_s` (60). A pass queries
`[max(watermark - history_overlap_s, now - retention_hours), now + clock_skew]`
in windows of at most the transport's `max_history_window_ns`, following page
cursors, and advances the watermark to the pass's start time only if every page
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
| Inbox, outbox terminal rows | pruned after `retention_hours` (168) by maintenance (unread rows included) |
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
