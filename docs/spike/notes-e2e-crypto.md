# Spike A2/B1: HPKE(base)+Ed25519 envelope over the local relay (disposable spike binary)

Crate: `spike/e2e-crypto/` (standalone, empty `[workspace]`, committed `Cargo.lock`). Results: `results/a2-e2e-crypto/`.
Everything below ran on **localhost / container network**: amd64 `logos-delivery v0.39.2` nodes (an-r1 service node, an-na, an-nb) under qemu on an arm64 macOS host that was heavily shared at the time (`uptime` load average 259 at 16:16), so every latency/CPU number is an upper bound and noisy. Not a real network test.

## 0. Reproduce

```
cd spike/e2e-crypto
cargo fmt --check && cargo clippy --all-targets -- -D warnings      # both exit 0 (results/a2-e2e-crypto/clippy-last.txt)
cargo run --release -- all                                           # or: roundtrip wrong-recipient forgery tamper replay expiry boundaries metadata bench load persistence
cargo run --release -- load --load-runs 100:50,100:200,100:1000 --pub-conc 8   # supplementary stress variant
# flags: --out DIR (default ../../results/a2-e2e-crypto) --work DIR --poll-ms N (default 25) --load-runs N:POLL,... --pub-conc N (default 2)
```
Every run writes `<test>-<ts>.json`, `summary-<cmd>-<ts>.json` and `run-<cmd>-<ts>.log` into the out dir. The authoritative full run is `summary-all-1795640646489.json` / `run-all-1795640646489.log` / `final-all-stdout.txt`: **11/11 tests PASS** (exit 0). Caveat: after that run I changed only the `bench` test (batch min/median reporting); the bench numbers quoted below come from three standalone runs with the final binary. The `persistence` test stops and restarts container `an-nb` (restored; topology verified afterwards, see section 6).

## 1. Construction as implemented (`src/crypto.rs`)

Crate versions from `Cargo.lock`: hpke 0.15.1 (`default-features=false, features=[alloc,getrandom,x25519,chacha]`, exact-pinned `=0.15.1`), ed25519-dalek 3.0.0, x25519-dalek 3.0.0 (transitive via hpke; the KEM keys are hpke's own types), curve25519-dalek 5.0.0, chacha20poly1305 0.11.0 (transitive via hpke), hkdf 0.13.0, sha2 0.11.2, rand_core 0.10.1, getrandom 0.4.3, tokio 1.54.1, reqwest 0.12.28. `rand` 0.10.4 appears in `Cargo.lock` but is NOT in the build graph (`cargo tree -i rand@0.10.4` -> "nothing to print"); randomness is `getrandom::fill` and hpke's `Kem::gen_keypair`. For the file lock I used std `File::try_lock` (Rust 1.89+, flock on unix), not fs4/fd-lock. Rust 1.92.0.

- Identity = Ed25519 `SigningKey::from_bytes(&getrandom 32 B)` + independent `Kem::gen_keypair()` (DHKEM(X25519,HKDF-SHA256)). Address = `"an1" + lowercase base32-nopad(pk32 || sha256("agentnet/v1/address-checksum"||pk)[..4])` (data-encoding); parse also rejects non-canonical (re-encode must equal input, so uppercase is rejected).
- Contact record = serde_json `{v:1, signing_pk(hex), kem_pk(hex), inbox_buckets:16, created_at}`, signature `Ed25519(domain "agentnet/v1/contact-record\0" || record_bytes)`. `verify_contact(address, record, sig)`: address -> pk+checksum, `verify_strict`, v==1, record.signing_pk==address key, buckets>0, KEM pk parses.
- Envelope = serde_json struct (field order as specified; `conversation_id`/`correlation_id` omitted when None). Exact serialized bytes are signed; receiver verifies the exact received bytes (never re-serialised). `type` field renamed via serde.
- Seal: `sig = Ed25519(sender_sk, "agentnet/v1/envelope\0"||env_bytes)`; plaintext `u32_be(64+len(env)) || sig || env || zero padding` to the next bucket in {512,1024,...}; HPKE single-shot Base; `info = "agentnet/v1/hpke\0" || recipient_kem_pk(32)`; `aad = 4-byte header`; frame = `b"AN" 0x01 0x01 || enc(32) || ct`.
- Open order: size cap (160 KiB) -> header (magic, version, suite) -> `Enc::from_bytes` -> HPKE open -> padding (length field in range, padding all zero) -> parse `{v}` only (reject != 1) -> full parse -> uuid-v4 shape of `message_id` -> sender/recipient addresses -> Ed25519 `verify_strict` under the sender address key -> `recipient == own address` -> `expires_at > created_at`, `created_at <= now+120 s`, `expires_at+120 s >= now` -> dedupe check, and only after all checks pass the (sender, message_id) is inserted (append + `sync_data` to a file `sender id expires_at_ms`; entries older than expires_at+skew pruned on load).
- Inbox topic: `/agentnet/1/inbox-<xx>/proto`, `xx = u16_be(sha256("agentnet/v1/inbox-topic"||signing_pk)[..2]) % inbox_buckets` as 2 hex digits.
- Waku message: payload base64, contentTopic, `timestamp = now ns`, `ephemeral=false`, published with `POST /relay/v1/auto/messages`; receive with `GET /relay/v1/auto/messages/{ct}`; recovery with `GET /store/v3/messages`.

### hpke API calls that compiled (hpke 0.15.1)
```rust
use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256,
           Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
type Kem = X25519HkdfSha256; type Kdf = HkdfSha256; type Aead = ChaCha20Poly1305;
type KemSk = <Kem as KemTrait>::PrivateKey; type KemPk = <Kem as KemTrait>::PublicKey; type Enc = <Kem as KemTrait>::EncappedKey;
// keygen / pk from sk / (de)serialise
let (kem_sk, kem_pk) = Kem::gen_keypair();                  // panics only if the system RNG fails
let kem_pk = Kem::sk_to_pk(&kem_sk);
let bytes = kem_pk.to_bytes().to_vec();                     // Serializable -> hybrid_array::Array<u8,32>
let kem_sk = KemSk::from_bytes(&bytes)?;  let kem_pk = KemPk::from_bytes(&bytes)?;   // Deserializable, Err on wrong length
// seal
let (enc, ct) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
    &OpModeS::Base, &rcpt_kem_pk, &info, &plaintext, &HEADER /*aad*/)?;
frame.extend_from_slice(&enc.to_bytes()); frame.extend_from_slice(&ct);        // ct already includes the 16 B tag
// open
let enc = Enc::from_bytes(enc_bytes)?;                                       // Err (not panic) on bad length
let pt = hpke::single_shot_open::<Aead, Kdf, Kem>(
    &OpModeR::Base, &kem_sk, &enc, &info, ct_and_tag, hdr /*aad*/)?;           // HpkeError::OpenError on any tamper
```
Ed25519 (ed25519-dalek 3.0.0): `SigningKey::from_bytes(&[u8;32])`, `use ed25519_dalek::Signer; sk.sign(&msg).to_bytes()`, `VerifyingKey::from_bytes(&pk)?`, `vk.verify_strict(&msg, &Signature::from_bytes(&[u8;64]))` (`Signature::from_bytes` is infallible in 3.x). `verifying_key().to_bytes()`.

**Anything the libraries could not express: nothing in the construction.** Notes: (1) `single_shot_seal`/`gen_keypair` panic if the system RNG fails (documented), they do not take untrusted input; (2) hpke's default features pull ML-KEM/X-Wing, which I disabled; (3) HPKE Base does not authenticate the sender, so sender authentication rests entirely on the inner Ed25519 signature (the tests below exercise exactly that).

## 2. Results per test

| # | test | result | key numbers | evidence |
|---|---|---|---|---|
| 1 | round trip over relay | PASS | A->B 100/100, B->A 100/100 (replies carry correlation_id of the A message); app duplicates 0; wire duplicates 0; integrity failures 0. Latency (Instant before publish call -> poller receive, poll 25 ms): A->B p50/p95/p99 = 24.6/39.8/50.3 ms (max 52.1); B->A 28.0/239.2/325.7 ms (max 326.7). Publish call p50/p95/p99 = 3.8/9.8/16.7 ms | `roundtrip-1795640646489.json` |
| 2 | wrong recipient | PASS | B (intended) 10/10 opened; C (same bucket topic `inbox-0b`, polled via the other node) 0 opened, 10/10 `hpke_open: Failed to open ciphertext`; D (other bucket, in process) 10/10 hpke_open | `wrong-recipient-1795640646489.json` |
| 3 | forgery / forwarding | PASS | M seals envelope claiming sender=A, signed by M -> B: `bad_signature` (1/1) while the honest control from A opened. B re-seals A's valid (sig, envelope) to C -> C: `wrong_recipient` (1/1; signature is checked before recipient, so this is the recipient binding rather than a bad signature). Contact records: tampered byte, wrong address, altered checksum char, uppercase address, KEM-key substitution signed by M -> all rejected; two controls accepted | `forgery-1795640646489.json` |
| 4 | tamper / fuzz | PASS | every single bit of a 564 B frame flipped: header 32/32, enc 256/256, ciphertext body 4096/4096, tag 128/128 rejected; truncation to every length 0..563: 564/564 rejected; extension by 1..64 B: 64/64 rejected; 1000 random frames: 0 panics (bad_magic 485, hpke_open 487, short_frame 28); 1000 HPKE-authenticated random plaintexts: 0 panics (bad_padding 691, envelope_parse 309); control frame opens | `tamper-1795640646489.json` |
| 5 | replay | PASS | same frame re-published with a fresh Waku timestamp (distinct hash): both deliveries reached B, 1 accepted, 1 `replay`; Store query via NB returned both entries, both `replay`; reload dedupe from file (1 line) in a fresh object: `replay`; control with an empty dedupe accepts (dedupe is the defence) | `replay-1795640646489.json`, dedupe file `work/replay-dedupe-1795640668481.txt` |
| 6 | expiry/skew/version/unknown field | PASS | 20 cases all as expected (table in section 3) | `expiry-1795640646489.json` |
| 7 | identity persistence | PASS | see section 4 | `persistence-1795640646489.json` |
| 8 | payload boundaries | PASS | see section 5 | `boundaries-1795640646489.json` |
| 9 | load 1/10/100 clients | PASS (as a measurement; delivery is NOT 100% in all configurations) | table in section 7 | `load-1795640646489.json` (+ `load-1795641030155.json` stress) |
| 10 | relay-visible metadata | PASS | section 8 | `metadata-1795640646489.json` |
| - | micro-benchmark | PASS | section 7 | `bench-1795641376189.json`, `-...382214`, `-...385809` |

## 3. Test 6 detail (policy: reject only an unknown envelope `v`)
Implemented policy, decided and reported: unknown extra JSON fields are **ignored** (serde default; they are still covered by the signature because the exact received bytes are verified); unknown `v` rejected (`v=0`, `v=2`; `v` as string or missing -> `envelope_parse`). Skew: `created_at` accepted up to now+120 s (60 s ok, 130 s rejected; 10 min rejected), `expires_at` accepted until expires_at+120 s (60 s past ok, 130 s past rejected, 5 min past rejected), `expires_at <= created_at` rejected. No max-TTL rule is implemented (recommend adding one, e.g. 30 days, to bound dedupe growth). Also tested: non-uuid `message_id`, non-address sender, trailing garbage after JSON, empty envelope (`bad_padding`: inner length 64), a 50 000-deep nested unknown field (accepted: serde_json skips it iteratively, no stack overflow; bounded by the 160 KiB frame cap), a 50 000-deep array in `body` (`envelope_parse`), frame >160 KiB (`frame_too_large` before any crypto).

## 4. Test 7 detail (run `persistence-1795640646489.json`, log in `run-all-1795640646489.log`)
- Identity saved by `Identity::save`: write temp file with `mode(0o600)`, `fsync`, rename; mode verified `600`. `Identity::load` refuses any group/other permission bits (mode 644 -> exit 4, `refusing identity file with permissions 644 (must be 0600)`).
- New OS process (`child-show`, the same binary) loads the identity: same address.
- Lock: `<dir>/.lock`, exclusive non-blocking `try_lock`. With the parent holding it, a second process exits 3 with `LOCKED: data dir ... is locked by another instance`; a second in-process acquire is refused; two child processes: the second is refused while the first sleeps holding the lock, and starts fine after the first exits.
- Offline recovery: `docker stop an-nb`; A published 20 sealed messages to B's inbox topic through NA with 0 failures; `docker start an-nb`: REST healthy and connected to R1 after 4.7 s. A **new process** (`child-recover`, B not running during the sends) loaded B's identity from disk and fetched `GET /store/v3/messages` through **NB's own store client** (no peerAddr): 20 store entries, **20/20 accepted, ids equal to the sent ids, none rejected**. A second new process with the persisted dedupe file: **0 accepted, 20 rejected as replay** (20 entries loaded from disk), so nothing processed twice.
- Migration: only `identity.json` copied to another directory (copy kept mode 600), loaded by another process: same address, empty dedupe, **20/20 decrypted**.
- Surprises: after NB restarted and re-subscribed, R1 listed NB as a mesh peer only after 62.8 s (earlier dev run) / 67.7 s (final run) although NB's REST was healthy and connected to R1 within 1.7-4.7 s (store recovery does not need the mesh, so the test is unaffected; live relay after a client-node restart is degraded for about a minute). Also, `ensure_mesh` drained 20 already-cached messages (in both the dev and the final run) from NB's REST cache right after re-subscribe, i.e. NB's relay cache already contained the offline messages (mechanism not investigated: probably gossip history on re-join). Do not rely on it; Store is the recovery path.

## 5. Test 8 detail (payload limits)
- Raw node limit for our content topic (`/agentnet/1/inbox-xx/proto`, 26 chars): bisecting random payloads gave **max accepted payload = 153 523 B**, which equals `153600 - (len(contentTopic) + 51)` (the 51 B being protobuf framing for payload tag/len, topic tag/len, 9-byte timestamp varint and the explicit `ephemeral` field); measured and the formula agree exactly. Just over: 153 524, 153 525, 153 543 -> `HTTP 400 ... publish failed in relay: NoPeersToPublish` (misleading); 153 623, 200 000, 2 000 000 -> `HTTP 400 Failed to publish: Message size exceeded maximum of 153600 bytes`.
- Frame overhead is 52 B (4 header + 32 enc + 16 tag) plus plaintext = 4 + 64 + envelope + padding. Envelope JSON overhead with empty body (type "chat", two 61-char addresses, uuid, timestamps) = 286 B. base64 expansion happens only on the REST hop: it does not count toward the 150 KiB node limit (that applies to the decoded payload), but REST request bodies are ~4/3 larger.
- **Effective max body (ASCII, no JSON escaping): 130 718 B with the spec's pure power-of-two padding** (largest bucket that fits is 131 072 B plaintext = 131 124 B frame; the next bucket, 262 144, cannot fit). With a cap rule (**powers of two up to the cap, last bucket = cap = node payload limit - 52 = 153 471 B plaintext**) the max body is **153 117 B**. Both maxima were published over the relay and decrypted at B; body+1 was rejected locally before publish in both policies (`local reject: frame 262196 B > node limit 153523 B`, `plaintext exceeds padding policy cap`); bypassing the local check the node answered `HTTP 400 ... Message size exceeded maximum of 153600 bytes` for the 262 196 B frame.
- **Recommendation**: define padding buckets as 512 * 2^k up to 64 KiB and a final bucket equal to the largest sendable plaintext (limit - topic overhead - 52), instead of unbounded doubling; reject locally when the sealed frame exceeds `153600 - (topic_len + 51)` and never rely on node errors (the error text for 1-20 B over the limit is `NoPeersToPublish`). Make the limit a configuration value tied to the node's `--max-msg-size`, and note that JSON escaping reduces the usable body for control-character-heavy bodies (up to 6x for `\u00XX`); binary bodies need base64 (4/3). Bodies above roughly 64 KiB leak size at a coarse granularity (one bucket) anyway.
- Unicode body (emoji incl. ZWJ family and flag, Hebrew and Arabic RTL, U+202E override, NUL, control chars, U+2028/2029, BOM, quotes/backslash/escapes, combining accent) round-trips byte-exact over the relay; the envelope bytes received equal the bytes sealed; NUL is serialized as `\u0000`.

## 6. Topology state
After all runs: `curl /admin/v1/peers` R1 = [Connected, Connected], NA = [Connected], NB = [Connected]; `/health` READY on all three; containers an-r1, an-na, an-nb up (an-nb was restarted by the persistence test; `ffi-dev` untouched). `post-run-health-check-metadata.txt`: a real publish/store/decrypt run after the full run passed. `/admin/v1/peers/mesh` on R1 flaps between 1 and 2 entries while delivery works.

## 7. Test 9 and benchmark detail
Setup: logical clients alternate NA/NB; **one poller per (node, topic)** fans out to every logical client on that bucket (GET is destructive, so two pollers on one topic of one node would steal each other's messages); every client trial-decrypts everything in its bucket; each of N clients sends 10 messages to a random other client (N=1: to itself), per-client pacing 20 ms, publish concurrency semaphore 2 (default). Poll interval = column below (32 pollers = both nodes x 16 buckets; empty buckets are polled at max(poll,500 ms) just to drain). REST cache capacity = 50 (the node setting, shared by all topics). Both nodes stay subscribed to all 16 buckets.

| clients | poll ms | sent | delivered unique | rate | app dups | trial-decrypt failures observed / expected | latency p50/p95/p99 ms | max batch in one poll |
|---|---|---|---|---|---|---|---|---|
| 1 | 50 | 10 | 10 | 100% | 0 | 0 / 0 | 112 / 241 / 241 | 5 |
| 10 | 50 | 100 | 100 | 100% | 0 | 72 / 72 | 404 / 1939 / 2703 | 7 |
| 100 | 50 | 1000 | 1000 | 100% | 0 | 6695 / 6695 | 141 / 468 / 783 | 4 |
| 100 | 200 | 1000 | 995 | 99.5% | 0 | 5515 / 5532 | 343 / 5984 / 6832 | 7 |
| 100 | 1000 | 1000 | 879 | 87.9% | 0 | 5067 / 5801 | 963 / 11777 / 13701 | 10 |

"Expected" failures = for each sent message, for each node that polls that bucket, (clients of that bucket on the node) minus the intended recipient if it is on that node; observed==expected exactly in the 100%-delivery runs. Supplementary stress (publish concurrency 8, `load-1795641030155.json`, `load-stress-conc8-stdout.txt`): 100 clients delivered 84.8% at poll 50 ms, 65.3% at 200 ms, 40.8% at 1000 ms, with tail latencies of 20-33 s and node CPU 111-202% (docker stats). Earlier dev runs in `dev/` (e.g. `dev/load-1795639939898.json`: 89.1% at 50 ms and 34.3% at 1000 ms at concurrency 8; concurrency 1: 91.5% at 200 ms, 48.3% at 1000 ms in `dev/load-1795640206019.json`).

Interpretation (partly inferred, not proven): (a) with a 1000 ms poll and ~90 msg/s into 2 nodes, the cumulative arrivals per poll interval exceed the shared 50-slot cache and messages are lost (48% delivered, latencies <1 s for the survivors, which matches eviction); (b) at faster polls the remaining loss and multi-second to 30 s tails coincide with node CPU saturation (R1 and clients above 100% CPU in `docker stats` taken 1.2 s into the send phase; the host was also heavily loaded), so they are node/host overload and relay delays, not decryption. Per-topic batch sizes never exceeded 15 so the 50-slot cache total could not be observed directly (no API). A real adapter must poll every subscribed topic on each node (including buckets it has no client in) or the shared cache fills with other buckets' messages; polling 32 topics every 50 ms is about 640 GET/s across the two nodes and visibly loads a qemu node, so MVP should use a small number of buckets per node, adaptive polling, and Store reconciliation for gaps.

Micro-benchmark (host macOS arm64 native, release, 10 000 ops in 20 batches; the host was loaded so the minimum batch is the best estimate), per operation:
| op | min-batch us | median-batch us (3 runs) |
|---|---|---|
| failed open by non-recipient (`decrypt_frame`: header + HPKE decap + AEAD fail) | 52.5 / 54.3 / 58.7 | 63.9 / 71.2 / 117.1 |
| successful HPKE open + unpad | 52.8 / 53.4 / 66.7 | 58.0 / 74.9 / 117.9 |
| full `open_frame` incl. Ed25519 verify | 97.1 / 101.0 / 102.0 | 111.3 / 118.5 / 180.1 |
| seal (sign + HPKE seal, 564 B frame) | 80.8 / 81.1 / 94.8 | 98.0 / 107.9 / 126.8 |
| short frame rejection | ~0.002 | ~0.002 |
So trial decryption costs ~55 us of X25519 decap per unrelated message: a client that sees 10 foreign messages/s in its bucket spends ~0.05% of a core; at 1000/s about 5%.

## 8. Test 10: what R1's Store returns (`metadata-1795640646489.json`, log in `run-all-...log`)
For three A->B messages (body 1 B, 115 B, 166 B) R1's store (`GET /store/v3/messages?contentTopics=...&includeData=true`) returned per message exactly: `messageHash` (0x sha256 hex; recomputed locally from pubsub||payload||contentTopic||timestamp and matched 3/3), `pubsubTopic` `/waku/2/rs/66/0`, `contentTopic` (the recipient's bucket), `timestamp` (ns, publisher clock), `payload` (564 / 564 / 1076 bytes), `version` 0, `meta` null, `ephemeral` false. The first 4 payload bytes are the cleartext header `41 4e 01 01`. Bodies of 1 B and 115 B (same 512 bucket) gave **identical payload length 564**; 166 B moved to the 1024 bucket (1076). No envelope plaintext string (sender, recipient, type, conversation id, body filler, `agentnet/v1`) appears in the wire payloads.
Not visible in the payload: envelope `v`, `message_id`, sender address, recipient address, `type`, `conversation_id`, `correlation_id`, `created_at`, `expires_at`, `body`, the inner signature, and the body length inside a bucket. Visible to relays/store: pubsub topic, recipient's inbox bucket (1 of 16, stable per recipient so it links messages to the same recipient bucket over time and co-locates ~1/16 of all identities), publish time, bucket-granular size, the HPKE `enc` (random per message), the 4-byte header. The publisher's network address as seen by its first-hop node is UNTESTED here.

## 9. Bugs, surprises, caveats (all observed)
1. **`DELETE /relay/v1/auto/subscriptions` of one content topic drops the node out of R1's relay mesh** even though another content topic on the same shard stays subscribed (`results/a2-e2e-crypto/unsub-experiment.txt`: R1 mesh peers 2 -> 1 and stayed 1 for 8+ s; re-POST restored it). My first harness unsubscribed pollers' topics at the end of each test and the next test then lost messages; the final harness never unsubscribes.
2. **R1 reporting both nodes as mesh peers is not a sufficient readiness check.** The very first run had no readiness check at all: A->B delivered 65/100 with p50 1013 ms / p99 3849 ms and B->A 100/100 (`dev/roundtrip-1795639623843.json`; R1's mesh list was empty afterwards because of item 1). After I added a check that waits for R1 to list both nodes as mesh peers, a later full run still lost 40% of A->B (60/100, B->A 100/100; `dev/aborted-run/roundtrip-1795640386876.json`, the check had taken 37.75 s). I then added an end-to-end canary (5 consecutive bidirectional canary round trips through a keeper topic); all later runs, including the final full run, delivered 100/100. Cause not established (gossip fallback is my guess from the 1-4 s latencies).
3. After a client node restart the mesh took 62.8 s and 67.7 s to include NB again (section 4) although REST health and the R1 connection returned in 1.7-4.7 s.
4. `NoPeersToPublish` is returned for payloads 1-20 B over the limit (section 5). Always check size locally.
5. Same-bucket sender/recipient: if A and B hash to the same bucket and are on different nodes each also receives the other's messages (own-direction echo): `hpke_open` failures 100/100 on each side in `dev/aborted-run/roundtrip-1795640386876.json`. This is the intended cost of 16 buckets; counted, not a bug.
6. The REST cache is shared by all topics of a node and a node keeps caching topics it is subscribed to even if nobody polls them, so a harness must drain/poll all of them (`ensure_mesh` drained 0-96 stale messages between tests).
7. Host noise: the benchmark means varied 53-830 us per failed open between runs because the machine was shared (load average 259); use the min batch.
8. Bugs in my own harness fixed along the way (all recorded in `dev/`): metadata test body sizes computed from an envelope without `conversation_id` (wrong bucket expectation); expiry expectations for deep nesting/empty envelope (corrected after observing serde_json behaviour, see section 3); clippy found an async-lock-held-across-await in the forwarding test.

## 10. UNTESTED
Real multi-host network / NAT; amd64 native nodes; any attacker-controlled relay (a malicious relay dropping, reordering or duplicating beyond what the dedupe test covered); store paging beyond 100 entries and retention expiry; clock skew > 20 s making R1's archive refuse messages (documented in `notes-daemon-rest.md` E3); concurrent writers on the dedupe file from two processes without the dir lock; dedupe file growth/compaction at scale (only prune-on-load of expired entries exists); key rotation (contact record carries no epoch/expiry, only the "A signs a new kem_pk" shape was accepted by `verify_contact`); forward secrecy against recipient key compromise (not provided by Base mode); timing side channels; hpke crate has no formal audit; `rand`-based sampling of messages was not used. Peer-selection in the load test uses `getrandom` modulo bias (negligible). The 100-client load test shares one process, so per-client REST isolation, OS limits and memory per client were not tested.
