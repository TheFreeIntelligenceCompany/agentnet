Reviewed HEAD `18ecac8e51720ca5334991e42b994f915234b486` against the requested documents. No files modified, network/Docker commands run, or tests executed. Findings below are confirmed by static code-path tracing, not runtime reproduction.

**Confirmed defects, ranked by severity**

1. **High — Allowed clock skew bypasses the rollback replay guard.**  
   [ingest.rs:238](/Users/dennison/develop/FIC-elipsis/crates/core/src/ingest.rs:238), [hpke_suite.rs:302](/Users/dennison/develop/FIC-elipsis/crates/core/src/crypto/hpke_suite.rs:302)

   Opening accepts messages created up to `clock_skew_ms` ahead, but the guard holds only messages created *before* its start. A trusted sender running 120 seconds ahead sends a message that is accepted. Restore a pre-message database and restart five seconds later: replaying that frame bypasses the active guard because its signed creation time remains in the future. It is delivered, acknowledged, and eligible to trigger again.

   **Fix:** include the permitted skew in the guard cutoff, including the equality boundary. Add a rollback test using a future-but-valid timestamp; existing rollback tests use a shared clock and miss this case. The documented rollback protection is therefore incomplete.

2. **High — Cached send batches publish obsolete frames after revocation or key updates.**  
   [send.rs:269](/Users/dennison/develop/FIC-elipsis/crates/core/src/send.rs:269), [send.rs:325](/Users/dennison/develop/FIC-elipsis/crates/core/src/send.rs:325), [system.rs:273](/Users/dennison/develop/FIC-elipsis/crates/core/src/system.rs:273), [system.rs:370](/Users/dennison/develop/FIC-elipsis/crates/core/src/system.rs:370)

   `step_send` copies an entire batch’s frames into memory before publishing sequentially. While its first publish awaits, another task can apply a recipient tombstone or replace pending frames following a key update. Subsequent batch entries still publish the cached frames without checking current state.

   Thus, messages marked failed by revocation can still be transmitted. After rotation following key compromise, a previously unpublished message can be transmitted under the compromised old key despite its database row having been re-sealed.

   **Fix:** coordinate publication with revocation/re-sealing, fetch current rows immediately before dispatch, and use a row revision to prevent obsolete publish results from overwriting newer retry state. Test with a transport that pauses the first publish while a later batch recipient is revoked or rotated.

3. **Medium — Accepting rollback releases content from subsequently blocked or revoked senders.**  
   [system.rs:546](/Users/dennison/develop/FIC-elipsis/crates/core/src/system.rs:546)

   `release_held` clears quarantine, emits `message.received`, and attempts an acknowledgement without checking current sender trust or revocation. A message held while its sender was trusted becomes normally visible after rollback acceptance even if that sender was subsequently blocked. Its stored trust also remains “trusted.”

   **Fix:** reapply current trust, revocation, and unknown-sender policy inside the release transaction. Add held-message → block/revoke → accept-rollback tests. Ordinary quarantine release already performs a current-trust check.

4. **Medium — Successfully published acknowledgements accumulate permanently.**  
   [send.rs:328](/Users/dennison/develop/FIC-elipsis/crates/core/src/send.rs:328), [node.rs:874](/Users/dennison/develop/FIC-elipsis/crates/core/src/node.rs:874), [node.rs:907](/Users/dennison/develop/FIC-elipsis/crates/core/src/node.rs:907)

   Published acknowledgements become `sent` with no next attempt. Maintenance explicitly excludes sent acknowledgements from expiration, while pruning removes only `delivered`, `failed`, or `expired` rows. Acknowledgements are never themselves acknowledged, so their normal lifecycle never reaches a prunable state.

   Every received message—and each permitted re-ack—therefore leaves a permanent outbox row containing its frame and metadata. Normal traffic causes unbounded database growth despite configured retention.

   **Fix:** treat published acknowledgements as terminal for retention, or explicitly prune old sent acknowledgements. Test maintenance beyond retention after successful ack publication and repeated re-acks.

5. **Medium — Valid remote traffic can make quarantine listing exceed the control protocol limit.**  
   [api_impl.rs:153](/Users/dennison/develop/FIC-elipsis/crates/core/src/api_impl.rs:153), [proto.rs:19](/Users/dennison/develop/FIC-elipsis/crates/daemon/src/proto.rs:19), [client.rs:187](/Users/dennison/develop/FIC-elipsis/crates/daemon/src/client.rs:187)

   Quarantine listing returns up to 1,000 complete bodies in one response; clients reject lines exceeding 64 MiB. An unknown sender can fill quarantine with 1,000 valid messages containing 40,000 quote or backslash characters each. Each encoded envelope fits the default frame limit, but the combined escaped JSON response exceeds 80 MB.

   `agentnet quarantine list` then fails repeatedly, and an oversized response terminates the multiplexed connection, failing other pending calls.

   **Fix:** paginate quarantine results and enforce a serialized response-byte budget. Test a full quarantine containing heavily escaped bodies.

6. **Medium — Malformed peer entries pass the supposedly fail-closed isolation audit.**  
   [wire.rs:343](/Users/dennison/develop/FIC-elipsis/crates/transport/src/logos_rest/wire.rs:343), [mod.rs:306](/Users/dennison/develop/FIC-elipsis/crates/transport/src/logos_rest/mod.rs:306)

   Missing, wrongly typed, or unrecognized `connected` values become `false`; even `[null]` parses successfully. Such entries are treated as disconnected, allowing the audit to succeed and traffic to proceed.

   A sidecar schema regression that changes connection-state encoding can therefore hide a connected foreign peer rather than produce an unauditable-node error. This contradicts threat-model T12. It is not evidence of exploitation against the pinned node’s normal responses.

   **Fix:** require structurally valid entries and explicitly recognized connection states; reject ambiguous responses. Existing malformed-response tests do not cover malformed individual entries or unknown states.

7. **Medium — Incomplete history responses advance the durable watermark.**  
   [node.rs:837](/Users/dennison/develop/FIC-elipsis/crates/core/src/node.rs:837), [wire.rs:243](/Users/dennison/develop/FIC-elipsis/crates/transport/src/logos_rest/wire.rs:243)

   Two traced paths incorrectly report successful completion:

   - A repeated nonempty pagination cursor terminates pagination like an absent cursor.
   - HTTP 200 `{}` or `{"error":"temporarily unavailable"}` parses as an empty successful Store page because status is optional and messages default to empty.

   During catch-up, either response advances the watermark despite missing history. Subsequent passes omit messages older than the overlap window; delivery can be permanently lost once sender retries have ended.

   **Fix:** require a valid successful Store envelope and treat repeated/cyclic cursors as failed passes without watermark advancement. Add recovery tests proving the missed interval is queried again.

**Suspicions requiring further verification**

- Private-peer configuration appears to validate the first IP and final peer ID without validating intermediate circuit-relay hops. Whether the pinned sidecar actually dials an unallowlisted intermediary needs upstream or runtime confirmation.
- Generation-sidecar publication lacks serialization for concurrent external callers of the core library. I did not establish that race in the normal daemon path, whose synchronous ingest operations run within joined loops.

I found no confirmed flaw in the reviewed HPKE/Ed25519 binding itself: exact envelope bytes are signed; recipient, suite, and decrypting epoch are checked; the header is AAD; and sealing creates fresh HPKE contexts. Likewise, no confirmed HTTP bearer-authentication or webhook SSRF bypass emerged. These are limited review observations, not security certification.

Not reviewed: upstream cryptographic/dependency internals; actual relay, DNS, Docker, or cross-machine behavior; power-loss/fsync behavior; memory-erasure guarantees; exhaustive CLI paths; fuzzing or hostile-load execution.