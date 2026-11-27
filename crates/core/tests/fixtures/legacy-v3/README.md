# legacy-v3 fixture: a data directory written by the ADR 0002 (HPKE + Ed25519, `an1`) code

Synthetic and disposable: keys generated for this fixture only, mock-clock time (2023-11-14), no real secrets.
Used by the `identity migrate` tests (`crates/core/tests/migration.rs`).

Made at commit `968e100` (the tree before the ADR 0004 cutover) with a throwaway integration test using the
engine harness (`crates/core/tests/common`): agents `a` and `b` on one `MockNetwork`, contacts exchanged,
`a` sends "legacy inbound hello" to `b` (delivered, `b` queues an ack), `b` sends "legacy outbound sent"
(published) and "legacy outbound queued" (not published). Agent `b`'s `identity.json` and SQLite store (closed
cleanly, WAL checkpointed) were copied here. `manifest.json` lists the ids.

Contents of `agentnet.db` (schema `user_version` 3): 1 contact (`a`), 1 inbox row, 1 `seen` row,
outbox rows: 1 `queued` (user message), 2 `sent` (the user message and the ack). Run

    sqlite3 agentnet.db "pragma user_version; select state,count(*) from outbox group by state;"

to check. The generator test was removed after the run (it needs the old code).
