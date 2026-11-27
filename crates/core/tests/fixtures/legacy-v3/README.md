# legacy-v3 fixture: a data directory written by the ADR 0002 (HPKE + Ed25519, `an1`) code

Synthetic and disposable: keys generated for this fixture only (disposable test keys by design, committed on
purpose), mock-clock time (2023-11-14), no real secrets. Used by the `identity migrate` tests
(`crates/core/tests/migration.rs`, `crates/daemon/tests/migrate.rs`).

The database is a binary file; `.gitignore` ignores `*.db` but has a negation rule for this directory
(`!crates/core/tests/fixtures/**/*.db`), and the tests fail with a clear message if any file here is missing.

## Regenerated 2026-11-26 (the original database was lost)

Made at commit `968e100` (the tree before the ADR 0004 cutover), in a temporary `git worktree` with its own
target dir (both removed afterwards), with a throwaway integration test (`crates/core/tests/gen_legacy.rs`, not
kept: it needs the old code) using the engine harness `crates/core/tests/common`:

1. `World::new()`; agents `a` and `b` on one `MockNetwork` (default `cfg()`), contacts exchanged, both
   `step_receive` once so they subscribe.
2. `a` sends "legacy inbound hello" to `b`; `a.step_send()`; `b.step_receive()` (delivered, `b` queues an ack).
3. `b` sends "legacy outbound sent"; `b.step_send()` publishes it and the ack.
4. `b` sends "legacy outbound queued" (never published).
5. `b.node.close()` (store closed cleanly, WAL checkpointed); copy `b`'s `identity.json` and SQLite file here as
   `identity.json` and `agentnet.db`; `manifest.json` (message ids, `b`'s address, `a`'s address and contact
   record) was written by the same test.

`identity.json`, `agentnet.db` and `manifest.json` are one consistent set; do not replace one alone.

Contents of `agentnet.db` (schema `user_version` 3): 1 contact (`a`), 1 inbox row, 1 `seen` row,
outbox rows: 1 `queued` (user message), 2 `sent` (the user message and the ack). Run

    sqlite3 agentnet.db "pragma user_version; select state,count(*) from outbox group by state;"

to check.
