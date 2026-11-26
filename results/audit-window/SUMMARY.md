# Audit-before-publish fix on real nodes

Single host: local relay topology of `spike/relay` (relay/store R1, client nodes
an-na and an-nb, node image linux/amd64 under qemu on an arm64 Mac), 2026-11-26.
Run by the lead.

Test: `audit_window::publish_audits_peers_immediately_before_sending` in
`crates/transport/tests/logos_rest_relay.rs`, gated by the `disruptive-tests`
feature, `AGENTNET_RELAY_TESTS=1` and `AGENTNET_RELAY_DISRUPTIVE=1`.

What it does: a private-mode transport on an-na with the allowlist = R1 and a
600 s audit interval publishes once; a throwaway third node (started and removed
by the test) is then dialled from an-na through its own REST admin API, so an-na
is meshed with a peer outside the allowlist; the next publish, with no status
call in between, must be refused with the isolation error and must not reach
R1's Store; after the throwaway node is removed a publish must succeed again.

Results:

* `run1.txt`, `run2.txt`, `run3.txt`: the test passed 3 of 3 (about 6 s each).
  an-na stopped listing the removed peer as Connected within about 3 ms of the
  poll after removal; it keeps a known-but-not-connected entry (`CanConnect`).
* `default-suite1.txt`, `default-suite2.txt`: the default relay-gated suite
  (`AGENTNET_RELAY_TESTS=1 cargo test --workspace --locked -- --ignored`) passed
  7 of 7 twice with the new test present (the default suite does not run it).

Not shown: the same fix against a real public relay; the residual window of one
REST round trip between the audit response and the publish request; the test was
not run against the pre-fix code on real nodes (the unit tests in
`crates/transport` failed before the fix and pass after it).

Note for operators: the node REST API (v0.39.2) has no call to disconnect a
peer. A node meshed with an unwanted peer has to be restarted, or the peer has
to go away.
