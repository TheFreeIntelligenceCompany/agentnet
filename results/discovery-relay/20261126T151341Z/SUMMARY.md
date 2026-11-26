# Capability discovery on the real local relay

Test: `crates/cli/tests/relay_discovery.rs` (`signed_capability_discovery_works_over_the_private_relay`).
Command: `AGENTNET_RELAY_TESTS=1 cargo test -p agentnet-cli --locked --test relay_discovery -- --ignored --nocapture`
Raw output: `run1.log`, `run2.log`, `run3.log` (3 runs, all PASSED, about 34 s each; each run uses fresh topic and capability names).

Setup: LOCALHOST / CONTAINER-NETWORK only. One host (arm64 macOS laptop, machine under load), containers on one
colima VM, nwaku v0.39.2 image running amd64 under qemu emulation (nodes an-na, an-nb, relay an-r1, cluster 66).
Two real `agentnet serve` processes, each with its own node. Not a cross-machine test.

Checked per run:
- A `discovery advertise`; B `discovery list` shows it after 0.52-0.54 s (525, 523, 535 ms): address, capability, display name, `is_contact=false`.
- B's `contact add` of the returned contact record with `--expect <A address>` succeeds (advert only accepted after signature and contact-record verification bound to the same address).
- Capability filter hit/miss; MCP `discover_agents` returns the same agent; unknown topic is `policy_denied`.
- Raw frame (1205 bytes, `AD 01` prefix) read from the relay Store, then injected through node A's REST API: the unmodified frame replayed on a second configured topic is listed by B (control); the same frame with one signature character flipped, injected on a third topic, is NOT listed after 20 s.
- Ordinary sealed message A -> B delivered and acked while discovery is active.
- `withdraw` removes A from B's listing (tombstone propagates); withdraw returns `withdrawn=true`.
- A restarted with `[discovery] enabled = false`: CLI advertise/withdraw/list exit 6 "disabled by host policy"; MCP `advertise_agent` -> `policy_denied`; the Store holds 2 frames on the topic before and after (nothing published).

Not established (UNTESTED): that B's `advert.invalid.*` counter incremented for the tampered frame (counters are not exposed
by `network status --verbose`; delivery of the tampered frame to B is inferred from the control frame, injected immediately
before it through the same node, arriving). Late-starter history recovery of adverts, republish cadence (900 s), multi-hop
or cross-machine delivery, and flooding behaviour were not exercised.
Observation: the signed record does not bind the topic, so a valid advert replayed onto another configured topic is accepted (this is how the control worked).
