# Capability discovery on the local relay, after binding the topic into the signed advert (format v2)

Test: `crates/cli/tests/relay_discovery.rs` (`signed_capability_discovery_works_over_the_private_relay`).
Command: `AGENTNET_RELAY_TESTS=1 cargo test -p agentnet-cli --locked --test relay_discovery -- --ignored --nocapture`
Raw output: `run1.log`, `run2.log` (2 runs, both PASSED, about 34 s each; fresh topic and capability names per run).

Setup: LOCALHOST / CONTAINER-NETWORK only. One host (arm64 macOS laptop), containers on one colima VM, nwaku node image
amd64 under qemu (an-na, an-nb, relay an-r1, cluster 66). Two real `agentnet serve` processes, each with its own node.
Not a cross-machine test.

What changed versus `../20261126T151341Z/SUMMARY.md`: the advert record is now `{"v":2,"topic":...}` and the receiver
rejects an advert whose signed topic differs from the topic it arrived on.

Checked per run:
- A advertises on topic T; B lists it after 0.52-0.53 s (523, 530 ms); `contact add --expect` of the returned record works.
- The raw advert frame (1235 bytes, `AD 01` prefix) was read from the relay Store and re-published through node A's REST
  API on a second configured topic (cross-topic replay): after 20 s B does NOT list anything on that topic (was listed in
  the earlier run, when the topic was not signed).
- Same frame with one signature character flipped on a third topic: not listed.
- Same-topic replay of the frame on T: B still lists exactly one entry.
- Positive control: a genuine advert signed for the second topic (different capability name) is then listed by B there
  after about 20 s, so that topic and path are functional; only the replay was refused.
- Message A -> B delivered while discovery is active; withdraw removes the advert at B; disabled phase behaves as before.

Not established (UNTESTED): that B's `advert.invalid.topic_mismatch` counter incremented on the relay (counters are not
exposed through `network status --verbose`); this is covered on the mock network by `engine_discovery.rs`
(`an_advert_replayed_onto_another_enabled_topic_is_rejected`).
