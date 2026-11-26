# AgentNet cross-machine run (goal.md "Cross-machine / NAT"), 2026-11-26

## What this is and is not

- IS: **two real, separate hosts on different networks.** Host 1 is a Mac (arm64) behind a real home NAT making only outbound connections; host 2 is a cloud sandbox (instabox VM, x86_64 Linux, native amd64 Docker, no emulation) that held the relay/store node R, node B and agent B. Agent A and node A (under qemu in colima) ran on the Mac. A <-> R traffic crossed the real internet between the two hosts. Both client nodes and agents are outbound-only; R has no public listener.
- The client-to-relay traffic was carried **inside an authenticated SSH tunnel provided by the sandbox service** (`instabox port-forward`, opened from the Mac).
- IS NOT: Tailscale; raw libp2p across the public internet; libp2p NAT traversal or hole punching (the relay was never dialled directly across the NAT); a test of a public relay. **Agent B shares host 2 with the relay**, so only one of the two clients (A) crossed the host boundary. Latencies include the SSH tunnel and are one run each (not statistics).
- Single trial wherever stated. Receipt latencies come from polling `status` every 100 ms.
- Topology and the exact addressing: `evidence/topology.md`. Scrubbed: account email, org id, box id, public IPs, macOS username (`<user>`), hostnames.

## Results (16 checks: 13 PASS, 0 FAIL, 3 UNTESTED; `checks.jsonl` timestamps are the time the file was written, not the event times)

| Check | Result |
|---|---|
| 1 each client node lists exactly one peer (R), Connected; `doctor --ready` exit 0 on both hosts | PASS |
| 2 contact exchange with `--expect`, both ways | PASS |
| 2 first message A->B 371 ms, B->A 523 ms (warm mesh) | PASS |
| 2 MCP `send_message` from A, delivered (397 ms) | PASS |
| 2 20 msgs A->B: 20/20, p50/p95/p99 = 427/855/855 ms | PASS |
| 2 20 msgs B->A: 20/20, p50/p95/p99 = 811/901/901 ms; inbox rows unique in both directions | PASS |
| 3 B offline (daemon + node B stopped): 10 messages from A (5 intended + 5 accidental extras), all 10 delivered with receipts 3.7 s after restart | PASS |
| 3 A offline (Mac): 5 messages from B, 5/5 delivered with receipts 3.5 s after restart | PASS |
| 4 Mac: libp2p port unpublished, only loopback listeners; box: `instabox port ls` empty, listeners loopback + sshd; R sees A as the box's docker gateway | PASS (x3) |
| 4 direct TCP connect from the Mac to the box's public address | UNTESTED (no public address is observable) |
| 5 tunnel down ~123 s: A lost R, message queued (NoPeersToPublish); after restore A lists R Connected in 4.2 s, queued message delivered in 49.5 s (SINGLE TRIAL) | PASS |
| 5 silent blackhole across the real hosts; NAT traversal | UNTESTED |

## Notes and deviations

- Recovery times in check 3 include about 3 s of command/ssh overhead and ~1 s per poll for the box side; they are upper bounds on the Store-sync path, and node restarts were `docker stop/start` of the same container (not a recreated node, so the ~62 s blind window did not apply).
- In check 3 a shell-array bug in the harness sent 10 messages instead of 5 to B while it was offline; all 10 were recovered, no duplicates.
- In check 5 killing the port-forward closes the TCP connection cleanly, so R noticed within 10 s and did **not** hold a stale socket; `tcp_retries2=6` was therefore not exercised. The path-loss result says nothing about a silent blackhole.
- `evidence/peers-b-node.json` and `peers-r-node.json` were re-captured after the test (the first snapshot was inspected live and showed exactly the same peers).
- Box facts: created 18:59:40Z, deleted 19:10:28Z (about 11 minutes, 2 vCPU / 4 GiB). Deleted and confirmed with `instabox ls --meta project=agentnet` = [].
- `agentnet doctor` always shows one standing warning (the single-instance note); it is not a failure.
- Nodes A and R/B: wakuorg/nwaku@sha256:cb4d14a2... (v0.39.2), amd64 (qemu on the Mac, native on the box). agentnet 0.1.0 at 5f004d8 on both hosts (Mac binary pre-built from HEAD; box binary built there with `cargo build --release --locked -p agentnet-cli`, 2 m 36 s).
