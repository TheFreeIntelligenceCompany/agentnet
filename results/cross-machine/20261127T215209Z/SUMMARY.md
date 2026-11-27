# AgentNet cross-machine run (goal.md "Cross-machine / NAT"), 2026-11-27, OpenPGP tree

Commit 481eb15 (`agentnet 0.1.0`; Mac binary built from 481eb15, box binary built there from a `git clone --depth 1` of main at 481eb152f3b3; `cargo build --release --locked -p agentnet-cli`, 1 m 44 s). Message protection is RFC 9580 OpenPGP (sequoia-openpgp 2.5.0, OpenSSL 3); addresses are `an2...`, contacts are certificates. **Single run.** This is the second run of this experiment, repeating the 2026-11-26 one (HPKE + Ed25519) on the OpenPGP tree. An earlier attempt of this same run was cut off by an account limit and is preserved separately as `20261127T193836Z` (marked PARTIAL); this directory is a complete fresh run.

## What this is and is not

- IS: **two real, separate hosts on different networks.** Host 1 is a Mac (arm64) behind a real home NAT making only outbound connections; host 2 is a cloud sandbox (instabox VM, x86_64 Linux, native amd64 Docker) that held the relay/store node R, node B and agent B. Agent A and node A (qemu amd64 under colima) ran on the Mac. A <-> R traffic crossed the real internet between the two hosts. Both client nodes and agents are outbound-only; R has no public listener.
- The client-to-relay traffic was carried **inside an authenticated SSH tunnel provided by the sandbox service** (`instabox port-forward`, opened from the Mac).
- IS NOT: Tailscale; raw libp2p across the public internet; libp2p NAT traversal or hole punching; a test of a public relay. **Agent B shares host 2 with the relay**, so only A crossed the host boundary. Latencies include the SSH tunnel and are one run each, not statistics. Receipt latencies come from polling `status` every 100 ms. Not audited, no forward secrecy.
- Topology and addressing: `evidence/topology.md`. Scrubbed: account email, org id, box id, public IPs, macOS username (`<user>`), hostnames.

## Results (`checks.jsonl` carries the real event time of each check)

| Check | Result |
|---|---|
| 1 each client node lists exactly one peer (R), Connected; `doctor --ready` exit 0 on both hosts | PASS |
| 2 contact exchange with `--expect` both ways; wrong `--expect` refused (rc 4) on both | PASS |
| 2 first message A->B 527 ms, B->A 225 ms (authenticated receipts) | PASS |
| 2 MCP `send_message` from A, delivered (465 ms) | PASS |
| 2 20 msgs A->B: 20/20, p50/p95/p99 = 410/636/942 ms | PASS |
| 2 20 msgs B->A: 20/20, p50/p95/p99 = 289/673/677 ms; inbox rows unique in both directions (A 21, B 22) | PASS |
| 3 B offline (daemon + node B stopped): 5 messages from A (state `sent`), all 5 delivered with receipts 0.75-0.79 s after the restart command | PASS |
| 3 A offline (daemon + node A stopped, same container restarted): 5 messages from B, 5/5 delivered 19.5 s after restart | PASS |
| 4 Mac: only loopback listeners, no 60000/8000, node container publishes only 127.0.0.1:18655; box: no published port, listeners loopback + sshd; R sees A as 172.28.66.1 | PASS |
| 4 direct TCP connect from the Mac to the box's public address | UNTESTED (no public address observable) |
| 5 tunnel down 76 s: A lost R, message queued (NoPeersToPublish); after restore A lists R Connected in 3.7 s, queued message delivered 29.9 s after restore (SINGLE TRIAL) | PASS |
| 5 silent blackhole across the real hosts; NAT traversal | UNTESTED |

Box facts: agentnet-rh1 (4 vCPU / 8 GiB) created 21:51:51Z, deleted 22:14:15Z (22.4 min, shared with the public-relay run). Nothing published.

## Notes and deviations

- Recovery times in check 3 are relative to the moment the restart command was issued on the Mac side (clock of the sender). B-offline recovery (0.75 s) was much faster than the 2026-11-26 run (1.5-5.7 s); not investigated, node restarts were `docker stop/start` of the same container, not a recreated node.
- Killing the port-forward closes the TCP connection cleanly, so `tcp_retries2=6` was not exercised; the path-loss result says nothing about a silent blackhole.
- `agentnet doctor` always shows one standing warning (single-instance note); it is not a failure.
- Both agents derived the same inbox topic (inbox-07) in this run: topics are hashed, collisions are expected with 16 topics.
- Nodes: wakuorg/nwaku@sha256:cb4d14a2... (v0.39.2) amd64 (qemu on the Mac, native on the box).
- Untested: the items marked UNTESTED above; any claim of production security.
