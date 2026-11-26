# AgentNet public-IP relay run (goal.md cross-machine experiment, strictest form), 2026-11-26

## What this is and is not

- IS: **one relay/store node R with its own public IPv4 on raw tcp/60000 (a DigitalOcean droplet, nyc1), reached directly over the public internet by one outbound-only client (node A + agent A on a Mac behind a home NAT)**. No tunnel, no shim, no tailnet. The cloud firewall admits only the Mac's single public IPv4 on tcp/22 and tcp/60000. Packet capture on the droplet shows the Mac's public address as the source of raw libp2p/Noise traffic. Node image `wakuorg/nwaku@sha256:cb4d14a2...` (v0.39.2), cluster 66 shard 0, discovery off, RLN off, `--dns-addrs-name-server=127.0.0.1`, R with `tcp_retries2=6`.
- IS NOT: NAT hole punching or client-to-client traversal (the client dials a server with a public address); an open public relay (no unauthenticated third party was admitted, the firewall allowed one address; cluster/shard ids are not access control, T13); a test against any public Waku/Logos network (none was contacted); a test of the peer-id allowlist against an unauthorized peer; multi-trial statistics. **Agent B shares the relay's host** (B <-> R never leaves the droplet). Everything is a **single run** and every timing a single sample. Path: x86_64 droplet native, Mac side under qemu/colima. Mac binary built from b3a60a6, droplet built from a `git clone --depth 1` of the public repo at b3a60a6 (`cargo build --release --locked -p agentnet-cli`, 8 min 25 s on 2 vCPU).
- Scrubbed: droplet public IP `<PUB_IP_R>`, the Mac's public IP `<PUB_IP_A>`, Mac LAN address `<LAN_IP_A>`, droplet/firewall/key ids, macOS user `<user>`. The pcap is not committed (raw IPs); `evidence/packet-capture.txt` is its scrubbed analysis.

## Main finding: a public relay address needs `mode = "public"`, which drops the isolation guarantees

- **Private mode (the default, fail closed) refuses this topology.** With `peers = ["/ip4/<PUB_IP_R>/tcp/60000/p2p/..."]` and `mode = "private"`: `doctor --ready` -> `[FAIL] config: invalid configuration: network: isolation violation: static_peers entry rejected in private mode: address must be a literal private IP` (exit 7); `agentnet serve` -> same message, exit 4 (`evidence/private-mode-rejection.txt`). `agentnet init --peer <public ip>` itself succeeds and writes the private-mode file, the error only appears at doctor/serve.
- **The supported configuration that works** is the explicit public mode on both agents (`evidence/public-mode-config.txt`):
  ```toml
  [network]
  mode = "public"
  i_understand_public = true
  node_url = "http://127.0.0.1:18690"
  peers = ["/ip4/<PUB_IP_R>/tcp/60000/p2p/16Uiu2HAm8fsfg223p9wnEDbuYEKrs2dMK4zSPzghoyfpJoCYesLV"]
  cluster_id = 66
  public_discovery = false
  public_fallback = false
  ```
  (`init` writes the private file; I changed the two keys `mode` and `i_understand_public` by hand.) No code was changed.
- **What the tools report in public mode** (`evidence/doctor-final.txt`): `doctor --ready` exit 0 with `[ok] config ... valid (public mode, 1 peer(s))`, `[ok] isolation: no isolation violation reported`, `[skip] peers == allowlist: public mode: no allowlist audit`, `[ok] transport ready: node reachable; 1 connected allowed peer(s)`. `network status`: `mode: public`, `ready: true`, `connected peers: 1`, `isolation: ok`.
- **Guarantees no longer enforced in public mode** (from `docs/configuration.md` and `crates/transport/src/logos_rest/mod.rs`, plus what was observed): the runtime peer-allowlist audit is skipped (`audit()` and `ensure_audit()` return early; the audit's `isolation_violation` can never fire); `fetch_audit_public` marks **every** connected peer `allowed: true`, so "1 connected allowed peer(s)" and `isolation: ok` would read the same with an unknown peer attached; the private-IP-literal checks on `node_url`, `peers`, `store_peer` do not apply; the preset-cluster-id rejection (1, 2, 3, 16) does not apply. In this mode the **only** thing keeping strangers off the relay was the cloud firewall (check 6). The peer-id allowlist is still derived from `peers`, but nothing enforces it. Whether messages from a non-allowlisted peer would be dropped, and whether the adapter redials static peers in public mode (the redial lives in `ensure_audit`, which returns early), is UNTESTED and was not exercised with a third party. This is a finding against goal.md's "users can choose public infrastructure or exclusively their own private relays": a user-owned relay on a public IP has no supported middle ground between "private IP literals only, allowlist enforced" and "public mode, nothing enforced".

## Results (23 records in `checks.jsonl`)

| Check | Result |
|---|---|
| 1 `nc` from the Mac to `<PUB_IP_R>:60000` connects | PASS |
| 1 capture on droplet eth0: `<PUB_IP_A>` is the source of all inbound tcp/60000 packets (3 source ports, 4788 packets); Mac's LAN address seen in `lsof`, public address on the wire = NATed by the home router | PASS |
| 1 R's peer list shows A at `/ip4/<PUB_IP_A>/tcp/54558` (Mac public IP); docker DNAT preserved the source; B (same host) shows as 172.28.66.1 | INFO |
| 2 node A lists exactly one peer, R, Connected, at the public multiaddr; node B exactly one (R) | PASS |
| 2 `doctor --ready` exit 0 on both hosts (public mode only; private mode: exit 7) | PASS / FINDING |
| 3 contact exchange with `--expect` both ways; a wrong `--expect` refused (exit 4) | PASS |
| 3 first message A->B 418 ms, B->A 199 ms, both with authenticated receipts | PASS |
| 3 MCP `send_message`: call 1 ms, receipt 238 ms | PASS |
| 3 20 msgs A->B 20/20 p50/p95/p99 = 198/379/415 ms; B->A 20/20 225/396/401 ms; no duplicates (A inbox 21/21 distinct, B 22/22) | PASS |
| 4 B offline, 5 msgs from A: all 5 receipts within 1.2 s of node B start. A offline, 5 msgs from B: all 5 receipts 3.65 s after node A start (Store/relay sync after `docker stop/start`, not a recreated node) | PASS |
| 5 Mac: only `127.0.0.1:18690` published, no :60000 listener, one outbound ESTABLISHED socket to R; from the droplet `nc <PUB_IP_A> 60000` times out | PASS |
| 6 trial 1: removing the Mac's tcp/60000 allow rule did **not** disconnect A: the DO cloud firewall is stateful, the established flow survived, a queued message was delivered in 0.3 s | FINDING |
| 6 trial 2: rule removed and node A restarted so it must dial anew: A cannot reach R (peer `CannotConnect`, `network status` ready=false connected=0, `nc` times out, tcp/22 still works), message stays `queued`. Rule restored: A Connected within 2.3 s of the firewall `succeeded`, message sent +35 s, delivered +36.8 s after `succeeded` (about 33 s of that is the agent's delay between peer-up and send, as in the Tailscale run) | PASS |
| 6 R holding a stale socket for A in trial 2 | UNTESTED (my droplet sampler did not start) |
| 7 payload on the public interface: plain `/multistream/1.0.0` and `/noise` lines, then Noise records; 0 hits for 10 known synthetic body strings (control: `/noise` is found by the same grep) | PASS |
| 8 order of events: droplet active 20:43:51Z, firewall (droplet attached) created 20:43:56Z, `succeeded` 20:44:01Z, relay started 20:45:49Z | PASS |

## Access control (check 6) in plain words

The cloud firewall is the only access control for the relay in this setup. Observed: it blocks new connections from any other address (and from the Mac once its rule is removed), but **it is stateful: deleting the allow rule does not drop connections that are already established**. To revoke a client you must also break the flow (restart R or the client). The firewall change itself took 2.6 s (remove) and 1.5 s (add) to reach `succeeded`. Pending "R holds a stale socket": see above, UNTESTED. No third party was admitted at any point.

## Deviations and notes

1. **No tag.** The brief's tag-based design was dropped (the DO token has no tag scope: first attempt failed with `tag:read`/`tag:create` Forbidden). The droplet is untagged, the firewall is attached by droplet id, cleanup was verified by name. Between "droplet active" (20:43:51Z) and "firewall succeeded" (20:44:01Z) key-only SSH was reachable without the cloud firewall (at most 10 s, no password login, nothing on tcp/60000 until 20:45:49Z).
2. **Agent B also ran in public mode** (its peer is the public address too). B's node sees R at the public multiaddr but B's TCP connection runs via the docker bridge (`172.28.66.1`).
3. **Trial 1 of check 6 did not test what it was meant to** (established flow survived), so I added trial 2 (node A restart while blocked). Both labelled single trials; the pkill in my second sampler start killed its own ssh command, so no droplet-side samples for trial 2 (`fw-trial2-driver.log`, `fw-trial2-sampler-mac.jsonl` only; trial 1 has both sides).
4. Sampling is 1 s; the 33 s agent delay and the 0.3 s same-flow delivery are single samples.
5. The `nc` run on macOS used the OS connect timeout (about 75 s), not `-w 5`, when the SYN was silently dropped.
6. `ssh` host key of the droplet was accepted on first use (`StrictHostKeyChecking=accept-new`) and removed from `known_hosts` after deletion. I pulled the `alpine` image once in colima for the "no listener inside the VM" check. The other contributor's `an-x-*` containers were not touched.
7. Local `HEAD` moved to 7f54712 during the run (another contributor); the Mac binary and the droplet clone are b3a60a6 (`evidence/versions-and-node-flags.txt`).
8. **Cost**: droplet s-2vcpu-4gb ($24/month list price, $0.036/h) alive 20:43:27Z - 21:05:41Z = 22 min 14 s, about $0.01 prorated (DO bills per second, minimum 60 s; if billed as a full hour $0.04). Firewall and key are free.
9. **Cleanup**: daemons stopped; `an-do-node-a` removed (Mac); droplet, firewall `agentnet-pub-test-fw`, key `agentnet-pub-test-key` deleted 21:05:41Z; `doctl` list counts by name: droplets 0, firewalls 0, ssh keys 0 (`evidence/cleanup-do.txt`); temp key dir and agent data dir removed.

## Files

`checks.jsonl`; `evidence/`: `topology.md`, `private-mode-rejection.txt`, `public-mode-config.txt`, `doctor-final.txt`, `nc-from-mac.txt`, `peers.txt`, `packet-capture.txt`, `firewall-rules-final.json`, `versions-and-node-flags.txt` (exact node flags), `contacts.txt`, `first-*.json`, `bench-*.json`, `mcp-send.json`, `mcp-status.json`, `duplicate-check.txt`, `offline-recovery-{A,B}.txt`, `outbound-only-mac.txt`, `droplet-to-mac.txt`, `fw-trial1-*`, `fw-trial2-*`, `r-sockets-final.txt`, `cleanup-do.txt`, `harness/`.
