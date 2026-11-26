# AgentNet Tailscale cross-machine run (goal.md "Tailscale experiment"), 2026-11-26

## What this is and is not

- IS: **two real, separate hosts on one real tailnet.** Host 1 is a Mac (macOS arm64, behind a home NAT, node A under qemu in colima, agent A on the macOS side). Host 2 is a cloud sandbox (instabox VM, Debian x86_64, native amd64 Docker) joined to the same tailnet as its own device. The relay/store node R, client node B and agent B ran on host 2. R's libp2p port is published **only on the box's tailnet IPv4** (`<TS_IP_B>:60000`) and firewalled so that only the Mac's tailnet IPv4 (and the box itself / node B) may reach it. Node A's only static peer is R at that tailnet address. The A <-> R traffic crossed the real tailnet.
- Path type as observed: **DIRECT** (WireGuard over IPv6, UDP 41641 between the two hosts), **not DERP-relayed**; tailscale ping 72-73 ms, ICMP over the tailnet 72-117 ms. The Mac's nearest DERP is New York, the box's home DERP Seattle. The task started with a DERP path; Tailscale upgraded it to direct before the first measurement and it was not changed by us (`evidence/tailscale-path-*.txt`).
- Packet evidence (check 5): 40 libp2p packets seen on `tailscale0` (tailnet addresses), 0 packets for tcp/60000 on the primary interface in the same window, only WireGuard UDP there.
- IS NOT / NOT TESTED: **tailnet ACL/grants enforcement** (ACL untouched, no admin access; the snippet in `spike/relay-tailscale/README.md` stays an untested recommendation), key expiry, MagicDNS names, a third unauthorized tailnet device trying to connect (only non-tailnet vantage points and a non-allowlisted local source were used), agent B on a third host (B shares the relay's host, and B's connection to R ran over the docker bridge, not the tailnet), public relays, NAT traversal under adverse conditions (the path happened to be direct over IPv6), multi-trial statistics. Every timing below is a single run.
- Scrubbed: tailnet IPs (`<TS_IP_A>` Mac, `<TS_IP_B>` box, `<peer>` for others), public IPs, macOS user, device hostnames, account email, box/org ids. Disposable test nodekeys from `spike/relay/.env` (already public in the repo).

## Results (22 records in `checks.jsonl`: 18 PASS, 3 INFO, 1 UNTESTED, 0 FAIL)

| Check | Result |
|---|---|
| 1 hosts are tailnet peers; path DIRECT (IPv6), tailscale ping 72 ms | PASS |
| 1 node A lists exactly one peer, R, at `<TS_IP_B>:60000`, Connected. Node B lists exactly one peer, R, Connected, but at the docker bridge address (R dialled B back) | PASS (B deviation) |
| 1 `doctor --ready` exit 0 on both hosts | PASS |
| 1 R sees A as 172.28.66.1 (docker gateway), not the Mac's tailnet IP: tailscaled's `ts-postrouting` MASQUERADE rewrites the source of traffic forwarded from `tailscale0` into the bridge. The packets on `tailscale0` do carry `<TS_IP_A>` | INFO |
| 2 contact exchange with `--expect` both ways; a wrong `--expect` is refused (exit 4) | PASS |
| 2 first message A->B 854 ms with authenticated receipt; B->A first 488 ms | PASS |
| 2 MCP `send_message`: call 15 ms, receipt 152 ms | PASS |
| 2 20 msgs A->B: 20/20, p50/p95/p99 = 424/679/1982 ms | PASS |
| 2 20 msgs B->A: 20/20, p50/p95/p99 = 440/488/496 ms; no duplicate message ids on either side | PASS |
| 3 B offline, 5 msgs from A: receipts 2.6 s (3 msgs), 10.6 s, 12.6 s after B restart | PASS |
| 3 A offline, 5 msgs from B: all 5 receipts 25.3 s after A restart | PASS |
| 4a R's port answers on `<TS_IP_B>` from the Mac | PASS |
| 4b no answer on loopback, primary interface, bridge, docker0, public IPv6 (from the box); none on the public IPv4/IPv6 from the Mac; only listener = docker-proxy on `<TS_IP_B>:60000` | PASS |
| 4c firewall DROP for the Mac then restore: A loses R, message `sent` with no receipt; restore -> Connected +3.5 s, delivery +33.4 s (same run as 6) | PASS |
| 4c **finding**: rules in `DOCKER-USER` do **not** restrict tailnet traffic (tailscaled's `ts-forward` accepts first); the raw table is where the restriction works | INFO |
| 4d tailnet ACL | UNTESTED |
| 4e `instabox port ls` empty | PASS |
| 5 40 packets on `tailscale0`, 0 on the primary interface for tcp/60000, 15 WireGuard UDP packets there | PASS |
| 6 silent path loss, single trial, 120 s DROP: A notices at +47.4 s, R's half-open socket gone at +47.9 s (about 38 s after its first retransmission, `tcp_retries2=6`), A Connected +3.5 s after restore, queued message delivered +33.4 s after restore | PASS |
| 6b unplanned second block (82 s): R kept an **idle** stale socket (nothing to retransmit, so `tcp_retries2` did not apply), closed every new connection from the Mac, A recovered only **7 min 25 s** after the path returned, 2 s after the stale socket vanished (exactly 8:00 after A closed; cause UNTESTED) | INFO |

## Notes and deviations (read these)

1. **No forwarder was needed.** A container in the colima VM connected directly to `<TS_IP_B>:60000`: the VM reaches tailnet addresses through the Mac's routing. `spike/relay-tailscale/tcp-forward.py` was not used.
2. **Firewall deviation.** The brief asked for DOCKER-USER (+INPUT). Measured: tailscaled's `ts-forward` accepts everything forwarded from `tailscale0` before `DOCKER-USER` is consulted (`evidence/fw-docker-user-bypassed.txt`: a DROP for the Mac's IP there did nothing, the Mac still connected and A stayed Connected). The working rules are in the **raw** table, `PREROUTING`, matching `-d <TS_IP_B> -p tcp --dport 60000` (ACCEPT `<TS_IP_A>`, ACCEPT the box itself, ACCEPT node B 172.28.66.22, DROP otherwise); `evidence/harness/box-fw.sh`. INPUT rules were tried first and removed: they also dropped node B's path through docker-proxy. Any firewall for a docker-published tailnet port on a Tailscale host must be tested this way. Counters are in `evidence/access-restriction.txt` (ACCEPT for `<TS_IP_A>`: 1502 packets at that point) and `evidence/fw-block-counters.txt` (DROP 108 packets).
3. **Node B and the tailnet.** B shares R's host. After B's restart R dialled B back over the bridge, so B's peer list shows R at 172.28.66.10. B only exercises the bridge. Only A crosses the tailnet. The first B start also had its tailnet-address connection blocked by an INPUT rule I had added; it was not retried by the node itself (known: nodes do not redial), fixed by restarting node B.
4. **Check 6 / 4c is one trial; 6b happened by accident.** I wanted a 15 s block for a counter capture; slow `instabox exec` round trips made it last 82 s and R's side did not clean up. I kept it as an observation, not a designed test. Time and clock caveat: timestamps of the two hosts come from NTP-synchronised clocks, differences below about 1 s are not meaningful.
5. The quoted ~30 s for `tcp_retries2=6` was ~38 s here (RTO about 0.3 s over a 72 ms RTT, 7 backoff intervals). The 8-minute stale socket in 6b is a case `tcp_retries2` cannot fix because R has no unacknowledged data to retransmit; the relay needs traffic toward the client or a separate TCP keepalive on the relay. Cause of the 8:00 expiry UNTESTED.
6. Sequential single-sender latencies; receipts come from polling `status` every 100 ms; latency = `delivered_at - created_at` on the sender's clock. The 1982 ms outlier in A->B is one sample (in the 20).
7. The offline tests used `docker stop/start` of the same node container (not a recreated node), so the ~62 s blind window did not apply; recovery in the A case (25.3 s) includes node A's own start-up.
8. First `doctor --ready` runs (about 19:24Z, both hosts, exit 0) were observed live but only the final ones are saved (`evidence/doctor-final.txt`).
9. `spike/relay-tailscale/remote-client.sh` / `remote-check.sh` (the formerly untested kit) were **not executed as written**; I used my own commands (`evidence/harness/`). Read against what I measured, the kit has at least one bug: `remote-client.sh up` extracts the agent address with `jq -r .address` from `agentnet --json identity show`, but the field is `agent_id` (`address` does not exist), so `address.txt` would contain `null`; the kit's node flags (`--nat=none`, static/store/filter/lightpush peer = R) match what worked here, and its `probe-relay` / `probe-lan` are plain `nc -z` checks equivalent to the ones I ran. The kit's relay side (`run.sh` on a Mac host with a forwarder) was not exercised: the relay here ran on a Linux host with docker publishing directly on the tailnet IP, which works (unlike colima).
10. Box facts: Debian x86_64, 2 vCPU / 4 GiB, Docker 29.8.2, Tailscale 1.104.7 (box) / 1.102.3 (Mac), agentnet 0.1.0 at c331f7a on both hosts (Mac binary pre-built from HEAD, box built there with `cargo build --release --locked -p agentnet-cli`). R's container has `tcp_retries2=6`; the box's own kernel default is 15. Node image `wakuorg/nwaku@sha256:cb4d14a2...` (v0.39.2), native on the box, qemu on the Mac.
11. Cleanup: daemons stopped, `an-x-node-a` removed on the Mac only, firewall rules and containers removed on the box, `sudo tailscale logout` rc=0, box deleted (`instabox ls --meta project=agentnet` = `[]`). After logout the device record `agentnet-ts-test` was still listed (offline) by the Mac's `tailscale status`; the repo holder should delete it in the Tailscale admin console if it is still there.

## Files

`checks.jsonl`; `evidence/`: `topology.md`, `tailscale-path-mac.txt`, `tailscale-path-box.txt`, `peers-a-node.txt`, `peers-b-and-r.txt`, `bench-a2b.json`, `bench-b2a.json`, `mcp-send.json`, `duplicate-check.txt`, `offline-recovery-A.txt`, `offline-recovery-B.txt`, `access-restriction.txt`, `fw-docker-user-bypassed.txt`, `fw-block-at-trial.txt`, `fw-restore-at-trial.txt`, `fw-block-counters.txt`, `packet-capture.txt`, `silent-loss-driver.log`, `silent-loss-sampler-{mac,box}.jsonl`, `stale-socket-sampler-{mac,box}.jsonl`, `doctor-final.txt`, `versions.txt`, `harness/` (the scripts used).
