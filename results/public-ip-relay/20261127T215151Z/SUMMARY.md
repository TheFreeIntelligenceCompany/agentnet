# Audited public-IP relay on the final tree (OpenPGP), 2026-11-27

## What this is and is not

- IS: the audited public mode (`agentnet init --public-relay`: `mode = "public"`, `i_understand_public = true`, `enforce_peer_allowlist = true`) run end to end against **one relay/store node R with its own public IPv4 on raw tcp/60000** (DigitalOcean droplet, nyc1, s-2vcpu-4gb, Ubuntu 24.04.5, x86_64), reached directly over the internet by agent A on a Mac behind a home NAT (node A in colima, amd64 under qemu). Private test relay only: cluster 66 / shard 0, discovery off, RLN off, image `wakuorg/nwaku@sha256:cb4d14a2...` (v0.39.2), R with `tcp_retries2=6`, `--dns-addrs-name-server=127.0.0.1`. No public Waku network was contacted; at most 20 messages per burst.
- Message protection: RFC 9580 OpenPGP (sequoia-openpgp 2.5.0, OpenSSL 3 backend); addresses `an2...`, contacts are certificates. Not audited, not forward-secret.
- Firewall `agentnet-pub-test-fw` (attached by droplet id before anything listened): inbound tcp/22, 60000, 60001 only from the Mac's single public IPv4 (`evidence/firewall-rules-final.txt`). The "foreign peer" R2 is a second node of mine on the same droplet (tcp/60001, different disposable nodekey), not a stranger.
- IS NOT: a wss/TLS or DNS-name peer test, a multi-client or long-duration run, or a benchmark. **Single run, single samples.** Agent B shares R's host (B<->R never crosses the internet; only A does). Only the Mac side is NATed; no NAT hole punching.
- Binaries: droplet built from `git clone --depth 1` of the public repo at main = **481eb152f3b3e1ea7ef9e22c05af20bf2ec13ff9** (`cargo build --release --locked -p agentnet-cli`, 8 min 34 s, rustc 1.100.1); Mac `target/release/agentnet` built from 481eb15 by the lead (the local checkout HEAD later moved to ebf278f; the binary did not).
- Scrubbed: droplet IP `<PUB_IP_R>`, Mac public IP `<PUB_IP_A>`, Mac LAN `<LAN_IP_A>`, macOS user, droplet/firewall/key ids. Agent addresses, message ids and disposable-key peer ids are synthetic and left in. The pcap is not committed.

## Results (19 records in `checks.jsonl`)

| # | Check | Result |
|---|---|---|
| 1 | `init --peer <public>` without `--public-relay` exits 4 with an actionable message naming the flag, writes nothing. A (Mac) and B (droplet) created with `init --public-relay`: `doctor` and `doctor --ready` rc 0 with `[ok] isolation: no isolation violation reported`, `[ok] peers == allowlist: 1 connected, all in the allowlist`, `[ok] transport ready: node reachable; 1 connected allowed peer(s)`; `network status --json` `isolation_audited: true` | PASS |
| 2 | capture on the droplet's eth0: all 4282 packets to :60000 have `<PUB_IP_A>` as source; `/multistream/1.0.0` and `/noise` visible then Noise; 0 hits for 13 synthetic strings and `an2` (control: `/noise` found 10 times) | PASS |
| 3 | wrong `--expect` refused (rc 4); first A->B 1787 ms, B->A 344 ms, authenticated receipts; MCP `send_message` call 43 ms, receipt 428 ms; 20/20 each way, A->B p50/p95/p99 664/1863/3074 ms, B->A 723/1937/2184 ms; duplicates 0 (A inbox 21/21 distinct, B 22/22); B's node down: 5/5 delivered 6.6 s after node start; A's node down: 5/5 delivered about 19-20 s after the node start returned | PASS |
| 3e | contact added without `--expect` is **untrusted** (warning printed), `--trust trusted` without `--expect` refused. Sending to it works (state `sent`, no receipt because that agent never ran). A message from an untrusted sender lands in `quarantine list` on the receiver, not in the inbox, and the sender sees `sent`, never `delivered` | PASS |
| 4 | Mac: no :60000 listener (host or colima VM), only `127.0.0.1:18690` published, one outbound ESTABLISHED socket to R; `nc <PUB_IP_A> 60000` from the droplet times out. R also tried to dial `<PUB_IP_A>:60000` from 70 distinct source ports (SYN retransmits, never answered) | PASS |
| 5a-b | node A told (own REST admin API) to connect to R2: the first `network status` after the connection says `ready: false`, `ISOLATION VIOLATION: node is connected to 1 peer(s) not in the allowlist`; `doctor --ready` rc 7; a message sent now stays `queued attempts=0` for 85 s, B inbox 0 | PASS |
| 5c | **race, 6 rounds**: connect R2 and send immediately, no status/doctor call between: **6 of 6 NOT published** (below) | PASS |
| 5d | R2 stopped: violation clears at the first poll, queued message delivered 5.3 s after the stop, `doctor --ready` rc 0 | PASS |
| 6 | plain public mode: `doctor` `[skip] isolation: not audited in public mode; the node may be connected to any peer`, `[skip] peers == allowlist`, transport `1 connected peer(s) (public mode: peers not audited)`; `network status` `isolation: not audited (public mode)`, JSON `isolation_audited: false`; R2 connected for 100 s with `ready=True violation=None`; message delivered; R2's relay cache did receive 2 messages (positive control) | PASS |
| 7 | Mac tcp/60000 rule removed + node A restarted: `nc` fails, peer `CannotConnect`, `ready: false connected 0`, message `queued attempts=0 ... NoPeersToPublish`, tcp/22 works. Rule restored (firewall `succeeded` 22:29:50.0Z): node A Connected 3.6 s later, queued message delivered 27.8 s after `succeeded` (single trial) | PASS |
| 8 | frame sizes (below) | PASS |

### The 6 race outcomes (`evidence/race-all.txt`, R2 subscribed to B's inbox content topic so its relay REST cache shows what it received)

| Round | send returned after connect | state after window (about 12-15 s of 1 s polls) | B inbox | R2 received | after R2 stop |
|---|---|---|---|---|---|
| 1 | +2.8 s | queued, attempts 0, `transport isolation violation` | 0 | 0 | delivered, B inbox 1 |
| 2 | +4.3 s | same | 0 | 0 | delivered, B inbox 1 |
| 3 | +2.1 s | same | 0 | 0 | delivered, B inbox 1 |
| 4 | +6.9 s | same | 0 | 0 | delivered, B inbox 1 |
| 5 | +1.4 s | same | 0 | 0 | delivered, B inbox 1 |
| 6 | +3.3 s | same | 0 | 0 | delivered, B inbox 1 |

(The earlier run without audit-before-publish published at 0.2-0.3 s.) The Mac was slow in this run, so the connect-to-send gap was 1.4-6.9 s, not milliseconds; the send CLI is one command right after the POST and no status call was made, but a tighter race window than a few seconds was not exercised. UNTESTED: a send racing within milliseconds of the connection from inside the daemon.

### Frame sizes (`evidence/frame-sizes.txt`, check 8, review finding M3)

Isolated single sends 7 s apart, sizes are TCP payload bytes on the public interface (the capture host coalesces segments, so sums per burst are given): A's message A->R = 855+1448+1448 = **3751 B**; B's ack of it arrives R->A as 69+2303 = **2372 B**. B's message R->A = 2372 B; A's ack of it goes A->R as 3751 B. So a message and its ack are the same size for a given sender, a one-character body and `tiny synthetic body` are the same size, and the size depends on who sent it (A 3751, B 2372; hypothesis: sender-specific certificate/envelope part, not tested). The ack is not a distinct size class from the smallest message. Other traffic in the windows (30/48/50/62-byte frames) is keepalive/gossip heartbeats; large coalesced bursts are history sync.

## Findings and observations

1. The audit-before-publish fix works against this race: 6/6 rounds not published, R2 saw nothing, everything delivered after R2 left. The audit remains detective for the node's mesh itself (R2 was connected to node A for the whole window), preventive only for AgentNet's own publishes.
2. `doctor` wording: while R2 is connected, `[FAIL] peers == allowlist` says "they are known, not connected (a connected one would be an isolation violation)" although R2 is connected. After recovery a `[warn] peers == allowlist ... knows 1 peer(s) outside the allowlist` stays until the node restarts (as in the previous run).
3. Audited-mode human `network status` prints only `isolation: ok`; the "audited" bit is visible in JSON (`isolation_audited`) and, in plain mode, as `isolation: not audited (public mode)`.
4. In the keytest message (5b) `last_error` was `None` while queued, in the race rounds it was `transport isolation violation`; both attempts 0.
5. Latencies here (p50 664/723 ms) are three times the previous run's (216/180 ms). The Mac was under load from other contributors' builds and containers (not measured); no attribution to OpenPGP versus load was made.

## UNTESTED

wss/TLS endpoint or DNS-name peers with the audited mode; more than one client; long duration or churn; the audit's own periodic cadence (all detections here were on-demand polls or send-time audits); an inbound stranger (R2 was dialled by A's own node via the admin API); why message sizes differ by sender; whether `doctor` stays red for the stale entry on a real node restart.

## Deviations and notes

- **The run was restarted from scratch.** A first attempt was interrupted (account limit); the lead deleted its droplet/firewall/key and its Mac container and no results of it exist. Its observations are not used, except one unverified remark: in that attempt R2's relay cache once showed 1 message in a race round while the message was still queued; it did not reproduce in the 6 final rounds and was not explained.
- Two race drivers were started by mistake at the same time (my error); their logs were discarded (kept outside `results/`) and all 6 rounds were rerun sequentially (`race-all.txt`).
- Another daemon on the Mac with a relative data-dir path survived my first `pkill` pattern once and held the lock (`another AgentNet process is using this data directory`); I killed it by pid and restarted A. A was restarted three times (plain switch, audited restore, firewall trial restarted only node A).
- No tags (token has no tag scope); firewall attached by droplet id, created 21:52:19Z, succeeded by 21:52:23Z; nothing listened on 60000/60001 until about 21:54Z (R) and 22:08Z (R2).
- Docker was not preinstalled on this droplet image; installed `docker.io tcpdump jq` with apt along with the build dependencies.
- B stayed audited during the plain-mode control (only A was switched).
- Mac data dirs under `/tmp/ando` (short path for the unix socket limit), removed.
- Runtime: droplet created 21:51:5xZ, deleted 22:31:49Z, about 40 min, about $0.024 at $0.036/h (per-second billing); firewall and key free.
- Cleanup: daemons stopped; `an-do-node-a` removed; droplet, firewall, key deleted, counts by name 0 (`evidence/cleanup-do.txt`); droplet IP removed from `known_hosts` and `known_hosts.old`.

## Files

`checks.jsonl`; `evidence/`: `topology.md`, `versions-and-flags.txt` (exact node flags), `firewall-rules-final.txt`, `init-public-peer.txt`, `a-init.txt`, `a-agentnet.toml`, `a-doctor-audited.txt`, `b-doctor-audited.txt`, `a-doctor-plain-before.txt`, `contacts.txt`, `untrusted-contact.txt`, `first-*.json`, `bench-*.json`, `mcp-send.json`, `mcp-status.txt`, `duplicate-check.txt`, `offline-recovery-{A,B}.txt`, `outbound-only.txt`, `packet-capture.txt`, `frame-sizes.txt`, `sizes-events.json`, `keytest-audited*.txt`, `race-all.txt`, `keytest-plain.txt`, `plain-r2-positive-control.txt`, `fw-trial.txt`, `cleanup-do.txt`, `harness/`.
