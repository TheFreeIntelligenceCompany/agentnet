# `enforce_peer_allowlist` against a real public-IP relay, 2026-11-26

## What this is and is not

- IS: the audited public mode (`mode = "public"`, `i_understand_public = true`, `enforce_peer_allowlist = true`) run end to end against **one relay/store node R with its own public IPv4 on raw tcp/60000** (DigitalOcean droplet, nyc1, s-2vcpu-4gb, Ubuntu 24.04, x86_64), reached directly over the internet by agent A on a Mac behind a home NAT (node A in colima, amd64 under qemu). Same topology as `results/public-ip-relay/20261126T204713Z/`, harness reused (`evidence/harness/`). Private test relay only: cluster 66 / shard 0, discovery off, RLN off, image `wakuorg/nwaku@sha256:cb4d14a2...` (v0.39.2), R with `tcp_retries2=6`, `--dns-addrs-name-server=127.0.0.1`; no public Waku network was contacted; no load.
- Cloud firewall `agentnet-pub-test-fw` (attached by droplet id before anything listened): inbound tcp/22, tcp/60000 and tcp/60001 only from the Mac's single public IPv4 (`evidence/firewall-rules-final.txt`). No third party was admitted. The "foreign peer" R2 is a second node of mine on the same droplet (libp2p tcp/60001, different disposable nodekey, same cluster/shard), not a stranger.
- IS NOT: a wss/TLS endpoint test, a DNS-name peer test, a multi-client or long-duration run, or a statistically meaningful benchmark (single samples). Agent B shares R's host (B<->R never crosses the internet; only A does).
- Binaries: Mac `target/release/agentnet` built from HEAD **e0bc847**; droplet built from `git clone --depth 1` of the public repo at main = **14631fd** (`cargo build --release --locked -p agentnet-cli`, 8 min 29 s). `git diff e0bc847 14631fd` touches docs only (AGENTS.md, README, 6 docs files), no `crates/` change, so the two binaries have identical source.
- Scrubbed: droplet IP `<PUB_IP_R>`, Mac public IP `<PUB_IP_A>`, scratch paths, macOS user, droplet/firewall/key ids. Agent addresses, message ids and disposable-key peer ids are left in (synthetic).

## Results (17 records in `checks.jsonl`)

| # | Check | Result |
|---|---|---|
| 1 | A (Mac) and B (droplet) in audited mode: `serve` starts; `doctor` and `doctor --ready` exit 0 with `[ok] isolation: no isolation violation reported`, `[ok] peers == allowlist: 1 connected, all in the allowlist`, `[ok] transport ready: node reachable; 1 connected allowed peer(s)`; `network status` ready true | PASS (`a-doctor-audited.txt`, `b-doctor-audited.txt`) |
| 2 | contact exchange with `--expect` (wrong `--expect` refused, rc 4); first messages A->B 289 ms, B->A 164 ms with authenticated receipts; 20/20 each way, A->B p50/p95/p99 = 216/416/417 ms, B->A 180/230/234 ms; B's node down, 5 messages from A, all delivered 1.4 s after node B restart | PASS |
| 3a | node A told via its own REST admin API (`POST /admin/v1/peers`) to connect to R2: first `network status` 0.3 s later is `ready: false`, `ISOLATION VIOLATION: node is connected to 1 peer(s) not in the allowlist (e.g. 16Uiu2HAmKGK...)`; `doctor --ready` exit 7 with `[FAIL] isolation`, `[FAIL] peers == allowlist` and `-> the node is connected to a peer outside agentnet.toml: restart it with the verified flags` | PASS (`keytest-audited.txt`) |
| 3b | a message sent after detection: `state=queued attempts=0 last_error=transport isolation violation` for 50 s; B's inbox for that conversation: 0 | PASS |
| 3c | `docker stop an-r2`: violation cleared at the first poll (0.1 s), message published and delivered 1.2 s after the stop (queued about 59 s in total), B inbox 1; `doctor --ready` ok again (a `[warn] peers == allowlist ... knows 1 peer(s) outside the allowlist` stays while R2 is listed `CannotConnect`) | PASS (`keytest-audited-recovery.txt`) |
| 3d | **race window**: a message sent 0.2 s / 0.3 s after connecting R2 with no `status`/`doctor` call in between was **published** (`state=sent attempts=1`) although `network status` showed `ready=False` right after; its receipt only came after R2 was stopped (30 s / 33 s) | FINDING (`keytest-audited-race.txt`) |
| 4 | plain public mode, same R2 connection: 55 s of polling `ready=True connected=2 violation=None`; `doctor --ready` exit 0 with `[skip] isolation: not audited in public mode; the node may be connected to any peer` and `[skip] peers == allowlist: public mode: no allowlist audit ...`; transport line `node reachable; 2 connected peer(s) (public mode: peers not audited)` (no "allowed"); a message was sent and delivered through the node meshed with R2 | PASS (`keytest-plain.txt`, `a-doctor-plain-before.txt`) |
| 4b | plain mode `network status` still prints `isolation: ok` | FINDING |
| 5 | `enforce_peer_allowlist = true` with `mode = "private"` refused (doctor rc 7, serve rc 4) with the actionable message; `/p2p-circuit` peer refused in audited mode; `/dns4/relay.example.org/tcp/443/wss/p2p/<id>` accepted by `doctor`'s config check (**config validation only; no wss relay was running, nothing was resolved or dialled**) | PASS (`config-validation.txt`) |
| 6 | `agentnet init --peer <public ip>` exits 0, writes `mode = "private"` with that peer, no warning; `doctor --ready` then fails rc 7 and `serve` rc 4 with `static_peers entry rejected in private mode: address must be a literal private IP`. `init` has no flag for public/audited mode | INFO (`init-public-peer.txt`) |

## Findings

1. **The audit is detective, with a race window (3d).** Sends racing the first audit leave the node. Here the first audit after the connection was effectively immediate on `network status`/`doctor` calls, but a send with no prior status call was published. The docs already say "detective, not preventive"; this run shows the concrete consequence: a message can be published to a node that is already meshed with a stranger. Whether R2 actually received that envelope was not inspected (UNTESTED; the envelope is HPKE-encrypted to B either way). I did not measure the audit's own periodic cadence (15 s per the docs) separately from on-demand audits triggered by `status`/`doctor`; so "within one audit interval" is not proven here, only "0.3 s when polled".
2. Plain public mode `network status` prints `isolation: ok` while `doctor` says not audited (4b). Suggested fix: print `isolation: not audited (public mode)`.
3. `init --peer <public ip>` is a usability trap (6), known and being fixed separately.
4. After a foreign peer disconnects, `doctor` keeps a `[warn] peers == allowlist` for the stale `CannotConnect` entry until the node is restarted; harmless, but it means `doctor` is not fully green after a recovered incident.

## What is now TESTED vs UNTESTED

TESTED on a real public-IP relay (raw tcp, single Mac client behind NAT, single run): audited mode starts and reports an honest `[ok]` from a real audit; messaging, receipts, latency and offline recovery work in it; a real foreign peer meshed into node A is detected, `ready` goes false, sends are held queued (not published) after detection, doctor exits non-zero with an actionable message, and everything recovers when the peer goes away; plain public mode does not flag the same event and `doctor` says so; config validation of the new key on the real binary.

UNTESTED: a `/dns4/.../wss` (or `/tls`) endpoint with the audited mode (only config validation ran); DNS-name peers end to end; more than one client; long duration / audit under churn; the periodic (not on-demand) audit cadence; whether the stranger actually received a racing message; a stranger that dials in (inbound) rather than being dialled by A's own node (I simulated "meshed" via A's admin API, so inbound-only exposure was not exercised); redial of allowlisted peers after a drop in this mode.

## Deviations and notes

- No tags (token has no tag scope); firewall attached by droplet id. Firewall created 21:11:38Z-21:11:44Z after the droplet was active at 21:11:28Z; key-only ssh was reachable for those seconds; nothing listened on 60000/60001 until 21:14:27Z / 21:25Z.
- tcp/60001 was opened to the Mac's IP from the start (nothing listened on it until R2 started).
- B stayed in audited mode during the plain-mode control (only A was switched; B never meshed with R2).
- The harness `keytest.sh` ran the audited recovery separately by hand (`keytest-audited-recovery.txt`).
- Mac data dirs were under a short scratch path (unix socket length limit); removed.
- Runtime: droplet created 21:11:28Z, deleted 21:29:56Z = 18 min 28 s (about $0.01 at $0.036/h; per-second billing, 60 s minimum). Firewall and key free.
- Cleanup: daemons stopped; Mac `an-do-node-a` removed; droplet `an-r1`/`an-r2`/`an-nb` removed with the droplet; droplet, firewall `agentnet-pub-test-fw`, key `agentnet-pub-test-key` deleted; counts by name 0 (`cleanup-do.txt`); droplet IP removed from `~/.ssh/known_hosts` (and from the `.old` backup ssh-keygen made).
