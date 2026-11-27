# Public-internet client-to-relay run (instabox edge, native wss), audited public mode, 2026-11-27

Commit 481eb15 (`agentnet 0.1.0`; Mac binary built from 481eb15, box binary built on the box from a `git clone --depth 1` of main at 481eb152f3b3). Message protection is RFC 9580 OpenPGP (sequoia-openpgp 2.5.0, OpenSSL 3). nwaku v0.39.2 `@sha256:cb4d14a2...`. **Single run.** This repeats the 2026-11-26 public-relay run, this time with agent A in the audited public mode that did not exist then. Earlier attempt cut off by an account limit is preserved separately (`20261127T195424Z`, marked PARTIAL). Box `agentnet-rh1` (4 vCPU / 8 GiB): created 21:51:51Z, deleted 22:14:15Z (22.4 min, shared with the cross-machine run). Raw results: `checks.jsonl` (real event times); evidence under `evidence/`.

## What this is

Native secure WebSocket, no shim. R serves plain `ws` on 8000; the provider edge publishes it (public HTTPS URL, TLS 1.3 terminated at the edge, WebSocket upgrade passes). The Mac's nwaku node dials `/dns4/<PUB_HOST>/tcp/443/wss/p2p/<R>` over the public internet, from behind home NAT, outbound only. Agent A: `agentnet init --public-relay --peer ...` (mode public, `i_understand_public = true`, `enforce_peer_allowlist = true`). Contact exchange with `--expect`, OpenPGP-encrypted messages, authenticated receipts, MCP send and Store recovery worked over that path.

## What this is NOT

- Not a relay with its own public IP and raw tcp/60000: the endpoint is a TLS/WebSocket front end operated by the provider's edge, which terminates TLS and forwards plain ws; libp2p's own Noise inside the ws stream was not separately verified, and payloads are additionally OpenPGP-encrypted.
- Not NAT traversal / hole punching; not public Waku/Logos infrastructure (private cluster 66 shard 0, discovery off, RLN off, one own relay, no public bootstrap contacted); not a load test (20 messages per burst), not fault injection, no IPv6.
- Agent B runs on the relay's host in private mode; only A crossed the public internet.
- DNS: node A used a public resolver (1.1.1.1), so "zero public egress" did not hold for node A.
- Not audited, no forward secrecy; the exposure finding below stands.

## Result table

| Check | Result |
|---|---|
| 1 Endpoint reachable from the public internet | PASS: TLS 1.3 verified, resolves to global addresses, WebSocket upgrade 101 |
| 1b Private-mode `init` refuses the wss/DNS peer and the public IP literal (rc 4) and names `--public-relay` | PASS |
| 2 Client nodes list exactly R Connected; `doctor --ready` rc 0 on both | PASS |
| 2b Audited public mode: `doctor` shows `[ok] isolation: no isolation violation reported` and `[ok] peers == allowlist: 1 connected, all in the allowlist`; `network status` mode public, isolation ok, ready true | PASS |
| 3 Contacts with `--expect` both ways, wrong `--expect` refused (rc 4); add without `--expect` is untrusted | PASS |
| 3 first A->B 2263 ms (cold), B->A 1044 ms; MCP `send_message` delivered (690 ms) | PASS |
| 3 20 msgs A->B: 20/20, p50/p95/p99 = 1160/2453/4142 ms | PASS |
| 3 20 msgs B->A: 20/20, p50/p95/p99 = 457/692/694 ms; inbox rows unique both directions | PASS |
| 4 B offline: 5/5 delivered 7.7-11.8 s after restart | PASS |
| 4 A offline: 5/5 delivered 28-36 s after node start (T0 approximated from the node log; the first poll was cut off by the exec time limit) | PASS |
| 5 Outbound-only: no 60000/8000 listener on the Mac; R sees A as 172.28.66.1 over ws | PASS |
| 6 Exposure | FINDING: a stranger with the right cluster id joins via the public endpoint, receives live frames and pulls R's Store history (101 messages). Every payload is a uniform **2197-byte** ciphertext frame (564 bytes with HPKE+Ed25519), topics inbox-00 / inbox-04 visible, 0 hits for the plaintext canary. |
| 6 REST not exposed: 502 on all paths through the edge, other ports 404, raw TCP on the public IPs times out, only port 8000 published | PASS |
| 7 Unpublish: edge answers 404, node A CannotConnect within ~11 s, a message sent afterwards stayed queued (NoPeersToPublish, 148 s watched). Recovery not tested | PASS |

## Deviations and notes

- A->B latencies were notably worse than the 2026-11-26 run (p50 1160 vs 440 ms); one run, cause not investigated (OpenPGP frame size 2197 bytes vs 564, or edge/network variance, not separated).
- Re-adding a known untrusted contact with the right `--expect` did NOT raise its trust (it stayed `untrusted`, `updated:false`); `contact remove` followed by `add --expect` did, see `evidence/contacts.txt`. Worth documenting or fixing.
- The relay's ws port stays open to anyone while published; the relay was published about 10.8 min.
- Doctor's allowlist audit works in public mode with `enforce_peer_allowlist = true`; the audit compared peer ids (the wss address resolves to the edge's address, the peer id is what is checked).
- Untested: recovery after re-publish, silent blackhole, NAT traversal, two public clients.

## Cleanup

Port unpublished, box deleted, `an-x-*` containers removed, agent A stopped and its data dir removed. See `evidence/cleanup.txt`.
