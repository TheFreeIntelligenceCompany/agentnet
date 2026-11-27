# Tailscale cross-machine run on the OpenPGP tree

Written by the lead from the subagent's report (the subagent could not write this
file). Raw data: `checks.jsonl` (24 records), `evidence/`, `evidence/harness/`.

## What was run

* Commit: box binary built from main at `301b12d`; Mac binary built from `481eb15`
  (`301b12d` only adds a log file). Message protection: RFC 9580 OpenPGP,
  sequoia-openpgp 2.5.0, OpenSSL 3. Single run, 2026-11-27 21:57Z to 23:12Z.
* Two real hosts on the repository holder's hosted Tailscale tailnet: a Mac behind
  a home NAT (Tailscale 1.102.3; node A in colima, agent A) and a cloud Linux box
  (Tailscale 1.104.7; relay/store R, node B, agent B).
* R's libp2p tcp/60000 published only on the box's tailnet IPv4; REST on loopback;
  raw-table PREROUTING rules allowing tcp/60000 only from the Mac's tailnet
  address, the box and node B. `tcp_retries2=6` on R.
* Path: **direct** (WireGuard over IPv6), `tailscale ping` 74 to 90 ms. Recorded,
  not changed.

## Results (single trials)

| Check | Result |
|---|---|
| Tailnet peers, direct path | PASS |
| Each client lists exactly R, Connected; `doctor --ready` exit 0 on both hosts | PASS |
| Wrong `--expect` refused (exit 4); correct `--expect` accepted both ways | PASS |
| First message A to B 525 ms, B to A 643 ms, authenticated receipts | PASS |
| MCP `send_message`: call 47 ms, receipt 1055 ms | PASS |
| 20 A to B: 20/20, p50/p95/p99 = 709/1367/2332 ms | PASS |
| 20 B to A: 20/20, p50/p95/p99 = 681/1464/1979 ms; no duplicate ids | PASS |
| B offline, 5 messages: receipts 3.2 to 3.4 s after B's node start | PASS |
| A offline, 5 messages: receipts 52.8 s after A's start was issued (the emulated node start was itself slow) | PASS |
| Port answers on the tailnet address from the Mac; no other address answers; only listener is docker-proxy on the tailnet address; no published instabox port | PASS |
| Firewall rule swapped to DROP then restored: A Connected 1 s after restore, queued message delivered 32.5 s after | PASS |
| Packets: 205 for tcp/60000 on `tailscale0`, 0 on the primary interface (270 WireGuard UDP packets there) | PASS |
| Tailnet ACL policy | UNTESTED here (a tag policy was verified separately on Headscale, `results/tailnet-acl/`) |

Silent loss (120 s drop, one trial): R's first retransmission at +6 s; R's
half-open socket destroyed at +45 s (39 s after the first retransmission); A
noticed between +52 and +63 s; after restore A was Connected 1 s later and the
queued message was delivered 32.5 s later.

Wire sizes: an acknowledgement and the smallest message are both 2303 bytes of
TCP payload on `tailscale0`, in both directions. Two extra 2303-byte records are
unexplained (`evidence/wire-sizes.txt`).

## Idle stale socket and the relay-side watchdog (first real-host test)

* A single 75 s drop did not produce the idle case: R had unacked data, so
  `tcp_retries2` removed the socket at +45 s.
* A 30 s drop, restore, 12 s gap, then a 75 s drop reproduced it in 2 of 4 trials
  designed for it. Without the watchdog R held an established socket with no
  timer and no traffic; the client was locked out for **5 min 54 s** after the
  path returned, and the queued message was delivered 9 min 34 s after the path
  returned (the extra 3 min 40 s after reconnection was not investigated).
* **The repository's `stale-watchdog.sh` refused to start on this host**
  (iproute2 6.15, kernel 6.18): `ss -K` prints `RTNETLINK answers: Invalid
  argument` on stderr with exit 0 even when it works, and the script treated any
  stderr as fatal. A copy that tolerates that exact line was used
  (`evidence/stale-watchdog-patch.diff`); the repository script has since been
  given the same change.
* With the patched watchdog (60 s idle threshold, pass every 10 s) in R's network
  namespace: it destroyed the stale socket after 68.5 s without data, 8 s before
  the path was restored; A was Connected 2 s after the restore and the probe was
  delivered 21 s after it was queued. One trial each, with and without.
* The mechanism behind the idle socket is inferred from the sampler data, not
  proven. The "exactly 8 minutes" expiry seen in an earlier run did not recur
  (6:29 to 6:49 after last traffic here; cause UNTESTED).

## What this is and is not

Two real hosts on one real hosted tailnet, relay reachable only at its tailnet
address and firewalled to one client, direct path. Not tested here: tailnet ACL
enforcement on the hosted control plane, key expiry, MagicDNS, a DERP-relayed
path (covered on Headscale), a third unauthorised tailnet device, agent B on a
third host (B shares the relay's host; only A crosses the tailnet). Latencies are
single-run numbers taken while the Mac was under load from other tests.

## Notes

* The `checks.jsonl` records for 2a to 2e were written after the fact; the
  measurements are in the evidence files with their own times.
* R's own peer list sometimes showed A as `CannotConnect` while messages were
  delivered; the socket data was treated as the reliable evidence.
* Cleanup: daemons and watchdog stopped, Mac container removed, box logged out of
  the tailnet and deleted. The device record `agentnet-ts-test` must be removed
  in the Tailscale admin console by the repository holder.
