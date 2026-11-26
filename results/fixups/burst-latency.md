# Burst latency: what delays delivery (measurements)

Scope: single host, amd64 `nwaku v0.39.2` nodes (R1 service node, NA and NB client nodes) under qemu on an arm64 Mac, docker bridge,
two `agentnet serve` daemons on the host (`release` build). **Not representative of a real network.** Latency = `delivered_at - created_at` of the sender's
outbox row (send to authenticated receipt), 100 messages per direction, both directions concurrently, `agentnet-acceptance bench`
(`scripts/burst-bench.sh` drives it; fresh agents and daemons per run). Everything is p50 / p95 / max in ms, "A to B" then "B to A".
Raw data: the directories next to this file (`burst-*/runN/bench.json`, `metrics-{a,b}.json` = the daemon `metrics` socket method, `daemon-*.log`).

## Conclusion (with the strength of each claim)

1. **Cold relay mesh is the dominant cause of the 24 to 31 s p50 (and the ~60 s tail).** (Strong evidence.)
   After a client node is (re)created, live relay between the two client nodes does not work for about 62 s: 3 trials, 62.3 / 62.3 / 61.9 s from
   "connected to R1" to the first live frame (`mesh-warmup.txt`); in the 4 probed sets whose first run started right after the nodes were recreated, a probe published through NA never reached NB (nor the reverse) within 20 s
   (`*/run1/live-probe-before.json`). In that window a publish is accepted (HTTP 200, "accepted but lost") and the message reaches the
   recipient only through the sender's retry backoff (first retry delay uniform in [1 ms, 2 s], then doubling) or the recipient's **60 s history sync**. All 8 runs that started within a minute of a node
   recreation (`burst-after` 1, `burst-warm-cache50` 1, `burst-warm-cache1000` 1, `burst-pace0-cache50` 1, `burst-pace0-cache1000` 1, `burst-cold-hist60` 2-4) had a maximum of 60 to 64 s in at least one direction;
   p50 was about 59.5 s in 4 of them (history sync at 60 s after the daemon started, `burst-after` 1 and `burst-cold-hist60` 2-4) and 24 to 25 s in 2 (the mesh came up during the burst). Mechanism of the 62 s is not
   verified in the node source (consistent with libp2p gossipsub's 60 s prune backoff for a re-joining peer with the same fixed peer id); the *effect* is measured.
   Run 1 of `burst-cold-hist60` (nodes not recreated, warm) took 272 ms p50: the bimodality of the acceptance runs (0.3 s versus 24 to 31 s) is warm versus recently restarted topology.
   Related observation while restoring the topology (`mesh-warmup-after-r1-restart.txt`): after R1 itself was recreated, live relay between NA and NB was still dead 8 minutes later (E12), and recreating the two client nodes
   restored it in 61.5 s (same 62 s as above). `docker restart an-na an-nb` is the practical remedy.
2. **The 60 s history sync interval sets the tail, and shortening it helps directly.** Same cold setup with `delivery.history_sync_interval_s = 10`
   (daemon config, not core): p50 9.8 to 18.8 s instead of 59.3 to 59.9 s (`burst-cold-hist10` vs `burst-cold-hist60`), same 0 loss. The receipt direction needs a second pass, hence 10 and 20 s.
3. **The node's 50-slot REST cache does overflow, but it was a secondary cause here.** (Direct evidence of the mechanism, weak evidence of its share.)
   Independent of AgentNet, 100 messages published back to back on NA reached ONE poll of NB as 30 and 40 entries (two runs), 50 with 25 ms pacing and 30 of 40
   (`node-cache-probe-cap50.txt`; the rest was silently evicted). In daemon bursts with a healthy mesh (pre-run live probe 9 to 235 ms) the 50-slot setting had 1 run in 4 with a 58 s tail
   (`burst-warm-cache50` run 4: p50 1.7 s, p95 58 s) while 1000 slots had 0 in 4 (`burst-warm-cache1000` runs 2-5: max 1.2 / 4.4 / 0.8 / 3.9 s). Four runs each is too few to call this significant.
4. **Send path at maximum rate is serialised by REST publish latency.** With 0 ms pacing every message waits for the one before it, about 35 ms per publish under qemu, and
   the receipts queue behind the burst: all 100 messages complete within a narrow band (p50 about equal to max) around N x publish time (`burst-pace0-*`: 2.8 to 7.2 s with 50 slots, 1.2 to 2.8 s with 1000 on a warm mesh).
   Nothing to fix; it is a throughput bound, not a loss.
5. **Retry amplification** accompanies every bad run: the sender's `publish.ok` counter reached 605 to 744 for 100 messages plus about 100 receipts (healthy runs: 214 to 232), with 287 to 545 `message.duplicate`
   at the receiver (`metrics-*.json`). The first retry delay is `uniform[1, 2000]` ms (full jitter), so a share of messages is re-published within milliseconds of the first publish, before any receipt can exist.
   This is wasted load, not the cause of the delay.
6. **Not the cause:** `send_batch` (64; a 100-message burst takes two passes of the 250 ms loop, negligible against the observed 10 to 60 s) and the daemon's 250 ms poll interval.

## Before / after (what was changed within the fence)

Change: `--rest-relay-cache-capacity` and `--rest-messaging-cache-capacity` 50 to 1000 (compose defaults, `agentnet relay print-config`, `docs/relay-setup.md` section 3a). The nodes were recreated to apply it (so the first run of each set is cold).
Burst: 100 messages per direction, 25 ms pacing, the acceptance driver.

| Run | cache 50 (before) A to B | cache 50 B to A | cache 1000 (after) A to B | cache 1000 B to A |
|---|---|---|---|---|
| 1 | 10700 / 59507 / 59986 | 8407 / 60325 / 60877 | 59535 / 60222 / 60359 (cold: nodes just recreated) | 59369 / 60194 / 60306 |
| 2 | 14688 / 66653 / 67773 | 14701 / 67617 / 68846 | 361 / 488 / 492 | 328 / 462 / 520 |
| 3 | 787 / 50334 / 58609 | 779 / 48301 / 58802 | 476 / 917 / 999 | 475 / 740 / 860 |

(`burst-before`, `burst-after`; the mesh state of the "before" runs was not probed.) A second, probed pair of sets:

| Run | live probe NA/NB before | cache 50 A to B | cache 50 B to A |
|---|---|---|---|
| 1 | none within 20 s | 25317 / 54976 / 60174 | 22622 / 52680 / 61123 |
| 2 | 124 / 35 ms | 364 / 477 / 503 | 247 / 550 / 578 |
| 3 | 119 / 119 ms | 405 / 617 / 759 | 456 / 709 / 783 |
| 4 | 117 / 9 ms | 1723 / 58020 / 61519 | 1392 / 35217 / 59078 |
| 5 | 13 / 113 ms | 1054 / 1740 / 2252 | 1068 / 1438 / 2478 |

| Run | live probe NA/NB before | cache 1000 A to B | cache 1000 B to A |
|---|---|---|---|
| 1 | none within 20 s | 23812 / 58823 / 60387 | 25505 / 58604 / 60318 |
| 2 | 115 / 32 ms | 462 / 1139 / 1248 | 486 / 1102 / 1154 |
| 3 | 11 / 17 ms | 3778 / 4268 / 4421 | 3494 / 3891 / 3970 |
| 4 | 124 / 17 ms | 479 / 743 / 827 | 567 / 732 / 772 |
| 5 | 119 / 235 ms | 1120 / 3740 / 3886 | 1092 / 3974 / 4064 |

Honest reading: raising the cache did **not** fix cold-mesh bursts (runs 1 above are identical in both sets). On a warm mesh it removed the one 58 s outlier seen with 50 slots in this sample
and made nothing worse. `burst-latency` in the acceptance table is therefore "warm versus cold topology", not cache overflow.

Zero pacing, warm mesh unless noted (`burst-pace0-*`):

| Run | cache 50 A to B | cache 1000 A to B |
|---|---|---|
| 1 (cold) | 3528 / 63641 / 63678 | 47823 / 61955 / 61970 |
| 2 | 7216 / 7530 / 7655 | 1194 / 1336 / 1343 |
| 3 | 2815 / 3882 / 4003 | 2196 / 2416 / 2422 |
| 4 | 3052 / 3512 / 3564 | 1222 / 1609 / 1613 |

Cold start with the history interval varied (nodes recreated before runs 2-4; run 1 warm), cache 1000:

| history_sync_interval_s | run 1 (warm) | run 2 | run 3 | run 4 (A to B p50) |
|---|---|---|---|---|
| 60 (default) | 272 | 59274 | 59760 | 59421 |
| 10 | 382 | 9837 | 18336 | 9917 |

## Recommended core changes (not made; `crates/core` is outside this change's fence)

1. `delivery.history_sync_interval_s`: default **60 to 15** (measured: tail 59.5 s to about 10 to 19 s at 10 s). Each pass is one small Store query (window from `watermark - history_overlap_s`). This is a daemon/core
   default in `crates/core/src/config.rs` (`DeliveryConfig::default`); users can already set it in `[delivery]` of `agentnet.toml`.
2. `Node::backoff_ms`: replace full jitter `uniform[1, ceiling]` with "equal jitter" `ceiling/2 + uniform[0, ceiling/2]` so the first retry is never within milliseconds of the first publish (it currently
   makes 287 to 545 receiver-side duplicates per bad 100-message burst). `retry_base_ms` can stay 2000.
3. Optional: a faster history pass after the daemon observes `transport.recovered` or after start already exists (`history_kick`); a node restart while the daemon keeps running is not detectable except by the 404 on poll (adapter
   resubscribe). Calling `history_kick` when the adapter reports a resubscribe would cut the post-node-restart delay for that case. (Not measured.)

## Commands

```
CACHE=50 RUNS=3 OUT=results/fixups/burst-before scripts/burst-bench.sh         # then CACHE=1000 ... burst-after
CACHE=1000 COLD=1 NOPROBE=1 RUNS=4 HIST_S=10 OUT=results/fixups/burst-cold-hist10 scripts/burst-bench.sh
scripts/mesh-warmup.sh 3                                                        # mesh-warmup.txt
python3 scripts/burst-node-probe.py 100 0                                       # node-cache-probe-cap50.txt (nodes at cache 50)
python3 scripts/relay-live-probe.py 20                                          # live relay probe
```
