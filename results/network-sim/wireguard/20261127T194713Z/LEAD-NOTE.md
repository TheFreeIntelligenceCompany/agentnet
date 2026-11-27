# Lead note: this run has 3 unresolved FAIL checks

Run of 2026-11-27 on the OpenPGP tree (commit 4b08e58) with the stale-watchdog sidecar enabled
(`WATCHDOG=1`, a script change made for this run). 32 PASS, 3 FAIL:

* `3.underlay_only_wg`: TCP between the machines was seen on the underlay (338 packets) besides WireGuard UDP.
* `3.no_cleartext`: the cleartext string `multistream` appeared twice in the main underlay capture.
* `5.no_fallback`: 1 TCP packet between the machines in the peer-removal window.

In the two runs of 2026-11-26 on the previous tree these checks passed with 0 such packets. The subagent that
ran this was cut off by the account spend limit before it could investigate, and the lead has not investigated
either. **Cause unknown.** Candidates, none verified: the capture windows overlapping the intruder control
phase (which is expected to show cleartext libp2p on the underlay), the script changes made for the watchdog
profile, other test containers running on the same docker host at the time, or a real change in the
simulation's firewalling. AgentNet itself does not control underlay routing, but until this is explained the
WireGuard simulation is **not verified** on this tree. The NAT simulation was not re-run.
