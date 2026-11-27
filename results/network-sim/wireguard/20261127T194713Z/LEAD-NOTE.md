# Lead note: the 3 FAIL checks of this run are explained (test interference, not a leak)

This run (WATCHDOG=1, R's REST published on host port 18650) recorded 32 PASS and 3 FAIL:
`3.underlay_only_wg`, `3.no_cleartext`, `5.no_fallback`.

Cause, from the saved capture (`pcap/main-an-wg-br0.pcap`, `evidence/u-main-tcp-between-machines.txt`,
`evidence/peers-r-initial.json`): another test that the lead was running on the same Mac at the same time (the
SSH-tunnel cross-machine run) had its `agentnet` daemon configured with node URL `127.0.0.1:18650`. That port was
at that moment the published REST port of this simulation's relay R, so that daemon's static-peer redial
(`POST /admin/v1/peers`) reached R and told it to dial the other test's relay address. All 338 TCP packets and both
`multistream` strings are that one outbound connection from R to the other test; the single packet in the removal
window is a reset from the other test's relay. No relay traffic from A, B or the intruder left the tunnel;
`4.nc_blocked` and `6.no_fallback` passed.

So this was a port collision between two of the lead's own concurrent tests. It is not a change in the product or in
the simulation's firewalling. It does illustrate a documented property: the node's REST API has no authentication,
so any local process that can reach it can make the node dial a peer.

Fix: the simulations now publish their REST ports on 28650-28653 (WireGuard) and 28660-28662 (NAT), and the
WireGuard run has a new check that R lists only overlay peers. Re-runs on the same tree:
`20261127T215251Z` (WATCHDOG=0) and `20261127T223230Z` (WATCHDOG=1), 36 PASS and 0 FAIL each. This run is superseded.
