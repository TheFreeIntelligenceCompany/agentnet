# Idle stale relay socket: cause and relay-side watchdog

Written by the lead from the investigating subagent's report (the subagent could
not write this file). Raw data per trial is in this directory (`<variant>-<n>/`:
`events.tsv`, `timeline.tsv`, `ss.log` = the relay's `ss -tion` for the client's
socket every ~2 s, `b-ss.log`, `b-node.log`, `r-node.log`, `summary.json`).

## Scope and caveats

* Single-host simulation: kernel WireGuard in the colima VM, node image
  `wakuorg/nwaku` v0.39.2 linux/amd64 under qemu on an arm64 Mac, 2 s polling.
  Not real hosts. The watchdog is **UNTESTED** on real hosts and on Tailscale.
* Few trials: 2 idle baselines, 3 watchdog trials, 3 heartbeat trials, 1 idle
  relay-restart trial (time box).

## The problem

After a silent path loss the client node gives up (about 47 to 56 s) and closes
its connection. If that close never reaches the relay and the relay has nothing
in flight to that client, the relay keeps an established socket that is idle:
no retransmission, so `net.ipv4.tcp_retries2` (the fix for the retransmitting
case, `results/reconnect/20261126T065412Z/SUMMARY.md`) never applies. While the
socket exists the relay refuses every new connection from that peer id (each
redial returns HTTP 400 in about 50 to 100 ms). Seen once on real hosts:
7 min 25 s lockout (`results/tailscale-cross-machine/20261126T192147Z/`).

## Reproduction

`spike/relay-wireguard/reconnect-up.sh`, then
`spike/relay-wireguard/reconnect-idle-trial.sh`: drop the client's overlay
address on the relay's `wg0` in both directions for 70 s; redial every 10 s
while the relay is not Connected; time recovery from the end of the block.

Two conditions make the case idle:

1. The client's close must never reach the relay. With default settings the
   client kernel keeps retrying its FIN and delivers it when the path returns,
   which cleans up the relay (trial `debug-1`: recovered in 2.4 s). The trials
   set `net.ipv4.tcp_orphan_retries=1` in the client's namespace as a stand-in
   for a lost FIN (expired NAT mapping, sleeping laptop).
2. The relay must have nothing in flight to the client. This is not
   controllable; a trial counts as idle only if `ss.log` shows no timer and no
   unacked data and the socket is still present when the path returns.

## Results

| Variant | Idle confirmed | Recovery after the path returned |
|---|---|---|
| Baseline, no fix (`probe-1`) | yes | 495.8 s (48 redials, all refused) |
| Baseline, relay at DEBUG (`debugstale-1`) | yes | 401.5 s |
| Relay-side watchdog, 60 s idle threshold (`watchdog60-1..3`) | yes, 3 of 3 | 2.4 s, 2.4 s, 2.4 s; socket destroyed 63.8, 59.2, 60.4 s into the block |
| Relay heartbeat every 20 s with `tcp_retries2=6` (`kick20r6-1..3`) | no longer idle by construction | 2.4, 2.4, 2.5 s. Not recommended: it publishes a message to every client and the Store |
| Restart the relay node when the path returns (`relayrestart-1`) | yes | 13.8 s; drops all of the relay's connections |
| Client firewall TCP-reset rule (`clientrst-1`, `clientrstb-1`) | **no** (the socket was retransmitting) | invalid for the idle case: **UNTESTED** |

## Cause

* Measured: the node sets no `SO_KEEPALIVE` (no keepalive timer on any libp2p
  socket), so the kernel `tcp_keepalive_*` settings do nothing; `tcp_retries2`
  does nothing because nothing is retransmitted.
* Source (`node_health_monitor.nim`): the keep-alive loop pings only outbound
  peers; the intervals are function defaults, not flags; `--help` of the pinned
  image has no keepalive, ping or idle option. A relay never pings its inbound
  clients.
* What ends the socket: the node closes it by itself after about 473 s and
  565 s idle in the two baselines (8 min on real hosts). The DEBUG log names no
  cause. `waku_switch.nim` passes 5-minute in/out timeouts to the stream
  multiplexer, which is consistent with a libp2p inactivity timeout, but this
  is **inferred**: the libp2p source was not available to read.

## Fix

`spike/relay-wireguard/scripts/stale-watchdog.sh [port] [idle_s] [every_s]`,
run in the relay's network namespace with `NET_ADMIN`: every 10 s it destroys
(`ss -K`) established sockets on the relay port that have received nothing for
60 s. Healthy client connections showed `lastrcv` of 1 to 6 s throughout, so a
60 s threshold did not touch them. Worst case is about 70 s after the client's
last packet plus the client's next redial. The compose file of
`spike/relay-wireguard` has it as an optional sidecar (profile `watchdog`);
`agentnet relay print-config` mentions it.

Not studied: a client that is legitimately quiet for more than 60 s would be
cut and would have to redial.

## No client-side fix

Nothing the client or the adapter does can clear the relay's socket: the relay
sends nothing on it, and redials are refused. A manual relay-node restart
clears it (13.8 s to reconnect, all clients dropped).
