# Slow reconnect after silent path loss: root cause and fix

Written by the lead from the investigating subagent's report (the subagent could
not write this file itself). Raw data is in this directory.

## Scope and caveats

* Single-host simulation: kernel WireGuard in the colima VM, three machines as
  containers, node image `wakuorg/nwaku` v0.39.2 linux/amd64 under qemu on an
  arm64 Mac. Not Tailscale, not real NAT, not separate hosts.
* Load: an emulated x86_64 cargo build ran concurrently during parts of the
  trials, so absolute times are noisy.
* All output written before the host disk filled and the VM was restarted was
  discarded as unreliable and is not in this directory.

## Method

* Outage: 120 s, made by removing client B's WireGuard peer on relay R
  (`wg set ... peer remove`), then re-adding it. Packets are dropped silently.
* Fresh topology per trial (`FRESH=1 OUT=120 MAXWAIT=300 N=4`,
  `spike/relay-wireguard/reconnect-trial.sh`, `reconnect-matrix.sh`).
* Client action: the adapter's behaviour, `POST /admin/v1/peers` with the static
  peer every 10 s while no peer is `Connected`.
* Measured: time from path restore until B's node lists R as `Connected`;
  whether R still held a TCP socket to B at restore (`ss` on R, every tick).
* Per trial: `timeline.tsv`, `redials.tsv` (status, body, duration of every
  redial), `node.log`, `summary.json`.

## Results

| Variant | R held a stale socket at restore | Recovery after path restore |
|---|---|---|
| Baseline: redial only (`baseline-redial`, `A-redial.out`) | 1, 1, 1, 1 | not within 300 s in 4 of 4 |
| Baseline, long (`baseline-long`, `E-baseline-long.out`) | yes | 97 redials, all HTTP 400; stale socket gone at about 1307 s (21.8 min); node did not reconnect by itself in the next 60 s; then one redial connected in 0.05 s |
| Client firewall answers stale relay segments with a TCP reset (`b-rst-rule`, `C-redial-b-rst-rule.out`) | 1, 1, 1, 1 | 9.6, 9.7, 9.6, 2.3 s |
| Relay `net.ipv4.tcp_retries2=6` (`r-retries2`, `D-redial-r-retries2.out`) | 0, 0, 0, 0 (socket died 31.0 to 31.8 s after path loss) | 3.4, 5.5, 9.5, 3.6 s |
| No redial, relay `tcp_retries2=6` (`none-retries2`) | INCOMPLETE | stopped in the first trial, no numbers |

The client rule was
`iptables -A INPUT -i wg0 -s 10.66.0.1/32 -p tcp -j REJECT --reject-with tcp-reset`.
The relay setting was applied in R's network namespace with `nsenter` from the VM,
because `/proc/sys` is read-only inside the container.

## Root cause

1. The client node kills its own connections after about 48 s of failed pings
   (`node_health_monitor.nim`, keep-alive loop). The FIN cannot cross the dead path.
2. The node pings only outbound peers. The relay has only inbound client
   connections, so it never notices. Its kernel keeps a half-open TCP socket and
   keeps retransmitting.
3. The client's default-deny firewall drops those retransmits silently (no RST),
   so the socket lives until `tcp_retries2` (default 15) runs out: 1307 s in the
   one trial that measured it.
4. While the stale socket exists, each client redial completes TCP and the
   security handshake, then the relay closes it
   (`evidence/b-wg0-tcpdump-two-redials-while-stale.txt`); the client sees
   HTTP 400 "Failed to connect" after about 45 ms.

**UNTESTED at source level:** why the relay closes the new connection. Inferred:
one connection per peer (`MaxConnectionsPerPeer = 1`, `waku_switch.nim:22`); the
libp2p connection-manager source was not read.

## Hypotheses

* H1, failed redials grow the node's backoff and slow recovery: **refuted**. The
  REST dial does not check the backoff; one redial connected in 50 ms as soon as
  the stale socket was gone.
* H2, the REST redial does not dial: **refuted**. It dials (10 s timeouts during
  the outage, about 45 ms rejections after).
* H3, the online monitor (with `--dns-addrs-name-server=127.0.0.1`) gates dialing:
  **refuted** for this failure. The node logged "Node is offline" while redials
  dialed and then succeeded.
* H4, a half-open socket on the relay: **confirmed** as above.

## Fix

* No client-side or adapter fix exists: the adapter cannot affect the relay's
  kernel. The adapter is unchanged; its redial is what reconnects once the stale
  socket is gone (the node did not reconnect by itself).
* Relay side: `net.ipv4.tcp_retries2=6` on the relay (compose `sysctls`, printed
  by `agentnet relay print-config`; a host `sysctl` when the relay uses host
  networking). Stale sockets then die after about 31 s.
* Alternative when the relay host cannot be changed: the client firewall answers
  stale relay segments with a TCP reset.

## Not tested

* Side effects of `tcp_retries2=6` on lossy but healthy links.
* Whether the spread seen in the NAT simulation has the same cause.
* Real Tailscale, real NAT, separate hosts.
* "Restarting the relay node clears the stale socket": only used as a reset in
  discarded data.
* `reconnect-forced.sh` (an attempt to force the stale socket by restarting B's
  node) did not reproduce the condition and is not evidence.
