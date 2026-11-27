# Topology (Tailscale cross-machine run on the final tree, 2026-11-27)

```
 Host 1: Mac (macOS arm64, home NAT)                                 Host 2: instabox sandbox VM (Debian x86_64, kernel 6.18, native amd64 Docker)
 agent A (agentnet serve, release build, data dir with a short path)   agent B (agentnet serve, built on the box from the public repo at 301b12d)
   | REST 127.0.0.1:18670 (colima VM, linux/arm64, amd64 via qemu)      | REST 127.0.0.1:18642
   node A  an-tsx-node-a, static peer = /ip4/<TS_IP_B>/tcp/60000/p2p/<R> docker bridge 172.28.66.0/24 ("ants")
   libp2p port not published                                              node R  an-r1 172.28.66.10  relay+store, cluster 66 shard 0, discovery off, rln off,
 Mac tailscale (<TS_IP_A>) <==== WireGuard, direct UDP over IPv6 ====>      --dns-addrs-name-server=127.0.0.1, --nat=extip:<TS_IP_B>, container sysctl tcp_retries2=6,
                                                                            published ports: <TS_IP_B>:60000->60000 and 127.0.0.1:18640->8645 (REST)
                                                                          node B  an-nb 172.28.66.22, static peer = same tailnet multiaddr (via docker-proxy)
                                                                          raw PREROUTING (tcp/60000 to <TS_IP_B>): ACCEPT <TS_IP_A>, ACCEPT <TS_IP_B>, ACCEPT 172.28.66.22, DROP otherwise
```
- The colima VM reaches tailnet addresses through the Mac's routing; no forwarder was used.
- R sees BOTH clients as the docker bridge gateway 172.28.66.1 (A through tailscaled's ts-postrouting MASQUERADE, B through docker-proxy), with different source ports.
- Agents' peer allowlist = R only. Node A and node B each list exactly R, Connected. R lists A and B, Connected.
- Image wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73. Disposable node keys: R and B from spike/relay/.env (public in the repo), node A's key random per run.
- Relay-side watchdog: `sudo nsenter -t <R pid> -n sh stale-watchdog-patched.sh 60000 60 10` (R's network namespace on the box).
