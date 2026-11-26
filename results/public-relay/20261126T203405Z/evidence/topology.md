# Topology (public-internet wss run, 2026-11-26)

```
 Mac (macOS arm64, home NAT, outbound only)                                         instabox edge (provider)                 instabox box agentnet-pub-r (Debian x86_64, no public IP)
 -------------------------------------------                                       ---------------------------              ---------------------------------------------------------
 agent A (agentnet serve, PUBLIC mode)                                              public HTTPS host <PUB_HOST>             docker-proxy 0.0.0.0:8000 -> node R ws listener
   | REST 127.0.0.1:18650                                                           resolves to public addresses (<PUB_IP>)   node R an-r1 172.28.66.10: relay+store, cluster 66 shard 0,
 colima VM (arm64; node image runs linux/amd64 via qemu)                            TLS 1.3 terminated here, then            --websocket-support --websocket-port=8000 (plain ws),
   node A an-x-node-a                                                               plain ws forwarded to the box             libp2p tcp/60000 NOT published, REST 127.0.0.1:18640 only
   --staticnode=/dns4/<PUB_HOST>/tcp/443/wss/p2p/<R> --- TLS 1.3 / wss / 443 --->   (WebSocket upgrade passes, HTTP/1.1)  -> node B an-nb 172.28.66.22 (docker bridge, private mode agent B),
   libp2p 60000 and ws 8000 NOT published on the Mac                                                                        REST 127.0.0.1:18642 only; agent B config private, peer /ip4/172.28.66.10/tcp/60000/p2p/<R>
   --dns-addrs-name-server=1.1.1.1 (see below)
```

- Approach A (native wss): the nwaku node in the pinned image dials `/dns4/<host>/tcp/443/wss/p2p/<R>` itself (it also needs `--websocket-support=true`, otherwise no ws transport is mounted). No client-side shim.
- Only ONE port was published: `instabox port publish agentnet-pub-r 8000` (public access), for 20:34:29Z..20:45:00Z (~10.5 min), then unpublished.
- DNS: `--dns-addrs-name-server=127.0.0.1` (the zero-egress setting) cannot resolve the published name. 127.0.0.11 (docker embedded DNS) did not resolve either (node stayed CannotConnect; cause not isolated). `--dns-addrs-name-server=1.1.1.1` worked: node A therefore sent DNS queries to a public resolver (a deliberate relaxation of "zero public egress" for this run). The relay and node B kept 127.0.0.1.
- Node A also needed `--nat=extip:<container ip>`; with the default `--nat=any` it tried UPnP/NAT-PMP port mapping on the home router ("NAT port mapping failed" in the first attempt). Final run used extip, no mapping attempts.
- Connections as seen by R: node A appears as `/ip4/172.28.66.1/tcp/<port>/ws` (the docker bridge gateway; docker-proxy hides the edge's and the Mac's addresses).
- Agent B shares R's host; B <-> R is on the docker bridge, not the public path. Only A <-> R crossed the public internet (via the provider edge).
- Keys: disposable test nodekeys from spike/relay/.env (already public in the repo; never reuse) plus one random throwaway intruder key (not recorded).
- Exact flags: evidence/node-flags.txt (nodekeys redacted).
