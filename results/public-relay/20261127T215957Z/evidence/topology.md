# Topology (public-internet wss run, OpenPGP tree 481eb15)

```
 Mac (macOS arm64, home NAT, outbound only)                                         instabox edge (provider)                 instabox box agentnet-rh1 (Debian x86_64, no public IP)
 -------------------------------------------                                       ---------------------------              ---------------------------------------------------------
 agent A (agentnet serve, AUDITED PUBLIC mode: init --public-relay)                 public HTTPS host <PUB_HOST>             docker-proxy 0.0.0.0:8000 -> node R ws listener
   | REST 127.0.0.1:18655                                                           resolves to 2 public addresses           node R an-r1 172.28.66.10: relay+store, cluster 66 shard 0,
 colima VM (arm64; node image runs linux/amd64 via qemu)                            TLS 1.3 terminated here, then            --websocket-support --websocket-port=8000 (plain ws),
   node A an-x-node-a                                                               plain ws forwarded to the box             libp2p tcp/60000 NOT published, REST 127.0.0.1:18640 only
   --staticnode=/dns4/<PUB_HOST>/tcp/443/wss/p2p/<R> --- TLS 1.3 / wss / 443 --->   (WebSocket upgrade passes, HTTP/1.1)  -> node B an-nb 172.28.66.22 (docker bridge, private-mode agent B),
   libp2p 60000 and ws 8000 NOT published on the Mac                                                                        REST 127.0.0.1:18642 only
   --dns-addrs-name-server=1.1.1.1, --nat=none
```

- Native wss, no client-side shim. The client node needs `--websocket-support=true` to mount the ws transport, a real DNS resolver (1.1.1.1; the zero-egress `127.0.0.1` cannot resolve the name, so node A sent DNS queries to a public resolver in this run) and `--nat=none` (the default `--nat=any` tries UPnP/NAT-PMP on the home router; the first-generation run used `--nat=extip`). The relay and node B kept `--dns-addrs-name-server=127.0.0.1`.
- Only ONE port was published: `instabox port publish agentnet-rh1 8000 --public`, 22:00:06Z to 22:10:54Z (about 10.8 min), then unpublished. REST (8645/18640) and libp2p 60000 were never published.
- Agent A config (evidence/config-a-excerpt.toml): `mode = "public"`, `i_understand_public = true`, `enforce_peer_allowlist = true`, peers = the wss multiaddr, so the allowlist (R's peer id) is audited. Agent B runs private mode on the docker bridge (shares R's host; only A <-> R crossed the public internet).
- R sees node A as `/ip4/172.28.66.1/tcp/<port>/ws` (docker-proxy hides the edge and the Mac).
- Keys: disposable test nodekeys from spike/relay/.env (public in the repo; never reuse) plus one random throwaway intruder key (not recorded). Exact flags: evidence/node-flags.txt.
