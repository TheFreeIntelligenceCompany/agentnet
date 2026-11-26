# Topology (public-IP relay run, 2026-11-26)

```
 Mac (macOS arm64, home NAT, outbound only)                        DigitalOcean droplet agentnet-pub-test (nyc1, s-2vcpu-4gb, Ubuntu 24.04, x86_64)
 -------------------------------------------                       --------------------------------------------------------------------------------
 agent A (agentnet serve, release build of b3a60a6, PUBLIC mode)    agent B (agentnet serve, native x86_64 build of b3a60a6, PUBLIC mode)
   | REST 127.0.0.1:18690                                             | REST 127.0.0.1:18642
 colima VM (linux/arm64) + qemu amd64                               docker bridge 172.28.66.0/24 ("ants")
   node A  an-do-node-a (nwaku v0.39.2 @sha256:cb4d14a2...)           node R  an-r1 172.28.66.10: relay+store, cluster 66 / shard 0, discovery off, rln off,
   --nat=none, libp2p port NOT published                                --dns-addrs-name-server=127.0.0.1, --nat=extip:<PUB_IP_R>, tcp_retries2=6,
   staticnode/storenode/... = /ip4/<PUB_IP_R>/tcp/60000/p2p/<R>         published <PUB_IP_R>:60000->60000 (the droplet's PUBLIC address), REST 127.0.0.1:18640
   |                                                                  node B  an-nb 172.28.66.22, static peer = /ip4/<PUB_IP_R>/tcp/60000/p2p/<R>, REST 127.0.0.1:18642
 home router (NAT, <PUB_IP_A>)  ====== raw tcp/60000 over the internet, no tunnel, no tailnet, no shim ======>  DO cloud firewall agentnet-pub-test-fw
                                                                      inbound tcp/22 and tcp/60000 ONLY from <PUB_IP_A>/32, outbound open (firewall-rules-final.json)
```

- Path: Mac LAN address -> home router NAT -> internet -> DO cloud firewall -> droplet eth0 -> docker DNAT -> R. R sees A at `/ip4/<PUB_IP_A>/tcp/54558` (the Mac's public address); docker's published-port DNAT preserved the source address (unlike the Tailscale run).
- Node B shares R's host; R sees B as 172.28.66.1 (docker gateway). Only A crosses the internet.
- No tag: the DigitalOcean token has no tag scope, so the droplet is untagged; the firewall was attached by droplet id.
- Keys: disposable nodekeys from `spike/relay/.env` (already public in this repo; never reuse).
- Agents run in `mode = "public"` (see SUMMARY.md): private mode refuses a public peer address.
- The Mac-side agent data dir was a short path outside the repo: macOS limits unix socket paths to 100 bytes and the scratch path was too long ("socket path ... is too long for a Unix socket").
