# Topology (tailnet-ACL re-run on the OpenPGP tree, 2026-11-27)

Three instabox cloud boxes (Debian 13, x86_64, native amd64 Docker 29.8.2, Tailscale 1.104.7; box 1 4 vCPU / 8 GiB, boxes 2 and 3 2 vCPU / 4 GiB), in the
provider's network behind NAT, no public IP, all joined to a THROWAWAY tailnet run by a self-hosted Headscale v0.29.7 (commit c9cf210b). The repo
holder's tailnet and the Mac's Tailscale were not used.

```
 box 1  (acl-r, tag:agentnet-relay, <TS_IP_R>)                         box 2 (acl-c1, tag:agentnet-client, <TS_IP_C1>)   box 3 (acl-c2, tag:agentnet-guest, <TS_IP_C2>)
 headscale v0.29.7 127.0.0.1:8080 (published via the instabox edge)    tailscaled + loopback ws-shim 127.0.0.1:18080       tailscaled + loopback ws-shim 127.0.0.1:18080
 loopback ws-shim 127.0.0.1:18080 (tsshim.py), tailscaled              node A1 (an-a1), REST 127.0.0.1:18650               node A2 (an-a2), REST 127.0.0.1:18660
 R (an-r1) relay+store, cluster 66 shard 0, discovery off, rln off,    agent A1 (~/a1, private mode, peer allowlist = R)   agent A2 (~/a2) = the DENIED device
   --dns-addrs-name-server=127.0.0.1, tcp_retries2=6,
   libp2p published ONLY on <TS_IP_R>:60000, --nat=extip:<TS_IP_R>
 node B (an-nb) + agent B (~/b) share R's host (B -> R over the docker bridge, not the tailnet)
 host firewall: NO AgentNet rule; access control = the Headscale policy only (evidence/check1.txt)
```

Control plane: tailscaled -> http://127.0.0.1:18080 (shim, WebSocket) -> instabox HTTPS edge (<HS_HOST>, one published port, 8080) -> headscale. The edge strips
`Upgrade: tailscale-control-protocol` (evidence/edge.txt) but passes WebSocket upgrades; the shim only converts the control connection's transport.
Data plane (WireGuard, direct or DERP) never touches it. DERP: Tailscale's public DERP map (Headscale's embedded DERP disabled).
Image: wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73. agentnet 0.1.0 built on box 1 from public main at
481eb152f3b3e1ea7ef9e22c05af20bf2ec13ff9 (`cargo build --release --locked -p agentnet-cli`), sha256 df629e51...; binary copied to boxes 2 and 3 through a Mac temp dir (removed).
Node keys of R and B are the disposable ones already public in spike/relay/.env; A1/A2 use fresh random keys. The DERP-relayed phase used a host rule on box 2
that dropped all UDP except DNS (IPv4 and IPv6); no firewall rule touched tcp/60000.
