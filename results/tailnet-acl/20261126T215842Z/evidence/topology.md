# Topology (tailnet-ACL run, 2026-11-26)

Three instabox cloud boxes (Debian, x86_64, 2 vCPU / 4 GiB, native amd64 Docker 29.8.2, Tailscale 1.104.7), all in the provider's
network behind NAT, no public IP. All three joined a THROWAWAY tailnet run by a self-hosted Headscale v0.29.7. The repo holder's
tailnet and the Mac's Tailscale were not used.

```
 box 1  (acl-r, tag:agentnet-relay, <TS_IP_R>)                           box 2 (acl-c1, tag:agentnet-client, <TS_IP_C1>)   box 3 (acl-c2, tag:agentnet-guest, <TS_IP_C2>)
 ----------------------------------------------------                    -----------------------------------------------   ----------------------------------------------
 headscale v0.29.7  127.0.0.1:8080 (published via the instabox edge)     tailscaled                                          tailscaled
 loopback ws-shim 127.0.0.1:18080 (tsshim.py)                            loopback ws-shim 127.0.0.1:18080                    loopback ws-shim 127.0.0.1:18080
 tailscaled                                                              node A1 (an-a1), REST 127.0.0.1:18650               node A2 (an-a2), REST 127.0.0.1:18660
 R  (an-r1) relay+store, cluster 66 shard 0, discovery off, rln off,       static peer /ip4/<TS_IP_R>/tcp/60000/p2p/<R>        static peer /ip4/<TS_IP_R>/tcp/60000/p2p/<R>
    --dns-addrs-name-server=127.0.0.1, tcp_retries2=6,                   agent A1 (~/a1, private mode, peer allowlist = R)   agent A2 (~/a2, same config) = the DENIED device
    libp2p published ONLY on <TS_IP_R>:60000 (docker -p), --nat=extip:<TS_IP_R>
 node B (an-nb) + agent B (~/b)  (B shares R's host; B -> R over the docker bridge/host, not the tailnet)
 host firewall: NO AgentNet rule; access control = the Headscale policy only (evidence/check1.txt)
```

Control plane path: tailscaled -> http://127.0.0.1:18080 (shim, WebSocket) -> instabox HTTPS edge (<HS_HOST>, one published port, 8080) -> headscale.
The edge strips the HTTP Upgrade header Tailscale clients use (evidence/edge.txt) but passes WebSocket upgrades; Headscale accepts the
same Noise handshake over WebSocket. The shim only converts the transport of the control connection; data-plane traffic (WireGuard, DERP/direct)
does not touch it. DERP: Tailscale's public DERP map (Headscale embedded DERP disabled, because its /derp Upgrade would be stripped by the same edge:
not tested). Public DERP servers only carry WireGuard-encrypted packets (used for the first seconds, then the path went direct).
Images: wakuorg/nwaku@sha256:cb4d14a22b8c5dad6ebfd86316c4fe33c4be8d68d48f155429c59117fc7c6b73. agentnet 0.1.0 built from public main at 92e91ce
(`cargo build --release --locked -p agentnet-cli` on box 1, binary copied to boxes 2 and 3; sha256 d1e05f94...).
Node keys of R and B are the disposable ones already public in spike/relay/.env; A1/A2 use fresh random keys.
