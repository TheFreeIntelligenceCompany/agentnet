# Topology (Tailscale cross-machine run, 2026-11-26)

```
 Host 1: Mac (macOS arm64, home NAT, outbound only)                 Host 2: instabox sandbox VM (Debian x86_64, native amd64 Docker)
 -------------------------------------------------                -----------------------------------------------------------------
 agent A (agentnet serve, release build of c331f7a, macOS)          agent B (agentnet serve, native x86_64 build of c331f7a)
   | REST 127.0.0.1:18650                                             | REST 127.0.0.1:18642
 colima VM (linux/arm64), docker, qemu for amd64                    docker bridge 172.28.66.0/24 (network "ants", created by hand, box-up.sh)
   node A  an-x-node-a  (nwaku v0.39.2 @sha256:cb4d14a2...)            node R  an-r1 172.28.66.10  relay+store, cluster 66 shard 0, discovery off,
   staticnode = /ip4/<TS_IP_B>/tcp/60000/p2p/<R>                         rln off, --dns-addrs-name-server=127.0.0.1, --nat=extip:<TS_IP_B>,
   libp2p port NOT published (nothing listens on the Mac)                tcp_retries2=6 (container sysctl), retention time:604800;capacity:100000
   |                                                                    published ports: <TS_IP_B>:60000->60000 (libp2p) and 127.0.0.1:18640->8645 (REST)
 Mac tailscale (utun, <TS_IP_A>)  <===== WireGuard, direct UDP =====>  node B  an-nb 172.28.66.22, REST 127.0.0.1:18642, static peer = /ip4/<TS_IP_B>/tcp/60000/p2p/<R>
   tailnet path: DIRECT over IPv6 (see tailscale-path-*.txt)          box tailscale (tailscale0, <TS_IP_B>)
                                                                      host firewall: iptables raw PREROUTING, tcp/60000 to <TS_IP_B>: ACCEPT from <TS_IP_A>,
                                                                      from <TS_IP_B> itself and from node B (172.28.66.22); DROP otherwise (box-fw.sh)
```

- The colima VM reaches tailnet addresses through the Mac's routing: a throw-away container in colima connected to `<TS_IP_B>:60000` directly
  (`nc` rc=0), so NO forwarder (tcp-forward.py or similar) was needed or used. Node A dials the tailnet address straight from the VM.
- R's libp2p port is bound by docker-proxy on `<TS_IP_B>:60000` only (`ss -ltnp`, `docker port an-r1`); REST is on the box's 127.0.0.1 only.
- Agents' peer allowlist = R only (`agentnet init --peer /ip4/<TS_IP_B>/tcp/60000/p2p/<R>`); node peer lists show exactly one peer, R.
- Node B shares R's host. B's tcp connection to R ended up on the docker bridge (R dialled B back at 172.28.66.22; B lists R as 172.28.66.10),
  not through the tailnet address; only A <-> R crosses hosts and the tailnet.
- Tailscale on the box rewrites the source of traffic it forwards from tailscale0 into the docker bridge (ts-postrouting MASQUERADE), so R sees
  A as 172.28.66.1 (the bridge gateway), NOT as the Mac's tailnet IP. The packets on tailscale0 do carry the Mac's tailnet IP (packet-capture.txt).
- Keys: disposable test nodekeys from spike/relay/.env (already public in the repo; never reuse).
