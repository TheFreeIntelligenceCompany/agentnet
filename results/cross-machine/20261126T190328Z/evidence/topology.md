# Topology (cross-machine run, 2026-11-26)

```
 Host 1: Mac (macOS arm64, home NAT, outbound only)           Host 2: instabox sandbox VM (Debian x86_64, native amd64 Docker)
 ------------------------------------------------           -----------------------------------------------------------
 agent A  (agentnet serve, release, macOS arm64)              agent B  (agentnet serve, native x86_64 Linux build of 5f004d8)
   | REST 127.0.0.1:18650                                       | REST 127.0.0.1:18642
 colima VM (linux/arm64) -- docker, qemu for amd64              docker network 172.28.66.0/24 (spike/relay compose, unmodified
   node A  an-x-node-a  (nwaku v0.39.2 @sha256:cb4d14a2...)       except one override: R's libp2p port also published on the box's
   staticnode = /ip4/192.168.5.2/tcp/61660/p2p/<R>                127.0.0.1:60000)
   libp2p port 60000 NOT published                              node R  an-r1 172.28.66.10  relay+store, cluster 66 shard 0, discovery off,
   |                                                              rln off, --dns-addrs-name-server=127.0.0.1, tcp_retries2=6
 192.168.5.2 = the Mac as seen from the VM (host.lima.internal)  node B  an-nb 172.28.66.22 static peer = R (172.28.66.10:60000)
   |                                                            sshd (the only listener on a non-loopback address, :22)
 Mac 127.0.0.1:61660  <== `instabox port-forward agentnet-xhost 61660:60000` (ssh -L, opened FROM the Mac, outbound) ==> box 127.0.0.1:60000 -> docker-proxy -> an-r1:60000
```

- Client-to-relay (A -> R) traffic is carried inside the authenticated SSH tunnel that `instabox port-forward` opens from the Mac to the
  sandbox. Nothing is published (`instabox port ls` = []). R has no listener except on the box's loopback.
- Agent B and node B share host 2 with R (they reach R over the box's docker network); only A <-> R crosses hosts.
- Node A reaches the tunnel via 192.168.5.2 (private-range literal IP, exactly one /p2p/ component), which satisfies private-mode validation. Agent A's allowlist = R's peer id only; agent B's likewise.
- R sees A's connection as coming from 172.28.66.1 (the box's docker bridge gateway), not from the Mac.
- Keys: disposable test nodekeys from spike/relay/.env (public in the repo; never reuse).
