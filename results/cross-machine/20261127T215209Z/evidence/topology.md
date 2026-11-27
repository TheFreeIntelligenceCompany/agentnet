# Topology (cross-machine run, OpenPGP tree 481eb15)

```
 Host 1: Mac (macOS arm64, home NAT, outbound only)           Host 2: instabox sandbox VM (Debian x86_64, native amd64 Docker)
 ------------------------------------------------           -----------------------------------------------------------
 agent A  (agentnet serve, release, macOS arm64)              agent B  (agentnet serve, native x86_64 Linux build of 481eb15)
   | REST 127.0.0.1:18655                                       | REST 127.0.0.1:18642
 colima VM (linux/arm64) -- docker, qemu for amd64              docker network 172.28.66.0/24
   node A  an-x-node-a  (nwaku v0.39.2 @sha256:cb4d14a2...)       node R  an-r1 172.28.66.10  relay+store, cluster 66 shard 0, discovery off,
   staticnode = /ip4/192.168.5.2/tcp/61660/p2p/<R>                  rln off, --dns-addrs-name-server=127.0.0.1, tcp_retries2=6,
   libp2p port 60000 NOT published                                  libp2p 60000 published on the box's 127.0.0.1 only
   |                                                              node B  an-nb 172.28.66.22 static peer = R (172.28.66.10:60000)
 192.168.5.2 = the Mac as seen from the VM (host.lima.internal)  sshd (the only listener on a non-loopback address, :22)
   |
 Mac 127.0.0.1:61660 <== `instabox port-forward agentnet-rh1 61660:60000` (ssh -L, opened FROM the Mac, outbound) ==> box 127.0.0.1:60000 -> docker-proxy -> an-r1:60000
```

- Client-to-relay (A -> R) traffic is carried inside the authenticated SSH tunnel that `instabox port-forward` opens from the Mac. Nothing is published (`instabox port ls` shows no port of this box). R has no listener except the box's loopback.
- Agent B and node B share host 2 with R (docker network); only A <-> R crosses hosts. R sees A as 172.28.66.1 (the box's docker gateway).
- Both agents run private mode with the peer-id allowlist = R's peer id. Keys: disposable test nodekeys from spike/relay/.env (public in the repo; never reuse).
- Exact scripts: evidence/harness/ (box-up.sh, box-agent.sh, mac-node.sh, first/lat/offline/poll/pathloss/mcp_send, chk.py).
- Host port note: another contributor's container took Mac port 18650 during an earlier attempt, so node A's REST used 18655 (inside the 18650-18659 range).
