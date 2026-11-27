# Topology (public-IP relay, audited mode, final tree, 2026-11-27)

```
 Mac (macOS 26.6.2 arm64, home NAT, outbound only)                  DigitalOcean droplet agentnet-pub-test (nyc1, s-2vcpu-4gb, Ubuntu 24.04.5, x86_64)
 agent A (agentnet serve, release build, audited public mode)        agent B (agentnet serve, native x86_64 build of 481eb15, audited public mode)
   | REST 127.0.0.1:18690                                              | REST 127.0.0.1:18642
 colima VM + qemu amd64: node A  an-do-node-a (nwaku v0.39.2)        docker bridge 172.28.66.0/24: node R an-r1 (relay+store, cluster 66 / shard 0,
   --nat=none, libp2p port NOT published                                discovery off, rln off, --dns-addrs-name-server=127.0.0.1, --nat=extip:<PUB_IP_R>,
   staticnode/storenode/... = /ip4/<PUB_IP_R>/tcp/60000/p2p/<R>          tcp_retries2=6, published <PUB_IP_R>:60000, REST 127.0.0.1:18640),
 home router NAT (<PUB_IP_A>) ===== raw tcp/60000 over the internet =====>  node B an-nb 172.28.66.22 (static peer R), node R2 an-r2 (foreign test node,
                                                                       libp2p tcp/60001 on <PUB_IP_R>, different disposable nodekey, same cluster/shard)
                                                                    DO cloud firewall agentnet-pub-test-fw: inbound tcp/22, 60000, 60001 ONLY from <PUB_IP_A>/32
```
- Agents created with `agentnet init --public-relay --node-url ... --peer /ip4/<PUB_IP_R>/tcp/60000/p2p/<R>`; no hand-edited config except removing `enforce_peer_allowlist` for the plain-mode control (check 6) and putting it back.
- R sees A at `/ip4/<PUB_IP_A>/tcp/<port>` (docker DNAT preserves the source); B reaches R via the docker bridge (172.28.66.1), only A crosses the internet.
- No tags (token has no tag scope): the firewall was attached by droplet id.
- Keys: all node keys freshly generated disposable keys (`openssl rand -hex 32`), not in the repo.
- The 4 harness scripts that hard-code `inbox-0a` use B's inbox content topic of this run (`identity show --json` field `inbox_topic`).
