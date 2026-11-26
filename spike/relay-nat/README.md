# spike/relay-nat: outbound-only clients behind simulated NAT (SIMULATION)

**What this is.** Two docker "LAN" bridges, each with a NAT gateway container (iptables MASQUERADE, stateful forwarding, the clients' default
route) and one client Logos Delivery node behind it, plus a "public" bridge with the relay. Clients publish no libp2p port and dial only the
relay. Two `agentnet serve` daemons on the host talk to the clients' node REST ports.

**What this is NOT.** Not real NAT or CGNAT: Linux conntrack/MASQUERADE only; the endpoint-independent mapping, hairpinning, UPnP and port-block
allocation of real routers are not modelled. No hole punching is needed or tested (clients only dial R). Not separate physical hosts. Do not
cite it as a cross-machine result. Analysis and results: `docs/network-simulations.md`.

## Topology

```
 public 172.30.80.0/24 (an-nat-pub):  R .10   gw-a .21   gw-b .22
 LAN-A 192.168.101.0/24 (an-nat-lana): gw-a .2 (default route of the clients)   client A node .10
 LAN-B 192.168.102.0/24 (an-nat-lanb): gw-b .2                                  client B node .10
 R: --nat=extip:172.30.80.10.   clients: --nat=none (announce nothing), --staticnode=/ip4/172.30.80.10/tcp/60000/p2p/<R id>
 host: agentnet serve (A) -> 127.0.0.1:18661, (B) -> 127.0.0.1:18662, R's REST 127.0.0.1:18660 (diagnostics)
```

Each client is a sidecar container (default route replaced to point at its gateway, REST published to the docker host's 127.0.0.1) with the node
sharing its namespace. The published REST ports exist only so that the daemons on the host can reach the nodes; in a real deployment the agent is
co-located with its node inside the LAN. REST between the host and the nodes is cleartext on the LAN bridges by design of this simulation.

## Run

```
cargo build --release --locked -p agentnet-cli -p agentnet-acceptance        # once, from the repo root
spike/relay-nat/run.sh                      # about 60+ min: results/network-sim/nat/<UTC timestamp>/
STEPS="1 2" spike/relay-nat/run.sh          # matrix + messaging only (about 3 min)
IDLE_S=600 CT_IDLE=120 MAPLOSS_TIMEOUT=1500 N_MSGS=20 BIN_DIR=... KEEP_UP=1 KEEP_RUN=1   # knobs
```

Steps: 1 topology + reachability matrix + what R sees, 2 messaging + offline recovery, 3 NAT mapping loss (flush with silent drop, flush with RST,
gateway restart), 4 idle keepalive with `nf_conntrack_tcp_timeout_established=120` (set at run time by a privileged helper joining the gateway
namespace, restored afterwards). Idempotent; removes its containers, networks, volume and keys on exit. Touches only `an-nat*`.
Node keys are generated per run into `.run/` (gitignored) and deleted on exit.
