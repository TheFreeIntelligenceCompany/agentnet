# spike/relay-tailscale: relay on a real tailnet address, single host (plus an UNTESTED second-host kit)

> **Scope, read first.** Part 1 (`run.sh`) was run on ONE macOS host that is a member of a real tailnet. It proves *configuration
> with a real tailnet address* and that the relay's libp2p port is bound to the tailnet address only. It does **not** prove
> cross-machine transport, Tailscale ACLs, DERP relays, NAT traversal or key expiry; all of those are **UNTESTED**. On one host the
> clients reach the relay through the host's own address, so **no packet crosses a WireGuard tunnel to another machine**. Part 2
> (`remote-client.sh`, `remote-check.sh`, the ACL snippet) is written but was **never executed: UNTESTED**.

Evidence: `results/tailscale/<UTC timestamp>/` (`SUMMARY.md`, `checks.jsonl`, `evidence/`). The tailnet IPv4 is written `<TS_IP>` and
device names `<host-a>`, `<host-b>`, ... everywhere in committed evidence; `run.sh` scrubs and verifies that at exit.

## Part 1: single-host run

```
cargo build --release --locked -p agentnet-cli -p agentnet-acceptance
spike/relay-tailscale/run.sh                 # about 1-2 min when the node image is cached; KEEP_UP=1 leaves the containers and the forwarder
```

Needs Tailscale up (CLI at `/Applications/Tailscale.app/Contents/MacOS/Tailscale`; only read-only `status` and `ip -4` are used), docker
(colima), docker-compose, jq, curl, python3, openssl, perl, lsof, nc. Touches only containers/networks/volumes named `an-ts*`; host ports
18671 (R REST), 18672 (A), 18673 (B), 61000 (see below); per-run disposable keys in `.run/` (gitignored, deleted on exit).

Topology: R (relay + store, cluster 66 shard 0, discovery off, RLN off, `--dns-addrs-name-server=127.0.0.1`, `--nat=extip:<TS_IP>`);
clients A and B whose only static peer is `/ip4/<TS_IP>/tcp/60000/p2p/<R id>`; two `agentnet serve` daemons on the host with the peer
allowlist set to R (`agentnet init --peer <that multiaddr>`); REST of every node on host 127.0.0.1 only.

### Binding findings (measured)

* `ports: ["<TS_IP>:60000:60000"]` **fails** under colima: `failed to bind host port <TS_IP>:60999/tcp: cannot assign requested address`
  (`evidence/bind-probe-tailnet-ip.txt`). Docker runs inside the colima Linux VM, whose addresses (`evidence/colima-vm-addresses.txt`)
  do not include the host's tailnet address; the macOS host's `utun` interface is not visible to it.
* No colima restart or reconfiguration was done (other work shares the VM). Workaround used: R publishes tcp/60000 on the **VM
  loopback** (`127.0.0.1:61000:60000`), colima's port forwarder exposes that on the host's `127.0.0.1:61000`, and `tcp-forward.py`
  (a 40-line asyncio forwarder, refuses wildcard and loopback listen addresses) listens **only on `<TS_IP>:60000`** and forwards to it.
* Result (`evidence/reachability-matrix.txt`, `evidence/lsof-60000.txt`): tcp/60000 answers on `<TS_IP>` only; no answer on
  `127.0.0.1:60000` nor on the host's LAN IPv4; the only listener on 60000 is the forwarder bound to `<TS_IP>:60000`.
* Residual exposure of this workaround: `127.0.0.1:61000` (loopback only, colima's ssh forwarder) also reaches R's libp2p port; the
  LAN address does not answer on 61000 or on R's REST. A host-level (non-VM) deployment, or a Linux host with docker publishing on the
  tailnet IP directly (or `network_mode: host` and `--listen-address=<TS_IP>`), has no such residue.
* Same-host path: the client containers (in the VM) reach `<TS_IP>:60000` through colima's NAT and the host's own address. lsof shows
  both ends of the connection as `<TS_IP>` (`evidence/lsof-established-60000.txt`). `route -n get <TS_IP>` reports interface `utun4`
  with flag LOCAL; the interface byte counters around the message exchange were inside the noise of unrelated tailnet traffic
  (`evidence/tailnet-iface-counters.txt`), so they neither prove nor refute that the loop goes through the Tailscale TUN device. Either way it never leaves the machine.

## Part 2: second-host kit (UNTESTED, never run)

Goal: a second tailnet machine becomes agent B against R on host A's tailnet address, so a message really crosses the tailnet.

On host A (the relay host), start the topology and keep it: `KEEP_UP=1 KEEP_RUN=1 spike/relay-tailscale/run.sh` (agent daemons stop at
exit; start your own `agentnet serve` for A afterwards, or use a separate agent dir), then print R's multiaddr:
`echo "/ip4/$(tailscale ip -4)/tcp/60000/p2p/$(curl -s http://127.0.0.1:18671/info | jq -r '.listenAddresses[0]|split("/p2p/")[1]')"`.

On the second machine (needs docker, the `agentnet` binary, curl, jq, nc):

```
remote-client.sh probe-relay <relay tailnet ip>                       # expect PASS
remote-client.sh up /ip4/<relay tailnet ip>/tcp/60000/p2p/<relay id>  # node + init (allowlist = R) + serve; prints ADDRESS, writes contact.record
remote-client.sh add-contact <A's contact record file> <A's address>
remote-client.sh send <A's address> "hello from B"
remote-client.sh probe-lan <host A's LAN IPv4>                        # expect PASS = does NOT answer
remote-client.sh down
```

On host A: `remote-check.sh --a-dir <A's agent dir> --b-address <B> --b-record <B's contact.record> --relay-tailnet-ip <ip> --lan-ip <host A LAN ip>`
(interactive; contact import, A->B with receipt, B->A reply, B offline recovery, LAN probe from the second machine; ACL and DERP
checks are emitted as UNTESTED lines on purpose). Copy `contact.record` and the address between the machines over any channel; they
are public contact data (verify the address out of band, `--expect` enforces the binding).

### Suggested Tailscale ACL (UNTESTED, not applied by any script)

```json
{
  "tagOwners": {"tag:agentnet-relay": ["autogroup:admin"], "tag:agentnet-client": ["autogroup:admin"]},
  "grants": [
    {"src": ["tag:agentnet-client"], "dst": ["tag:agentnet-relay"], "ip": ["tcp:60000"]}
  ]
}
```

Grants are additive: with no other rule admitting traffic to the relay tag this admits only tagged clients to tcp/60000; REST (8645)
stays on loopback/VM-local and is not listed. Check, once applied: `nc -z <relay ip> 60000` from an untagged tailnet node must fail and
from a tagged client succeed. Mind that on a host that also carries other tailnet policy (for example a catch-all `*:*` rule) this snippet
restricts nothing.

## Files

`docker-compose.yml`, `run.sh` (needs `../netsim-lib.sh`), `tcp-forward.py`, `remote-client.sh` (UNTESTED), `remote-check.sh` (UNTESTED), `.gitignore`.
