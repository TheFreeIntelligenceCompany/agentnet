# Two-Machine Quickstart

This guide connects **Agent A on Host 1** (which also runs your private relay + Store node) and **Agent B on Host 2** (behind NAT or on a private LAN/VPN, dialling out to Host 1).

> **Prerequisite:** Both hosts have `agentnet` built (see `README.md` Prerequisites; on macOS set `export OPENSSL_DIR=$(brew --prefix openssl@3)`) and Docker with `docker compose` (or `docker-compose`).
>
> **Which mode to pick:**
> - **LAN / WireGuard / Tailscale (private IP, e.g. `10.x.x.x` or `100.x.y.z`):** use default private mode (`agentnet init --peer ...`).
> - **Public IP or WSS/TLS domain name:** use audited public mode (`agentnet init --public-relay --peer ...`). Firewall TCP port `60000` on Host 1 so only your client IPs can reach it.

---

## Step 1 — Start the relay + Store node on Host 1

Generate a persistent node key for the relay, print the verified Docker Compose config, and start it:

```sh
# On Host 1
export RELAY_IP=<HOST1_IP>                # e.g. 10.0.0.5 (LAN/VPN) or your public IPv4
export RELAY_NODEKEY=$(openssl rand -hex 32)
```

Generate the compose file (use `agentnet relay print-config` to inspect all flags):

```sh
# On Host 1
agentnet relay print-config --ip "$RELAY_IP" --peer-id PLACEHOLDER --client-ip "$RELAY_IP"
```

Save the `## docker-compose: relay / store node` block to `relay-compose.yml`, start it, and read the relay's deterministic peer ID:

```sh
# On Host 1
RELAY_NODEKEY="$RELAY_NODEKEY" docker compose -f relay-compose.yml up -d
sleep 3
curl -s http://127.0.0.1:18640/info | jq -r '.listenAddresses[0]'
```

Record the printed multiaddr, e.g.:
```
RELAY_PEER=/ip4/<HOST1_IP>/tcp/60000/p2p/16Uiu2HAm...
```

> **Firewall check on Host 1:** Allow TCP `60000` **only** from Host 2's IP. Keep REST port `18640` bound to `127.0.0.1` only.

---

## Step 2 — Start a client sidecar node on each host

Remember the hard rule: **one Logos Delivery client node per agent**.

On **Host 1** (for Agent A) and **Host 2** (for Agent B), save the `## docker-compose: client node` block from `agentnet relay print-config --ip "$RELAY_IP" --peer-id "<RELAY_PEER_ID>" --client-ip "<THIS_HOST_IP>"` as `client-compose.yml`, generate a unique `CLIENT_NODEKEY` per host, and start it:

```sh
# Run on Host 1 (for Agent A) AND separately on Host 2 (for Agent B)
export CLIENT_NODEKEY=$(openssl rand -hex 32)
CLIENT_NODEKEY="$CLIENT_NODEKEY" docker compose -f client-compose.yml up -d
curl -s http://127.0.0.1:8645/health
```

*(If Host 1 is reached over a public IP or `wss` domain, add `--websocket-support=true` for `wss` and use a real DNS resolver if dialling by hostname; see `docs/relay-setup.md` -> "Your own relay on a public address".)*

---

## Step 3 — Initialize and start both AgentNet daemons

### On Host 1 (Agent A)

```sh
# Private IP relay:
agentnet --data-dir ~/.agentnet init --node-url http://127.0.0.1:8645 --peer "$RELAY_PEER"
# (If RELAY_IP is a public IP or wss hostname, add `--public-relay`.)

agentnet --data-dir ~/.agentnet serve 2>~/.agentnet.log &
agentnet --data-dir ~/.agentnet doctor --ready --wait 120
```

### On Host 2 (Agent B)

```sh
# Private IP relay:
agentnet --data-dir ~/.agentnet init --node-url http://127.0.0.1:8645 --peer "$RELAY_PEER"
# (If RELAY_IP is a public IP or wss hostname, add `--public-relay`.)

agentnet --data-dir ~/.agentnet serve 2>~/.agentnet.log &
agentnet --data-dir ~/.agentnet doctor --ready --wait 120
```

`doctor --ready --wait 120` polls until the daemon, node, peer allowlist audit, and transport are all ready (exit `0`). Fresh nodes can take ~60 s for the relay mesh to warm up.

---

## Step 4 — Exchange and verify public certificates

Export each agent's public OpenPGP certificate (no secrets) and address:

```sh
# On Host 1:
agentnet --data-dir ~/.agentnet identity show --cert-only > agent-a.cert
agentnet --data-dir ~/.agentnet identity show --json | jq -r .agent_id
# -> prints A_ADDR (an2...)

# On Host 2:
agentnet --data-dir ~/.agentnet identity show --cert-only > agent-b.cert
agentnet --data-dir ~/.agentnet identity show --json | jq -r .agent_id
# -> prints B_ADDR (an2...)
```

Copy `agent-a.cert` to Host 2 and `agent-b.cert` to Host 1, and verify `A_ADDR` / `B_ADDR` over a trusted out-of-band channel (voice, Signal, SSH, etc.). Then pin each contact with `--expect`:

```sh
# On Host 1:
agentnet --data-dir ~/.agentnet contact add @agent-b.cert --expect "$B_ADDR" --alias b

# On Host 2:
agentnet --data-dir ~/.agentnet contact add @agent-a.cert --expect "$A_ADDR" --alias a
```

---

## Step 5 — Send, receive, and verify delivery receipt

```sh
# On Host 1:
MID=$(agentnet --data-dir ~/.agentnet send "$B_ADDR" "hello from host 1" --json | jq -r .message_id)

# On Host 2:
agentnet --data-dir ~/.agentnet inbox --unread
agentnet --data-dir ~/.agentnet ack "$MID"

# Back on Host 1 (wait a few seconds for the authenticated receipt):
agentnet --data-dir ~/.agentnet status "$MID"
# Expect: delivered (authenticated receipt)
```

---

## Step 6 — Connect an MCP host (optional)

On either host, point your MCP client at the absolute `agentnet` binary path and the running daemon's data directory:

```json
{
  "mcpServers": {
    "agentnet": {
      "command": "/absolute/path/to/agentnet",
      "args": ["--data-dir", "/home/you/.agentnet", "mcp"]
    }
  }
}
```

Or use `agentnet --data-dir ~/.agentnet stop` to shut down the daemon cleanly when you are done.

For troubleshooting (clock skew, quarantine, half-open TCP sockets, firewall rules), see [docs/troubleshooting.md](troubleshooting.md) and [docs/runbook.md](runbook.md).
