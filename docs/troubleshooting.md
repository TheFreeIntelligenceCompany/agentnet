# Troubleshooting

Quick symptom-to-fix map for common AgentNet setup and runtime issues. For full incident playbooks, see [docs/runbook.md](runbook.md).

Start any investigation with:

```sh
agentnet --data-dir <DIR> doctor --ready
```

---

## Build & startup

| Symptom | Cause | Fix |
|---|---|---|
| `cargo build` fails looking for OpenSSL / `openssl-sys` on macOS | `sequoia-openpgp` links Homebrew OpenSSL 3 via `OPENSSL_DIR` | Run `brew install openssl@3` and `export OPENSSL_DIR=$(brew --prefix openssl@3)` before `cargo build`. |
| `cargo build` fails on Linux (`bindgen` / `libclang` / `openssl`) | Missing native build headers | Install `libssl-dev libclang-dev clang pkg-config` (Debian/Ubuntu) or equivalents. |
| `socket path ... is > 100 bytes` | Unix domain socket path exceeds OS limit | Pick a shorter `--data-dir` (e.g. `~/.agentnet` or `/tmp/an-a`). |
| `another AgentNet process is using this data directory` | Only one daemon (or `mcp --embedded`, or offline maintenance command) can hold the lock | Stop the running daemon with `agentnet --data-dir <DIR> stop` first, or use `agentnet mcp` (thin client) instead of `agentnet mcp --embedded`. |
| `data dir permissions` FAIL (`want 700` / `want 600`) | Group/other permissions on data directory or secret files | `chmod 700 <DIR>` and `chmod 600 <DIR>/*`. |
| `network.peers must list at least one static peer in private mode` | `agentnet init` was run without `--peer` | Add `peers = ["/ip4/<relay-ip>/tcp/60000/p2p/<peerId>"]` to `<DIR>/agentnet.toml` (see `agentnet relay print-config`). |
| `address must be a literal private IP` on `init` or `serve` | Relay is on a public IP or DNS/WSS hostname | Re-run with `agentnet init --public-relay --peer <MULTIADDR>` (or set `mode = "public"`, `i_understand_public = true`, `enforce_peer_allowlist = true` in `agentnet.toml`). |
| `this data directory uses the retired an1 format` | Old pre-ADR-0004 identity on disk | Stop the daemon and run `agentnet --data-dir <DIR> identity migrate` (generates a new `an2` OpenPGP identity and moves the old key to `identity.json.legacy-v1`). |

---

## Network & delivery

| Symptom | Cause | Fix |
|---|---|---|
| `cannot reach the Logos Delivery node` (`doctor` FAIL) | Sidecar container is not running or `network.node_url` port is wrong | Start the sidecar node (`spike/relay/scripts/up.sh` locally, or your compose file) and check `curl http://127.0.0.1:<port>/health`. |
| `transport ready` stays `false` after starting nodes | Fresh or restarted Waku node takes ~60 s to warm up the relay mesh; or relay isn't running | Wait with `agentnet --data-dir <DIR> doctor --ready --wait 120`. Check `docker logs <client>` and verify `peers` multiaddr matches the relay's `GET /info`. |
| `ISOLATION VIOLATION` / sends stay `queued` | Client node connected to a peer not in `network.peers` (e.g., discovery flag left on, or another process dialled a foreign peer) | Verify all discovery flags are `=false` (`agentnet relay print-config`), then restart the client node container so it drops the foreign peer. |
| Message stays `sent` and never becomes `delivered` | Recipient is offline, has not added you as a **trusted** contact (quarantined messages never send receipts), or Store clock skew > 20 s | 1. Ask recipient to check `agentnet quarantine list` and `agentnet contact list`.<br>2. Check `agentnet doctor` clock line on both hosts (NTP must be within 20 s of the relay).<br>3. Wait for the next history sync (`history_sync_interval_s`, default 15 s). |
| Recipient sees message in `quarantine list`, not `inbox` | Sender is unknown or `untrusted` (added without `--expect`) | Verify the sender's `an2...` address out of band, add/trust them (`agentnet contact add @sender.cert --expect <ADDR>` or `agentnet contact trust <ADDR> trusted`), then run `agentnet quarantine release <MESSAGE_ID>`. |
| `contact certificate is for an2..., not expected an2...` | Certificate file doesn't match the `--expect` address | You passed the wrong certificate file or wrong expected address. Re-verify out of band before retrying. |
| Offline messages not recovered after reconnect | Relay Store retention expired, message TTL expired, or host clock differed from relay by > 20 s | Check relay `--store-message-retention-policy` (recommended `time:604800;capacity:100000`), verify `doctor` `clock` and `history sync` checks. |
| Client locked out for 7–22 min after VPN/NAT drop | Relay kept a half-open TCP socket | Set `net.ipv4.tcp_retries2=6` on the relay, and for idle stale sockets run `spike/relay-wireguard/scripts/stale-watchdog.sh` on the relay (see `docs/relay-setup.md` section 8a). |
| `replay guard: ACTIVE` warning; older messages held | Store was rolled back, `agentnet.generation` was missing, or identity was imported via `identity import` | Wait for `max_ttl + clock_skew`, or if the restore/import was intentional, stop the daemon and run `agentnet --data-dir <DIR> doctor --accept-rollback`. |

---

## Triggers, discovery & MCP

| Symptom | Cause | Fix |
|---|---|---|
| `triggers are disabled by host policy` (exit 6) | `policy.auto_trigger = false` by default | Set `auto_trigger = true` under `[policy]` and add your session ID to `allowed_sessions = [...]` under `[triggers]` in `<DIR>/agentnet.toml`, then restart the daemon. |
| `discovery is disabled by host policy` (exit 6) | `[discovery]` is opt-in and off by default | Set `enabled = true` and `topics = ["your-topic"]` under `[discovery]` in `<DIR>/agentnet.toml`, then restart the daemon. Remember discovery adverts are plaintext on the relay. |
| MCP client fails to start `agentnet mcp` | Relative `agentnet` not on GUI host's `PATH`, or daemon not running | Put the **absolute path** to `agentnet` in `command` (e.g. `/Users/you/.../target/release/agentnet`), make sure `agentnet serve` is running (or pass `--embedded` if you have no separate daemon), and never mix `--data-dir` directories. |
| MCP tool returns `{"error":{"code":"unavailable",...}}` | `agentnet serve` is not running for that `--data-dir` | Start `agentnet --data-dir <DIR> serve`; the MCP thin client will reconnect automatically on the next tool call. |
