# Operations runbook

For someone running AgentNet. This file links to the detailed documents instead of repeating them. Every command below
exists in `docs/cli-help.txt`; where the documentation has no command for a task, the text says so.

## 1. Scope and status

AgentNet is an MVP validated on **one macOS arm64 host** (containers in one colima VM, node image under qemu). It is **not
audited, not production-secure and not forward-secret**; an **independent cryptographic review is required before any
production use involving sensitive information**. Real Tailscale, real NAT and operation across separate hosts are
**UNTESTED**: only single-host WireGuard-overlay and NAT-gateway simulations exist (`docs/network-simulations.md`). Public
mode is UNTESTED against any public network. Third-party MCP hosts are UNTESTED. This runbook itself is a write-up of the
documented behaviour; none of the playbooks was drilled as a whole.

Pointers: `README.md` (limitations), `docs/threat-model.md`, `docs/acceptance.md` (what was run), `docs/relay-setup.md`.

## 2. Components and what runs where

| Component | Where | Notes |
|---|---|---|
| Service node (relay + Store) | One host all clients can reach | A Logos Delivery node (`wakuorg/nwaku` v0.39.2, linux/amd64 only). Holds the Store retention window. tcp/60000 must be firewalled to known clients. |
| Client node (sidecar) | Next to each agent, **one per agent** | Same image. Its REST API (no authentication) is for `agentnet serve` only, on loopback. Sharing a node between agents is unsupported. |
| `agentnet serve` (daemon) | Next to its client node | Owns the identity, SQLite inbox/outbox, delivery engine, control socket, optional webhook and loopback HTTP MCP. One data directory = one identity = at most one process. |
| `agentnet mcp` | Started by the MCP host | Thin stdio client of the daemon. If the daemon is down, every tool returns `unavailable`. `--embedded` runs the daemon inside it instead. |

```
agentnet serve --REST (loopback)--> client node --libp2p--> service node (relay+Store)
```

Detail: `docs/relay-setup.md` section 1, `README.md` (Architecture).

## 3. First-time setup checklist

Details and the verified flag set: `docs/relay-setup.md`. Print the flags and compose snippets for your addresses:

```sh
agentnet relay print-config --ip <relay ip> --peer-id <relay peer id> --client-ip <client ip>
```

1. Service node: start it with the verified flags (`--dns-addrs-name-server=127.0.0.1`, cluster id not 1, 2, 3 or 16, discovery off,
   REST on loopback, `--rest-relay-cache-capacity=1000`). Generate its key with `openssl rand -hex 32`; read its peer id from the
   node's `GET /info` (`docs/relay-setup.md` section 4).
2. Firewall: allow tcp/60000 on the service node only from known client addresses. Publish REST ports only on host loopback.
3. NTP on every host (the Store silently refuses messages more than 20 s away from its own clock).
4. Client node, one per agent, with `--staticnode`/`--storenode` pointing at the service node.
5. Create the agent. Keep `--data-dir` short (the socket path must fit about 100 bytes):

   ```sh
   agentnet --data-dir <dir> init --node-url http://127.0.0.1:<client REST port> --peer /ip4/<service ip>/tcp/60000/p2p/<peer id>
   ```

   `init` prints the address and the signed contact record. `--peer` is required before `serve`; the allowlist is derived from it.
6. Start the daemon: `agentnet --data-dir <dir> serve` (foreground; use your own supervisor to keep it running, none ships with the repo; gate its health check on `agentnet --data-dir <dir> doctor --ready`).
7. Exchange contact records over a channel you trust, and bind each record to the address you obtained out of band:

   ```sh
   agentnet --data-dir <dir> identity show --json
   agentnet --data-dir <dir> contact add @<record file> --expect <address> --alias <name>
   agentnet --data-dir <dir> contact list
   ```

8. Verify:

   ```sh
   agentnet --data-dir <dir> doctor
   agentnet --data-dir <dir> network status --verbose
   ```

9. Send a test message and wait for `delivered` (`agentnet send`, then `agentnet status <message id>`).
10. Back up the identity (section 7).

The same sequence in one transcript: `README.md` Quickstart, `results/audit/readme-quickstart-transcript.log` (single host).

## 4. Routine checks

Add `--data-dir <dir>` (or set `AGENTNET_HOME`) to each command; `--json` gives machine-readable output.

| Check | Command | Healthy |
|---|---|---|
| Everything | `agentnet doctor` | Exit 0 and `0 failing`. Lines `[ok  ]` for data dir permissions, config, identity, replay guard, daemon socket, node reachable, clock, isolation, `peers == allowlist`, history sync, transport ready, local inbox database. |
| Ready to message | `agentnet doctor --ready` | Exit 0. Use this one in supervisors, scripts and CI; exit 7 and a `NOT READY` list on stderr otherwise. |
| Network | `agentnet network status --verbose` | `mode` private, `ready` true, no `isolation_violation`, `connected_peers` 1 and the peer id equals your service node. Also shows queue counters (`outbox_queued`, `outbox_sent_unacked`, `inbox_unread`, `inbox_quarantined`, `events_unacked`, `active_triggers`) and webhook counters (`delivered`, `retries`, `parked`, `last_error`). |
| Outbox | `agentnet outbox --limit 20` | Messages end in `delivered`. Rows stuck in `queued` or `sent` need section 6.2. |
| One message | `agentnet status <message id>` | `queued`, `sent`, `delivered`, `failed` or `expired`. Only `delivered` (an authenticated receipt) means received. |
| Inbox | `agentnet inbox --unread` | Messages appear oldest first; `agentnet ack <id>` marks one processed locally and sends nothing. |
| Events | `agentnet events tail` (Ctrl-C to stop) | `message.received` / `trigger.matched` events, references only. Delivery is at-least-once: de-duplicate on `event_id`. |
| Quarantine | `agentnet quarantine list` | Empty, or only senders you expect. |

Notes:

* `doctor` always prints one `[warn] single instance` line (the same identity in two data directories cannot be detected). It is expected
  and counts as a warning, not a failure (`results/network-sim/wireguard/20261126T034919Z/evidence/doctor-a.txt`).
* Exit 0 means no checks failed; warnings and skipped checks can still mean messaging is unavailable. For readiness use `agentnet doctor --ready`: it prints the
  same report, and additionally exits 7 (with the reasons on stderr, one line per condition and what to do next) when the daemon socket is unavailable, the node
  is unreachable, the transport is not ready, the isolation audit fails or a required check was skipped or not run (`daemon socket`, `node reachable`,
  `isolation`, `transport ready`, `local inbox database`). Warnings such as `single instance` and `history sync` do not affect it; `--json` output is unchanged.
* `doctor` exit codes: 0 no failing check (with `--ready`: and ready), 7 at least one failing check (with `--ready`: or not ready). Other exit codes (3 daemon or node unavailable, 4 invalid configuration,
  6 refused by policy) are listed in `docs/cli-help.txt`.
* Logs go to stderr; `RUST_LOG` sets the level (default `warn`). There is no documented log file or metrics endpoint; the socket method
  `metrics` exists (`docs/host-integration.md` section 1.2) but has no CLI command.
* Healthy latency on the single-host test topology was sub-second to a few seconds for a warm path (`docs/acceptance.md`); do not read
  that as a service level for real networks.

## 5. Start, stop, restart, upgrade

### Daemon

* Start: `agentnet --data-dir <dir> serve`. It takes the exclusive data-directory lock. A second `serve` (or `identity export|import|rotate-kem|revoke`,
  or `doctor --accept-rollback`) on the same directory fails with "another AgentNet process is using this data directory" and exit 1.
  A stale `agentnet.sock` is replaced while the lock is held.
* Stop: Ctrl-C or SIGTERM; it shuts down cleanly (SIGTERM to exit took 11 to 252 ms in the acceptance runs, `docs/acceptance.md`).
  There is no CLI `stop` command. The control socket has a `shutdown` method for hosts (`docs/host-integration.md`).
* While the daemon is down nothing is polled. Queued messages stay in the outbox; inbound messages stay in the relay Store until the retention
  window ends. On restart the daemon catches up from Store and retries the outbox.
* The daemon refuses to start on any configuration error or if the data directory is readable by group or others.

### Sidecar node

* Restart your container (for example `docker restart <client node>`, as `docs/relay-setup.md` section 4a does; use your own tooling).
* After the node is recreated, expect **about 62 s without live relay** between client nodes (3 of 3 trials, `docs/relay-setup.md` section 3a).
  A message sent in that window is accepted by the node but reaches the recipient through the sender's retries or the recipient's next
  Store sync (`delivery.history_sync_interval_s`, default 15 s). Delayed, not lost, inside the retention and TTL windows.
* Subscriptions live in the node's memory and are lost when the node restarts (`docs/spike/notes-daemon-rest.md`); whether and when the daemon re-registers them
  after a node restart was not checked for this runbook, so confirm with a test message. Never unsubscribe a content topic.
* Do not restart the node while time-critical traffic is flowing.

### Service node (relay)

* Restart it only deliberately. After a relay restart the client nodes reconnect through the adapter's redial (11.4 s in one measurement),
  but live relay delivery stayed broken for about 9 minutes in that observation and **can take minutes** (`docs/relay-setup.md` section 5).
  Recovery depends on sender retries and Store catch-up. Store data survives only if `/data` is a volume.
* Start order: service node, client node, then daemon.

### Upgrade

There is no documented upgrade or migration procedure and no tested path between versions: **UNTESTED**. The wire protocol is "not yet
frozen" (`docs/protocol.md`). A cautious sequence, which is an inference and not a tested procedure: back up the data directory (section 7),
stop the daemon, replace the binary, start the daemon, then run `agentnet doctor` and the other routine checks. Newer node releases than v0.39.2 are untested with the adapter.

## 6. Incident playbooks

### 6.1 Network not ready / peer allowlist violation (fail closed)

* **Symptom.** `network status` shows `ready` false and an `isolation_violation` such as "node is connected to N peer(s) not in the allowlist";
  `doctor` shows `[FAIL] isolation` and `[FAIL] peers == allowlist`; sends stay `queued`. Or `serve` refuses to start with a config error.
* **Likely cause.** The node is connected to, or remembers, a peer that is not in `network.peers` (for example the node was started without
  the verified flags, discovery is on, a second agent shares the node, or a wrong peer id was dialled earlier). Or the configuration is invalid
  (public IP or hostname in `peers`, preset cluster id, empty `peers`).
* **Check.** `agentnet network status --verbose` (peer ids), `agentnet doctor`, `agentnet relay print-config` to compare flags. Compare the
  listed peer ids with the `peers` in `agentnet.toml` (`docs/configuration.md`).
* **Action.** Do not loosen the allowlist. Fix the node: restart it with the verified flag set (peers are not persisted with
  `--peer-persistence=false`, so a restart clears stale entries; `docs/relay-setup.md` section 4a). Make sure only one daemon uses the node.
  For a config error, correct `agentnet.toml`; the daemon validates it at start. Reference run: `results/acceptance/20261126T014245Z/logs/step5-isolation.log`.
  Messages queue locally until the node is ready.

### 6.2 Messages stuck `queued` or `sent` without receipt

* **Symptom.** `agentnet status <id>` stays `queued` or `sent`; `outbox` grows.
* **Likely cause.** `queued`: the node or relay is not reachable (`ready` false), or the contact is unknown. `sent`: the frame was published but
  the recipient has not acknowledged: recipient daemon down, recipient inside the ~62 s cold mesh window, relay Store retention or the 20 s clock-skew
  rule prevents recovery, or the recipient quarantines or blocks you.
* **Check.** `agentnet network status` (ready, `outbox_queued`, `outbox_sent_unacked`); `agentnet doctor` (clock, node reachable); ask the
  recipient to run `agentnet quarantine list`, `agentnet contact list` and `doctor`.
* **Action.** Wait: the sender retries with backoff up to `max_attempts` 20, and `delivered` can take up to a minute or more after a node or relay
  restart. Fix `ready` first (6.1, 6.3, 6.4). Fix clocks (NTP). If the message reached its TTL it becomes `expired`/`failed`; send again. `send --idempotency-key <key>`
  makes a resend safe. Recovery is bounded by the minimum of the relay Store retention, the message TTL and `storage.retention_hours`
  (`docs/relay-setup.md` section 6).

### 6.3 Node lost the relay and is slow to reconnect

* **Symptom.** After a silent network failure (dropped tunnel, NAT mapping loss, firewall change) `network status` shows `ready` false with 0
  connected allowed peers, and messages stay `queued`.
* **Likely cause.** Known and not understood. In the single-host simulations the node noticed the dead path after about 48 s (health monitor log line
  `Too many consecutive ping failures, node likely disconnected. Killing all connections`), then reconnected anywhere from 42 s to over 16 minutes
  with the path restored; in one run it did not reconnect within 600 s. The root cause is under investigation (peer-manager backoff, SYN retransmission
  backoff, or the online monitor with `--dns-addrs-name-server=127.0.0.1`: `docs/network-simulations.md`, Findings 1, and E12 in `docs/spike/notes-daemon-rest.md`).
  A connection that dies by an RST is noticed in under a second but is just as slow to return.
* **Check.** First confirm the path itself works again (WireGuard/Tailscale handshake, firewall, NAT, relay up). Then watch `agentnet network status --verbose`
  for `connected_peers` and the peer id. The adapter already POSTs the static peer to the node every 10 s while no allowlisted peer is connected; that did not
  reliably shorten recovery.
* **Action.** Wait; messages are not lost, they are delivered from the sender's queue and Store within TTL (every message was delivered once in the
  simulations). The workaround to offer is restarting the client's sidecar node (`docker restart <client node>` or your equivalent) and expecting
  about 62 s before live relay works again. **The effect of that restart on this specific failure is UNTESTED.** Real Tailscale and real NAT behaviour
  are UNTESTED.

### 6.4 Relay restarted or relay Store unavailable

* **Symptom.** `ready` false while the relay is down; after it returns, delivery is late; offline messages do not appear.
* **Likely cause.** Relay down or restarting; client nodes reconnect, then live relay can stay broken for minutes (about 9 minutes observed once; in later
  acceptance runs the clients were usable in seconds, cause unknown). Store holds only what the retention window kept and what was published with a valid
  timestamp.
* **Check.** `agentnet network status`; `agentnet doctor` (`node reachable`, `history sync`); the relay container and its `/health`. Check that Store
  retention and the data volume are as intended (`docs/relay-setup.md` section 6).
  Doctor's `local inbox database` line checks the local SQLite inbox, not relay Store retrieval; a green line there says nothing about the Store. The
  Store is probed through the `history sync` line: it shows when the last history pass finished without a Store failure (the same time as
  `last history sync` in `agentnet network status`). The line is `warn` when no pass has completed since the daemon started, when the last one is older than
  four sync intervals (at least 60 s), or while recovery is pending, which means the Store has not answered recently. It cannot show whether the Store
  still holds a particular message: inspect the service node's Store separately (`docs/relay-setup.md`).
* **Action.** Restore the relay (start order: service node first). Wait for the clients to redial; do not restart the daemons unnecessarily. Messages in
  the senders' outboxes keep retrying; messages the relay retained are recovered by Store catch-up (up to `history_sync_interval_s`). With the Store unavailable,
  recovery comes from the sender's retry. If the Store lost its data (retention expiry, no volume), only senders still retrying can deliver; with the
  verified spike flags the relay keeps only 1 hour (`README.md`, Limitations). There is no automatic Store failover to a second service node
  (`docs/relay-setup.md` section 9). No command exists to force a Store sync; the daemon does it on its own.

### 6.5 Duplicate or replayed messages, quarantined senders

* **Symptom.** The same text twice in the inbox, repeated events, or messages from an unknown address that never reach the inbox.
* **Likely cause.** Duplicates: the engine de-duplicates on `(sender, message_id)`, so a visible duplicate is usually a sender that sent twice (use
  `--idempotency-key`) or an event consumer that does not de-duplicate (events are at-least-once; use `event_id`). Replay after a restored database or an
  identity import: the replay guard holds older messages (`doctor` reports it). Quarantine: `policy.unknown_senders = "quarantine"` is the default.
* **Check.** `agentnet quarantine list` (one page; continue with `--cursor`); `agentnet contact list`; `agentnet doctor` (replay guard line); `agentnet inbox --include-quarantined`.
* **Action.** Verify the sender's address out of band, then add them (`contact add ... --expect <address>`) or `contact trust <address> trusted`, and
  `agentnet quarantine release <message id>` (the sender must be trusted by then). Block abusers with `agentnet contact trust <address> blocked`.
  After a deliberate restore, run `agentnet doctor --accept-rollback` with the daemon stopped only if you accept that acknowledged messages from before
  the rollback cannot be recovered and frames replayed from before it are accepted again within their TTL. Quarantine is capped (`storage.max_quarantined`,
  default 1000; beyond it messages are dropped). Hostile flood load is untested.

### 6.6 Webhook delivery failures

* **Symptom.** The harness is not woken; `network status` shows webhook `parked` greater than 0, rising `retries`, or a `last_error`.
* **Likely cause.** The receiver is down, answers non-2xx (redirects are never followed), rejects the signature or the timestamp (+-300 s), the URL is not
  loopback/private and `allow_remote` is false, or the secret file is missing, too short (under 32 bytes) or not mode 0600.
* **Check.** `agentnet network status` (webhook counters), the daemon's stderr, the receiver's logs, `[webhook]` in `agentnet.toml` (`docs/configuration.md`).
* **Action.** Fix the receiver. After `max_attempts` (default 5) an event is parked and not retried automatically. Recover by replaying from an earlier cursor:
  `agentnet events tail --since <cursor>` (or `--all`), de-duplicating on `event_id`. Receiver duties and the signature scheme: `docs/host-integration.md` section 2.
  Events are recoverable only until `storage.event_max_age_hours` (default 720) for unacknowledged and `storage.event_retention_hours` (default 168) for acknowledged ones.

### 6.7 Suspected key compromise

Read the limits first. There is **no forward secrecy and no post-compromise security**: whoever obtained a KEM secret key can read everything
already sealed to it that they recorded. Rotation and revocation protect the future only. Revocation is **best effort**: there is no directory and no global
revocation list, and it reaches only contacts that are reachable within the TTL and retry limits or that receive the document out of band
(`docs/protocol.md` section 9, `docs/threat-model.md` T2). Secrets are in a mode-0600 plaintext file, so a compromised host loses everything.

* **Likely compromise of the agreement (KEM) key only.** Stop the daemon, then:

  ```sh
  agentnet --data-dir <dir> identity rotate-kem
  agentnet --data-dir <dir> identity rotate-kem --revoke-previous
  ```

  Use one of the two. The first keeps the old key decrypting until `--keep-hours` (default `storage.retention_hours`) so in-flight messages still open.
  `--revoke-previous` destroys every earlier KEM key at once: messages already sealed to them are lost unless their senders re-seal after learning the new
  record. At the next `serve` the new record goes to every Trusted contact as a `contact.update`. A contact that was offline or whose retries ran out must be
  given the record out of band (`agentnet identity show --json`, then their `contact add`).
* **Likely compromise of the signing key (the identity).** Stop the daemon, then:

  ```sh
  agentnet --data-dir <dir> identity revoke --reason "<text, 1-256 bytes>"
  agentnet --data-dir <dir> identity show-revocation
  ```

  This is irreversible for the address. The daemon then sends nothing except the tombstone, delivered to Trusted contacts at the next start. Hand the
  `show-revocation` document to contacts out of band; they import it with `agentnet contact revoke @<file>`. Create a new identity with `agentnet init` in a new
  data directory and exchange records again. Until a peer learns of the tombstone, a thief of the signing key can impersonate you, and a thief can also issue
  a tombstone for your address (denial of service).
* **A contact's key is compromised.** `agentnet contact trust <address> blocked`, and import their tombstone if you have one.
* Also rotate whatever else was exposed: `control.token`, `mcp-http.token` and the webhook secret file (no command regenerates them; the documentation does not
  describe a rotation procedure for these, so treat that step as manual and untested).

### 6.8 Lost data directory, moving an identity, concurrent identity

* **Lost data dir with an export.** Restore into a directory that has no identity:

  ```sh
  agentnet --data-dir <new dir> identity import --in <export file> --node-url http://127.0.0.1:<client REST port> --peer <relay multiaddr>
  ```

  The export is passphrase-encrypted (age); `--passphrase-file <file>` (mode 0600) avoids the prompt. Contacts, inbox and outbox are **not** in the export.
  Re-add contacts. By default the import starts the **replay guard**: older messages are held until `max_ttl + clock_skew` passes, or you run
  `agentnet doctor --accept-rollback` with the daemon stopped (with the effects stated in `docs/cli-help.txt`). `--no-replay-guard` skips this and lets frames
  captured before the import be accepted again within their TTL.
* **Lost data dir without an export.** The identity cannot be recovered: there is no documented recovery path. Create a new identity and tell contacts.
* **Moving with history.** Stop the old daemon first, copy `agentnet.db` and `agentnet.generation` together (and `identity.json`, `agentnet.toml`), then start the new one
  (`docs/configuration.md`, data directory layout).
* **Concurrent-identity hazard.** The same identity running in two data directories is **not detected**: both would receive, persist and acknowledge every message
  independently and may both fire triggers, splitting state. The data-dir lock covers one directory only. After moving, make sure the old daemon is stopped and the
  old directory is never started again. `doctor` always warns about this.

### 6.9 An unknown peer appears on the relay

* **Symptom.** The service node lists a peer you do not recognise (check with the node's admin REST on its loopback, `GET /admin/v1/peers`), or unexpected
  traffic on tcp/60000.
* **Likely cause.** Cluster and shard ids are **not access control**. Anyone who can reach the relay's libp2p port and knows cluster 66 / shard 0 can join the
  mesh, subscribe to every inbox bucket topic, publish, and query the Store (`docs/threat-model.md` T13). In the WireGuard simulation such a peer joined in about
  122 to 470 ms once the firewall rule was removed and saw ciphertext frames, topics, timing and sizes, not plaintext (`docs/network-simulations.md`, Finding 4).
  AgentNet clients ignore unknown peers on their own side (allowlist), but the relay has no RLN and no rate limit.
* **Check.** Firewall rules on tcp/60000 and its counters, the service node's peer list, the address the peer connects from.
* **Action.** Restrict tcp/60000 to known client addresses (host firewall, or tailnet or WireGuard policy). Removing an accept rule does not evict an established
  flow, so also restart the service node or kill the connection (the simulation placed the drop rule before the established-accept rule). A restart of the
  service node costs minutes of degraded live delivery (section 5). Assume the intruder saw metadata; message bodies stay end-to-end encrypted, subject to the
  unaudited-crypto caveat in section 1. If the intruder had your node key (`--nodekey`), generate a new one and update every client's `peers`.

## 7. Backup and restore

Back up with the daemon stopped (or accept an inconsistent copy): the whole data directory is the unit.

| Item | Back up | Notes |
|---|---|---|
| `identity.json` | Yes, encrypted | Secret keys. Prefer `agentnet identity export --out <file> [--passphrase-file <file>]` (age, mode 0600, never overwrites). Keep the passphrase elsewhere. |
| `agentnet.db` (+ `-wal`, `-shm`) and `agentnet.generation` | Together or not at all | Inbox, outbox, contacts, dedupe history. A database older than the sidecar, or a missing sidecar, starts the replay guard. |
| `agentnet.toml` | Yes | Contains no secrets, but names peers and paths. |
| `webhook.db`, `revocation.json` | Yes if used | |
| `control.token`, `mcp-http.token`, webhook secret file | Prefer regenerating | Local credentials. |
| `lock`, `agentnet.sock` | No | Runtime files. |
| Service node `--nodekey` and `/data` Store volume | Yes (the key is secret) | The peer id depends on the key. |

Restore: into a directory with no identity use `identity import` (6.8). Restoring an old copy of `agentnet.db` starts the replay guard: older messages are held until
`max_ttl + clock_skew` has passed or you run `agentnet doctor --accept-rollback` (daemon stopped). Messages received after the backup and before the rollback are lost.

**Never copy a data directory between two live instances.** Never run the same identity, or a copy of its data directory, in two places at once. Never share one sidecar
node between two daemons. Never put identity files, tokens or passphrases in logs, tickets or version control.

## 8. Security operations notes

* Data directory 0700 and every file 0600; the daemon and `doctor` check this (`docs/configuration.md`). Keep `--data-dir` on a local filesystem you trust.
* `control.token` (64 hex chars) authenticates the Unix socket `agentnet.sock` (mode 0600). Any process that can read the token file can control the agent.
  Treat it as a password.
* HTTP MCP (`[mcp_http]`, off by default) uses a static bearer token from `mcp-http.token`. It is **not** the MCP OAuth profile. The bind address must be
  loopback (anything else is a config error). Any local process of any user can reach loopback ports, so keep the token private on a shared machine.
* The node REST API has **no authentication** and `--rest-admin=true` lets a caller dial arbitrary peers. Bind it to loopback only; publish container ports
  as `127.0.0.1:<port>:8645`. **Never expose node REST** to a network or to the tailnet.
* Private mode and its fail-closed audit stay on. Do not set `mode = "public"` without understanding it; it skips the peer audit and is UNTESTED.
* Webhook: keep `secret_file` at 0600 and at least 32 bytes; leave `allow_remote` false unless needed.
* Remote message content is untrusted data, never instructions or code. Events carry references, not text. Keep `policy.auto_trigger` false unless you need it.
* Discovery adverts, if `[discovery]` is enabled, are plaintext and readable by every node on the relay (`docs/discovery.md`).
* Use synthetic messages and disposable keys for any test. Never load-test public relays.
* Cryptography is unaudited; independent review is required before production use with sensitive information.

## 9. Known limitations

* Single-host validation only; real Tailscale, NAT and separate hosts UNTESTED (`docs/network-simulations.md`, `docs/relay-setup.md` section 10).
* No forward secrecy, no post-compromise security, unaudited composition (`docs/threat-model.md`, `docs/crypto-requirements.md`).
* Revocation is best effort, no global list (`docs/protocol.md` section 9).
* A silently dropped connection can take minutes to recover; root cause not found (section 6.3).
* After node or relay restarts live delivery is degraded for about a minute or more; recovery relies on retries and Store.
* Recovery is bounded by the minimum of Store retention, message TTL and `storage.retention_hours`; the Store rejects messages when clocks differ by more than 20 s.
* One node per agent; no sharing, no embedded node, linux/amd64 node image only (`docs/relay-setup.md`).
* No automatic Store failover between service nodes (`docs/relay-setup.md` section 9).
* Anyone who can reach the relay port can join it; use a firewall.
* The same identity in two places is not detected.
* No documented upgrade procedure, no supervisor or service unit, no metrics CLI, no log shipping.
* Hostile load, third-party MCP hosts and public mode are untested.
* Full list: `README.md` (Limitations), `docs/spike-report.md`.
