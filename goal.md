AgentNet: Waku/Logos agent communication service
Engineering assignment · 25 November 2026 · Working name: AgentNet
1. Mission and operating instructions
Build a standalone, Rust-first communication service that gives autonomous agents persistent cryptographic addresses and allows them to exchange private, asynchronous messages across machines, clouds and networks. Expose the service through MCP, with a separate inbound event interface that a compatible harness can use to initiate execution. Eventually the same Rust core should be embeddable in a native harness, but do not modify or depend on the Pi port in this project.

Start with a discovery spike, not production implementation. Treat the architecture below as a set of hypotheses. Inspect upstream code, compile real dependencies, run experiments, and record failures and limitations. Do not claim support merely because a README mentions a feature. After the spike, select a transport based on evidence and proceed to the Rust MCP MVP if its gates pass. If a gate fails, document it, investigate the bounded fallback, and stop before committing to an unvalidated architecture. Do not silently substitute a centralized message broker or invent a cryptographic protocol.
Desired experience
- Install a local service, generate a durable agent identity, and obtain an address that survives restarts and machine migration.
- Two independently hosted agents can send encrypted messages without exposing inbound ports on their own machines (using suitable reachable service nodes).
- Users can choose public infrastructure or exclusively their own private relays, including relays reachable over Tailscale/WireGuard.
- Incoming messages can be recovered after downtime within configured retention and availability limits; no promise of unlimited offline delivery.
- An MCP client can send, read and discover messages; a capable host can subscribe to changes and optionally wake its agent. The model itself need not poll or remain running.
- A future Rust harness can consume the same library directly, without a second implementation.
2. Upstream research starting points
Verify versions, release dates, licenses, maintenance status, platform support and API compatibility at execution time. Pin exact commits/tags and crate versions in the spike report and lockfile. Starting points (not guarantees of functionality):
- Logos Messaging organization and naming: https://github.com/logos-messaging
- Logos Delivery (formerly Waku/nwaku): https://github.com/logos-messaging/logos-delivery
- Candidate Rust FFI bindings: https://github.com/logos-messaging/logos-delivery-rust-bindings — confirm current canonical location and API compatibility; inspect waku-sys/waku-bindings or successor crates.
- Logos Chat Rust library: https://github.com/logos-messaging/libchat — evaluate de-MLS, contact establishment, key persistence, private network configuration and suitability for nonhuman clients.
- Protocol specifications: https://github.com/logos-messaging/specs ; legacy docs: https://docs.waku.org/
- MCP specification: https://modelcontextprotocol.io/specification/2026-07-28
- Official Rust MCP SDK (rmcp): https://github.com/modelcontextprotocol/rust-sdk
- MCP subscription specification source: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/patterns/subscriptions.mdx
As of this brief, upstream MCP and rmcp documentation identify 2026-07-28 as stable, with transport-neutral subscriptions and compatibility with earlier protocol versions. Recheck before implementation. Use the newest mutually supported stable protocol/SDK pair; target 2025-11-25 interoperability where practical. Logos Delivery is a Nim reference implementation, not a pure Rust stack. A Rust process using native FFI may still require C/Nim build tooling or shared libraries.
3. Phase A — discovery spike
Create a minimal Rust workspace with a disposable spike binary, reproducible scripts and a test matrix. Avoid designing a large crate hierarchy until these experiments establish what the library actually supports. Use synthetic messages and disposable keys only; never send production secrets to public infrastructure.
A1. Build and integration audit
Compare three paths: (1) official Rust bindings to native Logos Delivery, (2) libchat atop supported Delivery APIs, (3) Rust adapter talking to a separately running Logos Delivery node via its supported local API. Prefer native library integration if reliable; use a local daemon adapter if native packaging/ABI is a blocker. Evaluate raw rust-libp2p only as a separately approved alternative, not as a Waku-compatible replacement by assumption.
- Build on Linux x86_64 first; assess macOS arm64 and Linux arm64. Record exact compiler, native toolchain, dependencies, build flags, binary sizes, runtime shared libraries and licensing. Test release build and clean checkout reproduction.
- Inventory available APIs: node lifecycle, static peers, discovery, shard/cluster configuration, publish, receive, Filter/Light Push/Store or current equivalents, durable history, reliable channels, and error reporting. Distinguish native reference node features from binding coverage.
- Examine callback threading, memory ownership, allocator boundaries, string/buffer lifetimes, panic handling, cancellation, Tokio integration and graceful shutdown. Bridge callbacks into a bounded async channel; never block or panic across FFI. Test repeated start/stop, reconnect and sustained message reception.
- For libchat, verify actual encryption model, authenticated contact bootstrap, key rotation, forward secrecy claims, offline key establishment, group membership, state backup/restore and ability to use isolated relays. Determine whether it exposes arbitrary structured payloads and machine-readable events. Do not assume chat handles task delivery semantics.
A2. Network experiments
Use two client processes A/B and at least one reachable relay/service node; repeat with two nodes. Save configs, commands, timestamps, logs with redaction, packet observations and results. Distinguish real cross-machine tests from simulated network namespaces or localhost tests.
Experiment	Required evidence
Basic messaging	A sends to B, B replies; unique IDs and payload integrity verified.
Cross-machine / NAT	Two actual separate hosts, outbound-only clients, no public client listener; record topology.
Private network	Static peer configuration, public bootstrap/discovery disabled, service access restricted; verify packet destinations and no public fallback.
Tailscale	Relay reachable by tailnet address; restrict access using tailnet policy/firewall; demonstrate client exchange if credentials/hosts are available. Otherwise mark untested and provide reproducible steps.
Offline recipient	Stop B, send, restart B, recover within specified retention; test unavailable Store and expired history.
Publisher/relay failures	Drop connections, restart relay and publisher; test reconnect, retry, duplicates, ordering and observable status.
Identity persistence	Restart client; migrate a test identity via explicit secure export/import or supported backup; ensure address and decryption remain valid. Test competing instances or reject concurrent writers.
Security	Wrong recipient cannot decrypt; forged/tampered/replayed messages rejected; inspect relay-visible topics, timing, size, IP and subscription metadata.
Payload boundaries	Test documented maximum and oversize rejection, malformed messages, clock skew, expired messages, Unicode and unknown versions.
Load	Run 1/10/100 logical clients where feasible; test bounded queues and callback backpressure, note resource limits.


Measure end-to-end latency (p50/p95/p99), delivery and duplicate rates, recovery latency, memory/CPU per process, idle bandwidth, startup and shutdown times, and sustainable message rate. Include sample size, topology and raw data. Initial local baseline: 100 numbered messages each direction, plus 20 offline messages and deliberate duplicate/reconnect tests. These are test workloads, not promised production SLAs. Test public connectivity only with authorized infrastructure, respecting network limits and RLN requirements; never load-test public relays without permission.
A3. MCP spike
Implement a tiny rmcp server and test client with one tool and one inbox resource. Demonstrate tool invocation over stdio, Streamable HTTP on loopback, and subscription to resource changes under the 2026-07-28 protocol. Verify the negotiated version and actual SDK behavior; exercise legacy clients if supported. Test subscribe/cancel/reconnect, lost notifications, pagination and concurrent calls. Standard MCP notifications indicate changes; they do not themselves start an agent inference loop. Do not invent a standard MCP wake-agent RPC or use deprecated sampling as a dependency.
A4. Spike deliverables and decision gates
Deliver docs/spike-report.md, docs/compatibility-matrix.md, docs/threat-model.md, a transport decision ADR, source and scripts, pinned versions, and raw test results. Every claim must have evidence, a source link or an explicit untested label. List upstream bugs/edge cases, workarounds, maintenance risks and remaining unknowns.

Go: reproducible Rust build with at least one viable Delivery path; bidirectional encrypted messaging; private isolation demonstrated on controlled infrastructure; durable identity; offline/retry semantics understood; standard MCP tool call and resource change notification demonstrated. A real Tailscale run and public interop may be deferred only if infrastructure is unavailable and explicitly recorded. Do not claim those features validated. If libchat is unsuitable, evaluate an established audited messaging library/protocol, with its key bootstrap and threat model documented; do not hand-roll encryption. If no safe encrypted transport or private isolation works, stop the MVP and report the blocker. If native bindings fail but a local daemon works, use the adapter and keep native embedding as a future option.
4. Phase B — Rust MCP MVP
Build only after the spike validates the foundations. Suggested workspace (adjust based on measured needs):
agentnet/
  crates/core/          # identities, message types, inbox/outbox, policy
  crates/transport/     # transport interface and tested Logos adapter
  crates/mcp/           # rmcp tools/resources/subscriptions
  crates/daemon/        # persistent service, event delivery, config
  crates/cli/           # init, serve, diagnostics, relay instructions
  tests/                # fixtures, mock transport, real relay integration
  docs/                 # spike report, ADRs, threat model, protocol, setup
Keep core independent of rmcp and the harness. Rust async/Tokio and serde are reasonable defaults. Use a bounded channel and transactional SQLite storage (or justify an alternative). The MCP stdio process can be a thin local client to the persistent daemon; distinguish process lifecycle from agent identity. Support direct embedding only if native dependencies allow it. No Node.js runtime required for the chosen Rust service; disclose any native library/sidecar dependency.
B1. Identity and message protocol
Define a versioned agent address format and explicit public contact record that binds signing and encryption keys (or a supported libchat identity). Provide key generation, secure persistence, import/export and documented rotation/revocation limitations. Do not assume an Ed25519 public key is an encryption key. If using independent signing and agreement keys, authenticate their binding. Use an established cryptographic protocol and library, authenticated encryption, and domain separation; never use home-grown cryptography.

Logical envelope (illustrative, not a mandated wire format): version, message_id, sender, recipient, type, conversation_id, correlation_id, created_at, expires_at, payload. Authenticate all security-relevant fields. Put identity and sensitive metadata inside the encrypted envelope where practical; document what transport metadata remains visible. Select an unambiguous serialization scheme and size limits; reject unknown versions safely. Message types initially: message, ack.received, and optionally task.request, task.result with correlation IDs. Remote instructions are untrusted data, never direct code execution.

Use durable outbox/inbox, unique IDs, deduplication, bounded exponential backoff with jitter, retention and TTL. Persist accepted inbound messages before notifying clients. Distinguish queued, transport accepted, recipient persisted (authenticated ack), failed and expired; transport acceptance is not recipient receipt. Assume at-least-once delivery attempts with idempotent handling, not exactly-once distributed execution. Document ordering (no global order guarantee), cursor pagination and recovery from missed events.
B2. Networking modes and privacy
private should be the safe default; require explicit configuration for public mode. Separate identity/contact policy from networking configuration. Private mode must specify static trusted peers/service nodes, disable public bootstrap and discovery, restrict binding/egress, and fail closed without public fallback. Cluster/shard separation alone is not an access control mechanism. Never bridge public and private messages automatically. Public mode is opt-in, with explicit relay/discovery and rate-limit settings. Hybrid gateways are out of scope for MVP.

Illustrative config (map to verified APIs):
[network]
mode = "private"
peers = ["<verified relay multiaddr or endpoint>"]
public_discovery = false
public_fallback = false
[storage]
retention_hours = 168
[policy]
unknown_senders = "quarantine"
auto_trigger = false
Document how to run a user-owned relay and relevant Store/Filter/Light Push services, firewall restrictions, static peer identities and a Tailscale deployment. Test that private clients do not contact public peers. Tailscale provides encrypted connectivity and machine-level policy, not application-level identity or message encryption. Its coordination service may see metadata; relay operators and hosts may see connection/subscription metadata. Protect endpoint keys and storage; do not claim anonymity or confidentiality from a compromised execution host. Evaluate shared topic buckets or private derived topics instead of a public-key-derived inbox; quantify bandwidth/privacy tradeoffs. Avoid claiming mixnet readiness without evidence.
B3. MCP surface
Use the official Rust SDK, current stable supported spec, version negotiation, typed JSON Schemas, standard tool/resource errors and documented limits. For 2026-07-28 use server/discover as required and subscriptions/listen for opted-in changes; do not treat a connection as an application session. Keep state in explicit agent IDs and durable records. Support stdio first (stdout reserved for protocol frames, logs to stderr), then authenticated Streamable HTTP bound to loopback/private interfaces by default. Implement legacy negotiation only via supported SDK behavior; test it. Remote HTTP authorization must follow applicable MCP requirements; no unauthenticated public listener.
Tool	Input / output contract
get_identity	No args; public address/contact record, never private keys.
send_message	recipient, body, optional conversation_id, TTL, idempotency_key; returns message_id and queued/accepted status.
read_inbox	cursor, limit, optional unread/conversation filter; returns authorized records and next_cursor.
acknowledge_message	message_id; mark locally processed idempotently; distinguish from transport receipt.
get_message_status	message_id; delivery state, last attempt and sanitized error.
add_contact	verified contact record; validate key binding, trust decision and address.
network_status	mode, connected peers/services, queue health; avoid sensitive info by default.
create_trigger	authorized sender/type/conversation filter, target session reference, once/expiry; returns trigger_id.
list_triggers / delete_trigger	scoped listing and idempotent deletion.


Optional after core works: advertise_agent and discover_agents using signed, expiring capability records on authorized discovery topics; discovery is opt-in, best effort, not a global directory. Do not broadcast private capabilities. Add task delegation tools only after basic messaging is stable; evaluate MCP Tasks extension separately rather than assuming all hosts implement it.

Resources: agentnet://identity, agentnet://inbox, agentnet://outbox, agentnet://conversations/{id}, agentnet://triggers. Use proper resource templates and authorization. Emit standard resource-update notifications only for requested subscriptions after persistence; clients reread using cursor to recover. Notifications are hints, not a durable queue.
B4. Inbound events and triggers
Provide a separate, small host integration API: authenticated local event stream or Unix-domain socket, with optional signed outbound webhook to a preconfigured allowlisted host. Polling remains available for basic MCP clients. The service emits events; the harness decides if/when to run inference. No generic MCP client is guaranteed to wake automatically. An entirely offline machine cannot be woken by a message without a separate always-on service/supervisor.

Event fields: event_id, event_type (message.received or trigger.matched), agent_id, message_id, trigger_id if applicable, target_session if authorized, timestamp, cursor. Prefer opaque references over plaintext in notifications. Persist event records, support replay by cursor, authenticated acknowledgement and bounded retries. A trigger is a durable predicate evaluated against authenticated inbound events, not arbitrary model-generated code. Support sender/type/correlation matching, once/expiry, atomic one-shot consumption, and idempotent delivery. Avoid race conditions if a reply arrives before a trigger is created: allow matching persisted events since an explicit cursor or register before sending.

Disable automatic invocation by default. Require host-controlled allowlists, per-agent/session authorization, concurrency and rate limits, event TTL, deduplication and maximum trigger/delegation budgets. Never allow an untrusted sender to change permissions, run shell commands, set arbitrary webhook targets or consume unlimited tokens. For webhook mode use configured endpoints, signature/timestamp/replay checks, timeouts and SSRF protections. Demonstrate with a tiny mock harness that consumes an event and records a simulated turn; do not modify Pi or require an LLM.
5. MVP validation and release
Automate unit tests for schemas, crypto-library integration, dedupe, TTL, cursor and trigger matching; deterministic mock transport tests for retries, backpressure, ordering and restarts; real relay integration tests for encrypted exchange and isolation; MCP conformance/interop tests for tools, resources, subscriptions and HTTP authorization. Include malformed input, unauthorized sender, replay, private mode egress, disk failure, queue saturation, key loss, shutdown and crash recovery. Fuzz parsers if feasible. Use cargo fmt --check, cargo clippy, cargo test --locked, dependency/license audit and documented native build steps in CI. No secrets in fixtures or logs.

Acceptance demonstration:
1. Start a controlled relay/service node and two independent Rust AgentNet instances; create identities and exchange verified contact records.
2. Client A calls MCP send_message; B's inbox receives the encrypted message, authenticated receipt updates A's status, and B's subscription sees a resource change.
3. B is stopped and later restarted; recover eligible retained messages without duplicate processing. Explain failures outside retention or relay availability.
4. B registers an authorized one-shot trigger; A sends a matching message; the mock host records one logical event despite retries. Unauthorized messages do not wake it.
5. Repeat on a private network with public discovery disabled; show no unexpected egress and demonstrate relay failure without public fallback. Run Tailscale test if available; clearly flag otherwise.
6. Provide stdio configuration for a generic MCP client and a Rust embedding example or clearly state why the selected adapter cannot be fully embedded.
Deliver a reproducible repository, README quickstart, CLI help, sample private/public configurations, container/relay setup instructions, protocol and API docs, threat model, test results, and a limitations section. Use provisional project name AgentNet; check name/license availability before publication. Do not publish packages, deploy public infrastructure, or incur costs without authorization.
6. Explicit non-goals
No Pi port changes, agent inference runtime, distributed scheduler, agent marketplace, payments, reputation, custom cryptography, bulk file transfer, global anonymity guarantees, arbitrary remote code execution or generic trigger orchestration. No commitment to a single static binary until native packaging has been tested. Do not treat public-network success as proof of production reliability or scalability.
7. First actions for the implementing agent
Inspect the linked upstream repositories and create a concise version/feature matrix. Initialize the spike workspace, get one Rust transport path compiling, and perform the two-client round trip. Next establish private isolation and evaluate libchat security and persistence. Run the MCP subscription spike independently. Write the evidence-based report and ADR before implementing the MVP. Work in small commits; include exact commands and outputs, disclose missing infrastructure, and never mark an unrun test as passing. The owner should be able to reproduce every material result from the repository.
