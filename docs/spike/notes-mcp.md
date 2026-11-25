# A3 MCP spike notes (rmcp)

Date of work: 2026-11-25. Host: macOS (Darwin 25.6.0) arm64, rustc 1.92.0, cargo 1.92.0.
Crate: `spike/mcp-spike/` (standalone, own `[workspace]`, `Cargo.lock` present).
Raw evidence: `results/a3-mcp/`. Reproduce everything with `spike/mcp-spike/run.sh`.

Convention: "VERIFIED" = I ran it or read the cited file. "README CLAIM" = only stated in upstream docs, not exercised here. "UNTESTED" = not run.

## 1. Verified facts about the spec

Sources: clone of `https://github.com/modelcontextprotocol/modelcontextprotocol` at `2bbace5` (2026-11-24) in `upstream/mcp-spec/` (paths below are relative to `upstream/mcp-spec/docs/specification/`). The subscriptions page fetched from `raw.githubusercontent.com/.../main/...` is byte-identical to the clone (`diff` empty).

**2026-07-28 is the latest stable revision.**
- `curl -sIL https://modelcontextprotocol.io/specification/latest` returns `HTTP/2 307 location: /specification/2026-07-28`.
- `docs/specification/` contains `2024-11-05 2025-03-26 2025-06-18 2025-11-25 2026-07-28 draft`. `draft/changelog.mdx` says "Changes since the most recent release will accumulate here" and lists only minor items (CIMD draft-03, `_meta` restored on a few types).

**What changed vs 2025-11-25** (`2026-07-28/changelog.mdx`):
- No handshake: "Make MCP stateless: remove the `initialize`/`notifications/initialized` handshake. Every request now carries its protocol version and client capabilities in `_meta` (`io.modelcontextprotocol/protocolVersion`, `io.modelcontextprotocol/clientCapabilities`)... Version mismatches return `UnsupportedProtocolVersionError`" (item 2).
- "Remove protocol-level sessions and the `Mcp-Session-Id` header from the Streamable HTTP transport." (item 1)
- "Add `server/discover`: servers MUST implement this RPC" (item 3; also `server/discover.mdx`: "Servers **MUST** implement it").
- "Replace the HTTP GET endpoint and `resources/subscribe`/`resources/unsubscribe` with `subscriptions/listen`: a single long-lived POST-response stream" (item 4).
- "Remove SSE stream resumability and message redelivery (the `Last-Event-ID` header and SSE event IDs)... A broken response stream loses the in-flight request" (item 9).
- Remove `ping`, `logging/setLevel`, `notifications/roots/list_changed` (item 5).
- Tasks "moved out of the core protocol and into an official extension (`io.modelcontextprotocol/tasks`)"; `tasks/list` removed (item 6). Not exercised by me (UNTESTED).
- Server-initiated sampling/elicitation/roots replaced by Multi Round-Trip Requests (item 7).
- Every result carries `resultType`; `ttlMs`/`cacheScope` required on discover/list/read results (minor item 5). Resource-not-found code changes -32002 -> -32602 (minor item 6).
- Required HTTP headers `Mcp-Method` and `Mcp-Name` (minor item 4); error codes -32020 HeaderMismatch, -32021 MissingRequiredClientCapability, -32022 UnsupportedProtocolVersion (minor item 12).

**Sampling is deprecated**: changelog "Deprecated" item 1 ("Deprecate the Roots, Sampling, and Logging features... new implementations should not add support for them"); `client/sampling.mdx` header "Deprecated: The Sampling feature is deprecated as of protocol version..."; also listed in `deprecated.mdx`. Dynamic Client Registration and HTTP+SSE are also deprecated.

**Versus 2025-06-18 -> 2025-11-25** (`2025-11-25/changelog.mdx`, 2025-06-18 -> this): OIDC discovery for auth servers, icons, incremental scope consent, URL-mode elicitation, sampling with tools, CIMD client registration, experimental tasks, "servers must respond with HTTP 403 Forbidden for invalid Origin headers" (minor item 3), SSE polling/resumption (SEP-1699). 2025-06-18 itself (`2025-06-18/changelog.mdx`): removed JSON-RPC batching, structured tool output, MCP servers are OAuth resource servers, RFC 8707 resource indicators, elicitation, resource links, `MCP-Protocol-Version` header on subsequent HTTP requests. None of those are blockers for the spike; the big break is 2026-07-28.

**"A connection is not a session"** - `2026-07-28/basic/index.mdx` lines 195-208: "Servers **SHOULD NOT** require that a client reuse the same connection or process to perform related operations. Clients **SHOULD NOT** use an individual task, thread, or conversation as the lifetime boundary for the stdio process. State that needs to span multiple requests... **MUST** be referenced by an explicit identifier the client passes on each request." and "an open connection, such as a STDIO process, is not a conversation or session". Matches goal.md B3 ("Keep state in explicit agent IDs and durable records").

**Subscriptions** (`2026-07-28/basic/patterns/subscriptions.mdx`):
- Filter fields: `toolsListChanged`, `promptsListChanged`, `resourcesListChanged`, `resourceSubscriptions: string[]`. "The server **MUST NOT** send notification types the client has not explicitly requested."
- "The server **MUST** send `notifications/subscriptions/acknowledged` as the first message carrying the subscription's ID in `_meta` under `io.modelcontextprotocol/subscriptionId`". The acknowledged filter is "the subset the server agreed to honor".
- Subscription ID = JSON-RPC id of the `subscriptions/listen` request; every notification carries it in `_meta`.
- Cancellation: client closes the SSE stream (HTTP) or sends `notifications/cancelled` (stdio). Server may end gracefully with a `subscriptions/listen` result (`resultType: "complete"`).
- "On **stdio**, if the connection is terminated and then re-established, the client **MUST** re-send `subscriptions/listen`... the server holds no subscription state across reconnections."
- `server/resources.mdx`: `subscribe` capability still exists and now means "supports resource-specific update notifications for resources requested through `subscriptions/listen` using the `resourceSubscriptions` filter" (line 58). There is no replay and no event id: notifications are hints (consistent with goal.md B3).

**Streamable HTTP** (`2026-07-28/basic/transports/streamable-http.mdx`):
- One MCP endpoint accepting POST; every JSON-RPC message is its own POST; response is `application/json` or `text/event-stream`; "The client **MUST** include an `Accept` header listing both".
- "Servers **MUST** validate the `Origin` header on all incoming connections to prevent DNS rebinding attacks. If the `Origin` header is present and invalid, servers **MUST** respond with HTTP 403 Forbidden." "When running locally, servers **SHOULD** bind only to localhost (127.0.0.1)". "Servers **SHOULD** implement proper authentication for all connections."
- "Every POST request to the MCP endpoint **MUST** include an `MCP-Protocol-Version` header" that must match `_meta`; mismatch -> `400` + `HeaderMismatch`; unsupported -> `400` + `UnsupportedProtocolVersionError`.
- "A server that supports only this revision and receives such [legacy] traffic... HTTP GET or DELETE to the MCP endpoint: respond with `405 Method Not Allowed`. An `Mcp-Session-Id` header on a request: ignore it". "Resumable SSE streams via `Last-Event-ID` are not supported."
- Dual-era servers are explicitly allowed (`basic/versioning.mdx`: "A dual-era **server** selects its behavior from how the client opens... A dual-era server **MAY** serve both eras concurrently on the same endpoint or process.").

**Authorization for HTTP** (`2026-07-28/basic/authorization/index.mdx`): "Authorization is **OPTIONAL**... Implementations using an HTTP-based transport **SHOULD** conform to this specification. Implementations using an STDIO transport **SHOULD NOT** follow this specification, and instead retrieve credentials from the environment." If conformant: OAuth 2.1 resource server, "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata (RFC9728)", validate token audience (RFC 8707), invalid/expired token -> HTTP 401 with `WWW-Authenticate: Bearer ...`. My static-bearer check is therefore NOT the spec's authorization flow; it is a local shared-secret gate that returns 401 + `WWW-Authenticate: Bearer`. A generic third-party MCP host expecting the OAuth discovery flow would not complete it against this server (UNTESTED with any real host).

**Pagination** (`2026-07-28/server/utilities/pagination.mdx`): opaque cursor, `nextCursor`, "clients MUST NOT assume a fixed page size". That is for `*/list` results. `resources/read` has no pagination in the spec, so my inbox pagination is my own convention carried in the URI (resource template `spike://inbox{?cursor,limit}`, RFC 6570 style) and in the JSON body (`cursor`, `next_cursor`).

**stdio** (`2026-07-28/basic/transports/stdio.mdx`): "The server **MUST NOT** write anything to its `stdout` that is not a valid MCP message", stderr free for logs; unexpected termination: "the client SHOULD restart it. Because the protocol is stateless, any in-flight requests are simply lost... Active `subscriptions/listen` streams must also be re-established after restart."

## 2. Verified facts about rmcp

Commands (outputs saved in scratchpad; key lines quoted):
- `cargo search rmcp --limit 5` -> `rmcp = "3.11.0"`.
- `cargo info rmcp` -> `version: 3.11.0`, `license: Apache-2.0`, `rust-version: 1.88`.
- crates.io API (`https://crates.io/api/v1/crates/rmcp`): 3.11.0 created `2026-11-17T15:32:59Z`, `rust_version 1.88`, not yanked; 3.10.0 2026-11-12; 3.9.0 2026-11-05; 3.8.0 2026-10-26; ... 3.0.0 2026-07-28 (`CHANGELOG.md`: "## [3.0.0] - 2026-07-28", 3.0.1 2026-07-29).
- Clone `upstream/rust-sdk/` at `d6c3e2c` (2026-11-25, "fix(client): cap list_all_* pagination"), workspace `version = "3.11.0"`, `rust-version = "1.88"`, `license = "Apache-2.0"`.

**Released crate vs main**: `diff -rq` of `rmcp-3.11.0/src` (crates.io tarball) against `rust-sdk/crates/rmcp/src` shows 11 differing files, all small post-release changes (e.g. `handler/server.rs`: main adds `result.strip_cache_hints_for_legacy_peer()`; `service/client.rs`: new `ListPaginationExceeded` error). No 2026-07-28 feature is main-only. The released 3.11.0 implements 2026-07-28 completely enough for this spike. So the newest mutually supported stable pair is **spec 2026-07-28 + rmcp 3.11.0** (pinned exactly; no git rev needed).

Protocol versions in 3.11.0 (`model.rs:169-173`): `V_2026_07_28`, `V_2025_11_25`, `V_2025_06_18`, `V_2025_03_26`, `V_2024_11_05`; `LATEST = V_2026_07_28`; `KNOWN_VERSIONS` is the list the server supports by default. `server/discover`: `ClientRequest::DiscoverRequest` -> `ServerHandler::discover` (`handler/server.rs`). `subscriptions/listen`: `ServerHandler::accepted_subscription_filter` + `listen(SubscriptionContext)`; client `Peer::listen(filter) -> Subscription`. Legacy `subscribe`/`unsubscribe` still exist, marked `#[deprecated]`, and are answered only for legacy-lifecycle peers (otherwise `-32601`).

Upstream conformance claim (README CLAIM, `ROADMAP.md`): 2026-07-28 server 30/30, client 100%; I did not run their conformance suite (UNTESTED).

**Pinned in `Cargo.toml`**: `rmcp = { version = "=3.11.0", default-features = false, features = ["server","client","macros","transport-io","transport-child-process","transport-streamable-http-server","transport-streamable-http-client-reqwest","reqwest"] }`.
- `server` + `macros`: handler traits and `#[tool_router]`/`#[tool_handler]`. `server` does NOT include stdio; add `transport-io`.
- `transport-streamable-http-server`: Tower service for axum. `transport-child-process`, `client`, `transport-streamable-http-client-reqwest` and `reqwest` (rustls): test client only. A production server crate should need only `server, macros, transport-io, transport-streamable-http-server` (server-only dependency tree UNTESTED). Note `reqwest` with rustls pulled `aws-lc-sys` + `cmake` into this build, i.e. a C toolchain requirement for the client features.
- `schemars` is re-exported as `rmcp::schemars`; the macros need `schemars` 1.x (I used the re-export).
- MSRV 1.88 is rmcp's declared value; my crate sets `rust-version = "1.88"` (cargo picked MSRV-compatible deps: "Locking 232 packages to latest Rust 1.88 compatible versions"). I only built with 1.92 (1.88 build UNTESTED).

## 3. Server design implemented

- `src/lib.rs`: `Shared` (process-wide state: `Mutex<Vec<Record>>`, `broadcast::Sender<()>`, legacy subscriber list, epoch), `SpikeServer` (cheap `Clone` handler), `http_router`, `serve_http`.
- Tool `echo_send` (`#[tool]` with `Parameters<EchoSendInput>`, returns `Json<EchoSendOutput>`; JSON Schema 2020-12 for input and output generated via schemars; see the T2 log line for the full schema). Body limit 4096 bytes.
- Resource `spike://inbox` (listed), template `spike://inbox{?cursor,limit}`; page JSON `{epoch, records[], cursor, next_cursor|null}`; cursor = `<epoch>:<last_seq>`; `limit` clamped 1..=100 (0 or garbage -> `-32602`). `read` sets `ttlMs: 0, cacheScope: private` so the rmcp client cache never serves a stale inbox.
- Notification path: `echo_send` -> `Shared::append` (record stored first, then notify). 2026 path: each running `listen()` holds a `broadcast::Receiver`; on event it calls `context.sink().notify_resource_updated(INBOX_URI)` only if its accepted filter contains that URI. Lagging receivers coalesce into one notification (acceptable: hints). Legacy path: `subscribe()` stores `context.peer.clone()` per handler instance; `append` calls `peer.notify_resource_updated` (spawned). `accepted_subscription_filter` drops every URI except `spike://inbox`.
- Transports: stdio (`ServiceExt::serve(rmcp::transport::stdio())`; logs to stderr via tracing); Streamable HTTP via `StreamableHttpService` mounted on axum at `/mcp`, bound to loopback only (the binary refuses non-loopback binds), static bearer middleware using `subtle::ConstantTimeEq`, `enforce_origin_validation()` (empty allowlist: any present `Origin` -> 403; browsers send Origin, CLI clients do not), default `allowed_hosts` (`localhost`, `127.0.0.1`, `::1`).

## 4. Demonstrations

Run: `cd spike/mcp-spike && ./run.sh` (fmt check, clippy, `cargo test --locked -- --nocapture --test-threads=1`, HTTP binary smoke). Results: `cargo fmt --check` rc=0 (`results/a3-mcp/fmt-check.txt`, empty); `cargo clippy --all-targets --locked -- -D warnings` rc=0 (`clippy.txt`); `cargo test`: 10 + 4 tests passed, 0 failed (`cargo-test.log`; test fns are in `tests/spike.rs` and `tests/transcripts.rs`).

| # | Demonstration | Result | Evidence |
|---|---|---|---|
| 1 | initialize + negotiated version printed, stdio and HTTP | PASS | `cargo-test.log` T1 lines |
| 2 | tool call over stdio | PASS | T2 lines; `transcript-stdio-modern.txt` |
| 3 | tool call over Streamable HTTP on loopback; reject missing/wrong token | PASS | T3 lines; `transcript-http.txt`; `http-binary-smoke.txt` |
| 4 | subscribe, change, receive update, re-read with cursor | PASS (2026 and legacy; stdio and HTTP) | T4/T4b lines; transcripts |
| 5 | unsubscribe/cancel, then no more notifications | PASS (2026 cancel; legacy unsubscribe; stdio and HTTP) | T5/T4b lines; `transcript-stdio-modern.txt`; `transcript-http.txt` |
| 6 | disconnect/reconnect; gap notifications lost; recover from cursor | PASS over HTTP. stdio reconnect N/A (process is the connection; in-memory inbox dies with it) | T6 lines |
| 7 | pagination over >1 page | PASS (25 records, pages of 10/10/5, stdio and HTTP) | T7 lines |
| 8 | 50 concurrent tool calls | PASS (stdio 22 ms, HTTP 128 ms; seqs exactly 1..=50, 50 distinct bodies) | T8 lines |
| 9 | legacy clients | PASS | T9 lines; `transcript-stdio-legacy-*.txt`; `transcript-http.txt` |

### (1) Negotiated versions (T1, rmcp client, both transports)
```
stdio mode=discover  -> 2026-07-28      http mode=discover  -> 2026-07-28
stdio mode=auto      -> 2026-07-28      http mode=auto      -> 2026-07-28
stdio mode=initialize(ClientConfig::default(), offers LATEST=2026-07-28) -> 2025-11-25
http  mode=initialize(same)                                              -> 2025-11-25
```
For 2026-07-28 there is no `initialize`; "negotiation" is `server/discover` (`supportedVersions` lists all five versions) plus per-request `_meta`. Raw frames: `transcript-stdio-modern.txt` (first two lines).

### (3) HTTP auth/Origin/Host results (raw requests, `T3` lines)
```
no Authorization                      -> 401 (WWW-Authenticate: Bearer)
wrong token / Basic scheme            -> 401
valid token                           -> 200
valid token + Origin: http://evil.example -> 403 "Forbidden: Origin header is not allowed"
valid token + Host: evil.example      -> 403 "Forbidden: Host header is not allowed"
rmcp client, wrong token  -> "Send message error Transport [...]: Auth required, when send discover request"
rmcp client, empty token (legacy initialize) -> same error, "when send initialize request"
```
Because the auth layer wraps the rmcp service, an unauthenticated request with a bad Origin gets 401, not 403 (order is mine, not mandated).

### (4)/(5) Subscriptions
- Requested `[spike://inbox, spike://not-offered]`; acknowledged `resource_subscriptions: Some(["spike://inbox"])` (spec "subset the server agreed to honor").
- Wire (stdio, from `transcript-stdio-modern.txt`):
```
-> {"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"_meta":{...},"notifications":{"resourceSubscriptions":["spike://inbox"]}}}
<- {"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3},"notifications":{"resourceSubscriptions":["spike://inbox"]}}}
<- {"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":3},"uri":"spike://inbox"}}
-> {"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3,"reason":"raw test"}}
   (then a tool call: 0 further resources/updated within 500 ms)
```
- HTTP: `subscriptions/listen` POST returns `200 text/event-stream`; first SSE event is the acknowledgment; the update arrives on that same stream; dropping the stream makes the server's `active_listeners` counter go to 0 (`transcript-http.txt`, T5: "server-side active listeners after cancel = 1" with two listeners open then one cancelled).
- Re-read: after a notification the client read `spike://inbox?cursor=<saved>` and got exactly the new records (`["two","three"]`). Notification count is not guaranteed (several appends may coalesce); correctness relies on the cursor read.
- Legacy (`initialize` 2025-11-25): `resources/subscribe` -> `notifications/resources/updated` (no `subscriptionId`) over stdio, and over HTTP delivered on the session's standalone GET stream (`transcript-http.txt`, `GET-stream chunk`); `resources/unsubscribe` -> no further notifications. On a legacy-negotiated rmcp client, `listen()` returns `Mcp error: -32601: subscriptions/listen`.
- Dual-era: a raw modern `subscriptions/listen` sent on a stdio process that already ran legacy `initialize` is served (ack received), as `versioning.mdx` describes (request with modern `_meta` is served modern).

### (6) Disconnect/reconnect (T6, HTTP)
Client#1 consumed record 1 and saved cursor `<epoch>:1`, then disconnected (server listeners -> 0). A second client appended m2..m4 during the gap. Client#2 reconnected, re-sent `listen`: no notification within 700 ms ("NONE (gap notifications lost, as designed)"), then `read(cursor=<epoch>:1)` returned `["m2","m3","m4"]`. Also: against a second server instance (new epoch) the stale cursor yields `Mcp error: -32602: cursor belongs to a different server epoch (server restarted)...` instead of silently returning wrong data. Real MVP needs a durable monotonic cursor, not an in-memory index.

### (9) Legacy versions
rmcp client with `ClientConfig.protocol_version` forced, `Initialize` lifecycle; each over stdio and HTTP; each did a successful tool call. Negotiated == offered in all 8 combinations: `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`. Raw stdio (`transcript-stdio-legacy-all.txt`): offering `2026-07-28` or unknown `1900-01-01` to `initialize` -> server answers `protocolVersion: "2025-11-25"` (newest version that has a handshake). Note rmcp's `ServerHandler::supported_protocol_versions` default is every known version including 2024-11-05, so we serve ancient clients unless narrowed.

### Other raw checks (`transcript-stdio-modern.txt`, `transcript-http.txt`)
- Request with `_meta.protocolVersion = 1900-01-01`: stdio -> `-32022 "Unsupported protocol version"` with `data.supported`; HTTP -> `400` + same body.
- No `_meta` at all: `-32602 "request _meta is missing or has malformed required fields: io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities"`.
- HTTP header/body mismatch (`Mcp-Method: tools/list` vs body `tools/call`) -> `400`, `-32020`. Omitted `MCP-Protocol-Version` on a modern body -> `400`, `-32020`.
- Modern HTTP responses never carry `Mcp-Session-Id`; legacy `initialize` over HTTP does (`mcp-session-id: c0206a59-...`).
- stdout hygiene: in every stdio run all stdout lines parsed as JSON (asserted in test); logs in `*.server.stderr.log`. HTTP binary prints exactly one non-protocol line (`LISTENING 127.0.0.1:PORT`) on stdout, only in `--transport http` mode.
- Binary guards: non-loopback bind and token < 16 bytes are refused (`http-binary-refusals.txt`).

## 5. SDK bugs, surprises, deviations (all observed unless marked)

1. **`ClientConfig::default().serve(transport)` does not give you 2026-07-28.** It uses the legacy `initialize` lifecycle and lands on 2025-11-25 (T1). You must call `serve_with_lifecycle(transport, ClientLifecycleMode::Discover{..} | Auto{..})` (trait `ClientServiceExt`).
2. **Upstream `README.md` on main does not compile against the released 3.11.0 for resources**: it shows struct literals `ListResourcesResult { resources, next_cursor, meta }` and `-> Result<ReadResourceResult, _>`. Compiler: `error[E0063]: missing fields cache_scope, result_type and ttl_ms in initializer of ListResourcesResult` and `E0271: expected Result<ReadResourceResponse, ErrorData>`. Use `ListResourcesResult::with_all_items(..).with_ttl_ms(..).with_cache_scope(..)` and `ReadResourceResult::new(..).with_ttl_ms(0).into()` (`ReadResourceResponse` is an MRTR-aware enum).
3. **stdio shutdown with an open `listen` takes ~5 s.** On stdin EOF with an active `subscriptions/listen`, the server exited with status 0 only after 5017 ms (`transcript-stdio-eof-active-listen.txt`); the same run without an open listen exits in ~30 ms. Cause (read from `rmcp-3.11.0/src/service.rs:1835`): `QuitReason::Closed` drains in-flight handler tasks for up to 5 s, and `SubscriptionContext::cancelled()` is not fired by transport close, so the listen loop keeps running until the drain timeout. In test `t5` (stdio, one `listen` left open) about 3 s passed between the last assertion and the next test's first log line; I did not isolate whether that is `client.cancel()` waiting on the child (UNCONFIRMED). The spec expects clients to cancel before exiting; a daemon proxy should still treat EOF as "end all listens".
4. **GET/DELETE on a modern HTTP endpoint without a session return `400 "Bad Request: Session ID is required"`**, not the `405` the spec says servers SHOULD return (`transcript-http.txt`).
5. **Modern HTTP responses are SSE by default**, even for plain request/response (`content-type: text/event-stream`, first event `data: {...}`). `StreamableHttpServerConfig::with_json_response(true)` exists (README CLAIM; UNTESTED here).
6. **`Mcp-Name` must equal the full `params.uri` including query**; my raw test initially sent the URI without `?limit=1` and the server correctly answered `-32020 "Mcp-Name header ... does not match body value ..."`. Beware of URIs needing Base64 sentinel encoding (`=?base64?...?=`) in header values.
7. **Origin validation is off by default**: `allowed_origins` empty = no check; `enforce_origin_validation()` turns on reject-all-present-Origins. Host allowlist is on by default (`localhost`,`127.0.0.1`,`::1`) (`streamable_http_server/tower.rs` `Default`, lines ~344-346).
8. **Server logs a fabricated `initialize`** for modern requests: stderr shows `Service initialized as server peer_info=Some(InitializeRequestParams { ... protocol_version: ProtocolVersion("2026-07-28") ...` (`http-binary.stderr`); this matches open upstream issue #1425 (README CLAIM for the cause; the log line itself is verified).
9. Per-request handler: with the 2026 stateless mode `StreamableHttpService` calls the factory closure per request (README CLAIM, consistent with my design needing `Arc<Shared>`); legacy session mode creates one handler per session (verified indirectly: legacy `subscribe` state per handler works over HTTP sessions).
10. Open upstream issues that touch what we use (listing of 2026-11-25 via `gh api repos/modelcontextprotocol/rust-sdk/issues`, none reproduced by me): #1395 stdio request over max line length gets no answer; #1325 `LocalSessionManager` doesn't cancel in-flight tool calls on client disconnect; #1347 known method with undeserializable params answered `-32601`; #1482 `tools/list`/`prompts/list` accept a cursor the server never issued; #1492 `with_sse_retry(None)` doesn't disable SSE priming (legacy-session responses in `transcript-http.txt` do start with an empty priming event `data: / id: 0 / retry: 3000`; I did not test `with_sse_retry(None)`); #1469 `chrono` flagged unmaintained (RUSTSEC-2026-0543).
11. Tool argument deserialization failure comes back as `isError: true` tool result ("failed to deserialize parameters: invalid type: integer `1`, expected a string"); unknown tool is JSON-RPC `-32602 "tool not found"`.

## 6. Guidance for the MVP

**Handler structure.** Keep the rmcp handler (`ServerHandler`) a thin, `Clone`, stateless facade over an `Arc<Daemon>`-style handle (here: `Arc<Shared>`). All durable state lives behind that handle with explicit agent IDs; never key anything on the rmcp peer/session. Use `#[tool_router]` for tools, hand-written `list_resources`/`list_resource_templates`/`read_resource` for `agentnet://identity|inbox|outbox|conversations/{id}|triggers`. Return `ttlMs: 0` on mutable resources (required fields in 2026-07-28; otherwise the rmcp client may cache). Keep `supported_protocol_versions` explicit (decide whether to serve 2024-11-05/2025-03-26) rather than inheriting `KNOWN_VERSIONS`. Do not use sampling.

**Emitting resource updates only to subscribers.** Notifications cannot be sent from arbitrary code in the 2026 model: the only valid sink is `SubscriptionContext::sink()` inside `ServerHandler::listen()` for the lifetime of that request. Pattern used here and recommended: persist first, then publish a lightweight event on a `tokio::sync::broadcast` (or per-agent channel) owned by the daemon; each `listen()` loop `select!`s on `context.cancelled()` and the receiver, checks `context.accepted()` (the filter the SDK computed from your `accepted_subscription_filter`) for the exact URI, then `sink().notify_resource_updated(uri)`. Authorization belongs in `accepted_subscription_filter` (drop URIs the caller may not see), not in the loop. Treat `Lagged` as "something changed" and send one notification. For legacy clients (initialize era) store `context.peer.clone()` from `subscribe()` and call `peer.notify_resource_updated(..)` from outside any request; remove peers on error. If you do not want to serve legacy subscribe at all, skip it (the SDK answers `-32601`).

**Cursors.** Notifications are hints. Clients re-read with a durable cursor. The in-memory `<epoch>:<seq>` used here is only valid within one process; the MVP should use the SQLite rowid/sequence plus a stable store id, and reject cursors from another store with `-32602` (as done here).

**Thin stdio process proxying to a daemon.** Spec supports it: stdio is "not a session"; stdout must carry only frames. Recommended shape: `agentnet mcp-stdio` = rmcp stdio server whose handler methods forward over a Unix-domain socket to the daemon (daemon owns identity, SQLite, cursors); its `listen()` opens a daemon event stream (cursor-based replay is possible on the daemon side) and forwards to the sink; when the stream ends or stdin hits EOF, end all listens immediately (see surprise 3). The proxy holds no state beyond sockets, so a crashed/restarted stdio process just means the client restarts it and re-sends `subscriptions/listen` (spec stdio "Unexpected Termination"). HTTP can be served by the daemon itself or by the same proxy binary.

**HTTP auth approach.** Bind loopback (or a private interface) by default; keep `allowed_hosts` and `enforce_origin_validation()` on; bearer check as an outer axum layer with constant-time compare, 401 + `WWW-Authenticate: Bearer`, token from env/file (not argv), minimum length, refuse non-loopback unless explicitly configured. Be explicit that this is a local shared secret, not the MCP OAuth profile: spec says HTTP implementations SHOULD conform to its OAuth 2.1 / RFC 9728 flow if they authenticate users, and "no unauthenticated public listener" (goal.md) is satisfied here only for loopback/private binds. Remote exposure needs the OAuth profile or a front proxy that terminates it; both UNTESTED. Whether common MCP hosts can be configured with a static `Authorization` header for remote servers: UNTESTED.

**Other.** The pinned dependency tree compiles on macOS arm64 only; Linux x86_64/arm64 are UNTESTED. Release-profile build, binary size, licences of the transitive tree (`cargo deny`/`cargo license`) are UNTESTED. MCP Tasks extension, MRTR, `with_json_response`, `request-state`, OAuth client support in rmcp (`auth` feature), and interop with real hosts (Claude Code, MCP Inspector) are UNTESTED. Load beyond 50 concurrent calls and many simultaneous `listen` streams are UNTESTED. IPv6 (`::1`) bind and Windows are UNTESTED.

## 7. Files

- `spike/mcp-spike/Cargo.toml`, `Cargo.lock`, `run.sh`
- `spike/mcp-spike/src/lib.rs`, `src/bin/mcp-spike-server.rs`
- `spike/mcp-spike/tests/spike.rs` (demos 1-9), `tests/transcripts.rs` (raw frames), `tests/common/mod.rs`
- `results/a3-mcp/`: `cargo-test.log`, `clippy.txt`, `fmt-check.txt`, `env.txt`, `transcript-stdio-modern.txt`, `transcript-stdio-legacy-{all,2025-11-25,2025-06-18,2025-03-26,2024-11-05,1900-01-01}.txt`, `transcript-http.txt`, `transcript-stdio-eof-active-listen.txt`, `http-binary-smoke.txt`, `http-binary-refusals.txt`, `http-binary.{stdout,stderr}`, `*.server.stderr.log`
