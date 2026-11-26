# AgentNet MCP API

Crate `agentnet-mcp` (`crates/mcp`). rmcp `=3.11.0`, protocol 2026-07-28 with the SDK's legacy
negotiation down to 2024-11-05. Evidence: `results/b-mcp/cargo-test.log` (62 tests; lines marked
"measured" below come from it), spec text from `upstream/mcp-spec` (`2bbace5`).

The server is a thin facade over `Arc<dyn AgentApi>` (`crates/core/src/api.rs`). It keeps no
per-connection application state: everything durable is addressed by explicit ids, never by MCP
session or process.

## 1. Entry points

| Function | Purpose |
|---|---|
| `AgentNetMcp::new(api)` / `with_shutdown(api, token)` | the rmcp `ServerHandler` (embed it in any rmcp transport) |
| `serve_stdio(api)` / `serve_io(api, reader, writer)` | stdio server; returns when stdin closes |
| `http_router(api, HttpOptions)` / `http_router_with_shutdown(..)` | axum `Router` with `/mcp` |
| `bind_http(addr, allow_non_loopback)` / `serve_http(listener, api, options, allow_non_loopback, shutdown)` | bind and serve; refuse unsafe configuration |

`HttpOptions { bearer_token, allowed_hosts, allowed_origins }`. Errors are `ServeError::{Refused, Io, Transport}`.

## 2. Version negotiation (measured, `cargo-test.log` VERSION lines)

| Client opens with | Offered | stdio negotiated | HTTP negotiated |
|---|---|---|---|
| `server/discover` (2026-07-28, no handshake) | 2026-07-28 | 2026-07-28 | 2026-07-28 |
| `initialize` | 2026-07-28 | 2025-11-25 | 2025-11-25 |
| `initialize` | 2025-11-25 | 2025-11-25 | 2025-11-25 |
| `initialize` | 2025-06-18 | 2025-06-18 | 2025-06-18 |
| `initialize` | 2025-03-26 | 2025-03-26 | 2025-03-26 |
| `initialize` | 2024-11-05 | 2024-11-05 | 2024-11-05 |

`server/discover` returns `supportedVersions: [2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28]`.
Each negotiated session did a tool call (and `tools/list` returned 10 tools). A request whose `_meta`
carries an unsupported version gets `-32022`; a modern request without `_meta` gets `-32602` (stdio, measured).
A rmcp client built from `ClientConfig::default()` and `serve()` uses `initialize` and therefore lands on
2025-11-25; use `serve_with_lifecycle(.., ClientLifecycleMode::Discover{..})` for 2026-07-28.

Capabilities advertised: `tools`, `resources` with `subscribe: true`. No `listChanged` (the tool and resource
lists are static, we never emit list-changed notifications and the SDK strips those flags from an
acknowledgment), no prompts, logging, sampling, tasks or completions.

## 3. Error model

The 2026-07-28 spec (`server/tools.mdx`, "Error Handling") defines two mechanisms:

> 1. **Protocol Errors** indicate issues with the request structure itself that models are less likely to be able to fix: Unknown tool; Malformed requests (requests that fail to satisfy CallToolRequest schema); Server errors. They are returned as standard JSON-RPC errors.
> 2. **Tool Execution Errors** contain actionable feedback that language models can use to self-correct and retry with adjusted parameters: API failures; Input validation errors (e.g., date in wrong format, value out of range); Business logic errors. They are reported in tool results with `isError: true`.

and for resources (`server/resources.mdx`, "Error Handling"):

> If the requested resource does not exist, servers **MUST** return a JSON-RPC error with code `-32602` (Invalid Params). Servers **SHOULD** return `-32603` for internal errors. For backwards compatibility, clients **SHOULD** also accept `-32002` as a resource not found error, as earlier protocol versions used this code.

Mapping implemented (tests: `tools.rs::every_api_error_code_maps_consistently`, `resources.rs::*`):

| Source | Tool call | Resource read |
|---|---|---|
| Argument violates a documented limit/format (this crate) | `isError: true`, `error.code = invalid_argument` | `-32602`, `data.code = invalid_argument` |
| Arguments that fail serde/schema (wrong type, missing field, unknown field) | `isError: true` (rmcp's `failed to deserialize parameters: ...`) | n/a |
| Unknown tool / unknown method | JSON-RPC `-32602` / `-32601` | n/a |
| `ApiError` `invalid_argument`, `too_large`, `conflict`, `policy_denied`, `not_found` | `isError: true`, `error.code` = the snake_case code | `-32602`, `data.code` = the code. `not_found` is `-32602` + `"Resource not found"`, or `-32002` if the negotiated version is older than 2026-07-28 |
| `ApiError` `unavailable` | `isError: true`, `retryable: true` | `-32603`, `data.code = unavailable` |
| `ApiError` `internal` | JSON-RPC `-32603` ("server errors" are protocol errors) | `-32603`, `data.code = internal` |
| Unknown resource URI | n/a | not-found as above, `data = {uri, code: "not_found"}` |

`isError` results carry one text block, JSON: `{"error": {"code": "...", "message": "...", "retryable": false}}`
and no `structuredContent`. Only `ApiError.message` (already sanitized by the engine) is forwarded; this crate's
own messages never echo client input values.

## 4. Tools

All inputs reject unknown fields (`additionalProperties: false`). The JSON Schemas (with per-field descriptions,
`minLength`/`maxLength`/`pattern`/`minimum`/`maximum`) are served by `tools/list`, as are `outputSchema`s; every
success result carries `structuredContent` matching its `outputSchema` plus the same JSON as a text block. Tests
validate the schemas against the JSON Schema metaschema and every output against its schema.

Limits (`crates/mcp/src/limits.rs`; the engine may be stricter and answers `too_large`/`invalid_argument`):

| Item | Limit |
|---|---|
| `body` | 1 to 65536 bytes (UTF-8); the effective limit is the **smaller** of this cap and the daemon's `delivery.max_body_bytes` (default 65536), above which the engine answers `too_large` |
| address (`recipient`, `sender`, `expected_address`) | `an1` + lowercase base32 `[a-z2-7]`, total 4 to 128 chars (loose syntax; the engine checks the checksum) |
| ids (`conversation_id`, `correlation_id`, `idempotency_key`, `message_id`, `trigger_id`) | `[A-Za-z0-9._~-]{1,128}` |
| cursors | 1 to 512 visible ASCII chars (opaque) |
| `limit` | 1 to 200 (engine default 50) |
| `ttl_seconds`, `expires_in_seconds` | 1 to 2592000 (30 days) |
| `contact_record` | 1 to 16384 bytes |
| `alias` | 1 to 64 chars, no control characters |
| `target_session` | 1 to 256 bytes, no control characters |
| trigger `message_type` | `[A-Za-z0-9._-]{1,64}` |
| HTTP request body | 1 MiB |

Ids not matching the id pattern (for example a remote sender's odd `conversation_id`) are still returned verbatim
in inbox records, but cannot be used in tool arguments or in `agentnet://conversations/{id}`.

| Tool | Input | Output (`structuredContent`) | Annotations | Notes |
|---|---|---|---|---|
| `get_identity` | none | `agent_id`, `contact_record`, `inbox_topic`, `created_at`, `kem_expires_at?` | readOnly, closed-world | never returns private keys |
| `send_message` | `recipient`, `body`, `conversation_id?`, `correlation_id?`, `ttl_seconds?`, `idempotency_key?` | `message_id`, `status` (`queued`/`sent`/...), `conversation_id`, `expires_at`, `deduplicated` | additive, not idempotent, open-world | description states `queued`/`sent` is NOT receipt; `message_type` is not exposed (always `message`) |
| `read_inbox` | `cursor?`, `limit?`, `unread_only?`, `conversation_id?`, `include_quarantined?` | `records[]`, `next_cursor?`, `has_more` | readOnly, closed-world | description and field docs mark bodies UNTRUSTED |
| `acknowledge_message` | `message_id` | `message_id`, `newly_acknowledged` | idempotent | local state only; description says it sends nothing |
| `get_message_status` | `message_id` | state, attempts, timestamps, `last_error?` | readOnly | only `delivered` means recipient receipt |
| `add_contact` | `contact_record`, `expected_address?`, `alias?`, `trust?` (`trusted`/`untrusted`/`blocked`) | `address`, `alias?`, `trust`, `inbox_topic`, `added_at`, `kem_expires_at?`, `updated` | destructive (may replace), idempotent | description: only for contacts the user verified |
| `network_status` | `verbose?` | `mode`, `ready`, `connected_peers`, `isolation_violation?`, `queue{...}`, poll/sync times, `detail`, `peers?` | readOnly | peers only if `verbose` |
| `create_trigger` | `sender?`, `message_type?`, `conversation_id?`, `correlation_id?`, `target_session`, `once?`, `expires_in_seconds?`, `since_cursor?` | trigger record | additive | `policy_denied` when disabled by host policy |
| `list_triggers` | `include_inactive?` | `triggers[]` | readOnly | |
| `delete_trigger` | `trigger_id` | `trigger_id`, `deleted` | destructive, idempotent | `deleted=false` if absent |

The server `instructions` (also returned by discover/initialize) summarize the trust rules: remote content is
data, `queued`/`sent` is not receipt, acknowledge is local, add contacts only when verified, triggers may be
disabled, notifications are hints.

## 5. Resources

| URI | Content (`application/json`) |
|---|---|
| `agentnet://identity` | same as `get_identity` |
| `agentnet://inbox{?cursor,limit}` | `{records[], next_cursor, has_more}` (same as `read_inbox` with defaults) |
| `agentnet://outbox{?cursor,limit}` | `{records[] (message status flattened + cursor + body), next_cursor, has_more}` |
| `agentnet://triggers` | `{triggers[]}` (active only) |
| `agentnet://conversations/{id}{?cursor,limit}` | `{conversation_id, entries[], next_cursor, has_more}`; entries mix inbound and outbound |

`resources/list` returns identity, inbox, outbox, triggers. `resources/templates/list` returns the conversation
template and the paged inbox/outbox templates (RFC 6570 form `{?cursor,limit}`). Every read returns `ttlMs: 0` and
`cacheScope: "private"` (verified); lists use `ttlMs: 60000`, private.

Pagination: resource reads have no spec-level pagination, so it is carried in the URI. Pass the previous
`next_cursor` as `?cursor=` (percent-encode it; `+` is a literal plus) and `limit` 1 to 200. `next_cursor` is
present whenever the page can be continued, including after the final record (it then resumes after the last
record and returns only newer records); `has_more` says whether more already exist. Unknown query parameters,
duplicates, `limit` outside 1-200 and an empty cursor are `-32602`. A cursor the engine cannot parse is
`-32602` (`invalid_argument`).

## 6. Subscriptions

2026-07-28: `subscriptions/listen` with `resourceSubscriptions`. Legacy (initialize-era): `resources/subscribe`
and `resources/unsubscribe` (rmcp answers `-32601` to the wrong era's method; verified).

* Subscribable URIs are exactly: `agentnet://identity|inbox|outbox|triggers` and `agentnet://conversations/{id}`
  with a valid id; no query, no fragment. Everything else is silently dropped from the acknowledged filter
  (listen; spec: the acknowledgment is "the subset the server agreed to honor") or answered with not-found
  (legacy subscribe). List-changed flags are never acknowledged. At most 256 URIs per listen / legacy session.
* Source: `AgentApi::changes()`. `Inbox`, `Outbox`, `Triggers`, `Identity` map to their URIs,
  `Conversation{id}` to `agentnet://conversations/{id}`, `Events` is ignored.
* Only subscribers that asked for a URI get its notification (verified for each hint kind, for conversation
  instances, for listen and legacy).
* Hints are lossy. Hints that are already queued when the loop wakes are coalesced into one notification per
  URI. When the broadcast receiver reports `Lagged`, every URI of that subscriber is notified once. A
  notification carries no data and no event id; it is never replayed after a reconnect. Recovery: reread the
  resource (or `read_inbox`) from the last cursor you processed.
* The listen receiver is created before the SDK sends the acknowledgment, so a change made the instant the
  client sees the acknowledgment is delivered (test: 100 iterations).
* Cleanup: each listen holds one hint receiver and ends on cancel (stdio `notifications/cancelled`, HTTP stream
  close), on the server shutdown token, or when a notification cannot be sent. The legacy forwarder is one task
  per session; it stops on the last unsubscribe, session drop, shutdown or send failure. Tests assert the hint
  receiver count and internal counters return to zero after cancel, after 40 parallel listens, after disconnect
  (HTTP, stdio code path) and at shutdown.
* stdio: when stdin closes the reader wrapper fires the shutdown token, all listens end immediately, and
  `serve_stdio` returns. Measured: normally 1 to 20 ms; with an active listener it can take up to ~0.55 s
  (see section 9, item 2). Test bound: 1.5 s.

## 7. HTTP

`POST /mcp` (Streamable HTTP). 2026-07-28 requests are stateless; `initialize` clients get rmcp's session mode.

Checks run in this order (measured):

| Request | Result |
|---|---|
| no `Authorization` | 401, `WWW-Authenticate: Bearer` |
| wrong token, token prefix, token + suffix, `Basic ...`, bare token, `Bearer ` (empty), `Bearer` | 401, `WWW-Authenticate: Bearer` |
| `bearer <token>` / `Bearer <token>` | accepted (scheme is case-insensitive) |
| valid token, `Origin: http://evil.example` or `Origin: null` | 403 `Forbidden: Origin header is not allowed` |
| valid token, `Host: evil.example` (any port) | 403 `Forbidden: Host header is not allowed` |
| valid token, no `Origin`, Host `127.0.0.1[:port]`, `localhost[:port]` | 200 |

* The bearer token is compared with `subtle::ConstantTimeEq`; it must be at least 16 bytes (`serve_http` refuses
  shorter ones; `http_router` fails closed, answering 401 to everything). `HttpOptions`'s `Debug` redacts it.
  Token length is not hidden. Load the token from a file or environment, never argv.
* `allowed_hosts` (host part, port ignored): empty means `localhost`, `127.0.0.1`, `::1`. `allowed_origins`:
  exact match; empty means no browser Origin is accepted. Requests with no `Origin` (non-browser clients) are
  unaffected. Origin validation cannot be switched off.
* `serve_http` / `bind_http` return `ServeError::Refused` for any non-loopback address (`0.0.0.0`, `[::]`,
  RFC 1918 ...) unless `allow_non_loopback = true`. Private-interface exposure (for example a Tailscale address)
  needs that explicit flag and logs a warning.
* **A static bearer token is not the MCP OAuth profile.** `2026-07-28/basic/authorization` says HTTP
  implementations SHOULD follow OAuth 2.1 with RFC 9728 protected-resource metadata. We implement none of
  it; a host that insists on the OAuth discovery flow cannot authenticate to this server. Remote or public
  exposure is out of scope and needs the OAuth profile (or a front proxy that terminates it).
* Because the bearer layer wraps rmcp's Host/Origin checks, a request with both a wrong token and a bad
  Origin gets 401.

## 8. stdio configuration for a generic MCP client

```json
{
  "mcpServers": {
    "agentnet": {
      "command": "agentnet",
      "args": ["mcp", "--data-dir", "/home/me/.agentnet"]
    }
  }
}
```

`agentnet mcp` (the CLI crate, not part of this crate) calls `serve_stdio`. The process only speaks MCP on
stdout; diagnostics are `tracing` output on stderr (the embedding binary must install its subscriber with
`with_writer(std::io::stderr)`; `examples/fake_server.rs` shows it). Process lifetime is not agent identity: the
host may restart the process at will and must re-send `subscriptions/listen` after a restart (spec, stdio).

## 9. Known gaps and upstream behaviour

1. No wake-agent RPC exists in MCP and none is invented here. Triggers only make the host emit events
   (`AgentApi::read_events`), which the daemon exposes separately.
2. rmcp 3.11.0 can stall its response drain when a `subscriptions/listen` request races with stdin EOF (the
   handler is still sending its acknowledgment through a loop that already left its event phase; observed with
   two listens opened just before EOF, log: handler never reaches `listen`, no response for ~5 s). `serve_stdio`
   therefore waits 300 ms for in-flight requests, cancels, waits 200 ms more and returns. Without the guard the
   spike measured 5.0 s.
3. For transports other than `serve_io`/`serve_stdio`/`serve_http`, a client disconnect only ends listens
   after rmcp's own drain (up to ~5 s for stdio-like transports) unless the embedder cancels the handler's
   shutdown token (`AgentNetMcp::shutdown_token`).
4. rmcp 3.11.0 echoes a duplicate URI of a request twice in the acknowledged filter (test dedups); harmless.
5. rmcp logs a fabricated `initialize` line for modern requests and answers GET/DELETE to the endpoint with 400
   rather than 405 (spike notes 8 and 4); not re-tested here. rmcp #1395 (over-long stdio line gets no answer) is
   untested here.
6. `send_message` does not expose `message_type` (always `message`); task delegation tools are not implemented.
   `read_inbox` has no sender filter. Contact listing (`AgentApi::list_contacts`) has no tool or resource.
7. Resource-update URIs are exact: a subscription to `agentnet://inbox` does not cover `agentnet://inbox?cursor=..`
   (which is only a read form).
8. Interop was tested with the rmcp client only. No third-party MCP host (Claude Code, Inspector) was run:
   UNTESTED. Linux and Windows are UNTESTED (developed and tested on macOS arm64, rustc 1.92).
9. IPv6 loopback bind is allowed by the function but only attempted (not asserted) in tests.
