# ADR 0003 — MCP SDK and protocol version

Status: accepted (2026-11-25). Owner: lead agent.

## Evidence

`docs/spike/notes-mcp.md`, `spike/mcp-spike/`, `results/a3-mcp/` (14 tests,
re-run by the lead) and `crates/mcp` (62 tests, re-run by the lead):

* MCP 2026-07-28 is the current stable revision (the `latest` URL redirects to
  it). `rmcp` 3.11.0 (2026-11-17, Apache-2.0, MSRV 1.88) implements it,
  including `server/discover` and `subscriptions/listen`, and also 2025-11-25,
  2025-06-18, 2025-03-26 and 2024-11-05.
* Observed negotiation: discover/auto clients get 2026-07-28; a default rmcp
  client using legacy `initialize` gets 2025-11-25; forced legacy offers are
  honoured as offered over stdio and HTTP.
* Under 2026-07-28 a resource-update notification can only be written from
  inside an open `subscriptions/listen` call. Legacy `resources/subscribe` uses
  a retained peer handle.

## Decision

* Pin `rmcp = "=3.11.0"`, server features only in the library.
* Target 2026-07-28; accept older versions only through the SDK's own
  negotiation; test each.
* The engine publishes lossy change hints on a broadcast channel; every listener
  selects on that channel and on cancellation, and notifies only URIs it was
  asked for. Hints are sent after persistence. Clients recover by rereading from
  their cursor.
* stdio first. Streamable HTTP binds loopback only, with a static bearer token
  (constant-time compare), Host allowlist and Origin validation.

## Consequences and limits

* A static bearer token is **not** the MCP OAuth authorization profile. Remote
  HTTP exposure is refused by default and is out of scope.
* MCP has no "wake the agent" request. Notifications tell a connected client
  that something changed; starting inference is the host's decision. Hosts that
  need to be started use the separate event socket/webhook (architecture §7).
* Sampling is not used.
* rmcp 3.11.0 can take ~5 s to exit on stdio EOF with an open listener; the
  crate works around it (worst case measured ~0.55 s).
* UNTESTED: third-party MCP hosts (only the rmcp client was used), Linux and
  Windows builds of the MCP crate, the Tasks extension, rmcp's `auth` feature.
