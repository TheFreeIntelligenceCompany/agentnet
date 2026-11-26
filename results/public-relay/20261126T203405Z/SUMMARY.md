# Public-internet client-to-relay run (instabox edge, native wss), 2026-11-26

Repo HEAD b3a60a6, `agentnet 0.1.0`, nwaku v0.39.2 `@sha256:cb4d14a2...`. Mac (home NAT, arm64, node in colima linux/amd64 via qemu) as outbound-only client; one instabox box `agentnet-pub-r` (x86_64, 2 vCPU/4 GiB) running relay R and agent B. Box lifetime 20:33:16Z to ~20:47:55Z (~14.7 min). Raw check results: `checks.jsonl`; evidence under `evidence/`.

## What this is

Approach A: native secure WebSocket, no shim. R's libp2p node serves plain `ws` on 8000; the provider edge publishes it (`instabox port publish`, public HTTPS URL, TLS 1.3 terminated at the edge, WebSocket upgrade passes). The Mac's own nwaku node dials `/dns4/<PUB_HOST>/tcp/443/wss/p2p/<R>` over the public internet, from behind home NAT, outbound only. The AgentNet message flow (contact exchange with `--expect`, end-to-end encrypted messages, authenticated receipts, MCP send, Store recovery) worked over that path.

## What this is NOT

- Not a relay with its own public IP and raw tcp/60000: the public endpoint is a TLS/WebSocket front end operated by the sandbox provider's edge, which terminates TLS and forwards plain ws to the box. The edge sees (and the provider could log) the libp2p-over-ws byte stream; libp2p's own Noise encryption inside the ws stream still protects it from the edge, which was not separately verified here, and AgentNet payloads are additionally end-to-end encrypted.
- NAT traversal / hole punching between clients is not involved or tested (clients only dial out; there is one relay in the path).
- Public Waku/Logos infrastructure was not used: private cluster 66 shard 0, discovery off, RLN off, one relay of my own. No public bootstrap node was contacted.
- Agent B runs on the relay's host, on the docker bridge, in private mode. Only agent A's path crossed the public internet. The second box (`agentnet-pub-c`) was not created.
- Not a load test (20 messages each way), not a long-duration or fault-injection test, no IPv6, no latency comparison across regions (one Mac, one edge region).
- DNS: the relaxed node A used a public resolver (1.1.1.1) for the name lookup, so "zero public egress" did not hold for node A in this run.

## Result table

| Check | Result |
|---|---|
| 1 Endpoint reachable from the public internet | PASS: TLS 1.3 to `<PUB_HOST>:443` verified, resolves to global addresses, WebSocket upgrade 101 |
| 2 Client nodes list exactly R | PASS: A: `/ip4/<PUB_IP>/tcp/443/wss/p2p/<R>` Connected (configured as /dns4/...); B: R on docker bridge. `doctor --ready` rc=0 on both |
| 3 Messaging | PASS: contacts with `--expect`; A->B 421 ms, B->A 399 ms; MCP `send_message` delivered; 20+20: A->B p50 440 / p95 481 / p99 485 ms, B->A p50 468 / p95 933 / p99 994 ms; 0 duplicates, all ids present |
| 4 Offline recovery | PASS: B offline 5/5 delivered 1.9-5.9 s after restart; A offline 5/5 delivered ~19.4 s after restart (Store sync vs sender retry not separated) |
| 5 Outbound-only | PASS: no listener on 60000/8000 on the Mac, only loopback REST published; R sees A as the docker gateway 172.28.66.1 over ws |
| 6 Exposure | FINDING: a stranger with the right cluster id joins the mesh via the public endpoint, receives live frames and pulls R's Store history (ciphertext only, uniform 564-byte payloads, 0 plaintext hits; topics inbox-NN visible). REST not reachable (502/404) |
| 7 Unpublish | PASS: edge answers 404, node A CannotConnect within ~10 s, a message sent afterwards stayed queued (NoPeersToPublish). Recovery not tested |

## Private mode versus public mode (finding against goal.md)

- Private mode (default) cannot express this deployment: it accepts only a single literal private-range IP plus `/p2p/` in `peers`/`store_peer`, rejecting DNS components and public IPs. `agentnet serve` rc=4 for both the /dns4 wss address and the resolved public IP (`evidence/private-mode-refusal.txt`).
- The only way in is `mode = "public"` + `i_understand_public = true`, which also removes the peer-id allowlist audit entirely (doctor: `[skip] peers == allowlist: public mode: no allowlist audit`). There is no middle mode ("my own relay on a public endpoint, allowlist kept"). Doctor in public mode still prints `[ok] isolation: no isolation violation reported` and `transport ready ... 1 connected allowed peer(s)` although nothing is audited, which reads as more assurance than there is.
- The "choose public infrastructure or exclusively your own private relays" requirement therefore has a gap: "own relay, reached over the public internet" forces the same setting as joining the public network. Agent A ran public mode, agent B private mode; `network status` showed `mode: public` / `mode: private`, `isolation_violation: null`, `ready: true` on both.
- Public mode with the REST adapter still requires single-shard 0; cluster 66 was fine.

## Deviations and notes

- Needed `--websocket-support=true` on the client node as well, `--nat=extip` (default `--nat=any` attempted UPnP/NAT-PMP mapping on the home router), and a real DNS resolver for the node (1.1.1.1; 127.0.0.1 cannot resolve, docker's 127.0.0.11 did not work).
- A first request through the edge using HTTP/2 returned 502; HTTP/1.1 upgrade works. nwaku's client uses HTTP/1.1.
- R lists node B's old connection as CannotConnect after B's restart (stale entry, B's own peer list shows R Connected, messaging worked).
- The relay's WebSocket port stays open to anyone while published; only the REST and tcp/60000 are not exposed. The relay was published ~10.5 min.
- Second box not used; an intruder control used the Mac.
- An unrelated process on the Mac (nc with default connect timeout) hung for about 2 minutes during the exposure check; killed by hand (noted in `rest-not-exposed.txt`).

## Cleanup

Port unpublished, box deleted, `an-x-*` containers removed, agent A stopped and its data dir removed. See `evidence/cleanup.txt`.
