# AgentNet tailnet-policy (ACL) re-run on the OpenPGP tree, 2026-11-27

Commit under test: `481eb152f3b3e1ea7ef9e22c05af20bf2ec13ff9` (public main, `git clone --depth 1` on box 1, `cargo build --release --locked -p agentnet-cli`).
Message protection: RFC 9580 OpenPGP (sequoia-openpgp 2.5.0, OpenSSL 3 backend); addresses `an2...`, contact records are certificates, `contact add` without
`--expect` leaves the contact untrusted. Single run, single trial for every timing. This directory replaces an interrupted earlier attempt (`20261127T193741Z`, left as is).

## What this is and is not

- IS: a real WireGuard-based tailnet with **real Tailscale clients (1.104.7)** on three separate cloud boxes, enforcing an access policy distributed by a
  **self-hosted Headscale control server (v0.29.7, commit c9cf210b)**. Relay/store R (libp2p tcp/60000 published only on box 1's tailnet IPv4), agent B (shares R's host),
  an ALLOWED client (box 2, tag:agentnet-client: node A1 + agent A1) and a DENIED tailnet member (box 3, tag:agentnet-guest: node A2 + agent A2). No host firewall rule for
  tcp/60000 existed: access control came from the tailnet policy alone.
- IS NOT: Tailscale's hosted control plane, and NOT the repo holder's tailnet. **Hosted-Tailscale ACL/grants syntax and behaviour, key expiry (node expiry 0) and MagicDNS (off) remain UNTESTED.**
  Agent B shares the relay host (B -> R is not a tailnet path). Not a security audit: the policy gates reachability of the relay's libp2p port, nothing else (cluster/shard ids and the contact list are not
  access control; a device that can reach R can read frames and Store history, which are end-to-end encrypted).
- Control-plane deviation: the instabox HTTPS edge strips `Upgrade: tailscale-control-protocol` (HTTP 500, `evidence/edge.txt`), so each box ran a ~60-line loopback WebSocket shim (`evidence/harness/tsshim.py`);
  the tailnet itself (tags, policy, netmap, WireGuard, filters) is unmodified Headscale and unmodified Tailscale clients. Headscale's embedded DERP was not used; Tailscale's public DERP map was (encrypted transit only).
- Exposure: one published port (box 1, 8080 -> Headscale), unpublished at the end (`evidence/port-ls-after.txt`: `"ports": []`). Relay and REST ports were never published.

## Results (24 records in `checks.jsonl`: 20 PASS, 3 INFO, 1 UNTESTED, 0 FAIL)

| # | Check | Result |
|---|---|---|
| 1 | Tailnet up: 3 nodes, tags relay / client / guest, Headscale v0.29.7, Tailscale 1.104.7 | PASS |
| 1 | Path box 2 <-> box 1: **DIRECT** (WireGuard over IPv6), 1 ms; first 3 pings via DERP(sea) at 18-20 ms | PASS |
| 1 | `doctor --ready` exit 0 on box 1 (B) and box 2 (A1), private mode with a 100.64/10 peer | PASS |
| 1 | box 1 iptables: no AgentNet rule | PASS |
| 2 | A1's node lists exactly R, Connected | PASS |
| 2 | Contact exchange with `--expect`; wrong `--expect` refused (exit 4); add without `--expect` -> untrusted + warning | PASS |
| 2 | First A1->B 260 ms, B->A1 293 ms, authenticated receipts | PASS |
| 2 | 20 A1->B: 20/20, p50/p95/p99 = 239/417/417 ms; 20 B->A1: 20/20, 181/236/246 ms; 21/21 unique ids at B | PASS |
| 2 | B's node offline, 5 msgs from A1: all received 0.15 s and receipted about 0.3 s after the container restart (same container, not recreated) | PASS |
| 3 | box 3 (guest): `nc <R> 60000` times out; 0 peers in its netmap, route via eth0, `tailscale ping` "no matching peer" | PASS |
| 3 | Node A2: CannotConnect, never Connected (totalConnections=0), `doctor --ready` exit 7; relay cache empty while A1 sent 3 messages (A2's node subscribed to both inbox topics) | PASS |
| 3 | R's peer list exactly A1 and B; R log 0 mentions of A2's IP or peer id | PASS |
| 3 | Variant (guest -> relay tcp/9999 only): guest now routes via tailscale0; 9999 refused (admitted), **60000 and 22 time out** (receiver's packet filter) | PASS |
| 4 | Grant guest->relay:60000 (SIGHUP 22:00:38.3Z): A2 Connected within about 2.7 s, live frames, Store returned 72 + 62 ciphertext messages, `doctor --ready` exit 0 | PASS |
| 4 | **Revert** (22:01:25.3Z): route gone by the next 12 s probe, new connections fail, **established connection died with it**: ticks 10-24 never reached A2, A2's node said Connected for about 53 s then CannotConnect. A1<->B unaffected (24/24 ticks delivered) | PASS |
| 5 | Scan from the allowed client: only tcp/60000 (5 sentinel hits) and 58436 open; sshd on 0.0.0.0:22 does not answer | PASS |
| 5 | **Exception:** tcp/58436, tailscaled's peerapi listener, answers from the client despite the policy (cause UNTESTED, same as the earlier run) | INFO |
| 6 | 25 s capture on box 1: 155 packets for tcp/60000 on `tailscale0`, 0 on eth0; 6 WireGuard UDP/41641 packets on eth0 | PASS |
| 9 | **DERP-relayed path** (box 2 drops all UDP except DNS; `tailscale ping` 18 ms via DERP(sea), no direct address): 20/20 A1->B 232/408/408 ms, 20/20 B->A1 193/243/292 ms; A1's node restarted and reconnected over DERP in 1.1 s; next message delivered | PASS |
| 4c | Frame sizes seen by the granted guest (ciphertext): 1- and 100-byte bodies 2064-2094 B, acks 2071-2092 B (same class), 1000-byte body 3986-4006 B | INFO |

## Frame sizes seen by the granted guest

Live relay frames (A2's node cache, `evidence/sampler4.out`): small messages (1-byte and 100-byte bodies) 2064-2094 bytes; delivery receipts (acks) 2071-2092 bytes; a 1000-byte body
3986-4006 bytes. Store history on R (`evidence/check4.txt`): B's topic 2046-2097 bytes for small frames plus 3986 and 4008; A1's topic (acks and B->A1 messages) 2049-2097. So the smallest
message and an ack are the same size class (about 2.05-2.1 KB, jitter of tens of bytes), and a body of about 1 KB is a second class at about 4 KB; size alone separates short from longer bodies but not message from ack.

## Policy under test (exact, `evidence/policy-main.hujson`)

```
{
  "tagOwners": {
    "tag:agentnet-relay":  ["agentnet@"],
    "tag:agentnet-client": ["agentnet@"],
    "tag:agentnet-guest":  ["agentnet@"]
  },
  "acls": [
    { "action": "accept", "src": ["tag:agentnet-client"], "dst": ["tag:agentnet-relay:60000"] }
  ]
}
```
(Headscale v0.29.7, policy mode `file`, reload by SIGHUP; `grants` not tried.) The guest tag owner entry exists only so box 3 can join with a different tag. The grant and the visibility variant are
`evidence/policy-4-grant.hujson` and `evidence/policy-3b-visibility-variant.hujson`.

## Notes and deviations

1. **Denial has two layers**, both measured: a node that no rule connects to is absent from the other's netmap (no route, no WireGuard peer); where a peer is visible, the receiving tailscaled drops disallowed ports.
2. **Revoking access cuts established connections** (check 4): the revoked peer disappears from the netmap and WireGuard drops its packets; the node keeps reporting Connected for about a minute.
3. R sees every client as the docker gateway address (172.28.66.1); only the tailnet policy gives per-client identity on this host.
4. Latencies differ from the earlier (pre-OpenPGP) run (p50 191/396 ms then, 239/181 ms now) and from the interrupted attempt of the same day (about 437 ms); single trials on shared cloud hosts, cause UNTESTED. The DERP-relayed run was no slower than the direct one, so the relay hop (18 ms) is not visible against the message round trip.
5. The first guest `tailscale ping` in the variant phase went via DERP before direct was established (a path-establishment timing difference, not a policy difference).
6. In this phase the guest's node was explicitly subscribed (REST) to the inbox topics of B and A1 so that "relay cache empty" is meaningful; the agent only subscribes its own topic.
7. Boxes `agentnet-acl-1..3`: created 2026-11-27 about 21:52Z, deleted 22:06:37Z (about 15 min each); `--delete-after 6h`. Scrubbed: published hostname, tailnet IPs, box ids, account email, public IPs (placeholders `<HS_HOST>`, `<TS_IP_*>`, `<PUBLIC_IP*>`); pre-auth keys were single-use, 3 h, never written to results/.
8. The `ts-input` iptables lines in `check1.txt` show some tailscale CGNAT source ranges as `<PUBLIC_IP4>` because the scrubber replaced them.
9. Cleanup: daemons and node containers removed, `tailscale logout` rc=0 on all boxes, Headscale and shims stopped, port 8080 unpublished, boxes deleted by name (`evidence/cleanup-boxes.txt`), Mac temp dir removed.

## Files

`checks.jsonl`; `evidence/`: `topology.md`, `topo.txt` (versions, Headscale config, nodes), `headscale-nodes.txt`, `path.txt`, `check1.txt`..`check6.txt`, `check3b.txt`, `derp.txt`, `edge.txt`, policies `policy-*.hujson`,
`sampler4.out`, `ticker4.out`, `bench-*.json`, `bench-derp-*.json`, `cleanup.txt`, `cleanup-boxes.txt`, `port-ls-after.txt`, `harness/` (scripts incl. the shim; `ev.sh` is the evidence wrapper that scrubs output).
