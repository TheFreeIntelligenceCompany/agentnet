# AgentNet tailnet-policy (ACL) run, 2026-11-26

## What this is and is not

- IS: a real WireGuard-based tailnet with **real Tailscale clients (1.104.7)** on three separate cloud boxes, enforcing an access policy
  distributed by a **self-hosted Headscale control server (v0.29.7, commit c9cf210b)**. Relay/store R (libp2p tcp/60000 published only on box 1's
  tailnet IPv4), agent B (shares R's host), an ALLOWED client (box 2, tag:agentnet-client: node A1 + agent A1) and a DENIED tailnet member
  (box 3, tag:agentnet-guest: node A2 + agent A2). No host firewall rule for tcp/60000 existed on box 1: access control came from the tailnet policy alone.
- IS NOT: Tailscale's hosted control plane, and NOT the repo holder's tailnet (it was never touched; the Mac's Tailscale was not used).
  **Hosted-Tailscale ACL/grants syntax and behaviour remain UNTESTED** (Headscale implements a compatible subset; the snippet in
  `spike/relay-tailscale/README.md` is still an untested recommendation for hosted ACLs). Key expiry (node expiry was 0) and MagicDNS (off) UNTESTED.
  Agent B shares the relay host (B -> R is not a tailnet path). Single run, single trial for every timing; clocks of different boxes agree to about 1 s.
  Not a security audit: the policy gates reachability of the relay's libp2p port, nothing else (T13: cluster/shard ids and the contact
  list are not access control; a device that can reach R can read frames and Store history, which are end-to-end encrypted).
- Control-plane exposure deviation (read this): the instabox HTTPS edge **strips `Upgrade: tailscale-control-protocol`**, so real Tailscale clients get
  HTTP 500 from Headscale's `/ts2021` (`evidence/edge.txt`: "no upgrade header in TS2021 request"); `instabox port publish --tcp` is disabled on this server.
  The edge does pass WebSocket upgrades and Headscale accepts the same Noise handshake over WebSocket, so each box ran a ~60-line loopback shim
  (`evidence/harness/tsshim.py`, tailscaled `--login-server http://127.0.0.1:18080`) that turns the client's upgrade into a WebSocket to the edge. The
  tailnet itself (tags, policy, netmap, WireGuard, filters) is unmodified Headscale and unmodified Tailscale clients. Headscale's embedded DERP was
  not used (its `/derp` upgrade would be stripped the same way; not tested); Tailscale's public DERP map was used (encrypted transit only).
- Exposure: one published port (box 1, 8080 -> Headscale, public HTTPS URL `<HS_HOST>`), unpublished at the end (`instabox port ls` for the box: `"ports": []`).
  Relay and REST ports were never published.

## Results (22 records in `checks.jsonl`: 19 PASS, 2 INFO, 1 UNTESTED, 0 FAIL)

| # | Check | Result |
|---|---|---|
| 1 | Tailnet up: 3 nodes with tags relay / client / guest; Headscale v0.29.7; Tailscale 1.104.7; node expiry 0 | PASS |
| 1 | Path box 2 <-> box 1: **DIRECT** (WireGuard UDP/41641 over IPv6, later IPv4), 1 ms. The first ping went via DERP(sea) (Tailscale public DERP) before direct was established | PASS |
| 1 | `doctor --ready` exit 0 on box 1 (B) and box 2 (A1); mode `private` with peer `/ip4/<TS_IP_R>/tcp/60000/...` (100.64.0.0/10 is accepted by private mode) | PASS |
| 1 | box 1 iptables: no AgentNet-specific rule (only Docker's own rules and tailscaled's `ts-forward`) | PASS |
| 2 | Node A1 lists exactly R, Connected, at `<TS_IP_R>:60000` | PASS |
| 2 | Contact exchange both ways with `--expect`; wrong `--expect` refused (exit 4) | PASS |
| 2 | First A1->B 242 ms, B->A1 285 ms, authenticated receipts | PASS |
| 2 | 20 msgs A1->B: 20/20, p50/p95/p99 = 191/237/241 ms | PASS |
| 2 | 20 msgs B->A1: 20/20, p50/p95/p99 = 396/431/433 ms; 21/21 unique ids at B | PASS |
| 2 | B node offline, 5 msgs from A1: all 5 received/receipted <1 s after the node container restart (docker stop/start of the same container) | PASS |
| 3 | box 3 (guest): `nc <TS_IP_R> 60000` times out. Under the main policy box 3 has **no peers in its netmap** and no route over tailscale0 (the packets leave via the primary interface and never reach R); `tailscale ping` = "no matching peer" | PASS |
| 3 | Node A2: peer `CannotConnect` after about 105 s; `doctor --ready` exit 7; relay cache empty while A1 sent 3 messages | PASS |
| 3 | R's peer list: exactly A1 and B, never A2; R log: 0 mentions of A2's peer id or tailnet IP | PASS |
| 3 | Variant (box 3 allowed to see R on tcp/9999 only): box 3 now routes via tailscale0 and `tailscale ping` works; tcp/9999 is admitted (connection refused by the host), **tcp/60000 and tcp/22 time out**: the receiving node's tailnet packet filter drops them | PASS |
| 4 | Positive control: add `guest -> relay:60000`, reload (SIGHUP, 22:20:09.85Z): A2 Connected within 4.5 s, 3 live frames seen, Store query returned 50 history messages of B's inbox topic (ciphertext), `doctor --ready` exit 0 | PASS |
| 4 | **Revert** (22:21:16.26Z): route gone within one 9 s sample, new connections time out, and the **established connection died with it**: later messages never reached A2, A2's node still said Connected for 53 s then CannotConnect, R shows A2 CannotConnect. A1<->B unaffected | PASS |
| 5 | From the allowed client, every other port on `<TS_IP_R>` is closed: 1-1024 + 8000-8100 + 18600-18700 + 58400-58500 + 59990-60010 scanned, only 60000 (5 sentinel hits) opens; sshd on 0.0.0.0:22 does not answer | PASS |
| 5 | **Exception:** tcp/58436, tailscaled's own peerapi listener, answers from the client despite the policy (cause UNTESTED) | INFO |
| 6 | 25 s capture on box 1: 122 packets for tcp/60000 on `tailscale0` (`<TS_IP_C1>` <-> `<TS_IP_R>`), 0 on the primary interface, 66 WireGuard UDP/41641 packets there | PASS |

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
(Headscale v0.29.7, policy mode `file`, reload by SIGHUP; `grants` were not tried.) The `tag:agentnet-guest` owner entry exists only so box 3 can join with
a different tag. The check-4 grant policy and the visibility variant are `evidence/policy-4-grant.hujson` and `evidence/policy-3b-visibility-variant.hujson`.

## Notes and deviations

1. **Denial mechanism has two layers**, both measured: (a) a node that no rule connects to is not in the other's netmap, so there is no route and no WireGuard peer (check 3);
   (b) where a peer is visible, the receiving tailscaled drops disallowed destination ports (check 3 variant, check 5). The first layer means the default-deny probe from
   box 3 never even reaches box 1; the second layer is what protects other ports from allowed peers.
2. **Revoking access cuts established connections** (check 4), unlike the cloud-firewall finding where only new connections were refused. Here the cut is a netmap change (seconds), so
   a node still holds a "Connected" libp2p peer for about a minute afterwards, but no data flows. Revocation of a peer that stays visible through another rule was not tested.
3. R sees every client, A1 included, as the docker gateway address (172.28.66.1), as in the earlier firewall run; tailscaled's packets on `tailscale0` carry the real tailnet source
   (`evidence/cap-tailscale0.txt`). So a policy, not R's own peer-source logs, is the only per-client identity on this host.
4. tcp/58436 (tailscaled peerapi) is reachable from an allowed client (INFO). Not an AgentNet port; recorded so the claim "nothing else answers" is not overstated.
5. `docker stop/start` of node B is not a recreated node (the ~62 s blind window did not apply); the sub-second recovery is from that. Clock skew between boxes about 1 s.
6. The tcp socket state in `sampler3.out` (`sock=[]`) is empty because the node's sockets live in the docker network namespace; connection state is judged from the node's peer list, frames received and new-connection probes.
7. The first scan attempt (100 parallel probes) missed the 60000 sentinel once and was discarded; the kept scan uses 30 parallel probes and 5 sentinel hits (`evidence/check5.txt`).
8. First `tailscale up` attempts through the unmodified edge failed (HTTP 500, 22:04Z); the shim fixed it; the three nodes joined at about 22:06-22:08Z. Preauth keys were single-use, 3 h, and never written to results/.
9. Box facts: created 2026-11-26T21:58:42Z, stopped (rm) 22:25:26Z, about 27 min each; names `agentnet-acl-1..3`; `--vcpus 2 --mem-mib 4096 --no-vault --secrets none --auto-suspend 30m --delete-after 4h --meta project=agentnet`.
10. Cleanup: daemons and node containers removed, `tailscale logout` rc=0 on all boxes, Headscale and shims stopped, port 8080 unpublished (`evidence/port-ls-after.txt`), boxes deleted, `instabox ls --meta project=agentnet` = `[]`.

## Files

`checks.jsonl`; `evidence/`: `topology.md`, `topo.txt` (nodes, Headscale config without secrets, versions, DERP), `headscale-nodes.txt`, `path.txt`, `check1.txt` ... `check6.txt`,
`check3b.txt` (visibility variant), `edge.txt`, policies `policy-*.hujson`, `sampler3.out`, `ticker.out`, `cap-*.txt`, `bench-*.json`, `cleanup-boxes.txt`, `port-ls-after.txt`, `harness/` (scripts incl. the shim).
