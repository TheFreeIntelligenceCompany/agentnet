#!/usr/bin/env python3
"""Measure the destructive REST relay cache of a client node, independent of AgentNet.

Subscribes NB to a probe topic, publishes N messages through NA as fast as the
REST API accepts them (or PACE_MS apart), lets them propagate, then performs ONE
poll on NB (GET is destructive) and reports how many of the N arrived.
usage: burst-node-probe.py [N] [PACE_MS] [NA_URL] [NB_URL]
"""
import base64, json, sys, time, urllib.parse, urllib.request

n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
pace = float(sys.argv[2]) / 1000 if len(sys.argv) > 2 else 0.0
na = sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:18641"
nb = sys.argv[4] if len(sys.argv) > 4 else "http://127.0.0.1:18642"
topic = f"/burst/1/probe{int(time.time())}/proto"
enc = urllib.parse.quote(topic, safe="")

def req(url, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers={"content-type": "application/json"})
    with urllib.request.urlopen(r, timeout=20) as f:
        return f.status, f.read()

req(nb + "/relay/v1/auto/subscriptions", "POST", [topic])
req(na + "/relay/v1/auto/subscriptions", "POST", [topic])
time.sleep(1)
t0 = time.time()
base = time.time_ns()
for i in range(n):
    req(na + "/relay/v1/auto/messages", "POST", {
        "payload": base64.b64encode(f"m{i:04d}".encode()).decode(),
        "contentTopic": topic, "timestamp": base + i * 1000, "ephemeral": False})
    if pace:
        time.sleep(pace)
pub_s = time.time() - t0
time.sleep(3)
_, body = req(nb + f"/relay/v1/auto/messages/{enc}")
got = {base64.b64decode(m["payload"]).decode() for m in json.loads(body)}
_, body2 = req(nb + f"/relay/v1/auto/messages/{enc}")
print(json.dumps({"published": n, "publish_phase_s": round(pub_s, 2), "pace_ms": pace * 1000,
                  "returned_by_single_poll": len(got), "second_poll": len(json.loads(body2)),
                  "missing": n - len(got)}))
