#!/usr/bin/env python3
"""Is LIVE relay NA -> NB and NB -> NA working right now? (independent of AgentNet)

Publishes one probe frame on a throw-away content topic through one client node and polls the other node
every 100 ms for up to MAX_S seconds. Prints one JSON line with the arrival time per direction (null = not seen).
usage: relay-live-probe.py [MAX_S=20] [NA_URL] [NB_URL]
"""
import base64, json, sys, time, urllib.parse, urllib.request

max_s = float(sys.argv[1]) if len(sys.argv) > 1 else 20
na = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:18641"
nb = sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:18642"

def req(url, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers={"content-type": "application/json"})
    with urllib.request.urlopen(r, timeout=10) as f:
        return f.status, f.read()

def one(src, dst):
    topic = f"/livep/1/p{time.time_ns()}/proto"
    enc = urllib.parse.quote(topic, safe="")
    for u in (src, dst):
        req(u + "/relay/v1/auto/subscriptions", "POST", [topic])
    time.sleep(0.3)
    t0 = time.time()
    req(src + "/relay/v1/auto/messages", "POST", {"payload": base64.b64encode(b"probe").decode(), "contentTopic": topic,
                                                  "timestamp": time.time_ns(), "ephemeral": False})
    while time.time() - t0 < max_s:
        _, b = req(dst + f"/relay/v1/auto/messages/{enc}")
        if json.loads(b):
            return round((time.time() - t0) * 1000)
        time.sleep(0.1)
    return None

print(json.dumps({"na_to_nb_ms": one(na, nb), "nb_to_na_ms": one(nb, na)}))
