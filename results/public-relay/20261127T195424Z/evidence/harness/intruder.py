#!/usr/bin/env python3
# intruder.py : a throwaway node (random key, cluster 66, shard 0, no agentnet identity) on 127.0.0.1:18651 joined R via the public endpoint.
# Subscribes to the 16 AgentNet inbox topics, reads what the relay delivers and what R's Store returns. Prints only metadata: topic, sizes, whether any known plaintext appears.
import base64, json, sys, urllib.parse, urllib.request
B = "http://127.0.0.1:18651"; CANARY = sys.argv[1].encode()
def call(m, p, body=None):
    r = urllib.request.Request(B + p, data=None if body is None else json.dumps(body).encode(), method=m, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=30) as f: return f.status, f.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
topics = [f"/agentnet/1/inbox-{i:02d}/proto" for i in range(16)]
for t in topics: print("subscribe", t, call("POST", "/relay/v1/auto/subscriptions", [t])[0])
if len(sys.argv) > 2 and sys.argv[2] == "subscribe-only": sys.exit()
seen = []
for t in topics:
    s, b = call("GET", "/relay/v1/auto/messages/" + urllib.parse.quote(t, safe=""))
    if s == 200:
        for m in json.loads(b): seen.append(("relay", t, len(base64.b64decode(m["payload"])), CANARY in base64.b64decode(m["payload"])))
print("relay-received frames (cache of the intruder's own node):", len(seen))
for x in seen: print("  ", x)
tot = 0; hit = 0; per = {}
for t in topics:
    s, b = call("GET", "/store/v3/messages?contentTopics=" + urllib.parse.quote(t, safe="") + "&includeData=true&ascending=true&pageSize=100")
    if s != 200: print("store", t, s, b[:120]); continue
    for m in json.loads(b).get("messages", []):
        p = base64.b64decode(m["message"]["payload"]); tot += 1; hit += CANARY in p
        per.setdefault(t, []).append(len(p))
print("store query via R (no authentication): messages", tot, "plaintext-canary-hits", hit)
for t, v in per.items(): print("  ", t, "n=%d" % len(v), "payload bytes min/max", min(v), max(v))
