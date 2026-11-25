#!/usr/bin/env python3
"""E3b: size error band, meta limit, version, dedup of identical publishes. Container network only."""
import base64, json, time, urllib.parse, sys
sys.path.insert(0, ".")
exec(open("probes.py").read().split("out = {}")[0])  # reuse call/pub/poll helpers
CT = "/agentnet/1/spike-a1-limits2/proto"
for n in (NA, NB): call("POST", n + "/relay/v1/auto/subscriptions", [CT])
time.sleep(2)
res = {}
# error band: first payload size that gives the 'exceeded maximum' text
band = {}
for n in (153516, 153517, 153530, 153560, 153580, 153590, 153600, 153700, 154000):
    st, body = pub(b"x" * n, ct=CT, ephemeral=True); band[n] = (st, body[:90])
res["size_band"] = band
# does the NB receive a max-ok message? and with a long content topic is boundary shifted?
poll(NB, CT)
for metan in (0, 32, 64, 65, 100, 2000):
    st, body = pub(b"meta%d" % metan, ct=CT, meta=base64.b64encode(b"m" * metan).decode(), ephemeral=True) if metan else pub(b"meta0", ct=CT, ephemeral=True)
    res.setdefault("meta", {})[metan] = {"publish": (st, body[:100])}
time.sleep(2)
st, body = poll(NB, CT)
got = [(base64.b64decode(m["payload"]).decode(), len(base64.b64decode(m.get("meta", "") or ""))) for m in json.loads(body)]
res["meta_received_payload_and_metalen"] = got
# identical publishes: same payload + explicit identical timestamp (same hash) twice
ts = time.time_ns()
r1 = pub(b"dup", ct=CT, timestamp=ts, ephemeral=True); r2 = pub(b"dup", ct=CT, timestamp=ts, ephemeral=True)
time.sleep(2)
st, body = poll(NB, CT); res["identical_ts_publish_twice"] = {"pub": (r1, r2), "NB_received_count": len(json.loads(body))}
st, body = poll(NA, CT); res["identical_ts_NA_cache_count"] = len(json.loads(body))
# cache overflow: publish 70 messages with NB not polled, cache capacity 50
for i in range(70): pub(b"cap-%03d" % i, ct=CT, ephemeral=True)
time.sleep(3)
st, body = poll(NB, CT); ps = [base64.b64decode(m["payload"]).decode() for m in json.loads(body)]
res["cache_overflow_70_into_cap50"] = {"count": len(ps), "first": ps[:3], "last": ps[-3:], "missing": sorted(set("cap-%03d" % i for i in range(70)) - set(ps))[:25]}
json.dump(res, open(sys.argv[1], "w"), indent=1); print(json.dumps(res, indent=1))
