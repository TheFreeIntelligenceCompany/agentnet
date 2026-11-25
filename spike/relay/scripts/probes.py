#!/usr/bin/env python3
"""Experiment E3: payload-boundary / malformed-input probes against the local topology (container network only)."""
import base64, json, time, urllib.request, urllib.parse, urllib.error, sys
NA, NB, R1 = "http://127.0.0.1:18641", "http://127.0.0.1:18642", "http://127.0.0.1:18640"
CT = "/agentnet/1/spike-a1-limits/proto"
def call(method, url, body=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    rq = urllib.request.Request(url, data=data, method=method, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(rq, timeout=30) as r: return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e: return e.code, e.read().decode(errors="replace")
    except Exception as e: return -1, repr(e)
def b64(b): return base64.b64encode(b).decode()
def pub(payload_bytes, ct=CT, **extra):
    m = {"payload": b64(payload_bytes), "contentTopic": ct}; m.update(extra)
    return call("POST", NA + "/relay/v1/auto/messages", m)
def poll(node, ct=CT):
    return call("GET", node + "/relay/v1/auto/messages/" + urllib.parse.quote(ct, safe=""))
out = {}
for n in (NA, NB): call("POST", n + "/relay/v1/auto/subscriptions", [CT])
time.sleep(2)
# --- size boundary (ephemeral so the store is not filled)
lo, hi = 1000, 400000  # lo ok, hi fail
def ok(n): return pub(b"x" * n, ephemeral=True)[0] == 200
assert ok(lo) and not ok(hi)
while hi - lo > 1:
    mid = (lo + hi) // 2
    if ok(mid): lo = mid
    else: hi = mid
poll(NB); poll(NA)
out["size_boundary"] = {"max_ok_payload_bytes": lo, "first_fail_payload_bytes": hi, "max_msg_size_configured": 150 * 1024,
                        "error_at_first_fail": pub(b"x" * hi, ephemeral=True)}
# does the receiver actually get the max-size message?
time.sleep(0.5); poll(NB)
st, _ = pub(b"y" * lo, ephemeral=True); time.sleep(2); st2, body = poll(NB)
out["size_boundary"]["receiver_got_max_ok_message"] = (st, st2, len(body))
st, body = pub(b"z" * 2_000_000, ephemeral=True)
out["size_2MB"] = (st, body[:300])
# --- malformed inputs
cases = {
 "bad_base64": lambda: call("POST", NA + "/relay/v1/auto/messages", {"payload": "!!!not base64!!!", "contentTopic": CT}),
 "empty_payload": lambda: call("POST", NA + "/relay/v1/auto/messages", {"payload": "", "contentTopic": CT}),
 "missing_payload": lambda: call("POST", NA + "/relay/v1/auto/messages", {"contentTopic": CT}),
 "missing_contentTopic": lambda: call("POST", NA + "/relay/v1/auto/messages", {"payload": b64(b"hi")}),
 "empty_body": lambda: call("POST", NA + "/relay/v1/auto/messages", raw=b""),
 "invalid_json": lambda: call("POST", NA + "/relay/v1/auto/messages", raw=b"{nope"),
 "ct_no_slashes": lambda: pub(b"hi", ct="foo"),
 "ct_3_parts": lambda: pub(b"hi", ct="/a/1/b"),
 "ct_5_parts_generation0": lambda: pub(b"hi", ct="/0/agentnet/1/spike-a1-limits/proto"),
 "ct_generation1": lambda: pub(b"hi", ct="/1/agentnet/1/spike-a1-limits/proto"),
 "ct_unicode_name": lambda: pub(b"hi", ct="/agentnet/1/café-☃/proto"),
 "ct_empty_string": lambda: pub(b"hi", ct=""),
 "ct_unknown_encoding": lambda: pub(b"hi", ct="/agentnet/1/x/weirdenc"),
 "ct_very_long_1000": lambda: pub(b"hi", ct="/agentnet/1/" + "a" * 1000 + "/proto"),
 "version_1": lambda: pub(b"hi", version=1, ephemeral=True),
 "meta_big_base64": lambda: pub(b"hi", meta=b64(b"m" * 2000), ephemeral=True),
 "timestamp_60s_past": lambda: pub(b"old", timestamp=time.time_ns() - 60 * 10**9),
 "timestamp_60s_future": lambda: pub(b"fut", timestamp=time.time_ns() + 60 * 10**9),
 "timestamp_negative": lambda: pub(b"neg", timestamp=-5),
 "unknown_field": lambda: call("POST", NA + "/relay/v1/auto/messages", {"payload": b64(b"hi"), "contentTopic": CT, "bogus": 1}),
 "subscribe_bad_ct": lambda: call("POST", NA + "/relay/v1/auto/subscriptions", ["not-a-topic"]),
 "poll_unsubscribed_ct": lambda: poll(NA, "/agentnet/1/never-subscribed/proto"),
 "publish_unsubscribed_ct_valid": lambda: pub(b"hi", ct="/agentnet/1/never-subscribed/proto", ephemeral=True),
}
out["cases"] = {}
for k, f in cases.items():
    st, body = f(); out["cases"][k] = {"http": st, "body": body[:400]}
time.sleep(2)
# which of the old/future-timestamp messages got stored by R1?
for k in ("timestamp_60s_past", "timestamp_60s_future"): pass
st, body = call("GET", R1 + "/store/v3/messages?contentTopics=" + urllib.parse.quote(CT, safe="") + "&includeData=true&pageSize=100")
stored = []
try:
    for m in json.loads(body)["messages"]: stored.append(base64.b64decode(m["message"]["payload"]).decode(errors="replace")[:20])
except Exception as e: stored = repr(e)
out["stored_payloads_on_R1_for_limits_topic"] = stored
st, body = poll(NB); out["NB_received_after_cases"] = [(base64.b64decode(m["payload"])[:12].decode(errors="replace")) for m in json.loads(body)] if st == 200 else (st, body)
# --- static pubsub variants
PS = "/waku/2/rs/66/0"
sv = {}
sv["subscribe_static_ok"] = [call("POST", n + "/relay/v1/subscriptions", [PS]) for n in (NA, NB)]
sv["subscribe_wrong_cluster"] = call("POST", NA + "/relay/v1/subscriptions", ["/waku/2/rs/1/0"])
sv["subscribe_bad_format"] = call("POST", NA + "/relay/v1/subscriptions", ["/waku/2/default-waku/proto"])
sv["subscribe_shard5"] = call("POST", NA + "/relay/v1/subscriptions", ["/waku/2/rs/66/5"])
time.sleep(1)
sv["publish_static"] = call("POST", NA + "/relay/v1/messages/" + urllib.parse.quote(PS, safe=""), {"payload": b64(b"static-pubsub"), "contentTopic": "/agentnet/1/static/proto", "ephemeral": True})
sv["publish_static_unsubscribed_shard"] = call("POST", NA + "/relay/v1/messages/" + urllib.parse.quote("/waku/2/rs/66/7", safe=""), {"payload": b64(b"x"), "contentTopic": "/agentnet/1/static/proto"})
time.sleep(1)
sv["NB_poll_static"] = call("GET", NB + "/relay/v1/messages/" + urllib.parse.quote(PS, safe=""))
out["static_pubsub"] = sv
json.dump(out, open(sys.argv[1], "w"), indent=1)
print(json.dumps(out, indent=1))
