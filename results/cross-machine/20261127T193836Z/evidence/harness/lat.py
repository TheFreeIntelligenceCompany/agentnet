#!/usr/bin/env python3
# lat.py BIN DATADIR RECIPIENT N TAG : send N messages sequentially, wait for each authenticated delivery receipt (poll status every 100 ms),
# latency = delivered_at - created_at (both from the sender's clock). Prints one JSON object.
import json, subprocess, sys, time
bin_, d, rcpt, n, tag = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
def an(*a):
    return json.loads(subprocess.run([bin_, "--json", "--data-dir", d, *a], capture_output=True, text=True, check=True).stdout)
samples, ids = [], []
for i in range(n):
    m = an("send", rcpt, f"{tag} {i}")
    ids.append(m["message_id"]); t0 = time.time()
    while True:
        s = an("status", m["message_id"])
        if s["state"] == "delivered":
            samples.append(s["delivered_at"] - s["created_at"]); break
        if time.time() - t0 > 120: samples.append(None); break
        time.sleep(0.1)
ok = sorted(x for x in samples if x is not None)
def pct(p): return ok[min(len(ok) - 1, int(round(p / 100 * len(ok) + 0.4999) - 1))] if ok else None
print(json.dumps({"tag": tag, "sent": n, "delivered": len(ok), "undelivered": n - len(ok), "p50": pct(50), "p95": pct(95), "p99": pct(99),
                  "min": ok[0] if ok else None, "max": ok[-1] if ok else None, "samples_ms": samples, "message_ids": ids}))
