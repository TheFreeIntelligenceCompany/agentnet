#!/usr/bin/env python3
# poll.py BIN DATADIR T0_EPOCH ID... : poll status every 2 s (max 20 min) until all delivered; print per-message seconds after T0
import json, subprocess, sys, time
bin_, d, t0 = sys.argv[1], sys.argv[2], float(sys.argv[3]); ids = sys.argv[4:]
st = {}
end = time.time() + 1200
while time.time() < end:
    for i in ids:
        s = json.loads(subprocess.run([bin_, "--json", "--data-dir", d, "status", i], capture_output=True, text=True).stdout or "{}")
        st[i] = s
    n = sum(1 for s in st.values() if s.get("state") == "delivered")
    print(time.strftime("%H:%M:%S", time.gmtime()), f"delivered={n}/{len(ids)}", flush=True)
    if n == len(ids): break
    time.sleep(2)
for i in ids:
    s = st[i]; print(json.dumps({"state": s.get("state"), "attempts": s.get("attempts"), "delivered_s_after_restart": (s["delivered_at"] / 1000 - t0) if s.get("delivered_at") else None}))
