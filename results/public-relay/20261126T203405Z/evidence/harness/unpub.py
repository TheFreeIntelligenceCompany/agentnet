#!/usr/bin/env python3
# unpub.py BIN DATADIR RECIPIENT : after the port was unpublished, sample node A's peer state every 5 s for up to 150 s; send one message at +5 s and report its state at the end.
import json, subprocess, sys, time, urllib.request
bin_, d, rcpt = sys.argv[1:4]
def peers():
    try: return [p["connected"] for p in json.loads(urllib.request.urlopen("http://127.0.0.1:18650/admin/v1/peers", timeout=5).read())]
    except Exception as e: return "err:" + type(e).__name__
t0 = time.time(); sent = None
while time.time() - t0 < 150:
    if sent is None and time.time() - t0 > 5:
        sent = json.loads(subprocess.run([bin_, "--json", "--data-dir", d, "send", rcpt, "synthetic message after unpublish"], capture_output=True, text=True).stdout)["message_id"]
        print(f"+{time.time()-t0:5.1f}s sent {sent}", flush=True)
    print(f"+{time.time()-t0:5.1f}s node-A peers: {peers()}", flush=True)
    time.sleep(5)
st = json.loads(subprocess.run([bin_, "--json", "--data-dir", d, "status", sent], capture_output=True, text=True).stdout)
print("final", json.dumps({k: st.get(k) for k in ("state", "attempts", "last_error", "delivered_at")}))
