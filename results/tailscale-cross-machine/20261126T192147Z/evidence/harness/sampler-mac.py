import json, os, subprocess, sys, time, urllib.request
dur = int(sys.argv[1]); bin_ = sys.argv[2]; d = sys.argv[3]; idf = sys.argv[4]; end = time.time() + dur
while time.time() < end:
    t = time.time(); rec = {"t": round(t, 3), "iso": time.strftime("%H:%M:%S", time.gmtime(t))}
    try:
        peers = json.load(urllib.request.urlopen("http://127.0.0.1:18650/admin/v1/peers", timeout=2))
        rec["a_peers"] = [[p["multiaddr"].split("/p2p/")[0], p["connected"]] for p in peers]
    except Exception as e: rec["a_peers_err"] = str(e)[:60]
    if os.path.exists(idf):
        mid = open(idf).read().strip()
        r = subprocess.run([bin_, "--json", "--data-dir", d, "status", mid], capture_output=True, text=True)
        try: s = json.loads(r.stdout); rec["msg"] = {k: s.get(k) for k in ("state", "attempts", "last_error", "delivered_at")}
        except Exception: rec["msg"] = "err"
    print(json.dumps(rec), flush=True)
    time.sleep(max(0, 1 - (time.time() - t)))
