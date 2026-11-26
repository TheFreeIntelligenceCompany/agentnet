import json, subprocess, sys, time, urllib.request
dur = int(sys.argv[1]); end = time.time() + dur
pid = subprocess.run(["docker","inspect","-f","{{.State.Pid}}","an-r1"],capture_output=True,text=True).stdout.strip()
while time.time() < end:
    t = time.time(); rec = {"t": round(t, 3), "iso": time.strftime("%H:%M:%S", time.gmtime(t))}
    try:
        peers = json.load(urllib.request.urlopen("http://127.0.0.1:18640/admin/v1/peers", timeout=2))
        rec["r_peers"] = [[p["multiaddr"].split("/p2p/")[0], p["connected"]] for p in peers]
    except Exception as e: rec["r_peers_err"] = str(e)[:60]
    ss = subprocess.run(["nsenter","-t",pid,"-n","ss","-tnoH","sport = :60000"],capture_output=True,text=True).stdout.strip().splitlines()
    rec["r_sockets"] = [" ".join(l.split()) for l in ss]
    print(json.dumps(rec), flush=True)
    time.sleep(max(0, 1 - (time.time() - t)))
