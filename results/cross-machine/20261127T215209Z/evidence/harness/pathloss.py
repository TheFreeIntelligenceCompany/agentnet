#!/usr/bin/env python3
# pathloss.py BIN DATADIR RECIPIENT PFPID : kill the port-forward, watch node A's peers every 3 s, send one message at +5 s, restore the tunnel at +75 s,
# then report time to Connected and to delivered. Timeline on stdout (UTC).
import json, subprocess, sys, time, urllib.request, os, signal
bin_, d, rcpt, pfpid = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
URL = "http://127.0.0.1:18655/admin/v1/peers"
def peers():
    try: return [p["connected"] for p in json.loads(urllib.request.urlopen(URL, timeout=4).read())]
    except Exception as e: return "err:" + type(e).__name__
def log(m): print(time.strftime("%H:%M:%S", time.gmtime()), m, flush=True)
os.kill(pfpid, signal.SIGTERM); t0 = time.time(); log("port-forward killed"); sent = None; restored = None; conn_t = None; deliv_t = None; mid = None
while time.time() - t0 < 330:
    el = time.time() - t0
    if mid is None and el > 5:
        mid = json.loads(subprocess.run([bin_, "--json", "--data-dir", d, "send", rcpt, "synthetic message during tunnel loss"], capture_output=True, text=True).stdout)["message_id"]; log("sent " + mid)
    if restored is None and el > 75:
        p = subprocess.Popen(["instabox", "port-forward", "agentnet-rh1", "61660:60000"], stdout=open("/private/tmp/claude-501/pf.log", "a"), stderr=subprocess.STDOUT, start_new_session=True)
        restored = time.time(); open("/private/tmp/claude-501/pf.pid", "w").write(str(p.pid)); log("port-forward restored (down %.0f s)" % (restored - t0))
    pe = peers()
    if restored and conn_t is None and pe == ["Connected"]: conn_t = time.time() - restored; log("A lists R Connected %.1f s after restore" % conn_t)
    st = json.loads(subprocess.run([bin_, "--json", "--data-dir", d, "status", mid], capture_output=True, text=True).stdout) if mid else {}
    if st.get("state") == "delivered" and restored: deliv_t = time.time() - restored; log("delivered %.1f s after restore" % deliv_t); break
    log(f"peers={pe} state={st.get('state')} err={st.get('last_error')}")
    time.sleep(3)
print(json.dumps({"down_s": round(restored - t0), "connected_after_restore_s": conn_t, "delivered_after_restore_s": deliv_t}))
