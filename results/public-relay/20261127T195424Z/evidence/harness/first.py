#!/usr/bin/env python3
# first.py BIN DATADIR RECIPIENT TEXT : send one message, wait (max 60 s) for the authenticated receipt, print the status JSON
import json, subprocess, sys, time
bin_, d, rcpt, text = sys.argv[1:5]
def an(*a): return json.loads(subprocess.run([bin_, "--json", "--data-dir", d, *a], capture_output=True, text=True, check=True).stdout)
m = an("send", rcpt, text); t0 = time.time()
while time.time() - t0 < 60:
    s = an("status", m["message_id"])
    if s["state"] == "delivered": break
    time.sleep(0.2)
print(json.dumps(s))
