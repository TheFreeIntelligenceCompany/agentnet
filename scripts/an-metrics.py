#!/usr/bin/env python3
"""Call one control-socket method of a running agentnet daemon and print the JSON result.

usage: an-metrics.py DATA_DIR [METHOD [PARAMS_JSON]]     (default METHOD: metrics)
Protocol: docs/host-integration.md (hello line with control.token, then NDJSON requests).
"""
import json, os, socket, sys

d = sys.argv[1]
method = sys.argv[2] if len(sys.argv) > 2 else "metrics"
params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
tok = open(os.path.join(d, "control.token")).read().strip()
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(os.path.join(d, "agentnet.sock"))
f = s.makefile("rwb")
f.write((json.dumps({"hello": {"token": tok, "client": "an-metrics"}}) + "\n").encode()); f.flush()
f.readline()  # hello reply
f.write((json.dumps({"id": 1, "method": method, "params": params}) + "\n").encode()); f.flush()
while True:
    line = f.readline()
    if not line:
        sys.exit("socket closed")
    msg = json.loads(line)
    if msg.get("id") == 1:
        print(json.dumps(msg.get("result", msg), indent=1, sort_keys=True))
        break
