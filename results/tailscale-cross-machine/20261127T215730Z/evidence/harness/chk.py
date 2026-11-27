#!/usr/bin/env python3
# chk.py FILE ID RESULT "text" [json-detail] : append one record with the real UTC event time to checks.jsonl
import json, sys, time
f, i, r, t = sys.argv[1:5]
d = json.loads(sys.argv[5]) if len(sys.argv) > 5 else {}
now = time.time()
rec = {"t": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % (now * 1000 % 1000), "id": i, "result": r, "text": t, **d}
open(f, "a").write(json.dumps(rec) + "\n")
print(json.dumps(rec))
