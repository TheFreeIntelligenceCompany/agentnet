#!/usr/bin/env python3
# chk.py FILE ID RESULT "detail" [evidence] : append one check line to checks.jsonl with the real event time (UTC, now)
import json, sys, time
f, i, r, d = sys.argv[1:5]; ev = sys.argv[5] if len(sys.argv) > 5 else ""
open(f, "a").write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "check": i, "result": r, "detail": d, "evidence": ev}) + "\n")
