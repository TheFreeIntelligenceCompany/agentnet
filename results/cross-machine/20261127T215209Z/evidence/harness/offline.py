#!/usr/bin/env python3
# offline.py BIN DATADIR RECIPIENT TAG : send 5 messages, print ids (JSON list)
import json, subprocess, sys
bin_, d, rcpt, tag = sys.argv[1:5]
ids = [json.loads(subprocess.run([bin_, "--json", "--data-dir", d, "send", rcpt, f"{tag} {i}"], capture_output=True, text=True, check=True).stdout)["message_id"] for i in range(1, 6)]
print(json.dumps(ids))
