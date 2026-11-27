#!/usr/bin/env python3
# mcp_send.py BIN DATADIR RECIPIENT TEXT : one stateless MCP 2026-07-28 request over stdio per call: send_message, then get_message_status polled until delivered.
import json, subprocess, sys, time
bin_, d, rcpt, text = sys.argv[1:5]
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}
def call(name, args, i=1):
    req = {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args, "_meta": META}}
    t0 = time.time()
    p = subprocess.run([bin_, "--data-dir", d, "mcp"], input=json.dumps(req) + "\n", capture_output=True, text=True, timeout=60)
    r = json.loads(p.stdout.strip().splitlines()[0])
    return {"elapsed_ms": round((time.time() - t0) * 1000), "is_error": r["result"].get("isError", False), "tool": name, "result": r["result"].get("structuredContent")}
s = call("send_message", {"recipient": rcpt, "body": text, "conversation_id": "x-mcp"})
print(json.dumps(s, indent=1, sort_keys=True))
mid = s["result"]["message_id"]; t0 = time.time()
while True:
    st = call("get_message_status", {"message_id": mid}, 2)
    if st["result"]["state"] == "delivered" or time.time() - t0 > 60: break
    time.sleep(0.2)
print(json.dumps(st, indent=1, sort_keys=True))
