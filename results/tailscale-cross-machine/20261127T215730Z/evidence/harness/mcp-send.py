#!/usr/bin/env python3
# mcp-send.py BIN DATADIR RECIPIENT BODY : MCP stdio client (thin client of the running daemon): initialize, tools/list, call send_message.
import json, subprocess, sys, time
bin_, d, rcpt, body = sys.argv[1:5]
p = subprocess.Popen([bin_, "--data-dir", d, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
def rpc(i, m, params=None):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": m, "params": params or {}}) + "\n"); p.stdin.flush()
    while True:
        r = json.loads(p.stdout.readline())
        if r.get("id") == i: return r
init = rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "chk", "version": "0"}})
p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"); p.stdin.flush()
tools = rpc(2, "tools/list")
names = [t["name"] for t in tools["result"]["tools"]]
t0 = time.time()
r = rpc(3, "tools/call", {"name": "send_message", "arguments": {"recipient": rcpt, "body": body}})
el = round((time.time() - t0) * 1000)
res = r["result"]; sc = res.get("structuredContent") or json.loads(res["content"][0]["text"])
print(json.dumps({"tools": names, "elapsed_ms": el, "is_error": res.get("isError", False), "protocol": init["result"]["protocolVersion"],
                  "server_info": init["result"]["serverInfo"], "result": sc}, indent=1))
p.stdin.close(); p.wait(timeout=5)
