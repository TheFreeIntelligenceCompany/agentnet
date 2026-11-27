#!/usr/bin/env python3
# mcp_send.py BIN DATADIR RECIPIENT BODY : MCP stdio client, initialize + tools/call send_message; prints JSON with elapsed_ms.
import json, subprocess, sys, time
bin_, d, rcpt, body = sys.argv[1:5]
p = subprocess.Popen([bin_, "--data-dir", d, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
def rpc(o): p.stdin.write(json.dumps(o) + "\n"); p.stdin.flush()
def rd(i):
    while True:
        m = json.loads(p.stdout.readline())
        if m.get("id") == i: return m
rpc({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}})
init = rd(1); rpc({"jsonrpc":"2.0","method":"notifications/initialized"})
t=time.time(); rpc({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_message","arguments":{"recipient":rcpt,"body":body}}})
r = rd(2); el = int((time.time()-t)*1000); p.terminate()
print(json.dumps({"tool":"send_message","elapsed_ms":el,"is_error":r["result"].get("isError"),"protocol":init["result"].get("protocolVersion"),"result":r["result"].get("structuredContent")}))
