#!/usr/bin/env python3
"""Loopback shim: the instabox HTTPS edge strips 'Upgrade: tailscale-control-protocol' but passes WebSocket upgrades.
Headscale (tailscale controlhttpserver) also accepts the ts2021 Noise handshake over WebSocket. This shim listens on
127.0.0.1:PORT, turns a client's /ts2021 HTTP upgrade into a WebSocket to the edge and pipes bytes; other requests
(GET /key etc.) are proxied to the edge over HTTPS. usage: tsshim.py EDGE_HOST PORT"""
import asyncio, sys, urllib.parse, http.client
import websockets
EDGE, PORT = sys.argv[1], int(sys.argv[2])

async def handle(r, w):
    try:
        head = await r.readuntil(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        hdrs = {}
        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1); hdrs[k.strip().lower()] = v.strip()
        if path.startswith("/ts2021") and "upgrade" in hdrs:
            hs = hdrs.get("x-tailscale-handshake", "")
            url = f"wss://{EDGE}/ts2021?X-Tailscale-Handshake={urllib.parse.quote(hs, safe='')}"
            ws = await websockets.connect(url, subprotocols=["tailscale-control-protocol"], max_size=None, compression=None, open_timeout=30, ping_interval=None)
            w.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\n")
            await w.drain()
            async def c2s():
                try:
                    while True:
                        d = await r.read(65536)
                        if not d: break
                        await ws.send(d)
                finally:
                    await ws.close()
            async def s2c():
                try:
                    async for m in ws:
                        w.write(m if isinstance(m, bytes) else m.encode()); await w.drain()
                finally:
                    w.close()
            await asyncio.gather(c2s(), s2c(), return_exceptions=True)
        else:
            clen = int(hdrs.get("content-length", "0")); body = await r.readexactly(clen) if clen else None
            c = http.client.HTTPSConnection(EDGE, timeout=30)
            c.request(method, path, body=body, headers={k: v for k, v in hdrs.items() if k in ("content-type", "accept", "user-agent")})
            resp = c.getresponse(); data = resp.read()
            w.write(f"HTTP/1.1 {resp.status} {resp.reason}\r\nContent-Type: {resp.getheader('content-type','application/octet-stream')}\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
            await w.drain(); w.close()
    except Exception as e:
        print("shim error", repr(e), file=sys.stderr, flush=True)
        try: w.close()
        except Exception: pass

async def main():
    s = await asyncio.start_server(handle, "127.0.0.1", PORT)
    async with s: await s.serve_forever()
asyncio.run(main())
