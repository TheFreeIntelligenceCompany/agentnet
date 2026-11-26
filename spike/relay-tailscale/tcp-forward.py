#!/usr/bin/env python3
"""Minimal TCP forwarder: listen on LISTEN_IP:PORT only, forward each connection to 127.0.0.1:TARGET_PORT.
Used because docker inside the colima VM cannot bind the host's tailnet address (README, Binding findings).
usage: tcp-forward.py LISTEN_IP LISTEN_PORT TARGET_PORT   (never listens on 0.0.0.0 / 127.0.0.1 / LAN)"""
import asyncio, sys
ip, lport, tport = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
if ip in ("0.0.0.0", "", "127.0.0.1", "::"):
    sys.exit("refusing to listen on a wildcard or loopback address")
async def pipe(r, w):
    try:
        while (d := await r.read(65536)):
            w.write(d); await w.drain()
    except Exception:
        pass
    finally:
        try: w.close()
        except Exception: pass
async def handle(cr, cw):
    try:
        ur, uw = await asyncio.open_connection("127.0.0.1", tport)
    except Exception:
        cw.close(); return
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
async def main():
    s = await asyncio.start_server(handle, ip, lport)
    print(f"forwarding {ip}:{lport} -> 127.0.0.1:{tport}", flush=True)
    async with s: await s.serve_forever()
asyncio.run(main())
