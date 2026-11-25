#!/usr/bin/env python3
"""Tiny UDP DNS responder (answers every A query with 10.255.255.1, AAAA with empty answer). Lets the nwaku online-monitor
(which resolves one.one.one.one every 5 s) succeed on an egress-less network without touching a real resolver."""
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 53))
while True:
    d, a = s.recvfrom(512)
    tid, flags, qd = struct.unpack(">HHH", d[:6])
    i = 12
    while d[i]: i += d[i] + 1
    qtype = struct.unpack(">H", d[i + 1:i + 3])[0]; q = d[12:i + 5]
    if qtype == 1:
        r = struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0) + q + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([10, 255, 255, 1])
    else:
        r = struct.pack(">HHHHHH", tid, 0x8180, 1, 0, 0, 0) + q
    s.sendto(r, a)
