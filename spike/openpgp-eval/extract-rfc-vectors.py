#!/usr/bin/env python3
"""Extract the RFC 9580 Appendix A armored test vectors from the downloaded RFC text.
Usage: python3 -I extract-rfc-vectors.py rfc9580.txt outdir
Vectors are taken from the RFC text, never typed from memory."""
import re, sys, os
txt = open(sys.argv[1]).read().split('\n')
out = sys.argv[2]; os.makedirs(out, exist_ok=True)
def section(title_prefix):
    start = next(i for i, l in enumerate(txt) if l.startswith(title_prefix))
    return start
def armor_after(line_idx, kind):
    i = line_idx
    while not txt[i].strip().startswith('-----BEGIN PGP ' + kind):
        i += 1
    j = i
    while not txt[j].strip().startswith('-----END PGP ' + kind):
        j += 1
    return '\n'.join(l.strip() for l in txt[i:j + 1]) + '\n', (i + 1, j + 1)
spec = [
    ('A.3.  Sample Version 6 Certificate', 'PUBLIC KEY BLOCK', 'a3.pub.asc'),
    ('A.4.  Sample Version 6 Secret Key', 'PRIVATE KEY BLOCK', 'a4.sec.asc'),
    ('A.7.  Sample Inline-Signed Message', 'MESSAGE', 'a7.msg.asc'),
    ('A.8.5.  Complete X25519-AEAD-OCB Encrypted Packet Sequence', 'MESSAGE', 'a85.msg.asc'),
]
for title, kind, name in spec:
    s = section(title)
    text, (a, b) = armor_after(s, kind)
    open(os.path.join(out, name), 'w').write(text)
    print(f'{name}: RFC 9580 text lines {a}-{b} (section "{title.split("  ")[0]}")')
