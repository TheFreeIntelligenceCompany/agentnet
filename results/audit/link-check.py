#!/usr/bin/env python3
"""Tiny relative-link checker for README.md and docs/**/*.md. Run: python3 -I results/audit/link-check.py
Checks that every relative markdown link target exists (fragments and external URLs are ignored; code spans and
fenced code blocks are skipped). Exit status is the number of broken links."""
import os, re, sys, glob
root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
files = [os.path.join(root, 'README.md')] + sorted(glob.glob(os.path.join(root, 'docs', '**', '*.md'), recursive=True))
link = re.compile(r'(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
bad = 0; total = 0
for f in files:
    text = open(f, encoding='utf-8').read()
    text = re.sub(r'```.*?```', '', text, flags=re.S)       # fenced code
    text = re.sub(r'`[^`\n]*`', '', text)                    # inline code
    for m in link.finditer(text):
        t = m.group(1)
        if re.match(r'^[a-z][a-z0-9+.-]*:', t) or t.startswith('#'):
            continue
        total += 1
        path = t.split('#', 1)[0]
        dest = os.path.normpath(os.path.join(os.path.dirname(f), path))
        if not os.path.exists(dest):
            bad += 1
            print(f'BROKEN {os.path.relpath(f, root)}: ({t}) -> {os.path.relpath(dest, root)} does not exist')
print(f'checked {len(files)} files, {total} relative links, {bad} broken')
sys.exit(min(bad, 125))
