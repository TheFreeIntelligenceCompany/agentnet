#!/usr/bin/env python3
"""Approximate licence check of `cargo tree` output against the repo's deny.toml allow list.
Not cargo-deny (not installed on this host): OR/`/` expressions pass if any alternative is allowed.
Usage: python3 -I licence-summary.py <results-dir> <feature>..."""
import re, collections, sys
R = sys.argv[1]
allow = {"MIT","Apache-2.0","Apache-2.0 WITH LLVM-exception","BSD-2-Clause","BSD-3-Clause","ISC","Unicode-3.0","Zlib","CDLA-Permissive-2.0","Unlicense","MIT-0","CC0-1.0","BSL-1.0"}
out = []
for f in sys.argv[2:]:
    pk = {}
    for line in open(f'{R}/cargo-tree-{f}.txt'):
        line = line.strip()
        if '|' not in line: continue
        p, l = line.split('|', 1)
        p = re.sub(r' \(.*\)$', '', p); l = l.replace(' (*)', '').strip()
        pk[p] = l
    def ok(expr):
        expr = expr.replace('/', ' OR ')
        for alt in re.split(r'\s+OR\s+', expr):
            alt = alt.strip().strip('()')
            if all(a.strip().strip('()') in allow for a in re.split(r'\s+AND\s+', alt)):
                return True
        return False
    bad = sorted((p, l) for p, l in pk.items() if l and not ok(l) and not p.startswith('openpgp-eval'))
    out.append(f'== feature {f}: {len(pk)} unique crates in the normal dependency graph')
    out.append('  crates whose licence expression is not satisfiable from the deny.toml allow list (approximation):')
    out += [f'    {p}  [{l}]' for p, l in bad]
    out.append('')
open(f'{R}/licence-summary.txt', 'w').write('\n'.join(out))
print('\n'.join(out))
