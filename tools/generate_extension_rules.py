#!/usr/bin/env python3
"""Generate OmniShield X browser-extension declarativeNetRequest rules
from the SAME bundled feeds the Android APK ships (unified intelligence core).
Output: two static rulesets, each within Chrome's per-extension limits."""
import json, re, sys

SRC = 'app/src/main/assets/core_lite_ads.txt'
OUT = ['extension/rules-1.json', 'extension/rules-2.json']
PER_FILE = 25_000
dom_re = re.compile(r'^\|\|([a-z0-9.-]+\.[a-z]{2,})\^')

rules, seen = [], set()
with open(SRC, encoding='utf-8') as fh:
    for line in fh:
        line = line.strip()
        if not line or line[0] in '!#':
            continue
        m = dom_re.match(line)
        if not m:
            continue
        d = m.group(1)
        if d in seen:
            continue
        seen.add(d)
        rules.append({
            "id": len(rules) + 1,
            "priority": 1,
            "action": {"type": "block"},
            "condition": {"requestDomains": [d], "domainType": "thirdParty"}
        })
        if len(rules) >= PER_FILE * len(OUT):
            break

import os
os.makedirs('extension', exist_ok=True)
total = 0
for i, out in enumerate(OUT):
    chunk = rules[i*PER_FILE:(i+1)*PER_FILE]
    # re-number per file
    for j, r in enumerate(chunk):
        r['id'] = j + 1
    with open(out, 'w', encoding='utf-8') as fh:
        json.dump(chunk, fh, separators=(',', ':'))
    total += len(chunk)
    print(f"{out}: {len(chunk)} rules")
print(f"TOTAL: {total} block rules from {SRC}")
