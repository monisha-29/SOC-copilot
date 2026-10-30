"""Offline test of the input regex filter on any jsonl file (no model needed).

    python check_filter.py data/heldout_attacks.jsonl      # attacks: want CAUGHT
    python check_filter.py data/benign_hard.jsonl --benign # benign: want ok (CAUGHT = false positive)
"""
import argparse
import collections
import json
import sys

from soc.guardrails import detect_injection

sys.stdout.reconfigure(encoding="utf-8")   # non-English test text must print on Windows consoles
ap = argparse.ArgumentParser()
ap.add_argument("path")
ap.add_argument("--benign", action="store_true")
a = ap.parse_args()
rows = [json.loads(l) for l in open(a.path, encoding="utf-8") if l.strip()]
by = collections.defaultdict(lambda: [0, 0])
for r in rows:
    hit = bool(detect_injection(r["text"]))
    cat = r.get("category", "benign")
    by[cat][0] += hit
    by[cat][1] += 1
    flag = ("FALSE POSITIVE" if hit else "ok") if a.benign else ("caught" if hit else "MISSED")
    print(f"{r['id']:<6}{cat:<22}{flag:<15}{r['text'][:70]!r}")
tot = sum(v[0] for v in by.values())
n = sum(v[1] for v in by.values())
print(f"\n{'flagged' if a.benign else 'caught'}: {tot}/{n}")
for c, (h, t) in by.items():
    print(f"  {c:<22}{h}/{t}")
