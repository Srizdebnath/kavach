#!/usr/bin/env python3
"""Fail if a bench report (from the `bench_report` kernel test) exceeds docs/bench/budget.json.

Usage: scripts/perf-gate.py bench.json [budget.json]
"""
import json, sys

def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    rep = json.load(open(sys.argv[1]))
    bud = json.load(open(sys.argv[2] if len(sys.argv) > 2 else "docs/bench/budget.json"))
    bad = []
    print(f"kernel {rep.get('kernel')}  cpu {rep.get('cpu')}")
    for k, lim in bud["max"].items():
        v = rep.get(k)
        if v is None:
            print(f"  skip {k:<40} (not measured on this host)"); continue
        ok = v <= lim
        print(f"  {'ok  ' if ok else 'FAIL'} {k:<40} {v:>10.1f} <= {lim}")
        ok or bad.append(k)
    insns = rep.get("verified_insns", {})
    for k, lim in bud["max_verified_insns"].items():
        v = insns.get(k)
        if v is None:
            print(f"  skip insns {k}"); continue
        ok = v <= lim
        print(f"  {'ok  ' if ok else 'FAIL'} insns {k:<34} {v:>10} <= {lim}")
        ok or bad.append(k)
    if bad:
        print("perf gate FAILED:", ", ".join(bad)); return 1
    print("perf gate passed"); return 0

sys.exit(main())
