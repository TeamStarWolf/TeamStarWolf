#!/usr/bin/env python3
"""Consistency check for research/data/library.json.

Since the export sources are not available on CI (and the file is now
hand-maintained), the summary fields can drift from the assets they
describe. This asserts they agree:

  - counts[type]     == number of assets of that type
  - vendors[v]       == number of assets whose vendor is v   (exact key set)
  - tactic_counts[t] == number of assets carrying tactic t   (exact key set)
  - asset "id" values are unique

Exit 1 and print every discrepancy on failure; exit 0 when clean.
Usage: check_library_consistency.py [path] | --self-test
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[2] / "research" / "data" / "library.json"


def check(doc: dict) -> list[str]:
    assets = doc.get("assets", [])
    errs: list[str] = []

    id_counts = Counter(a.get("id") for a in assets)
    for k, n in id_counts.items():
        if n > 1:
            errs.append(f"duplicate id: {k} (x{n})")

    def compare(label: str, stored: dict, actual: Counter) -> None:
        for key in sorted(set(stored) | set(actual), key=lambda x: str(x)):
            s, a = stored.get(key, 0), actual.get(key, 0)
            if s != a:
                errs.append(f"{label}[{key!r}]: stored {s} != actual {a}")

    compare("counts", doc.get("counts", {}), Counter(a.get("type") for a in assets))
    compare("vendors", doc.get("vendors", {}), Counter(a.get("vendor") for a in assets))

    actual_tactic: Counter = Counter()
    for a in assets:
        for t in a.get("attack_tactics", []):
            actual_tactic[t] += 1
    compare("tactic_counts", doc.get("tactic_counts", {}), actual_tactic)

    return errs


def _self_test() -> int:
    base_asset = {"id": "t:1", "type": "tool", "vendor": "@a", "attack_tactics": ["x"]}
    good = {"counts": {"tool": 1}, "vendors": {"@a": 1}, "tactic_counts": {"x": 1}, "assets": [dict(base_asset)]}
    assert check(good) == [], check(good)

    bad_count = {"counts": {"tool": 2}, "vendors": {"@a": 1}, "tactic_counts": {"x": 1}, "assets": [dict(base_asset)]}
    assert any("counts['tool']" in e for e in check(bad_count)), check(bad_count)

    bad_vendor = {"counts": {"tool": 1}, "vendors": {"@a": 2}, "tactic_counts": {"x": 1}, "assets": [dict(base_asset)]}
    assert any("vendors['@a']" in e for e in check(bad_vendor)), check(bad_vendor)

    bad_tactic = {"counts": {"tool": 1}, "vendors": {"@a": 1}, "tactic_counts": {"x": 2}, "assets": [dict(base_asset)]}
    assert any("tactic_counts['x']" in e for e in check(bad_tactic)), check(bad_tactic)

    dup = {"counts": {"tool": 2}, "vendors": {"@a": 2}, "tactic_counts": {},
           "assets": [{"id": "t:1", "type": "tool", "vendor": "@a", "attack_tactics": []},
                      {"id": "t:1", "type": "tool", "vendor": "@a", "attack_tactics": []}]}
    assert any("duplicate id" in e for e in check(dup)), check(dup)

    print("check_library_consistency self-test: 5 of 5 cases pass")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return _self_test()
    path = Path(argv[1]) if len(argv) > 1 and not argv[1].startswith("-") else DEFAULT
    doc = json.loads(path.read_text(encoding="utf-8"))
    errs = check(doc)
    if errs:
        print(f"FAIL library consistency ({len(errs)} issue(s)) in {path}:", file=sys.stderr)
        for e in errs:
            print("  " + e, file=sys.stderr)
        return 1
    print(f"OK library consistency: {len(doc.get('assets', []))} assets in {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
