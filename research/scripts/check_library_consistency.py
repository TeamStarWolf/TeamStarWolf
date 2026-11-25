#!/usr/bin/env python3
"""Consistency check for research/data/library.json.

Since the export sources are not available on CI (and the file is now
hand-maintained), the summary fields can drift from the assets they
describe. This asserts they agree:

  - counts[type]     == number of assets of that type
  - vendors[v]       == number of assets whose vendor is v   (exact key set)
  - tactic_counts[t] == number of assets carrying tactic t   (exact key set)
  - every asset "id" is non-empty and unique
  - no stored counts/vendors/tactic_counts key has value 0 (exact key set)
  - every asset's category is listed under categories[type]

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

    # every asset has a non-empty id (a single id-less asset would otherwise pass:
    # the duplicate check below only fires on two or more, as a repeated None).
    for i, a in enumerate(assets):
        if not a.get("id"):
            errs.append(f"asset #{i} (type={a.get('type')!r}, title={a.get('title')!r}) has a missing/empty id")
    id_counts = Counter(a.get("id") for a in assets if a.get("id"))
    for k, n in id_counts.items():
        if n > 1:
            errs.append(f"duplicate id: {k} (x{n})")

    def compare(label: str, stored: dict, actual: Counter) -> None:
        # exact key set: a stored key with value 0 is never legitimate (every key
        # must map to at least one asset), and 0 == 0 would slip past the compare.
        for key, val in stored.items():
            if val == 0:
                errs.append(f"{label}[{key!r}]: stored as 0 (exact key set has no zero-count keys)")
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

    # every asset's category is listed under categories[type]
    categories = doc.get("categories", {})
    for i, a in enumerate(assets):
        allowed = categories.get(a.get("type"), [])
        if a.get("category") not in allowed:
            errs.append(f"categories[{a.get('type')!r}] does not list {a.get('category')!r} "
                        f"(asset {a.get('id') or '#' + str(i)})")

    return errs


def _self_test() -> int:
    base_asset = {"id": "t:1", "type": "tool", "vendor": "@a", "attack_tactics": ["x"], "category": "C"}
    cats = {"tool": ["C"]}
    good = {"counts": {"tool": 1}, "vendors": {"@a": 1}, "tactic_counts": {"x": 1},
            "categories": cats, "assets": [dict(base_asset)]}
    assert check(good) == [], check(good)

    bad_count = {**good, "counts": {"tool": 2}}
    assert any("counts['tool']" in e for e in check(bad_count)), check(bad_count)

    bad_vendor = {**good, "vendors": {"@a": 2}}
    assert any("vendors['@a']" in e for e in check(bad_vendor)), check(bad_vendor)

    bad_tactic = {**good, "tactic_counts": {"x": 2}}
    assert any("tactic_counts['x']" in e for e in check(bad_tactic)), check(bad_tactic)

    dup = {"counts": {"tool": 2}, "vendors": {"@a": 2}, "tactic_counts": {}, "categories": cats,
           "assets": [{"id": "t:1", "type": "tool", "vendor": "@a", "attack_tactics": [], "category": "C"},
                      {"id": "t:1", "type": "tool", "vendor": "@a", "attack_tactics": [], "category": "C"}]}
    assert any("duplicate id" in e for e in check(dup)), check(dup)

    # a single id-less asset is caught (and not mislabeled as a duplicate None)
    missing_id = {**good, "assets": [{"type": "tool", "vendor": "@a", "attack_tactics": ["x"], "category": "C"}]}
    e_mid = check(missing_id)
    assert any("missing/empty id" in x for x in e_mid) and not any("duplicate" in x for x in e_mid), e_mid

    # a stored key with value 0 is caught (exact key set)
    zero_key = {**good, "vendors": {"@a": 1, "@b": 0}}
    assert any("vendors['@b']: stored as 0" in x for x in check(zero_key)), check(zero_key)

    # an asset whose category is not listed for its type is caught
    bad_cat = {**good, "assets": [{**base_asset, "category": "Z"}]}
    assert any("categories['tool'] does not list 'Z'" in x for x in check(bad_cat)), check(bad_cat)

    print("check_library_consistency self-test: 8 of 8 cases pass")
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
