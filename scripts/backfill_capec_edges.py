#!/usr/bin/env python3
"""Populate the `capec` edge on every technique profile from the CAPEC dataset.

data/weaknesses/capec.jsonl is the source of truth for the CAPEC<->ATT&CK
relationship: each CAPEC pattern lists the techniques it maps to in
`attack_techniques`. data/attack/technique_profiles.jsonl advertises a `capec`
field per technique but ships it empty in every row (a generator omission —
audit / Library Enhancement Roadmap Tier 1.5). This script inverts the CAPEC
mapping (technique_id -> sorted CAPEC ids) and writes it into each profile.

CAPEC is keyed on whatever ATT&CK id it was authored against, so a pattern mapped to
an id that ATT&CK later revoked (T1562.002, T1574.002, ...) is carried forward to the
live successor through data/attack/superseded_by.jsonl (T1562.002 -> T1685.001); the
revoked profile keeps its own edge. The carried CAPEC ids are recorded per
predecessor in `capec_via_revoked` ({predecessor_id: [CAPEC ids]}, present only when
non-empty), so a reader can tell a CAPEC mapping of the new id from an inherited one.

Default: rewrite technique_profiles.jsonl in place (only rows that gain edges
change; formatting and line endings are preserved for a clean diff).
--check:  recompute and fail (exit 1) if any profile's `capec` diverges from the
          value derived from capec.jsonl. CI runs this to guard against drift.
"""
from __future__ import annotations
import json, os, sys

from attack_ids import AttackIds

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(ROOT, "data", "attack", "technique_profiles.jsonl")
CAPEC = os.path.join(ROOT, "data", "weaknesses", "capec.jsonl")


def _capec_sort_key(capec_id: str):
    # "CAPEC-100" -> 100 so ids sort numerically, not lexically.
    try:
        return (0, int(capec_id.split("-", 1)[1]))
    except (IndexError, ValueError):
        return (1, capec_id)


def derive_edges():
    """(technique_id -> sorted CAPEC ids after the superseded_by carry-forward,
    successor_id -> {predecessor_id: [CAPEC ids]} provenance, raw technique ids)."""
    edges: dict[str, set] = {}
    with open(CAPEC, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            cid = row.get("capec_id")
            for tid in row.get("attack_techniques") or []:
                if isinstance(tid, str) and tid.startswith("T") and cid:
                    edges.setdefault(tid, set()).add(cid)
    merged, prov = AttackIds().carry_forward(edges)
    prov = {t: {old: sorted(c, key=_capec_sort_key) for old, c in sorted(by_old.items())}
            for t, by_old in prov.items()}
    return ({t: sorted(c, key=_capec_sort_key) for t, c in merged.items()}, prov, set(edges))


def _with_via_revoked(r, via):
    """Place capec_via_revoked right after capec (or drop it when empty)."""
    out = {}
    for k, v in r.items():
        if k == "capec_via_revoked":
            continue
        out[k] = v
        if k == "capec" and via:
            out["capec_via_revoked"] = via
    return out


def _read_profiles_raw():
    with open(PROFILES, "rb") as f:
        raw = f.read()
    nl = "\r\n" if b"\r\n" in raw else "\n"
    lines = [ln for ln in raw.decode("utf-8").replace("\r\n", "\n").split("\n") if ln.strip()]
    return [json.loads(ln) for ln in lines], nl


def main():
    edges, prov, raw_ids = derive_edges()
    rows, nl = _read_profiles_raw()
    profile_ids = {r["technique_id"] for r in rows}
    ids = AttackIds()
    # CAPEC-referenced techniques that are neither enterprise profiles nor resolvable
    # through superseded_by (data-hygiene signal, e.g. a Mobile-domain id).
    orphans = sorted(t for t in raw_ids - profile_ids if ids.resolve(t) is None)

    check = "--check" in sys.argv
    drift = []
    changed = 0
    for i, r in enumerate(rows):
        t = r["technique_id"]
        want = edges.get(t, [])
        via = prov.get(t, {})
        if r.get("capec", []) != want or (r.get("capec_via_revoked") or {}) != via:
            if check:
                drift.append(t)
            else:
                r["capec"] = want
                rows[i] = _with_via_revoked(r, via)
                changed += 1

    if check:
        if drift:
            print(f"CAPEC edge drift on {len(drift)} technique profiles "
                  f"(run scripts/backfill_capec_edges.py to fix):")
            for t in drift[:20]:
                print("  -", t)
            if len(drift) > 20:
                print(f"  ... and {len(drift) - 20} more")
            sys.exit(1)
        print(f"OK: all {len(rows)} technique profiles carry the CAPEC edges "
              f"derived from capec.jsonl ({sum(1 for r in rows if r.get('capec'))} populated)")
        return

    out = nl.join(json.dumps(r, ensure_ascii=False) for r in rows) + nl
    with open(PROFILES, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    populated = sum(1 for r in rows if r.get("capec"))
    print(f"wrote {PROFILES}")
    print(f"  profiles updated: {changed}")
    print(f"  profiles now carrying CAPEC edges: {populated} (of {len(rows)})")
    print(f"  distinct techniques mapped in capec.jsonl: {len(raw_ids)}")
    print(f"  live successors carrying CAPEC from revoked predecessors: "
          f"{sum(1 for t in prov if t in profile_ids)}")
    if orphans:
        print(f"  NOTE: {len(orphans)} CAPEC-referenced techniques are not enterprise "
              f"techniques (other ATT&CK domain?): {', '.join(orphans[:10])}"
              + (" ..." if len(orphans) > 10 else ""))


if __name__ == "__main__":
    main()
