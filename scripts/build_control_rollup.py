#!/usr/bin/env python3
"""Add the parent-rolled NIST 800-53 control set to every technique profile.

Why (mapping-consistency audit + Roadmap Tier 1.9 convergence): the library ships
only *direct* control->technique edges on a technique profile (e.g. T1021 = 14
controls), while consumers such as ATTACK-Navi roll each parent technique's
sub-technique control mappings up into the parent (T1021 = 31). Same CTID source,
two different answers. The fix is to define the rollup ONCE, here, and ship both:
keep `nist_800_53_controls` (direct) and add `nist_800_53_controls_rolled`
(direct ∪ all sub-technique direct edges) + `nist_control_count_rolled`. A
consumer then reads whichever it wants from one canonical source instead of
re-deriving, so the numbers agree by construction.

Rollup rule: a PARENT's rolled set = its own direct controls ∪ every direct
control of each of its sub-techniques. A sub-technique has no children, so its
rolled set equals its direct set.

Source of truth for edges is data/control_to_technique.jsonl (CTID Mappings
Explorer, NIST 800-53 r5). The script also asserts the profile's existing
`nist_800_53_controls` equals the direct edges derived from that file.

Default: rewrite technique_profiles.jsonl in place (formatting/CRLF preserved).
--check: recompute and exit 1 if the committed rolled fields drift.
"""
from __future__ import annotations
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES = os.path.join(ROOT, "data", "attack", "technique_profiles.jsonl")
C2T = os.path.join(ROOT, "data", "control_to_technique.jsonl")


def _ctrl_key(c: str):
    # "AC-2", "AC-10", "AC-2(1)", "SC-7(18)" -> (family, base#, enhancement#)
    m = re.match(r"^([A-Z]+)-(\d+)(?:\((\d+)\))?", c)
    if not m:
        return (c, 0, 0)
    return (m.group(1), int(m.group(2)), int(m.group(3) or 0))


def _direct_controls():
    m = {}
    with open(C2T, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            t, c = r.get("attack_technique"), r.get("nist_control")
            if t and c:
                m.setdefault(t, set()).add(c)
    return m


def _read_profiles():
    with open(PROFILES, "rb") as f:
        raw = f.read()
    nl = "\r\n" if b"\r\n" in raw else "\n"
    lines = [l for l in raw.decode("utf-8").replace("\r\n", "\n").split("\n") if l.strip()]
    return [json.loads(l) for l in lines], nl


def compute(profiles, direct):
    subs_by_parent = {}
    for r in profiles:
        pid = r.get("parent_id")
        if pid:
            subs_by_parent.setdefault(pid, []).append(r["technique_id"])
    rolled = {}
    for r in profiles:
        t = r["technique_id"]
        acc = set(direct.get(t, ()))
        for s in subs_by_parent.get(t, ()):
            acc |= direct.get(s, set())
        rolled[t] = sorted(acc, key=_ctrl_key)
    return rolled


def main():
    profiles, nl = _read_profiles()
    direct = _direct_controls()
    rolled = compute(profiles, direct)

    # Consistency: the profile's existing direct field must match the CTID edges.
    mismatches = []
    for r in profiles:
        t = r["technique_id"]
        have = set(r.get("nist_800_53_controls") or [])
        want = set(direct.get(t, set()))
        if have != want:
            mismatches.append((t, len(have), len(want)))

    check = "--check" in sys.argv
    if check:
        drift = [r["technique_id"] for r in profiles
                 if r.get("nist_800_53_controls_rolled") != rolled[r["technique_id"]]
                 or r.get("nist_control_count_rolled") != len(rolled[r["technique_id"]])]
        if drift:
            print(f"CONTROL-ROLLUP DRIFT on {len(drift)} profiles "
                  f"(run scripts/build_control_rollup.py): {', '.join(drift[:15])}"
                  + (" ..." if len(drift) > 15 else ""))
            sys.exit(1)
        if mismatches:
            print(f"WARNING: {len(mismatches)} profiles' direct nist_800_53_controls "
                  f"differ from control_to_technique.jsonl (not failing): "
                  + ", ".join(f"{t}({h}!={w})" for t, h, w in mismatches[:10]))
        print(f"OK: control rollup consistent for all {len(profiles)} profiles")
        return

    for r in profiles:
        t = r["technique_id"]
        r["nist_800_53_controls_rolled"] = rolled[t]
        r["nist_control_count_rolled"] = len(rolled[t])

    out = nl.join(json.dumps(r, ensure_ascii=False) for r in profiles) + nl
    with open(PROFILES, "w", encoding="utf-8", newline="") as f:
        f.write(out)

    parents = [r for r in profiles if not r.get("is_subtechnique")]
    gained = [r for r in parents
              if r["nist_control_count_rolled"] > len(r.get("nist_800_53_controls") or [])]
    print(f"wrote {PROFILES}")
    print(f"  profiles stamped with rolled controls: {len(profiles)}")
    print(f"  parent techniques whose rolled set exceeds direct: {len(gained)}")
    if mismatches:
        print(f"  NOTE: {len(mismatches)} profiles' direct field != control_to_technique "
              f"edges (pre-existing): {', '.join(t for t, _, _ in mismatches[:8])}")


if __name__ == "__main__":
    main()
