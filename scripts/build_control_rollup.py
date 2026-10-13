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
Explorer, NIST 800-53 r5, mapped against ATT&CK v16.1). Direct controls are carried
forward through data/attack/superseded_by.jsonl: the CTID mapping is keyed on ids that
ATT&CK has since revoked (T1562.001, T1070.001, ...) in favour of live successors
recorded in superseded_by.jsonl, so a live successor's direct set = its own CTID edges UNION the edges of
every revoked predecessor whose chain resolves to it (T1685 <- T1562, T1562.001,
T1562.006). The revoked rows keep their own edges. Carried controls are recorded per
predecessor in `nist_800_53_controls_via_revoked` ({predecessor_id: [controls]},
present only when non-empty) so the CTID source is never presented as mapping the new
id directly.

This script owns `nist_800_53_controls`, `nist_control_count`,
`nist_800_53_controls_via_revoked`, `nist_800_53_controls_rolled` and
`nist_control_count_rolled`.

Default: rewrite technique_profiles.jsonl in place (formatting/CRLF preserved).
--check: recompute and exit 1 if any of those committed fields drift.
"""
from __future__ import annotations
import json, os, re, sys

from attack_ids import AttackIds

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
    """technique_id -> set(controls) after the superseded_by carry-forward, plus the
    provenance {successor_id: {predecessor_id: [controls]}}."""
    m, rekeyed = {}, {}
    with open(C2T, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            t, c = r.get("attack_technique"), r.get("nist_control")
            if t and c:
                m.setdefault(t, set()).add(c)
                # rows build_ctid_edges.py re-keyed from a stale source id
                for old in r.get("via_revoked") or []:
                    rekeyed.setdefault(t, {}).setdefault(old, set()).add(c)
    merged, prov = AttackIds().carry_forward(m)
    for t, by_old in rekeyed.items():
        for old, cs in by_old.items():
            by_pred = prov.setdefault(t, {})
            by_pred[old] = sorted(set(by_pred.get(old, [])) | cs)
    prov = {t: {old: sorted(cs, key=_ctrl_key) for old, cs in sorted(by_old.items())}
            for t, by_old in prov.items()}
    return merged, prov


def _with_via_revoked(r, via):
    """Place nist_800_53_controls_via_revoked right after nist_control_count (or drop it)."""
    out = {}
    for k, v in r.items():
        if k == "nist_800_53_controls_via_revoked":
            continue
        out[k] = v
        if k == "nist_control_count" and via:
            out["nist_800_53_controls_via_revoked"] = via
    return out


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
    direct, prov = _direct_controls()
    rolled = compute(profiles, direct)

    def want_direct(r):
        # keep the committed order when the set is unchanged (lexical order otherwise)
        want = direct.get(r["technique_id"], set())
        have = r.get("nist_800_53_controls") or []
        return have if (set(have) == want and len(have) == len(want)) else sorted(want)

    check = "--check" in sys.argv
    if check:
        drift = []
        for r in profiles:
            t = r["technique_id"]
            d = sorted(direct.get(t, set()))
            if (sorted(r.get("nist_800_53_controls") or []) != d
                    or r.get("nist_control_count") != len(d)
                    or (r.get("nist_800_53_controls_via_revoked") or {}) != prov.get(t, {})
                    or r.get("nist_800_53_controls_rolled") != rolled[t]
                    or r.get("nist_control_count_rolled") != len(rolled[t])):
                drift.append(t)
        if drift:
            print(f"CONTROL-ROLLUP DRIFT on {len(drift)} profiles "
                  f"(run scripts/build_control_rollup.py): {', '.join(drift[:15])}"
                  + (" ..." if len(drift) > 15 else ""))
            sys.exit(1)
        print(f"OK: control rollup consistent for all {len(profiles)} profiles "
              f"({len(prov)} carry controls forward from revoked predecessors)")
        return

    changed_direct = []
    for i, r in enumerate(profiles):
        t = r["technique_id"]
        d = want_direct(r)
        if d != (r.get("nist_800_53_controls") or []):
            changed_direct.append(t)
        r["nist_800_53_controls"] = d
        r["nist_control_count"] = len(d)
        r["nist_800_53_controls_rolled"] = rolled[t]
        r["nist_control_count_rolled"] = len(rolled[t])
        profiles[i] = _with_via_revoked(r, prov.get(t))

    out = nl.join(json.dumps(r, ensure_ascii=False) for r in profiles) + nl
    with open(PROFILES, "w", encoding="utf-8", newline="") as f:
        f.write(out)

    parents = [r for r in profiles if not r.get("is_subtechnique")]
    gained = [r for r in parents
              if r["nist_control_count_rolled"] > len(r.get("nist_800_53_controls") or [])]
    print(f"wrote {PROFILES}")
    print(f"  profiles stamped with rolled controls: {len(profiles)}")
    print(f"  parent techniques whose rolled set exceeds direct: {len(gained)}")
    print(f"  profiles whose direct control set changed: {len(changed_direct)}"
          + (f" ({', '.join(changed_direct[:12])}{' ...' if len(changed_direct) > 12 else ''})"
             if changed_direct else ""))
    print(f"  live successors carrying controls from revoked predecessors: {len(prov)}")


if __name__ == "__main__":
    main()
