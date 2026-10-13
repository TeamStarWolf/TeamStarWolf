#!/usr/bin/env python3
"""Build the two CTID-derived edge tables from their sources, deterministically.

data/control_to_technique.jsonl  (NIST 800-53 r5 -> ATT&CK, CTID Mappings Explorer)
    The CTID rows are the source and are kept as published, with three hygiene rules:
      * `tactics` is a denormalised copy of the target technique's CURRENT tactics and is
        rewritten from data/attack/technique_profiles.jsonl (v19.2: stealth /
        defense-impairment, never the retired defense-evasion).
      * a target that has no profile row but is a revoked id in superseded_by.jsonl
        (a key that was already stale in the source's own ATT&CK version, e.g.
        T1574.002 -> T1574.001) is re-keyed to its live successor, with the old id kept in
        `via_revoked`; ids revoked in v19 that keep a profile row (T1562.x, T1070.00x,
        T1656, T1672) stay as-is - the CTID mapping really is keyed on them - and are
        carried forward by the consumers (build_control_rollup.py, this script's vendor
        join).
      * one row per (nist_control, attack_technique): exact duplicates are dropped, and a
        native row wins over a re-keyed one.
    An enterprise target that is neither live nor resolvable through superseded_by
    (e.g. a Mobile id) is an error.

data/vendor_to_technique.jsonl  (fully derived)
    vendor_to_control JOIN control_to_technique, with each revoked technique's controls
    also carried forward to its live successor (T1562.001 -> T1685 ...). A row that joins
    through at least one control the technique holds only through a revoked predecessor
    lists that predecessor in `via_revoked`, whichever way the control arrived: carried
    forward from a revoked id that keeps a profile row, or re-keyed above from a stale id
    (the control_to_technique row's own `via_revoked`, e.g. T1574.002 -> T1574.001).
    data/vendor_to_control.jsonl carries one `vendor_normalized` slug per product; a
    retired alias slug (VENDOR_SLUG_ALIASES) appearing there is an error, so a product is
    never joined, scored or listed twice. coverage_type / confidence follow
    the original derivation: SI-4/CA-7 detect, RA-5/CA-2 identify, everything else
    prevent; detect+prevent -> prevent_detect, else detect > identify > prevent;
    confidence by number of joining controls (1 low, 2 medium, 3+ high).

Default: rewrite both files (CRLF, one JSON object per line, as committed).
--check:  rebuild in memory and exit 1 if either committed file differs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from attack_ids import AttackIds, read_jsonl

ROOT = Path(__file__).resolve().parent.parent
C2T = ROOT / "data" / "control_to_technique.jsonl"
V2C = ROOT / "data" / "vendor_to_control.jsonl"
V2T = ROOT / "data" / "vendor_to_technique.jsonl"

DETECT = {"SI-4", "CA-7"}
IDENTIFY = {"RA-5", "CA-2"}
V2T_SOURCE = "Derived: vendor_to_control join control_to_technique (CTID)"

# Retired vendor_normalized slugs -> the product's one slug. Each pair was the same product
# listed in CONTROLS_MAPPING.md under a company name and a product name (or an old and a
# new product name); the data now carries only the right-hand slug. Kept so a retired
# slug cannot come back (build_v2t fails on one) and so scripts/compute_coverage.py can
# record the former keys in scores/. Zscaler ZIA, ZPA and the generic "zscaler" row are
# three products and are deliberately not listed here.
VENDOR_SLUG_ALIASES = {
    "cyberark": "cyberark-pam",
    "elastic-siem": "elastic-security",
    "microsoft-defender-for-o365": "microsoft-defender-for-office-365",
    "qualys": "qualys-vmdr",
    "rapid7": "rapid7-insightvm",
    "splunk-es": "splunk-enterprise-security",
    "tenable": "tenable-io",
}


def _insert_after(row: dict, after: str, key: str, value) -> dict:
    out = {}
    for k, v in row.items():
        if k == key:
            continue
        out[k] = v
        if k == after:
            out[key] = value
    if key not in out:
        out[key] = value
    return out


def build_c2t(ids: AttackIds) -> list[dict]:
    prof = ids.profiles["enterprise"]
    rows = read_jsonl(C2T)
    desc = {}
    for r in rows:
        desc.setdefault(r["attack_technique"], r.get("technique_desc"))

    bad = []
    out = []
    for r in rows:
        r = dict(r)
        t = r["attack_technique"]
        state, succ = ids.status(t)
        if state == "revoked" and t not in prof:
            prev = r.get("via_revoked") or []
            r["attack_technique"] = succ
            r["technique_desc"] = desc.get(succ) or prof[succ]["name"]
            r = _insert_after(r, "technique_desc", "via_revoked", sorted(set(prev) | {t}))
            t = succ
        elif state not in ("live", "revoked"):
            bad.append((r.get("nist_control"), t, state))
            continue
        r["tactics"] = list(prof[t].get("tactics") or [])
        out.append(r)
    if bad:
        print("ERROR: control_to_technique.jsonl targets that are not live enterprise "
              "techniques and do not resolve through superseded_by.jsonl:")
        for c, t, s in bad:
            print(f"  {c} -> {t} ({s})")
        sys.exit(2)

    # stable sort on the committed key; for a duplicate key the native row sorts first
    out.sort(key=lambda r: (r["nist_control"], r["attack_technique"], bool(r.get("via_revoked"))))
    seen, deduped = set(), []
    for r in out:
        k = (r["nist_control"], r["attack_technique"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)
    return deduped


def _coverage(via: list[str]) -> str:
    kinds = {"detect" if c in DETECT else "identify" if c in IDENTIFY else "prevent" for c in via}
    if "detect" in kinds and "prevent" in kinds:
        return "prevent_detect"
    for k in ("detect", "identify"):
        if k in kinds:
            return k
    return "prevent"


def build_v2t(ids: AttackIds, c2t: list[dict]) -> list[dict]:
    prof = ids.profiles["enterprise"]
    vendor_name, vendor_ctrls = {}, {}
    retired = set()
    for r in read_jsonl(V2C):
        vn = r["vendor_normalized"]
        if vn in VENDOR_SLUG_ALIASES:
            retired.add(vn)
        vendor_name.setdefault(vn, r["vendor"])
        vendor_ctrls.setdefault(vn, set()).add(r["nist_control"])
    if retired:
        print("ERROR: vendor_to_control.jsonl uses retired vendor slugs (one slug per product):")
        for vn in sorted(retired):
            print(f"  {vn} -> use {VENDOR_SLUG_ALIASES[vn]}")
        sys.exit(2)
    missing = sorted({c for c in VENDOR_SLUG_ALIASES.values() if c not in vendor_ctrls})
    if missing:
        print(f"ERROR: VENDOR_SLUG_ALIASES targets with no vendor_to_control rows: {missing}")
        sys.exit(2)

    # own[t]: every control the technique holds in control_to_technique (native or re-keyed);
    # native[t]: only the rows CTID keyed on t itself; rekeyed[t]: {stale id: controls}
    own, native, rekeyed, desc = {}, {}, {}, {}
    for r in c2t:
        t, c = r["attack_technique"], r["nist_control"]
        own.setdefault(t, set()).add(c)
        if r.get("via_revoked"):
            for old in r["via_revoked"]:
                rekeyed.setdefault(t, {}).setdefault(old, set()).add(c)
        else:
            native.setdefault(t, set()).add(c)
        desc.setdefault(t, r.get("technique_desc"))
    merged, prov = ids.carry_forward(own)
    # one provenance map per technique: predecessor -> controls it contributed
    via_pred: dict[str, dict[str, set]] = {}
    for src in (prov, rekeyed):
        for t, olds in src.items():
            for old, ctrls in olds.items():
                via_pred.setdefault(t, {}).setdefault(old, set()).update(ctrls)

    rows = []
    for vn in sorted(vendor_ctrls):
        vc = vendor_ctrls[vn]
        for t in sorted(merged):
            via = sorted(vc & merged[t])
            if not via:
                continue
            row = {
                "edge_type": "vendor_covers_technique",
                "vendor": vendor_name[vn],
                "vendor_normalized": vn,
                "attack_technique": t,
                "technique_desc": desc.get(t) or prof[t]["name"],
                "via_control": via[0],
                "via_controls": via,
                "coverage_type": _coverage(via),
                "confidence": "low" if len(via) == 1 else "medium" if len(via) == 2 else "high",
                "control_count": len(via),
                "tactics": list(prof[t].get("tactics") or []),
            }
            carried_only = set(via) - native.get(t, set())
            preds = sorted(p for p, ctrls in (via_pred.get(t) or {}).items() if carried_only & ctrls)
            if preds:
                row["via_revoked"] = preds
            row["source"] = V2T_SOURCE
            rows.append(row)
    return rows


def _serialise(rows: list[dict]) -> bytes:
    return "".join(json.dumps(r, ensure_ascii=False) + "\r\n" for r in rows).encode("utf-8")


def main():
    ids = AttackIds(ROOT)
    c2t = build_c2t(ids)
    v2t = build_v2t(ids, c2t)
    outputs = [(C2T, _serialise(c2t), len(c2t)), (V2T, _serialise(v2t), len(v2t))]

    if "--check" in sys.argv:
        stale = [p.relative_to(ROOT).as_posix() for p, data, _ in outputs
                 if not p.exists() or p.read_bytes() != data]
        if stale:
            print("CTID EDGE DRIFT (run scripts/build_ctid_edges.py): " + ", ".join(stale))
            sys.exit(1)
        print(f"OK: control_to_technique.jsonl ({len(c2t)} edges) and "
              f"vendor_to_technique.jsonl ({len(v2t)} edges) match their sources")
        return

    for p, data, n in outputs:
        p.write_bytes(data)
        print(f"wrote {p.relative_to(ROOT).as_posix()} ({n} rows)")
    print(f"  control edges re-keyed from stale ids: {sum(1 for r in c2t if r.get('via_revoked'))}")
    print(f"  vendor edges carried forward from revoked predecessors: "
          f"{sum(1 for r in v2t if r.get('via_revoked'))}")


if __name__ == "__main__":
    main()
