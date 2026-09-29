#!/usr/bin/env python3
"""Compute every advertised headline count directly from the source-of-truth data
files and emit data/generated/stats.json. With --check, scan the human-facing docs
for hard-coded numbers that must match stats.json and exit non-zero on divergence.

The point of this script (audit Wave 0): headline numbers stop being typed by hand.
Run it after any data change; CI runs --check to fail the build on drift.
"""
from __future__ import annotations
import json, sys, glob, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _rows(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return None
    out = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out

def _count(rel):
    r = _rows(rel)
    return len(r) if r is not None else None

def compute():
    tp = _rows("data/attack/technique_profiles.jsonl") or []
    sub = sum(1 for t in tp if t.get("is_subtechnique"))
    d3 = _rows("data/attack/technique_to_d3fend.jsonl") or []
    d3_tech = len({r.get("technique_id") for r in d3 if r.get("technique_id", "").startswith("T")})
    stats = {
        # --- ATT&CK core (project's own data = source of truth) ---
        "technique_total": len(tp),
        "technique_parent": len(tp) - sub,
        "technique_sub": sub,
        # MITRE currently lists 697 ACTIVE enterprise techniques; this file retains a
        # small number of superseded records on purpose (no revoked flag in-file), so
        # technique_total (file) legitimately exceeds MITRE-active. See docs footnote.
        "mitre_active_enterprise_techniques_ref": 697,
        "groups": _count("data/attack/groups.jsonl"),
        "software": _count("data/attack/software.jsonl"),
        "campaigns": _count("data/attack/campaigns.jsonl"),
        "mitigations": _count("data/attack/mitigations.jsonl"),
        "data_components": _count("data/attack/data_components.jsonl"),
        "detection_strategies": _count("data/attack/detection_strategies.jsonl"),
        "analytics": _count("data/attack/analytics.jsonl"),
        # --- Engage ---
        "engage_activities": _count("data/engage/engage_activities.jsonl"),
        "engage_approaches": _count("data/engage/engage_approaches.jsonl"),
        "engage_goals": _count("data/engage/engage_goals.jsonl"),
        "engage_mappings": _count("data/engage/attack_to_engage.jsonl"),
        # --- crosswalk edge tables ---
        "control_to_technique_edges": _count("data/control_to_technique.jsonl"),
        "vendor_to_technique_edges": _count("data/vendor_to_technique.jsonl"),
        "technique_to_d3fend_edges": len(d3) if d3 else None,
        "techniques_with_d3fend": d3_tech,
        # --- workbench / docs ---
        "navigator_layers": len(glob.glob(os.path.join(ROOT, "navigator", "**", "*.json"), recursive=True)) or None,
        "reference_docs": len(glob.glob(os.path.join(ROOT, "*.md"))),
    }
    return {k: v for k, v in stats.items() if v is not None}

# (regex on the doc, group(1) = the number)  ->  stats key it must equal
CHECKS = [
    (r"([\d,]+)\s+Enterprise techniques", "technique_total"),
    (r"([\d,]+)\s+(?:adversary\s+)?groups", "groups"),
    (r"([\d,]+)\s+malware", "software"),
    (r"([\d,]+)\s+strategies", "detection_strategies"),
    (r"([\d,]+)\s+analytics", "analytics"),
    (r"([\d,]+)\s+deception activities", "engage_activities"),
    (r"([\d,]+)\s+mappings? to ATT", "engage_mappings"),
    (r"([\d,]+)\s+(?:MITRE ATT&CK\s+)?(?:intrusion\s+)?campaigns", "campaigns"),
    (r"([\d,]+)\s+(?:workbench\s+|navigator\s+)?layers", "navigator_layers"),
]
DOCS = ["README.md", "HOME.md", "INDEX.md", "CITATION.cff"] + \
       [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "scores", "*.md"))]

def check(stats):
    problems = []
    for rel in DOCS:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8").read()
        for pat, key in CHECKS:
            if key not in stats:
                continue
            for m in re.finditer(pat, text):
                s = m.group(1).replace(",", "")
                if not s.isdigit():
                    continue
                got = int(s)
                if got != stats[key]:
                    problems.append(f"{rel}: '{m.group(0).strip()}' -> {key} should be {stats[key]:,} (found {got:,})")
    return problems

def main():
    stats = compute()
    if "--check" in sys.argv:
        probs = check(stats)
        if probs:
            print("STALE HEADLINE NUMBERS (must match data/generated/stats.json):")
            for p in probs:
                print("  -", p)
            sys.exit(1)
        print("OK: all scanned headline numbers match stats.json")
        return
    outdir = os.path.join(ROOT, "data", "generated")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, sort_keys=True)
        f.write("\n")
    print("wrote data/generated/stats.json")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v:,}" if isinstance(v, int) else f"  {k}: {v}")

if __name__ == "__main__":
    main()
