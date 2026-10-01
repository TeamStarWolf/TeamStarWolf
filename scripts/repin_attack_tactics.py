#!/usr/bin/env python3
"""
Re-pin the Enterprise ATT&CK *tactic* layer of the knowledge graph to v19.2.

Background
----------
The committed `data/attack/` core carries the ATT&CK v18.1 tactic vocabulary
("defense-evasion") in several tactic-keyed tables, and a later hand edit
(the Defense Evasion -> Stealth re-tag follow-up) left 18 live techniques with
a `tactics` value that contradicts the shipped v19.2 STIX bundle. v19.2 renamed
Defense Evasion (TA0005) to Stealth and split out Defense Impairment (TA0112),
so any table that keys on the tactic string silently mis-buckets those
techniques.

This script re-derives the `tactics` field of the Enterprise tactic-keyed
tables directly from the authoritative v19.2 Enterprise STIX bundle
(`kill_chain_phases[].phase_name`). It is deterministic and idempotent:
re-running it after a successful pass changes nothing.

Scope (Enterprise only)
-----------------------
Rewritten (only rows whose tactic set disagrees with the bundle):
  - data/attack/technique_profiles.jsonl     (live + revoked; fixes the 18-technique drift)
  - data/attack/group_to_technique.jsonl
  - data/attack/detection_strategies.jsonl
  - data/control_to_technique.jsonl
  - data/vendor_to_technique.jsonl

Deliberately NOT touched (different frameworks / editions that do not take the
Enterprise v19.2 rename):
  - data/ai/atlas_techniques.jsonl           (MITRE ATLAS, own tactic set)
  - data/attack/mobile/technique_profiles.jsonl (Mobile ATT&CK, pinned v18.1)
  - data/attack/ics/*, data/fraud/f3_*       (ICS / F3, own vocabularies)

Rows whose technique id is not present in the Enterprise bundle (e.g. a Mobile
id that appears in the CTID mapping) are left unchanged and reported.

Only the `tactics` field value is ever modified. Row count, row order, and
every other field are preserved byte-for-byte, so the resulting diff is limited
to the tactic corrections.

Usage
-----
    python scripts/repin_attack_tactics.py --bundle /path/to/enterprise-attack-19.2.json
    python scripts/repin_attack_tactics.py --bundle ... --check   # report only, write nothing

The bundle is the official MITRE release
(raw.githubusercontent.com/mitre-attack/attack-stix-data, enterprise-attack/enterprise-attack-19.2.json);
the copy vendored in the ATTACK-Navi app is byte-identical in content.
"""

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The 15 Enterprise v19.2 tactic shortnames (x_mitre_shortname).
V19_2_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
}

# Enterprise tactic-keyed tables to re-pin, relative to the repo root.
TARGETS = [
    "data/attack/technique_profiles.jsonl",
    "data/attack/group_to_technique.jsonl",
    "data/attack/detection_strategies.jsonl",
    "data/control_to_technique.jsonl",
    "data/vendor_to_technique.jsonl",
]

# The technique-id field name differs across tables.
TID_FIELDS = ("technique_id", "attack_technique")


def load_bundle_tactics(bundle_path: Path) -> dict:
    """technique external id -> ordered list of Enterprise tactic shortnames."""
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    out = {}
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern":
            continue
        ext = None
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                ext = r.get("external_id")
                break
        if not ext:
            continue
        phases = [
            k["phase_name"]
            for k in o.get("kill_chain_phases", [])
            if k.get("kill_chain_name") == "mitre-attack"
        ]
        out[ext] = phases
    return out


def tid_of(record: dict):
    for f in TID_FIELDS:
        if f in record:
            return record[f]
    return None


def repin_file(path: Path, bundle_tactics: dict, check: bool):
    """Returns (changed_rows, skipped_unknown, total_rows)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    changed = 0
    skipped = 0
    out_lines = []
    for raw in lines:
        if not raw.strip():
            out_lines.append(raw)
            continue
        rec = json.loads(raw)
        if "tactics" not in rec:
            out_lines.append(raw)
            continue
        tid = tid_of(rec)
        target = bundle_tactics.get(tid)
        if target is None:
            # Not an Enterprise technique (e.g. Mobile id in the CTID map); leave as-is.
            if rec.get("tactics"):
                skipped += 1
            out_lines.append(raw)
            continue
        current = rec.get("tactics") or []
        if set(current) != set(target):
            rec["tactics"] = list(target)  # bundle order, deterministic
            changed += 1
            out_lines.append(json.dumps(rec, ensure_ascii=False))
        else:
            out_lines.append(raw)
    if changed and not check:
        path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return changed, skipped, len([l for l in lines if l.strip()])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", required=True, help="Path to enterprise-attack-19.2.json")
    ap.add_argument("--check", action="store_true", help="Report changes but write nothing")
    args = ap.parse_args()

    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        print(f"ERROR: bundle not found: {bundle_path}", file=sys.stderr)
        sys.exit(2)

    bundle_tactics = load_bundle_tactics(bundle_path)
    # Sanity: the bundle must be v19.2 vocabulary.
    seen = {t for ts in bundle_tactics.values() for t in ts}
    if "defense-evasion" in seen or not {"stealth", "defense-impairment"} <= seen:
        print("ERROR: bundle does not carry the v19.2 tactic vocabulary "
              "(expected 'stealth' + 'defense-impairment', no 'defense-evasion').", file=sys.stderr)
        sys.exit(2)

    total_changed = 0
    print(f"Re-pinning Enterprise tactics from {bundle_path.name} "
          f"({len(bundle_tactics)} techniques){' [check]' if args.check else ''}\n")
    for rel in TARGETS:
        p = REPO / rel
        if not p.exists():
            print(f"  SKIP (missing): {rel}")
            continue
        changed, skipped, total = repin_file(p, bundle_tactics, args.check)
        total_changed += changed
        note = f", {skipped} non-Enterprise rows left unchanged" if skipped else ""
        print(f"  {rel}: {changed}/{total} rows re-pinned{note}")

    print(f"\n{'Would change' if args.check else 'Changed'} {total_changed} rows across {len(TARGETS)} files.")


if __name__ == "__main__":
    main()
