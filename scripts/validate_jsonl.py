#!/usr/bin/env python3
"""
Validate every TeamStarWolf JSONL dataset.

Three layers of checks:
  1. Universal (every data/**/*.jsonl): each non-empty line is valid JSON and is
     a JSON object.
  2. Primary-key integrity (node/entity files): the file's primary id field is
     present, non-empty and unique across the file. Edge tables are exempt —
     they legitimately repeat ids.
  3. Rich per-field schema (the vendor/control/technique crosswalks): required
     fields, enumerated values and ATT&CK id format.

Previously only the three crosswalks were validated (3 of 41 datasets); this
covers them all (Library Enhancement Roadmap Tier 1.9).
"""

import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Layer 3 — rich per-field schemas for the vendor/control/technique crosswalks.
SCHEMAS = {
    "data/vendor_to_control.jsonl": {
        "required": ["vendor", "vendor_normalized", "market_family", "pipeline_stage", "nist_control", "control_desc", "confidence"],
        "field_values": {
            "confidence": ["high", "medium", "low"],
        }
    },
    "data/control_to_technique.jsonl": {
        "required": ["nist_control", "control_desc", "attack_technique", "technique_desc", "ctid_source", "confidence"],
        "field_values": {
            "ctid_source": ["nist800-53-r5"],
            "confidence": ["high", "medium", "low"],
        }
    },
    "data/vendor_to_technique.jsonl": {
        "required": ["vendor", "vendor_normalized", "attack_technique", "technique_desc", "via_control", "coverage_type", "confidence"],
        "field_values": {
            "coverage_type": ["prevent", "detect", "respond", "identify", "prevent_detect"],
            "confidence": ["high", "medium", "low"],
        }
    },
}

# Layer 2 — the primary key of each node/entity file (must be unique per file).
# Edge tables (paths containing "_to_") are intentionally omitted.
PRIMARY_KEYS = {
    "data/ai/atlas_mitigations.jsonl": "mitigation_id",
    "data/ai/atlas_tactics.jsonl": "tactic_id",
    "data/ai/atlas_techniques.jsonl": "technique_id",
    "data/attack/analytics.jsonl": "analytic_id",
    "data/attack/campaign_profiles.jsonl": "campaign_id",
    "data/attack/campaigns.jsonl": "campaign_id",
    "data/attack/d3fend_countermeasures.jsonl": "d3fend_id",
    "data/attack/data_components.jsonl": "data_component",
    "data/attack/superseded_by.jsonl": "old_id",
    "data/attack/group_profiles.jsonl": "group_id",
    "data/attack/groups.jsonl": "group_id",
    "data/attack/ics/groups.jsonl": "group_id",
    "data/attack/ics/mitigations.jsonl": "mitigation_id",
    "data/attack/ics/software.jsonl": "software_id",
    "data/attack/ics/technique_profiles.jsonl": "technique_id",
    "data/attack/mitigations.jsonl": "mitigation_id",
    "data/attack/mobile/groups.jsonl": "group_id",
    "data/attack/mobile/mitigations.jsonl": "mitigation_id",
    "data/attack/mobile/software.jsonl": "software_id",
    "data/attack/mobile/technique_profiles.jsonl": "technique_id",
    "data/attack/software.jsonl": "software_id",
    "data/attack/software_profiles.jsonl": "software_id",
    "data/attack/technique_profiles.jsonl": "technique_id",
    "data/engage/engage_activities.jsonl": "activity_id",
    "data/engage/engage_approaches.jsonl": "approach_id",
    "data/engage/engage_goals.jsonl": "goal_id",
    "data/fraud/f3_tactics.jsonl": "tactic_id",
    "data/fraud/f3_techniques.jsonl": "technique_id",
    "data/weaknesses/capec.jsonl": "capec_id",
    "data/weaknesses/cwe.jsonl": "cwe_id",
}

# Files whose true primary key is a tuple. detection_strategies lists a strategy
# once per technique it covers (15 strategies appear against both a superseded
# and current v19.2 technique id), so (strategy_id, technique_id) is the unique key.
COMPOSITE_KEYS = {
    "data/attack/detection_strategies.jsonl": ("strategy_id", "technique_id"),
}


def validate_file(rel: str):
    """Return (line_count, errors, checks) for one JSONL file."""
    errors = []
    line_count = 0
    p = ROOT / rel
    if not p.exists():
        return 0, [f"File not found: {rel}"], []

    schema = SCHEMAS.get(rel)
    pk = PRIMARY_KEYS.get(rel)
    ck = COMPOSITE_KEYS.get(rel)
    seen_ids = {}
    checks = ["json-object"]
    if pk:
        checks.append(f"unique:{pk}")
    if ck:
        checks.append("unique:(" + "+".join(ck) + ")")
    if schema:
        checks.append("field-schema")

    with open(p, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            line_count += 1

            try:
                record = json.loads(raw)
            except json.JSONDecodeError as e:
                errors.append(f"  Line {lineno}: Invalid JSON — {e}")
                continue

            if not isinstance(record, dict):
                errors.append(f"  Line {lineno}: record is not a JSON object ({type(record).__name__})")
                continue

            # Layer 2 — primary-key presence + uniqueness (single or composite)
            if pk:
                val = record.get(pk)
                if val in (None, ""):
                    errors.append(f"  Line {lineno}: missing/empty primary key '{pk}'")
                elif val in seen_ids:
                    errors.append(f"  Line {lineno}: duplicate '{pk}' = '{val}' (first seen line {seen_ids[val]})")
                else:
                    seen_ids[val] = lineno
            if ck:
                if any(record.get(k) in (None, "") for k in ck):
                    errors.append(f"  Line {lineno}: missing/empty composite key {ck}")
                else:
                    val = tuple(record[k] for k in ck)
                    if val in seen_ids:
                        errors.append(f"  Line {lineno}: duplicate {ck} = {val} (first seen line {seen_ids[val]})")
                    else:
                        seen_ids[val] = lineno

            # Layer 3 — rich field schema
            if schema:
                for field in schema.get("required", []):
                    if field not in record:
                        errors.append(f"  Line {lineno}: Missing required field '{field}'")
                for field, allowed in schema.get("field_values", {}).items():
                    if field in record and record[field] not in allowed:
                        errors.append(f"  Line {lineno}: Field '{field}' = '{record[field]}' not in {allowed}")
                if "attack_technique" in record:
                    val = record["attack_technique"]
                    if not (isinstance(val, str) and val.startswith("T") and len(val) >= 5):
                        errors.append(f"  Line {lineno}: 'attack_technique' = '{val}' doesn't look like an ATT&CK technique ID")

    return line_count, errors, checks


def main():
    files = sorted(
        os.path.relpath(p, ROOT).replace("\\", "/")
        for p in glob.glob(str(ROOT / "data" / "**" / "*.jsonl"), recursive=True)
    )
    total_errors = 0
    total_lines = 0
    no_pk = []

    for rel in files:
        line_count, errors, checks = validate_file(rel)
        total_lines += line_count
        if (rel not in PRIMARY_KEYS and rel not in SCHEMAS
                and rel not in COMPOSITE_KEYS and "_to_" not in rel):
            no_pk.append(rel)
        if errors:
            print(f"FAIL  {rel}  ({len(errors)} error(s) in {line_count} records)")
            for e in errors[:25]:
                print(e)
            if len(errors) > 25:
                print(f"  ... and {len(errors) - 25} more")
            total_errors += len(errors)
        else:
            print(f"OK    {rel}  ({line_count} records; {', '.join(checks)})")

    print("\n" + "=" * 60)
    print(f"Datasets validated: {len(files)}   Records: {total_lines}")
    if no_pk:
        print("Note: no primary-key check for (add to PRIMARY_KEYS if these are entity files): "
              + ", ".join(no_pk))
    if total_errors:
        print(f"FAILED: {total_errors} error(s) found")
        sys.exit(1)
    print("PASSED: all datasets valid")


if __name__ == "__main__":
    main()
