#!/usr/bin/env python3
"""
Validate TeamStarWolf JSONL edge table files.
Checks: valid JSON on each line, required fields present, field value constraints.
"""

import json
import sys
from pathlib import Path

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

def validate_file(path: str, schema: dict) -> tuple[int, list[str]]:
    """Validate a JSONL file against a schema. Returns (line_count, errors)."""
    errors = []
    line_count = 0
    p = Path(path)

    if not p.exists():
        return 0, [f"File not found: {path}"]

    with open(p, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            line_count += 1

            # Check valid JSON
            try:
                record = json.loads(raw)
            except json.JSONDecodeError as e:
                errors.append(f"  Line {lineno}: Invalid JSON — {e}")
                continue

            # Check required fields
            for field in schema.get("required", []):
                if field not in record:
                    errors.append(f"  Line {lineno}: Missing required field '{field}'")

            # Check field value constraints
            for field, allowed in schema.get("field_values", {}).items():
                if field in record and record[field] not in allowed:
                    errors.append(f"  Line {lineno}: Field '{field}' = '{record[field]}' not in {allowed}")

            # Check ATT&CK technique ID format
            for field in ["attack_technique", "via_control"]:
                if field == "attack_technique" and field in record:
                    val = record[field]
                    if not (val.startswith("T") and len(val) >= 5):
                        errors.append(f"  Line {lineno}: '{field}' = '{val}' doesn't look like an ATT&CK technique ID")

    return line_count, errors


# --- Enterprise ATT&CK v19.2 tactic vocabulary guard ----------------------
# v19.2 renamed Defense Evasion (TA0005) -> Stealth and split out Defense
# Impairment (TA0112). The retired "defense-evasion" shortname must never
# reappear in the Enterprise tactic-keyed tables. These 15 shortnames are the
# complete v19.2 Enterprise set (x_mitre_shortname); the list is stable, so the
# check needs no STIX bundle at CI time. (ATLAS, Mobile 18.1, ICS and F3 carry
# their own tactic vocabularies and are intentionally out of scope here.)
V19_2_ENTERPRISE_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
}

ENTERPRISE_TACTIC_FILES = [
    "data/attack/technique_profiles.jsonl",
    "data/attack/group_to_technique.jsonl",
    "data/attack/detection_strategies.jsonl",
]


def validate_enterprise_tactics(path: str) -> tuple[int, list[str]]:
    """Every `tactics` value in an Enterprise tactic-keyed table must be a
    v19.2 shortname. Returns (rows_checked, errors)."""
    errors = []
    checked = 0
    p = Path(path)
    if not p.exists():
        return 0, [f"File not found: {path}"]
    with open(p, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError as e:
                errors.append(f"  Line {lineno}: Invalid JSON — {e}")
                continue
            if "tactics" not in record:
                continue
            checked += 1
            for t in record.get("tactics") or []:
                if t not in V19_2_ENTERPRISE_TACTICS:
                    tid = record.get("technique_id") or record.get("strategy_id") or "?"
                    errors.append(
                        f"  Line {lineno} ({tid}): tactic '{t}' is not a v19.2 "
                        f"Enterprise shortname (Defense Evasion became 'stealth' / 'defense-impairment')"
                    )
    return checked, errors


def main():
    total_errors = 0
    total_lines = 0

    for path, schema in SCHEMAS.items():
        print(f"\nValidating {path}...")
        line_count, errors = validate_file(path, schema)
        total_lines += line_count

        if errors:
            print(f"  FAIL — {len(errors)} error(s) in {line_count} records:")
            for e in errors:
                print(e)
            total_errors += len(errors)
        else:
            print(f"  OK — {line_count} records valid")

    for path in ENTERPRISE_TACTIC_FILES:
        print(f"\nValidating Enterprise v19.2 tactics in {path}...")
        checked, errors = validate_enterprise_tactics(path)
        if errors:
            print(f"  FAIL — {len(errors)} tactic error(s) in {checked} records:")
            for e in errors[:50]:
                print(e)
            if len(errors) > 50:
                print(f"  … and {len(errors) - 50} more")
            total_errors += len(errors)
        else:
            print(f"  OK — {checked} records carry only v19.2 Enterprise tactics")

    print(f"\n{'='*50}")
    print(f"Total records validated: {total_lines}")

    if total_errors:
        print(f"FAILED: {total_errors} error(s) found")
        sys.exit(1)
    else:
        print("PASSED: All data files valid")


if __name__ == "__main__":
    main()
