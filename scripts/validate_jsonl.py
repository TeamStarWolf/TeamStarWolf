#!/usr/bin/env python3
"""
Validate every TeamStarWolf JSONL dataset.

Layers of checks:
  1. Universal (every data/**/*.jsonl): each non-empty line is valid JSON and is
     a JSON object.
  2. Key integrity: a node/entity file's primary id field is present, non-empty and
     unique; an edge table's composite key (source, target) is unique, so an edge
     is never counted twice (control_to_technique.jsonl once shipped 50 duplicate
     (nist_control, attack_technique) rows).
  3. Rich per-field schema (the vendor/control/technique crosswalks): required
     fields, enumerated values and ATT&CK id format.
  4. Edge contract (source/target presence; see data/EDGES.md).
  5. Referential integrity of every ATT&CK technique reference (scripts/attack_ids.py):
     the id must be a live technique of the table's domain(s), or an id that
     data/attack/superseded_by.jsonl resolves to a live successor (a revoked id the
     upstream mapping is still keyed on; builders carry it forward). An unknown id
     (e.g. a Mobile id in an Enterprise table), a revoked id whose chain dead-ends,
     or a deprecated id (unless the table allows legacy deprecated targets) fails.
     A row's `via_revoked` provenance must name predecessors that resolve to its
     target, and a denormalised `tactics` copy must equal the target technique's
     current tactics in technique_profiles (no retired shortname such as
     defense-evasion survives a re-pin).

Previously only the three crosswalks were validated (3 of 41 datasets); this
covers them all (Library Enhancement Roadmap Tier 1.9).
"""

import glob
import json
import os
import sys
from pathlib import Path

from attack_ids import AttackIds

ROOT = Path(__file__).resolve().parent.parent

# Layer 3 — rich per-field schemas for the vendor/control/technique crosswalks.
SCHEMAS = {
    "data/vendor_to_control.jsonl": {
        "required": ["vendor", "vendor_normalized", "market_family", "pipeline_stage", "nist_control", "control_desc", "confidence"],
        "field_values": {
            "confidence": ["high", "medium", "low"],
            "edge_type": ["vendor_satisfies_control"],
        }
    },
    "data/control_to_technique.jsonl": {
        "required": ["nist_control", "control_desc", "attack_technique", "technique_desc", "ctid_source", "confidence"],
        "field_values": {
            "ctid_source": ["nist800-53-r5"],
            "confidence": ["high", "medium", "low"],
            "mapping_type": ["mitigates"],
            "edge_type": ["control_mitigates_technique"],
        }
    },
    "data/vendor_to_technique.jsonl": {
        "required": ["vendor", "vendor_normalized", "attack_technique", "technique_desc", "via_control", "coverage_type", "confidence"],
        "field_values": {
            "coverage_type": ["prevent", "detect", "respond", "identify", "prevent_detect"],
            "confidence": ["high", "medium", "low"],
            "edge_type": ["vendor_covers_technique"],
        }
    },
    "data/attack/superseded_by.jsonl": {
        "required": ["old_id", "reason"],
        "field_values": {
            "reason": ["revoked", "deprecated"],
        }
    },
    # Per-technique prevalence extracted from the (uncommitted) 529-machine training
    # corpus; scripts/generate_mitre_pages.py renders the "corpus signal" paragraph from it.
    "data/generated/corpus_signal.jsonl": {
        "required": ["technique_id", "corpus_n", "machines", "pct", "linux", "windows"],
        "field_values": {},
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
    "data/generated/corpus_signal.jsonl": "technique_id",
    "data/weaknesses/capec.jsonl": "capec_id",
    "data/weaknesses/cwe.jsonl": "cwe_id",
}

# Files whose true primary key is a tuple. detection_strategies lists a strategy
# once per technique it covers (15 strategies appear against both a superseded
# and current v19.2 technique id), so (strategy_id, technique_id) is the unique key.
COMPOSITE_KEYS = {
    "data/attack/detection_strategies.jsonl": ("strategy_id", "technique_id"),
    # edge tables: one row per (source, target)
    "data/control_to_technique.jsonl":                ("nist_control", "attack_technique"),
    "data/vendor_to_control.jsonl":                   ("vendor_normalized", "nist_control"),
    "data/vendor_to_technique.jsonl":                 ("vendor_normalized", "attack_technique"),
    "data/attack/mitigation_to_technique.jsonl":      ("mitigation_id", "technique_id"),
    "data/attack/software_to_technique.jsonl":        ("software_id", "technique_id"),
    "data/attack/group_to_technique.jsonl":           ("group_id", "technique_id"),
    "data/attack/ics/group_to_technique.jsonl":       ("group_id", "technique_id"),
    "data/attack/mobile/group_to_technique.jsonl":    ("group_id", "technique_id"),
    "data/attack/technique_to_d3fend.jsonl":          ("technique_id", "d3fend_technique"),
    "data/attack/technique_to_d3fend_internal.jsonl": ("technique_id", "d3fend_technique"),
    "data/engage/attack_to_engage.jsonl":             ("technique_id",),
    "data/attack/technique_to_car.jsonl":             ("technique_id",),
}

# Layer 5 - ATT&CK technique references: file -> (field, is_list, domains, allow_deprecated).
# technique_to_d3fend mixes Enterprise and ICS ids and, as a third-party mapping, may
# still name a technique ATT&CK deprecated without a successor (T1053.004).
# technique_to_d3fend_internal is keyed on D3FEND/SPARTA ids, not ATT&CK, so it is absent.
ENT, ALL = ("enterprise",), ("enterprise", "ics", "mobile")
TECHNIQUE_REFS = {
    "data/control_to_technique.jsonl":             ("attack_technique", False, ENT, False),
    "data/vendor_to_technique.jsonl":              ("attack_technique", False, ENT, False),
    "data/attack/mitigation_to_technique.jsonl":   ("technique_id", False, ENT, False),
    "data/attack/software_to_technique.jsonl":     ("technique_id", False, ENT, False),
    "data/attack/group_to_technique.jsonl":        ("technique_id", False, ENT, False),
    "data/attack/ics/group_to_technique.jsonl":    ("technique_id", False, ("ics",), False),
    "data/attack/mobile/group_to_technique.jsonl": ("technique_id", False, ("mobile",), False),
    "data/attack/technique_to_d3fend.jsonl":       ("technique_id", False, ("enterprise", "ics"), True),
    "data/attack/technique_to_car.jsonl":          ("technique_id", False, ENT, False),
    "data/engage/attack_to_engage.jsonl":          ("technique_id", False, ENT, False),
    "data/attack/detection_strategies.jsonl":      ("technique_id", False, ENT, False),
    "data/attack/analytics.jsonl":                 ("technique_ids", True, ENT, False),
    "data/generated/corpus_signal.jsonl":          ("technique_id", False, ENT, False),
    "data/weaknesses/capec.jsonl":                 ("attack_techniques", True, ALL, False),
}

# Layer 4 — edge contract (see data/EDGES.md). Each edge dataset asserts a
# relationship from a source id to a target id; every row must carry a non-empty
# source and a non-empty target (adjacency rows: a non-empty target list whose
# items carry the declared id key). The normalized (source_type, target_type,
# edge_type) interpretation is documented in data/EDGES.md; here we enforce the
# structural half of that contract so a consumer can join these edges reliably.
EDGES = {
    "data/control_to_technique.jsonl":             {"source": "nist_control",      "target": "attack_technique"},
    "data/vendor_to_control.jsonl":                {"source": "vendor_normalized", "target": "nist_control"},
    "data/vendor_to_technique.jsonl":              {"source": "vendor_normalized", "target": "attack_technique"},
    "data/attack/mitigation_to_technique.jsonl":   {"source": "mitigation_id",     "target": "technique_id"},
    "data/attack/software_to_technique.jsonl":     {"source": "software_id",       "target": "technique_id"},
    "data/attack/group_to_technique.jsonl":        {"source": "group_id",          "target": "technique_id"},
    "data/attack/ics/group_to_technique.jsonl":    {"source": "group_id",          "target": "technique_id"},
    "data/attack/mobile/group_to_technique.jsonl": {"source": "group_id",          "target": "technique_id"},
    "data/attack/technique_to_d3fend.jsonl":          {"source": "technique_id", "target": "d3fend_technique"},
    "data/attack/technique_to_d3fend_internal.jsonl": {"source": "technique_id", "target": "d3fend_technique"},
    "data/attack/superseded_by.jsonl":             {"source": "old_id", "target": "new_id", "target_nullable": True},
    "data/engage/attack_to_engage.jsonl":          {"source": "technique_id", "target": "engage_activities", "target_list_key": "id"},
    "data/attack/technique_to_car.jsonl":          {"source": "technique_id", "target": "car", "target_list_key": "car_id"},
}


def _ref_errors(record, ref, ids):
    """Layer 5 errors for one record (technique references, via_revoked, tactics)."""
    field, is_list, domains, allow_dep = ref
    val = record.get(field)
    vals = (val or []) if is_list else ([] if val in (None, "") else [val])
    errs = []
    resolved = {}
    for t in vals:
        states = [(d,) + ids.status(t, d) for d in domains]
        live = [s for s in states if s[1] == "live"]
        known = [s for s in states if s[1] != "unknown"]
        if not known:
            errs.append(f"'{field}' = '{t}' is not a technique in "
                        f"{'/'.join(domains)} ATT&CK and not in superseded_by.jsonl")
            continue
        d, st, _succ = (live or known)[0]
        if st == "dangling":
            errs.append(f"'{field}' = '{t}' is revoked but its superseded_by chain does not "
                        f"reach a live {d} technique")
        elif st == "deprecated" and not allow_dep:
            errs.append(f"'{field}' = '{t}' is deprecated in {d} ATT&CK with no successor")
        resolved[t] = d
    if not is_list and vals and vals[0] in resolved:
        t = vals[0]
        d = resolved[t]
        via = record.get("via_revoked")
        if via is not None:
            if not isinstance(via, list) or not via:
                errs.append("'via_revoked' must be a non-empty list of predecessor ids")
            else:
                for old in via:
                    if old == t or ids.resolve(old, d) != t:
                        errs.append(f"'via_revoked' id '{old}' does not resolve to '{t}' "
                                    f"through superseded_by.jsonl")
        if "tactics" in record:
            prof = ids.profiles[d].get(t)
            if prof is not None and record["tactics"] != (prof.get("tactics") or []):
                errs.append(f"'tactics' {record['tactics']} != {t}'s current tactics "
                            f"{prof.get('tactics') or []} (technique_profiles.jsonl)")
    return errs


def validate_file(rel: str, ids=None):
    """Return (line_count, errors, checks) for one JSONL file."""
    errors = []
    line_count = 0
    p = ROOT / rel
    if not p.exists():
        return 0, [f"File not found: {rel}"], []

    schema = SCHEMAS.get(rel)
    pk = PRIMARY_KEYS.get(rel)
    ck = COMPOSITE_KEYS.get(rel)
    edge = EDGES.get(rel)
    ref = TECHNIQUE_REFS.get(rel) if ids is not None else None
    seen_ids = {}
    checks = ["json-object"]
    if pk:
        checks.append(f"unique:{pk}")
    if ck:
        checks.append("unique:(" + "+".join(ck) + ")")
    if schema:
        checks.append("field-schema")
    if edge:
        checks.append("edge-contract")
    if ref:
        checks.append("technique-refs")

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

            # Layer 4 — edge contract (source/target presence; see data/EDGES.md)
            if edge:
                src = record.get(edge["source"])
                if src in (None, ""):
                    errors.append(f"  Line {lineno}: edge missing/empty source '{edge['source']}'")
                tkey = edge.get("target_list_key")
                if edge["target"] not in record:
                    errors.append(f"  Line {lineno}: edge missing target field '{edge['target']}'")
                else:
                    tgt = record[edge["target"]]
                    if tkey:
                        if not isinstance(tgt, list) or not tgt:
                            errors.append(f"  Line {lineno}: edge target '{edge['target']}' must be a non-empty list")
                        elif any(not isinstance(it, dict) or it.get(tkey) in (None, "") for it in tgt):
                            errors.append(f"  Line {lineno}: edge target list item missing '{tkey}'")
                    elif tgt is None:
                        if not edge.get("target_nullable"):
                            errors.append(f"  Line {lineno}: edge empty target '{edge['target']}'")
                    elif tgt == "":
                        errors.append(f"  Line {lineno}: edge empty target '{edge['target']}'")

            # Layer 5 - technique referential integrity / via_revoked / tactics copy
            if ref:
                for e in _ref_errors(record, ref, ids):
                    errors.append(f"  Line {lineno}: {e}")

            # superseded_by itself: a revoked old_id must reach a live successor
            if rel == "data/attack/superseded_by.jsonl" and ids is not None and record.get("new_id"):
                dom = record.get("domain") or "enterprise"
                if ids.status(record.get("old_id"), dom)[0] == "dangling":
                    errors.append(f"  Line {lineno}: '{record.get('old_id')}' -> "
                                  f"'{record['new_id']}' does not reach a live {dom} technique")

    return line_count, errors, checks


def main():
    ids = AttackIds(ROOT)
    files = sorted(
        os.path.relpath(p, ROOT).replace("\\", "/")
        for p in glob.glob(str(ROOT / "data" / "**" / "*.jsonl"), recursive=True)
    )
    total_errors = 0
    total_lines = 0
    no_pk = []

    for rel in files:
        line_count, errors, checks = validate_file(rel, ids)
        total_lines += line_count
        if (rel not in PRIMARY_KEYS and rel not in SCHEMAS
                and rel not in COMPOSITE_KEYS and rel not in EDGES
                and "_to_" not in rel):
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
