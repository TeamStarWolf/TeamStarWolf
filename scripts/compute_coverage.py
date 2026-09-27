#!/usr/bin/env python3
"""
TeamStarWolf Coverage Gap Scorer
Reads JSONL edge tables and computes ATT&CK tactic/technique coverage
across the enterprise vendor stack.

Usage:
    python scripts/compute_coverage.py
    python scripts/compute_coverage.py --output scores/
    python scripts/compute_coverage.py --tactic "credential-access"

Output:
    scores/tactic_coverage.json  - coverage % per tactic
    scores/coverage_gaps.json    - ranked gap list with recommendations
    scores/vendor_coverage.json  - per-vendor technique coverage summary
"""

import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict


# ATT&CK Enterprise v19.2 tactics (15). v19.2 renamed Defense Evasion (TA0005) -> Stealth
# and split out Defense Impairment (TA0112). "universe" technique counts are derived from the
# committed v19.2 technique_profiles (not hardcoded approximations) in load_technique_tactics().
TACTIC_METADATA = {
    "reconnaissance":       {"name": "Reconnaissance",       "weight": 0.8},
    "resource-development": {"name": "Resource Development", "weight": 0.8},
    "initial-access":       {"name": "Initial Access",       "weight": 1.5},
    "execution":            {"name": "Execution",            "weight": 1.3},
    "persistence":          {"name": "Persistence",          "weight": 1.2},
    "privilege-escalation": {"name": "Privilege Escalation", "weight": 1.2},
    "stealth":              {"name": "Stealth",              "weight": 1.4},
    "defense-impairment":   {"name": "Defense Impairment",   "weight": 1.4},
    "credential-access":    {"name": "Credential Access",    "weight": 1.4},
    "discovery":            {"name": "Discovery",            "weight": 1.0},
    "lateral-movement":     {"name": "Lateral Movement",     "weight": 1.3},
    "collection":           {"name": "Collection",           "weight": 1.3},
    "command-and-control":  {"name": "Command and Control",  "weight": 1.2},
    "exfiltration":         {"name": "Exfiltration",         "weight": 1.2},
    "impact":               {"name": "Impact",               "weight": 1.1},
}


def load_technique_tactics():
    """Derive the technique -> v19.2 tactics map from the committed technique_profiles
    (the full non-revoked universe), replacing the old hardcoded v13 approximation."""
    m = {}
    p = Path("data/attack/technique_profiles.jsonl")
    if not p.exists():
        return m
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("revoked"):
                continue
            tacs = [t for t in (r.get("tactics") or []) if t in TACTIC_METADATA]
            if tacs:
                m[r["technique_id"]] = tacs
    return m


TECHNIQUE_TACTIC_MAP = load_technique_tactics()


def load_jsonl(path: str) -> list[dict]:
    """Load a JSONL file into a list of records."""
    records = []
    p = Path(path)
    if not p.exists():
        print(f"Warning: {path} not found", file=sys.stderr)
        return records
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def compute_coverage(args):
    """Main coverage computation."""
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load edge tables
    v2c = load_jsonl("data/vendor_to_control.jsonl")
    c2t = load_jsonl("data/control_to_technique.jsonl")
    v2t = load_jsonl("data/vendor_to_technique.jsonl")

    print(f"Loaded: {len(v2c)} vendor->control edges")
    print(f"Loaded: {len(c2t)} control->technique edges")
    print(f"Loaded: {len(v2t)} vendor->technique edges")

    # Build covered technique set
    covered_techniques = set()
    vendor_technique_map = defaultdict(set)

    for edge in v2t:
        tech_id = edge.get("attack_technique", "")
        vendor = edge.get("vendor_normalized", "")
        covered_techniques.add(tech_id)
        if vendor:
            vendor_technique_map[vendor].add(tech_id)

    # Compute coverage per tactic
    tactic_coverage = {}
    technique_to_tactics = defaultdict(list)
    for tech, tactics in TECHNIQUE_TACTIC_MAP.items():
        for tactic in tactics:
            technique_to_tactics[tactic].append(tech)

    for tactic_id, meta in TACTIC_METADATA.items():
        tactic_techniques = set(technique_to_tactics[tactic_id])
        covered_in_tactic = tactic_techniques & covered_techniques
        total = max(len(tactic_techniques), 1)
        coverage_pct = round(len(covered_in_tactic) / total * 100, 1)

        tactic_coverage[tactic_id] = {
            "name": meta["name"],
            "covered_techniques": sorted(covered_in_tactic),
            "covered_count": len(covered_in_tactic),
            "total_in_attack": len(tactic_techniques),
            "coverage_pct_of_total": coverage_pct,
            "gap_techniques": sorted(tactic_techniques - covered_techniques),
            "weight": meta["weight"],
        }

    # Save tactic coverage
    tactic_path = output_dir / "tactic_coverage.json"
    with open(tactic_path, "w") as f:
        json.dump(tactic_coverage, f, indent=2)
    print(f"Written: {tactic_path}")

    # Compute vendor coverage
    vendor_coverage = {}
    for vendor, techniques in vendor_technique_map.items():
        tactic_dist = defaultdict(list)
        for tech in techniques:
            for tactic in TECHNIQUE_TACTIC_MAP.get(tech, ["unknown"]):
                tactic_dist[tactic].append(tech)
        vendor_coverage[vendor] = {
            "technique_count": len(techniques),
            "techniques": sorted(techniques),
            "tactic_distribution": {k: sorted(v) for k, v in tactic_dist.items()},
        }

    vendor_path = output_dir / "vendor_coverage.json"
    with open(vendor_path, "w") as f:
        json.dump(vendor_coverage, f, indent=2)
    print(f"Written: {vendor_path}")

    # Identify top gaps
    uncovered_with_high_nist_score = {
        # Techniques with high NIST coverage scores (from CTID overview) but not in our vendor stack
        "T1552": 33, "T1530": 33, "T1210": 32, "T1190": 29,
        "T1213": 24, "T1557": 24, "T1059": 24, "T1565": 26,
        "T1602": 25, "T1068": 25, "T1048": 23,
    }

    gaps = []
    for tactic_id, data in tactic_coverage.items():
        for tech in data.get("gap_techniques", []):
            nist_score = uncovered_with_high_nist_score.get(tech, 0)
            gaps.append({
                "technique_id": tech,
                "tactic": tactic_id,
                "tactic_name": data["name"],
                "nist_control_depth": nist_score,
                "priority": "critical" if nist_score >= 20 else "high" if nist_score >= 10 else "medium" if nist_score >= 5 else "low",
                "covered": False,
            })

    gaps.sort(key=lambda x: -x["nist_control_depth"])

    gaps_output = {
        "generated": "2026-09-27",
        "attack_version": "19.2",
        "total_covered_techniques": len(covered_techniques),
        "total_technique_universe": len(TECHNIQUE_TACTIC_MAP),
        "total_vendor_stack_vendors": len(vendor_technique_map),
        "tactic_summary": {
            tactic: {
                "covered": data["covered_count"],
                "total": data["total_in_attack"],
                "pct": data["coverage_pct_of_total"],
            }
            for tactic, data in tactic_coverage.items()
        },
        "top_gaps_by_nist_depth": gaps[:30],
        "recommended_additions": [
            {
                "capability": "DLP / CASB",
                "example_vendors": ["Netskope", "Microsoft Purview", "Forcepoint"],
                "fills_gap_in_tactics": ["collection", "exfiltration"],
                "key_techniques": ["T1213", "T1530", "T1560", "T1074", "T1114"],
                "rationale": "Collection tactic is 0% covered -- no DLP or CASB in current stack monitors data access and staging behavior",
            },
            {
                "capability": "UEBA (User and Entity Behavior Analytics)",
                "example_vendors": ["Microsoft Sentinel Analytics", "Splunk UBA", "Securonix"],
                "fills_gap_in_tactics": ["discovery", "credential-access", "lateral-movement"],
                "key_techniques": ["T1082", "T1083", "T1087", "T1552", "T1550"],
                "rationale": "Discovery tactic is 3% covered -- UEBA identifies reconnaissance behavior patterns from log telemetry already in SIEM",
            },
            {
                "capability": "Endpoint Hardening / Application Control",
                "example_vendors": ["CrowdStrike App Control", "Carbon Black App Control", "Tanium"],
                "fills_gap_in_tactics": ["stealth", "defense-impairment", "execution"],
                "key_techniques": ["T1218", "T1685", "T1027", "T1574", "T1543"],
                "rationale": "Stealth and the new Defense Impairment tactics are thinly covered -- LOLBAS, obfuscation, and disable/modify-tools (T1685) techniques largely uncovered",
            },
            {
                "capability": "NDR (Network Detection & Response)",
                "example_vendors": ["Corelight", "Darktrace", "ExtraHop Reveal(x)"],
                "fills_gap_in_tactics": ["command-and-control", "lateral-movement"],
                "key_techniques": ["T1090", "T1572", "T1095", "T1550", "T1563"],
                "rationale": "C2 and lateral movement have shallow coverage -- dedicated NDR adds protocol-level detection beyond NGFW policy",
            },
        ],
    }

    gaps_path = output_dir / "coverage_gaps.json"
    with open(gaps_path, "w") as f:
        json.dump(gaps_output, f, indent=2)
    print(f"Written: {gaps_path}")

    # Print summary
    print("\n=== COVERAGE SUMMARY ===")
    print(f"{'Tactic':<30} {'Covered':>8} {'Total':>8} {'Pct':>8}")
    print("-" * 58)
    for tactic, data in tactic_coverage.items():
        print(f"{data['name']:<30} {data['covered_count']:>8} {data['total_in_attack']:>8} {data['coverage_pct_of_total']:>7}%")


def main():
    parser = argparse.ArgumentParser(description="TeamStarWolf Coverage Gap Scorer")
    parser.add_argument("--output", default="scores", help="Output directory (default: scores/)")
    parser.add_argument("--tactic", help="Filter output to specific tactic")
    args = parser.parse_args()
    compute_coverage(args)


if __name__ == "__main__":
    main()
