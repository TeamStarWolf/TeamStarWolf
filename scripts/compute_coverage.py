#!/usr/bin/env python3
"""
TeamStarWolf Coverage Gap Scorer

Reads the vendor -> technique edge table and the ATT&CK v19.2 technique profiles and
computes tactic / technique coverage across the modeled vendor stack. Every number in the
output is derived from the committed data on each run; nothing is hand-maintained.

Usage:
    python scripts/compute_coverage.py                    # rewrite scores/ (4 files)
    python scripts/compute_coverage.py --check            # exit 1 if scores/ is stale
    python scripts/compute_coverage.py --output DIR       # write somewhere else
    python scripts/compute_coverage.py --tactic credential-access

--tactic narrows only the printed console summary to one tactic (and lists that tactic's
uncovered techniques); the score files below are always written for every tactic, so a
filtered run never leaves partial files in scores/.

Output (byte-for-byte deterministic for a given data tree; no wall-clock date is stamped,
the input files' content hashes are recorded instead):
    scores/tactic_coverage.json  - coverage % per tactic
    scores/coverage_gaps.json    - summary, ranked gap list, recommendations
    scores/vendor_coverage.json  - per-vendor technique coverage summary
    scores/coverage_gaps.md      - the human-readable page, rendered from coverage_gaps.json

What "covered" means: a technique is covered when at least one stack vendor satisfies a
NIST 800-53 R5 control that the CTID mapping links to it (data/vendor_to_technique.jsonl,
built by scripts/build_ctid_edges.py). Edge rows keyed on an ATT&CK id that v19 revoked
are resolved to the live successor through data/attack/superseded_by.jsonl, so a revoked
id is never counted as a technique and never lands in an "unknown" tactic bucket.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

from attack_ids import AttackIds

ROOT = Path(__file__).resolve().parents[1]

ATTACK_VERSION = "19.2"

# Inputs, relative to the repo root. All are required: a missing file is an error, never
# an empty table (an empty table used to produce an all-zero scores/ silently).
PROFILES = "data/attack/technique_profiles.jsonl"
SUPERSEDED = "data/attack/superseded_by.jsonl"
VENDOR_TO_TECHNIQUE = "data/vendor_to_technique.jsonl"
INPUTS = (PROFILES, SUPERSEDED, VENDOR_TO_TECHNIQUE)

# ATT&CK Enterprise v19.2 tactics (15), in matrix order. v19 renamed Defense Evasion
# (TA0005) -> Stealth and split out Defense Impairment (TA0112). The technique universe
# per tactic is derived from the committed profiles, never hardcoded.
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

# The edge table carries some products under two normalized keys (the same product listed
# twice in CONTROLS_MAPPING.md under a company name and a product name, or under an old
# and a new product name). Fold each alias into one canonical key so the vendor count and
# per-vendor figures count a product once; the folded keys are listed in the output.
# Zscaler ZIA and ZPA are distinct products and stay separate, as does the generic
# "zscaler" row, which does not identify a single product.
VENDOR_ALIASES = {
    "cyberark": "cyberark-pam",
    "elastic-siem": "elastic-security",
    "microsoft-defender-for-o365": "microsoft-defender-for-office-365",
    "qualys": "qualys-vmdr",
    "rapid7": "rapid7-insightvm",
    "splunk-es": "splunk-enterprise-security",
    "tenable": "tenable-io",
}

TOP_GAPS = 30
GAP_RANKING = ("group_count desc, software_count desc, campaign_count desc, "
               "nist_control_depth desc, technique_id")
# Worded so no number directly precedes "groups" (build_stats.py --check reads "<n> groups"
# in scores/*.md as the library-wide group total).
PRIORITY_BASIS = ("group_count (the number of ATT&CK groups documented using the technique, "
                  "from the v19.2 profiles): critical >= 20, high >= 10, medium >= 3, low otherwise")

# Curated capability recommendations. The capability, example vendors, target tactics and
# key technique families are editorial; every number in the rendered rationale (tactic
# coverage, uncovered family members) is computed from the data on each run.
RECOMMENDATIONS = [
    {
        "capability": "DLP / CASB",
        "example_vendors": ["Netskope", "Microsoft Purview", "Forcepoint"],
        "fills_gap_in_tactics": ["collection", "exfiltration"],
        "key_techniques": ["T1213", "T1530", "T1560", "T1074", "T1114"],
        "purpose": "monitors data access and staging before exfiltration",
    },
    {
        "capability": "UEBA (User and Entity Behavior Analytics)",
        "example_vendors": ["Microsoft Sentinel Analytics", "Splunk UBA", "Securonix"],
        "fills_gap_in_tactics": ["discovery", "credential-access", "lateral-movement"],
        "key_techniques": ["T1082", "T1083", "T1087", "T1552", "T1550"],
        "purpose": "identifies reconnaissance and account-misuse patterns from log telemetry already in the SIEM",
    },
    {
        "capability": "Endpoint Hardening / Application Control",
        "example_vendors": ["CrowdStrike App Control", "Carbon Black App Control", "Tanium"],
        "fills_gap_in_tactics": ["stealth", "defense-impairment", "execution"],
        "key_techniques": ["T1218", "T1685", "T1027", "T1574", "T1543"],
        "purpose": "limits LOLBAS proxy execution, obfuscation and disable/modify-tools abuse",
    },
    {
        "capability": "NDR (Network Detection & Response)",
        "example_vendors": ["Corelight", "Darktrace", "ExtraHop Reveal(x)"],
        "fills_gap_in_tactics": ["command-and-control", "lateral-movement"],
        "key_techniques": ["T1090", "T1572", "T1095", "T1550", "T1563"],
        "purpose": "adds protocol-level detection beyond NGFW policy",
    },
]


def fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def load_jsonl(rel: str) -> list[dict]:
    """Load a required JSONL input; a missing file or a malformed line is fatal."""
    p = ROOT / rel
    if not p.is_file():
        fail(f"{rel} not found (resolved from the repo root {ROOT})")
    records = []
    with open(p, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                fail(f"{rel}:{n}: invalid JSON ({e})")
    return records


def input_digest(rel: str) -> str:
    """sha256 of the file with line endings normalized to LF, so a Windows checkout
    (core.autocrlf) and a Linux checkout record the same hash."""
    data = (ROOT / rel).read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def pct(n: int, d: int) -> float:
    return round(n / d * 100, 1) if d else 0.0


def priority(group_count: int) -> str:
    if group_count >= 20:
        return "critical"
    if group_count >= 10:
        return "high"
    if group_count >= 3:
        return "medium"
    return "low"


def compute() -> dict:
    """Compute all score payloads in memory. Returns {filename: text}."""
    for rel in INPUTS:
        if not (ROOT / rel).is_file():
            fail(f"{rel} not found (resolved from the repo root {ROOT})")
    ids = AttackIds(ROOT)
    profiles = ids.profiles["enterprise"]
    live = ids.live["enterprise"]
    if not live:
        fail(f"{PROFILES} has no live technique rows")

    # technique -> v19.2 tactics, live techniques only
    tech_tactics: dict[str, list[str]] = {}
    for tid in sorted(live):
        tacs = profiles[tid].get("tactics") or []
        unknown = [t for t in tacs if t not in TACTIC_METADATA]
        if unknown:
            fail(f"{tid} has tactic(s) {unknown} not in the ATT&CK v{ATTACK_VERSION} tactic "
                 "table; update TACTIC_METADATA together with the re-pin")
        if not tacs:
            fail(f"{tid} is live but has no tactics in {PROFILES}")
        tech_tactics[tid] = list(tacs)
    by_tactic: dict[str, list[str]] = {t: [] for t in TACTIC_METADATA}
    for tid, tacs in tech_tactics.items():
        for t in tacs:
            by_tactic[t].append(tid)
    empty = [t for t, v in by_tactic.items() if not v]
    if empty:
        fail(f"no live techniques for tactic(s) {empty}; profiles are not ATT&CK v{ATTACK_VERSION}")

    # vendor -> covered live techniques (revoked ids resolved, aliases folded)
    v2t = load_jsonl(VENDOR_TO_TECHNIQUE)
    vendor_techs: dict[str, set] = defaultdict(set)
    display: dict[str, str] = {}
    aliases_seen: dict[str, set] = defaultdict(set)
    revoked_rows = 0
    for n, edge in enumerate(v2t, 1):
        raw = edge.get("attack_technique", "")
        key = edge.get("vendor_normalized", "")
        if not raw or not key:
            fail(f"{VENDOR_TO_TECHNIQUE}:{n}: missing attack_technique or vendor_normalized")
        tid = ids.resolve(raw)
        if tid is None:
            fail(f"{VENDOR_TO_TECHNIQUE}:{n}: {raw} is neither a live v{ATTACK_VERSION} "
                 "technique nor resolvable through superseded_by")
        if tid != raw:
            revoked_rows += 1
        canon = VENDOR_ALIASES.get(key, key)
        if canon != key:
            aliases_seen[canon].add(key)
        else:
            display[canon] = edge.get("vendor") or canon
        vendor_techs[canon].add(tid)
    unused = sorted(a for a, c in VENDOR_ALIASES.items() if a not in aliases_seen.get(c, ()))
    if unused:
        fail(f"VENDOR_ALIASES entries no longer present in the edge table: {unused}")
    missing_canon = sorted(c for c in aliases_seen if c not in display)
    if missing_canon:
        fail(f"alias targets with no edge rows of their own: {missing_canon}")

    covered = set().union(*vendor_techs.values())

    # ---- tactic coverage
    tactic_coverage = {}
    for tactic, meta in TACTIC_METADATA.items():
        universe = set(by_tactic[tactic])
        cov = universe & covered
        tactic_coverage[tactic] = {
            "name": meta["name"],
            "covered_techniques": sorted(cov),
            "covered_count": len(cov),
            "total_in_attack": len(universe),
            "coverage_pct_of_total": pct(len(cov), len(universe)),
            "gap_techniques": sorted(universe - covered),
            "weight": meta["weight"],
        }

    # ---- vendor coverage (sorted vendors, tactic keys in matrix order)
    vendor_coverage = {}
    for vendor in sorted(vendor_techs):
        techs = vendor_techs[vendor]
        dist = {}
        for tactic in TACTIC_METADATA:
            members = sorted(t for t in techs if tactic in tech_tactics[t])
            if members:
                dist[tactic] = members
        vendor_coverage[vendor] = {
            "vendor": display[vendor],
            "aliases": sorted(aliases_seen.get(vendor, ())),
            "technique_count": len(techs),
            "techniques": sorted(techs),
            "tactic_distribution": dist,
        }

    # ---- gaps: one entry per uncovered live technique
    gaps = []
    for tid in sorted(set(tech_tactics) - covered):
        p = profiles[tid]
        gaps.append({
            "technique_id": tid,
            "name": p.get("name", ""),
            "tactics": tech_tactics[tid],
            "tactic": tech_tactics[tid][0],
            "tactic_name": TACTIC_METADATA[tech_tactics[tid][0]]["name"],
            "group_count": int(p.get("group_count") or 0),
            "software_count": int(p.get("software_count") or 0),
            "campaign_count": int(p.get("campaign_count") or 0),
            "nist_control_depth": int(p.get("nist_control_count") or 0),
            "priority": priority(int(p.get("group_count") or 0)),
            "covered": False,
        })
    gaps.sort(key=lambda g: (-g["group_count"], -g["software_count"], -g["campaign_count"],
                             -g["nist_control_depth"], g["technique_id"]))
    depth_dist: dict[str, int] = defaultdict(int)
    for g in gaps:
        depth_dist[str(g["nist_control_depth"])] += 1
    priority_dist = {k: sum(1 for g in gaps if g["priority"] == k)
                     for k in ("critical", "high", "medium", "low")}

    # ---- recommendations with computed rationale
    recs = []
    for r in RECOMMENDATIONS:
        for t in r["fills_gap_in_tactics"]:
            if t not in TACTIC_METADATA:
                fail(f"recommendation {r['capability']!r}: unknown tactic {t}")
        fam_gaps = {}
        for k in r["key_techniques"]:
            if k not in live:
                fail(f"recommendation {r['capability']!r}: key technique {k} is not a live "
                     f"v{ATTACK_VERSION} technique (revoked? use its successor)")
            fam = sorted(t for t in tech_tactics if t == k or t.startswith(k + "."))
            fam_gaps[k] = {"family_size": len(fam),
                           "uncovered": sorted(t for t in fam if t not in covered)}
        tac_txt = ", ".join(
            f"{TACTIC_METADATA[t]['name']} {tactic_coverage[t]['coverage_pct_of_total']}% "
            f"({tactic_coverage[t]['covered_count']}/{tactic_coverage[t]['total_in_attack']})"
            for t in r["fills_gap_in_tactics"])
        open_fams = [k for k, v in fam_gaps.items() if v["uncovered"]]
        n_unc = sum(len(v["uncovered"]) for v in fam_gaps.values())
        fam_txt = (f"{len(open_fams)} of {len(fam_gaps)} key technique families have uncovered "
                   f"members ({n_unc} techniques: {', '.join(open_fams)})" if open_fams else
                   f"all {len(fam_gaps)} key technique families are fully covered")
        recs.append({
            "capability": r["capability"],
            "example_vendors": r["example_vendors"],
            "fills_gap_in_tactics": r["fills_gap_in_tactics"],
            "key_techniques": r["key_techniques"],
            "key_technique_gaps": fam_gaps,
            "rationale": f"Coverage today: {tac_txt}; {fam_txt}. Purpose: {r['purpose']}.",
        })

    gaps_output = {
        "generated_by": "scripts/compute_coverage.py",
        "attack_version": ATTACK_VERSION,
        "inputs_sha256": {rel: input_digest(rel) for rel in INPUTS},
        "coverage_definition": (
            "A technique is covered when at least one stack vendor satisfies a NIST 800-53 R5 "
            "control that the CTID mapping links to it (vendor_to_control JOIN "
            "control_to_technique, revoked ids carried forward to their live successor). It "
            "is control-mapping availability, not a measured detection or prevention."),
        "total_covered_techniques": len(covered),
        "total_technique_universe": len(tech_tactics),
        "total_vendor_stack_vendors": len(vendor_coverage),
        "vendor_aliases_folded": {a: VENDOR_ALIASES[a] for a in sorted(VENDOR_ALIASES)},
        "vendor_edge_rows": len(v2t),
        "vendor_edge_rows_on_revoked_ids": revoked_rows,
        "tactic_summary": {
            tactic: {
                "covered": data["covered_count"],
                "total": data["total_in_attack"],
                "pct": data["coverage_pct_of_total"],
            }
            for tactic, data in tactic_coverage.items()
        },
        "gap_count": len(gaps),
        "gap_nist_control_depth_distribution": dict(sorted(depth_dist.items(), key=lambda kv: int(kv[0]))),
        "gap_priority_distribution": priority_dist,
        "gap_ranking": GAP_RANKING,
        "priority_basis": PRIORITY_BASIS,
        "top_gaps": gaps[:TOP_GAPS],
        "recommended_additions": recs,
    }

    def dump(obj) -> str:
        return json.dumps(obj, indent=2) + "\n"

    return {
        "tactic_coverage.json": dump(tactic_coverage),
        "vendor_coverage.json": dump(vendor_coverage),
        "coverage_gaps.json": dump(gaps_output),
        "coverage_gaps.md": render_md(gaps_output, tactic_coverage, vendor_coverage, gaps),
    }, tactic_coverage


def _tech_link(tid: str) -> str:
    return f"[{tid}](/mitre/techniques/{tid.replace('.', '-')}.md)"


def render_md(g: dict, tactic_coverage: dict, vendor_coverage: dict, gaps: list) -> str:
    """Render scores/coverage_gaps.md from the coverage_gaps.json payload of the same run."""
    L = []
    a = L.append
    total, cov = g["total_technique_universe"], g["total_covered_techniques"]
    a("# Coverage Gap Analysis: TeamStarWolf Vendor Stack")
    a("")
    a("<!-- Generated by scripts/compute_coverage.py from scores/coverage_gaps.json. "
      "Do not edit by hand: edit the script or the data and re-run it. -->")
    a("")
    a(f"Generated by `scripts/compute_coverage.py` against ATT&CK Enterprise v{g['attack_version']} "
      "from these inputs (sha256, first 12 hex digits):")
    a("")
    for rel, h in g["inputs_sha256"].items():
        a(f"- [`{rel}`](/{rel}) `{h[:12]}`")
    a("")
    a(f"Modeled stack ({g['total_vendor_stack_vendors']} products): "
      + ", ".join(sorted((v["vendor"] for v in vendor_coverage.values()), key=str.lower)) + ".")
    a("")
    a("## What \"covered\" means here")
    a("")
    a("A technique counts as covered when at least one stack product satisfies a NIST 800-53 R5 "
      "control that the [CTID NIST 800-53 R5 mapping](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings) "
      "links to it ([`data/vendor_to_technique.jsonl`](/data/vendor_to_technique.jsonl), the "
      "`vendor_to_control` x `control_to_technique` join). This measures control-mapping "
      "availability, not a tested detection or prevention. Mappings that CTID keyed on an ATT&CK id "
      "that v19 revoked are carried forward to the live successor through "
      "[`superseded_by.jsonl`](/data/attack/superseded_by.jsonl) "
      f"({g['vendor_edge_rows_on_revoked_ids']:,} of {g['vendor_edge_rows']:,} edge rows are keyed on a "
      "revoked id), so revoked ids are never counted as techniques.")
    a("")
    if g["vendor_aliases_folded"]:
        a("Products listed under two keys in the edge table are counted once: "
          + "; ".join(f"`{k}` -> `{v}`" for k, v in g["vendor_aliases_folded"].items()) + ".")
        a("")
    a(f"Overall: {cov:,} of the {total:,} live Enterprise v{g['attack_version']} techniques and "
      f"sub-techniques are covered ({cov / total * 100:.1f}%); {g['gap_count']:,} are not.")
    a("")
    a("To recompute: `python scripts/compute_coverage.py` (writes all four files in `scores/`; "
      "`--check` exits non-zero if they are stale).")
    a("")
    a("---")
    a("")
    a("## Tactic coverage summary")
    a("")
    a("| Tactic | Covered | Live techniques | Coverage % | Uncovered |")
    a("|---|---:|---:|---:|---:|")
    for t, d in tactic_coverage.items():
        a(f"| {d['name']} | {d['covered_count']} | {d['total_in_attack']} | "
          f"{d['coverage_pct_of_total']}% | {len(d['gap_techniques'])} |")
    a("")
    a("A technique in several tactics is counted in each, so the rows do not sum to the overall total. "
      "Per-tactic technique lists are in [`tactic_coverage.json`](/scores/tactic_coverage.json); per-product "
      "lists are in [`vendor_coverage.json`](/scores/vendor_coverage.json).")
    a("")
    a("---")
    a("")
    a("## Why the gaps are where they are")
    a("")
    dd = g["gap_nist_control_depth_distribution"]
    zero = dd.get("0", 0)
    a(f"Coverage is derived through NIST controls, so a gap means no stack product satisfies any "
      f"control mapped to the technique. Of the {g['gap_count']:,} uncovered techniques, {zero:,} have "
      "no CTID NIST 800-53 mapping at all (under their own id or a revoked predecessor), so no "
      "product can be credited for them through this join, whatever it actually does. "
      + ("Distribution of mapped controls across the gaps: "
         + ", ".join(f"{k} control{'s' if k != '1' else ''}: {v}" for k, v in dd.items()) + "."))
    a("")
    a("The gap list is therefore ranked by adversary use rather than by NIST depth "
      f"(`{g['gap_ranking']}`). Priority basis: {g['priority_basis']}. "
      "Gaps by priority: " + ", ".join(f"{k} {v}" for k, v in g["gap_priority_distribution"].items()) + ".")
    a("")
    a(f"### Top {len(g['top_gaps'])} uncovered techniques")
    a("")
    a("| # | Technique | Name | Tactics | Groups | Software | Campaigns | NIST controls | Priority |")
    a("|---:|---|---|---|---:|---:|---:|---:|---|")
    for i, x in enumerate(g["top_gaps"], 1):
        tacs = ", ".join(TACTIC_METADATA[t]["name"] for t in x["tactics"])
        a(f"| {i} | {_tech_link(x['technique_id'])} | {x['name']} | {tacs} | {x['group_count']} | "
          f"{x['software_count']} | {x['campaign_count']} | {x['nist_control_depth']} | {x['priority']} |")
    a("")
    a("---")
    a("")
    a("## Lowest-coverage tactics")
    a("")
    by_gap = {x["technique_id"]: x for x in gaps}
    lowest = sorted(tactic_coverage.items(), key=lambda kv: (kv[1]["coverage_pct_of_total"], kv[0]))[:4]
    for t, d in lowest:
        tg = sorted((by_gap[tid] for tid in d["gap_techniques"]),
                    key=lambda x: (-x["group_count"], -x["software_count"], x["technique_id"]))
        a(f"### {d['name']}: {d['coverage_pct_of_total']}% ({d['covered_count']} of {d['total_in_attack']})")
        a("")
        shown = tg[:10]
        a(f"{len(tg)} uncovered" + (f"; the {len(shown)} most used by documented groups:" if len(tg) > len(shown) else ":"))
        a("")
        a("| Technique | Name | Groups | Software | NIST controls |")
        a("|---|---|---:|---:|---:|")
        for x in shown:
            a(f"| {_tech_link(x['technique_id'])} | {x['name']} | {x['group_count']} | "
              f"{x['software_count']} | {x['nist_control_depth']} |")
        a("")
    a("---")
    a("")
    a("## Recommended capability additions")
    a("")
    a("The capabilities, example vendors and key technique families are editorial; the coverage "
      "figures are computed on each run.")
    a("")
    a("| Capability | Example vendors | Tactic coverage today | Key families with uncovered members |")
    a("|---|---|---|---|")
    for r in g["recommended_additions"]:
        tac = "; ".join(
            f"{TACTIC_METADATA[t]['name']} {tactic_coverage[t]['coverage_pct_of_total']}%"
            for t in r["fills_gap_in_tactics"])
        fams = [f"{k} ({len(v['uncovered'])}/{v['family_size']})"
                for k, v in r["key_technique_gaps"].items() if v["uncovered"]]
        a(f"| {r['capability']} | {', '.join(r['example_vendors'])} | {tac} | "
          f"{', '.join(fams) if fams else 'none'} |")
    a("")
    a("Family figures are uncovered/total techniques in the family (the technique and its sub-techniques).")
    a("")
    a("---")
    a("")
    a("## How to use this analysis")
    a("")
    a("1. Load the [TeamStarWolf Navigator layers](/navigator/) to see coverage on the matrix.")
    a("2. Run `python scripts/compute_coverage.py` after the edge tables change; it rewrites this page and the three JSON files.")
    a("3. Treat a gap here as \"no mapped control in the stack\", then confirm with real detection tests before building a business case.")
    a("4. As products are added to `data/vendor_to_control.jsonl`, rebuild the join with `python scripts/build_ctid_edges.py` and re-run this script.")
    a("5. Cross-reference [CONTROLS_MAPPING.md](/CONTROLS_MAPPING.md) to see which NIST controls a candidate product would satisfy.")
    a("")
    a("---")
    a("")
    a("## References")
    a("")
    a("- [Vendor to Control edges](/data/vendor_to_control.jsonl)")
    a("- [Control to Technique edges](/data/control_to_technique.jsonl)")
    a("- [Vendor to Technique derived edges](/data/vendor_to_technique.jsonl)")
    a("- [CTID NIST 800-53 R5 mappings](https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings)")
    a("- [ATT&CK Navigator layers](/navigator/)")
    a("- [Coverage Schema](/COVERAGE_SCHEMA.md)")
    return "\n".join(L) + "\n"


def main():
    parser = argparse.ArgumentParser(description="TeamStarWolf Coverage Gap Scorer")
    parser.add_argument("--output", default=None,
                        help="Output directory (default: scores/ at the repo root)")
    parser.add_argument("--check", action="store_true",
                        help="Do not write; exit 1 if the committed score files differ")
    parser.add_argument("--tactic", choices=sorted(TACTIC_METADATA),
                        help="Narrow the printed summary to one tactic (score files are always complete)")
    args = parser.parse_args()

    files, tactic_coverage = compute()
    out = Path(args.output) if args.output else ROOT / "scores"

    if args.check:
        stale = []
        for name, text in files.items():
            p = out / name
            have = p.read_bytes().replace(b"\r\n", b"\n").decode("utf-8") if p.is_file() else None
            if have != text:
                stale.append(name)
        if stale:
            print(f"STALE: {', '.join(stale)} in {out} - run python scripts/compute_coverage.py")
            sys.exit(1)
        print(f"OK: {len(files)} score files in {out} match the data")
        return

    out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        with open(out / name, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(f"Written: {out / name}")

    selected = [args.tactic] if args.tactic else list(tactic_coverage)
    print("\n=== COVERAGE SUMMARY ===")
    print(f"{'Tactic':<30} {'Covered':>8} {'Total':>8} {'Pct':>8}")
    print("-" * 58)
    for tactic in selected:
        data = tactic_coverage[tactic]
        print(f"{data['name']:<30} {data['covered_count']:>8} {data['total_in_attack']:>8} {data['coverage_pct_of_total']:>7}%")
    if args.tactic:
        gaps = tactic_coverage[args.tactic]["gap_techniques"]
        print(f"\nUncovered techniques in {tactic_coverage[args.tactic]['name']} ({len(gaps)}):")
        for tech in gaps:
            print(f"  {tech}")


if __name__ == "__main__":
    main()
