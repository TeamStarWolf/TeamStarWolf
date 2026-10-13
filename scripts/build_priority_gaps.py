#!/usr/bin/env python3
"""
TeamStarWolf ATT&CK priority-gap ranking + analytics Navigator layers.

Derives, from the committed ATT&CK v19.2 data and the CTID NIST 800-53 R5 edge table:

    scores/attack_priority_gaps.json              ranked list + per-tactic coverage
    scores/attack_priority_gaps.md                the page, rendered from the same run
    navigator/analytics/group_frequency.json      Enterprise: techniques by group usage
    navigator/analytics/no_nist_coverage.json     Enterprise: techniques with no NIST control
    navigator/analytics/ics_group_frequency.json  ICS: techniques by group usage
    navigator/analytics/mobile_group_frequency.json  Mobile: techniques by group usage

Usage:
    python scripts/build_priority_gaps.py           # rewrite the six files
    python scripts/build_priority_gaps.py --check   # exit 1 if any committed file is stale

Every number is computed from the data on each run (nothing is hand-maintained) and the
output is byte-for-byte deterministic: no wall-clock date is stamped, the inputs'
content hashes are recorded instead.

Per-technique counts come from the edge tables (group_to_technique, software_to_technique,
mitigation_to_technique, control_to_technique). An edge keyed on an ATT&CK id that v19
revoked is resolved to its live successor through data/attack/superseded_by.jsonl (the
same rule as scripts/attack_ids.py), so a revoked id is never ranked, never placed in a
layer, and its usage counts under the successor. The derived counts must equal the
technique_profiles.jsonl fields of the same name; a mismatch means the profiles are stale
and is fatal (re-run scripts/build_attack_core.py / scripts/build_control_rollup.py).

Priority = group_count * (1 + 1 / (nist_control_count + 1)): technique usage amplified
by inverse NIST control depth. Ties are broken by technique id.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path

from attack_ids import AttackIds
from compute_coverage import ATTACK_VERSION, TACTIC_METADATA, repo_href

ROOT = Path(__file__).resolve().parents[1]

# Navigator layers are pinned to the ATT&CK major release the data was built from.
NAVIGATOR_ATTACK = ATTACK_VERSION.split(".")[0]
NAVIGATOR_VERSIONS = {"attack": NAVIGATOR_ATTACK, "navigator": "4.9", "layer": "4.5"}

TOP_N = 75

ENTERPRISE_INPUTS = (
    "data/attack/technique_profiles.jsonl",
    "data/attack/superseded_by.jsonl",
    "data/attack/group_to_technique.jsonl",
    "data/attack/software_to_technique.jsonl",
    "data/attack/mitigation_to_technique.jsonl",
    "data/control_to_technique.jsonl",
)

# ICS and Mobile tactic shortnames in ATT&CK v19.2 (from the v19.2 STIX bundles, matrix
# order). Enterprise uses compute_coverage.TACTIC_METADATA (Stealth TA0005 and Defense
# Impairment TA0112 in place of the retired Defense Evasion). Mobile v19.2 still has
# defense-evasion and ICS has evasion; neither domain took the Enterprise split.
ICS_TACTICS = (
    "initial-access", "execution", "persistence", "privilege-escalation", "evasion",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "inhibit-response-function", "impair-process-control", "impact",
)
MOBILE_TACTICS = (
    "initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
)

DOMAINS = {
    "ics": {
        "label": "ICS",
        "navigator_domain": "ics-attack",
        "tactics": ICS_TACTICS,
        "profiles": "data/attack/ics/technique_profiles.jsonl",
        "edges": "data/attack/ics/group_to_technique.jsonl",
        "out": "navigator/analytics/ics_group_frequency.json",
    },
    "mobile": {
        "label": "Mobile",
        "navigator_domain": "mobile-attack",
        "tactics": MOBILE_TACTICS,
        "profiles": "data/attack/mobile/technique_profiles.jsonl",
        "edges": "data/attack/mobile/group_to_technique.jsonl",
        "out": "navigator/analytics/mobile_group_frequency.json",
    },
}

# Navigator chrome shared by every layer (unchanged from the hand-exported layers).
LAYER_CHROME = {
    "sorting": 3,
    "layout": {
        "layout": "side",
        "aggregateFunction": "max",
        "showID": False,
        "showName": True,
        "showAggregateScores": True,
        "countUnscored": False,
    },
    "hideDisabled": True,
}
LAYER_TAIL = {
    "showTacticRowBackground": True,
    "tacticRowBackground": "#205b8f",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False,
}
BLUES = ["#f7fbff", "#4292c6", "#08306b"]
REDS = ["#fff5f0", "#fb6a4a", "#67000d"]

GENERATED_BY = "scripts/build_priority_gaps.py"
RISK_LENS = "/ATTACK_MATRIX_ANALYSIS_REFERENCE.md#lens-family-5-breach-patterns-amp-composite-risk"


def fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(2)


def load_jsonl(rel: str) -> list[dict]:
    p = ROOT / rel
    if not p.is_file():
        fail(f"{rel} not found (resolved from the repo root {ROOT})")
    rows = []
    with open(p, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                fail(f"{rel}:{n}: invalid JSON ({e})")
    return rows


def input_digest(rel: str) -> str:
    """sha256 with line endings normalized to LF (Windows autocrlf == Linux checkout)."""
    return hashlib.sha256((ROOT / rel).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def pct(n: int, d: int) -> float:
    return round(n / d * 100, 1) if d else 0.0


def edge_sets(ids: AttackIds, rel: str, tech_key: str, src_key: str,
              domain: str = "enterprise") -> dict[str, set]:
    """technique -> distinct sources, with revoked ids resolved to their live successor."""
    out: dict[str, set] = defaultdict(set)
    for n, row in enumerate(load_jsonl(rel), 1):
        raw, src = row.get(tech_key), row.get(src_key)
        if not raw or not src:
            fail(f"{rel}:{n}: missing {tech_key} or {src_key}")
        tid = ids.resolve(raw, domain)
        if tid is None:
            fail(f"{rel}:{n}: {raw} is neither a live {domain} technique nor resolvable "
                 "through data/attack/superseded_by.jsonl")
        out[tid].add(src)
    return out


def dump_json(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- enterprise
def enterprise(ids: AttackIds) -> tuple[list[dict], dict]:
    profiles = ids.profiles["enterprise"]
    live = sorted(ids.live["enterprise"])
    if not live:
        fail("data/attack/technique_profiles.jsonl has no live technique rows")

    counts = {
        "group_count": edge_sets(ids, "data/attack/group_to_technique.jsonl", "technique_id", "group_id"),
        "software_count": edge_sets(ids, "data/attack/software_to_technique.jsonl", "technique_id", "software_id"),
        "mitigation_count": edge_sets(ids, "data/attack/mitigation_to_technique.jsonl", "technique_id", "mitigation_id"),
        "nist_control_count": edge_sets(ids, "data/control_to_technique.jsonl", "attack_technique", "nist_control"),
    }
    stray = sorted(set().union(*(set(c) for c in counts.values())) - set(live))
    if stray:
        fail(f"edges resolve to non-live ids {stray[:10]}")

    rows = []
    for tid in live:
        p = profiles[tid]
        tacs = p.get("tactics") or []
        if not tacs:
            fail(f"{tid} is live but has no tactics")
        unknown = [t for t in tacs if t not in TACTIC_METADATA]
        if unknown:
            fail(f"{tid} has tactic(s) {unknown} not in the ATT&CK v{ATTACK_VERSION} Enterprise "
                 "tactic table (compute_coverage.TACTIC_METADATA)")
        row = {"technique_id": tid, "name": p.get("name", ""), "tactics": list(tacs)}
        for field, edges in counts.items():
            n = len(edges.get(tid, ()))
            if int(p.get(field) or 0) != n:
                fail(f"{tid}: {field} is {p.get(field)} in technique_profiles.jsonl but the edge "
                     f"tables give {n}; the profiles are stale (re-run scripts/build_attack_core.py "
                     "and scripts/build_control_rollup.py)")
            row[field] = n
        row["has_detection_strategy"] = bool(p.get("has_detection_strategy"))
        rows.append(row)
    return rows, counts


def priority(row: dict) -> Fraction:
    g, n = row["group_count"], row["nist_control_count"]
    return g * (1 + Fraction(1, n + 1))


def build_scores(rows: list[dict]) -> dict:
    ranked = sorted((r for r in rows if r["group_count"] > 0),
                    key=lambda r: (-priority(r), r["technique_id"]))
    top = []
    for r in ranked[:TOP_N]:
        top.append({
            "technique_id": r["technique_id"],
            "name": r["name"],
            "tactics": r["tactics"],
            "group_count": r["group_count"],
            "software_count": r["software_count"],
            "nist_control_count": r["nist_control_count"],
            "mitigation_count": r["mitigation_count"],
            "has_detection_strategy": r["has_detection_strategy"],
            "priority_score": round(float(priority(r)), 2),
        })
    tactic_cov = {}
    for tactic, meta in TACTIC_METADATA.items():
        members = [r for r in rows if tactic in r["tactics"]]
        if not members:
            fail(f"no live techniques for tactic {tactic}; profiles are not ATT&CK v{ATTACK_VERSION}")
        tactic_cov[tactic] = {
            "name": meta["name"],
            "techniques": len(members),
            "with_nist_control": sum(1 for r in members if r["nist_control_count"] > 0),
            "with_attack_mitigation": sum(1 for r in members if r["mitigation_count"] > 0),
            "with_detection_strategy": sum(1 for r in members if r["has_detection_strategy"]),
        }
    no_nist = [r for r in rows if r["nist_control_count"] == 0]
    return {
        "generated_by": GENERATED_BY,
        "attack_version": ATTACK_VERSION,
        "generated_from": f"MITRE ATT&CK Enterprise v{ATTACK_VERSION} + CTID NIST 800-53 R5",
        "inputs_sha256": {rel: input_digest(rel) for rel in ENTERPRISE_INPUTS},
        "formula": "priority = group_count * (1 + 1/(nist_control_count+1))",
        "ranking": "priority desc, technique_id; techniques with group_count 0 are not ranked",
        "revoked_ids": ("never ranked; edges keyed on a revoked id are counted under the live "
                        "successor from data/attack/superseded_by.jsonl"),
        "live_technique_count": len(rows),
        "ranked_technique_count": len(ranked),
        "no_nist_control_count": len(no_nist),
        "tactic_coverage": tactic_cov,
        "top_priority_techniques": top,
    }


def tech_link(tid: str, name: str) -> str:
    return f"[{tid} {name}](/mitre/techniques/{tid.replace('.', '-')}.md)"


def render_md(s: dict) -> str:
    L: list[str] = []
    a = L.append
    v = s["attack_version"]
    a("# ATT&CK Priority Gap Analysis")
    a("")
    a(f"<!-- Generated by {GENERATED_BY} from the ATT&CK v{v} data and edge tables. "
      "Do not edit by hand: edit the script or the data and re-run it. -->")
    a("")
    a(f"> A data-driven prioritization of MITRE ATT&CK Enterprise techniques (v{v}), combining how "
      "often adversaries use a technique (tracked threat-group count) with how thinly the control "
      "framework covers it (NIST 800-53 R5 control depth). The result surfaces the techniques that "
      "are both widely used and under-covered: the behaviors most worth detection and mitigation "
      "investment.")
    a("")
    a("| | |")
    a("|---|---|")
    a("| Read this when | deciding which ATT&CK techniques to invest detection or mitigation effort "
      "in next, justifying control gaps against NIST 800-53 coverage, building a threat-informed "
      "roadmap from real adversary usage |")
    a(f"| Start at | [Top {TOP_N} priority techniques](#top-{TOP_N}-priority-techniques), "
      "[Coverage by tactic](#coverage-by-tactic), [How to use this](#how-to-use-this) |")
    a("| Pairs with | [ATTACK_MATRIX_ANALYSIS_REFERENCE.md](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md), "
      "[detections/TECHNIQUE_DETECTION_LIBRARY.md](/detections/TECHNIQUE_DETECTION_LIBRARY.md) |")
    a("")
    a("Priority score = `group_count × (1 + 1 / (nist_control_count + 1))`, the same "
      f"inverse-coverage weighting as the [Risk lens]({RISK_LENS}). Machine-readable: "
      f"[`scores/attack_priority_gaps.json`]({repo_href('scores/attack_priority_gaps.json')}).")
    a("")
    a(f"Generated by `{GENERATED_BY}` from these inputs (sha256, first 12 hex digits); "
      "`--check` exits non-zero when this page or its layers are stale:")
    a("")
    for rel, h in s["inputs_sha256"].items():
        a(f"- [`{rel}`]({repo_href(rel)}) `{h[:12]}`")
    a("")
    a(f"Only live v{v} techniques are counted. A group, software, mitigation or NIST control edge "
      f"keyed on an id that ATT&CK v{v.split('.')[0]} revoked is counted under the live successor "
      f"recorded in [`superseded_by.jsonl`]({repo_href('data/attack/superseded_by.jsonl')}) (for example, the CTID "
      "NIST 800-53 mappings keyed on the revoked T1562.001 count under T1685), so a revoked id "
      "never appears in the ranking.")
    a("")
    a("## Coverage by tactic")
    a("")
    a("| Tactic | Techniques | With NIST control | With ATT&CK mitigation | With detection strategy |")
    a("|---|--:|--:|--:|--:|")
    for t in s["tactic_coverage"].values():
        n = t["techniques"]
        a(f"| {t['name']} | {n} | {t['with_nist_control']} ({pct(t['with_nist_control'], n)}%) | "
          f"{t['with_attack_mitigation']} ({pct(t['with_attack_mitigation'], n)}%) | "
          f"{t['with_detection_strategy']} ({pct(t['with_detection_strategy'], n)}%) |")
    a("")
    a("A technique in several tactics is counted in each, so the rows do not sum to the live total.")
    a("")
    a(f"> {s['no_nist_control_count']} of the {s['live_technique_count']} live Enterprise v{v} "
      "techniques have no mapped NIST 800-53 control, under their own id or a revoked predecessor's; "
      f"see the [framework blind-spots Navigator layer]({repo_href('navigator/analytics/no_nist_coverage.json')}). "
      "The CTID mapping targets ATT&CK v16.1, so a technique added since then that does not "
      "succeed a mapped id has no control mapping by construction.")
    a("")
    a(f"## Top {TOP_N} priority techniques")
    a("")
    a("Most-used, least-covered first; ties are broken by technique id. Load the companion "
      f"[group-frequency heatmap]({repo_href('navigator/analytics/group_frequency.json')}) in ATT&CK Navigator "
      "to see the full matrix.")
    a("")
    a("| # | Technique | Tactic(s) | Groups | Software | NIST | Mitig | Det | Priority |")
    a("|--:|---|---|--:|--:|--:|--:|:--:|--:|")
    for i, r in enumerate(s["top_priority_techniques"], 1):
        tacs = ", ".join(TACTIC_METADATA[t]["name"] for t in r["tactics"])
        a(f"| {i} | {tech_link(r['technique_id'], r['name'])} | {tacs} | {r['group_count']} | "
          f"{r['software_count']} | {r['nist_control_count']} | {r['mitigation_count']} | "
          f"{'Yes' if r['has_detection_strategy'] else 'No'} | {r['priority_score']} |")
    a("")
    a("---")
    a("")
    a("### How to use this")
    a("")
    a("1. Start at the top: these techniques combine heavy real-world use with thin control coverage.")
    a("2. For each, pull its detections from the [Technique Detection Library]"
      "(/detections/TECHNIQUE_DETECTION_LIBRARY.md) (or write them), validate with "
      "[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), and add compensating "
      "controls where NIST coverage is thin.")
    a(f"3. Track closure over time: after the data changes, run `python {GENERATED_BY}` to "
      "regenerate this page, its JSON and the analytics Navigator layers.")
    a("")
    a(f"*Source: MITRE ATT&CK Enterprise v{v} (STIX) + CTID NIST 800-53 R5 -> ATT&CK mappings. "
      "Priority is a coverage heuristic, not a substitute for environment-specific risk "
      "assessment.*")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- layers
def layer(name: str, domain: str, description: str, colors: list[str], max_value: int,
          legend: list[tuple[str, str]], metadata: list[tuple[str, str]],
          techniques: list[dict]) -> dict:
    out = {"name": name, "versions": dict(NAVIGATOR_VERSIONS), "domain": domain,
           "description": description}
    out.update(json.loads(json.dumps(LAYER_CHROME)))
    out["gradient"] = {"colors": colors, "minValue": 0, "maxValue": max_value}
    out["legendItems"] = [{"label": lab, "color": col} for lab, col in legend]
    out["metadata"] = [{"name": k, "value": val} for k, val in metadata]
    out.update(LAYER_TAIL)
    out["techniques"] = techniques
    return out


def enterprise_layers(rows: list[dict]) -> dict[str, str]:
    v = ATTACK_VERSION
    used = [r for r in rows if r["group_count"] > 0]
    gmax = max(r["group_count"] for r in used)
    freq = layer(
        "ATT&CK Technique Frequency - Threat Group Usage", "enterprise-attack",
        f"The {len(used)} ATT&CK Enterprise v{v} techniques used by at least one tracked threat "
        "group, colored by the number of groups observed using them. High-frequency techniques are "
        "the most broadly adopted adversary behaviors and are strong candidates for detection and "
        f"mitigation investment. Revoked ids are excluded (their usage counts under the live "
        f"successor). Source: MITRE ATT&CK Enterprise v{v} group-to-technique relationships. "
        f"Generated by {GENERATED_BY}.",
        BLUES, gmax,
        [("used by few groups", BLUES[0]),
         ("used by many groups (top adversary behaviors)", BLUES[2])],
        [("source", f"MITRE ATT&CK Enterprise v{v}"), ("generated_by", GENERATED_BY),
         ("techniques_scored", str(len(used))), ("max_group_count", str(gmax))],
        [{"techniqueID": r["technique_id"], "score": r["group_count"],
          "comment": (f"{plural(r['group_count'], 'threat group')} and "
                      f"{r['software_count']} software use this. "
                      f"{plural(r['nist_control_count'], 'NIST control')}, "
                      f"{plural(r['mitigation_count'], 'ATT&CK mitigation')}.")}
         for r in used])

    blind = [r for r in rows if r["nist_control_count"] == 0]
    bmax = max(r["group_count"] for r in blind) + 1
    nonist = layer(
        "ATT&CK Framework Blind Spots - No NIST 800-53 Coverage", "enterprise-attack",
        f"The {len(blind)} live ATT&CK Enterprise v{v} techniques with NO mapped NIST 800-53 R5 "
        "control (CTID), under their own id or a revoked predecessor's. These are framework blind "
        "spots that cannot be addressed by control coverage alone and require compensating "
        "detection, architecture, or process controls. Score = threat groups using the technique "
        "+ 1, so darker = used by more groups (higher priority) and every blind spot is shaded. "
        "The CTID mapping targets ATT&CK v16.1, so techniques added since then that do not succeed "
        f"a mapped id have no mapping by construction. Source: MITRE ATT&CK Enterprise v{v} + CTID "
        f"NIST 800-53 R5 mappings. Generated by {GENERATED_BY}.",
        REDS, bmax,
        [("blind spot, few groups", REDS[0]), ("blind spot, many groups (priority)", REDS[2])],
        [("source", f"MITRE ATT&CK Enterprise v{v} + CTID NIST 800-53 R5"),
         ("generated_by", GENERATED_BY), ("blind_spot_count", str(len(blind)))],
        [{"techniqueID": r["technique_id"], "score": r["group_count"] + 1,
          "comment": ("NO NIST 800-53 control maps to this technique (framework blind spot). "
                      f"Used by {plural(r['group_count'], 'group')}, {r['software_count']} software. "
                      f"ATT&CK mitigations: {r['mitigation_count']}. "
                      + ("ATT&CK detection strategy available." if r["has_detection_strategy"]
                         else "No ATT&CK detection strategy."))}
         for r in blind])
    return {"navigator/analytics/group_frequency.json": dump_json(freq),
            "navigator/analytics/no_nist_coverage.json": dump_json(nonist)}


def domain_layer(ids: AttackIds, key: str) -> tuple[str, str, list[str]]:
    cfg = DOMAINS[key]
    profiles = ids.profiles[key]
    live = sorted(ids.live[key])
    if not live:
        fail(f"{cfg['profiles']} has no live technique rows")
    groups = edge_sets(ids, cfg["edges"], "technique_id", "group_id", key)
    rows = []
    for tid in live:
        p = profiles[tid]
        unknown = [t for t in (p.get("tactics") or []) if t not in cfg["tactics"]]
        if unknown:
            fail(f"{cfg['label']} {tid} has tactic(s) {unknown} not in the ATT&CK "
                 f"v{ATTACK_VERSION} {cfg['label']} tactic table")
        n = len(groups.get(tid, ()))
        if int(p.get("group_count") or 0) != n:
            fail(f"{cfg['label']} {tid}: group_count is {p.get('group_count')} in "
                 f"{cfg['profiles']} but {cfg['edges']} gives {n}")
        if n:
            rows.append((tid, n, int(p.get("software_count") or 0), int(p.get("mitigation_count") or 0)))
    gmax = max(n for _, n, _, _ in rows)
    lbl = cfg["label"]
    lay = layer(
        f"{lbl} ATT&CK - Threat Group Frequency", cfg["navigator_domain"],
        f"The {len(rows)} MITRE ATT&CK for {lbl} techniques used by at least one tracked threat "
        f"group, colored by the number of groups using them. Source: {cfg['edges']} (ATT&CK "
        f"for {lbl}, rendered against ATT&CK v{NAVIGATOR_ATTACK}). Generated by {GENERATED_BY}.",
        BLUES, gmax,
        [("few groups", BLUES[0]), ("many groups", BLUES[2])],
        [("source", f"MITRE ATT&CK for {lbl} ({cfg['edges']})"), ("generated_by", GENERATED_BY),
         ("techniques_scored", str(len(rows))), ("max_group_count", str(gmax))],
        [{"techniqueID": tid, "score": n,
          "comment": (f"{plural(n, 'threat group')} and {sw} software use this. "
                      f"{plural(mit, 'ATT&CK mitigation')}.")}
         for tid, n, sw, mit in rows])
    return cfg["out"], dump_json(lay), [cfg["profiles"], cfg["edges"]]


def compute() -> dict[str, str]:
    ids = AttackIds(ROOT)
    rows, _ = enterprise(ids)
    scores = build_scores(rows)
    files = {
        "scores/attack_priority_gaps.json": dump_json(scores),
        "scores/attack_priority_gaps.md": render_md(scores),
    }
    files.update(enterprise_layers(rows))
    for key in DOMAINS:
        rel, text, _ = domain_layer(ids, key)
        files[rel] = text
    # every layer's declared count must equal its entry count
    for rel, text in files.items():
        if not rel.startswith("navigator/"):
            continue
        d = json.loads(text)
        meta = {m["name"]: m["value"] for m in d["metadata"]}
        declared = meta.get("techniques_scored", meta.get("blind_spot_count"))
        tids = [t["techniqueID"] for t in d["techniques"]]
        if len(tids) != len(set(tids)) or int(declared) != len(tids) \
                or not d["description"].startswith(("The " + declared + " ")):
            fail(f"{rel}: declared count {declared} does not match its {len(tids)} entries")
    return files


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="write nothing; exit 1 if any committed output differs")
    args = ap.parse_args()
    files = compute()
    if args.check:
        stale = []
        for rel, text in files.items():
            p = ROOT / rel
            have = p.read_bytes().replace(b"\r\n", b"\n").decode("utf-8") if p.is_file() else None
            if have != text:
                stale.append(rel)
        if stale:
            print(f"STALE: {', '.join(stale)} - run python {GENERATED_BY}")
            sys.exit(1)
        print(f"OK: {len(files)} priority-gap files match the data")
        return
    for rel, text in files.items():
        p = ROOT / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(f"Written: {rel}")


if __name__ == "__main__":
    main()
