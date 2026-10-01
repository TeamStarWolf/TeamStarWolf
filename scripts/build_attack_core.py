#!/usr/bin/env python3
r"""
Regenerate the ATT&CK core JSONL from the authoritative MITRE ATT&CK v19.2
enterprise STIX bundle.

This is the audit's #1 remediation ("re-pin the ATT&CK core to v19.2 end to
end"). It (over)writes eight files under data/attack/ from a single source of
truth, and patches technique_profiles.jsonl in place (tactics + revoked flag)
without disturbing its downstream enrichment.

Source of truth (immutable — the "-19.2" filename pins the content):
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json

Offline / CI override: set env ATTACK_STIX_PATH=<file> or pass --stix <file>.
    python scripts/build_attack_core.py --stix .stix-cache-enterprise-19.2.json

Every file is opened with encoding="utf-8" (the STIX is UTF-8; the Windows
cp1252 default crashes on it). Output is deterministic: each file is sorted by
its primary id (edge tables by their (source, target) tuple) and written as
one JSON object per line, CRLF-terminated with a trailing newline, matching the
existing data/attack/*.jsonl files exactly.

Generated files:
    groups.jsonl                    software.jsonl              campaigns.jsonl
    group_to_technique.jsonl        software_to_technique.jsonl
    mitigation_to_technique.jsonl   detection_strategies.jsonl analytics.jsonl
Patched in place:
    technique_profiles.jsonl        (tactics re-pinned + revoked flags; all
                                     other fields and row order preserved)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "attack"

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-19.2.json"
)

ATTACK = "mitre-attack"


# --------------------------------------------------------------------------- #
# STIX loading + helpers
# --------------------------------------------------------------------------- #
def load_stix(path: str | None) -> list[dict]:
    """Load the STIX bundle's `objects`. Prefer an explicit path/env override;
    otherwise fetch the pinned immutable URL."""
    src = path or os.environ.get("ATTACK_STIX_PATH")
    if src:
        print(f"[build_attack_core] reading STIX from {src}", file=sys.stderr)
        with open(src, encoding="utf-8") as f:
            bundle = json.load(f)
    else:
        print(f"[build_attack_core] fetching STIX from {STIX_URL}", file=sys.stderr)
        req = urllib.request.Request(STIX_URL, headers={"User-Agent": "attack-lib-v19/build_attack_core"})
        with urllib.request.urlopen(req) as resp:  # noqa: S310 (fixed, trusted URL)
            bundle = json.loads(resp.read().decode("utf-8"))
    return bundle["objects"]


def is_active(o: dict) -> bool:
    """A STIX object is ACTIVE iff NOT revoked and NOT x_mitre_deprecated."""
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def attack_ref(o: dict) -> dict | None:
    """The object's mitre-attack external_reference (carries the ATT&CK id/url)."""
    for e in o.get("external_references", []):
        if e.get("source_name") == ATTACK:
            return e
    return None


def attack_id(o: dict) -> str | None:
    ref = attack_ref(o)
    return ref.get("external_id") if ref else None


def attack_url(o: dict) -> str | None:
    ref = attack_ref(o)
    return ref.get("url") if ref else None


def technique_tactics(ap: dict) -> list[str]:
    """A technique's v19.2 tactic shortnames (kill-chain phase names), in STIX order."""
    return [
        p["phase_name"]
        for p in ap.get("kill_chain_phases", [])
        if p.get("kill_chain_name") == ATTACK
    ]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    """Deterministic JSONL writer: UTF-8, CRLF line endings, trailing newline."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\r\n")
    print(f"[build_attack_core] wrote {path.relative_to(ROOT)}  ({len(rows)} rows)", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Index construction
# --------------------------------------------------------------------------- #
class Index:
    def __init__(self, objs: list[dict]):
        self.objs = objs
        self.by_id = {o["id"]: o for o in objs}

        self.ap = [o for o in objs if o["type"] == "attack-pattern"]
        self.ap_by_id = {o["id"]: o for o in self.ap}
        self.ap_active_ids = {o["id"] for o in self.ap if is_active(o)}

        self.groups_active = [o for o in objs if o["type"] == "intrusion-set" and is_active(o)]
        self.software_active = [o for o in objs if o["type"] in ("malware", "tool") and is_active(o)]
        self.software_active_ids = {o["id"] for o in self.software_active}
        self.campaigns = [o for o in objs if o["type"] == "campaign" and is_active(o)]

        # M-code course-of-action only (external_id starts with "M"), active.
        self.mitigations = [
            o for o in objs
            if o["type"] == "course-of-action" and is_active(o)
            and str(attack_id(o) or "").startswith("M")
        ]

        self.analytics = [o for o in objs if o["type"] == "x-mitre-analytic" and is_active(o)]
        self.analytic_by_id = {o["id"]: o for o in objs if o["type"] == "x-mitre-analytic"}
        self.strategies = [o for o in objs if o["type"] == "x-mitre-detection-strategy" and is_active(o)]
        self.data_component_by_id = {o["id"]: o for o in objs if o["type"] == "x-mitre-data-component"}

        # revoked-by: revoked attack-pattern -> successor attack-pattern
        self.revoked_by: dict[str, str] = {}
        for o in objs:
            if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
                s, t = o["source_ref"], o["target_ref"]
                if s.startswith("attack-pattern--") and t.startswith("attack-pattern--"):
                    self.revoked_by[s] = t

        # detects: detection-strategy -> technique (strategy detects exactly one)
        self.detects: dict[str, str] = {}
        for o in objs:
            if o["type"] == "relationship" and o.get("relationship_type") == "detects" and is_active(o):
                self.detects[o["source_ref"]] = o["target_ref"]

    def resolve_technique(self, ref: str) -> str | None:
        """Follow revoked-by transitively to a non-revoked successor attack-pattern
        ref. Returns the terminal ref (may still be deprecated) or None."""
        seen = set()
        while ref in self.revoked_by and ref not in seen:
            seen.add(ref)
            ref = self.revoked_by[ref]
        return ref

    def resolve_to_active(self, ref: str) -> str | None:
        """Resolve a technique ref to an ACTIVE attack-pattern ref (translating a
        revoked target to its successor); None if it cannot resolve to an active
        technique (e.g. deprecated-but-not-revoked, no successor)."""
        ref = self.resolve_technique(ref)
        return ref if ref in self.ap_active_ids else None


# --------------------------------------------------------------------------- #
# Relationship gathering
# --------------------------------------------------------------------------- #
def uses_pairs(idx: Index):
    """All active `uses` relationships as (source_ref, target_ref)."""
    for o in idx.objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "uses" and is_active(o):
            yield o["source_ref"], o["target_ref"]


def mitigates_pairs(idx: Index):
    for o in idx.objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "mitigates" and is_active(o):
            yield o["source_ref"], o["target_ref"]


# --------------------------------------------------------------------------- #
# File builders
# --------------------------------------------------------------------------- #
def build_edge_maps(idx: Index):
    """Precompute, for each source entity, the set of active techniques it
    targets (revoked translated), plus group<->software adjacency."""
    group_tech: dict[str, set] = {}
    group_sw: dict[str, set] = {}
    sw_tech: dict[str, set] = {}
    sw_groups: dict[str, set] = {}
    camp_tech: dict[str, set] = {}
    mit_tech: dict[str, set] = {}

    group_ids = {o["id"] for o in idx.groups_active}
    camp_ids = {o["id"] for o in idx.campaigns}
    mit_ids = {o["id"] for o in idx.mitigations}

    for src, tgt in uses_pairs(idx):
        if tgt.startswith("attack-pattern--"):
            at = idx.resolve_to_active(tgt)
            if at is None:
                continue
            if src in group_ids:
                group_tech.setdefault(src, set()).add(at)
            elif src in idx.software_active_ids:
                sw_tech.setdefault(src, set()).add(at)
            elif src in camp_ids:
                camp_tech.setdefault(src, set()).add(at)
        elif tgt in idx.software_active_ids and src in group_ids:
            group_sw.setdefault(src, set()).add(tgt)
            sw_groups.setdefault(tgt, set()).add(src)

    for src, tgt in mitigates_pairs(idx):
        if src in mit_ids and tgt.startswith("attack-pattern--"):
            at = idx.resolve_to_active(tgt)
            if at is not None:
                mit_tech.setdefault(src, set()).add(at)

    return {
        "group_tech": group_tech, "group_sw": group_sw,
        "sw_tech": sw_tech, "sw_groups": sw_groups,
        "camp_tech": camp_tech, "mit_tech": mit_tech,
    }


def build_groups(idx: Index, m) -> list[dict]:
    rows = []
    for g in idx.groups_active:
        gid = attack_id(g)
        rows.append({
            "group_id": gid,
            "name": g.get("name"),
            "aliases": g.get("aliases", []),
            "technique_count": len(m["group_tech"].get(g["id"], ())),
            "software_count": len(m["group_sw"].get(g["id"], ())),
            "url": attack_url(g),
            "description": g.get("description", ""),
        })
    return sorted(rows, key=lambda r: r["group_id"])


def build_software(idx: Index, m) -> list[dict]:
    rows = []
    for s in idx.software_active:
        rows.append({
            "software_id": attack_id(s),
            "name": s.get("name"),
            "type": "malware" if s["type"] == "malware" else "tool",
            "platforms": s.get("x_mitre_platforms", []),
            "aliases": s.get("x_mitre_aliases", []),
            "technique_count": len(m["sw_tech"].get(s["id"], ())),
            "group_count": len(m["sw_groups"].get(s["id"], ())),
            "url": attack_url(s),
        })
    return sorted(rows, key=lambda r: r["software_id"])


def build_campaigns(idx: Index, m) -> list[dict]:
    rows = []
    for c in idx.campaigns:
        rows.append({
            "campaign_id": attack_id(c),
            "name": c.get("name"),
            "aliases": c.get("aliases", []),
            "first_seen": c.get("first_seen"),
            "last_seen": c.get("last_seen"),
            "technique_count": len(m["camp_tech"].get(c["id"], ())),
            "url": attack_url(c),
            "description": c.get("description", ""),
        })
    return sorted(rows, key=lambda r: r["campaign_id"])


def build_group_to_technique(idx: Index, m) -> list[dict]:
    rows = []
    for g in idx.groups_active:
        gid, gname = attack_id(g), g.get("name")
        for at in m["group_tech"].get(g["id"], ()):
            ap = idx.ap_by_id[at]
            rows.append({
                "group_id": gid, "group_name": gname,
                "technique_id": attack_id(ap), "technique_name": ap.get("name"),
                "tactics": technique_tactics(ap),
            })
    return sorted(rows, key=lambda r: (r["group_id"], r["technique_id"]))


def build_software_to_technique(idx: Index, m) -> list[dict]:
    rows = []
    for s in idx.software_active:
        sid, sname = attack_id(s), s.get("name")
        stype = "malware" if s["type"] == "malware" else "tool"
        for at in m["sw_tech"].get(s["id"], ()):
            ap = idx.ap_by_id[at]
            rows.append({
                "software_id": sid, "software_name": sname, "software_type": stype,
                "technique_id": attack_id(ap), "technique_name": ap.get("name"),
            })
    return sorted(rows, key=lambda r: (r["software_id"], r["technique_id"]))


def build_mitigation_to_technique(idx: Index, m) -> list[dict]:
    rows = []
    for mit in idx.mitigations:
        mid, mname = attack_id(mit), mit.get("name")
        for at in m["mit_tech"].get(mit["id"], ()):
            ap = idx.ap_by_id[at]
            rows.append({
                "mitigation_id": mid, "mitigation_name": mname,
                "technique_id": attack_id(ap), "technique_name": ap.get("name"),
            })
    return sorted(rows, key=lambda r: (r["mitigation_id"], r["technique_id"]))


def build_detection_strategies(idx: Index) -> list[dict]:
    rows = []
    for ds in idx.strategies:
        tgt = idx.detects.get(ds["id"])
        if not tgt:
            continue
        ap = idx.ap_by_id.get(tgt)
        if ap is None:
            continue
        analytic_ids = sorted(
            attack_id(idx.analytic_by_id[a])
            for a in ds.get("x_mitre_analytic_refs", [])
            if a in idx.analytic_by_id
        )
        platforms = sorted({
            p
            for a in ds.get("x_mitre_analytic_refs", [])
            if a in idx.analytic_by_id
            for p in idx.analytic_by_id[a].get("x_mitre_platforms", [])
        })
        rows.append({
            "strategy_id": attack_id(ds),
            "name": ds.get("name"),
            "technique_id": attack_id(ap),
            "technique_name": ap.get("name"),
            "tactics": technique_tactics(ap),
            "analytic_ids": analytic_ids,
            "analytic_count": len(analytic_ids),
            "platforms": platforms,
        })
    return sorted(rows, key=lambda r: r["strategy_id"])


def build_analytics(idx: Index) -> list[dict]:
    # analytic id -> set of technique ids (from strategies that reference it)
    an_to_tech: dict[str, set] = {}
    for ds in idx.strategies:
        tgt = idx.detects.get(ds["id"])
        tech = attack_id(idx.ap_by_id[tgt]) if tgt in idx.ap_by_id else None
        if not tech:
            continue
        for a in ds.get("x_mitre_analytic_refs", []):
            if a in idx.analytic_by_id:
                an_to_tech.setdefault(a, set()).add(tech)

    rows = []
    for an in idx.analytics:
        log_sources = []
        for ref in an.get("x_mitre_log_source_references", []):
            dc = idx.data_component_by_id.get(ref.get("x_mitre_data_component_ref"))
            log_sources.append({
                "log_source": ref.get("name"),
                "channel": ref.get("channel"),
                "data_component": dc.get("name") if dc else None,
            })
        mutable = [
            {"field": me.get("field"), "description": me.get("description")}
            for me in an.get("x_mitre_mutable_elements", [])
        ]
        rows.append({
            "analytic_id": attack_id(an),
            "name": an.get("name"),
            "platforms": an.get("x_mitre_platforms", []),
            "technique_ids": sorted(an_to_tech.get(an["id"], set())),
            "log_sources": log_sources,
            "mutable_elements": mutable,
            "description": an.get("description"),
        })
    return sorted(rows, key=lambda r: r["analytic_id"])


def patch_technique_profiles(idx: Index) -> dict:
    """Patch technique_profiles.jsonl in place: set each row's `tactics` from the
    v19.2 STIX technique, and add `revoked: true` for techniques revoked or
    deprecated in v19.2. Preserve every other field and the row order."""
    path = DATA / "technique_profiles.jsonl"
    ap_by_extid = {attack_id(o): o for o in idx.ap if attack_id(o)}

    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    tactics_changed = 0
    flagged = 0
    missing = []
    for r in rows:
        ap = ap_by_extid.get(r["technique_id"])
        if ap is None:
            missing.append(r["technique_id"])
            continue
        new_tactics = technique_tactics(ap)
        if new_tactics != r.get("tactics"):
            tactics_changed += 1
        r["tactics"] = new_tactics
        if not is_active(ap):
            r["revoked"] = True
            flagged += 1

    write_jsonl(path, rows)
    return {"rows": len(rows), "tactics_changed": tactics_changed,
            "flagged_revoked": flagged, "missing_in_stix": missing}


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Regenerate the ATT&CK core JSONL from MITRE v19.2 STIX.")
    ap.add_argument("--stix", help="Path to a local enterprise-attack-19.2.json (overrides the fetch).")
    args = ap.parse_args()

    objs = load_stix(args.stix)
    idx = Index(objs)
    m = build_edge_maps(idx)

    write_jsonl(DATA / "groups.jsonl", build_groups(idx, m))
    write_jsonl(DATA / "software.jsonl", build_software(idx, m))
    write_jsonl(DATA / "campaigns.jsonl", build_campaigns(idx, m))
    write_jsonl(DATA / "group_to_technique.jsonl", build_group_to_technique(idx, m))
    write_jsonl(DATA / "software_to_technique.jsonl", build_software_to_technique(idx, m))
    write_jsonl(DATA / "mitigation_to_technique.jsonl", build_mitigation_to_technique(idx, m))
    write_jsonl(DATA / "detection_strategies.jsonl", build_detection_strategies(idx))
    write_jsonl(DATA / "analytics.jsonl", build_analytics(idx))
    tp = patch_technique_profiles(idx)

    print(
        f"[build_attack_core] technique_profiles patched: {tp['rows']} rows, "
        f"{tp['tactics_changed']} tactics changed, {tp['flagged_revoked']} flagged revoked"
        + (f", MISSING in STIX: {tp['missing_in_stix']}" if tp["missing_in_stix"] else ""),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
