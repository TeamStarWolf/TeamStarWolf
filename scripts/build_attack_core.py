#!/usr/bin/env python3
r"""
Regenerate the ATT&CK core JSONL from the authoritative MITRE ATT&CK v19.2
enterprise STIX bundle.

This is the audit's #1 remediation ("re-pin the ATT&CK core to v19.2 end to
end"). It (over)writes nine files under data/attack/ from a single source of
truth, and patches technique_profiles.jsonl in place without disturbing its
downstream enrichment. Every profile field this script can derive from the STIX
is re-derived on every run, so no count or list on a profile is left as a
snapshot of an older release.

Source of truth, pinned to a commit. The "-19.2" filename alone pins nothing: the
file lives on the mutable `master` branch, and on release day it was added in
commit 8ce3fd8f and then replaced with different content in 6cda5ad8.
    mitre-attack/attack-stix-data @ 6cda5ad8462c79e14fbb872f4e09059b18e0cfc4 (tag v19.2)
    enterprise-attack/enterprise-attack-19.2.json
    SHA-256 dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4
The bundle's SHA-256 is verified before it is parsed, whether it was fetched or
read from a local file, and a mismatch aborts the run. data/MANIFEST.json records
the same pin under `inputs` (scripts/build_manifest.py reads it from here).

Offline / CI override: set env ATTACK_STIX_PATH=<file> or pass --stix <file>.
    python scripts/build_attack_core.py --stix .stix-cache-enterprise-19.2.json
The local file must be byte-identical to the pinned bundle (same SHA-256).

Re-pinning to a new ATT&CK release is a deliberate edit: set STIX_COMMIT to the
attack-stix-data commit that carries the new bundle (its release tag), STIX_FILE
to the bundle's path, and STIX_SHA256 to the bundle's SHA-256 (a mismatch error
prints the actual value), then regenerate.

Every file is opened with encoding="utf-8" (the STIX is UTF-8; the Windows
cp1252 default crashes on it). Output is deterministic: each file is sorted by
its primary id (edge tables by their (source, target) tuple) and written as
one JSON object per line, CRLF-terminated with a trailing newline, matching the
existing data/attack/*.jsonl files exactly.

Generated files:
    groups.jsonl                    software.jsonl              campaigns.jsonl
    group_to_technique.jsonl        software_to_technique.jsonl
    mitigation_to_technique.jsonl   detection_strategies.jsonl analytics.jsonl
    mitigations.jsonl               (id, name, url and technique_count from the STIX;
                                     an existing row keeps its curated one-paragraph
                                     `description`)
Patched in place (all other fields and the row order preserved):
    technique_profiles.jsonl        name, platforms, tactics, revoked flag,
                                    attack_version (x_mitre_version), mitigations,
                                    mitigation_count,
                                    group_count, software_count, campaign_count,
                                    detection_strategies, has_detection_strategy

The profile fields come from the same relationship maps that write the edge
tables, so `group_count` equals the technique's rows in group_to_technique.jsonl,
and so on; scripts/validate_jsonl.py enforces that. A technique revoked in v19.2
has no relationships of its own (ATT&CK moved its `uses`, `mitigates` and
`detects` edges to the successor recorded in superseded_by.jsonl), so its
ATT&CK-native counts are 0 and its page points at the successor. The third-party
crosswalks that are keyed on the revoked id (NIST, CAPEC, D3FEND, CAR) belong to
the downstream scripts and are not touched here.

After a re-pin, the files derived FROM the core are rebuilt in this order (skip
with --no-downstream):
    scripts/build_ctid_edges.py      control/vendor edge `tactics` copies, re-keying
    scripts/build_control_rollup.py  nist_800_53_controls* on technique_profiles
    scripts/backfill_capec_edges.py  capec / capec_via_revoked on technique_profiles

--check rebuilds everything in memory and exits 1 if any committed file differs.
It needs the STIX (--stix, ATTACK_STIX_PATH or network), writes nothing and does
not run the downstream scripts (each has its own --check).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "attack"

# The pinned STIX input (see the module docstring). A commit SHA, never a branch.
STIX_REPO = "mitre-attack/attack-stix-data"
STIX_COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"  # tag v19.2
STIX_FILE = "enterprise-attack/enterprise-attack-19.2.json"
STIX_SHA256 = "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
STIX_BYTES = 53835637
STIX_URL = f"https://raw.githubusercontent.com/{STIX_REPO}/{STIX_COMMIT}/{STIX_FILE}"

ATTACK = "mitre-attack"


# --------------------------------------------------------------------------- #
# STIX loading + helpers
# --------------------------------------------------------------------------- #
def verify_stix(raw: bytes, origin: str) -> None:
    """Abort unless `raw` is byte-identical to the pinned bundle (STIX_SHA256)."""
    digest = hashlib.sha256(raw).hexdigest()
    if digest != STIX_SHA256:
        sys.exit(
            f"[build_attack_core] STIX INTEGRITY FAILURE: {origin}\n"
            f"  expected sha256 {STIX_SHA256} ({STIX_BYTES:,} bytes, {STIX_REPO}@{STIX_COMMIT[:12]})\n"
            f"  actual   sha256 {digest} ({len(raw):,} bytes)\n"
            "  Nothing was written. Use the pinned bundle, or re-pin deliberately "
            "(STIX_COMMIT / STIX_FILE / STIX_SHA256; see the module docstring)."
        )


def load_stix(path: str | None) -> list[dict]:
    """Load the STIX bundle's `objects`. Prefer an explicit path/env override;
    otherwise fetch the commit-pinned URL. Either way the bytes must match
    STIX_SHA256 before anything is parsed."""
    src = path or os.environ.get("ATTACK_STIX_PATH")
    if src:
        print(f"[build_attack_core] reading STIX from {src}", file=sys.stderr)
        with open(src, "rb") as f:
            raw = f.read()
    else:
        print(f"[build_attack_core] fetching STIX from {STIX_URL}", file=sys.stderr)
        req = urllib.request.Request(STIX_URL, headers={"User-Agent": "attack-lib-v19/build_attack_core"})
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (fixed URL, hash-checked)
            raw = resp.read()
        src = STIX_URL
    verify_stix(raw, src)
    bundle = json.loads(raw.decode("utf-8"))
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


def serialise_jsonl(rows: list[dict]) -> bytes:
    """Deterministic JSONL bytes: UTF-8, CRLF line endings, trailing newline."""
    return "".join(json.dumps(row, ensure_ascii=False) + "\r\n" for row in rows).encode("utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_bytes(serialise_jsonl(rows))
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


def build_mitigations(idx: Index, m) -> list[dict]:
    """mitigations.jsonl from the STIX course-of-action objects. `technique_count` is
    the mitigation's row count in mitigation_to_technique.jsonl. The committed
    `description` is a curated one-paragraph summary (the STIX text continues into a
    bulleted implementation list), so an existing row keeps it; a mitigation that is
    new to the release gets the STIX text up to its first line break."""
    path = DATA / "mitigations.jsonl"
    curated = {}
    if path.exists():
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    curated[r["mitigation_id"]] = r.get("description")
    rows = []
    for mit in idx.mitigations:
        mid = attack_id(mit)
        desc = curated.get(mid)
        if desc is None:
            desc = (mit.get("description") or "").split("\n", 1)[0].strip()
        rows.append({
            "mitigation_id": mid,
            "name": mit.get("name"),
            "technique_count": len(m["mit_tech"].get(mit["id"], ())),
            "url": attack_url(mit),
            "description": desc,
        })
    return sorted(rows, key=lambda r: r["mitigation_id"])


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


def _invert(edges: dict[str, set]) -> dict[str, set]:
    """{source_ref: {technique_ref}} -> {technique_ref: {source_ref}}."""
    out: dict[str, set] = {}
    for src, techs in edges.items():
        for t in techs:
            out.setdefault(t, set()).add(src)
    return out


def patch_technique_profiles(idx: Index, m, strategies: list[dict]) -> tuple[dict, list[dict]]:
    """Re-derive, on every technique_profiles.jsonl row, the fields this script owns
    (see the module docstring) from the v19.2 STIX and from the same relationship
    maps that write the edge tables, and add `revoked: true` for techniques revoked
    or deprecated in v19.2. Every other field (the NIST/CAPEC enrichment owned by
    the downstream scripts, descriptions, ...) and the row order are preserved.
    Returns (stats, rows); nothing is written here."""
    path = DATA / "technique_profiles.jsonl"
    ap_by_extid = {attack_id(o): o for o in idx.ap if attack_id(o)}
    t_groups = _invert(m["group_tech"])
    t_sw = _invert(m["sw_tech"])
    t_camps = _invert(m["camp_tech"])
    t_mits = _invert(m["mit_tech"])
    # detection_strategies.jsonl rows -> strategy names per technique, in strategy-id order
    t_strats: dict[str, list[str]] = {}
    for st in sorted(strategies, key=lambda r: r["strategy_id"]):
        t_strats.setdefault(st["technique_id"], []).append(st["name"])

    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    tactics_changed = 0
    rows_changed = 0
    flagged = 0
    missing = []
    for r in rows:
        tid = r["technique_id"]
        ap = ap_by_extid.get(tid)
        if ap is None:
            missing.append(tid)
            continue
        before = dict(r)
        new_tactics = technique_tactics(ap)
        if new_tactics != r.get("tactics"):
            tactics_changed += 1
        r["tactics"] = new_tactics
        if not is_active(ap):
            r["revoked"] = True
            flagged += 1
        ref = ap["id"]
        mits = sorted(
            ({"id": attack_id(idx.by_id[x]), "name": idx.by_id[x].get("name")} for x in t_mits.get(ref, ())),
            key=lambda d: d["id"],
        )
        strats = t_strats.get(tid, [])
        r["name"] = ap.get("name")
        plats = ap.get("x_mitre_platforms", [])
        if set(r.get("platforms") or []) != set(plats):
            r["platforms"] = list(plats)  # keep the committed order when only the order differs
        r["attack_version"] = ap.get("x_mitre_version")
        r["mitigations"] = mits
        r["mitigation_count"] = len(mits)
        r["group_count"] = len(t_groups.get(ref, ()))
        r["software_count"] = len(t_sw.get(ref, ()))
        r["campaign_count"] = len(t_camps.get(ref, ()))
        r["detection_strategies"] = strats
        r["has_detection_strategy"] = bool(strats)
        if r != before:
            rows_changed += 1

    return ({"rows": len(rows), "tactics_changed": tactics_changed, "rows_changed": rows_changed,
             "flagged_revoked": flagged, "missing_in_stix": missing}, rows)


DOWNSTREAM = ("build_ctid_edges.py", "build_control_rollup.py", "backfill_capec_edges.py")


def run_downstream() -> None:
    """Rebuild what is derived from the core, in dependency order: the CTID edge
    tables copy each target's tactics from technique_profiles (build_ctid_edges),
    the NIST rollup reads those edges (build_control_rollup), and the CAPEC
    backfill follows the same superseded_by chains. Each script is deterministic,
    so on an unchanged core this is a no-op."""
    for script in DOWNSTREAM:
        print(f"[build_attack_core] running scripts/{script}", file=sys.stderr)
        subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=str(ROOT), check=True)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="Regenerate the ATT&CK core JSONL from MITRE v19.2 STIX.")
    ap.add_argument("--stix", help="Path to a local enterprise-attack-19.2.json (overrides the fetch).")
    ap.add_argument("--check", action="store_true",
                    help="Rebuild in memory and exit 1 if any committed file differs; write nothing.")
    ap.add_argument("--no-downstream", action="store_true",
                    help="Do not run " + ", ".join(DOWNSTREAM) + " after writing.")
    args = ap.parse_args()

    objs = load_stix(args.stix)
    idx = Index(objs)
    m = build_edge_maps(idx)

    strategies = build_detection_strategies(idx)
    # mitigations.jsonl and technique_profiles.jsonl are read (curated descriptions,
    # downstream enrichment) before anything is written.
    mitigations = build_mitigations(idx, m)
    tp, profiles = patch_technique_profiles(idx, m, strategies)
    outputs = [
        ("groups.jsonl", build_groups(idx, m)),
        ("software.jsonl", build_software(idx, m)),
        ("campaigns.jsonl", build_campaigns(idx, m)),
        ("group_to_technique.jsonl", build_group_to_technique(idx, m)),
        ("software_to_technique.jsonl", build_software_to_technique(idx, m)),
        ("mitigation_to_technique.jsonl", build_mitigation_to_technique(idx, m)),
        ("mitigations.jsonl", mitigations),
        ("detection_strategies.jsonl", strategies),
        ("analytics.jsonl", build_analytics(idx)),
        ("technique_profiles.jsonl", profiles),
    ]

    if args.check:
        stale = [name for name, rows in outputs
                 if not (DATA / name).exists() or (DATA / name).read_bytes() != serialise_jsonl(rows)]
        if stale:
            print("ATT&CK CORE DRIFT (run scripts/build_attack_core.py): " + ", ".join(stale))
            sys.exit(1)
        print(f"OK: {len(outputs)} data/attack files match the v19.2 STIX")
        return

    for name, rows in outputs:
        write_jsonl(DATA / name, rows)
    print(
        f"[build_attack_core] technique_profiles patched: {tp['rows']} rows, "
        f"{tp['tactics_changed']} tactics changed, {tp['rows_changed']} rows changed, "
        f"{tp['flagged_revoked']} flagged revoked"
        + (f", MISSING in STIX: {tp['missing_in_stix']}" if tp["missing_in_stix"] else ""),
        file=sys.stderr,
    )
    if not args.no_downstream:
        run_downstream()


if __name__ == "__main__":
    main()
