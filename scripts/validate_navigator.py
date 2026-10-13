#!/usr/bin/env python3
"""
Validate every ATT&CK Navigator layer under navigator/ against the library's own data.

    python scripts/validate_navigator.py        # exit 1 on any error

Each JSON file under navigator/ is either a layer (an object with a "techniques" list) or a
layer index (navigator/library-layers/index.json). The checks are domain-aware, because the
ATLAS and F3 layers legitimately carry non-ATT&CK ids and their own tactic sets:

  all layers
    * valid JSON object with name, versions (with layer), domain and a techniques list;
      domain in {enterprise-attack, ics-attack, mobile-attack, atlas-atlas, f3-financial}
    * no duplicate (techniqueID, tactic) entry; numeric scores; #rrggbb[aa] colors;
      gradient minValue <= maxValue
    * techniques_scored / technique_tactic_entries / blind_spot_count metadata, when present,
      equal the layer's distinct-technique / entry counts
    * a layer whose Source metadata names data/vendor_to_technique.jsonl only scores
      techniques that file maps (a hand-curated layer must not claim to be derived from it)
    * listed (linked) on navigator/index.md, so no layer is orphaned from the site

  ATT&CK layers (enterprise-attack, ics-attack, mobile-attack)
    * versions.attack equals the ATT&CK major the data is built from (19)
    * every techniqueID is LIVE in that domain's profile file - present and not revoked or
      deprecated (scripts/attack_ids.py). The profiles keep revoked ids as lineage rows with
      revoked: true, so a bare presence check would pass them; the error names the successor
      from data/attack/superseded_by.jsonl
    * every tactic is a v19.2 tactic of that domain AND one of the technique's own tactics
      (Enterprise: Stealth / Defense Impairment, never the retired defense-evasion)
    * a layer whose tactic_policy shows each technique under all its tactics does exactly that
    * filters.platforms are platforms of that domain in v19.2 and hide no scored technique

  ATLAS layers: techniqueID in data/ai/atlas_techniques.jsonl, tactic in its tactics
  F3 layers:    techniqueID in data/fraud/f3_techniques.jsonl, tactic in its tactics

  stage layers (navigator/stages/): a name of the form "Stage N - Title" must match the
  "## Stage N: Title" heading in SECURITY_PIPELINE.md

  navigator/library-layers/index.json lists exactly the library layers, by their names
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from attack_ids import AttackIds, read_jsonl
from build_priority_gaps import ICS_TACTICS, MOBILE_TACTICS, NAVIGATOR_ATTACK
from compute_coverage import TACTIC_METADATA

ROOT = Path(__file__).resolve().parents[1]
NAV = ROOT / "navigator"
LIBRARY_INDEX = "navigator/library-layers/index.json"
INDEX_MD = "navigator/index.md"
PIPELINE = "SECURITY_PIPELINE.md"

ATTACK_DOMAINS = {
    "enterprise-attack": ("enterprise", tuple(TACTIC_METADATA)),
    "ics-attack": ("ics", ICS_TACTICS),
    "mobile-attack": ("mobile", MOBILE_TACTICS),
}
OTHER_DOMAINS = {
    "atlas-atlas": ("data/ai/atlas_techniques.jsonl", "data/ai/atlas_tactics.jsonl"),
    "f3-financial": ("data/fraud/f3_techniques.jsonl", "data/fraud/f3_tactics.jsonl"),
}
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
COLOR = re.compile(r"^#[0-9A-Fa-f]{6}([0-9A-Fa-f]{2})?$")
STAGE_NAME = re.compile(r"^Stage (\d+)\s*[—–:-]\s*(.+)$")
TACTIC_POLICY_ALL = "Each selected technique is shown under all tactics"
COUNT_META = {"techniques_scored": "distinct", "blind_spot_count": "distinct",
              "technique_tactic_entries": "entries"}

errors: list[str] = []


def err(rel: str, msg: str) -> None:
    errors.append(f"{rel}: {msg}")


def read_text(p: Path) -> str:
    return p.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")


def meta(layer: dict) -> dict:
    return {m.get("name"): m.get("value") for m in layer.get("metadata") or [] if isinstance(m, dict)}


def other_domain(dom: str) -> tuple[dict, set]:
    tech_rel, tac_rel = OTHER_DOMAINS[dom]
    techs = {r["technique_id"]: r for r in read_jsonl(ROOT / tech_rel)
             if not r.get("revoked") and not r.get("deprecated")}
    tactics = {r["shortname"] for r in read_jsonl(ROOT / tac_rel)}
    if not techs or not tactics:
        errors.append(f"{tech_rel} / {tac_rel}: missing or empty")
    return techs, tactics


def check_layer(rel: str, layer: dict, ids: AttackIds, other: dict, platforms: dict,
                vendor_techs: set, pipeline: dict) -> None:
    for k in ("name", "versions", "domain", "techniques"):
        if k not in layer:
            err(rel, f"missing required field {k!r}")
    dom = layer.get("domain")
    versions = layer.get("versions") or {}
    if "layer" not in versions:
        err(rel, "versions.layer missing")
    if dom not in ATTACK_DOMAINS and dom not in OTHER_DOMAINS:
        err(rel, f"domain {dom!r} is not one of {sorted([*ATTACK_DOMAINS, *OTHER_DOMAINS])}")
        return
    techniques = layer.get("techniques") or []
    md = meta(layer)

    if dom in ATTACK_DOMAINS:
        key, vocab = ATTACK_DOMAINS[dom]
        if str(versions.get("attack")) != NAVIGATOR_ATTACK:
            err(rel, f"versions.attack is {versions.get('attack')!r}; ATT&CK layers must be pinned "
                     f"to {NAVIGATOR_ATTACK!r} (the release data/attack is built from)")
        profiles = ids.profiles[key]
        bad_ids = {}
        for t in techniques:
            tid = t.get("techniqueID", "")
            if not ATTACK_ID.match(tid):
                bad_ids[tid] = "not an ATT&CK technique id"
                continue
            state, succ = ids.status(tid, key)
            if state != "live":
                bad_ids[tid] = state + (f" (successor {succ}, data/attack/superseded_by.jsonl)" if succ else "")
                continue
            tac = t.get("tactic")
            if tac is None:
                continue
            if tac not in vocab:
                err(rel, f"{tid}: tactic {tac!r} is not an ATT&CK v19.2 {key} tactic")
            elif tac not in (profiles[tid].get("tactics") or []):
                err(rel, f"{tid}: tactic {tac!r} is not one of its v19.2 tactics "
                         f"{profiles[tid].get('tactics')} - Navigator would not render it")
        for tid, why in sorted(bad_ids.items()):
            err(rel, f"techniqueID {tid} is not a live {key} technique: {why}")
        if (md.get("tactic_policy") or "").startswith(TACTIC_POLICY_ALL):
            shown: dict[str, set] = {}
            for t in techniques:
                shown.setdefault(t["techniqueID"], set()).add(t.get("tactic"))
            for tid, tacs in sorted(shown.items()):
                want = set(profiles.get(tid, {}).get("tactics") or [])
                if tid not in bad_ids and tacs != want:
                    err(rel, f"{tid}: tactic_policy shows every technique under all its tactics, "
                             f"but it is under {sorted(tacs, key=str)} not {sorted(want)}")
        plat = (layer.get("filters") or {}).get("platforms")
        if plat is not None:
            unknown = sorted(set(plat) - platforms[key])
            if unknown:
                err(rel, f"filters.platforms {unknown} are not ATT&CK v19.2 {key} platforms "
                         f"{sorted(platforms[key])}")
            hidden = sorted({t["techniqueID"] for t in techniques if t["techniqueID"] not in bad_ids
                             and not set(profiles[t["techniqueID"]].get("platforms") or []) & set(plat)})
            if hidden:
                err(rel, f"filters.platforms {plat} hide scored techniques {hidden}")
    else:
        techs, tactics = other[dom]
        for t in techniques:
            tid, tac = t.get("techniqueID"), t.get("tactic")
            if tid not in techs:
                err(rel, f"techniqueID {tid} is not in {OTHER_DOMAINS[dom][0]}")
            elif tac is not None and (tac not in tactics or tac not in (techs[tid].get("tactics") or [])):
                err(rel, f"{tid}: tactic {tac!r} is not one of its tactics {techs[tid].get('tactics')}")

    seen = set()
    for t in techniques:
        k = (t.get("techniqueID"), t.get("tactic"))
        if k in seen:
            err(rel, f"duplicate entry {k[0]} / {k[1]}")
        seen.add(k)
        if "score" in t and not isinstance(t["score"], (int, float)):
            err(rel, f"{k[0]}: score {t['score']!r} is not numeric")
        if "color" in t and t["color"] and not COLOR.match(t["color"]):
            err(rel, f"{k[0]}: color {t['color']!r} is not #rrggbb[aa]")
    g = layer.get("gradient")
    if g and g.get("minValue", 0) > g.get("maxValue", 0):
        err(rel, "gradient minValue > maxValue")

    distinct = len({t.get("techniqueID") for t in techniques})
    for name, kind in COUNT_META.items():
        if md.get(name) is not None:
            want = distinct if kind == "distinct" else len(techniques)
            if str(md[name]) != str(want):
                err(rel, f"metadata {name}={md[name]} but the layer has {want} "
                         f"{'techniques' if kind == 'distinct' else 'entries'}")

    for name, value in md.items():
        if str(name).lower() == "source" and "vendor_to_technique.jsonl" in str(value) \
                and "not derived" not in str(value).lower():
            stray = sorted({t.get("techniqueID") for t in techniques} - vendor_techs)
            if stray:
                err(rel, f"Source names data/vendor_to_technique.jsonl but {stray} have no edge there")

    if rel.startswith("navigator/stages/"):
        m = STAGE_NAME.match(layer.get("name") or "")
        if m:
            n, title = int(m.group(1)), m.group(2).strip()
            if n not in pipeline:
                err(rel, f"name says Stage {n}, which {PIPELINE} does not define")
            elif not title.startswith(pipeline[n]):
                err(rel, f"name says 'Stage {n} - {title}' but {PIPELINE} Stage {n} is "
                         f"'{pipeline[n]}'")


def main() -> None:
    ids = AttackIds(ROOT)
    other = {dom: other_domain(dom) for dom in OTHER_DOMAINS}
    platforms = {key: {p for r in ids.profiles[key].values() if r["technique_id"] in ids.live[key]
                       for p in (r.get("platforms") or [])}
                 for key in ids.profiles}
    vendor_techs = {r.get("attack_technique") for r in read_jsonl(ROOT / "data/vendor_to_technique.jsonl")}
    pipeline = {int(m.group(1)): m.group(2).strip()
                for m in re.finditer(r"^## Stage (\d+): (.+)$", read_text(ROOT / PIPELINE), re.M)}
    if not pipeline:
        errors.append(f"{PIPELINE}: no '## Stage N: Title' headings found")
    index_md = read_text(ROOT / INDEX_MD)
    # A layer is listed by a Markdown link to its file: the GitHub blob URL that
    # build_navigator_layers.py writes (docsify would route a relative "x.json" link to
    # "x.json.md" and 404), or a relative path under navigator/.
    linked = set(re.findall(r"\]\(https://github\.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/"
                            r"([^)\s]+\.json)\)", index_md))
    linked |= {u for u in re.findall(r"\]\(([^)\s]+\.json)\)", index_md) if "://" not in u}
    raw = set(re.findall(r"raw\.githubusercontent\.com/TeamStarWolf/TeamStarWolf/main/navigator/"
                         r"([^)\s\"]+\.json)", index_md))

    layers, counts = {}, {}
    for p in sorted(NAV.rglob("*.json")):
        rel = p.relative_to(ROOT).as_posix()
        try:
            d = json.loads(read_text(p))
        except (ValueError, UnicodeDecodeError) as e:
            err(rel, f"invalid JSON: {e}")
            continue
        if rel == LIBRARY_INDEX:
            continue
        if not isinstance(d, dict) or not isinstance(d.get("techniques"), list):
            err(rel, "not a Navigator layer (an object with a techniques list) and not a known index file")
            continue
        layers[rel] = d
        check_layer(rel, d, ids, other, platforms, vendor_techs, pipeline)
        counts[d.get("domain")] = counts.get(d.get("domain"), 0) + 1
        if p.relative_to(NAV).as_posix() not in linked:
            err(rel, f"not listed on {INDEX_MD} (orphaned layer)")
    for link in sorted(linked | raw):
        if not (NAV / link).is_file():
            err(INDEX_MD, f"links navigator/{link}, which does not exist")

    lib = json.loads(read_text(ROOT / LIBRARY_INDEX))
    listed = {}
    for item in lib if isinstance(lib, list) else []:
        listed[item.get("file")] = item
        rel = f"navigator/library-layers/{item.get('file')}"
        if rel not in layers:
            err(LIBRARY_INDEX, f"lists {item.get('file')}, which is not a layer")
        elif item.get("name") != layers[rel].get("name"):
            err(LIBRARY_INDEX, f"{item.get('file')}: name {item.get('name')!r} != layer name "
                               f"{layers[rel].get('name')!r}")
    for rel in layers:
        if rel.startswith("navigator/library-layers/") and rel.rsplit("/", 1)[1] not in listed:
            err(LIBRARY_INDEX, f"does not list {rel}")

    if errors:
        for e in errors:
            print(f"ERROR: {e}")
        print(f"FAILED: {len(errors)} problem(s) in {len(layers)} Navigator layers")
        sys.exit(1)
    summary = ", ".join(f"{n} {d}" for d, n in sorted(counts.items()))
    print(f"OK: {len(layers)} Navigator layers valid ({summary}); every ATT&CK layer pinned to "
          f"v{NAVIGATOR_ATTACK} with live technique IDs and v19.2 tactics")


if __name__ == "__main__":
    main()
