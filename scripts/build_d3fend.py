#!/usr/bin/env python3
r"""
Rebuild the D3FEND data in data/attack/ and the generated tables on D3FEND_REFERENCE.md
from the pinned MITRE D3FEND release, D3FEND_RELEASE below.

Source of truth. D3FEND publishes each release under a versioned path,
https://d3fend.mitre.org/ontologies/d3fend/<release>/, and https://d3fend.mitre.org/api/version.json
names the current one (1.6.0, release_date 2026-08-31, read on 2026-11-03). Two files
from that path are read, and each one's SHA-256 and size are verified before it is
parsed, whether it was fetched or read from a local file; a mismatch aborts the run.
data/MANIFEST.json records both pins under `inputs` (scripts/build_manifest.py reads
them from D3FEND_INPUTS).

    d3fend-full-mappings.csv  the full inferred ATT&CK, ATT&CK for ICS and SPARTA to
                              D3FEND mappings: one row per (defensive technique, digital
                              artifact, offensive technique) path
    d3fend.json               the ontology as JSON-LD; read for each defensive
                              technique's D3FEND id and definition

Offline / CI override, per input: an option or an environment variable.
    --mappings FILE    or D3FEND_MAPPINGS_PATH
    --ontology FILE    or D3FEND_ONTOLOGY_PATH
A local file must be byte-identical to its pin.

Generated (every field derived on every run):
    data/attack/technique_to_d3fend.jsonl
        one row per (ATT&CK id, D3FEND defensive technique) pair, sorted by both:
        technique_id, technique_name (the ATT&CK v20.0 Enterprise or ICS name, "" when
        the id is in neither profile file), d3fend_technique, d3fend_tactic, relation
        (the defensive technique's relations to the artifact, sorted), digital_artifact
        (the artifacts it acts on, sorted). The upstream mappings still use some ATT&CK
        ids that ATT&CK has since revoked; those rows are kept as published, under the
        id D3FEND uses. Readers carry them forward to the live successor through
        data/attack/superseded_by.jsonl (generate_mitre_pages.py names the revoked
        predecessor on the successor's page), so the file holds no copied rows.
    data/attack/technique_to_d3fend_internal.jsonl
        the same shape for the SPARTA ids (not ATT&CK), sorted the same way
    data/attack/d3fend_countermeasures.jsonl
        one row per defensive technique that maps to at least one ATT&CK id: d3fend_id,
        name, d3fend_tactic, definition, how_to (""), attack_technique_ids (the ATT&CK
        ids as published, sorted), d3fend_version; sorted by name, letters and digits only
    D3FEND_REFERENCE.md, between the d3fend-data begin and end comments
        the tactic summary, one table per tactic (each technique with the ids it
        counters, the first eight shown) and the most-covered ATT&CK techniques. A
        revoked id is shown as its successor with "(replaces revoked <old>)", and a
        deprecated id with no successor as "<id> (deprecated, no replacement)".

--check rebuilds everything in memory and exits 1 on any difference from the committed
files. Run from the repository root:  python -I scripts/build_d3fend.py [--check]
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pinned_inputs as pi  # noqa: E402

TOOL = "build_d3fend"
D3FEND_RELEASE = "1.6.0"
D3FEND_RELEASE_DATE = "2026-08-31"
_BASE = "https://d3fend.mitre.org/ontologies/d3fend/" + D3FEND_RELEASE + "/"
D3FEND_INPUTS = {
    "mappings": {
        "label": "D3FEND " + D3FEND_RELEASE + " full inferred mappings (d3fend-full-mappings.csv)",
        "path": "d3fend-full-mappings.csv",
        "url": _BASE + "d3fend-full-mappings.csv",
        "bytes": 14751588,
        "sha256": "2b86a5a19de143560b75fb2b443a7ac60335d60dfb6b08a7a6e9a53a052ad79f",
        "env": "D3FEND_MAPPINGS_PATH",
    },
    "ontology": {
        "label": "D3FEND " + D3FEND_RELEASE + " ontology (d3fend.json)",
        "path": "d3fend.json",
        "url": _BASE + "d3fend.json",
        "bytes": 4833645,
        "sha256": "e1546d432c6aa64d45b62dd9e9484b0774ae84de7ff3605ff9dd4e20278957bf",
        "env": "D3FEND_ONTOLOGY_PATH",
    },
}

MAP_REL = "data/attack/technique_to_d3fend.jsonl"
INTERNAL_REL = "data/attack/technique_to_d3fend_internal.jsonl"
CM_REL = "data/attack/d3fend_countermeasures.jsonl"
REFERENCE = "D3FEND_REFERENCE.md"

TACTICS = [
    ("Model", "Inventory and understand the system: assets, data flows, and dependencies."),
    ("Harden", "Reduce attack surface before an attack (credential, message, platform, application hardening)."),
    ("Detect", "Identify adversary activity through analysis of artifacts and behaviors."),
    ("Isolate", "Create barriers between system components to limit adversary movement."),
    ("Deceive", "Advertise, entice, and expose the adversary with decoys and lures."),
    ("Evict", "Remove an adversary from the environment."),
    ("Restore", "Return the system to a known-good state after an incident."),
]
SHOWN_IDS = 8          # ids listed per defensive technique before "+N"
SHOWN_NAMES = 6        # countermeasures listed per ATT&CK technique before "+N"
MOST_COVERED = 60      # rows in the most-covered table


def _rows(rel: str) -> list[dict]:
    with open(os.path.join(pi.ROOT, rel), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _is_attack(tid: str) -> bool:
    return re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid) is not None


def _sort_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _jsonl(rows: list[dict]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


def _text(value) -> str:
    """A JSON-LD literal as one string (a list keeps its first string)."""
    if isinstance(value, list):
        value = next((v for v in value if isinstance(v, str)), "")
    if isinstance(value, dict):
        value = value.get("@value", "")
    return value if isinstance(value, str) else ""


def load_inputs(args: dict) -> tuple[list[dict], dict]:
    raw = pi.read(TOOL, D3FEND_INPUTS["mappings"], args.get("--mappings"))
    mappings = list(csv.DictReader(io.StringIO(raw.decode("utf-8"), newline="")))
    onto = json.loads(pi.read(TOOL, D3FEND_INPUTS["ontology"], args.get("--ontology")).decode("utf-8"))
    return mappings, onto


def build(mappings: list[dict], onto: dict) -> dict:
    sup = {r["old_id"]: r for r in _rows("data/attack/superseded_by.jsonl")}
    names = {}
    for rel in ("data/attack/ics/technique_profiles.jsonl", "data/attack/technique_profiles.jsonl"):
        names.update({r["technique_id"]: r.get("name", "") for r in _rows(rel)})

    # (offensive id, defensive technique) -> tactic, relations, artifacts
    pairs: dict = defaultdict(lambda: {"tactic": set(), "relation": set(), "artifact": set()})
    for m in mappings:
        p = pairs[(m["off_tech_id"], m["def_tech_label"])]
        p["tactic"].add(m["def_tactic_label"])
        p["relation"].add(m["def_artifact_rel_label"])
        p["artifact"].add(m["def_artifact_label"])
    for key, p in pairs.items():
        if len(p["tactic"]) != 1:
            sys.exit("[" + TOOL + "] " + repr(key) + " has more than one D3FEND tactic: " + repr(p["tactic"]))

    def row(tid, dtech, p):
        return {"technique_id": tid, "technique_name": names.get(tid, ""), "d3fend_technique": dtech,
                "d3fend_tactic": next(iter(p["tactic"])), "relation": sorted(p["relation"]),
                "digital_artifact": sorted(p["artifact"])}

    attack: dict = {}
    internal: dict = {}
    for (tid, dtech), p in pairs.items():
        (attack if _is_attack(tid) else internal)[(tid, dtech)] = row(tid, dtech, p)
    # defensive techniques: id and definition from the ontology, by label
    by_label = {}
    for n in onto.get("@graph", []):
        if "d3f:d3fend-id" in n and _text(n.get("rdfs:label")):
            by_label.setdefault(_text(n["rdfs:label"]), n)
    tactic_of = {dtech: next(iter(p["tactic"])) for (_t, dtech), p in pairs.items()}
    off_ids: dict = defaultdict(set)
    for (tid, dtech) in pairs:
        off_ids[dtech].add(tid)
    countermeasures = []
    for dtech in sorted(off_ids, key=_sort_name):
        ids = sorted(t for t in off_ids[dtech] if _is_attack(t))
        if not ids:
            continue
        node = by_label.get(dtech)
        if node is None:
            sys.exit("[" + TOOL + "] defensive technique " + repr(dtech) + " is not in the ontology")
        countermeasures.append({
            "d3fend_id": node["d3f:d3fend-id"], "name": dtech, "d3fend_tactic": tactic_of[dtech],
            "definition": _text(node.get("d3f:definition")), "how_to": "",
            "attack_technique_ids": ids, "d3fend_version": D3FEND_RELEASE})
    return {
        MAP_REL: _jsonl([attack[k] for k in sorted(attack)]),
        INTERNAL_REL: _jsonl([internal[k] for k in sorted(internal)]),
        CM_REL: _jsonl(countermeasures),
        "_pairs": pairs, "_countermeasures": countermeasures, "_sup": sup, "_names": names,
    }


# --------------------------------------------------------------------------- #
# D3FEND_REFERENCE.md tables
# --------------------------------------------------------------------------- #
BLOCK = "d3fend-data"
# A content block, fenced with "begin" and "end" comments rather than a "name:start" pair:
# the reading-time count (build_site_nav.words) and the voice lint skip a name:start block
# as navigation, and these tables are the page's reading content (the atlas-data
# convention of build_atlas.py).
BLOCK_RE = re.compile(r"(<!-- " + BLOCK + r" begin[^\n]*-->\n)(.*?)(<!-- " + BLOCK + r" end -->)", re.S)


def _shown(tid: str, sup: dict) -> str:
    s = sup.get(tid)
    if not s:
        return tid
    if s.get("new_id"):
        return s["new_id"] + " (replaces revoked " + tid + ")"
    return tid + " (deprecated, no replacement)"


def _url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def reference_block(built: dict) -> str:
    pairs, cms, sup, names = built["_pairs"], built["_countermeasures"], built["_sup"], built["_names"]
    off_ids: dict = defaultdict(set)
    for (tid, dtech) in pairs:
        off_ids[dtech].add(tid)
    by_tactic: dict = defaultdict(list)
    for c in cms:
        by_tactic[c["d3fend_tactic"]].append(c["name"])
    out = ["## The " + str(len(TACTICS)) + " defensive tactics", "",
           "| Tactic | Purpose | Defensive techniques |", "|---|---|--:|"]
    for tac, purpose in TACTICS:
        out.append("| " + tac + " | " + purpose + " | " + str(len(by_tactic[tac])) + " |")
    out += ["", "---", ""]
    for tac, purpose in TACTICS:
        out += ["## " + tac, "", "*" + purpose + "*", "",
                "| D3FEND technique | ATT&CK techniques countered |", "|---|--:|"]
        for name in sorted(by_tactic[tac]):
            ids = sorted(off_ids[name])
            cell = ", ".join(_shown(t, sup) for t in ids[:SHOWN_IDS])
            if len(ids) > SHOWN_IDS:
                cell += " +" + str(len(ids) - SHOWN_IDS)
            out.append("| " + name + " | " + str(len(ids)) + ": " + cell + " |")
        out.append("")
    out += ["---", "", "## ATT&CK technique to D3FEND countermeasures (most-covered)", "",
            "For each ATT&CK technique, the D3FEND defensive techniques that counter it. The table "
            "lists Enterprise techniques, most-covered first. Full mapping in the dataset.", "",
            "| ATT&CK | Technique | D3FEND countermeasures |", "|---|---|---|"]
    enterprise = {r["technique_id"] for r in _rows("data/attack/technique_profiles.jsonl")
                  if not r.get("revoked") and not r.get("deprecated")}
    counters: dict = defaultdict(set)
    shown: dict = {}
    for (tid, dtech) in pairs:
        if not _is_attack(tid):
            continue
        key = (sup.get(tid) or {}).get("new_id") or tid
        if key not in enterprise:
            continue
        counters[key].add(dtech)
        if key != tid:
            shown[key] = tid
    ranked = sorted(counters, key=lambda t: (len(counters[t]), t), reverse=True)[:MOST_COVERED]
    for tid in ranked:
        label = names.get(tid, "")
        if tid in shown:
            label += " (replaces revoked " + shown[tid] + ")"
        cms_sorted = sorted(counters[tid], key=str.lower)
        cell = ", ".join(cms_sorted[:SHOWN_NAMES])
        if len(cms_sorted) > SHOWN_NAMES:
            cell += " +" + str(len(cms_sorted) - SHOWN_NAMES)
        out.append("| [" + tid + "](" + _url(tid) + ") | " + label + " | " + cell + " |")
    return "\n".join(out) + "\n"


def reference_text(built: dict) -> str:
    raw = pi.committed(REFERENCE)
    if raw is None:
        sys.exit("[" + TOOL + "] " + REFERENCE + " is missing")
    text = pi.lf(raw).decode("utf-8")
    m = BLOCK_RE.search(text)
    if not m:
        sys.exit("[" + TOOL + "] " + REFERENCE + " has no <!-- " + BLOCK + " begin --> block")
    return text[:m.start(2)] + reference_block(built) + text[m.end(2):]


def outputs(args: dict) -> dict:
    built = build(*load_inputs(args))
    out = {k: v for k, v in built.items() if not k.startswith("_")}
    out[REFERENCE] = reference_text(built)
    return out


def _args(argv: list[str]) -> dict:
    args = {}
    it = iter(argv)
    for a in it:
        if a in ("--mappings", "--ontology"):
            args[a] = next(it, None)
        elif a in ("--check",):
            args[a] = True
        elif a in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        else:
            sys.exit("[" + TOOL + "] unknown option " + a)
    return args


def main(argv: list[str]) -> int:
    args = _args(argv)
    out = outputs(args)
    if args.get("--check"):
        stale = [rel for rel, text in out.items() if pi.drift(rel, text)]
        if stale:
            print("STALE: these files differ from the pinned D3FEND " + D3FEND_RELEASE +
                  " build (run python -I scripts/build_d3fend.py and commit):")
            for rel in stale:
                print("  - " + rel)
            return 1
        print("OK: D3FEND data and the D3FEND_REFERENCE.md tables match the pinned D3FEND " +
              D3FEND_RELEASE + " release (" + str(len(out)) + " files)")
        return 0
    for rel, text in out.items():
        if pi.write_text(rel, text):
            print("wrote " + rel)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
