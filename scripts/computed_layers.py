#!/usr/bin/env python3
"""The five computed ATT&CK Navigator layers in navigator/computed/, built from the
library's data by a one-line rule each. scripts/build_navigator_layers.py writes them,
lists them on navigator/index.md and checks them with --check.

Each layer's description quotes its rule (RULES below, word for word) and says the layer
is computed by the library, not an official MITRE mapping. The rule decides which live
ATT&CK Enterprise techniques are in the layer and what each one scores; every technique
is shown under all of its tactics in data/attack/technique_profiles.jsonl.
technique_set() returns the set the generator selects; reproduce() derives the same set
from the rule alone, reading the JSON Lines files directly, and
`python scripts/computed_layers.py --self-check` (run in CI) fails unless every committed
layer holds exactly that set and still quotes its rule.

    ransomware-family.json      techniques used by ransomware software
    d3fend-blindspot.json       techniques no D3FEND countermeasure maps to
    platform-exposure.json      techniques by the number of platforms they apply to
    coverage-completeness.json  techniques by how many of five mapping types they have
    detection-strategy-gap.json techniques ATT&CK publishes no detection strategy for
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIR = "navigator/computed"

# The ATT&CK software entries the ransomware layer counts: the first sentence of the
# description (citations dropped, links reduced to their text) contains "ransomware".
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_SENTENCE_END = re.compile(r"(?<=[a-z0-9)\]])\.\s")

RULES = {
    "ransomware-family": (
        "A live ATT&CK Enterprise technique is in the layer when at least one ATT&CK software "
        "entry whose description's first sentence contains the word \"ransomware\" uses it; "
        "the score is the number of those software entries that use it."),
    "d3fend-blindspot": (
        "A live ATT&CK Enterprise technique is in the layer when data/attack/technique_to_d3fend.jsonl "
        "has no row for its ID or for an ID it replaced (data/attack/superseded_by.jsonl); the score "
        "is the number of ATT&CK groups that use it."),
    "platform-exposure": (
        "Every live ATT&CK Enterprise technique is in the layer; the score is the number of "
        "ATT&CK platforms the technique lists."),
    "coverage-completeness": (
        "Every live ATT&CK Enterprise technique is in the layer; the score counts which of five "
        "library mappings it has (0 to 5): an ATT&CK mitigation, a NIST SP 800-53 control, a "
        "CAPEC pattern, a D3FEND countermeasure and an ATT&CK detection strategy."),
    "detection-strategy-gap": (
        "A live ATT&CK Enterprise technique is in the layer when ATT&CK publishes no detection "
        "strategy for it (has_detection_strategy is false in data/attack/technique_profiles.jsonl); "
        "the score is the number of ATT&CK groups that use it."),
}

LAYERS = [
    # (key, title, short description for navigator/index.md, sources, gradient colors)
    ("ransomware-family", "Ransomware Family Techniques",
     "Techniques used by ransomware software, scored by how many ransomware entries use them",
     "data/attack/software_profiles.jsonl (description, techniques)",
     ["#fee8c8", "#fdbb84", "#b30000"]),
    ("d3fend-blindspot", "D3FEND Blind Spots",
     "Techniques no D3FEND 1.6.0 countermeasure maps to, scored by threat-group usage",
     "data/attack/technique_to_d3fend.jsonl, data/attack/technique_profiles.jsonl (group_count)",
     ["#f2f0f7", "#9e9ac8", "#54278f"]),
    ("platform-exposure", "Platform Exposure",
     "Techniques scored by the number of ATT&CK platforms they apply to",
     "data/attack/technique_profiles.jsonl (platforms)",
     ["#eff3ff", "#6baed6", "#08519c"]),
    ("coverage-completeness", "Mapping Completeness",
     "Techniques scored 0 to 5 by which library mappings they have (mitigation, NIST control, "
     "CAPEC, D3FEND, detection strategy)",
     "data/attack/technique_profiles.jsonl (mitigation_count, nist_control_count, capec, "
     "has_detection_strategy), data/attack/technique_to_d3fend.jsonl",
     ["#fee0d2", "#fcbba1", "#238b45"]),
    ("detection-strategy-gap", "Detection Strategy Gaps",
     "Techniques ATT&CK publishes no detection strategy for, scored by threat-group usage",
     "data/attack/technique_profiles.jsonl (has_detection_strategy, group_count)",
     ["#fff5eb", "#fd8d3c", "#a63603"]),
]
NOT_OFFICIAL = ("Computed by the library from its own data with the rule above; this is not an "
                "official MITRE mapping or MITRE's assessment.")


def _rows(rel: str) -> list[dict]:
    with open(ROOT / rel, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def first_sentence(description: str) -> str:
    text = _LINK.sub(r"\1", _CITATION.sub("", description or ""))
    return _SENTENCE_END.split(text, maxsplit=1)[0]


def ransomware_software() -> list[dict]:
    return [s for s in _rows("data/attack/software_profiles.jsonl")
            if "ransomware" in first_sentence(s.get("description", "")).lower()]


def scores(key: str, ids) -> tuple[dict[str, int], dict[str, str]]:
    """{live Enterprise technique id: score} for the layer, and a comment per technique."""
    profiles = ids.profiles["enterprise"]
    live = sorted(ids.live["enterprise"])
    # D3FEND still publishes some mappings against revoked ids: count them on the successor
    d3 = {ids.resolve(r["technique_id"], "enterprise")
          for r in _rows("data/attack/technique_to_d3fend.jsonl")} - {None}
    out: dict[str, int] = {}
    notes: dict[str, str] = {}
    if key == "ransomware-family":
        users: dict[str, set] = defaultdict(set)
        for s in ransomware_software():
            for t in s.get("techniques") or []:
                live_id = ids.resolve(t, "enterprise")
                if live_id:
                    users[live_id].add(s["name"])
        for tid in live:
            if users.get(tid):
                names = sorted(users[tid], key=str.lower)
                out[tid] = len(names)
                notes[tid] = ("Used by " + str(len(names)) + " ransomware software entr" +
                              ("y" if len(names) == 1 else "ies") + ": " + ", ".join(names[:8]) +
                              (" +" + str(len(names) - 8) if len(names) > 8 else "") + ".")
    elif key == "d3fend-blindspot":
        for tid in live:
            if tid not in d3:
                out[tid] = int(profiles[tid].get("group_count") or 0)
                notes[tid] = ("No D3FEND 1.6.0 countermeasure maps to this technique; used by " +
                              str(out[tid]) + " ATT&CK group" + ("" if out[tid] == 1 else "s") + ".")
    elif key == "platform-exposure":
        for tid in live:
            plats = sorted(profiles[tid].get("platforms") or [])
            out[tid] = len(plats)
            notes[tid] = "Platforms: " + (", ".join(plats) or "none listed") + "."
    elif key == "coverage-completeness":
        for tid in live:
            p = profiles[tid]
            have = [name for name, ok in (
                ("ATT&CK mitigation", int(p.get("mitigation_count") or 0) > 0),
                ("NIST SP 800-53 control", int(p.get("nist_control_count") or 0) > 0),
                ("CAPEC pattern", bool(p.get("capec"))),
                ("D3FEND countermeasure", tid in d3),
                ("ATT&CK detection strategy", bool(p.get("has_detection_strategy"))),
            ) if ok]
            out[tid] = len(have)
            notes[tid] = ("Has " + str(len(have)) + " of 5: " + (", ".join(have) or "none") + ".")
    elif key == "detection-strategy-gap":
        for tid in live:
            if not profiles[tid].get("has_detection_strategy"):
                out[tid] = int(profiles[tid].get("group_count") or 0)
                notes[tid] = ("ATT&CK publishes no detection strategy for this technique; used by " +
                              str(out[tid]) + " ATT&CK group" + ("" if out[tid] == 1 else "s") + ".")
    else:
        raise KeyError(key)
    return out, notes


def technique_set(key: str, ids) -> set[str]:
    return set(scores(key, ids)[0])


def build(key: str, title: str, sources: str, colors: list[str], ids, chrome: dict, tail: dict,
          versions: dict, tactic_order: dict, platform_order: tuple, attack_version: str,
          generated_by: str) -> dict:
    profiles = ids.profiles["enterprise"]
    sc, notes = scores(key, ids)
    entries, platforms = [], set()
    for tid, score in sc.items():
        p = profiles[tid]
        platforms.update(p.get("platforms") or [])
        for tac in sorted(p.get("tactics") or [], key=tactic_order.get):
            entries.append({"techniqueID": tid, "tactic": tac, "score": score, "comment": notes[tid]})
    entries.sort(key=lambda e: (-e["score"], e["techniqueID"], tactic_order[e["tactic"]]))
    smax = max([e["score"] for e in entries] or [1])
    layer = {
        "name": "TeamStarWolf - " + title,
        "versions": dict(versions),
        "domain": "enterprise-attack",
        "description": ("Rule: " + RULES[key] + " " + NOT_OFFICIAL + " " + str(len(sc)) +
                        " techniques, ATT&CK Enterprise v" + attack_version + ". Each technique is "
                        "shown under all of its tactics. Source: " + sources + ". Generated by " +
                        generated_by + "."),
        "filters": {"platforms": [x for x in platform_order if x in platforms]},
    }
    layer.update(json.loads(json.dumps(chrome)))
    layer["gradient"] = {"colors": colors, "minValue": 0, "maxValue": max(smax, 1)}
    layer["legendItems"] = [
        {"label": "Lowest score in the layer", "color": colors[0]},
        {"label": "Highest score in the layer (" + str(smax) + ")", "color": colors[2]},
    ]
    layer["metadata"] = [{"name": k, "value": v} for k, v in (
        ("rule", RULES[key]),
        ("computed", NOT_OFFICIAL),
        ("attack_version", "MITRE ATT&CK Enterprise v" + attack_version),
        ("techniques_scored", str(len(sc))),
        ("technique_tactic_entries", str(len(entries))),
        ("score_distribution", ", ".join(str(s) + ": " + str(n) for s, n in
                                         sorted(Counter(sc.values()).items(), reverse=True))),
        ("generated_by", generated_by),
    )]
    layer.update(json.loads(json.dumps(tail)))
    layer["links"] = [
        {"label": "Navigator layer index",
         "url": "https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/index.md"},
        {"label": "Edge tables", "url": "https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data"},
    ]
    layer["techniques"] = entries
    return layer


# --------------------------------------------------------------------------- self-check
def reproduce(key: str) -> set[str]:
    """The layer's technique set from its rule alone, read straight from the JSON Lines
    files (no AttackIds, no shared scoring code), for --self-check."""
    prof = {r["technique_id"]: r for r in _rows("data/attack/technique_profiles.jsonl")}
    live = {t for t, r in prof.items() if not r.get("revoked") and not r.get("deprecated")}
    sup = {r["old_id"]: r.get("new_id") for r in _rows("data/attack/superseded_by.jsonl")
           if (r.get("domain") or "enterprise") == "enterprise"}

    def current(tid):
        seen = set()
        while tid in sup and tid not in seen:
            seen.add(tid)
            tid = sup[tid]
            if not tid:
                return None
        return tid if tid in live else None

    if key == "ransomware-family":
        out = set()
        for s in _rows("data/attack/software_profiles.jsonl"):
            text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", re.sub(r"\(Citation:[^)]*\)", "", s.get("description") or ""))
            if "ransomware" in re.split(r"(?<=[a-z0-9)\]])\.\s", text, maxsplit=1)[0].lower():
                out |= {c for c in (current(t) for t in s.get("techniques") or []) if c}
        return out
    mapped = {current(r["technique_id"]) for r in _rows("data/attack/technique_to_d3fend.jsonl")}
    if key == "d3fend-blindspot":
        return live - mapped
    if key in ("platform-exposure", "coverage-completeness"):
        return set(live)
    if key == "detection-strategy-gap":
        return {t for t in live if prof[t].get("has_detection_strategy") is False}
    raise KeyError(key)


def self_check() -> int:
    bad = 0
    for key, *_ in LAYERS:
        rel = DIR + "/" + key + ".json"
        with open(ROOT / rel, encoding="utf-8") as f:
            layer = json.load(f)
        got = {e["techniqueID"] for e in layer["techniques"]}
        want = reproduce(key)
        quoted = RULES[key] in layer.get("description", "") and NOT_OFFICIAL in layer.get("description", "")
        if got != want or not quoted:
            bad += 1
            print("FAIL " + rel + ": " + ("rule or computed note not quoted in the description; " if not quoted else "") +
                  str(len(got - want)) + " techniques the rule does not select, " +
                  str(len(want - got)) + " it selects that are missing")
        else:
            print("OK   " + rel + ": " + str(len(got)) + " techniques reproduce from the quoted rule")
    return 1 if bad else 0


if __name__ == "__main__":
    import sys
    if sys.argv[1:] != ["--self-check"]:
        sys.exit("usage: python scripts/computed_layers.py --self-check")
    sys.exit(self_check())
