#!/usr/bin/env python3
"""Build the Explore page: one filterable table of the framework objects that have a page.

The rows are the ATT&CK techniques, groups, software, campaigns and mitigations, the CAPEC
attack patterns, D3FEND countermeasures, ATLAS techniques and mitigations and F3 techniques.
Tactics are a filter, not rows; the ATT&CK tactic pages are linked from the page text.

    assets/explore.json   one row per object (kind, ID, name, tactics or type, platforms,
                          aliases, CAPEC abstraction and severity, connection counts), read
                          by the Explore plugin in index.html
    explore.md            the page: the table's mount point, and the family index tables,
                          which are all a reader sees on GitHub or without the JSON

The rows come from the JSONL files in data/, not from the rendered pages:

    ATT&CK techniques    data/attack/technique_profiles.jsonl   (tactics, platforms, and the
                         groups, software, mitigations and campaigns linked to each)
    ATT&CK groups        data/attack/group_profiles.jsonl       (aliases, techniques, software)
    ATT&CK software      data/attack/software_profiles.jsonl    (type, platforms, aliases)
    ATT&CK campaigns     data/attack/campaign_profiles.jsonl
    ATT&CK mitigations   data/attack/mitigations.jsonl
    CAPEC                data/weaknesses/capec.jsonl            (abstraction, typical severity)
    D3FEND               data/attack/d3fend_countermeasures.jsonl
    ATLAS                data/ai/atlas_techniques.jsonl, data/ai/atlas_mitigations.jsonl
    F3                   data/fraud/f3_techniques.jsonl

Each row links to its page under mitre/. The page for each object is found by the ID (or,
for D3FEND, the name) in the H1 of the pages in its folder; an object without a page, or a
page without an object, fails the build. A technique revoked or deprecated in ATT&CK v19.2
(data/attack/superseded_by.jsonl) carries the ID that replaced it.

Usage:
    python scripts/build_explore.py            # write both files
    python scripts/build_explore.py --check    # exit 1 if either committed file is stale
    python scripts/build_explore.py --report   # rows per kind and the JSON size, raw and gzip
"""
from __future__ import annotations

import argparse
import collections
import gzip
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_text, tracked_files  # noqa: E402

JSON_OUT = "assets/explore.json"
PAGE_OUT = "explore.md"
GENERATED_BY = "written by scripts/build_explore.py from data/; do not edit"
ATTACK_VERSION = "19.2"

# kind key, singular label, plural label, page folder, source files, connection labels
# (singular, plural)
KINDS = [
    ("technique", "ATT&CK technique", "ATT&CK techniques", "mitre/techniques/",
     ["data/attack/technique_profiles.jsonl"], [["group", "groups"], ["software", "software"], ["mitigation", "mitigations"], ["campaign", "campaigns"]]),
    ("group", "ATT&CK group", "ATT&CK groups", "mitre/groups/",
     ["data/attack/group_profiles.jsonl"], [["technique", "techniques"], ["software", "software"]]),
    ("software", "ATT&CK software", "ATT&CK software", "mitre/software/",
     ["data/attack/software_profiles.jsonl"], [["technique", "techniques"], ["group", "groups"]]),
    ("campaign", "ATT&CK campaign", "ATT&CK campaigns", "mitre/campaigns/",
     ["data/attack/campaign_profiles.jsonl"], [["technique", "techniques"], ["software", "software"], ["group", "groups"]]),
    ("mitigation", "ATT&CK mitigation", "ATT&CK mitigations", "mitre/mitigations/",
     ["data/attack/mitigations.jsonl"], [["technique", "techniques"]]),
    ("capec", "CAPEC attack pattern", "CAPEC attack patterns", "mitre/capec/",
     ["data/weaknesses/capec.jsonl"], [["ATT&CK technique", "ATT&CK techniques"], ["CWE weakness", "CWE weaknesses"]]),
    ("d3fend", "D3FEND countermeasure", "D3FEND countermeasures", "mitre/d3fend/",
     ["data/attack/d3fend_countermeasures.jsonl"], [["ATT&CK technique", "ATT&CK techniques"]]),
    ("atlas", "ATLAS technique", "ATLAS techniques", "mitre/atlas/",
     ["data/ai/atlas_techniques.jsonl"], [["mitigation", "mitigations"]]),
    ("atlas-mitigation", "ATLAS mitigation", "ATLAS mitigations", "mitre/atlas/",
     ["data/ai/atlas_mitigations.jsonl"], [["technique", "techniques"]]),
    ("f3", "F3 technique", "F3 techniques", "mitre/f3/",
     ["data/fraud/f3_techniques.jsonl"], []),
]
KIND_INDEX = {k[0]: i for i, k in enumerate(KINDS)}
FAMILY_INDEX = {
    "technique": "/mitre/techniques/README.md", "group": "/mitre/groups/README.md",
    "software": "/mitre/software/README.md", "campaign": "/mitre/campaigns/README.md",
    "mitigation": "/mitre/mitigations/README.md", "capec": "/mitre/capec/README.md",
    "d3fend": "/mitre/d3fend/README.md", "atlas": "/mitre/atlas/README.md",
    "atlas-mitigation": "/mitre/atlas/README.md", "f3": "/mitre/f3/README.md",
}

# ATT&CK v19.2 Enterprise tactics in matrix order; a tactic in the data that is not here
# fails the build, so a new ATT&CK release cannot drop one silently.
ATTACK_TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "stealth", "defense-impairment", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]
# D3FEND's tactics in the order of its matrix
D3FEND_TACTICS = ["Model", "Harden", "Detect", "Isolate", "Deceive", "Evict", "Restore"]
CAPEC_SEVERITY = ["Very High", "High", "Medium", "Low", "Very Low"]
CAPEC_ABSTRACTION = ["Meta", "Standard", "Detailed"]


def rows_of(rel: str) -> list[dict]:
    text = read_text(rel)
    if text is None:
        raise SystemExit(rel + ": not found")
    return [json.loads(line) for line in text.split("\n") if line.strip()]


def h1(rel: str) -> str:
    for line in (read_text(rel) or "").split("\n"):
        m = re.match(r"^#\s+(.+?)\s*$", line)
        if m:
            return m.group(1)
    return ""


def pages_by_id(folder: str, id_re: str) -> dict[str, str]:
    """ID (or D3FEND name) from the H1 of each page in folder -> file stem."""
    out = {}
    rx = re.compile(id_re)
    for f in tracked_files():
        if f.startswith(folder) and f.endswith(".md") and "/" not in f[len(folder):] \
                and not f.endswith("README.md") and not os.path.basename(f).startswith("_"):
            m = rx.match(h1(f))
            if m:
                key = m.group(1)
                if key in out:
                    raise SystemExit(folder + ": two pages for " + key)
                out[key] = os.path.basename(f)[:-3]
    return out


def tactic_names() -> dict[str, str]:
    out = {}
    for slug in ATTACK_TACTICS:
        t = h1("mitre/tactics/" + slug + ".md")
        if not t:
            raise SystemExit("mitre/tactics/" + slug + ".md: no page for an ATT&CK tactic")
        # the page H1 is title case ("Command And Control"); ATT&CK writes "and" in lower case
        out[slug] = re.sub(r"^Tactic:\s*", "", t).replace(" And ", " and ")
    return out


def default_stem(kind: str, oid: str, name: str) -> str:
    if kind in ("technique", "atlas", "atlas-mitigation"):
        return oid.replace(".", "-")
    if kind == "d3fend":
        return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return oid


def build() -> tuple[dict, dict]:
    tactics: list[list[str]] = []          # [framework, key, label]
    tindex: dict[tuple[str, str], int] = {}

    def tac(fw: str, key: str, label: str) -> int:
        if (fw, key) not in tindex:
            tindex[(fw, key)] = len(tactics)
            tactics.append([fw, key, label])
        return tindex[(fw, key)]

    names = tactic_names()
    for slug in ATTACK_TACTICS:
        tac("ATT&CK", slug, names[slug])
    for r in rows_of("data/ai/atlas_tactics.jsonl"):
        tac("ATLAS", r["shortname"], r["name"])
    for r in rows_of("data/fraud/f3_tactics.jsonl"):
        tac("F3", r["shortname"], r["name"])
    for t in D3FEND_TACTICS:
        tac("D3FEND", t, t)

    platform_count = collections.Counter()
    for src in ("data/attack/technique_profiles.jsonl", "data/attack/software_profiles.jsonl"):
        for r in rows_of(src):
            platform_count.update(r.get("platforms") or [])
    platforms = sorted(platform_count, key=lambda p: (-platform_count[p], p))
    pindex = {p: i for i, p in enumerate(platforms)}

    superseded = {r["old_id"]: r["new_id"] for r in rows_of("data/attack/superseded_by.jsonl")
                  if r.get("domain") == "enterprise"}
    page_maps = {
        "technique": pages_by_id("mitre/techniques/", r"^(T\d{4}(?:\.\d{3})?):"),
        "group": pages_by_id("mitre/groups/", r"^(G\d{4}):"),
        "software": pages_by_id("mitre/software/", r"^(S\d{4}):"),
        "campaign": pages_by_id("mitre/campaigns/", r"^(C\d{4}):"),
        "mitigation": pages_by_id("mitre/mitigations/", r"^(M\d{4}):"),
        "capec": pages_by_id("mitre/capec/", r"^(CAPEC-\d+):"),
        "d3fend": pages_by_id("mitre/d3fend/", r"^D3FEND:\s+(.+)$"),
        "atlas": pages_by_id("mitre/atlas/", r"^(AML\.T\d{4}(?:\.\d{3})?):"),
        "atlas-mitigation": pages_by_id("mitre/atlas/", r"^(AML\.M\d{4}):"),
        "f3": pages_by_id("mitre/f3/", r"^((?:F|T)\d{4}(?:\.\d{3})?):"),
    }
    rows: list[dict] = []
    problems: list[str] = []
    used = collections.defaultdict(set)

    def add(kind: str, oid: str, name: str, page_key: str, **extra) -> None:
        stem = page_maps[kind].get(page_key)
        if stem is None:
            problems.append(kind + " " + oid + " (" + name + "): no page under " + KINDS[KIND_INDEX[kind]][3])
            return
        used[kind].add(page_key)
        row = {"k": KIND_INDEX[kind], "i": oid, "n": name}
        if stem != default_stem(kind, oid, name):
            row["s"] = stem
        for key, val in extra.items():
            if val not in (None, [], "", 0, False) or key == "r":
                row[key] = val
        rows.append(row)

    def tlist(fw: str, keys) -> list[int]:
        out = []
        for k in keys or []:
            if (fw, k) not in tindex:
                problems.append(fw + " tactic '" + k + "' is not in the tactic list")
                continue
            out.append(tindex[(fw, k)])
        return out

    def plist(ps) -> list[int]:
        return [pindex[p] for p in ps or []]

    for r in rows_of("data/attack/technique_profiles.jsonl"):
        add("technique", r["technique_id"], r["name"], r["technique_id"],
            t=tlist("ATT&CK", r.get("tactics")), p=plist(r.get("platforms")),
            sub=1 if r.get("is_subtechnique") else 0, rev=superseded.get(r["technique_id"]),
            r=[r.get("group_count", 0), r.get("software_count", 0), r.get("mitigation_count", 0),
               r.get("campaign_count", 0)])
    for r in rows_of("data/attack/group_profiles.jsonl"):
        add("group", r["group_id"], r["name"], r["group_id"],
            a=[x for x in r.get("aliases") or [] if x != r["name"]],
            r=[len(r.get("techniques") or []), len(r.get("software") or [])])
    for r in rows_of("data/attack/software_profiles.jsonl"):
        add("software", r["software_id"], r["name"], r["software_id"],
            x=r.get("type"), p=plist(r.get("platforms")),
            a=[x for x in r.get("aliases") or [] if x != r["name"]],
            r=[len(r.get("techniques") or []), len(r.get("groups") or [])])
    for r in rows_of("data/attack/campaign_profiles.jsonl"):
        add("campaign", r["campaign_id"], r["name"], r["campaign_id"],
            r=[len(r.get("techniques") or []), len(r.get("software") or []), len(r.get("groups") or [])])
    for r in rows_of("data/attack/mitigations.jsonl"):
        add("mitigation", r["mitigation_id"], r["name"], r["mitigation_id"],
            r=[int(r.get("technique_count") or 0)])
    for r in rows_of("data/weaknesses/capec.jsonl"):
        add("capec", r["capec_id"], r["name"], r["capec_id"],
            x=r.get("abstraction"), sev=r.get("typical_severity"),
            dep=1 if r.get("status") in ("Deprecated", "Obsolete") else 0,
            r=[len(r.get("attack_techniques") or []), len(r.get("related_cwe") or [])])
    for r in rows_of("data/attack/d3fend_countermeasures.jsonl"):
        add("d3fend", r["d3fend_id"], r["name"], r["name"],
            t=tlist("D3FEND", [r.get("d3fend_tactic")] if r.get("d3fend_tactic") else []),
            r=[len(r.get("attack_technique_ids") or [])])
    for r in rows_of("data/ai/atlas_techniques.jsonl"):
        add("atlas", r["technique_id"], r["name"], r["technique_id"],
            t=tlist("ATLAS", r.get("tactics")), sub=1 if r.get("is_subtechnique") else 0,
            r=[int(r.get("mitigation_count") or 0)])
    for r in rows_of("data/ai/atlas_mitigations.jsonl"):
        add("atlas-mitigation", r["mitigation_id"], r["name"], r["mitigation_id"],
            r=[int(r.get("technique_count") or 0)])
    for r in rows_of("data/fraud/f3_techniques.jsonl"):
        add("f3", r["technique_id"], r["name"], r["technique_id"],
            t=tlist("F3", r.get("tactics")), sub=1 if r.get("is_subtechnique") else 0, r=[])

    for kind, m in page_maps.items():
        for key in sorted(set(m) - used[kind]):
            problems.append(KINDS[KIND_INDEX[kind]][3] + m[key] + ".md: a page with no " + kind + " row in data/")
    if problems:
        raise SystemExit("explore: " + "\n  ".join([""] + problems))

    capec_versions = sorted({r.get("capec_version") for r in rows_of("data/weaknesses/capec.jsonl")} - {None, ""})
    data = {
        "about": "Explore table data, " + GENERATED_BY + ". Row keys: k kind, i ID, n name, s page "
                 "file stem when it is not the default, t tactics, p platforms, a aliases, x software "
                 "type or CAPEC abstraction, sev CAPEC typical severity, dep CAPEC deprecated, sub "
                 "sub-technique, rev the ID that replaced a revoked or deprecated technique, r "
                 "connection counts in the order of the kind's 'reach' labels.",
        "attack": ATTACK_VERSION,
        "kinds": [{"key": k, "label": lab, "plural": pl, "dir": d, "reach": reach}
                  for k, lab, pl, d, _src, reach in KINDS],
        "tactics": tactics,
        "platforms": platforms,
        "severity": CAPEC_SEVERITY,
        "abstraction": CAPEC_ABSTRACTION,
        "rows": rows,
    }
    meta = {"capec_versions": capec_versions}
    return data, meta


def render_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n"


def render_page(data: dict, meta: dict) -> str:
    counts = collections.Counter(r["k"] for r in data["rows"])
    total = len(data["rows"])
    revoked = sum(1 for r in data["rows"] if r.get("rev"))
    deprecated = sum(1 for r in data["rows"] if r.get("dep"))
    out = ["<!-- explore:start (" + GENERATED_BY + ") -->", "",
           "# Explore the frameworks", "",
           "> One table of the framework objects that have a page in this library: ATT&CK "
           "techniques, groups, software, campaigns and mitigations, CAPEC attack patterns, D3FEND "
           "countermeasures, ATLAS techniques and mitigations, and F3 techniques. Tactics are a "
           "filter rather than rows; each ATT&CK tactic has its own page under "
           "[ATT&CK tactics](/mitre/tactics/README.md).", "",
           "Type an ID, a name or an alias (T1059, APT29, Cozy Bear, CAPEC-66), or filter by kind, "
           "tactic, platform, software type or CAPEC severity.", "",
           '<div id="tsw-explore" class="tsw-explore-app"></div>', "",
           "## Browse by family", "",
           "On GitHub, the table does not load; the family index pages below list the same objects. "
           "The table is built from the JSONL files in [data/](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data) "
           "into [assets/explore.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/" + JSON_OUT + "): "
           + format(total, ",") + " objects, one index page per family.", "",
           "| Family | Objects | Index | Built from |", "|---|---|---|---|"]
    for i, (key, _lab, plural, _d, srcs, _reach) in enumerate(KINDS):
        n = format(counts[i], ",")
        if key == "technique" and revoked:
            n += " (" + str(revoked) + " revoked or deprecated in v" + ATTACK_VERSION + ", kept for reference)"
        if key == "capec" and deprecated:
            n += " (" + str(deprecated) + " deprecated or obsolete upstream)"
        src = ", ".join("`" + s + "`" for s in srcs)
        out.append("| " + plural + " | " + n + " | " + "[" + plural + "](" + FAMILY_INDEX[key] + ") | " + src + " |")
    cap = (", CAPEC " + ", ".join(meta["capec_versions"])) if meta["capec_versions"] else ""
    out += ["",
            "Versions: ATT&CK v" + ATTACK_VERSION + " (Enterprise)" + cap + ". The licenses and "
            "notices for each framework are in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md); "
            "how the data is built and checked is in [About the data](/ABOUT_THE_DATA.md).", "",
            "ATT&CK&reg; and MITRE ATT&CK&reg; are registered trademarks of The MITRE Corporation. "
            "CAPEC, D3FEND and ATLAS are maintained by The MITRE Corporation, and F3 by MITRE's "
            "Center for Threat-Informed Defense. This project is not affiliated with or endorsed by MITRE.", "",
            "<!-- explore:end -->"]
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="fail if a committed file is stale")
    ap.add_argument("--report", action="store_true", help="rows per kind and the JSON size")
    args = ap.parse_args()
    data, meta = build()
    files = {JSON_OUT: render_json(data), PAGE_OUT: render_page(data, meta)}
    if args.report:
        raw = files[JSON_OUT].encode("utf-8")
        counts = collections.Counter(r["k"] for r in data["rows"])
        for i, k in enumerate(KINDS):
            print(k[2] + ": " + format(counts[i], ","))
        print("rows: " + format(len(data["rows"]), ","))
        print(JSON_OUT + ": " + format(len(raw), ",") + " bytes, "
              + format(len(gzip.compress(raw, 9, mtime=0)), ",") + " bytes gzip (level 9)")
        return 0
    stale = [f for f, t in files.items() if read_text(f) != t]
    if args.check:
        if stale:
            print("FAIL: stale (run python scripts/build_explore.py): " + ", ".join(stale))
            return 1
        print("OK: " + JSON_OUT + " and " + PAGE_OUT + " match data/ (" + format(len(data["rows"]), ",") + " rows)")
        return 0
    for f in stale:
        p = os.path.join(ROOT, f)
        os.makedirs(os.path.dirname(p) or ROOT, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(files[f])
        print("wrote " + f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
