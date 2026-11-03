#!/usr/bin/env python3
"""Write the four ATT&CK summary pages from the committed data in data/attack.

    ATTACK_TECHNIQUE_ATLAS.md   every live Enterprise technique and sub-technique by tactic,
                                scored by groups, software, mitigations, NIST 800-53
                                controls (CTID) and whether ATT&CK ships a detection strategy
    THREAT_GROUP_PROFILES.md    every Enterprise group with observed technique usage, with
                                aliases and counts, and a profile of the most active groups
    ICS_ATTACK_ATLAS.md         the ATT&CK for ICS matrix by tactic
    MOBILE_ATTACK_ATLAS.md      the ATT&CK for Mobile matrix by tactic

The pages state the release scripts/attack_ids.py names (ATTACK_VER, the one
build_attack_core.py pins), and every count on them is computed from the data. Revoked
techniques are left out; a technique ID a group record still cites is re-keyed through
data/attack/superseded_by.jsonl, so no page here cites a revoked ID.

Blocks other scripts own are carried over, never written here:

    <!-- meta:start ... meta:end -->         the header card (scripts/build_doc_meta.py)
    <!-- related:start ... related:end -->   the related-pages footer (build_crosslinks.py)
    " ([local](/mitre/...))" links and the
    local-id-links marker line               on ATTACK_TECHNIQUE_ATLAS.md (build_crosslinks.py)

A write keeps the committed card and footer where this script places them, and writes the
"(local)" links with build_crosslinks.py's own function, so a write followed by those two
scripts changes nothing. --check compares each page with those blocks taken out of both
sides; their own --check modes guard them. Each page keeps the line endings it has.

The tactic IDs of the ICS and Mobile matrices are not in the committed data, so they are
listed below (they are stable ATT&CK IDs); a tactic in the data that the list does not name
fails the run.

Usage:
    python scripts/build_attack_atlases.py           # write the four pages
    python scripts/build_attack_atlases.py --check   # exit 1 when a committed page differs
    python scripts/build_attack_atlases.py --self-test   # planted cases for the helpers
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from attack_ids import ATTACK_VER  # noqa: E402
from plain_markdown import plain  # noqa: E402
from repo_files import ROOT, read_bytes, read_text, tracked_files  # noqa: E402

DATA = os.path.join(ROOT, "data", "attack")
GITHUB_BLOB = "https://github.com/TeamStarWolf/TeamStarWolf/blob/main/"
ATT = "https://attack.mitre.org/"

# Mirrors generate_technique_detail_pages.TACTIC_ORDER (ATT&CK v19 split Defense Evasion into
# Stealth and Defense Impairment); main() asserts the two lists agree.
ENTERPRISE_TACTICS = [
    ("reconnaissance", "Reconnaissance", "TA0043"), ("resource-development", "Resource Development", "TA0042"),
    ("initial-access", "Initial Access", "TA0001"), ("execution", "Execution", "TA0002"),
    ("persistence", "Persistence", "TA0003"), ("privilege-escalation", "Privilege Escalation", "TA0004"),
    ("stealth", "Stealth", "TA0005"), ("defense-impairment", "Defense Impairment", "TA0112"),
    ("credential-access", "Credential Access", "TA0006"), ("discovery", "Discovery", "TA0007"),
    ("lateral-movement", "Lateral Movement", "TA0008"), ("collection", "Collection", "TA0009"),
    ("command-and-control", "Command and Control", "TA0011"), ("exfiltration", "Exfiltration", "TA0010"),
    ("impact", "Impact", "TA0040"),
]
ICS_TACTICS = [
    ("initial-access", "Initial Access", "TA0108"), ("execution", "Execution", "TA0104"),
    ("persistence", "Persistence", "TA0110"), ("privilege-escalation", "Privilege Escalation", "TA0111"),
    ("evasion", "Evasion", "TA0103"), ("discovery", "Discovery", "TA0102"),
    ("lateral-movement", "Lateral Movement", "TA0109"), ("collection", "Collection", "TA0100"),
    ("command-and-control", "Command and Control", "TA0101"),
    ("inhibit-response-function", "Inhibit Response Function", "TA0107"),
    ("impair-process-control", "Impair Process Control", "TA0106"), ("impact", "Impact", "TA0105"),
]
MOBILE_TACTICS = [
    ("initial-access", "Initial Access", "TA0027"), ("execution", "Execution", "TA0041"),
    ("persistence", "Persistence", "TA0028"), ("privilege-escalation", "Privilege Escalation", "TA0029"),
    ("defense-evasion", "Defense Evasion", "TA0030"), ("credential-access", "Credential Access", "TA0031"),
    ("discovery", "Discovery", "TA0032"), ("lateral-movement", "Lateral Movement", "TA0033"),
    ("collection", "Collection", "TA0035"), ("command-and-control", "Command and Control", "TA0037"),
    ("exfiltration", "Exfiltration", "TA0036"), ("impact", "Impact", "TA0034"),
]
# Section anchors kept for links made before a tactic was renamed: (tactic slug, old anchor).
LEGACY_ANCHORS = {"stealth": ["defense-evasion"]}

PLATFORM_ABBR = {"Containers": "Cnt", "Identity Provider": "IdP", "Linux": "Lnx", "macOS": "Mac",
                 "Network Devices": "NetDev", "Office Suite": "Office", "Windows": "Win"}

TOP_GROUPS = 40          # groups that get a detailed profile
NOTABLE = 18             # techniques listed by ID in each profile
ALIAS_WIDTH = 80         # characters of aliases in the all-groups table

NOTICE = ("\N{COPYRIGHT SIGN} 2026 The MITRE Corporation. This work is reproduced and distributed with "
          "the permission of The MITRE Corporation. License: [ATT&CK Terms of Use]"
          "(https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). "
          "ATT&CK\N{REGISTERED SIGN} and MITRE ATT&CK\N{REGISTERED SIGN} are registered trademarks of "
          "The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.")
GEN_MARK = ("<!-- generated: written by scripts/build_attack_atlases.py from data/attack (ATT&CK "
            + ATTACK_VER + "); edit the script, not this page. The header card and the related-pages "
            "footer belong to build_doc_meta.py and build_crosslinks.py. -->")

META_RE = re.compile(r"<!-- meta:start[^\n]*\n.*?<!-- meta:end -->", re.S)
REL_RE = re.compile(r"<!-- related:start[^\n]*\n.*?<!-- related:end -->", re.S)
LOCAL_MARK_RE = re.compile(r"^<!-- local-id-links [^\n]*-->\n(?:\n)?", re.M)
LOCAL_LINK_RE = re.compile(r" \(\[local\]\(/mitre/[^()\s]+\.md\)\)")
META_SLOT = "<!-- @@meta@@ -->"
REL_SLOT = "<!-- @@related@@ -->"

CITATION_RE = re.compile(r"\s*\(Citation:[^)]*\)")
MDLINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


# ----------------------------------------------------------------------------- data


def load(rel: str) -> list[dict]:
    with open(os.path.join(DATA, rel), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def id_key(tid: str) -> tuple:
    head, _, sub = tid.partition(".")
    return (head[0], int(head[1:]), int(sub) if sub else -1)


def successors() -> dict[str, str]:
    """Revoked technique ID -> the ID that replaces it (data/attack/superseded_by.jsonl)."""
    return {r["old_id"]: r["new_id"] for r in load("superseded_by.jsonl")
            if r.get("reason") == "revoked" and r.get("new_id")}


def rekey(tid: str, succ: dict[str, str]) -> str:
    seen = set()
    while tid in succ and tid not in seen:
        seen.add(tid)
        tid = succ[tid]
    return tid


def count(n: int, one: str, many: str | None = None) -> str:
    return "{:,} {}".format(n, one if n == 1 else (many or one + "s"))


def tech_url(tid: str) -> str:
    return ATT + "techniques/" + tid.replace(".", "/")


# ----------------------------------------------------------------------------- matrices


def tactic_rows(profiles: list[dict], slug: str) -> list[dict]:
    """The techniques of one tactic, each parent followed by its sub-techniques."""
    rows = [p for p in profiles if slug in p["tactics"]]
    return sorted(rows, key=lambda p: id_key(p["technique_id"]))


def tech_cell(p: dict, url: str) -> str:
    if p["is_subtechnique"]:
        return "&nbsp;&nbsp;↳ [." + p["technique_id"].split(".")[1] + " " + p["name"] + "](" + url + ")"
    return "[" + p["technique_id"] + " " + p["name"] + "](" + url + ")"


def tactic_index(tactics, rows_of) -> list[str]:
    out = ["## Tactics", ""]
    for slug, name, _ta in tactics:
        out.append("- [" + name + "](#" + slug + "): " + count(len(rows_of[slug]), "technique"))
    return out + ["", "---", ""]


def tactic_head(slug: str, name: str, ta: str, n: int, note: str | None = None,
                legacy: tuple[str, ...] = ()) -> list[str]:
    out = ["## " + name, '<a id="' + slug + '"></a>']
    out += ['<a id="' + a + '"></a>' for a in legacy]
    out += ["", "[`" + ta + "`](" + ATT + "tactics/" + ta + "/), " + count(n, "technique"), ""]
    if note:
        out += [note, ""]
    return out


def check_tactics(domain: str, profiles: list[dict], tactics) -> None:
    known = {s for s, _, _ in tactics}
    extra = sorted({t for p in profiles for t in p["tactics"]} - known)
    if extra:
        raise SystemExit(domain + ": tactics in the data that scripts/build_attack_atlases.py does not "
                         "list: " + ", ".join(extra))


def footer(source: str) -> list[str]:
    return ["", REL_SLOT, "", "---", "", "*Source: " + source + " " + NOTICE + "*", ""]


def render_enterprise(prof: list[dict]) -> str:
    live = [p for p in prof if not p.get("revoked")]
    check_tactics("Enterprise", live, ENTERPRISE_TACTICS)
    revoked = len(prof) - len(live)
    rows_of = {s: tactic_rows(live, s) for s, _, _ in ENTERPRISE_TACTICS}
    n = len(live)
    out = [
        "# ATT&CK Technique Atlas", "", GEN_MARK, "",
        "> A complete, cross-referenced map of the " + "{:,}".format(n) + " MITRE ATT&CK Enterprise "
        "techniques and sub-techniques (ATT&CK " + ATTACK_VER + "), organized by tactic. Every technique is "
        "scored by how many threat groups and pieces of software use it, how many ATT&CK mitigations and "
        "NIST 800-53 controls address it, and whether ATT&CK ships a detection strategy for it, so you can "
        "see, at a glance, what matters and what is under-covered.",
        "",
        "Legend: Grp = threat groups observed using it, SW = software (malware/tools) implementing it, "
        "Mit = ATT&CK mitigations, NIST = NIST 800-53 R5 controls (via CTID), Det = ATT&CK detection "
        "strategy exists. Machine-readable source: [`data/attack/technique_profiles.jsonl`]("
        + GITHUB_BLOB + "data/attack/technique_profiles.jsonl).",
        "",
        "A technique that serves more than one tactic is listed under each, so the tactic counts add up "
        "to more than " + "{:,}".format(n) + ". The " + count(revoked, "technique") + " that ATT&CK has "
        "revoked are left out; [`data/attack/superseded_by.jsonl`](" + GITHUB_BLOB
        + "data/attack/superseded_by.jsonl) names the technique that replaces each one.",
        "",
        "Want the full write-up per technique? Browse the [Technique Detail Pages](techniques/README.md): "
        "each of the " + "{:,}".format(n) + " techniques consolidated with its description, mitigations, "
        "NIST controls, detections, and the groups and software that use it.",
        "",
        "Related: [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), [Matrix Analysis]"
        "(ATTACK_MATRIX_ANALYSIS_REFERENCE.md), [Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md), "
        "[Threat Group Profiles](THREAT_GROUP_PROFILES.md), [ATT&CK Mitigations](ATTACK_MITIGATIONS_REFERENCE.md)",
        "", META_SLOT, "",
    ]
    out += tactic_index(ENTERPRISE_TACTICS, rows_of)
    for slug, name, ta in ENTERPRISE_TACTICS:
        rows = rows_of[slug]
        note = None
        if slug == "stealth":
            note = ("ATT&CK v19 split the former Defense Evasion tactic (TA0005) into Stealth, which keeps "
                    "its ID, and [Defense Impairment](#defense-impairment) (TA0112).")
        out += tactic_head(slug, name, ta, len(rows), note, tuple(LEGACY_ANCHORS.get(slug, [])))
        out += ["| Technique | Platforms | Grp | SW | Mit | NIST | Det |", "|---|---|--:|--:|--:|--:|:--:|"]
        for p in rows:
            plats = " ".join(PLATFORM_ABBR.get(x, x) for x in p["platforms"])
            out.append("| " + " | ".join([
                tech_cell(p, tech_url(p["technique_id"])), plats, str(p["group_count"]),
                str(p["software_count"]), str(p["mitigation_count"]), str(p["nist_control_count"]),
                "Yes" if p["has_detection_strategy"] else ""]) + " |")
        out.append("")
    out += footer("MITRE ATT&CK Enterprise " + ATTACK_VER + " (STIX) and the CTID NIST 800-53 R5 mappings, "
                  "through data/attack/technique_profiles.jsonl. Counts are of live (not revoked) ATT&CK objects.")
    return "\n".join(out)


def render_small_matrix(domain: str, title: str, tactics, prof: list[dict], intro_tail: str,
                        related: str) -> str:
    live = [p for p in prof if not p.get("revoked")]
    check_tactics(domain, live, tactics)
    rows_of = {s: tactic_rows(live, s) for s, _, _ in tactics}
    subs = sum(1 for p in live if p["is_subtechnique"])
    folder = domain.lower()
    out = [
        "# " + title, "", GEN_MARK, "",
        "> The complete MITRE ATT&CK for " + domain + " matrix (" + ATTACK_VER + "), "
        + "{:,}".format(len(live)) + " techniques and sub-techniques (" + count(len(live) - subs, "technique")
        + ", " + count(subs, "sub-technique") + ") across " + count(len(tactics), "tactic") + ", cross-referenced "
        "to the threat groups and software that use them and the ATT&CK mitigations that address them. "
        "Machine-readable source: [`data/attack/" + folder + "/technique_profiles.jsonl`](" + GITHUB_BLOB
        + "data/attack/" + folder + "/technique_profiles.jsonl).",
        "",
        "Legend: Grp = threat groups, SW = software, Mit = ATT&CK mitigations, Det = ATT&CK detection "
        "guidance exists.",
        "",
        intro_tail,
        "",
        "Related: " + related,
        "", META_SLOT, "",
    ]
    out += tactic_index(tactics, rows_of)
    for slug, name, ta in tactics:
        rows = rows_of[slug]
        out += tactic_head(slug, name, ta, len(rows))
        out += ["| Technique | Platforms | Grp | SW | Mit | Det |", "|---|---|--:|--:|--:|:--:|"]
        for p in rows:
            out.append("| " + " | ".join([
                tech_cell(p, p.get("url") or tech_url(p["technique_id"])), ", ".join(p["platforms"]) or "None",
                str(p["group_count"]), str(p["software_count"]), str(p["mitigation_count"]),
                "Yes" if p.get("has_detection") else ""]) + " |")
        out.append("")
    out += footer("MITRE ATT&CK for " + domain + " " + ATTACK_VER + " (STIX), through data/attack/" + folder
                  + "/technique_profiles.jsonl. Counts are of live (not revoked or deprecated) objects.")
    return "\n".join(out)


# ----------------------------------------------------------------------------- groups


def summary(desc: str) -> str:
    """The first two sentences of a group's ATT&CK description, without citations or links."""
    para = desc.strip().split("\n\n")[0]
    para = MDLINK_RE.sub(r"\1", CITATION_RE.sub("", para))
    para = re.sub(r"\s+", " ", para).strip()
    return " ".join(SENTENCE_RE.split(para)[:2])


def alias_cell(aliases: list[str]) -> str:
    if not aliases:
        return "None"
    shown: list[str] = []
    for a in aliases:
        if shown and len(", ".join(shown + [a])) > ALIAS_WIDTH:
            break
        shown.append(a)
    rest = len(aliases) - len(shown)
    return ", ".join(shown) + (" (+" + str(rest) + " more)" if rest else "")


def render_groups(groups: list[dict], gprof: dict[str, dict], tprof: dict[str, dict],
                  succ: dict[str, str]) -> str:
    def techniques(gid: str) -> list[str]:
        ids = {rekey(t, succ) for t in gprof[gid]["techniques"]}
        missing = sorted(t for t in ids if t not in tprof or tprof[t].get("revoked"))
        if missing:
            raise SystemExit(gid + ": cites techniques with no live profile: " + ", ".join(missing))
        return sorted(ids, key=id_key)

    used = [g for g in groups if g["technique_count"] > 0]
    tech = {g["group_id"]: techniques(g["group_id"]) for g in used}
    used.sort(key=lambda g: (-len(tech[g["group_id"]]), g["group_id"]))
    top = used[:TOP_GROUPS]
    top_ids = {g["group_id"] for g in top}
    out = [
        "# Threat Group Profiles", "", GEN_MARK, "",
        "> Authoritative profiles for the " + str(len(used)) + " tracked adversary groups in MITRE ATT&CK "
        "Enterprise (" + ATTACK_VER + ") that have observed technique usage (nation-state APTs, eCrime crews, "
        "and intrusion sets; " + str(len(used)) + " of the " + str(len(groups)) + " groups ATT&CK lists), each "
        "with its aliases, the count of techniques and software attributed to it, and (for the most active) "
        "its signature ATT&CK techniques. Pair this with [Threat Actors](THREAT_ACTORS.md) for narrative "
        "context and the [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) for the behaviors.",
        "", META_SLOT, "",
        "Machine-readable: [`data/attack/groups.jsonl`](" + GITHUB_BLOB + "data/attack/groups.jsonl), "
        "[`data/attack/group_to_technique.jsonl`](" + GITHUB_BLOB + "data/attack/group_to_technique.jsonl)",
        "",
        "## All tracked groups",
        "",
        "Sorted by breadth of attributed ATT&CK techniques. The " + str(len(top)) + " most active link to "
        "their profile below; the rest link to their ATT&CK entry.",
        "",
        "| Group | Also known as | Techniques | Software |",
        "|---|---|--:|--:|",
    ]
    for g in used:
        gid = g["group_id"]
        href = "#" + gid.lower() if gid in top_ids else ATT + "groups/" + gid + "/"
        out.append("| [" + gid + " " + g["name"] + "](" + href + ") | " + alias_cell(g["aliases"][1:])
                   + " | " + str(len(tech[gid])) + " | " + str(g["software_count"]) + " |")
    out += ["", "---", "", "## Detailed profiles: most active groups", ""]
    for g in top:
        gid = g["group_id"]
        ts = tech[gid]
        out += ["### " + gid + ": " + g["name"], '<a id="' + gid.lower() + '"></a>', ""]
        if g["aliases"][1:]:
            out.append("Aliases: " + ", ".join(g["aliases"][1:]) + "  ")
        out += ["ATT&CK: [" + gid + "](" + ATT + "groups/" + gid + "), " + count(len(ts), "technique") + ", "
                + str(g["software_count"]) + " software  ", ""]
        s = summary(g.get("description") or gprof[gid].get("description") or "")
        if s:
            out += [s, ""]
        notable = ", ".join("[" + t + "](" + tech_url(t) + ") " + tprof[t]["name"] for t in ts[:NOTABLE])
        more = len(ts) - NOTABLE
        out += ["Notable techniques: " + notable + (" _(+" + str(more) + " more)_" if more > 0 else ""),
                "", "---", ""]
    while out and out[-1] in ("", "---"):
        out.pop()
    out += footer("MITRE ATT&CK Enterprise " + ATTACK_VER + ", through data/attack/groups.jsonl and "
                  "data/attack/group_profiles.jsonl. Full technique lists for every group are in the "
                  "machine-readable edge table.")
    return "\n".join(out)


# ----------------------------------------------------------------------------- pages


def render_all() -> dict[str, str]:
    succ = successors()
    tprof_rows = load("technique_profiles.jsonl")
    tprof = {r["technique_id"]: r for r in tprof_rows}
    groups = load("groups.jsonl")
    gprof = {r["group_id"]: r for r in load("group_profiles.jsonl")}
    return {
        "ATTACK_TECHNIQUE_ATLAS.md": render_enterprise(tprof_rows),
        "THREAT_GROUP_PROFILES.md": render_groups(groups, gprof, tprof, succ),
        "ICS_ATTACK_ATLAS.md": render_small_matrix(
            "ICS", "ICS ATT&CK Technique Atlas", ICS_TACTICS, load("ics/technique_profiles.jsonl"),
            "A technique that serves more than one tactic is listed under each. Techniques that ATT&CK has "
            "revoked or deprecated are left out; [`data/attack/superseded_by.jsonl`](" + GITHUB_BLOB
            + "data/attack/superseded_by.jsonl) names the technique that replaces each one, where there is one.",
            "[ATT&CK Technique Atlas (Enterprise)](ATTACK_TECHNIQUE_ATLAS.md), [Threat Group Profiles]"
            "(THREAT_GROUP_PROFILES.md), [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), "
            "[ICS/OT Security Reference](ICS_OT_SECURITY_REFERENCE.md)"),
        "MOBILE_ATTACK_ATLAS.md": render_small_matrix(
            "Mobile", "Mobile ATT&CK Technique Atlas", MOBILE_TACTICS, load("mobile/technique_profiles.jsonl"),
            "A technique that serves more than one tactic is listed under each, so the tactic counts add up "
            "to more than the matrix total.",
            "[ATT&CK Technique Atlas (Enterprise)](ATTACK_TECHNIQUE_ATLAS.md), [Threat Group Profiles]"
            "(THREAT_GROUP_PROFILES.md), [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), "
            "[Mobile Security Reference](MOBILE_SECURITY_REFERENCE.md)"),
    }


def comparable(text: str) -> str:
    """A page without the blocks other scripts own (what --check compares)."""
    text = text.replace("\r\n", "\n")
    text = META_RE.sub("", REL_RE.sub("", text)).replace(META_SLOT, "").replace(REL_SLOT, "")
    text = LOCAL_LINK_RE.sub("", LOCAL_MARK_RE.sub("", text))
    return re.sub(r"\n{3,}", "\n\n", text)


def assemble(rel: str, body: str, committed: str | None, tracked: set[str]) -> str:
    """The page to write: the rendered body with the committed card and footer in their slots
    (an empty slot is dropped) and, on the Technique Atlas, the "(local)" links."""
    committed = (committed or "").replace("\r\n", "\n")
    meta = META_RE.search(committed)
    rel_block = REL_RE.search(committed)
    text = body.replace(META_SLOT + "\n\n", "" if not meta else META_SLOT + "\n\n")
    text = text.replace("\n" + REL_SLOT + "\n", "" if not rel_block else "\n" + REL_SLOT + "\n")
    if meta:
        text = text.replace(META_SLOT, meta.group(0))
    if rel_block:
        text = text.replace(REL_SLOT, rel_block.group(0))
    if rel in local_id_pages():
        import build_crosslinks  # noqa: E402  (imported late: it loads the site nav)
        text, _n = build_crosslinks.with_local_links(text, tracked)
    return text


def local_id_pages() -> set[str]:
    with open(os.path.join(ROOT, "docs", "crosslinks.json"), encoding="utf-8") as f:
        return set(json.load(f).get("local_id_pages", []))


def uses_crlf(rel: str) -> bool:
    b = read_bytes(rel)
    return bool(b) and b"\r\n" in b


def self_test() -> int:
    """Planted cases for the helpers the pages depend on."""
    problems = []

    def expect(what, got, want):
        if got != want:
            problems.append(what + ": got " + repr(got) + ", want " + repr(want))

    expect("rekey follows a chain", rekey("T1", {"T1": "T2", "T2": "T3"}), "T3")
    expect("rekey stops on a loop", rekey("T1", {"T1": "T2", "T2": "T1"}), "T1")
    expect("rekey keeps a live ID", rekey("T9", {"T1": "T2"}), "T9")
    expect("id order", sorted(["T1003.010", "T1003", "T1003.002", "T1001"], key=id_key),
           ["T1001", "T1003", "T1003.002", "T1003.010"])
    expect("summary", summary("[Grp](https://attack.mitre.org/groups/G0001) is a group. (Citation: X) "
                              "It is old.(Citation: Y) Third sentence.\n\nSecond paragraph."),
           "Grp is a group. It is old.")
    expect("aliases fit", alias_cell(["A", "B"]), "A, B")
    expect("aliases none", alias_cell([]), "None")
    cell = alias_cell(["Alias" + str(i) * 12 for i in range(10)])
    expect("aliases cut at a boundary", cell.startswith("Alias000000000000, ") and cell.endswith(" more)"), True)
    expect("count", (count(1, "technique"), count(1234, "technique")), ("1 technique", "1,234 techniques"))
    body = "# T\n\nintro\n\n" + META_SLOT + "\n\n## A\n\nrow\n\n" + REL_SLOT + "\n\n---\n\n*Source*\n"
    page = ("# T\n\nintro\n\n<!-- meta:start (x) -->\ncard\n<!-- meta:end -->\n\n## A\n\nrow ([local](/mitre/a.md))"
            "\n\n<!-- related:start (x) -->\nrel\n<!-- related:end -->\n\n---\n\n*Source*\n")
    expect("check ignores the blocks other scripts own", comparable(page.replace("\n", "\r\n")), comparable(body))
    expect("check sees a changed row", comparable(page.replace("row", "row2")) == comparable(body), False)
    expect("no committed blocks: slots dropped", assemble("X.md", body, None, set()),
           "# T\n\nintro\n\n## A\n\nrow\n\n---\n\n*Source*\n")
    kept = assemble("X.md", body, page, set())
    expect("committed blocks carried over", ("card" in kept, "rel" in kept, META_SLOT in kept), (True, True, False))
    for p in problems:
        print("FAIL " + p)
    print(("FAILED: " if problems else "OK: ") + "build_attack_atlases self-test, "
          + str(len(problems)) + " failure(s)")
    return 1 if problems else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="write nothing; exit 1 when a committed page differs")
    mode.add_argument("--self-test", action="store_true", help="run planted cases for the helpers")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    from generate_technique_detail_pages import TACTIC_ORDER  # noqa: E402
    if list(TACTIC_ORDER) != ENTERPRISE_TACTICS:
        raise SystemExit("ENTERPRISE_TACTICS differs from generate_technique_detail_pages.TACTIC_ORDER")

    pages = {rel: plain(body) for rel, body in render_all().items()}
    stale = [rel for rel, body in pages.items() if comparable(read_text(rel) or "") != comparable(body)]
    if args.check:
        if stale:
            print("ATLAS DRIFT: " + ", ".join(stale) + " differ from what scripts/build_attack_atlases.py "
                  "writes from data/attack. Run `python scripts/build_attack_atlases.py`, then "
                  "build_doc_meta.py and build_crosslinks.py, and commit the result.")
            return 1
        print("OK: " + str(len(pages)) + " ATT&CK summary pages match data/attack (" + ATTACK_VER + ")")
        return 0

    tracked = set(tracked_files())
    for rel, body in pages.items():
        committed = read_text(rel)
        text = assemble(rel, body, committed, tracked)
        if committed == text:
            continue
        nl = "\r\n" if uses_crlf(rel) else "\n"
        with open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="") as f:
            f.write(text.replace("\n", nl))
        print("wrote " + rel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
