#!/usr/bin/env python3
"""Generate the tactic-grouped Technique-Detail (techniques/) and Detection-Strategies
(detections/strategies/) subsystems from the committed v19.2 ATT&CK data.

These two subsystems predated the /mitre per-object pages and had NO generator in-repo
(they were v18.1-era one-offs). This builds both deterministically at ATT&CK v19.2:
the 15 v19.2 tactics (Defense Evasion -> Stealth + new Defense Impairment), the T1682-T1690
block included, revoked techniques excluded (their /mitre pages carry banners). G1056 and
the S9xxx software block are official ATT&CK v19.2 entries (verified against attack.mitre.org)
and are INCLUDED in the external attribution lists.

Outputs (repo root): techniques/README.md + techniques/<tactic>.md (x15);
detections/strategies/README.md + detections/strategies/<tactic>.md (x15).
Links: every in-repo link is root-absolute (/X.md). The site is docsify with relativePath:
false, which routes every Markdown link from the site root, so a '../X.md' link escapes it and
404s (scripts/check_docsify_links.py); GitHub resolves '/X.md' from the repository root too.
Each technique's body is folded into a <details> element under its visible heading.
Run from the repo root: python scripts/generate_technique_detail_pages.py
CI drift gate:          python scripts/generate_technique_detail_pages.py --check
  (renders into a temporary directory, writes nothing in the repo, and exits 1 if a
  committed page differs, is missing, or is an orphan the generator no longer writes)
"""
import argparse
import json
import re
import shutil
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from plain_markdown import plain

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "attack" if (ROOT / "attack").exists() else ROOT / "data" / "attack"
VER = "v19.2"

TACTIC_ORDER = [
    ("reconnaissance", "Reconnaissance", "TA0043"), ("resource-development", "Resource Development", "TA0042"),
    ("initial-access", "Initial Access", "TA0001"), ("execution", "Execution", "TA0002"),
    ("persistence", "Persistence", "TA0003"), ("privilege-escalation", "Privilege Escalation", "TA0004"),
    ("stealth", "Stealth", "TA0005"), ("defense-impairment", "Defense Impairment", "TA0112"),
    ("credential-access", "Credential Access", "TA0006"), ("discovery", "Discovery", "TA0007"),
    ("lateral-movement", "Lateral Movement", "TA0008"), ("collection", "Collection", "TA0009"),
    ("command-and-control", "Command and Control", "TA0011"), ("exfiltration", "Exfiltration", "TA0010"),
    ("impact", "Impact", "TA0040"),
]
TAC_NAME = {s: n for s, n, _ in TACTIC_ORDER}
TAC_TAID = {s: t for s, _, t in TACTIC_ORDER}
LAB_GROUPS = set()                     # G1056 is an official ATT&CK v19.2 group (verified live); include it
OFFICIAL_SW = re.compile(r"S\d{4}")    # S9xxx are official v19.2 software too; include the full S#### range


def load(p):
    p = DATA / p
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()] if p.exists() else []


def anchor(tid):
    return "t" + tid.replace(".", "").replace("T", "", 1).lower() if tid.startswith("T") else tid.lower()


def att_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/")


prof = {r["technique_id"]: r for r in load("technique_profiles.jsonl")}
live = [t for t, p in prof.items() if not p.get("revoked")]
# primary tactic = first v19.2 tactic; only keep techniques whose primary is a known tactic
primary = {}
for t in live:
    tacs = prof[t].get("tactics") or []
    tacs = [x for x in tacs if x in TAC_NAME]
    if tacs:
        primary[t] = tacs[0]
by_tac = defaultdict(list)
for t, ptac in primary.items():
    by_tac[ptac].append(t)
for s in by_tac:
    by_tac[s].sort()

groups_by_t = defaultdict(list)
for r in load("group_to_technique.jsonl"):
    if r.get("group_id") not in LAB_GROUPS:
        groups_by_t[r["technique_id"]].append((r["group_id"], r["group_name"]))
sw_by_t = defaultdict(list)
for r in load("software_to_technique.jsonl"):
    if OFFICIAL_SW.fullmatch(r.get("software_id", "")):
        sw_by_t[r["technique_id"]].append((r["software_id"], r["software_name"]))
det_by_t = defaultdict(list)
for r in load("detection_strategies.jsonl"):
    det_by_t[r["technique_id"]].append(r)
an_by_id = {r["analytic_id"]: r for r in load("analytics.jsonl")}


# Each technique's body is folded under its heading. The heading and its <a id> anchor stay
# visible, so links, the page's table of contents and search land on them, and the site
# opens the fold when a link targets that technique (index.html). The opening line matches
# the fold format scripts/build_doc_meta.py writes, so reading times leave the summary out.
FOLD_OPEN = '<details class="tsw-fold"><summary>{}</summary>'
FOLD_CLOSE = "</details>"


def count(n, noun, plural=None):
    if n == 1:
        return "1 " + noun
    if plural is None:
        plural = noun[:-1] + "ies" if noun.endswith("y") else noun + "s"
    return str(n) + " " + plural


def series(parts):
    """'a', 'a and b', 'a, b, and c' (serial comma, docs/VOICE.md)."""
    if len(parts) < 3:
        return " and ".join(parts)
    return ", ".join(parts[:-1]) + ", and " + parts[-1]


def dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ---------------------------------------------------------------- technique-detail pages
def tech_block(tid):
    p = prof[tid]
    out = ["### " + tid + " — " + p["name"], '<a id="' + anchor(tid) + '"></a>', ""]
    tacs = ", ".join(TAC_NAME[x] for x in (p.get("tactics") or []) if x in TAC_NAME)
    plats = ", ".join(p.get("platforms") or []) or "—"
    head = ""
    if p.get("is_subtechnique") and p.get("parent_id") in prof:
        par = p["parent_id"]
        head = "sub-technique of [" + par + "](/techniques/" + primary.get(par, primary.get(tid)) + ".md#" + anchor(par) + ") · "
    out.append(head + "**Tactics:** " + tacs + " · **Platforms:** " + plats +
               " · [ATT&CK ↗](" + att_url(tid) + ")  ")
    out.append("")
    migs, nist = p.get("mitigations") or [], p.get("nist_800_53_controls") or []
    strat = p.get("detection_strategies") or []
    grps, sw = dedup(groups_by_t.get(tid) or []), dedup(sw_by_t.get(tid) or [])
    parts = ["the description"] if p.get("description") else []
    parts += [count(len(migs), "ATT&CK mitigation")] if migs else []
    parts += [count(len(nist), "NIST 800-53 control")] if nist else []
    parts += [("the detection strategy" if len(strat) == 1 else count(len(strat), "detection strategy"))] if strat else []
    parts += [count(len(grps), "threat group")] if grps else []
    parts += [count(len(sw), "software entry", "software entries")] if sw else []
    out += [FOLD_OPEN.format("Show " + series(parts)), ""]
    if p.get("description"):
        out.append(p["description"].strip())
        out.append("")
    migs = p.get("mitigations") or []
    if migs:
        out.append("**ATT&CK mitigations (" + str(len(migs)) + "):** " +
                   ", ".join("[" + m["id"] + " " + m["name"] + "](/ATTACK_MITIGATIONS_REFERENCE.md#" +
                             m["id"].lower() + ")" for m in migs) + "  ")
    else:
        out.append("**ATT&CK mitigations:** none mapped  ")
    nist = p.get("nist_800_53_controls") or []
    if nist:
        via = p.get("nist_800_53_controls_via_revoked") or {}
        note = (" (carried forward from revoked " + ", ".join(sorted(via)) +
                ": the CTID mapping is keyed on the predecessor id)") if via else ""
        out.append("**NIST 800-53 R5 controls (" + str(len(nist)) + "):** " +
                   ", ".join("`" + c + "`" for c in nist) + note + "  ")
    else:
        # build_control_rollup.py already carries CTID edges forward from revoked
        # predecessors, so an empty list means neither this id nor any predecessor is mapped.
        out.append("**NIST 800-53 R5 controls:** none (*no CTID mapping under this ID or its "
                   "predecessors; rely on detection/design controls*)  ")
    strat = p.get("detection_strategies") or []
    if strat:
        out.append("**ATT&CK detection strategy:** " + "; ".join(strat) + "  ")
    grps = groups_by_t.get(tid) or []
    if grps:
        grps = dedup(grps)
        out.append("**Used by " + str(len(grps)) + " threat groups:** " +
                   ", ".join("[" + g + " " + n + "](https://attack.mitre.org/groups/" + g + ")" for g, n in grps) + "  ")
    sw = sw_by_t.get(tid) or []
    if sw:
        sw = dedup(sw)
        out.append("**Implemented by " + str(len(sw)) + " software:** " +
                   ", ".join("[" + s + " " + n + "](https://attack.mitre.org/software/" + s + ")" for s, n in sw) + "  ")
    out += ["", FOLD_CLOSE, "", "---", ""]
    return "\n".join(out)


def render_tech_tactic(slug):
    ts = by_tac.get(slug, [])
    name = TAC_NAME[slug]
    out = ["# " + name + " — Technique Detail", "",
           "> Full detail pages for the **" + str(len(ts)) + " ATT&CK techniques** whose primary tactic is "
           "[" + name + "](https://attack.mitre.org/tactics/" + TAC_TAID[slug] + "/) (ATT&CK Enterprise " + VER +
           "). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection "
           "guidance, and the threat groups and software that use it. See the "
           "[Technique Atlas](/ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and "
           "[all techniques index](/techniques/README.md).", "", "---", ""]
    for t in ts:
        out.append(tech_block(t))
    return "\n".join(out)


def render_tech_readme():
    navs = " · ".join("[" + n + "](/techniques/" + s + ".md)" for s, n, _ in TACTIC_ORDER)
    out = ["# ATT&CK Technique Detail — Index", "",
           "> Consolidated detail pages for all **" + str(len(primary)) + " MITRE ATT&CK Enterprise techniques** "
           "(" + VER + "), grouped by primary tactic. Each links its ATT&CK description, mitigations, NIST 800-53 "
           "controls, detections, and the groups and software that use it.", "",
           "**By tactic:** " + navs, "",
           "See also: [Technique Atlas](/ATTACK_TECHNIQUE_ATLAS.md) (matrix view) · "
           "[Threat Group Profiles](/THREAT_GROUP_PROFILES.md) · "
           "[Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md)", "",
           "| Technique | Name | Detail page |", "|---|---|---|"]
    for t in sorted(primary):
        s = primary[t]
        out.append("| `" + t + "` | " + prof[t]["name"] + " | [" + TAC_NAME[s] + "](/techniques/" + s +
                   ".md#" + anchor(t) + ") |")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- detection-strategy pages
def det_block(tid):
    strategies = det_by_t.get(tid) or []
    if not strategies:
        return ""
    p = prof[tid]
    out = ["### " + tid + " — " + p["name"], '<a id="' + anchor(tid) + '"></a>', ""]
    slug = primary.get(tid, "")
    n_an = sum(1 for st in strategies for aid in st.get("analytic_ids", []) if aid in an_by_id)
    what = "the detection strategy" if len(strategies) == 1 else count(len(strategies), "detection strategy")
    if n_an:
        what += (" and its " if len(strategies) == 1 else " and their ") + (
            "analytic" if n_an == 1 else count(n_an, "analytic"))
    out += [FOLD_OPEN.format("Show " + what), ""]
    for st in strategies:
        plats = ", ".join(st.get("platforms") or []) or "—"
        out.append("**Detection strategy:** " + st.get("name", "") + " (`" + st.get("strategy_id", "") + "`)  ")
        out.append("**Platforms:** " + plats + "  ")
        out.append("**ATT&CK:** [" + tid + "](" + att_url(tid) + "/) · [detail page](/techniques/" +
                   slug + ".md#" + anchor(tid) + ")")
        out.append("")
        for aid in st.get("analytic_ids", []):
            a = an_by_id.get(aid)
            if not a:
                continue
            ap = ", ".join(a.get("platforms") or []) or "—"
            out.append("- **`" + aid + "` " + a.get("name", "") + "** · " + ap)
            if a.get("description"):
                out.append("  " + a["description"].strip())
            ls = a.get("log_sources") or []
            if ls:
                parts = []
                for s in ls:
                    seg = "`" + str(s.get("log_source", ""))
                    if s.get("channel") and s["channel"] != "None":
                        seg += " (" + str(s["channel"]) + ")"
                    seg += "`"
                    parts.append(seg)
                out.append("  - *Log sources:* " + "; ".join(parts))
            tune = a.get("mutable_elements") or []
            if tune:
                out.append("  - *Tune:* " + "; ".join("`" + m.get("field", "") + "`: " + (m.get("description", "") or "")
                                                       for m in tune))
        out.append("")
    out += [FOLD_CLOSE, "", "---", ""]
    return "\n".join(out)


def render_det_tactic(slug):
    ts = [t for t in by_tac.get(slug, []) if det_by_t.get(t)]
    name = TAC_NAME[slug]
    out = ["# " + name + " — Detection Strategies", "",
           "> MITRE ATT&CK detection strategies and analytics (" + VER + ") for techniques whose primary tactic is "
           "**" + name + "**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, "
           "and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK "
           "detection-strategy model in the Enterprise STIX.", "",
           "See also: [all detection strategies index](/detections/strategies/README.md) · "
           "[Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · "
           "[Data Components & Log Sources](/ATTACK_DATA_COMPONENTS.md) · "
           "[Technique Detail Pages](/techniques/README.md)", "", "---", ""]
    for t in ts:
        out.append(det_block(t))
    return "\n".join(out)


def render_det_readme():
    navs = " · ".join("[" + n + "](/detections/strategies/" + s + ".md)" for s, n, _ in TACTIC_ORDER)
    n_strat = len({r["strategy_id"] for rs in det_by_t.values() for r in rs})
    n_an = len(an_by_id)
    out = ["# ATT&CK Detection Strategies — Index", "",
           "> **" + str(n_strat) + " MITRE ATT&CK detection strategies** and **" + str(n_an) + " analytics** (" + VER +
           ") — the authoritative, MITRE-authored guidance for detecting each technique, with concrete log "
           "sources, channels, detection logic, and tunable parameters. Complements the "
           "[ready-to-run Technique Detection Library](/detections/TECHNIQUE_DETECTION_LIBRARY.md).", "",
           "**By tactic:** " + navs, ""]
    return "\n".join(out)


TREES = ("techniques", "detections/strategies")


def check():
    """Render both trees into a temp dir and diff them against the committed pages."""
    tmp = Path(tempfile.mkdtemp(prefix="tsw-techdetail-check-"))
    try:
        write_pages(tmp)
        problems = []
        n = 0
        for tree in TREES:
            out, committed = tmp / tree, ROOT / tree
            produced = {f.name for f in out.glob("*.md")}
            n += len(produced)
            for name in sorted(produced):
                c = committed / name
                if not c.exists():
                    problems.append("missing  " + tree + "/" + name + "  (generator writes it; not committed)")
                elif c.read_text(encoding="utf-8") != (out / name).read_text(encoding="utf-8"):
                    problems.append("stale    " + tree + "/" + name + "  (committed page differs from the data)")
            for c in sorted(committed.glob("*.md")):
                if c.name not in produced:
                    problems.append("orphan   " + tree + "/" + c.name + "  (committed, but no longer generated)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if problems:
        print("TECHNIQUE/DETECTION PAGES DRIFT: run `python scripts/generate_technique_detail_pages.py` "
              "and commit the result:")
        for line in problems:
            print("  " + line)
        return 1
    print("OK: " + str(n) + " generated techniques/ + detections/strategies/ pages match the committed tree")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Generate techniques/ and detections/strategies/ from data/attack.")
    ap.add_argument("--check", action="store_true", help="write nothing; exit 1 if the committed pages drift")
    if ap.parse_args().check:
        sys.exit(check())
    write_pages(ROOT)


def write_pages(root):
    tdir = root / "techniques"
    ddir = root / "detections" / "strategies"
    tdir.mkdir(parents=True, exist_ok=True)
    ddir.mkdir(parents=True, exist_ok=True)
    # remove the stale defense-evasion.md (renamed to stealth + defense-impairment)
    for d in (tdir, ddir):
        old = d / "defense-evasion.md"
        if old.exists():
            old.unlink()
    for slug, _, _ in TACTIC_ORDER:
        (tdir / (slug + ".md")).write_text(plain(render_tech_tactic(slug)), encoding="utf-8", newline="\n")
        (ddir / (slug + ".md")).write_text(plain(render_det_tactic(slug)), encoding="utf-8", newline="\n")
    (tdir / "README.md").write_text(plain(render_tech_readme()), encoding="utf-8", newline="\n")
    (ddir / "README.md").write_text(plain(render_det_readme()), encoding="utf-8", newline="\n")
    print("techniques/: wrote 15 tactic pages + README (" + str(len(primary)) + " techniques)")
    print("detections/strategies/: wrote 15 tactic pages + README")


if __name__ == "__main__":
    main()
