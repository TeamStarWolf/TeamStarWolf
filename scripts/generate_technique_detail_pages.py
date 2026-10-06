#!/usr/bin/env python3
"""Generate the tactic-grouped Technique-Detail (techniques/) and Detection-Strategies
(detections/strategies/) subsystems from the committed v19.2 ATT&CK data.

These two subsystems predated the /mitre per-object pages and had NO generator in-repo
(they were v18.1-era one-offs). This builds both deterministically at ATT&CK v19.2:
the 15 v19.2 tactics (Defense Evasion -> Stealth + new Defense Impairment), the T1682-T1690
block included, revoked techniques excluded (their /mitre pages carry banners), and
lab-fictional groups (G1056) / non-official S9xxx software excluded from the external
attribution lists.

Outputs (repo root): techniques/README.md + techniques/<tactic>.md (x15);
detections/strategies/README.md + detections/strategies/<tactic>.md (x15).
Run from the repo root: python scripts/generate_technique_detail_pages.py
"""
import json
import re
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
LAB_GROUPS = {"G1056"}
OFFICIAL_SW = re.compile(r"S[01]\d{3}")


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
    if p.get("description"):
        out.append(p["description"].strip())
        out.append("")
    migs = p.get("mitigations") or []
    if migs:
        out.append("**ATT&CK mitigations (" + str(len(migs)) + "):** " +
                   ", ".join("[" + m["id"] + " " + m["name"] + "](../ATTACK_MITIGATIONS_REFERENCE.md#" +
                             m["id"].lower() + ")" for m in migs) + "  ")
    else:
        out.append("**ATT&CK mitigations:** none mapped  ")
    nist = p.get("nist_800_53_controls") or []
    if nist:
        out.append("**NIST 800-53 R5 controls (" + str(len(nist)) + "):** " +
                   ", ".join("`" + c + "`" for c in nist) + "  ")
    else:
        out.append("**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  ")
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
    out.append("")
    out.append("---")
    out.append("")
    return "\n".join(out)


def render_tech_tactic(slug):
    ts = by_tac.get(slug, [])
    name = TAC_NAME[slug]
    out = ["# " + name + " — Technique Detail", "",
           "> Full detail pages for the **" + str(len(ts)) + " ATT&CK techniques** whose primary tactic is "
           "[" + name + "](https://attack.mitre.org/tactics/" + TAC_TAID[slug] + "/) (ATT&CK Enterprise " + VER +
           "). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection "
           "guidance, and the threat groups and software that use it. See the "
           "[Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and "
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
           "See also: [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) (matrix view) · "
           "[Threat Group Profiles](../THREAT_GROUP_PROFILES.md) · "
           "[Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md)", "",
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
    for st in strategies:
        plats = ", ".join(st.get("platforms") or []) or "—"
        out.append("**Detection strategy:** " + st.get("name", "") + " (`" + st.get("strategy_id", "") + "`)  ")
        out.append("**Platforms:** " + plats + "  ")
        out.append("**ATT&CK:** [" + tid + "](" + att_url(tid) + "/) · [detail page](../../techniques/" +
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
                out.append("  - *Tune:* " + "; ".join("`" + m.get("field", "") + "` — " + (m.get("description", "") or "")
                                                       for m in tune))
        out.append("")
    out.append("---")
    out.append("")
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
           "[Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · "
           "[Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · "
           "[Technique Detail Pages](../../techniques/README.md)", "", "---", ""]
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
           "[ready-to-run Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md).", "",
           "**By tactic:** " + navs, ""]
    return "\n".join(out)


def main():
    tdir = ROOT / "techniques"
    ddir = ROOT / "detections" / "strategies"
    tdir.mkdir(parents=True, exist_ok=True)
    ddir.mkdir(parents=True, exist_ok=True)
    # remove the stale defense-evasion.md (renamed to stealth + defense-impairment)
    for d in (tdir, ddir):
        old = d / "defense-evasion.md"
        if old.exists():
            old.unlink()
    for slug, _, _ in TACTIC_ORDER:
        (tdir / (slug + ".md")).write_text(plain(render_tech_tactic(slug)), encoding="utf-8")
        (ddir / (slug + ".md")).write_text(plain(render_det_tactic(slug)), encoding="utf-8")
    (tdir / "README.md").write_text(plain(render_tech_readme()), encoding="utf-8")
    (ddir / "README.md").write_text(plain(render_det_readme()), encoding="utf-8")
    print("techniques/: wrote 15 tactic pages + README (" + str(len(primary)) + " techniques)")
    print("detections/strategies/: wrote 15 tactic pages + README")


if __name__ == "__main__":
    main()
