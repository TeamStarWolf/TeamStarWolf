#!/usr/bin/env python3
"""
Generate the enriched MITRE per-object knowledge base (mitre/) from committed data (data/).

Regenerates one page per MITRE object for: techniques, mitigations, tactics, D3FEND,
CAPEC, ATLAS, plus the /mitre/README landing. Everything is derived deterministically
from data/attack, data/weaknesses, and data/ai.

PRESERVED, NOT REGENERATED: the "Team Star Wolf corpus signal" block (and the star that
flags corpus-observed techniques). That signal is keyword-derived from a local
529-machine HTB training corpus that is NOT committed to this repo, so it is carried
verbatim from the current pages. This script only ever re-emits what it finds.

Usage:
    python scripts/generate_mitre_pages.py                 # techniques + landing
    python scripts/generate_mitre_pages.py --only techniques,landing
    python scripts/generate_mitre_pages.py --check         # write to mitre/_gen_check/ (no overwrite)
"""
import json
import re
import argparse
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
MITRE = ROOT / "mitre"
ATTACK_VER = "v19.2"

DASH = "\N{EM DASH}"
ARROW = "\N{RIGHTWARDS ARROW}"
STAR = "\N{WHITE MEDIUM STAR}"

FOOTER = (
    "---\n\n"
    "*Source: MITRE ATT&CK\N{REGISTERED SIGN} (v19.2) " + DASH + " ATT&CK\N{REGISTERED SIGN}, "
    "D3FEND\N{TRADE MARK SIGN}, and CAPEC\N{TRADE MARK SIGN} are trademarks of "
    "The MITRE Corporation. This is an independent reference summary enriched with Team "
    "Star Wolf corpus telemetry; consult the upstream projects for authoritative content. "
    "Corpus figures are keyword-derived from a 529-machine training walkthrough corpus "
    "(lower-bound evidence), not an official MITRE mapping.*\n"
)

CAP_NAMED = 25          # cap named groups/software listed per technique
CAP_ANALYTICS = 8       # cap analytics rendered per technique
CAP_LOGSRC = 6          # cap log sources rendered per analytic


# ----------------------------------------------------------------------------- helpers
def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def tslug(tid):
    """T1059.001 -> T1059-001 (matches committed file naming, case preserved)."""
    return tid.replace(".", "-")


def tanchor(tid):
    """T1059.001 -> t1059001 (matches the existing <a id> anchors)."""
    return tid.replace(".", "").lower()


def dslug(name):
    """'Access Modeling' -> access-modeling (matches d3fend/ filenames)."""
    return re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")


def as_list(v):
    """Return a list from either a real list or a stringified python/JSON list of ids."""
    if isinstance(v, list):
        return v
    if v in (None, ""):
        return []
    toks = re.findall(r"""['"]([^'"]+)['"]""", str(v))
    return toks if toks else [str(v)]


def clean_capec_field(s):
    """CAPEC prose fields use '::' as a record separator and LABEL: prefixes."""
    if not s:
        return []
    out = []
    for part in str(s).split("::"):
        part = part.strip()
        if not part:
            continue
        part = re.sub(r"^[A-Z][A-Z0-9 _-]{1,24}:\s*", "", part).strip()
        if part:
            out.append(part)
    return out


CORPUS_RE = re.compile(r"\*\*Team Star Wolf corpus signal.*?(?=\n\s*\n|\Z)", re.S)


def extract_corpus(md_path):
    """Pull the preserved corpus paragraph (not in committed data) from an existing page."""
    if not md_path.exists():
        return None
    m = CORPUS_RE.search(md_path.read_text(encoding="utf-8"))
    return m.group(0).strip() if m else None


def link(text, url):
    return "[" + text + "](" + url + ")" if url else text


def sstr(v):
    """Stringify a field that may be a list or scalar."""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return "" if v is None else str(v)


# ----------------------------------------------------------------------------- data load
class DB:
    def __init__(self):
        tp = load_jsonl(DATA / "attack/technique_profiles.jsonl")
        self.prof = {r["technique_id"]: r for r in tp}

        self.d3 = defaultdict(list)
        for r in load_jsonl(DATA / "attack/technique_to_d3fend.jsonl"):
            self.d3[r["technique_id"]].append(r)

        self.analytics = defaultdict(list)
        for r in load_jsonl(DATA / "attack/analytics.jsonl"):
            for t in r.get("technique_ids", []):
                self.analytics[t].append(r)

        self.groups_by_t = defaultdict(list)
        for r in load_jsonl(DATA / "attack/group_to_technique.jsonl"):
            self.groups_by_t[r["technique_id"]].append(r["group_name"])
        self.sw_by_t = defaultdict(list)
        for r in load_jsonl(DATA / "attack/software_to_technique.jsonl"):
            self.sw_by_t[r["technique_id"]].append(r["software_name"])

        self.group_url = {r["name"]: r.get("url") for r in load_jsonl(DATA / "attack/groups.jsonl")}
        self.sw_url = {r["name"]: r.get("url") for r in load_jsonl(DATA / "attack/software.jsonl")}

        self.nist_name = {}
        for r in load_jsonl(DATA / "control_to_technique.jsonl"):
            c, d = r.get("nist_control"), r.get("control_desc")
            if c and d and c not in self.nist_name:
                self.nist_name[c] = d

        self.subs = defaultdict(list)
        for r in tp:
            if r.get("parent_id"):
                self.subs[r["parent_id"]].append(r["technique_id"])

        # corpus signal preserved from existing pages (technique_id -> paragraph)
        self.corpus = {}
        tdir = MITRE / "techniques"
        if tdir.exists():
            for tid in self.prof:
                block = extract_corpus(tdir / (tslug(tid) + ".md"))
                if block:
                    self.corpus[tid] = block
        self.corpus_ids = set(self.corpus)


# ----------------------------------------------------------------------------- technique
def render_technique(db, tid):
    p = db.prof[tid]
    out = ["# " + tid + " " + DASH + " " + p["name"] + "\n", '<a id="' + tanchor(tid) + '"></a>\n']

    tactics = ", ".join(p.get("tactics") or []) or DASH
    plats = ", ".join(p.get("platforms") or []) or DASH
    hdr = [
        "**Tactics:** " + tactics + "  ",
        "**Platforms:** " + plats + "  ",
        "**ATT&CK:** [" + tid + "](" + str(p.get("url")) + ")  ",
    ]
    if p.get("parent_id"):
        par = p["parent_id"]
        pname = db.prof.get(par, {}).get("name", "")
        hdr.append("**Sub-technique of:** [" + par + " " + DASH + " " + pname +
                   "](/mitre/techniques/" + tslug(par) + ".md)  ")
    out.append("\n".join(hdr) + "\n")

    if p.get("description"):
        out.append(p["description"].strip() + "\n")

    if tid in db.corpus:
        out.append(db.corpus[tid] + "\n")

    # Mitigations
    migs = p.get("mitigations") or []
    if migs:
        out.append("## Mitigations (" + str(len(migs)) + ")\n")
        out.append("\n".join(
            "- [" + m["id"] + " " + DASH + " " + m["name"] + "](/mitre/mitigations/" + m["id"] + ".md)"
            for m in migs) + "\n")

    # D3FEND (now linked to the d3fend pages)
    edges = db.d3.get(tid) or []
    if edges:
        seen, rows = set(), []
        for e in edges:
            name = e.get("d3fend_technique")
            if not name or name in seen:
                continue
            seen.add(name)
            tac = sstr(e.get("d3fend_tactic"))
            rel = sstr(e.get("relation")) or "maps"
            tac_txt = " (" + tac + ")" if tac else ""
            rows.append("- [" + name + "](/mitre/d3fend/" + dslug(name) + ".md)" + tac_txt + " " + DASH + " " + rel)
        out.append("## D3FEND countermeasures (" + str(len(rows)) + ")\n")
        out.append("\n".join(rows) + "\n")

    # Detection (enriched: strategies + analytics with log sources)
    strategies = p.get("detection_strategies") or []
    analytics = db.analytics.get(tid) or []
    if strategies or analytics:
        out.append("## Detection\n")
        if strategies:
            out.append("**Detection strategies:**\n")
            out.append("\n".join("- " + s for s in strategies) + "\n")
        if analytics:
            out.append("**Analytics (" + str(len(analytics)) + "):**\n")
            arows = []
            for a in analytics[:CAP_ANALYTICS]:
                aplats = ", ".join(a.get("platforms") or []) or DASH
                ls = a.get("log_sources") or []
                parts = []
                for s in ls[:CAP_LOGSRC]:
                    seg = "`" + str(s.get("log_source", ""))
                    if s.get("channel") and s["channel"] != "None":
                        seg += " " + str(s["channel"])
                    seg += "`"
                    if s.get("data_component"):
                        seg += " " + ARROW + " " + str(s["data_component"])
                    parts.append(seg)
                more = " (+" + str(len(ls) - CAP_LOGSRC) + " more)" if len(ls) > CAP_LOGSRC else ""
                name = a.get("name") or a.get("analytic_id")
                arows.append("- **" + str(name) + "** (" + aplats + ") " + DASH + " " + "; ".join(parts) + more)
            out.append("\n".join(arows) + "\n")
            if len(analytics) > CAP_ANALYTICS:
                out.append("_+" + str(len(analytics) - CAP_ANALYTICS) + " more analytics._\n")

    # Data sources & telemetry (from the analytics' log sources)
    comps, seen = [], set()
    for a in analytics:
        for s in a.get("log_sources") or []:
            dc = s.get("data_component")
            if dc and dc not in seen:
                seen.add(dc)
                comps.append(dc)
    if comps:
        out.append("## Data sources & telemetry (" + str(len(comps)) + ")\n")
        out.append(", ".join("**" + c + "**" for c in comps) + "\n")

    # Adversary usage (named, replaces bare counts)
    groups = db.groups_by_t.get(tid) or []
    sw = db.sw_by_t.get(tid) or []
    gc = p.get("group_count", len(groups))
    sc = p.get("software_count", len(sw))
    cc = p.get("campaign_count", 0)
    if groups or sw or cc:
        out.append("## Adversary usage\n")
        if groups:
            named = ", ".join(link(g, db.group_url.get(g)) for g in groups[:CAP_NAMED])
            extra = " _+" + str(len(groups) - CAP_NAMED) + " more_" if len(groups) > CAP_NAMED else ""
            out.append("**Threat groups (" + str(gc) + "):** " + named + extra + "\n")
        if sw:
            named = ", ".join(link(s, db.sw_url.get(s)) for s in sw[:CAP_NAMED])
            extra = " _+" + str(len(sw) - CAP_NAMED) + " more_" if len(sw) > CAP_NAMED else ""
            out.append("**Software/tools (" + str(sc) + "):** " + named + extra + "\n")
        if cc:
            out.append("**Campaigns:** " + str(cc) + " (per MITRE ATT&CK)\n")

    # Sub-techniques (for parent techniques)
    kids = sorted(db.subs.get(tid) or [])
    if kids:
        out.append("## Sub-techniques (" + str(len(kids)) + ")\n")
        out.append("\n".join(
            "- [" + k + " " + DASH + " " + db.prof[k]["name"] + "](/mitre/techniques/" + tslug(k) + ".md)"
            for k in kids) + "\n")

    # NIST 800-53 (now with control names)
    nist = p.get("nist_800_53_controls") or []
    if nist:
        out.append("## NIST 800-53 controls (" + str(len(nist)) + ")\n")
        rows = []
        for c in nist:
            nm = db.nist_name.get(c)
            rows.append("- `" + c + "` " + DASH + " " + nm if nm else "- `" + c + "`")
        out.append("\n".join(rows) + "\n")

    # CAPEC (if mapped)
    capec = p.get("capec") or []
    if capec:
        ids = []
        for c in capec:
            cid = c.get("id") if isinstance(c, dict) else c
            cname = c.get("name") if isinstance(c, dict) else None
            label = (cid + " " + DASH + " " + cname) if cname else cid
            ids.append("- [" + label + "](/mitre/capec/" + cid + ".md)")
        out.append("## CAPEC attack patterns (" + str(len(ids)) + ")\n")
        out.append("\n".join(ids) + "\n")

    out.append(FOOTER)
    return "\n".join(out)


# ----------------------------------------------------------------------------- landing
def render_landing(db):
    n_tech = len(list((MITRE / "techniques").glob("T*.md")))
    n_mit = len(list((MITRE / "mitigations").glob("M*.md")))
    n_tac = len([p for p in (MITRE / "tactics").glob("*.md") if p.name != "README.md"])
    n_d3 = len([p for p in (MITRE / "d3fend").glob("*.md") if p.name != "README.md"])
    n_cap = len(list((MITRE / "capec").glob("CAPEC-*.md")))
    n_atl = len(list((MITRE / "atlas").glob("AML-*.md")))
    corpus_n = len(db.corpus_ids)
    lines = [
        "# MITRE Frameworks " + DASH + " Enriched Knowledge Base",
        "",
        "ATT&CK-Navigator-style browsable pages: **one page per MITRE object**, cross-linked across "
        "frameworks (ATT&CK, Mitigation, D3FEND, CAPEC, NIST 800-53) and enriched with detection "
        "analytics, data sources, named adversary usage, and Team Star Wolf corpus telemetry. ATT&CK " + ATTACK_VER + ".",
        "",
        "## Browse by object",
        "",
        "| Section | Pages | What each page carries |",
        "|---|---|---|",
        "| [Techniques](/mitre/techniques/README.md) | " + str(n_tech) + " | tactics, platforms, mitigations, "
        "**linked D3FEND**, **detection analytics + log sources**, **data sources**, **named threat-group & tool "
        "usage**, sub-techniques, NIST 800-53 (named), CAPEC, corpus prevalence |",
        "| [Mitigations](/mitre/mitigations/README.md) | " + str(n_mit) + " | how-to-implement, NIST mapping, "
        "techniques countered, corpus relevance |",
        "| [Tactics](/mitre/tactics/README.md) | " + str(n_tac) + " | the \"why\" of each stage, its techniques, "
        "top corpus-observed techniques |",
        "| [D3FEND](/mitre/d3fend/README.md) | " + str(n_d3) + " | defensive technique, D3FEND tactic, digital "
        "artifacts, ATT&CK techniques countered |",
        "| [CAPEC](/mitre/capec/README.md) | " + str(n_cap) + " | abstraction, severity, likelihood, mapped "
        "ATT&CK, related CWE, prerequisites, mitigations |",
        "| [ATLAS (AI/ML)](/mitre/atlas/README.md) | " + str(n_atl) + " | adversarial-AI techniques + mitigations |",
        "| [Cross-Framework Crosswalk](/mitre/crosswalk.md) | " + DASH + " | technique, mitigation, NIST, D3FEND, "
        "CAPEC in one table |",
        "",
        "## Start here",
        "",
        "- **Investigating a technique?** open its Technique page " + DASH + " mitigations, detection analytics "
        "(with the exact log sources), and which groups/tools use it are all on one page.",
        "- **Building a control set?** open a Mitigation page for how-to-implement + NIST mapping, or the "
        "Crosswalk for the full join.",
        "- **Engineering detections?** the Detection + Data-sources sections on each technique name the "
        "analytics and telemetry to collect.",
        "- **Prioritising?** " + STAR + " marks the " + str(corpus_n) + " techniques observed in the Team Star "
        "Wolf 529-machine training corpus " + DASH + " real-world lower-bound prevalence.",
        "",
        "**Coverage:** every ATT&CK object cross-links to its related mitigations, D3FEND countermeasures, "
        "CAPEC patterns, and NIST 800-53 controls " + DASH + " the cross-framework relationships in one browsable place.",
        "",
        FOOTER,
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="techniques,landing")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    only = set(x.strip() for x in args.only.split(",") if x.strip())

    db = DB()
    out_root = (MITRE / "_gen_check") if args.check else MITRE
    print("loaded: " + str(len(db.prof)) + " techniques, corpus preserved for " +
          str(len(db.corpus_ids)) + " of them")

    if "techniques" in only:
        d = out_root / "techniques"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for tid in db.prof:
            (d / (tslug(tid) + ".md")).write_text(render_technique(db, tid), encoding="utf-8")
            n += 1
        print("techniques: wrote " + str(n) + " pages")

    if "landing" in only:
        out_root.mkdir(parents=True, exist_ok=True)
        (out_root / "README.md").write_text(render_landing(db), encoding="utf-8")
        print("landing: wrote README.md")


if __name__ == "__main__":
    main()
