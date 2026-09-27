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

SHORT_FOOTER = (
    "---\n\n"
    "*Source: MITRE ATT&CK\N{REGISTERED SIGN} / D3FEND\N{TRADE MARK SIGN} / CAPEC\N{TRADE MARK SIGN} / "
    "ATLAS\N{TRADE MARK SIGN} " + DASH + " trademarks of The MITRE Corporation. Independent reference "
    "summary; consult the upstream projects for authoritative content.*\n"
)

CAP_NAMED = 25          # cap named groups/software listed per technique
CAP_ANALYTICS = 8       # cap analytics rendered per technique
CAP_LOGSRC = 6          # cap log sources rendered per analytic


def extract_section(md_text, heading):
    """Return the body of a '## {heading}' section (until the next '## ' or '---'), preserved verbatim."""
    if not md_text:
        return None
    lines = md_text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if ln.strip() == "## " + heading or ln.strip().startswith("## " + heading + " ("):
            start = i
            break
    if start is None:
        return None
    body = []
    for ln in lines[start + 1:]:
        if ln.startswith("## ") or ln.strip() == "---":
            break
        body.append(ln)
    return "\n".join(body).strip() or None


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
    """CAPEC prose fields: accept a JSON array (current data) or a '::'-joined string (legacy)."""
    if not s:
        return []
    parts = s if isinstance(s, list) else str(s).split("::")
    out = []
    for part in parts:
        part = str(part).strip()
        if not part:
            continue
        if part.rstrip(".").strip().lower() in ("none", "n/a", "na", "unknown", "tbd", "todo"):
            continue  # MITRE placeholder meaning "no content" — drop the noise bullet
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


# Non-canonical ATT&CK software links (the S9NNN emerging/community namespace has no
# attack.mitre.org page); strip the hyperlink from description prose, keep the name.
_NONCANON_SW = re.compile(r"\[([^\]]+)\]\(https://attack\.mitre\.org/software/S9\d{3}\)")


def canon_desc(text):
    return _NONCANON_SW.sub(r"\1", text or "")


def sstr(v):
    """Stringify a field that may be a list or scalar."""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return "" if v is None else str(v)


_ABBR = {"e.g", "i.e", "etc", "vs", "cf", "al", "u.s", "a.k.a", "resp", "approx",
         "fig", "eq", "dr", "mr", "ms", "inc", "ltd", "co", "st", "no", "ie", "eg", "ex"}


def summarize(text, max_chars=220):
    """First sentence (abbreviation-aware) of a description, on one line; else a length clip."""
    if not text:
        return ""
    t = re.sub(r"\s+", " ", str(text)).strip()
    s = t
    for m in re.finditer(r"[.!?]+(?=\s|$)", t):
        tok = re.sub(r"[^A-Za-z.]", "", t[:m.start()].rsplit(" ", 1)[-1]).rstrip(".").lower()
        if tok in _ABBR or len(tok) <= 1:
            continue  # abbreviation ("e.g.") or a single-letter initial — not a real sentence end
        s = t[:m.end()]
        break
    if len(s) > max_chars:
        s = s[:max_chars].rsplit(" ", 1)[0].rstrip(",;:(") + "\N{HORIZONTAL ELLIPSIS}"
    return s


def first_alias_str(aliases, primary_name, cap=4):
    """'aka X, Y' from an aliases list, excluding the primary name."""
    al = [a for a in (aliases or []) if a and a != primary_name][:cap]
    return "aka " + ", ".join(al) if al else ""


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

        gj = load_jsonl(DATA / "attack/groups.jsonl")
        self.group = {r["name"]: r for r in gj}
        self.group_url = {r["name"]: r.get("url") for r in gj}
        sj = load_jsonl(DATA / "attack/software.jsonl")
        self.sw = {r["name"]: r for r in sj}
        self.sw_url = {r["name"]: r.get("url") for r in sj}
        # optional deep-enrichment data (present after the data-refresh lane lands)
        d3c_path = DATA / "attack/d3fend_countermeasures.jsonl"
        self.d3_defs = {r["name"]: r for r in load_jsonl(d3c_path)} if d3c_path.exists() else {}

        # cross-framework crosswalks: CAR (analytics) + Engage (adversary engagement)
        car_p = DATA / "attack/technique_to_car.jsonl"
        self.car = {r["technique_id"]: r.get("car", []) for r in load_jsonl(car_p)} if car_p.exists() else {}
        self.engage = {}
        eng_p = DATA / "engage/attack_to_engage.jsonl"
        for r in (load_jsonl(eng_p) if eng_p.exists() else []):
            acts = re.findall(r"'id':\s*'([^']+)',\s*'name':\s*'([^']+)'", str(r.get("engage_activities", "")))
            if acts:
                self.engage[r["technique_id"]] = [{"id": i, "name": n} for i, n in acts]
        ea_p = DATA / "engage/engage_activities.jsonl"
        self.engage_desc = {r["activity_id"]: r.get("description", "") for r in (load_jsonl(ea_p) if ea_p.exists() else [])}

        # F3 — CTID Fight Fraud Framework
        f3_p = DATA / "fraud/f3_techniques.jsonl"
        self.f3 = {r["technique_id"]: r for r in (load_jsonl(f3_p) if f3_p.exists() else [])}
        self.f3_tactics = {r.get("shortname"): r for r in load_jsonl(DATA / "fraud/f3_tactics.jsonl")} if (DATA / "fraud/f3_tactics.jsonl").exists() else {}
        self.f3_subs = defaultdict(list)
        for r in self.f3.values():
            pid = r.get("parent_id")
            if pid and pid != "None":
                self.f3_subs[pid].append(r["technique_id"])
        # ATT&CK techniques that are also present in F3 (attack_derived, id-matched)
        self.f3_of_attack = {tid for tid, r in self.f3.items()
                             if str(r.get("attack_derived")).lower() == "true" and tid in self.prof}

        # Threat-group per-object pages (from the ATT&CK STIX group_profiles)
        gp_p = DATA / "attack/group_profiles.jsonl"
        self.group_prof = {r["group_id"]: r for r in (load_jsonl(gp_p) if gp_p.exists() else [])}
        self.group_name_to_id = {r["name"]: r["group_id"] for r in self.group_prof.values()}
        # software + campaign per-object pages (from the ATT&CK STIX).
        # Official ATT&CK software IDs are S0NNN / S1NNN; the bundle also carries a
        # non-official S9NNN namespace (emerging/community entries with no attack.mitre.org
        # page). We publish only official objects here so every page has a valid ATT&CK ID
        # and live external link; S9NNN names left uncited fall back to plain text in
        # cross-links (see software_link). The community set is tracked separately.
        sp_p = DATA / "attack/software_profiles.jsonl"
        _sw_all = load_jsonl(sp_p) if sp_p.exists() else []
        self.sw_prof = {r["software_id"]: r for r in _sw_all
                        if re.fullmatch(r"S[01]\d{3}", r["software_id"])}
        self.sw_name_to_id = {r["name"]: r["software_id"] for r in self.sw_prof.values()}
        cp_p = DATA / "attack/campaign_profiles.jsonl"
        self.camp_prof = {r["campaign_id"]: r for r in (load_jsonl(cp_p) if cp_p.exists() else [])}

        self.nist_name = {}
        for r in load_jsonl(DATA / "control_to_technique.jsonl"):
            c, d = r.get("nist_control"), r.get("control_desc")
            if c and d and c not in self.nist_name:
                self.nist_name[c] = d

        self.subs = defaultdict(list)
        for r in tp:
            if r.get("parent_id"):
                self.subs[r["parent_id"]].append(r["technique_id"])

        # reverse of superseded_by: successor_id -> [(revoked_id, revoked_name)]
        self.supersedes = defaultdict(list)
        for r in tp:
            if r.get("revoked") and r.get("superseded_by"):
                self.supersedes[r["superseded_by"]].append((r["technique_id"], r["name"]))

        # corpus signal preserved from existing pages (technique_id -> paragraph)
        self.corpus = {}
        tdir = MITRE / "techniques"
        if tdir.exists():
            for tid in self.prof:
                block = extract_corpus(tdir / (tslug(tid) + ".md"))
                if block:
                    self.corpus[tid] = block
        self.corpus_ids = set(self.corpus)
        # corpus prevalence percent parsed from the block (for tactic "most-observed")
        self.corpus_pct = {}
        for tid, blk in self.corpus.items():
            m = re.search(r"\(([\d.]+)%\)", blk)
            if m:
                self.corpus_pct[tid] = float(m.group(1))

        # --- mitigations ---
        self.mit = {r["mitigation_id"]: r for r in load_jsonl(DATA / "attack/mitigations.jsonl")}
        self.mit_techs = defaultdict(list)
        for r in load_jsonl(DATA / "attack/mitigation_to_technique.jsonl"):
            self.mit_techs[r["mitigation_id"]].append((r["technique_id"], r["technique_name"]))

        # --- CAPEC + CWE ---
        self.capec = {r["capec_id"]: r for r in load_jsonl(DATA / "weaknesses/capec.jsonl")}
        self.cwe = {r["cwe_id"]: r for r in load_jsonl(DATA / "weaknesses/cwe.jsonl")}
        self.cwe_name = {k: v.get("name", "") for k, v in self.cwe.items()}

        # --- ATLAS ---
        self.atlas = {r["technique_id"]: r for r in load_jsonl(DATA / "ai/atlas_techniques.jsonl")}
        self.atlas_mit = {r["mitigation_id"]: r for r in load_jsonl(DATA / "ai/atlas_mitigations.jsonl")}
        self.atlas_subs = defaultdict(list)
        for r in self.atlas.values():
            if r.get("parent_id"):
                self.atlas_subs[r["parent_id"]].append(r["technique_id"])

        # --- D3FEND (reverse map: countermeasure -> tactic, artifacts, ATT&CK techniques it counters) ---
        self.d3_pages = {}
        for r in load_jsonl(DATA / "attack/technique_to_d3fend.jsonl"):
            name = r.get("d3fend_technique")
            if not name:
                continue
            page = self.d3_pages.setdefault(name, {"tactic": "", "artifacts": [], "counters": []})
            if not page["tactic"] and r.get("d3fend_tactic"):
                page["tactic"] = sstr(r["d3fend_tactic"])
            for a in (r.get("digital_artifact") or []):
                if a not in page["artifacts"]:
                    page["artifacts"].append(a)
            tid = r.get("technique_id", "")
            if tid.startswith("T") and not tid.startswith("TA"):
                page["counters"].append((tid, sstr(r.get("relation")) or "maps"))


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

    if p.get("revoked"):
        sup = p.get("superseded_by")
        supname = p.get("superseded_by_name", "")
        if sup and sup in db.prof:
            tgt = "[" + sup + " " + DASH + " " + supname + "](/mitre/techniques/" + tslug(sup) + ".md)"
        elif sup:
            tgt = "[" + sup + " " + DASH + " " + supname + "](https://attack.mitre.org/techniques/" + sup.replace(".", "/") + ")"
        else:
            tgt = ""
        out.append("> **⚠ Revoked in ATT&CK v19.2**" + ((" " + DASH + " superseded by " + tgt + ".") if tgt else ".") + "\n")
    elif p.get("deprecated"):
        out.append("> **⚠ Deprecated in ATT&CK v19.2.**\n")

    sups = db.supersedes.get(tid) or []
    if sups:
        parts = ", ".join("[" + oid + " " + DASH + " " + onm + "](/mitre/techniques/" + tslug(oid) + ".md)"
                          for oid, onm in sorted(sups))
        out.append("> **New in ATT&CK v19.2** " + DASH + " supersedes " + parts +
                   " (revoked; kept for reference).\n")

    if p.get("description"):
        out.append(p["description"].strip() + "\n")

    if tid in db.corpus:
        out.append(db.corpus[tid] + "\n")

    # Mitigations
    migs = p.get("mitigations") or []
    if migs:
        out.append("## Mitigations (" + str(len(migs)) + ")\n")
        rows = []
        for m in migs:
            line = "- [" + m["id"] + " " + DASH + " " + m["name"] + "](/mitre/mitigations/" + m["id"] + ".md)"
            desc = summarize((db.mit.get(m["id"], {}) or {}).get("description"))
            if desc:
                line += " " + DASH + " " + desc
            rows.append(line)
        out.append("\n".join(rows) + "\n")

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
            drow = "- [" + name + "](/mitre/d3fend/" + dslug(name) + ".md)" + tac_txt + " " + DASH + " " + rel
            dfn = summarize((db.d3_defs.get(name, {}) or {}).get("definition"))
            if dfn:
                drow += ". " + dfn
            rows.append(drow)
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

    # CAR analytics (MITRE Cyber Analytics Repository — detection analytics with pseudocode)
    car = db.car.get(tid) or []
    if car:
        out.append("## CAR analytics (" + str(len(car)) + ")\n")
        out.append("\n".join(
            "- [" + c["car_id"] + " " + DASH + " " + c["title"] + "](" + c["url"] + ")" +
            ((" " + DASH + " coverage: " + c["coverage"]) if c.get("coverage") else "")
            for c in car) + "\n")

    # MITRE Engage (adversary engagement / deception opportunities)
    eng = db.engage.get(tid) or []
    if eng:
        out.append("## MITRE Engage (" + str(len(eng)) + ")\n")
        rows = []
        for a in eng:
            line = "- **" + a["id"] + " " + DASH + " " + a["name"] + "**"
            d = summarize(db.engage_desc.get(a["id"]))
            if d:
                line += " " + DASH + " " + d
            rows.append(line)
        out.append("\n".join(rows) + "\n")

    # F3 (CTID Fight Fraud Framework) — this technique is also modeled as a fraud technique
    if tid in db.f3_of_attack:
        fr = db.f3.get(tid, {})
        out.append("## Fraud (F3)\n")
        out.append("Also modeled in the CTID Fight Fraud Framework as [" + tid + " " + DASH + " " +
                   fr.get("name", "") + "](/mitre/f3/" + tid + ".md) (fraud tactic(s): " +
                   (", ".join(as_list(fr.get("tactics"))) or DASH) + ").\n")

    # Adversary usage (named, replaces bare counts)
    groups = db.groups_by_t.get(tid) or []
    sw = db.sw_by_t.get(tid) or []
    gc = p.get("group_count", len(groups))
    sc = p.get("software_count", len(sw))
    cc = p.get("campaign_count", 0)
    if groups or sw or cc:
        out.append("## Adversary usage\n")
        if groups:
            named = ", ".join(group_link(db, g) for g in groups[:CAP_NAMED])
            extra = " _+" + str(len(groups) - CAP_NAMED) + " more_" if len(groups) > CAP_NAMED else ""
            out.append("**Threat groups (" + str(gc) + "):** " + named + extra + "\n")
            notable = []
            for g in groups[:6]:
                gr = db.group.get(g, {}) or {}
                d = summarize(gr.get("description"))
                if not d:
                    continue
                al = first_alias_str(gr.get("aliases"), g)
                al_txt = " (" + al + ")" if al else ""
                notable.append("- " + group_link(db, g) + al_txt + " " + DASH + " " + d)
            if notable:
                out.append("_Notable groups seen using this technique:_\n")
                out.append("\n".join(notable) + "\n")
        if sw:
            named = ", ".join(software_link(db, s) for s in sw[:CAP_NAMED])
            extra = " _+" + str(len(sw) - CAP_NAMED) + " more_" if len(sw) > CAP_NAMED else ""
            out.append("**Software/tools (" + str(sc) + "):** " + named + extra + "\n")
        if cc:
            out.append("**Campaigns:** " + str(cc) + " (per MITRE ATT&CK)\n")

    # Sub-techniques (for parent techniques)
    kids = sorted(db.subs.get(tid) or [])
    if kids:
        out.append("## Sub-techniques (" + str(len(kids)) + ")\n")
        rows = []
        for k in kids:
            line = "- [" + k + " " + DASH + " " + db.prof[k]["name"] + "](/mitre/techniques/" + tslug(k) + ".md)"
            ks = summarize(db.prof[k].get("description"))
            if ks:
                line += " " + DASH + " " + ks
            rows.append(line)
        out.append("\n".join(rows) + "\n")

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


# ----------------------------------------------------------------------------- shared
def link_tech(db, tid, name=None):
    """Link an ATT&CK technique id: enterprise -> internal page, ICS (T0) -> official, else code."""
    nm = name or (db.prof.get(tid, {}) or {}).get("name")
    label = tid + " " + DASH + " " + nm if nm else tid
    if tid in db.prof:
        return "[" + label + "](/mitre/techniques/" + tslug(tid) + ".md)"
    if tid.startswith("T0"):
        return "[" + label + "](https://attack.mitre.org/techniques/" + tid + ")"
    return "`" + tid + "`"


# ----------------------------------------------------------------------------- mitigation
def render_mitigation(db, mid, existing):
    m = db.mit.get(mid, {})
    out = ["# " + mid + " " + DASH + " " + m.get("name", "") + "\n", '<a id="' + mid.lower() + '"></a>\n']
    tc = m.get("technique_count", len(db.mit_techs.get(mid, [])))
    out.append("**ATT&CK:** [" + mid + "](" + str(m.get("url")) + ") \N{MIDDLE DOT} addresses **" + str(tc) + "** techniques\n")
    if m.get("description"):
        out.append(m["description"].strip() + "\n")
    # preserved, non-data sections
    for h in ("How to implement", "Team Star Wolf corpus relevance"):
        body = extract_section(existing, h)
        if body:
            out.append("## " + h + "\n")
            out.append(body + "\n")
    techs = db.mit_techs.get(mid, [])
    if techs:
        out.append("## Techniques addressed (" + str(len(techs)) + ")\n")
        out.append("\n".join("- " + link_tech(db, t, n) for t, n in techs) + "\n")
    out.append(FOOTER)
    return "\n".join(out)


# ----------------------------------------------------------------------------- tactic
def render_tactic(db, slug, existing):
    # preserve title + description from the existing page
    title, desc = "Tactic: " + slug.replace("-", " ").title(), ""
    if existing:
        lines = existing.splitlines()
        if lines and lines[0].startswith("# "):
            title = lines[0][2:].strip()
        m = re.search(r'</a>\s*\n+(.*?)(?:\n\s*\n|\Z)', existing, re.S)
        if m:
            desc = m.group(1).strip()
    techs = [t for t, p in db.prof.items() if slug in (p.get("tactics") or [])]
    techs.sort()
    out = ["# " + title + "\n", '<a id="' + slug + '"></a>\n']
    if desc:
        out.append(desc + "\n")
    # most-observed in the corpus (this tactic's techniques that carry a corpus signal)
    obs = sorted(((db.corpus_pct.get(t, 0), t) for t in techs if t in db.corpus_ids), reverse=True)
    if obs:
        out.append("## Most-observed in the Team Star Wolf corpus\n")
        out.append("\n".join(
            "- [" + t + " " + DASH + " " + db.prof[t]["name"] + "](/mitre/techniques/" + tslug(t) +
            ".md) " + DASH + " " + (str(pct) + "% of machines" if pct else "observed")
            for pct, t in obs) + "\n")
    out.append("**" + str(len(techs)) + " techniques** in this tactic (Team Star Wolf enriched pages):\n")
    out.append("\n".join(
        "- [" + t + " " + DASH + " " + db.prof[t]["name"] + "](/mitre/techniques/" + tslug(t) + ".md)" +
        (" " + STAR if t in db.corpus_ids else "") for t in techs) + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


# ----------------------------------------------------------------------------- d3fend
def render_d3fend(db, slug, existing):
    # find this page's countermeasure name from the existing H1
    name = ""
    if existing:
        first = existing.splitlines()[0] if existing.splitlines() else ""
        if first.startswith("# D3FEND:"):
            name = first[len("# D3FEND:"):].strip()
    page = db.d3_pages.get(name)
    defrec = db.d3_defs.get(name, {}) or {}
    out = ["# D3FEND: " + name + "\n", '<a id="' + slug + '"></a>\n']
    if page:
        if page["tactic"]:
            out.append("**D3FEND tactic:** " + page["tactic"] + "  ")
        if page["artifacts"]:
            out.append("**Digital artifacts:** " + ", ".join(page["artifacts"]) + "  ")
        out.append("")
        if defrec.get("definition"):
            out.append(str(defrec["definition"]).strip() + "\n")
        if defrec.get("how_to"):
            out.append("## How to deploy\n")
            out.append(str(defrec["how_to"]).strip() + "\n")
        # ATT&CK techniques countered — link enterprise + ICS, drop non-ATT&CK (DE-) rows
        seen, rows = set(), []
        for tid, rel in page["counters"]:
            if tid in seen:
                continue
            seen.add(tid)
            line = "- " + link_tech(db, tid) + " " + DASH + " " + rel
            ts = summarize((db.prof.get(tid, {}) or {}).get("description"))
            if ts:
                line += ". " + ts
            rows.append(line)
        if rows:
            out.append("## ATT&CK techniques countered (" + str(len(rows)) + ")\n")
            out.append("\n".join(rows))
    out.append("\n" + SHORT_FOOTER)
    return "\n".join(out)


# ----------------------------------------------------------------------------- capec
def render_capec(db, cid):
    c = db.capec[cid]
    out = ["# " + cid + " " + DASH + " " + c.get("name", "") + "\n",
           '<a id="' + cid.lower() + '"></a>\n']
    meta = []
    for k, label in (("abstraction", "Abstraction"), ("typical_severity", "Typical severity"),
                     ("likelihood", "Likelihood"), ("status", "Status")):
        if c.get(k):
            meta.append("**" + label + ":** " + str(c[k]) + "  ")
    if meta:
        out.append("\n".join(meta) + "\n")
    if c.get("description"):
        out.append(str(c["description"]).strip() + "\n")
    # mapped ATT&CK
    techs = as_list(c.get("attack_techniques"))
    if techs:
        out.append("## Mapped ATT&CK techniques (" + str(len(techs)) + ")\n")
        rows = []
        for t in techs:
            line = "- " + link_tech(db, t)
            ts = summarize((db.prof.get(t, {}) or {}).get("description"))
            if ts:
                line += " " + DASH + " " + ts
            rows.append(line)
        out.append("\n".join(rows) + "\n")
    # related CWE — per-CWE links with names + inlined weakness detail
    cwes = as_list(c.get("related_cwe"))
    if cwes:
        out.append("## Related CWE (" + str(len(cwes)) + ")\n")
        rows = []
        for w in cwes:
            num = re.sub(r"\D", "", w)
            rec = db.cwe.get(w) or db.cwe.get("CWE-" + num) or {}
            nm = rec.get("name") or db.cwe_name.get(w) or db.cwe_name.get("CWE-" + num)
            label = w + " " + DASH + " " + nm if nm else w
            line = "- [" + label + "](https://cwe.mitre.org/data/definitions/" + num + ".html)"
            d = summarize(rec.get("description"))
            if d:
                line += " " + DASH + " " + d
            rows.append(line)
        out.append("\n".join(rows) + "\n")
    # prose lists (fix the '::' separators)
    for key, heading in (("prerequisites", "Prerequisites"), ("skills_required", "Skills required"),
                         ("consequences", "Consequences"), ("mitigations", "Mitigations")):
        items = clean_capec_field(c.get(key))
        if items:
            out.append("## " + heading + "\n")
            out.append("\n".join("- " + it for it in items) + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


# ----------------------------------------------------------------------------- atlas
def aml_slug(tid):
    return tid.replace(".", "-")


def aml_anchor(tid):
    return tid.replace(".", "").lower()


def render_atlas_technique(db, tid):
    r = db.atlas[tid]
    out = ["# " + tid + " " + DASH + " " + r.get("name", "") + "\n", '<a id="' + aml_anchor(tid) + '"></a>\n']
    hdr = ["**ATLAS tactics:** " + (", ".join(r.get("tactics") or []) or DASH) + "  "]
    if r.get("parent_id"):
        par = r["parent_id"]
        pnm = db.atlas.get(par, {}).get("name", "")
        hdr.append("**Sub-technique of:** [" + par + " " + DASH + " " + pnm + "](/mitre/atlas/" + aml_slug(par) + ".md)  ")
    hdr.append("**ATLAS:** [" + tid + "](" + str(r.get("url")) + ")  ")
    out.append("\n".join(hdr) + "\n")
    if r.get("description"):
        out.append(str(r["description"]).strip() + "\n")
    migs = r.get("mitigations") or []
    if migs:
        out.append("## Mitigations (" + str(len(migs)) + ")\n")
        rows = []
        for m in migs:
            line = "- [" + m["id"] + " " + DASH + " " + m["name"] + "](/mitre/atlas/" + aml_slug(m["id"]) + ".md)"
            d = summarize((db.atlas_mit.get(m["id"], {}) or {}).get("description"))
            if d:
                line += " " + DASH + " " + d
            rows.append(line)
        out.append("\n".join(rows) + "\n")
    kids = sorted(db.atlas_subs.get(tid) or [])
    if kids:
        out.append("## Sub-techniques (" + str(len(kids)) + ")\n")
        out.append("\n".join(
            "- [" + k + " " + DASH + " " + db.atlas[k].get("name", "") + "](/mitre/atlas/" + aml_slug(k) + ".md)"
            for k in kids) + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


def render_atlas_mitigation(db, mid):
    r = db.atlas_mit[mid]
    out = ["# " + mid + " " + DASH + " " + r.get("name", "") + "\n", '<a id="' + aml_anchor(mid) + '"></a>\n']
    out.append("**ATLAS:** [" + mid + "](" + str(r.get("url")) + ") \N{MIDDLE DOT} addresses **" +
               str(r.get("technique_count", 0)) + "** techniques\n")
    if r.get("description"):
        out.append(str(r["description"]).strip() + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


# ----------------------------------------------------------------------------- F3 (fraud)
def render_f3_technique(db, fid):
    r = db.f3[fid]
    out = ["# " + fid + " " + DASH + " " + r.get("name", "") + "\n", '<a id="f3-' + fid.lower() + '"></a>\n']
    tacs = as_list(r.get("tactics"))
    tac_names = ", ".join(db.f3_tactics.get(t, {}).get("name", t) for t in tacs) or DASH
    hdr = ["**F3 tactics:** " + tac_names + "  ",
           "**Fight Fraud Framework:** [" + fid + "](" + str(r.get("url")) + ")  "]
    if fid in db.f3_of_attack:
        hdr.append("**Also an ATT&CK technique:** [" + fid + " " + DASH + " " + db.prof[fid]["name"] +
                   "](/mitre/techniques/" + tslug(fid) + ".md)  ")
    pid = r.get("parent_id")
    if pid and pid != "None":
        hdr.append("**Sub-technique of:** [" + pid + " " + DASH + " " + db.f3.get(pid, {}).get("name", "") +
                   "](/mitre/f3/" + pid + ".md)  ")
    out.append("\n".join(hdr) + "\n")
    if r.get("description"):
        out.append(str(r["description"]).strip() + "\n")
    kids = sorted(db.f3_subs.get(fid) or [])
    if kids:
        out.append("## Sub-techniques (" + str(len(kids)) + ")\n")
        out.append("\n".join("- [" + k + " " + DASH + " " + db.f3[k].get("name", "") + "](/mitre/f3/" + k + ".md)"
                             for k in kids) + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


def render_f3_landing(db):
    by_tac = defaultdict(list)
    for fid, r in db.f3.items():
        if str(r.get("is_subtechnique")).lower() == "true":
            continue
        for t in (as_list(r.get("tactics")) or ["(untagged)"]):
            by_tac[t].append(fid)
    lines = ["# F3 " + DASH + " Fight Fraud Framework", "",
             "The CTID **Fight Fraud Framework (F3)** models the fraud lifecycle as tactics + techniques, "
             "alongside ATT&CK. " + str(len(db.f3_of_attack)) + " F3 techniques are ATT&CK-derived and cross-link "
             "to their [technique pages](/mitre/techniques/README.md); the rest are fraud-specific.", ""]
    for t in sorted(by_tac):
        tn = db.f3_tactics.get(t, {}).get("name", t.title())
        lines.append("## " + tn + " (" + str(len(by_tac[t])) + ")\n")
        for fid in sorted(by_tac[t]):
            tag = " ⭐ (ATT&CK)" if fid in db.f3_of_attack else ""
            lines.append("- [" + fid + " " + DASH + " " + db.f3[fid].get("name", "") + "](/mitre/f3/" + fid + ".md)" + tag)
        lines.append("")
    lines.append(SHORT_FOOTER)
    return "\n".join(lines)


# ----------------------------------------------------------------------------- threat groups
def group_link(db, name):
    gid = db.group_name_to_id.get(name)
    if gid:
        return "[" + name + "](/mitre/groups/" + gid + ".md)"
    return link(name, db.group_url.get(name))


def render_group(db, gid):
    g = db.group_prof[gid]
    out = ["# " + gid + " " + DASH + " " + g.get("name", "") + "\n", '<a id="' + gid.lower() + '"></a>\n']
    aliases = [a for a in (g.get("aliases") or []) if a and a != g.get("name")]
    hdr = ["**ATT&CK:** [" + gid + "](https://attack.mitre.org/groups/" + gid + ")  "]
    if aliases:
        hdr.append("**Aliases:** " + ", ".join(aliases) + "  ")
    out.append("\n".join(hdr) + "\n")
    if g.get("description"):
        out.append(canon_desc(g["description"]).strip() + "\n")
    techs = [t for t in (g.get("techniques") or []) if t in db.prof]
    if techs:
        out.append("## Techniques used (" + str(len(techs)) + ")\n")
        out.append("\n".join(
            "- [" + t + " " + DASH + " " + db.prof[t]["name"] + "](/mitre/techniques/" + tslug(t) + ".md)"
            for t in sorted(techs)) + "\n")
    sw = g.get("software") or []
    if sw:
        out.append("## Software & tools (" + str(len(sw)) + ")\n")
        out.append(", ".join(software_link(db, s) for s in sw) + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


def render_group_landing(db):
    lines = ["# Threat Groups (" + str(len(db.group_prof)) + ")", "",
             "ATT&CK-tracked adversary groups (intrusion sets), each with its aliases, the techniques it uses "
             "(linked to their technique pages), and the software it wields. ATT&CK " + ATTACK_VER + ".", ""]
    for gid in sorted(db.group_prof):
        g = db.group_prof[gid]
        al = [a for a in (g.get("aliases") or []) if a and a != g.get("name")][:3]
        alt = " (aka " + ", ".join(al) + ")" if al else ""
        lines.append("- [" + gid + " " + DASH + " " + g.get("name", "") + "](/mitre/groups/" + gid + ".md)" + alt)
    lines.append("\n" + SHORT_FOOTER)
    return "\n".join(lines)


# ----------------------------------------------------------------------------- software + campaigns
def software_link(db, name):
    sid = db.sw_name_to_id.get(name)
    if sid:
        return "[" + name + "](/mitre/software/" + sid + ".md)"
    return link(name, db.sw_url.get(name))


def render_software(db, sid):
    s = db.sw_prof[sid]
    out = ["# " + sid + " " + DASH + " " + s.get("name", "") + "\n", '<a id="' + sid.lower() + '"></a>\n']
    aliases = [a for a in (s.get("aliases") or []) if a and a != s.get("name")]
    hdr = ["**Type:** " + (s.get("type") or "tool") + "  ",
           "**ATT&CK:** [" + sid + "](https://attack.mitre.org/software/" + sid + ")  "]
    if s.get("platforms"):
        hdr.append("**Platforms:** " + ", ".join(s["platforms"]) + "  ")
    if aliases:
        hdr.append("**Aliases:** " + ", ".join(aliases) + "  ")
    out.append("\n".join(hdr) + "\n")
    if s.get("description"):
        out.append(canon_desc(s["description"]).strip() + "\n")
    techs = [t for t in (s.get("techniques") or []) if t in db.prof]
    if techs:
        out.append("## Techniques used (" + str(len(techs)) + ")\n")
        out.append("\n".join(
            "- [" + t + " " + DASH + " " + db.prof[t]["name"] + "](/mitre/techniques/" + tslug(t) + ".md)"
            for t in sorted(techs)) + "\n")
    grps = s.get("groups") or []
    if grps:
        out.append("## Used by groups (" + str(len(grps)) + ")\n")
        out.append(", ".join(group_link(db, g) for g in grps) + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


def render_software_landing(db):
    lines = ["# Software & Tools (" + str(len(db.sw_prof)) + ")", "",
             "ATT&CK-tracked software — malware and tools — each with its type, platforms, aliases, the "
             "techniques it implements (linked), and the groups that wield it. ATT&CK " + ATTACK_VER + ".", ""]
    for sid in sorted(db.sw_prof):
        s = db.sw_prof[sid]
        lines.append("- [" + sid + " " + DASH + " " + s.get("name", "") + "](/mitre/software/" + sid + ".md) (" +
                     (s.get("type") or "") + ")")
    lines.append("\n" + SHORT_FOOTER)
    return "\n".join(lines)


def render_campaign(db, cid):
    c = db.camp_prof[cid]
    out = ["# " + cid + " " + DASH + " " + c.get("name", "") + "\n", '<a id="' + cid.lower() + '"></a>\n']
    hdr = ["**ATT&CK:** [" + cid + "](https://attack.mitre.org/campaigns/" + cid + ")  "]
    span = " – ".join(x for x in (c.get("first_seen"), c.get("last_seen")) if x)
    if span:
        hdr.append("**Active:** " + span + "  ")
    out.append("\n".join(hdr) + "\n")
    if c.get("description"):
        out.append(canon_desc(c["description"]).strip() + "\n")
    if c.get("groups"):
        out.append("## Attributed to\n")
        out.append(", ".join(group_link(db, g) for g in c["groups"]) + "\n")
    techs = [t for t in (c.get("techniques") or []) if t in db.prof]
    if techs:
        out.append("## Techniques used (" + str(len(techs)) + ")\n")
        out.append("\n".join(
            "- [" + t + " " + DASH + " " + db.prof[t]["name"] + "](/mitre/techniques/" + tslug(t) + ".md)"
            for t in sorted(techs)) + "\n")
    if c.get("software"):
        out.append("## Software (" + str(len(c["software"])) + ")\n")
        out.append(", ".join(software_link(db, s) for s in c["software"]) + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


def render_campaign_landing(db):
    lines = ["# Campaigns (" + str(len(db.camp_prof)) + ")", "",
             "ATT&CK-tracked intrusion campaigns, each with its active window, the groups it is attributed to, "
             "the techniques used (linked), and the software deployed. ATT&CK " + ATTACK_VER + ".", ""]
    for cid in sorted(db.camp_prof):
        c = db.camp_prof[cid]
        span = c.get("first_seen", "")
        lines.append("- [" + cid + " " + DASH + " " + c.get("name", "") + "](/mitre/campaigns/" + cid + ".md)" +
                     ((" (" + span + ")") if span else ""))
    lines.append("\n" + SHORT_FOOTER)
    return "\n".join(lines)


# ----------------------------------------------------------------------------- landing
def render_landing(db):
    n_tech = len(list((MITRE / "techniques").glob("T*.md")))
    n_mit = len(list((MITRE / "mitigations").glob("M*.md")))
    n_tac = len([p for p in (MITRE / "tactics").glob("*.md") if p.name != "README.md"])
    n_d3 = len([p for p in (MITRE / "d3fend").glob("*.md") if p.name != "README.md"])
    n_cap = len(list((MITRE / "capec").glob("CAPEC-*.md")))
    n_atl = len(list((MITRE / "atlas").glob("AML-*.md")))
    n_f3 = len(db.f3)
    n_groups = len(db.group_prof)
    n_software = len(db.sw_prof)
    n_campaigns = len(db.camp_prof)
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
        "**linked D3FEND**, **detection analytics + log sources**, **data sources**, **CAR analytics**, "
        "**MITRE Engage**, **named threat-group & tool usage**, sub-techniques, NIST 800-53 (named), CAPEC, "
        "corpus prevalence |",
        "| [Mitigations](/mitre/mitigations/README.md) | " + str(n_mit) + " | how-to-implement, NIST mapping, "
        "techniques countered, corpus relevance |",
        "| [Tactics](/mitre/tactics/README.md) | " + str(n_tac) + " | the \"why\" of each stage, its techniques, "
        "top corpus-observed techniques |",
        "| [D3FEND](/mitre/d3fend/README.md) | " + str(n_d3) + " | defensive technique, D3FEND tactic, digital "
        "artifacts, ATT&CK techniques countered |",
        "| [CAPEC](/mitre/capec/README.md) | " + str(n_cap) + " | abstraction, severity, likelihood, mapped "
        "ATT&CK, related CWE, prerequisites, mitigations |",
        "| [ATLAS (AI/ML)](/mitre/atlas/README.md) | " + str(n_atl) + " | adversarial-AI techniques + mitigations |",
        "| [F3 (Fight Fraud)](/mitre/f3/README.md) | " + str(n_f3) + " | CTID fraud-lifecycle techniques; ATT&CK-derived "
        "ones cross-link to their technique pages |",
        "| [Threat Groups](/mitre/groups/README.md) | " + str(n_groups) + " | ATT&CK adversary groups (intrusion sets) "
        "— aliases, techniques used (linked), and software wielded |",
        "| [Software & Tools](/mitre/software/README.md) | " + str(n_software) + " | ATT&CK malware & tools — type, "
        "platforms, aliases, techniques implemented (linked), and the groups that wield them |",
        "| [Campaigns](/mitre/campaigns/README.md) | " + str(n_campaigns) + " | ATT&CK intrusion campaigns — active "
        "window, attributed groups, techniques used (linked), and software deployed |",
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

    if "mitigations" in only:
        d = out_root / "mitigations"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for f in sorted((MITRE / "mitigations").glob("M*.md")):
            mid = f.stem
            if mid not in db.mit:
                continue
            (d / (mid + ".md")).write_text(render_mitigation(db, mid, f.read_text(encoding="utf-8")), encoding="utf-8")
            n += 1
        print("mitigations: wrote " + str(n) + " pages")

    if "tactics" in only:
        d = out_root / "tactics"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for f in sorted((MITRE / "tactics").glob("*.md")):
            if f.name == "README.md":
                continue
            (d / f.name).write_text(render_tactic(db, f.stem, f.read_text(encoding="utf-8")), encoding="utf-8")
            n += 1
        print("tactics: wrote " + str(n) + " pages")

    if "d3fend" in only:
        d = out_root / "d3fend"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for f in sorted((MITRE / "d3fend").glob("*.md")):
            if f.name == "README.md":
                continue
            (d / f.name).write_text(render_d3fend(db, f.stem, f.read_text(encoding="utf-8")), encoding="utf-8")
            n += 1
        print("d3fend: wrote " + str(n) + " pages")

    if "capec" in only:
        d = out_root / "capec"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for cid in db.capec:
            (d / (cid + ".md")).write_text(render_capec(db, cid), encoding="utf-8")
            n += 1
        print("capec: wrote " + str(n) + " pages")

    if "atlas" in only:
        d = out_root / "atlas"
        d.mkdir(parents=True, exist_ok=True)
        nt = nm = 0
        for tid in db.atlas:
            (d / (aml_slug(tid) + ".md")).write_text(render_atlas_technique(db, tid), encoding="utf-8")
            nt += 1
        for mid in db.atlas_mit:
            (d / (aml_slug(mid) + ".md")).write_text(render_atlas_mitigation(db, mid), encoding="utf-8")
            nm += 1
        print("atlas: wrote " + str(nt) + " technique + " + str(nm) + " mitigation pages")

    if "f3" in only:
        d = out_root / "f3"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for fid in db.f3:
            (d / (fid + ".md")).write_text(render_f3_technique(db, fid), encoding="utf-8")
            n += 1
        (d / "README.md").write_text(render_f3_landing(db), encoding="utf-8")
        print("f3: wrote " + str(n) + " technique pages + README")

    if "groups" in only:
        d = out_root / "groups"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for gid in db.group_prof:
            (d / (gid + ".md")).write_text(render_group(db, gid), encoding="utf-8")
            n += 1
        (d / "README.md").write_text(render_group_landing(db), encoding="utf-8")
        print("groups: wrote " + str(n) + " pages + README")

    if "software" in only:
        d = out_root / "software"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for sid in db.sw_prof:
            (d / (sid + ".md")).write_text(render_software(db, sid), encoding="utf-8")
            n += 1
        (d / "README.md").write_text(render_software_landing(db), encoding="utf-8")
        print("software: wrote " + str(n) + " pages + README")

    if "campaigns" in only:
        d = out_root / "campaigns"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for cid in db.camp_prof:
            (d / (cid + ".md")).write_text(render_campaign(db, cid), encoding="utf-8")
            n += 1
        (d / "README.md").write_text(render_campaign_landing(db), encoding="utf-8")
        print("campaigns: wrote " + str(n) + " pages + README")

    if "landing" in only:
        out_root.mkdir(parents=True, exist_ok=True)
        (out_root / "README.md").write_text(render_landing(db), encoding="utf-8")
        print("landing: wrote README.md")


if __name__ == "__main__":
    main()
