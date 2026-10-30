#!/usr/bin/env python3
"""
Generate the enriched MITRE per-object knowledge base (mitre/) from committed data (data/).

Regenerates one page per MITRE object for: techniques, mitigations, tactics, D3FEND,
CAPEC, ATLAS, plus every section's README.md index and the /mitre/README landing.
Everything is derived deterministically from data/attack, data/weaknesses, and data/ai.

CORPUS SIGNAL: the "Team Star Wolf corpus signal" paragraph on a technique page (and the
"(observed)" mark that flags corpus-observed techniques on tactic pages, the crosswalk
and the landing page) is keyword-derived from a local 529-machine HTB training corpus
that is NOT committed to this repo. The extracted per-technique counts ARE committed, in
data/generated/corpus_signal.jsonl, and the paragraph is rendered from that file like
every other section. The generator never scrapes the previous pages for it: if a page
carries the paragraph for a technique the data file does not know, or the data file is
missing while pages carry the paragraph, the run aborts before writing anything.

Usage:
    python scripts/generate_mitre_pages.py                 # techniques (+ index) + landing
    python scripts/generate_mitre_pages.py --only all      # every mitre/ section
    python scripts/generate_mitre_pages.py --only techniques,landing
    python scripts/generate_mitre_pages.py --only all --check   # CI: render to a temp dir, fail on any drift
    python scripts/generate_mitre_pages.py --verify-corpus 21   # CI: data file <-> pages round-trip, exactly 21
"""
import json
import re
import argparse
import shutil
import tempfile
from pathlib import Path

from plain_markdown import plain
import build_crosslinks as xl  # owns the "Library references" block on each page
from attack_ids import AttackIds
from collections import defaultdict, Counter

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

# OpenCRE (OWASP) "smartlink": opens the CRE linked to a standard's entry, OpenCRE's page for
# the entry when it links to several, or the entry on the MITRE site when OpenCRE has no links
# for it (CWE and CAPEC only). The route is OpenCRE's smartlink() in application/web/web_main.py.
OPENCRE_SMARTLINK = "https://opencre.org/smartlink/standard/"
OPENCRE_SMARTLINK_SRC = ("https://github.com/OWASP/OpenCRE/blob/cbf22e06071c69b62f1b3c50c38015da1640e54e/"
                         "application/web/web_main.py#L757-L837")

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


CORPUS_PATH = DATA / "generated" / "corpus_signal.jsonl"
# Marker-tolerant: pages are written through plain(), which strips the "**" bold
# markers, so the committed paragraph starts with the bare phrase. (The old pattern
# required the literal "**" and matched nothing, which made a regeneration delete the
# paragraph from every page.)
CORPUS_RE = re.compile(r"(?:\*\*)?Team Star Wolf corpus signal.*?(?=\n\s*\n|\Z)", re.S)


def extract_corpus(md_path):
    """Return the corpus-signal paragraph an existing page carries (guard input, not a data source)."""
    if not md_path.exists():
        return None
    m = CORPUS_RE.search(md_path.read_text(encoding="utf-8"))
    return m.group(0).strip() if m else None


def render_corpus(row):
    """Render the corpus-signal paragraph for one data/generated/corpus_signal.jsonl row.

    Output is already in plain() form (no bold markers) so the written page is
    byte-identical whether or not plain() touches it.
    """
    return ("Team Star Wolf corpus signal (keyword-derived, n=" + str(row["corpus_n"]) +
            " HTB training machines): observed on " + str(row["machines"]) + " machines (" +
            ("%.1f" % float(row["pct"])) + "%) " + DASH + " Linux " + str(row["linux"]) +
            " / Windows " + str(row["windows"]) + ". See the corpus deep-dive and "
            "detection-coverage matrix in the Lylat Labs range for tooling and detections.")


class CorpusSignalError(RuntimeError):
    """Raised when regenerating would silently drop or contradict corpus evidence."""


def load_corpus_signal(prof_ids, tdir):
    """Load corpus_signal.jsonl and reconcile it against the paragraphs existing pages carry.

    Returns (corpus, corpus_pct, page_blocks):
      corpus      technique_id -> rendered paragraph (from data)
      corpus_pct  technique_id -> prevalence percent (from data)
      page_blocks technique_id -> paragraph currently on the committed page (guard only)
    Raises CorpusSignalError instead of letting a regeneration delete evidence.
    """
    page_blocks = {}
    if tdir.exists():
        for tid in prof_ids:
            block = extract_corpus(tdir / (tslug(tid) + ".md"))
            if block:
                page_blocks[tid] = block

    if not CORPUS_PATH.exists():
        if page_blocks:
            raise CorpusSignalError(
                str(len(page_blocks)) + " technique page(s) carry a corpus-signal paragraph but " +
                CORPUS_PATH.relative_to(ROOT).as_posix() + " is missing; refusing to regenerate "
                "(the paragraphs would be deleted). Restore the data file.")
        return {}, {}, page_blocks

    corpus, corpus_pct = {}, {}
    for row in load_jsonl(CORPUS_PATH):
        tid = row.get("technique_id")
        if tid not in prof_ids:
            raise CorpusSignalError("corpus_signal.jsonl row for unknown technique " + repr(tid))
        if tid in corpus:
            raise CorpusSignalError("corpus_signal.jsonl has duplicate technique_id " + tid)
        corpus[tid] = render_corpus(row)
        corpus_pct[tid] = float(row["pct"])

    lost = sorted(t for t in page_blocks if t not in corpus)
    if lost:
        raise CorpusSignalError(
            "pages carry a corpus-signal paragraph for " + ", ".join(lost) + " but " +
            CORPUS_PATH.relative_to(ROOT).as_posix() + " has no row for them; refusing to "
            "regenerate (the paragraphs would be deleted). Add the rows or remove the paragraphs "
            "deliberately.")
    return corpus, corpus_pct, page_blocks


def link(text, url):
    return "[" + text + "](" + url + ")" if url else text


# All ATT&CK software (official S0/S1 and the v19.2 S9xxx block) has a live
# attack.mitre.org page, so inline description links are kept as-is.
def canon_desc(text):
    return text or ""


def sstr(v):
    """Stringify a field that may be a list or scalar."""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return "" if v is None else str(v)


_ABBR = {"e.g", "i.e", "etc", "vs", "cf", "al", "u.s", "a.k.a", "resp", "approx",
         "fig", "eq", "dr", "mr", "ms", "inc", "ltd", "co", "st", "no", "ie", "eg", "ex"}


def summarize(text, max_chars=220):
    """First full sentence (abbreviation-aware) of a description, on one line.
    Never cut a complete sentence mid-word — a returned sentence always ends on
    its own terminal punctuation. Only text with NO sentence terminator at all
    (a run-on) is clipped at a word boundary with an ellipsis. max_chars only
    bounds that run-on fallback; a complete first sentence is returned in full
    even if longer, so guidance never reads as a fragment."""
    if not text:
        return ""
    t = re.sub(r"\s+", " ", str(text)).strip()
    for m in re.finditer(r"[.!?]+(?=\s|$)", t):
        raw = t[:m.start()].rsplit(" ", 1)[-1].rstrip(".")
        tok = re.sub(r"[^A-Za-z.]", "", raw).rstrip(".").lower()
        # Skip only known abbreviations ("e.g.") and single-LETTER initials ("J." in
        # "J. Smith"). A word ending in a digit ("unit 74455.") or any normal word is
        # a real sentence end — don't treat it as an initial just because it has no letters.
        if tok in _ABBR or (len(raw) == 1 and raw.isalpha()):
            continue
        return t[:m.end()]  # first complete sentence, in full — never truncated
    # No sentence terminator anywhere: clip the run-on at a word boundary.
    if len(t) > max_chars:
        return t[:max_chars].rsplit(" ", 1)[0].rstrip(",;:(") + "\N{HORIZONTAL ELLIPSIS}"
    return t


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
        self.ids = AttackIds(ROOT)
        self._carry_forward_crosswalks()
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
        # All ATT&CK software IDs — official S0/S1 and the v19.2 S9xxx block (e.g. G1056
        # TeamPCP's S9041-44, verified live on attack.mitre.org) — are first-class objects
        # with a valid ATT&CK ID and a live attack.mitre.org page.
        sp_p = DATA / "attack/software_profiles.jsonl"
        _sw_all = load_jsonl(sp_p) if sp_p.exists() else []
        self.sw_prof = {r["software_id"]: r for r in _sw_all
                        if re.fullmatch(r"S\d{4}", r["software_id"])}
        self.sw_name_to_id = {r["name"]: r["software_id"] for r in self.sw_prof.values()}
        # (The earlier S9xxx "emerging/community" and "lab/fictional" carve-outs were
        # removed — those entities are official MITRE ATT&CK v19.2, verified live.)
        cp_p = DATA / "attack/campaign_profiles.jsonl"
        self.camp_prof = {r["campaign_id"]: r for r in (load_jsonl(cp_p) if cp_p.exists() else [])}
        # Live per-technique edges. Technique pages print counts and lists from these
        # edge tables, not from the denormalised *_count / mitigations /
        # detection_strategies fields on technique_profiles (review gen-6/gen-7/gen-8:
        # those fields were a pre-v19 snapshot, so headers contradicted the lists).
        self.camps_by_t = defaultdict(list)
        for cid in sorted(self.camp_prof):
            for t in self.camp_prof[cid].get("techniques") or []:
                self.camps_by_t[t].append(cid)
        self.strats_by_t = defaultdict(list)
        for r in sorted(load_jsonl(DATA / "attack/detection_strategies.jsonl"), key=lambda r: r["strategy_id"]):
            self.strats_by_t[r["technique_id"]].append(r["name"])

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

        # corpus signal rendered from data/generated/corpus_signal.jsonl
        # (technique_id -> paragraph, technique_id -> percent for tactic "most-observed");
        # the paragraphs the committed pages carry are kept only as a loss guard.
        self.corpus, self.corpus_pct, self.corpus_on_pages = load_corpus_signal(
            set(self.prof), MITRE / "techniques")
        self.corpus_ids = set(self.corpus)

        # --- mitigations ---
        self.mit = {r["mitigation_id"]: r for r in load_jsonl(DATA / "attack/mitigations.jsonl")}
        self.mit_techs = defaultdict(list)
        self.mits_by_t = defaultdict(list)
        for r in load_jsonl(DATA / "attack/mitigation_to_technique.jsonl"):
            self.mit_techs[r["mitigation_id"]].append((r["technique_id"], r["technique_name"]))
            self.mits_by_t[r["technique_id"]].append({"id": r["mitigation_id"], "name": r["mitigation_name"]})

        # --- CAPEC + CWE ---
        self.capec = {r["capec_id"]: r for r in load_jsonl(DATA / "weaknesses/capec.jsonl")}
        self.cwe = {r["cwe_id"]: r for r in load_jsonl(DATA / "weaknesses/cwe.jsonl")}
        self.cwe_name = {k: v.get("name", "") for k, v in self.cwe.items()}

        # --- ATLAS ---
        self.atlas = {r["technique_id"]: r for r in load_jsonl(DATA / "ai/atlas_techniques.jsonl")}
        self.atlas_mit = {r["mitigation_id"]: r for r in load_jsonl(DATA / "ai/atlas_mitigations.jsonl")}
        self.atlas_tactics = {r["tactic_id"]: r for r in load_jsonl(DATA / "ai/atlas_tactics.jsonl")}
        self.atlas_subs = defaultdict(list)
        for r in self.atlas.values():
            if r.get("parent_id"):
                self.atlas_subs[r["parent_id"]].append(r["technique_id"])

        # --- D3FEND (reverse map: countermeasure -> tactic, artifacts, ATT&CK techniques it counters) ---
        # D3FEND publishes its ATT&CK mappings against whatever id they were authored for,
        # so a row keyed on an id ATT&CK has since revoked (T1562.010) is shown on the live
        # successor (T1689) with the predecessor kept as provenance, never as a second,
        # unmarked "countered" technique. Deprecated ids (no successor) are listed apart.
        # Artifacts and counters are sorted so the pages do not depend on the row order
        # of technique_to_d3fend.jsonl.
        self.d3_pages = {}
        for r in load_jsonl(DATA / "attack/technique_to_d3fend.jsonl"):
            name = r.get("d3fend_technique")
            if not name:
                continue
            page = self.d3_pages.setdefault(name, {"tactic": "", "artifacts": set(), "counters": {},
                                                   "retired": set()})
            if not page["tactic"] and r.get("d3fend_tactic"):
                page["tactic"] = sstr(r["d3fend_tactic"])
            page["artifacts"].update(a for a in (r.get("digital_artifact") or []) if a)
            tid = r.get("technique_id", "")
            if not (tid.startswith("T") and not tid.startswith("TA")):
                continue
            rel = sstr(r.get("relation")) or "maps"
            dom = self.attack_domain(tid)
            state, succ = self.ids.status(tid, dom)
            if state == "revoked":
                key, via = (dom, succ), tid
            elif state == "live":
                key, via = (dom, tid), None
            else:  # deprecated (no successor), dangling or unknown: not a current technique
                page["retired"].add(tid)
                continue
            c = page["counters"].setdefault(key, {"rels": set(), "direct": False, "via": set()})
            c["rels"].add(rel)
            if via:
                c["via"].add(via)
            else:
                c["direct"] = True
        for page in self.d3_pages.values():
            page["artifacts"] = sorted(page["artifacts"])
            page["retired"] = sorted(page["retired"])

    def attack_domain(self, tid):
        """'ics' for an ICS-domain technique id (T0xxx and the v19 ICS T16xx block), else 'enterprise'."""
        if tid in self.prof:
            return "enterprise"
        if tid in self.ids.profiles.get("ics", {}) or tid in self.ids.sup.get("ics", {}):
            return "ics"
        return "enterprise"


    def _carry_forward_crosswalks(self):
        """D3FEND, CAR and Engage publish their ATT&CK mappings against whatever id they
        were authored for, so an edge keyed on an id ATT&CK has since revoked (T1562 ->
        T1685, T1574.002 -> T1574.001, ...) is also shown on the live successor, following
        data/attack/superseded_by.jsonl chains - the same rule build_control_rollup.py and
        backfill_capec_edges.py apply to NIST and CAPEC. The revoked page keeps its own
        edges; an item already on the successor is not repeated.

        Provenance is kept per framework in self.{d3,car,engage}_via_revoked as
        successor -> {revoked predecessor: sorted keys that predecessor maps}, the same
        rule and shape as AttackIds.carry_forward() and the nist_800_53_controls_via_revoked
        / capec_via_revoked profile fields, so the technique page prints the same
        "Carried forward from revoked ..." line under the D3FEND, CAR and Engage sections.
        (The successor rows #48 copied into technique_to_d3fend.jsonl and
        technique_to_car.jsonl are those predecessors' mappings, so they are credited to
        the predecessor too.) Only live successors appear in predecessors(), so a revoked
        page never receives carried edges or the line."""
        def merge(dst, src, key):
            have = {x.get(key) for x in dst}
            for x in src:
                if x.get(key) not in have:
                    dst.append(x)
                    have.add(x.get(key))
            return sorted({x.get(key) for x in src})

        self.d3_via_revoked, self.car_via_revoked, self.engage_via_revoked = {}, {}, {}
        preds = self.ids.predecessors("enterprise")
        for succ in sorted(preds):
            for old in preds[succ]:
                if self.d3.get(old):
                    self.d3_via_revoked.setdefault(succ, {})[old] = merge(
                        self.d3[succ], self.d3[old], "d3fend_technique")
                if self.car.get(old):
                    self.car_via_revoked.setdefault(succ, {})[old] = merge(
                        self.car.setdefault(succ, []), self.car[old], "car_id")
                if self.engage.get(old):
                    self.engage_via_revoked.setdefault(succ, {})[old] = merge(
                        self.engage.setdefault(succ, []), self.engage[old], "id")


# ----------------------------------------------------------------------------- technique
def render_technique(db, tid):
    p = db.prof[tid]
    out = ["# " + tid + " " + DASH + " " + p["name"] + "\n", '<a id="' + tanchor(tid) + '"></a>\n']

    plats = ", ".join(p.get("platforms") or []) or DASH
    if p.get("revoked"):
        # A revoked object has no v19.2 tactic. Its stored tactic is the pre-v19 one put
        # through the Defense Evasion -> Stealth rename, so print it as the legacy tactic
        # and give the successor's v19.2 tactics next to it (review cur-8).
        legacy = [LEGACY_TACTIC.get(t, t) for t in (p.get("tactics") or [])]
        tac_lines = ["**Tactics (pre-v19, legacy):** " + (", ".join(legacy) or DASH) + "  "]
        sup = p.get("superseded_by")
        if sup and sup in db.prof:
            tac_lines.append("**Successor's tactics (" + ATTACK_VER + "):** " +
                             (", ".join(db.prof[sup].get("tactics") or []) or DASH) + "  ")
    else:
        tac_lines = ["**Tactics:** " + (", ".join(p.get("tactics") or []) or DASH) + "  "]
    hdr = tac_lines + [
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

    # Mitigations (live edges: mitigation_to_technique.jsonl)
    migs = sorted(db.mits_by_t.get(tid) or [], key=lambda m: m["id"])
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

    # D3FEND (now linked to the d3fend pages). One row per countermeasure (the first edge
    # for a name wins, as before), listed by D3FEND id (D3-AL, D3-AM, ...) so the page does
    # not depend on the row order of technique_to_d3fend.jsonl or on which carried-forward
    # predecessor was merged first; a name with no countermeasure record sorts last by name.
    edges = db.d3.get(tid) or []
    if edges:
        first = {}
        for e in edges:
            name = e.get("d3fend_technique")
            if name and name not in first:
                first[name] = e
        rows = []
        for name in sorted(first, key=lambda n: d3fend_sort_key(db, n)):
            e = first[name]
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
        via = db.d3_via_revoked.get(tid) or {}
        if via:
            out.append(_via_revoked_note(db, via, "D3FEND"))

    # Detection (enriched: strategies + analytics with log sources)
    strategies = db.strats_by_t.get(tid) or []
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
        via = db.car_via_revoked.get(tid) or {}
        if via:
            out.append(_via_revoked_note(db, via, "MITRE CAR"))

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
        via = db.engage_via_revoked.get(tid) or {}
        if via:
            out.append(_via_revoked_note(db, via, "MITRE Engage"))

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
    gc = len(groups)
    sc = len(sw)
    cc = len(db.camps_by_t.get(tid) or [])
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

    # Sub-techniques (for parent techniques). Revoked sub-techniques are not current
    # members of the parent (review cur-4): they are listed apart with their successor.
    kids = sorted(db.subs.get(tid) or [])
    live_kids = [k for k in kids if not db.prof[k].get("revoked")]
    gone_kids = [k for k in kids if db.prof[k].get("revoked")]
    if live_kids:
        out.append("## Sub-techniques (" + str(len(live_kids)) + ")\n")
        rows = []
        for k in live_kids:
            line = "- [" + k + " " + DASH + " " + db.prof[k]["name"] + "](/mitre/techniques/" + tslug(k) + ".md)"
            ks = summarize(db.prof[k].get("description"))
            if ks:
                line += " " + DASH + " " + ks
            rows.append(line)
        out.append("\n".join(rows) + "\n")
    if gone_kids:
        out.append("## Revoked sub-techniques (" + str(len(gone_kids)) + ")\n")
        out.append("Revoked in ATT&CK " + ATTACK_VER + "; the pages are kept for reference.\n")
        out.append("\n".join("- " + revoked_line(db, k) for k in gone_kids) + "\n")

    # NIST 800-53 (now with control names)
    nist = p.get("nist_800_53_controls") or []
    if nist:
        out.append("## NIST 800-53 controls (" + str(len(nist)) + ")\n")
        rows = []
        for c in nist:
            nm = db.nist_name.get(c)
            rows.append("- `" + c + "` " + DASH + " " + nm if nm else "- `" + c + "`")
        out.append("\n".join(rows) + "\n")
        via = p.get("nist_800_53_controls_via_revoked") or {}
        if via:
            out.append(_via_revoked_note(db, via, "the CTID NIST 800-53 mapping"))

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
        via = p.get("capec_via_revoked") or {}
        if via:
            out.append(_via_revoked_note(db, via, "CAPEC"))

    out.append(FOOTER)
    return "\n".join(out)


# ----------------------------------------------------------------------------- shared
def d3fend_sort_key(db, name):
    """Sort key for a D3FEND countermeasure: its D3FEND id (data/attack/d3fend_countermeasures.jsonl),
    then the name; a countermeasure with no id sorts after every one that has one."""
    did = (db.d3_defs.get(name, {}) or {}).get("d3fend_id") or ""
    return (0, did, name) if did else (1, "", name)


def revoked_line(db, tid):
    """'[T1562.001: Disable or Modify Tools](...) (revoked; superseded by [T1685: ...](...))'."""
    p = db.prof[tid]
    sup = p.get("superseded_by")
    line = "[" + tid + " " + DASH + " " + p["name"] + "](/mitre/techniques/" + tslug(tid) + ".md)"
    if sup:
        return line + " (revoked; superseded by " + link_tech(db, sup, p.get("superseded_by_name") or None) + ")"
    return line + " (revoked)"


def _via_revoked_note(db, via, source):
    """Provenance line for edges carried forward from revoked predecessor ids."""
    preds = ", ".join(link_tech(db, old) + " (" + str(len(items)) + ")"
                      for old, items in sorted(via.items()))
    return ("_Carried forward from revoked " + preds + ": " + source + " is keyed on the "
            "predecessor id, which ATT&CK has since revoked in favour of this technique (current release: v19.2)._\n")


def link_tech(db, tid, name=None, domain="enterprise"):
    """Link an ATT&CK technique id: enterprise -> internal page, ICS -> official, else code."""
    if domain == "ics":
        rec = db.ids.profiles.get("ics", {}).get(tid) or {}
        nm = name or rec.get("name")
        label = tid + " " + DASH + " " + nm if nm else tid
        url = rec.get("url") or "https://attack.mitre.org/techniques/" + tid.replace(".", "/")
        return "[" + label + "](" + url + ")"
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
    tc = len(db.mit_techs.get(mid, []))  # live edge count, never the stored snapshot
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
    # live techniques only: a revoked object has no v19.2 tactic (its stored one is the
    # pre-v19 tactic put through the rename), and the tactic landing counts live only
    techs = [t for t, p in db.prof.items()
             if not p.get("revoked") and slug in (p.get("tactics") or [])]
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


# v19.2 renamed Defense Evasion (TA0005) -> Stealth and split out Defense Impairment (TA0112).
RENAMED_TACTICS = {"defense-evasion": ("Defense Evasion", "stealth", "Stealth")}
LEGACY_TACTIC = {new: old for old, (_, new, _) in RENAMED_TACTICS.items()}  # stealth -> defense-evasion
TACTIC_ORDER = [
    ("reconnaissance", "Reconnaissance"), ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"), ("execution", "Execution"), ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"), ("stealth", "Stealth"),
    ("defense-impairment", "Defense Impairment"), ("credential-access", "Credential Access"),
    ("discovery", "Discovery"), ("lateral-movement", "Lateral Movement"), ("collection", "Collection"),
    ("command-and-control", "Command and Control"), ("exfiltration", "Exfiltration"), ("impact", "Impact"),
]
TACTIC_NAME = dict(TACTIC_ORDER)


def primary_tactic(p):
    """First v19.2 tactic of a technique (the grouping /techniques/ uses too), else None."""
    return next((t for t in (p.get("tactics") or []) if t in TACTIC_NAME), None)


def render_tactic_pointer(old_name, new_slug, new_name):
    return ("# Tactic: " + old_name + " (renamed)\n\n"
            '<a id="' + new_slug + '-legacy"></a>\n\n'
            "> **Renamed in ATT&CK v19.2.** _" + old_name + "_ (TA0005) is now **[" + new_name +
            "](/mitre/tactics/" + new_slug + ".md)**, and the impairment behaviours split into the new "
            "**[Defense Impairment](/mitre/tactics/defense-impairment.md)** (TA0112). This page is kept as a "
            "pointer so existing links resolve; see those two tactic pages.\n\n" + SHORT_FOOTER)


def render_tactic_landing(db):
    def count(slug):
        return sum(1 for p in db.prof.values() if not p.get("revoked") and slug in (p.get("tactics") or []))
    out = ["# ATT&CK Tactics (" + ATTACK_VER + ")", "",
           "The 15 Enterprise tactics. In **v19.2**, _Defense Evasion_ (TA0005) was renamed "
           "[Stealth](/mitre/tactics/stealth.md) and the new "
           "[Defense Impairment](/mitre/tactics/defense-impairment.md) tactic (TA0112) was split out.", ""]
    for slug, name in TACTIC_ORDER:
        out.append("- [" + name + "](/mitre/tactics/" + slug + ".md) " + DASH + " " + str(count(slug)) +
                    " techniques")
    out.append("")
    out.append("_Legacy pointer:_ [Defense Evasion (renamed → Stealth)](/mitre/tactics/defense-evasion.md)")
    out.append("\n[MITRE Hub](/mitre/README.md)")
    return "\n".join(out)


# ----------------------------------------------------------------------------- section landings
def render_technique_index(db):
    """mitre/techniques/README.md, from data (review gen-12/cur-7: it used to be a
    hand-maintained file that missed every v19 technique and listed revoked ids unmarked)."""
    live = sorted(t for t, p in db.prof.items() if not p.get("revoked"))
    gone = sorted(t for t, p in db.prof.items() if p.get("revoked"))
    by_tac, untagged = defaultdict(list), []
    for t in live:
        tac = primary_tactic(db.prof[t])
        (by_tac[tac] if tac else untagged).append(t)

    def item(t):
        return ("- [" + t + " " + DASH + " " + db.prof[t]["name"] + "](/mitre/techniques/" + tslug(t) + ".md)" +
                (" " + STAR if t in db.corpus_ids else ""))

    out = ["# MITRE ATT&CK Techniques: Enriched Pages", "",
           "One page per ATT&CK technique (" + str(len(db.prof)) + " pages: " + str(len(live)) +
           " current in ATT&CK " + ATTACK_VER + " plus " + str(len(gone)) + " revoked in " + ATTACK_VER +
           " and kept for reference), each enriched with mitigations, D3FEND countermeasures, CAPEC, NIST "
           "800-53 controls, detection strategies, and Team Star Wolf corpus prevalence where observed. "
           "Each current technique is listed once, under its primary (first) tactic; a "
           "[tactic page](/mitre/tactics/README.md) lists every technique in that tactic. " + STAR +
           " marks the " + str(len(db.corpus_ids)) + " techniques seen in the Team Star Wolf training corpus.", "",
           "[MITRE Hub](/mitre/README.md) \N{MIDDLE DOT} [Tactics](/mitre/tactics/README.md) \N{MIDDLE DOT} "
           "[Mitigations](/mitre/mitigations/README.md)", ""]
    for slug, name in TACTIC_ORDER:
        ts = by_tac.get(slug) or []
        if not ts:
            continue
        out.append("## " + name + " (" + str(len(ts)) + ")\n")
        out.append("\n".join(item(t) for t in ts) + "\n")
    if untagged:
        out.append("## No " + ATTACK_VER + " tactic (" + str(len(untagged)) + ")\n")
        out.append("\n".join(item(t) for t in untagged) + "\n")
    if gone:
        out.append("## Revoked in ATT&CK " + ATTACK_VER + " (" + str(len(gone)) + ")\n")
        out.append("No longer current ATT&CK techniques. Each page is kept so old links resolve, and "
                   "carries a banner to the technique that replaced it.\n")
        out.append("\n".join("- " + revoked_line(db, t) for t in gone) + "\n")
    out.append(SHORT_FOOTER)
    return "\n".join(out)


def render_mitigation_landing(db, mids):
    """mitre/mitigations/README.md: the per-mitigation counts, from the live edge table."""
    rows = sorted(mids, key=lambda m: (-len(db.mit_techs.get(m, [])), m))
    out = ["# MITRE ATT&CK Mitigations: with Implementation Guidance", "",
           "One page per ATT&CK mitigation (" + str(len(rows)) + "), each with concrete how-to-implement "
           "steps, mapped NIST 800-53 families, the techniques it addresses, and Team Star Wolf corpus "
           "relevance. ATT&CK " + ATTACK_VER + ".", "",
           "[MITRE Hub](/mitre/README.md), [Techniques](/mitre/techniques/README.md)", "", "",
           "| Mitigation | Techniques addressed |", "|---|---:|"]
    for mid in rows:
        out.append("| [" + mid + " " + DASH + " " + db.mit[mid].get("name", "") + "](/mitre/mitigations/" +
                   mid + ".md) | " + str(len(db.mit_techs.get(mid, []))) + " |")
    return "\n".join(out) + "\n"


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
            out.append("**Digital artifacts:** " + ", ".join(page["artifacts"]) + "  ")  # sorted in DB
        out.append("")
        if defrec.get("definition"):
            out.append(str(defrec["definition"]).strip() + "\n")
        if defrec.get("how_to"):
            out.append("## How to deploy\n")
            out.append(str(defrec["how_to"]).strip() + "\n")
        # ATT&CK techniques countered: live ids only (enterprise + ICS), sorted by id; a row
        # D3FEND keys on a revoked id is shown on its live successor with the predecessor
        # named as provenance (see DB.d3_pages).
        rows = []
        for (dom, tid) in sorted(page["counters"], key=lambda k: (k[1], k[0])):
            c = page["counters"][(dom, tid)]
            line = "- " + link_tech(db, tid, domain=dom) + " " + DASH + " " + ", ".join(sorted(c["rels"]))
            if c["via"] and not c["direct"]:
                line += (" (D3FEND maps the revoked predecessor " +
                         ", ".join(sorted(c["via"])) + ")")
            ts = summarize((db.prof.get(tid, {}) or {}).get("description")) if dom == "enterprise" else ""
            if ts:
                line += ". " + ts
            rows.append(line)
        if rows:
            out.append("## ATT&CK techniques countered (" + str(len(rows)) + ")\n")
            out.append("\n".join(rows))
        if page["retired"]:
            out.append("\n_D3FEND also maps " + ", ".join(page["retired"]) + ", deprecated in ATT&CK "
                       "with no successor; not counted above._")
    out.append("\n" + SHORT_FOOTER)
    return "\n".join(out)


def render_d3fend_index(db, names):
    """mitre/d3fend/README.md: one line per D3FEND page the generator writes (names from the
    page H1s), sorted by name, with the countermeasure's D3FEND tactic. It used to be a
    hand-maintained file; the count and order are now derived."""
    out = ["# D3FEND Countermeasures (" + str(len(names)) + ")", "",
           "One page per D3FEND technique, with the ATT&CK techniques it counters.", ""]
    for slug, name in sorted(names, key=lambda sn: sn[1]):
        tac = (db.d3_pages.get(name) or {}).get("tactic") or \
              sstr((db.d3_defs.get(name, {}) or {}).get("d3fend_tactic"))
        out.append("- [" + name + "](/mitre/d3fend/" + slug + ".md)" + (" (" + tac + ")" if tac else ""))
    out += ["", "[MITRE Hub](/mitre/README.md)", ""]
    return "\n".join(out)


# ----------------------------------------------------------------------------- capec
CAPEC_SEVERITY_ORDER = ("Very High", "High", "Medium", "Low", "Very Low")


def render_capec_index(db):
    """mitre/capec/README.md: every CAPEC page, grouped by typical severity (most severe
    first; a pattern with no severity under "Unknown"), ids in string order within a group.
    It used to be a hand-maintained file; the counts and grouping are now derived."""
    by_sev = defaultdict(list)
    for cid, c in db.capec.items():
        sev = str(c.get("typical_severity") or "").strip()
        by_sev[sev if sev in CAPEC_SEVERITY_ORDER else "Unknown"].append(cid)
    out = ["# CAPEC Attack Patterns (" + str(len(db.capec)) + ")", "",
           "One page per CAPEC pattern, mapped to ATT&CK techniques and CWE.", "",
           "Each page links to the pattern on [OpenCRE](https://opencre.org/), the OWASP project that "
           "links security standards through common requirements, so a pattern can be followed to "
           "requirements and guidance such as OWASP ASVS and the OWASP Cheat Sheets. OpenCRE reaches "
           "CAPEC patterns through their related CWE entries, and the link opens the pattern on the "
           "MITRE CAPEC site when OpenCRE has no links for it ([how the link resolves]("
           + OPENCRE_SMARTLINK_SRC + "))."
           , "", ""]
    for sev in CAPEC_SEVERITY_ORDER + ("Unknown",):
        ids = sorted(by_sev.get(sev) or [])
        if not ids:
            continue
        out += ["## " + sev + " severity (" + str(len(ids)) + ")", ""]
        out += ["- [" + cid + " " + DASH + " " + db.capec[cid].get("name", "") + "](/mitre/capec/" + cid + ".md)"
                for cid in ids]
        out.append("")
    out += ["[MITRE Hub](/mitre/README.md)", ""]
    return "\n".join(out)
def render_capec(db, cid):
    c = db.capec[cid]
    out = ["# " + cid + " " + DASH + " " + c.get("name", "") + "\n",
           '<a id="' + cid.lower() + '"></a>\n']
    meta = []
    for k, label in (("abstraction", "Abstraction"), ("typical_severity", "Typical severity"),
                     ("likelihood", "Likelihood"), ("status", "Status")):
        if c.get(k):
            meta.append("**" + label + ":** " + str(c[k]) + "  ")
    meta.append("**OpenCRE:** [" + cid + "](" + OPENCRE_SMARTLINK + "CAPEC/" + cid.replace("CAPEC-", "") + ")  ")
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


def render_atlas_index(db):
    """mitre/atlas/README.md (the MITRE ATLAS AI matrix pages): every ATLAS technique and
    mitigation page, ids in string order. It used to be a hand-maintained file; the counts
    are now derived (tactics from data/ai/atlas_tactics.jsonl)."""
    out = ["# MITRE ATLAS (AI/ML): Enriched Pages", "",
           str(len(db.atlas)) + " techniques + " + str(len(db.atlas_mit)) + " mitigations across " +
           str(len(db.atlas_tactics)) + " tactics. AI/ML adversarial threat landscape.", "",
           "## Techniques", ""]
    out += ["- [" + tid + " " + DASH + " " + db.atlas[tid].get("name", "") + "](/mitre/atlas/" + aml_slug(tid) + ".md)"
            for tid in sorted(db.atlas)]
    out += ["", "## Mitigations", ""]
    out += ["- [" + mid + " " + DASH + " " + db.atlas_mit[mid].get("name", "") + "](/mitre/atlas/" + aml_slug(mid) + ".md)"
            for mid in sorted(db.atlas_mit)]
    out += ["", "[MITRE Hub](/mitre/README.md)", ""]
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
             "ATT&CK-tracked software (malware and tools), each with its type, platforms, aliases, the "
             "techniques it implements (linked), and the groups that use it. ATT&CK " + ATTACK_VER + ".", ""]
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


# (The former "emerging & community tools" / lab-fictional subsystem was removed:
#  all S9xxx are official MITRE ATT&CK v19.2 software, rendered as first-class
#  objects under /mitre/software/ with live attack.mitre.org links.)


# ----------------------------------------------------------------------------- landing
def render_landing(db):
    n_tech = len(list((MITRE / "techniques").glob("T*.md")))
    n_mit = len(list((MITRE / "mitigations").glob("M*.md")))
    # the 15 v19.2 tactics; defense-evasion.md is only a legacy pointer to Stealth (review cur-7)
    n_tac = len([p for p in (MITRE / "tactics").glob("*.md")
                 if p.name != "README.md" and p.stem not in RENAMED_TACTICS])
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
        "- Investigating a technique? Open its Technique page. Mitigations, detection analytics (with the "
        "exact log sources), and the groups and tools that use it are all on one page.",
        "- Building a control set? Open a Mitigation page for implementation guidance and the NIST mapping, "
        "or the Crosswalk for the full join.",
        "- Engineering detections? The Detection and Data sources sections on each technique name the "
        "analytics and telemetry to collect.",
        "- Prioritising? Techniques marked (observed) are the " + str(corpus_n) + " seen in the Team Star "
        "Wolf 529-machine training corpus, a real-world lower bound on prevalence.",
        "",
        "Coverage: every ATT&CK object cross-links to its related mitigations, D3FEND countermeasures, "
        "CAPEC patterns, and NIST 800-53 controls, so the cross-framework relationships can be browsed in one place.",
        "",
        FOOTER,
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------------------- crosswalk
def _d3_count(db, tid):
    return len({e.get("d3fend_technique") for e in (db.d3.get(tid) or []) if e.get("d3fend_technique")})


def render_crosswalk(db):
    CAP_MIT = 6
    out = ["# MITRE Cross-Framework Crosswalk\n", '<a id="crosswalk"></a>\n',
           "[MITRE Hub](/mitre/README.md) · [Techniques](/mitre/techniques/README.md) · "
           "[Mitigations](/mitre/mitigations/README.md) · [D3FEND](/mitre/d3fend/README.md) · "
           "[CAPEC](/mitre/capec/README.md)\n",
           "The join in one place: **ATT&CK technique ↔ Mitigation (M-code) ↔ NIST 800-53 ↔ "
           "D3FEND ↔ CAPEC**. Two views: a per-mitigation rollup (which NIST families and D3FEND "
           "countermeasures each mitigation brings), and a per-technique index of counts + links. ATT&CK "
           + ATTACK_VER + ".\n"]

    # non-revoked techniques only (revoked pages carry banners; the crosswalk is the live join)
    live = [t for t in db.prof if not db.prof[t].get("revoked")]

    # ---- per-mitigation rollup
    mit_techs = defaultdict(list)
    for t in live:
        for m in (db.prof[t].get("mitigations") or []):
            mit_techs[m["id"]].append(t)
    out.append("## Per-mitigation rollup\n")
    out.append("For each ATT&CK mitigation: how many techniques it addresses, the NIST 800-53 control "
               "families most associated with those techniques, and how many distinct D3FEND countermeasures "
               "they map to. This is the mitigation ↔ control ↔ D3FEND join not expressed elsewhere.\n")
    out.append("| Mitigation | Techniques | Top NIST 800-53 families | D3FEND countermeasures |")
    out.append("|---|---:|---|---:|")
    for mid in sorted(mit_techs, key=lambda m: (-len(mit_techs[m]), m)):
        ts = mit_techs[mid]
        fam = Counter()
        d3 = set()
        for t in ts:
            for c in (db.prof[t].get("nist_800_53_controls") or []):
                fam[c.split("-")[0]] += 1
            d3 |= {e.get("d3fend_technique") for e in (db.d3.get(t) or []) if e.get("d3fend_technique")}
        fams = ", ".join(f for f, _ in fam.most_common(8)) or DASH
        name = (db.mit.get(mid, {}) or {}).get("name", "")
        out.append("| [" + mid + (" — " + name if name else "") + "](/mitre/mitigations/" + mid +
                   ".md) | " + str(len(ts)) + " | " + fams + " | " + str(len(d3)) + " |")
    out.append("")

    # ---- per-technique crosswalk
    out.append("## Per-technique crosswalk (counts + links)\n")
    out.append('"(observed)" marks techniques seen in the Team Star Wolf 529-machine training corpus. '
               "Counts link out to the per-object pages.\n")
    out.append("| Technique | Tactic | Mitigations | NIST | D3FEND | CAPEC |")
    out.append("|---|---|---|---:|---:|---:|")
    for t in sorted(live):
        p = db.prof[t]
        star = " " + STAR if t in db.corpus_ids else ""
        tac = ", ".join(p.get("tactics") or []) or DASH
        migs = p.get("mitigations") or []
        mlinks = " ".join("[" + m["id"] + "](/mitre/mitigations/" + m["id"] + ".md)" for m in migs[:CAP_MIT])
        if len(migs) > CAP_MIT:
            mlinks += " +" + str(len(migs) - CAP_MIT)
        mlinks = mlinks or DASH
        nist = len(p.get("nist_800_53_controls") or [])
        capec = len(p.get("capec") or [])
        out.append("| [" + t + "](/mitre/techniques/" + tslug(t) + ".md) " + p["name"] + star + " | " +
                   tac + " | " + mlinks + " | " + str(nist) + " | " + str(_d3_count(db, t)) + " | " +
                   str(capec) + " |")
    out.append("\n" + FOOTER)
    return "\n".join(out)


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="techniques,landing")
    ap.add_argument("--check", action="store_true",
                    help="write nothing under mitre/: render the selected sections into a temporary "
                         "directory and exit 1 if any committed page differs, is missing, or is an orphan "
                         "the generator no longer produces")
    ap.add_argument("--verify-corpus", type=int, metavar="N", default=None,
                    help="write nothing; fail unless corpus_signal.jsonl holds exactly N rows, every "
                         "row's paragraph is on its committed page verbatim, and no page carries a "
                         "paragraph the data file lacks")
    args = ap.parse_args()
    only = set(x.strip() for x in args.only.split(",") if x.strip())
    if "all" in only:
        only = {"techniques", "mitigations", "tactics", "d3fend", "capec", "atlas", "f3", "groups",
                "software", "campaigns", "crosswalk", "landing"}

    try:
        db = DB()
    except CorpusSignalError as e:
        print("ERROR: corpus signal: " + str(e))
        raise SystemExit(2)
    print("loaded: " + str(len(db.prof)) + " techniques, corpus preserved for " +
          str(len(db.corpus_ids)) + " of them (" + CORPUS_PATH.relative_to(ROOT).as_posix() +
          "; " + str(len(db.corpus_on_pages)) + " committed pages carry the paragraph)")

    if args.verify_corpus is not None:
        problems = []
        if len(db.corpus_ids) != args.verify_corpus:
            problems.append("expected " + str(args.verify_corpus) + " corpus-signal rows, data file has " +
                            str(len(db.corpus_ids)))
        for tid in sorted(db.corpus_ids):
            on_page = db.corpus_on_pages.get(tid)
            if on_page is None:
                problems.append(tid + ": page lacks the corpus-signal paragraph (regenerate techniques)")
            elif on_page != db.corpus[tid]:
                problems.append(tid + ": page paragraph differs from data (regenerate techniques)")
        # (a page paragraph with no data row already aborted inside DB())
        if problems:
            print("CORPUS SIGNAL CHECK FAILED:")
            for p in problems:
                print("  - " + p)
            raise SystemExit(1)
        print("OK: corpus signal round-trips for " + str(len(db.corpus_ids)) + " techniques "
              "(data file == committed pages)")
        return

    # --check renders OUTSIDE the repository (the old mitre/_gen_check/ lived inside the tree
    # that the Pages deploy publishes wholesale, so a stray local check run could be deployed).
    check_dir = Path(tempfile.mkdtemp(prefix="tsw-mitre-check-")) if args.check else None
    out_root = (check_dir / "mitre") if args.check else MITRE
    try:
        generate(db, only, out_root)
        if args.check:
            raise SystemExit(compare_tree(out_root, only))
    finally:
        if check_dir is not None:
            shutil.rmtree(check_dir, ignore_errors=True)


# Every section README.md is generated (capec, atlas and d3fend were hand-written until
# their index renderers landed), so the drift check compares and orphan-checks all of them.
SECTION_DIRS = ("techniques", "mitigations", "tactics", "d3fend", "capec", "atlas", "f3", "groups",
                "software", "campaigns")


def _norm(p):
    # read_text() already folds CRLF to LF, so a Windows checkout compares equal
    return p.read_text(encoding="utf-8")


def compare_tree(out_root, only):
    """Diff the freshly rendered sections against the committed mitre/ tree.
    Returns 0 when identical, 1 (after printing every difference) otherwise."""
    problems = []
    for f in sorted(out_root.rglob("*.md")):
        rel = f.relative_to(out_root)
        committed = MITRE / rel
        if not committed.exists():
            problems.append("missing  mitre/" + rel.as_posix() + "  (generator writes it; not committed)")
        elif _norm(committed) != _norm(f):
            problems.append("stale    mitre/" + rel.as_posix() + "  (committed page differs from the data)")
    for sec in SECTION_DIRS:
        if sec not in only:
            continue
        for committed in sorted((MITRE / sec).glob("*.md")):
            if not (out_root / sec / committed.name).exists():
                problems.append("orphan   mitre/" + sec + "/" + committed.name +
                                "  (committed, but the data no longer produces it)")
    n = sum(1 for _ in out_root.rglob("*.md"))
    if problems:
        sel = "all" if set(SECTION_DIRS) | {"crosswalk", "landing"} <= only else ",".join(sorted(only))
        print("MITRE PAGES DRIFT: " + str(len(problems)) + " of " + str(n) + " generated pages differ "
              "from the committed tree. Run `python scripts/generate_mitre_pages.py --only " + sel +
              "` and commit the result:")
        for line in problems[:200]:
            print("  " + line)
        if len(problems) > 200:
            print("  ... and " + str(len(problems) - 200) + " more")
        return 1
    print("OK: " + str(n) + " generated mitre/ pages match the committed tree (" + ",".join(sorted(only)) + ")")
    return 0


def emit(out_root, path, text):
    """Write one page. A committed page's "Library references" block is kept as it is:
    scripts/build_crosslinks.py writes that block from the hand-written pages and its
    --check guards it, so a regeneration here never adds, drops or changes it."""
    try:
        old = (MITRE / path.relative_to(out_root)).read_text(encoding="utf-8")
    except OSError:
        old = None
    path.write_text(xl.carry_library_refs(old, text), encoding="utf-8", newline="\n")


def generate(db, only, out_root):
    """Render the selected sections of mitre/ into out_root (mitre/ itself, or a --check temp dir)."""
    if "techniques" in only:
        d = out_root / "techniques"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for tid in db.prof:
            emit(out_root, d / (tslug(tid) + ".md"), plain(render_technique(db, tid)))
            n += 1
        emit(out_root, d / "README.md", plain(render_technique_index(db)))
        print("techniques: wrote " + str(n) + " pages + README")

    if "mitigations" in only:
        d = out_root / "mitigations"
        d.mkdir(parents=True, exist_ok=True)
        mids = []
        for f in sorted((MITRE / "mitigations").glob("M*.md")):
            mid = f.stem
            if mid not in db.mit:
                continue
            emit(out_root, d / (mid + ".md"), plain(render_mitigation(db, mid, xl.strip_library_refs(f.read_text(encoding="utf-8")))))
            mids.append(mid)
        emit(out_root, d / "README.md", plain(render_mitigation_landing(db, mids)))
        print("mitigations: wrote " + str(len(mids)) + " pages + README")

    if "tactics" in only:
        d = out_root / "tactics"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for f in sorted((MITRE / "tactics").glob("*.md")):
            if f.name == "README.md":
                continue
            if f.stem in RENAMED_TACTICS:
                on, ns, nn = RENAMED_TACTICS[f.stem]
                emit(out_root, d / f.name, plain(render_tactic_pointer(on, ns, nn)))
            else:
                emit(out_root, d / f.name, plain(render_tactic(db, f.stem, xl.strip_library_refs(f.read_text(encoding="utf-8")))))
            n += 1
        emit(out_root, d / "README.md", plain(render_tactic_landing(db)))
        print("tactics: wrote " + str(n) + " pages + README")

    if "d3fend" in only:
        d = out_root / "d3fend"
        d.mkdir(parents=True, exist_ok=True)
        names = []
        for f in sorted((MITRE / "d3fend").glob("*.md")):
            if f.name == "README.md":
                continue
            existing = xl.strip_library_refs(f.read_text(encoding="utf-8"))
            emit(out_root, d / f.name, plain(render_d3fend(db, f.stem, existing)))
            first = existing.splitlines()[0] if existing.splitlines() else ""
            names.append((f.stem, first[len("# D3FEND:"):].strip() if first.startswith("# D3FEND:") else ""))
        emit(out_root, d / "README.md", plain(render_d3fend_index(db, names)))
        print("d3fend: wrote " + str(len(names)) + " pages + README")

    if "capec" in only:
        d = out_root / "capec"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for cid in db.capec:
            emit(out_root, d / (cid + ".md"), plain(render_capec(db, cid)))
            n += 1
        emit(out_root, d / "README.md", plain(render_capec_index(db)))
        print("capec: wrote " + str(n) + " pages + README")

    if "atlas" in only:
        d = out_root / "atlas"
        d.mkdir(parents=True, exist_ok=True)
        nt = nm = 0
        for tid in db.atlas:
            emit(out_root, d / (aml_slug(tid) + ".md"), plain(render_atlas_technique(db, tid)))
            nt += 1
        for mid in db.atlas_mit:
            emit(out_root, d / (aml_slug(mid) + ".md"), plain(render_atlas_mitigation(db, mid)))
            nm += 1
        emit(out_root, d / "README.md", plain(render_atlas_index(db)))
        print("atlas: wrote " + str(nt) + " technique + " + str(nm) + " mitigation pages + README")

    if "f3" in only:
        d = out_root / "f3"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for fid in db.f3:
            emit(out_root, d / (fid + ".md"), plain(render_f3_technique(db, fid)))
            n += 1
        emit(out_root, d / "README.md", plain(render_f3_landing(db)))
        print("f3: wrote " + str(n) + " technique pages + README")

    if "groups" in only:
        d = out_root / "groups"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for gid in db.group_prof:
            emit(out_root, d / (gid + ".md"), plain(render_group(db, gid)))
            n += 1
        emit(out_root, d / "README.md", plain(render_group_landing(db)))
        print("groups: wrote " + str(n) + " pages + README")

    if "software" in only:
        d = out_root / "software"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for sid in db.sw_prof:
            emit(out_root, d / (sid + ".md"), plain(render_software(db, sid)))
            n += 1
        emit(out_root, d / "README.md", plain(render_software_landing(db)))
        print("software: wrote " + str(n) + " pages + README")

    if "campaigns" in only:
        d = out_root / "campaigns"
        d.mkdir(parents=True, exist_ok=True)
        n = 0
        for cid in db.camp_prof:
            emit(out_root, d / (cid + ".md"), plain(render_campaign(db, cid)))
            n += 1
        emit(out_root, d / "README.md", plain(render_campaign_landing(db)))
        print("campaigns: wrote " + str(n) + " pages + README")

    if "crosswalk" in only:
        out_root.mkdir(parents=True, exist_ok=True)
        emit(out_root, out_root / "crosswalk.md", plain(render_crosswalk(db)))
        print("crosswalk: wrote crosswalk.md")

    if "landing" in only:
        out_root.mkdir(parents=True, exist_ok=True)
        emit(out_root, out_root / "README.md", plain(render_landing(db)))
        print("landing: wrote README.md")


if __name__ == "__main__":
    main()
