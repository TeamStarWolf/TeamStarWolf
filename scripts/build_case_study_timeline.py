#!/usr/bin/env python3
"""Build the case study timeline: every study in case-studies/ on one filterable timeline.

    data/case_studies.yaml     one hand-written entry per study, keyed by its path: kind,
                               title, period, sectors, CVEs, ATT&CK groups, tags, exports
                               and up to 12 dated key events taken from the study
    assets/case-studies.json   one row per study with its events, read by the timeline
                               plugin in index.html
    case-studies/TIMELINE.md   the page: the timeline's mount point, then the same studies
                               and events as a plain list grouped by year, which is all a
                               reader sees on GitHub or without the JSON

The build fails, naming the entry and the field, when:
    - a study in case-studies/ (every top-level .md file except README.md and this page)
      has no entry, or an entry names no study
    - kind is not one of KINDS, or a sector is not in the file's sectors list
    - title is not the study's H1
    - a date is not YYYY, YYYY-MM or YYYY-MM-DD (a real day), end comes before start, a
      core period is half given or falls outside the period, or an event comes before the
      one listed above it (compared at the coarser of the two precisions, as are a core
      period and its period)
    - an entry has more than MAX_EVENTS events, or an event label is empty or too long
    - a CVE is not shaped CVE-YYYY-NNNN, or is not named in the study
    - an actor is not a group in data/attack/group_profiles.jsonl with a page in mitre/groups/,
      or is not named in the study
    - a pdf or pptx names no file in case-studies/pdf/ or case-studies/slides/, or an export
      in those folders belongs to no entry
    - any text holds an em dash (U+2014)

Each study is placed under the year its period starts, or the year its core period starts
when the entry gives one (Log4Shell's period starts in 2013, its core in November 2021).
The year filter on the site matches any study whose period overlaps the chosen years. The
headings of the plain list carry docsify-ignore, so the site's sidebar does not list the
headings the timeline hides.

Usage:
    python scripts/build_case_study_timeline.py              # write both files
    python scripts/build_case_study_timeline.py --check      # exit 1 if a file is stale or an entry is invalid
    python scripts/build_case_study_timeline.py --self-test  # planted cases for the date and entry rules
"""
from __future__ import annotations

import argparse
import calendar
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_text, tracked_files  # noqa: E402
from build_doc_meta import Invalid, parse_yaml  # noqa: E402  (the repository's YAML subset)

DATA = "data/case_studies.yaml"
JSON_OUT = "assets/case-studies.json"
PAGE_OUT = "case-studies/TIMELINE.md"
FOLDER = "case-studies/"
NOT_STUDIES = {"case-studies/README.md", PAGE_OUT}
PDF_DIR = "case-studies/pdf/"
PPTX_DIR = "case-studies/slides/"
GROUPS = "data/attack/group_profiles.jsonl"
GROUP_PAGES = "mitre/groups/"
RAW = "https://github.com/TeamStarWolf/TeamStarWolf/raw/main/"
BLOB = "https://github.com/TeamStarWolf/TeamStarWolf/blob/main/"
GENERATED_BY = "written by scripts/build_case_study_timeline.py from " + DATA + "; do not edit"
MAX_EVENTS = 12
MAX_LABEL = 160

# kind key, label, plural label
KINDS = [
    ("vulnerability", "Vulnerability", "Vulnerabilities"),
    ("incident", "Incident", "Incidents"),
    ("campaign", "Campaign", "Campaigns"),
    ("actor", "Threat actor", "Threat actors"),
    ("era", "Period record", "Period records"),
    ("reference", "Attack surface", "Attack surfaces"),
]
KIND_KEYS = [k[0] for k in KINDS]
KIND_LABEL = {k[0]: k[1] for k in KINDS}
FIELDS = {"kind", "title", "start", "end", "core_start", "core_end", "sectors", "cves",
          "actors", "tags", "pdf", "pptx", "events"}
REQUIRED = {"kind", "title", "start", "end", "sectors", "cves", "actors", "tags", "events"}
DATE_RE = re.compile(r"^(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GROUP_RE = re.compile(r"^G\d{4}$")
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August",
          "September", "October", "November", "December"]
EM_DASH = "\u2014"


# ----------------------------------------------------------------------------- dates


def parse_date(s) -> tuple[int, ...] | None:
    """(year,), (year, month) or (year, month, day) for a valid date string, else None."""
    if not isinstance(s, str):
        return None
    m = DATE_RE.match(s)
    if not m:
        return None
    parts = tuple(int(g) for g in m.groups() if g is not None)
    if len(parts) >= 2 and not 1 <= parts[1] <= 12:
        return None
    if len(parts) == 3 and not 1 <= parts[2] <= calendar.monthrange(parts[0], parts[1])[1]:
        return None
    return parts


def low(p: tuple[int, ...]) -> tuple[int, int, int]:
    """The first day a date of any precision covers."""
    return (p[0], p[1] if len(p) > 1 else 1, p[2] if len(p) > 2 else 1)


def high(p: tuple[int, ...]) -> tuple[int, int, int]:
    """The last day a date of any precision covers."""
    month = p[1] if len(p) > 1 else 12
    return (p[0], month, p[2] if len(p) > 2 else calendar.monthrange(p[0], month)[1])


def before(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """a is strictly before b when both are cut to the coarser precision of the two."""
    n = min(len(a), len(b))
    return a[:n] < b[:n]


def human(s: str) -> str:
    p = parse_date(s)
    if p is None:
        return s
    if len(p) == 1:
        return str(p[0])
    if len(p) == 2:
        return MONTHS[p[1] - 1] + " " + str(p[0])
    return str(p[2]) + " " + MONTHS[p[1] - 1] + " " + str(p[0])


def period(start: str, end: str | None) -> str:
    if end is None:
        return "From " + human(start) + ", ongoing"
    if start == end:
        return human(start)
    a, b = parse_date(start), parse_date(end)
    if len(a) == 2 and len(b) == 2 and a[0] == b[0]:
        return MONTHS[a[1] - 1] + " to " + human(end)
    return human(start) + " to " + human(end)


# ----------------------------------------------------------------------------- inputs


def h1(text: str) -> str:
    for line in text.split("\n"):
        m = re.match(r"^#\s+(.+?)\s*$", line)
        if m:
            return m.group(1)
    return ""


def group_names() -> dict[str, str]:
    text = read_text(GROUPS)
    if text is None:
        raise SystemExit(GROUPS + ": not found")
    out = {}
    for line in text.split("\n"):
        if line.strip():
            r = json.loads(line)
            out[r["group_id"]] = r["name"]
    return out


def studies(files: list[str]) -> list[str]:
    return sorted(f for f in files if f.startswith(FOLDER) and f.endswith(".md")
                  and "/" not in f[len(FOLDER):] and f not in NOT_STUDIES)


def load_data() -> dict:
    text = read_text(DATA)
    if text is None:
        raise SystemExit(DATA + ": not found")
    try:
        data = parse_yaml(text, DATA)
    except Invalid as e:
        raise SystemExit(str(e))
    if not isinstance(data, dict):
        raise SystemExit(DATA + ": the top level must be a mapping")
    return data


# ----------------------------------------------------------------------------- validation


def is_text(v) -> bool:
    return isinstance(v, str) and bool(v.strip()) and v == v.strip()


def str_list(v) -> bool:
    return isinstance(v, list) and all(is_text(x) for x in v) and len(set(v)) == len(v)


def validate(data: dict, files: list[str], texts: dict[str, str], groups: dict[str, str]) -> list[str]:
    """Every problem in the data, each naming its entry and field."""
    problems = []
    tracked = set(files)
    sectors = data.get("sectors")
    if not str_list(sectors) or not sectors:
        problems.append(DATA + ": sectors must be a non-empty list of distinct words")
        sectors = []
    entries = data.get("studies")
    if not isinstance(entries, dict) or not entries:
        return problems + [DATA + ": studies must be a mapping of study path to entry"]
    if set(data) - {"sectors", "studies"}:
        problems.append(DATA + ": unknown top-level keys " + ", ".join(sorted(set(data) - {"sectors", "studies"})))
    on_disk = studies(files)
    for rel in on_disk:
        if rel not in entries:
            problems.append(DATA + ": no entry for " + rel + " (every study needs one; see the file header)")
    exports = {"pdf": {}, "pptx": {}}
    for rel, e in entries.items():
        where = DATA + ": " + rel + ": "
        if rel not in on_disk:
            problems.append(where + "no such study in " + FOLDER)
            continue
        if not isinstance(e, dict):
            problems.append(where + "the entry must be a mapping")
            continue
        missing, extra = REQUIRED - set(e), set(e) - FIELDS
        if missing:
            problems.append(where + "missing " + ", ".join(sorted(missing)))
        if extra:
            problems.append(where + "unknown fields " + ", ".join(sorted(extra)))
        if missing:
            continue
        text = texts.get(rel, "")
        if e["kind"] not in KIND_KEYS:
            problems.append(where + "kind '" + str(e["kind"]) + "' is not one of " + ", ".join(KIND_KEYS))
        if e["title"] != h1(text):
            problems.append(where + "title is not the study's H1 ('" + h1(text) + "')")
        dates = {}
        for k in ("start", "end", "core_start", "core_end"):
            if k not in e or (k == "end" and e[k] is None):
                continue
            p = parse_date(e[k])
            if p is None:
                problems.append(where + k + " '" + str(e[k]) + "' is not YYYY, YYYY-MM or YYYY-MM-DD")
            else:
                dates[k] = p
        if ("core_start" in e) != ("core_end" in e):
            problems.append(where + "core_start and core_end go together")
        if "start" in dates and "end" in dates and high(dates["end"]) < low(dates["start"]):
            problems.append(where + "end comes before start")
        if "core_start" in dates and "core_end" in dates:
            if high(dates["core_end"]) < low(dates["core_start"]):
                problems.append(where + "core_end comes before core_start")
            if "start" in dates and before(dates["core_start"], dates["start"]):
                problems.append(where + "the core period starts before the period")
            if "end" in dates and before(dates["end"], dates["core_end"]):
                problems.append(where + "the core period ends after the period")
        for k in ("sectors", "cves", "actors", "tags"):
            if not str_list(e[k]):
                problems.append(where + k + " must be a list of distinct words")
        if str_list(e["sectors"]):
            if not e["sectors"]:
                problems.append(where + "sectors needs at least one sector")
            for s in e["sectors"]:
                if s not in sectors:
                    problems.append(where + "sector '" + s + "' is not in the sectors list at the top of the file")
        if str_list(e["cves"]):
            for c in e["cves"]:
                if not CVE_RE.match(c):
                    problems.append(where + "'" + c + "' is not a CVE id (CVE-YYYY-NNNN)")
                elif c not in text:
                    problems.append(where + c + " is not named in the study")
        if str_list(e["actors"]):
            for g in e["actors"]:
                if not GROUP_RE.match(g) or g not in groups:
                    problems.append(where + "actor '" + g + "' is not a group in " + GROUPS)
                elif GROUP_PAGES + g + ".md" not in tracked:
                    problems.append(where + "actor " + g + " has no page in " + GROUP_PAGES)
                elif not re.search(r"\b" + g + r"\b", text):
                    problems.append(where + g + " is not named in the study")
        for k, folder in (("pdf", PDF_DIR), ("pptx", PPTX_DIR)):
            v = e.get(k)
            if v is None:
                continue
            if not is_text(v) or "/" in v or not v.endswith("." + k) or folder + v not in tracked:
                problems.append(where + k + " '" + str(v) + "' is not a file in " + folder)
            else:
                exports[k][v] = rel
        events = e["events"]
        if not isinstance(events, list):
            problems.append(where + "events must be a list")
            events = []
        if len(events) > MAX_EVENTS:
            problems.append(where + str(len(events)) + " events; at most " + str(MAX_EVENTS))
        prev = None
        for i, ev in enumerate(events, 1):
            at = where + "event " + str(i) + ": "
            if not isinstance(ev, dict) or set(ev) != {"date", "label"}:
                problems.append(at + "write it as {\"date\": ..., \"label\": ...}")
                continue
            p = parse_date(ev["date"])
            if p is None:
                problems.append(at + "date '" + str(ev["date"]) + "' is not YYYY, YYYY-MM or YYYY-MM-DD")
            elif prev is not None and before(p, prev):
                problems.append(at + ev["date"] + " comes before the event above it")
            if p is not None:
                prev = p
            if not is_text(ev["label"]) or len(ev["label"]) > MAX_LABEL or "\n" in ev["label"]:
                problems.append(at + "label must be one line of 1 to " + str(MAX_LABEL) + " characters")
        if EM_DASH in json.dumps(e, ensure_ascii=False):
            problems.append(where + "an em dash (U+2014); use a comma, colon or parentheses")
    for k, folder in (("pdf", PDF_DIR), ("pptx", PPTX_DIR)):
        for f in sorted(files):
            if f.startswith(folder) and "/" not in f[len(folder):] and f.endswith("." + k) \
                    and f[len(folder):] not in exports[k]:
                problems.append(DATA + ": " + f + " belongs to no study; name it as the " + k
                                + " of its study's entry")
    return problems


# ----------------------------------------------------------------------------- outputs


def placement(e: dict) -> str:
    return e.get("core_start") or e["start"]


def build(data: dict, groups: dict[str, str]) -> dict:
    rows = []
    for rel, e in data["studies"].items():
        row = {"p": rel, "t": e["title"], "k": e["kind"], "s": e["start"], "e": e["end"]}
        if e.get("core_start"):
            row["cs"], row["ce"] = e["core_start"], e["core_end"]
        row["y"] = int(placement(e)[:4])
        row["sec"] = e["sectors"]
        row["cve"] = e["cves"]
        row["act"] = [[g, groups[g]] for g in e["actors"]]
        row["tag"] = e["tags"]
        if e.get("pdf"):
            row["pdf"] = RAW + PDF_DIR + e["pdf"]
        if e.get("pptx"):
            row["pptx"] = RAW + PPTX_DIR + e["pptx"]
        row["ev"] = [[ev["date"], ev["label"]] for ev in e["events"]]
        rows.append(row)
    rows.sort(key=lambda r: (low(parse_date(r.get("cs") or r["s"])), r["p"]), reverse=True)
    return {
        "about": "Case study timeline data, " + GENERATED_BY + ". Row keys: p study path, t title, "
                 "k kind, s and e the period (YYYY, YYYY-MM or YYYY-MM-DD; e null while ongoing), "
                 "cs and ce the core period when the study names one, y the year the study is "
                 "placed under, sec sectors, cve CVE ids named in the study, act ATT&CK groups "
                 "[id, name], tag tags, pdf and pptx download links, ev dated key events "
                 "[date, label]. Rows are newest first.",
        "kinds": [{"key": k, "label": lab, "plural": pl} for k, lab, pl in KINDS],
        "sectors": data["sectors"],
        "rows": rows,
    }


def render_json(out: dict) -> str:
    return json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n"


def capped(items: list[str], n: int = 6) -> str:
    if len(items) <= n:
        return ", ".join(items)
    return ", ".join(items[:n]) + " and " + str(len(items) - n) + " more"


def render_page(out: dict) -> str:
    lines = ["<!-- case-study-timeline:start (" + GENERATED_BY + ") -->", "",
             "# Case study timeline", "",
             "> Every case study in the library on one timeline: the vulnerabilities, incidents, "
             "campaigns, threat actors, years and attack surfaces they cover, each with the dated "
             "events its own timeline records. Filter by years, kind or sector, find a study by its "
             "title, a CVE or an ATT&CK group, and share the filtered view by its link.", "",
             "Try a CVE such as CVE-2021-44228, a group ID such as G0016, or a word from a title. "
             "[All case studies](/case-studies/README.md) has the full table, with what each study "
             "covers and its sources.", "",
             '<div id="tsw-timeline" class="tsw-timeline-app"></div>', "",
             "## Studies by year <!-- {docsify-ignore} -->", "",
             "On GitHub, or without JavaScript, the timeline does not load; this list holds the same "
             "studies and events. Each study sits under the year its period starts, or the year its "
             "core period starts where the study names one. The entries are kept in "
             "[data/case_studies.yaml](" + BLOB + DATA + ") and built into "
             "[assets/case-studies.json](" + BLOB + JSON_OUT + ") by "
             "`scripts/build_case_study_timeline.py`."]
    kinds = {k["key"]: k["label"] for k in out["kinds"]}
    year = None
    for r in out["rows"]:
        if r["y"] != year:
            year = r["y"]
            lines += ["", "### " + str(year) + " <!-- {docsify-ignore} -->", ""]
        bits = [kinds[r["k"]] + ", " + period(r["s"], r["e"])]
        if r.get("cs"):
            bits[0] += " (core: " + period(r["cs"], r["ce"]) + ")"
        bits.append("Sectors: " + ", ".join(r["sec"]))
        if r["cve"]:
            bits.append("CVEs: " + capped(r["cve"]))
        if r["act"]:
            bits.append("ATT&CK groups: " + capped([g + " " + n for g, n in r["act"]]))
        downloads = []
        if r.get("pdf"):
            downloads.append("[PDF](" + r["pdf"] + ")")
        if r.get("pptx"):
            downloads.append("[Slides (PowerPoint)](" + r["pptx"] + ")")
        if downloads:
            bits.append("Download: " + ", ".join(downloads))
        lines.append("- [" + r["t"] + "](/" + r["p"] + "). " + ". ".join(bits) + ".")
        for d, label in r["ev"]:
            lines.append("  - " + human(d) + ": " + label)
    lines += ["", "<!-- case-study-timeline:list-end (the timeline replaces the list above on the site) -->", "",
              "ATT&CK&reg; and MITRE ATT&CK&reg; are registered trademarks of The MITRE Corporation. "
              "The group names come from the library's ATT&CK data; this project is not affiliated "
              "with or endorsed by MITRE.", "",
              "<!-- case-study-timeline:end -->"]
    return "\n".join(lines) + "\n"


def outputs() -> tuple[dict[str, str], list[str]]:
    files = tracked_files()
    data = load_data()
    groups = group_names()
    texts = {rel: read_text(rel) or "" for rel in studies(files)}
    problems = validate(data, files, texts, groups)
    if problems:
        return {}, problems
    out = build(data, groups)
    return {JSON_OUT: render_json(out), PAGE_OUT: render_page(out)}, []


# ----------------------------------------------------------------------------- self-test


def self_test() -> int:
    failures = []

    def expect(name, cond):
        if not cond:
            failures.append(name)

    expect("year", parse_date("2024") == (2024,))
    expect("month", parse_date("2024-02") == (2024, 2))
    expect("day", parse_date("2024-02-29") == (2024, 2, 29))
    expect("not a leap day", parse_date("2023-02-29") is None)
    expect("month 13", parse_date("2024-13") is None)
    expect("loose form", parse_date("2024-2-1") is None)
    expect("not a string", parse_date(2024) is None)
    expect("coarse order", not before((2026, 10), (2026, 10, 27)))
    expect("fine order", before((2026, 10, 17), (2026, 10, 27)))
    expect("year order", before((2025,), (2026, 1)))
    expect("high of a month", high((2024, 2)) == (2024, 2, 29))
    expect("human day", human("2021-12-09") == "9 December 2021")
    expect("period month range", period("2023-05", "2023-06") == "May to June 2023")
    expect("period same", period("2026-10", "2026-10") == "October 2026")
    expect("period ongoing", period("2024", None) == "From 2024, ongoing")
    expect("period mixed", period("2019-01", "2021") == "January 2019 to 2021")

    study = "# A Study\n\nCVE-2024-0001 and G0016 are named.\n"
    files = ["case-studies/A.md", "case-studies/README.md", "case-studies/pdf/A.pdf", "mitre/groups/G0016.md"]
    texts = {"case-studies/A.md": study}
    groups = {"G0016": "APT29"}

    def entry(**kw):
        e = {"kind": "incident", "title": "A Study", "start": "2024-01", "end": "2024-03",
             "sectors": ["energy"], "cves": ["CVE-2024-0001"], "actors": ["G0016"], "tags": ["x"],
             "pdf": "A.pdf", "events": [{"date": "2024-01-05", "label": "Start"},
                                        {"date": "2024-01", "label": "Same month"}]}
        e.update(kw)
        return {"sectors": ["energy", "finance"], "studies": {"case-studies/A.md": e}}

    def problems(d, f=files):
        return validate(d, f, texts, groups)

    expect("valid entry", problems(entry()) == [])
    expect("missing study", any("no entry for case-studies/B.md" in p
                                for p in problems(entry(), files + ["case-studies/B.md"])))
    expect("timeline page is not a study", problems(entry(), files + [PAGE_OUT]) == [])
    expect("bad kind", any("kind" in p for p in problems(entry(kind="breach"))))
    expect("bad title", any("H1" in p for p in problems(entry(title="Other"))))
    expect("bad date", any("start" in p for p in problems(entry(start="2024-1"))))
    expect("end before start", any("end comes before start" in p for p in problems(entry(end="2023"))))
    expect("ongoing", problems(entry(end=None)) == [])
    expect("half core", any("go together" in p for p in problems(entry(core_start="2024-02"))))
    expect("core outside", any("core period ends after" in p
                               for p in problems(entry(core_start="2024-02", core_end="2024-05"))))
    expect("bad sector", any("sector 'water'" in p for p in problems(entry(sectors=["water"]))))
    expect("cve shape", any("not a CVE id" in p for p in problems(entry(cves=["CVE-24-1"]))))
    expect("cve not named", any("not named" in p for p in problems(entry(cves=["CVE-2024-0002"]))))
    expect("unknown group", any("not a group" in p for p in problems(entry(actors=["G9999"]))))
    expect("group without a page", any("has no page" in p for p in problems(entry(), files[:-1])))
    expect("missing pdf", any("not a file" in p for p in problems(entry(pdf="B.pdf"))))
    expect("orphan export", any("belongs to no study" in p for p in problems(entry(pdf=None))))
    expect("event order", any("comes before" in p for p in problems(entry(events=[
        {"date": "2024-02", "label": "b"}, {"date": "2024-01-31", "label": "a"}]))))
    expect("too many events", any("at most" in p for p in problems(entry(events=[
        {"date": "2024-01", "label": "e"}] * (MAX_EVENTS + 1)))))
    expect("event shape", any("write it as" in p for p in problems(entry(events=[{"date": "2024"}]))))
    expect("em dash", any("em dash" in p for p in problems(entry(tags=["a " + EM_DASH + " b"]))))
    expect("unknown field", any("unknown fields" in p for p in problems(entry(year=2024))))
    try:
        parse_yaml("studies:\n  case-studies/A.md:\n    kind: incident\n", "planted")
        expect("YAML values are JSON", False)
    except Invalid:
        pass
    if failures:
        print("FAIL: " + ", ".join(failures))
        return 1
    print("OK: planted cases for the date and entry rules pass")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="fail if a committed file is stale or an entry is invalid")
    ap.add_argument("--self-test", action="store_true", help="run the planted cases")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    files, problems = outputs()
    if problems:
        print("FAIL: " + DATA + " has " + str(len(problems)) + " problem(s):")
        for p in problems:
            print("  " + p)
        return 1
    stale = [f for f, t in files.items() if read_text(f) != t]
    if args.check:
        if stale:
            print("FAIL: stale (run python scripts/build_case_study_timeline.py): " + ", ".join(stale))
            return 1
        print("OK: " + JSON_OUT + " and " + PAGE_OUT + " match " + DATA)
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
