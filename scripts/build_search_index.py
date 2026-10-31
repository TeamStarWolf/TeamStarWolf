#!/usr/bin/env python3
"""Build the site search index: one Pagefind record per served Markdown page, plus ids.json
for the ID jump. Build output only: the deploy workflow (.github/workflows/pages.yml) runs
this into the Pages artifact, and the result is never committed.

    python scripts/build_search_index.py --site _site

writes
    _site/pagefind/   the Pagefind bundle (pagefind.js, the WASM, index and fragment chunks)
    _site/ids.json    framework ID -> docsify route, and exact object names -> IDs

The site is docsify, so there is no HTML to crawl. Each record is a Pagefind custom record
built from the Markdown: url is the docsify route (#/PATH), content is the page as plain
text, meta holds title, kind, section and a one-line summary, and kind and section are
also filters. The search overlay in index.html reads the bundle with Pagefind's JS API.

Which pages: every tracked .md file that docsify can route to, the same universe as
scripts/check_docsify_links.py, less the docsify chrome (_sidebar.md, _navbar.md,
_coverpage.md, _404.md) and .github/, which Pages does not serve.

ids.json: an ID typed into the overlay (T1059, t1059.001, T1059/001, G0016, S0154, C0024,
M1038, CAPEC-66, AML.T0051, F1002.001, D3-AL) opens its page directly. The IDs come from the
H1 of each generated mitre/ page ("# T1059: Command and Scripting Interpreter"); D3FEND
pages carry no ID in the H1, so their IDs come from data/attack/d3fend_countermeasures.jsonl
by name. Exact names of techniques, groups, software and campaigns map to IDs too ("apt29",
"cozy bear" -> G0016), from the page titles and the alias lists in
data/attack/*_profiles.jsonl.

Needs the pinned Pagefind Python package (scripts/requirements-search.txt). --ids-only
writes ids.json and checks the records without Pagefind installed.
"""
from __future__ import annotations

import argparse
import asyncio
import html
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_text, tracked_files  # noqa: E402

HOMEPAGE = "HOME.md"                       # index.html: homepage: 'HOME.md'
ALIASES = {"navigator/index.md": "navigator/"}   # index.html alias '/navigator/'
CHROME = {"_sidebar.md", "_navbar.md", "_coverpage.md", "_404.md"}
ROOT_ABOUT = {
    "README.md", "HOME.md", "INDEX.md", "ABOUT_THE_DATA.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md",
}
STUB_MARK = "This document has been superseded."
SUMMARY_MAX = 220
# Blocks the site hides (index.html CSS) but GitHub shows: not part of the page as read on
# the site, so neither searchable nor a summary. HOME.md opens with one.
SITE_HIDDEN_CLASSES = ("tsw-gh-only",)
# A metadata line at the top of a generated page: "Platforms: ...", "Type: tool",
# "Tactics (pre-v19, legacy): ...", "Successor's tactics (v19.2): ...". Not a summary.
META_LINE = re.compile(r"^[A-Z][A-Za-z0-9 &/'-]{0,40}(?:\([^()\n]{1,40}\))?:\s")

# The IDs the overlay must open directly; the build fails if any one is missing.
REQUIRED_IDS = ["T1059", "T1059.001", "G0016", "S0154", "C0024", "M1038", "CAPEC-66", "AML.T0051"]

# mitre/<folder>/ -> (kind, section prefix)
MITRE_KINDS = {
    "techniques": ("ATT&CK technique", "ATT&CK"),
    "tactics": ("ATT&CK tactic", "ATT&CK"),
    "groups": ("ATT&CK group", "ATT&CK"),
    "software": ("ATT&CK software", "ATT&CK"),
    "campaigns": ("ATT&CK campaign", "ATT&CK"),
    "mitigations": ("ATT&CK mitigation", "ATT&CK"),
    "capec": ("CAPEC", "CAPEC"),
    "d3fend": ("D3FEND", "D3FEND"),
    "atlas": ("ATLAS", "ATLAS"),
    "f3": ("F3", "F3"),
}
# top-level folder -> (kind, section)
FOLDER_KINDS = {
    "guides": ("Guide", "Guides"),
    "disciplines": ("Learning path", "Learning paths"),
    "techniques": ("Detection", "Technique detail"),
    "detections": ("Detection", "Detection library"),
    "tools": ("Tool", "Vendor tools"),
    "ai-tooling": ("Tool", "AI tooling"),
    "tools-research": ("Tool", "Tools research"),
    "case-studies": ("Case study", "Case studies"),
    "research": ("Research", "Research"),
    "data": ("Data", "Data"),
    "navigator": ("Data", "Navigator layers"),
    "scores": ("Data", "Coverage scores"),
    "docs": ("About", "Maintaining the library"),
    "hubs": ("Domain hub", "Domain hubs"),
    "scripts": ("About", "Maintaining the library"),
}

# Exact names (and, for groups, software and campaigns, every alias) that open a page
# directly: the names practitioners type ("APT29", "Cozy Bear", "Cobalt Strike",
# "PowerShell"). Long descriptive names (CAPEC, ATLAS, F3, D3FEND) are left to full-text
# search, which keeps ids.json small.
NAMED_FOLDERS = ("mitre/techniques/", "mitre/groups/", "mitre/software/", "mitre/campaigns/")

# The ID at the start of a generated page's H1, before the colon, per mitre/ folder. Only
# the folder's own ID family counts: mitre/f3/ also hosts the ATT&CK techniques F3 reuses
# (mitre/f3/T1070.md), and T1070 opens the ATT&CK page, not the F3 one.
ID_H1 = {
    "techniques": re.compile(r"^(T\d{4}(?:\.\d{3})?):\s+(.+)$"),
    "groups": re.compile(r"^(G\d{4}):\s+(.+)$"),
    "software": re.compile(r"^(S\d{4}):\s+(.+)$"),
    "campaigns": re.compile(r"^(C\d{4}):\s+(.+)$"),
    "mitigations": re.compile(r"^(M\d{4}):\s+(.+)$"),
    "capec": re.compile(r"^(CAPEC-\d+):\s+(.+)$"),
    "atlas": re.compile(r"^(AML\.[TM]\d{4}(?:\.\d{3})?):\s+(.+)$"),
    "f3": re.compile(r"^(F\d{4}(?:\.\d{3})?):\s+(.+)$"),
}


# ----------------------------------------------------------------------------- pages


def served_pages(files: list[str]) -> list[str]:
    return sorted(f for f in files
                  if f.endswith(".md") and not f.startswith(".github/")
                  and os.path.basename(f) not in CHROME)


def route_of(rel: str) -> str:
    """Repo path -> docsify route without the leading '#/' ('' is the homepage)."""
    if rel == HOMEPAGE:
        return ""
    if rel in ALIASES:
        return ALIASES[rel]
    if rel == "README.md":
        return "README"
    if rel.endswith("/README.md"):
        return rel[: -len("README.md")]
    return rel[:-3]


def strip_inline(s: str) -> str:
    """Markdown/HTML inline markup -> text."""
    s = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"\[([^\]]*)\]\[[^\]]*\]", r"\1", s)
    s = re.sub(r"<[^>\n]+>", " ", s)
    s = re.sub(r"(\*\*|__|`)", "", s)
    s = re.sub(r"(?<![\w*])\*(?!\s)([^*\n]+?)\*(?!\w)", r"\1", s)
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def without_hidden(text: str) -> str:
    """Drop every element whose class is in SITE_HIDDEN_CLASSES, with its content. Nested
    elements of the same tag are matched by depth. Applied to the raw Markdown, so it
    covers the HTML blocks pages embed, which is where these classes appear."""
    open_re = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*\bclass=\"[^\"]*\b(?:"
                         + "|".join(map(re.escape, SITE_HIDDEN_CLASSES)) + r")(?=[\s\"])[^\"]*\"[^>]*>")
    while True:
        m = open_re.search(text)
        if not m:
            return text
        tag = m.group(1).lower()
        tag_re = re.compile(r"<(/?)" + tag + r"\b[^>]*>", re.I)
        depth, end = 1, m.end()       # no closing tag: drop the opening tag only
        for t in tag_re.finditer(text, m.end()):
            depth += -1 if t.group(1) else 1
            if depth == 0:
                end = t.end()
                break
        text = text[:m.start()] + " " + text[end:]


def without_comments(text: str) -> str:
    """The page as the site shows it: no HTML comments, no site-hidden blocks."""
    return without_hidden(re.sub(r"<!--.*?-->", " ", text, flags=re.S))


def h1_of(text: str) -> str | None:
    """The first Markdown H1 outside code fences and HTML comments."""
    in_fence = False
    for line in without_comments(text).split("\n"):
        if re.match(r"^\s*(```|~~~)", line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r"^#\s+(.+?)(?:\s+#+)?\s*$", line)
        if m:
            return strip_inline(m.group(1))
    return None


def title_of(text: str, rel: str) -> str:
    h1 = h1_of(text)
    if h1:
        return h1
    if rel == HOMEPAGE:
        return "TeamStarWolf home"
    if rel == "README.md":
        return "TeamStarWolf README"
    base = os.path.basename(rel)[:-3]
    if base == "README" or base == "index":
        base = os.path.basename(os.path.dirname(rel)) or "TeamStarWolf"
    return re.sub(r"[_-]+", " ", base).strip().title()


def plain_text(text: str) -> str:
    """The page as searchable plain text. Code blocks stay (detection queries, commands and
    event IDs are things people search for); markup, URLs and link targets go."""
    t = without_comments(text)
    t = re.sub(r"^\s*(```|~~~)[^\n]*$", " ", t, flags=re.M)        # fence lines, keep code
    t = re.sub(r"<(script|style)\b.*?</\1>", " ", t, flags=re.S | re.I)
    t = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"^\s*\[[^\]]+\]:\s*\S+.*$", " ", t, flags=re.M)     # reference definitions
    t = re.sub(r"<https?://[^>\s]+>", " ", t)
    t = re.sub(r"https?://[^\s)<>\]|]+", " ", t)
    t = re.sub(r"<[^>\n]+>", " ", t)
    t = html.unescape(t)
    t = re.sub(r"^\s{0,3}(#{1,6}|>+|[-*+]|\d+[.)])\s+", " ", t, flags=re.M)
    t = re.sub(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$", " ", t, flags=re.M)
    t = re.sub(r"^\s*(-{3,}|\*{3,}|_{3,})\s*$", " ", t, flags=re.M)
    t = t.replace("|", " ")
    t = re.sub(r"(\*\*|__|`)", "", t)
    return re.sub(r"\s+", " ", t).strip()


META_BLOCK_RE = re.compile(r"<!--\s*meta:start\b.*?<!--\s*meta:end\s*-->", re.S)


def summary_of(text: str, title: str) -> str:
    """The first prose paragraph or blockquote after the H1, cut at a word boundary. The
    header card (scripts/build_doc_meta.py) is about the page, not its summary."""
    body = without_comments(META_BLOCK_RE.sub(" ", text))
    m = re.search(r"^#\s+.+$", body, flags=re.M)
    if m:
        body = body[m.end():]
    in_fence = False
    para: list[str] = []
    for line in body.split("\n"):
        s = line.strip()
        if re.match(r"^(```|~~~)", s):
            in_fence = not in_fence
            if para:
                break
            continue
        if in_fence:
            continue
        if not s:
            if para:
                break
            continue
        if s.startswith("<p") and strip_inline(s) and not para:
            s = strip_inline(s)                      # README.md centres its tagline in <p>
        if (s.startswith(("#", "|", "<", "---", "***", "- ", "* ", "+ ", "[![")) or " | " in s
                or re.match(r"^\d+[.)]\s", s) or META_LINE.match(s)):
            if para:
                break
            continue
        para.append(s.lstrip("> ").strip())
    out = strip_inline(" ".join(para))
    if out == title or len(out) < 25:
        return ""
    if len(out) > SUMMARY_MAX:
        out = out[:SUMMARY_MAX].rsplit(" ", 1)[0].rstrip(",;:") + "..."
    return out


def field(text: str, name: str) -> str:
    m = re.search(r"^" + re.escape(name) + r":\s*(.+?)\s*$", text, flags=re.M)
    return strip_inline(m.group(1)) if m else ""


def tactic_names() -> dict[str, str]:
    """ATT&CK tactic slug -> name, from the mitre/tactics/ page titles."""
    out = {}
    for f in tracked_files():
        if f.startswith("mitre/tactics/") and f.endswith(".md") and not f.endswith("README.md"):
            t = title_of(read_text(f) or "", f)
            out[os.path.basename(f)[:-3]] = re.sub(r"^Tactic:\s*", "", t)
    return out


def classify(rel: str, text: str, tactics: dict[str, str]) -> tuple[str, str]:
    parts = rel.split("/")
    if len(parts) == 1:
        if rel == "explore.md":
            return "Framework index", "MITRE frameworks"
        if rel in ROOT_ABOUT:
            return "About", "About the library"
        return "Reference", "Reference library"
    top = parts[0]
    if top == "mitre":
        if len(parts) == 2:
            return "Framework index", "MITRE frameworks"
        kind, prefix = MITRE_KINDS.get(parts[1], ("Framework index", "MITRE frameworks"))
        if parts[-1] == "README.md":
            return kind, prefix + " > Index"
        folder = parts[1]
        if folder == "techniques":
            # A technique revoked in v19.2 lists its own tactics as legacy, and its
            # successor's separately: show its own, marked as pre-v19.
            own, legacy = field(text, "Tactics"), field(text, "Tactics (pre-v19, legacy)")
            names = [tactics.get(s.strip(), s.strip().replace("-", " ").title())
                     for s in (own or legacy).split(",") if s.strip()]
            if not own:     # "Defense Evasion (renamed)" -> "Defense Evasion (pre-v19)"
                names = [re.sub(r"\s*\([^)]*\)$", "", n) for n in names]
            label = ", ".join(names) + (" (pre-v19)" if names and not own else "")
            return kind, prefix + (" > " + label if names else "")
        if folder == "tactics":
            return kind, prefix + " > Tactics"
        if folder == "groups":
            return kind, prefix + " > Groups"
        if folder == "software":
            typ = field(text, "Type")
            return kind, prefix + " > Software" + (" (" + typ + ")" if typ else "")
        if folder == "campaigns":
            return kind, prefix + " > Campaigns"
        if folder == "mitigations":
            return kind, prefix + " > Mitigations"
        if folder == "capec":
            ab = field(text, "Abstraction")
            return kind, prefix + (" > " + ab + " pattern" if ab else "")
        if folder == "d3fend":
            ta = field(text, "D3FEND tactic")
            return kind, prefix + (" > " + ta if ta else "")
        if folder == "atlas":
            if parts[-1].startswith("AML-M"):
                return kind, prefix + " > Mitigations"
            ta = field(text, "ATLAS tactics")
            names = [s.strip().replace("-", " ").title() for s in ta.split(",") if s.strip()]
            return kind, prefix + (" > " + ", ".join(names) if names else "")
        if folder == "f3":
            ta = field(text, "F3 tactics")
            return kind, prefix + (" > " + ta if ta else "")
        return kind, prefix
    kind, section = FOLDER_KINDS.get(top, ("Reference", top.replace("-", " ").capitalize()))
    if top == "detections" and len(parts) > 2 and parts[1] == "strategies":
        section = "Detection strategies"
    return kind, section


def build_records() -> list[dict]:
    tactics = tactic_names()
    records = []
    for rel in served_pages(tracked_files()):
        text = read_text(rel)
        if text is None:
            raise SystemExit("cannot read " + rel)
        title = title_of(text, rel)
        kind, section = classify(rel, text, tactics)
        if len(rel.split("/")) == 1 and kind == "Reference" and STUB_MARK in text[:600]:
            section = "Superseded"
        route = route_of(rel)
        body = plain_text(text)
        has_h1 = h1_of(text) is not None
        meta = {"title": title, "kind": kind, "section": section, "path": rel}
        summary = summary_of(text, title)
        if summary:
            meta["summary"] = summary
        records.append({
            "url": "#/" + route,
            # The H1 is part of the text; a page without one (HOME, README) gets its title
            "content": (body if has_h1 else title + ". " + body),
            "language": "en",
            "meta": meta,
            "filters": {"kind": [kind], "section": [section]},
        })
    return records


# ----------------------------------------------------------------------------- ids.json


def norm_name(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _jsonl(rel: str) -> list[dict]:
    text = read_text(rel) or ""
    return [json.loads(line) for line in text.split("\n") if line.strip()]


def build_ids(records: list[dict]) -> dict:
    ids: dict[str, str] = {}
    names: dict[str, list[str]] = {}

    def add_name(name: str, oid: str) -> None:
        k = norm_name(name)
        if not k or k == oid.lower():
            return
        lst = names.setdefault(k, [])
        if oid not in lst:
            lst.append(oid)

    d3_by_title: dict[str, str] = {}
    for r in records:
        rel = r["meta"]["path"]
        if not rel.startswith("mitre/") or rel.count("/") != 2 or rel.endswith("README.md"):
            continue
        title = r["meta"]["title"]
        route = r["url"][2:]
        pattern = ID_H1.get(rel.split("/")[1])
        m = pattern.match(title) if pattern else None
        if m:
            oid, name = m.group(1), m.group(2)
            if oid in ids and ids[oid] != route:
                raise SystemExit("ID " + oid + " has two pages: " + ids[oid] + ", " + route)
            ids[oid] = route
            if rel.startswith(NAMED_FOLDERS):
                add_name(name, oid)
        elif rel.startswith("mitre/d3fend/"):
            d3_by_title[norm_name(re.sub(r"^D3FEND:\s*", "", title))] = route
    for row in _jsonl("data/attack/d3fend_countermeasures.jsonl"):
        route = d3_by_title.get(norm_name(row.get("name", "")))
        if route and row.get("d3fend_id"):
            ids[row["d3fend_id"]] = route
    for rel, key in (("data/attack/group_profiles.jsonl", "group_id"),
                     ("data/attack/software_profiles.jsonl", "software_id"),
                     ("data/attack/campaign_profiles.jsonl", "campaign_id")):
        for row in _jsonl(rel):
            oid = row.get(key)
            if oid not in ids:
                continue
            for a in [row.get("name", "")] + list(row.get("aliases") or []):
                add_name(a, oid)
    missing = [i for i in REQUIRED_IDS if i not in ids]
    if missing:
        raise SystemExit("ids.json is missing required IDs: " + ", ".join(missing))
    return {
        "version": 1,
        "ids": dict(sorted(ids.items())),
        "names": {k: v for k, v in sorted(names.items())},
    }


# ----------------------------------------------------------------------------- Pagefind


def _fast_service_poll() -> None:
    """Pagefind's Python service (1.5.2) sleeps a fixed 100 ms before reading each response,
    which caps it at about ten records a second, so a full build took six minutes. Its read
    already waits for data, so the sleep only adds latency. Give that one module a copy of
    asyncio whose sleep yields instead; nothing else in the process is affected."""
    import types

    import pagefind.service as service

    shim = types.ModuleType("asyncio_shim")
    shim.__dict__.update(vars(asyncio))
    shim.sleep = lambda delay, result=None: asyncio.sleep(0, result)
    service.asyncio = shim


async def write_pagefind(records: list[dict], out: str) -> None:
    from pagefind.index import IndexConfig, PagefindIndex  # pinned in requirements-search.txt

    _fast_service_poll()
    config = IndexConfig(output_path=out, write_playground=False)
    async with PagefindIndex(config=config) as index:
        batch = 64
        for i in range(0, len(records), batch):
            await asyncio.gather(*(index.add_custom_record(**r) for r in records[i:i + batch]))


def dir_stats(path: str) -> tuple[int, int, dict[str, int]]:
    files = total = 0
    per: dict[str, int] = {}
    for d, _, fs in os.walk(path):
        for f in fs:
            n = os.path.getsize(os.path.join(d, f))
            files += 1
            total += n
            sub = os.path.relpath(d, path).replace(os.sep, "/").split("/")[0]
            per[sub] = per.get(sub, 0) + 1
    return files, total, per


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--site", required=True, help="site root to write pagefind/ and ids.json into")
    ap.add_argument("--ids-only", action="store_true", help="write ids.json only (no Pagefind)")
    ap.add_argument("--records", help="also write the records as JSON Lines to this file (debugging)")
    args = ap.parse_args()

    t0 = time.time()
    records = build_records()
    ids = build_ids(records)
    os.makedirs(args.site, exist_ok=True)
    with open(os.path.join(args.site, "ids.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(ids, f, ensure_ascii=False, separators=(",", ":"))
    if args.records:
        with open(args.records, "w", encoding="utf-8", newline="\n") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    kinds: dict[str, int] = {}
    for r in records:
        kinds[r["meta"]["kind"]] = kinds.get(r["meta"]["kind"], 0) + 1
    summary = {
        "records": len(records),
        "kinds": dict(sorted(kinds.items(), key=lambda kv: -kv[1])),
        "ids": len(ids["ids"]),
        "names": len(ids["names"]),
        "ids_json_bytes": os.path.getsize(os.path.join(args.site, "ids.json")),
    }
    if not args.ids_only:
        out = os.path.join(args.site, "pagefind")
        asyncio.run(write_pagefind(records, out))
        if not os.path.isfile(os.path.join(out, "pagefind.js")):
            raise SystemExit("Pagefind wrote no pagefind.js into " + out)
        files, total, per = dir_stats(out)
        summary.update({"pagefind_files": files, "pagefind_bytes": total,
                        "index_chunks": per.get("index", 0), "fragments": per.get("fragment", 0)})
    summary["seconds"] = round(time.time() - t0, 1)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
