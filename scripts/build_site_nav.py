#!/usr/bin/env python3
"""Build the site navigation from docs/site_nav.json.

Writes, from the config and the pages themselves:

    _sidebar.md                 the root sidebar: a few short sections (Start, Domains,
                                Frameworks, ...) instead of one link per page
    _navbar.md                  the top bar
    <folder>/_sidebar.md        nested sidebars for guides/, disciplines/, tools/,
                                ai-tooling/ and mitre/, each opening with the same
                                "Library" block of ways back
    hubs/README.md, hubs/*.md   the domain hubs: each lists its references with a one-line
                                summary and a reading time, then the learning paths, guides
                                and framework pages that go with them
    assets/site-nav.json        the breadcrumb trail of every hand-written page, read by the
                                breadcrumb plugin in index.html
    index.html                  the docsify alias block (between the nav-aliases markers),
                                so a page in a folder without a sidebar of its own loads the
                                nearest one directly instead of 404ing on the missing files

Titles come from each page's H1. A reference's summary is its line in INDEX.md, or else
the first sentence of the page's opening paragraph. Reading time is the page's words
(code blocks, comments, script-written blocks and link targets left out) at 230 words a
minute. A guide's time
and level come from its own header table, as on the homepage.

Rules the --check run enforces (CI, validate-data.yml):
  * the committed files match what this script writes;
  * every root reference (a root .md page that is not chrome, an about-the-repo page or a
    superseded stub) is in exactly one hub, and every hub entry exists;
  * every hand-written page is in a nav section: linked from a sidebar, the navbar or a
    hub, or from a folder landing page (a README.md that one of those links to) in its
    own folder. docs/site_nav.json "not_in_nav" lists the exceptions, each with a reason.

Usage:
    python scripts/build_site_nav.py            # write every file above
    python scripts/build_site_nav.py --check    # exit 1 on drift or a nav-coverage gap
    python scripts/build_site_nav.py --report   # link counts and clicks from the homepage
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import posixpath
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_text, tracked_files  # noqa: E402
import build_search_index as bsi  # noqa: E402  (title, summary and comment helpers)
import build_home_guides as bhg  # noqa: E402  (a guide's Time and Difficulty header)
import check_docsify_links as cdl  # noqa: E402  (link extraction, docsify routing)

CONFIG = "docs/site_nav.json"
INDEX_HTML = "index.html"
CRUMBS = "assets/site-nav.json"
HOMEPAGE = "HOME.md"
WPM = 230
GENERATED_BY = "written by scripts/build_site_nav.py from docs/site_nav.json; do not edit"
# Pages other generators own: not hand-written, so not held to the nav-coverage rule
# (each is reached through its family index, Explore and search).
GENERATED = ("mitre/", "techniques/", "detections/strategies/", "scores/", "navigator/index.md",
             "hubs/")
GENERATED_FILES = {"explore.md"}
# Root pages that are not references (same set as build_stats.py, plus Explore).
ROOT_META = {
    "README.md", "HOME.md", "INDEX.md", "ABOUT_THE_DATA.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md",
    "explore.md",
}
ALIAS_RE = re.compile(r"(// nav-aliases:start[^\n]*\n)(.*?)(\n[ \t]*// nav-aliases:end)", re.S)


# ----------------------------------------------------------------------------- inputs


def load_config() -> dict:
    text = read_text(CONFIG)
    if text is None:
        raise SystemExit(CONFIG + ": not found")
    return json.loads(text)


def page_text(rel: str) -> str:
    text = read_text(rel)
    if text is None:
        raise SystemExit(rel + ": not found")
    return text


def file_of(target: str) -> str | None:
    """A nav target ('/', '/X.md', '/folder/', '/X.md?id=a') -> repo file, None if external."""
    if cdl.SCHEME_RE.match(target):
        return None
    path = target.split("?", 1)[0].split("#", 1)[0]
    if path == "/":
        return HOMEPAGE
    if path == "/navigator/":
        return "navigator/index.md"
    if path.endswith("/"):
        return path.lstrip("/") + "README.md"
    return path.lstrip("/")


def route(rel: str) -> str:
    """Repo file -> docsify route without '#/' (the form the breadcrumbs link to)."""
    return bsi.route_of(rel)


def is_stub(rel: str) -> bool:
    return bsi.STUB_MARK in (read_text(rel) or "")[:600]


def references(files: list[str]) -> list[str]:
    return sorted(f for f in files if f.endswith(".md") and "/" not in f and not f.startswith("_")
                  and f not in ROOT_META and not is_stub(f))


def hand_written(files: list[str]) -> list[str]:
    out = []
    for f in files:
        if not f.endswith(".md") or f.startswith(".github/") or f.startswith(GENERATED):
            continue
        if f in GENERATED_FILES or posixpath.basename(f).startswith("_"):
            continue
        out.append(f)
    return sorted(out)


def title(rel: str) -> str:
    return bsi.title_of(page_text(rel), rel)


def index_entries() -> dict[str, tuple[str, str]]:
    """INDEX.md's (label, one-line description) of each page, keyed by repo path."""
    out = {}
    for line in (read_text("INDEX.md") or "").split("\n"):
        m = re.match(r"^\|\s*\[([^\]]+)\]\(([^)\s]+)\)\s*\|\s*(.+?)\s*\|\s*$", line)
        if m and not cdl.SCHEME_RE.match(m.group(2)):
            out[m.group(2).lstrip("/")] = (bsi.strip_inline(m.group(1)),
                                           bsi.strip_inline(m.group(3).replace("\\|", "|")))
    return out


def first_sentence(text: str) -> str:
    m = re.match(r"(.+?[.!?])(?:\s+[A-Z(\"]|$)", text)
    s = m.group(1) if m else text
    if len(s) > 240:
        s = s[:240].rsplit(" ", 1)[0].rstrip(",;:") + "..."
    return s


def summary(rel: str, descs: dict) -> str:
    if rel in descs and descs[rel][1]:
        return descs[rel][1]
    text = page_text(rel)
    return first_sentence(bsi.summary_of(text, bsi.title_of(text, rel)))


SCRIPT_BLOCK_RE = re.compile(r"<!--\s*([\w-]+):start\b.*?<!--\s*\1:end\s*-->", re.S)
LOCAL_ID_LINK_RE = re.compile(r" \(\[local\]\(/mitre/[^()\s]+\.md\)\)")


def word_count(text: str) -> int:
    # Script-written blocks (the "Related pages" footer from build_crosslinks.py and the
    # like) and its "(local)" links after MITRE IDs are navigation, not reading, so they
    # never move a reading time.
    t = bsi.without_comments(LOCAL_ID_LINK_RE.sub("", SCRIPT_BLOCK_RE.sub(" ", text)))
    t = re.sub(r"^\s*(```|~~~).*?^\s*\1[^\n]*$", " ", t, flags=re.S | re.M)
    t = re.sub(r"!\[([^\]]*)\]\([^)]*\)", " ", t)
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"https?://\S+", " ", t)
    t = re.sub(r"<[^>\n]+>", " ", t)
    return len(re.findall(r"[A-Za-z0-9][\w'.-]*", t))


def reading_time(rel: str) -> str:
    return str(max(1, round(word_count(page_text(rel)) / WPM))) + " min"


def cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").strip()


def landing_order(landing: str, folder: str) -> list[str]:
    """The pages of `folder` (not its subfolders), in the order the landing page links
    them, then any it does not link, A to Z by title."""
    files = [f for f in tracked_files() if f.startswith(folder + "/") and f.endswith(".md")
             and "/" not in f[len(folder) + 1:] and not posixpath.basename(f).startswith("_")
             and f != landing]
    order = []
    for m in re.finditer(r"\]\((/[^)\s]+)\)", page_text(landing)):
        f = file_of(m.group(1))
        if f in files and f not in order:
            order.append(f)
    rest = sorted((f for f in files if f not in order), key=lambda f: title(f).lower())
    return order + rest


# ----------------------------------------------------------------------------- renderers


def md_link(label: str, target: str) -> str:
    return "[" + label.replace("[", "(").replace("]", ")") + "](" + target + ")"


def sidebar(name: str, sections: list[tuple[str, list[tuple[str, str]]]]) -> str:
    out = ["<!-- " + name + ": " + GENERATED_BY + " -->", ""]
    for i, (label, links) in enumerate(sections):
        if i:
            out += ["", "---", ""]
        out.append("- " + label)
        out += ["  - " + md_link(lab, tgt) for lab, tgt in links]
    return "\n".join(out) + "\n"


def hub_target(h: dict) -> str:
    return "/hubs/" + h["slug"] + ".md"


def root_sidebar(cfg: dict) -> str:
    sections = []
    for s in cfg["sections"]:
        if s.get("hubs"):
            sections.append((s["label"], [(h["title"], hub_target(h)) for h in cfg["hubs"]]))
        else:
            sections.append((s["label"], [tuple(x) for x in s["links"]]))
    return sidebar("_sidebar.md", sections)


def navbar(cfg: dict) -> str:
    out = ["<!-- _navbar.md: " + GENERATED_BY + " -->", ""]
    out += ["- " + md_link(lab, tgt) for lab, tgt in cfg["navbar"]]
    return "\n".join(out) + "\n"


def frameworks_links(cfg: dict) -> list[tuple[str, str]]:
    for s in cfg["sections"]:
        if s["label"] == "Frameworks":
            return [tuple(x) for x in s["links"] if x[1] != "/explore.md"]
    raise SystemExit(CONFIG + ": no Frameworks section")


def nested_sidebars(cfg: dict) -> dict[str, str]:
    header = ("Library", [tuple(x) for x in cfg["library_header"]])
    out = {}
    for n in cfg["nested"]:
        lead = [tuple(x) for x in n.get("lead", [])]
        if n.get("fixed") == "Frameworks":
            links = lead + frameworks_links(cfg)
        else:
            seen = {file_of(t) for _, t in lead} | {file_of(t) for _, t in header[1]}
            links = lead + [(title(f), "/" + f) for f in landing_order(n["landing"], n["folder"])
                            if f not in seen]
        sections = [header, (n["label"], links)]
        if n.get("sub"):
            s = n["sub"]
            sections.append((s["label"], [(title(f), "/" + f) for f in landing_order(s["landing"], s["folder"])]))
        out[n["folder"] + "/_sidebar.md"] = sidebar(n["folder"] + "/_sidebar.md", sections)
    return out


# The words a guide's Difficulty cell may open with, so the hub tables read as one scale.
# A qualifier may follow after a colon ("Advanced: decisions under pressure").
DIFFICULTY_LEVELS = ("Beginner", "Beginner to intermediate", "Intermediate",
                     "Intermediate to advanced", "Advanced")


def difficulty(guide: str, raw: str) -> str:
    text = bhg.plain(raw).strip()
    level = text.split(":", 1)[0].strip()
    if level not in DIFFICULTY_LEVELS:
        raise SystemExit("guides/" + guide + ".md: Difficulty '" + text + "' does not open with one of: "
                         + ", ".join(DIFFICULTY_LEVELS))
    return text


def hub_page(h: dict, descs: dict) -> str:
    docs = [d for g in h["groups"] for d in g["docs"]]
    out = ["<!-- hub:start (" + GENERATED_BY + ") -->", "",
           "# " + h["title"], "",
           "> " + h["summary"], "",
           "Part of the [domain hubs](/hubs/README.md). " + str(len(docs)) + " reference "
           + ("document" if len(docs) == 1 else "documents") + " in this domain; reading time "
           "is the page's words at " + str(WPM) + " words a minute.", ""]
    for g in h["groups"]:
        out += ["## " + g["heading"], "", "| Reference | What it covers | Reading time |", "|---|---|---|"]
        for d in g["docs"]:
            label = descs[d][0] if d in descs else title(d)
            out.append("| " + md_link(cell(label), "/" + d) + " | " + cell(summary(d, descs))
                       + " | " + reading_time(d) + " |")
        out.append("")
    if h.get("paths"):
        out += ["## Learning paths", ""]
        out += ["- " + md_link(title("disciplines/" + p + ".md"), "/disciplines/" + p + ".md") for p in h["paths"]]
        out.append("")
    if h.get("guides"):
        out += ["## How-to guides", "", "Time and difficulty are quoted in full from each guide's header table.", "",
                "| Guide | Time | Difficulty |", "|---|---|---|"]
        for g in h["guides"]:
            hd = bhg.header(g)
            out.append("| " + md_link(cell(hd["title"]), "/guides/" + g + ".md") + " | "
                       + cell(bhg.plain(hd["time"])) + " | " + cell(difficulty(g, hd["level"])) + " |")
        out.append("")
    if h.get("see_also"):
        out += ["## See also", ""]
        out += ["- " + md_link(lab, tgt) for lab, tgt in h["see_also"]]
        out.append("")
    out += ["<!-- hub:end -->"]
    return "\n".join(out) + "\n"


def hubs_index(cfg: dict) -> str:
    out = ["<!-- hub:start (" + GENERATED_BY + ") -->", "",
           "# Domains", "",
           "> The reference documents, grouped by domain. Each domain page lists its references "
           "with a one-line summary and a reading time, then the learning paths, how-to guides "
           "and framework pages that go with them.", "",
           "| Domain | What it covers | References |", "|---|---|---|"]
    for h in cfg["hubs"]:
        n = sum(len(g["docs"]) for g in h["groups"])
        out.append("| " + md_link(h["title"], hub_target(h)) + " | " + cell(h["summary"]) + " | " + str(n) + " |")
    out += ["", "Every reference A to Z: the [reference index](/INDEX.md). The framework objects that have a "
            "page, in one filterable table: [Explore](/explore.md).", "", "<!-- hub:end -->"]
    return "\n".join(out) + "\n"


def crumbs(cfg: dict, nav_pages: set[str]) -> str:
    """Breadcrumb parents of each hand-written page in the nav: its hub for a reference,
    else the landing pages of the folders it sits in."""
    hub_of = {}
    for h in cfg["hubs"]:
        for g in h["groups"]:
            for d in g["docs"]:
                hub_of[d] = (h["title"], route("hubs/" + h["slug"] + ".md"))
    parents = sorted(cfg["crumb_parents"].items(), key=lambda kv: len(kv[0]))
    pages = {}
    for rel in sorted(nav_pages):
        if rel == HOMEPAGE:
            continue
        chain = []
        if rel in hub_of:
            chain.append(list(hub_of[rel]))
        for prefix, (label, target) in parents:
            f = file_of(target)
            if rel.startswith(prefix) and f != rel:
                chain.append([label, route(f)])
        pages[rel] = chain
    return json.dumps({"_about": "Breadcrumb parents per page, " + GENERATED_BY, "pages": pages},
                      indent=0, sort_keys=True, ensure_ascii=False).replace("\n", "") + "\n"


def alias_block(cfg: dict, indent: str) -> str:
    nested = [n["folder"] for n in cfg["nested"]]
    deep = [f for f in nested if f in ("mitre", "ai-tooling")]
    lines = [
        "// navigator/ ships index.md, not README.md; without this, /navigator/ 404s",
        "'/navigator/': '/navigator/index',",
        "// A folder without a sidebar of its own uses the nearest one, without first",
        "// requesting (and 404ing on) the missing _sidebar.md and _navbar.md files",
    ]
    for f in deep:
        lines.append("'/" + f + "/.+/_sidebar.md': '/" + f + "/_sidebar.md',")
    lines.append("'/(?!" + "|".join(f + "/" for f in nested) + ").+/_sidebar.md': '/_sidebar.md',")
    lines.append("'/.+/_navbar.md': '/_navbar.md'")
    return "\n".join(indent + x for x in lines)


def with_aliases(html: str, cfg: dict) -> str:
    m = ALIAS_RE.search(html)
    if not m:
        raise SystemExit(INDEX_HTML + ": no '// nav-aliases:start' ... '// nav-aliases:end' block")
    indent = re.match(r"[ \t]*", m.group(2)).group(0) if m.group(2) else "        "
    return html[:m.start(2)] + alias_block(cfg, indent) + html[m.end(2):]


HOME_RE = re.compile(r"(<!-- domains:start[^>]*-->\n)(.*?)(<!-- domains:end -->)", re.S)


def html_esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def hash_route(target: str) -> str:
    """'/X.md' -> '#/X' (raw-HTML hrefs on HOME.md use the hash form, no .md)."""
    f = file_of(target)
    return "#/" + route(f)


def with_home_domains(text: str, cfg: dict) -> str:
    m = HOME_RE.search(text)
    if not m:
        raise SystemExit(HOMEPAGE + ": no '<!-- domains:start ... -->' ... '<!-- domains:end -->' block")
    rows = ['<div class="tsw-domains">']
    for h in cfg["hubs"]:
        links = ['<a class="tsw-domain-t" href="' + hash_route(hub_target(h)) + '">' + html_esc(h["title"]) + "</a>"]
        links += ['<a href="' + hash_route(t) + '">' + html_esc(lab) + "</a>" for lab, t in h.get("home", [])]
        rows.append('  <div class="tsw-domain">' + " ".join(links) + "</div>")
    rows.append("</div>")
    return text[:m.start(2)] + "\n".join(rows) + "\n" + text[m.end(2):]


# ----------------------------------------------------------------------------- build + checks


def build(cfg: dict) -> dict[str, str]:
    descs = index_entries()
    files = {"_sidebar.md": root_sidebar(cfg), "_navbar.md": navbar(cfg)}
    files.update(nested_sidebars(cfg))
    files["hubs/README.md"] = hubs_index(cfg)
    for h in cfg["hubs"]:
        files["hubs/" + h["slug"] + ".md"] = hub_page(h, descs)
    covered, _ = coverage(files)
    hand = set(hand_written(tracked_files())) | {"explore.md"}
    nav_pages = {p for p in covered if p in hand} | {f for f in files if f.startswith("hubs/")}
    files[CRUMBS] = crumbs(cfg, nav_pages)
    return files


def links_in(text: str) -> list[str]:
    out = []
    for _ln, line, in_fence, _raw in cdl.code_free_lines(text):
        if in_fence:
            continue
        for m in cdl.LINK_RE.finditer(line):
            if m.group(1) != "!":
                out.append(m.group(2).strip())
        for m in cdl.HTML_ATTR_RE.finditer(line):
            href = m.group(3)[1:-1].strip()
            if href.startswith("#/"):
                out.append(href[1:])
    return out


def target_file(href: str, aliases: dict) -> str | None:
    if not href or cdl.SCHEME_RE.match(href) or href.startswith("#") and not href.startswith("#/"):
        return None
    if href.startswith("#/"):
        href = href[1:]
    path, _ = cdl.split_href(href)
    if path == "":
        return None
    f, kind = cdl.route_to_file("/" + path, aliases)
    return None if kind else f


def coverage(gen: dict[str, str]) -> tuple[set[str], set[str]]:
    """(pages linked from a nav file or from a folder landing page in their folder,
    the landing pages). Nav files: the sidebars, the navbar and the hubs."""
    aliases = cdl.load_aliases()
    nav = [t for f, t in gen.items() if f.endswith("_sidebar.md") or f.endswith("_navbar.md")
           or f.startswith("hubs/")]
    direct = set()
    for text in nav:
        for href in links_in(text):
            f = target_file(href, aliases)
            if f:
                direct.add(f)
    landings = {f for f in direct if posixpath.basename(f) == "README.md"}
    covered = set(direct)
    for land in landings:
        folder = posixpath.dirname(land)
        text = gen[land] if land in gen else read_text(land)
        if text is None:
            continue
        for href in links_in(text):
            f = target_file(href, aliases)
            if f and folder and f.startswith(folder + "/"):
                covered.add(f)
    return covered, landings


def problems(cfg: dict, gen: dict[str, str]) -> list[str]:
    files = tracked_files()
    tracked = set(files)
    out = []
    # hubs: every reference in exactly one hub; every entry real
    seen = collections.Counter(d for h in cfg["hubs"] for g in h["groups"] for d in g["docs"])
    refs = references(files)
    for d, n in seen.items():
        if n > 1:
            out.append(CONFIG + ": " + d + " is in " + str(n) + " hubs (one only)")
        if d not in refs:
            out.append(CONFIG + ": hub entry " + d + " is not a root reference document")
    for d in refs:
        if d not in seen:
            out.append(CONFIG + ": reference " + d + " is in no hub")
    for h in cfg["hubs"]:
        for p in h.get("paths", []):
            if "disciplines/" + p + ".md" not in tracked:
                out.append(CONFIG + ": hub " + h["slug"] + ": no learning path disciplines/" + p + ".md")
        for g in h.get("guides", []):
            if "guides/" + g + ".md" not in tracked:
                out.append(CONFIG + ": hub " + h["slug"] + ": no guide guides/" + g + ".md")
        own = {"/" + d for g in h["groups"] for d in g["docs"]} | {t for _, t in h.get("see_also", [])}
        for _, t in h.get("home", []):
            if t not in own:
                out.append(CONFIG + ": hub " + h["slug"] + ": home link " + t + " is not one of its references or see_also pages")
        for _, t in h.get("see_also", []):
            if file_of(t) and file_of(t) not in tracked:
                out.append(CONFIG + ": hub " + h["slug"] + ": see-also target " + t + " does not exist")
    for f, text in gen.items():
        for t in re.findall(r"\]\((/[^)\s]*)\)", text):
            fl = file_of(t)
            if fl and fl not in tracked and fl not in gen:
                out.append(f + ": link target " + t + " does not exist")
    # every hand-written page in a nav section
    covered, _ = coverage(gen)
    exempt = cfg.get("not_in_nav", {})
    for p in hand_written(files):
        if p in covered or p in exempt or is_stub(p):
            continue
        out.append(p + ": hand-written page in no nav section (link it from docs/site_nav.json, "
                   "a hub, or its folder's README.md, or list it under not_in_nav with a reason)")
    for p in exempt:
        if p not in tracked:
            out.append(CONFIG + ": not_in_nav entry " + p + " does not exist")
    return out


def block_edits(cfg: dict) -> list[tuple[str, str, object]]:
    """Generated blocks inside hand-written files: (file, what, text -> text)."""
    return [(INDEX_HTML, "nav-aliases block", lambda t: with_aliases(t, cfg)),
            (HOMEPAGE, "Browse by domain cards", lambda t: with_home_domains(t, cfg))]


def drift(gen: dict[str, str], cfg: dict) -> list[str]:
    out = []
    for f, text in sorted(gen.items()):
        cur = read_text(f)
        if cur != text:
            out.append(f + (" is missing" if cur is None else " is stale"))
    for f in tracked_files():
        if f.startswith("hubs/") and f not in gen:
            out.append(f + " is an orphan: no hub in " + CONFIG + " writes it")
    for f, what, edit in block_edits(cfg):
        cur = read_text(f) or ""
        if edit(cur) != cur:
            out.append(f + ": the " + what + " is stale")
    return out


def write(gen: dict[str, str], cfg: dict) -> None:
    for f, text in sorted(gen.items()):
        if os.path.exists(os.path.join(ROOT, f)) and read_text(f) == text:
            continue
        p = os.path.join(ROOT, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print("wrote " + f)
    keep = set(gen)
    for f in tracked_files():
        if f.startswith("hubs/") and f not in keep and os.path.exists(os.path.join(ROOT, f)):
            os.remove(os.path.join(ROOT, f))
            print("removed " + f)
    for f, what, edit in block_edits(cfg):
        p = os.path.join(ROOT, f)
        with open(p, "rb") as fh:
            raw = fh.read().decode("utf-8")
        crlf = "\r\n" in raw          # keep the checkout's line endings
        text = raw.replace("\r\n", "\n")
        new = edit(text)
        if new != text:
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(new.replace("\n", "\r\n") if crlf else new)
            print("wrote " + f + " " + what)


# ----------------------------------------------------------------------------- report


def count_links(text: str) -> int:
    return len(re.findall(r"\]\(", text))


def sidebar_for(rel: str, gen: dict[str, str], cfg: dict) -> str:
    """The sidebar docsify shows on a page, after the alias rules."""
    folder = rel.split("/", 1)[0] if "/" in rel else ""
    nested = {n["folder"] for n in cfg["nested"]}
    if folder in nested:
        return gen[folder + "/_sidebar.md"]
    return gen["_sidebar.md"]


def click_depths(gen: dict[str, str], cfg: dict) -> dict[str, int]:
    """Fewest clicks from the homepage to every served page, where each page offers its
    body links, its sidebar and the navbar."""
    aliases = cdl.load_aliases()
    served = [f for f in tracked_files() if f.endswith(".md") and not f.startswith(".github/")
              and not posixpath.basename(f).startswith("_")]
    for f in gen:
        if f.endswith(".md") and not posixpath.basename(f).startswith("_") and f not in served:
            served.append(f)
    chrome_cache: dict[str, list[str]] = {}

    def out_links(rel: str) -> list[str]:
        text = gen.get(rel) if rel in gen else read_text(rel)
        side = sidebar_for(rel, gen, cfg)
        if side not in chrome_cache:
            chrome_cache[side] = [x for x in (target_file(h, aliases) for h in links_in(side + "\n" + gen["_navbar.md"])) if x]
        body = [x for x in (target_file(h, aliases) for h in links_in(text or "")) if x]
        return body + chrome_cache[side]

    depth = {HOMEPAGE: 0}
    queue = collections.deque([HOMEPAGE])
    while queue:
        cur = queue.popleft()
        for nxt in out_links(cur):
            if nxt not in depth:
                depth[nxt] = depth[cur] + 1
                queue.append(nxt)
    return {f: depth.get(f, -1) for f in served}


def report(cfg: dict, gen: dict[str, str]) -> None:
    root, nav = gen["_sidebar.md"], gen["_navbar.md"]
    labels = len(re.findall(r"^- [^\[]", root, flags=re.M))
    print("root sidebar: " + str(count_links(root)) + " links in " + str(labels) + " sections")
    print("navbar: " + str(count_links(nav)) + " links")
    print("phone layout (navbar merged into the sidebar): " + str(count_links(root) + count_links(nav))
          + " links, " + str(count_links(root) + count_links(nav) + labels) + " items with the section labels")
    for f in sorted(gen):
        if f.endswith("/_sidebar.md"):
            print(f + ": " + str(count_links(gen[f])) + " links")
    d = click_depths(gen, cfg)
    hand = set(hand_written(tracked_files())) | {f for f in gen if f.startswith("hubs/")} | {"explore.md"}
    for name, group in (("hand-written", [f for f in d if f in hand]),
                        ("generated", [f for f in d if f not in hand])):
        vals = [d[f] for f in group]
        reach = [v for v in vals if v >= 0]
        hist = collections.Counter(reach)
        print(name + " pages: " + str(len(vals)) + ", clicks from the homepage: "
              + ", ".join(str(k) + ": " + str(hist[k]) for k in sorted(hist))
              + ("; unreachable: " + str(len(vals) - len(reach)) if len(reach) < len(vals) else ""))
        far = sorted((f for f in group if d[f] == max(reach or [0])))[:5]
        print("  deepest: " + ", ".join(far))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="fail on drift or a nav-coverage gap")
    ap.add_argument("--report", action="store_true", help="print link counts and click depths")
    args = ap.parse_args()
    cfg = load_config()
    gen = build(cfg)
    probs = problems(cfg, gen)
    if args.report:
        report(cfg, gen)
        return 0
    if args.check:
        probs += drift(gen, cfg)
        if probs:
            print("FAIL: site navigation (fix docs/site_nav.json or the pages, then run "
                  "python scripts/build_site_nav.py):")
            for p in probs:
                print("  - " + p)
            return 1
        print("OK: navigation, hubs, breadcrumbs and aliases match " + CONFIG
              + "; every hand-written page is in a nav section")
        return 0
    if probs:
        print("FAIL:")
        for p in probs:
            print("  - " + p)
        return 1
    write(gen, cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
