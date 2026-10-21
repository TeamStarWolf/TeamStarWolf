#!/usr/bin/env python3
"""Write the cross-links between the hand-written and generated halves of the library.

The links are written into the Markdown itself, between markers, so they work on GitHub
and on the site alike. Four kinds:

    path-reference   on each learning path in docs/crosslinks.json "path_references"
                     (disciplines/<name>.md): a line under the introduction naming the
                     root reference, or two, that covers the same subject in depth
    related          on each root reference: a "Related pages" footer with its domain
                     hub, the learning path that names it, then the pages in its own
                     "Pairs with" row, then references in the same hub group that it
                     links to or that link to it (both ways first), filled from the same
                     group in hub order up to "related_min"; at most "related_max" lines.
                     When the page ends with its own related, see-also or further-reading
                     section (its last heading or a heading enclosing it, up to the H2,
                     subsections included), the footer leaves out every page that
                     section links (the domain hub and learning path included) and is
                     not filled up to "related_min", since the page has its own list;
                     when nothing is left the page gets no footer
    local-id-links   on each page in "local_id_pages": a "(local)" link after every
                     link to attack.mitre.org, capec.mitre.org, atlas.mitre.org or the
                     F3 site whose object has a page under mitre/
    library-refs     on each mitre/ object page that has any: a "Library references"
                     block with a line to the technique's section in the generated
                     detection strategy and technique detail pages
                     (detections/strategies/<tactic>.md, techniques/<tactic>.md) where it
                     has one, then the hand-written pages that link to the object's page
                     here or to its MITRE entry (pages with neither get no block)

The library-refs block on a mitre/ page sits above the page footer. generate_mitre_pages.py
carries a committed block over when it rewrites a page, so this script is the only writer
of the block and its --check the only drift guard for it.

What counts as a link: a Markdown link outside code, resolved the way the docsify site
resolves it (scripts/check_docsify_links.py). Hand-written pages are the ones
build_site_nav.py holds to the nav rule, less the about-the-repo root pages (README,
HOME, INDEX, CHANGELOG, ...) and docs/ (the style guides). The links this script writes
into references and learning paths are left out of the link graph it reads, so a run
never feeds on its own output; the "(local)" links are kept in it, because they are what
makes those three pages cite each object.

A tracked page that is missing from disk (for example a local antivirus quarantine of a
security reference) is read from the git index, as every check here does, and is not
written; the run says which.

Usage:
    python scripts/build_crosslinks.py            # write every block
    python scripts/build_crosslinks.py --check    # exit 1 when a committed block differs
    python scripts/build_crosslinks.py --report   # blocks and links per kind
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
import build_site_nav as bsn  # noqa: E402  (hubs, references, hand-written pages, labels)
import check_docsify_links as cdl  # noqa: E402  (link extraction, docsify routing)
from generate_technique_detail_pages import TACTIC_ORDER  # noqa: E402

CONFIG = "docs/crosslinks.json"
BY = "written by scripts/build_crosslinks.py"

PATH_START = "<!-- path-reference:start (" + BY + " from " + CONFIG + "; do not edit) -->"
PATH_END = "<!-- path-reference:end -->"
REL_START = "<!-- related:start (" + BY + "; do not edit) -->"
REL_END = "<!-- related:end -->"
LIB_START = "<!-- library-refs:start (" + BY + "; do not edit) -->"
LIB_END = "<!-- library-refs:end -->"
LOCAL_MARK = ("<!-- local-id-links (" + BY + " from " + CONFIG + "): the \"(local)\" link after "
              "a MITRE ID opens that object's page in this library. Edit the MITRE link; the "
              "script rewrites the \"(local)\" link. -->")

PATH_RE = re.compile(r"<!-- path-reference:start[^\n]*\n.*?<!-- path-reference:end -->\n(?:\n)?", re.S)
REL_RE = re.compile(r"\n*<!-- related:start[^\n]*\n.*?<!-- related:end -->\n", re.S)
LIB_RE = re.compile(r"\n*<!-- library-refs:start[^\n]*\n.*?<!-- library-refs:end -->\n", re.S)
LOCAL_MARK_RE = re.compile(r"^<!-- local-id-links [^\n]*-->\n(?:\n)?", re.M)
LOCAL_LINK_RE = re.compile(r" \(\[local\]\(/mitre/[^()\s]+\.md\)\)")
# The header card build_doc_meta.py writes; of it, only the orientation rows are read.
META_RE = re.compile(r"<!-- meta:start[^\n]*\n(.*?)<!-- meta:end -->", re.S)
CARD_ROW_RE = re.compile(r"^\|\s*(Read this when|Start at|Pairs with)\s*\|")

# A trailing sign-off ("---" then one italic line) stays last; the footer goes above it.
SIGNOFF_RE = re.compile(r"\n---[ \t]*\n\n\*[^\n]*\*[ \t]*\n*\Z")
# The mitre/ page footer ("---" then the italic source and trademark line).
MITRE_FOOTER_RE = re.compile(r"\n---[ \t]*\n\n\*Source:[^\n]*\n*\Z")
# A heading, and the heading text that makes a page's trailing section its own related list.
HEADING_RE = re.compile(r"^(#{2,6})[ \t]+(.*?)[ \t#]*$")
OWN_RELATED_RE = re.compile(r"\b(related|see also|further reading)\b", re.I)

# The generated pages with a section per ATT&CK technique (an <a id> under each heading),
# linked from the technique's Library references block: (folder, line label).
SECTION_PAGES = (("detections/strategies/", "Detection strategy"), ("techniques/", "Technique detail"))
SECTION_ID_RE = re.compile(r'^<a id="t(\d{4})(\d{3})?"></a>[ \t]*$', re.M)

# Root pages that are not content: chrome, the front door and the about-the-repo pages.
NOT_CITING = set(bsn.ROOT_META)
NOT_CITING_PREFIX = ("docs/",)

TACTIC_PAGE = {ta: slug for slug, _name, ta in TACTIC_ORDER}

# External MITRE URL -> (family, id). Only the object URLs; matrices, resources and the
# like are not objects.
EXT_RULES = [
    ("technique", re.compile(r"^https?://attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?/?(?:[?#].*)?$")),
    ("tactic", re.compile(r"^https?://attack\.mitre\.org/tactics/(TA\d{4})/?(?:[?#].*)?$")),
    ("group", re.compile(r"^https?://attack\.mitre\.org/groups/(G\d{4})/?(?:[?#].*)?$")),
    ("software", re.compile(r"^https?://attack\.mitre\.org/software/(S\d{4})/?(?:[?#].*)?$")),
    ("campaign", re.compile(r"^https?://attack\.mitre\.org/campaigns/(C\d{4})/?(?:[?#].*)?$")),
    ("mitigation", re.compile(r"^https?://attack\.mitre\.org/mitigations/(M\d{4})/?(?:[?#].*)?$")),
    ("capec", re.compile(r"^https?://capec\.mitre\.org/data/definitions/(\d+)\.html(?:[?#].*)?$")),
    ("atlas", re.compile(r"^https?://atlas\.mitre\.org/(?:techniques|mitigations)/(AML\.[TM]\d{4}(?:\.\d{3})?)/?(?:[?#].*)?$")),
    ("f3", re.compile(r"^https?://ctid\.mitre\.org/fightfraud/#/technique/([FT]\d{4}(?:\.\d{3})?)$")),
]


# ----------------------------------------------------------------------------- inputs


def load_config() -> dict:
    text = read_text(CONFIG)
    if text is None:
        raise SystemExit(CONFIG + ": not found")
    cfg = json.loads(text)
    if not 1 <= cfg["related_min"] <= cfg["related_max"]:
        raise SystemExit(CONFIG + ": need 1 <= related_min <= related_max")
    return cfg


def ext_page(url: str, tracked: set[str]) -> str | None:
    """An external MITRE object URL -> the mitre/ page for that object, if there is one."""
    for fam, rx in EXT_RULES:
        m = rx.match(url)
        if not m:
            continue
        if fam == "technique":
            tid = m.group(1) + ("-" + m.group(2) if m.group(2) else "")
            page = "mitre/techniques/" + tid + ".md"
        elif fam == "tactic":
            slug = TACTIC_PAGE.get(m.group(1))
            page = "mitre/tactics/" + slug + ".md" if slug else None
        elif fam == "capec":
            page = "mitre/capec/CAPEC-" + m.group(1) + ".md"
        elif fam == "atlas":
            page = "mitre/atlas/" + m.group(1).replace(".", "-") + ".md"
        elif fam == "f3":
            page = "mitre/f3/" + m.group(1) + ".md"
            if page not in tracked and m.group(1).startswith("T"):
                page = "mitre/techniques/" + m.group(1).replace(".", "-") + ".md"
        else:
            page = "mitre/" + {"group": "groups", "software": "software", "campaign": "campaigns",
                               "mitigation": "mitigations"}[fam] + "/" + m.group(1) + ".md"
        return page if page in tracked else None
    return None


def local_target(href: str, aliases: dict) -> str | None:
    """A non-external Markdown href -> the repo file the docsify site opens, or None."""
    if href.startswith("#/"):
        path, _ = cdl.split_href(href[1:])
    elif href.startswith("#"):
        return None
    else:
        path, _ = cdl.split_href(href)
    if not path:
        return None
    target, kind = cdl.route_to_file("/" + path, aliases)
    return None if kind else target


def links_of(text: str):
    """Yield (line index, start, end, href) for every Markdown link outside code. Start and
    end index the raw line (inline code is blanked to spaces, so offsets line up)."""
    for ln, line, in_fence, _raw in cdl.code_free_lines(text):
        if in_fence or not line.strip():
            continue
        for m in cdl.LINK_RE.finditer(line):
            if m.group(1) == "!":
                continue
            yield ln - 1, m.start(), m.end(), m.group(2).strip()


def strip_generated(text: str) -> str:
    """The page without the blocks this script writes (the link graph's input). The header
    card (scripts/build_doc_meta.py) keeps only its hand-written orientation rows (Read this
    when, Start at, Pairs with): its learning-path, review and "Which page should I read?"
    links are navigation that script writes, not the page's own links."""
    text = PATH_RE.sub("", text)
    text = REL_RE.sub("\n", text)
    text = LIB_RE.sub("\n", text)
    text = META_RE.sub(lambda m: "\n".join(ln for ln in m.group(1).split("\n") if CARD_ROW_RE.match(ln)), text)
    return text


# ----------------------------------------------------------------------------- placement


def place_path_block(text: str, block: str) -> str:
    """Above the first rule or H2 after the H1 (the end of the introduction)."""
    lines = text.split("\n")
    at = len(lines)
    seen_h1 = False
    for i, line in enumerate(lines):
        if not seen_h1:
            seen_h1 = line.startswith("# ")
            continue
        if re.match(r"^(---+\s*|## .*)$", line):
            at = i
            break
    head = "\n".join(lines[:at]).rstrip("\n")
    tail = "\n".join(lines[at:])
    return head + "\n\n" + block + "\n\n" + tail if tail else head + "\n\n" + block + "\n"


def place_footer(text: str, block: str, tail_re: re.Pattern) -> str:
    """Above a trailing sign-off or footer when the page has one, else at the end."""
    m = tail_re.search(text)
    if m:
        return text[:m.start()].rstrip("\n") + "\n\n" + block + "\n" + text[m.start():]
    return text.rstrip("\n") + "\n\n" + block + "\n"


def strip_library_refs(text: str) -> str:
    """A mitre/ page without its library-refs block (generate_mitre_pages.py reads the
    committed page through this, so the block never leaks into a carried-over section)."""
    return LIB_RE.sub("\n", text)


def carry_library_refs(old: str | None, new: str) -> str:
    """generate_mitre_pages.py: keep the committed page's block on the freshly rendered page."""
    if not old:
        return new
    m = LIB_RE.search(old)
    if not m:
        return new
    return place_footer(strip_library_refs(new), m.group(0).strip("\n"), MITRE_FOOTER_RE)


# ----------------------------------------------------------------------------- renderers


def label(rel: str, descs: dict) -> str:
    if rel in descs and descs[rel][0]:
        return descs[rel][0]
    return bsn.title(rel)


def path_block(refs: list[str], descs: dict) -> str:
    links = [bsn.md_link(label(r, descs), "/" + r) for r in refs]
    if len(links) == 1:
        line = "> Matching reference: " + links[0] + ", the library's in-depth page on this subject."
    else:
        line = ("> Matching references: " + ", ".join(links[:-1]) + " and " + links[-1]
                + ", the library's in-depth pages on this subject.")
    return PATH_START + "\n\n" + line + "\n\n" + PATH_END


def related_block(lines: list[str]) -> str:
    return REL_START + "\n\n## Related pages\n\n" + "\n".join("- " + x for x in lines) + "\n\n" + REL_END


def library_block(obj_id: str, sections: list[tuple[str, str, str]], citers: list[str], descs: dict) -> str:
    parts = []
    if sections:
        parts.append("\n".join("- " + kind + ": " + bsn.md_link(obj_id + " in " + h1, href)
                               for kind, h1, href in sections))
    if citers:
        items = sorted(((label(c, descs), c) for c in citers), key=lambda x: (x[0].lower(), x[1]))
        parts.append("Hand-written pages in this library that link to this page or to this object's "
                     "entry on the MITRE site:\n\n"
                     + "\n".join("- " + bsn.md_link(lab, "/" + c) for lab, c in items))
    return LIB_START + "\n\n## Library references\n\n" + "\n\n".join(parts) + "\n\n" + LIB_END


def with_local_links(text: str, tracked: set[str]) -> tuple[str, int]:
    """The page with a "(local)" link after each external MITRE object link that has a
    page here, and the marker line under the H1. Returns (text, links written)."""
    text = LOCAL_MARK_RE.sub("", text)
    text = LOCAL_LINK_RE.sub("", text)
    lines = text.split("\n")
    inserts = collections.defaultdict(list)
    for i, start, end, href in links_of(text):
        if not cdl.SCHEME_RE.match(href):
            continue
        page = ext_page(href, tracked)
        if page and not lines[i].lstrip().startswith("#"):      # a heading keeps its anchor
            inserts[i].append((end, " ([local](/" + page + "))"))
    n = 0
    for i, items in inserts.items():
        line = lines[i]
        for end, add in sorted(items, reverse=True):
            line = line[:end] + add + line[end:]
            n += 1
        lines[i] = line
    for i, line in enumerate(lines):
        if line.startswith("# "):
            if i + 1 < len(lines) and lines[i + 1] == "":
                lines[i + 2:i + 2] = [LOCAL_MARK, ""]
            else:
                lines[i + 1:i + 1] = ["", LOCAL_MARK, ""]
            break
    return "\n".join(lines), n


# ----------------------------------------------------------------------------- build


def build() -> tuple[dict[str, str], dict]:
    """Every page this script owns a block on -> its expected text, plus report numbers."""
    cfg = load_config()
    nav = bsn.load_config()
    files = tracked_files()
    tracked = set(files)
    aliases = cdl.load_aliases()
    descs = bsn.index_entries()
    refs = bsn.references(files)
    ref_set = set(refs)
    hand = [f for f in bsn.hand_written(files)
            if f not in NOT_CITING and not f.startswith(NOT_CITING_PREFIX)]
    stats = collections.Counter()
    out: dict[str, str] = {}
    current = {f: bsn.page_text(f) for f in set(hand) | ref_set}

    # config checks
    problems = []
    for p, rs in cfg["path_references"].items():
        if "disciplines/" + p + ".md" not in tracked:
            problems.append(CONFIG + ": learning path disciplines/" + p + ".md does not exist")
        if not 1 <= len(rs) <= 2:
            problems.append(CONFIG + ": " + p + " needs one or two references")
        for r in rs:
            if r not in ref_set:
                problems.append(CONFIG + ": " + p + " -> " + r + " is not a root reference")
    for f in cfg["local_id_pages"]:
        if f not in tracked:
            problems.append(CONFIG + ": local_id_pages entry " + f + " does not exist")
    if problems:
        raise SystemExit("\n".join(problems))

    # 1. local-id links (they change the link graph, so they come first)
    configured = set(cfg["local_id_pages"])
    for f in hand:
        t = current[f]
        if f in configured:
            t, n = with_local_links(t, tracked)
            stats["local links"] += n
            stats["local links in " + f] = n
        elif LOCAL_MARK_RE.search(t):            # no longer configured: take them out
            t = LOCAL_LINK_RE.sub("", LOCAL_MARK_RE.sub("", t))
        current[f] = t

    # 2. the link graph of the hand-written pages, without this script's own blocks
    out_links: dict[str, set[str]] = {}
    cites: dict[str, set[str]] = collections.defaultdict(set)
    for f in hand:
        body = strip_generated(current[f])
        targets = set()
        for _i, _s, _e, href in links_of(body):
            if cdl.SCHEME_RE.match(href):
                page = ext_page(href, tracked)
                if page:
                    cites[page].add(f)
                continue
            t = local_target(href, aliases)
            if t and t in tracked and t != f:
                targets.add(t)
                if t.startswith("mitre/"):
                    cites[t].add(f)
        out_links[f] = targets
    in_links: dict[str, set[str]] = collections.defaultdict(set)
    for f, ts in out_links.items():
        for t in ts:
            in_links[t].add(f)

    # 3. path-reference blocks on learning paths
    paths_of_ref: dict[str, list[str]] = collections.defaultdict(list)
    for p, rs in sorted(cfg["path_references"].items()):
        f = "disciplines/" + p + ".md"
        for r in rs:
            paths_of_ref[r].append(f)
        body = PATH_RE.sub("", current[f])
        current[f] = place_path_block(body, path_block(rs, descs))
        stats["path-reference blocks"] += 1
        if not any(r in out_links.get(f, set()) for r in rs):
            stats["paths that linked none of their references outside the block"] += 1
    for f in hand:
        if f.startswith("disciplines/") and posixpath.basename(f)[:-3] not in cfg["path_references"]:
            current[f] = PATH_RE.sub("", current[f])

    # 4. related footers on references
    hub_of: dict[str, tuple[dict, dict]] = {}
    for h in nav["hubs"]:
        for g in h["groups"]:
            for d in g["docs"]:
                hub_of[d] = (h, g)
    for r in refs:
        if r not in hub_of:
            raise SystemExit(r + ": in no hub (run build_site_nav.py --check)")
        h, g = hub_of[r]
        own_heading, own_links = own_related(strip_generated(current[r]), aliases)
        dropped: set[str] = set()
        fixed = []
        for kind, name, c in ([("Domain", h["title"], "hubs/" + h["slug"] + ".md")]
                              + [("Learning path", bsn.title(p), p) for p in paths_of_ref.get(r, [])]):
            if c in own_links:
                dropped.add(c)
            else:
                fixed.append(kind + ": " + bsn.md_link(name, "/" + c))
        room = cfg["related_max"] - len(fixed)
        picks: list[str] = []

        def add(c: str) -> None:
            if c in own_links:
                dropped.add(c)
                return
            if len(picks) < room and c != r and c not in picks and c in tracked and c.endswith(".md") \
                    and not posixpath.basename(c).startswith("_") and c not in paths_of_ref.get(r, []):
                picks.append(c)

        for c in pairs_with(strip_generated(current[r]), aliases):
            add(c)
        group = [d for d in g["docs"] if d != r]
        both = [d for d in group if d in out_links.get(r, set()) and r in out_links.get(d, set())]
        one = [d for d in group if d not in both and (d in out_links.get(r, set()) or r in out_links.get(d, set()))]
        for c in both + one:
            add(c)
        fill = group + [d for gg in h["groups"] if gg is not g for d in gg["docs"]]
        for c in ([] if own_heading else fill):
            if len(fixed) + len(picks) >= cfg["related_min"]:
                break
            add(c)
        if own_heading:
            stats["related footers under the page's own related section"] += 1
            stats["related footers under the page's own related section: links"] += len(fixed) + len(picks)
            stats["related footers under the page's own related section: domain and path only"] += bool(fixed) and not picks
            stats["related footers under the page's own related section: none left, no footer"] += not (fixed or picks)
            stats["related candidates left out because the page's own section links them"] += len(dropped)
        lines = fixed + [bsn.md_link(label(c, descs), "/" + c) for c in picks]
        body = REL_RE.sub("\n", current[r])
        if not lines:                     # the page's own section already links every one
            current[r] = body
            continue
        current[r] = place_footer(body, related_block(lines), SIGNOFF_RE)
        stats["related footers"] += 1
        stats["related links"] += len(lines)
    for f in hand:
        if f not in ref_set and REL_RE.search(current[f]):
            current[f] = REL_RE.sub("\n", current[f])

    for f, t in current.items():
        out[f] = t

    # 5. library-refs blocks on mitre/ object pages
    objects = [f for f in files if f.startswith("mitre/") and f.endswith(".md")
               and posixpath.basename(f) not in ("README.md", "_sidebar.md") and f != "mitre/crosswalk.md"]
    stats["mitre/ object pages"] = len(objects)
    sections = section_pages(files)
    for f in objects:
        text = bsn.page_text(f)
        body = strip_library_refs(text)
        citers = sorted(cites.get(f, set()))
        secs = sections.get(f, [])
        if citers or secs:
            obj_id = posixpath.basename(f)[:-3]
            if f.startswith("mitre/techniques/"):
                obj_id = obj_id.replace("-", ".")
            body = place_footer(body, library_block(obj_id, secs, citers, descs), MITRE_FOOTER_RE)
            stats["library-refs blocks"] += 1
            stats["library-refs links"] += len(citers) + len(secs)
            stats["library-refs links to hand-written pages"] += len(citers)
            stats["library-refs links to detection strategy or technique detail sections"] += len(secs)
            stats["library-refs blocks with a detection strategy line"] += any(
                k == "Detection strategy" for k, _h, _l in secs)
            stats["library-refs blocks with a technique detail line"] += any(
                k == "Technique detail" for k, _h, _l in secs)
            stats["library-refs blocks with no hand-written page"] += not citers
        out[f] = body
    stats["hand-written pages that cite a mitre/ object"] = len({c for cs in cites.values() for c in cs})
    return out, stats


def own_related(text: str, aliases: dict) -> tuple[str | None, set[str]]:
    """The page's own trailing related section: (its heading, the pages it links). The
    trailing section is the one that holds the page's last heading: that heading and each
    heading that encloses it, up to its H2. The outermost of those whose text names related
    pages, a see-also list or further reading is the page's own list, and its links are
    collected from the whole section, subsections included ("## Related Resources" with
    "### Internal" and "### External" under it counts). A trailing sign-off line does not
    end it."""
    body = SIGNOFF_RE.sub("\n", text)
    lines = body.split("\n")
    heads: list[tuple[int, int, str]] = []
    in_fence = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        m = None if in_fence else HEADING_RE.match(line)
        if m:
            heads.append((i, len(m.group(1)), m.group(2)))
    if not heads:
        return None, set()
    chain = [heads[-1]]
    for h in reversed(heads[:-1]):
        if chain[-1][1] == 2:
            break
        if h[1] < chain[-1][1]:
            chain.append(h)
    own = next((h for h in reversed(chain) if OWN_RELATED_RE.search(h[2])), None)
    if not own:
        return None, set()
    linked = set()
    for _i, _s, _e, href in links_of("\n".join(lines[own[0] + 1:])):
        if cdl.SCHEME_RE.match(href):
            continue
        t = local_target(href, aliases)
        if t:
            linked.add(t)
    return own[2], linked


def section_pages(files: list[str]) -> dict[str, list[tuple[str, str, str]]]:
    """mitre/techniques/<id>.md -> [(line label, page H1, link to the section)] for each
    generated tactic page that has a section on that technique."""
    out: dict[str, list[tuple[str, str, str]]] = collections.defaultdict(list)
    for folder, kind in SECTION_PAGES:
        for f in files:
            if not (f.startswith(folder) and f.count("/") == folder.count("/") and f.endswith(".md")
                    and posixpath.basename(f) not in ("README.md", "_sidebar.md")):
                continue
            text = bsn.page_text(f) or ""
            h1 = next((ln[2:].strip() for ln in text.split("\n") if ln.startswith("# ")), bsn.title(f))
            for m in SECTION_ID_RE.finditer(text):
                tid = "T" + m.group(1) + ("-" + m.group(2) if m.group(2) else "")
                anchor = "t" + m.group(1) + (m.group(2) or "")
                out["mitre/techniques/" + tid + ".md"].append((kind, h1, "/" + f + "#" + anchor))
    return out


def pairs_with(text: str, aliases: dict) -> list[str]:
    """The pages in a reference's "Pairs with" header row, in order."""
    out = []
    for line in text.split("\n"):
        if re.match(r"^\|\s*Pairs with\s*\|", line):
            for m in cdl.LINK_RE.finditer(line):
                href = m.group(2).strip()
                if cdl.SCHEME_RE.match(href):
                    continue
                t = local_target(href, aliases)
                if t and t not in out:
                    out.append(t)
            break
    return out


# ----------------------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="exit 1 when a committed block differs")
    mode.add_argument("--report", action="store_true", help="print blocks and links per kind")
    args = ap.parse_args()

    expected, stats = build()
    stale = []
    for f in sorted(expected):
        committed = read_text(f) or ""
        if committed != expected[f]:
            stale.append(f)

    if args.report:
        for k in sorted(stats):
            print(k + ": " + str(stats[k]))
        print("pages whose blocks differ from the committed copy: " + str(len(stale)))
        return 0

    if args.check:
        if stale:
            print("CROSS-LINK DRIFT: " + str(len(stale)) + (" page differs" if len(stale) == 1 else " pages differ")
                  + " from what "
                  "scripts/build_crosslinks.py writes. Run `python scripts/build_crosslinks.py` "
                  "and commit the result:")
            for f in stale[:100]:
                print("  stale    " + f)
            if len(stale) > 100:
                print("  ... and " + str(len(stale) - 100) + " more")
            return 1
        print("OK: cross-link blocks match (" + str(stats["path-reference blocks"]) + " learning-path, "
              + str(stats["related footers"]) + " related, " + str(stats["library-refs blocks"])
              + " library-refs blocks; " + str(stats["local links"]) + " local ID links)")
        return 0

    written = skipped = 0
    for f in stale:
        path = os.path.join(ROOT, f)
        if not os.path.exists(path):
            print("NOTE: " + f + " is tracked but missing from disk; not written (its expected text "
                  "differs from the git index copy)", file=sys.stderr)
            skipped += 1
            continue
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(expected[f])
        written += 1
    print("wrote " + str(written) + " pages" + (", skipped " + str(skipped) if skipped else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
