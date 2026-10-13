#!/usr/bin/env python3
"""Check every internal link and anchor in the served Markdown the way the published
docsify site resolves it, and fail on any broken link that is not in the baseline.

Why not lychee for this: lychee resolves links the way GitHub does (relative to the
linking file, GitHub-style heading slugs). The site is docsify 4.13.1 with
`relativePath: false` served under /TeamStarWolf/, which differs in ways that matter
(each rule below was confirmed on the live site):

  * Every compiled Markdown link is a ROUTE resolved from the site root, not from the
    linking file: `[x](../FOO.md)` on techniques/bar.md becomes `#/../FOO`, which
    fetches https://teamstarwolf.github.io/FOO.md (outside the site) and 404s, and
    `[x](sibling.md)` on a page in a sub-directory resolves to /sibling.md.
  * A route that does not end in .md/.html gets ".md" appended, so a Markdown link to
    a data file (`[layer](navigator/x.json)`) becomes `#/navigator/x.json` and fetches
    navigator/x.json.md -> 404. Use an absolute GitHub URL or the `':ignore'` title.
  * Images are the exception: they resolve relative to the page's own directory.
  * Anchors use docsify's slugger, not GitHub's: the heading's rendered HTML is
    slugified, so "&" becomes "amp" ("A & B" -> "a-amp-b"), an apostrophe becomes "39",
    punctuation is dropped without collapsing to "--", a leading digit gets "_", and a
    repeated heading gets "-1", "-2".

The universe of files is `git ls-files` (what actions/checkout puts in the Pages
artifact; see repo_files.py), so an untracked local file never makes a link look valid.
Files under .github/ are not served by Pages and are skipped.

The anchor slugger reproduces docsify 4.13.1 + marked 1.x closely enough that, checked
against the live site's own compiler on 2026-10-13, it produced the identical id set for
331 of the 333 hand-written pages; the residue is marked's lazy-list handling of a fence
that directly follows a list line, where this script may accept an anchor the site lacks.

Pre-existing broken links are listed in scripts/baselines/docsify_links.json (one key
per file + kind + href, with a count). The check fails when a key is new or its count
grows, so the debt can only shrink; it reports, but does not fail on, baseline entries
that have since been fixed (rewrite the baseline with --update-baseline).

Usage:
    python scripts/check_docsify_links.py                    # gate (exit 1 on new breakage)
    python scripts/check_docsify_links.py --report           # list every broken link
    python scripts/check_docsify_links.py --update-baseline  # rewrite the baseline file
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import posixpath
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, "scripts", "baselines", "docsify_links.json")
SITE_BASE = "/TeamStarWolf"          # Pages project path; routes may not climb above it
HOMEPAGE = "HOME.md"                 # window.$docsify.homepage

KINDS = {
    "missing-target": "the routed page does not exist in the repository",
    "escapes-site-root": "the route climbs above the site root (`../` with relativePath: false) and 404s",
    "non-markdown-route": "a Markdown link to a non-.md file is routed to <file>.md and 404s",
    "missing-anchor": "the target page has no heading/id with this docsify slug",
    "missing-image": "the image file does not exist",
    "missing-html-target": "the raw-HTML href/src target does not exist",
}

# ----------------------------------------------------------------------------- files

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import read_text, tracked_files  # noqa: E402


def load_aliases() -> dict[str, str]:
    """Route aliases from index.html's window.$docsify.alias block."""
    html = read_text("index.html") or ""
    m = re.search(r"alias\s*:\s*\{(.*?)\}", html, re.S)
    if not m:
        return {}
    return dict(re.findall(r"""['"](/[^'"]*)['"]\s*:\s*['"](/[^'"]*)['"]""", m.group(1)))


# ----------------------------------------------------------------------------- markdown scanning

FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
INLINE_CODE_RE = re.compile(r"(`+)(?:(?!\1).)+?\1")
LINK_RE = re.compile(r"(!?)\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*<?([^()\s<>]*(?:\([^()\s]*\)[^()\s<>]*)*)>?"
                     r"(?:\s+(\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)")
REFDEF_RE = re.compile(r"^ {0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
HTML_ATTR_RE = re.compile(r"<(a|img)\b[^>]*?\b(href|src)\s*=\s*(\"[^\"]*\"|'[^']*')", re.I)
HTML_ID_RE = re.compile(r"""\s(?:id|name)\s*=\s*["']([^"']+)["']""", re.I)
ATX_RE = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$")
SETEXT_RE = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
SCHEME_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.\-]*:|//)")


def code_free_lines(text: str):
    """Yield (lineno, line, in_fence, raw) with inline code spans blanked in `line`."""
    fence = None
    for i, line in enumerate(text.split("\n"), 1):
        m = FENCE_RE.match(line)
        if fence is None and m:
            fence = m.group(1)[0] * len(m.group(1))
            yield i, "", True, line
            continue
        if fence is not None:
            # a closing fence is the same character, at least as long, and nothing after it
            if m and m.group(1).startswith(fence) and not line[m.end():].strip():
                fence = None
            yield i, "", True, line
            continue
        yield i, INLINE_CODE_RE.sub(lambda mm: " " * len(mm.group(0)), line), False, line


# ----------------------------------------------------------------------------- docsify slugs

SLUG_STRIP = re.compile("[\u2000-\u206f\u2e00-\u2e7f\\\\'!\"#$%&()*+,./:;<=>?@\\[\\]^`{|}~]")
ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);")


def _escape(s: str) -> str:
    # marked 1.x escape(): & < > " ' (existing entities are kept)
    s = re.sub(r"&(?!(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);)", "&amp;", s)
    return s.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def heading_html(raw: str) -> str:
    """Approximate marked's inline rendering of a heading, enough for slugging."""
    parts = []
    pos = 0
    for m in re.finditer(r"(`+)(.+?)\1|<[^>]+>", raw):
        parts.append(("md", raw[pos:m.start()]))
        if m.group(0).startswith("<"):
            parts.append(("html", m.group(0)))
        else:
            parts.append(("code", m.group(2).strip()))
        pos = m.end()
    parts.append(("md", raw[pos:]))
    out = []
    for kind, s in parts:
        if kind == "html":
            out.append(s)
        elif kind == "code":
            out.append("<code>" + _escape(s) + "</code>")
        else:
            s = re.sub(r"!\[[^\]]*\]\([^)]*\)", "<img>", s)               # images -> tag (dropped)
            s = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", s)                # links -> text
            s = re.sub(r"\[([^\]]*)\]\[[^\]]*\]", r"\1", s)               # reference links
            s = re.sub(r"(\*\*|__)(?=\S)(.+?)(?<=\S)\1", r"\2", s)        # strong
            s = re.sub(r"\*(?=\S)(.+?)(?<=\S)\*", r"\1", s)               # em (*)
            s = re.sub(r"(?<![\w])_(?=\S)(.+?)(?<=\S)_(?![\w])", r"\1", s)  # em (_)
            s = re.sub(r"~~(.+?)~~", r"\1", s)
            s = re.sub(r"\\([\\`*{}\[\]()#+\-.!_>~|])", r"\1", s)          # backslash escapes
            out.append(_escape(s))
    return "".join(out)


def docsify_slug(html: str, seen: dict) -> str:
    slug = re.sub(r"[A-Z]+", lambda m: m.group(0).lower(), html.strip())
    slug = re.sub(r"<[^>]+>", "", slug)
    slug = SLUG_STRIP.sub("", slug)
    slug = re.sub(r"\s", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    slug = re.sub(r"^(\d)", r"_\1", slug)
    count = seen.get(slug)
    count = 0 if count is None else count + 1
    seen[slug] = count
    return slug + "-" + str(count) if count else slug


_ANCHOR_CACHE: dict[str, set] = {}


def anchors_of(rel: str) -> set:
    if rel in _ANCHOR_CACHE:
        return _ANCHOR_CACHE[rel]
    text = read_text(rel) or ""
    ids: set = set()
    seen: dict = {}
    prev = prev_raw = None
    for _, line, in_fence, raw in code_free_lines(text):
        if in_fence:
            prev = None
            continue
        for tag in re.finditer(r"<[A-Za-z][^>]*>", line):
            for m in HTML_ID_RE.finditer(tag.group(0)):
                ids.add(m.group(1))
        m = ATX_RE.match(raw)
        title = None
        if m:
            title = m.group(2)
        elif prev is not None and prev.strip() and SETEXT_RE.match(raw) and not prev.lstrip().startswith(("|", ">", "-", "*", "#", "<")):
            title = prev_raw.strip()
        if title is not None:
            cfg = re.search(r"""\s*:id=([^\s'"]+)""", title)
            if cfg:
                ids.add(cfg.group(1))
                seen_slug = docsify_slug(heading_html(title[:cfg.start()]), seen)  # still counts
                del seen_slug
            else:
                ids.add(docsify_slug(heading_html(title), seen))
        prev, prev_raw = line, raw
    _ANCHOR_CACHE[rel] = ids
    return ids


# ----------------------------------------------------------------------------- resolution


def route_to_file(route: str, aliases: dict) -> tuple[str | None, str | None]:
    """docsify route path (leading '/') -> (repo-relative file, problem kind)."""
    joined = posixpath.normpath(SITE_BASE + "/" + route.lstrip("/")) if route.strip("/") else SITE_BASE
    if route.endswith("/") and not joined.endswith("/"):
        joined += "/"
    if not (joined == SITE_BASE or joined.startswith(SITE_BASE + "/")):
        return None, "escapes-site-root"
    path = "/" + joined[len(SITE_BASE):].lstrip("/")
    for src, dst in aliases.items():
        if path == src:
            path = dst
    if path == "/":
        return HOMEPAGE, None
    if path.endswith("/"):
        path += "README"
    if re.search(r"\.(md|html)$", path):
        f = path.lstrip("/")
    else:
        f = path.lstrip("/") + ".md"
        if re.search(r"\.[A-Za-z0-9]{1,5}$", path):
            return f, "non-markdown-route"
    return f, None


def split_href(href: str) -> tuple[str, str]:
    """'path?id=a#b' -> (path, anchor) the way docsify reads it."""
    anchor = ""
    if "#" in href:
        href, anchor = href.split("#", 1)
    if "?" in href:
        href, query = href.split("?", 1)
        m = re.search(r"(?:^|&)id=([^&]*)", query)
        if m:
            anchor = m.group(1)
    return href, anchor


def check(files: list[str]) -> list[tuple[str, int, str, str, str]]:
    tracked = set(files)
    aliases = load_aliases()
    served = [f for f in files if f.endswith(".md") and not f.startswith(".github/")]
    broken = []

    def anchor_ok(target: str, anchor: str) -> bool:
        from urllib.parse import unquote
        return not anchor or unquote(anchor) in anchors_of(target) or anchor in anchors_of(target)

    for rel in sorted(served):
        text = read_text(rel)
        if text is None:
            continue
        for ln, line, in_fence, _raw in code_free_lines(text):
            if in_fence or not line.strip():
                continue
            hits = [(m.group(1) == "!", m.group(2), m.group(3) or "") for m in LINK_RE.finditer(line)]
            m = REFDEF_RE.match(line)
            if m:
                hits.append((False, m.group(1), ""))
            for is_img, href, title in hits:
                href = href.strip()
                if not href or SCHEME_RE.match(href):
                    continue
                if is_img:
                    p, _ = split_href(href)
                    target = posixpath.normpath(p.lstrip("/") if p.startswith("/")
                                                else posixpath.join(posixpath.dirname(rel), p))
                    if target not in tracked:
                        broken.append((rel, ln, "missing-image", href, target))
                    continue
                if ":ignore" in title:   # left as a raw href: the browser resolves it from the site root
                    p, _ = split_href(href)
                    target = posixpath.normpath(p.lstrip("/"))
                    if p.startswith("/") or target not in tracked:
                        broken.append((rel, ln, "missing-html-target", href, target))
                    continue
                if href.startswith("#/"):
                    path, anchor = split_href(href[1:])
                elif href.startswith("#"):
                    path, anchor = "", href[1:]
                else:
                    if href == HOMEPAGE:
                        href = "README"
                    path, anchor = split_href(href)
                if path == "":
                    if posixpath.basename(rel) in ("_sidebar.md", "_navbar.md"):
                        continue   # shown on every page: a bare #anchor targets whichever page is open
                    target, kind = (HOMEPAGE if posixpath.basename(rel) == "_coverpage.md" else rel), None
                else:
                    target, kind = route_to_file("/" + path, aliases)
                if kind and kind != "non-markdown-route":
                    broken.append((rel, ln, kind, href, target or ""))
                    continue
                if kind == "non-markdown-route":
                    broken.append((rel, ln, kind, href, target))
                    continue
                if target not in tracked:
                    broken.append((rel, ln, "missing-target", href, target))
                    continue
                if anchor and target.endswith(".md") and not anchor_ok(target, anchor):
                    broken.append((rel, ln, "missing-anchor", href, target + "#" + anchor))
            for m in HTML_ATTR_RE.finditer(line):
                href = m.group(3)[1:-1].strip()
                if not href or SCHEME_RE.match(href) or href.startswith(("#", "mailto:")) and not href.startswith("#/"):
                    continue
                if href.startswith("#/"):
                    path, anchor = split_href(href[1:])
                    target, kind = route_to_file("/" + path, aliases)
                    if kind:
                        broken.append((rel, ln, kind, href, target or ""))
                    elif target not in tracked:
                        broken.append((rel, ln, "missing-target", href, target))
                    elif anchor and not anchor_ok(target, anchor):
                        broken.append((rel, ln, "missing-anchor", href, target + "#" + anchor))
                    continue
                p, _ = split_href(href)
                # raw HTML is not rewritten by docsify: the browser resolves it against the
                # document URL (the site root), so a leading "/" leaves the project path.
                target = posixpath.normpath(p.lstrip("/"))
                if p.startswith("/") or target.startswith("..") or target not in tracked:
                    broken.append((rel, ln, "missing-html-target", href, target))
    return broken


def key(b) -> str:
    return b[0] + "\t" + b[2] + "\t" + b[3]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--report", action="store_true", help="print every broken link, baselined or not")
    ap.add_argument("--update-baseline", action="store_true", help="rewrite " + os.path.relpath(BASELINE, ROOT))
    args = ap.parse_args()

    files = tracked_files()
    broken = check(files)
    counts = collections.Counter(key(b) for b in broken)
    by_kind = collections.Counter(b[2] for b in broken)
    n_files = len([f for f in files if f.endswith(".md") and not f.startswith(".github/")])

    if args.update_baseline:
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"_comment": "Known broken internal links (file\\tkind\\thref -> count). "
                                   "Written by scripts/check_docsify_links.py --update-baseline. "
                                   "Only ever shrink it: fix links, then rewrite.",
                       "links": dict(sorted(counts.items()))}, f, indent=1, ensure_ascii=False)
            f.write("\n")
        print("baseline written: " + str(sum(counts.values())) + " broken links in " +
              str(len({b[0] for b in broken})) + " files")
        return 0

    try:
        with open(BASELINE, encoding="utf-8") as f:
            base = collections.Counter(json.load(f).get("links", {}))
    except (OSError, ValueError):
        base = collections.Counter()

    new = [b for b in broken if counts[key(b)] > base.get(key(b), 0)]
    fixed = {k: base[k] - counts.get(k, 0) for k in base if counts.get(k, 0) < base[k]}

    if args.report:
        for b in broken:
            print(b[0] + ":" + str(b[1]) + ": " + b[2] + ": " + b[3] + "  ->  " + b[4])
    print("scanned " + str(n_files) + " served Markdown files: " + str(len(broken)) +
          " broken internal links (" + ", ".join(k + "=" + str(v) for k, v in sorted(by_kind.items())) +
          "); baseline allows " + str(sum(base.values())))
    if fixed:
        print("NOTE: " + str(sum(fixed.values())) + " baselined broken links are now fixed; "
              "shrink the baseline with --update-baseline")
    if new:
        print("FAIL: broken internal links not in the baseline:")
        seen = set()
        for b in new:
            if key(b) in seen:
                continue
            seen.add(key(b))
            print("  " + b[0] + ":" + str(b[1]) + ": " + b[2] + ": " + b[3] + "  ->  " + b[4] +
                  "  (" + KINDS[b[2]] + ")")
        return 1
    print("OK: no new broken internal links")
    return 0


if __name__ == "__main__":
    sys.exit(main())
