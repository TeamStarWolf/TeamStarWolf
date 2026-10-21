#!/usr/bin/env python3
"""Old-URL regression check: every route in scripts/old_urls.txt must still resolve.

Each line is a docsify route as readers and outside sites link to it: "#/PATH" or
"#/PATH?id=heading-slug". The route resolves when the page it names is a tracked Markdown
file (through the docsify aliases in index.html, the same way the site resolves it) and, for
"?id=", when that page still has a heading or HTML id with that slug under the docsify 4.13.1
slug rules. Resolution uses the functions of scripts/check_docsify_links.py, so the two checks
cannot disagree about a route.

The list was sampled from the sidebar and INDEX.md before the site revamp (commit 1234f86c).
Comment lines ("#" and a space) and blank lines are skipped; any other line is a route.

    python scripts/check_old_urls.py            check every route; exit 1 if one fails
    python scripts/check_old_urls.py --list     print each route and the file it reaches
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_docsify_links as links  # noqa: E402
from repo_files import read_text, tracked_files  # noqa: E402

LIST = os.path.join(links.ROOT, "scripts", "old_urls.txt")


def routes() -> list[str]:
    with open(LIST, encoding="utf-8") as f:
        return [s.strip() for s in f if s.strip() and not is_comment(s.strip())]


def is_comment(s: str) -> bool:
    """A comment line is '#' alone or '#' and a space; a route starts '#/'."""
    return s == "#" or s.startswith("# ")


def resolve(route: str, aliases: dict, tracked: set) -> tuple[str | None, str | None]:
    """'#/PATH?id=x' -> (file, problem); problem is None when the route resolves."""
    if not route.startswith("#/"):
        return None, "not a '#/' route"
    path, anchor = links.split_href(route[1:])
    f, kind = links.route_to_file(path, aliases)
    if kind or not f:
        return f, kind or "no file"
    if f not in tracked or read_text(f) is None:
        return f, "page missing"
    if anchor and anchor not in links.anchors_of(f):
        return f, "heading id '" + anchor + "' missing"
    return f, None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--list", action="store_true", help="print each route and the file it reaches")
    args = ap.parse_args()
    aliases = links.load_aliases()
    tracked = set(tracked_files())
    rs = routes()
    bad = []
    for r in rs:
        f, problem = resolve(r, aliases, tracked)
        if args.list:
            print(r + "  ->  " + str(f) + ("" if problem is None else "  (" + problem + ")"))
        if problem:
            bad.append((r, f, problem))
    anchors = sum(1 for r in rs if "?id=" in r)
    if bad:
        print("FAIL: " + str(len(bad)) + " of " + str(len(rs)) + " old routes no longer resolve:")
        for r, f, problem in bad:
            print("  " + r + "  ->  " + str(f) + ": " + problem)
        return 1
    print("OK: all " + str(len(rs)) + " old routes resolve (" + str(anchors) + " with a heading id)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
