#!/usr/bin/env python3
"""Guard the lowercase-kebab route aliases against silent collisions.

The site (index.html) builds a pretty-URL alias for every SCREAMING_SNAKE route at
runtime from assets/site-nav.json: it lowercases the last path segment and turns "_"
into "-", so #/ACTIVE_DIRECTORY_ATTACK_REFERENCE also answers at
#/active-directory-attack-reference. The resolver is collision-safe by construction
(it never shadows a real route and the first claimant of an alias wins), which means a
collision fails *silently*: if two different canonical pages reduce to the same kebab
form, one of them keeps its pretty URL and the other simply never gets one, with no
error anywhere. Pages are added continuously, so this check makes that silent case a
CI failure instead.

It mirrors the resolver in index.html exactly:

  route_of(f) = f without its trailing ".md"
  real        = { route_of(f) for every page }
  for each page (a basename of README is skipped, as in the site):
    k = route with its LAST segment lowercased and "_" -> "-"
    - k == route            -> already pretty, no alias
    - k in real             -> the kebab is itself a real page; the resolver leaves the
                               SCREAMING page without a kebab alias (safe, reported as a
                               note, not a failure: the real lowercase page owns the URL)
    - otherwise             -> k is an alias target; TWO pages reaching the same k is the
                               silent collision this check fails on

Usage:
  check_kebab_aliases.py            # check assets/site-nav.json, exit 1 on a collision
  check_kebab_aliases.py --check    # same (explicit)
  check_kebab_aliases.py --self-test  # run the built-in cases, exit 1 if any fail

The universe of pages is assets/site-nav.json (the generated nav the site actually
reads), so the guard sees exactly what the browser would.
"""

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NAV = os.path.join(HERE, os.pardir, "assets", "site-nav.json")


def route_of(f):
    return re.sub(r"\.md$", "", f, flags=re.IGNORECASE)


def kebab(route):
    seg = route.split("/")
    seg[-1] = seg[-1].lower().replace("_", "-")
    return "/".join(seg)


def analyse(files):
    """Return (aliases, shadows, collisions) for a list of page file names.

    aliases    : dict k -> route, the aliases the resolver would create
    shadows    : list of (route, k) where k is itself a real route (no alias made)
    collisions : dict k -> sorted[routes], where >1 page reaches the same alias k
    """
    real = {route_of(f) for f in files}
    claimants = {}   # k -> list of routes that would claim k as their alias
    shadows = []
    for f in files:
        route = route_of(f)
        base = route.split("/")[-1]
        if re.fullmatch(r"README", base, re.IGNORECASE):
            continue
        k = kebab(route)
        if k == route:
            continue
        if k in real:
            shadows.append((route, k))
            continue
        claimants.setdefault(k, []).append(route)
    aliases = {k: v[0] for k, v in claimants.items() if len(v) == 1}
    collisions = {k: sorted(v) for k, v in claimants.items() if len(v) > 1}
    return aliases, shadows, collisions


def load_pages(path):
    with open(path, encoding="utf-8") as fh:
        nav = json.load(fh)
    return list((nav.get("pages") or {}).keys())


def run_check(path):
    files = load_pages(path)
    aliases, shadows, collisions = analyse(files)
    print(
        "kebab aliases: %d pages, %d aliases, %d shadowed by a real lowercase route"
        % (len(files), len(aliases), len(shadows))
    )
    if not collisions:
        print("OK: no two pages collide on a lowercase-kebab alias")
        return 0
    print(
        "FAIL: %d lowercase-kebab alias(es) are claimed by more than one page, so only "
        "one of each pair keeps its pretty URL:" % len(collisions),
        file=sys.stderr,
    )
    for k in sorted(collisions):
        print("  #/%s  <=  %s" % (k, ", ".join(collisions[k])), file=sys.stderr)
    print(
        "Fix: rename one of each colliding pair so their last path segments differ by "
        "more than letter case or underscores-vs-hyphens.",
        file=sys.stderr,
    )
    return 1


def self_test():
    cases = []

    def check(name, cond):
        cases.append((name, bool(cond)))

    # A genuine collision: two SCREAMING pages whose kebab forms are identical.
    _, _, col = analyse(["NETWORK_ATTACKS.md", "Network-Attacks.md"])
    check("collision detected for NETWORK_ATTACKS vs Network-Attacks",
          col.get("network-attacks") == ["NETWORK_ATTACKS", "Network-Attacks"])

    # A clean set: distinct kebab forms, no collision.
    al, sh, col = analyse(["CVE_REFERENCE.md", "CLOUD_ATTACK_REFERENCE.md"])
    check("no false collision on distinct pages", col == {})
    check("aliases created for the two distinct pages", len(al) == 2)
    check("cve alias maps to its canonical route",
          al.get("cve-reference") == "CVE_REFERENCE")

    # README is skipped, as in the site.
    al, _, _ = analyse(["README.md", "guides/README.md"])
    check("README pages are skipped", al == {})

    # An already-pretty page needs no alias and is not a collision.
    al, _, col = analyse(["commands/aws-cli.md"])
    check("already-kebab page gets no alias", al == {} and col == {})

    # A SCREAMING page whose kebab equals a real lowercase page is a shadow, not a
    # collision, and makes no alias (the real page owns the URL).
    al, sh, col = analyse(["NETWORK_ATTACKS.md", "network-attacks.md"])
    check("kebab matching a real route is a shadow, not a collision", col == {})
    check("shadow makes no alias for the SCREAMING page", "network-attacks" not in al)
    check("shadow is recorded", ("NETWORK_ATTACKS", "network-attacks") in sh)

    # Only the last segment is kebabbed; directory parts are untouched.
    al, _, _ = analyse(["platforms/AWS_LAMBDA.md"])
    check("only the last segment is lowercased",
          al.get("platforms/aws-lambda") == "platforms/AWS_LAMBDA")

    ok = True
    for name, passed in cases:
        print(("  ok   " if passed else "  FAIL ") + name)
        ok = ok and passed
    print("self-test: %d/%d passed" % (sum(p for _, p in cases), len(cases)))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="check assets/site-nav.json (the default action)")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in cases instead of checking the corpus")
    ap.add_argument("--nav", default=NAV, help="path to site-nav.json")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return run_check(args.nav)


if __name__ == "__main__":
    sys.exit(main())
