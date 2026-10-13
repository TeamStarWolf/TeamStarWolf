#!/usr/bin/env python3
"""Repository hygiene gates that no single generator owns. Three checks:

1. junk     Fail if git tracks build/editor/OS junk (__pycache__/, *.pyc, venv/,
            node_modules/, .vs/, .idea/, .DS_Store, local DBs, the generator's old
            mitre/_gen_check/ scratch tree, the STIX cache). Everything tracked is
            published by pages-deploy.yml, so junk in git is junk on the site.

2. encoding Fail if a tracked text file is not valid UTF-8, contains U+FFFD (a lossy
            decode happened somewhere), or contains double-encoded UTF-8 ("mojibake":
            UTF-8 bytes decoded as cp1252/latin-1 and re-encoded, which turns an em-dash
            into the three characters a-circumflex, euro sign, right-quote). PR-15 cleaned
            the six affected pages; this keeps the class from coming back.

3. revoked  Report every revoked or deprecated ATT&CK ID (data/attack/superseded_by.jsonl)
            that a hand-written page still cites, and fail when a page cites one MORE
            often than scripts/baselines/revoked_ids.json allows. Generated trees are
            excluded (their generators already re-key through superseded_by and CI diffs
            them against the data); so is a line that also names the replacement ID or
            says the old one is revoked/deprecated/superseded/formerly/retired (history
            and migration notes are legitimate). The baseline is a ratchet: it records
            the pre-existing citations so the gate starts green, and may only shrink.

Usage:
    python scripts/check_repo_hygiene.py                    # all three gates
    python scripts/check_repo_hygiene.py --only encoding    # one gate (junk|encoding|revoked)
    python scripts/check_repo_hygiene.py --report           # also list every baselined citation
    python scripts/check_repo_hygiene.py --update-baseline  # rewrite the revoked-ID baseline
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_bytes, tracked_files  # noqa: E402

BASELINE = os.path.join(ROOT, "scripts", "baselines", "revoked_ids.json")

# ----------------------------------------------------------------------------- 1. junk
JUNK_RE = re.compile(
    r"(^|/)(__pycache__|\.?venv|env|node_modules|\.vs|\.idea|\.vscode|\.claude|\.pytest_cache|\.mypy_cache)/"
    r"|\.py[cod]$|(^|/)\.DS_Store$|(^|/)Thumbs\.db$|(^|/)Desktop\.ini$|\.(sqlite3?|db)$"
    r"|^mitre/_gen_check/|(^|/)\.stix-cache-[^/]*$|\.(suo|user|swp)$|~$")


def check_junk(files: list[str]) -> list[str]:
    return [f + ": tracked junk (remove it with `git rm --cached` and keep .gitignore covering it)"
            for f in files if JUNK_RE.search(f)]


# ----------------------------------------------------------------------------- 2. encoding
TEXT_EXT = (".md", ".json", ".jsonl", ".svg", ".py", ".yml", ".yaml", ".html", ".csv", ".cff",
            ".txt", ".js", ".css", ".gitignore", ".lycheeignore", ".nojekyll")
TEXT_NAMES = ("LICENSE",)
# Written with escapes so this file never matches itself. Each alternative is what a
# UTF-8 multi-byte sequence looks like after being misread as cp1252/latin-1:
#   C3 xx / C2 xx  -> "A-tilde" or "A-circumflex" + a Latin-1 symbol   (e-acute, nbsp, copyright...)
#   E2 80 xx       -> "a-circumflex" + euro sign (cp1252) or + U+0080   (dashes, quotes, bullets)
#   EF BB BF       -> "i-diaeresis" + ">>" + "inverted ?"               (a BOM pasted mid-text)
MOJIBAKE_RE = re.compile("[\u00c3\u00c2][\u0080-\u00bf]|\u00e2[\u20ac\u0080][\u0080-\u00bf\u2018-\u203a\u0152-\u02dc]?"
                         "|\u00ef\u00bb\u00bf")


def is_text(f: str) -> bool:
    return f.endswith(TEXT_EXT) or os.path.basename(f) in TEXT_NAMES


def check_encoding(files: list[str]) -> list[str]:
    problems = []
    for f in files:
        if not is_text(f):
            continue
        b = read_bytes(f)
        if b is None:
            continue
        try:
            t = b.decode("utf-8")
        except UnicodeDecodeError as e:
            problems.append(f + ": not valid UTF-8 (byte offset " + str(e.start) + ")")
            continue
        for i, line in enumerate(t.split("\n"), 1):
            if "\ufffd" in line:
                problems.append(f + ":" + str(i) + ": U+FFFD replacement character (a lossy decode)")
            m = MOJIBAKE_RE.search(line)
            if m:
                problems.append(f + ":" + str(i) + ": double-encoded UTF-8 " + ascii(m.group(0)) +
                                " in: " + line.strip()[:100])
    return problems


# ----------------------------------------------------------------------------- 3. revoked IDs
GENERATED = ("mitre/", "techniques/", "detections/strategies/", "scores/", "navigator/index.md")
ID_RE = re.compile(r"(?<![\w./-])(T\d{4}(?:\.\d{3})?)(?![\w])")
CONTEXT_RE = re.compile(r"revoked|deprecated|superseded|formerly|retired|renamed to|merged into", re.I)


def load_superseded() -> dict:
    out = {}
    with open(os.path.join(ROOT, "data", "attack", "superseded_by.jsonl"), encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                out[r["old_id"]] = r
    return out


def revoked_citations(files: list[str]):
    sup = load_superseded()
    hits = []
    for f in files:
        if not f.endswith(".md") or f.startswith(GENERATED) or f.startswith(".github/"):
            continue
        b = read_bytes(f)
        if b is None:
            continue
        for i, line in enumerate(b.decode("utf-8", errors="replace").split("\n"), 1):
            ids = {m.group(1) for m in ID_RE.finditer(line)}
            for old in sorted(ids & sup.keys()):
                new = sup[old].get("new_id")
                if (new and new in ids) or CONTEXT_RE.search(line):
                    continue
                hits.append((f, i, old, new, sup[old]["reason"], sup[old]["domain"]))
    return hits


def check_revoked(files: list[str], report: bool, update: bool) -> list[str]:
    hits = revoked_citations(files)
    counts = collections.Counter((h[0], h[2]) for h in hits)
    if update:
        base = collections.defaultdict(dict)
        for (f, old), n in sorted(counts.items()):
            base[f][old] = n
        os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
        with open(BASELINE, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"_comment": "Revoked/deprecated ATT&CK IDs still cited by hand-written pages "
                                   "(file -> old_id -> count). Written by scripts/check_repo_hygiene.py "
                                   "--update-baseline. Only ever shrink it: re-key the citation to the "
                                   "new_id in data/attack/superseded_by.jsonl, then rewrite.",
                       "citations": base}, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print("revoked: baseline written (" + str(len(hits)) + " citations in " +
              str(len({h[0] for h in hits})) + " files)")
        return []
    try:
        with open(BASELINE, encoding="utf-8") as fh:
            raw = json.load(fh).get("citations", {})
    except (OSError, ValueError):
        raw = {}
    base = collections.Counter({(f, old): n for f, d in raw.items() for old, n in d.items()})
    if report:
        for h in hits:
            print("  " + h[0] + ":" + str(h[1]) + ": " + h[2] + " (" + h[4] + ", " + h[5] + ") -> " +
                  (h[3] or "no replacement"))
    over = {k: n for k, n in counts.items() if n > base.get(k, 0)}
    shrunk = sum(base[k] - counts.get(k, 0) for k in base if counts.get(k, 0) < base[k])
    print("revoked: " + str(len(hits)) + " revoked/deprecated ATT&CK citations in " +
          str(len({h[0] for h in hits})) + " hand-written pages; baseline allows " + str(sum(base.values())))
    if shrunk:
        print("revoked: NOTE " + str(shrunk) + " baselined citations are gone; shrink the baseline with "
              "--update-baseline")
    problems = []
    for h in hits:
        k = (h[0], h[2])
        if k in over:
            problems.append(h[0] + ":" + str(h[1]) + ": cites " + h[2] + ", " + h[4] + " in the pinned ATT&CK v19.2 data " +
                            "(use " + (h[3] or "a current technique; no direct replacement") + ")")
            over.pop(k)
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", choices=("junk", "encoding", "revoked"), action="append")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--update-baseline", action="store_true")
    args = ap.parse_args()
    only = set(args.only or ("junk", "encoding", "revoked"))
    files = tracked_files()
    failed = False
    if args.update_baseline:
        check_revoked(files, False, True)
        return 0
    for name, fn in (("junk", lambda: check_junk(files)),
                     ("encoding", lambda: check_encoding(files)),
                     ("revoked", lambda: check_revoked(files, args.report, False))):
        if name not in only:
            continue
        problems = fn()
        if problems:
            failed = True
            print("FAIL " + name + ":")
            for p in problems:
                print("  " + p)
        else:
            print("OK " + name)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
