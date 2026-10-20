#!/usr/bin/env python3
"""Write the "Start-here guides" cards on the site homepage (HOME.md) from the guides'
own headers, so a card's time and level can never disagree with the guide.

Each how-to guide opens with a header table whose columns include "Time" and
"Difficulty". This script reads, for every guide in START_HERE: the H1 (the card title)
and the first row of that table (the card's time and level), and writes the cards
between `<!-- guides:start ... -->` and `<!-- guides:end -->` in HOME.md.

A pill shows the cell up to its first ";", ":" or " (" (the rest is the guide's own
elaboration) with a leading "~" spelled "About"; the full cell is the pill's title
attribute. A guide without a title or a Time/Difficulty table is an error.

Usage:
    python scripts/build_home_guides.py          # rewrite the block in HOME.md
    python scripts/build_home_guides.py --check  # exit 1 if the committed block is stale
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_text  # noqa: E402

HOME = "HOME.md"
# The guides on the homepage, in order. Every entry is a guides/<NAME>.md file.
START_HERE = [
    "HOW_TO_USE_THIS_LIBRARY",
    "TRIAGE_A_CVE",
    "BUILD_YOUR_FIRST_DETECTION",
    "RESPOND_TO_RANSOMWARE",
    "HARDEN_A_WINDOWS_BASELINE",
    "START_A_VULN_MGMT_PROGRAM",
]
BLOCK_RE = re.compile(r"(<!-- guides:start[^>]*-->\n)(.*?)(<!-- guides:end -->)", re.S)
H1_RE = re.compile(r"^# +(.+?)\s*$", re.M)


def cells(row: str) -> list[str]:
    row = row.strip()
    if row.startswith("|"):
        row = row[1:]
    if row.endswith("|"):
        row = row[:-1]
    return [c.strip() for c in re.split(r"(?<!\\)\|", row)]


def header(name: str) -> dict:
    rel = f"guides/{name}.md"
    text = read_text(rel)
    if text is None:
        raise SystemExit(f"{rel}: not found")
    m = H1_RE.search(text)
    if not m:
        raise SystemExit(f"{rel}: no H1 title")
    lines = text.split("\n")
    for i, line in enumerate(lines[:-2]):
        if not line.lstrip().startswith("|"):
            continue
        head = [c.lower() for c in cells(line)]
        if "time" in head and "difficulty" in head and re.match(r"^\s*\|?\s*:?-", lines[i + 1]):
            row = cells(lines[i + 2])
            return {"route": f"#/guides/{name}", "title": m.group(1),
                    "time": row[head.index("time")], "level": row[head.index("difficulty")]}
    raise SystemExit(f"{rel}: no header table with Time and Difficulty columns")


def short(cell: str) -> str:
    s = re.split(r";|:| \(", cell, maxsplit=1)[0].strip()
    return re.sub(r"^~\s*", "About ", s)


def plain(s: str) -> str:
    """Markdown cell text as plain text: drop emphasis and code markers, unescape pipes."""
    return re.sub(r"[*_`]", "", s).replace("\\|", "|").replace("\\*", "*")


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def block() -> str:
    # Spaces between the parts keep the card text readable on github.com, which drops the
    # classes; on the site the cards are flex boxes, so the spaces take no room.
    out = ['<div class="tsw-guides">']
    for name in START_HERE:
        g = header(name)
        pills = " ".join(
            f'<span class="tsw-pill" title="{esc(plain(full))}"><span class="tsw-sr-only">{label}: </span>'
            f'{esc(short(plain(full)))}</span>'
            for label, full in (("Time", g["time"]), ("Level", g["level"])))
        out.append(f'  <a class="tsw-guide" href="{g["route"]}"><span class="tsw-guide-t">{esc(plain(g["title"]))}</span>'
                   f' <span class="tsw-pills">{pills}</span></a>')
    out.append("</div>")
    return "\n".join(out) + "\n"


def main() -> int:
    text = read_text(HOME)
    m = BLOCK_RE.search(text or "")
    if not m:
        print(f"{HOME}: no <!-- guides:start --> ... <!-- guides:end --> block")
        return 1
    want = block()
    if "--check" in sys.argv:
        if m.group(2) != want:
            print(f"{HOME}: the Start-here guides block is stale; run `python scripts/build_home_guides.py`")
            return 1
        print("OK: the Start-here guide cards match the guides' header tables")
        return 0
    new = text[:m.start(2)] + want + text[m.end(2):]
    if new != text:
        with open(os.path.join(ROOT, HOME), "w", encoding="utf-8", newline="\n") as f:
            f.write(new)
        print(f"wrote {HOME} Start-here guides block")
    else:
        print(f"{HOME} Start-here guides block is current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
