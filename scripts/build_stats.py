#!/usr/bin/env python3
"""Compute every advertised headline count directly from the source-of-truth data
files and emit data/generated/stats.json. With --check, scan the human-facing docs
for hard-coded numbers that must match stats.json and exit non-zero on divergence.

The point of this script (audit Wave 0): headline numbers stop being typed by hand.
Run it after any data change; CI runs --check to fail the build on drift.

It also writes the "What's inside" counts in README.md (a table) and in HOME.md (the
site homepage's count cards), each between the markers `<!-- stats:start ... -->` and
`<!-- stats:end -->`. --check fails when either block differs from what the current
files produce, so the front-door counts cannot drift.
"""
from __future__ import annotations
import json, sys, glob, os, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import read_text, tracked_files  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Root Markdown files that are site chrome, community files or about-the-repo pages,
# not reference documents. Everything else at the root is a reference, except a
# superseded stub (a page that only points to its replacement).
ROOT_META = {
    "README.md", "HOME.md", "INDEX.md", "ABOUT_THE_DATA.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md",
    "explore.md",   # the Explore page (scripts/build_explore.py), a framework index
}
STUB_MARK = "This document has been superseded."

def _rows(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return None
    out = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out

def _navigator_layers():
    """Navigator layers = JSON objects with a techniques list; index files such as
    navigator/library-layers/index.json are not layers and are not counted."""
    n = 0
    for p in glob.glob(os.path.join(ROOT, "navigator", "**", "*.json"), recursive=True):
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(d, dict) and isinstance(d.get("techniques"), list):
            n += 1
    return n


def _library_counts():
    """Hand-written and generated page counts from the tracked tree (git ls-files), so a
    local checkout missing a file (antivirus quarantine) counts what CI counts."""
    files = [f for f in tracked_files() if f.endswith(".md")]
    refs = 0
    for f in files:
        if "/" in f or f.startswith("_") or f in ROOT_META:
            continue
        head = (read_text(f) or "")[:600]
        if STUB_MARK in head:
            continue
        refs += 1

    def page(f):
        """A content page: not a section README and not docsify chrome (_sidebar.md)."""
        base = f.rsplit("/", 1)[-1]
        return base != "README.md" and not base.startswith("_")

    def folder(prefix):
        return sum(1 for f in files if f.startswith(prefix) and "/" not in f[len(prefix):]
                   and page(f))
    # Framework pages are the object pages in mitre/<kind>/ (techniques, groups, capec,
    # ...). Pages at the mitre/ root, such as crosswalk.md, are not object pages.
    return {
        "reference_docs": refs,
        "guides": folder("guides/"),
        "learning_paths": folder("disciplines/"),
        "framework_pages": sum(1 for f in files if f.startswith("mitre/")
                               and f.count("/") >= 2 and page(f)),
    }


def _count(rel):
    r = _rows(rel)
    return len(r) if r is not None else None

def compute():
    tp = _rows("data/attack/technique_profiles.jsonl") or []
    sub = sum(1 for t in tp if t.get("is_subtechnique"))
    d3 = _rows("data/attack/technique_to_d3fend.jsonl") or []
    d3_tech = len({r.get("technique_id") for r in d3 if r.get("technique_id", "").startswith("T")})
    ds = _rows("data/attack/detection_strategies.jsonl") or []
    stats = {
        # --- ATT&CK core (project's own data = source of truth) ---
        "technique_total": len(tp),
        "technique_parent": len(tp) - sub,
        "technique_sub": sub,
        # MITRE currently lists 697 ACTIVE enterprise techniques; this file retains a
        # small number of superseded records on purpose (no revoked flag in-file), so
        # technique_total (file) legitimately exceeds MITRE-active. See docs footnote.
        "mitre_active_enterprise_techniques_ref": 697,
        # Authoritative entity counts come from the *_profiles files (the complete,
        # v19.2-current sets). All entities are official MITRE ATT&CK v19.2, including
        # the S9xxx software block and group G1056 (TeamPCP), which are genuine v19.2
        # additions (verified on attack.mitre.org), not lab/fictional entries.
        "groups": _count("data/attack/group_profiles.jsonl"),
        "software": _count("data/attack/software_profiles.jsonl"),
        "campaigns": _count("data/attack/campaign_profiles.jsonl"),
        "mitigations": _count("data/attack/mitigations.jsonl"),
        "data_components": _count("data/attack/data_components.jsonl"),
        # Count DISTINCT strategies, not rows: 15 strategies are listed against
        # both a technique's superseded and current v19.2 id (e.g. DET0532 under
        # T1070.001 and T1685.005), so the file has more rows than strategies.
        "detection_strategies": (len({r.get("strategy_id") for r in ds}) if ds else None),
        "detection_strategy_technique_rows": (len(ds) if ds else None),
        "analytics": _count("data/attack/analytics.jsonl"),
        # --- Engage ---
        "engage_activities": _count("data/engage/engage_activities.jsonl"),
        "engage_approaches": _count("data/engage/engage_approaches.jsonl"),
        "engage_goals": _count("data/engage/engage_goals.jsonl"),
        "engage_mappings": _count("data/engage/attack_to_engage.jsonl"),
        # --- crosswalk edge tables ---
        "control_to_technique_edges": _count("data/control_to_technique.jsonl"),
        "vendor_to_technique_edges": _count("data/vendor_to_technique.jsonl"),
        "technique_to_d3fend_edges": len(d3) if d3 else None,
        "techniques_with_d3fend": d3_tech,
        # --- workbench / docs ---
        "navigator_layers": _navigator_layers() or None,
        # --- hand-written and generated pages (README "What's inside") ---
        **_library_counts(),
    }
    return {k: v for k, v in stats.items() if v is not None}

# (regex on the doc, group(1) = the number)  ->  stats key it must equal
# technique_total (714) = the technique RECORDS/pages the library publishes; 697 are
# active per MITRE v19.2 (17 superseded records retained for lineage; see docs footnote).
CHECKS = [
    # Skip relational subset claims like "the 426 ATT&CK techniques they counter"
    # (a cross-reference count, not the technique total) via the trailing lookahead.
    (r"([\d,]+)\s+(?:MITRE\s+)?ATT&CK\s+(?:Enterprise\s+)?techniques\b(?! they counter)", "technique_total"),
    (r"([\d,]+)\s+(?:MITRE ATT&CK\s+)?(?:adversary\s+)?groups\b", "groups"),
    (r"([\d,]+)\s+(?:MITRE ATT&CK\s+)?malware", "software"),
    (r"([\d,]+)\s+(?:MITRE\s+)?detection strategies", "detection_strategies"),
    (r"([\d,]+)\s+analytics", "analytics"),
    (r"([\d,]+)\s+deception activities", "engage_activities"),
    (r"([\d,]+)\s+mappings? to ATT", "engage_mappings"),
    (r"([\d,]+)\s+(?:MITRE ATT&CK\s+)?(?:intrusion\s+)?campaigns", "campaigns"),
    (r"([\d,]+)\s+(?:workbench\s+|navigator\s+)?layers", "navigator_layers"),
    # the README "What's inside" nouns, so a hand-typed copy elsewhere cannot disagree
    (r"([\d,]+)\s+reference documents?\b", "reference_docs"),
    (r"([\d,]+)\s+(?:step-by-step\s+)?how-to guides?\b", "guides"),
    (r"([\d,]+)\s+(?:guided\s+|discipline\s+)?learning paths?\b", "learning_paths"),
    (r"([\d,]+)\s+(?:generated\s+)?framework pages?\b", "framework_pages"),
]
# guides/HOW_TO_USE_THIS_LIBRARY.md is the onboarding walk-through and quotes library-wide
# totals; the other guides quote relational subsets ("6 groups") the regexes would misread.
DOCS = ["README.md", "HOME.md", "INDEX.md", "CITATION.cff",
        os.path.join("guides", "HOW_TO_USE_THIS_LIBRARY.md")] + \
       [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "scores", "*.md"))]

def check(stats):
    problems = []
    for rel in DOCS:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8").read()
        for pat, key in CHECKS:
            if key not in stats:
                continue
            for m in re.finditer(pat, text):
                s = m.group(1).replace(",", "")
                if not s.isdigit():
                    continue
                got = int(s)
                if got != stats[key]:
                    problems.append(f"{rel}: '{m.group(0).strip()}' -> {key} should be {stats[key]:,} (found {got:,})")
    return problems

BLOCK_RE = re.compile(r"(<!-- stats:start[^>]*-->\n)(.*?)(<!-- stats:end -->)", re.S)

# The four front-door counts: (label, what it holds, stats key, README link, site route).
# Wording lives here so the numbers and the nouns they count change together, and the
# README table and the HOME cards say the same thing.
FRONT_DOOR = [
    ("Reference documents", "One topic each: its terms, tooling, and the frameworks and guidance that apply",
     "reference_docs", "[Reference index](INDEX.md)", "#/INDEX"),
    ("How-to guides", "One task, step by step, with the time it takes, what you need, and what you produce",
     "guides", "[Guides](guides/README.md)", "#/guides/README"),
    ("Learning paths", "An order of study for one discipline, with training, tools, books, and certifications",
     "learning_paths", "[Learning paths](disciplines/README.md)", "#/disciplines/README"),
    # Only the families that have pages under mitre/: Enterprise ATT&CK (not ICS or Mobile,
    # whose data has no pages), ATLAS techniques and mitigations, and F3 techniques.
    ("Framework pages", "One page per Enterprise ATT&CK technique, tactic, group, software entry, campaign, "
     "and mitigation, CAPEC attack pattern, D3FEND countermeasure, ATLAS technique and mitigation, "
     "and F3 technique",
     "framework_pages", "[Framework pages](mitre/README.md)", "#/mitre/README"),
]


def readme_block(stats):
    """The README "What's inside" table."""
    out = ["| What | Count | Contents | Start at |", "|---|---:|---|---|"]
    for name, what, key, link, _route in FRONT_DOOR:
        out.append(f"| {name} | {stats[key]:,} | {what} | {link} |")
    return "\n".join(out) + "\n"


def _html(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def home_block(stats):
    """The site homepage's "What's inside" cards (HOME.md): one raw-HTML block with no
    blank line, so docsify and GitHub both keep it as a single HTML block. The spaces
    between the spans keep the text readable on github.com, which drops the classes."""
    out = ['<div class="tsw-counts">']
    for name, what, key, _link, route in FRONT_DOOR:
        out.append(f'  <a class="tsw-count" href="{route}"><span class="tsw-count-n">{stats[key]:,}</span> '
                   f'<span class="tsw-count-l">{_html(name)}</span> '
                   f'<span class="tsw-count-d">{_html(what)}</span></a>')
    out.append("</div>")
    return "\n".join(out) + "\n"


# file -> renderer of its stats block
BLOCKS = {"README.md": readme_block, "HOME.md": home_block}


def block_problems(stats):
    probs = []
    for rel, render in BLOCKS.items():
        text = read_text(rel)
        if text is None:
            continue
        m = BLOCK_RE.search(text)
        if not m:
            probs.append(f"{rel}: no <!-- stats:start --> ... <!-- stats:end --> block")
        elif m.group(2) != render(stats):
            probs.append(f"{rel}: the What's inside block is stale; run `python scripts/build_stats.py`")
    return probs


def write_blocks(stats):
    for rel, render in BLOCKS.items():
        text = read_text(rel)
        m = BLOCK_RE.search(text or "")
        if not m:
            print(f"{rel} has no stats block; not written")
            continue
        new = text[:m.start(2)] + render(stats) + text[m.end(2):]
        if new != text:
            with open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="\n") as f:
                f.write(new)
            print(f"wrote {rel} What's inside block")


def main():
    stats = compute()
    if "--check" in sys.argv:
        probs = check(stats) + block_problems(stats)
        if probs:
            print("STALE HEADLINE NUMBERS (must match data/generated/stats.json):")
            for p in probs:
                print("  -", p)
            sys.exit(1)
        print("OK: all scanned headline numbers match stats.json")
        return
    outdir = os.path.join(ROOT, "data", "generated")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "stats.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(stats, f, indent=2, sort_keys=True)
        f.write("\n")
    print("wrote data/generated/stats.json")
    write_blocks(stats)
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v:,}" if isinstance(v, int) else f"  {k}: {v}")

if __name__ == "__main__":
    main()
