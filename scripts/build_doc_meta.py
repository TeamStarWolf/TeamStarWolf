#!/usr/bin/env python3
"""Write the header card at the top of every root reference and learning path, and fold
long appendices.

The card is a two-column table between markers, written into the page itself so it reads
the same on GitHub and on the site. The first table is what fits one screen; the rest sits
in two closed <details> folds (on the site, the "More about this page" fold opens by itself
on screens wider than 600 px):

    <!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

    | | |
    |---|---|
    | Who this is for | ... |
    | Level | ... |
    | Reading time | About 13 min (2,963 words at 230 words a minute) |
    | Read this when | ... |
    | Start at | ... (at most 3 links) |

    <details class="tsw-meta-more"><summary>More about this page (pairs with, ...)</summary>

    | | |
    |---|---|
    | Pairs with | ... |
    | Matching learning path | ... |
    | Last corrected | 2026-10-12, what the edit changed on this page ([#PR](...), ATT&CK v19.2) |
    | Last reviewed | No review recorded yet |

    </details>

    <details class="tsw-meta-which"><summary>Which page should I read? This page is one of 3 on ...</summary>

    | Page | Read it for |                    (pages in an overlap cluster)

    </details>

    Key takeaways (reviewed ...):          (only takeaways from data/doc_takeaways.yaml)

    <!-- meta:end -->

"Last corrected" and "Last reviewed" are different rows on purpose. A correction is a pull
request in the history that edited the page's text (a renamed tool, a re-keyed ATT&CK ID,
an updated regulation); its row says what that edit changed on this page, and names an
ATT&CK release only when the edit was about ATT&CK content. A review is a whole-page review
the owner records; until one is recorded the card says "No review recorded yet", and only a
review starts or resets the "Due for review" clock, so a find-and-replace never does.

Where each part comes from:

    data/doc_meta.yaml          the hand-written fields of each page (who it is for, level,
                                read this when, start at, pairs with, matching learning
                                path, its last correction and its last review), the
                                corrections and reviews themselves, the overlap clusters
                                and the folds. The file is YAML in which every value is
                                written as JSON (one line each), so it needs no YAML
                                library here and any YAML tool reads it the same.
    the page                    the word count and reading time: the page's words
                                (build_site_nav.word_count, the same count the domain hubs
                                show) at 230 words a minute
    git history                 the date the page's text last changed (commits that only
                                touch script-written blocks, link targets or the card do
                                not count). "Due for review" is added to the last-reviewed
                                row when the text changed more than 90 days after the
                                owner's review. The --check run needs full history (CI
                                checks out with fetch-depth: 0) and refuses a shallow clone.
    docs/crosslinks.json        the learning path that matches a reference; doc_meta.yaml
                                must name the same one (build_crosslinks.py writes the
                                callout under each path from the same pairs)
    data/doc_takeaways.yaml     key takeaways the owner has reviewed. Drafts wait in
                                data/doc_takeaways.draft.yaml, which is checked but never
                                rendered. Every takeaway names the section it comes from and
                                quotes the page; the check fails when the quote is no longer
                                in that section, so a takeaway cannot outlive its source.

Folds: a page's "fold" list in doc_meta.yaml wraps a section's body ("section:<anchor>")
or each table of more than 40 rows inside a section ("tables:<anchor>") in a <details>
element with a one-line summary. 40 table rows is about two screens at 1440 x 900. The
heading stays outside the fold, so anchors, the table of contents and links keep working;
on the site, a link to an anchor inside a fold opens it (index.html). --report lists the
appendix and glossary sections over two screens that are not folded yet.

Rules the --check run enforces (CI, validate-data.yml):
  * every root reference and learning path has an entry, and every entry is one of them;
  * each committed card and fold matches what this script writes;
  * no "Read this when", "Start at" or "Pairs with" row outside the card (they live in
    doc_meta.yaml now);
  * level is one of LEVELS, "Read this when" starts with a capital letter, "Start at"
    has at most 3 links, a correction or review id
    exists, a fold names a real heading, a learning path matches docs/crosslinks.json, a
    page sits in at most one cluster;
  * every takeaway (draft or reviewed): 3 to 5 per page, one line, the voice rules of
    docs/VOICE.md, a "from" anchor on the page, and a quote found in that section.

Usage:
    python scripts/build_doc_meta.py              # write every card and fold
    python scripts/build_doc_meta.py --check      # exit 1 on drift or an invalid entry
    python scripts/build_doc_meta.py --report     # cards, reading times, reviews, folds
    python scripts/build_doc_meta.py --self-test  # the YAML reader, folds and due rule
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_text, tracked_files  # noqa: E402
import build_search_index as bsi  # noqa: E402  (inline-markup stripping)
import build_site_nav as bsn  # noqa: E402  (references, titles, word count, levels)
import check_docsify_links as cdl  # noqa: E402  (docsify heading slugs)
import check_voice as cv  # noqa: E402  (voice rules for takeaways)

META = "data/doc_meta.yaml"
TAKEAWAYS = "data/doc_takeaways.yaml"
DRAFT = "data/doc_takeaways.draft.yaml"
CROSSLINKS = "docs/crosslinks.json"
REPO_URL = "https://github.com/TeamStarWolf/TeamStarWolf"

START = "<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->"
END = "<!-- meta:end -->"
META_RE = re.compile(r"^<!-- meta:start[^\n]*-->\n.*?^<!-- meta:end -->", re.S | re.M)
CARD_ROW_RE = re.compile(r"^\|\s*(Read this when|Start at|Pairs with)\s*\|")
CARD_FIELDS = (("read_when", "Read this when"), ("start_at", "Start at"), ("pairs_with", "Pairs with"))
FIRST_SCREEN = ("read_when", "start_at")     # the rest of the card goes in "More about this page"
START_AT_MAX = 3                             # plan section 5: at most three anchors
LINK_RE = re.compile(r"\]\(")
MORE_OPEN = '<details class="tsw-meta-more"><summary>{}</summary>'
WHICH_OPEN = '<details class="tsw-meta-which"><summary>{}</summary>'
CORRECTED_LABEL = "Last corrected"

WPM = bsn.WPM
DUE_DAYS = 90
FOLD_ROWS = 40                  # table rows in about two screens at 1440 x 900
FOLD_OPEN = '<details class="tsw-fold"><summary>{}</summary>'
FOLD_OPEN_RE = bsn.FOLD_OPEN_RE
FOLD_CLOSE = "</details>"
# The guides' difficulty scale (build_site_nav.py), plus the span a learning path covers:
# each path's own "Where to Start" table runs from foundation to advanced.
LEVELS = bsn.DIFFICULTY_LEVELS + ("Beginner to advanced",)
TAKEAWAYS_MIN, TAKEAWAYS_MAX, TAKEAWAY_LEN = 3, 5, 220
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ATTACK_RE = re.compile(r"^v\d+\.\d+$")
UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")


class Invalid(Exception):
    pass


# ----------------------------------------------------------------------------- YAML subset

KEY_RE = re.compile(r'^([A-Za-z0-9_][A-Za-z0-9_./-]*|"(?:[^"\\]|\\.)*"):(?:[ ](.*))?$')
PLAIN_KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*$")
YAML_WORDS = {"true", "false", "null", "yes", "no", "on", "off", "y", "n", "~"}


def parse_yaml(text: str, name: str):
    """The YAML this repository writes: nested block mappings ("key:" on its own line, the
    children indented by two more spaces), block lists ("- value") and one-line values,
    every value written as JSON. Full-line comments and blank lines are skipped. Anything
    else fails with the line number, so a stray edit cannot be read two ways."""
    items = []
    for n, line in enumerate(text.split("\n"), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        body = line.lstrip(" ")
        indent = len(line) - len(body)
        if "\t" in line[:indent + 1] or indent % 2:
            raise Invalid(name + ":" + str(n) + ": indent with an even number of spaces, no tabs")
        body = body.rstrip()
        if body.startswith("- ") or body == "-":
            items.append((indent, "item", None, _json(body[2:], name, n), n))
            continue
        m = KEY_RE.match(body)
        if not m:
            raise Invalid(name + ":" + str(n) + ": expected 'key: value', 'key:' or '- value'")
        key = json.loads(m.group(1)) if m.group(1).startswith('"') else m.group(1)
        value = None if m.group(2) is None or not m.group(2).strip() else _json(m.group(2), name, n)
        items.append((indent, "key", key, value, n))
    if not items:
        return {}
    obj, i = _block(items, 0, items[0][0], name)
    if i != len(items):
        raise Invalid(name + ":" + str(items[i][4]) + ": unexpected indent")
    return obj


def _json(s: str, name: str, n: int):
    try:
        return json.loads(s)
    except ValueError as e:
        raise Invalid(name + ":" + str(n) + ": value is not JSON (" + str(e) + "); quote text in double quotes")


def _block(items, i, indent, name):
    if items[i][1] == "item":
        out = []
        while i < len(items) and items[i][0] == indent and items[i][1] == "item":
            out.append(items[i][3])
            i += 1
        if i < len(items) and items[i][0] > indent:
            raise Invalid(name + ":" + str(items[i][4]) + ": a list item cannot have children; write it as JSON")
        return out, i
    out = {}
    while i < len(items) and items[i][0] == indent:
        _, kind, key, value, n = items[i]
        if kind != "key":
            raise Invalid(name + ":" + str(n) + ": a list item where a key was expected")
        if key in out:
            raise Invalid(name + ":" + str(n) + ": duplicate key '" + key + "'")
        i += 1
        if value is None and i < len(items) and items[i][0] > indent:
            out[key], i = _block(items, i, items[i][0], name)
        else:
            out[key] = value
    if i < len(items) and items[i][0] > indent:
        raise Invalid(name + ":" + str(items[i][4]) + ": unexpected indent")
    return out, i


def dump_yaml(obj: dict, indent: int = 0) -> list[str]:
    """The inverse of parse_yaml, for files this script or its tools write."""
    out = []
    pad = " " * indent
    for k, v in obj.items():
        key = k if PLAIN_KEY_RE.match(k) and k.lower() not in YAML_WORDS and not re.match(r"^[\d.-]+$", k) \
            else json.dumps(k, ensure_ascii=False)
        if isinstance(v, dict) and v:
            out.append(pad + key + ":")
            out += dump_yaml(v, indent + 2)
        elif isinstance(v, list) and v:
            out.append(pad + key + ":")
            out += [pad + "  - " + json.dumps(x, ensure_ascii=False) for x in v]
        else:
            out.append(pad + key + ": " + json.dumps(v, ensure_ascii=False))
    return out


def load(rel: str, required: bool = True) -> dict:
    text = read_text(rel)
    if text is None:
        if required:
            raise SystemExit(rel + ": not found")
        return {}
    try:
        data = parse_yaml(text, rel)
    except Invalid as e:
        raise SystemExit(str(e))
    if not isinstance(data, dict):
        raise SystemExit(rel + ": the top level must be a mapping")
    return data


# ----------------------------------------------------------------------------- pages


def scope(files: list[str]) -> tuple[list[str], list[str]]:
    """(root references, learning paths)."""
    refs = bsn.references(files)
    paths = sorted(f for f in files if f.startswith("disciplines/") and f.endswith(".md")
                   and f.count("/") == 1 and not os.path.basename(f).startswith("_")
                   and f != "disciplines/README.md")
    return refs, paths


def path_refs() -> dict[str, list[str]]:
    """Reference -> the learning paths docs/crosslinks.json pairs with it."""
    cfg = json.loads(read_text(CROSSLINKS) or "{}")
    out: dict[str, list[str]] = {}
    for path, refs in cfg.get("path_references", {}).items():
        for r in refs:
            out.setdefault(r, []).append("disciplines/" + path + ".md")
    return {r: sorted(p) for r, p in out.items()}


def fences(lines: list[str]) -> list[bool]:
    """in_fence per line (fence lines included)."""
    out, fence = [], None
    for line in lines:
        m = cdl.FENCE_RE.match(line)
        if fence is None and m:
            fence = m.group(1)[0] * len(m.group(1))
            out.append(True)
        elif fence is not None:
            if m and m.group(1).startswith(fence) and not line[m.end():].strip():
                fence = None
            out.append(True)
        else:
            out.append(False)
    return out


def headings(lines: list[str]) -> list[tuple[int, int, str, str]]:
    """(line index, level, docsify id, text) of every ATX heading outside code."""
    out, seen = [], {}
    for i, (line, f) in enumerate(zip(lines, fences(lines))):
        if f:
            continue
        m = cdl.ATX_RE.match(line)
        if m:
            raw = m.group(2)
            cfg = re.search(r"""\s*:id=([^\s'"]+)""", raw)
            slug = cdl.docsify_slug(cdl.heading_html(raw[:cfg.start()] if cfg else raw), seen)
            out.append((i, len(m.group(1)), cfg.group(1) if cfg else slug, bsi.strip_inline(raw)))
    return out


def section_range(lines: list[str], anchor: str) -> tuple[int, int, int, str] | None:
    """(heading line, first body line, end line exclusive, heading text) of a section: up
    to the next heading of the same or a higher level, a script-written block, or a
    trailing sign-off. An H1's section ends at the first H2."""
    hs = headings(lines)
    for n, (i, level, slug, text) in enumerate(hs):
        if slug != anchor:
            continue
        end = len(lines)
        limit = 2 if level == 1 else level
        for j, lv, _, _ in hs[n + 1:]:
            if lv <= limit:
                end = j
                break
        for k in range(i + 1, end):
            if re.match(r"^<!-- [\w-]+:start", lines[k]):
                end = k
                break
        return i, i + 1, end, text
    return None


# ----------------------------------------------------------------------------- history


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")


def text_key(text: str) -> str:
    """What counts as the page's text for "last changed": its words, without the card,
    card rows, script-written blocks, fold summaries, comments and link targets."""
    t = META_RE.sub(" ", text)
    t = "\n".join(line for line in t.split("\n") if not CARD_ROW_RE.match(line))
    return hashlib.sha1("\x00".join(bsn.words(t)).encode("utf-8")).hexdigest()


class History:
    """The date a page's text last changed, from git history (one cat-file process)."""

    def __init__(self) -> None:
        if git("rev-parse", "--is-shallow-repository").strip() == "true":
            raise SystemExit("build_doc_meta.py needs the full git history to date each page's last "
                             "change; this clone is shallow (in CI, check out with fetch-depth: 0)")
        self.proc = subprocess.Popen(["git", "cat-file", "--batch"], cwd=ROOT,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.cache: dict[str, str] = {}

    def blob(self, rev: str, rel: str) -> str | None:
        self.proc.stdin.write((rev + ":" + rel + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        header = self.proc.stdout.readline().decode("utf-8")
        if header.rstrip().endswith("missing"):
            return None
        size = int(header.split()[2])
        data = self.proc.stdout.read(size)
        self.proc.stdout.read(1)
        t = data.decode("utf-8", errors="replace")
        return (t[1:] if t.startswith("\ufeff") else t).replace("\r\n", "\n")

    def last_changed(self, rel: str, current: str) -> str:
        if rel in self.cache:
            return self.cache[rel]
        today = datetime.date.today().isoformat()
        log = [ln.split() for ln in git("log", "--format=%H %cs", "--", rel).split("\n") if ln.strip()]
        head = self.blob("HEAD", rel)
        if not log or head is None or text_key(head) != text_key(current):
            self.cache[rel] = today          # changed in the working tree, not committed yet
            return today
        keys = [text_key(self.blob(h, rel) or "") for h, _ in log]
        date = log[-1][1]                    # the commit that added the page
        for n in range(len(log) - 1):
            if keys[n] != keys[n + 1]:
                date = log[n][1]
                break
        self.cache[rel] = date
        return date


def due(reviewed: str, changed: str) -> bool:
    return (datetime.date.fromisoformat(changed) - datetime.date.fromisoformat(reviewed)).days > DUE_DAYS


# ----------------------------------------------------------------------------- validation


def validate(meta: dict, refs: list[str], paths: list[str]) -> list[str]:
    problems = []
    corrections = meta.get("corrections") or {}
    for cid, r in corrections.items():
        if not isinstance(r, dict) or set(r) - {"date", "pr", "what", "attack", "label"} \
                or not DATE_RE.match(str(r.get("date", ""))) or not isinstance(r.get("pr"), int) \
                or not str(r.get("what", "")).strip() \
                or ("attack" in r and not ATTACK_RE.match(str(r["attack"]))) \
                or ("label" in r and not str(r["label"]).strip()):
            problems.append(META + ": correction '" + cid + "' needs date (YYYY-MM-DD), pr (a number) "
                            "and what, and may have attack (vNN.N, only for an edit to ATT&CK content) "
                            "and label")
    reviews = meta.get("reviews") or {}
    for rid, r in reviews.items():
        if not isinstance(r, dict) or set(r) - {"date", "what", "attack", "pr"} \
                or not DATE_RE.match(str(r.get("date", ""))) or not str(r.get("what", "")).strip() \
                or ("attack" in r and not ATTACK_RE.match(str(r["attack"]))) \
                or ("pr" in r and not isinstance(r["pr"], int)):
            problems.append(META + ": review '" + rid + "' needs date (YYYY-MM-DD) and what, and may "
                            "have attack (vNN.N) and pr (a number)")
    pages = meta.get("pages") or {}
    want = set(refs) | set(paths)
    for rel in sorted(want - set(pages)):
        problems.append(META + ": no entry for " + rel)
    for rel in sorted(set(pages) - want):
        problems.append(META + ": " + rel + " is not a root reference or a learning path")
    matched = path_refs()
    for rel, e in sorted(pages.items()):
        if rel not in want:
            continue
        where = META + ": " + rel + ": "
        if not isinstance(e, dict):
            problems.append(where + "must be a mapping")
            continue
        unknown = set(e) - {"audience", "level", "read_when", "start_at", "pairs_with",
                            "learning_path", "corrected", "corrected_what", "reviewed", "fold"}
        if unknown:
            problems.append(where + "unknown field(s) " + ", ".join(sorted(unknown)))
        if not str(e.get("audience") or "").strip():
            problems.append(where + "audience is empty")
        if e.get("level") not in LEVELS:
            problems.append(where + "level must be one of: " + ", ".join(LEVELS))
        for field, _ in CARD_FIELDS + (("audience", ""), ("corrected_what", "")):
            v = e.get(field)
            if v is not None and (not isinstance(v, str) or "\n" in v or UNESCAPED_PIPE_RE.search(v)):
                problems.append(where + field + " must be one line with any '|' escaped as '\\|'")
        rw = str(e.get("read_when") or "")
        if rw[:1].islower():
            problems.append(where + "read_when starts with a lower-case letter; start every row with a capital")
        n_start = len(LINK_RE.findall(str(e.get("start_at") or "")))
        if n_start > START_AT_MAX:
            problems.append(where + "start_at has " + str(n_start) + " links; plan section 5 allows at most "
                            + str(START_AT_MAX))
        lp = e.get("learning_path") or []
        if rel in refs and sorted(lp) != matched.get(rel, []):
            problems.append(where + "learning_path " + json.dumps(lp) + " differs from " + CROSSLINKS
                            + " (" + json.dumps(matched.get(rel, [])) + "); change both together")
        if rel in paths and lp:
            problems.append(where + "a learning path has no learning_path field")
        rv = e.get("reviewed")
        if rv is not None and rv not in reviews:
            problems.append(where + "reviewed '" + str(rv) + "' is not under reviews:")
        cv_ = e.get("corrected")
        if cv_ is not None and cv_ not in corrections:
            problems.append(where + "corrected '" + str(cv_) + "' is not under corrections:")
        if e.get("corrected_what") is not None and cv_ is None:
            problems.append(where + "corrected_what without corrected")
        for spec in e.get("fold") or []:
            kind, _, anchor = str(spec).partition(":")
            if kind not in ("section", "tables") or not anchor:
                problems.append(where + "fold '" + str(spec) + "' must be section:<anchor> or tables:<anchor>")
    seen: dict[str, str] = {}
    for cid, c in (meta.get("clusters") or {}).items():
        members = (c or {}).get("pages") or {}
        if not str((c or {}).get("topic") or "").strip() or len(members) < 2:
            problems.append(META + ": cluster '" + cid + "' needs a topic and at least two pages")
        for rel, why in members.items():
            if rel not in want:
                problems.append(META + ": cluster '" + cid + "': " + rel + " is not a reference or path")
            if rel in seen:
                problems.append(META + ": " + rel + " is in clusters '" + seen[rel] + "' and '" + cid + "'")
            seen[rel] = cid
            if not isinstance(why, str) or not why.strip() or UNESCAPED_PIPE_RE.search(why):
                problems.append(META + ": cluster '" + cid + "': " + rel + " needs a one-line reason")
    return problems


def norm_text(s: str) -> str:
    """Text as a reader sees it, for matching a takeaway's quote: markup stripped, code
    spans kept as written (so a '*' inside code is not read as emphasis), curly quotes
    straightened, whitespace collapsed."""
    codes: list[str] = []

    def keep(m: re.Match) -> str:
        codes.append(m.group(2).strip())
        return "\x00" + str(len(codes) - 1) + "\x00"

    s = bsi.strip_inline(re.sub(r"(`+)(.+?)\1", keep, s))
    s = re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], s)
    s = s.replace("\u2019", "'").replace("\u2018", "'").replace("\u201c", '"').replace("\u201d", '"')
    return re.sub(r"\s+", " ", s).strip()


def section_text(lines: list[str], anchor: str) -> str | None:
    r = section_range(lines, anchor)
    if r is None:
        return None
    i, a, b, _ = r
    keep = [ln for ln, f in zip(lines[a:b], fences(lines)[a:b]) if not f]
    # Blockquote markers go, so a quote may run across the lines of a blockquote.
    return " ".join(norm_text(re.sub(r"^\s{0,3}(?:>\s?)+", "", ln)) for ln in keep)


def voice_hits(s: str) -> list[str]:
    return sorted({h[2] for h in cv.scan("takeaway", s)})


def validate_takeaways(data: dict, name: str, texts: dict[str, str], draft: bool) -> list[str]:
    problems = []
    if draft and data.get("status") != "owner review pending":
        problems.append(name + ": status must be \"owner review pending\" (drafts are never rendered)")
    for rel, e in sorted((data.get("pages") or {}).items()):
        where = name + ": " + rel + ": "
        if rel not in texts:
            problems.append(where + "not a root reference or learning path")
            continue
        items = (e or {}).get("items") or []
        if not draft and not DATE_RE.match(str((e or {}).get("reviewed", ""))):
            problems.append(where + "reviewed must be the review date (YYYY-MM-DD)")
        if not TAKEAWAYS_MIN <= len(items) <= TAKEAWAYS_MAX:
            problems.append(where + str(len(items)) + " takeaways; write " + str(TAKEAWAYS_MIN)
                            + " to " + str(TAKEAWAYS_MAX))
        lines = META_RE.sub("", texts[rel]).split("\n")
        for n, it in enumerate(items, 1):
            at = where + "takeaway " + str(n) + ": "
            if not isinstance(it, dict) or set(it) != {"text", "from", "quote"}:
                problems.append(at + "needs exactly text, from and quote")
                continue
            t = it["text"]
            if not isinstance(t, str) or "\n" in t or not t.strip() or len(t) > TAKEAWAY_LEN \
                    or not t.rstrip().endswith("."):
                problems.append(at + "text must be one sentence-ended line of at most "
                                + str(TAKEAWAY_LEN) + " characters")
            hits = voice_hits(t) if isinstance(t, str) else []
            if hits:
                problems.append(at + "breaks docs/VOICE.md (" + ", ".join(hits) + ")")
            anchor = str(it["from"]).lstrip("#")
            body = section_text(lines, anchor)
            if body is None:
                problems.append(at + "from '#" + anchor + "' is not a heading on the page")
            elif norm_text(str(it["quote"])) not in body:
                problems.append(at + "the quote is not in section #" + anchor + " (did the page change?)")
    return problems


# ----------------------------------------------------------------------------- card


def label(rel: str, descs: dict) -> str:
    return descs[rel][0] if rel in descs and descs[rel][0] else bsn.title(rel)


def reading_row(text: str) -> tuple[str, int]:
    """The page's words as the domain hubs count them (build_site_nav.word_count), with a
    hand-written card row left out too, so a page reads the same before and after its card
    moves into the header block."""
    n = bsn.word_count("\n".join(ln for ln in text.split("\n") if not CARD_ROW_RE.match(ln)))
    return "About " + str(max(1, round(n / WPM))) + " min (" + format(n, ",") + " words at " + str(WPM) \
        + " words a minute)", n


def pr_link(n: int) -> str:
    return "[#" + str(n) + "](" + REPO_URL + "/pull/" + str(n) + ")"


def corrected_row(e: dict, corrections: dict) -> tuple[str, str] | None:
    """(label, value) of the page's last recorded correction: its date, what the edit
    changed on this page, the pull request, and the ATT&CK release only when the edit was
    about ATT&CK content. An entry with a label (the pages #68 added) says only its date
    and pull request, "Added: 2026-09-29 (#68)", unless the page has its own corrected_what."""
    cid = e.get("corrected")
    if not cid:
        return None
    c = corrections[cid]
    tail = pr_link(c["pr"]) + (", ATT&CK " + c["attack"] if c.get("attack") else "")
    what = e.get("corrected_what") or ("" if c.get("label") else c["what"])
    return c.get("label") or CORRECTED_LABEL, c["date"] + (", " + what if what else "") + " (" + tail + ")"


def review_row(e: dict, reviews: dict, changed: str | None) -> str:
    """The owner's last whole-page review, or "No review recorded yet". Only a review
    starts the "Due for review" clock."""
    rid = e.get("reviewed")
    if not rid:
        return "No review recorded yet"
    r = reviews[rid]
    extra = [x for x in ((pr_link(r["pr"]) if r.get("pr") else ""),
                         ("against ATT&CK " + r["attack"] if r.get("attack") else "")) if x]
    row = r["date"] + ", " + r["what"] + (" (" + ", ".join(extra) + ")" if extra else "")
    if changed and due(r["date"], changed):
        row += ". Due for review: the text changed more than " + str(DUE_DAYS) + " days after this review"
    return row


def cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def cluster_note(rel: str, meta: dict, descs: dict) -> list[str]:
    for c in (meta.get("clusters") or {}).values():
        members = c["pages"]
        if rel not in members:
            continue
        out = [WHICH_OPEN.format("Which page should I read? This page is one of " + str(len(members))
                                 + " on " + c["topic"] + "."), "", "| Page | Read it for |", "|---|---|",
               "| " + label(rel, descs) + " (this page) | " + cap(members[rel]) + " |"]
        for other, why in members.items():
            if other != rel:
                out.append("| " + bsn.md_link(label(other, descs), "/" + other) + " | " + cap(why) + " |")
        return out + ["", "</details>"]
    return []


def takeaway_lines(rel: str, reviewed: dict, text: str) -> list[str]:
    e = (reviewed.get("pages") or {}).get(rel)
    if not e:
        return []
    lines = META_RE.sub("", text).split("\n")
    out = ["Key takeaways (reviewed " + e["reviewed"] + "):", ""]
    for it in e["items"]:
        anchor = it["from"].lstrip("#")
        r = section_range(lines, anchor)
        where = r[3] if r else anchor
        out.append("- " + it["text"] + " ([" + where.replace("[", "(").replace("]", ")") + "](#" + anchor + "))")
    return out


def card(rel: str, text: str, meta: dict, reviewed: dict, descs: dict, hist: History | None) -> str:
    e = meta["pages"][rel]
    rows = [("Who this is for", e["audience"]), ("Level", e["level"]),
            ("Reading time", reading_row(text)[0])]
    rows += [(lab, e[f]) for f, lab in CARD_FIELDS if f in FIRST_SCREEN and e.get(f)]
    more = [(lab, e[f]) for f, lab in CARD_FIELDS if f not in FIRST_SCREEN and e.get(f)]
    lp = e.get("learning_path") or []
    if lp:
        more.append(("Matching learning path" if len(lp) == 1 else "Matching learning paths",
                     ", ".join(bsn.md_link(bsn.title(p), "/" + p) for p in lp)))
    fixed = corrected_row(e, meta.get("corrections") or {})
    if fixed:
        more.append(fixed)
    changed = hist.last_changed(rel, text) if (hist and e.get("reviewed")) else None
    more.append(("Last reviewed", review_row(e, meta.get("reviews") or {}, changed)))
    table = ["| | |", "|---|---|"]
    out = [START, ""] + table + ["| " + k + " | " + v + " |" for k, v in rows]
    out += ["", MORE_OPEN.format("More about this page (" + ", ".join(k[:1].lower() + k[1:] for k, _ in more)
                                 + ")"), ""] + table + ["| " + k + " | " + v + " |" for k, v in more]
    out += ["", "</details>"]
    for part in (cluster_note(rel, meta, descs), takeaway_lines(rel, reviewed, text)):
        if part:
            out += [""] + part
    return "\n".join(out + ["", END])


def place(text: str, block: str) -> str:
    """The page with its card: replaced in place when it has one; else where its
    hand-written card table was (whose rows now live in doc_meta.yaml); else at the end of
    the introduction (above the learning-path callout, the first rule or the first H2)."""
    if META_RE.search(text):
        return META_RE.sub(lambda m: block, text, count=1)
    lines = text.split("\n")
    fl = fences(lines)
    h1 = next((i for i, (ln, f) in enumerate(zip(lines, fl)) if not f and ln.startswith("# ")), -1)
    rows = [i for i, (ln, f) in enumerate(zip(lines, fl)) if not f and i > h1 and CARD_ROW_RE.match(ln)]
    if rows:
        a = rows[0]
        while a > 0 and lines[a - 1].startswith("|"):
            a -= 1
        b = rows[0]
        while b + 1 < len(lines) and lines[b + 1].startswith("|"):
            b += 1
        return "\n".join(lines[:a] + block.split("\n") + lines[b + 1:])
    at = len(lines)
    for i in range(h1 + 1, len(lines)):
        if fl[i]:
            continue
        if lines[i].startswith("<!-- path-reference:start") or re.match(r"^(---+\s*|## .*)$", lines[i]):
            at = i
            break
    head = "\n".join(lines[:at]).rstrip("\n")
    tail = "\n".join(lines[at:])
    return head + "\n\n" + block + "\n\n" + tail if tail else head + "\n\n" + block + "\n"


# ----------------------------------------------------------------------------- folds


def unfold(text: str) -> str:
    """The page without the folds this script wrote (an opening line, its blank line, the
    matching closing line and the blank line before it)."""
    lines = text.split("\n")
    fl = fences(lines)
    drop: set[int] = set()
    stack: list[int | None] = []
    for i, (ln, f) in enumerate(zip(lines, fl)):
        if f:
            continue
        if FOLD_OPEN_RE.match(ln):
            stack.append(i)
            drop.add(i)
            if i + 1 < len(lines) and not lines[i + 1].strip():
                drop.add(i + 1)
        elif re.match(r"^<details\b", ln):
            stack.append(None)
        elif ln.strip() == FOLD_CLOSE and stack:
            if stack.pop() is not None:
                drop.add(i)
                if i > 0 and not lines[i - 1].strip():
                    drop.add(i - 1)
    return "\n".join(ln for i, ln in enumerate(lines) if i not in drop)


def table_runs(lines: list[str], a: int, b: int) -> list[tuple[int, int]]:
    fl = fences(lines)
    runs, start = [], None
    for i in range(a, b + 1):
        is_row = i < b and not fl[i] and lines[i].startswith("|")
        if is_row and start is None:
            start = i
        elif not is_row and start is not None:
            runs.append((start, i))
            start = None
    return runs


def fold_summary(body: list[str]) -> str:
    runs = table_runs(body, 0, len(body))
    rows = sum(max(0, e - s - 2) for s, e in runs)
    parts = [format(bsn.word_count("\n".join(body)), ",") + " words"]
    if len(runs) == 1:
        parts.append("a table of " + format(rows, ",") + " rows")
    elif runs:
        parts.append(str(len(runs)) + " tables, " + format(rows, ",") + " rows")
    return "Show this section (" + " and ".join(parts) + ")"


def wrap(lines: list[str], a: int, b: int, summary: str) -> list[str]:
    """lines[a:b] in a fold, leading and trailing blank lines and a trailing rule kept outside."""
    while a < b and not lines[a].strip():
        a += 1
    end = b
    while end > a and (not lines[end - 1].strip() or re.match(r"^---+\s*$", lines[end - 1])):
        end -= 1
    if end <= a:
        return lines
    return (lines[:a] + [FOLD_OPEN.format(summary), ""] + lines[a:end] + ["", FOLD_CLOSE]
            + ([""] if end < len(lines) and lines[end].strip() else []) + lines[end:])


def before_signoff(lines: list[str], a: int, b: int) -> int:
    """The end of a section's body, leaving out a closing rule and the short sign-off
    after it (the page's "Last updated" lines) when the section is the last one."""
    fl = fences(lines)
    rules = [i for i in range(a, b) if not fl[i] and re.match(r"^---+\s*$", lines[i])]
    if rules:
        tail = [ln for ln in lines[rules[-1] + 1:b] if ln.strip()]
        if len(tail) <= 4 and not any(cdl.ATX_RE.match(ln) for ln in tail):
            return rules[-1]
    return b


def apply_folds(text: str, specs: list[str], rel: str) -> str:
    lines = unfold(text).split("\n")
    for spec in specs:
        kind, _, anchor = spec.partition(":")
        r = section_range(lines, anchor)
        if r is None:
            raise Invalid(rel + ": fold '" + spec + "': no heading with that anchor")
        _, a, b, _ = r
        if kind == "section":
            b = before_signoff(lines, a, b)
            lines = wrap(lines, a, b, fold_summary(lines[a:b]))
        else:
            for s, e in reversed(table_runs(lines, a, b)):
                rows = e - s - 2
                if rows > FOLD_ROWS:
                    lines = wrap(lines, s, e, "Show the table (" + format(rows, ",") + " rows)")
    return "\n".join(lines)


def fold_candidates(rel: str, text: str, specs: list[str]) -> list[tuple[str, str, int]]:
    """Back-matter sections (appendix, glossary) over two screens that are not folded:
    (anchor, heading, rows-equivalent), where a prose line counts as one row."""
    lines = unfold(text).split("\n")
    folded = {s.partition(":")[2] for s in specs}
    out = []
    for i, level, slug, head in headings(lines):
        if level != 2 or not re.match(r"^(appendix|glossary)\b", head, re.I) or slug in folded:
            continue
        _, a, b, _ = section_range(lines, slug)
        size = sum(1 for ln in lines[a:b] if ln.strip() and not re.match(r"^\|?\s*:?-{3,}", ln))
        if size > FOLD_ROWS:
            out.append((slug, head, size))
    return out


# ----------------------------------------------------------------------------- build


def build(hist: History | None) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """(current text, expected text) of every page in scope, and the problems found."""
    files = tracked_files()
    refs, paths = scope(files)
    meta = load(META)
    reviewed = load(TAKEAWAYS)
    draft = load(DRAFT)
    problems = validate(meta, refs, paths)
    descs = bsn.index_entries()
    current = {rel: bsn.page_text(rel) for rel in refs + paths}
    problems += validate_takeaways(reviewed, TAKEAWAYS, current, draft=False)
    problems += validate_takeaways(draft, DRAFT, current, draft=True)
    if problems:
        return current, {}, problems
    expected = {}
    for rel in refs + paths:
        text = current[rel]
        outside = META_RE.sub("", text).split("\n")
        stray = [i + 1 for i, (ln, f) in enumerate(zip(outside, fences(outside))) if not f and CARD_ROW_RE.match(ln)]
        if stray and META_RE.search(text):
            problems.append(rel + ": a hand-written card row outside the header card; move it to " + META)
            continue
        try:
            new = place(text, card(rel, text, meta, reviewed, descs, hist))
            new = apply_folds(new, meta["pages"][rel].get("fold") or [], rel)
        except Invalid as e:
            problems.append(str(e))
            continue
        expected[rel] = new
    return current, expected, problems


def write(expected: dict[str, str], current: dict[str, str]) -> int:
    n = 0
    for rel, text in expected.items():
        if text == current[rel]:
            continue
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            print("NOTE: " + rel + " is missing from disk (read from the git index); not written. "
                  "Stage the new text with git hash-object -w and git update-index.", file=sys.stderr)
            continue
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        n += 1
    return n


def report(current: dict[str, str], expected: dict[str, str], hist: History) -> None:
    files = tracked_files()
    refs, paths = scope(files)
    meta = load(META)
    draft = load(DRAFT)
    reviewed = load(TAKEAWAYS)
    pages = meta["pages"]
    print("Header cards: " + str(len(refs)) + " root references, " + str(len(paths)) + " learning paths")
    for f, lab in CARD_FIELDS:
        print("  '" + lab + "' row: " + str(sum(1 for r in refs if pages[r].get(f))) + " references, "
              + str(sum(1 for r in paths if pages[r].get(f))) + " learning paths")
    starts = [len(LINK_RE.findall(pages[r].get("start_at") or "")) for r in refs + paths]
    print("  'Start at' links per page: at most " + str(max(starts)) + " (limit " + str(START_AT_MAX) + ")")
    print("  'Matching learning path' row: " + str(sum(1 for r in refs if pages[r].get("learning_path"))) + " references")
    levels: dict[str, int] = {}
    for rel in refs + paths:
        levels[pages[rel]["level"]] = levels.get(pages[rel]["level"], 0) + 1
    print("  levels: " + ", ".join(k + " " + str(v) for k, v in sorted(levels.items(), key=lambda x: LEVELS.index(x[0]))))
    for name, group in (("references", refs), ("learning paths", paths)):
        w = sorted(bsn.word_count(current[r]) for r in group)
        mins = sorted(max(1, round(x / WPM)) for x in w)
        print("Reading time, " + name + ": words median " + format(int(statistics.median(w)), ",")
              + ", p90 " + format(w[int(0.9 * (len(w) - 1))], ",") + ", max " + format(w[-1], ",")
              + "; minutes median " + str(statistics.median(mins)) + ", max " + str(mins[-1]))
    corrections = meta.get("corrections") or {}
    with_fix = [r for r in refs + paths if pages[r].get("corrected")]
    print("Last corrected: " + str(len(with_fix)) + " pages name their last recorded correction, "
          + str(sum(1 for p in with_fix if pages[p].get("corrected_what"))) + " of them with a "
          "page-specific description; " + str(sum(1 for p in with_fix if corrections[pages[p]["corrected"]].get("attack")))
          + " print an ATT&CK release (edits to ATT&CK content)")
    for cid, c in corrections.items():
        print("  " + cid + " (" + c["date"] + ", #" + str(c["pr"]) + (", ATT&CK " + c["attack"] if c.get("attack") else "")
              + "): " + str(sum(1 for p in with_fix if pages[p]["corrected"] == cid)) + " pages")
    reviews = meta.get("reviews") or {}
    with_review = [r for r in refs + paths if pages[r].get("reviewed")]
    print("Last reviewed: " + str(len(with_review)) + " pages have a review the owner recorded, "
          + str(len(refs) + len(paths) - len(with_review)) + " show 'No review recorded yet'")
    for rid, r in reviews.items():
        print("  " + rid + " (" + r["date"] + "): "
              + str(sum(1 for p in with_review if pages[p]["reviewed"] == rid)) + " pages")
    n_due = sum(1 for p in with_review if due(reviews[pages[p]["reviewed"]]["date"], hist.last_changed(p, current[p])))
    print("  due for review (text changed more than " + str(DUE_DAYS) + " days after the review): " + str(n_due))
    clusters = meta.get("clusters") or {}
    print("Which page should I read? notes: " + str(len(clusters)) + " clusters, "
          + str(sum(len(c["pages"]) for c in clusters.values())) + " pages")
    folds = [(r, s) for r in refs + paths for s in pages[r].get("fold") or []]
    n_wrapped = sum(len(FOLD_OPEN_RE.findall(expected.get(r, ""))) for r in refs + paths)
    print("Folds: " + str(len(folds)) + " fold entries on " + str(len({r for r, _ in folds}))
          + " pages, " + str(n_wrapped) + " <details> written")
    cands = [(r, c) for r in refs + paths for c in fold_candidates(r, current[r], pages[r].get("fold") or [])]
    print("  appendix and glossary sections over two screens (" + str(FOLD_ROWS) + " lines) not folded: "
          + str(len(cands)))
    for r, (slug, head, size) in cands:
        print("    " + r + " #" + slug + " (" + head + ", " + str(size) + " lines)")
    dp = draft.get("pages") or {}
    batches: dict[int, int] = {}
    for e in dp.values():
        batches[e.get("batch", 0)] = batches.get(e.get("batch", 0), 0) + 1
    print("Key takeaways: " + str(len(reviewed.get("pages") or {})) + " pages reviewed and rendered; "
          + str(len(dp)) + " drafted (" + str(sum(len(e["items"]) for e in dp.values()))
          + " takeaways), owner review pending, in batches: "
          + ", ".join("batch " + str(k) + " " + str(v) for k, v in sorted(batches.items())))


# ----------------------------------------------------------------------------- self-test


def self_test() -> int:
    fails = []
    sample = {"reviews": {"r1": {"date": "2026-01-02", "attack": "v19.2", "pr": 7, "what": "a: b # c"}},
              "pages": {"A.md": {"audience": "x \"y\" | z", "fold": ["section:a", "tables:b"],
                                 "items": [{"text": "T.", "from": "#a", "quote": "q"}]}},
              "empty": {}, "null": None}
    text = "\n".join(["# comment", ""] + dump_yaml(sample)) + "\n"
    if parse_yaml(text, "sample") != sample:
        fails.append("YAML round trip")
    for bad in ("a:\n\tb: 1\n", "a: plain words\n", "a:\n   b: 1\n", "a: 1\na: 2\n", "- 1\n  - 2\n"):
        try:
            parse_yaml(bad, "bad")
            fails.append("accepted bad YAML: " + repr(bad))
        except Invalid:
            pass
    page = "\n".join(["# P", "", "Intro.", "", "## Appendix A", "", "text", "",
                      "| a | b |", "|---|---|"] + ["| %d | x |" % i for i in range(45)] +
                     ["", "---", "", "## Next", "", "```", "<details>", "```", ""])
    once = apply_folds(page, ["section:appendix-a"], "P")
    twice = apply_folds(once, ["section:appendix-a"], "P")
    if once == page or once != twice or unfold(once) != page:
        fails.append("section fold is not idempotent or does not unfold")
    if "<details>\n```" not in once or once.count(FOLD_CLOSE) != 1:
        fails.append("fold touched fenced code")
    tabled = apply_folds(page, ["tables:appendix-a"], "P")
    if "Show the table (45 rows)" not in tabled or unfold(tabled) != page:
        fails.append("table fold")
    block = START + "\n\n| | |\n|---|---|\n| Level | Beginner |\n\n" + END
    p1 = place("# T\n\n> s\n\n| | |\n|---|---|\n| Read this when | x |\n\n---\n\n## A\n", block)
    if p1 != place(p1, block) or "Read this when" in META_RE.sub("", p1):
        fails.append("card placement")
    raw = "# T\n\n> s\n\n| | |\n|---|---|\n| Read this when | three more words |\n\nBody text here.\n"
    if reading_row(raw) != reading_row(place(raw, block)):
        fails.append("reading time moves when the card rows move into the block")
    if not due("2026-01-01", "2026-04-02") or due("2026-01-01", "2026-04-01"):
        fails.append("due rule (more than 90 days)")
    m = {"corrections": {"c1": {"date": "2026-01-02", "pr": 5, "what": "a tool renamed"},
                         "c2": {"date": "2026-01-03", "pr": 6, "what": "IDs re-keyed", "attack": "v19.2"}},
         "reviews": {},
         "pages": {"A.md": {"audience": "x", "level": "Intermediate", "corrected": "c1",
                            "start_at": "[a](#a), [b](#b), [c](#c), [d](#d)"}}}
    if not any("start_at has 4 links" in p for p in validate(m, ["A.md"], [])):
        fails.append("start_at limit of " + str(START_AT_MAX) + " links not enforced")
    e = m["pages"]["A.md"]
    if corrected_row(e, m["corrections"]) != ("Last corrected", "2026-01-02, a tool renamed (" + pr_link(5) + ")") \
            or "ATT&CK v19.2" not in corrected_row({"corrected": "c2"}, m["corrections"])[1]:
        fails.append("correction row (ATT&CK release only for ATT&CK edits)")
    m["corrections"]["c3"] = {"date": "2026-01-04", "pr": 68, "what": "page created", "label": "Added"}
    if corrected_row({"corrected": "c3"}, m["corrections"]) != ("Added", "2026-01-04 (" + pr_link(68) + ")"):
        fails.append("an Added row says only its date and pull request")
    e["read_when"] = "starting out"
    if not any("read_when starts with a lower-case letter" in p for p in validate(m, ["A.md"], [])):
        fails.append("read_when capital letter not enforced")
    del e["read_when"]
    if review_row(e, {}, "2027-06-01") != "No review recorded yet":
        fails.append("a correction must not count as a review or start the due clock")
    if voice_hits("A seamless tool.") != ["hype:seamless"] or voice_hits("Plain words."):
        fails.append("voice rules on takeaways")
    print("self-test: " + ("OK" if not fails else "FAILED: " + "; ".join(fails)))
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="exit 1 on drift or an invalid entry")
    mode.add_argument("--report", action="store_true", help="cards, reading times, reviews, folds, takeaways")
    mode.add_argument("--self-test", action="store_true",
                      help="YAML reader, folds, placement, due rule, Start at limit, correction and review rows")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    hist = History()
    current, expected, problems = build(hist)
    if problems:
        print("DOC META: " + str(len(problems)) + " problem(s):")
        for p in problems:
            print("  " + p)
        return 1
    stale = sorted(r for r in expected if expected[r] != current[r])
    if args.check:
        if stale:
            print("DOC META DRIFT: run `python scripts/build_doc_meta.py` and commit the result:")
            for r in stale:
                print("  stale    " + r)
            return 1
        n_take = len(load(TAKEAWAYS).get("pages") or {})
        print("OK: header cards match " + META + " (" + str(len(expected)) + " pages, "
              + str(sum(len(FOLD_OPEN_RE.findall(t)) for t in expected.values())) + " folds, "
              + str(n_take) + " pages with reviewed takeaways); drafts in " + DRAFT + " are valid")
        return 0
    if args.report:
        report(current, expected, hist)
        return 0
    n = write(expected, current)
    print("build_doc_meta.py: wrote " + str(n) + " page(s); " + str(len(stale) - n) + " not written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
