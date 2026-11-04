#!/usr/bin/env python3
"""Voice lint for the hand-written pages: the mechanical half of docs/VOICE.md.

Scope: every hand-written Markdown page, which is the tracked Markdown at the repository
root (README, HOME, _coverpage, _navbar, _sidebar and every root reference), under
guides/, disciplines/, case-studies/, tools-research/ and docs/, and every page that
build_site_nav.hand_written() returns: tools/, platforms/, languages/, paradigms/,
frameworks/, commands/, formats/, databases/, ai-tooling/, research/, data/, scripts/ and
the hand-written pages under detections/ (in_scope()). The trees other generators write
(mitre/, techniques/, detections/strategies/, scores/, hubs/, navigator/index.md) are out
of scope; their generators own their wording. Two rules, agent-note and em-dash, ignore
this scope and cover more (below).

Rules (the rule key is what the baseline counts):

  emoji         A pictographic emoji: U+1F000..U+1FAFF, the emoji code points in
                U+2300..U+2BFF (warning sign, ballot box with check, heavy check mark,
                the small squares U+25FD and U+25FE and so on) and U+FE0F, the selector that forces emoji presentation.
                Typographic symbols that are not emoji (the check mark U+2713, the
                star U+2605, arrows, box drawing, (c), (R), TM) pass.
  exclamation   A '!' that ends a sentence, in prose. Code (fenced, inline, or indented
                four spaces outside a list item), URLs, HTML tags and comments are not
                prose, but alt and title attribute values are; '!=', '![image]' and
                '<!--' never match.
  hype:<word>   A word from HYPE below, in prose, matched case-insensitively on word
                boundaries with its inflections ("leverages", "leveraged",
                "empowering", "comprehensively"), each counted under the listed word.
                A hyphenated word also matches with a space in place of the hyphen
                ("cutting edge", "battle tested"), except the words in SPACED_EXCEPT
                ("one stop", "must have", "next level"), whose spaced forms are plain
                English. Proper nouns that contain one of the words are allowed through
                ALLOW (the ATT&CK campaign C0029 "Cutting Edge", Seamless SSO, the
                Revolutionary Guard, Oracle's Unbreakable Enterprise Kernel).
  count         A hand-typed headline count in prose: "<N> references", "<N> guides",
                "<N> paths" or "<N> pages", the noun in any case ("## 140 References")
                and not after "Level " (a course level), with at most one word between the number
                and the noun ("140 in-depth references", "47 discipline paths") and
                bold or italic markers allowed around the number or that word
                ("**140** references"). Counts belong in script output: text between
                a script-written marker pair, `<!-- name:start ... -->` and
                `<!-- name:end -->`, is skipped.
  agent-note    A drafting or process note left in page text by an assistant or a
                workflow: a search-tool name or budget ("search budget was
                exhausted"), a session stamp ("this turn", "live-verified",
                "re-verified live this run", "in this research"), "workflow
                agents", "compiled from prior knowledge", "rely on established
                knowledge", and notes to itself ("verify if seen elsewhere",
                "confirm before publishing", "confirm slug before use"), or
                "drafted with an AI". It is not a fact for the reader. Unlike the rules above it covers every
                tracked Markdown file, generated or hand-written, whatever in_scope()
                says, matches code and prose alike, and has no baseline: one hit
                fails the gate.
  em-dash       U+2014 anywhere in any tracked text file: Markdown, JSON, YAML, Python,
                dotfiles, generated or hand-written, code and prose alike (git ls-files,
                less the blobs git treats as binary). Use a colon, a comma, parentheses
                or a new sentence; never a hyphen pair or an en dash as a stand-in. Like
                agent-note it has no baseline: one hit fails the gate. The one exemption
                is upstream data: in a JSONL row under UPSTREAM_DATA, a dash inside a
                name, description, definition or mitigation value (UPSTREAM_KEYS, at any
                depth) is the upstream text, reproduced verbatim.

Upstream text is not voice debt. Object names and quoted descriptions from ATT&CK,
CAPEC, CWE, ATLAS, D3FEND, Engage and F3 are reproduced verbatim (docs/VOICE.md), so a
'!' or hype word is skipped when the words around it match the name,
description or definition fields of the upstream datasets under data/ (UPSTREAM_DATA):
six words or more as part of any such value, three to five words only as a whole name.

The baseline (scripts/baselines/voice.json) records the hits that existed when the
lint was introduced, as file -> rule -> count, plus the list of rules that were checked
when it was written. The gate fails when a (file, rule) count grows past its baseline,
so new copy must follow the guide while the existing long references are cleaned up in
later passes. It reports, but does not fail on, baseline entries that have since
shrunk. The gate also fails when the word list in docs/VOICE.md and HYPE below
disagree, so the guide and the lint stay in step.

The baseline only shrinks, and two checks enforce that:

  --update-baseline   writes min(old, current) for every (file, rule), drops entries
                      that reached zero, and refuses (exit 1) when a count would rise or
                      a new (file, rule) entry would appear. --allow-growth overrides
                      the refusal; it exists for adding a rule (a new word in HYPE),
                      whose existing hits must be recorded once.
  --base REF          also compares the baseline with the one at git REF (CI passes the
                      pull request's base branch) and fails when any rule's total rises.
                      A rule that REF did not check yet is exempt, so adding a word to
                      HYPE does not fail; raising an existing rule's debt does, even
                      with --allow-growth. Totals per rule, not per file, so renaming a
                      page moves its entries without failing.

Usage:
    python scripts/check_voice.py                    # gate (exit 1 on a new hit)
    python scripts/check_voice.py --base REF         # gate, plus baseline vs git REF
    python scripts/check_voice.py --report           # also list every hit with its line
    python scripts/check_voice.py --summary          # per-rule totals only
    python scripts/check_voice.py --update-baseline  # lower the baseline to the hits left
    python scripts/check_voice.py --update-baseline --allow-growth  # record a new rule
    python scripts/check_voice.py FILE.md ...        # check only these files, no baseline
    python scripts/check_voice.py --self-test        # planted cases (SELF_TEST) must hit or pass
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_bytes, read_text, tracked_files  # noqa: E402
import build_site_nav as bsn  # noqa: E402  (hand_written(): the hand-written pages)

BASELINE = os.path.join(ROOT, "scripts", "baselines", "voice.json")
# The root pages and the folders scoped before build_site_nav.hand_written() was used; the
# root keeps the generated _sidebar, _navbar and explore pages in scope, as it always has.
SCOPE_RE = re.compile(r"^(?:[^/]+|(?:guides|disciplines|case-studies|tools-research|docs)/.+)\.md$")


def in_scope_file(rel: str) -> bool:
    """A hand-written page: SCOPE_RE or build_site_nav.hand_written()."""
    return bool(SCOPE_RE.match(rel)) or bool(bsn.hand_written([rel]))

# Marketing and vague-superlative words. Each says how the writer feels about a thing,
# not what the thing does. docs/VOICE.md lists the same words; keep the two in step.
# Each word is matched with its inflections (FORMS: "leverages", "leveraged",
# "empowering", "comprehensively") and, unless it is in SPACED_EXCEPT, with a space in
# place of each hyphen ("cutting edge"). Every form counts under the listed word's rule
# key (hype:leverage). "robust", "unlock" and "ultimate" are left out on purpose: each
# has a technical sense (adversarial robustness, unlocking a volume or an account) that
# the guide allows.
HYPE = (
    "comprehensive", "powerful", "cutting-edge", "state-of-the-art", "world-class",
    "best-in-class", "industry-leading", "enterprise-grade", "military-grade",
    "next-level", "game-changing", "game-changer", "revolutionary", "revolutionize",
    "groundbreaking", "unparalleled", "seamless", "effortless", "supercharge",
    "blazing-fast", "lightning-fast", "unbreakable", "hack-proof", "unhackable",
    "one-stop", "must-have", "battle-tested", "leverage", "empower",
)
# Spaced spellings that are ordinary English ("one stop on the route", "every finding
# must have an owner", "escalate to the next level"): only the hyphenated form counts.
SPACED_EXCEPT = ("one-stop", "must-have", "next-level")


def inflections(word: str) -> set[str]:
    """The word plus -s, -ly and the -ed/-ing forms ("leverage": leverages, leveraged,
    leveraging, leveragely). A form that is not an English word costs nothing."""
    out = {word, word + "s", word + "ly"}
    if word.endswith("e"):
        out |= {word + "d", word[:-1] + "ing"}
    else:
        out |= {word + "ed", word + "ing"}
    return out


FORMS = {f: w for w in HYPE for f in inflections(w)}


def _form_pattern(form: str) -> str:
    sep = "-" if FORMS[form] in SPACED_EXCEPT else "[- ]"
    return sep.join(re.escape(part) for part in form.split("-"))


HYPE_RE = re.compile(r"(?<![\w-])(" + "|".join(_form_pattern(f) for f in
                     sorted(FORMS, key=len, reverse=True)) + r")(?![\w-])", re.I)


def hype_word(match_text: str) -> str:
    """The listed word a matched form belongs to: "Leveraged" -> "leverage"."""
    return FORMS[match_text.lower().replace(" ", "-")]


# Proper nouns and product names that contain a hype word. Matched case-sensitively
# against the text around the hit.
ALLOW = (
    re.compile(r"Cutting Edge"),               # ATT&CK campaign C0029 (Ivanti VPN, 2023-24)
    re.compile(r"Seamless SSO"),               # Microsoft Entra Seamless Single Sign-On
    re.compile(r"Revolutionary Guard"),        # Islamic Revolutionary Guard Corps
    re.compile(r"Unbreakable Enterprise Kernel"),  # Oracle Linux's UEK kernel line
    re.compile(r"Cryptography: State-of-the-Art"),  # a 34C3 talk title (research/CONFERENCE_TALKS.md)
)

# Escapes keep this file free of the characters it looks for.
EM_DASH = "\u2014"
EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF\uFE0F"
    "\u231A\u231B\u2328\u23CF\u23E9-\u23F3\u23F8-\u23FA"
    "\u2600-\u2604\u260E\u2611\u2614\u2615\u2618\u261D\u2620\u2622\u2623\u2626\u262A"
    "\u262E\u262F\u2638-\u263A\u2640\u2642\u2648-\u2653\u265F\u2660\u2663\u2665\u2666"
    "\u2668\u267B\u267E\u267F\u2692-\u2697\u2699\u269B\u269C\u26A0\u26A1\u26A7\u26AA"
    "\u26AB\u26B0\u26B1\u26BD\u26BE\u26C4\u26C5\u26C8\u26CE\u26CF\u26D1\u26D3\u26D4"
    "\u26E9\u26EA\u26F0-\u26F5\u26F7-\u26FA\u26FD"
    "\u2702\u2705\u2708-\u270D\u270F\u2712\u2714\u2716\u271D\u2721\u2728\u2733\u2734"
    "\u2744\u2747\u274C\u274E\u2753-\u2755\u2757\u2763\u2764\u2795-\u2797\u27A1\u27B0"
    "\u27BF\u2B05-\u2B07\u2B1B\u2B1C\u2B50\u2B55\u203C\u2049\u25FD\u25FE]")
# A '!' directly after a word or closing bracket, followed by space, end of line or
# closing punctuation. '!=' and '![' fail the lookahead, '<!--' the lookbehind, and a
# '!' right before a closing quote belongs to the quotation, which keeps its own
# punctuation.
EXCLAIM_RE = re.compile(r"(?<=[\w)\]*_])!+(?=[\s)\]*_|]|$)")
# The nouns match in any case, so a title-case headline ("## 140 References") counts. A
# number after "Level " names a course level (TryHackMe "Level 2 Paths"); a number that
# closes a range ("1-2 pages") describes a length, not the library; magnitudes ("3
# billion pages") are quoted figures about someone else's corpus.
EMPH = r"(?:\*{1,2}|_{1,2})?"                   # bold or italic markers: "**140** references"
COUNT_RE = re.compile(r"(?<![\w.,\u2013-])(?<![Ll]evel )" + EMPH +
                      r"(\d+(?:,\d{3})*)(?![\d,])\+?" + EMPH +
                      r"\s+(?!(?:hundred|thousand|million|billion)\b)"
                      r"(?:" + EMPH + r"[A-Za-z][\w-]*" + EMPH + r"\s+)?"
                      r"((?i:references|guides|paths|pages))\b")
# Agent process notes (rule agent-note). Phrases an assistant or a workflow wrote about
# its own process, never about the subject: the search tool's name and budget, session
# stamps, notes to itself. "this turn" must not run on into "this turns" or
# "this turn-based"; `WebSearchTool` (an SDK class) is not the bare tool name. A bare
# "this run" is ordinary English in the procedure guides ("wiped before this run"), so
# it counts only after "search", "live" or "budget for". A first-person verification
# note ("I could not verify ...") is a process note; so is a subjectless "could not
# verify" (sentence start, list item, after a semicolon). A product with a subject
# ("Invicti could not verify the fix") is a vendor status and passes, and "could not
# confirm" stays legal reader guidance. The passive forms of the same note ("NOT
# confirmed from public docs", "could not be verified") are process notes too.
AGENT_NOTE_RE = re.compile(
    r"\bWebSearch\b"
    r"|\bthis turn\b(?!-)"
    r"|\bworkflow agents\b"
    r"|\blive[- ]verified\b"
    r"|\bcompiled from (?:high-confidence )?prior knowledge\b"
    r"|\bverify if seen elsewhere\b"
    r"|\bdrafted (?:with|by) an? (?:AI|LLM)\b"
    r"|\bsearch(?:-session)? budget\b"
    r"|\bbudget (?:for this run )?was exhausted\b"
    r"|\b(?:search|live|budget for) this run\b"
    r"|\bre-(?:verified|confirmed) live\b"
    r"|\blive re-verification\b"
    r"|\bnot confirmable via search\b"
    r"|\bin this research\b"
    r"|\bnot verified here\b"
    r"|\brely on established knowledge\b"
    r"|\bconfirm before publishing\b"
    r"|\bconfirm slug before use\b"
    r"|\bverify exact app ID\b"
    r"|\bI (?:could not|couldn['\u2019]t|was unable to|did not|didn['\u2019]t) (?:verify|confirm)\b"
    r"|(?<![A-Za-z] )\bcould not verify\b"
    r"|\bunverified publicly\b"
    r"|\bnot confirmed from (?:public|official) docs\b"
    r"|\bcould not be verified\b",
    re.I)
# CHANGELOG entries are dated records: a count there is true as of its date and does
# not go stale the way a headline does.
COUNT_EXEMPT = ("CHANGELOG.md",)
# Names that end in '!' (the SANS OUCH! newsletter).
EXCLAIM_ALLOW = re.compile(r"\bOUCH!", re.I)

FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
MARKER_START_RE = re.compile(r"<!--\s*([\w-]+):start\b")
INLINE_CODE_RE = re.compile(r"(`+)(?:(?!\1).)+?\1")
LINK_TARGET_RE = re.compile(r"\]\([^)\s]*(?:\s+\"[^\"]*\")?\)")
URL_RE = re.compile(r"<?https?://[^\s<>)\]|]+>?")
TAG_RE = re.compile(r"</?[A-Za-z][^<>]*>")
# alt and title values are text a reader reads (image descriptions, tooltips).
TAG_TEXT_RE = re.compile(r"""\b(?:alt|title)\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)
LIST_ITEM_RE = re.compile(r"^ *(?:[-*+]|\d{1,9}[.)])( +|$)")


def blank(m: re.Match) -> str:
    """Replace a match with spaces, keeping newlines so line numbers survive."""
    return re.sub(r"[^\n]", " ", m.group(0))


def blank_tag(m: re.Match) -> str:
    """Blank an HTML tag but keep its alt and title values, which readers read."""
    tag = m.group(0)
    out = [" "] * len(tag)
    for a in TAG_TEXT_RE.finditer(tag):
        g = 1 if a.group(1) is not None else 2
        out[a.start(g):a.end(g)] = tag[a.start(g):a.end(g)]
    return "".join(out)


def strip_fences(text: str) -> str:
    out, fence = [], None
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if fence:
            out.append("")
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence):
                fence = None
            continue
        if m:
            fence = m.group(1)
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def strip_markers(text: str) -> str:
    """Blank every region between `<!-- name:start ... -->` and `<!-- name:end -->`."""
    pos, out = 0, []
    while True:
        m = MARKER_START_RE.search(text, pos)
        if not m:
            break
        end = re.compile(r"<!--\s*" + re.escape(m.group(1)) + r":end\s*-->").search(text, m.end())
        if not end:
            break
        out.append(text[pos:m.start()])
        out.append(re.sub(r"[^\n]", " ", text[m.start():end.end()]))
        pos = end.end()
    out.append(text[pos:])
    return "".join(out)


def prose(text: str) -> str:
    """The text a reader reads as sentences: no code, comments, URLs or link targets,
    and of an HTML tag only its alt and title values.

    A line indented four spaces is an indented code block only outside a list item.
    Inside one it continues the item (a second paragraph, a nested list) and is prose,
    unless it is indented four columns past the item's text after a blank line, which
    is a code block inside the item.
    """
    text = strip_fences(text)
    text = COMMENT_RE.sub(blank, text)
    lines = []
    content = None                  # column where the open list item's text starts
    prev_blank, prev_code = True, False
    for line in text.split("\n"):
        if not line.strip():
            lines.append(line)
            prev_blank = True
            continue
        indent = len(line) - len(line.lstrip(" "))
        item = LIST_ITEM_RE.match(line)
        if item and (content is None or indent < content + 4):
            content = len(item.group(0)) + (0 if item.group(1) else 1)
        elif content is not None and indent < content and (prev_blank or line.lstrip().startswith("#")):
            content = None                         # a block after the list ends it
        if content is None:
            code = line.startswith("    ") and not line.lstrip().startswith(("-", "*", "|", ">")) \
                and not re.match(r"\s*\d+\.", line)
        else:
            code = not item and indent >= content + 4 and (prev_blank or prev_code)
        prev_blank, prev_code = False, code
        if code:
            lines.append("")                       # indented code block
            continue
        line = INLINE_CODE_RE.sub(blank, line)
        line = LINK_TARGET_RE.sub(lambda m: "]" + " " * (len(m.group(0)) - 1), line)
        line = URL_RE.sub(blank, line)
        line = TAG_RE.sub(blank_tag, line)
        lines.append(line)
    return "\n".join(lines)


def allowed(line: str, start: int, end: int, patterns) -> bool:
    """True when the hit at line[start:end] sits inside an allowed name."""
    for rx in patterns:
        for m in rx.finditer(line):
            if m.start() <= start and end <= m.end():
                return True
    return False


# Upstream text. Object names and quoted descriptions from ATT&CK, CAPEC, CWE, ATLAS,
# D3FEND, Engage and F3 are reproduced verbatim and never edited for voice
# (docs/VOICE.md). A word, em-dash or '!' is upstream text when the words around it,
# inside its table cell, appear in the name, description or definition fields of the
# upstream datasets under UPSTREAM_DATA, after both sides drop link targets, citations,
# emphasis and case. Three words of context at least, so a lone word never matches. A
# match of fewer than SHORT_MATCH words must equal a whole upstream name ("Leverage
# Alternate Encoding", CAPEC-267): that short a part of a description is stock phrasing
# ("Adversaries may leverage"), which team-written copy can repeat.
UPSTREAM_DATA = ("data/attack/", "data/ai/", "data/fraud/", "data/weaknesses/", "data/engage/")
# "mitigation" is the CWE mitigation text (data/weaknesses/cwe.jsonl) that the generated
# CWE_REFERENCE.md tables quote.
UPSTREAM_KEYS = ("name", "description", "definition", "mitigation")
_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_LEFT_RE = re.compile(r"(?:\S+\s+){0,6}\S*$")
_RIGHT_RE = re.compile(r"^\S*(?:\s+\S+){0,6}")
SHORT_MATCH = 6
_upstream_values: list[str] | None = None
_upstream_names: set[str] = set()
_upstream_corpus: dict[str, str] = {}


def norm(text: str) -> str:
    text = _MD_LINK_RE.sub(r"\1", _CITATION_RE.sub(" ", text))
    text = re.sub(r"&nbsp;|[\[\]*_`|<>]", " ", text)
    return " ".join(text.split()).lower()


def upstream_values() -> list[str]:
    global _upstream_values
    if _upstream_values is None:
        vals = []
        for f in tracked_files():
            if not (f.startswith(UPSTREAM_DATA) and f.endswith(".jsonl")):
                continue
            for row in (read_text(f) or "").splitlines():
                try:
                    rec = json.loads(row)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                vals.extend(rec[k] for k in UPSTREAM_KEYS if isinstance(rec.get(k), str))
                if isinstance(rec.get("name"), str):
                    _upstream_names.add(norm(rec["name"]))
        _upstream_values = vals
    return _upstream_values


def upstream_corpus(key: str) -> str:
    """The normalized upstream values that contain `key` (lowercase), one per line."""
    if key not in _upstream_corpus:
        _upstream_corpus[key] = "\n".join(norm(v) for v in upstream_values()
                                          if key in v.lower().replace(" ", "-"))
    return _upstream_corpus[key]


def upstream(line: str, start: int, end: int, key: str) -> bool:
    """True when line[start:end] sits inside text copied verbatim from upstream data."""
    lo = line.rfind("|", 0, start) + 1
    hi = line.find("|", end)
    hi = len(line) if hi < 0 else hi
    left = _LEFT_RE.search(line[lo:start]).group(0)
    right = _RIGHT_RE.match(line[end:hi]).group(0)
    hit = line[start:end]
    corpus = upstream_corpus(key)
    if not corpus:
        return False
    # SHORT_MATCH words or more: part of any upstream name, description or definition.
    for a, b in ((left[-60:], right[:60]), (left, ""), ("", right)):
        cand = norm(a + hit + b)
        if len(cand.split()) >= SHORT_MATCH and cand in corpus:
            return True
    # Fewer: the words around the hit, cut at word boundaries, must be a whole name.
    lefts = [left[m.start():] for m in re.finditer(r"(?<!\S)\S", left)] + [""]
    rights = [right[:m.end()] for m in re.finditer(r"\S(?!\S)", right)] + [""]
    for a in lefts:
        for b in rights:
            cand = norm(a + hit + b)
            if 3 <= len(cand.split()) < SHORT_MATCH and cand in _upstream_names:
                return True
    return False


def scan(rel: str, raw: str, em_dash: bool = True) -> list[tuple[str, int, str, str]]:
    """Every hit in one file as (file, line, rule, excerpt). The gate passes
    em_dash=False and runs em_dashes() over every tracked text file instead."""
    hits = []
    raw_lines = raw.split("\n")

    def excerpt(i: int) -> str:
        s = raw_lines[i - 1].strip()
        return s if len(s) <= 110 else s[:107] + "..."

    if em_dash:
        hits.extend(em_dashes(rel, raw))
    for i, line in enumerate(raw_lines, 1):
        for m in EMOJI_RE.finditer(line):
            hits.append((rel, i, "emoji", "U+%04X in: %s" % (ord(m.group(0)), excerpt(i))))
    text = prose(raw)
    word_list = guide_words(raw) if rel == GUIDE_REL else {}
    for i, line in enumerate(text.split("\n"), 1):
        for m in EXCLAIM_RE.finditer(line):
            if allowed(line, m.start() - 4, m.end(), (EXCLAIM_ALLOW,)):
                continue
            if not upstream(line, m.start(), m.end(), "!"):
                hits.append((rel, i, "exclamation", excerpt(i)))
        for m in HYPE_RE.finditer("" if i in word_list else line):
            word = hype_word(m.group(1))
            stem = word[:-1] if word.endswith("e") else word
            if not allowed(line, m.start(), m.end(), ALLOW) and \
                    not upstream(line, m.start(), m.end(), stem):
                hits.append((rel, i, "hype:" + word, excerpt(i)))
    if rel in COUNT_EXEMPT:
        return hits
    for i, line in enumerate(prose(strip_markers(raw)).split("\n"), 1):
        for m in COUNT_RE.finditer(line):
            hits.append((rel, i, "count", '"%s" in: %s' % (m.group(0), excerpt(i))))
    return hits


def _upstream_dashes(value, key: str = "") -> int:
    """U+2014 characters inside the upstream text of a JSON value, at any depth: an
    UPSTREAM_KEYS string value, or a string elsewhere in the row that repeats one verbatim
    (technique_profiles.jsonl lists its detection strategies by their upstream names)."""
    if isinstance(value, dict):
        return sum(_upstream_dashes(v, k) for k, v in value.items())
    if isinstance(value, list):
        return sum(_upstream_dashes(v, key) for v in value)
    if isinstance(value, str) and EM_DASH in value:
        if key in UPSTREAM_KEYS or value in upstream_value_set():
            return value.count(EM_DASH)
    return 0


_upstream_set: set[str] | None = None


def upstream_value_set() -> set[str]:
    global _upstream_set
    if _upstream_set is None:
        _upstream_set = set(upstream_values())
    return _upstream_set


def em_dashes(rel: str, raw: str) -> list[tuple[str, int, str, str]]:
    """Every U+2014 in one file as (file, line, "em-dash", excerpt), code and prose alike.
    In a JSONL row under UPSTREAM_DATA, the dashes inside its upstream name, description,
    definition and mitigation values are upstream text and do not count."""
    hits = []
    upstream_rows = rel.startswith(UPSTREAM_DATA) and rel.endswith(".jsonl")
    for i, line in enumerate(raw.split("\n"), 1):
        n = line.count(EM_DASH)
        if not n:
            continue
        if upstream_rows:
            try:
                n -= _upstream_dashes(json.loads(line))
            except ValueError:
                pass
        s = line.strip()
        for _ in range(max(n, 0)):
            hits.append((rel, i, "em-dash", s if len(s) <= 110 else s[:107] + "..."))
    return hits


def text_files(files: list[str]) -> list[str]:
    """The tracked files git treats as text (git ls-files --eol is not i/-text); a file
    whose blob holds a NUL byte counts as binary when git cannot be asked."""
    try:
        out = subprocess.run(["git", "ls-files", "--eol", "-z"], cwd=ROOT, capture_output=True,
                             check=True).stdout.decode("utf-8")
        binary = {e.split("\t", 1)[1] for e in out.split("\0")
                  if "\t" in e and e.split()[0] == "i/-text"}
    except (OSError, subprocess.CalledProcessError, IndexError):
        binary = {f for f in files if b"\0" in (read_bytes(f) or b"")}
    return [f for f in files if f not in binary]


def agent_notes(rel: str, raw: str) -> list[tuple[str, int, str, str]]:
    """Every agent process note in one file as (file, line, "agent-note", excerpt).
    Raw lines, code included: a note in a code comment is still published."""
    hits = []
    for i, line in enumerate(raw.split("\n"), 1):
        for m in AGENT_NOTE_RE.finditer(line):
            s = line.strip()
            hits.append((rel, i, "agent-note", '"%s" in: %s' % (
                m.group(0), s if len(s) <= 110 else s[:107] + "...")))
    return hits


def markdown_files(files: list[str]) -> list[str]:
    """Every tracked Markdown file, in or out of SCOPE_RE (the agent-note rule's scope)."""
    return [f for f in files if f.endswith(".md")]


GUIDE = os.path.join(ROOT, "docs", "VOICE.md")
GUIDE_REL = "docs/VOICE.md"
GUIDE_SECTION = "## Words we do not use"
GUIDE_ITEM_RE = re.compile(r"^([a-z]+(?:-[a-z]+)*)\\?$")


def guide_words(text: str) -> dict[int, str]:
    """The word list in docs/VOICE.md: line number -> word, one word per line under
    GUIDE_SECTION, each line but the last ending in a backslash (a hard line break, so
    the page shows a plain list in which no word breaks at a hyphen). scan() skips
    these lines for the hype rule, because the guide has to name the words it bans."""
    words, inside = {}, False
    for i, line in enumerate(text.split("\n"), 1):
        if line.startswith("## "):
            inside = line.strip() == GUIDE_SECTION
            continue
        m = GUIDE_ITEM_RE.match(line.strip()) if inside else None
        if m:
            words[i] = m.group(1)
    return words


def guide_drift() -> list[str]:
    """The word list in docs/VOICE.md must name exactly the words in HYPE (inflected
    and spaced forms are matched by the lint, not listed)."""
    try:
        with open(GUIDE, encoding="utf-8") as fh:
            listed = set(guide_words(fh.read()).values())
    except OSError:
        return ["docs/VOICE.md is missing"]
    want = set(HYPE)
    problems = []
    if want - listed:
        problems.append("docs/VOICE.md does not list: " + ", ".join(sorted(want - listed)))
    if listed - want:
        problems.append("docs/VOICE.md lists words check_voice.py does not check: " +
                        ", ".join(sorted(listed - want)))
    return problems


def in_scope(files: list[str]) -> list[str]:
    hand = set(bsn.hand_written(files))
    return [f for f in files if SCOPE_RE.match(f) or f in hand]


# The baselined rules. agent-note and em-dash have no baseline: one hit fails the gate.
RULES = ("count", "emoji", "exclamation") + tuple("hype:" + w for w in HYPE)


def parse_baseline(doc: dict) -> tuple[collections.Counter, set]:
    """(counts, rules checked) from a baseline document. A baseline written before the
    rule list was recorded counts as checking every rule that has an entry."""
    raw = doc.get("hits", {}) if isinstance(doc, dict) else {}
    counts = collections.Counter({(f, r): n for f, d in raw.items() for r, n in d.items()})
    rules = set(doc.get("rules") or {r for _, r in counts}) if isinstance(doc, dict) else set()
    return counts, rules


def load_baseline() -> tuple[collections.Counter, set]:
    try:
        with open(BASELINE, encoding="utf-8") as fh:
            return parse_baseline(json.load(fh))
    except (OSError, ValueError):
        return collections.Counter(), set()


def write_baseline(counts: collections.Counter) -> None:
    base: dict = collections.defaultdict(dict)
    for (f, r), n in sorted(counts.items()):
        if n > 0:
            base[f][r] = n
    os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
    with open(BASELINE, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"_comment": "Voice-lint hits that predate scripts/check_voice.py (file -> rule -> "
                               "count), and the rules checked when it was written. Written by "
                               "scripts/check_voice.py --update-baseline, which only lowers counts; "
                               "CI fails a pull request that raises any rule's total. Fix the copy "
                               "per docs/VOICE.md, then rewrite.",
                   "rules": sorted(RULES), "hits": base}, fh, indent=1, sort_keys=True)
        fh.write("\n")


def update_baseline(counts: collections.Counter, allow_growth: bool) -> int:
    """Lower the baseline to the hits that remain. A rise or a new entry is refused
    unless allow_growth is set (recording the hits of a newly added rule)."""
    old, _ = load_baseline()
    grow = {k: n for k, n in counts.items() if n > old.get(k, 0)}
    if grow and not allow_growth:
        print("FAIL voice: --update-baseline only lowers counts; these would rise "
              "(fix the copy, or pass --allow-growth when adding a rule):")
        for (f, rule), n in sorted(grow.items()):
            print("  %s: %s: %d -> %d" % (f, rule, old.get((f, rule), 0), n))
        return 1
    if allow_growth:
        new = collections.Counter(counts)
    else:
        new = collections.Counter({k: min(n, counts.get(k, 0)) for k, n in old.items()})
    write_baseline(new)
    print("voice: baseline written to %s (%d -> %d hits%s)" % (
        os.path.relpath(BASELINE, ROOT).replace(os.sep, "/"), sum(old.values()),
        sum(v for v in new.values() if v > 0), ", growth allowed" if grow else ""))
    return 0


def base_growth(ref: str) -> list[str] | None:
    """Rules whose baselined total is higher here than at git REF. None when REF has no
    baseline file (the lint is being introduced). A rule REF did not check is exempt."""
    rel = os.path.relpath(BASELINE, ROOT).replace(os.sep, "/")
    try:
        out = subprocess.run(["git", "show", "%s:%s" % (ref, rel)], cwd=ROOT,
                             capture_output=True, check=True).stdout
        then, then_rules = parse_baseline(json.loads(out.decode("utf-8")))
    except subprocess.CalledProcessError as exc:
        err = exc.stderr.decode("utf-8", "replace")
        if "exists on disk, but not in" in err or "does not exist in" in err:
            return None
        raise SystemExit("FAIL voice: cannot read %s at %s: %s" % (rel, ref, err.strip()))
    now, _ = load_baseline()

    def totals(c: collections.Counter) -> collections.Counter:
        t: collections.Counter = collections.Counter()
        for (_, r), n in c.items():
            t[r] += n
        return t
    a, b = totals(then), totals(now)
    return ["%s: %d at %s -> %d" % (r, a.get(r, 0), ref, n) for r, n in sorted(b.items())
            if r in then_rules and n > a.get(r, 0)]


# Planted cases for --self-test: (Markdown, the rules it must hit). An empty tuple means
# the text must pass. Each is scanned as a guides/ page, so the baseline plays no part.
SELF_TEST = (
    # Words, inflections and spaced forms.
    ("It leverages, leveraged and is leveraging the API.", ("hype:leverage",) * 3),
    ("Empowering, supercharged, revolutionizes, seamlessly, comprehensively.",
     ("hype:empower", "hype:supercharge", "hype:revolutionize", "hype:seamless",
      "hype:comprehensive")),
    ("Industry leading, enterprise grade, battle tested, lightning fast tools.",
     ("hype:industry-leading", "hype:enterprise-grade", "hype:battle-tested",
      "hype:lightning-fast")),
    ("One stop on the route; every finding must have an owner; the next level.", ()),
    ("A one-stop, must-have, next-level page.",
     ("hype:one-stop", "hype:must-have", "hype:next-level")),
    ("The C0029 Cutting Edge campaign abused Seamless SSO.", ()),
    ("Oracle Linux ships the Unbreakable Enterprise Kernel (UEK).", ()),
    ("An unbreakable kernel.", ("hype:unbreakable",)),
    ("Adversaries may leverage the API to read data.", ("hype:leverage",)),
    # Counts.
    ("A library of **140** references and 3 learning paths.", ("count", "count")),
    ("Read 1-2 pages of a site with 3 billion pages.", ()),
    ("TryHackMe Level 2 Paths and level 3 paths are course levels.", ()),            # item 7
    ("## 140 References", ("count",)),                                               # item 7
    ("**47 Paths** and 12 Guides", ("count", "count")),                              # item 7
    # Marks.
    ("Done \u2713 and starred \u2605.", ()),
    ("Done \u2705 and \u2714.", ("emoji", "emoji")),
    ("Status \u25FD and \u25FE.", ("emoji", "emoji")),                               # item 9
    ("A dash\u2014closed, and one \u2014 spaced.", ("em-dash", "em-dash")),
    ("```bash\n# a comment \u2014 in code\n```\n", ("em-dash",)),
    ("It works!", ("exclamation",)),
    ("Use `a != b` and ![logo](x.png).", ()),
    # Code blocks and list items.                                                       item 8
    ("Text.\n\n    leverage = comprehensive()  # indented code\n", ()),
    ("- First point.\n\n    It leverages the API, a list-continuation paragraph.\n",
     ("hype:leverage",)),
    ("1. Step one.\n\n    A comprehensive second paragraph of the step.\n",
     ("hype:comprehensive",)),
    ("- Item.\n\n        leverage = 1  # code inside the item\n", ()),
    ("- Item.\n\nParagraph after the list.\n\n    leverage = 1  # code again\n", ()),
    # HTML: alt and title values are read, the rest of the tag is not.                 item 9
    ('<img src="powerful.png" alt="A powerful scanner">', ("hype:powerful",)),
    ("<abbr title='Works great!'>WG</abbr>", ("exclamation",)),
    ('<a href="seamless.html" class="cutting-edge">link</a>', ()),
)

# Planted cases for the agent-note rule, scanned as a tools/ page: tools/ is outside
# SCOPE_RE, so a hit here shows the rule does not depend on it.
AGENT_SELF_TEST_FILE = "tools/_agent_note_self_test.md"
AGENT_SELF_TEST = (
    ("> Note: LIVE-VERIFIED via WebSearch 2026-10-08. Duo is part of Cisco.",
     ("agent-note", "agent-note")),
    ("The shared WebSearch budget was exhausted this turn.",
     ("agent-note", "agent-note", "agent-note")),
    ("NOT LIVE-VERIFIED THIS TURN: shared by all concurrent workflow agents.",
     ("agent-note", "agent-note", "agent-note")),
    ("These URLs are compiled from high-confidence prior knowledge.", ("agent-note",)),
    ("No product named 'Aura' found - verify if seen elsewhere.", ("agent-note",)),
    ("Drafted with an AI assistant.", ("agent-note",)),
    ("```bash\n# live verified on 2026-09-29\n```\n", ("agent-note",)),
    ("Search-session budget was exhausted before re-verification this run.",
     ("agent-note",)),
    ("The web-search budget for this run was exhausted.", ("agent-note",)),
    ("The quota budget was exhausted early.", ("agent-note",)),
    ("Paths were not re-verified live this run.", ("agent-note",)),
    ("Every GitHub path was re-confirmed live today.", ("agent-note",)),
    ("Checked live this run against the vendor page.", ("agent-note",)),
    ("Exhausted before live re-verification.", ("agent-note",)),
    ("(NOTE: org existence not confirmable via search; check it)", ("agent-note",)),
    ("The codes were NOT verified in this research.", ("agent-note",)),
    ("The meaning of 378 is not verified here.", ("agent-note",)),
    ("These URLs rely on established knowledge.", ("agent-note",)),
    ("Repo paths are unchecked; confirm before publishing.", ("agent-note",)),
    ("github.com/tenable/navi (confirm slug before use)", ("agent-note",)),
    ("Splunk add-on (verify exact app ID on Splunkbase)", ("agent-note",)),
    ("I could NOT verify the exact field from public docs.", ("agent-note",)),
    ("NOTE: I could not confirm native CEF output from the docs.", ("agent-note",)),
    ("I couldn't verify the path; I was unable to confirm the column.",
     ("agent-note", "agent-note")),
    ("- Could not verify the exact finding-type list against official docs.", ("agent-note",)),
    ("Push from the cloud tier; could not verify a CEF push.", ("agent-note",)),
    ("GET /api/1.0/scans -- endpoint names unverified publicly", ("agent-note",)),
    ("Field names are NOT confirmed from public docs.", ("agent-note",)),
    ("The SSO pages could not be verified.", ("agent-note",)),
    # Ordinary English and real API names pass.
    ("This turns a list into a plan, in this turn-based game.", ()),
    ("Hosted tools such as `WebSearchTool` skip the guardrail pipeline.", ()),
    ("Attackers with no prior knowledge of the target guess passwords.", ()),
    ("Confirm free capacity and that the destination was wiped before this run.", ()),
    ("Set a budget per run and research this topic before publishing.", ()),
    ("Analysts rely on established playbooks; verify the exact hash.", ()),
    ("If I could verify it, I would.", ()),
    ("Fixed (Can't Retest) means Invicti could not verify the fix.", ()),
    ("If the browser could not confirm the chain, treat the site as untrusted.", ()),
)


# Planted cases for the em-dash rule, which covers every tracked text file whatever its
# type or folder: (path, content, hits). Upstream JSONL rows keep their dashes only inside
# the upstream name and description values.
EM_DASH_SELF_TEST = (
    ("tools/x.md", "# Tool\n\nIt scans hosts \u2014 fast.\n", 1),
    ("platforms/x.md", "Text \u2014 more.\n", 1),
    ("languages/x.md", "Text \u2014 more.\n", 1),
    ("navigator/stages/x.json", '{"name": "Stage 9 \u2014 Test", "techniques": []}\n', 1),
    (".github/ISSUE_TEMPLATE/x.yml", "description: Scope \u2014 what it covers\n", 1),
    (".gitignore", "# secrets \u2014 never commit\n", 1),
    ("scripts/x.py", "# a comment \u2014 in code\n", 1),
    ("data/attack/x.jsonl", '{"name": "A \u2014 B", "description": "C\u2014D"}\n', 0),
    ("data/attack/x.jsonl", '{"mutable_elements": [{"field": "f", "description": "x\u2014y"}]}\n', 0),
    ("data/attack/x.jsonl", '{"name": "A", "x_note": "ours \u2014 not upstream"}\n', 1),
    ("data/generated/x.jsonl", '{"name": "A \u2014 B"}\n', 1),
    ("data/attack/x.jsonl", '{"detection_strategies": ["ours \u2014 not a copy"]}\n', 1),
    ("tools/x.md", "Plain words, a colon: and a comma.\n", 0),
)
# Pages the hand-written rules (emoji, exclamation, hype, count) must reach, and the
# generated pages they must not.
SCOPE_SELF_TEST = ("platforms/x.md", "languages/x.md", "tools/x.md", "paradigms/x.md",
                   "frameworks/x.md", "commands/x.md", "formats/x.md", "databases/x.md",
                   "ai-tooling/x.md", "research/x.md", "detections/TECHNIQUE_DETECTION_LIBRARY.md",
                   "guides/x.md", "disciplines/x.md", "operating-systems/x.md", "HOME.md")
SCOPE_OUT_SELF_TEST = ("mitre/x.md", "techniques/x.md", "detections/strategies/x.md",
                       "scores/x.md", "hubs/x.md", "navigator/index.md")


def self_test() -> int:
    """Scan every SELF_TEST case and compare its rules with the expected ones."""
    failed = 0
    for text, want in SELF_TEST:
        got = sorted(h[2] for h in scan("guides/_voice_self_test.md", text))
        if got != sorted(want):
            failed += 1
            print("FAIL self-test: %r\n  want %s\n  got  %s" % (text, sorted(want), got))
    for rel, text, want in EM_DASH_SELF_TEST:
        got = len(em_dashes(rel, text))
        if got != want:
            failed += 1
            print("FAIL self-test: em-dash in %s: %r\n  want %d hits, got %d" % (rel, text, want, got))
    for rel in SCOPE_SELF_TEST:
        if not in_scope_file(rel):
            failed += 1
            print("FAIL self-test: %s must be in scope" % rel)
    for rel in SCOPE_OUT_SELF_TEST:
        if in_scope_file(rel):
            failed += 1
            print("FAIL self-test: %s must be out of scope (a generator owns it)" % rel)
    missing = [f for f in bsn.hand_written(tracked_files()) if not in_scope_file(f)]
    if missing:
        failed += 1
        print("FAIL self-test: hand-written pages outside the scope: " + ", ".join(missing[:10]))
    for rel in ("platforms/x.md", "languages/x.md"):
        got = sorted(h[2] for h in scan(rel, "A powerful tool \u2014 here.") if in_scope_file(rel))
        if got != ["em-dash", "hype:powerful"]:
            failed += 1
            print("FAIL self-test: planted hits in %s: got %s" % (rel, got))
    if in_scope_file(AGENT_SELF_TEST_FILE):
        failed += 1
        print("FAIL self-test: %s must be outside the scope" % AGENT_SELF_TEST_FILE)
    for text, want in AGENT_SELF_TEST:
        got = sorted(h[2] for h in scan(AGENT_SELF_TEST_FILE, text) +
                     agent_notes(AGENT_SELF_TEST_FILE, text))
        if got != sorted(want):
            failed += 1
            print("FAIL self-test: %r\n  want %s\n  got  %s" % (text, sorted(want), got))
    total = (len(SELF_TEST) + len(AGENT_SELF_TEST) + len(EM_DASH_SELF_TEST) +
             len(SCOPE_SELF_TEST) + len(SCOPE_OUT_SELF_TEST) + 4)
    print("voice self-test: %d of %d cases pass" % (total - failed, total))
    return 1 if failed else 0


def rule_family(rule: str) -> str:
    return "hype" if rule.startswith("hype:") else rule


def main() -> int:
    try:
        sys.stdout.reconfigure(errors="backslashreplace")   # Windows consoles are not UTF-8
    except AttributeError:
        pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="*", help="check only these files and ignore the baseline")
    ap.add_argument("--report", action="store_true", help="list every hit, baselined or not")
    ap.add_argument("--summary", action="store_true", help="print per-rule totals and exit 0")
    ap.add_argument("--update-baseline", action="store_true",
                    help="lower the baseline to the hits that remain; refuses a rise")
    ap.add_argument("--allow-growth", action="store_true",
                    help="with --update-baseline: record a rise (only when adding a rule)")
    ap.add_argument("--base", metavar="REF",
                    help="also fail when a rule's baselined total is higher than at git REF")
    ap.add_argument("--self-test", action="store_true",
                    help="scan the planted cases in SELF_TEST and exit 1 if any is wrong")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.allow_growth and not args.update_baseline:
        ap.error("--allow-growth only applies to --update-baseline")

    named = [f.replace(os.sep, "/") for f in args.files]
    files = named or in_scope(tracked_files())
    hits = []
    for f in files:
        t = read_text(f)
        if t is not None:
            hits.extend(scan(f, t, em_dash=False))
    # em-dash: every tracked text file (or the named ones), never baselined.
    dashes = []
    dash_files = named or text_files(tracked_files())
    for f in dash_files:
        t = read_text(f)
        if t is not None and EM_DASH in t:
            dashes.extend(em_dashes(f, t))
    # agent-note: every tracked Markdown file (or the named ones), never baselined.
    notes = []
    for f in markdown_files(named or tracked_files()):
        t = read_text(f)
        if t is not None:
            notes.extend(agent_notes(f, t))
    counts = collections.Counter((h[0], h[2]) for h in hits)
    fam = collections.Counter(rule_family(h[2]) for h in hits)
    print("voice: %d hits in %d of %d files (%s)" % (
        len(hits), len({h[0] for h in hits}), len(files),
        ", ".join("%s %d" % (k, fam[k]) for k in ("emoji", "exclamation", "hype", "count"))))

    print("voice: %d agent-note hits in %d Markdown files (no baseline)" % (
        len(notes), len(markdown_files(named or tracked_files()))))
    print("voice: %d em-dash hits in %d tracked text files (no baseline)" % (
        len(dashes), len(dash_files)))

    if args.summary:
        totals = collections.Counter(h[2] for h in hits + notes + dashes)
        for rule in ("agent-note", "em-dash"):
            totals.setdefault(rule, 0)
        for rule, n in sorted(totals.items()):
            print("  %-26s %d" % (rule, n))
        return 0
    if args.update_baseline:
        if args.files:
            ap.error("--update-baseline scans the whole scope; do not name files")
        return update_baseline(counts, args.allow_growth)
    if args.report or args.files:
        for h in hits + notes + dashes:
            print("  %s:%d: %s: %s" % h)
    if args.files:
        return 1 if hits or notes or dashes else 0

    failed = False
    if notes:
        print("FAIL voice: agent process notes in published pages (state the fact and its "
              "source, or delete the note; docs/VOICE.md):")
        for h in notes:
            print("  %s:%d: %s" % (h[0], h[1], h[3]))
        failed = True
    if dashes:
        print("FAIL voice: em dashes (U+2014) in tracked files; use a colon, a comma, parentheses "
              "or a new sentence (docs/VOICE.md):")
        for h in dashes:
            print("  %s:%d: %s" % (h[0], h[1], h[3]))
        failed = True
    for p in guide_drift():
        print("FAIL voice: " + p)
        failed = True
    if args.base:
        grown = base_growth(args.base)
        if grown is None:
            print("voice: %s has no baseline yet; nothing to compare" % args.base)
        elif grown:
            print("FAIL voice: the baseline grew against %s (it may only shrink):" % args.base)
            for g in grown:
                print("  " + g)
            failed = True
        else:
            print("voice: no rule's baselined total grew against %s" % args.base)
    base, _ = load_baseline()
    print("voice: baseline allows %d" % sum(base.values()))
    shrunk = sum(base[k] - counts.get(k, 0) for k in base if counts.get(k, 0) < base[k])
    if shrunk:
        print("voice: NOTE %d baselined hits are gone; shrink the baseline with --update-baseline" % shrunk)
    over = {k: n - base.get(k, 0) for k, n in counts.items() if n > base.get(k, 0)}
    if not over:
        if failed:
            return 1
        print("OK voice")
        return 0
    print("FAIL voice: new hits (see docs/VOICE.md):")
    for (f, rule), extra in sorted(over.items()):
        lines = [h for h in hits if h[0] == f and h[2] == rule]
        print("  %s: %s: %d over the baseline of %d" % (f, rule, extra, base.get((f, rule), 0)))
        for h in lines:
            print("    line %d: %s" % (h[1], h[3]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
