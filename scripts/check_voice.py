#!/usr/bin/env python3
"""Voice lint for the hand-written pages: the mechanical half of docs/VOICE.md.

Scope: tracked Markdown at the repository root (README, HOME, _coverpage, _navbar,
_sidebar and every root reference) and under guides/, disciplines/, case-studies/,
tools-research/ and docs/. Generated trees (mitre/, techniques/, detections/, scores/,
navigator/) and data are out of scope; their generators own their wording.

Rules (the rule key is what the baseline counts):

  em-dash       U+2014 anywhere in the file. Use a colon, a comma, parentheses or a
                new sentence.
  emoji         A pictographic emoji: U+1F000..U+1FAFF, the emoji code points in
                U+2300..U+2BFF (warning sign, ballot box with check, heavy check mark
                and so on) and U+FE0F, the selector that forces emoji presentation.
                Typographic symbols that are not emoji (the check mark U+2713, the
                star U+2605, arrows, box drawing, (c), (R), TM) pass.
  exclamation   A '!' that ends a sentence, in prose. Code, URLs, HTML and comments
                are not prose; '!=', '![image]' and '<!--' never match.
  hype:<word>   A word from HYPE below, in prose, matched case-insensitively on word
                boundaries with its inflections ("leverages", "leveraged",
                "empowering", "comprehensively"), each counted under the listed word.
                A hyphenated word also matches with a space in place of the hyphen
                ("cutting edge", "battle tested"), except the words in SPACED_EXCEPT
                ("one stop", "must have", "next level"), whose spaced forms are plain
                English. Proper nouns that contain one of the words are allowed through
                ALLOW (the ATT&CK campaign C0029 "Cutting Edge", Seamless SSO, the
                Revolutionary Guard).
  count         A hand-typed headline count in prose: "<N> references", "<N> guides",
                "<N> paths" or "<N> pages", with at most one word between the number
                and the noun ("140 in-depth references", "47 discipline paths") and
                bold or italic markers allowed around the number or that word
                ("**140** references"). Counts belong in script output: text between
                a script-written marker pair, `<!-- name:start ... -->` and
                `<!-- name:end -->`, is skipped.

Upstream text is not voice debt. Object names and quoted descriptions from ATT&CK,
CAPEC, CWE, ATLAS, D3FEND, Engage and F3 are reproduced verbatim (docs/VOICE.md), so an
em-dash, '!' or hype word is skipped when the words around it match the name,
description or definition fields of the upstream datasets under data/ (UPSTREAM_DATA).

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
from repo_files import ROOT, read_text, tracked_files  # noqa: E402

BASELINE = os.path.join(ROOT, "scripts", "baselines", "voice.json")
SCOPE_RE = re.compile(r"^(?:[^/]+|(?:guides|disciplines|case-studies|tools-research|docs)/.+)\.md$")

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
    "\u27BF\u2B05-\u2B07\u2B1B\u2B1C\u2B50\u2B55\u203C\u2049]")
# A '!' directly after a word or closing bracket, followed by space, end of line or
# closing punctuation. '!=' and '![' fail the lookahead, '<!--' the lookbehind, and a
# '!' right before a closing quote belongs to the quotation, which keeps its own
# punctuation.
EXCLAIM_RE = re.compile(r"(?<=[\w)\]*_])!+(?=[\s)\]*_|]|$)")
# Lowercase nouns only ("Level 2 Paths" is a product name); a number that closes a range
# ("1-2 pages") describes a length, not the library; magnitudes ("3 billion pages") are
# quoted figures about someone else's corpus.
EMPH = r"(?:\*{1,2}|_{1,2})?"                   # bold or italic markers: "**140** references"
COUNT_RE = re.compile(r"(?<![\w.,\u2013-])" + EMPH + r"(\d+(?:,\d{3})*)(?![\d,])\+?" + EMPH +
                      r"\s+(?!(?:hundred|thousand|million|billion)\b)"
                      r"(?:" + EMPH + r"[A-Za-z][\w-]*" + EMPH + r"\s+)?"
                      r"(references|guides|paths|pages)\b")
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


def blank(m: re.Match) -> str:
    """Replace a match with spaces, keeping newlines so line numbers survive."""
    return re.sub(r"[^\n]", " ", m.group(0))


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
    """The text a reader reads as sentences: no code, comments, tags, URLs or link targets."""
    text = strip_fences(text)
    text = COMMENT_RE.sub(blank, text)
    lines = []
    for line in text.split("\n"):
        if line.startswith("    ") and not line.lstrip().startswith(("-", "*", "|", ">")) and \
                not re.match(r"\s*\d+\.", line):
            lines.append("")                       # indented code block
            continue
        line = INLINE_CODE_RE.sub(blank, line)
        line = LINK_TARGET_RE.sub(lambda m: "]" + " " * (len(m.group(0)) - 1), line)
        line = URL_RE.sub(blank, line)
        line = TAG_RE.sub(blank, line)
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
# emphasis and case. Three words of context at least, so a lone word never matches.
UPSTREAM_DATA = ("data/attack/", "data/ai/", "data/fraud/", "data/weaknesses/", "data/engage/")
UPSTREAM_KEYS = ("name", "description", "definition")
_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_LEFT_RE = re.compile(r"(?:\S+\s+){0,6}\S*$")
_RIGHT_RE = re.compile(r"^\S*(?:\s+\S+){0,6}")
_upstream_values: list[str] | None = None
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
                vals.extend(rec[k] for k in UPSTREAM_KEYS
                            if isinstance(rec, dict) and isinstance(rec.get(k), str))
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
    for a, b in ((left[-60:], right[:60]), (left, ""), ("", right)):
        cand = norm(a + hit + b)
        if len(cand.split()) >= 3 and cand in corpus:
            return True
    return False


def scan(rel: str, raw: str) -> list[tuple[str, int, str, str]]:
    """Every hit in one file as (file, line, rule, excerpt)."""
    hits = []
    raw_lines = raw.split("\n")

    def excerpt(i: int) -> str:
        s = raw_lines[i - 1].strip()
        return s if len(s) <= 110 else s[:107] + "..."

    for i, line in enumerate(raw_lines, 1):
        if EM_DASH in line:
            plain = URL_RE.sub(blank, LINK_TARGET_RE.sub(
                lambda m: "]" + " " * (len(m.group(0)) - 1), line))
            for m in re.finditer(EM_DASH, plain):
                if not upstream(plain, m.start(), m.end(), EM_DASH):
                    hits.append((rel, i, "em-dash", excerpt(i)))
        for m in EMOJI_RE.finditer(line):
            hits.append((rel, i, "emoji", "U+%04X in: %s" % (ord(m.group(0)), excerpt(i))))
    text = prose(raw)
    for i, line in enumerate(text.split("\n"), 1):
        for m in EXCLAIM_RE.finditer(line):
            if allowed(line, m.start() - 4, m.end(), (EXCLAIM_ALLOW,)):
                continue
            if not upstream(line, m.start(), m.end(), "!"):
                hits.append((rel, i, "exclamation", excerpt(i)))
        for m in HYPE_RE.finditer(line):
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


GUIDE = os.path.join(ROOT, "docs", "VOICE.md")
GUIDE_LIST_RE = re.compile(r"^`[a-z-]+`(?:, `[a-z-]+`)*\.$")


def guide_drift() -> list[str]:
    """The word list in docs/VOICE.md must name exactly the words in HYPE (inflected
    and spaced forms are matched by the lint, not listed)."""
    try:
        with open(GUIDE, encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh]
    except OSError:
        return ["docs/VOICE.md is missing"]
    listed = set()
    for ln in lines:
        if GUIDE_LIST_RE.match(ln):
            listed |= set(re.findall(r"`([a-z-]+)`", ln))
    want = set(HYPE)
    problems = []
    if want - listed:
        problems.append("docs/VOICE.md does not list: " + ", ".join(sorted(want - listed)))
    if listed - want:
        problems.append("docs/VOICE.md lists words check_voice.py does not check: " +
                        ", ".join(sorted(listed - want)))
    return problems


def in_scope(files: list[str]) -> list[str]:
    return [f for f in files if SCOPE_RE.match(f)]


RULES = ("count", "em-dash", "emoji", "exclamation") + tuple("hype:" + w for w in HYPE)


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
    args = ap.parse_args()
    if args.allow_growth and not args.update_baseline:
        ap.error("--allow-growth only applies to --update-baseline")

    files = [f.replace(os.sep, "/") for f in args.files] if args.files else in_scope(tracked_files())
    hits = []
    for f in files:
        t = read_text(f)
        if t is not None:
            hits.extend(scan(f, t))
    counts = collections.Counter((h[0], h[2]) for h in hits)
    fam = collections.Counter(rule_family(h[2]) for h in hits)
    print("voice: %d hits in %d of %d files (%s)" % (
        len(hits), len({h[0] for h in hits}), len(files),
        ", ".join("%s %d" % (k, fam[k]) for k in ("em-dash", "emoji", "exclamation", "hype", "count"))))

    if args.summary:
        for rule, n in sorted(collections.Counter(h[2] for h in hits).items()):
            print("  %-26s %d" % (rule, n))
        return 0
    if args.update_baseline:
        if args.files:
            ap.error("--update-baseline scans the whole scope; do not name files")
        return update_baseline(counts, args.allow_growth)
    if args.report or args.files:
        for h in hits:
            print("  %s:%d: %s: %s" % h)
    if args.files:
        return 1 if hits else 0

    failed = False
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
