"""Plain-text formatting for generated Markdown pages.

The page generators pass every page through ``plain()`` before writing it, so
generated pages follow the same conventions as the hand-written references:
no bold markers, emoji, middot separators, or Unicode arrows; "ID: Name" rather
than "ID — Name"; and colons, parentheses, or a sentence break in place of
template em dashes. Fenced code, inline code, link targets, URLs, and HTML tags
are left untouched, and every change is made within a single line.

Text quoted from upstream sources (for example MITRE descriptions) can still
contain dashes; only the template patterns below are rewritten.
"""
import re

FENCE = re.compile(r"^\s*(```|~~~)")
PROTECT = re.compile(
    r"(``[^`]+``|`[^`\n]+`"           # inline code
    r"|\]\([^)\s]*(?:\s+\"[^\"]*\")?\)"  # link target
    r"|<https?://[^>]+>"               # autolink
    r"|https?://[^\s)<>\]|]+"          # bare URL
    r"|<[A-Za-z/!][^>\n]*>)"           # HTML tag
)
PICTO = re.compile(
    "(?![★☆])[\U0001F300-\U0001FAFF☀-⛿✀-➿⬆⬇⬛⬜"
    "⭐⭕⏩-⏺⌚⌛⌨⏏]️?\\s?"
)
YES = ["✅", "✔️", "✔", "✓", "☑️", "☑"]
NO = ["❌", "✖️", "✖", "✗", "✘", "❎"]
ARROWS = (("⟶", "->"), ("⟵", "<-"), ("→", "->"), ("←", "<-"), ("↔", "<->"),
          ("⇒", "=>"), ("⇐", "<="), ("➜", "->"), ("➡️", "->"), ("➡", "->"),
          ("⬅️", "<-"), ("⬅", "<-"))
DASH = r"\s+[—–]\s+"
STAR = "⭐"


def _protect(line):
    keep = []

    def sub(m):
        keep.append(m.group(0))
        return "\x00%d\x00" % (len(keep) - 1)

    return PROTECT.sub(sub, line), keep


def _restore(line, keep):
    return re.sub(r"\x00(\d+)\x00", lambda m: keep[int(m.group(1))], line)


def _term_lead(text, keep, maxlen=90):
    """'Term — rest' becomes 'Term: rest' when Term reads as a short label."""
    m = re.match(r"^(\s*)(.+?)\s+[—–]\s+(\S.*)$", text)
    if not m:
        return text
    pre, left, rest = m.groups()
    tail = re.search(r"\x00(\d+)\x00\s*$", left)
    if tail and keep[int(tail.group(1))].lstrip("<").startswith("http"):
        return text
    bare = re.sub(r"\x00\d+\x00", "X", left)
    if (len(bare) > maxlen or len(bare.split()) > 12 or re.search(r"[.!?;—–]\s|[—–]", bare)
            or bare.rstrip().endswith(":")):
        return text
    return "%s%s: %s" % (pre, left, rest)


def _prose(s):
    s = re.sub(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", r"\1", s)
    s = s.replace(" · ", ", ").replace(" &middot; ", ", ")
    s = re.sub(r"\s?↗", "", s)
    for a, b in ARROWS:
        s = s.replace(a, b)
    s = s.replace("…", "...")
    s = s.replace(" " + STAR, " (observed)").replace(STAR + " ", "(observed) ").replace(STAR, "(observed)")
    for y in YES:
        s = s.replace(y + " Yes", "Yes").replace(y + " yes", "Yes")
    for n in NO:
        s = s.replace(n + " No", "No").replace(n + " no", "No")
    for y in YES:
        s = s.replace(y, "Yes")
    for n in NO:
        s = s.replace(n, "No")
    s = PICTO.sub("", s)
    s = re.sub(r"(?<=\w)–(?=\w)", "-", s)
    return s


def _cap(s):
    return s[:1].upper() + s[1:] if s[:1].islower() else s


def _templates(work):
    """Rewrite the dash patterns that the generators' templates produce."""
    work = re.sub(r"^\*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™" + DASH
                  + r"trademarks of The MITRE Corporation\.",
                  "*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks"
                  " of The MITRE Corporation.", work)
    work = re.sub(r"^\*Source: MITRE ATT&CK® \((v[\d.]+)\)" + DASH
                  + r"ATT&CK®, D3FEND™, and CAPEC™ are trademarks",
                  "*Source: MITRE ATT&CK® (\\1). ATT&CK®, D3FEND™, and CAPEC™ are trademarks", work)
    work = re.sub(r"\bnone" + DASH + r"(\*framework blind spot[^*]*\*)", r"none (\1)", work)
    work = re.sub(DASH + r"(coverage: [A-Za-z]+)\s*$", r" (\1)", work)
    work = re.sub(DASH + r"(\d[\d.,]*% of machines)\s*$", r" (\1)", work)
    work = re.sub(r"\[((?:[A-Z]{1,6}[.\-]?)+\d[\w.\-]*)" + DASH, r"[\1: ", work)
    work = re.sub(r"(\d{4}-\d\d-\d\d)\s+–\s+(\d{4}-\d\d-\d\d)", r"\1 to \2", work)
    m = re.match(r"^(\s*(?:[-*+]|\d+[.)])\s+)(.*)$", work)
    if m:
        marker, body = m.groups()
        body = re.sub(r"^(\[[^\]\x00]*\x00\d+\x00)" + DASH + r"(?=\S)", r"\1: ", body, count=1)
        mm = re.match(r"^([A-Z][\w.\-]*\d[\w.\-]*: [^—–:.!?]{1,80}?)" + DASH + r"(\S.*)$", body)
        if mm:
            body = "%s. %s" % (mm.group(1), _cap(mm.group(2)))
        work = marker + body
    return work


def plain_line(line):
    work, keep = _protect(line)
    stripped = work.lstrip()
    if stripped.startswith("#"):
        m = re.match(r"^(\s*#+\s+)(.*)$", work)
        if m:
            head, body = m.groups()
            body = _prose(body).strip()
            body = re.sub(DASH, ": ", body, count=1)
            body = re.sub(DASH, ", ", body)
            work = head + body
    elif stripped.startswith("|"):
        cells = re.split(r"(?<!\\)\|", work)
        out = []
        for c in cells:
            c2 = _prose(c)
            if re.fullmatch(r"\s*—\s*", c2):
                c2 = " n/a "
            elif c2.count("—") + c2.count(" – ") == 1:
                c2 = _term_lead(c2, keep, 60)
            out.append(c2)
        work = "|".join(out)
    else:
        work = _prose(work)
        m = re.match(r"^(\s*(?:[-*+]|\d+[.)])\s+)(.*)$", work)
        if m:
            work = m.group(1) + _term_lead(m.group(2), keep)
    if not stripped.startswith("|") and line.strip() != work.strip():
        work = re.sub(r"(?<=\S) {2,}(?=\S)", " ", work)
    work = _templates(work)
    return _restore(work, keep)


def plain(text):
    """Return ``text`` with the plain-formatting rules applied outside code blocks."""
    out, fence = [], False
    for line in text.split("\n"):
        if FENCE.match(line):
            fence = not fence
            out.append(line)
        else:
            out.append(line if fence else plain_line(line))
    return "\n".join(out)
