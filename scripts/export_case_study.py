#!/usr/bin/env python3
"""Export the case studies under case-studies/ to PDF and PowerPoint.

Every study in case-studies/README.md is meant to carry a PDF and a slide deck next to its
web page. This script writes both in the house style of the first eight exports:

  PDF    US Letter, ReportLab. A navy cover block (logo, the kicker CASE STUDY, the title,
         the study's italic byline), then the study's Markdown rendered in full: headings,
         paragraphs, bullet and numbered lists, tables with wrapped cells, block quotes,
         fenced code, the italic notice lines and the images under case-studies/assets,
         scaled to the text width. Links are underlined text (the URLs stay visible in
         the Sources table). Every page after the first carries the running header
         TEAM STAR WOLF and the title, and the footer teamstarwolf.github.io, the
         published date and Page N. The navigation line under the byline and the
         generated page card (the meta:start to meta:end block) are site furniture and
         are left out.
  Deck   16:9 (13.333 by 7.5 inches), python-pptx, rendered from a slide plan (below).
         Cambria titles, Calibri body, the navy, teal and orange palette, a cover slide,
         then one slide per plan section with a kicker, a narrative title, a body and
         the footer TEAM STAR WOLF | teamstarwolf.github.io, date | slide number.

Usage (from the repository root; the writers need reportlab and python-pptx):

    python scripts/export_case_study.py pdf case-studies/GHOSTCAT_CVE_2020_1938.md
    python scripts/export_case_study.py pptx case-studies/slides/plans/GHOSTCAT_CVE_2020_1938.md
    python scripts/export_case_study.py all-pdf     # every README study that has no PDF yet
    python scripts/export_case_study.py --check     # standard library only; exit 1 on a problem

--check verifies that every study row in case-studies/README.md either links an existing
PDF and an existing deck under the expected names or says in plain text why one is
missing (for example "Slides: pending" or "PDF and slides not yet produced"), that every
plan under case-studies/slides/plans fits its character budgets, and that no two studies
share an export name. It is not wired into CI.

The README Download cell reads "[PDF](<raw link>) · [Slides (PowerPoint)](<raw link>)",
or "[PDF](<raw link>) · Slides: pending" until a deck exists, followed by any Navigator
layer link the row already had. download_cell() writes that text.

Export names
------------
EXPORT_NAMES maps a study file's stem to the file name stem of its exports; the script adds
_Case_Study.pdf and _Case_Study.pptx. A study missing from the table gets a name built from
its stem (each word capitalised, digits kept), so add a row when a new study lands if that
default reads badly. The eight names that existed before the table are kept as they are.

Slide plan format (case-studies/slides/plans/<STUDY STEM>.md)
--------------------------------------------------------------
A plan is a Markdown page. It opens with a level-one heading, "Slide plan: " and the deck
title (the study's title; the prefix keeps the page apart from the study in generated
listings and is dropped from the deck), then a list of fields:

    # Slide plan: Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab

    - Study: case-studies/GHOSTCAT_CVE_2020_1938.md
    - Cover title: Ghostcat, CVE-2020-1938 / The Tomcat AJP File Read / in the Lab
    - Subtitle: One default-on port, one file read, and a fix that holds
    - Published: 4 November 2026
    - Notes: speaker notes for the cover slide (optional)

"Cover title" is the cover's big title, two or three lines separated by " / ". Every level-two
heading after that is one slide, written as KICKER | Narrative title. The kicker is the small
capitals label (EXECUTIVE SUMMARY, KEY FACTS, PART 1, MITRE MAPPINGS, DEFENDER VIEW,
CROSS-CUTTING THEMES); the title states a claim, not a label. Under the heading, in any order:

    - A bullet, with **bold** lead-in words allowed
      - A second-level bullet (two spaces of indent)
    A line with no marker is a paragraph without a bullet.
    Stat: 9.8 | CVSS 3.1 base score from NVD
    Left: Optional heading for the left column
    - bullets after Left: go in the left column
    Right: Optional heading for the right column
    - bullets after Right: go in the right column
    | A | Markdown | table |
    |---|---|---|
    | rows | of | cells |
    Caption: one closing line in small grey type above the footer
    Notes: speaker notes; carry the source numbers ([1][23]) the slide draws on

Two to four Stat lines make a row of big numbers with captions at the top of the slide. The
blocks stack in the order stats, paragraphs and bullets, columns, table. A deck has thirteen
to sixteen slides counting the cover, and every slide after the cover needs a Notes line.
The footer number is the slide's position in the deck, the cover being slide 1.

The renderer checks every text box against a character budget before it writes anything: it
estimates, word by word, how many lines each paragraph needs at the box's font size and
width and compares the total height with the box. A plan that breaks a budget is refused
with the slide, the box and the overrun, and nothing is written. After writing, the deck is
read back with python-pptx and every text frame and table is checked again.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CS_DIR = os.path.join(ROOT, "case-studies")
PDF_DIR = os.path.join(CS_DIR, "pdf")
PPTX_DIR = os.path.join(CS_DIR, "slides")
PLAN_DIR = os.path.join(PPTX_DIR, "plans")
README = os.path.join(CS_DIR, "README.md")
LOGO = os.path.join(ROOT, "assets", "brand", "starwolf64-logotype-480.png")
RAW_BASE = "https://github.com/TeamStarWolf/TeamStarWolf/raw/main/case-studies/"
SITE = "https://teamstarwolf.github.io/TeamStarWolf/"
BLOB_BASE = "https://github.com/TeamStarWolf/TeamStarWolf/blob/main"
SUFFIX = "_Case_Study"
EM_DASH = "\u2014"

# Study file stem -> export name stem. The first eight are the names on main before the
# exporter existed; keep them.
EXPORT_NAMES = {
    "AI_THREATS_2026": "AI_Threats_2026",
    "PHP2SHELL_OCTOBER_2026": "PHP2Shell_October_2026",
    "XZ_UTILS_BACKDOOR_2024": "XZ_Utils_Backdoor_2024",
    "EMUDHRA_CA_COMPROMISE_2026": "eMudhra_CA_Compromise_2026",
    "SHAREPOINT_TOOLSHELL_2025": "SharePoint_ToolShell_2025",
    "CL0P_FILE_TRANSFER_2023": "Cl0p_MOVEit_File_Transfer_2023",
    "LINUX_TCP_UAF_2026": "Linux_TCP_UAF_2026",
    "MPTCP_ATTACK_SURFACE_2026": "MPTCP_Attack_Surface_2026",
    "SOLARWINDS_SUNBURST": "SolarWinds_SUNBURST_2019_2021",
    "CHRONICLE_2019": "Chronicle_2019",
    "CHRONICLE_2020": "Chronicle_2020",
    "ICS_ATTACKS_AND_ADVISORIES_2024_2026": "ICS_Attacks_and_Advisories_2024_2026",
    "LOG4SHELL": "Log4Shell_CVE_2021_44228",
    "NPM_SUPPLY_CHAIN_ATTACKS": "npm_Supply_Chain_Attacks_2018_2026",
    "HUGGING_FACE_SUPPLY_CHAIN": "Hugging_Face_Supply_Chain_2021_2026",
    "STUXNET": "Stuxnet",
    "APT41_PUBLIC_RECORD": "APT41_Public_Record_2012_2026",
    "CHANGE_HEALTHCARE_2024": "Change_Healthcare_2024",
    "GHOSTCAT_CVE_2020_1938": "Ghostcat_CVE_2020_1938",
    "PROFTPD_MOD_COPY_CVE_2015_3306": "ProFTPD_mod_copy_CVE_2015_3306",
    "NODEJS_CVE_2026_111497": "Nodejs_CVE_2026_111497",
    "MAGENTO_CVE_2026_48356": "Magento_CVE_2026_48356",
    "PHP_8_4_27_CVES": "PHP_8_4_27_CVEs",
    "NEXTCLOUD_RICHDOCUMENTS_CVE_2026_110447": "Nextcloud_Richdocuments_CVE_2026_110447",
    "PLEX_MEDIA_SERVER_2026_CVES": "Plex_Media_Server_2026_CVEs",
    "GITLAB_CVE_2026_97229": "GitLab_CVE_2026_97229",
    "SSHOLE_CVE_2026_123158": "SSHole_CVE_2026_123158",
    "CHROME_ISOLATED_WEB_APPS_2026": "Chrome_Isolated_Web_Apps_2026",
    "MANDIANT_INTRUSION_2020": "FireEye_Mandiant_Intrusion_2020",
    "CONNECTWISE_STORM_0940_2026": "ConnectWise_Storm_0940_2026",
    "STRYKER_HANDALA_WIPER_2026": "Stryker_Handala_Wiper_2026",
    "BINANCE_HEIST_2026": "Binance_Heist_2026",
    "DENTAQUEST_BREACH_2026": "DentaQuest_Breach_2026",
    "INSTRUCTURE_CANVAS_BREACH_2026": "Instructure_Canvas_Breach_2026",
    "FBI_SURVEILLANCE_SYSTEM_BREACH_2026": "FBI_Surveillance_System_Breach_2026",
    "NSA_CIA_TOOL_LEAKS": "NSA_CIA_Tool_Leaks_2016_2017",
    "RANSOMWARE_ECOSYSTEM": "Ransomware_Ecosystem_2019_2026",
    "NABLE_NCENTRAL_ABLE2SHELL_2026": "Nable_Ncentral_Able2Shell_2026",
    "EXCHANGE_MARAUDER_2021": "Exchange_Marauder_2021",
    "THREAT_ACTORS_CHINA": "Threat_Actors_China",
    "CISCO_SDWAN_CVE_2026_20127": "Cisco_SD_WAN_CVE_2026_20127",
    "SHAREPOINT_2026_EXPLOITATION": "SharePoint_2026_Exploitation",
    "PALO_ALTO_PAN_OS_CVE_2026_0257": "Palo_Alto_PAN_OS_CVE_2026_0257",
}


def export_name(stem: str) -> str:
    """The export file name stem for a study stem, with the _Case_Study suffix."""
    if stem in EXPORT_NAMES:
        return EXPORT_NAMES[stem] + SUFFIX
    words = [w if any(c.isdigit() for c in w) else w.capitalize() for w in stem.split("_") if w]
    return "_".join(words) + SUFFIX


def rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def resolve_input(path: str) -> str:
    """A path given on the command line, relative to the working directory or the root."""
    for cand in (path, os.path.join(ROOT, path)):
        if os.path.isfile(cand):
            return os.path.abspath(cand)
    raise SystemExit(f"error: no such file: {path}")


def read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ----------------------------------------------------------------------------- README rows
ROW_RE = re.compile(r"^\|\s*\[(?P<title>[^\]]+)\]\(/case-studies/(?P<file>[A-Za-z0-9_]+)\.md\)")
LINK_ANY_RE = re.compile(r"\[([^\]]*)\]\(([^)\s]+)\)")
REASON_RE = re.compile(r"(?i)\b(pending|not yet|markdown only|no pdf|no slides|not produced)\b")


def split_cells(row: str) -> list[str]:
    """Split a Markdown table row on unescaped pipes; returns the stripped cell texts."""
    s = row.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    cells, cur, i = [], [], 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] == "|":
            cur.append("|")
            i += 2
            continue
        if ch == "|":
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    cells.append("".join(cur).strip())
    return cells


@dataclass
class Row:
    line_no: int
    title: str
    stem: str
    cell: str


def readme_rows(text: str | None = None) -> list[Row]:
    text = read_text(README) if text is None else text
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        m = ROW_RE.match(line)
        if m:
            rows.append(Row(n, m.group("title"), m.group("file"), split_cells(line)[-1]))
    return rows


def download_cell(stem: str, has_pptx: bool, keep: str = "") -> str:
    """The Download cell text: the PDF link, the deck link or "Slides: pending", then keep."""
    name = export_name(stem)
    parts = [f"[PDF]({RAW_BASE}pdf/{name}.pdf)"]
    parts.append(f"[Slides (PowerPoint)]({RAW_BASE}slides/{name}.pptx)" if has_pptx else "Slides: pending")
    if keep:
        parts.append(keep)
    return " \u00b7 ".join(parts)


# ----------------------------------------------------------------------------- study text
@dataclass
class Study:
    path: str
    stem: str
    title: str
    byline: str
    published: str
    body: list


def load_study(path: str) -> Study:
    lines = read_text(path).splitlines()
    title, byline, i = "", "", 0
    while i < len(lines) and not title:
        if lines[i].startswith("# "):
            title = lines[i][2:].strip()
        i += 1
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i < len(lines) and re.match(r"^\*[^*].*\*$", lines[i].strip()):
        byline = lines[i].strip()[1:-1].strip()
        i += 1
    if not title or not byline:
        raise SystemExit(f"error: {rel(path)}: expected a '# ' title followed by an italic byline")
    m = re.search(r"Published (\d{1,2} [A-Z][a-z]+ \d{4})", byline)
    published = m.group(1) if m else ""
    body, skipping = [], False
    for line in lines[i:]:
        s = line.strip()
        if s.startswith("<!-- meta:start"):
            skipping = True
            continue
        if skipping:
            if s.startswith("<!-- meta:end"):
                skipping = False
            continue
        body.append(line)
    # The navigation line under the byline ("[All case studies](...) · Related: ...").
    for k, line in enumerate(body):
        if line.strip():
            if line.strip().startswith("[All case studies]"):
                del body[k]
            break
    stem = os.path.splitext(os.path.basename(path))[0]
    return Study(path, stem, title, byline, published, body)


# ----------------------------------------------------------------------------- Markdown blocks
LIST_RE = re.compile(r"^(\s*)([-*+]|\d+[.)])\s+(.*)$")
IMG_RE = re.compile(r'^!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)\s*$')
FENCE_RE = re.compile(r"^(`{3,}|~{3,})(.*)$")
HEAD_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
SEP_CELL_RE = re.compile(r"^:?-{1,}:?$")


def _starts_block(s: str) -> bool:
    return bool(s.startswith(("#", "|", ">", "```", "~~~", "<!--")) or LIST_RE.match(s)
                or IMG_RE.match(s) or s in ("---", "***", "___"))


def parse_blocks(lines: list) -> list:
    """Block-level Markdown: h, p, list, table, quote, code, img, hr."""
    blocks: list = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        s = line.strip()
        if not s:
            i += 1
            continue
        if s.startswith("<!--"):
            while i < n and "-->" not in lines[i]:
                i += 1
            i += 1
            continue
        m = FENCE_RE.match(s)
        if m:
            fence, buf = m.group(1), []
            i += 1
            while i < n and not lines[i].strip().startswith(fence):
                buf.append(lines[i].rstrip())
                i += 1
            i += 1
            blocks.append(("code", "\n".join(buf)))
            continue
        m = HEAD_RE.match(line)
        if m:
            blocks.append(("h", len(m.group(1)), m.group(2)))
            i += 1
            continue
        if s.startswith("|"):
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                cells = split_cells(lines[i])
                if not all(SEP_CELL_RE.match(c.replace(" ", "")) for c in cells):
                    rows.append(cells)
                i += 1
            if rows:
                blocks.append(("table", rows))
            continue
        if s.startswith(">"):
            paras, cur = [], []
            while i < n and lines[i].strip().startswith(">"):
                t = re.sub(r"^\s*>\s?", "", lines[i]).strip()
                if t:
                    cur.append(t)
                elif cur:
                    paras.append(" ".join(cur))
                    cur = []
                i += 1
            if cur:
                paras.append(" ".join(cur))
            blocks.append(("quote", paras))
            continue
        m = IMG_RE.match(s)
        if m:
            blocks.append(("img", m.group(1), m.group(2)))
            i += 1
            continue
        if s in ("---", "***", "___"):
            blocks.append(("hr",))
            i += 1
            continue
        if LIST_RE.match(line):
            items: list = []
            while i < n:
                cur_line = lines[i]
                m = LIST_RE.match(cur_line)
                if m:
                    items.append([len(m.group(1).expandtabs(4)), m.group(2), m.group(3).strip()])
                    i += 1
                    continue
                if cur_line.strip() and items and cur_line[:1] in (" ", "\t") \
                        and not _starts_block(cur_line.strip()):
                    items[-1][2] += " " + cur_line.strip()
                    i += 1
                    continue
                if not cur_line.strip():
                    j = i
                    while j < n and not lines[j].strip():
                        j += 1
                    if j < n and LIST_RE.match(lines[j]):
                        i = j
                        continue
                break
            blocks.append(("list", items))
            continue
        if s.startswith("<"):
            buf = []
            while i < n and lines[i].strip():
                buf.append(lines[i])
                i += 1
            text = re.sub(r"<[^>]+>", " ", " ".join(buf))
            text = re.sub(r"\s+", " ", text).strip()
            if text:
                blocks.append(("p", text))
            continue
        buf = []
        while i < n and lines[i].strip() and not (buf and _starts_block(lines[i].strip())):
            buf.append(lines[i].strip())
            i += 1
        blocks.append(("p", " ".join(buf)))
    return blocks


# ----------------------------------------------------------------------------- PDF text
# The PDF uses the standard Helvetica and Courier fonts, which carry the Windows-1252
# character set. Characters outside it are spelled out here, or reduced to their base letter.
CHAR_MAP = {
    "\u2192": "->", "\u2190": "<-", "\u2194": "<->", "\u21d2": "=>", "\u2265": ">=",
    "\u2264": "<=", "\u2248": "~", "\u2260": "!=", "\u2212": "-", "\u2010": "-", "\u2011": "-",
    "\u00a0": " ", "\u2009": " ", "\u202f": " ", "\u2007": " ", "\u200b": "", "\ufeff": "",
    "\u2713": "yes", "\u2714": "yes", "\u2717": "no", "\u2032": "'", "\u2033": '"',
    "\u2208": "in", "\u221e": "infinity",
}


def pdf_text(s: str, unmapped: set) -> str:
    out = []
    for ch in s:
        if ch in CHAR_MAP:
            out.append(CHAR_MAP[ch])
            continue
        try:
            ch.encode("cp1252")
            out.append(ch)
            continue
        except UnicodeEncodeError:
            pass
        base = unicodedata.normalize("NFKD", ch).encode("ascii", "ignore").decode()
        if base:
            out.append(base)
        else:
            unmapped.add(ch)
            out.append("?")
    return "".join(out)


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def link_target(url: str):
    if url.startswith(("http://", "https://", "mailto:")):
        return url
    if url.startswith("/"):
        path = url.split("#", 1)[0]
        if path.endswith(".md"):
            return SITE + "#" + path[:-3]
        return BLOB_BASE + path
    return None


CODE_SPAN_RE = re.compile(r"(`+)(.+?)\1")
LINK_RE = re.compile(r"\[((?:[^\[\]]|\[[^\[\]]*\])+)\]\(([^()\s]+(?:\([^()\s]*\)[^()\s]*)*)(?:\s+\"[^\"]*\")?\)")
AUTOLINK_RE = re.compile(r"<(https?://[^>\s]+)>")
HTML_TAG_RE = re.compile(r"</?(?:span|sup|sub|a|b|i|em|strong|code|kbd|small|abbr|p|div|img)\b[^>]*>", re.I)
BOLD_RE = re.compile(r"(\*\*|__)(?=\S)(.+?)(?<=\S)\1")
ITAL_STAR_RE = re.compile(r"(?<![*\w])\*(?=\S)(.+?)(?<=\S)\*(?![*\w])")
ITAL_UNDER_RE = re.compile(r"(?<![\w])_(?=\S)(.+?)(?<=\S)_(?![\w])")


def inline(text: str, size: float, slots=None) -> str:
    """Markdown inline syntax to ReportLab paragraph markup.

    A link label is converted by a nested call that shares the outer call's slots, so a
    code span already set aside inside the label is restored once, at the end.
    """
    top = slots is None
    slots = [] if top else slots

    def keep(markup: str) -> str:
        slots.append(markup)
        return f"\x00{len(slots) - 1}\x00"

    text = re.sub(r"\\([\\`*_{}\[\]()#+\-.!|<>])", lambda m: keep(esc(m.group(1))), text)
    text = CODE_SPAN_RE.sub(lambda m: keep(
        f'<font face="Courier" size="{size - 1:.1f}" backColor="#EEF1F7">{esc(m.group(2).strip())}</font>'), text)
    text = re.sub(r"<br\s*/?>", lambda m: keep("<br/>"), text, flags=re.I)

    def link(label: str, url: str) -> str:
        target = link_target(url)
        if target:
            return keep(f'<link href="{esc(target)}"><u>{label}</u></link>')
        return keep(f"<u>{label}</u>")

    text = AUTOLINK_RE.sub(lambda m: link(esc(m.group(1)), m.group(1)), text)
    text = LINK_RE.sub(lambda m: link(inline(m.group(1), size, slots), m.group(2)), text)
    text = HTML_TAG_RE.sub("", text)
    text = esc(text)
    text = BOLD_RE.sub(lambda m: f"<b>{m.group(2)}</b>", text)
    text = ITAL_STAR_RE.sub(lambda m: f"<i>{m.group(1)}</i>", text)
    text = ITAL_UNDER_RE.sub(lambda m: f"<i>{m.group(1)}</i>", text)
    while top and "\x00" in text:
        new = re.sub(r"\x00(\d+)\x00", lambda m: slots[int(m.group(1))], text)
        if new == text:
            break
        text = new
    return text


def plain(text: str) -> str:
    """Markdown inline syntax stripped to the visible characters (for measuring)."""
    text = LINK_RE.sub(lambda m: m.group(1), text)
    text = CODE_SPAN_RE.sub(lambda m: m.group(2), text)
    text = text.replace("**", "").replace("__", "")
    return re.sub(r"(?<![\w])[*_](?=\S)|(?<=\S)[*_](?![\w])", "", text)


# ----------------------------------------------------------------------------- PDF writer
PDF_COLORS = {
    "navy": "#0B1220", "heading": "#0B1220", "h3": "#16223B", "body": "#14202E", "red": "#FC0604",
    "green": "#ACDF55", "cream": "#FCF6B9", "rowalt": "#F2F5FB", "rule": "#D9E0EC",
    "muted": "#5A6678", "code": "#EEF1F7", "callout": "#EEF7DF", "teal": "#168F87",
}
PAGE_W, PAGE_H = 612.0, 792.0
MARGIN_X = 66.24
TOP_MARGIN = 79.44
BOTTOM_MARGIN = 64.0
TEXT_W = PAGE_W - 2 * MARGIN_X - 12  # the frame keeps 6 pt of padding on each side


def build_pdf(md_path: str, out_path=None) -> str:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.platypus import (HRFlowable, Image, Paragraph, Preformatted, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    study = load_study(md_path)
    if any(EM_DASH in line for line in study.body) or EM_DASH in study.title + study.byline:
        raise SystemExit(f"error: {rel(md_path)} contains an em dash (U+2014); fix the study first")
    out_path = out_path or os.path.join(PDF_DIR, export_name(study.stem) + ".pdf")
    unmapped: set = set()

    def T(s: str) -> str:
        return pdf_text(s, unmapped)

    C = {k: colors.HexColor(v) for k, v in PDF_COLORS.items()}

    body = ParagraphStyle("body", fontName="Helvetica", fontSize=9.6, leading=14.2, textColor=C["body"],
                          alignment=TA_JUSTIFY, spaceAfter=6.5, splitLongWords=1)
    h2 = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=14.5, leading=18, textColor=C["heading"],
                        spaceBefore=14, spaceAfter=2, keepWithNext=1)
    h3 = ParagraphStyle("h3", fontName="Helvetica-Bold", fontSize=11.3, leading=15, textColor=C["h3"],
                        spaceBefore=9, spaceAfter=4, keepWithNext=1)
    h4 = ParagraphStyle("h4", parent=h3, fontSize=10, leading=13.5, spaceBefore=7)
    notice = ParagraphStyle("notice", parent=body, fontName="Helvetica-Oblique", fontSize=8.4, leading=11.6,
                            textColor=C["muted"], alignment=TA_LEFT)
    item = ParagraphStyle("item", parent=body, alignment=TA_LEFT, spaceAfter=3.5)
    quote = ParagraphStyle("quote", parent=body, fontSize=9.2, leading=13.4, alignment=TA_LEFT, spaceAfter=4)
    callout = ParagraphStyle("callout", parent=body, alignment=TA_LEFT, spaceAfter=0)
    code = ParagraphStyle("code", fontName="Courier", fontSize=7.6, leading=9.8, textColor=C["body"],
                          backColor=C["code"], borderPadding=(5, 6, 5, 6), leftIndent=6, rightIndent=6,
                          spaceBefore=6, spaceAfter=11)
    cover_kicker = ParagraphStyle("ck", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=C["green"])
    cover_title = ParagraphStyle("ct", fontName="Helvetica-Bold", fontSize=25, leading=29, textColor=colors.white)
    cover_by = ParagraphStyle("cb", fontName="Helvetica-Oblique", fontSize=11, leading=16, textColor=C["cream"])

    story: list = []
    cover_w = TEXT_W + 12
    logo = Image(LOGO, width=165.6, height=55.2)
    logo.hAlign = "LEFT"
    cover = Table([[logo], [Spacer(1, 4)], [Paragraph("CASE STUDY", cover_kicker)],
                   [Paragraph(esc(T(study.title)), cover_title)],
                   [Paragraph(inline(T(study.byline), 11), cover_by)]], colWidths=[cover_w])
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C["navy"]),
        ("LEFTPADDING", (0, 0), (-1, -1), 22), ("RIGHTPADDING", (0, 0), (-1, -1), 22),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (0, 0), 22), ("BOTTOMPADDING", (0, -1), (0, -1), 24),
        ("TOPPADDING", (0, 3), (0, 3), 8), ("BOTTOMPADDING", (0, 3), (0, 3), 10),
    ]))
    story += [cover, Spacer(1, 3),
              HRFlowable(width="100%", thickness=3, color=C["red"], spaceBefore=0, spaceAfter=4, lineCap="round")]

    def boxed(flows, bg, line):
        t = Table([[flows]], colWidths=[TEXT_W])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg), ("LINEBEFORE", (0, 0), (0, -1), 2, line),
            ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        t.spaceBefore, t.spaceAfter = 3, 9
        return t

    def table_flow(rows):
        ncol = max(len(r) for r in rows)
        rows = [r + [""] * (ncol - len(r)) for r in rows]
        size = 8.7 if ncol <= 2 else 8.3 if ncol <= 4 else 7.6 if ncol <= 6 else 7.0 if ncol == 7 else 6.6
        side = 6 if ncol <= 6 else 4
        lead = round(size * 1.34, 1)
        cell = ParagraphStyle("cell", fontName="Helvetica", fontSize=size, leading=lead, textColor=C["body"],
                              splitLongWords=1)
        head = ParagraphStyle("head", parent=cell, fontName="Helvetica-Bold", textColor=colors.white)
        pad = 2 * side + 3.0
        mins, maxs = [], []
        for c in range(ncol):
            texts = [T(plain(r[c])) for r in rows]
            words = [w for t in texts for w in t.split()] or [""]
            longest = max(stringWidth(w, "Helvetica-Bold", size) for w in words)
            full = max(stringWidth(t, "Helvetica", size) for t in texts)
            # A word longer than this cap (a URL, a code name) breaks inside its cell
            # rather than starving the other columns; identifiers and dates stay whole.
            mins.append(min(longest, TEXT_W * (0.3 if ncol <= 4 else 0.15)) + pad)
            maxs.append(max(full, longest) + pad)
        if sum(mins) >= TEXT_W:
            # Water-fill: cap the widest minimums (long URLs, code names) so the short
            # columns keep their longest word whole and only the long words break.
            lo, hi = 0.0, max(mins)
            for _ in range(40):
                cap = (lo + hi) / 2
                if sum(min(m, cap) for m in mins) > TEXT_W * 0.97:
                    hi = cap
                else:
                    lo = cap
            mins = [min(m, lo) for m in mins]
        if sum(maxs) <= TEXT_W:
            widths = [m + (TEXT_W - sum(maxs)) * m / sum(maxs) for m in maxs]
        elif sum(mins) >= TEXT_W:
            widths = [TEXT_W * m / sum(mins) for m in mins]
        else:
            extra = TEXT_W - sum(mins)
            want = [mx - mn for mx, mn in zip(maxs, mins)]
            widths = [mn + extra * w / sum(want) for mn, w in zip(mins, want)]
        data = [[Paragraph(inline(T(c), size), head if k == 0 else cell) for c in r] for k, r in enumerate(rows)]
        t = Table(data, colWidths=widths, repeatRows=1, hAlign="CENTER")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C["navy"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C["rowalt"]]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), side), ("RIGHTPADDING", (0, 0), (-1, -1), side),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, -1), (-1, -1), 0.5, C["rule"]),
        ]))
        t.spaceBefore, t.spaceAfter = 4, 10
        return t

    italic_line = re.compile(r"^(\*[^*].*\*|_[^_].*_)$")
    blocks = parse_blocks(study.body)
    for k, b in enumerate(blocks):
        kind = b[0]
        if kind == "h":
            level, text = b[1], T(b[2])
            if level <= 2:
                story.append(Paragraph(inline(text, 14.5), h2))
                rule = HRFlowable(width="100%", thickness=1.1, color=C["red"], spaceBefore=1, spaceAfter=7,
                                  lineCap="round")
                rule.keepWithNext = 1
                story.append(rule)
            else:
                story.append(Paragraph(inline(text, 11.3), h3 if level == 3 else h4))
        elif kind == "p":
            s = b[1].strip()
            if italic_line.match(s):
                story.append(Paragraph("<i>" + inline(T(s[1:-1]), 8.4) + "</i>", notice))
            elif s.startswith("Evidence grade"):
                story.append(boxed(Paragraph(inline(T(s), 9.6), callout), C["callout"], C["green"]))
            else:
                story.append(Paragraph(inline(T(s), 9.6), body))
        elif kind == "list":
            indents = sorted({it[0] for it in b[1]})
            for indent, marker, text in b[1]:
                depth = indents.index(indent)
                bullet = "\u2022" if marker in "-*+" else marker
                st = ParagraphStyle(f"li{depth}", parent=item, leftIndent=16 + depth * 16,
                                    bulletIndent=4 + depth * 16, bulletFontName="Helvetica",
                                    bulletFontSize=9.6 if bullet == "\u2022" else 9.2)
                story.append(Paragraph(inline(T(text), 9.6), st, bulletText=bullet))
            story.append(Spacer(1, 4))
        elif kind == "table":
            story.append(table_flow(b[1]))
        elif kind == "quote":
            story.append(boxed([Paragraph(inline(T(p), 9.2), quote) for p in b[1]], C["rowalt"], C["teal"]))
        elif kind == "code":
            chars = int((TEXT_W - 24) / (7.6 * 0.6))
            text = T(b[1].expandtabs(4))
            story.append(Preformatted(text, code, maxLineLength=chars, newLineChars=""))
        elif kind == "img":
            src = b[2]
            path = os.path.join(ROOT, src.lstrip("/")) if src.startswith("/") else \
                os.path.normpath(os.path.join(os.path.dirname(study.path), src))
            if not os.path.isfile(path):
                raise SystemExit(f"error: {rel(study.path)}: image not found: {src}")
            from PIL import Image as PILImage
            with PILImage.open(path) as im:
                iw, ih = im.size
            w = TEXT_W
            h = w * ih / iw
            max_h = PAGE_H - TOP_MARGIN - BOTTOM_MARGIN - 90
            if h > max_h:
                w, h = w * max_h / h, max_h
            img = Image(path, width=w, height=h)
            img.hAlign = "CENTER"
            nxt = blocks[k + 1] if k + 1 < len(blocks) else None
            if nxt and nxt[0] == "p" and italic_line.match(nxt[1].strip()):
                img.keepWithNext = 1
            story += [Spacer(1, 4), img, Spacer(1, 6)]
        elif kind == "hr":
            story.append(HRFlowable(width="100%", thickness=0.6, color=C["rule"], spaceBefore=6, spaceAfter=8))

    title_t = T(study.title)
    date_t = T(study.published)

    def later(canv, doc):
        canv.saveState()
        canv.setFillColor(C["navy"])
        canv.rect(0, PAGE_H - 40.32, PAGE_W, 40.32, stroke=0, fill=1)
        canv.setFillColor(C["red"])
        canv.rect(0, PAGE_H - 41.76, PAGE_W, 2.16, stroke=0, fill=1)
        canv.setFillColor(C["cream"])
        canv.setFont("Helvetica-Bold", 8.5)
        canv.drawString(MARGIN_X, PAGE_H - 27.36, "TEAM STAR WOLF")
        room = PAGE_W - 2 * MARGIN_X - stringWidth("TEAM STAR WOLF", "Helvetica-Bold", 8.5) - 24
        shown = title_t
        if stringWidth(shown, "Helvetica", 8.5) > room:
            words = shown.split()
            while words and stringWidth(" ".join(words) + "...", "Helvetica", 8.5) > room:
                words.pop()
            shown = " ".join(words).rstrip(",:;") + "..."
        canv.setFillColor(colors.white)
        canv.setFont("Helvetica", 8.5)
        canv.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 27.36, shown)
        canv.setStrokeColor(C["rule"])
        canv.setLineWidth(0.6)
        canv.line(MARGIN_X, 47.52, PAGE_W - MARGIN_X, 47.52)
        canv.setFillColor(C["muted"])
        canv.setFont("Helvetica", 8)
        canv.drawString(MARGIN_X, 36, "teamstarwolf.github.io")
        canv.drawCentredString(PAGE_W / 2, 36, date_t)
        canv.drawRightString(PAGE_W - MARGIN_X, 36, f"Page {doc.page}")
        canv.restoreState()

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp = out_path + ".tmp"
    doc = SimpleDocTemplate(tmp, pagesize=letter, leftMargin=MARGIN_X, rightMargin=MARGIN_X,
                            topMargin=TOP_MARGIN, bottomMargin=BOTTOM_MARGIN, title=title_t,
                            author="TeamStarWolf", subject="TeamStarWolf case study",
                            creator="scripts/export_case_study.py", invariant=1)
    doc.build(story, onFirstPage=lambda c, d: None, onLaterPages=later)
    os.replace(tmp, out_path)
    if unmapped:
        print(f"warning: {rel(md_path)}: characters shown as '?': {''.join(sorted(unmapped))}", file=sys.stderr)
    return out_path


# ----------------------------------------------------------------------------- slide plans
@dataclass
class Para:
    text: str
    level: int = 0          # -1 = no bullet, 0 = bullet, 1 = second-level bullet


@dataclass
class SlidePlan:
    line_no: int
    kicker: str
    title: str
    paras: list = field(default_factory=list)
    left_head: str = ""
    left: list = field(default_factory=list)
    right_head: str = ""
    right: list = field(default_factory=list)
    has_columns: bool = False
    stats: list = field(default_factory=list)
    table: list = field(default_factory=list)
    caption: str = ""
    notes: str = ""


@dataclass
class DeckPlan:
    path: str
    title: str = ""
    study: str = ""
    cover_lines: list = field(default_factory=list)
    subtitle: str = ""
    published: str = ""
    cover_notes: str = ""
    slides: list = field(default_factory=list)


def parse_plan(path: str):
    plan, errors = DeckPlan(path), []
    cur = None
    target = "body"
    where = rel(path)
    for n, raw in enumerate(read_text(path).splitlines(), 1):
        line = raw.rstrip()
        s = line.strip()
        if not s:
            continue
        if EM_DASH in s:
            errors.append(f"{where}:{n}: em dash (U+2014)")
        if line.startswith("# ") and not plan.title:
            plan.title = re.sub(r"^Slide plan:\s*", "", s[2:].strip())
            continue
        if line.startswith("## "):
            m = re.match(r"^##\s+(.+?)\s+\|\s+(.+)$", line)
            if not m:
                errors.append(f"{where}:{n}: a slide heading reads '## KICKER | Narrative title'")
                continue
            cur = SlidePlan(n, m.group(1).strip(), m.group(2).strip())
            plan.slides.append(cur)
            target = "body"
            continue
        if cur is None:
            m = re.match(r"^- (Study|Cover title|Subtitle|Published|Notes):\s*(.+)$", s)
            if not m:
                errors.append(f"{where}:{n}: unexpected line before the first slide: {s[:60]}")
                continue
            key, val = m.group(1), m.group(2).strip()
            if key == "Study":
                plan.study = val.lstrip("/")
            elif key == "Cover title":
                plan.cover_lines = [p.strip() for p in val.split(" / ") if p.strip()]
            elif key == "Subtitle":
                plan.subtitle = val
            elif key == "Published":
                plan.published = val
            else:
                plan.cover_notes = val
            continue
        m = re.match(r"^(Notes|Caption|Stat|Left|Right):\s*(.*)$", s)
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key == "Notes":
                cur.notes = (cur.notes + " " + val).strip()
            elif key == "Caption":
                cur.caption = val
            elif key == "Stat":
                if " | " not in val:
                    errors.append(f"{where}:{n}: a Stat line reads 'Stat: VALUE | caption'")
                else:
                    v, c = val.split(" | ", 1)
                    cur.stats.append((v.strip(), c.strip()))
            elif key == "Left":
                cur.has_columns, cur.left_head, target = True, val, "left"
            else:
                cur.has_columns, cur.right_head, target = True, val, "right"
            continue
        if s.startswith("|"):
            cells = split_cells(s)
            if not all(SEP_CELL_RE.match(c.replace(" ", "")) for c in cells):
                cur.table.append(cells)
            continue
        m = LIST_RE.match(line)
        para = Para(m.group(3).strip(), 0 if len(m.group(1)) < 2 else 1) if m else Para(s, -1)
        {"body": cur.paras, "left": cur.left, "right": cur.right}[target].append(para)
    return plan, errors


# ----------------------------------------------------------------------------- deck layout
SLIDE_W, SLIDE_H = 13.333, 7.5
LM, CW = 0.62, 12.09
BODY_TOP = 1.75
BODY_BOTTOM = 6.92
CAPTION_Y, CAPTION_H = 6.5, 0.42
INSET_X, INSET_Y = 0.08, 0.04
COLORS = {"navy": "16243A", "ink": "141C28", "teal": "168F87", "orange": "E4572E", "light": "F2F5FB",
          "line": "D5DCE6", "mid": "56657F", "white": "FFFFFF", "soft": "A9B6C9"}
# Average glyph width as a share of the point size, set on the wide side so an estimate that
# fits leaves room on the slide.
EM = {"Calibri": 0.50, "Cambria": 0.55}
LINE = 1.22


def wrap_lines(text: str, cpl: int) -> int:
    lines, cur = 1, 0
    for word in text.split():
        size = len(word)
        if cur == 0:
            cur = size
        elif cur + 1 + size <= cpl:
            cur += 1 + size
        else:
            lines += 1
            cur = size
        while cur > cpl:
            lines += 1
            cur -= cpl
    return lines


def text_need(paras: list, width_in: float) -> float:
    """Points of height a box needs. paras: (text, size, font, indent_in, space_after_pt)."""
    total = 0.0
    for text, size, font, indent, after in paras:
        cpl = max(1, int(((width_in - 2 * INSET_X - indent) * 72) / (size * EM[font])))
        total += wrap_lines(plain(text), cpl) * size * LINE + after
    return total + 2 * INSET_Y * 72


def capacity(width_in: float, height_in: float, size: float, font: str = "Calibri") -> int:
    """The character budget of a box: characters per line times lines that fit."""
    cpl = int(((width_in - 2 * INSET_X) * 72) / (size * EM[font]))
    lines = int(((height_in - 2 * INSET_Y) * 72) / (size * LINE))
    return max(0, cpl * lines)


@dataclass
class Box:
    name: str
    x: float
    y: float
    w: float
    h: float
    paras: list            # dicts: text, size, font, color, bold, level, after, align
    anchor: str = "t"


@dataclass
class Layout:
    boxes: list = field(default_factory=list)
    stats: list = field(default_factory=list)      # (x, y, w, h)
    table: dict = None


BULLET_INDENT = {-1: 0.0, 0: 0.3, 1: 0.65}


def body_paras(paras: list, size0: float, size1: float) -> list:
    out = []
    for p in paras:
        size = size1 if p.level == 1 else size0
        out.append({"text": p.text, "size": size, "font": "Calibri", "color": COLORS["ink"], "bold": False,
                    "level": p.level, "after": 7 if p.level <= 0 else 4, "align": "l"})
    return out


def need_of(box_paras: list, width: float) -> float:
    return text_need([(p["text"], p["size"], p["font"], BULLET_INDENT.get(p["level"], 0), p["after"])
                      for p in box_paras], width) / 72


def table_layout(rows: list, width: float) -> dict:
    ncol = max(len(r) for r in rows)
    rows = [r + [""] * (ncol - len(r)) for r in rows]
    size = 12.0 if (len(rows) <= 7 and ncol <= 3) else 11.0
    lens = [max(len(plain(r[c])) for r in rows) for c in range(ncol)]
    longest = [max((len(w) for r in rows for w in plain(r[c]).split()), default=4) for c in range(ncol)]
    mins = [max(1.2, min(4.0, lw * size * EM["Calibri"] / 72 + 0.25)) for lw in longest]
    weights = [max(1, ln) ** 0.8 for ln in lens]
    widths = [width * w / sum(weights) for w in weights]
    for _ in range(3):
        short = [k for k in range(ncol) if widths[k] < mins[k]]
        if not short:
            break
        for k in short:
            widths[k] = mins[k]
        rest = [k for k in range(ncol) if k not in short]
        room = width - sum(widths[k] for k in short)
        tot = sum(weights[k] for k in rest) or 1
        for k in rest:
            widths[k] = room * weights[k] / tot
    heights = []
    for r in rows:
        need = max(text_need([(c, size, "Calibri", 0, 0)], widths[j]) for j, c in enumerate(r)) / 72
        heights.append(max(0.36, need + 0.04))
    return {"rows": rows, "size": size, "widths": widths, "heights": heights}


def layout_slide(sp: SlidePlan, where: str):
    lay, errors = Layout(), []
    tag = f"{where}:{sp.line_no}"
    if len(sp.kicker) > 40 or sp.kicker != sp.kicker.upper():
        errors.append(f"{tag}: kicker must be capitals and at most 40 characters: {sp.kicker}")
    # Title: one line at 27 pt, or at 24 pt when it is a little longer.
    title_size = None
    for size in (27.0, 24.0):
        if text_need([(sp.title, size, "Cambria", 0, 0)], CW) / 72 <= 0.62:
            title_size = size
            break
    if title_size is None:
        errors.append(f"{tag}: title is {len(sp.title)} characters; the budget is "
                      f"{capacity(CW, 0.62, 24.0, 'Cambria')} on one line: {sp.title}")
        title_size = 24.0
    lay.boxes.append(Box("kicker", LM, 0.50, CW, 0.30, [{"text": sp.kicker, "size": 11.0, "font": "Calibri",
                         "color": COLORS["teal"], "bold": True, "level": -1, "after": 0, "align": "l"}]))
    lay.boxes.append(Box("title", LM, 0.78, CW, 0.62, [{"text": sp.title, "size": title_size, "font": "Cambria",
                         "color": COLORS["navy"], "bold": True, "level": -1, "after": 0, "align": "l"}]))
    if not sp.notes:
        errors.append(f"{tag}: no Notes line; speaker notes carry the source numbers")
    if not (sp.paras or sp.has_columns or sp.stats or sp.table):
        errors.append(f"{tag}: the slide has no body")
    if sp.stats and not 2 <= len(sp.stats) <= 4:
        errors.append(f"{tag}: a stat row has two to four numbers, not {len(sp.stats)}")
    bottom = CAPTION_Y - 0.06 if sp.caption else BODY_BOTTOM
    if sp.caption:
        cap = [{"text": sp.caption, "size": 11.5, "font": "Calibri", "color": COLORS["mid"], "bold": False,
                "level": -1, "after": 0, "align": "l"}]
        if need_of(cap, CW) > CAPTION_H:
            errors.append(f"{tag}: caption is {len(sp.caption)} characters; the budget is "
                          f"{capacity(CW, CAPTION_H, 11.5)} on one line")
        lay.boxes.append(Box("caption", LM, CAPTION_Y, CW, CAPTION_H, cap))
    y = BODY_TOP
    if sp.stats:
        n = max(1, min(4, len(sp.stats)))
        gap = 0.25
        cw = (CW - gap * (n - 1)) / n
        for k, (val, cap) in enumerate(sp.stats[:4]):
            x = LM + k * (cw + gap)
            vbox = [{"text": val, "size": 34.0, "font": "Cambria", "color": COLORS["orange"] if k == 0 else
                     COLORS["teal"], "bold": True, "level": -1, "after": 0, "align": "l"}]
            cbox = [{"text": cap, "size": 12.5, "font": "Calibri", "color": COLORS["mid"], "bold": False,
                     "level": -1, "after": 0, "align": "l"}]
            if need_of(vbox, cw - 0.3) > 0.72:
                errors.append(f"{tag}: stat value '{val}' is {len(val)} characters; the budget is "
                              f"{capacity(cw - 0.3, 0.72, 34.0, 'Cambria')}")
            if need_of(cbox, cw - 0.3) > 0.62:
                errors.append(f"{tag}: stat caption is {len(cap)} characters; the budget is "
                              f"{capacity(cw - 0.3, 0.62, 12.5)}: {cap}")
            lay.stats.append((x, y + 0.05, cw, 1.5))
            lay.boxes.append(Box(f"stat {k + 1} value", x + 0.15, y + 0.2, cw - 0.3, 0.72, vbox))
            lay.boxes.append(Box(f"stat {k + 1} caption", x + 0.15, y + 0.88, cw - 0.3, 0.62, cbox))
        y += 1.55 + 0.22
    parts = []
    if sp.paras:
        size0, size1 = (16.5, 15.0) if not (sp.stats or sp.table or sp.has_columns) else (15.0, 14.0)
        bp = body_paras(sp.paras, size0, size1)
        parts.append(("body", need_of(bp, CW), bp))
    if sp.has_columns:
        cols = []
        for head, items in ((sp.left_head, sp.left), (sp.right_head, sp.right)):
            ps = []
            if head:
                ps.append({"text": head, "size": 15.0, "font": "Calibri", "color": COLORS["teal"], "bold": True,
                           "level": -1, "after": 6, "align": "l"})
            ps += body_paras(items, 15.0, 13.5)
            cols.append(ps)
        colw = (CW - 0.35) / 2
        parts.append(("columns", max(need_of(c, colw) for c in cols), cols))
    if sp.table:
        tl = table_layout(sp.table, CW)
        parts.append(("table", sum(tl["heights"]), tl))
    gaps = 0.15 * (len(parts) - 1)
    total = sum(p[1] for p in parts) + gaps
    room = bottom - y
    if total > room + 1e-6:
        detail = ", ".join(f"{p[0]} {p[1]:.2f} in" for p in parts)
        errors.append(f"{tag}: the body needs {total:.2f} in but {room:.2f} in is free ({detail}); "
                      f"cut text or move some to the next slide")
    for k, (kind, need, data) in enumerate(parts):
        last = k == len(parts) - 1
        h = max(need, bottom - y) if last and kind != "table" else need
        if kind == "body":
            lay.boxes.append(Box("body", LM, y, CW, h, data))
        elif kind == "columns":
            colw = (CW - 0.35) / 2
            lay.boxes.append(Box("left column", LM, y, colw, h, data[0]))
            lay.boxes.append(Box("right column", LM + colw + 0.35, y, colw, h, data[1]))
        else:
            data["x"], data["y"] = LM, y
            lay.table = data
        y += h + 0.15
    return lay, errors


def check_plan(plan: DeckPlan) -> list:
    where = rel(plan.path)
    errors = []
    if not plan.study or not os.path.isfile(os.path.join(ROOT, plan.study)):
        errors.append(f"{where}: '- Study:' must name an existing study file, got '{plan.study}'")
    if not 2 <= len(plan.cover_lines) <= 3:
        errors.append(f"{where}: '- Cover title:' needs two or three lines separated by ' / '")
    cover_cpl = int(((CW - 2 * INSET_X) * 72) / (38.0 * EM["Cambria"]))
    for line in plan.cover_lines:
        if wrap_lines(line, cover_cpl) > 1:
            errors.append(f"{where}: cover title line is {len(line)} characters; the budget is "
                          f"{cover_cpl} on one line: {line}")
    if plan.cover_lines and text_need([(t, 38.0, "Cambria", 0, 0) for t in plan.cover_lines], CW) / 72 > 2.1:
        errors.append(f"{where}: the cover title needs more than its 2.1 in box")
    if not plan.subtitle:
        errors.append(f"{where}: '- Subtitle:' is missing")
    elif text_need([(plan.subtitle, 18.0, "Calibri", 0, 0)], 10.09) / 72 > 0.8:
        errors.append(f"{where}: subtitle is {len(plan.subtitle)} characters; the budget is "
                      f"{capacity(10.09, 0.8, 18.0)}")
    if not re.match(r"^\d{1,2} [A-Z][a-z]+ \d{4}$", plan.published):
        errors.append(f"{where}: '- Published:' reads like '4 November 2026'")
    count = len(plan.slides) + 1
    if not 13 <= count <= 16:
        errors.append(f"{where}: {count} slides counting the cover; a deck has 13 to 16")
    for sp in plan.slides:
        errors += layout_slide(sp, where)[1]
    return errors


# ----------------------------------------------------------------------------- deck writer
def _rgb(hexstr: str):
    from pptx.dml.color import RGBColor
    return RGBColor.from_string(hexstr)


def _bold_runs(text: str) -> list:
    out = []
    for p in re.split(r"(\*\*.+?\*\*)", text):
        if not p:
            continue
        if p.startswith("**") and p.endswith("**") and len(p) > 4:
            out.append((p[2:-2], True))
        else:
            out.append((p, False))
    return out


def _bullet(para, level: int) -> None:
    from lxml import etree
    from pptx.oxml.ns import qn
    from pptx.util import Inches
    pPr = para._p.get_or_add_pPr()
    for tag in ("a:buClr", "a:buSzPct", "a:buFont", "a:buNone", "a:buChar", "a:buAutoNum"):
        for el in pPr.findall(qn(tag)):
            pPr.remove(el)
    if level < 0:
        pPr.set("marL", "0")
        pPr.set("indent", "0")
        etree.SubElement(pPr, qn("a:buNone"))
        return
    pPr.set("marL", str(int(Inches(BULLET_INDENT[level]))))
    pPr.set("indent", str(-int(Inches(0.24 if level == 0 else 0.22))))
    clr = etree.SubElement(pPr, qn("a:buClr"))
    etree.SubElement(clr, qn("a:srgbClr")).set("val", COLORS["teal"] if level == 0 else COLORS["mid"])
    etree.SubElement(pPr, qn("a:buFont")).set("typeface", "Arial")
    etree.SubElement(pPr, qn("a:buChar")).set("char", "\u2022" if level == 0 else "\u2013")


def _fill_tf(tf, paras: list) -> None:
    from pptx.enum.text import PP_ALIGN
    from pptx.util import Pt
    for k, p in enumerate(paras):
        para = tf.paragraphs[0] if k == 0 else tf.add_paragraph()
        para.alignment = {"l": PP_ALIGN.LEFT, "c": PP_ALIGN.CENTER, "r": PP_ALIGN.RIGHT}[p.get("align", "l")]
        para.line_spacing = 1.0
        para.space_after = Pt(p.get("after", 0))
        _bullet(para, p.get("level", -1))
        for text, bold in _bold_runs(p["text"]):
            run = para.add_run()
            run.text = text
            f = run.font
            f.name = p["font"]
            f.size = Pt(p["size"])
            f.bold = bool(bold or p.get("bold"))
            f.color.rgb = _rgb(p["color"])


def _textbox(slide, box: Box):
    from pptx.enum.text import MSO_ANCHOR, MSO_AUTO_SIZE
    from pptx.util import Inches
    shape = slide.shapes.add_textbox(Inches(box.x), Inches(box.y), Inches(box.w), Inches(box.h))
    shape.name = box.name
    tf = shape.text_frame
    tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.NONE
    tf.margin_left = tf.margin_right = Inches(INSET_X)
    tf.margin_top = tf.margin_bottom = Inches(INSET_Y)
    tf.vertical_anchor = {"t": MSO_ANCHOR.TOP, "m": MSO_ANCHOR.MIDDLE, "b": MSO_ANCHOR.BOTTOM}[box.anchor]
    _fill_tf(tf, box.paras)
    return shape


def _rect(slide, x, y, w, h, color, name):
    from pptx.enum.shapes import MSO_SHAPE
    from pptx.util import Inches
    shp = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    shp.name = name
    shp.fill.solid()
    shp.fill.fore_color.rgb = _rgb(color)
    shp.line.fill.background()
    shp.shadow.inherit = False
    return shp


def _cell_borders(cell, color: str) -> None:
    from lxml import etree
    from pptx.oxml.ns import qn
    tcPr = cell._tc.get_or_add_tcPr()
    for tag in ("a:lnB", "a:lnT", "a:lnR", "a:lnL"):
        ln = etree.Element(qn(tag), w="6350", cap="flat", cmpd="sng", algn="ctr")
        fill = etree.SubElement(ln, qn("a:solidFill"))
        etree.SubElement(fill, qn("a:srgbClr")).set("val", color)
        etree.SubElement(ln, qn("a:prstDash")).set("val", "solid")
        tcPr.insert(0, ln)


def _footer(slide, date: str, number: int) -> None:
    _rect(slide, LM, 7.0, CW, 0.02, COLORS["orange"], "footer rule")
    base = {"font": "Calibri", "size": 9.0, "color": COLORS["mid"], "level": -1, "after": 0}
    _textbox(slide, Box("footer left", LM, 7.03, 4.0, 0.3, [dict(base, text="TEAM STAR WOLF", bold=True)]))
    _textbox(slide, Box("footer centre", 3.67, 7.03, 6.0, 0.3,
                        [dict(base, text=f"teamstarwolf.github.io  \u00b7  {date}", bold=False, align="c")]))
    _textbox(slide, Box("footer number", 11.71, 7.03, 1.0, 0.3,
                        [dict(base, text=str(number), bold=False, align="r")]))


def render_deck(plan: DeckPlan, out_path: str) -> str:
    from pptx import Presentation
    from pptx.util import Inches
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(SLIDE_W), Inches(SLIDE_H)
    blank = prs.slide_layouts[6]
    where = rel(plan.path)

    cover = prs.slides.add_slide(blank)
    cover.background.fill.solid()
    cover.background.fill.fore_color.rgb = _rgb(COLORS["navy"])
    _rect(cover, 0, 0, SLIDE_W, 0.16, COLORS["orange"], "top band")
    _textbox(cover, Box("kicker", LM, 1.5, CW, 0.4, [{"text": "TEAM STAR WOLF  \u00b7  CASE STUDY", "size": 14.0,
             "font": "Calibri", "color": COLORS["teal"], "bold": True, "level": -1, "after": 0}]))
    _textbox(cover, Box("title", LM, 1.98, CW, 2.1, [{"text": t, "size": 38.0, "font": "Cambria", "color":
             COLORS["white"], "bold": True, "level": -1, "after": 0} for t in plan.cover_lines]))
    _rect(cover, LM, 4.16, 1.5, 0.05, COLORS["orange"], "title rule")
    _textbox(cover, Box("subtitle", LM, 4.34, 10.09, 0.8, [{"text": plan.subtitle, "size": 18.0, "font": "Calibri",
             "color": COLORS["soft"], "bold": False, "level": -1, "after": 0}]))
    _textbox(cover, Box("published", LM, 6.5, 9.5, 0.32, [{"text": f"Published {plan.published}", "size": 12.0,
             "font": "Calibri", "color": COLORS["soft"], "bold": False, "level": -1, "after": 0}]))
    pic = cover.shapes.add_picture(LOGO, Inches(11.11), Inches(6.35), Inches(1.6), Inches(0.53))
    pic.name = "logo"
    cover.notes_slide.notes_text_frame.text = plan.cover_notes or f"Study: {plan.study}"

    for number, sp in enumerate(plan.slides, 2):
        lay, errors = layout_slide(sp, where)
        if errors:
            raise SystemExit("\n".join(errors))
        slide = prs.slides.add_slide(blank)
        slide.background.fill.solid()
        slide.background.fill.fore_color.rgb = _rgb(COLORS["white"])
        _rect(slide, LM, 1.46, 1.1, 0.04, COLORS["orange"], "title rule")
        for k, (x, y, w, h) in enumerate(lay.stats):
            _rect(slide, x, y, w, h, COLORS["light"], f"stat {k + 1} card")
            _rect(slide, x, y, w, 0.06, COLORS["orange"] if k == 0 else COLORS["teal"], f"stat {k + 1} accent")
        for box in lay.boxes:
            _textbox(slide, box)
        if lay.table:
            tl = lay.table
            nrow, ncol = len(tl["rows"]), len(tl["widths"])
            gf = slide.shapes.add_table(nrow, ncol, Inches(tl["x"]), Inches(tl["y"]), Inches(CW),
                                        Inches(sum(tl["heights"])))
            gf.name = "table"
            tbl = gf.table
            tbl.first_row = True
            tbl.horz_banding = False
            for j, w in enumerate(tl["widths"]):
                tbl.columns[j].width = Inches(w)
            for r, row in enumerate(tl["rows"]):
                tbl.rows[r].height = Inches(tl["heights"][r])
                for j, text in enumerate(row):
                    cell = tbl.cell(r, j)
                    cell.margin_left = cell.margin_right = Inches(INSET_X)
                    cell.margin_top = cell.margin_bottom = Inches(INSET_Y)
                    cell.fill.solid()
                    cell.fill.fore_color.rgb = _rgb(COLORS["navy"] if r == 0 else
                                                    (COLORS["light"] if r % 2 == 0 else COLORS["white"]))
                    _cell_borders(cell, COLORS["line"])
                    tf = cell.text_frame
                    tf.word_wrap = True
                    _fill_tf(tf, [{"text": text, "size": tl["size"], "font": "Calibri",
                                   "color": COLORS["white"] if r == 0 else COLORS["ink"], "bold": r == 0,
                                   "level": -1, "after": 0}])
        _footer(slide, plan.published, number)
        slide.notes_slide.notes_text_frame.text = sp.notes
    props = prs.core_properties
    props.title = plan.title
    props.author = "TeamStarWolf"
    props.subject = "TeamStarWolf case study"
    props.last_modified_by = "TeamStarWolf"
    props.revision = 1
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp = out_path + ".tmp"
    prs.save(tmp)
    problems = verify_pptx(tmp)
    if problems:
        os.remove(tmp)
        raise SystemExit("error: the written deck failed its read-back check:\n" + "\n".join(problems))
    os.replace(tmp, out_path)
    return out_path


def verify_pptx(path: str) -> list:
    """Read a deck back and check every text frame and table against its box."""
    from pptx import Presentation
    from pptx.util import Emu
    problems = []
    prs = Presentation(path)

    def inches(v) -> float:
        return Emu(v).inches

    for idx, slide in enumerate(prs.slides, 1):
        caption_top = None
        for shape in slide.shapes:
            if shape.name == "caption":
                caption_top = inches(shape.top)
        for shape in slide.shapes:
            if shape.has_text_frame and shape.text_frame.text.strip():
                tf = shape.text_frame
                paras = []
                for p in tf.paragraphs:
                    if not p.runs:
                        continue
                    size = max((r.font.size.pt for r in p.runs if r.font.size), default=18.0)
                    font = p.runs[0].font.name or "Calibri"
                    pPr = p._p.pPr
                    mar = int(pPr.get("marL", "0")) / 914400 if pPr is not None else 0.0
                    after = p.space_after.pt if p.space_after is not None else 0.0
                    paras.append((p.text, size, font if font in EM else "Calibri", mar, after))
                need = text_need(paras, inches(shape.width)) / 72
                if need > inches(shape.height) + 0.01:
                    problems.append(f"slide {idx} '{shape.name}': text needs {need:.2f} in, the box is "
                                    f"{inches(shape.height):.2f} in")
                if inches(shape.top) + inches(shape.height) > SLIDE_H + 0.01:
                    problems.append(f"slide {idx} '{shape.name}': box runs off the slide")
            if shape.has_table:
                tbl = shape.table
                total = 0.0
                for row in tbl.rows:
                    row_need = 0.0
                    for j, cell in enumerate(row.cells):
                        runs = [run for p in cell.text_frame.paragraphs for run in p.runs]
                        size = max((run.font.size.pt for run in runs if run.font.size), default=12.0)
                        width = inches(tbl.columns[j].width)
                        row_need = max(row_need, text_need([(cell.text_frame.text, size, "Calibri", 0, 0)],
                                                           width) / 72)
                    total += max(row_need + 0.04, inches(row.height))
                limit = (caption_top - 0.04) if caption_top else 6.97
                if inches(shape.top) + total > limit + 0.01:
                    problems.append(f"slide {idx} table: rows need {total:.2f} in from {inches(shape.top):.2f} in, "
                                    f"past the {limit:.2f} in limit")
    return problems


# ----------------------------------------------------------------------------- check
def run_check() -> int:
    problems: list = []
    rows = readme_rows()
    if not rows:
        problems.append("case-studies/README.md: no study rows found")
    names: dict = {}
    for stem in sorted(set(EXPORT_NAMES) | {r.stem for r in rows}):
        name = export_name(stem).lower()
        if name in names:
            problems.append(f"export name collision: {stem} and {names[name]} both export as {export_name(stem)}")
        names[name] = stem
    known = {export_name(r.stem) for r in rows}
    for r in rows:
        where = f"case-studies/README.md:{r.line_no}"
        if not os.path.isfile(os.path.join(CS_DIR, r.stem + ".md")):
            problems.append(f"{where}: the study file case-studies/{r.stem}.md does not exist")
        name = export_name(r.stem)
        links = [u for _, u in LINK_ANY_RE.findall(r.cell)]
        outside = LINK_ANY_RE.sub("", r.cell)
        for kind, folder, ext in (("PDF", "pdf", "pdf"), ("deck", "slides", "pptx")):
            mine = [u for u in links if u.lower().endswith("." + ext)]
            if mine:
                want = f"{RAW_BASE}{folder}/{name}.{ext}"
                for u in mine:
                    if u != want:
                        problems.append(f"{where}: {kind} link {u} should be {want}")
                if not os.path.isfile(os.path.join(CS_DIR, folder, f"{name}.{ext}")):
                    problems.append(f"{where}: links case-studies/{folder}/{name}.{ext}, which does not exist")
            elif not REASON_RE.search(outside):
                problems.append(f"{where}: no {kind} link and no plain-text reason (such as 'Slides: pending')")
    for folder, ext in (("pdf", "pdf"), ("slides", "pptx")):
        d = os.path.join(CS_DIR, folder)
        for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if fn.lower().endswith("." + ext) and fn[: -len(ext) - 1] not in known:
                problems.append(f"case-studies/{folder}/{fn}: matches no study row in case-studies/README.md")
    if os.path.isdir(PLAN_DIR):
        for fn in sorted(os.listdir(PLAN_DIR)):
            if fn.endswith(".md"):
                plan, errors = parse_plan(os.path.join(PLAN_DIR, fn))
                problems += errors + check_plan(plan)
                stem = os.path.splitext(fn)[0]
                if plan.study and os.path.splitext(os.path.basename(plan.study))[0] != stem:
                    problems.append(f"case-studies/slides/plans/{fn}: the plan is named for {stem} but its "
                                    f"Study line names {plan.study}")
    for p in problems:
        print(p)
    print(f"export_case_study --check: {len(rows)} study rows, "
          f"{'OK' if not problems else str(len(problems)) + ' problem(s)'}")
    return 1 if problems else 0


# ----------------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="verify README links, plan budgets and names")
    ap.add_argument("command", nargs="?", choices=("pdf", "pptx", "all-pdf"))
    ap.add_argument("path", nargs="?", help="the study (pdf) or the slide plan (pptx)")
    args = ap.parse_args(argv)
    if args.check:
        return run_check()
    if args.command == "pdf":
        if not args.path:
            ap.error("pdf needs a study path")
        print(rel(build_pdf(resolve_input(args.path))))
        return 0
    if args.command == "pptx":
        if not args.path:
            ap.error("pptx needs a slide plan path")
        path = resolve_input(args.path)
        plan, errors = parse_plan(path)
        errors += check_plan(plan)
        if errors:
            print("\n".join(errors), file=sys.stderr)
            print(f"error: {rel(path)}: the plan breaks its budgets; nothing was written", file=sys.stderr)
            return 1
        stem = os.path.splitext(os.path.basename(plan.study))[0]
        print(rel(render_deck(plan, os.path.join(PPTX_DIR, export_name(stem) + ".pptx"))))
        return 0
    if args.command == "all-pdf":
        built = 0
        for r in readme_rows():
            out = os.path.join(PDF_DIR, export_name(r.stem) + ".pdf")
            if not os.path.isfile(out):
                print(rel(build_pdf(os.path.join(CS_DIR, r.stem + ".md"), out)))
                built += 1
        print(f"all-pdf: built {built}")
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
