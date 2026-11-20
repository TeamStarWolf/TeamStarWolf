#!/usr/bin/env python3
"""Repository hygiene gates that no single generator owns. Four checks:

1. junk     Fail if git tracks build/editor/OS junk (__pycache__/, *.pyc, venv/,
            node_modules/, .vs/, .idea/, .DS_Store, local DBs, the generator's old
            mitre/_gen_check/ scratch tree, the STIX cache). Everything tracked is
            published by the Pages deploy (.github/workflows/pages.yml), so junk in
            git is junk on the site.

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

4. paths    Fail if a tracked file carries a path from the machine that built it: a home
            directory for an account that is not a stock example name, an agent tool's
            encoded project directory, or, inside an Office file or a PDF, a temp-directory
            path, a file URL, or image alt text that is a file path. Everything tracked is
            published, and such a path names a local account and its folder layout. Pages
            quote example paths all the time, so a home-directory path passes when its
            account is in EXAMPLE_ACCOUNTS. Office files are unzipped and each PDF stream
            is decoded through the filters its dictionary names (ASCII85, hex, Flate),
            because a text search of the repository does not reach inside them. The PDF
            exporter writes ASCII85 over Flate, so inflating alone would read almost none
            of the page text. Text set in an embedded font is stored as glyph codes and is
            translated through the font's ToUnicode map. A PDF whose text cannot be read
            fails: an unread stream is an unchecked one. A message names the file and the
            kind of path and never prints the path, because the CI log is public too.

Usage:
    python scripts/check_repo_hygiene.py                    # all four gates
    python scripts/check_repo_hygiene.py --only encoding    # one gate (junk|encoding|revoked|paths)
    python scripts/check_repo_hygiene.py --self-test        # the PDF reader on built-in cases
    python scripts/check_repo_hygiene.py --report           # also list every baselined citation
    python scripts/check_repo_hygiene.py --update-baseline  # rewrite the revoked-ID baseline
"""
from __future__ import annotations

import argparse
import base64
import binascii
import collections
import io
import json
import os
import re
import sys
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_bytes, tracked_files  # noqa: E402
from attack_ids import ATTACK_VER  # noqa: E402

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
            ".txt", ".js", ".css", ".toml", ".gitignore", ".lycheeignore", ".nojekyll")
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
            problems.append(h[0] + ":" + str(h[1]) + ": cites " + h[2] + ", " + h[4] + " in the pinned ATT&CK " + ATTACK_VER + " data " +
                            "(use " + (h[3] or "a current technique; no direct replacement") + ")")
            over.pop(k)
    return problems


# ----------------------------------------------------------------------------- 4. build paths
# Account names that pages use in example paths. A home-directory path under one of these
# passes; under any other name it fails. Add a name here only when a page needs it as an
# example, never to quiet a path that came from a real machine.
EXAMPLE_ACCOUNTS = frozenset((
    "public", "default", "administrator", "admin", "user", "username", "victim", "attacker",
    "analyst", "guest", "test", "foo", "bar", "dev", "shared", "library", "alice", "bob",
    "john", "jane", "jdoe", "cowrie", "vault", "pi", "node", "runner", "root", "ubuntu",
    "ec2-user", "kali", "www-data",
))
# A separator is a slash or a backslash, single or doubled (JSON escapes double it).
_SEP = rb"[\\/]{1,2}"
_ACCOUNT = rb"([A-Za-z0-9._-]{1,40})"
# A drive letter, the users folder and an account; or a rooted users or home folder, an
# account and at least one more segment (which keeps an API route such as a SCIM users
# endpoint from matching).
HOME_RE = re.compile(rb"[A-Za-z]:" + _SEP + rb"(?i:users)" + _SEP + _ACCOUNT +
                     rb"|(?<![\w.])/(?:Users|home)/" + _ACCOUNT + rb"/")
# The form an agent tool gives a project directory: a drive letter, two hyphens, the
# users folder, a hyphen.
ENCODED_RE = re.compile(rb"(?<![\w-])[A-Za-z]--Users-")
# Checked only inside Office files and PDFs. Pages document temp folders and file URLs
# as subject matter; an exported file has no reason to hold either.
TEMP_RE = re.compile(rb"AppData" + _SEP + rb"Local" + _SEP + rb"Temp" + _SEP)
FILE_URL_RE = re.compile(rb"file:///")
ALT_PATH_RE = re.compile(rb'descr="(?:[A-Za-z]:[\\/]|[\\/~])')
OFFICE_EXT = (".pptx", ".potx", ".docx", ".xlsx")
INNER_TEXT_EXT = (".xml", ".rels", ".vml", ".txt", ".json")


def _home_path(blob: bytes) -> bool:
    for m in HOME_RE.finditer(blob):
        account = (m.group(1) or m.group(2)).decode("ascii", "replace").lower()
        if account not in EXAMPLE_ACCOUNTS and not account.isdigit():
            return True
    return False


def _path_kinds(blob: bytes, exported: bool) -> list[str]:
    kinds = []
    if _home_path(blob):
        kinds.append("a home-directory path for an account that is not in EXAMPLE_ACCOUNTS")
    if ENCODED_RE.search(blob):
        kinds.append("an agent tool's encoded project directory")
    if exported:
        if TEMP_RE.search(blob):
            kinds.append("a temp-directory path")
        if FILE_URL_RE.search(blob):
            kinds.append("a file URL")
        if ALT_PATH_RE.search(blob):
            kinds.append("image alt text that is a file path (describe the image instead)")
    return kinds


# A PDF stores each stream through the filters its dictionary names, so a stream is read
# by undoing that chain in order. "stream" also ends the word "endstream"; skip that one.
_STREAM_RE = re.compile(rb"(?<!end)stream\r?\n")
_FILTER_RE = re.compile(rb"(?<![A-Za-z])/Filter\s*(\[[^\]]*\]|/[A-Za-z0-9]+)")
_NAME_RE = re.compile(rb"/([A-Za-z0-9]+)")
_LITERAL_RE = re.compile(rb"\((?:\\.|[^\\()])*\)")
_HEXSTR_RE = re.compile(rb"<([0-9A-Fa-f\s]+)>")
_BFCHAR_RE = re.compile(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>")
_BFRANGE_RE = re.compile(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]+>|\[[^\]]*\])")
_ESCAPE_RE = re.compile(rb"\\([0-7]{1,3}|.)", re.S)
_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}
# Image codecs hold pixels, not text. A stream under one of them, or one its dictionary
# declares an image, is left alone.
_IMAGE_FILTERS = frozenset((b"DCTDecode", b"DCT", b"JPXDecode", b"CCITTFaxDecode", b"CCF",
                            b"JBIG2Decode"))
_IMAGE_RE = re.compile(rb"/Subtype\s*/Image(?![A-Za-z])")


def _a85(data: bytes) -> bytes:
    d = data.strip()
    if d.startswith(b"<~"):
        d = d[2:]
    end = d.rfind(b"~>")
    if end != -1:
        d = d[:end]
    return base64.a85decode(d, ignorechars=b" \t\n\r\v\f\x00")


def _ahx(data: bytes) -> bytes:
    d = re.sub(rb"\s", b"", data).rstrip(b">")
    return binascii.unhexlify(d + (b"0" if len(d) % 2 else b""))


def _flate(data: bytes) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error:
        return zlib.decompressobj().decompress(data)


_PDF_DECODERS = {b"ASCII85Decode": _a85, b"A85": _a85, b"ASCIIHexDecode": _ahx, b"AHx": _ahx,
                 b"FlateDecode": _flate, b"Fl": _flate}


def _pdf_streams(b: bytes):
    """Yield (decoded bytes or None, is_image) for each stream in a PDF."""
    for m in _STREAM_RE.finditer(b):
        end = b.find(b"endstream", m.end())
        if end == -1:
            continue
        # The stream's dictionary sits between the previous object's end and this keyword.
        head = b[max(b.rfind(b"endobj", 0, m.start()), 0):m.start()]
        fm = _FILTER_RE.search(head)
        chain = _NAME_RE.findall(fm.group(1)) if fm else []
        if _IMAGE_RE.search(head) or any(name in _IMAGE_FILTERS for name in chain):
            yield None, True
            continue
        data = b[m.end():end]
        try:
            for name in chain:
                data = _PDF_DECODERS[name](data)
        except (KeyError, ValueError, zlib.error):
            yield None, False
            continue
        yield data, False


def _unescape(m) -> bytes:
    g = m.group(1)
    return bytes([int(g, 8) & 0xFF]) if g[:1] in b"01234567" else _ESCAPES.get(g, g)


def _joined_strings(stream: bytes) -> bytes:
    """The string operands of a content stream, joined, so text that kerning split across
    several operands reads as one run."""
    return b"".join(_ESCAPE_RE.sub(_unescape, lit[1:-1]) for lit in _LITERAL_RE.findall(stream))


def _tounicode_maps(streams: list[bytes]) -> list[dict]:
    """One {(hex digits, code): UTF-16BE hex} map per ToUnicode CMap in the file."""
    maps = []
    for d in streams:
        if b"beginbfchar" not in d and b"beginbfrange" not in d:
            continue
        cmap = {}
        for block in re.findall(rb"beginbfchar(.*?)endbfchar", d, re.S):
            for src, dst in _BFCHAR_RE.findall(block):
                cmap[(len(src), int(src, 16))] = dst
        for block in re.findall(rb"beginbfrange(.*?)endbfrange", d, re.S):
            for lo, hi, dst in _BFRANGE_RE.findall(block):
                first, last = int(lo, 16), int(hi, 16)
                if not 0 <= last - first <= 0xFFFF:
                    continue
                if dst.startswith(b"["):
                    for i, item in enumerate(re.findall(rb"<([0-9A-Fa-f]+)>", dst)):
                        cmap[(len(lo), first + i)] = item
                else:
                    width, base = len(dst) - 2, int(dst[1:-1], 16)
                    for i in range(last - first + 1):
                        cmap[(len(lo), first + i)] = format(base + i, "0%dX" % width).encode()
        if cmap:
            maps.append(cmap)
    return maps


def _glyph_text(streams: list[bytes], cmap: dict) -> bytes:
    """Every hex string operand in the file, read through one ToUnicode map. Which font a
    string is set in is not tracked: each map is tried on all of them, and the right one
    yields the text."""
    width = next(iter(cmap))[0]
    out = []
    for stream in streams:
        for h in _HEXSTR_RE.findall(stream):
            h = re.sub(rb"\s", b"", h)
            for i in range(0, len(h) - width + 1, width):
                dst = cmap.get((width, int(h[i:i + width], 16)))
                if dst and len(dst) % 2 == 0:
                    out.append(binascii.unhexlify(dst).decode("utf-16-be", "ignore"))
    return "".join(out).encode("utf-8", "ignore")


def _pdf_views(b: bytes) -> tuple[list[bytes], list[str]]:
    """Every byte view of a PDF worth searching, and the reasons (if any) why part of it
    could not be read: the file as stored, each decoded stream, each stream's joined
    string operands, and the glyph-coded text read through each ToUnicode map."""
    views, decoded, unread = [b], [], 0
    for data, is_image in _pdf_streams(b):
        if data is None:
            unread += 0 if is_image else 1
            continue
        decoded.append(data)
        views.append(data)
        joined = _joined_strings(data)
        if joined:
            views.append(joined)
    maps = _tounicode_maps(decoded)
    views.extend(_glyph_text(decoded, cmap) for cmap in maps)
    why = []
    if unread:
        why.append(str(unread) + " stream(s) could not be decoded, so their text was not checked")
    if not maps and any(b"/Identity-H" in v or b"/Identity-V" in v for v in views):
        why.append("sets text in an embedded font with no ToUnicode map, so its text was not checked")
    return views, why


def check_paths(files: list[str]) -> list[str]:
    problems = []
    for f in files:
        low = f.lower()
        if not (is_text(f) or low.endswith(OFFICE_EXT) or low.endswith(".pdf")):
            continue
        b = read_bytes(f)
        if b is None:
            continue
        if low.endswith(OFFICE_EXT):
            try:
                with zipfile.ZipFile(io.BytesIO(b)) as z:
                    for part in z.namelist():
                        if part.lower().endswith(INNER_TEXT_EXT):
                            for kind in _path_kinds(z.read(part), True):
                                problems.append(f + ": " + part + ": holds " + kind)
            except zipfile.BadZipFile:
                problems.append(f + ": not a readable Office file, so it cannot be checked")
        elif low.endswith(".pdf"):
            views, why = _pdf_views(b)
            kinds = []
            for blob in views:
                for kind in _path_kinds(blob, True):
                    if kind not in kinds:
                        kinds.append(kind)
            for kind in kinds:
                problems.append(f + ": holds " + kind)
            for reason in why:
                problems.append(f + ": " + reason)
        else:
            for i, line in enumerate(b.split(b"\n"), 1):
                for kind in _path_kinds(line, False):
                    problems.append(f + ":" + str(i) + ": holds " + kind)
    return problems


# ----------------------------------------------------------------------------- self-test
def _fake_pdf(objects: list[tuple[bytes, bytes]]) -> bytes:
    """A minimal PDF: one stream object per (dictionary entries, stored bytes) pair."""
    out = [b"%PDF-1.4\n"]
    for n, (entries, data) in enumerate(objects, 1):
        out.append(str(n).encode() + b" 0 obj\n<< /Length " + str(len(data)).encode() + b" " +
                   entries + b" >>\nstream\n" + data + b"\nendstream\nendobj\n")
    out.append(b"%%EOF\n")
    return b"".join(out)


def self_test() -> int:
    """The PDF reader on small built-in files. Each path is assembled from pieces at run
    time, so this script holds no line the gate itself would flag."""
    sep = b"\\\\"  # a backslash as a PDF string stores it: escaped

    def home(account: bytes) -> bytes:
        return b"C:" + sep + b"Users" + sep + account + sep + b"Desktop" + sep + b"logo.png"

    def text(s: bytes) -> bytes:
        return b"BT /F1 10 Tf (" + s + b") Tj ET"

    def a85_flate(s: bytes) -> tuple[bytes, bytes]:
        return b"/Filter [ /ASCII85Decode /FlateDecode ]", base64.a85encode(zlib.compress(s)) + b"~>"

    def flate(s: bytes) -> tuple[bytes, bytes]:
        return b"/Filter /FlateDecode", zlib.compress(s)

    leak, example = home(b"notanexample"), home(b"victim")
    temp = b"AppData" + sep + b"Local" + sep + b"Temp" + sep + b"x.png"
    # Kerning splits the folder name itself, so only the joined operands show the path.
    split = b"BT [(C:" + sep + b"Us) -3 (ers" + sep + b"notanexample" + sep + b"Desktop)] TJ ET"
    # Glyph-coded text: codes 0001 and up stand for the characters of the same path.
    plain = leak.replace(sep, b"\\")
    chars = sorted(set(plain))
    code = {c: i + 1 for i, c in enumerate(chars)}
    cmap = (b"1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n" + str(len(chars)).encode() +
            b" beginbfchar\n" + b"".join(b"<%04X> <%04X>\n" % (code[c], c) for c in chars) + b"endbfchar\n")
    glyphs = b"BT /F2 10 Tf <" + b"".join(b"%04X" % code[c] for c in plain) + b"> Tj ET"
    # The two range forms of a ToUnicode map. Counting up: code 0100 + n stands for
    # character n. Listed: one range over the codes above, its targets given one by one.
    span_cmap = b"1 beginbfrange\n<0100> <01FF> <0000>\nendbfrange\n"
    span_glyphs = b"BT /F2 10 Tf <" + b"".join(b"%04X" % (0x100 + c) for c in plain) + b"> Tj ET"
    list_cmap = (b"1 beginbfrange\n<0001> <%04X> [" % len(chars) +
                 b" ".join(b"<%04X>" % c for c in chars) + b"]\nendbfrange\n")
    font = (b"/Type /Font /Subtype /Type0 /Encoding /Identity-H", b"")
    home_kind = "a home-directory path for an account that is not in EXAMPLE_ACCOUNTS"
    cases = [
        ("Flate stream, non-example account", [flate(text(leak))], [home_kind], 0),
        ("ASCII85 over Flate, non-example account", [a85_flate(text(leak))], [home_kind], 0),
        ("ASCII85 over Flate, example account", [a85_flate(text(example))], [], 0),
        ("ASCII85 over Flate, temp-directory path", [a85_flate(text(temp))], ["a temp-directory path"], 0),
        ("hex over Flate, non-example account",
         [(b"/Filter [ /ASCIIHexDecode /FlateDecode ]", binascii.hexlify(zlib.compress(text(leak))) + b">")],
         [home_kind], 0),
        ("path split across kerned operands", [a85_flate(split)], [home_kind], 0),
        ("glyph-coded text with a ToUnicode map", [flate(cmap), flate(glyphs), font], [home_kind], 0),
        ("glyph-coded text, ToUnicode range that counts up",
         [flate(span_cmap), flate(span_glyphs), font], [home_kind], 0),
        ("glyph-coded text, ToUnicode range that lists its targets",
         [flate(list_cmap), flate(glyphs), font], [home_kind], 0),
        ("glyph-coded text with no ToUnicode map", [flate(glyphs), font], [], 1),
        ("image stream is left alone", [(b"/Filter /DCTDecode", b"\xff\xd8\xff\xe0 pixels")], [], 0),
        ("image under Flate is left alone", [(b"/Subtype /Image /Filter /FlateDecode", b"not zlib: pixels")], [], 0),
        ("string with a non-octal escape", [flate(b"BT (page \\9 of 9) Tj ET")], [], 0),
        ("stream under a filter this reader does not know", [(b"/Filter /LZWDecode", b"\x80\x0b\x60\x50")], [], 1),
        ("corrupt Flate stream", [(b"/Filter /FlateDecode", b"not a zlib stream")], [], 1),
    ]
    failed = 0
    for name, objects, want_kinds, want_unread in cases:
        views, why = _pdf_views(_fake_pdf(objects))
        kinds = sorted({k for v in views for k in _path_kinds(v, True)})
        if kinds != sorted(want_kinds) or len(why) != want_unread:
            failed += 1
            print("FAIL self-test: " + name + ": found " + str(len(kinds)) + " kind(s) and " +
                  str(len(why)) + " unread reason(s), expected " + str(len(want_kinds)) + " and " +
                  str(want_unread))
    print("hygiene self-test: " + str(len(cases) - failed) + " of " + str(len(cases)) + " cases pass")
    own_cases = [
        # The two off-list fixtures split the literal right after the slash so this file never
        # matches its own gate (Python joins the adjacent string literals at run time).
        ("off-list owner/name fails", "see github.com/TeamStarWolf/" "SecretApp", 1),
        ("allowed repo .git passes", "git clone https://github.com/TeamStarWolf/ATTACK-Navi.git", 0),
        ("self repo passes", "github.com/TeamStarWolf/TeamStarWolf", 0),
        ("pages path passes", "https://teamstarwolf.github.io/TeamStarWolf/assets/brand/og.jpg", 0),
        ("bare off-list owner/name fails", "the TeamStarWolf/" "PrivateThing repo", 1),
        ("intelligence-hub passes", "TeamStarWolf/intelligence-hub", 0),
    ]
    own_failed = 0
    for nm, line, want in own_cases:
        if (1 if _own_repo_names(line) else 0) != want:
            own_failed += 1
            print("FAIL self-test (own-repos): " + nm)
    print("own-repos self-test: " + str(len(own_cases) - own_failed) + " of " + str(len(own_cases)) + " cases pass")
    return 1 if (failed or own_failed) else 0


# --------------------------------------------------------------- own-repository allow-list
# The library may reference the owner's PUBLIC repositories by owner/name, but never a
# private one. The allow-list holds only public names, which leak nothing; any other
# TeamStarWolf/<name> in a tracked text file fails the gate. Clone URLs (<name>.git, the
# .git is not part of the captured name) and the Pages path (<sub>.github.io/TeamStarWolf/
# <path>, excluded by the lookbehind) are not owner/name references. The gate names the
# file and line only, never the offending name.
ALLOWED_OWN_REPOS = {"teamstarwolf", "intelligence-hub", "attack-navi", "cybersecurity-resources"}
OWN_REPO_RE = re.compile(r"(?<!github\.io/)teamstarwolf/([A-Za-z0-9_-]+)", re.I)


def _own_repo_names(line: str) -> list[str]:
    return [m.group(1) for m in OWN_REPO_RE.finditer(line)
            if m.group(1).lower() not in ALLOWED_OWN_REPOS]


def check_own_repos(files: list[str]) -> list[str]:
    problems = []
    for f in files:
        if not is_text(f):
            continue
        b = read_bytes(f)
        if b is None:
            continue
        # Decode lossily rather than skip: a guard must not silently pass a file it could not
        # read. The encoding gate reports a non-UTF-8 file on its own.
        t = b.decode("utf-8", "replace")
        for i, line in enumerate(t.split("\n"), 1):
            if _own_repo_names(line):
                problems.append(f + ":" + str(i) + ": a TeamStarWolf/<name> reference is not on the "
                                "public allow-list (an own private repository name must not appear in "
                                "a tracked file)")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--only", choices=("junk", "encoding", "revoked", "paths", "own-repos"), action="append")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    only = set(args.only or ("junk", "encoding", "revoked", "paths", "own-repos"))
    files = tracked_files()
    failed = False
    if args.update_baseline:
        check_revoked(files, False, True)
        return 0
    for name, fn in (("junk", lambda: check_junk(files)),
                     ("encoding", lambda: check_encoding(files)),
                     ("revoked", lambda: check_revoked(files, args.report, False)),
                     ("paths", lambda: check_paths(files)),
                     ("own-repos", lambda: check_own_repos(files))):
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
