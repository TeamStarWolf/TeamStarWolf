#!/usr/bin/env python3
r"""
Rebuild the MITRE ATLAS data in data/ai/ and the two ATLAS Navigator layers in
navigator/ai/ from the pinned ATLAS release, ATLAS_RELEASE below.

Source of truth, pinned to a commit. ATLAS publishes one YAML file per release in
mitre-atlas/atlas-data (dist/v6/ATLAS-<release>.yaml, format 6.x; the older
dist/ATLAS.yaml is deprecated upstream and the STIX repository atlas-navigator-data
was retired on 2026-06-24). Both inputs below are read at ATLAS_COMMIT, the commit
the release tag points at, and each one's SHA-256 and size are verified before it is
parsed, whether it was fetched or read from a local file; a mismatch aborts the run.
The YAML must also declare FORMAT_VERSION and name ATLAS_RELEASE in its collection
block. data/MANIFEST.json records both pins under `inputs` (scripts/build_manifest.py
reads them from ATLAS_INPUTS).

    ATLAS-<release>.yaml   every tactic, technique, mitigation and case study, and the
                           relationships between them
    CHANGELOG.md           the release notes; the only upstream record of which retired
                           technique ID moved to which new one ("Previously ... (AML.Txxxx)"
                           and "moved from ... (AML.Txxxx)" under a technique entry)

Offline / CI override, per input: an option or an environment variable.
    --yaml FILE        or ATLAS_YAML_PATH
    --changelog FILE   or ATLAS_CHANGELOG_PATH
A local file must be byte-identical to its pin. An input with no override is fetched
from its commit-pinned raw.githubusercontent.com URL (about 1.2 MB for both).

Parsing uses only the standard library: _Parser reads the block-style YAML subset that
the release file is written in and raises on anything outside it (anchors, tags, block
scalars, flow collections other than [] and {}, comments, unquoted dates), so a format
change upstream fails here instead of producing wrong rows. Its output was compared
with PyYAML 6.0.2 safe_load on ATLAS-2026.10.yaml and ATLAS-2026.09.yaml: identical.

Generated (each file sorted as shown; every field derived on every run):
    data/ai/atlas_tactics.jsonl       one row per tactic, in matrix order (the
                                      `sequences` relationships): tactic_id, shortname
                                      (the name, lower-case, words joined by "-"), name,
                                      technique_count (techniques and sub-techniques
                                      that list the tactic), url, description
    data/ai/atlas_techniques.jsonl    one row per technique and sub-technique, by id:
                                      technique_id, name, is_subtechnique, parent_id
                                      (`specializes`), tactics (`achieves`, in matrix
                                      order; a sub-technique with none of its own takes
                                      its parent's), url, mitigations ([{id, name}] from
                                      `mitigates`, by id), mitigation_count, description
    data/ai/atlas_mitigations.jsonl   one row per mitigation, by id: mitigation_id, name,
                                      technique_count (the techniques that list it), url,
                                      description
    data/ai/atlas_superseded_by.jsonl one row per technique ID that an earlier release
                                      used and the pinned release no longer has, by
                                      old_id: old_name, new_id (null when the release
                                      notes name no successor), new_name (a sub-technique
                                      as "Parent: Sub"), retired_in, source. Rows come from the pinned CHANGELOG.md, plus
                                      RETIRED_WITHOUT_SUCCESSOR for IDs the notes drop
                                      without naming a successor.
    navigator/ai/atlas-matrix.json    every technique in the atlas-atlas Navigator domain
                                      (one entry per parent technique and tactic, one per
                                      sub-technique), coloured as an ATLAS technique
    navigator/ai/atlas-case-study-frequency.json
                                      the same entries scored by the number of case
                                      studies that employ the technique (direct
                                      `employs` steps, counted once per study), on a
                                      0..case-study-count gradient
    ATLAS_REFERENCE.md                three blocks between script markers: the counts in
                                      the intro (atlas-counts), the summary table
                                      (atlas-summary), and the matrix, one section per
                                      tactic, the mitigations and the retired IDs
                                      (atlas-data). Table descriptions are the first
                                      sentence of each definition. Everything outside the
                                      markers is hand-written and left alone.

Description transform (the one the committed rows already used): the upstream
Markdown text with every link [text](target) replaced by its text and every run of
whitespace, line breaks included, collapsed to one space. ATLAS 2026.10 added reference
markers ("[[sysdig]]", pointing into an object's references list), which are dropped.

Every file is written as bytes in the format it is committed in: JSON Lines with
json.dumps defaults (ASCII-escaped) and the layers with indent=2, each line keeping the
committed file's line ending (CRLF for a new file). --check compares LF-normalized
bytes, so the result does not depend on a checkout's core.autocrlf setting.

    python scripts/build_atlas.py               rewrite the files above
    python scripts/build_atlas.py --check       rebuild in memory; exit 1 if a committed
                                                file differs (writes nothing)
    python scripts/build_atlas.py --self-check  offline: exit 1 unless every committed
                                                row and layer re-serializes to its exact
                                                committed bytes, so --check compares
                                                content and never formatting
    python scripts/build_atlas.py --self-test   offline: planted cases for the YAML
                                                reader, the description transform and
                                                the release-notes reader

CI runs --self-test, --self-check and --check in .github/workflows/validate-data.yml,
fetching the pinned inputs for --check.

Re-pinning to a new ATLAS release is a deliberate edit: set ATLAS_RELEASE, ATLAS_COMMIT
(the commit the release tag points at) and each input's SHA-256 and size in
ATLAS_INPUTS (a mismatch error prints the actual values), check FORMAT_VERSION and
RETIRED_WITHOUT_SUCCESSOR against the release notes, then regenerate and run, in order,
generate_mitre_pages.py --only all, build_explore.py, build_manifest.py and
build_stats.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_AI = ROOT / "data" / "ai"
NAV_AI = ROOT / "navigator" / "ai"

ATLAS_RELEASE = "2026.10"
FORMAT_VERSION = "6.1.0"
ATLAS_REPO = "mitre-atlas/atlas-data"
ATLAS_COMMIT = "f56c1468731d6428e5bf875263b4643b46d67437"  # tag v2026.10 (also v6.1.0)
_RAW = "https://raw.githubusercontent.com/" + ATLAS_REPO + "/" + ATLAS_COMMIT + "/"
ATLAS_INPUTS = {
    "yaml": {
        "label": "ATLAS " + ATLAS_RELEASE + " data",
        "path": "dist/v6/ATLAS-" + ATLAS_RELEASE + ".yaml",
        "url": _RAW + "dist/v6/ATLAS-" + ATLAS_RELEASE + ".yaml",
        "bytes": 1154660,
        "sha256": "ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d",
        "env": "ATLAS_YAML_PATH",
    },
    "changelog": {
        "label": "ATLAS " + ATLAS_RELEASE + " release notes",
        "path": "CHANGELOG.md",
        "url": _RAW + "CHANGELOG.md",
        "bytes": 59401,
        "sha256": "892c8b00810eddf9616a8a30ab89b7576ab9db6646f8cf5878b4f10281a0f8cc",
        "env": "ATLAS_CHANGELOG_PATH",
    },
}

# Technique IDs that a release dropped without the release notes naming a successor.
# id -> (name in the last release that had it, release that dropped it). Checked
# against the notes on every re-pin; an entry the notes do map is an error.
RETIRED_WITHOUT_SUCCESSOR = {
    "AML.T0024.002": ("Exfiltration via AI Inference API: Extract AI Model", "2026.10"),
}

SITE = "https://atlas.mitre.org/"
FETCH_ATTEMPTS = 3
EOL = "\r\n"
LAYER_COLOR = "#C8E6C9"
LAYER_VERSIONS = {"layer": "4.3", "navigator": "4.6.4"}


def _log(msg: str) -> None:
    print("[build_atlas] " + msg, file=sys.stderr)


class YamlSubsetError(ValueError):
    pass


_KEY = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9_.\-]*):(?: (.*))?$")
_INT = re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")


class _Parser:
    """A reader for the block-style YAML subset that PyYAML's safe_dump emits, which is
    the subset the ATLAS distribution file uses: block mappings with plain keys, block
    sequences (indented or not), plain / single-quoted / double-quoted scalars that may
    span lines, and the empty flow collections [] and {}. Anything else (anchors, tags,
    block scalars, other flow collections, comments, unquoted dates) raises
    YamlSubsetError, so an upstream format change fails loudly instead of parsing wrong."""

    def __init__(self, text: str):
        if "\t" in text:
            raise YamlSubsetError("tab characters are outside the supported subset")
        self.lines = text.replace("\r\n", "\n").split("\n")
        self.i = 0

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _indent(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    def _peek(self):
        """(index, indent) of the next non-blank line, or (None, -1) at the end."""
        j = self.i
        while j < len(self.lines) and not self.lines[j].strip():
            j += 1
        if j >= len(self.lines):
            return None, -1
        return j, self._indent(self.lines[j])

    def _err(self, msg: str, j=None):
        j = self.i if j is None else j
        raise YamlSubsetError(f"line {j + 1}: {msg}")

    @staticmethod
    def _is_seq(content: str) -> bool:
        return content == "-" or content.startswith("- ")

    # -- structure ------------------------------------------------------------
    def parse(self):
        j, n = self._peek()
        if j is None:
            return None
        node = self._node(n)
        j, _ = self._peek()
        if j is not None:
            self._err("unexpected content after the document", j)
        return node

    def _node(self, n: int):
        j, _ = self._peek()
        content = self.lines[j][n:]
        if self._is_seq(content):
            return self._sequence(n)
        return self._mapping(n)

    def _mapping(self, n: int) -> dict:
        out: dict = {}
        while True:
            j, ind = self._peek()
            if j is None or ind < n:
                return out
            if ind > n:
                self._err("unexpected indentation", j)
            content = self.lines[j][n:]
            if self._is_seq(content):
                return out  # an indentless sequence belongs to the parent key
            m = _KEY.match(content)
            if not m:
                self._err("expected a 'key: value' line", j)
            key, rest = m.group(1), m.group(2)
            if key in out:
                self._err(f"duplicate key {key!r}", j)
            self.i = j + 1
            if rest is None or rest == "":
                k, kind = self._peek()
                if k is not None and kind > n:
                    out[key] = self._node(kind)
                elif k is not None and kind == n and self._is_seq(self.lines[k][n:]):
                    out[key] = self._sequence(n)
                else:
                    out[key] = None
            else:
                out[key] = self._scalar(rest, n, j)

    def _sequence(self, n: int) -> list:
        out: list = []
        while True:
            j, ind = self._peek()
            if j is None or ind != n or not self._is_seq(self.lines[j][n:]):
                if j is not None and ind > n:
                    self._err("unexpected indentation", j)
                return out
            content = self.lines[j][n + 2:] if len(self.lines[j]) > n + 1 else ""
            if content == "":
                self.i = j + 1
                k, kind = self._peek()
                out.append(self._node(kind) if k is not None and kind > n else None)
            elif _KEY.match(content):
                # "- key: value": the item is a mapping that starts on this line at n + 2
                self.lines[j] = " " * (n + 2) + content
                self.i = j
                out.append(self._mapping(n + 2))
            else:
                self.i = j + 1
                out.append(self._scalar(content, n, j))

    # -- scalars --------------------------------------------------------------
    def _scalar(self, first: str, parent: int, j: int):
        """`first` is the text after "key: " or "- " on line j; continuation lines must be
        indented deeper than `parent`. Sets self.i past the scalar."""
        if first.startswith("'"):
            return self._quoted(first, j, "'")
        if first.startswith('"'):
            return self._quoted(first, j, '"')
        if first == "[]":
            return []
        if first == "{}":
            return {}
        if first[0] in "[{&*!|>%@`#" or first == "-" or first.startswith("- "):
            self._err(f"unsupported construct {first[:10]!r}", j)
        parts = [first.strip()]
        k = j + 1
        while k < len(self.lines):
            line = self.lines[k]
            if line.strip() and self._indent(line) <= parent:
                break
            parts.append(line.strip())
            k += 1
        while len(parts) > 1 and parts[-1] == "":
            parts.pop()
        self.i = j + 1 + (len(parts) - 1)
        for p in parts:
            if p.startswith("#") or " #" in p or ": " in p or p.endswith(":"):
                self._err("plain scalar outside the supported subset", j)
        text = self._fold(parts)
        if len(parts) == 1:
            return self._resolve(text, j)
        return text

    def _resolve(self, text: str, j: int):
        if text in ("null", "Null", "NULL", "~"):
            return None
        if text in ("true", "True", "TRUE"):
            return True
        if text in ("false", "False", "FALSE"):
            return False
        if text.lower() in ("yes", "no", "on", "off", "y", "n") or _DATE.match(text):
            self._err(f"ambiguous plain scalar {text!r}", j)
        if _INT.match(text):
            return int(text)
        return text

    @staticmethod
    def _fold(parts: list) -> str:
        """YAML line folding for flow scalars: a single line break between two text lines
        becomes a space; each empty line in a run becomes one newline."""
        out = parts[0]
        empties = 0
        for p in parts[1:]:
            if p == "":
                empties += 1
                continue
            out += ("\n" * empties) if empties else " "
            out += p
            empties = 0
        return out

    def _quoted(self, first: str, j: int, q: str) -> str:
        # Gather raw lines until the closing quote, then decode.
        raw_lines = [first[1:]]
        k = j
        while True:
            body = "\n".join(raw_lines)
            end = self._find_close(body, q)
            if end is not None:
                break
            k += 1
            if k >= len(self.lines):
                self._err("unterminated quoted scalar", j)
            raw_lines.append(self.lines[k])
        tail = body[end + 1:]
        if tail.strip():
            self._err("text after a closing quote", k)
        self.i = k + 1
        body = body[:end]
        return self._decode_single(body) if q == "'" else self._decode_double(body, j)

    @staticmethod
    def _find_close(body: str, q: str):
        i = 0
        while i < len(body):
            c = body[i]
            if q == "'" and c == "'":
                if i + 1 < len(body) and body[i + 1] == "'":
                    i += 2
                    continue
                return i
            if q == '"':
                if c == "\\":
                    i += 2
                    continue
                if c == '"':
                    return i
            i += 1
        return None

    def _decode_single(self, body: str) -> str:
        lines = body.split("\n")
        parts = [lines[0].rstrip(" ")] + [l.strip(" ") for l in lines[1:-1]]
        if len(lines) > 1:
            parts.append(lines[-1].lstrip(" "))
        return self._fold(parts).replace("''", "'")

    _ESC = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v",
            "f": "\f", "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\",
            "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029"}
    _HEX = {"x": 2, "u": 4, "U": 8}

    def _decode_double(self, body: str, j: int) -> str:
        out: list = []
        keep = 0  # out[:keep] may not lose trailing spaces (escaped content)
        i, n = 0, len(body)
        while i < n:
            c = body[i]
            if c == "\\":
                e = body[i + 1] if i + 1 < n else ""
                if e == "\n":
                    i += 2
                    while i < n and body[i] == " ":
                        i += 1
                    keep = len(out)
                    continue
                if e in self._ESC:
                    out.append(self._ESC[e])
                    i += 2
                elif e in self._HEX:
                    w = self._HEX[e]
                    hx = body[i + 2:i + 2 + w]
                    if len(hx) != w or not re.fullmatch(r"[0-9A-Fa-f]+", hx):
                        self._err("bad escape in double-quoted scalar", j)
                    out.append(chr(int(hx, 16)))
                    i += 2 + w
                else:
                    self._err(f"unknown escape \\{e}", j)
                keep = len(out)
                continue
            if c == "\n":
                while len(out) > keep and out[-1] == " ":
                    out.pop()
                empties = 0
                i += 1
                while True:
                    s = i
                    while i < n and body[i] == " ":
                        i += 1
                    if i < n and body[i] == "\n":
                        empties += 1
                        i += 1
                        continue
                    break
                out.append("\n" * empties if empties else " ")
                keep = len(out)
                continue
            out.append(c)
            i += 1
        return "".join(out)


def load_yaml(text: str):
    """Parse the YAML subset described on _Parser."""
    return _Parser(text).parse()


# --------------------------------------------------------------------------- #
# Pinned inputs
# --------------------------------------------------------------------------- #
def read_pinned(key: str, override: str | None) -> bytes:
    """The bytes of one pinned input: an explicit path/env override, else the
    commit-pinned URL. Either way they must match the pin's SHA-256 and size."""
    pin = ATLAS_INPUTS[key]
    src = override or os.environ.get(pin["env"])
    if src:
        _log("reading " + pin["label"] + " from " + src)
        with open(src, "rb") as f:
            raw = f.read()
    else:
        src = pin["url"]
        _log("fetching " + pin["label"] + " from " + src)
        req = urllib.request.Request(src, headers={"User-Agent": "teamstarwolf-library/build_atlas"})
        for attempt in range(1, FETCH_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (fixed URL, hash-checked)
                    raw = resp.read()
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt == FETCH_ATTEMPTS:
                    raise
                _log(f"fetch attempt {attempt} failed ({exc}); retrying")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pin["sha256"] or len(raw) != pin["bytes"]:
        sys.exit(
            f"[build_atlas] INTEGRITY FAILURE ({pin['label']}): {src}\n"
            f"  expected sha256 {pin['sha256']} ({pin['bytes']:,} bytes, {ATLAS_REPO}@{ATLAS_COMMIT[:12]})\n"
            f"  actual   sha256 {digest} ({len(raw):,} bytes)\n"
            "  Nothing was written. Use the pinned file, or re-pin deliberately "
            "(ATLAS_RELEASE, ATLAS_COMMIT and ATLAS_INPUTS; see the module docstring).")
    return raw


# --------------------------------------------------------------------------- #
# Transform
# --------------------------------------------------------------------------- #
_MD_LINK = re.compile(r"\[([^\[\]]+)\]\(\s*[^()\s]+\s*\)")
_REF_MARK = re.compile(r"\s*\[\[[^\[\]]+\]\]")


def flatten(text) -> str:
    """The committed description transform: Markdown links to their text (ATLAS sometimes
    writes "[text]( /target)"), ATLAS reference markers ("[[sysdig]]", which point into the
    object's references list) removed, and whitespace runs (line breaks included) to one
    space."""
    text = _MD_LINK.sub(r"\1", _REF_MARK.sub("", text or ""))
    return re.sub(r"\s+", " ", text).strip()


def shortname(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _rels(doc: dict, rtype: str) -> list[dict]:
    out = []
    for groups in (doc.get("relationships") or {}).values():
        out.extend(groups.get(rtype) or [])
    return out


def build(doc: dict) -> dict:
    """{relative path: list of rows (jsonl) or dict (layer)} for every generated file."""
    if str(doc.get("format-version")) != FORMAT_VERSION:
        sys.exit(f"[build_atlas] the YAML is format {doc.get('format-version')!r}, expected "
                 f"{FORMAT_VERSION!r}. Nothing was written.")
    if str((doc.get("collection") or {}).get("version")) != ATLAS_RELEASE:
        sys.exit(f"[build_atlas] the YAML is ATLAS {(doc.get('collection') or {}).get('version')!r}, "
                 f"but ATLAS_RELEASE is {ATLAS_RELEASE!r}. Nothing was written.")
    tactics, techniques, mitigations = doc["tactics"], doc["techniques"], doc["mitigations"]
    for kind, objs in (("tactic", tactics), ("technique", techniques), ("mitigation", mitigations)):
        for oid, obj in objs.items():
            if obj.get("id") != oid or obj.get("object-type") != kind:
                sys.exit(f"[build_atlas] {kind} entry {oid} has id {obj.get('id')!r} and type "
                         f"{obj.get('object-type')!r}. Nothing was written.")

    order = [r["target"] for r in sorted(
        (r for r in _rels(doc, "sequences") if r["source"] == "ATLAS-matrix"), key=lambda r: r["position"])]
    if sorted(order) != sorted(tactics):
        sys.exit("[build_atlas] the matrix sequence does not list every tactic exactly once.")
    rank = {t: i for i, t in enumerate(order)}
    short = {t: shortname(tactics[t]["name"]) for t in order}

    parent: dict[str, str] = {}
    for r in _rels(doc, "specializes"):
        if r["source"] in parent:
            sys.exit(f"[build_atlas] {r['source']} specializes two techniques.")
        parent[r["source"]] = r["target"]
    achieves = defaultdict(set)
    for r in _rels(doc, "achieves"):
        achieves[r["source"]].add(r["target"])
    mitigates = defaultdict(set)
    for r in _rels(doc, "mitigates"):
        mitigates[r["target"]].add(r["source"])
    for tid, mids in mitigates.items():
        unknown = sorted(set(mids) - set(mitigations)) + ([tid] if tid not in techniques else [])
        if unknown:
            sys.exit(f"[build_atlas] mitigates relationship names unknown ids {unknown}.")

    tech_rows = []
    for tid in sorted(techniques):
        t = techniques[tid]
        par = parent.get(tid)
        if (par is None) != ("." not in tid[len("AML.T"):]):
            sys.exit(f"[build_atlas] {tid}: sub-technique id and specializes relationship disagree.")
        tac = achieves.get(tid) or (achieves.get(par) if par else None) or set()
        if not tac:
            sys.exit(f"[build_atlas] {tid} achieves no tactic.")
        mits = sorted(mitigates.get(tid, ()))
        tech_rows.append({
            "technique_id": tid,
            "name": t["name"],
            "is_subtechnique": par is not None,
            "parent_id": par,
            "tactics": [short[x] for x in sorted(tac, key=rank.__getitem__)],
            "url": SITE + "techniques/" + tid,
            "mitigations": [{"id": m, "name": mitigations[m]["name"]} for m in mits],
            "mitigation_count": len(mits),
            "description": flatten(t.get("description")),
        })
    per_tactic = Counter(s for r in tech_rows for s in r["tactics"])
    per_mit = Counter(m["id"] for r in tech_rows for m in r["mitigations"])
    tactic_rows = [{
        "tactic_id": t,
        "shortname": short[t],
        "name": tactics[t]["name"],
        "technique_count": per_tactic[short[t]],
        "url": SITE + "tactics/" + t,
        "description": flatten(tactics[t].get("description")),
    } for t in order]
    mit_rows = [{
        "mitigation_id": m,
        "name": mitigations[m]["name"],
        "technique_count": per_mit[m],
        "url": SITE + "mitigations/" + m,
        "description": flatten(mitigations[m].get("description")),
    } for m in sorted(mitigations)]

    studies = doc.get("case-studies") or {}
    employed = Counter()
    for cs, groups in (doc.get("relationships") or {}).items():
        if cs in studies:
            for tid in {r["target"] for r in groups.get("employs") or []}:
                employed[tid] += 1
    return {
        "data/ai/atlas_tactics.jsonl": tactic_rows,
        "data/ai/atlas_techniques.jsonl": tech_rows,
        "data/ai/atlas_mitigations.jsonl": mit_rows,
        "navigator/ai/atlas-matrix.json": layer(tech_rows, "matrix", employed, len(studies)),
        "navigator/ai/atlas-case-study-frequency.json": layer(tech_rows, "frequency", employed, len(studies)),
        "_meta": {"released": str((doc.get("collection") or {}).get("modified-date") or ""),
                  "case_studies": len(studies)},
    }


def layer(tech_rows: list[dict], kind: str, employed: Counter, n_studies: int) -> dict:
    entries = []
    for r in tech_rows:
        value = {"color": LAYER_COLOR} if kind == "matrix" else {"score": employed[r["technique_id"]]}
        if r["is_subtechnique"]:
            entries.append({"techniqueID": r["technique_id"], **value})
        else:
            for tac in r["tactics"]:
                entries.append({"techniqueID": r["technique_id"], "showSubtechniques": True,
                                "tactic": tac, **value})
    out = {
        "versions": dict(LAYER_VERSIONS),
        "domain": "atlas-atlas",
        "metadata": [
            {"name": "atlas_data_version", "value": ATLAS_RELEASE},
            {"name": "source", "value": "MITRE ATLAS (atlas.mitre.org)"},
            {"name": "upstream", "value": "https://github.com/" + ATLAS_REPO + "/blob/" + ATLAS_COMMIT
             + "/" + ATLAS_INPUTS["yaml"]["path"]},
            {"name": "generated_by", "value": "scripts/build_atlas.py"},
        ],
    }
    if kind == "matrix":
        out.update({
            "name": "ATLAS Matrix",
            "description": "Adversarial Threat Landscape for Artificial-Intelligence Systems, see atlas.mitre.org",
            "techniques": entries,
            "legendItems": [{"label": "ATLAS technique", "color": LAYER_COLOR}],
        })
    else:
        out.update({
            "name": "ATLAS Case Study Frequency",
            "description": f"Heatmap of technique occurrences in {n_studies} ATLAS case studies",
            "techniques": entries,
            "gradient": {"colors": ["#FFFFFF", "#F44336"], "minValue": 0, "maxValue": n_studies},
        })
    return out


# --------------------------------------------------------------------------- #
# Retired technique IDs
# --------------------------------------------------------------------------- #
_RELEASE_HDR = re.compile(r"^## \[([^\]]+)\]")
_TECH_BULLET = re.compile(r"^(\s*)- \[[^\]]+\]\(/techniques/(AML\.T\d{4}(?:\.\d{3})?)\)\s*$")
_MOVED = re.compile(r"^\s*- (?:Previously|moved from) \"([^\"]+)\" \((AML\.T\d{4}(?:\.\d{3})?)\)\s*$")


def superseded(changelog: str, tech_rows: list[dict]) -> list[dict]:
    names = {r["technique_id"]: r["name"] for r in tech_rows}
    live = {r["technique_id"]: (names[r["parent_id"]] + ": " + r["name"] if r["parent_id"] else r["name"])
            for r in tech_rows}  # sub-techniques by "Parent: Sub", as the release notes name them
    moves: dict[str, tuple[str, str, str]] = {}  # old id -> (old name, new id, release)
    release, current = None, None
    for line in changelog.replace("\r\n", "\n").split("\n"):
        m = _RELEASE_HDR.match(line)
        if m:
            release, current = m.group(1), None
            continue
        m = _TECH_BULLET.match(line)
        if m:
            current = m.group(2)
            continue
        m = _MOVED.match(line)
        if m and current and m.group(2) != current:
            old = m.group(2)
            if old in moves and moves[old][1] != current:
                sys.exit(f"[build_atlas] the release notes move {old} to both {moves[old][1]} and {current}.")
            moves.setdefault(old, (m.group(1), current, release))
    rows = []
    for old, (old_name, new, rel) in moves.items():
        if old in live:
            continue  # the ID is still current (only its content moved)
        seen = {old}
        while new not in live and new in moves and new not in seen:
            seen.add(new)
            new = moves[new][1]
        if new not in live:
            sys.exit(f"[build_atlas] {old} moves to {new}, which ATLAS {ATLAS_RELEASE} does not have.")
        rows.append({"old_id": old, "old_name": old_name, "new_id": new, "new_name": live[new],
                     "retired_in": rel, "source": "ATLAS release notes (CHANGELOG.md), " + rel})
    for old, (old_name, rel) in RETIRED_WITHOUT_SUCCESSOR.items():
        if old in live:
            sys.exit(f"[build_atlas] RETIRED_WITHOUT_SUCCESSOR lists {old}, which is still current.")
        if old in moves:
            sys.exit(f"[build_atlas] the release notes now name a successor for {old}: remove it "
                     "from RETIRED_WITHOUT_SUCCESSOR.")
        rows.append({"old_id": old, "old_name": old_name, "new_id": None, "new_name": None,
                     "retired_in": rel, "source": "ATLAS " + rel + " (absent from the release; "
                     "the release notes name no successor)"})
    return sorted(rows, key=lambda r: r["old_id"])


# --------------------------------------------------------------------------- #
# Serialisation
# --------------------------------------------------------------------------- #
def serialise(rel: str, content, eol: str = EOL) -> bytes:
    if rel.endswith(".jsonl"):
        text = "".join(json.dumps(row) + "\n" for row in content)
    else:
        text = json.dumps(content, indent=2) + "\n"
    return text.replace("\n", eol).encode("utf-8")


def _lf(raw: bytes) -> bytes:
    return raw.replace(b"\r\n", b"\n")


def committed(rel: str) -> bytes | None:
    path = ROOT / rel
    return path.read_bytes() if path.exists() else None


def self_check() -> int:
    """Every committed output re-serializes to its own bytes (offline), so a --check
    difference is always a content difference, never formatting."""
    bad = 0
    for rel in OUTPUTS:
        raw = committed(rel)
        if raw is None:
            print("MISSING " + rel)
            bad += 1
            continue
        eol = "\r\n" if b"\r\n" in raw else "\n"
        text = _lf(raw).decode("utf-8")
        content = ([json.loads(line) for line in text.split("\n") if line.strip()]
                   if rel.endswith(".jsonl") else json.loads(text))
        if serialise(rel, content, eol) != raw:
            print("NOT A FIXED POINT " + rel)
            bad += 1
        else:
            n = len(content) if isinstance(content, list) else len(content["techniques"])
            unit = "rows" if isinstance(content, list) else "layer entries"
            print(f"OK    {rel} ({n} {unit} re-serialize byte-identical)")
    return bad


# --------------------------------------------------------------------------- #
# ATLAS_REFERENCE.md: the data-derived blocks
# --------------------------------------------------------------------------- #
REFERENCE = "ATLAS_REFERENCE.md"
BLOB = "https://github.com/TeamStarWolf/TeamStarWolf/blob/main/"
# Heading ids that older links use for a tactic section (the tactic's earlier names).
LEGACY_ANCHORS = {"AML.TA0001": ["ai-attack-staging"]}
_ABBREV = re.compile(r"(?:\b(?:e\.g|i\.e|etc|vs|al|approx|incl)|\b[A-Z])\.$")


def first_sentence(text: str) -> str:
    """The first complete sentence of a flattened description (never clipped)."""
    for m in re.finditer(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])", text):
        head = text[:m.start()]
        if not _ABBREV.search(head):
            return head
    return text


def cell(text: str) -> str:
    """Text safe inside a Markdown table cell on GitHub and docsify."""
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|"))


# The atlas-data block is fenced with "begin"/"end" comments, not a "name:start" pair: the
# site's reading-time count (build_site_nav.words) and the voice lint treat a name:start block
# as navigation and skip it, and these tables are the page's reading content. Its upstream
# text is still exempt from the voice lint, which recognises data/ai/ descriptions.
CONTENT_BLOCKS = ("atlas-data",)


def _block(name: str, note: str) -> tuple[str, str]:
    if name in CONTENT_BLOCKS:
        return ("<!-- " + name + " begin (written by scripts/build_atlas.py" + note + "; do not edit) -->",
                "<!-- " + name + " end -->")
    return ("<!-- " + name + ":start (written by scripts/build_atlas.py" + note + "; do not edit) -->",
            "<!-- " + name + ":end -->")


def reference_blocks(files: dict) -> dict[str, str]:
    """{block name: content} for the three blocks build_atlas.py owns in REFERENCE."""
    tactics = files["data/ai/atlas_tactics.jsonl"]
    techs = files["data/ai/atlas_techniques.jsonl"]
    mits = files["data/ai/atlas_mitigations.jsonl"]
    retired = files["data/ai/atlas_superseded_by.jsonl"]
    meta = files["_meta"]
    by_id = {r["technique_id"]: r for r in techs}
    subs = defaultdict(list)
    for r in techs:
        if r["parent_id"]:
            subs[r["parent_id"]].append(r)
    n_sub = sum(1 for r in techs if r["is_subtechnique"])
    src = "https://github.com/" + ATLAS_REPO + "/blob/" + ATLAS_COMMIT + "/" + ATLAS_INPUTS["yaml"]["path"]

    counts = (f"{len(techs)} techniques ({len(techs) - n_sub} parent + {n_sub} sub-techniques), "
              f"{len(mits)} mitigations, and {len(tactics)} tactics")

    summary = "\n".join([
        "| | |",
        "|---|---|",
        f"| Release | [ATLAS {ATLAS_RELEASE}]({src}) (data format {FORMAT_VERSION}), dated {meta['released']} |",
        f"| Tactics | {len(tactics)} |",
        f"| Techniques | {len(techs)} ({len(techs) - n_sub} parent, {n_sub} sub-techniques) |",
        f"| Mitigations | {len(mits)} |",
        f"| Case studies in the release | {meta['case_studies']} |",
        f"| Retired technique IDs | {len(retired)}, listed with their successors under "
        "[Retired technique IDs](#retired-technique-ids) |",
        "| Navigator layers | [ATLAS matrix](" + BLOB + "navigator/ai/atlas-matrix.json), "
        "[case-study frequency](" + BLOB + "navigator/ai/atlas-case-study-frequency.json) |",
        "| Datasets | [techniques](" + BLOB + "data/ai/atlas_techniques.jsonl), [tactics](" + BLOB
        + "data/ai/atlas_tactics.jsonl), [mitigations](" + BLOB + "data/ai/atlas_mitigations.jsonl), "
        "[retired IDs](" + BLOB + "data/ai/atlas_superseded_by.jsonl) |",
    ])

    out = ["## The ATLAS matrix", "",
           f"The {len(tactics)} tactics in the order ATLAS {ATLAS_RELEASE} lays them out, with the number "
           "of techniques and sub-techniques filed under each (a technique can sit under more than one).",
           "", "| # | Tactic | Techniques | Description |", "|---|---|--:|---|"]
    for i, t in enumerate(tactics, 1):
        out.append(f"| {i} | [{cell(t['name'])}]({t['url']}) | {t['technique_count']} | "
                   f"{cell(first_sentence(t['description']))} |")
    out += ["", "---"]

    def row(r: dict, sub: bool) -> str:
        lead = "&nbsp;&nbsp;↳ " if sub else ""
        return (f"| {lead}[{r['technique_id']} {cell(r['name'])}]({r['url']}) | {r['mitigation_count']} | "
                f"{cell(first_sentence(r['description']))} |")

    for t in tactics:
        sn = t["shortname"]
        out += ["", "## " + t["name"], f'<a id="{sn}"></a>']
        out += [f'<a id="{a}"></a>' for a in LEGACY_ANCHORS.get(t["tactic_id"], [])]
        out += ["", f"[`{t['tactic_id']}`]({t['url']}), {t['technique_count']} techniques", "",
                cell(t["description"]), "", "| Technique | Mitigations | Description |", "|---|--:|---|"]
        for r in techs:
            if sn not in r["tactics"]:
                continue
            if r["is_subtechnique"] and sn in by_id[r["parent_id"]]["tactics"]:
                continue  # listed under its parent
            out.append(row(r, r["is_subtechnique"]))
            out += [row(s, True) for s in subs.get(r["technique_id"], []) if sn in s["tactics"]]

    ranked = sorted(mits, key=lambda m: (-m["technique_count"], m["mitigation_id"]))
    out += ["", "---", "", "## ATLAS mitigations", "",
            f"ATLAS {ATLAS_RELEASE} lists {len(mits)} mitigations, ordered here by the number of techniques "
            "each one addresses, then by ID.", "",
            "| Mitigation | Techniques | Description |", "|---|--:|---|"]
    out += [f"| [{m['mitigation_id']} {cell(m['name'])}]({m['url']}) | {m['technique_count']} | "
            f"{cell(first_sentence(m['description']))} |" for m in ranked]
    out += ["", "## Retired technique IDs", "",
            "Technique IDs that earlier ATLAS releases used and " + ATLAS_RELEASE + " no longer has. The "
            "successor is the one the ATLAS release notes name; where they name none, the ID was dropped "
            "and no replacement should be inferred.", "",
            "| Retired ID | Name in its last release | Successor | Retired in |", "|---|---|---|---|"]
    for r in retired:
        succ = (f"[{r['new_id']} {cell(r['new_name'])}]({by_id[r['new_id']]['url']})"
                if r["new_id"] else "None named")
        out.append(f"| {r['old_id']} | {cell(r['old_name'])} | {succ} | ATLAS {r['retired_in']} |")
    return {"atlas-counts": counts, "atlas-summary": summary, "atlas-data": "\n".join(out)}


def render_reference(text: str, files: dict) -> str:
    """REFERENCE with each owned block replaced. atlas-counts is inline (inside the intro
    sentence); the others are block-level and sit on lines of their own."""
    blocks = reference_blocks(files)
    for name, content in blocks.items():
        start, end = _block(name, "" if name == "atlas-counts" else " from data/ai/")
        pat = re.compile(re.escape(start) + r".*?" + re.escape(end), re.S)
        found = pat.findall(text)
        if len(found) != 1:
            sys.exit(f"[build_atlas] {REFERENCE} must hold exactly one {name} block "
                     f"({start} ... {end}); found {len(found)}.")
        body = start + content + end if name == "atlas-counts" else start + "\n\n" + content + "\n\n" + end
        text = pat.sub(lambda _m: body, text)
    return text


# --------------------------------------------------------------------------- #
# Planted cases (--self-test)
# --------------------------------------------------------------------------- #
_PLANTED_YAML = """\
top:
  plain: a plain value
  folded: 'first line
    continues here


    after two blank lines it''s a new paragraph'
  dq: "tab\\there \\"quoted\\" and a\\
    \\ joined line\\u00e9"
  multi: plain words that
    wrap onto a second line
  number: 9
  version: 6.1.0
  empty: []
  nothing: {}
  none:
  seq:
  - one
  - key: value
    other: 'x'
"""
_PLANTED_EXPECT = {"top": {
    "plain": "a plain value",
    "folded": "first line continues here\n\nafter two blank lines it's a new paragraph",
    "dq": 'tab\there "quoted" and a joined line\u00e9',
    "multi": "plain words that wrap onto a second line",
    "number": 9, "version": "6.1.0", "empty": [], "nothing": {}, "none": None,
    "seq": ["one", {"key": "value", "other": "x"}],
}}
_PLANTED_REJECT = ["a: &anchor x\n", "a: !tag x\n", "a: |\n  block\n", "a: [1, 2]\n", "a: 2026-10-28\n",
                   "a: yes\n", "a:\n- - x\n", "a:\tx\n", "a: x # comment\n", "a: 1\na: 2\n", "a: 'open\n"]
_PLANTED_NOTES = """\
## [2026.10]() (2026-10-28)
- Added new techniques
  - [New Child](/techniques/AML.T0900.000)
    - moved from "Old: Child" (AML.T0800.001)
  - [Kept](/techniques/AML.T0901)
    - Previously "Old name"
## [2026.07]() (2026-07-31)
  - [Middle](/techniques/AML.T0902)
    - Previously "Oldest" (AML.T0700)
  - [Gone again](/techniques/AML.T0903)
    - Previously "Chain start" (AML.T0600)
## [2026.05]() (2026-05-27)
  - [Chain middle](/techniques/AML.T0903)
"""


def self_test() -> int:
    failures = []
    got = load_yaml(_PLANTED_YAML)
    if got != _PLANTED_EXPECT:
        failures.append(f"YAML reader: got {got!r}")
    for bad in _PLANTED_REJECT:
        try:
            load_yaml(bad)
            failures.append(f"YAML reader accepted {bad!r}")
        except YamlSubsetError:
            pass
    text = ("See [Replicate AI Model Behavior](/techniques/AML.T0005).[[ref]]\n\nNext   paragraph, "
            "as in [LLMjacking]( /studies/AML.CS0030) campaigns.[[a]][[b]]")
    if flatten(text) != ("See Replicate AI Model Behavior. Next paragraph, as in LLMjacking "
                         "campaigns."):
        failures.append(f"flatten: got {flatten(text)!r}")
    if first_sentence("Use e.g. rate limits. Then more.") != "Use e.g. rate limits.":
        failures.append("first_sentence split after an abbreviation")
    if cell("a | b <c>") != "a \\| b &lt;c&gt;":
        failures.append(f"cell: got {cell('a | b <c>')!r}")
    rows = [{"technique_id": "AML.T0900", "name": "New", "parent_id": None},
            {"technique_id": "AML.T0900.000", "name": "Child", "parent_id": "AML.T0900"},
            {"technique_id": "AML.T0901", "name": "Kept", "parent_id": None},
            {"technique_id": "AML.T0902", "name": "Middle", "parent_id": None}]
    saved = dict(RETIRED_WITHOUT_SUCCESSOR)
    RETIRED_WITHOUT_SUCCESSOR.clear()
    try:
        try:
            sup = superseded(_PLANTED_NOTES, rows)
            failures.append(f"release notes: a move to a missing ID was accepted ({sup!r})")
        except SystemExit:
            pass
        rows.append({"technique_id": "AML.T0903", "name": "Gone again", "parent_id": None})
        sup = superseded(_PLANTED_NOTES, rows)
        want = [("AML.T0600", "AML.T0903", "2026.07"), ("AML.T0700", "AML.T0902", "2026.07"),
                ("AML.T0800.001", "AML.T0900.000", "2026.10")]
        if [(r["old_id"], r["new_id"], r["retired_in"]) for r in sup] != want:
            failures.append(f"release notes: got {sup!r}")
        elif sup[2]["new_name"] != "New: Child":
            failures.append(f"release notes: sub-technique successor named {sup[2]['new_name']!r}")
    finally:
        RETIRED_WITHOUT_SUCCESSOR.update(saved)
    for f in failures:
        print("FAIL " + f)
    print(f"FAILED: {len(failures)} planted case(s)" if failures
          else "OK: every planted case passed (YAML reader, transform, release notes)")
    return 1 if failures else 0


OUTPUTS = (
    "data/ai/atlas_tactics.jsonl",
    "data/ai/atlas_techniques.jsonl",
    "data/ai/atlas_mitigations.jsonl",
    "data/ai/atlas_superseded_by.jsonl",
    "navigator/ai/atlas-matrix.json",
    "navigator/ai/atlas-case-study-frequency.json",
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].strip(),
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="Rebuild in memory and exit 1 if any committed file differs; write nothing.")
    ap.add_argument("--self-check", action="store_true",
                    help="Offline: exit 1 unless every committed output re-serializes to its own bytes.")
    ap.add_argument("--self-test", action="store_true",
                    help="Offline: run the planted cases for the YAML reader, transform and release notes.")
    ap.add_argument("--yaml", help="Local copy of the pinned ATLAS YAML (default: fetch; env ATLAS_YAML_PATH).")
    ap.add_argument("--changelog", help="Local copy of the pinned CHANGELOG.md (env ATLAS_CHANGELOG_PATH).")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.self_check:
        return 1 if self_check() else 0

    doc = load_yaml(read_pinned("yaml", args.yaml).decode("utf-8"))
    files = build(doc)
    files["data/ai/atlas_superseded_by.jsonl"] = superseded(
        read_pinned("changelog", args.changelog).decode("utf-8"), files["data/ai/atlas_techniques.jsonl"])
    stale = []
    for rel in OUTPUTS:
        content = files[rel]
        have = committed(rel)
        # Line endings follow the committed file (CRLF for a new one); the comparison is
        # on LF-normalized bytes, so a checkout's core.autocrlf setting never matters.
        eol = "\n" if have is not None and b"\r\n" not in have else EOL
        want = serialise(rel, content, eol)
        if have is not None and _lf(have) == _lf(want):
            continue
        if args.check:
            stale.append(rel)
            continue
        (ROOT / rel).write_bytes(want)
        n = len(content) if isinstance(content, list) else len(content["techniques"])
        _log(f"wrote {rel} ({n} {'rows' if isinstance(content, list) else 'entries'})")
    page = committed(REFERENCE)
    if page is None:
        sys.exit(f"[build_atlas] {REFERENCE} is missing.")
    text = _lf(page).decode("utf-8")
    new = render_reference(text, files)
    if new != text:
        if args.check:
            stale.append(REFERENCE)
        else:
            out = new.replace("\n", "\r\n") if b"\r\n" in page else new
            (ROOT / REFERENCE).write_bytes(out.encode("utf-8"))
            _log(f"wrote the ATLAS blocks in {REFERENCE}")
    counts ={k.rsplit("/", 1)[1]: len(v) for k, v in files.items() if isinstance(v, list)}
    if args.check:
        if stale:
            print("STALE (run python scripts/build_atlas.py and commit): " + ", ".join(stale))
            return 1
        print(f"OK: data/ai, navigator/ai and the {REFERENCE} blocks match ATLAS {ATLAS_RELEASE} ({ATLAS_REPO}@{ATLAS_COMMIT[:12]}): "
              + ", ".join(f"{k} {v}" for k, v in counts.items()))
        return 0
    print(f"ATLAS {ATLAS_RELEASE}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
