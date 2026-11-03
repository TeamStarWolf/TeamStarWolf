#!/usr/bin/env python3
r"""
Rebuild data/weaknesses/cwe.jsonl from the pinned CWE List release and verify
data/weaknesses/capec.jsonl against the pinned CAPEC List release.

Source of truth. Both lists publish each release as a versioned download, and each
file's SHA-256 and size are verified before it is parsed, whether it was fetched or read
from a local file; a mismatch aborts the run. data/MANIFEST.json records both pins
under `inputs` (scripts/build_manifest.py reads them from WEAKNESS_INPUTS).

    CWE List 5.0     https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip (cwec_v5.0.xml,
                     Version="5.0", Date="2026-10-28" in the catalog element)
    CAPEC List 3.9   https://capec.mitre.org/data/archive/capec_v3.9.zip (capec_v3.9.xml,
                     Version="3.9", Date="2023-01-24"); capec.mitre.org/data/index.html
                     names 3.9 as the current release on 2026-11-03

Offline / CI override, per input: an option or an environment variable.
    --cwe FILE      or CWE_ZIP_PATH
    --capec FILE    or CAPEC_ZIP_PATH
A local file must be byte-identical to its pin.

Generated, data/weaknesses/cwe.jsonl: one row per Weakness element (Deprecated ones
included, as upstream lists them), by numeric id. Every field is derived on every run:
    cwe_id                  "CWE-" + ID
    name, abstraction, status
                            the element's attributes, verbatim
    applicable_platforms    the platforms in CWE's own CSV form, each entry
                            "<KIND> NAME|CLASS:<value>:<KIND> PREVALENCE:<value>" and the
                            entries joined by "::" with "::" at both ends; the first
                            120 characters
    common_consequences     the distinct impact categories of every Consequence (each
                            Impact value up to its first colon: "DoS: Crash, Exit, or
                            Restart" counts as "DoS"), sorted
    mitigation              the Description of the first Potential_Mitigations entry,
                            whitespace collapsed; the first 200 characters ("" when none)
    related_capec           the Related_Attack_Pattern CAPEC ids as "CAPEC-<n>", sorted as
                            strings; attacked_by_capec_count is their number
    description             the Description, whitespace collapsed; the first 400 characters
The length caps are the ones the dataset has always used; read the full text upstream.

Generated, CWE_REFERENCE.md between the cwe-data begin and end comments, from those rows. Deprecated
entries are counted separately and left out of every table:
    the abstraction line    the non-deprecated rows by abstraction, then the deprecated
    Pillars                 every Pillar, by id: link, name, the first 140 characters of
                            the description
    Most-attacked           the 40 rows with the most related CAPEC patterns, most first
                            and then by id: link, name, abstraction, pattern count, the
                            first three consequences
    Weakness classes        every Class, by id: link, name, the first two consequences,
                            the first 90 characters of the mitigation ("N/A" when none)

Verified, data/weaknesses/capec.jsonl: the file is maintained by hand and by
scripts/backfill_capec_edges.py (the ATT&CK links), so it is not rewritten here. --check
fails unless its rows are exactly the Attack_Pattern elements of the pinned release
(Deprecated and Obsolete included) and each row's capec_id, name, abstraction, status,
typical_severity, likelihood, related_cwe (in upstream order) and capec_version equal
the pinned XML.

Run from the repository root:  python -I scripts/build_weaknesses.py [--check]
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pinned_inputs as pi  # noqa: E402

TOOL = "build_weaknesses"
CWE_RELEASE = "5.0"
CWE_RELEASE_DATE = "2026-10-28"
CAPEC_RELEASE = "3.9"
CAPEC_RELEASE_DATE = "2023-01-24"
WEAKNESS_INPUTS = {
    "cwe": {
        "label": "CWE List " + CWE_RELEASE + " (cwec_v5.0.xml.zip)",
        "upstream": "cwe",
        "version": CWE_RELEASE,
        "path": "cwec_v5.0.xml.zip",
        "member": "cwec_v5.0.xml",
        "url": "https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip",
        "bytes": 2119263,
        "sha256": "bcda44c9abf61ff977f50c3c6649eea5a97a7b0626b0396c2c3ec4bfb973a3dc",
        "env": "CWE_ZIP_PATH",
    },
    "capec": {
        "label": "CAPEC List " + CAPEC_RELEASE + " (capec_v3.9.zip)",
        "upstream": "capec",
        "version": CAPEC_RELEASE,
        "path": "capec_v3.9.zip",
        "member": "capec_v3.9.xml",
        "url": "https://capec.mitre.org/data/archive/capec_v3.9.zip",
        "bytes": 587404,
        "sha256": "c56527f3d64b7164fcdae73c1a7545ee6e83b1150546c07a93339b1543a3041d",
        "env": "CAPEC_ZIP_PATH",
    },
}
CWE_REL = "data/weaknesses/cwe.jsonl"
CWE_PAGE = "CWE_REFERENCE.md"
CAPEC_REL = "data/weaknesses/capec.jsonl"
CAP = {"applicable_platforms": 120, "mitigation": 200, "description": 400}


def _xml(key: str, override: str | None):
    pin = WEAKNESS_INPUTS[key]
    raw = pi.read(TOOL, pin, override)
    # The bytes are SHA-256 pinned, so the XML parsed here is a known file; the standard
    # library parser does not fetch external entities.
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        root = ET.fromstring(zf.read(pin["member"]))
    ns = root.tag.split("}")[0] + "}"
    if root.get("Version") != pin["version"]:
        sys.exit("[" + TOOL + "] " + pin["member"] + " declares Version=" + repr(root.get("Version")) +
                 ", expected " + pin["version"])
    return root, ns


def _text(el) -> str:
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


def _platforms(w, ns: str) -> str:
    ap = w.find(ns + "Applicable_Platforms")
    parts = []
    for c in (ap if ap is not None else []):
        kind = c.tag.replace(ns, "").upper().replace("_", " ")
        s = ""
        if c.get("Name"):
            s += kind + " NAME:" + c.get("Name") + ":"
        if c.get("Class"):
            s += kind + " CLASS:" + c.get("Class") + ":"
        s += kind + " PREVALENCE:" + c.get("Prevalence", "")
        parts.append(s)
    return ("::" + "::".join(parts) + "::") if parts else ""


def cwe_rows(root, ns: str) -> list[dict]:
    rows = []
    for w in root.iter(ns + "Weakness"):
        mit = w.find(ns + "Potential_Mitigations")
        first = mit.find(ns + "Mitigation") if mit is not None else None
        capec = sorted({"CAPEC-" + r.get("CAPEC_ID") for r in w.iter(ns + "Related_Attack_Pattern")})
        rows.append({
            "cwe_id": "CWE-" + w.get("ID"),
            "name": w.get("Name"),
            "abstraction": w.get("Abstraction"),
            "status": w.get("Status"),
            "applicable_platforms": _platforms(w, ns)[:CAP["applicable_platforms"]],
            "common_consequences": sorted({_text(i).split(":")[0].strip() for c in w.iter(ns + "Consequence")
                                           for i in c.findall(ns + "Impact")} - {""}),
            "mitigation": (_text(first.find(ns + "Description")) if first is not None else "")[:CAP["mitigation"]],
            "related_capec": capec,
            "attacked_by_capec_count": len(capec),
            "description": _text(w.find(ns + "Description"))[:CAP["description"]],
        })
    rows.sort(key=lambda r: int(r["cwe_id"][4:]))
    return rows


# --------------------------------------------------------------------------- #
# CWE_REFERENCE.md tables
# --------------------------------------------------------------------------- #
BLOCK = "cwe-data"
# A content block, fenced with "begin" and "end" comments rather than a "name:start" pair:
# the reading-time count (build_site_nav.words) and the voice lint skip a name:start block
# as navigation, and these tables are the page's reading content (the atlas-data
# convention of build_atlas.py).
BLOCK_RE = re.compile(r"(<!-- " + BLOCK + r" begin[^\n]*-->\n)(.*?)(<!-- " + BLOCK + r" end -->)", re.S)
ABSTRACTIONS = [("Pillar", "Pillars", "(most abstract)"), ("Class", "Classes", ""),
                ("Base", "Base", ""), ("Variant", "Variants", "(most specific)")]
MOST_ATTACKED = 40


def _cell(s: str) -> str:
    return s.replace("|", "\\|")


def _link(cwe_id: str) -> str:
    return "[" + cwe_id + "](https://cwe.mitre.org/data/definitions/" + cwe_id[4:] + ".html)"


def page_block(rows: list[dict]) -> str:
    live = [r for r in rows if r["status"] != "Deprecated"]
    n = {a: sum(1 for r in live if r["abstraction"] == a) for a in ("Pillar", "Class", "Base", "Variant", "Compound")}
    chain = " -> ".join(str(n[a]) + " " + label + ((" " + note) if note else "") for a, label, note in ABSTRACTIONS)
    out = ["### Abstraction levels", "",
           "CWE is a hierarchy: " + chain + ", plus " + str(n["Compound"]) + " Compound weaknesses. CWE " +
           CWE_RELEASE + " also keeps " + str(len(rows) - len(live)) +
           " deprecated entries, which the tables below leave out.", "",
           "## Pillars: the top-level weakness categories", "",
           "| CWE | Weakness | Description |", "|---|---|---|"]
    for r in live:
        if r["abstraction"] == "Pillar":
            out.append("| " + _link(r["cwe_id"]) + " | " + _cell(r["name"]) + " | " +
                       _cell(r["description"][:140]) + " |")
    out += ["", "---", "", "## Most-attacked weaknesses", "",
            "Ranked by the number of CAPEC attack patterns that target them: a data-driven view of "
            "which weaknesses have the richest known exploit tradecraft.", "",
            "| CWE | Weakness | Abstraction | CAPEC patterns | Consequences |", "|---|---|---|--:|---|"]
    ranked = sorted(live, key=lambda r: (-r["attacked_by_capec_count"], int(r["cwe_id"][4:])))[:MOST_ATTACKED]
    for r in ranked:
        out.append("| " + _link(r["cwe_id"]) + " | " + _cell(r["name"]) + " | " + r["abstraction"] + " | " +
                   str(r["attacked_by_capec_count"]) + " | " + _cell(", ".join(r["common_consequences"][:3])) + " |")
    out += ["", "---", "", "## Weakness classes", "",
            "The Class-level weaknesses: the practical taxonomy most secure-coding and testing work maps to.", "",
            "| CWE | Class | Consequences | Example mitigation |", "|---|---|---|---|"]
    for r in live:
        if r["abstraction"] == "Class":
            out.append("| " + _link(r["cwe_id"]) + " | " + _cell(r["name"]) + " | " +
                       _cell(", ".join(r["common_consequences"][:2])) + " | " +
                       _cell(r["mitigation"][:90] or "N/A") + " |")
    return "\n".join(out) + "\n"


def page_text(rows: list[dict]) -> str:
    raw = pi.committed(CWE_PAGE)
    if raw is None:
        sys.exit("[" + TOOL + "] " + CWE_PAGE + " is missing")
    text = pi.lf(raw).decode("utf-8")
    m = BLOCK_RE.search(text)
    if not m:
        sys.exit("[" + TOOL + "] " + CWE_PAGE + " has no <!-- " + BLOCK + " begin --> block")
    return text[:m.start(2)] + page_block(rows) + text[m.end(2):]


def capec_problems(root, ns: str) -> list[str]:
    upstream = {}
    for a in root.iter(ns + "Attack_Pattern"):
        upstream["CAPEC-" + a.get("ID")] = {
            "capec_id": "CAPEC-" + a.get("ID"), "name": a.get("Name"),
            "abstraction": a.get("Abstraction"), "status": a.get("Status"),
            "typical_severity": a.findtext(ns + "Typical_Severity") or "",
            "likelihood": a.findtext(ns + "Likelihood_Of_Attack") or "",
            "related_cwe": ["CWE-" + x.get("CWE_ID") for x in a.iter(ns + "Related_Weakness")],
            "capec_version": CAPEC_RELEASE,
        }
    with open(os.path.join(pi.ROOT, CAPEC_REL), encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]
    probs = []
    ids = [r.get("capec_id") for r in rows]
    missing = sorted(set(upstream) - set(ids), key=lambda s: int(s[6:]))
    extra = sorted(set(ids) - set(upstream))
    if missing:
        probs.append(CAPEC_REL + ": missing " + str(len(missing)) + " CAPEC " + CAPEC_RELEASE +
                     " patterns: " + ", ".join(missing[:10]))
    if extra:
        probs.append(CAPEC_REL + ": " + str(len(extra)) + " ids not in CAPEC " + CAPEC_RELEASE +
                     ": " + ", ".join(extra[:10]))
    if len(ids) != len(set(ids)):
        probs.append(CAPEC_REL + ": duplicate capec_id rows")
    for r in rows:
        u = upstream.get(r.get("capec_id"))
        if not u:
            continue
        for k, v in u.items():
            if r.get(k) != v:
                probs.append(CAPEC_REL + ": " + r["capec_id"] + " " + k + " is " + repr(r.get(k))[:80] +
                             ", CAPEC " + CAPEC_RELEASE + " has " + repr(v)[:80])
    return probs


def _args(argv: list[str]) -> dict:
    args = {}
    it = iter(argv)
    for a in it:
        if a in ("--cwe", "--capec"):
            args[a] = next(it, None)
        elif a == "--check":
            args[a] = True
        elif a in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        else:
            sys.exit("[" + TOOL + "] unknown option " + a)
    return args


def main(argv: list[str]) -> int:
    args = _args(argv)
    cwe_root, cwe_ns = _xml("cwe", args.get("--cwe"))
    capec_root, capec_ns = _xml("capec", args.get("--capec"))
    rows = cwe_rows(cwe_root, cwe_ns)
    text = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    page = page_text(rows)
    probs = capec_problems(capec_root, capec_ns)
    if args.get("--check"):
        for rel, body in ((CWE_REL, text), (CWE_PAGE, page)):
            if pi.drift(rel, body):
                probs.insert(0, rel + " differs from the pinned CWE " + CWE_RELEASE +
                             " build (run python -I scripts/build_weaknesses.py and commit)")
        if probs:
            print("FAIL:")
            for p in probs[:40]:
                print("  - " + p)
            return 1
        print("OK: " + CWE_REL + " and the " + CWE_PAGE + " tables match CWE " + CWE_RELEASE +
              ", and " + CAPEC_REL + " matches CAPEC " + CAPEC_RELEASE)
        return 0
    for rel, body in ((CWE_REL, text), (CWE_PAGE, page)):
        if pi.write_text(rel, body):
            print("wrote " + rel)
    for p in probs[:40]:
        print("CAPEC: " + p)
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
