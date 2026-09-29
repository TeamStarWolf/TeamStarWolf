#!/usr/bin/env python3
"""Generate data/MANIFEST.json: a per-file catalogue of the source datasets with
row count, byte size, SHA-256 and provenance (upstream project + license).

Why (audit / Library Enhancement Roadmap Tier 1.9): the repository ships 40
source data files aggregated from several upstreams (MITRE ATT&CK/D3FEND/CAR/
Engage/CWE/CAPEC/ATLAS, the CTID Mappings Explorer, and first-party TeamStarWolf
crosswalks) under an MIT license with no manifest and no third-party notice.
The manifest is the referential-integrity + provenance foundation every later
dataset addition depends on; THIRD_PARTY_NOTICES.md carries the attributions.

Objective facts (path/rows/bytes/sha256, and any version field found in the
data itself) are computed. Provenance (source/license/url) comes from the
explicit PROVENANCE table below — edit it, never guess, when adding data.

Default: (re)write data/MANIFEST.json.
--check: regenerate in memory and exit 1 if the committed manifest is stale.
"""
from __future__ import annotations
import json, os, sys, glob, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "data", "MANIFEST.json")

# Upstream projects present in this repository. SPDX where a clear license
# applies; MITRE content is used under the MITRE Terms of Use (not an SPDX id).
SOURCES = {
    "attack":  {"upstream": "MITRE ATT&CK", "license": "MITRE Terms of Use",
                "url": "https://attack.mitre.org/", "copyright": "(c) The MITRE Corporation"},
    "d3fend":  {"upstream": "MITRE D3FEND", "license": "MITRE Terms of Use",
                "url": "https://d3fend.mitre.org/", "copyright": "(c) The MITRE Corporation"},
    "car":     {"upstream": "MITRE Cyber Analytics Repository (CAR)", "license": "MITRE Terms of Use",
                "url": "https://car.mitre.org/", "copyright": "(c) The MITRE Corporation"},
    "engage":  {"upstream": "MITRE Engage", "license": "MITRE Terms of Use",
                "url": "https://engage.mitre.org/", "copyright": "(c) The MITRE Corporation"},
    "cwe":     {"upstream": "MITRE CWE", "license": "MITRE Terms of Use",
                "url": "https://cwe.mitre.org/", "copyright": "(c) The MITRE Corporation"},
    "capec":   {"upstream": "MITRE CAPEC", "license": "MITRE Terms of Use",
                "url": "https://capec.mitre.org/", "copyright": "(c) The MITRE Corporation"},
    "atlas":   {"upstream": "MITRE ATLAS", "license": "MITRE Terms of Use",
                "url": "https://atlas.mitre.org/", "copyright": "(c) The MITRE Corporation"},
    "ctid_map":{"upstream": "Center for Threat-Informed Defense — Mappings Explorer (NIST SP 800-53 Rev 5; control text is US-Government public domain)",
                "license": "Apache-2.0", "url": "https://center-for-threat-informed-defense.github.io/mappings-explorer/",
                "copyright": "(c) The MITRE Corporation, all rights reserved (Apache-2.0)"},
    "ctid_f3": {"upstream": "Center for Threat-Informed Defense — F3EAD / Fraud (F3) framework",
                "license": "Apache-2.0", "url": "https://github.com/center-for-threat-informed-defense",
                "copyright": "(c) The MITRE Corporation, all rights reserved (Apache-2.0)"},
    "tsw":     {"upstream": "TeamStarWolf (first-party)", "license": "MIT",
                "url": "https://github.com/TeamStarWolf/TeamStarWolf", "copyright": "(c) TeamStarWolf"},
    "tsw_attack": {"upstream": "TeamStarWolf (first-party) — aggregated/derived from MITRE ATT&CK",
                   "license": "MIT (derivation); underlying ATT&CK under MITRE Terms of Use",
                   "url": "https://github.com/TeamStarWolf/TeamStarWolf", "copyright": "(c) TeamStarWolf; ATT&CK (c) The MITRE Corporation"},
    "tsw_ctid": {"upstream": "TeamStarWolf (first-party) — derived by joining vendor->control with CTID control->technique",
                 "license": "MIT (derivation); underlying CTID mappings Apache-2.0",
                 "url": "https://github.com/TeamStarWolf/TeamStarWolf", "copyright": "(c) TeamStarWolf; CTID mappings (c) The MITRE Corporation (Apache-2.0)"},
}

# Longest matching prefix wins. Paths are POSIX-relative to the repo root.
PROVENANCE = [
    ("data/attack/ics/",                       "attack"),
    ("data/attack/mobile/",                    "attack"),
    ("data/attack/technique_to_d3fend.jsonl",  "d3fend"),
    ("data/attack/d3fend_countermeasures.jsonl","d3fend"),
    ("data/attack/technique_to_car.jsonl",     "car"),
    ("data/attack/technique_profiles.jsonl",   "tsw_attack"),
    ("data/attack/group_profiles.jsonl",       "tsw_attack"),
    ("data/attack/software_profiles.jsonl",    "tsw_attack"),
    ("data/attack/campaign_profiles.jsonl",    "tsw_attack"),
    ("data/attack/",                           "attack"),
    ("data/engage/",                           "engage"),
    ("data/weaknesses/cwe.jsonl",              "cwe"),
    ("data/weaknesses/capec.jsonl",            "capec"),
    ("data/ai/",                               "atlas"),
    ("data/fraud/",                            "ctid_f3"),
    ("data/control_to_technique.jsonl",        "ctid_map"),
    ("data/vendor_to_technique.jsonl",         "tsw_ctid"),
    ("data/vendor_to_control.jsonl",           "tsw"),
]

VERSION_KEYS = ["attack_version", "capec_version", "cwe_version", "atlas_version",
                "x_mitre_version", "version", "spec_version"]


def _source_for(rel: str):
    best = None
    for prefix, key in PROVENANCE:
        if rel.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, key)
    return SOURCES[best[1]] if best else None


def _file_entry(path: str, rel: str):
    with open(path, "rb") as f:
        raw = f.read()
    # Hash/size the LF-normalized content so the manifest is identical on every
    # platform (git stores text as LF; a Windows working tree checks out CRLF).
    # These are all UTF-8 text datasets, so CRLF->LF normalization is lossless.
    norm = raw.replace(b"\r\n", b"\n")
    sha = hashlib.sha256(norm).hexdigest()
    entry = {"path": rel, "bytes": len(norm), "sha256": sha}
    if rel.endswith(".jsonl"):
        text = norm.decode("utf-8")
        lines = [l for l in text.split("\n") if l.strip()]
        entry["rows"] = len(lines)
        # data-declared version/source, if the rows carry one (informational)
        try:
            row0 = json.loads(lines[0])
            for k in VERSION_KEYS:
                if k in row0:
                    entry["data_version_field"] = {k: row0[k]}
                    break
            for sk in ("source", "ctid_source"):
                if sk in row0:
                    entry["data_source_field"] = row0[sk]
                    break
        except Exception:
            pass
    src = _source_for(rel)
    entry["provenance"] = src if src else {"upstream": "UNSPECIFIED — add to PROVENANCE",
                                           "license": "UNSPECIFIED", "url": "", "copyright": ""}
    return entry


def compute():
    files = sorted(
        p.replace("\\", "/") for p in
        glob.glob(os.path.join(ROOT, "data", "**", "*.jsonl"), recursive=True)
        + glob.glob(os.path.join(ROOT, "data", "**", "*.json"), recursive=True)
    )
    entries, total = [], 0
    for p in files:
        rel = os.path.relpath(p, ROOT).replace("\\", "/")
        if rel == "data/MANIFEST.json" or rel.startswith("data/generated/"):
            continue  # catalogue source data only, not the manifest or generated artifacts
        e = _file_entry(p, rel)
        total += e["bytes"]
        entries.append(e)
    return {
        "_comment": ("Generated by scripts/build_manifest.py — do not edit by hand. "
                     "Objective fields (rows/bytes/sha256) are computed; provenance comes "
                     "from the script's PROVENANCE table. See THIRD_PARTY_NOTICES.md."),
        "dataset_count": len(entries),
        "total_bytes": total,
        "files": entries,
    }


def main():
    manifest = compute()
    if "--check" in sys.argv:
        if not os.path.exists(MANIFEST):
            print("ERROR: data/MANIFEST.json is missing — run scripts/build_manifest.py")
            sys.exit(1)
        committed = json.load(open(MANIFEST, encoding="utf-8"))
        if committed != manifest:
            print("STALE: data/MANIFEST.json does not match the data on disk "
                  "(run scripts/build_manifest.py and commit).")
            unspecified = [e["path"] for e in manifest["files"]
                           if e["provenance"]["license"] == "UNSPECIFIED"]
            if unspecified:
                print("  files with UNSPECIFIED provenance:", ", ".join(unspecified))
            sys.exit(1)
        print(f"OK: data/MANIFEST.json matches all {manifest['dataset_count']} source datasets")
        return
    with open(MANIFEST, "w", encoding="utf-8", newline="") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote data/MANIFEST.json — {manifest['dataset_count']} datasets, "
          f"{manifest['total_bytes']:,} bytes")
    unspecified = [e["path"] for e in manifest["files"]
                   if e["provenance"]["license"] == "UNSPECIFIED"]
    if unspecified:
        print("  WARNING: UNSPECIFIED provenance for:", ", ".join(unspecified))


if __name__ == "__main__":
    main()
