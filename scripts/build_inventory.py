#!/usr/bin/env python3
"""Validate the vendor and capability inventory and build its roll-up.

Three hand-authored sources under data/inventory/ describe a capability taxonomy and
the companies and products that document each capability:

    data/inventory/capabilities.jsonl   the capability taxonomy (one row per capability),
                                         each mapped to a framework item only where the
                                         framework's own published text supports it.
    data/inventory/companies.jsonl       one row per company, keyed to a `vendor:<slug>`
                                         id in data/vocab/ so the inventory and the shared
                                         entity vocabulary name the same vendor.
    data/inventory/products.jsonl        one row per product, each tied to a company and
                                         to the capabilities the vendor documents for it.

From them this script writes a generated roll-up:

    data/inventory/inventory.json        counts, the taxonomy, and the companies and
                                         products joined to capability and vendor names.
                                         Not edited by hand; `source_sha256` lets a
                                         consumer verify it against the three sources.

Principles this validator enforces (see data/INVENTORY.md):
  * One model. A company id is a `vendor:<slug>` that already exists in the shared
    vocabulary; a product names its company; a capability mapping names a capability.
  * Every fact is sourced. A company fact and every "documented" capability mapping
    carry the vendor page URL and the date it was read. A mapping that could not be
    confirmed on a vendor page is recorded `unverified` with a note and NO source, so
    it is never a name written from memory.
  * Framework items are cited, not invented. A NIST CSF 2.0 Function, a CIS Controls
    v8.1 Control or a MITRE D3FEND countermeasure is accepted only when its id and name
    match the framework's own text; D3FEND ids are checked against the pinned 1.6.0
    release in data/attack/d3fend_countermeasures.jsonl.
  * Neutral wording. Ranking and marketing words, and unsourced "vulnerable"/"breached"
    claims, fail; a capability mapping means the vendor documents the function, not that
    a product does it best. Em dashes fail (docs/VOICE.md).

Usage:
    python scripts/build_inventory.py              # validate, then (re)write inventory.json
    python scripts/build_inventory.py --check      # exit 1 if the roll-up is stale
    python scripts/build_inventory.py --self-test  # planted bad-record controls
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import tracked_files  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INV_DIR = "data/inventory"
CAPS = f"{INV_DIR}/capabilities.jsonl"
COMPANIES = f"{INV_DIR}/companies.jsonl"
PRODUCTS = f"{INV_DIR}/products.jsonl"
INVENTORY_JSON = f"{INV_DIR}/inventory.json"
VOCAB_JSON = "data/vocab/vocabulary.json"
D3FEND = "data/attack/d3fend_countermeasures.jsonl"
SCHEMA_VERSION = 1

# ---------------------------------------------------------------- locked vocabularies

CATEGORIES = (
    "endpoint-xdr", "vuln-exposure", "siem-soar", "email-network", "firewall-appliance",
    "identity-access", "appsec-crowdsourced", "cloud-container", "ot-ics", "backup-resilience",
)
CATEGORY_LABELS = {
    "endpoint-xdr": "Endpoint and extended detection",
    "vuln-exposure": "Vulnerability and exposure management",
    "siem-soar": "Vulnerability workflow, SIEM, and SOAR",
    "email-network": "Email and network security",
    "firewall-appliance": "Firewalls and network appliances",
    "identity-access": "Identity, access, and privilege",
    "appsec-crowdsourced": "Application and crowdsourced security",
    "cloud-container": "Cloud and container security",
    "ot-ics": "Operational technology and ICS",
    "backup-resilience": "Backup, recovery, and cyber resilience",
}
COMPANY_STATUS = ("independent", "subsidiary", "merged", "defunct")
PRODUCT_STATUS = ("current", "renamed", "eol", "discontinued")
CAP_MAP_STATUS = ("documented", "unverified")

# NIST CSF 2.0 Functions (NIST CSWP 29). Names are the framework's own.
CSF_FUNCTIONS = {
    "GV": "Govern", "ID": "Identify", "PR": "Protect",
    "DE": "Detect", "RS": "Respond", "RC": "Recover",
}
# CIS Critical Security Controls v8.1 (cisecurity.org). Titles are the framework's own.
CIS_CONTROLS = {
    "1": "Inventory and Control of Enterprise Assets",
    "2": "Inventory and Control of Software Assets",
    "3": "Data Protection",
    "4": "Secure Configuration of Enterprise Assets and Software",
    "5": "Account Management",
    "6": "Access Control Management",
    "7": "Continuous Vulnerability Management",
    "8": "Audit Log Management",
    "9": "Email and Web Browser Protections",
    "10": "Malware Defenses",
    "11": "Data Recovery",
    "12": "Network Infrastructure Management",
    "13": "Network Monitoring and Defense",
    "14": "Security Awareness and Skills Training",
    "15": "Service Provider Management",
    "16": "Application Software Security",
    "17": "Incident Response Management",
    "18": "Penetration Testing",
}

# Field sets (hand-authored, so order is free; the set must match exactly).
CAP_FIELDS = frozenset(("id", "name", "category", "definition", "aka",
                        "frameworks", "library_refs", "reviewed_at"))
COMPANY_FIELDS = frozenset(("id", "name", "former_names", "status", "parent",
                            "parent_name", "acquired_on", "official_url", "sources", "reviewed_at"))
PRODUCT_FIELDS = frozenset(("id", "company", "name", "former_names", "status",
                            "official_url", "capabilities", "sources", "reviewed_at"))
COMPANY_SOURCE_KEYS = frozenset(("status", "former_names", "name", "parent",
                                 "acquired_on", "official_url"))
PRODUCT_SOURCE_KEYS = frozenset(("name", "former_names", "official_url", "status"))

CAP_ID_RE = re.compile(r"^capability:[a-z0-9][a-z0-9-]*$")
VENDOR_ID_RE = re.compile(r"^vendor:[a-z0-9][a-z0-9-]*$")
PRODUCT_ID_RE = re.compile(r"^product:[a-z0-9][a-z0-9-]*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ACQUIRED_RE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")
HTTPS_RE = re.compile(r"^https://\S+$")
EM_DASH = "\u2014"
# Ranking / marketing words that have no place in a neutral catalogue, plus the two
# claims the brief bars without a CVE/advisory/regulator source.
BANNED_WORDS = (
    "best", "leading", "leader", "market-leading", "world-class", "cutting-edge",
    "state-of-the-art", "unbeatable", "flawless", "bulletproof", "superior",
    "ultimate", "revolutionary", "award-winning", "top-rated", "number one",
    "best-in-class", "industry-leading", "vulnerable", "breached",
)
BANNED_RE = re.compile(r"(?<![a-z])(" + "|".join(re.escape(w) for w in BANNED_WORDS) + r")(?![a-z])", re.I)


class InventoryError(Exception):
    pass


# ----------------------------------------------------------------------------- helpers

def _is_str(x):
    return isinstance(x, str) and x.strip() != ""


def _str_list(x):
    return isinstance(x, list) and all(_is_str(i) for i in x)


def _text_problems(where, text, errors):
    """Em dash and banned-word scan for a free-text field."""
    if not isinstance(text, str):
        return
    if EM_DASH in text:
        errors.append(f"{where}: contains an em dash (use a hyphen; docs/VOICE.md)")
    m = BANNED_RE.search(text)
    if m:
        errors.append(f"{where}: banned ranking/marketing or unsourced word {m.group(0)!r} "
                      f"(keep wording neutral; a product documents a function, it is not ranked)")


def _source_entry(where, key, val, errors):
    if not isinstance(val, dict) or set(val.keys()) != {"url", "read_date"}:
        errors.append(f"{where}: source {key!r} must be an object with exactly url and read_date")
        return
    if not (isinstance(val["url"], str) and HTTPS_RE.match(val["url"])):
        errors.append(f"{where}: source {key!r} url must be an https URL")
    if not (isinstance(val["read_date"], str) and DATE_RE.match(val["read_date"])):
        errors.append(f"{where}: source {key!r} read_date must be YYYY-MM-DD")


# ----------------------------------------------------------------------------- the build

def validate(src: dict) -> dict:
    """Pure validation over collected sources; raises InventoryError listing every
    problem, or returns a structure the roll-up is rendered from.

    `src` keys: caps, companies, products (lists of dict); vocab_vendors (set of
    vendor ids); d3fend (dict d3fend_id -> name); exists(rel) -> bool.
    """
    errors: list[str] = []
    vocab_vendors = src["vocab_vendors"]
    d3fend = src["d3fend"]
    exists = src["exists"]

    # ---- capabilities
    cap_ids: dict[str, dict] = {}
    for r in src["caps"]:
        cid = r.get("id")
        where = f"{CAPS} {cid!r}"
        if not isinstance(r, dict) or set(r.keys()) != CAP_FIELDS:
            errors.append(f"{where}: fields must be exactly {sorted(CAP_FIELDS)}")
            continue
        if not (_is_str(cid) and CAP_ID_RE.match(cid)):
            errors.append(f"{where}: id must match capability:<lowercase-slug>")
            continue
        if cid in cap_ids:
            errors.append(f"{where}: duplicate id")
            continue
        cap_ids[cid] = r
        if not _is_str(r["name"]):
            errors.append(f"{where}: name is required")
        if r["category"] not in CATEGORIES:
            errors.append(f"{where}: category {r['category']!r} must be one of {CATEGORIES}")
        if not _is_str(r["definition"]):
            errors.append(f"{where}: definition is required")
        _text_problems(f"{where} name", r.get("name"), errors)
        _text_problems(f"{where} definition", r.get("definition"), errors)
        if not _str_list(r["aka"]):
            errors.append(f"{where}: aka must be a list of non-empty strings")
        if not isinstance(r["frameworks"], list):
            errors.append(f"{where}: frameworks must be a list")
        else:
            for fr in r["frameworks"]:
                _framework_problems(where, fr, d3fend, errors)
        if not _str_list(r["library_refs"]):
            errors.append(f"{where}: library_refs must be a list of non-empty strings")
        else:
            for p in r["library_refs"]:
                if not exists(p):
                    errors.append(f"{where}: library_ref {p!r} is not a repository file")
        if not (isinstance(r["reviewed_at"], str) and DATE_RE.match(r["reviewed_at"])):
            errors.append(f"{where}: reviewed_at must be YYYY-MM-DD")

    # ---- companies
    company_ids: dict[str, dict] = {}
    for r in src["companies"]:
        cid = r.get("id")
        where = f"{COMPANIES} {cid!r}"
        if not isinstance(r, dict) or set(r.keys()) != COMPANY_FIELDS:
            errors.append(f"{where}: fields must be exactly {sorted(COMPANY_FIELDS)}")
            continue
        if not (_is_str(cid) and VENDOR_ID_RE.match(cid)):
            errors.append(f"{where}: id must match vendor:<lowercase-slug>")
            continue
        if cid in company_ids:
            errors.append(f"{where}: duplicate id")
            continue
        company_ids[cid] = r
        if cid not in vocab_vendors:
            errors.append(f"{where}: id is not a vendor in {VOCAB_JSON} "
                          f"(add the vendor to data/vocab/ first so there is one model)")
        if not _is_str(r["name"]):
            errors.append(f"{where}: name is required")
        _text_problems(f"{where} name", r.get("name"), errors)
        if not _str_list(r["former_names"]):
            errors.append(f"{where}: former_names must be a list of non-empty strings")
        else:
            for n in r["former_names"]:
                _text_problems(f"{where} former_name", n, errors)
        if r["status"] not in COMPANY_STATUS:
            errors.append(f"{where}: status {r['status']!r} must be one of {COMPANY_STATUS}")
        parent, parent_name = r["parent"], r["parent_name"]
        if parent is not None:
            if not (_is_str(parent) and VENDOR_ID_RE.match(parent)):
                errors.append(f"{where}: parent must be null or a vendor:<slug> id")
            elif parent not in vocab_vendors:
                errors.append(f"{where}: parent {parent!r} is not a vendor in {VOCAB_JSON}")
            elif parent == cid:
                errors.append(f"{where}: parent must not be the company itself")
        if parent_name is not None and not _is_str(parent_name):
            errors.append(f"{where}: parent_name must be null or a non-empty string")
        if r["status"] in ("subsidiary", "merged") and parent is None and parent_name is None:
            errors.append(f"{where}: status {r['status']} needs a parent or parent_name")
        if r["status"] == "independent" and (parent is not None or parent_name is not None):
            errors.append(f"{where}: an independent company must not name a parent")
        if r["acquired_on"] is not None and not (isinstance(r["acquired_on"], str)
                                                 and ACQUIRED_RE.match(r["acquired_on"])):
            errors.append(f"{where}: acquired_on must be null or YYYY, YYYY-MM or YYYY-MM-DD")
        if not (_is_str(r["official_url"]) and HTTPS_RE.match(r["official_url"])):
            errors.append(f"{where}: official_url must be an https URL")
        _sources_problems(where, r["sources"], COMPANY_SOURCE_KEYS, errors)
        if isinstance(r["sources"], dict):
            # An ownership change (acquisition/merger/shutdown) is always cited; an
            # independent company is evidenced by its own official_url, so a status
            # source is optional there.
            if r["status"] != "independent" and "status" not in r["sources"]:
                errors.append(f"{where}: a non-independent status needs a source "
                              f"(the acquirer announcement or company page the ownership came from)")
            if r["former_names"] and "former_names" not in r["sources"]:
                errors.append(f"{where}: former_names present but not sourced")
        if not (isinstance(r["reviewed_at"], str) and DATE_RE.match(r["reviewed_at"])):
            errors.append(f"{where}: reviewed_at must be YYYY-MM-DD")

    # ---- products
    product_ids: dict[str, dict] = {}
    for r in src["products"]:
        pid = r.get("id")
        where = f"{PRODUCTS} {pid!r}"
        if not isinstance(r, dict) or set(r.keys()) != PRODUCT_FIELDS:
            errors.append(f"{where}: fields must be exactly {sorted(PRODUCT_FIELDS)}")
            continue
        if not (_is_str(pid) and PRODUCT_ID_RE.match(pid)):
            errors.append(f"{where}: id must match product:<lowercase-slug>")
            continue
        if pid in product_ids:
            errors.append(f"{where}: duplicate id")
            continue
        product_ids[pid] = r
        comp = r["company"]
        if not (_is_str(comp) and VENDOR_ID_RE.match(comp)):
            errors.append(f"{where}: company must be a vendor:<slug> id")
        elif comp not in company_ids:
            errors.append(f"{where}: company {comp!r} has no row in {COMPANIES}")
        if not _is_str(r["name"]):
            errors.append(f"{where}: name is required")
        _text_problems(f"{where} name", r.get("name"), errors)
        if not _str_list(r["former_names"]):
            errors.append(f"{where}: former_names must be a list of non-empty strings")
        else:
            for n in r["former_names"]:
                _text_problems(f"{where} former_name", n, errors)
        if r["status"] not in PRODUCT_STATUS:
            errors.append(f"{where}: status {r['status']!r} must be one of {PRODUCT_STATUS}")
        if not (_is_str(r["official_url"]) and HTTPS_RE.match(r["official_url"])):
            errors.append(f"{where}: official_url must be an https URL")
        if not isinstance(r["capabilities"], list) or not r["capabilities"]:
            errors.append(f"{where}: capabilities must be a non-empty list")
        else:
            seen = set()
            for m in r["capabilities"]:
                _mapping_problems(where, m, cap_ids, seen, errors)
        _sources_problems(where, r["sources"], PRODUCT_SOURCE_KEYS, errors)
        if isinstance(r["sources"], dict) and r["former_names"] and "former_names" not in r["sources"]:
            errors.append(f"{where}: former_names present but not sourced")
        if not (isinstance(r["reviewed_at"], str) and DATE_RE.match(r["reviewed_at"])):
            errors.append(f"{where}: reviewed_at must be YYYY-MM-DD")

    if errors:
        raise InventoryError("\n".join(errors))
    return {"caps": cap_ids, "companies": company_ids, "products": product_ids}


def _framework_problems(where, fr, d3fend, errors):
    if not isinstance(fr, dict) or "framework" not in fr:
        errors.append(f"{where}: each framework entry must be an object with a framework key")
        return
    fw = fr["framework"]
    if fw == "nist-csf-2.0":
        if set(fr.keys()) != {"framework", "ref", "name", "source_url", "read_date"}:
            errors.append(f"{where}: nist-csf-2.0 entry needs framework, ref, name, source_url, read_date")
            return
        if fr["ref"] not in CSF_FUNCTIONS:
            errors.append(f"{where}: CSF ref {fr['ref']!r} is not a CSF 2.0 Function id")
        elif fr["name"] != CSF_FUNCTIONS[fr["ref"]]:
            errors.append(f"{where}: CSF {fr['ref']} name must be {CSF_FUNCTIONS[fr['ref']]!r}")
        if not (isinstance(fr["source_url"], str) and HTTPS_RE.match(fr["source_url"])):
            errors.append(f"{where}: CSF source_url must be an https URL")
        if not (isinstance(fr["read_date"], str) and DATE_RE.match(fr["read_date"])):
            errors.append(f"{where}: CSF read_date must be YYYY-MM-DD")
    elif fw == "cis-controls-v8.1":
        if set(fr.keys()) != {"framework", "ref", "name", "source_url", "read_date"}:
            errors.append(f"{where}: cis-controls-v8.1 entry needs framework, ref, name, source_url, read_date")
            return
        if fr["ref"] not in CIS_CONTROLS:
            errors.append(f"{where}: CIS ref {fr['ref']!r} is not a CIS v8.1 Control number (1-18, as a string)")
        elif fr["name"] != CIS_CONTROLS[fr["ref"]]:
            errors.append(f"{where}: CIS Control {fr['ref']} title must be {CIS_CONTROLS[fr['ref']]!r}")
        if not (isinstance(fr["source_url"], str) and HTTPS_RE.match(fr["source_url"])):
            errors.append(f"{where}: CIS source_url must be an https URL")
        if not (isinstance(fr["read_date"], str) and DATE_RE.match(fr["read_date"])):
            errors.append(f"{where}: CIS read_date must be YYYY-MM-DD")
    elif fw == "d3fend-1.6.0":
        if set(fr.keys()) != {"framework", "ref", "name", "dataset"}:
            errors.append(f"{where}: d3fend-1.6.0 entry needs framework, ref, name, dataset")
            return
        if fr["dataset"] != D3FEND:
            errors.append(f"{where}: d3fend dataset must be {D3FEND!r}")
        if fr["ref"] not in d3fend:
            errors.append(f"{where}: D3FEND ref {fr['ref']!r} is not in the pinned 1.6.0 release {D3FEND}")
        elif fr["name"] != d3fend[fr["ref"]]:
            errors.append(f"{where}: D3FEND {fr['ref']} name must be {d3fend[fr['ref']]!r} (the pinned release)")
    else:
        errors.append(f"{where}: framework {fw!r} must be nist-csf-2.0, cis-controls-v8.1 or d3fend-1.6.0")


def _mapping_problems(where, m, cap_ids, seen, errors):
    if not isinstance(m, dict) or "capability_id" not in m or "status" not in m:
        errors.append(f"{where}: each capability mapping needs capability_id and status")
        return
    cap = m["capability_id"]
    if cap not in cap_ids:
        errors.append(f"{where}: capability_id {cap!r} has no row in {CAPS}")
    if cap in seen:
        errors.append(f"{where}: capability_id {cap!r} is mapped twice")
    seen.add(cap)
    st = m["status"]
    if st == "documented":
        if set(m.keys()) != {"capability_id", "status", "source_url", "read_date"}:
            errors.append(f"{where} {cap}: a documented mapping needs capability_id, status, "
                          f"source_url, read_date (the vendor page and date it was read)")
            return
        if not (isinstance(m["source_url"], str) and HTTPS_RE.match(m["source_url"])):
            errors.append(f"{where} {cap}: documented source_url must be an https URL")
        if not (isinstance(m["read_date"], str) and DATE_RE.match(m["read_date"])):
            errors.append(f"{where} {cap}: documented read_date must be YYYY-MM-DD")
    elif st == "unverified":
        if set(m.keys()) != {"capability_id", "status", "note"}:
            errors.append(f"{where} {cap}: an unverified mapping carries capability_id, status and a "
                          f"note ONLY (no source_url: it was not confirmed on a vendor page)")
            return
        if not _is_str(m["note"]):
            errors.append(f"{where} {cap}: unverified mapping needs a non-empty note")
        _text_problems(f"{where} {cap} note", m.get("note"), errors)
    else:
        errors.append(f"{where} {cap}: status {st!r} must be 'documented' or 'unverified'")


def _sources_problems(where, sources, allowed, errors):
    if not isinstance(sources, dict):
        errors.append(f"{where}: sources must be an object")
        return
    for k, v in sources.items():
        if k not in allowed:
            errors.append(f"{where}: source key {k!r} is not one of {sorted(allowed)}")
            continue
        _source_entry(where, k, v, errors)


# ----------------------------------------------------------------------------- IO + roll-up

def _read_jsonl(rel: str) -> list[dict]:
    out = []
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        for line in f:
            if line.strip():
                out.append(json.loads(line))
    return out


def _sha256(rel: str) -> str:
    with open(os.path.join(ROOT, rel), "rb") as f:
        data = f.read().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def collect() -> dict:
    tracked = set(tracked_files())

    def exists(rel):
        return rel in tracked or os.path.isfile(os.path.join(ROOT, rel))

    vocab = json.load(open(os.path.join(ROOT, VOCAB_JSON), encoding="utf-8"))
    vocab_vendors = {e["id"] for e in vocab["entities"] if e["type"] == "vendor"}
    d3fend = {r["d3fend_id"]: r["name"] for r in _read_jsonl(D3FEND)}
    return {
        "caps": _read_jsonl(CAPS),
        "companies": _read_jsonl(COMPANIES),
        "products": _read_jsonl(PRODUCTS),
        "vocab_vendors": vocab_vendors,
        "vocab_labels": {e["id"]: e["label"] for e in vocab["entities"]},
        "d3fend": d3fend,
        "exists": exists,
    }


def roll_up(src: dict, resolved: dict) -> dict:
    labels = src.get("vocab_labels", {})
    caps, companies, products = resolved["caps"], resolved["companies"], resolved["products"]

    prod_by_company: dict[str, list[str]] = {}
    prod_by_cap: dict[str, list[str]] = {}
    doc_by_cap: dict[str, int] = {}
    unv_by_cap: dict[str, int] = {}
    for pid, p in products.items():
        prod_by_company.setdefault(p["company"], []).append(pid)
        for m in p["capabilities"]:
            prod_by_cap.setdefault(m["capability_id"], []).append(pid)
            if m["status"] == "documented":
                doc_by_cap[m["capability_id"]] = doc_by_cap.get(m["capability_id"], 0) + 1
            else:
                unv_by_cap[m["capability_id"]] = unv_by_cap.get(m["capability_id"], 0) + 1

    cap_rows = []
    for cid in sorted(caps):
        c = caps[cid]
        cap_rows.append({
            "id": cid, "name": c["name"], "category": c["category"],
            "frameworks": [{"framework": f["framework"], "ref": f["ref"], "name": f["name"]}
                           for f in c["frameworks"]],
            "product_count": len(prod_by_cap.get(cid, [])),
            "documented_count": doc_by_cap.get(cid, 0),
            "unverified_count": unv_by_cap.get(cid, 0),
            "products": sorted(prod_by_cap.get(cid, [])),
        })
    categories = [{
        "category": cat, "label": CATEGORY_LABELS[cat],
        "capabilities": sorted(cid for cid in caps if caps[cid]["category"] == cat),
    } for cat in CATEGORIES]
    company_rows = []
    for cid in sorted(companies):
        c = companies[cid]
        company_rows.append({
            "id": cid, "label": labels.get(cid, c["name"]), "name": c["name"],
            "status": c["status"], "parent": c["parent"], "parent_name": c["parent_name"],
            "acquired_on": c["acquired_on"],
            "products": sorted(prod_by_company.get(cid, [])),
        })
    product_rows = []
    for pid in sorted(products):
        p = products[pid]
        product_rows.append({
            "id": pid, "company": p["company"], "company_label": labels.get(p["company"], p["company"]),
            "name": p["name"], "status": p["status"],
            "capabilities": [{"capability_id": m["capability_id"],
                              "name": caps[m["capability_id"]]["name"] if m["capability_id"] in caps else None,
                              "status": m["status"]} for m in p["capabilities"]],
        })

    doc_total = sum(doc_by_cap.values())
    unv_total = sum(unv_by_cap.values())
    return {
        "_comment": ("Generated by scripts/build_inventory.py: do not edit by hand. A roll-up of "
                     "data/inventory/*.jsonl joined to the shared vocabulary; source_sha256 is the "
                     "LF-normalised SHA-256 of each source. Field meanings: data/INVENTORY.md."),
        "schema_version": SCHEMA_VERSION,
        "sources": [CAPS, COMPANIES, PRODUCTS],
        "source_sha256": {rel: _sha256(rel) for rel in (CAPS, COMPANIES, PRODUCTS)},
        "counts": {
            "capabilities": len(caps), "companies": len(companies), "products": len(products),
            "capability_mappings": doc_total + unv_total,
            "documented_mappings": doc_total, "unverified_mappings": unv_total,
            "companies_by_status": {s: sum(1 for c in companies.values() if c["status"] == s)
                                    for s in COMPANY_STATUS},
            "products_by_status": {s: sum(1 for p in products.values() if p["status"] == s)
                                   for s in PRODUCT_STATUS},
        },
        "categories": categories,
        "capabilities": cap_rows,
        "companies": company_rows,
        "products": product_rows,
    }


def render_json(doc: dict) -> str:
    """Pretty header, one compact row per line for the list sections (readable diffs)."""
    list_keys = ("categories", "capabilities", "companies", "products")
    head = {k: v for k, v in doc.items() if k not in list_keys}
    text = json.dumps(head, indent=2, ensure_ascii=False).rstrip().rstrip("}").rstrip().rstrip(",") + ",\n"
    parts = []
    for k in list_keys:
        body = ",\n".join("    " + json.dumps(r, ensure_ascii=False) for r in doc[k])
        parts.append(f'  "{k}": [\n{body}\n  ]')
    return text + ",\n".join(parts) + "\n}\n"


def outputs() -> tuple[dict, str]:
    src = collect()
    resolved = validate(src)
    doc = roll_up(src, resolved)
    return doc, render_json(doc)


def _read(rel: str) -> str | None:
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


def main_build() -> int:
    doc, text = outputs()
    with open(os.path.join(ROOT, INVENTORY_JSON), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    c = doc["counts"]
    print(f"wrote {INVENTORY_JSON}: {c['capabilities']} capabilities, {c['companies']} companies, "
          f"{c['products']} products, {c['capability_mappings']} mappings "
          f"({c['documented_mappings']} documented, {c['unverified_mappings']} unverified)")
    return 0


def main_check() -> int:
    doc, text = outputs()
    if _read(INVENTORY_JSON) != text:
        print(f"STALE: {INVENTORY_JSON} differs from what the sources produce. "
              f"Run python scripts/build_inventory.py and commit it.")
        return 1
    c = doc["counts"]
    print(f"OK: {INVENTORY_JSON} matches its sources ({c['capabilities']} capabilities, "
          f"{c['companies']} companies, {c['products']} products)")
    return 0


# ----------------------------------------------------------------------------- self-test

def self_test() -> int:
    fails = []

    def expect(name, cond):
        if not cond:
            fails.append(name)

    RD = "2026-11-25"
    d3fend = {"D3-MFA": "Multi-factor Authentication", "D3-EF": "Email Filtering"}

    def base_cap(**over):
        r = {"id": "capability:edr", "name": "Endpoint Detection and Response",
             "category": "endpoint-xdr", "definition": "Recording endpoint activity for detection.",
             "aka": ["EDR"],
             "frameworks": [{"framework": "nist-csf-2.0", "ref": "DE", "name": "Detect",
                             "source_url": "https://doi.org/10.6028/NIST.CSWP.29", "read_date": RD}],
             "library_refs": ["platforms/README.md"], "reviewed_at": RD}
        r.update(over)
        return r

    def base_company(**over):
        r = {"id": "vendor:crowdstrike", "name": "CrowdStrike", "former_names": [],
             "status": "independent", "parent": None, "parent_name": None, "acquired_on": None,
             "official_url": "https://www.crowdstrike.com/",
             "sources": {"status": {"url": "https://www.crowdstrike.com/about/", "read_date": RD}},
             "reviewed_at": RD}
        r.update(over)
        return r

    def base_product(**over):
        r = {"id": "product:falcon-insight", "company": "vendor:crowdstrike",
             "name": "Falcon Insight XDR", "former_names": [], "status": "current",
             "official_url": "https://www.crowdstrike.com/platform/",
             "capabilities": [{"capability_id": "capability:edr", "status": "documented",
                               "source_url": "https://www.crowdstrike.com/platform/", "read_date": RD}],
             "sources": {}, "reviewed_at": RD}
        r.update(over)
        return r

    def src(caps=None, companies=None, products=None):
        return {
            "caps": caps if caps is not None else [base_cap()],
            "companies": companies if companies is not None else [base_company()],
            "products": products if products is not None else [base_product()],
            "vocab_vendors": {"vendor:crowdstrike", "vendor:microsoft"},
            "vocab_labels": {"vendor:crowdstrike": "CrowdStrike"},
            "d3fend": d3fend,
            "exists": lambda rel: rel == "platforms/README.md",
        }

    # the clean baseline validates
    try:
        validate(src())
        ok_baseline = True
    except InventoryError as e:
        ok_baseline = False
        print("baseline error:\n" + str(e))
    expect("clean baseline validates", ok_baseline)

    def fails_with(fragment, **kw):
        try:
            validate(src(**kw))
        except InventoryError as e:
            return fragment in str(e)
        return False

    # --- planted controls (one fault each) ---
    expect("C1 unknown capability category",
           fails_with("must be one of", caps=[base_cap(category="not-a-category")]))
    expect("C2 company id not a vocab vendor",
           fails_with("is not a vendor in", companies=[base_company(id="vendor:not-real")],
                      products=[base_product(company="vendor:not-real")]))
    expect("C3 product names a missing company",
           fails_with("has no row in", products=[base_product(company="vendor:microsoft")]))
    expect("C4 documented mapping without a source",
           fails_with("documented mapping needs", products=[base_product(
               capabilities=[{"capability_id": "capability:edr", "status": "documented"}])]))
    expect("C5 unverified mapping carrying a source",
           fails_with("no source_url", products=[base_product(
               capabilities=[{"capability_id": "capability:edr", "status": "unverified",
                              "note": "seen on a blog", "source_url": "https://x.example/"}])]))
    expect("C6 mapping to an unknown capability",
           fails_with("has no row in", products=[base_product(
               capabilities=[{"capability_id": "capability:nope", "status": "documented",
                              "source_url": "https://x.example/", "read_date": RD}])]))
    expect("C7 CSF function name does not match the id",
           fails_with("name must be 'Detect'", caps=[base_cap(
               frameworks=[{"framework": "nist-csf-2.0", "ref": "DE", "name": "Protect",
                            "source_url": "https://doi.org/10.6028/NIST.CSWP.29", "read_date": RD}])]))
    expect("C8 CIS control title does not match the number",
           fails_with("title must be", caps=[base_cap(
               frameworks=[{"framework": "cis-controls-v8.1", "ref": "10", "name": "Data Recovery",
                            "source_url": "https://www.cisecurity.org/controls/cis-controls-list",
                            "read_date": RD}])]))
    expect("C9 D3FEND ref not in the pinned release",
           fails_with("not in the pinned 1.6.0 release", caps=[base_cap(
               frameworks=[{"framework": "d3fend-1.6.0", "ref": "D3-NOPE", "name": "X",
                            "dataset": D3FEND}])]))
    expect("C10 ranking word in a definition",
           fails_with("banned ranking", caps=[base_cap(
               definition="The leading endpoint product on the market.")]))
    expect("C11 unsourced 'vulnerable' claim in free text",
           fails_with("banned ranking", products=[base_product(
               capabilities=[{"capability_id": "capability:edr", "status": "unverified",
                              "note": "left the host vulnerable"}])]))
    expect("C12 em dash in a string",
           fails_with("em dash", caps=[base_cap(definition="Endpoint detection \u2014 and response.")]))
    expect("C13 subsidiary without a parent",
           fails_with("needs a parent", companies=[base_company(status="subsidiary")]))
    expect("C14 non-independent status not sourced",
           fails_with("non-independent status needs a source",
                      companies=[base_company(status="subsidiary", parent_name="Example Holdings",
                                              acquired_on="2021", sources={})]))
    expect("C15 former_names present but unsourced",
           fails_with("former_names present but not sourced",
                      companies=[base_company(former_names=["Old Name"])]))
    expect("C16 duplicate capability id",
           fails_with("duplicate id", caps=[base_cap(), base_cap()]))
    expect("C17 bad reviewed_at date",
           fails_with("reviewed_at must be", caps=[base_cap(reviewed_at="Nov 2026")]))
    expect("C18 a capability mapped twice on one product",
           fails_with("mapped twice", products=[base_product(
               capabilities=[{"capability_id": "capability:edr", "status": "documented",
                              "source_url": "https://x.example/", "read_date": RD},
                             {"capability_id": "capability:edr", "status": "documented",
                              "source_url": "https://y.example/", "read_date": RD}])]))
    expect("C19 non-https official_url",
           fails_with("official_url must be an https URL",
                      companies=[base_company(official_url="http://insecure.example/")]))
    expect("C20 unknown source key",
           fails_with("is not one of", companies=[base_company(
               sources={"status": {"url": "https://x.example/", "read_date": RD},
                        "ceo": {"url": "https://x.example/", "read_date": RD}})]))
    expect("C21 independent company naming a parent",
           fails_with("must not name a parent",
                      companies=[base_company(parent="vendor:microsoft")]))
    expect("C22 wrong field set on a capability",
           fails_with("fields must be exactly", caps=[{"id": "capability:x", "name": "X"}]))
    expect("C23 library_ref is not a repository file",
           fails_with("is not a repository file", caps=[base_cap(library_refs=["platforms/ghost.md"])]))

    if fails:
        print("SELF-TEST FAILED: " + "; ".join(fails))
        return 1
    print("OK: build_inventory self-test (23 planted controls: schema, vocab/d3fend/cis/csf "
          "cross-refs, sourcing, unverified-vs-documented, neutral wording, duplicates)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="exit 1 if inventory.json is stale")
    g.add_argument("--self-test", action="store_true", help="run the planted bad-record controls")
    a = ap.parse_args()
    try:
        if a.self_test:
            return self_test()
        return main_check() if a.check else main_build()
    except InventoryError as e:
        print("ERROR: build_inventory:\n" + str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
