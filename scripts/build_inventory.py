#!/usr/bin/env python3
"""Validate the vendor and capability inventory and build its roll-up.

Three hand-authored sources under data/inventory/ describe a capability taxonomy and
the companies and products that document each capability:

    data/inventory/capabilities.jsonl   the capability taxonomy (one row per capability),
                                         each mapped to a framework ITEM (a NIST CSF 2.0
                                         Function with its Subcategories, a CIS Controls
                                         v8.1 Control with its Safeguards, or a pinned
                                         MITRE D3FEND countermeasure) only where the
                                         framework's own text supports it.
    data/inventory/companies.jsonl       one row per company, keyed to a `vendor:<slug>`
                                         id in data/vocab/; its ownership is stated with a
                                         sourced, dated status (public, private, pe-owned,
                                         acquired, public-controlled or defunct) and, when
                                         there is an announced-but-unclosed deal, that too.
    data/inventory/products.jsonl        one row per NAMED product, tied to the vocabulary
                                         (`vocab_product`), to its company and platform,
                                         and to the capabilities the vendor documents, each
                                         with the vendor's own term on the cited page
                                         (`documented_as`).

From them this script writes a generated roll-up, data/inventory/inventory.json.

Principles this validator enforces (see data/INVENTORY.md):
  * One model. A company id is a `vendor:<slug>` in the shared vocabulary; a product's
    `vocab_product` is a vocabulary product of the same vendor (null only where the
    vocabulary does not cover it yet), and a product id that is itself a vocabulary id
    must equal its `vocab_product` (no parallel slug for an existing vocabulary product).
  * Every fact is sourced and dated. Every company carries a status source; every
    "documented" capability mapping carries a vendor page URL and read date; an
    ownership change (acquired / pe-owned / public-controlled) names its holder. A
    mapping that could not be confirmed on a vendor page is `unverified` with a note and
    NO source. Product pages and mapping sources must be on the company's own domains;
    a status source may be on the company's or its holder's domain.
  * Framework items are cited, not invented. A CSF 2.0 Function / CIS v8.1 Control id and
    name must match the framework's own text; the Subcategory / Safeguard `items` must
    sit under that Function / Control; D3FEND ids are checked against the pinned 1.6.0
    release and say whether they cover the whole capability or a `part`.
  * Wording filter. This is a word list, not a check of claims: it fails ranking and
    marketing words and the unsourced security words "vulnerable", "breached",
    "insecure", "hacked" and "compromised" in free text, and em dashes (docs/VOICE.md).
    It cannot tell a true claim from a false one.

Usage:
    python scripts/build_inventory.py              # validate, then (re)write inventory.json
    python scripts/build_inventory.py --check      # exit 1 if the roll-up is stale
    python scripts/build_inventory.py --self-test  # planted bad-record controls
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from urllib.parse import urlsplit

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
SCHEMA_VERSION = 2
TODAY = "2026-11-25"

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
# Ownership that says what is true and is sourced in every case (see INVENTORY.md).
COMPANY_STATUS = ("public", "private", "pe-owned", "acquired", "public-controlled", "defunct")
STATUS_NEEDS_HOLDER = ("pe-owned", "acquired", "public-controlled")
STATUS_NEEDS_SINCE = ("pe-owned", "acquired")
STATUS_NEEDS_TICKER = ("public", "public-controlled")
PRODUCT_STATUS = ("current", "renamed", "eol", "discontinued")
CAP_MAP_STATUS = ("documented", "unverified")

CSF_FUNCTIONS = {"GV": "Govern", "ID": "Identify", "PR": "Protect",
                 "DE": "Detect", "RS": "Respond", "RC": "Recover"}
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

CAP_FIELDS = frozenset(("id", "name", "category", "definition", "synonyms", "components",
                        "frameworks", "library_refs", "reviewed_at"))
COMPANY_FIELDS = frozenset(("id", "name", "former_names", "status", "holder", "holder_name",
                            "ownership_since", "ticker", "announced_acquisition", "domains",
                            "holder_domains", "official_url", "sources", "reviewed_at"))
PRODUCT_FIELDS = frozenset(("id", "vocab_product", "company", "name", "former_names", "platform",
                            "status", "official_url", "capabilities", "sources", "reviewed_at"))
COMPANY_SOURCE_KEYS = frozenset(("status", "former_names", "name", "ownership_since", "official_url"))
PRODUCT_SOURCE_KEYS = frozenset(("name", "former_names", "official_url", "status", "platform"))

CAP_ID_RE = re.compile(r"^capability:[a-z0-9][a-z0-9-]*$")
VENDOR_ID_RE = re.compile(r"^vendor:[a-z0-9][a-z0-9-]*$")
PRODUCT_ID_RE = re.compile(r"^product:[a-z0-9][a-z0-9-]*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SINCE_RE = re.compile(r"^\d{4}(-\d{2}(-\d{2})?)?$")
DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
CSF_ITEM_RE = re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$")
CIS_ITEM_RE = re.compile(r"^(1[0-8]|[1-9])\.\d{1,2}$")
EM_DASH = "\u2014"
BANNED_WORDS = (
    "best", "leading", "leader", "market-leading", "world-class", "cutting-edge",
    "state-of-the-art", "unbeatable", "flawless", "bulletproof", "superior", "ultimate",
    "revolutionary", "award-winning", "top-rated", "number one", "best-in-class",
    "industry-leading", "vulnerable", "breached", "insecure", "hacked", "compromised",
)
BANNED_RE = re.compile(r"(?<![a-z])(" + "|".join(re.escape(w) for w in BANNED_WORDS) + r")(?![a-z])", re.I)


class InventoryError(Exception):
    pass


# ----------------------------------------------------------------------------- helpers

def _is_str(x):
    return isinstance(x, str) and x.strip() != ""


def _str_list(x):
    return isinstance(x, list) and all(_is_str(i) for i in x)


def _valid_date(s):
    if not (isinstance(s, str) and DATE_RE.match(s)):
        return False
    try:
        _dt.date.fromisoformat(s)
        return True
    except ValueError:
        return False


def _not_future(s):
    return _valid_date(s) and s <= TODAY


def _valid_since(s):
    """YYYY, YYYY-MM or YYYY-MM-DD, a real calendar date, not after today."""
    if not (isinstance(s, str) and SINCE_RE.match(s)):
        return False
    full = s + "-01-01" if len(s) == 4 else (s + "-01" if len(s) == 7 else s)
    return _valid_date(full) and s <= TODAY


def _host(url):
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname:
        return None
    if "@" in (parts.netloc or ""):          # credentials in the URL
        return None
    host = parts.hostname
    if not host.isascii() or not DOMAIN_RE.match(host):   # lookalike letters, bad host
        return None
    return host.lower()


def _host_in(url, domains):
    h = _host(url)
    if h is None:
        return False
    return any(h == d or h.endswith("." + d) for d in domains)


def _bad_text(s):
    """A string that must never appear raw in a name/definition/term: pipe, newline, HTML."""
    return "|" in s or "\n" in s or "\r" in s or re.search(r"<[^>]+>", s) is not None


def _text_problems(where, text, errors):
    if not isinstance(text, str):
        return
    if EM_DASH in text:
        errors.append(f"{where}: contains an em dash (use a hyphen; docs/VOICE.md)")
    if _bad_text(text):
        errors.append(f"{where}: contains a pipe, newline or HTML tag (would break generated pages)")
    m = BANNED_RE.search(text)
    if m:
        errors.append(f"{where}: wording-filter word {m.group(0)!r} (keep wording neutral; this is a "
                      f"word filter, not a verified claim)")


def _source_entry(where, key, val, domains, errors):
    if not isinstance(val, dict) or set(val.keys()) != {"url", "read_date"}:
        errors.append(f"{where}: source {key!r} must be an object with exactly url and read_date")
        return
    if _host(val["url"]) is None:
        errors.append(f"{where}: source {key!r} url must be a clean https URL (no credentials, ASCII host)")
    elif domains is not None and not _host_in(val["url"], domains):
        errors.append(f"{where}: source {key!r} url host is not one of the allowed domains {sorted(domains)}")
    if not _not_future(val["read_date"]):
        errors.append(f"{where}: source {key!r} read_date must be a real date no later than {TODAY}")


# ----------------------------------------------------------------------------- the build

def validate(src: dict) -> dict:
    errors: list[str] = []
    vocab_vendors = src["vocab_vendors"]
    vocab_products = src["vocab_products"]   # product id -> vendor id
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
        for f in ("synonyms", "components"):
            if not isinstance(r[f], list) or not all(isinstance(x, str) and x.strip() for x in r[f]):
                errors.append(f"{where}: {f} must be a list of non-empty strings")
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
        if not _not_future(r["reviewed_at"]):
            errors.append(f"{where}: reviewed_at must be a real date no later than {TODAY}")

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
            errors.append(f"{where}: id is not a vendor in {VOCAB_JSON}")
        if not _is_str(r["name"]):
            errors.append(f"{where}: name is required")
        _text_problems(f"{where} name", r.get("name"), errors)
        if not _str_list(r["former_names"]):
            errors.append(f"{where}: former_names must be a list of non-empty strings")
        else:
            for n in r["former_names"]:
                _text_problems(f"{where} former_name", n, errors)
        domains = r["domains"] if isinstance(r["domains"], list) else []
        if not (domains and all(isinstance(d, str) and DOMAIN_RE.match(d) for d in domains)):
            errors.append(f"{where}: domains must be a non-empty list of bare hostnames")
            domains = []
        holder_domains = r["holder_domains"] if isinstance(r["holder_domains"], list) else []
        if not all(isinstance(d, str) and DOMAIN_RE.match(d) for d in holder_domains):
            errors.append(f"{where}: holder_domains must be a list of bare hostnames")
            holder_domains = []
        st = r["status"]
        if st not in COMPANY_STATUS:
            errors.append(f"{where}: status {st!r} must be one of {COMPANY_STATUS}")
        holder, holder_name = r["holder"], r["holder_name"]
        if holder is not None:
            if not (_is_str(holder) and VENDOR_ID_RE.match(holder)):
                errors.append(f"{where}: holder must be null or a vendor:<slug> id")
            elif holder not in vocab_vendors:
                errors.append(f"{where}: holder {holder!r} is not a vendor in {VOCAB_JSON}")
            elif holder == cid:
                errors.append(f"{where}: holder must not be the company itself")
        if holder_name is not None and not _is_str(holder_name):
            errors.append(f"{where}: holder_name must be null or a non-empty string")
        if st in STATUS_NEEDS_HOLDER and holder is None and holder_name is None:
            errors.append(f"{where}: status {st} needs a holder or holder_name")
        if st in ("public", "private") and (holder is not None or holder_name is not None):
            errors.append(f"{where}: a {st} company must not name a holder")
        if st in STATUS_NEEDS_SINCE and r["ownership_since"] is None:
            errors.append(f"{where}: status {st} needs ownership_since")
        if r["ownership_since"] is not None and not _valid_since(r["ownership_since"]):
            errors.append(f"{where}: ownership_since must be a real past date (YYYY, YYYY-MM or YYYY-MM-DD)")
        if r["ticker"] is not None:
            _text_problems(f"{where} ticker", r["ticker"], errors)
        aa = r["announced_acquisition"]
        if aa is not None:
            if not isinstance(aa, dict) or set(aa.keys()) != {"acquirer", "acquirer_name",
                                                              "announced_date", "source"}:
                errors.append(f"{where}: announced_acquisition needs acquirer, acquirer_name, "
                              f"announced_date, source")
            else:
                if aa["acquirer"] is not None and not (
                        _is_str(aa["acquirer"]) and VENDOR_ID_RE.match(aa["acquirer"])):
                    errors.append(f"{where}: announced_acquisition.acquirer must be null or a vendor id")
                if not _is_str(aa["acquirer_name"]):
                    errors.append(f"{where}: announced_acquisition.acquirer_name is required")
                if not _not_future(aa["announced_date"]):
                    errors.append(f"{where}: announced_acquisition.announced_date must be a real date "
                                  f"no later than {TODAY}")
                _source_entry(f"{where} announced_acquisition", "source", aa.get("source"),
                              (domains + holder_domains) or None, errors)
        if _host(r["official_url"]) is None:
            errors.append(f"{where}: official_url must be a clean https URL")
        elif domains and not _host_in(r["official_url"], domains):
            errors.append(f"{where}: official_url host is not one of domains {sorted(domains)}")
        if not isinstance(r["sources"], dict):
            errors.append(f"{where}: sources must be an object")
        else:
            for k, v in r["sources"].items():
                if k not in COMPANY_SOURCE_KEYS:
                    errors.append(f"{where}: source key {k!r} is not one of {sorted(COMPANY_SOURCE_KEYS)}")
                    continue
                allowed = (domains + holder_domains) if k in ("status", "ownership_since") else domains
                _source_entry(where, k, v, allowed or None, errors)
            if "status" not in r["sources"]:
                errors.append(f"{where}: every company needs a status source (the company or acquirer "
                              f"page the ownership came from)")
            if r["former_names"] and "former_names" not in r["sources"]:
                errors.append(f"{where}: former_names present but not sourced")
        if not _not_future(r["reviewed_at"]):
            errors.append(f"{where}: reviewed_at must be a real date no later than {TODAY}")

    # ---- products
    product_ids: dict[str, dict] = {}
    product_names: dict[str, str] = {}
    companies_with_product: set[str] = set()
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
        comp_domains = []
        if not (_is_str(comp) and VENDOR_ID_RE.match(comp)):
            errors.append(f"{where}: company must be a vendor:<slug> id")
        elif comp not in company_ids:
            errors.append(f"{where}: company {comp!r} has no row in {COMPANIES}")
        else:
            companies_with_product.add(comp)
            comp_domains = company_ids[comp]["domains"] if isinstance(company_ids[comp]["domains"], list) else []
        vp = r["vocab_product"]
        if vp is not None:
            if vp not in vocab_products:
                errors.append(f"{where}: vocab_product {vp!r} is not a product in {VOCAB_JSON}")
            elif comp in company_ids and vocab_products[vp] != comp:
                errors.append(f"{where}: vocab_product {vp!r} belongs to {vocab_products[vp]}, not {comp}")
        if pid in vocab_products and pid != vp:
            errors.append(f"{where}: id is a vocabulary product, so vocab_product must equal it "
                          f"(do not mint a parallel slug)")
        if not _is_str(r["name"]):
            errors.append(f"{where}: name is required")
        else:
            _text_problems(f"{where} name", r["name"], errors)
            key = r["name"].strip().lower()
            if key in product_names:
                errors.append(f"{where}: product name duplicates {product_names[key]}")
            else:
                product_names[key] = pid
        if not _str_list(r["former_names"]):
            errors.append(f"{where}: former_names must be a list of non-empty strings")
        else:
            for n in r["former_names"]:
                _text_problems(f"{where} former_name", n, errors)
        if not _is_str(r["platform"]):
            errors.append(f"{where}: platform is required (the suite the product belongs to)")
        else:
            _text_problems(f"{where} platform", r["platform"], errors)
        if r["status"] not in PRODUCT_STATUS:
            errors.append(f"{where}: status {r['status']!r} must be one of {PRODUCT_STATUS}")
        if _host(r["official_url"]) is None:
            errors.append(f"{where}: official_url must be a clean https URL")
        elif comp_domains and not _host_in(r["official_url"], comp_domains):
            errors.append(f"{where}: official_url host is not the company's domain {sorted(comp_domains)}")
        if not isinstance(r["capabilities"], list) or not r["capabilities"]:
            errors.append(f"{where}: capabilities must be a non-empty list")
        else:
            seen = set()
            for m in r["capabilities"]:
                _mapping_problems(where, m, cap_ids, seen, comp_domains, errors)
        if not isinstance(r["sources"], dict):
            errors.append(f"{where}: sources must be an object")
        else:
            for k, v in r["sources"].items():
                if k not in PRODUCT_SOURCE_KEYS:
                    errors.append(f"{where}: source key {k!r} is not one of {sorted(PRODUCT_SOURCE_KEYS)}")
                    continue
                _source_entry(where, k, v, comp_domains or None, errors)
            if r["former_names"] and "former_names" not in r["sources"]:
                errors.append(f"{where}: former_names present but not sourced")
        if not _not_future(r["reviewed_at"]):
            errors.append(f"{where}: reviewed_at must be a real date no later than {TODAY}")

    for cid in sorted(company_ids):
        if cid not in companies_with_product:
            errors.append(f"{COMPANIES} {cid!r}: company has no product in {PRODUCTS}")

    if errors:
        raise InventoryError("\n".join(errors))
    return {"caps": cap_ids, "companies": company_ids, "products": product_ids}


def _framework_problems(where, fr, d3fend, errors):
    if not isinstance(fr, dict) or "framework" not in fr:
        errors.append(f"{where}: each framework entry must be an object with a framework key")
        return
    fw = fr["framework"]
    if fw in ("nist-csf-2.0", "cis-controls-v8.1"):
        if set(fr.keys()) != {"framework", "ref", "name", "items", "source_url", "read_date"}:
            errors.append(f"{where}: {fw} entry needs framework, ref, name, items, source_url, read_date")
            return
        table = CSF_FUNCTIONS if fw == "nist-csf-2.0" else CIS_CONTROLS
        item_re = CSF_ITEM_RE if fw == "nist-csf-2.0" else CIS_ITEM_RE
        if fr["ref"] not in table:
            errors.append(f"{where}: {fw} ref {fr['ref']!r} is not a valid id")
        elif fr["name"] != table[fr["ref"]]:
            errors.append(f"{where}: {fw} {fr['ref']} name must be {table[fr['ref']]!r}")
        if not isinstance(fr["items"], list) or not all(isinstance(x, str) for x in fr["items"]):
            errors.append(f"{where}: {fw} items must be a list of strings")
        else:
            for it in fr["items"]:
                if not item_re.match(it):
                    errors.append(f"{where}: {fw} item {it!r} is not a valid id")
                elif fw == "nist-csf-2.0" and not it.startswith(fr["ref"] + "."):
                    errors.append(f"{where}: CSF item {it!r} is not under Function {fr['ref']}")
                elif fw == "cis-controls-v8.1" and it.split(".")[0] != fr["ref"]:
                    errors.append(f"{where}: CIS item {it!r} is not under Control {fr['ref']}")
        if _host(fr["source_url"]) is None:
            errors.append(f"{where}: {fw} source_url must be a clean https URL")
        if not _not_future(fr["read_date"]):
            errors.append(f"{where}: {fw} read_date must be a real date no later than {TODAY}")
    elif fw == "d3fend-1.6.0":
        if set(fr.keys()) != {"framework", "ref", "name", "scope", "dataset"}:
            errors.append(f"{where}: d3fend-1.6.0 entry needs framework, ref, name, scope, dataset")
            return
        if fr["dataset"] != D3FEND:
            errors.append(f"{where}: d3fend dataset must be {D3FEND!r}")
        if fr["ref"] not in d3fend:
            errors.append(f"{where}: D3FEND ref {fr['ref']!r} is not in the pinned 1.6.0 release")
        elif fr["name"] != d3fend[fr["ref"]]:
            errors.append(f"{where}: D3FEND {fr['ref']} name must be {d3fend[fr['ref']]!r}")
        if fr["scope"] not in ("full", "part"):
            errors.append(f"{where}: d3fend scope must be 'full' or 'part'")
    else:
        errors.append(f"{where}: framework {fw!r} must be nist-csf-2.0, cis-controls-v8.1 or d3fend-1.6.0")


def _mapping_problems(where, m, cap_ids, seen, comp_domains, errors):
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
        if set(m.keys()) != {"capability_id", "status", "documented_as", "source_url", "read_date"}:
            errors.append(f"{where} {cap}: a documented mapping needs capability_id, status, "
                          f"documented_as, source_url, read_date")
            return
        if not _is_str(m["documented_as"]):
            errors.append(f"{where} {cap}: documented_as (the vendor's own term on the page) is required")
        else:
            _text_problems(f"{where} {cap} documented_as", m["documented_as"], errors)
        if _host(m["source_url"]) is None:
            errors.append(f"{where} {cap}: source_url must be a clean https URL")
        elif comp_domains and not _host_in(m["source_url"], comp_domains):
            errors.append(f"{where} {cap}: source_url host is not the company's domain "
                          f"(a mapping must cite the vendor's own page)")
        if not _not_future(m["read_date"]):
            errors.append(f"{where} {cap}: read_date must be a real date no later than {TODAY}")
    elif st == "unverified":
        if set(m.keys()) != {"capability_id", "status", "note"}:
            errors.append(f"{where} {cap}: an unverified mapping carries capability_id, status and note only")
            return
        if not _is_str(m["note"]):
            errors.append(f"{where} {cap}: unverified mapping needs a non-empty note")
        else:
            _text_problems(f"{where} {cap} note", m["note"], errors)
            low = m["note"].lower()
            if "http" in low or "www." in low:
                errors.append(f"{where} {cap}: an unverified note must not contain a URL")
            if re.search(r"(?<![a-z])confirm", low):
                errors.append(f"{where} {cap}: an unverified note must not claim it was confirmed")
    else:
        errors.append(f"{where} {cap}: status {st!r} must be 'documented' or 'unverified'")


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
    vocab_products = {e["id"]: e.get("vendor") for e in vocab["entities"] if e["type"] == "product"}
    d3fend = {r["d3fend_id"]: r["name"] for r in _read_jsonl(D3FEND)}
    return {
        "caps": _read_jsonl(CAPS), "companies": _read_jsonl(COMPANIES), "products": _read_jsonl(PRODUCTS),
        "vocab_vendors": vocab_vendors, "vocab_products": vocab_products,
        "vocab_labels": {e["id"]: e["label"] for e in vocab["entities"]},
        "d3fend": d3fend, "exists": exists,
    }


def roll_up(src: dict, resolved: dict) -> dict:
    labels = src.get("vocab_labels", {})
    caps, companies, products = resolved["caps"], resolved["companies"], resolved["products"]
    prod_by_company, prod_by_cap, doc_by_cap, unv_by_cap = {}, {}, {}, {}
    for pid, p in products.items():
        prod_by_company.setdefault(p["company"], []).append(pid)
        for m in p["capabilities"]:
            prod_by_cap.setdefault(m["capability_id"], []).append(pid)
            bucket = doc_by_cap if m["status"] == "documented" else unv_by_cap
            bucket.setdefault(m["capability_id"], []).append(pid)

    cap_rows = [{
        "id": cid, "name": caps[cid]["name"], "category": caps[cid]["category"],
        "frameworks": [{k: f[k] for k in f if k not in ("source_url", "read_date", "dataset")}
                       for f in caps[cid]["frameworks"]],
        "product_count": len(prod_by_cap.get(cid, [])),
        "documented_count": len(doc_by_cap.get(cid, [])),
        "unverified_count": len(unv_by_cap.get(cid, [])),
        "products": sorted(prod_by_cap.get(cid, [])),
    } for cid in sorted(caps)]
    categories = [{"category": c, "label": CATEGORY_LABELS[c],
                   "capabilities": sorted(k for k in caps if caps[k]["category"] == c)}
                  for c in CATEGORIES]
    company_rows = [{
        "id": cid, "label": labels.get(cid, companies[cid]["name"]), "name": companies[cid]["name"],
        "status": companies[cid]["status"], "holder": companies[cid]["holder"],
        "holder_name": companies[cid]["holder_name"], "ownership_since": companies[cid]["ownership_since"],
        "ticker": companies[cid]["ticker"],
        "announced_acquisition": (companies[cid]["announced_acquisition"] or {}).get("acquirer_name"),
        "products": sorted(prod_by_company.get(cid, [])),
    } for cid in sorted(companies)]
    product_rows = [{
        "id": pid, "vocab_product": products[pid]["vocab_product"], "company": products[pid]["company"],
        "company_label": labels.get(products[pid]["company"], products[pid]["company"]),
        "name": products[pid]["name"], "platform": products[pid]["platform"],
        "status": products[pid]["status"],
        "capabilities": [{"capability_id": m["capability_id"], "status": m["status"],
                          "documented_as": m.get("documented_as")} for m in products[pid]["capabilities"]],
    } for pid in sorted(products)]

    doc_total = sum(len(v) for v in doc_by_cap.values())
    unv_total = sum(len(v) for v in unv_by_cap.values())
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
        "categories": categories, "capabilities": cap_rows,
        "companies": company_rows, "products": product_rows,
    }


def render_json(doc: dict) -> str:
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
             "synonyms": ["EDR"], "components": [],
             "frameworks": [{"framework": "nist-csf-2.0", "ref": "DE", "name": "Detect", "items": [],
                             "source_url": "https://doi.org/10.6028/NIST.CSWP.29", "read_date": RD},
                            {"framework": "cis-controls-v8.1", "ref": "13",
                             "name": "Network Monitoring and Defense", "items": ["13.7"],
                             "source_url": "https://www.cisecurity.org/controls/cis-controls-list",
                             "read_date": RD}],
             "library_refs": ["platforms/README.md"], "reviewed_at": RD}
        r.update(over)
        return r

    def base_company(**over):
        r = {"id": "vendor:crowdstrike", "name": "CrowdStrike", "former_names": [],
             "status": "public", "holder": None, "holder_name": None, "ownership_since": None,
             "ticker": "NASDAQ: CRWD", "announced_acquisition": None,
             "domains": ["crowdstrike.com"], "holder_domains": [],
             "official_url": "https://www.crowdstrike.com/",
             "sources": {"status": {"url": "https://ir.crowdstrike.com/", "read_date": RD}},
             "reviewed_at": RD}
        r.update(over)
        return r

    def base_product(**over):
        r = {"id": "product:crowdstrike-falcon-cloud-security", "vocab_product": "product:crowdstrike-falcon",
             "company": "vendor:crowdstrike", "name": "CrowdStrike Falcon Cloud Security",
             "former_names": [], "platform": "CrowdStrike Falcon", "status": "current",
             "official_url": "https://www.crowdstrike.com/platform/cloud-security/",
             "capabilities": [{"capability_id": "capability:edr", "status": "documented",
                               "documented_as": "CNAPP",
                               "source_url": "https://www.crowdstrike.com/platform/cloud-security/",
                               "read_date": RD}],
             "sources": {}, "reviewed_at": RD}
        r.update(over)
        return r

    def src(caps=None, companies=None, products=None):
        return {
            "caps": caps if caps is not None else [base_cap()],
            "companies": companies if companies is not None else [base_company()],
            "products": products if products is not None else [base_product()],
            "vocab_vendors": {"vendor:crowdstrike", "vendor:cisco"},
            "vocab_products": {"product:crowdstrike-falcon": "vendor:crowdstrike",
                               "product:other": "vendor:cisco"},
            "vocab_labels": {"vendor:crowdstrike": "CrowdStrike"},
            "d3fend": d3fend,
            "exists": lambda rel: rel == "platforms/README.md",
        }

    try:
        validate(src()); ok = True
    except InventoryError as e:
        ok = False; print("baseline error:\n" + str(e))
    expect("clean baseline validates", ok)

    def fails_with(fragment, **kw):
        try:
            validate(src(**kw))
        except InventoryError as e:
            return fragment in str(e)
        return False

    expect("C01 unknown category", fails_with("must be one of", caps=[base_cap(category="nope")]))
    expect("C02 company not a vocab vendor", fails_with("is not a vendor in",
           companies=[base_company(id="vendor:nope")], products=[base_product(company="vendor:nope")]))
    expect("C03 product names a missing company", fails_with("has no row in",
           products=[base_product(company="vendor:cisco")]))
    expect("C04 wrong field set on a capability", fails_with("fields must be exactly",
           caps=[{"id": "capability:x", "name": "X"}]))
    expect("C05 duplicate capability id", fails_with("duplicate id", caps=[base_cap(), base_cap()]))
    expect("C06 library_ref not a file", fails_with("is not a repository file",
           caps=[base_cap(library_refs=["platforms/ghost.md"])]))
    expect("C07 documented mapping without source", fails_with("documented mapping needs",
           products=[base_product(capabilities=[{"capability_id": "capability:edr", "status": "documented"}])]))
    expect("C08 unverified mapping carrying extra keys", fails_with("carries capability_id, status and note",
           products=[base_product(capabilities=[{"capability_id": "capability:edr", "status": "unverified",
                                                  "note": "n", "source_url": "https://x.crowdstrike.com/"}])]))
    expect("C09 mapping to unknown capability", fails_with("has no row in",
           products=[base_product(capabilities=[{"capability_id": "capability:nope", "status": "documented",
                                                  "documented_as": "x",
                                                  "source_url": "https://www.crowdstrike.com/x", "read_date": RD}])]))
    expect("C10 capability mapped twice", fails_with("mapped twice", products=[base_product(
           capabilities=[{"capability_id": "capability:edr", "status": "documented", "documented_as": "a",
                          "source_url": "https://www.crowdstrike.com/a", "read_date": RD},
                         {"capability_id": "capability:edr", "status": "documented", "documented_as": "b",
                          "source_url": "https://www.crowdstrike.com/b", "read_date": RD}])]))
    expect("C11 documented_as missing", fails_with("documented_as (the vendor", products=[base_product(
           capabilities=[{"capability_id": "capability:edr", "status": "documented", "documented_as": "",
                          "source_url": "https://www.crowdstrike.com/a", "read_date": RD}])]))
    expect("C12 mapping source off the vendor domain", fails_with("source_url host is not the company",
           products=[base_product(capabilities=[{"capability_id": "capability:edr", "status": "documented",
                                                  "documented_as": "x",
                                                  "source_url": "https://en.wikipedia.org/wiki/CrowdStrike",
                                                  "read_date": RD}])]))
    expect("C13 unverified note with a URL", fails_with("must not contain a URL", products=[base_product(
           capabilities=[{"capability_id": "capability:edr", "status": "unverified",
                          "note": "see https://x.com/y"}])]))
    expect("C14 unverified note claims confirmed", fails_with("must not claim it was confirmed",
           products=[base_product(capabilities=[{"capability_id": "capability:edr", "status": "unverified",
                                                  "note": "confirmed on a blog"}])]))
    expect("C15 CSF name mismatch", fails_with("name must be 'Detect'", caps=[base_cap(
           frameworks=[{"framework": "nist-csf-2.0", "ref": "DE", "name": "Protect", "items": [],
                        "source_url": "https://doi.org/10.6028/NIST.CSWP.29", "read_date": RD}])]))
    expect("C16 CIS title mismatch", fails_with("name must be", caps=[base_cap(
           frameworks=[{"framework": "cis-controls-v8.1", "ref": "10", "name": "Data Recovery", "items": [],
                        "source_url": "https://www.cisecurity.org/controls/cis-controls-list", "read_date": RD}])]))
    expect("C17 CIS item not under control", fails_with("is not under Control", caps=[base_cap(
           frameworks=[{"framework": "cis-controls-v8.1", "ref": "13", "name": "Network Monitoring and Defense",
                        "items": ["9.3"], "source_url": "https://www.cisecurity.org/controls/cis-controls-list",
                        "read_date": RD}])]))
    expect("C18 CSF subcategory not under function", fails_with("is not under Function", caps=[base_cap(
           frameworks=[{"framework": "nist-csf-2.0", "ref": "DE", "name": "Detect", "items": ["PR.AA-05"],
                        "source_url": "https://doi.org/10.6028/NIST.CSWP.29", "read_date": RD}])]))
    expect("C19 D3FEND ref not pinned", fails_with("not in the pinned 1.6.0 release", caps=[base_cap(
           frameworks=[{"framework": "d3fend-1.6.0", "ref": "D3-NOPE", "name": "X", "scope": "part",
                        "dataset": D3FEND}])]))
    expect("C20 D3FEND scope bad", fails_with("scope must be", caps=[base_cap(
           frameworks=[{"framework": "d3fend-1.6.0", "ref": "D3-MFA", "name": "Multi-factor Authentication",
                        "scope": "most", "dataset": D3FEND}])]))
    expect("C21 ranking word", fails_with("wording-filter word", caps=[base_cap(
           definition="The leading endpoint tool.")]))
    expect("C22 unsourced insecure claim", fails_with("wording-filter word", caps=[base_cap(
           definition="Finds insecure hosts.")]))
    expect("C23 em dash", fails_with("em dash", caps=[base_cap(definition="Endpoint detection \u2014 response.")]))
    expect("C24 pipe/newline/HTML in name", fails_with("pipe, newline or HTML",
           products=[base_product(name="Falcon <b>Cloud</b>")]))
    expect("C25 public company names a holder", fails_with("must not name a holder",
           companies=[base_company(holder_name="Someone")]))
    expect("C26 acquired without holder", fails_with("needs a holder", companies=[base_company(
           status="acquired", ownership_since="2024-03-18", ticker=None, holder_domains=["cisco.com"],
           sources={"status": {"url": "https://newsroom.cisco.com/x", "read_date": RD}})]))
    expect("C27 acquired without ownership_since", fails_with("needs ownership_since", companies=[base_company(
           status="acquired", holder_name="Cisco", ticker=None, holder_domains=["cisco.com"],
           sources={"status": {"url": "https://newsroom.cisco.com/x", "read_date": RD}})]))
    expect("C28 future ownership_since", fails_with("real past date", companies=[base_company(
           status="acquired", holder_name="Acquirer", holder_domains=["acquirer.com"], ticker=None,
           ownership_since="2099-01-01",
           sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": RD}})]))
    expect("C29 status not sourced", fails_with("needs a status source", companies=[base_company(sources={})]))
    expect("C30 status source off-domain", fails_with("host is not", companies=[base_company(
           sources={"status": {"url": "https://reseller.example.com/crowdstrike", "read_date": RD}})]))
    expect("C31 impossible date", fails_with("real date", companies=[base_company(
           sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": "2026-13-45"}})]))
    expect("C32 future read_date", fails_with("no later than", companies=[base_company(
           sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": "2027-01-01"}})]))
    expect("C33 bad reviewed_at", fails_with("real date", caps=[base_cap(reviewed_at="Nov 2026")]))
    expect("C34 official_url off-domain", fails_with("official_url host is not",
           companies=[base_company(official_url="https://example.net/")]))
    expect("C35 credentials in URL", fails_with("official_url must be a clean https URL",
           companies=[base_company(official_url="https://user:pass@crowdstrike.com/")]))
    expect("C36 non-ascii lookalike host", fails_with("official_url must be a clean https URL",
           companies=[base_company(official_url="https://crоwdstrike.com/")]))
    expect("C37 empty domains", fails_with("domains must be a non-empty list",
           companies=[base_company(domains=[])]))
    expect("C38 unknown company source key", fails_with("is not one of", companies=[base_company(
           sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": RD},
                    "ceo": {"url": "https://www.crowdstrike.com/x", "read_date": RD}})]))
    expect("C39 vocab_product wrong vendor", fails_with("belongs to", products=[base_product(
           vocab_product="product:other")]))
    expect("C40 id is a vocab product but vocab_product differs", fails_with("must equal it",
           products=[base_product(id="product:crowdstrike-falcon", vocab_product=None)]))
    expect("C41 duplicate product name", fails_with("product name duplicates", products=[base_product(),
           base_product(id="product:crowdstrike-falcon-next-gen-siem", vocab_product="product:crowdstrike-falcon")]))
    expect("C42 company with no product", fails_with("has no product", products=[]))
    expect("C43 non-https product url", fails_with("official_url must be a clean https URL",
           products=[base_product(official_url="http://www.crowdstrike.com/x")]))

    if fails:
        print("SELF-TEST FAILED: " + "; ".join(fails))
        return 1
    print("OK: build_inventory self-test (43 planted controls: schema, ids, vocab/d3fend/cis/csf "
          "cross-refs and item placement, per-fact sourcing, vendor-domain enforcement, dates, "
          "ownership model, unverified-vs-documented, neutral wording, duplicates)")
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
