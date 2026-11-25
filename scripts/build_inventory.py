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
                                         acquired, public-controlled or defunct), a `stake`
                                         where a holder's interest is majority rather than
                                         full, and an announced-but-unclosed deal.
    data/inventory/products.jsonl        one row per NAMED product, tied to the vocabulary
                                         (`vocab_product`), to its company and platform,
                                         and to the capabilities the vendor documents, each
                                         with the vendor's own words from the cited page
                                         (`documented_as`) and an optional editor `note`.

From them this script writes a generated roll-up, data/inventory/inventory.json.

Principles this validator enforces (see data/INVENTORY.md):
  * One model. A company id is a `vendor:<slug>` in the shared vocabulary; a product's
    `vocab_product` is a vocabulary product of the same vendor (null only where the
    vocabulary does not cover it yet); a product id that is itself a vocabulary id must
    equal its `vocab_product`.
  * Every fact is sourced and dated. Every company carries a status source (on its own,
    its holder's, or a regulator's declared domain); every "documented" mapping carries a
    vendor page URL, read date and the vendor's own `documented_as` words; an unconfirmed
    mapping is `unverified` with a note and no source. The first declared domain is the
    official site's host; a product page and a mapping source must be on a company domain.
  * Framework items are cited and checkable. A CSF 2.0 Function / CIS v8.1 Control id and
    name must match the framework; every CSF / CIS entry names at least one Subcategory /
    Safeguard, and each item is checked for existence: a CSF Subcategory against the exact set
    of active CSF 2.0 Subcategory ids in its Category (a withdrawn 1.1 id such as DE.CM-04 is
    rejected) and a CIS Safeguard against its Control's Safeguard count (both tables sourced
    from the framework docs below, not from memory); D3FEND ids are checked against the pinned
    1.6.0 release with a full/part scope.
  * Wording filter. A word list, not a claim checker: it fails ranking and marketing words
    and the unsourced security words "vulnerable", "breached", "insecure", "hacked" and
    "compromised" in free text, and em dashes, backticks, Markdown links and HTML.

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
SCHEMA_VERSION = 3
MIN_READ = "2015-01-01"   # a read_date before this is a mistake, not a real read


def _today():
    return _dt.datetime.now(_dt.timezone.utc).date().isoformat()


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
COMPANY_STATUS = ("public", "private", "pe-owned", "acquired", "public-controlled", "defunct")
STATUS_NEEDS_HOLDER = ("pe-owned", "acquired", "public-controlled")
STATUS_NEEDS_SINCE = ("pe-owned", "acquired")
PRODUCT_STATUS = ("current", "renamed", "eol", "discontinued")
STAKE_VALUES = ("majority", "full")

CSF_FUNCTIONS = {"GV": "Govern", "ID": "Identify", "PR": "Protect",
                 "DE": "Detect", "RS": "Respond", "RC": "Recover"}
# The exact set of ACTIVE NIST CSF 2.0 Subcategory ids, by Category. A Subcategory id is
# <Category>-NN; its Category must be one of these, it must sit under the cited Function, and
# NN must be in the Category's set. Derived from the NIST CSF 2.0 Reference Tool export (the
# .xlsx served by csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all,
# fetched 2026-11-25) by reading the "Subcategory" column and dropping every row whose text
# begins "[Withdrawn: Incorporated into ...]". That export keeps the 79 Subcategories CSF 2.0
# withdrew from CSF 1.1 (e.g. ID.AM-06, PR.AT-03/04/05, the PR.DS-03..08 block, DE.CM-04/05/07/08,
# DE.AE-01/05, RS.AN-01/02/04/05, RS.CO-01/04/05, RS.MI-03, RC.CO-01/02, and every PR.AC/PR.IP/
# DE.DP/... Category that 2.0 dropped); holding counts would accept those, so we hold the exact
# ids. The active total is 106 across 22 Categories (see the self-test). The numbers are NOT
# contiguous: ID.AM skips 06, PR.AT keeps only 01-02, PR.DS keeps 01, 02, 10, 11, DE.CM keeps
# 01, 02, 03, 06, 09, DE.AE keeps 02-04 and 06-08, RS.AN keeps 03 and 06-08, RS.CO keeps 02-03,
# RS.MI keeps 01-02, RC.CO keeps 03-04. RS.MA is a Category new in 2.0.
CSF_SUBCATEGORIES = {
    "GV.OC": frozenset({"01", "02", "03", "04", "05"}),
    "GV.RM": frozenset({"01", "02", "03", "04", "05", "06", "07"}),
    "GV.RR": frozenset({"01", "02", "03", "04"}),
    "GV.PO": frozenset({"01", "02"}),
    "GV.OV": frozenset({"01", "02", "03"}),
    "GV.SC": frozenset({"01", "02", "03", "04", "05", "06", "07", "08", "09", "10"}),
    "ID.AM": frozenset({"01", "02", "03", "04", "05", "07", "08"}),
    "ID.RA": frozenset({"01", "02", "03", "04", "05", "06", "07", "08", "09", "10"}),
    "ID.IM": frozenset({"01", "02", "03", "04"}),
    "PR.AA": frozenset({"01", "02", "03", "04", "05", "06"}),
    "PR.AT": frozenset({"01", "02"}),
    "PR.DS": frozenset({"01", "02", "10", "11"}),
    "PR.PS": frozenset({"01", "02", "03", "04", "05", "06"}),
    "PR.IR": frozenset({"01", "02", "03", "04"}),
    "DE.CM": frozenset({"01", "02", "03", "06", "09"}),
    "DE.AE": frozenset({"02", "03", "04", "06", "07", "08"}),
    "RS.MA": frozenset({"01", "02", "03", "04", "05"}),
    "RS.AN": frozenset({"03", "06", "07", "08"}),
    "RS.CO": frozenset({"02", "03"}),
    "RS.MI": frozenset({"01", "02"}),
    "RC.RP": frozenset({"01", "02", "03", "04", "05", "06"}),
    "RC.CO": frozenset({"03", "04"}),
}
CSF_CATEGORIES = frozenset(CSF_SUBCATEGORIES)
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
# Number of Safeguards in each CIS Controls v8.1 Control, from the CIS Controls Navigator
# v8.1 (cisecurity.org/controls/cis-controls-navigator, fetched 2026-11-25). Safeguards are
# numbered contiguously 1..N within a Control, so a Safeguard N.M is valid iff 1 <= M <= N.
CIS_SAFEGUARD_COUNTS = {
    "1": 5, "2": 7, "3": 14, "4": 12, "5": 6, "6": 8, "7": 7, "8": 12, "9": 7,
    "10": 7, "11": 5, "12": 8, "13": 11, "14": 9, "15": 7, "16": 14, "17": 9, "18": 5,
}

# A regulator's domain may host a company's status source (filings).
REGULATOR_DOMAINS = ("sec.gov",)
# Hosts that are never a vendor's own site; they may not be declared as a company domain.
DENY_DOMAINS = ("wikipedia.org", "reddit.com", "medium.com", "facebook.com", "twitter.com",
                "x.com", "linkedin.com", "youtube.com", "crunchbase.com", "github.io")

CAP_FIELDS = frozenset(("id", "name", "category", "definition", "synonyms", "components",
                        "related", "frameworks", "library_refs", "reviewed_at"))
COMPANY_FIELDS = frozenset(("id", "name", "former_names", "status", "stake", "holder",
                            "holder_name", "ownership_since", "ticker", "announced_acquisition",
                            "domains", "holder_domains", "official_url", "note", "sources",
                            "reviewed_at"))
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
# An unverified note may use a "confirm" word only inside one of these negated phrases; every
# other use is read as an affirmative claim and rejected. The negation must govern the word
# itself, in the phrase - a negation earlier in the sentence ("Not reviewed. Confirmed ...")
# does not count. Matching phrases are blanked out, then any surviving "confirm" fails.
CONFIRM_RE = re.compile(r"(?<![a-z])confirm")
CONFIRM_NEGATED_RE = re.compile(
    r"\b(?:not\s+(?:yet\s+)?confirmed"
    r"|could\s+not\s+confirm"
    r"|cannot\s+confirm"
    r"|can\s*not\s+confirm"
    r"|unable\s+to\s+confirm"
    r"|no\s+confirmation"
    r"|without\s+confirming"
    r"|unconfirmed"
    r"|confirmation\s+pending)\b"
)
URL_BAD_RE = re.compile(r"""[\s<>\[\]()"'`\\]""")
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
    return _valid_date(s) and s <= _today()


def _valid_read(s):
    return _valid_date(s) and MIN_READ <= s <= _today()


def _valid_since(s):
    if not (isinstance(s, str) and SINCE_RE.match(s)):
        return False
    full = s + "-01-01" if len(s) == 4 else (s + "-01" if len(s) == 7 else s)
    return _valid_date(full) and "1990" <= s <= _today()


def _host(url):
    if not isinstance(url, str) or URL_BAD_RE.search(url) or "javascript:" in url.lower():
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname or "@" in (parts.netloc or ""):
        return None
    host = parts.hostname
    if not host.isascii() or not DOMAIN_RE.match(host):
        return None
    return host.lower()


def _host_in(url, domains):
    h = _host(url)
    return h is not None and any(h == d or h.endswith("." + d) for d in domains)


def _bad_text(s):
    return ("|" in s or "\n" in s or "\r" in s or "`" in s or "](" in s
            or re.search(r"<[^>]+>", s) is not None)


def _text_problems(where, text, errors):
    if not isinstance(text, str):
        return
    if EM_DASH in text:
        errors.append(f"{where}: contains an em dash (use a hyphen; docs/VOICE.md)")
    if _bad_text(text):
        errors.append(f"{where}: contains a pipe, newline, backtick, Markdown link or HTML tag")
    m = BANNED_RE.search(text)
    if m:
        errors.append(f"{where}: wording-filter word {m.group(0)!r} (this is a word filter, not a "
                      f"verified claim)")


def _source_entry(where, key, val, domains, errors):
    if not isinstance(val, dict) or set(val.keys()) != {"url", "read_date"}:
        errors.append(f"{where}: source {key!r} must be an object with exactly url and read_date")
        return None
    h = _host(val["url"])
    if h is None:
        errors.append(f"{where}: source {key!r} url must be a clean https URL (no spaces, brackets, "
                      f"credentials, javascript or non-ASCII host)")
    elif domains is not None and not _host_in(val["url"], domains):
        errors.append(f"{where}: source {key!r} url host is not one of the allowed domains {sorted(domains)}")
    if not _valid_read(val["read_date"]):
        errors.append(f"{where}: source {key!r} read_date must be a real date in [{MIN_READ}, {_today()}]")
    return h


# ----------------------------------------------------------------------------- the build

def validate(src: dict) -> dict:
    errors: list[str] = []
    vocab_vendors = src["vocab_vendors"]
    vocab_products = src["vocab_products"]
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
        seen_terms = {}
        for f in ("synonyms", "components", "related"):
            if not isinstance(r[f], list) or not all(isinstance(x, str) and x.strip() for x in r[f]):
                errors.append(f"{where}: {f} must be a list of non-empty strings")
                continue
            for term in r[f]:
                _text_problems(f"{where} {f}", term, errors)
                key = term.strip().casefold()
                if key == (r["name"] or "").strip().casefold():
                    errors.append(f"{where}: {f} repeats the capability's own name {term!r}")
                if key in seen_terms and seen_terms[key] != f:
                    errors.append(f"{where}: term {term!r} is in both {seen_terms[key]} and {f}")
                seen_terms[key] = f
        if not isinstance(r["frameworks"], list):
            errors.append(f"{where}: frameworks must be a list")
        else:
            fw_seen = set()
            for fr in r["frameworks"]:
                key = _framework_problems(where, fr, d3fend, errors)
                if key is not None:
                    if key in fw_seen:
                        errors.append(f"{where}: framework entry {key} appears twice")
                    fw_seen.add(key)
        if not _str_list(r["library_refs"]):
            errors.append(f"{where}: library_refs must be a list of non-empty strings")
        else:
            for p in r["library_refs"]:
                if not exists(p):
                    errors.append(f"{where}: library_ref {p!r} is not a repository file")
        if not _valid_read(r["reviewed_at"]):
            errors.append(f"{where}: reviewed_at must be a real date in [{MIN_READ}, {_today()}]")

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
        if r["note"] is not None:
            if not _is_str(r["note"]):
                errors.append(f"{where}: note must be null or a non-empty string")
            else:
                _text_problems(f"{where} note", r["note"], errors)
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
        for d in domains + holder_domains:
            if any(d == bad or d.endswith("." + bad) for bad in DENY_DOMAINS):
                errors.append(f"{where}: {d!r} is not a vendor domain and may not be declared")
        official_host = _host(r["official_url"])
        if official_host is None:
            errors.append(f"{where}: official_url must be a clean https URL")
        elif domains and not _host_in(r["official_url"], domains):
            errors.append(f"{where}: official_url host is not one of domains {sorted(domains)}")
        if domains and official_host is not None and not (
                domains[0] == official_host or official_host.endswith("." + domains[0])):
            errors.append(f"{where}: the first domain must be the official_url host ({official_host})")
        # status + ownership
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
        if holder_domains and holder is None and holder_name is None:
            errors.append(f"{where}: holder_domains needs a holder or holder_name (the status names none)")
        if st in STATUS_NEEDS_SINCE and r["ownership_since"] is None:
            errors.append(f"{where}: status {st} needs ownership_since")
        if st == "public" and r["ownership_since"] is not None:
            errors.append(f"{where}: a public company must not carry ownership_since")
        if r["ownership_since"] is not None and not _valid_since(r["ownership_since"]):
            errors.append(f"{where}: ownership_since must be a real past date (YYYY, YYYY-MM or YYYY-MM-DD)")
        # stake
        stake = r["stake"]
        if stake is not None and stake not in STAKE_VALUES:
            errors.append(f"{where}: stake must be null, 'majority' or 'full'")
        if st == "acquired" and stake not in STAKE_VALUES:
            errors.append(f"{where}: an acquired company needs stake 'majority' or 'full'")
        if st in ("public", "private") and stake is not None:
            errors.append(f"{where}: a {st} company must not carry a stake")
        # ticker
        if st == "private" and r["ticker"] is not None:
            errors.append(f"{where}: a private company must not carry a ticker")
        if r["ticker"] is not None:
            _text_problems(f"{where} ticker", r["ticker"], errors)
        # announced acquisition
        aa_host = None
        aa = r["announced_acquisition"]
        if aa is not None:
            if not isinstance(aa, dict) or set(aa.keys()) != {"acquirer", "acquirer_name",
                                                              "announced_date", "source"}:
                errors.append(f"{where}: announced_acquisition needs acquirer, acquirer_name, "
                              f"announced_date, source")
            else:
                if aa["acquirer"] is not None:
                    if not (_is_str(aa["acquirer"]) and VENDOR_ID_RE.match(aa["acquirer"])):
                        errors.append(f"{where}: announced_acquisition.acquirer must be null or a vendor id")
                    elif aa["acquirer"] == cid:
                        errors.append(f"{where}: announced_acquisition.acquirer must not be the company itself")
                if not _is_str(aa["acquirer_name"]):
                    errors.append(f"{where}: announced_acquisition.acquirer_name is required")
                if not _valid_read(aa["announced_date"]):
                    errors.append(f"{where}: announced_acquisition.announced_date must be a real recent date")
                aa_host = _source_entry(f"{where} announced_acquisition", "source", aa.get("source"),
                                        (domains + holder_domains) or None, errors)
        # sources
        used_hosts = set()
        if official_host:
            used_hosts.add(official_host)
        if aa_host:
            used_hosts.add(aa_host)
        if not isinstance(r["sources"], dict):
            errors.append(f"{where}: sources must be an object")
        else:
            for k, v in r["sources"].items():
                if k not in COMPANY_SOURCE_KEYS:
                    errors.append(f"{where}: source key {k!r} is not one of {sorted(COMPANY_SOURCE_KEYS)}")
                    continue
                if k in ("status", "ownership_since"):
                    allowed = (domains + holder_domains + list(REGULATOR_DOMAINS)) or None
                else:
                    allowed = domains or None
                h = _source_entry(where, k, v, allowed, errors)
                if h:
                    used_hosts.add(h)
            if "status" not in r["sources"]:
                errors.append(f"{where}: every company needs a status source")
            if r["former_names"] and "former_names" not in r["sources"]:
                errors.append(f"{where}: former_names present but not sourced")
        # each further declared domain must be justified by something in the record
        for d in domains[1:]:
            if not any(h == d or h.endswith("." + d) for h in used_hosts):
                errors.append(f"{where}: declared domain {d!r} is used by no URL in the record")
        for d in holder_domains:
            if not any(h == d or h.endswith("." + d) for h in used_hosts):
                errors.append(f"{where}: holder_domain {d!r} is used by no source in the record")
        if not _valid_read(r["reviewed_at"]):
            errors.append(f"{where}: reviewed_at must be a real date in [{MIN_READ}, {_today()}]")

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
            errors.append(f"{where}: id is a vocabulary product, so vocab_product must equal it")
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
            errors.append(f"{where}: platform is required")
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
        if not _valid_read(r["reviewed_at"]):
            errors.append(f"{where}: reviewed_at must be a real date in [{MIN_READ}, {_today()}]")

    for cid in sorted(company_ids):
        if cid not in companies_with_product:
            errors.append(f"{COMPANIES} {cid!r}: company has no product in {PRODUCTS}")

    if errors:
        raise InventoryError("\n".join(errors))
    return {"caps": cap_ids, "companies": company_ids, "products": product_ids}


def _framework_problems(where, fr, d3fend, errors):
    if not isinstance(fr, dict) or "framework" not in fr:
        errors.append(f"{where}: each framework entry must be an object with a framework key")
        return None
    fw = fr["framework"]
    if fw in ("nist-csf-2.0", "cis-controls-v8.1"):
        if set(fr.keys()) != {"framework", "ref", "name", "items", "source_url", "read_date"}:
            errors.append(f"{where}: {fw} entry needs framework, ref, name, items, source_url, read_date")
            return None
        table = CSF_FUNCTIONS if fw == "nist-csf-2.0" else CIS_CONTROLS
        if fr["ref"] not in table:
            errors.append(f"{where}: {fw} ref {fr['ref']!r} is not a valid id")
        elif fr["name"] != table[fr["ref"]]:
            errors.append(f"{where}: {fw} {fr['ref']} name must be {table[fr['ref']]!r}")
        if not isinstance(fr["items"], list) or not fr["items"] \
                or not all(isinstance(x, str) for x in fr["items"]):
            errors.append(f"{where}: {fw} items must be a non-empty list of strings "
                          f"(name the Subcategory/Safeguard, or drop the mapping)")
        else:
            for it in fr["items"]:
                if fw == "nist-csf-2.0":
                    if not CSF_ITEM_RE.match(it):
                        errors.append(f"{where}: CSF item {it!r} is not shaped like PR.AA-05")
                        continue
                    cat, _, num = it.rpartition("-")
                    if cat.split(".")[0] != fr["ref"]:
                        errors.append(f"{where}: CSF item {it!r} is not under Function {fr['ref']}")
                    elif cat not in CSF_SUBCATEGORIES:
                        errors.append(f"{where}: CSF item {it!r} names no active CSF 2.0 Category")
                    elif num not in CSF_SUBCATEGORIES[cat]:
                        errors.append(f"{where}: CSF item {it!r} is not an active CSF 2.0 Subcategory "
                                      f"of {cat} (it was withdrawn or never existed)")
                else:
                    if not CIS_ITEM_RE.match(it):
                        errors.append(f"{where}: CIS item {it!r} is not shaped like 13.7")
                        continue
                    control, _, num = it.partition(".")
                    if control != fr["ref"]:
                        errors.append(f"{where}: CIS item {it!r} is not under Control {fr['ref']}")
                    elif not (1 <= int(num) <= CIS_SAFEGUARD_COUNTS.get(control, 0)):
                        errors.append(f"{where}: CIS item {it!r} is not a Safeguard of Control {control} "
                                      f"(1-{CIS_SAFEGUARD_COUNTS.get(control, 0)})")
        if _host(fr["source_url"]) is None:
            errors.append(f"{where}: {fw} source_url must be a clean https URL")
        if not _valid_read(fr["read_date"]):
            errors.append(f"{where}: {fw} read_date must be a real date in [{MIN_READ}, {_today()}]")
        return (fw, fr.get("ref"))
    elif fw == "d3fend-1.6.0":
        if set(fr.keys()) != {"framework", "ref", "name", "scope", "dataset"}:
            errors.append(f"{where}: d3fend-1.6.0 entry needs framework, ref, name, scope, dataset")
            return None
        if fr["dataset"] != D3FEND:
            errors.append(f"{where}: d3fend dataset must be {D3FEND!r}")
        if fr["ref"] not in d3fend:
            errors.append(f"{where}: D3FEND ref {fr['ref']!r} is not in the pinned 1.6.0 release")
        elif fr["name"] != d3fend[fr["ref"]]:
            errors.append(f"{where}: D3FEND {fr['ref']} name must be {d3fend[fr['ref']]!r}")
        if fr["scope"] not in ("full", "part"):
            errors.append(f"{where}: d3fend scope must be 'full' or 'part'")
        return (fw, fr.get("ref"))
    else:
        errors.append(f"{where}: framework {fw!r} must be nist-csf-2.0, cis-controls-v8.1 or d3fend-1.6.0")
        return None


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
        allowed = {"capability_id", "status", "documented_as", "source_url", "read_date", "note"}
        required = {"capability_id", "status", "documented_as", "source_url", "read_date"}
        if not (set(m.keys()) <= allowed and required <= set(m.keys())):
            errors.append(f"{where} {cap}: a documented mapping needs capability_id, status, "
                          f"documented_as, source_url, read_date (and an optional note)")
            return
        if not _is_str(m["documented_as"]):
            errors.append(f"{where} {cap}: documented_as (the vendor's own words on the page) is required")
        else:
            _text_problems(f"{where} {cap} documented_as", m["documented_as"], errors)
        if "note" in m:
            if not _is_str(m["note"]):
                errors.append(f"{where} {cap}: note must be a non-empty string")
            else:
                _text_problems(f"{where} {cap} note", m["note"], errors)
        if _host(m["source_url"]) is None:
            errors.append(f"{where} {cap}: source_url must be a clean https URL")
        elif comp_domains and not _host_in(m["source_url"], comp_domains):
            errors.append(f"{where} {cap}: source_url host is not the company's domain")
        if not _valid_read(m["read_date"]):
            errors.append(f"{where} {cap}: read_date must be a real date in [{MIN_READ}, {_today()}]")
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
            # Reject an AFFIRMATIVE confirmation claim. A "confirm" word is allowed only as part
            # of one of the negated phrases (blank those out first); any that survives is a claim.
            if CONFIRM_RE.search(CONFIRM_NEGATED_RE.sub(" ", low)):
                errors.append(f"{where} {cap}: an unverified note must not claim the capability was "
                              f"confirmed (only a negated phrase such as 'not confirmed' is allowed)")
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
            (doc_by_cap if m["status"] == "documented" else unv_by_cap).setdefault(
                m["capability_id"], []).append(pid)

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
        "status": companies[cid]["status"], "stake": companies[cid]["stake"],
        "holder": companies[cid]["holder"], "holder_name": companies[cid]["holder_name"],
        "ownership_since": companies[cid]["ownership_since"], "ticker": companies[cid]["ticker"],
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
    FUT = "2099-01-01"
    d3fend = {"D3-MFA": "Multi-factor Authentication", "D3-EF": "Email Filtering"}

    def base_cap(**over):
        r = {"id": "capability:edr", "name": "Endpoint Detection and Response",
             "category": "endpoint-xdr", "definition": "Recording endpoint activity for detection.",
             "synonyms": ["EDR"], "components": [], "related": [],
             "frameworks": [{"framework": "nist-csf-2.0", "ref": "DE", "name": "Detect",
                             "items": ["DE.CM-09"], "source_url": "https://doi.org/10.6028/NIST.CSWP.29",
                             "read_date": RD},
                            {"framework": "cis-controls-v8.1", "ref": "13",
                             "name": "Network Monitoring and Defense", "items": ["13.7", "13.2"],
                             "source_url": "https://www.cisecurity.org/controls/cis-controls-list",
                             "read_date": RD}],
             "library_refs": ["platforms/README.md"], "reviewed_at": RD}
        r.update(over)
        return r

    def base_company(**over):
        r = {"id": "vendor:crowdstrike", "name": "CrowdStrike", "former_names": [],
             "status": "public", "stake": None, "holder": None, "holder_name": None,
             "ownership_since": None, "ticker": "NASDAQ: CRWD", "announced_acquisition": None,
             "domains": ["crowdstrike.com"], "holder_domains": [], "note": None,
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
            "d3fend": d3fend, "exists": lambda rel: rel == "platforms/README.md",
        }

    try:
        validate(src()); ok = True
    except InventoryError as e:
        ok = False; print("baseline error:\n" + str(e))
    expect("clean baseline validates", ok)

    def fw(frs):
        return base_cap(frameworks=frs)

    CSF = "https://doi.org/10.6028/NIST.CSWP.29"
    CIS = "https://www.cisecurity.org/controls/cis-controls-list"

    def fails_with(fragment, **kw):
        try:
            validate(src(**kw))
        except InventoryError as e:
            return fragment in str(e)
        return False

    def validates(**kw):
        try:
            validate(src(**kw))
            return True
        except InventoryError as e:
            print("unexpected error (expected clean):\n" + str(e))
            return False

    def unverified(note):
        return [base_product(capabilities=[{"capability_id": "capability:edr",
                                            "status": "unverified", "note": note}])]

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
    expect("C08 unverified mapping with extra keys", fails_with("carries capability_id, status and note",
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
           capabilities=[{"capability_id": "capability:edr", "status": "unverified", "note": "see https://x.com/y"}])]))
    expect("C14 unverified note claims confirmed", fails_with("must not claim the capability was",
           products=[base_product(capabilities=[{"capability_id": "capability:edr", "status": "unverified",
                                                  "note": "confirmed on a blog"}])]))
    expect("C15 CSF name mismatch", fails_with("name must be 'Detect'",
           caps=[fw([{"framework": "nist-csf-2.0", "ref": "DE", "name": "Protect", "items": ["DE.CM-09"],
                      "source_url": CSF, "read_date": RD}])]))
    expect("C16 CIS title mismatch", fails_with("name must be",
           caps=[fw([{"framework": "cis-controls-v8.1", "ref": "10", "name": "Data Recovery", "items": ["10.1"],
                      "source_url": CIS, "read_date": RD}])]))
    expect("C17 CIS item not under control", fails_with("is not under Control",
           caps=[fw([{"framework": "cis-controls-v8.1", "ref": "13", "name": "Network Monitoring and Defense",
                      "items": ["9.3"], "source_url": CIS, "read_date": RD}])]))
    expect("C18 CSF subcategory not under function", fails_with("is not under Function",
           caps=[fw([{"framework": "nist-csf-2.0", "ref": "DE", "name": "Detect", "items": ["PR.AA-05"],
                      "source_url": CSF, "read_date": RD}])]))
    expect("C19 D3FEND ref not pinned", fails_with("not in the pinned 1.6.0 release",
           caps=[fw([{"framework": "d3fend-1.6.0", "ref": "D3-NOPE", "name": "X", "scope": "part",
                      "dataset": D3FEND}])]))
    expect("C20 D3FEND scope bad", fails_with("scope must be",
           caps=[fw([{"framework": "d3fend-1.6.0", "ref": "D3-MFA", "name": "Multi-factor Authentication",
                      "scope": "most", "dataset": D3FEND}])]))
    expect("C21 ranking word", fails_with("wording-filter word", caps=[base_cap(definition="The leading tool.")]))
    expect("C22 unsourced insecure claim", fails_with("wording-filter word",
           caps=[base_cap(definition="Finds insecure hosts.")]))
    expect("C23 em dash", fails_with("em dash", caps=[base_cap(definition="Endpoint detection \u2014 response.")]))
    expect("C24 HTML in name", fails_with("pipe, newline", products=[base_product(name="Falcon <b>Cloud</b>")]))
    expect("C25 public company names a holder", fails_with("must not name a holder",
           companies=[base_company(holder_name="Someone")]))
    expect("C26 acquired without holder", fails_with("needs a holder", companies=[base_company(
           status="acquired", stake="full", ownership_since="2024-03-18", ticker=None, holder_domains=["cisco.com"],
           sources={"status": {"url": "https://newsroom.cisco.com/x", "read_date": RD}})]))
    expect("C27 acquired without ownership_since", fails_with("needs ownership_since", companies=[base_company(
           status="acquired", stake="full", holder_name="Cisco", ticker=None, holder_domains=["cisco.com"],
           sources={"status": {"url": "https://newsroom.cisco.com/x", "read_date": RD}})]))
    expect("C28 future ownership_since", fails_with("real past date", companies=[base_company(
           status="acquired", stake="full", holder_name="Acquirer", holder_domains=["acquirer.com"], ticker=None,
           ownership_since=FUT, sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": RD}})]))
    expect("C29 status not sourced", fails_with("needs a status source", companies=[base_company(sources={})]))
    expect("C30 status source off-domain", fails_with("host is not", companies=[base_company(
           sources={"status": {"url": "https://reseller.example.com/x", "read_date": RD}})]))
    expect("C31 impossible date", fails_with("real date", companies=[base_company(
           sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": "2026-13-45"}})]))
    expect("C32 future read_date", fails_with("real date", companies=[base_company(
           sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": FUT}})]))
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
    # round-2 additions
    expect("C44 empty CSF items", fails_with("non-empty list", caps=[fw([
           {"framework": "nist-csf-2.0", "ref": "DE", "name": "Detect", "items": [],
            "source_url": CSF, "read_date": RD}])]))
    expect("C45 made-up CSF category", fails_with("names no active CSF 2.0 Category", caps=[fw([
           {"framework": "nist-csf-2.0", "ref": "PR", "name": "Protect", "items": ["PR.ZZ-99"],
            "source_url": CSF, "read_date": RD}])]))
    expect("C46 CIS safeguard out of range", fails_with("is not a Safeguard of Control 13", caps=[fw([
           {"framework": "cis-controls-v8.1", "ref": "13", "name": "Network Monitoring and Defense",
            "items": ["13.99"], "source_url": CIS, "read_date": RD}])]))
    expect("C47 duplicate framework entry", fails_with("appears twice", caps=[base_cap(frameworks=[
           {"framework": "cis-controls-v8.1", "ref": "13", "name": "Network Monitoring and Defense",
            "items": ["13.7"], "source_url": CIS, "read_date": RD},
           {"framework": "cis-controls-v8.1", "ref": "13", "name": "Network Monitoring and Defense",
            "items": ["13.2"], "source_url": CIS, "read_date": RD}])]))
    expect("C48 markdown link in documented_as", fails_with("Markdown link", products=[base_product(
           capabilities=[{"capability_id": "capability:edr", "status": "documented",
                          "documented_as": "[click](https://x.crowdstrike.com/)",
                          "source_url": "https://www.crowdstrike.com/a", "read_date": RD}])]))
    expect("C49 backtick in platform", fails_with("backtick", products=[base_product(platform="Falcon `x`")]))
    expect("C50 javascript in url", fails_with("clean https URL", products=[base_product(
           official_url="https://www.crowdstrike.com/)](javascript:alert(1)")]))
    expect("C51 denylisted domain declared", fails_with("not a vendor domain", companies=[base_company(
           domains=["crowdstrike.com", "wikipedia.org"])]))
    expect("C52 first domain not official host", fails_with("first domain must be the official",
           companies=[base_company(domains=["example.com", "crowdstrike.com"])]))
    expect("C53 unjustified holder_domain", fails_with("used by no source", companies=[base_company(
           status="acquired", stake="full", holder_name="Cisco", ownership_since="2024-03-18", ticker=None,
           holder_domains=["cisco.com"],
           sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": RD}})]))
    expect("C54 announced acquirer is self", fails_with("must not be the company itself",
           companies=[base_company(announced_acquisition={"acquirer": "vendor:crowdstrike",
                      "acquirer_name": "CrowdStrike", "announced_date": RD,
                      "source": {"url": "https://www.crowdstrike.com/press", "read_date": RD}})]))
    expect("C55 private with a ticker", fails_with("must not carry a ticker", companies=[base_company(
           status="private", ticker="NASDAQ: X", holder=None, holder_name=None,
           sources={"status": {"url": "https://www.crowdstrike.com/about", "read_date": RD}})]))
    expect("C56 public with ownership_since", fails_with("must not carry ownership_since",
           companies=[base_company(ownership_since="2020-01-01")]))
    expect("C57 acquired without stake", fails_with("needs stake", companies=[base_company(
           status="acquired", holder_name="Cisco", ownership_since="2024-03-18", ticker=None,
           holder_domains=["cisco.com"],
           sources={"status": {"url": "https://newsroom.cisco.com/x", "read_date": RD}})]))
    expect("C58 public with a stake", fails_with("must not carry a stake", companies=[base_company(stake="full")]))
    expect("C59 read_date before floor", fails_with("real date", companies=[base_company(
           sources={"status": {"url": "https://ir.crowdstrike.com/", "read_date": "1999-01-01"}})]))
    expect("C60 term in two lists", fails_with("is in both", caps=[base_cap(
           synonyms=["EDR", "telemetry"], components=["telemetry"])]))
    expect("C61 synonym repeats the name", fails_with("repeats the capability's own name",
           caps=[base_cap(synonyms=["Endpoint Detection and Response"])]))
    expect("C62 holder_domains without a holder", fails_with("holder_domains needs a holder",
           companies=[base_company(status="private", ticker=None, holder=None, holder_name=None,
                      holder_domains=["blog.example.com"],
                      sources={"status": {"url": "https://blog.example.com/x", "read_date": RD}})]))
    # framework items that are well-shaped and under the right Function/Control but do not exist
    expect("C63 CSF subcategory number too high (PR.AA-99)",
           fails_with("is not an active CSF 2.0 Subcategory of PR.AA", caps=[fw([
           {"framework": "nist-csf-2.0", "ref": "PR", "name": "Protect", "items": ["PR.AA-99"],
            "source_url": CSF, "read_date": RD}])]))
    expect("C64 CSF subcategory number too high (PR.PS-99)",
           fails_with("is not an active CSF 2.0 Subcategory of PR.PS", caps=[fw([
           {"framework": "nist-csf-2.0", "ref": "PR", "name": "Protect", "items": ["PR.PS-99"],
            "source_url": CSF, "read_date": RD}])]))
    expect("C65 CIS safeguard past its control's count (10.18)",
           fails_with("is not a Safeguard of Control 10", caps=[fw([
           {"framework": "cis-controls-v8.1", "ref": "10", "name": "Malware Defenses",
            "items": ["10.18"], "source_url": CIS, "read_date": RD}])]))
    expect("C66 CIS safeguard past its control's count (13.12)",
           fails_with("is not a Safeguard of Control 13", caps=[fw([
           {"framework": "cis-controls-v8.1", "ref": "13", "name": "Network Monitoring and Defense",
            "items": ["13.12"], "source_url": CIS, "read_date": RD}])]))

    # --- A1: CSF 2.0 withdrew these from 1.1; the exact-set check must reject them ...
    def csf_item(it):
        fn = it.split(".")[0]
        return fw([{"framework": "nist-csf-2.0", "ref": fn, "name": CSF_FUNCTIONS[fn],
                    "items": [it], "source_url": CSF, "read_date": RD}])
    for n, it in enumerate(["ID.AM-06", "PR.AT-03", "PR.DS-05", "DE.CM-04", "DE.AE-01",
                            "RS.AN-01", "RS.CO-01", "RS.MI-03", "RC.CO-01"], start=67):
        expect(f"C{n} withdrawn CSF id {it} rejected",
               fails_with("is not an active CSF 2.0 Subcategory", caps=[csf_item(it)]))
    # ... and keep accepting their still-active neighbours.
    for n, it in enumerate(["DE.CM-09", "PR.DS-10", "RS.AN-03", "RC.CO-03"], start=76):
        expect(f"C{n} active CSF id {it} passes", validates(caps=[csf_item(it)]))
    # the accepted CSF set is exactly the 106 active 2.0 Subcategories
    expect("C80 CSF accepted set totals 106",
           sum(len(v) for v in CSF_SUBCATEGORIES.values()) == 106)

    # --- A2: a "confirm" word is allowed in an unverified note only inside a negated phrase.
    NOTE_CASES = [
        ("Not reviewed. Confirmed on the vendor page.", False),
        ("Not only documented but confirmed by the vendor.", False),
        ("No doubt this is confirmed.", False),
        ("The vendor did not reply; a reseller confirmed it.", False),
        ("This is confirmed.", False),
        ("Not confirmed on the vendor page.", True),
        ("Could not confirm this capability from vendor documentation.", True),
        ("Unconfirmed on the vendor page.", True),
        ("No confirmation found on the vendor page.", True),
        ("Listed by a reseller, not the vendor; confirmation pending.", True),
    ]
    for n, (note, ok) in enumerate(NOTE_CASES, start=81):
        if ok:
            expect(f"C{n} note passes: {note[:34]!r}", validates(products=unverified(note)))
        else:
            expect(f"C{n} note fails: {note[:34]!r}",
                   fails_with("must not claim the capability was", products=unverified(note)))

    if fails:
        print("SELF-TEST FAILED: " + "; ".join(fails))
        return 1
    print("OK: build_inventory self-test (90 controls: schema, ids, vocab/d3fend/csf/cis "
          "cross-refs and item placement, framework items checked for existence against the exact "
          "active CSF 2.0 Subcategory set (withdrawn 1.1 ids rejected, active neighbours pass, 106 "
          "total) and the CIS Safeguard count per Control, non-empty framework items, per-fact "
          "sourcing, vendor-domain + first-domain + holder-domain rules, dates with floor, ownership "
          "model with stake, unverified-vs-documented incl. negated-phrase confirm rule, neutral "
          "wording incl. Markdown/backtick/HTML, duplicates)")
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
