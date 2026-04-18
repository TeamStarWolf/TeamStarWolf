#!/usr/bin/env python3
"""
Build a unified library index from the TeamStarWolf-profile catalogues.

Inputs (in the profile repo root):
  - "Starred GitHub Repositories.md"  → tools / repos
  - "YouTube Channels.md"             → channels
  - "X Account Lists.md"              → accounts
  - "Cybersecurity Research.md"       → books / learning resources

Output:
  - research/data/library.json        — single JSON consumed by the explorer site

Schema: see Asset / Library types below. One asset per entry, normalized.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

PROFILE_ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = PROFILE_ROOT / "research" / "data" / "library.json"


@dataclass
class Asset:
    """A single library entry — tool, channel, account, book, or research note."""

    id: str
    type: str  # "tool" | "channel" | "x-account" | "book" | "field-note"
    title: str
    url: str
    description: str = ""
    category: str = ""           # primary section heading (e.g. "Threat Intelligence")
    subcategory: str = ""        # secondary heading where present (e.g. "MITRE ATT&CK Core")
    vendor: str = ""             # GitHub owner / org / channel owner / account owner
    handle: str = ""             # for x-accounts and channels
    affiliation: str = ""        # for x-accounts (employer / role)
    attack_tactics: list[str] = field(default_factory=list)  # e.g. ["credential-access","lateral-movement"]
    metadata: dict = field(default_factory=dict)


@dataclass
class Library:
    generated_at: str
    counts: dict[str, int]
    categories: dict[str, list[str]]   # type → list of distinct categories seen
    vendors: dict[str, int]            # vendor → count of assets
    assets: list[Asset]


# --------------------------------------------------------------------------- #
# Parsers — one per source file
# --------------------------------------------------------------------------- #

REPO_LINE = re.compile(r"^\s*-\s*\[([^\]]+)\]\(([^)]+)\)\s*$")
HEADER = re.compile(r"^(#{2,3})\s+(.+?)(?:\s*\((\d+)\))?\s*$")


def parse_starred_repos(text: str) -> Iterable[Asset]:
    """Parse 'Starred GitHub Repositories.md'.

    Structure: ## Section, ### Subsection (count), - [owner/repo](url)
    """
    section = ""
    subsection = ""
    for line in text.splitlines():
        m = HEADER.match(line)
        if m:
            level, title, _ = m.groups()
            if level == "##":
                section = title.strip()
                subsection = ""
            elif level == "###":
                subsection = title.strip()
            continue

        m = REPO_LINE.match(line)
        if not m:
            continue
        slug, url = m.group(1), m.group(2)
        if "github.com" not in url:
            continue
        owner, _, repo = slug.partition("/")
        if not repo:
            continue
        yield Asset(
            id=f"tool:{slug.lower()}",
            type="tool",
            title=slug,
            url=url,
            category=section,
            subcategory=subsection,
            vendor=owner,
            metadata={"repo": repo, "owner": owner},
        )


YT_LINE = re.compile(
    r"^\s*-\s*\*\*([^*]+)\*\*\s*-\s*(https?://www\.youtube\.com/[^\s-]+)\s*-\s*(.+?)\s*$"
)


def parse_youtube_channels(text: str) -> Iterable[Asset]:
    """Parse 'YouTube Channels.md'.

    Structure: ## Section, - **Name** - https://...  - description
    """
    section = ""
    for line in text.splitlines():
        m = HEADER.match(line)
        if m and m.group(1) == "##":
            section = m.group(2).strip()
            continue

        m = YT_LINE.match(line)
        if not m:
            continue
        name, url, desc = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        # Extract handle from URL
        handle = ""
        hm = re.search(r"/@([\w.\-]+)", url)
        if hm:
            handle = "@" + hm.group(1)
        yield Asset(
            id=f"channel:{handle.lower() if handle else url.lower()}",
            type="channel",
            title=name,
            url=url,
            description=desc,
            category=section,
            handle=handle,
            vendor=handle or name,
        )


X_LINE = re.compile(r"^\s*-\s*@([\w_]+)\s*[—\-]\s*(.+?)\s*$")


def parse_x_accounts(text: str) -> Iterable[Asset]:
    """Parse 'X Account Lists.md'.

    Structure: ## Section, - @handle — Display Name (Affiliation)
    """
    section = ""
    for line in text.splitlines():
        m = HEADER.match(line)
        if m and m.group(1) == "##":
            section = m.group(2).strip()
            continue

        m = X_LINE.match(line)
        if not m:
            continue
        handle, rest = m.group(1).strip(), m.group(2).strip()
        # Pull out trailing affiliation in parens, if present
        affiliation = ""
        am = re.match(r"^(.+?)\s*\(([^)]+)\)\s*$", rest)
        if am:
            display, affiliation = am.group(1).strip(), am.group(2).strip()
        else:
            display = rest
        yield Asset(
            id=f"x:@{handle.lower()}",
            type="x-account",
            title=display or f"@{handle}",
            url=f"https://x.com/{handle}",
            description=affiliation,
            category=section,
            handle=f"@{handle}",
            affiliation=affiliation,
            vendor=affiliation or display,
        )


# --------------------------------------------------------------------------- #
# Vendor normalization — collapses obvious variants for cleaner faceting
# --------------------------------------------------------------------------- #

VENDOR_ALIASES = {
    "crowdstrike": "CrowdStrike",
    "microsoft": "Microsoft",
    "mandiant": "Mandiant",
    "googlecloudplatform": "Google Cloud",
    "google": "Google",
    "mitre": "MITRE",
    "mitre-attack": "MITRE",
    "mitre-engenuity": "MITRE",
    "center-for-threat-informed-defense": "MITRE CTID",
    "owasp": "OWASP",
    "elastic": "Elastic",
    "splunk": "Splunk",
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "rapid7": "Rapid7",
    "trustedsec": "TrustedSec",
    "sensepost": "SensePost",
    "trailofbits": "Trail of Bits",
    "bishopfox": "Bishop Fox",
    "specterops": "SpecterOps",
    "cisagov": "CISA",
    "usnistgov": "NIST",
    "redhat": "Red Hat",
    "facebookarchive": "Meta",
    "facebook": "Meta",
    "azure": "Microsoft",
    "microsoftdocs": "Microsoft",
    "microsoftgraph": "Microsoft",
    "azuread": "Microsoft",
    "fortra": "Fortra",
    "snort3": "Cisco Talos",
    "talos-incident-response": "Cisco Talos",
    "cisco-talos": "Cisco Talos",
    "ciscotalos": "Cisco Talos",
}


def normalize_vendor(raw: str) -> str:
    if not raw:
        return ""
    key = raw.strip().lower().replace(" ", "")
    return VENDOR_ALIASES.get(key, raw.strip())


# --------------------------------------------------------------------------- #
# ATT&CK tactic classification — keyword heuristics
# --------------------------------------------------------------------------- #

# Tactic IDs match ATT&CK STIX (TA0043, TA0042, TA0001, ...) but use slugs for
# easier UI/URL handling. Mapping back to TA-IDs is straightforward.
TACTIC_KEYWORDS: dict[str, list[str]] = {
    "reconnaissance": [
        "recon", "osint", "subdomain", "dns enumeration", "scanner", "spider",
        "subfinder", "amass", "harvester", "shodan", "censys", "fingerprint",
        "asset discovery", "external attack surface", "asm",
    ],
    "resource-development": [
        "phishing kit", "evilginx", "gophish", "infrastructure", "c2 setup",
        "domain generation", "typosquat",
    ],
    "initial-access": [
        "phishing", "phish", "exploit kit", "spear", "drive-by", "supply chain",
        "valid account", "credential stuffing", "exposed service",
    ],
    "execution": [
        "command execution", "powershell", "shell", "wmi", "scheduled task",
        "interpreter", "container exec", "user execution",
    ],
    "persistence": [
        "persistence", "startup", "boot", "registry run", "service install",
        "scheduled task", "cron", "rootkit", "implant",
    ],
    "privilege-escalation": [
        "privilege escalation", "privesc", "uac bypass", "sudo", "setuid",
        "kernel exploit", "winpeas", "linpeas", "peass", "privilege",
    ],
    "defense-evasion": [
        "evasion", "obfuscation", "donut", "shellcode loader", "av bypass",
        "edr bypass", "amsi bypass", "etw", "rootkit", "process injection",
        "dll injection", "process hollowing", "unhook",
    ],
    "credential-access": [
        "credential", "kerberos", "kerberoast", "asreproast", "mimikatz",
        "lsass", "ntds", "ntlm", "password crack", "hash", "hashcat", "john the ripper",
        "secrets", "vault dump", "dpapi", "keepass", "bloodhound",
    ],
    "discovery": [
        "discovery", "enumeration", "enum4linux", "ldap", "active directory",
        "domain enumeration", "share enumeration", "smb scan",
    ],
    "lateral-movement": [
        "lateral movement", "psexec", "wmiexec", "smbexec", "winrm", "ssh hop",
        "pivot", "rdp", "pass the hash", "pass the ticket", "overpass",
    ],
    "collection": [
        "collection", "screen capture", "keylogger", "audio capture",
        "clipboard", "browser data", "email harvest",
    ],
    "command-and-control": [
        "c2", "command and control", "beacon", "implant", "rat", "covenant",
        "metasploit", "sliver", "havoc", "mythic", "empire", "cobalt strike",
        "merlin", "nimplant", "caldera",
    ],
    "exfiltration": [
        "exfiltration", "exfil", "data staging", "dns tunneling", "icmp tunnel",
        "stego", "steganography",
    ],
    "impact": [
        "ransomware", "wiper", "destructive", "ddos", "defacement", "encryption attack",
        "denial of service", "disk wipe",
    ],
}

# Map bulk asset categories to tactic sets. Matches whole category strings (case-insensitive substring).
CATEGORY_TACTIC_MAP: dict[str, list[str]] = {
    # tools
    "active directory": ["credential-access", "discovery", "lateral-movement", "privilege-escalation"],
    "post-exploitation": ["execution", "persistence", "command-and-control"],
    "command and control": ["command-and-control"],
    "command-and-control": ["command-and-control"],
    "malware analysis": ["defense-evasion", "execution"],
    "reverse engineering": ["defense-evasion"],
    "dfir": ["collection", "discovery"],
    "incident response": ["collection", "discovery"],
    "forensics": ["collection"],
    "detection engineering": ["defense-evasion", "command-and-control", "execution"],
    "threat intelligence": ["reconnaissance", "command-and-control"],
    "osint": ["reconnaissance"],
    "external reconnaissance": ["reconnaissance"],
    "bug bounty": ["reconnaissance", "initial-access", "discovery"],
    "web application": ["initial-access", "discovery"],
    "cloud security": ["discovery", "credential-access", "privilege-escalation"],
    "container security": ["execution", "privilege-escalation"],
    "kubernetes": ["execution", "privilege-escalation", "discovery"],
    "vulnerability management": ["initial-access", "privilege-escalation"],
    "attack surface": ["reconnaissance"],
    "edr": ["defense-evasion", "execution"],
    "endpoint security": ["defense-evasion", "execution"],
    "siem": ["collection", "discovery"],
    "soar": ["collection"],
    "honeypot": ["initial-access", "discovery"],
    "deception": ["initial-access"],
    "email security": ["initial-access"],
    "phishing": ["initial-access"],
    "wireless": ["credential-access", "initial-access"],
    "mobile": ["initial-access", "discovery"],
    "ics": ["initial-access", "impact"],
    "ot": ["initial-access", "impact"],
    "appsec": ["initial-access"],
    "sast": ["initial-access"],
    "dast": ["initial-access"],
    "cti": ["reconnaissance", "command-and-control"],
    "mitre att&ck": ["reconnaissance", "execution", "credential-access"],
    "mitre attack": ["reconnaissance", "execution", "credential-access"],
}


def classify_attack_tactics(asset: Asset) -> list[str]:
    """Best-effort heuristic mapping of an asset to ATT&CK tactic slugs.

    Strategy:
      1. Bulk-map by category substring (high signal — categories were curated).
      2. Add per-keyword hits from title + description + subcategory.
      3. Deduplicate and return.

    No keyword found → empty list (UI shows "untagged" facet).
    """
    hits: set[str] = set()
    haystack = " ".join([asset.category, asset.subcategory, asset.title, asset.description]).lower()

    # Category bulk-map
    cat_lower = asset.category.lower()
    for needle, tactics in CATEGORY_TACTIC_MAP.items():
        if needle in cat_lower:
            hits.update(tactics)

    # Per-keyword hits
    for tactic, kws in TACTIC_KEYWORDS.items():
        for kw in kws:
            if kw in haystack:
                hits.add(tactic)
                break

    return sorted(hits)


# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #


def build() -> Library:
    from datetime import datetime, timezone

    sources = {
        "Starred GitHub Repositories.md": parse_starred_repos,
        "YouTube Channels.md": parse_youtube_channels,
        "X Account Lists.md": parse_x_accounts,
    }

    assets: list[Asset] = []
    seen_ids: set[str] = set()

    for fname, parser in sources.items():
        path = PROFILE_ROOT / fname
        if not path.exists():
            print(f"  WARN: {fname} not found, skipping", file=sys.stderr)
            continue
        text = path.read_text(encoding="utf-8")
        added = 0
        for asset in parser(text):
            asset.vendor = normalize_vendor(asset.vendor)
            asset.attack_tactics = classify_attack_tactics(asset)
            if asset.id in seen_ids:
                continue
            seen_ids.add(asset.id)
            assets.append(asset)
            added += 1
        print(f"  {fname}: {added} assets")

    counts: dict[str, int] = {}
    categories: dict[str, set[str]] = {}
    vendors: dict[str, int] = {}
    tactic_counts: dict[str, int] = {}
    untagged = 0
    for a in assets:
        counts[a.type] = counts.get(a.type, 0) + 1
        categories.setdefault(a.type, set()).add(a.category)
        if a.vendor:
            vendors[a.vendor] = vendors.get(a.vendor, 0) + 1
        if a.attack_tactics:
            for t in a.attack_tactics:
                tactic_counts[t] = tactic_counts.get(t, 0) + 1
        else:
            untagged += 1

    print(f"  ATT&CK tactic coverage: {len(assets) - untagged}/{len(assets)} assets tagged ({untagged} untagged)")

    lib = Library(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        counts=counts,
        categories={k: sorted(v) for k, v in categories.items()},
        vendors=dict(sorted(vendors.items(), key=lambda kv: -kv[1])),
        assets=assets,
    )
    # Stash tactic_counts in a separate side dict that ends up in the JSON via main()
    setattr(lib, "tactic_counts", dict(sorted(tactic_counts.items(), key=lambda kv: -kv[1])))
    return lib


def main() -> int:
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    print(f"Building library index from {PROFILE_ROOT}")
    lib = build()

    # Custom encoder for dataclasses
    payload = {
        "generated_at": lib.generated_at,
        "counts": lib.counts,
        "categories": lib.categories,
        "vendors": lib.vendors,
        "tactic_counts": getattr(lib, "tactic_counts", {}),
        "assets": [asdict(a) for a in lib.assets],
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {OUT_PATH} ({OUT_PATH.stat().st_size:,} bytes)")
    print(f"  totals: {lib.counts}")
    print(f"  top vendors: {dict(list(lib.vendors.items())[:8])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
