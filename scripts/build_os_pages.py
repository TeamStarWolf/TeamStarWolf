#!/usr/bin/env python3
"""Write the operating-system pages, operating-systems/<os>.md and operating-systems/README.md,
from the catalog data/os/os-catalog.jsonl.

One catalog row per operating system and major version (or per channel, or one row for a
rolling release). Rows that share an `os` slug make one page with a version table; the
README index groups the pages by `family`. Nothing on a page is typed by hand: edit the
catalog and re-run this script.

Where the data comes from:
    support dates      the endoflife.date API (https://endoflife.date/api/<product>.json,
                       MIT licence), one product and cycle per row, with the fetch date.
                       --refresh-eol re-reads the API and rewrites those fields only.
    everything else    the vendor documentation listed in each row's `sources`, opened on
                       the row's `reviewed_at` date.

Rules (--check and --self-test fail on any of them):
  * every row has exactly FIELDS, in order; ids, slugs, dates and URLs are well formed;
    `family` is one of FAMILIES;
  * the per-system fields (OS_FIELDS) are identical on every row of one `os`, so a page
    never mixes two descriptions of the same system;
  * every root-relative link (hardening pages, case studies) names a tracked page;
  * no text carries an em dash (docs/VOICE.md);
  * an endoflife.date row names its product, cycle and fetch date; a vendor, rolling or
    unknown row names no API product and carries a note (`unknown` is for a system whose
    end-of-life date no vendor page confirmed: the page says so instead of guessing);
  * `shell` is one of SHELLS; a system with no shell (`none`) lists no patch commands;
  * a system with no identify commands says why in `identify_basis`; a system with no
    os-release file has `os_release` null and no `os_release_checked`.

The status column ("Supported", "Security support only", ...) is computed against the
row's fetch date, not today's date, so a page only changes when the data does.

Usage:
    python scripts/build_os_pages.py               # (re)write the pages
    python scripts/build_os_pages.py --check       # exit 1 if a page is stale, missing or an orphan
    python scripts/build_os_pages.py --self-test   # planted cases for the rules above
    python scripts/build_os_pages.py --refresh-eol # re-read endoflife.date (network)
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from repo_files import ROOT, read_text, tracked_files  # noqa: E402

CATALOG = "data/os/os-catalog.jsonl"
OUT = "operating-systems"
INDEX = OUT + "/README.md"
EOL_API = "https://endoflife.date/api/{product}.json"
EOL_SITE = "https://endoflife.date/"
USER_AGENT = "teamstarwolf-library-build (+https://github.com/TeamStarWolf/TeamStarWolf)"
GENERATED_BY = "written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit"
START = "<!-- os-pages:start (" + GENERATED_BY + ") -->"
END = "<!-- os-pages:end -->"
HUB = "https://teamstarwolf.github.io/intelligence-hub/"
EM_DASH = "\u2014"

FIELDS = ("id", "os", "family", "name", "summary", "version", "codename", "release_model",
          "base", "kernel", "architectures", "package_manager", "update_channel", "patch_commands",
          "shell", "patch_notes", "advisories", "advisory_notes", "identify", "identify_basis",
          "os_release",
          "os_release_checked", "eol", "hardening", "case_studies", "vocab_id", "licence",
          "sources", "reviewed_at")
# Fields that describe the system, not one version: identical on every row of an `os`.
OS_FIELDS = ("family", "name", "summary", "package_manager", "patch_commands", "shell", "patch_notes",
             "advisories", "advisory_notes", "identify", "identify_basis", "hardening", "case_studies",
             "vocab_id", "licence")
RELEASE_MODELS = ("point", "rolling", "channel")
EOL_SOURCES = ("endoflife.date", "vendor", "rolling", "unknown")
# shell -> (code fence language or None, identify heading, first identify column)
SHELLS = {
    "sh": ("sh", "Identify it from a terminal", "Command"),
    "powershell": ("powershell", "Identify it from a terminal", "Command"),
    "cli": ("text", "Identify it from the device CLI", "Command"),
    "none": (None, "Identify the version", "Where to look"),
}
EOL_FIELDS = ("source", "product", "cycle", "fetched", "release_date", "support_end",
              "security_end", "extended_end", "latest", "url", "note")
ADVISORY_FIELDS = ("name", "id_format", "example", "url", "feeds")
# Page order of the README groups, with the line under each group heading.
FAMILIES = {
    "debian": ("Debian family", "Debian and Ubuntu, whose archive draws on Debian; both patch with apt and dpkg."),
    "rhel": ("Red Hat Enterprise Linux family", "Red Hat Enterprise Linux, the distributions that follow its "
             "releases, and Fedora, patched with dnf and rpm."),
    "suse": ("SUSE family", "SUSE Linux Enterprise and the openSUSE distributions, patched with zypper and rpm."),
    "independent": ("Independent distributions", "Distributions with their own package managers and release models."),
    "cloud": ("Cloud provider distributions", "Distributions a cloud provider builds and patches for its own platform."),
    "container": ("Container and immutable hosts", "Systems built to run containers: a container base with no kernel, "
                  "and hosts that update by swapping whole images."),
    "security": ("Security testing distributions", "Distributions for penetration testing and security research, built "
                 "on Debian."),
    "bsd": ("BSD family", "FreeBSD, OpenBSD, and NetBSD, each released as one base system (kernel and userland) with "
            "its own update tools and its own advisory series."),
    "windows": ("Windows", "Windows client and Windows Server, patched by the monthly cumulative updates that Microsoft "
                "publishes on the second Tuesday of each month."),
    "macos": ("macOS", "Apple's desktop operating system, updated through Software Update."),
    "mobile": ("Mobile operating systems", "Android and iOS: the phone and tablet systems whose security fixes arrive "
               "as vendor updates and monthly bulletins."),
    "network": ("Network operating systems", "The software on routers, switches, firewalls, and application delivery "
                "controllers, upgraded by installing a vendor image; their advisories fill a large share of the "
                "known-exploited record."),
    "hypervisor": ("Hypervisors and Kubernetes node images", "The hosts that run virtual machines and containers: "
                   "bare-metal hypervisors, the KVM stack on general-purpose Linux, and the node images managed "
                   "Kubernetes services boot."),
    "embedded": ("Embedded and real-time systems", "Real-time kernels, embedded platforms, and router firmware, "
                 "most of them built into products by a device maker rather than installed by the operator."),
}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
VOCAB_RE = re.compile(r"^product:[a-z0-9][a-z0-9-]*$")
LINK_RE = re.compile(r"\]\((/[^)\s]+)\)")


class CatalogError(Exception):
    pass


# ----------------------------------------------------------------------------- validation

def _texts(v):
    """Every string inside a value (for the em dash rule)."""
    if isinstance(v, str):
        yield v
    elif isinstance(v, list):
        for x in v:
            yield from _texts(x)
    elif isinstance(v, dict):
        for x in v.values():
            yield from _texts(x)


def _is_url(u) -> bool:
    return isinstance(u, str) and u.startswith("https://") and " " not in u


def _str_list(v) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) and x.strip() for x in v)


def validate(rows: list[dict], exists=lambda rel: True) -> list[str]:
    """Every problem with the catalog, as messages; [] when it is clean."""
    errs: list[str] = []
    seen: set[str] = set()
    first: dict[str, dict] = {}
    for n, r in enumerate(rows, 1):
        rid = r.get("id")
        where = f"{CATALOG} row {n} ({rid!r})"
        if tuple(r.keys()) != FIELDS:
            errs.append(f"{where}: fields must be exactly {list(FIELDS)}")
            continue
        if not isinstance(rid, str) or not ID_RE.match(rid):
            errs.append(f"{where}: id must be lowercase letters, digits, dots and dashes")
        elif rid in seen:
            errs.append(f"{where}: duplicate id")
        seen.add(rid)
        if not isinstance(r["os"], str) or not SLUG_RE.match(r["os"]):
            errs.append(f"{where}: os must be a lowercase slug (the page name)")
            continue
        if r["family"] not in FAMILIES:
            errs.append(f"{where}: family must be one of {list(FAMILIES)}")
        for f in ("name", "summary", "version", "base", "package_manager", "update_channel", "licence"):
            if not isinstance(r[f], str) or not r[f].strip():
                errs.append(f"{where}: {f} must be a non-empty string")
        for f in ("codename", "kernel", "patch_notes", "advisory_notes", "os_release_checked"):
            if r[f] is not None and (not isinstance(r[f], str) or not r[f].strip()):
                errs.append(f"{where}: {f} must be null or a non-empty string")
        if r["release_model"] not in RELEASE_MODELS:
            errs.append(f"{where}: release_model must be one of {RELEASE_MODELS}")
        if not _str_list(r["architectures"]):
            errs.append(f"{where}: architectures must be a list of strings (empty when not checked)")
        if not _str_list(r["patch_commands"]):
            errs.append(f"{where}: patch_commands must be a list of strings")
        if r["shell"] not in SHELLS:
            errs.append(f"{where}: shell must be one of {list(SHELLS)}")
        elif r["shell"] == "none" and r["patch_commands"]:
            errs.append(f"{where}: a system with no shell lists no patch commands")
        if r["identify_basis"] is not None and (not isinstance(r["identify_basis"], str)
                                                or not r["identify_basis"].strip()):
            errs.append(f"{where}: identify_basis must be null or a non-empty string")
        if not isinstance(r["advisories"], list):
            errs.append(f"{where}: advisories must be a list")
        else:
            for a in r["advisories"]:
                if not isinstance(a, dict) or tuple(a.keys()) != ADVISORY_FIELDS:
                    errs.append(f"{where}: each advisory has exactly {list(ADVISORY_FIELDS)}")
                    continue
                if not isinstance(a["name"], str) or not _is_url(a["url"]):
                    errs.append(f"{where}: advisory {a.get('name')!r} needs a name and an https url")
                for fd in a["feeds"] if isinstance(a["feeds"], list) else [None]:
                    if not isinstance(fd, dict) or tuple(fd.keys()) != ("label", "url") or not _is_url(fd["url"]):
                        errs.append(f"{where}: advisory {a.get('name')!r}: each feed is {{label, url}} with an https url")
        if not r["advisories"] and not r["advisory_notes"]:
            errs.append(f"{where}: a system with no advisory series needs advisory_notes saying so")
        ident = r["identify"]
        if not isinstance(ident, list) or not all(
                isinstance(c, dict) and tuple(c.keys()) == ("command", "shows")
                and isinstance(c["command"], str) and isinstance(c["shows"], str) for c in ident):
            errs.append(f"{where}: identify must be a list of {{command, shows}}")
        elif not ident and not r["identify_basis"]:
            errs.append(f"{where}: a system with no identify commands says why in identify_basis")
        osr = r["os_release"]
        if osr is None:
            if r["os_release_checked"] is not None:
                errs.append(f"{where}: os_release_checked needs an os_release")
        elif not isinstance(osr, dict) or "ID" not in osr or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in osr.items()):
            errs.append(f"{where}: os_release must be null or map os-release keys (at least ID) to values")
        e = r["eol"]
        if not isinstance(e, dict) or tuple(e.keys()) != EOL_FIELDS:
            errs.append(f"{where}: eol must have exactly {list(EOL_FIELDS)}")
        else:
            if e["source"] not in EOL_SOURCES:
                errs.append(f"{where}: eol.source must be one of {EOL_SOURCES}")
            if not isinstance(e["fetched"], str) or not DATE_RE.match(e["fetched"]):
                errs.append(f"{where}: eol.fetched must be YYYY-MM-DD")
            for f in ("release_date", "support_end", "security_end", "extended_end"):
                if e[f] is not None and (not isinstance(e[f], str) or not DATE_RE.match(e[f])):
                    errs.append(f"{where}: eol.{f} must be null or YYYY-MM-DD")
            if e["source"] == "endoflife.date":
                if not e["product"] or not e["cycle"] or e["note"] is not None:
                    errs.append(f"{where}: an endoflife.date row names product and cycle and has no note")
                if e["url"] != EOL_API.format(product=e["product"]):
                    errs.append(f"{where}: eol.url must be the API URL for product {e['product']!r}")
            elif e["source"] in ("vendor", "rolling", "unknown"):
                if e["product"] is not None or e["cycle"] is not None or not e["note"]:
                    errs.append(f"{where}: a {e['source']} row has no API product or cycle and needs a note")
                if e["source"] == "vendor" and not _is_url(e["url"]):
                    errs.append(f"{where}: a vendor eol row cites the vendor page in eol.url")
                if e["source"] == "unknown" and (e["url"] is not None and not _is_url(e["url"])):
                    errs.append(f"{where}: an unknown eol row's url is null or https")
                if e["source"] == "unknown" and any(e[f] is not None for f in (
                        "support_end", "security_end", "extended_end")):
                    errs.append(f"{where}: an unknown eol row carries no end dates")
        for f in ("hardening", "case_studies"):
            items = r[f]
            if not isinstance(items, list) or not all(
                    isinstance(h, dict) and tuple(h.keys()) == ("label", "path")
                    and isinstance(h["path"], str) and h["path"].startswith("/") for h in items):
                errs.append(f"{where}: {f} must be a list of {{label, path}} with root-relative paths")
                continue
            for h in items:
                if not exists(h["path"].lstrip("/").split("?", 1)[0]):
                    errs.append(f"{where}: {f} link {h['path']} is not a tracked page")
        if not r["hardening"]:
            errs.append(f"{where}: hardening lists at least one library page")
        if not isinstance(r["vocab_id"], str) or not VOCAB_RE.match(r["vocab_id"]):
            errs.append(f"{where}: vocab_id must be product:<slug>")
        srcs = r["sources"]
        if not isinstance(srcs, list) or not srcs or not all(
                isinstance(s, dict) and tuple(s.keys()) == ("title", "url") and _is_url(s["url"]) for s in srcs):
            errs.append(f"{where}: sources must be a non-empty list of {{title, url}} with https urls")
        if not isinstance(r["reviewed_at"], str) or not DATE_RE.match(r["reviewed_at"]):
            errs.append(f"{where}: reviewed_at must be YYYY-MM-DD")
        for t in _texts(r):
            if EM_DASH in t:
                errs.append(f"{where}: em dash in {t[:60]!r} (docs/VOICE.md)")
                break
        base = first.setdefault(r["os"], r)
        for f in OS_FIELDS:
            if r[f] != base[f]:
                errs.append(f"{where}: {f} differs from row {base['id']!r} of the same os "
                            f"(system fields must match on every row)")
    return errs


# ----------------------------------------------------------------------------- rendering

def cell(s) -> str:
    return "" if s is None else str(s).replace("|", "\\|").replace("\n", " ").strip()


def md_link(label: str, url: str) -> str:
    return "[" + label.replace("[", "(").replace("]", ")") + "](" + url + ")"


def code(s: str) -> str:
    return "`" + s + "`"


def status(e: dict, model: str) -> str:
    """Support status on the fetch date (computed, never typed)."""
    if e["source"] == "rolling":
        return "Rolling release" if model == "rolling" else "Channel moves forward"
    if e["source"] == "unknown":
        return "Not confirmed (see note)"
    day = e["fetched"]
    sec = e["security_end"]
    ext = e["extended_end"]
    act = e["support_end"]
    if sec is None:
        return "Vendor statement (see note)" if e["source"] == "vendor" else "No date published"
    if day < sec:
        if act is not None and act <= day:
            return "Security support only"
        return "Supported"
    if ext is not None and day < ext:
        return "Extended support only"
    return "Ended"


def date_or(v, rolling: bool, unknown: bool = False) -> str:
    if v is not None:
        return v
    if rolling:
        return "Not applicable"
    return "Not checked" if unknown else "Not published"


def group(rows: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r["os"], []).append(r)
    return out


def fetched_dates(rows: list[dict]) -> list[str]:
    return sorted({r["eol"]["fetched"] for r in rows})


def eol_line(rs: list[dict]) -> str:
    api = [r for r in rs if r["eol"]["source"] == "endoflife.date"]
    if not api:
        srcs = {r["eol"]["source"] for r in rs}
        if "vendor" in srcs:
            return ("endoflife.date does not track this system, so the support column below quotes the "
                    "vendor's own statement.")
        if "unknown" in srcs:
            return ("endoflife.date does not track this system and no vendor page confirmed an "
                    "end-of-life date, so the support columns say so; the notes under the table "
                    "say where to look.")
        return "This is a rolling release: it has no numbered versions that reach end of life."
    prods = list(dict.fromkeys(r["eol"]["product"] for r in api))
    days = ", ".join(fetched_dates(api))
    if len(prods) == 1:
        p = prods[0]
        return ("Support dates come from the " + md_link("endoflife.date", EOL_SITE + p) + " API ("
                + code(EOL_API.format(product=p)) + "), fetched on " + days + ".")
    return ("Support dates come from the " + md_link("endoflife.date", EOL_SITE) + " API ("
            + ", ".join(code(EOL_API.format(product=p)) for p in prods) + "), fetched on " + days + ".")


def render_page(rs: list[dict]) -> str:
    r0 = rs[0]
    fam_label = FAMILIES[r0["family"]][0]
    out = [START, "", "# " + r0["name"], "", "> " + r0["summary"], "",
           "Part of " + md_link("Operating systems", "/" + INDEX) + " (" + fam_label + "). "
           + eol_line(rs), ""]

    # versions and support
    out += ["## Versions and support", ""]
    out += ["| Version | Codename | Released | Latest release | Full support ends | Security support ends "
            "| Extended support ends | Status on the fetch date |",
            "|---|---|---|---|---|---|---|---|"]
    for r in rs:
        e = r["eol"]
        roll = r["release_model"] != "point"
        unk = e["source"] == "unknown"
        out.append("| " + " | ".join([
            cell(r["version"]), cell(r["codename"] or "None"), cell(date_or(e["release_date"], roll, unk)),
            cell(e["latest"] or date_or(None, roll, unk)),
            cell(date_or(e["support_end"], roll, unk)), cell(date_or(e["security_end"], roll, unk)),
            cell(date_or(e["extended_end"], roll, unk)), cell(status(e, r["release_model"]))]) + " |")
    out.append("")
    notes: dict[tuple, list[str]] = {}
    for r in rs:
        if r["eol"]["note"]:
            notes.setdefault((r["eol"]["note"], r["eol"]["url"]), []).append(r["version"])
    for (note, url), vs in notes.items():
        label = "All versions" if len(vs) == len(rs) and len(rs) > 1 else ", ".join(vs)
        line = "- " + cell(label) + ": " + note
        if url:
            line += " (" + md_link("source", url) + ")"
        out.append(line)
    if notes:
        out.append("")
    if any(r["eol"]["source"] == "endoflife.date" for r in rs):
        out += ["Full support is the vendor's regular maintenance; security support is the end of "
                "security fixes from the vendor (endoflife.date's `eol` field); extended support is "
                "paid or third-party coverage after that (`extendedSupport`).", ""]
    out += ["| Version | Kernel | Architectures | Based on | Updates from |", "|---|---|---|---|---|"]
    for r in rs:
        out.append("| " + " | ".join([cell(r["version"]), cell(r["kernel"] or "Not checked"),
                                      cell(", ".join(r["architectures"]) or "Not checked"), cell(r["base"]),
                                      cell(r["update_channel"])]) + " |")
    out.append("")

    # advisories
    out += ["## Where its advisories live", ""]
    for a in r0["advisories"]:
        line = "- " + md_link(a["name"], a["url"])
        if a["id_format"]:
            line += ": IDs take the form " + code(a["id_format"])
            if a["example"]:
                line += " (for example " + code(a["example"]) + ")"
            line += "."
        else:
            line += "."
        if a["feeds"]:
            line += " Machine-readable: " + ", ".join(md_link(f["label"], f["url"]) for f in a["feeds"]) + "."
        out.append(line)
    if r0["advisories"]:
        out.append("")
    if r0["advisory_notes"]:
        out += [r0["advisory_notes"], ""]

    # patching
    out += ["## How it patches", "", "Package manager: " + r0["package_manager"] + ".", ""]
    if r0["patch_notes"]:
        out += [r0["patch_notes"], ""]
    lang, ident_heading, ident_col = SHELLS[r0["shell"]]
    if r0["patch_commands"]:
        out += ["```" + lang] + r0["patch_commands"] + ["```", ""]

    # identify
    out += ["## " + ident_heading, ""]
    if r0["identify"]:
        out += ["| " + ident_col + " | What it shows |", "|---|---|"]
        for c in r0["identify"]:
            what = code(cell(c["command"])) if lang else cell(c["command"])
            out.append("| " + what + " | " + cell(c["shows"]) + " |")
        out.append("")
    if r0["identify_basis"]:
        out += [r0["identify_basis"], ""]
    if any(r["os_release"] is not None for r in rs):
        out += ["The `ID` and `VERSION_ID` fields of `/etc/os-release` (the "
                + md_link("os-release format", "https://www.freedesktop.org/software/systemd/man/latest/os-release.html")
                + ") for each version:", "",
                "| Version | os-release fields | Checked against |", "|---|---|---|"]
        for r in rs:
            fields = ", ".join(code(k + "=" + v) for k, v in (r["os_release"] or {}).items()) or "None"
            out.append("| " + cell(r["version"]) + " | " + fields + " | "
                       + cell(r["os_release_checked"] or "Not checked on a running system") + " |")
        out.append("")

    # hardening
    out += ["## Hardening", ""]
    out += ["- " + md_link(h["label"], h["path"]) for h in r0["hardening"]]
    out.append("")
    if r0["case_studies"]:
        out += ["Case studies that discuss " + r0["name"] + ":", ""]
        out += ["- " + md_link(h["label"], h["path"]) for h in r0["case_studies"]]
        out.append("")

    # hub
    out += ["## On the Intelligence Hub", "",
            "The library's vocabulary id for " + r0["name"] + " is " + code(r0["vocab_id"])
            + ". The " + md_link("Intelligence Hub", HUB) + " tags advisories, research, and news "
            "with ids from that vocabulary.", ""]

    # licence and sources
    out += ["## Licence and sources", "", r0["licence"], ""]
    seen, srcs = set(), []
    for r in rs:
        for s in r["sources"]:
            if s["url"] not in seen:
                seen.add(s["url"])
                srcs.append(s)
    out += ["Vendor and project pages read for this page (" + ", ".join(sorted({r["reviewed_at"] for r in rs}))
            + "):", ""]
    out += ["- " + md_link(s["title"], s["url"]) for s in srcs]
    out += ["", END]
    return "\n".join(out) + "\n"


def render_index(rows: list[dict]) -> str:
    groups = group(rows)
    days = fetched_dates([r for r in rows if r["eol"]["source"] == "endoflife.date"] or rows)
    out = [START, "", "# Operating systems", "",
           "> The operating systems defenders run, patch, and have to identify, from Linux and BSD servers "
           "to Windows, Apple, and Android devices, network appliances, hypervisors, and embedded systems: "
           "one page per system with its versions and support dates, where its security advisories are "
           "published, how it takes updates, and the commands that tell you which one you are on.", "",
           "Support dates come from the " + md_link("endoflife.date", EOL_SITE) + " API, fetched on "
           + ", ".join(days) + ", or from the vendor page a row cites; where neither gives a date the page "
           "says so. Everything else comes from the vendor and project pages each page cites. For "
           "hardening steps, start with the "
           + md_link("Linux Hardening Reference", "/LINUX_HARDENING_REFERENCE.md") + ", the "
           + md_link("Harden a Linux Host", "/guides/HARDEN_A_LINUX_HOST.md") + " guide, the "
           + md_link("Windows Hardening Reference", "/WINDOWS_HARDENING_REFERENCE.md") + ", and the "
           + md_link("macOS Security Reference", "/MACOS_SECURITY_REFERENCE.md") + "; for what each "
           "offensive, forensic, and privacy distribution is for, see "
           + md_link("Security Operating Systems and Distributions", "/SECURITY_OPERATING_SYSTEMS_REFERENCE.md")
           + ".", ""]
    for fam, (label, blurb) in FAMILIES.items():
        pages = [(slug, rs) for slug, rs in groups.items() if rs[0]["family"] == fam]
        if not pages:
            continue
        out += ["## " + label, "", blurb, "",
                "| System | Versions | Package manager | Advisories |", "|---|---|---|---|"]
        for slug, rs in pages:
            adv = ", ".join(a["name"] for a in rs[0]["advisories"]) or "No numbered advisories"
            out.append("| " + md_link(rs[0]["name"], "/" + OUT + "/" + slug + ".md") + " | "
                       + cell(", ".join(r["version"] for r in rs)) + " | " + cell(rs[0]["package_manager"])
                       + " | " + cell(adv) + " |")
        out.append("")
    out += ["## About the catalog", "",
            "Every page here is written by " + code("scripts/build_os_pages.py") + " from "
            + code(CATALOG) + ", one row per system and major version (or release train, channel, or "
            "node image). Edit the catalog, then run "
            + code("python scripts/build_os_pages.py") + "; " + code("--refresh-eol")
            + " re-reads the support dates from endoflife.date, and CI runs " + code("--check")
            + ". The vocabulary ids in each page's last section are the " + code("product:")
            + " rows of " + code("data/vocab/entities.jsonl") + ".", "", END]
    return "\n".join(out) + "\n"


def build(rows: list[dict]) -> dict[str, str]:
    files = {OUT + "/" + slug + ".md": render_page(rs) for slug, rs in group(rows).items()}
    files[INDEX] = render_index(rows)
    return files


# ----------------------------------------------------------------------------- IO

def load(text: str | None = None) -> list[dict]:
    if text is None:
        text = read_text(CATALOG)
        if text is None:
            raise CatalogError(CATALOG + ": not found")
    rows = []
    for n, line in enumerate(text.split("\n"), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise CatalogError(f"{CATALOG} line {n}: {e}")
    return rows


def dump(rows: list[dict]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


def _exists_factory():
    tracked = set(tracked_files())
    return lambda rel: rel in tracked or os.path.isfile(os.path.join(ROOT, rel))


def run(check: bool) -> int:
    rows = load()
    errs = validate(rows, _exists_factory())
    if errs:
        print("FAIL: " + CATALOG + ":")
        for e in errs:
            print("  - " + e)
        return 1
    gen = build(rows)
    on_disk = {OUT + "/" + f for f in os.listdir(os.path.join(ROOT, OUT))} if os.path.isdir(os.path.join(ROOT, OUT)) else set()
    orphans = sorted(f for f in on_disk if f.endswith(".md") and not os.path.basename(f).startswith("_")
                     and f not in gen)
    stale = []
    for rel, new in gen.items():
        cur = read_text(rel) if os.path.isfile(os.path.join(ROOT, rel)) else None
        if cur != new:
            stale.append(rel)
            if not check:
                os.makedirs(os.path.dirname(os.path.join(ROOT, rel)), exist_ok=True)
                with open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(new)
                print("wrote " + rel)
    if check:
        if stale or orphans:
            print("FAIL: operating-systems/ does not match " + CATALOG + "; run python scripts/build_os_pages.py")
            for rel in stale:
                print("  - stale or missing: " + rel)
            for rel in orphans:
                print("  - orphan (no catalog row writes it): " + rel)
            return 1
        print("OK: " + str(len(gen)) + " pages in " + OUT + "/ match " + CATALOG + " (" + str(len(rows))
              + " rows)")
        return 0
    for rel in orphans:
        print("WARNING: orphan page " + rel + " (delete it or add catalog rows)")
    print(str(len(stale)) + " of " + str(len(gen)) + " pages written")
    return 1 if orphans else 0


def _norm(v):
    """endoflife.date values: a date string stays; anything else (true, false, missing) is null."""
    return v if isinstance(v, str) and DATE_RE.match(v) else None


def apply_eol(rows: list[dict], api: dict[str, list[dict]], day: str) -> list[str]:
    """Rewrite the endoflife.date fields of `rows` in place from `api` ({product: cycles});
    returns problems (a product or cycle the API no longer lists)."""
    probs = []
    for r in rows:
        e = r["eol"]
        if e["source"] != "endoflife.date":
            continue
        cycles = {str(c.get("cycle")): c for c in api.get(e["product"], [])}
        c = cycles.get(e["cycle"])
        if c is None:
            probs.append(f"{r['id']}: endoflife.date has no cycle {e['cycle']!r} for {e['product']!r}")
            continue
        e.update({"fetched": day, "release_date": _norm(c.get("releaseDate")),
                  "support_end": _norm(c.get("support")), "security_end": _norm(c.get("eol")),
                  "extended_end": _norm(c.get("extendedSupport")),
                  "latest": c.get("latest") if isinstance(c.get("latest"), str) else None})
    return probs


def refresh_eol() -> int:
    rows = load()
    products = sorted({r["eol"]["product"] for r in rows if r["eol"]["source"] == "endoflife.date"})
    api = {}
    for p in products:
        req = urllib.request.Request(EOL_API.format(product=p), headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as resp:
            api[p] = json.loads(resp.read().decode("utf-8"))
        print("read " + EOL_API.format(product=p) + " (" + str(len(api[p])) + " cycles)")
    day = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    probs = apply_eol(rows, api, day)
    for p in probs:
        print("FAIL: " + p)
    if probs:
        return 1
    with open(os.path.join(ROOT, CATALOG), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(dump(rows))
    print("wrote " + CATALOG + "; now run python scripts/build_os_pages.py")
    return 0


# ----------------------------------------------------------------------------- self-test

def _planted() -> dict:
    eol = {"source": "endoflife.date", "product": "acme", "cycle": "1", "fetched": "2026-01-10",
           "release_date": "2024-01-01", "support_end": "2025-01-01", "security_end": "2027-01-01",
           "extended_end": None, "latest": "1.4", "url": EOL_API.format(product="acme"), "note": None}
    return {"id": "acme-1", "os": "acme", "family": "independent", "name": "Acme Linux",
            "summary": "A planted test system.", "version": "1", "codename": None,
            "release_model": "point", "base": "Independent", "kernel": "Linux 6.1 series",
            "architectures": ["x86_64"], "package_manager": "`acme-get`", "update_channel": "acme-security",
            "patch_commands": ["sudo acme-get upgrade"], "shell": "sh", "patch_notes": None,
            "advisories": [{"name": "Acme Security Advisories", "id_format": "ASA-NNNN", "example": "ASA-0001",
                            "url": "https://acme.example/sec", "feeds": [{"label": "RSS", "url": "https://acme.example/sec.rss"}]}],
            "advisory_notes": None,
            "identify": [{"command": "cat /etc/os-release", "shows": "ID and VERSION_ID"}],
            "identify_basis": None,
            "os_release": {"ID": "acme", "VERSION_ID": "1"}, "os_release_checked": None, "eol": eol,
            "hardening": [{"label": "Linux Hardening Reference", "path": "/LINUX_HARDENING_REFERENCE.md"}],
            "case_studies": [], "vocab_id": "product:acme-linux", "licence": "Planted.",
            "sources": [{"title": "Acme docs", "url": "https://acme.example/docs"}], "reviewed_at": "2026-01-10"}


def self_test() -> int:
    fails = []

    def expect(name, ok):
        print(("ok   " if ok else "FAIL ") + name)
        if not ok:
            fails.append(name)

    good = _planted()
    expect("clean row validates", validate([good]) == [])
    two = json.loads(json.dumps(good))
    two["id"], two["version"], two["eol"]["cycle"] = "acme-2", "2", "2"
    expect("two versions of one system validate", validate([good, two]) == [])
    bad = json.loads(json.dumps(two))
    bad["package_manager"] = "`other`"
    expect("system field mismatch across rows fails",
           any("package_manager differs" in e for e in validate([good, bad])))
    bad = json.loads(json.dumps(good))
    bad["summary"] = "Has an em dash \u2014 here."
    expect("em dash fails", any("em dash" in e for e in validate([bad])))
    bad = dict(good)
    bad.pop("licence")
    expect("missing field fails", any("fields must be exactly" in e for e in validate([bad])))
    bad = json.loads(json.dumps(good))
    bad["family"] = "nope"
    expect("unknown family fails", any("family must be" in e for e in validate([bad])))
    bad = json.loads(json.dumps(good))
    bad["eol"]["url"] = "https://endoflife.date/api/other.json"
    expect("wrong API url fails", any("API URL" in e for e in validate([bad])))
    bad = json.loads(json.dumps(good))
    bad["eol"].update({"source": "vendor", "product": None, "cycle": None, "url": None, "note": "x"})
    expect("vendor eol without a url fails", any("vendor page" in e for e in validate([bad])))
    bad = json.loads(json.dumps(good))
    bad["advisories"], bad["advisory_notes"] = [], None
    expect("no advisories and no note fails", any("advisory_notes" in e for e in validate([bad])))
    expect("missing hardening page fails",
           any("not a tracked page" in e for e in validate([good], exists=lambda rel: False)))
    bad = json.loads(json.dumps(good))
    bad["id"] = two["id"] = "dup"
    expect("duplicate id fails", any("duplicate id" in e for e in validate([bad, two])))
    bad = json.loads(json.dumps(good))
    bad["shell"] = "fish"
    expect("unknown shell fails", any("shell must be" in e for e in validate([bad])))
    bad = json.loads(json.dumps(good))
    bad["shell"] = "none"
    expect("no-shell system with patch commands fails", any("no patch commands" in e for e in validate([bad])))
    bad = json.loads(json.dumps(good))
    bad["identify"] = []
    expect("no identify commands and no basis fails", any("identify_basis" in e for e in validate([bad])))
    bad["identify_basis"] = "The vendor's command reference refused automated requests."
    expect("no identify commands with a basis validates", validate([bad]) == [])
    bad = json.loads(json.dumps(good))
    bad["os_release"], bad["os_release_checked"] = None, "2026-01-10 on a VM"
    expect("os_release_checked without os_release fails", any("needs an os_release" in e for e in validate([bad])))
    bad["os_release_checked"] = None
    expect("system with no os-release validates", validate([bad]) == [])
    unk = json.loads(json.dumps(good))
    unk["eol"].update({"source": "unknown", "product": None, "cycle": None, "release_date": None,
                       "support_end": None, "security_end": None, "extended_end": None, "url": None,
                       "note": "No vendor page gives a date."})
    expect("unknown eol row validates", validate([unk]) == [])
    expect("status: unknown", status(unk["eol"], "point") == "Not confirmed (see note)")
    bad = json.loads(json.dumps(unk))
    bad["eol"]["security_end"] = "2030-01-01"
    expect("unknown eol row with a date fails", any("no end dates" in e for e in validate([bad])))
    page = build([unk])[OUT + "/acme.md"]
    expect("unknown row page says no date was confirmed", "no vendor page confirmed" in page)
    expect("unknown row dates read Not checked", "| 1 | None | Not checked | 1.4 | Not checked |" in page)
    idx = build([good, dict(unk, id="acme-x", os="acme-x", eol=dict(unk["eol"], fetched="2026-02-02"))])[INDEX]
    expect("index cites only the API fetch dates", "fetched on 2026-01-10," in idx and "2026-02-02" not in idx)
    cli = json.loads(json.dumps(unk))
    cli.update({"shell": "none", "patch_commands": [], "os_release": None,
                "identify": [{"command": "Settings > About", "shows": "Version"}]})
    page = build([cli])[OUT + "/acme.md"]
    expect("no-shell page uses the plain identify heading",
           "\n## Identify the version\n" in page and "/etc/os-release" not in page and "```" not in page)

    e = dict(good["eol"])
    expect("status: active support ended, security running", status(e, "point") == "Security support only")
    e.update({"support_end": "2026-06-01"})
    expect("status: supported", status(e, "point") == "Supported")
    e.update({"security_end": "2026-01-10", "extended_end": "2030-01-01"})
    expect("status: ends on the fetch day counts as ended", status(e, "point") == "Extended support only")
    e.update({"extended_end": None})
    expect("status: ended", status(e, "point") == "Ended")
    expect("status: rolling", status(dict(good["eol"], source="rolling"), "rolling") == "Rolling release")

    pages = build([good, two])
    expect("one page per system plus the index", sorted(pages) == sorted([OUT + "/acme.md", INDEX]))
    page = pages[OUT + "/acme.md"]
    expect("page carries the markers", page.startswith(START + "\n") and page.rstrip().endswith(END))
    for h in ("## Versions and support", "## Where its advisories live", "## How it patches",
              "## Identify it from a terminal", "## Hardening", "## On the Intelligence Hub"):
        expect("page has " + h, ("\n" + h + "\n") in page)
    expect("each table has a row per version", page.count("\n| 1 |") == 3 and page.count("\n| 2 |") == 3)
    expect("links are root-relative", all(t.startswith("/") or t.startswith("https://")
                                          for t in re.findall(r"\]\(([^)]+)\)", page)))
    expect("no em dash in output", all(EM_DASH not in t for t in pages.values()))
    expect("rendering is stable", build([good, two]) == pages)
    expect("index links the page", "](/operating-systems/acme.md)" in pages[INDEX])
    u2 = json.loads(json.dumps(unk))
    u2["id"], u2["version"] = "acme-2", "2"
    expect("a note shared by every version is written once",
           build([unk, u2])[OUT + "/acme.md"].count("No vendor page gives a date.") == 1)
    other = json.loads(json.dumps(two))
    other["eol"].update({"product": "other", "url": EOL_API.format(product="other")})
    expect("two API products are both cited",
           EOL_API.format(product="other") in build([good, other])[OUT + "/acme.md"])

    api = {"acme": [{"cycle": "1", "releaseDate": "2024-02-02", "eol": "2028-01-01", "support": True,
                     "extendedSupport": False, "latest": "1.5"}]}
    rows = [json.loads(json.dumps(good))]
    expect("refresh applies API values", apply_eol(rows, api, "2026-02-01") == [] and rows[0]["eol"]["release_date"]
           == "2024-02-02" and rows[0]["eol"]["support_end"] is None and rows[0]["eol"]["latest"] == "1.5"
           and rows[0]["eol"]["fetched"] == "2026-02-01")
    expect("refresh reports a vanished cycle", apply_eol([json.loads(json.dumps(two))], api, "2026-02-01") != [])
    expect("round trip through JSONL", load(dump([good, two])) == [good, two])

    print(("FAIL: " + str(len(fails)) + " planted case(s)") if fails else "OK: all planted cases pass")
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="exit 1 if any page is stale, missing or an orphan")
    g.add_argument("--self-test", action="store_true", help="run the planted cases")
    g.add_argument("--refresh-eol", action="store_true", help="re-read endoflife.date (network)")
    a = ap.parse_args()
    try:
        if a.self_test:
            return self_test()
        if a.refresh_eol:
            return refresh_eol()
        return run(a.check)
    except CatalogError as e:
        print("FAIL: " + str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
