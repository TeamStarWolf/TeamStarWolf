#!/usr/bin/env python3
"""Build the shared entity vocabulary: data/vocab/entities.jsonl and its JSON copy
data/vocab/vocabulary.json.

One record per vendor, product, threat actor, malware family (ATT&CK software) and
sector, each with a stable id (`vendor:fortinet`, `product:cisco-duo`, `actor:G0016`,
`malware:S0154`, `sector:energy`), a display label, the names a tagger may match, and
the library page that covers it (`library_path`, `library_anchor`, `library_url`). The
Intelligence Hub vendors a pinned copy and tags its items with these ids, so the two
sites agree on names and link to each other without either one computing slugs.

Sources (nothing here is typed into the output by hand):
    platforms/*.md                    every platform page (label = the page's H1)
    data/vendor_to_technique.jsonl    the vendor_normalized keys (`vendor_keys`)
    data/attack/groups.jsonl          actor rows (+ ics/ and mobile/ groups.jsonl)
    data/attack/software.jsonl        malware rows (+ ics/ and mobile/ software.jsonl)
    data/attack/superseded_by.jsonl   a revoked G/S id folds into its successor
    data/vocab/curated.jsonl          the curated vendor, product, non-ATT&CK actor and
                                      sector rows: KEV vendorProject spellings, which
                                      platform page each entity owns, explicit library
                                      pins (a page, optionally a heading)
    data/vocab/stop_aliases.jsonl     names a tagger must never match (ordinary words,
                                      command names, place and personal names)

Rules:
  * Every platform page must be claimed by exactly one curated row, and every
    vendor_to_technique key by exactly one row; the build fails otherwise.
  * ATT&CK rows are derived, never curated: a curated actor or malware row whose label
    is an ATT&CK name fails the build (use the ATT&CK row instead).
  * `match` = label + aliases + kev_vendor_project, minus `stop_aliases` (stop-list
    hits, and ATT&CK names shorter than 4 characters) and minus `ambiguous_aliases`
    (a name two entities of the same type both claim). A curated row may set `match`
    explicitly; the stop list still applies.
  * `library_anchor` is the docsify slug of `library_heading`, computed with
    check_docsify_links.docsify_slug over the page's own heading sequence (so a
    repeated heading gets its -1/-2 suffix). Every library_path must exist and every
    anchor must resolve.

vocabulary.json carries `generated_from` (the library commit the build ran on top of;
kept unchanged while the content is unchanged) and `entities_sha256` (LF-normalised
SHA-256 of entities.jsonl), so a consumer can pin and verify the copy it vendors.
generated_from is `git merge-base HEAD origin/main`, not HEAD: a rebuild on a pull
request branch would otherwise record a branch commit that the squash merge discards,
and consumers could not resolve it. Only when origin/main is unavailable (no remote,
shallow clone without it) does the build fall back to HEAD.

Usage:
    python scripts/build_vocab.py              # (re)write both files
    python scripts/build_vocab.py --check      # exit 1 if either committed file is stale
    python scripts/build_vocab.py --self-test  # planted cases for the build rules
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_docsify_links as cdl  # noqa: E402  (docsify slugger + anchor reader)
from attack_ids import ATTACK_RELEASE  # noqa: E402
from repo_files import tracked_files  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTITIES = "data/vocab/entities.jsonl"
VOCAB_JSON = "data/vocab/vocabulary.json"
CURATED = "data/vocab/curated.jsonl"
STOP = "data/vocab/stop_aliases.jsonl"
V2T = "data/vendor_to_technique.jsonl"
SUPERSEDED = "data/attack/superseded_by.jsonl"
PLATFORMS = "platforms"
DOMAINS = ("enterprise", "ics", "mobile")
GROUP_FILES = {"enterprise": "data/attack/groups.jsonl", "ics": "data/attack/ics/groups.jsonl",
               "mobile": "data/attack/mobile/groups.jsonl"}
SOFTWARE_FILES = {"enterprise": "data/attack/software.jsonl", "ics": "data/attack/ics/software.jsonl",
                  "mobile": "data/attack/mobile/software.jsonl"}
SITE = "https://teamstarwolf.github.io/TeamStarWolf/"
SCHEMA_VERSION = 1

TYPES = ("vendor", "product", "actor", "malware", "sector")
STOP_REASONS = ("ordinary-word", "command-name", "personal-name", "place-name", "legitimate-service")
MIN_ATTACK_MATCH = 4   # ATT&CK names shorter than this (at, Net, cmd, WCE) are never matched
# The most frequent vendorProject values in the CISA KEV catalog; the vocabulary must keep them.
REQUIRED_IDS = ("vendor:microsoft", "vendor:cisco", "vendor:apple", "vendor:adobe", "vendor:google",
                "vendor:oracle", "vendor:apache", "vendor:ivanti", "vendor:fortinet", "vendor:citrix",
                "vendor:vmware", "vendor:sonicwall")

FIELDS = ("id", "type", "label", "aliases", "match", "stop_aliases", "ambiguous_aliases",
          "kev_vendor_project", "vendor", "attack_id", "attack_domains", "software_type",
          "superseded_ids", "vendor_keys", "library_path", "library_anchor", "library_url",
          "source", "reviewed_at")
CURATED_FIELDS = ("id", "type", "label", "aliases", "match", "kev_vendor_project", "vendor",
                  "platform_page", "library", "library_heading", "vendor_keys", "basis",
                  "reviewed_at")
ID_RE = re.compile(r"^(vendor|product|actor|malware|sector):[a-z0-9][a-z0-9-]*$")
ATTACK_ID_RE = re.compile(r"^(actor|malware):[GS]\d{4}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class VocabError(Exception):
    pass


# ----------------------------------------------------------------------------- helpers

def _fold(s: str) -> str:
    return s.casefold().strip()


def _uniq_sorted(names) -> list[str]:
    """Unique by case-folded form (first spelling wins), sorted case-insensitively."""
    seen = {}
    for n in names:
        if isinstance(n, str) and n.strip() and _fold(n) not in seen:
            seen[_fold(n)] = n.strip()
    return sorted(seen.values(), key=lambda s: (_fold(s), s))


def heading_slugs(text: str) -> list[tuple[str, str]]:
    """(heading text, docsify slug) for every heading of a page, in order; mirrors
    check_docsify_links.anchors_of so repeated headings get the same -1/-2 suffixes."""
    out, seen = [], {}
    prev = prev_raw = None
    for _, line, in_fence, raw in cdl.code_free_lines(text):
        if in_fence:
            prev = None
            continue
        m = cdl.ATX_RE.match(raw)
        title = None
        if m:
            title = m.group(2)
        elif (prev is not None and prev.strip() and cdl.SETEXT_RE.match(raw)
              and not prev.lstrip().startswith(("|", ">", "-", "*", "#", "<"))):
            title = prev_raw.strip()
        if title is not None:
            cfg = re.search(r"""\s*:id=([^\s'"]+)""", title)
            if cfg:
                cdl.docsify_slug(cdl.heading_html(title[:cfg.start()]), seen)  # still counts
                out.append((title[:cfg.start()].strip(), cfg.group(1)))
            else:
                out.append((title.strip(), cdl.docsify_slug(cdl.heading_html(title), seen)))
        prev, prev_raw = line, raw
    return out


def first_h1(text: str) -> str | None:
    for _, _line, in_fence, raw in cdl.code_free_lines(text):
        if in_fence:
            continue
        m = cdl.ATX_RE.match(raw)
        if m and len(m.group(1)) == 1:
            return m.group(2).strip()
    return None


def library_url(path: str | None, anchor: str | None) -> str | None:
    if not path:
        return None
    route = path[:-3] if path.endswith(".md") else path
    return SITE + "#" + route + ("?id=" + anchor if anchor else "")


# ----------------------------------------------------------------------------- the build

def build(src: dict) -> list[dict]:
    """Pure build over the collected sources (see collect()); raises VocabError listing
    every problem. `src` keys: pages {rel: h1}, v2t {key: name}, groups {domain: rows},
    software {domain: rows}, superseded rows, curated rows, stop rows, exists(rel),
    slug(rel, heading) -> slug | None, anchors(rel) -> set."""
    errors: list[str] = []

    # stop list
    stop = {}
    for r in src["stop"]:
        a, why = r.get("alias"), r.get("reason")
        if not isinstance(a, str) or not a.strip() or why not in STOP_REASONS:
            errors.append(f"{STOP}: bad row {r!r} (alias + reason in {STOP_REASONS})")
            continue
        stop[_fold(a)] = a

    # revoked/deprecated G and S ids -> terminal successor (None = deprecated)
    sup = {r["old_id"]: r.get("new_id") for r in src["superseded"]
           if isinstance(r.get("old_id"), str) and r["old_id"][:1] in ("G", "S")}

    def resolve(i):
        seen = set()
        while i in sup and i not in seen:
            seen.add(i)
            i = sup[i]
            if i is None:
                return None
        return i

    entities: dict[str, dict] = {}
    attack_names: dict[str, set] = {"actor": set(), "malware": set()}

    # ---- ATT&CK actors and malware (derived)
    for etype, files, key, folder in (("actor", src["groups"], "group_id", "groups"),
                                      ("malware", src["software"], "software_id", "software")):
        merged: dict[str, dict] = {}
        for dom in DOMAINS:
            for r in files.get(dom, []):
                old = r.get(key)
                aid = resolve(old)
                if aid is None:
                    continue  # deprecated with no successor
                e = merged.setdefault(aid, {"names": [], "domains": set(), "superseded": set(),
                                            "label": None, "software_type": None, "source": None})
                if aid == old and e["label"] is None:
                    e["label"] = r.get("name")
                    e["software_type"] = r.get("type")
                    e["source"] = (GROUP_FILES if etype == "actor" else SOFTWARE_FILES)[dom]
                if aid != old:
                    e["superseded"].add(old)
                e["names"] += [r.get("name")] + list(r.get("aliases") or [])
                e["domains"].add(dom)
        for aid, e in sorted(merged.items()):
            if not e["label"]:
                errors.append(f"{etype} {aid}: successor named by superseded_by.jsonl has no row")
                continue
            lib = f"mitre/{folder}/{aid}.md"
            label = e["label"]
            names = _uniq_sorted(e["names"])
            attack_names[etype].update(_fold(n) for n in names)
            entities[f"{etype}:{aid}"] = {
                "id": f"{etype}:{aid}", "type": etype, "label": label,
                "aliases": [n for n in names if _fold(n) != _fold(label)],
                "_explicit_match": None, "_attack": True,
                "kev_vendor_project": [], "vendor": None, "attack_id": aid,
                "attack_domains": [d for d in DOMAINS if d in e["domains"]],
                "software_type": e["software_type"] if etype == "malware" else None,
                "superseded_ids": sorted(e["superseded"]), "vendor_keys": [],
                "library_path": "/" + lib if src["exists"](lib) else None,
                "library_anchor": None, "source": e["source"], "reviewed_at": None,
            }

    # ---- curated vendors, products, non-ATT&CK actors, sectors
    page_owner: dict[str, str] = {}
    key_owner: dict[str, str] = {}
    curated_ids = set()
    for r in src["curated"]:
        cid = r.get("id")
        where = f"{CURATED} {cid!r}"
        if tuple(r.keys()) != CURATED_FIELDS:
            errors.append(f"{where}: fields must be exactly {list(CURATED_FIELDS)}")
            continue
        if not isinstance(cid, str) or not ID_RE.match(cid) or ATTACK_ID_RE.match(cid):
            errors.append(f"{where}: id must be <type>:<lowercase-slug> (ATT&CK ids are derived)")
            continue
        if r["type"] not in TYPES or not cid.startswith(r["type"] + ":"):
            errors.append(f"{where}: type {r['type']!r} must be in {TYPES} and prefix the id")
            continue
        if cid in curated_ids or cid in entities:
            errors.append(f"{where}: duplicate id")
            continue
        curated_ids.add(cid)
        if not isinstance(r["reviewed_at"], str) or not DATE_RE.match(r["reviewed_at"]):
            errors.append(f"{where}: reviewed_at must be YYYY-MM-DD")
        for f in ("aliases", "kev_vendor_project", "vendor_keys"):
            if not isinstance(r[f], list) or not all(isinstance(x, str) and x.strip() for x in r[f]):
                errors.append(f"{where}: {f} must be a list of non-empty strings")
        if r["match"] is not None and (not isinstance(r["match"], list)
                                       or not all(isinstance(x, str) and x.strip() for x in r["match"])):
            errors.append(f"{where}: match must be null or a list of non-empty strings")
        page = r["platform_page"]
        label = r["label"]
        lib = r["library"]
        if page is not None:
            if page not in src["pages"]:
                errors.append(f"{where}: platform_page {page} is not a platforms/ page")
            elif page in page_owner:
                errors.append(f"{where}: platform_page {page} is already owned by {page_owner[page]}")
            else:
                page_owner[page] = cid
                label = label or src["pages"][page]
                lib = lib or page
        if not isinstance(label, str) or not label.strip():
            errors.append(f"{where}: label is required (or a platform_page whose H1 supplies it)")
            continue
        if r["type"] in ("actor", "malware") and _fold(label) in attack_names[r["type"]]:
            errors.append(f"{where}: {label!r} is an ATT&CK {r['type']} name; drop the curated row "
                          f"and use the ATT&CK-derived one")
        for k in r["vendor_keys"]:
            if k not in src["v2t"]:
                errors.append(f"{where}: vendor_key {k!r} is not a vendor_normalized value in {V2T}")
            elif k in key_owner:
                errors.append(f"{where}: vendor_key {k!r} is already owned by {key_owner[k]}")
            else:
                key_owner[k] = cid
        anchor = None
        if lib is not None:
            if not src["exists"](lib):
                errors.append(f"{where}: library {lib} does not exist")
                lib = None
            elif r["library_heading"] is not None:
                anchor = src["slug"](lib, r["library_heading"])
                if anchor is None:
                    errors.append(f"{where}: {lib} has no heading {r['library_heading']!r}")
        elif r["library_heading"] is not None:
            errors.append(f"{where}: library_heading needs a library page")
        entities[cid] = {
            "id": cid, "type": r["type"], "label": label.strip(),
            "aliases": [a for a in _uniq_sorted(r["aliases"]) if _fold(a) != _fold(label)],
            "_explicit_match": r["match"], "_attack": False,
            "kev_vendor_project": sorted(set(r["kev_vendor_project"])), "vendor": r["vendor"],
            "attack_id": None, "attack_domains": [], "software_type": None, "superseded_ids": [],
            "vendor_keys": sorted(set(r["vendor_keys"])),
            "library_path": "/" + lib if lib else None, "library_anchor": anchor,
            "source": page or CURATED, "reviewed_at": r["reviewed_at"],
        }

    for page in sorted(set(src["pages"]) - set(page_owner)):
        errors.append(f"{page}: no row in {CURATED} claims this platform page "
                      f"(add one with platform_page set)")
    for k in sorted(set(src["v2t"]) - set(key_owner)):
        errors.append(f"{V2T}: vendor_normalized {k!r} ({src['v2t'][k]}) is in no curated row's vendor_keys")
    for e in entities.values():
        v = e["vendor"]
        if v is not None and (v not in entities or entities[v]["type"] != "vendor"):
            errors.append(f"{e['id']}: vendor {v!r} is not a vendor row")
        if v is not None and e["type"] != "product":
            errors.append(f"{e['id']}: only product rows name a vendor")
    for rid in REQUIRED_IDS:
        if rid not in entities:
            errors.append(f"required top-KEV vendor {rid} is missing from {CURATED}")

    # ---- match / stop / ambiguity
    for e in entities.values():
        names = [e["label"]] + e["aliases"] + e["kev_vendor_project"]
        stopped = [n for n in names if _fold(n) in stop
                   or (e["_attack"] and len(n.strip()) < MIN_ATTACK_MATCH)]
        e["stop_aliases"] = _uniq_sorted(stopped)
        sf = {_fold(n) for n in stopped}
        cand = e["_explicit_match"] if e["_explicit_match"] is not None else names
        e["match"] = [n for n in _uniq_sorted(cand) if _fold(n) not in sf]
    owners: dict[tuple, set] = {}
    for e in entities.values():
        for n in e["match"]:
            owners.setdefault((e["type"], _fold(n)), set()).add(e["id"])
    for e in entities.values():
        amb = [n for n in e["match"] if len(owners[(e["type"], _fold(n))]) > 1]
        e["ambiguous_aliases"] = amb
        e["match"] = [n for n in e["match"] if n not in amb]

    # ---- library links resolve
    for e in entities.values():
        p = e["library_path"]
        e["library_url"] = library_url(p, e["library_anchor"])
        if p and e["library_anchor"] and e["library_anchor"] not in src["anchors"](p[1:]):
            errors.append(f"{e['id']}: anchor {e['library_anchor']!r} does not resolve on {p}")

    if errors:
        raise VocabError("\n".join(errors))
    return [{k: e[k] for k in FIELDS} for _, e in sorted(entities.items())]


# ----------------------------------------------------------------------------- IO

def _read_jsonl(rel: str) -> list[dict]:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def collect() -> dict:
    tracked = set(tracked_files())

    def exists(rel):
        return rel in tracked or os.path.isfile(os.path.join(ROOT, rel))

    def text(rel):
        return cdl.read_text(rel) or ""

    pages = {}
    for name in sorted(os.listdir(os.path.join(ROOT, PLATFORMS))):
        rel = f"{PLATFORMS}/{name}"
        if name.endswith(".md") and not name.startswith("_") and name != "README.md":
            h1 = first_h1(text(rel))
            if not h1:
                raise VocabError(f"{rel}: no H1 heading to label the entity with")
            pages[rel] = h1
    v2t = {}
    for r in _read_jsonl(V2T):
        v2t.setdefault(r["vendor_normalized"], r["vendor"])

    def slug(rel, heading):
        for title, s in heading_slugs(text(rel)):
            if title == heading:
                return s
        return None

    return {
        "pages": pages, "v2t": v2t,
        "groups": {d: _read_jsonl(p) for d, p in GROUP_FILES.items()},
        "software": {d: _read_jsonl(p) for d, p in SOFTWARE_FILES.items()},
        "superseded": _read_jsonl(SUPERSEDED),
        "curated": _read_jsonl(CURATED), "stop": _read_jsonl(STOP),
        "exists": exists, "slug": slug, "anchors": cdl.anchors_of,
    }


def render_jsonl(rows: list[dict]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


def payload(rows: list[dict], entities_text: str) -> dict:
    data = entities_text.encode("utf-8")
    counts = {t: sum(1 for r in rows if r["type"] == t) for t in TYPES}
    return {
        "_comment": ("Generated by scripts/build_vocab.py: do not edit by hand. A JSON copy of "
                     "data/vocab/entities.jsonl; entities_sha256 is the LF-normalised SHA-256 of that "
                     "file. generated_from is the library commit the build ran on top of. Field "
                     "meanings: data/VOCABULARIES.md."),
        "schema_version": SCHEMA_VERSION,
        "attack_release": ATTACK_RELEASE,
        "site": SITE,
        "entities_path": ENTITIES,
        "entities_sha256": hashlib.sha256(data).hexdigest(),
        "entities_bytes": len(data),
        "entity_count": len(rows),
        "counts": counts,
        "types": list(TYPES),
        "inputs": [PLATFORMS + "/*.md", V2T] + list(GROUP_FILES.values())
                  + list(SOFTWARE_FILES.values()) + [SUPERSEDED, CURATED, STOP],
        "entities": rows,
    }


def render_json(doc: dict) -> str:
    """Pretty header, one compact entity per line (valid JSON, readable diffs)."""
    head = {k: v for k, v in doc.items() if k != "entities"}
    lines = json.dumps(head, indent=2, ensure_ascii=False).rstrip("}").rstrip().rstrip("\n")
    body = ",\n".join("    " + json.dumps(r, ensure_ascii=False) for r in doc["entities"])
    return lines + ',\n  "entities": [\n' + body + "\n  ]\n}\n"


def _git(args: list[str]) -> tuple[int, str]:
    out = subprocess.run(["git"] + args, cwd=ROOT, capture_output=True, text=True)
    return out.returncode, out.stdout.strip()


def base_commit(git=_git) -> str:
    """The commit generated_from records: the merge base of HEAD and origin/main.

    Rule: never record a pull-request branch commit. A squash merge drops branch
    commits, so a SHA taken from `git rev-parse HEAD` on a branch would not resolve
    on main afterwards. The merge base is always a main commit. HEAD is the fallback
    only when origin/main cannot be resolved (for example a clone with no remote).
    The self-test covers all three cases.
    """
    for args in (["merge-base", "HEAD", "origin/main"], ["rev-parse", "HEAD"]):
        rc, sha = git(args)
        if rc == 0 and re.fullmatch(r"[0-9a-f]{40}", sha):
            return sha
    raise VocabError("cannot read the base commit (git merge-base HEAD origin/main, "
                     "then git rev-parse HEAD)")


def _read(rel: str) -> str | None:
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


def _committed_doc() -> dict | None:
    t = _read(VOCAB_JSON)
    try:
        return json.loads(t) if t is not None else None
    except json.JSONDecodeError:
        return None


def _without_sha(doc: dict) -> dict:
    return {k: v for k, v in doc.items() if k != "generated_from"}


def outputs() -> tuple[str, dict]:
    rows = build(collect())
    text = render_jsonl(rows)
    return text, payload(rows, text)


def with_generated_from(doc: dict, sha: str) -> dict:
    out = {}
    for k, v in doc.items():
        out[k] = v
        if k == "schema_version":
            out["generated_from"] = sha
    return out


def main_build() -> int:
    text, doc = outputs()
    old = _committed_doc()
    if old and re.fullmatch(r"[0-9a-f]{40}", str(old.get("generated_from"))) and _without_sha(old) == doc:
        sha = old["generated_from"]
    else:
        sha = base_commit()
    os.makedirs(os.path.join(ROOT, "data", "vocab"), exist_ok=True)
    with open(os.path.join(ROOT, ENTITIES), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    with open(os.path.join(ROOT, VOCAB_JSON), "w", encoding="utf-8", newline="\n") as f:
        f.write(render_json(with_generated_from(doc, sha)))
    print(f"wrote {ENTITIES} and {VOCAB_JSON}: {doc['entity_count']} entities "
          + ", ".join(f"{n} {t}" for t, n in doc["counts"].items()) + f" (generated_from {sha[:12]})")
    return 0


def main_check() -> int:
    text, doc = outputs()
    problems = []
    if _read(ENTITIES) != text:
        problems.append(f"{ENTITIES} differs from what the sources produce")
    old = _committed_doc()
    if old is None:
        problems.append(f"{VOCAB_JSON} is missing or not valid JSON")
    else:
        if not re.fullmatch(r"[0-9a-f]{40}", str(old.get("generated_from"))):
            problems.append(f"{VOCAB_JSON}: generated_from must be a 40-character commit SHA")
        if _without_sha(old) != doc:
            problems.append(f"{VOCAB_JSON} differs from what the sources produce")
        elif _read(VOCAB_JSON) != render_json(with_generated_from(doc, old["generated_from"])):
            problems.append(f"{VOCAB_JSON} is not in the generated layout")
    if problems:
        print("STALE: " + "; ".join(problems) + ". Run python scripts/build_vocab.py and commit both files.")
        return 1
    print(f"OK: {ENTITIES} and {VOCAB_JSON} match the sources ({doc['entity_count']} entities: "
          + ", ".join(f"{n} {t}" for t, n in doc["counts"].items()) + ")")
    return 0


# ----------------------------------------------------------------------------- self-test

def self_test() -> int:
    fails = []

    def expect(name, cond):
        if not cond:
            fails.append(name)

    # docsify slugs over a page's heading sequence
    page = ("# Title\n\n## VMware ESXi / vSphere Hardening\n\n```\n# not a heading\n```\n"
            "## A & B\n## 2026 notes\n## Repeat\n## Repeat\n")
    slugs = dict((t, s) for t, s in heading_slugs(page))
    expect("slug punctuation", slugs.get("VMware ESXi / vSphere Hardening") == "vmware-esxi-vsphere-hardening")
    expect("slug ampersand", slugs.get("A & B") == "a-amp-b")
    expect("slug leading digit", slugs.get("2026 notes") == "_2026-notes")
    expect("slug duplicate", [s for t, s in heading_slugs(page) if t == "Repeat"] == ["repeat", "repeat-1"])
    expect("fenced line is not a heading", "not a heading" not in slugs)
    expect("library_url", library_url("/platforms/x.md", "a-b") == SITE + "#/platforms/x?id=a-b")

    def cur(id, label=None, **kw):
        row = dict.fromkeys(CURATED_FIELDS)
        row.update({"id": id, "type": id.split(":")[0], "label": label, "aliases": [],
                    "kev_vendor_project": [], "vendor_keys": [], "reviewed_at": "2026-11-03"})
        row.update(kw)
        return {k: row[k] for k in CURATED_FIELDS}

    required = [cur(i, i.split(":")[1].title()) for i in REQUIRED_IDS]

    def src(**over):
        base = {
            "pages": {"platforms/acme.md": "Acme Shield"},
            "v2t": {"acme-shield": "Acme Shield"},
            "groups": {"enterprise": [
                {"group_id": "G0001", "name": "Axiom", "aliases": ["Axiom", "Group 72", "Thrip"]},
                {"group_id": "G0002", "name": "Moafee", "aliases": ["Moafee", "Thrip"]},
                {"group_id": "G9998", "name": "Old Axiom", "aliases": ["Old Axiom"]},
                {"group_id": "G9997", "name": "Gone", "aliases": ["Gone"]}],
                "ics": [{"group_id": "G0001", "name": "Axiom", "aliases": ["Axiom"]}], "mobile": []},
            "software": {"enterprise": [
                {"software_id": "S0002", "name": "Net", "type": "tool", "aliases": ["Net", "net.exe"]},
                {"software_id": "S0003", "name": "Silence", "type": "malware", "aliases": ["Silence"]}],
                "ics": [], "mobile": [{"software_id": "S0004", "name": "BRATA", "type": "malware"}]},
            "superseded": [{"old_id": "G9998", "new_id": "G0001", "reason": "revoked"},
                           {"old_id": "G9997", "new_id": None, "reason": "deprecated"},
                           {"old_id": "T1000", "new_id": None, "reason": "deprecated"}],
            "curated": required + [
                cur("vendor:acme", "Acme", kev_vendor_project=["Acme Corp"], match=None),
                cur("product:acme-shield", None, platform_page="platforms/acme.md", vendor="vendor:acme",
                    vendor_keys=["acme-shield"], library_heading="Setup"),
                cur("sector:energy", "Energy", aliases=["Energy Sector"])],
            "stop": [{"alias": "silence", "reason": "ordinary-word"}],
            "exists": lambda rel: rel in ("platforms/acme.md", "mitre/groups/G0001.md"),
            "slug": lambda rel, h: "setup" if h == "Setup" else None,
            "anchors": lambda rel: {"setup"},
        }
        base.update(over)
        return base

    rows = {r["id"]: r for r in build(src())}
    ax = rows.get("actor:G0001", {})
    expect("revoked id folds into successor", "actor:G9998" not in rows and ax.get("superseded_ids") == ["G9998"])
    expect("successor gains the revoked name", "Old Axiom" in ax.get("aliases", []))
    expect("deprecated id dropped", "actor:G9997" not in rows)
    expect("domains merged", ax.get("attack_domains") == ["enterprise", "ics"])
    expect("library path only when the page exists", ax.get("library_path") == "/mitre/groups/G0001.md"
           and rows["actor:G0002"]["library_path"] is None)
    expect("intra-type ambiguity leaves match", "Thrip" in ax.get("ambiguous_aliases", [])
           and "Thrip" not in ax.get("match", []))
    expect("short ATT&CK name stopped", rows["malware:S0002"]["stop_aliases"] == ["Net"]
           and rows["malware:S0002"]["match"] == ["net.exe"])
    expect("stop list applies", rows["malware:S0003"]["match"] == [] and rows["malware:S0003"]["stop_aliases"] == ["Silence"])
    expect("software_type kept", rows["malware:S0002"]["software_type"] == "tool")
    expect("mobile-only software kept", rows.get("malware:S0004", {}).get("attack_domains") == ["mobile"])
    shield = rows.get("product:acme-shield", {})
    expect("platform H1 labels the row", shield.get("label") == "Acme Shield"
           and shield.get("library_path") == "/platforms/acme.md" and shield.get("library_anchor") == "setup")
    expect("kev spelling is matchable", rows["vendor:acme"]["match"] == ["Acme", "Acme Corp"])

    def fails_with(fragment, **over):
        try:
            build(src(**over))
        except VocabError as e:
            return fragment in str(e)
        return False

    expect("unclaimed platform page fails", fails_with("claims this platform page",
           pages={"platforms/acme.md": "Acme Shield", "platforms/new.md": "New"}))
    expect("unclaimed vendor key fails", fails_with("is in no curated row's vendor_keys",
           v2t={"acme-shield": "Acme Shield", "other": "Other"}))
    expect("curated ATT&CK name fails", fails_with("is an ATT&CK actor name",
           curated=src()["curated"] + [cur("actor:axiom", "Axiom")]))
    expect("bad vendor ref fails", fails_with("is not a vendor row",
           curated=src()["curated"] + [cur("product:x", "X", vendor="vendor:nope")]))
    expect("missing heading fails", fails_with("has no heading",
           curated=src()["curated"] + [cur("product:y", "Y", library="platforms/acme.md", library_heading="Nope")]))
    expect("missing library page fails", fails_with("does not exist",
           curated=src()["curated"] + [cur("product:z", "Z", library="platforms/none.md")]))
    expect("required vendor enforced", fails_with("vendor:microsoft is missing",
           curated=[r for r in src()["curated"] if r["id"] != "vendor:microsoft"]))
    expect("doubly claimed page fails", fails_with("is already owned by",
           curated=src()["curated"] + [cur("vendor:dup", "Dup", platform_page="platforms/acme.md")]))

    doc = payload(list(rows.values()), render_jsonl(list(rows.values())))
    rendered = render_json(with_generated_from(doc, "0" * 40))
    expect("vocabulary.json is valid JSON and round-trips", _without_sha(json.loads(rendered)) == doc)

    # generated_from rule: the merge base with origin/main, HEAD only as a fallback
    base, head = "b" * 40, "c" * 40
    def fake_git(merge_base_ok, head_ok=True):
        def git(args):
            if args[0] == "merge-base":
                return (0, base) if merge_base_ok else (128, "")
            return (0, head) if head_ok else (128, "")
        return git
    expect("generated_from is the merge base on a branch", base_commit(fake_git(True)) == base)
    expect("generated_from falls back to HEAD without origin/main",
           base_commit(fake_git(False)) == head)
    try:
        base_commit(fake_git(False, head_ok=False))
        expect("no commit at all fails", False)
    except VocabError:
        pass

    if fails:
        print("SELF-TEST FAILED: " + "; ".join(fails))
        return 1
    print("OK: build_vocab self-test (slugs, revoked folding, stop/short/ambiguous names, "
          "curation errors, JSON layout, generated_from base rule)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="exit 1 if a committed file is stale")
    g.add_argument("--self-test", action="store_true", help="run the planted cases")
    a = ap.parse_args()
    try:
        if a.self_test:
            return self_test()
        return main_check() if a.check else main_build()
    except VocabError as e:
        print("ERROR: build_vocab:\n" + str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
