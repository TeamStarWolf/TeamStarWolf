# Data Vocabularies

The controlled vocabularies used by the crosswalk / edge datasets, and the shared
entity vocabulary (vendors, products, actors, malware, sectors) the Intelligence Hub
tags with. These are the
allowed value sets a consumer (e.g. ATT&CK-Navi's cross-framework graph) can rely
on. Library-defined vocabularies are stable and owned here; MITRE-derived
vocabularies track the upstream framework and are updated when it changes. The
`confidence`, `coverage_type`, `mapping_type`, `edge_type`, `relation`, and
`reason` values below are enforced in CI by `scripts/validate_jsonl.py`; a value
outside the locked set fails the build. See [MANIFEST.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/MANIFEST.json) for
per-file provenance and [../THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).

## Edge / crosswalk vocabularies (library-defined: locked)

| Field | Files | Allowed values | Meaning |
|---|---|---|---|
| `confidence` | control_to_technique, vendor_to_technique, vendor_to_control | `high`, `medium`, `low` | Mapping confidence. control_to_technique + vendor_to_control are all `high` (direct CTID / authored mappings); vendor_to_technique spans all three (derived join). |
| `edge_type` | control_to_technique / vendor_to_technique / vendor_to_control | `control_mitigates_technique` / `vendor_covers_technique` / `vendor_satisfies_control` | The relationship the row asserts (one value per file). |
| `mapping_type` | control_to_technique | `mitigates` | The CTID mapping relationship. |
| `coverage_type` | vendor_to_technique | `prevent`, `detect`, `respond`, `identify`, `prevent_detect` | How a vendor control covers a technique (NIST CSF-style function; `prevent_detect` = both). |
| `ctid_source` | control_to_technique | `nist800-53-r5` | The CTID Mappings Explorer source dataset. |
| `reason` | superseded_by | `revoked`, `deprecated` | Why an ATT&CK id was retired: `revoked` (replaced by `new_id`; may be null if the replacement is itself a dead-end) vs `deprecated` (removed, `new_id` null). |

> Known gap: `vendor_to_control.pipeline_stage` is present in the schema but empty in every row; populate or drop it in a future pass. Not currently consumed.

## Framework-derived vocabularies (track upstream)

| Field | Files | Allowed values | Source |
|---|---|---|---|
| `relation` | technique_to_d3fend | analyzes, authenticates, blocks, configures, creates, deletes, detects, disables, encrypts, erases, evaluates, filters, hardens, inventories, isolates, limits, manages, maps, may-access, may-contain, modifies, monitors, neutralizes, obfuscates, quarantines, reads, regenerates, restores, restricts, spoofs, strengthens, suspends, terminates, updates, use-limits, uses, validates, verifies | MITRE D3FEND digital-artifact relationships |
| `abstraction` | weaknesses/capec | Meta, Standard, Detailed | MITRE CAPEC |
| `abstraction` | weaknesses/cwe | Pillar, Class, Base, Variant, Compound | MITRE CWE |
| `status` | weaknesses/capec | Draft, Usable, Stable, Obsolete, Deprecated | MITRE CAPEC |
| `status` | weaknesses/cwe | Draft, Incomplete, Stable, Deprecated | MITRE CWE |
| `likelihood` | weaknesses/capec | High, Medium, Low (or empty) | MITRE CAPEC (Likelihood Of Attack) |
| `typical_severity` | weaknesses/capec | Very High, High, Medium, Low, Very Low (or empty) | MITRE CAPEC |

## Entity vocabulary (library-defined: generated)

The library and the [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) talk about the same vendors, products, threat actors, malware families and sectors. `data/vocab/entities.jsonl` gives each one a stable id, so a Hub item tagged `vendor:fortinet` and the library's Fortinet page point at the same thing, and the Hub links to library pages without computing a slug of its own.

`scripts/build_vocab.py` writes the file and a JSON copy, `data/vocab/vocabulary.json`. The copy adds `generated_from` (the library commit the build ran on top of, kept while the content does not change; it is `git merge-base HEAD origin/main`, so a rebuild on a pull request branch still records a commit on main that survives the squash merge, and only a clone without origin/main falls back to HEAD) and `entities_sha256` (the SHA-256 of entities.jsonl with LF line endings), so a consumer can pin the copy it keeps and verify it. Neither file is edited by hand: change a source, then rebuild. CI runs `build_vocab.py --check` and `--self-test`, and `validate_jsonl.py` checks every id, ATT&CK id, vendor reference, library path and anchor.

| Type | Id | Where the rows come from |
|---|---|---|
| `vendor`, `product` | `vendor:<slug>`, `product:<slug>` | `data/vocab/curated.jsonl`. Every page under platforms/ is claimed by exactly one row (the page's H1 is the label), every `vendor_normalized` key of data/vendor_to_technique.jsonl by exactly one row, and the most frequent `vendorProject` values in the CISA KEV catalog (catalog 2026.10.30) each have a row carrying the exact KEV spellings. The build fails on an unclaimed page or key. |
| `actor` | `actor:<G id>`, or `actor:<slug>` for a name ATT&CK does not track | ATT&CK groups of the pinned release (Enterprise, ICS and Mobile `groups.jsonl`). Curated rows add actors outside ATT&CK, such as Storm-0940; a curated actor whose name ATT&CK already tracks fails the build. |
| `malware` | `malware:<S id>` | ATT&CK software of the pinned release, malware and tools alike (`software_type` says which). |
| `sector` | `sector:<slug>` | Curated: the locked list below. |

A revoked group or software id listed in data/attack/superseded_by.jsonl folds into its successor (it is kept in `superseded_ids` and its name joins the aliases); a deprecated one is dropped.

| Field | Meaning |
|---|---|
| `id` | `<type>:<slug>`, unique across the file. |
| `type` | `vendor`, `product`, `actor`, `malware` or `sector` (locked). |
| `label` | Display name. |
| `aliases` | Other names: ATT&CK aliases, former product names, KEV spellings that differ from the label. |
| `match` | Names a tagger may match: the label, aliases and KEV spellings, minus `stop_aliases` and `ambiguous_aliases`. A curated row may set it explicitly (Progress Software, so that the word "progress" never tags a vendor). |
| `stop_aliases` | Names that are never matched: an entry in `data/vocab/stop_aliases.jsonl` (ordinary words such as Silence, Carbon or Bitter, command names such as ipconfig, place and personal names), or an ATT&CK name shorter than four characters (at, Net, WCE). |
| `ambiguous_aliases` | Names that two entities of the same type both carry (Thrip names two ATT&CK groups). A tagger must not pick one of them. |
| `kev_vendor_project` | The exact CISA KEV `vendorProject` strings for this vendor or product. |
| `vendor` | For a product, the id of its vendor row; null otherwise. |
| `attack_id`, `attack_domains` | The ATT&CK id and the domains (`enterprise`, `ics`, `mobile`) it appears in; null and empty for curated rows. |
| `software_type` | `malware` or `tool` for ATT&CK software; null otherwise. |
| `superseded_ids` | Revoked ATT&CK ids folded into this row. |
| `vendor_keys` | The `vendor_normalized` keys of data/vendor_to_technique.jsonl this row stands for, so the crosswalk joins to the vocabulary. |
| `library_path`, `library_anchor` | The library page that covers the entity, `/`-prefixed from the repo root, and the docsify heading slug on it, computed with `check_docsify_links.docsify_slug` from the curated `library_heading`. Null where no page covers the entity yet. |
| `library_url` | The rendered site link, `https://teamstarwolf.github.io/TeamStarWolf/#/<page>?id=<anchor>`. |
| `source` | The page or data file the row came from. |
| `reviewed_at` | The date a person last reviewed a curated row; null for ATT&CK-derived rows. |

Sectors (locked): the 16 critical infrastructure sectors CISA lists, under their CISA names, plus two library additions.

| Id | Label |
|---|---|
| `sector:chemical` | Chemical |
| `sector:commercial-facilities` | Commercial Facilities |
| `sector:communications` | Communications |
| `sector:critical-manufacturing` | Critical Manufacturing |
| `sector:dams` | Dams |
| `sector:defense-industrial-base` | Defense Industrial Base |
| `sector:emergency-services` | Emergency Services |
| `sector:energy` | Energy |
| `sector:financial-services` | Financial Services |
| `sector:food-agriculture` | Food and Agriculture |
| `sector:government-facilities` | Government Services and Facilities |
| `sector:healthcare-public-health` | Healthcare and Public Health |
| `sector:information-technology` | Information Technology |
| `sector:nuclear` | Nuclear Reactors, Materials, and Waste |
| `sector:transportation` | Transportation Systems |
| `sector:water-wastewater` | Water and Wastewater |
| `sector:education` | Education (library addition) |
| `sector:retail` | Retail (library addition) |

To add a platform page or a vendor, add a row to `data/vocab/curated.jsonl` (set `platform_page` for a page), run `python scripts/build_vocab.py` and `python scripts/build_manifest.py`, and commit `curated.jsonl`, `entities.jsonl`, `vocabulary.json` and `data/MANIFEST.json` together.

Actor and malware names and aliases come from MITRE ATT&CK v20.0:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

*Last updated: 2026-11-03 | TeamStarWolf Cybersecurity Reference Library*
