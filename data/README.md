# Data

Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17.

> The machine-readable side of the library: MITRE framework objects and the relationships between them, as JSON Lines files (one JSON object per line), with a manifest that records each file's source, license, row count, and SHA-256.

## What is here

| Path | Contents | Upstream |
|---|---|---|
| `attack/` | ATT&CK Enterprise objects (techniques, groups, software, campaigns, mitigations, data components, detection strategies, analytics) and the edges between them: `group_to_technique`, `software_to_technique`, `mitigation_to_technique`, `technique_to_d3fend`, `technique_to_car`, `superseded_by` | MITRE ATT&CK v19.2, D3FEND, CAR |
| `attack/ics/`, `attack/mobile/` | The same core objects and group edges for ATT&CK for ICS and ATT&CK for Mobile | MITRE ATT&CK v19.2 |
| `attack/*_profiles.jsonl` | One row per technique, group, software entry, or campaign, with the lists and counts the pages use (tactics, platforms, mitigations, NIST controls, CAPEC patterns, detection strategies) | Derived by this library from the files above |
| `control_to_technique.jsonl` | NIST SP 800-53 Rev. 5 controls mapped to ATT&CK techniques | CTID Mappings Explorer (Apache-2.0) |
| `vendor_to_control.jsonl` | Products mapped to NIST controls | This library's editorial assessment ([CONTROLS_MAPPING.md](/CONTROLS_MAPPING.md)) |
| `vendor_to_technique.jsonl` | Products mapped to techniques, by joining the two files above | Derived |
| `ai/` | ATLAS tactics, techniques, and mitigations | MITRE ATLAS |
| `engage/` | Engage goals, approaches, activities, and their ATT&CK mappings | MITRE Engage |
| `fraud/` | F3 tactics and techniques | CTID F3 (Apache-2.0) |
| `weaknesses/` | CWE weaknesses and CAPEC attack patterns, with CAPEC's ATT&CK links | MITRE CWE, CAPEC |
| `generated/` | `stats.json` (headline counts) and `corpus_signal.jsonl` (the corpus-signal paragraphs on technique pages) | Written by scripts |
| `doc_meta.yaml` | The hand-written fields of each root reference's and learning path's header card, the recorded corrections and owner reviews, the overlap clusters, and the folds, read by `scripts/build_doc_meta.py` | This library |
| `doc_takeaways.yaml`, `doc_takeaways.draft.yaml` | Key takeaways: the ones the owner has reviewed (shown on the pages) and the drafts awaiting review (never shown) | This library |
| [EDGES.md](/data/EDGES.md) | The edge contract: source and target field, node types, and edge type of every relationship file | |
| [VOCABULARIES.md](/data/VOCABULARIES.md) | Allowed values for `edge_type`, `confidence`, `relation`, and other enumerated fields | |
| `MANIFEST.json` | Per-file path, rows, bytes, SHA-256, and provenance, plus the pinned upstream inputs | Written by `scripts/build_manifest.py` |

[THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md) gives the license and notice for each upstream. MITRE content stays under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) and the other frameworks' terms; this library's own derivations are MIT.

## How it is generated

- `scripts/build_attack_core.py` rebuilds the ATT&CK files under `attack/`, `attack/ics/`, and `attack/mobile/` from the ATT&CK v19.2 STIX bundles, pinned to a commit of `mitre-attack/attack-stix-data` and checked by SHA-256 before parsing. It also writes `superseded_by.jsonl` and patches `technique_profiles.jsonl` in place.
- `scripts/build_ctid_edges.py` normalizes `control_to_technique.jsonl` (the CTID rows as published, with tactics refreshed from the v19.2 profiles, stale revoked ids re-keyed to their successors, and duplicates dropped) and builds `vendor_to_technique.jsonl` by joining it with `vendor_to_control.jsonl`.
- `scripts/build_control_rollup.py` adds the parent-rolled NIST controls to each technique profile, and `scripts/backfill_capec_edges.py` adds the CAPEC edge from `weaknesses/capec.jsonl`.
- The ATLAS, Engage, F3, CWE, CAPEC, D3FEND, and CAR files are committed snapshots of their upstream releases. No script here re-fetches them. `scripts/validate_jsonl.py` checks every file: each line parses as a JSON object, ids and edge keys are unique, and every ATT&CK technique id is live or resolves to a live successor through `attack/superseded_by.jsonl`.
- `scripts/build_manifest.py` writes `MANIFEST.json`, and `scripts/build_stats.py` writes `generated/stats.json`.

The Validate Data Files workflow runs every builder above in check mode on each pull request and fails if a committed file differs from what the script produces. [scripts/README.md](/scripts/README.md) lists the jobs.

## How to use it

Read a file from a clone, or fetch it through the Raw button on its GitHub page. Each line is one JSON object, so standard tools work without a schema step. In Python, using only the standard library:

```python
import json

with open("data/attack/technique_profiles.jsonl", encoding="utf-8") as f:
    rows = [json.loads(line) for line in f if line.strip()]

t = next(r for r in rows if r["technique_id"] == "T1059.001")
print(t["name"], t["group_count"], t["nist_800_53_controls"])
```

- Join on the ids described in [EDGES.md](/data/EDGES.md): `technique_id`, `group_id`, `software_id`, `mitigation_id`, `nist_control`.
- Resolve a revoked or deprecated technique id through `attack/superseded_by.jsonl` before joining; `new_id` is null for a deprecation.
- Pin to a commit, not `main`, if your tooling needs the rows to stay put. `MANIFEST.json` gives each file's SHA-256 for the check.
- For ATT&CK Navigator layers built from this data, see [navigator/index.md](/navigator/index.md). For what each page set is built from, see [About the Library and Its Data](/ABOUT_THE_DATA.md).
