# Scripts

Drafted with an AI assistant from the sources cited; checked against them on 2026-10-17.

> The generators and checks that keep the library's data, generated pages, and headline numbers in step. Each builder has a `--check` mode that rebuilds in memory and fails on any difference from the committed files, and CI runs those modes on every pull request.

## What is here

| Script | What it does | CI job that runs it |
|---|---|---|
| `build_attack_core.py` | Rebuilds the ATT&CK Enterprise, ICS, and Mobile files in `data/attack/` from the v19.2 STIX bundles, pinned by commit and SHA-256, and writes `superseded_by.jsonl` | Validate Data Files: JSONL edge tables (`--check`) |
| `build_ctid_edges.py` | Normalizes the CTID NIST SP 800-53 to ATT&CK table and builds the vendor-to-technique join | Validate Data Files: JSONL edge tables (`--check`) |
| `backfill_capec_edges.py` | Writes the CAPEC edge on each technique profile from `data/weaknesses/capec.jsonl` | Validate Data Files: JSONL edge tables (`--check`) |
| `build_control_rollup.py` | Adds the parent-rolled NIST controls to each technique profile | Validate Data Files: headline-number drift guard |
| `validate_jsonl.py` | Validates every JSONL file: JSON per line, unique keys, the edge contract in [data/EDGES.md](/data/EDGES.md), live ATT&CK ids, and counts that match their edge tables | Validate Data Files: JSONL edge tables |
| `generate_mitre_pages.py` | Generates the `mitre/` framework pages and their indexes from `data/` | Validate Data Files: generated page trees (`--only all --check`) and corpus signal (`--verify-corpus`) |
| `generate_technique_detail_pages.py` | Generates `techniques/` and `detections/strategies/` | Validate Data Files: generated page trees (`--check`) |
| `compute_coverage.py` | Writes the four coverage files in `scores/` | Validate Data Files: Navigator layers (`--check`) |
| `build_priority_gaps.py` | Writes the priority-gap page and JSON in `scores/` and the layers in `navigator/analytics/` | Validate Data Files: headline-number drift guard (`--check`) |
| `build_navigator_layers.py` | Generates the vendor coverage layer, normalizes the curated layers to v19.2, and writes `navigator/index.md` | Validate Data Files: Navigator layers (`--check`) |
| `validate_navigator.py` | Checks every Navigator layer's shape, domain, ATT&CK version, technique ids, and tactics against the data | Validate Data Files: Navigator layers |
| `build_manifest.py` | Writes `data/MANIFEST.json` (rows, bytes, SHA-256, and provenance per file) | Validate Data Files: headline-number drift guard (`--check`) |
| `build_stats.py` | Writes `data/generated/stats.json` and the "What's inside" table in README.md; `--check` fails when a front-door number differs from the data or the README table is stale | Validate Data Files: headline-number drift guard |
| `check_docsify_links.py` | Resolves every internal link and anchor the way the docsify site does; a new broken link fails | Link Check: internal links and anchors |
| `check_repo_hygiene.py` | Fails on tracked junk, invalid UTF-8 or mojibake, and new citations of revoked ATT&CK ids in hand-written pages | Validate Data Files: repo hygiene |
| `check_voice.py` | The voice lint for hand-written pages ([docs/VOICE.md](/docs/VOICE.md)) | Validate Data Files: repo hygiene |
| `build_brand_assets.py` | Exports the web-sized images in `assets/brand/` from the banner masters in `assets/` | Not run in CI (needs Pillow) |
| `attack_ids.py`, `plain_markdown.py`, `repo_files.py` | Shared helpers: the ATT&CK id lifecycle rule, plain-text formatting for generated pages, and the tracked-file list | Imported by the scripts above |
| `baselines/` | The ratchet baselines for the link, voice, and revoked-id checks and the lychee allowlist; each may only shrink | Read by the checks above |

The Link Check workflow also runs lychee on the outbound links a pull request adds, and a full outbound scan every Monday.

## How it is generated

These are hand-written. Every script except `build_brand_assets.py` uses only the Python standard library; CI runs them on Python 3.11. `build_attack_core.py` fetches the pinned STIX bundles over the network unless you pass local copies; it verifies each bundle's SHA-256 either way.

## How to use it

Run from the repository root. After a data change, rebuild in dependency order, then run the checks:

```
python scripts/build_attack_core.py          # only when re-pinning ATT&CK; it also runs the next three
python scripts/build_ctid_edges.py
python scripts/build_control_rollup.py
python scripts/backfill_capec_edges.py
python scripts/generate_mitre_pages.py --only all
python scripts/generate_technique_detail_pages.py
python scripts/compute_coverage.py
python scripts/build_priority_gaps.py
python scripts/build_navigator_layers.py
python scripts/build_manifest.py
python scripts/build_stats.py

python scripts/validate_jsonl.py
python scripts/validate_navigator.py
python scripts/check_docsify_links.py
python scripts/check_repo_hygiene.py
python scripts/check_voice.py
```

Each script's docstring (`python scripts/<name>.py --help` where supported) gives its options. Commit what the builders write; the `--check` modes in CI fail on anything left stale.
