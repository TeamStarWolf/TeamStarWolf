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
| `generate_technique_detail_pages.py` | Generates `techniques/` and `detections/strategies/`, with each technique's body folded into a `<details>` element under its heading | Validate Data Files: generated page trees (`--check`) |
| `compute_coverage.py` | Writes the coverage files in `scores/` | Validate Data Files: Navigator layers (`--check`) |
| `build_priority_gaps.py` | Writes the priority-gap page and JSON in `scores/` and the layers in `navigator/analytics/` | Validate Data Files: headline-number drift guard (`--check`) |
| `build_navigator_layers.py` | Generates the vendor coverage layer, normalizes the curated layers to v19.2, and writes `navigator/index.md` | Validate Data Files: Navigator layers (`--check`) |
| `validate_navigator.py` | Checks every Navigator layer's shape, domain, ATT&CK version, technique ids, and tactics against the data | Validate Data Files: Navigator layers |
| `build_manifest.py` | Writes `data/MANIFEST.json` (rows, bytes, SHA-256, and provenance per file) | Validate Data Files: headline-number drift guard (`--check`) |
| `build_stats.py` | Writes `data/generated/stats.json` and the "What's inside" table in README.md; `--check` fails when a front-door number differs from the data or the README table is stale | Validate Data Files: headline-number drift guard |
| `check_docsify_links.py` | Resolves every internal link and anchor the way the docsify site does; a new broken link fails | Link Check: internal links and anchors |
| `check_repo_hygiene.py` | Fails on tracked junk, invalid UTF-8 or mojibake, and new citations of revoked ATT&CK ids in hand-written pages | Validate Data Files: repo hygiene |
| `check_voice.py` | The voice lint for hand-written pages ([docs/VOICE.md](/docs/VOICE.md)) | Validate Data Files: repo hygiene |
| `build_site_nav.py` | Writes the site navigation from `docs/site_nav.json`: the root sidebar and navbar, the nested sidebars for guides/, disciplines/, tools/, ai-tooling/ and mitre/, the domain hubs in `hubs/`, the homepage's "Browse by domain" cards, the breadcrumb trails in `assets/site-nav.json` and the docsify alias block in `index.html`. `--check` also fails when a root reference is in no hub or in two, or a hand-written page is in no nav section; `--report` prints link counts and clicks from the homepage to every page | Validate Data Files: repo hygiene (`--check`) |
| `build_explore.py` | Writes `assets/explore.json` (one row per framework object with a page, from the JSONL files in `data/`) and `explore.md`, the Explore page; `--report` prints rows per kind and the JSON size | Validate Data Files: repo hygiene (`--check`) |
| `build_doc_meta.py` | Writes the header card at the top of each root reference and learning path from `data/doc_meta.yaml`, as labelled rows (`<th scope="row">`): who the page is for, level, reading time ("Length" on a lookup page, more than three quarters tables), the "Read this when", "Start at" (at most 3 links) and "Pairs with" rows, the matching learning path, the last recorded correction ("Last corrected": what the edit changed on the page), the owner's last review ("No review recorded yet" until there is one, and "Due for review" when the text changed more than 90 days after it, from git history), and a folded "Which page should I read?" table on overlapping pages. Shows key takeaways only from `data/doc_takeaways.yaml`, checks the drafts in `data/doc_takeaways.draft.yaml` (each must quote its page), and folds long appendices and tables into `<details>`. `--report` prints coverage, reading times and fold candidates; `--self-test` runs planted cases | Validate Data Files: header cards (`--self-test`, `--check`, full git history) |
| `build_crosslinks.py` | Writes the cross-links between the hand-written and generated pages from `docs/crosslinks.json` and the pages' own links: each learning path's matching reference, a "Related pages" footer on each root reference (less the pages its own closing related or see-also section already links), a "(local)" link after each MITRE ID link in the three framework atlases, and a "Library references" block on each `mitre/` page that hand-written pages cite or that has a section in `detections/strategies/` and `techniques/` (`generate_mitre_pages.py` keeps that block when it rewrites a page). `--report` prints blocks and links per kind | Validate Data Files: repo hygiene (`--check`) |
| `build_brand_assets.py` | Exports the web-sized images in `assets/brand/` from the banner masters in `assets/` | Not run in CI (needs Pillow) |
| `build_search_index.py` | Builds the site search: one [Pagefind](https://pagefind.app/) record per served page (title, kind, section, summary, `#/` route) into `pagefind/`, and `ids.json`, which maps framework IDs and exact technique, group, software, and campaign names to their pages for the ID jump. Build output only, never committed. Needs the pinned, hash-checked packages in `requirements-search.txt` | Deploy site: build job (`.github/workflows/pages.yml`), on every push to main and on pull requests that change the site shell, the builder, any page, or the ATT&CK data it reads |
| `attack_ids.py`, `plain_markdown.py`, `repo_files.py` | Shared helpers: the ATT&CK id lifecycle rule, plain-text formatting for generated pages, and the tracked-file list | Imported by the scripts above |
| `baselines/` | The ratchet baselines for the link, voice, and revoked-id checks and the lychee allowlist; each may only shrink | Read by the checks above |

The Link Check workflow also runs lychee on the outbound links a pull request adds, and a full outbound scan every Monday.

## How it is generated

These are hand-written. Every script except `build_brand_assets.py` and `build_search_index.py` uses only the Python standard library; CI runs them on Python 3.11. `build_attack_core.py` fetches the pinned STIX bundles over the network unless you pass local copies; it verifies each bundle's SHA-256 either way.

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

To try site search locally, build the artifact the way the deploy job does, then serve `_site/` with any static file server (`_site/` is in `.gitignore`):

```
python -m pip install --no-deps --require-hashes -r scripts/requirements-search.txt
mkdir _site && git archive --format=tar HEAD | tar -x -C _site
python scripts/build_search_index.py --site _site
python -m http.server --directory _site 8000
```

Each script's docstring (`python scripts/<name>.py --help` where supported) gives its options. Commit what the builders write; the `--check` modes in CI fail on anything left stale.
