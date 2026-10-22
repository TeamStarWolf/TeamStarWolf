# Maintaining the Site

> How the library's website is built, where each piece of page metadata lives, what every script and CI check does, how a change reaches the live site, and how to roll the site back. For writing rules, see the [Voice and Credibility Guide](/docs/VOICE.md); for the contribution workflow, see [CONTRIBUTING](/CONTRIBUTING.md).

## How the site works

The site at [teamstarwolf.github.io/TeamStarWolf](https://teamstarwolf.github.io/TeamStarWolf/) is the Markdown in this repository rendered in the browser by [docsify](https://docsify.js.org/) 4.13.1. There is no static-site build: `index.html` loads docsify and the pinned plugins from jsDelivr (each with a Subresource Integrity hash), and docsify fetches the `.md` file for the route in the address bar.

- A page's route is its path without `.md`: `SIEM_REFERENCE.md` is `#/SIEM_REFERENCE`, and a folder's `README.md` is the folder route (`#/guides/`). The homepage is `HOME.md` at `#/`.
- A heading's anchor is `?id=<slug>`, using docsify 4.13.1's slug rules. Docsify slugs the heading's rendered HTML, not its Markdown: lower case, `&` becomes `amp` and an apostrophe becomes `39` (`## Cloud & Supply Chain` is `?id=cloud-amp-supply-chain`), other punctuation dropped, spaces to hyphens, `_` before a leading digit, `-1`, `-2` on repeats. The docstring of `scripts/check_docsify_links.py` lists the rules the link check applies.
- `relativePath` is off, so links in pages are root-absolute: `[SIEM Reference](/SIEM_REFERENCE.md)`. They work on GitHub too.
- `index.html` also holds the site's own code: the theme tokens for the dark and light themes, the search overlay and ID jump, the header card and fold behaviour, breadcrumbs, the Explore table, the keyboard handling and the tab titles. Each block has a comment saying what it does and which script, if any, writes into it. The docsify alias block between `// nav-aliases:start` and `// nav-aliases:end` is written by `scripts/build_site_nav.py`.
- The shell pages: `_coverpage.md` (the hero, hand-written), `_404.md` (shown for a route with no page, hand-written), `_navbar.md` and every `_sidebar.md` (written by `scripts/build_site_nav.py`).
- No file is ever renamed or moved without a plan for its old routes: outside sites, ATTACK-Navi and GitHub blob URLs link to these paths. `scripts/old_urls.txt` holds a sample of routes from before the site revamp, and CI fails if one stops resolving.

## Add or change a page

### A root reference

1. Write the page at the root as `TOPIC_REFERENCE.md`, following [docs/VOICE.md](/docs/VOICE.md). Open with the `#` title and a one-sentence `>` summary. Link other pages root-absolute.
2. Put it in exactly one domain hub: add the file name to that hub's `docs` list in `docs/site_nav.json`.
3. Add its row to [INDEX.md](/INDEX.md), in alphabetical order. The hub shows the INDEX description.
4. Add its entry to `data/doc_meta.yaml` with at least `audience` and `level`, and `read_when`, `start_at` and `pairs_with` if it has them.
5. If a learning path covers the same subject, pair them in `path_references` in `docs/crosslinks.json`.
6. Run the writers, then the checks (from the repository root):

```
python scripts/build_site_nav.py
python scripts/build_doc_meta.py
python scripts/build_crosslinks.py
python scripts/build_stats.py
python scripts/check_docsify_links.py
python scripts/check_voice.py
python scripts/build_site_nav.py --check
```

7. Commit the page and every file the writers changed, and open a pull request.

### A guide, learning path, tool page or other folder page

Add the page to its folder and link it from that folder's `README.md`; the nested sidebar and breadcrumbs follow from `docs/site_nav.json` and the README. A learning path in `disciplines/` also needs a `data/doc_meta.yaml` entry. Then run the same writers and checks.

### A correction to an existing page

Edit the text. If the edit changes facts on the page, record it under `corrections:` in `data/doc_meta.yaml` and set the page's `corrected:` (see "Header Cards, Reviews and Takeaways" in [CONTRIBUTING](/CONTRIBUTING.md)). Run `python scripts/build_doc_meta.py` and the checks.

### Removing or renaming a page

Avoid it. If a page is superseded, keep the file and replace its body with a note that starts `> This document has been superseded.` in its first lines and links the replacement (see `SUPPLY_CHAIN_SECURITY.md`). Take it out of its hub in `docs/site_nav.json` and out of INDEX; `build_site_nav.py` recognises that sentence and leaves the stub out of the nav, and `build_search_index.py` still indexes it but lists it under "Superseded"; its old links still land on the note. If a heading that other pages link to must change, keep the old anchor working with an HTML id on the new heading (`<a id="old-slug"></a>`), and check `scripts/old_urls.txt` still passes.

## Where metadata lives

| File | What it holds | Written by | Read by |
|---|---|---|---|
| `docs/site_nav.json` | Sidebar sections, navbar, nested folder sidebars, domain hubs and their groups, breadcrumb parents, pages kept out of the nav | Hand | `build_site_nav.py`, `build_search_index.py` (section of each page) |
| `docs/crosslinks.json` | Learning path to reference pairs, pages that get "(local)" ID links, size of the "Related pages" lists | Hand | `build_crosslinks.py`, `build_doc_meta.py` |
| `data/doc_meta.yaml` | Header card rows, corrections, reviews, overlap clusters, folds | Hand | `build_doc_meta.py` |
| `data/doc_takeaways.yaml` | Key takeaways the owner has reviewed (shown on pages) | Hand, after review | `build_doc_meta.py` |
| `data/doc_takeaways.draft.yaml` | Drafted takeaways waiting for review (not shown) | Hand or agent draft | `build_doc_meta.py --check` |
| `INDEX.md` | One row and description per page | Hand | Readers, `build_site_nav.py` (hub descriptions) |
| `data/generated/stats.json` | Headline counts | `build_stats.py` | README and HOME "What's inside", `build_stats.py --check` |
| `assets/site-nav.json` | Breadcrumb trails | `build_site_nav.py` | `index.html` |
| `assets/explore.json` | One row per framework object with a page | `build_explore.py` | The Explore page in `index.html` |
| `data/MANIFEST.json` | Rows, bytes, SHA-256 and provenance per dataset | `build_manifest.py` | `build_manifest.py --check`, readers |
| `scripts/baselines/` | Ratchet baselines for links, voice, revoked IDs and the lychee allowlist; each may only shrink | The checks' `--update-baseline` modes | The checks |
| `scripts/old_urls.txt` | Old site routes that must keep resolving | Hand (add lines, never remove one to pass) | `check_old_urls.py` |
| `index.html` | Theme tokens, site code, docsify config and plugin pins | Hand, except the alias block | Browsers, `check_contrast.py` |
| `CITATION.cff` | How to cite the library | Hand | GitHub's "Cite this repository" |

Generated blocks inside pages sit between `<!-- name:start -->` and `<!-- name:end -->` markers. Never edit inside them: change the source file in the table and rerun the script that owns the block.

## Scripts

[scripts/README.md](/scripts/README.md) describes each script and its options in full, and gives the order to rebuild the data after an ATT&CK refresh. In short:

| Script | Writes or checks | Run it when |
|---|---|---|
| `build_site_nav.py` | Sidebars, navbar, hubs, homepage domain cards, breadcrumbs, docsify aliases | A page is added, moved out of the nav, or `docs/site_nav.json` changes |
| `build_doc_meta.py` | Header cards, folds, "Which page should I read?" tables, takeaways | A reference or path is added, `data/doc_meta.yaml` or the takeaway files change, or a page's words change much |
| `build_crosslinks.py` | "Matching reference" lines, "Related pages" footers, "(local)" ID links, "Library references" blocks | Links between pages change, or `docs/crosslinks.json` changes |
| `build_explore.py` | `assets/explore.json` and `explore.md` | The framework data in `data/` changes |
| `build_stats.py` | `stats.json` and the README and HOME counts; `--check` scans pages for stale headline numbers | Any data change, and before every pull request |
| `build_home_guides.py` | The homepage guide cards, from each guide's time and difficulty table | A guide's header table changes |
| `build_search_index.py` | The Pagefind index and `ids.json` in the deploy artifact (never committed) | Only in the deploy job, or locally to try search |
| `build_brand_assets.py` | Web exports in `assets/brand/` from the banner masters | The banner art changes (needs Pillow) |
| `generate_mitre_pages.py`, `generate_technique_detail_pages.py` | The `mitre/`, `techniques/` and `detections/strategies/` pages | The framework data changes |
| `build_attack_core.py`, `build_ctid_edges.py`, `build_control_rollup.py`, `backfill_capec_edges.py`, `compute_coverage.py`, `build_priority_gaps.py`, `build_navigator_layers.py`, `build_manifest.py` | The data in `data/`, `scores/` and `navigator/` | An ATT&CK or mapping refresh, in the order scripts/README.md gives |
| `check_docsify_links.py` | Every internal link and anchor, resolved the way the site does | Before every pull request |
| `check_old_urls.py` | Every route in `scripts/old_urls.txt` still reaches its page and heading | Before a pull request that renames headings or touches aliases |
| `check_voice.py` | The voice rules in [docs/VOICE.md](/docs/VOICE.md) on hand-written pages | Before every pull request |
| `check_contrast.py` | Every text and background pair in the `index.html` theme tokens meets WCAG AA in both themes | A colour token changes |
| `check_repo_hygiene.py` | No tracked junk, valid UTF-8, no new revoked ATT&CK IDs | Before every pull request |
| `validate_jsonl.py`, `validate_navigator.py` | The JSONL edge tables and the Navigator layers | A data change |

Every writer has a `--check` mode that rebuilds in memory and fails on any difference from the committed files. Commit what the writers produce; never hand-edit their output.

## CI checks

| Workflow | Job | Fails when |
|---|---|---|
| Link Check (`link-check.yml`) | Internal links and anchors | A new broken internal link or anchor (`check_docsify_links.py`), or an old route in `scripts/old_urls.txt` stops resolving (`check_old_urls.py`) |
| Link Check | External links (lychee) | On a pull request or push: an `http(s)` link the change adds is dead. Every Monday at 06:00 UTC: a full scan of every page, reported in the run summary and the `link-check-report` artifact, not failing yet |
| Validate Data Files (`validate-data.yml`) | JSONL edge tables | A JSONL file breaks its schema or edge contract, or the ATT&CK core, CAPEC or CTID edges differ from their pinned sources |
| Validate Data Files | Corpus signal | The corpus-signal paragraphs and their data file disagree |
| Validate Data Files | Generated page trees | A `mitre/`, `techniques/` or `detections/strategies/` page differs from what the data produces |
| Validate Data Files | Repo hygiene | Junk, bad encoding, a new revoked ID, a theme colour below AA, stale navigation or a hand-written page in no nav section, a stale Explore page, stale cross-link blocks, or a new voice violation |
| Validate Data Files | Header cards | A header card, fold or overlap table differs from `data/doc_meta.yaml`, a reference or path has no entry, or a takeaway's quote is no longer in its section |
| Validate Data Files | Navigator layers | A layer is malformed, uses a revoked technique, or differs from the data |
| Validate Data Files | Headline-number drift | `stats.json`, the README or HOME counts, the guide cards, the manifest or the control rollup are stale, or a page states a headline number the data does not support |
| Deploy site (`pages.yml`) | Build site and search index | The search index cannot be built: an unreadable page, a required ID missing, or one ID on two pages. Runs on pull requests that touch pages, data, `index.html` or the builder |
| CodeQL | GitHub default setup, on pushes and pull requests | Code scanning of the workflows (`actions`) and scripts (`python`); findings appear under Security, Code scanning |

## How the deploy works

The Pages source is "GitHub Actions" (Settings, Pages, Build and deployment). `.github/workflows/pages.yml` publishes the site:

1. On every push to `main`, the build job checks out the commit, copies the tracked tree into `_site/` with `git archive` (so nothing untracked is published, and `.github/` is removed), and runs `scripts/build_search_index.py --site _site`, which writes `pagefind/` and `ids.json`. Pagefind is installed from `scripts/requirements-search.txt`, pinned by version and hash.
2. The job checks that the index files exist, writes the artifact's size to the run summary, and uploads `_site/` as the Pages artifact.
3. The deploy job publishes the artifact to the `github-pages` environment. It runs only for `main`, only when the Pages source is "GitHub Actions", and joins the `pages` concurrency group so two deploys never overlap.

A pull request runs the build job only, so a change that would break the index fails before merge. `workflow_dispatch` with `dry_run: true` builds and uploads without deploying.

To see a change locally before merging, build the artifact the way the deploy job does (the commands are in [scripts/README.md](/scripts/README.md)), serve `_site/` with `python -m http.server --directory _site 8000`, open `http://127.0.0.1:8000/`, and stop the server when done. Serving the checkout itself also works, but search then shows its fallback message, because the index exists only in the artifact.

## Roll back

Pick the smallest step that fixes the problem.

1. **A bad change.** Open a pull request that reverts it (`git revert <merge commit>` on a branch from `main`) and merge it. The push to `main` redeploys. This keeps the history and the checks.
2. **A broken deploy of good content.** Re-run the last good "Deploy site" run on `main` (Actions, Deploy site, the run, "Re-run all jobs", or `gh run rerun <run id>`). A re-run builds the commit that run built, so the site shows that commit until the next push to `main` deploys again.
3. **The Actions deploy itself fails.** Switch the Pages source back to the branch: Settings, Pages, Build and deployment, Source "Deploy from a branch", branch `main`, folder `/ (root)`. GitHub then serves the tracked files as they are (`.nojekyll` turns off Jekyll processing), every route and anchor keeps working, and the deploy job skips itself because it reads the Pages source on each run. Search shows its fallback message (a link to INDEX and to GitHub code search), because the branch has no index. To return, set the source to "GitHub Actions" and run "Deploy site" (Actions, Deploy site, Run workflow, branch `main`).

The same source switch through the API, for an account with admin rights on the repository (not exercised during this handover):

```
gh api -X PUT repos/TeamStarWolf/TeamStarWolf/pages -f build_type=legacy -f "source[branch]=main" -f "source[path]=/"
gh api -X PUT repos/TeamStarWolf/TeamStarWolf/pages -f build_type=workflow
```

Check the result with `gh api repos/TeamStarWolf/TeamStarWolf/pages --jq .build_type`.

## Before you merge a site change

- The CI checks above are green.
- For a change to `index.html`, the theme, search or navigation: load the changed routes in a desktop browser at 1440 px and at 375 px, in both themes; Tab from the top of a page (the first stop is "Skip to content"), press `/` and Ctrl K to open search and Esc to close it; and search for `T1059` and `APT29`.
- Keep the page free of horizontal scroll at 375 px; wide tables scroll inside their own box.
