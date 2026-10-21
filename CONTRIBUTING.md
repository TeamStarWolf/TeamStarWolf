# Contributing to TeamStarWolf

Thank you for helping improve this resource. This is a community-maintained cybersecurity library; the goal is accurate, practical, and current information for practitioners at every level.

---

## What We Accept

| Contribution Type | Welcome? | Notes |
|---|---|---|
| Adding a tool or repository | Yes | Must be publicly accessible; include GitHub link |
| Fixing a broken link or wrong URL | Yes | Please include the correct link in your PR |
| Correcting a certification name, issuer, or scope | Yes | Include a source link confirming the correction |
| Adding a commercial platform | Yes | Note the market category and key capability |
| Adding a book or learning resource | Yes | Must be publicly available or widely accessible |
| Adding a certification | Yes | Must be a real, currently active credential with a verifiable issuer |
| Adding a YouTube channel or Twitter/X handle | Yes | Must actively post security content |
| Nominating a new discipline page | Yes | Open an issue first to discuss scope |
| Adding data to JSONL edge tables | Yes | Follow the schema in COVERAGE_SCHEMA.md |
| Removing deprecated or archived tools | Yes | Note the reason (archived, deprecated, acquired) |
| Promotional content or vendor marketing | No | Vendors are listed on merit, not sponsorship |
| Unverifiable claims | No | All facts must be checkable against a public source |

---

## How to Contribute

### Cloning on Windows

A few reference docs quote attack and evasion snippets as analysis samples. Microsoft Defender detects the
AMSI-bypass example in `MALWARE_ANALYSIS_REFERENCE.md` and quarantines the file during `git clone`, so a
default Windows clone starts with that tracked file deleted (`git status --short` shows
` D MALWARE_ANALYSIS_REFERENCE.md`). The detection is expected; the snippet is intentional reference material.
Pick one of these before you clone:

- Add a Defender exclusion for the folder you will clone into (Windows Security -> Virus & threat protection
  -> Manage settings -> Exclusions), clone, and confirm `git status` is clean. If the file was already
  quarantined, restore it with `git checkout -- MALWARE_ANALYSIS_REFERENCE.md` once the exclusion is in place.
- Or leave Defender alone and skip that one file with a sparse checkout:

  ```
  git clone --no-checkout https://github.com/TeamStarWolf/TeamStarWolf.git
  cd TeamStarWolf
  git sparse-checkout set --no-cone "*" "!MALWARE_ANALYSIS_REFERENCE.md"
  git checkout
  ```

Either way, never commit the deletion. Stage files by name rather than with `git add -A` or `git commit -a`
if `git status` shows the ` D` entry.

### Quick Fix (Broken Link, Typo, Wrong Cert Name)

1. Click "Edit this page on GitHub" at the top of any page on the site
2. Make your change directly in the GitHub editor
3. Submit a pull request with a short description of what you fixed

### Adding a Tool or Resource

1. Fork the repository
2. Find the appropriate discipline page in `disciplines/`
3. Add your entry to the relevant table section
4. Follow the existing table format exactly (pipe-delimited markdown table)
5. Submit a pull request: use the "Add Tool or Resource" PR template

### Fixing a Factual Error

1. Open an issue using the "Fix Factual Error" template
2. Or submit a PR directly with a source link in the PR description

### Nominating a New Discipline Page

1. Open an issue using the "New Discipline Page" template
2. The page will be created if the discipline has sufficient depth for a full learning path

---

## Content Standards

### Voice
- Follow the [Voice and Credibility Guide](docs/VOICE.md): plain declarative sentences, precise framework terms, sources for every external claim, and no hand-typed headline counts
- Check your change locally: `python scripts/check_voice.py` (CI runs the same check)

### Tools and Repositories
- Must have a working public URL (GitHub, official site, or documentation)
- Archived repos should be noted as `(archived)`: not removed, since they may still be useful
- Include a one-line description of what the tool does, not its marketing tagline

### Certifications
- Must be a real credential with a verifiable issuer (GIAC, ISC², ISACA, CREST, EC-Council, INE, Offensive Security, etc.)
- Include the full certification name and abbreviation
- Note the issuer accurately: especially for certifications that have changed hands (e.g., eLearnSecurity -> INE Security)
- Do not include courses as certifications (e.g., SANS SEC courses are not certs; GIAC exams are)

### Commercial Platforms
- Include the vendor name, a one-line description of what it does, and the market category
- Do not include pricing, sales language, or marketing superlatives
- Note if a product has been acquired, renamed, or discontinued

### Who to Follow
- Must actively post security content (at least occasional original posts, not just retweets)
- Include their primary focus area in the description
- No duplicate entries across pages

### JSONL Data Files
- Follow the schema defined in [COVERAGE_SCHEMA.md](COVERAGE_SCHEMA.md)
- Validate your additions locally: `python scripts/validate_jsonl.py`
- Include a source reference for vendor-to-control mappings where possible

### New Pages and the Site Navigation
- [Maintaining the Site](docs/MAINTAINING_THE_SITE.md) walks through adding a page, where each piece of page metadata lives, what every script and CI check does, how the deploy works and how to roll the site back.
- The sidebars, the navbar, the domain hubs in `hubs/`, the "Browse by domain" cards on the homepage and the breadcrumbs are written by `scripts/build_site_nav.py` from `docs/site_nav.json`. Edit the JSON, not the generated files.
- A new root reference goes in exactly one hub: add its file name to that hub's `docs` list in `docs/site_nav.json`, add its row to [INDEX.md](INDEX.md) (the hub shows the INDEX description), then run `python scripts/build_site_nav.py`.
- A new page in a folder (a guide, a learning path, a tool page) is listed by that folder's README.md; link it there and run the script again.
- CI runs `python scripts/build_site_nav.py --check`, which fails when a generated file is stale or when a hand-written page is in no nav section.

### Cross-Links Written by a Script
- Some blocks inside pages are written by `scripts/build_crosslinks.py` and sit between `<!-- name:start -->` and `<!-- name:end -->` markers: the "Matching reference" line under a learning path's introduction, the "Related pages" footer on each root reference, and the "Library references" block on `mitre/` pages. The "(local)" links after MITRE IDs in CAPEC_REFERENCE.md, ATTACK_TECHNIQUE_ATLAS.md and ATTACK_SOFTWARE_REFERENCE.md are written the same way. Do not edit them by hand.
- To pair a learning path with its reference, or to change the size of the "Related pages" lists, edit `docs/crosslinks.json`. A footer also picks up the pages in the reference's own "Pairs with" row and the references in the same hub group that it links to or that link to it. When a reference ends with its own related, see-also or further-reading section (its subsections included, such as Internal and External lists under a Related Resources heading), the footer leaves out every page that section links, so the two lists never repeat each other.
- After adding or removing links between pages, run `python scripts/build_crosslinks.py`. CI runs it with `--check`, which fails when a committed block differs from what the script writes.

### Header Cards, Reviews and Takeaways
- Every root reference and learning path opens with a header card that `scripts/build_doc_meta.py` writes between `<!-- meta:start -->` and `<!-- meta:end -->` markers: who the page is for, its level, its reading time (the page's words at 230 words a minute, the same count the domain hubs show; a reference with more than three quarters of its words in tables is a lookup page, and its row says "Length" and to find an entry rather than read it end to end), its "Read this when", "Start at" (at most 3 links) and "Pairs with" rows, the matching learning path, its last recorded correction and its last review. On a phone the first five rows fit one screen and the rest sit in a "More about this page" fold. Do not edit the card in the page; edit the page's entry in `data/doc_meta.yaml` and run `python scripts/build_doc_meta.py`.
- A new reference or learning path needs an entry in `data/doc_meta.yaml`, with at least `audience` and `level`; the check fails without one. A "Read this when" table written into a page outside its card also fails the check: put those rows in the page's entry instead. Write "Read this when" as clauses with their subject, so the row reads on from the label: "You are planning or auditing logging coverage, you need ..., or an advisory lands and ...", not "Planning ..., deciding ...". It starts with a capital letter, and no part opens with a bare "-ing" verb (the check enforces both). Say what the reader is doing, in the page's own terms. Links in "Start at" and "Pairs with" use the page's title as their text, not its file name (the check enforces it).
- A correction and a review are different things. A pull request that edits a page's text (a renamed tool, a re-keyed ATT&CK ID, an updated regulation) is recorded under `corrections:` and set as the page's `corrected:`, with `corrected_what:` saying what it changed on that page; the card shows it as "Last corrected" and names an ATT&CK release only when the edit touched ATT&CK content (`attack:` on the entry). A review is a whole-page review by the owner: add it under `reviews:` (the date, what was checked, and optionally the ATT&CK release it was checked against and the pull request) and set `reviewed:` on each page it covered. Until then the card says "No review recorded yet". The card shows "Due for review" when the page's text changed more than 90 days after its last review; corrections never reset that clock. The date of the last change comes from git history, so CI runs this check with the full history.
- Pages that overlap share a `clusters:` entry, and each of them gets a "Which page should I read?" table naming the others with a one-line focus.
- A page's `fold:` list puts a long appendix (`section:<anchor>`) or every table of more than 40 rows in a section (`tables:<anchor>`) into a `<details>` fold under its heading. `python scripts/build_doc_meta.py --report` lists appendix and glossary sections over two screens that are not folded yet.
- Key takeaways appear on a page only from `data/doc_takeaways.yaml`, which holds the ones the owner has reviewed. Drafts wait in `data/doc_takeaways.draft.yaml`. Every takeaway names the section it comes from and quotes the page, and the check fails when the quote is no longer in that section, so a takeaway cannot outlive its source.

---

## Pull Request Checklist

Before submitting, verify:

- [ ] The link you added actually works
- [ ] The certification or tool name is spelled correctly and the issuer is accurate
- [ ] You haven't introduced duplicate entries
- [ ] Your change follows the existing table format
- [ ] If you added a JSONL record, it passes `python scripts/validate_jsonl.py`
- [ ] `python scripts/check_voice.py` passes (see [docs/VOICE.md](docs/VOICE.md))
- [ ] If you added, renamed or moved a page, `python scripts/build_site_nav.py --check` passes
- [ ] If you added or removed links between pages, `python scripts/build_crosslinks.py --check` passes
- [ ] If you added a reference or learning path, changed one's text, or edited `data/doc_meta.yaml`, `python scripts/build_doc_meta.py --check` passes
- [ ] Your diff does not delete `MALWARE_ANALYSIS_REFERENCE.md` (see [Cloning on Windows](#cloning-on-windows))

---

## Code of Conduct

This project follows a simple standard: be accurate, be helpful, be respectful. Contributions motivated by accuracy and practitioner value are welcome. Contributions motivated by promotion or self-interest are not.

---

## Questions?

Open a [GitHub Discussion](https://github.com/TeamStarWolf/TeamStarWolf/discussions) or [GitHub Issue](https://github.com/TeamStarWolf/TeamStarWolf/issues/new/choose).
