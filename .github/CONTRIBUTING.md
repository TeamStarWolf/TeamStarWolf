# Contributing to TeamStarWolf

Thank you for helping improve this resource. This is a community-maintained cybersecurity library — the goal is accurate, practical, and current information for practitioners at every level.

---

## What We Accept

| Contribution Type | Welcome? | Notes |
|---|---|---|
| Adding a tool or repository | ✅ Yes | Must be publicly accessible; include GitHub link |
| Fixing a broken link or wrong URL | ✅ Yes | Please include the correct link in your PR |
| Correcting a certification name, issuer, or scope | ✅ Yes | Include a source link confirming the correction |
| Adding a commercial platform | ✅ Yes | Note the market category and key capability |
| Adding a book or learning resource | ✅ Yes | Must be publicly available or widely accessible |
| Adding a certification | ✅ Yes | Must be a real, currently active credential with a verifiable issuer |
| Adding a YouTube channel or Twitter/X handle | ✅ Yes | Must actively post security content |
| Nominating a new discipline page | ✅ Yes | Open an issue first to discuss scope |
| Adding data to JSONL edge tables | ✅ Yes | Follow the schema in COVERAGE_SCHEMA.md |
| Removing deprecated or archived tools | ✅ Yes | Note the reason (archived, deprecated, acquired) |
| Promotional content or vendor marketing | ❌ No | Vendors are listed on merit, not sponsorship |
| Unverifiable claims | ❌ No | All facts must be checkable against a public source |

---

## How to Contribute

### Quick Fix (Broken Link, Typo, Wrong Cert Name)

1. Click **"Edit this page on GitHub"** at the top of any page on the site
2. Make your change directly in the GitHub editor
3. Submit a pull request with a short description of what you fixed

### Adding a Tool or Resource

1. Fork the repository
2. Find the appropriate discipline page in `disciplines/`
3. Add your entry to the relevant table section
4. Follow the existing table format exactly (pipe-delimited markdown table)
5. Submit a pull request — use the **"Add Tool or Resource"** PR template

### Fixing a Factual Error

1. Open an issue using the **"Fix Factual Error"** template
2. Or submit a PR directly with a source link in the PR description

### Nominating a New Discipline Page

1. Open an issue using the **"New Discipline Page"** template
2. The page will be created if the discipline has sufficient depth for a full learning path

---

## Content Standards

### Tools and Repositories
- Must have a working public URL (GitHub, official site, or documentation)
- Archived repos should be noted as `(archived)` — not removed, since they may still be useful
- Include a one-line description of what the tool does, not its marketing tagline

### Certifications
- Must be a real credential with a verifiable issuer (GIAC, ISC², ISACA, CREST, EC-Council, INE, Offensive Security, etc.)
- Include the full certification name and abbreviation
- Note the issuer accurately — especially for certifications that have changed hands (e.g., eLearnSecurity → INE Security)
- Do not include courses as certifications (e.g., SANS SEC courses are not certs — GIAC exams are)

### Commercial Platforms
- Include the vendor name, a one-line description of what it does, and the market category
- Do not include pricing, sales language, or marketing superlatives
- Note if a product has been acquired, renamed, or discontinued

### Who to Follow
- Must actively post security content (at least occasional original posts, not just retweets)
- Include their primary focus area in the description
- No duplicate entries across pages

### JSONL Data Files
- Follow the schema defined in [COVERAGE_SCHEMA.md](../COVERAGE_SCHEMA.md)
- Validate your additions locally: `python scripts/validate_jsonl.py`
- Include a source reference for vendor-to-control mappings where possible

---

## Pull Request Checklist

Before submitting, verify:

- [ ] The link you added actually works
- [ ] The certification or tool name is spelled correctly and the issuer is accurate
- [ ] You haven't introduced duplicate entries
- [ ] Your change follows the existing table format
- [ ] If you added a JSONL record, it passes `python scripts/validate_jsonl.py`

---

## Code of Conduct

This project follows a simple standard: be accurate, be helpful, be respectful. Contributions motivated by accuracy and practitioner value are welcome. Contributions motivated by promotion or self-interest are not.

---

## Questions?

Open a [GitHub Discussion](https://github.com/TeamStarWolf/TeamStarWolf/discussions) or [GitHub Issue](https://github.com/TeamStarWolf/TeamStarWolf/issues/new/choose).
