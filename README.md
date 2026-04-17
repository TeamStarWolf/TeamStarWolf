<div align="center">

# TeamStarWolf

Security tooling, detection-engineering workbenches, and applied research from [**@WolfenLabs**](https://x.com/WolfenLabs).

[![ATT&CK Workbench](https://img.shields.io/badge/ATT%26CK--Navi-Angular%2019-DD0031?style=for-the-badge&logo=angular&logoColor=white)](https://github.com/TeamStarWolf/ATTACK-Navi)
[![LimeWire](https://img.shields.io/badge/LimeWire-Python%204.0-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://github.com/TeamStarWolf/LimeWire)
[![Field Notes](https://img.shields.io/badge/field--notes-applied%20research-2ECC71?style=for-the-badge)](FIELD_NOTES.md)

</div>

---

## Projects

### [ATT&CK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) — Flagship
**Angular 19 single-page workbench for MITRE ATT&CK.** Interactive workflows across technique coverage, exposure mapping, detection engineering, threat intelligence, and defense planning. Integrates Sigma, YARA, NIST 800-53, MISP, OpenCTI, and CISA KEV. Hardened against 7 confirmed XSS / CSRF / open-redirect vulnerabilities since v0.1.0 with a maintained `SECURITY.md` policy.

[Repository](https://github.com/TeamStarWolf/ATTACK-Navi) · [Live site](https://teamstarwolf.github.io/ATTACK-Navi/) · [CHANGELOG](https://github.com/TeamStarWolf/ATTACK-Navi/blob/main/CHANGELOG.md)

### [LimeWire Studio v4](https://github.com/TeamStarWolf/LimeWire) — Desktop Audio Workstation
**Python desktop audio production studio** with download, analysis, editing, stem separation, playlist transfer, and batch processing. 25 tabs, 25 themes, 6 languages. **Hardened against 32 confirmed vulnerabilities** across three security audit rounds covering SSRF via subprocess, path-policy enforcement, ffmpeg filter-string injection, plaintext credential handling, and DPAPI-based token storage.

[Repository](https://github.com/TeamStarWolf/LimeWire) · [Latest release](https://github.com/TeamStarWolf/LimeWire/releases)

### [PokeNav](https://github.com/TeamStarWolf/PokeNav) — Local-First Encyclopedia
**Offline-first Pokemon encyclopedia** with game-aware browsing, trainer archives, and linked reference data. React 19 / TypeScript / Vite static site demonstrating local-first architecture, schema-first design, and security-conscious client rendering (CSP, runtime input validation, escaped SVG generation).

[Repository](https://github.com/TeamStarWolf/PokeNav) · [Live site](https://teamstarwolf.github.io/PokeNav/)

---

## Field Notes — Applied Research and Writeups

Original analysis and post-mortems from working on the projects above. See [**FIELD_NOTES.md**](FIELD_NOTES.md) for the running index.

Current entries:

- **Hardening LimeWire v4: 32 vulnerabilities across 3 audit rounds** — A practitioner write-up on iterative offensive review of a real Python desktop application: SSRF via ffmpeg subprocess, path-policy bypass, plaintext credential storage, ffmpeg filter-string injection, fail-open authorization, and the recurring pattern of "fix introduces regression." [Read →](FIELD_NOTES.md#1-hardening-limewire-v4)
- **Auto-classifying 917 stars into 26 GitHub Lists via the unstable Stars API** — A small applied-engineering note on reverse-engineering the GitHub Stars list-menu endpoint, handling the `Accept: application/json` quirk, surviving 429 rate limits, and bulk-bookkeeping starred repositories. [Read →](FIELD_NOTES.md#2-bulk-bookkeeping-the-github-stars-api)

---

## Reference Library

Working catalogues used internally and published for the community. Verified, deduplicated, and culled regularly.

| Catalogue | Scope |
|---|---|
| [**Curated Stars Lists**](CURATED_STARS_LISTS.md) | 30 GitHub Stars Lists across the cybersecurity discipline taxonomy, populated and live on the [profile](https://github.com/TeamStarWolf?tab=stars) |
| [**Starred Repos Index**](STARRED_REPOS.md) | Master searchable index of every starred repository organized by major section |
| [**Cybersecurity Book List**](CYBERSECURITY_BOOK_LIST.md) | Reading guide pairing every major security book with companion repos, hands-on labs, and difficulty ratings |
| [**YouTube Channel Library**](YOUTUBE_CHANNELS.md) | Verified-active YouTube channels across 18 disciplines (broken handles and dead channels pruned) |
| [**X / Twitter Follow List**](TWITTER_FOLLOW_LIST.md) | Vetted accounts that consistently publish original research, tooling, or actionable intelligence |

---

## Security Posture

All TeamStarWolf repositories follow a consistent security baseline:

- **CodeQL** static analysis on every push and pull request
- **Dependabot** dependency review and weekly updates
- **OSV-Scanner** continuous vulnerability monitoring
- **`SECURITY.md` policy** with a documented disclosure path on each project
- **`CODEOWNERS`** review requirement on the default branch
- Standardised `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, and `pyproject.toml` / `package.json` metadata across the org

Vulnerabilities can be reported per the policy in each repository's `SECURITY.md`.
