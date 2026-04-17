# Field Notes

Writeups and lessons learned from building, reviewing, and hardening projects in public. The goal is to document what changed, what it surfaced, and what may be useful to other people doing similar work.

## How To Use This File

- Start with the index if you want the shortest route to a topic.
- Entries are append-only and listed in reverse-chronological order.
- Expect concrete details: file paths, failure modes, fixes, and lessons carried forward.

---

## Index

| # | Entry | Topic |
|---|---|---|
| 2 | [Bulk-bookkeeping the GitHub Stars API](#2-bulk-bookkeeping-the-github-stars-api) | Web reverse engineering, rate-limit handling |
| 1 | [Hardening LimeWire v4 — 32 vulnerabilities, 3 audit rounds](#1-hardening-limewire-v4) | Application security, secure coding patterns |

---

## 1. Hardening LimeWire v4

**Project:** [TeamStarWolf/LimeWire](https://github.com/TeamStarWolf/LimeWire) — a Python desktop audio production studio (~100 source files, Tkinter GUI, ffmpeg/yt-dlp subprocess heavy).

**Method:** Three iterative rounds of `code-reviewer` agent audits with manual triage, `pytest` regression coverage on the security module after each fix, and a hard "fix-introduces-regression" check before every commit.

**Outcome:** 32 confirmed vulnerabilities patched across 9 files. The complete diff is committed in the LimeWire main branch under tags `v4.0.0`–`v4.0.3`. Commit messages include the CWE family for each fix.

### Findings by class

| Class | Count | Examples |
|---|---|---|
| SSRF / unvalidated subprocess input | 6 | ffmpeg `-i` accepting `http://`, `smb://`, `rtsp://` URLs in `audio_processing.py`, `analyze.py`, `converter.py` |
| Path policy bypass | 3 | `require_allowed_write` returning silently when `_ALLOWED_ROOTS` was never initialised; `~/Documents` and `~/Music` were the entire allowed surface |
| Plaintext credential storage | 2 | API client secrets (Spotify, YouTube, TIDAL, Deezer) stored unencrypted in `~/.limewire_settings.json` despite OAuth tokens being DPAPI-encrypted |
| Filter-string injection (ffmpeg) | 2 | Two-pass loudnorm interpolating ffprobe-parsed JSON values directly into ffmpeg's `-af` filter chain without numeric validation |
| URL injection (frontend) | 1 | `web/frontend/app.js` rendering `info.thumbnail` from yt-dlp output as `<img src>` without `is_public_http_url` validation |
| Honest-encryption mislabelling | 1 | Non-Windows fallback to base64 obfuscation while UI still displayed "Encrypted Storage — DPAPI" |
| Subprocess allowlist gaps | 4 | Bare `subprocess.Popen` for FL Studio, `open`, and `xdg-open` outside the `_ALLOWED_BINARIES` policy |
| Web API path-traversal & key allowlists | 3 | Validated under `_DOWNLOAD_DIR_RESOLVED` and `_SAFE_KEYS` |
| Token storage primitives | 2 | DPAPI wrappers, atomic writes, structured `safe_subprocess.CommandResult.ok` |
| Misc input-validation | 8 | URL allowlist regexes, sanitize_filename Windows reserved-name handling, FFmpeg/FFprobe wrapper-call enforcement |

### Recurring patterns

1. **The fix-introduces-regression problem.** Two rounds of audit produced fixes that themselves needed fixing. Examples: `_safe_float` accidentally returning `int` strings that ffmpeg interpreted differently; the path-policy initialiser not being called from `app.py` startup despite the policy being defined. The lesson: every security fix needs both a positive test (the policy *blocks* the bad case) and a negative test (the policy *allows* the legitimate case).
2. **The "permissive default" anti-pattern.** Three of the bypasses (`require_allowed_write`, `_ALLOWED_BINARIES` skip on uninitialised state, the non-Windows fallback) were "fail open" defaults that silently degraded security. Replaced with "fail closed and log warn" patterns throughout.
3. **`subprocess` is the perimeter.** The biggest cluster of issues was in subprocess invocations. The `safe_subprocess` module — a binary allowlist plus mandatory timeouts plus structured `CommandResult` — paid for itself across 9 separate fix sites once it was the sole entry point.

### What stays in the codebase

- `limewire/security/safe_subprocess.py` — `_ALLOWED_BINARIES = {ffmpeg, ffprobe, yt-dlp, open, xdg-open}`, `shell=False`, mandatory timeout
- `limewire/security/safe_paths.py` — `init_allowed_roots()` called from `app.py:__init__`, fail-closed default, scoped roots
- `limewire/security/safe_json.py` — size limits (5 MB), depth checks (10 levels), key allowlists for themes/settings
- `limewire/security/network.py` — `is_public_http_url` SSRF guard now applied at every URL ingress
- 195+ `pytest` cases under `tests/test_safe_*.py` covering each of the above

---

## 2. Bulk-bookkeeping the GitHub Stars API

**Project:** [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) — the meta-repository hosting the curation catalogues.

**Problem:** A library of ~1,000 starred repositories that needed to be sorted into 30 GitHub Stars Lists, each with curated names and descriptions. The official `gh` CLI does not expose Lists; the public REST API does not document them; the GraphQL `createUserList` mutation requires the `user` OAuth scope which the standard `gh` token does not hold.

**Approach:** Reverse-engineer the per-repo `/{owner}/{repo}/lists?experimental=1` UJS endpoint that the GitHub web UI uses for the "Add to list" dropdown, drive it through an authenticated browser session.

### Endpoint shape

```
POST /{owner}/{repo}/lists
  authenticity_token=<csrf from include-fragment>
  _method=put
  repository_id=<numeric repo ID>
  context=user_list_menu
  list_ids[]=<id1>&list_ids[]=<id2>&...
  user_list_menu_dirty=1

Headers:
  Accept: application/json    ← required; text/html returns 406
  X-Requested-With: XMLHttpRequest
```

### Practical notes

1. **`Accept: application/json` is mandatory.** The endpoint returns `406 Not Acceptable` for `text/html`, `text/javascript`, `application/vnd.github+json`, and `text/fragment+html`. Only `application/json` works, despite the response body being HTML in some cases.
2. **The PUT is destructive.** `list_ids[]` *replaces* the entire set of memberships for that repository. Adding a repo to one list while preserving its existing memberships requires fetching the current state from `/{repo}/lists?experimental=1`, parsing the `data-value` attributes of `aria-selected="true"` items, and unioning before submission.
3. **Rate limit kicks in around ~250 requests in a short window.** The endpoint returns 429 with no `Retry-After` header. A 1.5-second per-request delay was sufficient to avoid throttling for the remainder of the session. A 90-second backoff cleared the rate-limit state when it did engage.
4. **Description body has a server-side length limit.** Empirically two of the longer descriptions (~600 chars) returned 500. Trimming below ~400 chars resolved it. The error response is opaque HTML, not a JSON validation error.
5. **List slugs are derived from the name and change on rename.** Renaming "Daily Driver Toolkit" to "Daily Operational Toolkit" silently changed the canonical URL from `/lists/daily-driver-toolkit` to `/lists/daily-operational-toolkit`. The numeric list ID is stable across renames; cache that, not the slug.
6. **Topics are starrable too** — via the GraphQL `addStar` mutation against the topic node ID. 200 cybersecurity topics were starred this way without invoking the unstable Stars-list endpoint.

### What was built

- A Python classifier (`smart_categorize.py`) using owner allow-lists and keyword heuristics to plan list memberships for 917 repositories.
- A browser-resident JavaScript runner that paginates the plan in 25-repo batches, with progress persisted to `window.__PG` so a renderer crash mid-run is resumable.
- Verification scripts that page through each list and sanity-check against the planned set.

The end result: 30 Stars Lists, ~872 list-memberships, 0 destructive overwrites of pre-existing memberships.

---

## Contributing future entries

Each entry should answer: **what was being built, what did the work surface, what changed in the code or process as a result.** Entries are short on prose and heavy on specifics — file paths, commit ranges, error codes, kept patterns. Numbered sequentially, never edited after publication except to fix factual errors (with a note).
