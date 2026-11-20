# Field Notes

Writeups and lessons learned from building, reviewing, and hardening projects in public. The goal is to document what changed, what it surfaced, and what may be useful to other people doing similar work.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Builders and maintainers who harden and run projects in public

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 2 min (570 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want the lessons from hardening and maintaining a real project in public, or you are about to do similar work and want to know what it surfaced

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Index](#index), [1. Bulk-bookkeeping the GitHub Stars API](#_1-bulk-bookkeeping-the-github-stars-api)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Curated GitHub Stars Lists](/research/CURATED_STARS_LISTS.md), [Starred Repositories](/STARRED_REPOS.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## How To Use This File

- Start with the index if you want the shortest route to a topic.
- Entries are append-only and listed in reverse-chronological order.
- Expect concrete details: file paths, failure modes, fixes, and lessons carried forward.

---

## Index

| # | Entry | Topic |
|---|---|---|
| 1 | [Bulk-bookkeeping the GitHub Stars API](#_1-bulk-bookkeeping-the-github-stars-api) | Web reverse engineering, rate-limit handling |

---

## 1. Bulk-bookkeeping the GitHub Stars API

Project: [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf), the meta-repository hosting the curation catalogues.

Problem: A library of ~1,000 starred repositories that needed to be sorted into 30 GitHub Stars Lists, each with curated names and descriptions. The official `gh` CLI does not expose Lists; the public REST API does not document them; the GraphQL `createUserList` mutation requires the `user` OAuth scope which the standard `gh` token does not hold.

Approach: Reverse-engineer the per-repo `/{owner}/{repo}/lists?experimental=1` UJS endpoint that the GitHub web UI uses for the "Add to list" dropdown, drive it through an authenticated browser session.

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

1. `Accept: application/json` is mandatory. The endpoint returns `406 Not Acceptable` for `text/html`, `text/javascript`, `application/vnd.github+json`, and `text/fragment+html`. Only `application/json` works, despite the response body being HTML in some cases.
2. The PUT is destructive. `list_ids[]` *replaces* the entire set of memberships for that repository. Adding a repo to one list while preserving its existing memberships requires fetching the current state from `/{repo}/lists?experimental=1`, parsing the `data-value` attributes of `aria-selected="true"` items, and unioning before submission.
3. Rate limit kicks in around ~250 requests in a short window. The endpoint returns 429 with no `Retry-After` header. A 1.5-second per-request delay was sufficient to avoid throttling for the remainder of the session. A 90-second backoff cleared the rate-limit state when it did engage.
4. Description body has a server-side length limit. Empirically two of the longer descriptions (~600 chars) returned 500. Trimming below ~400 chars resolved it. The error response is opaque HTML, not a JSON validation error.
5. List slugs are derived from the name and change on rename. Renaming "Daily Driver Toolkit" to "Daily Operational Toolkit" silently changed the canonical URL from `/lists/daily-driver-toolkit` to `/lists/daily-operational-toolkit`. The numeric list ID is stable across renames; cache that, not the slug.
6. Topics are starrable too: via the GraphQL `addStar` mutation against the topic node ID. 200 cybersecurity topics were starred this way without invoking the unstable Stars-list endpoint.

### What was built

- A Python classifier (`smart_categorize.py`) using owner allow-lists and keyword heuristics to plan list memberships for 917 repositories.
- A browser-resident JavaScript runner that paginates the plan in 25-repo batches, with progress persisted to `window.__PG` so a renderer crash mid-run is resumable.
- Verification scripts that page through each list and sanity-check against the planned set.

The end result: 30 Stars Lists, ~872 list-memberships, 0 destructive overwrites of pre-existing memberships.

---

## Contributing future entries

Each entry should answer: what was being built, what did the work surface, what changed in the code or process as a result. Entries are short on prose and heavy on specifics: file paths, commit ranges, error codes, kept patterns. Numbered sequentially, never edited after publication except to fix factual errors (with a note).

## Related pages

- [Research](/research/README.md)
- [Curated GitHub Stars Lists](/research/CURATED_STARS_LISTS.md)
- [Starred Repositories Index](/STARRED_REPOS.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
