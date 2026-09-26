# Security Policy

TeamStarWolf is a **documentation and data library** — a collection of Markdown references, learning paths, and machine-readable mapping datasets. It ships no executable application, so it has no runtime attack surface of its own. The "security" concerns that matter here are the **accuracy and integrity of the content** and the **safety of the small build/validation scripts** in `scripts/`.

## What to report, and how

| You found… | Please report via |
|---|---|
| A factual error, a wrong ATT&CK/CVE/control ID, or a mapping presented as authoritative that isn't | A [content-fix issue](../../issues/new/choose) |
| A broken or hijacked outbound link (e.g. a cited domain that now resolves to something malicious) | A [content-fix issue](../../issues/new/choose), marked **urgent** |
| A genuine vulnerability in a `scripts/` build/validation script, or anything you'd rather not disclose publicly | **[Private vulnerability reporting](../../security/advisories/new)** (GitHub → Security → Report a vulnerability) |

For anything sensitive, prefer the private advisory channel over a public issue so it can be triaged before disclosure.

## Scope

- **In scope:** content accuracy and integrity; the `scripts/` build and validation code; the CI workflows; the docsify site configuration.
- **Out of scope:** the security of third-party sites, tools, or datasets this library *links to* or *describes* — report those to their respective owners. Descriptions of offensive techniques are documented for **defensive** purposes; this library contains no exploit code or operational attack tooling.

## Response

This is a volunteer, community-maintained project — there is no formal SLA. Reports are reviewed on a best-effort basis; well-scoped reports with a source or a reproduction are actioned fastest. Verified content errors are corrected and noted in [CHANGELOG.md](CHANGELOG.md).

## A note on using this library

Everything here is a **reference**, not a guarantee. Commands, queries, and configurations change; verify anything against current official documentation before running it in production, and never test techniques against systems you are not authorized to touch.
