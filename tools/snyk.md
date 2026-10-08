# Snyk

*Snyk Ltd. (private; late-stage, highly funded) · Developer-first application security (SCA, SAST, Container, IaC) + AI security / AppRisk (ASPM)*

Snyk is the developer-first security platform that embeds scanning into the places developers already work - IDEs, pull requests, CLI and CI/CD - to find and fix vulnerabilities in open-source dependencies, first-party code, containers and infrastructure-as-code. It emphasizes actionable fix guidance (upgrade paths, fix PRs) over mere detection. In 2024-2025 it extended into AI/ML and agentic-app security (Snyk AI Trust Platform) and risk-based prioritization (Snyk AppRisk/ASPM).

## Capabilities & architecture

**Core capabilities**
- Snyk Open Source (SCA) - open-source dependency vulnerability + license scanning with automated fix PRs and upgrade paths
- Snyk Code (SAST) - AI-powered static analysis (built on DeepCode) with in-IDE real-time scanning
- Snyk Container - container image and base-image vulnerability scanning with base-image upgrade recommendations
- Snyk IaC - infrastructure-as-code misconfiguration scanning (Terraform, K8s, CloudFormation, ARM)
- Snyk AppRisk (ASPM add-on) - application risk posture, asset discovery, risk-based prioritization across the SDLC
- Snyk DAST (via Probely acquisition) - developer-first dynamic API/web testing
- AI Trust Platform / Invariant Labs Guardrails - securing AI-generated code and AI/agentic applications
- IDE plugins, PR checks, CLI, CI/CD gating, and the Snyk vulnerability database

**Architecture & deployment.** SaaS-first. Scanning runs via IDE plugins, Git/SCM integrations (scanning repos and raising fix PRs), CLI, and CI/CD pipeline steps; results aggregate in the Snyk cloud console. Container scanning hooks into registries and Kubernetes; IaC scans templates in repos/pipelines. Largely agentless for code/SCA/IaC (source and manifest analysis); runtime/cloud monitoring (Snyk Cloud) adds posture context. On-prem broker available for private-repo connectivity.

**Editions & licensing.** Per-contributing-developer model (a contributing developer = made a commit to a private Snyk-monitored repo in the last 90 days; public/OSS contributions excluded). Tiers: Free ($0), Team (from ~$25/dev/mo, adds higher test limits + Jira), Ignite (~$1,260/dev/year for orgs under 50 devs, unlocks higher/unlimited tests), Enterprise (custom). Products can be purchased individually but must sit in the same plan; AppRisk is an Enterprise add-on. Sources disagree on exact free-tier test limits - verify.

**Key integrations.** SCM: GitHub, GitLab, Bitbucket, Azure Repos; IDEs: VS Code, JetBrains, Visual Studio, Eclipse; CI/CD: Jenkins, GitHub Actions, GitLab CI, CircleCI; Container registries + Kubernetes; Ticketing: Jira, ServiceNow; SIEM and cloud providers (AWS, Azure, GCP); Extensive API/CLI.

**Differentiators**
- Developer-first UX: fixes where developers work, with actionable upgrade paths and automated fix PRs - high remediation adoption
- Breadth across SCA + SAST + Container + IaC in one platform with a single policy/priority model
- Strong proprietary vulnerability database and AI-powered SAST (DeepCode)
- Shift-left plus AppRisk ASPM gives both find-early and prioritize-across-portfolio
- Early, aggressive move into securing AI-generated code and agentic apps (Invariant Labs Guardrails)

**Limitations & considerations**
- Per-contributing-developer billing can scale unpredictably and get expensive; third parties report quotes above initial estimates
- Primarily shift-left/pre-production - historically weaker at runtime/production exposure context (improving via Snyk Cloud)
- SAST can produce findings needing tuning; coverage varies by language
- DAST (Probely) is newer and less mature than incumbents like Invicti
- AppRisk/ASPM and AI-security modules are relatively new; Enterprise add-on costs stack

## Vulnerability-mitigation role

Snyk's VM role is Discover-Assess-Prioritize-Remediate for the software supply chain and application code, heavily biased toward fast Remediate/Patch rather than compensating controls: it identifies vulnerable dependencies/images/IaC and proposes the specific upgrade or base-image change that removes the vuln, often as an automated fix PR. Its mitigation value in the pre-patch window is dependency/base-image pinning, blocking vulnerable builds via CI/CD gates (preventing new exposure from shipping), and policy ignore/snooze with justification while a fix is prepared. It shrinks the exposure window by shortening time-to-fix at the source.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Remediate/Patch · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: Identify (software inventory/SBOM), Protect; CIS Controls v8: 16 (Application Software Security), 2 (Software Inventory/SBOM), 7 (Continuous Vulnerability Management), 4 (Secure Configuration for IaC); MITRE ATT&CK mitigations: M1051 Update Software, M1016 Vulnerability Scanning, M1047 Audit; strong relevance to supply-chain compromise (T1195)

**In a critical-CVE scenario.** First 24-72h on a critical CVE in an internet-facing app + cloud workload: (1) Snyk Open Source/Container instantly identifies every project, image and running workload pulling the vulnerable package/base image across all monitored repos; (2) prioritizes by reachability, exploit maturity and whether the vulnerable function is actually called; (3) auto-generates fix PRs with the exact safe upgrade/base-image swap; (4) sets CI/CD gates to fail builds containing the vulnerable version so no new exposure ships; (5) tracks remediation across the portfolio in AppRisk. Pair with a runtime/CNAPP tool for assets Snyk does not build.

## Validation & telemetry

**Log sources**
- Snyk console; REST API at api.snyk.io/rest (docs apidocs.snyk.io); legacy v1 API at api.snyk.io/v1; CLI (snyk test --json, snyk container test --json).
- Webhooks managed via the v1 API: POST /api/v1/org/{orgId}/webhooks (destination URL + signing secret).
- Event Forwarding to SIEM/cloud: Amazon EventBridge (issue + audit events), AWS CloudTrail Lake (audit), AWS Security Hub, Google Security Command Center, CrowdStrike Falcon Next-Gen SIEM (issue events). Audit-event type requires an Enterprise plan; issue events exclude Snyk Cloud issues.
- Audit logs also retrievable by API (org/group audit-log endpoint, separate from REST issues).

**Telemetry format / transport.** JSON everywhere: REST JSON:API (versioned via ?version=YYYY-MM-DD), v1 API JSON, CLI --json output, and webhook POSTs carrying X-Snyk-Event + X-Hub-Signature (HMAC) headers. Event Forwarding emits in each destination's native format.

**Control-presence check (present & configured?).** The 'control' here = scanning is actually wired in and current. The project_snapshot webhook fires on EVERY test (Open Source + container) whether or not issues change = a heartbeat that the project is being scanned. Presence/health = project exists, monitored=true, and a recent last_tested_date / snapshot; for containers, the image is monitored via the registry integration. A project that is 'monitored' but has a stale last_tested_date is configured-but-not-scanning. PR/CI gating (Snyk checks) confirms the control is enforcing in the pipeline.

**Validation signals (actually working?)**
- Per-issue remediation fields prove a fix exists: isUpgradable / isPatchable / isPinnable (REST spellings is-upgradeable, is-patchable, is-pinnable), nearestFixedInVersion, fixedIn, upgradePath.
- Fix VALIDATED when the issue drops out of GET /issues AND appears in the project_snapshot webhook's removedIssues[] array on the next test after the dependency bump = the vulnerable version has left the resolved dependency graph (reachability removal).
- Reachability and exploit-maturity fields (part of the Nov 20 2024 accuracy rollout) refine whether the vuln is actually present/exploitable, not just declared.
- CONFIGURED vs EFFECTIVE: isUpgradable=true means a fix is AVAILABLE (configured path); the issue leaving the next snapshot is the proof it was APPLIED.

**Key events / fields / tables / APIs**
- REST: GET /rest/orgs/{org_id}/issues (Unified Issues API, now GA - covers SCA/SAST/IaC+) with fields effective_severity_level, status, type (e.g. package_vulnerability), coordinates[].remedies, is_fixable flags, ignored; GET /rest/orgs/{org_id}/projects.
- v1 CLI/test JSON: vulnerabilities[].{id, packageName, version, isUpgradable, isPatchable, upgradePath, semver, patches, fixedIn, nearestFixedInVersion, identifiers.CVE}.
- Webhook: event project_snapshot (payload: project, org, group, newIssues[], removedIssues[]); headers X-Snyk-Event (event type) and X-Hub-Signature (HMAC - must verify).
- Event Forwarding event families: issue events and platform audit events (Enterprise).

**Example queries**

*Container image: list issues with an available fix to drive remediation* (CLI (jq))

```
snyk container test <registry>/<image>:<tag> --json | jq '.vulnerabilities[] | select(.isUpgradable==true or .isPatchable==true) | {id, packageName, version, fixedIn, nearestFixedInVersion}'
```

*Pull current open package vulns for an org, then diff daily to detect resolutions* (API/REST)

```
curl -s -H 'Authorization: token $SNYK_TOKEN' 'https://api.snyk.io/rest/orgs/{org_id}/issues?version=2024-10-15&type=package_vulnerability&status=open&limit=100'
```

*Show vulnerabilities actually removed (fixes landing) per project* (SPL (over forwarded project_snapshot events))

```
index=snyk sourcetype="snyk:webhook" event="project_snapshot" | spath path=removedIssues{} output=removed | mvexpand removed | spath input=removed | stats count by project.name id severity
```

**How it mitigates (mechanism).** Snyk is a dependency-graph / reachability oracle, not an inline blocker. The fix is to upgrade/pin/patch the package so the vulnerable version no longer resolves in the graph; the observable is the issue disappearing from /issues (and showing in the next snapshot's removedIssues[]) - reachability removal - plus CI gating that stops a vulnerable build from shipping.

**Logging gotchas**
- REST Issues API coverage drifted: early docs returned 404 for non-Code projects; it is now the GA Unified Issues API. The v1->REST migration guide noted 'fix information is not available yet in the REST API', so fixedIn/nearestFixedInVersion are most reliable in v1/CLI JSON - verify current coverage in apidocs.snyk.io before coding.
- The Nov 20 2024 accuracy rollout can change is-pinnable/is-patchable/is-upgradeable/reachability values (<1% of recurring tests) with no change on your side - values can shift between scans.
- project_snapshot covers Open Source + container only (not Code/IaC); issue events exclude Snyk Cloud.
- Webhooks live on the v1 API (/api/v1/org/{orgId}/webhooks), separate from REST; you MUST verify X-Hub-Signature or payloads are spoofable.
- Event Forwarding was historically MT-US-only / needed enablement for single-tenant, and audit events require Enterprise.
- 'monitored=true' with a stale last_tested_date is configured-but-not-actually-scanning - treat snapshot recency as the health signal.

## Documentation & repositories

_Official documentation & manuals_
- [Snyk documentation hub](https://docs.snyk.io)
- [Snyk API overview (REST + V1)](https://docs.snyk.io/snyk-api)
- [Snyk CLI documentation](https://docs.snyk.io/snyk-cli)
- [Docs machine index for LLMs](https://docs.snyk.io/llms.txt)

_API & developer docs_
- [Snyk REST API (OpenAPI/JSON:API, versioned)](https://docs.snyk.io/developer-tools/snyk-api/rest-api)
- [Snyk API reference & authentication](https://docs.snyk.io/snyk-api)
- [Snyk Apps APIs (build integrations)](https://docs.snyk.io/developer-tools/snyk-api/using-specific-snyk-apis/snyk-apps-apis)
- [Terraform provider for Snyk (community/partner)](https://registry.terraform.io/providers/pavel-snyk/snyk/latest/docs)

_GitHub (official)_
- [Snyk GitHub organization (~240 repos)](https://github.com/snyk)
- [snyk/cli — Snyk CLI (TypeScript, ~5.7k stars)](https://github.com/snyk/cli)
- [snyk/actions — official GitHub Actions for CI scanning](https://github.com/snyk/actions)
- [snyk/snyk-to-html — export CLI reports to HTML](https://github.com/snyk/snyk-to-html)
- [snyk/vscode-extension & snyk/snyk-intellij-plugin — IDE plugins](https://github.com/snyk/vscode-extension)
- [snyk/driftctl — IaC drift detection](https://github.com/snyk/driftctl)

_Community / integration / detection repos_
- [snyk-labs GitHub organization (community/example tooling)](https://github.com/snyk-labs)
- [snyk-apps-demo — starter for building a Snyk App](https://github.com/snyk/snyk-apps-demo)
- [snyk-api-import — bulk import/onboard projects via API](https://github.com/snyk/snyk-api-import)
- [snyk-labs/nodejs-goof & other 'goof' vulnerable demo apps](https://github.com/snyk-labs/nodejs-goof)

_Learning & reference_
- [Snyk Learn — free interactive secure-coding lessons (NIST NICE aligned)](https://learn.snyk.io)
- [Snyk blog](https://snyk.io/blog/)
- [Snyk Vulnerability Database](https://security.snyk.io)
- [Snyk Tutorials & product training —  (learning series within docs)](https://docs.snyk.io)

> Note: Snyk REST API is OpenAPI + JSON:API and requires a date-based ?version= query parameter on every request; the older V1 API is being sunset in favor of REST. API availability can depend on plan tier (historically Business/Enterprise, with some token access on lower tiers) — check the current plans page. Core open-source tooling (CLI, actions, IDE plugins, driftctl, snyk-ls language server) lives under github.com/snyk; demos/experiments under github.com/snyk-labs.

## Current state (2025-26)

Acquired Probely (Nov 2024, developer-first DAST) and Invariant Labs (June 2025, AI/agentic security Guardrails - now part of the Snyk AI Trust Platform); earlier DeepCode (2020 -> Snyk Code). Platform positioned around securing AI-generated code and agentic applications. Pricing remains per-contributing-developer with Free/Team/Ignite/Enterprise tiers; AppRisk is an Enterprise add-on. Exact free-tier test limits and Enterprise pricing vary by source - verify at snyk.io.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
