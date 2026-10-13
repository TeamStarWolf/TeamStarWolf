# Invicti

*Invicti Security (PE-backed: Summit Partners majority since Oct 2021 $625M investment; Turn/River Capital remaining shareholder) · Application security testing (DAST/IAST) expanding to a full AppSec/ASPM platform*

Invicti is the umbrella brand uniting two pioneering DAST scanners - Netsparker (rebranded Invicti in 2022) and Acunetix - plus the Kondukto ASPM engine acquired in 2025. Its signature is proof-based scanning: when it finds a likely vulnerability it safely auto-exploits it to confirm the finding is real, cutting false positives. In 2025 it broadened from pure web-app scanning into a unified application security platform spanning DAST, SAST, IAST, SCA, API security, container and secrets scanning, and ASPM.

## Capabilities & architecture

**Core capabilities**
- DAST - black-box dynamic scanning of web apps and APIs (both Invicti and Acunetix engines)
- Proof-Based Scanning / automated vulnerability verification - safely exploits to confirm real issues and minimize false positives
- IAST - Invicti 'Shark' and Acunetix 'AcuSensor' runtime agents that confirm which findings reach vulnerable code
- API security scanning (REST, SOAP, GraphQL)
- SAST (static analysis), SCA (software composition analysis / open source), container security, secrets scanning
- ASPM (Application Security Posture Management) powered by Kondukto - correlates and orchestrates findings across tools
- Authenticated scanning, CI/CD and issue-tracker integration, discovery/crawling of unknown web assets

**Architecture & deployment.** Delivered as SaaS (cloud) and on-prem/self-hosted. Core DAST scans from outside the application like an attacker (black-box). Optional IAST sensors (Shark/AcuSensor) deploy as lightweight agents inside the app runtime to improve coverage and confirmation. Scanners integrate into CI/CD pipelines and ticketing. The ASPM/Kondukto layer ingests and correlates findings from Invicti's own engines plus third-party AppSec tools. No inline production proxy - it is a testing tool, not a runtime WAF.

**Editions & licensing.** Commercial subscription. Invicti (ex-Netsparker) is pitched at enterprise scale/automation; Acunetix at smaller teams wanting a hands-on approach. Licensing is typically per-target/per-website or per-app-seat, tiered by number of targets and features; enterprise licensing for the broader platform. Pricing is quote-based (not publicly posted).

**Key integrations.** CI/CD: Jenkins, GitHub Actions, GitLab, Azure DevOps, Bamboo; Issue trackers: Jira, GitHub Issues, Azure Boards, ServiceNow; SIEM; WAF: can export virtual-patch rules to some WAFs; ASPM (Kondukto): ingests third-party SAST/SCA/DAST tools for consolidated posture.

**Differentiators**
- Proof-Based Scanning: auto-confirms exploitable vulns, dramatically reducing false positives and triage load
- Two mature, complementary DAST engines under one brand (Invicti + Acunetix) covering enterprise and SMB
- IAST (Shark/AcuSensor) adds grey-box confirmation and code-location detail to black-box findings
- 2025 expansion into DAST-first ASPM (Kondukto) correlating runtime-validated findings with broader AppSec data
- Strong at discovering and scanning large, sprawling web/API estates

**Limitations & considerations**
- DAST inherently covers only reachable/running app surface - gaps vs pure SAST for non-executed code paths
- Reviewers report friction configuring authenticated/complex SPA scans
- Two engines (Invicti vs Acunetix) can create overlap/confusion about which to deploy
- ASPM/SAST/SCA breadth is newer (post-2025 Kondukto) and less proven than the core DAST
- As a testing tool it finds and verifies vulns but does not itself block exploitation in production (needs WAF integration for virtual patching)

## Vulnerability-mitigation role

Invicti's VM role is Assess/Scan-Prioritize-Validate for the web/API layer: it finds application vulnerabilities, proves they are real (reducing noise), and pinpoints the vulnerable code via IAST so remediation is targeted. As a compensating control it supports virtual patching by exporting rules to integrated WAFs so a confirmed vuln can be blocked at the WAF while developers prepare a code fix - mitigating the exposure window before the patch ships. Re-scanning validates the fix or virtual patch.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Validate

**Framework mapping:** NIST CSF 2.0: Identify (app/API inventory), Protect, Detect; CIS Controls v8: 16 (Application Software Security), 7 (Continuous Vulnerability Management), 18 (Penetration Testing); MITRE ATT&CK mitigations: M1050 Exploit Protection, M1051 Update Software, M1016 Vulnerability Scanning; OWASP Top 10 / ASVS alignment for web findings

**In a critical-CVE scenario.** First 24-72h on a critical CVE in an internet-facing app: (1) run targeted Invicti/Acunetix DAST across the affected web apps and APIs to detect whether the vulnerable condition is present and reachable; (2) use Proof-Based Scanning and Shark/AcuSensor IAST to confirm exploitability and locate the vulnerable code; (3) prioritize confirmed, exploitable findings over theoretical ones; (4) export a virtual-patch/WAF rule to block exploitation while developers fix the code; (5) re-scan to validate the fix and feed results into ASPM for posture tracking. Cloud workload coverage is limited to its web/API surface - pair with a VM/CNAPP tool.

## Validation & telemetry

**Log sources**
- Invicti Platform / Invicti Enterprise (cloud or on-prem) and Invicti Standard (desktop).
- Invicti Enterprise REST API (API-key/token) for scans and issues; a documented Scan REST API accepts OpenAPI3/Swagger2/RAML/WADL/Postman definitions for API scanning.
- Webhooks and send-to integrations (Jira, ServiceNow, etc.); report exports with a 'confirmed issues only' option (PDF/HTML, not JSON).
- Third-party pull (e.g. Praetorian integration) reads scan results via the REST API and filters on issue STATE (processes 'new'/'confirmed', excludes 'fixed'/'ignored') - confirms a state filter exists even though the schema is not public.

**Telemetry format / transport.** JSON over REST API + webhook POST payloads; report exports (PDF/HTML/XML/JSON). Could not verify the exact vulnerabilities endpoint path (e.g. /api/1.0/vulnerabilities) or its JSON field names from public docs.

**Control-presence check (present & configured?).** DAST confirms an app-layer control is present by actually exercising it. Invicti's Proof-Based Scanning issues a safe exploit and attaches PROOF (e.g. echoed command output / extracted data) when a finding is Confirmed. Issue statuses: Present (default on discovery), Accepted Risk, False Positive, Fixed (Unconfirmed), Fixed (Confirmed), Fixed (Can't Retest), Ignored. A WAF / input-validation / auth control being present and effective shows up as Invicti's attack being neutralized so the issue is NOT confirmed (or moves to Fixed (Confirmed) on retest).

**Validation signals (actually working?)**
- Retest -> 'Fixed (Confirmed)': Invicti re-runs a scan profile restricted to that single vulnerability; if the proof-based exploit no longer succeeds the status becomes Fixed (Confirmed) = the fix / WAF rule actually stops the attack (verified, not merely deployed).
- 'Rediscovered' / 'Revived' status = a previously-fixed issue reappears on a later scan = the mitigation regressed or was removed.
- 'Confirmed'=true + a proof artifact on a still-OPEN (Present) issue = the control is absent or ineffective at the app layer.
- CONFIGURED vs VERIFIED line: Fixed (Unconfirmed) = remediation reported but NOT retested; Fixed (Can't Retest) = Invicti could not verify - neither should be treated as mitigated. Only Fixed (Confirmed) is proof.

**Key events / fields / tables / APIs**
- Issue status strings (seen raw via the ServiceNow integration mapping): Present, FixedConfirmed, FixedUnconfirmed, FixedCantRetest, AcceptedRisk, FalsePositive, Ignored, Revived/Rediscovered.
- Per-issue: confirmed flag, severity, vulnerability type / CWE, proof/evidence content, retest scan status.
- Scan REST API (scan create/status, API-definition import). Retest is driven from Scans > All scans in the UI.
- NOTE: exact JSON field names (e.g. LastSeenDate) and whether a retest can be triggered via API are NOT confirmed from public docs - verify in your tenant's Swagger/API reference.

**Example queries**

*List issues still in an exploitable state (Present/Confirmed) to prove controls are NOT yet effective* (API/REST (shape - verify in tenant Swagger))

```
GET https://<enterprise-host>/api/1.0/vulnerabilities?state=Present,Confirmed  (Authorization: <API_TOKEN>) -- endpoint/param names unverified publicly; a known integration filters on state in {new, confirmed} and excludes {fixed, ignored}
```

*Validate a fix for one vulnerability (produces Fixed (Confirmed) or Rediscovered)* (Native UI / retest)

```
Scans > All scans > open target > vulnerability details > Retest  (runs a single-vuln scan profile; result = Fixed (Confirmed) if the proof-based attack no longer succeeds, else Rediscovered). Ensure login/logout is configured or the retest lands in Fixed (Can't Retest).
```

*Alert when a confirmed issue regresses after a reported fix* (SPL (over forwarded Invicti webhook/issue JSON))

```
index=appsec sourcetype=invicti:issues (state="Revived" OR state="Rediscovered") | stats latest(_time) as seen by target_url vuln_type severity
```

**How it mitigates (mechanism).** Invicti is an active oracle at the application layer: a retest fires the same proof-based attack through the live app/WAF, so an issue moving to Fixed (Confirmed) means the attack path is now blocked inline (WAF signature, input validation, or patched code). The observable is the state transition plus the disappearance of the proof artifact, not a configuration claim.

**Logging gotchas**
- Fixed (Unconfirmed) and Fixed (Can't Retest) are NOT verification - only Fixed (Confirmed) proves the control works. Auth-gated apps often fall into Can't Retest when login/logout isn't set for the retest profile.
- A WAF that blocks only the specific probe can produce Fixed (Confirmed) while the underlying code is still vulnerable (virtual patch vs real fix) - DAST confirms the attack PATH is closed, not that the bug is gone.
- Public API docs are thin: the vulnerabilities endpoint schema, LastSeenDate, and whether retest is API-triggerable are unconfirmed - verify in your instance. A Platform webhook that fires specifically on 'confirmed issue' is not clearly documented; Invicti Standard's send-to webhook is a manual per-issue action.
- The 'confirmed issues only' report export is PDF/HTML, not a JSON feed.

## Documentation & repositories

_Official documentation & manuals_
- [Invicti documentation site](https://docs.invicti.com)
- [Invicti Platform docs (Invicti Platform 'ip' section)](https://docs.invicti.com/ip/)
- [Acunetix product manual (Standard & Premium)](https://www.acunetix.com/support/docs/wvs)
- [Invicti AppSec (ASPM / Acunetix integration guides)](https://docs.invicti.com/appsec/)
- [Invicti Support / Help Center](https://www.invicti.com/support)

_API & developer docs_
- [Invicti Platform API — getting started](https://docs.invicti.com/ip/category/platform-api)
- [Get your Invicti Platform API key](https://docs.invicti.com/ip/s1-get-your-api-key)
- [Access API documentation (Swagger UI from user settings)](https://docs.invicti.com/ip/access-api-documentation)
- [Acunetix API usage articles —  (examples; no formal standalone REST reference published)](https://www.acunetix.com/blog/)

_GitHub (official)_
- [Invicti Security GitHub organization](https://github.com/Invicti-Security)
- [brainstorm — LLM-assisted web fuzzing (ffuf wrapper)](https://github.com/Invicti-Security/brainstorm)
- [netsparker-custom-security-checks — custom checks for Netsparker/Invicti](https://github.com/Invicti-Security/netsparker-custom-security-checks)
- [netsparker-cloud-scan-plugin — Jenkins plugin to trigger Enterprise scans](https://github.com/Invicti-Security/netsparker-cloud-scan-plugin)
- [invicti-platform-onprem-tools — on-prem deployment tooling](https://github.com/Invicti-Security/invicti-platform-onprem-tools)

_Community / integration / detection repos_
- Acunetix/Invicti CI integrations are mostly first-party (Jenkins, Azure DevOps, GitHub) under the Invicti-Security org; few notable independent community repos exist for this commercial DAST.
- [jenkinsci/netsparker-cloud-scan-plugin (upstream Jenkins plugin index)](https://plugins.jenkins.io/netsparker-cloud-scan/)

_Learning & reference_
- [Invicti blog](https://www.invicti.com/blog/)
- [Acunetix blog](https://www.acunetix.com/blog/)
- [Invicti web security resources / learning center](https://www.invicti.com/learn/)

> Note: Invicti Security owns both Acunetix and Netsparker; 'Netsparker' was rebranded to 'Invicti'. Documentation is split: docs.invicti.com covers the modern Invicti Platform (the 'ip' path), while acunetix.com/support/docs covers the standalone Acunetix scanner. The Platform API is OpenAPI/Swagger and the full reference is only reachable after authenticating and generating an API key (Inventory, DAST, Reports API sections; regional base URLs for SaaS). Acunetix tokens are shown only once on generation; default on-prem port is 3443.

## Current state (2025-26)

Invicti acquired Kondukto (announced Aug 14 2025, Istanbul-based ASPM pioneer) to deliver proof-based ASPM, and now markets a unified platform spanning DAST, SAST, IAST, SCA, API security, secrets, container security and ASPM. Ownership: Summit Partners majority (since Oct 2021 $625M growth investment), Turn/River Capital remains a shareholder - NOT Third Rock (that is an unrelated biotech VC). Netsparker->Invicti rebrand was March 2022; Acunetix remains a distinct SMB-oriented product line under Invicti.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
