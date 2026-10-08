# HackerOne

*HackerOne, Inc. (private) · Human-powered + agentic AI offensive security: bug bounty, VDP, PTaaS, AI red teaming, code security*

HackerOne is the leading hacker-powered security platform, pairing the world's largest community of external security researchers with an AI layer (Hai) to find and fix vulnerabilities across the SDLC - including AI systems. Its products span bug bounty, vulnerability disclosure (Response/VDP), pentest-as-a-service, AI red teaming, and (from 2025) AI-native code security. It operationalizes crowdsourced and expert human testing with triage, dedup, routing and remediation workflow on one platform.

## Capabilities & architecture

**Core capabilities**
- Bug Bounty - managed crowdsourced vulnerability discovery with payouts to vetted researchers
- HackerOne Response (VDP) - receives, routes and resolves vulnerability reports from external researchers; policy creation/launch guidance and trend reporting
- Pentest as a Service (PTaaS) / Agentic Pentest - on-demand pentests for web, mobile, API, cloud and AI, with vetted experts, live reporting and (2025-2026) agentic AI support under human review
- AI Red Teaming - adversarial testing of AI systems/models for prompt injection, tool misuse, data exfiltration and safety risks
- HackerOne Code - AI-native, expert-supported source-code security review (evolved from the 2022 PullRequest acquisition); GA announced Oct 2025
- Hai - in-platform AI, evolved from copilot to agentic AI system: triage, context, remediation guidance, program-data querying
- Hai Triage (managed human triage analysts), dedup/validation, and remediation workflow integration

**Architecture & deployment.** SaaS platform. Customers define scope and policy; researchers/pentesters test the customer's internet-facing and internal (via VPN/agent) targets. Reports flow into the HackerOne platform for triage (Hai AI + human Triage analysts), dedup, severity rating and routing to the customer's dev/ticketing systems. It is an orchestration + human/AI-testing layer, not a scanner or inline control. Code security integrates with SCM for AI-native review.

**Editions & licensing.** Subscription for platform access plus program-specific costs. Bug bounty = platform/subscription fee + variable bounty payouts set by the customer. PTaaS priced per pentest/engagement or subscription. Response/VDP and Code licensed as products. Enterprise, quote-based; also offered via AWS Marketplace.

**Key integrations.** Ticketing/dev: Jira, GitHub, GitLab, ServiceNow, Azure DevOps; SIEM/SOAR; Collaboration: Slack, Microsoft Teams; SCM for HackerOne Code; APIs for findings export; AWS Marketplace availability.

**Differentiators**
- Largest community of external security researchers - finds novel, chained, business-logic and real-world-exploitable issues automated scanners miss
- Breadth from VDP (free intake channel) through paid bounty, PTaaS and AI red teaming on one platform
- Early, serious AI red teaming for LLM/agentic systems
- Hai agentic AI + managed human triage reduces customer triage burden and noise
- 2025 scale: 580,000+ validated vulnerabilities, ~1,950-2,000 active enterprise programs, ~$81M annual payouts

**Limitations & considerations**
- Human-powered testing is point-in-time/variable, not continuous automated coverage - complements, does not replace, scanners/VM
- Public bug bounty/VDP programs can generate high submission volume and noise requiring triage effort
- Finds vulnerabilities but does not patch or block them - remediation is entirely the customer's job
- Bounty payout costs are variable and can be hard to budget
- 'Hai' name ambiguity (AI layer vs human 'Hai Triage analysts') can confuse; some 2026 roadmap items (Agentic PTaaS GA) are aggregator-reported - verify

## Vulnerability-mitigation role

HackerOne's VM role is Discover-Assess-Validate via human/agentic offensive testing - it proves real exploitability of vulnerabilities (including those scanners miss or misrate) and validates whether a patch or mitigation actually closed the issue (retesting). It is not itself a compensating/virtual-patching control; its mitigation contribution is intelligence: confirming which exposures are genuinely exploitable in the real environment so defenders apply patches or compensating controls to the right things first, and verifying the fix held. VDP also provides a safe-harbor channel to learn of exploitable exposure before attackers weaponize it.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: Identify, Detect, Respond (coordinated disclosure); CIS Controls v8: 18 (Penetration Testing), 7 (Continuous Vulnerability Management), 16 (Application Software Security); MITRE ATT&CK: offensive emulation across many techniques; mitigations validated include M1051 Update Software and M1050 Exploit Protection (via retest); aligns to ISO 29147/30111 coordinated disclosure

**In a critical-CVE scenario.** First 24-72h on a critical CVE in an internet-facing app + cloud workload: (1) spin up or expand a bounty/PTaaS scope targeting the affected internet-facing app to confirm whether the CVE is actually exploitable in the live environment (and surface variants/chains); (2) researchers/agentic pentest attempt safe exploitation and report with reproduction steps; (3) Hai + human triage validate, dedup and rate severity, routing confirmed findings to dev/ticketing; (4) after the team patches or applies a compensating control, request retest to validate the fix closed the exposure; (5) VDP keeps an open channel for related reports. Cloud workload coverage depends on scope granted to testers; pair with VM/CNAPP for breadth.

## Validation & telemetry

**Log sources**
- HackerOne platform; official REST API at api.hackerone.com (Core Resources reference at api.hackerone.com/customer-resources) - resources include reports, report state changes, comments/activities, and structured scopes.
- Integrations: Jira/ServiceNow, and SIEM/SOAR connectors (Elastic HackerOne integration, Tracecat, Mindflow).
- Undocumented GraphQL at hackerone.com/graphql backs the public Hacktivity feed - it moves and is NOT authoritative; use REST for report/scope/bounty data.

**Telemetry format / transport.** JSON:API over HTTPS REST (api.hackerone.com); integration-specific formats downstream (e.g. Elastic ECS). Token auth from program settings; available on Professional/Community/Enterprise editions.

**Control-presence check (present & configured?).** The 'control' is continuous adversarial validation over an asset. Confirm it is active by checking the program's structured_scopes: entries marked eligible_for_submission (URLs, domains, IPs, CIDR blocks) define what is actually under test. An asset NOT in a structured scope receives no validation (a coverage gap that can masquerade as 'no findings'). Confirm API access with a program token.

**Validation signals (actually working?)**
- Report state machine new -> triaged -> resolved. The RETEST flow is the strong signal: the program requests a retest (via a comment/activity), the researcher re-runs the actual exploit against production, and on program approval the report closes as Resolved with a bounty; if the retest is not performed the status returns to Triaged. Resolved-after-researcher-retest = human-verified that the fix actually stops the exploit.
- The /reports/{id}/state_changes endpoint records the transition (e.g. auto-resolve when the linked internal ticket is resolved).
- hai_priority_score / hai_prioritization_tier attributes (recent report-object additions) for triage context.
- CONFIGURED vs VERIFIED: a team can set state=resolved WITHOUT an independent retest (auto-resolve on ticket close) - only the researcher-approved retest path is external validation.

**Key events / fields / tables / APIs**
- Report object attributes: state (new, triaged, resolved, duplicate, informative, not-applicable, spam, ...), created_at, triaged_at, closed_at, title, severity/rating, weakness (CWE), plus structured_scope and bounty relationships.
- Endpoints: GET /v1/reports (list + filter by state/program), GET /v1/reports/{id}, POST /v1/reports/{id}/state_changes (change state), POST /v1/reports/{id}/activities (comments, incl. retest request), structured-scopes resource.
- NOTE: exact attribute spellings (e.g. a bounty-amount field name, the retest relationship) are NOT confirmed from public docs and drift (hai_* were added recently) - verify in the Core Resources reference or by inspecting a real report response.

**Example queries**

*List fix-validated (resolved) reports for a program since a date* (API/REST)

```
curl -s -u $H1_USER:$H1_TOKEN 'https://api.hackerone.com/v1/reports?filter%5Bprogram%5D%5B%5D=<handle>&filter%5Bstate%5D%5B%5D=resolved&filter%5Blast_activity_at__gt%5D=2026-01-01T00:00:00Z'  (verify filter keys against Core Resources)
```

*Record a verified fix by transitioning a report to resolved* (API/REST)

```
curl -s -X POST -u $H1_USER:$H1_TOKEN 'https://api.hackerone.com/v1/reports/<id>/state_changes' -H 'Content-Type: application/json' -d '{"data":{"type":"state-change","attributes":{"state":"resolved","message":"Retest passed, fix verified in prod"}}}'
```

*Request the finder re-test after deploying a fix (drives the validation flow)* (API/REST)

```
curl -s -X POST -u $H1_USER:$H1_TOKEN 'https://api.hackerone.com/v1/reports/<id>/activities' -H 'Content-Type: application/json' -d '{"data":{"type":"activity-comment","attributes":{"message":"Fix deployed - please retest","internal":false}}}'
```

**How it mitigates (mechanism).** HackerOne is human adversarial validation: a report resolved after an approved retest means an external researcher re-executed the real exploit against the live system and it no longer works - the strongest real-world proof a mitigation holds. The observable is the state transition to Resolved recorded via state_changes plus the retest approval, not any config or inline-block signal.

**Logging gotchas**
- 'Resolved' can be set by the team without an independent retest (e.g. auto-resolve on internal ticket close) - only the researcher-approved retest path is true external validation; distinguish a state_changes-set resolution from a completed retest.
- The hackerone.com/graphql / Hacktivity endpoint is undocumented, moves, and is not authoritative - use REST for scope/state/bounty.
- API is edition-gated (Professional/Community/Enterprise) and exact attribute names drift (hai_* recently added) - verify against the Core Resources reference, do not hardcode.
- structured_scope eligible_for_submission defines what is actually under test; assets outside it get no validation - absence of reports there is a coverage gap, not assurance.

## Documentation & repositories

_Official documentation & manuals_
- [HackerOne Platform Documentation (Help Center)](https://docs.hackerone.com)
- [Get Started section —   (navigate from docs.hackerone.com 'Get Started')](https://docs.hackerone.com/en/collections/...)
- [Run a Program (customer/program-owner guidance) —  (Run a Program section)](https://docs.hackerone.com)
- [Integrate Tools (third-party integrations incl. GitHub/Jira) —  (Integrate Tools section)](https://docs.hackerone.com)

_API & developer docs_
- [HackerOne API documentation](https://api.hackerone.com)
- [HackerOne API getting started](https://api.hackerone.com/getting-started/)
- [HackerOne REST API reference (reports, programs, bounties, balances)](https://api.hackerone.com/customer-resources/)
- [HackerOne GraphQL API (used by the official MCP server) — see](https://github.com/Hacker0x01/hackerone-graphql-mcp-server)

_GitHub (official)_
- [Hacker0x01 — HackerOne's verified official GitHub organization (~168 repos)](https://github.com/Hacker0x01)
- [hacker101 — source for Hacker101.com free security class (~14.6k stars)](https://github.com/Hacker0x01/hacker101)
- [hackerone-graphql-mcp-server — MCP server for the HackerOne GraphQL API](https://github.com/Hacker0x01/hackerone-graphql-mcp-server)
- [react-datepicker — widely used React component maintained by HackerOne](https://github.com/Hacker0x01/react-datepicker)

_Community / integration / detection repos_
- [kryndex/hackerone-client — community Node client library (limited operations)](https://github.com/kryndex/hackerone-client)
- [nu11pointer/hackerone-cli — unofficial CLI client over the official API](https://github.com/nu11pointer/hackerone-cli)

_Learning & reference_
- [Hacker101 — free web & mobile security course](https://www.hacker101.com)
- [Hacker101 CTF — hands-on capture-the-flag labs](https://ctf.hacker101.com)
- [HackerOne blog](https://www.hackerone.com/blog)
- [Hacktivity (public disclosed reports)](https://hackerone.com/hacktivity)

> Note: The official API lives at api.hackerone.com (NOT docs.hackerone.com); the docs.hackerone.com Help Center is the product/program documentation portal (12 sections incl. Get Started, Run a Program, Integrate Tools, Pentesting, AI) but has no standalone API section. Official GitHub org is 'Hacker0x01' (verified controlling hackerone.com) — note github.com/hackerone is an UNRELATED personal user account, not HackerOne. REST API uses HTTP Basic auth (API token identifier + token value); a newer GraphQL API also exists. hackerone-client / hackerone-cli are community, not official.

## Current state (2025-26)

Oct 15 2025: Hai evolved from copilot to an agentic AI system, and HackerOne Code (AI-native source-code security) reached GA; company previewed Agentic Pentest as a Service. 2025 Hacker-Powered Security Report cites 580,000+ validated vulnerabilities, ~1,950 active programs, ~$81M payouts. HackerOne Code traces to the 2022 PullRequest acquisition - no new 2025-2026 acquisition surfaced. Jan 2026 Agentic PTaaS launch is aggregator-reported - verify against HackerOne's newsroom. Market context for the group: Google closed its ~$32B acquisition of Wiz (Mar 11 2026); Cisco closed its ~$28B Splunk acquisition (Mar 2024); CrowdStrike Falcon Exposure Management is CrowdStrike-built (not an acquisition).

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
