# Tanium

*Tanium Inc. · Converged / Autonomous Endpoint Management (XEM/AEM) — unified IT operations, patching, compliance and endpoint security on one real-time platform*

Tanium is a single-agent platform that unifies IT operations and security operations, giving real-time visibility and control over every managed endpoint at enterprise scale. Its linear-chain peer-to-peer architecture lets a central server query and act on hundreds of thousands of endpoints in seconds, which is the basis for its vulnerability, patch and compliance capabilities. Tanium's current positioning is Autonomous Endpoint Management (AEM), evolving the earlier Converged Endpoint Management (XEM) brand toward AI-driven, recommendation-and-automation-led operations. It solves the fragmentation and stale-data problem of running separate discovery, patch, vuln-scan, compliance and EDR tools.

## Capabilities & architecture

**Core capabilities**
- Tanium Patch — OS patching for Windows, macOS and Linux with real-time deployment status
- Tanium Comply — vulnerability scanning (CVE) and configuration/compliance assessment (CIS, DISA STIG, custom benchmarks)
- Tanium Deploy — third-party application deployment and continuous software updating
- Tanium Discover — active and passive discovery of managed and unmanaged assets
- Tanium Asset — hardware/software inventory, auditing and CMDB enrichment
- Tanium Threat Response — EDR: detection, live investigation, hunting and response
- Tanium Enforce — endpoint policy/configuration enforcement (firewall, BitLocker, AppLocker, etc.)
- Tanium Impact — lateral-movement / privilege-exposure mapping
- Tanium Reveal — sensitive-data discovery (DLP-style)
- Tanium Integrity Monitor, Benchmark, Certificate Manager, SBOM — file integrity, config scoring, cert and software-bill-of-materials visibility
- Tanium Automate — no-code orchestration/workflow automation
- Tanium Ask — agentic AI assistant (launched Converge 2025) for natural-language troubleshooting and remediation
- Tanium Performance — digital employee experience / endpoint performance monitoring
- Autonomous Endpoint Management (AEM) engine — AI recommendations, peer-success benchmarking and automated/zero-touch actions driven by customer risk thresholds

**Architecture & deployment.** Agent-based. A lightweight Tanium Client on each endpoint forms a dynamic 'linear chain' peer-to-peer ring per network segment, so queries and actions propagate endpoint-to-endpoint rather than each agent calling home — this is what delivers 15-second-scale answers across very large estates with minimal bandwidth and few collectors. Delivered as Tanium Cloud (vendor-hosted SaaS, now the default) or as a customer-managed on-prem/private-cloud Core Platform server. Modules are activated on the same agent/console (no per-capability agent). Zones/edge servers relay to endpoints that cannot reach the core directly.

**Editions & licensing.** Licensed per endpoint (seat) with modules packaged into solution bundles (e.g. Client Management = Discover, Patch, Deploy, Asset, Performance, Enforce, Provision; plus security bundles for Comply, Threat Response, Reveal, Impact, etc.). Bundles and included modules vary heavily by contract; AEM is the overarching subscription framing. New customers typically require a mandatory onboarding/deployment service. Pricing is quote-based via sales/channel.

**Key integrations.** ServiceNow (deep bi-directional ITSM/CMDB; 2024 integration enables end-to-end and zero-touch patch workflows and the Tanium AI Agent for ServiceNow); Microsoft — Intune connector (added 2025), Sentinel, Defender, Entra; SIEM/SOAR — Splunk, Microsoft Sentinel, Palo Alto Cortex XSOAR; Cloud — AWS, Azure, GCP asset/data flows; Identity — Active Directory / Entra ID; Flexera, Qualys and other vuln/asset tools via connect/feed.

**Differentiators**
- Real-time data at scale — seconds-fresh answers and actions across 100k+ endpoints via the linear-chain architecture, versus the stale snapshots of poll-and-aggregate tools
- Single agent, single platform converging ITOps + SecOps (discovery, inventory, patch, config, compliance, EDR, DEX) — removes tool and data silos
- Acts as both the scanner and the remediator — it can patch/deploy/enforce on the same endpoints it assesses, closing the find-to-fix loop natively
- AEM: AI recommendations with peer-success rates and risk-threshold-gated automation for zero-touch patching and self-healing

**Limitations & considerations**
- Heavy, consultative deployment — the linear-chain model, network zoning and tuning demand expertise and services; not a quick turn-up
- Cost and packaging complexity — premium pricing and module bundling make it hard to know exactly what you are entitled to
- Not a dedicated best-of-breed vuln scanner — Comply covers CVE/config assessment but lacks the depth, breadth of signatures and app-level/DAST coverage of Tenable/Qualys/Rapid7 for some use cases
- EDR (Threat Response) is capable but generally rated behind CrowdStrike/Defender as a standalone best-of-breed EDR
- Agent-only — unmanaged/unagentable devices (many IoT/OT, appliances) need Discover plus other tooling; OT/PLC coverage is newer (2025)

## Vulnerability-mitigation role

Tanium is the fast-acting compensating/remediation control in the mitigation window: once a critical CVE is known, Comply identifies every affected (and crucially, every unknown/unmanaged) asset in near real time, and Patch/Deploy/Enforce apply the fix or a compensating configuration (disable a service, close a port via Enforce, remove/block a vulnerable app, deploy a vendor workaround script via Automate) across the whole estate within the same session — often hours, not weeks. Before a patch exists, Enforce and Automate deliver virtual-patch-style mitigations (config hardening, feature/registry changes, service disablement) and Threat Response detects exploitation attempts. The real-time loop means you can also validate that the mitigation actually landed on every endpoint.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Remediate/Patch · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: IDENTIFY (asset/vuln inventory), PROTECT (patch, config enforcement), DETECT (Threat Response), RESPOND (remediation/containment); CIS Controls v8: 1 (Inventory of Enterprise Assets), 2 (Software Assets), 4 (Secure Configuration), 7 (Continuous Vulnerability Management), 10 (Malware Defenses), 12 (Network Infrastructure); MITRE ATT&CK mitigations: M1051 Update Software, M1053 Data Backup (n/a), M1042 Disable or Remove Feature/Program, M1035 Limit Access to Resource Over Network, M1026 Privileged Account Management, M1038 Execution Prevention

**In a critical-CVE scenario.** Hour 0-6: Comply runs an on-demand query to find every asset with the vulnerable software/version (including shadow/unmanaged devices surfaced by Discover), giving an exact, real-time blast radius for both the internet-facing app and cloud workloads. Hour 6-24: Enforce/Automate push an immediate compensating control (disable the vulnerable feature, block the port, remove the component, apply the vendor workaround), while Threat Response deploys IOCs/hunt queries to catch active exploitation. Hour 24-72: Patch/Deploy roll out the vendor patch in risk-ordered rings (internet-facing first) with live success telemetry, feeding ServiceNow change records; Comply re-scans to validate remediation reached 100% and flags stragglers for auto-remediation.

## Validation & telemetry

**Log sources**
- Architecture: endpoints run the Tanium Client + module 'client extensions' (CX tools). Real-time answers come from linear-chain 'questions'; results that need history are kept in the Tanium Data Service (TDS) as registered/saved questions. Comply, Patch and Enforce each push their own sensors/questions.
- Comply: compliance findings (OpenSCAP / CIS-CAT / embedded engine against a SCAP or CIS benchmark) and vulnerability findings (CVE). Surfaced as Comply sensors and as the 'Tanium Comply (Findings)' Connect source.
- Patch: applicable / installed / needed patch lists, deployment (success/failure) status, and reboot status per endpoint.
- Enforce: per-policy enforcement status and policy 'Health' pages; 'action lock' condition shown in enforcement status since Enforce 1.6.
- Egress/collection: Tanium Connect is the forwarder. A connection is a scheduled job: SOURCE (Saved Question, Comply (Findings), Client Status, Question Log, Audit, Event) -> DESTINATION (syslog TCP/UDP, Socket Receiver, HTTP, Amazon S3, SIEM: Splunk via the Tanium app/add-on + HEC, Microsoft Sentinel, ArcSight, etc.). Audit Log -> SIEM is the STIG-expected path.
- SIEM add-ons: 'Tanium' app + 'Tanium Add-On (TA)' for Splunk; Chronicle/Sentinel default parsers exist for Tanium Comply.

**Telemetry format / transport.** JSON or CSV rows carried over syslog (RFC 5424-style header with bracketed structured data / key=value), Socket Receiver, HTTP, or S3; to Splunk via HEC. Column customization in Connect needs a current Connect version. NOTE: I could not confirm native CEF/LEEF output from Tanium's own docs — practitioners emit JSON/syslog and convert to CEF/LEEF in a stream processor (e.g. Cribl). Verify at docs.tanium.com/connect for your version.

**Control-presence check (present & configured?).** Agent present/healthy: Tanium Client service ('Tanium Client' / TaniumClient) running and recently registered — check the 'Client Status' sensor / last-registration time (an endpoint that answers questions is online). Module capability present: the Comply/Patch/Enforce CX tools must be deployed to the endpoint (check tool version via sensors — Comply 2.22 explicitly warns vuln findings stop reporting until CX tools are upgraded). Control configured: Comply = a benchmark/SCAP assessment assigned to the computer group on a schedule and returning findings; Patch = patch lists + deployment schedules/maintenance windows assigned; Enforce = policy assigned to the group with enforcement status populated. Query route: ask a Saved Question in-console, or via the Tanium REST API (/api/v2 questions, saved_questions, results), the Tanium GraphQL API (Core 7.5+), or the Enforce API (documented since Enforce 1.5). I could not verify exact Patch/Enforce REST field names for current versions — confirm the sensor and endpoint names in your own console.

**Validation signals (actually working?)**
- Comply (effective config): a finding for a specific Test ID / Rule ID (CCE) flips state=fail -> pass (compliant) with Expected vs Actual value columns matching and First Found vs Last Scan timestamps advancing. Those investigation columns (Test ID, expected, actual) were added to the Comply (Findings) Connect source in Comply 2.17 — they are what distinguishes 'benchmark assigned' from 'setting actually applied on the box'.
- Patch (reachability removed): deployment status = Installed/success for the KB that fixes the CVE, reboot-pending satisfied, AND the KB drops out of the endpoint's 'needed patches' list. 'Deployed in a schedule' is NOT the effective signal; Installed + rebooted + no-longer-needed is.
- Enforce (enforced not pending): enforcement status = Enforced (not Pending/Failed) for the policy on that endpoint; the per-policy Health page / 'action lock' condition confirms the policy is actually applied, not merely targeted.

**Key events / fields / tables / APIs**
- Comply sensors / Connect columns (confirm exact names in console): 'Comply - Compliance Findings', 'Comply - Vulnerability Findings'; columns Test ID, Rule ID, State (pass/fail), Expected Value, Actual Value, First Found, Last Scan.
- Patch sensors (confirm names): 'Patch - Applicable Patches', 'Patch - Installed Patches', 'Patch - Needed Patches', reboot/pending-reboot status.
- Enforce: enforcement status field + action-lock condition; per-policy Health.
- Collection sources in Connect: Saved Question, Tanium Comply (Findings), Client Status, Question Log, Audit, Event.
- APIs: Tanium REST /api/v2 (questions/saved_questions/results), Tanium GraphQL API (Core 7.5+), Enforce API (since 1.5), Comply API. Splunk CIM target models: Change (patch state), Vulnerabilities, Compliance. Exact field/endpoint names drift by version — verify.

**Example queries**

*Presence + effectiveness of a benchmark control: which machines still FAIL a given CIS rule (non-compliant = control not applied).* (tanium)

```
Get Comply - Compliance Findings containing "fail" from all machines with Computer Group equals "Windows Servers"   // then drill the specific Test ID; sensor name may differ in your console
```

*Over Connect-forwarded Comply findings in Splunk: confirm a specific CIS rule moved from fail to pass fleet-wide (effective config).* (spl)

```spl
index=tanium sourcetype="tanium:comply:findings" rule_id="CCE-XXXXX" | stats latest(state) as state latest(actual_value) as actual by computer_name | where state="pass"
```

*Patch mitigation validation: endpoints that still NEED the KB fixing the CVE (non-empty = still vulnerable / patch not effective).* (tanium)

```
Get Patch - Needed Patches matching "KB5040000" from all machines   // empty result for a host = patch installed and no longer needed; confirm sensor name
```

**How it mitigates (mechanism).** Comply enforces/attests a secure configuration state (the OS setting that neutralizes the weakness) and Patch removes the vulnerable code by installing the vendor fix (reachability removal); Enforce pushes and continuously re-applies the policy. The observable proof is the finding flipping to compliant, the KB leaving the 'needed' list after a reboot, and enforcement status = Enforced.

**Logging gotchas**
- 'Findings returned' depends on CX/module tools being current — Comply 2.20.x and earlier can silently stop reporting vuln findings until tools are upgraded; a quiet feed can look like 'compliant' when it is actually 'not assessed'.
- Connect exports have known null First Found/Last Found dates and (in some releases) Remote Authenticated Scan findings exporting 0 rows — a blind spot that mimics 'no findings'.
- No verified native CEF — if your SIEM needs CEF/LEEF you must transform JSON/syslog downstream; mapping errors here corrupt the rule id/CVE fields analysts key on.
- Patch 'deployed' != 'installed+rebooted'; a pending-reboot host is still exploitable. Always pair deployment status with the needed-patch and reboot sensors.
- Real-time questions reflect only currently-online endpoints; use TDS/saved questions for an offline host's last-known state or you will under-count exposure.

## Documentation & repositories

_Official documentation & manuals_
- [Tanium Documentation Portal (current product docs)](https://docs.tanium.com)
- [Tanium Patch module guide](https://docs.tanium.com/patch/patch/index.html)
- [Tanium Knowledge Base (legacy; being decommissioned ~2026, content moving to docs.tanium.com)](https://kb.tanium.com)

_API & developer docs_
- [Tanium Developer Hub](https://developer.tanium.com)
- [Tanium API Reference (GraphQL API Gateway + Platform REST API)](https://developer.tanium.com/site/global/docs/api_reference)

_GitHub (official)_
- [Tanium GitHub organization —  (NOTE: org existence not confirmable via search this run; verify the org is Tanium-verified before trusting)](https://github.com/Tanium)

_Community / integration / detection repos_
- [PyTan — community Python wrapper for the Tanium SOAP/REST API](https://github.com/tanium/pytan)
- [pytan3 (newer Python client, docs on Read the Docs)](https://pytan3.readthedocs.io)

_Learning & reference_
- [Tanium blog and Tech Talks series](https://www.tanium.com/blog)
- [Tanium company / product overview](https://www.tanium.com/about)

> Note: Docs consolidated onto docs.tanium.com; the old kb.tanium.com Knowledge Base is slated for retirement around 2026 and redirects to the Resource Center. Tanium now positions the GraphQL API Gateway as the preferred integration path over the older Platform REST API; module-specific REST docs are reached via help links inside the Tanium Console (auth required). Console and most API docs require a customer login. GitHub org and the PyTan repo paths rely on established knowledge — web-search budget for this run was exhausted before they could be re-verified live; confirm before publishing.

## Current state (2025-26)

VERIFIED 2025-2026: Tanium's current brand framing is Autonomous Endpoint Management (AEM) / Autonomous IT, evolving the prior Converged Endpoint Management (XEM) category. At Converge 2025 Tanium launched Tanium Ask (agentic AI for troubleshooting/remediation), added zero-touch patching and self-healing via the Tanium AI Agent for ServiceNow, added a Microsoft Intune connector, expanded Apple mobile device coverage, and added PLC/OT ICS management. Tanium Cloud (SaaS) is the default delivery. Company remains privately held (Orion Hindawi, CEO). Exact per-contract module bundles still vary — verify specific entitlements against the customer's order form.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
