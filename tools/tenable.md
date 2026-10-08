# Tenable

*Tenable Holdings, Inc. (NASDAQ: TENB) · Exposure management / vulnerability management (VM) + attack-surface and risk prioritization*

Tenable is the long-standing vulnerability-management vendor whose Nessus scanner is the de facto industry standard for vulnerability assessment. Tenable One is its unified Exposure Management platform that ingests findings across VM, cloud, OT, identity, web apps and attack surface, then prioritizes them against real-world threat context so teams fix what actually matters. VPR (Vulnerability Priority Rating) is its dynamic, ML-driven 0.1-10.0 risk score that supplements static CVSS by weighting exploitability and threat activity.

## Capabilities & architecture

**Core capabilities**
- Nessus scanner (authenticated/unauthenticated, credentialed, agent and network scanning) - largest VM dataset in the industry
- Tenable Vulnerability Management (formerly Tenable.io) - cloud-delivered VM
- Tenable Security Center (formerly Tenable.sc) - on-prem/self-managed VM console
- VPR - dynamic ML risk score (threat actor activity, exploit code maturity, vuln age + CVSS impact; enhanced VPR weights threat and impact equally)
- Tenable One: Lumin Exposure View (unified Cyber Exposure Score/CES, Asset Exposure Score/AES), Attack Path Analysis, Asset Inventory
- Tenable Cloud Security (CNAPP/CSPM/CIEM; DSPM via Eureka), Tenable OT Security, Tenable Identity Exposure (AD/Entra), Tenable Web App Scanning (DAST), Tenable Attack Surface Management (external/EASM)
- Tenable AI Exposure (govern and secure AI usage and AI the org builds - from Apex Security)
- Vulcan Cyber-derived capabilities: third-party findings aggregation (100+ tools), risk prioritization, remediation/mitigation orchestration
- Tenable Patch Management, Container Security, PCI ASV, Network Monitor, Nessus Agent

**Architecture & deployment.** Hybrid. Nessus deploys as a scanner (software/appliance/VM); Nessus Agents run on endpoints for authenticated/offline scanning. Tenable Vulnerability Management, Tenable One, Cloud Security and ASM are SaaS. Security Center is self-managed on-prem. Cloud Security is largely agentless (API/cloud connectors) with optional agents. Scanners and agents collect data, which flows to the cloud (or Security Center) for analysis, VPR scoring, correlation and exposure scoring. Tenable One sits as the aggregation/analytics layer above the sensors and third-party data feeds.

**Editions & licensing.** Nessus sold as Nessus Professional (per-scanner annual subscription) and Nessus Expert. Tenable Vulnerability Management and Tenable One are subscription, priced primarily per-asset (assets under management). Tenable One is tiered/bundled across the exposure domains. Cloud Security and OT Security licensed separately (per resource / per asset). Add-on model for domain modules rolled into the Tenable One bundle.

**Key integrations.** SIEM/SOAR: Splunk, Microsoft Sentinel, QRadar, Cortex XSOAR; Ticketing/ITSM: ServiceNow VR, Jira; CMDB: ServiceNow; Cloud: AWS, Azure, GCP; Identity: Active Directory, Entra ID; Patch tools and 100+ third-party security tools ingested via Vulcan-derived connectors; API and pyTenable SDK.

**Differentiators**
- Nessus plugin/vuln coverage breadth is unmatched; largest VM dataset
- VPR adds dynamic exploitability-aware prioritization on top of CVSS, updated as threats change
- Tenable One unifies IT/cloud/OT/identity/web/EASM exposure in one Cyber Exposure Score with attack-path analysis
- Vulcan Cyber acquisition (2025) adds mature third-party findings aggregation and remediation orchestration
- Strong OT/ICS depth (Tenable OT Security, ex-Indegy) that pure-IT VM vendors lack

**Limitations & considerations**
- Severity semantics differ by product: Tenable One VM calculates severity from CVSS while Tenable Exposure Management uses VPR only - expect different values between consoles
- Vulns without a CVE (many Info findings) receive no VPR, falling back to CVSS severity
- Tenable One licensing/bundling can be complex and asset counts drive cost
- Breadth across many acquired modules (Vulcan, Apex, Eureka, Ermetic) means integration maturity varies by domain
- Still fundamentally an assess/prioritize platform - remediation/patch execution depends on integrated tools and the new Patch Management module

## Vulnerability-mitigation role

Tenable's primary VM role is Discover-Assess-Prioritize, telling teams which exposures are genuinely exploitable (VPR) and which lie on real attack paths (Attack Path Analysis). As a compensating/virtual-patching control it is weaker than an inline WAF/IPS, but the Vulcan-derived capabilities and Patch Management module let it recommend and orchestrate mitigations (config changes, compensating controls, remediation campaigns) and shrink the exposure window. Its strongest mitigation value is reducing the attack surface that needs patching by surfacing choke points on attack paths, so defenders can break the path even before a CVE is patched.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Remediate/Patch · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: Identify (asset/vuln discovery), Protect, Detect; CIS Controls v8: 1 (Inventory), 2 (Software Inventory), 7 (Continuous Vulnerability Management), 4 (Secure Configuration), 12 (Network); MITRE ATT&CK mitigations: M1051 Update Software, M1016 Vulnerability Scanning, M1030 Network Segmentation (attack-path remediation)

**In a critical-CVE scenario.** First 24-72h on a critical CVE in an internet-facing app + cloud workload: (1) Query Tenable ASM/Inventory and Cloud Security for all affected internet-facing and cloud assets; (2) run targeted Nessus/agent and Web App Scanning + agentless cloud checks to confirm presence and exploitability; (3) use VPR and Attack Path Analysis to rank which exposed assets sit on paths to crown-jewel assets; (4) push prioritized remediation/mitigation tickets (ServiceNow/Jira) and recommend compensating controls or segmentation via Vulcan-derived orchestration; (5) re-scan to validate and track CES reduction.

## Validation & telemetry

**Log sources**
- Native console: Tenable One / Tenable Vulnerability Management (ex-Tenable.io); sensors = Nessus, Nessus Agent, Nessus Network Monitor (NNM).
- REST Exports API (asynchronous): POST /vulns/export -> GET /vulns/export/{export_uuid}/status -> GET /vulns/export/{export_uuid}/chunks/{chunk_id}; POST /compliance/export for audit/config checks; GET /audit-log/v1/events for tenant activity; GET /plugins/plugin for plugin metadata.
- SIEM: Tenable Add-on for Splunk (modular input URI tenable_io://<input>) with sourcetypes tenable:io:vuln, tenable:io:assets, tenable:io:plugin, tenable:io:compliance, tenable:io:audit_logs, and WAS sourcetype tenable:io:vuln:was; CIM field mapping via the CyberCX TA (search-head only). Sumo Logic Tenable cloud-to-cloud source also pulls via API.
- Collection is scheduled API pull; retention/latency are governed by your SIEM and your export cadence, not by Tenable.

**Telemetry format / transport.** JSON over REST (gzip export chunks); Splunk modular-input JSON events. TVM cloud is API-PULL, not a native CEF/syslog stream (Tenable.sc can syslog/CEF separately; could not verify a CEF push from TVM cloud).

**Control-presence check (present & configured?).** Confirm the scanner can actually SEE the device's state (prerequisite for any 'fixed' claim): Nessus plugin 19506 'Nessus Scan Information' output must contain 'Credentialed checks : yes' (SSH form: 'yes as <user> via ssh'). Degraded/unauth scans show plugin 21745 (Authentication Failure - Local Checks Not Run) or 24786 (Windows admin privileges not used). To confirm a CONFIG/HARDENING control is present on a host, run a compliance audit (CIS/DISA .audit); each check returns result = Passed/Failed/Warning/Info/Skipped/Error/Unknown (Unix compliance = plugin 21157; Security Center renumbers compliance plugins into the 1,000,000+ range). A 'Passed' check means the control/setting is actually present and correctly configured on that device. Sensor/agent health: asset.last_scanned / agent last_seen + scan status via the scans API.

**Validation signals (actually working?)**
- Finding `state` lifecycle OPEN -> REOPENED -> FIXED. FIXED is set ONLY after a successful authenticated rescan where the plugin no longer fires = positive proof the patch/config remediation is live on the host. This is the real 'mitigation validated' signal.
- `last_fixed` timestamp populated on the vuln record.
- Compliance check flipping Failed -> Passed on rescan = the hardening control is now enforced.
- Patch context: plugin.patch_publication_date / definition.patch_published present AND plugin.vendor_unpatched=false, combined with the host no longer matching the plugin.
- CONFIGURED vs ENFORCED distinction: a finding that was 'recast' (severity changed) or 'accepted' is still OPEN underneath - only `state`=FIXED (or compliance Passed) is verified remediation, not a risk-acceptance.

**Key events / fields / tables / APIs**
- Vuln export record fields: state (OPEN/REOPENED/FIXED), output ('Plugin Output'), first_found, last_found, last_fixed, severity, plugin.id, plugin.cve, plugin.patch_publication_date (export uses definition.patch_published), plugin.vendor_unpatched, asset.uuid, asset.hostname.
- Endpoints: POST /vulns/export, GET /vulns/export/{uuid}/status, GET /vulns/export/{uuid}/chunks/{id}, POST /compliance/export, GET /audit-log/v1/events, GET /plugins/plugin.
- Diagnostic plugin IDs: 19506 (scan info / credentialed checks), 21745 (auth failure), 24786 (Windows admin), 21157 (Unix compliance).
- Splunk sourcetypes: tenable:io:vuln, tenable:io:compliance, tenable:io:plugin, tenable:io:audit_logs, tenable:io:vuln:was.

**Example queries**

*Pull fixed findings (validated remediation) since a date via the async Exports API* (API/curl)

```
curl -s -X POST https://cloud.tenable.com/vulns/export -H 'X-ApiKeys: accessKey=...;secretKey=...' -H 'Content-Type: application/json' -d '{"num_assets":50,"filters":{"state":["FIXED"],"last_fixed":1704067200}}'   # returns export_uuid; then GET /vulns/export/{uuid}/status until FINISHED, then GET .../chunks/{id}
```

*Confirm the control-presence prerequisite: which hosts were actually authenticated-scanned* (SPL)

```spl
sourcetype="tenable:io:vuln" plugin_id=19506 output="*Credentialed checks : yes*" | stats latest(_time) as last_auth_scan by "asset.hostname" | eval stale=if(now()-last_auth_scan>604800,"STALE","ok")
```

*Validate mitigation of a specific CVE family by watching state=FIXED per host* (SPL)

```spl
sourcetype="tenable:io:vuln" "plugin.cve"="CVE-2024-3400" | stats latest(state) as current_state latest(last_fixed) as fixed_ts by "asset.hostname" "plugin.id" | where current_state="FIXED"
```

**How it mitigates (mechanism).** Tenable itself blocks nothing; it is the verification ORACLE. A credentialed rescan re-runs the plugin's version/registry/file/config logic directly against the live target, so a finding flipping to state=FIXED (or a compliance check flipping to Passed) is read-from-the-device evidence that the patch was installed or the hardening setting is enforced - reachability/config state observed, not asserted.

**Logging gotchas**
- state=FIXED is trustworthy ONLY after an authenticated rescan - if plugin 19506 shows 'Credentialed checks : no', the scan degraded to unauth and FIXED/Passed can be a false negative. ALWAYS gate remediation reporting on 19506.
- Recast severity or accepted risk != fixed; the displayed severity can be edited while `state` is still OPEN. Trust `state`, not the badge.
- Field names differ by surface: patch date is patch_publication_date in /plugins/plugin but definition.patch_published in the export; CSV vs JSON keys differ. Compliance plugin IDs are renumbered (1,000,000+) when imported into Security Center, so do not filter on 21157 alone there.
- Per-plugin output is capped around 1 MB; long compliance actual_value strings get truncated.
- TVM cloud has no native real-time CEF/syslog feed - it is API-pull via the Splunk add-on / Sumo, so detection latency = your export cadence.
- Could not verify the exact compliance-export column names (e.g. check_result / check_name / actual_value) from public docs - inspect a sample compliance export before coding against them.

## Documentation & repositories

_Official documentation & manuals_
- [Tenable Documentation Hub (all products)](https://docs.tenable.com)
- [Tenable One Exposure Management Platform docs](https://docs.tenable.com/Tenableone.htm)
- [Tenable Vulnerability Management (formerly Tenable.io) docs](https://docs.tenable.com/Tenableio.htm)
- [Tenable Nessus documentation (Essentials/Professional/Expert/Manager)](https://docs.tenable.com/nessus.htm)
- [Tenable Security Center docs](https://docs.tenable.com/security-center.htm)

_API & developer docs_
- [Tenable Developer Portal (API reference, API Explorer)](https://developer.tenable.com)
- [pyTenable Python SDK documentation](https://pytenable.readthedocs.io)
- Tenable Security Center API Docs (linked from Developer Resources on docs.tenable.com)

_GitHub (official)_
- [Tenable GitHub organization (~89 repos)](https://github.com/tenable)
- [pyTenable — Python library for Tenable platform APIs](https://github.com/tenable/pyTenable)
- [tenable-connectors — officially supported connectors for the Tenable Integration Framework](https://github.com/tenable/tenable-connectors)
- [integration-jira-cloud — Jira Cloud integration](https://github.com/tenable/integration-jira-cloud)
- [container-security-action / was-action — official GitHub Actions for Tenable container & WAS scans](https://github.com/tenable/container-security-action)

_Community / integration / detection repos_
- [Tenable App & Add-on for Splunk (SIEM integration) —  (verify exact app ID on Splunkbase)](https://splunkbase.splunk.com/app/4060)
- [Security-Hub — Tenable.io to AWS Security Hub integration](https://github.com/tenable/Security-Hub)
- Navi — community CLI/automation tool for Tenable.io (github.com/tenable/navi — confirm slug before use)

_Learning & reference_
- [Tenable University / training](https://www.tenable.com/education)
- [Tenable Research blog](https://www.tenable.com/blog)
- [Tenable Community (forums/knowledge)](https://community.tenable.com)

> Note: Nessus guides are version-specific (URLs like docs.tenable.com/nessus/<ver>/...), so use the version selector on the Nessus docs page. Tenable One is the exposure-management umbrella that includes Tenable Vulnerability Management, Web App Scanning, Cloud Security, and Lumin. The legacy Nessus/SecurityCenter XMLRPC API reference is outdated — use the Developer Portal + API Explorer for current REST APIs. GitHub org has both Tenable-supported and community-supported (open-source) integrations. WebSearch budget was exhausted this turn; the org, pyTenable, connectors, and Jira repos were directly verified, Navi and the Splunk app ID were not fully re-verified live.

## Current state (2025-26)

Tenable acquired Vulcan Cyber (announced Jan 29 2025, closed Feb 7 2025, ~$148.5M) for third-party findings aggregation and remediation; acquired Apex Security (June 2025, ~$47.8M) for AI exposure, now Tenable AI Exposure; earlier acquired Eureka Security (June 2024, DSPM) and Ermetic (2023, CNAPP/CIEM). VPR has an 'enhanced' version weighting threat and impact equally. Product renames: Tenable.io -> Tenable Vulnerability Management, Tenable.sc -> Tenable Security Center. No product/acquisition named 'Aura' found - verify if seen elsewhere.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
