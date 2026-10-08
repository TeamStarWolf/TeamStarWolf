# Zafran Security

*Zafran Security (Israeli startup; backed by Sequoia, Cyberstarts, Menlo Ventures, Cisco Investments, American Express Ventures) · Threat/continuous exposure management (CTEM) with control-aware risk mitigation*

Zafran is a Threat Exposure Management platform built around a core thesis that most risk assessments ignore the compensating controls an organization already owns. It correlates vulnerabilities and exposures with existing security controls (EDR, WAF, firewall, IPS, email security, etc.) to determine what is actually exploitable and reachable, then mobilizes those existing controls to mitigate risk in the window before a patch lands. It is positioned as agentless and tool-agnostic, sitting on top of the stack a customer already has.

## Capabilities & architecture

**Core capabilities**
- AI-native Exposure Graph - maps relationships among assets, weaknesses, controls and attacker movement; surfaces choke points where attack paths converge
- Exploitability analysis weighing runtime presence, internet reachability, exploitation-in-the-wild, asset criticality, and existing control mitigations
- Mitigate module - uses already-deployed controls to reduce exploitability; maps exposures to compensating controls and can push/adjust mitigation policies to those controls
- Aggregation of vuln/finding data from existing scanners (Tenable, Qualys, Rapid7, CrowdStrike, Wiz, etc.)
- Threat intelligence enrichment (reported integration with Google Threat Intelligence - verify)
- Agentic Exposure Management (2025) - autonomous agents to identify vulnerabilities and take mitigation steps, reducing remediation from weeks to hours
- Exposure-window shrinking / prioritization before patching begins

**Architecture & deployment.** SaaS, agentless. Connects via API/read integrations to existing scanners, cloud providers, EDR/XDR, network and email security controls. It ingests findings and control configurations rather than deploying its own sensors, then builds the Exposure Graph in the cloud. For mitigation it can push policy changes to the customer's existing controls. No appliance, no inline proxy of its own.

**Editions & licensing.** Enterprise SaaS subscription, not publicly itemized; sold to large enterprises (multiple Fortune 500 customers). Licensing is enterprise/consumption-style around assets/environment scope - verify exact metering with vendor.

**Key integrations.** Vulnerability scanners: Tenable, Qualys, Rapid7; CNAPP/cloud: Wiz and cloud-native services; EDR/XDR: CrowdStrike and others; Network/perimeter controls: WAF, firewall, IPS; Email security controls; Threat intel: reportedly Google Threat Intelligence (verify); SIEM/SOAR and ticketing for remediation workflow.

**Differentiators**
- Control-aware risk: explicitly factors in compensating controls the org already owns, so a 'critical' CVE already blocked by EDR/WAF is deprioritized
- Mitigation-first rather than patch-first - actively mobilizes existing controls to close exposure windows
- Exposure Graph choke-point analysis to break many attack paths with one mitigation
- Agentless, fast time-to-value; no new sensors
- Gartner reportedly cited it as covering the full exposure-management lifecycle (vendor-sourced claim)

**Limitations & considerations**
- Young company (emerged from stealth 2024) - smaller install base and less independent validation than incumbents
- Much positioning is vendor-published; independent performance benchmarks are scarce
- Depends entirely on the quality/coverage of the customer's existing tools and controls it reads - blind spots propagate
- Pushing mitigation policies to third-party controls requires trust and change-management maturity; risk of misconfiguration
- Not a scanner or patch engine itself - it is an analytics/orchestration overlay

## Vulnerability-mitigation role

This is the case-study exemplar for mitigation-as-compensating-control. Zafran's entire model is to mitigate exposure in the window before/if a patch lands by identifying which existing controls already neutralize a vulnerability and by pushing new mitigating policies (block rules, EDR policy, segmentation, WAF virtual patch) to those controls. It reframes VM from 'patch everything' to 'what is truly exploitable given my controls, and what mitigation closes it fastest.'

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: Identify, Protect (compensating controls), Detect, Respond (mitigation); CIS Controls v8: 7 (Continuous Vulnerability Management), 4 (Secure Configuration), 13 (Network Monitoring/Defense), 12 (Network Infrastructure); MITRE ATT&CK mitigations: M1031 Network Intrusion Prevention, M1037 Filter Network Traffic, M1030 Network Segmentation, M1050 Exploit Protection, M1051 Update Software (one option among mitigations)

**In a critical-CVE scenario.** First 24-72h on a critical CVE in an internet-facing app + cloud workload: (1) Exposure Graph instantly identifies affected assets from already-ingested scanner/cloud data; (2) determines true exploitability via internet reachability, runtime presence and in-the-wild exploitation; (3) checks which existing controls (WAF, EDR, IPS, cloud SG) already mitigate it and flags residual exposure; (4) for still-exposed assets, recommends or (agentically) pushes a mitigating policy to existing controls - a virtual patch/block rule - to close the window before the vendor patch is deployed; (5) tracks the shrinking exposure and validates mitigation.

## Validation & telemetry

**Log sources**
- Agentless, API-based platform: inbound connectors pull from vulnerability scanners (Tenable, Qualys, etc.), EDR/XDR (CrowdStrike Falcon, Trend Micro XDR, Microsoft Defender), WAF/network controls, and identity providers (Okta, Entra ID).
- Outbound/consumption: Zafran REST API (requires a Zafran API key + active SaaS subscription), and the ServiceNow store app that matches Zafran Assets to the CMDB and imports Zafran findings as Vulnerable Items; plus ticketing/SOAR routing.
- Primary analyst surface for control evidence = the Zafran console + Zafran API; secondary = ServiceNow VR fields it writes.

**Telemetry format / transport.** JSON over REST API (API-key auth); ServiceNow records via the certified Zafran VR app. No publicly documented syslog/CEF/OCSF schema found - treat output as API/JSON pulled into ITSM/SOAR.

**Control-presence check (present & configured?).** Zafran's entire purpose is answering 'is a compensating control present and covering this asset?'. Per asset/finding it exposes: Mitigative Factors (which deployed control mitigates the finding), security-control COVERAGE-GAP detection (assets missing an EDR agent or running an outdated/vulnerable agent), Internet-Facing Evidence (reachability), and identity misconfigurations (e.g. a root user without MFA, read from the connected IdP). Query the Zafran API (or the Zafran fields in ServiceNow) to see whether a given asset/CVE has a mapped mitigative control vs a coverage gap.

**Validation signals (actually working?)**
- Recalculated 'Applicable Risk Score' that drops when a connected control is in BLOCK/PREVENT mode for that CVE's technique - this is Zafran's explicit 'configured vs actually enforcing' signal (a detect-only control is 'present' but does NOT reduce applicable risk).
- 'Mitigative Factors' evidence naming the specific enforcing control (e.g. Trend Micro XDR virtual-patch / EDR exploit-prevention) covering the CVE - one control action can be shown mitigating many findings/assets at once (Zafran markets ~1,251 findings mitigated by a single XDR action).
- Coverage-gap findings closing once an asset gains the missing agent/control = control now present.
- Zafran Remediation Items (ZRIs) consolidating many vulnerabilities into one remediation unit, written to ServiceNow Vulnerable Items.

**Key events / fields / tables / APIs**
- ServiceNow-surfaced objects (documented): Zafran Assets (CMDB match), Zafran findings carrying 'Mitigative Factors', 'Internet-Facing Evidence', and a recalculated 'Applicable Risk Score'; Zafran Remediation Items (ZRIs) -> ServiceNow Vulnerable Items (VIT).
- Auth: Zafran API key.
- NOTE: Zafran does not publish its REST endpoint paths or exact JSON field names publicly (sources are vendor one-pagers + the ServiceNow store listing) - could not verify field-level schema; obtain from your tenant's API docs.

**Example queries**

*Pull findings that have a mitigative control so you can report mitigated-by-control vs needs-patch* (API/REST (shape only - verify paths in tenant))

```
GET https://<tenant>.zafran.io/api/.../findings?has_mitigative_factor=true&applicable_risk=lt:medium   (Authorization: Bearer <ZAFRAN_API_KEY>) -- NOTE: endpoint/param names NOT publicly documented; confirm in your tenant API reference
```

*List Vulnerable Items whose applicable risk was reduced by a block-mode control* (ServiceNow (query the imported Zafran VR data))

```
sn_vul_vulnerable_item: zafran_mitigative_factors ISNOTEMPTY ^ zafran_applicable_risk_score < zafran_base_risk_score   (field names depend on the Zafran app's import mapping - validate in your instance dictionary)
```

**How it mitigates (mechanism).** Zafran blocks nothing itself; it correlates your already-deployed controls to each exposure to prove reachability removal or compensating-control coverage. When a connected EDR/WAF is actively enforcing (block mode) against the CVE's exploitation technique, Zafran flags the finding as mitigated and lowers its applicable risk, so the observable is the mitigative-factor evidence + the risk delta, not a patch on the host.

**Logging gotchas**
- A control shown as 'present' in detect-only mode does NOT reduce applicable risk - the block/prevent mode check is exactly the 'configured != enforcing' line, so always verify the control's enforcement mode, not just its deployment.
- Accuracy is entirely a function of integration depth; a missing or stale upstream connector creates a blind spot that can look like 'no mitigation available' or a false coverage gap.
- No open API schema and no independent validation of the risk-scoring math exist publicly (vendor marketing + ServiceNow listing only) - do not hardcode field names; pull them from your tenant.
- Zafran reflects the state of the controls it ingests, so its 'mitigated' verdict is only as fresh as the last sync from the EDR/WAF/scanner it reads.

## Documentation & repositories

_Official documentation & manuals_
- [Zafran Threat Exposure Management Platform (product overview)](https://zafran.io/platform)
- [Zafran homepage](https://zafran.io)
- [Zafran resource library (whitepapers, briefs)](https://zafran.io/resources)

_API & developer docs_
- [Zafran Security API profile (third-party index, API Evangelist) —  (no public first-party API reference located; API access is behind customer authentication)](https://providers.apievangelist.com/providers/zafran-security/)

_GitHub (official)_
- No official Zafran Security GitHub organization or public repositories were found.

_Community / integration / detection repos_
- No notable community repositories specific to Zafran were found (product is closed/SaaS with marketplace-based integrations rather than open-source tooling).

_Learning & reference_
- [Zafran blog & resources](https://zafran.io/resources)
- [AWS Marketplace listing](https://aws.amazon.com/marketplace/pp/prodview-3fcfd4kifsf7k)
- CrowdStrike Marketplace / Trend Micro partner platform listings (integration references)

> Note: Zafran is a newer (venture-backed) AI-native Continuous Threat Exposure Management (CTEM) / mitigation platform. There is NO public developer documentation site, no public API reference, and no official GitHub presence that could be verified — technical docs, API, and integration setup require a customer account and vendor engagement. Integrations (Cyera, CrowdStrike, Trend Micro, Jira, ServiceNow VR, SOAR) are configured in-product rather than via open-source repos. Treat vendor exploitability/mitigation claims (e.g. '90% of critical vulns not exploitable') as marketing until validated.

## Current state (2025-26)

Series C of $60M led by Menlo Ventures announced Dec 2 2025, bringing total funding to $130M (existing investors Sequoia and Cyberstarts participated; prior ~$70M Series B Sep 2024). Cisco Investments and American Express Ventures made strategic investments. 2025 'State of Threat Exposure Management' report published. Platform now marketed as 'Agentic Exposure Management' built on the AI-native Exposure Graph. Reported to have doubled valuation and tripled ARR since prior round. Exposure Graph + Google Threat Intelligence tie-in is vendor/aggregator-sourced - verify.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
