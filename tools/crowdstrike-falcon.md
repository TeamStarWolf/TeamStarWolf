# CrowdStrike Falcon

*CrowdStrike · Cloud-native single-agent endpoint/XDR platform with integrated, scanless Exposure Management (risk-based vulnerability management)*

CrowdStrike Falcon is a cloud-native platform delivered through a single lightweight agent that spans endpoint protection (NGAV), EDR/XDR, identity protection, cloud security and IT/exposure management. Falcon Exposure Management (FEM) is its unified exposure/vulnerability offering, built on the long-standing Falcon Spotlight scanless vulnerability-management engine plus Falcon Surface (external attack surface management), Falcon Discover (asset/account/app discovery) and, since 2025, AI-powered Network Vulnerability Assessment. It solves real-time, agent-based vulnerability and exposure visibility with no scan windows, correlated against CrowdStrike's threat intelligence and the same telemetry that powers its EDR. FEM positions vulnerability data inside a prioritized, exploitation-aware exposure view rather than a flat CVE list.

## Capabilities & architecture

**Core capabilities**
- Falcon Prevent — next-gen antivirus (NGAV) / EPP
- Falcon Insight — EDR/XDR with real-time detection, threat graph and response
- Falcon Spotlight — scanless, real-time vulnerability management with CVE-to-endpoint mapping and ExPRT.AI exploit-prediction prioritization
- Falcon Exposure Management (FEM) — unified exposure platform consolidating Spotlight (vuln), Surface (EASM) and Discover (asset/app/account discovery)
- Falcon Surface — external attack surface management (internet-facing exposure)
- Falcon Discover — IT hygiene: unmanaged asset, application and account discovery
- Network Vulnerability Assessment (GA 2025) — scanless, agentless assessment of network devices (routers, switches, firewalls) with no extra scanners/hardware
- Falcon Identity Protection — identity threat detection and response
- Falcon Cloud Security (CNAPP/CWPP/CSPM) and Falcon Data Protection (DLP)
- Falcon Fusion SOAR — workflow automation/orchestration
- Falcon LogScale (SIEM/next-gen logging) and Falcon Next-Gen SIEM
- Falcon for IT — IT automation/remediation on the same agent
- Charlotte AI — agentic/generative AI analyst for triage, prioritization and response
- Falcon Complete — fully managed MDR service

**Architecture & deployment.** 100% cloud-native SaaS with a single lightweight Falcon sensor (agent) per endpoint; all modules are activated on that one agent (no additional agent per capability). Telemetry streams to the CrowdStrike Security Cloud / Threat Graph for correlation and analytics. Vulnerability assessment is 'scanless' — derived continuously from sensor telemetry, so there are no scan jobs, scan windows or credentialed scan infrastructure for covered endpoints. Network Vulnerability Assessment extends coverage to network devices without additional scanners, agents or hardware. Covers Windows, macOS, Linux, cloud workloads/containers and, via agentless methods, cloud and network assets.

**Editions & licensing.** Historically sold as tiered bundles (Falcon Go / Pro / Enterprise / Elite / Complete), with Spotlight vulnerability management typically in the Enterprise tier and higher, plus separately-priced module add-ons. CrowdStrike now pushes Falcon Flex — a consumption/commit licensing model that lets customers draw down against a committed spend and adopt, expand or swap modules without new procurement cycles; Flex for Services extends this to its managed/expert services. Licensing is largely per-endpoint/per-asset with module entitlements; quote-based via sales/channel (Complete and Flex are not self-serve).

**Key integrations.** SIEM — Splunk, Microsoft Sentinel, plus CrowdStrike's own Falcon Next-Gen SIEM / LogScale; ITSM/ticketing — ServiceNow, Jira; Cloud — AWS, Azure, GCP (via Falcon Cloud Security, agentless); Identity — Microsoft Entra ID, Active Directory, Okta; SOAR — Falcon Fusion (native) and third-party; CrowdStrike Marketplace / Store — large third-party integration ecosystem; ingests third-party vulnerability scan data into Exposure Management.

**Differentiators**
- Single lightweight agent for EPP, EDR/XDR, identity, cloud and exposure — and scanless vulnerability assessment from that same telemetry means no scan windows, no separate vuln agent, always-current data
- Exploitation-aware prioritization (ExPRT.AI) that ranks CVEs by real-world exploit likelihood using CrowdStrike's industry-leading adversary/threat intelligence — not just CVSS
- Exposure Management unifies internal vuln, external attack surface and asset discovery into one adversary-centric risk view, with the ability to ingest third-party scan data
- Fast time-to-value and operational simplicity of a pure-SaaS, single-agent platform; Charlotte AI and Fusion SOAR add agentic automation; named a Leader in the 2025 IDC MarketScape for Exposure Management

**Limitations & considerations**
- Not a native patch-deployment engine — Falcon finds, prioritizes and (via Falcon for IT / Fusion / integrations) can orchestrate remediation, but patch rollout generally relies on Intune/SCCM/Tanium/ServiceNow or Falcon for IT scripting rather than a mature, dedicated patch module
- Scanless model depends on the Falcon sensor being present — unagentable devices, many OT/IoT and appliances need the newer agentless network assessment or third-party scan ingestion, which is narrower than Tenable/Qualys deep network/web coverage
- No deep DAST/web-application vulnerability scanning — FEM is infrastructure/host/network and attack-surface focused
- Cost and packaging complexity — premium pricing, many add-on modules, and Flex commit models require careful sizing
- Reputational/operational memory of the July 2024 global sensor-update outage keeps change-control and sensor-update rigor top of mind for adopters

## Vulnerability-mitigation role

Falcon's primary mitigation value in the pre-patch window is detection-and-response as a compensating control plus exploitation-aware prioritization: the same sensor that reports the vulnerability (Spotlight) will detect and block exploitation attempts (Prevent/Insight/behavioral IOAs), effectively covering the exposure until a patch lands. FEM/Spotlight pinpoints every affected host in real time and ranks by ExPRT.AI exploit likelihood so teams fix what adversaries will actually hit first; Fusion SOAR and Falcon for IT can push scripted compensating actions (disable a service, apply a config/registry workaround, isolate a host via network containment) and orchestrate the patch through integrated tools. Network containment and USB/device control provide immediate blast-radius reduction. It is a 'detect-and-contain while you prioritize and remediate' control rather than an inline virtual patch.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Monitor/Detect · Validate

**Framework mapping:** NIST CSF 2.0: IDENTIFY (exposure/asset/vuln), PROTECT (NGAV, device/USB control, config workarounds), DETECT (EDR/XDR, threat intel), RESPOND (containment, Fusion SOAR), GOVERN (risk prioritization); CIS Controls v8: 1 (Asset Inventory), 2 (Software Inventory), 7 (Continuous Vulnerability Management), 10 (Malware Defenses), 13 (Network Monitoring & Defense), 17 (Incident Response); MITRE ATT&CK mitigations: M1051 Update Software, M1040 Behavior Prevention on Endpoint, M1038 Execution Prevention, M1042 Disable or Remove Feature or Program, M1030 Network Segmentation / M1035 Limit Access, M1049 Antivirus/Antimalware

**In a critical-CVE scenario.** Hour 0-6: Spotlight/FEM instantly identifies every endpoint and cloud workload running the vulnerable version from existing sensor telemetry (no scan), and ExPRT.AI plus CrowdStrike threat intel flag whether the CVE is being actively exploited in the wild, ranking it to the top. For the internet-facing app, Falcon Surface confirms the external exposure. Hour 6-24: EDR/IOA detections and custom hunts are deployed to catch exploitation; affected or high-value hosts can be network-contained immediately; Fusion SOAR/Falcon for IT pushes a scripted compensating control (disable feature, apply workaround) as a stopgap. Hour 24-72: remediation is orchestrated via Falcon for IT or hand-off to Intune/SCCM/ServiceNow to deploy the vendor patch, prioritized internet-facing-first; Spotlight continuously re-confirms remediation in real time and Charlotte AI summarizes residual exposure and response actions.

## Validation & telemetry

**Log sources**
- Spotlight (Falcon Exposure Management) vulnerability data via the Spotlight Vulnerabilities API: combined endpoint /spotlight/combined/vulnerabilities/v1 (combinedQueryVulnerabilities, returns full entities), ID query /spotlight/queries/vulnerabilities/v1 (queryVulnerabilities), entities /spotlight/entities/vulnerabilities/v1. A filter is MANDATORY on these endpoints.
- EDR/sensor telemetry: bulk via Falcon Data Replicator (FDR, gzipped NDJSON to an S3 bucket, keyed on event_simpleName/aid/cid — must be enabled by CrowdStrike support); real-time via the Event Streams API; queried in Falcon Next-Gen SIEM / Falcon LogScale using CQL. Third-party SIEM via the CrowdStrike FDR technical add-on (Splunk/Humio).
- Host/sensor inventory: Hosts (Devices) API /devices/queries/devices-scroll/v1 + /devices/entities/devices/v2 (fields agent_version, last_seen, status, reduced_functionality_mode, device_policies).
- Detections/policy: alerts API alerts/aggregates/alerts/v2 (the older detects endpoints were deprecated ~Sep 2025); prevention-policy API.
- Microsoft Sentinel: CrowdStrikeVulnerabilities table (Aid, HostInfo dynamic, Status) via the CrowdStrike data connector.

**Telemetry format / transport.** REST JSON with FQL filters (string values single-quoted, multi-values in [ ], + = AND, comma = OR, dates UTC, no wildcards); FDR = gzip NDJSON in S3; Event Streams = JSON; LogScale/Next-Gen SIEM query language = CQL; Splunk via the FDR add-on. OCSF alignment for exposure (Vulnerability Finding) in newer integrations.

**Control-presence check (present & configured?).** Sensor present/healthy on device: Windows service CSFalconService + CSAgent driver running. Version on-box: Linux 'sudo /opt/CrowdStrike/falconctl -g --version'; macOS 'sysctl cs.version'; Windows via CSSensorSettings.exe --version (installer/version command has changed across releases — verify for your build). Cloud connectivity / protection state: 'sudo /opt/CrowdStrike/falconctl -g --rfm-state' — expect rfm-state=false (true = Reduced Functionality Mode: installed but NOT fully protecting). This is community-documented — verify. Via API (fleet-wide): Hosts API device entity -> status, last_seen (recent), agent_version, reduced_functionality_mode=false, and device_policies showing an assigned Prevention policy. Spotlight present: tenant licensed for Spotlight/FEM and the API key holds spotlight-vulnerabilities:read; the endpoint returns data. Prevention actually set to block: prevention-policy settings (e.g. credential-dumping, suspicious-process, exploit-mitigation toggles) = Enabled/Prevent, not Detect-only.

**Validation signals (actually working?)**
- Vulnerability remediated: Spotlight record status open -> closed with a populated closed_timestamp (and per-app sub_status closed). That proves the exposure was removed. Do NOT count status=expired as remediation — that is set when a host is deleted or inactive 45 days, then dropped 3 days later, and is visible only in API responses (not console/reports).
- Prevention actually BLOCKED vs merely detected: a Prevention policy in Prevent mode produces a detection/alert where an action was taken (process killed/blocked); the same activity under a Detect-only policy produces telemetry with no block. This Detect-vs-Prevent distinction is the configured-vs-effective line. (I could not verify the exact FDR event_simpleName for a prevention/EPP block from public docs — confirm the EppDetectionSummary-style event name and PatternDisposition bits in your own tenant schema.)
- Sensor effective, not just installed: Hosts API status normal + reduced_functionality_mode=false. RFM=true is the key trap — the sensor is present and reporting but its prevention/collection is degraded.

**Key events / fields / tables / APIs**
- Spotlight API fields: cve.id, cve.severity, cve.exprt_rating (ExPRT.AI), status (open|closed|expired), sub_status, closed_timestamp, apps.remediation.ids (filterable, supports negation), host_info.*, host_last_seen_timestamp (populated ONLY when a host is offline >=3 days, resets to null on reconnect), suppression_info.is_suppressed. Scope: spotlight-vulnerabilities:read.
- Hosts API: /devices/queries/devices-scroll/v1, /devices/entities/devices/v2 -> agent_version, last_seen, status, reduced_functionality_mode, device_policies.
- FDR / Next-Gen SIEM / LogScale: event_simpleName, aid, cid, ComputerName; CQL for queries. PSFalcon cmdlet Get-FalconVulnerability; FalconPy spotlight_vulnerabilities (combined_query_vulnerabilities).
- Sentinel: CrowdStrikeVulnerabilities(Aid, HostInfo [dynamic], Status). On-box: CSFalconService, falconctl -g --version / --rfm-state.

**Example queries**

*Presence of exposure: open critical CVEs (first) and remediation validation: the same CVE now closed (second) for a host group.* (fql)

```
GET /spotlight/combined/vulnerabilities/v1?filter=status:'open'+cve.severity:'CRITICAL'&limit=400
// validate remediation:
GET /spotlight/combined/vulnerabilities/v1?filter=cve.id:'CVE-2024-38063'+status:'closed'&facet=host_info&facet=remediation
```

*PSFalcon: pull open, non-suppressed vulns and their remediation IDs to measure what is actually exposed.* (powershell)

```powershell
Get-FalconVulnerability -Filter "status:'open'+cve.exprt_rating:['HIGH','CRITICAL']" -Facet cve,host_info,remediation -Detailed -All
```

*Next-Gen SIEM / LogScale over FDR: confirm a sensor is alive and reporting (heartbeat present) — presence/health.* (cql)

```
#event_simpleName=/.*/ | aid="<agentID>" | groupBy([event_simpleName], function=count()) | sort(limit=50)   // confirm event_simpleName values for your tenant; a silent aid may be RFM or a dropped-telemetry pipeline
```

*Sentinel: join CrowdStrike vuln status to open exposures by host/agent (validate closed vs still-open).* (kql)

```kql
CrowdStrikeVulnerabilities
| summarize arg_max(TimeGenerated, Status) by Aid, CveId=tostring(HostInfo.cve_id)
| summarize Open=countif(Status=='open'), Closed=countif(Status=='closed') by Aid
```

**How it mitigates (mechanism).** Spotlight/FEM measures reachable exposure and confirms removal (status open->closed = the vulnerable software/config no longer present); the Falcon sensor's Prevention policy performs inline process/exploit blocking at the kernel level. The observable proof is the Spotlight status flip with closed_timestamp plus an EDR alert showing an action was taken under a Prevent-mode policy.

**Logging gotchas**
- Reduced Functionality Mode (RFM): the sensor can show as installed/present while prevention and collection are degraded — always check reduced_functionality_mode / rfm-state, not just 'sensor installed'.
- status=expired is API-only (host deleted or inactive 45d, removed after a further 3d) and never appears in the console/reports — comparing API counts to UI counts without excluding expired produces phantom 'remediations'. Also exclude suppression_info.is_suppressed when measuring real risk.
- Detect-only vs Prevent: a policy in Detect mode logs the behaviour but does NOT block it; a detection record alone does not prove mitigation — confirm the policy mode and that an action was taken.
- FDR must be enabled by CrowdStrike support, and SIEM ingestion pipelines commonly DROP sensor-health/telemetry-only events as low-signal — a 'silent' host may be a filtered pipeline, not a dead sensor.
- Spotlight endpoints REQUIRE a filter and reject wildcards; host_last_seen_timestamp is only populated after >=3 days offline, so it is not a general 'last seen' field (use the Hosts API last_seen for that).
- I could NOT verify from public docs the exact /spotlight/combined/vulnerabilities/v1 vs /queries path pairing for every Falcon region/version, the Windows sensor version command for current builds, or the FDR prevention event_simpleName — verify these against the Falcon API reference and your tenant before operationalizing.

## Documentation & repositories

_Official documentation & manuals_
- [CrowdStrike Falcon product documentation (in-console, auth required)](https://falcon.crowdstrike.com/documentation)
- [CrowdStrike resources / tech center](https://www.crowdstrike.com/resources/)

_API & developer docs_
- [CrowdStrike Developer Center (public API/SDK reference)](https://developer.crowdstrike.com)
- [FalconPy official project documentation](https://www.falconpy.io)

_GitHub (official)_
- [CrowdStrike GitHub organization](https://github.com/CrowdStrike)
- [FalconPy — official Python SDK](https://github.com/CrowdStrike/falconpy)
- [PSFalcon — official PowerShell SDK](https://github.com/CrowdStrike/psfalcon)
- [gofalcon — official Go SDK](https://github.com/CrowdStrike/gofalcon)
- [falcon-scripts — official sensor install/uninstall scripts](https://github.com/CrowdStrike/falcon-scripts)

_Community / integration / detection repos_
- [rusty-falcon — Rust SDK](https://github.com/CrowdStrike/rusty-falcon)
- [falcon-helm — Kubernetes Helm charts for Falcon sensors](https://github.com/CrowdStrike/falcon-helm)
- [falcon-operator — Kubernetes operator](https://github.com/CrowdStrike/falcon-operator)
- [CrowdStrike community samples](https://github.com/CrowdStrike/community)
- [helpful-links — curated index of CrowdStrike open-source projects & resources](https://github.com/CrowdStrike/helpful-links)
- [Sigma detection rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team (ATT&CK test content)](https://github.com/redcanaryco/atomic-red-team)

_Learning & reference_
- [CrowdStrike University (training/certification)](https://www.crowdstrike.com/services/crowdstrike-university/)
- [FalconPy documentation site & wiki](https://www.falconpy.io)
- [CrowdStrike blog](https://www.crowdstrike.com/blog/)

> Note: CrowdStrike has a strong, verified official GitHub presence at github.com/CrowdStrike (falconpy, psfalcon, gofalcon, rusty-falcon, falcon-scripts, falcon-operator, falcon-helm, community, helpful-links all confirmed). The SDKs are open-source and community-supported, not formal CrowdStrike products. In-console docs at falcon.crowdstrike.com require authentication; developer.crowdstrike.com is the public API reference. Falcon API uses OAuth2 with regional base URLs. A Terraform provider (CrowdStrike/terraform-provider-crowdstrike) also exists for IaC but was not re-verified live this run. crowdstrike-falconpy is the PyPI package name. developer.crowdstrike.com, falconpy.io, falcon.crowdstrike.com, CrowdStrike University and blog URLs rely on established knowledge — search budget was exhausted before live re-verification.

## Current state (2025-26)

VERIFIED 2025-2026: Falcon Exposure Management (FEM) is the current umbrella for exposure/vulnerability, built on Falcon Spotlight (vuln mgmt), Falcon Surface (EASM) and Falcon Discover; Spotlight remains the scanless vuln engine (no confirmed formal rename — treat Spotlight as the component inside FEM). AI-powered Network Vulnerability Assessment reached GA in March 2025 (free for existing FEM customers up to 10% of licensed managed assets, capped at 10,000 assets). Falcon Flex consumption licensing is the current commercial model, extended to services as 'Flex for Services' in 2026. CrowdStrike was named a Leader in the 2025 IDC MarketScape: Worldwide Exposure Management. Charlotte AI (agentic AI) and Falcon Next-Gen SIEM are current. Verify exact tier contents and per-asset pricing with CrowdStrike/reseller, as bundle composition and Flex entitlements vary by contract.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
