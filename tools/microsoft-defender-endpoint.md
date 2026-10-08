# Microsoft Defender for Endpoint & Vulnerability Management

*Microsoft · Cloud-delivered EDR/EPP with integrated risk-based Vulnerability Management (part of Microsoft Defender XDR)*

Microsoft Defender for Endpoint (MDE) is a cloud-delivered endpoint protection and EDR platform that combines next-gen antimalware, attack surface reduction, endpoint detection and response, automated investigation and response, and threat/vulnerability management on a single agent built into Windows. Microsoft Defender Vulnerability Management (MDVM) is the integrated, agentless-from-the-endpoint, continuously-assessing vulnerability capability — core features ship inside MDE Plan 2, with premium features sold as an add-on or standalone. It solves endpoint protection and vulnerability visibility natively for Windows-centric and Microsoft 365 estates without a separate scan agent. It feeds the broader Defender XDR and Microsoft Sentinel ecosystem.

## Capabilities & architecture

**Core capabilities**
- Next-generation antimalware / AV (Microsoft Defender Antivirus) with cloud-delivered protection
- Attack Surface Reduction (ASR) rules, network protection, controlled folder access, exploit protection
- Endpoint Detection and Response (EDR) with behavioral sensors and cloud analytics (Plan 2)
- Automated Investigation and Response (AIR) / self-healing (Plan 2)
- Microsoft Defender Vulnerability Management (MDVM): continuous real-time vulnerability and misconfiguration assessment, risk-based exposure scoring, software inventory
- MDVM premium (add-on/standalone): security baseline assessment, block vulnerable applications, browser-extension assessment, digital-certificate assessment, network-share analysis, hardware/firmware assessment, authenticated scan for Windows, consolidated inventories and broader asset coverage
- Threat & Vulnerability Management dashboards with CVE-to-device mapping and threat-informed prioritization (links to exploit availability and active threat campaigns)
- Advanced hunting (KQL), threat analytics, Microsoft Threat Intelligence
- Device discovery (agentless network discovery of unmanaged endpoints via onboarded devices)
- Microsoft Security Copilot integration for AI-assisted investigation, summarization and remediation guidance
- Mobile Threat Defense (Android/iOS), macOS and Linux server support

**Architecture & deployment.** Cloud-native SaaS backend with a built-in sensor. On Windows 10/11 and Windows Server the EDR sensor is native to the OS (no separate install); other platforms (macOS, Linux, Android, iOS) use a deployed agent. Onboarding is via Microsoft Intune (service-to-service connector, the recommended path), Group Policy, Configuration Manager, local script (<=10 devices), or VDI scripts. Telemetry flows to the customer's Defender tenant in the Microsoft cloud; management is through the Microsoft Defender portal (security.microsoft.com). MDVM assessment runs off the same endpoint sensor — no separate scan agent or scan schedule — with optional authenticated network scans for unmanaged/network devices.

**Editions & licensing.** Per-user/per-device subscription. MDE Plan 1 (prevention: AV, ASR, device-based conditional access; included in Microsoft 365 E3). MDE Plan 2 (adds EDR, AIR, and CORE Defender Vulnerability Management; included in Microsoft 365 E5). Microsoft Defender Vulnerability Management Add-on extends Plan 2 with the premium features. Defender Vulnerability Management Standalone is available for customers without Plan 2 (e.g. E3/P1). Defender for Endpoint for Servers / server add-on SKU covers server workloads (often paired with Defender for Cloud / per-server-hour billing for cloud workloads). Defender for Business targets SMB (<=300 seats).

**Key integrations.** Microsoft Defender XDR (native correlation across identity, email, cloud apps, cloud); Microsoft Sentinel (SIEM/SOAR); Microsoft Intune (onboarding, compliance, and remediation task hand-off; device risk gates Conditional Access via Entra ID); Microsoft Defender for Cloud (cloud workload / server vulnerability assessment); Microsoft Security Copilot; ServiceNow and third-party ITSM via APIs/connectors; Entra ID Conditional Access; Open APIs / streaming API for third-party SIEM.

**Differentiators**
- Agentless-to-the-endpoint vulnerability management — MDVM reuses the EDR sensor already present and native in Windows, so there is no separate scan agent, scan window or credentialed-scan infrastructure for managed devices
- Deep native integration across the Microsoft stack (Intune for remediation, Entra for risk-based access, Sentinel for SIEM, Defender XDR for correlation) — exposure data and response are one fabric
- Built into Windows and bundled in M365 E5 — enormous install base and low friction/marginal cost for Microsoft-licensed shops
- Threat-informed prioritization tying CVEs to active exploitation and Microsoft's threat intelligence, plus one-click remediation requests to Intune

**Limitations & considerations**
- Best value and completeness assume a Microsoft-centric estate; licensing (E3 vs E5 vs add-on vs standalone vs server SKUs) is genuinely confusing and easy to under/over-buy
- Vulnerability depth is primarily endpoint-OS and installed-software centric — weaker for network devices (authenticated/network scan is newer and narrower), appliances, OT/IoT, and deep web-app/DAST coverage than dedicated Tenable/Qualys/Rapid7
- Non-Windows and server coverage can require additional SKUs (Defender for Servers / Defender for Cloud), adding cost and complexity
- Heavy reliance on the Microsoft cloud and portal; multi-vendor / non-Microsoft shops get less value and face integration overhead
- Premium MDVM features gated behind the add-on; the 'core' set in P2 is deliberately limited

## Vulnerability-mitigation role

MDE/MDVM mitigates in the pre-patch window chiefly through configuration-based compensating controls and exposure reduction rather than classic network virtual patching: Attack Surface Reduction rules, exploit protection, network protection and 'block vulnerable application' can neutralize or block exploitation of a vulnerable component before a patch is deployed; security-baseline and misconfiguration remediation reduce the attack surface. MDVM continuously identifies affected devices and, via the Intune hand-off, drives the actual patch/remediation task, while EDR/AIR detect and auto-contain exploitation attempts. The tight exposure-to-remediation loop (CVE detected -> prioritized by active threat -> remediation request to Intune -> re-assessed) is its core mitigation value.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Remediate/Patch · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: IDENTIFY (vuln/asset inventory), PROTECT (AV, ASR, config, patch via Intune), DETECT (EDR, threat analytics), RESPOND (AIR), GOVERN/ IDENTIFY exposure scoring; CIS Controls v8: 1, 2, 4 (Secure Configuration), 7 (Continuous Vulnerability Management), 10 (Malware Defenses), 13 (Network Monitoring & Defense); MITRE ATT&CK mitigations: M1051 Update Software, M1042 Disable or Remove Feature or Program, M1050 Exploit Protection, M1040 Behavior Prevention on Endpoint, M1038 Execution Prevention, M1031 Network Intrusion Prevention

**In a critical-CVE scenario.** Hour 0-6: MDVM's continuous assessment already shows which onboarded devices run the vulnerable software/version with no scan needed; threat analytics flags whether the CVE is under active exploitation and raises its priority. For the internet-facing app, ASR rules / 'block vulnerable application' / network protection are enabled as an immediate compensating control, and EDR detections/hunting queries are deployed to catch exploitation. Hour 6-24: a remediation request is pushed to Intune to deploy the patch or workaround to affected devices; Conditional Access can block non-compliant/high-risk devices. For the cloud workload, Defender for Cloud/Servers surfaces the same exposure and feeds remediation. Hour 24-72: Intune rolls the patch in rings, MDVM re-assesses to confirm the CVE count drops to zero, and AIR/EDR continue monitoring; Security Copilot summarizes status and residual risk.

## Validation & telemetry

**Log sources**
- Cloud: Microsoft Defender XDR Advanced Hunting (Kusto/KQL). TVM/MDVM tables: DeviceTvmSecureConfigurationAssessment (+ ...KB), DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, DeviceTvmInfoGathering, DeviceTvmBrowserExtensions, etc. Behaviour tables: DeviceEvents, DeviceProcessEvents, DeviceInfo.
- On-device Windows Event Logs: Microsoft-Windows-Windows Defender/Operational (AV + ASR + Controlled Folder Access + Network Protection events); onboarding script logs to the Application log under source 'WDATPOnboarding'. (Some sources list certain ASR IDs under the Security channel — see gotchas.)
- APIs: Defender for Endpoint API (api.securitycenter.microsoft.com) and the newer Microsoft Graph security endpoints — machines, machineSecureConfigurationAssessments, vulnerabilities, recommendations; Advanced Hunting API via Graph POST /security/runHuntingQuery.
- Collection into SIEM: Defender XDR -> Microsoft Sentinel connector (lands the same table names in Log Analytics, ASIM-normalizable); or Event Log via AMA -> Sentinel; or the Defender streaming/SIEM API -> Azure Event Hub/Storage (JSON). Splunk via the Microsoft 365 Defender add-on; Windows events as XmlWinEventLog.

**Telemetry format / transport.** KQL tables (Advanced Hunting and the mirrored Sentinel/Log Analytics tables); Windows Event Log (EVTX/XML); JSON over the Graph/streaming API to Event Hub; ASIM in Sentinel, Splunk CIM (Malware/Endpoint, Change, Vulnerabilities) via the add-on.

**Control-presence check (present & configured?).** Onboarded (sensor present): registry HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status, REG_DWORD OnboardingState = 1 (onboarded; treat anything else as not-onboarded but confirm 0/2 meanings in current docs — sources conflict on 2=in-progress vs not). SENSE service running: 'sc query sense' (binary MsSense.exe, startup Automatic only when onboarded). PowerShell: Get-MpComputerStatus (OnboardingState, AMServiceEnabled, RealTimeProtectionEnabled=true, AMRunningMode=Normal — Passive/EDR-block means AV is not actively remediating). AV policy path HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection. ASR configured on device: Get-MpPreference -> AttackSurfaceReductionRules_Ids + AttackSurfaceReductionRules_Actions (0=Disabled, 1=Block, 2=Audit, 6=Warn); registry HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules (GUID=value; local/MDM path drops 'Policies\'). Controlled Folder Access: Get-MpPreference EnableControlledFolderAccess. Cloud-side config attestation: DeviceTvmSecureConfigurationAssessment per ConfigurationId (IsApplicable/IsCompliant), or the machineSecureConfigurationAssessments API.

**Validation signals (actually working?)**
- ASR actually BLOCKED (not just configured/audited): Windows Defender/Operational Event ID 1121 = rule blocked an operation; 1122 = audit-only (observed, NOT blocked); 1129 = user overrode a Warn-mode block; 5007 = ASR config changed. The 1121 vs 1122 split is the configured-vs-effective line. In Advanced Hunting: DeviceEvents | where ActionType startswith "Asr" — the '...Audited' suffix is confirmed (e.g. AsrLsassCredentialTheftAudited); the '...Blocked' variant follows the same Asr<Rule>Blocked pattern but I could NOT verify the exact blocked string from Microsoft docs — confirm in your tenant's schema. The rule GUID is in AdditionalFields.
- Controlled Folder Access / Network Protection block events exist in the same Operational log (CFA commonly cited as 1123 block / 1124 audit — VERIFY the exact IDs against current Microsoft docs before alerting).
- Secure config effective: DeviceTvmSecureConfigurationAssessment | where ConfigurationId == '<the setting that mitigates the CVE>' and IsApplicable == true and IsCompliant == true.
- Vulnerability remediated: the CveId no longer appears for the DeviceId in DeviceTvmSoftwareVulnerabilities and DeviceTvmSoftwareInventory shows the fixed version (reachability removed).

**Key events / fields / tables / APIs**
- Tables/columns: DeviceTvmSecureConfigurationAssessment(ConfigurationId, IsApplicable, IsCompliant, ConfigurationCategory, ConfigurationImpact, Context) + DeviceTvmSecureConfigurationAssessmentKB(ConfigurationDescription); DeviceTvmSoftwareVulnerabilities(CveId, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, VulnerabilitySeverityLevel); DeviceTvmSoftwareInventory; DeviceTvmInfoGathering; DeviceEvents(ActionType, AdditionalFields); DeviceInfo(OnboardingStatus, OSPlatform).
- Windows Defender/Operational Event IDs: 1121 ASR block, 1122 ASR audit, 1129 Warn override, 5007 config change. (1125/1126 are reported inconsistently across Splunk/Wazuh content, some under the Security channel — verify.) Onboarding: Application log 'WDATPOnboarding' event 15 (SENSE failed to start), event 35 (onboarding value not written to registry).
- Registry: ...\Windows Advanced Threat Protection\Status\OnboardingState; ...\Windows Defender Exploit Guard\ASR\Rules.
- PowerShell: Get-MpComputerStatus, Get-MpPreference, Add-MpPreference (Tamper Protection silently blocks changes made this way).
- APIs: Graph POST /security/runHuntingQuery; api.securitycenter.microsoft.com /api/machines, /machineSecureConfigurationAssessments, /vulnerabilities, /recommendations.

**Example queries**

*Presence + effectiveness of a mitigating secure-config setting, with its human description (confirm the control is present AND compliant).* (kql)

```kql
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010"   // the ConfigurationId mapping to the CVE's mitigating setting
| summarize arg_max(Timestamp, IsApplicable, IsCompliant) by DeviceId, ConfigurationId
| join kind=leftouter DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
| summarize Compliant=countif(IsCompliant==true), NonCompliant=countif(IsApplicable==true and IsCompliant==false) by ConfigurationId, ConfigurationDescription
```

*Prove ASR is actively BLOCKING (inline prevention), not just auditing, per rule over 30d.* (kql)

```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType startswith "Asr"
| extend RuleId = tostring(parse_json(AdditionalFields).RuleId)
| summarize Events=count() by ActionType, RuleId, DeviceName
| order by Events desc   // '...Blocked' rows = enforced; '...Audited' rows = configured but not blocking
```

*Validate a CVE is actually remediated across the fleet (devices still exposed = patch not effective).* (kql)

```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2024-38063"
| summarize StillVulnerable = dcount(DeviceId), Software = make_set(SoftwareName), Fix = any(RecommendedSecurityUpdate)
```

*On-device presence check: sensor onboarded, AV live, and the ASR rule set to Block (1) not Audit (2).* (powershell)

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status').OnboardingState; (Get-MpComputerStatus).RealTimeProtectionEnabled; $p=Get-MpPreference; for($i=0;$i -lt $p.AttackSurfaceReductionRules_Ids.Count;$i++){ '{0} = {1}' -f $p.AttackSurfaceReductionRules_Ids[$i], $p.AttackSurfaceReductionRules_Actions[$i] }
```

**How it mitigates (mechanism).** MDVM attests/scores the device's secure configuration and missing patches (config enforcement + reachability removal); MDE's ASR, Controlled Folder Access, Network Protection and AV perform inline blocking of the exploit behaviour in the kernel/minifilter. The observable proof is IsCompliant==true for the mitigating ConfigurationId, the CveId leaving DeviceTvmSoftwareVulnerabilities after patch, and a 1121 / Asr...Blocked event when an attempt is stopped.

**Logging gotchas**
- Audit vs Block: 1122 / 'Asr...Audited' prove the rule SAW the behaviour but did NOT stop it — counting audit events as 'mitigated' is the classic false pass. Only 1121 / 'Asr...Blocked' is enforcement.
- Advanced Hunting ASR events are throttled to unique processes per hour (first occurrence timestamp) — AH counts understate raw block volume; use the on-device Operational log for true counts.
- Registry OnboardingState and the portal can disagree (registry 0 while portal still shows onboarded); corroborate with DeviceInfo/API before declaring a device offboarded.
- AMRunningMode = Passive/EDR-Block means MDE is reporting but Microsoft AV is NOT the active remediator — 'onboarded' is not the same as 'actively blocking'.
- Tamper Protection silently blocks Add-MpPreference changes, so a config push can appear applied yet never take; verify with Get-MpPreference, not the deployment tool's success code.
- TVM tables carry prerelease notices and several ActionType/CFA event IDs are reported inconsistently in third-party content — verify exact strings/IDs against the Defender portal schema reference and current Microsoft docs before building detections.

## Documentation & repositories

_Official documentation & manuals_
- [Microsoft Defender for Endpoint documentation (Microsoft Learn hub)](https://learn.microsoft.com/en-us/defender-endpoint/)
- [Microsoft Defender Vulnerability Management documentation](https://learn.microsoft.com/en-us/defender-vulnerability-management/)
- [Microsoft Defender XDR documentation (parent suite)](https://learn.microsoft.com/en-us/defender-xdr/)

_API & developer docs_
- [Defender for Endpoint management & APIs overview](https://learn.microsoft.com/en-us/defender-endpoint/management-apis)
- [Defender for Endpoint API reference (apis-intro)](https://learn.microsoft.com/en-us/defender-endpoint/api/apis-intro)
- [Microsoft Graph Security API (strategic API surface for Defender)](https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview)

_GitHub (official)_
- [Microsoft GitHub organization](https://github.com/microsoft)
- [mdatp-xplat — official cross-platform (Linux/macOS) Defender deployment & config samples](https://github.com/microsoft/mdatp-xplat)
- [mdatp-devicecontrol — official device-control policy samples](https://github.com/microsoft/mdatp-devicecontrol)

_Community / integration / detection repos_
- [Microsoft 365 Defender Hunting Queries (KQL, archived but widely referenced)](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
- [Sigma detection rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team (ATT&CK test content)](https://github.com/redcanaryco/atomic-red-team)
- [MITRE CALDERA (adversary emulation)](https://github.com/mitre/caldera)

_Learning & reference_
- [Microsoft Learn training catalog (Secure your organization with Defender for Endpoint)](https://learn.microsoft.com/en-us/training/)
- [Microsoft Defender for Endpoint Ninja training (Tech Community)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/bg-p/MicrosoftDefenderATPBlog)

> Note: Product is part of Microsoft Defender XDR; the operations portal is security.microsoft.com (was securitycenter.microsoft.com). Advanced hunting uses KQL. The legacy Defender for Endpoint REST API is being superseded by the unified Microsoft Graph Security API — build new automation against Graph. Localized Learn URLs exist (/en-us/ is canonical). The /defender-endpoint/api/apis-intro path reflects a recent restructure of the API docs section; verify the exact leaf page if deep-linking. API-reference and DVM URLs rely on established knowledge — search budget was exhausted before live re-verification this run.

## Current state (2025-26)

VERIFIED 2025-2026: Current product family is Microsoft Defender for Endpoint Plan 1 / Plan 2, Microsoft Defender Vulnerability Management (core in P2, plus Add-on and Standalone SKUs), under the Microsoft Defender XDR umbrella managed in the unified Microsoft Defender portal (security.microsoft.com). Defender Vulnerability Management Standalone is GA for new customers and for existing P1/M365 E3 customers. Microsoft Security Copilot is integrated into the Defender portal for AI-assisted triage/remediation. Server/cloud-workload vulnerability assessment is delivered via Defender for Servers / Defender for Cloud. Exact premium-feature list and per-seat pricing should be verified against Microsoft's current licensing pages/reseller.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
