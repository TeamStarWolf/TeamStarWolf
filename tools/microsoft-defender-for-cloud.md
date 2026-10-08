# Microsoft Defender for Cloud

*Microsoft · Cloud-Native Application Protection Platform (CNAPP): CSPM + CWPP + DevSecOps, plus native update/patch management*

Microsoft Defender for Cloud is Microsoft's CNAPP: a unified platform combining Cloud Security Posture Management (CSPM) for misconfiguration/risk and Cloud Workload Protection (CWPP) for runtime threat protection across Azure, AWS, GCP, on-premises and hybrid estates. Azure Update Manager is the companion native patch-management service that assesses and deploys OS updates to Windows/Linux machines across Azure, on-prem and other clouds. Together they solve posture-plus-workload security and the remediation (patching) step for Microsoft-centric and multicloud environments.

## Capabilities & architecture

**Core capabilities**
- Foundational CSPM (free): secure score, misconfiguration recommendations, asset inventory, regulatory compliance dashboard, access to Microsoft Defender XDR
- Defender CSPM (paid): agentless vulnerability scanning, attack-path analysis, cloud security graph (Cloud Security Explorer), data-aware security posture (DSPM), permissions management (CIEM), code-to-cloud/DevOps security, external attack surface management (EASM)
- Defender for Servers (Plan 1 and Plan 2): agent-based and agentless VM protection, integrated vulnerability assessment (Microsoft Defender Vulnerability Management), EDR via Defender for Endpoint, file integrity monitoring, just-in-time VM access, adaptive network hardening (Plan 2)
- Defender for Containers: Kubernetes/AKS/EKS/GKE posture, agentless and agent-based runtime threat detection, registry image scanning, Kubernetes admission control
- Workload plans: Defender for App Service, Defender for Storage (incl. malware scanning), Defender for SQL/Databases, Defender for Key Vault, Defender for Resource Manager, Defender for APIs, Defender for AI Services
- Azure Update Manager: agentless assessment and deployment of OS updates for Windows/Linux across Azure, on-prem and multicloud (via Azure Arc), scheduled maintenance windows, update compliance reporting, hotpatching for supported Windows Server

**Architecture & deployment.** SaaS control plane in Azure. Multicloud and hybrid resources are onboarded via Azure Arc (for servers/Kubernetes outside Azure) and native cloud connectors for AWS/GCP. Posture and agentless vulnerability scanning use snapshot-based agentless scanning plus the cloud security graph; deeper workload protection uses the Microsoft Defender for Endpoint (MDE) agent (or agentless where available) on servers. Azure Update Manager is agentless (no separate agent; uses the Azure/Arc platform) and manages updates in-place. Findings surface in the Defender for Cloud portal and flow to Microsoft Sentinel/Defender XDR.

**Editions & licensing.** Foundational CSPM and access to Defender XDR are free. Paid plans are enabled individually and billed by resource/consumption: Defender CSPM per billable resource/month; Defender for Servers Plan 1 and Plan 2 per server/hour (Plan 2 includes integrated vulnerability management, 500MB/day free data, and bundles Azure Update Manager and guest configuration at no extra charge for Arc servers); Defender for Containers per vCPU/hour; Defender for Storage per storage account (malware scanning billed per GB scanned and excluded from the free trial). 30-day free trial for most plans. Azure Update Manager is free for native Azure VMs; for Arc-enabled (non-Azure) servers it is billed per server/day unless Defender for Servers Plan 2 is enabled (then included). Note: all Defender for Cloud features retire in the Azure China (21Vianet) region on August 18, 2026.

**Key integrations.** Microsoft Sentinel (SIEM) and Microsoft Defender XDR (native); Azure Arc for hybrid/multicloud onboarding; AWS and GCP connectors; GitHub Advanced Security and Azure DevOps (code-to-cloud); Microsoft Entra ID for CIEM/identity; ServiceNow and ticketing via connectors/Logic Apps; Azure Policy for guest configuration/governance; Event Hubs and Log Analytics for export.

**Differentiators**
- Deepest native integration with the Microsoft estate (Entra ID, Defender XDR, Sentinel, Intune, Azure Policy) - single identity and SIEM fabric
- Free foundational CSPM tier lowers adoption barrier; pay only for the workload plans you enable
- Native patch remediation via Azure Update Manager bundled into Defender for Servers Plan 2 - closes the detect-to-remediate loop inside one vendor
- Code-to-cloud attack-path analysis and cloud security graph rival specialist CNAPPs
- Integrated Microsoft Defender Vulnerability Management (MDVM) engine reused across endpoint and cloud

**Limitations & considerations**
- Strongest for Azure; AWS/GCP coverage is good but generally a step behind third-party multicloud-native CNAPPs like Wiz in breadth and parity
- Plan sprawl and per-resource billing make cost modeling complex; easy to overspend as plans multiply
- Agent (MDE) dependency for deepest server protection adds operational overhead vs fully agentless competitors
- Multicloud onboarding depends on Azure Arc, adding a dependency and management layer
- Historically noisier/less-consolidated UX than best-of-breed; attack-path depth outside Azure less mature (verify current parity)
- No inline virtual-patching/WAF; mitigation is posture hardening, JIT access, adaptive network hardening and patching - not inline shielding (Azure WAF/Front Door are separate)

## Vulnerability-mitigation role

Serves the full lifecycle for Microsoft and multicloud estates. Agentless vulnerability scanning plus integrated MDVM discover and assess CVEs on VMs, containers and registries; attack-path analysis and the cloud security graph prioritize by actual exploitable exposure (internet reachability + identity + data sensitivity). Compensating/mitigating controls in the patch window: just-in-time VM access and adaptive network hardening to cut reachability, file integrity monitoring and Defender for Servers EDR to detect exploitation, and Azure Policy/guest configuration to enforce hardened state. Azure Update Manager is the remediation control - assessing and deploying the fixing OS update (including hotpatch where supported) through scheduled maintenance windows, then re-assessing to validate closure.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Remediate/Patch · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: Identify (inventory, Defender CSPM), Protect (Update Manager, JIT, adaptive hardening), Detect (Defender for Servers/Containers, XDR), Respond/Recover (Sentinel playbooks); CIS Controls v8: 1-2 (inventory), 4 (secure config/CSPM), 5-6 (identity/CIEM), 7 (continuous vulnerability management), 8 (logging), 13 (monitoring); MITRE ATT&CK mitigations: M1051 Update Software (Azure Update Manager), M1030 Network Segmentation (adaptive network hardening), M1026 Privileged Account Management (JIT/CIEM), M1049 Antimalware (Defender for Storage/Servers), M1047 Audit, M1018 User Account Management

**In a critical-CVE scenario.** First 24-72h of a critical CVE in an internet-facing app and cloud workload: Defender for Cloud agentless scan and MDVM identify all affected VMs, containers and registry images across Azure/AWS/GCP; attack-path analysis and Cloud Security Explorer rank which affected assets are internet-exposed with privileged identity or sensitive data. Immediate mitigation: enable just-in-time access and adaptive network hardening to reduce reachability, confirm Defender for Servers EDR is detecting exploitation attempts, and tighten Azure Policy. Then use Azure Update Manager to schedule and deploy the patch (or hotpatch) across affected machines through an expedited maintenance window, with re-assessment and secure-score/compliance checks validating remediation.

## Validation & telemetry

**Log sources**
- Posture/recommendation data (control-present evidence): Azure Resource Graph securityresources table — assessment results (type microsoft.security/assessments), secure-score controls, regulatory compliance states, and sub-assessments (microsoft.security/assessments/subassessments) carrying CVE-level findings from the integrated scanner / MDVM.
- Security alerts (detection/block evidence): emitted by Defender plans; readable in portal, Microsoft.Security/alerts API, exported to Log Analytics SecurityAlert table, and ingested into Sentinel via the Defender for Cloud / Defender XDR connector.
- Unified Defender portal Advanced Hunting: AlertInfo / AlertEvidence, plus CloudStorageAggregatedEvents (GA-preview Aug 2025).
- Collection: Azure Monitor / Log Analytics agent or AMA + Data Collection Rules for guest telemetry; Continuous Export (Log Analytics or Event Hub) for alerts/recommendations/secure score; Event Hub -> third-party SIEM. Sentinel maps alerts to the ASIM schema.
- VERIFIED: securityresources + microsoft.security/assessments with status.code Healthy|Unhealthy|NotApplicable; SecurityAlert (ASC) as the Sentinel Log Analytics table; CloudStorageAggregatedEvents in Advanced Hunting.

**Telemetry format / transport.** KQL-queryable tables: ARM JSON (Azure Resource Graph posture), Log Analytics SecurityAlert rows (alerts), Defender XDR Advanced Hunting tables. Export transport: Azure Monitor / Event Hub (AMQP/Kafka) or Continuous Export. Sentinel normalizes to ASIM; alerts also available as Microsoft.Security/alerts REST JSON.

**Control-presence check (present & configured?).** Plan state: `az security pricing list` / `Get-AzSecurityPricing` -> each plan (VirtualMachines, Containers, StorageAccounts...) pricingTier == 'Standard' (resource Microsoft.Security/pricings, api 2018-06-01; VM sub-plan P2 enables agentless + MDVM). Agent/sensor health: query securityresources for the 'Log Analytics agent/Defender extension should be installed' assessments, or check MDE.Windows/MDE.Linux + AMA provisioning state on the VM. Control presence: assessment status.code == 'Healthy' means the resource satisfies the control. On-host (MDE-onboarded server) secure-config presence via Advanced Hunting DeviceTvmSecureConfigurationAssessment (IsCompliant/IsApplicable).

**Validation signals (actually working?)**
- CONFIGURED: assessment/recommendation status.code == Healthy and Defender plan pricingTier == Standard.
- EFFECTIVE: a CVE sub-assessment transitions Unhealthy->Healthy / stops returning after patch — vulnerability remediated.
- EFFECTIVE: a SecurityAlert row for an exploitation attempt against the asset (with Intent/kill-chain stage) proves the plan is actively detecting.
- EFFECTIVE (inline): Defender for Containers admission denial, or an upstream Azure WAF (Front Door/App Gateway) action=Block — note WAF block logs live in that resource's diagnostic logs, NOT in SecurityAlert.
- Distinguish: a Healthy assessment proves the control is PRESENT; a disappearing CVE sub-assessment + an alert showing a blocked/contained action prove it MITIGATED something.

**Key events / fields / tables / APIs**
- securityresources: properties.status.code (Healthy|Unhealthy|NotApplicable), properties.displayName, properties.resourceDetails.Id, properties.metadata.severity.
- sub-assessments: properties.id (CVE), properties.additionalData.cve, properties.status.code, properties.resourceDetails.
- SecurityAlert (Log Analytics): AlertName, AlertType, AlertSeverity, CompromisedEntity, ProductName ('Microsoft Defender for Cloud'/'Azure Security Center'), Entities, ExtendedProperties, Intent, Status, RemediationSteps, Tactics.
- Advanced Hunting: AlertInfo (AlertId, Title, Severity, Category, ServiceSource, DetectionSource), AlertEvidence; DeviceTvmSecureConfigurationAssessment (ConfigurationId, IsCompliant, IsApplicable), DeviceTvmSoftwareVulnerabilities (CveId, RecommendedSecurityUpdate) for onboarded servers.
- NOTE: SecurityAlert AlertType/CompromisedEntity column names are from general knowledge — verify against the live Log Analytics SecurityAlert table reference for your workspace.

**Example queries**

*Presence: resources where a control is Healthy (present & configured) vs Unhealthy* (KQL)

```kql
securityresources
| where type =~ 'microsoft.security/assessments'
| extend status = tostring(properties.status.code), rec = tostring(properties.displayName)
| where rec has 'System updates' or rec has 'vulnerabilit'
| summarize count() by status, rec
```

*Validation: CVE sub-assessments still Unhealthy (not yet mitigated) for a scanned image/VM* (KQL)

```kql
securityresources
| where type =~ 'microsoft.security/assessments/subassessments'
| extend cve = tostring(properties.id), st = tostring(properties.status.code), res = tostring(properties.resourceDetails.id)
| where st =~ 'Unhealthy'
| project res, cve, add = properties.additionalData
```

*Validation (Sentinel/Log Analytics): Defender for Cloud alerts actively firing against a host, 24h* (KQL)

```kql
SecurityAlert
| where ProductName in ('Azure Security Center','Microsoft Defender for Cloud') and TimeGenerated > ago(24h)
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Status, Tactics
| sort by TimeGenerated desc
```

**How it mitigates (mechanism).** Mitigation = config enforcement + reachability removal: a Healthy assessment means the enforced baseline/patch/network restriction is in place, and a CVE sub-assessment dropping to Healthy means the vulnerable-package reachability is gone; SecurityAlert is detective proof the plan is live, while true inline blocking is done by an upstream enforcement point (WAF, Just-in-Time VM access, admission control) logged in that resource's own diagnostics.

**Logging gotchas**
- 'Standard' pricing (plan enabled) != coverage — without AMA/MDE extension or agentless scanning provisioned, assessments return NotApplicable, which is neither Healthy nor a pass.
- Posture in Resource Graph refreshes on a scan cadence (not real-time), so a freshly patched host can show Unhealthy for a cycle.
- Defender for Cloud is largely posture+detection and does not block inline — prevention proof must come from the enforcing service's logs (Azure WAF diagnostic action=Block, Just-in-Time records, Entra SigninLogs appliedConditionalAccessPolicies), not SecurityAlert.
- The legacy subscription-based Sentinel connector writes only to SecurityAlert and does not support DCRs.
- Could not verify a dedicated SecurityRecommendation/SecurityRegulatoryCompliance Advanced Hunting table from official docs — read recommendations via Azure Resource Graph securityresources or Continuous Export, and confirm any table name with getschema before building detections.

## Documentation & repositories

_Official documentation & manuals_
- [Microsoft Defender for Cloud documentation hub](https://learn.microsoft.com/en-us/azure/defender-for-cloud/)
- [What is Microsoft Defender for Cloud?](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction)
- [Defender CSPM (cloud security posture management)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management)
- [Defender for Cloud deployment / enable plans](https://learn.microsoft.com/en-us/azure/defender-for-cloud/get-started)

_API & developer docs_
- [Microsoft Defender for Cloud REST API reference](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/)
- [Security Center REST API (legacy namespace, still referenced)](https://learn.microsoft.com/en-us/rest/api/securitycenter/)
- [Azure Resource Manager Microsoft.Security provider (api-version query)](https://learn.microsoft.com/en-us/azure/templates/microsoft.security/)
- [azurerm Terraform provider (security_center_* resources)](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
- [Azure SDK for Python / .NET developer docs](https://learn.microsoft.com/en-us/azure/developer/)

_GitHub (official)_
- [Microsoft Defender for Cloud community repo (official, Microsoft/Azure)](https://github.com/Azure/Microsoft-Defender-for-Cloud)
- [Azure org](https://github.com/Azure)
- [Microsoft org](https://github.com/microsoft)

_Community / integration / detection repos_
- [Microsoft Sentinel / Defender detection content & hunting queries](https://github.com/Azure/Azure-Sentinel)
- [Defender for Cloud workbooks, Logic App playbooks, policies (inside Azure/Microsoft-Defender-for-Cloud)](https://github.com/Azure/Microsoft-Defender-for-Cloud)
- [Azure Landing Zones / policy baselines (Enterprise-Scale)](https://github.com/Azure/Enterprise-Scale)

_Learning & reference_
- [Microsoft Learn training catalog](https://learn.microsoft.com/en-us/training/)
- [Defender for Cloud Ninja training (Microsoft Tech Community)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/become-a-microsoft-defender-for-cloud-ninja/ba-p/1608761)
- [Microsoft Defender for Cloud blog (Tech Community)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/bg-p/MicrosoftDefenderCloudBlog)

> Note: Product was renamed from Azure Security Center / Azure Defender to Microsoft Defender for Cloud; older REST docs still live under the 'securitycenter' namespace and the ARM Microsoft.Security provider. REST reference pages on Microsoft Learn may show a sign-in/authorization banner. Do NOT confuse with 'Microsoft Defender for Cloud Apps' (MCAS) — a separate product with its own tenant-scoped REST API. The Azure/Microsoft-Defender-for-Cloud GitHub repo is the official home for workbooks, automation playbooks, and sample policies.

## Current state (2025-26)

Defender for Cloud is positioned and documented by Microsoft as a CNAPP (CSPM+CWPP); foundational CSPM and Defender XDR access are free, paid plans added on top. Naming has consolidated around 'Defender CSPM' (paid) vs 'Foundational CSPM' (free), with agentless vulnerability scanning in the paid tier. Azure Update Manager is bundled with Defender for Servers Plan 2 at no extra charge for Arc servers; billed per Arc server/day otherwise. All Defender for Cloud features will be retired in the Azure China (21Vianet) region on August 18, 2026. Verify exact per-unit 2026 pricing on the Azure pricing pages/cost calculator (figures not publicly fixed).

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
