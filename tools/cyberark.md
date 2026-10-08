# CyberArk

*CyberArk — as of February 2026 a Palo Alto Networks company (acquisition completed ~Feb 2026, ~USD 25B; CyberArk continues as a standalone-available platform while being integrated into Palo Alto Networks) · Privileged Access Management (PAM) / secrets management / machine & workload identity / identity security platform (ITDR-adjacent)*

CyberArk is the market-leading privileged access and identity security platform. It secures the most dangerous access in an enterprise — privileged human accounts, application and machine credentials, secrets, certificates, and now AI-agent identities — by vaulting credentials, isolating and recording privileged sessions, enforcing least privilege, and moving toward zero standing privileges (ZSP). It solves the problem that a single compromised privileged credential can turn one exploited vulnerability into full domain/cloud takeover. For vulnerability mitigation it is the primary blast-radius and lateral-movement control: it removes standing privilege and controls the credentials attackers need to weaponize a CVE.

## Capabilities & architecture

**Core capabilities**
- Privileged Access Manager (PAM) — self-hosted and SaaS (Privilege Cloud): Enterprise Password Vault / Digital Vault for credential storage, Central Policy Manager (CPM) for automated credential rotation (change/verify/reconcile), Privileged Session Manager (PSM) for session isolation, proxying, recording, and auditing of privileged sessions, and Privileged Threat Analytics (PTA) for privileged-account threat detection
- Secrets Management: Secrets Manager (SaaS and Self-Hosted, evolved from Conjur) and Conjur Open Source for application/DevOps/CI-CD secrets; Secrets Rotation Service; cloud-native secrets discovery and management across AWS, Azure, GCP; Secret-less broker patterns
- Endpoint Privilege Manager (EPM): least-privilege and local-admin removal on Windows/macOS/Linux endpoints and servers, application control, credential theft protection, ransomware mitigation
- Secure Infrastructure Access / Secure Cloud Access: Zero Standing Privileges with just-in-time, ephemeral access to cloud consoles, VMs, databases, and Kubernetes; session management for modern infrastructure
- Machine Identity Security (from Venafi acquisition): TLS/machine certificate lifecycle management, PKI-as-a-service, workload identity, SSH key management, post-quantum-crypto readiness
- Identity Governance & Administration (from Zilla Security acquisition): AI-driven access reviews, provisioning, and identity compliance
- Workforce & Customer Identity: CyberArk Identity SSO, adaptive MFA, lifecycle management, user behavior analytics (the former Idaptive capabilities)
- CORA AI: embedded AI intelligence engine across the platform (anomaly detection, risk insight, assisting the Secure AI Agents solution)
- Secure AI Agents Solution: protects AI/agentic identities from prompt injection, credential leakage, and permission abuse
- Shared services: identity analytics, audit, and a unified Identity Security Platform control plane

**Architecture & deployment.** Hybrid: available as self-hosted (on-prem/private-cloud Digital Vault + CPM + PSM + PVWA web interface, hardened and often network-isolated) and as SaaS (Privilege Cloud, Secrets Manager SaaS, Secure Infrastructure Access, Identity). The Vault is a hardened, encrypted credential store; CPM rotates credentials against managed targets; PSM acts as a jump/proxy host that brokers and records sessions so the user never directly holds the target credential. Connectors/components (PSM, CPM, connector servers) are deployed near targets; cloud SaaS services use lightweight connectors for hybrid reach and brokered, ephemeral (ZSP) access to modern infrastructure. Secrets Manager/Conjur runs as a service or cluster that apps call via API/SDK or sidecar. EPM uses an endpoint agent reporting to a SaaS console. The platform is delivered via the unified CyberArk Identity Security Platform with shared identity, analytics, and audit services.

**Editions & licensing.** Modular, largely per-identity / per-managed-component subscription (plus consumption for some SaaS and secrets services); not a single SKU. Priced by number of privileged users/accounts, endpoints (EPM), secrets/workloads, machine identities/certificates, and which modules are licensed (PAM Self-Hosted vs Privilege Cloud, Secrets Manager, EPM, Secure Infrastructure/Cloud Access, Machine Identity, Identity/IGA). Enterprise, high-touch pricing typically via sales/partners; frequently sold as platform bundles. Self-hosted PAM uses term licensing (e.g., PAM Self-Hosted v15 line, Standard-Term Support). Verify current packaging, especially post-Palo Alto-acquisition bundling.

**Key integrations.** SIEM/SOAR: Splunk, Microsoft Sentinel, QRadar, Chronicle (session and privileged-threat telemetry); Palo Alto Cortex (increasing post-acquisition); ITSM/ticketing: ServiceNow (access requests, approvals, CMDB), BMC; Identity providers: Microsoft Entra ID, Okta, Ping for SSO/MFA federation into CyberArk; SCIM provisioning; Cloud platforms: AWS, Azure, GCP (console, IAM, secrets, VMs, databases, Kubernetes) for Secure Cloud/Infrastructure Access and cloud-native secrets; DevOps/CI-CD: Jenkins, Ansible, Terraform, Kubernetes, HashiCorp ecosystem via Secrets Manager/Conjur SDKs and APIs; MFA: integrates with Cisco Duo, Entra MFA, and CyberArk's own adaptive MFA as the step-up for privileged access; PKI/certificate authorities and machine-identity ecosystems via Venafi-derived capabilities.

**Differentiators**
- Deepest, most mature PAM in the market — vaulting, session isolation/recording, and credential rotation at enterprise scale with strong hardening pedigree
- End-to-end identity security across human, machine (Venafi), application/secrets (Conjur), cloud, and AI-agent identities under one platform — unusually broad
- Aggressive Zero Standing Privileges / JIT model for modern cloud and infrastructure, reducing the standing-credential attack surface
- Strong compliance/audit story: tamper-resistant session recordings and full privileged-access audit trail
- Rapid credential-rotation capability makes it a uniquely effective emergency response lever when credentials may be exposed
- Backed (post-Feb 2026) by Palo Alto Networks, promising tighter SOC/XDR and platform integration

**Limitations & considerations**
- Complex and heavy to deploy and operate, especially self-hosted (Vault HA, PSM/CPM sizing, target onboarding); real professional-services and run cost
- High total cost of ownership; modular licensing can get expensive and hard to forecast across PAM/EPM/Secrets/Machine Identity
- Onboarding every privileged account and target is a long program; partial coverage leaves gaps that undermine the control
- Session proxying and credential rotation can break fragile or custom applications and non-standard targets without careful plugin/connector work
- Acquisition-driven breadth (Venafi, Zilla, Idaptive heritage) means some modules have differing UX/consoles and integration maturity; roadmap/branding is in flux post-Palo-Alto acquisition (e.g., Conjur OSS momentum, platform naming) — verify
- Not an MFA/SSO front-door for the general workforce at Duo/Entra scale; its identity (ex-Idaptive) piece is less dominant than its PAM
- Operationally sensitive: a misconfigured or down Vault/PSM can block legitimate emergency access, so break-glass design is essential

## Vulnerability-mitigation role

The definitive lateral-movement and privilege-escalation mitigation — it attacks the exploitation chain rather than the flaw. Even when a CVE is exploited, CyberArk ensures the privileged credentials an attacker needs to pivot are vaulted, rotated, and not standing: Zero Standing Privileges and JIT access mean there is often no durable admin credential to steal; PSM isolation means the target password never reaches the (potentially compromised) endpoint and sessions are recorded for detection; CPM can force immediate rotation of all potentially exposed credentials across the estate the moment a CVE is disclosed, invalidating anything harvested; EPM removes local admin so a client-side exploit cannot gain or abuse elevated rights or deploy ransomware; Secrets Manager rotates application/machine secrets and API keys that an exploited workload might leak; PTA/CORA AI detect anomalous privileged use indicative of active exploitation. It is the classic compensating control that keeps a single exploited vulnerability from becoming a breach while patching proceeds.

**VM lifecycle:** Discover · Prioritize · Mitigate · Monitor/Detect · Validate

**Framework mapping:** NIST CSF 2.0: PR (Protect) — PR.AA Identity Management & Access Control, PR.PS platform security/least privilege (primary); DE (Detect) — DE.CM via PTA/CORA AI; RS (Respond) — credential rotation/containment; ID (Identify) — privileged account/secret discovery; CIS Controls v8: 5 (Account Management), 6 (Access Control Management — esp. 6.8 role-based, least privilege), 4 (Secure Configuration), 8 (Audit Log Management — session recording), 3 (Data Protection — secrets), 2 (adjacent, app/secret inventory); MITRE ATT&CK mitigations: M1026 Privileged Account Management (primary), M1027 Password Policies, M1032 Multi-factor Authentication, M1028 Operating System Configuration, M1015/M1018 account/user management, M1043 Credential Access Protection, M1047 Audit

**In a critical-CVE scenario.** Hour 0-24: when a critical CVE drops on an internet-facing app or cloud workload, immediately trigger CPM to rotate all credentials associated with the affected systems, service accounts, and any secrets the workload could expose — invalidating anything an attacker may have harvested. Enforce that all admin access to affected systems goes only through PSM (isolated, recorded) and require MFA + approval; ensure no standing privileged credentials remain (switch to JIT/ZSP for the exposed estate). For the cloud workload, use Secure Cloud/Infrastructure Access to grant only ephemeral, time-boxed access and rotate cloud-native secrets/keys via Secrets Manager. Pull local admin on exposed endpoints via EPM to prevent privilege abuse/ransomware post-exploit. Hour 24-72: use PTA/CORA AI and session recordings to hunt for anomalous privileged activity indicating exploitation; review which accounts/secrets touched the vulnerable system; expand rotation and JIT scope; feed telemetry to SIEM/SOAR. Validate that no standing credentials and no direct-credential sessions remain, and keep the tightened posture until systems are patched and confirmed clean.

## Validation & telemetry

**Log sources**
- Vault server audit → syslog, configured in DBParm.ini [SYSLOG] (SyslogServerIP, SyslogServerPort, SyslogServerProtocol, SyslogMessageCodeFilter, SyslogTranslatorFile).
- PTA (Privileged Threat Analytics) detections → syslog CEF/LEEF, set via PVWA > Administration > Configuration Options > Privileged Threat Analytics, or systemparm.properties syslog_outbound.
- SIEM: Splunk (sourcetypes cyberark:epv:cef and cyberark:pta:cef), Microsoft Sentinel CyberArk connector (lands in CommonSecurityLog as CEF), Elastic cyberarkpas / cyberark_pta integrations, QRadar, Google SecOps.
- CyberArk PAS REST API (/PasswordVault/API/...) for account/CPM configuration and state queries.
- Component logs (CPM, PSM, PVWA) locally on each component — NOT in the Vault syslog stream unless separately forwarded.

**Telemetry format / transport.** CEF (or LEEF) over syslog, TCP/TLS recommended with RFC5424 format (DBParm.ini UseLegacySyslogFormat=No). The Vault converts internal XML audit records to CEF via an XSL translator (Arcsight.sample.xsl = standard CEF, SplunkCIM.xsl = Splunk CIM, PTA.xsl, XSIAM.xsl). PTA emits CEF/LEEF syslog. REST config/state queries return JSON.

**Control-presence check (present & configured?).** Confirm the rotation/isolation control is configured via the REST API and Vault/PTA config, not a device key. Account under CPM management: GET /PasswordVault/API/Accounts/{id} → secretManagement.automaticManagementEnabled == true (if false, secretManagement.manualManagementReason explains why, e.g. 'This is a static account'); record secretManagement.lastModifiedTime. List scope with GET /PasswordVault/API/Accounts?search=.... Rotation policy itself lives in the platform definition's PasswordManagement section (change/verify/reconcile periods). Confirm syslog is forwarding: DBParm.ini [SYSLOG] SyslogServerIP set and SyslogMessageCodeFilter covers the action codes you need. Confirm CPM/PSM/PTA components are healthy and registered in PVWA System Health.

**Validation signals (actually working?)**
- CREDENTIAL ROTATION actually ran (mitigation effective, not just enabled): a CPM 'password changed/reconciled' Vault audit action code in the syslog stream combined with an updated secretManagement.lastModifiedTime on the account — proves the known/stolen secret was invalidated. (The exact numeric CPM change/verify/reconcile codes live in CyberArk's 'Vault Audit Action Codes' reference; confirm them for your version — see gotchas.)
- SESSION ISOLATION active: Vault action code 300 (PSM Connect) events prove the credential was brokered through PSM and never exposed to the user; 301 = connect failure. Code 295 = password retrieve (direct checkout — watch for retrievals that bypass PSM).
- PTA detective coverage firing: CEF name 'Suspected credentials theft' (deviceEventClassId 1, severity 8), 'Privileged access to the Vault during irregular hours' (class 23), plus Kerberos attack detections (Golden Ticket / DCSync) and suspicious password change performed outside the Vault.
- Distinguish configured vs effective: automaticManagementEnabled==true only proves intent; an account can be in CPM 'Failed' or 'Disabled by CPM' state and never rotate — you must see an actual CPM change audit event + moving lastModifiedTime to prove effectiveness.

**Key events / fields / tables / APIs**
- CEF: deviceEventClassId = the Vault audit action/message code; name = the action description; severity. Elastic's mapping: event.code = Vault audit action code, cyberarkpas.audit.message = description, cyberarkpas.audit.message_id = record code ID. Sentinel: CommonSecurityLog with DeviceVendor 'Cyber-Ark', DeviceEventClassID, Activity.
- Confirmed Vault action codes: 295 (retrieve password), 300 (PSM connect), 301 (connect failure); 295/300/378 appear in the Elastic 'recommended-monitor' action-code set (meaning of 378 not verified here). Full enumeration = CyberArk 'Vault Audit Action Codes' reference, 'Recommended Action Codes for Monitoring' section.
- DBParm.ini [SYSLOG] keys: SyslogServerIP, SyslogServerPort, SyslogServerProtocol, SyslogMessageCodeFilter, SyslogTranslatorFile, UseLegacySyslogFormat.
- PTA: sourcetype cyberark:pta:cef; CEF name + deviceEventClassId (e.g. 1 'Suspected credentials theft', 23 'irregular hours') + severity; forwarding in systemparm.properties syslog_outbound.
- REST: GET /PasswordVault/API/Accounts/{id} and ?search=; POST /PasswordVault/API/Accounts/{id}/Change, /Verify, /Reconcile; response fields secretManagement.automaticManagementEnabled, secretManagement.manualManagementReason, secretManagement.lastModifiedTime.

**Example queries**

*Validation: show credential checkouts and PSM-brokered sessions (isolation evidence) by account/user.* (Splunk SPL)

```
sourcetype="cyberark:epv:cef" (signature=295 OR signature=300 OR signature=301)
| eval action=case(signature=295,"RetrievePassword",signature=300,"PSMConnect",signature=301,"ConnectFailure")
| stats count by action user src cs_account
```

*Validation: prove PTA is actively detecting credential theft (effective detective control).* (Splunk SPL)

```
sourcetype="cyberark:pta:cef" name="Suspected credentials theft"
| table _time name deviceEventClassId severity src suser dst
```

*Presence + effectiveness: confirm the account is CPM-managed, then correlate to a real rotation.* (CyberArk PAS REST API)

```
GET /PasswordVault/API/Accounts/{id}  -> assert secretManagement.automaticManagementEnabled==true and capture secretManagement.lastModifiedTime; then confirm a CPM change audit event in syslog and that lastModifiedTime advanced after the scheduled/triggered Change. (Trigger with POST /PasswordVault/API/Accounts/{id}/Change when validating.)
```

*Presence/coverage: see which Vault action codes are actually arriving so you know your SyslogMessageCodeFilter isn't dropping rotation evidence.* (KQL (Sentinel CommonSecurityLog))

```
CommonSecurityLog
| where DeviceVendor == "Cyber-Ark"
| where TimeGenerated > ago(7d)
| summarize count() by DeviceEventClassID, Activity
```

**How it mitigates (mechanism).** Two complementary mechanisms: (1) credential invalidation — the CPM rotates/reconciles the vaulted secret on a schedule or after each use, so a leaked or known password stops working (observable = CPM change/reconcile audit code + advancing lastModifiedTime); (2) reachability removal / isolation and accountability — PSM brokers the privileged session so the human never holds the credential and all activity is recorded (observable = PSM Connect code 300). PTA adds inline detective analytics emitted as CEF alerts.

**Logging gotchas**
- SyslogMessageCodeFilter governs what is EVER emitted: the default can flood you with all user/safe activity, while a narrowed 'recommended' set can silently drop the exact CPM-change evidence you need to prove rotation. Audit this filter first.
- UseLegacySyslogFormat=Yes produces inaccurate timestamps and UDP transport drops events under load — use TCP/TLS + RFC5424. Translator-file choice (SplunkCIM.xsl vs Arcsight CEF vs XSIAM.xsl) changes field names; multiple destinations require the IP / translator / code-filter lists to be matched in count and order.
- automaticManagementEnabled==true is 'configured', not 'effective' — accounts in CPM 'Failed' or 'Disabled by CPM' state show management intent yet never rotate; always correlate an actual change audit event + moving lastModifiedTime.
- Exact numeric CPM change/verify/reconcile action codes and the meaning of code 378 were NOT verified in this research — confirm them against the 'Vault Audit Action Codes' reference for your Vault version before hard-coding detections.
- PTA event-class-ID ↔ name mapping is deployment/version-specific; validate the IDs in your own PTA. Component logs (CPM/PSM/PVWA) are not in the Vault syslog stream unless separately forwarded, so a rotation failure logged only on the CPM host can be invisible to the SIEM.

## Documentation & repositories

_Official documentation & manuals_
- [CyberArk documentation portal (all products)](https://docs.cyberark.com/)
- [CyberArk Privileged Access Manager – Self-Hosted docs](https://docs.cyberark.com/pam-self-hosted/)
- [CyberArk Privilege Cloud (SaaS PAM) docs](https://docs.cyberark.com/privilege-cloud-shared-services/)
- [CyberArk Identity (SSO/MFA, formerly Idaptive) docs](https://docs.cyberark.com/identity/)
- [CyberArk corporate site / product pages](https://www.cyberark.com/)

_API & developer docs_
- [CyberArk REST API reference (navigate per-product from docs hub)](https://docs.cyberark.com/)
- [Conjur open-source secrets manager documentation](https://docs.conjur.org/)
- [Conjur project site](https://www.conjur.org/)
- [Terraform CyberArk Conjur provider](https://registry.terraform.io/providers/cyberark/conjur/latest/docs)

_GitHub (official)_
- [CyberArk GitHub organization](https://github.com/cyberark)
- [Conjur (secrets management)](https://github.com/cyberark/conjur)
- [epv-api-scripts (Vault/PAS REST API automation scripts)](https://github.com/cyberark/epv-api-scripts)
- [Summon (secrets injection into env)](https://github.com/cyberark/summon)
- [Secretless Broker](https://github.com/cyberark/secretless-broker)
- [CyberArk Ansible security automation collection](https://github.com/cyberark/ansible-security-automation-collection)

_Community / integration / detection repos_
- [psPAS — community PowerShell module for the CyberArk PAS/PVWA REST API (widely used)](https://github.com/pspete/psPAS)
- [SigmaHQ detection rules (CyberArk Vault/PAS activity)](https://github.com/SigmaHQ/sigma)
- [CyberArk apps & add-ons on Splunkbase (SIEM integration)](https://splunkbase.splunk.com/apps?keyword=cyberark)

_Learning & reference_
- [CyberArk University / training catalog](https://training.cyberark.com/)
- [CyberArk Technical Community (forums, Marketplace, how-tos)](https://community.cyberark.com/)
- [Conjur tutorials & guides](https://docs.conjur.org/)

> Note: NOT LIVE-VERIFIED THIS TURN: the shared WebSearch budget (200 calls/turn, shared by all concurrent workflow agents) was exhausted after the Entra ID and Duo queries, so these CyberArk URLs are compiled from high-confidence prior knowledge and should be re-confirmed. Product structure to be aware of: CyberArk splits into PAM Self-Hosted (on-prem, formerly 'PAS') vs Privilege Cloud (SaaS); CyberArk Identity is the former Idaptive (SSO/MFA/IGA); Conjur is the open-source developer/secrets product with its own site (conjur.org). Deep doc paths under docs.cyberark.com are versioned and change per release — navigate from the hub and pick the matching version. Confirm the exact product slugs (pam-self-hosted, privilege-cloud-shared-services, identity) and the ansible-security-automation-collection repo name against the live sites before publishing into the reference library.

## Current state (2025-26)

Palo Alto Networks completed its acquisition of CyberArk (announced July 2025, ~USD 25B, closed ~February 2026) — the largest deal in Palo Alto's history; CyberArk continues to be available as a standalone Identity Security Platform while being integrated into Palo Alto's ecosystem. CyberArk acquired Venafi (machine identity / certificate lifecycle, ~USD 1.5B, closed Oct 2024) and Zilla Security (AI-driven IGA, ~USD 165M + earn-out, 2025). Key 2025 launches (IMPACT 2025): Secure All Secrets, Secrets Rotation Service, cloud-native secrets management (AWS/Azure/GCP), Secure Certificates & PKI with post-quantum readiness, the Secure AI Agents Solution, and CORA AI as the embedded intelligence engine. Secrets Manager is the current name for the Conjur-derived offering (SaaS, Self-Hosted, and Conjur OSS); PAM Self-Hosted v15 line shipped from Dec 2025 (Standard-Term Support) with 15.2.x builds in mid-2026. Post-acquisition product naming/bundling is evolving — verify current platform branding and SKUs against CyberArk/Palo Alto newsrooms.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
