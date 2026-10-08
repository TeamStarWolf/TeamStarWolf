# Microsoft Entra ID

*Microsoft · Cloud identity & access management (IDaaS) / identity governance / Zero Trust identity control plane*

Microsoft Entra ID is Microsoft's cloud identity and access management service and the identity control plane for Microsoft 365, Azure, and tens of thousands of integrated SaaS and on-prem apps. It solves the problem of authenticating and authorizing human, workload, and device identities while enforcing adaptive, risk-aware access policy at sign-in. It is the former Azure Active Directory (renamed to Entra ID on 15 July 2023) and sits at the center of the broader Microsoft Entra product family. For vulnerability mitigation it is a front-line compensating control: Conditional Access and risk-based policy can block or step up access to an exposed app or identity faster than any patch can ship.

## Capabilities & architecture

**Core capabilities**
- Single sign-on (SSO) and federation (SAML, OIDC, WS-Fed, OAuth 2.0) to M365, Azure, and ~many thousands of pre-integrated SaaS apps via the app gallery
- Multi-factor authentication (MFA): Authenticator app (push, passwordless, number matching), FIDO2/passkeys, Windows Hello for Business, certificate-based auth, OATH tokens; phishing-resistant MFA enforcement
- Conditional Access (P1): policy engine evaluating user/group, app, device compliance, location/named networks, client app, and (with P2) sign-in/user risk to grant, block, require MFA, require compliant device, or limit session
- Entra ID Protection (P2): machine-learning risk detection (leaked credentials, password spray, anonymous IP, impossible travel, malware-linked IP, token anomalies) with risk-based Conditional Access and automated remediation
- Privileged Identity Management (PIM, P2): just-in-time, time-bound role activation for Entra and Azure RBAC roles and PIM for Groups, with approval workflows, justification, MFA-on-activation, and access reviews
- Self-service password reset (SSPR) and password protection (banned-password lists, on-prem password protection)
- Entra ID Governance: entitlement management (access packages), access reviews, lifecycle workflows (joiner/mover/leaver), separation-of-duties
- Device identity: Entra join / hybrid join / registration, device-based Conditional Access in concert with Intune compliance
- Application management: app registrations, enterprise apps, SSO config, Application Proxy for on-prem web apps, App governance
- Workload identities: service principals and managed identities, Conditional Access for workload identities, workload identity risk detections
- External identities: B2B collaboration, B2C / External ID (CIAM), cross-tenant access settings
- Global Secure Access (SSE): Entra Internet Access (secure web gateway) and Entra Private Access (ZTNA) delivering identity-centric network access
- Verified ID: decentralized/verifiable credentials

**Architecture & deployment.** Delivered as a multi-tenant global SaaS identity provider; no customer-run servers for the core directory. Hybrid identity is bridged from on-prem Active Directory via Entra Connect Sync (or Cloud Sync), with options for password hash sync, pass-through authentication, or AD FS federation. Authentication is cloud-terminated at Microsoft's global network; apps redirect users to Entra for token issuance (OIDC/SAML). Conditional Access evaluates signals inline at token issuance. Device signal flows from Intune/Entra-registered devices; on-prem app publishing uses the lightweight Application Proxy connector (outbound-only). Global Secure Access adds a client agent plus cloud edge for SWG/ZTNA. Logs flow to the Entra admin center and can stream to Log Analytics, Event Hub, or a SIEM.

**Editions & licensing.** Per-user subscription. Free tier (basic directory, SSO, security defaults) included with Azure/M365 subscriptions. Entra ID P1 (adds Conditional Access, dynamic groups, SSPR with on-prem writeback, Application Proxy, Entra Connect Health, basic access reviews) is bundled in Microsoft 365 E3 / Business Premium. Entra ID P2 (adds Identity Protection risk-based policy, PIM, full access reviews) is bundled in Microsoft 365 E5; standalone P2 commonly listed around USD 9/user/mo (verify). Entra ID Governance is a separate per-user add-on. The Entra Suite (GA Sept 2024) bundles ID Protection, ID Governance, Verified ID, Internet Access, and Private Access on top of a required P1 foundation. Global Secure Access components and Verified ID also licensed separately. Common pattern: P1 for all users, P2 scoped to admins/privileged and high-risk users.

**Key integrations.** Microsoft Sentinel and any SIEM (Splunk, QRadar, Chronicle) via diagnostic log streaming to Event Hub / Log Analytics; Microsoft Intune (device compliance signal for Conditional Access) and Microsoft Defender XDR / Defender for Cloud Apps (risk signal, session control); ServiceNow and other ITSM/ticketing for access requests, access package fulfillment, and lifecycle workflows; Thousands of SaaS apps via SAML/OIDC app gallery (Salesforce, ServiceNow, AWS, GCP, Workday, SAP, etc.); Cross-cloud federation to AWS IAM Identity Center and Google Cloud via SAML/OIDC; On-prem AD via Entra Connect; SCIM provisioning to downstream apps; Partner MFA/identity tools and FIDO2 security keys; works alongside Cisco Duo as an external MFA or as a federated IdP in some topologies.

**Differentiators**
- Default identity plane for the entire Microsoft 365 / Azure estate — unmatched reach and native signal depth for organizations already on Microsoft
- Rich ML-driven risk engine (Identity Protection) trained on Microsoft's trillions of daily signals, feeding risk directly into Conditional Access
- Tight native loop between identity (Entra), device (Intune), and threat (Defender XDR) for a unified Zero Trust posture
- Continuous Access Evaluation for near-real-time token revocation rather than waiting for token expiry
- Breadth: AuthN/AuthZ, governance (IGA), PAM-lite (PIM), CIAM (External ID), and SSE (Global Secure Access) under one license family

**Limitations & considerations**
- Licensing complexity: key controls (risk-based CA, PIM, full access reviews) are gated behind P2/E5 or add-ons; easy to under-license and lose protections
- PIM is time-bound elevation, not full PAM — no credential vaulting, session recording/isolation, or secrets management; not a replacement for CyberArk for infrastructure/privileged-session control
- Strongest when the estate is Microsoft-centric; governing non-Microsoft and multi-cloud identities well often needs add-ons or third-party IGA
- Conditional Access policy sprawl is a real operational risk — misconfiguration can lock out admins or create gaps; requires disciplined change control, report-only mode, and break-glass accounts
- Identity Protection risk detections can lag or generate false positives; tuning and E5 licensing needed for full fidelity
- Global Secure Access (SSE) is comparatively young versus incumbent SSE/ZTNA vendors

## Vulnerability-mitigation role

Acts as an identity-layer compensating / virtual-patching control during the exposure window. When a critical CVE hits an internet-facing or SaaS app, Conditional Access can immediately require phishing-resistant MFA, require a compliant/managed device, restrict to named locations, block legacy authentication protocols, or block the app outright for all or high-risk users, cutting off the exploitation path for identity- and access-dependent vulnerabilities (credential theft, token replay, session hijack, auth bypass) without touching the vulnerable code. Identity Protection auto-remediates compromised credentials (force password reset, block sign-in) that attackers would leverage post-exploit. PIM shrinks the standing-privilege blast radius so that even if a workstation or app is compromised, few accounts hold exploitable persistent admin rights. Continuous access evaluation (CAE) revokes tokens near-real-time when risk changes. It does not patch the CVE but materially reduces exploitability and blast radius until the vendor patch lands.

**VM lifecycle:** Prioritize · Mitigate · Monitor/Detect · Validate

**Framework mapping:** NIST CSF 2.0: PR (Protect) — PR.AA Identity Management, Authentication, and Access Control (primary); DE (Detect) — DE.CM continuous monitoring via Identity Protection; RS (Respond) — automated remediation; GV (Govern) — access governance; CIS Controls v8: 5 (Account Management), 6 (Access Control Management — esp. 6.3/6.4 MFA, 6.5 unique admin), 4 (Secure Configuration), 8 (Audit Log Management), 12 (Network — via Global Secure Access); MITRE ATT&CK mitigations: M1032 Multi-factor Authentication, M1036 Account Use Policies, M1018 User Account Management, M1026 Privileged Account Management, M1047 Audit, M1017 User Training (adjacent)

**In a critical-CVE scenario.** Hour 0-24: identify affected app(s) in Entra enterprise apps; create (report-only then enforced) Conditional Access policies to require phishing-resistant MFA and a compliant device for the exposed app, and block legacy auth. For a high-severity identity-exploitable flaw, scope a block or session-limit policy to all users or to Identity Protection high-risk users. Raise PIM so no standing admin access is active; require approval+MFA on activation. Hour 24-72: review Entra sign-in and audit logs (and Sentinel) for anomalous sign-ins, token anomalies, and risky users tied to the CVE; force credential reset / sign-in block on compromised accounts via Identity Protection; tighten named-location and device filters. For a cloud workload, constrain the relevant workload identity / managed identity with Conditional Access for workload identities and rotate associated secrets. Validate via report-only insights and sign-in telemetry; keep policies until the patched version is deployed and confirmed.

## Validation & telemetry

**Log sources**
- Native: Entra admin center > Sign-in logs, Audit logs, and Identity Protection reports (Risky users / Risk detections / Risky sign-ins).
- Diagnostic Settings export to Microsoft Sentinel / Log Analytics tables: SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs, AuditLogs, AADRiskyUsers, AADUserRiskEvents, AADRiskyServicePrincipals, AADProvisioningLogs. Each category must be ticked individually in the diagnostic setting.
- Microsoft Graph API: /auditLogs/signIns, /auditLogs/directoryAudits, /identityProtection/riskDetections, /identityProtection/riskyUsers, plus config endpoints /identity/conditionalAccess/policies and /policies/authenticationMethodsPolicy.
- Microsoft Defender XDR Advanced Hunting: AADSignInEventsBeta (Entra interactive sign-ins), AADSpnSignInEventsBeta, IdentityLogonEvents (Defender for Identity / cloud).
- SIEM collection: Splunk via the Microsoft Entra ID / Azure Monitor add-ons (Event Hub), Sentinel data connector (native).

**Telemetry format / transport.** JSON records exposed as Log Analytics/KQL columns (many are nested dynamic JSON). Emitted natively in the Entra admin center; exported via Diagnostic Settings to Microsoft Sentinel/Log Analytics, Event Hub (JSON), or Storage; and read via Microsoft Graph REST (JSON). Normalized downstream to Sentinel ASIM Authentication (imAuthentication/_Im_Authentication) and Splunk CIM (Authentication, Change data models).

**Control-presence check (present & configured?).** Confirm the control exists and is correctly configured via Microsoft Graph rather than any on-device key (Entra is a cloud IdP). Conditional Access: GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies (PowerShell: Get-MgIdentityConditionalAccessPolicy; perm Policy.Read.All) and assert state == 'enabled' (NOT 'enabledForReportingButNotEnforced' = report-only, NOT 'disabled'), that conditions match the intended users/apps, and grantControls.builtInControls contains 'mfa' or grantControls.authenticationStrength is set, or 'block'. MFA method config: GET /policies/authenticationMethodsPolicy and .../authenticationMethodConfigurations/{id} (e.g. fido2, microsoftAuthenticator) with state=='enabled'. User registration posture: GET /reports/authenticationMethods/userRegistrationDetails (Get-MgReportAuthenticationMethodUserRegistrationDetail) → isMfaRegistered / isMfaCapable. Catch config drift in AuditLogs OperationName 'Update Conditional Access policy' / 'Add conditional access policy'.

**Validation signals (actually working?)**
- SigninLogs.ConditionalAccessStatus with values success / failure / notApplied, combined with AuthenticationRequirement == 'multiFactorAuthentication' and AuthenticationDetails showing MFA was satisfied — proves a policy fired AND how it resolved.
- Per-policy result inside the ConditionalAccessPolicies (a.k.a. AppliedConditionalAccessPolicies) dynamic array: each object's result == 'success' | 'failure' | 'notApplied' | 'notEnabled' | 'reportOnlySuccess/Failure/NotApplied', with enforcedGrantControls (e.g. 'Mfa','Block'). result=='notApplied'/'notEnabled' means the policy did NOT act — distinguishes configured-but-idle from actually enforcing.
- ResultType codes that PROVE an enforcement action blocked or stepped up a sign-in (not just that a policy exists): 53003 (access blocked by Conditional Access), 50074 (strong auth required), 50076/50079 (MFA required / proof-up required), 530031 (blocked by a CA/security-defaults policy), 50158 (external security challenge not satisfied).
- Identity Protection: AADUserRiskEvents RiskEventType/RiskLevel/RiskState and risk-based CA outcomes; RiskState transition atRisk → remediated (user did MFA/password reset) proves the remediation control actually ran, not merely that risk was detected.

**Key events / fields / tables / APIs**
- Tables: SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, AADRiskyUsers, AADUserRiskEvents.
- SigninLogs fields: ConditionalAccessStatus; ConditionalAccessPolicies / AppliedConditionalAccessPolicies (dynamic array of {id, displayName, result, enforcedGrantControls, enforcedSessionControls}); AuthenticationRequirement; AuthenticationDetails; MfaDetail; ResultType; ResultDescription; Status; RiskLevelDuringSignIn; RiskState; ClientAppUsed; IPAddress; UserPrincipalName; AppDisplayName.
- AuditLogs fields: OperationName (e.g. 'Update Conditional Access policy'), Category ('Policy'), ActivityDisplayName 'User registered security info' (LoggedByService 'Azure MFA', per a community-observed record — verify in-tenant), InitiatedBy, TargetResources[].modifiedProperties (oldValue/newValue JSON).
- AADUserRiskEvents fields: RiskEventType, RiskLevel (low/medium/high/none), RiskState (atRisk/confirmedCompromised/remediated/dismissed), RiskDetail, Source, UserPrincipalName, CorrelationId.
- Graph endpoints for the same data: /auditLogs/signIns, /auditLogs/directoryAudits, /identityProtection/riskDetections, /identityProtection/riskyUsers, /identity/conditionalAccess/policies, /policies/authenticationMethodsPolicy, /reports/authenticationMethods/userRegistrationDetails.
- ResultType reference values: 0 success, 50074/50076/50079 MFA, 53003 blocked-by-CA, 530031 blocked, 50158 external challenge.

**Example queries**

*Validation: separate policies that actually enforced ('success'/'failure') from idle ones ('notApplied'/'notEnabled'/report-only) for a named MFA policy.* (KQL (Sentinel/Log Analytics))

```
SigninLogs
| where TimeGenerated > ago(7d)
| mv-expand policy = parse_json(ConditionalAccessPolicies)
| where tostring(policy.displayName) == "Require MFA for All Users"
| extend caResult = tostring(policy.result), grant = tostring(policy.enforcedGrantControls)
| summarize count() by caResult, grant, ConditionalAccessStatus
```

*Validation: prove the control actively blocked or forced MFA (hard enforcement evidence), not just that it was configured.* (KQL (Sentinel/Log Analytics))

```
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType in (53003, 50074, 50076, 50079, 530031)
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResultType, ResultDescription, ConditionalAccessStatus, IPAddress
```

*Presence / drift: detect changes to the enforcing CA policy and who made them.* (KQL (Sentinel/Log Analytics))

```
AuditLogs
| where OperationName in ("Update Conditional Access policy","Add conditional access policy","Delete conditional access policy")
| project TimeGenerated, OperationName, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName), TargetResources
```

**How it mitigates (mechanism).** Conditional Access is an inline policy decision point evaluated at token issuance: for every auth request it grants, requires an additional control (MFA, compliant/hybrid-joined device, authentication strength), or blocks, so credential-theft / phishing / legacy-auth vulnerabilities are mitigated by refusing or step-up-challenging the token. The observable proof is the per-policy result plus the ResultType on each sign-in event.

**Logging gotchas**
- Entra portal retains sign-in/audit logs ~30 days and Identity Protection risk data 30 days (P1) / 90 days (P2); only data exported via Diagnostic Settings persists longer. Enable retention before you need it.
- Report-only policies (state 'enabledForReportingButNotEnforced') log appliedConditionalAccessPolicies with result 'reportOnly*' and DO NOT block — presence of a policy object or an applied entry is NOT proof of enforcement.
- Non-interactive and service-principal sign-ins live in SEPARATE, high-volume tables (AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs) that must be enabled explicitly; token-theft/replay on service principals is missed if only SigninLogs is collected.
- Column naming drifts: AppliedConditionalAccessPolicies vs ConditionalAccessPolicies differs across ingestion paths — use column_ifexists(); and KQL '==' is case-sensitive, so match the documented casing 'Update Conditional Access policy' or use =~/in~.
- Legacy/basic auth (ClientAppUsed == 'Other clients') bypasses most grant controls unless a policy explicitly blocks legacy auth; those sign-ins can show MFA 'notApplied' while still succeeding.

## Documentation & repositories

_Official documentation & manuals_
- [Microsoft Entra ID documentation (Microsoft Learn)](https://learn.microsoft.com/en-us/entra/identity/)
- [Microsoft Entra documentation hub (all Entra products)](https://learn.microsoft.com/en-us/entra/)
- [What is Microsoft Entra ID? (overview)](https://learn.microsoft.com/en-us/entra/fundamentals/whatis)
- [Microsoft Entra admin center (console)](https://entra.microsoft.com/)

_API & developer docs_
- [Microsoft identity platform documentation](https://learn.microsoft.com/en-us/entra/identity-platform/)
- [Microsoft Graph API reference (overview)](https://learn.microsoft.com/en-us/graph/api/overview)
- [Microsoft Graph Azure AD / Entra resources overview](https://learn.microsoft.com/en-us/graph/api/resources/azure-ad-overview)
- [Microsoft identity platform code samples (auth libraries)](https://learn.microsoft.com/en-us/entra/identity-platform/sample-v2-code)
- [Terraform azuread provider (HashiCorp Registry)](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs)
- [HashiCorp tutorial: Manage Microsoft Entra ID users and groups](https://developer.hashicorp.com/terraform/tutorials/azure/entra-id)

_GitHub (official)_
- [AzureAD GitHub organization (MSAL + identity libraries)](https://github.com/AzureAD)
- [MSAL for JavaScript](https://github.com/AzureAD/microsoft-authentication-library-for-js)
- [MSAL for .NET](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet)
- [MSAL for Python](https://github.com/AzureAD/microsoft-authentication-library-for-python)
- [microsoft-identity-web (.NET web app auth)](https://github.com/AzureAD/microsoft-identity-web)
- [Microsoft Graph SDKs organization](https://github.com/microsoftgraph)
- [Azure-Samples (identity/auth code samples)](https://github.com/Azure-Samples)

_Community / integration / detection repos_
- [Microsoft Sentinel detection content (Entra sign-in/audit analytics)](https://github.com/Azure/Azure-Sentinel)
- [SigmaHQ detection rules (Azure/Entra sign-in & audit logs)](https://github.com/SigmaHQ/sigma)
- [Azure AD Incident Response PowerShell Module](https://github.com/AzureAD/Azure-AD-Incident-Response-PowerShell-Module)
- [ROADtools (Entra/Azure AD recon & enumeration)](https://github.com/dirkjanm/ROADtools)
- [AADInternals (Entra/Azure AD admin & offensive toolkit)](https://github.com/Gerenios/AADInternals)
- [Atomic Red Team (T1098 cloud account manipulation / Azure AD)](https://github.com/redcanaryco/atomic-red-team)

_Learning & reference_
- [Microsoft Learn training (browse Entra products)](https://learn.microsoft.com/en-us/training/browse/?products=entra)
- [Microsoft Entra blog (Tech Community)](https://techcommunity.microsoft.com/t5/microsoft-entra-blog/bg-p/Identity)
- [Microsoft Entra admin center (hands-on console)](https://entra.microsoft.com/)

> Note: LIVE-VERIFIED via WebSearch 2026-10-08. Product renamed from Azure Active Directory (Azure AD) to Microsoft Entra ID in 2023; docs moved from learn.microsoft.com/azure/active-directory to learn.microsoft.com/entra (old paths redirect). GitHub auth libraries still live under the legacy 'AzureAD' org, not an 'Entra' org. Microsoft Learn flagged the sample-v2-code page as undergoing maintenance with some possibly broken sample links — check live before relying on a specific sample repo. For the azuread Terraform provider, confirm the current major version/resource schema on the registry page.

## Current state (2025-26)

Azure AD was renamed Microsoft Entra ID (effective 15 July 2023); naming is stable in 2025-2026 with no new rebrand. Entra Suite reached GA in September 2024 bundling ID Protection, ID Governance, Verified ID, Internet Access, and Private Access over a P1 base. Global Secure Access (Entra Internet Access SWG + Entra Private Access ZTNA) continued maturing through 2025-2026 with ongoing client updates (e.g., v2.3x releases in 2026) and Purview DLP extended to network/web traffic via GSA integration; from November 2026 the GSA client is slated to update via Windows Update. Verify exact current standalone P2 pricing and Entra Suite pricing on Microsoft's site. Passkey/phishing-resistant MFA and passwordless remain the push direction.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
