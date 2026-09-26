# SaaS Security Reference

> **SaaS is someone else's software but your security problem.** The vendor patches the platform; you own the identities, the sharing settings, the third-party integrations, and the audit-log configuration — and that customer-side half is where the recent breach record lives. The anchor framework for getting it right is **[CISA's Secure Cloud Business Applications (SCuBA) project](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project)** (established 2022): free, testable Secure Configuration Baselines for Microsoft 365 and Google Workspace, plus the automated tools — **ScubaGear** and **ScubaGoggles** — to score a live tenant against them.

The defining pattern of 2023–2025 SaaS incidents is not exploitation of vendor code. It is **abused trust**: a legacy OAuth app with tenant-wide mail access (Midnight Blizzard), a forged signing key redeemed for mailbox tokens (Storm-0558), session tokens lifted from support-ticket attachments (Okta), and a compromised third-party integration's OAuth tokens replayed against hundreds of customer tenants (Salesloft Drift). Every one of those was an identity-and-configuration failure a customer-side control could have narrowed — and in several, the victims who *detected* it were the ones who had paid for the right logs.

This reference covers the SaaS threat surface at a taxonomy level, the case studies as the vendors publicly documented them, the SSPM tool category, CISA SCuBA and adjacent frameworks, identity-centric controls, OAuth app governance, license-gated logging, and per-platform hardening checklists.

**Related:** [Identity & Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) · [Identity Security](IDENTITY_SECURITY_REFERENCE.md) · [Cloud Security](CLOUD_SECURITY_REFERENCE.md) · [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) · [Secrets Management](SECRETS_MANAGEMENT_REFERENCE.md) · [Email Security](EMAIL_SECURITY_REFERENCE.md)

| | |
|---|---|
| **Read this when** | you inherit or stand up an M365/GWS/Salesforce/GitHub tenant and need a hardening baseline, an OAuth app or third-party integration needs review or a vendor just got breached, you are deciding which log tier or SSPM tooling to buy |
| **Start at** | [The SaaS threat surface](#the-saas-threat-surface) for the five threat classes, [Case studies from public advisories](#case-studies-from-public-advisories) for the incidents that motivate every control, [Hardening checklists by platform](#hardening-checklists-by-platform) to act today |

---

## Why SaaS security is different

| Property | Consequence for defenders |
|---|---|
| **No perimeter, no agent** | The "server" is a vendor API endpoint. You cannot deploy EDR to Salesforce; controls are configuration, identity, and API-consumed logs |
| **Admin plane is a web console** | Tenant-wide compromise is one hijacked admin session away; the console itself is internet-facing by design |
| **Vendor patches, customer configures** | CVE count is a poor risk signal; misconfiguration and over-permissive defaults are the dominant exposure class |
| **Integration sprawl** | Every OAuth grant, API key, marketplace app, and webhook is a standing credential with its own blast radius — a supply chain inside your tenant |
| **Tenants multiply silently** | Business units buy SaaS on a credit card; each unmanaged tenant is unmonitored attack surface (shadow SaaS) |
| **Telemetry is license-gated** | What you can detect depends on what tier you bought — a procurement decision becomes a detection decision |
| **Data leaves by design** | Sharing links, guest access, and export APIs are features; "exfiltration" often looks like normal product usage |

### The SaaS shared-responsibility split

| Layer | Vendor owns | Customer owns |
|---|---|---|
| **Platform code & infrastructure** | Vulnerabilities, patching, availability | — |
| **Identity** | The authentication machinery | Who has accounts, MFA strength, SSO enforcement, lifecycle (SCIM) |
| **Authorization** | The permission model | Role assignments, admin count, least privilege |
| **Integrations** | The OAuth/consent machinery | Which apps are consented, what scopes they hold, review and revocation |
| **Data exposure** | The sharing feature set | Default sharing posture, external/guest policy, DLP |
| **Telemetry** | Generating the logs | Licensing the right tier, exporting to SIEM, building detections |

Everything in the right-hand column is assessable, and most of it is scriptable — which is exactly the gap SCuBA and the SSPM category exist to close.

---

## The SaaS threat surface

Five conceptual threat classes cover most of what public advisories document against SaaS estates.

```
                        ┌─────────────────────────────┐
                        │      IDENTITY PROVIDER      │◄── password spray, MFA fatigue,
                        │   (Entra ID / Okta / GWS)   │    token forgery, session theft
                        └──────────────┬──────────────┘
                             SSO / OAuth / SCIM
              ┌────────────────┬───────┴───────┬────────────────┐
              ▼                ▼               ▼                ▼
        ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌─────────────┐
        │   M365   │    │   GWS    │    │Salesforce│    │ GitHub /    │
        │  tenant  │    │  tenant  │    │   org    │    │ other SaaS  │
        └────┬─────┘    └────┬─────┘    └────┬─────┘    └──────┬──────┘
             │               │               │                 │
       OAuth grants    marketplace     connected apps     OAuth & GitHub
       & app roles        apps         & API tokens            Apps
             ▼               ▼               ▼                 ▼
        ┌────────────────────────────────────────────────────────────┐
        │            THIRD-PARTY INTEGRATIONS (non-human)            │◄── the Drift lesson:
        │   each grant = a standing credential outside your MFA      │    compromise one vendor,
        └────────────────────────────────────────────────────────────┘    replay into every tenant
             + unmanaged tenants & personal accounts (shadow SaaS)
             + sharing links, guest access, public repos (misconfig)
```

| Threat class | What it is | Why it works | Primary control |
|---|---|---|---|
| **OAuth consent abuse** | An attacker-controlled app obtains a user's or admin's consent to scopes (mail read, file access), or an attacker with a foothold creates/repurposes apps and grants them roles | Consent screens are habitual clicks; legacy test apps keep tenant-wide permissions nobody remembers | Restrict user consent, admin consent workflow, periodic app-permission audit |
| **Token theft & replay** | Stolen access/refresh tokens, session cookies, or forged tokens are replayed to authenticate as the victim | A bearer token *is* the authentication — replay bypasses password and MFA entirely | Short token lifetimes, conditional access, token binding where offered, revocation runbooks |
| **Over-privileged third-party integrations** | A legitimate vendor integration holds broader scopes than its function needs; compromising the vendor compromises every customer grant | Integrations are approved once, scoped generously, and never re-reviewed | Scope least privilege at grant time, integration inventory, vendor-compromise revocation drill |
| **Shadow SaaS** | Tenants, apps, and integrations adopted outside IT visibility | Procurement is a credit card; discovery lags adoption | SSO-only policy, egress/CASB discovery, expense-report mining, app allowlisting |
| **Misconfigured sharing** | Public links, org-wide defaults, anonymous access, over-broad guest permissions | Sharing is the product's core feature; secure defaults vary by platform and era of tenant creation | Baseline the sharing settings (SCuBA SCBs), continuous posture monitoring (SSPM), DLP |

> **The non-human identity problem.** OAuth app registrations, service accounts, and API tokens are identities that never do MFA, never get offboarded by HR, and frequently outlive their purpose. Treat every integration grant as an account with a credential — inventoried, scoped, owned, and expiring. This is the core argument of the [OWASP Non-Human Identities Top 10 (2025)](https://owasp.org/www-project-non-human-identities-top-10/), covered under Frameworks below.

---

## Case studies from public advisories

Four incidents, documented by the affected vendors themselves, that together map the SaaS threat surface end to end. Descriptions below follow the language of the cited advisories.

### Storm-0558 — forged tokens and the logging gap (2023)

| | |
|---|---|
| **Victim surface** | Exchange Online mailboxes, including U.S. government agencies |
| **Actor** | Storm-0558 (Microsoft designation) |
| **Mechanism** | Forged authentication tokens signed with an acquired Microsoft account (MSA) signing key |
| **Detection** | The U.S. State Department spotted anomalous access via the `MailItemsAccessed` audit event — which at the time required premium (E5-tier) logging |
| **Public record** | [Microsoft Security Blog, July 19, 2023](https://www.microsoft.com/en-us/security/blog/2023/07/19/expanding-cloud-logging-to-give-customers-deeper-security-visibility/) |

**Why it matters:** the customer who could see the attack was the one paying for the right log tier. Under CISA pressure, Microsoft announced on July 19, 2023 that it would expand cloud logging access at no additional cost — moving events like mail items accessed, mail sent, and user search into Purview Audit (Standard). The structural lesson: **log availability is a security control, and it was being sold as a premium feature.** See the license-tier section below.

### Okta support system — one saved credential, 134 downstream victims (2023)

| | |
|---|---|
| **Victim surface** | Okta's support case management system; customer session tokens inside uploaded HAR files |
| **Root cause (per Okta)** | A service account credential had been saved into an employee's **personal Google account** on an Okta-managed laptop |
| **Window** | September 28 – October 17, 2023 (20 days of unauthorized access) |
| **Impact** | Support files of **134 customers** accessed; session tokens within HAR files enabled **session hijacking against 5 customers** |
| **Remediations (per Okta)** | Service account disabled, personal Google profiles blocked on managed laptops, session token binding by network location shipped for admin sessions |
| **Public record** | [Okta root-cause disclosure, Nov 2023](https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/) |

**Why it matters:** three SaaS failure modes in one incident — an unmonitored **non-human identity** (the service account), **credential sprawl into unmanaged SaaS** (personal Google profile), and **tokens as toxic residue** (HAR files carry live session cookies; scrub them before upload). If your IdP's vendor can be a source of your session tokens, token binding and short admin-session lifetimes are your compensating controls.

### Midnight Blizzard vs. Microsoft — legacy OAuth app abuse (2024)

| | |
|---|---|
| **Actor** | Midnight Blizzard / NOBELIUM, attributed by Microsoft to Russia's SVR |
| **Detected** | January 12, 2024 |
| **Initial access** | Password spray against a **legacy, non-production test tenant account without MFA**, using distributed residential proxies and deliberately low-frequency attempts |
| **Escalation** | Compromised a **legacy test OAuth application** that had elevated access to the corporate environment; created additional malicious OAuth apps and new user accounts to grant them consent |
| **Objective mechanics** | Granted the **`Office 365 Exchange Online full_access_as_app`** role to an attacker-controlled app, then collected corporate email via Exchange Web Services (EWS) |
| **Public record** | [Microsoft Security Blog responder guidance, Jan 25, 2024](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/) |

**Why it matters:** every link in the chain is a customer-side SaaS control. Microsoft's own responder guidance is the checklist: audit privileged identities **and application permissions** (not just users), remove unneeded Exchange impersonation and high-privilege app roles, enforce MFA and conditional access everywhere including test tenants, and hunt OAuth apps with Entra ID Protection and Defender for Cloud Apps anomaly detections. A "test tenant" with a trust path into production *is* production.

### UNC6395 / Salesloft Drift — third-party OAuth tokens as a supply chain (2025)

| | |
|---|---|
| **Actor** | UNC6395 (Google Threat Intelligence Group designation) |
| **Window** | August 8 to at least August 18, 2025 |
| **Mechanism** | Compromised OAuth tokens for the **Salesloft Drift** third-party app, used to authenticate to customers' **Salesforce** instances and mass-export data |
| **Follow-on** | Stolen data hunted for embedded secrets — AWS access keys (`AKIA…`), passwords, Snowflake tokens |
| **Response** | Salesloft and Salesforce revoked all active Drift access/refresh tokens on August 20, 2025; Salesforce temporarily removed Drift from AppExchange; scope later expanded beyond the Salesforce integration (e.g., Drift Email) |
| **Public record** | [GTIG advisory, Aug 26, 2025](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift) · [Salesforce security response](https://help.salesforce.com/s/articleView?id=005134951&language=en_US&type=1) |

**Why it matters:** customers were breached without their own credentials, users, or infrastructure being touched — the integration *was* the credential. Two durable lessons: (1) your integration inventory is a dependency list you must be able to revoke in hours, not weeks; (2) SaaS data stores are full of secondary credentials — the actor's first move after export was secret-hunting, so treat CRM cases, chat transcripts, and attachments as secret-bearing material ([Secrets Management](SECRETS_MANAGEMENT_REFERENCE.md)). Salesforce's secure-by-default follow-up (blocking uninstalled connected apps, from early September 2025) is covered in the governance section below.

---

## The ATT&CK lens on SaaS threats

MITRE ATT&CK v19 (released April 28, 2026) covers Enterprise with **15 tactics, 222 techniques, 475 sub-techniques, and 44 mitigations**; v19 split the old Defense Evasion tactic into **Stealth (TA0005)** and **Defense Impairment (TA0112)**. The SaaS-relevant platform tags in Enterprise ATT&CK are **SaaS**, **Office Suite**, and **Identity Provider** — filter any matrix view to those three to get the SaaS-relevant technique set. ([v19 release notes](https://attack.mitre.org/resources/updates/updates-april-2026/))

The two anchor techniques for the OAuth-token threat class, verified current in v19 (both last modified May 12, 2026):

| Technique | Tactic (v19) | Relevance |
|---|---|---|
| **[T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)** | Credential Access | Consent phishing and token theft — the acquisition side of every case study above |
| **[T1550.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001/)** (under T1550 Use Alternate Authentication Material) | Lateral Movement | Replaying stolen/issued tokens to act as the app or user — the Drift mechanism |

Adjacent techniques that recur in the case studies (IDs verified against this library's [technique dataset](data/attack/technique_profiles.jsonl); re-check tactic placement on attack.mitre.org, since v19 moved several techniques between tactics):

| Technique | Where it appeared above |
|---|---|
| **T1110.003 Password Spraying** | Midnight Blizzard initial access |
| **T1078.004 Valid Accounts: Cloud Accounts** | Every case — the post-compromise operating mode |
| **T1606 Forge Web Credentials** | Storm-0558 token forgery |
| **T1098.001/.002/.003 Account Manipulation** (additional cloud credentials, email delegate permissions, cloud roles) | Midnight Blizzard app-role grants |
| **T1136.003 Create Account: Cloud Account** | Midnight Blizzard new-user creation for consent |
| **T1539 Steal Web Session Cookie** | Okta HAR-file session tokens |
| **T1114.002 Remote Email Collection** | Midnight Blizzard EWS collection |
| **T1530 Data from Cloud Storage** / **T1213 Data from Information Repositories** | Drift-style mass export from SaaS data stores |

> **No official crosswalk exists** from ATT&CK to the SCuBA baselines or to the SSPM tool category. Map your own detections technique-by-technique using this library's [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) and [Detection Strategies](detections/strategies/README.md), and treat any vendor-published "SSPM×ATT&CK" matrix as marketing until you've verified each cell.

---

## Frameworks and guidance

### CISA SCuBA — the tenant baseline standard

The [Secure Cloud Business Applications (SCuBA) project](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project) (CISA, established 2022) publishes Secure Configuration Baselines (SCBs) and automated assessment tools for the two dominant productivity suites. Everything is free — GitHub, PowerShell Gallery, PyPI. Related deliverables include Hybrid Identity Solutions Guidance and a Technical Reference Architecture.

| Tool | Platform | Current release | How it works |
|---|---|---|---|
| **[ScubaGear](https://github.com/cisagov/ScubaGear)** | Microsoft 365 | **v1.8.0** (2026-05-07) | PowerShell; queries M365 APIs, evaluates settings against Rego policies with Open Policy Agent (OPA), emits HTML/JSON/CSV reports; a YAML config file is required for BOD 25-01 submissions |
| **[ScubaGoggles](https://github.com/cisagov/ScubaGoggles)** | Google Workspace | **v1.0.1** (2026-07-28; v1.0.0 was 2026-07-24) | Python (PyPI `scubagoggles`); exports settings via the Google Admin SDK / Policy API, evaluates with OPA Rego |

**M365 baseline coverage** — seven products per the current ScubaGear README: Microsoft Entra ID, Security Suite (Defender for Office 365 + Microsoft Purview functions), Exchange Online, Power BI, Power Platform, SharePoint Online & OneDrive (one combined baseline), and Teams. The repo's [baselines directory](https://github.com/cisagov/ScubaGear/tree/main/PowerShell/ScubaGear/baselines) currently carries eight baseline documents (`aad`, `defender`, `exo`, `powerbi`, `powerplatform`, `securitysuite`, `sharepoint`, `teams`) — note the baselines are mid-reorganization (`defender.md` and the newer `securitysuite.md` coexist), so check the repo before quoting per-baseline policy IDs.

**Google Workspace baseline coverage** — eleven baseline documents in the ScubaGoggles repo: Assured Controls, Calendar, Chat, Classroom, Common Controls, Drive & Docs, Gemini for Workspace, Gmail, Groups for Business, Meet, and Sites.

### BOD 25-01 — the baselines become mandatory

CISA Binding Operational Directive [25-01 "Implementing Secure Practices for Cloud Services"](https://www.cisa.gov/news-events/directives/bod-25-01-implementing-secure-practices-cloud-services) (issued December 17, 2024) made the SCuBA M365 baselines enforceable for Federal Civilian Executive Branch agencies:

| Deadline | Requirement |
|---|---|
| **2025-02-21** | Inventory all cloud tenants |
| **2025-04-25** | Deploy SCuBA assessment tools (ScubaGear) |
| **2025-06-20** | Implement all mandatory ("SHALL") SCuBA M365 policies, with deviations documented |

Even outside the federal space, BOD 25-01 is the useful template: inventory → automated assessment → mandatory policy floor → documented deviations. That is a SaaS security program in four lines.

### CSA SaaS Security Capability Framework (SSCF)

The Cloud Security Alliance released [SSCF v1.0](https://cloudsecurityalliance.org/artifacts/saas-security-capability-framework) on September 24, 2025 (v1.0.1 followed in April 2026 with a self-assessment questionnaire). It is the **vendor-facing complement** to SCuBA: a vendor-agnostic definition of the configurable, customer-facing security controls a SaaS vendor should *expose* (SSO support, audit-log access, token revocation, etc.), aligned to CSA CCM domains. Use it in procurement — as the requirements list you hand a SaaS vendor before signing — where SCuBA governs how you configure the tenant you already have.

### OWASP — what exists and what doesn't

**OWASP has no flagship "SaaS Security" project and no SaaS Top 10** (verified as of this writing — do not cite one). The closest official OWASP material is the **[Non-Human Identities Top 10, 2025 edition](https://owasp.org/www-project-non-human-identities-top-10/)** — directly on point for integration risk. Its **NHI3:2025 "Vulnerable Third-Party NHI"** covers third-party OAuth/SaaS integrations and cites the Midnight Blizzard legacy-OAuth-app incident as its real-world example. For the application layer of SaaS products you *build*, the general OWASP Top 10 and ASVS apply as usual ([Web Application Security](WEB_APPLICATION_SECURITY_REFERENCE.md)).

### NIST SSDF adjacency

For teams that build or heavily extend SaaS, the [Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf) is the vendor-side hygiene standard: **SP 800-218 v1.1 remains the current final version**; SP 800-218A (the SSDF Community Profile for generative AI and dual-use foundation models) is final; and an initial public draft of **SP 800-218r1 (SSDF v1.2)** was released in December 2025 under EO 14306 — check CSRC for its final status before citing it as current. SSDF is about how the software is built; SCuBA/SSCF are about how the service is configured and what controls it exposes. A complete SaaS assurance story needs both.

---

## SSPM: the SaaS Security Posture Management category

**SSPM** is a tool category defined by Gartner — widely credited to its *Hype Cycle for Cloud Security, 2020* — for tools that **continuously assess security risk and manage the security posture of SaaS applications**: misconfiguration detection against baselines, reporting on native security settings, and remediation suggestions. (The U.S. CMS security program maintains a useful public [SSPM explainer](https://security.cms.gov/learn/saas-security-posture-management-sspm).)

| | CSPM | SSPM |
|---|---|---|
| **Watches** | IaaS/PaaS (AWS/Azure/GCP resources) | SaaS tenants (M365, GWS, Salesforce, GitHub, …) |
| **Finds** | Public buckets, over-permissive IAM, exposed workloads | Weak tenant auth settings, risky OAuth grants, sharing misconfigurations, dormant privileged accounts |
| **Talks to** | Cloud provider APIs | Each SaaS product's admin APIs |
| **Coverage limit** | Provider services | Only the SaaS apps the vendor has built connectors for |

What a credible SSPM deployment gives you, regardless of vendor:

- **Continuous configuration drift detection** against a named baseline (CIS benchmark, SCuBA SCB, or vendor best practice) — not a quarterly screenshot audit
- **Third-party app/OAuth inventory** across tenants: what is connected, with which scopes, granted by whom, last used when
- **Identity posture**: admin sprawl, MFA-less accounts, dormant users, non-human identities without owners
- **Cross-tenant visibility** — the estate view a single product's admin console cannot give you

**Do**
- Start free: **ScubaGear and ScubaGoggles are, functionally, no-cost SSPM for the two big suites** — run them before buying anything, and keep them as the neutral scoring reference afterward.
- Use vendor-native posture tools where they exist — e.g., **[Okta HealthInsight](https://help.okta.com/en-us/content/topics/security/healthinsight/about-healthinsight.htm)** audits an Okta org's settings against Okta best practices (admin MFA policies, ThreatInsight, session policies).
- Buy commercial SSPM for breadth (the long tail of apps) and for continuous OAuth-grant monitoring — the two things scripts and native tools cover least.
- Feed SSPM findings into the same remediation pipeline as vulnerabilities — owner, SLA, ticket ([CTEM mobilization](CTEM_REFERENCE.md)).

**Don't**
- Treat an SSPM purchase as the program. The tool finds misconfigurations; governance (who approves apps, who owns settings, who fixes drift) is still yours.
- Assume coverage — verify your actual app list against the vendor's connector catalog before contract.
- Accept "SSPM maps to ATT&CK" claims uncritically; no official mapping exists.

---

## Identity-centric controls

Identity is the SaaS perimeter. Four controls carry most of the weight.

| Control | What it stops | Key facts |
|---|---|---|
| **SSO enforcement** | Password sprawl, per-app credential attacks, invisible accounts | Route every app through the IdP; disable or alert on local-password logins the app still allows |
| **SCIM lifecycle** | Orphaned accounts, standing access after offboarding | SCIM 2.0 = IETF **RFC 7643** (Core Schema) + **RFC 7644** (Protocol), both September 2015; automates provision/deprovision from the HR-driven source of truth |
| **Conditional access** | Token replay from unexpected contexts, legacy-protocol bypass | Policy-gate sign-ins by user risk, device compliance, location, and client app; block legacy authentication outright |
| **Phishing-resistant MFA** | Credential phishing, OTP relay, SIM swap, push fatigue | Per [CISA's fact sheet](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf): FIDO/WebAuthn and PKI-based (PIV/CAC) methods are phishing-resistant; OTP, SMS, and push are all phishable. OMB M-22-09 (Jan 2022) requires federal agencies to adopt phishing-resistant MFA and stop supporting phishable methods |

**Do**
- Enforce MFA on **every** account in **every** tenant — Midnight Blizzard's entry point was a non-production test tenant account without it.
- Prioritize phishing-resistant factors for admins, then developers and finance, then everyone; treat SMS as a migration debt with a retirement date.
- Deprovision through SCIM from HR events, then **verify**: reconcile IdP-assigned users against each app's actual account list monthly — apps accumulate accounts SCIM never created.
- Constrain admin sessions hardest: shortest lifetimes, re-auth for sensitive actions, and token/session binding where the platform offers it (Okta shipped network-location binding for admin sessions as a direct remediation of its 2023 incident).
- Extend the lifecycle to non-human identities: every OAuth app, service account, and API token gets an owner, a scope review date, and an expiry.

**Don't**
- Let "break-glass" accounts become unmonitored MFA exemptions — vault them, alert on any use.
- Assume MFA ends the story: a stolen post-auth token never sees your MFA prompt. Session controls and revocation capability are the second half.
- Leave test/dev tenants outside the identity baseline. If a trust path to production exists, the baseline applies.

---

## App-integration governance and the OAuth app review workflow

The lifecycle every tenant needs, independent of platform:

1. **Inventory** — enumerate every consented app and integration, with scopes, grant date, grantor, and last-used timestamp.
2. **Risk-tier by scope** — mail-read, files-wide, directory-write, and app-only ("act as the app, no user present") permissions are high tier; presence/profile-read is low. Refresh-token issuance (`offline_access`-style grants) raises any tier.
3. **Gate new consent** — end users request; a reviewer approves against written criteria (publisher verification, scope minimalism, vendor security posture — hand them the CSA SSCF).
4. **Monitor** — alert on new high-scope grants, consent from admin accounts, and dormant apps that suddenly wake up.
5. **Re-certify and revoke** — periodic review; unused for N days → revoke; vendor breach → revoke first, ask questions after (the Drift response was mass token revocation within days).

### Platform capabilities

| Platform | Native controls |
|---|---|
| **Microsoft Entra ID** | [User consent settings](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent) restrict or disable self-service consent (e.g., allow only verified publishers requesting low-risk permissions); the [admin consent workflow](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/admin-consent-workflow-overview) lets users request and designated reviewers approve centrally |
| **Microsoft Defender for Cloud Apps** | [App governance](https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-manage-app-governance) adds visibility, policy, detection, and remediation for OAuth apps registered in **Entra ID, Google, and Salesforce** — which user-installed apps have data access, their permissions, and who consented |
| **Google Workspace** | [App access control](https://knowledge.workspace.google.com/admin/apps/control-which-apps-access-google-workspace-data): classify third-party apps **Trusted / Limited / access-to-specific-data / Blocked**, mark Google services (Gmail, Drive, …) as *restricted* so only configured apps reach them via OAuth scopes, and block access to unconfigured apps entirely |
| **Salesforce** | Secure-by-default from early September 2025: end users are **blocked from using uninstalled connected apps**. Admins review **Setup → Connected Apps OAuth Usage**, explicitly *Install* trusted apps, set Permitted Users to **"Admin approved users are pre-authorized"** (Salesforce's recommendation), and *Block* untrusted apps ([Salesforce guidance](https://help.salesforce.com/s/articleView?id=005132365&language=en_US&type=1)) |
| **GitHub** | Organization-level approval controls over which OAuth apps and GitHub Apps may access org resources; review installed apps and their repository scopes as part of the same re-certification cycle |

> **Hunt the legacy apps first.** Microsoft's Midnight Blizzard responder guidance is explicit: audit *application* permissions, not just user privileges, and remove unneeded high-privilege app roles (Exchange impersonation, `full_access_as_app`-class grants). The most dangerous app in the tenant is usually the oldest one nobody owns.

---

## Logging and audit-trail availability across license tiers

What you can detect in SaaS depends on what you licensed. This is the Storm-0558 lesson made general, and it belongs in procurement conversations, not just SOC ones.

| Platform | Baseline tier | Gated tier | What changed / what's gated |
|---|---|---|---|
| **Microsoft 365** | **Purview Audit (Standard)** — E3/G3-level — now includes previously premium-only events: **mail sent, mail items accessed, user search** in Exchange Online and SharePoint Online (the post-Storm-0558 expansion Microsoft announced July 19, 2023) | Purview Audit (Premium) retains longer retention and additional capability | The events that detected Storm-0558 moved down-tier; CISA's [Microsoft Expanded Cloud Logs Implementation Playbook](https://www.cisa.gov/sites/default/files/2025-01/microsoft-expanded-cloud-logs-implementation-playbook-508c.pdf) (Jan 2025) covers operationalizing them in Microsoft Sentinel and Splunk |
| **Salesforce** | Setup audit trail and basic login history | **Salesforce Shield / Event Monitoring add-on** (Enterprise, Performance, Unlimited, Developer editions): full event log files with ~1 year retention, plus **Real-Time Event Monitoring** with Transaction Security policies ([Shield](https://www.salesforce.com/platform/shield/)) | Detection-grade telemetry — the kind needed to spot a Drift-style mass export — sits behind the add-on |
| **Google Workspace** | Admin console audit and investigation capability varies by edition | Higher Workspace editions carry the more advanced investigation tooling | Verify specifics against Google's current edition-comparison documentation before relying on a given log source |
| **GitHub** | Organization audit log | Streaming/API export options vary by plan | Confirm your plan's audit-log retention and export path against current GitHub docs |

**Do**
- Write log availability into vendor selection: "security-relevant audit events at the tier we're buying, exportable by API" — the CSA SSCF gives you the vocabulary.
- Export SaaS audit logs to your SIEM on day one; retention inside the SaaS product is not incident-response retention ([SIEM Reference](SIEM_REFERENCE.md)).
- Build detections for the SaaS-specific event classes: new OAuth consent grants, app-role assignments, mass download/export, anomalous token usage, admin-setting changes, new mail-forwarding rules.
- Know your revocation levers *before* the incident: which console/API call kills a user session, an app's tokens, a refresh token family — and who is authorized to pull it at 2 a.m.

**Don't**
- Assume the default tier logs what you need — verify event-by-event against your detection requirements.
- Let a licensing negotiation silently delete a detection capability the SOC depends on.

---

## Hardening checklists by platform

Baseline-first: run the automated assessment, then work the failures. These checklists highlight the controls with the strongest incident pedigree; the SCuBA baselines are the fuller authority for M365 and GWS.

### Microsoft 365

- Run **ScubaGear** against all seven SCB products (Entra ID, Security Suite, Exchange Online, Power BI, Power Platform, SharePoint & OneDrive, Teams); track failures to closure and re-run on a schedule.
- Enforce **phishing-resistant MFA via conditional access** for all users; no MFA-less accounts in any tenant, test tenants included.
- **Block legacy authentication** protocols tenant-wide.
- **Restrict user consent** to verified publishers/low-risk permissions and enable the **admin consent workflow**.
- **Audit application permissions**: enumerate high-privilege app roles (EWS impersonation, `full_access_as_app`-class grants), remove any without a current owner and justification.
- Confirm **Purview Audit (Standard)** events are flowing (mail items accessed, mail sent, user search) and exported per CISA's implementation playbook.
- Use **Entra ID Protection** risk policies and **Defender for Cloud Apps** OAuth-app anomaly detections and hunting.
- Review privileged roles: minimize Global Administrators, require separate admin accounts, protect break-glass accounts with alerts on use.

### Google Workspace

- Run **ScubaGoggles** against the GWS baselines (Common Controls first, then Gmail, Drive & Docs, and the rest of the eleven).
- Work Google's own [security checklist for medium and large businesses](https://support.google.com/a/answer/7587183) — admin accounts, accounts/2SV, apps, Gmail, Drive, Groups, devices.
- Enforce **2-Step Verification** with security keys for admins and high-value users.
- Configure **app access control**: mark Gmail and Drive as *restricted* services, classify third-party apps Trusted/Limited/Blocked, and **block unconfigured third-party apps**.
- Set Drive sharing defaults conservatively (external sharing off or domain-allowlisted where the business allows); audit existing broadly-shared files.
- Keep super-admin count minimal; use dedicated admin accounts that aren't daily-driver mailboxes.

### Salesforce

- Complete the **connected-app lockdown**: review *Connected Apps OAuth Usage*, Install the trusted apps, set Permitted Users to "Admin approved users are pre-authorized," Block the rest.
- Enforce MFA and SSO via your IdP; disable direct login for SSO-managed users where feasible.
- License and enable **Shield/Event Monitoring** if the org's data warrants it; ship event log files to the SIEM; add Transaction Security policies for mass-export patterns.
- Constrain API access: profiles/permission sets grant "API Enabled" deliberately, not by default; scope integration users to least privilege with IP restrictions where supported.
- Sweep stored data for embedded secrets (cases, notes, attachments) — the UNC6395 post-export secret hunt is the reason.

### GitHub

- **Require 2FA for all organization members** ([docs](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization)); GitHub itself required 2FA for code contributors on GitHub.com starting March 13, 2023, reporting ~95% opt-in among the required cohort and a ~25% drop in SMS's share as a second factor between early 2023 and early 2024 ([GitHub blog](https://github.blog/security/supply-chain-security/securing-millions-of-developers-through-2fa/)) — prefer security keys/passkeys over SMS.
- Govern **OAuth app and GitHub App access** to the organization: approval required, scopes reviewed, unused installations removed on the same re-certification cycle as other SaaS integrations.
- Enable **secret scanning** (with push protection) and dependency/code scanning on organization repositories; treat a leaked token in a repo as an active incident.
- Protect default branches (reviews required, force-push restricted) and minimize organization owners.
- Export and monitor the **organization audit log**; alert on member privilege changes, deploy-key additions, and new app installations.

### Every platform

- One named **owner** per tenant; no orphan tenants.
- SSO + SCIM wherever the product supports it; documented exception list where it doesn't.
- Quarterly access review covering humans **and** integrations.
- Sharing defaults reviewed annually and after every major vendor feature release — defaults drift.

---

## Building a SaaS security program

| Program element | What it looks like in practice |
|---|---|
| **1. Inventory** | Enumerate tenants and apps: IdP sign-in logs, SSO app catalogs, OAuth grant lists, egress/CASB data, expense reports. Shadow SaaS is found in finance systems as often as in network logs. BOD 25-01 made tenant inventory step one for a reason |
| **2. Baseline & assess on a cadence** | ScubaGear/ScubaGoggles scheduled (monthly or better) with results tracked as findings, not reports; SSPM for continuous drift and the long-tail apps; vendor-native tools (Okta HealthInsight) where offered |
| **3. Integration review board** | The OAuth workflow above, with real authority: new high-scope grants require approval; every integration has an owner and a re-certification date; a standing "vendor compromised → revoke tokens" runbook with named executors |
| **4. Identity lifecycle** | SSO enforcement targets, SCIM coverage percentage, phishing-resistant MFA rollout tiers, non-human identity register with expiries |
| **5. Detection engineering** | SaaS log sources in the SIEM with detections for consent grants, app-role changes, token anomalies, mass export, forwarding rules; coverage mapped per technique via the [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md), never assumed |
| **6. Procurement gate** | Security requirements in every SaaS purchase: SSO/SCIM support, audit-log availability at the purchased tier, token revocation capability, SSCF-style control exposure |
| **7. Exercise it** | Tabletop the Drift scenario: "our vendor's tokens are compromised — revoke, scope, notify." Measure hours-to-revocation the way you measure MTTR ([Security Metrics](SECURITY_METRICS_REFERENCE.md)) |

Run it as a [CTEM](CTEM_REFERENCE.md) scope: "the SaaS estate" is a textbook scoping choice — discovery is the inventory, prioritization weighs scope-breadth × data sensitivity, validation tests whether the consent gate and revocation runbook actually work, and mobilization gives every failing baseline control an owner and an SLA.

---

## Sources

**CISA / U.S. government**
- SCuBA project — https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project
- ScubaGear (M365) — https://github.com/cisagov/ScubaGear · baselines: https://github.com/cisagov/ScubaGear/tree/main/PowerShell/ScubaGear/baselines
- ScubaGoggles (Google Workspace) — https://github.com/cisagov/ScubaGoggles
- BOD 25-01 — https://www.cisa.gov/news-events/directives/bod-25-01-implementing-secure-practices-cloud-services
- Microsoft Expanded Cloud Logs Implementation Playbook (Jan 2025) — https://www.cisa.gov/sites/default/files/2025-01/microsoft-expanded-cloud-logs-implementation-playbook-508c.pdf
- Implementing Phishing-Resistant MFA fact sheet — https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf
- CMS SSPM explainer — https://security.cms.gov/learn/saas-security-posture-management-sspm

**Vendor advisories & documentation**
- Microsoft — Midnight Blizzard responder guidance (Jan 25, 2024) — https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- Microsoft — Expanding cloud logging (July 19, 2023) — https://www.microsoft.com/en-us/security/blog/2023/07/19/expanding-cloud-logging-to-give-customers-deeper-security-visibility/
- Microsoft — Entra user consent configuration — https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent · admin consent workflow — https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/admin-consent-workflow-overview
- Microsoft — Defender for Cloud Apps app governance — https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-manage-app-governance
- Google Threat Intelligence Group — Salesloft Drift / UNC6395 advisory (Aug 26, 2025) — https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift
- Salesforce — Drift incident response — https://help.salesforce.com/s/articleView?id=005134951&language=en_US&type=1 · connected app secure-by-default guidance — https://help.salesforce.com/s/articleView?id=005132365&language=en_US&type=1 · Shield — https://www.salesforce.com/platform/shield/
- Okta — support system root-cause disclosure (Nov 2023) — https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/ · HealthInsight — https://help.okta.com/en-us/content/topics/security/healthinsight/about-healthinsight.htm
- Google Workspace — security checklist (100+ users) — https://support.google.com/a/answer/7587183 · app access control — https://knowledge.workspace.google.com/admin/apps/control-which-apps-access-google-workspace-data
- GitHub — 2FA enforcement results — https://github.blog/security/supply-chain-security/securing-millions-of-developers-through-2fa/ · requiring 2FA in your organization — https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization

**Frameworks & standards**
- CSA SaaS Security Capability Framework — https://cloudsecurityalliance.org/artifacts/saas-security-capability-framework
- OWASP Non-Human Identities Top 10 — https://owasp.org/www-project-non-human-identities-top-10/
- NIST SSDF project — https://csrc.nist.gov/projects/ssdf
- SCIM 2.0 — RFC 7643: https://www.rfc-editor.org/rfc/rfc7643.html · RFC 7644: https://www.rfc-editor.org/rfc/rfc7644.html
- MITRE ATT&CK v19 release notes — https://attack.mitre.org/resources/updates/updates-april-2026/ · T1528: https://attack.mitre.org/techniques/T1528/ · T1550.001: https://attack.mitre.org/techniques/T1550/001/

---

*This reference summarizes third-party frameworks and public vendor disclosures — including CISA's SCuBA project and BOD 25-01, the CSA SSCF, the OWASP NHI Top 10, MITRE ATT&CK®, and the Gartner-defined SSPM category — as an independent practitioner summary. It is not affiliated with or endorsed by any of those organizations; release versions and dates were verified as of September 2026 and will drift — consult the linked upstream sources for authoritative and current content.*
