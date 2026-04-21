# Identity & Access Management

Identity and Access Management (IAM) is the discipline of ensuring that every user, device, and workload can prove who they are, gets only the access they need, and that privileged access is tightly controlled and audited. In modern enterprise environments, identity has replaced the network perimeter as the primary security boundary — compromising an identity often means compromising everything that identity can reach, which in an overprivileged organization can mean the entire environment. The shift to cloud, remote work, and SaaS has made IAM simultaneously more complex and more critical: identities now span on-premises Active Directory, cloud directories, SaaS applications, and non-human service accounts in numbers that dwarf human user counts.

IAM failures drive a disproportionate share of significant breaches. The Lapsus$ campaign, the SolarWinds supply chain attack, and the majority of ransomware deployment chains all depend on identity compromise — credential theft, privilege escalation, and lateral movement through misconfigured trust relationships. Understanding IAM means understanding why these attacks succeed, and building the controls that make them fail.

> Ensuring every user, device, and workload can prove who they are, gets only the access they need, and that privileged access is tightly controlled and audited.

## What IAM Engineers Do

- Design and operate Identity Providers (IdP) and federated identity architectures (SAML, OIDC, OAuth 2.0)
- Implement and enforce Multi-Factor Authentication (MFA) and phishing-resistant authentication (FIDO2/passkeys)
- Manage Privileged Access Management (PAM): just-in-time access, session recording, credential vaulting
- Define and enforce Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC)
- Conduct access reviews and certifications (Joiner-Mover-Leaver lifecycle)
- Implement Zero Trust identity controls: continuous authentication, device trust, context-aware access
- Manage cloud entitlements and CIEM (Cloud Infrastructure Entitlement Management)
- Investigate identity-based attacks: credential stuffing, MFA fatigue, Kerberoasting, Golden Ticket

---

## Where to Start

IAM has two distinct learning tracks that eventually converge: the defensive/engineering track (building identity systems, configuring MFA, managing access reviews) and the offensive/detection track (understanding how attackers abuse identity to move laterally). Both tracks require understanding Active Directory deeply — even in cloud-first organizations, AD remains the identity backbone that most attacks pivot through.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Active Directory fundamentals, authentication protocols (Kerberos, NTLM, SAML, OAuth 2.0/OIDC), MFA concepts, RBAC vs ABAC, Joiner-Mover-Leaver lifecycle | [Microsoft Learn — Identity fundamentals](https://learn.microsoft.com/en-us/training/paths/m365-identity-associate/), [TryHackMe Active Directory Basics](https://tryhackme.com/room/winadbasics), [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html), [BHIS IAM webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) |
| Practitioner | Cloud IAM (AWS IAM, Entra ID Conditional Access), PAM deployment, BloodHound AD attack path analysis, SSO federation, SCIM provisioning, access certification programs | [BloodHound CE](https://github.com/SpecterOps/BloodHound), [SC-300 learning path (free)](https://learn.microsoft.com/en-us/certifications/identity-and-access-administrator/), [SpecterOps blog](https://specterops.io/blog/), [The Hacker Recipes — AD](https://www.thehacker.recipes/ad/) |
| Advanced | Zero trust architecture design, CIEM, non-human identity (NHI) governance, cross-cloud identity federation, identity threat detection engineering, IGA program design | [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final), [SANS SEC542 AD/IAM content](https://www.sans.org/cyber-security-courses/web-app-penetration-testing-ethical-hacking/), [SailPoint identity program design](https://www.sailpoint.com/identity-library/), [CyberArk Blueprint](https://www.cyberark.com/resources/blueprint/) |

---

## Free Training

- [Microsoft Learn — Identity and Access Administrator](https://learn.microsoft.com/en-us/certifications/identity-and-access-administrator/) — Free comprehensive learning path covering Entra ID, Conditional Access, MFA, external identities, and application access; the SC-300 prep path doubles as an excellent IAM foundations course for any practitioner
- [TryHackMe Active Directory](https://tryhackme.com/room/winadbasics) — Free introductory rooms covering AD structure, users/groups, GPOs, and domain trusts; essential foundational knowledge before studying AD attack techniques
- [SpecterOps Blog and Talks](https://specterops.io/blog/) — Free deep-dive research on AD/Azure attack techniques, BloodHound development, and identity-based attack paths; some of the most technically rigorous IAM security content published anywhere
- [The Hacker Recipes — Active Directory](https://www.thehacker.recipes/ad/) — Free comprehensive reference for AD attack techniques (for defensive awareness); covers NTLM relay, Kerberoasting, AS-REP roasting, DCSync, and domain privilege escalation paths
- [NIST SP 800-63 Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) — Free government standard defining identity assurance levels, authenticator assurance levels, and federation assurance levels; the authoritative reference for identity program design
- [BloodHound Community Edition Documentation](https://support.bloodhoundenterprise.io/) — Free documentation explaining attack path concepts, AD relationships, and how attackers chain privileges; reading the docs teaches you the attack paths even without running the tool
- [HashiCorp Vault Learn](https://developer.hashicorp.com/vault/tutorials) — Free tutorials covering secrets management, dynamic credentials, PKI, and encryption as a service; the most important PAM-adjacent open-source skill for cloud practitioners
- [Okta Developer Documentation](https://developer.okta.com/docs/) — Free documentation covering OAuth 2.0, OIDC, SAML, and modern identity federation implementation; excellent for understanding how enterprise SSO actually works
- [SANS Cyber Aces — Windows Security](https://www.sans.org/cyberaces/) — Free introductory course covering Windows authentication, AD basics, and access control; a good entry point before diving into attack-oriented content
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model) — Free government guidance on zero trust identity pillar implementation; practical framework for planning identity-centric zero trust programs

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) | Digital Identity Guidelines — Authentication |
| [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) | Zero Trust Architecture |
| [NIST SP 800-53 AC/IA families](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) | Access Control and Identification/Authentication controls |
| [OAuth 2.0 / OIDC](https://oauth.net/2/) | Delegated authorization and federated identity |
| [SAML 2.0](https://www.oasis-open.org/standards#samlv2.0) | Enterprise SSO federation standard |
| [FIDO2 / WebAuthn](https://fidoalliance.org/fido2/) | Phishing-resistant passwordless authentication |
| [MITRE ATT&CK — Credential Access](https://attack.mitre.org/tactics/TA0006/) | Identity attack technique taxonomy |

---

## Free & Open-Source Tools

### Identity & Directory

| Tool | Purpose | Notes |
|---|---|---|
| [Keycloak](https://www.keycloak.org/) | Open-source IAM / SSO | OIDC, SAML, OAuth 2.0; Red Hat-maintained |
| [FreeIPA](https://www.freeipa.org/) | Linux identity management | Integrates LDAP, Kerberos, DNS, NTP |
| [OpenLDAP](https://www.openldap.org/) | LDAP directory service | Core directory infrastructure |
| [Samba](https://www.samba.org/) | AD-compatible domain controller | Linux-based Active Directory |

### Privileged Access & Secrets

| Tool | Purpose | Notes |
|---|---|---|
| [HashiCorp Vault](https://www.vaultproject.io/) | Secrets + dynamic credentials + PKI | Gold standard; dynamic creds for databases, cloud |
| [OpenBao](https://openbao.org/) | Open-source Vault fork | Community fork post-BSL license change |
| [CyberArk Conjur (OSS)](https://www.conjur.org/) | Secrets management | Enterprise-grade OSS secrets manager |
| [Teleport](https://goteleport.com/) | Zero trust access for infrastructure | SSH, Kubernetes, DB access with SSO |

### Active Directory Security & Attack Tools (Defensive Use)

| Tool | Purpose | Notes |
|---|---|---|
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) | AD attack path analysis | Visualize privilege escalation paths |
| [PingCastle](https://www.pingcastle.com/) | AD security assessment | Risk scoring for AD misconfigurations |
| [ADRecon](https://github.com/sense-of-security/ADRecon) | AD reconnaissance | Enumerate AD for security auditing |
| [Impacket](https://github.com/fortra/impacket) | Windows protocol toolkit | Understand Kerberos attacks defensively |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Kerberos attack toolkit | Used by red teams; understand for detection |

### MFA & Authentication

| Tool | Purpose | Notes |
|---|---|---|
| [privacyIDEA](https://www.privacyidea.org/) | Open-source MFA server | TOTP, FIDO2, SMS; on-premises |
| [Authelia](https://www.authelia.com/) | Open-source auth portal | 2FA + SSO for self-hosted apps |

---

## Commercial Platforms

| Vendor | Capability | Strength |
|---|---|---|
| [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id) | Cloud IAM + Conditional Access | Dominant in enterprise; deep M365 integration; Conditional Access is the most flexible policy engine at scale |
| [Okta](https://okta.com/) | Universal directory + SSO + MFA | Best-in-class workforce and customer identity; richest third-party integration library; Okta Verify supports FIDO2 |
| [CyberArk](https://www.cyberark.com/) | PAM + secrets + endpoint privilege | Market leader in PAM; strongest for privileged session recording and credential vaulting at enterprise scale |
| [BeyondTrust](https://www.beyondtrust.com/) | PAM + remote access | Strong in endpoint privilege management and remote vendor access; Privileged Remote Access module is a key differentiator |
| [SailPoint](https://www.sailpoint.com/) | Identity governance | Leading IGA platform; access certification, entitlement management, and role mining; strong in regulated industries |
| [Saviynt](https://saviynt.com/) | Cloud-native IGA | Converged IGA + PAM; strong for cloud application access governance; SaaS delivery model reduces operational overhead |
| [Ping Identity](https://www.pingidentity.com/) | Enterprise SSO + MFA | Strong federation capabilities; widely deployed in financial services; handles complex B2B federation scenarios |
| [Delinea](https://delinea.com/) | PAM (formerly Thycotic + Centrify) | Secret Server for credential vaulting; Privilege Manager for endpoint privilege; strong SMB to mid-market PAM option |

---

## NIST 800-53 Control Alignment

IAM directly implements the Access Control (AC) and Identification & Authentication (IA) families from [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final). These controls define the baseline requirements that IAM programs must satisfy in federal systems and are widely adopted as the compliance anchor for enterprise IAM programs.

| Control Family | Control ID(s) | IAM Implementation |
|---|---|---|
| Access Control (AC) | AC-2 | Account management lifecycle: provisioning, access reviews, deprovisioning via Joiner-Mover-Leaver process and IGA platform |
| Access Control (AC) | AC-3, AC-6 | Enforce least-privilege RBAC; periodic access reviews; privileged access restricted to PAM-vaulted accounts |
| Access Control (AC) | AC-7 | Account lockout after failed authentication attempts; rate limiting on authentication endpoints |
| Access Control (AC) | AC-17 | Remote access via MFA-enforced VPN or zero trust network access (ZTNA); conditional access policies evaluating device trust |
| Identification & Authentication (IA) | IA-2, IA-2(1), IA-2(6) | MFA for all interactive logins; phishing-resistant MFA (FIDO2) for privileged accounts; network device authentication |
| Identification & Authentication (IA) | IA-5 | Authenticator management: password policy enforcement, credential rotation for service accounts, hardware token lifecycle |
| Identification & Authentication (IA) | IA-8 | Non-organizational user identification: external partner federation via SAML/OIDC, guest account lifecycle |
| Identification & Authentication (IA) | IA-12 | Identity proofing for high-assurance accounts aligning to NIST SP 800-63A IAL2/IAL3 requirements |
| Audit and Accountability (AU) | AU-2, AU-12 | Audit logging of authentication events, privilege use, account changes; SIEM ingestion of identity logs for anomaly detection |
| Personnel Security (PS) | PS-4, PS-5 | Timely account termination on separation; access transfer on role change; IGA workflow automation for HR-triggered events |
| Configuration Management (CM) | CM-5, CM-11 | Privileged access for change management; least privilege enforcement for software installation and configuration changes |
| System and Services Acquisition (SA) | SA-9 | External information system services: third-party identity federation governance, SaaS OAuth application registration controls |

---

## ATT&CK Techniques & Mitigations

### High-Priority Techniques to Detect/Prevent

| Technique | Description | IAM Control |
|---|---|---|
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | MFA, anomaly detection, just-in-time access |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Account lockout, rate limiting, MFA |
| [T1556](https://attack.mitre.org/techniques/T1556/) | Modify Authentication Process | Integrity monitoring on auth providers |
| [T1621](https://attack.mitre.org/techniques/T1621/) | MFA Request Generation (fatigue) | Number matching, phishing-resistant MFA |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Privileged account monitoring, JML process |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | Token binding, conditional access |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal/Forge Kerberos Tickets | Kerberoasting detection, tiered AD model |
| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Guard, LAPS, PAM |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Account creation alerting, IGA governance |

### Navigator Layer
Load the [Identity & Access Stage Layer](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/stages/stage2_identity_access.json) in ATT&CK Navigator.

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [SC-300](https://learn.microsoft.com/en-us/certifications/identity-and-access-administrator/) | Microsoft | Microsoft Identity and Access Administrator — Entra ID, Conditional Access, MFA, external identities, application access; free preparation materials on Microsoft Learn |
| [GIAC GPEN](https://www.giac.org/certifications/penetration-tester-gpen/) | GIAC | Includes AD/Kerberos attack techniques; valuable for IAM defenders who need to understand the attack perspective |
| [CyberArk Trustee / Defender](https://www.cyberark.com/services/training-certification/) | CyberArk | PAM practitioner certifications for CyberArk platform administration and security design |
| [Okta Certified Professional](https://www.okta.com/learning/certification/) | Okta | Okta platform implementation covering SSO, MFA, lifecycle management, and API access management |
| [CISSP](https://www.isc2.org/Certifications/CISSP) | ISC2 | Domain 5: Identity and Access Management covers IAM architecture, access control models, and identity federation at a strategic level |
| [CIAM](https://www.iapp.org/) | IAPP | Customer identity and privacy; covers GDPR and privacy-by-design considerations for customer-facing identity systems |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Microsoft Entra ID Documentation](https://learn.microsoft.com/en-us/entra/identity/) | Reference | Comprehensive cloud IAM docs |
| [BloodHound Documentation](https://support.bloodhoundenterprise.io/) | Reference | AD attack path concepts |
| [SpecterOps Posts](https://specterops.io/blog/) | Blog | Deep AD/identity attack research |
| [NIST 800-207 Zero Trust](https://csrc.nist.gov/publications/detail/sp/800-207/final) | Framework | Zero trust architecture for IAM |
| [The Hacker Recipes — AD](https://www.thehacker.recipes/ad/) | Reference | AD attack technique walkthroughs (defensive awareness) |
| [OpenSecurityTraining2](https://p.ost2.fyi/) | Free course | Architecture 1001: PC Internals includes auth |
| [CyberArk Identity Security Blueprint](https://www.cyberark.com/resources/blueprint/) | Framework | Structured approach to building a privileged access management program from initial deployment to mature zero trust |
| [SailPoint Identity Library](https://www.sailpoint.com/identity-library/) | Reference | Free practitioner resources on IGA program design, access certification best practices, and identity governance maturity |

---

---

#### Identity Attack Techniques

**Credential-Based Attacks**
- Password spraying: Low-and-slow against many accounts (avoid lockout); `ruler --brute --users users.txt --passwords passwords.txt`; target Office 365, VPN, Citrix
- Credential stuffing: Reuse credentials from breached databases (Have I Been Pwned API for detection)
- MFA fatigue: Bombard with push notifications until user approves; Scattered Spider/Lapsus$ primary TTPs
- AiTM (Adversary-in-the-Middle): Evilginx3 captures session token post-MFA — bypasses all TOTP/push MFA
- Device code phishing: Abuse OAuth device authorization flow — user enters code at login.microsoftonline.com/devicelogin; attacker gets token

**Privilege Escalation via IAM**
- AWS: `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, `iam:PassRole` + Lambda create → admin
- Azure: App Registration with Directory.ReadWrite.All; Service Principal with Contributor; adding self to Global Admin via Graph API with right permissions
- Cross-account: Overly permissive assume-role trust policies allow any account to escalate

#### PAM (Privileged Access Management)

**PAM Architecture Components**
- Vault: Encrypted credential store; check-out/check-in workflow; automatic password rotation
- Session manager: Broker privileged sessions; proxy connections; record full session video/keystrokes
- Just-in-time (JIT) access: Provision privileged access on-demand with approval workflow; auto-deprovision
- Dual control: Require two-person authorization for most sensitive actions
- Command filtering: Allow/deny specific commands in privileged sessions

**PAM Products**

| Product | Tier | Notes |
|---|---|---|
| CyberArk PAS/EPM | Enterprise | Market leader; most comprehensive; expensive |
| BeyondTrust Password Safe + Privilege Management | Enterprise | Strong for Windows environments |
| Delinea Secret Server | Mid-market | Formerly Thycotic; good UX |
| HashiCorp Vault | OSS/Enterprise | Developer-friendly; dynamic secrets; API-first |
| Teleport | OSS/Enterprise | Modern PAM for cloud/K8s; certificate-based access |

#### Zero Trust Identity Implementation

**Identity-Centric Zero Trust Controls**
- Strong authentication: Phishing-resistant MFA (FIDO2/WebAuthn, PIV/CAC smart cards) — not TOTP or push
- Continuous evaluation: Re-evaluate risk mid-session (sign-in frequency policies, continuous access evaluation)
- Device posture: Require managed, compliant device for access to sensitive resources
- Risk-based conditional access: Block sign-ins from risky locations/IPs/devices automatically
- Privileged access workstation (PAW): Dedicated hardened device for admin tasks only

**Phishing-Resistant MFA Methods**

| Method | Standard | Phishing Resistant | Notes |
|---|---|---|---|
| FIDO2/WebAuthn | W3C + FIDO Alliance | Yes | Hardware keys (YubiKey, Titan) or platform authenticators (Windows Hello, Face ID) |
| PIV/CAC Smart Card | NIST SP 800-73 | Yes | US federal standard; certificate-based |
| Passkeys | FIDO2 | Yes | Passwordless evolution of FIDO2; synced across devices |
| TOTP (Google Authenticator) | RFC 6238 | No | AiTM attacks steal the time-based token |
| Push notification (Duo, Okta Verify) | Vendor | No | MFA fatigue attacks; AiTM attacks |
| SMS | Telco | No | SIM swapping; SS7 interception |

#### IAM Governance

**Access Certification (Access Reviews)**
- Quarterly access reviews: Manager reviews reports' access; approve or revoke
- Certification tools: SailPoint IdentityNow, Saviynt, Omada — automate review campaigns
- Trigger: User role change, departure, 90-day tenure, sensitive data access

**Identity Governance and Administration (IGA)**
- Joiner-Mover-Leaver (JML) process: Automate account lifecycle
  - Joiner: Provision based on HR system (Workday/SAP/BambooHR) — right access from Day 1
  - Mover: Re-provision on role change; remove old access; provisioning new access
  - Leaver: Disable accounts within hours of termination; start 90-day retention before deletion

**SCIM (System for Cross-domain Identity Management)**
- Standard protocol for automating user provisioning between IdP and SaaS apps
- Eliminates manual account creation; real-time deprovisioning on departure
- Supported by: Okta, Azure AD, most major SaaS (Salesforce, GitHub, Slack, Zoom, Snowflake)

---

## Related Disciplines

- [security-architecture.md](security-architecture.md) — Zero trust design, identity-aware access
- [detection-engineering.md](detection-engineering.md) — Detecting credential-based attacks; identity threat detection requires SIEM rules for Kerberoasting, golden ticket use, anomalous authentication patterns, and privilege escalation chains that detection engineers build using IAM log sources
- [governance-risk-compliance.md](governance-risk-compliance.md) — Access reviews, SOX/HIPAA controls; IGA programs are the operational mechanism for meeting access control requirements in SOX, HIPAA, PCI DSS, and FedRAMP compliance frameworks
- [cryptography-pki.md](cryptography-pki.md) — Certificate-based auth, smart cards; PKI underpins phishing-resistant MFA (smart cards, FIDO2), mutual TLS for service-to-service authentication, and code signing for software supply chain integrity
- [cloud-security.md](cloud-security.md) — Cloud IAM is a distinct and critical subdiscipline: AWS IAM, Azure Entra ID Conditional Access, and GCP Workload Identity are the access control planes that CIEM tools analyze and cloud security practitioners must master
- [threat-intelligence.md](threat-intelligence.md) — Identity-targeted threat actors and campaigns (credential phishing, AiTM attacks, MFA fatigue campaigns) require CTI context to understand current adversary tradecraft and prioritize which authentication controls to harden first
- [incident-response.md](incident-response.md) — Identity compromise is the most common initial access and lateral movement vector; IR teams depend on IAM teams to reset credentials, revoke tokens, and implement emergency access controls during active incidents
- [Enterprise Security Pipeline](../SECURITY_PIPELINE.md) — Stage 2: Identity & Access
