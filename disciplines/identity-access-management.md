# Identity & Access Management

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

| Vendor | Capability | Notes |
|---|---|---|
| [Microsoft Entra ID](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id) | Cloud IAM + Conditional Access | Dominant in enterprise; integrates with M365 |
| [Okta](https://okta.com/) | Universal directory + SSO + MFA | Workforce and customer identity |
| [CyberArk](https://www.cyberark.com/) | PAM + secrets + endpoint privilege | Market leader in PAM |
| [BeyondTrust](https://www.beyondtrust.com/) | PAM + remote access | Strong in endpoint privilege management |
| [SailPoint](https://www.sailpoint.com/) | Identity governance | Access reviews, certifications, IGA |
| [Saviynt](https://saviynt.com/) | Cloud-native IGA | Converged IGA + PAM |
| [Ping Identity](https://www.pingidentity.com/) | Enterprise SSO + MFA | Strong federation capabilities |
| [Delinea](https://delinea.com/) | PAM (formerly Thycotic + Centrify) | Secret Server, Privilege Manager |

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
| [SC-300](https://learn.microsoft.com/en-us/certifications/identity-and-access-administrator/) | Microsoft | Microsoft Identity and Access Administrator |
| [GIAC GPEN](https://www.giac.org/certifications/penetration-tester-gpen/) | GIAC | Includes AD/Kerberos attack techniques |
| [CyberArk Trustee / Defender](https://www.cyberark.com/services/training-certification/) | CyberArk | PAM practitioner certs |
| [Okta Certified Professional](https://www.okta.com/learning/certification/) | Okta | Okta implementation |
| [CISSP](https://www.isc2.org/Certifications/CISSP) | ISC² | Domain 5: Identity and Access Management |
| [CIAM](https://www.iapp.org/) | IAPP | Customer identity and privacy |

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

---

## Related Disciplines

- [Security Architecture](security-architecture.md) — Zero trust design, identity-aware access
- [Detection Engineering](detection-engineering.md) — Detecting credential-based attacks
- [Governance, Risk & Compliance](governance-risk-compliance.md) — Access reviews, SOX/HIPAA controls
- [Cryptography & PKI](cryptography-pki.md) — Certificate-based auth, smart cards
- [Enterprise Security Pipeline](../SECURITY_PIPELINE.md) — Stage 2: Identity & Access
