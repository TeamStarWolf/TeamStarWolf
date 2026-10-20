<!-- hub:start (written by scripts/build_site_nav.py from docs/site_nav.json; do not edit) -->

# Identity and data protection

> Identity and access, Active Directory, passwords, zero trust, cryptography, and protecting and governing data.

Part of the [domain hubs](/hubs/README.md). 10 reference documents in this domain; reading time is the page's words at 230 words a minute.

## Identity and access

| Reference | What it covers | Reading time |
|---|---|---|
| [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md) | IAM, PAM, MFA bypass techniques, AD attacks, Okta/Entra/CyberArk/Vault vendor controls, identity detection | 15 min |
| [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) | FIDO2/WebAuthn, RBAC/ABAC/ReBAC, Entra ID/Okta/CyberArk/Vault, JIT/PAM, SCIM, SPIFFE, Zero Trust identity, IGA | 13 min |
| [Active Directory Security Reference](/ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) | AD architecture, Kerberos attacks (Kerberoasting/Golden Ticket/DCSync), AD CS ESC vulnerabilities, GPO hardening, tiered admin model, MDI detection | 33 min |
| [Password Security Reference](/PASSWORD_SECURITY_REFERENCE.md) | Hash formats, hashcat/John mastery, Argon2/bcrypt/PBKDF2 storage, NIST 800-63B policy, LAPS, gMSA, HIBP API | 14 min |
| [Zero Trust Reference](/ZERO_TRUST_REFERENCE.md) | NIST SP 800-207, CISA ZTMM v2.0, identity/device/network/data pillars, ZTNA, micro-segmentation, and implementation roadmap | 37 min |

## Cryptography and data

| Reference | What it covers | Reading time |
|---|---|---|
| [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md) | Cryptographic concepts, algorithms, attacks, and best practices | 38 min |
| [Post-Quantum Migration Reference](/POST_QUANTUM_MIGRATION_REFERENCE.md) | Harvest-now-decrypt-later risk, FIPS 203/204/205, NIST IR 8547 timelines, CNSA 2.0, CBOM discovery, crypto-agility, hybrid TLS/SSH deployment, PKI impact, program governance | 26 min |
| [Data Security Reference](/DATA_SECURITY_REFERENCE.md) | CSF 2.0 PR.DS, classification tiers and Purview sensitivity labels, DSPM discovery, DLP channels and false-positive economics, encryption at rest/in transit/in use, egress controls, SP 800-171r3/CMMC drivers, program metrics | 24 min |
| [Database Security](/DATABASE_SECURITY_REFERENCE.md) | DBMS hardening (SQL Server/PostgreSQL/MySQL/Oracle/MongoDB/Redis/Elasticsearch), Database Activity Monitoring, privileged DB access, encryption, audit | 13 min |
| [Privacy Engineering Reference](/PRIVACY_ENGINEERING_REFERENCE.md) | GDPR/CCPA/HIPAA, Privacy by Design, anonymization/pseudonymization, consent management, DPIA, field-level encryption | 19 min |

## Learning paths

- [Identity & Access Management](/disciplines/identity-access-management.md)
- [Active Directory Security](/disciplines/active-directory.md)
- [Zero Trust Architecture](/disciplines/zero-trust-architecture.md)
- [Cryptography & PKI](/disciplines/cryptography-pki.md)
- [Data Security](/disciplines/data-security.md)
- [Privacy Engineering](/disciplines/privacy-engineering.md)

## How-to guides

| Guide | Time | Level |
|---|---|---|
| [Roll Out Phishing-Resistant MFA and Conditional Access](/guides/ROLL_OUT_PHISHING_RESISTANT_MFA.md) | A week for the admin pilot | Intermediate-Advanced |

## See also

- [Active Directory attacks](/ACTIVE_DIRECTORY_ATTACKS.md)

<!-- hub:end -->
