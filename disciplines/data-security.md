# Data Security

> Protecting data throughout its lifecycle — at rest, in transit, and in use — through classification, encryption, access controls, data loss prevention, and posture management.

## What Data Security Engineers Do

- Design and implement data classification frameworks and label policies
- Deploy and tune Data Loss Prevention (DLP) controls across endpoints, email, and cloud
- Manage encryption at rest and in transit: key management, KMS, field-level encryption
- Implement Data Security Posture Management (DSPM) to discover and classify sensitive data across cloud stores
- Operate database security controls: DAM (Database Activity Monitoring), masking, tokenization
- Define and enforce data retention, deletion, and archival policies
- Respond to data breach incidents: scope PII exposure, notify per breach notification laws
- Manage rights management (IRM/DRM) for sensitive documents

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [NIST SP 800-53 MP/SC families](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) | Media Protection and System/Communications Protection |
| [NIST SP 800-111](https://csrc.nist.gov/publications/detail/sp/800-111/final) | Guide to Storage Encryption for End User Devices |
| [NIST SP 800-188](https://csrc.nist.gov/publications/detail/sp/800-188/final) | De-Identification of Government Datasets |
| [PCI DSS](https://www.pcisecuritystandards.org/) | Payment card data protection |
| [GDPR Article 32](https://gdpr.eu/article-32-security-of-processing/) | Technical measures for data protection |
| [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html) | PHI protection requirements |
| [ISO/IEC 27001 Annex A.8](https://www.iso.org/standard/27001) | Asset management and data classification |

---

## Free & Open-Source Tools

### Data Discovery & Classification

| Tool | Purpose | Notes |
|---|---|---|
| [Microsoft Presidio](https://github.com/microsoft/presidio) | PII detection and anonymization | 50+ entity types; Python/REST API |
| [Privado](https://github.com/Privado-Inc/privado) | Code-level PII data flow scanner | Traces PII through source code |
| [Apache Atlas](https://atlas.apache.org/) | Data catalog and governance | Metadata management for Hadoop ecosystems |
| [OpenMetadata](https://open-metadata.org/) | Modern data catalog | Data lineage, classification, quality |

### Encryption & Key Management

| Tool | Purpose | Notes |
|---|---|---|
| [HashiCorp Vault](https://www.vaultproject.io/) | Secrets + encryption-as-a-service | Transit secrets engine for app-layer encryption |
| [OpenSSL](https://openssl.org/) | Cryptographic operations | File/stream encryption, key generation |
| [GnuPG](https://gnupg.org/) | File and email encryption | OpenPGP standard |
| [age](https://github.com/FiloSottile/age) | Modern file encryption | Simple, audited; replaces GPG for files |
| [Tink](https://github.com/google/tink) | Crypto library | Google; safe-by-default crypto primitives |

### DLP & Monitoring

| Tool | Purpose | Notes |
|---|---|---|
| [OpenDLP](https://github.com/ezarko/opendlp) | Agent-based DLP scanner | Scans endpoints for sensitive data patterns |
| [Nightfall](https://nightfall.ai/) | Cloud DLP API | SaaS; detects PII in cloud apps |
| [Wazuh](https://wazuh.com/) | FIM + data monitoring | File integrity monitoring; detects data changes |

### Database Security

| Tool | Purpose | Notes |
|---|---|---|
| [pgaudit](https://www.pgaudit.org/) | PostgreSQL audit logging | Session + object-level audit |
| [MySQL Enterprise Audit](https://www.mysql.com/products/enterprise/audit.html) | MySQL audit plugin | Activity monitoring |
| [Faker / Mimesis](https://faker.readthedocs.io/) | Synthetic data for masking | Replace production PII in dev/test |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [Microsoft Purview](https://www.microsoft.com/en-us/security/business/microsoft-purview) | DLP + classification + compliance | Native M365 integration; sensitivity labels |
| [Varonis](https://www.varonis.com/) | DSPM + DAM + DLP | Deep on-prem + cloud data visibility |
| [BigID](https://bigid.com/) | DSPM + privacy + data catalog | ML-driven PII discovery |
| [Normalyze](https://normalyze.ai/) | Cloud DSPM | Agentless cloud data discovery |
| [Forcepoint DLP](https://www.forcepoint.com/product/dlp) | Enterprise DLP | Endpoint + email + cloud |
| [Symantec DLP (Broadcom)](https://www.broadcom.com/products/cybersecurity/information-protection/data-loss-prevention) | Enterprise DLP | Legacy market leader |
| [Netskope](https://www.netskope.com/) | CASB + DLP | Cloud-delivered; real-time inspection |
| [Thales CipherTrust](https://cpl.thalesgroup.com/encryption/ciphertrust-platform) | Enterprise KMS + encryption | HSM-backed key management |
| [IBM Guardium](https://www.ibm.com/products/ibm-guardium) | DAM + compliance | Database activity monitoring at scale |
| [Rubrik Security Cloud](https://www.rubrik.com/solutions/cyber-recovery) | Backup + data security | Ransomware recovery + data classification |

---

## Data Classification Reference

### Typical Classification Tiers

| Level | Examples | Controls |
|---|---|---|
| **Public** | Marketing materials, press releases | No restrictions |
| **Internal** | Internal wikis, general business docs | Employee access only |
| **Confidential** | Business plans, contracts, HR data | Need-to-know, encrypted in transit |
| **Restricted** | PII, PHI, PCI data, trade secrets | Encrypted at rest + in transit, strict access, DLP |
| **Top Secret** | M&A data, key material, source code | Isolated systems, PAM, full audit |

### Common Sensitive Data Types

| Type | Regulation | Detection Pattern |
|---|---|---|
| Social Security Numbers | HIPAA, state laws | \d{3}-\d{2}-\d{4} |
| Credit Card Numbers | PCI DSS | Luhn algorithm, 13-19 digits |
| Protected Health Information (PHI) | HIPAA | Name + medical context |
| EU Personal Data | GDPR | Name, email, IP, location |
| Passport / National ID | Various | Country-specific patterns |
| Bank Account / Routing | GLBA, PCI | ABA routing, IBAN |

---

## ATT&CK Coverage

Data security controls directly address:

- **T1530** — Data from Cloud Storage (DSPM, CASB, bucket policy enforcement)
- **T1552** — Unsecured Credentials (KMS, Vault, secrets scanning)
- **T1005** — Data from Local System (DLP endpoint agents)
- **T1039** — Data from Network Shared Drive (DLP, access monitoring)
- **T1048** — Exfiltration Over Alt Protocol (DLP network inspection)
- **T1537** — Transfer Data to Cloud Account (CASB, egress monitoring)
- **T1213** — Data from Information Repositories (DAM, SharePoint DLP)

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [CDPSE](https://www.isaca.org/credentialing/cdpse) | ISACA | Certified Data Privacy Solutions Engineer |
| [CIPT](https://iapp.org/certify/cipt/) | IAPP | Privacy technologist — data handling |
| [CompTIA Security+](https://www.comptia.org/certifications/security) | CompTIA | Encryption and data protection fundamentals |
| [CISSP](https://www.isc2.org/Certifications/CISSP) | ISC2 | Domain 2: Asset Security (data classification) |
| [Microsoft SC-400](https://learn.microsoft.com/en-us/certifications/information-protection-administrator/) | Microsoft | Microsoft Purview / Information Protection |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Microsoft Purview Documentation](https://learn.microsoft.com/en-us/purview/) | Reference | DLP, sensitivity labels, compliance portal |
| [NIST Cybersecurity Framework — Protect](https://www.nist.gov/cyberframework) | Framework | Data security is core to the Protect function |
| [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | Reference | Application-layer encryption best practices |
| [Cloud Security Alliance STAR](https://cloudsecurityalliance.org/star/) | Registry | Cloud provider security and data controls |
| [ENISA Data Protection Guidelines](https://www.enisa.europa.eu/topics/data-protection) | Reference | EU agency data protection technical guides |

---

## Related Disciplines

- [Privacy Engineering](privacy-engineering.md) — PII minimization, consent, DSR workflows
- [Cryptography & PKI](cryptography-pki.md) — Encryption algorithms, key management, HSMs
- [Cloud Security](cloud-security.md) — Cloud storage security, CSPM, DSPM
- [Governance, Risk & Compliance](governance-risk-compliance.md) — Data governance, regulatory compliance
- [Supply Chain Security](supply-chain-security.md) — SBOM, third-party data handling
