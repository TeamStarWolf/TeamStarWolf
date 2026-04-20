# Data Security

> Protecting data throughout its lifecycle — at rest, in transit, and in use — through classification, encryption, access controls, data loss prevention, and posture management.

Data security is the set of technical and operational practices that ensure sensitive information is only accessible to authorized parties, remains unaltered by unauthorized processes, and is available when needed. As organizations migrate data to cloud platforms and third-party SaaS tools, the attack surface for data exposure has grown dramatically — a single misconfigured S3 bucket or overly permissive database role can expose millions of records. Data security engineers build the controls that prevent, detect, and respond to data breaches: they classify what matters, encrypt what is sensitive, monitor who touches what, and automate the deletion of data that should no longer exist. The discipline sits at the intersection of cryptography, identity, cloud architecture, and regulatory compliance, making it central to nearly every security program.

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

## Where to Start

| Stage | Focus | Resources |
|---|---|---|
| **Foundation** | Understand data classification tiers, encryption fundamentals (symmetric vs. asymmetric, AES, TLS), and regulatory drivers (GDPR, HIPAA, PCI DSS). Learn what DLP is and why it fails without classification. | [NIST SP 800-53 MP/SC families](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final), [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), CompTIA Security+ study materials, GDPR Article 32 text |
| **Practitioner** | Deploy and tune DLP policies in a lab environment. Practice key management with HashiCorp Vault. Run Microsoft Presidio against a sample dataset. Understand DSPM and how it differs from CSPM. Build a data classification policy from scratch. | [HashiCorp Vault tutorials](https://developer.hashicorp.com/vault/tutorials), [Microsoft Presidio](https://github.com/microsoft/presidio), [Microsoft Purview learning path](https://learn.microsoft.com/en-us/purview/), CDPSE exam prep materials |
| **Advanced** | Design enterprise-wide data governance programs. Integrate DSPM into cloud pipelines. Implement field-level encryption and tokenization in applications. Lead data breach response. Build a KMS strategy across multi-cloud. Evaluate DSPM/DAM vendors against requirements. | [NIST SP 800-188](https://csrc.nist.gov/publications/detail/sp/800-188/final) (de-identification), [Cloud Security Alliance research](https://cloudsecurityalliance.org/research/), Varonis/BigID vendor documentation, breach notification law matrix |

---

## Free Training

- [NIST SP 800-53 MP and SC Control Families](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — The authoritative federal control catalog; Media Protection (MP) and System and Communications Protection (SC) families map directly to data security requirements; reading the control baselines and supplemental guidance teaches the full scope of what data security programs must address
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) — Practical developer-facing guidance on how to encrypt data at the application layer; covers algorithm selection, key storage, IV handling, and common mistakes; essential for anyone implementing encryption in code rather than just configuring cloud services
- [Microsoft Learn — Information Protection and Governance](https://learn.microsoft.com/en-us/purview/information-protection) — Free Microsoft documentation covering sensitivity labels, DLP policy design, data classification, and the Microsoft Purview compliance portal; hands-on learning path available for the SC-400 certification
- [HashiCorp Vault Tutorials](https://developer.hashicorp.com/vault/tutorials) — Free interactive tutorials covering secrets management, encryption-as-a-service (Transit secrets engine), dynamic database credentials, and PKI; the best hands-on introduction to enterprise key management concepts
- [Microsoft Presidio Documentation and Notebooks](https://microsoft.github.io/presidio/) — Free documentation and Jupyter notebooks for the open-source PII detection and anonymization engine; teaches how PII recognition, NLP-based entity detection, and anonymization operators work in practice
- [GDPR Article 32 and Recital 83](https://gdpr.eu/article-32-security-of-processing/) — The actual legal text defining what "appropriate technical measures" means under EU law; understanding the regulatory driver is as important as knowing the controls; free to read at gdpr.eu
- [ENISA Guidelines on Pseudonymisation](https://www.enisa.europa.eu/publications/pseudonymisation-techniques-and-best-practices) — Free technical guide from the EU Agency for Cybersecurity covering pseudonymisation techniques, implementation patterns, and their limitations; directly applicable to GDPR Article 25 compliance
- [Google Cloud Data Loss Prevention Documentation](https://cloud.google.com/dlp/docs) — Free reference covering DLP concepts, info type detectors, de-identification transformations, and risk analysis; teaches DLP architecture patterns applicable to any platform, not just GCP
- [NIST SP 800-111: Storage Encryption for End User Devices](https://csrc.nist.gov/publications/detail/sp/800-111/final) — Free NIST guide on full-disk encryption, volume encryption, and file/folder encryption; explains the threat models that each approach addresses and which to use for which scenarios
- [PCI DSS Quick Reference Guide](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf) — Free condensed summary of PCI DSS requirements; Requirement 3 (protect stored cardholder data) and Requirement 4 (encrypt transmission) are the core data security requirements; useful for understanding how payment card data protection works

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

## Commercial & Enterprise Platforms

| Vendor | Capability | Strength |
|---|---|---|
| [Microsoft Purview](https://www.microsoft.com/en-us/security/business/microsoft-purview) | DLP + classification + compliance | Native M365 integration; sensitivity labels; best choice for Microsoft-heavy environments |
| [Varonis](https://www.varonis.com/) | DSPM + DAM + DLP | Deep on-prem + cloud data visibility; behavioral analytics on data access patterns |
| [BigID](https://bigid.com/) | DSPM + privacy + data catalog | ML-driven PII discovery across structured and unstructured data at scale |
| [Normalyze](https://normalyze.ai/) | Cloud DSPM | Agentless cloud data discovery; maps data flows and access paths |
| [Forcepoint DLP](https://www.forcepoint.com/product/dlp) | Enterprise DLP | Endpoint + email + cloud; behavior-based policy enforcement |
| [Symantec DLP (Broadcom)](https://www.broadcom.com/products/cybersecurity/information-protection/data-loss-prevention) | Enterprise DLP | Legacy market leader; deep content inspection across all channels |
| [Netskope](https://www.netskope.com/) | CASB + DLP | Cloud-delivered; real-time inspection of SaaS and cloud traffic |
| [Thales CipherTrust](https://cpl.thalesgroup.com/encryption/ciphertrust-platform) | Enterprise KMS + encryption | HSM-backed key management; tokenization; transparent data encryption |
| [IBM Guardium](https://www.ibm.com/products/ibm-guardium) | DAM + compliance | Database activity monitoring at scale; real-time policy enforcement |
| [Rubrik Security Cloud](https://www.rubrik.com/solutions/cyber-recovery) | Backup + data security | Ransomware recovery + data classification; immutable backup architecture |

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

## NIST 800-53 Control Alignment

| Control Family | Control ID | Control Name | Data Security Relevance |
|---|---|---|---|
| Media Protection | MP-2 | Media Access | Restricts access to digital and physical media containing sensitive data; foundational for preventing unauthorized data extraction |
| Media Protection | MP-5 | Media Transport | Requires encryption and chain-of-custody for data transported on removable media; prevents data exposure during physical transfer |
| Media Protection | MP-6 | Media Sanitization | Defines how storage media must be wiped or destroyed before disposal; prevents data recovery from decommissioned hardware |
| System & Comms Protection | SC-8 | Transmission Confidentiality | Requires cryptographic protection of data in transit; the technical basis for TLS enforcement and VPN requirements |
| System & Comms Protection | SC-28 | Protection of Information at Rest | Requires cryptographic protection of sensitive data stored on systems; the control basis for full-disk and database encryption requirements |
| System & Comms Protection | SC-12 | Cryptographic Key Establishment | Governs key generation, distribution, storage, and destruction; the control framework for KMS and HSM deployment |
| Identification & Auth | IA-5 | Authenticator Management | Covers credential protection; authenticator data (passwords, keys, certs) is among the most sensitive data a system stores |
| Audit & Accountability | AU-9 | Protection of Audit Information | Audit logs contain sensitive user activity data; this control prevents tampering and unauthorized access to audit records |
| Risk Assessment | RA-7 | Risk Response | Requires timely response to identified data security risks; drives the prioritization of remediation in DSPM findings |
| Incident Response | IR-6 | Incident Reporting | Mandates breach notification procedures; data security programs must have defined processes to scope and report data exposure incidents |

---

## ATT&CK Coverage

Data security controls directly address the following MITRE ATT&CK techniques:

| Technique | ID | How Data Security Addresses It |
|---|---|---|
| Data from Cloud Storage | T1530 | DSPM continuously discovers and classifies cloud storage; CASB enforces bucket/container policies; alerts on unexpected access to sensitive data stores |
| Unsecured Credentials | T1552 | KMS and secrets management (Vault, AWS Secrets Manager) prevent credentials from being stored in plaintext; secrets scanning detects exposed keys in code and configs |
| Data from Local System | T1005 | DLP endpoint agents detect and block sensitive data reads; file-level encryption makes stolen data unreadable without the key |
| Data from Network Shared Drive | T1039 | DLP network inspection monitors SMB/NFS traffic; DAM detects bulk data reads from file servers; access controls limit who can mount shares |
| Exfiltration Over Alternative Protocol | T1048 | DLP network inspection detects data leaving on non-standard protocols (DNS, ICMP tunneling); egress filtering blocks exfiltration channels |
| Transfer Data to Cloud Account | T1537 | CASB monitors uploads to cloud storage services; DLP policies block or alert on large file uploads to unsanctioned destinations |
| Data from Information Repositories | T1213 | DAM monitors database query patterns; SharePoint/Confluence DLP detects bulk downloads from internal repositories; sensitivity labels restrict export |
| Data Encrypted for Impact | T1486 | Immutable backup architecture (Rubrik, Cohesity) enables recovery without paying ransom; data classification identifies which backups are highest priority for protection |
| Data Destruction | T1485 | Backup integrity monitoring detects unexpected deletions; write-once storage protects critical datasets from destruction by compromised accounts |

---

## Certifications

| Certification | Issuer | Who Should Pursue It | What It Covers |
|---|---|---|---|
| [CDPSE](https://www.isaca.org/credentialing/cdpse) | ISACA | Privacy engineers and data security engineers who work at the intersection of technical controls and regulatory compliance | Data governance, privacy architecture, data lifecycle management, and technical privacy engineering; one of the few certifications that bridges technical data handling and regulatory requirements |
| [CIPT](https://iapp.org/certify/cipt/) | IAPP | Software engineers, data engineers, and security engineers who handle PII | Privacy technologies, data flow mapping, PII in code, privacy-by-design patterns, and technical implementation of privacy controls; the most technical of the IAPP certifications |
| [CompTIA Security+](https://www.comptia.org/certifications/security) | CompTIA | Entry-level practitioners entering data security from a general IT background | Encryption fundamentals, PKI, data classification basics, and secure data handling; broad coverage but limited depth; useful as a baseline before specializing |
| [CISSP](https://www.isc2.org/Certifications/CISSP) | ISC2 | Experienced security professionals seeking broad validation with depth in data security | Domain 2 (Asset Security) covers data classification, ownership, retention, and protection requirements in depth; the governance-layer credential for senior data security roles |
| [Microsoft SC-400](https://learn.microsoft.com/en-us/certifications/information-protection-administrator/) | Microsoft | Security engineers working in Microsoft 365 and Azure environments | Microsoft Purview DLP, sensitivity labels, information barriers, insider risk management, and compliance portal administration; highly practical for Microsoft-centric organizations |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Microsoft Purview Documentation](https://learn.microsoft.com/en-us/purview/) | Reference | DLP, sensitivity labels, compliance portal; the most complete free documentation for a commercial data security platform |
| [NIST Cybersecurity Framework — Protect](https://www.nist.gov/cyberframework) | Framework | Data security is core to the Protect function; free download includes implementation tiers and profiles |
| [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | Reference | Application-layer encryption best practices; algorithm selection, key storage, and common implementation errors |
| [Cloud Security Alliance STAR](https://cloudsecurityalliance.org/star/) | Registry | Cloud provider security and data controls; the CCM (Cloud Controls Matrix) maps data security requirements to cloud provider capabilities |
| [ENISA Data Protection Guidelines](https://www.enisa.europa.eu/topics/data-protection) | Reference | EU agency data protection technical guides; free and authoritative for GDPR-aligned data security programs |
| [The Data Warehouse Toolkit (Kimball)](https://www.kimballgroup.com/) | Book | Foundational text for understanding how data is structured in analytics environments; essential context for data security engineers protecting analytics platforms |
| [NIST SP 800-188](https://csrc.nist.gov/publications/detail/sp/800-188/final) | Standard | De-identification of government datasets; the technical reference for anonymization techniques and their limitations |
| [Securosis Data Security Lifecycle](https://securosis.com/) | Research | Vendor-neutral research on data security architecture and cloud data protection; practitioner-focused and free |

---

## Related Disciplines

- [Privacy Engineering](privacy-engineering.md) — Data security provides the technical controls (encryption, DLP, access) that privacy engineering programs depend on to enforce consent, minimization, and DSR workflows; the two disciplines share tooling but have different regulatory drivers
- [Cryptography & PKI](cryptography-pki.md) — Encryption is the foundational data security control; understanding cipher modes, key derivation, certificate management, and HSMs is required to implement data-at-rest and data-in-transit protection correctly
- [Cloud Security](cloud-security.md) — Most sensitive data now lives in cloud storage, databases, and SaaS applications; cloud security controls (CSPM, CASB, IAM) are the enforcement layer for data security policies in cloud environments
- [Governance, Risk & Compliance](governance-risk-compliance.md) — Regulatory frameworks (GDPR, HIPAA, PCI DSS) define what data must be protected and how; GRC programs translate these requirements into the classification policies and control mandates that data security engineers implement
- [Supply Chain Security](supply-chain-security.md) — Third parties and software dependencies are frequent vectors for data exposure; SBOM analysis and vendor data processing agreements are data security responsibilities that connect to supply chain risk management
