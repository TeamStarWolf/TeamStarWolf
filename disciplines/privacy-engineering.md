# Privacy Engineering

> Designing systems that minimize data collection, enforce consent, and protect personal information — building privacy in, not bolting it on.

## What Privacy Engineers Do

- Conduct Privacy Impact Assessments (PIAs) and Data Protection Impact Assessments (DPIAs)
- Implement privacy-by-design patterns (data minimization, purpose limitation, storage limits)
- Build and maintain data maps and records of processing activities (RoPA)
- Implement consent management platforms and preference centers
- Design and automate Data Subject Rights (DSR) workflows: access, deletion, portability
- Evaluate and remediate PII handling in code, APIs, and data pipelines
- Implement technical controls for GDPR, CCPA/CPRA, HIPAA, and other regulations
- Conduct vendor privacy assessments and data processing agreement reviews
- Implement data anonymization, pseudonymization, and synthetic data techniques

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [NIST Privacy Framework 1.0](https://www.nist.gov/privacy-framework/privacy-framework) | Identify-Govern-Control-Communicate-Protect |
| [ISO/IEC 29101](https://www.iso.org/standard/45269.html) | Privacy Architecture Framework |
| [ISO/IEC 27701](https://www.iso.org/standard/71670.html) | Privacy Information Management (extends ISO 27001) |
| [GDPR (EU 2016/679)](https://gdpr.eu/) | EU General Data Protection Regulation |
| [CCPA/CPRA](https://oag.ca.gov/privacy/ccpa) | California Consumer Privacy Act |
| [NIST SP 800-188](https://csrc.nist.gov/publications/detail/sp/800-188/final) | De-Identification of Government Datasets |
| [LINDDUN](https://linddun.org/) | Privacy threat modeling framework |

---

## Free & Open-Source Tools

### PII Detection & Data Discovery

| Tool | Purpose | Notes |
|---|---|---|
| [Microsoft Presidio](https://github.com/microsoft/presidio) | PII detection and anonymization | 50+ entity types; Python/REST API |
| [spaCy](https://spacy.io/) | NLP for custom PII entity detection | Build custom NER models |
| [Faker](https://faker.readthedocs.io/) | Synthetic data generation | Replace PII in test data |
| [Mimesis](https://github.com/lk-geimfari/mimesis) | High-performance synthetic data | Alternative to Faker |
| [Tonic.ai (community)](https://www.tonic.ai/) | Synthetic data for dev/test | Freemium; structured data synthesis |

### Anonymization & De-identification

| Tool | Purpose | Notes |
|---|---|---|
| [ARX Data Anonymization Tool](https://arx.deidentifier.org/) | k-anonymity, l-diversity, t-closeness | GUI + Java API; research-grade |
| [sdcMicro (R)](https://sdctools.github.io/sdcMicro/) | Statistical disclosure control | R package; survey microdata |
| [Google Differential Privacy](https://github.com/google/differential-privacy) | Differential privacy libraries | C++/Go/Java; proven DP algorithms |
| [OpenDP](https://opendp.org/) | Differential privacy toolkit | Python; Harvard-maintained |
| [Tumult Analytics](https://tmlt.dev/) | DP for data analytics | Python API for differential privacy |

### Consent & Preference Management

| Tool | Purpose | Notes |
|---|---|---|
| [Consent2Share (ONC)](https://bhits.github.io/consent2share/) | Healthcare consent management | HL7/FHIR-based; open source |
| [Open Notice (CIPL)](https://www.informationpolicycentre.com/) | Consent notice standards | Framework for consent UX |

### Policy & Compliance Tooling

| Tool | Purpose | Notes |
|---|---|---|
| [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) | Policy-as-code for data access | Rego-based; enforce data policies |
| [Privado](https://github.com/Privado-Inc/privado) | Code-level PII data flow scanner | Traces PII through source code |
| [Nightfall](https://nightfall.ai/) | DLP + PII detection API | Cloud-native; Freemium available |

---

## Commercial Platforms

| Vendor | Capability | Notes |
|---|---|---|
| [OneTrust](https://onetrust.com/) | Privacy management platform | PIAs, DSRs, consent, RoPA |
| [BigID](https://bigid.com/) | Data discovery and intelligence | ML-driven PII discovery across all data stores |
| [Immuta](https://immuta.com/) | Data access governance | Attribute-based access control for data platforms |
| [Collibra](https://collibra.com/) | Data governance + catalog | Lineage, glossary, policy management |
| [Informatica CDGC](https://www.informatica.com/) | Cloud data governance | Metadata management + privacy |
| [Securiti](https://securiti.ai/) | Privacy ops + data security | DSR automation; data catalog |
| [TrustArc](https://trustarc.com/) | Privacy compliance management | Assessments, consent, vendor management |
| [Osano](https://osano.com/) | Consent + privacy monitoring | SMB-friendly; cookie consent |

---

## Privacy-by-Design Patterns

### Data Minimization Checklist

```
□ Collect only data necessary for the stated purpose
□ Set retention periods; implement automated deletion
□ Separate PII from analytics data at collection time
□ Use surrogate keys / pseudonymization in data pipelines
□ Implement field-level encryption for sensitive attributes
□ Tokenize PII before sending to third-party systems
□ Replace PII with synthetic data in dev/test environments
```

### LINDDUN Threat Categories

| Threat | Description | Mitigation |
|---|---|---|
| **L**inkability | Linking records across contexts | k-anonymity, differential privacy |
| **I**dentifiability | Identifying individuals from data | De-identification, pseudonymization |
| **N**on-repudiation | Users can't deny actions | Minimize audit logging of PII |
| **D**etectability | Inferring existence of data | Traffic analysis countermeasures |
| **D**isclosure | Unauthorized data exposure | Encryption, access controls |
| **U**nawareness | Users unaware of data use | Consent notices, transparency |
| **N**on-compliance | Regulatory violations | PIAs, DPIAs, policy automation |

---

## Regulatory Quick Reference

| Regulation | Jurisdiction | Key Requirements |
|---|---|---|
| GDPR | EU/EEA | Lawful basis, consent, DSRs, DPIAs, 72hr breach notification |
| CCPA/CPRA | California | Right to know, delete, opt-out of sale; sensitive data opt-in |
| HIPAA | US (healthcare) | PHI safeguards, BAAs, breach notification |
| PIPEDA / Law 25 | Canada / Quebec | Consent, breach notification, privacy officer |
| LGPD | Brazil | Similar to GDPR; DPA enforcement |
| PDPA | Singapore/Thailand | Consent, purpose limitation, data transfer rules |
| APRA CPS 234 | Australia | Information security for financial services |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [CIPP/E](https://iapp.org/certify/cipp/europe/) | IAPP | Certified Information Privacy Professional – Europe (GDPR) |
| [CIPP/US](https://iapp.org/certify/cipp/us/) | IAPP | CIPP – United States (CCPA, HIPAA, etc.) |
| [CIPT](https://iapp.org/certify/cipt/) | IAPP | Certified Information Privacy Technologist (engineering focus) |
| [CIPM](https://iapp.org/certify/cipm/) | IAPP | Certified Information Privacy Manager |
| [FIP](https://iapp.org/certify/fip/) | IAPP | Fellow of Information Privacy |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [IAPP Privacy Engineering Microsite](https://iapp.org/resources/article/privacy-engineering/) | Reference | IAPP privacy engineering resources |
| [NIST Privacy Framework](https://www.nist.gov/privacy-framework) | Framework | Free download; profiles and implementation guides |
| [Privacypatterns.eu](https://privacypatterns.eu/) | Pattern library | Design patterns for privacy |
| [ENISA Privacy and Data Protection by Design](https://www.enisa.europa.eu/publications/privacy-and-data-protection-by-design) | Guide | EU Agency technical guide |
| [The Privacy Engineer's Manifesto](https://link.springer.com/book/10.1007/978-1-4302-6356-2) | Book | Foundational privacy engineering text |
| [Differential Privacy: A Primer](https://differentialprivacy.org/a-primer/) | Tutorial | Accessible intro to differential privacy |

---

## Related Disciplines

- [Governance, Risk & Compliance](governance-risk-compliance.md) — GDPR program management, DPIAs
- [Data Security](data-security.md) — Encryption, DLP, data classification
- [Security Architecture](security-architecture.md) — Privacy-by-design in system design
- [Cloud Security](cloud-security.md) — Cloud data residency and sovereignty
