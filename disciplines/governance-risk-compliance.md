# Governance, Risk & Compliance (GRC)

GRC is the backbone of every mature security program. Governance defines policies and accountability structures. Risk management identifies, assesses, and prioritizes threats to the business. Compliance maps those risks to regulatory and contractual obligations — NIST CSF, ISO 27001, SOC 2, HIPAA, PCI DSS, FedRAMP, and more. A GRC practitioner translates between the language of risk and the language of technical security controls, enabling the organization to make informed, documented decisions about acceptable risk.

---

## Where to Start

GRC is framework-heavy but fundamentally about communication and process. Start with NIST CSF because it is the most accessible entry point into the risk and controls world, then branch into whichever compliance frameworks your organization requires.

1. Read the [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) — free, authoritative, and widely adopted
2. Work through [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) to understand what security controls actually look like at depth
3. Practice with the [CISA Cyber Resilience Review (CRR)](https://www.cisa.gov/resources-tools/services/cyber-resilience-review) self-assessment
4. Explore [OpenRMF](https://github.com/Cingulara/openrmf-oss) to see how control frameworks are operationalized in practice
5. Use the [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) to map NIST 800-53 controls to ATT&CK techniques — this connects compliance to threat reality

---

## Free Training

| Resource | What You Learn |
|---|---|
| [NIST CSF 2.0 Learning Resources](https://www.nist.gov/cyberframework/getting-started) | Official NIST learning path for the Cybersecurity Framework |
| [CISA Free Training Catalog](https://niccs.cisa.gov/training/catalog) | Federal GRC, risk assessment, and compliance training — free to the public |
| [ISACA GRC Fundamentals (free articles)](https://www.isaca.org/resources/isaca-journal) | Practitioner articles covering GRC concepts, audit, and risk management |
| [CompTIA Security+ Study Content](https://www.comptia.org/certifications/security) | Risk management and compliance concepts foundational to GRC |
| [ISO 27001 Toolkit Preview — IT Governance](https://www.itgovernance.co.uk/iso27001) | ISO 27001 overview and free implementation resources |
| [SOC 2 Academy — Thoropass](https://thoropass.com/learn/) | Free SOC 2 fundamentals, trust service criteria, and audit prep |
| [NIST Risk Management Framework (RMF) Course](https://csrc.nist.gov/projects/risk-management/rmf-overview) | Full RMF lifecycle: Categorize, Select, Implement, Assess, Authorize, Monitor |
| [FedRAMP Training](https://www.fedramp.gov/training/) | Cloud compliance in the federal context |

---

## Tools & Repositories

| Tool | Purpose | Link |
|---|---|---|
| **OpenRMF** | Open-source RMF compliance automation and STIG tracking | [Cingulara/openrmf-oss](https://github.com/Cingulara/openrmf-oss) |
| **OSCAL** | NIST Open Security Controls Assessment Language — machine-readable compliance data | [usnistgov/OSCAL](https://github.com/usnistgov/OSCAL) |
| **ComplianceAsCode / SCAP Security Guide** | SCAP content and security baselines for automated compliance checking | [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) |
| **CTID Mappings Explorer** | Maps NIST 800-53, CSA CCM, CIS Controls → ATT&CK techniques | [mappings-explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) |
| **Wazuh** | Open-source SIEM with built-in PCI DSS, HIPAA, GDPR, NIST compliance dashboards | [wazuh/wazuh](https://github.com/wazuh/wazuh) |
| **CIS-CAT Lite** | Free CIS Benchmark assessment tool — scores system configs against CIS controls | [CIS Downloads](https://www.cisecurity.org/cybersecurity-tools/cis-cat-lite) |
| **MITRE ATT&CK Navigator** | Map controls and coverage across ATT&CK techniques | [mitre-attack/attack-navigator](https://github.com/mitre-attack/attack-navigator) |
| **py-erm** | Python enterprise risk modeling library | [ermsec/py-erm](https://github.com/ermsec/py-erm) |
| **GovReady-Q** | Open-source compliance-as-code platform built on OSCAL | [GovReady/govready-q](https://github.com/GovReady/govready-q) |

---

## Commercial & Enterprise Platforms

| Platform | Category | Key Capabilities |
|---|---|---|
| **ServiceNow GRC** | Integrated Risk Management | Policy lifecycle, risk registers, third-party risk, audit management — deeply integrated with IT operations |
| **RSA Archer** | GRC Platform | Risk management, compliance workflows, vendor risk, BCM — widely deployed in regulated industries |
| **MetricStream** | GRC / IRM | Enterprise risk, audit management, regulatory compliance, ESG reporting |
| **OneTrust** | Privacy & GRC | Privacy program management, DPIA/PIA, consent management, third-party risk, ESG |
| **Archer/IBM OpenPages** | Financial Risk & GRC | Operational risk, financial regulatory compliance (Basel, SOX), audit |
| **Diligent (formerly BoardEffect)** | Board & ESG Reporting | Board-level governance, ESG metrics, executive risk reporting |
| **Tugboat Logic / OneTrust Trust Center** | Security Posture / Compliance | Automated evidence collection for SOC 2, ISO 27001, HIPAA |
| **Drata** | Continuous Compliance Automation | Automated SOC 2, ISO 27001, HIPAA, GDPR, PCI DSS monitoring and evidence collection |
| **Vanta** | Compliance Automation | Continuous compliance monitoring, automated control testing, trust center |
| **Hyperproof** | Compliance Operations | Multi-framework compliance management, control mapping, audit readiness |

---

## Frameworks & Standards Reference

| Framework | Use Case | Link |
|---|---|---|
| **NIST CSF 2.0** | Universal risk-based cybersecurity framework | [nist.gov/cyberframework](https://www.nist.gov/cyberframework) |
| **NIST SP 800-53 Rev 5** | Federal and enterprise security controls catalog | [csrc.nist.gov](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) |
| **NIST RMF** | Risk Management Framework — categorize through monitor | [csrc.nist.gov/projects/risk-management](https://csrc.nist.gov/projects/risk-management) |
| **ISO/IEC 27001:2022** | ISMS certification standard — global | [iso.org/standard/27001](https://www.iso.org/standard/27001) |
| **SOC 2 (AICPA)** | Trust Service Criteria for SaaS and cloud | [aicpa.org](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome.html) |
| **CIS Controls v8** | Prioritized security controls mapped to common attack patterns | [cisecurity.org](https://www.cisecurity.org/controls) |
| **COBIT 2019** | IT governance and management framework | [isaca.org/resources/cobit](https://www.isaca.org/resources/cobit) |
| **PCI DSS v4.0** | Payment card data security requirements | [pcisecuritystandards.org](https://www.pcisecuritystandards.org) |
| **HIPAA Security Rule** | Healthcare data security requirements | [hhs.gov](https://www.hhs.gov/hipaa/for-professionals/security/index.html) |
| **FedRAMP** | Cloud security authorization for U.S. federal agencies | [fedramp.gov](https://www.fedramp.gov) |

---

## Books & Learning

| Resource | Focus |
|---|---|
| *How to Measure Anything in Cybersecurity Risk* — Douglas Hubbard & Richard Seiersen | Quantitative risk measurement using FAIR and Monte Carlo methods — the best book on security risk analysis |
| *The CISO’s Guide to an Effective Security Program* — Todd Fitzgerald | Practical program-building from a practitioner perspective |
| *IT Auditing: Using Controls to Protect Information Assets* — Davis, Schiller & Wheeler | Internal audit methodology and IT control frameworks |
| *NIST SP 800-30 Rev 1: Guide for Conducting Risk Assessments* | Authoritative NIST risk assessment methodology — free |
| *FAIR Analysis Handbook* — FAIR Institute | Factor Analysis of Information Risk (FAIR) model reference |
| *ISO 27001 Implementation Guide* — IT Governance Ltd | Step-by-step ISO 27001 certification guidance |

---

## Certifications

| Certification | Issuer | What It Validates |
|---|---|---|
| **CRISC** — Certified in Risk and Information Systems Control | ISACA | Risk identification, assessment, response, and monitoring — highly valued by GRC practitioners |
| **CISM** — Certified Information Security Manager | ISACA | Security management, governance, risk, and incident response |
| **CGRC** — Certified in Governance, Risk and Compliance (formerly CAP) | ISC² | U.S. federal RMF, FISMA, NIST control frameworks |
| **CISSP** — CISO / program-level credential | ISC² | Broad security knowledge including risk, governance, architecture |
| **ISO 27001 Lead Implementer** | PECB / BSI | ISMS implementation and audit according to ISO 27001 |
| **ISO 27001 Lead Auditor** | PECB / BSI | External and internal audit of ISO 27001 ISMS |
| **CDPSE** — Certified Data Privacy Solutions Engineer | ISACA | Privacy-by-design implementation and governance |
| **GRCP / GRCA** — GRC Professional / Auditor | OCEG | GRC program design and audit |

---

## YouTube Channels

| Channel | Focus |
|---|---|
| [ISACA](https://www.youtube.com/@ISACAorg) | GRC, audit, risk, and cybersecurity governance content from the association |
| [NIST](https://www.youtube.com/user/USNISTgov) | Official NIST framework explanations, RMF, OSCAL, and CSF updates |
| [Gerald Auger — Simply Cyber](https://www.youtube.com/@SimplyCyber) | Practitioner-level GRC, compliance, and security career content |
| [Cybersecurity Guide](https://www.youtube.com/@CybersecurityGuide) | Security management, compliance, and career guidance |

---

## Who to Follow

| Handle | Focus |
|---|---|
| [@GeraldAuger](https://twitter.com/GeraldAuger) | GRC, compliance, security careers — Simply Cyber founder |
| [@ISACA](https://twitter.com/ISACANews) | GRC and audit standards updates |
| [@NISTcyber](https://twitter.com/NISTcyber) | NIST framework and publication announcements |
| [@RiskQuantified](https://twitter.com/RiskQuantified) | Quantitative risk analysis, FAIR methodology |
| [@CISAgov](https://twitter.com/CISAgov) | Federal guidance, advisories, and compliance requirements |

---

## Key Resources

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST SP 800-53 Rev 5 — Full Control Catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CTID Mappings Explorer — NIST 800-53 → ATT&CK](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/)
- [CIS Controls v8](https://www.cisecurity.org/controls/cis-controls-list)
- [FAIR Institute — Quantitative Risk Analysis](https://www.fairinstitute.org)
- [OSCAL — Machine-Readable Compliance Data](https://pages.nist.gov/OSCAL/)
- [FedRAMP Authorization Process](https://www.fedramp.gov/program-basics/)
- [TeamStarWolf Controls Mapping](../CONTROLS_MAPPING.md) — Vendor → NIST 800-53 → ATT&CK cross-reference
- [TeamStarWolf Security Pipeline](../SECURITY_PIPELINE.md) — GRC in the enterprise security lifecycle
