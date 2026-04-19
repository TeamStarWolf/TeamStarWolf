# Security Frameworks Reference

A quick-reference guide to major cybersecurity and privacy frameworks — what they cover, who they apply to, and how they relate to each other.

---

## Framework Comparison Overview

| Framework | Org | Type | Primary Audience | Mandatory? |
|---|---|---|---|---|
| [NIST CSF 2.0](#nist-cybersecurity-framework-csf-20) | NIST | Risk management | All sectors | No (US govt recommended) |
| [NIST RMF (SP 800-37)](#nist-risk-management-framework-rmf) | NIST | Authorization process | US federal agencies | Yes (FedRAMP, FISMA) |
| [NIST 800-53 R5](#nist-sp-800-53-r5) | NIST | Control catalog | US federal & contractors | Yes (federal systems) |
| [ISO/IEC 27001:2022](#isoiec-270012022) | ISO/IEC | ISMS certification | Global, all sectors | No (certification-based) |
| [SOC 2 Type II](#soc-2) | AICPA | Audit report | SaaS/cloud providers | No (customer-driven) |
| [PCI DSS v4.0](#pci-dss-v40) | PCI SSC | Payment card security | Card processors/merchants | Yes (for card data) |
| [HIPAA Security Rule](#hipaa-security-rule) | HHS | Healthcare data | US healthcare entities | Yes (US law) |
| [CMMC 2.0](#cmmc-20) | DoD | Supply chain security | US DoD contractors | Yes (contracts) |
| [CIS Controls v8](#cis-controls-v8) | CIS | Control prioritization | All sectors | No (best practice) |
| [NIST CSF / MITRE ATT&CK](#nist-csf--mitre-attck) | NIST/MITRE | Threat-informed defense | All sectors | No |
| [ISO 27701](#iso-27701) | ISO/IEC | Privacy extension to 27001 | Privacy programs | No (certification) |
| [GDPR](#gdpr) | EU | Privacy regulation | EU data processors | Yes (EU law) |
| [CCPA / CPRA](#ccpacpra) | California | Privacy regulation | CA consumer data | Yes (CA law) |
| [NIST AI RMF](#nist-ai-rmf) | NIST | AI risk management | AI system developers | No |
| [IEC 62443](#iec-62443) | IEC | OT/ICS security | Industrial control systems | Sector-specific |

---

## NIST Cybersecurity Framework (CSF) 2.0

**Published**: 2024 | **Org**: NIST | **Cost**: Free

The CSF provides a common language for managing cybersecurity risk across sectors. Version 2.0 added a sixth function (Govern) and expanded supply chain guidance.

### Six Core Functions
| Function | Goal | Key Activities |
|---|---|---|
| **Govern** | Establish organizational context and accountability | Policies, roles, risk strategy, supply chain |
| **Identify** | Understand assets, risks, and environment | Asset inventory, risk assessment, threat intelligence |
| **Protect** | Implement safeguards | Access control, awareness training, data security, platform hardening |
| **Detect** | Identify cybersecurity events | Continuous monitoring, anomaly detection |
| **Respond** | Take action on detected incidents | IR planning, communication, containment, analysis |
| **Recover** | Restore capabilities | Recovery planning, lessons learned, comms |

### Tiers (1–4)
- **Tier 1 Partial** — Reactive, ad hoc
- **Tier 2 Risk Informed** — Awareness without org-wide policy
- **Tier 3 Repeatable** — Formalized, org-wide practices
- **Tier 4 Adaptive** — Continuous improvement, threat-informed

**Resources**: [NIST CSF 2.0](https://www.nist.gov/cyberframework) | [CSF 2.0 Quick Start Guide](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)

---

## NIST Risk Management Framework (RMF)

**Published**: SP 800-37 Rev 2 (2018) | **Org**: NIST | **Mandatory**: FISMA, FedRAMP

The RMF is the US federal authorization process. Every federal system must go through RMF to receive an Authority to Operate (ATO).

### Seven Steps
| Step | Activity |
|---|---|
| 1. Prepare | Org-level context and prerequisites |
| 2. Categorize | FIPS 199 impact level (Low/Moderate/High) |
| 3. Select | Choose NIST 800-53 control baseline |
| 4. Implement | Deploy selected controls |
| 5. Assess | 3PAO or internal assessment against 800-53A |
| 6. Authorize | AO grants ATO, P-ATO, or DATO |
| 7. Monitor | Continuous monitoring, annual assessments, POA&M |

**Resources**: [SP 800-37](https://csrc.nist.gov/publications/detail/sp/800-37/rev-2/final) | [OSCAL](https://pages.nist.gov/OSCAL/) (machine-readable RMF)

---

## NIST SP 800-53 R5

**Published**: 2020 (R5) | **Org**: NIST | **Mandatory**: US federal systems (FISMA)

The most comprehensive security and privacy control catalog available. Maps to CSF, ISO 27001, CMMC, and ATT&CK. Used as the baseline for FedRAMP, DoD, and civilian agency ATOs.

### 20 Control Families
| Family | Code | Focus |
|---|---|---|
| Access Control | AC | Authentication, authorization, separation of duties |
| Audit & Accountability | AU | Event logging, log review, audit protection |
| Awareness & Training | AT | Security literacy, role-based training |
| Configuration Management | CM | Baselines, change control, inventory |
| Contingency Planning | CP | BCP/DR, backup, alternate sites |
| Identification & Authentication | IA | MFA, credential management, PKI |
| Incident Response | IR | IR plan, handling, monitoring |
| Maintenance | MA | Controlled maintenance, media sanitization |
| Media Protection | MP | Media access, transport, sanitization |
| Physical Protection | PE | Physical access, environmental controls |
| Planning | PL | Security plans, rules of behavior |
| Program Management | PM | Risk strategy, supply chain, workforce |
| Personnel Security | PS | Screening, termination, access agreements |
| PII Processing & Transparency | PT | Privacy notices, consent, data minimization |
| Risk Assessment | RA | Risk assessment, vulnerability scanning |
| System & Services Acquisition | SA | SDLC, developer testing, supply chain |
| System & Communications Protection | SC | Network segmentation, crypto, boundary |
| System & Information Integrity | SI | Malware protection, patching, monitoring |
| Supply Chain Risk Management | SR | Supplier assessment, SBOM, provenance |
| Individual Participation | IP | Privacy rights, redress |

**Resources**: [SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) | [Controls Mapping](CONTROLS_MAPPING.md) | [CTID ATT&CK Mapping](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/)

---

## ISO/IEC 27001:2022

**Published**: October 2022 | **Org**: ISO/IEC | **Cost**: Purchasable standard (~$170)

The international standard for Information Security Management Systems (ISMS). Organizations can pursue third-party certification. Used globally across industries.

### Clause Structure
| Clauses | Content |
|---|---|
| Clauses 4–10 | Mandatory ISMS requirements (context, leadership, planning, support, operation, evaluation, improvement) |
| Annex A | 93 controls in 4 themes (Organizational, People, Physical, Technological) |

### Four Control Themes (2022 restructure from 14 domains)
| Theme | Controls |
|---|---|
| Organizational | 37 controls — policies, roles, supplier security, IR, BCP |
| People | 8 controls — screening, awareness, training, disciplinary |
| Physical | 14 controls — physical access, equipment, media disposal |
| Technological | 34 controls — endpoint, network, cryptography, logging, SDLC |

**Relationship to 800-53**: NIST provides a mapping between 800-53 and ISO 27001 controls. Most controls overlap with ~70% coverage equivalence.

**Resources**: [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html) | [NIST 800-53 / 27001 mapping](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/mappings)

---

## SOC 2

**Published**: Ongoing | **Org**: AICPA | **Cost**: Audit fees ($30K–$100K+)

An audit framework for service organizations (SaaS, cloud, managed services). Customers — especially enterprises — require SOC 2 reports from their vendors. Not a certification; rather a third-party auditor's opinion.

### Trust Services Criteria (TSC)
| Criteria | Required? | Focus |
|---|---|---|
| Security (CC) | Yes | Logical and physical access, change management, risk assessment |
| Availability | Optional | Uptime, performance, incident response |
| Processing Integrity | Optional | Complete, accurate, timely processing |
| Confidentiality | Optional | Protection of confidential information |
| Privacy | Optional | PII collection, use, retention, disposal |

### Type I vs Type II
- **Type I**: Point-in-time assessment — controls designed appropriately
- **Type II**: Period of time (usually 6–12 months) — controls operating effectively

**Resources**: [AICPA SOC 2](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services) | [AICPA TSC](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria)

---

## PCI DSS v4.0

**Published**: March 2022 | **Org**: PCI SSC | **Mandatory**: Card brands (Visa, Mastercard, etc.)

Required for any entity that stores, processes, or transmits payment card data. Version 4.0 introduces customized implementation and multi-factor authentication expansion.

### 12 Requirements
| Req | Focus |
|---|---|
| 1 | Install and maintain network security controls |
| 2 | Apply secure configurations to all system components |
| 3 | Protect stored account data |
| 4 | Protect cardholder data in transit (TLS) |
| 5 | Protect all systems against malware |
| 6 | Develop and maintain secure systems and software |
| 7 | Restrict access to cardholder data by business need |
| 8 | Identify users and authenticate access (MFA) |
| 9 | Restrict physical access to cardholder data |
| 10 | Log and monitor all access |
| 11 | Test security of systems and networks regularly |
| 12 | Support information security with organizational policies |

**Resources**: [PCI SSC](https://www.pcisecuritystandards.org/) | [PCI DSS v4.0 document](https://www.pcisecuritystandards.org/document_library/)

---

## HIPAA Security Rule

**Published**: 2003 (original), ongoing updates | **Org**: HHS | **Mandatory**: US covered entities and business associates

Requires administrative, physical, and technical safeguards to protect electronic protected health information (ePHI).

### Three Safeguard Categories
| Category | Examples |
|---|---|
| Administrative | Risk analysis, workforce training, IR procedures, contingency plan |
| Physical | Facility access controls, workstation use policies, media disposal |
| Technical | Access control, audit controls, integrity, transmission security (encryption) |

**Resources**: [HHS Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)

---

## CMMC 2.0

**Published**: November 2021 | **Org**: DoD | **Mandatory**: DoD contractors handling CUI or FCI

Cybersecurity Maturity Model Certification — required for defense industrial base (DIB) contractors. Streamlined from CMMC 1.0 (5 levels) to 3 levels.

### Three Levels
| Level | Requirements | Assessment |
|---|---|---|
| Level 1 (Foundational) | 17 practices (NIST 800-171 subset) | Annual self-assessment |
| Level 2 (Advanced) | 110 practices (full NIST 800-171) | Triennial C3PAO assessment |
| Level 3 (Expert) | 110 + NIST 800-172 | Government-led assessment |

**Resources**: [DoD CMMC](https://dodcio.defense.gov/CMMC/) | [NIST SP 800-171](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)

---

## CIS Controls v8

**Published**: May 2021 | **Org**: Center for Internet Security | **Cost**: Free

18 prioritized controls mapped to Implementation Groups (IG1/IG2/IG3) for organizations of different sizes. Excellent starting point for smaller organizations or those without formal frameworks.

### Implementation Groups
| IG | Target | Controls |
|---|---|---|
| IG1 (Basic hygiene) | Small orgs, limited IT staff | 56 safeguards covering CIS Controls 1–6 |
| IG2 (Moderate security) | Mid-size, multiple departments | Adds 74 safeguards |
| IG3 (Advanced) | Complex/regulated orgs | Adds 23 safeguards |

### 18 Controls (summary)
| # | Control |
|---|---|
| 1 | Enterprise Asset Inventory |
| 2 | Software Asset Inventory |
| 3 | Data Protection |
| 4 | Secure Configuration |
| 5 | Account Management |
| 6 | Access Control Management |
| 7 | Continuous Vulnerability Management |
| 8 | Audit Log Management |
| 9 | Email and Web Browser Protections |
| 10 | Malware Defenses |
| 11 | Data Recovery |
| 12 | Network Infrastructure Management |
| 13 | Network Monitoring and Defense |
| 14 | Security Awareness and Skills Training |
| 15 | Service Provider Management |
| 16 | Application Software Security |
| 17 | Incident Response Management |
| 18 | Penetration Testing |

**Resources**: [CIS Controls v8](https://www.cisecurity.org/controls/v8)

---

## NIST CSF / MITRE ATT&CK

The [CTID (Center for Threat-Informed Defense)](https://ctid.mitre-engenuity.org/) maintains mappings between NIST 800-53 controls and ATT&CK techniques. This enables:
- Measuring ATT&CK coverage from your control implementation
- Identifying technique gaps in your control baseline
- Prioritizing controls based on adversary behavior data

**See**: [Controls Mapping](CONTROLS_MAPPING.md) | [ATT&CK Navigator layers](navigator/) | [CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist800-53/)

---

## ISO 27701

**Published**: 2019 | **Org**: ISO/IEC

Privacy Information Management System (PIMS) — an extension to ISO 27001 for organizations acting as PII controllers or processors. Provides a structured path to GDPR accountability.

**Resources**: [ISO 27701](https://www.iso.org/standard/71670.html)

---

## GDPR

**Published**: May 2018 | **Org**: EU | **Mandatory**: EU law

Applies to any organization processing personal data of EU residents. Key security requirements:

| Article | Requirement |
|---|---|
| Art. 25 | Data protection by design and default |
| Art. 32 | Appropriate technical and organizational measures (encryption, pseudonymization, availability) |
| Art. 33 | 72-hour breach notification to supervisory authority |
| Art. 34 | Notification to data subjects when high risk |

**Resources**: [GDPR text](https://gdpr-info.eu/) | [EDPB guidelines](https://www.edpb.europa.eu/edpb_en)

---

## CCPA/CPRA

**Published**: CCPA 2018, CPRA amendments 2023 | **Org**: California | **Mandatory**: CA law

Applies to for-profit businesses meeting size/data thresholds in California. CPRA created the California Privacy Protection Agency (CPPA) and added data minimization, purpose limitation, and correction rights.

**Resources**: [CPPA](https://cppa.ca.gov/) | [CCPA text](https://oag.ca.gov/privacy/ccpa)

---

## NIST AI RMF

**Published**: January 2023 | **Org**: NIST | **Cost**: Free

Framework for managing risks from AI systems. Four core functions:
- **GOVERN** — Policies, accountability, culture for AI risk management
- **MAP** — Context and risk identification for AI systems
- **MEASURE** — Analyze, assess, and track AI risks
- **MANAGE** — Prioritize and treat AI risks; plan for residual risk

**Resources**: [NIST AI RMF](https://www.nist.gov/system/files/documents/2023/01/26/NIST.AI.100-1.pdf) | [AI RMF Playbook](https://airc.nist.gov/Docs/2)

---

## IEC 62443

**Published**: Ongoing series | **Org**: IEC | **Mandatory**: Sector-specific (energy, manufacturing, water)

International standard for industrial automation and control system (IACS) security. Addresses product suppliers, system integrators, and asset owners.

### Security Levels (SL 0–4)
| Level | Protection |
|---|---|
| SL 0 | No special security requirements |
| SL 1 | Protection against unintentional/casual violation |
| SL 2 | Protection against intentional violation with simple means |
| SL 3 | Protection against sophisticated means with IACS-specific knowledge |
| SL 4 | Protection against state-sponsored actors with extensive resources |

**Resources**: [IEC 62443](https://www.iec.ch/iec62443) | [ISA/IEC 62443 overview](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)

---

## Framework Mapping Quick Reference

| Your Goal | Start With |
|---|---|
| Build a baseline security program | CIS Controls v8 (IG1→IG2→IG3) |
| Achieve enterprise risk management | NIST CSF 2.0 |
| US federal ATO / FedRAMP | NIST RMF + NIST 800-53 R5 |
| ISO certification for enterprise sales | ISO 27001:2022 |
| SaaS vendor compliance for B2B deals | SOC 2 Type II |
| Process payment card data | PCI DSS v4.0 |
| Handle US healthcare data | HIPAA Security Rule |
| Work with US DoD / defense contracts | CMMC 2.0 + NIST 800-171 |
| EU data subjects | GDPR |
| AI system development | NIST AI RMF |
| Industrial / OT environments | IEC 62443 |
| Map controls to adversary techniques | NIST 800-53 → MITRE ATT&CK (CTID) |

---

## Related Resources
- [Enterprise Security Pipeline](SECURITY_PIPELINE.md) — controls mapped to pipeline stages and vendors
- [Controls Mapping](CONTROLS_MAPPING.md) — NIST 800-53 → ATT&CK technique chain
- [Governance, Risk & Compliance](disciplines/governance-risk-compliance.md) — GRC discipline page
- [Privacy Engineering](disciplines/privacy-engineering.md) — GDPR/CCPA technical implementation
- [ICS / OT Security](disciplines/ics-ot-security.md) — IEC 62443 implementation
