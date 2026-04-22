# GRC Reference

> **Governance, Risk, and Compliance** — comprehensive operational reference for security program management, risk quantification, regulatory compliance, third-party risk, and audit management.

**NIST 800-53 families**: PM (Program Management), CA (Assessment & Authorization), RA (Risk Assessment), SA (System & Services Acquisition)
**ISO 27001:2022**: Clause 6 (Planning), Annex A Organizational/People/Physical/Technological controls
**SOC 2**: CC9 (Risk Mitigation), CC1 (Control Environment), CC2 (Communication & Information)

---

## Table of Contents

1. [Security Governance](#security-governance)
2. [Risk Management](#risk-management)
3. [Compliance Programs](#compliance-programs)
4. [Third-Party Risk Management (TPRM)](#third-party-risk-management-tprm)
5. [Audit Management](#audit-management)
6. [Exception Management](#exception-management)

---

## Security Governance

### Security Program Governance Structure

```
Board of Directors
  └── Audit Committee
        └── CISO (Chief Information Security Officer)
              └── Security Leadership (VPs / Directors)
                    ├── Security Operations (SOC, IR)
                    ├── Risk & Compliance
                    ├── Identity & Access Management
                    ├── Application Security
                    └── Infrastructure Security
```

The board sets risk appetite; the audit committee provides oversight; the CISO translates risk into program priorities; security leadership executes across functional teams.

---

### Security Policies Hierarchy

| Level | Type | Mandatory? | Scope | Example |
|---|---|---|---|---|
| 1 | **Policy** | Yes | What must be done | Information Security Policy |
| 2 | **Standard** | Yes | Specific measurable requirements | Password Standard (min 12 chars, MFA required) |
| 3 | **Procedure** | Yes | How to do it, step-by-step | Access Request Procedure |
| 4 | **Guideline** | No (recommended) | Best practice, optional | Secure Coding Guideline |

**Key principle**: Policies are technology-agnostic and durable (3–5 year lifecycle); standards and procedures change more frequently as technology evolves.

---

### Policy Lifecycle

```
Draft → Legal/HR/IT Review → CISO/Board Approval → Publish → Communicate
  ↑                                                                  ↓
Retire ← Annual Review ← Monitor & Measure ← Enforce ← Training & Awareness
```

**Trigger events** that force out-of-cycle review: significant incident, regulatory change, major technology change, merger/acquisition.

---

### Core Security Policies

| Policy Name | Purpose | Key Requirements | Owner |
|---|---|---|---|
| Information Security Policy | Master policy governing all security activity | Risk management, roles, compliance obligations | CISO |
| Acceptable Use Policy (AUP) | Governs employee use of company assets | Prohibited activities, monitoring notice, consequences | CISO / Legal |
| Access Control Policy | Manage who can access what | Least privilege, need-to-know, access review frequency | IAM / CISO |
| Data Classification Policy | Classify data by sensitivity | Classification tiers, handling requirements per tier | CISO / Data Owner |
| Incident Response Policy | Guide response to security events | Severity levels, roles, notification thresholds | CISO / IR Lead |
| Business Continuity Policy | Ensure operational resilience | RTO/RPO targets, BIA requirements, test cadence | CISO / BCP Owner |
| Vendor Management Policy | Govern third-party security risk | Risk tiering, assessment frequency, contractual requirements | CISO / Procurement |
| Change Management Policy | Control changes to IT systems | Change types, approval gates, rollback requirements | IT / CISO |
| Password / Authentication Policy | Credential security | Complexity, MFA requirements, expiry, banned passwords | IAM / CISO |
| Encryption Policy | Protect data at rest and in transit | Approved algorithms, key management, prohibited ciphers | CISO / Architecture |

---

### Security Committee Structure

**Information Security Steering Committee (ISSC)**

| Attribute | Detail |
|---|---|
| Composition | CISO (chair), CTO, CFO, CLO, CPO, business unit heads, Internal Audit |
| Charter | Set security strategy, approve risk appetite, review major risks, approve policies |
| Meeting cadence | Quarterly formal meetings; ad hoc for significant incidents or material changes |
| Outputs | Risk decisions, policy approvals, budget endorsements, escalation resolutions |

---

### RACI Model for Security Responsibilities

| Process | CISO | Security Team | IT Ops | Business Units | Legal/Compliance | Audit |
|---|---|---|---|---|---|---|
| Policy development | A | R | C | C | C | I |
| Risk assessment | A | R | C | C | I | I |
| Vulnerability management | A | R | R | I | I | I |
| Incident response | A | R | C | I | C | I |
| Access reviews | I | R | R | A | I | C |
| Vendor risk assessments | A | R | I | C | C | I |
| Security awareness training | A | R | I | I | C | I |
| Audit response | A | R | R | R | C | A |

**R** = Responsible, **A** = Accountable, **C** = Consulted, **I** = Informed

---

### Board Reporting

Board-level metrics focus on business impact and strategic posture, not technical detail.

| Metric Category | Example Metrics |
|---|---|
| **Risk Posture** | Number of critical/high open risks; top 5 risks by residual score; risk trend (↑↓) |
| **Program Maturity** | CMMI or CSF maturity score by function; year-over-year improvement |
| **Spend Efficiency** | Security budget as % of IT budget; cost per employee; ROI on major controls |
| **Incident Summary** | Incidents by severity, MTTD, MTTR, regulatory notifications required |
| **Compliance Status** | Audit findings open/closed; regulatory deadlines; certification status |
| **Third-Party Risk** | Tier 1 vendor assessment completion rate; vendors with critical findings |

**Presentation tips**: Use RAG (Red/Amber/Green) status indicators; avoid technical jargon; tie every metric to business risk or regulatory exposure.

---

## Risk Management

### Risk Management Process (ISO 31000)

```
Establish Context
      ↓
Risk Identification  ←─────────────────────────────────┐
      ↓                                                 │
Risk Analysis (Qualitative / Quantitative)              │
      ↓                                               Communicate
Risk Evaluation (vs. Risk Appetite)                   & Consult
      ↓                                                 │
Risk Treatment (Accept / Avoid / Transfer / Mitigate)   │
      ↓                                                 │
Monitor & Review ────────────────────────────────────────┘
```

---

### Risk Identification Methods

| Method | Description | Best For |
|---|---|---|
| **Threat modeling** | Structured analysis of attack paths against system components | New systems, architecture reviews |
| **Vulnerability assessments** | Technical scanning to identify exploitable weaknesses | Existing infrastructure |
| **Risk workshops** | Facilitated sessions with stakeholders to surface operational risks | Business process risks |
| **Incident history analysis** | Mining past incidents for recurring risk patterns | Residual / systemic risks |
| **Industry threat intelligence** | ISAC feeds, vendor advisories, CISA KEV | Emerging threat risks |
| **Regulatory horizon scanning** | Tracking upcoming compliance obligations | Compliance-driven risks |

---

### Risk Analysis Approaches

#### Qualitative: 5×5 Risk Matrix

| Likelihood \ Impact | 1-Negligible | 2-Minor | 3-Moderate | 4-Major | 5-Critical |
|---|---|---|---|---|---|
| **5-Almost Certain** | 5 | 10 | 15 | 20 | **25** |
| **4-Likely** | 4 | 8 | 12 | **16** | **20** |
| **3-Possible** | 3 | 6 | 9 | 12 | **15** |
| **2-Unlikely** | 2 | 4 | 6 | 8 | 10 |
| **1-Rare** | 1 | 2 | 3 | 4 | 5 |

**Heat map thresholds**: 1–5 = Green (Low), 6–10 = Yellow (Medium), 11–16 = Orange (High), 17–25 = Red (Critical)

#### Quantitative: FAIR Model

```
Loss Event Frequency (LEF) = Threat Event Frequency (TEF) × Vulnerability
Loss Magnitude (LM) = Primary Loss + Secondary Loss
Annualized Loss Expectancy (ALE) = LEF × LM
```

**Primary Loss components**:
- Productivity (downtime × employees affected × hourly cost)
- Response (IR team time, tools, forensics)
- Replacement (hardware, software, rebuilding systems)
- Competitive Advantage (IP theft, lost deals)
- Fines & Judgments (regulatory penalties, litigation)
- Reputation (customer churn, brand damage)

**Secondary Loss**: downstream losses after the primary event (e.g., customers who leave after a breach notification).

Monte Carlo simulation runs thousands of iterations across input ranges to produce a probability distribution of ALE — more defensible than single-point estimates.

#### Semi-Quantitative Approaches

**DREAD scoring** (Damage, Reproducibility, Exploitability, Affected Users, Discoverability) — rates each 1–10, averages to a risk score.

**CVSS as risk input**: CVSS Base Score measures vulnerability severity, not risk. Adjust with CVSS Temporal (exploit availability, remediation level) and Environmental (asset criticality, existing controls) to produce context-aware risk scores.

---

### Risk Register Fields

| Field | Description |
|---|---|
| Risk ID | Unique identifier (e.g., RISK-2025-042) |
| Description | Clear narrative of the risk scenario |
| Category | Strategic / Operational / Compliance / Technology / Third-Party |
| Assets Affected | Systems, data, processes impacted |
| Threat | The actor or event that could cause harm |
| Vulnerability | The weakness being exploited |
| Likelihood (1–5) | Probability of occurrence |
| Impact (1–5) | Business consequence if realized |
| Inherent Risk Score | Likelihood × Impact (before controls) |
| Controls | Existing mitigating controls |
| Residual Risk Score | Likelihood × Impact (after controls) |
| Risk Owner | Accountable business owner (not the security team) |
| Treatment Plan | Accept / Avoid / Transfer / Mitigate with specific actions |
| Due Date | Target date for treatment completion |
| Status | Open / In Progress / Closed / Accepted |

---

### Risk Treatment Options

| Option | When to Use | Key Requirement |
|---|---|---|
| **Accept** | Residual risk within appetite; cost to mitigate exceeds benefit | Documented rationale, named owner, board/CISO sign-off |
| **Avoid** | Risk is too high and the activity is optional | Formal decision to eliminate the activity |
| **Transfer** | Risk is insurable or contractually shiftable | Cyber insurance policy, indemnification clauses in contracts |
| **Mitigate** | Controls can meaningfully reduce likelihood or impact | Control implementation plan with measurable target residual |

---

### Risk Appetite and Tolerance

**Appetite** = the amount of risk an organization is willing to accept in pursuit of its objectives.
**Tolerance** = the acceptable variance around that appetite before escalation is required.

**Example appetite statements**:

| Domain | Appetite Statement |
|---|---|
| Regulatory violations | **Zero tolerance** — no knowing or willful non-compliance; regulatory fines are unacceptable |
| Data breach (PII/PHI) | **Low** — residual risk of data breach must be < Medium on the risk matrix |
| Service availability | **Moderate** — planned downtime acceptable; unplanned < 99.5% uptime triggers treatment |
| Third-party risk | **Low** — Tier 1 vendors must complete full assessment before go-live |
| Insider threat | **Low** — privileged access reviews quarterly; DLP controls mandatory |

---

### Cyber Insurance

**Coverage types**:

| Type | Covers |
|---|---|
| **First-party** | Direct losses to the insured: breach response costs, forensics, notification, credit monitoring, ransomware payments, business interruption |
| **Third-party** | Claims made against the insured: liability for customer data exposure, regulatory defense costs, media liability |

**Common exclusions** (review policy carefully):
- War and nation-state attacks (Lloyd's 2023 war exclusion clauses)
- Known unpatched vulnerabilities (carrier may deny if CVE was public >30 days before incident)
- Fraudulent wire transfer (often sublimited or excluded)
- Bodily injury / property damage from cyber events (may require separate policy)
- Prior acts before policy inception date

**Application questionnaire hot topics**: MFA on all remote access and email, EDR deployment %, backup frequency and immutability, patch SLAs, incident response retainer, security awareness training completion rates.

**Ransomware coverage evolution**: Many carriers now require: offline/immutable backups, IR retainer in place, and MFA on RDP/VPN as conditions of coverage. Average ransomware claim has increased ransom sublimits and co-insurance requirements.

---

### FAIR Model Deep Dive

**OpenFAIR** is an ANSI/The Open Group standard (O-RA, O-RT) for cyber risk quantification.

```
Risk = Loss Event Frequency (LEF) × Loss Magnitude (LM)

LEF = Threat Event Frequency (TEF) × Vulnerability (%)
    = [Contact Frequency × Probability of Action] × [Threat Capability / Difficulty]

LM = Primary Loss Magnitude + Secondary Loss Magnitude
   Secondary LM = Secondary Loss Event Frequency × Secondary Loss Magnitude
```

**FAIR analysis steps**:
1. Define the scenario (asset, threat community, effect)
2. Estimate TEF using threat intelligence data
3. Estimate Vulnerability using control strength vs. threat capability
4. Estimate Loss Magnitude ranges (min / most likely / max) for each primary loss component
5. Run Monte Carlo simulation (10,000+ iterations)
6. Output: 80th/90th percentile ALE, probability of exceeding threshold

**Resources**: FAIR Institute (fairinstitute.org), Open FAIR Body of Knowledge, RiskLens platform.

---

## Compliance Programs

### Compliance vs. Security

**Key distinction**: Compliance is a **floor**, not a ceiling. Meeting a compliance requirement does not mean you are secure — it means you have demonstrated minimum acceptable controls to an auditor at a point in time.

**Compliance theater risks**:
- Checkbox mentality: passing audits without improving actual security posture
- Point-in-time assessments may not reflect current state
- Auditors test samples, not 100% of population
- Framework requirements lag behind current threat landscape

**Recommended posture**: Use compliance frameworks as a baseline. Layer threat-informed controls and continuous monitoring on top to build genuine security.

---

### Compliance Calendar

| Period | Activity |
|---|---|
| Q1 | Annual risk assessment kickoff; prior year audit remediation review |
| Q2 | ISO 27001 / SOC 2 evidence collection; HIPAA training completion |
| Q3 | Internal audit fieldwork; PCI DSS quarterly ASV scan review |
| Q4 | External audit (SOC 2 Type 2 window close); management review; policy renewal cycle |
| Ongoing | Continuous monitoring (SIEM alerts, vulnerability scan results, access reviews) |

**Point-in-time vs. continuous**: SOC 2 Type 1 and ISO Stage 1 audits are point-in-time. SOC 2 Type 2 covers a period (6–12 months). Continuous monitoring tools (Vanta, Drata, Secureframe) automate evidence collection to reduce audit prep burden.

---

### Framework Alignment Cross-Walk

| Domain | ISO 27001:2022 | NIST CSF 2.0 | SOC 2 TSC | PCI DSS v4.0 | HIPAA | CMMC 2.0 |
|---|---|---|---|---|---|---|
| Asset Management | A.5.9–5.10 | ID.AM | CC6.1 | Req 2, 12 | §164.310(d) | AC.1.001 |
| Access Control | A.5.15–5.18 | PR.AA | CC6.1–6.3 | Req 7–8 | §164.312(a) | AC.1.001–2.006 |
| Cryptography | A.8.24 | PR.DS | CC6.7 | Req 3–4 | §164.312(e) | SC.3.177 |
| Incident Response | A.5.24–5.28 | RS.MA | CC7.3–7.5 | Req 12.10 | §164.308(a)(6) | IR.2.092 |
| Vulnerability Mgmt | A.8.8 | ID.RA, PR.IP | CC7.1 | Req 6, 11 | §164.308(a)(1) | RA.2.141 |
| Supplier Risk | A.5.19–5.22 | GV.SC | CC9.2 | Req 12.8 | §164.308(b) | SR.3.169 |
| Logging & Monitoring | A.8.15–8.17 | DE.CM | CC7.2 | Req 10 | §164.312(b) | AU.2.041 |

---

### SOC 2

**Report types**:

| Type | Scope | Use Case |
|---|---|---|
| **Type 1** | Design effectiveness of controls at a specific point in time | Quick-start; satisfies early customer due diligence |
| **Type 2** | Operating effectiveness of controls over a period (typically 6–12 months) | Customer contracts; enterprise procurement requirements |

**Trust Services Criteria (TSC)**:

| Criteria | Code | Description |
|---|---|---|
| Security (Common Criteria) | CC | Logical and physical access, change management, risk management — **required for all SOC 2** |
| Availability | A | System availability per SLA commitments |
| Processing Integrity | PI | Complete, accurate, timely processing |
| Confidentiality | C | Protection of confidential information |
| Privacy | P | Personal information collection, use, retention, and disposal |

**Readiness assessment checklist**:

- [ ] Policies and procedures documented and approved
- [ ] System description drafted (infrastructure, data flows, boundaries)
- [ ] Access control evidence (provisioning, de-provisioning, reviews)
- [ ] Change management tickets with approvals
- [ ] Incident response plan tested; incidents logged
- [ ] Vendor management: risk assessments on sub-service organizations
- [ ] Encryption in transit (TLS 1.2+) and at rest (AES-256)
- [ ] Logging and monitoring configured; alerts tested
- [ ] Vulnerability scans and pen test report (if CC6.8 in scope)
- [ ] Background checks for personnel with system access

**Common SOC 2 findings**:

| Finding | Root Cause | Remediation |
|---|---|---|
| Access review gaps | Quarterly reviews not completed or not documented | Automate reviews in IAM tool; evidence in ticketing system |
| Change management | Changes deployed without approval tickets | Enforce CI/CD pipeline gates; no direct production access |
| Vendor management | Sub-processors not assessed | Maintain vendor register; annual questionnaire workflow |
| Encryption key rotation | Keys not rotated per policy | Automate rotation; alert on keys approaching expiry |

**Auditors**: Big 4 (Deloitte, EY, KPMG, PwC) for enterprise customers; specialist firms (Schellman, Coalfire, Prescient, A-LIGN) often preferred for cost and speed.

---

### ISO 27001:2022

**Certification process**:

```
Gap Assessment → Remediation Program → Stage 1 Audit (documentation review)
      → Stage 2 Audit (implementation testing) → Certification (3 years)
            → Annual Surveillance Audits → Recertification (year 3)
```

**Key ISMS documents**:
- **Scope statement**: boundaries of the ISMS (locations, systems, business units)
- **Statement of Applicability (SoA)**: lists all 93 Annex A controls, justification for inclusion/exclusion, and implementation status
- **Risk assessment and treatment plan**
- **Internal audit program and results**
- **Management review minutes** (annual minimum; must cover specific agenda items per Clause 9.3)

**Annex A controls (93 controls, 4 themes)**:

| Theme | Count | Examples |
|---|---|---|
| **Organizational** | 37 | Information security policies, roles, threat intelligence, supplier relationships, incident management |
| **People** | 8 | Screening, employment terms, security awareness, disciplinary process |
| **Physical** | 14 | Physical security perimeters, entry controls, desk/screen clear policy, equipment maintenance |
| **Technological** | 34 | Access control, malware protection, logging, cryptography, secure development, vulnerability management |

**New controls added in 2022 revision** (compared to 2013): Threat intelligence (5.7), Information security for cloud services (5.23), ICT readiness for business continuity (5.30), Physical security monitoring (7.4), Data masking (8.11), Data leakage prevention (8.12), Web filtering (8.23), Secure coding (8.28).

---

### PCI DSS v4.0

**Cardholder Data Environment (CDE) scoping**:
- Reduce scope via **tokenization** (replace PANs with tokens; out-of-scope systems never see real card data)
- **Point-to-point encryption (P2PE)**: validated P2PE solution reduces scope to POI devices only
- **Network segmentation**: isolate CDE with firewalls; validate with penetration testing

**Self-Assessment Questionnaire (SAQ) types**:

| SAQ | Who | Key Controls |
|---|---|---|
| SAQ A | Card-not-present merchants using fully outsourced payment | Minimal — vendor attestation |
| SAQ A-EP | Merchants with partially outsourced e-commerce | Web application security |
| SAQ B | Merchants with imprint machines or standalone dial-out terminals | Physical security |
| SAQ B-IP | Merchants with IP-connected POI terminals | Network security |
| SAQ C | Merchants with payment application connected to internet | Application + network |
| SAQ C-VT | Merchants using web-based virtual terminals | Workstation security |
| SAQ D (Merchant) | All other merchants | Full 12 requirements |
| SAQ D (Service Provider) | Service providers not using SAQ A–C | Full 12 requirements + extras |

**Key v4.0 new/changed requirements** (effective March 2025 for future-dated):
- **Customized approach**: organizations can implement alternative controls that demonstrably meet the intent of each requirement (replaces compensating controls for mature programs)
- **Targeted risk analysis**: required for several requirements to justify implementation choices
- **Phishing-resistant MFA** for all access into the CDE (Req 8.4.2)
- **Web-facing application security**: automated technical testing or WAF for all public-facing apps (Req 6.4.2)
- **Ecommerce skimming prevention**: script integrity verification for all payment pages (Req 6.4.3)

**QSA engagement**: Qualified Security Assessors conduct on-site assessments for merchants/service providers above SAQ eligibility thresholds. Output is a **Report on Compliance (RoC)** and **Attestation of Compliance (AoC)**.

---

### HIPAA

**Protected Health Information (PHI)**:
PHI is individually identifiable health information in any medium. The 18 HIPAA identifiers include name, address, dates (except year), phone, fax, email, SSN, MRN, health plan beneficiary number, account number, certificate/license number, VINs, device identifiers, URLs, IPs, biometric identifiers, full-face photos, and any unique identifying number.

**ePHI technical safeguards** (§164.312):

| Safeguard | Required (R) / Addressable (A) | Control |
|---|---|---|
| Unique user identification | R | Assign unique IDs; no shared accounts |
| Emergency access procedure | R | Break-glass access with audit trail |
| Automatic logoff | A | Session timeout policy |
| Encryption & decryption | A | Encrypt ePHI in transit and at rest |
| Audit controls | R | Log access to ePHI systems |
| Integrity controls | A | Prevent improper alteration |
| Transmission security | A | Encrypt ePHI in transit |

**Required vs. Addressable**: "Required" means you must implement it. "Addressable" means you must assess whether it is reasonable and appropriate; if not, document why and implement an equivalent alternative.

**Business Associate Agreement (BAA)**:
Required before any vendor receives, creates, or transmits ePHI on behalf of a covered entity. Key BAA provisions: permitted uses, security safeguards, breach notification obligations (within 60 days of discovery), subcontractor requirements, return/destruction of PHI on termination.

**Breach notification rule**:
- Individual notification: without unreasonable delay, no later than **60 days** after discovery
- HHS notification: same 60-day rule; breaches of 500+ in a state require simultaneous **media notification**
- Annual HHS reporting for breaches affecting fewer than 500 individuals
- Risk assessment to determine if incident is a breach (4 factors: nature/extent of PHI, who accessed, whether PHI was actually acquired, extent of mitigation)

**OCR audit protocol categories**: Security Management Process, Workforce Training & Management, Access Management, Audit Controls, Transmission Security, Business Associate Agreements, Notice of Privacy Practices.

---

### CMMC 2.0

**Level structure**:

| Level | Practices | Assessment | Who Needs It |
|---|---|---|---|
| **Level 1 (Foundational)** | 17 practices (FAR 52.204-21) | Annual self-assessment | Contractors handling FCI (Federal Contract Information) |
| **Level 2 (Advanced)** | 110 practices (NIST SP 800-171) | Triennial C3PAO assessment (or self-assess for non-prioritized) | Contractors handling CUI (Controlled Unclassified Information) |
| **Level 3 (Expert)** | 110+ practices (NIST SP 800-172 subset) | DIBCAC-led government assessment | Critical programs with highest-value CUI |

**Key documents**:
- **System Security Plan (SSP)**: describes the system boundary, security requirements, and how each of the 110 practices is implemented
- **Plan of Action & Milestones (POA&M)**: documents practices not yet implemented, remediation timeline, and responsible party

**SPRS score calculation**:
- Start at 110 points
- Deduct points for each unimplemented NIST 800-171 practice based on DoD assessment methodology weights (practices carry 1, 3, or 5 points)
- Minimum score is -203
- Score submitted to **Supplier Performance Risk System (SPRS)**
- Scores visible to contracting officers

**C3PAO**: CMMC Third-Party Assessment Organizations — accredited by the CMMC Accreditation Body (Cyber-AB) to conduct Level 2 assessments.

---

## Third-Party Risk Management (TPRM)

### Vendor Risk Lifecycle

```
Onboarding Assessment → Contract Negotiation → Active Monitoring → Offboarding
        ↑                                              |                  ↓
   Risk Tiering                              Annual Re-assessment    Data Return/
   (Tier 1–4)                                + Event-triggered       Destruction
                                              reviews
```

---

### Risk Tiering

| Tier | Label | Criteria | Assessment Frequency |
|---|---|---|---|
| **Tier 1** | Critical | Accesses sensitive data AND is business-critical (outage would halt operations) | Annual full assessment + real-time monitoring |
| **Tier 2** | High | Accesses sensitive data OR is business-critical | Annual assessment |
| **Tier 3** | Medium | Limited access to non-sensitive systems; moderate operational impact | Biennial assessment |
| **Tier 4** | Low | No access to sensitive data; low operational impact | Standard contract terms only |

**Examples**:
- Tier 1: Cloud ERP (SAP/Oracle), managed security service provider, cloud infrastructure (AWS/Azure/GCP)
- Tier 2: HR platform (Workday), payroll processor, CRM (Salesforce)
- Tier 3: Marketing analytics, project management SaaS
- Tier 4: Office supplies vendor, catering company

---

### Assessment Methods by Tier

| Tier | Methods |
|---|---|
| **Tier 1** | On-site audit rights exercise, full security questionnaire (SIG Core), penetration test report review, SOC 2 Type 2 / ISO 27001 cert review, financial stability check |
| **Tier 2** | Full questionnaire + evidence artifacts, SOC 2 Type 2 or equivalent certification |
| **Tier 3** | Simplified questionnaire (SIG Lite), public certification verification |
| **Tier 4** | Standard contract security exhibits, no formal assessment |

---

### TPRM Questionnaire Sections

| Section | Key Topics |
|---|---|
| Company Overview | Ownership, locations, key personnel, financial stability, subcontractors |
| Security Program | CISO/security leadership, security budget, policies, security team size |
| Access Controls | MFA, PAM, access reviews, privileged account management |
| Data Handling | Data classification, encryption (at rest/transit), data retention, deletion |
| Incident Response | IR plan, detection capabilities, breach notification procedures and SLAs |
| Business Continuity | BCP/DR plan, RTO/RPO, last test date and results |
| Subprocessors | List of fourth parties with access to your data; their security posture |
| Certifications | SOC 2, ISO 27001, PCI DSS, HIPAA compliance status; report age |

---

### SIG (Standardized Information Gathering) Questionnaire

Developed by Shared Assessments; the industry-standard TPRM questionnaire format.

| Version | Scope | Use Case |
|---|---|---|
| **SIG Core** | Full questionnaire (~800 questions across 18 domains) | Tier 1/2 critical vendors |
| **SIG Lite** | Abbreviated (~126 questions) | Tier 2/3 vendors; initial screening |

**SIG domains**: Access Control, Application Security, Cloud Hosting, Cybersecurity Incident Management, Operational Resilience, Endpoint Security, Physical & Environmental Security, Privacy, Risk Management, Vulnerability & Patch Management, and more.

---

### Continuous Monitoring

| Tool | Data Source | Key Metrics |
|---|---|---|
| **BitSight** | Passive internet scanning, sinkhole data | Security rating (250–900), risk vectors (patching cadence, DKIM/SPF, open ports, malware) |
| **SecurityScorecard** | Similar passive scanning | Letter grade A–F across 10 factor groups |
| **RiskRecon** | Asset discovery + configuration analysis | Issue severity and density by domain |

**Interpretation**: A drop of 50+ points (BitSight) or two letter grades (SecurityScorecard) within 30 days is a material event requiring immediate vendor outreach.

**Alert triggers**: New critical CVE on vendor infrastructure, ransomware infection detected via sinkhole, exposed credentials on paste sites, significant score drop, breach news.

---

### Contract Security Requirements

Key security provisions to include in vendor contracts:

| Clause | Requirement |
|---|---|
| Security exhibit / Addendum | Baseline security controls the vendor must maintain throughout the relationship |
| Data Processing Agreement (DPA) | GDPR/CCPA required; governs lawful basis, data subject rights, subprocessor obligations |
| SLA | Uptime guarantees, security incident response SLAs (e.g., notify within 24/48/72 hours) |
| Audit rights | Right to audit vendor security controls annually, or upon a security incident |
| Breach notification | Vendor must notify customer within defined timeframe (align to regulatory requirements: 72 hours for GDPR) |
| Insurance minimums | Cyber liability (e.g., $5M+), general liability, E&O/professional liability |
| Right to terminate | Termination for cause if vendor fails to remediate critical security findings within defined period |
| Data return & destruction | Upon contract end, vendor must return or certify destruction of all customer data within 30/60/90 days |
| Subprocessor restrictions | Vendor cannot engage new subprocessors without prior written consent |

---

## Audit Management

### Internal Audit Program

**Audit universe**: comprehensive catalog of all auditable entities (processes, systems, business units, controls). Updated annually.

**Annual audit plan**:
- Risk-based prioritization: higher-risk areas audited more frequently
- Inputs: risk register, prior audit findings, regulatory requirements, significant changes, management requests
- Approved by Audit Committee

---

### Audit Lifecycle

```
Planning → Fieldwork → Reporting → Remediation Tracking → Closure
   ↓           ↓           ↓               ↓                 ↓
Scope       Evidence    Draft report   Management         Final report
definition  collection  issued         response due       issued; finding
+ timeline  + testing   for comment    + remediation      closed upon
                                       plan               evidence review
```

**Planning outputs**: audit scope memo, audit program (test steps), stakeholder notification, evidence request list.

**Fieldwork timing**: typical IT audit = 2–4 weeks fieldwork; GRC/compliance audit = 4–8 weeks.

---

### Evidence Collection

| Evidence Type | Examples |
|---|---|
| **Policy documents** | Approved policies with version dates, CISO/board approval signatures |
| **Configuration screenshots** | Firewall rules, MFA settings, encryption configurations |
| **System-generated reports** | Access review reports, scan results, log exports |
| **Sample selections** | Random sample of change tickets, access provisioning records |
| **Interviews** | Process walkthrough notes, signed by interviewee |
| **Observation** | Auditor-witnessed process execution (e.g., watching an access review) |

---

### Control Testing Types

| Type | Method | Example |
|---|---|---|
| **Inquiry** | Ask the control owner how the control works | Interview the system admin about patch deployment process |
| **Observation** | Watch the control being performed | Observe a security awareness training session |
| **Inspection (Walkthrough)** | Review documentation and artifacts | Examine change management tickets for approval evidence |
| **Re-performance** | Independently re-execute the control | Re-run a vulnerability scan and compare to management's results |

Stronger evidence comes from lower levels of reliance on management inquiry. Re-performance > Observation > Inspection > Inquiry.

---

### Finding Classification

| Severity | Definition | Remediation Timeline |
|---|---|---|
| **Critical** | Immediate risk of material breach, regulatory violation, or significant financial loss | Immediate (0–30 days) |
| **High** | Significant control failure with high likelihood and impact | 30–60 days |
| **Medium** | Control weakness with moderate risk; compensating controls may exist | 60–90 days |
| **Low** | Minor deficiency; low risk; best practice improvement | 90–180 days |
| **Informational** | Observation or improvement opportunity; no control failure | No required deadline |

---

### Audit Tracking

**Finding management workflow**:
1. Draft finding issued to management for response
2. Management response: accept finding + remediation plan, or dispute with evidence
3. Agreed remediation plan entered into tracking system with owner and due date
4. Evidence of remediation collected by auditor at due date
5. Finding closed upon satisfactory evidence review; escalated if overdue

---

### GRC Platform Tools

| Tool | Type | Strengths | Best For |
|---|---|---|---|
| **ServiceNow GRC** | Enterprise GRC | Full integration with ITSM, deep customization | Large enterprises with existing ServiceNow |
| **Archer (RSA)** | Enterprise GRC | Mature risk quantification, highly configurable | Financial services, regulated industries |
| **LogicGate** | Mid-market GRC | Modern UX, flexible workflow builder | Mid-size organizations |
| **Vanta** | Compliance automation | Native integrations, automated evidence collection | SOC 2, ISO 27001, fast-growing SaaS companies |
| **Drata** | Compliance automation | 200+ integrations, continuous compliance monitoring | SOC 2, ISO 27001, HIPAA for startups/scale-ups |
| **Secureframe** | Compliance automation | Rapid time-to-report, questionnaire automation | SOC 2, HIPAA, PCI DSS for SMBs |
| **Tugboat Logic** | Policy & compliance | Policy library, readiness assessments | ISO 27001 readiness; acquired by OneTrust |

---

## Exception Management

### Exception Request Components

| Field | Description |
|---|---|
| Exception ID | Unique identifier (e.g., EXC-2025-018) |
| Requestor | Name, title, business unit |
| Control Being Excepted | Reference to specific policy/standard control |
| Business Justification | Why compliance is not feasible (technical, business, cost constraints) |
| Risk Assessment | Inherent risk without the control; likelihood and impact |
| Compensating Controls | Alternative controls reducing risk to an acceptable level |
| Duration | Time-bounded expiry date (no permanent exceptions without annual re-approval) |
| Approver | Authority based on risk level |
| Review Date | Date for exception renewal review |

---

### Approval Authority by Risk Level

| Risk Level | Approval Required |
|---|---|
| **Low** | Direct manager or department head |
| **Medium** | CISO or VP of Security |
| **High** | CISO + Risk Committee |
| **Critical** | Board of Directors or Audit Committee |

---

### Exception Register Maintenance

- **Quarterly review**: exception register reviewed to identify expired or overdue exceptions
- **Escalation**: exceptions not renewed by expiry date are escalated to the original approver's management chain
- **Metrics**: number of open exceptions by risk level and business unit; average exception duration; exceptions overdue for renewal
- **Trend reporting**: increasing exception count in a business unit may signal systemic control design issues

---

## Framework Mappings

| GRC Domain | NIST 800-53 | ISO 27001:2022 | SOC 2 TSC |
|---|---|---|---|
| Security program governance | PM-1, PM-2, PM-9 | Clause 5 (Leadership), 6 (Planning) | CC1.1–CC1.5 |
| Risk management process | RA-1 through RA-9 | Clause 6.1, Annex A 5.7, 8.8 | CC3.1–CC3.4, CC9.1 |
| Compliance management | CA-1 through CA-9 | Clause 9 (Performance Evaluation) | CC2.1–CC2.3 |
| Third-party risk | SA-9, SA-12, SR-1 through SR-12 | A.5.19–5.22, A.5.23 | CC9.2 |
| Audit and assessment | CA-2, CA-7, CA-8 | Clause 9.2 (Internal Audit) | CC4.1–CC4.2 |
| Exception management | PM-9, CA-5 | Clause 6.1.3 (Risk Treatment) | CC3.2 |
| Policy management | PL-1, PL-2 | Clause 5.2, Annex A 5.1, 5.2 | CC1.3 |

---

*Last updated: 2026-04-21 | TeamStarWolf Cybersecurity Reference Library*
