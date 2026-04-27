# GRC Compliance Reference

> Comprehensive reference for Governance, Risk & Compliance (GRC) — covering foundational concepts, major frameworks, automation tooling, and practical implementation guidance.

---

## Table of Contents

1. [GRC Fundamentals](#1-grc-fundamentals)
2. [NIST Cybersecurity Framework (CSF) 2.0](#2-nist-cybersecurity-framework-csf-20)
3. [OSCAL — Open Security Controls Assessment Language](#3-oscal--open-security-controls-assessment-language)
4. [ComplianceAsCode / OpenSCAP](#4-complianceascode--openscap)
5. [CIS Controls v8](#5-cis-controls-v8)
6. [PCI DSS v4.0](#6-pci-dss-v40)
7. [HIPAA / HITECH Security Rule](#7-hipaa--hitech-security-rule)
8. [SOC 2 Type II](#8-soc-2-type-ii)
9. [ISO 27001:2022](#9-iso-270012022)
10. [GRC Tools and Automation](#10-grc-tools-and-automation)

---

## 1. GRC Fundamentals

### 1.1 Governance, Risk, and Compliance — Definitions

| Pillar | Definition | Primary Owner | Key Outputs |
|--------|-----------|---------------|-------------|
| **Governance** | The system of rules, practices, and processes by which an organization is directed and controlled — including policies, accountability structures, and strategic alignment | Board / C-Suite | Policies, charters, organizational structures, oversight committees |
| **Risk** | The potential for loss, harm, or missed opportunity resulting from an event or circumstance; risk management is the process of identifying, assessing, treating, and monitoring risks | CISO / CRO | Risk register, risk appetite statement, risk treatment plans |
| **Compliance** | Adherence to applicable laws, regulations, standards, and contractual obligations | Compliance Officer / Legal | Compliance calendar, audit evidence, gap assessments, remediation plans |

**Why GRC matters:** Organizations that silo governance, risk, and compliance end up with duplicated effort, inconsistent control testing, and gaps where risks fall between teams. Integrated GRC aligns security spend to actual risk and regulatory obligation.

### 1.2 GRC Program Components

A mature GRC program includes the following components:

```
GRC Program
├── Policy Framework
│   ├── Information Security Policy (top-level)
│   ├── Acceptable Use Policy
│   ├── Data Classification Policy
│   ├── Access Control Policy
│   ├── Incident Response Policy
│   ├── Business Continuity / DR Policy
│   └── Vendor Management Policy
│
├── Risk Management Program
│   ├── Risk Appetite Statement
│   ├── Risk Register
│   ├── Risk Assessment Methodology
│   ├── Risk Treatment Plans
│   └── Key Risk Indicators (KRIs)
│
├── Compliance Program
│   ├── Regulatory Inventory (applicable laws/regs)
│   ├── Compliance Calendar
│   ├── Control Mapping Matrix
│   ├── Evidence Repository
│   └── Audit Management
│
├── Control Framework
│   ├── Control Library (mapped to NIST/ISO/CIS)
│   ├── Control Ownership Assignments
│   ├── Control Testing Procedures
│   └── Continuous Control Monitoring
│
└── Third-Party Risk Management (TPRM)
    ├── Vendor Inventory
    ├── Vendor Risk Tiering
    ├── Vendor Assessment Questionnaires
    └── Ongoing Monitoring
```

### 1.3 Risk Appetite vs. Risk Tolerance

| Concept | Definition | Example |
|---------|-----------|---------|
| **Risk Appetite** | The broad-level amount of risk the organization is willing to accept in pursuit of its objectives — a strategic statement | "We have a low appetite for risks that could result in exposure of customer PII" |
| **Risk Tolerance** | The acceptable variation around risk appetite — operational bounds for specific risk categories | "We tolerate no more than 4 hours of unplanned downtime per quarter for Tier 1 systems" |
| **Risk Threshold** | The point at which a risk must be escalated or treated immediately | "Any risk with a residual score above 15 must be reported to the CISO within 24 hours" |
| **Risk Capacity** | The maximum amount of risk the organization can absorb before it threatens viability | Determined by capital reserves, insurance, legal exposure limits |

**Practical tip:** Risk appetite statements should be tied to business objectives. A startup in growth mode may have high appetite for operational risk but near-zero appetite for reputational/regulatory risk.

### 1.4 Risk Register Structure

A comprehensive risk register captures the full risk life cycle. Recommended columns:

| Field | Description | Example Value |
|-------|-------------|---------------|
| **Risk ID** | Unique identifier | RISK-2024-047 |
| **Asset** | System, process, or data affected | Customer PII database (prod-db-01) |
| **Threat** | The threat event or actor | Ransomware / external attacker |
| **Vulnerability** | The weakness being exploited | Unpatched OS (CVE-2024-XXXX), no MFA on RDP |
| **Likelihood** | Probability of occurrence (1–5 qualitative or % quantitative) | 4 (High) |
| **Impact** | Business impact if realized (1–5 or financial) | 5 (Critical) — regulatory fines + data breach costs |
| **Inherent Risk Score** | Likelihood × Impact before controls | 20 (Critical) |
| **Existing Controls** | Controls currently in place | EDR, daily backups, network segmentation |
| **Control Effectiveness** | How well controls reduce likelihood/impact | Partial (backups not tested, RDP exposed) |
| **Residual Risk Score** | Risk remaining after controls | 12 (High) |
| **Risk Owner** | Accountable individual | VP of Engineering |
| **Treatment Decision** | Accept / Mitigate / Transfer / Avoid | Mitigate |
| **Treatment Plan** | Specific remediation actions and due dates | Patch OS by 2024-12-01, enforce MFA on all remote access by 2024-11-15 |
| **Target Residual Score** | Risk score after planned treatment | 6 (Medium) |
| **Review Date** | Next scheduled review | Quarterly |
| **Status** | Open / In Remediation / Closed | In Remediation |

### 1.5 Risk Scoring Methodologies

#### Qualitative — 5x5 Risk Matrix

```
       |  1-Negligible  |  2-Minor  |  3-Moderate  |  4-Major  |  5-Catastrophic
-------+----------------+-----------+--------------+-----------+-----------------
5-     |      5         |    10     |      15      |    20     |       25
Almost |   MEDIUM       |  HIGH     |    HIGH      |  CRITICAL |    CRITICAL
Certain|                |           |              |           |
-------+----------------+-----------+--------------+-----------+-----------------
4-     |      4         |     8     |      12      |    16     |       20
Likely |    LOW         |  MEDIUM   |    HIGH      |  CRITICAL |    CRITICAL
-------+----------------+-----------+--------------+-----------+-----------------
3-     |      3         |     6     |       9      |    12     |       15
Poss.  |   LOW          |  MEDIUM   |    MEDIUM    |   HIGH    |     HIGH
-------+----------------+-----------+--------------+-----------+-----------------
2-     |      2         |     4     |       6      |     8     |       10
Unlikly|   LOW          |   LOW     |    MEDIUM    |  MEDIUM   |     HIGH
-------+----------------+-----------+--------------+-----------+-----------------
1-Rare |      1         |     2     |       3      |     4     |        5
       |   LOW          |   LOW     |    LOW       |   LOW     |     MEDIUM
```

**Score Thresholds:**
- 1-4: LOW — Accept or monitor; document rationale
- 5-9: MEDIUM — Treat within 90 days; assign owner
- 10-16: HIGH — Treat within 30 days; escalate to CISO
- 17-25: CRITICAL — Immediate treatment required; executive notification

#### Quantitative — FAIR Model (Factor Analysis of Information Risk)

FAIR decomposes risk into financially measurable components:

```
Risk = Loss Event Frequency (LEF) x Loss Magnitude (LM)

LEF = Threat Event Frequency (TEF) x Vulnerability (Vuln%)
    Where:
      TEF = Contact Frequency x Probability of Action
      Vuln% = 1 - Control Strength / Threat Capability

LM = Primary Loss + Secondary Loss
   Primary Loss  = Productivity + Response + Replacement costs
   Secondary Loss = Reputation + Regulatory + Competitive + Legal costs
```

**FAIR Analysis Steps:**
1. Identify the asset and threat scenario
2. Estimate Threat Event Frequency (events/year)
3. Estimate Threat Capability (percentile vs. controls)
4. Estimate Control Strength (NIST/CIS maturity level -> percentile)
5. Calculate Vulnerability %
6. Estimate Primary and Secondary Loss Magnitudes (min/most likely/max)
7. Run Monte Carlo simulation (1,000-10,000 iterations)
8. Output: Loss Exceedance Curve with 10th/50th/90th percentile values

**FAIR Tools:** RiskLens (commercial), PyFAIR (open-source Python library), FAIR-U (free training tool)

### 1.6 Control Types

| Type | Definition | Examples |
|------|-----------|---------|
| **Preventive** | Stop an incident before it occurs | Firewalls, MFA, encryption, access controls, code reviews |
| **Detective** | Identify an incident during or after it occurs | SIEM, IDS, audit logs, anomaly detection, file integrity monitoring |
| **Corrective** | Restore systems after an incident | Incident response procedures, backup restoration, patch management |
| **Deterrent** | Discourage threat actors from attempting an attack | Security awareness training, legal notices, visible cameras, warning banners |
| **Compensating** | Alternative controls when primary controls are not feasible | Enhanced logging + monitoring instead of MFA for legacy systems; network segmentation where patching is not possible |
| **Directive** | Mandate behavior through policy or procedure | Security policies, acceptable use agreements, compliance training requirements |

### 1.7 Control Frameworks Comparison

| Framework | Primary Use | Controls Count | Prescriptiveness | Certifiable? | Best For |
|-----------|------------|----------------|-----------------|--------------|----------|
| **NIST CSF 2.0** | Risk-based cybersecurity program | ~100 subcategories | Low (outcome-based) | No | Most organizations; flexible starting point |
| **NIST SP 800-53 r5** | Federal/FedRAMP compliance | 1,189 controls | High (very detailed) | Via FedRAMP/FISMA | Federal agencies; FedRAMP cloud providers |
| **CIS Controls v8** | Prioritized cyber hygiene | 153 safeguards across 18 controls | Medium | Via CIS CSAT | SMBs and enterprises wanting prioritized approach |
| **ISO 27001:2022** | ISMS certification | 93 Annex A controls | Medium | Yes (formal cert) | Global enterprises; customer-facing trust |
| **SOC 2** | Service organization trust | ~60 Trust Service Criteria points | Medium | Yes (audit report) | SaaS companies; vendor assessment |
| **PCI DSS v4.0** | Payment card security | 12 requirements / 250+ sub-requirements | High | Yes (QSA audit/SAQ) | Any entity processing card payments |
| **HIPAA Security Rule** | Healthcare data | 18 standards / 36 specifications | Medium | No (enforcement-based) | Healthcare providers, payers, BAs |
| **CMMC 2.0** | Defense contractor cybersecurity | 110-320 practices (L1-L3) | High | Yes (C3PAO for L2/L3) | DoD contractors |
| **GDPR** | EU personal data privacy | Principles + 99 articles | Medium-High | No (regulatory) | Any org processing EU resident data |

---

## 2. NIST Cybersecurity Framework (CSF) 2.0

### 2.1 Overview

Released February 2024, CSF 2.0 expands the framework beyond critical infrastructure to all organizations. The most significant addition is the **Govern** function, which elevates cybersecurity governance as a first-class discipline alongside the original five functions.

**Key CSF 2.0 Documents:**
- Framework Core: `NIST.CSWP.29.pdf`
- Implementation Examples: `NIST.CSWP.32.pdf`
- Quick-Start Guides (Enterprise, SMB, Communities)
- Reference Tool: `https://csf.tools/`

### 2.2 Six Functions

#### GV — Govern (NEW in 2.0)

The Govern function establishes and monitors the organization's cybersecurity risk management strategy, expectations, and policy.

| Category | Category ID | Description |
|----------|-------------|-------------|
| Organizational Context | GV.OC | Mission, stakeholder expectations, dependencies understood |
| Risk Management Strategy | GV.RM | Risk appetite, tolerance, and strategy established |
| Roles and Responsibilities | GV.RR | Cybersecurity roles defined; accountability assigned |
| Policy | GV.PO | Cybersecurity policy established and communicated |
| Oversight | GV.OV | Results of cybersecurity risk management reviewed |
| Cybersecurity Supply Chain Risk Mgmt | GV.SC | SCRM integrated into enterprise risk management |

#### ID — Identify

| Category | Category ID | Key Subcategories |
|----------|-------------|-------------------|
| Asset Management | ID.AM | Hardware/software inventory; data flows; network maps; criticality classification |
| Risk Assessment | ID.RA | Threat intelligence; vulnerability identification; risk scoring; risk register maintenance |
| Improvement | ID.IM | Lessons learned; improvements identified from incidents and exercises |

**Key Subcategory Examples:**
- ID.AM-01: Software assets inventoried
- ID.AM-02: Hardware assets inventoried
- ID.AM-07: Data flows mapped (NEW in 2.0)
- ID.RA-01: Vulnerabilities identified and documented
- ID.RA-09: Third-party component vulnerabilities assessed (supply chain)

#### PR — Protect

| Category | Category ID | Key Subcategories |
|----------|-------------|-------------------|
| Identity Management and Access Control | PR.AA | MFA; least privilege; identity lifecycle; remote access |
| Awareness and Training | PR.AT | Security awareness; role-based training; privileged user training |
| Data Security | PR.DS | Encryption at rest/transit; DLP; data retention; backups |
| Platform Security | PR.PS | Hardening baselines; patch management; secure configuration; software integrity |
| Technology Infrastructure Resilience | PR.IR | Network segmentation; redundancy; capacity management |

#### DE — Detect

| Category | Category ID | Key Subcategories |
|----------|-------------|-------------------|
| Continuous Monitoring | DE.CM | Network monitoring; endpoint monitoring; user activity; log aggregation; threat intelligence integration |
| Adverse Event Analysis | DE.AE | Alerts analyzed; anomalies correlated; incident declared when appropriate |

#### RS — Respond

| Category | Category ID | Key Subcategories |
|----------|-------------|-------------------|
| Incident Management | RS.MA | Incident response plan; incident classification; escalation procedures |
| Incident Analysis | RS.AN | Forensic analysis; root cause investigation; impact assessment |
| Incident Response Reporting and Communication | RS.CO | Coordination with stakeholders; regulatory notification |
| Incident Mitigation | RS.MI | Containment actions; eradication procedures |

#### RC — Recover

| Category | Category ID | Key Subcategories |
|----------|-------------|-------------------|
| Incident Recovery Plan Execution | RC.RP | Recovery objectives (RTO/RPO); restoration procedures; validation |
| Incident Recovery Communication | RC.CO | Recovery updates to stakeholders; reputation management |

### 2.3 CSF Tiers

CSF Tiers describe the degree to which an organization's cybersecurity risk management practices exhibit the characteristics of the framework. Tiers are NOT maturity levels — they describe practices, not scores.

| Tier | Name | Characteristics |
|------|------|----------------|
| **Tier 1** | Partial | Risk management is ad hoc and reactive. No formal cybersecurity program. Little awareness of organizational risk. |
| **Tier 2** | Risk Informed | Risk management practices approved by management but not enterprise-wide policy. Awareness exists but not consistently implemented. Some external collaboration. |
| **Tier 3** | Repeatable | Formal cybersecurity policies exist, are enforced, and regularly updated. Risk management integrated into enterprise risk. Threat intelligence shared. |
| **Tier 4** | Adaptive | Continuous improvement based on lessons learned and predictive indicators. Active participation in threat intelligence sharing. Supply chain risk fully integrated. |

**Tier Selection Guidance:** Most organizations should target Tier 2 or 3. Tier 4 is appropriate for critical infrastructure or organizations with mature cyber programs. Moving from Tier 1 to Tier 2 often has the highest ROI.

### 2.4 CSF Profiles

**Current Profile:** Documents the current state of cybersecurity outcomes the organization is achieving.

**Target Profile:** Documents the desired state of outcomes — what the organization wants to achieve, based on risk appetite and business objectives.

**Gap Analysis:** The difference between Current and Target Profiles drives the remediation roadmap.

```
Profile Development Process:
1. Identify scope (business unit, system, enterprise-wide)
2. Select applicable categories from CSF Core
3. Prioritize categories based on business objectives and risk appetite
4. Document Current Profile (self-assessment or third-party assessment)
5. Define Target Profile (what "good" looks like for each category)
6. Perform gap analysis
7. Create prioritized action plan
8. Implement and track progress
9. Update profiles annually or after major changes
```

### 2.5 CSF 2.0 New Additions

**Govern Function:** Elevates cybersecurity governance; previously embedded in framework implementation guidance only. Now explicitly includes supply chain risk management (GV.SC).

**Supply Chain Risk Management (SCRM):** GV.SC contains 10 subcategories covering:
- Identifying and prioritizing suppliers
- Contractual requirements for cybersecurity
- Supplier risk assessments
- Incident notification from suppliers
- Due diligence for critical software

**Implementation Examples:** CSF 2.0 ships with concrete implementation examples for each subcategory — more practical than CSF 1.1.

**Community Profiles:** NIST is publishing sector-specific profiles (healthcare, financial services, etc.) as reference baselines.

### 2.6 CSF Mapping to CIS Controls v8 and ISO 27001

| CSF Function | CSF Category | CIS Controls v8 | ISO 27001:2022 Annex A |
|--------------|--------------|-----------------|------------------------|
| Govern | GV.OC | CIS 1, 2 (inventory context) | A.5.1, A.5.2 (policies) |
| Govern | GV.RM | — | A.6.1 (org roles) |
| Identify | ID.AM | CIS 1 (inventory/control of assets), CIS 2 | A.5.9 (asset inventory) |
| Identify | ID.RA | CIS 12 (network monitoring), CIS 7 (vuln mgmt) | A.8.8 (vuln mgmt), A.6.1.2 (risk assessment) |
| Protect | PR.AA | CIS 5 (account mgmt), CIS 6 (access control) | A.8.2 (privileged access), A.8.3 (info access) |
| Protect | PR.DS | CIS 3 (data protection), CIS 11 (data recovery) | A.8.24 (encryption), A.8.13 (backup) |
| Protect | PR.PS | CIS 4 (secure config), CIS 7 (vuln mgmt) | A.8.9 (config mgmt), A.8.19 (software install) |
| Detect | DE.CM | CIS 8 (audit logs), CIS 13 (network monitoring) | A.8.15 (logging), A.8.16 (monitoring) |
| Respond | RS.MA | CIS 17 (incident response) | A.5.24 (IR planning), A.5.26 (IR) |
| Recover | RC.RP | CIS 11 (data recovery) | A.5.29 (BCP), A.5.30 (ICT readiness) |

---

## 3. OSCAL — Open Security Controls Assessment Language

### 3.1 What is OSCAL?

OSCAL (Open Security Controls Assessment Language) is a NIST-developed standard for expressing security control catalogs, profiles, system security plans, assessment plans, assessment results, and plans of action and milestones in a machine-readable format (XML, JSON, or YAML).

**Problem OSCAL Solves:** Security documentation is traditionally in Word/Excel/PDF — unstructured, hard to validate, not reusable. OSCAL makes compliance documentation machine-readable, enabling automation, consistency, and cross-framework mapping.

**Governance:** NIST maintains OSCAL at `https://pages.nist.gov/OSCAL/`
**Repository:** `https://github.com/usnistgov/OSCAL`
**Current Release:** OSCAL v1.1.x

### 3.2 OSCAL Models

OSCAL defines a layered set of models that cover the full compliance life cycle:

```
OSCAL Model Hierarchy

Catalog (lowest layer)
  Defines security controls (e.g., NIST 800-53)
  Format: catalog.json / catalog.xml

Profile
  Selects/tailors controls from one or more catalogs
  Produces a "baseline" (e.g., NIST 800-53 Moderate)
  Format: profile.json

Component Definition
  Documents how a software/hardware component implements controls
  Used by vendors to ship pre-mapped compliance evidence
  Format: component-definition.json

System Security Plan (SSP)
  Documents how a system implements the baseline controls
  References components from Component Definitions
  Format: system-security-plan.json

Assessment Plan (AP)
  Defines how the SSP will be assessed
  Lists activities, test methods, objectives
  Format: assessment-plan.json

Assessment Results (AR)
  Documents findings from executing the Assessment Plan
  Links findings to specific controls and objectives
  Format: assessment-results.json

Plan of Action and Milestones (POA&M)
  Tracks identified weaknesses and remediation plans
  Links to Assessment Results findings
  Format: plan-of-action-and-milestones.json
```

### 3.3 OSCAL Catalog Structure (NIST 800-53 Example)

```json
{
  "catalog": {
    "uuid": "74c8ba1e-5cd4-4ad1-bbfd-d888e2f6c724",
    "metadata": {
      "title": "NIST Special Publication 800-53 Revision 5",
      "version": "5.1.1"
    },
    "groups": [
      {
        "id": "ac",
        "title": "Access Control",
        "controls": [
          {
            "id": "ac-1",
            "title": "Policy and Procedures",
            "parts": [
              {
                "id": "ac-1_smt",
                "name": "statement",
                "prose": "Develop, document, and disseminate..."
              }
            ],
            "params": [
              {
                "id": "ac-01_odp.01",
                "label": "organization-defined personnel or roles"
              }
            ]
          }
        ]
      }
    ]
  }
}
```

### 3.4 NIST OSCAL CLI

The `oscal-cli` tool provides command-line utilities for validating and converting OSCAL content.

**Installation:**
```bash
# Download from GitHub releases
wget https://github.com/usnistgov/oscal-cli/releases/latest/download/oscal-cli.zip
unzip oscal-cli.zip
chmod +x oscal-cli

# Or via brew (macOS)
brew install usnistgov/oscal-cli/oscal-cli
```

**Key Commands:**
```bash
# Validate an OSCAL document
oscal-cli validate --file ssp.json

# Convert between formats (JSON <-> XML <-> YAML)
oscal-cli convert --file catalog.xml --to json --output catalog.json

# Resolve a profile (apply selections/modifications) to a resolved catalog
oscal-cli profile resolve --profile nist-800-53-moderate-profile.json --output resolved-catalog.json

# Validate against a specific metaschema
oscal-cli metaschema validate --metaschema oscal_catalog_metaschema.xml --file my-catalog.xml
```

### 3.5 compliance-trestle (IBM/OSCAL Python Tool)

`compliance-trestle` is an open-source Python CLI and SDK for OSCAL content authoring, transformation, and compliance automation.

**Repository:** `https://github.com/oscal-compass/compliance-trestle`
**Install:** `pip install compliance-trestle`

**Key Commands:**
```bash
# Initialize a trestle workspace
trestle init --verbose

# Import an existing OSCAL catalog (e.g., NIST 800-53)
trestle import -f nist-800-53-rev5-catalog.json -o nist-800-53-rev5

# Import and author profile
trestle import -f moderate-profile.json -o moderate-profile
trestle author profile edit -n moderate-profile

# Generate SSP template from profile
trestle author ssp generate -p moderate-profile -o my-system-ssp -s ssp-sections.md

# Assemble SSP markdown into OSCAL JSON
trestle author ssp assemble -n my-system-ssp -o my-system-ssp-assembled

# Validate SSP
trestle validate -a -t system-security-plans

# Generate component definition
trestle author component-definition generate -c my-component -p moderate-profile

# Create POA&M from assessment results
trestle author poam generate -a assessment-results-name -o my-poam
```

**Trestle Workspace Structure:**
```
trestle-workspace/
├── .trestle/
│   └── config.ini
├── catalogs/
│   └── nist-800-53-rev5/
│       └── catalog.json
├── profiles/
│   └── moderate-profile/
│       └── profile.json
├── component-definitions/
├── system-security-plans/
│   └── my-system-ssp/
│       ├── system-security-plan.json
│       └── ssp/
│           ├── ac/
│           │   ├── ac-1.md
│           │   └── ac-2.md
│           └── (control implementation markdown per control)
├── assessment-plans/
├── assessment-results/
└── plan-of-action-and-milestones/
```

### 3.6 Automating SSP Generation Workflow

```python
# Example: Auto-generate SSP stubs for all controls in a profile
import subprocess

WORKSPACE = "/path/to/trestle-workspace"
PROFILE = "nist-800-53-moderate"
SSP_NAME = "my-system-ssp"

# 1. Import NIST 800-53 catalog
subprocess.run(["trestle", "import", "-f",
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
    "-o", "nist-800-53-rev5"], cwd=WORKSPACE)

# 2. Import moderate profile
subprocess.run(["trestle", "import", "-f",
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
    "-o", PROFILE], cwd=WORKSPACE)

# 3. Generate SSP
subprocess.run(["trestle", "author", "ssp", "generate",
    "-p", PROFILE, "-o", SSP_NAME, "--force"], cwd=WORKSPACE)

# 4. Assemble and validate
subprocess.run(["trestle", "author", "ssp", "assemble",
    "-n", SSP_NAME, "-o", f"{SSP_NAME}-assembled"], cwd=WORKSPACE)
subprocess.run(["trestle", "validate", "-a", "-t",
    "system-security-plans"], cwd=WORKSPACE)

print(f"SSP generated at {WORKSPACE}/system-security-plans/{SSP_NAME}/")
```

### 3.7 Key OSCAL Resources

| Resource | URL |
|----------|-----|
| NIST OSCAL Website | https://pages.nist.gov/OSCAL/ |
| OSCAL GitHub | https://github.com/usnistgov/OSCAL |
| OSCAL Content (catalogs/profiles) | https://github.com/usnistgov/oscal-content |
| compliance-trestle | https://github.com/oscal-compass/compliance-trestle |
| OSCAL CLI | https://github.com/usnistgov/oscal-cli |
| FedRAMP OSCAL Templates | https://github.com/GSA/fedramp-automation |
| OSCAL Reference Tool | https://pages.nist.gov/OSCAL/reference/ |

---

## 4. ComplianceAsCode / OpenSCAP

### 4.1 What is ComplianceAsCode?

ComplianceAsCode (formerly SCAP Security Guide / SSG) is an open-source project that produces machine-readable security content — SCAP DataStreams, Ansible playbooks, Bash scripts, and Kubernetes remediations — from a single source of truth.

**Repository:** `https://github.com/ComplianceAsCode/content`
**Supported Platforms:** RHEL 7/8/9, CentOS, Fedora, Ubuntu 18/20/22/24, Debian, Windows Server, OCP/Kubernetes, macOS

### 4.2 Repository Structure

```
content/
├── products/              # Per-platform content
│   ├── rhel9/
│   │   ├── profiles/      # XCCDF profile YAML files (cis, stig, pci-dss, hipaa)
│   │   └── product.yml
│   ├── ubuntu2204/
│   └── windows10/
├── controls/              # Control files mapping to CIS/NIST/DISA controls
│   ├── cis_rhel9.yml
│   └── nist_800-53.yml
├── shared/
│   ├── checks/            # OVAL check definitions (XML)
│   ├── fixes/             # Remediation content
│   │   ├── ansible/       # Ansible task files
│   │   ├── bash/          # Bash remediation scripts
│   │   └── powershell/    # PowerShell remediations
│   └── templates/         # Jinja2 templates for check/fix generation
├── build/                 # CMake build output directory
├── CMakeLists.txt
└── build_product         # Convenience build script
```

### 4.3 SCAP Content Types

| Component | Format | Purpose |
|-----------|--------|---------|
| **XCCDF** | XML | Checklist format — defines rules, profiles, benchmark structure |
| **OVAL** | XML | Open Vulnerability and Assessment Language — machine-readable checks |
| **DataStream** | XML | Combined XCCDF + OVAL in a single file for distribution |
| **CPE Dictionary** | XML | Platform identification for conditional applicability |
| **OCIL** | XML | Questionnaire-based checks for items that cannot be automated |

### 4.4 Building Profiles with CMake

```bash
# Install build dependencies (RHEL/Fedora)
sudo dnf install cmake openscap-utils python3-pyyaml python3-jinja2 ansible

# Clone repository
git clone https://github.com/ComplianceAsCode/content.git
cd content

# Create build directory
mkdir build && cd build

# Configure for specific product
cmake -DPRODUCT=rhel9 ..

# Build all profiles for product
make -j4

# Build specific profile DataStream
make rhel9-ds            # Full DataStream
make rhel9-xccdf         # XCCDF only

# Build all products
cmake -DALL_PRODUCTS=ON ..
make -j8
```

**Build Outputs (in `build/`):**
```
build/
├── ssg-rhel9-ds.xml              # Full DataStream (use this for scanning)
├── ssg-rhel9-xccdf.xml           # XCCDF benchmark
├── ssg-rhel9-oval.xml            # OVAL checks only
├── ssg-rhel9-cpe-dictionary.xml  # CPE dictionary
└── guides/                        # Human-readable HTML guides per profile
    ├── ssg-rhel9-guide-cis.html
    ├── ssg-rhel9-guide-stig.html
    └── ssg-rhel9-guide-pci-dss.html
```

### 4.5 Available Profiles

| Profile ID | Standard | Platforms | Notes |
|------------|----------|-----------|-------|
| `cis` | CIS Benchmark Level 1+2 | RHEL, Ubuntu, Fedora, Windows | Most widely used |
| `cis_server_l1` | CIS Benchmark Level 1 (Server) | RHEL, Ubuntu | Less disruptive |
| `stig` | DISA STIG | RHEL, Ubuntu, Windows | DoD requirement |
| `stig_gui` | DISA STIG with GUI | RHEL | For workstations |
| `pci-dss` | PCI DSS v3.2.1/v4.0 | RHEL, Ubuntu | Payment card requirements |
| `hipaa` | HIPAA Security Rule | RHEL | Healthcare safeguards |
| `e8` | Essential Eight | RHEL, Ubuntu | Australian ASD framework |
| `ospp` | OSPP / Common Criteria | RHEL | Evaluated configuration |
| `cui` | NIST 800-171 / CUI protection | RHEL | Defense contractor use |
| `anssi_bp28_high` | ANSSI BP-028 High | RHEL | French government |

### 4.6 Scanning with OpenSCAP

```bash
# Install OpenSCAP scanner
sudo dnf install openscap-scanner scap-security-guide   # RHEL/Fedora
sudo apt install libopenscap8 scap-security-guide        # Ubuntu/Debian

# List available profiles in a DataStream
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Run compliance scan — CIS profile on RHEL 9
oscap xccdf eval   --profile xccdf_org.ssgproject.content_profile_cis   --results scan-results.xml   --report scan-report.html   /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Run STIG scan
oscap xccdf eval   --profile xccdf_org.ssgproject.content_profile_stig   --results stig-results.xml   --report stig-report.html   /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Generate remediation Ansible playbook from scan results
oscap xccdf generate fix   --fix-type ansible   --output remediation-playbook.yml   --result-id ""   scan-results.xml

# Generate remediation Bash script from scan results
oscap xccdf generate fix   --fix-type bash   --output remediation.sh   scan-results.xml

# Scan a remote host via SSH
oscap-ssh root@target-host 22 xccdf eval   --profile xccdf_org.ssgproject.content_profile_cis   --results remote-results.xml   --report remote-report.html   /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Scan a Docker container image
oscap-docker image rhel9:latest xccdf eval   --profile xccdf_org.ssgproject.content_profile_cis   --report container-report.html   /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

### 4.7 Generating Remediation Content

ComplianceAsCode can generate remediation content directly from build:

```bash
# Generate Ansible playbook for CIS profile (RHEL 9) at build time
cd build
cmake -DPRODUCT=rhel9 -DBUILD_REMEDIATIONS=ON ..
make rhel9-playbook-cis

# Output: build/rhel9/playbooks/ssg-rhel9-playbook-cis.yml

# Generate standalone Bash script
make rhel9-bash-cis
# Output: build/rhel9/bash/ssg-rhel9-script-cis.sh

# Generate PowerShell remediation (Windows)
cmake -DPRODUCT=windows10 ..
make windows10-powershell-stig
```

### 4.8 SCAP Workbench (GUI)

SCAP Workbench provides a graphical interface for running SCAP scans, customizing profiles, and viewing results.

```bash
# Install
sudo dnf install scap-workbench   # RHEL/Fedora
sudo apt install scap-workbench   # Ubuntu

# Launch
scap-workbench
```

**Workbench Workflow:**
1. Load DataStream file
2. Select profile from dropdown
3. Customize rules (enable/disable, change values)
4. Run scan locally or on remote host (SSH)
5. View results with pass/fail color coding
6. Export: HTML report, XCCDF results XML, Ansible playbook, Bash script
7. Save customized profile as a tailoring file (XCCDF tailoring)

### 4.9 Automating Compliance in CI/CD

```yaml
# GitLab CI example — scan container image before deploy
stages:
  - build
  - security-scan
  - deploy

scap_scan:
  stage: security-scan
  image: registry.access.redhat.com/ubi9/ubi
  script:
    - dnf install -y openscap-scanner scap-security-guide
    - oscap xccdf eval
        --profile xccdf_org.ssgproject.content_profile_cis_server_l1
        --results scan-results.xml
        --report scan-report.html
        /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
    - |
      FAIL_COUNT=$(grep -c 'result>fail<' scan-results.xml || echo 0)
      echo "Failed rules: $FAIL_COUNT"
      if [ "$FAIL_COUNT" -gt 10 ]; then exit 1; fi
  artifacts:
    paths:
      - scan-report.html
      - scan-results.xml
    when: always

# GitHub Actions example
# jobs:
#   compliance-scan:
#     runs-on: ubuntu-22.04
#     steps:
#       - name: Install OpenSCAP
#         run: sudo apt-get install -y libopenscap8 scap-security-guide
#       - name: Run CIS scan
#         run: |
#           oscap xccdf eval #             --profile xccdf_org.ssgproject.content_profile_cis_level1_server #             --results results.xml --report report.html #             /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml || true
#       - name: Upload report
#         uses: actions/upload-artifact@v3
#         with:
#           name: scap-report
#           path: report.html
```

---

## 5. CIS Controls v8

### 5.1 Overview

CIS Controls v8 (released May 2021) is a prioritized set of 18 controls with 153 safeguards organized into three Implementation Groups (IGs) based on organizational risk profile and resources.

**Key Resources:**
- Controls document: `https://www.cisecurity.org/controls/v8`
- CIS Benchmarks: `https://www.cisecurity.org/cis-benchmarks`
- CIS-CAT Pro: Automated assessment tool
- CIS WorkBench: Compliance tracking platform

### 5.2 Implementation Groups

| Group | Target Organization | Profile |
|-------|---------------------|---------|
| **IG1** | Small organizations with limited IT/security expertise and resources | Basic cyber hygiene — essential safeguards all organizations should implement |
| **IG2** | Organizations with moderate IT expertise handling sensitive data | Includes IG1 + additional safeguards for managing risk in multi-department organizations |
| **IG3** | Large organizations with significant security expertise facing sophisticated attacks | Includes IG1+2 + advanced safeguards for critical infrastructure and sensitive data |

**Safeguard counts:** IG1 = 56 safeguards; IG2 = 130 safeguards; IG3 = 153 safeguards

### 5.3 All 18 CIS Controls

| # | Control | Description |
|---|---------|-------------|
| **1** | Inventory and Control of Enterprise Assets | Actively manage all hardware assets; DHCP logging; passive discovery |
| **2** | Inventory and Control of Software Assets | Software inventory; authorized software only (allowlisting) |
| **3** | Data Protection | Data classification; secure data disposal; encryption at rest/transit; DLP; retention policies |
| **4** | Secure Configuration of Enterprise Assets and Software | Hardening baselines; secure defaults; configuration management; automated scanning |
| **5** | Account Management | Account inventory; least privilege; MFA for admin; account lifecycle management |
| **6** | Access Control Management | Least privilege; deny by default; MFA for remote access |
| **7** | Continuous Vulnerability Management | Automated vulnerability scanning; patch within SLA; remediation tracking |
| **8** | Audit Log Management | Enable logging; centralize logs; log retention (90+ days accessible, 1+ year retained) |
| **9** | Email and Web Browser Protections | Anti-malware filtering; browser hardening; DNS filtering |
| **10** | Malware Defenses | Antimalware on all assets; automatic updates; USB/removable media controls; anti-exploit features |
| **11** | Data Recovery | Automated backups; backup isolation; tested recovery; offsite backups |
| **12** | Network Infrastructure Management | Network diagrams; secure network protocols; DMZ; updated network infrastructure |
| **13** | Network Monitoring and Defense | Centralized network monitoring; DNS filtering; IDS/IPS; traffic filtering |
| **14** | Security Awareness and Skills Training | Security awareness program; role-based training; phishing simulations |
| **15** | Service Provider Management | Vendor inventory; service provider security requirements; monitor providers |
| **16** | Application Software Security | SDLC security; WAF; application hardening; penetration testing |
| **17** | Incident Response Management | Incident response plan; IR contacts; tabletop exercises; post-incident review |
| **18** | Penetration Testing | External and internal penetration tests; red team exercises; remediation validation |

### 5.4 CIS Benchmarks

CIS Benchmarks are consensus-based hardening guidelines for 100+ technologies. Available for free (PDF) or automated via CIS-CAT.

**Categories:**
- **Operating Systems:** Windows 10/11/Server, RHEL, Ubuntu, macOS, Debian, Amazon Linux, SLES
- **Cloud:** AWS Foundations, Azure, GCP, Oracle Cloud
- **Containers:** Docker, Kubernetes, EKS, GKE, AKS
- **Databases:** MySQL, PostgreSQL, Oracle DB, MSSQL, MongoDB
- **Network:** Cisco IOS, Palo Alto, Juniper, F5
- **Web Servers:** Apache, NGINX, IIS
- **Applications:** Microsoft 365, Chrome, Firefox, Safari

**Benchmark Levels:**
- **Level 1:** Essential, minimal performance impact. Recommended for all organizations.
- **Level 2:** Defense-in-depth, may impact usability/performance. For high-security environments.
- **STIG:** Defense Information Systems Agency STIG mappings.

### 5.5 CIS-CAT Tool

CIS-CAT (CIS Configuration Assessment Tool) automates benchmark assessment.

```bash
# CIS-CAT Lite (free) — limited benchmarks
java -jar CIS-CAT-Lite-Assessor.jar   --benchmark CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v1.0.0.xml   --profile "Level 1 - Server"   --report-dir /reports

# CIS-CAT Pro (licensed) — full benchmark library + remote scanning
java -jar CIS-CAT-Pro-Assessor-CLI.jar   --benchmark /benchmarks/CIS_RHEL9_Benchmark.xml   --profile "Level 2"   --report-dir /reports   --report-name rhel9-cis-scan

# Remote scan via SSH
java -jar CIS-CAT-Pro-Assessor-CLI.jar   --sessions sessions.properties   --benchmark /benchmarks/CIS_Ubuntu_22.04_Benchmark.xml   --profile "Level 1 - Server"
```

**CIS-CAT Pro Dashboard:** Web-based dashboard for aggregating scan results, tracking remediation, trending over time, and generating compliance reports.

### 5.6 CIS Controls to ATT&CK Mapping

| CIS Control | MITRE ATT&CK Technique Examples Addressed |
|-------------|------------------------------------------|
| CIS 1 (Asset Inventory) | T1592 (Gather Victim Host Info), T1190 (Exploit Public-Facing App) |
| CIS 3 (Data Protection) | T1530 (Data from Cloud Storage), T1486 (Ransomware), T1041 (Exfiltration) |
| CIS 5 (Account Mgmt) | T1078 (Valid Accounts), T1136 (Create Account), T1110 (Brute Force) |
| CIS 7 (Vuln Mgmt) | T1190 (Exploit Public-Facing), T1203 (Exploitation for Client Execution) |
| CIS 8 (Audit Logs) | T1070 (Indicator Removal), T1562 (Impair Defenses) |
| CIS 10 (Malware Defenses) | T1204 (User Execution), T1059 (Command Scripting), T1055 (Process Injection) |
| CIS 13 (Network Monitoring) | T1021 (Remote Services), T1071 (App Layer Protocol C2), T1041 |
| CIS 16 (App Security) | T1190 (Web Exploit), T1059.007 (JavaScript), T1566 (Phishing - Attachment) |

**Full mapping:** `https://www.cisecurity.org/controls/cis-controls-navigator/`

### 5.7 CIS RAM (Risk Assessment Method)

CIS RAM is a methodology for conducting risk assessments aligned to CIS Controls, suitable for any organization size.

**CIS RAM Process:**
1. Define scope — systems, processes, or enterprise-wide
2. Identify stakeholders and their needs — what must be protected and why
3. Catalog safeguards — what CIS Controls safeguards are implemented at what level
4. Identify threats — threat scenarios relevant to the organization
5. Evaluate likelihood and impact — using qualitative scales calibrated to the organization
6. Score risks — inherent and residual
7. Prioritize treatment — focus on IG1 gaps first
8. Document — risk register with safeguard ownership

**CIS RAM Versions:** CIS RAM v2.1 — available at `https://www.cisecurity.org/insights/white-papers/cis-ram`

---

## 6. PCI DSS v4.0

### 6.1 Overview

PCI DSS (Payment Card Industry Data Security Standard) v4.0 was released March 2022 by the PCI Security Standards Council. Organizations had until March 2024 to adopt v4.0 (v3.2.1 retired). New "future-dated" requirements in v4.0 are mandatory as of March 31, 2025.

**Governing Body:** PCI Security Standards Council (PCI SSC)
**Applies to:** Any entity that stores, processes, or transmits cardholder data (CHD) or sensitive authentication data (SAD)

### 6.2 The 12 Requirements Summary

| Req | Domain | Title | Key Focus |
|-----|--------|-------|-----------|
| **1** | Network Security | Install and Maintain Network Security Controls | Firewalls, network access controls, documentation of all connections |
| **2** | Secure Configs | Apply Secure Configurations to All System Components | No default passwords; system hardening; software inventory |
| **3** | Account Data Protection | Protect Stored Account Data | No storage of SAD post-authorization; CHD minimization; encryption/tokenization |
| **4** | Encryption in Transit | Protect Cardholder Data with Strong Cryptography During Transmission | TLS 1.2+ for all CHD in transit; no deprecated protocols (SSL, TLS 1.0, 1.1) |
| **5** | Anti-Malware | Protect All Systems Against Malware | Anti-malware on all applicable systems; behavioral detection; periodic reviews |
| **6** | Secure Development | Develop and Maintain Secure Systems and Software | SDLC; patching SLAs; web-app scanning; WAF for public-facing apps |
| **7** | Access Control | Restrict Access to System Components and Cardholder Data | Need-to-know principle; documented access control policy; role-based access |
| **8** | Authentication | Identify Users and Authenticate Access | Unique IDs; strong authentication (MFA for all CDE access v4.0); password complexity |
| **9** | Physical Security | Restrict Physical Access to Cardholder Data | Facility entry controls; visitor logs; media protection; card reader protection |
| **10** | Logging and Monitoring | Log and Monitor All Access to System Components and Cardholder Data | Centralized logging; tamper-evident logs; daily log review; 12-month retention |
| **11** | Security Testing | Test Security of Systems and Networks Regularly | Internal/external vulnerability scans; penetration testing; network change detection; IDS/IPS |
| **12** | Security Policy | Support Information Security with Organizational Policies and Programs | Security policy; risk assessment; awareness training; vendor management; IR plan |

### 6.3 Key Changes from v3.2.1 to v4.0

| Area | v3.2.1 | v4.0 Change |
|------|--------|-------------|
| Authentication (Req 8) | MFA required only for remote access | MFA required for all access to CDE (not just remote) |
| Password Policy (Req 8) | 7+ char, change every 90 days | Passphrase option; change 90-day requirement replaced with complexity metrics |
| Customized Approach | Not available | New: Organizations can meet intent of requirement using custom controls with formal risk assessment |
| Targeted Risk Analysis | Not structured | Required for several requirements to define frequency of activities |
| Phishing Resistance (Req 8) | Not specified | Phishing-resistant MFA for all non-console admin access and all access to cardholder web pages |
| Web App Scanning (Req 6) | WAF required for public-facing apps | WAF still required; automated technical solutions for detecting/preventing web attacks expanded |
| Responsibility Matrix | Not required | Required: All entities must document which PCI DSS requirements are their responsibility vs. service provider |
| E-commerce Security | Limited coverage | Req 6.4: All payment pages monitored for unauthorized script changes (skimming attacks) |

### 6.4 Self-Assessment Questionnaire (SAQ) Types

| SAQ | Who Uses It | Scope |
|-----|-------------|-------|
| **SAQ A** | Card-not-present merchants; fully outsourced card processing; no electronic storage | ~22 requirements |
| **SAQ A-EP** | E-commerce merchants with third-party payment page but direct connection to payment processor | ~191 requirements |
| **SAQ B** | Merchants using only imprint machines or stand-alone dial-up terminals; no electronic storage | ~41 requirements |
| **SAQ B-IP** | Merchants using standalone IP-connected PTS-approved terminals | ~83 requirements |
| **SAQ C** | Merchants with payment app systems connected to internet; no electronic CHD storage | ~160 requirements |
| **SAQ C-VT** | Merchants using web-based virtual terminal; no electronic CHD storage | ~77 requirements |
| **SAQ D-Merchant** | All other merchants not eligible for SAQ A through C | All 12 requirements (~250 sub-reqs) |
| **SAQ D-Service Provider** | Service providers not eligible for other SAQs | All 12 requirements + additional SP requirements |

### 6.5 Scoping

**Cardholder Data Environment (CDE):** Systems that store, process, or transmit CHD or SAD.

**Connected-to or Security-Impacting:** Systems that connect to the CDE or could impact CDE security — these are in scope even if they do not touch CHD directly (examples: authentication servers, log management, patch management, Active Directory for CDE systems).

**Out-of-Scope:** Systems fully segmented from the CDE with no connectivity path and no ability to impact CDE security.

**Scope Reduction Techniques:**
- Network segmentation (firewalls, VLANs) to isolate CDE
- Tokenization — replace PANs with tokens outside the CDE
- Point-to-Point Encryption (P2PE) — validated P2PE solutions reduce scope significantly
- Third-party payment processors — redirect to hosted payment page removes e-commerce from scope (SAQ A)

### 6.6 Key Technical Controls

#### Requirement 1: Network Security Controls

```
Required documentation:
- Diagram of all network connections to/from CDE
- Diagram of all CDE component types and their functions
- Business justification for each allowed protocol/port/service
- Review all NSC rules at least every 6 months

Technical requirements:
- Deny all traffic not explicitly permitted (default-deny)
- Restrict inbound/outbound traffic to only what is necessary
- Stateful inspection on all traffic entering/leaving CDE
- Anti-spoofing measures (RFC 1918 filtering on inbound)
```

#### Requirement 6: Secure Software Development

```
Patching SLAs (v4.0):
- Critical vulnerabilities: patch within defined timeframe per targeted risk analysis
- High vulnerabilities: patch within defined timeframe
- After installation: validate patches do not break security controls

Web Application Security:
- WAF deployed in front of all public-facing web apps processing CHD
- WAF rules updated as threats change
- OR: Web application vulnerability assessment annually and after changes

Requirement 6.4 (NEW - mandatory March 2025):
- All scripts loaded by payment pages must be authorized
- Integrity of payment page scripts monitored for unauthorized changes
- Change/tamper detection methods deployed
```

#### Requirement 8: Authentication

```
v4.0 MFA Requirements:
- MFA required for ALL access into the CDE (not just remote)
- For non-console admin access: phishing-resistant MFA required by March 2025
- For all access to cardholder web pages: phishing-resistant MFA by March 2025

Phishing-resistant MFA options:
- FIDO2/WebAuthn hardware keys (YubiKey, etc.)
- PKI-based smart cards
- NOT: TOTP apps, SMS codes (these are MFA but not phishing-resistant)
```

#### Requirement 10: Logging and Monitoring

```
Events to log (minimum):
- All individual user access to CHD
- All actions taken by root or administrative privileges
- Access to all audit trails
- Invalid logical access attempts
- Use of/changes to identification/authentication mechanisms
- Initialization/stopping of audit logs
- Creation/deletion of system-level objects

Log retention:
- 12 months total; 3 months immediately available; 9 months archivable

Daily log review:
- All security events reviewed daily
- Automated log monitoring tools strongly recommended
- Alerts for suspicious activity must be investigated
```

### 6.7 Customized Approach vs. Defined Approach

| Approach | Description | When to Use | Documentation Required |
|----------|-------------|-------------|------------------------|
| **Defined Approach** | Traditional PCI DSS; implement specific stated requirements | Most organizations | Standard testing procedures apply |
| **Customized Approach** | Meet the Customized Approach Objective using alternative controls | Organizations with mature security programs wanting flexibility | Formal risk analysis required; document controls; QSA validates independently |

### 6.8 Timeline

| Date | Milestone |
|------|-----------|
| March 2022 | PCI DSS v4.0 published |
| March 2024 | v3.2.1 retired; v4.0 mandatory for all assessments |
| March 31, 2025 | All "future-dated" v4.0 requirements become mandatory |

---

## 7. HIPAA / HITECH Security Rule

### 7.1 Overview

HIPAA (Health Insurance Portability and Accountability Act, 1996) Privacy and Security Rules protect Protected Health Information (PHI). HITECH (Health Information Technology for Economic and Clinical Health Act, 2009) strengthened HIPAA enforcement and extended requirements to Business Associates.

**Regulated Entities (Covered Entities):**
- Health plans (insurance companies, HMOs, employer health plans)
- Healthcare clearinghouses
- Healthcare providers who transmit health information electronically

**Business Associates (BAs):** Vendors/contractors who handle PHI on behalf of covered entities. Business Associates must sign a **Business Associate Agreement (BAA)** and are directly liable for HIPAA Security Rule compliance under HITECH.

**ePHI:** Electronic Protected Health Information — any PHI created, received, maintained, or transmitted in electronic form.

### 7.2 HIPAA Security Rule — Three Safeguard Categories

#### Administrative Safeguards (164.308)

| Standard | Required (R) / Addressable (A) | Description |
|----------|-------------------------------|-------------|
| Security Management Process | R | Risk analysis, risk management, sanction policy, information system activity review |
| Assigned Security Responsibility | R | Designated security official |
| Workforce Security | A | Authorization/supervision, workforce clearance, termination procedures |
| Information Access Management | R/A | Isolating healthcare clearinghouse, access authorization/establishment/modification |
| Security Awareness and Training | A | Security reminders, malware protection, log-in monitoring, password management |
| Security Incident Procedures | R | Response and reporting procedures for security incidents |
| Contingency Plan | R/A | Data backup, DR plan, emergency mode, testing/revision, applications criticality |
| Evaluation | R | Periodic technical and nontechnical evaluation |
| Business Associate Contracts | R | BAA requirements with vendors/partners handling ePHI |

#### Physical Safeguards (164.310)

| Standard | R/A | Description |
|----------|-----|-------------|
| Facility Access Controls | A | Contingency operations, facility security plan, access control/validation, maintenance records |
| Workstation Use | R | Policies specifying proper workstation use and physical surroundings |
| Workstation Security | R | Physical safeguards for workstations accessing ePHI |
| Device and Media Controls | R/A | Disposal, media re-use, accountability, data backup/storage |

#### Technical Safeguards (164.312)

| Standard | R/A | Description |
|----------|-----|-------------|
| Access Control | R/A | Unique user identification (R), emergency access (R), automatic logoff (A), encryption/decryption (A) |
| Audit Controls | R | Hardware/software/procedural mechanisms to record and examine ePHI access |
| Integrity | A | Authenticate ePHI has not been improperly altered or destroyed |
| Person or Entity Authentication | R | Verify identity of person/entity seeking ePHI access |
| Transmission Security | A | Guard against unauthorized ePHI access during transmission (encryption) |

### 7.3 Required vs. Addressable Specifications

**Required (R):** Must be implemented; no flexibility. The specific implementation may vary but the standard must be met.

**Addressable (A):** Entities must assess whether the implementation specification is reasonable and appropriate. If yes, implement it. If no, document the rationale and implement an equivalent alternative measure.

**Common misunderstanding:** "Addressable" does NOT mean optional. Most addressable specifications are implemented by virtually all organizations; the flexibility is in HOW, not WHETHER.

### 7.4 Risk Analysis Requirement (164.308(a)(1))

The risk analysis is the cornerstone of HIPAA Security Rule compliance and the most cited deficiency in OCR audits.

**Required elements of a compliant risk analysis:**
1. **Scope:** Identify all ePHI the organization creates, receives, maintains, or transmits
2. **Threat identification:** Identify reasonably anticipated threats to ePHI confidentiality, integrity, availability
3. **Vulnerability identification:** Identify vulnerabilities that, if exploited by threats, would create risk
4. **Current controls:** Assess existing security measures protecting ePHI
5. **Likelihood assessment:** Estimate the probability that each threat will exploit each vulnerability
6. **Impact assessment:** Estimate the impact on operations and ePHI if the threat is realized
7. **Risk rating:** Assign risk levels to identified risk combinations
8. **Documentation:** Documented risk analysis that can be produced for OCR auditors

**NIST SP 800-66 Rev. 2:** Implementation guidance for HIPAA Security Rule — highly recommended reference.

### 7.5 Business Associate Agreements (BAA)

A BAA is a contract between a covered entity and a business associate (or between two BAs — a subcontractor BAA).

**Required BAA provisions:**
- Permitted and required uses/disclosures of PHI
- BA will not use/disclose PHI other than permitted or required by the BAA or law
- BA will use appropriate safeguards to prevent unauthorized PHI use/disclosure
- BA will report to covered entity any security incident or PHI breach
- BA will ensure any subcontractors agree to same restrictions
- BA will return or destroy PHI at contract termination
- BA will make internal practices available to HHS/OCR for audit

**Cloud BAAs:** Major cloud providers offer BAAs:
- **AWS:** Sign via AWS Artifact; covers 130+ services
- **Azure:** Covered under Microsoft Online Services Agreement; BAA available via portal
- **GCP:** Healthcare and Life Sciences addendum (BAA) available for all customers
- **Microsoft 365:** HIPAA BAA available for E3/E5 licenses and above

### 7.6 HITECH — Increased Penalties

HITECH (2009) significantly increased HIPAA penalties and extended liability to Business Associates.

**Civil Monetary Penalty Tiers:**

| Violation Category | Per Violation | Annual Cap |
|-------------------|---------------|------------|
| Did not know (and with reasonable diligence would not have known) | $100-$50,000 | $25,000 |
| Reasonable cause (not willful neglect) | $1,000-$50,000 | $100,000 |
| Willful neglect — corrected | $10,000-$50,000 | $250,000 |
| Willful neglect — not corrected | $50,000-$1,900,000 | $1,900,000 |

**Notable OCR Settlements:**
- Advocate Health Care (2016): $5.55M — lost unencrypted laptops
- Memorial Hermann (2017): $2.4M — PHI on press release
- Premera Blue Cross (2020): $6.85M — inadequate risk analysis; 10.4M records breached
- Montefiore Medical Center (2023): $4.75M — insider threat; inadequate access controls

### 7.7 Breach Notification Requirements

**Breach:** Impermissible use or disclosure of PHI that compromises security or privacy.

**Notification timelines:**
- **Individuals:** Written notice within 60 days of discovery
- **HHS Secretary:** Within 60 days (breaches fewer than 500 records can be reported annually); same day for breaches affecting 500 or more
- **Media:** Prominent media notice within 60 days for breaches affecting 500 or more residents of a state/jurisdiction

**Safe Harbors (no breach notification required):**
- PHI was encrypted per NIST standards AND the decryption key was not compromised
- PHI was destroyed per NIST standards
- The incident was an unintentional acquisition by a workforce member acting in good faith

### 7.8 Common HIPAA Violations and Prevention

| Violation | Examples | Prevention |
|-----------|---------|------------|
| Insufficient access controls | Shared passwords; excessive access; terminated employee accounts | RBAC; automatic deprovisioning; quarterly access reviews |
| Lack of encryption | Unencrypted laptops/USB; unencrypted email with PHI | Full disk encryption (BitLocker/FileVault); S/MIME or secure messaging |
| No/inadequate risk analysis | Never performed; outdated; not documented | Annual risk analysis; documented evidence; follow NIST 800-66 |
| Missing/improper BAA | No BAA with cloud provider; outdated BAA | Vendor inventory; BAA tracking; legal review of all BA relationships |
| Improper disposal | Paper PHI in trash; unwiped hard drives | Secure shredding contracts; NIST 800-88 compliant media sanitization |
| Unauthorized disclosure | Responding to records requests without authorization | Training; verification procedures; minimum necessary standard |
| Workforce training failures | No HIPAA training; training not documented | Annual training; documentation; role-based modules |

---

## 8. SOC 2 Type II

### 8.1 Overview

SOC 2 (Service Organization Control 2) is an auditing standard developed by the AICPA for service organizations. SOC 2 Type II reports evaluate the design AND operating effectiveness of controls over a defined period (typically 6-12 months).

**SOC 2 vs. SOC 1:** SOC 1 covers internal controls over financial reporting (ICFR). SOC 2 covers security, availability, and related criteria.

**SOC 2 Type I vs. Type II:**
- **Type I:** Point-in-time assessment — controls are suitably designed (but not tested over time). Faster to obtain; less rigorous.
- **Type II:** Assessment over a period (typically 6-12 months) — controls are suitably designed AND operating effectively. More valuable to customers.

**Who needs SOC 2:** SaaS companies, cloud providers, data centers, managed service providers — any service organization whose systems store, process, or transmit customer data.

### 8.2 Trust Service Criteria (TSC)

**Security (CC):** Required for all SOC 2 reports — the "Common Criteria" (CC) covering logical access, system operations, change management, and risk management.

**Availability (A):** System availability for operation and use as committed. Add if customers have uptime SLAs.

**Confidentiality (C):** Information designated as confidential is protected as committed. Add for data handling sensitivity commitments.

**Processing Integrity (PI):** System processing is complete, valid, accurate, timely, and authorized. Add for transactional systems (payments, data processing).

**Privacy (P):** Personal information is collected, used, retained, disclosed per privacy notice and AICPA Generally Accepted Privacy Principles. Add for consumer data handling.

### 8.3 Common Criteria (CC) Series — Key Controls

#### CC6 — Logical and Physical Access Controls

| Criterion | Description | Example Evidence |
|-----------|-------------|-----------------|
| CC6.1 | Access credentials managed per policy; new access requires authorization | Access provisioning tickets; HRIS-to-IAM integration |
| CC6.2 | Established processes to remove access no longer required | Offboarding procedures; quarterly access reviews; automated deprovisioning |
| CC6.3 | Role-based access; least privilege enforced | RBAC documentation; access matrix; quarterly access reviews |
| CC6.4 | Authorized modifications to user access | Change tickets for access changes; manager approval workflow |
| CC6.5 | Physical access to facilities restricted | Badge access logs; visitor logs; CCTV records |
| CC6.6 | Remote access managed; MFA required | VPN with MFA; Okta/Azure AD MFA logs; remote access policy |
| CC6.7 | Transmission of data restricted | TLS certificates; network diagram; DLP controls |
| CC6.8 | System accounts restricted; privileged access monitored | PAM solution (CyberArk/Vault); privileged account inventory; session recordings |

#### CC7 — System Operations

| Criterion | Description | Example Evidence |
|-----------|-------------|-----------------|
| CC7.1 | Vulnerabilities detected, monitored, and evaluated | Vulnerability scanner reports; patch tracking |
| CC7.2 | Security events detected and monitored | SIEM alerts; log aggregation; alerting runbooks |
| CC7.3 | Security events evaluated to determine incident impact | Incident classification criteria; investigation records |
| CC7.4 | Security incidents identified and responded to | Incident response policy; IR runbooks; post-incident reviews |
| CC7.5 | Disclosure of security incidents | Breach notification procedure; customer notification examples |

#### CC8 — Change Management

| Criterion | Description | Example Evidence |
|-----------|-------------|-----------------|
| CC8.1 | Infrastructure/software changes authorized and tested before production | Change management policy; approved change tickets; test results; CAB meeting minutes |

#### CC9 — Risk Mitigation

| Criterion | Description | Example Evidence |
|-----------|-------------|-----------------|
| CC9.1 | Risk mitigation activities identified and implemented | Risk register; risk treatment plans |
| CC9.2 | Vendor risk management | Vendor assessment questionnaires; BAA/DPA tracking; third-party security reviews |

### 8.4 Evidence Collection

SOC 2 auditors request extensive evidence. Organize evidence by criterion:

```
Evidence Repository Structure (example):
evidence/
├── CC6-Access-Control/
│   ├── access-provisioning-policy.pdf
│   ├── access-review-Q1-2024.xlsx
│   ├── deprovisioning-ticket-samples/
│   ├── mfa-enrollment-report.pdf
│   └── privileged-account-inventory.xlsx
├── CC7-System-Operations/
│   ├── vulnerability-scan-reports/
│   ├── patch-compliance-reports/
│   ├── siem-alert-examples/
│   └── incident-log.xlsx
├── CC8-Change-Management/
│   ├── change-management-policy.pdf
│   ├── change-tickets-sample/
│   └── cab-meeting-minutes/
├── CC9-Risk-Mitigation/
│   ├── risk-register.xlsx
│   └── vendor-assessment/
│       ├── vendor-inventory.xlsx
│       └── completed-questionnaires/
└── Policies/
    ├── information-security-policy.pdf
    ├── access-control-policy.pdf
    ├── incident-response-policy.pdf
    └── change-management-policy.pdf
```

### 8.5 Continuous Compliance Platforms

| Platform | Key Features | Pricing |
|----------|-------------|---------|
| **Vanta** | Automated evidence collection; 200+ integrations; vendor management; trust center | ~$15K-$40K/year |
| **Drata** | Continuous monitoring; policy management; employee security training; cross-framework | ~$15K-$35K/year |
| **Secureframe** | SOC 2, ISO 27001, HIPAA, PCI DSS, GDPR; AI-assisted evidence collection | ~$12K-$30K/year |
| **Tugboat Logic** | Policy management; evidence collection; risk assessment; acquired by OneTrust | Varies |
| **Sprinto** | Fast SOC 2 (6-8 weeks claim); 100+ integrations; onboarding assistance | ~$8K-$20K/year |
| **AuditBoard** | Enterprise GRC; SOX + SOC 2; cross-functional audit management | Enterprise pricing |

**Self-managed SOC 2:** Organizations can achieve SOC 2 without a compliance platform using spreadsheets + evidence repo + audit firm — typically takes longer and requires more internal effort.

### 8.6 SOC 2 to CSF and ISO 27001 Mapping

| SOC 2 Criterion | NIST CSF | ISO 27001:2022 |
|-----------------|----------|----------------|
| CC6.1 (Credentials) | PR.AA-01 | A.5.16 (Identity mgmt), A.8.2 |
| CC6.2 (Access removal) | PR.AA-05 | A.5.18 (Access rights) |
| CC6.6 (MFA) | PR.AA-03 | A.8.5 (Secure authentication) |
| CC6.8 (Privileged access) | PR.AA-06 | A.8.2 (Privileged access rights) |
| CC7.1 (Vuln detection) | DE.CM-08 | A.8.8 (Vulnerability mgmt) |
| CC7.2 (Security monitoring) | DE.CM-01 | A.8.16 (Monitoring) |
| CC7.4 (IR) | RS.MA-01 | A.5.26 (Response to IS incidents) |
| CC8.1 (Change mgmt) | PR.PS-07 | A.8.32 (Change management) |
| CC9.2 (Vendor risk) | GV.SC-06 | A.5.21 (ICT supply chain) |

---

## 9. ISO 27001:2022

### 9.1 Overview

ISO/IEC 27001:2022 is the international standard for information security management systems (ISMS). Organizations can pursue formal third-party certification by an accredited certification body.

**2022 Update:** ISO 27001:2022 replaced ISO 27001:2013. Key changes:
- Annex A restructured from 114 controls in 14 domains to 93 controls in 4 themes
- 11 new controls added (covering threat intelligence, cloud security, ICT readiness, data masking, etc.)
- Control attributes added (control type, security properties, cybersecurity concepts, operational capabilities, security domains)
- Transition deadline: Organizations with 2013 certification had until October 31, 2025 to transition

### 9.2 ISMS — Information Security Management System

An ISMS is the framework of policies, processes, procedures, and controls to manage information security risks. ISO 27001 follows the **Plan-Do-Check-Act (PDCA)** cycle and uses **Annex SL** (common management system structure shared with ISO 9001, ISO 22301, etc.).

**ISMS Clauses (4 through 10 — mandatory):**

| Clause | Title | Key Requirements |
|--------|-------|-----------------|
| 4 | Context of the Organization | Internal/external issues; interested parties; ISMS scope |
| 5 | Leadership | Top management commitment; security policy; roles/responsibilities |
| 6 | Planning | Risk assessment; risk treatment; statement of applicability; security objectives |
| 7 | Support | Resources; competence; awareness; communication; documented information |
| 8 | Operation | Operational planning; risk assessment execution; risk treatment plan |
| 9 | Performance Evaluation | Monitoring; internal audit; management review |
| 10 | Improvement | Nonconformities; corrective actions; continual improvement |

### 9.3 Annex A Controls — 2022 Structure

ISO 27001:2022 Annex A has 93 controls across 4 themes:

#### Theme 1: Organizational Controls (37 controls — A.5.x)

| Control | Title |
|---------|-------|
| A.5.1 | Policies for information security |
| A.5.2 | Information security roles and responsibilities |
| A.5.3 | Segregation of duties |
| A.5.4 | Management responsibilities |
| A.5.5 | Contact with authorities |
| A.5.6 | Contact with special interest groups |
| A.5.7 | Threat intelligence (NEW) |
| A.5.8 | Information security in project management |
| A.5.9 | Inventory of information and other associated assets |
| A.5.10 | Acceptable use of information and associated assets |
| A.5.11 | Return of assets |
| A.5.12 | Classification of information |
| A.5.13 | Labelling of information |
| A.5.14 | Information transfer |
| A.5.15 | Access control |
| A.5.16 | Identity management |
| A.5.17 | Authentication information |
| A.5.18 | Access rights |
| A.5.19 | Information security in supplier relationships |
| A.5.20 | Addressing information security within supplier agreements |
| A.5.21 | Managing information security in the ICT supply chain (NEW) |
| A.5.22 | Monitoring, review and change management of supplier services |
| A.5.23 | Information security for use of cloud services (NEW) |
| A.5.24 | Information security incident management planning and preparation |
| A.5.25 | Assessment and decision on information security events |
| A.5.26 | Response to information security incidents |
| A.5.27 | Learning from information security incidents |
| A.5.28 | Collection of evidence |
| A.5.29 | Information security during disruption |
| A.5.30 | ICT readiness for business continuity (NEW) |
| A.5.31 | Legal, statutory, regulatory and contractual requirements |
| A.5.32 | Intellectual property rights |
| A.5.33 | Protection of records |
| A.5.34 | Privacy and protection of PII |
| A.5.35 | Independent review of information security |
| A.5.36 | Compliance with policies, rules and standards |
| A.5.37 | Documented operating procedures |

#### Theme 2: People Controls (8 controls — A.6.x)

| Control | Title |
|---------|-------|
| A.6.1 | Screening |
| A.6.2 | Terms and conditions of employment |
| A.6.3 | Information security awareness, education and training |
| A.6.4 | Disciplinary process |
| A.6.5 | Responsibilities after termination or change of employment |
| A.6.6 | Confidentiality or non-disclosure agreements |
| A.6.7 | Remote working |
| A.6.8 | Information security event reporting |

#### Theme 3: Physical Controls (14 controls — A.7.x)

| Control | Title |
|---------|-------|
| A.7.1 | Physical security perimeters |
| A.7.2 | Physical entry |
| A.7.3 | Securing offices, rooms and facilities |
| A.7.4 | Physical security monitoring (NEW) |
| A.7.5 | Protecting against physical and environmental threats |
| A.7.6 | Working in secure areas |
| A.7.7 | Clear desk and clear screen |
| A.7.8 | Equipment siting and protection |
| A.7.9 | Security of assets off-premises |
| A.7.10 | Storage media |
| A.7.11 | Supporting utilities |
| A.7.12 | Cabling security |
| A.7.13 | Equipment maintenance |
| A.7.14 | Secure disposal or re-use of equipment |

#### Theme 4: Technological Controls (34 controls — A.8.x)

| Control | Title |
|---------|-------|
| A.8.1 | User endpoint devices |
| A.8.2 | Privileged access rights |
| A.8.3 | Information access restriction |
| A.8.4 | Access to source code |
| A.8.5 | Secure authentication |
| A.8.6 | Capacity management |
| A.8.7 | Protection against malware |
| A.8.8 | Management of technical vulnerabilities |
| A.8.9 | Configuration management |
| A.8.10 | Information deletion |
| A.8.11 | Data masking (NEW) |
| A.8.12 | Data leakage prevention |
| A.8.13 | Information backup |
| A.8.14 | Redundancy of information processing facilities |
| A.8.15 | Logging |
| A.8.16 | Monitoring activities |
| A.8.17 | Clock synchronization |
| A.8.18 | Use of privileged utility programs |
| A.8.19 | Installation of software on operational systems |
| A.8.20 | Networks security |
| A.8.21 | Security of network services |
| A.8.22 | Segregation of networks |
| A.8.23 | Web filtering |
| A.8.24 | Use of cryptography |
| A.8.25 | Secure development life cycle |
| A.8.26 | Application security requirements |
| A.8.27 | Secure system architecture and engineering principles |
| A.8.28 | Secure coding |
| A.8.29 | Security testing in development and acceptance |
| A.8.30 | Outsourced development |
| A.8.31 | Separation of development, test and production environments |
| A.8.32 | Change management |
| A.8.33 | Test information |
| A.8.34 | Protection of information systems during audit testing |

### 9.4 New Controls in ISO 27001:2022

| Control | Theme | Why It Was Added |
|---------|-------|-----------------|
| A.5.7 Threat intelligence | Organizational | Proactive threat monitoring was missing; threat intel increasingly critical |
| A.5.21 ICT supply chain | Organizational | SolarWinds and similar attacks drove supply chain security into mainstream |
| A.5.23 Cloud services security | Organizational | 2013 standard predated widespread cloud adoption |
| A.5.30 ICT readiness for BCP | Organizational | Merges IT DR with BCM; ensures ICT recovery is part of continuity planning |
| A.7.4 Physical security monitoring | Physical | CCTV/monitoring not explicitly addressed in 2013 |
| A.8.9 Configuration management | Technological | System hardening and config baselines now explicitly required |
| A.8.10 Information deletion | Technological | Right to erasure (GDPR) and secure data destruction now mainstream |
| A.8.11 Data masking | Technological | Privacy-by-design; anonymization/pseudonymization for dev/test environments |
| A.8.12 Data leakage prevention | Technological | DLP tools now widely available; explicit control required |
| A.8.16 Monitoring activities | Technological | Broader than just audit logs — includes anomaly detection, threat monitoring |
| A.8.23 Web filtering | Technological | Web-based threat vectors increased significantly |

### 9.5 Statement of Applicability (SoA)

The SoA is the central ISMS document listing all 93 Annex A controls, whether each is applicable, justification for applicability or exclusion, and implementation status.

**SoA Template Structure:**

| Control ID | Control Title | Applicable? | Justification | Implementation Status | Evidence Reference |
|------------|--------------|-------------|---------------|-----------------------|--------------------|
| A.5.1 | Policies for information security | Yes | All organizations need security policies | Implemented | IS-POL-001 |
| A.5.23 | Cloud services security | Yes | Organization uses AWS and Azure | In progress | Cloud-SEC-PROC-003 |
| A.7.1 | Physical security perimeters | No | Fully remote organization; no physical office | Excluded | — |

**Important:** Excluding a control requires documented justification. Auditors will challenge exclusions that do not have sound rationale.

### 9.6 Risk Treatment Options

| Option | Description | When to Use |
|--------|-------------|-------------|
| **Modify** (Treat/Mitigate) | Implement controls to reduce likelihood or impact | Risk above tolerance; controls are cost-effective |
| **Retain** (Accept) | Consciously accept the risk without additional controls | Risk within appetite; treatment cost exceeds potential loss |
| **Avoid** | Eliminate the activity that creates the risk | Risk is unacceptable and activity is not essential |
| **Share** (Transfer) | Transfer risk to a third party via insurance or contract | Financial risks; low control over threat sources |

### 9.7 ISO 27001 Certification Process

```
Certification Timeline (typical 9-18 months):

Month 1-3: ISMS Development
  Define scope
  Conduct risk assessment
  Develop/update policies and procedures
  Implement controls
  Create Statement of Applicability

Month 4-6: ISMS Operation
  Run ISMS for at least 1 cycle
  Conduct internal audit
  Management review
  Remediate nonconformities

Month 6-8: Stage 1 Audit (Documentation Review)
  Certification body reviews ISMS documentation
  Confirms scope and readiness for Stage 2
  Identifies any major gaps -> remediate before Stage 2

Month 8-12: Stage 2 Audit (Certification Audit)
  On-site (or remote) audit of ISMS implementation
  Evidence review for all in-scope controls
  Interviews with personnel
  Audit report: Pass (possibly with nonconformities) or Fail

Month 12+: Certification Issued
  Certificate valid for 3 years
  Surveillance audits: Year 1 and Year 2 (subset of controls)
  Recertification audit: Year 3 (full audit)
```

**Major Nonconformity:** Failure to meet a mandatory clause requirement or an applicable Annex A control. Must be corrected before certification is granted.
**Minor Nonconformity:** Control gap that does not represent a system failure. Must be corrected within the certification cycle.
**Observation:** Area for improvement, not a finding. Not required to address.

---

## 10. GRC Tools and Automation

### 10.1 Open-Source GRC Platforms

#### GovReady-Q

An open-source compliance automation platform designed to make FedRAMP, NIST 800-53, and other government framework compliance more manageable.

**Repository:** `https://github.com/GovReady/govready-q`
**Key features:**
- Questionnaire-driven compliance data collection
- Machine-readable compliance output (OSCAL)
- Multi-tenant (multiple systems/teams)
- Python/Django; can self-host

```bash
# Quick start with Docker
git clone https://github.com/GovReady/govready-q.git
cd govready-q
docker-compose up
# Access at http://localhost:8000
```

#### VECTR (SecurityRiskAdvisors)

VECTR tracks adversary simulation and purple team activities against security controls, helping organizations measure control effectiveness over time.

**Repository:** `https://github.com/SecurityRiskAdvisors/VECTR`
**Key features:**
- Track red team and blue team activities
- Map findings to MITRE ATT&CK
- Measure detection and prevention rates per control
- Track remediation over time
- Generate reports showing risk posture improvement

```bash
# Docker deployment
git clone https://github.com/SecurityRiskAdvisors/VECTR.git
cd VECTR
cp .env.example .env
# Edit .env with organization name and admin password
docker-compose up -d
# Access at https://localhost:8081
```

**VECTR Workflow:**
1. Create a campaign (e.g., "Q4 2024 Purple Team")
2. Import ATT&CK techniques as test cases
3. Record attack execution results (succeed/fail)
4. Record detection results (detected/not detected)
5. Map to security controls
6. Generate coverage and gap reports

#### ArcherySec (Vulnerability + Compliance Aggregation)

Open-source vulnerability assessment and management platform that aggregates scanner output and maps to compliance frameworks.

**Repository:** `https://github.com/archerysec/archerysec`

```bash
# Docker deployment
git clone https://github.com/archerysec/archerysec.git
cd archerysec
docker-compose up -d
# Import NESSUS, OpenVAS, Burp Suite, OWASP ZAP scan results
# Map vulnerabilities to CIS Controls, PCI DSS requirements
```

### 10.2 Risk Register — Spreadsheet vs. GRC Platform

| Feature | Spreadsheet (Excel/Sheets) | Dedicated GRC Platform |
|---------|---------------------------|------------------------|
| Cost | Free | $10K-$200K+/year |
| Setup time | Hours | Days-weeks |
| Scalability | Poor (100+ risks becomes unwieldy) | Excellent |
| Workflow automation | Limited (macros) | Built-in |
| Control linkage | Manual | Automated |
| Evidence management | Manual (folder links) | Integrated repository |
| Audit trails | None | Full audit logging |
| Reporting | Manual pivot tables | Real-time dashboards |
| Access control | Limited | Role-based |
| API/integrations | None | Extensive |
| Best for | Startups, small orgs, initial programs | Mid-market and enterprise |

**Spreadsheet Risk Register Template Columns (minimal viable):**
```
Risk ID | Asset | Threat | Vulnerability | Likelihood (1-5) | Impact (1-5) |
Inherent Score | Controls | Residual Score | Owner | Due Date | Status | Notes
```

### 10.3 Commercial Compliance Automation Platforms

#### Vanta
- **Focus:** SOC 2, ISO 27001, HIPAA, PCI DSS, GDPR, CCPA, CMMC
- **Integrations:** 200+ (AWS, GCP, Azure, GitHub, Jira, Okta, Slack, etc.)
- **Key differentiator:** Automated evidence collection; continuous compliance monitoring
- **Trust Center:** Public-facing page showing compliance status to customers
- **Pricing:** ~$15,000-$40,000/year depending on frameworks and size

#### Drata
- **Focus:** SOC 2, ISO 27001, HIPAA, PCI DSS, GDPR, CMMC, FedRAMP
- **Integrations:** 150+ with automated evidence pull
- **Key differentiator:** Policy management; employee security training module built-in
- **Workflows:** Automated vendor questionnaires; access review automation
- **Pricing:** ~$15,000-$35,000/year

#### Secureframe
- **Focus:** SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, NIST, FedRAMP
- **Key differentiator:** AI-assisted gap identification; faster time to compliance
- **Integrations:** 150+
- **Pricing:** ~$12,000-$30,000/year

### 10.4 Policy Management Platforms

| Platform | Type | Key Features |
|----------|------|-------------|
| **Tugboat Logic** (OneTrust) | SaaS | Policy library; control mapping; evidence collection |
| **PolicyTech** (NAVEX) | SaaS | Policy lifecycle; attestation tracking; version control |
| **LogicManager** | SaaS | Enterprise GRC; policy + risk + audit integration |
| **ServiceNow GRC** | SaaS/On-prem | Enterprise; ITSM integration; deep customization |
| **Hyperproof** | SaaS | Multi-framework; evidence collection; audit management |

### 10.5 Third-Party Risk Management (TPRM) Workflow

```
TPRM Life Cycle:

1. VENDOR ONBOARDING
   - Vendor discovery (procurement intake)
   - Risk tiering (Critical/High/Medium/Low based on data access, criticality)
   - Questionnaire assignment based on tier

2. INITIAL ASSESSMENT
   - Send security questionnaire (SIG, CAIQ, custom)
   - Request evidence (SOC 2 report, pentest summary, ISO cert)
   - Review completed questionnaire
   - Risk scoring; document findings

3. RISK TREATMENT
   - Contractual controls (DPA, BAA, SLAs, right-to-audit clauses)
   - Compensating controls if gaps identified
   - Residual risk acceptance by risk owner

4. ONGOING MONITORING
   - Annual re-assessment (or more frequent for critical vendors)
   - Continuous monitoring (SecurityScorecard, BitSight, RiskRecon)
   - Incident notification from vendor (contractual requirement)
   - Track vendor's public breach/incident history

5. OFFBOARDING
   - Data return/deletion confirmation
   - Access revocation verification
   - Contract termination checklist
```

**Questionnaire Standards:**
- **SIG (Standardized Information Gathering):** Industry standard; ~1,400 questions; maintained by Shared Assessments
- **CAIQ (Consensus Assessments Initiative Questionnaire):** CSA cloud security questionnaire for cloud providers
- **VSA (Vendor Security Alliance Questionnaire):** Shorter, focused questionnaire
- **Custom:** Internal questionnaire tailored to organization's risk areas

**Continuous Monitoring Tools:**

| Tool | Key Metrics | Notes |
|------|-------------|-------|
| **SecurityScorecard** | Letter grade (A-F); 10+ factor analysis | Widely used; customer-facing scorecards |
| **BitSight** | Numeric score (250-900) | Strong enterprise adoption |
| **RiskRecon** | Risk rating with issue details | Internet-facing asset discovery |
| **Black Kite** | Three-dimensional rating (cyber/financial/compliance) | Regulatory compliance scoring |

### 10.6 Evidence Collection Automation

```python
# Example: Automated evidence collection pipeline (Python)
# Collects evidence from common SaaS tools for SOC 2 audit

import requests, json, datetime

# Pull MFA enrollment report from Okta
def collect_okta_mfa_evidence(api_token, domain):
    headers = {'Authorization': f'SSWS {api_token}', 'Accept': 'application/json'}
    users = []
    url = f'https://{domain}/api/v1/users?limit=200&filter=status eq "ACTIVE"'
    while url:
        r = requests.get(url, headers=headers)
        users.extend(r.json())
        url = r.links.get('next', {}).get('url')

    mfa_enrolled = []
    for user in users:
        factors_url = f'https://{domain}/api/v1/users/{user["id"]}/factors'
        factors = requests.get(factors_url, headers=headers).json()
        mfa_enrolled.append({
            'user': user['profile']['login'],
            'mfa': len(factors) > 0,
            'factors': [f['factorType'] for f in factors]
        })

    date = datetime.date.today().isoformat()
    with open(f'evidence/CC6-MFA-Enrollment-{date}.json', 'w') as f:
        json.dump(mfa_enrolled, f, indent=2)

    total = len(mfa_enrolled)
    enrolled = sum(1 for u in mfa_enrolled if u['mfa'])
    print(f"MFA Evidence: {enrolled}/{total} users enrolled ({enrolled/total*100:.1f}%)")

# Pull AWS IAM credential report
def collect_aws_iam_evidence():
    import boto3, time
    iam = boto3.client('iam')
    iam.generate_credential_report()
    time.sleep(5)
    report = iam.get_credential_report()
    date = datetime.date.today().isoformat()
    with open(f'evidence/CC6-AWS-IAM-CredentialReport-{date}.csv', 'wb') as f:
        f.write(report['Content'])
    print(f"IAM Credential Report saved for {date}")
```

### 10.7 Continuous Compliance Monitoring Pipeline

```
Continuous Compliance Architecture:

Controls -> Monitoring -> Evidence -> Reporting

Firewall rules  -> Daily log review -> Evidence repo -> GRC dashboard
Patch levels    -> Vuln scanner     -> Auto-tagged   -> Risk score
Access matrix   -> SIEM alerts      -> By criterion  -> Audit package
Vendor certs    -> API polling      -> Timestamped   -> Customer report

Exceptions/Drift Alerts:
  - Slack/Teams notification
  - Jira ticket creation
  - Risk register update
```

**Key Integrations for Continuous Compliance:**
```
Identity:    Okta, Azure AD, JumpCloud           -> CC6 (access, MFA)
Cloud:       AWS Config, Azure Policy, GCP SCC   -> CC6, CC7
Endpoint:    CrowdStrike, SentinelOne, Defender  -> CC7 (malware)
Vuln:        Tenable, Qualys, Rapid7             -> CC7 (vuln mgmt)
SIEM:        Splunk, Sentinel, Chronicle         -> CC7 (monitoring)
Code:        GitHub, GitLab                      -> CC8 (change management)
HR:          Workday, BambooHR                   -> CC6 (offboarding)
Infra:       Terraform, Ansible                  -> CC4 (config management)
```

### 10.8 GRC Maturity Model

```
Level 1 - Initial (Ad Hoc)
  No formal GRC program; compliance reactive; risk management ad hoc; no consistent policies

Level 2 - Developing (Managed)
  Basic policies documented; risk register exists but not consistently maintained;
  compliance calendar tracked; annual risk assessments performed

Level 3 - Defined (Repeatable)
  Formal GRC program with dedicated ownership; risk register actively maintained quarterly;
  controls mapped to frameworks; internal audit function established;
  vendor risk management program exists

Level 4 - Measured (Quantified)
  KRIs and KPIs tracked in real-time dashboards; quantitative risk analysis (FAIR) for key risks;
  continuous control monitoring; compliance automation (Vanta/Drata or equivalent);
  regular penetration testing and red team exercises

Level 5 - Optimizing (Adaptive)
  Predictive risk analytics; threat intelligence integrated into risk management;
  automated remediation for common control failures;
  continuous assurance (real-time audit evidence);
  board-level risk reporting with financial quantification
```

### 10.9 Key GRC Resources

| Resource | URL | Type |
|----------|-----|------|
| NIST CSF 2.0 | https://www.nist.gov/cyberframework | Free |
| NIST SP 800-53 r5 | https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final | Free |
| NIST SP 800-66 r2 (HIPAA) | https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final | Free |
| CIS Controls v8 | https://www.cisecurity.org/controls/v8 | Free |
| PCI DSS v4.0 | https://www.pcisecuritystandards.org | Free (registration) |
| ISO 27001:2022 | https://www.iso.org/standard/82875.html | Paid (~$180) |
| OSCAL | https://pages.nist.gov/OSCAL/ | Free |
| ComplianceAsCode | https://github.com/ComplianceAsCode/content | Free/Open Source |
| VECTR | https://github.com/SecurityRiskAdvisors/VECTR | Free/Open Source |
| GovReady-Q | https://github.com/GovReady/govready-q | Free/Open Source |
| FAIR Institute | https://www.fairinstitute.org | Free resources |
| Shared Assessments (SIG) | https://sharedassessments.org | Free (registration) |
| CSA CAIQ | https://cloudsecurityalliance.org/star/registry | Free |

---

*Last updated: April 2026 | Maintained by the TeamStarWolf community*
