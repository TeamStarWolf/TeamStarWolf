# Enterprise Security Pipeline

This page maps the full enterprise security lifecycle — from governance through continuous improvement — with the commercial vendors that operate at each stage. The pipeline is the framework that ties the individual disciplines together into a coherent program.

The most important insight: **vendors are not confined to a single stage.** CrowdStrike appears in prevention, telemetry, detection, response, and forensics. Microsoft appears in identity, endpoint, cloud, detection, and recovery. Splunk appears in telemetry, detection, investigation, and evidence. This is not overlap — it reflects how the most capable platforms operate across the full security lifecycle. The pipeline organizes what they *do*, not just what category they are sold into.

---

## The Pipeline at a Glance

```
GRC (ServiceNow, RSA, OneTrust)
  → Identity & Trust (Microsoft Entra, Okta, CyberArk, Zscaler)
  → Preventive Controls (CrowdStrike, Palo Alto, Wiz, Proofpoint, Snyk)
  → Telemetry (Splunk, Microsoft Sentinel, Elastic, Chronicle)
  → Detection Engineering (Splunk, Exabeam, Recorded Future, Mandiant)
  → Triage & Correlation (SIEM + SOAR + MSSP)
  → Investigation (CrowdStrike, SentinelOne, Splunk, Varonis)
  → Incident Response & Containment (EDR + Identity + Network + SOAR)
  → Evidence & Forensics (Mandiant, Magnet Forensics, CrowdStrike)
  → Eradication & Recovery (Veeam, Rubrik, Wiz, Okta)
  → Post-Incident & Continuous Improvement (ServiceNow, Splunk, Qualys, Rapid7)
```

---

## Stage 1 — Governance, Risk & Compliance (GRC)

**Purpose:** Define what must be protected, establish policies, and manage risk at the organizational level. GRC is the foundation — it drives the control requirements that every downstream stage must satisfy.

**What happens here:**
- Security policies are defined and approved
- Risk registers are maintained and scored
- Compliance requirements are mapped to controls (NIST CSF, ISO 27001, SOC 2, HIPAA, PCI DSS)
- Remediation SLAs are enforced
- Risk feeds into detection prioritization downstream

**Vendors:**

| Vendor | Role |
|---|---|
| **ServiceNow** | The operational backbone of most enterprise security programs; GRC module for policy management, risk registers, and control tracking; integrates with every downstream stage for remediation ticketing and workflow |
| **RSA Archer** | Enterprise GRC platform for risk governance, audit management, and third-party risk; strong in financial services and regulated industries |
| **OneTrust** | Privacy, compliance, and ESG management; strongest for data privacy regulation compliance (GDPR, CCPA) and third-party risk assessments |
| **MetricStream** | Enterprise GRC with integrated risk quantification; CISO dashboard and board-level risk reporting |
| **Lockpath (Navex)** | Policy management, incident reporting, and compliance automation; mid-market GRC alternative |
| **SAP GRC** | Risk and compliance modules integrated into SAP enterprise environments; strongest for organizations running SAP ERP |

---

## Stage 2 — Asset, Identity & Trust Foundation

**Purpose:** Know everything that exists in your environment and control who/what can access it. You cannot protect assets you don't know about, and you cannot detect anomalies without a baseline of normal identity and asset behavior.

**What happens here:**
- Complete asset inventory (hardware, software, cloud resources, OT/IoT)
- Identity lifecycle management (provisioning, de-provisioning, privileged access)
- Zero trust architecture enforcement
- Trust baselines established for detection use downstream

**Identity & Access Management:**

| Vendor | Role |
|---|---|
| **Microsoft Entra ID (Azure AD)** | The dominant enterprise identity platform; SSO, MFA, Conditional Access, Privileged Identity Management; the identity telemetry source for most enterprise detection pipelines |
| **Okta** | Cloud-first identity platform; strongest for multi-cloud and SaaS-heavy environments; Universal Directory and Okta Identity Governance |
| **Ping Identity** | Enterprise IAM with strong federation and API security; common in financial services and large enterprises with complex identity requirements |
| **CyberArk** | Privileged Access Management (PAM) market leader; vault, session recording, and just-in-time access for privileged accounts; the standard for protecting administrative credentials |
| **BeyondTrust** | PAM and privileged remote access; strong for securing vendor and contractor access |

**Zero Trust / Network Access:**

| Vendor | Role |
|---|---|
| **Zscaler** | Zero Trust Network Access (ZTNA) and Secure Web Gateway; SWG, CASB, and ZTNA in a cloud-delivered platform; the defining zero trust access vendor |
| **Netskope** | CASB and ZTNA with deep data context; strongest for organizations needing visibility into cloud app usage and data movement |

**Asset & Exposure Management:**

| Vendor | Role |
|---|---|
| **Tanium** | Endpoint management and security at scale; real-time asset inventory, patch management, and vulnerability data from a single agent |
| **Axonius** | Cybersecurity asset management aggregating data from 800+ integrations; the most comprehensive asset inventory solution for complex environments |

---

## Stage 3 — Preventive Controls (Attack Surface Reduction)

**Purpose:** Stop as many attacks as possible before they succeed. Prevention reduces attacker success rates and improves signal quality for the detection stages — a prevented attack generates no noisy alerts.

**Endpoint Protection & EDR:**

| Vendor | Role |
|---|---|
| **CrowdStrike Falcon** | Market-leading EDR and endpoint protection; behavioral AI prevention, threat intelligence integration, and the fastest response capability in the industry |
| **SentinelOne Singularity** | EDR and XDR with autonomous response; strong prevention through behavioral AI without cloud connectivity dependency |
| **Microsoft Defender for Endpoint** | Integrated endpoint protection for Microsoft environments; strong value for organizations with existing Microsoft licensing |
| **Trellix (McAfee/FireEye)** | Enterprise endpoint protection with XDR integration; long-standing enterprise market presence |

**Network Security:**

| Vendor | Role |
|---|---|
| **Palo Alto Networks NGFW** | Market-leading next-generation firewall with App-ID and threat prevention; the dominant enterprise perimeter security platform |
| **Fortinet FortiGate** | High-performance NGFW strong in mid-market and distributed enterprises; FortiOS integrates firewall, IPS, VPN, and SD-WAN |
| **Cisco Secure Firewall** | Enterprise network security deeply integrated with Cisco infrastructure; SecureX platform for coordinated network defense |
| **Zscaler Internet Access** | Cloud-delivered secure web gateway; routes all web traffic through Zscaler for inspection without on-premises hardware |

**Email Security:**

| Vendor | Role |
|---|---|
| **Proofpoint** | The dominant enterprise email security platform; advanced threat protection, DLP, and email authentication; captures phishing and BEC that gateway filters miss |
| **Mimecast** | Email security and resilience; threat protection, archiving, and continuity in a single platform |
| **Microsoft Defender for Office 365** | Native email protection for Microsoft 365 environments; strong value for organizations already in the Microsoft stack |

**Application Security:**

| Vendor | Role |
|---|---|
| **Veracode** | Enterprise SAST and DAST; compliance-focused with policy-based security gates |
| **Checkmarx** | SAST, SCA, DAST, and IaC scanning unified platform |
| **Snyk** | Developer-first security for code, open-source, containers, and IaC; the shift-left platform |
| **GitHub Advanced Security** | CodeQL SAST, secret scanning, and dependency review integrated into GitHub |

**Cloud Security:**

| Vendor | Role |
|---|---|
| **Wiz** | Agentless cloud security across AWS, Azure, and GCP; attack path visualization; the CNAPP market leader |
| **Orca Security** | Agentless cloud workload protection; fast deployment with comprehensive coverage |
| **Prisma Cloud (Palo Alto)** | Full CNAPP platform; CSPM, CWPP, container security, and IaC scanning |

**Data Security:**

| Vendor | Role |
|---|---|
| **Varonis** | Data security platform for on-premises and cloud file systems; detects data exposure, abnormal access, and insider threats through data behavior analytics |
| **BigID** | Data discovery and classification for privacy and security; finds sensitive data across structured and unstructured sources |

---

## Stage 4 — Telemetry Collection & Ingestion

**Purpose:** Collect, normalize, and store the raw security data that every downstream stage depends on. This is the central nervous system of the security program — without comprehensive, high-quality telemetry, detection and investigation are impossible.

**Core SIEM Platforms:**

| Vendor | Role |
|---|---|
| **Splunk Enterprise Security** | The most widely deployed enterprise SIEM; powerful SPL query language, Risk-Based Alerting, and the most mature ecosystem of detection content and integrations |
| **Microsoft Sentinel** | Cloud-native SIEM and SOAR; KQL analytics, Microsoft 365 Defender integration, and the most cost-effective option for Microsoft-heavy environments |
| **Elastic Security** | Open-source core with enterprise tiers; EQL for behavioral detection, unified endpoint and SIEM, and strong cost efficiency for high-volume environments |
| **Google Chronicle** | Cloud-native SIEM purpose-built for petabyte-scale telemetry; sub-second search across years of data; strongest for organizations in the Google Cloud ecosystem |
| **Devo** | Cloud-native SIEM with real-time streaming analytics; strong for organizations that need sub-second detection on high-velocity telemetry |

**Telemetry Sources by Domain:**

| Domain | Primary Sources |
|---|---|
| Endpoint | CrowdStrike Falcon, SentinelOne, Microsoft Defender, Carbon Black |
| Identity | Microsoft Entra ID, Okta, CyberArk PAM session logs |
| Network | Palo Alto Networks, Cisco, Zeek/Corelight, Suricata, NetFlow |
| Cloud | AWS CloudTrail/VPC Flow Logs, Azure Monitor, GCP Cloud Logging |
| Email | Proofpoint, Mimecast, Microsoft 365 Defender |
| Application | Web application logs, API gateway logs, WAF events |
| OT/ICS | Dragos, Claroty, Nozomi (forwarded to SIEM selectively) |

---

## Stage 5 — Detection Engineering

**Purpose:** Convert raw telemetry into meaningful signals by building, testing, and maintaining detection logic mapped to adversary behavior.

**What happens here:**
- Detection rules authored (Sigma → converted to platform-native format)
- Coverage mapped to ATT&CK
- Atomic Red Team tests validate coverage
- Threat intelligence enriches signals with context

**Detection Platforms:**

| Vendor | Role |
|---|---|
| **Splunk** | Correlation searches, Risk-Based Alerting framework, and Splunk Security Essentials detection content library |
| **Microsoft Sentinel** | KQL analytics rules, UEBA, Fusion ML-based correlation, and Azure Lighthouse for multi-tenant detection |
| **Elastic** | EQL rule engine with temporal sequence matching; ATT&CK alignment built in |
| **Exabeam** | UEBA-focused behavioral analytics; builds behavioral baselines and detects deviation; strong for insider threat and compromised credential use cases |
| **Securonix** | UEBA and SIEM with threat chains; purpose-built for behavioral detection where rule-based approaches struggle |

**Threat Intelligence Enrichment:**

| Vendor | Role |
|---|---|
| **Recorded Future** | Enriches alerts with real-time threat actor context, infrastructure attribution, and exploit intelligence |
| **Mandiant Advantage** | APT-level threat intelligence enrichment with the deepest adversary research in the industry |
| **CrowdStrike Falcon Intelligence** | Integrates adversary tracking directly into Falcon detections; eCrime and nation-state actor correlation |

---

## Stage 6 — Triage & Correlation

**Purpose:** Separate real threats from noise. The average enterprise SIEM generates thousands of alerts daily — effective triage determines what gets investigated, what gets closed, and what escalates.

**What happens here:**
- Alert scoring and prioritization
- False positive suppression through tuning and allow-listing
- Risk-based alert correlation (multiple low-fidelity signals = high-priority incident)
- Escalation to investigation or MSSP handoff

**Triage Platforms:**

| Vendor | Role |
|---|---|
| **Splunk** | Risk-Based Alerting (RBA) correlates low-priority risk events into high-priority notable events; reduces alert volume while maintaining coverage |
| **Microsoft Sentinel** | Fusion ML correlation; automatically groups related alerts into incidents; reduces analyst workload |
| **Exabeam** | Smart Timelines automatically build session context; threat chaining groups related events across users, hosts, and time |
| **Securonix** | Threat chains and UEBA baselines for behavioral triage |

**SOAR / Workflow Automation:**

| Vendor | Role |
|---|---|
| **Palo Alto Cortex XSOAR** | The dominant enterprise SOAR platform; 700+ integration packs and playbook automation for alert triage and enrichment |
| **Splunk SOAR (Phantom)** | SOAR integrated with Splunk SIEM; strong for automated triage and enrichment within Splunk ecosystems |
| **ServiceNow SecOps** | Connects security alerts to IT service management workflows; strong when triage outcomes need to flow into change management and IT ticketing |

**MSSP / MDR Layer:**

| Vendor | Role |
|---|---|
| **Secureworks Taegis** | MDR platform with co-managed SIEM, threat hunting, and 24/7 SOC coverage |
| **IBM Security Services** | Full-spectrum MSSP with QRadar SIEM, SOAR, and managed detection services |
| **Mandiant Managed Defense** | Premium MDR from Google; expert threat hunting and response on top of your existing SIEM |
| **Arctic Wolf** | MDR platform purpose-built for mid-market; Concierge Security Team model |

---

## Stage 7 — Investigation

**Purpose:** Understand what actually happened. When triage determines an alert represents a real threat, investigation builds the complete attack timeline: initial access, lateral movement, actions on objectives, and full scope.

**What happens here:**
- Endpoint timeline reconstruction
- Identity activity analysis (authentication logs, MFA bypasses, privilege use)
- Network traffic review
- Data access trail analysis
- Attack scope determination (what was touched, what was taken)

**Investigation Platforms:**

| Vendor | Role |
|---|---|
| **CrowdStrike Falcon** | Endpoint timeline with process trees, network connections, file operations, and registry changes; Process Explorer for real-time process investigation |
| **SentinelOne** | Storyline attack chain reconstruction; automated attack narrative generation from endpoint telemetry |
| **Splunk** | Cross-domain correlation during investigation; SPL queries joining endpoint, identity, and network logs into a unified timeline |
| **Elastic** | EQL temporal queries for attack sequence reconstruction across millions of events |
| **Microsoft Defender XDR** | Cross-domain investigation across endpoint, identity, email, and cloud in a unified incident view |
| **Varonis** | Data access trails showing exactly which files were accessed, modified, or exfiltrated; essential for data breach scope assessment |

---

## Stage 8 — Incident Response & Containment

**Purpose:** Stop the attacker's activity before further damage occurs. Containment must be fast, targeted, and coordinated across endpoint, identity, network, and email simultaneously to prevent re-entry.

**Endpoint Containment:**

| Vendor | Role |
|---|---|
| **CrowdStrike Falcon** | Network containment (isolate host while maintaining Falcon connectivity); Real Time Response for live forensic triage on isolated systems |
| **SentinelOne** | Remote kill process, quarantine file, network isolation with one-click automated response |
| **Microsoft Defender** | Device isolation, investigation package collection, and live response shell |

**Identity Containment:**

| Vendor | Role |
|---|---|
| **Microsoft Entra ID** | Disable compromised user accounts, revoke refresh tokens, force MFA re-enrollment, reset passwords at scale |
| **Okta** | Terminate active sessions, suspend accounts, reset MFA factors, and enforce step-up authentication |
| **CyberArk** | Rotate compromised privileged credentials, terminate PAM sessions, and enforce just-in-time access lockdown |

**Network Containment:**

| Vendor | Role |
|---|---|
| **Palo Alto Networks** | Dynamic firewall policy updates; block IPs, domains, and C2 infrastructure in real time |
| **Cisco** | Network segmentation enforcement; ISE for dynamic quarantine of compromised devices |
| **Zscaler** | Block user internet access, quarantine cloud app sessions, and enforce policy during active incidents |

**Email Containment:**

| Vendor | Role |
|---|---|
| **Proofpoint** | Email purge — retroactively remove malicious emails from all recipient mailboxes after delivery |
| **Microsoft Defender for Office 365** | Threat Explorer for bulk deletion of delivered phishing messages across the tenant |

**SOAR Automation:**

| Vendor | Role |
|---|---|
| **Palo Alto Cortex XSOAR** | Orchestrated playbooks coordinating containment actions across endpoint, identity, network, and email simultaneously |
| **Splunk SOAR** | Automated response playbooks triggered by SIEM detections; coordinates multi-tool containment without manual intervention |
| **ServiceNow** | IR case management, SLA tracking, and stakeholder communication workflows during active incidents |

---

## Stage 9 — Evidence & Forensics

**Purpose:** Preserve a truthful, auditable record of what happened. Evidence supports legal proceedings, regulatory reporting, insurance claims, and root cause analysis.

**What happens here:**
- Forensic images acquired (disk, memory, cloud snapshots)
- Chain of custody maintained
- SIEM logs preserved and timestamped
- Attack timeline documented with evidence artifacts
- Root cause determined

**Forensics Platforms:**

| Vendor | Role |
|---|---|
| **CrowdStrike Falcon Forensics** | Remote forensic artifact collection without physical access; KAPE-based triage across thousands of endpoints simultaneously |
| **Magnet Forensics** | AXIOM platform for disk, cloud, and mobile forensics; widely used in legal and law enforcement contexts requiring court-admissible evidence |
| **Cellebrite** | Digital intelligence platform for mobile device forensics and enterprise investigation |
| **FTI Consulting** | IR and forensics consulting firm specializing in legal-grade evidence preservation and expert witness testimony |
| **Mandiant (Google)** | Deep forensics expertise from the firm that defined modern IR methodology; used for complex nation-state and sophisticated threat actor investigations |

**Data Sources for Evidence:**

| Source | What It Preserves |
|---|---|
| SIEM (Splunk, Sentinel) | Full event timeline across all log sources |
| Endpoint (CrowdStrike, SentinelOne) | Process execution, file operations, network connections |
| Cloud logs (CloudTrail, Azure Monitor) | API calls, IAM actions, data access |
| Email (Proofpoint, Microsoft) | Message headers, delivery timestamps, recipient lists |
| Network pcap (Corelight, ExtraHop) | Packet-level evidence of communications |

---

## Stage 10 — Eradication & Recovery

**Purpose:** Remove every trace of attacker presence and restore systems to a verified clean state. Incomplete eradication leads to re-compromise.

**What happens here:**
- All persistence mechanisms identified and removed
- Compromised accounts reset or re-provisioned
- Malware and implants removed from all affected systems
- Systems rebuilt from known-good images where compromise depth requires it
- Cloud resources re-provisioned from IaC/Terraform
- Services restored with enhanced monitoring

**Eradication & Recovery Platforms:**

| Domain | Vendors |
|---|---|
| **Endpoint rebuild** | Microsoft (re-image via Intune/SCCM), CrowdStrike (verify clean state post-eradication) |
| **Identity reset** | Okta (bulk user reset, MFA re-enrollment), Microsoft Entra (credential reset at scale, Conditional Access enforcement) |
| **Cloud remediation** | Wiz (verify clean cloud posture post-incident), Prisma Cloud (policy enforcement on rebuilt resources), AWS/Azure/GCP native tools |
| **Backup and recovery** | Veeam (enterprise backup and recovery; immutable backup protection against ransomware), Rubrik (cloud-native backup with ransomware recovery SLA), Cohesity (data management and recovery) |
| **Privileged access rotation** | CyberArk (rotate all privileged credentials in vault after compromise) |

---

## Stage 11 — Post-Incident & Continuous Improvement

**Purpose:** Ensure each incident makes the program stronger. Lessons identified must become lessons implemented — not just documented.

**What happens here:**
- Incident retrospective / after-action review
- New detections built from observed attacker behavior
- Vulnerability gaps patched (the ones attackers used)
- Policies and controls updated
- Training gaps addressed
- Metrics updated for board reporting

**Improvement Platforms:**

| Vendor | Role |
|---|---|
| **ServiceNow** | Track all remediation tasks from retrospective findings; enforce SLAs on post-incident improvements; connect security findings to IT change management |
| **Splunk / Microsoft Sentinel** | Build new detections from TTPs observed during the incident; the fastest path from "this happened" to "we can detect this happening again" |
| **Recorded Future** | Update threat intelligence context with post-incident adversary attribution; adjust monitoring for observed adversary infrastructure |
| **Qualys / Rapid7** | Identify and track unpatched vulnerabilities that created attack surface; close gaps that contributed to the incident |
| **CrowdStrike** | Update prevention policy to block observed malware and tooling; add attacker indicators to custom IOC blocking |
| **Proofpoint / Mimecast** | Update email security policies based on observed phishing techniques |

---

## The Multi-Stage Vendor Map

The most mature vendors in the market operate across multiple pipeline stages simultaneously. Understanding this span is critical for both practitioners and security leaders evaluating platforms.

| Vendor | Stages Active |
|---|---|
| **CrowdStrike** | Prevention → Telemetry → Detection → Triage → Investigation → Containment → Forensics → Recovery verification |
| **Microsoft** | Identity → Prevention → Telemetry → Detection → Triage → Investigation → Containment → Recovery |
| **Splunk** | Telemetry → Detection → Triage → Investigation → Evidence → Improvement |
| **Palo Alto Networks** | Prevention (NGFW) → Triage (XSOAR) → Containment → Detection (Cortex XDR) |
| **Wiz** | Prevention (CSPM) → Telemetry (cloud context) → Detection (attack paths) → Recovery (posture verification) |
| **ServiceNow** | GRC → Triage (ticketing) → Containment (case management) → Improvement (remediation tracking) |
| **Okta** | Identity foundation → Containment → Recovery |
| **Recorded Future** | Detection enrichment → Triage context → Improvement (new intel) |
| **Varonis** | Prevention (data access control) → Investigation (data trails) → Evidence |
| **Proofpoint** | Prevention (email blocking) → Telemetry (email logs) → Containment (purge) → Recovery |

---

## Reading This Pipeline

**For practitioners entering the field:** Each stage maps to a discipline page in this repository. Start with the stage closest to your current role and use the pipeline to understand what feeds you inputs and what depends on your outputs.

**For practitioners building programs:** The pipeline reveals dependencies. You cannot do effective detection (Stage 5) without comprehensive telemetry (Stage 4). You cannot contain effectively (Stage 8) without identity and network tool integrations established in advance (Stage 2). Security program maturity follows this sequence.

**For security leaders:** Vendor sprawl is reduced by selecting platforms that span multiple stages. A CrowdStrike + Splunk + Microsoft + Palo Alto core covers the majority of the pipeline with deep integration between stages. Every additional point solution should be evaluated against whether it fills a genuine gap in that core or adds complexity that reduces effectiveness.

---

## Related Discipline Pages

Each stage in this pipeline has a corresponding deep-dive discipline page with free training, open-source tools, commercial platforms, certifications, and learning paths.

| Pipeline Stage | Discipline Page |
|---|---|
| GRC | [Threat Intelligence](disciplines/threat-intelligence.md) (feeds GRC risk context) |
| Identity & Trust | [Cloud Security](disciplines/cloud-security.md) (IAM attack surface) |
| Preventive Controls | [Application Security](disciplines/application-security.md), [Network Security](disciplines/network-security.md), [ICS/OT Security](disciplines/ics-ot-security.md) |
| Telemetry + Detection | [Detection Engineering](disciplines/detection-engineering.md) |
| Investigation + IR | [Incident Response](disciplines/incident-response.md) |
| Forensics | [Incident Response](disciplines/incident-response.md), [Malware Analysis](disciplines/malware-analysis.md) |
| Vulnerability + Recovery | [Vulnerability Management](disciplines/vulnerability-management.md) |
| Adversary Simulation | [Offensive Security](disciplines/offensive-security.md) |
| AI-Driven Stages | [AI & LLM Security](disciplines/ai-llm-security.md) |
