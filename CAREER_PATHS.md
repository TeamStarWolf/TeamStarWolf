# Cybersecurity Career Paths

> Comprehensive progression guides covering 15+ cybersecurity roles — from entry-level to CISO. Each path includes salary ranges, key skills, certifications, HTB tracks, tools, and typical job titles at every level.

---

## Overview: The Career Landscape

Cybersecurity careers fall into five broad domains. Most practitioners start in one domain and later specialize or pivot as they develop depth.

| Domain | Focus | Example Roles |
|---|---|---|
| **Offensive Security** | Adversarial testing, vulnerability discovery, exploitation | Penetration Tester, Red Team Operator, Bug Bounty Hunter |
| **Defensive Security / Blue Team** | Detection, response, hunting, forensics | SOC Analyst, Incident Responder, Threat Hunter, Malware Analyst |
| **Security Engineering** | Building and securing systems, infrastructure, code | AppSec Engineer, Cloud Security Engineer, Detection Engineer |
| **Governance, Risk & Compliance** | Policy, audit, risk frameworks, regulatory compliance | GRC Analyst, Vulnerability Manager, Security Architect, CISO |
| **Research & Intelligence** | Threat intelligence, reverse engineering, vulnerability research | Threat Intelligence Analyst, Malware Analyst, RE Specialist |

> **Navigation tip:** Use [CERTIFICATIONS.md](CERTIFICATIONS.md) for detailed cert breakdowns, [LABS.md](LABS.md) for hands-on practice environments, [TOOLS.md](TOOLS.md) for tool references, and [research/HTB_TRACKS.md](research/HTB_TRACKS.md) for structured HackTheBox learning paths.

---

## Career Path 1: SOC Analyst (Tier 1 / 2 / 3)

**Role description:** SOC Analysts are the frontline of security operations. They monitor SIEM dashboards, triage alerts, investigate suspicious activity, and escalate confirmed incidents. Tier 1 handles initial alert triage; Tier 2 performs deeper investigation; Tier 3 leads threat hunting and detection engineering.

**Typical responsibilities:**
- Monitor SIEM, EDR, and NDR alerts in real time
- Triage, investigate, and document security events
- Execute incident response playbooks
- Tune detection rules to reduce false positives
- Escalate confirmed incidents to IR / leadership
- Produce shift handoff reports and metrics

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry (Tier 1) | Junior SOC Analyst / SOC Analyst I | $50,000 – $75,000 |
| Mid (Tier 2) | SOC Analyst II / Senior Analyst | $75,000 – $105,000 |
| Senior (Tier 3) | SOC Lead / Principal Analyst | $105,000 – $140,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Windows & Linux fundamentals | Threat hunting methodology | Detection-as-code, Sigma authoring |
| TCP/IP networking basics | Malware triage (static/dynamic) | SOAR playbook development |
| SIEM navigation (Splunk, Sentinel) | EDR deep-dive investigation | ATT&CK coverage gap analysis |
| Alert triage and ticketing | OSINT and threat intel lookups | Mentorship and shift leadership |
| Basic scripting (Python/Bash) | Intermediate scripting / automation | Advanced log correlation and analytics |

**Recommended certifications:** [CompTIA Security+](CERTIFICATIONS.md), [CompTIA CySA+](CERTIFICATIONS.md), [BTL1](CERTIFICATIONS.md), [SC-200](CERTIFICATIONS.md), [GIAC GSOC](CERTIFICATIONS.md), [GIAC GSOM](CERTIFICATIONS.md)

**Recommended HTB tracks:** [SOC Analyst Path](research/HTB_TRACKS.md), [Defensive Security Track](research/HTB_TRACKS.md)

**Tools commonly used:** Splunk, Microsoft Sentinel, IBM QRadar, CrowdStrike Falcon, SentinelOne, Elastic SIEM, TheHive, MISP, Cortex XSOAR, VirusTotal, AbuseIPDB

---

## Career Path 2: Incident Responder / DFIR

**Role description:** Digital Forensics and Incident Response (DFIR) specialists investigate confirmed breaches, contain active threats, and recover evidence to support remediation and legal proceedings. They work under pressure with tight timelines and must quickly understand attacker actions across endpoints, networks, and cloud environments.

**Typical responsibilities:**
- Lead and coordinate incident response engagements
- Acquire and analyze disk, memory, and network forensic artifacts
- Build and execute containment and eradication plans
- Produce executive summaries and detailed forensic reports
- Conduct post-incident root cause analysis
- Maintain and improve IR playbooks and runbooks

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Junior IR Analyst / DFIR Analyst | $65,000 – $90,000 |
| Mid | Incident Responder / DFIR Engineer | $90,000 – $130,000 |
| Senior | Senior IR Lead / DFIR Manager | $130,000 – $175,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Windows event log analysis | Memory forensics (Volatility) | Cloud forensics (AWS/Azure/GCP) |
| Disk imaging and chain of custody | Network forensics (Wireshark, Zeek) | Threat actor TTPs and campaign attribution |
| Basic malware triage | Lateral movement detection | IR program development and tabletop design |
| IR playbook execution | Timeline reconstruction | Executive communication and crisis management |
| Log parsing (Splunk / ELK) | Endpoint artifact analysis (MFT, prefetch) | Advanced scripting for artifact automation |

**Recommended certifications:** [GIAC GCFE](CERTIFICATIONS.md), [GIAC GCFA](CERTIFICATIONS.md), [GIAC GREM](CERTIFICATIONS.md), [BTL1](CERTIFICATIONS.md), [GCIH](CERTIFICATIONS.md), [GIAC FOR508](CERTIFICATIONS.md)

**Recommended HTB tracks:** [DFIR Track](research/HTB_TRACKS.md), [SOC Analyst Path](research/HTB_TRACKS.md)

**Tools commonly used:** Velociraptor, KAPE, Volatility3, Autopsy, FTK Imager, Wireshark, Zeek, Elastic, Splunk UBA, CrowdStrike Falcon, Cado Security, Mandiant Redline

---

## Career Path 3: Threat Hunter

**Role description:** Threat Hunters proactively search for attacker activity that has evaded automated detections. They operate hypothesis-driven investigations, develop hunting queries, and feed findings back into the detection pipeline.

**Typical responsibilities:**
- Develop and execute threat hunts based on intel and ATT&CK TTPs
- Analyze large datasets across SIEM, EDR, and network logs
- Produce hunt reports with detection recommendations
- Collaborate with detection engineers to productize hunt findings
- Stay current on adversary tradecraft and new TTPs
- Contribute to threat intel sharing

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Junior Threat Hunter / Hunt Analyst | $75,000 – $100,000 |
| Mid | Threat Hunter | $100,000 – $135,000 |
| Senior | Lead Threat Hunter / Principal Hunter | $135,000 – $175,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| SIEM query proficiency (SPL/KQL) | Hypothesis-driven hunt methodology | Hunt program development and metrics |
| ATT&CK framework navigation | Behavioral analytics and anomaly detection | Threat intel consumption and production |
| Log source knowledge (Windows, Linux, AD) | UEBA and statistical baselining | Detection feedback loop automation |
| Scripting (Python/PowerShell) | Advanced EDR query capabilities | Research and external threat briefings |

**Recommended certifications:** [GIAC GCTI](CERTIFICATIONS.md), [GIAC GDAT](CERTIFICATIONS.md), [SANS FOR578](CERTIFICATIONS.md), [SC-200](CERTIFICATIONS.md), [Splunk Core Power User](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Threat Hunting Path](research/HTB_TRACKS.md), [SOC Analyst Path](research/HTB_TRACKS.md)

**Tools commonly used:** Splunk, Microsoft Sentinel, Elastic Stack, CrowdStrike Humio, Tanium, Velociraptor, Jupyter Notebooks, MISP, YARA, OpenCTI

---

## Career Path 4: Penetration Tester

**Role description:** Penetration testers simulate real-world attacks against networks, systems, and applications to find vulnerabilities before adversaries do. They produce detailed reports with risk-rated findings and remediation guidance for clients or internal stakeholders.

**Typical responsibilities:**
- Conduct scoped penetration tests (network, web app, internal, external)
- Perform reconnaissance, exploitation, and post-exploitation
- Document findings with proof-of-concept evidence
- Deliver technical and executive-level reports
- Retest remediated vulnerabilities
- Develop and maintain testing toolkits and scripts

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Junior Penetration Tester / Associate Consultant | $65,000 – $90,000 |
| Mid | Penetration Tester / Security Consultant | $90,000 – $130,000 |
| Senior | Senior Pentester / Engagement Lead | $130,000 – $175,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Network fundamentals and enumeration | Active Directory attacks (Kerberoasting, DCSync) | Custom exploit development |
| Web application testing (OWASP Top 10) | Evasion and AV bypass techniques | Red team operation design |
| Basic exploitation (Metasploit) | Pivoting and tunneling | Client management and scope negotiation |
| Report writing | Web app deep-dive (OAuth, API, GraphQL) | Mentoring junior testers |
| Linux privilege escalation | Post-exploitation and persistence | Research and CVE discovery |

**Recommended certifications:** [OSCP (OffSec)](CERTIFICATIONS.md), [eJPT](CERTIFICATIONS.md), [GIAC GPEN](CERTIFICATIONS.md), [GIAC GWAPT](CERTIFICATIONS.md), [CompTIA PenTest+](CERTIFICATIONS.md), [BSCP](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Penetration Tester Path](research/HTB_TRACKS.md), [Active Directory Track](research/HTB_TRACKS.md)

**Tools commonly used:** Nmap, Metasploit Framework, Burp Suite Pro, Bloodhound, Impacket, CrackMapExec, Cobalt Strike, Havoc C2, Nessus, Nuclei, ffuf, sqlmap, John the Ripper, Hashcat

---

## Career Path 5: Red Team Operator

**Role description:** Red Team Operators emulate specific advanced persistent threat (APT) actors against mature organizations to test detection, response, and resilience. Unlike penetration testing, the focus is on stealth, persistence, and full attack chain simulation rather than maximum coverage.

**Typical responsibilities:**
- Plan and execute full-scope adversary emulation engagements
- Develop custom malware, implants, and C2 infrastructure
- Emulate specific threat actor TTPs from intel reports
- Coordinate purple team exercises with blue team counterparts
- Produce detailed engagement reports with ATT&CK mapping
- Research new offensive techniques and weaponize vulnerabilities

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Red Team Analyst / Junior Operator | $85,000 – $110,000 |
| Mid | Red Team Operator | $110,000 – $150,000 |
| Senior | Senior Red Team Operator / Red Team Lead | $150,000 – $200,000+ |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Penetration testing fundamentals | C2 framework operation (Cobalt Strike, Havoc) | Custom implant and C2 development |
| Active Directory exploitation | OPSEC tradecraft | Adversary emulation planning |
| Basic C/C++ or Golang for tooling | EDR and AV evasion | Purple team program leadership |
| Scripting (Python, PowerShell) | Phishing infrastructure setup | Research and novel TTP development |
| Report writing | Persistence and lateral movement | Senior stakeholder engagement |

**Recommended certifications:** [CRTO](CERTIFICATIONS.md), [CRTE](CERTIFICATIONS.md), [OSEP (OffSec)](CERTIFICATIONS.md), [GIAC GRTP](CERTIFICATIONS.md), [PNPT](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Red Team Operator Path](research/HTB_TRACKS.md), [Active Directory Track](research/HTB_TRACKS.md)

**Tools commonly used:** Cobalt Strike, Havoc, Sliver, Metasploit, Bloodhound, Impacket, Rubeus, Mimikatz, Donut, PEzor, phishing frameworks (GoPhish, Evilginx2)

---

## Career Path 6: Application Security Engineer (AppSec)

**Role description:** AppSec Engineers embed security into the software development lifecycle. They perform code review, threat modeling, SAST/DAST scanning, and work alongside developers to reduce vulnerabilities before code ships to production.

**Typical responsibilities:**
- Conduct code reviews and static analysis (SAST)
- Perform dynamic application testing (DAST) and API security testing
- Lead threat modeling sessions with development teams
- Build and maintain AppSec tooling in CI/CD pipelines
- Triage and track vulnerability remediation
- Develop secure coding guidelines and training

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Junior AppSec Engineer / Security Analyst | $75,000 – $100,000 |
| Mid | Application Security Engineer | $100,000 – $145,000 |
| Senior | Senior AppSec Engineer / AppSec Lead | $145,000 – $195,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Web application vulnerability classes (OWASP) | Threat modeling (STRIDE, PASTA) | AppSec program design |
| SAST tool operation (Semgrep, CodeQL) | DAST and API fuzzing | Security champion program leadership |
| Basic code review (Python, JS, Java) | SBOM and supply chain security | Security architecture review |
| Scripting and automation | Secure SDLC integration | Developer enablement and training |
| Bug tracking and remediation | Container security (Dockerfile, K8s) | Executive risk communication |

**Recommended certifications:** [GWEB](CERTIFICATIONS.md), [GIAC GWEB](CERTIFICATIONS.md), [BSCP](CERTIFICATIONS.md), [CSSLP (ISC2)](CERTIFICATIONS.md), [OSWE](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Bug Bounty Hunter Path](research/HTB_TRACKS.md), [Web Fundamentals Track](research/HTB_TRACKS.md)

**Tools commonly used:** Burp Suite Pro, Semgrep, SonarQube, CodeQL, OWASP ZAP, Snyk, Checkmarx, Veracode, Nuclei, ffuf, OWASP Dependency-Check, Trivy

---

## Career Path 7: Cloud Security Engineer

**Role description:** Cloud Security Engineers design and enforce security controls across AWS, Azure, and GCP environments. They focus on identity and access management, infrastructure hardening, workload protection, and security posture management.

**Typical responsibilities:**
- Design cloud IAM policies and least-privilege access models
- Implement and tune CSPM tools (Prisma Cloud, Defender for Cloud)
- Harden cloud infrastructure (S3 buckets, security groups, KMS)
- Integrate security into cloud-native CI/CD pipelines
- Perform cloud penetration testing and architecture reviews
- Build detective controls using CloudTrail, GuardDuty, or Defender

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Cloud Security Analyst / Junior Engineer | $80,000 – $110,000 |
| Mid | Cloud Security Engineer | $110,000 – $155,000 |
| Senior | Senior Cloud Security Engineer / Architect | $155,000 – $210,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| AWS/Azure/GCP fundamentals | IAM design and federation (SAML, OIDC) | Multi-cloud architecture and zero trust |
| Cloud networking basics (VPC, NSG) | Container and Kubernetes security | Cloud security program leadership |
| Basic IaC (Terraform, CloudFormation) | CSPM configuration and tuning | Governance and policy automation |
| Security group and bucket policy review | Secrets management (Vault, AWS SM) | Cloud threat modeling |
| Logging and monitoring (CloudTrail, CloudWatch) | CI/CD security integration | Cost-effective security control design |

**Recommended certifications:** [AWS Security Specialty](CERTIFICATIONS.md), [AZ-500](CERTIFICATIONS.md), [Google Professional Cloud Security Engineer](CERTIFICATIONS.md), [CCSP (ISC2)](CERTIFICATIONS.md), [CKS (Kubernetes)](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Cloud Security Track](research/HTB_TRACKS.md), [Penetration Tester Path](research/HTB_TRACKS.md)

**Tools commonly used:** AWS GuardDuty, Microsoft Defender for Cloud, Prisma Cloud, Wiz, Orca Security, Terraform, Checkov, Trivy, Falco, Lacework, CloudSploit, ScoutSuite, Prowler

---

## Career Path 8: Security Engineer (Detection Engineering)

**Role description:** Detection Engineers build, tune, and maintain the detection logic that powers SOC operations. They translate threat intelligence and red team findings into high-fidelity alerts using SIEM platforms, EDR, and custom tooling.

**Typical responsibilities:**
- Author Sigma, KQL, and SPL detection rules
- Map detections to ATT&CK techniques and track coverage gaps
- Implement detection-as-code workflows with CI/CD pipelines
- Analyze false positive rates and tune existing detections
- Conduct purple team exercises to validate detection coverage
- Ingest new log sources and build parsing pipelines

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Junior Detection Engineer / SOC Engineer | $75,000 – $100,000 |
| Mid | Detection Engineer | $100,000 – $140,000 |
| Senior | Senior Detection Engineer / Lead | $140,000 – $185,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| SIEM query language (SPL, KQL, Lucene) | Sigma rule authoring | Detection-as-code CI/CD pipelines |
| ATT&CK framework proficiency | Detection coverage analysis | Purple team exercise design |
| Log source fundamentals | Automated testing of detections | Detection program metrics and KPIs |
| Python scripting | UEBA and anomaly detection | Platform engineering (data pipelines) |
| Version control (Git) | API integrations (threat intel feeds) | Mentorship and technical leadership |

**Recommended certifications:** [GIAC GCED](CERTIFICATIONS.md), [GIAC GDAT](CERTIFICATIONS.md), [SC-200](CERTIFICATIONS.md), [Splunk Enterprise Security Admin](CERTIFICATIONS.md)

**Recommended HTB tracks:** [SOC Analyst Path](research/HTB_TRACKS.md), [Defensive Security Track](research/HTB_TRACKS.md)

**Tools commonly used:** Splunk Enterprise Security, Microsoft Sentinel, Elastic SIEM, CrowdStrike Falcon, SigmaHQ, Uncoder.io, ATT&CK Navigator, MITRE Cyber Analytics Repository (CAR), DetectionLab, Atomic Red Team

---

## Career Path 9: GRC Analyst / Compliance

**Role description:** GRC (Governance, Risk, and Compliance) Analysts manage an organization's risk posture through policy development, control frameworks, audits, and regulatory compliance programs. They bridge business and technical teams.

**Typical responsibilities:**
- Develop, maintain, and socialize security policies and standards
- Conduct risk assessments and manage the risk register
- Lead audit readiness and response (SOC 2, ISO 27001, PCI DSS, CMMC)
- Map controls to multiple frameworks (NIST CSF, 800-53, CIS)
- Manage third-party / vendor risk assessments
- Produce compliance reports and board-level risk briefings

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | GRC Analyst / Compliance Analyst | $55,000 – $80,000 |
| Mid | Senior GRC Analyst / Risk Analyst | $80,000 – $115,000 |
| Senior | GRC Manager / Risk Manager | $115,000 – $160,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Security framework fundamentals (NIST CSF, ISO) | Control design and gap analysis | GRC program strategy and roadmap |
| Risk assessment methodology | Third-party risk management | Board and executive risk reporting |
| Policy writing and documentation | Audit management and evidence collection | M&A security due diligence |
| Excel and basic GRC tool use | GRC platform administration (ServiceNow, Archer) | Regulatory watch and program adaptation |
| Ticketing and project management | Continuous monitoring program | Multi-framework compliance management |

**Recommended certifications:** [CISA (ISACA)](CERTIFICATIONS.md), [CISM (ISACA)](CERTIFICATIONS.md), [CISSP (ISC2)](CERTIFICATIONS.md), [CompTIA Security+](CERTIFICATIONS.md), [ISO 27001 Lead Auditor](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Governance & Compliance Track](research/HTB_TRACKS.md)

**Tools commonly used:** ServiceNow GRC, RSA Archer, OneTrust, Drata, Vanta, Tugboat Logic, Qualys VMDR, Tenable.sc, Microsoft Compliance Manager, Jira

---

## Career Path 10: Vulnerability Management

**Role description:** Vulnerability Management specialists identify, prioritize, track, and drive remediation of vulnerabilities across an organization's entire attack surface — endpoints, servers, cloud workloads, applications, and network devices.

**Typical responsibilities:**
- Operate and tune vulnerability scanners across all asset types
- Prioritize findings using CVSS, EPSS, and business context
- Coordinate remediation with IT and engineering teams
- Track and report on SLA compliance and patching metrics
- Integrate VM data with GRC and CMDB platforms
- Manage vulnerability disclosure and bug bounty programs

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Vulnerability Analyst | $60,000 – $82,000 |
| Mid | Vulnerability Management Engineer | $82,000 – $120,000 |
| Senior | VM Program Lead / Senior Engineer | $120,000 – $160,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Vulnerability scanner operation (Nessus, Qualys) | CVSS and EPSS scoring | VM program development and metrics |
| Asset inventory fundamentals | Risk-based prioritization | Executive reporting and KPIs |
| Basic networking and system hardening | Patch management integration | Attack surface management strategy |
| Ticketing and SLA tracking | API integrations and automation | Third-party and supply chain VM |
| Remediation workflow basics | Cloud vulnerability management | Strategic tool evaluation |

**Recommended certifications:** [CompTIA Security+](CERTIFICATIONS.md), [GIAC GISF](CERTIFICATIONS.md), [Tenable Nessus Certification](CERTIFICATIONS.md), [Qualys Certified Specialist](CERTIFICATIONS.md), [AWS Security Specialty](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Penetration Tester Path](research/HTB_TRACKS.md), [Defensive Security Track](research/HTB_TRACKS.md)

**Tools commonly used:** Tenable.io, Qualys VMDR, Rapid7 InsightVM, Microsoft Defender Vulnerability Management, Wiz, Orca, CrowdStrike Spotlight, ServiceNow, Jira, Archer

---

## Career Path 11: Threat Intelligence Analyst

**Role description:** Threat Intelligence Analysts collect, process, analyze, and disseminate intelligence about adversaries, campaigns, and emerging threats to inform defensive priorities and decision-making at all organizational levels.

**Typical responsibilities:**
- Monitor open-source, commercial, and dark web threat feeds
- Produce strategic, operational, and tactical intelligence products
- Profile threat actors and map TTPs to ATT&CK
- Deliver intelligence briefings to SOC, IR, and leadership
- Manage threat intelligence platforms (TIPs) and indicator ingestion
- Support incident response with attribution and context

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Junior Threat Intel Analyst | $65,000 – $90,000 |
| Mid | Threat Intelligence Analyst | $90,000 – $130,000 |
| Senior | Senior CTI Analyst / Intel Lead | $130,000 – $175,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| OSINT collection techniques | Malware analysis and campaign tracking | Intelligence program strategy |
| ATT&CK and Diamond Model | Adversary profiling and attribution | Intelligence community relationships |
| Indicator ingestion and enrichment | TIP platform administration | Finished intelligence production |
| Report writing | Dark web monitoring | Collection management and requirements |
| STIX/TAXII fundamentals | Intelligence sharing (ISACs, ISAOs) | Executive intelligence briefings |

**Recommended certifications:** [GIAC GCTI](CERTIFICATIONS.md), [SANS FOR578](CERTIFICATIONS.md), [eCTHP (eLearnSecurity)](CERTIFICATIONS.md), [CompTIA CySA+](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Threat Intelligence Track](research/HTB_TRACKS.md), [SOC Analyst Path](research/HTB_TRACKS.md)

**Tools commonly used:** MISP, OpenCTI, Recorded Future, Mandiant Advantage, ThreatConnect, Anomali, Maltego, Shodan, SpiderFoot, VirusTotal Enterprise, Censys, YARA

---

## Career Path 12: Security Architect

**Role description:** Security Architects design the security framework for complex systems, networks, and cloud environments. They translate business requirements and risk appetite into defensible architectures, reference designs, and technology standards.

**Typical responsibilities:**
- Design security architecture for new systems, platforms, and acquisitions
- Develop and maintain enterprise security reference architectures
- Lead security design reviews for major projects and cloud migrations
- Define technology standards and tool selection criteria
- Assess architecture risk and produce architecture decision records
- Mentor engineers and consult on complex technical decisions

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Security Engineer (architecture track) | $100,000 – $130,000 |
| Mid | Security Architect | $130,000 – $180,000 |
| Senior | Principal / Enterprise Security Architect | $180,000 – $240,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Network and systems security fundamentals | Zero trust architecture design | Enterprise architecture and TOGAF |
| Cloud security foundations | Threat modeling (STRIDE, PASTA, LINDDUN) | Board-level risk communication |
| Identity and access management | Security reference architecture development | M&A security due diligence |
| Application security principles | Multi-cloud and hybrid architecture | Security program strategy |
| Compliance and risk frameworks | Technology standards governance | Emerging technology evaluation |

**Recommended certifications:** [CISSP (ISC2)](CERTIFICATIONS.md), [SABSA](CERTIFICATIONS.md), [TOGAF](CERTIFICATIONS.md), [CCSP](CERTIFICATIONS.md), [AWS Solutions Architect — Security](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Enterprise Architecture Track](research/HTB_TRACKS.md), [Cloud Security Track](research/HTB_TRACKS.md)

**Tools commonly used:** Lucidchart, draw.io, Microsoft Visio, IriusRisk, OWASP Threat Dragon, Archimate, AWS Well-Architected Tool, Azure Advisor, Terraform, SABSA framework tools

---

## Career Path 13: CISO / Security Leadership

**Role description:** The Chief Information Security Officer (CISO) owns the enterprise security program. This executive role requires equal parts technical credibility, business acumen, and leadership skill. CISOs report to the CEO, CFO, or Board and are accountable for security strategy, risk posture, and regulatory compliance.

**Typical responsibilities:**
- Set and execute the enterprise security strategy and roadmap
- Own the security budget and resource allocation
- Report security posture and risk to the Board and executive team
- Lead security incident management at the executive level
- Drive security culture and awareness across the organization
- Manage vendor and partner security relationships
- Interface with regulators, auditors, and insurance carriers

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Director of Security / VP of Security | $150,000 – $200,000 |
| Mid | CISO (mid-market) | $200,000 – $300,000 |
| Senior | CISO (enterprise / Fortune 500) | $300,000 – $500,000+ |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Security program management | Board and executive communication | Corporate governance and fiduciary duty |
| Budget planning and forecasting | Cyber risk quantification (FAIR) | M&A and business integration |
| GRC program leadership | Regulatory and legal liaison | Public company reporting (SEC disclosures) |
| Team building and retention | Vendor and contract negotiation | Industry leadership and thought leadership |
| Incident management leadership | Security culture programs | Crisis management and media relations |

**Recommended certifications:** [CISSP (ISC2)](CERTIFICATIONS.md), [CISM (ISACA)](CERTIFICATIONS.md), [CGEIT (ISACA)](CERTIFICATIONS.md), [CRISC (ISACA)](CERTIFICATIONS.md), [Harvard/MIT Executive Education](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Leadership & Strategy Track](research/HTB_TRACKS.md)

**Tools commonly used:** Board reporting dashboards, GRC platforms (ServiceNow, Archer), Cyber risk quantification tools (RiskLens/FAIR), Microsoft Secure Score, CTEM platforms, Bitsight, SecurityScorecard

---

## Career Path 14: Malware Analyst / Reverse Engineer

**Role description:** Malware Analysts and Reverse Engineers dissect malicious software to understand its behavior, capabilities, and origins. Their findings feed threat intelligence, detection engineering, and incident response teams.

**Typical responsibilities:**
- Perform static and dynamic analysis of malware samples
- Reverse engineer compiled binaries (x86/x64, ARM)
- Identify C2 protocols, evasion techniques, and persistence mechanisms
- Write YARA and Sigma rules based on discovered indicators
- Produce detailed malware analysis reports
- Support incident response with active sample analysis
- Contribute to threat actor tracking and campaign analysis

**Salary ranges (USD):**

| Level | Title | Salary Range |
|---|---|---|
| Entry | Junior Malware Analyst | $70,000 – $95,000 |
| Mid | Malware Analyst / Reverse Engineer | $95,000 – $140,000 |
| Senior | Senior RE / Principal Malware Analyst | $140,000 – $190,000 |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| Static analysis (PE structure, strings, hashes) | x86/x64 assembly proficiency | Kernel-level and rootkit analysis |
| Dynamic analysis (sandboxes, process monitoring) | Anti-analysis technique identification | Vulnerability research from binaries |
| YARA rule writing | Deobfuscation and unpacking | Advanced RE (firmware, mobile, embedded) |
| Basic assembly reading | C2 protocol reverse engineering | Research publications and CVE analysis |
| Network traffic analysis (Wireshark) | Automated analysis scripting | Malware family tracking and attribution |

**Recommended certifications:** [GIAC GREM](CERTIFICATIONS.md), [SANS FOR610](CERTIFICATIONS.md), [eMAPT (eLearnSecurity)](CERTIFICATIONS.md), [OSCP](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Malware Analysis Track](research/HTB_TRACKS.md), [Reverse Engineering Track](research/HTB_TRACKS.md)

**Tools commonly used:** IDA Pro, Ghidra, x64dbg, OllyDbg, Binary Ninja, Cutter, Radare2, PE-bear, DIE, Detect-It-Easy, ANY.RUN, Cuckoo Sandbox, CAPE Sandbox, FLARE-VM, REMnux, Wireshark, Procmon, TCPView

---

## Career Path 15: Bug Bounty Hunter (Non-Traditional Path)

**Role description:** Bug Bounty Hunters independently discover and responsibly disclose vulnerabilities in exchange for monetary rewards from organizations via platforms like HackerOne, Bugcrowd, and Intigriti. This is an entrepreneurial, self-directed path with high variance in income and no formal employment structure.

**Typical responsibilities:**
- Select programs and review scope documentation
- Perform web, mobile, and API security testing
- Discover, reproduce, and document vulnerabilities
- Write high-quality, reproducible bug reports
- Respond to triage team questions and provide clarifications
- Build a reputation and relationships within the community

**Earnings (variable, not salary):**

| Level | Profile | Typical Annual Earnings |
|---|---|---|
| Beginner | Learning and first P3/P4 bugs | $0 – $10,000 |
| Intermediate | Consistent P2/P3 finder, known program contributor | $15,000 – $80,000 |
| Top Hunter | P1/Critical finder, invited private programs | $100,000 – $500,000+ |

**Key skills:**

| Entry | Mid | Senior |
|---|---|---|
| OWASP Top 10 web vulnerabilities | Chained vulnerability exploitation | Novel vulnerability class research |
| Burp Suite proficiency | Mobile and API testing | Program-specific deep-dives |
| Recon and subdomain enumeration | Automation and custom tooling | Community contributions and writeups |
| Clear bug report writing | Business logic flaw discovery | Private program invitations |
| Basic scripting | SSRF, XXE, deserialization attacks | CVE disclosure and researcher reputation |

**Recommended certifications:** [BSCP (PortSwigger)](CERTIFICATIONS.md), [eWPT (eLearnSecurity)](CERTIFICATIONS.md), [OSWE](CERTIFICATIONS.md), [GIAC GWEB](CERTIFICATIONS.md)

**Recommended HTB tracks:** [Bug Bounty Hunter Path](research/HTB_TRACKS.md), [Web Fundamentals Track](research/HTB_TRACKS.md)

**Tools commonly used:** Burp Suite Pro, ffuf, Amass, Subfinder, httpx, Nuclei, GitHub Dorking, Shodan, Wayback Machine, gau, hakrawler, Arjun, SQLMap, custom Python automation

---

## Skill Progression Matrix

The table below summarizes the skills expected at each career level across technical and non-technical domains.

| Domain | Entry Level | Mid Level | Senior Level |
|---|---|---|---|
| **Technical — Networking** | TCP/IP, DNS, HTTP, VLANs, packet capture | Firewall rules, IDS/IPS, advanced protocol analysis | Network architecture, zero trust segmentation, SD-WAN |
| **Technical — Operating Systems** | Windows/Linux CLI, basic admin, file system | Kernel internals, Active Directory, hardening benchmarks | OS security architecture, custom kernel modules, firmware |
| **Technical — Cloud** | Console navigation, basic IAM, S3/VMs | IaC (Terraform), CSPM, container basics | Multi-cloud architecture, cloud security program design |
| **Technical — Programming** | Python scripting, Bash, PowerShell basics | API development, custom tooling, automation frameworks | Security tool development, platform engineering |
| **Technical — Security Tools** | SIEM navigation, scanner operation, Burp Suite basics | SIEM administration, EDR tuning, CI/CD integration | Platform engineering, custom detection pipelines |
| **Non-Technical — Communication** | Email and ticket writing, incident notes | Technical reports, stakeholder briefings | Board presentations, executive risk communication |
| **Non-Technical — Project Management** | Task tracking, following runbooks | Leading workstreams, coordinating across teams | Program ownership, budget, roadmap, OKRs |
| **Non-Technical — Business Acumen** | Understanding team goals | Translating technical risk to business impact | Cyber risk quantification, M&A, executive alignment |
| **Non-Technical — Mentorship** | Peer learning and knowledge sharing | Onboarding and guiding juniors | Team building, career development, succession planning |

---

## Transition Paths

Common and well-worn ways to move between roles as you grow.

| From | To | Key Bridge Skills | Estimated Transition Time |
|---|---|---|---|
| SOC Analyst (T1/T2) | Threat Hunter | Hypothesis-driven investigation, ATT&CK depth, advanced SIEM queries | 1 – 2 years |
| SOC Analyst (T2/T3) | Detection Engineer | Sigma authoring, git workflows, ATT&CK coverage analysis | 1 – 2 years |
| SOC Analyst | Incident Responder | Memory/disk forensics, Volatility, KAPE, timeline reconstruction | 1 – 2 years |
| Incident Responder | Malware Analyst | x86 assembly, Ghidra/IDA, sandbox analysis, YARA | 1 – 3 years |
| Penetration Tester | Red Team Operator | C2 operations, OPSEC, custom implant development, adversary emulation | 2 – 3 years |
| Penetration Tester | AppSec Engineer | Code review, threat modeling, SAST/DAST tooling, secure SDLC | 1 – 2 years |
| AppSec Engineer | Security Architect | Architecture patterns, threat modeling, risk frameworks, IaC | 2 – 4 years |
| Detection Engineer | Threat Intelligence Analyst | CTI frameworks, STIX/TAXII, adversary profiling, TIP administration | 1 – 2 years |
| GRC Analyst | Risk Manager / CISO track | Cyber risk quantification (FAIR), executive communication, program strategy | 3 – 6 years |
| Any technical role | Security Architect | Breadth across domains, threat modeling, risk frameworks, communication | 5 – 8 years |
| Security Architect / Sr. Manager | CISO | Executive leadership, board communication, FAIR/CTEM, legal/regulatory | 3 – 5 years |
| Bug Bounty Hunter | Penetration Tester | Scoped testing methodology, report writing, engagement management | 1 – 2 years |
| SOC / IR | Cloud Security Engineer | AWS/Azure/GCP fundamentals, IaC, CSPM, cloud IAM | 1 – 3 years |

---

## Career Transition Paths

### From IT/Sysadmin to Security
- **Strengths:** Deep system knowledge; networking; Windows/Linux administration
- **Recommended path:** CompTIA Security+ → CySA+ → get help desk/IT admin to SOC role → OSCP
- **Focus areas:** Learn detection engineering (Splunk/SIEM), incident response basics, vulnerability management
- **Timeline:** 6–12 months to first security role from IT background

### From Software Developer to AppSec/DevSecOps
- **Strengths:** Code understanding; SDLC familiarity; language expertise
- **Recommended path:** CSSLP or GWEB → AppSec engineer role at developer-friendly company → bug bounty
- **Focus areas:** OWASP Top 10 in depth; SAST/SCA/DAST tooling; threat modeling; secure code review
- **Timeline:** 3–6 months of focused study; can often lateral within same company

### From Military/Government to Civilian Security
- **Strengths:** TS/SCI clearance (high value); discipline; incident response experience
- **Recommended path:** Leverage clearance for cleared positions → CISSP for leadership → or OSCP for technical
- **Resources:** Hire Veterans (Military.com), ClearanceJobs.com, Veteran SEC (veteran security community)
- **DoD 8570/8140:** Mapping military experience to civilian cert equivalencies

### From Finance/Compliance to GRC
- **Strengths:** Risk mindset; regulatory knowledge; audit experience
- **Recommended path:** CISM or CRISC → GRC analyst role → CISA for audit-focused career
- **Focus areas:** NIST CSF/800-53, SOC 2, ISO 27001 implementation, vendor risk management

---

## Job Search Strategy

### Resume Tips for Security
- **Quantify impact:** "Reduced MTTD from 4 hours to 45 minutes by implementing X" beats "improved detection"
- **List certifications prominently:** Certs are table stakes for HR keyword filtering
- **Include GitHub:** Especially for technical roles; show tools, scripts, CTF writeups
- **Tailor to job description:** Mirror language from job posting; ATS (Applicant Tracking System) keyword matching
- **Avoid:** Listing Windows/Linux as skills (assumed); generic "team player" language

### Where to Find Security Jobs

| Platform | Best For | Notes |
|---|---|---|
| LinkedIn | All roles | Best network; set "Open to Work"; connect with recruiters |
| CyberSecJobs.com | Security-specific | Aggregates security jobs |
| Indeed | Volume | Broad search; many entry-level roles |
| Dice | Technical roles | Strong for security engineers |
| USAJobs.gov | Federal/cleared | All federal positions; clearance required for many |
| ClearanceJobs.com | Cleared positions | Requires active clearance or eligibility |
| Hack The Box Jobs | Technical roles | Self-selecting for technical candidates |
| Twitter/X | Networking | Many CISO/practitioner referrals shared on cybersecurity Twitter |
| Discord servers | Community referrals | TryHackMe, HTB, SANS Discord communities |

---

## Resource Recommendations

| Resource | What it covers |
|---|---|
| [CERTIFICATIONS.md](CERTIFICATIONS.md) | 40+ certifications with cost, difficulty, DoD 8570 mapping, and target audience |
| [LABS.md](LABS.md) | Free and paid hands-on lab environments, CTF platforms, and home lab builds |
| [TOOLS.md](TOOLS.md) | 100+ security tools organized by category with OSS/commercial tags |
| [research/HTB_TRACKS.md](research/HTB_TRACKS.md) | Structured HackTheBox learning paths mapped to career tracks |
| [FRAMEWORKS.md](FRAMEWORKS.md) | Side-by-side comparison of NIST CSF, 800-53, ISO 27001, SOC 2, and 10+ others |
| [Disciplines](README.md#disciplines) | Deep-dive pages for 30+ cybersecurity specializations |
| [IR Playbooks](IR_PLAYBOOKS.md) | Step-by-step response procedures for common incident types |
| [Threat Actors](THREAT_ACTORS.md) | Nation-state APTs and ransomware groups mapped to ATT&CK TTPs |

---

*Last updated: April 2026 · Maintained by [TeamStarWolf](https://github.com/TeamStarWolf)*
