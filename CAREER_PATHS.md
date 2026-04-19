# Cybersecurity Career Paths

> Structured progression guides from entry-level to senior for the most common cybersecurity career tracks. Each path lists the skills, certs, and discipline pages relevant at each stage.

---

## How to Use This Guide

1. Pick the track closest to your current or target role
2. Start with the **Foundation** tier if you're new to security
3. Follow the cert and skill progression for each tier
4. Use the linked [discipline pages](README.md#disciplines) for deep-dives on each topic

---

## Track 1: Security Operations (SOC) Analyst

**Role:** Monitor SIEM alerts, investigate incidents, triage threats, operate SOAR playbooks.

| Tier | Title | Key Skills | Certs | Discipline Pages |
|---|---|---|---|---|
| Foundation | Junior SOC Analyst | Windows/Linux fundamentals, basic networking, SIEM navigation, alert triage | CompTIA Security+, CompTIA CySA+, BTL1 | [Security Operations](disciplines/security-operations.md), [Detection Engineering](disciplines/detection-engineering.md) |
| Mid | SOC Analyst L2 | Incident investigation, malware triage, threat hunting basics, Splunk/Sentinel | GIAC GSOC, SC-200, Splunk Core Power User | [Incident Response](disciplines/incident-response.md), [Threat Intelligence](disciplines/threat-intelligence.md) |
| Senior | SOC Lead / Threat Hunter | Detection engineering, Sigma rules, ATT&CK coverage analysis, SOAR automation | GIAC GSOM, GIAC GDAT, Splunk ES Admin | [Detection Engineering](disciplines/detection-engineering.md), [Active Defense & Deception](disciplines/active-defense-deception.md) |

---

## Track 2: Detection Engineer

**Role:** Build, tune, and validate detection content across SIEM, EDR, and NDR platforms.

| Tier | Title | Key Skills | Certs | Discipline Pages |
|---|---|---|---|---|
| Foundation | Junior Detection Engineer | SIEM basics, log analysis, Sigma rule structure, ATT&CK fundamentals | CompTIA Security+, SC-200 | [Detection Engineering](disciplines/detection-engineering.md), [Security Operations](disciplines/security-operations.md) |
| Mid | Detection Engineer | Sigma rule authoring, ATT&CK mapping, detection coverage analysis, Python/SPL | GIAC GCED, Splunk ES Admin | [Detection Engineering](disciplines/detection-engineering.md), [Threat Intelligence](disciplines/threat-intelligence.md) |
| Senior | Senior Detection Engineer | Detection-as-code, CI/CD for rules, purple team exercises, adversary emulation | GIAC GDAT, SANS FOR578 | [Purple Teaming](disciplines/purple-teaming.md), [Detection Engineering](disciplines/detection-engineering.md) |

---

## Track 3: Incident Responder / DFIR

**Role:** Investigate security incidents, perform forensic analysis, contain threats, and restore systems.

| Tier | Title | Key Skills | Certs | Discipline Pages |
|---|---|---|---|---|
| Foundation | Junior IR Analyst | Windows event logs, basic memory analysis, chain of custody, IR playbooks | CompTIA Security+, BTL1, GIAC GSEC | [Incident Response](disciplines/incident-response.md), [Digital Forensics](disciplines/digital-forensics.md) |
| Mid | Incident Responder | Disk/memory forensics, malware triage, network forensics, DFIR tooling | GCFE, GCFA, GNFA | [Digital Forensics](disciplines/digital-forensics.md), [Malware Analysis](disciplines/malware-analysis.md) |
| Senior | Senior DFIR / Threat Analyst | Advanced memory analysis, full intrusion reconstruction, threat intelligence, malware RE | GREM, GCFE, CCE | [Malware Analysis](disciplines/malware-analysis.md), [Threat Intelligence](disciplines/threat-intelligence.md) |

---

## Track 4: Penetration Tester / Red Team

**Role:** Simulate adversaries to identify vulnerabilities before attackers do.

| Tier | Title | Key Skills | Certs | Discipline Pages |
|---|---|---|---|---|
| Foundation | Junior Pentester | Networking fundamentals, Linux, web app basics, CTF methodology | CompTIA PenTest+, PJPT, eJPT | [Offensive Security](disciplines/offensive-security.md), [Bug Bounty](disciplines/bug-bounty.md) |
| Mid | Penetration Tester | Web/network/AD pentesting, Burp Suite, Metasploit, report writing | OSCP, PNPT, GPEN | [Offensive Security](disciplines/offensive-security.md), [Application Security](disciplines/application-security.md) |
| Senior | Red Team Operator | C2 operations, adversary emulation, custom tooling, evasion techniques | CRTO, OSED, OSEP | [Purple Teaming](disciplines/purple-teaming.md), [Active Defense & Deception](disciplines/active-defense-deception.md) |

---

## Track 5: Cloud Security Engineer

**Role:** Secure cloud infrastructure, manage CSPM/DSPM, enforce cloud IAM, and respond to cloud incidents.

| Tier | Title | Key Skills | Certs | Discipline Pages |
|---|---|---|---|---|
| Foundation | Cloud Security Analyst | AWS/Azure/GCP basics, IAM fundamentals, cloud misconfigurations, CSPM tools | CompTIA Cloud+, AWS Cloud Practitioner | [Cloud Security](disciplines/cloud-security.md), [Identity & Access Management](disciplines/identity-access-management.md) |
| Mid | Cloud Security Engineer | CSPM/DSPM, container security, cloud IAM hardening, IaC scanning | AWS Security Specialty, AZ-500, CCSP | [Cloud Security](disciplines/cloud-security.md), [DevSecOps](disciplines/devsecops.md) |
| Senior | Cloud Security Architect | Zero Trust cloud architecture, CIEM, data security, multi-cloud governance | CCSP, CCSK, AWS/Azure architect certs | [Security Architecture](disciplines/security-architecture.md), [Data Security](disciplines/data-security.md) |

---

## Track 6: AppSec / DevSecOps Engineer

**Role:** Integrate security into the software development lifecycle — shift left, automate scanning, and reduce vulnerabilities before production.

| Tier | Title | Key Skills | Certs | Discipline Pages |
|---|---|---|---|---|
| Foundation | AppSec Analyst | OWASP Top 10, basic SAST/DAST, code review fundamentals, bug bounty basics | CompTIA Security+, Web Security Academy | [Application Security](disciplines/application-security.md), [Bug Bounty](disciplines/bug-bounty.md) |
| Mid | DevSecOps Engineer | CI/CD pipeline security, SAST/SCA/DAST tools, IaC scanning, secrets management | CSSLP, GCSA | [DevSecOps](disciplines/devsecops.md), [Supply Chain Security](disciplines/supply-chain-security.md) |
| Senior | Principal AppSec / DevSecOps | Threat modeling, security architecture review, developer training, tool strategy | CSSLP, CISSP, BSCP | [Security Architecture](disciplines/security-architecture.md), [Cryptography & PKI](disciplines/cryptography-pki.md) |

---

## Track 7: GRC / Security Analyst

**Role:** Manage risk frameworks, lead compliance programs, conduct security assessments, and govern the security posture.

| Tier | Title | Key Skills | Certs | Discipline Pages |
|---|---|---|---|---|
| Foundation | GRC Analyst | NIST CSF, risk assessment basics, policy writing, audit support | CompTIA Security+, CISA (entry prep) | [Governance, Risk & Compliance](disciplines/governance-risk-compliance.md), [Privacy Engineering](disciplines/privacy-engineering.md) |
| Mid | Security Risk Analyst | NIST RMF, ISO 27001, SOC 2 audit, vendor risk management | CISM, CGRC, ISO 27001 Lead Implementer | [Governance, Risk & Compliance](disciplines/governance-risk-compliance.md) |
| Senior | CISO / Security Program Lead | Enterprise risk strategy, board reporting, security program management | CRISC, CISM, CISSP | [Governance, Risk & Compliance](disciplines/governance-risk-compliance.md), [Security Architecture](disciplines/security-architecture.md) |

---

## Certification Progression Map

### Entry-Level Certs (0–2 years)
```
CompTIA Security+  →  Industry baseline; required for many government/contractor roles
CompTIA CySA+      →  Blue team / SOC focus
CompTIA PenTest+   →  Offensive fundamentals
BTL1               →  Practical blue team; SOC analyst foundation
eJPT               →  Entry-level pentesting
```

### Mid-Level Certs (2–5 years)
```
OSCP               →  Gold standard for offensive; required for many red team roles
PNPT               →  Practical network pentesting; TCM Security
GPEN               →  Penetration testing professional
GCFE/GCFA          →  Forensic examiner / analyst
SC-200             →  Microsoft Sentinel operations
AWS Security Spec  →  Cloud security for AWS environments
CCSP               →  Cloud security professional (ISC²)
```

### Senior-Level Certs (5+ years)
```
CISSP              →  Broad security management; widely recognized
CISM               →  Security management focus
CRTO               →  Red team operator (Cobalt Strike / C2)
GREM               →  Malware reverse engineering
GDAT               →  Defending advanced threats
CRISC              →  Risk and compliance leadership
```

---

## Free Learning Path Resources

| Resource | Best For | Notes |
|---|---|---|
| [TryHackMe SOC Level 1](https://tryhackme.com/path/outline/soclevel1) | SOC beginners | Structured 60+ hour path |
| [HackTheBox CPTS](https://academy.hackthebox.com/path/preview/penetration-tester) | Pentesting | CPTS certification path |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | AppSec / Bug Bounty | 250+ free interactive labs |
| [Antisyphon Training](https://www.antisyphontraining.com/pay-forward-what-you-can/) | All tracks | Pay-what-you-can live courses |
| [SANS Cyber Aces](https://www.sans.org/cyberaces/) | Foundations | Free OS, networking, sys admin basics |
| [Professor Messer Security+](https://www.professormesser.com/security-plus/) | Security+ prep | Free video course |
| [TCM Security Academy](https://academy.tcm-sec.com/) | Pentesting / SOC | Affordable; practical hands-on |
| [LetsDefend](https://letsdefend.io/) | SOC / Blue team | Free SOC simulator |
