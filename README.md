<div align="center">

# TeamStarWolf

A public resource library for the cybersecurity community.

[Reference Index](INDEX.md) &nbsp;|&nbsp; [Discipline Paths](disciplines/) &nbsp;|&nbsp; [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/)

</div>

---

## Browse by Domain

<details>
<summary><strong>Offensive Security</strong></summary>

| Reference | Coverage |
|---|---|
| [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md) | Structured methodology for external, internal, web, and AD engagements |
| [Red Team Reference](RED_TEAM_REFERENCE.md) | ROE, C2 frameworks, OPSEC, payload dev, lateral movement tradecraft |
| [Active Directory Attacks](ACTIVE_DIRECTORY_ATTACKS.md) | Kerberoasting, DCSync, Golden tickets, BloodHound, AD CS attacks |
| [Web Application Pentesting](WEB_APPLICATION_PENTESTING.md) | SQLi, XSS, SSRF, JWT attacks, Burp Suite, auth bypass |
| [Social Engineering Reference](SOCIAL_ENGINEERING_REFERENCE.md) | Phishing, vishing, AiTM, pretexting, campaign ops |
| [Privilege Escalation Reference](PRIVESC_REFERENCE.md) | Windows and Linux privesc with detection and remediation |
| [Exploit Development Reference](EXPLOIT_DEVELOPMENT_REFERENCE.md) | Buffer overflows, ROP chains, shellcode, pwntools |
| [CTF Methodology](CTF_METHODOLOGY.md) | Web, forensics, crypto, reversing, pwn — systematic approach and tooling |

</details>

<details>
<summary><strong>Defensive Security</strong></summary>

| Reference | Coverage |
|---|---|
| [Incident Response Reference](INCIDENT_RESPONSE_REFERENCE.md) | NIST/SANS IR frameworks, live response, forensic triage |
| [Threat Hunting Reference](THREAT_HUNTING_REFERENCE.md) | Hypothesis-driven hunting, KQL/SPL queries, data sources |
| [SIEM Reference](SIEM_REFERENCE.md) | Splunk, Sentinel, QRadar, Elastic — query languages and detection engineering |
| [Digital Forensics Reference](DIGITAL_FORENSICS_REFERENCE.md) | Disk, memory, network, and cloud forensics workflows |
| [Malware Analysis Reference](MALWARE_ANALYSIS_REFERENCE.md) | Static/dynamic analysis, sandbox, behavioral detection |
| [Purple Team Reference](PURPLE_TEAM_REFERENCE.md) | Adversary emulation, Atomic Red Team, detection validation |
| [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) | Sigma, YARA, Suricata rule writing with examples |
| [Network Defense Reference](NETWORK_DEFENSE_REFERENCE.md) | IDS/IPS, firewall policy, network segmentation, NDR |

</details>

<details>
<summary><strong>Cloud & Infrastructure</strong></summary>

| Reference | Coverage |
|---|---|
| [Cloud Security Reference](CLOUD_SECURITY_REFERENCE.md) | AWS/Azure/GCP controls, IAM, CSPM, cloud-native threats |
| [Cloud Attack Reference](CLOUD_ATTACK_REFERENCE.md) | Cloud privilege escalation, lateral movement, exfiltration, persistence |
| [Container Security Reference](CONTAINER_SECURITY_REFERENCE.md) | Docker hardening, Kubernetes security, container escapes |
| [DevSecOps Reference](DEVSECOPS_REFERENCE.md) | SAST/DAST/SCA, GitHub Actions security, secrets in CI/CD |
| [Supply Chain Security Reference](SUPPLY_CHAIN_SECURITY_REFERENCE.md) | SBOM, Sigstore/cosign, SLSA, dependency security |
| [Network Security Architecture](NETWORK_SECURITY_ARCHITECTURE.md) | DMZ design, VLAN segmentation, firewall policy |
| [Windows Hardening Reference](WINDOWS_HARDENING_REFERENCE.md) | Sysmon, WEF, Defender, AppControl, GPO, ASR rules |
| [Linux Hardening Reference](LINUX_HARDENING_REFERENCE.md) | CIS benchmarks, sysctl, SELinux, auditd, service hardening |

</details>

<details>
<summary><strong>Identity, Access & Cryptography</strong></summary>

| Reference | Coverage |
|---|---|
| [Identity Access Management Reference](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) | IAM architecture, MFA, PAM, JIT, SSO |
| [Active Directory Security Reference](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) | AD hardening, tiered admin, MDI, Kerberos defense |
| [Zero Trust Reference](ZERO_TRUST_REFERENCE.md) | NIST SP 800-207, CISA ZTMM, microsegmentation, BeyondCorp |
| [Secrets Management Reference](SECRETS_MANAGEMENT_REFERENCE.md) | Vault, AWS Secrets Manager, rotation, detection |
| [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md) | Symmetric/asymmetric, TLS, PKI, HSM, quantum-resistant algorithms |
| [Password Security Reference](PASSWORD_SECURITY_REFERENCE.md) | Hash formats, hashcat/John, credential stuffing defense |

</details>

<details>
<summary><strong>Governance, Risk & Compliance</strong></summary>

| Reference | Coverage |
|---|---|
| [GRC Compliance Reference](GRC_COMPLIANCE_REFERENCE.md) | NIST 800-53, ISO 27001, SOC 2, PCI DSS, HIPAA, CMMC |
| [Security Metrics Reference](SECURITY_METRICS_REFERENCE.md) | MTTD/MTTR, vulnerability SLAs, SOC KPIs, FAIR model |
| [Threat Modeling Reference](THREAT_MODELING_REFERENCE.md) | STRIDE, PASTA, attack trees, MITRE ATT&CK integration |
| [Vulnerability Management Reference](VULNERABILITY_MANAGEMENT_REFERENCE.md) | CVSS, EPSS, CISA KEV, VEX, patch prioritization |
| [Privacy Engineering Reference](PRIVACY_ENGINEERING_REFERENCE.md) | GDPR/CCPA, PbD, data minimization, PIA |
| [Security Architecture Reference](SECURITY_ARCHITECTURE_REFERENCE.md) | Zero trust, defense-in-depth, SABSA, enterprise patterns |

</details>

<details>
<summary><strong>Specialized Domains</strong></summary>

| Reference | Coverage |
|---|---|
| [Automotive Security Reference](AUTOMOTIVE_SECURITY_REFERENCE.md) | CAN bus, ECU, V2X, OTA updates, ISO 21434 |
| [ICS/OT Security Reference](ICS_OT_SECURITY_REFERENCE.md) | SCADA, PLC, Purdue model, IEC 62443, OT incident response |
| [Hardware Security Reference](HARDWARE_SECURITY_REFERENCE.md) | TPM, HSM, side-channel attacks, JTAG/SWD, fault injection |
| [Firmware & IoT Security Reference](FIRMWARE_IOT_SECURITY_REFERENCE.md) | Binwalk, UART/JTAG extraction, firmware emulation |
| [Mobile Security Reference](MOBILE_SECURITY_REFERENCE.md) | OWASP MASVS, Android/iOS RE, Frida, MDM/MAM |
| [AI Security Reference](AI_SECURITY_REFERENCE.md) | LLM threat models, prompt injection, adversarial ML, MCP security |
| [SDR & RF Security Reference](SDR_RF_SECURITY_REFERENCE.md) | HackRF, Flipper Zero, sub-GHz analysis, RF attack surface |

</details>

<details>
<summary><strong>Research & Analysis</strong></summary>

| Reference | Coverage |
|---|---|
| [OSINT Reference](OSINT_REFERENCE.md) | Passive recon, Shodan/Censys, GEOINT, SOCMINT, automation |
| [Reverse Engineering Reference](REVERSE_ENGINEERING_REFERENCE.md) | Ghidra/IDA/Binary Ninja, dynamic analysis, firmware RE |
| [Threat Intelligence Reference](THREAT_INTELLIGENCE_REFERENCE.md) | Intel lifecycle, STIX/TAXII, threat actor tracking |
| [Network Protocols Reference](NETWORK_PROTOCOLS_REFERENCE.md) | TCP/IP, DNS, TLS, authentication protocols, analysis tools |
| [Packet Analysis Reference](PACKET_ANALYSIS_REFERENCE.md) | Wireshark, tcpdump, Zeek, JA3, attack pattern detection |
| [Network Forensics Reference](NETWORK_FORENSICS_REFERENCE.md) | PCAP forensics, NetFlow, encrypted traffic analysis, cloud |

**Coverage & Data**

ATT&CK Navigator layer and machine-readable edge tables mapping the TeamStarWolf vendor stack to NIST 800-53 controls and ATT&CK techniques.

| Resource | Description |
|---|---|
| [ATT&CK Navigator Layer](navigator/teamstarwolf_vendor_coverage.json) | NIST 800-53 R5 -> ATT&CK heatmap (313 techniques, CTID-sourced) &nbsp;[Load in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json) |
| [Vendor -> Control edges](data/vendor_to_control.jsonl) | 100+ vendor -> NIST 800-53 control mappings |
| [Control -> Technique edges](data/control_to_technique.jsonl) | NIST 800-53 R5 -> ATT&CK technique mappings (CTID) |
| [Vendor -> Technique edges](data/vendor_to_technique.jsonl) | Derived vendor -> ATT&CK technique coverage via control join |
| [Controls Mapping](CONTROLS_MAPPING.md) | Full vendor -> NIST 800-53 -> ATT&CK cross-reference |
| [Coverage Schema](COVERAGE_SCHEMA.md) | Gap scoring data model, JSON schemas, and Python scoring functions |

</details>

<details>
<summary><strong>Learning & Career</strong></summary>

| Reference | Coverage |
|---|---|
| [Career Paths](CAREER_PATHS.md) | 15+ security roles with skill maps, salary ranges, and cert roadmaps |
| [Certifications Reference](CERTIFICATIONS.md) | 40+ certifications with cost, difficulty, and domain coverage |
| [Interview Prep](INTERVIEW_PREP.md) | Questions by role: SOC analyst, pentester, DFIR, cloud security |
| [Home Lab Setup](HOMELAB_SETUP.md) | Hardware, hypervisors, network design, detection stacks |
| [Hands-On Labs](LABS.md) | Free lab environments and CTF platforms mapped to each security domain |
| [Cybersecurity Book List](CYBERSECURITY_BOOK_LIST.md) | Curated reading organized by discipline and level |
| [Starred Repositories](STARRED_REPOS.md) | Curated GitHub repos structured around the security technology landscape |

**Free Training**

| Platform | What You Get |
|---|---|
| [Antisyphon Training](https://www.antisyphontraining.com/pay-forward-what-you-can/) | Pay-what-you-can live courses — SOC, pentesting, active defense |
| [Black Hills Information Security](https://www.blackhillsinfosec.com/blog/webcasts/) | Hundreds of free webcasts on every security discipline |
| [TCM Security Academy](https://academy.tcm-sec.com/courses) | Practical ethical hacking and SOC content, free tier |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Best free web security training — interactive labs for every major vuln class |
| [Hack The Box Academy](https://academy.hackthebox.com) | Free Student tier — SOC, DFIR, pentesting, and cloud paths |
| [TryHackMe](https://tryhackme.com) | Browser-based labs from beginner to advanced, no local setup required |
| [IppSec](https://www.youtube.com/@ippsec) | HackTheBox walkthroughs with full attack methodology |
| [Blue Team Labs Online](https://blueteamlabs.online) | Free investigation challenges for detection, forensics, and IR |
| [LetsDefend](https://letsdefend.io) | Free SOC simulator for alert triage and threat analysis |
| [CISA Training Catalog](https://niccs.cisa.gov/training/catalog) | No-cost federal training — ICS/OT, cloud, and IR |
| [Anthropic Courses](https://github.com/anthropics/courses) | Free AI and LLM security courses |

</details>

---

## ATTACK-Navi

[![Deploy to GitHub Pages](https://github.com/TeamStarWolf/ATTACK-Navi/workflows/Deploy%20to%20GitHub%20Pages/badge.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/actions/workflows/deploy.yml) [![Docker Build](https://github.com/TeamStarWolf/ATTACK-Navi/workflows/Docker%20Build/badge.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/actions/workflows/docker.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/blob/main/LICENSE)

MITRE ATT&CK workbench for coverage review, detection engineering, exposure mapping, and threat-intelligence correlation. Supports Enterprise, ICS, and Mobile ATT&CK domains.

| Capability | Details |
|---|---|
| Heatmap modes | Coverage, detection, exposure, compliance, and risk |
| Live integrations | MISP, OpenCTI, EPSS, CISA KEV, NVD, Elastic, Splunk, Sigma, Atomic Red Team, ExploitDB, Nuclei |
| Data | STIX 2.1 import/export, custom technique editing, collection sharing |
| Deployment | Docker or GitHub Pages |

[Repository](https://github.com/TeamStarWolf/ATTACK-Navi) &nbsp;|&nbsp; [Live Site](https://teamstarwolf.github.io/ATTACK-Navi/) &nbsp;|&nbsp; [Docs](https://github.com/TeamStarWolf/ATTACK-Navi/blob/main/docs/README.md)

---

## Projects

| Project | Description |
|---|---|
| [LimeWire](https://github.com/TeamStarWolf/LimeWire) | Python desktop audio studio — download, analysis, editing, stem separation, and batch processing |
| [PokeNav](https://github.com/TeamStarWolf/PokeNav) | Offline-first Pokemon encyclopedia with game-aware browsing and trainer archives |
