<div align="center">





# TeamStarWolf





A public resource library for the cybersecurity community.





</div>





---





## Start Here





| Resource | Description |


|---|---|


| [Enterprise Security Pipeline](SECURITY_PIPELINE.md) | End-to-end security lifecycle with vendor mapping across all 11 stages |


| [Starred Repositories](STARRED_REPOS.md) | Curated repos structured around Cybersecurity Technology |


| [Cybersecurity Book List](CYBERSECURITY_BOOK_LIST.md) | Books, labs, and companion repos grouped for practical learning, with cert roadmaps and learning paths |


| [YouTube Channel Library](YOUTUBE_CHANNELS.md) | Active channels across multiple security disciplines |


| [X / Twitter Follow List](TWITTER_FOLLOW_LIST.md) | Vetted accounts that regularly share original research, tooling, or operational insight |





---





## Disciplines





Focused starting points by area of practice. Each page includes a learning path, free training resources, tools, books, certifications, and who to follow.





| Area | Description |


|---|---|


| [Threat Intelligence](disciplines/threat-intelligence.md) | Collecting, analyzing, and acting on threat data |


| [Detection Engineering](disciplines/detection-engineering.md) | Building and tuning detections across log sources and SIEMs |


| [Incident Response](disciplines/incident-response.md) | Responding to and recovering from security incidents |


| [Offensive Security](disciplines/offensive-security.md) | Penetration testing, red teaming, and adversary emulation |


| [Vulnerability Management](disciplines/vulnerability-management.md) | Identifying, prioritizing, and remediating vulnerabilities |


| [Cloud Security](disciplines/cloud-security.md) | Securing cloud infrastructure, containers, and identity |


| [Network Security](disciplines/network-security.md) | Monitoring and defending network traffic; NSM, IDS/IPS, wireless |


| [Malware Analysis](disciplines/malware-analysis.md) | Static and dynamic analysis, reverse engineering, and sandbox investigation |


| [ICS/OT Security](disciplines/ics-ot-security.md) | Securing industrial control systems, SCADA, and critical infrastructure |


| [Application Security](disciplines/application-security.md) | Web app and API security, secure SDLC, threat modeling, and bug bounty |


| [AI & LLM Security](disciplines/ai-llm-security.md) | Securing AI systems, red-teaming LLMs, and adversarial machine learning |


| [Governance, Risk & Compliance](disciplines/governance-risk-compliance.md) | Risk frameworks, compliance programs, NIST CSF/800-53, ISO 27001, GRC tooling |


| [Digital Forensics](disciplines/digital-forensics.md) | Disk, memory, and network forensics; evidence handling; DFIR methodology |


| [Security Architecture](disciplines/security-architecture.md) | Zero Trust design, threat modeling, defense-in-depth, architectural frameworks |


| [DevSecOps](disciplines/devsecops.md) | CI/CD pipeline security, SAST/DAST/SCA, IaC scanning, secrets detection | Semgrep, Trivy, Checkov, Gitleaks | Snyk, Checkmarx, Veracode | CSSLP, GCSA |


| [Cryptography & PKI](disciplines/cryptography-pki.md) | Certificate lifecycle, key management, HSMs, TLS hardening, post-quantum prep | OpenSSL, step-ca, Vault, Cosign | Venafi, DigiCert, Entrust, Thales | CISSP, CPP |


| [Supply Chain Security](disciplines/supply-chain-security.md) | SBOM generation, artifact signing, dependency security, SLSA framework | Syft, Grype, Cosign, in-toto | Chainguard, Snyk, JFrog Xray | CSSLP |


| [Privacy Engineering](disciplines/privacy-engineering.md) | PII detection, data minimization, consent management, DSR automation, GDPR/CCPA | Presidio, ARX, OPA, Privado | OneTrust, BigID, Immuta | CIPP/E, CIPT |

| [Identity & Access Management](disciplines/identity-access-management.md) | IAM/PAM architecture, SSO/MFA, Zero Trust identity, AD security, CIEM | Keycloak, BloodHound, HashiCorp Vault, Teleport | Microsoft Entra ID, Okta, CyberArk, SailPoint | CISSP, SC-300 |

| [Security Operations](disciplines/security-operations.md) | SOC operations, SIEM/SOAR, threat hunting, detection lifecycle, metrics | Wazuh, Sigma, TheHive, Hayabusa, Shuffle | Splunk ES, Sentinel, CrowdStrike SIEM, Exabeam | GSOC, GSOM, SC-200 |

| [Data Security](disciplines/data-security.md) | Data classification, DLP, encryption at rest/transit, DSPM, DAM | Presidio, Vault, OpenDLP, Privado | Microsoft Purview, Varonis, BigID, Netskope | CDPSE, CISSP, SC-400 |
| [Active Defense & Deception](disciplines/active-defense-deception.md) | Honeypots, honeytokens, canary tokens, deception grids, adversary engagement | OpenCanary, Cowrie, T-Pot, Canarytokens, SNARE | Thinkst Canary, Attivo/SentinelOne, Illusive/CrowdStrike | GDAT |





---





## Free & Accessible Training





High-quality training does not require a large budget. These platforms offer free or pay-what-you-can content taught by working practitioners.





| Platform | Focus |


|---|---|


| [Antisyphon Training](https://www.antisyphontraining.com/pay-forward-what-you-can/) | Pay-what-you-can live courses from John Strand and practitioners; SOC, pentesting, active defense |


| [Black Hills Information Security](https://www.blackhillsinfosec.com/blog/webcasts/) | Hundreds of free webcasts on every security discipline |


| [TCM Security Academy](https://academy.tcm-sec.com/courses) | Free tier with 25+ hours of on-demand content; practical ethical hacking and SOC |


| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | The best free web application security training available; interactive labs for every major vulnerability class |


| [Hack The Box Academy](https://academy.hackthebox.com) | Free Student tier; SOC analyst, DFIR, penetration testing, and cloud security paths |


| [TryHackMe](https://tryhackme.com) | Browser-based beginner-to-advanced labs; no local setup required |


| [IppSec](https://www.youtube.com/@ippsec) | HackTheBox walkthroughs demonstrating real attack techniques with full methodology |


| [Blue Team Labs Online](https://blueteamlabs.online) | Free investigation challenges for detection, forensics, and IR |


| [LetsDefend](https://letsdefend.io) | Free SOC simulator for alert triage and threat analysis |


| [CISA Training Catalog](https://niccs.cisa.gov/training/catalog) | No-cost federal training open to the public including ICS/OT, cloud, and IR content |


| [Anthropic Courses](https://github.com/anthropics/courses) | Free AI and LLM security courses from Anthropic |





---





## Coverage & Data





Machine-readable data files and an ATT&CK Navigator layer connecting the TeamStarWolf vendor stack to NIST 800-53 controls and ATT&CK techniques.





| Resource | Description |


|---|---|


| [ATT&CK Navigator Layer](navigator/teamstarwolf_vendor_coverage.json) | NIST 800-53 R5 → ATT&CK coverage heatmap (313 techniques, CTID-sourced). [Load in Navigator ↗](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json) |


| [Vendor → Control edges](data/vendor_to_control.jsonl) | JSONL edge table: 100+ vendor → NIST 800-53 control mappings |


| [Control → Technique edges](data/control_to_technique.jsonl) | JSONL edge table: NIST 800-53 R5 → ATT&CK technique mappings (CTID) |


| [Vendor → Technique edges](data/vendor_to_technique.jsonl) | JSONL derived edge table: vendor → ATT&CK technique coverage via control join |


| [Controls Mapping](CONTROLS_MAPPING.md) | Full Vendor → NIST 800-53 → ATT&CK cross-reference |


| [Coverage Schema](COVERAGE_SCHEMA.md) | Gap scoring data model, JSON schemas, Python scoring functions |





---





## Tool





### [ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi)





[![Deploy to GitHub Pages](https://github.com/TeamStarWolf/ATTACK-Navi/workflows/Deploy%20to%20GitHub%20Pages/badge.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/actions/workflows/deploy.yml)


[![Docker Build](https://github.com/TeamStarWolf/ATTACK-Navi/workflows/Docker%20Build/badge.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/actions/workflows/docker.yml)


[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/blob/main/LICENSE)





MITRE ATT&CK workbench for coverage review, detection engineering, exposure mapping, and threat-intelligence correlation. Supports Enterprise, ICS, and Mobile ATT&CK domains.





**Capabilities**


- Multiple heatmap modes across coverage, detection, exposure, compliance, and risk


- CVE mappings with live integrations: MISP, OpenCTI, EPSS, CISA KEV, NVD, Elastic, Splunk, Sigma, Atomic Red Team, ExploitDB, and Nuclei


- STIX 2.1 import/export, custom technique editing, and collection sharing


- Deployable via Docker or GitHub Pages





[Repository](https://github.com/TeamStarWolf/ATTACK-Navi) | [Live Site](https://teamstarwolf.github.io/ATTACK-Navi/) | [Docs](https://github.com/TeamStarWolf/ATTACK-Navi/blob/main/docs/README.md)





---





## Side Projects





| Project | Description |


|---|---|


| [LimeWire](https://github.com/TeamStarWolf/LimeWire) | Python desktop audio studio — download, analysis, editing, stem separation, and batch processing |


| [PokeNav](https://github.com/TeamStarWolf/PokeNav) | Offline-first Pokemon encyclopedia with game-aware browsing and trainer archives |


