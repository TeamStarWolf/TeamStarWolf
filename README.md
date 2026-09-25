<div align="center">

# 🐺 TeamStarWolf

### An open, threat-informed cybersecurity reference library

*Practitioner-built references for offense, defense, cloud, identity, GRC, and specialized security — anchored to MITRE ATT&CK and mapped to real controls, detections, and tooling.*

[![Reference docs](https://img.shields.io/badge/reference_docs-132-2b6cb0?style=flat-square)](INDEX.md)
[![Discipline paths](https://img.shields.io/badge/discipline_paths-47-2b6cb0?style=flat-square)](disciplines/)
[![ATT&CK](https://img.shields.io/badge/ATT%26CK-NIST_800--53_mapped-6b46c1?style=flat-square)](THREAT_INFORMED_DEFENSE_REFERENCE.md)
[![Live docs](https://img.shields.io/badge/docs-live-2f855a?style=flat-square)](https://teamstarwolf.github.io/TeamStarWolf/)
[![License: MIT](https://img.shields.io/badge/license-MIT-4a5568?style=flat-square)](LICENSE)

[**Reference Index**](INDEX.md) &nbsp;·&nbsp; [**Discipline Paths**](disciplines/) &nbsp;·&nbsp; [**Threat-Informed Defense**](THREAT_INFORMED_DEFENSE_REFERENCE.md) &nbsp;·&nbsp; [**Coverage & Data**](#coverage-data) &nbsp;·&nbsp; [**ATTACK-Navi**](https://teamstarwolf.github.io/ATTACK-Navi/)

</div>

---

## About

**TeamStarWolf is a free, vendor-neutral knowledge base for working security practitioners.** It is not a
blog or a link dump — it is a structured library of **132 in-depth reference documents** and **47 discipline
learning paths** that cover the cybersecurity field end to end: how attacks work, how to detect and respond
to them, how to harden systems and clouds, how to govern risk, and how to build a career doing it.

Three principles run through everything here:

- **ATT&CK at the center.** Adversary behavior is the common language. References map techniques to the
  controls that mitigate them (NIST 800-53 via [CTID](https://center-for-threat-informed-defense.github.io/mappings-explorer/)),
  the detections that catch them, and the tests that validate them.
- **Operational, not theoretical.** Real commands, real queries, real tooling, and real detection logic —
  written to be used on an engagement or in a SOC, not just read.
- **Open and practitioner-built.** Everything is free, MIT-licensed, and cross-referenced so you can move
  from a concept to a command to a control in a couple of clicks.

New here? Jump to [**Start here**](#start-here) for goal-based entry points, or browse the full
[**Reference Index**](INDEX.md).

---

## At a glance

| | | |
|---|---|---|
| 📚 **132** reference documents | 🧭 **47** discipline learning paths | 🗺️ **28** ATT&CK Navigator coverage layers |
| 🐉 **691** Enterprise + **83** ICS + **124** Mobile techniques | 👥 **168** threat groups & **784** software profiled | 🎬 **52** campaigns · 🛡️ **44** mitigations |
| 🔬 **691** detection strategies · **1,739** analytics | 🧬 **969** CWE weaknesses · **615** CAPEC patterns | 🛡️ **156** D3FEND countermeasures |
| 💳 **123** MITRE F3 fraud techniques (8 tactics) | 🤖 **170** ATLAS AI-attack techniques | 🪤 **31** Engage deception activities |
| 🔁 **CTEM** 5-stage exposure loop | 🎯 **65** multi-platform detection queries | 📋 **106** data components / log sources |
| 🔗 **5,314** control→technique mappings (CTID) | 🏢 **60+** enterprise vendors mapped to NIST 800-53 | 🧩 ATT&CK · ATLAS · Engage · D3FEND · F3 · EMB3D · FiGHT · CWE · CAPEC |
| 🎓 **40+** certifications & role roadmaps | 🧪 Home-lab & free-training guides | 🆓 Free · open source · MIT licensed |

---

## Start here

Pick your goal — each path drops you into the right part of the library.

| I want to… | Start with |
|---|---|
| **Learn a discipline from zero** | [Discipline learning paths](disciplines/) → pick a track (e.g. [Threat Intelligence](disciplines/threat-intelligence.md), [Detection Engineering](disciplines/detection-engineering.md), [Red Teaming](disciplines/red-teaming.md)) |
| **Run or prep for a pentest** | [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md) · [Pentest Checklists](PENTEST_CHECKLISTS.md) · [Red Team Reference](RED_TEAM_REFERENCE.md) |
| **Build detections & hunt** | [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Detection Rules](DETECTION_RULES_REFERENCE.md) · [Threat Hunting](THREAT_HUNTING_REFERENCE.md) · [SIEM Reference](SIEM_REFERENCE.md) |
| **Map coverage & find gaps** | [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [ATT&CK Matrix Analysis](ATTACK_MATRIX_ANALYSIS_REFERENCE.md) · [Navigator layers](navigator/) |
| **Respond to an incident** | [Incident Response](INCIDENT_RESPONSE_REFERENCE.md) · [IR Playbooks](IR_PLAYBOOKS.md) · [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md) |
| **Harden systems & cloud** | [Windows](WINDOWS_HARDENING_REFERENCE.md) / [Linux](LINUX_HARDENING_REFERENCE.md) hardening · [Cloud Security](CLOUD_SECURITY_REFERENCE.md) · [Zero Trust](ZERO_TRUST_REFERENCE.md) |
| **Run an exposure management program** | [CTEM Reference](CTEM_REFERENCE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Priority Gap Analysis](scores/attack_priority_gaps.md) |
| **Secure AI/ML systems** | [MITRE ATLAS](ATLAS_REFERENCE.md) · [AI Security](AI_SECURITY_REFERENCE.md) · [AI & MCP Security](AI_MCP_SECURITY_REFERENCE.md) |
| **Run deception / active defense** | [MITRE Engage](ENGAGE_REFERENCE.md) · [Honeypot & Deception](HONEYPOT_DECEPTION_REFERENCE.md) · [Deception Technology](DECEPTION_TECHNOLOGY_REFERENCE.md) |
| **Defend against financial fraud** | [MITRE F3 Fraud Framework](FRAUD_FRAMEWORK_REFERENCE.md) · [Social Engineering](SOCIAL_ENGINEERING_REFERENCE.md) · [Identity Security](IDENTITY_SECURITY_REFERENCE.md) |
| **Break into the field / level up** | [Career Paths](CAREER_PATHS.md) · [Certifications](CERTIFICATIONS.md) · [Home Lab Setup](HOMELAB_SETUP.md) · [Free Training](#learn-grow) |

---

## ⭐ Threat-Informed Defense

The flagship of the library: **MITRE ATT&CK at the center**, enriched with the vulnerability, weakness,
detection, and control knowledge that turns a coverage map into decisions. It shares its data model with the
[ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) workbench, and the mappings below are
machine-readable so you can query them, not just read them.

| Resource | What you get |
|---|---|
| [Threat-Informed Defense Reference](THREAT_INFORMED_DEFENSE_REFERENCE.md) | The ATT&CK-centric knowledge graph (**CVE → CWE → CAPEC → ATT&CK → D3FEND**), the open-source data-source stack, and the per-technique coverage-stack model |
| [ATT&CK Matrix Analysis Reference](ATTACK_MATRIX_ANALYSIS_REFERENCE.md) | **24 analytic lenses** for reading an ATT&CK matrix — mitigation, threat activity, exposure, detection, and composite risk |
| [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) | Multi-platform detection queries (**Splunk · Elastic · Microsoft · Chronicle · CrowdStrike**) keyed to ATT&CK techniques and the NIST controls that mitigate them |
| [ATT&CK Navigator Coverage Layers](navigator/) | Live heatmaps of NIST 800-53 R5 control depth and vendor/domain coverage — [**load the master layer ↗**](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json) |

**ATT&CK knowledge base** — the full MITRE ATT&CK Enterprise matrix (v18.1), parsed and cross-referenced:

| Resource | What you get |
|---|---|
| [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) | All **691 Enterprise techniques** by tactic, each scored by threat-group usage, software, ATT&CK mitigations, NIST controls, and detection availability |
| [Technique Detail Pages](techniques/README.md) | A **full consolidated write-up per technique** — description, mitigations, NIST controls, detections, and the groups & software that use it |
| [Threat Group Profiles](THREAT_GROUP_PROFILES.md) | **168 adversary groups** (APTs, eCrime) with aliases, attributed techniques, and tooling |
| [ATT&CK Software Reference](ATTACK_SOFTWARE_REFERENCE.md) | **784 malware families & tools** with the techniques they implement and the groups that use them |
| [ATT&CK Campaigns Reference](ATTACK_CAMPAIGNS_REFERENCE.md) | **52 intrusion campaigns** with active windows, techniques, software, and group attribution |
| [ATT&CK Mitigations Reference](ATTACK_MITIGATIONS_REFERENCE.md) | All **44 ATT&CK mitigations** (M-codes) and the techniques each one addresses |
| [ATT&CK Priority Gap Analysis](scores/attack_priority_gaps.md) | The most-used, least-covered techniques — where to focus detection and mitigation |
| [ICS ATT&CK Atlas](ICS_ATTACK_ATLAS.md) · [Mobile ATT&CK Atlas](MOBILE_ATTACK_ATLAS.md) | The **ICS** (83 techniques) and **Mobile** (124 techniques) ATT&CK matrices, same cross-referenced treatment |

**Machine-readable datasets** &nbsp;·&nbsp; [Technique profiles](data/attack/technique_profiles.jsonl) &nbsp;·&nbsp; [Group → Technique](data/attack/group_to_technique.jsonl) &nbsp;·&nbsp; [Software → Technique](data/attack/software_to_technique.jsonl) &nbsp;·&nbsp; [Mitigation → Technique](data/attack/mitigation_to_technique.jsonl) &nbsp;·&nbsp; [Groups](data/attack/groups.jsonl) &nbsp;·&nbsp; [Software](data/attack/software.jsonl) &nbsp;·&nbsp; [Mitigations](data/attack/mitigations.jsonl) &nbsp;·&nbsp; [Campaigns](data/attack/campaigns.jsonl) &nbsp;·&nbsp; [ICS datasets](data/attack/ics/) &nbsp;·&nbsp; [Mobile datasets](data/attack/mobile/)

**Detection engineering** — MITRE's own detection guidance, with concrete log sources and tunable logic:

| Resource | What you get |
|---|---|
| [ATT&CK Detection Strategies](detections/strategies/README.md) | **691 detection strategies** and **1,739 analytics** — per technique, the log sources/channels, detection logic, and tunable parameters to detect it |
| [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) | Ready-to-adapt SIEM/EDR queries (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike) |
| [ATT&CK Data Components & Log Sources](ATTACK_DATA_COMPONENTS.md) | **106 telemetry categories** mapped to the techniques they detect — plan your logging coverage |

**Completing the knowledge graph** — the *weakness*, *attack-pattern*, and *defense* nodes of **CVE → CWE → CAPEC → ATT&CK → D3FEND**:

| Resource | What you get |
|---|---|
| [CWE Weakness Reference](CWE_REFERENCE.md) | **969 weakness types** (10 pillars, 114 classes) with consequences, mitigations, and a data-driven "most-attacked" ranking |
| [CAPEC Attack Pattern Reference](CAPEC_REFERENCE.md) | **615 attack patterns** — 177 bridging directly to ATT&CK techniques, linked to their CWE weaknesses |
| [D3FEND Countermeasure Reference](D3FEND_REFERENCE.md) | **156 defensive techniques** (7 D3FEND tactics) mapped to the **426 ATT&CK techniques** they counter |

**The rest of the MITRE stack** — adversary behavior beyond the classic enterprise intrusion:

| Resource | What you get |
|---|---|
| [MITRE ATLAS Reference](ATLAS_REFERENCE.md) | **ATT&CK for AI** — **170 techniques** across **16 tactics** targeting ML/AI systems, including the AI-only *AI Model Access* and *AI Attack Staging* tactics, plus 35 mitigations · [Navigator layers](navigator/ai/) · [datasets](data/ai/) |
| [MITRE Engage Reference](ENGAGE_REFERENCE.md) | **Denial, deception & adversary engagement** — 5 goals → 9 approaches → **31 activities**, with **793 mappings** to ATT&CK techniques so deception becomes a measurable control · [datasets](data/engage/) |

**More datasets** &nbsp;·&nbsp; [Detection strategies](data/attack/detection_strategies.jsonl) &nbsp;·&nbsp; [Analytics](data/attack/analytics.jsonl) &nbsp;·&nbsp; [Data components](data/attack/data_components.jsonl) &nbsp;·&nbsp; [Technique → D3FEND](data/attack/technique_to_d3fend.jsonl) &nbsp;·&nbsp; [CWE](data/weaknesses/cwe.jsonl) &nbsp;·&nbsp; [CAPEC](data/weaknesses/capec.jsonl)

**Exposure management & fraud** — running the loop, and extending it past the intrusion to where the money leaves:

| Resource | What you get |
|---|---|
| [CTEM Reference](CTEM_REFERENCE.md) | **Continuous Threat Exposure Management** — Gartner's 5-stage loop (scope → discover → prioritize → validate → mobilize), the EASM/CAASM/BAS/AEV tool landscape, metrics that matter, and a 90-day starting plan wired to this library's data |
| [MITRE F3 Fraud Framework](FRAUD_FRAMEWORK_REFERENCE.md) | The **Fight Fraud Framework** — **123 fraud-actor techniques** across **8 tactics** (through to **Monetization**), from MITRE's Center for Threat-Informed Defense · [Navigator layer](navigator/fraud/f3-matrix.json) · [datasets](data/fraud/) |

---

## 📚 Explore the library

Curated highlights by domain — see the [full Reference Index](INDEX.md) for all 132 documents.

<details open>
<summary><strong>🗡️ Offensive Security</strong> — adversary tradecraft, end to end</summary>

> Reconnaissance and initial access through privilege escalation, lateral movement, and exfiltration —
> mapped to ATT&CK with real tooling, commands, and OPSEC.

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
<summary><strong>🛡️ Defensive Security</strong> — detect, hunt, respond, investigate</summary>

> The blue-team lifecycle: detection engineering, hypothesis-driven hunting, incident response, and
> forensics, with query languages and data-source guidance for the major SIEM/EDR stacks.

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
| [Ransomware Defense & Resilience](RANSOMWARE_DEFENSE_REFERENCE.md) | CISA #StopRansomware, NIST IR 8374r1, immutable backups, payment policy |
| [Insider Threat Program Reference](INSIDER_THREAT_REFERENCE.md) | CTID Insider Threat TTP KB, NITTF/CISA program guidance, UAM detection |

</details>

<details>
<summary><strong>☁️ Cloud & Infrastructure</strong> — secure the modern stack</summary>

> Cloud-native security across AWS/Azure/GCP, containers and Kubernetes, CI/CD and supply chain, and
> OS-level hardening — attacker techniques paired with the controls that stop them.

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
| [macOS Security Reference](MACOS_SECURITY_REFERENCE.md) | Gatekeeper/TCC/XProtect, mSCP and CIS baselines, Endpoint Security telemetry |
| [SaaS Security Reference](SAAS_SECURITY_REFERENCE.md) | OAuth app governance, CISA SCuBA, SSPM, M365/GWS tenant hardening |

</details>

<details>
<summary><strong>🔑 Identity, Access & Cryptography</strong> — the new perimeter</summary>

> Identity is the primary attack surface in cloud-first environments. IAM and PAM architecture, Zero Trust,
> secrets management, and applied cryptography — with attacker techniques and defensive design side by side.

| Reference | Coverage |
|---|---|
| [Identity Access Management Reference](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) | IAM architecture, MFA, PAM, JIT, SSO |
| [Active Directory Security Reference](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) | AD hardening, tiered admin, MDI, Kerberos defense |
| [Zero Trust Reference](ZERO_TRUST_REFERENCE.md) | NIST SP 800-207, CISA ZTMM, microsegmentation, BeyondCorp |
| [Secrets Management Reference](SECRETS_MANAGEMENT_REFERENCE.md) | Vault, AWS Secrets Manager, rotation, detection |
| [Cryptography Reference](CRYPTOGRAPHY_REFERENCE.md) | Symmetric/asymmetric, TLS, PKI, HSM, quantum-resistant algorithms |
| [Post-Quantum Migration Reference](POST_QUANTUM_MIGRATION_REFERENCE.md) | HNDL risk, FIPS 203/204/205, CNSA 2.0 timelines, CBOM, crypto-agility |
| [Password Security Reference](PASSWORD_SECURITY_REFERENCE.md) | Hash formats, hashcat/John, credential stuffing defense |

</details>

<details>
<summary><strong>📋 Governance, Risk & Compliance</strong> — run the program</summary>

> Turning security into a managed program: control frameworks, risk quantification, metrics, threat
> modeling, and vulnerability management that maps back to ATT&CK and real business risk.

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
<summary><strong>🔬 Specialized Domains</strong> — beyond the enterprise IT boundary</summary>

> Where security meets the physical and the emerging: vehicles, industrial control systems, hardware and
> firmware, mobile, radio, and AI/LLM systems — each with its own threat model and toolchain.

| Reference | Coverage |
|---|---|
| [Automotive Security Reference](AUTOMOTIVE_SECURITY_REFERENCE.md) | CAN bus, ECU, V2X, OTA updates, ISO 21434 |
| [ICS/OT Security Reference](ICS_OT_SECURITY_REFERENCE.md) | SCADA, PLC, Purdue model, IEC 62443, OT incident response |
| [Hardware Security Reference](HARDWARE_SECURITY_REFERENCE.md) | TPM, HSM, side-channel attacks, JTAG/SWD, fault injection |
| [Firmware & IoT Security Reference](FIRMWARE_IOT_SECURITY_REFERENCE.md) | Binwalk, UART/JTAG extraction, firmware emulation |
| [Mobile Security Reference](MOBILE_SECURITY_REFERENCE.md) | OWASP MASVS, Android/iOS RE, Frida, MDM/MAM |
| [AI Security Reference](AI_SECURITY_REFERENCE.md) | LLM threat models, prompt injection, adversarial ML, MCP security |
| [SDR & RF Security Reference](SDR_RF_SECURITY_REFERENCE.md) | HackRF, Flipper Zero, sub-GHz analysis, RF attack surface |
| [Space Systems Security Reference](SPACE_SECURITY_REFERENCE.md) | SPARTA framework, TT&C/SDLS protection, GNSS resilience, Viasat case study |
| [Telecom & 5G Security Reference](TELECOM_5G_SECURITY_REFERENCE.md) | MITRE FiGHT, SS7/Diameter defense, 5G core security, Salt Typhoon |
| [EMB3D Reference](EMB3D_REFERENCE.md) | MITRE EMB3D device threat model, tiered mitigations, IEC 62443 alignment |

</details>

<details>
<summary><strong>🔎 Research & Analysis</strong> — recon, RE, and traffic</summary>

> The investigative disciplines: open-source intelligence, reverse engineering, threat intelligence, and
> the network and protocol analysis skills that underpin both offense and defense.

| Reference | Coverage |
|---|---|
| [OSINT Reference](OSINT_REFERENCE.md) | Passive recon, Shodan/Censys, GEOINT, SOCMINT, automation |
| [Reverse Engineering Reference](REVERSE_ENGINEERING_REFERENCE.md) | Ghidra/IDA/Binary Ninja, dynamic analysis, firmware RE |
| [Threat Intelligence Reference](THREAT_INTELLIGENCE_REFERENCE.md) | Intel lifecycle, STIX/TAXII, threat actor tracking |
| [Threat Actors](THREAT_ACTORS.md) | Nation-state APTs, ransomware groups, and eCrime actors mapped to ATT&CK |
| [Network Protocols Reference](NETWORK_PROTOCOLS_REFERENCE.md) | TCP/IP, DNS, TLS, authentication protocols, analysis tools |
| [Packet Analysis Reference](PACKET_ANALYSIS_REFERENCE.md) | Wireshark, tcpdump, Zeek, JA3, attack pattern detection |
| [Network Forensics Reference](NETWORK_FORENSICS_REFERENCE.md) | PCAP forensics, NetFlow, encrypted traffic analysis, cloud |

</details>

---

## 🗺️ Coverage & Data
<a id="coverage-data"></a>

Machine-readable mappings that connect **security vendors → NIST 800-53 controls → ATT&CK techniques**, plus
the ATT&CK Navigator layers that visualize them. The control→technique bridge is sourced from the authoritative
[CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) (NIST 800-53
R5 → ATT&CK v16.1). See [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md) and [COVERAGE_SCHEMA.md](COVERAGE_SCHEMA.md)
for the model and [scores/coverage_gaps.md](scores/coverage_gaps.md) for gap analysis.

| Resource | Description |
|---|---|
| [ATT&CK Navigator Layer](navigator/teamstarwolf_vendor_coverage.json) | NIST 800-53 R5 → ATT&CK control-depth heatmap (**470 techniques**, CTID-sourced) · [Load in Navigator ↗](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/teamstarwolf_vendor_coverage.json) |
| [Control → Technique edges](data/control_to_technique.jsonl) | NIST 800-53 R5 → ATT&CK mappings, CTID (**5,314 edges**, 109 controls) |
| [Vendor → Control edges](data/vendor_to_control.jsonl) | 60+ vendors → NIST 800-53 controls (**237 edges**) |
| [Vendor → Technique edges](data/vendor_to_technique.jsonl) | Derived vendor → ATT&CK coverage via control join (**17K+ edges**) |
| [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) | Multi-platform detections keyed to techniques + mitigating NIST controls |
| [Group Frequency layer](navigator/analytics/group_frequency.json) | ATT&CK techniques colored by threat-group usage — the most common adversary behaviors |
| [Framework Blind Spots layer](navigator/analytics/no_nist_coverage.json) | The **223 techniques** with no NIST 800-53 control mapping — coverage blind spots |
| [Enterprise Security Pipeline](SECURITY_PIPELINE.md) | End-to-end security lifecycle with vendor mapping across all 6 stages |

---

## 🎓 Learn & grow
<a id="learn-grow"></a>

<details open>
<summary><strong>Career & study</strong></summary>

| Reference | Coverage |
|---|---|
| [Career Paths](CAREER_PATHS.md) | 15+ security roles with skill maps, salary ranges, and cert roadmaps |
| [Certifications Reference](CERTIFICATIONS.md) | 40+ certifications with cost, difficulty, and domain coverage |
| [Interview Prep](INTERVIEW_PREP.md) | Questions by role: SOC analyst, pentester, DFIR, cloud security |
| [Home Lab Setup](HOMELAB_SETUP.md) | Hardware, hypervisors, network design, detection stacks |
| [Hands-On Labs](LABS.md) | Free lab environments and CTF platforms mapped to each security domain |
| [Cybersecurity Book List](CYBERSECURITY_BOOK_LIST.md) | Curated reading organized by discipline and level |
| [Starred Repositories](STARRED_REPOS.md) | Curated GitHub repos structured around the security technology landscape |

</details>

<details>
<summary><strong>Free training platforms</strong></summary>

| Platform | What you get |
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

## 🛠️ ATTACK-Navi

[![Deploy to GitHub Pages](https://github.com/TeamStarWolf/ATTACK-Navi/workflows/Deploy%20to%20GitHub%20Pages/badge.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/actions/workflows/deploy.yml) [![Docker Build](https://github.com/TeamStarWolf/ATTACK-Navi/workflows/Docker%20Build/badge.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/actions/workflows/docker.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/TeamStarWolf/ATTACK-Navi/blob/main/LICENSE)

The interactive companion to this library — a MITRE ATT&CK workbench for coverage review, detection
engineering, exposure mapping, and threat-intelligence correlation. Supports Enterprise, ICS, and Mobile
ATT&CK domains, and consumes the same [coverage data](#coverage-data) published here.

| Capability | Details |
|---|---|
| Heatmap modes | Coverage, detection, exposure, compliance, and risk — [24 analytic lenses](ATTACK_MATRIX_ANALYSIS_REFERENCE.md) |
| Live integrations | MISP, OpenCTI, EPSS, CISA KEV, NVD, Elastic, Splunk, Sigma, Atomic Red Team, ExploitDB, Nuclei |
| Data | STIX 2.1 import/export, custom technique editing, collection sharing |
| Deployment | Docker or GitHub Pages |

[**Repository**](https://github.com/TeamStarWolf/ATTACK-Navi) &nbsp;·&nbsp; [**Live Site**](https://teamstarwolf.github.io/ATTACK-Navi/) &nbsp;·&nbsp; [**Docs**](https://github.com/TeamStarWolf/ATTACK-Navi/blob/main/docs/README.md)

---

## 📦 Other projects

| Project | Description |
|---|---|
| [LimeWire](https://github.com/TeamStarWolf/LimeWire) | Python desktop audio studio — download, analysis, editing, stem separation, and batch processing |
| [PokeNav](https://github.com/TeamStarWolf/PokeNav) | Offline-first Pokémon encyclopedia with game-aware browsing and trainer archives |

---

## 🤝 Contributing & license

Contributions, corrections, and new references are welcome — see [CONTRIBUTING](.github/CONTRIBUTING.md) and
open an [issue](https://github.com/TeamStarWolf/TeamStarWolf/issues) to suggest a tool, fix content, or
propose a new discipline. Released under the [MIT License](LICENSE).

> **Disclaimer.** All offensive material is provided for authorized security testing, education, and defensive
> research only. Use it only against systems you own or have explicit permission to test.

<div align="center">

**[📖 Reference Index](INDEX.md)** · **[🧭 Discipline Paths](disciplines/)** · **[🌐 Live Docs](https://teamstarwolf.github.io/TeamStarWolf/)**

<sub>🐺 TeamStarWolf — built for the cybersecurity community.</sub>

</div>
