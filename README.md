<div align="center">

# 🐺 TeamStarWolf

### An open, threat-informed cybersecurity reference library

*Practitioner-built references for offense, defense, cloud, identity, GRC, and specialized security — anchored to MITRE ATT&CK and mapped to real controls, detections, and tooling.*

[![Reference docs](https://img.shields.io/badge/reference_docs-140-2b6cb0?style=flat-square)](INDEX.md)
[![How-to guides](https://img.shields.io/badge/how--to_guides-16-2f855a?style=flat-square)](guides/README.md)
[![Discipline paths](https://img.shields.io/badge/discipline_paths-47-2b6cb0?style=flat-square)](disciplines/)
[![ATT&CK](https://img.shields.io/badge/ATT%26CK-NIST_800--53_mapped-6b46c1?style=flat-square)](THREAT_INFORMED_DEFENSE_REFERENCE.md)
[![Live docs](https://img.shields.io/badge/docs-live-2f855a?style=flat-square)](https://teamstarwolf.github.io/TeamStarWolf/)
[![License: MIT](https://img.shields.io/badge/license-MIT-4a5568?style=flat-square)](LICENSE)

[**🌐 Live Site**](https://teamstarwolf.github.io/TeamStarWolf/) &nbsp;·&nbsp; [**Reference Index**](INDEX.md) &nbsp;·&nbsp; [**Discipline Paths**](disciplines/README.md) &nbsp;·&nbsp; [**Threat-Informed Defense**](THREAT_INFORMED_DEFENSE_REFERENCE.md) &nbsp;·&nbsp; [**ATTACK-Navi**](https://teamstarwolf.github.io/ATTACK-Navi/)

<sub>This README is the GitHub view — the live site opens on a faster navigation homepage ([HOME.md](HOME.md)).</sub>

</div>

---

## About

**TeamStarWolf is a free, vendor-neutral knowledge base for working security practitioners.** It is not a
blog or a link dump — it is a structured library of **140 in-depth reference documents**, **16 step-by-step [how-to guides](guides/README.md)**, and **47 discipline
learning paths** that cover the cybersecurity field end to end: how attacks work, how to detect and respond
to them, how to harden systems and clouds, how to govern risk, and how to build a career doing it.

- **ATT&CK at the center** — techniques mapped to the controls that mitigate them ([CTID](https://center-for-threat-informed-defense.github.io/mappings-explorer/)), the detections that catch them, and the tests that validate them.
- **Operational, not theoretical** — real commands, queries, tooling, and detection logic, written to be used on an engagement or in a SOC.
- **Open and practitioner-built** — free, MIT-licensed, and cross-referenced so you can move from a concept to a command to a control in a couple of clicks.

---

## At a glance

<!-- SINGLE SOURCE OF TRUTH: every other surface (HOME.md hero/stats/chain, _coverpage.md bullets,
     the badges above) mirrors these numbers — update them all in the same PR. -->

| | | |
|---|---|---|
| 📚 **140** reference documents | 🧭 **47** discipline learning paths · **16** how-to guides | 🗺️ **28** ATT&CK Navigator coverage layers |
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
| **Learn a discipline from zero** | [Discipline learning paths](disciplines/README.md) → pick a track (e.g. [Threat Intelligence](disciplines/threat-intelligence.md), [Detection Engineering](disciplines/detection-engineering.md), [Red Teaming](disciplines/red-teaming.md)) |
| **Run or prep for a pentest** | [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md) · [Pentest Checklists](PENTEST_CHECKLISTS.md) · [Red Team Reference](RED_TEAM_REFERENCE.md) |
| **Build detections & hunt** | [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Detection Rules](DETECTION_RULES_REFERENCE.md) · [Threat Hunting](THREAT_HUNTING_REFERENCE.md) · [SIEM Reference](SIEM_REFERENCE.md) |
| **Map coverage & find gaps** | [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [ATT&CK Matrix Analysis](ATTACK_MATRIX_ANALYSIS_REFERENCE.md) · [Navigator layers](navigator/) |
| **Respond to an incident** | [Incident Response](INCIDENT_RESPONSE_REFERENCE.md) · [IR Playbooks](IR_PLAYBOOKS.md) · [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md) |
| **Harden systems & cloud** | [Windows](WINDOWS_HARDENING_REFERENCE.md) / [Linux](LINUX_HARDENING_REFERENCE.md) hardening · [Cloud Security](CLOUD_SECURITY_REFERENCE.md) · [Zero Trust](ZERO_TRUST_REFERENCE.md) |
| **Run an exposure management program** | [CTEM Reference](CTEM_REFERENCE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Priority Gap Analysis](scores/attack_priority_gaps.md) |
| **Secure AI/ML systems** | [MITRE ATLAS](ATLAS_REFERENCE.md) · [AI Security](AI_SECURITY_REFERENCE.md) · [AI & MCP Security](AI_MCP_SECURITY_REFERENCE.md) |
| **Run deception / active defense** | [MITRE Engage](ENGAGE_REFERENCE.md) · [Honeypot & Deception](HONEYPOT_DECEPTION_REFERENCE.md) · [Deception Technology](DECEPTION_TECHNOLOGY_REFERENCE.md) |
| **Defend against financial fraud** | [MITRE F3 Fraud Framework](FRAUD_FRAMEWORK_REFERENCE.md) · [Social Engineering](SOCIAL_ENGINEERING_REFERENCE.md) · [Identity Security](IDENTITY_SECURITY_REFERENCE.md) |
| **Break into the field / level up** | [Career Paths](CAREER_PATHS.md) · [Certifications](CERTIFICATIONS.md) · [Home Lab Setup](HOMELAB_SETUP.md) · [Free Training](#learn-amp-grow) |

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

**ATT&CK knowledge base & the rest of the MITRE stack** — parsed, cross-referenced, one row per node:

| Resource | What you get |
|---|---|
| [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) | All **691 Enterprise techniques** scored by group usage, software, mitigations, NIST controls, and detection availability |
| [Technique Detail Pages](techniques/README.md) | A full consolidated write-up per technique |
| [Threat Group Profiles](THREAT_GROUP_PROFILES.md) | **168 adversary groups** with aliases, attributed techniques, and tooling |
| [ATT&CK Software Reference](ATTACK_SOFTWARE_REFERENCE.md) | **784 malware families & tools** and the techniques they implement |
| [ATT&CK Campaigns Reference](ATTACK_CAMPAIGNS_REFERENCE.md) | **52 intrusion campaigns** with active windows, techniques, and attribution |
| [ATT&CK Mitigations Reference](ATTACK_MITIGATIONS_REFERENCE.md) | All **44 mitigations** (M-codes) and the techniques each one addresses |
| [ATT&CK Priority Gap Analysis](scores/attack_priority_gaps.md) | The most-used, least-covered techniques |
| [ICS](ICS_ATTACK_ATLAS.md) & [Mobile](MOBILE_ATTACK_ATLAS.md) Atlases | The **83-technique ICS** and **124-technique Mobile** matrices, same treatment |
| [ATT&CK Detection Strategies](detections/strategies/README.md) | **691 strategies** and **1,739 analytics** with log sources and tunable logic |
| [Data Components & Log Sources](ATTACK_DATA_COMPONENTS.md) | **106 telemetry categories** mapped to the techniques they detect |
| [CWE Weakness Reference](CWE_REFERENCE.md) | **969 weakness types** with consequences and mitigations |
| [CAPEC Attack Pattern Reference](CAPEC_REFERENCE.md) | **615 attack patterns**, 177 bridging directly to ATT&CK |
| [D3FEND Countermeasure Reference](D3FEND_REFERENCE.md) | **156 countermeasures** mapped to the **426 techniques** they counter |
| [MITRE ATLAS Reference](ATLAS_REFERENCE.md) | **170 AI-attack techniques** across 16 tactics, plus 35 mitigations |
| [MITRE Engage Reference](ENGAGE_REFERENCE.md) | **31 deception activities** with **793 mappings** to ATT&CK techniques |
| [CTEM Reference](CTEM_REFERENCE.md) | Gartner's 5-stage exposure loop, the tool landscape, and a 90-day plan |
| [MITRE F3 Fraud Framework](FRAUD_FRAMEWORK_REFERENCE.md) | **123 fraud-actor techniques** across 8 tactics, through to Monetization |

**Machine-readable datasets** &nbsp;·&nbsp; [Technique profiles](data/attack/technique_profiles.jsonl) &nbsp;·&nbsp; [Group → Technique](data/attack/group_to_technique.jsonl) &nbsp;·&nbsp; [Software → Technique](data/attack/software_to_technique.jsonl) &nbsp;·&nbsp; [Mitigation → Technique](data/attack/mitigation_to_technique.jsonl) &nbsp;·&nbsp; [Groups](data/attack/groups.jsonl) &nbsp;·&nbsp; [Software](data/attack/software.jsonl) &nbsp;·&nbsp; [Mitigations](data/attack/mitigations.jsonl) &nbsp;·&nbsp; [Campaigns](data/attack/campaigns.jsonl) &nbsp;·&nbsp; [Detection strategies](data/attack/detection_strategies.jsonl) &nbsp;·&nbsp; [Analytics](data/attack/analytics.jsonl) &nbsp;·&nbsp; [Data components](data/attack/data_components.jsonl) &nbsp;·&nbsp; [Technique → D3FEND](data/attack/technique_to_d3fend.jsonl) &nbsp;·&nbsp; [CWE](data/weaknesses/cwe.jsonl) &nbsp;·&nbsp; [CAPEC](data/weaknesses/capec.jsonl)

**Coverage edges & layers** — the vendor → control → technique bridge, sourced from the authoritative
[CTID Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/) (NIST 800-53 R5 → ATT&CK v16.1).
See [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md) and [COVERAGE_SCHEMA.md](COVERAGE_SCHEMA.md) for the model and
[scores/coverage_gaps.md](scores/coverage_gaps.md) for gap analysis.

| Resource | Description |
|---|---|
| [Control → Technique](data/control_to_technique.jsonl) · [Vendor → Control](data/vendor_to_control.jsonl) · [Vendor → Technique](data/vendor_to_technique.jsonl) | NIST 800-53 R5 → ATT&CK edges (**5,314**, CTID) · 60+ vendors → controls (**237 edges**) · derived vendor coverage (**17K+ edges**) |
| [Framework Blind Spots layer](navigator/analytics/no_nist_coverage.json) | The **223 techniques** with no NIST 800-53 control mapping — coverage blind spots |
| [Enterprise Security Pipeline](SECURITY_PIPELINE.md) | End-to-end security lifecycle with vendor mapping across all 6 stages |

---

## 📁 Repo layout

| Path | Contents |
|---|---|
| [`data/`](data/) | JSONL datasets — every mapping in the library, machine-readable |
| [`navigator/`](navigator/) | ATT&CK Navigator layers (28) |
| [`detections/`](detections/) | Detection strategies + the multi-platform query library |
| [`techniques/`](techniques/) | Per-technique detail pages |
| [`disciplines/`](disciplines/) | 47 learning paths + the [paths hub](disciplines/README.md) |
| [`scores/`](scores/) | Gap analyses |

---

## 📚 Library map

Flagships by domain — the [Reference Index](INDEX.md) lists all 140 documents, and the
[live site](https://teamstarwolf.github.io/TeamStarWolf/) browses every domain in two clicks.

| Domain | Flagship references | |
|---|---|---|
| 🗡️ **Offensive** | [Pentest Methodology](PENETRATION_TESTING_METHODOLOGY.md) · [Red Team](RED_TEAM_REFERENCE.md) · [AD Attacks](ACTIVE_DIRECTORY_ATTACKS.md) · [Web App Pentesting](WEB_APPLICATION_PENTESTING.md) | [full index →](INDEX.md) |
| 🛡️ **Defensive** | [Incident Response](INCIDENT_RESPONSE_REFERENCE.md) · [Threat Hunting](THREAT_HUNTING_REFERENCE.md) · [SIEM](SIEM_REFERENCE.md) · [Detection Rules](DETECTION_RULES_REFERENCE.md) | [full index →](INDEX.md) |
| ☁️ **Cloud & Infrastructure** | [Cloud Security](CLOUD_SECURITY_REFERENCE.md) · [Container Security](CONTAINER_SECURITY_REFERENCE.md) · [DevSecOps](DEVSECOPS_REFERENCE.md) · [Supply Chain](SUPPLY_CHAIN_SECURITY_REFERENCE.md) | [full index →](INDEX.md) |
| 🔑 **Identity, Access & Crypto** | [IAM](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) · [Zero Trust](ZERO_TRUST_REFERENCE.md) · [AD Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md) · [Cryptography](CRYPTOGRAPHY_REFERENCE.md) | [full index →](INDEX.md) |
| 📋 **GRC** | [GRC Compliance](GRC_COMPLIANCE_REFERENCE.md) · [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md) · [Security Metrics](SECURITY_METRICS_REFERENCE.md) · [Threat Modeling](THREAT_MODELING_REFERENCE.md) | [full index →](INDEX.md) |
| 🔬 **Specialized Domains** | [ICS/OT](ICS_OT_SECURITY_REFERENCE.md) · [Hardware](HARDWARE_SECURITY_REFERENCE.md) · [AI Security](AI_SECURITY_REFERENCE.md) · [Telecom & 5G](TELECOM_5G_SECURITY_REFERENCE.md) | [full index →](INDEX.md) |
| 🔎 **Research & Analysis** | [OSINT](OSINT_REFERENCE.md) · [Reverse Engineering](REVERSE_ENGINEERING_REFERENCE.md) · [Threat Intelligence](THREAT_INTELLIGENCE_REFERENCE.md) · [Packet Analysis](PACKET_ANALYSIS_REFERENCE.md) | [full index →](INDEX.md) |

---

<a id="learn-amp-grow"></a>

## 🎓 Learn & grow

| Reference | Coverage |
|---|---|
| [Career Paths](CAREER_PATHS.md) | 15+ security roles with skill maps, salary ranges, and cert roadmaps |
| [Certifications Reference](CERTIFICATIONS.md) | 40+ certifications with cost, difficulty, and domain coverage |
| [Interview Prep](INTERVIEW_PREP.md) | Questions by role: SOC analyst, pentester, DFIR, cloud security |
| [Home Lab Setup](HOMELAB_SETUP.md) | Hardware, hypervisors, network design, detection stacks |
| [Hands-On Labs](LABS.md) | Free lab environments and CTF platforms mapped to each security domain |
| [Cybersecurity Book List](CYBERSECURITY_BOOK_LIST.md) | Curated reading organized by discipline and level |
| [Starred Repositories](STARRED_REPOS.md) | Curated GitHub repos structured around the security technology landscape |

Free training platforms — Antisyphon, Black Hills, PortSwigger, HTB Academy, TryHackMe,
LetsDefend, and more — live in [Hands-On Labs](LABS.md) and [Resources](RESOURCES.md).

---

## 🛠️ ATTACK-Navi

The interactive companion to this library — a MITRE ATT&CK workbench for coverage review, detection
engineering, exposure mapping, and threat-intelligence correlation across the Enterprise, ICS, and Mobile
domains, consuming the same coverage data published here.

| Capability | Details |
|---|---|
| Heatmap modes | Coverage, detection, exposure, compliance, and risk — [24 analytic lenses](ATTACK_MATRIX_ANALYSIS_REFERENCE.md) |
| Live integrations | MISP, OpenCTI, EPSS, CISA KEV, NVD, Elastic, Splunk, Sigma, Atomic Red Team, ExploitDB, Nuclei |
| Data | STIX 2.1 import/export, custom technique editing, collection sharing |
| Deployment | Docker or GitHub Pages |

[**Repository**](https://github.com/TeamStarWolf/ATTACK-Navi) &nbsp;·&nbsp; [**Live Site**](https://teamstarwolf.github.io/ATTACK-Navi/) &nbsp;·&nbsp; [**Docs**](https://github.com/TeamStarWolf/ATTACK-Navi/blob/main/docs/README.md)

---

## 🤝 Contributing, projects & license

Other projects: [**LimeWire**](https://github.com/TeamStarWolf/LimeWire) — Python desktop audio studio ·
[**PokeNav**](https://github.com/TeamStarWolf/PokeNav) — offline-first Pokémon encyclopedia.

Contributions, corrections, and new references are welcome — see [CONTRIBUTING](.github/CONTRIBUTING.md) and
open an [issue](https://github.com/TeamStarWolf/TeamStarWolf/issues) to suggest a tool, fix content, or
propose a new discipline. Released under the [MIT License](LICENSE).

> **Disclaimer.** All offensive material is provided for authorized security testing, education, and defensive research only.

<div align="center">

**[🌐 Live Site](https://teamstarwolf.github.io/TeamStarWolf/)** · **[📖 Reference Index](INDEX.md)** · **[🧭 Discipline Paths](disciplines/README.md)**

<sub>🐺 TeamStarWolf — built for the cybersecurity community.</sub>

</div>
