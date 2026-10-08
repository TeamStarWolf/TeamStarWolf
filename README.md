# TeamStarWolf

A cybersecurity reference library

## About

TeamStarWolf is an open collection of reference material on cybersecurity practice. It covers offensive
testing, detection and response, system and cloud hardening, identity, governance and compliance, and
specialized areas such as industrial control systems and AI security.

Most of the material is in one of four forms. Reference documents summarize a topic, its terminology, its
tooling, and the relevant public frameworks and guidance. [How-to guides](guides/README.md) walk through a
specific task step by step. [Learning paths](disciplines/README.md) suggest an order for studying a
discipline and collect training, tools, books, and certifications for it. [Framework pages](mitre/README.md)
are generated from MITRE data, one page for each ATT&CK technique, group, software entry, campaign, and
mitigation, and for each CAPEC, D3FEND, ATLAS, and F3 entry. The library also includes curated lists of
tools, reading, and other resources, and [Tools Research](tools-research/README.md) studies that review
security products and their integrations against the vendors' official documentation.

Where a published mapping exists, an ATT&CK technique is linked to the NIST SP 800-53 controls that mitigate
it, the detection strategies and analytics MITRE publishes for it, the CAPEC attack patterns that reference
it (and through them the related CWE weaknesses), and the countermeasures in MITRE D3FEND. These
relationships are also published as data files and ATT&CK Navigator layers.

It can be read here on GitHub or on the [website](https://teamstarwolf.github.io/TeamStarWolf/), which
renders the same files.

## Where to start

| Goal | Start with |
|---|---|
| Learn a discipline | [Learning paths](disciplines/README.md), for example [Threat Intelligence](disciplines/threat-intelligence.md), [Detection Engineering](disciplines/detection-engineering.md), or [Red Teaming](disciplines/red-teaming.md) |
| Plan a penetration test | [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md), [Pentest Checklists](PENTEST_CHECKLISTS.md), [Red Team Reference](RED_TEAM_REFERENCE.md) |
| Write detections or hunt | [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md), [Detection Rules](DETECTION_RULES_REFERENCE.md), [Threat Hunting](THREAT_HUNTING_REFERENCE.md), [SIEM](SIEM_REFERENCE.md) |
| Assess ATT&CK coverage | [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), [ATT&CK Matrix Analysis](ATTACK_MATRIX_ANALYSIS_REFERENCE.md), [Priority Gap Analysis](scores/attack_priority_gaps.md), [Navigator layers](navigator/index.md) |
| Respond to an incident | [Incident Response](INCIDENT_RESPONSE_REFERENCE.md), [IR Playbooks](IR_PLAYBOOKS.md), [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md) |
| Harden systems and cloud | [Windows](WINDOWS_HARDENING_REFERENCE.md) and [Linux](LINUX_HARDENING_REFERENCE.md) hardening, [Cloud Security](CLOUD_SECURITY_REFERENCE.md), [Zero Trust](ZERO_TRUST_REFERENCE.md) |
| Manage vulnerabilities | [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md), [Vulnerability Prioritization](VULNERABILITY_PRIORITIZATION_REFERENCE.md), [CTEM](CTEM_REFERENCE.md), [Triage a CVE](guides/TRIAGE_A_CVE.md), [Tools Research](tools-research/README.md) |
| Secure AI and ML systems | [MITRE ATLAS](ATLAS_REFERENCE.md), [AI Security](AI_SECURITY_REFERENCE.md), [AI and MCP Security](AI_MCP_SECURITY_REFERENCE.md) |
| Use deception | [MITRE Engage](ENGAGE_REFERENCE.md), [Honeypots and Deception](HONEYPOT_DECEPTION_REFERENCE.md), [Deception Technology](DECEPTION_TECHNOLOGY_REFERENCE.md) |
| Counter fraud | [MITRE F3](FRAUD_FRAMEWORK_REFERENCE.md), [Social Engineering](SOCIAL_ENGINEERING_REFERENCE.md), [Identity Security](IDENTITY_SECURITY_REFERENCE.md) |
| Build a career | [Career Paths](CAREER_PATHS.md), [Certifications](CERTIFICATIONS.md), [Home Lab Setup](HOMELAB_SETUP.md), [Hands-On Labs](LABS.md) |

The [reference index](INDEX.md) lists the reference documents alphabetically. The website's sidebar groups
them by domain.

## ATT&CK and related frameworks

Most of these pages restate public MITRE knowledge bases so they can be browsed and cross-referenced in one
place. The Threat-Informed Defense reference explains how they fit together.

| Reference | Contents |
|---|---|
| [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) | How vulnerabilities, weaknesses, attack patterns, ATT&CK techniques, and countermeasures relate (from CVE to CWE, CAPEC, ATT&CK, and D3FEND), and how to use those relationships to reason about coverage |
| [Framework pages](mitre/README.md) | One page for each ATT&CK technique, group, software entry, campaign, and mitigation, and for each CAPEC, D3FEND, ATLAS, and F3 entry, linked to one another |
| [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) and [technique pages](techniques/README.md) | Enterprise techniques by tactic, with the groups, software, mitigations, NIST controls, and detections associated with each |
| [ICS](ICS_ATTACK_ATLAS.md) and [Mobile](MOBILE_ATTACK_ATLAS.md) atlases | ICS and Mobile techniques by tactic, with the groups, software, and mitigations associated with each (no NIST control mappings) |
| [Threat Groups](THREAT_GROUP_PROFILES.md), [Software](ATTACK_SOFTWARE_REFERENCE.md), [Campaigns](ATTACK_CAMPAIGNS_REFERENCE.md), [Mitigations](ATTACK_MITIGATIONS_REFERENCE.md) | ATT&CK's groups, software, campaigns, and mitigations, with the number of techniques associated with each and example techniques for selected entries. Complete technique lists are in the data files. |
| [Detection Strategies](detections/strategies/README.md), [Data Components](ATTACK_DATA_COMPONENTS.md) | ATT&CK's detection strategies and analytics, and the telemetry each relies on |
| [CWE](CWE_REFERENCE.md), [CAPEC](CAPEC_REFERENCE.md), [D3FEND](D3FEND_REFERENCE.md) | Weaknesses, attack patterns, and defensive countermeasures, linked to ATT&CK where a mapping exists |
| [ATLAS](ATLAS_REFERENCE.md), [Engage](ENGAGE_REFERENCE.md), [F3](FRAUD_FRAMEWORK_REFERENCE.md) | MITRE's frameworks for attacks on AI systems, adversary engagement, and financial fraud |
| [EMB3D](EMB3D_REFERENCE.md), [FiGHT](TELECOM_5G_SECURITY_REFERENCE.md) | MITRE's threat models for embedded devices and for 5G networks (FiGHT is covered in the Telecom and 5G reference) |

### Data

The relationships behind these pages are published as JSONL files in [`data/`](data/) and as ATT&CK
Navigator layers, which [navigator/index.md](navigator/index.md) lists with a description and a link to
open each one in the Navigator. [data/EDGES.md](data/EDGES.md) describes each relationship file,
[data/VOCABULARIES.md](data/VOCABULARIES.md) lists the allowed field values, and
[data/MANIFEST.json](data/MANIFEST.json) records each file's source, license, row count, and checksum.

The ATT&CK data files, the technique pages, and the framework pages are built from MITRE ATT&CK v19.2. The
technique records also keep a small number of techniques that MITRE has since revoked or renumbered. Some
summary pages, including the technique atlases, Threat Group Profiles, and the Priority Gap Analysis, and
most Navigator layers were generated from earlier ATT&CK releases and have not yet been regenerated. Each
states the version it was built from.

Control mappings from NIST SP 800-53 Rev. 5 to ATT&CK come from the Center for Threat-Informed Defense
[Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/). This library
uses the Rev. 5 mapping for ATT&CK v16.1. Not every technique has a control mapping: the CTID mapping does
not cover every technique, and techniques added or renumbered after v16.1 have no mapping under their
current ID.

The vendor-to-control mappings in [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md) are this library's own
editorial assessments. They are not provided or validated by the vendors, and they should be treated as a
starting point for research rather than as evidence of coverage. The vendor, control, and technique model is
described in [COVERAGE_SCHEMA.md](COVERAGE_SCHEMA.md).

Continuous integration validates the JSONL data files, checks the structure of the main Navigator coverage
layer, and checks that the figures quoted on the index pages and the data manifest match the data. A
scheduled link check reports broken links but does not block changes.

## Library by domain

| Domain | Representative references |
|---|---|
| Offensive | [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md), [Red Team](RED_TEAM_REFERENCE.md), [Active Directory Attacks](ACTIVE_DIRECTORY_ATTACKS.md), [Web Application Testing](WEB_APPLICATION_PENTESTING.md) |
| Defensive | [Incident Response](INCIDENT_RESPONSE_REFERENCE.md), [Threat Hunting](THREAT_HUNTING_REFERENCE.md), [SIEM](SIEM_REFERENCE.md), [Detection Rules](DETECTION_RULES_REFERENCE.md) |
| Cloud and infrastructure | [Cloud Security](CLOUD_SECURITY_REFERENCE.md), [Container Security](CONTAINER_SECURITY_REFERENCE.md), [DevSecOps](DEVSECOPS_REFERENCE.md), [Supply Chain Security](SUPPLY_CHAIN_SECURITY_REFERENCE.md) |
| Identity and cryptography | [Identity and Access Management](IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md), [Zero Trust](ZERO_TRUST_REFERENCE.md), [Active Directory Security](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md), [Cryptography](CRYPTOGRAPHY_REFERENCE.md) |
| Governance and risk | [GRC and Compliance](GRC_COMPLIANCE_REFERENCE.md), [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md), [Security Metrics](SECURITY_METRICS_REFERENCE.md), [Threat Modeling](THREAT_MODELING_REFERENCE.md) |
| Specialized | [ICS/OT](ICS_OT_SECURITY_REFERENCE.md), [Hardware](HARDWARE_SECURITY_REFERENCE.md), [AI Security](AI_SECURITY_REFERENCE.md), [Telecom and 5G](TELECOM_5G_SECURITY_REFERENCE.md) |
| Research and analysis | [OSINT](OSINT_REFERENCE.md), [Reverse Engineering](REVERSE_ENGINEERING_REFERENCE.md), [Threat Intelligence](THREAT_INTELLIGENCE_REFERENCE.md), [Packet Analysis](PACKET_ANALYSIS_REFERENCE.md) |

For study and career development, see [Career Paths](CAREER_PATHS.md), [Certifications](CERTIFICATIONS.md),
[Interview Preparation](INTERVIEW_PREP.md), [Home Lab Setup](HOMELAB_SETUP.md), [Hands-On Labs](LABS.md),
and the [reading list](CYBERSECURITY_BOOK_LIST.md).

## ATTACK-Navi

[ATTACK-Navi](https://github.com/TeamStarWolf/ATTACK-Navi) is a companion web application for exploring
the Enterprise, ICS, and Mobile ATT&CK matrices. It draws on the same public sources as this library, MITRE
ATT&CK and D3FEND and the CTID control mappings, which it loads directly in the browser. It also bundles
several of this library's Navigator overlays and adds views for detection coverage, threat intelligence,
vulnerability exposure, and compliance. It needs no backend, and a
[live version](https://teamstarwolf.github.io/ATTACK-Navi/) is hosted on GitHub Pages.

## Accuracy and use

The references summarize third-party frameworks, standards, and publications, and they can fall behind
upstream changes. Check the primary source before relying on a detail, particularly for version-specific
facts, regulatory requirements, and anything you intend to run.

Offensive techniques and tooling are described for authorized testing, education, and defensive research.
Do not use them against systems you do not have permission to test.

MITRE ATT&CK, ATLAS, CAPEC, CWE, D3FEND, EMB3D, Engage, F3, and FiGHT are maintained by The MITRE
Corporation, and the Mappings Explorer is published by MITRE's Center for Threat-Informed Defense. ATT&CK is
a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## Contributing and license

Corrections and additions are welcome. See [CONTRIBUTING](.github/CONTRIBUTING.md), or open an
[issue](https://github.com/TeamStarWolf/TeamStarWolf/issues).

Original content is released under the [MIT License](LICENSE). Data and text drawn from MITRE and other
sources remain under their owners' terms, as described in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
