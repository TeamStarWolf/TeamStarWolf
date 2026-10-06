<img src="assets/StarWolf64Version2Banner.png" alt="TeamStarWolf" width="100%">

# TeamStarWolf

A cybersecurity reference library organized around MITRE ATT&CK. Read it on the [website](https://teamstarwolf.github.io/TeamStarWolf/) or start from the [reference index](INDEX.md).

## About

TeamStarWolf is an open collection of reference material on cybersecurity practice. It covers offensive
testing, detection and response, system and cloud hardening, identity, governance and compliance, and a
number of specialized areas such as industrial control systems and AI security.

The material takes three forms. Reference documents summarize a topic, its terminology, its tooling, and
the relevant public frameworks and guidance. [How-to guides](guides/README.md) walk through a specific task
step by step. [Learning paths](disciplines/README.md) suggest an order for studying a discipline and point
to the relevant references.

Most of the library is cross-referenced to MITRE ATT&CK. Where a reliable public mapping exists, a technique
is linked to the NIST SP 800-53 controls that mitigate it, the detection analytics MITRE publishes for it,
the related weaknesses and attack patterns (CWE and CAPEC), and the defensive techniques in MITRE D3FEND.
The underlying relationships are also published as machine-readable data files and ATT&CK Navigator layers.

The library is free to use under the MIT License. It is read on GitHub or on the
[website](https://teamstarwolf.github.io/TeamStarWolf/), which is generated from this repository.

## Where to start

| Goal | Start with |
|---|---|
| Learn a discipline | [Learning paths](disciplines/README.md), for example [Threat Intelligence](disciplines/threat-intelligence.md), [Detection Engineering](disciplines/detection-engineering.md), or [Red Teaming](disciplines/red-teaming.md) |
| Plan a penetration test | [Penetration Testing Methodology](PENETRATION_TESTING_METHODOLOGY.md), [Pentest Checklists](PENTEST_CHECKLISTS.md), [Red Team Reference](RED_TEAM_REFERENCE.md) |
| Write detections or hunt | [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md), [Detection Rules](DETECTION_RULES_REFERENCE.md), [Threat Hunting](THREAT_HUNTING_REFERENCE.md), [SIEM](SIEM_REFERENCE.md) |
| Assess ATT&CK coverage | [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), [ATT&CK Matrix Analysis](ATTACK_MATRIX_ANALYSIS_REFERENCE.md), [Navigator layers](navigator/) |
| Respond to an incident | [Incident Response](INCIDENT_RESPONSE_REFERENCE.md), [IR Playbooks](IR_PLAYBOOKS.md), [Digital Forensics](DIGITAL_FORENSICS_REFERENCE.md) |
| Harden systems and cloud | [Windows](WINDOWS_HARDENING_REFERENCE.md) and [Linux](LINUX_HARDENING_REFERENCE.md) hardening, [Cloud Security](CLOUD_SECURITY_REFERENCE.md), [Zero Trust](ZERO_TRUST_REFERENCE.md) |
| Manage vulnerabilities and exposure | [Vulnerability Management](VULNERABILITY_MANAGEMENT_REFERENCE.md), [CTEM](CTEM_REFERENCE.md), [Priority Gap Analysis](scores/attack_priority_gaps.md) |
| Secure AI and ML systems | [MITRE ATLAS](ATLAS_REFERENCE.md), [AI Security](AI_SECURITY_REFERENCE.md), [AI and MCP Security](AI_MCP_SECURITY_REFERENCE.md) |
| Use deception | [MITRE Engage](ENGAGE_REFERENCE.md), [Honeypots and Deception](HONEYPOT_DECEPTION_REFERENCE.md), [Deception Technology](DECEPTION_TECHNOLOGY_REFERENCE.md) |
| Counter fraud | [MITRE F3](FRAUD_FRAMEWORK_REFERENCE.md), [Social Engineering](SOCIAL_ENGINEERING_REFERENCE.md), [Identity Security](IDENTITY_SECURITY_REFERENCE.md) |
| Build a career | [Career Paths](CAREER_PATHS.md), [Certifications](CERTIFICATIONS.md), [Home Lab Setup](HOMELAB_SETUP.md), [Hands-On Labs](LABS.md) |

The [reference index](INDEX.md) lists every document by domain.

## ATT&CK and related frameworks

These references restate public MITRE knowledge bases in a form that is easier to browse and cross-reference.

| Reference | Contents |
|---|---|
| [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) | How vulnerabilities, weaknesses, attack patterns, ATT&CK techniques, and countermeasures relate (from CVE to CWE, CAPEC, ATT&CK, and D3FEND), and how to use that chain to reason about coverage |
| [ATT&CK Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) and [technique pages](techniques/README.md) | Enterprise techniques with their associated groups, software, mitigations, controls, and detections |
| [ICS](ICS_ATTACK_ATLAS.md) and [Mobile](MOBILE_ATTACK_ATLAS.md) atlases | The same treatment for the ICS and Mobile matrices |
| [Threat Groups](THREAT_GROUP_PROFILES.md), [Software](ATTACK_SOFTWARE_REFERENCE.md), [Campaigns](ATTACK_CAMPAIGNS_REFERENCE.md), [Mitigations](ATTACK_MITIGATIONS_REFERENCE.md) | ATT&CK's groups, malware and tools, campaigns, and mitigations, each with the techniques attributed to it |
| [Detection Strategies](detections/strategies/README.md), [Data Components](ATTACK_DATA_COMPONENTS.md) | ATT&CK's detection strategies and analytics, and the telemetry each relies on |
| [CWE](CWE_REFERENCE.md), [CAPEC](CAPEC_REFERENCE.md), [D3FEND](D3FEND_REFERENCE.md) | Weaknesses, attack patterns, and defensive countermeasures, linked to ATT&CK where a mapping exists |
| [ATLAS](ATLAS_REFERENCE.md), [Engage](ENGAGE_REFERENCE.md), [F3](FRAUD_FRAMEWORK_REFERENCE.md) | MITRE's frameworks for attacks on AI systems, adversary engagement, and financial fraud |

### Data

The relationships behind these pages are published as JSONL files in [`data/`](data/) and as
ATT&CK Navigator layers in [`navigator/`](navigator/).

ATT&CK content is parsed from MITRE ATT&CK v19.2. The technique records include a small number of
superseded entries that MITRE no longer lists as active.

Control mappings from NIST SP 800-53 Rev. 5 to ATT&CK come from the Center for Threat-Informed
Defense [Mappings Explorer](https://center-for-threat-informed-defense.github.io/mappings-explorer/),
which maps to ATT&CK v16.1. Techniques added to ATT&CK after that version have no control mapping yet.

The vendor-to-control mappings in [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md) are this library's own
editorial assessments. They are not provided or validated by the vendors, and they should be treated as a
starting point for research rather than as evidence of coverage.

The data model is described in [COVERAGE_SCHEMA.md](COVERAGE_SCHEMA.md). Continuous integration checks
that the data files are well formed, that Navigator layers are valid, that summary statistics match the
underlying data, and that links resolve.

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
the ATT&CK matrix. It uses the same mapping data as this library and adds views for detection coverage,
threat intelligence, vulnerability exposure, and compliance. It runs in the browser without a backend;
a [live version](https://teamstarwolf.github.io/ATTACK-Navi/) is hosted on GitHub Pages.

## Accuracy and use

The references summarize third-party frameworks, standards, and publications, and they can fall behind
upstream changes. Check the primary source before relying on a detail, particularly for version-specific
facts, regulatory requirements, and anything you intend to run.

Offensive techniques and tooling are described for authorized testing, education, and defensive research.
Do not use them against systems you do not have permission to test.

MITRE ATT&CK, ATLAS, CAPEC, CWE, D3FEND, and Engage are maintained by The MITRE Corporation. This project
is not affiliated with or endorsed by MITRE.

## Contributing and license

Corrections and additions are welcome. See [CONTRIBUTING](.github/CONTRIBUTING.md), or open an
[issue](https://github.com/TeamStarWolf/TeamStarWolf/issues). Released under the [MIT License](LICENSE).
