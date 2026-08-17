# MITRE Engage Reference — Denial, Deception & Adversary Engagement

> **[MITRE Engage™](https://engage.mitre.org/)** is the framework for planning and running **adversary engagement, denial, and deception** operations. Where ATT&CK describes what the adversary does and D3FEND describes countermeasures, Engage describes what *you* do to expose, affect, and learn from an adversary already in your environment — **5 goals**, **9 approaches**, and **31 activities**, with **793 mappings** to ATT&CK techniques.

| | |
|---|---|
| **Goals** | 5 — Expose, Affect, Elicit, Prepare, Understand |
| **Approaches** | 9 |
| **Activities** | 31 |
| **ATT&CK mappings** | 793 across 175 techniques |
| **Datasets** | [goals](data/engage/engage_goals.jsonl) · [approaches](data/engage/engage_approaches.jsonl) · [activities](data/engage/engage_activities.jsonl) · [ATT&CK → Engage](data/engage/attack_to_engage.jsonl) |

> **Deception is a detection strategy, not a trap for its own sake.** Engage's value is that every activity ties back to an adversary behavior (ATT&CK technique) and a defensive outcome — so a honeypot becomes a measurable control rather than a science project.

**Related:** [Honeypot & Deception Reference](HONEYPOT_DECEPTION_REFERENCE.md) · [Deception Technology](DECEPTION_TECHNOLOGY_REFERENCE.md) · [D3FEND](D3FEND_REFERENCE.md) · [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [Purple Team](PURPLE_TEAM_REFERENCE.md)

---

## The Engage matrix

Goals set intent, approaches group tactics, activities are what you actually deploy.

### EGO0001 — Expose

Reveal the presence of ongoing adversary operations.

**EAP0001 · Collect** — Gather adversary tools, observe tactics, and collect other raw intelligence about the adversary’s activity.

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [EAC0001 API Monitoring](https://engage.mitre.org/activities/EAC0001/) | 23 | Monitor local APIs that might be used by adversary tools and activity. |
| [EAC0002 Network Monitoring](https://engage.mitre.org/activities/EAC0002/) | 25 | Monitor network traffic in order to detect adversary activity. |
| [EAC0014 Software Manipulation](https://engage.mitre.org/activities/EAC0014/) | 53 | Make changes to a system’s software properties and functions to achieve a desired effect. |
| [EAC0003 System Activity Monitoring](https://engage.mitre.org/activities/EAC0003/) | 22 | Collect system activity logs that can reveal adversary activity. |

**EAP0002 · Detect** — Establish or maintain awareness regarding adversary activity.

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [EAC0005 Lures](https://engage.mitre.org/activities/EAC0005/) | 93 | Deceptive systems and artifacts intended to serve as decoys, breadcrumbs, or bait to elicit a specific response from the adversary. |
| [EAC0013 Malware Detonation](https://engage.mitre.org/activities/EAC0013/) | 11 | Execute malware under controlled conditions to analyze its functionality. |
| [EAC0004 Network Analysis](https://engage.mitre.org/activities/EAC0004/) | 12 | Analyze network traffic to gain intelligence on communications between systems. |
| [EAC0023 Introduced Vulnerabilities](https://engage.mitre.org/activities/EAC0023/) | 4 | Intentionally introduce vulnerabilities into the environment for the adversary to exploit. |

---

### EGO0002 — Affect

Negatively impact the adversaries operations.

**EAP0003 · Prevent** — Stop all or part of the adversary’s ability to conduct their operation as intended.

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [EAC0019 Baseline](https://engage.mitre.org/activities/EAC0019/) | 14 | Identify key system elements to establish a baseline and be prepared to reset a system to that baseline when necessary. |
| [EAC0017 Hardware Manipulation](https://engage.mitre.org/activities/EAC0017/) | 3 | Alter the hardware configuration of a system to limit what an adversary can do with the device. |
| [EAC0020 Isolation](https://engage.mitre.org/activities/EAC0020/) | 6 | Configure devices, systems, networks, etc. to contain activity and data, thus preventing the expansion of an engagement beyond desired limits. |
| [EAC0016 Network Manipulation](https://engage.mitre.org/activities/EAC0016/) | 45 | Make changes to network properties and functions to achieve a desired effect. |
| [EAC0018 Security Controls](https://engage.mitre.org/activities/EAC0018/) | 66 | Alter security controls to make the system more or less vulnerable to attack. |

**EAP0004 · Direct** — Encourage or discourage the adversary from conducting their operation as intended.

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [EAC0005 Lures](https://engage.mitre.org/activities/EAC0005/) | 93 | Deceptive systems and artifacts intended to serve as decoys, breadcrumbs, or bait to elicit a specific response from the adversary. |
| [EAC0013 Malware Detonation](https://engage.mitre.org/activities/EAC0013/) | 11 | Execute malware under controlled conditions to analyze its functionality. |
| [EAC0009 Email Manipulation](https://engage.mitre.org/activities/EAC0009/) | 3 | Modify the flow of email in the environment. |
| [EAC0021 Attack Vector Migration](https://engage.mitre.org/activities/EAC0021/) | 7 | Move a malicious link, file, or device from its intended location to an engagement system or network for execution/use. |
| [EAC0016 Network Manipulation](https://engage.mitre.org/activities/EAC0016/) | 45 | Make changes to network properties and functions to achieve a desired effect. |
| [EAC0010 Peripheral Management](https://engage.mitre.org/activities/EAC0010/) | 8 | Manage peripheral devices used on systems within the network for engagement purposes. |
| [EAC0018 Security Controls](https://engage.mitre.org/activities/EAC0018/) | 66 | Alter security controls to make the system more or less vulnerable to attack. |
| [EAC0014 Software Manipulation](https://engage.mitre.org/activities/EAC0014/) | 53 | Make changes to a system’s software properties and functions to achieve a desired effect. |
| [EAC0023 Introduced Vulnerabilities](https://engage.mitre.org/activities/EAC0023/) | 4 | Intentionally introduce vulnerabilities into the environment for the adversary to exploit. |

**EAP0005 · Disrupt** — Impair an adversary’s ability to conduct their operation as intended.

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [EAC0005 Lures](https://engage.mitre.org/activities/EAC0005/) | 93 | Deceptive systems and artifacts intended to serve as decoys, breadcrumbs, or bait to elicit a specific response from the adversary. |
| [EAC0020 Isolation](https://engage.mitre.org/activities/EAC0020/) | 6 | Configure devices, systems, networks, etc. to contain activity and data, thus preventing the expansion of an engagement beyond desired limits. |
| [EAC0016 Network Manipulation](https://engage.mitre.org/activities/EAC0016/) | 45 | Make changes to network properties and functions to achieve a desired effect. |
| [EAC0014 Software Manipulation](https://engage.mitre.org/activities/EAC0014/) | 53 | Make changes to a system’s software properties and functions to achieve a desired effect. |

---

### EGO0003 — Elicit

Learn about adversaries tactics, techniques, and procedures (TTPs).

**EAP0006 · Reassure** — Add authenticity to deceptive components to convince an adversary that an environment is real.

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [EAC0006 Application Diversity](https://engage.mitre.org/activities/EAC0006/) | 23 | Present the adversary with a variety of installed applications and services. |
| [EAC0022 Artifact Diversity](https://engage.mitre.org/activities/EAC0022/) | 21 | Present the adversary with a variety of network and system artifacts. |
| [EAC0008 Burn-In](https://engage.mitre.org/activities/EAC0008/) | 13 | Exercise a target system in a manner where it will generate desirable system artifacts. |
| [EAC0009 Email Manipulation](https://engage.mitre.org/activities/EAC0009/) | 3 | Modify the flow of email in the environment. |
| [EAC0015 Information Manipulation](https://engage.mitre.org/activities/EAC0015/) | 54 | Conceal and reveal both facts and fictions to support a deception story |
| [EAC0007 Network Diversity](https://engage.mitre.org/activities/EAC0007/) | 10 | Use a diverse set of devices on the network to help establish the legitimacy of a deceptive network. |
| [EAC0010 Peripheral Management](https://engage.mitre.org/activities/EAC0010/) | 8 | Manage peripheral devices used on systems within the network for engagement purposes. |
| [EAC0011 Pocket Litter](https://engage.mitre.org/activities/EAC0011/) | 58 | Data used to support the engagement narrative. |

**EAP0007 · Motivate** — Encourage an adversary to conduct part or all of their mission.

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [EAC0006 Application Diversity](https://engage.mitre.org/activities/EAC0006/) | 23 | Present the adversary with a variety of installed applications and services. |
| [EAC0022 Artifact Diversity](https://engage.mitre.org/activities/EAC0022/) | 21 | Present the adversary with a variety of network and system artifacts. |
| [EAC0013 Malware Detonation](https://engage.mitre.org/activities/EAC0013/) | 11 | Execute malware under controlled conditions to analyze its functionality. |
| [EAC0015 Information Manipulation](https://engage.mitre.org/activities/EAC0015/) | 54 | Conceal and reveal both facts and fictions to support a deception story |
| [EAC0012 Personas](https://engage.mitre.org/activities/EAC0012/) | 22 | Create fictitious human user(s) through a combination of planted data and revealed behavior patterns. |
| [EAC0007 Network Diversity](https://engage.mitre.org/activities/EAC0007/) | 10 | Use a diverse set of devices on the network to help establish the legitimacy of a deceptive network. |
| [EAC0023 Introduced Vulnerabilities](https://engage.mitre.org/activities/EAC0023/) | 4 | Intentionally introduce vulnerabilities into the environment for the adversary to exploit. |

---

### SGO0001 — Prepare

Help the defender think about what they want to accomplish with operations.

**SAP0001 · Plan** — Identify and align an operation with a desired end-state.

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [SAC0004 Cyber Threat Intelligence](https://engage.mitre.org/activities/SAC0004/) | 0 | The process of analyzing actionable knowledge about adversaries and their malicious activities, enabling defenders and their organizations to reduce h… |
| [SAC0012 Engagement Environment](https://engage.mitre.org/activities/SAC0012/) | 0 | Design the systems and network for the operation. |
| [SAC0005 Gating Criteria](https://engage.mitre.org/activities/SAC0005/) | 0 | Define the set of events that would lead to the unnegotiable pause or conclusion to the operation. |
| [SAC0001 Operational Objective](https://engage.mitre.org/activities/SAC0001/) | 0 | Define the objective of the desired end-state of your adversary engagement operations. |
| [SAC0002 Persona Creation](https://engage.mitre.org/activities/SAC0002/) | 0 | Plan and create a fictitious human user through a combination of planted data and revealed behavior patterns. |
| [SAC0003 Storyboarding](https://engage.mitre.org/activities/SAC0003/) | 0 | Plan and create the deception story. |
| [SAC0009 Threat Model](https://engage.mitre.org/activities/SAC0009/) | 0 | A risk assessment that models organizational strengths and weaknesses |

---

### SGO0002 — Understand

Make sure that the defender is capturing, utilizing, and refining knowledge learned to improve the defender’s posture.

**SAP0002 · Analyze** — Retrospective review of information gained from an operation .

| Activity | ATT&CK techniques | Description |
|---|--:|---|
| [SAC0006 After-Action Review](https://engage.mitre.org/activities/SAC0006/) | 0 | Review of operational activities. |
| [SAC0004 Cyber Threat Intelligence](https://engage.mitre.org/activities/SAC0004/) | 0 | The process of analyzing actionable knowledge about adversaries and their malicious activities, enabling defenders and their organizations to reduce h… |
| [SAC0009 Threat Model](https://engage.mitre.org/activities/SAC0009/) | 0 | A risk assessment that models organizational strengths and weaknesses |

---

## Activities by ATT&CK coverage

Which engagement activities apply to the widest range of adversary behavior — a good place to start a deception program.

| Activity | ATT&CK techniques covered |
|---|--:|
| [EAC0005 Lures](https://engage.mitre.org/activities/EAC0005/) | 93 |
| [EAC0018 Security Controls](https://engage.mitre.org/activities/EAC0018/) | 66 |
| [EAC0011 Pocket Litter](https://engage.mitre.org/activities/EAC0011/) | 58 |
| [EAC0015 Information Manipulation](https://engage.mitre.org/activities/EAC0015/) | 54 |
| [EAC0014 Software Manipulation](https://engage.mitre.org/activities/EAC0014/) | 53 |
| [EAC0016 Network Manipulation](https://engage.mitre.org/activities/EAC0016/) | 45 |
| [EAC0002 Network Monitoring](https://engage.mitre.org/activities/EAC0002/) | 25 |
| [EAC0001 API Monitoring](https://engage.mitre.org/activities/EAC0001/) | 23 |
| [EAC0006 Application Diversity](https://engage.mitre.org/activities/EAC0006/) | 23 |
| [EAC0003 System Activity Monitoring](https://engage.mitre.org/activities/EAC0003/) | 22 |
| [EAC0012 Personas](https://engage.mitre.org/activities/EAC0012/) | 22 |
| [EAC0022 Artifact Diversity](https://engage.mitre.org/activities/EAC0022/) | 21 |
| [EAC0019 Baseline](https://engage.mitre.org/activities/EAC0019/) | 14 |
| [EAC0008 Burn-In](https://engage.mitre.org/activities/EAC0008/) | 13 |
| [EAC0004 Network Analysis](https://engage.mitre.org/activities/EAC0004/) | 12 |
| [EAC0013 Malware Detonation](https://engage.mitre.org/activities/EAC0013/) | 11 |
| [EAC0007 Network Diversity](https://engage.mitre.org/activities/EAC0007/) | 10 |
| [EAC0010 Peripheral Management](https://engage.mitre.org/activities/EAC0010/) | 8 |
| [EAC0021 Attack Vector Migration](https://engage.mitre.org/activities/EAC0021/) | 7 |
| [EAC0020 Isolation](https://engage.mitre.org/activities/EAC0020/) | 6 |
| [EAC0023 Introduced Vulnerabilities](https://engage.mitre.org/activities/EAC0023/) | 4 |
| [EAC0009 Email Manipulation](https://engage.mitre.org/activities/EAC0009/) | 3 |
| [EAC0017 Hardware Manipulation](https://engage.mitre.org/activities/EAC0017/) | 3 |
| [SAC0001 Operational Objective](https://engage.mitre.org/activities/SAC0001/) | 0 |
| [SAC0002 Persona Creation](https://engage.mitre.org/activities/SAC0002/) | 0 |
| [SAC0003 Storyboarding](https://engage.mitre.org/activities/SAC0003/) | 0 |
| [SAC0004 Cyber Threat Intelligence](https://engage.mitre.org/activities/SAC0004/) | 0 |
| [SAC0005 Gating Criteria](https://engage.mitre.org/activities/SAC0005/) | 0 |
| [SAC0006 After-Action Review](https://engage.mitre.org/activities/SAC0006/) | 0 |
| [SAC0012 Engagement Environment](https://engage.mitre.org/activities/SAC0012/) | 0 |
| [SAC0009 Threat Model](https://engage.mitre.org/activities/SAC0009/) | 0 |

---

## ATT&CK techniques with the most engagement options

For these techniques, Engage offers the widest choice of deception/denial responses. Cross-reference with the [Technique Detail Pages](techniques/README.md).

| ATT&CK | Technique | Engage activities |
|---|---|---|
| [T1135](https://attack.mitre.org/techniques/T1135/) | Network Share Discovery | Information Manipulation, Lures, Network Diversity, Network Manipulation, Peripheral Management, Pocket Litter +2 |
| [T1020](https://attack.mitre.org/techniques/T1020/) | Automated Exfiltration | Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring, Pocket Litter +1 |
| [T1052](https://attack.mitre.org/techniques/T1052/) | Exfiltration Over Physical Medium | Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring, Peripheral Management +1 |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | API Monitoring, Artifact Diversity, Information Manipulation, Lures, Personas, Pocket Litter +1 |
| [T1091](https://attack.mitre.org/techniques/T1091/) | Replication Through Removable Media | API Monitoring, Attack Vector Migration, Isolation, Peripheral Management, Security Controls, Software Manipulation +1 |
| [T1092](https://attack.mitre.org/techniques/T1092/) | Communication Through Removable Media | Attack Vector Migration, Isolation, Malware Detonation, Peripheral Management, Personas, Security Controls +1 |
| [T1119](https://attack.mitre.org/techniques/T1119/) | Automated Collection | Email Manipulation, Information Manipulation, Lures, Network Manipulation, Personas, Pocket Litter +1 |
| [T1125](https://attack.mitre.org/techniques/T1125/) | Video Capture | Hardware Manipulation, Information Manipulation, Lures, Network Manipulation, Peripheral Management, Personas +1 |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | Burn-In, Information Manipulation, Lures, Network Diversity, Network Manipulation, Pocket Litter +1 |
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Burn-In, Information Manipulation, Lures, Pocket Litter, Security Controls, Software Manipulation |
| [T1011](https://attack.mitre.org/techniques/T1011/) | Exfiltration Over Other Network Medium | Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring, Security Controls |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | API Monitoring, Burn-In, Information Manipulation, Lures, Pocket Litter, Software Manipulation |
| [T1029](https://attack.mitre.org/techniques/T1029/) | Scheduled Transfer | Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring, Security Controls |
| [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | Introduced Vulnerabilities, Lures, Network Diversity, Network Manipulation, Pocket Litter, Software Manipulation |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring, Security Controls |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Scanning | Introduced Vulnerabilities, Lures, Network Diversity, Network Manipulation, Pocket Litter, Software Manipulation |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Information Manipulation, Lures, Malware Detonation, Pocket Litter, Security Controls, Software Manipulation |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring, Security Controls |
| [T1049](https://attack.mitre.org/techniques/T1049/) | System Network Connections Discovery | API Monitoring, Burn-In, Information Manipulation, Lures, Pocket Litter, Software Manipulation |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Artifact Diversity, Burn-In, Lures, Personas, Pocket Litter, System Activity Monitoring |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Artifact Diversity, Information Manipulation, Lures, Personas, Pocket Litter, Software Manipulation |
| [T1123](https://attack.mitre.org/techniques/T1123/) | Audio Capture | Hardware Manipulation, Information Manipulation, Lures, Network Manipulation, Peripheral Management, Pocket Litter |
| [T1132](https://attack.mitre.org/techniques/T1132/) | Data Encoding | API Monitoring, Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring |
| [T1219](https://attack.mitre.org/techniques/T1219/) | Remote Access Software | Application Diversity, Lures, Malware Detonation, Network Manipulation, Personas, Pocket Litter |
| [T1531](https://attack.mitre.org/techniques/T1531/) | Account Access Removal | Application Diversity, Lures, Personas, Security Controls, Software Manipulation, System Activity Monitoring |
| [T1537](https://attack.mitre.org/techniques/T1537/) | Transfer Data to Cloud Account | Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring, Security Controls |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Information Manipulation, Lures, Network Analysis, Network Manipulation, Network Monitoring, Security Controls |
| [T1602](https://attack.mitre.org/techniques/T1602/) | Data from Configuration Repository | Artifact Diversity, Burn-In, Information Manipulation, Lures, Pocket Litter, Security Controls |
| [T1007](https://attack.mitre.org/techniques/T1007/) | System Service Discovery | API Monitoring, Information Manipulation, Lures, Pocket Litter, Software Manipulation |
| [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | Lures, Network Diversity, Network Manipulation, Pocket Litter, Software Manipulation |
| [T1030](https://attack.mitre.org/techniques/T1030/) | Data Transfer Size Limits | Information Manipulation, Lures, Network Manipulation, Network Monitoring, Security Controls |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | API Monitoring, Lures, Personas, Pocket Litter, Software Manipulation |
| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Information Manipulation, Lures, Network Manipulation, Pocket Litter, Security Controls |
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | Artifact Diversity, Burn-In, Lures, Pocket Litter, Software Manipulation |
| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Artifact Diversity, Lures, Personas, Pocket Litter, Software Manipulation |
| [T1072](https://attack.mitre.org/techniques/T1072/) | Software Deployment Tools | Application Diversity, Introduced Vulnerabilities, Lures, Security Controls, Software Manipulation |
| [T1080](https://attack.mitre.org/techniques/T1080/) | Taint Shared Content | Information Manipulation, Lures, Network Manipulation, Security Controls, System Activity Monitoring |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | API Monitoring, Burn-In, Information Manipulation, Pocket Litter, Software Manipulation |
| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Burn-In, Email Manipulation, Information Manipulation, Lures, Pocket Litter |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | Burn-In, Lures, Network Diversity, Pocket Litter, System Activity Monitoring |

---

*Source: [MITRE Engage](https://engage.mitre.org/) via [mitre/engage](https://github.com/mitre/engage) published data. Engage™ and ATT&CK® are trademarks of The MITRE Corporation. Independent reference summary — consult the upstream project for authoritative content.*
