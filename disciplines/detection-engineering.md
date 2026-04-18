# Detection Engineering

Detection engineering is the practice of building, testing, validating, and maintaining a scalable program for identifying adversary behavior across an organization's environments. It is distinct from alert triage — detection engineers don't respond to alerts, they design the systems that generate them. The discipline covers the full detection lifecycle: identifying coverage gaps through threat modeling and adversary emulation, authoring detection logic in structured formats like Sigma and YARA, validating coverage using atomic tests and purple team exercises, tuning to eliminate false positives, and retiring detections that no longer reflect the threat landscape.

Good detection programs are hypothesis-driven, not signature-collection exercises. The goal is behavioral coverage of adversary TTPs mapped to the threats most relevant to your organization — not maximizing alert volume. Every detection should have a documented data source requirement, a validation test, and a clear suppression policy. This engineering rigor is what separates mature detection programs from collections of vendor-default rules that fire constantly and get ignored.

---

## Where to Start

Learn your log sources before you learn detection logic. Understanding what Windows Event ID 4624 actually means, what Sysmon event 1 captures versus event 10, and how network flow data differs from full packet capture is foundational. From there, learn Sigma as your portable rule format, then learn the query language for whichever SIEM your environment uses. Practice in free environments — Elastic SIEM, Splunk free trial, or Microsoft Sentinel trial — before working with production data.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Windows Event IDs, Sysmon configuration and telemetry, Sigma rule format, SIEM basics (Splunk/Elastic/Sentinel), ATT&CK technique-to-log-source mapping | BHIS SOC Core Skills webcasts (free), TryHackMe SOC paths, 13Cubed Windows forensics YouTube |
| Practitioner | Detection content pipelines, Sigma rule authoring and validation, Atomic Red Team testing, MITRE D3FEND, coverage heatmaps, false positive tuning | SigmaHQ documentation, Atomic Red Team project, Splunk Security Essentials (free), HTB Academy SOC path |
| Advanced | Detection-as-code CI/CD pipelines, behavioral detection beyond indicators, UEBA, threat hunting integration, Palantir ADS framework | Palantir ADS framework, MITRE CTID publications, Elastic detection-rules repository, SANS FOR555 content |

---

## Free Training

- [BHIS SOC Core Skills Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Hundreds of free hours covering detection methodology, SIEM tuning, log analysis, and SOC workflow from John Strand and the BHIS team; the most accessible free detection training available anywhere
- [SANS Threat Hunting and Detection Summit Talks](https://www.youtube.com/@SansInstitute) — Annual summit recordings covering detection-as-code, behavioral analytics, and advanced detection programs from leading practitioners; free YouTube archive
- [TryHackMe SOC Level 1 and Level 2 Paths](https://tryhackme.com) — Structured browser-based learning covering Windows Event Logs, Splunk, Snort, Zeek, and detection fundamentals with no local setup required
- [Hack The Box Academy SOC Analyst Path](https://academy.hackthebox.com) — Free Student tier covering Windows and Linux log analysis, SIEM fundamentals, IDS/IPS, and network traffic analysis with hands-on labs
- [Sigma Documentation and Community](https://github.com/SigmaHQ/sigma) — Free rule format documentation, conversion tools, and the community rule repository; learn Sigma before platform-specific query languages
- [Splunk Security Essentials App](https://splunkbase.splunk.com/app/3435) — Free Splunk app containing 200+ detections mapped to ATT&CK with detailed explanations of each use case; the best reference for what production detection content looks like
- [Elastic Security Labs](https://www.elastic.co/security-labs) — Free detection research publications, EQL rule examples, and malware analysis from Elastic's security team; vendor-neutral quality content
- [LetsDefend](https://letsdefend.io) — Free SOC simulator for practicing alert triage, threat analysis, and detection validation in a realistic platform environment
- [Blue Team Labs Online](https://blueteamlabs.online) — Free detection and forensics challenges covering log analysis, SIEM alert investigation, and threat hunting scenarios
- [Antisyphon SOC Core Skills](https://www.antisyphontraining.com) — Pay-what-you-can live training from John Strand covering detection fundamentals, SIEM workflows, and SOC analyst skills; exceptional value

---

## Tools & Repositories

### Detection Content & Rule Formats
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — The universal detection rule format; write once, convert to Splunk SPL, Elastic EQL, Microsoft KQL, QRadar AQL, and 30+ other targets; 3000+ community rules mapped to ATT&CK; the standard for portable detection content
- [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma) — Modern Python library for Sigma rule parsing, validation, and backend conversion; use this to build detection pipelines and CI/CD workflows
- [elastic/detection-rules](https://github.com/elastic/detection-rules) — Elastic's production detection rules for Elastic Security; excellent reference for EQL, KQL, and ML-based detection patterns regardless of your SIEM platform
- [splunk/security_content](https://github.com/splunk/security_content) — Splunk Threat Research Team detection content with ATT&CK mappings, data source requirements, and validation notes; high-quality reference for Splunk SPL detections

### Sysmon & Endpoint Telemetry
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — The most widely deployed Sysmon configuration; carefully tuned to maximize visibility while controlling noise; the starting point for every Windows endpoint telemetry deployment
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) — Modular Sysmon configuration framework for selective event collection and easier maintenance; the production alternative for environments where the monolithic config is too noisy
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) — Florian Roth's extensive YARA and Sigma rule base; thousands of production-quality detection rules covering threat actor tools and malware families

### Adversary Emulation & Validation
- [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) — Library of focused test cases mapped to ATT&CK techniques; the standard for validating detection coverage by executing the exact behaviors your detections target
- [mitre/caldera](https://github.com/mitre/caldera) — MITRE's automated adversary emulation platform; runs ATT&CK-mapped agent operations for continuous detection validation and purple team exercises
- [center-for-threat-informed-defense/summiting_the_pyramid](https://github.com/center-for-threat-informed-defense/summiting_the_pyramid) — CTID's framework for building detections robust against adversary evasion; teaches analysts to detect behavior rather than brittle indicators

### YARA
- [VirusTotal/yara](https://github.com/VirusTotal/yara) — The YARA pattern matching engine for malware identification; write rules matching file content, byte patterns, and string signatures across malware families
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) — See above; includes both YARA and Sigma rules from years of production threat intelligence work
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules) — Community-maintained YARA rule collection covering major malware families and threat actor tools

### Log Analysis & Hunting
- [OTRF/OSSEM](https://github.com/OTRF/OSSEM) — Open Source Security Events Metadata; standardized event schemas that normalize log sources for detection and hunting across SIEM platforms
- [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) — Pre-recorded adversary simulation telemetry for building and testing detections without running live attacks; the Mordor project dataset library
- [hunters-forge/ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) — ATT&CK-mapped hunting hypotheses with data requirements and detection analytics; bridges TI and detection engineering with structured hunt documentation

---

## Commercial & Enterprise Platforms

Detection programs run on commercial SIEM, EDR, and analytics platforms. Open-source tooling builds the skills and the detection content; these platforms execute it at scale.

| Platform | Strength |
|---|---|
| **Splunk Enterprise Security** | The most widely deployed enterprise SIEM; powerful SPL query language, Risk-Based Alerting (RBA) framework, extensive threat intelligence integration, and the Splunk Security Essentials free content library |
| **Microsoft Sentinel** | Cloud-native SIEM and SOAR on Azure; KQL-based analytics, tight Microsoft 365 Defender integration, and the most cost-effective option for Microsoft-heavy environments; large community detection rule library |
| **Elastic Security (SIEM)** | Open-source core with enterprise tiers; EQL detection language with temporal sequence matching, built-in ATT&CK alignment, and unified endpoint and SIEM coverage |
| **CrowdStrike Falcon** | Market-leading EDR with a behavioral detection engine that does not rely on signatures; OverWatch 24/7 managed hunting; Fusion SOAR for automated response; the benchmark for endpoint detection |
| **SentinelOne Singularity** | EDR and XDR with autonomous response and Storyline attack chain reconstruction; behavioral AI detection engine; strong for reducing analyst workload through automation |
| **Palo Alto Cortex XDR** | XDR correlating endpoint, network, and cloud telemetry; strong ATT&CK mapping, behavioral analytics, and integration with Palo Alto's broader security portfolio |
| **IBM QRadar** | Long-standing enterprise SIEM dominant in regulated industries; AQL query language, deep compliance reporting, and extensive out-of-box correlation rule library |
| **Vectra AI** | Network detection and response (NDR) using AI to detect attacker behaviors in network traffic; strongest for C2 beaconing and lateral movement detection that endpoint tools miss |
| **Darktrace** | Unsupervised ML anomaly detection across network, email, and cloud; strongest for detecting novel or slow-burn threats that signature-based rules would miss; controversial tuning requirements |
| **Securonix** | UEBA-focused SIEM and XDR; purpose-built for behavioral detection and insider threat use cases where rule-based approaches struggle |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| The Practice of Network Security Monitoring | Richard Bejtlich | The foundational NSM text; teaches the analyst mindset and systematic approach to network-based detection that applies across all detection disciplines |
| Crafting the InfoSec Playbook | Bollinger, Enright, Valites | Practical guide to building detection playbooks, hunting hypotheses, and detection content libraries; from Cisco's security team with real production examples |
| The Threat Hunter Playbook | Jose Rodriguez | ATT&CK-driven hunting methodology from the creator of OSSEM; highly practical with real query examples across Splunk, Elastic, and Microsoft Sentinel |
| Applied Incident Response | Steve Anson | Bridges detection and response; the treatment of log source requirements for detection is among the best available in a single volume |

---

## Certifications

- **GCED** (GIAC Certified Enterprise Defender) — Covers enterprise defense including network security monitoring, SIEM tuning, and endpoint detection; the most relevant GIAC certification for detection engineers; pairs with SANS SEC555
- **GCIH** (GIAC Certified Incident Handler) — Core certification covering incident detection, analysis, and response; widely respected and validates the full detection-to-response workflow
- **BTL1** (Blue Team Labs Level 1 — Security Blue Team) — Hands-on SOC analyst certification covering log analysis, SIEM investigation, threat intelligence, and digital forensics; strong practical validation for entry-level detection roles
- **CySA+** (CompTIA Cybersecurity Analyst) — Vendor-neutral certification covering threat detection, analysis, and response; widely recognized as an entry-to-mid-level credential for SOC and detection engineering roles
- **Splunk Core Certified User / Power User** — Vendor certification for SPL proficiency; valuable for detection engineers operating primarily in Splunk environments
- **Microsoft SC-200** (Security Operations Analyst) — Microsoft Sentinel-focused certification covering detection rule authoring, threat hunting, and SOAR playbook development in the Microsoft ecosystem

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — The most prolific free detection engineering content creator; hundreds of hours covering SIEM workflows, detection methodology, and SOC skills
- [13Cubed](https://www.youtube.com/@13Cubed) — Windows forensics and endpoint detection content with exceptional clarity; deep dives into Windows Event IDs and Sysmon telemetry that directly support detection development
- [Florian Roth (Neo23x0)](https://www.youtube.com/@florianroth) — Detection rule authoring, YARA development, and threat hunting from the creator of the Sigma format
- [Splunk](https://www.youtube.com/@splunk) — SIEM detection content, SPL tutorials, and .conf presentations on enterprise detection program design
- [Elastic](https://www.youtube.com/@Elastic) — EQL tutorials, detection engineering research, and Elastic Security product walkthroughs

---

## Who to Follow

- [@cyb3rward0g](https://x.com/cyb3rward0g) — Roberto Rodriguez; creator of OSSEM and the Threat Hunter Playbook; the most systematic thinker in open-source detection engineering
- [@SigmaHQ](https://x.com/SigmaHQ) — Sigma project updates, new rule releases, and detection content community news
- [@FlorianRoth10](https://x.com/FlorianRoth10) — Florian Roth; YARA and Sigma rule author; prolific threat intelligence and detection content
- [@olafhartong](https://x.com/olafhartong) — Sysmon-modular maintainer; Windows telemetry depth and detection engineering best practices
- [@neu5ron](https://x.com/neu5ron) — Nate Guagenti; Elastic detection engineering and EQL; excellent technical content on production detection at scale
- [@jaredcatkinson](https://x.com/jaredcatkinson) — PowerShell-based detection methodology and ATT&CK technique coverage measurement
- [@Kostastsale](https://x.com/Kostastsale) — KQL and Microsoft Sentinel detection content; excellent resource for Sentinel-focused engineers
- [@Antonlovesdnb](https://x.com/Antonlovesdnb) — Anton Chuvakin; SIEM strategy, detection program design, and the "detection engineering" discipline framing

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Map detection coverage across ATT&CK, identify gaps by tactic, and correlate Sigma rules, Elastic and Splunk detection counts, and Atomic Red Team tests against specific techniques; the recommended coverage analysis surface
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma) — The community detection rule library; browse existing rules before authoring new ones — many techniques already have high-quality Sigma coverage
- [MITRE D3FEND](https://d3fend.mitre.org) — The complementary framework to ATT&CK; maps defensive techniques to adversary techniques; use it to identify the right detection mechanism for any given attack pattern
- [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework) — The Alerting and Detection Strategy framework for structuring detection hypotheses, data requirements, and rule documentation; the standard template for professional detection engineering
- [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) — Pre-recorded adversary simulation telemetry for building and testing detections without running live attacks
- [ATT&CK Data Sources](https://attack.mitre.org/datasources/) — The official mapping of ATT&CK techniques to the log sources required to detect them; essential for coverage gap analysis and telemetry planning
- [Elastic Detection Rules Repository](https://github.com/elastic/detection-rules) — 1000+ production detection rules from Elastic's security research team; excellent reference for detection logic patterns regardless of SIEM platform
