# Detection Engineering

Detection engineering is the discipline of systematically designing, building, testing, and maintaining the detection content that drives a security operations program. It is distinct from alert triage: where a SOC analyst responds to existing alerts, the detection engineer is responsible for creating and sustaining the alert logic itself. A mature detection program treats detections as code — versioned, peer-reviewed, validated against real adversary behavior, and retired when they no longer provide signal. The detection lifecycle moves from identifying a coverage gap (via a threat intelligence input, a hunting hypothesis, or an incident finding) through rule authoring, validation against emulated adversary behavior, tuning against false positive sources, and eventual retirement or replacement as adversary techniques or logging infrastructure changes.

Structured rule formats are central to the discipline. Sigma provides a platform-agnostic detection rule syntax that can be compiled to Splunk SPL, Elastic EQL, Microsoft KQL, QRadar AQL, and dozens of other targets — allowing detection teams to write once and deploy across their SIEM stack. YARA provides pattern-matching for files and process memory, enabling malware family identification and hunting across endpoint telemetry. Suricata and Zeek rule formats drive network-based detection. Mastering these formats before diving into platform-specific syntax pays long-term dividends: the logic transfers even when the SIEM platform changes. MITRE ATT&CK serves as the primary coverage framework, providing a technique-level map of adversary behavior against which teams can assess their detection posture and prioritize new content development.

Adversary emulation is the quality control mechanism for detection engineering. Writing a detection rule without validating it against the actual adversary behavior it targets produces false confidence. Atomic Red Team provides small, focused test cases mapped to ATT&CK techniques that allow detection engineers to confirm a rule fires correctly, measure its false positive rate, and document its data source requirements. The best detection programs are hypothesis-driven — they start with a question about a specific adversary technique, identify the telemetry required to observe that behavior, author a rule, and validate coverage — rather than treating detection as a signature collection exercise.

---

## Where to Start

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Log sources, Windows Event IDs, Sysmon, Sigma rule format, SIEM basics (Splunk/Elastic), ATT&CK technique-to-log-source mapping | SANS Threat Hunting and Detection courses (free YouTube), BHIS SOC Core Skills webcasts, TryHackMe SOC paths |
| Practitioner | Detection content pipelines, Sigma rule authoring, Atomic Red Team validation, MITRE D3FEND, building coverage heatmaps, tuning false positives | SigmaHQ docs, Atomic Red Team docs, Splunk Security Essentials (free), HTB Academy SOC Analyst path |
| Advanced | Detection-as-code pipelines, CI/CD for detection content, behavioral detection beyond indicators, UEBA, threat hunting integration | Palantir Alerting and Detection Strategy framework, MITRE CTID publications, SANS FOR555 content |

---

## Free Training

- **BHIS SOC Core Skills Webcasts** — Hundreds of free hours covering detection methodology, SIEM tuning, log analysis, and SOC workflow from John Strand and the BHIS team; the most accessible free detection training available
- **SANS Threat Hunting and Detection Summit Talks (YouTube)** — Annual summit recordings covering advanced detection content, detection-as-code, and behavioral analytics from leading practitioners
- **TryHackMe SOC Level 1 and Level 2 Paths** — Structured browser-based paths covering Windows Event Logs, Splunk, Snort, Zeek, and detection fundamentals with no local setup required
- **Hack The Box Academy SOC Analyst Path** — Free Student tier covering Windows/Linux log analysis, SIEM fundamentals, IDS/IPS, and network traffic analysis
- **Sigma Project Documentation and Community** — Free rule format documentation, conversion tools, and the community rule repository; learn the standard format before platform-specific syntax
- **Splunk Security Essentials (Free App)** — Free Splunk app with 200+ detections mapped to ATT&CK with explanations; the best way to learn what good detection content looks like
- **Elastic Security Labs** — Free detection research publications, EQL rule examples, and threat research from Elastic's security team; high-quality vendor-neutral content
- **LetsDefend** — Free SOC simulator for practicing alert triage, threat analysis, and detection validation in a realistic environment
- **Blue Team Labs Online** — Free detection and forensics challenges covering log analysis, SIEM alert investigation, and threat hunting
- **Antisyphon SOC Core Skills (PWYW)** — Pay-what-you-can live course from John Strand covering detection fundamentals, SIEM workflows, and SOC analyst skills; one of the best value training options in the field
- **SANS SEC555 (audit free)** — SIEM with Tactical Analytics; covers detection engineering in enterprise SIEM environments using Elastic Stack; audit the course material for free via SANS summit recordings and community resources

---

## Tools & Repositories

### Detection Content & Rule Formats
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — The universal detection rule format; write once, convert to Splunk SPL, Elastic EQL, Microsoft KQL, QRadar AQL, and 30+ other targets; the standard for portable detection content
- [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma) — The modern Python library for Sigma rule parsing, validation, and backend conversion; use this to build detection pipelines and CI/CD workflows
- [elastic/detection-rules](https://github.com/elastic/detection-rules) — Elastic's production detection rules for Elastic Security; excellent reference for EQL, KQL, and machine learning-based detection patterns
- [splunk/security_content](https://github.com/splunk/security_content) — Splunk Threat Research Team detection content with ATT&CK mappings, data source requirements, and validation guidance

### Sysmon & Endpoint Telemetry
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — The most widely deployed Sysmon configuration; carefully tuned to maximize visibility while controlling noise; the starting point for every Windows endpoint telemetry deployment
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) — Modular Sysmon configuration framework allowing selective event collection and easier maintenance; excellent for production environments where the monolithic config creates too much noise
- [Microsoft Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) — The authoritative endpoint monitoring tool for Windows; captures process creation, network connections, file operations, registry changes, and more with configurable filtering

### Adversary Emulation & Validation
- [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) — Library of small, focused test cases mapped to ATT&CK techniques; the standard for validating detection coverage by executing the behaviors your detections target
- [mitre/caldera](https://github.com/mitre/caldera) — MITRE's automated adversary emulation platform; runs ATT&CK-mapped agent operations for continuous detection validation and adversary simulation exercises
- [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) — Baseline Windows Event Log data for identifying anomalous events against known-good system state; reduces false positive noise during detection development
- [center-for-threat-informed-defense/summiting_the_pyramid](https://github.com/center-for-threat-informed-defense/summiting_the_pyramid) — CTID framework for building detections that are robust against adversary evasion; teaches analysts to detect behavior rather than brittle indicators

### YARA
- [VirusTotal/yara](https://github.com/VirusTotal/yara) — The YARA pattern matching engine for malware identification; write rules matching file content, byte patterns, and string signatures across malware families
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) — Florian Roth's extensive YARA and Sigma rule base from years of threat intelligence work; thousands of production-quality malware detection rules
- [InQuest/yara-rules](https://github.com/InQuest/yara-rules) — InQuest Labs YARA rules focused on document-based malware, phishing lures, and embedded threat payloads
- [Yara-Rules/rules](https://github.com/Yara-Rules/rules) — Community-maintained YARA rule collection covering major malware families and threat actor tools

### Log Analysis & Hunting
- [OTRF/OSSEM](https://github.com/OTRF/OSSEM) — Open Source Security Events Metadata; standardized event schemas that normalize log sources for detection and hunting across different SIEM platforms
- [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) — Mordor project threat hunting datasets; pre-recorded adversary simulation telemetry for building and testing detections without running live attacks
- [hunters-forge/ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) — ATT&CK-mapped hunting hypotheses with data requirements and detection analytics; bridges TI and detection engineering with structured hunt documentation
- [Neo23x0/loki](https://github.com/Neo23x0/loki) — IOC and YARA rule scanner for compromise assessment and detection validation on endpoints and file shares

---

## Commercial & Enterprise Platforms

Enterprise detection programs run on commercial SIEM, EDR, and analytics platforms. Open-source tooling builds the skills and the content; these platforms execute it at scale.

| Platform | Role |
|---|---|
| **Splunk Enterprise Security** | The most widely deployed enterprise SIEM; powerful SPL query language, extensive threat intelligence integration, and Splunk Security Essentials free detection content library |
| **Microsoft Sentinel** | Cloud-native SIEM/SOAR on Azure; KQL-based analytics, tight Microsoft 365 Defender integration, and the most cost-effective option for Microsoft-heavy environments |
| **Elastic Security (SIEM)** | Open-source core with enterprise tiers; EQL detection language, built-in ATT&CK alignment, and strong endpoint + SIEM integration |
| **CrowdStrike Falcon** | Market-leading EDR with behavioral detection engine; OverWatch managed hunting service; strong detection validation via Falcon adversary intelligence |
| **SentinelOne Singularity** | EDR + XDR platform with autonomous response capabilities; behavioral AI detection engine; strong for organizations wanting reduced analyst workload |
| **Palo Alto Cortex XDR** | XDR platform correlating endpoint, network, and cloud telemetry; strong ATT&CK mapping and behavioral analytics |
| **IBM QRadar** | Long-standing enterprise SIEM with deep integration in regulated industries; AQL query language and extensive out-of-box correlation rules |
| **Securonix** | UEBA-focused SIEM/XDR; strong for behavioral detection use cases and insider threat programs |
| **Vectra AI** | Network detection and response (NDR) using AI to detect attacker behaviors in network traffic; strong for C2 and lateral movement detection |
| **Darktrace** | Unsupervised ML-based anomaly detection across network, email, and cloud; strongest for detecting novel or slow-burn threats that evade signature-based rules |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| The Practice of Network Security Monitoring | Richard Bejtlich | The foundational NSM text; teaches the analyst mindset and systematic approach to network-based detection that carries over to all detection disciplines |
| Crafting the InfoSec Playbook | Jeff Bollinger, Brandon Enright, Matthew Valites | Practical guide to building detection playbooks, hunting hypotheses, and detection content libraries from Cisco's security team |
| Applied Incident Response | Steve Anson | Bridges detection and response; the treatment of log source requirements for detection is among the best available |
| The Threat Hunter Playbook | Jose Rodriguez | ATT&CK-driven hunting methodology from the creator of OSSEM; highly practical with real query examples |

---

## Certifications

- **GCED** (GIAC Certified Enterprise Defender) — Covers enterprise defense including network security monitoring, SIEM tuning, and endpoint detection; pairs with SANS SEC555
- **GCIH** (GIAC Certified Incident Handler) — Core certification covering incident detection, analysis, and response; widely respected and validates the detection-to-response workflow
- **BTL1** (Blue Team Labs Level 1) — Hands-on SOC analyst certification covering log analysis, SIEM investigation, threat intelligence, and digital forensics; strong practical validation for entry-level roles
- **CySA+** (CompTIA Cybersecurity Analyst) — Vendor-neutral certification covering threat detection, analysis, and response; widely recognized as an entry-to-mid-level SOC and detection credential
- **Splunk Core Certified User / Power User** — Vendor certification for Splunk SPL proficiency; valuable for detection engineers operating in Splunk-heavy environments
- **Microsoft SC-200** (Security Operations Analyst) — Microsoft Sentinel-focused certification covering detection rule writing, threat hunting, and SOAR playbook development in the Microsoft ecosystem

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — The most prolific free detection engineering content creator; hundreds of hours on SIEM workflows, detection methodology, and SOC analyst skills
- [13Cubed](https://www.youtube.com/@13Cubed) — Windows forensics and endpoint detection content with exceptional clarity; deep dives into Windows Event IDs and Sysmon telemetry
- [Florian Roth (Neo23x0)](https://www.youtube.com/@florianroth) — Detection rule authoring, YARA development, and threat hunting methodology from the creator of the Sigma format
- [LetsDefend](https://www.youtube.com/@LetsDefend) — SOC analyst training walkthroughs and detection investigation demonstrations
- [Splunk](https://www.youtube.com/@splunk) — SIEM detection content, SPL tutorials, and Splunk .conf presentations on enterprise detection programs
- [Elastic](https://www.youtube.com/@Elastic) — EQL tutorials, detection engineering content, and Elastic Security research talks

---

## Who to Follow

- [@neu5ron](https://x.com/neu5ron) — Nate Guagenti; Elastic detection engineering and EQL; excellent technical content on building detections in Elastic
- [@cyb3rward0g](https://x.com/cyb3rward0g) — Roberto Rodriguez; creator of OSSEM and the Threat Hunter Playbook; the most systematic thinker in detection engineering
- [@0xd4y](https://x.com/0xd4y) — Detection engineering content and Sigma rule development
- [@SigmaHQ](https://x.com/SigmaHQ) — Sigma project updates, new rule releases, and detection content community news
- [@FlorianRoth10](https://x.com/FlorianRoth10) — Florian Roth; YARA/Sigma rule author; prolific threat intelligence and detection content
- [@olafhartong](https://x.com/olafhartong) — Sysmon-modular maintainer; Windows telemetry and detection engineering depth
- [@jaredcatkinson](https://x.com/jaredcatkinson) — PowerShell-based detection and PSAttack author; ATT&CK technique coverage methodology
- [@Antonlovesdnb](https://x.com/Antonlovesdnb) — Anton Chuvakin; SIEM/detection strategy and detection program design
- [@Kostastsale](https://x.com/Kostastsale) — KQL and Microsoft Sentinel detection content; excellent for Sentinel-focused detection engineers

---

## Key Resources

- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Map your detection coverage across ATT&CK, identify gaps by tactic, and correlate Sigma rules, Elastic/Splunk detection counts, and Atomic Red Team tests against specific techniques
- [Sigma Rule Repository](https://github.com/SigmaHQ/sigma) — The community rule library; browse existing rules before writing new ones — many techniques already have high-quality Sigma coverage
- [MITRE D3FEND](https://d3fend.mitre.org) — The complementary framework to ATT&CK; maps defensive techniques to adversary techniques; use it to identify the right detection mechanism for a given attack pattern
- [Palantir Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework) — The ADS framework for structuring detection hypotheses, data requirements, and rule documentation; the standard template for professional detection engineering
- [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) — Pre-recorded adversary simulation telemetry for building and testing detections without running live attacks
- [Elastic Detection Rules Repository](https://github.com/elastic/detection-rules) — 1000+ production detection rules; excellent reference for detection logic patterns regardless of your SIEM platform
- [ATT&CK Data Sources](https://attack.mitre.org/datasources/) — The official mapping of ATT&CK techniques to the log sources and telemetry required to detect them; essential planning reference for coverage gap analysis
