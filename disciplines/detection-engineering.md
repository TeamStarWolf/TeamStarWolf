# Detection Engineering

Building, testing, and maintaining detection logic across log sources, SIEMs, and EDR platforms to reliably identify adversary behavior.

---

## Tools & Repositories

### Sigma
- [sigma](https://github.com/SigmaHQ/sigma) — Vendor-agnostic SIEM detection rule format; the Rosetta Stone of detections
- [pySigma](https://github.com/SigmaHQ/pySigma) — Convert Sigma rules to any SIEM query language
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) — Command-line tool for converting and validating Sigma rules
- [sigma-specification](https://github.com/SigmaHQ/sigma-specification) — The Sigma rule specification document
- [pySigma-backend-splunk](https://github.com/SigmaHQ/pySigma-backend-splunk) — Splunk SPL backend for pySigma

### Sysmon & Windows Logging
- [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — SwiftOnSecurity's widely-used Sysmon configuration baseline
- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) — Modular Sysmon configuration for selective telemetry
- [windows-event-forwarding](https://github.com/palantir/windows-event-forwarding) — Palantir Windows Event Forwarding guidance and configuration
- [Sysmon](https://github.com/palantir/Sysmon) — Palantir Sysmon configuration
- [python-evtx](https://github.com/williballenthin/python-evtx) — Pure Python parser for Windows EVTX log files
- [evtx](https://github.com/omerbenamram/evtx) — Fast EVTX parser in Rust
- [MSTIC-Sysmon](https://github.com/microsoft/MSTIC-Sysmon) — Microsoft Threat Intelligence Center Sysmon resources

### Detection Content
- [detection-rules](https://github.com/elastic/detection-rules) — Elastic SIEM detection rules and ATT&CK-mapped analytics
- [security_content](https://github.com/splunk/security_content) — Splunk Security detection content and research
- [SIGMA-detection-rules](https://github.com/mdecrevoisier/SIGMA-detection-rules) — Community Sigma rules with EVTX mapping
- [wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) — Wazuh detection rules and decoders
- [ThreatHunting-Keywords](https://github.com/mthcht/ThreatHunting-Keywords) — Hunting keywords mapped to ATT&CK techniques

### YARA
- [yara](https://github.com/VirusTotal/yara) — Pattern matching tool for malware identification
- [yara-python](https://github.com/VirusTotal/yara-python) — Python bindings for YARA
- [awesome-yara](https://github.com/InQuest/awesome-yara) — Curated list of YARA rules, tools, and resources
- [yara-rules](https://github.com/InQuest/yara-rules) — InQuest Labs YARA rules
- [rules](https://github.com/Yara-Rules/rules) — Large community YARA rule repository
- [reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) — ReversingLabs threat detection YARA rules

### Florian Roth / Neo23x0 Tools
- [Loki](https://github.com/Neo23x0/Loki) — Simple IOC and YARA scanner
- [signature-base](https://github.com/Neo23x0/signature-base) — YARA rules and IOC files from Florian Roth
- [yarGen](https://github.com/Neo23x0/yarGen) — YARA rule generator from malware samples
- [Fenrir](https://github.com/Neo23x0/Fenrir) — Simple Bash IOC checker
- [Raccine](https://github.com/Neo23x0/Raccine) — Ransomware vaccine targeting vssadmin abuse
- [panopticon](https://github.com/Neo23x0/panopticon) — YARA scanning tool

### Endpoint Telemetry & Hunting
- [osquery](https://github.com/osquery/osquery) — SQL-powered endpoint instrumentation
- [velociraptor](https://github.com/Velocidex/velociraptor) — Advanced live endpoint forensics and detection response
- [velociraptor-sigma-rules](https://github.com/Velocidex/velociraptor-sigma-rules) — Sigma rules converted for Velociraptor VQL
- [sysmon-dfir](https://github.com/MHaggis/sysmon-dfir) — Sysmon resources for threat detection and DFIR

### Log Analysis
- [hayabusa](https://github.com/Yamato-Security/hayabusa) — Sigma-based Windows event log threat hunting and timeline tool
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) — PowerShell event log analysis for threat hunting
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) — Visualize malicious Windows logon activity
- [EventLogging](https://github.com/blackhillsinfosec/EventLogging) — Black Hills Windows event logging guidance

### Adversary Emulation & Testing
- [atomic-red-team](https://github.com/redcanaryco/atomic-red-team) — Atomic tests mapped to ATT&CK for validating detections
- [invoke-atomicredteam](https://github.com/redcanaryco/invoke-atomicredteam) — PowerShell framework for executing Atomic Red Team tests
- [caldera](https://github.com/mitre/caldera) — MITRE automated adversary emulation platform
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) — Detection hypotheses and hunt procedures
- [sensor-mappings-to-attack](https://github.com/center-for-threat-informed-defense/sensor-mappings-to-attack) — Maps sensor telemetry to ATT&CK data sources
- [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) — EVTX samples mapped to MITRE ATT&CK

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| Blue Team Field Manual (BTFM) | Clark & Robertson | The defender's desk reference — detection commands for every platform |
| Crafting the InfoSec Playbook | Bollinger et al. | Building detection strategies, analytics pipelines, and security metrics |
| The Practice of Network Security Monitoring | Richard Bejtlich | NSM fundamentals and how to build a program around log data |
| Applied Network Security Monitoring | Sanders & Smith | Practical NSM with Zeek, Snort, and Security Onion — lab-first |
| Security Operations Center | Joseph Muniz | SOC design, detection workflows, staffing, and tool selection |

## Certifications

- **GCED** (GIAC Certified Enterprise Defender) — Covers defensive network infrastructure and detection
- **GCIH** (GIAC Certified Incident Handler) — Detection, response, and containment of incidents
- **BTL1** (Blue Team Labs Level 1) — Hands-on detection and analysis cert from Security Blue Team
- **CySA+** (CompTIA Cybersecurity Analyst) — SIEM, threat detection, and security analytics

## Channels

- [13Cubed](https://www.youtube.com/@13Cubed) — DFIR techniques, Windows forensics, and event log analysis
- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Detection engineering, webcasts, and Wild West Hackin' Fest talks
- [Elastic](https://www.youtube.com/@elastic) — Detection rule engineering and SIEM content
- [Splunk](https://www.youtube.com/@splunkofficial) — Boss of the SOC, ESCU, and detection use cases
- [Red Canary](https://www.youtube.com/@RedCanary) — Detection engineering and Atomic Red Team content
- [The Weekly Purple Team](https://www.youtube.com/@WeeklyPurpleTeam) — Purple-team operations, detection coverage, and methodology
- [SANS Digital Forensics and Incident Response](https://www.youtube.com/@SANSForensics) — SANS DFIR and detection content
- [Microsoft Security Community](https://www.youtube.com/@MicrosoftSecurityCommunity) — Sentinel, Defender, and KQL-based detection

## Who to Follow

- [@SBousseaden](https://x.com/SBousseaden) — Detection engineering, Sigma rules, and endpoint research
- [@mattifestation](https://x.com/mattifestation) — Matt Graeber; PowerShell, detection bypass research, and AMSI
- [@cyb3rward0g](https://x.com/cyb3rward0g) — Roberto Rodriguez; HELK, OSSEM, and ATT&CK data modeling
- [@cyb3rops](https://x.com/cyb3rops) — Florian Roth; Sigma, YARA, and signature-based detection
- [@JohnLaTwC](https://x.com/JohnLaTwC) — John Lambert, Microsoft; threat hunting and detection strategy
- [@SigmaHQ](https://x.com/SigmaHQ) — Sigma project official account
- [@ElasticSecurity](https://x.com/ElasticSecurity) — Elastic Security detections and research
- [@splunk](https://x.com/splunk) — Splunk platform and ESCU updates
- [@HuntressLabs](https://x.com/HuntressLabs) — Huntress; SMB-focused detection and threat hunting
- [@Velocidex](https://x.com/Velocidex) — Velociraptor project
- [@swannysec](https://x.com/swannysec) — Detection engineering practice and community

## Key Resources

- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma) — The primary community detection rule library
- [The DFIR Report](https://thedfirreport.com) — Real intrusion case studies with full ATT&CK mapping
- [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) — Labeled telemetry datasets for detection testing
- [Elastic Detection Blog](https://www.elastic.co/security-labs) — Detection engineering research and rule walkthroughs
- [Splunk ESCU](https://research.splunk.com) — Splunk's published detection content with analytics stories
- [ATT&CK Data Sources](https://attack.mitre.org/datasources/) — MITRE mapping of telemetry to detectable behaviors

---

*Part of the [TeamStarWolf](https://github.com/TeamStarWolf) community resource library.*
