# Detection Engineering

Building, testing, and maintaining detection logic across log sources, SIEMs, and EDR platforms to reliably identify adversary behavior.

---

## Where to Start

Detection engineering is where threat intelligence becomes operational. The goal is not to collect logs — it is to build reliable, tuned, ATT&CK-mapped analytics that alert when adversary behavior is present and stay quiet when it is not. Start by learning Windows event logs and Sysmon: they are the primary telemetry source for most enterprise detections. Then learn Sigma — the vendor-agnostic rule format that lets you write a detection once and deploy it anywhere. Practice writing detections against known attack techniques using Atomic Red Team to generate the behavior, then validate your rules catch it.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Windows event logs, Sysmon setup, log analysis basics | DeepBlueCLI, Antisyphon SOC Core Skills, TryHackMe Blue Team path |
| Practitioner | Sigma rules, SIEM queries, ATT&CK data sources, adversary emulation | HTB Academy SOC path, BHIS webcasts, LetsDefend |
| Advanced | Detection-as-code, analytics pipelines, purple teaming, metrics | SANS SEC555, GCED, detection maturity frameworks |

---

## Free Training

- [Antisyphon: SOC Core Skills with John Strand](https://www.antisyphontraining.com/product/soc-core-skills-with-john-strand/) — Pay-what-you-can ($0+); covers detection strategy, log analysis, and building a detection program
- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts covering detection engineering, log analysis, Active Directory detection, and adversary behavior
- [BHIS YouTube](https://www.youtube.com/@BlackHillsInformationSecurity) — Extensive free content on Windows event logging, network detection, and SOC operations; search their channel for specific techniques
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — SOC 101 course and free YouTube content covering detection from an analyst perspective
- [TCM Academy Free Tier](https://academy.tcm-sec.com/courses) — 25+ hours of free on-demand content
- [Hack The Box Academy](https://academy.hackthebox.com) — Free Student tier; SOC Analyst path with hands-on SIEM and detection labs
- [Blue Team Labs Online](https://blueteamlabs.online) — Free tier; practical detection and analysis challenges
- [LetsDefend](https://letsdefend.io) — SOC simulation platform with detection alert triage and analysis exercises
- [IppSec](https://www.youtube.com/@ippsec) — HackTheBox walkthroughs that show exactly how attacks behave; essential context for writing detections
- [IppSec Search](https://ippsec.rocks) — Search across all IppSec walkthrough transcripts by tool or technique name
- [SANS Cheat Sheets](https://www.sans.org/posters) — Free Windows forensics, log analysis, and SIEM cheat sheets

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
- [EventLogging](https://github.com/blackhillsinfosec/EventLogging) — Black Hills Windows event logging guidance

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

---

## Certifications

- **GCED** (GIAC Certified Enterprise Defender) — Covers network security, endpoint visibility, and detection engineering fundamentals
- **GCIH** (GIAC Certified Incident Handler) — Detection, triage, and containment of security incidents
- **BTL1** (Blue Team Labs Level 1) — Practical hands-on certification covering detection, log analysis, and incident triage
- **CompTIA CySA+** — Entry-level detection and analysis certification; good vendor-neutral foundation
- **Antisyphon SOC Core Skills** — Pay-what-you-can with credential upon completion

---

## Channels

- [Black Hills Information Security](https://www.youtube.com/@BlackHillsInformationSecurity) — Detection engineering, Windows event logging, and adversary behavior content; BHIS is behind the widely-used EventLogging repo
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — SOC analyst training and detection-focused content
- [13Cubed](https://www.youtube.com/@13Cubed) — Windows forensics, log analysis, and artifact deep dives
- [SANS Internet Storm Center](https://www.youtube.com/@SansInstitute) — Threat analysis and detection guidance
- [John Hammond](https://www.youtube.com/@_JohnHammond) — CTF walkthroughs, malware analysis, and detection technique demonstrations

---

## Who to Follow

- [@cyb3rops](https://x.com/cyb3rops) — Florian Roth; Sigma co-creator, YARA expert, detection engineering authority
- [@olafhartong](https://x.com/olafhartong) — Sysmon-modular author; Windows telemetry and detection engineering
- [@neu5ron](https://x.com/neu5ron) — Detection engineering research
- [@SBousseaden](https://x.com/SBousseaden) — Elastic detection research; Windows internals for detection
- [@SwiftOnSecurity](https://x.com/SwiftOnSecurity) — Author of the most-used Sysmon config baseline
- [@SecurityOnion](https://x.com/SecurityOnion) — Open source NSM platform
- [@DougBurks](https://x.com/DougBurks) — Security Onion creator
- [@Cyb3rWard0g](https://x.com/Cyb3rWard0g) — HELK and ThreatHunter-Playbook creator

---

## Key Resources

- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/) — Maps telemetry sources to the techniques they can detect
- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Visualize Sigma rule coverage, Atomic Red Team tests, Elastic/Splunk detections, and CAR analytics across the ATT&CK matrix
- [SigmaHQ Rules](https://github.com/SigmaHQ/sigma/tree/master/rules) — The community Sigma rule repository; a detection engineering curriculum in itself
- [Atomic Red Team](https://atomicredteam.io) — Free adversary emulation tests for every ATT&CK technique
- [Security Onion](https://securityonionsolutions.com) — Free NSM and detection platform; the fastest way to build a detection lab
- [SANS Blue Team Posters](https://www.sans.org/posters) — Free cheat sheets for Windows event IDs, log analysis, and memory forensics
