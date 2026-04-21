# Detection Engineering

Detection engineering is the practice of building, testing, validating, and maintaining a scalable program for identifying adversary behavior across an organization's environments. It is distinct from alert triage — detection engineers don't respond to alerts, they design the systems that generate them. The discipline covers the full detection lifecycle: identifying coverage gaps through threat modeling and adversary emulation, authoring detection logic in structured formats like Sigma and YARA, validating coverage using atomic tests and purple team exercises, tuning to eliminate false positives, and retiring detections that no longer reflect the threat landscape.

Good detection programs are hypothesis-driven, not signature-collection exercises. The goal is behavioral coverage of adversary TTPs mapped to the threats most relevant to your organization — not maximizing alert volume. The Pyramid of Pain illustrates this: IOC-based detections (hashes, IPs, domains) are trivially bypassed by adversaries, while TTP-based detections (process injection, LOLBAS abuse, credential dumping behaviors) remain durable even when tooling changes. Every detection should have a documented data source requirement, a validation test, and a clear suppression policy. This engineering rigor separates mature detection programs from collections of vendor-default rules that fire constantly and get ignored.

---

## Where to Start

Learn your log sources before you learn detection logic. Understanding what Windows Event ID 4624 actually means, what Sysmon event 1 captures versus event 10, and how network flow data differs from full packet capture is foundational. From there, learn Sigma as your portable rule format, then learn the query language for whichever SIEM your environment uses. Practice in free environments — Elastic SIEM, Splunk free trial, or Microsoft Sentinel trial — before working with production data.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Windows Event IDs (4624/4625, 4688, 4697/7045, 4698/4702, 4720, 1102), Sysmon Event IDs (1, 3, 7, 8, 10, 11, 22), Sigma rule structure, SIEM basics, ATT&CK technique-to-log-source mapping | BHIS SOC Core Skills webcasts (free), TryHackMe SOC paths, 13Cubed Windows forensics YouTube |
| Practitioner | Detection content pipelines, Sigma rule authoring and validation, Atomic Red Team testing, MITRE D3FEND, coverage heatmaps, false positive tuning, Pyramid of Pain | SigmaHQ documentation, Atomic Red Team project, Splunk Security Essentials (free), HTB Academy SOC path |
| Advanced | Detection-as-code CI/CD pipelines, behavioral detection beyond indicators, UEBA, threat hunting integration, attacker evasion detection (AMSI bypass, LOLBAS, timestomping), Palantir ADS framework | Palantir ADS framework, MITRE CTID publications, Elastic detection-rules repository, SANS FOR555 |

---

## Detection Lifecycle

Detection engineering is a continuous cycle, not a one-time configuration effort.

```
1. Requirement       → Threat model, red team finding, or TI report identifies a coverage gap
2. Data Source       → Identify what logs are needed (Sysmon, Windows Event Log, EDR telemetry, network flows)
3. Rule Authoring    → Write Sigma YAML (or native SIEM query); peer review
4. Testing           → Validate with Atomic Red Team test; confirm true positive fires, false negatives absent
5. Deployment        → Push to production SIEM/EDR via content pipeline (CI/CD preferred)
6. Tuning            → Suppress known false positive patterns; adjust thresholds
7. Deprecation       → Retire detections for retired technologies, superseded TTPs, or consistently FP-heavy rules
```

**Pyramid of Pain** (David Bianco): Attacker cost to evade detections increases as you move up the pyramid.

```
[TTP-Based Detections]     ← Tough! Changing behavior requires significant effort
[Tools]                    ← Challenging — new tool versions, custom tooling
[Network/Host Artifacts]   ← Annoying — registry keys, process names
[Domain Names]             ← Simple — new domain registered
[IP Addresses]             ← Easy — new IP spun up
[Hash Values]              ← Trivial — recompile, trivially different hash
```

The detection engineering goal is to build detections as high on this pyramid as possible — detecting **behaviors** (process injection, LOLBAS execution, credential access patterns) rather than specific indicators.

---

## Critical Windows Event IDs

These are the highest-value Windows Security and System event IDs for detection engineering. Every detection program must have coverage on these before chasing exotic telemetry.

| Event ID | Log | Description | Detection Value |
|---|---|---|---|
| 4624 | Security | Successful logon | Baseline for lateral movement, after-hours access, and unusual logon types (Type 3 network, Type 10 RemoteInteractive) |
| 4625 | Security | Failed logon | Brute-force and password spray detection; threshold-based alerting on repeated failures |
| 4688 | Security | Process creation (with command line if audited) | Process execution monitoring; key source for LOLBAS detection, malicious scripts, and lateral movement tools |
| 4697 | Security | Service installed in the system | Persistence via malicious service; high-fidelity alert when combined with allowlisting |
| 7045 | System | New service installed | Equivalent service creation event in System log; covers cases where Security log is cleared |
| 4698 | Security | Scheduled task created | Persistence via scheduled tasks; alert on tasks creating processes from temp directories or running encoded commands |
| 4702 | Security | Scheduled task modified | Existing task hijacked for persistence; compare task content against known-good baseline |
| 4720 | Security | User account created | New account creation; critical to alert in real time to catch attacker-created persistence accounts |
| 4732 | Security | Member added to a security-enabled local group | Privilege escalation via group membership; alert on additions to Administrators, Remote Desktop Users |
| 4776 | Security | NTLM authentication attempt | Pass-the-hash and NTLM relay detection when Kerberos should be in use; correlate with lateral movement |
| 1102 | Security | Audit log was cleared | High-priority alert; legitimate clearing is rare; almost always indicates active attacker covering tracks |

**Enabling Process Creation Logging**: Event ID 4688 with command-line logging requires enabling "Audit Process Creation" in Advanced Audit Policy and setting the `ProcessCreationIncludeCmdLine_Enabled` registry key. Without command-line, 4688 is significantly less useful.

---

## Sysmon Event IDs

Sysmon (System Monitor) provides dramatically richer telemetry than native Windows logging. These are the highest-value Sysmon event IDs:

| Event ID | Name | Description | Detection Value |
|---|---|---|---|
| 1 | Process Create | Full process creation with parent, command line, hashes, and user | Richest process execution source; enables parent-child chain analysis |
| 3 | Network Connection | Outbound network connections with process, destination, and ports | C2 beaconing detection, lateral movement via network, LOLBAS network activity |
| 7 | Image Load | DLL loaded into a process with hash and signature status | Detect DLL hijacking, unsigned DLL loading, and in-memory module execution |
| 8 | CreateRemoteThread | Remote thread creation into another process | Process injection detection; highly anomalous when source/target processes mismatch |
| 10 | ProcessAccess | Process opening a handle to another process | Credential dumping (LSASS access), process hollowing; alert on unexpected access to lsass.exe |
| 11 | FileCreate | File creation with hash | Dropper detection, payload staging, suspicious file writes to temp directories |
| 22 | DNSQuery | DNS query with process and result | C2 domain detection, DNS tunneling, fast-flux identification; correlate with Threat Intelligence |
| 13 | RegistryEvent (Value Set) | Registry value written | Persistence via registry Run keys, COM hijacking, service configuration changes |
| 25 | ProcessTampering | Process hollowing or herpaderping detected | Direct detection of advanced evasion techniques attempting to hide process identity |

---

## Sigma Rule Structure

Sigma is the universal detection rule format — write once, convert to Splunk SPL, Elastic EQL, Microsoft KQL, QRadar AQL, and 30+ other targets.

```yaml
title: Suspicious LSASS Memory Access
id: a8c6c8e0-f5b1-4b4a-9b7f-3e2c1d0e6f5a
status: experimental
description: Detects suspicious access to LSASS process memory, indicative of credential dumping
references:
    - https://attack.mitre.org/techniques/T1003/001/
author: Detection Engineering Team
date: 2024/01/15
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x147a'
            - '0x143a'
    filter_legit:
        SourceImage|contains:
            - '\Windows\System32\'
            - '\Windows\SysWOW64\'
            - 'MsMpEng.exe'
    condition: selection and not filter_legit
falsepositives:
    - Legitimate security software accessing LSASS
    - Antivirus products
level: high
```

**Key YAML fields**:
- `logsource` — defines the log category and product; pySigma backends translate this to the correct index/source
- `detection` — named selection blocks; supports field modifiers (`|contains`, `|endswith`, `|startswith`, `|re`)
- `condition` — boolean logic combining selection blocks; `1 of selection*` matches any block prefixed with "selection"
- `falsepositives` — documented expected FP sources for tuning guidance
- `level` — informational / low / medium / high / critical; drives SIEM alert priority

---

## Attacker Evasion Techniques (What Detection Must Catch)

Detection programs must explicitly cover adversary evasion, not just the initial attack TTPs.

| Evasion Technique | How It Works | Detection Approach |
|---|---|---|
| **Timestomping** | Modifying file timestamps to blend with legitimate files or pre-date the incident | Sysmon Event 2 (file creation time changed); compare filesystem timestamps with MFT timestamps |
| **Parent Process Spoofing** | Using `CreateProcess` with `PROCESS_CREATION` flags to set a fake parent process — e.g., making malware appear as a child of explorer.exe | Detect mismatches between the process tree and expected parent-child relationships |
| **AMSI Bypass** | Patching the AmsiScanBuffer function in memory to return "clean" for all content; defeats script-based malware detection | Sysmon Event 10 (handle to amsi.dll process); memory write patterns; PowerShell ScriptBlock logging |
| **Log Clearing** | Deleting event logs (wevtutil cl, Clear-EventLog) to remove forensic evidence | Event ID 1102 (Security log cleared), 104 (System log cleared); near-real-time SIEM forwarding to preserve logs before clearing |
| **LOLBAS** | Using legitimate binaries (certutil, mshta, regsvr32, wscript, bitsadmin) for malicious purposes to blend with legitimate activity | Process execution rules for known LOLBAS binaries with suspicious command-line patterns; network connections from non-network binaries |
| **Process Injection** | Injecting malicious code into legitimate processes (e.g., svchost.exe, explorer.exe) to hide execution and evade process-based detection | Sysmon Event 8 (CreateRemoteThread), Event 10 (ProcessAccess to injection targets); behavioral detection of unexpected modules |

---

## Free Training

- [BHIS SOC Core Skills Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Hundreds of free hours covering detection methodology, SIEM tuning, log analysis, and SOC workflow
- [SANS Threat Hunting and Detection Summit Talks](https://www.youtube.com/@SansInstitute) — Annual summit recordings covering detection-as-code, behavioral analytics, and advanced detection programs
- [TryHackMe SOC Level 1 and Level 2 Paths](https://tryhackme.com) — Structured browser-based learning covering Windows Event Logs, Splunk, Snort, Zeek, and detection fundamentals
- [Hack The Box Academy SOC Analyst Path](https://academy.hackthebox.com) — Free Student tier covering Windows/Linux log analysis, SIEM fundamentals, IDS/IPS, and network traffic analysis
- [Sigma Documentation and Community](https://github.com/SigmaHQ/sigma) — Free rule format documentation, conversion tools, and the community rule repository
- [Splunk Security Essentials App](https://splunkbase.splunk.com/app/3435) — Free Splunk app containing 200+ detections mapped to ATT&CK with detailed explanations
- [Elastic Security Labs](https://www.elastic.co/security-labs) — Free detection research, EQL rule examples, and malware analysis from Elastic's security team
- [LetsDefend](https://letsdefend.io) — Free SOC simulator for practicing alert triage, threat analysis, and detection validation
- [Blue Team Labs Online](https://blueteamlabs.online) — Free detection and forensics challenges covering log analysis and SIEM investigation
- [Antisyphon SOC Core Skills](https://www.antisyphontraining.com) — Pay-what-you-can live training from John Strand; exceptional value

---

## Tools & Repositories

### Detection Content & Rule Formats
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — Universal detection rule format; 3000+ community rules mapped to ATT&CK; convert to Splunk SPL, Elastic EQL, Microsoft KQL, and 30+ other targets
- [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma) — Python library for Sigma rule parsing, validation, and backend conversion; use to build detection pipelines and CI/CD workflows
- [elastic/detection-rules](https://github.com/elastic/detection-rules) — Elastic's production detection rules; excellent reference for EQL and KQL detection patterns regardless of SIEM
- [splunk/security_content](https://github.com/splunk/security_content) — Splunk Threat Research Team detection content with ATT&CK mappings and data source requirements

### Sysmon & Endpoint Telemetry
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — Most widely deployed Sysmon configuration; carefully tuned for maximum visibility with controlled noise
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) — Modular Sysmon configuration framework for selective event collection and easier maintenance
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) — Florian Roth's YARA and Sigma rule base; thousands of production-quality detection rules

### Adversary Emulation & Validation
- [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) — Library of focused test cases mapped to ATT&CK techniques; the standard for validating detection coverage
- [mitre/caldera](https://github.com/mitre/caldera) — MITRE's automated adversary emulation platform; runs ATT&CK-mapped operations for continuous detection validation
- [center-for-threat-informed-defense/summiting_the_pyramid](https://github.com/center-for-threat-informed-defense/summiting_the_pyramid) — Framework for building detections robust against adversary evasion; detect behavior rather than brittle indicators

### SIEM-Specific Content
- [microsoft/Microsoft-Sentinel-Content](https://github.com/Azure/Azure-Sentinel) — Microsoft Sentinel Content Hub rules, workbooks, and playbooks; the community contribution point for Sentinel detections
- [Splunk Security Content](https://github.com/splunk/security_content) — See above; 1000+ SPL detections with ATT&CK mappings and data model documentation

---

## Commercial Platforms

| Platform | Strength |
|---|---|
| **Splunk Enterprise Security** | Most widely deployed enterprise SIEM; Risk-Based Alerting (RBA), Splunk Security Essentials content library, powerful SPL |
| **Microsoft Sentinel** | Cloud-native SIEM; KQL analytics, tight M365 Defender integration, Sentinel Content Hub with community rules |
| **Elastic Security** | Open-source core with enterprise tiers; EQL temporal sequence matching, built-in ATT&CK alignment |
| **CrowdStrike Falcon** | Market-leading EDR; behavioral engine, OverWatch managed hunting, Fusion SOAR for automated response |
| **SentinelOne Singularity** | EDR and XDR with autonomous response and Storyline attack chain reconstruction |
| **Palo Alto Cortex XDR** | XDR correlating endpoint, network, and cloud telemetry; behavioral analytics with ATT&CK mapping |
| **IBM QRadar** | Long-standing enterprise SIEM dominant in regulated industries; AQL query language, deep compliance reporting |
| **Vectra AI** | Network detection and response using AI; strongest for C2 beaconing and lateral movement detection |

---

## NIST 800-53 Control Alignment

| Control | ID | Detection Engineering Relevance |
|---|---|---|
| Audit Events | AU-2 | Define the event types to be logged — Security Event IDs, Sysmon, EDR telemetry; the data source foundation for all detection |
| Audit Record Generation | AU-12 | Ensure logging is enabled at endpoints, servers, and network devices; detection fails completely when logs are absent |
| Audit Record Review, Analysis, and Reporting | AU-6 | The SIEM detection program implements this control; automated analysis of audit records to identify anomalous activity |
| Security Alerts, Advisories, and Directives | SI-5 | Threat intelligence feeds integrated into SIEM/detection content to operationalize external adversary indicators |
| Information System Monitoring | SI-4 | Continuous monitoring via SIEM, EDR, and NDR; intrusion detection systems; the architectural control detection engineering implements |
| Software, Firmware, and Information Integrity | SI-7 | File integrity monitoring (FIM) for critical system files; detect unauthorized modification of binaries, configurations, and scripts |
| Incident Handling | IR-4 | Detection engineering produces the alerts that initiate incident response; playbook integration between detection rules and IR procedures |
| Penetration Testing | CA-8 | Red team and adversary emulation outputs (Atomic Red Team tests, purple team findings) drive detection coverage improvements |

---

## ATT&CK Coverage

Detection engineering directly implements coverage against specific ATT&CK techniques. Priority coverage areas:

| Technique | ID | Detection Approach | Key Log Sources |
|---|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Alert on processes accessing lsass.exe with dump-capable access rights | Sysmon Event 10 (ProcessAccess), Windows Event 4656 |
| Process Injection | T1055 | Alert on CreateRemoteThread to non-self targets; unusual module loads into system processes | Sysmon Events 8, 10; EDR behavioral |
| Scheduled Task/Job Creation | T1053.005 | Alert on task creation with executable/script paths in temp directories or using encoded commands | Windows Event 4698, 4702; Sysmon Event 1 (schtasks.exe) |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Monitor PowerShell script block logging (Event 4104); alert on encoded commands, AMSI bypass patterns | Windows Event 4104, Sysmon Event 1 |
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | Monitor registry writes to Run/RunOnce keys and service configuration keys | Sysmon Event 13 (RegistryEvent), Windows Event 4657 |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | Alert immediately on Security log (1102) or System log (104) clear events | Windows Security 1102, System 104 |
| Living Off The Land Binaries (LOLBAS) | T1218 | Detect LOLBAS execution (certutil, mshta, regsvr32) with network connections or encoding flags | Sysmon Events 1, 3; Windows Event 4688 |
| Lateral Movement: Pass the Hash | T1550.002 | Detect Type 3 (network) logons with NTLM authentication where Kerberos is expected | Windows Event 4624 (logon type 3), 4776 |

---

## Certifications

- **GCIA** (GIAC Certified Intrusion Analyst) — Covers network traffic analysis, IDS/IPS signature development, and protocol analysis; strong foundation for detection engineers focused on network-layer telemetry
- **GCIH** (GIAC Certified Incident Handler) — Core certification covering incident detection, analysis, and response; validates the full detection-to-response workflow
- **GCED** (GIAC Certified Enterprise Defender) — Enterprise defense including network security monitoring, SIEM tuning, and endpoint detection; most directly aligned to detection engineering roles
- **BTL1** (Blue Team Labs Level 1 — Security Blue Team) — Hands-on SOC analyst certification covering log analysis, SIEM investigation, and digital forensics; strong practical validation for entry-level detection roles
- **Splunk Core Certified User / Power User** — SPL proficiency; valuable for detection engineers operating primarily in Splunk environments
- **Elastic Certified Analyst** — EQL proficiency and Elastic Security platform expertise; the corresponding credential for Elastic-focused detection engineers
- **Microsoft SC-200** (Security Operations Analyst) — Microsoft Sentinel-focused certification covering detection rule authoring, threat hunting, and SOAR playbook development
- **CySA+** (CompTIA Cybersecurity Analyst) — Vendor-neutral credential covering threat detection, analysis, and response; widely recognized as an entry-to-mid-level credential

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) | Free tool | Map detection coverage across ATT&CK; identify gaps by tactic; correlate Sigma rules and Atomic Red Team tests |
| [Sigma Rule Repository](https://github.com/SigmaHQ/sigma) | Free rules | Community detection rule library; browse existing rules before authoring new ones |
| [MITRE D3FEND](https://d3fend.mitre.org) | Free framework | Maps defensive techniques to adversary techniques; identify the right detection mechanism for any attack pattern |
| [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework) | Free framework | Alerting and Detection Strategy framework; standard template for professional detection engineering documentation |
| [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) | Free datasets | Pre-recorded adversary simulation telemetry for building and testing detections |
| [ATT&CK Data Sources](https://attack.mitre.org/datasources/) | Free reference | Official mapping of ATT&CK techniques to required log sources; essential for gap analysis |
| The Practice of Network Security Monitoring (Bejtlich) | Book | Foundational NSM text; teaches analyst mindset and systematic detection approach |
| Crafting the InfoSec Playbook (Bollinger et al.) | Book | Practical guide to detection playbooks, hunting hypotheses, and detection content libraries |

---

## Related Disciplines

- [Incident Response](incident-response.md)
- [Threat Intelligence](threat-intelligence.md)
- [Threat Hunting](threat-hunting.md)
- [SIEM & Log Management](siem-log-management.md)
- [Offensive Security](offensive-security.md)
- [Malware Analysis](malware-analysis.md)
