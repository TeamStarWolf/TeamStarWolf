# SIEM & SOAR

## Introduction

Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) are the operational backbone of a modern Security Operations Center (SOC). SIEM aggregates and correlates security telemetry from across the environment to detect threats. SOAR automates the response workflow — enriching alerts, making decisions, and taking actions at machine speed.

Together, they reduce mean time to detect (MTTD) and mean time to respond (MTTR) — the two metrics that most determine how much damage an attacker can do before being stopped.

## Where to Start

1. **Deploy a free/open-source SIEM first** — Elastic SIEM (ELK Stack) or Wazuh to learn the concepts without cost
2. **Learn log sources** — Windows Event Logs, Syslog, firewall logs, DNS logs are the most universal
3. **Master one query language** — SPL (Splunk) or KQL (Elastic/Sentinel) before branching out
4. **Build 5–10 detection rules** — brute force, impossible travel, process injection, large outbound transfer
5. **Practice with real data** — Splunk BOTS (Boss of the SOC) CTF dataset is free and excellent
6. **Understand the alert lifecycle** — triage, enrichment, investigation, containment, closure

## Free Training

- [Splunk Boss of the SOC (BOTS)](https://bots.splunk.com/) — free CTF dataset with guided exercises
- [Splunk Free Training](https://www.splunk.com/en_us/training/free-courses/overview.html) — Splunk Fundamentals 1 is free
- [Elastic SIEM Documentation](https://www.elastic.co/guide/en/security/current/index.html) — free; covers detection rules, EQL
- [Microsoft Sentinel Ninja Training](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/become-a-microsoft-sentinel-ninja-the-complete-level-400/ba-p/1246310) — free; Level 400 content
- [Microsoft Sentinel GitHub](https://github.com/Azure/Azure-Sentinel) — free detection rules, workbooks, playbooks
- [SANS SEC555 Syllabus](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/) — paid course; free syllabus as study guide
- [TryHackMe SOC Level 1 Path](https://tryhackme.com/path/outline/soclevel1) — affordable, hands-on SIEM labs
- [LetsDefend Platform](https://letsdefend.io/) — SOC analyst simulation platform; free tier

## Tools & Repositories

### Open Source SIEM/Log Management
| Tool | Description |
|---|---|
| [Elastic SIEM (ELK Stack)](https://www.elastic.co/siem) | Elasticsearch + Kibana + Beats; ECS-normalized; production-grade free tier |
| [Wazuh](https://wazuh.com/) | Open-source XDR/SIEM; agent-based; built on Elasticsearch |
| [OpenSearch Security Analytics](https://opensearch.org/docs/latest/security-analytics/) | AWS-backed open source; fork of Elasticsearch |
| [Graylog](https://www.graylog.org/) | Log management + alerting; good for smaller environments |
| [OSSEC](https://www.ossec.net/) | Host-based IDS with log analysis; lightweight |

### Log Shippers & Agents
| Tool | Use Case |
|---|---|
| [Splunk Universal Forwarder](https://www.splunk.com/en_us/download/universal-forwarder.html) | Windows/Linux log shipping to Splunk |
| [Elastic Agent / Beats](https://www.elastic.co/beats/) | Winlogbeat (Windows), Filebeat (logs), Packetbeat (network) |
| [Fluentd / Fluent Bit](https://fluentbit.io/) | Cloud-native log routing; lightweight Kubernetes logging |
| [Vector (Datadog)](https://vector.dev/) | High-performance log/metric pipeline |
| rsyslog / syslog-ng | Traditional Unix syslog forwarding |

### Open Source SOAR
| Tool | Description |
|---|---|
| [Shuffle](https://shuffler.io/) | Open-source SOAR; drag-and-drop playbooks; Docker-based |
| [TheHive + Cortex](https://thehive-project.org/) | Open-source incident management + automated analysis |
| [OpenCTI](https://www.opencti.io/) | Threat intelligence platform with SOAR-like automation |
| [MISP](https://www.misp-project.org/) | Threat intelligence sharing platform; Cortex integration |

### Detection Rule Repositories
| Repository | Content |
|---|---|
| [Sigma Rules](https://github.com/SigmaHQ/sigma) | 3000+ vendor-agnostic detection rules; converts to SPL/KQL/AQL |
| [Elastic Detection Rules](https://github.com/elastic/detection-rules) | Production rules for Elastic SIEM |
| [Microsoft Sentinel Detections](https://github.com/Azure/Azure-Sentinel/tree/master/Detections) | KQL rules for Sentinel |
| [Splunk Security Content](https://github.com/splunk/security_content) | Splunk analytic stories mapped to ATT&CK |
| [SOC Prime TDM](https://tdm.socprime.com/) | Community detection rules marketplace |

## Commercial Platforms

| Platform | Query Language | Strengths | Weaknesses |
|---|---|---|---|
| **Splunk Enterprise / Cloud** | SPL | Most powerful; largest ecosystem; Phantom SOAR; UEBA | Very expensive at scale; complex licensing |
| **Microsoft Sentinel** | KQL | Azure-native; threat intel integration; UEBA; Logic Apps SOAR | KQL learning curve; Azure dependency |
| **Elastic SIEM / Security** | EQL / KQL | Open-source core; fast search; ECS standard; ML anomaly | Complex to self-manage at scale |
| **IBM QRadar** | AQL | Network-centric; strong large enterprise; built-in SOAR | Dated UI; complex administration; expensive |
| **Google Chronicle / SecOps** | YARA-L | Petabyte retention; Google threat intel; massive scale | Proprietary; Google Cloud lock-in |
| **LogRhythm NextGen SIEM** | LEQL | Compliance-focused; UEBA built-in; good workflow | Expensive; complex; slower innovation |
| **Sumo Logic** | SumoQL | Cloud-native SaaS; easy setup; good for cloud logs | Less powerful correlation than Splunk |
| **Exabeam Fusion SIEM** | Search DSL | UEBA-first; behavioral analytics; timeline view | Newer; smaller ecosystem |
| **Securonix** | Spotter | Cloud-native; strong UEBA; MITRE ATT&CK overlay | Less community content |

## SIEM Architecture Deep Dive

### Data Collection Methods
| Method | Examples | Use Case |
|---|---|---|
| **Agent-based** | Splunk UF, Elastic Agent, Winlogbeat | Windows endpoints, servers — rich telemetry |
| **Syslog (UDP/TCP)** | rsyslog, syslog-ng | Network devices, firewalls, Unix systems |
| **API Polling** | O365 Management API, AWS CloudTrail, Google Workspace | Cloud service logs |
| **Network TAP / Span Port** | Zeek, Suricata, Packetbeat | Network flow and protocol analysis |
| **File/Webhook Ingest** | S3 bucket ingestion, HTTP Event Collector (HEC) | Batch log delivery from cloud services |

### Log Normalization Standards
- **ECS (Elastic Common Schema)**: Standardizes field names across log sources for Elastic; `source.ip`, `event.action`, `user.name`
- **CEF (Common Event Format)**: ArcSight-originated standard; widely supported by security products
- **LEEF (Log Event Extended Format)**: IBM QRadar standard
- **OCSF (Open Cybersecurity Schema Framework)**: Newer open standard backed by AWS, Splunk, IBM; gaining adoption

### Storage and Retention Architecture
- **Hot tier**: Recent data (7–30 days); SSD; fast search; expensive
- **Warm tier**: Medium-term data (30–90 days); HDD; slower search; moderate cost
- **Cold/Frozen tier**: Long-term data (90 days–7 years); object storage (S3, Azure Blob); compliance retention; slow search
- **Retention policies**: PCI DSS requires 1 year; HIPAA requires 6 years; set policies that meet compliance minimums

### Correlation Rule Types
| Rule Type | Example | Strength |
|---|---|---|
| **Threshold** | 10 failed logins in 60 seconds | Simple, low FP for clear thresholds |
| **Statistical Anomaly** | Outbound bytes > 3σ from baseline | Catches novel attacks; requires baseline |
| **Pattern Matching** | Specific command sequence in shell history | High fidelity for known attack patterns |
| **Sequence Detection** | Recon → lateral movement → exfil within 24h | Complex multi-stage attack detection |
| **ML/UEBA Behavioral** | User suddenly accesses 500 files not in their baseline | Catches insider threat and account compromise |

## Search Language Examples

### SPL (Splunk Processing Language) — Production Queries

```spl
# Top talkers — identify unusual data volumes by host
index=network
| stats sum(bytes_out) AS total_out BY src_ip
| sort -total_out
| head 20

# Detect brute force login attempts (5-minute windows)
index=windows EventCode=4625
| bucket _time span=5m
| stats count AS failures BY _time, src_ip, TargetUserName
| where failures > 10
| sort -failures

# Hunt for PowerShell download cradles
index=windows (EventCode=4688 OR EventCode=1)
| search CommandLine IN ("*IEX*","*Invoke-Expression*","*DownloadString*","*WebClient*","*Net.WebRequest*")
| table _time host user CommandLine

# Detect lateral movement via PsExec/remote service creation
index=windows EventCode=7045
| where ServiceFileName LIKE "%\\\\%\\%" OR ServiceFileName LIKE "%ADMIN$%"
| table _time host ServiceName ServiceFileName AccountName

# Identify accounts with new admin group membership
index=windows EventCode=4728 OR EventCode=4732
| table _time host SubjectUserName TargetUserName MemberName GroupName
```

### KQL (Kusto Query Language) — Microsoft Sentinel Production Queries

```kql
// Detect impossible travel (sign-ins from two geographies within 1 hour)
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location
| summarize Locations = make_list(Location), IPList = make_list(IPAddress), Times = make_list(TimeGenerated)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1 and Locations[0] != Locations[1]

// Alert on mass file deletion — ransomware indicator
DeviceFileEvents
| where ActionType == "FileDeleted"
| summarize DeletedCount = count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where DeletedCount > 100
| sort by DeletedCount desc

// Detect new local admin creation
SecurityEvent
| where EventID == 4732
| where TargetSid endswith "-544"  // Administrators group SID suffix
| project TimeGenerated, Computer, SubjectUserName, MemberName

// Hunt for LSASS memory access (credential dumping)
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "csrss.exe", "services.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

### EQL (Event Query Language) — Elastic Detection

```eql
// Detect parent process spoofing
process where event.type == "start"
  and process.parent.name == "winword.exe"
  and process.name in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")

// Detect credential access via registry
registry where registry.path like~ "*\\SAM\\*" or registry.path like~ "*\\SECURITY\\*"
  and not process.name in ("svchost.exe", "lsass.exe")
```

## SOAR Architecture and Design

### Playbook Anatomy
A well-designed SOAR playbook follows this lifecycle:

```
TRIGGER (SIEM Alert / Email / API)
    ↓
ENRICHMENT (VirusTotal, WHOIS, Shodan, Recorded Future, CrowdStrike TI)
    ↓
DECISION (Automated scoring: is this a true positive?)
    ↓
ACTION (Isolate endpoint / Block IP / Disable account / Create ticket)
    ↓
NOTIFICATION (Slack/Teams/Email to analyst or stakeholder)
    ↓
DOCUMENTATION (Auto-close with notes / Escalate to tier 2)
```

### Key Enrichment Sources
| Source | Data Provided | API |
|---|---|---|
| VirusTotal | File hash, IP, URL, domain reputation | Free (limited) + paid |
| Shodan | Host open ports, services, banners | Free (limited) + paid |
| AbuseIPDB | IP reputation, abuse reports | Free (limited) + paid |
| Recorded Future | Threat intel, threat actor context | Paid |
| MISP | Internal/community threat intel | Free, self-hosted |
| Cortex Analyzers | 100+ analyzers (passive DNS, sandboxing, etc.) | Free, self-hosted |
| GreyNoise | Internet background noise vs. targeted scanning | Free (limited) + paid |
| URLScan.io | URL/domain screenshot and analysis | Free API |

### Common SOAR Actions
| Action | Integration | Effect |
|---|---|---|
| Isolate endpoint | CrowdStrike / Defender / SentinelOne API | Removes host from network; preserves forensics |
| Block IP at firewall | Palo Alto / Fortinet / AWS NACL API | Drops traffic from malicious IP |
| Disable AD account | Microsoft Graph API / LDAP | Locks compromised account |
| Force MFA re-auth | Okta / Azure AD API | Revokes active sessions |
| Create JIRA/ServiceNow ticket | REST API | Tracks incident lifecycle |
| Send Slack/Teams alert | Webhook | Notifies analyst in real time |
| Collect forensic triage | EDR API (CS RTR, Defender LRS) | Pulls process list, netstat, autoruns |
| Add to threat intel | MISP API | Shares IOC with other tools |

## SOAR Platforms Comparison

| Platform | Type | Strengths |
|---|---|---|
| **Splunk SOAR (Phantom)** | Commercial | Largest app ecosystem (400+ integrations); Python playbooks; tight Splunk integration |
| **Palo Alto XSOAR (Demisto)** | Commercial | Content Hub with 700+ integrations; Case Management; MITRE ATT&CK mapping |
| **Microsoft Sentinel Automation** | Cloud-native | Native to Sentinel; Logic Apps-based; no separate product license |
| **Tines** | Commercial/Low-code | No-code/low-code; accessible for non-developers; fast playbook development |
| **Shuffle** | Open source | Free; Docker-based; REST API integrations; growing community |
| **TheHive + Cortex** | Open source | Free; strong incident case management; 100+ Cortex analyzers |

## Offensive Angle — SIEM/SOAR Evasion

Sophisticated attackers actively study and evade SIEM detection. Understanding these techniques is essential for detection engineers.

### Log Manipulation Techniques
- **Event Log Clearing**: `wevtutil cl Security` / `Clear-EventLog` — clears Windows event logs. **High confidence IOC** — SIEM should alert immediately on EventID 1102 (Security log cleared) and 104 (System log cleared). However, if SIEM is not real-time, clearing buys time
- **Timestomping**: Modify file $MTIME/$CTIME/$ATIME attributes to blend into normal activity. `Invoke-TimeStomp` or `touch -t` on Linux. **Mitigation**: Rely on SIEM ingest time, not file timestamps, for forensic timelines
- **Log Flooding**: Generate thousands of low-severity events (port scans, failed logins) to bury real alerts in noise. **Mitigation**: Dynamic threshold tuning; risk scoring to suppress known-noisy sources

### Detection Evasion Techniques
- **Living Off the Land (LOTL)**: Use legitimate OS binaries — `certutil`, `mshta`, `wscript`, `regsvr32`, `rundll32` — to execute payloads. Fewer signatures than custom malware. **Mitigation**: Process lineage analysis; parent-child relationship rules (Excel spawning PowerShell)
- **Slow and Low Attacks**: Stay below threshold-based detection rates — one failed login per 10 minutes instead of 100 in 60 seconds. **Mitigation**: Longer time-window correlation; UEBA behavioral baselines
- **Detection Blind Spots by Protocol**: Move laterally via protocols with poor SIEM coverage — WMI (`wmic` remote commands), DCOM, RDP `ShellBrowserWindow`. **Mitigation**: Enable verbose WMI and DCOM logging; correlate EventID 4688 with network connections
- **Obfuscated Commands**: Base64 encoding (`-EncodedCommand`), string concatenation, character substitution in PowerShell and cmd.exe. **Mitigation**: Script block logging (EventID 4104); AmsiScanBuffer hooks; command-line deobfuscation
- **SOAR Abuse via False Positives**: If SOAR automatically blocks IPs, attackers can trigger false positives to block legitimate infrastructure (defensive abuse). **Mitigation**: Human approval gates for high-impact SOAR actions

## NIST 800-53 Alignment

| Control | Family | SIEM/SOAR Relevance |
|---|---|---|
| AU-2 | Audit & Accountability | Determine events to audit; ensure all security-relevant events are logged to SIEM |
| AU-3 | Audit & Accountability | Audit record content; ensure logs contain sufficient detail for investigation (user, IP, timestamp, outcome) |
| AU-6 | Audit & Accountability | Audit review, analysis, and reporting; SIEM automates review and alerts on anomalies |
| AU-12 | Audit & Accountability | Audit record generation; ensure systems generate required audit records |
| SI-4 | System & Info Integrity | System monitoring; SIEM is the primary implementation of continuous monitoring |
| IR-4 | Incident Response | Incident handling; SOAR automates containment and response steps |
| CA-7 | Security Assessment | Continuous monitoring; SIEM feeds the continuous monitoring program |
| RA-5 | Risk Assessment | Vulnerability scanning; SIEM correlates scan findings with exploitation attempts |
| IR-5 | Incident Response | Incident monitoring; track and document incidents in SOAR case management |
| PM-16 | Program Management | Threat awareness program; SIEM/TI integration feeds threat awareness |

## ATT&CK Coverage

| Technique | ID | Detection Approach |
|---|---|---|
| Indicator Removal (Log Clearing) | T1070 | EventID 1102/104; monitor for `wevtutil`, `Clear-EventLog` commands |
| Impair Defenses | T1562 | Monitor for AV/EDR service stops; Event Log service manipulation |
| Masquerading | T1036 | Process name vs. path correlation; signed binary misuse detection |
| Obfuscated Files or Information | T1027 | Script block logging (EID 4104); detect encoded command-line arguments |
| Command and Scripting Interpreter | T1059 | PowerShell/WMI/cmd.exe spawned by unusual parents; script block logging |
| Application Layer Protocol | T1071 | Unusual process making DNS/HTTP connections; DGA detection |
| Exfiltration Over Alternative Protocol | T1048 | Large DNS query volumes; FTP/SCP/cloud storage uploads from servers |
| Process Injection | T1055 | OpenProcess calls to other process spaces; memory-resident shellcode |

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| **Splunk Core Certified User** | Splunk | Entry-level SPL and Splunk navigation |
| **Splunk Core Certified Power User** | Splunk | Intermediate SPL; advanced searches, dashboards |
| **Splunk Enterprise Certified Admin** | Splunk | Architecture, deployment, management |
| **Splunk Enterprise Security Certified Admin** | Splunk | ES-specific; correlation rules, threat intel |
| **Elastic Certified Analyst** | Elastic | ELK Stack, EQL, Elastic SIEM |
| **SC-200** (Microsoft Security Operations Analyst) | Microsoft | Microsoft Sentinel, Defender XDR |
| **GCIA** (GIAC Certified Intrusion Analyst) | GIAC/SANS | Deep packet analysis, IDS/SIEM |
| **BTL1** (Blue Team Labs Level 1) | Security Blue Team | Practical SOC analyst skills |
| **CySA+** | CompTIA | Cybersecurity analyst; SIEM/threat detection |
| **eCDFP** | eLearnSecurity | Digital forensics integrated with SIEM analysis |

## Learning Resources

| Resource | Type | Cost |
|---|---|---|
| [Splunk BOTS (Boss of the SOC) Dataset](https://bots.splunk.com/) | CTF / Hands-on | Free |
| [Splunk Free Training (Fundamentals 1)](https://www.splunk.com/en_us/training/free-courses/overview.html) | Course | Free |
| [Microsoft Sentinel Ninja Training](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/become-a-microsoft-sentinel-ninja-the-complete-level-400/ba-p/1246310) | Course series | Free |
| [Microsoft Sentinel GitHub](https://github.com/Azure/Azure-Sentinel) | Detection rules / playbooks | Free |
| [Sigma Rules GitHub](https://github.com/SigmaHQ/sigma) | Detection rule library | Free |
| [Elastic Detection Rules GitHub](https://github.com/elastic/detection-rules) | Detection rules | Free |
| [TryHackMe SOC Level 1](https://tryhackme.com/path/outline/soclevel1) | Guided labs | Paid (affordable) |
| [LetsDefend](https://letsdefend.io/) | SOC simulation | Free tier |
| [SANS SEC555: SIEM with Tactical Analytics](https://www.sans.org/cyber-security-courses/siem-with-tactical-analytics/) | Course | Paid |
| [The Practice of Network Security Monitoring (Bejtlich)](https://nostarch.com/nsm) | Book | Paid |
| [Applied Network Security Monitoring (Sanders & Smith)](https://www.oreilly.com/library/view/applied-network-security/9780124172081/) | Book | Paid |

## Related Disciplines

- [threat-hunting.md](threat-hunting.md)
- [incident-response.md](incident-response.md)
- [digital-forensics.md](digital-forensics.md)
- [threat-intelligence.md](threat-intelligence.md)
- [zero-trust-architecture.md](zero-trust-architecture.md)
- [network-security.md](network-security.md)
- [cloud-security.md](cloud-security.md)
