# Security Operations (SOC / SecOps)

Security Operations is the continuous practice of monitoring, detecting, analyzing, and responding to cybersecurity threats across an organization's environment. It is carried out by Security Operations Centers (SOCs) staffed by analysts working in tiered roles — from alert triage through advanced threat hunting and incident response. The discipline matters because prevention alone fails: sophisticated adversaries get through defenses, and the difference between a contained incident and a breach is how quickly the SOC detects, understands, and neutralizes the threat. SOC practitioners work with SIEM platforms, SOAR orchestration, endpoint telemetry, network logs, and threat intelligence feeds. The offensive perspective is equally critical: defenders must understand SOC evasion techniques — log flooding, timestomping, LOLBAS abuse, and living-off-the-land binaries — because adversaries specifically craft tradecraft to blind detection tooling. A mature SOC is built on the principle that attackers and defenders use the same tools; knowing how attackers evade detection is what makes detections resilient.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Learn the SOC analyst workflow, understand what a SIEM does, and practice alert triage on LetsDefend or Blue Team Labs Online. Study log formats (Windows Event IDs, syslog, auth logs). | [LetsDefend SOC Analyst Path](https://letsdefend.io/) |
| Intermediate | Build detection rules in Splunk or Elastic SIEM, map TTPs to MITRE ATT&CK, and complete Splunk Boss of the SOC (BOTS). Practice threat hunting using hypothesis-driven methodology. | [Splunk Boss of the SOC](https://bots.splunk.com/) |
| Advanced | Design SOAR playbooks, tune detections to reduce false positives, build a threat hunting program using ATT&CK-mapped analytics, and operate during live incident response exercises. | [Blue Team Labs Online](https://blueteamlabs.online/) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| LetsDefend | https://letsdefend.io/ | SOC analyst workflows, alert triage, SIEM analysis, incident handling |
| Blue Team Labs Online | https://blueteamlabs.online/ | Defensive security challenges, log analysis, DFIR labs |
| Splunk Boss of the SOC | https://bots.splunk.com/ | Splunk SIEM investigation, hunting, and detection in a CTF format |
| TryHackMe SOC Level 1 | https://tryhackme.com/path/outline/soclevel1 | Guided learning for Tier 1 SOC analyst skills |
| Elastic SIEM Lab | https://www.elastic.co/security-labs | Detection engineering with Elastic, tutorials and research |
| SANS Cyber Aces | https://www.sans.org/cyberaces/ | Foundational cybersecurity for analysts entering the field |
| Microsoft Learn: SC-200 | https://learn.microsoft.com/en-us/certifications/exams/sc-200 | Microsoft Sentinel, Defender, and security operations |

---

## SOC Analyst Tiers

| Tier | Role | Primary Responsibilities |
|---|---|---|
| Tier 1 | Alert Analyst | Monitor SIEM queue, triage alerts, classify true/false positives, escalate confirmed incidents |
| Tier 2 | Incident Responder | Deep investigation of escalated incidents, log correlation, containment actions, evidence collection |
| Tier 3 | Threat Hunter / Senior Analyst | Proactive threat hunting, detection rule development, adversary simulation review, root cause analysis |
| Lead / Manager | SOC Lead | SLA management, process improvement, team mentoring, executive reporting |

---

## SOC Models

| Model | Description | Best For |
|---|---|---|
| Internal SOC | Fully in-house team operating 24x7 | Large enterprises with mature security programs |
| MSSP (Managed Security Service Provider) | Outsourced monitoring and response to a third party | Organizations without staffing for 24x7 coverage |
| Hybrid SOC | Internal team handles business-hours; MSSP covers nights and weekends | Mid-size organizations balancing cost and control |
| Virtual SOC | Distributed team across time zones without a dedicated physical facility | Cloud-native and remote-first organizations |

---

## Tools & Repositories

### SIEM Platforms

| Tool | Purpose | Link |
|---|---|---|
| Splunk | Industry-leading SIEM and data analytics platform | https://www.splunk.com/ |
| Elastic SIEM (ELK Stack) | Open-source log aggregation, analysis, and detection | https://github.com/elastic/elasticsearch |
| Microsoft Sentinel | Cloud-native SIEM on Azure with SOAR integration | https://azure.microsoft.com/en-us/products/microsoft-sentinel |
| IBM QRadar | Enterprise SIEM with deep correlation and threat intelligence | https://www.ibm.com/products/qradar-siem |
| Graylog | Open-source log management and security analytics | https://github.com/Graylog2/graylog2-server |

### SOAR & Orchestration

| Tool | Purpose | Link |
|---|---|---|
| TheHive | Open-source incident response and case management platform | https://github.com/TheHive-Project/TheHive |
| Cortex | Automated analysis and active response with 100+ analyzers | https://github.com/TheHive-Project/Cortex |
| Shuffle | Open-source SOAR platform with workflow automation | https://github.com/Shuffle/Shuffle |
| MISP | Threat intelligence platform and IOC sharing | https://github.com/MISP/MISP |
| Velociraptor | Digital forensics and incident response at scale | https://github.com/Velocidex/velociraptor |

### Detection Engineering

| Tool | Purpose | Link |
|---|---|---|
| Sigma | Generic SIEM rule format — write once, deploy anywhere | https://github.com/SigmaHQ/sigma |
| YARA | Pattern matching for malware identification | https://github.com/VirusTotal/yara |
| Zeek | Network traffic analysis and protocol dissection | https://github.com/zeek/zeek |
| Suricata | High-performance IDS/IPS with rule-based detection | https://github.com/OISF/suricata |
| OSQuery | SQL-based endpoint telemetry and querying | https://github.com/osquery/osquery |

---

## Commercial Platforms

| Platform | Description |
|---|---|
| Splunk Enterprise Security | Premium SIEM with risk-based alerting, UBA, and SOAR integration |
| Microsoft Sentinel | Cloud-native SIEM/SOAR with native Microsoft 365 Defender integration |
| IBM QRadar SIEM | Enterprise-grade correlation engine with AI-assisted investigation |
| Palo Alto Cortex XSIAM | AI-driven SOC platform combining SIEM, SOAR, and XDR |
| CrowdStrike Falcon LogScale | Cloud-native log management and detection with petabyte-scale ingestion |
| Exabeam Fusion | SIEM with built-in UEBA (user and entity behavior analytics) |
| ServiceNow Security Operations | Ticketing, vulnerability response, and SOAR integrated with ITSM |
| Recorded Future | Threat intelligence platform with real-time actor and IOC enrichment |

---

## SIEM Fundamentals

A SIEM ingests logs from across the environment, normalizes them into a common schema, and applies correlation rules to surface suspicious activity:

1. **Log Ingestion** — Forward Windows Event Logs, syslog (Linux), DNS, proxy, firewall, EDR, and cloud logs to the SIEM
2. **Normalization** — Parse raw log formats into structured fields (timestamp, source IP, user, action, outcome)
3. **Correlation Rules** — Multi-event logic: "4 failed logins followed by a successful login from the same IP within 5 minutes"
4. **Alert Triage** — Analysts classify alerts as true positive (TP), false positive (FP), or benign true positive
5. **Enrichment** — Add context: IP reputation (VirusTotal, Shodan), user identity (AD), asset criticality
6. **Escalation** — Confirmed TPs become incidents; complex cases escalate from Tier 1 to Tier 2/3

---

## Alert Triage Process

| Step | Action |
|---|---|
| 1. Receive Alert | Pull alert from SIEM queue; note severity, rule name, affected assets |
| 2. Initial Review | Review raw log event; determine if the alert rule fired correctly |
| 3. Enrichment | Check IOCs (IP, hash, domain) against threat intel; query asset inventory |
| 4. Context Building | Pull related events (surrounding 15 minutes, same user/host); look for lateral movement |
| 5. Classification | True Positive: real threat. False Positive: benign activity triggering detection rule. |
| 6. Escalation or Close | TPs: open incident ticket and escalate to Tier 2. FPs: document and tune rule to reduce noise. |

---

## Threat Hunting

Threat hunting is the proactive, hypothesis-driven search for adversaries that have evaded automated detections:

- **Hypothesis-Driven** — Start with an ATT&CK technique: "Assume T1078 (Valid Accounts) — look for logins at unusual hours from new geolocations"
- **Data-Driven** — Analyze baseline behavior anomalies: "Find processes making outbound connections that have never done so before"
- **IOC-Driven** — Hunt for known indicators from threat intelligence feeds across historical logs
- **Hunt Tools**: Splunk SPL, Elastic EQL, KQL (Sentinel), OSQuery, Velociraptor VQL

---

## SOC Evasion: Offensive & Defensive Perspectives

| Evasion Technique | Offensive Implementation | Detection Approach |
|---|---|---|
| Log Flooding | Generate thousands of benign events to bury malicious ones in SIEM noise | Anomaly-based alerting on event volume spikes; rate-limit log sources |
| Timestomping | Modify file MAC times to make malware appear legitimate and old | Monitor $STANDARD_INFORMATION vs $FILE_NAME timestamp discrepancies (Windows NTFS) |
| LOLBAS Abuse | Use living-off-the-land binaries (certutil, mshta, regsvr32) to execute payloads | Behavioral detection on parent-child process chains; command-line argument analysis |
| Log Deletion / Tampering | Delete Windows Event Logs (Event ID 1102 / 104) or clear syslog | Alert on Event ID 1102 (audit log cleared), monitor for log gaps, use immutable log forwarding |
| Parent Process Spoofing | Spoof legitimate parent process (explorer.exe) to hide malicious child processes | Process tree integrity checks; compare reported vs actual parent PID |
| DNS Tunneling | Exfiltrate data via abnormally long DNS queries or high-frequency DNS to a single domain | Alert on DNS query length > 50 chars; entropy analysis on subdomain labels |
| Encrypted C2 | Use HTTPS or DNS-over-HTTPS for C2 to blend with normal traffic | JA3/JA3S fingerprinting; certificate transparency monitoring; beacon timing analysis |
| Living-off-the-Land (LOL) | Use PowerShell, WMI, or built-in admin tools to move laterally without dropping binaries | Script block logging (Event ID 4104); WMI activity logs; command-line argument telemetry |

---

## SOC Metrics

| Metric | Definition | Target |
|---|---|---|
| MTTD (Mean Time to Detect) | Average time from compromise to detection | Less than 24 hours for high-severity |
| MTTR (Mean Time to Respond) | Average time from detection to containment | Less than 4 hours for critical incidents |
| Alert-to-Incident Ratio | Percentage of alerts that become real incidents | Varies; track trend to measure tuning effectiveness |
| False Positive Rate | Percentage of alerts that are benign | Under 30% for well-tuned detections |
| SLA Compliance | Percentage of alerts triaged within SLA window | Over 95% for Tier 1 queue |
| Dwell Time | Time adversary was present before detection | Minimize; industry average historically over 200 days |

---

## SOAR Playbook Design

A SOAR playbook automates repetitive analyst tasks triggered by specific alert types:

**Example: Phishing Triage Playbook**
1. Trigger: Email security alert on suspicious message
2. Extract IOCs: sender domain, URLs, attachment hashes
3. Enrich: Query VirusTotal API for URL and hash reputation
4. Check: Has the recipient clicked the link? (proxy logs)
5. Decision: If VT score > 50 and link clicked → isolate endpoint, block domain, open P1 incident
6. Notify: Alert Tier 2 via Slack/Teams; auto-create ServiceNow or Jira ticket

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| IR-4 | Incident Handling | SOC incident response processes directly implement IR-4 detection and containment requirements |
| IR-5 | Incident Monitoring | SIEM correlation and alerting provide the continuous monitoring required by IR-5 |
| IR-6 | Incident Reporting | SOC escalation paths and ticketing fulfill IR-6 reporting to stakeholders |
| AU-6 | Audit Record Review, Analysis, and Reporting | Alert triage and log analysis implement AU-6 audit review requirements |
| SI-4 | System Monitoring | SIEM, IDS/IPS, and EDR telemetry implement SI-4 information system monitoring |
| RA-5 | Vulnerability Monitoring and Scanning | SOC integrates vulnerability scan results into risk prioritization |
| IR-8 | Incident Response Plan | SOC runbooks and playbooks implement and exercise the IR plan |
| AU-12 | Audit Record Generation | Ensuring log sources generate the records that the SOC depends on |
| CM-6 | Configuration Settings | Baseline configurations enable anomaly detection when deviations occur |
| SI-3 | Malicious Code Protection | EDR and AV telemetry fed into the SIEM for correlation with other indicators |

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| T1070 | Indicator Removal | Defense Evasion | Log deletion and timestomping that SOC must detect via integrity monitoring |
| T1562 | Impair Defenses | Defense Evasion | Disabling logging, AV, or EDR agents; SOC must alert on agent health status |
| T1036 | Masquerading | Defense Evasion | LOLBAS and renamed binaries detected via process signature and path analysis |
| T1055 | Process Injection | Privilege Escalation | Injected code in legitimate processes detected via memory anomaly analysis |
| T1059 | Command and Scripting Interpreter | Execution | PowerShell, WMI, and scripting engine abuse detected via script block logging |
| T1003 | OS Credential Dumping | Credential Access | LSASS access alerts, Mimikatz signatures, and EDR credential dump detections |
| T1021 | Remote Services | Lateral Movement | Anomalous RDP, WinRM, and SMB connections between hosts in the environment |
| T1078 | Valid Accounts | Defense Evasion / Persistence | Behavioral analytics detecting legitimate credentials used anomalously |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| CompTIA CySA+ | CompTIA | Cybersecurity analyst skills including SIEM, threat hunting, and incident response |
| GCIA (GIAC Certified Intrusion Analyst) | GIAC | Network traffic analysis, IDS, and intrusion detection |
| GCIH (GIAC Certified Incident Handler) | GIAC | Incident response methodology, handling, and remediation |
| GCFE (GIAC Certified Forensic Examiner) | GIAC | Windows forensics and evidence analysis for SOC investigations |
| Splunk Core Certified User | Splunk | Splunk search, dashboards, and data analysis fundamentals |
| SC-200 (Security Operations Analyst) | Microsoft | Microsoft Sentinel, Defender XDR, and Azure security operations |
| BTL1 (Blue Team Labs Level 1) | Security Blue Team | Practical SOC analyst skills in a hands-on lab environment |
| SANS FOR508 / GCFA | GIAC | Advanced incident response and digital forensics |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [LetsDefend](https://letsdefend.io/) | Free platform | SOC analyst simulation with realistic alert queues and investigations |
| [Blue Team Labs Online](https://blueteamlabs.online/) | Free / paid | Defensive security challenges across SIEM, forensics, and malware analysis |
| [Splunk Boss of the SOC](https://bots.splunk.com/) | Free CTF | Splunk-based investigation CTF with real attack data sets |
| [TryHackMe SOC Level 1](https://tryhackme.com/path/outline/soclevel1) | Guided path | Structured Tier 1 SOC analyst curriculum with hands-on labs |
| [SANS FOR508: Advanced Incident Response](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/) | Paid course | Gold standard for enterprise incident response and threat hunting |
| [The Practice of Network Security Monitoring — Richard Bejtlich](https://nostarch.com/nsm) | Book | Foundational reference for NSM methodology and SOC workflows |
| [Blue Team Handbook — Don Murdoch](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1726273989) | Book | Quick-reference SOC playbook for incident response and triage |
| [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | Free tool | Visualize detection coverage against ATT&CK techniques |
| [Sigma Rules Repository](https://github.com/SigmaHQ/sigma) | Free | Community SIEM detection rules mapped to ATT&CK techniques |
| [Elastic Detection Rules](https://github.com/elastic/detection-rules) | Free | Production-ready Elastic SIEM rules with ATT&CK mappings |

---


## SOC Tiers and Responsibilities

### SOC Tier Model

| Tier | Role | Responsibilities | Tools | Escalation |
|---|---|---|---|---|
| Tier 1 (Alert Analyst) | Monitor, triage, basic investigation | Review SIEM alerts; close false positives; escalate true positives; collect initial evidence | SIEM dashboard, ticketing system | Escalate after 15-30 min if unclear |
| Tier 2 (Incident Responder) | Deep investigation, containment | Full incident investigation; threat hunting; malware analysis basics; containment recommendations | EDR, SOAR, sandboxes, forensic tools | Escalate critical/advanced threats to T3 |
| Tier 3 (Threat Hunter / SME) | Proactive hunting, advanced IR | Hypothesis-based hunting; reverse engineering; custom detection creation; threat intel correlation | Memory forensics tools, Volatility, custom analytics | Brief leadership; drive resolution |
| SOC Manager | Operations management | Metrics, staffing, process improvement, escalation coordination, regulatory reporting | All platforms + dashboards | Brief CISO; initiate war room if needed |

### SOC Metrics (KPIs)

| Metric | Target | Why It Matters |
|---|---|---|
| MTTD (Mean Time to Detect) | <24 hours | Industry avg 197 days; every hour matters |
| MTTR (Mean Time to Respond/Resolve) | <72 hours | How fast are we containing and recovering? |
| Alert volume per analyst per day | 20-30 actionable alerts | More than this = analyst fatigue; tuning needed |
| False positive rate | <20% | High FPR = alert fatigue; missed detections |
| Escalation accuracy rate | >85% | T1 calling T2 unnecessarily = wasted senior time |
| Ticket closure within SLA | >95% | Process discipline |
| Detection coverage (ATT&CK %) | Track & improve | How many techniques do we detect? |
| Phishing simulation response time | <30 minutes to report | Measures security culture |

---

## SIEM Operations

### Alert Triage Workflow

1. Alert fires → T1 analyst receives in queue
2. Context enrichment: Lookup user in HR/CMDB; lookup IP in threat intel; check asset criticality
3. Initial determination: True positive / false positive / needs investigation
4. If TP or unclear: Create incident ticket; collect evidence (logs, memory, artifacts)
5. Escalate to T2 if: Activity ongoing, privileged account involved, multiple systems, unknown malware
6. T2 investigates → contains → documents → hands to T3 if APT-level
7. Post-incident: Update detection rules to reduce FP or improve TP capture

### Splunk SPL for SOC Operations

```spl
# Alert queue management - incidents by severity last 24h
index=security sourcetype=alert severity IN (high critical)
| timechart span=1h count by severity

# Analyst workload distribution
index=ticketing status=open
| stats count by assigned_analyst
| sort -count

# Top alert sources (tune noisiest detections)
index=security sourcetype=alert
| stats count by alert_name
| sort -count
| head 20

# Mean time to acknowledge (MTTA) calculation
index=ticketing
| eval acknowledge_time = (first_acknowledged - created) / 3600
| stats avg(acknowledge_time) as MTTA_hours by severity
```

### SOAR Platform Comparison

| Platform | Parent | Strength | Pricing |
|---|---|---|---|
| Splunk SOAR (Phantom) | Splunk | Largest playbook library; strong Splunk integration | Commercial |
| Palo Alto XSOAR (Demisto) | Palo Alto | Most mature; many integrations; complex | Commercial |
| Microsoft Sentinel Automation | Microsoft | Native with Sentinel; Logic Apps based; no-code | Included with Sentinel |
| Tines | Independent | Modern; no-code/low-code; developer-friendly | Commercial (startup pricing) |
| Shuffle | OSS | Open-source; 400+ apps; self-hosted | Free (OSS) |
| TheHive | OSS | Case management + MISP integration; collaborative | Free (OSS) |
| Cortex | OSS | Complement to TheHive; observable analysis automation | Free (OSS) |

---

## Threat Intelligence Operations

### Intel Lifecycle in the SOC

- Strategic: Brief leadership on threat landscape; inform security program investment
- Operational: Track active campaigns targeting your sector; IOC watchlists in SIEM
- Tactical: Real-time IOC feeds → SIEM correlation rules; block lists for firewall/proxy

### Intel Platforms

| Platform | Type | Key Feature |
|---|---|---|
| MISP | OSS | Structured sharing; ATT&CK tagging; STIX/TAXII; self-hosted |
| OpenCTI | OSS | Graph-based; STIX 2.1; Elasticsearch backend; free |
| Recorded Future | Commercial | Machine speed threat intel; browser plugin; SIEM integration |
| Mandiant Advantage | Commercial | APT tracking; actor profiles; malware intel |
| ThreatConnect | Commercial | Risk scoring; team workflow; STIX/TAXII |
| Anomali | Commercial | ThreatStream; IOC management; integration platform |
| AlienVault OTX | Free/Commercial | Community threat intel; STIX/TAXII export; AT&T owned |

### Threat Intel Feed Integration

```python
# MISP push to Splunk (conceptual)
import pymisp
misp = pymisp.ExpandedPyMISP(url="https://misp.internal", key="API_KEY", ssl=True)
events = misp.search(tags="tlp:white", type_attribute="ip-dst", to_ids=True, last="1d")
for event in events:
    for attribute in event.attributes:
        # Push to Splunk lookup table
        print(f"{attribute.value},{attribute.type},{event.info}")
```

---

## Related Disciplines

- [Detection Engineering](detection-engineering.md)
- [Incident Response](incident-response.md)
- [Threat Intelligence](threat-intelligence.md)
- [Digital Forensics](digital-forensics.md)
- [Offensive Security](offensive-security.md)
- [DevSecOps](devsecops.md)
- [Vulnerability Management](vulnerability-management.md)
