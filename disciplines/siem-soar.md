# SIEM and SOAR

SIEM (Security Information and Event Management) provides centralized log collection, correlation, and alerting across an organization's environment. SOAR (Security Orchestration, Automation and Response) adds automated playbook execution and structured case management on top of that data. Together they form the operational backbone of the modern Security Operations Center: SIEM tells you what happened, SOAR decides what to do about it. A mature program integrates both tightly — SIEM detections fire directly into SOAR playbooks, reducing mean time to respond (MTTR) from hours to minutes without requiring analyst intervention for routine cases.

The gap between a functional SIEM and a mature one is almost always data quality and coverage, not the platform itself. Before optimizing detection logic, ensure your log sources are complete, your parsing is correct, and your normalization is consistent. Garbage in, garbage in.

---

## Where to Start

Begin with one SIEM platform and one set of log sources rather than trying to ingest everything at once. Windows Security Events and Sysmon on endpoints give you more detection coverage per dollar than almost any other investment. From there, add network telemetry, then authentication logs, then cloud. Learn the query language for your platform deeply before writing complex detection rules.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | SIEM architecture, Windows Security Event IDs, Sysmon telemetry, basic SPL or KQL queries, log normalization | TryHackMe SOC paths, HTB Academy SOC Analyst path, Splunk free trial, Microsoft Sentinel free trial (free tier) |
| Practitioner | Correlation rule authoring, use case development, SOAR playbook design, tuning false positives, log source onboarding | Splunk Security Essentials app, Microsoft Sentinel content hub, TheHive + Shuffle lab builds |
| Advanced | UEBA, ML-based detection, detection-as-code integration, multi-tenant SOAR, threat intel enrichment pipelines, SOC metrics | Elastic detection-rules repo, Splunk ES Risk-Based Alerting, Palo Alto XSOAR marketplace, SANS SEC555 |

---

## SIEM Architecture

A SIEM pipeline has five conceptual layers. Understanding each helps diagnose gaps and performance bottlenecks before they become operational problems.

**Data Sources** — Everything that generates security-relevant logs: endpoints (Sysmon, Windows Event Log, Auditd), network (Zeek, Suricata, NetFlow/IPFIX), authentication (Active Directory, Okta, Azure AD / Entra ID), cloud (CloudTrail, Azure Monitor, GCP Audit Log), and applications (web servers, databases, custom apps).

**Ingestion** — The transport layer: agents (Beats, Universal Forwarder, Logstash), syslog (UDP/TCP/TLS), API pulls from cloud services, and streaming pipelines (Kafka, Azure Event Hub) for high-volume sources.

**Processing** — Parsing raw log text into structured fields, normalizing field names across sources (user vs. username vs. account_name), and enriching events with GeoIP lookups, threat intelligence context, and asset inventory data.

**Storage** — Tiered by age and query frequency: hot storage (fast SSD, last 7–30 days, full query performance), warm storage (slower, last 90 days, acceptable query speed), cold/archive (object storage or tape, compliance retention, slow or offline retrieval). Retention requirements are driven by compliance frameworks (PCI: 1 year, HIPAA: 6 years, GDPR: varies).

**Correlation and Visualization** — Rule-based alerting (threshold, aggregation, sequence), statistical anomaly detection, ML/UEBA for behavioral baselines, plus dashboards, ad-hoc search, and threat hunting interfaces.

---

## Major SIEM Platforms

| Platform | Type | Query Language | Best For |
|---|---|---|---|
| **Splunk Enterprise / Cloud** | Commercial | SPL (Search Processing Language) | Large enterprise, rich ecosystem, Risk-Based Alerting |
| **Microsoft Sentinel** | SaaS | KQL (Kusto Query Language) | Microsoft-heavy environments, Azure-native, cost-effective |
| **Elastic Security** | Open source + commercial | EQL, KQL, Lucene | Flexible deployment, open source option, strong EDR integration |
| **IBM QRadar** | Commercial | AQL (Ariel Query Language) | Large enterprise, regulated industries, legacy environments |
| **Securonix** | Commercial + SaaS | SNYPR / Spark SQL | UEBA-heavy, ML-centric, high-noise environments |
| **LogRhythm SIEM** | Commercial | — | Mid-market, integrated SIEM + SOAR |
| **Sumo Logic** | SaaS | — | Cloud-native focus, DevOps-friendly |
| **Graylog** | Open source + commercial | — | SMB, simple deployment, structured log focus |
| **OSSIM (AlienVault)** | Open source | — | Resource-limited environments, OTX threat intel integration |
| **Wazuh** | Open source | — | Endpoint-focused, FIM, vulnerability detection, regulatory compliance |

---

## SPL (Splunk) Fundamentals

SPL (Search Processing Language) is Splunk's query language. Searches are pipelines: each command receives the output of the previous command. Start with an index filter and source filter, then chain transformations.

**Core commands:**

| Command | Purpose | Example |
|---|---|---|
| `index=` / `sourcetype=` | Specify data source | `index=windows sourcetype=WinEventLog` |
| `stats count by field` | Aggregate and group | `stats count by Account_Name, src_ip` |
| `eval` | Field calculations and conditionals | `eval result=if(status="fail","blocked","allowed")` |
| `rex` | Regex field extraction | `rex field=_raw "User:\s+(?<username>\S+)"` |
| `transaction` | Correlate events sharing a field | `transaction src_ip maxspan=5m` |
| `join` | Join two search results | `join src_ip [search index=threat_intel]` |
| `lookup` | Enrich with external data | `lookup ip_reputation src_ip OUTPUT verdict` |
| `timechart` | Time-series visualization | `timechart count by EventCode` |

**Detection examples:**

Failed logon brute force:
```spl
index=windows EventCode=4625
| stats count by Account_Name, src_ip
| where count > 10
| sort -count
```

New local administrator added:
```spl
index=windows EventCode=4732 Group_Name="Administrators"
| table _time, ComputerName, Account_Name, MemberName
```

PowerShell encoded command execution:
```spl
index=windows EventCode=4688 CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
| table _time, ComputerName, user, CommandLine
```

Scheduled task creation:
```spl
index=windows EventCode=4698
| table _time, ComputerName, SubjectUserName, TaskName, TaskContent
```

Service installation (common persistence):
```spl
index=windows EventCode=7045
| table _time, ComputerName, ServiceName, ServiceFileName, ServiceType
```

---

## KQL (Microsoft Sentinel) Fundamentals

KQL (Kusto Query Language) powers Microsoft Sentinel (and Azure Monitor, Defender XDR). It is strongly typed and optimized for columnar analytics. Queries read top-to-bottom, piping results through operators with `|`.

**Core operators:**

| Operator | Purpose | Example |
|---|---|---|
| `where` | Filter rows | `where EventID == 4625` |
| `project` | Select columns | `project TimeGenerated, Account, IpAddress` |
| `summarize` | Aggregate | `summarize count() by Account` |
| `join kind=inner` | Join tables | `join kind=inner (OtherTable) on $left.Account == $right.User` |
| `extend` | Add computed column | `extend hour=bin(TimeGenerated, 1h)` |
| `parse` | Extract fields with pattern | `parse CommandLine with * "-enc " encoded_payload` |
| `mv-expand` | Expand dynamic arrays | `mv-expand TargetResources` |
| `ago()` | Relative time filter | `where TimeGenerated > ago(24h)` |

**Detection examples:**

Impossible travel (multiple locations within one hour):
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 0
| summarize locations=make_set(Location), count() by UserPrincipalName
| where array_length(locations) > 1
```

PowerShell encoded command:
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has "-enc" or CommandLine has "-EncodedCommand"
| project TimeGenerated, Computer, Account, CommandLine
```

New member added to privileged role:
```kql
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].displayName has "Admin"
| project TimeGenerated, InitiatedBy, TargetResources
```

Anomalous sign-in volume (baseline comparison):
```kql
let baseline = SigninLogs
    | where TimeGenerated between (ago(14d) .. ago(1d))
    | summarize avg_count=count()/13 by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d)
| summarize today_count=count() by UserPrincipalName
| join kind=inner baseline on UserPrincipalName
| where today_count > avg_count * 3
```

---

## SOAR Platforms

| Platform | Type | Key Features | Integration Ecosystem |
|---|---|---|---|
| **Splunk SOAR (Phantom)** | Commercial | Case management, visual playbook builder, App Hub | 350+ integrations |
| **Palo Alto XSOAR (Cortex)** | Commercial | Multi-tenancy, marketplace, War Room collaboration | 700+ integrations |
| **Microsoft Sentinel (built-in)** | SaaS | Logic Apps-based automation, native Azure | Native Microsoft 365 and Azure ecosystem |
| **IBM Resilient** | Commercial | Incident management focus, dynamic playbooks | SOAR-centric, enterprise |
| **Swimlane** | Commercial | Low-code builder, SPM (Security Performance Management) | Flexible, API-driven |
| **TheHive Project** | Open source | Case management + Cortex for automated analysis | Community integrations, REST API |
| **Shuffle SOAR** | Open source | n8n-style workflow builder, Docker-based | REST API native, extensible |
| **Tines** | SaaS | No-code, engineer-friendly, Story builder | Broad REST API coverage |

---

## SOAR Playbook Design

Effective playbooks automate repetitive analyst work at scale without removing human judgment from high-stakes decisions. Every playbook should have a documented trigger condition, defined escalation path, and clear close criteria.

**Playbook lifecycle:**

```
Trigger → Triage → Enrichment → Decision → Response → Close
```

**Common playbook patterns:**

**1. Phishing triage**
Email security alert fires → extract sender, URLs, attachment hashes → query VirusTotal and URLScan for IOCs → sandbox URLs and attachments → if malicious: purge from all mailboxes, block sender domain at gateway, create incident, notify affected user via OOB channel → close with IOC summary.

**2. Malware alert response**
EDR behavioral alert fires → query asset inventory for host criticality → if high criticality: isolate host via EDR API → pull process tree and memory strings → submit hash to threat intel → if confirmed malware: escalate to IR team, create P1 incident → if low confidence: notify analyst for manual review.

**3. Account compromise**
Suspicious MFA push or sign-in alert fires → pull sign-in logs for user (last 24h) → check for impossible travel or new geolocation → revoke all active sessions via IdP API → force password reset → notify user via OOB channel (SMS or secondary email) → create case, assign to Tier 2.

**4. Brute force / password spray**
Ten or more EventCode 4625 events from single source IP within 5 minutes → check IP against threat intel and known scanner lists → if external: block IP at perimeter firewall via API → create ticket → notify analyst with full event context → if internal: alert on workstation, escalate immediately.

**Playbook design principles:**
- Keep decision branches binary where possible — reduces playbook complexity and audit trail confusion
- Always create a case/ticket even for auto-closed alerts — maintain full audit trail
- Build in a human escalation path for every automated response action
- Log every action taken by the playbook with timestamp and rationale
- Test playbooks against simulated alerts before enabling on production detections

---

## Log Source Checklist

Prioritize log sources by detection value per ingestion cost. Endpoint and authentication logs deliver the most coverage for the most common attack patterns.

| Category | Sources | Key Event IDs / Fields |
|---|---|---|
| **Windows Security** | Windows Event Log (Security channel) | 4624/4625 (logon/fail), 4648 (explicit cred), 4688 (process create), 4698 (scheduled task), 4720 (account create), 4732 (group add), 7045 (service install) |
| **Sysmon** | Microsoft Sysinternals Sysmon | EID 1 (process), 3 (network), 7 (image load), 8 (remote thread), 11 (file create), 12/13 (registry), 17/18 (named pipe), 22 (DNS query), 23 (file delete) |
| **PowerShell** | PowerShell operational log | 4103 (module logging), 4104 (script block logging — enable this) |
| **DNS** | Zeek dns.log or Windows DNS debug log | Query, response, NXDOMAIN ratio, high-volume domains |
| **Network flows** | NetFlow/IPFIX or Zeek conn.log | Source/dest IP/port, bytes transferred, duration, protocol |
| **Web proxy** | Squid, Bluecoat, Zscaler logs | URL, user agent, category, bytes, response code |
| **Email gateway** | Proofpoint, Mimecast, Defender for O365 | Sender, recipient, attachments, links, disposition |
| **Authentication** | Okta, Entra ID, Duo | Sign-in success/fail, MFA result, location, device |
| **Cloud** | AWS CloudTrail, Azure Activity Log, GCP Audit Log | API calls, resource changes, IAM modifications, data access |
| **EDR telemetry** | CrowdStrike, SentinelOne API | Process trees, network connections, file writes, behavioral detections |

---

## Free Training

- [TryHackMe SOC Level 1 and Level 2 Paths](https://tryhackme.com) — Structured browser-based labs covering Windows Event Logs, Splunk, Zeek, Snort, and SIEM fundamentals; no local setup required; the most accessible starting point for SIEM skills
- [Hack The Box Academy SOC Analyst Path](https://academy.hackthebox.com) — Free Student tier covering Windows/Linux log analysis, SIEM fundamentals, IDS/IPS, and network traffic analysis with hands-on lab environments
- [Splunk Security Essentials App](https://splunkbase.splunk.com/app/3435) — Free Splunk app containing 200+ detections mapped to ATT&CK with full explanations; the best reference for what production SIEM detection content looks like
- [Microsoft Sentinel Ninja Training](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/become-a-microsoft-sentinel-ninja-the-complete-level-400/ba-p/1246310) — Microsoft's free 400-level Sentinel training covering KQL, analytics rules, playbooks, and workbooks; levels 100 through 400
- [Microsoft KQL for Beginners](https://github.com/rod-trent/MustLearnKQL) — Rod Trent's free "Must Learn KQL" series covering Kusto from syntax basics to advanced detection patterns; best KQL-specific free resource
- [Elastic SIEM documentation and detection rules](https://github.com/elastic/detection-rules) — Elastic's production detection rules with full EQL examples and documentation; free reference regardless of which SIEM you use
- [LetsDefend](https://letsdefend.io) — Free SOC simulator for practicing SIEM alert triage, investigation workflows, and incident handling in a realistic platform
- [Blue Team Labs Online](https://blueteamlabs.online) — Free detection and forensics challenges covering log analysis, SIEM investigation, and threat hunting scenarios
- [BHIS SOC Core Skills Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts from John Strand covering SIEM methodology, log analysis, and SOC workflow fundamentals
- [Shuffle SOAR documentation and community](https://shuffler.io/docs) — Free open-source SOAR platform documentation; the fastest way to build and test SOAR playbooks without commercial licensing

---

## Tools and Repositories

### SIEM and Log Analysis
- [elastic/detection-rules](https://github.com/elastic/detection-rules) — Elastic's production detection rules covering EQL and KQL patterns; high-quality reference for detection logic regardless of platform
- [splunk/security_content](https://github.com/splunk/security_content) — Splunk Threat Research Team detection content with ATT&CK mappings, SPL queries, and data source requirements
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — Universal detection rule format convertible to SPL, KQL, EQL, AQL, and 30+ other targets; write detections once and deploy anywhere
- [OTRF/OSSEM](https://github.com/OTRF/OSSEM) — Open Source Security Events Metadata; standardized event schemas for normalizing log sources across SIEM platforms
- [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) — Pre-recorded adversary simulation telemetry for building and testing SIEM detections without running live attacks
- [microsoft/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) — Microsoft Sentinel community detections, workbooks, and playbooks; the largest single source of KQL detection examples

### SOAR and Automation
- [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) — Open source incident response platform and case management system; pairs with Cortex for automated IOC analysis
- [TheHive-Project/Cortex](https://github.com/TheHive-Project/Cortex) — Automated analysis engine for TheHive; runs analyzers and responders against observables (IPs, hashes, URLs, emails)
- [Shuffle/Shuffle](https://github.com/Shuffle/Shuffle) — Open source SOAR with a visual workflow builder; easiest path to self-hosted SOAR for labs and small environments
- [demisto/content](https://github.com/demisto/content) — Palo Alto XSOAR community content; 700+ integrations, playbooks, and scripts; best reference for enterprise SOAR playbook design

### Log Collection and Enrichment
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — The most widely deployed Sysmon configuration; tuned for maximum visibility with controlled noise
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) — Modular Sysmon configuration for selective collection and easier tuning in production environments
- [stamparm/maltrail](https://github.com/stamparm/maltrail) — Malicious traffic detection and threat intelligence feed aggregator; useful for enriching SIEM network events with reputation data

---

## Common SIEM and SOAR Certifications

| Certification | Platform | Provider |
|---|---|---|
| Splunk Core Certified User | Splunk | Splunk |
| Splunk Core Certified Power User | Splunk | Splunk |
| Splunk Enterprise Certified Admin | Splunk | Splunk |
| Splunk Certified Cybersecurity Defense Analyst | Splunk | Splunk |
| SC-200: Microsoft Security Operations Analyst | Microsoft Sentinel | Microsoft |
| Elastic Certified SIEM Professional | Elastic Security | Elastic |
| HTB CDSA (Certified Defensive Security Analyst) | Elastic / Wazuh | Hack The Box |

---

## Related Disciplines

- [Detection Engineering](disciplines/detection-engineering.md) — Detection logic authoring, Sigma, rule validation, and detection-as-code pipelines that feed SIEM platforms
- [Security Operations](disciplines/security-operations.md) — SOC structure, analyst workflows, and the operational context in which SIEM and SOAR are used daily
- [Threat Hunting](disciplines/threat-hunting.md) — Proactive hypothesis-driven hunting using SIEM data beyond what automated alerting surfaces
- [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) — Quick-reference index of detection rules and event IDs used across the curriculum
