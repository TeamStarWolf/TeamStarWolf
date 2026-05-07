# SIEM Reference Library

> **Professional Cybersecurity Reference** | SIEM · Detection Engineering · SOC Operations · Threat Hunting

---

## Table of Contents

1. [SIEM Fundamentals](#1-siem-fundamentals)
2. [Splunk Enterprise Security](#2-splunk-enterprise-security)
3. [Microsoft Sentinel](#3-microsoft-sentinel)
4. [IBM QRadar](#4-ibm-qradar)
5. [Elastic SIEM & Open Source](#5-elastic-siem--open-source)
6. [Log Collection & Normalization](#6-log-collection--normalization)
7. [Detection Engineering](#7-detection-engineering)
8. [SOC Operations & Triage](#8-soc-operations--triage)
9. [Threat Hunting with SIEM](#9-threat-hunting-with-siem)
10. [SIEM Performance, Tuning & Operations](#10-siem-performance-tuning--operations)

---

## 1. SIEM Fundamentals

### Core Functions

| Function | Description |
|---|---|
| **Log Aggregation** | Collect events from heterogeneous sources (firewalls, endpoints, cloud, apps) into a central repository |
| **Normalization** | Map vendor-specific fields to a common schema (CEF, ECS, CIM) enabling cross-source correlation |
| **Correlation** | Apply logic rules across multiple events/sources to detect multi-step attack patterns |
| **Alerting** | Generate actionable notifications when correlation rules or ML thresholds are met |
| **Dashboards** | Real-time visualizations of security posture, alert queues, and KPIs |
| **Reporting** | Scheduled and on-demand compliance and executive reports (PCI DSS, HIPAA, SOX, ISO 27001) |
| **Retention** | Policy-driven log storage with tiered hot/warm/cold lifecycle management |
| **Compliance** | Demonstrate audit trails, access logs, and policy enforcement for regulatory frameworks |

### SIEM vs SOAR vs XDR vs MDR

| Platform | Primary Function | Key Differentiator |
|---|---|---|
| **SIEM** | Log aggregation, correlation, alerting | Centralized visibility across all log sources; compliance reporting |
| **SOAR** | Orchestration and automated response | Playbook-driven automation; integrates with 300+ tools; reduces MTTR |
| **XDR** | Cross-layer detection and response | Native integration across endpoint+network+cloud+email; vendor-managed detections |
| **MDR** | Managed detection and response service | 24/7 SOC-as-a-service; human analysts + tooling delivered as a subscription |

### Architecture Components

```
[Data Sources]
  Endpoints (Windows/Linux/Mac) -> Universal/Heavy Forwarders / Agents
  Network Devices (firewall/switch/router) -> Syslog / SNMP / API
  Cloud Services (AWS/Azure/GCP) -> API connectors / EventBridge / Pub/Sub
  Applications (web/RDBMS/IAM) -> JSON webhooks / JDBC / REST polling
       |
[Collection & Parsing Layer]
  Log Collectors -> Protocol normalization -> Field extraction -> Schema mapping
       |
[Indexing & Storage]
  Hot tier (SSD, fast search) -> Warm tier (HDD, indexed) -> Cold tier (object storage)
       |
[Correlation Engine]
  Rule evaluation -> Threshold detection -> ML anomaly scoring -> Alert generation
       |
[Analytics & Search]
  Interactive ad-hoc search -> Saved searches -> Reports -> Scheduled alerts
       |
[Presentation]
  Dashboards -> Case Management -> SOAR integration -> API export
```

### Deployment Models

| Model | Pros | Cons | Best For |
|---|---|---|---|
| **On-Premises** | Full data sovereignty; no egress costs; air-gap capable | High CapEx; maintenance burden; scaling complexity | Regulated industries; classified environments |
| **Cloud-Native** | Elastic scaling; auto-updates; no hardware | Data residency concerns; egress costs; internet dependency | SaaS-first orgs; fast deployment needs |
| **SaaS** | Zero infrastructure; subscription pricing | Limited customization; shared tenancy risks | SMBs; limited security staff |
| **Hybrid** | On-prem sensitive data + cloud burst capacity | Complex data routing; dual-management overhead | Large enterprises with mixed requirements |

### Capacity Planning

**EPS (Events Per Second) Calculation:**
```
Total EPS = Sum(source_count x avg_eps_per_source)

Typical EPS estimates:
  Domain Controller     : 500-2,000 EPS
  Windows endpoint      : 5-50 EPS (with Sysmon: 50-200 EPS)
  Firewall (enterprise) : 1,000-10,000 EPS
  Web proxy             : 200-2,000 EPS
  Linux server          : 10-100 EPS
  Cloud (AWS CloudTrail): 20-500 EPS per account
```

**GB/Day Sizing:**
```
GB/day = (EPS x avg_event_size_bytes x 86400) / 1,073,741,824
Compression ratio: raw / 6-10x (typical gzip compression)
Rule of thumb: 1,000 EPS ~ 50-150 GB/day uncompressed
```

**Storage Tiering:**
| Tier | Duration | Storage Type | Use Case |
|---|---|---|---|
| **Hot** | 0-90 days | NVMe/SSD | Active investigation, real-time search |
| **Warm** | 91-365 days | SAS HDD / cloud standard | Incident review, compliance queries |
| **Cold** | 1-7 years | Object storage (S3/Blob/GCS) | Legal hold, regulatory audit, forensics |

### Vendor Landscape

| Vendor | Product | Licensing Model | Strengths |
|---|---|---|---|
| **Splunk** | Enterprise Security | GB/day ingested | Ecosystem depth; SPL power; app marketplace |
| **Microsoft** | Sentinel | GB/day ingested | Azure-native; free Microsoft 365 connector |
| **IBM** | QRadar | EPS + flow rate | Network visibility; offense management |
| **Elastic** | Security / SIEM | Endpoint count or GB | Open ecosystem; EQL; free tier available |
| **Exabeam** | Fusion SIEM | User/entity count | UEBA-first; timeline-based investigation |
| **LogRhythm** | SIEM | EPS | Strong compliance reporting; NDDR included |
| **ArcSight** | ESM / Recon | EPS | Legacy enterprise; deep CEF support |
| **Securonix** | SNYPR | User/entity count | Cloud-native UEBA; long-term analytics |
| **Devo** | Platform | GB/day | Streaming architecture; sub-second search |
| **Sumo Logic** | Cloud SIEM | Credits/GB | Cloud-native; multi-tenant; CIP |

### SIEM Maturity Model

| Level | Description | Capabilities |
|---|---|---|
| **L1 - Initial** | Log collection only; manual review | Syslog aggregation; basic dashboards; no correlation |
| **L2 - Managed** | Basic correlation rules active | Rule-based alerting; compliance reporting; 8x5 monitoring |
| **L3 - Defined** | Tuned detections; documented processes | ATT&CK-mapped rules; playbooks; case management; SOC tier model |
| **L4 - Quantified** | Metrics-driven operations | MTTD/MTTR tracked; FP rate monitored; coverage gap analysis |
| **L5 - Optimizing** | Continuous improvement loop | Detection-as-code; automated tuning; threat-hunting program; ML anomaly detection |

---
## 2. Splunk Enterprise Security

### Architecture

**Indexer Cluster:**
```
Cluster Manager (Master)
  +-- Indexer Peer 1  (replication_factor=2, search_factor=2)
  +-- Indexer Peer 2
  +-- Indexer Peer 3

Replication Factor (RF): number of raw data copies
Search Factor (SF): number of searchable copies (SF <= RF)
Recommended production: RF=3, SF=2 (tolerates 1 peer loss)
```

**Search Head Cluster (SHC):**
```
Deployer -> pushes apps to all SH members
Captain Election: Raft consensus among SH members; captain coordinates jobs
SH Members: each can accept user searches; dispatch to indexers
KV Store replication: shared across members for lookups/collections
```

**Forwarder Types:**
| Type | Parsing | Port | Use Case |
|---|---|---|---|
| **Universal Forwarder (UF)** | None (raw forwarding) | 9997 | Endpoint log collection; minimal footprint |
| **Heavy Forwarder (HF)** | Full parsing + filtering | 9997 | DMZ collection; protocol conversion; data masking |
| **Intermediate Forwarder** | Routing/load balancing | 9997 | Aggregation tier for large deployments |

**Deployment Server:** Manages forwarder configuration at scale via deployment apps pushed to forwarder classes (serverclasses.conf).

### SPL Security Reference

**tstats (accelerated search over data models):**
```spl
| tstats count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication
    where nodename=Authentication.Failed_Authentication
        Authentication.action="failure"
    by _time Authentication.user Authentication.src span=1h
| rename Authentication.user as user Authentication.src as src
| where count > 10
| sort -count
```

**stats / eval / rex patterns:**
```spl
| stats count dc(src_ip) as unique_sources values(signature) as signatures
    by dest_ip, dest_port
| eval risk_score = if(unique_sources > 50, "HIGH", if(unique_sources > 10, "MEDIUM", "LOW"))
| rex field=_raw "(?<extracted_user>user=\S+)"
| where isnotnull(extracted_user)
```

**lookup / join / append:**
```spl
| lookup threat_intel_ips ip as src_ip OUTPUT threat_category confidence
| where isnotnull(threat_category)

| join type=left src_ip [search index=asset_db | table ip department owner]

| append [search index=firewall earliest=-24h | stats count by src_ip]
```

**transaction (session reconstruction):**
```spl
index=proxy
| transaction src_ip maxspan=30m maxpause=5m keepevicted=true
| where eventcount > 100 AND duration > 300
| table src_ip, duration, eventcount, uri_domain
```

**streamstats / eventstats:**
```spl
| streamstats time_window=1h count as rolling_count by src_ip
| eventstats avg(bytes_out) as avg_bytes stdev(bytes_out) as stdev_bytes by dest_ip
| where bytes_out > avg_bytes + (3 * stdev_bytes)
```

**Time modifiers:**
```spl
earliest=-24h@h latest=now
earliest=-7d@d latest=@d
earliest="2024-01-01T00:00:00" latest="2024-01-31T23:59:59"
```

**Field extractions (rex at search time):**
```spl
| rex field=_raw "process_name=(?<proc_name>[^\s]+)\s+pid=(?<pid>\d+)"
| rex mode=sed field=CommandLine "s/\s+/ /g"
```

**Summary indexes:**
```spl
| sitimechart span=1h count by src_ip limit=0
| collect index=summary_auth marker="report=failed_auth_hourly"
```

### ES Data Models (CIM)

| Data Model | Key Fields | Primary Sources |
|---|---|---|
| **Authentication** | user, src, dest, action, app | AD, LDAP, VPN, SSH, Office 365 |
| **Network_Traffic** | src_ip, dest_ip, src_port, dest_port, bytes_in/out, transport | Firewall, NetFlow, proxy |
| **Endpoint** | process_name, parent_process, user, file_path, registry_path | Sysmon, CrowdStrike, Carbon Black |
| **Web** | uri_path, http_method, status, bytes, referrer, user_agent | Proxy, WAF, web server logs |
| **Email** | src_user, recipient, subject, attachment_name, direction | O365, Exchange, Proofpoint |
| **Intrusion_Detection** | signature, severity, category, src, dest | IDS/IPS, WAF, threat platform |
| **Change** | object, action, user, change_type | AD changes, config management |

### Correlation Searches & Notable Events

```spl
-- Brute Force Detection (creates Notable Event)
| tstats summariesonly=true count from datamodel=Authentication
    where nodename=Authentication.Failed_Authentication
    by Authentication.user, Authentication.src span=10m
| where count >= 10
| eval severity="high", description="Brute force: ".count." failures from ".src
| outputlookup append=true notable_events_lookup
```

Notable Event fields: `rule_name`, `rule_title`, `severity`, `urgency`, `status`, `owner`, `event_id`, `src`, `dest`, `user`

### Risk-Based Alerting (RBA)

```
Risk Object: user | system | other (the "who/what")
Risk Score: integer added to object's cumulative score
Risk Rule: search that fires risk_message + score
Risk Notable: triggered when object's score > threshold (e.g., 100)

Example Risk Rule (SPL):
| tstats count from datamodel=Authentication.Failed_Authentication by user, src
| where count > 5
| eval risk_score=20, risk_object=user, risk_object_type="user"
    risk_message="Multiple auth failures from ".src
| collect index=risk_index

Risk Threshold Alert:
index=risk_index
| stats sum(risk_score) as total_risk by risk_object
| where total_risk > 100
| sort -total_risk
```

### ES Dashboards

| Dashboard | Purpose | Key Panels |
|---|---|---|
| **Security Posture** | C-suite overview | Active notable count by severity; MTTD/MTTR trend |
| **Incident Review** | Analyst queue | Notable events table; status filter; owner assignment |
| **Risk Analysis** | RBA investigation | Top risk objects; risk score timeline; contributing events |
| **Executive Summary** | Weekly report | Incident trends; top threats; coverage metrics |

### MITRE ATT&CK & UEBA

- **MITRE ATT&CK App:** Maps correlation searches to techniques; provides coverage heatmap by tactic
- **Splunk UBA:** Separate ML platform ingesting from Splunk; generates anomaly events back into ES; entity timelines per user/device
- **Notable Event Workflow:** New -> In Progress -> Pending -> Resolved (with closing classification: true_positive / false_positive / duplicate / other)

---
## 3. Microsoft Sentinel

### Architecture

```
Microsoft Sentinel
  +-- Log Analytics Workspace (data store; KQL query engine)
  +-- Data Connectors (ingestion from 200+ sources)
  +-- Analytics Rules (detection logic: Scheduled/NRT/Fusion/ML Anomaly)
  +-- Automation Rules -> Logic Apps (playbook orchestration)
  +-- Workbooks (dashboards; built on Azure Monitor Workbooks)
  +-- Notebooks (Jupyter + MSTICPy for hunting)
  +-- UEBA (entity behavior analytics; user/host/IP timelines)
  +-- Threat Intelligence (TAXII/STIX feeds; MDTI integration)
```

**Workspace Design:**
- Single workspace (recommended for most): unified query plane; cross-table KQL
- Multi-workspace: regulatory data sovereignty; MSSP multi-tenant; use workspace() KQL function
- Data retention: interactive 90 days (free) + archive up to 7 years; Basic Logs tier for verbose/cheap sources

### KQL Security Reference

**Core filtering and projection:**
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4625, 4648)
| where AccountType == "User"
| project TimeGenerated, Computer, Account, EventID, LogonType, IpAddress
| sort by TimeGenerated desc
```

**Summarize and bin:**
```kql
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count(), UniqueAccounts = dcount(Account)
    by bin(TimeGenerated, 1h), Computer, IpAddress
| where FailureCount > 20
| sort by FailureCount desc
```

**Join kinds:**
```kql
let FailedLogins = SecurityEvent
    | where EventID == 4625 and TimeGenerated > ago(1h)
    | summarize Failures = count() by Account, IpAddress;
let SuccessLogins = SecurityEvent
    | where EventID == 4624 and TimeGenerated > ago(1h)
    | summarize Successes = count() by Account, IpAddress;
FailedLogins
| join kind=inner SuccessLogins on Account, IpAddress
| where Failures > 5 and Successes >= 1
| project Account, IpAddress, Failures, Successes
```

**Parse with regex:**
```kql
Syslog
| where SyslogMessage has "Failed password"
| parse SyslogMessage with * "for " username " from " src_ip " port" *
| where isnotnull(username) and isnotnull(src_ip)
| summarize count() by username, src_ip
```

**between and ago:**
```kql
AzureActivity
| where TimeGenerated between(ago(7d) .. ago(1d))
| where OperationNameValue has "delete" and ActivityStatusValue == "Success"
```

**make_series and anomaly detection:**
```kql
SecurityEvent
| where EventID == 4688
| make_series ProcessCount = count() on TimeGenerated
    from ago(14d) to now() step 1h by Computer
| extend (anomalies, score, baseline) = series_decompose_anomalies(ProcessCount, 2.0)
| mv-expand TimeGenerated, ProcessCount, anomalies, score, baseline
| where anomalies == 1
```

**scan operator (stateful sequence detection):**
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4625, 4624)
| sort by Account asc, TimeGenerated asc
| scan with (
    step login_failure: EventID == 4625 => account_fail = Account;
    step login_success: EventID == 4624 and Account == account_fail
        and TimeGenerated between (login_failure.TimeGenerated .. (login_failure.TimeGenerated + 10m))
        => success_after_fail = true;
)
| where success_after_fail == true
```

**let statements and stored functions:**
```kql
let RareProcessThreshold = 5;
let KnownSafePaths = dynamic(["C:\\Windows\\System32", "C:\\Program Files"]);
let GetRareProcesses = (lookback:timespan) {
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where not(FolderPath has_any (KnownSafePaths))
    | summarize count() by FileName, FolderPath
    | where count_ < RareProcessThreshold
};
GetRareProcesses(7d)
| sort by count_ asc
```

### Built-in Data Connectors

| Connector | Data Tables | Auth Method |
|---|---|---|
| Microsoft 365 Defender (XDR) | DeviceEvents, EmailEvents, IdentityLogonEvents, AlertInfo | First-party AAD |
| Azure Active Directory | SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs | First-party AAD |
| Office 365 | OfficeActivity (Exchange/SharePoint/Teams) | First-party AAD |
| AWS CloudTrail | AWSCloudTrail | IAM role + S3 |
| Syslog / CEF | Syslog, CommonSecurityLog | Log Forwarder VM (rsyslog/syslog-ng) |
| Windows Security Events via AMA | SecurityEvent | Azure Monitor Agent |

### Custom Data Ingestion

**DCR-based Custom Logs (v2):**
```json
{
  "dataCollectionRuleId": "/subscriptions/.../dcr-custom-app",
  "streams": ["Custom-MyAppLogs_CL"],
  "destinations": { "logAnalytics": [{ "workspaceId": "...", "name": "la-dest" }] }
}
```

**REST Log Ingestion API:**
```
POST https://{DCE-endpoint}/dataCollectionRules/{DCR-immutableId}/streams/{stream}?api-version=2023-01-01
Authorization: Bearer {token}
Content-Type: application/json
[{"TimeGenerated":"2024-01-01T00:00:00Z","Column1":"value1","Column2":"value2"}]
```

### Analytics Rule Types

| Type | Trigger | Latency | Best For |
|---|---|---|---|
| **Scheduled KQL** | KQL query on schedule | 5 min+ | Custom correlation; threshold-based |
| **NRT (Near Real-Time)** | Continuous micro-batch | ~1 min | High-priority detections |
| **Microsoft Security** | Ingest alerts from M365D/Defender | Real-time | Escalate MSFT alerts to incidents |
| **Fusion (ML)** | ML correlation across signals | Hours | Multi-stage attacks; low-volume APT |
| **Anomaly** | Built-in ML baseline deviation | Hours | UEBA; rare events |

### UEBA Entity Pages

- **User entity:** Sign-in timeline, peer group comparison, anomaly score history, related alerts, associated hosts
- **Host entity:** Process tree, network connections, alerts, logged-on users, CVE exposure
- **IP entity:** Geolocation, threat intel hits, associated users/hosts, traffic volume

### Threat Intelligence Integration

```kql
-- Query TI against network events
ThreatIntelligenceIndicator
| where TimeGenerated > ago(7d) and Active == true
| join kind=innerunique (
    CommonSecurityLog
    | where TimeGenerated > ago(1h)
    | project DestinationIP, SourceIP, DeviceVendor
) on $left.NetworkIP == $right.DestinationIP
| project DestinationIP, ConfidenceScore, ThreatType, Description
```

**Sources:** MDTI (Microsoft Defender Threat Intelligence), TAXII 2.0/2.1 servers, custom CSV upload via API, Logic App TI import

### Hunting with Notebooks (MSTICPy)

```python
import msticpy as mp
mp.init_notebook()
qry_prov = mp.QueryProvider("MicrosoftSentinel")
qry_prov.connect(WorkspaceConfig())
results = qry_prov.execute_query(
    "SecurityEvent | where EventID == 4688 | take 1000"
)
ioc_extractor = mp.IoCExtract()
iocs = ioc_extractor.extract(results["CommandLine"])
```

---
## 4. IBM QRadar

### Architecture

```
QRadar Distributed Deployment:

Event Sources (syslog/SNMP/JDBC/API)
    |
Event Collector (EC)          Flow Sources (NetFlow/IPFIX/sFlow/PacketCapture)
    |                                 |
Event Processor (EP)          Flow Collector (FC) -> Flow Processor (FP)
    |                                 |
           Console (Magistrate + UI + AQL Engine)
                    |
            Ariel Database (events/flows indexed storage)
```

**Component Roles:**
| Component | Function |
|---|---|
| **Event Collector** | Receives raw events; DSM parsing; normalization |
| **Event Processor** | Applies rules; generates offenses; stores events |
| **Flow Collector** | Captures and deduplicates network flow data |
| **Flow Processor** | Enriches flows; applies flow rules |
| **Console** | Magistrate (correlation); UI; reporting; AQL query engine |

### AQL (Ariel Query Language) Reference

**Basic event query:**
```aql
SELECT sourceip, destinationip, username, eventcount, starttime, endtime
FROM events
WHERE category = 5000
    AND LOGSOURCETYPENAME(devicetype) = 'Linux OS'
    AND username IS NOT NULL
LAST 24 HOURS
ORDER BY eventcount DESC
LIMIT 100
```

**Group By and aggregation:**
```aql
SELECT sourceip,
       COUNT(*) AS event_count,
       SUM(eventcount) AS total_events,
       MIN(starttime) AS first_seen,
       MAX(endtime) AS last_seen
FROM events
WHERE LOGSOURCETYPENAME(devicetype) IN ('Microsoft Windows Security Event Log', 'WinCollect')
    AND qidname(qid) ILIKE '%logon failure%'
GROUP BY sourceip
HAVING COUNT(*) > 10
LAST 1 HOURS
ORDER BY event_count DESC
```

**Flow query:**
```aql
SELECT sourceip, destinationip, sourceport, destinationport,
       SUM(sourcebytes) AS bytes_out,
       SUM(destinationbytes) AS bytes_in,
       SUM(flowcount) AS connections
FROM flows
WHERE destinationport IN (443, 80, 8080, 8443)
    AND flowdirection = 'L2R'
START '2024-01-01 00:00:00'
STOP '2024-01-01 23:59:59'
GROUP BY sourceip, destinationip, sourceport, destinationport
ORDER BY bytes_out DESC
LIMIT 50
```

**Reference set membership:**
```aql
SELECT sourceip, username, eventcount, starttime
FROM events
WHERE sourceip IN (SELECT value FROM referenceset('Known_Bad_IPs'))
    AND category != 6000
LAST 24 HOURS
```

**Custom properties in AQL:**
```aql
SELECT sourceip, destinationip,
       "Process Name" AS process_name,
       "Parent Process" AS parent_process
FROM events
WHERE LOGSOURCETYPENAME(devicetype) = 'Microsoft Windows Security Event Log'
    AND eventid IN (4688, 1)
LAST 1 HOURS
```

### Log Source Management

**DSM (Device Support Module):**
- DSM Editor: GUI to create/modify parsing rules for custom log sources
- Universal DSM: Fallback parser; accepts any syslog; custom field extraction via regex
- Automatic DSM Detection: QRadar auto-identifies log sources by pattern matching

**WinCollect Agent:**
```xml
<!-- WinCollect configuration for Windows Event Forwarding -->
<destination type="syslog" host="qradar-ec-01" port="514" protocol="UDP"/>
<event-source name="Security" channel="Security">
    <xpath-filter>*[System[(EventID=4624 or EventID=4625 or EventID=4688)]]</xpath-filter>
</event-source>
```

**Bulk Log Source Import:**
- CSV format: `name,type_id,hostname,protocol_type,enabled`
- API endpoint: `POST /api/config/event_sources/log_source_management/log_sources`

### Offense Management Lifecycle

**Offense Magnitude Formula:**
```
Magnitude = (Severity x 0.4) + (Credibility x 0.3) + (Relevance x 0.3)

Severity:    0-10, based on event category severity
Credibility: 0-10, based on log source credibility rating
Relevance:   0-10, based on whether destination is a local/watched asset
```

**Offense States:**
```
Active -> In Progress (analyst assigned) -> Closed
Closing reasons: False Positive / Non-Issue / Policy Violation /
                 User Error / System Change / Resolved / Other
```

**Offense Workflow:**
1. Rule match -> Offense created or updated
2. Magnitude calculated; notifications sent if threshold met
3. Analyst assigns offense; adds notes; runs AQL for investigation
4. Containment actions taken; evidence documented
5. Offense closed with classification and analyst notes

### Rule Types

**Event Rules:**
```
Building Block (BB): Reusable logic component; not a standalone rule
Test: AND/OR logic on event fields, reference sets, custom properties
Functions: COUNT, SEQUENCE, ACCUMULATE, SAME/DIFFERENT field groupings

Example BB: BB:NetworkScan
  when the event(s) were detected by one or more of:
    Log Source Type is Firewall
  AND when the destination port is one of: 22, 23, 80, 443, 3389
  AND when these events are seen more than 50 times in 5 minutes
```

**Anomaly Detection Rules:**
- Statistical deviation from 7-day/30-day baseline
- Flow-based volume anomalies (bytes, packets, connections)
- NEW rule type: fires when value not seen in past N days (new external IP, new user-agent)

**Reference Set Population via API:**
```python
import requests
HEADERS = {'SEC': 'admin-token', 'Content-Type': 'application/json', 'Version': '14.0'}
BASE = 'https://qradar/api'
# Add IP to Known_Bad_IPs reference set
requests.post(f'{BASE}/reference_data/sets/bulk_load/Known_Bad_IPs',
              headers=HEADERS, json=["203.0.113.1", "198.51.100.5"])
```

**ATT&CK Tagging (QRadar 7.5+):**
- Rules can be tagged with MITRE ATT&CK technique IDs
- Coverage dashboard shows heatmap by tactic/technique
- Offense detail shows associated ATT&CK techniques

---
## 5. Elastic SIEM & Open Source

### Elastic Stack Security Architecture

```
Data Sources -> Elastic Agent (Fleet-managed)
                    |
             Elasticsearch (indexing + storage)
                    |
             Kibana Security App
               +-- Detection Rules Engine (KQL/EQL/ML/Threshold)
               +-- Timeline (investigation workspace)
               +-- Cases (case management)
               +-- Dashboards (prebuilt security views)

Elastic Endpoint Security: EDR built into Elastic Agent; prevention + detection
Fleet: centralized agent policy management (Kibana UI + API)
```

### Elastic Common Schema (ECS) Field Mappings

| Category | Key Fields |
|---|---|
| **Event** | event.category, event.type, event.action, event.outcome, event.severity |
| **Network** | source.ip, source.port, destination.ip, destination.port, network.protocol |
| **Process** | process.name, process.pid, process.parent.name, process.command_line, process.hash.sha256 |
| **File** | file.path, file.name, file.extension, file.hash.md5, file.hash.sha256 |
| **User** | user.name, user.domain, user.id, user.email |
| **Host** | host.name, host.hostname, host.ip, host.os.type, host.os.version |
| **DNS** | dns.question.name, dns.question.type, dns.resolved_ip |
| **Registry** | registry.key, registry.value.name, registry.value.data |

### Elastic Detection Rules (TOML Format)

```toml
[metadata]
creation_date = "2024-01-15"
integration = ["windows"]
maturity = "production"
updated_date = "2024-06-01"

[rule]
author = ["Security Team"]
description = "Detects PowerShell execution with encoded command argument"
false_positives = ["Legitimate software using encoded commands for installation"]
from = "now-9m"
index = ["winlogbeat-*", "logs-endpoint.events.*"]
language = "eql"
license = "Elastic License v2"
name = "PowerShell Encoded Command Execution"
references = ["https://attack.mitre.org/techniques/T1059/001/"]
risk_score = 73
rule_id = "a8b4c2d1-e5f6-4a3b-8c9d-0e1f2a3b4c5d"
severity = "high"
tags = ["Domain: Endpoint", "OS: Windows", "Use Case: Threat Detection",
        "Tactic: Execution", "Data Source: Elastic Defend"]
type = "eql"

query = '''
process where host.os.type == "windows" and event.type == "start"
and process.name : ("powershell.exe", "pwsh.exe")
and process.command_line : ("*-EncodedCommand*", "*-enc *", "*-e *", "*-ec *")
and not process.parent.name : ("msiexec.exe", "setup.exe")
'''

[[rule.threat]]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1059"
name = "Command and Scripting Interpreter"
reference = "https://attack.mitre.org/techniques/T1059/"
[[rule.threat.technique.subtechnique]]
id = "T1059.001"
name = "PowerShell"
reference = "https://attack.mitre.org/techniques/T1059/001/"
[[rule.threat.tactic]]
id = "TA0002"
name = "Execution"
reference = "https://attack.mitre.org/tactics/TA0002/"
```

### EQL (Event Query Language) Sequence Detection

```eql
/* Credential dumping via LSASS memory access */
sequence by host.id with maxspan=2m
  [process where event.type == "start"
   and process.name != null
   and not process.name : ("lsass.exe", "MsMpEng.exe", "SenseIR.exe")]
  [process where event.action == "open_process_handle"
   and process.pe.original_file_name == "lsass.exe"
   and process.Ext.token.integrity_level_name == "high"]
  [file where event.action == "creation"
   and file.extension : ("dmp", "dump", "bin")]
```

```eql
/* Lateral movement via PsExec pattern */
sequence by host.id with maxspan=5m
  [network where event.type == "start"
   and destination.port == 445
   and source.ip != "127.0.0.1"]
  [file where event.action == "creation"
   and file.path : "C:\\Windows\\PSEXESVC.exe"]
  [process where event.type == "start"
   and process.parent.name : "services.exe"]
```

### ES|QL (Elasticsearch Query Language) - Modern Analytics

```esql
FROM logs-endpoint.events.process-*
| WHERE @timestamp > NOW() - 24 HOURS
| WHERE event.type == "start" AND host.os.type == "windows"
| WHERE process.name IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| STATS process_count = COUNT(*), unique_hosts = COUNT_DISTINCT(host.name)
    BY process.parent.name
| SORT process_count DESC
| LIMIT 20
```

### ML Anomaly Detection Jobs

| Job ID | Description | Key Signal |
|---|---|---|
| `network_traffic_rare_server_by_country` | Rare server contacted from unusual country | Geo anomaly per host |
| `auth_rare_hour` | Login at unusual hour for user | Time-of-day anomaly per user |
| `v3_windows_anomalous_process_creation` | Unusual process creation patterns | Process parent-child anomaly |
| `v3_windows_rare_user_type10_remote_login` | Rare Type 10 (RemoteInteractive) login | User + logon type combo |
| `v3_packetbeat_rare_dns_question` | DNS query to rarely seen domain | DNS entropy + rarity |

### Wazuh (Open Source SIEM/XDR)

**Architecture:** Manager (analysis + rules) + Indexer (OpenSearch) + Dashboard + Agents (cross-platform)

**Rule XML Format:**
```xml
<group name="syscheck,pci_dss_11.5,">
  <rule id="100100" level="12">
    <if_sid>553</if_sid>
    <field name="file">/etc/passwd</field>
    <description>Critical file modified: /etc/passwd</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>pci_dss_10.2.7,hipaa_164.312.b,</group>
  </rule>
</group>

<!-- Active Response: block IP on firewall -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100200</rules_id>
  <timeout>600</timeout>
</active-response>
```

**Decoder XML:**
```xml
<decoder name="custom-app">
  <prematch>CustomApp:</prematch>
  <regex>(\S+) user=(\S+) action=(\S+) result=(\S+)</regex>
  <order>srcip, username, action, result</order>
</decoder>
```

### OpenSearch Security Analytics

- **Sigma Rule Import:** Upload `.yml` Sigma rules via API or UI; auto-converted to OpenSearch DSL
- **Detection Rules Engine:** Runs Sigma rules against OpenSearch indices on schedule
- **Findings:** Matched events grouped by rule; severity mapped from Sigma level
- **Correlation Rules:** Chain multiple findings across rules for complex detection

---
## 6. Log Collection & Normalization

### Critical Windows Event IDs

**Security Log (Microsoft-Windows-Security-Auditing):**

| Event ID | Description | Key Fields | Detection Value |
|---|---|---|---|
| **4624** | Successful logon | Account, LogonType (2=Interactive, 3=Network, 10=RemoteInteractive), IpAddress | Baseline for anomaly; Type 10 = RDP |
| **4625** | Failed logon | Account, FailureReason, SubStatus, IpAddress | Brute force; credential stuffing |
| **4648** | Explicit credential logon (RunAs) | SubjectAccount, TargetAccount, TargetServer | Pass-the-hash; lateral movement |
| **4663** | Object access attempt | ObjectName, ObjectType, AccessMask, SubjectAccount | File access; sensitive data exfil |
| **4688** | Process creation | NewProcessName, ParentProcessName, CommandLine*, Creator | T1059 execution; LOLBins |
| **4698** | Scheduled task created | TaskName, TaskContent, SubjectAccount | T1053 persistence |
| **4720** | User account created | NewAccount, SubjectAccount | Backdoor account creation |
| **4726** | User account deleted | TargetAccount, SubjectAccount | Account tampering; covering tracks |
| **4732** | Member added to security group | MemberName, TargetGroup | Privilege escalation; T1098 |
| **7045** | New service installed | ServiceName, ServiceFileName, ServiceType | T1543 service persistence |

*Requires "Audit Process Creation" + "Include Command Line in Process Creation Events" GPO

**System Log:**
| Event ID | Description | Detection Value |
|---|---|---|
| **7036** | Service state changed | Service stopped/started; detect critical service kills |

**Sysmon Event IDs (Microsoft-Windows-Sysmon/Operational):**

| Event ID | Description | Key Fields |
|---|---|---|
| **1** | Process Create | Image, CommandLine, ParentImage, ParentCommandLine, Hashes, User |
| **3** | Network Connection | Image, DestinationIp, DestinationPort, Protocol, User |
| **7** | Image Loaded (DLL) | Image, ImageLoaded, Hashes, Signed, Signature |
| **8** | CreateRemoteThread | SourceImage, TargetImage -> LSASS injection |
| **10** | ProcessAccess (LSASS) | SourceImage, TargetImage=lsass.exe, CallTrace |
| **11** | FileCreate | TargetFilename, Image -> dropper activity |
| **13** | RegistryEvent (Set) | TargetObject (HKLM Run keys), Details -> T1547 |
| **22** | DNS Query | QueryName, QueryResults, Image -> C2 domain resolution |

### Windows Event Forwarding (WEF)

**GPO Configuration:**
```
Computer Configuration -> Administrative Templates -> Windows Components
  -> Event Forwarding -> Configure target Subscription Manager:
    Server=http://wec-server.domain.local:5985/wsman/SubscriptionManager/WEC,Refresh=60

  -> Event Log Readers Group: add NETWORK SERVICE on WEC server

Windows Remote Management -> Allow automatic configuration of listeners: Enabled
```

**WEC Subscription Types:**
| Type | Description | Use Case |
|---|---|---|
| **Source-Initiated (Push)** | Endpoints push events to WEC | Domain-joined; GPO-configured |
| **Collector-Initiated (Pull)** | WEC polls endpoints | Non-domain; explicit subscription list |

**XPath Filter (high-value events only):**
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625 or EventID=4648
               or EventID=4688 or EventID=4698 or EventID=4732)]]
    </Select>
  </Query>
  <Query Id="1" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=1 or EventID=3 or EventID=7 or EventID=8
               or EventID=10 or EventID=11 or EventID=13 or EventID=22)]]
    </Select>
  </Query>
</QueryList>
```

### Linux Log Forwarding

**rsyslog (TLS-encrypted remote forwarding):**
```conf
# /etc/rsyslog.conf
module(load="imjournal")        # systemd journal
module(load="imfile")           # file-based inputs

# TLS transport
global(DefaultNetStreamDriver="gtls"
       DefaultNetStreamDriverCAFile="/etc/ssl/certs/ca.pem"
       DefaultNetStreamDriverCertFile="/etc/ssl/certs/client.pem"
       DefaultNetStreamDriverKeyFile="/etc/ssl/private/client-key.pem")

# CEF template
template(name="CEF" type="string"
  string="CEF:0|Linux|rsyslog|1.0|%syslogfacility-text%|%msg%|5|src=%FROMHOST-IP% msg=%msg%
")

# Forward to SIEM
action(type="omfwd" target="siem.corp.local" port="6514"
       protocol="tcp" netStreamDriver="gtls"
       netStreamDriverPermittedPeers="siem.corp.local"
       template="CEF")
```

**Filebeat modules for Linux:**
```yaml
# /etc/filebeat/filebeat.yml
filebeat.modules:
  - module: system
    syslog: { enabled: true }
    auth: { enabled: true }
  - module: auditd
    log: { enabled: true }
  - module: nginx
    access: { enabled: true }
    error: { enabled: true }

output.logstash:
  hosts: ["logstash.corp.local:5044"]
  ssl.certificate_authorities: ["/etc/filebeat/ca.crt"]
```

### Log Format Specifications

**CEF (Common Event Format):**
```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|Threat Detected|7|
  src=192.168.1.100 dst=203.0.113.50 spt=54321 dpt=443
  proto=TCP act=block cs1=malware cs1Label=ThreatCategory
  fileHash=44d88612fea8a8f36de82e1278abb02f
  msg=Malware detected in HTTPS traffic
```

**CEF Severity Scale:** 0=Unknown, 1-3=Low, 4-6=Medium, 7-8=High, 9-10=Very-High

**Syslog RFC 5424 Structured Data:**
```
<165>1 2024-01-15T10:30:00.123Z host1 myapp 1234 ID47
  [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]
  User logged in successfully
```

**Grok Patterns (Logstash):**
```ruby
filter {
  grok {
    match => { "message" => [
      "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:msg}",
      "%{COMBINEDAPACHELOG}"
    ]}
  }
  date { match => ["timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"] }
  geoip { source => "clientip" target => "geoip" }
  mutate { add_field => { "environment" => "production" } }
}
```

### Log Enrichment Pipeline

```
Raw Event
    |
[GeoIP Enrichment]        src_ip -> country, city, ASN, lat/long
    |
[Threat Intel Lookup]     ip/domain/hash -> malicious score, feed name, confidence
    |
[Asset Database Join]     hostname/IP -> owner, department, criticality_tier, OS
    |
[User-to-Department Map]  username -> AD groups, manager, department, risk_tier
    |
[Normalization]           Vendor fields -> ECS/CIM/CEF common schema
    |
Enriched Event -> SIEM Indexing
```

---
## 7. Detection Engineering

### Detection Lifecycle

```
1. Hypothesis Generation
   +-- Threat intelligence (new TTPs from reports/ISACs)
   +-- Incident post-mortems (what we missed)
   +-- Purple team findings (gaps from adversary simulation)
   +-- ATT&CK gap analysis (uncovered techniques)

2. Rule Development
   +-- Identify data sources (Sysmon/EDR/network/cloud)
   +-- Write detection logic (Sigma -> SIEM-native)
   +-- Define risk score, severity, false positive list
   +-- Map to ATT&CK technique

3. Testing
   +-- Atomic Red Team execution
   +-- Validate rule fires on test data
   +-- Measure FP rate on historical data
   +-- Performance impact assessment

4. Deployment
   +-- PR review + peer approval
   +-- Deploy to dev/staging SIEM first
   +-- Monitor for 2 weeks; track FP rate
   +-- Promote to production with tuning

5. Tuning
   +-- Add exception conditions for known-good activity
   +-- Adjust thresholds based on environment baseline
   +-- Update lookup tables for asset/user exclusions
   +-- Document all tuning decisions

6. Periodic Review
   +-- Quarterly: review FP rate, coverage, relevance
   +-- Annual: full rule audit; sunset obsolete rules
   +-- Post-incident: coverage gap assessment
```

### ATT&CK Coverage Mapping

**ATT&CK Navigator Workflow:**
1. Export current detection rules -> extract technique IDs
2. Import technique list into Navigator (JSON layer format)
3. Color-code by coverage level: No Coverage / Partial / Full
4. Identify gaps: prioritize by threat actor TTPs targeting your sector

**Coverage by Data Source Priority:**
| Data Source | ATT&CK Techniques Covered | Collection Priority |
|---|---|---|
| Process creation (Sysmon 1 / EDR) | T1059, T1055, T1543, T1053, T1218 | CRITICAL |
| Network connections (Sysmon 3 / firewall) | T1071, T1095, T1572, T1008 | CRITICAL |
| Authentication events (4624/4625/4648) | T1078, T1110, T1550, T1021 | CRITICAL |
| DNS queries (Sysmon 22 / DNS log) | T1071.004, T1568, T1008 | HIGH |
| File creation/modification (Sysmon 11) | T1105, T1027, T1566 | HIGH |
| Registry events (Sysmon 13) | T1547.001, T1112, T1574 | HIGH |
| LSASS access (Sysmon 10) | T1003.001, T1055 | HIGH |
| Scheduled tasks (4698/Sysmon) | T1053.005 | MEDIUM |
| Service creation (7045) | T1543.003 | MEDIUM |

### Sigma Rule Format

```yaml
title: PowerShell Base64 Encoded Command Execution
id: a8b4c2d1-e5f6-4a3b-8c9d-0e1f2a3b4c5d
status: production
description: Detects execution of PowerShell with base64 encoded commands
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001
author: Security Team
date: 2024-01-15
modified: 2024-06-01
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_main:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_encoded:
    CommandLine|contains|any:
      - '-EncodedCommand '
      - ' -enc '
      - ' -e '
      - ' -ec '
  filter_legitimate:
    CommandLine|contains:
      - 'Microsoft.PowerShell.Commands'
      - 'C:\Program Files\SomeApp'
  condition: selection_main and selection_encoded and not filter_legitimate
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Legitimate software using encoded commands during installation
  - Configuration management tools (SCCM, Ansible)
level: high
```

**pySigma Backend Conversion:**
```bash
# Install sigma CLI and backends
pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch

# Convert to Splunk SPL
sigma convert -t splunk -p splunk_windows sigma/rules/windows/process_creation/proc_creation_win_powershell_encoded.yml

# Convert to Elastic EQL
sigma convert -t elasticsearch -p ecs_windows -f eql sigma/rules/ --output-format eql

# Convert to Sentinel KQL
sigma convert -t microsoft365defender -p microsoft365defender sigma/rules/windows/

# Convert to QRadar AQL
sigma convert -t qradar sigma/rules/windows/ -o output_rules/
```

**SigmaHQ Community Repo:** `github.com/SigmaHQ/sigma` -- 3,000+ community rules

### Detection Quality Criteria

| Criterion | Definition | Target |
|---|---|---|
| **Precision** | True Positives / (True Positives + False Positives) | > 70% |
| **Recall** | True Positives / (True Positives + False Negatives) | > 80% |
| **Specificity** | True Negatives / (True Negatives + False Positives) | > 95% |
| **Data Source Availability** | Is required log source collected? | 100% |
| **Performance Impact** | Search time; EPS overhead | < 5% cluster load |

### Testing with Atomic Red Team

```powershell
# Install Invoke-AtomicRedTeam
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser

# List available tests for T1059.001
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Execute test #1 (generates telemetry)
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Execute with custom parameters
Invoke-AtomicTest T1059.001 -TestNumbers 2 -InputArgs @{encoded_command="cGluZyAxMjcuMC4wLjE="}

# Cleanup after test
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup

# Run all T1003 (credential dumping) tests
Invoke-AtomicTest T1003 -GetPrereqs
Invoke-AtomicTest T1003
```

**Validation Checklist:**
- [ ] Alert fires within expected detection window
- [ ] Alert contains required fields (src, dest, process, user)
- [ ] Severity and risk score are appropriate
- [ ] ATT&CK technique tag is correct
- [ ] False positive filter does not block the test

### Detection-as-Code

```
Git Repository Structure:
  detections/
    windows/
      T1059_001_powershell_encoded.yml   (Sigma)
      T1003_001_lsass_access.yml
    network/
      T1071_001_http_c2_beacon.yml
    cloud/
      T1078_004_cloud_account_anomaly.yml
  tests/
    T1059_001_test_data.json
    atomic_red_team_mappings.json
  pipelines/
    splunk_pipeline.yml
    elastic_pipeline.yml

CI/CD Pipeline (GitHub Actions):
  on: pull_request
  jobs:
    validate:
      - sigma check rule.yml          # syntax validation
      - sigma convert -t splunk ...   # test conversion
      - python test_detection.py      # replay test data
    deploy:
      - sigma convert -> push to SIEM API (on merge to main)
```

### Alert Fatigue Management

1. **Baseline establishment:** Run new rules in "report only" mode for 2 weeks; measure FP rate
2. **Exception conditions:** Build exclusion lookup tables for known-good (IT admin IPs, service accounts, automation)
3. **Score-based prioritization:** Combine rule severity + asset criticality + threat intel hit -> unified risk score
4. **Dynamic thresholds:** Tune thresholds via lookup table (updated weekly from rolling 30-day average)
5. **Rule retirement:** Auto-disable rules with >95% FP rate over 30 days; requires re-review before re-enable
6. **Documentation:** Every tuning decision recorded in rule comments with date, analyst, and justification

---
## 8. SOC Operations & Triage

### SOC Tier Model

| Tier | Role | Responsibilities | Typical Shift |
|---|---|---|---|
| **T1** | Alert Analyst / Security Analyst | Alert monitoring; initial triage; enrichment; escalation decision; ticket creation | 24x7 rotating |
| **T2** | Senior Analyst / Incident Responder | Deep investigation; containment actions; playbook execution; T1 escalation review | Business hours + on-call |
| **T3** | Threat Hunter / Detection Engineer | Proactive threat hunting; rule development; purple team; DFIR leadership; tool tuning | Business hours |
| **Management** | SOC Manager / CISO | KPI reporting; resource allocation; vendor management; executive communication | Business hours |

### 5-Step Triage Process

```
Step 1: IDENTIFY
  +-- Asset classification: Is the alert target a critical asset? (Tier 1/2/3)
  +-- Alert type: Category (intrusion/malware/anomaly/policy/compliance)
  +-- Data source: Is the log source reliable? (coverage gap risk)

Step 2: CLASSIFY SEVERITY
  +-- Critical: Active exploitation of critical asset; confirmed C2; data exfil in progress
  +-- High: Malware confirmed; lateral movement detected; privileged account compromise
  +-- Medium: Suspicious behavior; policy violation; failed exploitation attempt
  +-- Low: Informational; compliance violation; minor anomaly

Step 3: ENRICH CONTEXT
  +-- Threat Intel: VirusTotal, AbuseIPDB, MDTI reputation check on IPs/hashes/domains
  +-- Asset DB: Owner, department, criticality, patch level, EDR agent status
  +-- User Info: AD group membership, role, recent HR events, last login location
  +-- Historical: Has this alert fired before? What was the resolution?

Step 4: SCOPE BLAST RADIUS
  +-- Lateral movement: Which other hosts communicated with affected host in past 24h?
  +-- Privilege escalation: What systems can the compromised account access?
  +-- Data at risk: What sensitive data stores are accessible from affected host?
  +-- Timeline: When did the activity start? (first seen across all log sources)

Step 5: RESPOND
  +-- Playbook execution: Follow documented runbook for alert category
  +-- Containment: Isolate host / disable account / block IP / revoke token
  +-- Documentation: Record all findings, actions, and decisions in case
  +-- Escalate or close: T2 escalation or close as FP with documented justification
```

### Enrichment Automation

**VirusTotal API:**
```python
import requests

VT_API_KEY = "your_api_key"
VT_BASE = "https://www.virustotal.com/api/v3"

def vt_check_ip(ip: str) -> dict:
    r = requests.get(f"{VT_BASE}/ip_addresses/{ip}",
                     headers={"x-apikey": VT_API_KEY})
    data = r.json().get("data", {}).get("attributes", {})
    return {
        "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
        "country": data.get("country"),
        "asn": data.get("asn"),
        "reputation": data.get("reputation", 0)
    }

def vt_check_hash(sha256: str) -> dict:
    r = requests.get(f"{VT_BASE}/files/{sha256}",
                     headers={"x-apikey": VT_API_KEY})
    data = r.json().get("data", {}).get("attributes", {})
    return {
        "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
        "type_description": data.get("type_description"),
        "name": data.get("meaningful_name"),
        "size": data.get("size")
    }

def abuseipdb_check(ip: str) -> dict:
    r = requests.get("https://api.abuseipdb.com/api/v2/check",
                     headers={"Key": "your_key", "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90})
    data = r.json().get("data", {})
    return {
        "abuse_score": data.get("abuseConfidenceScore"),
        "reports": data.get("totalReports"),
        "country": data.get("countryCode"),
        "isp": data.get("isp")
    }
```

**Shodan Context:**
```python
import shodan
api = shodan.Shodan("your_shodan_key")
host = api.host("203.0.113.50")
print(f"Ports: {[item['port'] for item in host.get('data', [])]}")
print(f"Vulns: {list(host.get('vulns', {}).keys())}")
print(f"Org: {host.get('org')}")
```

### SOC Dashboard Design

```
Primary SOC Dashboard Panels:

+---------------------------------------------+
| OPEN CRITICAL ALERTS    |  MTTD (24h avg)   |
| [Count: 12] up 3 from   |  [42 min] Target: |
| last hour               |  < 30 min         |
+-------------------------+-------------------+
| MTTR BY ANALYST         | ALERT VOLUME TREND|
| Analyst A: 38min        | [Line chart 7d]   |
| Analyst B: 52min        |                   |
| Analyst C: 28min        |                   |
+-------------------------+-------------------+
| TOP TRIGGERED RULES (24h)   | FP RATE (7d)  |
| 1. Brute Force      [847]   | Rule A: 94%   |
| 2. Suspicious PS    [312]   | Rule B: 12%   |
| 3. New Admin User   [89]    | Rule C: 67%   |
+---------------------------------------------+
| ALERT VOLUME BY SOURCE (7-day bar chart)    |
| Windows Security / Endpoint EDR / Firewall  |
+---------------------------------------------+
```

### Case Management Integration

| Platform | Integration Method | Use Case |
|---|---|---|
| **TheHive** | API: POST /api/case | SOC-native case management; observable tracking; task assignment |
| **ServiceNow** | REST Table API or webhook | Enterprise ITSM; SLA tracking; change management integration |
| **Jira** | Jira API: POST /rest/api/2/issue | Vulnerability management; dev-sec collaboration |
| **PagerDuty** | Events API v2 | On-call alerting; escalation routing |

**Auto-Case Creation (Python):**
```python
import requests

def create_thehive_case(alert: dict) -> str:
    case = {
        "title": f"[SIEM] {alert['rule_name']} - {alert['src_ip']}",
        "description": alert['description'],
        "severity": {"low": 1, "medium": 2, "high": 3, "critical": 4}[alert['severity']],
        "tags": [alert['mitre_technique'], alert['category']],
        "tlp": 2,  # AMBER
        "flag": True if alert['severity'] == "critical" else False
    }
    r = requests.post("https://thehive.corp.local/api/case",
                      headers={"Authorization": "Bearer token"},
                      json=case)
    return r.json()["id"]
```

### Shift Handoff Documentation Template

```
SHIFT HANDOFF REPORT -- [Date] [Shift Time]
Outgoing Analyst: [Name]   Incoming Analyst: [Name]

OPEN CRITICAL/HIGH INCIDENTS:
  Case #      | Alert           | Status      | Next Action
  INC-2024-001| Ransomware IOC  | Investigating| Await forensics from IR team
  INC-2024-002| Data Exfil      | Contained   | Verify block effective

PENDING INVESTIGATIONS:
  [List with context and what still needs to be done]

NOISE/FALSE POSITIVES:
  [Any rules generating excessive FPs; ticket # if filed]

ENVIRONMENT NOTES:
  [Maintenance windows; known issues; new data sources coming online]

ESCALATION CONTACTS:
  [On-call T3 / management / IR firm contact for the shift]
```

### Alert Categorization Taxonomy

| Category | Subcategory | Examples |
|---|---|---|
| **Intrusion** | Network | Port scan, exploit attempt, C2 callback |
| **Intrusion** | Endpoint | Malware execution, code injection, persistence |
| **Account** | Authentication | Brute force, credential stuffing, account takeover |
| **Account** | Privilege | Privilege escalation, admin account creation |
| **Data** | Exfiltration | Large upload, DLP trigger, cloud storage anomaly |
| **Data** | Access | Unauthorized file access, sensitive DB query |
| **Insider** | Policy Violation | USB usage, prohibited software, off-hours access |
| **Vulnerability** | Exploitation | CVE exploit, unpatched system targeted |
| **Compliance** | Regulatory | PCI DSS violation, HIPAA log gap, audit failure |

---
## 9. Threat Hunting with SIEM

### Hunting Methodology

```
Hypothesis-Driven Hunting:
  Source: CTI report of APT group using T1055 (Process Injection)
  Hypothesis: Threat actor may have injected into svchost.exe on domain controllers
  Data sources needed: Sysmon Event 8 (CreateRemoteThread), Event 10 (ProcessAccess)
  Hunt: Query for unusual processes accessing svchost.exe on DCs past 90 days
  Outcome: Document findings; convert to detection rule if confirmed

Analytics-Driven Hunting:
  Source: ML anomaly job fired on rare process execution
  Hypothesis: Investigate anomalous process tree on host WKSTN-042
  Data sources needed: Process creation logs, network connections, file events
  Hunt: Build timeline for host; correlate with user activity; pivot on network IOCs
  Outcome: Escalate to IR or tune ML model

Situational Awareness Hunting:
  Source: Industry alert on active Log4j exploitation campaign
  Hypothesis: Check for Log4j exploitation indicators in our environment
  Data sources needed: Web server logs, JNDI strings in HTTP headers, DNS for ldap://
  Hunt: Targeted search for JNDI exploit strings; DNS lookups to known exploit servers
  Outcome: Patch validation; incident response if hits found
```

### KQL Hunting Queries (Microsoft Sentinel)

**PowerShell Obfuscation Detection:**
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where CommandLine has_any ("-enc", "-e ", "-EncodedCommand", "-ec ", "EncodedCommand")
| where not (CommandLine has_any (
    "Microsoft.PowerShell", "WindowsPowerShell", "C:\\Program Files\\",
    "C:\\Windows\\System32\\WindowsPowerShell"))
| where not (Account has_any ("SYSTEM", "svc_", "admin"))
| project TimeGenerated, Computer, Account, ParentProcessName,
          CommandLine, NewProcessName
| sort by TimeGenerated desc
```

**LSASS Access Anomalies:**
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4656
| where ObjectName endswith "lsass.exe"
| where AccessMask in ("0x1010", "0x1410", "0x143A", "0x40", "0x1fffff")
| where not (SubjectAccount has_any ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"))
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | project DeviceName, ProcessId, FileName, SHA256
) on $left.SubjectLogonId == $right.ProcessId
| project TimeGenerated, Computer, SubjectAccount, ObjectName,
          AccessMask, FileName, SHA256
```

**Scheduled Task Creation Spike:**
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4698
| summarize TaskCreations = count() by bin(TimeGenerated, 1h), Computer
| where TaskCreations > 3
| join kind=inner (
    SecurityEvent
    | where EventID == 4698
    | project TimeGenerated, Computer, TaskName,
              SubjectAccount = tostring(parse_json(EventData).SubjectUserName)
) on Computer
| project TimeGenerated, Computer, SubjectAccount, TaskName, TaskCreations
| sort by TaskCreations desc
```

**Beaconing Pattern Detection (KQL):**
```kql
let lookback = 24h;
let min_requests = 20;
let max_jitter = 0.15;
CommonSecurityLog
| where TimeGenerated > ago(lookback)
| where DeviceVendor has_any ("Palo Alto", "Fortinet", "Check Point")
| summarize RequestTimes = make_list(TimeGenerated), Count = count()
    by SourceIP, DestinationIP, DestinationPort
| where Count >= min_requests
| extend intervals = array_sort_asc(RequestTimes)
| extend avg_interval = series_stats(intervals).avg
| extend stdev_interval = series_stats(intervals).stdev
| extend jitter_ratio = iif(avg_interval > 0, stdev_interval / avg_interval, real(null))
| where jitter_ratio < max_jitter
| project SourceIP, DestinationIP, DestinationPort, Count,
          avg_interval_mins = avg_interval / 60, jitter_ratio
| sort by jitter_ratio asc
```

**New Admin Account Detection:**
```kql
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4732
| where TargetAccount has_any ("Administrators", "Domain Admins", "Enterprise Admins")
| extend MemberAdded = tostring(parse_json(EventData).MemberName)
| project TimeGenerated, Computer, SubjectAccount, MemberAdded, TargetAccount
| join kind=leftouter (
    SecurityEvent
    | where EventID == 4720
    | project AccountCreated = Account, CreationTime = TimeGenerated
) on $left.MemberAdded == $right.AccountCreated
| project TimeGenerated, SubjectAccount, MemberAdded, TargetAccount,
          AccountCreated, CreationTime
```

### SPL Hunting Queries (Splunk)

**Beaconing Detection via Standard Deviation:**
```spl
| tstats count dc(dest_port) as port_diversity
    values(dest_ip) as dest_ips
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.direction=outbound
    by All_Traffic.src_ip _time span=1h
| rename All_Traffic.src_ip as src_ip
| eventstats avg(count) as avg_count stdev(count) as stdev_count by src_ip
| eval is_beaconing=if(stdev_count < 2 AND count > 10, 1, 0)
| where is_beaconing=1 AND port_diversity=1
| table src_ip, dest_ips, count, avg_count, stdev_count
| sort -count
```

**Rare Parent-Child Process Combinations:**
```spl
| tstats count
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe", "winword.exe",
                                              "excel.exe", "outlook.exe", "iexplore.exe")
    by Processes.parent_process_name Processes.process_name
| rename Processes.* as *
| sort count
| head 30
| table parent_process_name, process_name, count
```

**DNS Tunneling Detection:**
```spl
index=dns OR sourcetype=stream:dns
| eval query_length=len(query)
| stats count avg(query_length) as avg_len max(query_length) as max_len
    dc(query) as unique_subdomains values(query) as queries
    by src, record_type, answer
| where avg_len > 40 AND unique_subdomains > 20 AND record_type IN ("TXT", "A", "AAAA")
| eval suspicious_score=if(max_len > 63, 2, 0)
| eval suspicious_score=suspicious_score + if(unique_subdomains > 50, 3, 0)
| sort -suspicious_score
| head 20
```

**Lateral Movement via SMB:**
```spl
| tstats count values(Authentication.dest) as targets dc(Authentication.dest) as target_count
    from datamodel=Authentication
    where Authentication.action=success
        Authentication.authentication_type=NTLM
    by Authentication.src Authentication.user _time span=1h
| rename Authentication.* as *
| where target_count > 5
| eval lateral_movement_score=target_count * 10
| sort -lateral_movement_score
```

### Hunting Technique Coverage

| ATT&CK Technique | Hunt Name | Key Data Source | Sigma Rule Exists |
|---|---|---|---|
| **T1059.001** | PowerShell Obfuscation | Sysmon 1, Event 4688 | Yes |
| **T1071.001** | HTTP C2 Beaconing | Proxy/Firewall logs | Yes |
| **T1053.005** | Scheduled Task Persistence | Event 4698, Sysmon | Yes |
| **T1003.001** | LSASS Memory Dump | Sysmon 10, Event 4656 | Yes |
| **T1055** | Process Injection | Sysmon 8, EDR events | Partial |
| **T1078** | Valid Account Abuse | Auth events, VPN logs | Partial |
| **T1547.001** | Registry Run Key | Sysmon 13 | Yes |
| **T1021.002** | SMB Lateral Movement | Event 4624 Type 3 | Yes |

### Hunt Documentation Template

```markdown
## Hunt Report: [Hunt Name]
**Date:** [YYYY-MM-DD]
**Analyst:** [Name]
**Hypothesis:** [What adversary behavior are we looking for and why?]
**ATT&CK Technique:** [T####.###]

### Data Sources Used
- [List sources and time range queried]

### Query Used
[paste query here]

### Findings
- Total events analyzed: [N]
- Suspicious findings: [N]
- Confirmed malicious: [Y/N]

### IOCs Identified
- IPs: [list]
- Hashes: [list]
- Domains: [list]

### Actions Taken
- [ ] Created detection rule
- [ ] Opened incident case [INC-####]
- [ ] Notified IR team
- [ ] Updated threat intel platform

### Follow-up Required
[What needs to happen next?]
```

### HMM Threat Hunting Maturity Model

| Level | Description | Capabilities |
|---|---|---|
| **HM0** | Initial | Relies entirely on automated alerting; no proactive hunting |
| **HM1** | Minimal | Occasional hunts based on IOCs; no structured methodology |
| **HM2** | Procedural | Regular hunts using documented procedures; ATT&CK-mapped |
| **HM3** | Innovative | Hypothesis-driven; analytics-based; ML-assisted; custom tooling |
| **HM4** | Leading | Automated hunt pipelines; full ATT&CK coverage; purple team cadence |

---
## 10. SIEM Performance, Tuning & Operations

### Splunk Optimization

**Summary Indexes (pre-computed aggregations):**
```spl
-- Scheduled search: runs hourly, populates summary index
| tstats count from datamodel=Authentication.Failed_Authentication
    by Authentication.src Authentication.user _time span=1h
| rename Authentication.* as *
| collect index=summary_auth_hourly
    marker="source=auth_summary version=1"

-- Report accelerated from summary (sub-second for 90-day range):
index=summary_auth_hourly source=auth_summary
| timechart span=1d sum(count) by user limit=20
```

**Data Model Acceleration:**
```conf
# datamodels.conf -- enable acceleration
[Authentication]
acceleration = true
acceleration.earliest_time = -90d
acceleration.cron_schedule = */5 * * * *
acceleration.max_time = 3600

# tstats queries use accelerated data automatically
| tstats summariesonly=true count from datamodel=Authentication
    where nodename=Authentication.Successful_Authentication
    by _time span=1h
```

**Index-time vs Search-time Extractions:**
| Type | When | Performance | Use For |
|---|---|---|---|
| Index-time (SEDCMD/transforms) | At ingestion | Fastest search; increases index size | High-frequency, always-needed fields |
| Search-time (KV_MODE/rex) | At query | Flexible; no index bloat | Rarely-needed; dynamic extractions |

**Peer Node Sizing Guidelines:**
```
Indexer (per 200 GB/day workload):
  CPU: 16+ cores
  RAM: 64 GB minimum
  Storage Hot: 2TB NVMe (RAID 10)
  Storage Warm: 8TB SAS (RAID 5)
  Network: 10 Gbps

Search Head:
  CPU: 16 cores
  RAM: 32 GB
  Storage: 500 GB SSD (for artifacts/KV store)
```

### Elastic ILM (Index Lifecycle Management)

```json
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": { "max_size": "50gb", "max_age": "1d" },
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": { "number_of_shards": 1 },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 50 },
          "allocate": { "require": { "data": "warm" } }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "searchable_snapshot": { "snapshot_repository": "s3-security-archive" },
          "set_priority": { "priority": 0 }
        }
      },
      "delete": {
        "min_age": "2555d",
        "actions": { "delete": {} }
      }
    }
  }
}
```

**Shard Sizing:**
- Target: 10-50 GB per shard (optimal search performance)
- Too small shards: overhead; too large: slow recovery and search
- Formula: `shard_count = ceil(daily_GB / 30)`
- Replicas: 1 replica minimum for HA; 0 replicas on frozen tier

### QRadar Performance Tuning

**ARP Caching:**
```bash
# Increase ARP cache to reduce network lookups
sysctl -w net.ipv4.neigh.default.gc_thresh3=32768
sysctl -w net.ipv4.neigh.default.gc_thresh2=16384
echo "net.ipv4.neigh.default.gc_thresh3 = 32768" >> /etc/sysctl.conf
```

**Magistrate Thread Tuning:**
```xml
<!-- /opt/qradar/conf/ecs-ec-ingress.conf -->
<configuration>
  <magistrate>
    <threadcount>16</threadcount>
    <buffersize>10000</buffersize>
    <flowratelimit>50000</flowratelimit>
  </magistrate>
</configuration>
```

### License Optimization

**Filtering Noisy Sources (Splunk):**
```conf
# transforms.conf -- null queue high-volume low-value events
[setnull]
REGEX = .
DEST_KEY = queue
FORMAT = nullQueue

# inputs.conf or props.conf -- suppress noisy Event ID 4702
[source::.../Microsoft-Windows-TaskScheduler%4Operational.evtx]
TRANSFORMS-setnull = setnull
```

**Normalization to reduce field count:**
- Keep only fields used in correlation rules or reports
- Avoid extracting all vendor-specific fields
- Use lookup tables instead of inline field explosion

### False Positive Tuning

```spl
-- Step 1: Identify high-volume low-fidelity rules (Splunk ES Notable Events)
index=notable
| stats count dc(src) as unique_sources avg(urgency) as avg_urgency
    by rule_name
| where count > 100 AND avg_urgency < 3
| sort -count
| head 20

-- Step 2: Build exception lookup (notable_exceptions.csv: src,dest,user,exception_reason)
| lookup notable_exceptions src dest user OUTPUT exception_reason
| where isnull(exception_reason)

-- Step 3: Dynamic threshold via rolling baseline lookup
| lookup auth_baseline_lookup user OUTPUT avg_failures_1h, stdev_failures_1h
| where failure_count > avg_failures_1h + (2 * stdev_failures_1h)
```

### SIEM Health Monitoring

**Splunk Health Checks:**
```spl
-- Index lag (how far behind is indexing)
index=_internal source=*metrics.log group=pipeline
| eval ingest_lag = current_size / processor
| timechart avg(ingest_lag) by name

-- License usage (approaching limit warning)
index=_internal source=*license_usage.log type=Usage
| stats sum(b) as bytes by pool
| eval GB = round(bytes/1073741824, 2)
| eval pct_used = round((GB / license_limit_GB) * 100, 1)
| where pct_used > 80

-- Search head performance
index=_internal source=*scheduler.log status=completed
| stats avg(run_time) as avg_runtime p95(run_time) as p95_runtime count
    by savedsearch_name
| where p95_runtime > 300
| sort -p95_runtime
```

**Elastic Cluster Health:**
```bash
# Cluster health overview
curl -s "https://elastic:9200/_cluster/health?pretty"

# Index ingestion rate
curl -s "https://elastic:9200/_cat/indices/logs-*?v&s=docs.count:desc&h=index,docs.count,store.size"

# JVM heap usage (should stay < 75%)
curl -s "https://elastic:9200/_nodes/stats/jvm?pretty" | jq '.nodes | to_entries[] | {name: .value.name, heap_pct: .value.jvm.mem.heap_used_percent}'

# Hot threads (for performance investigation)
curl -s "https://elastic:9200/_nodes/hot_threads"
```

### Disaster Recovery

| Platform | HA/DR Mechanism | RPO | RTO |
|---|---|---|---|
| **Splunk** | Indexer cluster (RF=2+); SHC; SmartStore on S3 | Minutes | < 1 hour |
| **Elastic** | Cross-cluster replication (CCR); searchable snapshots | Minutes | < 30 min |
| **QRadar** | HA pair (active/passive); tape archive for cold | Minutes | 1-4 hours |

**Splunk SmartStore (S3 hot/warm tiering):**
```conf
# indexes.conf
[security_events]
remotePath = volume:s3storage/$_index_name
maxDataSize = auto_high_volume

[volume:s3storage]
storageType = remote
path = s3://splunk-smartstore-bucket/
remote.s3.access_key = AKIAIOSFODNN7EXAMPLE
remote.s3.secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
remote.s3.region = us-east-1
```

### XDR Platform Evolution

Modern XDR platforms are consolidating capabilities that previously required separate SIEM + SOAR + EDR deployments:

| Platform | Vendor | Key Strengths |
|---|---|---|
| **Microsoft Defender XDR** | Microsoft | Native M365/Azure integration; Fusion ML correlation; KQL hunting |
| **CrowdStrike Falcon** | CrowdStrike | NG-SIEM with Humio; EDR-first; Threat Graph; Charlotte AI |
| **Palo Alto Cortex XDR** | Palo Alto Networks | Causality-based analysis; XSIAM for SOAR+SIEM+TIP; ML analytics |
| **SentinelOne Singularity** | SentinelOne | eBPF-based endpoint telemetry; Purple AI; autonomous response |
| **Trend Micro Vision One** | Trend Micro | Multi-layer XDR; Attack Surface Risk Management; threat intelligence |

**SIEM vs XDR Decision Framework:**
```
Choose SIEM when:
  - Compliance requires centralized log retention (PCI, HIPAA, SOX)
  - Multi-vendor environment needing centralized correlation
  - Custom detection logic beyond vendor-provided rules
  - Long-term retention (5-7 years) at reasonable cost

Choose XDR when:
  - Homogeneous vendor ecosystem (all Microsoft or all CrowdStrike)
  - Limited security staff; prefer vendor-managed detections
  - Speed to detection/response > customization
  - Integration with SOAR/automation is primary use case

Hybrid approach (most enterprises):
  SIEM: compliance, custom rules, log retention, cross-domain correlation
  XDR: endpoint/cloud telemetry, automated response, ML detections
  SOAR: orchestration layer connecting both + all other security tools
```

---

## Quick Reference Cheat Sheet

### Common SPL Patterns
| Task | SPL |
|---|---|
| Recent failures | `index=auth action=failure earliest=-1h \| stats count by user, src` |
| Top talkers | `\| tstats sum(All_Traffic.bytes_out) from datamodel=Network_Traffic by All_Traffic.src_ip \| sort -sum` |
| Hash lookup | `\| lookup malware_hashes md5 OUTPUT threat_name` |
| Rex extract | `\| rex "user=(?<u>[^ ]+)"` |

### Common KQL Patterns
| Task | KQL |
|---|---|
| Recent failures | `SecurityEvent \| where EventID==4625 and TimeGenerated>ago(1h) \| summarize count() by Account, IpAddress` |
| Anomaly time series | `\| make_series c=count() on TimeGenerated step 1h \| extend anomalies=series_decompose_anomalies(c)` |
| IP TI match | `ThreatIntelligenceIndicator \| join CommonSecurityLog on $left.NetworkIP==$right.DestinationIP` |
| Parse message | `\| parse SyslogMessage with * "user=" user " " *` |

### Log Source Priority Matrix
| Priority | Source | Why |
|---|---|---|
| P0 | Domain Controllers | All auth, AD changes, Golden Ticket |
| P0 | Endpoint EDR | Process, network, file telemetry |
| P0 | Perimeter Firewall | N/S + E/W traffic; C2 detection |
| P1 | DNS Servers | C2, DGA, data exfil via DNS |
| P1 | VPN / Remote Access | Initial access, credential abuse |
| P1 | Email Gateway | Phishing; BEC; malware delivery |
| P2 | Web Proxy | HTTP C2; shadow IT; malware download |
| P2 | Cloud (AWS/Azure/GCP) | Cloud-native attacks; misconfiguration |
| P3 | Applications | Custom alerts; business logic abuse |

### MITRE ATT&CK Quick Reference
| Tactic | ID | Common Techniques |
|---|---|---|
| Initial Access | TA0001 | T1566 Phishing; T1078 Valid Accounts; T1190 Exploit Public App |
| Execution | TA0002 | T1059 Scripting; T1053 Scheduled Tasks; T1204 User Execution |
| Persistence | TA0003 | T1547 Boot Autostart; T1543 Services; T1098 Account Manipulation |
| Privilege Escalation | TA0004 | T1055 Process Injection; T1068 Exploit; T1134 Token Impersonation |
| Defense Evasion | TA0005 | T1036 Masquerading; T1027 Obfuscation; T1070 Log Clearing |
| Credential Access | TA0006 | T1003 OS Credential Dumping; T1110 Brute Force; T1558 Kerberoasting |
| Discovery | TA0007 | T1082 System Info; T1083 File Discovery; T1018 Remote System Discovery |
| Lateral Movement | TA0008 | T1021 Remote Services; T1550 Pass-the-Hash; T1534 Internal Spearphishing |
| Collection | TA0009 | T1560 Archive Data; T1056 Input Capture; T1005 Local Data |
| Exfiltration | TA0010 | T1048 Exfil Over Alt Protocol; T1041 Exfil Over C2; T1567 Web Service |
| Command and Control | TA0011 | T1071 App Layer Protocol; T1572 Protocol Tunneling; T1008 Fallback Channels |

---

*SIEM Reference Library -- Generated 2026-05-06 | TeamStarWolf Security*
