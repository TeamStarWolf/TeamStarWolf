# Threat Hunting Reference Library

> A comprehensive, practitioner-focused reference for proactive threat hunting across Windows, Linux, and cloud environments. Covers hypothesis generation, platform-specific query languages, YARA/Sigma rule authoring, and end-to-end hunt tracking workflows.

---

## Table of Contents

1. [Threat Hunting Fundamentals](#1-threat-hunting-fundamentals)
2. [KQL Threat Hunting (Microsoft Sentinel / Defender XDR)](#2-kql-threat-hunting-microsoft-sentinel--defender-xdr)
3. [Splunk SPL Threat Hunting](#3-splunk-spl-threat-hunting)
4. [Sigma Rules](#4-sigma-rules)
5. [YARA Rules for Threat Hunting](#5-yara-rules-for-threat-hunting)
6. [ATT&CK-Aligned Hunting Playbooks](#6-attck-aligned-hunting-playbooks)
7. [Velociraptor for Threat Hunting](#7-velociraptor-for-threat-hunting)
8. [osquery for Threat Hunting](#8-osquery-for-threat-hunting)
9. [Threat Intelligence Integration](#9-threat-intelligence-integration)
10. [Hunt Tracking and Reporting](#10-hunt-tracking-and-reporting)

---

## 1. Threat Hunting Fundamentals

### 1.1 Definition: Threat Hunting vs. Detection Engineering

**Threat Hunting** is the proactive, human-led search for adversary activity that has evaded existing automated detections. It is iterative, hypothesis-driven, and relies on analyst expertise to explore data that rules have not yet classified as malicious.

**Detection Engineering** is the systematic process of building, testing, and deploying automated detection logic (SIEM rules, EDR policies, IDS signatures) based on known TTPs and prior hunt findings. The two disciplines are complementary: hunts discover novel attacker behavior; detection engineering operationalizes those discoveries at scale.

| Dimension | Threat Hunting | Detection Engineering |
|---|---|---|
| Driver | Human hypothesis | Known TTP / IOC |
| Output | New knowledge, potential detections | Deployed, automated alert |
| Automation level | Low (analyst-intensive) | High (runs continuously) |
| Cadence | Periodic / ad-hoc | Always-on |
| Skill focus | Hypothesis creativity, data intuition | Logic, tuning, CI/CD |
| Feedback direction | Feeds detection engineering | Reduces analyst alert load |

---

### 1.2 Hunting Maturity Model (HMM) - Levels 0-4

The Hunting Maturity Model (HMM), originally articulated by Sqrrl (now part of Amazon), defines five progressive capability levels for a hunting program.

**Level 0 - Initial (Reliant):** The organization relies entirely on automated alerts. Data collection is inconsistent; logs may not be centralized. Hunts, if any, are unstructured and reactive. Action: Centralize logging (SIEM), establish baseline endpoint telemetry.

**Level 1 - Minimal:** Basic IOC searching: IP/domain/hash lookups against log sources. Hunts triggered by external intelligence (ISAC feeds, vendor advisories). No formal hypothesis framework. Action: Standardize on a query language; introduce Sigma rules; begin documenting findings.

**Level 2 - Procedural:** Adopts community-developed hunting procedures and playbooks. Hunts documented in a repeatable format (hypothesis, scope, queries, findings). Basic TTP-based hunting using ATT&CK as a guide. Action: Build a hunt library; track ATT&CK coverage; establish MTTD baseline.

**Level 3 - Innovative:** Team creates custom hunting procedures from internal data analysis. Statistical and behavioral baselines used to surface anomalies. Machine learning-assisted clustering to identify outliers. Action: Formalize feedback loop to detection engineering; instrument custom telemetry.

**Level 4 - Leading:** Hunting program automates data collection, hypothesis suggestion, and initial analysis. Comprehensive ATT&CK coverage across all data sources. Hunts inform threat intelligence production and purple team exercises. Action: Publish internal research; contribute to community (Sigma, YARA, blog posts).

---

### 1.3 Hunting Approaches

#### Hypothesis-Driven Hunting

Start with a structured "if an attacker did X, we would expect to see Y" statement.

**Hypothesis template:**
```
Given that [threat actor / technique],
an adversary may [specific action],
which would produce [observable artifact]
in [data source / log type].
We will look for [specific indicator / statistical anomaly]
using [query / tool] to confirm or refute this hypothesis.
```

**Example:** Given that APT29 uses spearphishing with macro-enabled Office documents, an adversary may spawn PowerShell or WScript from WINWORD.EXE. We will search process creation events for child processes of Office applications that execute script interpreters.

#### IOC-Based Hunting

Search for known indicators of compromise: IP addresses, domain names, file hashes, registry keys, mutex names. Source IOCs from MISP, TAXII feeds, vendor reports, and ISAC sharing. Limitations: IOCs are ephemeral; sophisticated actors rotate infrastructure frequently.

**IOC pivot methodology:**
1. Match IOC against logs to confirm presence
2. Identify affected hosts and accounts
3. Reconstruct timeline around first IOC contact
4. Search for related behavioral artifacts (process trees, network flows)
5. Discover new IOCs from behavioral context and feed back to TI

#### TTP-Based Hunting

Hunt for adversary techniques regardless of specific IOCs. Aligned to MITRE ATT&CK. More durable than IOC-based hunting (TTPs change slowly vs. infrastructure). Requires richer telemetry (EDR, Sysmon, PowerShell script block logging).

Example: Hunt for T1003.001 (LSASS Memory) by looking for any process opening LSASS with suspicious access rights, regardless of tool name.

---

### 1.4 Sqrrl Hunting Loop

The Sqrrl hunting loop defines four iterative phases:

```
+------------------+     +----------------------+
|  1. Hypothesis   |---->|  2. Investigate      |
|                  |     |                      |
|  Formulate a     |     |  Query data sources  |
|  testable        |     |  Look for anomalies  |
|  statement about |     |  Pivot on findings   |
|  attacker        |     |  Enrich with TI      |
|  activity        |     |                      |
+------------------+     +-----------+----------+
        ^                            |
        |                            v
+-------+-----------+     +----------+-----------+
|  4. Inform        |<----|  3. Uncover           |
|                   |     |                      |
|  Document         |     |  Confirm/refute      |
|  findings         |     |  hypothesis          |
|  Create           |     |  Identify attacker   |
|  detections       |     |  TTPs used           |
|  Update           |     |  Scope impact        |
|  playbooks        |     |                      |
+-------------------+     +----------------------+
```

**Phase 1 - Hypothesis:** Generate from ATT&CK, threat intel, vulnerability disclosures, or internal anomalies. Document in a standardized template.

**Phase 2 - Investigate:** Query logs, EDR telemetry, network flows. Apply statistics (frequency analysis, clustering, regression). Enrich with external context.

**Phase 3 - Uncover:** Determine if the hypothesis is confirmed (true positive), refuted (true negative), or inconclusive. Document all findings regardless of outcome.

**Phase 4 - Inform:** Produce hunt report. Convert confirmed findings to detection rules. Update threat model. Brief stakeholders. Archive hunt in tracking system.

---

### 1.5 Hunting Program Metrics

| Metric | Definition | Target |
|---|---|---|
| Hunts per month | Number of formal hypothesis-driven hunts completed | 4-8 for mature teams |
| New detections generated | Alerts/rules created directly from hunt findings | >= 1 per hunt |
| MTTD improvement | Reduction in mean time to detect vs. previous quarter | 10-20% QoQ |
| ATT&CK coverage | Percentage of techniques with at least one hunt or detection | Track quarterly |
| Data source coverage | Percentage of relevant telemetry sources actively queried | Track quarterly |
| False positive rate | Percentage of alerts from hunt-generated rules that are non-malicious | <20% at 30 days |
| Hunt conversion rate | Percentage of hypotheses yielding at least one actionable finding | Track for improvement |

**Reporting cadence:** Weekly status to team lead; Monthly dashboard to security manager; Quarterly ATT&CK coverage map update; Annually full program review, staffing and tooling recommendations.

---

### 1.6 DetectionLab for Hunting Practice

DetectionLab (by Chris Long / clong) provides a pre-configured Windows AD environment with logging and security tools.

**Components:** DC01 (Windows Server 2019 DC), WEF (Windows Event Forwarding), WIN10 (Windows 10 with Sysmon, Osquery, Splunk UF), Logger (Ubuntu 18.04 with Splunk, Fleet, Zeek, Suricata).

**Setup:**
```bash
git clone https://github.com/clong/DetectionLab
cd DetectionLab/Vagrant
vagrant up --provider virtualbox
# Splunk: https://192.168.56.105:8000 (admin/changeme)
# Fleet: https://192.168.56.105:8412 (admin@detectionlab.network/admin123#)
```

**Sysmon events covered (SwiftOnSecurity/sysmon-config):**
- Event ID 1: Process Create
- Event ID 3: Network Connection
- Event ID 7: Image Loaded
- Event ID 8: CreateRemoteThread
- Event ID 10: ProcessAccess
- Event ID 11: FileCreate
- Event ID 13: RegistryEvent (Value Set)
- Event ID 22: DNSEvent

**Test activity generation:**
```powershell
Invoke-Mimikatz -DumpCreds
Enter-PSSession -ComputerName DC01 -Credential $creds
schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -enc <base64>" /sc daily
```

---

## 2. KQL Threat Hunting (Microsoft Sentinel / Defender XDR)

### 2.1 KQL Fundamentals

Kusto Query Language (KQL) is used in Microsoft Sentinel, Defender XDR, Azure Monitor, and Azure Data Explorer.

**Core operators:**
```kql
// project - select columns
SecurityEvent | project TimeGenerated, Account, EventID, Computer, Activity

// extend - computed columns
SecurityEvent | extend HourOfDay = hourofday(TimeGenerated)

// where - filter rows
SecurityEvent | where EventID == 4624 and LogonType == 3

// summarize - aggregate
SecurityEvent | summarize Count=count() by Account, bin(TimeGenerated, 1h)

// join - combine tables
SecurityEvent
| where EventID == 4624
| join kind=inner (SecurityEvent | where EventID == 4648) on Account

// parse - extract from strings
SecurityEvent | parse CommandLine with * "-enc " EncodedCommand " " *

// mv-expand - expand dynamic arrays
DeviceNetworkEvents | mv-expand ParsedFields

// top
SecurityEvent | summarize Count=count() by Account | top 20 by Count desc

// let - variables
let timeframe = 24h;
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4625
| summarize FailCount=count() by Account
| where FailCount > 5
```

**Key functions:** tolower(), toupper(), strlen(), ago(), now(), bin(), datetime_diff(), hourofday(), dayofweek(), log(), round(), percentile(), bag_keys(), array_length(), set_union(), tostring(), toint(), todatetime()

---

### 2.2 Suspicious PowerShell Execution Detection

```kql
// Hunt: Suspicious PowerShell Execution
// ATT&CK: T1059.001

let timeframe = 7d;
let suspiciousFlags = dynamic(["-enc", "-encodedcommand", "-nop", "-noni",
    "-windowstyle hidden", "-w hidden", "-exec bypass", "-executionpolicy bypass",
    "iex", "invoke-expression", "downloadstring", "downloadfile",
    "webclient", "net.webclient", "bitstransfer"]);
DeviceProcessEvents
| where Timestamp >= ago(timeframe)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (suspiciousFlags)
| extend
    IsEncoded = ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-encodedcommand",
    HasDownloadCradle = ProcessCommandLine has_any (dynamic(["downloadstring", "downloadfile", "webclient"])),
    IsHidden = ProcessCommandLine has_any (dynamic(["-windowstyle hidden", "-w hidden"])),
    IsBypassExec = ProcessCommandLine has_any (dynamic(["-exec bypass", "-executionpolicy bypass"]))
| extend SuspicionScore = toint(IsEncoded) + toint(HasDownloadCradle) + toint(IsHidden) + toint(IsBypassExec)
| where SuspicionScore >= 2
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    ProcessCommandLine, IsEncoded, HasDownloadCradle, IsHidden, SuspicionScore
| order by SuspicionScore desc, Timestamp desc

// Decode base64 encoded commands
DeviceProcessEvents
| where Timestamp >= ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}"
| extend EncodedPart = extract(@"(?i)-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend DecodedCommand = base64_decode_tostring(EncodedPart)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, DecodedCommand
```

---

### 2.3 LSASS Access Patterns (Credential Dumping)

```kql
// Hunt: LSASS Memory Access
// ATT&CK: T1003.001

let timeframe = 7d;
let legitimateLsassAccessors = dynamic([
    "MsMpEng.exe", "WerFault.exe", "svchost.exe", "csrss.exe",
    "wininit.exe", "lsm.exe", "taskmgr.exe"
]);
DeviceEvents
| where Timestamp >= ago(timeframe)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where not(InitiatingProcessFileName in~ (legitimateLsassAccessors))
| extend SuspiciousAccess = ProcessAccessRights in~ (dynamic(["0x1010", "0x1410", "0x0410", "0x1fffff"]))
| project Timestamp, DeviceName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, ProcessAccessRights, AccountName, SuspiciousAccess
| order by Timestamp desc

// Sysmon Event 10 in Sentinel
Sysmon
| where EventID == 10
| where TargetImage endswith "lsass.exe"
| where not(SourceImage has_any (legitimateLsassAccessors))
| where GrantedAccess in ("0x1010", "0x1410", "0x0410", "0x1fffff", "0x1438")
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess, CallTrace
| order by TimeGenerated desc
```

---

### 2.4 Kerberoasting Detection

```kql
// Hunt: Kerberoasting
// ATT&CK: T1558.003

let timeframe = 7d;
let excludedAccounts = dynamic(["krbtgt", "ANONYMOUS LOGON"]);
SecurityEvent
| where TimeGenerated >= ago(timeframe)
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4 - indicates Kerberoasting tools
| where ServiceName !endswith "$"
| where not(ServiceName in~ (excludedAccounts))
| summarize
    RequestCount = count(),
    UniqueServices = dcount(ServiceName),
    ServiceList = make_set(ServiceName, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account, IpAddress
| where RequestCount >= 3 or UniqueServices >= 3
| extend
    IsLikelyKerberoasting = UniqueServices >= 5,
    TimeDeltaSeconds = datetime_diff("second", LastSeen, FirstSeen)
| order by UniqueServices desc, RequestCount desc
```

---

### 2.5 DNS Beaconing Detection

```kql
// Hunt: DNS Beaconing - Regular Interval Queries
// ATT&CK: T1071.004

let timeframe = 24h;
DnsEvents
| where TimeGenerated >= ago(timeframe)
| where QueryType == "A" or QueryType == "AAAA"
| where not(Name endswith ".microsoft.com" or Name endswith ".windows.com"
    or Name endswith ".office.com" or Name endswith ".google.com")
| summarize
    QueryTimes = make_list(TimeGenerated),
    QueryCount = count()
    by ClientIP, Name
| where QueryCount >= 20
| extend QueryRate = QueryCount / 24.0
| where QueryRate >= 1
| project ClientIP, Name, QueryCount, QueryRate, QueryTimes
| order by QueryCount desc

// Beacon analysis using average interval
let timeframe = 24h;
DnsEvents
| where TimeGenerated >= ago(timeframe)
| summarize QueryTimes=make_list(TimeGenerated, 1000) by ClientIP, Name
| where array_length(QueryTimes) >= 20
| extend Count = array_length(QueryTimes)
| extend TotalSpanSec = datetime_diff("second", tostring(QueryTimes[-1]), tostring(QueryTimes[0]))
| extend AvgIntervalSec = TotalSpanSec / (Count - 1)
| where AvgIntervalSec between (30 .. 3600)
| project ClientIP, Name, Count, AvgIntervalSec
| order by Count desc
```

---

### 2.6 Impossible Travel Detection

```kql
// Hunt: Impossible Travel
// ATT&CK: T1078

let timeframe = 7d;
let impossibleSpeedKmH = 900.0;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultType == 0
| extend
    Latitude = toreal(LocationDetails.geoCoordinates.latitude),
    Longitude = toreal(LocationDetails.geoCoordinates.longitude),
    Country = tostring(LocationDetails.countryOrRegion)
| where isnotnull(Latitude) and isnotnull(Longitude)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, Latitude, Longitude
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend
    PrevTime = prev(TimeGenerated, 1),
    PrevLat = prev(Latitude, 1),
    PrevLon = prev(Longitude, 1),
    PrevCountry = prev(Country, 1),
    PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDeltaMin = datetime_diff("minute", TimeGenerated, PrevTime)
| where TimeDeltaMin >= 30 and PrevCountry != Country
| extend
    DeltaLatRad = (Latitude - PrevLat) * 3.14159 / 180,
    DeltaLonRad = (Longitude - PrevLon) * 3.14159 / 180,
    Lat1Rad = PrevLat * 3.14159 / 180,
    Lat2Rad = Latitude * 3.14159 / 180
| extend A = pow(sin(DeltaLatRad / 2), 2) + cos(Lat1Rad) * cos(Lat2Rad) * pow(sin(DeltaLonRad / 2), 2)
| extend DistanceKm = 2 * 6371 * asin(sqrt(A))
| extend ImpliedSpeedKmH = DistanceKm / (toreal(TimeDeltaMin) / 60.0)
| where ImpliedSpeedKmH > impossibleSpeedKmH
| project TimeGenerated, UserPrincipalName, PrevCountry, Country,
    DistanceKm=round(DistanceKm, 1), TimeDeltaMin, ImpliedSpeedKmH=round(ImpliedSpeedKmH, 1)
| order by ImpliedSpeedKmH desc
```

---

### 2.7 Lateral Movement Detection (SMB + RDP + WMI)

```kql
// Hunt: Multi-protocol Lateral Movement Correlation
// ATT&CK: T1021.001 (RDP), T1021.002 (SMB), T1047 (WMI)

let timeframe = 7d;
let smbLateral = SecurityEvent
| where TimeGenerated >= ago(timeframe) and EventID == 4648
| where TargetServerName != "localhost" and TargetServerName != ComputerName
| where not(Account endswith "$")
| project Time=TimeGenerated, SourceHost=ComputerName, DestHost=TargetServerName, Account, Method="SMB";

let rdpLateral = SecurityEvent
| where TimeGenerated >= ago(timeframe) and EventID == 4624 and LogonType == 10
| where IpAddress !startswith "127." and isnotempty(IpAddress)
| project Time=TimeGenerated, SourceHost=IpAddress, DestHost=Computer, Account, Method="RDP";

let wmiLateral = DeviceProcessEvents
| where Timestamp >= ago(timeframe)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName !in~ ("WmiPrvSE.exe", "svchost.exe")
| project Time=Timestamp, SourceHost=InitiatingProcessAccountName,
    DestHost=DeviceName, Account=AccountName, Method="WMI";

union smbLateral, rdpLateral, wmiLateral
| summarize
    Methods = make_set(Method),
    MethodCount = dcount(Method),
    HopCount = dcount(DestHost),
    DestHosts = make_set(DestHost, 20),
    FirstSeen = min(Time), LastSeen = max(Time)
    by Account, SourceHost
| where MethodCount >= 2 or HopCount >= 3
| order by HopCount desc, MethodCount desc
```

---

### 2.8 KQL Hunting Query Repositories

- **SlimKQL/Hunting-Queries-Detection-Rules:** https://github.com/SlimKQL/Hunting-Queries-Detection-Rules
- **f-bader/AzSentinelQueries:** https://github.com/f-bader/AzSentinelQueries
- **reprise99/Sentinel-Queries:** https://github.com/reprise99/Sentinel-Queries
- **Azure-Sentinel (official):** https://github.com/Azure/Azure-Sentinel/tree/master/Hunting%20Queries
- **Microsoft-365-Defender-Hunting-Queries:** https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries
- **KQL Search:** https://www.kqlsearch.com/

---

## 3. Splunk SPL Threat Hunting

### 3.1 SPL Fundamentals

```splunk
| search index=wineventlog EventCode=4625
| stats count by user, src_ip
| where count > 5
| rex field=_raw "CommandLine=(?P<cmd>[^\r\n]+)"
| transaction maxspan=5m user
| sort -count
| table _time, user, src_ip, count
| rename src_ip as "Source IP"
| dedup user
| head 100
| chart count by user, EventCode
| timechart span=1h count by EventCode
| lookup threat_intel ip as src_ip OUTPUT threat_category
| inputlookup baseline_processes.csv
```

**SPL functions:**
```splunk
| eval len = len(field)
| eval hour = strftime(_time, "%H")
| eval weekday = strftime(_time, "%A")
| stats stdev(interval) as jitter avg(interval) as avg_interval by src_ip, dest
| streamstats count by user
| eventstats avg(count) as avg_count stdev(count) as stdev_count by dest_ip
| tstats count WHERE index=endpoint by _time host
```

---

### 3.2 Beaconing Detection Using Standard Deviation

```splunk
// Detect C2 beaconing via statistical regularity of connection intervals
// Data source: Zeek, Palo Alto, Squid proxy logs

index=network sourcetype=zeek_conn dest_port IN (80, 443)
| bin _time span=1m
| stats count as conns_per_min by _time, src_ip, dest_ip
| stats
    avg(conns_per_min) as avg_conns,
    stdev(conns_per_min) as stdev_conns,
    count as active_minutes,
    max(_time) as last_seen, min(_time) as first_seen
    by src_ip, dest_ip
| where active_minutes >= 60
| eval jitter_ratio = stdev_conns / avg_conns
| where jitter_ratio < 0.2 AND avg_conns > 0.5
| eval beacon_score = round((1 - jitter_ratio) * 100, 1)
| table src_ip, dest_ip, avg_conns, stdev_conns, jitter_ratio, active_minutes, beacon_score
| sort -beacon_score
```

---

### 3.3 Rare Parent-Child Process Relationships

```splunk
// Detect unusual parent-child process spawning
// Data source: Sysmon EventID 1

index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| stats
    count as spawn_count,
    dc(Computer) as host_count,
    values(CommandLine) as sample_cmdlines
    by ParentImage, Image
| where spawn_count < 5 AND host_count < 3
| search NOT ParentImage IN ("C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\explorer.exe")
| eval rare_combo = ParentImage . " -> " . Image
| eval suspicion = case(
    match(ParentImage, "(?i)\\b(winword|excel|powerpnt|outlook|acrord32)\\.exe$")
        AND match(Image, "(?i)\\b(cmd|powershell|wscript|cscript|mshta|certutil|bitsadmin)\\.exe$"), "HIGH",
    match(ParentImage, "(?i)\\bsvchost\\.exe$")
        AND match(Image, "(?i)\\b(cmd|powershell|wscript)\\.exe$"), "HIGH",
    match(Image, "(?i)\\b(mshta|regsvr32|rundll32|certutil)\\.exe$"), "MEDIUM",
    true(), "LOW"
)
| where suspicion IN ("HIGH", "MEDIUM")
| table rare_combo, spawn_count, host_count, suspicion, sample_cmdlines
| sort suspicion, -spawn_count
```

---

### 3.4 DGA Domain Detection Using Character Analysis

```splunk
// Detect DGA domains via character frequency analysis
// Data source: Sysmon EventID 22 or network DNS

index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=22
| rex field=QueryName "^(?P<subdomain>[^.]+)\\.(?P<tld>.+)$"
| eval domain_len = len(subdomain)
| where domain_len >= 8
| eval
    char_set = split(lower(subdomain), ""),
    vowel_count = mvcount(mvfilter(match(char_set, "^[aeiou]$"))),
    digit_count = mvcount(mvfilter(match(char_set, "^[0-9]$")))
| eval vowel_ratio = vowel_count / domain_len
| eval digit_ratio = digit_count / domain_len
| where vowel_ratio < 0.20 AND domain_len >= 10 AND digit_ratio < 0.3
| stats
    count as query_count,
    dc(Computer) as host_count,
    dc(QueryName) as unique_domains,
    values(QueryName) as sample_domains
    by subdomain, tld
| where host_count <= 2 AND unique_domains >= 1
| eval dga_score = (domain_len * 0.3) + ((1 - vowel_ratio) * 70)
| sort -dga_score
| table subdomain, tld, domain_len, vowel_ratio, digit_ratio, query_count, host_count, dga_score, sample_domains
```

---

### 3.5 Credential Access via LSASS (Sysmon Event 10)

```splunk
// Detect LSASS memory access - credential dumping

index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10
    TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)(MsMpEng|WerFault|csrss|wininit|lsm|svchost)\\.exe$")
| eval
    suspicious_access = if(match(GrantedAccess, "^(0x1010|0x1410|0x0410|0x1fffff|0x1438)$"), 1, 0),
    has_calltrace_anomaly = if(
        match(CallTrace, "(?i)(unknown|unbacked|UNKNOWN_MODULE)") OR
        NOT match(CallTrace, "ntdll\\.dll"), 1, 0
    )
| eval risk_score = (suspicious_access * 50) + (has_calltrace_anomaly * 30)
| where risk_score >= 50
| stats
    count as access_count,
    values(GrantedAccess) as access_rights,
    values(CallTrace) as call_traces,
    max(risk_score) as max_risk
    by Computer, SourceImage, TargetImage
| sort -max_risk
| table Computer, SourceImage, access_count, access_rights, max_risk, call_traces
```

---

### 3.6 Lateral Movement via Scheduled Tasks (Event 4698)

```splunk
// Detect suspicious scheduled task creation

index=wineventlog EventCode=4698
| rex field=_raw "Task Name:\s+(?P<task_name>[^\r\n]+)"
| rex field=_raw "Command>(?P<task_command>[^<]+)<"
| eval
    has_encoded = if(match(task_command, "(?i)-enc|-encodedcommand"), 1, 0),
    has_download = if(match(task_command, "(?i)downloadstring|downloadfile|webclient|curl|wget|bitsadmin"), 1, 0),
    has_script_host = if(match(task_command, "(?i)(wscript|cscript|mshta|regsvr32)"), 1, 0)
| eval risk = has_encoded + has_download + has_script_host
| where risk >= 1
| stats
    count as creation_count,
    values(task_name) as task_names,
    values(task_command) as commands,
    dc(ComputerName) as affected_hosts
    by SubjectUserName, SubjectDomainName
| sort -risk -count
| table SubjectUserName, SubjectDomainName, creation_count, affected_hosts, task_names, commands
```

---

### 3.7 mthcht/ThreatHunting-Keywords Integration

The ThreatHunting-Keywords project (by mthcht) provides a curated list of keywords associated with offensive tools, LOLBins, and attacker tradecraft.

```splunk
// Load keywords from lookup table (import CSV from GitHub)
| inputlookup threathunting_keywords.csv
| where category IN ("offensive_tool", "lolbin", "c2_framework")
| table keyword, category, description, reference

// Hunt process events for known offensive tool names
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| rex field=CommandLine "(?i)(?P<found_keyword>mimikatz|rubeus|sharphound|cobalt|meterpreter|empire|havoc|sliver)"
| where isnotnull(found_keyword)
| stats count by found_keyword, Computer, User, CommandLine
| sort -count

// Broad keyword search using inputlookup format
index=endpoint
    [| inputlookup threathunting_keywords.csv
     | where risk_level="high"
     | fields keyword
     | format]
| stats count, values(host) as affected_hosts by keyword, sourcetype
| sort -count
```

**Reference:** https://github.com/mthcht/ThreatHunting-Keywords

---

## 4. Sigma Rules

### 4.1 Sigma Format Overview

Sigma is a generic, vendor-agnostic signature format for SIEM detection rules. Rules are written in YAML and compiled to platform-specific query languages.

**Full Sigma rule structure:**
```yaml
title: Suspicious PowerShell Encoded Command Execution
id: 7f93d3b2-1a4c-4e9d-b8c6-2e5f1234abcd
status: experimental
description: |
  Detects execution of PowerShell with encoded command parameter,
  commonly used by attackers to obfuscate malicious commands.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://github.com/SigmaHQ/sigma
author: TeamStarWolf
date: 2024/01/15
modified: 2024/03/20
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
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_flags:
    CommandLine|contains|all:
      - '-enc'
  selection_flags_alt:
    CommandLine|contains:
      - '-encodedcommand'
  condition: selection_main and (selection_flags or selection_flags_alt)
falsepositives:
  - Legitimate administrative scripts using encoded commands
  - Software deployment tools (SCCM, etc.)
level: medium
```

---

### 4.2 Sigma Detection Logic

**Field modifiers:**
- `contains` - substring match
- `startswith` / `endswith` - prefix/suffix match
- `contains|all` - AND logic: all items in list must match
- `contains` list - OR logic: any item in list matches
- `re` - regular expression match
- `base64offset|contains` - detect base64-encoded strings
- `windash` - handles Windows dash/slash flag variations (-enc and /enc)
- `nocase` - case-insensitive match

**Condition operators:**
```yaml
# AND, OR, NOT
condition: selection1 and selection2
condition: selection1 or selection2
condition: selection1 and not filter1

# Aggregation
condition: selection | count() > 5
condition: selection | count(field) > 3

# Complex
condition: (selection_a or selection_b) and not filter_legitimate
```

---

### 4.3 Writing Rules from Scratch

**Step 1:** Identify the technique - reference ATT&CK for sub-technique details; review malware analysis reports and tool documentation.

**Step 2:** Identify the data source - what log type captures this activity? Map to Sigma logsource categories: `process_creation`, `network_connection`, `file_event`, `registry_event`, `dns_query`.

**Step 3:** Define the signature - what fields and values uniquely identify the behavior? Add filter conditions for known-good processes/paths to reduce false positives.

**DCSync detection example:**
```yaml
title: DCSync Attack - Replication Privilege Abuse
id: a0b1c2d3-e4f5-6789-abcd-ef0123456789
status: stable
description: |
  Detects DCSync attack where an adversary replicates domain credentials
  by abusing AD replication rights (DS-Replication-Get-Changes-All).
references:
  - https://attack.mitre.org/techniques/T1003/006/
author: TeamStarWolf
date: 2024/01/15
tags:
  - attack.credential_access
  - attack.t1003.006
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  filter_dc:
    SubjectUserName|endswith: '$'
    SubjectUserName|contains: 'MSOL_'
  condition: selection and not filter_dc
falsepositives:
  - Domain Controllers performing legitimate replication
  - Azure AD Connect accounts (MSOL_*)
  - Backup solutions with replication rights
level: high
```

---

### 4.4 Sigma Compiler: sigmac and pySigma

**Using sigmac (legacy):**
```bash
pip install sigmatools
sigmac -t splunk -c splunk-windows rules/windows/credential_access/lsass_access.yml
sigmac -t azure-monitor -c azure-monitor rules/windows/credential_access/lsass_access.yml
sigmac -t es-qs -c ecs-windows rules/windows/credential_access/lsass_access.yml
sigmac -t splunk -c splunk-windows rules/windows/credential_access/*.yml -r
```

**Using sigma-cli (pySigma - recommended):**
```bash
pip install sigma-cli
sigma list backends
sigma plugin install splunk
sigma plugin install microsoft365defender
sigma convert -t splunk rules/windows/credential_access/proc_access_win_lsass_memdump.yml
sigma convert -t splunk -p sysmon rules/windows/credential_access/proc_access_win_lsass_memdump.yml
sigma convert -t microsoft365defender rules/windows/ -r -o output_queries.txt
sigma check rules/windows/credential_access/proc_access_win_lsass_memdump.yml
```

---

### 4.5 ATT&CK Tagging in Sigma

```yaml
tags:
  # Tactic tags
  - attack.initial_access
  - attack.execution
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.credential_access
  - attack.discovery
  - attack.lateral_movement
  - attack.collection
  - attack.command_and_control
  - attack.exfiltration
  - attack.impact

  # Technique tags (T-number, lowercase, dots preserved)
  - attack.t1059.001  # PowerShell
  - attack.t1003.001  # LSASS Memory
  - attack.t1021.002  # SMB/Windows Admin Shares

  # Software and group tags
  - attack.s0002  # Mimikatz
  - attack.s0154  # Cobalt Strike
  - attack.g0016  # APT29
```

---

### 4.6 Community Rule Repositories

- **SigmaHQ/sigma (official):** https://github.com/SigmaHQ/sigma - 3000+ rules
- **detection.fyi:** https://detection.fyi - Sigma rule search engine
- **Sigma Rule Explorer:** https://sigmasearchengine.com/
- **Elastic Detection Rules:** https://github.com/elastic/detection-rules
- **Panther-Labs:** https://github.com/panther-labs/panther-analysis

---

## 5. YARA Rules for Threat Hunting

### 5.1 YARA Rule Structure

YARA (Yet Another Ridiculous Acronym) is a pattern-matching tool for identifying malware based on textual or binary patterns.

```yara
rule Mimikatz_Memory_Strings
{
    meta:
        description = "Detects Mimikatz credential dumper in memory or on disk"
        author = "TeamStarWolf"
        date = "2024-01-15"
        reference = "https://github.com/gentilkiwi/mimikatz"
        mitre_attack = "T1003.001"
        severity = "critical"
        tlp = "WHITE"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii nocase
        $s2 = "lsadump::sam" ascii nocase
        $s3 = "privilege::debug" ascii nocase
        $s4 = "mimikatz" ascii nocase wide
        $h1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 80 3D ?? ?? ?? ?? 00 }
        $r1 = /sekurlsa::[a-z]+/ nocase
        $w1 = "mimikatz" wide
        $combo1 = "wdigest" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 10MB
        and (
            2 of ($s*)
            or any of ($h*)
            or $r1
        )
}
```

---

### 5.2 String Types and Modifiers

```yara
strings:
    $ascii = "malware"                          // ASCII text (default)
    $hex = { 4D 5A 90 00 03 00 00 00 }          // Hex bytes
    $hex_wild = { 4D 5A ?? 00 ?? ?? 00 00 }     // Single-byte wildcards
    $hex_range = { 4D [2-4] 5A }                // Range wildcard
    $hex_alt = { 4D (5A | 4E) 90 }             // Alternation in hex
    $re = /https?:\/\/[a-z0-9]{8,}\.onion/     // Regular expression
    $nocase = "Mimikatz" nocase                 // Case-insensitive
    $wide = "kernel32.dll" wide                 // UTF-16LE encoding
    $ascii_wide = "malware" ascii wide          // Both ASCII and wide
    $fullword = "cmd" fullword                  // Whole word boundaries only
    $xor_s = { 4D 5A } xor                     // XOR with single byte key (YARA 3.9+)
    $b64 = "malicious" base64                   // Base64 encoded version (YARA 4.0+)
    $b64wide = "malicious" base64wide           // Base64 of wide string
```

---

### 5.3 Condition Operators and Logic

```yara
condition:
    $a and $b                   // Both must match
    $a or $b                    // Either must match
    not $a                      // Must not match
    #a == 5                     // Exactly 5 occurrences
    #a >= 2                     // At least 2 occurrences
    all of ($s*)                // All strings in $s group
    any of ($s*)                // Any string in $s group
    2 of ($s*)                  // At least 2 of $s group
    all of them                 // All defined strings
    $a at 0                     // Exact offset 0 (fastest check - use for PE magic)
    $a at 0x100                 // String at specific offset
    $a in (0x100..0x200)        // String within byte range
    filesize < 5MB              // File size constraint
    uint16(0) == 0x5A4D         // PE MZ header check
    uint32(0) == 0x464C45       // ELF magic check
    uint32(0) == 0xBEBAFECA     // Mach-O fat binary
```

---

### 5.4 YARA Module Usage

**PE module:**
```yara
import "pe"

rule Suspicious_PE_Characteristics
{
    meta:
        description = "Detects PE with process injection import combination"

    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread") and
        pe.number_of_sections < 3
}
```

**Math module (entropy for packed/encrypted sections):**
```yara
import "math"

rule High_Entropy_Section
{
    meta:
        description = "Detects packed or encrypted PE sections via high entropy"

    condition:
        pe.is_pe and
        for any i in (0..pe.number_of_sections - 1):
        (
            math.entropy(pe.sections[i].raw_data_offset,
                         pe.sections[i].raw_data_size) > 7.0
            and pe.sections[i].raw_data_size > 4096
        )
}
```

---

### 5.5 yarGen - Automatic Rule Generation

yarGen (by Florian Roth / Neo23x0) generates YARA rules automatically from malware samples by extracting unique strings not found in goodware databases.

**Installation:**
```bash
pip install yara-python
git clone https://github.com/Neo23x0/yarGen
cd yarGen
pip install -r requirements.txt
python yarGen.py --update   # Download goodware string databases (~1.5GB)
```

**Usage:**
```bash
python yarGen.py -m /path/to/malware/sample.exe -o output_rule.yar
python yarGen.py -m /malware/samples/ -o rules/new_malware_family.yar
python yarGen.py -m /malware/ -e /path/to/goodware/ -o output.yar
python yarGen.py -m /malware/ --score 75 -o output.yar
python yarGen.py -m /malware/ -v -o output.yar
```

**Quality improvement tips:**
1. Test against clean system32 before deploying (should have zero hits)
2. Remove generic Windows API strings from selected strings
3. Add PE module conditions (imphash, section count, import checks)
4. Use minimum score threshold to include only highly unique strings

---

### 5.6 YARA Scanning with yara-python

```python
import yara, os

rules = yara.compile('my_rules.yar')

# Single file scan
matches = rules.match('/path/to/suspicious/file.exe')
for match in matches:
    print(f"Rule: {match.rule}, Tags: {match.tags}")
    for string_match in match.strings:
        print(f"  String: {string_match.identifier}")

# Directory scan
def scan_directory(path, rule_set):
    for root, dirs, files in os.walk(path):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                hits = rule_set.match(filepath)
                if hits:
                    print(f"MATCH in {filepath}: {[h.rule for h in hits]}")
            except yara.Error:
                pass

scan_directory('/suspicious/directory/', rules)

# Process memory scan (requires elevated privileges on Windows)
pid = 1234
matches = rules.match(pid=pid)
```

---

### 5.7 Integration with Velociraptor and THOR

**Velociraptor YARA artifact:**
```yaml
name: Custom.YARA.FileScan
description: Scan files with custom YARA rules
sources:
  - query: |
      SELECT * FROM foreach(
        row=glob(globs=["C:/Users/**", "C:/Temp/**", "C:/Windows/Temp/**"]),
        query={
          SELECT FullPath, Size,
            yara(rules=YaraRules, files=FullPath) as YaraHits
          FROM scope()
          WHERE YaraHits
        }
      )
parameters:
  - name: YaraRules
    type: yara
    default: |
      rule Suspicious_Downloader {
        strings:
          $s1 = "DownloadString" nocase
          $s2 = "DownloadFile" nocase
        condition: any of them
      }
```

**THOR (Nextron Systems) CLI:**
```bash
thor64.exe --yara /custom/yara/rules/ --outputfile report.txt
thor-lite-win.exe --quick --outputfile scan_results.txt
```

**Key YARA repositories:**
- **Neo23x0/signature-base:** https://github.com/Neo23x0/signature-base
- **CAPE Sandbox YARA:** https://github.com/kevoreilly/CAPEv2/tree/master/data/yara
- **YARAify:** https://yaraify.abuse.ch/

---

## 6. ATT&CK-Aligned Hunting Playbooks

### 6.1 Overview

For each ATT&CK tactic, specific hunt hypotheses, key observables, and representative queries are provided for both Splunk SPL and KQL.

---

### 6.2 TA0001 - Initial Access

**Hypothesis:** An adversary sent a spearphishing email with a macro-enabled Office attachment that executed a payload upon opening.

**Key observables:** Office applications spawning scripting hosts; WINWORD.EXE creating executables in %TEMP%; network connections from Office processes.

```splunk
// Splunk: Office spawning script interpreters
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| where match(ParentImage, "(?i)(WINWORD|EXCEL|POWERPNT|OUTLOOK|AcroRd32|FoxitReader)\\.exe$")
| where match(Image, "(?i)(cmd|powershell|wscript|cscript|mshta|certutil|regsvr32|rundll32)\\.exe$")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

```kql
// KQL: Office child process spawning
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

---

### 6.3 TA0002 - Execution

**Hypothesis:** An adversary used LOLBins to execute malicious code while evading signature detection.

**Key LOLBins:** `mshta.exe` (HTA/VBScript execution), `regsvr32.exe` (Squiblydoo/COM scripts), `certutil.exe` (download/decode), `rundll32.exe` (DLL exports), `wmic.exe` (remote process execution), `msiexec.exe` (MSI from URL), `forfiles.exe` (per-file command execution).

```splunk
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| eval lolbin_flag = if(match(Image, "(?i)(mshta|regsvr32|certutil|rundll32|wmic|msiexec|forfiles|pcalua|cmstp|installutil)\\.exe$"), 1, 0)
| where lolbin_flag == 1
| where match(CommandLine, "(?i)(http|ftp|\\\\\\\\|\\.hta|scriptlet|scrobj|javascript|vbscript)")
| stats count by Image, CommandLine, Computer
| sort -count
```

---

### 6.4 TA0003 - Persistence

**Hypothesis:** An adversary established persistence via registry Run keys pointing to user-writable paths.

```kql
// Registry Run key additions to non-standard paths
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
)
| where not(RegistryValueData has_any (
    "C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\"
))
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData
```

**WMI event subscription persistence (Sysmon EventIDs 19/20/21):**
```splunk
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode IN (19, 20, 21)
| table _time, Computer, User, EventCode, Name, Type, Destination, Query, Consumer
```

---

### 6.5 TA0004 - Privilege Escalation

**Hypothesis:** An adversary exploited a UAC bypass via fodhelper or eventvwr registry hijacking.

```splunk
// UAC bypass via ms-settings registry key hijack
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=13
| where match(RegistryPath, "(?i)(ms-settings|Software\\\\Classes\\\\ms-settings)\\\\shell\\\\open\\\\command")
| table _time, Computer, User, RegistryPath, Details
```

---

### 6.6 TA0005 - Defense Evasion

**Hypothesis:** An adversary cleared Windows event logs to conceal activity.

```kql
// Event log clearing
SecurityEvent
| where EventID in (1102, 104)
| project TimeGenerated, Computer, Account, EventID, Activity
| order by TimeGenerated desc
```

---

### 6.7 TA0006 - Credential Access

**Hypothesis:** An adversary performed a DCSync attack from a non-Domain-Controller workstation.

```splunk
// DCSync via replication rights abuse (Event 4662)
index=wineventlog EventCode=4662
| where match(Properties, "1131f6ad|1131f6aa|89e95b76")
| where NOT match(SubjectUserName, "\\$$")
| where NOT match(SubjectUserName, "^MSOL_")
| table _time, SubjectUserName, SubjectDomainName, Properties, Computer
```

**Kerberoasting + LSASS dump correlation:**
```kql
let kerberoasting = SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize KerbCount=count() by Account, bin(TimeGenerated, 1h);
let lsassDump = DeviceEvents
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| summarize DumpCount=count() by AccountName, bin(Timestamp, 1h)
| project-rename Account=AccountName, TimeGenerated=Timestamp;
kerberoasting
| join kind=leftouter lsassDump on Account, TimeGenerated
| where KerbCount >= 3
| extend CredentialAttack = isnotempty(DumpCount)
```

---

### 6.8 TA0007 - Discovery

**Hypothesis:** An adversary ran BloodHound/SharpHound to enumerate Active Directory via high-volume LDAP queries.

```splunk
// BloodHound LDAP enumeration via Zeek LDAP logs
index=network sourcetype=zeek_ldap
| stats
    count as ldap_queries,
    dc(request.base) as unique_bases,
    values(request.filter) as filters
    by id.orig_h
| where ldap_queries > 500 AND unique_bases > 20
| sort -ldap_queries
```

---

### 6.9 TA0008 - Lateral Movement

**Hypothesis:** An adversary moved laterally via WMI remote execution, spawning processes through WmiPrvSE.exe.

```kql
// WMI remote process execution
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName !in~ ("WmiPrvSE.exe", "svchost.exe", "msiexec.exe")
| extend IsScriptHost = FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| where IsScriptHost or ProcessCommandLine has_any ("IEX", "-enc", "http", "\\\\")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
```

**Pass-the-Hash (NTLM network logon from unusual source):**
```splunk
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where NOT match(AccountName, "\\$$")
| where NOT match(IpAddress, "^(127|::1)")
| stats count as logon_count, dc(Computer) as target_hosts, values(Computer) as targets
    by AccountName, IpAddress
| where logon_count > 5 AND target_hosts > 3
| sort -logon_count
```

---

### 6.10 TA0011 - Command and Control

**Hypothesis:** An adversary used DNS tunneling to exfiltrate data and receive commands via long subdomain queries.

```splunk
// Long DNS subdomain queries (DNS tunneling indicator)
index=network sourcetype=zeek_dns
| where len(query) > 50
| eval subdomain_count = mvcount(split(query, ".")) - 2
| where subdomain_count > 4
| stats count, values(query) as sample_queries, dc(id.orig_h) as clients by answers
| where count > 5
| sort -count
```

---

### 6.11 TA0010 - Exfiltration

**Hypothesis:** An adversary exfiltrated data by uploading to cloud storage services.

```kql
// Large outbound transfers to cloud storage
DeviceNetworkEvents
| where RemoteUrl has_any ("amazonaws.com", "blob.core.windows.net",
    "storage.googleapis.com", "dropboxapi.com", "onedrive.live.com",
    "mega.nz", "anonfiles.com", "transfer.sh")
| summarize
    TotalBytes = sum(SentBytes),
    SessionCount = count(),
    FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, AccountName, RemoteUrl
| where TotalBytes > 100000000
| extend TotalMB = round(toreal(TotalBytes) / 1048576, 2)
| order by TotalBytes desc
```

---

## 7. Velociraptor for Threat Hunting

### 7.1 Architecture Overview

Velociraptor is an open-source DFIR and threat hunting platform using a server/client model with VQL (Velociraptor Query Language).

```
+-------------------------------+
|     Velociraptor Server       |
|  +--------+  +-----------+   |
|  | Web UI |  |    API    |   |
|  +---+----+  +-----+-----+   |
|      +-----------+            |
|  +---+-----------+----------+ |
|  |    Datastore / Flows     | |
|  +----------+---------------+ |
|             | (gRPC TLS)       |
+-------------+-----------------+
              |
   +----------+----------+
+--+----+  +--+----+  +--+----+
|Client1|  |Client2|  |Client3|
|Windows|  |Linux  |  |macOS  |
+-------+  +-------+  +-------+
```

**Server setup:**
```bash
wget https://github.com/Velocidex/velociraptor/releases/download/v0.7.0/velociraptor-v0.7.0-linux-amd64
./velociraptor config generate -i
./velociraptor --config server.config.yaml frontend -v
# Windows client
velociraptor.exe --config client.config.yaml service install
```

---

### 7.2 VQL (Velociraptor Query Language)

VQL is SQL-inspired and queries endpoint state through built-in plugins.

```vql
-- Basic queries
SELECT * FROM pslist()
SELECT Pid, Name, Exe FROM pslist()
SELECT * FROM pslist() WHERE Name =~ "powershell"

-- JOIN processes with network connections
SELECT * FROM foreach(
    row={SELECT Pid FROM pslist() WHERE Name="svchost.exe"},
    query={SELECT * FROM netstat() WHERE Pid=row.Pid}
)

-- LET for variable definitions
LET suspicious_procs = SELECT Pid, Name, Exe FROM pslist()
    WHERE Name =~ "(mimikatz|pwdump|procdump)"
SELECT * FROM suspicious_procs

-- Key built-in plugins
SELECT * FROM glob(globs="C:/Users/**/*.exe")
SELECT * FROM yara(rules=MyRule, files="C:/Temp/suspicious.exe")
SELECT * FROM parse_evtx(filename="C:/Windows/System32/winevt/Logs/Security.evtx")
SELECT * FROM read_reg_key(key="HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run")
SELECT * FROM hash(path="C:/Windows/System32/cmd.exe")
```

---

### 7.3 Built-in Hunting Artifacts

| Artifact | Purpose | Key Fields |
|---|---|---|
| Windows.KapeFiles.Targets | Collect forensic artifacts | All major artifact paths |
| Windows.EventLogs.Evtx | Parse Windows event logs | EventID, TimeCreated, Message |
| Windows.System.TaskScheduler | Enumerate scheduled tasks | Name, Command, Enabled, NextRunTime |
| Windows.Sys.CertificateAuthorities | Enumerate trusted CAs | Subject, Issuer, NotBefore, NotAfter |
| Windows.Persistence.PermanentWMIEvents | WMI persistence | Name, Query, Consumer |
| Windows.System.Services | Running services | DisplayName, PathName, State |
| Windows.Network.ListeningPorts | Open listening ports | Pid, Laddr, Lport, FamilyString |
| Windows.Registry.Sysinternals | Sysinternals EULA run evidence | KeyPath, Value, Mtime |
| Windows.Forensics.Prefetch | Prefetch execution evidence | Executable, LastRunTime, RunCount |
| Windows.Memory.Acquisition | Full memory image | RawMemory |
| Linux.Sys.Cron | Cron job enumeration | Command, Schedule, User |

---

### 7.4 Custom Artifact Creation

```yaml
name: Custom.Threat.LsassAccess
description: Hunt for LSASS process access events indicating credential dumping.
type: CLIENT

parameters:
  - name: SuspiciousAccessRights
    default: "0x1010,0x1410,0x0410,0x1fffff,0x1438"

sources:
  - name: LsassAccessEvents
    query: |
      LET access_rights = split(string=SuspiciousAccessRights, sep=",")
      LET evtx_path = "C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"
      SELECT
          timestamp(epoch=System.TimeCreated.SystemTime) AS EventTime,
          System.Computer AS Host,
          EventData.SourceImage AS SourceProcess,
          EventData.TargetImage AS TargetProcess,
          EventData.GrantedAccess AS AccessRights,
          EventData.CallTrace AS CallTrace
      FROM parse_evtx(filename=evtx_path)
      WHERE System.EventID.Value = 10
        AND EventData.TargetImage =~ "lsass.exe"
        AND EventData.GrantedAccess IN access_rights
        AND NOT EventData.SourceImage =~ "(MsMpEng|WerFault|csrss|wininit|lsm)\\.exe$"
```

---

### 7.5 Hunt Deployment via API

```python
import requests

SERVER = "https://velociraptor-server:8889"
HEADERS = {"Authorization": "Bearer your_api_token"}

hunt_data = {
    "start_request": {
        "artifacts": ["Windows.System.TaskScheduler", "Windows.Persistence.PermanentWMIEvents"]
    },
    "description": "Persistence Hunt 2024-01-15",
    "expires": 86400
}
r = requests.post(f"{SERVER}/api/v1/CreateHunt", headers=HEADERS, json=hunt_data)
hunt_id = r.json().get("hunt_id")

requests.post(f"{SERVER}/api/v1/ModifyHunt",
    headers=HEADERS,
    json={"hunt_id": hunt_id, "state": "RUNNING"})
print(f"Hunt {hunt_id} started")
```

---

### 7.6 Velociraptor Notebooks for Collaborative Investigation

```vql
-- Timeline analysis for a compromised host
LET target_host = "WIN-COMPROMISED01"
LET hunt_start = "2024-01-15T00:00:00Z"
LET hunt_end = "2024-01-15T23:59:59Z"

SELECT *
FROM source(artifact="Windows.EventLogs.Evtx",
            client_id=clientid(hostname=target_host))
WHERE System.TimeCreated.SystemTime > hunt_start
  AND System.TimeCreated.SystemTime < hunt_end
  AND System.EventID.Value IN (4624, 4625, 4648, 4688, 4698, 4720, 4732, 7045)
ORDER BY System.TimeCreated.SystemTime ASC
```

---

## 8. osquery for Threat Hunting

### 8.1 osquery Architecture

osquery exposes the operating system as a relational database, allowing SQL queries against system state in real-time.

**Installation:**
```bash
# macOS
brew install osquery

# Ubuntu/Debian
export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
sudo apt-get update && sudo apt-get install osquery

# Interactive mode
osqueryi
.tables            -- list all tables
.schema processes  -- show table schema
.quit
```

---

### 8.2 Process + Network Connection Correlation

```sql
-- Running processes with established outbound connections
SELECT
    p.pid, p.name, p.path, p.cmdline,
    p.parent AS ppid, pp.name AS parent_name,
    u.username,
    n.local_address, n.local_port,
    n.remote_address, n.remote_port, n.state,
    h.sha256
FROM processes AS p
LEFT JOIN process_open_sockets AS n ON p.pid = n.pid
LEFT JOIN processes AS pp ON p.parent = pp.pid
LEFT JOIN users AS u ON p.uid = u.uid
LEFT JOIN hash AS h ON p.path = h.path
WHERE n.remote_port != 0
    AND n.state = 'ESTABLISHED'
    AND p.name NOT IN ('svchost.exe', 'lsass.exe', 'services.exe')
ORDER BY p.start_time DESC;

-- Unsigned or unverified binaries
SELECT p.pid, p.name, p.path, p.cmdline, s.signed, s.identifier, s.authority
FROM processes AS p
LEFT JOIN signature AS s ON p.path = s.path
WHERE p.path != ''
    AND (s.signed = 0 OR s.signed IS NULL)
    AND p.name NOT IN ('svchost.exe', 'csrss.exe', 'smss.exe')
ORDER BY p.start_time DESC;
```

---

### 8.3 Scheduled Tasks and Cron Jobs

```sql
-- Windows: All enabled scheduled tasks
SELECT name, action, path, enabled, state, next_run_time, last_run_time, hidden
FROM scheduled_tasks
WHERE enabled = 1
ORDER BY last_run_time DESC;

-- Suspicious scheduled tasks (non-standard paths)
SELECT name, action, path, enabled, hidden
FROM scheduled_tasks
WHERE action NOT LIKE '%C:\Windows\%'
    AND action NOT LIKE '%C:\Program Files%'
    AND enabled = 1;

-- Linux/macOS: Cron jobs with network utilities
SELECT c.command, c.minute, c.hour, c.username
FROM crontab AS c
WHERE command LIKE '%curl%'
    OR command LIKE '%wget%'
    OR command LIKE '%nc %'
    OR command LIKE '%bash -i%';
```

---

### 8.4 Browser Extensions Inventory

```sql
-- Chrome extensions with high-risk permissions
SELECT u.username, ce.name, ce.version, ce.description, ce.author, ce.permissions, ce.path
FROM users AS u
JOIN chrome_extensions AS ce ON u.uid = ce.uid
WHERE ce.permissions LIKE '%tabs%'
    OR ce.permissions LIKE '%nativeMessaging%'
    OR ce.permissions LIKE '%debugger%'
    OR ce.permissions LIKE '%management%'
ORDER BY u.username, ce.name;

-- Firefox active add-ons
SELECT u.username, fe.name, fe.version, fe.source_url, fe.active
FROM users AS u
JOIN firefox_addons AS fe ON u.uid = fe.uid
WHERE fe.active = 1
ORDER BY u.username, fe.name;
```

---

### 8.5 SSH Authorized Keys

```sql
-- All authorized keys across all users
SELECT u.username, u.uid, ak.algorithm, ak.comment, ak.key
FROM users AS u
JOIN authorized_keys AS ak ON u.uid = ak.uid
ORDER BY u.username;

-- Keys not from known internal CA (potential backdoors)
SELECT u.username, ak.algorithm, ak.comment, ak.key, f.mtime AS key_file_modified
FROM users AS u
JOIN authorized_keys AS ak ON u.uid = ak.uid
JOIN file AS f ON f.path = u.directory || '/.ssh/authorized_keys'
WHERE ak.comment NOT LIKE '%@company.com'
    AND ak.options NOT LIKE '%cert-authority%'
ORDER BY f.mtime DESC;
```

---

### 8.6 Loaded Kernel Modules and Admin Users

```sql
-- Linux: Loaded kernel modules (rootkit hunting)
SELECT name, size, status, address
FROM kernel_modules
WHERE name NOT IN (
    'ip_tables', 'iptable_filter', 'nf_conntrack', 'nf_nat',
    'bridge', 'overlay', 'br_netfilter', 'veth'
)
ORDER BY name;

-- Windows: Unsigned kernel drivers
SELECT d.name, d.path, d.state, d.start_type, s.signed, s.authority
FROM drivers AS d
LEFT JOIN signature AS s ON d.path = s.path
WHERE state = 'RUNNING'
    AND (s.signed = 0 OR s.signed IS NULL)
    AND path NOT LIKE 'C:\Windows\%';

-- Users with administrative privileges
SELECT u.username, u.uid, u.gid, g.groupname, u.shell
FROM users AS u
JOIN user_groups AS ug ON u.uid = ug.uid
JOIN groups AS g ON ug.gid = g.gid
WHERE g.groupname IN ('sudo', 'wheel', 'admin', 'Administrators', 'Domain Admins')
ORDER BY u.username;
```

---

### 8.7 osquery Packs and Fleet Integration

**Security pack excerpt:**
```json
{
  "queries": {
    "unexpected_talkers": {
      "query": "SELECT p.name, p.cmdline, n.remote_address, n.remote_port FROM processes AS p JOIN process_open_sockets AS n ON p.pid = n.pid WHERE n.remote_port != 0 AND p.name NOT IN ('chrome','firefox','slack');",
      "interval": 300,
      "platform": "all"
    },
    "kernel_modules": {
      "query": "SELECT * FROM kernel_modules;",
      "interval": 3600,
      "platform": "linux"
    },
    "startup_items": {
      "query": "SELECT * FROM startup_items;",
      "interval": 3600,
      "platform": "darwin"
    }
  }
}
```

**Fleet (osquery management):**
```bash
docker run -p 8080:8080 \
  -e DATABASE_ADDRESS=db:3306 \
  -e DATABASE_DATABASE=fleet \
  -e DATABASE_USERNAME=fleet \
  -e DATABASE_PASSWORD=secret \
  fleetdm/fleet:latest
```

**Reference:** https://github.com/osquery/osquery | DetectionLab includes pre-configured osquery with security packs.

---

## 9. Threat Intelligence Integration

### 9.1 MISP for Threat Hunting

MISP (Malware Information Sharing Platform) is an open-source threat intelligence platform supporting IOC ingestion, correlation, and sharing.

**Docker setup:**
```bash
git clone https://github.com/MISP/misp-docker
cd misp-docker && cp template.env .env
docker-compose up -d
# Access: https://localhost, admin@admin.test / admin
```

**MISP API for hunt IOC extraction:**
```python
from pymisp import PyMISP

misp = PyMISP(url="https://misp.company.com", key="your_api_key", ssl=False)

result = misp.search(
    return_format='json',
    type_attribute=['ip-dst', 'domain', 'sha256', 'url'],
    to_ids=True,
    last="7d",
    threat_level_id=[1, 2],
    published=True
)

iocs = {'ip': [], 'domain': [], 'hash': []}
for event in result:
    for attr in event.get('Attribute', []):
        if attr['type'] == 'ip-dst':
            iocs['ip'].append(attr['value'])
        elif attr['type'] == 'domain':
            iocs['domain'].append(attr['value'])
        elif attr['type'] == 'sha256':
            iocs['hash'].append(attr['value'])

with open('threat_intel.csv', 'w') as f:
    f.write("indicator,type,threat_level,event_id\n")
    for event in result:
        for attr in event.get('Attribute', []):
            f.write(f"{attr['value']},{attr['type']},{event['threat_level_id']},{event['id']}\n")
```

**MISP taxonomy and galaxy clusters:**
- Threat actor tracking: `misp-galaxy:threat-actor="APT28"`
- TLP taxonomy: `tlp:white`, `tlp:green`, `tlp:amber`, `tlp:red`
- ATT&CK tagging: `misp-galaxy:mitre-attack-pattern="T1059.001"`
- Sector targeting: `misp-galaxy:sector="Financial"`

---

### 9.2 OpenCTI: STIX 2.1 Knowledge Graph

OpenCTI is an open-source threat intelligence platform using STIX 2.1 as its native format.

**STIX 2.1 intrusion-set object example:**
```json
{
  "type": "intrusion-set",
  "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
  "name": "APT29",
  "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
  "first_seen": "2008-01-01T00:00:00.000Z",
  "goals": ["Intelligence gathering", "Long-term persistence"],
  "resource_level": "government",
  "primary_motivation": "organizational-gain"
}
```

**Key STIX relationships for hunting pivots:**
- `Indicator` --[indicates]--> `Malware`
- `Malware` --[uses]--> `Attack-Pattern` (TTP)
- `Intrusion-Set` --[uses]--> `Malware`
- `Intrusion-Set` --[attributed-to]--> `Threat-Actor`
- `Indicator` --[based-on]--> `Observable` (IP, domain, hash)

**OpenCTI API:**
```python
from pycti import OpenCTIApiClient

opencti = OpenCTIApiClient("https://opencti.company.com", "your_api_token")
indicators = opencti.indicator.list(
    filters={
        "mode": "and",
        "filters": [
            {"key": "createdBy", "values": ["APT29 Entity ID"]},
            {"key": "valid_until", "values": ["2024-01-01"], "operator": "gt"}
        ]
    }
)
```

---

### 9.3 TAXII Feeds

TAXII (Trusted Automated eXchange of Indicator Information) is the transport protocol for STIX threat intelligence.

**Key public feeds:**
```python
from taxii2client.v21 import Server

# CISA AIS - register at https://www.cisa.gov/ais
cisa_server = Server("https://ais2.cisa.dhs.gov/taxii2/",
    user="your_username", password="your_password")

api_root = cisa_server.api_roots[0]
for collection in api_root.collections:
    print(f"Collection: {collection.title} ({collection.id})")
    bundle = collection.get_objects(type="indicator", added_after="2024-01-01T00:00:00Z")
    for obj in bundle.objects:
        print(f"  {obj.type}: {obj.id}")

# MITRE ATT&CK TAXII (public, no authentication required)
att_server = Server("https://cti-taxii.mitre.org/taxii/")

# FS-ISAC TAXII (Financial Sector) - requires membership
# https://www.fsisac.com/
```

---

### 9.4 IOC-to-Hunt Pivot Methodology

```
Step 1: Receive IOC (IP, domain, hash, email)
         |
         v
Step 2: Historical SIEM/EDR search
         Did any asset contact this IOC?
         |
    +----+----+
   YES        NO
    |          |
    v          v
Step 3a:   Step 3b:
Triage     Build
affected   proactive
hosts      detection
    |
    v
Step 4: Timeline reconstruction
    What processes, files, accounts were
    involved before/after IOC contact?
         |
         v
Step 5: Extract behavioral IOCs
    New process names, registry keys,
    network patterns, file paths
         |
         v
Step 6: Search for behavioral IOCs
    Expand scope beyond original asset
         |
         v
Step 7: Scope full compromise
         |
         v
Step 8: Convert to detection rules
    Sigma/YARA/SIEM rules from behavioral IOCs
```

---

### 9.5 Diamond Model for Threat Analysis

```
              Adversary
             /         \
            /           \
        Capability ---- Infrastructure
            \           /
             \         /
               Victim
```

**Application to hunting:**
- **Adversary:** Threat actor attribution, TTPs, motivation - informs who you are hunting
- **Capability:** Malware families, exploits, custom tools - map to YARA and Sigma rules
- **Infrastructure:** C2 IPs, domains, ASNs, hosting providers - map to network IOCs
- **Victim:** Targeted industries, geographies, software versions - focus hunt scope

---

### 9.6 Threat Actor Infrastructure Reuse

**Pivoting via Shodan for infrastructure clustering:**
```python
import shodan
api = shodan.Shodan("your_shodan_api_key")

# Search for Cobalt Strike C2s via known JARM fingerprint
results = api.search('ssl.jarm:07d14d16d21d21d00042d41d00041d58c7162162b6a603d3d90a1987a333c2')
for result in results['matches']:
    print(f"IP: {result['ip_str']}, Port: {result['port']}, Country: {result['location']['country_code']}")

# Infrastructure pivot strategies:
# - Shared SSL certificate thumbprints
# - Common hosting ASN or IP range
# - Shared WHOIS registrant email or phone
# - Common open port/banner combinations
```

**mthcht/awesome-lists:** https://github.com/mthcht/awesome-lists - Comprehensive curated list of threat intelligence sources, tools, and communities.

---

## 10. Hunt Tracking and Reporting

### 10.1 VECTR for Hunt Activity Tracking

VECTR (by SecurityRiskAdvisors) is an open-source platform for tracking purple team and threat hunting activities against ATT&CK.

**Deployment:**
```bash
git clone https://github.com/SecurityRiskAdvisors/VECTR
cd VECTR
cp .env.template .env
docker-compose up -d
# Access at http://localhost:8081
```

**VECTR workflow:**
1. Create **Campaign** representing a hunt sprint (e.g., "Q1 2024 Credential Access Hunt")
2. Create **Test Cases** for individual hunt hypotheses
3. Record **Results** per test case: Detected / Not Detected / Inconclusive
4. Tag each test case with the corresponding ATT&CK technique
5. Export campaign report for stakeholder communication

---

### 10.2 Hunt Hypothesis Documentation Template

```markdown
## Hunt Hypothesis: [HUNT-2024-001]

### Metadata
- **Date:** 2024-01-15
- **Analyst:** Jane Smith
- **Status:** In Progress / Complete / Archived
- **ATT&CK Technique:** T1003.001 - LSASS Memory
- **Priority:** High
- **Related Intel:** APT29 CISA Advisory AA23-347A

### Hypothesis Statement
IF an adversary is present in our environment and attempting to dump credentials,
THEY MAY access LSASS memory using tools like Mimikatz, Dumpert, or custom loaders,
WHICH WOULD produce Sysmon Event ID 10 entries with LSASS as the target image
and suspicious access rights (0x1010, 0x1410, 0x1fffff).

### Data Sources Required
- [ ] Sysmon EventID 10 (Process Access)
- [ ] Windows Security EventID 4656 (Handle requested on object)
- [ ] EDR process telemetry

### Queries Executed
[Link to query documentation or paste queries here]

### Findings
**Result:** Confirmed / Refuted / Inconclusive
**Hosts affected:** [List]
**Accounts affected:** [List]
**Timeline:** [First indicator - Last indicator]
**Evidence:** [Screenshots, log snippets, file hashes]

### False Positives Identified
[Document legitimate activity that triggered the queries]

### Actions Taken
- [ ] Detection rule created: [Link to Sigma rule or SIEM alert]
- [ ] Incident ticket opened: [Ticket number]
- [ ] Threat intel updated: [MISP event ID]
- [ ] Playbook updated: [Link]

### Metrics
- Hunt duration: X hours
- Data sources queried: Y
- New detections generated: Z
```

---

### 10.3 ATT&CK Coverage Heatmap (ATT&CK Navigator)

ATT&CK Navigator provides visual representation of technique coverage.

**Generate heatmap layer file:**
```python
import json

coverage = {
    "T1059.001": {"score": 3, "comment": "PowerShell hunting complete, detection deployed"},
    "T1003.001": {"score": 2, "comment": "LSASS hunt complete, Sigma rule created"},
    "T1558.003": {"score": 1, "comment": "Kerberoasting query exists, no formal hunt yet"},
    "T1071.004": {"score": 0, "comment": "DNS C2 - not yet hunted"},
}

layer = {
    "name": "Threat Hunting Coverage Q1 2024",
    "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Current threat hunting coverage mapped to ATT&CK",
    "filters": {"platforms": ["Windows", "Linux", "macOS"]},
    "techniques": [],
    "gradient": {
        "colors": ["#ff6666", "#ffff66", "#66ff66"],
        "minValue": 0, "maxValue": 3
    },
    "legendItems": [
        {"label": "Not Hunted", "color": "#ff6666"},
        {"label": "Hunt In Progress", "color": "#ffff66"},
        {"label": "Hunt Complete + Detection", "color": "#66ff66"}
    ]
}

for technique_id, data in coverage.items():
    layer["techniques"].append({
        "techniqueID": technique_id,
        "score": data["score"],
        "comment": data["comment"],
        "enabled": True,
        "showSubtechniques": False
    })

with open("hunting_coverage.json", "w") as f:
    json.dump(layer, f, indent=2)

print("Layer generated - import at https://mitre-attack.github.io/attack-navigator/")
```

---

### 10.4 Hunt-to-Detection Feedback Loop

```
Hunt Finding -----------------------------------------> Detection Rule
     |
     | 1. Document the observable artifact
     |    (specific field values, thresholds,
     |     context required for high fidelity)
     |
     | 2. Write Sigma rule
     |    (vendor-agnostic, reusable across SIEMs)
     |
     | 3. Compile to target SIEM
     |    Using sigmac or pySigma sigma-cli
     |
     | 4. Test against known-good data
     |    (measure false positive rate over 30 days)
     |
     | 5. Deploy with severity level and
     |    response playbook attached
     |
     | 6. Monitor and tune
     |    Adjust if FP rate exceeds 20%
     |
     +---- Update hunt library
           (mark hypothesis as "Detection Active")
```

**Hunt-to-rule conversion checklist:**
- [ ] Observable specific enough to avoid alert fatigue
- [ ] False positive cases documented in Sigma `falsepositives` field
- [ ] ATT&CK tags applied (tactic and technique)
- [ ] Severity level appropriate to actual impact
- [ ] Response playbook linked in rule metadata
- [ ] Rule tested in detection lab before production deployment
- [ ] Rule tracked in VECTR with associated hunt campaign ID

---

### 10.5 OTRF/ATTACKdatamap - Data Source Coverage Assessment

```python
import json, requests

attack_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
attack_data = requests.get(attack_url).json()

technique_datasources = {}
for obj in attack_data['objects']:
    if obj['type'] == 'attack-pattern' and not obj.get('revoked', False):
        tid = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                tid = ref['external_id']
        if tid and 'x_mitre_data_sources' in obj:
            technique_datasources[tid] = obj['x_mitre_data_sources']

available_sources = {
    "Process: Process Creation",
    "Process: Process Access",
    "Network Traffic: Network Connection Creation",
    "Windows Registry: Windows Registry Key Modification",
    "Command: Command Execution",
    "File: File Creation",
    "Logon Session: Logon Session Creation",
}

covered = 0
total = len(technique_datasources)
coverage_gaps = []

for tid, sources in technique_datasources.items():
    if any(s in available_sources for s in sources):
        covered += 1
    else:
        coverage_gaps.append({"technique": tid, "required_sources": sources})

print(f"Coverage: {covered}/{total} techniques ({covered/total*100:.1f}%)")
print("Top coverage gaps:")
for gap in sorted(coverage_gaps, key=lambda x: x['technique'])[:20]:
    print(f"  {gap['technique']}: requires {gap['required_sources'][:2]}")
```

---

### 10.6 Hunting Program Maturity Assessment

**Annual assessment checklist:**

**Data Foundation:**
- [ ] Endpoint telemetry (Sysmon/EDR) on >= 95% of Windows assets
- [ ] DNS query logging centralized
- [ ] Network flow data (NetFlow/Zeek) at all egress points
- [ ] Cloud API logs (CloudTrail, Azure Monitor, GCP Audit) ingested
- [ ] Log retention >= 90 days for all sources

**Process Maturity:**
- [ ] Formal hunt hypothesis template in use
- [ ] Hunt calendar with at least monthly cadence
- [ ] All hunts tracked in VECTR or equivalent
- [ ] Hunt-to-detection feedback loop documented and measured
- [ ] ATT&CK coverage map updated at least quarterly

**Technical Capability:**
- [ ] SIEM with KQL or SPL capability
- [ ] Sigma rule pipeline: authoring, compilation, deployment
- [ ] YARA scanning capability (Velociraptor or THOR)
- [ ] Threat intelligence platform (MISP or OpenCTI) with active feeds
- [ ] DetectionLab or equivalent hunt practice environment

**Team Capability:**
- [ ] At least one analyst with ATT&CK practitioner certification (ACP)
- [ ] Regular threat intelligence read-outs to hunting team
- [ ] Participation in community (Sigma contributions, blog posts)
- [ ] Purple team exercises at least annually

---

## Quick Reference: Key Resources

| Resource | Type | URL |
|---|---|---|
| SigmaHQ/sigma | Sigma rules | https://github.com/SigmaHQ/sigma |
| Neo23x0/signature-base | YARA rules | https://github.com/Neo23x0/signature-base |
| mthcht/ThreatHunting-Keywords | Hunt keywords | https://github.com/mthcht/ThreatHunting-Keywords |
| mthcht/awesome-lists | TI resources | https://github.com/mthcht/awesome-lists |
| MITRE ATT&CK Navigator | Coverage heatmap | https://mitre-attack.github.io/attack-navigator/ |
| clong/DetectionLab | Lab environment | https://github.com/clong/DetectionLab |
| Velocidex/velociraptor | DFIR platform | https://github.com/Velocidex/velociraptor |
| osquery/osquery | Endpoint queries | https://github.com/osquery/osquery |
| MISP Project | Threat intel platform | https://www.misp-project.org/ |
| OpenCTI | Threat intel platform | https://www.opencti.io/ |
| SecurityRiskAdvisors/VECTR | Hunt tracking | https://github.com/SecurityRiskAdvisors/VECTR |
| OTRF/ATTACKdatamap | Data source mapping | https://github.com/OTRF/ATTACKdatamap |
| detection.fyi | Sigma search engine | https://detection.fyi |
| Neo23x0/yarGen | YARA auto-generation | https://github.com/Neo23x0/yarGen |
| f-bader/AzSentinelQueries | KQL query library | https://github.com/f-bader/AzSentinelQueries |
| Azure/Azure-Sentinel | Official KQL hunting | https://github.com/Azure/Azure-Sentinel |
| SlimKQL/Hunting-Queries-Detection-Rules | KQL hunting | https://github.com/SlimKQL/Hunting-Queries-Detection-Rules |
| Microsoft-365-Defender-Hunting-Queries | MDE hunting | https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries |
| YARAify | Community YARA sharing | https://yaraify.abuse.ch/ |

---

*Last Updated: 2026-04-26 | Maintained by TeamStarWolf | Licensed under MIT*
