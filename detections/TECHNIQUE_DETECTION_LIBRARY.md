# Technique Detection Library

> Multi-platform detection content keyed to MITRE ATT&CK techniques. Each technique below carries ready-to-adapt analytics for the major SIEM/EDR query languages, the telemetry each one needs, an analyst confidence rating, and the candidate NIST 800-53 controls mapped to the technique (a reference relationship, not proven mitigation), so a hunt can move from behavior, to detection, to control gap in one place.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Detection engineers, threat hunters and SOC analysts

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 15 min (3,469 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or tuning a SIEM or EDR detection for a specific ATT&CK technique, you need a hunt query in your platform's language (SPL, EQL/KQL, YARA-L, CQL), or you want to check which NIST 800-53 controls are mapped to a technique you just detected

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[How to use this library](#how-to-use-this-library), [Technique index](#technique-index), [Provenance & attribution](#provenance-amp-attribution)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last corrected, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Detection Rules Reference](/DETECTION_RULES_REFERENCE.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md), [Detection strategies](/detections/strategies/README.md), [Controls Mapping](/CONTROLS_MAPPING.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last corrected</th><td>

2026-11-25, detection queries corrected against their data-source schemas and query-language semantics across all five platforms: the retired Defender XDR AADSignInEventsBeta table replaced with EntraIdSignInEvents, ATT&CK tactic names updated to v19 (Stealth), brute-force / baseline / injection / RDP / persistence / discovery queries fixed, Chronicle match-section placeholders and UDM fields (extensions.auth.mechanism, FAIL vs BLOCK, target.user.userid) corrected, CrowdStrike CQL marked where its field dictionary is not publicly verifiable, and the control-mapping / validation / provenance framing tightened; verified against primary sources and parser docs (queries were not executed against a live SIEM), and the rendered page and technique-queries.json kept in sync ([#421](https://github.com/TeamStarWolf/TeamStarWolf/pull/421))

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

Platforms covered: Splunk (SPL), Elastic (EQL/KQL), Microsoft Defender / Sentinel (KQL), Google SecOps / Chronicle (YARA-L / UDM), CrowdStrike Falcon LogScale (CQL)  
Techniques covered: 13  
Machine-readable source: [`detections/technique-queries.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/detections/technique-queries.json)

### How to use this library

1. Pick the technique you are hunting or building coverage for (see the index below).
2. Copy the query for your platform and adapt field names/indexes to your environment: these are original examples informed by community detection projects, not ports of their rules and not drop-in production rules. Validate against your own data model and tune out benign activity before deploying.
3. Validate the rule before deploying: use documented synthetic event fixtures, or, where one exists, the matching [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test run in an approved, isolated exercise (not every technique has a matching test). Confirm both that the expected event reaches the right data source and that it produces the intended alert.
4. Close the loop: the NIST 800-53 Rev 5 controls listed per technique are the *candidate* controls mapped to it - a reference relationship from the library's ATT&CK-to-800-53 control-rollup data, not evidence that a control mitigates the technique in your deployment. Check them against your control stack using the [control-depth coverage layer](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/teamstarwolf_vendor_coverage.json) and [edge tables](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data).

### Provenance & attribution

These analytics are original example rules written for this library, informed by the detection approaches of the open community projects below rather than ported from specific upstream rules; treat them as hypotheses to validate, not maintained signatures. Where you adapt one from a specific upstream rule, record that rule's ID, a link to its source at a fixed revision, its license and your local changes. For canonical, maintained, individually licensed rules, consult the upstream projects directly:

- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- [splunk/security_content](https://github.com/splunk/security_content)
- [elastic/detection-rules](https://github.com/elastic/detection-rules)
- [microsoft/Microsoft-365-Defender-Hunting-Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)
- [chronicle/detection-rules](https://github.com/chronicle/detection-rules)

> Confidence ratings (`high` / `medium` / `low`) reflect the expected true-positive strength of the pattern before environment tuning. Treat everything here as a hypothesis to validate, not an authoritative signature.

> CrowdStrike Falcon LogScale (CQL) note: these examples follow CrowdStrike's public community query content ([CrowdStrike/logscale-community-content](https://github.com/CrowdStrike/logscale-community-content), at commit `77cfc4e`), which is where the events and fields used here can be cited - `ProcessRollup2`, `UserLogon` with `LogonType`, `UserLogonFailed2`, `InjectedThread`, `AsepValueUpdate` and `HttpRequest` all appear there - though none was executed here. What is not public is Falcon's in-console Events Data Dictionary, and no public example was found for a file-write event, so the T1486 query names `FsWriteEnded` by convention only; confirm it against your own sensor's dictionary. For those techniques Falcon's built-in detections are the maintained signal.

## Technique index

| ATT&CK ID | Technique | Tactic(s) | Queries | NIST 800-53 controls |
|---|---|---|---|---|
| [T1003.001](#t1003001-lsass-memory) | LSASS Memory | Credential Access | 4 (+1 note) | 19 controls |
| [T1018](#t1018-remote-system-discovery) | Remote System Discovery | Discovery | 5 | 0 controls |
| [T1021.001](#t1021001-remote-desktop-protocol) | Remote Desktop Protocol | Lateral Movement | 5 | 23 controls |
| [T1027](#t1027-obfuscated-files-or-information) | Obfuscated Files or Information | Stealth | 5 | 8 controls |
| [T1053.005](#t1053005-scheduled-task) | Scheduled Task | Execution, Persistence, Privilege Escalation | 5 | 13 controls |
| [T1055](#t1055-process-injection) | Process Injection | Stealth, Privilege Escalation | 5 | 12 controls |
| [T1059.001](#t1059001-powershell) | PowerShell | Execution | 5 | 19 controls |
| [T1078](#t1078-valid-accounts) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | 5 | 25 controls |
| [T1110](#t1110-brute-force) | Brute Force | Credential Access | 5 | 14 controls |
| [T1190](#t1190-exploit-public-facing-application) | Exploit Public-Facing Application | Initial Access | 5 | 29 controls |
| [T1486](#t1486-data-encrypted-for-impact) | Data Encrypted for Impact | Impact | 5 | 11 controls |
| [T1547.001](#t1547001-registry-run-keys-startup-folder) | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | 5 | 0 controls |
| [T1566.001](#t1566001-spearphishing-attachment) | Spearphishing Attachment | Initial Access | 5 | 12 controls |

---

## T1003.001: LSASS Memory
<a id="t1003001"></a>

Tactic(s): Credential Access  
ATT&CK: [T1003.001](https://attack.mitre.org/techniques/T1003/001/)  
Candidate NIST 800-53 R5 controls mapped to this technique (19): `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-3`, `SC-39`, `SI-16` (+3 more)  
Validate with: [Atomic Red Team, T1003.001](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1003.001)

### Splunk (SPL): LSASS process access from non-system parent

- Data source: Sysmon EventCode 10 (ProcessAccess)
- Confidence: `high`
- Logic: Detect processes opening a handle to LSASS for credential dumping. Excludes known benign callers.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| eval target=lower(TargetImage)
| where target="c:\\windows\\system32\\lsass.exe"
| eval call_trace=lower(CallTrace)
| where match(GrantedAccess, "0x1010|0x1410|0x1438|0x143a|0x1fffff")
| where NOT match(SourceImage, "(?i)\\\\windows\\\\system32\\\\(svchost|wininit|csrss|services|lsm|taskmgr|MsMpEng)\\.exe")
| stats count by SourceImage, TargetImage, GrantedAccess, ComputerName, _time
```

### Elastic (EQL/KQL): LSASS handle access (mimikatz/dumpert pattern)

- Data source: Elastic Defend / winlogbeat-sysmon
- Confidence: `high`
- Logic: Elastic EQL detecting suspicious GrantedAccess masks against lsass.exe.

```sql
process where event.code == "10" and
  winlog.event_data.TargetImage : "?:\\Windows\\System32\\lsass.exe" and
  winlog.event_data.GrantedAccess : ("0x1010", "0x1410", "0x1438", "0x143a", "0x1FFFFF") and
  not winlog.event_data.SourceImage : (
    "?:\\Windows\\System32\\svchost.exe",
    "?:\\Windows\\System32\\wininit.exe",
    "?:\\Windows\\System32\\csrss.exe",
    "?:\\Windows\\System32\\MsMpEng.exe"
  )
```

### Microsoft Defender / Sentinel (KQL): LSASS access from rare process

- Data source: DeviceEvents (M365 Defender)
- Confidence: `high`
- Logic: M365D hunting query for processes opening lsass that are rare in the environment.

```kql
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ (
    "svchost.exe","wininit.exe","csrss.exe","services.exe","lsm.exe","taskmgr.exe","MsMpEng.exe")
| summarize Devices = dcount(DeviceId), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by InitiatingProcessFileName, InitiatingProcessFolderPath
| where Devices < 5
| order by Devices asc
```

### Google SecOps / Chronicle (YARA-L / UDM): LSASS dump indicator

- Data source: Sysmon UDM events
- Confidence: `high`
- Logic: YARA-L 2.0 rule for credential dump pattern against LSASS.

```yara
rule t1003_001_lsass_dump {
  meta:
    mitre_attack = "T1003.001"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "PROCESS_OPEN"
    $e.target.process.file.full_path = /lsass\.exe$/ nocase
    $e.security_result.detection_fields["GrantedAccess"] = /0x(1010|1410|1438|143A|1FFFFF)/ nocase
    not $e.principal.process.file.full_path = /\\(svchost|wininit|csrss|services|lsm|MsMpEng)\.exe$/ nocase
    $host = $e.principal.hostname
  match:
    $host over 10m
  condition:
    $e
}
```

### CrowdStrike Falcon LogScale (CQL): LSASS access by uncommon process

- Data source: not expressible from public Falcon telemetry; see note
- Confidence: `n/a`: see note
- Logic: LSASS handle-access cannot be written as a raw process-execution query in CQL.

> `ProcessRollup2` records process execution, not cross-process handle access, so an "opened a
> handle to lsass.exe" query cannot be written over it, and no public Falcon event for LSASS
> open-handle access was found in CrowdStrike's community query content. Alert on Falcon's own
> credential-access detections instead, and for host-level `GrantedAccess`-mask logic use the
> Sysmon EventCode 10 (`ProcessAccess`) and Elastic queries shown above.

---

## T1018: Remote System Discovery
<a id="t1018"></a>

Tactic(s): Discovery  
ATT&CK: [T1018](https://attack.mitre.org/techniques/T1018/)  
Validate with: [Atomic Red Team, T1018](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1018)

### Splunk (SPL): Network discovery (net.exe view, ping sweep)

- Data source: Sysmon EventCode 1
- Confidence: `medium`
- Logic: Detect built-in Windows reconnaissance commands typical of post-exploit discovery.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image IN ("*net.exe","*nltest.exe","*ping.exe","*nslookup.exe")
| where match(CommandLine,"(?i)(view|/dclist|/domain_trusts|-n\\s+1)") OR like(Image, "%nslookup.exe")
| stats count, values(CommandLine) as cmds by ComputerName, User, Image
```

### Elastic (EQL/KQL): Living-off-the-land discovery commands

- Data source: endpoint process events
- Confidence: `medium`
- Logic: Detect net/nltest/ping recon patterns.

```sql
process where event.type == "start" and (
  (process.name : "net.exe" and process.args : "view") or
  (process.name : "nltest.exe" and process.args : ("/dclist*", "/domain_trusts*")) or
  (process.name : "nslookup.exe")
)
```

### Microsoft Defender / Sentinel (KQL): Discovery commands

- Data source: DeviceProcessEvents
- Confidence: `medium`
- Logic: Hunt for native discovery utilities.

```kql
DeviceProcessEvents
| where FileName in~ ("net.exe", "nltest.exe", "nslookup.exe", "ping.exe")
| where ProcessCommandLine has_any ("view", "/dclist", "/domain_trusts", "-n 1")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Google SecOps / Chronicle (YARA-L / UDM): Built-in discovery commands

- Data source: UDM PROCESS_LAUNCH
- Confidence: `medium`
- Logic: YARA-L rule for native Windows discovery utilities.

```yara
rule t1018_remote_system_discovery {
  meta:
    mitre_attack = "T1018"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.target.process.file.full_path = /(net|nltest|nslookup|ping)\.exe$/ nocase
    $p.target.process.command_line = /(view|\/dclist|\/domain_trusts)/ nocase
  condition:
    $p
}
```

### CrowdStrike Falcon LogScale (CQL): Discovery commands

- Data source: Falcon ProcessRollup2
- Confidence: `medium`
- Logic: LogScale detection for built-in discovery utilities.

```sql
#event_simpleName=ProcessRollup2 FileName=/(?i)(net|nltest|nslookup|ping)\.exe/ CommandLine=/(?i)(view|\/dclist|\/domain_trusts)/
| groupBy([ComputerName, UserName, FileName])
```

---

## T1021.001: Remote Desktop Protocol
<a id="t1021001"></a>

Tactic(s): Lateral Movement  
ATT&CK: [T1021.001](https://attack.mitre.org/techniques/T1021/001/)  
Candidate NIST 800-53 R5 controls mapped to this technique (23): `AC-11`, `AC-12`, `AC-17`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `AC-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2` (+7 more)  
Validate with: [Atomic Red Team, T1021.001](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1021.001)

### Splunk (SPL): RDP successful logon from unusual source

- Data source: Windows Security 4624
- Confidence: `medium`
- Logic: Logon Type 10 (RemoteInteractive) from a new source IP.

```spl
index=wineventlog EventCode=4624 LogonType=10
| stats earliest(_time) as first_seen, count by Account_Name, IpAddress, ComputerName
| eval is_new=if(first_seen>relative_time(now(),"-24h"),1,0)
| where is_new=1
```

### Elastic (EQL/KQL): RDP successful logon

- Data source: winlog 4624 LogonType:10
- Confidence: `medium`
- Logic: EQL detection for RDP authentication.

```sql
authentication where event.outcome == "success" and winlog.event_data.LogonType == "10"
```

### Microsoft Defender / Sentinel (KQL): RDP logon to server

- Data source: DeviceLogonEvents
- Confidence: `medium`
- Logic: Hunting for RDP successful sessions.

```kql
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountDomain, AccountName, RemoteIP, RemoteDeviceName
```

### Google SecOps / Chronicle (YARA-L / UDM): RDP successful logon

- Data source: UDM USER_LOGIN
- Confidence: `medium`
- Logic: YARA-L rule for RemoteInteractive successful logon.

```yara
rule t1021_001_rdp_logon {
  meta:
    mitre_attack = "T1021.001"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.extensions.auth.mechanism = "REMOTE_INTERACTIVE"
    $e.security_result.action = "ALLOW"
  condition:
    $e
}
```

### CrowdStrike Falcon LogScale (CQL): RDP logon

- Data source: Falcon UserLogon
- Confidence: `medium`
- Logic: LogScale RDP logon pattern: `UserLogon` with `LogonType=10` (RemoteInteractive), grouped by user and source IP. CrowdStrike's community content uses the numeric `LogonType=10`.

```sql
#event_simpleName=UserLogon LogonType=10
| groupBy([UserName, RemoteAddressIP4, ComputerName])
```

---

## T1027: Obfuscated Files or Information
<a id="t1027"></a>

Tactic(s): Stealth  
ATT&CK: [T1027](https://attack.mitre.org/techniques/T1027/)  
Candidate NIST 800-53 R5 controls mapped to this technique (8): `AC-3`, `CM-2`, `CM-6`, `CM-7`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
Validate with: [Atomic Red Team, T1027](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1027)

### Splunk (SPL): Suspicious base64 / obfuscated cmdline

- Data source: Sysmon EventCode 1
- Confidence: `medium`
- Logic: Detect long base64-like strings and frombase64string usage in command-lines.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval cl=lower(CommandLine)
| where match(cl,"frombase64string|::base64") OR (len(CommandLine)>500 AND match(CommandLine,"[A-Za-z0-9+/=]{200,}"))
| stats count by Image, CommandLine, ComputerName
```

### Elastic (EQL/KQL): Long encoded command-line content

- Data source: endpoint process events
- Confidence: `medium`
- Logic: EQL detection for suspiciously long encoded command-lines.

```sql
process where length(process.command_line) > 500 and
  process.command_line : ("*FromBase64String*", "*::Base64*", "*-EncodedCommand*")
```

### Microsoft Defender / Sentinel (KQL): Encoded command-line activity

- Data source: DeviceProcessEvents
- Confidence: `medium`
- Logic: Hunting for encoded payloads in command-lines.

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("FromBase64String", "::Base64", "-EncodedCommand", "-enc ")
| where strlen(ProcessCommandLine) > 200
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Google SecOps / Chronicle (YARA-L / UDM): Encoded payload pattern

- Data source: UDM PROCESS_LAUNCH
- Confidence: `medium`
- Logic: YARA-L for base64-encoded command execution.

```yara
rule t1027_encoded_payload {
  meta:
    mitre_attack = "T1027"
    severity = "MEDIUM"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.target.process.command_line = /(FromBase64String|::Base64|-EncodedCommand|-enc\s)/ nocase
  condition:
    $p
}
```

### CrowdStrike Falcon LogScale (CQL): base64 payload in cmdline

- Data source: Falcon ProcessRollup2
- Confidence: `medium`
- Logic: LogScale base64 detection.

```sql
#event_simpleName=ProcessRollup2 CommandLine=/(?i)(FromBase64String|::Base64|-EncodedCommand|-enc\s)/
| groupBy([FileName, ComputerName])
```

---

## T1053.005: Scheduled Task
<a id="t1053005"></a>

Tactic(s): Execution, Persistence, Privilege Escalation  
ATT&CK: [T1053.005](https://attack.mitre.org/techniques/T1053/005/)  
Candidate NIST 800-53 R5 controls mapped to this technique (13): `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `RA-5`, `SI-4`  
Validate with: [Atomic Red Team, T1053.005](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1053.005)

### Splunk (SPL): Scheduled task created with suspicious payload

- Data source: Sysmon EventCode 1
- Confidence: `high`
- Logic: schtasks.exe /create with cmd or powershell payload.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*schtasks.exe" CommandLine="*/create*"
| eval cl=lower(CommandLine)
| where match(cl, "powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32")
| table _time, ComputerName, User, ParentImage, CommandLine
```

### Elastic (EQL/KQL): schtasks create with script payload

- Data source: endpoint process events
- Confidence: `high`
- Logic: Elastic EQL for scheduled task creation invoking scripting host.

```sql
process where process.name : "schtasks.exe" and process.args : "/create" and
  process.command_line : ("*powershell*", "*cmd.exe*", "*wscript*", "*mshta*", "*rundll32*", "*regsvr32*")
```

### Microsoft Defender / Sentinel (KQL): Scheduled task created with payload

- Data source: DeviceProcessEvents
- Confidence: `high`
- Logic: Hunt for schtasks.exe /create with suspicious payload.

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell", "cmd.exe", "wscript", "mshta", "rundll32", "regsvr32")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

### Google SecOps / Chronicle (YARA-L / UDM): Scheduled task with script payload

- Data source: UDM PROCESS_LAUNCH
- Confidence: `high`
- Logic: YARA-L rule for schtasks creation with scripting payload.

```yara
rule t1053_005_schtasks_create {
  meta:
    mitre_attack = "T1053.005"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.target.process.file.full_path = /schtasks\.exe$/ nocase
    $p.target.process.command_line = /\/create/ nocase
    $p.target.process.command_line = /(powershell|cmd\.exe|wscript|mshta|rundll32|regsvr32)/ nocase
  condition:
    $p
}
```

### CrowdStrike Falcon LogScale (CQL): schtasks /create

- Data source: Falcon ProcessRollup2
- Confidence: `high`
- Logic: LogScale detection for scheduled task creation with script payload.

```sql
#event_simpleName=ProcessRollup2 FileName=/(?i)schtasks\.exe/ CommandLine=/\/create/i CommandLine=/(?i)(powershell|cmd\.exe|wscript|mshta|rundll32|regsvr32)/
| groupBy([ComputerName, UserName])
```

---

## T1055: Process Injection
<a id="t1055"></a>

Tactic(s): Stealth, Privilege Escalation  
ATT&CK: [T1055](https://attack.mitre.org/techniques/T1055/)  
Candidate NIST 800-53 R5 controls mapped to this technique (12): `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
Validate with: [Atomic Red Team, T1055](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1055)

### Splunk (SPL): CreateRemoteThread / WriteProcessMemory pattern

- Data source: Sysmon EventCode 8
- Confidence: `high`
- Logic: Sysmon EventCode 8 (CreateRemoteThread) into a non-system target.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
| where NOT match(SourceImage,"(?i)\\\\windows\\\\system32\\\\(svchost|wininit|csrss|services|MsMpEng)\\.exe")
| stats count by SourceImage, TargetImage, ComputerName, _time
```

### Elastic (EQL/KQL): Process injection via remote thread

- Data source: Sysmon EventID 8 (Elastic Windows integration)
- Confidence: `high`
- Logic: EQL over Sysmon EventID 8 (CreateRemoteThread) - a thread created in another process - excluding common benign source processes. Elastic's own injection rules key on the Sysmon provider and `event.code == "8"`, not a bare `event.action` value.

```sql
process where host.os.type == "windows" and
  event.provider == "Microsoft-Windows-Sysmon" and event.code == "8" and
  not process.executable : ("?:\\Windows\\System32\\svchost.exe",
                            "?:\\Windows\\System32\\MsMpEng.exe")
```

### Microsoft Defender / Sentinel (KQL): Cross-process injection events

- Data source: DeviceEvents
- Confidence: `high`
- Logic: Hunt for cross-process injection - remote-thread creation into another process and writes into LSASS memory. The `CreateRemoteThreadApiCall` and `WriteToLsassProcessMemory` ActionType values are listed only in the in-portal DeviceEvents schema reference.

```kql
DeviceEvents
| where ActionType in ("CreateRemoteThreadApiCall", "WriteToLsassProcessMemory")
| where InitiatingProcessFileName !in~ ("svchost.exe","MsMpEng.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, AdditionalFields
```

### Google SecOps / Chronicle (YARA-L / UDM): Process injection indicator

- Data source: UDM PROCESS events
- Confidence: `high`
- Logic: YARA-L rule for cross-process injection.

```yara
rule t1055_process_injection {
  meta:
    mitre_attack = "T1055"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "PROCESS_INJECTION"
    not $e.principal.process.file.full_path = /\\(svchost|MsMpEng)\.exe$/ nocase
  condition:
    $e
}
```

### CrowdStrike Falcon LogScale (CQL): Cross-process injection

- Data source: Falcon cross-process injection telemetry
- Confidence: `medium`
- Logic: LogScale pattern for injected-thread telemetry, grouped by source/target process. Confirm the `#event_simpleName` and field names against your sensor's data dictionary (see the CrowdStrike note under Provenance); Falcon's built-in injection detections are the maintained signal.

```sql
#event_simpleName=InjectedThread
| groupBy([SourceProcessImageFileName, TargetProcessImageFileName, ComputerName])
```

---

## T1059.001: PowerShell
<a id="t1059001"></a>

Tactic(s): Execution  
ATT&CK: [T1059.001](https://attack.mitre.org/techniques/T1059/001/)  
Candidate NIST 800-53 R5 controls mapped to this technique (19): `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `IA-8`, `IA-9`, `RA-5`, `SI-10`, `SI-16`, `SI-2` (+3 more)  
Validate with: [Atomic Red Team, T1059.001](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1059.001)

### Splunk (SPL): PowerShell encoded command execution

- Data source: Sysmon EventCode 1 (ProcessCreate)
- Confidence: `high`
- Logic: Detect powershell.exe with -enc / -e / -EncodedCommand parameters typical of obfuscated payloads.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  Image="*powershell.exe"
| regex CommandLine="(?i)(\s-e(nc|nco|ncod|ncode|ncoded|ncodedcommand)?\s)"
| stats count, values(CommandLine) as cmds by User, Computer, ParentImage
| where count > 0
```

### Elastic (EQL/KQL): PowerShell suspicious script-block content

- Data source: winlog.channel: Microsoft-Windows-PowerShell/Operational, EventID 4104
- Confidence: `medium`
- Logic: Elastic KQL (kuery) query rule, not EQL - EQL cannot search a `text` field, and `powershell.file.script_block_text` is `text`, so Elastic's own PowerShell rules are kuery. On a `text` field a quoted value matches as a phrase (no wildcards), so the `*...*` wrappers are dropped.

```kql
event.category:process and host.os.type:windows and powershell.file.script_block_text : (
  "Invoke-Mimikatz" or "Invoke-Expression" or "IEX" or
  "FromBase64String" or "Reflection.Assembly" or "Net.WebClient" or
  "DownloadString" or "-EncodedCommand" or "WindowStyle Hidden")
```

### Microsoft Defender / Sentinel (KQL): PowerShell with download cradle

- Data source: DeviceProcessEvents
- Confidence: `high`
- Logic: Hunt for PowerShell processes invoking common download / iex cradles.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("DownloadString", "DownloadFile", "IEX", "Invoke-Expression", "FromBase64String", "-enc ", "-EncodedCommand")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

### Google SecOps / Chronicle (YARA-L / UDM): PowerShell encoded execution

- Data source: UDM PROCESS_LAUNCH
- Confidence: `high`
- Logic: YARA-L rule for encoded PowerShell command-line patterns.

```yara
rule t1059_001_powershell_encoded {
  meta:
    mitre_attack = "T1059.001"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /powershell(_ise)?\.exe$/ nocase
    $e.target.process.command_line = /\s-e(nc|ncoded|ncodedcommand)?\s/ nocase
  condition:
    $e
}
```

### CrowdStrike Falcon LogScale (CQL): PowerShell encoded cmdline

- Data source: Falcon ProcessRollup2
- Confidence: `high`
- Logic: LogScale query for PowerShell encoded command invocations.

```sql
#event_simpleName=ProcessRollup2 FileName=/(?i)powershell(_ise)?\.exe/
| CommandLine=/(?i)\s-e(nc|ncoded|ncodedcommand)?\s/
| groupBy([ComputerName, UserName, ParentBaseFileName])
```

---

## T1078: Valid Accounts
<a id="t1078"></a>

Tactic(s): Stealth, Persistence, Privilege Escalation, Initial Access  
ATT&CK: [T1078](https://attack.mitre.org/techniques/T1078/)  
Candidate NIST 800-53 R5 controls mapped to this technique (25): `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-3`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `IA-12`, `IA-13`, `IA-2`, `IA-5`, `RA-5`, `SA-10`, `SA-11` (+9 more)  
Validate with: Atomic Red Team, T1078 sub-techniques (no parent-level test directory): [T1078.001](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1078.001), [T1078.003](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1078.003), [T1078.004](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1078.004)

### Splunk (SPL): Suspicious successful logon (first time on host)

- Data source: Windows Security 4624
- Confidence: `medium`
- Logic: Successful interactive logon from an account that has never authenticated to this host before. Field names assume the Splunk Add-on for Windows classic (non-XML) rendering (`Account_Name`, `Logon_Type`); the raw XML rendering uses `TargetUserName`, `LogonType`.

```spl
index=wineventlog EventCode=4624 Logon_Type IN (2,3,10) earliest=-30d
| stats earliest(_time) as first_seen, count by Account_Name, ComputerName
| eval is_new=if(first_seen>relative_time(now(),"-24h"),1,0)
| where is_new=1
| convert ctime(first_seen)
```

### Elastic (EQL/KQL): Anomalous logon (new user/host pair)

- Data source: winlog.event_id 4624
- Confidence: `medium`
- Logic: Successful interactive logons (type 2/3/10). This is only a filter - EQL cannot do first-seen logic; wrap it in an Elastic `new_terms` rule keyed on `user.name` and `host.name` with a history window to flag a genuinely new pair.

```sql
authentication where event.action == "logged-in" and
  winlog.event_data.LogonType : ("2", "3", "10") and
  event.outcome == "success"
```

### Microsoft Defender / Sentinel (KQL): Rare logon location for account

- Data source: EntraIdSignInEvents (Microsoft Defender XDR; AADSignInEventsBeta is deprecated and auto-migrates to EntraIdSignInEvents, per Microsoft, on 19 October 2026). On a Sentinel workspace with the Microsoft Entra connector, use SigninLogs and map the fields (TimeGenerated, ResultType, UserPrincipalName, Location, IPAddress, AppDisplayName).
- Confidence: `medium`
- Logic: A successful sign-in from a country the account did not use in the prior 30 days. The baseline and evaluation windows are disjoint, so today's country cannot seed its own history, and new or no-history accounts are not flagged. Triage signal, not a confirmed compromise.

```kql
let eval_start = ago(1d);
let known =
    EntraIdSignInEvents
    | where Timestamp between (ago(30d) .. eval_start) and ErrorCode == 0 and isnotempty(Country)
    | summarize KnownCountries = make_set(Country) by AccountUpn;
EntraIdSignInEvents
| where Timestamp > eval_start and ErrorCode == 0 and isnotempty(Country)
| join kind=inner known on AccountUpn
| where not(set_has_element(KnownCountries, Country))
| project Timestamp, AccountUpn, Country, IPAddress, Application
```

### Google SecOps / Chronicle (YARA-L / UDM): Different-country successful sign-ins

- Data source: UDM USER_LOGIN
- Confidence: `medium`
- Logic: Two *successful* sign-ins for one account from different countries within an hour. A triage signal, not a travel-feasibility (speed/distance) calculation.

```yara
rule t1078_different_country_logins {
  meta:
    mitre_attack = "T1078"
    severity = "MEDIUM"
  events:
    $a.metadata.event_type = "USER_LOGIN"
    $a.security_result.action = "ALLOW"
    $b.metadata.event_type = "USER_LOGIN"
    $b.security_result.action = "ALLOW"
    $user = $a.target.user.userid
    $user = $b.target.user.userid
    $a.principal.location.country_or_region != $b.principal.location.country_or_region
  match:
    $user over 1h
  condition:
    #a >= 1 and #b >= 1
}
```

### CrowdStrike Falcon LogScale (CQL): Multiple geographies for same user

- Data source: Falcon UserLogon (+ ipLocation)
- Confidence: `medium`
- Logic: Detect an identity seen from two or more distinct countries over the search window. `UserLogon` has no country field, so geography is derived with `ipLocation(RemoteAddressIP4)`, which adds `RemoteAddressIP4.country`; the time span is the search range.

```sql
#event_simpleName=UserLogon RemoteAddressIP4=*
| ipLocation(RemoteAddressIP4)
| groupBy([UserName], function=count(RemoteAddressIP4.country, distinct=true, as=country_count))
| country_count >= 2
```

---

## T1110: Brute Force
<a id="t1110"></a>

Tactic(s): Credential Access  
ATT&CK: [T1110](https://attack.mitre.org/techniques/T1110/)  
Candidate NIST 800-53 R5 controls mapped to this technique (14): `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
Validate with: Atomic Red Team, T1110 sub-techniques (no parent-level test directory): [T1110.001](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1110.001), [T1110.002](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1110.002), [T1110.003](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1110.003), [T1110.004](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1110.004)

### Splunk (SPL): Brute force (high-volume failed logons followed by success)

- Data source: Windows Security log
- Confidence: `high`
- Logic: At least 10 failed (4625) and one successful (4624) logon for the same account and source IP within 5 minutes. `mvlist=t` keeps every event code so the counts are right; `transaction` clusters them in time but does not strictly order failure-before-success - use the Elastic/KQL sequence versions below when ordering matters. Field names assume the Splunk Add-on for Windows classic (non-XML) rendering (`Account_Name`, `Source_Network_Address`); the raw XML rendering uses `TargetUserName`, `IpAddress`.

```spl
index=wineventlog EventCode IN (4624,4625) Account_Name=*
| transaction Account_Name, Source_Network_Address maxspan=5m mvlist=t
| eval failures=mvcount(mvfilter(EventCode=4625))
| eval successes=mvcount(mvfilter(EventCode=4624))
| where failures>=10 AND successes>=1
| table _time, Account_Name, Source_Network_Address, failures, successes, ComputerName
```

### Elastic (EQL/KQL): Auth burst followed by success (sequence)

- Data source: winlog 4624/4625
- Confidence: `high`
- Logic: Elastic EQL sequence of N failures then 1 success per source.

```sql
sequence by source.ip with maxspan=5m
  [authentication where event.outcome == "failure"] with runs=10
  [authentication where event.outcome == "success"]
```

### Microsoft Defender / Sentinel (KQL): Failed sign-ins followed by success (cloud or AD)

- Data source: EntraIdSignInEvents (Microsoft Defender XDR; AADSignInEventsBeta is deprecated and auto-migrates to EntraIdSignInEvents). For on-prem AD, IdentityLogonEvents has a different schema - map its ActionType, AccountName and DeviceName fields before reusing this logic.
- Confidence: `high`
- Logic: A burst of credential-failure sign-ins for one account and source IP, followed by a success that occurs after the last failure within 10 minutes (credential stuffing / brute force against a single account and source, not a distributed spray). Failures are restricted to the bad-credential codes (`50126` invalid username or password, `50053` account locked) so that MFA challenges and sign-in interrupts - which also set a non-zero `ErrorCode` - are not counted as brute-force attempts. The join requires the success to be chronologically after the failures.

```kql
let fails =
    EntraIdSignInEvents
    | where Timestamp > ago(1h) and ErrorCode in (50126, 50053)
    | summarize Failures = count(), LastFailure = max(Timestamp) by AccountUpn, IPAddress, bin(Timestamp, 10m)
    | where Failures >= 10;
EntraIdSignInEvents
| where Timestamp > ago(1h) and ErrorCode == 0
| join kind=inner fails on AccountUpn, IPAddress
| where Timestamp > LastFailure and Timestamp <= LastFailure + 10m
| project SuccessTime = Timestamp, AccountUpn, IPAddress, Country, Failures, LastFailure
```

### Google SecOps / Chronicle (YARA-L / UDM): Brute force success

- Data source: UDM USER_LOGIN events
- Confidence: `high`
- Logic: YARA-L 2.0 rule for credential brute-force pattern.

```yara
rule t1110_brute_force {
  meta:
    mitre_attack = "T1110"
    severity = "HIGH"
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "FAIL"
    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $fail.principal.ip = $success.principal.ip
    $user = $fail.target.user.userid
    $user = $success.target.user.userid
    $fail.metadata.event_timestamp.seconds < $success.metadata.event_timestamp.seconds
  match:
    $user over 5m
  outcome:
    $fail_count = count($fail.metadata.id)
  condition:
    $success and $fail_count >= 10
}
```

### CrowdStrike Falcon LogScale (CQL): Brute force pattern

- Data source: Falcon UserLogonFailed2
- Confidence: `high`
- Logic: A burst of failed logons per account and source IP. CrowdStrike's community content records the failed-logon event as `UserLogonFailed2`. Correlating the follow-on success in one CQL query needs a join with `UserLogon`; Falcon's built-in brute-force detections already cover the failure-then-success pattern.

```sql
#event_simpleName=UserLogonFailed2
| groupBy([UserName, RemoteAddressIP4], function=count(as=fails))
| fails >= 10
```

---

## T1190: Exploit Public-Facing Application
<a id="t1190"></a>

Tactic(s): Initial Access  
ATT&CK: [T1190](https://attack.mitre.org/techniques/T1190/)  
Candidate NIST 800-53 R5 controls mapped to this technique (29): `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-2`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-8`, `RA-10`, `RA-5`, `SA-8` (+13 more)  
Validate with: Atomic Red Team has no T1190 test (listed as "contribute a test" in its [technique index](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/Indexes/Indexes-Markdown/index.md), checked 2026-10-13)

### Splunk (SPL): Public-facing app exploit attempts in web logs

- Data source: Web access logs (Apache/IIS/Nginx)
- Confidence: `medium`
- Logic: Detect requests to known exploit and scanner paths against perimeter web servers (any response status; this flags the attempt, not the outcome).

```spl
index=web sourcetype IN (access_combined, iis, nginx)
| eval path=lower(uri_path)
| where match(path,"(jndi:ldap|/wp-admin/|/phpmyadmin|/\\.env|/\\.git/|/console|/struts|/cgi-bin/)") OR match(path,"\\.(php|asp|jsp)\\?cmd=")
| stats count, values(uri_path) as paths by src_ip, status, host
| where count > 5
| sort -count
```

### Elastic (EQL/KQL): Web exploit indicator strings

- Data source: logs-* (network/http)
- Confidence: `medium`
- Logic: EQL alert on common exploit strings in URL or user-agent.

```sql
network where url.path : ("*jndi:ldap*", "*/wp-admin/*", "*/phpmyadmin*", "*/.git/*", "*/.env*", "*${jndi*")
or user_agent.original : ("*sqlmap*", "*nmap*", "*nikto*", "*acunetix*")
```

### Microsoft Defender / Sentinel (KQL): Inbound requests to exploit and scanner paths (IIS web log)

- Data source: W3CIISLog (Sentinel / Log Analytics)
- Confidence: `medium`
- Logic: Requests to known exploit and scanner paths or query strings against IIS-hosted public-facing apps, read from the inbound `W3CIISLog` web log (the server's own request log, so this is traffic arriving at the app, not an outbound connection). Any status, so it flags the attempt, not the outcome.

```kql
W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem has_any ("/wp-admin", "/phpmyadmin", "/struts", "/cgi-bin/", "/.env", "/.git/")
    or csUriQuery has_any ("jndi:ldap", "${jndi", "cmd=", "/etc/passwd")
| project TimeGenerated, cIP, csMethod, csUriStem, csUriQuery, scStatus, csUserAgent
| sort by TimeGenerated desc
```

### Google SecOps / Chronicle (YARA-L / UDM): Web exploit string in URL

- Data source: UDM NETWORK_HTTP
- Confidence: `medium`
- Logic: YARA-L rule detecting exploitation patterns in HTTP traffic.

```yara
rule t1190_web_exploit {
  meta:
    mitre_attack = "T1190"
    severity = "HIGH"
  events:
    $h.metadata.event_type = "NETWORK_HTTP"
    $h.target.url = /(jndi:ldap|wp-admin|phpmyadmin|\/\.env|\/\.git\/|\$\{jndi)/ nocase
  condition:
    $h
}
```

### CrowdStrike Falcon LogScale (CQL): Web exploit indicators

- Data source: Falcon Network/HTTP
- Confidence: `medium`
- Logic: Search for exploit strings in Falcon network/HTTP telemetry. HTTP request-URL telemetry depends on sensor/module coverage; confirm the `#event_simpleName` and URL field against your sensor's data dictionary (see the CrowdStrike note under Provenance).

```sql
#event_simpleName=NetworkConnect or #event_simpleName=HttpRequest
| RequestUrl=/(jndi:ldap|\/wp-admin|\/phpmyadmin|\/\.env|\/\.git\/)/i
| groupBy([RemoteAddressIP4, RequestUrl])
```

---

## T1486: Data Encrypted for Impact
<a id="t1486"></a>

Tactic(s): Impact  
ATT&CK: [T1486](https://attack.mitre.org/techniques/T1486/)  
Candidate NIST 800-53 R5 controls mapped to this technique (11): `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-6`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
Validate with: [Atomic Red Team, T1486](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1486)

### Splunk (SPL): Mass file modification + extension change (ransomware indicator)

- Data source: Sysmon EventCode 11 (FileCreate) + 23 (FileDelete)
- Confidence: `high`
- Logic: High-volume file write events with new extensions appearing on a single host.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (11,23)
| rex field=TargetFilename "\.(?<ext>[a-zA-Z0-9]{2,8})$"
| bin _time span=5m
| stats dc(TargetFilename) as file_count, values(ext) as extensions by ComputerName, _time
| where file_count > 200
| eval suspicious=if(mvcount(extensions)<3,1,0)
| where suspicious=1
```

### Elastic (EQL/KQL): Ransomware bulk file rename

- Data source: endgame/elastic-defend file events
- Confidence: `high`
- Logic: Elastic EQL detecting bulk RenameFile events with anomalous extensions.

```sql
sequence by host.id, user.name with maxspan=5m
  [file where event.action == "rename" and
    file.extension in ("crypt", "locked", "enc", "crypted", "encrypted", "crypz", "locky", "wcry", "wncry")] with runs=20
```

### Microsoft Defender / Sentinel (KQL): Mass file encryption activity

- Data source: DeviceFileEvents
- Confidence: `high`
- Logic: Hunt for high write volume with rename activity on a single device.

```kql
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where Timestamp > ago(1h)
| extend Ext = tostring(split(FileName, ".")[-1])
| where Ext in~ ("crypt","locked","enc","encrypted","locky","wcry","wncry","ryk","conti")
| summarize Files = dcount(tostring(pack_array(FolderPath, FileName))), Extensions = make_set(Ext) by DeviceName, bin(Timestamp, 5m)
| where Files > 100
```

### Google SecOps / Chronicle (YARA-L / UDM): Bulk file modification with ransom extension

- Data source: UDM FILE_CREATION/MODIFICATION
- Confidence: `high`
- Logic: YARA-L 2.0 rule for ransomware-extension write storm.

```yara
rule t1486_ransomware_ext {
  meta:
    mitre_attack = "T1486"
    severity = "CRITICAL"
  events:
    $f.metadata.event_type = "FILE_MODIFICATION"
    $f.target.file.full_path = /\.(crypt|locked|encrypted|wncry|locky|conti|ryk)$/ nocase
    $host = $f.principal.hostname
  match:
    $host over 5m
  outcome:
    $count = count_distinct($f.target.file.full_path)
  condition:
    $f and $count > 50
}
```

### CrowdStrike Falcon LogScale (CQL): Ransomware file extension burst

- Data source: Falcon FsWriteEnded
- Confidence: `high`
- Logic: Bulk write activity with known ransomware extensions - more than 50 matching writes per process. Confirm the file-write `#event_simpleName` and field names against your sensor's data dictionary (see the CrowdStrike note under Provenance).

```sql
#event_simpleName=FsWriteEnded TargetFileName=/\.(crypt|locked|encrypted|wncry|conti|ryk|locky)$/i
| groupBy([ComputerName, ContextProcessId])
| _count > 50
```

---

## T1547.001: Registry Run Keys / Startup Folder
<a id="t1547001"></a>

Tactic(s): Persistence, Privilege Escalation  
ATT&CK: [T1547.001](https://attack.mitre.org/techniques/T1547/001/)  
Validate with: [Atomic Red Team, T1547.001](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1547.001)

### Splunk (SPL): Persistence via registry Run key modification

- Data source: Sysmon EventCode 13
- Confidence: `high`
- Logic: Sysmon EventCode 13 (RegistryValueSet) for HKCU/HKLM Run keys.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where match(TargetObject,"(?i)\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run")
| where NOT match(Image,"(?i)\\\\windows\\\\system32\\\\(svchost|MsMpEng|TiWorker)\\.exe")
| stats count by Image, TargetObject, Details, ComputerName
```

### Elastic (EQL/KQL): Run key autostart written by non-system

- Data source: endpoint registry events
- Confidence: `high`
- Logic: EQL for new persistence registry value under Run/RunOnce.

```sql
registry where event.type == "change" and
  registry.path : ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
                   "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
                   "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*")
```

### Microsoft Defender / Sentinel (KQL): Autostart registry persistence

- Data source: DeviceRegistryEvents
- Confidence: `high`
- Logic: Hunt for Run/RunOnce registry value writes.

```kql
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey contains "\\CurrentVersion\\Run" or RegistryKey contains "\\CurrentVersion\\RunOnce"
| where InitiatingProcessFileName !in~ ("svchost.exe","MsMpEng.exe","TiWorker.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
```

### Google SecOps / Chronicle (YARA-L / UDM): Run-key persistence

- Data source: UDM REGISTRY_MODIFICATION
- Confidence: `high`
- Logic: YARA-L rule for Run-key autostart write.

```yara
rule t1547_001_run_key {
  meta:
    mitre_attack = "T1547.001"
  events:
    $r.metadata.event_type = "REGISTRY_MODIFICATION"
    $r.target.registry.registry_key = /\\CurrentVersion\\(Run|RunOnce)(\\|$)/ nocase
  condition:
    $r
}
```

### CrowdStrike Falcon LogScale (CQL): Run-key persistence

- Data source: Falcon AsepValueUpdate
- Confidence: `high`
- Logic: LogScale pattern for Run/RunOnce registry persistence from ASEP registry telemetry. Confirm the ASEP field names against your sensor's data dictionary (see the CrowdStrike note under Provenance).

```sql
#event_simpleName=AsepValueUpdate AsepValueType=/(?i)Run/
| groupBy([ComputerName, AsepKeyName, AsepValueName, AsepValueData])
```

---

## T1566.001: Spearphishing Attachment
<a id="t1566001"></a>

Tactic(s): Initial Access  
ATT&CK: [T1566.001](https://attack.mitre.org/techniques/T1566/001/)  
Candidate NIST 800-53 R5 controls mapped to this technique (12): `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-8`  
Validate with: [Atomic Red Team, T1566.001](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1566.001)

### Splunk (SPL): Spearphishing attachment (email gateway → endpoint execution)

- Data source: Email gateway + Sysmon EventCode 1
- Confidence: `high`
- Logic: Correlate an inbound email attachment with subsequent process creation by an Office app. The join uses a normalized user key (email local-part vs the Windows account name) - tune the normalization to your directory; this assumes the local-part equals the sAMAccountName.

```spl
index=email
| eval user_key=lower(mvindex(split(recipient,"@"),0))
| join user_key [ search index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*OUTLOOK.EXE") Image IN ("*powershell.exe","*cmd.exe","*wscript.exe","*cscript.exe","*mshta.exe","*rundll32.exe")
  | eval user_key=lower(mvindex(split(User,"\\"),-1)) ]
| stats count by sender, recipient, ParentImage, Image, CommandLine
```

### Elastic (EQL/KQL): Office spawns suspicious child

- Data source: endpoint events
- Confidence: `high`
- Logic: Detect MS Office processes spawning script/loader children.

```sql
process where event.type == "start" and
  process.parent.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE") and
  process.name : ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe")
```

### Microsoft Defender / Sentinel (KQL): Office app spawning script interpreter

- Data source: DeviceProcessEvents
- Confidence: `high`
- Logic: Hunting query for spearphishing macro execution.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Google SecOps / Chronicle (YARA-L / UDM): Office macro spawn

- Data source: UDM PROCESS_LAUNCH
- Confidence: `high`
- Logic: YARA-L rule for Office process launching scripting host.

```yara
rule t1566_001_office_macro {
  meta:
    mitre_attack = "T1566.001"
    severity = "HIGH"
  events:
    $p.metadata.event_type = "PROCESS_LAUNCH"
    $p.principal.process.file.full_path = /(winword|excel|powerpnt|outlook)\.exe$/ nocase
    $p.target.process.file.full_path = /(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil)\.exe$/ nocase
  condition:
    $p
}
```

### CrowdStrike Falcon LogScale (CQL): Office spawning script host

- Data source: Falcon ProcessRollup2
- Confidence: `high`
- Logic: Detect Office app spawning a script interpreter.

```sql
#event_simpleName=ProcessRollup2 ParentBaseFileName=/(winword|excel|powerpnt|outlook)\.exe/i FileName=/(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil)\.exe/i
| groupBy([ComputerName, UserName, ParentBaseFileName, FileName])
```

---

## Related references

- [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md): the ATT&CK-centric knowledge graph and data-source stack behind this library
- [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md): coverage, detection, and risk scoring lenses
- [Detection Rules Reference](/DETECTION_RULES_REFERENCE.md): writing Sigma, YARA, and Suricata rules
- [SIEM Reference](/SIEM_REFERENCE.md), [Threat Hunting Reference](/THREAT_HUNTING_REFERENCE.md), [Purple Team Reference](/PURPLE_TEAM_REFERENCE.md)
- [Controls Mapping](/CONTROLS_MAPPING.md), [Coverage layer](/navigator/index.md), [Edge tables](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data)

*Detection content: original example queries written for this reference library, following the detection patterns of the listed open community projects (not ports of specific upstream rules); see the provenance note above. A study and hunting aid, no warranty.*
