# Threat Hunting Playbooks

Hypothesis-driven hunting procedures mapped to MITRE ATT&CK. Each playbook includes data sources, detection logic, investigation steps, and response actions.

---

## How to Use These Playbooks

1. Select a hypothesis based on threat intelligence, recent incidents, or ATT&CK coverage gaps
2. Verify data sources are available and ingested
3. Execute hunt queries in your SIEM or EDR
4. Triage findings — separate true positives from false positives
5. Escalate or remediate confirmed findings
6. Convert validated hunt logic into automated detection rules

---

## HP-001: LSASS Credential Dumping

**ATT&CK Technique**: T1003.001 — OS Credential Dumping: LSASS Memory
**ATT&CK Tactic**: Credential Access
**Data Sources**: Sysmon EventID 10, EDR process telemetry
**Hunt Frequency**: Weekly

### Hypothesis
An adversary with local admin rights is accessing LSASS memory to dump credentials for lateral movement.

### Detection Query (Splunk)
```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*\\lsass.exe"
NOT (SourceImage="*\\MsMpEng.exe" OR SourceImage="*\\csrss.exe" OR SourceImage="*\\svchost.exe")
| stats count by SourceImage, GrantedAccess, host
| where count < 5
```

### Investigation Steps
1. Identify source process and parent process chain
2. Check if process is signed and verify signature validity
3. Review GrantedAccess mask — 0x1fffff = full access (highly suspicious), 0x1010 = common Mimikatz mask
4. Search for subsequent credential use (Event 4624 from same host with harvested accounts)
5. Check for dump file creation: .dmp files, procdump.exe, comsvcs.dll MiniDump

### Response Actions
- Isolate host if confirmed credential dumping
- Force password reset on all accounts that logged into the affected system
- Check for lateral movement from affected host (Event 4624 Type 3)
- Preserve memory image for forensic analysis

---

## HP-002: Kerberoasting Detection

**ATT&CK Technique**: T1558.003 — Kerberoasting
**ATT&CK Tactic**: Credential Access
**Data Sources**: Windows Security Event Log on Domain Controllers
**Hunt Frequency**: Weekly

### Hypothesis
An adversary is requesting Kerberos TGS tickets for service accounts to crack offline.

### Detection Query (Splunk)
```
index=windows source="WinEventLog:Security" EventCode=4769
TicketEncryptionType="0x17"
NOT ServiceName="$"
NOT ServiceName="krbtgt"
| stats count, dc(ServiceName) as unique_services by src_ip, user
| where count > 5 OR unique_services > 3
```

### Investigation Steps
1. Identify which service accounts had tickets requested
2. Check if RC4 (0x17) encryption was requested (indicates targeting for offline cracking)
3. Correlate with failed login attempts against identified service accounts
4. Verify if requesting account is expected to access these services

### Response Actions
- Enforce AES256 for service account tickets (msDS-SupportedEncryptionTypes = 24)
- Rotate service account passwords immediately if confirmed
- Implement service account tiering — high-privilege accounts should not have SPNs unless required

---

## HP-003: Lateral Movement via SMB

**ATT&CK Technique**: T1021.002 — Remote Services: SMB/Windows Admin Shares
**ATT&CK Tactic**: Lateral Movement
**Data Sources**: Windows Security Event Log, network flow data
**Hunt Frequency**: Daily

### Hypothesis
An adversary is using compromised credentials to move laterally via SMB administrative shares.

### Detection Query (Splunk)
```
index=windows source="WinEventLog:Security" EventCode=4624
LogonType=3 AuthPackage=NTLM
| stats count, dc(dest_host) as unique_targets by src_ip, user
| where unique_targets > 3
| eval alert=case(
    count > 20 AND unique_targets > 5, "HIGH - Mass SMB Lateral Movement",
    count > 5 AND unique_targets > 2, "MEDIUM - SMB Lateral Movement Candidate",
    true(), "LOW"
)
| where alert != "LOW"
```

### Investigation Steps
1. Map source IP to endpoint name and user account
2. Identify the first hop — was the source a workstation or server?
3. Check for PsExec, SC.exe, WMI exec artifacts on target systems
4. Review share access: Did they access C$, ADMIN$, or data shares?

### Response Actions
- Block lateral movement source (VLAN isolation or EDR network isolation)
- Review all hosts contacted for follow-on compromise
- Disable the compromised account and force credential rotation
- Enable SMB signing if not enforced

---

## HP-004: PowerShell Download and Execute

**ATT&CK Techniques**: T1059.001, T1105
**ATT&CK Tactic**: Execution, Command and Control
**Data Sources**: PowerShell Script Block Logging (EventID 4104)
**Hunt Frequency**: Daily

### Hypothesis
An adversary is using PowerShell to download and execute payloads from the internet.

### Detection Query (KQL)
```
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "DownloadString", "DownloadFile", "WebClient",
    "IEX", "Invoke-Expression", "Invoke-WebRequest",
    "FromBase64String", "bitsadmin", "certutil -decode"
)
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

### Investigation Steps
1. Decode any Base64 encoded commands
2. Extract URLs and check domain reputation (VirusTotal, Shodan)
3. Identify parent process — was PowerShell spawned by Office, browser, or unusual process?
4. Review network logs for connections to identified infrastructure

### Response Actions
- Block identified domains and IPs at DNS and perimeter
- Isolate affected host
- Enable PowerShell Constrained Language Mode via AppLocker or WDAC
- Verify PowerShell Script Block Logging is enabled (EventID 4104)

---

## HP-005: DNS Beaconing

**ATT&CK Technique**: T1071.004 — Application Layer Protocol: DNS
**ATT&CK Tactic**: Command and Control
**Data Sources**: DNS logs (Zeek, Windows DNS, firewall DNS)
**Hunt Frequency**: Daily

### Hypothesis
An adversary has malware beaconing over DNS or exfiltrating data via DNS tunneling.

### Detection Query (Splunk)
```
index=network sourcetype=dns
| eval query_length=len(query)
| where query_length > 50
| stats count, avg(query_length) as avg_len, dc(query) as unique_queries
    by src_ip, answer
| where count > 100 AND unique_queries > 50
| eval alert="DNS Tunneling / High-Entropy Beacon Candidate"
```

### Investigation Steps
1. Extract all unique DNS queries from suspected host over 24-48 hours
2. Calculate query entropy — DGA and tunnel domains have high entropy
3. Check if domain has legitimate purpose (reputation, WHOIS, passive DNS)
4. Compare query patterns — beaconing shows periodic behavior; DGA shows NXDOMAIN flood

### Response Actions
- Block identified domains at DNS resolver
- Enable DNS Response Policy Zones (RPZ) for malicious domains
- Deploy DNS Security (Cisco Umbrella, Zscaler, BIND RPZ) to sink DGA domains

---

## Hunting Maturity Model Reference

| Level | Name | Description |
|---|---|---|
| 0 | Initial | Reactive only — hunting triggered by alerts |
| 1 | Minimal | Basic indicator-based hunting; IOC sweeps |
| 2 | Procedural | Following documented hunting playbooks |
| 3 | Innovative | Creating new hunting hypotheses from scratch |
| 4 | Leading | Automating and continuously improving hunts |

## Hunt Prioritization Matrix

| ATT&CK Tactic | Hunt Priority | Rationale |
|---|---|---|
| Credential Access | Critical | Compromised credentials enable all subsequent attacker activity |
| Lateral Movement | Critical | Indicates active intrusion expansion |
| Command and Control | High | C2 detection can catch post-initial-access activity |
| Persistence | High | Indicates established foothold |
| Defense Evasion | High | Indicates sophisticated attacker |
| Execution | Medium | High volume, many FPs; use as supporting data |

## Related Resources
- [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) — Sigma, YARA, and Suricata rule writing
- [Threat Hunting Discipline](disciplines/threat-hunting.md) — Hunting methodology and maturity model
- [MITRE ATT&CK](https://attack.mitre.org/) — Technique reference for hunt hypotheses
