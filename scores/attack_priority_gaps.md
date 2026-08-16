# ATT&CK Priority Gap Analysis

> A data-driven prioritization of MITRE ATT&CK Enterprise techniques (v18.1), combining **how often adversaries use a technique** (tracked threat-group count) with **how thinly the control framework covers it** (NIST 800-53 R5 control depth). The result surfaces the techniques that are both widely used and under-covered — the behaviors most worth detection and mitigation investment.

**Priority score** = `group_count × (1 + 1 / (nist_control_count + 1))` — the same inverse-coverage weighting as the [Risk lens](../ATTACK_MATRIX_ANALYSIS_REFERENCE.md#lens-family-5--breach-patterns--composite-risk). Machine-readable: [`scores/attack_priority_gaps.json`](attack_priority_gaps.json).

## Coverage by tactic

| Tactic | Techniques | With NIST control | With ATT&CK mitigation | With detection strategy |
|---|--:|--:|--:|--:|
| Reconnaissance | 45 | 7 (15%) | 45 (100%) | 45 (100%) |
| Resource Development | 47 | 0 (0%) | 47 (100%) | 47 (100%) |
| Initial Access | 22 | 20 (90%) | 22 (100%) | 22 (100%) |
| Execution | 46 | 38 (82%) | 45 (97%) | 46 (100%) |
| Persistence | 126 | 108 (85%) | 111 (88%) | 126 (100%) |
| Privilege Escalation | 109 | 94 (86%) | 94 (86%) | 109 (100%) |
| Defense Evasion | 215 | 164 (76%) | 177 (82%) | 215 (100%) |
| Credential Access | 67 | 63 (94%) | 63 (94%) | 67 (100%) |
| Discovery | 49 | 15 (30%) | 14 (28%) | 49 (100%) |
| Lateral Movement | 23 | 22 (95%) | 22 (95%) | 23 (100%) |
| Collection | 41 | 27 (65%) | 28 (68%) | 41 (100%) |
| Command and Control | 45 | 39 (86%) | 42 (93%) | 45 (100%) |
| Exfiltration | 19 | 18 (94%) | 18 (94%) | 19 (100%) |
| Impact | 33 | 26 (78%) | 27 (81%) | 33 (100%) |

> **223 of 691 techniques have no mapped NIST 800-53 control** — see the [framework blind-spots Navigator layer](../navigator/analytics/no_nist_coverage.json).

## Top 75 priority techniques

Most-used, least-covered first. Load the companion [group-frequency heatmap](../navigator/analytics/group_frequency.json) in ATT&CK Navigator to see the full matrix.

| # | Technique | Tactic(s) | Groups | Software | NIST | Mitig | Det | Priority |
|--:|---|---|--:|--:|--:|--:|:--:|--:|
| 1 | [T1588.002 Tool](https://attack.mitre.org/techniques/T1588/002) | Resource Development | 79 | 1 | 0 | 1 | ✓ | 158.0 |
| 2 | [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082) | Discovery | 55 | 336 | 0 | 0 | ✓ | 110.0 |
| 3 | [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001) | Persistence, Privilege Escalation | 55 | 194 | 0 | 0 | ✓ | 110.0 |
| 4 | [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083) | Discovery | 50 | 295 | 0 | 0 | ✓ | 100.0 |
| 5 | [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) | Command and Control | 85 | 385 | 8 | 2 | ✓ | 94.44 |
| 6 | [T1070.004 File Deletion](https://attack.mitre.org/techniques/T1070/004) | Defense Evasion | 46 | 239 | 0 | 0 | ✓ | 92.0 |
| 7 | [T1204.002 Malicious File](https://attack.mitre.org/techniques/T1204/002) | Execution | 84 | 90 | 12 | 3 | ✓ | 90.46 |
| 8 | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001) | Execution | 83 | 124 | 19 | 5 | ✓ | 87.15 |
| 9 | [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) | Discovery | 42 | 225 | 0 | 0 | ✓ | 84.0 |
| 10 | [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) | Initial Access | 77 | 55 | 12 | 7 | ✓ | 82.92 |
| 11 | [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057) | Discovery | 40 | 255 | 0 | 0 | ✓ | 80.0 |
| 12 | [T1583.001 Domains](https://attack.mitre.org/techniques/T1583/001) | Resource Development | 40 | 3 | 0 | 1 | ✓ | 80.0 |
| 13 | [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018) | Discovery | 39 | 52 | 0 | 0 | ✓ | 78.0 |
| 14 | [T1059.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) | Execution | 71 | 286 | 11 | 1 | ✓ | 76.92 |
| 15 | [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) | Discovery | 38 | 186 | 0 | 0 | ✓ | 76.0 |
| 16 | [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) | Defense Evasion | 38 | 274 | 0 | 0 | ✓ | 76.0 |
| 17 | [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049) | Discovery | 32 | 60 | 0 | 0 | ✓ | 64.0 |
| 18 | [T1036.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005) | Defense Evasion | 59 | 130 | 12 | 3 | ✓ | 63.54 |
| 19 | [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001) | Command and Control | 56 | 329 | 15 | 2 | ✓ | 59.5 |
| 20 | [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Execution, Persistence, Privilege Escalation | 54 | 118 | 13 | 4 | ✓ | 57.86 |
| 21 | [T1027.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013) | Defense Evasion | 37 | 172 | 1 | 2 | ✓ | 55.5 |
| 22 | [T1074.001 Local Data Staging](https://attack.mitre.org/techniques/T1074/001) | Collection | 27 | 88 | 0 | 0 | ✓ | 54.0 |
| 23 | [T1518.001 Security Software Discovery](https://attack.mitre.org/techniques/T1518/001) | Discovery | 27 | 105 | 0 | 0 | ✓ | 54.0 |
| 24 | [T1056.001 Keylogging](https://attack.mitre.org/techniques/T1056/001) | Collection, Credential Access | 26 | 123 | 0 | 0 | ✓ | 52.0 |
| 25 | [T1553.002 Code Signing](https://attack.mitre.org/techniques/T1553/002) | Defense Evasion | 26 | 52 | 0 | 0 | ✓ | 52.0 |
| 26 | [T1204.001 Malicious Link](https://attack.mitre.org/techniques/T1204/001) | Execution | 47 | 28 | 11 | 3 | ✓ | 50.92 |
| 27 | [T1608.001 Upload Malware](https://attack.mitre.org/techniques/T1608/001) | Resource Development | 25 | 0 | 0 | 1 | ✓ | 50.0 |
| 28 | [T1583.006 Web Services](https://attack.mitre.org/techniques/T1583/006) | Resource Development | 24 | 0 | 0 | 1 | ✓ | 48.0 |
| 29 | [T1059.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005) | Execution | 45 | 67 | 17 | 5 | ✓ | 47.5 |
| 30 | [T1566.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) | Initial Access | 43 | 29 | 11 | 5 | ✓ | 46.58 |
| 31 | [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005) | Collection | 43 | 161 | 13 | 1 | ✓ | 46.07 |
| 32 | [T1555.003 Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003) | Credential Access | 23 | 62 | 0 | 5 | ✓ | 46.0 |
| 33 | [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) | Defense Evasion, Persistence, Privilege Escalation, Initial Access | 44 | 6 | 25 | 8 | ✓ | 45.69 |
| 34 | [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001) | Credential Access | 42 | 26 | 19 | 7 | ✓ | 44.1 |
| 35 | [T1036.004 Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004) | Defense Evasion | 22 | 61 | 0 | 0 | ✓ | 44.0 |
| 36 | [T1587.001 Malware](https://attack.mitre.org/techniques/T1587/001) | Resource Development | 22 | 0 | 0 | 1 | ✓ | 44.0 |
| 37 | [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203) | Execution | 41 | 14 | 16 | 3 | ✓ | 43.41 |
| 38 | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Initial Access | 42 | 8 | 29 | 8 | ✓ | 43.4 |
| 39 | [T1560.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001) | Collection | 37 | 31 | 5 | 1 | ✓ | 43.17 |
| 40 | [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) | Execution | 39 | 88 | 17 | 4 | ✓ | 41.17 |
| 41 | [T1012 Query Registry](https://attack.mitre.org/techniques/T1012) | Discovery | 19 | 98 | 0 | 0 | ✓ | 38.0 |
| 42 | [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) | Lateral Movement | 35 | 17 | 23 | 8 | ✓ | 36.46 |
| 43 | [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112) | Defense Evasion, Persistence | 29 | 136 | 3 | 1 | ✓ | 36.25 |
| 44 | [T1113 Screen Capture](https://attack.mitre.org/techniques/T1113) | Collection | 18 | 148 | 0 | 0 | ✓ | 36.0 |
| 45 | [T1585.002 Email Accounts](https://attack.mitre.org/techniques/T1585/002) | Resource Development | 18 | 0 | 0 | 1 | ✓ | 36.0 |
| 46 | [T1574.001 DLL](https://attack.mitre.org/techniques/T1574/001) | Persistence, Privilege Escalation, Defense Evasion | 32 | 67 | 8 | 5 | ✓ | 35.56 |
| 47 | [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003) | Persistence | 31 | 19 | 8 | 2 | ✓ | 34.44 |
| 48 | [T1585.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001) | Resource Development | 17 | 0 | 0 | 1 | ✓ | 34.0 |
| 49 | [T1087.002 Domain Account](https://attack.mitre.org/techniques/T1087/002) | Discovery | 27 | 25 | 3 | 1 | ✓ | 33.75 |
| 50 | [T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010) | Defense Evasion | 28 | 31 | 4 | 2 | ✓ | 33.6 |
| 51 | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046) | Discovery | 31 | 35 | 11 | 3 | ✓ | 33.58 |
| 52 | [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189) | Initial Access | 31 | 10 | 18 | 5 | ✓ | 32.63 |
| 53 | [T1562.001 Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001) | Defense Evasion | 30 | 71 | 13 | 5 | ✓ | 32.14 |
| 54 | [T1218.011 Rundll32](https://attack.mitre.org/techniques/T1218/011) | Defense Evasion | 26 | 69 | 4 | 1 | ✓ | 31.2 |
| 55 | [T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) | Exfiltration | 24 | 15 | 3 | 1 | ✓ | 30.0 |
| 56 | [T1588.001 Malware](https://attack.mitre.org/techniques/T1588/001) | Resource Development | 15 | 0 | 0 | 1 | ✓ | 30.0 |
| 57 | [T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003) | Persistence, Privilege Escalation | 26 | 108 | 8 | 5 | ✓ | 28.89 |
| 58 | [T1007 System Service Discovery](https://attack.mitre.org/techniques/T1007) | Discovery | 14 | 51 | 0 | 0 | ✓ | 28.0 |
| 59 | [T1583.003 Virtual Private Server](https://attack.mitre.org/techniques/T1583/003) | Resource Development | 14 | 0 | 0 | 1 | ✓ | 28.0 |
| 60 | [T1589.002 Email Addresses](https://attack.mitre.org/techniques/T1589/002) | Reconnaissance | 14 | 1 | 0 | 1 | ✓ | 28.0 |
| 61 | [T1027.002 Software Packing](https://attack.mitre.org/techniques/T1027/002) | Defense Evasion | 23 | 72 | 4 | 1 | ✓ | 27.6 |
| 62 | [T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) | Lateral Movement | 26 | 30 | 16 | 4 | ✓ | 27.53 |
| 63 | [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133) | Persistence, Initial Access | 26 | 5 | 17 | 5 | ✓ | 27.44 |
| 64 | [T1059.007 JavaScript](https://attack.mitre.org/techniques/T1059/007) | Execution | 25 | 32 | 16 | 4 | ✓ | 26.47 |
| 65 | [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) | Exfiltration | 25 | 156 | 18 | 2 | ✓ | 26.32 |
| 66 | [T1069.002 Domain Groups](https://attack.mitre.org/techniques/T1069/002) | Discovery | 13 | 21 | 0 | 0 | ✓ | 26.0 |
| 67 | [T1124 System Time Discovery](https://attack.mitre.org/techniques/T1124) | Discovery | 13 | 77 | 0 | 0 | ✓ | 26.0 |
| 68 | [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002) | Reconnaissance | 13 | 0 | 0 | 1 | ✓ | 26.0 |
| 69 | [T1564.001 Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001) | Defense Evasion | 12 | 45 | 0 | 0 | ✓ | 24.0 |
| 70 | [T1586.002 Email Accounts](https://attack.mitre.org/techniques/T1586/002) | Resource Development | 12 | 0 | 0 | 1 | ✓ | 24.0 |
| 71 | [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) | Privilege Escalation | 22 | 19 | 21 | 5 | ✓ | 23.0 |
| 72 | [T1087.001 Local Account](https://attack.mitre.org/techniques/T1087/001) | Discovery | 18 | 44 | 3 | 1 | ✓ | 22.5 |
| 73 | [T1016.001 Internet Connection Discovery](https://attack.mitre.org/techniques/T1016/001) | Discovery | 11 | 13 | 0 | 0 | ✓ | 22.0 |
| 74 | [T1070.006 Timestomp](https://attack.mitre.org/techniques/T1070/006) | Defense Evasion | 11 | 42 | 0 | 0 | ✓ | 22.0 |
| 75 | [T1518 Software Discovery](https://attack.mitre.org/techniques/T1518) | Discovery | 11 | 36 | 0 | 0 | ✓ | 22.0 |

---

### How to use this

1. Start at the top — these techniques combine heavy real-world use with thin control coverage.
2. For each, pull its detections from the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md) (or write them), validate with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), and add compensating controls where NIST coverage is thin.
3. Track closure over time by re-exporting the Navigator layers.

*Source: MITRE ATT&CK Enterprise v18.1 (STIX) + CTID NIST 800-53 R5 → ATT&CK mappings. Priority is a coverage heuristic, not a substitute for environment-specific risk assessment.*
