# Mobile ATT&CK Technique Atlas

> The complete **MITRE ATT&CK for Mobile** matrix (v18.1) — **124 techniques** across 12 tactics — cross-referenced to the threat groups and software that use them and the ATT&CK mitigations that address them. Machine-readable source: [`data/attack/mobile/technique_profiles.jsonl`](data/attack/mobile/technique_profiles.jsonl).

**Legend** — **Grp** = threat groups · **SW** = software · **Mit** = ATT&CK mitigations · **Det** = ATT&CK detection guidance exists.

Related: [ATT&CK Technique Atlas (Enterprise)](ATTACK_TECHNIQUE_ATLAS.md) · [Threat Group Profiles](THREAT_GROUP_PROFILES.md) · [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [Mobile Security Reference](MOBILE_SECURITY_REFERENCE.md)

## Tactics

- [Initial Access](#initial-access) — 11 techniques
- [Execution](#execution) — 5 techniques
- [Persistence](#persistence) — 10 techniques
- [Privilege Escalation](#privilege-escalation) — 5 techniques
- [Defense Evasion](#defense-evasion) — 33 techniques
- [Credential Access](#credential-access) — 10 techniques
- [Discovery](#discovery) — 13 techniques
- [Lateral Movement](#lateral-movement) — 2 techniques
- [Collection](#collection) — 24 techniques
- [Command and Control](#command-and-control) — 17 techniques
- [Exfiltration](#exfiltration) — 3 techniques
- [Impact](#impact) — 11 techniques

---

## Initial Access
<a id="initial-access"></a>

[`TA0027`](https://attack.mitre.org/tactics/TA0027/) · 11 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1451 SIM Card Swap](https://attack.mitre.org/techniques/T1451) | Android, iOS | 2 | 0 | 2 |  |
| [T1456 Drive-By Compromise](https://attack.mitre.org/techniques/T1456) | Android, iOS | 0 | 5 | 1 |  |
| [T1458 Replication Through Removable Media](https://attack.mitre.org/techniques/T1458) | Android, iOS | 0 | 2 | 5 |  |
| [T1461 Lockscreen Bypass](https://attack.mitre.org/techniques/T1461) | Android, iOS | 0 | 3 | 2 |  |
| [T1474 Supply Chain Compromise](https://attack.mitre.org/techniques/T1474) | Android, iOS | 0 | 0 | 2 |  |
| &nbsp;&nbsp;↳ [.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1474/001) | Android, iOS | 0 | 1 | 1 |  |
| &nbsp;&nbsp;↳ [.002 Compromise Hardware Supply Chain](https://attack.mitre.org/techniques/T1474/002) | Android, iOS | 0 | 0 | 1 |  |
| &nbsp;&nbsp;↳ [.003 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1474/003) | Android, iOS | 0 | 5 | 2 |  |
| [T1660 Phishing](https://attack.mitre.org/techniques/T1660) | Android, iOS | 5 | 9 | 2 |  |
| [T1661 Application Versioning](https://attack.mitre.org/techniques/T1661) | Android, iOS | 0 | 1 | 2 |  |
| [T1664 Exploitation for Initial Access](https://attack.mitre.org/techniques/T1664) | Android, iOS | 0 | 2 | 2 |  |

## Execution
<a id="execution"></a>

[`TA0041`](https://attack.mitre.org/tactics/TA0041/) · 5 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1575 Native API](https://attack.mitre.org/techniques/T1575) | Android | 0 | 9 | 0 |  |
| [T1603 Scheduled Task/Job](https://attack.mitre.org/techniques/T1603) | Android, iOS | 0 | 5 | 0 |  |
| [T1623 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1623) | Android, iOS | 0 | 2 | 2 |  |
| &nbsp;&nbsp;↳ [.001 Unix Shell](https://attack.mitre.org/techniques/T1623/001) | Android, iOS | 0 | 7 | 2 |  |
| [T1658 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1658) | Android, iOS | 0 | 2 | 2 |  |

## Persistence
<a id="persistence"></a>

[`TA0028`](https://attack.mitre.org/tactics/TA0028/) · 10 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1398 Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1398) | Android, iOS | 0 | 4 | 4 |  |
| [T1541 Foreground Persistence](https://attack.mitre.org/techniques/T1541) | Android | 0 | 5 | 1 |  |
| [T1577 Compromise Application Executable](https://attack.mitre.org/techniques/T1577) | Android | 0 | 3 | 2 |  |
| [T1603 Scheduled Task/Job](https://attack.mitre.org/techniques/T1603) | Android, iOS | 0 | 5 | 0 |  |
| [T1624 Event Triggered Execution](https://attack.mitre.org/techniques/T1624) | Android | 0 | 2 | 1 |  |
| &nbsp;&nbsp;↳ [.001 Broadcast Receivers](https://attack.mitre.org/techniques/T1624/001) | Android | 0 | 20 | 1 |  |
| [T1625 Hijack Execution Flow](https://attack.mitre.org/techniques/T1625) | Android | 0 | 1 | 2 |  |
| &nbsp;&nbsp;↳ [.001 System Runtime API Hijacking](https://attack.mitre.org/techniques/T1625/001) | Android | 0 | 3 | 2 |  |
| [T1645 Compromise Client Software Binary](https://attack.mitre.org/techniques/T1645) | Android, iOS | 0 | 8 | 4 |  |
| [T1676 Linked Devices](https://attack.mitre.org/techniques/T1676) | Android, iOS | 2 | 0 | 1 |  |

## Privilege Escalation
<a id="privilege-escalation"></a>

[`TA0029`](https://attack.mitre.org/tactics/TA0029/) · 5 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1404 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1404) | Android, iOS | 0 | 18 | 3 |  |
| [T1626 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1626) | Android | 0 | 0 | 1 |  |
| &nbsp;&nbsp;↳ [.001 Device Administrator Permissions](https://attack.mitre.org/techniques/T1626/001) | Android | 0 | 8 | 2 |  |
| [T1631 Process Injection](https://attack.mitre.org/techniques/T1631) | Android, iOS | 0 | 2 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Ptrace System Calls](https://attack.mitre.org/techniques/T1631/001) | Android, iOS | 0 | 3 | 0 |  |

## Defense Evasion
<a id="defense-evasion"></a>

[`TA0030`](https://attack.mitre.org/tactics/TA0030/) · 33 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1406 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1406) | Android, iOS | 1 | 44 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Steganography](https://attack.mitre.org/techniques/T1406/001) | Android | 0 | 1 | 0 |  |
| &nbsp;&nbsp;↳ [.002 Software Packing](https://attack.mitre.org/techniques/T1406/002) | iOS, Android | 0 | 5 | 0 |  |
| [T1407 Download New Code at Runtime](https://attack.mitre.org/techniques/T1407) | Android, iOS | 1 | 38 | 1 |  |
| [T1516 Input Injection](https://attack.mitre.org/techniques/T1516) | Android | 0 | 13 | 2 |  |
| [T1541 Foreground Persistence](https://attack.mitre.org/techniques/T1541) | Android | 0 | 5 | 1 |  |
| [T1575 Native API](https://attack.mitre.org/techniques/T1575) | Android | 0 | 9 | 0 |  |
| [T1604 Proxy Through Victim](https://attack.mitre.org/techniques/T1604) | Android | 0 | 2 | 0 |  |
| [T1617 Hooking](https://attack.mitre.org/techniques/T1617) | Android | 0 | 3 | 2 |  |
| [T1627 Execution Guardrails](https://attack.mitre.org/techniques/T1627) | Android, iOS | 0 | 1 | 2 |  |
| &nbsp;&nbsp;↳ [.001 Geofencing](https://attack.mitre.org/techniques/T1627/001) | Android, iOS | 1 | 2 | 2 |  |
| [T1628 Hide Artifacts](https://attack.mitre.org/techniques/T1628) | Android | 0 | 0 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Suppress Application Icon](https://attack.mitre.org/techniques/T1628/001) | Android | 0 | 21 | 2 |  |
| &nbsp;&nbsp;↳ [.002 User Evasion](https://attack.mitre.org/techniques/T1628/002) | Android | 0 | 5 | 1 |  |
| &nbsp;&nbsp;↳ [.003 Conceal Multimedia Files](https://attack.mitre.org/techniques/T1628/003) | Android | 1 | 0 | 1 |  |
| [T1629 Impair Defenses](https://attack.mitre.org/techniques/T1629) | Android | 0 | 2 | 5 |  |
| &nbsp;&nbsp;↳ [.001 Prevent Application Removal](https://attack.mitre.org/techniques/T1629/001) | Android | 0 | 8 | 3 |  |
| &nbsp;&nbsp;↳ [.002 Device Lockout](https://attack.mitre.org/techniques/T1629/002) | Android | 0 | 3 | 1 |  |
| &nbsp;&nbsp;↳ [.003 Disable or Modify Tools](https://attack.mitre.org/techniques/T1629/003) | Android | 0 | 12 | 4 |  |
| [T1630 Indicator Removal on Host](https://attack.mitre.org/techniques/T1630) | iOS, Android | 0 | 2 | 3 |  |
| &nbsp;&nbsp;↳ [.001 Uninstall Malicious Application](https://attack.mitre.org/techniques/T1630/001) | Android | 0 | 6 | 3 |  |
| &nbsp;&nbsp;↳ [.002 File Deletion](https://attack.mitre.org/techniques/T1630/002) | Android | 0 | 18 | 1 |  |
| &nbsp;&nbsp;↳ [.003 Disguise Root/Jailbreak Indicators](https://attack.mitre.org/techniques/T1630/003) | Android, iOS | 0 | 0 | 0 |  |
| [T1631 Process Injection](https://attack.mitre.org/techniques/T1631) | Android, iOS | 0 | 2 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Ptrace System Calls](https://attack.mitre.org/techniques/T1631/001) | Android, iOS | 0 | 3 | 0 |  |
| [T1632 Subvert Trust Controls](https://attack.mitre.org/techniques/T1632) | Android, iOS | 0 | 0 | 3 |  |
| &nbsp;&nbsp;↳ [.001 Code Signing Policy Modification](https://attack.mitre.org/techniques/T1632/001) | Android, iOS | 1 | 8 | 3 |  |
| [T1633 Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) | Android, iOS | 0 | 2 | 0 |  |
| &nbsp;&nbsp;↳ [.001 System Checks](https://attack.mitre.org/techniques/T1633/001) | Android, iOS | 1 | 15 | 0 |  |
| [T1655 Masquerading](https://attack.mitre.org/techniques/T1655) | Android, iOS | 0 | 3 | 1 |  |
| &nbsp;&nbsp;↳ [.001 Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1655/001) | Android, iOS | 3 | 40 | 1 |  |
| [T1661 Application Versioning](https://attack.mitre.org/techniques/T1661) | Android, iOS | 0 | 1 | 2 |  |
| [T1670 Virtualization Solution](https://attack.mitre.org/techniques/T1670) | Android | 0 | 2 | 1 |  |

## Credential Access
<a id="credential-access"></a>

[`TA0031`](https://attack.mitre.org/tactics/TA0031/) · 10 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1414 Clipboard Data](https://attack.mitre.org/techniques/T1414) | Android, iOS | 0 | 5 | 1 |  |
| [T1417 Input Capture](https://attack.mitre.org/techniques/T1417) | Android, iOS | 0 | 3 | 3 |  |
| &nbsp;&nbsp;↳ [.001 Keylogging](https://attack.mitre.org/techniques/T1417/001) | Android, iOS | 1 | 16 | 2 |  |
| &nbsp;&nbsp;↳ [.002 GUI Input Capture](https://attack.mitre.org/techniques/T1417/002) | Android, iOS | 0 | 28 | 2 |  |
| [T1453 Abuse Accessibility Features](https://attack.mitre.org/techniques/T1453) | Android | 0 | 5 | 1 |  |
| [T1517 Access Notifications](https://attack.mitre.org/techniques/T1517) | Android | 0 | 13 | 3 |  |
| [T1634 Credentials from Password Store](https://attack.mitre.org/techniques/T1634) | iOS | 0 | 0 | 3 |  |
| &nbsp;&nbsp;↳ [.001 Keychain](https://attack.mitre.org/techniques/T1634/001) | iOS | 0 | 3 | 3 |  |
| [T1635 Steal Application Access Token](https://attack.mitre.org/techniques/T1635) | Android, iOS | 0 | 0 | 3 |  |
| &nbsp;&nbsp;↳ [.001 URI Hijacking](https://attack.mitre.org/techniques/T1635/001) | Android, iOS | 0 | 0 | 3 |  |

## Discovery
<a id="discovery"></a>

[`TA0032`](https://attack.mitre.org/tactics/TA0032/) · 13 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1418 Software Discovery](https://attack.mitre.org/techniques/T1418) | Android, iOS | 0 | 47 | 2 |  |
| &nbsp;&nbsp;↳ [.001 Security Software Discovery](https://attack.mitre.org/techniques/T1418/001) | Android, iOS | 0 | 3 | 2 |  |
| [T1420 File and Directory Discovery](https://attack.mitre.org/techniques/T1420) | Android, iOS | 1 | 14 | 1 |  |
| [T1421 System Network Connections Discovery](https://attack.mitre.org/techniques/T1421) | Android | 0 | 8 | 0 |  |
| [T1422 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1422) | Android, iOS | 1 | 45 | 1 |  |
| &nbsp;&nbsp;↳ [.001 Internet Connection Discovery](https://attack.mitre.org/techniques/T1422/001) | Android, iOS | 0 | 19 | 1 |  |
| &nbsp;&nbsp;↳ [.002 Wi-Fi Discovery](https://attack.mitre.org/techniques/T1422/002) | Android, iOS | 0 | 10 | 1 |  |
| [T1423 Network Service Scanning](https://attack.mitre.org/techniques/T1423) | Android, iOS | 0 | 1 | 0 |  |
| [T1424 Process Discovery](https://attack.mitre.org/techniques/T1424) | Android, iOS | 0 | 12 | 2 |  |
| [T1426 System Information Discovery](https://attack.mitre.org/techniques/T1426) | Android, iOS | 1 | 53 | 0 |  |
| [T1430 Location Tracking](https://attack.mitre.org/techniques/T1430) | Android, iOS | 1 | 55 | 4 |  |
| &nbsp;&nbsp;↳ [.001 Remote Device Management Services](https://attack.mitre.org/techniques/T1430/001) | Android, iOS | 0 | 0 | 2 |  |
| &nbsp;&nbsp;↳ [.002 Impersonate SS7 Nodes](https://attack.mitre.org/techniques/T1430/002) | Android, iOS | 0 | 1 | 1 |  |

## Lateral Movement
<a id="lateral-movement"></a>

[`TA0033`](https://attack.mitre.org/tactics/TA0033/) · 2 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1428 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1428) | Android, iOS | 0 | 2 | 1 |  |
| [T1458 Replication Through Removable Media](https://attack.mitre.org/techniques/T1458) | Android, iOS | 0 | 2 | 5 |  |

## Collection
<a id="collection"></a>

[`TA0035`](https://attack.mitre.org/tactics/TA0035/) · 24 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1409 Stored Application Data](https://attack.mitre.org/techniques/T1409) | Android, iOS | 1 | 29 | 1 |  |
| [T1414 Clipboard Data](https://attack.mitre.org/techniques/T1414) | Android, iOS | 0 | 5 | 1 |  |
| [T1417 Input Capture](https://attack.mitre.org/techniques/T1417) | Android, iOS | 0 | 3 | 3 |  |
| &nbsp;&nbsp;↳ [.001 Keylogging](https://attack.mitre.org/techniques/T1417/001) | Android, iOS | 1 | 16 | 2 |  |
| &nbsp;&nbsp;↳ [.002 GUI Input Capture](https://attack.mitre.org/techniques/T1417/002) | Android, iOS | 0 | 28 | 2 |  |
| [T1429 Audio Capture](https://attack.mitre.org/techniques/T1429) | Android, iOS | 1 | 49 | 2 |  |
| [T1430 Location Tracking](https://attack.mitre.org/techniques/T1430) | Android, iOS | 1 | 55 | 4 |  |
| &nbsp;&nbsp;↳ [.001 Remote Device Management Services](https://attack.mitre.org/techniques/T1430/001) | Android, iOS | 0 | 0 | 2 |  |
| &nbsp;&nbsp;↳ [.002 Impersonate SS7 Nodes](https://attack.mitre.org/techniques/T1430/002) | Android, iOS | 0 | 1 | 1 |  |
| [T1453 Abuse Accessibility Features](https://attack.mitre.org/techniques/T1453) | Android | 0 | 5 | 1 |  |
| [T1512 Video Capture](https://attack.mitre.org/techniques/T1512) | Android, iOS | 1 | 38 | 1 |  |
| [T1513 Screen Capture](https://attack.mitre.org/techniques/T1513) | Android | 0 | 26 | 3 |  |
| [T1517 Access Notifications](https://attack.mitre.org/techniques/T1517) | Android | 0 | 13 | 3 |  |
| [T1532 Archive Collected Data](https://attack.mitre.org/techniques/T1532) | Android, iOS | 0 | 13 | 0 |  |
| [T1533 Data from Local System](https://attack.mitre.org/techniques/T1533) | Android, iOS | 1 | 50 | 0 |  |
| [T1616 Call Control](https://attack.mitre.org/techniques/T1616) | Android | 0 | 14 | 1 |  |
| [T1636 Protected User Data](https://attack.mitre.org/techniques/T1636) | Android, iOS | 0 | 0 | 2 |  |
| &nbsp;&nbsp;↳ [.001 Calendar Entries](https://attack.mitre.org/techniques/T1636/001) | Android, iOS | 0 | 6 | 1 |  |
| &nbsp;&nbsp;↳ [.002 Call Log](https://attack.mitre.org/techniques/T1636/002) | Android, iOS | 0 | 38 | 1 |  |
| &nbsp;&nbsp;↳ [.003 Contact List](https://attack.mitre.org/techniques/T1636/003) | Android, iOS | 1 | 53 | 1 |  |
| &nbsp;&nbsp;↳ [.004 SMS Messages](https://attack.mitre.org/techniques/T1636/004) | Android, iOS | 1 | 68 | 1 |  |
| &nbsp;&nbsp;↳ [.005 Accounts](https://attack.mitre.org/techniques/T1636/005) | Android, iOS | 0 | 2 | 2 |  |
| [T1638 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1638) | Android, iOS | 0 | 3 | 2 |  |
| [T1676 Linked Devices](https://attack.mitre.org/techniques/T1676) | Android, iOS | 2 | 0 | 1 |  |

## Command and Control
<a id="command-and-control"></a>

[`TA0037`](https://attack.mitre.org/tactics/TA0037/) · 17 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1437 Application Layer Protocol](https://attack.mitre.org/techniques/T1437) | Android, iOS | 0 | 4 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Web Protocols](https://attack.mitre.org/techniques/T1437/001) | Android, iOS | 1 | 46 | 0 |  |
| [T1481 Web Service](https://attack.mitre.org/techniques/T1481) | Android, iOS | 0 | 1 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Dead Drop Resolver](https://attack.mitre.org/techniques/T1481/001) | Android, iOS | 0 | 5 | 0 |  |
| &nbsp;&nbsp;↳ [.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1481/002) | Android, iOS | 0 | 3 | 0 |  |
| &nbsp;&nbsp;↳ [.003 One-Way Communication](https://attack.mitre.org/techniques/T1481/003) | Android, iOS | 0 | 1 | 0 |  |
| [T1509 Non-Standard Port](https://attack.mitre.org/techniques/T1509) | Android, iOS | 0 | 8 | 0 |  |
| [T1521 Encrypted Channel](https://attack.mitre.org/techniques/T1521) | Android, iOS | 0 | 2 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Symmetric Cryptography](https://attack.mitre.org/techniques/T1521/001) | Android, iOS | 1 | 4 | 0 |  |
| &nbsp;&nbsp;↳ [.002 Asymmetric Cryptography](https://attack.mitre.org/techniques/T1521/002) | Android, iOS | 0 | 7 | 0 |  |
| &nbsp;&nbsp;↳ [.003 SSL Pinning](https://attack.mitre.org/techniques/T1521/003) | Android, iOS | 0 | 1 | 2 |  |
| [T1544 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1544) | Android, iOS | 0 | 14 | 0 |  |
| [T1616 Call Control](https://attack.mitre.org/techniques/T1616) | Android | 0 | 14 | 1 |  |
| [T1637 Dynamic Resolution](https://attack.mitre.org/techniques/T1637) | Android, iOS | 0 | 0 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Domain Generation Algorithms](https://attack.mitre.org/techniques/T1637/001) | Android, iOS | 0 | 4 | 0 |  |
| [T1644 Out of Band Data](https://attack.mitre.org/techniques/T1644) | Android, iOS | 0 | 18 | 1 |  |
| [T1663 Remote Access Software](https://attack.mitre.org/techniques/T1663) | Android, iOS | 0 | 2 | 2 |  |

## Exfiltration
<a id="exfiltration"></a>

[`TA0036`](https://attack.mitre.org/tactics/TA0036/) · 3 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1639 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1639) | Android, iOS | 0 | 1 | 0 |  |
| &nbsp;&nbsp;↳ [.001 Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1639/001) | Android, iOS | 0 | 2 | 0 |  |
| [T1646 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1646) | Android, iOS | 0 | 25 | 0 |  |

## Impact
<a id="impact"></a>

[`TA0034`](https://attack.mitre.org/tactics/TA0034/) · 11 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1464 Network Denial of Service](https://attack.mitre.org/techniques/T1464) | Android, iOS | 0 | 1 | 0 |  |
| [T1471 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1471) | Android | 0 | 3 | 0 |  |
| [T1516 Input Injection](https://attack.mitre.org/techniques/T1516) | Android | 0 | 13 | 2 |  |
| [T1582 SMS Control](https://attack.mitre.org/techniques/T1582) | Android | 0 | 32 | 1 |  |
| [T1616 Call Control](https://attack.mitre.org/techniques/T1616) | Android | 0 | 14 | 1 |  |
| [T1640 Account Access Removal](https://attack.mitre.org/techniques/T1640) | Android | 0 | 1 | 1 |  |
| [T1641 Data Manipulation](https://attack.mitre.org/techniques/T1641) | Android | 0 | 0 | 1 |  |
| &nbsp;&nbsp;↳ [.001 Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1641/001) | Android | 0 | 2 | 1 |  |
| [T1642 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1642) | Android, iOS | 0 | 5 | 2 |  |
| [T1643 Generate Traffic from Victim](https://attack.mitre.org/techniques/T1643) | Android, iOS | 0 | 16 | 1 |  |
| [T1662 Data Destruction](https://attack.mitre.org/techniques/T1662) | Android | 0 | 3 | 1 |  |

---

*Source: MITRE ATT&CK for Mobile v18.1 (STIX). Counts reflect non-deprecated objects.*
