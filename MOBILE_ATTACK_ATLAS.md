# Mobile ATT&CK Technique Atlas

<!-- generated: written by scripts/build_attack_atlases.py from data/attack (ATT&CK v20.0); edit the script, not this page. The header card and the related-pages footer belong to build_doc_meta.py and build_crosslinks.py. -->

> The complete MITRE ATT&CK for Mobile matrix (v20.0), 125 techniques and sub-techniques (78 techniques, 47 sub-techniques) across 12 tactics, cross-referenced to the threat groups and software that use them and the ATT&CK mitigations that address them. Machine-readable source: [`data/attack/mobile/technique_profiles.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/mobile/technique_profiles.jsonl).

Legend: Grp = threat groups, SW = software, Mit = ATT&CK mitigations, Det = ATT&CK detection guidance exists.

A technique that serves more than one tactic is listed under each, so the tactic counts add up to more than the matrix total.

Related: [ATT&CK Technique Atlas (Enterprise)](ATTACK_TECHNIQUE_ATLAS.md), [Threat Group Profiles](THREAT_GROUP_PROFILES.md), [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), [Mobile Security Reference](MOBILE_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Mobile security engineers and threat intelligence analysts

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Length</th><td>

Lookup page: 1,817 words, 85% in tables; look entries up from Start at or the search (about 8 min end to end at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are assessing Android/iOS threat coverage, you are mapping a mobile malware finding to ATT&CK, or you are checking which mitigations address a mobile technique

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Tactics](#tactics) for the 12-tactic index, [Initial Access](#initial-access) for how devices get compromised, [Collection](#collection) for what spyware harvests

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Tactics

- [Initial Access](#initial-access): 12 techniques
- [Execution](#execution): 5 techniques
- [Persistence](#persistence): 10 techniques
- [Privilege Escalation](#privilege-escalation): 5 techniques
- [Defense Evasion](#defense-evasion): 33 techniques
- [Credential Access](#credential-access): 10 techniques
- [Discovery](#discovery): 13 techniques
- [Lateral Movement](#lateral-movement): 2 techniques
- [Collection](#collection): 24 techniques
- [Command and Control](#command-and-control): 17 techniques
- [Exfiltration](#exfiltration): 3 techniques
- [Impact](#impact): 11 techniques

---

## Initial Access
<a id="initial-access"></a>

[`TA0027`](https://attack.mitre.org/tactics/TA0027/), 12 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1451 SIM Card Swap](https://attack.mitre.org/techniques/T1451) | Android, iOS | 2 | 0 | 2 | Yes |
| [T1456 Drive-By Compromise](https://attack.mitre.org/techniques/T1456) | Android, iOS | 0 | 5 | 1 | Yes |
| [T1458 Replication Through Removable Media](https://attack.mitre.org/techniques/T1458) | Android, iOS | 0 | 2 | 5 | Yes |
| [T1461 Lockscreen Bypass](https://attack.mitre.org/techniques/T1461) | Android, iOS | 0 | 4 | 2 | Yes |
| [T1474 Supply Chain Compromise](https://attack.mitre.org/techniques/T1474) | Android, iOS | 0 | 0 | 2 | Yes |
| &nbsp;&nbsp;↳ [.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1474/001) | Android, iOS | 0 | 1 | 1 | Yes |
| &nbsp;&nbsp;↳ [.002 Compromise Hardware Supply Chain](https://attack.mitre.org/techniques/T1474/002) | Android, iOS | 0 | 0 | 1 | Yes |
| &nbsp;&nbsp;↳ [.003 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1474/003) | Android, iOS | 0 | 5 | 2 | Yes |
| [T1476 Deliver Malicious Application via Other Means](https://attack.mitre.org/techniques/T1476) | Android, iOS | 3 | 31 | 0 |  |
| [T1660 Phishing](https://attack.mitre.org/techniques/T1660) | Android, iOS | 6 | 12 | 2 | Yes |
| [T1661 Application Versioning](https://attack.mitre.org/techniques/T1661) | Android, iOS | 0 | 1 | 2 | Yes |
| [T1664 Exploitation for Initial Access](https://attack.mitre.org/techniques/T1664) | Android, iOS | 0 | 2 | 2 | Yes |

## Execution
<a id="execution"></a>

[`TA0041`](https://attack.mitre.org/tactics/TA0041/), 5 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1575 Native API](https://attack.mitre.org/techniques/T1575) | Android | 0 | 10 | 0 | Yes |
| [T1603 Scheduled Task/Job](https://attack.mitre.org/techniques/T1603) | Android, iOS | 0 | 5 | 0 | Yes |
| [T1623 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1623) | Android, iOS | 0 | 3 | 2 | Yes |
| &nbsp;&nbsp;↳ [.001 Unix Shell](https://attack.mitre.org/techniques/T1623/001) | Android, iOS | 0 | 7 | 2 | Yes |
| [T1658 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1658) | Android, iOS | 0 | 2 | 2 | Yes |

## Persistence
<a id="persistence"></a>

[`TA0028`](https://attack.mitre.org/tactics/TA0028/), 10 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1398 Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1398) | Android, iOS | 0 | 4 | 4 | Yes |
| [T1541 Foreground Persistence](https://attack.mitre.org/techniques/T1541) | Android | 0 | 6 | 1 | Yes |
| [T1577 Compromise Application Executable](https://attack.mitre.org/techniques/T1577) | Android | 0 | 3 | 2 | Yes |
| [T1603 Scheduled Task/Job](https://attack.mitre.org/techniques/T1603) | Android, iOS | 0 | 5 | 0 | Yes |
| [T1624 Event Triggered Execution](https://attack.mitre.org/techniques/T1624) | Android | 0 | 2 | 1 | Yes |
| &nbsp;&nbsp;↳ [.001 Broadcast Receivers](https://attack.mitre.org/techniques/T1624/001) | Android | 0 | 21 | 1 | Yes |
| [T1625 Hijack Execution Flow](https://attack.mitre.org/techniques/T1625) | Android | 0 | 1 | 2 | Yes |
| &nbsp;&nbsp;↳ [.001 System Runtime API Hijacking](https://attack.mitre.org/techniques/T1625/001) | Android | 0 | 3 | 2 | Yes |
| [T1645 Compromise Client Software Binary](https://attack.mitre.org/techniques/T1645) | Android, iOS | 0 | 8 | 4 | Yes |
| [T1676 Linked Devices](https://attack.mitre.org/techniques/T1676) | Android, iOS | 2 | 0 | 1 | Yes |

## Privilege Escalation
<a id="privilege-escalation"></a>

[`TA0029`](https://attack.mitre.org/tactics/TA0029/), 5 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1404 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1404) | Android, iOS | 0 | 18 | 3 | Yes |
| [T1626 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1626) | Android | 0 | 0 | 1 | Yes |
| &nbsp;&nbsp;↳ [.001 Device Administrator Permissions](https://attack.mitre.org/techniques/T1626/001) | Android | 0 | 9 | 2 | Yes |
| [T1631 Process Injection](https://attack.mitre.org/techniques/T1631) | Android, iOS | 0 | 2 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Ptrace System Calls](https://attack.mitre.org/techniques/T1631/001) | Android, iOS | 0 | 3 | 0 | Yes |

## Defense Evasion
<a id="defense-evasion"></a>

[`TA0030`](https://attack.mitre.org/tactics/TA0030/), 33 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1406 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1406) | Android, iOS | 1 | 47 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Steganography](https://attack.mitre.org/techniques/T1406/001) | Android | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Software Packing](https://attack.mitre.org/techniques/T1406/002) | iOS, Android | 0 | 6 | 0 | Yes |
| [T1407 Download New Code at Runtime](https://attack.mitre.org/techniques/T1407) | Android, iOS | 1 | 39 | 1 | Yes |
| [T1516 Input Injection](https://attack.mitre.org/techniques/T1516) | Android | 0 | 14 | 2 | Yes |
| [T1541 Foreground Persistence](https://attack.mitre.org/techniques/T1541) | Android | 0 | 6 | 1 | Yes |
| [T1575 Native API](https://attack.mitre.org/techniques/T1575) | Android | 0 | 10 | 0 | Yes |
| [T1604 Proxy Through Victim](https://attack.mitre.org/techniques/T1604) | Android | 0 | 2 | 0 | Yes |
| [T1617 Hooking](https://attack.mitre.org/techniques/T1617) | Android | 0 | 3 | 2 | Yes |
| [T1627 Execution Guardrails](https://attack.mitre.org/techniques/T1627) | Android, iOS | 0 | 2 | 2 | Yes |
| &nbsp;&nbsp;↳ [.001 Geofencing](https://attack.mitre.org/techniques/T1627/001) | Android, iOS | 1 | 2 | 2 | Yes |
| [T1628 Hide Artifacts](https://attack.mitre.org/techniques/T1628) | Android | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Suppress Application Icon](https://attack.mitre.org/techniques/T1628/001) | Android | 0 | 21 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 User Evasion](https://attack.mitre.org/techniques/T1628/002) | Android | 0 | 6 | 1 | Yes |
| &nbsp;&nbsp;↳ [.003 Conceal Multimedia Files](https://attack.mitre.org/techniques/T1628/003) | Android | 1 | 0 | 1 | Yes |
| [T1629 Impair Defenses](https://attack.mitre.org/techniques/T1629) | Android | 0 | 2 | 5 | Yes |
| &nbsp;&nbsp;↳ [.001 Prevent Application Removal](https://attack.mitre.org/techniques/T1629/001) | Android | 0 | 9 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Device Lockout](https://attack.mitre.org/techniques/T1629/002) | Android | 0 | 3 | 1 | Yes |
| &nbsp;&nbsp;↳ [.003 Disable or Modify Tools](https://attack.mitre.org/techniques/T1629/003) | Android | 0 | 12 | 4 | Yes |
| [T1630 Indicator Removal on Host](https://attack.mitre.org/techniques/T1630) | iOS, Android | 0 | 2 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 Uninstall Malicious Application](https://attack.mitre.org/techniques/T1630/001) | Android | 0 | 7 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 File Deletion](https://attack.mitre.org/techniques/T1630/002) | Android | 0 | 19 | 1 | Yes |
| &nbsp;&nbsp;↳ [.003 Disguise Root/Jailbreak Indicators](https://attack.mitre.org/techniques/T1630/003) | Android, iOS | 0 | 0 | 0 | Yes |
| [T1631 Process Injection](https://attack.mitre.org/techniques/T1631) | Android, iOS | 0 | 2 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Ptrace System Calls](https://attack.mitre.org/techniques/T1631/001) | Android, iOS | 0 | 3 | 0 | Yes |
| [T1632 Subvert Trust Controls](https://attack.mitre.org/techniques/T1632) | Android, iOS | 0 | 0 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 Code Signing Policy Modification](https://attack.mitre.org/techniques/T1632/001) | Android, iOS | 1 | 8 | 3 | Yes |
| [T1633 Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1633) | Android, iOS | 0 | 2 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 System Checks](https://attack.mitre.org/techniques/T1633/001) | Android, iOS | 1 | 15 | 0 | Yes |
| [T1655 Masquerading](https://attack.mitre.org/techniques/T1655) | Android, iOS | 0 | 5 | 1 | Yes |
| &nbsp;&nbsp;↳ [.001 Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1655/001) | Android, iOS | 3 | 42 | 1 | Yes |
| [T1661 Application Versioning](https://attack.mitre.org/techniques/T1661) | Android, iOS | 0 | 1 | 2 | Yes |
| [T1670 Virtualization Solution](https://attack.mitre.org/techniques/T1670) | Android | 0 | 2 | 1 | Yes |

## Credential Access
<a id="credential-access"></a>

[`TA0031`](https://attack.mitre.org/tactics/TA0031/), 10 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1414 Clipboard Data](https://attack.mitre.org/techniques/T1414) | Android, iOS | 0 | 5 | 1 | Yes |
| [T1417 Input Capture](https://attack.mitre.org/techniques/T1417) | Android, iOS | 0 | 3 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 Keylogging](https://attack.mitre.org/techniques/T1417/001) | Android, iOS | 1 | 19 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 GUI Input Capture](https://attack.mitre.org/techniques/T1417/002) | Android, iOS | 0 | 30 | 2 | Yes |
| [T1453 Abuse Accessibility Features](https://attack.mitre.org/techniques/T1453) | Android | 0 | 8 | 1 | Yes |
| [T1517 Access Notifications](https://attack.mitre.org/techniques/T1517) | Android | 0 | 14 | 3 | Yes |
| [T1634 Credentials from Password Store](https://attack.mitre.org/techniques/T1634) | iOS | 0 | 0 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 Keychain](https://attack.mitre.org/techniques/T1634/001) | iOS | 0 | 3 | 3 | Yes |
| [T1635 Steal Application Access Token](https://attack.mitre.org/techniques/T1635) | Android, iOS | 0 | 0 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 URI Hijacking](https://attack.mitre.org/techniques/T1635/001) | Android, iOS | 0 | 0 | 3 | Yes |

## Discovery
<a id="discovery"></a>

[`TA0032`](https://attack.mitre.org/tactics/TA0032/), 13 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1418 Software Discovery](https://attack.mitre.org/techniques/T1418) | Android, iOS | 0 | 50 | 2 | Yes |
| &nbsp;&nbsp;↳ [.001 Security Software Discovery](https://attack.mitre.org/techniques/T1418/001) | Android, iOS | 0 | 3 | 2 | Yes |
| [T1420 File and Directory Discovery](https://attack.mitre.org/techniques/T1420) | Android, iOS | 1 | 17 | 1 | Yes |
| [T1421 System Network Connections Discovery](https://attack.mitre.org/techniques/T1421) | Android | 0 | 9 | 0 | Yes |
| [T1422 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1422) | Android, iOS | 1 | 46 | 1 | Yes |
| &nbsp;&nbsp;↳ [.001 Internet Connection Discovery](https://attack.mitre.org/techniques/T1422/001) | Android, iOS | 0 | 19 | 1 | Yes |
| &nbsp;&nbsp;↳ [.002 Wi-Fi Discovery](https://attack.mitre.org/techniques/T1422/002) | Android, iOS | 0 | 12 | 1 | Yes |
| [T1423 Network Service Scanning](https://attack.mitre.org/techniques/T1423) | Android, iOS | 0 | 1 | 0 | Yes |
| [T1424 Process Discovery](https://attack.mitre.org/techniques/T1424) | Android, iOS | 0 | 12 | 2 | Yes |
| [T1426 System Information Discovery](https://attack.mitre.org/techniques/T1426) | Android, iOS | 1 | 55 | 0 | Yes |
| [T1430 Location Tracking](https://attack.mitre.org/techniques/T1430) | Android, iOS | 1 | 57 | 4 | Yes |
| &nbsp;&nbsp;↳ [.001 Remote Device Management Services](https://attack.mitre.org/techniques/T1430/001) | Android, iOS | 0 | 0 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 Impersonate SS7 Nodes](https://attack.mitre.org/techniques/T1430/002) | Android, iOS | 0 | 1 | 1 | Yes |

## Lateral Movement
<a id="lateral-movement"></a>

[`TA0033`](https://attack.mitre.org/tactics/TA0033/), 2 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1428 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1428) | Android, iOS | 0 | 2 | 1 | Yes |
| [T1458 Replication Through Removable Media](https://attack.mitre.org/techniques/T1458) | Android, iOS | 0 | 2 | 5 | Yes |

## Collection
<a id="collection"></a>

[`TA0035`](https://attack.mitre.org/tactics/TA0035/), 24 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1409 Stored Application Data](https://attack.mitre.org/techniques/T1409) | Android, iOS | 1 | 30 | 1 | Yes |
| [T1414 Clipboard Data](https://attack.mitre.org/techniques/T1414) | Android, iOS | 0 | 5 | 1 | Yes |
| [T1417 Input Capture](https://attack.mitre.org/techniques/T1417) | Android, iOS | 0 | 3 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 Keylogging](https://attack.mitre.org/techniques/T1417/001) | Android, iOS | 1 | 19 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 GUI Input Capture](https://attack.mitre.org/techniques/T1417/002) | Android, iOS | 0 | 30 | 2 | Yes |
| [T1429 Audio Capture](https://attack.mitre.org/techniques/T1429) | Android, iOS | 1 | 51 | 2 | Yes |
| [T1430 Location Tracking](https://attack.mitre.org/techniques/T1430) | Android, iOS | 1 | 57 | 4 | Yes |
| &nbsp;&nbsp;↳ [.001 Remote Device Management Services](https://attack.mitre.org/techniques/T1430/001) | Android, iOS | 0 | 0 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 Impersonate SS7 Nodes](https://attack.mitre.org/techniques/T1430/002) | Android, iOS | 0 | 1 | 1 | Yes |
| [T1453 Abuse Accessibility Features](https://attack.mitre.org/techniques/T1453) | Android | 0 | 8 | 1 | Yes |
| [T1512 Video Capture](https://attack.mitre.org/techniques/T1512) | Android, iOS | 1 | 41 | 1 | Yes |
| [T1513 Screen Capture](https://attack.mitre.org/techniques/T1513) | Android | 0 | 27 | 3 | Yes |
| [T1517 Access Notifications](https://attack.mitre.org/techniques/T1517) | Android | 0 | 14 | 3 | Yes |
| [T1532 Archive Collected Data](https://attack.mitre.org/techniques/T1532) | Android, iOS | 0 | 13 | 0 | Yes |
| [T1533 Data from Local System](https://attack.mitre.org/techniques/T1533) | Android, iOS | 1 | 52 | 0 | Yes |
| [T1616 Call Control](https://attack.mitre.org/techniques/T1616) | Android | 0 | 17 | 1 | Yes |
| [T1636 Protected User Data](https://attack.mitre.org/techniques/T1636) | Android, iOS | 0 | 0 | 2 | Yes |
| &nbsp;&nbsp;↳ [.001 Calendar Entries](https://attack.mitre.org/techniques/T1636/001) | Android, iOS | 0 | 6 | 1 | Yes |
| &nbsp;&nbsp;↳ [.002 Call Log](https://attack.mitre.org/techniques/T1636/002) | Android, iOS | 0 | 40 | 1 | Yes |
| &nbsp;&nbsp;↳ [.003 Contact List](https://attack.mitre.org/techniques/T1636/003) | Android, iOS | 1 | 56 | 1 | Yes |
| &nbsp;&nbsp;↳ [.004 SMS Messages](https://attack.mitre.org/techniques/T1636/004) | Android, iOS | 1 | 71 | 1 | Yes |
| &nbsp;&nbsp;↳ [.005 Accounts](https://attack.mitre.org/techniques/T1636/005) | Android, iOS | 0 | 4 | 2 | Yes |
| [T1638 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1638) | Android, iOS | 0 | 3 | 2 | Yes |
| [T1676 Linked Devices](https://attack.mitre.org/techniques/T1676) | Android, iOS | 2 | 0 | 1 | Yes |

## Command and Control
<a id="command-and-control"></a>

[`TA0037`](https://attack.mitre.org/tactics/TA0037/), 17 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1437 Application Layer Protocol](https://attack.mitre.org/techniques/T1437) | Android, iOS | 0 | 5 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Web Protocols](https://attack.mitre.org/techniques/T1437/001) | Android, iOS | 1 | 49 | 0 | Yes |
| [T1481 Web Service](https://attack.mitre.org/techniques/T1481) | Android, iOS | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Dead Drop Resolver](https://attack.mitre.org/techniques/T1481/001) | Android, iOS | 0 | 5 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1481/002) | Android, iOS | 0 | 4 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 One-Way Communication](https://attack.mitre.org/techniques/T1481/003) | Android, iOS | 0 | 1 | 0 | Yes |
| [T1509 Non-Standard Port](https://attack.mitre.org/techniques/T1509) | Android, iOS | 0 | 8 | 0 | Yes |
| [T1521 Encrypted Channel](https://attack.mitre.org/techniques/T1521) | Android, iOS | 0 | 2 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Symmetric Cryptography](https://attack.mitre.org/techniques/T1521/001) | Android, iOS | 1 | 4 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Asymmetric Cryptography](https://attack.mitre.org/techniques/T1521/002) | Android, iOS | 0 | 7 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 SSL Pinning](https://attack.mitre.org/techniques/T1521/003) | Android, iOS | 0 | 1 | 2 | Yes |
| [T1544 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1544) | Android, iOS | 0 | 15 | 0 | Yes |
| [T1616 Call Control](https://attack.mitre.org/techniques/T1616) | Android | 0 | 17 | 1 | Yes |
| [T1637 Dynamic Resolution](https://attack.mitre.org/techniques/T1637) | Android, iOS | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Domain Generation Algorithms](https://attack.mitre.org/techniques/T1637/001) | Android, iOS | 0 | 4 | 0 | Yes |
| [T1644 Out of Band Data](https://attack.mitre.org/techniques/T1644) | Android, iOS | 0 | 19 | 1 | Yes |
| [T1663 Remote Access Software](https://attack.mitre.org/techniques/T1663) | Android, iOS | 0 | 2 | 2 | Yes |

## Exfiltration
<a id="exfiltration"></a>

[`TA0036`](https://attack.mitre.org/tactics/TA0036/), 3 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1639 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1639) | Android, iOS | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1639/001) | Android, iOS | 0 | 3 | 0 | Yes |
| [T1646 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1646) | Android, iOS | 0 | 29 | 0 | Yes |

## Impact
<a id="impact"></a>

[`TA0034`](https://attack.mitre.org/tactics/TA0034/), 11 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T1464 Network Denial of Service](https://attack.mitre.org/techniques/T1464) | Android, iOS | 0 | 1 | 0 | Yes |
| [T1471 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1471) | Android | 0 | 3 | 0 | Yes |
| [T1516 Input Injection](https://attack.mitre.org/techniques/T1516) | Android | 0 | 14 | 2 | Yes |
| [T1582 SMS Control](https://attack.mitre.org/techniques/T1582) | Android | 0 | 33 | 1 | Yes |
| [T1616 Call Control](https://attack.mitre.org/techniques/T1616) | Android | 0 | 17 | 1 | Yes |
| [T1640 Account Access Removal](https://attack.mitre.org/techniques/T1640) | Android | 0 | 1 | 1 | Yes |
| [T1641 Data Manipulation](https://attack.mitre.org/techniques/T1641) | Android | 0 | 0 | 1 | Yes |
| &nbsp;&nbsp;↳ [.001 Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1641/001) | Android | 0 | 2 | 1 | Yes |
| [T1642 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1642) | Android, iOS | 0 | 5 | 2 | Yes |
| [T1643 Generate Traffic from Victim](https://attack.mitre.org/techniques/T1643) | Android, iOS | 0 | 16 | 1 | Yes |
| [T1662 Data Destruction](https://attack.mitre.org/techniques/T1662) | Android | 0 | 4 | 1 | Yes |

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Threat-informed defense and ATT&CK](/hubs/threat-informed-defense.md)
- [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md)
- [ATT&CK Technique Atlas](/ATTACK_TECHNIQUE_ATLAS.md)

<!-- related:end -->

---

*Source: MITRE ATT&CK for Mobile v20.0 (STIX), through data/attack/mobile/technique_profiles.jsonl. Counts are of live (not revoked or deprecated) objects. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*
