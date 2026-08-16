# ATT&CK Technique Atlas

> A complete, cross-referenced map of the **691 MITRE ATT&CK Enterprise techniques and sub-techniques** (ATT&CK v18.1), organized by tactic. Every technique is scored by how many threat groups and pieces of software use it, how many ATT&CK mitigations and NIST 800-53 controls address it, and whether ATT&CK ships a detection strategy for it — so you can see, at a glance, what matters and what is under-covered.

**Legend** — **Grp** = threat groups observed using it · **SW** = software (malware/tools) implementing it · **Mit** = ATT&CK mitigations · **NIST** = NIST 800-53 R5 controls (via CTID) · **Det** = ATT&CK detection strategy exists. Machine-readable source: [`data/attack/technique_profiles.jsonl`](data/attack/technique_profiles.jsonl).

Related: [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [Matrix Analysis](ATTACK_MATRIX_ANALYSIS_REFERENCE.md) · [Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md) · [Threat Group Profiles](THREAT_GROUP_PROFILES.md) · [ATT&CK Mitigations](ATTACK_MITIGATIONS_REFERENCE.md)

## Tactics

- [Reconnaissance](#reconnaissance) — 45 techniques
- [Resource Development](#resource-development) — 47 techniques
- [Initial Access](#initial-access) — 22 techniques
- [Execution](#execution) — 46 techniques
- [Persistence](#persistence) — 126 techniques
- [Privilege Escalation](#privilege-escalation) — 109 techniques
- [Defense Evasion](#defense-evasion) — 215 techniques
- [Credential Access](#credential-access) — 67 techniques
- [Discovery](#discovery) — 49 techniques
- [Lateral Movement](#lateral-movement) — 23 techniques
- [Collection](#collection) — 41 techniques
- [Command and Control](#command-and-control) — 45 techniques
- [Exfiltration](#exfiltration) — 19 techniques
- [Impact](#impact) — 33 techniques

---

## Reconnaissance
<a id="reconnaissance"></a>

[`TA0043`](https://attack.mitre.org/tactics/TA0043/) · 45 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1589 Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589) | PRE | 9 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Credentials](https://attack.mitre.org/techniques/T1589/001) | PRE | 5 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Email Addresses](https://attack.mitre.org/techniques/T1589/002) | PRE | 14 | 1 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Employee Names](https://attack.mitre.org/techniques/T1589/003) | PRE | 3 | 0 | 1 | 0 | ✓ |
| [T1590 Gather Victim Network Information](https://attack.mitre.org/techniques/T1590) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Domain Properties](https://attack.mitre.org/techniques/T1590/001) | PRE | 1 | 1 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 DNS](https://attack.mitre.org/techniques/T1590/002) | PRE | 0 | 0 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.003 Network Trust Dependencies](https://attack.mitre.org/techniques/T1590/003) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Network Topology](https://attack.mitre.org/techniques/T1590/004) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 IP Addresses](https://attack.mitre.org/techniques/T1590/005) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 Network Security Appliances](https://attack.mitre.org/techniques/T1590/006) | PRE | 1 | 0 | 1 | 0 | ✓ |
| [T1591 Gather Victim Org Information](https://attack.mitre.org/techniques/T1591) | PRE | 6 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Determine Physical Locations](https://attack.mitre.org/techniques/T1591/001) | PRE | 1 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Business Relationships](https://attack.mitre.org/techniques/T1591/002) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Identify Business Tempo](https://attack.mitre.org/techniques/T1591/003) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Identify Roles](https://attack.mitre.org/techniques/T1591/004) | PRE | 4 | 0 | 1 | 0 | ✓ |
| [T1592 Gather Victim Host Information](https://attack.mitre.org/techniques/T1592) | PRE | 1 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Hardware](https://attack.mitre.org/techniques/T1592/001) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Software](https://attack.mitre.org/techniques/T1592/002) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Firmware](https://attack.mitre.org/techniques/T1592/003) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Client Configurations](https://attack.mitre.org/techniques/T1592/004) | PRE | 1 | 0 | 1 | 0 | ✓ |
| [T1593 Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) | PRE | 6 | 0 | 2 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Social Media](https://attack.mitre.org/techniques/T1593/001) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Search Engines](https://attack.mitre.org/techniques/T1593/002) | PRE | 1 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Code Repositories](https://attack.mitre.org/techniques/T1593/003) | PRE | 3 | 0 | 2 | 1 | ✓ |
| [T1594 Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594) | PRE | 6 | 0 | 1 | 0 | ✓ |
| [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Scanning IP Blocks](https://attack.mitre.org/techniques/T1595/001) | PRE | 2 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002) | PRE | 13 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003) | PRE | 2 | 0 | 2 | 1 | ✓ |
| [T1596 Search Open Technical Databases](https://attack.mitre.org/techniques/T1596) | PRE | 2 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 DNS/Passive DNS](https://attack.mitre.org/techniques/T1596/001) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 WHOIS](https://attack.mitre.org/techniques/T1596/002) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Digital Certificates](https://attack.mitre.org/techniques/T1596/003) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 CDNs](https://attack.mitre.org/techniques/T1596/004) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Scan Databases](https://attack.mitre.org/techniques/T1596/005) | PRE | 2 | 0 | 1 | 0 | ✓ |
| [T1597 Search Closed Sources](https://attack.mitre.org/techniques/T1597) | PRE | 1 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Threat Intel Vendors](https://attack.mitre.org/techniques/T1597/001) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Purchase Technical Data](https://attack.mitre.org/techniques/T1597/002) | PRE | 1 | 0 | 1 | 0 | ✓ |
| [T1598 Phishing for Information](https://attack.mitre.org/techniques/T1598) | PRE | 5 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.001 Spearphishing Service](https://attack.mitre.org/techniques/T1598/001) | PRE | 0 | 0 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.002 Spearphishing Attachment](https://attack.mitre.org/techniques/T1598/002) | PRE | 4 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 Spearphishing Link](https://attack.mitre.org/techniques/T1598/003) | PRE | 15 | 2 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1598/004) | PRE | 2 | 0 | 1 | 0 | ✓ |
| [T1681 Search Threat Vendor Data](https://attack.mitre.org/techniques/T1681) | PRE | 2 | 0 | 1 | 0 | ✓ |

## Resource Development
<a id="resource-development"></a>

[`TA0042`](https://attack.mitre.org/tactics/TA0042/) · 47 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1583 Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) | PRE | 8 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Domains](https://attack.mitre.org/techniques/T1583/001) | PRE | 40 | 3 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 DNS Server](https://attack.mitre.org/techniques/T1583/002) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Virtual Private Server](https://attack.mitre.org/techniques/T1583/003) | PRE | 14 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Server](https://attack.mitre.org/techniques/T1583/004) | PRE | 6 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Botnet](https://attack.mitre.org/techniques/T1583/005) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 Web Services](https://attack.mitre.org/techniques/T1583/006) | PRE | 24 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.007 Serverless](https://attack.mitre.org/techniques/T1583/007) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.008 Malvertising](https://attack.mitre.org/techniques/T1583/008) | PRE | 1 | 1 | 1 | 0 | ✓ |
| [T1584 Compromise Infrastructure](https://attack.mitre.org/techniques/T1584) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Domains](https://attack.mitre.org/techniques/T1584/001) | PRE | 6 | 1 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 DNS Server](https://attack.mitre.org/techniques/T1584/002) | PRE | 2 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Virtual Private Server](https://attack.mitre.org/techniques/T1584/003) | PRE | 2 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Server](https://attack.mitre.org/techniques/T1584/004) | PRE | 10 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Botnet](https://attack.mitre.org/techniques/T1584/005) | PRE | 4 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 Web Services](https://attack.mitre.org/techniques/T1584/006) | PRE | 4 | 1 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.007 Serverless](https://attack.mitre.org/techniques/T1584/007) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.008 Network Devices](https://attack.mitre.org/techniques/T1584/008) | PRE | 4 | 0 | 1 | 0 | ✓ |
| [T1585 Establish Accounts](https://attack.mitre.org/techniques/T1585) | PRE | 5 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001) | PRE | 17 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Email Accounts](https://attack.mitre.org/techniques/T1585/002) | PRE | 18 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Cloud Accounts](https://attack.mitre.org/techniques/T1585/003) | PRE | 1 | 0 | 1 | 0 | ✓ |
| [T1586 Compromise Accounts](https://attack.mitre.org/techniques/T1586) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Social Media Accounts](https://attack.mitre.org/techniques/T1586/001) | PRE | 2 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Email Accounts](https://attack.mitre.org/techniques/T1586/002) | PRE | 12 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Cloud Accounts](https://attack.mitre.org/techniques/T1586/003) | PRE | 1 | 0 | 1 | 0 | ✓ |
| [T1587 Develop Capabilities](https://attack.mitre.org/techniques/T1587) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Malware](https://attack.mitre.org/techniques/T1587/001) | PRE | 22 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Code Signing Certificates](https://attack.mitre.org/techniques/T1587/002) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Digital Certificates](https://attack.mitre.org/techniques/T1587/003) | PRE | 4 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Exploits](https://attack.mitre.org/techniques/T1587/004) | PRE | 3 | 0 | 1 | 0 | ✓ |
| [T1588 Obtain Capabilities](https://attack.mitre.org/techniques/T1588) | PRE | 0 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Malware](https://attack.mitre.org/techniques/T1588/001) | PRE | 15 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Tool](https://attack.mitre.org/techniques/T1588/002) | PRE | 79 | 1 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Code Signing Certificates](https://attack.mitre.org/techniques/T1588/003) | PRE | 7 | 1 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Digital Certificates](https://attack.mitre.org/techniques/T1588/004) | PRE | 7 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Exploits](https://attack.mitre.org/techniques/T1588/005) | PRE | 2 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 Vulnerabilities](https://attack.mitre.org/techniques/T1588/006) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.007 Artificial Intelligence](https://attack.mitre.org/techniques/T1588/007) | PRE | 1 | 0 | 1 | 0 | ✓ |
| [T1608 Stage Capabilities](https://attack.mitre.org/techniques/T1608) | PRE | 1 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Upload Malware](https://attack.mitre.org/techniques/T1608/001) | PRE | 25 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Upload Tool](https://attack.mitre.org/techniques/T1608/002) | PRE | 2 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Install Digital Certificate](https://attack.mitre.org/techniques/T1608/003) | PRE | 1 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Drive-by Target](https://attack.mitre.org/techniques/T1608/004) | PRE | 8 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Link Target](https://attack.mitre.org/techniques/T1608/005) | PRE | 3 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 SEO Poisoning](https://attack.mitre.org/techniques/T1608/006) | PRE | 1 | 0 | 1 | 0 | ✓ |
| [T1650 Acquire Access](https://attack.mitre.org/techniques/T1650) | PRE | 1 | 0 | 1 | 0 | ✓ |

## Initial Access
<a id="initial-access"></a>

[`TA0001`](https://attack.mitre.org/tactics/TA0001/) · 22 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 44 | 6 | 8 | 25 | ✓ |
| &nbsp;&nbsp;↳ [.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 4 | 2 | 2 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002) | ESXi Lnx Mac Win | 18 | 5 | 5 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003) | Lnx Mac Win Cnt NetDev ESXi | 12 | 5 | 4 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) | IaaS IdP Office SaaS | 9 | 3 | 7 | 24 | ✓ |
| [T1091 Replication Through Removable Media](https://attack.mitre.org/techniques/T1091) | Win | 8 | 20 | 3 | 10 | ✓ |
| [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133) | Cnt Lnx Mac Win | 26 | 5 | 5 | 17 | ✓ |
| [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189) | IdP Lnx Mac Win | 31 | 10 | 5 | 18 | ✓ |
| [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Cnt ESXi IaaS Lnx Mac NetDev Win | 42 | 8 | 8 | 29 | ✓ |
| [T1195 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) | Lnx Win Mac SaaS | 3 | 2 | 6 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001) | Lnx Mac Win | 0 | 2 | 4 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002) | Lnx Win Mac | 9 | 3 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 Compromise Hardware Supply Chain](https://attack.mitre.org/techniques/T1195/003) | Lnx Mac Win | 0 | 0 | 1 | 14 | ✓ |
| [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199) | Win SaaS IaaS Lnx Mac IdP Office | 11 | 0 | 3 | 8 | ✓ |
| [T1200 Hardware Additions](https://attack.mitre.org/techniques/T1200) | Win Lnx Mac | 1 | 0 | 2 | 5 | ✓ |
| [T1566 Phishing](https://attack.mitre.org/techniques/T1566) | IdP Lnx Mac Office SaaS Win | 6 | 3 | 6 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) | Lnx Mac Win | 77 | 55 | 7 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) | IdP Lnx Mac Office SaaS Win | 43 | 29 | 5 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003) | Lnx Mac Win | 14 | 1 | 5 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004) | Lnx Mac Win IdP | 1 | 0 | 1 | 0 | ✓ |
| [T1659 Content Injection](https://attack.mitre.org/techniques/T1659) | Lnx Mac Win | 1 | 1 | 2 | 3 | ✓ |
| [T1669 Wi-Fi Networks](https://attack.mitre.org/techniques/T1669) | Lnx NetDev Win Mac | 1 | 0 | 3 | 0 | ✓ |

## Execution
<a id="execution"></a>

[`TA0002`](https://attack.mitre.org/tactics/TA0002/) · 46 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) | Win | 39 | 88 | 4 | 17 | ✓ |
| [T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) | Win Lnx Mac Cnt ESXi | 0 | 1 | 5 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 At](https://attack.mitre.org/techniques/T1053/002) | Win Lnx Mac | 3 | 3 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Cron](https://attack.mitre.org/techniques/T1053/003) | Lnx Mac ESXi | 3 | 12 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Win | 54 | 118 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.006 Systemd Timers](https://attack.mitre.org/techniques/T1053/006) | Lnx | 0 | 0 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.007 Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007) | Cnt | 0 | 0 | 2 | 7 | ✓ |
| [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) | ESXi IaaS IdP Lnx Mac NetDev Office Win | 17 | 22 | 9 | 23 | ✓ |
| &nbsp;&nbsp;↳ [.001 PowerShell](https://attack.mitre.org/techniques/T1059/001) | Win | 83 | 124 | 5 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.002 AppleScript](https://attack.mitre.org/techniques/T1059/002) | Mac | 0 | 5 | 2 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) | Win | 71 | 286 | 1 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004) | ESXi Lnx Mac NetDev | 10 | 45 | 1 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005) | Lnx Mac Win | 45 | 67 | 5 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.006 Python](https://attack.mitre.org/techniques/T1059/006) | ESXi Lnx Mac Win | 17 | 34 | 4 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.007 JavaScript](https://attack.mitre.org/techniques/T1059/007) | Lnx Mac Win | 25 | 32 | 4 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.008 Network Device CLI](https://attack.mitre.org/techniques/T1059/008) | NetDev | 0 | 1 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.009 Cloud API](https://attack.mitre.org/techniques/T1059/009) | IaaS IdP Office SaaS | 3 | 1 | 2 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.010 AutoHotKey & AutoIT](https://attack.mitre.org/techniques/T1059/010) | Win | 1 | 5 | 1 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.011 Lua](https://attack.mitre.org/techniques/T1059/011) | Lnx NetDev Win Mac | 0 | 5 | 3 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.012 Hypervisor CLI](https://attack.mitre.org/techniques/T1059/012) | ESXi | 1 | 3 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.013 Container CLI/API](https://attack.mitre.org/techniques/T1059/013) | Cnt | 1 | 0 | 2 | 0 | ✓ |
| [T1072 Software Deployment Tools](https://attack.mitre.org/techniques/T1072) | Lnx Mac NetDev SaaS Win | 6 | 1 | 10 | 27 | ✓ |
| [T1106 Native API](https://attack.mitre.org/techniques/T1106) | Lnx Mac Win | 18 | 189 | 2 | 7 | ✓ |
| [T1129 Shared Modules](https://attack.mitre.org/techniques/T1129) | Lnx Mac Win | 1 | 21 | 1 | 6 | ✓ |
| [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203) | Lnx Mac Win | 41 | 14 | 3 | 16 | ✓ |
| [T1204 User Execution](https://attack.mitre.org/techniques/T1204) | Lnx Win Mac IaaS Cnt | 2 | 2 | 6 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.001 Malicious Link](https://attack.mitre.org/techniques/T1204/001) | Lnx Mac Win | 47 | 28 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.002 Malicious File](https://attack.mitre.org/techniques/T1204/002) | Lnx Mac Win | 84 | 90 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.003 Malicious Image](https://attack.mitre.org/techniques/T1204/003) | IaaS Cnt | 1 | 0 | 4 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.004 Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004) | Lnx Mac Win | 1 | 1 | 3 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Malicious Library](https://attack.mitre.org/techniques/T1204/005) | Lnx Mac Win | 1 | 0 | 3 | 0 | ✓ |
| [T1559 Inter-Process Communication](https://attack.mitre.org/techniques/T1559) | Lnx Mac Win | 0 | 14 | 6 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.001 Component Object Model](https://attack.mitre.org/techniques/T1559/001) | Win | 3 | 17 | 2 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.002 Dynamic Data Exchange](https://attack.mitre.org/techniques/T1559/002) | Win | 11 | 8 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.003 XPC Services](https://attack.mitre.org/techniques/T1559/003) | Mac | 0 | 0 | 1 | 7 | ✓ |
| [T1569 System Services](https://attack.mitre.org/techniques/T1569) | Win Mac Lnx | 0 | 0 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.001 Launchctl](https://attack.mitre.org/techniques/T1569/001) | Mac | 0 | 6 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.002 Service Execution](https://attack.mitre.org/techniques/T1569/002) | Win | 16 | 51 | 3 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Systemctl](https://attack.mitre.org/techniques/T1569/003) | Lnx | 1 | 0 | 1 | 0 | ✓ |
| [T1609 Container Administration Command](https://attack.mitre.org/techniques/T1609) | Cnt | 1 | 4 | 5 | 11 | ✓ |
| [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610) | Cnt | 1 | 3 | 4 | 9 | ✓ |
| [T1648 Serverless Execution](https://attack.mitre.org/techniques/T1648) | SaaS IaaS Office | 0 | 1 | 2 | 8 | ✓ |
| [T1651 Cloud Administration Command](https://attack.mitre.org/techniques/T1651) | IaaS | 1 | 2 | 1 | 6 | ✓ |
| [T1674 Input Injection](https://attack.mitre.org/techniques/T1674) | Win Mac Lnx | 1 | 0 | 2 | 0 | ✓ |
| [T1675 ESXi Administration Command](https://attack.mitre.org/techniques/T1675) | ESXi | 1 | 1 | 1 | 0 | ✓ |
| [T1677 Poisoned Pipeline Execution](https://attack.mitre.org/techniques/T1677) | SaaS | 0 | 0 | 2 | 0 | ✓ |

## Persistence
<a id="persistence"></a>

[`TA0003`](https://attack.mitre.org/tactics/TA0003/) · 126 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1037 Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037) | Mac Win Lnx NetDev ESXi | 4 | 2 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.001 Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001) | Win | 2 | 4 | 1 | 2 | ✓ |
| &nbsp;&nbsp;↳ [.002 Login Hook](https://attack.mitre.org/techniques/T1037/002) | Mac | 0 | 0 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.003 Network Logon Script](https://attack.mitre.org/techniques/T1037/003) | Win | 0 | 0 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.004 RC Scripts](https://attack.mitre.org/techniques/T1037/004) | Mac Lnx NetDev ESXi | 3 | 4 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.005 Startup Items](https://attack.mitre.org/techniques/T1037/005) | Mac | 0 | 1 | 1 | 7 | ✓ |
| [T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) | Win Lnx Mac Cnt ESXi | 0 | 1 | 5 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 At](https://attack.mitre.org/techniques/T1053/002) | Win Lnx Mac | 3 | 3 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Cron](https://attack.mitre.org/techniques/T1053/003) | Lnx Mac ESXi | 3 | 12 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Win | 54 | 118 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.006 Systemd Timers](https://attack.mitre.org/techniques/T1053/006) | Lnx | 0 | 0 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.007 Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007) | Cnt | 0 | 0 | 2 | 7 | ✓ |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 44 | 6 | 8 | 25 | ✓ |
| &nbsp;&nbsp;↳ [.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 4 | 2 | 2 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002) | ESXi Lnx Mac Win | 18 | 5 | 5 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003) | Lnx Mac Win Cnt NetDev ESXi | 12 | 5 | 4 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) | IaaS IdP Office SaaS | 9 | 3 | 7 | 24 | ✓ |
| [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 3 | 2 | 7 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) | IaaS IdP SaaS | 1 | 1 | 5 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.002 Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002) | Win Office | 3 | 0 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) | IaaS IdP Office SaaS | 3 | 0 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.004 SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004) | Lnx Mac IaaS NetDev ESXi | 3 | 3 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.005 Device Registration](https://attack.mitre.org/techniques/T1098/005) | Win IdP | 1 | 1 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.006 Additional Container Cluster Roles](https://attack.mitre.org/techniques/T1098/006) | Cnt | 0 | 0 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007) | Win Mac Lnx | 7 | 4 | 0 | 11 | ✓ |
| [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112) | Win | 29 | 136 | 1 | 3 | ✓ |
| [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133) | Cnt Lnx Mac Win | 26 | 5 | 5 | 17 | ✓ |
| [T1136 Create Account](https://attack.mitre.org/techniques/T1136) | Win IaaS Lnx Mac NetDev Cnt SaaS Office IdP ESXi | 3 | 1 | 4 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.001 Local Account](https://attack.mitre.org/techniques/T1136/001) | Lnx Mac Win NetDev Cnt ESXi | 14 | 15 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.002 Domain Account](https://attack.mitre.org/techniques/T1136/002) | Lnx Mac Win | 5 | 4 | 4 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.003 Cloud Account](https://attack.mitre.org/techniques/T1136/003) | IaaS SaaS Office IdP | 2 | 1 | 3 | 14 | ✓ |
| [T1137 Office Application Startup](https://attack.mitre.org/techniques/T1137) | Win Office | 2 | 0 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.001 Office Template Macros](https://attack.mitre.org/techniques/T1137/001) | Win Office | 1 | 2 | 2 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.002 Office Test](https://attack.mitre.org/techniques/T1137/002) | Win Office | 1 | 0 | 2 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.003 Outlook Forms](https://attack.mitre.org/techniques/T1137/003) | Win Office | 0 | 1 | 2 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.004 Outlook Home Page](https://attack.mitre.org/techniques/T1137/004) | Win Office | 1 | 1 | 2 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.005 Outlook Rules](https://attack.mitre.org/techniques/T1137/005) | Win Office | 0 | 1 | 2 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.006 Add-ins](https://attack.mitre.org/techniques/T1137/006) | Win Office | 1 | 3 | 1 | 6 | ✓ |
| [T1176 Software Extensions](https://attack.mitre.org/techniques/T1176) | Lnx Mac Win | 0 | 0 | 5 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.001 Browser Extensions](https://attack.mitre.org/techniques/T1176/001) | Lnx Win Mac | 1 | 6 | 5 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 IDE Extensions](https://attack.mitre.org/techniques/T1176/002) | Lnx Mac Win | 1 | 0 | 5 | 0 | ✓ |
| [T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197) | Win | 5 | 8 | 3 | 14 | ✓ |
| [T1205 Traffic Signaling](https://attack.mitre.org/techniques/T1205) | Lnx Mac NetDev Win | 3 | 16 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.001 Port Knocking](https://attack.mitre.org/techniques/T1205/001) | Lnx Mac Win NetDev | 2 | 4 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Socket Filters](https://attack.mitre.org/techniques/T1205/002) | Lnx Mac Win | 0 | 4 | 1 | 2 | ✓ |
| [T1505 Server Software Component](https://attack.mitre.org/techniques/T1505) | Win Lnx Mac NetDev ESXi | 0 | 0 | 7 | 21 | ✓ |
| &nbsp;&nbsp;↳ [.001 SQL Stored Procedures](https://attack.mitre.org/techniques/T1505/001) | Win Lnx | 0 | 1 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.002 Transport Agent](https://attack.mitre.org/techniques/T1505/002) | Lnx Win | 0 | 1 | 3 | 21 | ✓ |
| &nbsp;&nbsp;↳ [.003 Web Shell](https://attack.mitre.org/techniques/T1505/003) | Lnx Mac NetDev Win | 31 | 19 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 IIS Components](https://attack.mitre.org/techniques/T1505/004) | Win | 0 | 3 | 4 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.005 Terminal Services DLL](https://attack.mitre.org/techniques/T1505/005) | Win | 0 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.006 vSphere Installation Bundles](https://attack.mitre.org/techniques/T1505/006) | ESXi | 1 | 1 | 3 | 0 | ✓ |
| [T1525 Implant Internal Image](https://attack.mitre.org/techniques/T1525) | IaaS Cnt | 0 | 0 | 3 | 15 | ✓ |
| [T1542 Pre-OS Boot](https://attack.mitre.org/techniques/T1542) | Lnx NetDev Win Mac | 0 | 0 | 5 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.001 System Firmware](https://attack.mitre.org/techniques/T1542/001) | Win NetDev | 0 | 3 | 3 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.002 Component Firmware](https://attack.mitre.org/techniques/T1542/002) | Win Lnx Mac | 1 | 1 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Bootkit](https://attack.mitre.org/techniques/T1542/003) | Lnx Win | 3 | 6 | 2 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.004 ROMMONkit](https://attack.mitre.org/techniques/T1542/004) | NetDev | 0 | 0 | 3 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.005 TFTP Boot](https://attack.mitre.org/techniques/T1542/005) | NetDev | 0 | 0 | 6 | 23 | ✓ |
| [T1543 Create or Modify System Process](https://attack.mitre.org/techniques/T1543) | Win Mac Lnx Cnt | 0 | 6 | 9 | 20 | ✓ |
| &nbsp;&nbsp;↳ [.001 Launch Agent](https://attack.mitre.org/techniques/T1543/001) | Mac | 1 | 20 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002) | Lnx | 3 | 8 | 4 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.003 Windows Service](https://attack.mitre.org/techniques/T1543/003) | Win | 26 | 108 | 5 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Launch Daemon](https://attack.mitre.org/techniques/T1543/004) | Mac | 0 | 10 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.005 Container Service](https://attack.mitre.org/techniques/T1543/005) | Cnt | 0 | 0 | 2 | 5 | ✓ |
| [T1546 Event Triggered Execution](https://attack.mitre.org/techniques/T1546) | Lnx Mac Win SaaS IaaS Office | 0 | 3 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.001 Change Default File Association](https://attack.mitre.org/techniques/T1546/001) | Win | 1 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Screensaver](https://attack.mitre.org/techniques/T1546/002) | Win | 0 | 1 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.003 Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003) | Win | 10 | 13 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.004 Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004) | Lnx Mac | 1 | 4 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.005 Trap](https://attack.mitre.org/techniques/T1546/005) | Mac Lnx | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 LC_LOAD_DYLIB Addition](https://attack.mitre.org/techniques/T1546/006) | Mac | 0 | 0 | 3 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.007 Netsh Helper DLL](https://attack.mitre.org/techniques/T1546/007) | Win | 0 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.008 Accessibility Features](https://attack.mitre.org/techniques/T1546/008) | Win | 6 | 1 | 3 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.009 AppCert DLLs](https://attack.mitre.org/techniques/T1546/009) | Win | 0 | 1 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.010 AppInit DLLs](https://attack.mitre.org/techniques/T1546/010) | Win | 1 | 3 | 2 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.011 Application Shimming](https://attack.mitre.org/techniques/T1546/011) | Win | 1 | 3 | 2 | 2 | ✓ |
| &nbsp;&nbsp;↳ [.012 Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012) | Win | 0 | 2 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.013 PowerShell Profile](https://attack.mitre.org/techniques/T1546/013) | Win | 1 | 0 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.014 Emond](https://attack.mitre.org/techniques/T1546/014) | Mac | 0 | 0 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.015 Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015) | Win | 1 | 11 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.016 Installer Packages](https://attack.mitre.org/techniques/T1546/016) | Lnx Win Mac | 0 | 1 | 0 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.017 Udev Rules](https://attack.mitre.org/techniques/T1546/017) | Lnx | 0 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.018 Python Startup Hooks](https://attack.mitre.org/techniques/T1546/018) | Lnx Mac Win | 0 | 0 | 0 | 0 | ✓ |
| [T1547 Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547) | Lnx Mac Win NetDev | 1 | 5 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001) | Win | 55 | 194 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Authentication Package](https://attack.mitre.org/techniques/T1547/002) | Win | 0 | 1 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.003 Time Providers](https://attack.mitre.org/techniques/T1547/003) | Win | 0 | 0 | 2 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.004 Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547/004) | Win | 3 | 10 | 2 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.005 Security Support Provider](https://attack.mitre.org/techniques/T1547/005) | Win | 0 | 3 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.006 Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006) | Mac Lnx | 0 | 3 | 4 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.007 Re-opened Applications](https://attack.mitre.org/techniques/T1547/007) | Mac | 0 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.008 LSASS Driver](https://attack.mitre.org/techniques/T1547/008) | Win | 0 | 2 | 3 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.009 Shortcut Modification](https://attack.mitre.org/techniques/T1547/009) | Win | 4 | 25 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.010 Port Monitors](https://attack.mitre.org/techniques/T1547/010) | Win | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.012 Print Processors](https://attack.mitre.org/techniques/T1547/012) | Win | 1 | 2 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.013 XDG Autostart Entries](https://attack.mitre.org/techniques/T1547/013) | Lnx | 1 | 6 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.014 Active Setup](https://attack.mitre.org/techniques/T1547/014) | Win | 0 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.015 Login Items](https://attack.mitre.org/techniques/T1547/015) | Mac | 0 | 3 | 0 | 0 | ✓ |
| [T1554 Compromise Host Software Binary](https://attack.mitre.org/techniques/T1554) | Lnx Mac Win ESXi | 2 | 16 | 1 | 9 | ✓ |
| [T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556) | Win Lnx Mac NetDev IaaS SaaS Office IdP | 1 | 3 | 9 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.001 Domain Controller Authentication](https://attack.mitre.org/techniques/T1556/001) | Win | 1 | 1 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 Password Filter DLL](https://attack.mitre.org/techniques/T1556/002) | Win | 2 | 1 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.003 Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003) | Lnx Mac | 0 | 2 | 2 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.004 Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) | NetDev | 0 | 2 | 2 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.005 Reversible Encryption](https://attack.mitre.org/techniques/T1556/005) | Win | 0 | 0 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.006 Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006) | Win SaaS IaaS Lnx Mac Office IdP | 1 | 2 | 3 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.007 Hybrid Identity](https://attack.mitre.org/techniques/T1556/007) | Win SaaS IaaS Office IdP | 1 | 1 | 3 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.008 Network Provider DLL](https://attack.mitre.org/techniques/T1556/008) | Win | 0 | 0 | 3 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.009 Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009) | IaaS IdP | 2 | 0 | 1 | 14 | ✓ |
| [T1574 Hijack Execution Flow](https://attack.mitre.org/techniques/T1574) | Lnx Mac Win | 0 | 8 | 10 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.001 DLL](https://attack.mitre.org/techniques/T1574/001) | Win | 32 | 67 | 5 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Dylib Hijacking](https://attack.mitre.org/techniques/T1574/004) | Mac | 0 | 1 | 1 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.005 Executable Installer File Permissions Weakness](https://attack.mitre.org/techniques/T1574/005) | Win | 1 | 0 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.006 Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006) | Lnx Mac | 3 | 6 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.007 Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007) | Win Mac Lnx | 0 | 3 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.008 Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008) | Win | 0 | 2 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.009 Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009) | Win | 0 | 2 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.010 Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010) | Win | 0 | 1 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.011 Services Registry Permissions Weakness](https://attack.mitre.org/techniques/T1574/011) | Win | 0 | 0 | 1 | 2 | ✓ |
| &nbsp;&nbsp;↳ [.012 COR_PROFILER](https://attack.mitre.org/techniques/T1574/012) | Win | 1 | 1 | 3 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.013 KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013) | Win | 1 | 1 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014) | Win | 0 | 1 | 1 | 10 | ✓ |
| [T1653 Power Settings](https://attack.mitre.org/techniques/T1653) | Win Lnx Mac NetDev | 0 | 2 | 1 | 4 | ✓ |
| [T1668 Exclusive Control](https://attack.mitre.org/techniques/T1668) | Lnx Mac Win | 0 | 0 | 0 | 0 | ✓ |
| [T1671 Cloud Application Integration](https://attack.mitre.org/techniques/T1671) | Office SaaS | 0 | 0 | 2 | 0 | ✓ |

## Privilege Escalation
<a id="privilege-escalation"></a>

[`TA0004`](https://attack.mitre.org/tactics/TA0004/) · 109 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1037 Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037) | Mac Win Lnx NetDev ESXi | 4 | 2 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.001 Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001) | Win | 2 | 4 | 1 | 2 | ✓ |
| &nbsp;&nbsp;↳ [.002 Login Hook](https://attack.mitre.org/techniques/T1037/002) | Mac | 0 | 0 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.003 Network Logon Script](https://attack.mitre.org/techniques/T1037/003) | Win | 0 | 0 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.004 RC Scripts](https://attack.mitre.org/techniques/T1037/004) | Mac Lnx NetDev ESXi | 3 | 4 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.005 Startup Items](https://attack.mitre.org/techniques/T1037/005) | Mac | 0 | 1 | 1 | 7 | ✓ |
| [T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) | Win Lnx Mac Cnt ESXi | 0 | 1 | 5 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 At](https://attack.mitre.org/techniques/T1053/002) | Win Lnx Mac | 3 | 3 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Cron](https://attack.mitre.org/techniques/T1053/003) | Lnx Mac ESXi | 3 | 12 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Win | 54 | 118 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.006 Systemd Timers](https://attack.mitre.org/techniques/T1053/006) | Lnx | 0 | 0 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.007 Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007) | Cnt | 0 | 0 | 2 | 7 | ✓ |
| [T1055 Process Injection](https://attack.mitre.org/techniques/T1055) | Lnx Mac Win | 15 | 60 | 2 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.001 Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001) | Win | 9 | 56 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.002 Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002) | Win | 2 | 10 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.003 Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003) | Win | 0 | 4 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.004 Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004) | Win | 1 | 11 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.005 Thread Local Storage](https://attack.mitre.org/techniques/T1055/005) | Win | 0 | 2 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.008 Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008) | Lnx | 0 | 1 | 2 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.009 Proc Memory](https://attack.mitre.org/techniques/T1055/009) | Lnx | 0 | 0 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.011 Extra Window Memory Injection](https://attack.mitre.org/techniques/T1055/011) | Win | 0 | 2 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.012 Process Hollowing](https://attack.mitre.org/techniques/T1055/012) | Win | 7 | 32 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.013 Process Doppelgänging](https://attack.mitre.org/techniques/T1055/013) | Win | 1 | 2 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.014 VDSO Hijacking](https://attack.mitre.org/techniques/T1055/014) | Lnx | 0 | 0 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.015 ListPlanting](https://attack.mitre.org/techniques/T1055/015) | Win | 0 | 1 | 1 | 1 | ✓ |
| [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) | Cnt Lnx Mac Win | 22 | 19 | 5 | 21 | ✓ |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 44 | 6 | 8 | 25 | ✓ |
| &nbsp;&nbsp;↳ [.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 4 | 2 | 2 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002) | ESXi Lnx Mac Win | 18 | 5 | 5 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003) | Lnx Mac Win Cnt NetDev ESXi | 12 | 5 | 4 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) | IaaS IdP Office SaaS | 9 | 3 | 7 | 24 | ✓ |
| [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 3 | 2 | 7 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) | IaaS IdP SaaS | 1 | 1 | 5 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.002 Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002) | Win Office | 3 | 0 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) | IaaS IdP Office SaaS | 3 | 0 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.004 SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004) | Lnx Mac IaaS NetDev ESXi | 3 | 3 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.005 Device Registration](https://attack.mitre.org/techniques/T1098/005) | Win IdP | 1 | 1 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.006 Additional Container Cluster Roles](https://attack.mitre.org/techniques/T1098/006) | Cnt | 0 | 0 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007) | Win Mac Lnx | 7 | 4 | 0 | 11 | ✓ |
| [T1134 Access Token Manipulation](https://attack.mitre.org/techniques/T1134) | Win | 3 | 19 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.001 Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) | Win | 2 | 15 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Create Process with Token](https://attack.mitre.org/techniques/T1134/002) | Win | 2 | 11 | 2 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.003 Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) | Win | 2 | 3 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004) | Win | 0 | 4 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 SID-History Injection](https://attack.mitre.org/techniques/T1134/005) | Win | 0 | 2 | 1 | 13 | ✓ |
| [T1484 Domain or Tenant Policy Modification](https://attack.mitre.org/techniques/T1484) | Win IdP | 0 | 0 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.001 Group Policy Modification](https://attack.mitre.org/techniques/T1484/001) | Win | 4 | 8 | 2 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Trust Modification](https://attack.mitre.org/techniques/T1484/002) | IdP Win | 2 | 1 | 2 | 0 | ✓ |
| [T1543 Create or Modify System Process](https://attack.mitre.org/techniques/T1543) | Win Mac Lnx Cnt | 0 | 6 | 9 | 20 | ✓ |
| &nbsp;&nbsp;↳ [.001 Launch Agent](https://attack.mitre.org/techniques/T1543/001) | Mac | 1 | 20 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002) | Lnx | 3 | 8 | 4 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.003 Windows Service](https://attack.mitre.org/techniques/T1543/003) | Win | 26 | 108 | 5 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Launch Daemon](https://attack.mitre.org/techniques/T1543/004) | Mac | 0 | 10 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.005 Container Service](https://attack.mitre.org/techniques/T1543/005) | Cnt | 0 | 0 | 2 | 5 | ✓ |
| [T1546 Event Triggered Execution](https://attack.mitre.org/techniques/T1546) | Lnx Mac Win SaaS IaaS Office | 0 | 3 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.001 Change Default File Association](https://attack.mitre.org/techniques/T1546/001) | Win | 1 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Screensaver](https://attack.mitre.org/techniques/T1546/002) | Win | 0 | 1 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.003 Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003) | Win | 10 | 13 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.004 Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004) | Lnx Mac | 1 | 4 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.005 Trap](https://attack.mitre.org/techniques/T1546/005) | Mac Lnx | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 LC_LOAD_DYLIB Addition](https://attack.mitre.org/techniques/T1546/006) | Mac | 0 | 0 | 3 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.007 Netsh Helper DLL](https://attack.mitre.org/techniques/T1546/007) | Win | 0 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.008 Accessibility Features](https://attack.mitre.org/techniques/T1546/008) | Win | 6 | 1 | 3 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.009 AppCert DLLs](https://attack.mitre.org/techniques/T1546/009) | Win | 0 | 1 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.010 AppInit DLLs](https://attack.mitre.org/techniques/T1546/010) | Win | 1 | 3 | 2 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.011 Application Shimming](https://attack.mitre.org/techniques/T1546/011) | Win | 1 | 3 | 2 | 2 | ✓ |
| &nbsp;&nbsp;↳ [.012 Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012) | Win | 0 | 2 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.013 PowerShell Profile](https://attack.mitre.org/techniques/T1546/013) | Win | 1 | 0 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.014 Emond](https://attack.mitre.org/techniques/T1546/014) | Mac | 0 | 0 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.015 Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015) | Win | 1 | 11 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.016 Installer Packages](https://attack.mitre.org/techniques/T1546/016) | Lnx Win Mac | 0 | 1 | 0 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.017 Udev Rules](https://attack.mitre.org/techniques/T1546/017) | Lnx | 0 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.018 Python Startup Hooks](https://attack.mitre.org/techniques/T1546/018) | Lnx Mac Win | 0 | 0 | 0 | 0 | ✓ |
| [T1547 Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547) | Lnx Mac Win NetDev | 1 | 5 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001) | Win | 55 | 194 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Authentication Package](https://attack.mitre.org/techniques/T1547/002) | Win | 0 | 1 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.003 Time Providers](https://attack.mitre.org/techniques/T1547/003) | Win | 0 | 0 | 2 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.004 Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547/004) | Win | 3 | 10 | 2 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.005 Security Support Provider](https://attack.mitre.org/techniques/T1547/005) | Win | 0 | 3 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.006 Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006) | Mac Lnx | 0 | 3 | 4 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.007 Re-opened Applications](https://attack.mitre.org/techniques/T1547/007) | Mac | 0 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.008 LSASS Driver](https://attack.mitre.org/techniques/T1547/008) | Win | 0 | 2 | 3 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.009 Shortcut Modification](https://attack.mitre.org/techniques/T1547/009) | Win | 4 | 25 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.010 Port Monitors](https://attack.mitre.org/techniques/T1547/010) | Win | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.012 Print Processors](https://attack.mitre.org/techniques/T1547/012) | Win | 1 | 2 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.013 XDG Autostart Entries](https://attack.mitre.org/techniques/T1547/013) | Lnx | 1 | 6 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.014 Active Setup](https://attack.mitre.org/techniques/T1547/014) | Win | 0 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.015 Login Items](https://attack.mitre.org/techniques/T1547/015) | Mac | 0 | 3 | 0 | 0 | ✓ |
| [T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548) | Lnx Mac Win IaaS Office IdP | 1 | 1 | 8 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.001 Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001) | Lnx Mac | 0 | 2 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.002 Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002) | Win | 11 | 49 | 4 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003) | Lnx Mac | 0 | 3 | 3 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.004 Elevated Execution with Prompt](https://attack.mitre.org/techniques/T1548/004) | Mac | 0 | 1 | 1 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.005 Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005) | IaaS Office IdP | 0 | 0 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.006 TCC Manipulation](https://attack.mitre.org/techniques/T1548/006) | Mac | 0 | 1 | 3 | 17 | ✓ |
| [T1574 Hijack Execution Flow](https://attack.mitre.org/techniques/T1574) | Lnx Mac Win | 0 | 8 | 10 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.001 DLL](https://attack.mitre.org/techniques/T1574/001) | Win | 32 | 67 | 5 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Dylib Hijacking](https://attack.mitre.org/techniques/T1574/004) | Mac | 0 | 1 | 1 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.005 Executable Installer File Permissions Weakness](https://attack.mitre.org/techniques/T1574/005) | Win | 1 | 0 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.006 Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006) | Lnx Mac | 3 | 6 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.007 Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007) | Win Mac Lnx | 0 | 3 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.008 Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008) | Win | 0 | 2 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.009 Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009) | Win | 0 | 2 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.010 Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010) | Win | 0 | 1 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.011 Services Registry Permissions Weakness](https://attack.mitre.org/techniques/T1574/011) | Win | 0 | 0 | 1 | 2 | ✓ |
| &nbsp;&nbsp;↳ [.012 COR_PROFILER](https://attack.mitre.org/techniques/T1574/012) | Win | 1 | 1 | 3 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.013 KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013) | Win | 1 | 1 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014) | Win | 0 | 1 | 1 | 10 | ✓ |
| [T1611 Escape to Host](https://attack.mitre.org/techniques/T1611) | Win Lnx Cnt ESXi | 1 | 4 | 5 | 19 | ✓ |

## Defense Evasion
<a id="defense-evasion"></a>

[`TA0005`](https://attack.mitre.org/tactics/TA0005/) · 215 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1006 Direct Volume Access](https://attack.mitre.org/techniques/T1006) | NetDev Win | 2 | 1 | 2 | 0 | ✓ |
| [T1014 Rootkit](https://attack.mitre.org/techniques/T1014) | Lnx Mac Win | 6 | 24 | 0 | 0 | ✓ |
| [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) | ESXi Lnx Mac NetDev Win | 18 | 130 | 4 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.001 Binary Padding](https://attack.mitre.org/techniques/T1027/001) | Lnx Win Mac | 8 | 20 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Software Packing](https://attack.mitre.org/techniques/T1027/002) | Lnx Mac Win | 23 | 72 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.003 Steganography](https://attack.mitre.org/techniques/T1027/003) | Lnx Mac Win | 8 | 19 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Compile After Delivery](https://attack.mitre.org/techniques/T1027/004) | Lnx Mac Win | 4 | 6 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005) | Lnx Mac Win | 7 | 9 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 HTML Smuggling](https://attack.mitre.org/techniques/T1027/006) | Win Lnx Mac | 1 | 2 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.007 Dynamic API Resolution](https://attack.mitre.org/techniques/T1027/007) | Win | 2 | 13 | 0 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.008 Stripped Payloads](https://attack.mitre.org/techniques/T1027/008) | Mac Lnx Win NetDev | 0 | 2 | 0 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.009 Embedded Payloads](https://attack.mitre.org/techniques/T1027/009) | Lnx Mac Win | 3 | 18 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010) | Lnx Mac Win | 28 | 31 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.011 Fileless Storage](https://attack.mitre.org/techniques/T1027/011) | Win Lnx | 2 | 27 | 1 | 1 | ✓ |
| &nbsp;&nbsp;↳ [.012 LNK Icon Smuggling](https://attack.mitre.org/techniques/T1027/012) | Win | 3 | 1 | 2 | 2 | ✓ |
| &nbsp;&nbsp;↳ [.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013) | Lnx Mac Win | 37 | 172 | 2 | 1 | ✓ |
| &nbsp;&nbsp;↳ [.014 Polymorphic Code](https://attack.mitre.org/techniques/T1027/014) | Win Mac Lnx | 0 | 1 | 2 | 1 | ✓ |
| &nbsp;&nbsp;↳ [.015 Compression](https://attack.mitre.org/techniques/T1027/015) | Lnx Win Mac | 7 | 24 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.016 Junk Code Insertion](https://attack.mitre.org/techniques/T1027/016) | Lnx Mac Win | 5 | 14 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.017 SVG Smuggling](https://attack.mitre.org/techniques/T1027/017) | Lnx Mac Win | 0 | 0 | 1 | 0 | ✓ |
| [T1036 Masquerading](https://attack.mitre.org/techniques/T1036) | Cnt ESXi Lnx Mac Win | 20 | 31 | 8 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.001 Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001) | Win Mac | 2 | 7 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.002 Right-to-Left Override](https://attack.mitre.org/techniques/T1036/002) | Lnx Mac Win | 5 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Rename Legitimate Utilities](https://attack.mitre.org/techniques/T1036/003) | Lnx Mac Win | 6 | 4 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004) | Lnx Mac Win | 22 | 61 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005) | Cnt ESXi Lnx Mac Win | 59 | 130 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.006 Space after Filename](https://attack.mitre.org/techniques/T1036/006) | Lnx Mac | 1 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.007 Double File Extension](https://attack.mitre.org/techniques/T1036/007) | Win | 2 | 3 | 2 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.008 Masquerade File Type](https://attack.mitre.org/techniques/T1036/008) | Lnx Mac Win | 3 | 11 | 3 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.009 Break Process Trees](https://attack.mitre.org/techniques/T1036/009) | Lnx Mac | 0 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.010 Masquerade Account Name](https://attack.mitre.org/techniques/T1036/010) | Lnx Mac Win SaaS IaaS Cnt Office IdP | 4 | 2 | 2 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.011 Overwrite Process Arguments](https://attack.mitre.org/techniques/T1036/011) | Lnx | 0 | 1 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.012 Browser Fingerprint](https://attack.mitre.org/techniques/T1036/012) | Lnx Mac Win | 0 | 1 | 1 | 0 | ✓ |
| [T1055 Process Injection](https://attack.mitre.org/techniques/T1055) | Lnx Mac Win | 15 | 60 | 2 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.001 Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001) | Win | 9 | 56 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.002 Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002) | Win | 2 | 10 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.003 Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003) | Win | 0 | 4 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.004 Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004) | Win | 1 | 11 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.005 Thread Local Storage](https://attack.mitre.org/techniques/T1055/005) | Win | 0 | 2 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.008 Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008) | Lnx | 0 | 1 | 2 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.009 Proc Memory](https://attack.mitre.org/techniques/T1055/009) | Lnx | 0 | 0 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.011 Extra Window Memory Injection](https://attack.mitre.org/techniques/T1055/011) | Win | 0 | 2 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.012 Process Hollowing](https://attack.mitre.org/techniques/T1055/012) | Win | 7 | 32 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.013 Process Doppelgänging](https://attack.mitre.org/techniques/T1055/013) | Win | 1 | 2 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.014 VDSO Hijacking](https://attack.mitre.org/techniques/T1055/014) | Lnx | 0 | 0 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.015 ListPlanting](https://attack.mitre.org/techniques/T1055/015) | Win | 0 | 1 | 1 | 1 | ✓ |
| [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070) | Cnt ESXi Lnx Mac NetDev Office Win | 4 | 25 | 3 | 20 | ✓ |
| &nbsp;&nbsp;↳ [.001 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001) | Win | 13 | 26 | 3 | 21 | ✓ |
| &nbsp;&nbsp;↳ [.002 Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1070/002) | Lnx Mac | 4 | 4 | 3 | 21 | ✓ |
| &nbsp;&nbsp;↳ [.003 Clear Command History](https://attack.mitre.org/techniques/T1070/003) | ESXi Lnx Mac NetDev Win | 8 | 3 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.004 File Deletion](https://attack.mitre.org/techniques/T1070/004) | ESXi Lnx Mac Win | 46 | 239 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Network Share Connection Removal](https://attack.mitre.org/techniques/T1070/005) | Win | 1 | 4 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 Timestomp](https://attack.mitre.org/techniques/T1070/006) | ESXi Lnx Mac Win | 11 | 42 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.007 Clear Network Connection History and Configurations](https://attack.mitre.org/techniques/T1070/007) | Lnx Mac Win NetDev | 2 | 1 | 2 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.008 Clear Mailbox Data](https://attack.mitre.org/techniques/T1070/008) | Lnx Mac Office Win | 2 | 2 | 3 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.009 Clear Persistence](https://attack.mitre.org/techniques/T1070/009) | ESXi Lnx Win Mac | 0 | 15 | 2 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.010 Relocate Malware](https://attack.mitre.org/techniques/T1070/010) | Lnx Mac Win NetDev | 0 | 0 | 0 | 3 | ✓ |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 44 | 6 | 8 | 25 | ✓ |
| &nbsp;&nbsp;↳ [.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 4 | 2 | 2 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002) | ESXi Lnx Mac Win | 18 | 5 | 5 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003) | Lnx Mac Win Cnt NetDev ESXi | 12 | 5 | 4 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) | IaaS IdP Office SaaS | 9 | 3 | 7 | 24 | ✓ |
| [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112) | Win | 29 | 136 | 1 | 3 | ✓ |
| [T1127 Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127) | Win | 0 | 0 | 3 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.001 MSBuild](https://attack.mitre.org/techniques/T1127/001) | Win | 0 | 2 | 2 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.002 ClickOnce](https://attack.mitre.org/techniques/T1127/002) | Win | 0 | 0 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.003 JamPlus](https://attack.mitre.org/techniques/T1127/003) | Win | 0 | 0 | 2 | 0 | ✓ |
| [T1134 Access Token Manipulation](https://attack.mitre.org/techniques/T1134) | Win | 3 | 19 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.001 Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) | Win | 2 | 15 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Create Process with Token](https://attack.mitre.org/techniques/T1134/002) | Win | 2 | 11 | 2 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.003 Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) | Win | 2 | 3 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004) | Win | 0 | 4 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 SID-History Injection](https://attack.mitre.org/techniques/T1134/005) | Win | 0 | 2 | 1 | 13 | ✓ |
| [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) | ESXi Lnx Mac Win | 38 | 274 | 0 | 0 | ✓ |
| [T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197) | Win | 5 | 8 | 3 | 14 | ✓ |
| [T1202 Indirect Command Execution](https://attack.mitre.org/techniques/T1202) | Win | 2 | 2 | 0 | 0 | ✓ |
| [T1205 Traffic Signaling](https://attack.mitre.org/techniques/T1205) | Lnx Mac NetDev Win | 3 | 16 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.001 Port Knocking](https://attack.mitre.org/techniques/T1205/001) | Lnx Mac Win NetDev | 2 | 4 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Socket Filters](https://attack.mitre.org/techniques/T1205/002) | Lnx Mac Win | 0 | 4 | 1 | 2 | ✓ |
| [T1207 Rogue Domain Controller](https://attack.mitre.org/techniques/T1207) | Win | 0 | 1 | 0 | 0 | ✓ |
| [T1211 Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) | Lnx Win Mac SaaS IaaS | 2 | 0 | 4 | 22 | ✓ |
| [T1216 System Script Proxy Execution](https://attack.mitre.org/techniques/T1216) | Win | 0 | 0 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.001 PubPrn](https://attack.mitre.org/techniques/T1216/001) | Win | 1 | 0 | 2 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.002 SyncAppvPublishingServer](https://attack.mitre.org/techniques/T1216/002) | Win | 0 | 0 | 1 | 4 | ✓ |
| [T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218) | Win Lnx Mac | 2 | 0 | 6 | 20 | ✓ |
| &nbsp;&nbsp;↳ [.001 Compiled HTML File](https://attack.mitre.org/techniques/T1218/001) | Win | 5 | 1 | 2 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.002 Control Panel](https://attack.mitre.org/techniques/T1218/002) | Win | 0 | 2 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 CMSTP](https://attack.mitre.org/techniques/T1218/003) | Win | 2 | 2 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.004 InstallUtil](https://attack.mitre.org/techniques/T1218/004) | Win | 2 | 4 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.005 Mshta](https://attack.mitre.org/techniques/T1218/005) | Win | 17 | 11 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.007 Msiexec](https://attack.mitre.org/techniques/T1218/007) | Win | 6 | 21 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.008 Odbcconf](https://attack.mitre.org/techniques/T1218/008) | Win | 1 | 2 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.009 Regsvcs/Regasm](https://attack.mitre.org/techniques/T1218/009) | Win | 0 | 1 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010) | Win | 11 | 23 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.011 Rundll32](https://attack.mitre.org/techniques/T1218/011) | Win | 26 | 69 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.012 Verclsid](https://attack.mitre.org/techniques/T1218/012) | Win | 0 | 1 | 3 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.013 Mavinject](https://attack.mitre.org/techniques/T1218/013) | Win | 0 | 1 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.014 MMC](https://attack.mitre.org/techniques/T1218/014) | Win | 1 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.015 Electron Applications](https://attack.mitre.org/techniques/T1218/015) | Lnx Mac Win | 0 | 1 | 3 | 18 | ✓ |
| [T1220 XSL Script Processing](https://attack.mitre.org/techniques/T1220) | Win | 2 | 1 | 1 | 6 | ✓ |
| [T1221 Template Injection](https://attack.mitre.org/techniques/T1221) | Win | 7 | 2 | 4 | 14 | ✓ |
| [T1222 File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222) | ESXi Lnx Mac Win | 0 | 1 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.001 Windows File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/001) | Win | 2 | 9 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.002 Linux and Mac File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/002) | Mac Lnx | 3 | 10 | 2 | 11 | ✓ |
| [T1480 Execution Guardrails](https://attack.mitre.org/techniques/T1480) | ESXi Lnx Mac Win | 3 | 33 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Environmental Keying](https://attack.mitre.org/techniques/T1480/001) | Lnx Win Mac | 2 | 8 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Mutual Exclusion](https://attack.mitre.org/techniques/T1480/002) | Lnx Mac Win | 1 | 15 | 1 | 0 | ✓ |
| [T1484 Domain or Tenant Policy Modification](https://attack.mitre.org/techniques/T1484) | Win IdP | 0 | 0 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.001 Group Policy Modification](https://attack.mitre.org/techniques/T1484/001) | Win | 4 | 8 | 2 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Trust Modification](https://attack.mitre.org/techniques/T1484/002) | IdP Win | 2 | 1 | 2 | 0 | ✓ |
| [T1497 Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) | Lnx Mac Win | 3 | 22 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 System Checks](https://attack.mitre.org/techniques/T1497/001) | Lnx Mac Win | 5 | 59 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 User Activity Based Checks](https://attack.mitre.org/techniques/T1497/002) | Lnx Win Mac | 2 | 3 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Time Based Checks](https://attack.mitre.org/techniques/T1497/003) | Lnx Mac Win | 0 | 45 | 0 | 0 | ✓ |
| [T1535 Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535) | IaaS | 0 | 0 | 1 | 1 | ✓ |
| [T1542 Pre-OS Boot](https://attack.mitre.org/techniques/T1542) | Lnx NetDev Win Mac | 0 | 0 | 5 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.001 System Firmware](https://attack.mitre.org/techniques/T1542/001) | Win NetDev | 0 | 3 | 3 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.002 Component Firmware](https://attack.mitre.org/techniques/T1542/002) | Win Lnx Mac | 1 | 1 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Bootkit](https://attack.mitre.org/techniques/T1542/003) | Lnx Win | 3 | 6 | 2 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.004 ROMMONkit](https://attack.mitre.org/techniques/T1542/004) | NetDev | 0 | 0 | 3 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.005 TFTP Boot](https://attack.mitre.org/techniques/T1542/005) | NetDev | 0 | 0 | 6 | 23 | ✓ |
| [T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548) | Lnx Mac Win IaaS Office IdP | 1 | 1 | 8 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.001 Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001) | Lnx Mac | 0 | 2 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.002 Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002) | Win | 11 | 49 | 4 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003) | Lnx Mac | 0 | 3 | 3 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.004 Elevated Execution with Prompt](https://attack.mitre.org/techniques/T1548/004) | Mac | 0 | 1 | 1 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.005 Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005) | IaaS Office IdP | 0 | 0 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.006 TCC Manipulation](https://attack.mitre.org/techniques/T1548/006) | Mac | 0 | 1 | 3 | 17 | ✓ |
| [T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550) | Win SaaS IaaS Cnt IdP Office Lnx | 0 | 1 | 7 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001) | SaaS Cnt IaaS Office IdP | 2 | 2 | 5 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002) | Win | 11 | 8 | 4 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.003 Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) | Win | 3 | 3 | 4 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.004 Web Session Cookie](https://attack.mitre.org/techniques/T1550/004) | SaaS IaaS Office | 1 | 0 | 1 | 3 | ✓ |
| [T1553 Subvert Trust Controls](https://attack.mitre.org/techniques/T1553) | Win Mac Lnx | 1 | 0 | 5 | 20 | ✓ |
| &nbsp;&nbsp;↳ [.001 Gatekeeper Bypass](https://attack.mitre.org/techniques/T1553/001) | Mac | 0 | 6 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.002 Code Signing](https://attack.mitre.org/techniques/T1553/002) | Mac Win | 26 | 52 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 SIP and Trust Provider Hijacking](https://attack.mitre.org/techniques/T1553/003) | Win | 0 | 0 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.004 Install Root Certificate](https://attack.mitre.org/techniques/T1553/004) | Lnx Mac Win | 0 | 4 | 2 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.005 Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005) | Win | 3 | 2 | 2 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.006 Code Signing Policy Modification](https://attack.mitre.org/techniques/T1553/006) | Win Mac | 2 | 3 | 3 | 13 | ✓ |
| [T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556) | Win Lnx Mac NetDev IaaS SaaS Office IdP | 1 | 3 | 9 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.001 Domain Controller Authentication](https://attack.mitre.org/techniques/T1556/001) | Win | 1 | 1 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 Password Filter DLL](https://attack.mitre.org/techniques/T1556/002) | Win | 2 | 1 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.003 Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003) | Lnx Mac | 0 | 2 | 2 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.004 Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) | NetDev | 0 | 2 | 2 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.005 Reversible Encryption](https://attack.mitre.org/techniques/T1556/005) | Win | 0 | 0 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.006 Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006) | Win SaaS IaaS Lnx Mac Office IdP | 1 | 2 | 3 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.007 Hybrid Identity](https://attack.mitre.org/techniques/T1556/007) | Win SaaS IaaS Office IdP | 1 | 1 | 3 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.008 Network Provider DLL](https://attack.mitre.org/techniques/T1556/008) | Win | 0 | 0 | 3 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.009 Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009) | IaaS IdP | 2 | 0 | 1 | 14 | ✓ |
| [T1562 Impair Defenses](https://attack.mitre.org/techniques/T1562) | Win IaaS Lnx Mac Cnt NetDev IdP Office ESXi | 2 | 3 | 7 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.001 Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001) | Cnt IaaS Lnx Mac NetDev Win | 30 | 71 | 5 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.002 Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002) | Win | 2 | 1 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.003 Impair Command History Logging](https://attack.mitre.org/techniques/T1562/003) | ESXi Lnx Mac NetDev Win | 4 | 4 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.004 Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004) | ESXi Lnx Mac NetDev Win | 17 | 24 | 4 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.006 Indicator Blocking](https://attack.mitre.org/techniques/T1562/006) | Win Mac Lnx ESXi | 2 | 8 | 3 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.007 Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007) | IaaS | 0 | 1 | 2 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.008 Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008) | IaaS SaaS Office IdP | 1 | 1 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.009 Safe Mode Boot](https://attack.mitre.org/techniques/T1562/009) | Win | 0 | 7 | 2 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.010 Downgrade Attack](https://attack.mitre.org/techniques/T1562/010) | Win Lnx Mac | 0 | 2 | 2 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.011 Spoof Security Alerting](https://attack.mitre.org/techniques/T1562/011) | Win Mac Lnx | 0 | 0 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.012 Disable or Modify Linux Audit System](https://attack.mitre.org/techniques/T1562/012) | Lnx | 0 | 1 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.013 Disable or Modify Network Device Firewall](https://attack.mitre.org/techniques/T1562/013) | NetDev | 1 | 1 | 3 | 0 | ✓ |
| [T1564 Hide Artifacts](https://attack.mitre.org/techniques/T1564) | Lnx Office Win Mac ESXi | 0 | 5 | 4 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001) | Lnx Win Mac | 12 | 45 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Hidden Users](https://attack.mitre.org/techniques/T1564/002) | Mac Win Lnx | 2 | 1 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.003 Hidden Window](https://attack.mitre.org/techniques/T1564/003) | Lnx Mac Win | 16 | 38 | 2 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.004 NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004) | Win | 1 | 15 | 1 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.005 Hidden File System](https://attack.mitre.org/techniques/T1564/005) | Lnx Mac Win | 2 | 4 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.006 Run Virtual Instance](https://attack.mitre.org/techniques/T1564/006) | Lnx Mac Win ESXi | 0 | 3 | 3 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.007 VBA Stomping](https://attack.mitre.org/techniques/T1564/007) | Lnx Win Mac | 0 | 0 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.008 Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008) | Win Lnx Mac Office | 2 | 0 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.009 Resource Forking](https://attack.mitre.org/techniques/T1564/009) | Mac | 0 | 2 | 1 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.010 Process Argument Spoofing](https://attack.mitre.org/techniques/T1564/010) | Win | 0 | 2 | 0 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.011 Ignore Process Interrupts](https://attack.mitre.org/techniques/T1564/011) | Lnx Mac Win | 2 | 4 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.012 File/Path Exclusions](https://attack.mitre.org/techniques/T1564/012) | Lnx Mac Win | 1 | 0 | 2 | 1 | ✓ |
| &nbsp;&nbsp;↳ [.013 Bind Mounts](https://attack.mitre.org/techniques/T1564/013) | Lnx | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.014 Extended Attributes](https://attack.mitre.org/techniques/T1564/014) | Lnx Mac | 0 | 0 | 1 | 0 | ✓ |
| [T1574 Hijack Execution Flow](https://attack.mitre.org/techniques/T1574) | Lnx Mac Win | 0 | 8 | 10 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.001 DLL](https://attack.mitre.org/techniques/T1574/001) | Win | 32 | 67 | 5 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Dylib Hijacking](https://attack.mitre.org/techniques/T1574/004) | Mac | 0 | 1 | 1 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.005 Executable Installer File Permissions Weakness](https://attack.mitre.org/techniques/T1574/005) | Win | 1 | 0 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.006 Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006) | Lnx Mac | 3 | 6 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.007 Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007) | Win Mac Lnx | 0 | 3 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.008 Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008) | Win | 0 | 2 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.009 Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009) | Win | 0 | 2 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.010 Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010) | Win | 0 | 1 | 3 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.011 Services Registry Permissions Weakness](https://attack.mitre.org/techniques/T1574/011) | Win | 0 | 0 | 1 | 2 | ✓ |
| &nbsp;&nbsp;↳ [.012 COR_PROFILER](https://attack.mitre.org/techniques/T1574/012) | Win | 1 | 1 | 3 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.013 KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013) | Win | 1 | 1 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014) | Win | 0 | 1 | 1 | 10 | ✓ |
| [T1578 Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578) | IaaS | 0 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.001 Create Snapshot](https://attack.mitre.org/techniques/T1578/001) | IaaS | 0 | 1 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.002 Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002) | IaaS | 2 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.003 Delete Cloud Instance](https://attack.mitre.org/techniques/T1578/003) | IaaS | 2 | 0 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.004 Revert Cloud Instance](https://attack.mitre.org/techniques/T1578/004) | IaaS | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.005 Modify Cloud Compute Configurations](https://attack.mitre.org/techniques/T1578/005) | IaaS | 0 | 0 | 2 | 5 | ✓ |
| [T1599 Network Boundary Bridging](https://attack.mitre.org/techniques/T1599) | NetDev | 1 | 0 | 5 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.001 Network Address Translation Traversal](https://attack.mitre.org/techniques/T1599/001) | NetDev | 0 | 0 | 5 | 18 | ✓ |
| [T1600 Weaken Encryption](https://attack.mitre.org/techniques/T1600) | NetDev | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Reduce Key Space](https://attack.mitre.org/techniques/T1600/001) | NetDev | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Disable Crypto Hardware](https://attack.mitre.org/techniques/T1600/002) | NetDev | 0 | 0 | 0 | 0 | ✓ |
| [T1601 Modify System Image](https://attack.mitre.org/techniques/T1601) | NetDev | 0 | 0 | 6 | 24 | ✓ |
| &nbsp;&nbsp;↳ [.001 Patch System Image](https://attack.mitre.org/techniques/T1601/001) | NetDev | 0 | 1 | 6 | 24 | ✓ |
| &nbsp;&nbsp;↳ [.002 Downgrade System Image](https://attack.mitre.org/techniques/T1601/002) | NetDev | 0 | 0 | 6 | 24 | ✓ |
| [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610) | Cnt | 1 | 3 | 4 | 9 | ✓ |
| [T1612 Build Image on Host](https://attack.mitre.org/techniques/T1612) | Cnt | 0 | 0 | 4 | 11 | ✓ |
| [T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620) | Lnx Mac Win | 4 | 22 | 0 | 0 | ✓ |
| [T1622 Debugger Evasion](https://attack.mitre.org/techniques/T1622) | Lnx Mac Win | 1 | 21 | 0 | 15 | ✓ |
| [T1647 Plist File Modification](https://attack.mitre.org/techniques/T1647) | Mac | 0 | 2 | 1 | 15 | ✓ |
| [T1656 Impersonation](https://attack.mitre.org/techniques/T1656) | Lnx Mac Office SaaS Win | 8 | 1 | 2 | 0 | ✓ |
| [T1666 Modify Cloud Resource Hierarchy](https://attack.mitre.org/techniques/T1666) | IaaS | 0 | 0 | 3 | 1 | ✓ |
| [T1672 Email Spoofing](https://attack.mitre.org/techniques/T1672) | Office Win Mac Lnx | 0 | 0 | 1 | 0 | ✓ |
| [T1678 Delay Execution](https://attack.mitre.org/techniques/T1678) | Lnx Mac Win | 1 | 2 | 0 | 0 | ✓ |
| [T1679 Selective Exclusion](https://attack.mitre.org/techniques/T1679) | Win | 0 | 3 | 0 | 0 | ✓ |

## Credential Access
<a id="credential-access"></a>

[`TA0006`](https://attack.mitre.org/tactics/TA0006/) · 67 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003) | Lnx Mac Win | 13 | 7 | 9 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001) | Win | 42 | 26 | 7 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.002 Security Account Manager](https://attack.mitre.org/techniques/T1003/002) | Win | 13 | 15 | 4 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.003 NTDS](https://attack.mitre.org/techniques/T1003/003) | Win | 17 | 4 | 4 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.004 LSA Secrets](https://attack.mitre.org/techniques/T1003/004) | Win | 10 | 9 | 3 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.005 Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005) | Win Lnx | 4 | 4 | 5 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.006 DCSync](https://attack.mitre.org/techniques/T1003/006) | Win | 4 | 1 | 3 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.007 Proc Filesystem](https://attack.mitre.org/techniques/T1003/007) | Lnx | 0 | 3 | 2 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.008 /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008) | Lnx | 0 | 1 | 2 | 14 | ✓ |
| [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040) | Lnx Mac Win NetDev IaaS | 8 | 16 | 4 | 12 | ✓ |
| [T1056 Input Capture](https://attack.mitre.org/techniques/T1056) | Lnx Mac NetDev Win | 3 | 7 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Keylogging](https://attack.mitre.org/techniques/T1056/001) | Lnx Mac NetDev Win | 26 | 123 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 GUI Input Capture](https://attack.mitre.org/techniques/T1056/002) | Mac Win Lnx | 2 | 11 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.003 Web Portal Capture](https://attack.mitre.org/techniques/T1056/003) | Lnx Mac Win | 1 | 2 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.004 Credential API Hooking](https://attack.mitre.org/techniques/T1056/004) | Win Lnx Mac | 1 | 11 | 0 | 0 | ✓ |
| [T1110 Brute Force](https://attack.mitre.org/techniques/T1110) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 14 | 7 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 2 | 9 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 Password Cracking](https://attack.mitre.org/techniques/T1110/002) | Lnx Mac Win NetDev Office IdP | 4 | 1 | 2 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003) | Cnt ESXi IaaS IdP Lnx NetDev Office SaaS Win Mac | 11 | 4 | 3 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.004 Credential Stuffing](https://attack.mitre.org/techniques/T1110/004) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 1 | 1 | 4 | 14 | ✓ |
| [T1111 Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111) | Lnx Win Mac | 4 | 2 | 1 | 9 | ✓ |
| [T1187 Forced Authentication](https://attack.mitre.org/techniques/T1187) | Win | 2 | 1 | 2 | 10 | ✓ |
| [T1212 Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212) | Lnx Win Mac IdP | 1 | 0 | 5 | 24 | ✓ |
| [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528) | SaaS Cnt IaaS Office IdP | 2 | 2 | 4 | 19 | ✓ |
| [T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539) | Lnx Office SaaS Win Mac | 8 | 16 | 6 | 10 | ✓ |
| [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP | 1 | 4 | 11 | 32 | ✓ |
| &nbsp;&nbsp;↳ [.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001) | Cnt IaaS Lnx Mac Win | 14 | 18 | 4 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.002 Credentials in Registry](https://attack.mitre.org/techniques/T1552/002) | Win | 2 | 7 | 3 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.003 Shell History](https://attack.mitre.org/techniques/T1552/003) | Lnx Mac Win | 0 | 1 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.004 Private Keys](https://attack.mitre.org/techniques/T1552/004) | Lnx Mac NetDev Win | 5 | 11 | 4 | 21 | ✓ |
| &nbsp;&nbsp;↳ [.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005) | IaaS | 1 | 2 | 3 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.006 Group Policy Preferences](https://attack.mitre.org/techniques/T1552/006) | Win | 2 | 2 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.007 Container API](https://attack.mitre.org/techniques/T1552/007) | Cnt | 0 | 1 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.008 Chat Messages](https://attack.mitre.org/techniques/T1552/008) | SaaS Office | 1 | 0 | 2 | 2 | ✓ |
| [T1555 Credentials from Password Stores](https://attack.mitre.org/techniques/T1555) | IaaS Lnx Mac Win | 12 | 24 | 3 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.001 Keychain](https://attack.mitre.org/techniques/T1555/001) | Mac | 1 | 10 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.002 Securityd Memory](https://attack.mitre.org/techniques/T1555/002) | Lnx Mac | 0 | 1 | 0 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.003 Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003) | Lnx Mac Win | 23 | 62 | 5 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004) | Win | 4 | 9 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.005 Password Managers](https://attack.mitre.org/techniques/T1555/005) | Lnx Mac Win | 7 | 4 | 5 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.006 Cloud Secrets Management Stores](https://attack.mitre.org/techniques/T1555/006) | IaaS | 2 | 1 | 1 | 4 | ✓ |
| [T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556) | Win Lnx Mac NetDev IaaS SaaS Office IdP | 1 | 3 | 9 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.001 Domain Controller Authentication](https://attack.mitre.org/techniques/T1556/001) | Win | 1 | 1 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.002 Password Filter DLL](https://attack.mitre.org/techniques/T1556/002) | Win | 2 | 1 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.003 Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003) | Lnx Mac | 0 | 2 | 2 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.004 Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) | NetDev | 0 | 2 | 2 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.005 Reversible Encryption](https://attack.mitre.org/techniques/T1556/005) | Win | 0 | 0 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.006 Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006) | Win SaaS IaaS Lnx Mac Office IdP | 1 | 2 | 3 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.007 Hybrid Identity](https://attack.mitre.org/techniques/T1556/007) | Win SaaS IaaS Office IdP | 1 | 1 | 3 | 6 | ✓ |
| &nbsp;&nbsp;↳ [.008 Network Provider DLL](https://attack.mitre.org/techniques/T1556/008) | Win | 0 | 0 | 3 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.009 Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009) | IaaS IdP | 2 | 0 | 1 | 14 | ✓ |
| [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) | Lnx Mac NetDev Win | 3 | 3 | 7 | 24 | ✓ |
| &nbsp;&nbsp;↳ [.001 LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001) | Win | 2 | 5 | 4 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.002 ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002) | Lnx Win Mac | 2 | 0 | 6 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.003 DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003) | Lnx Win Mac | 0 | 0 | 2 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.004 Evil Twin](https://attack.mitre.org/techniques/T1557/004) | NetDev | 1 | 0 | 2 | 16 | ✓ |
| [T1558 Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558) | Win Lnx Mac | 1 | 0 | 6 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.001 Golden Ticket](https://attack.mitre.org/techniques/T1558/001) | Win | 1 | 4 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.002 Silver Ticket](https://attack.mitre.org/techniques/T1558/002) | Win | 0 | 4 | 3 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003) | Win | 3 | 6 | 3 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.004 AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004) | Win | 0 | 1 | 3 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.005 Ccache Files](https://attack.mitre.org/techniques/T1558/005) | Lnx Mac | 0 | 1 | 2 | 10 | ✓ |
| [T1606 Forge Web Credentials](https://attack.mitre.org/techniques/T1606) | SaaS Win Mac Lnx IaaS Office IdP | 0 | 0 | 4 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.001 Web Cookies](https://attack.mitre.org/techniques/T1606/001) | Lnx Mac Win SaaS IaaS | 0 | 0 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.002 SAML Tokens](https://attack.mitre.org/techniques/T1606/002) | SaaS Win IaaS Office IdP | 0 | 1 | 4 | 4 | ✓ |
| [T1621 Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621) | Win Lnx Mac IaaS SaaS Office IdP | 3 | 0 | 3 | 7 | ✓ |
| [T1649 Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649) | Win Lnx Mac IdP | 1 | 2 | 4 | 3 | ✓ |

## Discovery
<a id="discovery"></a>

[`TA0007`](https://attack.mitre.org/tactics/TA0007/) · 49 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1007 System Service Discovery](https://attack.mitre.org/techniques/T1007) | Lnx Mac Win | 14 | 51 | 0 | 0 | ✓ |
| [T1010 Application Window Discovery](https://attack.mitre.org/techniques/T1010) | Lnx Win Mac | 3 | 32 | 0 | 0 | ✓ |
| [T1012 Query Registry](https://attack.mitre.org/techniques/T1012) | Win | 19 | 98 | 0 | 0 | ✓ |
| [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) | ESXi Lnx Mac NetDev Win | 42 | 225 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Internet Connection Discovery](https://attack.mitre.org/techniques/T1016/001) | Win Lnx Mac ESXi | 11 | 13 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Wi-Fi Discovery](https://attack.mitre.org/techniques/T1016/002) | Lnx Win Mac | 1 | 5 | 0 | 0 | ✓ |
| [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018) | ESXi Lnx Mac NetDev Win | 39 | 52 | 0 | 0 | ✓ |
| [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) | Lnx Mac NetDev Win | 38 | 186 | 0 | 0 | ✓ |
| [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040) | Lnx Mac Win NetDev IaaS | 8 | 16 | 4 | 12 | ✓ |
| [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046) | Cnt IaaS Lnx Mac NetDev Win | 31 | 35 | 3 | 11 | ✓ |
| [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049) | Win IaaS Lnx Mac NetDev ESXi | 32 | 60 | 0 | 0 | ✓ |
| [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057) | ESXi Lnx Mac NetDev Win | 40 | 255 | 0 | 0 | ✓ |
| [T1069 Permission Groups Discovery](https://attack.mitre.org/techniques/T1069) | Cnt IaaS IdP Lnx Mac Office SaaS Win | 6 | 6 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Local Groups](https://attack.mitre.org/techniques/T1069/001) | Lnx Mac Win | 7 | 21 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Domain Groups](https://attack.mitre.org/techniques/T1069/002) | Lnx Mac Win | 13 | 21 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Cloud Groups](https://attack.mitre.org/techniques/T1069/003) | SaaS IaaS Office IdP | 0 | 3 | 0 | 0 | ✓ |
| [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082) | ESXi IaaS Lnx Mac NetDev Win | 55 | 336 | 0 | 0 | ✓ |
| [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083) | ESXi Lnx Mac NetDev Win | 50 | 295 | 0 | 0 | ✓ |
| [T1087 Account Discovery](https://attack.mitre.org/techniques/T1087) | ESXi IaaS IdP Lnx Mac Office SaaS Win | 3 | 5 | 2 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.001 Local Account](https://attack.mitre.org/techniques/T1087/001) | ESXi Lnx Mac Win | 18 | 44 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.002 Domain Account](https://attack.mitre.org/techniques/T1087/002) | Lnx Mac Win | 27 | 25 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.003 Email Account](https://attack.mitre.org/techniques/T1087/003) | Win Office | 4 | 8 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.004 Cloud Account](https://attack.mitre.org/techniques/T1087/004) | IaaS IdP Office SaaS | 2 | 3 | 2 | 6 | ✓ |
| [T1120 Peripheral Device Discovery](https://attack.mitre.org/techniques/T1120) | Lnx Win Mac | 9 | 46 | 0 | 0 | ✓ |
| [T1124 System Time Discovery](https://attack.mitre.org/techniques/T1124) | ESXi Lnx Mac NetDev Win | 13 | 77 | 0 | 0 | ✓ |
| [T1135 Network Share Discovery](https://attack.mitre.org/techniques/T1135) | Lnx Mac Win | 16 | 57 | 1 | 3 | ✓ |
| [T1201 Password Policy Discovery](https://attack.mitre.org/techniques/T1201) | Win Lnx Mac IaaS NetDev IdP SaaS Office | 3 | 4 | 1 | 5 | ✓ |
| [T1217 Browser Information Discovery](https://attack.mitre.org/techniques/T1217) | Lnx Mac Win | 6 | 17 | 0 | 0 | ✓ |
| [T1482 Domain Trust Discovery](https://attack.mitre.org/techniques/T1482) | Win | 9 | 19 | 2 | 9 | ✓ |
| [T1497 Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) | Lnx Mac Win | 3 | 22 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 System Checks](https://attack.mitre.org/techniques/T1497/001) | Lnx Mac Win | 5 | 59 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 User Activity Based Checks](https://attack.mitre.org/techniques/T1497/002) | Lnx Win Mac | 2 | 3 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Time Based Checks](https://attack.mitre.org/techniques/T1497/003) | Lnx Mac Win | 0 | 45 | 0 | 0 | ✓ |
| [T1518 Software Discovery](https://attack.mitre.org/techniques/T1518) | ESXi IaaS Lnx Mac Win | 11 | 36 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Security Software Discovery](https://attack.mitre.org/techniques/T1518/001) | IaaS Lnx Mac Win | 27 | 105 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Backup Software Discovery](https://attack.mitre.org/techniques/T1518/002) | Win Mac Lnx | 1 | 0 | 0 | 0 | ✓ |
| [T1526 Cloud Service Discovery](https://attack.mitre.org/techniques/T1526) | IaaS IdP Office SaaS | 1 | 3 | 0 | 0 | ✓ |
| [T1538 Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538) | IaaS SaaS Office IdP | 1 | 0 | 1 | 6 | ✓ |
| [T1580 Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580) | IaaS | 2 | 1 | 1 | 5 | ✓ |
| [T1613 Container and Resource Discovery](https://attack.mitre.org/techniques/T1613) | Cnt | 1 | 2 | 3 | 10 | ✓ |
| [T1614 System Location Discovery](https://attack.mitre.org/techniques/T1614) | IaaS Lnx Mac Win | 2 | 18 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 System Language Discovery](https://attack.mitre.org/techniques/T1614/001) | Lnx Mac Win | 4 | 31 | 0 | 0 | ✓ |
| [T1615 Group Policy Discovery](https://attack.mitre.org/techniques/T1615) | Win | 1 | 5 | 0 | 0 | ✓ |
| [T1619 Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619) | IaaS | 0 | 2 | 1 | 7 | ✓ |
| [T1622 Debugger Evasion](https://attack.mitre.org/techniques/T1622) | Lnx Mac Win | 1 | 21 | 0 | 15 | ✓ |
| [T1652 Device Driver Discovery](https://attack.mitre.org/techniques/T1652) | Lnx Mac Win | 1 | 3 | 0 | 0 | ✓ |
| [T1654 Log Enumeration](https://attack.mitre.org/techniques/T1654) | ESXi IaaS Lnx Mac Win | 5 | 5 | 1 | 4 | ✓ |
| [T1673 Virtual Machine Discovery](https://attack.mitre.org/techniques/T1673) | ESXi Lnx Mac Win | 1 | 3 | 0 | 0 | ✓ |
| [T1680 Local Storage Discovery](https://attack.mitre.org/techniques/T1680) | ESXi IaaS Lnx Mac Win | 10 | 86 | 0 | 0 | ✓ |

## Lateral Movement
<a id="lateral-movement"></a>

[`TA0008`](https://attack.mitre.org/tactics/TA0008/) · 23 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1021 Remote Services](https://attack.mitre.org/techniques/T1021) | Lnx Mac Win IaaS ESXi | 3 | 4 | 6 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) | Win | 35 | 17 | 8 | 23 | ✓ |
| &nbsp;&nbsp;↳ [.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) | Win | 26 | 30 | 4 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.003 Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003) | Win | 0 | 3 | 4 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.004 SSH](https://attack.mitre.org/techniques/T1021/004) | ESXi Lnx Mac | 19 | 4 | 3 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.005 VNC](https://attack.mitre.org/techniques/T1021/005) | Lnx Win Mac | 4 | 7 | 4 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.006 Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) | Win | 5 | 3 | 3 | 16 | ✓ |
| &nbsp;&nbsp;↳ [.007 Cloud Services](https://attack.mitre.org/techniques/T1021/007) | IaaS IdP Office SaaS | 3 | 0 | 2 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.008 Direct Cloud VM Connections](https://attack.mitre.org/techniques/T1021/008) | IaaS | 0 | 0 | 2 | 11 | ✓ |
| [T1072 Software Deployment Tools](https://attack.mitre.org/techniques/T1072) | Lnx Mac NetDev SaaS Win | 6 | 1 | 10 | 27 | ✓ |
| [T1080 Taint Shared Content](https://attack.mitre.org/techniques/T1080) | Win SaaS Lnx Mac Office | 5 | 7 | 4 | 10 | ✓ |
| [T1091 Replication Through Removable Media](https://attack.mitre.org/techniques/T1091) | Win | 8 | 20 | 3 | 10 | ✓ |
| [T1210 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210) | Lnx Win Mac ESXi | 11 | 13 | 8 | 31 | ✓ |
| [T1534 Internal Spearphishing](https://attack.mitre.org/techniques/T1534) | Win Mac Lnx SaaS Office | 4 | 0 | 0 | 0 | ✓ |
| [T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550) | Win SaaS IaaS Cnt IdP Office Lnx | 0 | 1 | 7 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001) | SaaS Cnt IaaS Office IdP | 2 | 2 | 5 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002) | Win | 11 | 8 | 4 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.003 Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) | Win | 3 | 3 | 4 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.004 Web Session Cookie](https://attack.mitre.org/techniques/T1550/004) | SaaS IaaS Office | 1 | 0 | 1 | 3 | ✓ |
| [T1563 Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563) | Lnx Mac Win | 0 | 0 | 5 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.001 SSH Hijacking](https://attack.mitre.org/techniques/T1563/001) | Lnx Mac | 0 | 1 | 4 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.002 RDP Hijacking](https://attack.mitre.org/techniques/T1563/002) | Win | 1 | 1 | 7 | 18 | ✓ |
| [T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570) | ESXi Lnx Mac Win | 19 | 25 | 2 | 11 | ✓ |

## Collection
<a id="collection"></a>

[`TA0009`](https://attack.mitre.org/tactics/TA0009/) · 41 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005) | ESXi Lnx Mac NetDev Win | 43 | 161 | 1 | 13 | ✓ |
| [T1025 Data from Removable Media](https://attack.mitre.org/techniques/T1025) | Lnx Mac Win | 4 | 20 | 1 | 15 | ✓ |
| [T1039 Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039) | Lnx Mac Win | 8 | 4 | 0 | 0 | ✓ |
| [T1056 Input Capture](https://attack.mitre.org/techniques/T1056) | Lnx Mac NetDev Win | 3 | 7 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Keylogging](https://attack.mitre.org/techniques/T1056/001) | Lnx Mac NetDev Win | 26 | 123 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 GUI Input Capture](https://attack.mitre.org/techniques/T1056/002) | Mac Win Lnx | 2 | 11 | 1 | 4 | ✓ |
| &nbsp;&nbsp;↳ [.003 Web Portal Capture](https://attack.mitre.org/techniques/T1056/003) | Lnx Mac Win | 1 | 2 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.004 Credential API Hooking](https://attack.mitre.org/techniques/T1056/004) | Win Lnx Mac | 1 | 11 | 0 | 0 | ✓ |
| [T1074 Data Staged](https://attack.mitre.org/techniques/T1074) | Win IaaS Lnx Mac ESXi | 4 | 4 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Local Data Staging](https://attack.mitre.org/techniques/T1074/001) | ESXi Lnx Mac Win | 27 | 88 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Remote Data Staging](https://attack.mitre.org/techniques/T1074/002) | Win IaaS Lnx Mac ESXi | 10 | 1 | 0 | 0 | ✓ |
| [T1113 Screen Capture](https://attack.mitre.org/techniques/T1113) | Lnx Win Mac | 18 | 148 | 0 | 0 | ✓ |
| [T1114 Email Collection](https://attack.mitre.org/techniques/T1114) | Win Mac Lnx Office | 4 | 2 | 4 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.001 Local Email Collection](https://attack.mitre.org/techniques/T1114/001) | Win | 6 | 11 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.002 Remote Email Collection](https://attack.mitre.org/techniques/T1114/002) | Win Office | 12 | 4 | 3 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.003 Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003) | Lnx Mac Office Win | 5 | 0 | 4 | 12 | ✓ |
| [T1115 Clipboard Data](https://attack.mitre.org/techniques/T1115) | Lnx Mac Win | 3 | 41 | 0 | 0 | ✓ |
| [T1119 Automated Collection](https://attack.mitre.org/techniques/T1119) | IaaS Lnx Mac Office SaaS Win | 20 | 44 | 2 | 17 | ✓ |
| [T1123 Audio Capture](https://attack.mitre.org/techniques/T1123) | Lnx Mac Win | 1 | 30 | 0 | 0 | ✓ |
| [T1125 Video Capture](https://attack.mitre.org/techniques/T1125) | Win Mac Lnx | 3 | 31 | 0 | 0 | ✓ |
| [T1185 Browser Session Hijacking](https://attack.mitre.org/techniques/T1185) | Win | 1 | 13 | 2 | 14 | ✓ |
| [T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213) | Lnx Win Mac SaaS IaaS Office | 1 | 2 | 7 | 24 | ✓ |
| &nbsp;&nbsp;↳ [.001 Confluence](https://attack.mitre.org/techniques/T1213/001) | SaaS | 1 | 0 | 3 | 23 | ✓ |
| &nbsp;&nbsp;↳ [.002 Sharepoint](https://attack.mitre.org/techniques/T1213/002) | Win Office | 6 | 1 | 3 | 23 | ✓ |
| &nbsp;&nbsp;↳ [.003 Code Repositories](https://attack.mitre.org/techniques/T1213/003) | SaaS | 3 | 0 | 4 | 14 | ✓ |
| &nbsp;&nbsp;↳ [.004 Customer Relationship Management Software](https://attack.mitre.org/techniques/T1213/004) | SaaS | 0 | 0 | 4 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.005 Messaging Applications](https://attack.mitre.org/techniques/T1213/005) | SaaS Office | 3 | 0 | 3 | 24 | ✓ |
| &nbsp;&nbsp;↳ [.006 Databases](https://attack.mitre.org/techniques/T1213/006) | Lnx Win Mac IaaS SaaS | 4 | 2 | 5 | 0 | ✓ |
| [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530) | IaaS Office SaaS | 5 | 3 | 6 | 32 | ✓ |
| [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) | Lnx Mac NetDev Win | 3 | 3 | 7 | 24 | ✓ |
| &nbsp;&nbsp;↳ [.001 LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001) | Win | 2 | 5 | 4 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.002 ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002) | Lnx Win Mac | 2 | 0 | 6 | 22 | ✓ |
| &nbsp;&nbsp;↳ [.003 DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003) | Lnx Win Mac | 0 | 0 | 2 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.004 Evil Twin](https://attack.mitre.org/techniques/T1557/004) | NetDev | 1 | 0 | 2 | 16 | ✓ |
| [T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560) | Lnx Mac Win | 13 | 41 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001) | Lnx Mac Win | 37 | 31 | 1 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.002 Archive via Library](https://attack.mitre.org/techniques/T1560/002) | Lnx Mac Win | 2 | 13 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Archive via Custom Method](https://attack.mitre.org/techniques/T1560/003) | Lnx Mac Win | 7 | 31 | 0 | 0 | ✓ |
| [T1602 Data from Configuration Repository](https://attack.mitre.org/techniques/T1602) | NetDev | 0 | 0 | 6 | 25 | ✓ |
| &nbsp;&nbsp;↳ [.001 SNMP (MIB Dump)](https://attack.mitre.org/techniques/T1602/001) | NetDev | 0 | 0 | 6 | 25 | ✓ |
| &nbsp;&nbsp;↳ [.002 Network Device Configuration Dump](https://attack.mitre.org/techniques/T1602/002) | NetDev | 1 | 0 | 6 | 25 | ✓ |

## Command and Control
<a id="command-and-control"></a>

[`TA0011`](https://attack.mitre.org/tactics/TA0011/) · 45 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1001 Data Obfuscation](https://attack.mitre.org/techniques/T1001) | ESXi Lnx Mac Win | 1 | 11 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.001 Junk Data](https://attack.mitre.org/techniques/T1001/001) | ESXi Lnx Mac Win | 1 | 16 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.002 Steganography](https://attack.mitre.org/techniques/T1001/002) | Lnx Mac Win ESXi | 1 | 11 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.003 Protocol or Service Impersonation](https://attack.mitre.org/techniques/T1001/003) | ESXi Lnx Mac Win | 3 | 18 | 1 | 7 | ✓ |
| [T1008 Fallback Channels](https://attack.mitre.org/techniques/T1008) | Lnx Win Mac ESXi | 5 | 47 | 1 | 8 | ✓ |
| [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071) | Lnx Mac Win NetDev ESXi | 5 | 10 | 2 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001) | ESXi Lnx Mac NetDev Win | 56 | 329 | 2 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.002 File Transfer Protocols](https://attack.mitre.org/techniques/T1071/002) | ESXi Lnx Mac NetDev Win | 4 | 19 | 2 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.003 Mail Protocols](https://attack.mitre.org/techniques/T1071/003) | Lnx Mac NetDev Win | 6 | 20 | 2 | 15 | ✓ |
| &nbsp;&nbsp;↳ [.004 DNS](https://attack.mitre.org/techniques/T1071/004) | Lnx Mac Win NetDev ESXi | 11 | 41 | 2 | 18 | ✓ |
| &nbsp;&nbsp;↳ [.005 Publish/Subscribe Protocols](https://attack.mitre.org/techniques/T1071/005) | Mac Lnx Win NetDev | 0 | 1 | 2 | 4 | ✓ |
| [T1090 Proxy](https://attack.mitre.org/techniques/T1090) | ESXi Lnx Mac NetDev Win | 17 | 46 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.001 Internal Proxy](https://attack.mitre.org/techniques/T1090/001) | Lnx NetDev Win Mac ESXi | 9 | 20 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 External Proxy](https://attack.mitre.org/techniques/T1090/002) | ESXi Lnx NetDev Win Mac | 11 | 10 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.003 Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003) | ESXi Lnx Mac NetDev Win | 11 | 20 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.004 Domain Fronting](https://attack.mitre.org/techniques/T1090/004) | Lnx Mac Win ESXi | 1 | 4 | 1 | 1 | ✓ |
| [T1092 Communication Through Removable Media](https://attack.mitre.org/techniques/T1092) | Lnx Mac Win | 1 | 2 | 2 | 8 | ✓ |
| [T1095 Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095) | ESXi Lnx Mac NetDev Win | 12 | 86 | 4 | 11 | ✓ |
| [T1102 Web Service](https://attack.mitre.org/techniques/T1102) | ESXi Lnx Win Mac | 14 | 27 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.001 Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001) | ESXi Lnx Mac Win | 6 | 15 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002) | Lnx Mac Win ESXi | 16 | 37 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.003 One-Way Communication](https://attack.mitre.org/techniques/T1102/003) | Lnx Mac Win ESXi | 2 | 6 | 2 | 8 | ✓ |
| [T1104 Multi-Stage Channels](https://attack.mitre.org/techniques/T1104) | Lnx Mac Win ESXi | 4 | 10 | 1 | 8 | ✓ |
| [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) | ESXi Lnx Mac NetDev Win | 85 | 385 | 2 | 8 | ✓ |
| [T1132 Data Encoding](https://attack.mitre.org/techniques/T1132) | Lnx Mac Win ESXi | 1 | 5 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.001 Standard Encoding](https://attack.mitre.org/techniques/T1132/001) | ESXi Lnx Win Mac | 11 | 108 | 1 | 7 | ✓ |
| &nbsp;&nbsp;↳ [.002 Non-Standard Encoding](https://attack.mitre.org/techniques/T1132/002) | ESXi Lnx Mac Win | 0 | 16 | 1 | 7 | ✓ |
| [T1205 Traffic Signaling](https://attack.mitre.org/techniques/T1205) | Lnx Mac NetDev Win | 3 | 16 | 2 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.001 Port Knocking](https://attack.mitre.org/techniques/T1205/001) | Lnx Mac Win NetDev | 2 | 4 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Socket Filters](https://attack.mitre.org/techniques/T1205/002) | Lnx Mac Win | 0 | 4 | 1 | 2 | ✓ |
| [T1219 Remote Access Tools](https://attack.mitre.org/techniques/T1219) | Lnx Mac Win | 13 | 7 | 5 | 13 | ✓ |
| &nbsp;&nbsp;↳ [.001 IDE Tunneling](https://attack.mitre.org/techniques/T1219/001) | Lnx Mac Win | 1 | 0 | 1 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Remote Desktop Software](https://attack.mitre.org/techniques/T1219/002) | Lnx Mac Win | 9 | 0 | 3 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 Remote Access Hardware](https://attack.mitre.org/techniques/T1219/003) | Lnx Mac Win | 0 | 0 | 1 | 0 | ✓ |
| [T1568 Dynamic Resolution](https://attack.mitre.org/techniques/T1568) | Lnx Mac Win ESXi | 6 | 8 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.001 Fast Flux DNS](https://attack.mitre.org/techniques/T1568/001) | Lnx Mac Win ESXi | 3 | 3 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002) | Lnx Mac Win ESXi | 2 | 20 | 2 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.003 DNS Calculation](https://attack.mitre.org/techniques/T1568/003) | Lnx Mac Win ESXi | 1 | 0 | 0 | 0 | ✓ |
| [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571) | ESXi Lnx Mac Win | 16 | 37 | 2 | 8 | ✓ |
| [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572) | ESXi Lnx Mac Win | 14 | 18 | 2 | 11 | ✓ |
| [T1573 Encrypted Channel](https://attack.mitre.org/techniques/T1573) | ESXi Lnx Mac NetDev Win | 4 | 11 | 2 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.001 Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001) | ESXi Lnx Mac NetDev Win | 14 | 159 | 1 | 11 | ✓ |
| &nbsp;&nbsp;↳ [.002 Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) | ESXi Lnx Mac NetDev Win | 11 | 73 | 2 | 11 | ✓ |
| [T1659 Content Injection](https://attack.mitre.org/techniques/T1659) | Lnx Mac Win | 1 | 1 | 2 | 3 | ✓ |
| [T1665 Hide Infrastructure](https://attack.mitre.org/techniques/T1665) | ESXi Lnx NetDev Win Mac | 2 | 3 | 0 | 0 | ✓ |

## Exfiltration
<a id="exfiltration"></a>

[`TA0010`](https://attack.mitre.org/tactics/TA0010/) · 19 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1011 Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011) | Lnx Mac Win | 0 | 0 | 2 | 5 | ✓ |
| &nbsp;&nbsp;↳ [.001 Exfiltration Over Bluetooth](https://attack.mitre.org/techniques/T1011/001) | Lnx Mac Win | 0 | 1 | 2 | 8 | ✓ |
| [T1020 Automated Exfiltration](https://attack.mitre.org/techniques/T1020) | Lnx Mac NetDev Win | 6 | 20 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Traffic Duplication](https://attack.mitre.org/techniques/T1020/001) | NetDev IaaS | 0 | 0 | 3 | 21 | ✓ |
| [T1029 Scheduled Transfer](https://attack.mitre.org/techniques/T1029) | Lnx Mac Win | 1 | 17 | 1 | 7 | ✓ |
| [T1030 Data Transfer Size Limits](https://attack.mitre.org/techniques/T1030) | Lnx Mac Win ESXi | 5 | 14 | 1 | 7 | ✓ |
| [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) | ESXi Lnx Mac Win | 25 | 156 | 2 | 18 | ✓ |
| [T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) | ESXi IaaS Lnx Mac NetDev Office SaaS Win | 2 | 7 | 6 | 23 | ✓ |
| &nbsp;&nbsp;↳ [.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001) | Lnx Mac Win ESXi | 0 | 0 | 3 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002) | Lnx Mac Win ESXi | 3 | 2 | 4 | 23 | ✓ |
| &nbsp;&nbsp;↳ [.003 Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003) | ESXi Lnx Mac NetDev Win | 11 | 22 | 4 | 23 | ✓ |
| [T1052 Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052) | Lnx Mac Win | 0 | 0 | 3 | 19 | ✓ |
| &nbsp;&nbsp;↳ [.001 Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001) | Lnx Win Mac | 2 | 5 | 3 | 19 | ✓ |
| [T1537 Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537) | IaaS Office SaaS | 3 | 0 | 4 | 20 | ✓ |
| [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567) | ESXi Lnx Mac Office SaaS Win | 4 | 7 | 2 | 17 | ✓ |
| &nbsp;&nbsp;↳ [.001 Exfiltration to Code Repository](https://attack.mitre.org/techniques/T1567/001) | Lnx Mac Win ESXi | 0 | 1 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) | ESXi Lnx Mac Win | 24 | 15 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.003 Exfiltration to Text Storage Sites](https://attack.mitre.org/techniques/T1567/003) | Lnx Mac Win ESXi | 0 | 0 | 1 | 3 | ✓ |
| &nbsp;&nbsp;↳ [.004 Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004) | Win Mac Lnx SaaS Office ESXi | 0 | 0 | 1 | 3 | ✓ |

## Impact
<a id="impact"></a>

[`TA0040`](https://attack.mitre.org/tactics/TA0040/) · 33 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485) | Cnt ESXi IaaS Lnx Mac Win | 5 | 24 | 3 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.001 Lifecycle-Triggered Deletion](https://attack.mitre.org/techniques/T1485/001) | IaaS | 0 | 0 | 2 | 6 | ✓ |
| [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) | ESXi IaaS Lnx Mac Win | 17 | 61 | 2 | 11 | ✓ |
| [T1489 Service Stop](https://attack.mitre.org/techniques/T1489) | ESXi IaaS Lnx Mac Win | 6 | 44 | 5 | 14 | ✓ |
| [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490) | Cnt ESXi IaaS Lnx Mac NetDev Win | 6 | 48 | 4 | 13 | ✓ |
| [T1491 Defacement](https://attack.mitre.org/techniques/T1491) | Win IaaS Lnx Mac ESXi | 0 | 0 | 1 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.001 Internal Defacement](https://attack.mitre.org/techniques/T1491/001) | ESXi Lnx Mac Win | 3 | 9 | 1 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.002 External Defacement](https://attack.mitre.org/techniques/T1491/002) | Win IaaS Lnx Mac | 2 | 0 | 1 | 10 | ✓ |
| [T1495 Firmware Corruption](https://attack.mitre.org/techniques/T1495) | Lnx Mac NetDev Win | 0 | 2 | 3 | 16 | ✓ |
| [T1496 Resource Hijacking](https://attack.mitre.org/techniques/T1496) | Win IaaS Lnx Mac Cnt SaaS | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.001 Compute Hijacking](https://attack.mitre.org/techniques/T1496/001) | Win IaaS Lnx Mac Cnt | 4 | 9 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.002 Bandwidth Hijacking](https://attack.mitre.org/techniques/T1496/002) | Lnx Win Mac IaaS Cnt | 0 | 0 | 0 | 0 | ✓ |
| &nbsp;&nbsp;↳ [.003 SMS Pumping](https://attack.mitre.org/techniques/T1496/003) | SaaS | 0 | 0 | 1 | 1 | ✓ |
| &nbsp;&nbsp;↳ [.004 Cloud Service Hijacking](https://attack.mitre.org/techniques/T1496/004) | SaaS | 0 | 0 | 0 | 0 | ✓ |
| [T1498 Network Denial of Service](https://attack.mitre.org/techniques/T1498) | Win IaaS Lnx Mac Cnt | 1 | 2 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.001 Direct Network Flood](https://attack.mitre.org/techniques/T1498/001) | Win IaaS Lnx Mac | 0 | 0 | 1 | 8 | ✓ |
| &nbsp;&nbsp;↳ [.002 Reflection Amplification](https://attack.mitre.org/techniques/T1498/002) | Win IaaS Lnx Mac | 0 | 0 | 1 | 8 | ✓ |
| [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499) | Win Lnx Mac Cnt IaaS | 1 | 2 | 1 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.001 OS Exhaustion Flood](https://attack.mitre.org/techniques/T1499/001) | Lnx Mac Win | 0 | 0 | 1 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.002 Service Exhaustion Flood](https://attack.mitre.org/techniques/T1499/002) | Win IaaS Lnx Mac | 0 | 0 | 1 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.003 Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003) | Win IaaS Lnx Mac | 0 | 0 | 1 | 9 | ✓ |
| &nbsp;&nbsp;↳ [.004 Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004) | Win IaaS Lnx Mac | 0 | 1 | 1 | 9 | ✓ |
| [T1529 System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) | ESXi Lnx Mac NetDev Win | 4 | 23 | 0 | 0 | ✓ |
| [T1531 Account Access Removal](https://attack.mitre.org/techniques/T1531) | Lnx Mac Win SaaS IaaS Office ESXi | 2 | 4 | 0 | 0 | ✓ |
| [T1561 Disk Wipe](https://attack.mitre.org/techniques/T1561) | Lnx Mac Win NetDev | 0 | 0 | 1 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.001 Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) | Lnx NetDev Win Mac | 2 | 13 | 1 | 10 | ✓ |
| &nbsp;&nbsp;↳ [.002 Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) | Lnx Mac Win NetDev | 5 | 11 | 1 | 10 | ✓ |
| [T1565 Data Manipulation](https://attack.mitre.org/techniques/T1565) | Lnx Mac Win | 1 | 0 | 4 | 26 | ✓ |
| &nbsp;&nbsp;↳ [.001 Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001) | Lnx Mac Win | 1 | 2 | 3 | 23 | ✓ |
| &nbsp;&nbsp;↳ [.002 Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002) | Lnx Mac Win | 1 | 3 | 1 | 12 | ✓ |
| &nbsp;&nbsp;↳ [.003 Runtime Data Manipulation](https://attack.mitre.org/techniques/T1565/003) | Lnx Mac Win | 1 | 0 | 2 | 13 | ✓ |
| [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657) | Lnx Mac Office SaaS Win | 14 | 5 | 2 | 2 | ✓ |
| [T1667 Email Bombing](https://attack.mitre.org/techniques/T1667) | Lnx Office Win Mac | 1 | 0 | 2 | 0 | ✓ |

---

*Source: MITRE ATT&CK Enterprise v18.1 (STIX) + CTID NIST 800-53 R5 mappings. Counts reflect non-deprecated ATT&CK objects at time of generation.*
