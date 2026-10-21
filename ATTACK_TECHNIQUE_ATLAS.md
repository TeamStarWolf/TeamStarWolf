# ATT&CK Technique Atlas

<!-- local-id-links (written by scripts/build_crosslinks.py from docs/crosslinks.json): the "(local)" link after a MITRE ID opens that object's page in this library. Edit the MITRE link; the script rewrites the "(local)" link. -->

> A complete, cross-referenced map of the 691 MITRE ATT&CK Enterprise techniques and sub-techniques (ATT&CK v18.1), organized by tactic. Every technique is scored by how many threat groups and pieces of software use it, how many ATT&CK mitigations and NIST 800-53 controls address it, and whether ATT&CK ships a detection strategy for it, so you can see, at a glance, what matters and what is under-covered.

Legend: Grp = threat groups observed using it, SW = software (malware/tools) implementing it, Mit = ATT&CK mitigations, NIST = NIST 800-53 R5 controls (via CTID), Det = ATT&CK detection strategy exists. Machine-readable source: [`data/attack/technique_profiles.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_profiles.jsonl).

Want the full write-up per technique? Browse the [Technique Detail Pages](techniques/README.md): each of the 691 techniques consolidated with its description, mitigations, NIST controls, detections, and the groups and software that use it.

Related: [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), [Matrix Analysis](ATTACK_MATRIX_ANALYSIS_REFERENCE.md), [Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md), [Threat Group Profiles](THREAT_GROUP_PROFILES.md), [ATT&CK Mitigations](ATTACK_MITIGATIONS_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

| | |
|---|---|
| Who this is for | Detection engineers, threat-informed defense analysts, and anyone looking up an ATT&CK technique |
| Level | Intermediate |
| Reading time | About 51 min (11,649 words at 230 words a minute) |
| Read this when | You need to look up any ATT&CK technique fast, you want to see which techniques are heavily used by groups but light on mitigations or detections, you are prioritizing coverage across a whole tactic |
| Start at | [Tactics](#tactics) for the per-tactic index, [Initial Access](#initial-access) or [Defense Evasion](#defense-evasion) to see the scoring columns in action |

<details class="tsw-meta-more"><summary>More about this page (last reviewed)</summary>

| | |
|---|---|
| Last reviewed | No review recorded yet |

</details>

<!-- meta:end -->

## Tactics

- [Reconnaissance](#reconnaissance): 45 techniques
- [Resource Development](#resource-development): 47 techniques
- [Initial Access](#initial-access): 22 techniques
- [Execution](#execution): 46 techniques
- [Persistence](#persistence): 126 techniques
- [Privilege Escalation](#privilege-escalation): 109 techniques
- [Defense Evasion](#defense-evasion): 215 techniques
- [Credential Access](#credential-access): 67 techniques
- [Discovery](#discovery): 49 techniques
- [Lateral Movement](#lateral-movement): 23 techniques
- [Collection](#collection): 41 techniques
- [Command and Control](#command-and-control): 45 techniques
- [Exfiltration](#exfiltration): 19 techniques
- [Impact](#impact): 33 techniques

---

## Reconnaissance
<a id="reconnaissance"></a>

[`TA0043`](https://attack.mitre.org/tactics/TA0043/) ([local](/mitre/tactics/reconnaissance.md)), 45 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1589 Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589) ([local](/mitre/techniques/T1589.md)) | PRE | 9 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Credentials](https://attack.mitre.org/techniques/T1589/001) ([local](/mitre/techniques/T1589-001.md)) | PRE | 5 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Email Addresses](https://attack.mitre.org/techniques/T1589/002) ([local](/mitre/techniques/T1589-002.md)) | PRE | 14 | 1 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Employee Names](https://attack.mitre.org/techniques/T1589/003) ([local](/mitre/techniques/T1589-003.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| [T1590 Gather Victim Network Information](https://attack.mitre.org/techniques/T1590) ([local](/mitre/techniques/T1590.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Domain Properties](https://attack.mitre.org/techniques/T1590/001) ([local](/mitre/techniques/T1590-001.md)) | PRE | 1 | 1 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 DNS](https://attack.mitre.org/techniques/T1590/002) ([local](/mitre/techniques/T1590-002.md)) | PRE | 0 | 0 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.003 Network Trust Dependencies](https://attack.mitre.org/techniques/T1590/003) ([local](/mitre/techniques/T1590-003.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Network Topology](https://attack.mitre.org/techniques/T1590/004) ([local](/mitre/techniques/T1590-004.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 IP Addresses](https://attack.mitre.org/techniques/T1590/005) ([local](/mitre/techniques/T1590-005.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 Network Security Appliances](https://attack.mitre.org/techniques/T1590/006) ([local](/mitre/techniques/T1590-006.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| [T1591 Gather Victim Org Information](https://attack.mitre.org/techniques/T1591) ([local](/mitre/techniques/T1591.md)) | PRE | 6 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Determine Physical Locations](https://attack.mitre.org/techniques/T1591/001) ([local](/mitre/techniques/T1591-001.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Business Relationships](https://attack.mitre.org/techniques/T1591/002) ([local](/mitre/techniques/T1591-002.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Identify Business Tempo](https://attack.mitre.org/techniques/T1591/003) ([local](/mitre/techniques/T1591-003.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Identify Roles](https://attack.mitre.org/techniques/T1591/004) ([local](/mitre/techniques/T1591-004.md)) | PRE | 4 | 0 | 1 | 0 | Yes |
| [T1592 Gather Victim Host Information](https://attack.mitre.org/techniques/T1592) ([local](/mitre/techniques/T1592.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Hardware](https://attack.mitre.org/techniques/T1592/001) ([local](/mitre/techniques/T1592-001.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Software](https://attack.mitre.org/techniques/T1592/002) ([local](/mitre/techniques/T1592-002.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Firmware](https://attack.mitre.org/techniques/T1592/003) ([local](/mitre/techniques/T1592-003.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Client Configurations](https://attack.mitre.org/techniques/T1592/004) ([local](/mitre/techniques/T1592-004.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| [T1593 Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) ([local](/mitre/techniques/T1593.md)) | PRE | 6 | 0 | 2 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Social Media](https://attack.mitre.org/techniques/T1593/001) ([local](/mitre/techniques/T1593-001.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Search Engines](https://attack.mitre.org/techniques/T1593/002) ([local](/mitre/techniques/T1593-002.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Code Repositories](https://attack.mitre.org/techniques/T1593/003) ([local](/mitre/techniques/T1593-003.md)) | PRE | 3 | 0 | 2 | 1 | Yes |
| [T1594 Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594) ([local](/mitre/techniques/T1594.md)) | PRE | 6 | 0 | 1 | 0 | Yes |
| [T1595 Active Scanning](https://attack.mitre.org/techniques/T1595) ([local](/mitre/techniques/T1595.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Scanning IP Blocks](https://attack.mitre.org/techniques/T1595/001) ([local](/mitre/techniques/T1595-001.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002) ([local](/mitre/techniques/T1595-002.md)) | PRE | 13 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003) ([local](/mitre/techniques/T1595-003.md)) | PRE | 2 | 0 | 2 | 1 | Yes |
| [T1596 Search Open Technical Databases](https://attack.mitre.org/techniques/T1596) ([local](/mitre/techniques/T1596.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 DNS/Passive DNS](https://attack.mitre.org/techniques/T1596/001) ([local](/mitre/techniques/T1596-001.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 WHOIS](https://attack.mitre.org/techniques/T1596/002) ([local](/mitre/techniques/T1596-002.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Digital Certificates](https://attack.mitre.org/techniques/T1596/003) ([local](/mitre/techniques/T1596-003.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 CDNs](https://attack.mitre.org/techniques/T1596/004) ([local](/mitre/techniques/T1596-004.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Scan Databases](https://attack.mitre.org/techniques/T1596/005) ([local](/mitre/techniques/T1596-005.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| [T1597 Search Closed Sources](https://attack.mitre.org/techniques/T1597) ([local](/mitre/techniques/T1597.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Threat Intel Vendors](https://attack.mitre.org/techniques/T1597/001) ([local](/mitre/techniques/T1597-001.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Purchase Technical Data](https://attack.mitre.org/techniques/T1597/002) ([local](/mitre/techniques/T1597-002.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| [T1598 Phishing for Information](https://attack.mitre.org/techniques/T1598) ([local](/mitre/techniques/T1598.md)) | PRE | 5 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.001 Spearphishing Service](https://attack.mitre.org/techniques/T1598/001) ([local](/mitre/techniques/T1598-001.md)) | PRE | 0 | 0 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.002 Spearphishing Attachment](https://attack.mitre.org/techniques/T1598/002) ([local](/mitre/techniques/T1598-002.md)) | PRE | 4 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 Spearphishing Link](https://attack.mitre.org/techniques/T1598/003) ([local](/mitre/techniques/T1598-003.md)) | PRE | 15 | 2 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1598/004) ([local](/mitre/techniques/T1598-004.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| [T1681 Search Threat Vendor Data](https://attack.mitre.org/techniques/T1681) ([local](/mitre/techniques/T1681.md)) | PRE | 2 | 0 | 1 | 0 | Yes |

## Resource Development
<a id="resource-development"></a>

[`TA0042`](https://attack.mitre.org/tactics/TA0042/) ([local](/mitre/tactics/resource-development.md)), 47 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1583 Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) ([local](/mitre/techniques/T1583.md)) | PRE | 8 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Domains](https://attack.mitre.org/techniques/T1583/001) ([local](/mitre/techniques/T1583-001.md)) | PRE | 40 | 3 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 DNS Server](https://attack.mitre.org/techniques/T1583/002) ([local](/mitre/techniques/T1583-002.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Virtual Private Server](https://attack.mitre.org/techniques/T1583/003) ([local](/mitre/techniques/T1583-003.md)) | PRE | 14 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Server](https://attack.mitre.org/techniques/T1583/004) ([local](/mitre/techniques/T1583-004.md)) | PRE | 6 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Botnet](https://attack.mitre.org/techniques/T1583/005) ([local](/mitre/techniques/T1583-005.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 Web Services](https://attack.mitre.org/techniques/T1583/006) ([local](/mitre/techniques/T1583-006.md)) | PRE | 24 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.007 Serverless](https://attack.mitre.org/techniques/T1583/007) ([local](/mitre/techniques/T1583-007.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.008 Malvertising](https://attack.mitre.org/techniques/T1583/008) ([local](/mitre/techniques/T1583-008.md)) | PRE | 1 | 1 | 1 | 0 | Yes |
| [T1584 Compromise Infrastructure](https://attack.mitre.org/techniques/T1584) ([local](/mitre/techniques/T1584.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Domains](https://attack.mitre.org/techniques/T1584/001) ([local](/mitre/techniques/T1584-001.md)) | PRE | 6 | 1 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 DNS Server](https://attack.mitre.org/techniques/T1584/002) ([local](/mitre/techniques/T1584-002.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Virtual Private Server](https://attack.mitre.org/techniques/T1584/003) ([local](/mitre/techniques/T1584-003.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Server](https://attack.mitre.org/techniques/T1584/004) ([local](/mitre/techniques/T1584-004.md)) | PRE | 10 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Botnet](https://attack.mitre.org/techniques/T1584/005) ([local](/mitre/techniques/T1584-005.md)) | PRE | 4 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 Web Services](https://attack.mitre.org/techniques/T1584/006) ([local](/mitre/techniques/T1584-006.md)) | PRE | 4 | 1 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.007 Serverless](https://attack.mitre.org/techniques/T1584/007) ([local](/mitre/techniques/T1584-007.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.008 Network Devices](https://attack.mitre.org/techniques/T1584/008) ([local](/mitre/techniques/T1584-008.md)) | PRE | 4 | 0 | 1 | 0 | Yes |
| [T1585 Establish Accounts](https://attack.mitre.org/techniques/T1585) ([local](/mitre/techniques/T1585.md)) | PRE | 5 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Social Media Accounts](https://attack.mitre.org/techniques/T1585/001) ([local](/mitre/techniques/T1585-001.md)) | PRE | 17 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Email Accounts](https://attack.mitre.org/techniques/T1585/002) ([local](/mitre/techniques/T1585-002.md)) | PRE | 18 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Cloud Accounts](https://attack.mitre.org/techniques/T1585/003) ([local](/mitre/techniques/T1585-003.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| [T1586 Compromise Accounts](https://attack.mitre.org/techniques/T1586) ([local](/mitre/techniques/T1586.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Social Media Accounts](https://attack.mitre.org/techniques/T1586/001) ([local](/mitre/techniques/T1586-001.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Email Accounts](https://attack.mitre.org/techniques/T1586/002) ([local](/mitre/techniques/T1586-002.md)) | PRE | 12 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Cloud Accounts](https://attack.mitre.org/techniques/T1586/003) ([local](/mitre/techniques/T1586-003.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| [T1587 Develop Capabilities](https://attack.mitre.org/techniques/T1587) ([local](/mitre/techniques/T1587.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Malware](https://attack.mitre.org/techniques/T1587/001) ([local](/mitre/techniques/T1587-001.md)) | PRE | 22 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Code Signing Certificates](https://attack.mitre.org/techniques/T1587/002) ([local](/mitre/techniques/T1587-002.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Digital Certificates](https://attack.mitre.org/techniques/T1587/003) ([local](/mitre/techniques/T1587-003.md)) | PRE | 4 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Exploits](https://attack.mitre.org/techniques/T1587/004) ([local](/mitre/techniques/T1587-004.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| [T1588 Obtain Capabilities](https://attack.mitre.org/techniques/T1588) ([local](/mitre/techniques/T1588.md)) | PRE | 0 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Malware](https://attack.mitre.org/techniques/T1588/001) ([local](/mitre/techniques/T1588-001.md)) | PRE | 15 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Tool](https://attack.mitre.org/techniques/T1588/002) ([local](/mitre/techniques/T1588-002.md)) | PRE | 79 | 1 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Code Signing Certificates](https://attack.mitre.org/techniques/T1588/003) ([local](/mitre/techniques/T1588-003.md)) | PRE | 7 | 1 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Digital Certificates](https://attack.mitre.org/techniques/T1588/004) ([local](/mitre/techniques/T1588-004.md)) | PRE | 7 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Exploits](https://attack.mitre.org/techniques/T1588/005) ([local](/mitre/techniques/T1588-005.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 Vulnerabilities](https://attack.mitre.org/techniques/T1588/006) ([local](/mitre/techniques/T1588-006.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.007 Artificial Intelligence](https://attack.mitre.org/techniques/T1588/007) ([local](/mitre/techniques/T1588-007.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| [T1608 Stage Capabilities](https://attack.mitre.org/techniques/T1608) ([local](/mitre/techniques/T1608.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Upload Malware](https://attack.mitre.org/techniques/T1608/001) ([local](/mitre/techniques/T1608-001.md)) | PRE | 25 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Upload Tool](https://attack.mitre.org/techniques/T1608/002) ([local](/mitre/techniques/T1608-002.md)) | PRE | 2 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Install Digital Certificate](https://attack.mitre.org/techniques/T1608/003) ([local](/mitre/techniques/T1608-003.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Drive-by Target](https://attack.mitre.org/techniques/T1608/004) ([local](/mitre/techniques/T1608-004.md)) | PRE | 8 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Link Target](https://attack.mitre.org/techniques/T1608/005) ([local](/mitre/techniques/T1608-005.md)) | PRE | 3 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 SEO Poisoning](https://attack.mitre.org/techniques/T1608/006) ([local](/mitre/techniques/T1608-006.md)) | PRE | 1 | 0 | 1 | 0 | Yes |
| [T1650 Acquire Access](https://attack.mitre.org/techniques/T1650) ([local](/mitre/techniques/T1650.md)) | PRE | 1 | 0 | 1 | 0 | Yes |

## Initial Access
<a id="initial-access"></a>

[`TA0001`](https://attack.mitre.org/tactics/TA0001/) ([local](/mitre/tactics/initial-access.md)), 22 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) ([local](/mitre/techniques/T1078.md)) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 44 | 6 | 8 | 25 | Yes |
| &nbsp;&nbsp;↳ [.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001) ([local](/mitre/techniques/T1078-001.md)) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 4 | 2 | 2 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002) ([local](/mitre/techniques/T1078-002.md)) | ESXi Lnx Mac Win | 18 | 5 | 5 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003) ([local](/mitre/techniques/T1078-003.md)) | Lnx Mac Win Cnt NetDev ESXi | 12 | 5 | 4 | 19 | Yes |
| &nbsp;&nbsp;↳ [.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) ([local](/mitre/techniques/T1078-004.md)) | IaaS IdP Office SaaS | 9 | 3 | 7 | 24 | Yes |
| [T1091 Replication Through Removable Media](https://attack.mitre.org/techniques/T1091) ([local](/mitre/techniques/T1091.md)) | Win | 8 | 20 | 3 | 10 | Yes |
| [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133) ([local](/mitre/techniques/T1133.md)) | Cnt Lnx Mac Win | 26 | 5 | 5 | 17 | Yes |
| [T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189) ([local](/mitre/techniques/T1189.md)) | IdP Lnx Mac Win | 31 | 10 | 5 | 18 | Yes |
| [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) ([local](/mitre/techniques/T1190.md)) | Cnt ESXi IaaS Lnx Mac NetDev Win | 42 | 8 | 8 | 29 | Yes |
| [T1195 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) ([local](/mitre/techniques/T1195.md)) | Lnx Win Mac SaaS | 3 | 2 | 6 | 22 | Yes |
| &nbsp;&nbsp;↳ [.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001) ([local](/mitre/techniques/T1195-001.md)) | Lnx Mac Win | 0 | 2 | 4 | 18 | Yes |
| &nbsp;&nbsp;↳ [.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002) ([local](/mitre/techniques/T1195-002.md)) | Lnx Win Mac | 9 | 3 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 Compromise Hardware Supply Chain](https://attack.mitre.org/techniques/T1195/003) ([local](/mitre/techniques/T1195-003.md)) | Lnx Mac Win | 0 | 0 | 1 | 14 | Yes |
| [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199) ([local](/mitre/techniques/T1199.md)) | Win SaaS IaaS Lnx Mac IdP Office | 11 | 0 | 3 | 8 | Yes |
| [T1200 Hardware Additions](https://attack.mitre.org/techniques/T1200) ([local](/mitre/techniques/T1200.md)) | Win Lnx Mac | 1 | 0 | 2 | 5 | Yes |
| [T1566 Phishing](https://attack.mitre.org/techniques/T1566) ([local](/mitre/techniques/T1566.md)) | IdP Lnx Mac Office SaaS Win | 6 | 3 | 6 | 13 | Yes |
| &nbsp;&nbsp;↳ [.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) ([local](/mitre/techniques/T1566-001.md)) | Lnx Mac Win | 77 | 55 | 7 | 12 | Yes |
| &nbsp;&nbsp;↳ [.002 Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) ([local](/mitre/techniques/T1566-002.md)) | IdP Lnx Mac Office SaaS Win | 43 | 29 | 5 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003) ([local](/mitre/techniques/T1566-003.md)) | Lnx Mac Win | 14 | 1 | 5 | 10 | Yes |
| &nbsp;&nbsp;↳ [.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004) ([local](/mitre/techniques/T1566-004.md)) | Lnx Mac Win IdP | 1 | 0 | 1 | 0 | Yes |
| [T1659 Content Injection](https://attack.mitre.org/techniques/T1659) ([local](/mitre/techniques/T1659.md)) | Lnx Mac Win | 1 | 1 | 2 | 3 | Yes |
| [T1669 Wi-Fi Networks](https://attack.mitre.org/techniques/T1669) ([local](/mitre/techniques/T1669.md)) | Lnx NetDev Win Mac | 1 | 0 | 3 | 0 | Yes |

## Execution
<a id="execution"></a>

[`TA0002`](https://attack.mitre.org/tactics/TA0002/) ([local](/mitre/tactics/execution.md)), 46 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1047 Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) | Win | 39 | 88 | 4 | 17 | Yes |
| [T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) ([local](/mitre/techniques/T1053.md)) | Win Lnx Mac Cnt ESXi | 0 | 1 | 5 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 At](https://attack.mitre.org/techniques/T1053/002) ([local](/mitre/techniques/T1053-002.md)) | Win Lnx Mac | 3 | 3 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Cron](https://attack.mitre.org/techniques/T1053/003) ([local](/mitre/techniques/T1053-003.md)) | Lnx Mac ESXi | 3 | 12 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) | Win | 54 | 118 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.006 Systemd Timers](https://attack.mitre.org/techniques/T1053/006) ([local](/mitre/techniques/T1053-006.md)) | Lnx | 0 | 0 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.007 Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007) ([local](/mitre/techniques/T1053-007.md)) | Cnt | 0 | 0 | 2 | 7 | Yes |
| [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) ([local](/mitre/techniques/T1059.md)) | ESXi IaaS IdP Lnx Mac NetDev Office Win | 17 | 22 | 9 | 23 | Yes |
| &nbsp;&nbsp;↳ [.001 PowerShell](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) | Win | 83 | 124 | 5 | 19 | Yes |
| &nbsp;&nbsp;↳ [.002 AppleScript](https://attack.mitre.org/techniques/T1059/002) ([local](/mitre/techniques/T1059-002.md)) | Mac | 0 | 5 | 2 | 15 | Yes |
| &nbsp;&nbsp;↳ [.003 Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) | Win | 71 | 286 | 1 | 11 | Yes |
| &nbsp;&nbsp;↳ [.004 Unix Shell](https://attack.mitre.org/techniques/T1059/004) ([local](/mitre/techniques/T1059-004.md)) | ESXi Lnx Mac NetDev | 10 | 45 | 1 | 11 | Yes |
| &nbsp;&nbsp;↳ [.005 Visual Basic](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) | Lnx Mac Win | 45 | 67 | 5 | 17 | Yes |
| &nbsp;&nbsp;↳ [.006 Python](https://attack.mitre.org/techniques/T1059/006) ([local](/mitre/techniques/T1059-006.md)) | ESXi Lnx Mac Win | 17 | 34 | 4 | 15 | Yes |
| &nbsp;&nbsp;↳ [.007 JavaScript](https://attack.mitre.org/techniques/T1059/007) ([local](/mitre/techniques/T1059-007.md)) | Lnx Mac Win | 25 | 32 | 4 | 16 | Yes |
| &nbsp;&nbsp;↳ [.008 Network Device CLI](https://attack.mitre.org/techniques/T1059/008) ([local](/mitre/techniques/T1059-008.md)) | NetDev | 0 | 1 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.009 Cloud API](https://attack.mitre.org/techniques/T1059/009) ([local](/mitre/techniques/T1059-009.md)) | IaaS IdP Office SaaS | 3 | 1 | 2 | 6 | Yes |
| &nbsp;&nbsp;↳ [.010 AutoHotKey & AutoIT](https://attack.mitre.org/techniques/T1059/010) ([local](/mitre/techniques/T1059-010.md)) | Win | 1 | 5 | 1 | 11 | Yes |
| &nbsp;&nbsp;↳ [.011 Lua](https://attack.mitre.org/techniques/T1059/011) ([local](/mitre/techniques/T1059-011.md)) | Lnx NetDev Win Mac | 0 | 5 | 3 | 9 | Yes |
| &nbsp;&nbsp;↳ [.012 Hypervisor CLI](https://attack.mitre.org/techniques/T1059/012) ([local](/mitre/techniques/T1059-012.md)) | ESXi | 1 | 3 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.013 Container CLI/API](https://attack.mitre.org/techniques/T1059/013) ([local](/mitre/techniques/T1059-013.md)) | Cnt | 1 | 0 | 2 | 0 | Yes |
| [T1072 Software Deployment Tools](https://attack.mitre.org/techniques/T1072) ([local](/mitre/techniques/T1072.md)) | Lnx Mac NetDev SaaS Win | 6 | 1 | 10 | 27 | Yes |
| [T1106 Native API](https://attack.mitre.org/techniques/T1106) ([local](/mitre/techniques/T1106.md)) | Lnx Mac Win | 18 | 189 | 2 | 7 | Yes |
| [T1129 Shared Modules](https://attack.mitre.org/techniques/T1129) ([local](/mitre/techniques/T1129.md)) | Lnx Mac Win | 1 | 21 | 1 | 6 | Yes |
| [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203) ([local](/mitre/techniques/T1203.md)) | Lnx Mac Win | 41 | 14 | 3 | 16 | Yes |
| [T1204 User Execution](https://attack.mitre.org/techniques/T1204) ([local](/mitre/techniques/T1204.md)) | Lnx Win Mac IaaS Cnt | 2 | 2 | 6 | 13 | Yes |
| &nbsp;&nbsp;↳ [.001 Malicious Link](https://attack.mitre.org/techniques/T1204/001) ([local](/mitre/techniques/T1204-001.md)) | Lnx Mac Win | 47 | 28 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.002 Malicious File](https://attack.mitre.org/techniques/T1204/002) ([local](/mitre/techniques/T1204-002.md)) | Lnx Mac Win | 84 | 90 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.003 Malicious Image](https://attack.mitre.org/techniques/T1204/003) ([local](/mitre/techniques/T1204-003.md)) | IaaS Cnt | 1 | 0 | 4 | 16 | Yes |
| &nbsp;&nbsp;↳ [.004 Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004) ([local](/mitre/techniques/T1204-004.md)) | Lnx Mac Win | 1 | 1 | 3 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Malicious Library](https://attack.mitre.org/techniques/T1204/005) ([local](/mitre/techniques/T1204-005.md)) | Lnx Mac Win | 1 | 0 | 3 | 0 | Yes |
| [T1559 Inter-Process Communication](https://attack.mitre.org/techniques/T1559) ([local](/mitre/techniques/T1559.md)) | Lnx Mac Win | 0 | 14 | 6 | 19 | Yes |
| &nbsp;&nbsp;↳ [.001 Component Object Model](https://attack.mitre.org/techniques/T1559/001) ([local](/mitre/techniques/T1559-001.md)) | Win | 3 | 17 | 2 | 13 | Yes |
| &nbsp;&nbsp;↳ [.002 Dynamic Data Exchange](https://attack.mitre.org/techniques/T1559/002) ([local](/mitre/techniques/T1559-002.md)) | Win | 11 | 8 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.003 XPC Services](https://attack.mitre.org/techniques/T1559/003) ([local](/mitre/techniques/T1559-003.md)) | Mac | 0 | 0 | 1 | 7 | Yes |
| [T1569 System Services](https://attack.mitre.org/techniques/T1569) ([local](/mitre/techniques/T1569.md)) | Win Mac Lnx | 0 | 0 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.001 Launchctl](https://attack.mitre.org/techniques/T1569/001) ([local](/mitre/techniques/T1569-001.md)) | Mac | 0 | 6 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.002 Service Execution](https://attack.mitre.org/techniques/T1569/002) ([local](/mitre/techniques/T1569-002.md)) | Win | 16 | 51 | 3 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Systemctl](https://attack.mitre.org/techniques/T1569/003) ([local](/mitre/techniques/T1569-003.md)) | Lnx | 1 | 0 | 1 | 0 | Yes |
| [T1609 Container Administration Command](https://attack.mitre.org/techniques/T1609) ([local](/mitre/techniques/T1609.md)) | Cnt | 1 | 4 | 5 | 11 | Yes |
| [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610) ([local](/mitre/techniques/T1610.md)) | Cnt | 1 | 3 | 4 | 9 | Yes |
| [T1648 Serverless Execution](https://attack.mitre.org/techniques/T1648) ([local](/mitre/techniques/T1648.md)) | SaaS IaaS Office | 0 | 1 | 2 | 8 | Yes |
| [T1651 Cloud Administration Command](https://attack.mitre.org/techniques/T1651) ([local](/mitre/techniques/T1651.md)) | IaaS | 1 | 2 | 1 | 6 | Yes |
| [T1674 Input Injection](https://attack.mitre.org/techniques/T1674) ([local](/mitre/techniques/T1674.md)) | Win Mac Lnx | 1 | 0 | 2 | 0 | Yes |
| [T1675 ESXi Administration Command](https://attack.mitre.org/techniques/T1675) ([local](/mitre/techniques/T1675.md)) | ESXi | 1 | 1 | 1 | 0 | Yes |
| [T1677 Poisoned Pipeline Execution](https://attack.mitre.org/techniques/T1677) ([local](/mitre/techniques/T1677.md)) | SaaS | 0 | 0 | 2 | 0 | Yes |

## Persistence
<a id="persistence"></a>

[`TA0003`](https://attack.mitre.org/tactics/TA0003/) ([local](/mitre/tactics/persistence.md)), 126 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1037 Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037) ([local](/mitre/techniques/T1037.md)) | Mac Win Lnx NetDev ESXi | 4 | 2 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.001 Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001) ([local](/mitre/techniques/T1037-001.md)) | Win | 2 | 4 | 1 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 Login Hook](https://attack.mitre.org/techniques/T1037/002) ([local](/mitre/techniques/T1037-002.md)) | Mac | 0 | 0 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.003 Network Logon Script](https://attack.mitre.org/techniques/T1037/003) ([local](/mitre/techniques/T1037-003.md)) | Win | 0 | 0 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.004 RC Scripts](https://attack.mitre.org/techniques/T1037/004) ([local](/mitre/techniques/T1037-004.md)) | Mac Lnx NetDev ESXi | 3 | 4 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.005 Startup Items](https://attack.mitre.org/techniques/T1037/005) ([local](/mitre/techniques/T1037-005.md)) | Mac | 0 | 1 | 1 | 7 | Yes |
| [T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) ([local](/mitre/techniques/T1053.md)) | Win Lnx Mac Cnt ESXi | 0 | 1 | 5 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 At](https://attack.mitre.org/techniques/T1053/002) ([local](/mitre/techniques/T1053-002.md)) | Win Lnx Mac | 3 | 3 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Cron](https://attack.mitre.org/techniques/T1053/003) ([local](/mitre/techniques/T1053-003.md)) | Lnx Mac ESXi | 3 | 12 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) | Win | 54 | 118 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.006 Systemd Timers](https://attack.mitre.org/techniques/T1053/006) ([local](/mitre/techniques/T1053-006.md)) | Lnx | 0 | 0 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.007 Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007) ([local](/mitre/techniques/T1053-007.md)) | Cnt | 0 | 0 | 2 | 7 | Yes |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) ([local](/mitre/techniques/T1078.md)) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 44 | 6 | 8 | 25 | Yes |
| &nbsp;&nbsp;↳ [.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001) ([local](/mitre/techniques/T1078-001.md)) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 4 | 2 | 2 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002) ([local](/mitre/techniques/T1078-002.md)) | ESXi Lnx Mac Win | 18 | 5 | 5 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003) ([local](/mitre/techniques/T1078-003.md)) | Lnx Mac Win Cnt NetDev ESXi | 12 | 5 | 4 | 19 | Yes |
| &nbsp;&nbsp;↳ [.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) ([local](/mitre/techniques/T1078-004.md)) | IaaS IdP Office SaaS | 9 | 3 | 7 | 24 | Yes |
| [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098) ([local](/mitre/techniques/T1098.md)) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 3 | 2 | 7 | 11 | Yes |
| &nbsp;&nbsp;↳ [.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) ([local](/mitre/techniques/T1098-001.md)) | IaaS IdP SaaS | 1 | 1 | 5 | 15 | Yes |
| &nbsp;&nbsp;↳ [.002 Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002) ([local](/mitre/techniques/T1098-002.md)) | Win Office | 3 | 0 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) ([local](/mitre/techniques/T1098-003.md)) | IaaS IdP Office SaaS | 3 | 0 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.004 SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004) ([local](/mitre/techniques/T1098-004.md)) | Lnx Mac IaaS NetDev ESXi | 3 | 3 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.005 Device Registration](https://attack.mitre.org/techniques/T1098/005) ([local](/mitre/techniques/T1098-005.md)) | Win IdP | 1 | 1 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.006 Additional Container Cluster Roles](https://attack.mitre.org/techniques/T1098/006) ([local](/mitre/techniques/T1098-006.md)) | Cnt | 0 | 0 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007) ([local](/mitre/techniques/T1098-007.md)) | Win Mac Lnx | 7 | 4 | 0 | 11 | Yes |
| [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) | Win | 29 | 136 | 1 | 3 | Yes |
| [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133) ([local](/mitre/techniques/T1133.md)) | Cnt Lnx Mac Win | 26 | 5 | 5 | 17 | Yes |
| [T1136 Create Account](https://attack.mitre.org/techniques/T1136) ([local](/mitre/techniques/T1136.md)) | Win IaaS Lnx Mac NetDev Cnt SaaS Office IdP ESXi | 3 | 1 | 4 | 15 | Yes |
| &nbsp;&nbsp;↳ [.001 Local Account](https://attack.mitre.org/techniques/T1136/001) ([local](/mitre/techniques/T1136-001.md)) | Lnx Mac Win NetDev Cnt ESXi | 14 | 15 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.002 Domain Account](https://attack.mitre.org/techniques/T1136/002) ([local](/mitre/techniques/T1136-002.md)) | Lnx Mac Win | 5 | 4 | 4 | 15 | Yes |
| &nbsp;&nbsp;↳ [.003 Cloud Account](https://attack.mitre.org/techniques/T1136/003) ([local](/mitre/techniques/T1136-003.md)) | IaaS SaaS Office IdP | 2 | 1 | 3 | 14 | Yes |
| [T1137 Office Application Startup](https://attack.mitre.org/techniques/T1137) ([local](/mitre/techniques/T1137.md)) | Win Office | 2 | 0 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.001 Office Template Macros](https://attack.mitre.org/techniques/T1137/001) ([local](/mitre/techniques/T1137-001.md)) | Win Office | 1 | 2 | 2 | 10 | Yes |
| &nbsp;&nbsp;↳ [.002 Office Test](https://attack.mitre.org/techniques/T1137/002) ([local](/mitre/techniques/T1137-002.md)) | Win Office | 1 | 0 | 2 | 10 | Yes |
| &nbsp;&nbsp;↳ [.003 Outlook Forms](https://attack.mitre.org/techniques/T1137/003) ([local](/mitre/techniques/T1137-003.md)) | Win Office | 0 | 1 | 2 | 7 | Yes |
| &nbsp;&nbsp;↳ [.004 Outlook Home Page](https://attack.mitre.org/techniques/T1137/004) ([local](/mitre/techniques/T1137-004.md)) | Win Office | 1 | 1 | 2 | 7 | Yes |
| &nbsp;&nbsp;↳ [.005 Outlook Rules](https://attack.mitre.org/techniques/T1137/005) ([local](/mitre/techniques/T1137-005.md)) | Win Office | 0 | 1 | 2 | 7 | Yes |
| &nbsp;&nbsp;↳ [.006 Add-ins](https://attack.mitre.org/techniques/T1137/006) ([local](/mitre/techniques/T1137-006.md)) | Win Office | 1 | 3 | 1 | 6 | Yes |
| [T1176 Software Extensions](https://attack.mitre.org/techniques/T1176) ([local](/mitre/techniques/T1176.md)) | Lnx Mac Win | 0 | 0 | 5 | 14 | Yes |
| &nbsp;&nbsp;↳ [.001 Browser Extensions](https://attack.mitre.org/techniques/T1176/001) ([local](/mitre/techniques/T1176-001.md)) | Lnx Win Mac | 1 | 6 | 5 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 IDE Extensions](https://attack.mitre.org/techniques/T1176/002) ([local](/mitre/techniques/T1176-002.md)) | Lnx Mac Win | 1 | 0 | 5 | 0 | Yes |
| [T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197) ([local](/mitre/techniques/T1197.md)) | Win | 5 | 8 | 3 | 14 | Yes |
| [T1205 Traffic Signaling](https://attack.mitre.org/techniques/T1205) ([local](/mitre/techniques/T1205.md)) | Lnx Mac NetDev Win | 3 | 16 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.001 Port Knocking](https://attack.mitre.org/techniques/T1205/001) ([local](/mitre/techniques/T1205-001.md)) | Lnx Mac Win NetDev | 2 | 4 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Socket Filters](https://attack.mitre.org/techniques/T1205/002) ([local](/mitre/techniques/T1205-002.md)) | Lnx Mac Win | 0 | 4 | 1 | 2 | Yes |
| [T1505 Server Software Component](https://attack.mitre.org/techniques/T1505) ([local](/mitre/techniques/T1505.md)) | Win Lnx Mac NetDev ESXi | 0 | 0 | 7 | 21 | Yes |
| &nbsp;&nbsp;↳ [.001 SQL Stored Procedures](https://attack.mitre.org/techniques/T1505/001) ([local](/mitre/techniques/T1505-001.md)) | Win Lnx | 0 | 1 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.002 Transport Agent](https://attack.mitre.org/techniques/T1505/002) ([local](/mitre/techniques/T1505-002.md)) | Lnx Win | 0 | 1 | 3 | 21 | Yes |
| &nbsp;&nbsp;↳ [.003 Web Shell](https://attack.mitre.org/techniques/T1505/003) ([local](/mitre/techniques/T1505-003.md)) | Lnx Mac NetDev Win | 31 | 19 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 IIS Components](https://attack.mitre.org/techniques/T1505/004) ([local](/mitre/techniques/T1505-004.md)) | Win | 0 | 3 | 4 | 22 | Yes |
| &nbsp;&nbsp;↳ [.005 Terminal Services DLL](https://attack.mitre.org/techniques/T1505/005) ([local](/mitre/techniques/T1505-005.md)) | Win | 0 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.006 vSphere Installation Bundles](https://attack.mitre.org/techniques/T1505/006) ([local](/mitre/techniques/T1505-006.md)) | ESXi | 1 | 1 | 3 | 0 | Yes |
| [T1525 Implant Internal Image](https://attack.mitre.org/techniques/T1525) ([local](/mitre/techniques/T1525.md)) | IaaS Cnt | 0 | 0 | 3 | 15 | Yes |
| [T1542 Pre-OS Boot](https://attack.mitre.org/techniques/T1542) ([local](/mitre/techniques/T1542.md)) | Lnx NetDev Win Mac | 0 | 0 | 5 | 19 | Yes |
| &nbsp;&nbsp;↳ [.001 System Firmware](https://attack.mitre.org/techniques/T1542/001) ([local](/mitre/techniques/T1542-001.md)) | Win NetDev | 0 | 3 | 3 | 17 | Yes |
| &nbsp;&nbsp;↳ [.002 Component Firmware](https://attack.mitre.org/techniques/T1542/002) ([local](/mitre/techniques/T1542-002.md)) | Win Lnx Mac | 1 | 1 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Bootkit](https://attack.mitre.org/techniques/T1542/003) ([local](/mitre/techniques/T1542-003.md)) | Lnx Win | 3 | 6 | 2 | 18 | Yes |
| &nbsp;&nbsp;↳ [.004 ROMMONkit](https://attack.mitre.org/techniques/T1542/004) ([local](/mitre/techniques/T1542-004.md)) | NetDev | 0 | 0 | 3 | 19 | Yes |
| &nbsp;&nbsp;↳ [.005 TFTP Boot](https://attack.mitre.org/techniques/T1542/005) ([local](/mitre/techniques/T1542-005.md)) | NetDev | 0 | 0 | 6 | 23 | Yes |
| [T1543 Create or Modify System Process](https://attack.mitre.org/techniques/T1543) ([local](/mitre/techniques/T1543.md)) | Win Mac Lnx Cnt | 0 | 6 | 9 | 20 | Yes |
| &nbsp;&nbsp;↳ [.001 Launch Agent](https://attack.mitre.org/techniques/T1543/001) ([local](/mitre/techniques/T1543-001.md)) | Mac | 1 | 20 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002) ([local](/mitre/techniques/T1543-002.md)) | Lnx | 3 | 8 | 4 | 16 | Yes |
| &nbsp;&nbsp;↳ [.003 Windows Service](https://attack.mitre.org/techniques/T1543/003) ([local](/mitre/techniques/T1543-003.md)) | Win | 26 | 108 | 5 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Launch Daemon](https://attack.mitre.org/techniques/T1543/004) ([local](/mitre/techniques/T1543-004.md)) | Mac | 0 | 10 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.005 Container Service](https://attack.mitre.org/techniques/T1543/005) ([local](/mitre/techniques/T1543-005.md)) | Cnt | 0 | 0 | 2 | 5 | Yes |
| [T1546 Event Triggered Execution](https://attack.mitre.org/techniques/T1546) ([local](/mitre/techniques/T1546.md)) | Lnx Mac Win SaaS IaaS Office | 0 | 3 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.001 Change Default File Association](https://attack.mitre.org/techniques/T1546/001) ([local](/mitre/techniques/T1546-001.md)) | Win | 1 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Screensaver](https://attack.mitre.org/techniques/T1546/002) ([local](/mitre/techniques/T1546-002.md)) | Win | 0 | 1 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.003 Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003) ([local](/mitre/techniques/T1546-003.md)) | Win | 10 | 13 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.004 Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004) ([local](/mitre/techniques/T1546-004.md)) | Lnx Mac | 1 | 4 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.005 Trap](https://attack.mitre.org/techniques/T1546/005) ([local](/mitre/techniques/T1546-005.md)) | Mac Lnx | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 LC_LOAD_DYLIB Addition](https://attack.mitre.org/techniques/T1546/006) ([local](/mitre/techniques/T1546-006.md)) | Mac | 0 | 0 | 3 | 13 | Yes |
| &nbsp;&nbsp;↳ [.007 Netsh Helper DLL](https://attack.mitre.org/techniques/T1546/007) ([local](/mitre/techniques/T1546-007.md)) | Win | 0 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.008 Accessibility Features](https://attack.mitre.org/techniques/T1546/008) ([local](/mitre/techniques/T1546-008.md)) | Win | 6 | 1 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.009 AppCert DLLs](https://attack.mitre.org/techniques/T1546/009) ([local](/mitre/techniques/T1546-009.md)) | Win | 0 | 1 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.010 AppInit DLLs](https://attack.mitre.org/techniques/T1546/010) ([local](/mitre/techniques/T1546-010.md)) | Win | 1 | 3 | 2 | 5 | Yes |
| &nbsp;&nbsp;↳ [.011 Application Shimming](https://attack.mitre.org/techniques/T1546/011) ([local](/mitre/techniques/T1546-011.md)) | Win | 1 | 3 | 2 | 2 | Yes |
| &nbsp;&nbsp;↳ [.012 Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012) ([local](/mitre/techniques/T1546-012.md)) | Win | 0 | 2 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.013 PowerShell Profile](https://attack.mitre.org/techniques/T1546/013) ([local](/mitre/techniques/T1546-013.md)) | Win | 1 | 0 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.014 Emond](https://attack.mitre.org/techniques/T1546/014) ([local](/mitre/techniques/T1546-014.md)) | Mac | 0 | 0 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.015 Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015) ([local](/mitre/techniques/T1546-015.md)) | Win | 1 | 11 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.016 Installer Packages](https://attack.mitre.org/techniques/T1546/016) ([local](/mitre/techniques/T1546-016.md)) | Lnx Win Mac | 0 | 1 | 0 | 7 | Yes |
| &nbsp;&nbsp;↳ [.017 Udev Rules](https://attack.mitre.org/techniques/T1546/017) ([local](/mitre/techniques/T1546-017.md)) | Lnx | 0 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.018 Python Startup Hooks](https://attack.mitre.org/techniques/T1546/018) ([local](/mitre/techniques/T1546-018.md)) | Lnx Mac Win | 0 | 0 | 0 | 0 | Yes |
| [T1547 Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547) ([local](/mitre/techniques/T1547.md)) | Lnx Mac Win NetDev | 1 | 5 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001) ([local](/mitre/techniques/T1547-001.md)) | Win | 55 | 194 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Authentication Package](https://attack.mitre.org/techniques/T1547/002) ([local](/mitre/techniques/T1547-002.md)) | Win | 0 | 1 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.003 Time Providers](https://attack.mitre.org/techniques/T1547/003) ([local](/mitre/techniques/T1547-003.md)) | Win | 0 | 0 | 2 | 10 | Yes |
| &nbsp;&nbsp;↳ [.004 Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547/004) ([local](/mitre/techniques/T1547-004.md)) | Win | 3 | 10 | 2 | 13 | Yes |
| &nbsp;&nbsp;↳ [.005 Security Support Provider](https://attack.mitre.org/techniques/T1547/005) ([local](/mitre/techniques/T1547-005.md)) | Win | 0 | 3 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.006 Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006) ([local](/mitre/techniques/T1547-006.md)) | Mac Lnx | 0 | 3 | 4 | 18 | Yes |
| &nbsp;&nbsp;↳ [.007 Re-opened Applications](https://attack.mitre.org/techniques/T1547/007) ([local](/mitre/techniques/T1547-007.md)) | Mac | 0 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.008 LSASS Driver](https://attack.mitre.org/techniques/T1547/008) ([local](/mitre/techniques/T1547-008.md)) | Win | 0 | 2 | 3 | 7 | Yes |
| &nbsp;&nbsp;↳ [.009 Shortcut Modification](https://attack.mitre.org/techniques/T1547/009) ([local](/mitre/techniques/T1547-009.md)) | Win | 4 | 25 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.010 Port Monitors](https://attack.mitre.org/techniques/T1547/010) ([local](/mitre/techniques/T1547-010.md)) | Win | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.012 Print Processors](https://attack.mitre.org/techniques/T1547/012) ([local](/mitre/techniques/T1547-012.md)) | Win | 1 | 2 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.013 XDG Autostart Entries](https://attack.mitre.org/techniques/T1547/013) ([local](/mitre/techniques/T1547-013.md)) | Lnx | 1 | 6 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.014 Active Setup](https://attack.mitre.org/techniques/T1547/014) ([local](/mitre/techniques/T1547-014.md)) | Win | 0 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.015 Login Items](https://attack.mitre.org/techniques/T1547/015) ([local](/mitre/techniques/T1547-015.md)) | Mac | 0 | 3 | 0 | 0 | Yes |
| [T1554 Compromise Host Software Binary](https://attack.mitre.org/techniques/T1554) ([local](/mitre/techniques/T1554.md)) | Lnx Mac Win ESXi | 2 | 16 | 1 | 9 | Yes |
| [T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556) ([local](/mitre/techniques/T1556.md)) | Win Lnx Mac NetDev IaaS SaaS Office IdP | 1 | 3 | 9 | 17 | Yes |
| &nbsp;&nbsp;↳ [.001 Domain Controller Authentication](https://attack.mitre.org/techniques/T1556/001) ([local](/mitre/techniques/T1556-001.md)) | Win | 1 | 1 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 Password Filter DLL](https://attack.mitre.org/techniques/T1556/002) ([local](/mitre/techniques/T1556-002.md)) | Win | 2 | 1 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.003 Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003) ([local](/mitre/techniques/T1556-003.md)) | Lnx Mac | 0 | 2 | 2 | 12 | Yes |
| &nbsp;&nbsp;↳ [.004 Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) ([local](/mitre/techniques/T1556-004.md)) | NetDev | 0 | 2 | 2 | 13 | Yes |
| &nbsp;&nbsp;↳ [.005 Reversible Encryption](https://attack.mitre.org/techniques/T1556/005) ([local](/mitre/techniques/T1556-005.md)) | Win | 0 | 0 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.006 Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006) ([local](/mitre/techniques/T1556-006.md)) | Win SaaS IaaS Lnx Mac Office IdP | 1 | 2 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.007 Hybrid Identity](https://attack.mitre.org/techniques/T1556/007) ([local](/mitre/techniques/T1556-007.md)) | Win SaaS IaaS Office IdP | 1 | 1 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.008 Network Provider DLL](https://attack.mitre.org/techniques/T1556/008) ([local](/mitre/techniques/T1556-008.md)) | Win | 0 | 0 | 3 | 9 | Yes |
| &nbsp;&nbsp;↳ [.009 Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009) ([local](/mitre/techniques/T1556-009.md)) | IaaS IdP | 2 | 0 | 1 | 14 | Yes |
| [T1574 Hijack Execution Flow](https://attack.mitre.org/techniques/T1574) ([local](/mitre/techniques/T1574.md)) | Lnx Mac Win | 0 | 8 | 10 | 18 | Yes |
| &nbsp;&nbsp;↳ [.001 DLL](https://attack.mitre.org/techniques/T1574/001) ([local](/mitre/techniques/T1574-001.md)) | Win | 32 | 67 | 5 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Dylib Hijacking](https://attack.mitre.org/techniques/T1574/004) ([local](/mitre/techniques/T1574-004.md)) | Mac | 0 | 1 | 1 | 13 | Yes |
| &nbsp;&nbsp;↳ [.005 Executable Installer File Permissions Weakness](https://attack.mitre.org/techniques/T1574/005) ([local](/mitre/techniques/T1574-005.md)) | Win | 1 | 0 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.006 Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006) ([local](/mitre/techniques/T1574-006.md)) | Lnx Mac | 3 | 6 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.007 Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007) ([local](/mitre/techniques/T1574-007.md)) | Win Mac Lnx | 0 | 3 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.008 Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008) ([local](/mitre/techniques/T1574-008.md)) | Win | 0 | 2 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.009 Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009) ([local](/mitre/techniques/T1574-009.md)) | Win | 0 | 2 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.010 Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010) ([local](/mitre/techniques/T1574-010.md)) | Win | 0 | 1 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.011 Services Registry Permissions Weakness](https://attack.mitre.org/techniques/T1574/011) ([local](/mitre/techniques/T1574-011.md)) | Win | 0 | 0 | 1 | 2 | Yes |
| &nbsp;&nbsp;↳ [.012 COR_PROFILER](https://attack.mitre.org/techniques/T1574/012) ([local](/mitre/techniques/T1574-012.md)) | Win | 1 | 1 | 3 | 9 | Yes |
| &nbsp;&nbsp;↳ [.013 KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013) ([local](/mitre/techniques/T1574-013.md)) | Win | 1 | 1 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014) ([local](/mitre/techniques/T1574-014.md)) | Win | 0 | 1 | 1 | 10 | Yes |
| [T1653 Power Settings](https://attack.mitre.org/techniques/T1653) ([local](/mitre/techniques/T1653.md)) | Win Lnx Mac NetDev | 0 | 2 | 1 | 4 | Yes |
| [T1668 Exclusive Control](https://attack.mitre.org/techniques/T1668) ([local](/mitre/techniques/T1668.md)) | Lnx Mac Win | 0 | 0 | 0 | 0 | Yes |
| [T1671 Cloud Application Integration](https://attack.mitre.org/techniques/T1671) ([local](/mitre/techniques/T1671.md)) | Office SaaS | 0 | 0 | 2 | 0 | Yes |

## Privilege Escalation
<a id="privilege-escalation"></a>

[`TA0004`](https://attack.mitre.org/tactics/TA0004/) ([local](/mitre/tactics/privilege-escalation.md)), 109 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1037 Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037) ([local](/mitre/techniques/T1037.md)) | Mac Win Lnx NetDev ESXi | 4 | 2 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.001 Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001) ([local](/mitre/techniques/T1037-001.md)) | Win | 2 | 4 | 1 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 Login Hook](https://attack.mitre.org/techniques/T1037/002) ([local](/mitre/techniques/T1037-002.md)) | Mac | 0 | 0 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.003 Network Logon Script](https://attack.mitre.org/techniques/T1037/003) ([local](/mitre/techniques/T1037-003.md)) | Win | 0 | 0 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.004 RC Scripts](https://attack.mitre.org/techniques/T1037/004) ([local](/mitre/techniques/T1037-004.md)) | Mac Lnx NetDev ESXi | 3 | 4 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.005 Startup Items](https://attack.mitre.org/techniques/T1037/005) ([local](/mitre/techniques/T1037-005.md)) | Mac | 0 | 1 | 1 | 7 | Yes |
| [T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) ([local](/mitre/techniques/T1053.md)) | Win Lnx Mac Cnt ESXi | 0 | 1 | 5 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 At](https://attack.mitre.org/techniques/T1053/002) ([local](/mitre/techniques/T1053-002.md)) | Win Lnx Mac | 3 | 3 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Cron](https://attack.mitre.org/techniques/T1053/003) ([local](/mitre/techniques/T1053-003.md)) | Lnx Mac ESXi | 3 | 12 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) | Win | 54 | 118 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.006 Systemd Timers](https://attack.mitre.org/techniques/T1053/006) ([local](/mitre/techniques/T1053-006.md)) | Lnx | 0 | 0 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.007 Container Orchestration Job](https://attack.mitre.org/techniques/T1053/007) ([local](/mitre/techniques/T1053-007.md)) | Cnt | 0 | 0 | 2 | 7 | Yes |
| [T1055 Process Injection](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) | Lnx Mac Win | 15 | 60 | 2 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) | Win | 9 | 56 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.002 Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002) ([local](/mitre/techniques/T1055-002.md)) | Win | 2 | 10 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.003 Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003) ([local](/mitre/techniques/T1055-003.md)) | Win | 0 | 4 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.004 Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004) ([local](/mitre/techniques/T1055-004.md)) | Win | 1 | 11 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.005 Thread Local Storage](https://attack.mitre.org/techniques/T1055/005) ([local](/mitre/techniques/T1055-005.md)) | Win | 0 | 2 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.008 Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008) ([local](/mitre/techniques/T1055-008.md)) | Lnx | 0 | 1 | 2 | 12 | Yes |
| &nbsp;&nbsp;↳ [.009 Proc Memory](https://attack.mitre.org/techniques/T1055/009) ([local](/mitre/techniques/T1055-009.md)) | Lnx | 0 | 0 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.011 Extra Window Memory Injection](https://attack.mitre.org/techniques/T1055/011) ([local](/mitre/techniques/T1055-011.md)) | Win | 0 | 2 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.012 Process Hollowing](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) | Win | 7 | 32 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.013 Process Doppelgänging](https://attack.mitre.org/techniques/T1055/013) ([local](/mitre/techniques/T1055-013.md)) | Win | 1 | 2 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.014 VDSO Hijacking](https://attack.mitre.org/techniques/T1055/014) ([local](/mitre/techniques/T1055-014.md)) | Lnx | 0 | 0 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.015 ListPlanting](https://attack.mitre.org/techniques/T1055/015) ([local](/mitre/techniques/T1055-015.md)) | Win | 0 | 1 | 1 | 1 | Yes |
| [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) ([local](/mitre/techniques/T1068.md)) | Cnt Lnx Mac Win | 22 | 19 | 5 | 21 | Yes |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) ([local](/mitre/techniques/T1078.md)) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 44 | 6 | 8 | 25 | Yes |
| &nbsp;&nbsp;↳ [.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001) ([local](/mitre/techniques/T1078-001.md)) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 4 | 2 | 2 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002) ([local](/mitre/techniques/T1078-002.md)) | ESXi Lnx Mac Win | 18 | 5 | 5 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003) ([local](/mitre/techniques/T1078-003.md)) | Lnx Mac Win Cnt NetDev ESXi | 12 | 5 | 4 | 19 | Yes |
| &nbsp;&nbsp;↳ [.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) ([local](/mitre/techniques/T1078-004.md)) | IaaS IdP Office SaaS | 9 | 3 | 7 | 24 | Yes |
| [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098) ([local](/mitre/techniques/T1098.md)) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 3 | 2 | 7 | 11 | Yes |
| &nbsp;&nbsp;↳ [.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001) ([local](/mitre/techniques/T1098-001.md)) | IaaS IdP SaaS | 1 | 1 | 5 | 15 | Yes |
| &nbsp;&nbsp;↳ [.002 Additional Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002) ([local](/mitre/techniques/T1098-002.md)) | Win Office | 3 | 0 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) ([local](/mitre/techniques/T1098-003.md)) | IaaS IdP Office SaaS | 3 | 0 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.004 SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004) ([local](/mitre/techniques/T1098-004.md)) | Lnx Mac IaaS NetDev ESXi | 3 | 3 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.005 Device Registration](https://attack.mitre.org/techniques/T1098/005) ([local](/mitre/techniques/T1098-005.md)) | Win IdP | 1 | 1 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.006 Additional Container Cluster Roles](https://attack.mitre.org/techniques/T1098/006) ([local](/mitre/techniques/T1098-006.md)) | Cnt | 0 | 0 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007) ([local](/mitre/techniques/T1098-007.md)) | Win Mac Lnx | 7 | 4 | 0 | 11 | Yes |
| [T1134 Access Token Manipulation](https://attack.mitre.org/techniques/T1134) ([local](/mitre/techniques/T1134.md)) | Win | 3 | 19 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.001 Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) ([local](/mitre/techniques/T1134-001.md)) | Win | 2 | 15 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Create Process with Token](https://attack.mitre.org/techniques/T1134/002) ([local](/mitre/techniques/T1134-002.md)) | Win | 2 | 11 | 2 | 7 | Yes |
| &nbsp;&nbsp;↳ [.003 Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) ([local](/mitre/techniques/T1134-003.md)) | Win | 2 | 3 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004) ([local](/mitre/techniques/T1134-004.md)) | Win | 0 | 4 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 SID-History Injection](https://attack.mitre.org/techniques/T1134/005) ([local](/mitre/techniques/T1134-005.md)) | Win | 0 | 2 | 1 | 13 | Yes |
| [T1484 Domain or Tenant Policy Modification](https://attack.mitre.org/techniques/T1484) ([local](/mitre/techniques/T1484.md)) | Win IdP | 0 | 0 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 Group Policy Modification](https://attack.mitre.org/techniques/T1484/001) ([local](/mitre/techniques/T1484-001.md)) | Win | 4 | 8 | 2 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Trust Modification](https://attack.mitre.org/techniques/T1484/002) ([local](/mitre/techniques/T1484-002.md)) | IdP Win | 2 | 1 | 2 | 0 | Yes |
| [T1543 Create or Modify System Process](https://attack.mitre.org/techniques/T1543) ([local](/mitre/techniques/T1543.md)) | Win Mac Lnx Cnt | 0 | 6 | 9 | 20 | Yes |
| &nbsp;&nbsp;↳ [.001 Launch Agent](https://attack.mitre.org/techniques/T1543/001) ([local](/mitre/techniques/T1543-001.md)) | Mac | 1 | 20 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Systemd Service](https://attack.mitre.org/techniques/T1543/002) ([local](/mitre/techniques/T1543-002.md)) | Lnx | 3 | 8 | 4 | 16 | Yes |
| &nbsp;&nbsp;↳ [.003 Windows Service](https://attack.mitre.org/techniques/T1543/003) ([local](/mitre/techniques/T1543-003.md)) | Win | 26 | 108 | 5 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Launch Daemon](https://attack.mitre.org/techniques/T1543/004) ([local](/mitre/techniques/T1543-004.md)) | Mac | 0 | 10 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.005 Container Service](https://attack.mitre.org/techniques/T1543/005) ([local](/mitre/techniques/T1543-005.md)) | Cnt | 0 | 0 | 2 | 5 | Yes |
| [T1546 Event Triggered Execution](https://attack.mitre.org/techniques/T1546) ([local](/mitre/techniques/T1546.md)) | Lnx Mac Win SaaS IaaS Office | 0 | 3 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.001 Change Default File Association](https://attack.mitre.org/techniques/T1546/001) ([local](/mitre/techniques/T1546-001.md)) | Win | 1 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Screensaver](https://attack.mitre.org/techniques/T1546/002) ([local](/mitre/techniques/T1546-002.md)) | Win | 0 | 1 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.003 Windows Management Instrumentation Event Subscription](https://attack.mitre.org/techniques/T1546/003) ([local](/mitre/techniques/T1546-003.md)) | Win | 10 | 13 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.004 Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004) ([local](/mitre/techniques/T1546-004.md)) | Lnx Mac | 1 | 4 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.005 Trap](https://attack.mitre.org/techniques/T1546/005) ([local](/mitre/techniques/T1546-005.md)) | Mac Lnx | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 LC_LOAD_DYLIB Addition](https://attack.mitre.org/techniques/T1546/006) ([local](/mitre/techniques/T1546-006.md)) | Mac | 0 | 0 | 3 | 13 | Yes |
| &nbsp;&nbsp;↳ [.007 Netsh Helper DLL](https://attack.mitre.org/techniques/T1546/007) ([local](/mitre/techniques/T1546-007.md)) | Win | 0 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.008 Accessibility Features](https://attack.mitre.org/techniques/T1546/008) ([local](/mitre/techniques/T1546-008.md)) | Win | 6 | 1 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.009 AppCert DLLs](https://attack.mitre.org/techniques/T1546/009) ([local](/mitre/techniques/T1546-009.md)) | Win | 0 | 1 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.010 AppInit DLLs](https://attack.mitre.org/techniques/T1546/010) ([local](/mitre/techniques/T1546-010.md)) | Win | 1 | 3 | 2 | 5 | Yes |
| &nbsp;&nbsp;↳ [.011 Application Shimming](https://attack.mitre.org/techniques/T1546/011) ([local](/mitre/techniques/T1546-011.md)) | Win | 1 | 3 | 2 | 2 | Yes |
| &nbsp;&nbsp;↳ [.012 Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012) ([local](/mitre/techniques/T1546-012.md)) | Win | 0 | 2 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.013 PowerShell Profile](https://attack.mitre.org/techniques/T1546/013) ([local](/mitre/techniques/T1546-013.md)) | Win | 1 | 0 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.014 Emond](https://attack.mitre.org/techniques/T1546/014) ([local](/mitre/techniques/T1546-014.md)) | Mac | 0 | 0 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.015 Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015) ([local](/mitre/techniques/T1546-015.md)) | Win | 1 | 11 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.016 Installer Packages](https://attack.mitre.org/techniques/T1546/016) ([local](/mitre/techniques/T1546-016.md)) | Lnx Win Mac | 0 | 1 | 0 | 7 | Yes |
| &nbsp;&nbsp;↳ [.017 Udev Rules](https://attack.mitre.org/techniques/T1546/017) ([local](/mitre/techniques/T1546-017.md)) | Lnx | 0 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.018 Python Startup Hooks](https://attack.mitre.org/techniques/T1546/018) ([local](/mitre/techniques/T1546-018.md)) | Lnx Mac Win | 0 | 0 | 0 | 0 | Yes |
| [T1547 Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547) ([local](/mitre/techniques/T1547.md)) | Lnx Mac Win NetDev | 1 | 5 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001) ([local](/mitre/techniques/T1547-001.md)) | Win | 55 | 194 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Authentication Package](https://attack.mitre.org/techniques/T1547/002) ([local](/mitre/techniques/T1547-002.md)) | Win | 0 | 1 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.003 Time Providers](https://attack.mitre.org/techniques/T1547/003) ([local](/mitre/techniques/T1547-003.md)) | Win | 0 | 0 | 2 | 10 | Yes |
| &nbsp;&nbsp;↳ [.004 Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547/004) ([local](/mitre/techniques/T1547-004.md)) | Win | 3 | 10 | 2 | 13 | Yes |
| &nbsp;&nbsp;↳ [.005 Security Support Provider](https://attack.mitre.org/techniques/T1547/005) ([local](/mitre/techniques/T1547-005.md)) | Win | 0 | 3 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.006 Kernel Modules and Extensions](https://attack.mitre.org/techniques/T1547/006) ([local](/mitre/techniques/T1547-006.md)) | Mac Lnx | 0 | 3 | 4 | 18 | Yes |
| &nbsp;&nbsp;↳ [.007 Re-opened Applications](https://attack.mitre.org/techniques/T1547/007) ([local](/mitre/techniques/T1547-007.md)) | Mac | 0 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.008 LSASS Driver](https://attack.mitre.org/techniques/T1547/008) ([local](/mitre/techniques/T1547-008.md)) | Win | 0 | 2 | 3 | 7 | Yes |
| &nbsp;&nbsp;↳ [.009 Shortcut Modification](https://attack.mitre.org/techniques/T1547/009) ([local](/mitre/techniques/T1547-009.md)) | Win | 4 | 25 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.010 Port Monitors](https://attack.mitre.org/techniques/T1547/010) ([local](/mitre/techniques/T1547-010.md)) | Win | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.012 Print Processors](https://attack.mitre.org/techniques/T1547/012) ([local](/mitre/techniques/T1547-012.md)) | Win | 1 | 2 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.013 XDG Autostart Entries](https://attack.mitre.org/techniques/T1547/013) ([local](/mitre/techniques/T1547-013.md)) | Lnx | 1 | 6 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.014 Active Setup](https://attack.mitre.org/techniques/T1547/014) ([local](/mitre/techniques/T1547-014.md)) | Win | 0 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.015 Login Items](https://attack.mitre.org/techniques/T1547/015) ([local](/mitre/techniques/T1547-015.md)) | Mac | 0 | 3 | 0 | 0 | Yes |
| [T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548) ([local](/mitre/techniques/T1548.md)) | Lnx Mac Win IaaS Office IdP | 1 | 1 | 8 | 22 | Yes |
| &nbsp;&nbsp;↳ [.001 Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001) ([local](/mitre/techniques/T1548-001.md)) | Lnx Mac | 0 | 2 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002) ([local](/mitre/techniques/T1548-002.md)) | Win | 11 | 49 | 4 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003) ([local](/mitre/techniques/T1548-003.md)) | Lnx Mac | 0 | 3 | 3 | 13 | Yes |
| &nbsp;&nbsp;↳ [.004 Elevated Execution with Prompt](https://attack.mitre.org/techniques/T1548/004) ([local](/mitre/techniques/T1548-004.md)) | Mac | 0 | 1 | 1 | 11 | Yes |
| &nbsp;&nbsp;↳ [.005 Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005) ([local](/mitre/techniques/T1548-005.md)) | IaaS Office IdP | 0 | 0 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.006 TCC Manipulation](https://attack.mitre.org/techniques/T1548/006) ([local](/mitre/techniques/T1548-006.md)) | Mac | 0 | 1 | 3 | 17 | Yes |
| [T1574 Hijack Execution Flow](https://attack.mitre.org/techniques/T1574) ([local](/mitre/techniques/T1574.md)) | Lnx Mac Win | 0 | 8 | 10 | 18 | Yes |
| &nbsp;&nbsp;↳ [.001 DLL](https://attack.mitre.org/techniques/T1574/001) ([local](/mitre/techniques/T1574-001.md)) | Win | 32 | 67 | 5 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Dylib Hijacking](https://attack.mitre.org/techniques/T1574/004) ([local](/mitre/techniques/T1574-004.md)) | Mac | 0 | 1 | 1 | 13 | Yes |
| &nbsp;&nbsp;↳ [.005 Executable Installer File Permissions Weakness](https://attack.mitre.org/techniques/T1574/005) ([local](/mitre/techniques/T1574-005.md)) | Win | 1 | 0 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.006 Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006) ([local](/mitre/techniques/T1574-006.md)) | Lnx Mac | 3 | 6 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.007 Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007) ([local](/mitre/techniques/T1574-007.md)) | Win Mac Lnx | 0 | 3 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.008 Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008) ([local](/mitre/techniques/T1574-008.md)) | Win | 0 | 2 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.009 Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009) ([local](/mitre/techniques/T1574-009.md)) | Win | 0 | 2 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.010 Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010) ([local](/mitre/techniques/T1574-010.md)) | Win | 0 | 1 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.011 Services Registry Permissions Weakness](https://attack.mitre.org/techniques/T1574/011) ([local](/mitre/techniques/T1574-011.md)) | Win | 0 | 0 | 1 | 2 | Yes |
| &nbsp;&nbsp;↳ [.012 COR_PROFILER](https://attack.mitre.org/techniques/T1574/012) ([local](/mitre/techniques/T1574-012.md)) | Win | 1 | 1 | 3 | 9 | Yes |
| &nbsp;&nbsp;↳ [.013 KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013) ([local](/mitre/techniques/T1574-013.md)) | Win | 1 | 1 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014) ([local](/mitre/techniques/T1574-014.md)) | Win | 0 | 1 | 1 | 10 | Yes |
| [T1611 Escape to Host](https://attack.mitre.org/techniques/T1611) ([local](/mitre/techniques/T1611.md)) | Win Lnx Cnt ESXi | 1 | 4 | 5 | 19 | Yes |

## Defense Evasion
<a id="defense-evasion"></a>

[`TA0005`](https://attack.mitre.org/tactics/TA0005/) ([local](/mitre/tactics/stealth.md)), 215 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1006 Direct Volume Access](https://attack.mitre.org/techniques/T1006) ([local](/mitre/techniques/T1006.md)) | NetDev Win | 2 | 1 | 2 | 0 | Yes |
| [T1014 Rootkit](https://attack.mitre.org/techniques/T1014) ([local](/mitre/techniques/T1014.md)) | Lnx Mac Win | 6 | 24 | 0 | 0 | Yes |
| [T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) | ESXi Lnx Mac NetDev Win | 18 | 130 | 4 | 8 | Yes |
| &nbsp;&nbsp;↳ [.001 Binary Padding](https://attack.mitre.org/techniques/T1027/001) ([local](/mitre/techniques/T1027-001.md)) | Lnx Win Mac | 8 | 20 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Software Packing](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) | Lnx Mac Win | 23 | 72 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.003 Steganography](https://attack.mitre.org/techniques/T1027/003) ([local](/mitre/techniques/T1027-003.md)) | Lnx Mac Win | 8 | 19 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Compile After Delivery](https://attack.mitre.org/techniques/T1027/004) ([local](/mitre/techniques/T1027-004.md)) | Lnx Mac Win | 4 | 6 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005) ([local](/mitre/techniques/T1027-005.md)) | Lnx Mac Win | 7 | 9 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 HTML Smuggling](https://attack.mitre.org/techniques/T1027/006) ([local](/mitre/techniques/T1027-006.md)) | Win Lnx Mac | 1 | 2 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.007 Dynamic API Resolution](https://attack.mitre.org/techniques/T1027/007) ([local](/mitre/techniques/T1027-007.md)) | Win | 2 | 13 | 0 | 4 | Yes |
| &nbsp;&nbsp;↳ [.008 Stripped Payloads](https://attack.mitre.org/techniques/T1027/008) ([local](/mitre/techniques/T1027-008.md)) | Mac Lnx Win NetDev | 0 | 2 | 0 | 4 | Yes |
| &nbsp;&nbsp;↳ [.009 Embedded Payloads](https://attack.mitre.org/techniques/T1027/009) ([local](/mitre/techniques/T1027-009.md)) | Lnx Mac Win | 3 | 18 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) | Lnx Mac Win | 28 | 31 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.011 Fileless Storage](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) | Win Lnx | 2 | 27 | 1 | 1 | Yes |
| &nbsp;&nbsp;↳ [.012 LNK Icon Smuggling](https://attack.mitre.org/techniques/T1027/012) ([local](/mitre/techniques/T1027-012.md)) | Win | 3 | 1 | 2 | 2 | Yes |
| &nbsp;&nbsp;↳ [.013 Encrypted/Encoded File](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) | Lnx Mac Win | 37 | 172 | 2 | 1 | Yes |
| &nbsp;&nbsp;↳ [.014 Polymorphic Code](https://attack.mitre.org/techniques/T1027/014) ([local](/mitre/techniques/T1027-014.md)) | Win Mac Lnx | 0 | 1 | 2 | 1 | Yes |
| &nbsp;&nbsp;↳ [.015 Compression](https://attack.mitre.org/techniques/T1027/015) ([local](/mitre/techniques/T1027-015.md)) | Lnx Win Mac | 7 | 24 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.016 Junk Code Insertion](https://attack.mitre.org/techniques/T1027/016) ([local](/mitre/techniques/T1027-016.md)) | Lnx Mac Win | 5 | 14 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.017 SVG Smuggling](https://attack.mitre.org/techniques/T1027/017) ([local](/mitre/techniques/T1027-017.md)) | Lnx Mac Win | 0 | 0 | 1 | 0 | Yes |
| [T1036 Masquerading](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) | Cnt ESXi Lnx Mac Win | 20 | 31 | 8 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001) ([local](/mitre/techniques/T1036-001.md)) | Win Mac | 2 | 7 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.002 Right-to-Left Override](https://attack.mitre.org/techniques/T1036/002) ([local](/mitre/techniques/T1036-002.md)) | Lnx Mac Win | 5 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Rename Legitimate Utilities](https://attack.mitre.org/techniques/T1036/003) ([local](/mitre/techniques/T1036-003.md)) | Lnx Mac Win | 6 | 4 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) | Lnx Mac Win | 22 | 61 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Match Legitimate Resource Name or Location](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) | Cnt ESXi Lnx Mac Win | 59 | 130 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.006 Space after Filename](https://attack.mitre.org/techniques/T1036/006) ([local](/mitre/techniques/T1036-006.md)) | Lnx Mac | 1 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.007 Double File Extension](https://attack.mitre.org/techniques/T1036/007) ([local](/mitre/techniques/T1036-007.md)) | Win | 2 | 3 | 2 | 6 | Yes |
| &nbsp;&nbsp;↳ [.008 Masquerade File Type](https://attack.mitre.org/techniques/T1036/008) ([local](/mitre/techniques/T1036-008.md)) | Lnx Mac Win | 3 | 11 | 3 | 5 | Yes |
| &nbsp;&nbsp;↳ [.009 Break Process Trees](https://attack.mitre.org/techniques/T1036/009) ([local](/mitre/techniques/T1036-009.md)) | Lnx Mac | 0 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.010 Masquerade Account Name](https://attack.mitre.org/techniques/T1036/010) ([local](/mitre/techniques/T1036-010.md)) | Lnx Mac Win SaaS IaaS Cnt Office IdP | 4 | 2 | 2 | 5 | Yes |
| &nbsp;&nbsp;↳ [.011 Overwrite Process Arguments](https://attack.mitre.org/techniques/T1036/011) ([local](/mitre/techniques/T1036-011.md)) | Lnx | 0 | 1 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.012 Browser Fingerprint](https://attack.mitre.org/techniques/T1036/012) ([local](/mitre/techniques/T1036-012.md)) | Lnx Mac Win | 0 | 1 | 1 | 0 | Yes |
| [T1055 Process Injection](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) | Lnx Mac Win | 15 | 60 | 2 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) | Win | 9 | 56 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.002 Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002) ([local](/mitre/techniques/T1055-002.md)) | Win | 2 | 10 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.003 Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003) ([local](/mitre/techniques/T1055-003.md)) | Win | 0 | 4 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.004 Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004) ([local](/mitre/techniques/T1055-004.md)) | Win | 1 | 11 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.005 Thread Local Storage](https://attack.mitre.org/techniques/T1055/005) ([local](/mitre/techniques/T1055-005.md)) | Win | 0 | 2 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.008 Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008) ([local](/mitre/techniques/T1055-008.md)) | Lnx | 0 | 1 | 2 | 12 | Yes |
| &nbsp;&nbsp;↳ [.009 Proc Memory](https://attack.mitre.org/techniques/T1055/009) ([local](/mitre/techniques/T1055-009.md)) | Lnx | 0 | 0 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.011 Extra Window Memory Injection](https://attack.mitre.org/techniques/T1055/011) ([local](/mitre/techniques/T1055-011.md)) | Win | 0 | 2 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.012 Process Hollowing](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) | Win | 7 | 32 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.013 Process Doppelgänging](https://attack.mitre.org/techniques/T1055/013) ([local](/mitre/techniques/T1055-013.md)) | Win | 1 | 2 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.014 VDSO Hijacking](https://attack.mitre.org/techniques/T1055/014) ([local](/mitre/techniques/T1055-014.md)) | Lnx | 0 | 0 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.015 ListPlanting](https://attack.mitre.org/techniques/T1055/015) ([local](/mitre/techniques/T1055-015.md)) | Win | 0 | 1 | 1 | 1 | Yes |
| [T1070 Indicator Removal](https://attack.mitre.org/techniques/T1070) ([local](/mitre/techniques/T1070.md)) | Cnt ESXi Lnx Mac NetDev Office Win | 4 | 25 | 3 | 20 | Yes |
| &nbsp;&nbsp;↳ [.001 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001) ([local](/mitre/techniques/T1070-001.md)) | Win | 13 | 26 | 3 | 21 | Yes |
| &nbsp;&nbsp;↳ [.002 Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1070/002) ([local](/mitre/techniques/T1070-002.md)) | Lnx Mac | 4 | 4 | 3 | 21 | Yes |
| &nbsp;&nbsp;↳ [.003 Clear Command History](https://attack.mitre.org/techniques/T1070/003) ([local](/mitre/techniques/T1070-003.md)) | ESXi Lnx Mac NetDev Win | 8 | 3 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.004 File Deletion](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) | ESXi Lnx Mac Win | 46 | 239 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Network Share Connection Removal](https://attack.mitre.org/techniques/T1070/005) ([local](/mitre/techniques/T1070-005.md)) | Win | 1 | 4 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 Timestomp](https://attack.mitre.org/techniques/T1070/006) ([local](/mitre/techniques/T1070-006.md)) | ESXi Lnx Mac Win | 11 | 42 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.007 Clear Network Connection History and Configurations](https://attack.mitre.org/techniques/T1070/007) ([local](/mitre/techniques/T1070-007.md)) | Lnx Mac Win NetDev | 2 | 1 | 2 | 10 | Yes |
| &nbsp;&nbsp;↳ [.008 Clear Mailbox Data](https://attack.mitre.org/techniques/T1070/008) ([local](/mitre/techniques/T1070-008.md)) | Lnx Mac Office Win | 2 | 2 | 3 | 22 | Yes |
| &nbsp;&nbsp;↳ [.009 Clear Persistence](https://attack.mitre.org/techniques/T1070/009) ([local](/mitre/techniques/T1070-009.md)) | ESXi Lnx Win Mac | 0 | 15 | 2 | 10 | Yes |
| &nbsp;&nbsp;↳ [.010 Relocate Malware](https://attack.mitre.org/techniques/T1070/010) ([local](/mitre/techniques/T1070-010.md)) | Lnx Mac Win NetDev | 0 | 0 | 0 | 3 | Yes |
| [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078) ([local](/mitre/techniques/T1078.md)) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 44 | 6 | 8 | 25 | Yes |
| &nbsp;&nbsp;↳ [.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001) ([local](/mitre/techniques/T1078-001.md)) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 4 | 2 | 2 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002) ([local](/mitre/techniques/T1078-002.md)) | ESXi Lnx Mac Win | 18 | 5 | 5 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Local Accounts](https://attack.mitre.org/techniques/T1078/003) ([local](/mitre/techniques/T1078-003.md)) | Lnx Mac Win Cnt NetDev ESXi | 12 | 5 | 4 | 19 | Yes |
| &nbsp;&nbsp;↳ [.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) ([local](/mitre/techniques/T1078-004.md)) | IaaS IdP Office SaaS | 9 | 3 | 7 | 24 | Yes |
| [T1112 Modify Registry](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) | Win | 29 | 136 | 1 | 3 | Yes |
| [T1127 Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127) ([local](/mitre/techniques/T1127.md)) | Win | 0 | 0 | 3 | 8 | Yes |
| &nbsp;&nbsp;↳ [.001 MSBuild](https://attack.mitre.org/techniques/T1127/001) ([local](/mitre/techniques/T1127-001.md)) | Win | 0 | 2 | 2 | 5 | Yes |
| &nbsp;&nbsp;↳ [.002 ClickOnce](https://attack.mitre.org/techniques/T1127/002) ([local](/mitre/techniques/T1127-002.md)) | Win | 0 | 0 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.003 JamPlus](https://attack.mitre.org/techniques/T1127/003) ([local](/mitre/techniques/T1127-003.md)) | Win | 0 | 0 | 2 | 0 | Yes |
| [T1134 Access Token Manipulation](https://attack.mitre.org/techniques/T1134) ([local](/mitre/techniques/T1134.md)) | Win | 3 | 19 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.001 Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001) ([local](/mitre/techniques/T1134-001.md)) | Win | 2 | 15 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Create Process with Token](https://attack.mitre.org/techniques/T1134/002) ([local](/mitre/techniques/T1134-002.md)) | Win | 2 | 11 | 2 | 7 | Yes |
| &nbsp;&nbsp;↳ [.003 Make and Impersonate Token](https://attack.mitre.org/techniques/T1134/003) ([local](/mitre/techniques/T1134-003.md)) | Win | 2 | 3 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004) ([local](/mitre/techniques/T1134-004.md)) | Win | 0 | 4 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 SID-History Injection](https://attack.mitre.org/techniques/T1134/005) ([local](/mitre/techniques/T1134-005.md)) | Win | 0 | 2 | 1 | 13 | Yes |
| [T1140 Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) ([local](/mitre/techniques/T1140.md)) | ESXi Lnx Mac Win | 38 | 274 | 0 | 0 | Yes |
| [T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197) ([local](/mitre/techniques/T1197.md)) | Win | 5 | 8 | 3 | 14 | Yes |
| [T1202 Indirect Command Execution](https://attack.mitre.org/techniques/T1202) ([local](/mitre/techniques/T1202.md)) | Win | 2 | 2 | 0 | 0 | Yes |
| [T1205 Traffic Signaling](https://attack.mitre.org/techniques/T1205) ([local](/mitre/techniques/T1205.md)) | Lnx Mac NetDev Win | 3 | 16 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.001 Port Knocking](https://attack.mitre.org/techniques/T1205/001) ([local](/mitre/techniques/T1205-001.md)) | Lnx Mac Win NetDev | 2 | 4 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Socket Filters](https://attack.mitre.org/techniques/T1205/002) ([local](/mitre/techniques/T1205-002.md)) | Lnx Mac Win | 0 | 4 | 1 | 2 | Yes |
| [T1207 Rogue Domain Controller](https://attack.mitre.org/techniques/T1207) ([local](/mitre/techniques/T1207.md)) | Win | 0 | 1 | 0 | 0 | Yes |
| [T1211 Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) ([local](/mitre/techniques/T1211.md)) | Lnx Win Mac SaaS IaaS | 2 | 0 | 4 | 22 | Yes |
| [T1216 System Script Proxy Execution](https://attack.mitre.org/techniques/T1216) ([local](/mitre/techniques/T1216.md)) | Win | 0 | 0 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.001 PubPrn](https://attack.mitre.org/techniques/T1216/001) ([local](/mitre/techniques/T1216-001.md)) | Win | 1 | 0 | 2 | 6 | Yes |
| &nbsp;&nbsp;↳ [.002 SyncAppvPublishingServer](https://attack.mitre.org/techniques/T1216/002) ([local](/mitre/techniques/T1216-002.md)) | Win | 0 | 0 | 1 | 4 | Yes |
| [T1218 System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218) ([local](/mitre/techniques/T1218.md)) | Win Lnx Mac | 2 | 0 | 6 | 20 | Yes |
| &nbsp;&nbsp;↳ [.001 Compiled HTML File](https://attack.mitre.org/techniques/T1218/001) ([local](/mitre/techniques/T1218-001.md)) | Win | 5 | 1 | 2 | 10 | Yes |
| &nbsp;&nbsp;↳ [.002 Control Panel](https://attack.mitre.org/techniques/T1218/002) ([local](/mitre/techniques/T1218-002.md)) | Win | 0 | 2 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 CMSTP](https://attack.mitre.org/techniques/T1218/003) ([local](/mitre/techniques/T1218-003.md)) | Win | 2 | 2 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.004 InstallUtil](https://attack.mitre.org/techniques/T1218/004) ([local](/mitre/techniques/T1218-004.md)) | Win | 2 | 4 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.005 Mshta](https://attack.mitre.org/techniques/T1218/005) ([local](/mitre/techniques/T1218-005.md)) | Win | 17 | 11 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.007 Msiexec](https://attack.mitre.org/techniques/T1218/007) ([local](/mitre/techniques/T1218-007.md)) | Win | 6 | 21 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.008 Odbcconf](https://attack.mitre.org/techniques/T1218/008) ([local](/mitre/techniques/T1218-008.md)) | Win | 1 | 2 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.009 Regsvcs/Regasm](https://attack.mitre.org/techniques/T1218/009) ([local](/mitre/techniques/T1218-009.md)) | Win | 0 | 1 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010) ([local](/mitre/techniques/T1218-010.md)) | Win | 11 | 23 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.011 Rundll32](https://attack.mitre.org/techniques/T1218/011) ([local](/mitre/techniques/T1218-011.md)) | Win | 26 | 69 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.012 Verclsid](https://attack.mitre.org/techniques/T1218/012) ([local](/mitre/techniques/T1218-012.md)) | Win | 0 | 1 | 3 | 16 | Yes |
| &nbsp;&nbsp;↳ [.013 Mavinject](https://attack.mitre.org/techniques/T1218/013) ([local](/mitre/techniques/T1218-013.md)) | Win | 0 | 1 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.014 MMC](https://attack.mitre.org/techniques/T1218/014) ([local](/mitre/techniques/T1218-014.md)) | Win | 1 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.015 Electron Applications](https://attack.mitre.org/techniques/T1218/015) ([local](/mitre/techniques/T1218-015.md)) | Lnx Mac Win | 0 | 1 | 3 | 18 | Yes |
| [T1220 XSL Script Processing](https://attack.mitre.org/techniques/T1220) ([local](/mitre/techniques/T1220.md)) | Win | 2 | 1 | 1 | 6 | Yes |
| [T1221 Template Injection](https://attack.mitre.org/techniques/T1221) ([local](/mitre/techniques/T1221.md)) | Win | 7 | 2 | 4 | 14 | Yes |
| [T1222 File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222) ([local](/mitre/techniques/T1222.md)) | ESXi Lnx Mac Win | 0 | 1 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.001 Windows File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/001) ([local](/mitre/techniques/T1222-001.md)) | Win | 2 | 9 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.002 Linux and Mac File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222/002) ([local](/mitre/techniques/T1222-002.md)) | Mac Lnx | 3 | 10 | 2 | 11 | Yes |
| [T1480 Execution Guardrails](https://attack.mitre.org/techniques/T1480) ([local](/mitre/techniques/T1480.md)) | ESXi Lnx Mac Win | 3 | 33 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Environmental Keying](https://attack.mitre.org/techniques/T1480/001) ([local](/mitre/techniques/T1480-001.md)) | Lnx Win Mac | 2 | 8 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Mutual Exclusion](https://attack.mitre.org/techniques/T1480/002) ([local](/mitre/techniques/T1480-002.md)) | Lnx Mac Win | 1 | 15 | 1 | 0 | Yes |
| [T1484 Domain or Tenant Policy Modification](https://attack.mitre.org/techniques/T1484) ([local](/mitre/techniques/T1484.md)) | Win IdP | 0 | 0 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 Group Policy Modification](https://attack.mitre.org/techniques/T1484/001) ([local](/mitre/techniques/T1484-001.md)) | Win | 4 | 8 | 2 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Trust Modification](https://attack.mitre.org/techniques/T1484/002) ([local](/mitre/techniques/T1484-002.md)) | IdP Win | 2 | 1 | 2 | 0 | Yes |
| [T1497 Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) ([local](/mitre/techniques/T1497.md)) | Lnx Mac Win | 3 | 22 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 System Checks](https://attack.mitre.org/techniques/T1497/001) ([local](/mitre/techniques/T1497-001.md)) | Lnx Mac Win | 5 | 59 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 User Activity Based Checks](https://attack.mitre.org/techniques/T1497/002) ([local](/mitre/techniques/T1497-002.md)) | Lnx Win Mac | 2 | 3 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Time Based Checks](https://attack.mitre.org/techniques/T1497/003) ([local](/mitre/techniques/T1497-003.md)) | Lnx Mac Win | 0 | 45 | 0 | 0 | Yes |
| [T1535 Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535) ([local](/mitre/techniques/T1535.md)) | IaaS | 0 | 0 | 1 | 1 | Yes |
| [T1542 Pre-OS Boot](https://attack.mitre.org/techniques/T1542) ([local](/mitre/techniques/T1542.md)) | Lnx NetDev Win Mac | 0 | 0 | 5 | 19 | Yes |
| &nbsp;&nbsp;↳ [.001 System Firmware](https://attack.mitre.org/techniques/T1542/001) ([local](/mitre/techniques/T1542-001.md)) | Win NetDev | 0 | 3 | 3 | 17 | Yes |
| &nbsp;&nbsp;↳ [.002 Component Firmware](https://attack.mitre.org/techniques/T1542/002) ([local](/mitre/techniques/T1542-002.md)) | Win Lnx Mac | 1 | 1 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Bootkit](https://attack.mitre.org/techniques/T1542/003) ([local](/mitre/techniques/T1542-003.md)) | Lnx Win | 3 | 6 | 2 | 18 | Yes |
| &nbsp;&nbsp;↳ [.004 ROMMONkit](https://attack.mitre.org/techniques/T1542/004) ([local](/mitre/techniques/T1542-004.md)) | NetDev | 0 | 0 | 3 | 19 | Yes |
| &nbsp;&nbsp;↳ [.005 TFTP Boot](https://attack.mitre.org/techniques/T1542/005) ([local](/mitre/techniques/T1542-005.md)) | NetDev | 0 | 0 | 6 | 23 | Yes |
| [T1548 Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548) ([local](/mitre/techniques/T1548.md)) | Lnx Mac Win IaaS Office IdP | 1 | 1 | 8 | 22 | Yes |
| &nbsp;&nbsp;↳ [.001 Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001) ([local](/mitre/techniques/T1548-001.md)) | Lnx Mac | 0 | 2 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002) ([local](/mitre/techniques/T1548-002.md)) | Win | 11 | 49 | 4 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003) ([local](/mitre/techniques/T1548-003.md)) | Lnx Mac | 0 | 3 | 3 | 13 | Yes |
| &nbsp;&nbsp;↳ [.004 Elevated Execution with Prompt](https://attack.mitre.org/techniques/T1548/004) ([local](/mitre/techniques/T1548-004.md)) | Mac | 0 | 1 | 1 | 11 | Yes |
| &nbsp;&nbsp;↳ [.005 Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005) ([local](/mitre/techniques/T1548-005.md)) | IaaS Office IdP | 0 | 0 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.006 TCC Manipulation](https://attack.mitre.org/techniques/T1548/006) ([local](/mitre/techniques/T1548-006.md)) | Mac | 0 | 1 | 3 | 17 | Yes |
| [T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550) ([local](/mitre/techniques/T1550.md)) | Win SaaS IaaS Cnt IdP Office Lnx | 0 | 1 | 7 | 7 | Yes |
| &nbsp;&nbsp;↳ [.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001) ([local](/mitre/techniques/T1550-001.md)) | SaaS Cnt IaaS Office IdP | 2 | 2 | 5 | 15 | Yes |
| &nbsp;&nbsp;↳ [.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002) ([local](/mitre/techniques/T1550-002.md)) | Win | 11 | 8 | 4 | 8 | Yes |
| &nbsp;&nbsp;↳ [.003 Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) ([local](/mitre/techniques/T1550-003.md)) | Win | 3 | 3 | 4 | 11 | Yes |
| &nbsp;&nbsp;↳ [.004 Web Session Cookie](https://attack.mitre.org/techniques/T1550/004) ([local](/mitre/techniques/T1550-004.md)) | SaaS IaaS Office | 1 | 0 | 1 | 3 | Yes |
| [T1553 Subvert Trust Controls](https://attack.mitre.org/techniques/T1553) ([local](/mitre/techniques/T1553.md)) | Win Mac Lnx | 1 | 0 | 5 | 20 | Yes |
| &nbsp;&nbsp;↳ [.001 Gatekeeper Bypass](https://attack.mitre.org/techniques/T1553/001) ([local](/mitre/techniques/T1553-001.md)) | Mac | 0 | 6 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.002 Code Signing](https://attack.mitre.org/techniques/T1553/002) ([local](/mitre/techniques/T1553-002.md)) | Mac Win | 26 | 52 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 SIP and Trust Provider Hijacking](https://attack.mitre.org/techniques/T1553/003) ([local](/mitre/techniques/T1553-003.md)) | Win | 0 | 0 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.004 Install Root Certificate](https://attack.mitre.org/techniques/T1553/004) ([local](/mitre/techniques/T1553-004.md)) | Lnx Mac Win | 0 | 4 | 2 | 6 | Yes |
| &nbsp;&nbsp;↳ [.005 Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005) ([local](/mitre/techniques/T1553-005.md)) | Win | 3 | 2 | 2 | 6 | Yes |
| &nbsp;&nbsp;↳ [.006 Code Signing Policy Modification](https://attack.mitre.org/techniques/T1553/006) ([local](/mitre/techniques/T1553-006.md)) | Win Mac | 2 | 3 | 3 | 13 | Yes |
| [T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556) ([local](/mitre/techniques/T1556.md)) | Win Lnx Mac NetDev IaaS SaaS Office IdP | 1 | 3 | 9 | 17 | Yes |
| &nbsp;&nbsp;↳ [.001 Domain Controller Authentication](https://attack.mitre.org/techniques/T1556/001) ([local](/mitre/techniques/T1556-001.md)) | Win | 1 | 1 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 Password Filter DLL](https://attack.mitre.org/techniques/T1556/002) ([local](/mitre/techniques/T1556-002.md)) | Win | 2 | 1 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.003 Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003) ([local](/mitre/techniques/T1556-003.md)) | Lnx Mac | 0 | 2 | 2 | 12 | Yes |
| &nbsp;&nbsp;↳ [.004 Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) ([local](/mitre/techniques/T1556-004.md)) | NetDev | 0 | 2 | 2 | 13 | Yes |
| &nbsp;&nbsp;↳ [.005 Reversible Encryption](https://attack.mitre.org/techniques/T1556/005) ([local](/mitre/techniques/T1556-005.md)) | Win | 0 | 0 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.006 Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006) ([local](/mitre/techniques/T1556-006.md)) | Win SaaS IaaS Lnx Mac Office IdP | 1 | 2 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.007 Hybrid Identity](https://attack.mitre.org/techniques/T1556/007) ([local](/mitre/techniques/T1556-007.md)) | Win SaaS IaaS Office IdP | 1 | 1 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.008 Network Provider DLL](https://attack.mitre.org/techniques/T1556/008) ([local](/mitre/techniques/T1556-008.md)) | Win | 0 | 0 | 3 | 9 | Yes |
| &nbsp;&nbsp;↳ [.009 Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009) ([local](/mitre/techniques/T1556-009.md)) | IaaS IdP | 2 | 0 | 1 | 14 | Yes |
| [T1562 Impair Defenses](https://attack.mitre.org/techniques/T1562) ([local](/mitre/techniques/T1562.md)) | Win IaaS Lnx Mac Cnt NetDev IdP Office ESXi | 2 | 3 | 7 | 16 | Yes |
| &nbsp;&nbsp;↳ [.001 Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001) ([local](/mitre/techniques/T1562-001.md)) | Cnt IaaS Lnx Mac NetDev Win | 30 | 71 | 5 | 13 | Yes |
| &nbsp;&nbsp;↳ [.002 Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002) ([local](/mitre/techniques/T1562-002.md)) | Win | 2 | 1 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.003 Impair Command History Logging](https://attack.mitre.org/techniques/T1562/003) ([local](/mitre/techniques/T1562-003.md)) | ESXi Lnx Mac NetDev Win | 4 | 4 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.004 Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004) ([local](/mitre/techniques/T1562-004.md)) | ESXi Lnx Mac NetDev Win | 17 | 24 | 4 | 13 | Yes |
| &nbsp;&nbsp;↳ [.006 Indicator Blocking](https://attack.mitre.org/techniques/T1562/006) ([local](/mitre/techniques/T1562-006.md)) | Win Mac Lnx ESXi | 2 | 8 | 3 | 17 | Yes |
| &nbsp;&nbsp;↳ [.007 Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007) ([local](/mitre/techniques/T1562-007.md)) | IaaS | 0 | 1 | 2 | 6 | Yes |
| &nbsp;&nbsp;↳ [.008 Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008) ([local](/mitre/techniques/T1562-008.md)) | IaaS SaaS Office IdP | 1 | 1 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.009 Safe Mode Boot](https://attack.mitre.org/techniques/T1562/009) ([local](/mitre/techniques/T1562-009.md)) | Win | 0 | 7 | 2 | 13 | Yes |
| &nbsp;&nbsp;↳ [.010 Downgrade Attack](https://attack.mitre.org/techniques/T1562/010) ([local](/mitre/techniques/T1562-010.md)) | Win Lnx Mac | 0 | 2 | 2 | 7 | Yes |
| &nbsp;&nbsp;↳ [.011 Spoof Security Alerting](https://attack.mitre.org/techniques/T1562/011) ([local](/mitre/techniques/T1562-011.md)) | Win Mac Lnx | 0 | 0 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.012 Disable or Modify Linux Audit System](https://attack.mitre.org/techniques/T1562/012) ([local](/mitre/techniques/T1562-012.md)) | Lnx | 0 | 1 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.013 Disable or Modify Network Device Firewall](https://attack.mitre.org/techniques/T1562/013) ([local](/mitre/techniques/T1562-013.md)) | NetDev | 1 | 1 | 3 | 0 | Yes |
| [T1564 Hide Artifacts](https://attack.mitre.org/techniques/T1564) ([local](/mitre/techniques/T1564.md)) | Lnx Office Win Mac ESXi | 0 | 5 | 4 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001) ([local](/mitre/techniques/T1564-001.md)) | Lnx Win Mac | 12 | 45 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Hidden Users](https://attack.mitre.org/techniques/T1564/002) ([local](/mitre/techniques/T1564-002.md)) | Mac Win Lnx | 2 | 1 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.003 Hidden Window](https://attack.mitre.org/techniques/T1564/003) ([local](/mitre/techniques/T1564-003.md)) | Lnx Mac Win | 16 | 38 | 2 | 3 | Yes |
| &nbsp;&nbsp;↳ [.004 NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004) ([local](/mitre/techniques/T1564-004.md)) | Win | 1 | 15 | 1 | 6 | Yes |
| &nbsp;&nbsp;↳ [.005 Hidden File System](https://attack.mitre.org/techniques/T1564/005) ([local](/mitre/techniques/T1564-005.md)) | Lnx Mac Win | 2 | 4 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.006 Run Virtual Instance](https://attack.mitre.org/techniques/T1564/006) ([local](/mitre/techniques/T1564-006.md)) | Lnx Mac Win ESXi | 0 | 3 | 3 | 7 | Yes |
| &nbsp;&nbsp;↳ [.007 VBA Stomping](https://attack.mitre.org/techniques/T1564/007) ([local](/mitre/techniques/T1564-007.md)) | Lnx Win Mac | 0 | 0 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.008 Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008) ([local](/mitre/techniques/T1564-008.md)) | Win Lnx Mac Office | 2 | 0 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.009 Resource Forking](https://attack.mitre.org/techniques/T1564/009) ([local](/mitre/techniques/T1564-009.md)) | Mac | 0 | 2 | 1 | 13 | Yes |
| &nbsp;&nbsp;↳ [.010 Process Argument Spoofing](https://attack.mitre.org/techniques/T1564/010) ([local](/mitre/techniques/T1564-010.md)) | Win | 0 | 2 | 0 | 3 | Yes |
| &nbsp;&nbsp;↳ [.011 Ignore Process Interrupts](https://attack.mitre.org/techniques/T1564/011) ([local](/mitre/techniques/T1564-011.md)) | Lnx Mac Win | 2 | 4 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.012 File/Path Exclusions](https://attack.mitre.org/techniques/T1564/012) ([local](/mitre/techniques/T1564-012.md)) | Lnx Mac Win | 1 | 0 | 2 | 1 | Yes |
| &nbsp;&nbsp;↳ [.013 Bind Mounts](https://attack.mitre.org/techniques/T1564/013) ([local](/mitre/techniques/T1564-013.md)) | Lnx | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.014 Extended Attributes](https://attack.mitre.org/techniques/T1564/014) ([local](/mitre/techniques/T1564-014.md)) | Lnx Mac | 0 | 0 | 1 | 0 | Yes |
| [T1574 Hijack Execution Flow](https://attack.mitre.org/techniques/T1574) ([local](/mitre/techniques/T1574.md)) | Lnx Mac Win | 0 | 8 | 10 | 18 | Yes |
| &nbsp;&nbsp;↳ [.001 DLL](https://attack.mitre.org/techniques/T1574/001) ([local](/mitre/techniques/T1574-001.md)) | Win | 32 | 67 | 5 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Dylib Hijacking](https://attack.mitre.org/techniques/T1574/004) ([local](/mitre/techniques/T1574-004.md)) | Mac | 0 | 1 | 1 | 13 | Yes |
| &nbsp;&nbsp;↳ [.005 Executable Installer File Permissions Weakness](https://attack.mitre.org/techniques/T1574/005) ([local](/mitre/techniques/T1574-005.md)) | Win | 1 | 0 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.006 Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006) ([local](/mitre/techniques/T1574-006.md)) | Lnx Mac | 3 | 6 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.007 Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007) ([local](/mitre/techniques/T1574-007.md)) | Win Mac Lnx | 0 | 3 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.008 Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008) ([local](/mitre/techniques/T1574-008.md)) | Win | 0 | 2 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.009 Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009) ([local](/mitre/techniques/T1574-009.md)) | Win | 0 | 2 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.010 Services File Permissions Weakness](https://attack.mitre.org/techniques/T1574/010) ([local](/mitre/techniques/T1574-010.md)) | Win | 0 | 1 | 3 | 11 | Yes |
| &nbsp;&nbsp;↳ [.011 Services Registry Permissions Weakness](https://attack.mitre.org/techniques/T1574/011) ([local](/mitre/techniques/T1574-011.md)) | Win | 0 | 0 | 1 | 2 | Yes |
| &nbsp;&nbsp;↳ [.012 COR_PROFILER](https://attack.mitre.org/techniques/T1574/012) ([local](/mitre/techniques/T1574-012.md)) | Win | 1 | 1 | 3 | 9 | Yes |
| &nbsp;&nbsp;↳ [.013 KernelCallbackTable](https://attack.mitre.org/techniques/T1574/013) ([local](/mitre/techniques/T1574-013.md)) | Win | 1 | 1 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014) ([local](/mitre/techniques/T1574-014.md)) | Win | 0 | 1 | 1 | 10 | Yes |
| [T1578 Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578) ([local](/mitre/techniques/T1578.md)) | IaaS | 0 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.001 Create Snapshot](https://attack.mitre.org/techniques/T1578/001) ([local](/mitre/techniques/T1578-001.md)) | IaaS | 0 | 1 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.002 Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002) ([local](/mitre/techniques/T1578-002.md)) | IaaS | 2 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.003 Delete Cloud Instance](https://attack.mitre.org/techniques/T1578/003) ([local](/mitre/techniques/T1578-003.md)) | IaaS | 2 | 0 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.004 Revert Cloud Instance](https://attack.mitre.org/techniques/T1578/004) ([local](/mitre/techniques/T1578-004.md)) | IaaS | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.005 Modify Cloud Compute Configurations](https://attack.mitre.org/techniques/T1578/005) ([local](/mitre/techniques/T1578-005.md)) | IaaS | 0 | 0 | 2 | 5 | Yes |
| [T1599 Network Boundary Bridging](https://attack.mitre.org/techniques/T1599) ([local](/mitre/techniques/T1599.md)) | NetDev | 1 | 0 | 5 | 18 | Yes |
| &nbsp;&nbsp;↳ [.001 Network Address Translation Traversal](https://attack.mitre.org/techniques/T1599/001) ([local](/mitre/techniques/T1599-001.md)) | NetDev | 0 | 0 | 5 | 18 | Yes |
| [T1600 Weaken Encryption](https://attack.mitre.org/techniques/T1600) ([local](/mitre/techniques/T1600.md)) | NetDev | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Reduce Key Space](https://attack.mitre.org/techniques/T1600/001) ([local](/mitre/techniques/T1600-001.md)) | NetDev | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Disable Crypto Hardware](https://attack.mitre.org/techniques/T1600/002) ([local](/mitre/techniques/T1600-002.md)) | NetDev | 0 | 0 | 0 | 0 | Yes |
| [T1601 Modify System Image](https://attack.mitre.org/techniques/T1601) ([local](/mitre/techniques/T1601.md)) | NetDev | 0 | 0 | 6 | 24 | Yes |
| &nbsp;&nbsp;↳ [.001 Patch System Image](https://attack.mitre.org/techniques/T1601/001) ([local](/mitre/techniques/T1601-001.md)) | NetDev | 0 | 1 | 6 | 24 | Yes |
| &nbsp;&nbsp;↳ [.002 Downgrade System Image](https://attack.mitre.org/techniques/T1601/002) ([local](/mitre/techniques/T1601-002.md)) | NetDev | 0 | 0 | 6 | 24 | Yes |
| [T1610 Deploy Container](https://attack.mitre.org/techniques/T1610) ([local](/mitre/techniques/T1610.md)) | Cnt | 1 | 3 | 4 | 9 | Yes |
| [T1612 Build Image on Host](https://attack.mitre.org/techniques/T1612) ([local](/mitre/techniques/T1612.md)) | Cnt | 0 | 0 | 4 | 11 | Yes |
| [T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620) ([local](/mitre/techniques/T1620.md)) | Lnx Mac Win | 4 | 22 | 0 | 0 | Yes |
| [T1622 Debugger Evasion](https://attack.mitre.org/techniques/T1622) ([local](/mitre/techniques/T1622.md)) | Lnx Mac Win | 1 | 21 | 0 | 15 | Yes |
| [T1647 Plist File Modification](https://attack.mitre.org/techniques/T1647) ([local](/mitre/techniques/T1647.md)) | Mac | 0 | 2 | 1 | 15 | Yes |
| [T1656 Impersonation](https://attack.mitre.org/techniques/T1656) ([local](/mitre/techniques/T1656.md)) | Lnx Mac Office SaaS Win | 8 | 1 | 2 | 0 | Yes |
| [T1666 Modify Cloud Resource Hierarchy](https://attack.mitre.org/techniques/T1666) ([local](/mitre/techniques/T1666.md)) | IaaS | 0 | 0 | 3 | 1 | Yes |
| [T1672 Email Spoofing](https://attack.mitre.org/techniques/T1672) ([local](/mitre/techniques/T1672.md)) | Office Win Mac Lnx | 0 | 0 | 1 | 0 | Yes |
| [T1678 Delay Execution](https://attack.mitre.org/techniques/T1678) ([local](/mitre/techniques/T1678.md)) | Lnx Mac Win | 1 | 2 | 0 | 0 | Yes |
| [T1679 Selective Exclusion](https://attack.mitre.org/techniques/T1679) ([local](/mitre/techniques/T1679.md)) | Win | 0 | 3 | 0 | 0 | Yes |

## Credential Access
<a id="credential-access"></a>

[`TA0006`](https://attack.mitre.org/tactics/TA0006/) ([local](/mitre/tactics/credential-access.md)), 67 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1003 OS Credential Dumping](https://attack.mitre.org/techniques/T1003) ([local](/mitre/techniques/T1003.md)) | Lnx Mac Win | 13 | 7 | 9 | 22 | Yes |
| &nbsp;&nbsp;↳ [.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) | Win | 42 | 26 | 7 | 19 | Yes |
| &nbsp;&nbsp;↳ [.002 Security Account Manager](https://attack.mitre.org/techniques/T1003/002) ([local](/mitre/techniques/T1003-002.md)) | Win | 13 | 15 | 4 | 15 | Yes |
| &nbsp;&nbsp;↳ [.003 NTDS](https://attack.mitre.org/techniques/T1003/003) ([local](/mitre/techniques/T1003-003.md)) | Win | 17 | 4 | 4 | 18 | Yes |
| &nbsp;&nbsp;↳ [.004 LSA Secrets](https://attack.mitre.org/techniques/T1003/004) ([local](/mitre/techniques/T1003-004.md)) | Win | 10 | 9 | 3 | 14 | Yes |
| &nbsp;&nbsp;↳ [.005 Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005) ([local](/mitre/techniques/T1003-005.md)) | Win Lnx | 4 | 4 | 5 | 17 | Yes |
| &nbsp;&nbsp;↳ [.006 DCSync](https://attack.mitre.org/techniques/T1003/006) ([local](/mitre/techniques/T1003-006.md)) | Win | 4 | 1 | 3 | 16 | Yes |
| &nbsp;&nbsp;↳ [.007 Proc Filesystem](https://attack.mitre.org/techniques/T1003/007) ([local](/mitre/techniques/T1003-007.md)) | Lnx | 0 | 3 | 2 | 14 | Yes |
| &nbsp;&nbsp;↳ [.008 /etc/passwd and /etc/shadow](https://attack.mitre.org/techniques/T1003/008) ([local](/mitre/techniques/T1003-008.md)) | Lnx | 0 | 1 | 2 | 14 | Yes |
| [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040) ([local](/mitre/techniques/T1040.md)) | Lnx Mac Win NetDev IaaS | 8 | 16 | 4 | 12 | Yes |
| [T1056 Input Capture](https://attack.mitre.org/techniques/T1056) ([local](/mitre/techniques/T1056.md)) | Lnx Mac NetDev Win | 3 | 7 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Keylogging](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) | Lnx Mac NetDev Win | 26 | 123 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 GUI Input Capture](https://attack.mitre.org/techniques/T1056/002) ([local](/mitre/techniques/T1056-002.md)) | Mac Win Lnx | 2 | 11 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.003 Web Portal Capture](https://attack.mitre.org/techniques/T1056/003) ([local](/mitre/techniques/T1056-003.md)) | Lnx Mac Win | 1 | 2 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.004 Credential API Hooking](https://attack.mitre.org/techniques/T1056/004) ([local](/mitre/techniques/T1056-004.md)) | Win Lnx Mac | 1 | 11 | 0 | 0 | Yes |
| [T1110 Brute Force](https://attack.mitre.org/techniques/T1110) ([local](/mitre/techniques/T1110.md)) | Cnt ESXi IaaS IdP Lnx Mac NetDev Office SaaS Win | 14 | 7 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001) ([local](/mitre/techniques/T1110-001.md)) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 2 | 9 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 Password Cracking](https://attack.mitre.org/techniques/T1110/002) ([local](/mitre/techniques/T1110-002.md)) | Lnx Mac Win NetDev Office IdP | 4 | 1 | 2 | 14 | Yes |
| &nbsp;&nbsp;↳ [.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003) ([local](/mitre/techniques/T1110-003.md)) | Cnt ESXi IaaS IdP Lnx NetDev Office SaaS Win Mac | 11 | 4 | 3 | 14 | Yes |
| &nbsp;&nbsp;↳ [.004 Credential Stuffing](https://attack.mitre.org/techniques/T1110/004) ([local](/mitre/techniques/T1110-004.md)) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP ESXi | 1 | 1 | 4 | 14 | Yes |
| [T1111 Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111) ([local](/mitre/techniques/T1111.md)) | Lnx Win Mac | 4 | 2 | 1 | 9 | Yes |
| [T1187 Forced Authentication](https://attack.mitre.org/techniques/T1187) ([local](/mitre/techniques/T1187.md)) | Win | 2 | 1 | 2 | 10 | Yes |
| [T1212 Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212) ([local](/mitre/techniques/T1212.md)) | Lnx Win Mac IdP | 1 | 0 | 5 | 24 | Yes |
| [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528) ([local](/mitre/techniques/T1528.md)) | SaaS Cnt IaaS Office IdP | 2 | 2 | 4 | 19 | Yes |
| [T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539) ([local](/mitre/techniques/T1539.md)) | Lnx Office SaaS Win Mac | 8 | 16 | 6 | 10 | Yes |
| [T1552 Unsecured Credentials](https://attack.mitre.org/techniques/T1552) ([local](/mitre/techniques/T1552.md)) | Win SaaS IaaS Lnx Mac Cnt NetDev Office IdP | 1 | 4 | 11 | 32 | Yes |
| &nbsp;&nbsp;↳ [.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001) ([local](/mitre/techniques/T1552-001.md)) | Cnt IaaS Lnx Mac Win | 14 | 18 | 4 | 17 | Yes |
| &nbsp;&nbsp;↳ [.002 Credentials in Registry](https://attack.mitre.org/techniques/T1552/002) ([local](/mitre/techniques/T1552-002.md)) | Win | 2 | 7 | 3 | 18 | Yes |
| &nbsp;&nbsp;↳ [.003 Shell History](https://attack.mitre.org/techniques/T1552/003) ([local](/mitre/techniques/T1552-003.md)) | Lnx Mac Win | 0 | 1 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.004 Private Keys](https://attack.mitre.org/techniques/T1552/004) ([local](/mitre/techniques/T1552-004.md)) | Lnx Mac NetDev Win | 5 | 11 | 4 | 21 | Yes |
| &nbsp;&nbsp;↳ [.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005) ([local](/mitre/techniques/T1552-005.md)) | IaaS | 1 | 2 | 3 | 14 | Yes |
| &nbsp;&nbsp;↳ [.006 Group Policy Preferences](https://attack.mitre.org/techniques/T1552/006) ([local](/mitre/techniques/T1552-006.md)) | Win | 2 | 2 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.007 Container API](https://attack.mitre.org/techniques/T1552/007) ([local](/mitre/techniques/T1552-007.md)) | Cnt | 0 | 1 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.008 Chat Messages](https://attack.mitre.org/techniques/T1552/008) ([local](/mitre/techniques/T1552-008.md)) | SaaS Office | 1 | 0 | 2 | 2 | Yes |
| [T1555 Credentials from Password Stores](https://attack.mitre.org/techniques/T1555) ([local](/mitre/techniques/T1555.md)) | IaaS Lnx Mac Win | 12 | 24 | 3 | 8 | Yes |
| &nbsp;&nbsp;↳ [.001 Keychain](https://attack.mitre.org/techniques/T1555/001) ([local](/mitre/techniques/T1555-001.md)) | Mac | 1 | 10 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Securityd Memory](https://attack.mitre.org/techniques/T1555/002) ([local](/mitre/techniques/T1555-002.md)) | Lnx Mac | 0 | 1 | 0 | 5 | Yes |
| &nbsp;&nbsp;↳ [.003 Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003) ([local](/mitre/techniques/T1555-003.md)) | Lnx Mac Win | 23 | 62 | 5 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004) ([local](/mitre/techniques/T1555-004.md)) | Win | 4 | 9 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.005 Password Managers](https://attack.mitre.org/techniques/T1555/005) ([local](/mitre/techniques/T1555-005.md)) | Lnx Mac Win | 7 | 4 | 5 | 8 | Yes |
| &nbsp;&nbsp;↳ [.006 Cloud Secrets Management Stores](https://attack.mitre.org/techniques/T1555/006) ([local](/mitre/techniques/T1555-006.md)) | IaaS | 2 | 1 | 1 | 4 | Yes |
| [T1556 Modify Authentication Process](https://attack.mitre.org/techniques/T1556) ([local](/mitre/techniques/T1556.md)) | Win Lnx Mac NetDev IaaS SaaS Office IdP | 1 | 3 | 9 | 17 | Yes |
| &nbsp;&nbsp;↳ [.001 Domain Controller Authentication](https://attack.mitre.org/techniques/T1556/001) ([local](/mitre/techniques/T1556-001.md)) | Win | 1 | 1 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.002 Password Filter DLL](https://attack.mitre.org/techniques/T1556/002) ([local](/mitre/techniques/T1556-002.md)) | Win | 2 | 1 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.003 Pluggable Authentication Modules](https://attack.mitre.org/techniques/T1556/003) ([local](/mitre/techniques/T1556-003.md)) | Lnx Mac | 0 | 2 | 2 | 12 | Yes |
| &nbsp;&nbsp;↳ [.004 Network Device Authentication](https://attack.mitre.org/techniques/T1556/004) ([local](/mitre/techniques/T1556-004.md)) | NetDev | 0 | 2 | 2 | 13 | Yes |
| &nbsp;&nbsp;↳ [.005 Reversible Encryption](https://attack.mitre.org/techniques/T1556/005) ([local](/mitre/techniques/T1556-005.md)) | Win | 0 | 0 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.006 Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006) ([local](/mitre/techniques/T1556-006.md)) | Win SaaS IaaS Lnx Mac Office IdP | 1 | 2 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.007 Hybrid Identity](https://attack.mitre.org/techniques/T1556/007) ([local](/mitre/techniques/T1556-007.md)) | Win SaaS IaaS Office IdP | 1 | 1 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.008 Network Provider DLL](https://attack.mitre.org/techniques/T1556/008) ([local](/mitre/techniques/T1556-008.md)) | Win | 0 | 0 | 3 | 9 | Yes |
| &nbsp;&nbsp;↳ [.009 Conditional Access Policies](https://attack.mitre.org/techniques/T1556/009) ([local](/mitre/techniques/T1556-009.md)) | IaaS IdP | 2 | 0 | 1 | 14 | Yes |
| [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) ([local](/mitre/techniques/T1557.md)) | Lnx Mac NetDev Win | 3 | 3 | 7 | 24 | Yes |
| &nbsp;&nbsp;↳ [.001 LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001) ([local](/mitre/techniques/T1557-001.md)) | Win | 2 | 5 | 4 | 15 | Yes |
| &nbsp;&nbsp;↳ [.002 ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002) ([local](/mitre/techniques/T1557-002.md)) | Lnx Win Mac | 2 | 0 | 6 | 22 | Yes |
| &nbsp;&nbsp;↳ [.003 DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003) ([local](/mitre/techniques/T1557-003.md)) | Lnx Win Mac | 0 | 0 | 2 | 15 | Yes |
| &nbsp;&nbsp;↳ [.004 Evil Twin](https://attack.mitre.org/techniques/T1557/004) ([local](/mitre/techniques/T1557-004.md)) | NetDev | 1 | 0 | 2 | 16 | Yes |
| [T1558 Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558) ([local](/mitre/techniques/T1558.md)) | Win Lnx Mac | 1 | 0 | 6 | 19 | Yes |
| &nbsp;&nbsp;↳ [.001 Golden Ticket](https://attack.mitre.org/techniques/T1558/001) ([local](/mitre/techniques/T1558-001.md)) | Win | 1 | 4 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.002 Silver Ticket](https://attack.mitre.org/techniques/T1558/002) ([local](/mitre/techniques/T1558-002.md)) | Win | 0 | 4 | 3 | 19 | Yes |
| &nbsp;&nbsp;↳ [.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003) ([local](/mitre/techniques/T1558-003.md)) | Win | 3 | 6 | 3 | 19 | Yes |
| &nbsp;&nbsp;↳ [.004 AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004) ([local](/mitre/techniques/T1558-004.md)) | Win | 0 | 1 | 3 | 19 | Yes |
| &nbsp;&nbsp;↳ [.005 Ccache Files](https://attack.mitre.org/techniques/T1558/005) ([local](/mitre/techniques/T1558-005.md)) | Lnx Mac | 0 | 1 | 2 | 10 | Yes |
| [T1606 Forge Web Credentials](https://attack.mitre.org/techniques/T1606) ([local](/mitre/techniques/T1606.md)) | SaaS Win Mac Lnx IaaS Office IdP | 0 | 0 | 4 | 7 | Yes |
| &nbsp;&nbsp;↳ [.001 Web Cookies](https://attack.mitre.org/techniques/T1606/001) ([local](/mitre/techniques/T1606-001.md)) | Lnx Mac Win SaaS IaaS | 0 | 0 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.002 SAML Tokens](https://attack.mitre.org/techniques/T1606/002) ([local](/mitre/techniques/T1606-002.md)) | SaaS Win IaaS Office IdP | 0 | 1 | 4 | 4 | Yes |
| [T1621 Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621) ([local](/mitre/techniques/T1621.md)) | Win Lnx Mac IaaS SaaS Office IdP | 3 | 0 | 3 | 7 | Yes |
| [T1649 Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649) ([local](/mitre/techniques/T1649.md)) | Win Lnx Mac IdP | 1 | 2 | 4 | 3 | Yes |

## Discovery
<a id="discovery"></a>

[`TA0007`](https://attack.mitre.org/tactics/TA0007/) ([local](/mitre/tactics/discovery.md)), 49 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1007 System Service Discovery](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) | Lnx Mac Win | 14 | 51 | 0 | 0 | Yes |
| [T1010 Application Window Discovery](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) | Lnx Win Mac | 3 | 32 | 0 | 0 | Yes |
| [T1012 Query Registry](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) | Win | 19 | 98 | 0 | 0 | Yes |
| [T1016 System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) | ESXi Lnx Mac NetDev Win | 42 | 225 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Internet Connection Discovery](https://attack.mitre.org/techniques/T1016/001) ([local](/mitre/techniques/T1016-001.md)) | Win Lnx Mac ESXi | 11 | 13 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Wi-Fi Discovery](https://attack.mitre.org/techniques/T1016/002) ([local](/mitre/techniques/T1016-002.md)) | Lnx Win Mac | 1 | 5 | 0 | 0 | Yes |
| [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) | ESXi Lnx Mac NetDev Win | 39 | 52 | 0 | 0 | Yes |
| [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) | Lnx Mac NetDev Win | 38 | 186 | 0 | 0 | Yes |
| [T1040 Network Sniffing](https://attack.mitre.org/techniques/T1040) ([local](/mitre/techniques/T1040.md)) | Lnx Mac Win NetDev IaaS | 8 | 16 | 4 | 12 | Yes |
| [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) | Cnt IaaS Lnx Mac NetDev Win | 31 | 35 | 3 | 11 | Yes |
| [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) | Win IaaS Lnx Mac NetDev ESXi | 32 | 60 | 0 | 0 | Yes |
| [T1057 Process Discovery](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) | ESXi Lnx Mac NetDev Win | 40 | 255 | 0 | 0 | Yes |
| [T1069 Permission Groups Discovery](https://attack.mitre.org/techniques/T1069) ([local](/mitre/techniques/T1069.md)) | Cnt IaaS IdP Lnx Mac Office SaaS Win | 6 | 6 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Local Groups](https://attack.mitre.org/techniques/T1069/001) ([local](/mitre/techniques/T1069-001.md)) | Lnx Mac Win | 7 | 21 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Domain Groups](https://attack.mitre.org/techniques/T1069/002) ([local](/mitre/techniques/T1069-002.md)) | Lnx Mac Win | 13 | 21 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Cloud Groups](https://attack.mitre.org/techniques/T1069/003) ([local](/mitre/techniques/T1069-003.md)) | SaaS IaaS Office IdP | 0 | 3 | 0 | 0 | Yes |
| [T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) | ESXi IaaS Lnx Mac NetDev Win | 55 | 336 | 0 | 0 | Yes |
| [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) | ESXi Lnx Mac NetDev Win | 50 | 295 | 0 | 0 | Yes |
| [T1087 Account Discovery](https://attack.mitre.org/techniques/T1087) ([local](/mitre/techniques/T1087.md)) | ESXi IaaS IdP Lnx Mac Office SaaS Win | 3 | 5 | 2 | 4 | Yes |
| &nbsp;&nbsp;↳ [.001 Local Account](https://attack.mitre.org/techniques/T1087/001) ([local](/mitre/techniques/T1087-001.md)) | ESXi Lnx Mac Win | 18 | 44 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Domain Account](https://attack.mitre.org/techniques/T1087/002) ([local](/mitre/techniques/T1087-002.md)) | Lnx Mac Win | 27 | 25 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.003 Email Account](https://attack.mitre.org/techniques/T1087/003) ([local](/mitre/techniques/T1087-003.md)) | Win Office | 4 | 8 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.004 Cloud Account](https://attack.mitre.org/techniques/T1087/004) ([local](/mitre/techniques/T1087-004.md)) | IaaS IdP Office SaaS | 2 | 3 | 2 | 6 | Yes |
| [T1120 Peripheral Device Discovery](https://attack.mitre.org/techniques/T1120) ([local](/mitre/techniques/T1120.md)) | Lnx Win Mac | 9 | 46 | 0 | 0 | Yes |
| [T1124 System Time Discovery](https://attack.mitre.org/techniques/T1124) ([local](/mitre/techniques/T1124.md)) | ESXi Lnx Mac NetDev Win | 13 | 77 | 0 | 0 | Yes |
| [T1135 Network Share Discovery](https://attack.mitre.org/techniques/T1135) ([local](/mitre/techniques/T1135.md)) | Lnx Mac Win | 16 | 57 | 1 | 3 | Yes |
| [T1201 Password Policy Discovery](https://attack.mitre.org/techniques/T1201) ([local](/mitre/techniques/T1201.md)) | Win Lnx Mac IaaS NetDev IdP SaaS Office | 3 | 4 | 1 | 5 | Yes |
| [T1217 Browser Information Discovery](https://attack.mitre.org/techniques/T1217) ([local](/mitre/techniques/T1217.md)) | Lnx Mac Win | 6 | 17 | 0 | 0 | Yes |
| [T1482 Domain Trust Discovery](https://attack.mitre.org/techniques/T1482) ([local](/mitre/techniques/T1482.md)) | Win | 9 | 19 | 2 | 9 | Yes |
| [T1497 Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) ([local](/mitre/techniques/T1497.md)) | Lnx Mac Win | 3 | 22 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 System Checks](https://attack.mitre.org/techniques/T1497/001) ([local](/mitre/techniques/T1497-001.md)) | Lnx Mac Win | 5 | 59 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 User Activity Based Checks](https://attack.mitre.org/techniques/T1497/002) ([local](/mitre/techniques/T1497-002.md)) | Lnx Win Mac | 2 | 3 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Time Based Checks](https://attack.mitre.org/techniques/T1497/003) ([local](/mitre/techniques/T1497-003.md)) | Lnx Mac Win | 0 | 45 | 0 | 0 | Yes |
| [T1518 Software Discovery](https://attack.mitre.org/techniques/T1518) ([local](/mitre/techniques/T1518.md)) | ESXi IaaS Lnx Mac Win | 11 | 36 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Security Software Discovery](https://attack.mitre.org/techniques/T1518/001) ([local](/mitre/techniques/T1518-001.md)) | IaaS Lnx Mac Win | 27 | 105 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Backup Software Discovery](https://attack.mitre.org/techniques/T1518/002) ([local](/mitre/techniques/T1518-002.md)) | Win Mac Lnx | 1 | 0 | 0 | 0 | Yes |
| [T1526 Cloud Service Discovery](https://attack.mitre.org/techniques/T1526) ([local](/mitre/techniques/T1526.md)) | IaaS IdP Office SaaS | 1 | 3 | 0 | 0 | Yes |
| [T1538 Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538) ([local](/mitre/techniques/T1538.md)) | IaaS SaaS Office IdP | 1 | 0 | 1 | 6 | Yes |
| [T1580 Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580) ([local](/mitre/techniques/T1580.md)) | IaaS | 2 | 1 | 1 | 5 | Yes |
| [T1613 Container and Resource Discovery](https://attack.mitre.org/techniques/T1613) ([local](/mitre/techniques/T1613.md)) | Cnt | 1 | 2 | 3 | 10 | Yes |
| [T1614 System Location Discovery](https://attack.mitre.org/techniques/T1614) ([local](/mitre/techniques/T1614.md)) | IaaS Lnx Mac Win | 2 | 18 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 System Language Discovery](https://attack.mitre.org/techniques/T1614/001) ([local](/mitre/techniques/T1614-001.md)) | Lnx Mac Win | 4 | 31 | 0 | 0 | Yes |
| [T1615 Group Policy Discovery](https://attack.mitre.org/techniques/T1615) ([local](/mitre/techniques/T1615.md)) | Win | 1 | 5 | 0 | 0 | Yes |
| [T1619 Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619) ([local](/mitre/techniques/T1619.md)) | IaaS | 0 | 2 | 1 | 7 | Yes |
| [T1622 Debugger Evasion](https://attack.mitre.org/techniques/T1622) ([local](/mitre/techniques/T1622.md)) | Lnx Mac Win | 1 | 21 | 0 | 15 | Yes |
| [T1652 Device Driver Discovery](https://attack.mitre.org/techniques/T1652) ([local](/mitre/techniques/T1652.md)) | Lnx Mac Win | 1 | 3 | 0 | 0 | Yes |
| [T1654 Log Enumeration](https://attack.mitre.org/techniques/T1654) ([local](/mitre/techniques/T1654.md)) | ESXi IaaS Lnx Mac Win | 5 | 5 | 1 | 4 | Yes |
| [T1673 Virtual Machine Discovery](https://attack.mitre.org/techniques/T1673) ([local](/mitre/techniques/T1673.md)) | ESXi Lnx Mac Win | 1 | 3 | 0 | 0 | Yes |
| [T1680 Local Storage Discovery](https://attack.mitre.org/techniques/T1680) ([local](/mitre/techniques/T1680.md)) | ESXi IaaS Lnx Mac Win | 10 | 86 | 0 | 0 | Yes |

## Lateral Movement
<a id="lateral-movement"></a>

[`TA0008`](https://attack.mitre.org/tactics/TA0008/) ([local](/mitre/tactics/lateral-movement.md)), 23 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1021 Remote Services](https://attack.mitre.org/techniques/T1021) ([local](/mitre/techniques/T1021.md)) | Lnx Mac Win IaaS ESXi | 3 | 4 | 6 | 14 | Yes |
| &nbsp;&nbsp;↳ [.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) ([local](/mitre/techniques/T1021-001.md)) | Win | 35 | 17 | 8 | 23 | Yes |
| &nbsp;&nbsp;↳ [.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) ([local](/mitre/techniques/T1021-002.md)) | Win | 26 | 30 | 4 | 16 | Yes |
| &nbsp;&nbsp;↳ [.003 Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003) ([local](/mitre/techniques/T1021-003.md)) | Win | 0 | 3 | 4 | 19 | Yes |
| &nbsp;&nbsp;↳ [.004 SSH](https://attack.mitre.org/techniques/T1021/004) ([local](/mitre/techniques/T1021-004.md)) | ESXi Lnx Mac | 19 | 4 | 3 | 15 | Yes |
| &nbsp;&nbsp;↳ [.005 VNC](https://attack.mitre.org/techniques/T1021/005) ([local](/mitre/techniques/T1021-005.md)) | Lnx Win Mac | 4 | 7 | 4 | 22 | Yes |
| &nbsp;&nbsp;↳ [.006 Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) ([local](/mitre/techniques/T1021-006.md)) | Win | 5 | 3 | 3 | 16 | Yes |
| &nbsp;&nbsp;↳ [.007 Cloud Services](https://attack.mitre.org/techniques/T1021/007) ([local](/mitre/techniques/T1021-007.md)) | IaaS IdP Office SaaS | 3 | 0 | 2 | 7 | Yes |
| &nbsp;&nbsp;↳ [.008 Direct Cloud VM Connections](https://attack.mitre.org/techniques/T1021/008) ([local](/mitre/techniques/T1021-008.md)) | IaaS | 0 | 0 | 2 | 11 | Yes |
| [T1072 Software Deployment Tools](https://attack.mitre.org/techniques/T1072) ([local](/mitre/techniques/T1072.md)) | Lnx Mac NetDev SaaS Win | 6 | 1 | 10 | 27 | Yes |
| [T1080 Taint Shared Content](https://attack.mitre.org/techniques/T1080) ([local](/mitre/techniques/T1080.md)) | Win SaaS Lnx Mac Office | 5 | 7 | 4 | 10 | Yes |
| [T1091 Replication Through Removable Media](https://attack.mitre.org/techniques/T1091) ([local](/mitre/techniques/T1091.md)) | Win | 8 | 20 | 3 | 10 | Yes |
| [T1210 Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210) ([local](/mitre/techniques/T1210.md)) | Lnx Win Mac ESXi | 11 | 13 | 8 | 31 | Yes |
| [T1534 Internal Spearphishing](https://attack.mitre.org/techniques/T1534) ([local](/mitre/techniques/T1534.md)) | Win Mac Lnx SaaS Office | 4 | 0 | 0 | 0 | Yes |
| [T1550 Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550) ([local](/mitre/techniques/T1550.md)) | Win SaaS IaaS Cnt IdP Office Lnx | 0 | 1 | 7 | 7 | Yes |
| &nbsp;&nbsp;↳ [.001 Application Access Token](https://attack.mitre.org/techniques/T1550/001) ([local](/mitre/techniques/T1550-001.md)) | SaaS Cnt IaaS Office IdP | 2 | 2 | 5 | 15 | Yes |
| &nbsp;&nbsp;↳ [.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002) ([local](/mitre/techniques/T1550-002.md)) | Win | 11 | 8 | 4 | 8 | Yes |
| &nbsp;&nbsp;↳ [.003 Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) ([local](/mitre/techniques/T1550-003.md)) | Win | 3 | 3 | 4 | 11 | Yes |
| &nbsp;&nbsp;↳ [.004 Web Session Cookie](https://attack.mitre.org/techniques/T1550/004) ([local](/mitre/techniques/T1550-004.md)) | SaaS IaaS Office | 1 | 0 | 1 | 3 | Yes |
| [T1563 Remote Service Session Hijacking](https://attack.mitre.org/techniques/T1563) ([local](/mitre/techniques/T1563.md)) | Lnx Mac Win | 0 | 0 | 5 | 19 | Yes |
| &nbsp;&nbsp;↳ [.001 SSH Hijacking](https://attack.mitre.org/techniques/T1563/001) ([local](/mitre/techniques/T1563-001.md)) | Lnx Mac | 0 | 1 | 4 | 17 | Yes |
| &nbsp;&nbsp;↳ [.002 RDP Hijacking](https://attack.mitre.org/techniques/T1563/002) ([local](/mitre/techniques/T1563-002.md)) | Win | 1 | 1 | 7 | 18 | Yes |
| [T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570) ([local](/mitre/techniques/T1570.md)) | ESXi Lnx Mac Win | 19 | 25 | 2 | 11 | Yes |

## Collection
<a id="collection"></a>

[`TA0009`](https://attack.mitre.org/tactics/TA0009/) ([local](/mitre/tactics/collection.md)), 41 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1005 Data from Local System](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) | ESXi Lnx Mac NetDev Win | 43 | 161 | 1 | 13 | Yes |
| [T1025 Data from Removable Media](https://attack.mitre.org/techniques/T1025) ([local](/mitre/techniques/T1025.md)) | Lnx Mac Win | 4 | 20 | 1 | 15 | Yes |
| [T1039 Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039) ([local](/mitre/techniques/T1039.md)) | Lnx Mac Win | 8 | 4 | 0 | 0 | Yes |
| [T1056 Input Capture](https://attack.mitre.org/techniques/T1056) ([local](/mitre/techniques/T1056.md)) | Lnx Mac NetDev Win | 3 | 7 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Keylogging](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) | Lnx Mac NetDev Win | 26 | 123 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 GUI Input Capture](https://attack.mitre.org/techniques/T1056/002) ([local](/mitre/techniques/T1056-002.md)) | Mac Win Lnx | 2 | 11 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.003 Web Portal Capture](https://attack.mitre.org/techniques/T1056/003) ([local](/mitre/techniques/T1056-003.md)) | Lnx Mac Win | 1 | 2 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.004 Credential API Hooking](https://attack.mitre.org/techniques/T1056/004) ([local](/mitre/techniques/T1056-004.md)) | Win Lnx Mac | 1 | 11 | 0 | 0 | Yes |
| [T1074 Data Staged](https://attack.mitre.org/techniques/T1074) ([local](/mitre/techniques/T1074.md)) | Win IaaS Lnx Mac ESXi | 4 | 4 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Local Data Staging](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) | ESXi Lnx Mac Win | 27 | 88 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Remote Data Staging](https://attack.mitre.org/techniques/T1074/002) ([local](/mitre/techniques/T1074-002.md)) | Win IaaS Lnx Mac ESXi | 10 | 1 | 0 | 0 | Yes |
| [T1113 Screen Capture](https://attack.mitre.org/techniques/T1113) ([local](/mitre/techniques/T1113.md)) | Lnx Win Mac | 18 | 148 | 0 | 0 | Yes |
| [T1114 Email Collection](https://attack.mitre.org/techniques/T1114) ([local](/mitre/techniques/T1114.md)) | Win Mac Lnx Office | 4 | 2 | 4 | 15 | Yes |
| &nbsp;&nbsp;↳ [.001 Local Email Collection](https://attack.mitre.org/techniques/T1114/001) ([local](/mitre/techniques/T1114-001.md)) | Win | 6 | 11 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.002 Remote Email Collection](https://attack.mitre.org/techniques/T1114/002) ([local](/mitre/techniques/T1114-002.md)) | Win Office | 12 | 4 | 3 | 14 | Yes |
| &nbsp;&nbsp;↳ [.003 Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003) ([local](/mitre/techniques/T1114-003.md)) | Lnx Mac Office Win | 5 | 0 | 4 | 12 | Yes |
| [T1115 Clipboard Data](https://attack.mitre.org/techniques/T1115) ([local](/mitre/techniques/T1115.md)) | Lnx Mac Win | 3 | 41 | 0 | 0 | Yes |
| [T1119 Automated Collection](https://attack.mitre.org/techniques/T1119) ([local](/mitre/techniques/T1119.md)) | IaaS Lnx Mac Office SaaS Win | 20 | 44 | 2 | 17 | Yes |
| [T1123 Audio Capture](https://attack.mitre.org/techniques/T1123) ([local](/mitre/techniques/T1123.md)) | Lnx Mac Win | 1 | 30 | 0 | 0 | Yes |
| [T1125 Video Capture](https://attack.mitre.org/techniques/T1125) ([local](/mitre/techniques/T1125.md)) | Win Mac Lnx | 3 | 31 | 0 | 0 | Yes |
| [T1185 Browser Session Hijacking](https://attack.mitre.org/techniques/T1185) ([local](/mitre/techniques/T1185.md)) | Win | 1 | 13 | 2 | 14 | Yes |
| [T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213) ([local](/mitre/techniques/T1213.md)) | Lnx Win Mac SaaS IaaS Office | 1 | 2 | 7 | 24 | Yes |
| &nbsp;&nbsp;↳ [.001 Confluence](https://attack.mitre.org/techniques/T1213/001) ([local](/mitre/techniques/T1213-001.md)) | SaaS | 1 | 0 | 3 | 23 | Yes |
| &nbsp;&nbsp;↳ [.002 Sharepoint](https://attack.mitre.org/techniques/T1213/002) ([local](/mitre/techniques/T1213-002.md)) | Win Office | 6 | 1 | 3 | 23 | Yes |
| &nbsp;&nbsp;↳ [.003 Code Repositories](https://attack.mitre.org/techniques/T1213/003) ([local](/mitre/techniques/T1213-003.md)) | SaaS | 3 | 0 | 4 | 14 | Yes |
| &nbsp;&nbsp;↳ [.004 Customer Relationship Management Software](https://attack.mitre.org/techniques/T1213/004) ([local](/mitre/techniques/T1213-004.md)) | SaaS | 0 | 0 | 4 | 18 | Yes |
| &nbsp;&nbsp;↳ [.005 Messaging Applications](https://attack.mitre.org/techniques/T1213/005) ([local](/mitre/techniques/T1213-005.md)) | SaaS Office | 3 | 0 | 3 | 24 | Yes |
| &nbsp;&nbsp;↳ [.006 Databases](https://attack.mitre.org/techniques/T1213/006) ([local](/mitre/techniques/T1213-006.md)) | Lnx Win Mac IaaS SaaS | 4 | 2 | 5 | 0 | Yes |
| [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530) ([local](/mitre/techniques/T1530.md)) | IaaS Office SaaS | 5 | 3 | 6 | 32 | Yes |
| [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) ([local](/mitre/techniques/T1557.md)) | Lnx Mac NetDev Win | 3 | 3 | 7 | 24 | Yes |
| &nbsp;&nbsp;↳ [.001 LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001) ([local](/mitre/techniques/T1557-001.md)) | Win | 2 | 5 | 4 | 15 | Yes |
| &nbsp;&nbsp;↳ [.002 ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002) ([local](/mitre/techniques/T1557-002.md)) | Lnx Win Mac | 2 | 0 | 6 | 22 | Yes |
| &nbsp;&nbsp;↳ [.003 DHCP Spoofing](https://attack.mitre.org/techniques/T1557/003) ([local](/mitre/techniques/T1557-003.md)) | Lnx Win Mac | 0 | 0 | 2 | 15 | Yes |
| &nbsp;&nbsp;↳ [.004 Evil Twin](https://attack.mitre.org/techniques/T1557/004) ([local](/mitre/techniques/T1557-004.md)) | NetDev | 1 | 0 | 2 | 16 | Yes |
| [T1560 Archive Collected Data](https://attack.mitre.org/techniques/T1560) ([local](/mitre/techniques/T1560.md)) | Lnx Mac Win | 13 | 41 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.001 Archive via Utility](https://attack.mitre.org/techniques/T1560/001) ([local](/mitre/techniques/T1560-001.md)) | Lnx Mac Win | 37 | 31 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.002 Archive via Library](https://attack.mitre.org/techniques/T1560/002) ([local](/mitre/techniques/T1560-002.md)) | Lnx Mac Win | 2 | 13 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Archive via Custom Method](https://attack.mitre.org/techniques/T1560/003) ([local](/mitre/techniques/T1560-003.md)) | Lnx Mac Win | 7 | 31 | 0 | 0 | Yes |
| [T1602 Data from Configuration Repository](https://attack.mitre.org/techniques/T1602) ([local](/mitre/techniques/T1602.md)) | NetDev | 0 | 0 | 6 | 25 | Yes |
| &nbsp;&nbsp;↳ [.001 SNMP (MIB Dump)](https://attack.mitre.org/techniques/T1602/001) ([local](/mitre/techniques/T1602-001.md)) | NetDev | 0 | 0 | 6 | 25 | Yes |
| &nbsp;&nbsp;↳ [.002 Network Device Configuration Dump](https://attack.mitre.org/techniques/T1602/002) ([local](/mitre/techniques/T1602-002.md)) | NetDev | 1 | 0 | 6 | 25 | Yes |

## Command and Control
<a id="command-and-control"></a>

[`TA0011`](https://attack.mitre.org/tactics/TA0011/) ([local](/mitre/tactics/command-and-control.md)), 45 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1001 Data Obfuscation](https://attack.mitre.org/techniques/T1001) ([local](/mitre/techniques/T1001.md)) | ESXi Lnx Mac Win | 1 | 11 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.001 Junk Data](https://attack.mitre.org/techniques/T1001/001) ([local](/mitre/techniques/T1001-001.md)) | ESXi Lnx Mac Win | 1 | 16 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.002 Steganography](https://attack.mitre.org/techniques/T1001/002) ([local](/mitre/techniques/T1001-002.md)) | Lnx Mac Win ESXi | 1 | 11 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.003 Protocol or Service Impersonation](https://attack.mitre.org/techniques/T1001/003) ([local](/mitre/techniques/T1001-003.md)) | ESXi Lnx Mac Win | 3 | 18 | 1 | 7 | Yes |
| [T1008 Fallback Channels](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) | Lnx Win Mac ESXi | 5 | 47 | 1 | 8 | Yes |
| [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071) ([local](/mitre/techniques/T1071.md)) | Lnx Mac Win NetDev ESXi | 5 | 10 | 2 | 15 | Yes |
| &nbsp;&nbsp;↳ [.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) | ESXi Lnx Mac NetDev Win | 56 | 329 | 2 | 15 | Yes |
| &nbsp;&nbsp;↳ [.002 File Transfer Protocols](https://attack.mitre.org/techniques/T1071/002) ([local](/mitre/techniques/T1071-002.md)) | ESXi Lnx Mac NetDev Win | 4 | 19 | 2 | 15 | Yes |
| &nbsp;&nbsp;↳ [.003 Mail Protocols](https://attack.mitre.org/techniques/T1071/003) ([local](/mitre/techniques/T1071-003.md)) | Lnx Mac NetDev Win | 6 | 20 | 2 | 15 | Yes |
| &nbsp;&nbsp;↳ [.004 DNS](https://attack.mitre.org/techniques/T1071/004) ([local](/mitre/techniques/T1071-004.md)) | Lnx Mac Win NetDev ESXi | 11 | 41 | 2 | 18 | Yes |
| &nbsp;&nbsp;↳ [.005 Publish/Subscribe Protocols](https://attack.mitre.org/techniques/T1071/005) ([local](/mitre/techniques/T1071-005.md)) | Mac Lnx Win NetDev | 0 | 1 | 2 | 4 | Yes |
| [T1090 Proxy](https://attack.mitre.org/techniques/T1090) ([local](/mitre/techniques/T1090.md)) | ESXi Lnx Mac NetDev Win | 17 | 46 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 Internal Proxy](https://attack.mitre.org/techniques/T1090/001) ([local](/mitre/techniques/T1090-001.md)) | Lnx NetDev Win Mac ESXi | 9 | 20 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 External Proxy](https://attack.mitre.org/techniques/T1090/002) ([local](/mitre/techniques/T1090-002.md)) | ESXi Lnx NetDev Win Mac | 11 | 10 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.003 Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003) ([local](/mitre/techniques/T1090-003.md)) | ESXi Lnx Mac NetDev Win | 11 | 20 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.004 Domain Fronting](https://attack.mitre.org/techniques/T1090/004) ([local](/mitre/techniques/T1090-004.md)) | Lnx Mac Win ESXi | 1 | 4 | 1 | 1 | Yes |
| [T1092 Communication Through Removable Media](https://attack.mitre.org/techniques/T1092) ([local](/mitre/techniques/T1092.md)) | Lnx Mac Win | 1 | 2 | 2 | 8 | Yes |
| [T1095 Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095) ([local](/mitre/techniques/T1095.md)) | ESXi Lnx Mac NetDev Win | 12 | 86 | 4 | 11 | Yes |
| [T1102 Web Service](https://attack.mitre.org/techniques/T1102) ([local](/mitre/techniques/T1102.md)) | ESXi Lnx Win Mac | 14 | 27 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.001 Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001) ([local](/mitre/techniques/T1102-001.md)) | ESXi Lnx Mac Win | 6 | 15 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002) ([local](/mitre/techniques/T1102-002.md)) | Lnx Mac Win ESXi | 16 | 37 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.003 One-Way Communication](https://attack.mitre.org/techniques/T1102/003) ([local](/mitre/techniques/T1102-003.md)) | Lnx Mac Win ESXi | 2 | 6 | 2 | 8 | Yes |
| [T1104 Multi-Stage Channels](https://attack.mitre.org/techniques/T1104) ([local](/mitre/techniques/T1104.md)) | Lnx Mac Win ESXi | 4 | 10 | 1 | 8 | Yes |
| [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) | ESXi Lnx Mac NetDev Win | 85 | 385 | 2 | 8 | Yes |
| [T1132 Data Encoding](https://attack.mitre.org/techniques/T1132) ([local](/mitre/techniques/T1132.md)) | Lnx Mac Win ESXi | 1 | 5 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.001 Standard Encoding](https://attack.mitre.org/techniques/T1132/001) ([local](/mitre/techniques/T1132-001.md)) | ESXi Lnx Win Mac | 11 | 108 | 1 | 7 | Yes |
| &nbsp;&nbsp;↳ [.002 Non-Standard Encoding](https://attack.mitre.org/techniques/T1132/002) ([local](/mitre/techniques/T1132-002.md)) | ESXi Lnx Mac Win | 0 | 16 | 1 | 7 | Yes |
| [T1205 Traffic Signaling](https://attack.mitre.org/techniques/T1205) ([local](/mitre/techniques/T1205.md)) | Lnx Mac NetDev Win | 3 | 16 | 2 | 9 | Yes |
| &nbsp;&nbsp;↳ [.001 Port Knocking](https://attack.mitre.org/techniques/T1205/001) ([local](/mitre/techniques/T1205-001.md)) | Lnx Mac Win NetDev | 2 | 4 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Socket Filters](https://attack.mitre.org/techniques/T1205/002) ([local](/mitre/techniques/T1205-002.md)) | Lnx Mac Win | 0 | 4 | 1 | 2 | Yes |
| [T1219 Remote Access Tools](https://attack.mitre.org/techniques/T1219) ([local](/mitre/techniques/T1219.md)) | Lnx Mac Win | 13 | 7 | 5 | 13 | Yes |
| &nbsp;&nbsp;↳ [.001 IDE Tunneling](https://attack.mitre.org/techniques/T1219/001) ([local](/mitre/techniques/T1219-001.md)) | Lnx Mac Win | 1 | 0 | 1 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Remote Desktop Software](https://attack.mitre.org/techniques/T1219/002) ([local](/mitre/techniques/T1219-002.md)) | Lnx Mac Win | 9 | 0 | 3 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 Remote Access Hardware](https://attack.mitre.org/techniques/T1219/003) ([local](/mitre/techniques/T1219-003.md)) | Lnx Mac Win | 0 | 0 | 1 | 0 | Yes |
| [T1568 Dynamic Resolution](https://attack.mitre.org/techniques/T1568) ([local](/mitre/techniques/T1568.md)) | Lnx Mac Win ESXi | 6 | 8 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.001 Fast Flux DNS](https://attack.mitre.org/techniques/T1568/001) ([local](/mitre/techniques/T1568-001.md)) | Lnx Mac Win ESXi | 3 | 3 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002) ([local](/mitre/techniques/T1568-002.md)) | Lnx Mac Win ESXi | 2 | 20 | 2 | 8 | Yes |
| &nbsp;&nbsp;↳ [.003 DNS Calculation](https://attack.mitre.org/techniques/T1568/003) ([local](/mitre/techniques/T1568-003.md)) | Lnx Mac Win ESXi | 1 | 0 | 0 | 0 | Yes |
| [T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571) ([local](/mitre/techniques/T1571.md)) | ESXi Lnx Mac Win | 16 | 37 | 2 | 8 | Yes |
| [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572) ([local](/mitre/techniques/T1572.md)) | ESXi Lnx Mac Win | 14 | 18 | 2 | 11 | Yes |
| [T1573 Encrypted Channel](https://attack.mitre.org/techniques/T1573) ([local](/mitre/techniques/T1573.md)) | ESXi Lnx Mac NetDev Win | 4 | 11 | 2 | 11 | Yes |
| &nbsp;&nbsp;↳ [.001 Symmetric Cryptography](https://attack.mitre.org/techniques/T1573/001) ([local](/mitre/techniques/T1573-001.md)) | ESXi Lnx Mac NetDev Win | 14 | 159 | 1 | 11 | Yes |
| &nbsp;&nbsp;↳ [.002 Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) ([local](/mitre/techniques/T1573-002.md)) | ESXi Lnx Mac NetDev Win | 11 | 73 | 2 | 11 | Yes |
| [T1659 Content Injection](https://attack.mitre.org/techniques/T1659) ([local](/mitre/techniques/T1659.md)) | Lnx Mac Win | 1 | 1 | 2 | 3 | Yes |
| [T1665 Hide Infrastructure](https://attack.mitre.org/techniques/T1665) ([local](/mitre/techniques/T1665.md)) | ESXi Lnx NetDev Win Mac | 2 | 3 | 0 | 0 | Yes |

## Exfiltration
<a id="exfiltration"></a>

[`TA0010`](https://attack.mitre.org/tactics/TA0010/) ([local](/mitre/tactics/exfiltration.md)), 19 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1011 Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011) ([local](/mitre/techniques/T1011.md)) | Lnx Mac Win | 0 | 0 | 2 | 5 | Yes |
| &nbsp;&nbsp;↳ [.001 Exfiltration Over Bluetooth](https://attack.mitre.org/techniques/T1011/001) ([local](/mitre/techniques/T1011-001.md)) | Lnx Mac Win | 0 | 1 | 2 | 8 | Yes |
| [T1020 Automated Exfiltration](https://attack.mitre.org/techniques/T1020) ([local](/mitre/techniques/T1020.md)) | Lnx Mac NetDev Win | 6 | 20 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Traffic Duplication](https://attack.mitre.org/techniques/T1020/001) ([local](/mitre/techniques/T1020-001.md)) | NetDev IaaS | 0 | 0 | 3 | 21 | Yes |
| [T1029 Scheduled Transfer](https://attack.mitre.org/techniques/T1029) ([local](/mitre/techniques/T1029.md)) | Lnx Mac Win | 1 | 17 | 1 | 7 | Yes |
| [T1030 Data Transfer Size Limits](https://attack.mitre.org/techniques/T1030) ([local](/mitre/techniques/T1030.md)) | Lnx Mac Win ESXi | 5 | 14 | 1 | 7 | Yes |
| [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) | ESXi Lnx Mac Win | 25 | 156 | 2 | 18 | Yes |
| [T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) ([local](/mitre/techniques/T1048.md)) | ESXi IaaS Lnx Mac NetDev Office SaaS Win | 2 | 7 | 6 | 23 | Yes |
| &nbsp;&nbsp;↳ [.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/001) ([local](/mitre/techniques/T1048-001.md)) | Lnx Mac Win ESXi | 0 | 0 | 3 | 12 | Yes |
| &nbsp;&nbsp;↳ [.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/002) ([local](/mitre/techniques/T1048-002.md)) | Lnx Mac Win ESXi | 3 | 2 | 4 | 23 | Yes |
| &nbsp;&nbsp;↳ [.003 Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003) ([local](/mitre/techniques/T1048-003.md)) | ESXi Lnx Mac NetDev Win | 11 | 22 | 4 | 23 | Yes |
| [T1052 Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052) ([local](/mitre/techniques/T1052.md)) | Lnx Mac Win | 0 | 0 | 3 | 19 | Yes |
| &nbsp;&nbsp;↳ [.001 Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001) ([local](/mitre/techniques/T1052-001.md)) | Lnx Win Mac | 2 | 5 | 3 | 19 | Yes |
| [T1537 Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537) ([local](/mitre/techniques/T1537.md)) | IaaS Office SaaS | 3 | 0 | 4 | 20 | Yes |
| [T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567) ([local](/mitre/techniques/T1567.md)) | ESXi Lnx Mac Office SaaS Win | 4 | 7 | 2 | 17 | Yes |
| &nbsp;&nbsp;↳ [.001 Exfiltration to Code Repository](https://attack.mitre.org/techniques/T1567/001) ([local](/mitre/techniques/T1567-001.md)) | Lnx Mac Win ESXi | 0 | 1 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) ([local](/mitre/techniques/T1567-002.md)) | ESXi Lnx Mac Win | 24 | 15 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.003 Exfiltration to Text Storage Sites](https://attack.mitre.org/techniques/T1567/003) ([local](/mitre/techniques/T1567-003.md)) | Lnx Mac Win ESXi | 0 | 0 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.004 Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004) ([local](/mitre/techniques/T1567-004.md)) | Win Mac Lnx SaaS Office ESXi | 0 | 0 | 1 | 3 | Yes |

## Impact
<a id="impact"></a>

[`TA0040`](https://attack.mitre.org/tactics/TA0040/) ([local](/mitre/tactics/impact.md)), 33 techniques

| Technique | Platforms | Grp | SW | Mit | NIST | Det |
|---|---|--:|--:|--:|--:|:--:|
| [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485) ([local](/mitre/techniques/T1485.md)) | Cnt ESXi IaaS Lnx Mac Win | 5 | 24 | 3 | 10 | Yes |
| &nbsp;&nbsp;↳ [.001 Lifecycle-Triggered Deletion](https://attack.mitre.org/techniques/T1485/001) ([local](/mitre/techniques/T1485-001.md)) | IaaS | 0 | 0 | 2 | 6 | Yes |
| [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) ([local](/mitre/techniques/T1486.md)) | ESXi IaaS Lnx Mac Win | 17 | 61 | 2 | 11 | Yes |
| [T1489 Service Stop](https://attack.mitre.org/techniques/T1489) ([local](/mitre/techniques/T1489.md)) | ESXi IaaS Lnx Mac Win | 6 | 44 | 5 | 14 | Yes |
| [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490) ([local](/mitre/techniques/T1490.md)) | Cnt ESXi IaaS Lnx Mac NetDev Win | 6 | 48 | 4 | 13 | Yes |
| [T1491 Defacement](https://attack.mitre.org/techniques/T1491) ([local](/mitre/techniques/T1491.md)) | Win IaaS Lnx Mac ESXi | 0 | 0 | 1 | 10 | Yes |
| &nbsp;&nbsp;↳ [.001 Internal Defacement](https://attack.mitre.org/techniques/T1491/001) ([local](/mitre/techniques/T1491-001.md)) | ESXi Lnx Mac Win | 3 | 9 | 1 | 10 | Yes |
| &nbsp;&nbsp;↳ [.002 External Defacement](https://attack.mitre.org/techniques/T1491/002) ([local](/mitre/techniques/T1491-002.md)) | Win IaaS Lnx Mac | 2 | 0 | 1 | 10 | Yes |
| [T1495 Firmware Corruption](https://attack.mitre.org/techniques/T1495) ([local](/mitre/techniques/T1495.md)) | Lnx Mac NetDev Win | 0 | 2 | 3 | 16 | Yes |
| [T1496 Resource Hijacking](https://attack.mitre.org/techniques/T1496) ([local](/mitre/techniques/T1496.md)) | Win IaaS Lnx Mac Cnt SaaS | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.001 Compute Hijacking](https://attack.mitre.org/techniques/T1496/001) ([local](/mitre/techniques/T1496-001.md)) | Win IaaS Lnx Mac Cnt | 4 | 9 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.002 Bandwidth Hijacking](https://attack.mitre.org/techniques/T1496/002) ([local](/mitre/techniques/T1496-002.md)) | Lnx Win Mac IaaS Cnt | 0 | 0 | 0 | 0 | Yes |
| &nbsp;&nbsp;↳ [.003 SMS Pumping](https://attack.mitre.org/techniques/T1496/003) ([local](/mitre/techniques/T1496-003.md)) | SaaS | 0 | 0 | 1 | 1 | Yes |
| &nbsp;&nbsp;↳ [.004 Cloud Service Hijacking](https://attack.mitre.org/techniques/T1496/004) ([local](/mitre/techniques/T1496-004.md)) | SaaS | 0 | 0 | 0 | 0 | Yes |
| [T1498 Network Denial of Service](https://attack.mitre.org/techniques/T1498) ([local](/mitre/techniques/T1498.md)) | Win IaaS Lnx Mac Cnt | 1 | 2 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.001 Direct Network Flood](https://attack.mitre.org/techniques/T1498/001) ([local](/mitre/techniques/T1498-001.md)) | Win IaaS Lnx Mac | 0 | 0 | 1 | 8 | Yes |
| &nbsp;&nbsp;↳ [.002 Reflection Amplification](https://attack.mitre.org/techniques/T1498/002) ([local](/mitre/techniques/T1498-002.md)) | Win IaaS Lnx Mac | 0 | 0 | 1 | 8 | Yes |
| [T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499) ([local](/mitre/techniques/T1499.md)) | Win Lnx Mac Cnt IaaS | 1 | 2 | 1 | 9 | Yes |
| &nbsp;&nbsp;↳ [.001 OS Exhaustion Flood](https://attack.mitre.org/techniques/T1499/001) ([local](/mitre/techniques/T1499-001.md)) | Lnx Mac Win | 0 | 0 | 1 | 9 | Yes |
| &nbsp;&nbsp;↳ [.002 Service Exhaustion Flood](https://attack.mitre.org/techniques/T1499/002) ([local](/mitre/techniques/T1499-002.md)) | Win IaaS Lnx Mac | 0 | 0 | 1 | 9 | Yes |
| &nbsp;&nbsp;↳ [.003 Application Exhaustion Flood](https://attack.mitre.org/techniques/T1499/003) ([local](/mitre/techniques/T1499-003.md)) | Win IaaS Lnx Mac | 0 | 0 | 1 | 9 | Yes |
| &nbsp;&nbsp;↳ [.004 Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004) ([local](/mitre/techniques/T1499-004.md)) | Win IaaS Lnx Mac | 0 | 1 | 1 | 9 | Yes |
| [T1529 System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) ([local](/mitre/techniques/T1529.md)) | ESXi Lnx Mac NetDev Win | 4 | 23 | 0 | 0 | Yes |
| [T1531 Account Access Removal](https://attack.mitre.org/techniques/T1531) ([local](/mitre/techniques/T1531.md)) | Lnx Mac Win SaaS IaaS Office ESXi | 2 | 4 | 0 | 0 | Yes |
| [T1561 Disk Wipe](https://attack.mitre.org/techniques/T1561) ([local](/mitre/techniques/T1561.md)) | Lnx Mac Win NetDev | 0 | 0 | 1 | 10 | Yes |
| &nbsp;&nbsp;↳ [.001 Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) ([local](/mitre/techniques/T1561-001.md)) | Lnx NetDev Win Mac | 2 | 13 | 1 | 10 | Yes |
| &nbsp;&nbsp;↳ [.002 Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) ([local](/mitre/techniques/T1561-002.md)) | Lnx Mac Win NetDev | 5 | 11 | 1 | 10 | Yes |
| [T1565 Data Manipulation](https://attack.mitre.org/techniques/T1565) ([local](/mitre/techniques/T1565.md)) | Lnx Mac Win | 1 | 0 | 4 | 26 | Yes |
| &nbsp;&nbsp;↳ [.001 Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001) ([local](/mitre/techniques/T1565-001.md)) | Lnx Mac Win | 1 | 2 | 3 | 23 | Yes |
| &nbsp;&nbsp;↳ [.002 Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002) ([local](/mitre/techniques/T1565-002.md)) | Lnx Mac Win | 1 | 3 | 1 | 12 | Yes |
| &nbsp;&nbsp;↳ [.003 Runtime Data Manipulation](https://attack.mitre.org/techniques/T1565/003) ([local](/mitre/techniques/T1565-003.md)) | Lnx Mac Win | 1 | 0 | 2 | 13 | Yes |
| [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657) ([local](/mitre/techniques/T1657.md)) | Lnx Mac Office SaaS Win | 14 | 5 | 2 | 2 | Yes |
| [T1667 Email Bombing](https://attack.mitre.org/techniques/T1667) ([local](/mitre/techniques/T1667.md)) | Lnx Office Win Mac | 1 | 0 | 2 | 0 | Yes |

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Threat-informed defense and ATT&CK](/hubs/threat-informed-defense.md)
- [Threat-Informed Defense Reference](/THREAT_INFORMED_DEFENSE_REFERENCE.md)
- [ATT&CK Mitigations Reference](/ATTACK_MITIGATIONS_REFERENCE.md)
- [ATT&CK Matrix Analysis Reference](/ATTACK_MATRIX_ANALYSIS_REFERENCE.md)
- [ATT&CK Software Reference](/ATTACK_SOFTWARE_REFERENCE.md)
- [Mobile ATT&CK Atlas](/MOBILE_ATTACK_ATLAS.md)

<!-- related:end -->

---

*Source: MITRE ATT&CK Enterprise v18.1 (STIX) + CTID NIST 800-53 R5 mappings. Counts reflect non-deprecated ATT&CK objects at time of generation.*
