# ICS ATT&CK Technique Atlas

<!-- generated: written by scripts/build_attack_atlases.py from data/attack (ATT&CK v20.0); edit the script, not this page. The header card and the related-pages footer belong to build_doc_meta.py and build_crosslinks.py. -->

> The complete MITRE ATT&CK for ICS matrix (v20.0), 104 techniques and sub-techniques (78 techniques, 26 sub-techniques) across 12 tactics, cross-referenced to the threat groups and software that use them and the ATT&CK mitigations that address them. Machine-readable source: [`data/attack/ics/technique_profiles.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/ics/technique_profiles.jsonl).

Legend: Grp = threat groups, SW = software, Mit = ATT&CK mitigations, Det = ATT&CK detection guidance exists.

A technique that serves more than one tactic is listed under each. Techniques that ATT&CK has revoked or deprecated are left out; [`data/attack/superseded_by.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/superseded_by.jsonl) names the technique that replaces each one, where there is one.

Related: [ATT&CK Technique Atlas (Enterprise)](ATTACK_TECHNIQUE_ATLAS.md), [Threat Group Profiles](THREAT_GROUP_PROFILES.md), [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md), [ICS/OT Security Reference](ICS_OT_SECURITY_REFERENCE.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

ICS and OT defenders and threat intelligence analysts

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Length</th><td>

Lookup page: 1,750 words, 83% in tables; look entries up from Start at or the search (about 8 min end to end at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need to look up an ICS ATT&CK technique by tactic, you want to check which threat groups or software use a technique, or you need the ATT&CK mitigations that address it

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Tactics](#tactics) for the full tactic index, then jump to ICS-specific tactics like [Inhibit Response Function](#inhibit-response-function) or [Impair Process Control](#impair-process-control)

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
- [Execution](#execution): 15 techniques
- [Persistence](#persistence): 10 techniques
- [Privilege Escalation](#privilege-escalation): 2 techniques
- [Evasion](#evasion): 9 techniques
- [Discovery](#discovery): 8 techniques
- [Lateral Movement](#lateral-movement): 11 techniques
- [Collection](#collection): 11 techniques
- [Command and Control](#command-and-control): 5 techniques
- [Inhibit Response Function](#inhibit-response-function): 20 techniques
- [Impair Process Control](#impair-process-control): 8 techniques
- [Impact](#impact): 12 techniques

---

## Initial Access
<a id="initial-access"></a>

[`TA0108`](https://attack.mitre.org/tactics/TA0108/), 12 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0817 Drive-by Compromise](https://attack.mitre.org/techniques/T0817) | Windows, Linux | 4 | 1 | 4 | Yes |
| [T0819 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T0819) | Embedded, Windows, Linux, Network Devices | 1 | 0 | 6 | Yes |
| [T0822 External Remote Services](https://attack.mitre.org/techniques/T0822) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 7 | Yes |
| [T0847 Replication Through Removable Media](https://attack.mitre.org/techniques/T0847) | Embedded, Windows, Linux, Network Devices | 0 | 2 | 3 | Yes |
| [T0848 Rogue Master](https://attack.mitre.org/techniques/T0848) | Embedded, Windows, Linux, Network Devices | 0 | 0 | 5 | Yes |
| [T0860 Wireless Compromise](https://attack.mitre.org/techniques/T0860) | Embedded, Windows, Linux | 0 | 0 | 4 | Yes |
| [T0862 Supply Chain Compromise](https://attack.mitre.org/techniques/T0862) | Embedded, Windows, Linux, Network Devices | 2 | 1 | 5 | Yes |
| [T0864 Transient Cyber Asset](https://attack.mitre.org/techniques/T0864) | Windows, Linux | 0 | 0 | 5 | Yes |
| [T0865 Spearphishing Attachment](https://attack.mitre.org/techniques/T0865) | Embedded, Windows, Linux | 4 | 2 | 4 | Yes |
| [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866) | Embedded, Windows, Linux, Network Devices | 0 | 4 | 8 | Yes |
| [T0883 Internet Accessible Device](https://attack.mitre.org/techniques/T0883) | Embedded, Windows, Linux, Network Devices | 1 | 1 | 1 | Yes |
| [T0886 Remote Services](https://attack.mitre.org/techniques/T0886) | Embedded, Windows, Linux, Network Devices | 1 | 3 | 9 | Yes |

## Execution
<a id="execution"></a>

[`TA0104`](https://attack.mitre.org/tactics/TA0104/), 15 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0821 Modify Controller Tasking](https://attack.mitre.org/techniques/T0821) | Embedded | 0 | 3 | 4 | Yes |
| [T0823 Graphical User Interface](https://attack.mitre.org/techniques/T0823) | Embedded, Windows, Linux, Network Devices | 0 | 0 | 1 | Yes |
| [T0834 Native API](https://attack.mitre.org/techniques/T0834) | Embedded, Windows, Linux, Network Devices | 0 | 3 | 1 | Yes |
| [T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858) | Embedded | 0 | 3 | 7 | Yes |
| [T0863 User Execution](https://attack.mitre.org/techniques/T0863) | Embedded, Windows, Linux | 0 | 4 | 6 | Yes |
| [T0871 Execution through API](https://attack.mitre.org/techniques/T0871) | Embedded, Windows, Linux, Network Devices | 1 | 1 | 4 | Yes |
| [T0874 Hooking](https://attack.mitre.org/techniques/T0874) | Embedded, Windows, Linux, Network Devices | 0 | 2 | 2 | Yes |
| [T0895 Autorun Image](https://attack.mitre.org/techniques/T0895) | Embedded, Windows, Linux | 0 | 0 | 1 | Yes |
| [T1701 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1701) | None | 0 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 PowerShell](https://attack.mitre.org/techniques/T1701/001) | None | 3 | 1 | 5 | Yes |
| &nbsp;&nbsp;↳ [.002 Windows Command Shell](https://attack.mitre.org/techniques/T1701/002) | None | 1 | 2 | 1 | Yes |
| &nbsp;&nbsp;↳ [.003 Unix Shell](https://attack.mitre.org/techniques/T1701/003) | None | 0 | 1 | 1 | Yes |
| &nbsp;&nbsp;↳ [.004 Visual Basic](https://attack.mitre.org/techniques/T1701/004) | None | 1 | 0 | 5 | Yes |
| &nbsp;&nbsp;↳ [.005 Python](https://attack.mitre.org/techniques/T1701/005) | None | 0 | 1 | 4 | Yes |
| &nbsp;&nbsp;↳ [.006 JavaScript](https://attack.mitre.org/techniques/T1701/006) | None | 0 | 1 | 4 | Yes |

## Persistence
<a id="persistence"></a>

[`TA0110`](https://attack.mitre.org/tactics/TA0110/), 10 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859) | Embedded, Windows, Linux, Network Devices | 2 | 2 | 10 | Yes |
| [T0873 Project File Infection](https://attack.mitre.org/techniques/T0873) | Windows, Linux | 0 | 0 | 4 | Yes |
| &nbsp;&nbsp;↳ [.001 Siemens Project File Format](https://attack.mitre.org/techniques/T0873/001) | Windows, Linux | 0 | 1 | 4 | Yes |
| [T0889 Modify Program](https://attack.mitre.org/techniques/T0889) | Embedded | 1 | 2 | 4 | Yes |
| [T1693 Modify Firmware](https://attack.mitre.org/techniques/T1693) | Embedded | 0 | 0 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 System Firmware](https://attack.mitre.org/techniques/T1693/001) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 13 | Yes |
| &nbsp;&nbsp;↳ [.002 Module Firmware](https://attack.mitre.org/techniques/T1693/002) | Embedded | 0 | 0 | 12 | Yes |
| [T1694 Insecure Credentials](https://attack.mitre.org/techniques/T1694) | Embedded, Windows, Linux, Network Devices | 0 | 0 | 1 | Yes |
| &nbsp;&nbsp;↳ [.001 Default Credentials](https://attack.mitre.org/techniques/T1694/001) | Embedded, Windows, Linux, Network Devices | 1 | 0 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 Hardcoded Credentials](https://attack.mitre.org/techniques/T1694/002) | Embedded | 0 | 2 | 1 | Yes |

## Privilege Escalation
<a id="privilege-escalation"></a>

[`TA0111`](https://attack.mitre.org/tactics/TA0111/), 2 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0874 Hooking](https://attack.mitre.org/techniques/T0874) | Embedded, Windows, Linux, Network Devices | 0 | 2 | 2 | Yes |
| [T0890 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T0890) | Embedded, Windows, Linux, Network Devices | 0 | 2 | 4 | Yes |

## Evasion
<a id="evasion"></a>

[`TA0103`](https://attack.mitre.org/tactics/TA0103/), 9 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0820 Exploitation for Evasion](https://attack.mitre.org/techniques/T0820) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 4 | Yes |
| [T0849 Masquerading](https://attack.mitre.org/techniques/T0849) | Embedded, Windows, Linux, Network Devices | 0 | 4 | 3 | Yes |
| [T0851 Rootkit](https://attack.mitre.org/techniques/T0851) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 2 | Yes |
| [T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858) | Embedded | 0 | 3 | 7 | Yes |
| [T0872 Indicator Removal on Host](https://attack.mitre.org/techniques/T0872) | Embedded, Windows, Linux, Network Devices | 0 | 2 | 1 | Yes |
| [T0894 System Binary Proxy Execution](https://attack.mitre.org/techniques/T0894) | Embedded, Windows, Linux | 0 | 0 | 1 | Yes |
| [T1692 Unauthorized Message](https://attack.mitre.org/techniques/T1692) | Embedded, Windows, Linux | 0 | 0 | 5 | Yes |
| &nbsp;&nbsp;↳ [.001 Command Message](https://attack.mitre.org/techniques/T1692/001) | Embedded, Windows, Linux | 1 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.002 Reporting Message](https://attack.mitre.org/techniques/T1692/002) | Embedded, Windows, Linux, Network Devices | 0 | 0 | 5 | Yes |

## Discovery
<a id="discovery"></a>

[`TA0102`](https://attack.mitre.org/tactics/TA0102/), 8 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0840 Network Connection Enumeration](https://attack.mitre.org/techniques/T0840) | Embedded, Windows, Linux, Network Devices | 0 | 2 | 1 | Yes |
| [T0842 Network Sniffing](https://attack.mitre.org/techniques/T0842) | Embedded, Windows, Linux, Network Devices | 0 | 3 | 5 | Yes |
| [T0846 Remote System Discovery](https://attack.mitre.org/techniques/T0846) | Embedded, Windows, Linux, Network Devices | 0 | 3 | 1 | Yes |
| &nbsp;&nbsp;↳ [.001 Port Scan](https://attack.mitre.org/techniques/T0846/001) | Embedded, Windows, Linux, Network Devices | 0 | 4 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Broadcast Discovery](https://attack.mitre.org/techniques/T0846/002) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 2 | Yes |
| &nbsp;&nbsp;↳ [.003 Multicast Discovery](https://attack.mitre.org/techniques/T0846/003) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 2 | Yes |
| [T0887 Wireless Sniffing](https://attack.mitre.org/techniques/T0887) | Embedded, Windows, Linux | 0 | 0 | 2 | Yes |
| [T0888 Remote System Information Discovery](https://attack.mitre.org/techniques/T0888) | Embedded, Windows, Linux, Network Devices | 0 | 5 | 1 | Yes |

## Lateral Movement
<a id="lateral-movement"></a>

[`TA0109`](https://attack.mitre.org/tactics/TA0109/), 11 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0843 Program Download](https://attack.mitre.org/techniques/T0843) | Embedded | 1 | 4 | 10 | Yes |
| &nbsp;&nbsp;↳ [.001 Download All](https://attack.mitre.org/techniques/T0843/001) | Embedded | 0 | 1 | 10 | Yes |
| &nbsp;&nbsp;↳ [.002 Online Edit](https://attack.mitre.org/techniques/T0843/002) | Embedded | 0 | 0 | 10 | Yes |
| &nbsp;&nbsp;↳ [.003 Program Append](https://attack.mitre.org/techniques/T0843/003) | Embedded | 0 | 0 | 10 | Yes |
| [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859) | Embedded, Windows, Linux, Network Devices | 2 | 2 | 10 | Yes |
| [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866) | Embedded, Windows, Linux, Network Devices | 0 | 4 | 8 | Yes |
| [T0867 Lateral Tool Transfer](https://attack.mitre.org/techniques/T0867) | Embedded, Windows, Linux | 0 | 5 | 1 | Yes |
| [T0886 Remote Services](https://attack.mitre.org/techniques/T0886) | Embedded, Windows, Linux, Network Devices | 1 | 3 | 9 | Yes |
| [T1694 Insecure Credentials](https://attack.mitre.org/techniques/T1694) | Embedded, Windows, Linux, Network Devices | 0 | 0 | 1 | Yes |
| &nbsp;&nbsp;↳ [.001 Default Credentials](https://attack.mitre.org/techniques/T1694/001) | Embedded, Windows, Linux, Network Devices | 1 | 0 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 Hardcoded Credentials](https://attack.mitre.org/techniques/T1694/002) | Embedded | 0 | 2 | 1 | Yes |

## Collection
<a id="collection"></a>

[`TA0100`](https://attack.mitre.org/tactics/TA0100/), 11 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0801 Monitor Process State](https://attack.mitre.org/techniques/T0801) | Embedded, Windows, Linux, Network Devices | 0 | 4 | 1 | Yes |
| [T0802 Automated Collection](https://attack.mitre.org/techniques/T0802) | Embedded, Windows, Linux | 0 | 3 | 2 | Yes |
| [T0811 Data from Information Repositories](https://attack.mitre.org/techniques/T0811) | Embedded, Windows, Linux | 0 | 1 | 6 | Yes |
| [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 8 | Yes |
| [T0845 Program Upload](https://attack.mitre.org/techniques/T0845) | Embedded | 1 | 2 | 8 | Yes |
| [T0852 Screen Capture](https://attack.mitre.org/techniques/T0852) | Embedded, Windows, Linux | 2 | 0 | 1 | Yes |
| [T0861 Point & Tag Identification](https://attack.mitre.org/techniques/T0861) | Embedded, Windows, Linux, Network Devices | 0 | 2 | 8 | Yes |
| [T0868 Detect Operating Mode](https://attack.mitre.org/techniques/T0868) | Embedded | 0 | 1 | 8 | Yes |
| [T0877 I/O Image](https://attack.mitre.org/techniques/T0877) | Embedded | 0 | 1 | 1 | Yes |
| [T0887 Wireless Sniffing](https://attack.mitre.org/techniques/T0887) | Embedded, Windows, Linux | 0 | 0 | 2 | Yes |
| [T0893 Data from Local System](https://attack.mitre.org/techniques/T0893) | Embedded, Windows, Linux, Network Devices | 0 | 3 | 4 | Yes |

## Command and Control
<a id="command-and-control"></a>

[`TA0101`](https://attack.mitre.org/tactics/TA0101/), 5 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0869 Standard Application Layer Protocol](https://attack.mitre.org/techniques/T0869) | Embedded, Windows, Linux, Network Devices | 1 | 6 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 DNS](https://attack.mitre.org/techniques/T0869/001) | None | 0 | 1 | 2 | Yes |
| &nbsp;&nbsp;↳ [.002 Publish/Subscribe Protocols](https://attack.mitre.org/techniques/T0869/002) | None | 0 | 1 | 2 | Yes |
| [T0884 Connection Proxy](https://attack.mitre.org/techniques/T0884) | Embedded, Windows, Linux, Network Devices | 1 | 2 | 4 | Yes |
| [T0885 Commonly Used Port](https://attack.mitre.org/techniques/T0885) | Embedded, Windows, Linux, Network Devices | 1 | 3 | 4 | Yes |

## Inhibit Response Function
<a id="inhibit-response-function"></a>

[`TA0107`](https://attack.mitre.org/tactics/TA0107/), 20 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0800 Activate Firmware Update Mode](https://attack.mitre.org/techniques/T0800) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 8 | Yes |
| [T0809 Data Destruction](https://attack.mitre.org/techniques/T0809) | Embedded, Windows, Linux, Network Devices | 0 | 4 | 3 | Yes |
| [T0814 Denial of Service](https://attack.mitre.org/techniques/T0814) | Embedded, Windows, Linux, Network Devices | 0 | 4 | 1 | Yes |
| [T0816 Device Restart/Shutdown](https://attack.mitre.org/techniques/T0816) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 9 | Yes |
| [T0835 Manipulate I/O Image](https://attack.mitre.org/techniques/T0835) | Embedded | 0 | 2 | 1 | Yes |
| [T0838 Modify Alarm Settings](https://attack.mitre.org/techniques/T0838) | Embedded, Windows, Linux, Network Devices | 1 | 0 | 7 | Yes |
| [T0851 Rootkit](https://attack.mitre.org/techniques/T0851) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 2 | Yes |
| [T0878 Alarm Suppression](https://attack.mitre.org/techniques/T0878) | Embedded, Windows, Linux, Network Devices | 0 | 0 | 4 | Yes |
| [T0881 Service Stop](https://attack.mitre.org/techniques/T0881) | Embedded, Windows, Linux, Network Devices | 0 | 5 | 4 | Yes |
| [T0892 Change Credential](https://attack.mitre.org/techniques/T0892) | Embedded, Windows, Linux, Network Devices | 1 | 0 | 3 | Yes |
| [T1691 Block Operational Technology Message](https://attack.mitre.org/techniques/T1691) | Embedded, Windows, Linux | 0 | 0 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 Command Message](https://attack.mitre.org/techniques/T1691/001) | Embedded, Windows, Linux | 0 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Reporting Message](https://attack.mitre.org/techniques/T1691/002) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 3 | Yes |
| [T1693 Modify Firmware](https://attack.mitre.org/techniques/T1693) | Embedded | 0 | 0 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 System Firmware](https://attack.mitre.org/techniques/T1693/001) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 13 | Yes |
| &nbsp;&nbsp;↳ [.002 Module Firmware](https://attack.mitre.org/techniques/T1693/002) | Embedded | 0 | 0 | 12 | Yes |
| [T1695 Block Communications](https://attack.mitre.org/techniques/T1695) | Embedded, Windows, Linux, Network Devices | 1 | 0 | 3 | Yes |
| &nbsp;&nbsp;↳ [.001 Serial COM](https://attack.mitre.org/techniques/T1695/001) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.002 Ethernet](https://attack.mitre.org/techniques/T1695/002) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 3 | Yes |
| &nbsp;&nbsp;↳ [.003 Wi-Fi](https://attack.mitre.org/techniques/T1695/003) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 3 | Yes |

## Impair Process Control
<a id="impair-process-control"></a>

[`TA0106`](https://attack.mitre.org/tactics/TA0106/), 8 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0806 Brute Force I/O](https://attack.mitre.org/techniques/T0806) | Embedded, Windows, Linux | 0 | 3 | 4 | Yes |
| [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836) | Embedded, Windows, Linux | 0 | 4 | 4 | Yes |
| [T1692 Unauthorized Message](https://attack.mitre.org/techniques/T1692) | Embedded, Windows, Linux | 0 | 0 | 5 | Yes |
| &nbsp;&nbsp;↳ [.001 Command Message](https://attack.mitre.org/techniques/T1692/001) | Embedded, Windows, Linux | 1 | 3 | 6 | Yes |
| &nbsp;&nbsp;↳ [.002 Reporting Message](https://attack.mitre.org/techniques/T1692/002) | Embedded, Windows, Linux, Network Devices | 0 | 0 | 5 | Yes |
| [T1693 Modify Firmware](https://attack.mitre.org/techniques/T1693) | Embedded | 0 | 0 | 12 | Yes |
| &nbsp;&nbsp;↳ [.001 System Firmware](https://attack.mitre.org/techniques/T1693/001) | Embedded, Windows, Linux, Network Devices | 0 | 1 | 13 | Yes |
| &nbsp;&nbsp;↳ [.002 Module Firmware](https://attack.mitre.org/techniques/T1693/002) | Embedded | 0 | 0 | 12 | Yes |

## Impact
<a id="impact"></a>

[`TA0105`](https://attack.mitre.org/tactics/TA0105/), 12 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0813 Denial of Control](https://attack.mitre.org/techniques/T0813) | None | 0 | 1 | 3 | Yes |
| [T0815 Denial of View](https://attack.mitre.org/techniques/T0815) | None | 0 | 1 | 3 | Yes |
| [T0826 Loss of Availability](https://attack.mitre.org/techniques/T0826) | None | 1 | 1 | 3 | Yes |
| [T0827 Loss of Control](https://attack.mitre.org/techniques/T0827) | None | 1 | 2 | 3 | Yes |
| [T0828 Loss of Productivity and Revenue](https://attack.mitre.org/techniques/T0828) | None | 0 | 7 | 1 | Yes |
| [T0829 Loss of View](https://attack.mitre.org/techniques/T0829) | None | 1 | 4 | 3 | Yes |
| [T0831 Manipulation of Control](https://attack.mitre.org/techniques/T0831) | None | 0 | 2 | 3 | Yes |
| [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832) | None | 0 | 2 | 3 | Yes |
| [T0837 Loss of Protection](https://attack.mitre.org/techniques/T0837) | None | 0 | 1 | 0 | Yes |
| [T0879 Damage to Property](https://attack.mitre.org/techniques/T0879) | None | 1 | 0 | 3 | Yes |
| [T0880 Loss of Safety](https://attack.mitre.org/techniques/T0880) | None | 1 | 1 | 2 | Yes |
| [T0882 Theft of Operational Information](https://attack.mitre.org/techniques/T0882) | None | 0 | 4 | 4 | Yes |

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [ICS, OT, and hardware](/hubs/ics-ot-and-hardware.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [EMB3D Reference (Embedded Devices)](/EMB3D_REFERENCE.md)

<!-- related:end -->

---

*Source: MITRE ATT&CK for ICS v20.0 (STIX), through data/attack/ics/technique_profiles.jsonl. Counts are of live (not revoked or deprecated) objects. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*
