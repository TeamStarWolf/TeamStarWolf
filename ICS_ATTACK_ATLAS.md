# ICS ATT&CK Technique Atlas

> The complete **MITRE ATT&CK for ICS** matrix (v18.1) — **83 techniques** across 12 tactics — cross-referenced to the threat groups and software that use them and the ATT&CK mitigations that address them. Machine-readable source: [`data/attack/ics/technique_profiles.jsonl`](data/attack/ics/technique_profiles.jsonl).

**Legend** — **Grp** = threat groups · **SW** = software · **Mit** = ATT&CK mitigations · **Det** = ATT&CK detection guidance exists.

Related: [ATT&CK Technique Atlas (Enterprise)](ATTACK_TECHNIQUE_ATLAS.md) · [Threat Group Profiles](THREAT_GROUP_PROFILES.md) · [Threat-Informed Defense](THREAT_INFORMED_DEFENSE_REFERENCE.md) · [ICS/OT Security Reference](ICS_OT_SECURITY_REFERENCE.md)

## Tactics

- [Initial Access](#initial-access) — 12 techniques
- [Execution](#execution) — 10 techniques
- [Persistence](#persistence) — 6 techniques
- [Privilege Escalation](#privilege-escalation) — 2 techniques
- [Evasion](#evasion) — 7 techniques
- [Discovery](#discovery) — 5 techniques
- [Lateral Movement](#lateral-movement) — 7 techniques
- [Collection](#collection) — 11 techniques
- [Command and Control](#command-and-control) — 3 techniques
- [Inhibit Response Function](#inhibit-response-function) — 14 techniques
- [Impair Process Control](#impair-process-control) — 5 techniques
- [Impact](#impact) — 12 techniques

---

## Initial Access
<a id="initial-access"></a>

[`TA0108`](https://attack.mitre.org/tactics/TA0108/) · 12 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0817 Drive-by Compromise](https://attack.mitre.org/techniques/T0817) | None | 4 | 1 | 4 |  |
| [T0819 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T0819) | None | 1 | 0 | 6 |  |
| [T0822 External Remote Services](https://attack.mitre.org/techniques/T0822) | None | 0 | 1 | 7 |  |
| [T0847 Replication Through Removable Media](https://attack.mitre.org/techniques/T0847) | None | 0 | 2 | 3 |  |
| [T0848 Rogue Master](https://attack.mitre.org/techniques/T0848) | None | 0 | 0 | 5 |  |
| [T0860 Wireless Compromise](https://attack.mitre.org/techniques/T0860) | None | 0 | 0 | 4 |  |
| [T0862 Supply Chain Compromise](https://attack.mitre.org/techniques/T0862) | None | 2 | 1 | 5 |  |
| [T0864 Transient Cyber Asset](https://attack.mitre.org/techniques/T0864) | None | 0 | 0 | 5 |  |
| [T0865 Spearphishing Attachment](https://attack.mitre.org/techniques/T0865) | None | 4 | 2 | 4 |  |
| [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866) | None | 0 | 4 | 8 |  |
| [T0883 Internet Accessible Device](https://attack.mitre.org/techniques/T0883) | None | 0 | 1 | 1 |  |
| [T0886 Remote Services](https://attack.mitre.org/techniques/T0886) | None | 0 | 3 | 9 |  |

## Execution
<a id="execution"></a>

[`TA0104`](https://attack.mitre.org/tactics/TA0104/) · 10 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0807 Command-Line Interface](https://attack.mitre.org/techniques/T0807) | None | 1 | 3 | 2 |  |
| [T0821 Modify Controller Tasking](https://attack.mitre.org/techniques/T0821) | None | 0 | 3 | 4 |  |
| [T0823 Graphical User Interface](https://attack.mitre.org/techniques/T0823) | None | 0 | 0 | 1 |  |
| [T0834 Native API](https://attack.mitre.org/techniques/T0834) | None | 0 | 3 | 1 |  |
| [T0853 Scripting](https://attack.mitre.org/techniques/T0853) | None | 2 | 2 | 3 |  |
| [T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858) | None | 0 | 3 | 7 |  |
| [T0863 User Execution](https://attack.mitre.org/techniques/T0863) | None | 0 | 4 | 6 |  |
| [T0871 Execution through API](https://attack.mitre.org/techniques/T0871) | None | 0 | 1 | 4 |  |
| [T0874 Hooking](https://attack.mitre.org/techniques/T0874) | None | 0 | 2 | 2 |  |
| [T0895 Autorun Image](https://attack.mitre.org/techniques/T0895) | — | 0 | 0 | 1 |  |

## Persistence
<a id="persistence"></a>

[`TA0110`](https://attack.mitre.org/tactics/TA0110/) · 6 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0839 Module Firmware](https://attack.mitre.org/techniques/T0839) | None | 0 | 0 | 12 |  |
| [T0857 System Firmware](https://attack.mitre.org/techniques/T0857) | None | 0 | 1 | 13 |  |
| [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859) | None | 2 | 2 | 10 |  |
| [T0873 Project File Infection](https://attack.mitre.org/techniques/T0873) | None | 0 | 1 | 4 |  |
| [T0889 Modify Program](https://attack.mitre.org/techniques/T0889) | None | 0 | 2 | 4 |  |
| [T0891 Hardcoded Credentials](https://attack.mitre.org/techniques/T0891) | None | 0 | 2 | 1 |  |

## Privilege Escalation
<a id="privilege-escalation"></a>

[`TA0111`](https://attack.mitre.org/tactics/TA0111/) · 2 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0874 Hooking](https://attack.mitre.org/techniques/T0874) | None | 0 | 2 | 2 |  |
| [T0890 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T0890) | None | 0 | 2 | 4 |  |

## Evasion
<a id="evasion"></a>

[`TA0103`](https://attack.mitre.org/tactics/TA0103/) · 7 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0820 Exploitation for Evasion](https://attack.mitre.org/techniques/T0820) | None | 0 | 1 | 4 |  |
| [T0849 Masquerading](https://attack.mitre.org/techniques/T0849) | None | 0 | 4 | 3 |  |
| [T0851 Rootkit](https://attack.mitre.org/techniques/T0851) | None | 0 | 1 | 2 |  |
| [T0856 Spoof Reporting Message](https://attack.mitre.org/techniques/T0856) | None | 0 | 0 | 5 |  |
| [T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858) | None | 0 | 3 | 7 |  |
| [T0872 Indicator Removal on Host](https://attack.mitre.org/techniques/T0872) | None | 0 | 2 | 1 |  |
| [T0894 System Binary Proxy Execution](https://attack.mitre.org/techniques/T0894) | None | 0 | 0 | 1 |  |

## Discovery
<a id="discovery"></a>

[`TA0102`](https://attack.mitre.org/tactics/TA0102/) · 5 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0840 Network Connection Enumeration](https://attack.mitre.org/techniques/T0840) | None | 0 | 2 | 1 |  |
| [T0842 Network Sniffing](https://attack.mitre.org/techniques/T0842) | None | 0 | 3 | 5 |  |
| [T0846 Remote System Discovery](https://attack.mitre.org/techniques/T0846) | None | 0 | 5 | 1 |  |
| [T0887 Wireless Sniffing](https://attack.mitre.org/techniques/T0887) | None | 0 | 0 | 2 |  |
| [T0888 Remote System Information Discovery](https://attack.mitre.org/techniques/T0888) | None | 0 | 5 | 1 |  |

## Lateral Movement
<a id="lateral-movement"></a>

[`TA0109`](https://attack.mitre.org/tactics/TA0109/) · 7 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0812 Default Credentials](https://attack.mitre.org/techniques/T0812) | None | 0 | 0 | 2 |  |
| [T0843 Program Download](https://attack.mitre.org/techniques/T0843) | None | 0 | 4 | 10 |  |
| [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859) | None | 2 | 2 | 10 |  |
| [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866) | None | 0 | 4 | 8 |  |
| [T0867 Lateral Tool Transfer](https://attack.mitre.org/techniques/T0867) | None | 0 | 5 | 1 |  |
| [T0886 Remote Services](https://attack.mitre.org/techniques/T0886) | None | 0 | 3 | 9 |  |
| [T0891 Hardcoded Credentials](https://attack.mitre.org/techniques/T0891) | None | 0 | 2 | 1 |  |

## Collection
<a id="collection"></a>

[`TA0100`](https://attack.mitre.org/tactics/TA0100/) · 11 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0801 Monitor Process State](https://attack.mitre.org/techniques/T0801) | None | 0 | 4 | 1 |  |
| [T0802 Automated Collection](https://attack.mitre.org/techniques/T0802) | None | 0 | 3 | 2 |  |
| [T0811 Data from Information Repositories](https://attack.mitre.org/techniques/T0811) | None | 0 | 1 | 6 |  |
| [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830) | None | 0 | 1 | 8 |  |
| [T0845 Program Upload](https://attack.mitre.org/techniques/T0845) | None | 0 | 2 | 8 |  |
| [T0852 Screen Capture](https://attack.mitre.org/techniques/T0852) | None | 2 | 0 | 1 |  |
| [T0861 Point & Tag Identification](https://attack.mitre.org/techniques/T0861) | None | 0 | 2 | 8 |  |
| [T0868 Detect Operating Mode](https://attack.mitre.org/techniques/T0868) | None | 0 | 1 | 8 |  |
| [T0877 I/O Image](https://attack.mitre.org/techniques/T0877) | None | 0 | 1 | 1 |  |
| [T0887 Wireless Sniffing](https://attack.mitre.org/techniques/T0887) | None | 0 | 0 | 2 |  |
| [T0893 Data from Local System](https://attack.mitre.org/techniques/T0893) | None | 0 | 3 | 4 |  |

## Command and Control
<a id="command-and-control"></a>

[`TA0101`](https://attack.mitre.org/tactics/TA0101/) · 3 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0869 Standard Application Layer Protocol](https://attack.mitre.org/techniques/T0869) | None | 1 | 6 | 3 |  |
| [T0884 Connection Proxy](https://attack.mitre.org/techniques/T0884) | None | 1 | 2 | 4 |  |
| [T0885 Commonly Used Port](https://attack.mitre.org/techniques/T0885) | None | 0 | 3 | 4 |  |

## Inhibit Response Function
<a id="inhibit-response-function"></a>

[`TA0107`](https://attack.mitre.org/tactics/TA0107/) · 14 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0800 Activate Firmware Update Mode](https://attack.mitre.org/techniques/T0800) | None | 0 | 1 | 8 |  |
| [T0803 Block Command Message](https://attack.mitre.org/techniques/T0803) | None | 0 | 1 | 3 |  |
| [T0804 Block Reporting Message](https://attack.mitre.org/techniques/T0804) | None | 0 | 1 | 3 |  |
| [T0805 Block Serial COM](https://attack.mitre.org/techniques/T0805) | None | 0 | 1 | 3 |  |
| [T0809 Data Destruction](https://attack.mitre.org/techniques/T0809) | None | 0 | 4 | 3 |  |
| [T0814 Denial of Service](https://attack.mitre.org/techniques/T0814) | None | 0 | 4 | 1 |  |
| [T0816 Device Restart/Shutdown](https://attack.mitre.org/techniques/T0816) | None | 0 | 1 | 9 |  |
| [T0835 Manipulate I/O Image](https://attack.mitre.org/techniques/T0835) | None | 0 | 2 | 1 |  |
| [T0838 Modify Alarm Settings](https://attack.mitre.org/techniques/T0838) | None | 0 | 0 | 7 |  |
| [T0851 Rootkit](https://attack.mitre.org/techniques/T0851) | None | 0 | 1 | 2 |  |
| [T0857 System Firmware](https://attack.mitre.org/techniques/T0857) | None | 0 | 1 | 13 |  |
| [T0878 Alarm Suppression](https://attack.mitre.org/techniques/T0878) | None | 0 | 0 | 4 |  |
| [T0881 Service Stop](https://attack.mitre.org/techniques/T0881) | None | 0 | 5 | 4 |  |
| [T0892 Change Credential](https://attack.mitre.org/techniques/T0892) | None | 0 | 0 | 3 |  |

## Impair Process Control
<a id="impair-process-control"></a>

[`TA0106`](https://attack.mitre.org/tactics/TA0106/) · 5 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0806 Brute Force I/O](https://attack.mitre.org/techniques/T0806) | None | 0 | 3 | 4 |  |
| [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836) | None | 0 | 4 | 4 |  |
| [T0839 Module Firmware](https://attack.mitre.org/techniques/T0839) | None | 0 | 0 | 12 |  |
| [T0855 Unauthorized Command Message](https://attack.mitre.org/techniques/T0855) | None | 0 | 3 | 6 |  |
| [T0856 Spoof Reporting Message](https://attack.mitre.org/techniques/T0856) | None | 0 | 0 | 5 |  |

## Impact
<a id="impact"></a>

[`TA0105`](https://attack.mitre.org/tactics/TA0105/) · 12 techniques

| Technique | Platforms | Grp | SW | Mit | Det |
|---|---|--:|--:|--:|:--:|
| [T0813 Denial of Control](https://attack.mitre.org/techniques/T0813) | None | 0 | 1 | 3 |  |
| [T0815 Denial of View](https://attack.mitre.org/techniques/T0815) | None | 0 | 1 | 3 |  |
| [T0826 Loss of Availability](https://attack.mitre.org/techniques/T0826) | None | 0 | 1 | 3 |  |
| [T0827 Loss of Control](https://attack.mitre.org/techniques/T0827) | None | 0 | 2 | 3 |  |
| [T0828 Loss of Productivity and Revenue](https://attack.mitre.org/techniques/T0828) | None | 0 | 7 | 1 |  |
| [T0829 Loss of View](https://attack.mitre.org/techniques/T0829) | None | 0 | 4 | 3 |  |
| [T0831 Manipulation of Control](https://attack.mitre.org/techniques/T0831) | None | 0 | 2 | 3 |  |
| [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832) | None | 0 | 2 | 3 |  |
| [T0837 Loss of Protection](https://attack.mitre.org/techniques/T0837) | None | 0 | 1 | 0 |  |
| [T0879 Damage to Property](https://attack.mitre.org/techniques/T0879) | None | 0 | 0 | 3 |  |
| [T0880 Loss of Safety](https://attack.mitre.org/techniques/T0880) | None | 0 | 1 | 2 |  |
| [T0882 Theft of Operational Information](https://attack.mitre.org/techniques/T0882) | None | 0 | 4 | 4 |  |

---

*Source: MITRE ATT&CK for ICS v18.1 (STIX). Counts reflect non-deprecated objects.*
