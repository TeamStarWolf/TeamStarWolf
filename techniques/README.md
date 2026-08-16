# ATT&CK Technique Detail — Index

> Consolidated detail pages for all **691 MITRE ATT&CK Enterprise techniques** (v18.1), grouped by primary tactic. Each links its ATT&CK description, mitigations, NIST 800-53 controls, detections, and the groups and software that use it.

**By tactic:** [Reconnaissance](reconnaissance.md) · [Resource Development](resource-development.md) · [Initial Access](initial-access.md) · [Execution](execution.md) · [Persistence](persistence.md) · [Privilege Escalation](privilege-escalation.md) · [Defense Evasion](defense-evasion.md) · [Credential Access](credential-access.md) · [Discovery](discovery.md) · [Lateral Movement](lateral-movement.md) · [Collection](collection.md) · [Command and Control](command-and-control.md) · [Exfiltration](exfiltration.md) · [Impact](impact.md)

See also: [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) (matrix view) · [Threat Group Profiles](../THREAT_GROUP_PROFILES.md) · [Software Reference](../ATTACK_SOFTWARE_REFERENCE.md) · [Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md)

| Technique | Name | Detail page |
|---|---|---|
| `T1001` | Data Obfuscation | [Command and Control](command-and-control.md#t1001) |
| `T1001.001` | Junk Data | [Command and Control](command-and-control.md#t1001001) |
| `T1001.002` | Steganography | [Command and Control](command-and-control.md#t1001002) |
| `T1001.003` | Protocol or Service Impersonation | [Command and Control](command-and-control.md#t1001003) |
| `T1003` | OS Credential Dumping | [Credential Access](credential-access.md#t1003) |
| `T1003.001` | LSASS Memory | [Credential Access](credential-access.md#t1003001) |
| `T1003.002` | Security Account Manager | [Credential Access](credential-access.md#t1003002) |
| `T1003.003` | NTDS | [Credential Access](credential-access.md#t1003003) |
| `T1003.004` | LSA Secrets | [Credential Access](credential-access.md#t1003004) |
| `T1003.005` | Cached Domain Credentials | [Credential Access](credential-access.md#t1003005) |
| `T1003.006` | DCSync | [Credential Access](credential-access.md#t1003006) |
| `T1003.007` | Proc Filesystem | [Credential Access](credential-access.md#t1003007) |
| `T1003.008` | /etc/passwd and /etc/shadow | [Credential Access](credential-access.md#t1003008) |
| `T1005` | Data from Local System | [Collection](collection.md#t1005) |
| `T1006` | Direct Volume Access | [Defense Evasion](defense-evasion.md#t1006) |
| `T1007` | System Service Discovery | [Discovery](discovery.md#t1007) |
| `T1008` | Fallback Channels | [Command and Control](command-and-control.md#t1008) |
| `T1010` | Application Window Discovery | [Discovery](discovery.md#t1010) |
| `T1011` | Exfiltration Over Other Network Medium | [Exfiltration](exfiltration.md#t1011) |
| `T1011.001` | Exfiltration Over Bluetooth | [Exfiltration](exfiltration.md#t1011001) |
| `T1012` | Query Registry | [Discovery](discovery.md#t1012) |
| `T1014` | Rootkit | [Defense Evasion](defense-evasion.md#t1014) |
| `T1016` | System Network Configuration Discovery | [Discovery](discovery.md#t1016) |
| `T1016.001` | Internet Connection Discovery | [Discovery](discovery.md#t1016001) |
| `T1016.002` | Wi-Fi Discovery | [Discovery](discovery.md#t1016002) |
| `T1018` | Remote System Discovery | [Discovery](discovery.md#t1018) |
| `T1020` | Automated Exfiltration | [Exfiltration](exfiltration.md#t1020) |
| `T1020.001` | Traffic Duplication | [Exfiltration](exfiltration.md#t1020001) |
| `T1021` | Remote Services | [Lateral Movement](lateral-movement.md#t1021) |
| `T1021.001` | Remote Desktop Protocol | [Lateral Movement](lateral-movement.md#t1021001) |
| `T1021.002` | SMB/Windows Admin Shares | [Lateral Movement](lateral-movement.md#t1021002) |
| `T1021.003` | Distributed Component Object Model | [Lateral Movement](lateral-movement.md#t1021003) |
| `T1021.004` | SSH | [Lateral Movement](lateral-movement.md#t1021004) |
| `T1021.005` | VNC | [Lateral Movement](lateral-movement.md#t1021005) |
| `T1021.006` | Windows Remote Management | [Lateral Movement](lateral-movement.md#t1021006) |
| `T1021.007` | Cloud Services | [Lateral Movement](lateral-movement.md#t1021007) |
| `T1021.008` | Direct Cloud VM Connections | [Lateral Movement](lateral-movement.md#t1021008) |
| `T1025` | Data from Removable Media | [Collection](collection.md#t1025) |
| `T1027` | Obfuscated Files or Information | [Defense Evasion](defense-evasion.md#t1027) |
| `T1027.001` | Binary Padding | [Defense Evasion](defense-evasion.md#t1027001) |
| `T1027.002` | Software Packing | [Defense Evasion](defense-evasion.md#t1027002) |
| `T1027.003` | Steganography | [Defense Evasion](defense-evasion.md#t1027003) |
| `T1027.004` | Compile After Delivery | [Defense Evasion](defense-evasion.md#t1027004) |
| `T1027.005` | Indicator Removal from Tools | [Defense Evasion](defense-evasion.md#t1027005) |
| `T1027.006` | HTML Smuggling | [Defense Evasion](defense-evasion.md#t1027006) |
| `T1027.007` | Dynamic API Resolution | [Defense Evasion](defense-evasion.md#t1027007) |
| `T1027.008` | Stripped Payloads | [Defense Evasion](defense-evasion.md#t1027008) |
| `T1027.009` | Embedded Payloads | [Defense Evasion](defense-evasion.md#t1027009) |
| `T1027.010` | Command Obfuscation | [Defense Evasion](defense-evasion.md#t1027010) |
| `T1027.011` | Fileless Storage | [Defense Evasion](defense-evasion.md#t1027011) |
| `T1027.012` | LNK Icon Smuggling | [Defense Evasion](defense-evasion.md#t1027012) |
| `T1027.013` | Encrypted/Encoded File | [Defense Evasion](defense-evasion.md#t1027013) |
| `T1027.014` | Polymorphic Code | [Defense Evasion](defense-evasion.md#t1027014) |
| `T1027.015` | Compression | [Defense Evasion](defense-evasion.md#t1027015) |
| `T1027.016` | Junk Code Insertion | [Defense Evasion](defense-evasion.md#t1027016) |
| `T1027.017` | SVG Smuggling | [Defense Evasion](defense-evasion.md#t1027017) |
| `T1029` | Scheduled Transfer | [Exfiltration](exfiltration.md#t1029) |
| `T1030` | Data Transfer Size Limits | [Exfiltration](exfiltration.md#t1030) |
| `T1033` | System Owner/User Discovery | [Discovery](discovery.md#t1033) |
| `T1036` | Masquerading | [Defense Evasion](defense-evasion.md#t1036) |
| `T1036.001` | Invalid Code Signature | [Defense Evasion](defense-evasion.md#t1036001) |
| `T1036.002` | Right-to-Left Override | [Defense Evasion](defense-evasion.md#t1036002) |
| `T1036.003` | Rename Legitimate Utilities | [Defense Evasion](defense-evasion.md#t1036003) |
| `T1036.004` | Masquerade Task or Service | [Defense Evasion](defense-evasion.md#t1036004) |
| `T1036.005` | Match Legitimate Resource Name or Location | [Defense Evasion](defense-evasion.md#t1036005) |
| `T1036.006` | Space after Filename | [Defense Evasion](defense-evasion.md#t1036006) |
| `T1036.007` | Double File Extension | [Defense Evasion](defense-evasion.md#t1036007) |
| `T1036.008` | Masquerade File Type | [Defense Evasion](defense-evasion.md#t1036008) |
| `T1036.009` | Break Process Trees | [Defense Evasion](defense-evasion.md#t1036009) |
| `T1036.010` | Masquerade Account Name | [Defense Evasion](defense-evasion.md#t1036010) |
| `T1036.011` | Overwrite Process Arguments | [Defense Evasion](defense-evasion.md#t1036011) |
| `T1036.012` | Browser Fingerprint | [Defense Evasion](defense-evasion.md#t1036012) |
| `T1037` | Boot or Logon Initialization Scripts | [Persistence](persistence.md#t1037) |
| `T1037.001` | Logon Script (Windows) | [Persistence](persistence.md#t1037001) |
| `T1037.002` | Login Hook | [Persistence](persistence.md#t1037002) |
| `T1037.003` | Network Logon Script | [Persistence](persistence.md#t1037003) |
| `T1037.004` | RC Scripts | [Persistence](persistence.md#t1037004) |
| `T1037.005` | Startup Items | [Persistence](persistence.md#t1037005) |
| `T1039` | Data from Network Shared Drive | [Collection](collection.md#t1039) |
| `T1040` | Network Sniffing | [Credential Access](credential-access.md#t1040) |
| `T1041` | Exfiltration Over C2 Channel | [Exfiltration](exfiltration.md#t1041) |
| `T1046` | Network Service Discovery | [Discovery](discovery.md#t1046) |
| `T1047` | Windows Management Instrumentation | [Execution](execution.md#t1047) |
| `T1048` | Exfiltration Over Alternative Protocol | [Exfiltration](exfiltration.md#t1048) |
| `T1048.001` | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | [Exfiltration](exfiltration.md#t1048001) |
| `T1048.002` | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | [Exfiltration](exfiltration.md#t1048002) |
| `T1048.003` | Exfiltration Over Unencrypted Non-C2 Protocol | [Exfiltration](exfiltration.md#t1048003) |
| `T1049` | System Network Connections Discovery | [Discovery](discovery.md#t1049) |
| `T1052` | Exfiltration Over Physical Medium | [Exfiltration](exfiltration.md#t1052) |
| `T1052.001` | Exfiltration over USB | [Exfiltration](exfiltration.md#t1052001) |
| `T1053` | Scheduled Task/Job | [Execution](execution.md#t1053) |
| `T1053.002` | At | [Execution](execution.md#t1053002) |
| `T1053.003` | Cron | [Execution](execution.md#t1053003) |
| `T1053.005` | Scheduled Task | [Execution](execution.md#t1053005) |
| `T1053.006` | Systemd Timers | [Execution](execution.md#t1053006) |
| `T1053.007` | Container Orchestration Job | [Execution](execution.md#t1053007) |
| `T1055` | Process Injection | [Defense Evasion](defense-evasion.md#t1055) |
| `T1055.001` | Dynamic-link Library Injection | [Defense Evasion](defense-evasion.md#t1055001) |
| `T1055.002` | Portable Executable Injection | [Defense Evasion](defense-evasion.md#t1055002) |
| `T1055.003` | Thread Execution Hijacking | [Defense Evasion](defense-evasion.md#t1055003) |
| `T1055.004` | Asynchronous Procedure Call | [Defense Evasion](defense-evasion.md#t1055004) |
| `T1055.005` | Thread Local Storage | [Defense Evasion](defense-evasion.md#t1055005) |
| `T1055.008` | Ptrace System Calls | [Defense Evasion](defense-evasion.md#t1055008) |
| `T1055.009` | Proc Memory | [Defense Evasion](defense-evasion.md#t1055009) |
| `T1055.011` | Extra Window Memory Injection | [Defense Evasion](defense-evasion.md#t1055011) |
| `T1055.012` | Process Hollowing | [Defense Evasion](defense-evasion.md#t1055012) |
| `T1055.013` | Process Doppelgänging | [Defense Evasion](defense-evasion.md#t1055013) |
| `T1055.014` | VDSO Hijacking | [Defense Evasion](defense-evasion.md#t1055014) |
| `T1055.015` | ListPlanting | [Defense Evasion](defense-evasion.md#t1055015) |
| `T1056` | Input Capture | [Collection](collection.md#t1056) |
| `T1056.001` | Keylogging | [Collection](collection.md#t1056001) |
| `T1056.002` | GUI Input Capture | [Collection](collection.md#t1056002) |
| `T1056.003` | Web Portal Capture | [Collection](collection.md#t1056003) |
| `T1056.004` | Credential API Hooking | [Collection](collection.md#t1056004) |
| `T1057` | Process Discovery | [Discovery](discovery.md#t1057) |
| `T1059` | Command and Scripting Interpreter | [Execution](execution.md#t1059) |
| `T1059.001` | PowerShell | [Execution](execution.md#t1059001) |
| `T1059.002` | AppleScript | [Execution](execution.md#t1059002) |
| `T1059.003` | Windows Command Shell | [Execution](execution.md#t1059003) |
| `T1059.004` | Unix Shell | [Execution](execution.md#t1059004) |
| `T1059.005` | Visual Basic | [Execution](execution.md#t1059005) |
| `T1059.006` | Python | [Execution](execution.md#t1059006) |
| `T1059.007` | JavaScript | [Execution](execution.md#t1059007) |
| `T1059.008` | Network Device CLI | [Execution](execution.md#t1059008) |
| `T1059.009` | Cloud API | [Execution](execution.md#t1059009) |
| `T1059.010` | AutoHotKey & AutoIT | [Execution](execution.md#t1059010) |
| `T1059.011` | Lua | [Execution](execution.md#t1059011) |
| `T1059.012` | Hypervisor CLI | [Execution](execution.md#t1059012) |
| `T1059.013` | Container CLI/API | [Execution](execution.md#t1059013) |
| `T1068` | Exploitation for Privilege Escalation | [Privilege Escalation](privilege-escalation.md#t1068) |
| `T1069` | Permission Groups Discovery | [Discovery](discovery.md#t1069) |
| `T1069.001` | Local Groups | [Discovery](discovery.md#t1069001) |
| `T1069.002` | Domain Groups | [Discovery](discovery.md#t1069002) |
| `T1069.003` | Cloud Groups | [Discovery](discovery.md#t1069003) |
| `T1070` | Indicator Removal | [Defense Evasion](defense-evasion.md#t1070) |
| `T1070.001` | Clear Windows Event Logs | [Defense Evasion](defense-evasion.md#t1070001) |
| `T1070.002` | Clear Linux or Mac System Logs | [Defense Evasion](defense-evasion.md#t1070002) |
| `T1070.003` | Clear Command History | [Defense Evasion](defense-evasion.md#t1070003) |
| `T1070.004` | File Deletion | [Defense Evasion](defense-evasion.md#t1070004) |
| `T1070.005` | Network Share Connection Removal | [Defense Evasion](defense-evasion.md#t1070005) |
| `T1070.006` | Timestomp | [Defense Evasion](defense-evasion.md#t1070006) |
| `T1070.007` | Clear Network Connection History and Configurations | [Defense Evasion](defense-evasion.md#t1070007) |
| `T1070.008` | Clear Mailbox Data | [Defense Evasion](defense-evasion.md#t1070008) |
| `T1070.009` | Clear Persistence | [Defense Evasion](defense-evasion.md#t1070009) |
| `T1070.010` | Relocate Malware | [Defense Evasion](defense-evasion.md#t1070010) |
| `T1071` | Application Layer Protocol | [Command and Control](command-and-control.md#t1071) |
| `T1071.001` | Web Protocols | [Command and Control](command-and-control.md#t1071001) |
| `T1071.002` | File Transfer Protocols | [Command and Control](command-and-control.md#t1071002) |
| `T1071.003` | Mail Protocols | [Command and Control](command-and-control.md#t1071003) |
| `T1071.004` | DNS | [Command and Control](command-and-control.md#t1071004) |
| `T1071.005` | Publish/Subscribe Protocols | [Command and Control](command-and-control.md#t1071005) |
| `T1072` | Software Deployment Tools | [Execution](execution.md#t1072) |
| `T1074` | Data Staged | [Collection](collection.md#t1074) |
| `T1074.001` | Local Data Staging | [Collection](collection.md#t1074001) |
| `T1074.002` | Remote Data Staging | [Collection](collection.md#t1074002) |
| `T1078` | Valid Accounts | [Defense Evasion](defense-evasion.md#t1078) |
| `T1078.001` | Default Accounts | [Defense Evasion](defense-evasion.md#t1078001) |
| `T1078.002` | Domain Accounts | [Defense Evasion](defense-evasion.md#t1078002) |
| `T1078.003` | Local Accounts | [Defense Evasion](defense-evasion.md#t1078003) |
| `T1078.004` | Cloud Accounts | [Defense Evasion](defense-evasion.md#t1078004) |
| `T1080` | Taint Shared Content | [Lateral Movement](lateral-movement.md#t1080) |
| `T1082` | System Information Discovery | [Discovery](discovery.md#t1082) |
| `T1083` | File and Directory Discovery | [Discovery](discovery.md#t1083) |
| `T1087` | Account Discovery | [Discovery](discovery.md#t1087) |
| `T1087.001` | Local Account | [Discovery](discovery.md#t1087001) |
| `T1087.002` | Domain Account | [Discovery](discovery.md#t1087002) |
| `T1087.003` | Email Account | [Discovery](discovery.md#t1087003) |
| `T1087.004` | Cloud Account | [Discovery](discovery.md#t1087004) |
| `T1090` | Proxy | [Command and Control](command-and-control.md#t1090) |
| `T1090.001` | Internal Proxy | [Command and Control](command-and-control.md#t1090001) |
| `T1090.002` | External Proxy | [Command and Control](command-and-control.md#t1090002) |
| `T1090.003` | Multi-hop Proxy | [Command and Control](command-and-control.md#t1090003) |
| `T1090.004` | Domain Fronting | [Command and Control](command-and-control.md#t1090004) |
| `T1091` | Replication Through Removable Media | [Lateral Movement](lateral-movement.md#t1091) |
| `T1092` | Communication Through Removable Media | [Command and Control](command-and-control.md#t1092) |
| `T1095` | Non-Application Layer Protocol | [Command and Control](command-and-control.md#t1095) |
| `T1098` | Account Manipulation | [Persistence](persistence.md#t1098) |
| `T1098.001` | Additional Cloud Credentials | [Persistence](persistence.md#t1098001) |
| `T1098.002` | Additional Email Delegate Permissions | [Persistence](persistence.md#t1098002) |
| `T1098.003` | Additional Cloud Roles | [Persistence](persistence.md#t1098003) |
| `T1098.004` | SSH Authorized Keys | [Persistence](persistence.md#t1098004) |
| `T1098.005` | Device Registration | [Persistence](persistence.md#t1098005) |
| `T1098.006` | Additional Container Cluster Roles | [Persistence](persistence.md#t1098006) |
| `T1098.007` | Additional Local or Domain Groups | [Persistence](persistence.md#t1098007) |
| `T1102` | Web Service | [Command and Control](command-and-control.md#t1102) |
| `T1102.001` | Dead Drop Resolver | [Command and Control](command-and-control.md#t1102001) |
| `T1102.002` | Bidirectional Communication | [Command and Control](command-and-control.md#t1102002) |
| `T1102.003` | One-Way Communication | [Command and Control](command-and-control.md#t1102003) |
| `T1104` | Multi-Stage Channels | [Command and Control](command-and-control.md#t1104) |
| `T1105` | Ingress Tool Transfer | [Command and Control](command-and-control.md#t1105) |
| `T1106` | Native API | [Execution](execution.md#t1106) |
| `T1110` | Brute Force | [Credential Access](credential-access.md#t1110) |
| `T1110.001` | Password Guessing | [Credential Access](credential-access.md#t1110001) |
| `T1110.002` | Password Cracking | [Credential Access](credential-access.md#t1110002) |
| `T1110.003` | Password Spraying | [Credential Access](credential-access.md#t1110003) |
| `T1110.004` | Credential Stuffing | [Credential Access](credential-access.md#t1110004) |
| `T1111` | Multi-Factor Authentication Interception | [Credential Access](credential-access.md#t1111) |
| `T1112` | Modify Registry | [Defense Evasion](defense-evasion.md#t1112) |
| `T1113` | Screen Capture | [Collection](collection.md#t1113) |
| `T1114` | Email Collection | [Collection](collection.md#t1114) |
| `T1114.001` | Local Email Collection | [Collection](collection.md#t1114001) |
| `T1114.002` | Remote Email Collection | [Collection](collection.md#t1114002) |
| `T1114.003` | Email Forwarding Rule | [Collection](collection.md#t1114003) |
| `T1115` | Clipboard Data | [Collection](collection.md#t1115) |
| `T1119` | Automated Collection | [Collection](collection.md#t1119) |
| `T1120` | Peripheral Device Discovery | [Discovery](discovery.md#t1120) |
| `T1123` | Audio Capture | [Collection](collection.md#t1123) |
| `T1124` | System Time Discovery | [Discovery](discovery.md#t1124) |
| `T1125` | Video Capture | [Collection](collection.md#t1125) |
| `T1127` | Trusted Developer Utilities Proxy Execution | [Defense Evasion](defense-evasion.md#t1127) |
| `T1127.001` | MSBuild | [Defense Evasion](defense-evasion.md#t1127001) |
| `T1127.002` | ClickOnce | [Defense Evasion](defense-evasion.md#t1127002) |
| `T1127.003` | JamPlus | [Defense Evasion](defense-evasion.md#t1127003) |
| `T1129` | Shared Modules | [Execution](execution.md#t1129) |
| `T1132` | Data Encoding | [Command and Control](command-and-control.md#t1132) |
| `T1132.001` | Standard Encoding | [Command and Control](command-and-control.md#t1132001) |
| `T1132.002` | Non-Standard Encoding | [Command and Control](command-and-control.md#t1132002) |
| `T1133` | External Remote Services | [Persistence](persistence.md#t1133) |
| `T1134` | Access Token Manipulation | [Defense Evasion](defense-evasion.md#t1134) |
| `T1134.001` | Token Impersonation/Theft | [Defense Evasion](defense-evasion.md#t1134001) |
| `T1134.002` | Create Process with Token | [Defense Evasion](defense-evasion.md#t1134002) |
| `T1134.003` | Make and Impersonate Token | [Defense Evasion](defense-evasion.md#t1134003) |
| `T1134.004` | Parent PID Spoofing | [Defense Evasion](defense-evasion.md#t1134004) |
| `T1134.005` | SID-History Injection | [Defense Evasion](defense-evasion.md#t1134005) |
| `T1135` | Network Share Discovery | [Discovery](discovery.md#t1135) |
| `T1136` | Create Account | [Persistence](persistence.md#t1136) |
| `T1136.001` | Local Account | [Persistence](persistence.md#t1136001) |
| `T1136.002` | Domain Account | [Persistence](persistence.md#t1136002) |
| `T1136.003` | Cloud Account | [Persistence](persistence.md#t1136003) |
| `T1137` | Office Application Startup | [Persistence](persistence.md#t1137) |
| `T1137.001` | Office Template Macros | [Persistence](persistence.md#t1137001) |
| `T1137.002` | Office Test | [Persistence](persistence.md#t1137002) |
| `T1137.003` | Outlook Forms | [Persistence](persistence.md#t1137003) |
| `T1137.004` | Outlook Home Page | [Persistence](persistence.md#t1137004) |
| `T1137.005` | Outlook Rules | [Persistence](persistence.md#t1137005) |
| `T1137.006` | Add-ins | [Persistence](persistence.md#t1137006) |
| `T1140` | Deobfuscate/Decode Files or Information | [Defense Evasion](defense-evasion.md#t1140) |
| `T1176` | Software Extensions | [Persistence](persistence.md#t1176) |
| `T1176.001` | Browser Extensions | [Persistence](persistence.md#t1176001) |
| `T1176.002` | IDE Extensions | [Persistence](persistence.md#t1176002) |
| `T1185` | Browser Session Hijacking | [Collection](collection.md#t1185) |
| `T1187` | Forced Authentication | [Credential Access](credential-access.md#t1187) |
| `T1189` | Drive-by Compromise | [Initial Access](initial-access.md#t1189) |
| `T1190` | Exploit Public-Facing Application | [Initial Access](initial-access.md#t1190) |
| `T1195` | Supply Chain Compromise | [Initial Access](initial-access.md#t1195) |
| `T1195.001` | Compromise Software Dependencies and Development Tools | [Initial Access](initial-access.md#t1195001) |
| `T1195.002` | Compromise Software Supply Chain | [Initial Access](initial-access.md#t1195002) |
| `T1195.003` | Compromise Hardware Supply Chain | [Initial Access](initial-access.md#t1195003) |
| `T1197` | BITS Jobs | [Defense Evasion](defense-evasion.md#t1197) |
| `T1199` | Trusted Relationship | [Initial Access](initial-access.md#t1199) |
| `T1200` | Hardware Additions | [Initial Access](initial-access.md#t1200) |
| `T1201` | Password Policy Discovery | [Discovery](discovery.md#t1201) |
| `T1202` | Indirect Command Execution | [Defense Evasion](defense-evasion.md#t1202) |
| `T1203` | Exploitation for Client Execution | [Execution](execution.md#t1203) |
| `T1204` | User Execution | [Execution](execution.md#t1204) |
| `T1204.001` | Malicious Link | [Execution](execution.md#t1204001) |
| `T1204.002` | Malicious File | [Execution](execution.md#t1204002) |
| `T1204.003` | Malicious Image | [Execution](execution.md#t1204003) |
| `T1204.004` | Malicious Copy and Paste | [Execution](execution.md#t1204004) |
| `T1204.005` | Malicious Library | [Execution](execution.md#t1204005) |
| `T1205` | Traffic Signaling | [Defense Evasion](defense-evasion.md#t1205) |
| `T1205.001` | Port Knocking | [Defense Evasion](defense-evasion.md#t1205001) |
| `T1205.002` | Socket Filters | [Defense Evasion](defense-evasion.md#t1205002) |
| `T1207` | Rogue Domain Controller | [Defense Evasion](defense-evasion.md#t1207) |
| `T1210` | Exploitation of Remote Services | [Lateral Movement](lateral-movement.md#t1210) |
| `T1211` | Exploitation for Defense Evasion | [Defense Evasion](defense-evasion.md#t1211) |
| `T1212` | Exploitation for Credential Access | [Credential Access](credential-access.md#t1212) |
| `T1213` | Data from Information Repositories | [Collection](collection.md#t1213) |
| `T1213.001` | Confluence | [Collection](collection.md#t1213001) |
| `T1213.002` | Sharepoint | [Collection](collection.md#t1213002) |
| `T1213.003` | Code Repositories | [Collection](collection.md#t1213003) |
| `T1213.004` | Customer Relationship Management Software | [Collection](collection.md#t1213004) |
| `T1213.005` | Messaging Applications | [Collection](collection.md#t1213005) |
| `T1213.006` | Databases | [Collection](collection.md#t1213006) |
| `T1216` | System Script Proxy Execution | [Defense Evasion](defense-evasion.md#t1216) |
| `T1216.001` | PubPrn | [Defense Evasion](defense-evasion.md#t1216001) |
| `T1216.002` | SyncAppvPublishingServer | [Defense Evasion](defense-evasion.md#t1216002) |
| `T1217` | Browser Information Discovery | [Discovery](discovery.md#t1217) |
| `T1218` | System Binary Proxy Execution | [Defense Evasion](defense-evasion.md#t1218) |
| `T1218.001` | Compiled HTML File | [Defense Evasion](defense-evasion.md#t1218001) |
| `T1218.002` | Control Panel | [Defense Evasion](defense-evasion.md#t1218002) |
| `T1218.003` | CMSTP | [Defense Evasion](defense-evasion.md#t1218003) |
| `T1218.004` | InstallUtil | [Defense Evasion](defense-evasion.md#t1218004) |
| `T1218.005` | Mshta | [Defense Evasion](defense-evasion.md#t1218005) |
| `T1218.007` | Msiexec | [Defense Evasion](defense-evasion.md#t1218007) |
| `T1218.008` | Odbcconf | [Defense Evasion](defense-evasion.md#t1218008) |
| `T1218.009` | Regsvcs/Regasm | [Defense Evasion](defense-evasion.md#t1218009) |
| `T1218.010` | Regsvr32 | [Defense Evasion](defense-evasion.md#t1218010) |
| `T1218.011` | Rundll32 | [Defense Evasion](defense-evasion.md#t1218011) |
| `T1218.012` | Verclsid | [Defense Evasion](defense-evasion.md#t1218012) |
| `T1218.013` | Mavinject | [Defense Evasion](defense-evasion.md#t1218013) |
| `T1218.014` | MMC | [Defense Evasion](defense-evasion.md#t1218014) |
| `T1218.015` | Electron Applications | [Defense Evasion](defense-evasion.md#t1218015) |
| `T1219` | Remote Access Tools | [Command and Control](command-and-control.md#t1219) |
| `T1219.001` | IDE Tunneling | [Command and Control](command-and-control.md#t1219001) |
| `T1219.002` | Remote Desktop Software | [Command and Control](command-and-control.md#t1219002) |
| `T1219.003` | Remote Access Hardware | [Command and Control](command-and-control.md#t1219003) |
| `T1220` | XSL Script Processing | [Defense Evasion](defense-evasion.md#t1220) |
| `T1221` | Template Injection | [Defense Evasion](defense-evasion.md#t1221) |
| `T1222` | File and Directory Permissions Modification | [Defense Evasion](defense-evasion.md#t1222) |
| `T1222.001` | Windows File and Directory Permissions Modification | [Defense Evasion](defense-evasion.md#t1222001) |
| `T1222.002` | Linux and Mac File and Directory Permissions Modification | [Defense Evasion](defense-evasion.md#t1222002) |
| `T1480` | Execution Guardrails | [Defense Evasion](defense-evasion.md#t1480) |
| `T1480.001` | Environmental Keying | [Defense Evasion](defense-evasion.md#t1480001) |
| `T1480.002` | Mutual Exclusion | [Defense Evasion](defense-evasion.md#t1480002) |
| `T1482` | Domain Trust Discovery | [Discovery](discovery.md#t1482) |
| `T1484` | Domain or Tenant Policy Modification | [Defense Evasion](defense-evasion.md#t1484) |
| `T1484.001` | Group Policy Modification | [Defense Evasion](defense-evasion.md#t1484001) |
| `T1484.002` | Trust Modification | [Defense Evasion](defense-evasion.md#t1484002) |
| `T1485` | Data Destruction | [Impact](impact.md#t1485) |
| `T1485.001` | Lifecycle-Triggered Deletion | [Impact](impact.md#t1485001) |
| `T1486` | Data Encrypted for Impact | [Impact](impact.md#t1486) |
| `T1489` | Service Stop | [Impact](impact.md#t1489) |
| `T1490` | Inhibit System Recovery | [Impact](impact.md#t1490) |
| `T1491` | Defacement | [Impact](impact.md#t1491) |
| `T1491.001` | Internal Defacement | [Impact](impact.md#t1491001) |
| `T1491.002` | External Defacement | [Impact](impact.md#t1491002) |
| `T1495` | Firmware Corruption | [Impact](impact.md#t1495) |
| `T1496` | Resource Hijacking | [Impact](impact.md#t1496) |
| `T1496.001` | Compute Hijacking | [Impact](impact.md#t1496001) |
| `T1496.002` | Bandwidth Hijacking | [Impact](impact.md#t1496002) |
| `T1496.003` | SMS Pumping | [Impact](impact.md#t1496003) |
| `T1496.004` | Cloud Service Hijacking | [Impact](impact.md#t1496004) |
| `T1497` | Virtualization/Sandbox Evasion | [Defense Evasion](defense-evasion.md#t1497) |
| `T1497.001` | System Checks | [Defense Evasion](defense-evasion.md#t1497001) |
| `T1497.002` | User Activity Based Checks | [Defense Evasion](defense-evasion.md#t1497002) |
| `T1497.003` | Time Based Checks | [Defense Evasion](defense-evasion.md#t1497003) |
| `T1498` | Network Denial of Service | [Impact](impact.md#t1498) |
| `T1498.001` | Direct Network Flood | [Impact](impact.md#t1498001) |
| `T1498.002` | Reflection Amplification | [Impact](impact.md#t1498002) |
| `T1499` | Endpoint Denial of Service | [Impact](impact.md#t1499) |
| `T1499.001` | OS Exhaustion Flood | [Impact](impact.md#t1499001) |
| `T1499.002` | Service Exhaustion Flood | [Impact](impact.md#t1499002) |
| `T1499.003` | Application Exhaustion Flood | [Impact](impact.md#t1499003) |
| `T1499.004` | Application or System Exploitation | [Impact](impact.md#t1499004) |
| `T1505` | Server Software Component | [Persistence](persistence.md#t1505) |
| `T1505.001` | SQL Stored Procedures | [Persistence](persistence.md#t1505001) |
| `T1505.002` | Transport Agent | [Persistence](persistence.md#t1505002) |
| `T1505.003` | Web Shell | [Persistence](persistence.md#t1505003) |
| `T1505.004` | IIS Components | [Persistence](persistence.md#t1505004) |
| `T1505.005` | Terminal Services DLL | [Persistence](persistence.md#t1505005) |
| `T1505.006` | vSphere Installation Bundles | [Persistence](persistence.md#t1505006) |
| `T1518` | Software Discovery | [Discovery](discovery.md#t1518) |
| `T1518.001` | Security Software Discovery | [Discovery](discovery.md#t1518001) |
| `T1518.002` | Backup Software Discovery | [Discovery](discovery.md#t1518002) |
| `T1525` | Implant Internal Image | [Persistence](persistence.md#t1525) |
| `T1526` | Cloud Service Discovery | [Discovery](discovery.md#t1526) |
| `T1528` | Steal Application Access Token | [Credential Access](credential-access.md#t1528) |
| `T1529` | System Shutdown/Reboot | [Impact](impact.md#t1529) |
| `T1530` | Data from Cloud Storage | [Collection](collection.md#t1530) |
| `T1531` | Account Access Removal | [Impact](impact.md#t1531) |
| `T1534` | Internal Spearphishing | [Lateral Movement](lateral-movement.md#t1534) |
| `T1535` | Unused/Unsupported Cloud Regions | [Defense Evasion](defense-evasion.md#t1535) |
| `T1537` | Transfer Data to Cloud Account | [Exfiltration](exfiltration.md#t1537) |
| `T1538` | Cloud Service Dashboard | [Discovery](discovery.md#t1538) |
| `T1539` | Steal Web Session Cookie | [Credential Access](credential-access.md#t1539) |
| `T1542` | Pre-OS Boot | [Defense Evasion](defense-evasion.md#t1542) |
| `T1542.001` | System Firmware | [Persistence](persistence.md#t1542001) |
| `T1542.002` | Component Firmware | [Persistence](persistence.md#t1542002) |
| `T1542.003` | Bootkit | [Persistence](persistence.md#t1542003) |
| `T1542.004` | ROMMONkit | [Defense Evasion](defense-evasion.md#t1542004) |
| `T1542.005` | TFTP Boot | [Defense Evasion](defense-evasion.md#t1542005) |
| `T1543` | Create or Modify System Process | [Persistence](persistence.md#t1543) |
| `T1543.001` | Launch Agent | [Persistence](persistence.md#t1543001) |
| `T1543.002` | Systemd Service | [Persistence](persistence.md#t1543002) |
| `T1543.003` | Windows Service | [Persistence](persistence.md#t1543003) |
| `T1543.004` | Launch Daemon | [Persistence](persistence.md#t1543004) |
| `T1543.005` | Container Service | [Persistence](persistence.md#t1543005) |
| `T1546` | Event Triggered Execution | [Privilege Escalation](privilege-escalation.md#t1546) |
| `T1546.001` | Change Default File Association | [Privilege Escalation](privilege-escalation.md#t1546001) |
| `T1546.002` | Screensaver | [Privilege Escalation](privilege-escalation.md#t1546002) |
| `T1546.003` | Windows Management Instrumentation Event Subscription | [Privilege Escalation](privilege-escalation.md#t1546003) |
| `T1546.004` | Unix Shell Configuration Modification | [Privilege Escalation](privilege-escalation.md#t1546004) |
| `T1546.005` | Trap | [Privilege Escalation](privilege-escalation.md#t1546005) |
| `T1546.006` | LC_LOAD_DYLIB Addition | [Privilege Escalation](privilege-escalation.md#t1546006) |
| `T1546.007` | Netsh Helper DLL | [Privilege Escalation](privilege-escalation.md#t1546007) |
| `T1546.008` | Accessibility Features | [Privilege Escalation](privilege-escalation.md#t1546008) |
| `T1546.009` | AppCert DLLs | [Privilege Escalation](privilege-escalation.md#t1546009) |
| `T1546.010` | AppInit DLLs | [Privilege Escalation](privilege-escalation.md#t1546010) |
| `T1546.011` | Application Shimming | [Privilege Escalation](privilege-escalation.md#t1546011) |
| `T1546.012` | Image File Execution Options Injection | [Privilege Escalation](privilege-escalation.md#t1546012) |
| `T1546.013` | PowerShell Profile | [Privilege Escalation](privilege-escalation.md#t1546013) |
| `T1546.014` | Emond | [Privilege Escalation](privilege-escalation.md#t1546014) |
| `T1546.015` | Component Object Model Hijacking | [Privilege Escalation](privilege-escalation.md#t1546015) |
| `T1546.016` | Installer Packages | [Privilege Escalation](privilege-escalation.md#t1546016) |
| `T1546.017` | Udev Rules | [Persistence](persistence.md#t1546017) |
| `T1546.018` | Python Startup Hooks | [Persistence](persistence.md#t1546018) |
| `T1547` | Boot or Logon Autostart Execution | [Persistence](persistence.md#t1547) |
| `T1547.001` | Registry Run Keys / Startup Folder | [Persistence](persistence.md#t1547001) |
| `T1547.002` | Authentication Package | [Persistence](persistence.md#t1547002) |
| `T1547.003` | Time Providers | [Persistence](persistence.md#t1547003) |
| `T1547.004` | Winlogon Helper DLL | [Persistence](persistence.md#t1547004) |
| `T1547.005` | Security Support Provider | [Persistence](persistence.md#t1547005) |
| `T1547.006` | Kernel Modules and Extensions | [Persistence](persistence.md#t1547006) |
| `T1547.007` | Re-opened Applications | [Persistence](persistence.md#t1547007) |
| `T1547.008` | LSASS Driver | [Persistence](persistence.md#t1547008) |
| `T1547.009` | Shortcut Modification | [Persistence](persistence.md#t1547009) |
| `T1547.010` | Port Monitors | [Persistence](persistence.md#t1547010) |
| `T1547.012` | Print Processors | [Persistence](persistence.md#t1547012) |
| `T1547.013` | XDG Autostart Entries | [Persistence](persistence.md#t1547013) |
| `T1547.014` | Active Setup | [Persistence](persistence.md#t1547014) |
| `T1547.015` | Login Items | [Persistence](persistence.md#t1547015) |
| `T1548` | Abuse Elevation Control Mechanism | [Privilege Escalation](privilege-escalation.md#t1548) |
| `T1548.001` | Setuid and Setgid | [Privilege Escalation](privilege-escalation.md#t1548001) |
| `T1548.002` | Bypass User Account Control | [Privilege Escalation](privilege-escalation.md#t1548002) |
| `T1548.003` | Sudo and Sudo Caching | [Privilege Escalation](privilege-escalation.md#t1548003) |
| `T1548.004` | Elevated Execution with Prompt | [Privilege Escalation](privilege-escalation.md#t1548004) |
| `T1548.005` | Temporary Elevated Cloud Access | [Privilege Escalation](privilege-escalation.md#t1548005) |
| `T1548.006` | TCC Manipulation | [Defense Evasion](defense-evasion.md#t1548006) |
| `T1550` | Use Alternate Authentication Material | [Defense Evasion](defense-evasion.md#t1550) |
| `T1550.001` | Application Access Token | [Defense Evasion](defense-evasion.md#t1550001) |
| `T1550.002` | Pass the Hash | [Defense Evasion](defense-evasion.md#t1550002) |
| `T1550.003` | Pass the Ticket | [Defense Evasion](defense-evasion.md#t1550003) |
| `T1550.004` | Web Session Cookie | [Defense Evasion](defense-evasion.md#t1550004) |
| `T1552` | Unsecured Credentials | [Credential Access](credential-access.md#t1552) |
| `T1552.001` | Credentials In Files | [Credential Access](credential-access.md#t1552001) |
| `T1552.002` | Credentials in Registry | [Credential Access](credential-access.md#t1552002) |
| `T1552.003` | Shell History | [Credential Access](credential-access.md#t1552003) |
| `T1552.004` | Private Keys | [Credential Access](credential-access.md#t1552004) |
| `T1552.005` | Cloud Instance Metadata API | [Credential Access](credential-access.md#t1552005) |
| `T1552.006` | Group Policy Preferences | [Credential Access](credential-access.md#t1552006) |
| `T1552.007` | Container API | [Credential Access](credential-access.md#t1552007) |
| `T1552.008` | Chat Messages | [Credential Access](credential-access.md#t1552008) |
| `T1553` | Subvert Trust Controls | [Defense Evasion](defense-evasion.md#t1553) |
| `T1553.001` | Gatekeeper Bypass | [Defense Evasion](defense-evasion.md#t1553001) |
| `T1553.002` | Code Signing | [Defense Evasion](defense-evasion.md#t1553002) |
| `T1553.003` | SIP and Trust Provider Hijacking | [Defense Evasion](defense-evasion.md#t1553003) |
| `T1553.004` | Install Root Certificate | [Defense Evasion](defense-evasion.md#t1553004) |
| `T1553.005` | Mark-of-the-Web Bypass | [Defense Evasion](defense-evasion.md#t1553005) |
| `T1553.006` | Code Signing Policy Modification | [Defense Evasion](defense-evasion.md#t1553006) |
| `T1554` | Compromise Host Software Binary | [Persistence](persistence.md#t1554) |
| `T1555` | Credentials from Password Stores | [Credential Access](credential-access.md#t1555) |
| `T1555.001` | Keychain | [Credential Access](credential-access.md#t1555001) |
| `T1555.002` | Securityd Memory | [Credential Access](credential-access.md#t1555002) |
| `T1555.003` | Credentials from Web Browsers | [Credential Access](credential-access.md#t1555003) |
| `T1555.004` | Windows Credential Manager | [Credential Access](credential-access.md#t1555004) |
| `T1555.005` | Password Managers | [Credential Access](credential-access.md#t1555005) |
| `T1555.006` | Cloud Secrets Management Stores | [Credential Access](credential-access.md#t1555006) |
| `T1556` | Modify Authentication Process | [Credential Access](credential-access.md#t1556) |
| `T1556.001` | Domain Controller Authentication | [Credential Access](credential-access.md#t1556001) |
| `T1556.002` | Password Filter DLL | [Credential Access](credential-access.md#t1556002) |
| `T1556.003` | Pluggable Authentication Modules | [Credential Access](credential-access.md#t1556003) |
| `T1556.004` | Network Device Authentication | [Credential Access](credential-access.md#t1556004) |
| `T1556.005` | Reversible Encryption | [Credential Access](credential-access.md#t1556005) |
| `T1556.006` | Multi-Factor Authentication | [Credential Access](credential-access.md#t1556006) |
| `T1556.007` | Hybrid Identity | [Credential Access](credential-access.md#t1556007) |
| `T1556.008` | Network Provider DLL | [Credential Access](credential-access.md#t1556008) |
| `T1556.009` | Conditional Access Policies | [Credential Access](credential-access.md#t1556009) |
| `T1557` | Adversary-in-the-Middle | [Credential Access](credential-access.md#t1557) |
| `T1557.001` | LLMNR/NBT-NS Poisoning and SMB Relay | [Credential Access](credential-access.md#t1557001) |
| `T1557.002` | ARP Cache Poisoning | [Credential Access](credential-access.md#t1557002) |
| `T1557.003` | DHCP Spoofing | [Credential Access](credential-access.md#t1557003) |
| `T1557.004` | Evil Twin | [Credential Access](credential-access.md#t1557004) |
| `T1558` | Steal or Forge Kerberos Tickets | [Credential Access](credential-access.md#t1558) |
| `T1558.001` | Golden Ticket | [Credential Access](credential-access.md#t1558001) |
| `T1558.002` | Silver Ticket | [Credential Access](credential-access.md#t1558002) |
| `T1558.003` | Kerberoasting | [Credential Access](credential-access.md#t1558003) |
| `T1558.004` | AS-REP Roasting | [Credential Access](credential-access.md#t1558004) |
| `T1558.005` | Ccache Files | [Credential Access](credential-access.md#t1558005) |
| `T1559` | Inter-Process Communication | [Execution](execution.md#t1559) |
| `T1559.001` | Component Object Model | [Execution](execution.md#t1559001) |
| `T1559.002` | Dynamic Data Exchange | [Execution](execution.md#t1559002) |
| `T1559.003` | XPC Services | [Execution](execution.md#t1559003) |
| `T1560` | Archive Collected Data | [Collection](collection.md#t1560) |
| `T1560.001` | Archive via Utility | [Collection](collection.md#t1560001) |
| `T1560.002` | Archive via Library | [Collection](collection.md#t1560002) |
| `T1560.003` | Archive via Custom Method | [Collection](collection.md#t1560003) |
| `T1561` | Disk Wipe | [Impact](impact.md#t1561) |
| `T1561.001` | Disk Content Wipe | [Impact](impact.md#t1561001) |
| `T1561.002` | Disk Structure Wipe | [Impact](impact.md#t1561002) |
| `T1562` | Impair Defenses | [Defense Evasion](defense-evasion.md#t1562) |
| `T1562.001` | Disable or Modify Tools | [Defense Evasion](defense-evasion.md#t1562001) |
| `T1562.002` | Disable Windows Event Logging | [Defense Evasion](defense-evasion.md#t1562002) |
| `T1562.003` | Impair Command History Logging | [Defense Evasion](defense-evasion.md#t1562003) |
| `T1562.004` | Disable or Modify System Firewall | [Defense Evasion](defense-evasion.md#t1562004) |
| `T1562.006` | Indicator Blocking | [Defense Evasion](defense-evasion.md#t1562006) |
| `T1562.007` | Disable or Modify Cloud Firewall | [Defense Evasion](defense-evasion.md#t1562007) |
| `T1562.008` | Disable or Modify Cloud Logs | [Defense Evasion](defense-evasion.md#t1562008) |
| `T1562.009` | Safe Mode Boot | [Defense Evasion](defense-evasion.md#t1562009) |
| `T1562.010` | Downgrade Attack | [Defense Evasion](defense-evasion.md#t1562010) |
| `T1562.011` | Spoof Security Alerting | [Defense Evasion](defense-evasion.md#t1562011) |
| `T1562.012` | Disable or Modify Linux Audit System | [Defense Evasion](defense-evasion.md#t1562012) |
| `T1562.013` | Disable or Modify Network Device Firewall | [Defense Evasion](defense-evasion.md#t1562013) |
| `T1563` | Remote Service Session Hijacking | [Lateral Movement](lateral-movement.md#t1563) |
| `T1563.001` | SSH Hijacking | [Lateral Movement](lateral-movement.md#t1563001) |
| `T1563.002` | RDP Hijacking | [Lateral Movement](lateral-movement.md#t1563002) |
| `T1564` | Hide Artifacts | [Defense Evasion](defense-evasion.md#t1564) |
| `T1564.001` | Hidden Files and Directories | [Defense Evasion](defense-evasion.md#t1564001) |
| `T1564.002` | Hidden Users | [Defense Evasion](defense-evasion.md#t1564002) |
| `T1564.003` | Hidden Window | [Defense Evasion](defense-evasion.md#t1564003) |
| `T1564.004` | NTFS File Attributes | [Defense Evasion](defense-evasion.md#t1564004) |
| `T1564.005` | Hidden File System | [Defense Evasion](defense-evasion.md#t1564005) |
| `T1564.006` | Run Virtual Instance | [Defense Evasion](defense-evasion.md#t1564006) |
| `T1564.007` | VBA Stomping | [Defense Evasion](defense-evasion.md#t1564007) |
| `T1564.008` | Email Hiding Rules | [Defense Evasion](defense-evasion.md#t1564008) |
| `T1564.009` | Resource Forking | [Defense Evasion](defense-evasion.md#t1564009) |
| `T1564.010` | Process Argument Spoofing | [Defense Evasion](defense-evasion.md#t1564010) |
| `T1564.011` | Ignore Process Interrupts | [Defense Evasion](defense-evasion.md#t1564011) |
| `T1564.012` | File/Path Exclusions | [Defense Evasion](defense-evasion.md#t1564012) |
| `T1564.013` | Bind Mounts | [Defense Evasion](defense-evasion.md#t1564013) |
| `T1564.014` | Extended Attributes | [Defense Evasion](defense-evasion.md#t1564014) |
| `T1565` | Data Manipulation | [Impact](impact.md#t1565) |
| `T1565.001` | Stored Data Manipulation | [Impact](impact.md#t1565001) |
| `T1565.002` | Transmitted Data Manipulation | [Impact](impact.md#t1565002) |
| `T1565.003` | Runtime Data Manipulation | [Impact](impact.md#t1565003) |
| `T1566` | Phishing | [Initial Access](initial-access.md#t1566) |
| `T1566.001` | Spearphishing Attachment | [Initial Access](initial-access.md#t1566001) |
| `T1566.002` | Spearphishing Link | [Initial Access](initial-access.md#t1566002) |
| `T1566.003` | Spearphishing via Service | [Initial Access](initial-access.md#t1566003) |
| `T1566.004` | Spearphishing Voice | [Initial Access](initial-access.md#t1566004) |
| `T1567` | Exfiltration Over Web Service | [Exfiltration](exfiltration.md#t1567) |
| `T1567.001` | Exfiltration to Code Repository | [Exfiltration](exfiltration.md#t1567001) |
| `T1567.002` | Exfiltration to Cloud Storage | [Exfiltration](exfiltration.md#t1567002) |
| `T1567.003` | Exfiltration to Text Storage Sites | [Exfiltration](exfiltration.md#t1567003) |
| `T1567.004` | Exfiltration Over Webhook | [Exfiltration](exfiltration.md#t1567004) |
| `T1568` | Dynamic Resolution | [Command and Control](command-and-control.md#t1568) |
| `T1568.001` | Fast Flux DNS | [Command and Control](command-and-control.md#t1568001) |
| `T1568.002` | Domain Generation Algorithms | [Command and Control](command-and-control.md#t1568002) |
| `T1568.003` | DNS Calculation | [Command and Control](command-and-control.md#t1568003) |
| `T1569` | System Services | [Execution](execution.md#t1569) |
| `T1569.001` | Launchctl | [Execution](execution.md#t1569001) |
| `T1569.002` | Service Execution | [Execution](execution.md#t1569002) |
| `T1569.003` | Systemctl | [Execution](execution.md#t1569003) |
| `T1570` | Lateral Tool Transfer | [Lateral Movement](lateral-movement.md#t1570) |
| `T1571` | Non-Standard Port | [Command and Control](command-and-control.md#t1571) |
| `T1572` | Protocol Tunneling | [Command and Control](command-and-control.md#t1572) |
| `T1573` | Encrypted Channel | [Command and Control](command-and-control.md#t1573) |
| `T1573.001` | Symmetric Cryptography | [Command and Control](command-and-control.md#t1573001) |
| `T1573.002` | Asymmetric Cryptography | [Command and Control](command-and-control.md#t1573002) |
| `T1574` | Hijack Execution Flow | [Persistence](persistence.md#t1574) |
| `T1574.001` | DLL | [Persistence](persistence.md#t1574001) |
| `T1574.004` | Dylib Hijacking | [Persistence](persistence.md#t1574004) |
| `T1574.005` | Executable Installer File Permissions Weakness | [Persistence](persistence.md#t1574005) |
| `T1574.006` | Dynamic Linker Hijacking | [Persistence](persistence.md#t1574006) |
| `T1574.007` | Path Interception by PATH Environment Variable | [Persistence](persistence.md#t1574007) |
| `T1574.008` | Path Interception by Search Order Hijacking | [Persistence](persistence.md#t1574008) |
| `T1574.009` | Path Interception by Unquoted Path | [Persistence](persistence.md#t1574009) |
| `T1574.010` | Services File Permissions Weakness | [Persistence](persistence.md#t1574010) |
| `T1574.011` | Services Registry Permissions Weakness | [Persistence](persistence.md#t1574011) |
| `T1574.012` | COR_PROFILER | [Persistence](persistence.md#t1574012) |
| `T1574.013` | KernelCallbackTable | [Persistence](persistence.md#t1574013) |
| `T1574.014` | AppDomainManager | [Persistence](persistence.md#t1574014) |
| `T1578` | Modify Cloud Compute Infrastructure | [Defense Evasion](defense-evasion.md#t1578) |
| `T1578.001` | Create Snapshot | [Defense Evasion](defense-evasion.md#t1578001) |
| `T1578.002` | Create Cloud Instance | [Defense Evasion](defense-evasion.md#t1578002) |
| `T1578.003` | Delete Cloud Instance | [Defense Evasion](defense-evasion.md#t1578003) |
| `T1578.004` | Revert Cloud Instance | [Defense Evasion](defense-evasion.md#t1578004) |
| `T1578.005` | Modify Cloud Compute Configurations | [Defense Evasion](defense-evasion.md#t1578005) |
| `T1580` | Cloud Infrastructure Discovery | [Discovery](discovery.md#t1580) |
| `T1583` | Acquire Infrastructure | [Resource Development](resource-development.md#t1583) |
| `T1583.001` | Domains | [Resource Development](resource-development.md#t1583001) |
| `T1583.002` | DNS Server | [Resource Development](resource-development.md#t1583002) |
| `T1583.003` | Virtual Private Server | [Resource Development](resource-development.md#t1583003) |
| `T1583.004` | Server | [Resource Development](resource-development.md#t1583004) |
| `T1583.005` | Botnet | [Resource Development](resource-development.md#t1583005) |
| `T1583.006` | Web Services | [Resource Development](resource-development.md#t1583006) |
| `T1583.007` | Serverless | [Resource Development](resource-development.md#t1583007) |
| `T1583.008` | Malvertising | [Resource Development](resource-development.md#t1583008) |
| `T1584` | Compromise Infrastructure | [Resource Development](resource-development.md#t1584) |
| `T1584.001` | Domains | [Resource Development](resource-development.md#t1584001) |
| `T1584.002` | DNS Server | [Resource Development](resource-development.md#t1584002) |
| `T1584.003` | Virtual Private Server | [Resource Development](resource-development.md#t1584003) |
| `T1584.004` | Server | [Resource Development](resource-development.md#t1584004) |
| `T1584.005` | Botnet | [Resource Development](resource-development.md#t1584005) |
| `T1584.006` | Web Services | [Resource Development](resource-development.md#t1584006) |
| `T1584.007` | Serverless | [Resource Development](resource-development.md#t1584007) |
| `T1584.008` | Network Devices | [Resource Development](resource-development.md#t1584008) |
| `T1585` | Establish Accounts | [Resource Development](resource-development.md#t1585) |
| `T1585.001` | Social Media Accounts | [Resource Development](resource-development.md#t1585001) |
| `T1585.002` | Email Accounts | [Resource Development](resource-development.md#t1585002) |
| `T1585.003` | Cloud Accounts | [Resource Development](resource-development.md#t1585003) |
| `T1586` | Compromise Accounts | [Resource Development](resource-development.md#t1586) |
| `T1586.001` | Social Media Accounts | [Resource Development](resource-development.md#t1586001) |
| `T1586.002` | Email Accounts | [Resource Development](resource-development.md#t1586002) |
| `T1586.003` | Cloud Accounts | [Resource Development](resource-development.md#t1586003) |
| `T1587` | Develop Capabilities | [Resource Development](resource-development.md#t1587) |
| `T1587.001` | Malware | [Resource Development](resource-development.md#t1587001) |
| `T1587.002` | Code Signing Certificates | [Resource Development](resource-development.md#t1587002) |
| `T1587.003` | Digital Certificates | [Resource Development](resource-development.md#t1587003) |
| `T1587.004` | Exploits | [Resource Development](resource-development.md#t1587004) |
| `T1588` | Obtain Capabilities | [Resource Development](resource-development.md#t1588) |
| `T1588.001` | Malware | [Resource Development](resource-development.md#t1588001) |
| `T1588.002` | Tool | [Resource Development](resource-development.md#t1588002) |
| `T1588.003` | Code Signing Certificates | [Resource Development](resource-development.md#t1588003) |
| `T1588.004` | Digital Certificates | [Resource Development](resource-development.md#t1588004) |
| `T1588.005` | Exploits | [Resource Development](resource-development.md#t1588005) |
| `T1588.006` | Vulnerabilities | [Resource Development](resource-development.md#t1588006) |
| `T1588.007` | Artificial Intelligence | [Resource Development](resource-development.md#t1588007) |
| `T1589` | Gather Victim Identity Information | [Reconnaissance](reconnaissance.md#t1589) |
| `T1589.001` | Credentials | [Reconnaissance](reconnaissance.md#t1589001) |
| `T1589.002` | Email Addresses | [Reconnaissance](reconnaissance.md#t1589002) |
| `T1589.003` | Employee Names | [Reconnaissance](reconnaissance.md#t1589003) |
| `T1590` | Gather Victim Network Information | [Reconnaissance](reconnaissance.md#t1590) |
| `T1590.001` | Domain Properties | [Reconnaissance](reconnaissance.md#t1590001) |
| `T1590.002` | DNS | [Reconnaissance](reconnaissance.md#t1590002) |
| `T1590.003` | Network Trust Dependencies | [Reconnaissance](reconnaissance.md#t1590003) |
| `T1590.004` | Network Topology | [Reconnaissance](reconnaissance.md#t1590004) |
| `T1590.005` | IP Addresses | [Reconnaissance](reconnaissance.md#t1590005) |
| `T1590.006` | Network Security Appliances | [Reconnaissance](reconnaissance.md#t1590006) |
| `T1591` | Gather Victim Org Information | [Reconnaissance](reconnaissance.md#t1591) |
| `T1591.001` | Determine Physical Locations | [Reconnaissance](reconnaissance.md#t1591001) |
| `T1591.002` | Business Relationships | [Reconnaissance](reconnaissance.md#t1591002) |
| `T1591.003` | Identify Business Tempo | [Reconnaissance](reconnaissance.md#t1591003) |
| `T1591.004` | Identify Roles | [Reconnaissance](reconnaissance.md#t1591004) |
| `T1592` | Gather Victim Host Information | [Reconnaissance](reconnaissance.md#t1592) |
| `T1592.001` | Hardware | [Reconnaissance](reconnaissance.md#t1592001) |
| `T1592.002` | Software | [Reconnaissance](reconnaissance.md#t1592002) |
| `T1592.003` | Firmware | [Reconnaissance](reconnaissance.md#t1592003) |
| `T1592.004` | Client Configurations | [Reconnaissance](reconnaissance.md#t1592004) |
| `T1593` | Search Open Websites/Domains | [Reconnaissance](reconnaissance.md#t1593) |
| `T1593.001` | Social Media | [Reconnaissance](reconnaissance.md#t1593001) |
| `T1593.002` | Search Engines | [Reconnaissance](reconnaissance.md#t1593002) |
| `T1593.003` | Code Repositories | [Reconnaissance](reconnaissance.md#t1593003) |
| `T1594` | Search Victim-Owned Websites | [Reconnaissance](reconnaissance.md#t1594) |
| `T1595` | Active Scanning | [Reconnaissance](reconnaissance.md#t1595) |
| `T1595.001` | Scanning IP Blocks | [Reconnaissance](reconnaissance.md#t1595001) |
| `T1595.002` | Vulnerability Scanning | [Reconnaissance](reconnaissance.md#t1595002) |
| `T1595.003` | Wordlist Scanning | [Reconnaissance](reconnaissance.md#t1595003) |
| `T1596` | Search Open Technical Databases | [Reconnaissance](reconnaissance.md#t1596) |
| `T1596.001` | DNS/Passive DNS | [Reconnaissance](reconnaissance.md#t1596001) |
| `T1596.002` | WHOIS | [Reconnaissance](reconnaissance.md#t1596002) |
| `T1596.003` | Digital Certificates | [Reconnaissance](reconnaissance.md#t1596003) |
| `T1596.004` | CDNs | [Reconnaissance](reconnaissance.md#t1596004) |
| `T1596.005` | Scan Databases | [Reconnaissance](reconnaissance.md#t1596005) |
| `T1597` | Search Closed Sources | [Reconnaissance](reconnaissance.md#t1597) |
| `T1597.001` | Threat Intel Vendors | [Reconnaissance](reconnaissance.md#t1597001) |
| `T1597.002` | Purchase Technical Data | [Reconnaissance](reconnaissance.md#t1597002) |
| `T1598` | Phishing for Information | [Reconnaissance](reconnaissance.md#t1598) |
| `T1598.001` | Spearphishing Service | [Reconnaissance](reconnaissance.md#t1598001) |
| `T1598.002` | Spearphishing Attachment | [Reconnaissance](reconnaissance.md#t1598002) |
| `T1598.003` | Spearphishing Link | [Reconnaissance](reconnaissance.md#t1598003) |
| `T1598.004` | Spearphishing Voice | [Reconnaissance](reconnaissance.md#t1598004) |
| `T1599` | Network Boundary Bridging | [Defense Evasion](defense-evasion.md#t1599) |
| `T1599.001` | Network Address Translation Traversal | [Defense Evasion](defense-evasion.md#t1599001) |
| `T1600` | Weaken Encryption | [Defense Evasion](defense-evasion.md#t1600) |
| `T1600.001` | Reduce Key Space | [Defense Evasion](defense-evasion.md#t1600001) |
| `T1600.002` | Disable Crypto Hardware | [Defense Evasion](defense-evasion.md#t1600002) |
| `T1601` | Modify System Image | [Defense Evasion](defense-evasion.md#t1601) |
| `T1601.001` | Patch System Image | [Defense Evasion](defense-evasion.md#t1601001) |
| `T1601.002` | Downgrade System Image | [Defense Evasion](defense-evasion.md#t1601002) |
| `T1602` | Data from Configuration Repository | [Collection](collection.md#t1602) |
| `T1602.001` | SNMP (MIB Dump) | [Collection](collection.md#t1602001) |
| `T1602.002` | Network Device Configuration Dump | [Collection](collection.md#t1602002) |
| `T1606` | Forge Web Credentials | [Credential Access](credential-access.md#t1606) |
| `T1606.001` | Web Cookies | [Credential Access](credential-access.md#t1606001) |
| `T1606.002` | SAML Tokens | [Credential Access](credential-access.md#t1606002) |
| `T1608` | Stage Capabilities | [Resource Development](resource-development.md#t1608) |
| `T1608.001` | Upload Malware | [Resource Development](resource-development.md#t1608001) |
| `T1608.002` | Upload Tool | [Resource Development](resource-development.md#t1608002) |
| `T1608.003` | Install Digital Certificate | [Resource Development](resource-development.md#t1608003) |
| `T1608.004` | Drive-by Target | [Resource Development](resource-development.md#t1608004) |
| `T1608.005` | Link Target | [Resource Development](resource-development.md#t1608005) |
| `T1608.006` | SEO Poisoning | [Resource Development](resource-development.md#t1608006) |
| `T1609` | Container Administration Command | [Execution](execution.md#t1609) |
| `T1610` | Deploy Container | [Defense Evasion](defense-evasion.md#t1610) |
| `T1611` | Escape to Host | [Privilege Escalation](privilege-escalation.md#t1611) |
| `T1612` | Build Image on Host | [Defense Evasion](defense-evasion.md#t1612) |
| `T1613` | Container and Resource Discovery | [Discovery](discovery.md#t1613) |
| `T1614` | System Location Discovery | [Discovery](discovery.md#t1614) |
| `T1614.001` | System Language Discovery | [Discovery](discovery.md#t1614001) |
| `T1615` | Group Policy Discovery | [Discovery](discovery.md#t1615) |
| `T1619` | Cloud Storage Object Discovery | [Discovery](discovery.md#t1619) |
| `T1620` | Reflective Code Loading | [Defense Evasion](defense-evasion.md#t1620) |
| `T1621` | Multi-Factor Authentication Request Generation | [Credential Access](credential-access.md#t1621) |
| `T1622` | Debugger Evasion | [Defense Evasion](defense-evasion.md#t1622) |
| `T1647` | Plist File Modification | [Defense Evasion](defense-evasion.md#t1647) |
| `T1648` | Serverless Execution | [Execution](execution.md#t1648) |
| `T1649` | Steal or Forge Authentication Certificates | [Credential Access](credential-access.md#t1649) |
| `T1650` | Acquire Access | [Resource Development](resource-development.md#t1650) |
| `T1651` | Cloud Administration Command | [Execution](execution.md#t1651) |
| `T1652` | Device Driver Discovery | [Discovery](discovery.md#t1652) |
| `T1653` | Power Settings | [Persistence](persistence.md#t1653) |
| `T1654` | Log Enumeration | [Discovery](discovery.md#t1654) |
| `T1656` | Impersonation | [Defense Evasion](defense-evasion.md#t1656) |
| `T1657` | Financial Theft | [Impact](impact.md#t1657) |
| `T1659` | Content Injection | [Initial Access](initial-access.md#t1659) |
| `T1665` | Hide Infrastructure | [Command and Control](command-and-control.md#t1665) |
| `T1666` | Modify Cloud Resource Hierarchy | [Defense Evasion](defense-evasion.md#t1666) |
| `T1667` | Email Bombing | [Impact](impact.md#t1667) |
| `T1668` | Exclusive Control | [Persistence](persistence.md#t1668) |
| `T1669` | Wi-Fi Networks | [Initial Access](initial-access.md#t1669) |
| `T1671` | Cloud Application Integration | [Persistence](persistence.md#t1671) |
| `T1672` | Email Spoofing | [Defense Evasion](defense-evasion.md#t1672) |
| `T1673` | Virtual Machine Discovery | [Discovery](discovery.md#t1673) |
| `T1674` | Input Injection | [Execution](execution.md#t1674) |
| `T1675` | ESXi Administration Command | [Execution](execution.md#t1675) |
| `T1677` | Poisoned Pipeline Execution | [Execution](execution.md#t1677) |
| `T1678` | Delay Execution | [Defense Evasion](defense-evasion.md#t1678) |
| `T1679` | Selective Exclusion | [Defense Evasion](defense-evasion.md#t1679) |
| `T1680` | Local Storage Discovery | [Discovery](discovery.md#t1680) |
| `T1681` | Search Threat Vendor Data | [Reconnaissance](reconnaissance.md#t1681) |
