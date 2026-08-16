# ATT&CK Detection Strategies — Index

> **691 MITRE ATT&CK detection strategies** and **1739 analytics** (v18.1) — the authoritative, MITRE-authored guidance for detecting each technique, with concrete log sources, channels, detection logic, and tunable parameters. Complements the [ready-to-run Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md).

**By tactic:** [Reconnaissance](reconnaissance.md) · [Resource Development](resource-development.md) · [Initial Access](initial-access.md) · [Execution](execution.md) · [Persistence](persistence.md) · [Privilege Escalation](privilege-escalation.md) · [Defense Evasion](defense-evasion.md) · [Credential Access](credential-access.md) · [Discovery](discovery.md) · [Lateral Movement](lateral-movement.md) · [Collection](collection.md) · [Command and Control](command-and-control.md) · [Exfiltration](exfiltration.md) · [Impact](impact.md)

Datasets: [`detection_strategies.jsonl`](../../data/attack/detection_strategies.jsonl) · [`analytics.jsonl`](../../data/attack/analytics.jsonl) · [`data_components.jsonl`](../../data/attack/data_components.jsonl)

| Technique | Name | Strategy | Detail |
|---|---|---|---|
| `T1001` | Data Obfuscation | Detect Obfuscated C2 via Network Traffic Analysis | [Command and Control](command-and-control.md#t1001) |
| `T1001.001` | Junk Data | Detecting Junk Data in C2 Channels via Behavioral Analysis | [Command and Control](command-and-control.md#t1001001) |
| `T1001.002` | Steganography | Detecting Steganographic Command and Control via File + Network Correlation | [Command and Control](command-and-control.md#t1001002) |
| `T1001.003` | Protocol or Service Impersonation | Detecting Protocol or Service Impersonation via Anomalous TLS, HTTP Header, and Port Mismatch Correlation | [Command and Control](command-and-control.md#t1001003) |
| `T1003` | OS Credential Dumping | Credential Dumping via Sensitive Memory and Registry Access Correlation | [Credential Access](credential-access.md#t1003) |
| `T1003.001` | LSASS Memory | Detection of Credential Dumping from LSASS Memory via Access and Dump Sequence | [Credential Access](credential-access.md#t1003001) |
| `T1003.002` | Security Account Manager | Credential Dumping from SAM via Registry Dump and Local File Access | [Credential Access](credential-access.md#t1003002) |
| `T1003.003` | NTDS | Detection of NTDS.dit Credential Dumping from Domain Controllers | [Credential Access](credential-access.md#t1003003) |
| `T1003.004` | LSA Secrets | Detection of LSA Secrets Dumping via Registry and Memory Extraction | [Credential Access](credential-access.md#t1003004) |
| `T1003.005` | Cached Domain Credentials | Detection of Cached Domain Credential Dumping via Local Hash Cache Access | [Credential Access](credential-access.md#t1003005) |
| `T1003.006` | DCSync | Detection of Unauthorized DCSync Operations via Replication API Abuse | [Credential Access](credential-access.md#t1003006) |
| `T1003.007` | Proc Filesystem | Detecting OS Credential Dumping via /proc Filesystem Access on Linux | [Credential Access](credential-access.md#t1003007) |
| `T1003.008` | /etc/passwd and /etc/shadow | Credential Access via /etc/passwd and /etc/shadow Parsing | [Credential Access](credential-access.md#t1003008) |
| `T1005` | Data from Local System | Detection of Local Data Collection Prior to Exfiltration | [Collection](collection.md#t1005) |
| `T1006` | Direct Volume Access | Detection of Direct Volume Access for File System Evasion | [Defense Evasion](defense-evasion.md#t1006) |
| `T1007` | System Service Discovery | Detection of System Service Discovery Commands Across OS Platforms | [Discovery](discovery.md#t1007) |
| `T1008` | Fallback Channels | Behavioral Detection of Fallback or Alternate C2 Channels | [Command and Control](command-and-control.md#t1008) |
| `T1010` | Application Window Discovery | Detection of Application Window Enumeration via API or Scripting | [Discovery](discovery.md#t1010) |
| `T1011` | Exfiltration Over Other Network Medium | Detection of Exfiltration Over Alternate Network Interfaces | [Exfiltration](exfiltration.md#t1011) |
| `T1011.001` | Exfiltration Over Bluetooth | Detection of Bluetooth-Based Data Exfiltration | [Exfiltration](exfiltration.md#t1011001) |
| `T1012` | Query Registry | Detection of Registry Query for Environmental Discovery | [Discovery](discovery.md#t1012) |
| `T1014` | Rootkit | Detection of Kernel/User-Level Rootkit Behavior Across Platforms | [Defense Evasion](defense-evasion.md#t1014) |
| `T1016` | System Network Configuration Discovery | Behavioral Detection of System Network Configuration Discovery | [Discovery](discovery.md#t1016) |
| `T1016.001` | Internet Connection Discovery | Behavioral Detection of Internet Connection Discovery | [Discovery](discovery.md#t1016001) |
| `T1016.002` | Wi-Fi Discovery | Behavioral Detection of Wi-Fi Discovery Activity | [Discovery](discovery.md#t1016002) |
| `T1018` | Remote System Discovery | Detection Strategy for Remote System Enumeration Behavior | [Discovery](discovery.md#t1018) |
| `T1020` | Automated Exfiltration | Automated Exfiltration Detection Strategy | [Exfiltration](exfiltration.md#t1020) |
| `T1020.001` | Traffic Duplication | Detection Strategy for Traffic Duplication via Mirroring in IaaS and Network Devices | [Exfiltration](exfiltration.md#t1020001) |
| `T1021` | Remote Services | Behavioral Detection Strategy for Remote Service Logins and Post-Access Activity | [Lateral Movement](lateral-movement.md#t1021) |
| `T1021.001` | Remote Desktop Protocol | Multi-event Detection Strategy for RDP-Based Remote Logins and Post-Access Activity | [Lateral Movement](lateral-movement.md#t1021001) |
| `T1021.002` | SMB/Windows Admin Shares | Multi-Event Detection for SMB Admin Share Lateral Movement | [Lateral Movement](lateral-movement.md#t1021002) |
| `T1021.003` | Distributed Component Object Model | Multi-Event Behavioral Detection for DCOM-Based Remote Code Execution | [Lateral Movement](lateral-movement.md#t1021003) |
| `T1021.004` | SSH | Behavioral Detection of Remote SSH Logins Followed by Post-Login Execution | [Lateral Movement](lateral-movement.md#t1021004) |
| `T1021.005` | VNC | Behavioral Detection of Unauthorized VNC Remote Control Sessions | [Lateral Movement](lateral-movement.md#t1021005) |
| `T1021.006` | Windows Remote Management | Behavioral Detection of WinRM-Based Remote Access | [Lateral Movement](lateral-movement.md#t1021006) |
| `T1021.007` | Cloud Services | Behavioral Detection of Remote Cloud Logins via Valid Accounts | [Lateral Movement](lateral-movement.md#t1021007) |
| `T1021.008` | Direct Cloud VM Connections | Detection of Direct VM Console Access via Cloud-Native Methods | [Lateral Movement](lateral-movement.md#t1021008) |
| `T1025` | Data from Removable Media | Detection of Data Access and Collection from Removable Media | [Collection](collection.md#t1025) |
| `T1027` | Obfuscated Files or Information | Behavioral Detection of Obfuscated Files or Information | [Defense Evasion](defense-evasion.md#t1027) |
| `T1027.001` | Binary Padding | Detection Strategy for Obfuscated Files or Information: Binary Padding | [Defense Evasion](defense-evasion.md#t1027001) |
| `T1027.002` | Software Packing | Obfuscated Binary Unpacking Detection via Behavioral Patterns | [Defense Evasion](defense-evasion.md#t1027002) |
| `T1027.003` | Steganography | Detection Strategy for Steganographic Abuse in File & Script Execution | [Defense Evasion](defense-evasion.md#t1027003) |
| `T1027.004` | Compile After Delivery | Detection Strategy for Compile After Delivery - Source Code to Executable Transformation | [Defense Evasion](defense-evasion.md#t1027004) |
| `T1027.005` | Indicator Removal from Tools | Detection Strategy for Indicator Removal from Tools - Post-AV Evasion Modification | [Defense Evasion](defense-evasion.md#t1027005) |
| `T1027.006` | HTML Smuggling | Detection Strategy for HTML Smuggling via JavaScript Blob + Dynamic File Drop | [Defense Evasion](defense-evasion.md#t1027006) |
| `T1027.007` | Dynamic API Resolution | Detection Strategy for Dynamic API Resolution via Hash-Based Function Lookups | [Defense Evasion](defense-evasion.md#t1027007) |
| `T1027.008` | Stripped Payloads | Detection Strategy for Stripped Payloads Across Platforms | [Defense Evasion](defense-evasion.md#t1027008) |
| `T1027.009` | Embedded Payloads | Detection Strategy for Embedded Payloads | [Defense Evasion](defense-evasion.md#t1027009) |
| `T1027.010` | Command Obfuscation | Detection Strategy for Command Obfuscation | [Defense Evasion](defense-evasion.md#t1027010) |
| `T1027.011` | Fileless Storage | Detection Strategy for Fileless Storage via Registry, WMI, and Shared Memory | [Defense Evasion](defense-evasion.md#t1027011) |
| `T1027.012` | LNK Icon Smuggling | Detection Strategy for LNK Icon Smuggling | [Defense Evasion](defense-evasion.md#t1027012) |
| `T1027.013` | Encrypted/Encoded File | Encrypted or Encoded File Payload Detection Strategy | [Defense Evasion](defense-evasion.md#t1027013) |
| `T1027.014` | Polymorphic Code | Detection Strategy for Polymorphic Code Mutation and Execution | [Defense Evasion](defense-evasion.md#t1027014) |
| `T1027.015` | Compression | Detection Strategy for Compressed Payload Creation and Execution | [Defense Evasion](defense-evasion.md#t1027015) |
| `T1027.016` | Junk Code Insertion | Detection Strategy for Junk Code Obfuscation with Suspicious Execution Patterns | [Defense Evasion](defense-evasion.md#t1027016) |
| `T1027.017` | SVG Smuggling | Detection Strategy for SVG Smuggling with Script Execution and Delivery Behavior | [Defense Evasion](defense-evasion.md#t1027017) |
| `T1029` | Scheduled Transfer | Detection Strategy for Scheduled Transfer and Recurrent Exfiltration Patterns | [Exfiltration](exfiltration.md#t1029) |
| `T1030` | Data Transfer Size Limits | Detection Strategy for Data Transfer Size Limits and Chunked Exfiltration | [Exfiltration](exfiltration.md#t1030) |
| `T1033` | System Owner/User Discovery | Behavioral Detection of User Discovery via Local and Remote Enumeration | [Discovery](discovery.md#t1033) |
| `T1036` | Masquerading | Behavioral Detection of Masquerading Across Platforms via Metadata and Execution Discrepancy | [Defense Evasion](defense-evasion.md#t1036) |
| `T1036.001` | Invalid Code Signature | Invalid Code Signature Execution Detection via Metadata and Behavioral Context | [Defense Evasion](defense-evasion.md#t1036001) |
| `T1036.002` | Right-to-Left Override | Right-to-Left Override Masquerading Detection via Filename and Execution Context | [Defense Evasion](defense-evasion.md#t1036002) |
| `T1036.003` | Rename Legitimate Utilities | Renamed Legitimate Utility Execution with Metadata Mismatch and Suspicious Path | [Defense Evasion](defense-evasion.md#t1036003) |
| `T1036.004` | Masquerade Task or Service | Detection of Masqueraded Tasks or Services with Suspicious Naming and Execution | [Defense Evasion](defense-evasion.md#t1036004) |
| `T1036.005` | Match Legitimate Resource Name or Location | Detection Strategy for Masquerading via Legitimate Resource Name or Location | [Defense Evasion](defense-evasion.md#t1036005) |
| `T1036.006` | Space after Filename | Masquerading via Space After Filename - Behavioral Detection Strategy | [Defense Evasion](defense-evasion.md#t1036006) |
| `T1036.007` | Double File Extension | Detection Strategy for Double File Extension Masquerading | [Defense Evasion](defense-evasion.md#t1036007) |
| `T1036.008` | Masquerade File Type | Detection Strategy for Masquerading via File Type Modification | [Defense Evasion](defense-evasion.md#t1036008) |
| `T1036.009` | Break Process Trees | Detection Strategy for Masquerading via Breaking Process Trees | [Defense Evasion](defense-evasion.md#t1036009) |
| `T1036.010` | Masquerade Account Name | Detection Strategy for Masquerading via Account Name Similarity | [Defense Evasion](defense-evasion.md#t1036010) |
| `T1036.011` | Overwrite Process Arguments | Detection Strategy for Overwritten Process Arguments Masquerading | [Defense Evasion](defense-evasion.md#t1036011) |
| `T1036.012` | Browser Fingerprint | Detection of Spoofed User-Agent | [Defense Evasion](defense-evasion.md#t1036012) |
| `T1037` | Boot or Logon Initialization Scripts | Boot or Logon Initialization Scripts Detection Strategy | [Persistence](persistence.md#t1037) |
| `T1037.001` | Logon Script (Windows) | Detect Logon Script Modifications and Execution | [Persistence](persistence.md#t1037001) |
| `T1037.002` | Login Hook | Detection Strategy for Login Hook Persistence on macOS | [Persistence](persistence.md#t1037002) |
| `T1037.003` | Network Logon Script | Detect Network Logon Script Abuse via Multi-Event Correlation on Windows | [Persistence](persistence.md#t1037003) |
| `T1037.004` | RC Scripts | Detection Strategy for Boot or Logon Initialization Scripts: RC Scripts | [Persistence](persistence.md#t1037004) |
| `T1037.005` | Startup Items | Detect Modification of macOS Startup Items | [Persistence](persistence.md#t1037005) |
| `T1039` | Data from Network Shared Drive | Detection Strategy for Data from Network Shared Drive | [Collection](collection.md#t1039) |
| `T1040` | Network Sniffing | Detection Strategy for Network Sniffing Across Platforms | [Credential Access](credential-access.md#t1040) |
| `T1041` | Exfiltration Over C2 Channel | Detection Strategy for Exfiltration Over C2 Channel | [Exfiltration](exfiltration.md#t1041) |
| `T1046` | Network Service Discovery | Behavioral Detection Strategy for Network Service Discovery Across Platforms | [Discovery](discovery.md#t1046) |
| `T1047` | Windows Management Instrumentation | Behavioral Detection Strategy for WMI Execution Abuse on Windows | [Execution](execution.md#t1047) |
| `T1048` | Exfiltration Over Alternative Protocol | Behavioral Detection Strategy for Exfiltration Over Alternative Protocol | [Exfiltration](exfiltration.md#t1048) |
| `T1048.001` | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | Behavioral Detection Strategy for Exfiltration Over Symmetric Encrypted Non-C2 Protocol | [Exfiltration](exfiltration.md#t1048001) |
| `T1048.002` | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Detection of Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | [Exfiltration](exfiltration.md#t1048002) |
| `T1048.003` | Exfiltration Over Unencrypted Non-C2 Protocol | Detection of Exfiltration Over Unencrypted Non-C2 Protocol | [Exfiltration](exfiltration.md#t1048003) |
| `T1049` | System Network Connections Discovery | Detection of System Network Connections Discovery Across Platforms | [Discovery](discovery.md#t1049) |
| `T1052` | Exfiltration Over Physical Medium | Detection of Data Exfiltration via Removable Media | [Exfiltration](exfiltration.md#t1052) |
| `T1052.001` | Exfiltration over USB | Detection of USB-Based Data Exfiltration | [Exfiltration](exfiltration.md#t1052001) |
| `T1053` | Scheduled Task/Job | Cross-Platform Behavioral Detection of Scheduled Task/Job Abuse | [Execution](execution.md#t1053) |
| `T1053.002` | At | Cross-Platform Detection of Scheduled Task/Job Abuse via `at` Utility | [Execution](execution.md#t1053002) |
| `T1053.003` | Cron | Cross-Platform Detection of Cron Job Abuse for Persistence and Execution | [Execution](execution.md#t1053003) |
| `T1053.005` | Scheduled Task | Detection of Suspicious Scheduled Task Creation and Execution on Windows | [Execution](execution.md#t1053005) |
| `T1053.006` | Systemd Timers | Behavioral Detection of Systemd Timer Abuse for Scheduled Execution | [Execution](execution.md#t1053006) |
| `T1053.007` | Container Orchestration Job | Detection of Malicious Kubernetes CronJob Scheduling | [Execution](execution.md#t1053007) |
| `T1055` | Process Injection | Behavioral Detection of Process Injection Across Platforms | [Defense Evasion](defense-evasion.md#t1055) |
| `T1055.001` | Dynamic-link Library Injection | Behavioral Detection of DLL Injection via Windows API | [Defense Evasion](defense-evasion.md#t1055001) |
| `T1055.002` | Portable Executable Injection | Behavioral Detection of PE Injection via Remote Memory Mapping | [Defense Evasion](defense-evasion.md#t1055002) |
| `T1055.003` | Thread Execution Hijacking | Behavioral Detection of Thread Execution Hijacking via Thread Suspension and Context Switching | [Defense Evasion](defense-evasion.md#t1055003) |
| `T1055.004` | Asynchronous Procedure Call | Behavioral Detection of Asynchronous Procedure Call (APC) Injection via Remote Thread Queuing | [Defense Evasion](defense-evasion.md#t1055004) |
| `T1055.005` | Thread Local Storage | Detection Strategy for TLS Callback Injection via PE Memory Modification and Hollowing | [Defense Evasion](defense-evasion.md#t1055005) |
| `T1055.008` | Ptrace System Calls | Detection Strategy for Ptrace-Based Process Injection on Linux | [Defense Evasion](defense-evasion.md#t1055008) |
| `T1055.009` | Proc Memory | Detection Strategy for /proc Memory Injection on Linux | [Defense Evasion](defense-evasion.md#t1055009) |
| `T1055.011` | Extra Window Memory Injection | Detection Strategy for Extra Window Memory (EWM) Injection on Windows | [Defense Evasion](defense-evasion.md#t1055011) |
| `T1055.012` | Process Hollowing | Detection Strategy for Process Hollowing on Windows | [Defense Evasion](defense-evasion.md#t1055012) |
| `T1055.013` | Process Doppelgänging | Detection Strategy for Process Doppelgänging on Windows | [Defense Evasion](defense-evasion.md#t1055013) |
| `T1055.014` | VDSO Hijacking | Detection Strategy for VDSO Hijacking on Linux | [Defense Evasion](defense-evasion.md#t1055014) |
| `T1055.015` | ListPlanting | Detection Strategy for ListPlanting Injection on Windows | [Defense Evasion](defense-evasion.md#t1055015) |
| `T1056` | Input Capture | Behavioral Detection of Input Capture Across Platforms | [Collection](collection.md#t1056) |
| `T1056.001` | Keylogging | Behavioral Detection of Keylogging Activity Across Platforms | [Collection](collection.md#t1056001) |
| `T1056.002` | GUI Input Capture | Behavioral Detection of Spoofed GUI Credential Prompts | [Collection](collection.md#t1056002) |
| `T1056.003` | Web Portal Capture | Detection of Credential Harvesting via Web Portal Modification | [Collection](collection.md#t1056003) |
| `T1056.004` | Credential API Hooking | Detection of Credential Harvesting via API Hooking | [Collection](collection.md#t1056004) |
| `T1057` | Process Discovery | Detection of Adversarial Process Discovery Behavior | [Discovery](discovery.md#t1057) |
| `T1059` | Command and Scripting Interpreter | Behavioral Detection of Command and Scripting Interpreter Abuse | [Execution](execution.md#t1059) |
| `T1059.001` | PowerShell | Abuse of PowerShell for Arbitrary Execution | [Execution](execution.md#t1059001) |
| `T1059.002` | AppleScript | Detection of AppleScript-Based Execution on macOS | [Execution](execution.md#t1059002) |
| `T1059.003` | Windows Command Shell | Behavioral Detection of Windows Command Shell Execution | [Execution](execution.md#t1059003) |
| `T1059.004` | Unix Shell | Behavioral Detection of Unix Shell Execution | [Execution](execution.md#t1059004) |
| `T1059.005` | Visual Basic | Behavioral Detection of Visual Basic Execution (VBS/VBA/VBScript) | [Execution](execution.md#t1059005) |
| `T1059.006` | Python | Cross-Platform Behavioral Detection of Python Execution | [Execution](execution.md#t1059006) |
| `T1059.007` | JavaScript | Cross-Platform Detection of JavaScript Execution Abuse | [Execution](execution.md#t1059007) |
| `T1059.008` | Network Device CLI | Behavioral Detection of CLI Abuse on Network Devices | [Execution](execution.md#t1059008) |
| `T1059.009` | Cloud API | Behavioral Detection of Malicious Cloud API Scripting | [Execution](execution.md#t1059009) |
| `T1059.010` | AutoHotKey & AutoIT | Detection Strategy for AutoHotKey & AutoIT Abuse | [Execution](execution.md#t1059010) |
| `T1059.011` | Lua | Detection Strategy for Lua Scripting Abuse | [Execution](execution.md#t1059011) |
| `T1059.012` | Hypervisor CLI | Detection Strategy for ESXi Hypervisor CLI Abuse | [Execution](execution.md#t1059012) |
| `T1059.013` | Container CLI/API | Container CLI and API Abuse via Docker/Kubernetes (T1059.013) | [Execution](execution.md#t1059013) |
| `T1068` | Exploitation for Privilege Escalation | Detection Strategy for Exploitation for Privilege Escalation | [Privilege Escalation](privilege-escalation.md#t1068) |
| `T1069` | Permission Groups Discovery | Behavioral Detection of Permission Groups Discovery | [Discovery](discovery.md#t1069) |
| `T1069.001` | Local Groups | Behavioral Detection of Local Group Enumeration Across OS Platforms | [Discovery](discovery.md#t1069001) |
| `T1069.002` | Domain Groups | Behavioral Detection of Domain Group Discovery | [Discovery](discovery.md#t1069002) |
| `T1069.003` | Cloud Groups | Behavioral Detection of Cloud Group Enumeration via API and CLI Access | [Discovery](discovery.md#t1069003) |
| `T1070` | Indicator Removal | Behavioral Detection of Indicator Removal Across Platforms | [Defense Evasion](defense-evasion.md#t1070) |
| `T1070.001` | Clear Windows Event Logs | Detection of Event Log Clearing on Windows via Behavioral Chain | [Defense Evasion](defense-evasion.md#t1070001) |
| `T1070.002` | Clear Linux or Mac System Logs | Behavioral Detection of Log File Clearing on Linux and macOS | [Defense Evasion](defense-evasion.md#t1070002) |
| `T1070.003` | Clear Command History | Behavioral Detection of Command History Clearing | [Defense Evasion](defense-evasion.md#t1070003) |
| `T1070.004` | File Deletion | Behavioral Detection of Malicious File Deletion | [Defense Evasion](defense-evasion.md#t1070004) |
| `T1070.005` | Network Share Connection Removal | Behavioral Detection of Network Share Connection Removal via CLI and SMB Disconnects | [Defense Evasion](defense-evasion.md#t1070005) |
| `T1070.006` | Timestomp | Cross-Platform Behavioral Detection of File Timestomping via Metadata Tampering | [Defense Evasion](defense-evasion.md#t1070006) |
| `T1070.007` | Clear Network Connection History and Configurations | Behavioral Detection of Network History and Configuration Tampering | [Defense Evasion](defense-evasion.md#t1070007) |
| `T1070.008` | Clear Mailbox Data | Behavioral Detection of Mailbox Data and Log Deletion for Anti-Forensics | [Defense Evasion](defense-evasion.md#t1070008) |
| `T1070.009` | Clear Persistence | Detection of Persistence Artifact Removal Across Host Platforms | [Defense Evasion](defense-evasion.md#t1070009) |
| `T1070.010` | Relocate Malware | Detection of Malware Relocation via Suspicious File Movement | [Defense Evasion](defense-evasion.md#t1070010) |
| `T1071` | Application Layer Protocol | Detection of Command and Control Over Application Layer Protocols | [Command and Control](command-and-control.md#t1071) |
| `T1071.001` | Web Protocols | Detection of Web Protocol-Based C2 Over HTTP, HTTPS, or WebSockets | [Command and Control](command-and-control.md#t1071001) |
| `T1071.002` | File Transfer Protocols | Detection of File Transfer Protocol-Based C2 (FTP, FTPS, SMB, TFTP) | [Command and Control](command-and-control.md#t1071002) |
| `T1071.003` | Mail Protocols | Detection of Mail Protocol-Based C2 Activity (SMTP, IMAP, POP3) | [Command and Control](command-and-control.md#t1071003) |
| `T1071.004` | DNS | Behavioral Detection of DNS Tunneling and Application Layer Abuse | [Command and Control](command-and-control.md#t1071004) |
| `T1071.005` | Publish/Subscribe Protocols | Behavioral Detection of Publish/Subscribe Protocol Misuse for C2 | [Command and Control](command-and-control.md#t1071005) |
| `T1072` | Software Deployment Tools | Detection of Adversary Abuse of Software Deployment Tools | [Execution](execution.md#t1072) |
| `T1074` | Data Staged | Detection of Data Staging Prior to Exfiltration | [Collection](collection.md#t1074) |
| `T1074.001` | Local Data Staging | Detection of Local Data Staging Prior to Exfiltration | [Collection](collection.md#t1074001) |
| `T1074.002` | Remote Data Staging | Detection of Remote Data Staging Prior to Exfiltration | [Collection](collection.md#t1074002) |
| `T1078` | Valid Accounts | Detection of Valid Account Abuse Across Platforms | [Defense Evasion](defense-evasion.md#t1078) |
| `T1078.001` | Default Accounts | Detection of Default Account Abuse Across Platforms | [Defense Evasion](defense-evasion.md#t1078001) |
| `T1078.002` | Domain Accounts | Abuse of Domain Accounts | [Defense Evasion](defense-evasion.md#t1078002) |
| `T1078.003` | Local Accounts | Detection of Local Account Abuse for Initial Access and Persistence | [Defense Evasion](defense-evasion.md#t1078003) |
| `T1078.004` | Cloud Accounts | Detection of Abused or Compromised Cloud Accounts for Access and Persistence | [Defense Evasion](defense-evasion.md#t1078004) |
| `T1080` | Taint Shared Content | Detection of Tainted Content Written to Shared Storage | [Lateral Movement](lateral-movement.md#t1080) |
| `T1082` | System Information Discovery | System Discovery via Native and Remote Utilities | [Discovery](discovery.md#t1082) |
| `T1083` | File and Directory Discovery | Recursive Enumeration of Files and Directories Across Privilege Contexts | [Discovery](discovery.md#t1083) |
| `T1087` | Account Discovery | Enumeration of User or Account Information Across Platforms | [Discovery](discovery.md#t1087) |
| `T1087.001` | Local Account | Local Account Enumeration Across Host Platforms | [Discovery](discovery.md#t1087001) |
| `T1087.002` | Domain Account | Domain Account Enumeration Across Platforms | [Discovery](discovery.md#t1087002) |
| `T1087.003` | Email Account | Enumeration of Global Address Lists via Email Account Discovery | [Discovery](discovery.md#t1087003) |
| `T1087.004` | Cloud Account | Cloud Account Enumeration via API, CLI, and Scripting Interfaces | [Discovery](discovery.md#t1087004) |
| `T1090` | Proxy | Detection of Proxy Infrastructure Setup and Traffic Bridging | [Command and Control](command-and-control.md#t1090) |
| `T1090.001` | Internal Proxy | Internal Proxy Behavior via Lateral Host-to-Host C2 Relay | [Command and Control](command-and-control.md#t1090001) |
| `T1090.002` | External Proxy | External Proxy Behavior via Outbound Relay to Intermediate Infrastructure | [Command and Control](command-and-control.md#t1090002) |
| `T1090.003` | Multi-hop Proxy | Multi-hop Proxy Behavior via Relay Node Chaining, Onion Routing, and Network Tunneling | [Command and Control](command-and-control.md#t1090003) |
| `T1090.004` | Domain Fronting | Domain Fronting Behavior via Mismatched TLS SNI and HTTP Host Headers | [Command and Control](command-and-control.md#t1090004) |
| `T1091` | Replication Through Removable Media | Removable Media Execution Chain Detection via File and Process Activity | [Lateral Movement](lateral-movement.md#t1091) |
| `T1092` | Communication Through Removable Media | Cross-host C2 via Removable Media Relay | [Command and Control](command-and-control.md#t1092) |
| `T1095` | Non-Application Layer Protocol | Detection of Non-Application Layer Protocols for C2 | [Command and Control](command-and-control.md#t1095) |
| `T1098` | Account Manipulation | Account Manipulation Behavior Chain Detection | [Persistence](persistence.md#t1098) |
| `T1098.001` | Additional Cloud Credentials | Detection Strategy for Additional Cloud Credentials in IaaS/IdP/SaaS | [Persistence](persistence.md#t1098001) |
| `T1098.002` | Additional Email Delegate Permissions | Detection Strategy for Addition of Email Delegate Permissions | [Persistence](persistence.md#t1098002) |
| `T1098.003` | Additional Cloud Roles | Detection Strategy for Role Addition to Cloud Accounts | [Persistence](persistence.md#t1098003) |
| `T1098.004` | SSH Authorized Keys | Detection Strategy for SSH Key Injection in Authorized Keys | [Persistence](persistence.md#t1098004) |
| `T1098.005` | Device Registration | Suspicious Device Registration via Entra ID or MFA Platform | [Persistence](persistence.md#t1098005) |
| `T1098.006` | Additional Container Cluster Roles | Suspicious RoleBinding or ClusterRoleBinding Assignment in Kubernetes | [Persistence](persistence.md#t1098006) |
| `T1098.007` | Additional Local or Domain Groups | Suspicious Addition to Local or Domain Groups | [Persistence](persistence.md#t1098007) |
| `T1102` | Web Service | Suspicious Use of Web Services for C2 | [Command and Control](command-and-control.md#t1102) |
| `T1102.001` | Dead Drop Resolver | Detection Strategy for Web Service: Dead Drop Resolver | [Command and Control](command-and-control.md#t1102001) |
| `T1102.002` | Bidirectional Communication | Detect Bidirectional Web Service C2 Channels via Process & Network Correlation | [Command and Control](command-and-control.md#t1102002) |
| `T1102.003` | One-Way Communication | Detect One-Way Web Service Command Channels | [Command and Control](command-and-control.md#t1102003) |
| `T1104` | Multi-Stage Channels | Detect Multi-Stage Command and Control Channels | [Command and Control](command-and-control.md#t1104) |
| `T1105` | Ingress Tool Transfer | Detect Ingress Tool Transfers via Behavioral Chain | [Command and Control](command-and-control.md#t1105) |
| `T1106` | Native API | Behavioral Detection of Native API Invocation via Unusual DLL Loads and Direct Syscalls | [Execution](execution.md#t1106) |
| `T1110` | Brute Force | Brute Force Authentication Failures with Multi-Platform Log Correlation | [Credential Access](credential-access.md#t1110) |
| `T1110.001` | Password Guessing | Password Guessing via Multi-Source Authentication Failure Correlation | [Credential Access](credential-access.md#t1110001) |
| `T1110.002` | Password Cracking | Post-Credential Dump Password Cracking Detection via Suspicious File Access and Hash Analysis Tools | [Credential Access](credential-access.md#t1110002) |
| `T1110.003` | Password Spraying | Distributed Password Spraying via Authentication Failures Across Multiple Accounts | [Credential Access](credential-access.md#t1110003) |
| `T1110.004` | Credential Stuffing | Credential Stuffing Detection via Reused Breached Credentials Across Services | [Credential Access](credential-access.md#t1110004) |
| `T1111` | Multi-Factor Authentication Interception | Detection Strategy for MFA Interception via Input Capture and Smart Card Proxying | [Credential Access](credential-access.md#t1111) |
| `T1112` | Modify Registry | Behavior-Based Registry Modification Detection on Windows | [Defense Evasion](defense-evasion.md#t1112) |
| `T1113` | Screen Capture | Detect Screen Capture via Commands and API Calls | [Collection](collection.md#t1113) |
| `T1114` | Email Collection | Email Collection via Local Email Access and Auto-Forwarding Behavior | [Collection](collection.md#t1114) |
| `T1114.001` | Local Email Collection | Detect Local Email Collection via Outlook Data File Access and Command Line Tooling | [Collection](collection.md#t1114001) |
| `T1114.002` | Remote Email Collection | Detect Remote Email Collection via Abnormal Login and Programmatic Access | [Collection](collection.md#t1114002) |
| `T1114.003` | Email Forwarding Rule | Email Forwarding Rule Abuse Detection Across Platforms | [Collection](collection.md#t1114003) |
| `T1115` | Clipboard Data | Clipboard Data Access with Anomalous Context | [Collection](collection.md#t1115) |
| `T1119` | Automated Collection | Automated File and API Collection Detection Across Platforms | [Collection](collection.md#t1119) |
| `T1120` | Peripheral Device Discovery | Peripheral Device Enumeration via System Utilities and API Calls | [Discovery](discovery.md#t1120) |
| `T1123` | Audio Capture | Behavioral Detection Strategy for T1123 Audio Capture Across Windows, Linux, macOS | [Collection](collection.md#t1123) |
| `T1124` | System Time Discovery | Behavior-chain, platform-aware detection strategy for T1124 System Time Discovery | [Discovery](discovery.md#t1124) |
| `T1125` | Video Capture | Behavior-chain, platform-aware detection strategy for T1125 Video Capture | [Collection](collection.md#t1125) |
| `T1127` | Trusted Developer Utilities Proxy Execution | Behavior-chain, platform-aware detection strategy for T1127 Trusted Developer Utilities Proxy Execution (Windows) | [Defense Evasion](defense-evasion.md#t1127) |
| `T1127.001` | MSBuild | Behavior-chain detection strategy for T1127.001 Trusted Developer Utilities Proxy Execution: MSBuild (Windows) | [Defense Evasion](defense-evasion.md#t1127001) |
| `T1127.002` | ClickOnce | Behavior-chain detection strategy for T1127.002 Trusted Developer Utilities Proxy Execution: ClickOnce (Windows) | [Defense Evasion](defense-evasion.md#t1127002) |
| `T1127.003` | JamPlus | Behavior-chain detection strategy for T1127.003 Trusted Developer Utilities Proxy Execution: JamPlus (Windows) | [Defense Evasion](defense-evasion.md#t1127003) |
| `T1129` | Shared Modules | Behavior-chain, platform-aware detection strategy for T1129 Shared Modules | [Execution](execution.md#t1129) |
| `T1132` | Data Encoding | Detection Strategy for Data Encoding in C2 Channels | [Command and Control](command-and-control.md#t1132) |
| `T1132.001` | Standard Encoding | Behavior-chain detection for T1132.001 Data Encoding: Standard Encoding (Base64/Hex/MIME) across Windows, Linux, macOS, ESXi | [Command and Control](command-and-control.md#t1132001) |
| `T1132.002` | Non-Standard Encoding | Behavior-chain detection for T1132.002 Data Encoding: Non-Standard Encoding across Windows, Linux, macOS, ESXi | [Command and Control](command-and-control.md#t1132002) |
| `T1133` | External Remote Services | Behavior-chain detection for T1133 External Remote Services across Windows, Linux, macOS, Containers | [Persistence](persistence.md#t1133) |
| `T1134` | Access Token Manipulation | Behavior-chain detection for T1134 Access Token Manipulation on Windows | [Defense Evasion](defense-evasion.md#t1134) |
| `T1134.001` | Token Impersonation/Theft | Behavior-chain detection for T1134.001 Access Token Manipulation: Token Impersonation/Theft on Windows | [Defense Evasion](defense-evasion.md#t1134001) |
| `T1134.002` | Create Process with Token | Behavior-chain detection for T1134.002 Create Process with Token (Windows) | [Defense Evasion](defense-evasion.md#t1134002) |
| `T1134.003` | Make and Impersonate Token | Behavior‑chain detection for T1134.003 Make and Impersonate Token (Windows) | [Defense Evasion](defense-evasion.md#t1134003) |
| `T1134.004` | Parent PID Spoofing | Behavior-chain detection for T1134.004 Access Token Manipulation: Parent PID Spoofing (Windows) | [Defense Evasion](defense-evasion.md#t1134004) |
| `T1134.005` | SID-History Injection | Behavior-chain detection for T1134.005 Access Token Manipulation: SID-History Injection (Windows) | [Defense Evasion](defense-evasion.md#t1134005) |
| `T1135` | Network Share Discovery | Behavior-chain detection for T1135 Network Share Discovery across Windows, Linux, and macOS | [Discovery](discovery.md#t1135) |
| `T1136` | Create Account | Detection Strategy for T1136 - Create Account across platforms | [Persistence](persistence.md#t1136) |
| `T1136.001` | Local Account | T1136.001 Detection Strategy - Local Account Creation Across Platforms | [Persistence](persistence.md#t1136001) |
| `T1136.002` | Domain Account | T1136.002 Detection Strategy - Domain Account Creation Across Platforms | [Persistence](persistence.md#t1136002) |
| `T1136.003` | Cloud Account | Detection Strategy for T1136.003 - Cloud Account Creation across IaaS, IdP, SaaS, Office | [Persistence](persistence.md#t1136003) |
| `T1137` | Office Application Startup | Detect Office Startup-Based Persistence via Macros, Forms, and Registry Hooks | [Persistence](persistence.md#t1137) |
| `T1137.001` | Office Template Macros | Detect Persistence via Office Template Macro Injection or Registry Hijack | [Persistence](persistence.md#t1137001) |
| `T1137.002` | Office Test | Detect Persistence via Office Test Registry DLL Injection | [Persistence](persistence.md#t1137002) |
| `T1137.003` | Outlook Forms | Detect Persistence via Outlook Custom Forms Triggered by Malicious Email | [Persistence](persistence.md#t1137003) |
| `T1137.004` | Outlook Home Page | Detect Persistence via Outlook Home Page Exploitation | [Persistence](persistence.md#t1137004) |
| `T1137.005` | Outlook Rules | Detect Persistence via Malicious Outlook Rules | [Persistence](persistence.md#t1137005) |
| `T1137.006` | Add-ins | Detect Persistence via Malicious Office Add-ins | [Persistence](persistence.md#t1137006) |
| `T1140` | Deobfuscate/Decode Files or Information | Detect Adversary Deobfuscation or Decoding of Files and Payloads | [Defense Evasion](defense-evasion.md#t1140) |
| `T1176` | Software Extensions | Detection of Malicious or Unauthorized Software Extensions | [Persistence](persistence.md#t1176) |
| `T1176.001` | Browser Extensions | Detecting Malicious Browser Extensions Across Platforms | [Persistence](persistence.md#t1176001) |
| `T1176.002` | IDE Extensions | Detect malicious IDE extension install/usage and IDE tunneling | [Persistence](persistence.md#t1176002) |
| `T1185` | Browser Session Hijacking | Detect browser session hijacking via privilege, handle access, and remote thread into browsers | [Collection](collection.md#t1185) |
| `T1187` | Forced Authentication | Detect Forced SMB/WebDAV Authentication via lure files and outbound NTLM | [Credential Access](credential-access.md#t1187) |
| `T1189` | Drive-by Compromise | Drive-by Compromise — Behavior-based, Multi-platform Detection Strategy (T1189) | [Initial Access](initial-access.md#t1189) |
| `T1190` | Exploit Public-Facing Application | Exploit Public-Facing Application – multi-signal correlation (request → error → post-exploit process/egress) | [Initial Access](initial-access.md#t1190) |
| `T1195` | Supply Chain Compromise | Behavioral detection for Supply Chain Compromise (package/update tamper → install → first-run) | [Initial Access](initial-access.md#t1195) |
| `T1195.001` | Compromise Software Dependencies and Development Tools | Supply-chain tamper in dependencies/dev-tools (manager→write/install→first-run→egress) | [Initial Access](initial-access.md#t1195001) |
| `T1195.002` | Compromise Software Supply Chain | Compromised software/update chain (installer/write → first-run/child → egress/signature anomaly) | [Initial Access](initial-access.md#t1195002) |
| `T1195.003` | Compromise Hardware Supply Chain | Hardware Supply Chain Compromise Detection via Host Status & Boot Integrity Checks | [Initial Access](initial-access.md#t1195003) |
| `T1197` | BITS Jobs | Detect abuse of Windows BITS Jobs for download, execution and persistence | [Defense Evasion](defense-evasion.md#t1197) |
| `T1199` | Trusted Relationship | Detect abuse of Trusted Relationships (third-party and delegated admin access) | [Initial Access](initial-access.md#t1199) |
| `T1200` | Hardware Additions | Detect unauthorized or suspicious Hardware Additions (USB/Thunderbolt/Network) | [Initial Access](initial-access.md#t1200) |
| `T1201` | Password Policy Discovery | Password Policy Discovery – cross-platform behavior-chain analytics | [Discovery](discovery.md#t1201) |
| `T1202` | Indirect Command Execution | Indirect Command Execution – Windows utility abuse behavior chain | [Defense Evasion](defense-evasion.md#t1202) |
| `T1203` | Exploitation for Client Execution | Exploitation for Client Execution – cross-platform behavior chain (browser/Office/3rd-party apps) | [Execution](execution.md#t1203) |
| `T1204` | User Execution | User Execution – multi-surface behavior chain (documents/links → helper/unpacker → LOLBIN/child → egress) | [Execution](execution.md#t1204) |
| `T1204.001` | Malicious Link | User Execution – Malicious Link (click → suspicious egress → download/write → follow-on activity) | [Execution](execution.md#t1204001) |
| `T1204.002` | Malicious File | User Execution – Malicious File via download/open → spawn chain (T1204.002) | [Execution](execution.md#t1204002) |
| `T1204.003` | Malicious Image | User Execution – Malicious Image (containers & IaaS) – pull/run → start → anomalous behavior (T1204.003) | [Execution](execution.md#t1204003) |
| `T1204.004` | Malicious Copy and Paste | User Execution – Malicious Copy & Paste (browser/email → shell with obfuscated one-liner) – T1204.004 | [Execution](execution.md#t1204004) |
| `T1204.005` | Malicious Library | User-Initiated Malicious Library Installation via Package Manager (T1204.005) | [Execution](execution.md#t1204005) |
| `T1205` | Traffic Signaling | Traffic Signaling (Port-knock / magic-packet → firewall or service activation) – T1205 | [Defense Evasion](defense-evasion.md#t1205) |
| `T1205.001` | Port Knocking | Port-knock → rule/daemon change → first successful connect (T1205.001) | [Defense Evasion](defense-evasion.md#t1205001) |
| `T1205.002` | Socket Filters | Socket-filter trigger → on-host raw-socket activity → reverse connection (T1205.002) | [Defense Evasion](defense-evasion.md#t1205002) |
| `T1207` | Rogue Domain Controller | Detection Strategy for Rogue Domain Controller (DCShadow) Registration and Replication Abuse | [Defense Evasion](defense-evasion.md#t1207) |
| `T1210` | Exploitation of Remote Services | Exploitation of Remote Services – multi-platform lateral movement detection | [Lateral Movement](lateral-movement.md#t1210) |
| `T1211` | Exploitation for Defense Evasion | Detection Strategy for Exploitation for Defense Evasion | [Defense Evasion](defense-evasion.md#t1211) |
| `T1212` | Exploitation for Credential Access | Detection Strategy for Exploitation for Credential Access | [Credential Access](credential-access.md#t1212) |
| `T1213` | Data from Information Repositories | Abuse of Information Repositories for Data Collection | [Collection](collection.md#t1213) |
| `T1213.001` | Confluence | Programmatic and Excessive Access to Confluence Documentation | [Collection](collection.md#t1213001) |
| `T1213.002` | Sharepoint | Detecting Abnormal SharePoint Data Mining by Privileged or Rare Users | [Collection](collection.md#t1213002) |
| `T1213.003` | Code Repositories | Detecting Bulk or Anomalous Access to Private Code Repositories via SaaS Platforms | [Collection](collection.md#t1213003) |
| `T1213.004` | Customer Relationship Management Software | Detecting Suspicious Access to CRM Data in SaaS Environments | [Collection](collection.md#t1213004) |
| `T1213.005` | Messaging Applications | Detecting Unauthorized Collection from Messaging Applications in SaaS and Office Environments | [Collection](collection.md#t1213005) |
| `T1213.006` | Databases | Suspicious Database Access and Dump Activity Across Environments (T1213.006) | [Collection](collection.md#t1213006) |
| `T1216` | System Script Proxy Execution | Detection of Script-Based Proxy Execution via Signed Microsoft Utilities | [Defense Evasion](defense-evasion.md#t1216) |
| `T1216.001` | PubPrn | Detecting Remote Script Proxy Execution via PubPrn.vbs | [Defense Evasion](defense-evasion.md#t1216001) |
| `T1216.002` | SyncAppvPublishingServer | Detecting PowerShell Execution via SyncAppvPublishingServer.vbs Proxy Abuse | [Defense Evasion](defense-evasion.md#t1216002) |
| `T1217` | Browser Information Discovery | Detection of Local Browser Artifact Access for Reconnaissance | [Discovery](discovery.md#t1217) |
| `T1218` | System Binary Proxy Execution | Detection of Proxy Execution via Trusted Signed Binaries Across Platforms | [Defense Evasion](defense-evasion.md#t1218) |
| `T1218.001` | Compiled HTML File | Detection of Suspicious Compiled HTML File Execution via hh.exe | [Defense Evasion](defense-evasion.md#t1218001) |
| `T1218.002` | Control Panel | Detection of Malicious Control Panel Item Execution via control.exe or Rundll32 | [Defense Evasion](defense-evasion.md#t1218002) |
| `T1218.003` | CMSTP | Detection of Malicious Profile Installation via CMSTP.exe | [Defense Evasion](defense-evasion.md#t1218003) |
| `T1218.004` | InstallUtil | Detection of Malicious Code Execution via InstallUtil.exe | [Defense Evasion](defense-evasion.md#t1218004) |
| `T1218.005` | Mshta | Detecting Mshta-based Proxy Execution via Suspicious HTA or Script Invocation | [Defense Evasion](defense-evasion.md#t1218005) |
| `T1218.007` | Msiexec | Detection of Msiexec Abuse for Local, Network, and DLL Execution | [Defense Evasion](defense-evasion.md#t1218007) |
| `T1218.008` | Odbcconf | Detecting Odbcconf Proxy Execution of Malicious DLLs | [Defense Evasion](defense-evasion.md#t1218008) |
| `T1218.009` | Regsvcs/Regasm | Detecting .NET COM Registration Abuse via Regsvcs/Regasm | [Defense Evasion](defense-evasion.md#t1218009) |
| `T1218.010` | Regsvr32 | Detection Strategy for System Binary Proxy Execution: Regsvr32 | [Defense Evasion](defense-evasion.md#t1218010) |
| `T1218.011` | Rundll32 | Detection Strategy for T1218.011 Rundll32 Abuse | [Defense Evasion](defense-evasion.md#t1218011) |
| `T1218.012` | Verclsid | Detection Strategy for T1218.012 Verclsid Abuse | [Defense Evasion](defense-evasion.md#t1218012) |
| `T1218.013` | Mavinject | Detecting Code Injection via mavinject.exe (App-V Injector) | [Defense Evasion](defense-evasion.md#t1218013) |
| `T1218.014` | MMC | Detecting MMC (.msc) Proxy Execution and Malicious COM Activation | [Defense Evasion](defense-evasion.md#t1218014) |
| `T1218.015` | Electron Applications | Detecting Electron Application Abuse for Proxy Execution | [Defense Evasion](defense-evasion.md#t1218015) |
| `T1219` | Remote Access Tools | Behavior-Chain Detection for Remote Access Tools (Tool-Agnostic) | [Command and Control](command-and-control.md#t1219) |
| `T1219.001` | IDE Tunneling | IDE Tunneling Detection via Process, File, and Network Behaviors | [Command and Control](command-and-control.md#t1219001) |
| `T1219.002` | Remote Desktop Software | Remote Desktop Software Execution and Beaconing Detection | [Command and Control](command-and-control.md#t1219002) |
| `T1219.003` | Remote Access Hardware | Detect Remote Access via USB Hardware (TinyPilot, PiKVM) | [Command and Control](command-and-control.md#t1219003) |
| `T1220` | XSL Script Processing | Detect XSL Script Abuse via msxsl and wmic | [Defense Evasion](defense-evasion.md#t1220) |
| `T1221` | Template Injection | Template Injection Detection - Windows | [Defense Evasion](defense-evasion.md#t1221) |
| `T1222` | File and Directory Permissions Modification | Multi-Platform File and Directory Permissions Modification Detection Strategy | [Defense Evasion](defense-evasion.md#t1222) |
| `T1222.001` | Windows File and Directory Permissions Modification | Windows DACL Manipulation Behavioral Chain Detection Strategy | [Defense Evasion](defense-evasion.md#t1222001) |
| `T1222.002` | Linux and Mac File and Directory Permissions Modification | Unix-like File Permission Manipulation Behavioral Chain Detection Strategy | [Defense Evasion](defense-evasion.md#t1222002) |
| `T1480` | Execution Guardrails | Multi-Platform Execution Guardrails Environmental Validation Detection Strategy | [Defense Evasion](defense-evasion.md#t1480) |
| `T1480.001` | Environmental Keying | Environmental Keying Discovery-to-Decryption Behavioral Chain Detection Strategy | [Defense Evasion](defense-evasion.md#t1480001) |
| `T1480.002` | Mutual Exclusion | Detection of Mutex-Based Execution Guardrails Across Platforms | [Defense Evasion](defense-evasion.md#t1480002) |
| `T1482` | Domain Trust Discovery | Detection of Domain Trust Discovery via API, Script, and CLI Enumeration | [Discovery](discovery.md#t1482) |
| `T1484` | Domain or Tenant Policy Modification | Detection of Domain or Tenant Policy Modifications via AD and Identity Provider | [Defense Evasion](defense-evasion.md#t1484) |
| `T1484.001` | Group Policy Modification | Detection of Group Policy Modifications via AD Object Changes and File Activity | [Defense Evasion](defense-evasion.md#t1484001) |
| `T1484.002` | Trust Modification | Detection of Trust Relationship Modifications in Domain or Tenant Policies | [Defense Evasion](defense-evasion.md#t1484002) |
| `T1485` | Data Destruction | Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns | [Impact](impact.md#t1485) |
| `T1485.001` | Lifecycle-Triggered Deletion | Detection of Lifecycle Policy Modifications for Triggered Deletion in IaaS Cloud Storage | [Impact](impact.md#t1485001) |
| `T1486` | Data Encrypted for Impact | Detection of Multi-Platform File Encryption for Impact | [Impact](impact.md#t1486) |
| `T1489` | Service Stop | Behavioral Detection for Service Stop across Platforms | [Impact](impact.md#t1489) |
| `T1490` | Inhibit System Recovery | Behavioral Detection for T1490 - Inhibit System Recovery | [Impact](impact.md#t1490) |
| `T1491` | Defacement | Defacement via File and Web Content Modification Across Platforms | [Impact](impact.md#t1491) |
| `T1491.001` | Internal Defacement | Internal Website and System Content Defacement via UI or Messaging Modifications | [Impact](impact.md#t1491001) |
| `T1491.002` | External Defacement | Behavioral Detection of External Website Defacement across Platforms | [Impact](impact.md#t1491002) |
| `T1495` | Firmware Corruption | Firmware Modification via Flash Tool or Corrupted Firmware Upload | [Impact](impact.md#t1495) |
| `T1496` | Resource Hijacking | Resource Hijacking Detection Strategy | [Impact](impact.md#t1496) |
| `T1496.001` | Compute Hijacking | Multi-Platform Behavioral Detection for Compute Hijacking | [Impact](impact.md#t1496001) |
| `T1496.002` | Bandwidth Hijacking | Detect Excessive or Unauthorized Bandwidth Usage for Botnet, Proxyjacking, or Scanning Purposes | [Impact](impact.md#t1496002) |
| `T1496.003` | SMS Pumping | Detection Strategy for Resource Hijacking: SMS Pumping via SaaS Application Logs | [Impact](impact.md#t1496003) |
| `T1496.004` | Cloud Service Hijacking | Detection Strategy for Cloud Service Hijacking via SaaS Abuse | [Impact](impact.md#t1496004) |
| `T1497` | Virtualization/Sandbox Evasion | Detection Strategy for T1497 Virtualization/Sandbox Evasion | [Defense Evasion](defense-evasion.md#t1497) |
| `T1497.001` | System Checks | Virtualization/Sandbox Evasion via System Checks across Windows, Linux, macOS | [Defense Evasion](defense-evasion.md#t1497001) |
| `T1497.002` | User Activity Based Checks | Detect User Activity Based Sandbox Evasion via Input & Artifact Probing | [Defense Evasion](defense-evasion.md#t1497002) |
| `T1497.003` | Time Based Checks | Detect Time-Based Evasion via Sleep, Timer Loops, and Delayed Execution | [Defense Evasion](defense-evasion.md#t1497003) |
| `T1498` | Network Denial of Service | Behavioral Detection of T1498 – Network Denial of Service Across Platforms | [Impact](impact.md#t1498) |
| `T1498.001` | Direct Network Flood | Direct Network Flood Detection across IaaS, Linux, Windows, and macOS | [Impact](impact.md#t1498001) |
| `T1498.002` | Reflection Amplification | Detection Strategy for Reflection Amplification DoS (T1498.002) | [Impact](impact.md#t1498002) |
| `T1499` | Endpoint Denial of Service | Endpoint Resource Saturation and Crash Pattern Detection Across Platforms | [Impact](impact.md#t1499) |
| `T1499.001` | OS Exhaustion Flood | Endpoint DoS via OS Exhaustion Flood Detection Strategy | [Impact](impact.md#t1499001) |
| `T1499.002` | Service Exhaustion Flood | Detection Strategy for Endpoint DoS via Service Exhaustion Flood | [Impact](impact.md#t1499002) |
| `T1499.003` | Application Exhaustion Flood | Application Exhaustion Flood Detection Across Platforms | [Impact](impact.md#t1499003) |
| `T1499.004` | Application or System Exploitation | Detection Strategy for Endpoint DoS via Application or System Exploitation | [Impact](impact.md#t1499004) |
| `T1505` | Server Software Component | Detection Strategy for T1505 - Server Software Component | [Persistence](persistence.md#t1505) |
| `T1505.001` | SQL Stored Procedures | Detection Strategy for SQL Stored Procedures Abuse via T1505.001 | [Persistence](persistence.md#t1505001) |
| `T1505.002` | Transport Agent | Detection Strategy for T1505.002 - Transport Agent Abuse (Windows/Linux) | [Persistence](persistence.md#t1505002) |
| `T1505.003` | Web Shell | Web Shell Detection via Server Behavior and File Execution Chains | [Persistence](persistence.md#t1505003) |
| `T1505.004` | IIS Components | Detection Strategy for T1505.004 - Malicious IIS Components | [Persistence](persistence.md#t1505004) |
| `T1505.005` | Terminal Services DLL | Detection Strategy for T1505.005 – Terminal Services DLL Modification (Windows) | [Persistence](persistence.md#t1505005) |
| `T1505.006` | vSphere Installation Bundles | Detect Abuse of vSphere Installation Bundles (VIBs) for Persistent Access | [Persistence](persistence.md#t1505006) |
| `T1518` | Software Discovery | Multi-Platform Software Discovery Behavior Chain | [Discovery](discovery.md#t1518) |
| `T1518.001` | Security Software Discovery | Security Software Discovery Across Platforms | [Discovery](discovery.md#t1518001) |
| `T1518.002` | Backup Software Discovery | Backup Software Discovery via CLI, Registry, and Process Inspection (T1518.002) | [Discovery](discovery.md#t1518002) |
| `T1525` | Implant Internal Image | Detection Strategy for T1525 – Implant Internal Image | [Persistence](persistence.md#t1525) |
| `T1526` | Cloud Service Discovery | Detection Strategy for Cloud Service Discovery | [Discovery](discovery.md#t1526) |
| `T1528` | Steal Application Access Token | Detection Strategy for T1528 - Steal Application Access Token | [Credential Access](credential-access.md#t1528) |
| `T1529` | System Shutdown/Reboot | Multi-Platform Shutdown or Reboot Detection via Execution and Host Status Events | [Impact](impact.md#t1529) |
| `T1530` | Data from Cloud Storage | Multi-Platform Cloud Storage Exfiltration Behavior Chain | [Collection](collection.md#t1530) |
| `T1531` | Account Access Removal | Account Access Removal via Multi-Platform Audit Correlation | [Impact](impact.md#t1531) |
| `T1534` | Internal Spearphishing | Internal Spearphishing via Trusted Accounts | [Lateral Movement](lateral-movement.md#t1534) |
| `T1535` | Unused/Unsupported Cloud Regions | Detection of Adversary Use of Unused or Unsupported Cloud Regions (IaaS) | [Defense Evasion](defense-evasion.md#t1535) |
| `T1537` | Transfer Data to Cloud Account | Cross-Platform Detection of Data Transfer to Cloud Account | [Exfiltration](exfiltration.md#t1537) |
| `T1538` | Cloud Service Dashboard | Detection of Cloud Service Dashboard Usage via GUI-Based Cloud Access | [Discovery](discovery.md#t1538) |
| `T1539` | Steal Web Session Cookie | Detection of Web Session Cookie Theft via File, Memory, and Network Artifacts | [Credential Access](credential-access.md#t1539) |
| `T1542` | Pre-OS Boot | Detection Strategy for T1542 Pre-OS Boot | [Defense Evasion](defense-evasion.md#t1542) |
| `T1542.001` | System Firmware | Detection Strategy for T1542.001 Pre-OS Boot: System Firmware | [Persistence](persistence.md#t1542001) |
| `T1542.002` | Component Firmware | Detection Strategy for T1542.002 Pre-OS Boot: Component Firmware | [Persistence](persistence.md#t1542002) |
| `T1542.003` | Bootkit | Detection Strategy for File Creation or Modification of Boot Files | [Persistence](persistence.md#t1542003) |
| `T1542.004` | ROMMONkit | Detection Strategy for T1542.004 Pre-OS Boot: ROMMONkit | [Defense Evasion](defense-evasion.md#t1542004) |
| `T1542.005` | TFTP Boot | Detection Strategy for T1542.005 Pre-OS Boot: TFTP Boot | [Defense Evasion](defense-evasion.md#t1542005) |
| `T1543` | Create or Modify System Process | Detection of System Process Creation or Modification Across Platforms | [Persistence](persistence.md#t1543) |
| `T1543.001` | Launch Agent | Detection of Launch Agent Creation or Modification on macOS | [Persistence](persistence.md#t1543001) |
| `T1543.002` | Systemd Service | Detection of Systemd Service Creation or Modification on Linux | [Persistence](persistence.md#t1543002) |
| `T1543.003` | Windows Service | Detection of Windows Service Creation or Modification | [Persistence](persistence.md#t1543003) |
| `T1543.004` | Launch Daemon | Detection Strategy for Launch Daemon Creation or Modification (macOS) | [Persistence](persistence.md#t1543004) |
| `T1543.005` | Container Service | Detect persistent or elevated container services via container runtime or cluster manipulation | [Persistence](persistence.md#t1543005) |
| `T1546` | Event Triggered Execution | Behavioral Detection of Event Triggered Execution Across Platforms | [Privilege Escalation](privilege-escalation.md#t1546) |
| `T1546.001` | Change Default File Association | Detect Default File Association Hijack via Registry & Execution Correlation on Windows | [Privilege Escalation](privilege-escalation.md#t1546001) |
| `T1546.002` | Screensaver | Detect Screensaver-Based Persistence via Registry and Execution Chains | [Privilege Escalation](privilege-escalation.md#t1546002) |
| `T1546.003` | Windows Management Instrumentation Event Subscription | Detect WMI Event Subscription for Persistence via WmiPrvSE Process and MOF Compilation | [Privilege Escalation](privilege-escalation.md#t1546003) |
| `T1546.004` | Unix Shell Configuration Modification | Detect Shell Configuration Modification for Persistence via Event-Triggered Execution | [Privilege Escalation](privilege-escalation.md#t1546004) |
| `T1546.005` | Trap | Detection Strategy for Event Triggered Execution via Trap (T1546.005) | [Privilege Escalation](privilege-escalation.md#t1546005) |
| `T1546.006` | LC_LOAD_DYLIB Addition | Detection Strategy for LC_LOAD_DYLIB Modification in Mach-O Binaries on macOS | [Privilege Escalation](privilege-escalation.md#t1546006) |
| `T1546.007` | Netsh Helper DLL | Detection Strategy for Netsh Helper DLL Persistence via Registry and Child Process Monitoring (Windows) | [Privilege Escalation](privilege-escalation.md#t1546007) |
| `T1546.008` | Accessibility Features | Detection Strategy for Accessibility Feature Hijacking via Binary Replacement or Registry Modification | [Privilege Escalation](privilege-escalation.md#t1546008) |
| `T1546.009` | AppCert DLLs | Detection Strategy for AppCert DLLs Persistence via Registry Injection | [Privilege Escalation](privilege-escalation.md#t1546009) |
| `T1546.010` | AppInit DLLs | Detection Strategy for Event Triggered Execution: AppInit DLLs (Windows) | [Privilege Escalation](privilege-escalation.md#t1546010) |
| `T1546.011` | Application Shimming | Detection Strategy for Application Shimming via sdbinst.exe and Registry Artifacts (Windows) | [Privilege Escalation](privilege-escalation.md#t1546011) |
| `T1546.012` | Image File Execution Options Injection | Detection Strategy for IFEO Injection on Windows | [Privilege Escalation](privilege-escalation.md#t1546012) |
| `T1546.013` | PowerShell Profile | Detection Strategy for PowerShell Profile Persistence via profile.ps1 Modification | [Privilege Escalation](privilege-escalation.md#t1546013) |
| `T1546.014` | Emond | Detection Strategy for Event Triggered Execution via emond on macOS | [Privilege Escalation](privilege-escalation.md#t1546014) |
| `T1546.015` | Component Object Model Hijacking | Windows COM Hijacking Detection via Registry and DLL Load Correlation | [Privilege Escalation](privilege-escalation.md#t1546015) |
| `T1546.016` | Installer Packages | Detection Strategy for T1546.016 - Event Triggered Execution via Installer Packages | [Privilege Escalation](privilege-escalation.md#t1546016) |
| `T1546.017` | Udev Rules | Detection Strategy for T1546.017 - Udev Rules (Linux) | [Persistence](persistence.md#t1546017) |
| `T1546.018` | Python Startup Hooks | Linux Python Startup Hook Persistence via .pth and Customize Files (T1546.018) | [Persistence](persistence.md#t1546018) |
| `T1547` | Boot or Logon Autostart Execution | Boot or Logon Autostart Execution Detection Strategy | [Persistence](persistence.md#t1547) |
| `T1547.001` | Registry Run Keys / Startup Folder | Detect Registry and Startup Folder Persistence (Windows) | [Persistence](persistence.md#t1547001) |
| `T1547.002` | Authentication Package | Detect LSA Authentication Package Persistence via Registry and LSASS DLL Load | [Persistence](persistence.md#t1547002) |
| `T1547.003` | Time Providers | Detect Abuse of Windows Time Providers for Persistence | [Persistence](persistence.md#t1547003) |
| `T1547.004` | Winlogon Helper DLL | Detect Winlogon Helper DLL Abuse via Registry and Process Artifacts on Windows | [Persistence](persistence.md#t1547004) |
| `T1547.005` | Security Support Provider | Registry and LSASS Monitoring for Security Support Provider Abuse | [Persistence](persistence.md#t1547005) |
| `T1547.006` | Kernel Modules and Extensions | Detection Strategy for Kernel Modules and Extensions Autostart Execution | [Persistence](persistence.md#t1547006) |
| `T1547.007` | Re-opened Applications | Detect persistence via reopened application plist modification (macOS) | [Persistence](persistence.md#t1547007) |
| `T1547.008` | LSASS Driver | Detect unauthorized LSASS driver persistence via LSA plugin abuse (Windows) | [Persistence](persistence.md#t1547008) |
| `T1547.009` | Shortcut Modification | Detection Strategy for T1547.009 – Shortcut Modification (Windows) | [Persistence](persistence.md#t1547009) |
| `T1547.010` | Port Monitors | Detection Strategy for T1547.010 – Port Monitor DLL Persistence via spoolsv.exe (Windows) | [Persistence](persistence.md#t1547010) |
| `T1547.012` | Print Processors | Windows Detection Strategy for T1547.012 - Print Processor DLL Persistence | [Persistence](persistence.md#t1547012) |
| `T1547.013` | XDG Autostart Entries | Linux Detection Strategy for T1547.013 - XDG Autostart Entries | [Persistence](persistence.md#t1547013) |
| `T1547.014` | Active Setup | Detect Active Setup Persistence via StubPath Execution | [Persistence](persistence.md#t1547014) |
| `T1547.015` | Login Items | Detection Strategy for T1547.015 – Login Items on macOS | [Persistence](persistence.md#t1547015) |
| `T1548` | Abuse Elevation Control Mechanism | Detection Strategy for Abuse Elevation Control Mechanism (T1548) | [Privilege Escalation](privilege-escalation.md#t1548) |
| `T1548.001` | Setuid and Setgid | Setuid/Setgid Privilege Abuse Detection (Linux/macOS) | [Privilege Escalation](privilege-escalation.md#t1548001) |
| `T1548.002` | Bypass User Account Control | Detection Strategy for T1548.002 – Bypass User Account Control (UAC) | [Privilege Escalation](privilege-escalation.md#t1548002) |
| `T1548.003` | Sudo and Sudo Caching | Behavioral Detection Strategy for Abuse of Sudo and Sudo Caching | [Privilege Escalation](privilege-escalation.md#t1548003) |
| `T1548.004` | Elevated Execution with Prompt | macOS AuthorizationExecuteWithPrivileges Elevation Prompt Detection | [Privilege Escalation](privilege-escalation.md#t1548004) |
| `T1548.005` | Temporary Elevated Cloud Access | Detection Strategy for Temporary Elevated Cloud Access Abuse (T1548.005) | [Privilege Escalation](privilege-escalation.md#t1548005) |
| `T1548.006` | TCC Manipulation | TCC Database Manipulation via Launchctl and Unprotected SIP | [Defense Evasion](defense-evasion.md#t1548006) |
| `T1550` | Use Alternate Authentication Material | Behavioral Detection Strategy for Use Alternate Authentication Material (T1550) | [Defense Evasion](defense-evasion.md#t1550) |
| `T1550.001` | Application Access Token | Behavioral Detection Strategy for Use Alternate Authentication Material: Application Access Token (T1550.001) | [Defense Evasion](defense-evasion.md#t1550001) |
| `T1550.002` | Pass the Hash | Detection Strategy for T1550.002 - Pass the Hash (Windows) | [Defense Evasion](defense-evasion.md#t1550002) |
| `T1550.003` | Pass the Ticket | Detection Strategy for T1550.003 - Pass the Ticket (Windows) | [Defense Evasion](defense-evasion.md#t1550003) |
| `T1550.004` | Web Session Cookie | Detect Use of Stolen Web Session Cookies Across Platforms | [Defense Evasion](defense-evasion.md#t1550004) |
| `T1552` | Unsecured Credentials | Detect Access or Search for Unsecured Credentials Across Platforms | [Credential Access](credential-access.md#t1552) |
| `T1552.001` | Credentials In Files | Detect Access to Unsecured Credential Files Across Platforms | [Credential Access](credential-access.md#t1552001) |
| `T1552.002` | Credentials in Registry | Detect Credential Discovery via Windows Registry Enumeration | [Credential Access](credential-access.md#t1552002) |
| `T1552.003` | Shell History | Detect Access and Parsing of .bash_history Files for Credential Harvesting | [Credential Access](credential-access.md#t1552003) |
| `T1552.004` | Private Keys | Detect Suspicious Access to Private Key Files and Export Attempts Across Platforms | [Credential Access](credential-access.md#t1552004) |
| `T1552.005` | Cloud Instance Metadata API | Detect Access to Cloud Instance Metadata API (IaaS) | [Credential Access](credential-access.md#t1552005) |
| `T1552.006` | Group Policy Preferences | Detect Access and Decryption of Group Policy Preference (GPP) Credentials in SYSVOL | [Credential Access](credential-access.md#t1552006) |
| `T1552.007` | Container API | Detect Abuse of Container APIs for Credential Access | [Credential Access](credential-access.md#t1552007) |
| `T1552.008` | Chat Messages | Detect Unsecured Credentials Shared in Chat Messages | [Credential Access](credential-access.md#t1552008) |
| `T1553` | Subvert Trust Controls | Detect Subversion of Trust Controls via Certificate, Registry, and Attribute Manipulation | [Defense Evasion](defense-evasion.md#t1553) |
| `T1553.001` | Gatekeeper Bypass | Detect Gatekeeper Bypass via Quarantine Flag and Trust Control Manipulation | [Defense Evasion](defense-evasion.md#t1553001) |
| `T1553.002` | Code Signing | Detect Suspicious or Malicious Code Signing Abuse | [Defense Evasion](defense-evasion.md#t1553002) |
| `T1553.003` | SIP and Trust Provider Hijacking | Detection Strategy for Subvert Trust Controls using SIP and Trust Provider Hijacking. | [Defense Evasion](defense-evasion.md#t1553003) |
| `T1553.004` | Install Root Certificate | Detection Strategy for Subvert Trust Controls via Install Root Certificate. | [Defense Evasion](defense-evasion.md#t1553004) |
| `T1553.005` | Mark-of-the-Web Bypass | Detect Mark-of-the-Web (MOTW) Bypass via Container and Disk Image Files | [Defense Evasion](defense-evasion.md#t1553005) |
| `T1553.006` | Code Signing Policy Modification | Detect Code Signing Policy Modification (Windows & macOS) | [Defense Evasion](defense-evasion.md#t1553006) |
| `T1554` | Compromise Host Software Binary | Detect Compromise of Host Software Binaries | [Persistence](persistence.md#t1554) |
| `T1555` | Credentials from Password Stores | Detect Credentials Access from Password Stores | [Credential Access](credential-access.md#t1555) |
| `T1555.001` | Keychain | Detect Access to macOS Keychain for Credential Theft | [Credential Access](credential-access.md#t1555001) |
| `T1555.002` | Securityd Memory | Detect Suspicious Access to securityd Memory for Credential Extraction | [Credential Access](credential-access.md#t1555002) |
| `T1555.003` | Credentials from Web Browsers | Detect Suspicious Access to Browser Credential Stores | [Credential Access](credential-access.md#t1555003) |
| `T1555.004` | Windows Credential Manager | Detect Suspicious Access to Windows Credential Manager | [Credential Access](credential-access.md#t1555004) |
| `T1555.005` | Password Managers | Detect Unauthorized Access to Password Managers | [Credential Access](credential-access.md#t1555005) |
| `T1555.006` | Cloud Secrets Management Stores | Detect Unauthorized Access to Cloud Secrets Management Stores | [Credential Access](credential-access.md#t1555006) |
| `T1556` | Modify Authentication Process | Detect Modification of Authentication Processes Across Platforms | [Credential Access](credential-access.md#t1556) |
| `T1556.001` | Domain Controller Authentication | Detect Domain Controller Authentication Process Modification (Skeleton Key) | [Credential Access](credential-access.md#t1556001) |
| `T1556.002` | Password Filter DLL | Detect Malicious Password Filter DLL Registration | [Credential Access](credential-access.md#t1556002) |
| `T1556.003` | Pluggable Authentication Modules | Detect Malicious Modification of Pluggable Authentication Modules (PAM) | [Credential Access](credential-access.md#t1556003) |
| `T1556.004` | Network Device Authentication | Detect Modification of Network Device Authentication via Patched System Images | [Credential Access](credential-access.md#t1556004) |
| `T1556.005` | Reversible Encryption | Detect Modification of Authentication Process via Reversible Encryption | [Credential Access](credential-access.md#t1556005) |
| `T1556.006` | Multi-Factor Authentication | Detect MFA Modification or Disabling Across Platforms | [Credential Access](credential-access.md#t1556006) |
| `T1556.007` | Hybrid Identity | Detect Hybrid Identity Authentication Process Modification | [Credential Access](credential-access.md#t1556007) |
| `T1556.008` | Network Provider DLL | Detect Network Provider DLL Registration and Credential Capture | [Credential Access](credential-access.md#t1556008) |
| `T1556.009` | Conditional Access Policies | Detect Conditional Access Policy Modification in Identity and Cloud Platforms | [Credential Access](credential-access.md#t1556009) |
| `T1557` | Adversary-in-the-Middle | Detect Adversary-in-the-Middle via Network and Configuration Anomalies | [Credential Access](credential-access.md#t1557) |
| `T1557.001` | LLMNR/NBT-NS Poisoning and SMB Relay | Detect LLMNR/NBT-NS Poisoning and SMB Relay on Windows | [Credential Access](credential-access.md#t1557001) |
| `T1557.002` | ARP Cache Poisoning | Detect ARP Cache Poisoning Across Linux, Windows, and macOS | [Credential Access](credential-access.md#t1557002) |
| `T1557.003` | DHCP Spoofing | Detect DHCP Spoofing Across Linux, Windows, and macOS | [Credential Access](credential-access.md#t1557003) |
| `T1557.004` | Evil Twin | Detect Evil Twin Wi-Fi Access Points on Network Devices | [Credential Access](credential-access.md#t1557004) |
| `T1558` | Steal or Forge Kerberos Tickets | Detect Kerberos Ticket Theft or Forgery (T1558) | [Credential Access](credential-access.md#t1558) |
| `T1558.001` | Golden Ticket | Detect Forged Kerberos Golden Tickets (T1558.001) | [Credential Access](credential-access.md#t1558001) |
| `T1558.002` | Silver Ticket | Detect Forged Kerberos Silver Tickets (T1558.002) | [Credential Access](credential-access.md#t1558002) |
| `T1558.003` | Kerberoasting | Detect Kerberoasting Attempts (T1558.003) | [Credential Access](credential-access.md#t1558003) |
| `T1558.004` | AS-REP Roasting | Detect AS-REP Roasting Attempts (T1558.004) | [Credential Access](credential-access.md#t1558004) |
| `T1558.005` | Ccache Files | Detect Kerberos Ccache File Theft or Abuse (T1558.005) | [Credential Access](credential-access.md#t1558005) |
| `T1559` | Inter-Process Communication | Detect Abuse of Inter-Process Communication (T1559) | [Execution](execution.md#t1559) |
| `T1559.001` | Component Object Model | Detect Abuse of Component Object Model (T1559.001) | [Execution](execution.md#t1559001) |
| `T1559.002` | Dynamic Data Exchange | Detect Abuse of Dynamic Data Exchange (T1559.002) | [Execution](execution.md#t1559002) |
| `T1559.003` | XPC Services | Detect Abuse of XPC Services (T1559.003) | [Execution](execution.md#t1559003) |
| `T1560` | Archive Collected Data | Detect Archiving and Encryption of Collected Data (T1560) | [Collection](collection.md#t1560) |
| `T1560.001` | Archive via Utility | Detect Archiving via Utility (T1560.001) | [Collection](collection.md#t1560001) |
| `T1560.002` | Archive via Library | Detect Archiving via Library (T1560.002) | [Collection](collection.md#t1560002) |
| `T1560.003` | Archive via Custom Method | Detect Archiving via Custom Method (T1560.003) | [Collection](collection.md#t1560003) |
| `T1561` | Disk Wipe | Detection Strategy for Disk Wipe via Direct Disk Access and Destructive Commands | [Impact](impact.md#t1561) |
| `T1561.001` | Disk Content Wipe | Detection Strategy for Disk Content Wipe via Direct Access and Overwrite | [Impact](impact.md#t1561001) |
| `T1561.002` | Disk Structure Wipe | Detection Strategy for Disk Structure Wipe via Boot/Partition Overwrite | [Impact](impact.md#t1561002) |
| `T1562` | Impair Defenses | Detection Strategy for Impair Defenses Across Platforms | [Defense Evasion](defense-evasion.md#t1562) |
| `T1562.001` | Disable or Modify Tools | Detection of Impair Defenses through Disabled or Modified Tools across OS Platforms. | [Defense Evasion](defense-evasion.md#t1562001) |
| `T1562.002` | Disable Windows Event Logging | Detect disabled Windows event logging | [Defense Evasion](defense-evasion.md#t1562002) |
| `T1562.003` | Impair Command History Logging | Detection Strategy for Impair Defenses via Impair Command History Logging across OS platforms. | [Defense Evasion](defense-evasion.md#t1562003) |
| `T1562.004` | Disable or Modify System Firewall | Detection of Disabled or Modified System Firewalls across OS Platforms. | [Defense Evasion](defense-evasion.md#t1562004) |
| `T1562.006` | Indicator Blocking | Detection Strategy for Impair Defenses Indicator Blocking | [Defense Evasion](defense-evasion.md#t1562006) |
| `T1562.007` | Disable or Modify Cloud Firewall | Detection Strategy for Disable or Modify Cloud Firewall | [Defense Evasion](defense-evasion.md#t1562007) |
| `T1562.008` | Disable or Modify Cloud Logs | Detection Strategy for Disable or Modify Cloud Logs | [Defense Evasion](defense-evasion.md#t1562008) |
| `T1562.009` | Safe Mode Boot | Detection Strategy for Safe Mode Boot Abuse | [Defense Evasion](defense-evasion.md#t1562009) |
| `T1562.010` | Downgrade Attack | Detecting Downgrade Attacks | [Defense Evasion](defense-evasion.md#t1562010) |
| `T1562.011` | Spoof Security Alerting | Detection for Spoofing Security Alerting across OS Platforms | [Defense Evasion](defense-evasion.md#t1562011) |
| `T1562.012` | Disable or Modify Linux Audit System | Detection Strategy for Disable or Modify Linux Audit System | [Defense Evasion](defense-evasion.md#t1562012) |
| `T1562.013` | Disable or Modify Network Device Firewall | Unauthorized Network Firewall Rule Modification (T1562.013) | [Defense Evasion](defense-evasion.md#t1562013) |
| `T1563` | Remote Service Session Hijacking | Detection of Remote Service Session Hijacking | [Lateral Movement](lateral-movement.md#t1563) |
| `T1563.001` | SSH Hijacking | Detection Strategy for SSH Session Hijacking | [Lateral Movement](lateral-movement.md#t1563001) |
| `T1563.002` | RDP Hijacking | Detection fo Remote Service Session Hijacking for RDP. | [Lateral Movement](lateral-movement.md#t1563002) |
| `T1564` | Hide Artifacts | Detection Strategy for Hidden Artifacts Across Platforms | [Defense Evasion](defense-evasion.md#t1564) |
| `T1564.001` | Hidden Files and Directories | Detection Strategy for Hidden Files and Directories | [Defense Evasion](defense-evasion.md#t1564001) |
| `T1564.002` | Hidden Users | Detection Strategy for Hidden User Accounts | [Defense Evasion](defense-evasion.md#t1564002) |
| `T1564.003` | Hidden Window | Detection Strategy for Hidden Windows | [Defense Evasion](defense-evasion.md#t1564003) |
| `T1564.004` | NTFS File Attributes | Detection Strategy for NTFS File Attribute Abuse (ADS/EAs) | [Defense Evasion](defense-evasion.md#t1564004) |
| `T1564.005` | Hidden File System | Detection Strategy for Hidden File System Abuse | [Defense Evasion](defense-evasion.md#t1564005) |
| `T1564.006` | Run Virtual Instance | Detection Strategy for Hidden Virtual Instance Execution | [Defense Evasion](defense-evasion.md#t1564006) |
| `T1564.007` | VBA Stomping | Detection Strategy for VBA Stomping | [Defense Evasion](defense-evasion.md#t1564007) |
| `T1564.008` | Email Hiding Rules | Detection Strategy for Email Hiding Rules | [Defense Evasion](defense-evasion.md#t1564008) |
| `T1564.009` | Resource Forking | Detection Strategy for Resource Forking on macOS | [Defense Evasion](defense-evasion.md#t1564009) |
| `T1564.010` | Process Argument Spoofing | Detection Strategy for Process Argument Spoofing on Windows | [Defense Evasion](defense-evasion.md#t1564010) |
| `T1564.011` | Ignore Process Interrupts | Detection Strategy for Ignore Process Interrupts | [Defense Evasion](defense-evasion.md#t1564011) |
| `T1564.012` | File/Path Exclusions | Detection Strategy for File/Path Exclusions | [Defense Evasion](defense-evasion.md#t1564012) |
| `T1564.013` | Bind Mounts | Detection Strategy for Bind Mounts on Linux | [Defense Evasion](defense-evasion.md#t1564013) |
| `T1564.014` | Extended Attributes | Detection Strategy for Extended Attributes Abuse | [Defense Evasion](defense-evasion.md#t1564014) |
| `T1565` | Data Manipulation | Detection Strategy for Data Manipulation | [Impact](impact.md#t1565) |
| `T1565.001` | Stored Data Manipulation | Detection Strategy for Stored Data Manipulation across OS Platforms. | [Impact](impact.md#t1565001) |
| `T1565.002` | Transmitted Data Manipulation | Detection Strategy of Transmitted Data Manipulation | [Impact](impact.md#t1565002) |
| `T1565.003` | Runtime Data Manipulation | Detection Strategy for Runtime Data Manipulation. | [Impact](impact.md#t1565003) |
| `T1566` | Phishing | Detection Strategy for Phishing across platforms. | [Initial Access](initial-access.md#t1566) |
| `T1566.001` | Spearphishing Attachment | Detection Strategy for Spearphishing Attachment across OS Platforms | [Initial Access](initial-access.md#t1566001) |
| `T1566.002` | Spearphishing Link | Detection Strategy for Spearphishing Links | [Initial Access](initial-access.md#t1566002) |
| `T1566.003` | Spearphishing via Service | Detection Strategy for Spearphishing via a Service across OS Platforms | [Initial Access](initial-access.md#t1566003) |
| `T1566.004` | Spearphishing Voice | Detection Strategy for Spearphishing Voice across OS platforms | [Initial Access](initial-access.md#t1566004) |
| `T1567` | Exfiltration Over Web Service | Detection Strategy for Exfiltration Over Web Service | [Exfiltration](exfiltration.md#t1567) |
| `T1567.001` | Exfiltration to Code Repository | Detection Strategy for Exfiltration to Code Repository | [Exfiltration](exfiltration.md#t1567001) |
| `T1567.002` | Exfiltration to Cloud Storage | Detection Strategy for Exfiltration to Cloud Storage | [Exfiltration](exfiltration.md#t1567002) |
| `T1567.003` | Exfiltration to Text Storage Sites | Detection Strategy for Exfiltration to Text Storage Sites | [Exfiltration](exfiltration.md#t1567003) |
| `T1567.004` | Exfiltration Over Webhook | Detection Strategy for Exfiltration Over Webhook | [Exfiltration](exfiltration.md#t1567004) |
| `T1568` | Dynamic Resolution | Detection Strategy for Dynamic Resolution across OS Platforms | [Command and Control](command-and-control.md#t1568) |
| `T1568.001` | Fast Flux DNS | Detection Strategy for Dynamic Resolution using Fast Flux DNS | [Command and Control](command-and-control.md#t1568001) |
| `T1568.002` | Domain Generation Algorithms | Detection Strategy for Dynamic Resolution using Domain Generation Algorithms. | [Command and Control](command-and-control.md#t1568002) |
| `T1568.003` | DNS Calculation | Detection Strategy for Dynamic Resolution through DNS Calculation | [Command and Control](command-and-control.md#t1568003) |
| `T1569` | System Services | Detection Strategy for System Services across OS platforms. | [Execution](execution.md#t1569) |
| `T1569.001` | Launchctl | Detection Strategy for System Services: Launchctl | [Execution](execution.md#t1569001) |
| `T1569.002` | Service Execution | Detection Strategy for System Services Service Execution | [Execution](execution.md#t1569002) |
| `T1569.003` | Systemctl | Detection Strategy for System Services: Systemctl | [Execution](execution.md#t1569003) |
| `T1570` | Lateral Tool Transfer | Detection Strategy for Lateral Tool Transfer across OS platforms | [Lateral Movement](lateral-movement.md#t1570) |
| `T1571` | Non-Standard Port | Detection Strategy for Non-Standard Ports | [Command and Control](command-and-control.md#t1571) |
| `T1572` | Protocol Tunneling | Detection Strategy for Protocol Tunneling accross OS platforms. | [Command and Control](command-and-control.md#t1572) |
| `T1573` | Encrypted Channel | Detection Strategy for Encrypted Channel across OS Platforms | [Command and Control](command-and-control.md#t1573) |
| `T1573.001` | Symmetric Cryptography | Detection Strategy for Encrypted Channel via Symmetric Cryptography across OS Platforms | [Command and Control](command-and-control.md#t1573001) |
| `T1573.002` | Asymmetric Cryptography | Detection Strategy for Encrypted Channel via Asymmetric Cryptography across OS Platforms | [Command and Control](command-and-control.md#t1573002) |
| `T1574` | Hijack Execution Flow | Detection Strategy for Hijack Execution Flow across OS platforms. | [Persistence](persistence.md#t1574) |
| `T1574.001` | DLL | Detection Strategy for Hijack Execution Flow for DLLs | [Persistence](persistence.md#t1574001) |
| `T1574.004` | Dylib Hijacking | Detection Strategy for Hijack Execution Flow: Dylib Hijacking | [Persistence](persistence.md#t1574004) |
| `T1574.005` | Executable Installer File Permissions Weakness | Detection Strategy for Hijack Execution Flow using Executable Installer File Permissions Weakness | [Persistence](persistence.md#t1574005) |
| `T1574.006` | Dynamic Linker Hijacking | Detection Strategy for Hijack Execution Flow: Dynamic Linker Hijacking | [Persistence](persistence.md#t1574006) |
| `T1574.007` | Path Interception by PATH Environment Variable | Detection Strategy for Hijack Execution Flow using Path Interception by PATH Environment Variable. | [Persistence](persistence.md#t1574007) |
| `T1574.008` | Path Interception by Search Order Hijacking | Detection Strategy for Hijack Execution Flow using Path Interception by Search Order Hijacking | [Persistence](persistence.md#t1574008) |
| `T1574.009` | Path Interception by Unquoted Path | Detection Strategy for Hijack Execution Flow through Path Interception by Unquoted Path | [Persistence](persistence.md#t1574009) |
| `T1574.010` | Services File Permissions Weakness | Detection Strategy for Hijack Execution Flow through Services File Permissions Weakness. | [Persistence](persistence.md#t1574010) |
| `T1574.011` | Services Registry Permissions Weakness | Detection Strategy for Hijack Execution Flow through Service Registry Premission Weakness. | [Persistence](persistence.md#t1574011) |
| `T1574.012` | COR_PROFILER | Detection Strategy for Hijack Execution Flow using the Windows COR_PROFILER. | [Persistence](persistence.md#t1574012) |
| `T1574.013` | KernelCallbackTable | Detection Strategy for Hijack Execution Flow through the KernelCallbackTable on Windows. | [Persistence](persistence.md#t1574013) |
| `T1574.014` | AppDomainManager | Detection Strategy for Hijack Execution Flow through the AppDomainManager on Windows. | [Persistence](persistence.md#t1574014) |
| `T1578` | Modify Cloud Compute Infrastructure | Detection Strategy for Modify Cloud Compute Infrastructure | [Defense Evasion](defense-evasion.md#t1578) |
| `T1578.001` | Create Snapshot | Detection Strategy for Modify Cloud Compute Infrastructure: Create Snapshot | [Defense Evasion](defense-evasion.md#t1578001) |
| `T1578.002` | Create Cloud Instance | Detection Strategy for Modify Cloud Compute Infrastructure: Create Cloud Instance | [Defense Evasion](defense-evasion.md#t1578002) |
| `T1578.003` | Delete Cloud Instance | Detection Strategy for Modify Cloud Compute Infrastructure: Delete Cloud Instance | [Defense Evasion](defense-evasion.md#t1578003) |
| `T1578.004` | Revert Cloud Instance | Detection Strategy for Modify Cloud Compute Infrastructure: Revert Cloud Instance | [Defense Evasion](defense-evasion.md#t1578004) |
| `T1578.005` | Modify Cloud Compute Configurations | Detection Strategy for Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations | [Defense Evasion](defense-evasion.md#t1578005) |
| `T1580` | Cloud Infrastructure Discovery | Detection Strategy for Cloud Infrastructure Discovery | [Discovery](discovery.md#t1580) |
| `T1583` | Acquire Infrastructure | Detection of Acquire Infrastructure | [Resource Development](resource-development.md#t1583) |
| `T1583.001` | Domains | Detection of Domains | [Resource Development](resource-development.md#t1583001) |
| `T1583.002` | DNS Server | Detection of DNS Server | [Resource Development](resource-development.md#t1583002) |
| `T1583.003` | Virtual Private Server | Detection of Virtual Private Server | [Resource Development](resource-development.md#t1583003) |
| `T1583.004` | Server | Detection of Server | [Resource Development](resource-development.md#t1583004) |
| `T1583.005` | Botnet | Detection of Botnet | [Resource Development](resource-development.md#t1583005) |
| `T1583.006` | Web Services | Detection of Web Services | [Resource Development](resource-development.md#t1583006) |
| `T1583.007` | Serverless | Detection of Serverless | [Resource Development](resource-development.md#t1583007) |
| `T1583.008` | Malvertising | Detection of Malvertising | [Resource Development](resource-development.md#t1583008) |
| `T1584` | Compromise Infrastructure | Detection of Compromise Infrastructure | [Resource Development](resource-development.md#t1584) |
| `T1584.001` | Domains | Detection of Domains | [Resource Development](resource-development.md#t1584001) |
| `T1584.002` | DNS Server | Detection of DNS Server | [Resource Development](resource-development.md#t1584002) |
| `T1584.003` | Virtual Private Server | Detection of Virtual Private Server | [Resource Development](resource-development.md#t1584003) |
| `T1584.004` | Server | Detection of Server | [Resource Development](resource-development.md#t1584004) |
| `T1584.005` | Botnet | Detection of Botnet | [Resource Development](resource-development.md#t1584005) |
| `T1584.006` | Web Services | Detection of Web Services | [Resource Development](resource-development.md#t1584006) |
| `T1584.007` | Serverless | Detection of Serverless | [Resource Development](resource-development.md#t1584007) |
| `T1584.008` | Network Devices | Detection of Network Devices | [Resource Development](resource-development.md#t1584008) |
| `T1585` | Establish Accounts | Detection of Establish Accounts | [Resource Development](resource-development.md#t1585) |
| `T1585.001` | Social Media Accounts | Detection of Social Media Accounts | [Resource Development](resource-development.md#t1585001) |
| `T1585.002` | Email Accounts | Detection of Email Accounts | [Resource Development](resource-development.md#t1585002) |
| `T1585.003` | Cloud Accounts | Detection of Cloud Accounts | [Resource Development](resource-development.md#t1585003) |
| `T1586` | Compromise Accounts | Detection of Compromise Accounts | [Resource Development](resource-development.md#t1586) |
| `T1586.001` | Social Media Accounts | Detection of Social Media Accounts | [Resource Development](resource-development.md#t1586001) |
| `T1586.002` | Email Accounts | Detection of Email Accounts | [Resource Development](resource-development.md#t1586002) |
| `T1586.003` | Cloud Accounts | Detection of Cloud Accounts | [Resource Development](resource-development.md#t1586003) |
| `T1587` | Develop Capabilities | Detection of Develop Capabilities | [Resource Development](resource-development.md#t1587) |
| `T1587.001` | Malware | Detection of Malware | [Resource Development](resource-development.md#t1587001) |
| `T1587.002` | Code Signing Certificates | Detection of Code Signing Certificates | [Resource Development](resource-development.md#t1587002) |
| `T1587.003` | Digital Certificates | Detection of Digital Certificates | [Resource Development](resource-development.md#t1587003) |
| `T1587.004` | Exploits | Detection of Exploits | [Resource Development](resource-development.md#t1587004) |
| `T1588` | Obtain Capabilities | Detection of Obtain Capabilities | [Resource Development](resource-development.md#t1588) |
| `T1588.001` | Malware | Detection of Malware | [Resource Development](resource-development.md#t1588001) |
| `T1588.002` | Tool | Detection of Tool | [Resource Development](resource-development.md#t1588002) |
| `T1588.003` | Code Signing Certificates | Detection of Code Signing Certificates | [Resource Development](resource-development.md#t1588003) |
| `T1588.004` | Digital Certificates | Detection of Digital Certificates | [Resource Development](resource-development.md#t1588004) |
| `T1588.005` | Exploits | Detection of Exploits | [Resource Development](resource-development.md#t1588005) |
| `T1588.006` | Vulnerabilities | Detection of Vulnerabilities | [Resource Development](resource-development.md#t1588006) |
| `T1588.007` | Artificial Intelligence | Detection of Artificial Intelligence | [Resource Development](resource-development.md#t1588007) |
| `T1589` | Gather Victim Identity Information | Detection of Gather Victim Identity Information | [Reconnaissance](reconnaissance.md#t1589) |
| `T1589.001` | Credentials | Detection of Credentials | [Reconnaissance](reconnaissance.md#t1589001) |
| `T1589.002` | Email Addresses | Detection of Email Addresses | [Reconnaissance](reconnaissance.md#t1589002) |
| `T1589.003` | Employee Names | Detection of Employee Names | [Reconnaissance](reconnaissance.md#t1589003) |
| `T1590` | Gather Victim Network Information | Detection of Gather Victim Network Information | [Reconnaissance](reconnaissance.md#t1590) |
| `T1590.001` | Domain Properties | Detection of Domain Properties | [Reconnaissance](reconnaissance.md#t1590001) |
| `T1590.002` | DNS | Detection of DNS | [Reconnaissance](reconnaissance.md#t1590002) |
| `T1590.003` | Network Trust Dependencies | Detection of Network Trust Dependencies | [Reconnaissance](reconnaissance.md#t1590003) |
| `T1590.004` | Network Topology | Detection of Network Topology | [Reconnaissance](reconnaissance.md#t1590004) |
| `T1590.005` | IP Addresses | Detection of IP Addresses | [Reconnaissance](reconnaissance.md#t1590005) |
| `T1590.006` | Network Security Appliances | Detection of Network Security Appliances | [Reconnaissance](reconnaissance.md#t1590006) |
| `T1591` | Gather Victim Org Information | Detection of Gather Victim Org Information | [Reconnaissance](reconnaissance.md#t1591) |
| `T1591.001` | Determine Physical Locations | Detection of Determine Physical Locations | [Reconnaissance](reconnaissance.md#t1591001) |
| `T1591.002` | Business Relationships | Detection of Business Relationships | [Reconnaissance](reconnaissance.md#t1591002) |
| `T1591.003` | Identify Business Tempo | Detection of Identify Business Tempo | [Reconnaissance](reconnaissance.md#t1591003) |
| `T1591.004` | Identify Roles | Detection of Identify Roles | [Reconnaissance](reconnaissance.md#t1591004) |
| `T1592` | Gather Victim Host Information | Detection of Gather Victim Host Information | [Reconnaissance](reconnaissance.md#t1592) |
| `T1592.001` | Hardware | Detection of Hardware | [Reconnaissance](reconnaissance.md#t1592001) |
| `T1592.002` | Software | Detection of Software | [Reconnaissance](reconnaissance.md#t1592002) |
| `T1592.003` | Firmware | Detection of Firmware | [Reconnaissance](reconnaissance.md#t1592003) |
| `T1592.004` | Client Configurations | Detection of Client Configurations | [Reconnaissance](reconnaissance.md#t1592004) |
| `T1593` | Search Open Websites/Domains | Detection of Search Open Websites/Domains | [Reconnaissance](reconnaissance.md#t1593) |
| `T1593.001` | Social Media | Detection of Social Media | [Reconnaissance](reconnaissance.md#t1593001) |
| `T1593.002` | Search Engines | Detection of Search Engines | [Reconnaissance](reconnaissance.md#t1593002) |
| `T1593.003` | Code Repositories | Detection of Code Repositories | [Reconnaissance](reconnaissance.md#t1593003) |
| `T1594` | Search Victim-Owned Websites | Detection of Search Victim-Owned Websites | [Reconnaissance](reconnaissance.md#t1594) |
| `T1595` | Active Scanning | Detection of Active Scanning | [Reconnaissance](reconnaissance.md#t1595) |
| `T1595.001` | Scanning IP Blocks | Detection of Scanning IP Blocks | [Reconnaissance](reconnaissance.md#t1595001) |
| `T1595.002` | Vulnerability Scanning | Detection of Vulnerability Scanning | [Reconnaissance](reconnaissance.md#t1595002) |
| `T1595.003` | Wordlist Scanning | Detection of Wordlist Scanning | [Reconnaissance](reconnaissance.md#t1595003) |
| `T1596` | Search Open Technical Databases | Detection of Search Open Technical Databases | [Reconnaissance](reconnaissance.md#t1596) |
| `T1596.001` | DNS/Passive DNS | Detection of DNS/Passive DNS | [Reconnaissance](reconnaissance.md#t1596001) |
| `T1596.002` | WHOIS | Detection of WHOIS | [Reconnaissance](reconnaissance.md#t1596002) |
| `T1596.003` | Digital Certificates | Detection of Digital Certificates | [Reconnaissance](reconnaissance.md#t1596003) |
| `T1596.004` | CDNs | Detection of CDNs | [Reconnaissance](reconnaissance.md#t1596004) |
| `T1596.005` | Scan Databases | Detection of Scan Databases | [Reconnaissance](reconnaissance.md#t1596005) |
| `T1597` | Search Closed Sources | Detection of Search Closed Sources | [Reconnaissance](reconnaissance.md#t1597) |
| `T1597.001` | Threat Intel Vendors | Detection of Threat Intel Vendors | [Reconnaissance](reconnaissance.md#t1597001) |
| `T1597.002` | Purchase Technical Data | Detection of Purchase Technical Data | [Reconnaissance](reconnaissance.md#t1597002) |
| `T1598` | Phishing for Information | Detection of Phishing for Information | [Reconnaissance](reconnaissance.md#t1598) |
| `T1598.001` | Spearphishing Service | Detection of Spearphishing Service | [Reconnaissance](reconnaissance.md#t1598001) |
| `T1598.002` | Spearphishing Attachment | Detection of Spearphishing Attachment | [Reconnaissance](reconnaissance.md#t1598002) |
| `T1598.003` | Spearphishing Link | Detection of Spearphishing Link | [Reconnaissance](reconnaissance.md#t1598003) |
| `T1598.004` | Spearphishing Voice | Detection of Spearphishing Voice | [Reconnaissance](reconnaissance.md#t1598004) |
| `T1599` | Network Boundary Bridging | Detection Strategy for Network Boundary Bridging | [Defense Evasion](defense-evasion.md#t1599) |
| `T1599.001` | Network Address Translation Traversal | Detection Strategy for Network Address Translation Traversal | [Defense Evasion](defense-evasion.md#t1599001) |
| `T1600` | Weaken Encryption | Detection Strategy for Weaken Encryption on Network Devices | [Defense Evasion](defense-evasion.md#t1600) |
| `T1600.001` | Reduce Key Space | Detection Strategy for Weaken Encryption: Reduce Key Space on Network Devices | [Defense Evasion](defense-evasion.md#t1600001) |
| `T1600.002` | Disable Crypto Hardware | Detection Strategy for Weaken Encryption: Disable Crypto Hardware on Network Devices | [Defense Evasion](defense-evasion.md#t1600002) |
| `T1601` | Modify System Image | Detection Strategy for Modify System Image on Network Devices | [Defense Evasion](defense-evasion.md#t1601) |
| `T1601.001` | Patch System Image | Detection Strategy for Patch System Image on Network Devices | [Defense Evasion](defense-evasion.md#t1601001) |
| `T1601.002` | Downgrade System Image | Detection Strategy for Downgrade System Image on Network Devices | [Defense Evasion](defense-evasion.md#t1601002) |
| `T1602` | Data from Configuration Repository | Detection Strategy for Data from Configuration Repository on Network Devices | [Collection](collection.md#t1602) |
| `T1602.001` | SNMP (MIB Dump) | Detection Strategy for SNMP (MIB Dump) on Network Devices | [Collection](collection.md#t1602001) |
| `T1602.002` | Network Device Configuration Dump | Detection Strategy for Network Device Configuration Dump via Config Repositories | [Collection](collection.md#t1602002) |
| `T1606` | Forge Web Credentials | Detection Strategy for Forged Web Credentials | [Credential Access](credential-access.md#t1606) |
| `T1606.001` | Web Cookies | Detection Strategy for Forged Web Cookies | [Credential Access](credential-access.md#t1606001) |
| `T1606.002` | SAML Tokens | Detection Strategy for Forged SAML Tokens | [Credential Access](credential-access.md#t1606002) |
| `T1608` | Stage Capabilities | Detection of Stage Capabilities | [Resource Development](resource-development.md#t1608) |
| `T1608.001` | Upload Malware | Detection of Upload Malware | [Resource Development](resource-development.md#t1608001) |
| `T1608.002` | Upload Tool | Detection of Upload Tool | [Resource Development](resource-development.md#t1608002) |
| `T1608.003` | Install Digital Certificate | Detection of Install Digital Certificate | [Resource Development](resource-development.md#t1608003) |
| `T1608.004` | Drive-by Target | Detection of Drive-by Target | [Resource Development](resource-development.md#t1608004) |
| `T1608.005` | Link Target | Detection of Link Target | [Resource Development](resource-development.md#t1608005) |
| `T1608.006` | SEO Poisoning | Detection of SEO Poisoning | [Resource Development](resource-development.md#t1608006) |
| `T1609` | Container Administration Command | Detection Strategy for Container Administration Command Abuse | [Execution](execution.md#t1609) |
| `T1610` | Deploy Container | Behavior-chain detection for T1610 Deploy Container across Docker & Kubernetes control/node planes | [Defense Evasion](defense-evasion.md#t1610) |
| `T1611` | Escape to Host | Detection Strategy for Escape to Host | [Privilege Escalation](privilege-escalation.md#t1611) |
| `T1612` | Build Image on Host | Detection Strategy for Build Image on Host | [Defense Evasion](defense-evasion.md#t1612) |
| `T1613` | Container and Resource Discovery | Detection Strategy for Container and Resource Discovery | [Discovery](discovery.md#t1613) |
| `T1614` | System Location Discovery | Detection Strategy for System Location Discovery | [Discovery](discovery.md#t1614) |
| `T1614.001` | System Language Discovery | Detection Strategy for System Language Discovery | [Discovery](discovery.md#t1614001) |
| `T1615` | Group Policy Discovery | Detection strategy for Group Policy Discovery on Windows | [Discovery](discovery.md#t1615) |
| `T1619` | Cloud Storage Object Discovery | Detection Strategy for Cloud Storage Object Discovery | [Discovery](discovery.md#t1619) |
| `T1620` | Reflective Code Loading | Detection Strategy for Reflective Code Loading | [Defense Evasion](defense-evasion.md#t1620) |
| `T1621` | Multi-Factor Authentication Request Generation | Detection Strategy for Multi-Factor Authentication Request Generation (T1621) | [Credential Access](credential-access.md#t1621) |
| `T1622` | Debugger Evasion | Detection Strategy for Debugger Evasion (T1622) | [Defense Evasion](defense-evasion.md#t1622) |
| `T1647` | Plist File Modification | Detection Strategy for Plist File Modification (T1647) | [Defense Evasion](defense-evasion.md#t1647) |
| `T1648` | Serverless Execution | Detection Strategy for Serverless Execution (T1648) | [Execution](execution.md#t1648) |
| `T1649` | Steal or Forge Authentication Certificates | Detection Strategy for Steal or Forge Authentication Certificates | [Credential Access](credential-access.md#t1649) |
| `T1650` | Acquire Access | Detection of Acquire Access | [Resource Development](resource-development.md#t1650) |
| `T1651` | Cloud Administration Command | Detection Strategy for Cloud Administration Command | [Execution](execution.md#t1651) |
| `T1652` | Device Driver Discovery | Detection Strategy for Device Driver Discovery | [Discovery](discovery.md#t1652) |
| `T1653` | Power Settings | Detection Strategy for Power Settings Abuse | [Persistence](persistence.md#t1653) |
| `T1654` | Log Enumeration | Detection Strategy for Log Enumeration | [Discovery](discovery.md#t1654) |
| `T1656` | Impersonation | Detection Strategy for Impersonation | [Defense Evasion](defense-evasion.md#t1656) |
| `T1657` | Financial Theft | Detection Strategy for Financial Theft | [Impact](impact.md#t1657) |
| `T1659` | Content Injection | Detection Strategy for Content Injection | [Initial Access](initial-access.md#t1659) |
| `T1665` | Hide Infrastructure | Detection Strategy for Hide Infrastructure | [Command and Control](command-and-control.md#t1665) |
| `T1666` | Modify Cloud Resource Hierarchy | Detection Strategy for Modify Cloud Resource Hierarchy | [Defense Evasion](defense-evasion.md#t1666) |
| `T1667` | Email Bombing | Detection Strategy for Email Bombing | [Impact](impact.md#t1667) |
| `T1668` | Exclusive Control | Detection Strategy for Exclusive Control | [Persistence](persistence.md#t1668) |
| `T1669` | Wi-Fi Networks | Detection Strategy for Wi-Fi Networks | [Initial Access](initial-access.md#t1669) |
| `T1671` | Cloud Application Integration | Detection Strategy for Cloud Application Integration | [Persistence](persistence.md#t1671) |
| `T1672` | Email Spoofing | Detection Strategy for Email Spoofing | [Defense Evasion](defense-evasion.md#t1672) |
| `T1673` | Virtual Machine Discovery | Detection Strategy for Virtual Machine Discovery | [Discovery](discovery.md#t1673) |
| `T1674` | Input Injection | Detection Strategy for Input Injection | [Execution](execution.md#t1674) |
| `T1675` | ESXi Administration Command | Detection Strategy for ESXi Administration Command | [Execution](execution.md#t1675) |
| `T1677` | Poisoned Pipeline Execution | Detection Strategy for Poisoned Pipeline Execution via SaaS CI/CD Workflows | [Execution](execution.md#t1677) |
| `T1678` | Delay Execution | Multi-Platform Detection Strategy for T1678 - Delay Execution | [Defense Evasion](defense-evasion.md#t1678) |
| `T1679` | Selective Exclusion | Detection of Selective Exclusion | [Defense Evasion](defense-evasion.md#t1679) |
| `T1680` | Local Storage Discovery | Local Storage Discovery via Drive Enumeration and Filesystem Probing | [Discovery](discovery.md#t1680) |
| `T1681` | Search Threat Vendor Data | Detection of Search Threat Vendor Data | [Reconnaissance](reconnaissance.md#t1681) |
