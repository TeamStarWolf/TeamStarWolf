# ATT&CK Mitigations Reference

> The **44 MITRE ATT&CK Enterprise mitigations** (M-codes, v18.1) — the defensive measures ATT&CK maps to adversary techniques. Each mitigation lists how many techniques it addresses and the behaviors it counters. Use it alongside the [NIST 800-53 control mappings](CONTROLS_MAPPING.md) and [D3FEND](https://d3fend.mitre.org/) for a full defensive picture.

| | |
|---|---|
| **Read this when** | prioritizing which defensive measures buy the most technique coverage, translating an ATT&CK technique into concrete hardening steps, building or reviewing a mitigation-to-control mapping |
| **Start at** | [Mitigations by coverage](#mitigations-by-coverage) for the ranked table, [Detail](#detail) for per-mitigation descriptions and example techniques |
| **Pairs with** | [CONTROLS_MAPPING.md](CONTROLS_MAPPING.md), [D3FEND_REFERENCE.md](D3FEND_REFERENCE.md), [ATTACK_TECHNIQUE_ATLAS.md](ATTACK_TECHNIQUE_ATLAS.md) |

Machine-readable: [`data/attack/mitigations.jsonl`](data/attack/mitigations.jsonl) · [`data/attack/mitigation_to_technique.jsonl`](data/attack/mitigation_to_technique.jsonl)

## Mitigations by coverage

| Mitigation | Techniques addressed |
|---|--:|
| [M1018 User Account Management](#m1018-user-account-management) | 120 |
| [M1026 Privileged Account Management](#m1026-privileged-account-management) | 112 |
| [M1047 Audit](#m1047-audit) | 109 |
| [M1056 Pre-compromise](#m1056-pre-compromise) | 84 |
| [M1038 Execution Prevention](#m1038-execution-prevention) | 80 |
| [M1042 Disable or Remove Feature or Program](#m1042-disable-or-remove-feature-or-program) | 71 |
| [M1022 Restrict File and Directory Permissions](#m1022-restrict-file-and-directory-permissions) | 61 |
| [M1017 User Training](#m1017-user-training) | 59 |
| [M1031 Network Intrusion Prevention](#m1031-network-intrusion-prevention) | 59 |
| [M1040 Behavior Prevention on Endpoint](#m1040-behavior-prevention-on-endpoint) | 51 |
| [M1037 Filter Network Traffic](#m1037-filter-network-traffic) | 49 |
| [M1032 Multi-factor Authentication](#m1032-multi-factor-authentication) | 48 |
| [M1027 Password Policies](#m1027-password-policies) | 47 |
| [M1051 Update Software](#m1051-update-software) | 42 |
| [M1028 Operating System Configuration](#m1028-operating-system-configuration) | 39 |
| [M1030 Network Segmentation](#m1030-network-segmentation) | 37 |
| [M1054 Software Configuration](#m1054-software-configuration) | 37 |
| [M1041 Encrypt Sensitive Information](#m1041-encrypt-sensitive-information) | 33 |
| [M1021 Restrict Web-Based Content](#m1021-restrict-web-based-content) | 31 |
| [M1049 Antivirus/Antimalware](#m1049-antivirusantimalware) | 23 |
| [M1045 Code Signing](#m1045-code-signing) | 22 |
| [M1024 Restrict Registry Permissions](#m1024-restrict-registry-permissions) | 20 |
| [M1035 Limit Access to Resource Over Network](#m1035-limit-access-to-resource-over-network) | 19 |
| [M1013 Application Developer Guidance](#m1013-application-developer-guidance) | 17 |
| [M1033 Limit Software Installation](#m1033-limit-software-installation) | 17 |
| [M1015 Active Directory Configuration](#m1015-active-directory-configuration) | 15 |
| [M1046 Boot Integrity](#m1046-boot-integrity) | 14 |
| [M1048 Application Isolation and Sandboxing](#m1048-application-isolation-and-sandboxing) | 14 |
| [M1050 Exploit Protection](#m1050-exploit-protection) | 12 |
| [M1057 Data Loss Prevention](#m1057-data-loss-prevention) | 12 |
| [M1029 Remote Data Storage](#m1029-remote-data-storage) | 11 |
| [M1036 Account Use Policies](#m1036-account-use-policies) | 10 |
| [M1043 Credential Access Protection](#m1043-credential-access-protection) | 10 |
| [M1053 Data Backup](#m1053-data-backup) | 10 |
| [M1025 Privileged Process Integrity](#m1025-privileged-process-integrity) | 7 |
| [M1034 Limit Hardware Installation](#m1034-limit-hardware-installation) | 7 |
| [M1052 User Account Control](#m1052-user-account-control) | 7 |
| [M1060 Out-of-Band Communications Channel](#m1060-out-of-band-communications-channel) | 7 |
| [M1016 Vulnerability Scanning](#m1016-vulnerability-scanning) | 5 |
| [M1019 Threat Intelligence Program](#m1019-threat-intelligence-program) | 5 |
| [M1020 SSL/TLS Inspection](#m1020-ssltls-inspection) | 4 |
| [M1044 Restrict Library Loading](#m1044-restrict-library-loading) | 3 |
| [M1055 Do Not Mitigate](#m1055-do-not-mitigate) | 3 |
| [M1039 Environment Variable Permissions](#m1039-environment-variable-permissions) | 2 |

---

## Detail

### M1013 — Application Developer Guidance
<a id="m1013"></a>

**ATT&CK:** [M1013](https://attack.mitre.org/mitigations/M1013) · addresses **17** techniques  

Application Developer Guidance focuses on providing developers with the knowledge, tools, and best practices needed to write secure code, reduce vulnerabilities, and implement secure design principles. By integrating security throughout the software development lifecycle (SDLC), this mitigation aims to prevent the introduction of exploitable weaknesses in applications, systems, and APIs.

**Example techniques:** [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1195](https://attack.mitre.org/techniques/T1195) Supply Chain Compromise · [T1195.001](https://attack.mitre.org/techniques/T1195/001) Compromise Software Dependencies and Development Tools · [T1212](https://attack.mitre.org/techniques/T1212) Exploitation for Credential Access · [T1496.003](https://attack.mitre.org/techniques/T1496/003) SMS Pumping · [T1550](https://attack.mitre.org/techniques/T1550) Use Alternate Authentication Material · [T1550.001](https://attack.mitre.org/techniques/T1550/001) Application Access Token · [T1559](https://attack.mitre.org/techniques/T1559) Inter-Process Communication · [T1559.003](https://attack.mitre.org/techniques/T1559/003) XPC Services · [T1564](https://attack.mitre.org/techniques/T1564) Hide Artifacts · [T1564.009](https://attack.mitre.org/techniques/T1564/009) Resource Forking · [T1564.012](https://attack.mitre.org/techniques/T1564/012) File/Path Exclusions · [T1574](https://attack.mitre.org/techniques/T1574) Hijack Execution Flow · [T1574.001](https://attack.mitre.org/techniques/T1574/001) DLL · [T1593](https://attack.mitre.org/techniques/T1593) Search Open Websites/Domains · [T1593.003](https://attack.mitre.org/techniques/T1593/003) Code Repositories · [T1647](https://attack.mitre.org/techniques/T1647) Plist File Modification

---

### M1015 — Active Directory Configuration
<a id="m1015"></a>

**ATT&CK:** [M1015](https://attack.mitre.org/mitigations/M1015) · addresses **15** techniques  

Implement robust Active Directory (AD) configurations using group policies to secure user accounts, control access, and minimize the attack surface. AD configurations enable centralized control over account settings, logon policies, and permissions, reducing the risk of unauthorized access and lateral movement within the network.

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials · [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts · [T1134.005](https://attack.mitre.org/techniques/T1134/005) SID-History Injection · [T1550](https://attack.mitre.org/techniques/T1550) Use Alternate Authentication Material · [T1550.003](https://attack.mitre.org/techniques/T1550/003) Pass the Ticket · [T1552](https://attack.mitre.org/techniques/T1552) Unsecured Credentials · [T1552.006](https://attack.mitre.org/techniques/T1552/006) Group Policy Preferences · [T1558](https://attack.mitre.org/techniques/T1558) Steal or Forge Kerberos Tickets · [T1558.001](https://attack.mitre.org/techniques/T1558/001) Golden Ticket · [T1606.002](https://attack.mitre.org/techniques/T1606/002) SAML Tokens · [T1649](https://attack.mitre.org/techniques/T1649) Steal or Forge Authentication Certificates

---

### M1016 — Vulnerability Scanning
<a id="m1016"></a>

**ATT&CK:** [M1016](https://attack.mitre.org/mitigations/M1016) · addresses **5** techniques  

Vulnerability scanning involves the automated or manual assessment of systems, applications, and networks to identify misconfigurations, unpatched software, or other security weaknesses. The process helps prioritize remediation efforts by classifying vulnerabilities based on risk and impact, reducing the likelihood of exploitation by adversaries.

**Example techniques:** [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1195](https://attack.mitre.org/techniques/T1195) Supply Chain Compromise · [T1195.001](https://attack.mitre.org/techniques/T1195/001) Compromise Software Dependencies and Development Tools · [T1195.002](https://attack.mitre.org/techniques/T1195/002) Compromise Software Supply Chain · [T1210](https://attack.mitre.org/techniques/T1210) Exploitation of Remote Services

---

### M1017 — User Training
<a id="m1017"></a>

**ATT&CK:** [M1017](https://attack.mitre.org/mitigations/M1017) · addresses **59** techniques  

User Training involves educating employees and contractors on recognizing, reporting, and preventing cyber threats that rely on human interaction, such as phishing, social engineering, and other manipulative techniques. Comprehensive training programs create a human firewall by empowering users to be an active component of the organization's cybersecurity defenses.

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS · [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets · [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.007](https://attack.mitre.org/techniques/T1036/007) Double File Extension · [T1056.002](https://attack.mitre.org/techniques/T1056/002) GUI Input Capture · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts · [T1111](https://attack.mitre.org/techniques/T1111) Multi-Factor Authentication Interception · [T1176](https://attack.mitre.org/techniques/T1176) Software Extensions · [T1176.001](https://attack.mitre.org/techniques/T1176/001) Browser Extensions · [T1176.002](https://attack.mitre.org/techniques/T1176/002) IDE Extensions · [T1185](https://attack.mitre.org/techniques/T1185) Browser Session Hijacking · [T1189](https://attack.mitre.org/techniques/T1189) Drive-by Compromise

---

### M1018 — User Account Management
<a id="m1018"></a>

**ATT&CK:** [M1018](https://attack.mitre.org/mitigations/M1018) · addresses **120** techniques  

User Account Management involves implementing and enforcing policies for the lifecycle of user accounts, including creation, modification, and deactivation. Proper account management reduces the attack surface by limiting unauthorized access, managing account privileges, and ensuring accounts are used according to organizational policies.

**Example techniques:** [T1006](https://attack.mitre.org/techniques/T1006) Direct Volume Access · [T1020.001](https://attack.mitre.org/techniques/T1020/001) Traffic Duplication · [T1021](https://attack.mitre.org/techniques/T1021) Remote Services · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH · [T1021.008](https://attack.mitre.org/techniques/T1021/008) Direct Cloud VM Connections · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.010](https://attack.mitre.org/techniques/T1036/010) Masquerade Account Name · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1048](https://attack.mitre.org/techniques/T1048) Exfiltration Over Alternative Protocol · [T1053](https://attack.mitre.org/techniques/T1053) Scheduled Task/Job · [T1053.002](https://attack.mitre.org/techniques/T1053/002) At · [T1053.003](https://attack.mitre.org/techniques/T1053/003) Cron · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1053.006](https://attack.mitre.org/techniques/T1053/006) Systemd Timers · [T1053.007](https://attack.mitre.org/techniques/T1053/007) Container Orchestration Job · [T1059.008](https://attack.mitre.org/techniques/T1059/008) Network Device CLI · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts

---

### M1019 — Threat Intelligence Program
<a id="m1019"></a>

**ATT&CK:** [M1019](https://attack.mitre.org/mitigations/M1019) · addresses **5** techniques  

A Threat Intelligence Program enables organizations to proactively identify, analyze, and act on cyber threats by leveraging internal and external data sources. The program supports decision-making processes, prioritizes defenses, and improves incident response by delivering actionable intelligence tailored to the organization's risk profile and operational environment.

**Example techniques:** [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1210](https://attack.mitre.org/techniques/T1210) Exploitation of Remote Services · [T1211](https://attack.mitre.org/techniques/T1211) Exploitation for Defense Evasion · [T1212](https://attack.mitre.org/techniques/T1212) Exploitation for Credential Access · [T1656](https://attack.mitre.org/techniques/T1656) Impersonation

---

### M1020 — SSL/TLS Inspection
<a id="m1020"></a>

**ATT&CK:** [M1020](https://attack.mitre.org/mitigations/M1020) · addresses **4** techniques  

SSL/TLS inspection involves decrypting encrypted network traffic to examine its content for signs of malicious activity. This capability is crucial for detecting threats that use encryption to evade detection, such as phishing, malware, or data exfiltration. After inspection, the traffic is re-encrypted and forwarded to its destination.

**Example techniques:** [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1090.004](https://attack.mitre.org/techniques/T1090/004) Domain Fronting · [T1573](https://attack.mitre.org/techniques/T1573) Encrypted Channel · [T1573.002](https://attack.mitre.org/techniques/T1573/002) Asymmetric Cryptography

---

### M1021 — Restrict Web-Based Content
<a id="m1021"></a>

**ATT&CK:** [M1021](https://attack.mitre.org/mitigations/M1021) · addresses **31** techniques  

Restricting web-based content involves enforcing policies and technologies that limit access to potentially malicious websites, unsafe downloads, and unauthorized browser behaviors. This can include URL filtering, download restrictions, script blocking, and extension control to protect against exploitation, phishing, and malware delivery.

**Example techniques:** [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1102](https://attack.mitre.org/techniques/T1102) Web Service · [T1102.001](https://attack.mitre.org/techniques/T1102/001) Dead Drop Resolver · [T1102.002](https://attack.mitre.org/techniques/T1102/002) Bidirectional Communication · [T1102.003](https://attack.mitre.org/techniques/T1102/003) One-Way Communication · [T1127](https://attack.mitre.org/techniques/T1127) Trusted Developer Utilities Proxy Execution · [T1127.002](https://attack.mitre.org/techniques/T1127/002) ClickOnce · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1189](https://attack.mitre.org/techniques/T1189) Drive-by Compromise · [T1204](https://attack.mitre.org/techniques/T1204) User Execution · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1204.004](https://attack.mitre.org/techniques/T1204/004) Malicious Copy and Paste · [T1218](https://attack.mitre.org/techniques/T1218) System Binary Proxy Execution · [T1218.001](https://attack.mitre.org/techniques/T1218/001) Compiled HTML File · [T1528](https://attack.mitre.org/techniques/T1528) Steal Application Access Token · [T1539](https://attack.mitre.org/techniques/T1539) Steal Web Session Cookie · [T1550.001](https://attack.mitre.org/techniques/T1550/001) Application Access Token · [T1555.003](https://attack.mitre.org/techniques/T1555/003) Credentials from Web Browsers

---

### M1022 — Restrict File and Directory Permissions
<a id="m1022"></a>

**ATT&CK:** [M1022](https://attack.mitre.org/mitigations/M1022) · addresses **61** techniques  

Restricting file and directory permissions involves setting access controls at the file system level to limit which users, groups, or processes can read, write, or execute files. By configuring permissions appropriately, organizations can reduce the attack surface for adversaries seeking to access sensitive data, plant malicious code, or tamper with system files.

**Example techniques:** [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.003](https://attack.mitre.org/techniques/T1036/003) Rename Legitimate Utilities · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1037](https://attack.mitre.org/techniques/T1037) Boot or Logon Initialization Scripts · [T1037.002](https://attack.mitre.org/techniques/T1037/002) Login Hook · [T1037.003](https://attack.mitre.org/techniques/T1037/003) Network Logon Script · [T1037.004](https://attack.mitre.org/techniques/T1037/004) RC Scripts · [T1037.005](https://attack.mitre.org/techniques/T1037/005) Startup Items · [T1048](https://attack.mitre.org/techniques/T1048) Exfiltration Over Alternative Protocol · [T1053](https://attack.mitre.org/techniques/T1053) Scheduled Task/Job · [T1053.006](https://attack.mitre.org/techniques/T1053/006) Systemd Timers · [T1055.009](https://attack.mitre.org/techniques/T1055/009) Proc Memory · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs · [T1070.002](https://attack.mitre.org/techniques/T1070/002) Clear Linux or Mac System Logs · [T1070.003](https://attack.mitre.org/techniques/T1070/003) Clear Command History · [T1070.008](https://attack.mitre.org/techniques/T1070/008) Clear Mailbox Data · [T1070.009](https://attack.mitre.org/techniques/T1070/009) Clear Persistence · [T1080](https://attack.mitre.org/techniques/T1080) Taint Shared Content · [T1098](https://attack.mitre.org/techniques/T1098) Account Manipulation

---

### M1024 — Restrict Registry Permissions
<a id="m1024"></a>

**ATT&CK:** [M1024](https://attack.mitre.org/mitigations/M1024) · addresses **20** techniques  

Restricting registry permissions involves configuring access control settings for sensitive registry keys and hives to ensure that only authorized users or processes can make modifications. By limiting access, organizations can prevent unauthorized changes that adversaries might use for persistence, privilege escalation, or defense evasion.

**Example techniques:** [T1037](https://attack.mitre.org/techniques/T1037) Boot or Logon Initialization Scripts · [T1037.001](https://attack.mitre.org/techniques/T1037/001) Logon Script (Windows) · [T1070.007](https://attack.mitre.org/techniques/T1070/007) Clear Network Connection History and Configurations · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1489](https://attack.mitre.org/techniques/T1489) Service Stop · [T1505](https://attack.mitre.org/techniques/T1505) Server Software Component · [T1505.005](https://attack.mitre.org/techniques/T1505/005) Terminal Services DLL · [T1547.003](https://attack.mitre.org/techniques/T1547/003) Time Providers · [T1553](https://attack.mitre.org/techniques/T1553) Subvert Trust Controls · [T1553.003](https://attack.mitre.org/techniques/T1553/003) SIP and Trust Provider Hijacking · [T1553.006](https://attack.mitre.org/techniques/T1553/006) Code Signing Policy Modification · [T1556](https://attack.mitre.org/techniques/T1556) Modify Authentication Process · [T1556.008](https://attack.mitre.org/techniques/T1556/008) Network Provider DLL · [T1562](https://attack.mitre.org/techniques/T1562) Impair Defenses · [T1562.001](https://attack.mitre.org/techniques/T1562/001) Disable or Modify Tools · [T1562.002](https://attack.mitre.org/techniques/T1562/002) Disable Windows Event Logging · [T1562.004](https://attack.mitre.org/techniques/T1562/004) Disable or Modify System Firewall · [T1574](https://attack.mitre.org/techniques/T1574) Hijack Execution Flow · [T1574.011](https://attack.mitre.org/techniques/T1574/011) Services Registry Permissions Weakness · [T1574.012](https://attack.mitre.org/techniques/T1574/012) COR_PROFILER

---

### M1025 — Privileged Process Integrity
<a id="m1025"></a>

**ATT&CK:** [M1025](https://attack.mitre.org/mitigations/M1025) · addresses **7** techniques  

Privileged Process Integrity focuses on defending highly privileged processes (e.g., system services, antivirus, or authentication processes) from tampering, injection, or compromise by adversaries. These processes often interact with critical components, making them prime targets for techniques like code injection, privilege escalation, and process manipulation.

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1547.002](https://attack.mitre.org/techniques/T1547/002) Authentication Package · [T1547.005](https://attack.mitre.org/techniques/T1547/005) Security Support Provider · [T1547.008](https://attack.mitre.org/techniques/T1547/008) LSASS Driver · [T1556](https://attack.mitre.org/techniques/T1556) Modify Authentication Process · [T1556.001](https://attack.mitre.org/techniques/T1556/001) Domain Controller Authentication

---

### M1026 — Privileged Account Management
<a id="m1026"></a>

**ATT&CK:** [M1026](https://attack.mitre.org/mitigations/M1026) · addresses **112** techniques  

Privileged Account Management focuses on implementing policies, controls, and tools to securely manage privileged accounts (e.g., SYSTEM, root, or administrative accounts).

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS · [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets · [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials · [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync · [T1003.007](https://attack.mitre.org/techniques/T1003/007) Proc Filesystem · [T1003.008](https://attack.mitre.org/techniques/T1003/008) /etc/passwd and /etc/shadow · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1021.003](https://attack.mitre.org/techniques/T1021/003) Distributed Component Object Model · [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management · [T1021.007](https://attack.mitre.org/techniques/T1021/007) Cloud Services · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053](https://attack.mitre.org/techniques/T1053) Scheduled Task/Job · [T1053.002](https://attack.mitre.org/techniques/T1053/002) At · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1053.006](https://attack.mitre.org/techniques/T1053/006) Systemd Timers · [T1053.007](https://attack.mitre.org/techniques/T1053/007) Container Orchestration Job

---

### M1027 — Password Policies
<a id="m1027"></a>

**ATT&CK:** [M1027](https://attack.mitre.org/mitigations/M1027) · addresses **47** techniques  

Set and enforce secure password policies for accounts to reduce the likelihood of unauthorized access. Strong password policies include enforcing password complexity, requiring regular password changes, and preventing password reuse.

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS · [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets · [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials · [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync · [T1003.007](https://attack.mitre.org/techniques/T1003/007) Proc Filesystem · [T1003.008](https://attack.mitre.org/techniques/T1003/008) /etc/passwd and /etc/shadow · [T1021](https://attack.mitre.org/techniques/T1021) Remote Services · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.001](https://attack.mitre.org/techniques/T1078/001) Default Accounts · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1078.003](https://attack.mitre.org/techniques/T1078/003) Local Accounts · [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts · [T1110](https://attack.mitre.org/techniques/T1110) Brute Force · [T1110.001](https://attack.mitre.org/techniques/T1110/001) Password Guessing · [T1110.002](https://attack.mitre.org/techniques/T1110/002) Password Cracking

---

### M1028 — Operating System Configuration
<a id="m1028"></a>

**ATT&CK:** [M1028](https://attack.mitre.org/mitigations/M1028) · addresses **39** techniques  

Operating System Configuration involves adjusting system settings and hardening the default configurations of an operating system (OS) to mitigate adversary exploitation and prevent abuse of system functionality. Proper OS configurations address security vulnerabilities, limit attack surfaces, and ensure robust defense against a wide range of techniques.

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials · [T1011](https://attack.mitre.org/techniques/T1011) Exfiltration Over Other Network Medium · [T1011.001](https://attack.mitre.org/techniques/T1011/001) Exfiltration Over Bluetooth · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1036.007](https://attack.mitre.org/techniques/T1036/007) Double File Extension · [T1053](https://attack.mitre.org/techniques/T1053) Scheduled Task/Job · [T1053.002](https://attack.mitre.org/techniques/T1053/002) At · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1087](https://attack.mitre.org/techniques/T1087) Account Discovery · [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account · [T1087.002](https://attack.mitre.org/techniques/T1087/002) Domain Account · [T1092](https://attack.mitre.org/techniques/T1092) Communication Through Removable Media · [T1098](https://attack.mitre.org/techniques/T1098) Account Manipulation · [T1135](https://attack.mitre.org/techniques/T1135) Network Share Discovery · [T1136](https://attack.mitre.org/techniques/T1136) Create Account · [T1136.002](https://attack.mitre.org/techniques/T1136/002) Domain Account · [T1197](https://attack.mitre.org/techniques/T1197) BITS Jobs

---

### M1029 — Remote Data Storage
<a id="m1029"></a>

**ATT&CK:** [M1029](https://attack.mitre.org/mitigations/M1029) · addresses **11** techniques  

Remote Data Storage focuses on moving critical data, such as security logs and sensitive files, to secure, off-host locations to minimize unauthorized access, tampering, or destruction by adversaries. By leveraging remote storage solutions, organizations enhance the protection of forensic evidence, sensitive information, and monitoring data.

**Example techniques:** [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs · [T1070.002](https://attack.mitre.org/techniques/T1070/002) Clear Linux or Mac System Logs · [T1070.003](https://attack.mitre.org/techniques/T1070/003) Clear Command History · [T1070.007](https://attack.mitre.org/techniques/T1070/007) Clear Network Connection History and Configurations · [T1070.008](https://attack.mitre.org/techniques/T1070/008) Clear Mailbox Data · [T1070.009](https://attack.mitre.org/techniques/T1070/009) Clear Persistence · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1119](https://attack.mitre.org/techniques/T1119) Automated Collection · [T1565](https://attack.mitre.org/techniques/T1565) Data Manipulation · [T1565.001](https://attack.mitre.org/techniques/T1565/001) Stored Data Manipulation

---

### M1030 — Network Segmentation
<a id="m1030"></a>

**ATT&CK:** [M1030](https://attack.mitre.org/mitigations/M1030) · addresses **37** techniques  

Network segmentation involves dividing a network into smaller, isolated segments to control and limit the flow of traffic between devices, systems, and applications. By segmenting networks, organizations can reduce the attack surface, restrict lateral movement by adversaries, and protect critical assets from compromise.

**Example techniques:** [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.003](https://attack.mitre.org/techniques/T1021/003) Distributed Component Object Model · [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1048](https://attack.mitre.org/techniques/T1048) Exfiltration Over Alternative Protocol · [T1048.001](https://attack.mitre.org/techniques/T1048/001) Exfiltration Over Symmetric Encrypted Non-C2 Protocol · [T1048.002](https://attack.mitre.org/techniques/T1048/002) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1098](https://attack.mitre.org/techniques/T1098) Account Manipulation · [T1098.001](https://attack.mitre.org/techniques/T1098/001) Additional Cloud Credentials · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1136](https://attack.mitre.org/techniques/T1136) Create Account · [T1136.002](https://attack.mitre.org/techniques/T1136/002) Domain Account · [T1136.003](https://attack.mitre.org/techniques/T1136/003) Cloud Account · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1199](https://attack.mitre.org/techniques/T1199) Trusted Relationship · [T1210](https://attack.mitre.org/techniques/T1210) Exploitation of Remote Services

---

### M1031 — Network Intrusion Prevention
<a id="m1031"></a>

**ATT&CK:** [M1031](https://attack.mitre.org/mitigations/M1031) · addresses **59** techniques  

Use intrusion detection signatures to block traffic at network boundaries.

**Example techniques:** [T1001](https://attack.mitre.org/techniques/T1001) Data Obfuscation · [T1001.001](https://attack.mitre.org/techniques/T1001/001) Junk Data · [T1001.002](https://attack.mitre.org/techniques/T1001/002) Steganography · [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1029](https://attack.mitre.org/techniques/T1029) Scheduled Transfer · [T1030](https://attack.mitre.org/techniques/T1030) Data Transfer Size Limits · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1048](https://attack.mitre.org/techniques/T1048) Exfiltration Over Alternative Protocol · [T1048.001](https://attack.mitre.org/techniques/T1048/001) Exfiltration Over Symmetric Encrypted Non-C2 Protocol · [T1048.002](https://attack.mitre.org/techniques/T1048/002) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1071](https://attack.mitre.org/techniques/T1071) Application Layer Protocol · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols · [T1071.003](https://attack.mitre.org/techniques/T1071/003) Mail Protocols · [T1071.004](https://attack.mitre.org/techniques/T1071/004) DNS · [T1071.005](https://attack.mitre.org/techniques/T1071/005) Publish/Subscribe Protocols · [T1090](https://attack.mitre.org/techniques/T1090) Proxy

---

### M1032 — Multi-factor Authentication
<a id="m1032"></a>

**ATT&CK:** [M1032](https://attack.mitre.org/mitigations/M1032) · addresses **48** techniques  

Multi-Factor Authentication (MFA) enhances security by requiring users to provide at least two forms of verification to prove their identity before granting access. These factors typically include: - *Something you know*: Passwords, PINs. - *Something you have*: Physical tokens, smartphone authenticator apps.

**Example techniques:** [T1021](https://attack.mitre.org/techniques/T1021) Remote Services · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH · [T1021.007](https://attack.mitre.org/techniques/T1021/007) Cloud Services · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.001](https://attack.mitre.org/techniques/T1078/001) Default Accounts · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1078.003](https://attack.mitre.org/techniques/T1078/003) Local Accounts · [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts · [T1098](https://attack.mitre.org/techniques/T1098) Account Manipulation · [T1098.001](https://attack.mitre.org/techniques/T1098/001) Additional Cloud Credentials · [T1098.002](https://attack.mitre.org/techniques/T1098/002) Additional Email Delegate Permissions · [T1098.003](https://attack.mitre.org/techniques/T1098/003) Additional Cloud Roles · [T1098.005](https://attack.mitre.org/techniques/T1098/005) Device Registration · [T1098.006](https://attack.mitre.org/techniques/T1098/006) Additional Container Cluster Roles · [T1110](https://attack.mitre.org/techniques/T1110) Brute Force · [T1110.001](https://attack.mitre.org/techniques/T1110/001) Password Guessing · [T1110.002](https://attack.mitre.org/techniques/T1110/002) Password Cracking

---

### M1033 — Limit Software Installation
<a id="m1033"></a>

**ATT&CK:** [M1033](https://attack.mitre.org/mitigations/M1033) · addresses **17** techniques  

Prevent users or groups from installing unauthorized or unapproved software to reduce the risk of introducing malicious or vulnerable applications. This can be achieved through allowlists, software restriction policies, endpoint management tools, and least privilege access principles.

**Example techniques:** [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1059.011](https://attack.mitre.org/techniques/T1059/011) Lua · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1176](https://attack.mitre.org/techniques/T1176) Software Extensions · [T1176.001](https://attack.mitre.org/techniques/T1176/001) Browser Extensions · [T1176.002](https://attack.mitre.org/techniques/T1176/002) IDE Extensions · [T1195](https://attack.mitre.org/techniques/T1195) Supply Chain Compromise · [T1195.001](https://attack.mitre.org/techniques/T1195/001) Compromise Software Dependencies and Development Tools · [T1204](https://attack.mitre.org/techniques/T1204) User Execution · [T1204.005](https://attack.mitre.org/techniques/T1204/005) Malicious Library · [T1543](https://attack.mitre.org/techniques/T1543) Create or Modify System Process · [T1543.002](https://attack.mitre.org/techniques/T1543/002) Systemd Service · [T1547.013](https://attack.mitre.org/techniques/T1547/013) XDG Autostart Entries · [T1564](https://attack.mitre.org/techniques/T1564) Hide Artifacts · [T1564.003](https://attack.mitre.org/techniques/T1564/003) Hidden Window

---

### M1034 — Limit Hardware Installation
<a id="m1034"></a>

**ATT&CK:** [M1034](https://attack.mitre.org/mitigations/M1034) · addresses **7** techniques  

Prevent unauthorized users or groups from installing or using hardware, such as external drives, peripheral devices, or unapproved internal hardware components, by enforcing hardware usage policies and technical controls. This includes disabling USB ports, restricting driver installation, and implementing endpoint security tools to monitor and block unapproved devices.

**Example techniques:** [T1052](https://attack.mitre.org/techniques/T1052) Exfiltration Over Physical Medium · [T1052.001](https://attack.mitre.org/techniques/T1052/001) Exfiltration over USB · [T1091](https://attack.mitre.org/techniques/T1091) Replication Through Removable Media · [T1200](https://attack.mitre.org/techniques/T1200) Hardware Additions · [T1219](https://attack.mitre.org/techniques/T1219) Remote Access Tools · [T1219.003](https://attack.mitre.org/techniques/T1219/003) Remote Access Hardware · [T1674](https://attack.mitre.org/techniques/T1674) Input Injection

---

### M1035 — Limit Access to Resource Over Network
<a id="m1035"></a>

**ATT&CK:** [M1035](https://attack.mitre.org/mitigations/M1035) · addresses **19** techniques  

Restrict access to network resources, such as file shares, remote systems, and services, to only those users, accounts, or systems with a legitimate business requirement. This can include employing technologies like network concentrators, RDP gateways, and zero-trust network access (ZTNA) models, alongside hardening services and protocols.

**Example techniques:** [T1021](https://attack.mitre.org/techniques/T1021) Remote Services · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1200](https://attack.mitre.org/techniques/T1200) Hardware Additions · [T1542](https://attack.mitre.org/techniques/T1542) Pre-OS Boot · [T1542.005](https://attack.mitre.org/techniques/T1542/005) TFTP Boot · [T1546.008](https://attack.mitre.org/techniques/T1546/008) Accessibility Features · [T1552](https://attack.mitre.org/techniques/T1552) Unsecured Credentials · [T1552.005](https://attack.mitre.org/techniques/T1552/005) Cloud Instance Metadata API · [T1552.007](https://attack.mitre.org/techniques/T1552/007) Container API · [T1557](https://attack.mitre.org/techniques/T1557) Adversary-in-the-Middle · [T1557.002](https://attack.mitre.org/techniques/T1557/002) ARP Cache Poisoning · [T1563.002](https://attack.mitre.org/techniques/T1563/002) RDP Hijacking · [T1609](https://attack.mitre.org/techniques/T1609) Container Administration Command · [T1610](https://attack.mitre.org/techniques/T1610) Deploy Container · [T1612](https://attack.mitre.org/techniques/T1612) Build Image on Host · [T1613](https://attack.mitre.org/techniques/T1613) Container and Resource Discovery

---

### M1036 — Account Use Policies
<a id="m1036"></a>

**ATT&CK:** [M1036](https://attack.mitre.org/mitigations/M1036) · addresses **10** techniques  

Account Use Policies help mitigate unauthorized access by configuring and enforcing rules that govern how and when accounts can be used. These policies include enforcing account lockout mechanisms, restricting login times, and setting inactivity timeouts.

**Example techniques:** [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts · [T1110](https://attack.mitre.org/techniques/T1110) Brute Force · [T1110.001](https://attack.mitre.org/techniques/T1110/001) Password Guessing · [T1110.003](https://attack.mitre.org/techniques/T1110/003) Password Spraying · [T1110.004](https://attack.mitre.org/techniques/T1110/004) Credential Stuffing · [T1550](https://attack.mitre.org/techniques/T1550) Use Alternate Authentication Material · [T1550.001](https://attack.mitre.org/techniques/T1550/001) Application Access Token · [T1621](https://attack.mitre.org/techniques/T1621) Multi-Factor Authentication Request Generation · [T1648](https://attack.mitre.org/techniques/T1648) Serverless Execution

---

### M1037 — Filter Network Traffic
<a id="m1037"></a>

**ATT&CK:** [M1037](https://attack.mitre.org/mitigations/M1037) · addresses **49** techniques  

Employ network appliances and endpoint software to filter ingress, egress, and lateral network traffic. This includes protocol-based filtering, enforcing firewall rules, and blocking or restricting traffic based on predefined conditions to limit adversary movement and data exfiltration.

**Example techniques:** [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC · [T1048](https://attack.mitre.org/techniques/T1048) Exfiltration Over Alternative Protocol · [T1048.001](https://attack.mitre.org/techniques/T1048/001) Exfiltration Over Symmetric Encrypted Non-C2 Protocol · [T1048.002](https://attack.mitre.org/techniques/T1048/002) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1071](https://attack.mitre.org/techniques/T1071) Application Layer Protocol · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols · [T1071.003](https://attack.mitre.org/techniques/T1071/003) Mail Protocols · [T1071.004](https://attack.mitre.org/techniques/T1071/004) DNS · [T1071.005](https://attack.mitre.org/techniques/T1071/005) Publish/Subscribe Protocols · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1187](https://attack.mitre.org/techniques/T1187) Forced Authentication · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1197](https://attack.mitre.org/techniques/T1197) BITS Jobs · [T1205](https://attack.mitre.org/techniques/T1205) Traffic Signaling

---

### M1038 — Execution Prevention
<a id="m1038"></a>

**ATT&CK:** [M1038](https://attack.mitre.org/mitigations/M1038) · addresses **80** techniques  

Prevent the execution of unauthorized or malicious code on systems by implementing application control, script blocking, and other execution prevention mechanisms. This ensures that only trusted and authorized code is executed, reducing the risk of malware and unauthorized actions.

**Example techniques:** [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.002](https://attack.mitre.org/techniques/T1059/002) AppleScript · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1059.008](https://attack.mitre.org/techniques/T1059/008) Network Device CLI · [T1059.009](https://attack.mitre.org/techniques/T1059/009) Cloud API · [T1059.010](https://attack.mitre.org/techniques/T1059/010) AutoHotKey & AutoIT · [T1059.011](https://attack.mitre.org/techniques/T1059/011) Lua · [T1059.013](https://attack.mitre.org/techniques/T1059/013) Container CLI/API · [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1080](https://attack.mitre.org/techniques/T1080) Taint Shared Content · [T1106](https://attack.mitre.org/techniques/T1106) Native API

---

### M1039 — Environment Variable Permissions
<a id="m1039"></a>

**ATT&CK:** [M1039](https://attack.mitre.org/mitigations/M1039) · addresses **2** techniques  

Restrict the modification of environment variables to authorized users and processes by enforcing strict permissions and policies. This ensures the integrity of environment variables, preventing adversaries from abusing or altering them for malicious purposes.

**Example techniques:** [T1070.003](https://attack.mitre.org/techniques/T1070/003) Clear Command History · [T1562.003](https://attack.mitre.org/techniques/T1562/003) Impair Command History Logging

---

### M1040 — Behavior Prevention on Endpoint
<a id="m1040"></a>

**ATT&CK:** [M1040](https://attack.mitre.org/mitigations/M1040) · addresses **51** techniques  

Behavior Prevention on Endpoint refers to the use of technologies and strategies to detect and block potentially malicious activities by analyzing the behavior of processes, files, API calls, and other endpoint events.

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1006](https://attack.mitre.org/techniques/T1006) Direct Volume Access · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.009](https://attack.mitre.org/techniques/T1027/009) Embedded Payloads · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.012](https://attack.mitre.org/techniques/T1027/012) LNK Icon Smuggling · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1027.014](https://attack.mitre.org/techniques/T1027/014) Polymorphic Code · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1055.002](https://attack.mitre.org/techniques/T1055/002) Portable Executable Injection · [T1055.003](https://attack.mitre.org/techniques/T1055/003) Thread Execution Hijacking · [T1055.004](https://attack.mitre.org/techniques/T1055/004) Asynchronous Procedure Call · [T1055.005](https://attack.mitre.org/techniques/T1055/005) Thread Local Storage · [T1055.008](https://attack.mitre.org/techniques/T1055/008) Ptrace System Calls · [T1055.009](https://attack.mitre.org/techniques/T1055/009) Proc Memory

---

### M1041 — Encrypt Sensitive Information
<a id="m1041"></a>

**ATT&CK:** [M1041](https://attack.mitre.org/mitigations/M1041) · addresses **33** techniques  

Protect sensitive information at rest, in transit, and during processing by using strong encryption algorithms. Encryption ensures the confidentiality and integrity of data, preventing unauthorized access or tampering.

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS · [T1020.001](https://attack.mitre.org/techniques/T1020/001) Traffic Duplication · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs · [T1070.002](https://attack.mitre.org/techniques/T1070/002) Clear Linux or Mac System Logs · [T1114](https://attack.mitre.org/techniques/T1114) Email Collection · [T1114.001](https://attack.mitre.org/techniques/T1114/001) Local Email Collection · [T1114.002](https://attack.mitre.org/techniques/T1114/002) Remote Email Collection · [T1114.003](https://attack.mitre.org/techniques/T1114/003) Email Forwarding Rule · [T1119](https://attack.mitre.org/techniques/T1119) Automated Collection · [T1213](https://attack.mitre.org/techniques/T1213) Data from Information Repositories · [T1213.006](https://attack.mitre.org/techniques/T1213/006) Databases · [T1530](https://attack.mitre.org/techniques/T1530) Data from Cloud Storage · [T1550.001](https://attack.mitre.org/techniques/T1550/001) Application Access Token · [T1552](https://attack.mitre.org/techniques/T1552) Unsecured Credentials · [T1552.004](https://attack.mitre.org/techniques/T1552/004) Private Keys · [T1557](https://attack.mitre.org/techniques/T1557) Adversary-in-the-Middle · [T1557.002](https://attack.mitre.org/techniques/T1557/002) ARP Cache Poisoning

---

### M1042 — Disable or Remove Feature or Program
<a id="m1042"></a>

**ATT&CK:** [M1042](https://attack.mitre.org/mitigations/M1042) · addresses **71** techniques  

Disable or remove unnecessary and potentially vulnerable software, features, or services to reduce the attack surface and prevent abuse by adversaries. This involves identifying software or features that are no longer needed or that could be exploited and ensuring they are either removed or properly disabled.

**Example techniques:** [T1011](https://attack.mitre.org/techniques/T1011) Exfiltration Over Other Network Medium · [T1011.001](https://attack.mitre.org/techniques/T1011/001) Exfiltration Over Bluetooth · [T1021](https://attack.mitre.org/techniques/T1021) Remote Services · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.003](https://attack.mitre.org/techniques/T1021/003) Distributed Component Object Model · [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH · [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC · [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management · [T1021.008](https://attack.mitre.org/techniques/T1021/008) Direct Cloud VM Connections · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1052](https://attack.mitre.org/techniques/T1052) Exfiltration Over Physical Medium · [T1052.001](https://attack.mitre.org/techniques/T1052/001) Exfiltration over USB · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1091](https://attack.mitre.org/techniques/T1091) Replication Through Removable Media · [T1092](https://attack.mitre.org/techniques/T1092) Communication Through Removable Media · [T1098](https://attack.mitre.org/techniques/T1098) Account Manipulation · [T1098.001](https://attack.mitre.org/techniques/T1098/001) Additional Cloud Credentials

---

### M1043 — Credential Access Protection
<a id="m1043"></a>

**ATT&CK:** [M1043](https://attack.mitre.org/mitigations/M1043) · addresses **10** techniques  

Credential Access Protection focuses on implementing measures to prevent adversaries from obtaining credentials, such as passwords, hashes, tokens, or keys, that could be used for unauthorized access.

**Example techniques:** [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1547.008](https://attack.mitre.org/techniques/T1547/008) LSASS Driver · [T1558](https://attack.mitre.org/techniques/T1558) Steal or Forge Kerberos Tickets · [T1558.005](https://attack.mitre.org/techniques/T1558/005) Ccache Files · [T1599](https://attack.mitre.org/techniques/T1599) Network Boundary Bridging · [T1599.001](https://attack.mitre.org/techniques/T1599/001) Network Address Translation Traversal · [T1601](https://attack.mitre.org/techniques/T1601) Modify System Image · [T1601.001](https://attack.mitre.org/techniques/T1601/001) Patch System Image · [T1601.002](https://attack.mitre.org/techniques/T1601/002) Downgrade System Image

---

### M1044 — Restrict Library Loading
<a id="m1044"></a>

**ATT&CK:** [M1044](https://attack.mitre.org/mitigations/M1044) · addresses **3** techniques  

Restricting library loading involves implementing security controls to ensure that only trusted and verified libraries (DLLs, shared objects, etc.) are loaded into processes. Adversaries often abuse Dynamic-Link Library (DLL) Injection, DLL Search Order Hijacking, or LD_PRELOAD mechanisms to execute malicious code by forcing the operating system to load untrusted libraries.

**Example techniques:** [T1547.008](https://attack.mitre.org/techniques/T1547/008) LSASS Driver · [T1574](https://attack.mitre.org/techniques/T1574) Hijack Execution Flow · [T1574.001](https://attack.mitre.org/techniques/T1574/001) DLL

---

### M1045 — Code Signing
<a id="m1045"></a>

**ATT&CK:** [M1045](https://attack.mitre.org/mitigations/M1045) · addresses **22** techniques  

Code Signing is a security process that ensures the authenticity and integrity of software by digitally signing executables, scripts, and other code artifacts. It prevents untrusted or malicious code from executing by verifying the digital signatures against trusted sources.

**Example techniques:** [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.001](https://attack.mitre.org/techniques/T1036/001) Invalid Code Signature · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.002](https://attack.mitre.org/techniques/T1059/002) AppleScript · [T1127.002](https://attack.mitre.org/techniques/T1127/002) ClickOnce · [T1204.003](https://attack.mitre.org/techniques/T1204/003) Malicious Image · [T1505](https://attack.mitre.org/techniques/T1505) Server Software Component · [T1505.001](https://attack.mitre.org/techniques/T1505/001) SQL Stored Procedures · [T1505.002](https://attack.mitre.org/techniques/T1505/002) Transport Agent · [T1505.004](https://attack.mitre.org/techniques/T1505/004) IIS Components · [T1505.006](https://attack.mitre.org/techniques/T1505/006) vSphere Installation Bundles · [T1525](https://attack.mitre.org/techniques/T1525) Implant Internal Image · [T1543](https://attack.mitre.org/techniques/T1543) Create or Modify System Process · [T1543.003](https://attack.mitre.org/techniques/T1543/003) Windows Service · [T1546.006](https://attack.mitre.org/techniques/T1546/006) LC_LOAD_DYLIB Addition · [T1546.013](https://attack.mitre.org/techniques/T1546/013) PowerShell Profile · [T1554](https://attack.mitre.org/techniques/T1554) Compromise Host Software Binary · [T1601](https://attack.mitre.org/techniques/T1601) Modify System Image

---

### M1046 — Boot Integrity
<a id="m1046"></a>

**ATT&CK:** [M1046](https://attack.mitre.org/mitigations/M1046) · addresses **14** techniques  

Boot Integrity ensures that a system starts securely by verifying the integrity of its boot process, operating system, and associated components. This mitigation focuses on leveraging secure boot mechanisms, hardware-rooted trust, and runtime integrity checks to prevent tampering during the boot sequence.

**Example techniques:** [T1195](https://attack.mitre.org/techniques/T1195) Supply Chain Compromise · [T1195.003](https://attack.mitre.org/techniques/T1195/003) Compromise Hardware Supply Chain · [T1495](https://attack.mitre.org/techniques/T1495) Firmware Corruption · [T1505](https://attack.mitre.org/techniques/T1505) Server Software Component · [T1505.006](https://attack.mitre.org/techniques/T1505/006) vSphere Installation Bundles · [T1542](https://attack.mitre.org/techniques/T1542) Pre-OS Boot · [T1542.001](https://attack.mitre.org/techniques/T1542/001) System Firmware · [T1542.003](https://attack.mitre.org/techniques/T1542/003) Bootkit · [T1542.004](https://attack.mitre.org/techniques/T1542/004) ROMMONkit · [T1542.005](https://attack.mitre.org/techniques/T1542/005) TFTP Boot · [T1553.006](https://attack.mitre.org/techniques/T1553/006) Code Signing Policy Modification · [T1601](https://attack.mitre.org/techniques/T1601) Modify System Image · [T1601.001](https://attack.mitre.org/techniques/T1601/001) Patch System Image · [T1601.002](https://attack.mitre.org/techniques/T1601/002) Downgrade System Image

---

### M1047 — Audit
<a id="m1047"></a>

**ATT&CK:** [M1047](https://attack.mitre.org/mitigations/M1047) · addresses **109** techniques  

Auditing is the process of recording activity and systematically reviewing and analyzing the activity and system configurations. The primary purpose of auditing is to detect anomalies and identify potential threats or weaknesses in the environment. Proper auditing configurations can also help to meet compliance requirements.

**Example techniques:** [T1021](https://attack.mitre.org/techniques/T1021) Remote Services · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.010](https://attack.mitre.org/techniques/T1036/010) Masquerade Account Name · [T1036.012](https://attack.mitre.org/techniques/T1036/012) Browser Fingerprint · [T1053](https://attack.mitre.org/techniques/T1053) Scheduled Task/Job · [T1053.002](https://attack.mitre.org/techniques/T1053/002) At · [T1053.003](https://attack.mitre.org/techniques/T1053/003) Cron · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1059.011](https://attack.mitre.org/techniques/T1059/011) Lua · [T1070.008](https://attack.mitre.org/techniques/T1070/008) Clear Mailbox Data · [T1087.004](https://attack.mitre.org/techniques/T1087/004) Cloud Account · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1114](https://attack.mitre.org/techniques/T1114) Email Collection · [T1114.003](https://attack.mitre.org/techniques/T1114/003) Email Forwarding Rule

---

### M1048 — Application Isolation and Sandboxing
<a id="m1048"></a>

**ATT&CK:** [M1048](https://attack.mitre.org/mitigations/M1048) · addresses **14** techniques  

Application Isolation and Sandboxing refers to the technique of restricting the execution of code to a controlled and isolated environment (e.g., a virtual environment, container, or sandbox). This method prevents potentially malicious code from affecting the rest of the system or network by limiting access to sensitive resources and critical operations.

**Example techniques:** [T1021.003](https://attack.mitre.org/techniques/T1021/003) Distributed Component Object Model · [T1027.006](https://attack.mitre.org/techniques/T1027/006) HTML Smuggling · [T1027.017](https://attack.mitre.org/techniques/T1027/017) SVG Smuggling · [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1189](https://attack.mitre.org/techniques/T1189) Drive-by Compromise · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution · [T1210](https://attack.mitre.org/techniques/T1210) Exploitation of Remote Services · [T1211](https://attack.mitre.org/techniques/T1211) Exploitation for Defense Evasion · [T1212](https://attack.mitre.org/techniques/T1212) Exploitation for Credential Access · [T1559](https://attack.mitre.org/techniques/T1559) Inter-Process Communication · [T1559.001](https://attack.mitre.org/techniques/T1559/001) Component Object Model · [T1559.002](https://attack.mitre.org/techniques/T1559/002) Dynamic Data Exchange · [T1611](https://attack.mitre.org/techniques/T1611) Escape to Host

---

### M1049 — Antivirus/Antimalware
<a id="m1049"></a>

**ATT&CK:** [M1049](https://attack.mitre.org/mitigations/M1049) · addresses **23** techniques  

Antivirus/Antimalware solutions utilize signatures, heuristics, and behavioral analysis to detect, block, and remediate malicious software, including viruses, trojans, ransomware, and spyware. These solutions continuously monitor endpoints and systems for known malicious patterns and suspicious behaviors that indicate compromise.

**Example techniques:** [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.009](https://attack.mitre.org/techniques/T1027/009) Embedded Payloads · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.012](https://attack.mitre.org/techniques/T1027/012) LNK Icon Smuggling · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1027.014](https://attack.mitre.org/techniques/T1027/014) Polymorphic Code · [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression · [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1080](https://attack.mitre.org/techniques/T1080) Taint Shared Content · [T1221](https://attack.mitre.org/techniques/T1221) Template Injection · [T1547.006](https://attack.mitre.org/techniques/T1547/006) Kernel Modules and Extensions · [T1564](https://attack.mitre.org/techniques/T1564) Hide Artifacts · [T1564.012](https://attack.mitre.org/techniques/T1564/012) File/Path Exclusions

---

### M1050 — Exploit Protection
<a id="m1050"></a>

**ATT&CK:** [M1050](https://attack.mitre.org/mitigations/M1050) · addresses **12** techniques  

Deploy capabilities that detect, block, and mitigate conditions indicative of software exploits. These capabilities aim to prevent exploitation by addressing vulnerabilities, monitoring anomalous behaviors, and applying exploit-mitigation techniques to harden systems and software.

**Example techniques:** [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1080](https://attack.mitre.org/techniques/T1080) Taint Shared Content · [T1189](https://attack.mitre.org/techniques/T1189) Drive-by Compromise · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution · [T1210](https://attack.mitre.org/techniques/T1210) Exploitation of Remote Services · [T1211](https://attack.mitre.org/techniques/T1211) Exploitation for Defense Evasion · [T1212](https://attack.mitre.org/techniques/T1212) Exploitation for Credential Access · [T1218](https://attack.mitre.org/techniques/T1218) System Binary Proxy Execution · [T1218.010](https://attack.mitre.org/techniques/T1218/010) Regsvr32 · [T1218.011](https://attack.mitre.org/techniques/T1218/011) Rundll32 · [T1218.015](https://attack.mitre.org/techniques/T1218/015) Electron Applications

---

### M1051 — Update Software
<a id="m1051"></a>

**ATT&CK:** [M1051](https://attack.mitre.org/mitigations/M1051) · addresses **42** techniques  

Software updates ensure systems are protected against known vulnerabilities by applying patches and upgrades provided by vendors. Regular updates reduce the attack surface and prevent adversaries from exploiting known security gaps. This includes patching operating systems, applications, drivers, and firmware.

**Example techniques:** [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1110.001](https://attack.mitre.org/techniques/T1110/001) Password Guessing · [T1137](https://attack.mitre.org/techniques/T1137) Office Application Startup · [T1137.003](https://attack.mitre.org/techniques/T1137/003) Outlook Forms · [T1137.004](https://attack.mitre.org/techniques/T1137/004) Outlook Home Page · [T1137.005](https://attack.mitre.org/techniques/T1137/005) Outlook Rules · [T1176](https://attack.mitre.org/techniques/T1176) Software Extensions · [T1176.001](https://attack.mitre.org/techniques/T1176/001) Browser Extensions · [T1176.002](https://attack.mitre.org/techniques/T1176/002) IDE Extensions · [T1189](https://attack.mitre.org/techniques/T1189) Drive-by Compromise · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1195](https://attack.mitre.org/techniques/T1195) Supply Chain Compromise · [T1195.001](https://attack.mitre.org/techniques/T1195/001) Compromise Software Dependencies and Development Tools · [T1195.002](https://attack.mitre.org/techniques/T1195/002) Compromise Software Supply Chain · [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution · [T1210](https://attack.mitre.org/techniques/T1210) Exploitation of Remote Services · [T1211](https://attack.mitre.org/techniques/T1211) Exploitation for Defense Evasion · [T1212](https://attack.mitre.org/techniques/T1212) Exploitation for Credential Access · [T1495](https://attack.mitre.org/techniques/T1495) Firmware Corruption

---

### M1052 — User Account Control
<a id="m1052"></a>

**ATT&CK:** [M1052](https://attack.mitre.org/mitigations/M1052) · addresses **7** techniques  

User Account Control (UAC) is a security feature in Microsoft Windows that prevents unauthorized changes to the operating system. UAC prompts users to confirm or provide administrator credentials when an action requires elevated privileges. Proper configuration of UAC reduces the risk of privilege escalation attacks.

**Example techniques:** [T1546.011](https://attack.mitre.org/techniques/T1546/011) Application Shimming · [T1548](https://attack.mitre.org/techniques/T1548) Abuse Elevation Control Mechanism · [T1548.002](https://attack.mitre.org/techniques/T1548/002) Bypass User Account Control · [T1550.002](https://attack.mitre.org/techniques/T1550/002) Pass the Hash · [T1574](https://attack.mitre.org/techniques/T1574) Hijack Execution Flow · [T1574.005](https://attack.mitre.org/techniques/T1574/005) Executable Installer File Permissions Weakness · [T1574.010](https://attack.mitre.org/techniques/T1574/010) Services File Permissions Weakness

---

### M1053 — Data Backup
<a id="m1053"></a>

**ATT&CK:** [M1053](https://attack.mitre.org/mitigations/M1053) · addresses **10** techniques  

Data Backup involves taking and securely storing backups of data from end-user systems and critical servers. It ensures that data remains available in the event of system compromise, ransomware attacks, or other disruptions.

**Example techniques:** [T1485](https://attack.mitre.org/techniques/T1485) Data Destruction · [T1485.001](https://attack.mitre.org/techniques/T1485/001) Lifecycle-Triggered Deletion · [T1486](https://attack.mitre.org/techniques/T1486) Data Encrypted for Impact · [T1490](https://attack.mitre.org/techniques/T1490) Inhibit System Recovery · [T1491](https://attack.mitre.org/techniques/T1491) Defacement · [T1491.001](https://attack.mitre.org/techniques/T1491/001) Internal Defacement · [T1491.002](https://attack.mitre.org/techniques/T1491/002) External Defacement · [T1561](https://attack.mitre.org/techniques/T1561) Disk Wipe · [T1561.001](https://attack.mitre.org/techniques/T1561/001) Disk Content Wipe · [T1561.002](https://attack.mitre.org/techniques/T1561/002) Disk Structure Wipe

---

### M1054 — Software Configuration
<a id="m1054"></a>

**ATT&CK:** [M1054](https://attack.mitre.org/mitigations/M1054) · addresses **37** techniques  

Software configuration refers to making security-focused adjustments to the settings of applications, middleware, databases, or other software to mitigate potential threats. These changes help reduce the attack surface, enforce best practices, and protect sensitive data.

**Example techniques:** [T1137](https://attack.mitre.org/techniques/T1137) Office Application Startup · [T1137.002](https://attack.mitre.org/techniques/T1137/002) Office Test · [T1213](https://attack.mitre.org/techniques/T1213) Data from Information Repositories · [T1213.004](https://attack.mitre.org/techniques/T1213/004) Customer Relationship Management Software · [T1213.006](https://attack.mitre.org/techniques/T1213/006) Databases · [T1535](https://attack.mitre.org/techniques/T1535) Unused/Unsupported Cloud Regions · [T1537](https://attack.mitre.org/techniques/T1537) Transfer Data to Cloud Account · [T1539](https://attack.mitre.org/techniques/T1539) Steal Web Session Cookie · [T1543](https://attack.mitre.org/techniques/T1543) Create or Modify System Process · [T1543.005](https://attack.mitre.org/techniques/T1543/005) Container Service · [T1546.013](https://attack.mitre.org/techniques/T1546/013) PowerShell Profile · [T1550.004](https://attack.mitre.org/techniques/T1550/004) Web Session Cookie · [T1553](https://attack.mitre.org/techniques/T1553) Subvert Trust Controls · [T1553.004](https://attack.mitre.org/techniques/T1553/004) Install Root Certificate · [T1555.005](https://attack.mitre.org/techniques/T1555/005) Password Managers · [T1559](https://attack.mitre.org/techniques/T1559) Inter-Process Communication · [T1559.002](https://attack.mitre.org/techniques/T1559/002) Dynamic Data Exchange · [T1562](https://attack.mitre.org/techniques/T1562) Impair Defenses · [T1562.006](https://attack.mitre.org/techniques/T1562/006) Indicator Blocking · [T1562.009](https://attack.mitre.org/techniques/T1562/009) Safe Mode Boot

---

### M1055 — Do Not Mitigate
<a id="m1055"></a>

**ATT&CK:** [M1055](https://attack.mitre.org/mitigations/M1055) · addresses **3** techniques  

The Do Not Mitigate category highlights scenarios where attempting to mitigate a specific technique may inadvertently increase the organization's security risk or operational instability. This could happen due to the complexity of the system, the integration of critical processes, or the potential for introducing new vulnerabilities.

**Example techniques:** [T1480](https://attack.mitre.org/techniques/T1480) Execution Guardrails · [T1480.001](https://attack.mitre.org/techniques/T1480/001) Environmental Keying · [T1480.002](https://attack.mitre.org/techniques/T1480/002) Mutual Exclusion

---

### M1056 — Pre-compromise
<a id="m1056"></a>

**ATT&CK:** [M1056](https://attack.mitre.org/mitigations/M1056) · addresses **84** techniques  

Pre-compromise mitigations involve proactive measures and defenses implemented to prevent adversaries from successfully identifying and exploiting weaknesses during the Reconnaissance and Resource Development phases of an attack.

**Example techniques:** [T1583](https://attack.mitre.org/techniques/T1583) Acquire Infrastructure · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1583.002](https://attack.mitre.org/techniques/T1583/002) DNS Server · [T1583.003](https://attack.mitre.org/techniques/T1583/003) Virtual Private Server · [T1583.004](https://attack.mitre.org/techniques/T1583/004) Server · [T1583.005](https://attack.mitre.org/techniques/T1583/005) Botnet · [T1583.006](https://attack.mitre.org/techniques/T1583/006) Web Services · [T1583.007](https://attack.mitre.org/techniques/T1583/007) Serverless · [T1583.008](https://attack.mitre.org/techniques/T1583/008) Malvertising · [T1584](https://attack.mitre.org/techniques/T1584) Compromise Infrastructure · [T1584.001](https://attack.mitre.org/techniques/T1584/001) Domains · [T1584.002](https://attack.mitre.org/techniques/T1584/002) DNS Server · [T1584.003](https://attack.mitre.org/techniques/T1584/003) Virtual Private Server · [T1584.004](https://attack.mitre.org/techniques/T1584/004) Server · [T1584.005](https://attack.mitre.org/techniques/T1584/005) Botnet · [T1584.006](https://attack.mitre.org/techniques/T1584/006) Web Services · [T1584.007](https://attack.mitre.org/techniques/T1584/007) Serverless · [T1584.008](https://attack.mitre.org/techniques/T1584/008) Network Devices · [T1585](https://attack.mitre.org/techniques/T1585) Establish Accounts · [T1585.001](https://attack.mitre.org/techniques/T1585/001) Social Media Accounts

---

### M1057 — Data Loss Prevention
<a id="m1057"></a>

**ATT&CK:** [M1057](https://attack.mitre.org/mitigations/M1057) · addresses **12** techniques  

Data Loss Prevention (DLP) involves implementing strategies and technologies to identify, categorize, monitor, and control the movement of sensitive data within an organization. This includes protecting data formats indicative of Personally Identifiable Information (PII), intellectual property, or financial data from unauthorized access, transmission, or exfiltration.

**Example techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1020.001](https://attack.mitre.org/techniques/T1020/001) Traffic Duplication · [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1048](https://attack.mitre.org/techniques/T1048) Exfiltration Over Alternative Protocol · [T1048.002](https://attack.mitre.org/techniques/T1048/002) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1052](https://attack.mitre.org/techniques/T1052) Exfiltration Over Physical Medium · [T1052.001](https://attack.mitre.org/techniques/T1052/001) Exfiltration over USB · [T1537](https://attack.mitre.org/techniques/T1537) Transfer Data to Cloud Account · [T1567](https://attack.mitre.org/techniques/T1567) Exfiltration Over Web Service · [T1567.004](https://attack.mitre.org/techniques/T1567/004) Exfiltration Over Webhook

---

### M1060 — Out-of-Band Communications Channel
<a id="m1060"></a>

**ATT&CK:** [M1060](https://attack.mitre.org/mitigations/M1060) · addresses **7** techniques  

Establish secure out-of-band communication channels to ensure the continuity of critical communications during security incidents, data integrity attacks, or in-network communication failures. Out-of-band communication refers to using an alternative, separate communication path that is not dependent on the potentially compromised primary network infrastructure.

**Example techniques:** [T1114](https://attack.mitre.org/techniques/T1114) Email Collection · [T1114.001](https://attack.mitre.org/techniques/T1114/001) Local Email Collection · [T1114.002](https://attack.mitre.org/techniques/T1114/002) Remote Email Collection · [T1114.003](https://attack.mitre.org/techniques/T1114/003) Email Forwarding Rule · [T1213](https://attack.mitre.org/techniques/T1213) Data from Information Repositories · [T1213.005](https://attack.mitre.org/techniques/T1213/005) Messaging Applications · [T1489](https://attack.mitre.org/techniques/T1489) Service Stop

---

