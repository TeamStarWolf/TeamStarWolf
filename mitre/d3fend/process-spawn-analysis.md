# D3FEND: Process Spawn Analysis

<a id="process-spawn-analysis"></a>

**D3FEND tactic:** Detect
**Digital artifacts:** Process, Create Process

Analyzing spawn arguments or attributes of a process to detect processes that are unauthorized.

## ATT&CK techniques countered (48)

- [T0806](https://attack.mitre.org/techniques/T0806) — analyzes
- [T0813](https://attack.mitre.org/techniques/T0813) — analyzes
- [T0814](https://attack.mitre.org/techniques/T0814) — analyzes
- [T0819](https://attack.mitre.org/techniques/T0819) — analyzes
- [T0821](https://attack.mitre.org/techniques/T0821) — analyzes
- [T0823](https://attack.mitre.org/techniques/T0823) — analyzes
- [T0846](https://attack.mitre.org/techniques/T0846) — analyzes
- [T0863](https://attack.mitre.org/techniques/T0863) — analyzes
- [T0878](https://attack.mitre.org/techniques/T0878) — analyzes
- [T0888](https://attack.mitre.org/techniques/T0888) — analyzes
- [T0894](https://attack.mitre.org/techniques/T0894) — analyzes
- [T0895](https://attack.mitre.org/techniques/T0895) — analyzes
- [T1003.001 — LSASS Memory](/mitre/techniques/T1003-001.md) — analyzes. Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).
- [T1003.002 — Security Account Manager](/mitre/techniques/T1003-002.md) — analyzes. Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.
- [T1003.004 — LSA Secrets](/mitre/techniques/T1003-004.md) — analyzes. Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.
- [T1007 — System Service Discovery](/mitre/techniques/T1007.md) — analyzes. Adversaries may try to gather information about registered local system services.
- [T1010 — Application Window Discovery](/mitre/techniques/T1010.md) — analyzes. Adversaries may attempt to get a listing of open application windows.
- [T1016 — System Network Configuration Discovery](/mitre/techniques/T1016.md) — analyzes. Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems.
- [T1018 — Remote System Discovery](/mitre/techniques/T1018.md) — analyzes. Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.
- [T1033 — System Owner/User Discovery](/mitre/techniques/T1033.md) — analyzes. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1047 — Windows Management Instrumentation](/mitre/techniques/T1047.md) — analyzes. Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
- [T1053 — Scheduled Task/Job](/mitre/techniques/T1053.md) — analyzes. Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- [T1053.005 — Scheduled Task](/mitre/techniques/T1053-005.md) — analyzes. Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.
- [T1055.004 — Asynchronous Procedure Call](/mitre/techniques/T1055-004.md) — analyzes. Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges.
- [T1055.013 — Process Doppelgänging](/mitre/techniques/T1055-013.md) — analyzes. Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges.
- [T1057 — Process Discovery](/mitre/techniques/T1057.md) — analyzes. Adversaries may attempt to get information about running processes on a system.
- [T1082 — System Information Discovery](/mitre/techniques/T1082.md) — analyzes. An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.
- [T1124 — System Time Discovery](/mitre/techniques/T1124.md) — analyzes. An adversary may gather the system time and/or time zone settings from a local or remote system.
- [T1134.004 — Parent PID Spoofing](/mitre/techniques/T1134-004.md) — analyzes. Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges.
- [T1140 — Deobfuscate/Decode Files or Information](/mitre/techniques/T1140.md) — analyzes. Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.
- [T1212 — Exploitation for Credential Access](/mitre/techniques/T1212.md) — analyzes. Adversaries may exploit software vulnerabilities in an attempt to collect credentials.
- [T1218.001 — Compiled HTML File](/mitre/techniques/T1218-001.md) — analyzes. Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code.
- [T1218.002 — Control Panel](/mitre/techniques/T1218-002.md) — analyzes. Adversaries may abuse control.exe to proxy execution of malicious payloads.
- [T1218.003 — CMSTP](/mitre/techniques/T1218-003.md) — analyzes. Adversaries may abuse CMSTP to proxy execution of malicious code.
- [T1218.005 — Mshta](/mitre/techniques/T1218-005.md) — analyzes. Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility.
- [T1218.011 — Rundll32](/mitre/techniques/T1218-011.md) — analyzes. Adversaries may abuse rundll32.exe to proxy execution of malicious code.
- [T1220 — XSL Script Processing](/mitre/techniques/T1220.md) — analyzes. Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files.
- [T1505.001 — SQL Stored Procedures](/mitre/techniques/T1505-001.md) — analyzes. Adversaries may abuse SQL stored procedures to establish persistent access to systems.
- [T1505.002 — Transport Agent](/mitre/techniques/T1505-002.md) — analyzes. Adversaries may abuse Microsoft transport agents to establish persistent access to systems.
- [T1505.003 — Web Shell](/mitre/techniques/T1505-003.md) — analyzes. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1546.007 — Netsh Helper DLL](/mitre/techniques/T1546-007.md) — analyzes. Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs.
- [T1546.009 — AppCert DLLs](/mitre/techniques/T1546-009.md) — analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes.
- [T1546.010 — AppInit DLLs](/mitre/techniques/T1546-010.md) — analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes.
- [T1548.002 — Bypass User Account Control](/mitre/techniques/T1548-002.md) — analyzes. Adversaries may bypass UAC mechanisms to elevate process privileges on system.
- [T1550 — Use Alternate Authentication Material](/mitre/techniques/T1550.md) — analyzes. Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.
- [T1556 — Modify Authentication Process](/mitre/techniques/T1556.md) — analyzes. Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.
- [T1562.001 — Disable or Modify Tools](/mitre/techniques/T1562-001.md) — analyzes. Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.
- [T1621 — Multi-Factor Authentication Request Generation](/mitre/techniques/T1621.md) — analyzes. Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
