# D3FEND: Executable Allowlisting

<a id="executable-allowlisting"></a>

**D3FEND tactic:** Isolate
**Digital artifacts:** Create Process, Executable File

Using a digital signature to authenticate a file before opening.

## ATT&CK techniques countered (58)

- [T0846](https://attack.mitre.org/techniques/T0846) — filters
- [T0853](https://attack.mitre.org/techniques/T0853) — blocks
- [T0863](https://attack.mitre.org/techniques/T0863) — filters
- [T0871](https://attack.mitre.org/techniques/T0871) — blocks
- [T0888](https://attack.mitre.org/techniques/T0888) — filters
- [T0894](https://attack.mitre.org/techniques/T0894) — blocks, filters
- [T0895](https://attack.mitre.org/techniques/T0895) — blocks, filters
- [T1007 — System Service Discovery](/mitre/techniques/T1007.md) — filters. Adversaries may try to gather information about registered local system services.
- [T1010 — Application Window Discovery](/mitre/techniques/T1010.md) — filters. Adversaries may attempt to get a listing of open application windows.
- [T1016 — System Network Configuration Discovery](/mitre/techniques/T1016.md) — blocks, filters. Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems.
- [T1018 — Remote System Discovery](/mitre/techniques/T1018.md) — filters. Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.
- [T1027.001 — Binary Padding](/mitre/techniques/T1027-001.md) — blocks. Adversaries may use binary padding to add junk data and change the on-disk representation of malware.
- [T1027.002 — Software Packing](/mitre/techniques/T1027-002.md) — blocks. Adversaries may perform software packing or virtual machine software protection to conceal their code.
- [T1027.004 — Compile After Delivery](/mitre/techniques/T1027-004.md) — blocks. Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code.
- [T1033 — System Owner/User Discovery](/mitre/techniques/T1033.md) — filters. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1036.001 — Invalid Code Signature](/mitre/techniques/T1036-001.md) — blocks. Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool.
- [T1036.003 — Rename Legitimate Utilities](/mitre/techniques/T1036-003.md) — blocks. Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities.
- [T1037.001 — Logon Script (Windows)](/mitre/techniques/T1037-001.md) — blocks. Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence.
- [T1037.002 — Login Hook](/mitre/techniques/T1037-002.md) — blocks. Adversaries may use a Login Hook to establish persistence executed upon user logon.
- [T1037.003 — Network Logon Script](/mitre/techniques/T1037-003.md) — blocks. Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence.
- [T1037.004 — RC Scripts](/mitre/techniques/T1037-004.md) — blocks. Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup.
- [T1047 — Windows Management Instrumentation](/mitre/techniques/T1047.md) — filters. Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
- [T1053 — Scheduled Task/Job](/mitre/techniques/T1053.md) — filters. Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- [T1055.003 — Thread Execution Hijacking](/mitre/techniques/T1055-003.md) — blocks. Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges.
- [T1055.004 — Asynchronous Procedure Call](/mitre/techniques/T1055-004.md) — filters. Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges.
- [T1055.013 — Process Doppelgänging](/mitre/techniques/T1055-013.md) — filters. Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges.
- [T1057 — Process Discovery](/mitre/techniques/T1057.md) — filters. Adversaries may attempt to get information about running processes on a system.
- [T1059 — Command and Scripting Interpreter](/mitre/techniques/T1059.md) — blocks. Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.
- [T1082 — System Information Discovery](/mitre/techniques/T1082.md) — filters. An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.
- [T1124 — System Time Discovery](/mitre/techniques/T1124.md) — filters. An adversary may gather the system time and/or time zone settings from a local or remote system.
- [T1134.004 — Parent PID Spoofing](/mitre/techniques/T1134-004.md) — filters. Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges.
- [T1137.001 — Office Template Macros](/mitre/techniques/T1137-001.md) — blocks. Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system.
- [T1140 — Deobfuscate/Decode Files or Information](/mitre/techniques/T1140.md) — blocks, filters. Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.
- [T1204.002 — Malicious File](/mitre/techniques/T1204-002.md) — blocks. An adversary may rely upon a user opening a malicious file in order to gain execution.
- [T1218.001 — Compiled HTML File](/mitre/techniques/T1218-001.md) — filters. Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code.
- [T1218.002 — Control Panel](/mitre/techniques/T1218-002.md) — filters. Adversaries may abuse control.exe to proxy execution of malicious payloads.
- [T1218.003 — CMSTP](/mitre/techniques/T1218-003.md) — filters. Adversaries may abuse CMSTP to proxy execution of malicious code.
- [T1218.005 — Mshta](/mitre/techniques/T1218-005.md) — filters. Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility.
- [T1218.011 — Rundll32](/mitre/techniques/T1218-011.md) — filters. Adversaries may abuse rundll32.exe to proxy execution of malicious code.
- [T1220 — XSL Script Processing](/mitre/techniques/T1220.md) — blocks, filters. Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files.
- [T1505.001 — SQL Stored Procedures](/mitre/techniques/T1505-001.md) — filters. Adversaries may abuse SQL stored procedures to establish persistent access to systems.
- [T1505.003 — Web Shell](/mitre/techniques/T1505-003.md) — blocks. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1546.002 — Screensaver](/mitre/techniques/T1546-002.md) — blocks. Adversaries may establish persistence by executing malicious content triggered by user inactivity.
- [T1546.005 — Trap](/mitre/techniques/T1546-005.md) — blocks. Adversaries may establish persistence by executing malicious content triggered by an interrupt signal.
- [T1546.006 — LC_LOAD_DYLIB Addition](/mitre/techniques/T1546-006.md) — blocks. Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries.
- [T1546.008 — Accessibility Features](/mitre/techniques/T1546-008.md) — blocks. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.
- [T1546.009 — AppCert DLLs](/mitre/techniques/T1546-009.md) — filters. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes.
- [T1546.010 — AppInit DLLs](/mitre/techniques/T1546-010.md) — filters. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes.
- [T1546.013 — PowerShell Profile](/mitre/techniques/T1546-013.md) — blocks. Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles.
- [T1546.015 — Component Object Model Hijacking](/mitre/techniques/T1546-015.md) — blocks. Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects.
- [T1547.001 — Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md) — blocks. Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.
- [T1547.009 — Shortcut Modification](/mitre/techniques/T1547-009.md) — blocks. Adversaries may create or modify shortcuts that can execute a program during system boot or user login.
- [T1548.002 — Bypass User Account Control](/mitre/techniques/T1548-002.md) — blocks, filters. Adversaries may bypass UAC mechanisms to elevate process privileges on system.
- [T1562.003 — Impair Command History Logging](/mitre/techniques/T1562-003.md) — blocks. Adversaries may impair command history logging to hide commands they run on a compromised system.
- [T1565.003 — Runtime Data Manipulation](/mitre/techniques/T1565-003.md) — blocks. Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data.
- [T1574.007 — Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md) — blocks. Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries.
- [T1574.008 — Path Interception by Search Order Hijacking](/mitre/techniques/T1574-008.md) — blocks. Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs.
- [T1574.009 — Path Interception by Unquoted Path](/mitre/techniques/T1574-009.md) — blocks. Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
