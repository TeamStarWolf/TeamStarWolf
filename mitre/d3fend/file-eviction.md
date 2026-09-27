# D3FEND: File Eviction

<a id="file-eviction"></a>

**D3FEND tactic:** Evict  
**Digital artifacts:** File  

File eviction techniques delete files from system storage.

## ATT&CK techniques countered (107)

- [T0851](https://attack.mitre.org/techniques/T0851) — deletes
- [T0853](https://attack.mitre.org/techniques/T0853) — deletes
- [T0865](https://attack.mitre.org/techniques/T0865) — deletes
- [T0871](https://attack.mitre.org/techniques/T0871) — deletes
- [T0888](https://attack.mitre.org/techniques/T0888) — deletes
- [T0893](https://attack.mitre.org/techniques/T0893) — deletes
- [T0894](https://attack.mitre.org/techniques/T0894) — deletes
- [T0895](https://attack.mitre.org/techniques/T0895) — deletes
- [T1003.007 — Proc Filesystem](/mitre/techniques/T1003-007.md) — deletes. Adversaries may gather credentials from the proc filesystem or `/proc`.
- [T1003.008 — /etc/passwd and /etc/shadow](/mitre/techniques/T1003-008.md) — deletes. Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking.
- [T1005 — Data from Local System](/mitre/techniques/T1005.md) — deletes. Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration.
- [T1014 — Rootkit](/mitre/techniques/T1014.md) — deletes. Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.
- [T1016 — System Network Configuration Discovery](/mitre/techniques/T1016.md) — deletes. Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems.
- [T1018 — Remote System Discovery](/mitre/techniques/T1018.md) — deletes. Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.
- [T1027.001 — Binary Padding](/mitre/techniques/T1027-001.md) — deletes. Adversaries may use binary padding to add junk data and change the on-disk representation of malware.
- [T1027.002 — Software Packing](/mitre/techniques/T1027-002.md) — deletes. Adversaries may perform software packing or virtual machine software protection to conceal their code.
- [T1027.004 — Compile After Delivery](/mitre/techniques/T1027-004.md) — deletes. Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code.
- [T1033 — System Owner/User Discovery](/mitre/techniques/T1033.md) — deletes. Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.
- [T1036.001 — Invalid Code Signature](/mitre/techniques/T1036-001.md) — deletes. Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool.
- [T1036.003 — Rename Legitimate Utilities](/mitre/techniques/T1036-003.md) — deletes. Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities.
- [T1036.005 — Match Legitimate Resource Name or Location](/mitre/techniques/T1036-005.md) — deletes. Adversaries may match or approximate the name or location of legitimate files, Registry keys, or other resources when naming/placing them.
- [T1036.006 — Space after Filename](/mitre/techniques/T1036-006.md) — deletes. Adversaries can hide a program's true filetype by changing the extension of a file.
- [T1037.001 — Logon Script (Windows)](/mitre/techniques/T1037-001.md) — deletes. Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence.
- [T1037.002 — Login Hook](/mitre/techniques/T1037-002.md) — deletes. Adversaries may use a Login Hook to establish persistence executed upon user logon.
- [T1037.003 — Network Logon Script](/mitre/techniques/T1037-003.md) — deletes. Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence.
- [T1037.004 — RC Scripts](/mitre/techniques/T1037-004.md) — deletes. Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup.
- [T1041 — Exfiltration Over C2 Channel](/mitre/techniques/T1041.md) — deletes. Adversaries may steal data by exfiltrating it over an existing command and control channel.
- [T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](/mitre/techniques/T1048-002.md) — deletes. Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel.
- `T1053.004` — deletes
- [T1055.001 — Dynamic-link Library Injection](/mitre/techniques/T1055-001.md) — deletes. Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges.
- [T1055.002 — Portable Executable Injection](/mitre/techniques/T1055-002.md) — deletes. Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges.
- [T1055.003 — Thread Execution Hijacking](/mitre/techniques/T1055-003.md) — deletes. Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges.
- [T1055.009 — Proc Memory](/mitre/techniques/T1055-009.md) — deletes. Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges.
- [T1055.014 — VDSO Hijacking](/mitre/techniques/T1055-014.md) — deletes. Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges.
- [T1059 — Command and Scripting Interpreter](/mitre/techniques/T1059.md) — deletes. Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.
- [T1070.002 — Clear Linux or Mac System Logs](/mitre/techniques/T1070-002.md) — deletes. Adversaries may clear system logs to hide evidence of an intrusion.
- [T1070.004 — File Deletion](/mitre/techniques/T1070-004.md) — deletes. Adversaries may delete files left behind by the actions of their intrusion activity.
- [T1071 — Application Layer Protocol](/mitre/techniques/T1071.md) — deletes. Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.
- [T1071.001 — Web Protocols](/mitre/techniques/T1071-001.md) — deletes. Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
- [T1072 — Software Deployment Tools](/mitre/techniques/T1072.md) — deletes. Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network.
- [T1074.001 — Local Data Staging](/mitre/techniques/T1074-001.md) — deletes. Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration.
- [T1083 — File and Directory Discovery](/mitre/techniques/T1083.md) — deletes. Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.
- [T1114.001 — Local Email Collection](/mitre/techniques/T1114-001.md) — deletes. Adversaries may target user email on local systems to collect sensitive information.
- [T1119 — Automated Collection](/mitre/techniques/T1119.md) — deletes. Once established within a system or network, an adversary may use automated techniques for collecting internal data.
- [T1127.001 — MSBuild](/mitre/techniques/T1127-001.md) — deletes. Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility.
- [T1137.001 — Office Template Macros](/mitre/techniques/T1137-001.md) — deletes. Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system.
- [T1137.003 — Outlook Forms](/mitre/techniques/T1137-003.md) — deletes. Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system.
- [T1140 — Deobfuscate/Decode Files or Information](/mitre/techniques/T1140.md) — deletes. Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis.
- [T1187 — Forced Authentication](/mitre/techniques/T1187.md) — deletes. Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.
- [T1204.002 — Malicious File](/mitre/techniques/T1204-002.md) — deletes. An adversary may rely upon a user opening a malicious file in order to gain execution.
- [T1218.005 — Mshta](/mitre/techniques/T1218-005.md) — deletes. Adversaries may abuse mshta.exe to proxy execution of malicious.hta files and Javascript or VBScript through a trusted Windows utility.
- [T1218.011 — Rundll32](/mitre/techniques/T1218-011.md) — deletes. Adversaries may abuse rundll32.exe to proxy execution of malicious code.
- [T1220 — XSL Script Processing](/mitre/techniques/T1220.md) — deletes. Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files.
- [T1486 — Data Encrypted for Impact](/mitre/techniques/T1486.md) — deletes. Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.
- [T1505.003 — Web Shell](/mitre/techniques/T1505-003.md) — deletes. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1534 — Internal Spearphishing](/mitre/techniques/T1534.md) — deletes. After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization.
- [T1543.001 — Launch Agent](/mitre/techniques/T1543-001.md) — deletes. Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence.
- [T1543.002 — Systemd Service](/mitre/techniques/T1543-002.md) — deletes. Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence.
- [T1543.004 — Launch Daemon](/mitre/techniques/T1543-004.md) — deletes. Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence.
- [T1546.002 — Screensaver](/mitre/techniques/T1546-002.md) — deletes. Adversaries may establish persistence by executing malicious content triggered by user inactivity.
- [T1546.004 — Unix Shell Configuration Modification](/mitre/techniques/T1546-004.md) — deletes. Adversaries may establish persistence through executing malicious commands triggered by a user’s shell.
- [T1546.005 — Trap](/mitre/techniques/T1546-005.md) — deletes. Adversaries may establish persistence by executing malicious content triggered by an interrupt signal.
- [T1546.006 — LC_LOAD_DYLIB Addition](/mitre/techniques/T1546-006.md) — deletes. Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries.
- [T1546.008 — Accessibility Features](/mitre/techniques/T1546-008.md) — deletes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.
- [T1546.009 — AppCert DLLs](/mitre/techniques/T1546-009.md) — deletes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes.
- [T1546.010 — AppInit DLLs](/mitre/techniques/T1546-010.md) — deletes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes.
- [T1546.013 — PowerShell Profile](/mitre/techniques/T1546-013.md) — deletes. Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles.
- [T1546.014 — Emond](/mitre/techniques/T1546-014.md) — deletes. Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond).
- [T1546.015 — Component Object Model Hijacking](/mitre/techniques/T1546-015.md) — deletes. Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects.
- [T1547.001 — Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md) — deletes. Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.
- [T1547.006 — Kernel Modules and Extensions](/mitre/techniques/T1547-006.md) — deletes. Adversaries may modify the kernel to automatically execute programs on system boot.
- [T1547.007 — Re-opened Applications](/mitre/techniques/T1547-007.md) — deletes. Adversaries may modify plist files to automatically run an application when a user logs in.
- [T1547.008 — LSASS Driver](/mitre/techniques/T1547-008.md) — deletes. Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems.
- [T1547.009 — Shortcut Modification](/mitre/techniques/T1547-009.md) — deletes. Adversaries may create or modify shortcuts that can execute a program during system boot or user login.
- `T1547.011` — deletes
- [T1548.002 — Bypass User Account Control](/mitre/techniques/T1548-002.md) — deletes. Adversaries may bypass UAC mechanisms to elevate process privileges on system.
- [T1548.003 — Sudo and Sudo Caching](/mitre/techniques/T1548-003.md) — deletes. Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges.
- [T1552.001 — Credentials In Files](/mitre/techniques/T1552-001.md) — deletes. Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.
- [T1552.003 — Shell History](/mitre/techniques/T1552-003.md) — deletes. Adversaries may search the command history on compromised systems for insecurely stored credentials.
- [T1555 — Credentials from Password Stores](/mitre/techniques/T1555.md) — deletes. Adversaries may search for common password storage locations to obtain user credentials.
- [T1555.003 — Credentials from Web Browsers](/mitre/techniques/T1555-003.md) — deletes. Adversaries may acquire credentials from web browsers by reading files specific to the target browser.
- [T1556.002 — Password Filter DLL](/mitre/techniques/T1556-002.md) — deletes. Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated.
- [T1556.003 — Pluggable Authentication Modules](/mitre/techniques/T1556-003.md) — deletes. Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts.
- [T1560 — Archive Collected Data](/mitre/techniques/T1560.md) — deletes. An adversary may compress and/or encrypt data that is collected prior to exfiltration.
- [T1560.001 — Archive via Utility](/mitre/techniques/T1560-001.md) — deletes. Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration.
- [T1560.002 — Archive via Library](/mitre/techniques/T1560-002.md) — deletes. An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries.
- [T1560.003 — Archive via Custom Method](/mitre/techniques/T1560-003.md) — deletes. An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method.
- [T1562.003 — Impair Command History Logging](/mitre/techniques/T1562-003.md) — deletes. Adversaries may impair command history logging to hide commands they run on a compromised system.
- [T1564.002 — Hidden Users](/mitre/techniques/T1564-002.md) — deletes. Adversaries may use hidden users to hide the presence of user accounts they create or modify.
- [T1564.003 — Hidden Window](/mitre/techniques/T1564-003.md) — deletes. Adversaries may use hidden windows to conceal malicious activity from the plain sight of users.
- [T1564.006 — Run Virtual Instance](/mitre/techniques/T1564-006.md) — deletes. Adversaries may carry out malicious operations using a virtual instance to avoid detection.
- [T1564.007 — VBA Stomping](/mitre/techniques/T1564-007.md) — deletes. Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data.
- [T1565.001 — Stored Data Manipulation](/mitre/techniques/T1565-001.md) — deletes. Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data.
- [T1565.003 — Runtime Data Manipulation](/mitre/techniques/T1565-003.md) — deletes. Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data.
- [T1566.001 — Spearphishing Attachment](/mitre/techniques/T1566-001.md) — deletes. Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002 — Spearphishing Link](/mitre/techniques/T1566-002.md) — deletes. Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.
- [T1566.003 — Spearphishing via Service](/mitre/techniques/T1566-003.md) — deletes. Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems.
- [T1573.002 — Asymmetric Cryptography](/mitre/techniques/T1573-002.md) — deletes. Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
- [T1574.001 — DLL](/mitre/techniques/T1574-001.md) — deletes. Adversaries may abuse dynamic-link library files (DLLs) in order to achieve persistence, escalate privileges, and evade defenses.
- `T1574.002` — deletes
- [T1574.004 — Dylib Hijacking](/mitre/techniques/T1574-004.md) — deletes. Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime.
- [T1574.006 — Dynamic Linker Hijacking](/mitre/techniques/T1574-006.md) — deletes. Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries.
- [T1574.007 — Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md) — deletes. Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries.
- [T1574.008 — Path Interception by Search Order Hijacking](/mitre/techniques/T1574-008.md) — deletes. Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs.
- [T1574.009 — Path Interception by Unquoted Path](/mitre/techniques/T1574-009.md) — deletes. Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.
- [T1574.012 — COR_PROFILER](/mitre/techniques/T1574-012.md) — deletes. Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the.NET CLR.
- [T1649 — Steal or Forge Authentication Certificates](/mitre/techniques/T1649.md) — deletes. Adversaries may steal or forge certificates used for authentication to access remote systems or resources.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
