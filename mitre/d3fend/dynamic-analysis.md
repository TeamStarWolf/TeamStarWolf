# D3FEND: Dynamic Analysis

<a id="dynamic-analysis"></a>

**D3FEND tactic:** Detect
**Digital artifacts:** Executable File, Document File

Executing or opening a file in a synthetic "sandbox" environment to determine if the file is a malicious program or if the file exploits another program such as a document reader.

## ATT&CK techniques countered (43)

- [T0853](https://attack.mitre.org/techniques/T0853) — analyzes
- [T0865](https://attack.mitre.org/techniques/T0865) — analyzes
- [T0871](https://attack.mitre.org/techniques/T0871) — analyzes
- [T0894](https://attack.mitre.org/techniques/T0894) — analyzes
- [T0895](https://attack.mitre.org/techniques/T0895) — analyzes
- [T1016 — System Network Configuration Discovery](/mitre/techniques/T1016.md) — analyzes. Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems.
- [T1027.001 — Binary Padding](/mitre/techniques/T1027-001.md) — analyzes. Adversaries may use binary padding to add junk data and change the on-disk representation of malware.
- [T1027.002 — Software Packing](/mitre/techniques/T1027-002.md) — analyzes. Adversaries may perform software packing or virtual machine software protection to conceal their code.
- [T1027.004 — Compile After Delivery](/mitre/techniques/T1027-004.md) — analyzes. Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code.
- [T1036.001 — Invalid Code Signature](/mitre/techniques/T1036-001.md) — analyzes. Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool.
- [T1036.003 — Rename Legitimate Utilities](/mitre/techniques/T1036-003.md) — analyzes. Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities.
- [T1037.001 — Logon Script (Windows)](/mitre/techniques/T1037-001.md) — analyzes. Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence.
- [T1037.002 — Login Hook](/mitre/techniques/T1037-002.md) — analyzes. Adversaries may use a Login Hook to establish persistence executed upon user logon.
- [T1037.003 — Network Logon Script](/mitre/techniques/T1037-003.md) — analyzes. Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence.
- [T1037.004 — RC Scripts](/mitre/techniques/T1037-004.md) — analyzes. Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup.
- [T1055.003 — Thread Execution Hijacking](/mitre/techniques/T1055-003.md) — analyzes. Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges.
- [T1059 — Command and Scripting Interpreter](/mitre/techniques/T1059.md) — analyzes. Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.
- [T1114.001 — Local Email Collection](/mitre/techniques/T1114-001.md) — analyzes. Adversaries may target user email on local systems to collect sensitive information.
- [T1137.001 — Office Template Macros](/mitre/techniques/T1137-001.md) — analyzes. Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system.
- [T1137.003 — Outlook Forms](/mitre/techniques/T1137-003.md) — analyzes. Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system.
- [T1140 — Deobfuscate/Decode Files or Information](/mitre/techniques/T1140.md) — analyzes. Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.
- [T1204.002 — Malicious File](/mitre/techniques/T1204-002.md) — analyzes. An adversary may rely upon a user opening a malicious file in order to gain execution.
- [T1218.005 — Mshta](/mitre/techniques/T1218-005.md) — analyzes. Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility.
- [T1220 — XSL Script Processing](/mitre/techniques/T1220.md) — analyzes. Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files.
- [T1505.003 — Web Shell](/mitre/techniques/T1505-003.md) — analyzes. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1534 — Internal Spearphishing](/mitre/techniques/T1534.md) — analyzes. After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization.
- [T1546.002 — Screensaver](/mitre/techniques/T1546-002.md) — analyzes. Adversaries may establish persistence by executing malicious content triggered by user inactivity.
- [T1546.005 — Trap](/mitre/techniques/T1546-005.md) — analyzes. Adversaries may establish persistence by executing malicious content triggered by an interrupt signal.
- [T1546.006 — LC_LOAD_DYLIB Addition](/mitre/techniques/T1546-006.md) — analyzes. Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries.
- [T1546.008 — Accessibility Features](/mitre/techniques/T1546-008.md) — analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.
- [T1546.013 — PowerShell Profile](/mitre/techniques/T1546-013.md) — analyzes. Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles.
- [T1546.015 — Component Object Model Hijacking](/mitre/techniques/T1546-015.md) — analyzes. Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects.
- [T1547.001 — Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md) — analyzes. Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.
- [T1547.009 — Shortcut Modification](/mitre/techniques/T1547-009.md) — analyzes. Adversaries may create or modify shortcuts that can execute a program during system boot or user login.
- [T1548.002 — Bypass User Account Control](/mitre/techniques/T1548-002.md) — analyzes. Adversaries may bypass UAC mechanisms to elevate process privileges on system.
- [T1562.003 — Impair Command History Logging](/mitre/techniques/T1562-003.md) — analyzes. Adversaries may impair command history logging to hide commands they run on a compromised system.
- [T1564.007 — VBA Stomping](/mitre/techniques/T1564-007.md) — analyzes. Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data.
- [T1565.003 — Runtime Data Manipulation](/mitre/techniques/T1565-003.md) — analyzes. Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data.
- [T1566.001 — Spearphishing Attachment](/mitre/techniques/T1566-001.md) — analyzes. Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002 — Spearphishing Link](/mitre/techniques/T1566-002.md) — analyzes. Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.
- [T1574.007 — Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md) — analyzes. Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries.
- [T1574.008 — Path Interception by Search Order Hijacking](/mitre/techniques/T1574-008.md) — analyzes. Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs.
- [T1574.009 — Path Interception by Unquoted Path](/mitre/techniques/T1574-009.md) — analyzes. Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
