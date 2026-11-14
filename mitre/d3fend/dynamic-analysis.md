# D3FEND: Dynamic Analysis

<a id="dynamic-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: Document File, Executable File  

Executing or opening a file in a synthetic "sandbox" environment to determine if the file is a malicious program or if the file exploits another program such as a document reader.

## ATT&CK techniques countered (42)

- [T0865: Spearphishing Attachment](https://attack.mitre.org/techniques/T0865): analyzes
- [T0871: Execution through API](https://attack.mitre.org/techniques/T0871): analyzes
- [T0894: System Binary Proxy Execution](https://attack.mitre.org/techniques/T0894): analyzes
- [T0895: Autorun Image](https://attack.mitre.org/techniques/T0895): analyzes
- [T1016: System Network Configuration Discovery](/mitre/techniques/T1016.md): analyzes. Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems.
- [T1027.001: Binary Padding](/mitre/techniques/T1027-001.md): analyzes. Adversaries may use binary padding to add junk data and change the on-disk representation of malware.
- [T1027.002: Software Packing](/mitre/techniques/T1027-002.md): analyzes. Adversaries may perform software packing or virtual machine software protection to conceal their code.
- [T1027.004: Compile After Delivery](/mitre/techniques/T1027-004.md): analyzes. Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code.
- [T1036.001: Invalid Code Signature](/mitre/techniques/T1036-001.md): analyzes. Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool.
- [T1036.003: Rename Legitimate Utilities](/mitre/techniques/T1036-003.md): analyzes. Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities.
- [T1037.001: Logon Script (Windows)](/mitre/techniques/T1037-001.md): analyzes. Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence.
- [T1037.002: Login Hook](/mitre/techniques/T1037-002.md): analyzes. Adversaries may use a Login Hook to establish persistence executed upon user logon.
- [T1037.003: Network Logon Script](/mitre/techniques/T1037-003.md): analyzes. Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence.
- [T1037.004: RC Scripts](/mitre/techniques/T1037-004.md): analyzes. Adversaries may establish persistence by modifying RC scripts, which are executed during a Unix-like system’s startup.
- [T1055.003: Thread Execution Hijacking](/mitre/techniques/T1055-003.md): analyzes. Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges.
- [T1059: Command and Scripting Interpreter](/mitre/techniques/T1059.md): analyzes. Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.
- [T1114.001: Local Email Collection](/mitre/techniques/T1114-001.md): analyzes. Adversaries may target user email on local systems to collect sensitive information.
- [T1137.001: Office Template Macros](/mitre/techniques/T1137-001.md): analyzes. Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system.
- [T1137.003: Outlook Forms](/mitre/techniques/T1137-003.md): analyzes. Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system.
- [T1140: Deobfuscate/Decode Files or Information](/mitre/techniques/T1140.md): analyzes. Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis.
- [T1204.002: Malicious File](/mitre/techniques/T1204-002.md): analyzes. An adversary may rely upon a user opening a malicious file in order to gain execution.
- [T1218.005: Mshta](/mitre/techniques/T1218-005.md): analyzes. Adversaries may abuse mshta.exe to proxy execution of malicious.hta files and Javascript or VBScript through a trusted Windows utility.
- [T1220: XSL Script Processing](/mitre/techniques/T1220.md): analyzes. Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files.
- [T1505.003: Web Shell](/mitre/techniques/T1505-003.md): analyzes. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1534: Internal Spearphishing](/mitre/techniques/T1534.md): analyzes. After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization.
- [T1546.002: Screensaver](/mitre/techniques/T1546-002.md): analyzes. Adversaries may establish persistence by executing malicious content triggered by user inactivity.
- [T1546.005: Trap](/mitre/techniques/T1546-005.md): analyzes. Adversaries may establish persistence by executing malicious content triggered by an interrupt signal.
- [T1546.006: LC_LOAD_DYLIB Addition](/mitre/techniques/T1546-006.md): analyzes. Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries.
- [T1546.008: Accessibility Features](/mitre/techniques/T1546-008.md): analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.
- [T1546.013: PowerShell Profile](/mitre/techniques/T1546-013.md): analyzes. Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles.
- [T1546.015: Component Object Model Hijacking](/mitre/techniques/T1546-015.md): analyzes. Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects.
- [T1547.001: Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md): analyzes. Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.
- [T1547.009: Shortcut Modification](/mitre/techniques/T1547-009.md): analyzes. Adversaries may create or modify shortcuts that can execute a program during system boot or user login.
- [T1548.002: Bypass User Account Control](/mitre/techniques/T1548-002.md): analyzes. Adversaries may bypass UAC mechanisms to elevate process privileges on system.
- [T1564.007: VBA Stomping](/mitre/techniques/T1564-007.md): analyzes. Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data.
- [T1565.003: Runtime Data Manipulation](/mitre/techniques/T1565-003.md): analyzes. Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data.
- [T1566.001: Spearphishing Attachment](/mitre/techniques/T1566-001.md): analyzes. Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002: Spearphishing Link](/mitre/techniques/T1566-002.md): analyzes. Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.
- [T1574.007: Path Interception by PATH Environment Variable](/mitre/techniques/T1574-007.md): analyzes. Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries.
- [T1574.008: Path Interception by Search Order Hijacking](/mitre/techniques/T1574-008.md): analyzes. Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs.
- [T1574.009: Path Interception by Unquoted Path](/mitre/techniques/T1574-009.md): analyzes. Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.
- [T1690: Prevent Command History Logging](/mitre/techniques/T1690.md): analyzes (D3FEND maps the revoked predecessor T1562.003). Adversaries may impair command history logging to hide commands they run on a compromised system.

_D3FEND also maps T0853, deprecated in ATT&CK with no successor; not counted above._

## Related pages

- [Content Filtering](/mitre/d3fend/content-filtering.md), which also counters 42 of these techniques
- [Content Modification](/mitre/d3fend/content-modification.md), which also counters 42 of these techniques
- [Content Quarantine](/mitre/d3fend/content-quarantine.md), which also counters 42 of these techniques
- [Decoy File](/mitre/d3fend/decoy-file.md), which also counters 42 of these techniques
- [Emulated File Analysis](/mitre/d3fend/emulated-file-analysis.md), which also counters 42 of these techniques
- [File Analysis](/mitre/d3fend/file-analysis.md), which also counters 42 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md)
- [Hugging Face as an AI Supply-Chain Attack Surface: A 2021 to 2026 Case Study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md)
- [North Korea-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)
- [Other State-Linked Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_OTHER_STATES.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [The Binance Hot-Wallet Theft of October 2026: A Case Study](/case-studies/BINANCE_HEIST_2026.md)
- [The Microsoft Office Security Feature Bypass of 2026 (CVE-2026-21509) and APT28: A Case Study](/case-studies/MICROSOFT_OFFICE_CVE_2026_21509.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)
- [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)
- [The Year 2011 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2011.md)
- [The Year 2012 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2012.md)
- [The Year 2014 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2014.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
