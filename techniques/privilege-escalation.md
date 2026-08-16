# Privilege Escalation — Technique Detail

> Full detail pages for the **25 ATT&CK techniques** whose primary tactic is [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](README.md).

---

### T1068 — Exploitation for Privilege Escalation
<a id="t1068"></a>

**Tactics:** Privilege Escalation · **Platforms:** Containers, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1068)  

Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.

**ATT&CK mitigations (5):** [M1019 Threat Intelligence Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1019), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (21):** `AC-2`, `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-10`, `RA-5`, `SC-18`, `SC-2`, `SC-3`, `SC-30`, `SC-39`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-5`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Exploitation for Privilege Escalation  
**Used by 22 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0107 Whitefly](https://attack.mitre.org/groups/G0107), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 19 software:** [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0654 ProLock](https://attack.mitre.org/software/S0654), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0664 Pandora](https://attack.mitre.org/software/S0664), [S0672 Zox](https://attack.mitre.org/software/S0672), [S1151 ZeroCleare](https://attack.mitre.org/software/S1151), [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1546 — Event Triggered Execution
<a id="t1546"></a>

**Tactics:** Privilege Escalation, Persistence · **Platforms:** Linux, macOS, Windows, SaaS, IaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546)  

Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (9):** `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-3`, `CM-6`, `IA-9`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Event Triggered Execution Across Platforms  
**Implemented by 3 software:** [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1091 Pacu](https://attack.mitre.org/software/S1091), [S1164 UPSTYLE](https://attack.mitre.org/software/S1164)  

---

### T1546.001 — Change Default File Association
<a id="t1546001"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/001)  

Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Default File Association Hijack via Registry & Execution Correlation on Windows  
**Used by 1 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  
**Implemented by 1 software:** [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692)  

---

### T1546.002 — Screensaver
<a id="t1546002"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/002)  

Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (9):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Screensaver-Based Persistence via Registry and Execution Chains  
**Implemented by 1 software:** [S0168 Gazer](https://attack.mitre.org/software/S0168)  

---

### T1546.003 — Windows Management Instrumentation Event Subscription
<a id="t1546003"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/003)  

Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `SI-14`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect WMI Event Subscription for Persistence via WmiPrvSE Process and MOF Compilation  
**Used by 10 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0075 Rancor](https://attack.mitre.org/groups/G0075), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1013 Metador](https://attack.mitre.org/groups/G1013)  
**Implemented by 13 software:** [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0150 POSHSPY](https://attack.mitre.org/software/S0150), [S0202 adbupd](https://attack.mitre.org/software/S0202), [S0371 POWERTON](https://attack.mitre.org/software/S0371), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0511 RegDuke](https://attack.mitre.org/software/S0511), [S0682 TrailBlazer](https://attack.mitre.org/software/S0682), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1059 metaMain](https://attack.mitre.org/software/S1059), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1085 Sardonic](https://attack.mitre.org/software/S1085)  

---

### T1546.004 — Unix Shell Configuration Modification
<a id="t1546004"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/004)  

Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User Unix Shells execute several configuration scripts at different points throughout the session based on events.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Shell Configuration Modification for Persistence via Event-Triggered Execution  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 4 software:** [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0690 Green Lambert](https://attack.mitre.org/software/S0690), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078)  

---

### T1546.005 — Trap
<a id="t1546005"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/005)  

Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Event Triggered Execution via Trap (T1546.005)  

---

### T1546.006 — LC_LOAD_DYLIB Addition
<a id="t1546006"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/006)  

Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded.

**ATT&CK mitigations (3):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (13):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-9`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for LC_LOAD_DYLIB Modification in Mach-O Binaries on macOS  

---

### T1546.007 — Netsh Helper DLL
<a id="t1546007"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/007)  

Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Netsh Helper DLL Persistence via Registry and Child Process Monitoring (Windows)  
**Implemented by 1 software:** [S0108 netsh](https://attack.mitre.org/software/S0108)  

---

### T1546.008 — Accessibility Features
<a id="t1546008"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/008)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen).

**ATT&CK mitigations (3):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (6):** `CM-10`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Accessibility Feature Hijacking via Binary Replacement or Registry Modification  
**Used by 6 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117)  
**Implemented by 1 software:** [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1546.009 — AppCert DLLs
<a id="t1546009"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/009)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (3):** `CM-7`, `SI-10`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for AppCert DLLs Persistence via Registry Injection  
**Implemented by 1 software:** [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196)  

---

### T1546.010 — AppInit DLLs
<a id="t1546010"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/010)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (5):** `CM-2`, `CM-7`, `SI-10`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Event Triggered Execution: AppInit DLLs (Windows)  
**Used by 1 threat groups:** [G0087 APT39](https://attack.mitre.org/groups/G0087)  
**Implemented by 3 software:** [S0098 T9000](https://attack.mitre.org/software/S0098), [S0107 Cherry Picker](https://attack.mitre.org/software/S0107), [S0458 Ramsay](https://attack.mitre.org/software/S0458)  

---

### T1546.011 — Application Shimming
<a id="t1546011"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/011)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims.

**ATT&CK mitigations (2):** [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (2):** `AC-6`, `SI-2`  
**ATT&CK detection strategy:** Detection Strategy for Application Shimming via sdbinst.exe and Registry Artifacts (Windows)  
**Used by 1 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046)  
**Implemented by 3 software:** [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0517 Pillowmint](https://attack.mitre.org/software/S0517)  

---

### T1546.012 — Image File Execution Options Injection
<a id="t1546012"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/012)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for IFEO Injection on Windows  
**Implemented by 2 software:** [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0559 SUNBURST](https://attack.mitre.org/software/S0559)  

---

### T1546.013 — PowerShell Profile
<a id="t1546013"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/013)  

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile (<code>profile.ps1</code>) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CA-7`, `CM-10`, `CM-2`, `CM-6`, `IA-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for PowerShell Profile Persistence via profile.ps1 Modification  
**Used by 1 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010)  

---

### T1546.014 — Emond
<a id="t1546014"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/014)  

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a Launch Daemon that accepts events from various services, runs them through a simple rules engine, and takes action.

**ATT&CK mitigations (1):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (6):** `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Event Triggered Execution via emond on macOS  

---

### T1546.015 — Component Object Model Hijacking
<a id="t1546015"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/015)  

Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Windows COM Hijacking Detection via Registry and DLL Load Correlation  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  
**Implemented by 11 software:** [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0256 Mosquito](https://attack.mitre.org/software/S0256), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0679 Ferocious](https://attack.mitre.org/software/S0679), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1050 PcShare](https://attack.mitre.org/software/S1050), [S1064 SVCReady](https://attack.mitre.org/software/S1064)  

---

### T1546.016 — Installer Packages
<a id="t1546016"></a>

sub-technique of [T1546](privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/016)  

Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (7):** `AC-6`, `CA-7`, `CM-5`, `CM-6`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1546.016 - Event Triggered Execution via Installer Packages  
**Implemented by 1 software:** [S0584 AppleJeus](https://attack.mitre.org/software/S0584)  

---

### T1548 — Abuse Elevation Control Mechanism
<a id="t1548"></a>

**Tactics:** Privilege Escalation, Defense Evasion · **Platforms:** Linux, macOS, Windows, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548)  

Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine.

**ATT&CK mitigations (8):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (22):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SC-18`, `SC-34`, `SI-12`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Abuse Elevation Control Mechanism (T1548)  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 1 software:** [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130)  

---

### T1548.001 — Setuid and Setgid
<a id="t1548001"></a>

sub-technique of [T1548](privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation, Defense Evasion · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/001)  

An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (3):** `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Setuid/Setgid Privilege Abuse Detection (Linux/macOS)  
**Implemented by 2 software:** [S0276 Keydnap](https://attack.mitre.org/software/S0276), [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401)  

---

### T1548.002 — Bypass User Account Control
<a id="t1548002"></a>

sub-technique of [T1548](privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation, Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/002)  

Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `RA-5`, `SI-2`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1548.002 – Bypass User Account Control (UAC)  
**Used by 11 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 49 software:** [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0116 UACMe](https://attack.mitre.org/software/S0116), [S0129 AutoIt backdoor](https://attack.mitre.org/software/S0129), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0134 Downdelph](https://attack.mitre.org/software/S0134), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0254 PLAINTEE](https://attack.mitre.org/software/S0254), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0458 Ramsay](https://attack.mitre.org/software/S0458) _(+25 more)_  

---

### T1548.003 — Sudo and Sudo Caching
<a id="t1548003"></a>

sub-technique of [T1548](privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation, Defense Evasion · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/003)  

Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (13):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for Abuse of Sudo and Sudo Caching  
**Implemented by 3 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0281 Dok](https://attack.mitre.org/software/S0281)  

---

### T1548.004 — Elevated Execution with Prompt
<a id="t1548004"></a>

sub-technique of [T1548](privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation, Defense Evasion · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/004)  

Adversaries may leverage the <code>AuthorizationExecuteWithPrivileges</code> API to escalate privileges by prompting the user for credentials. The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (11):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-18`, `SC-34`, `SI-12`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** macOS AuthorizationExecuteWithPrivileges Elevation Prompt Detection  
**Implemented by 1 software:** [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402)  

---

### T1548.005 — Temporary Elevated Cloud Access
<a id="t1548005"></a>

sub-technique of [T1548](privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation, Defense Evasion · **Platforms:** IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/005)  

Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `CM-5`  
**ATT&CK detection strategy:** Detection Strategy for Temporary Elevated Cloud Access Abuse (T1548.005)  

---

### T1611 — Escape to Host
<a id="t1611"></a>

**Tactics:** Privilege Escalation · **Platforms:** Windows, Linux, Containers, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1611)  

Adversaries may break out of a container or virtualized environment to gain access to the underlying host. This can allow an adversary access to other containerized or virtualized resources from the host level or to the host itself.

**ATT&CK mitigations (5):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (19):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-2`, `SC-3`, `SC-34`, `SC-39`, `SC-7`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Escape to Host  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 4 software:** [S0600 Doki](https://attack.mitre.org/software/S0600), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

