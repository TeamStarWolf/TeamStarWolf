# Privilege Escalation — Technique Detail

> Full detail pages for the **26 ATT&CK techniques** whose primary tactic is [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) (ATT&CK Enterprise v19.2). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1068 — Exploitation for Privilege Escalation
<a id="t1068"></a>

**Tactics:** Privilege Escalation · **Platforms:** Containers, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1068)  

Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions. When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host. This may be a necessary step for an adversary compromising an endpoint system that has been properly configured and limits other privilege escalation methods. Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD). Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) or [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570).

**ATT&CK mitigations (5):** [M1019 Threat Intelligence Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1019), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (21):** `AC-2`, `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-10`, `RA-5`, `SC-18`, `SC-2`, `SC-3`, `SC-30`, `SC-39`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-5`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Exploitation for Privilege Escalation  
**Used by 22 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0107 Whitefly](https://attack.mitre.org/groups/G0107), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 19 software:** [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0654 ProLock](https://attack.mitre.org/software/S0654), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0664 Pandora](https://attack.mitre.org/software/S0664), [S0672 Zox](https://attack.mitre.org/software/S0672), [S1151 ZeroCleare](https://attack.mitre.org/software/S1151), [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1546 — Event Triggered Execution
<a id="t1546"></a>

**Tactics:** Privilege Escalation, Persistence · **Platforms:** Linux, macOS, Windows, SaaS, IaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546)  

Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events. Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked. Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (9):** `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-3`, `CM-6`, `IA-9`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Event Triggered Execution Across Platforms  
**Implemented by 3 software:** [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1091 Pacu](https://attack.mitre.org/software/S1091), [S1164 UPSTYLE](https://attack.mitre.org/software/S1164)  

---

### T1546.001 — Change Default File Association
<a id="t1546001"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/001)  

Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened. System file associations are listed under <code>HKEY_CLASSES_ROOT\.[extension]</code>, for example <code>HKEY_CLASSES_ROOT\.txt</code>. The entries point to a handler for that extension located at <code>HKEY_CLASSES_ROOT\\[handler]</code>. The various commands are then listed as subkeys underneath the shell key at <code>HKEY_CLASSES_ROOT\\[handler]\shell\\[action]\command</code>. For example: * <code>HKEY_CLASSES_ROOT\txtfile\shell\open\command</code> * <code>HKEY_CLASSES_ROOT\txtfile\shell\print\command</code> * <code>HKEY_CLASSES_ROOT\txtfile\shell\printto\command</code> The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Default File Association Hijack via Registry & Execution Correlation on Windows  
**Used by 1 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  
**Implemented by 1 software:** [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692)  

---

### T1546.002 — Screensaver
<a id="t1546002"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/002)  

Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a.scr file extension. The Windows screensaver application scrnsave.scr is located in <code>C:\Windows\System32\</code>, and <code>C:\Windows\sysWOW64\</code> on 64-bit Windows systems, along with screensavers included with base Windows installations. The following screensaver settings are stored in the Registry (<code>HKCU\Control Panel\Desktop\</code>) and could be manipulated to achieve persistence: * <code>SCRNSAVE.exe</code> - set to malicious PE path * <code>ScreenSaveActive</code> - set to '1' to enable the screensaver * <code>ScreenSaverIsSecure</code> - set to '0' to not require a password to unlock * <code>ScreenSaveTimeout</code> - sets user inactivity timeout before screensaver is executed Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (9):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Screensaver-Based Persistence via Registry and Execution Chains  
**Implemented by 1 software:** [S0168 Gazer](https://attack.mitre.org/software/S0168)  

---

### T1546.003 — Windows Management Instrumentation Event Subscription
<a id="t1546003"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/003)  

Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user login, or the computer's uptime. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may also compile WMI scripts – using `mofcomp.exe` –into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription. WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `SI-14`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect WMI Event Subscription for Persistence via WmiPrvSE Process and MOF Compilation  
**Used by 10 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0075 Rancor](https://attack.mitre.org/groups/G0075), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1013 Metador](https://attack.mitre.org/groups/G1013)  
**Implemented by 13 software:** [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0150 POSHSPY](https://attack.mitre.org/software/S0150), [S0202 adbupd](https://attack.mitre.org/software/S0202), [S0371 POWERTON](https://attack.mitre.org/software/S0371), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0511 RegDuke](https://attack.mitre.org/software/S0511), [S0682 TrailBlazer](https://attack.mitre.org/software/S0682), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1059 metaMain](https://attack.mitre.org/software/S1059), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1085 Sardonic](https://attack.mitre.org/software/S1085)  

---

### T1546.004 — Unix Shell Configuration Modification
<a id="t1546004"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/004)  

Adversaries may establish persistence through executing malicious commands triggered by a user’s shell. User [Unix Shell](https://attack.mitre.org/techniques/T1059/004)s execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login shell executes scripts from the system (<code>/etc</code>) and the user’s home directory (<code>~/</code>) to configure the environment. All login shells on a system use /etc/profile when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user’s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately. Adversaries may attempt to establish persistence by inserting commands into scripts automatically executed by shells. Using bash as an example, the default shell for most GNU/Linux systems, adversaries may add commands that launch malicious binaries into the <code>/etc/profile</code> and <code>/etc/profile.d</code> files. These files typically require root permissions to modify and are executed each time any shell on a system launches. For user level permissions, adversaries can insert malicious commands into <code>~/.bash_profile</code>, <code>~/.bash_login</code>, or <code>~/.profile</code> which are sourced when a user opens a command-line interface or connects remotely. Since the system only executes the first existing file in the listed order, adversaries have used <code>~/.bash_profile</code> to ensure execution. Adversaries have also leveraged the <code>~/.bashrc</code> file which is additionally executed if the connection is established remotely or an additional interactive shell is opened, such as a new tab in the command-line interface. Some malware targets the termination of a program to trigger execution, adversaries can use the <code>~/.bash_logout</code> file to execute malicious commands at the end of a session. For macOS, the functionality of this technique is similar but may leverage zsh, the default shell for macOS 10.15+. When the Terminal.app is opened, the application launches a zsh login shell and a zsh interactive shell. The login shell configures the system environment using <code>/etc/profile</code>, <code>/etc/zshenv</code>, <code>/etc/zprofile</code>, and <code>/etc/zlogin</code>. The login shell then configures the user environment with <code>~/.zprofile</code> and <code>~/.zlogin</code>. The interactive shell uses the <code>~/.zshrc</code> to configure the user environment. Upon exiting, <code>/etc/zlogout</code> and <code>~/.zlogout</code> are executed. For legacy programs, macOS executes <code>/etc/bashrc</code> on startup.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Shell Configuration Modification for Persistence via Event-Triggered Execution  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 4 software:** [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0690 Green Lambert](https://attack.mitre.org/software/S0690), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078)  

---

### T1546.005 — Trap
<a id="t1546005"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/005)  

Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>. Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format <code>trap 'command list' signals</code> where "command list" will be executed when "signals" are received.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Event Triggered Execution via Trap (T1546.005)  

---

### T1546.006 — LC_LOAD_DYLIB Addition
<a id="t1546006"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/006)  

Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies. There are tools available to perform these changes. Adversaries may modify Mach-O binary headers to load and execute malicious dylibs every time the binary is executed. Although any changes will invalidate digital signatures on binaries because the binary is being modified, this can be remediated by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load time.

**ATT&CK mitigations (3):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (13):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-9`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for LC_LOAD_DYLIB Modification in Mach-O Binaries on macOS  

---

### T1546.007 — Netsh Helper DLL
<a id="t1546007"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/007)  

Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at <code>HKLM\SOFTWARE\Microsoft\Netsh</code>. Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner. This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if other software (ex: VPN) is present on the system that executes netsh.exe as part of its normal functionality.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Netsh Helper DLL Persistence via Registry and Child Process Monitoring (Windows)  
**Implemented by 1 software:** [S0108 netsh](https://attack.mitre.org/software/S0108)  

---

### T1546.008 — Accessibility Features
<a id="t1546008"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/008)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system. Two common accessibility programs are <code>C:\Windows\System32\sethc.exe</code>, launched when the shift key is pressed five times and <code>C:\Windows\System32\utilman.exe</code>, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen. Depending on the version of Windows, an adversary may take advantage of these features in different ways. Common methods used by adversaries include replacing accessibility feature binaries or pointers/references to these binaries in the Registry. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in <code>%systemdir%\</code>, and it must be protected by Windows File or Resource Protection (WFP/WRP). The [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012) debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced. For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 and later, for example, the program (e.g., <code>C:\Windows\System32\utilman.exe</code>) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) will cause the replaced file to be executed with SYSTEM privileges. Other accessibility features exist that may also be leveraged in a similar fashion: * On-Screen Keyboard: <code>C:\Windows\System32\osk.exe</code> * Magnifier: <code>C:\Windows\System32\Magnify.exe</code> * Narrator: <code>C:\Windows\System32\Narrator.exe</code> * Display Switcher: <code>C:\Windows\System32\DisplaySwitch.exe</code> * App Switcher: <code>C:\Windows\System32\AtBroker.exe</code>

**ATT&CK mitigations (3):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (6):** `CM-10`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Accessibility Feature Hijacking via Binary Replacement or Registry Modification  
**Used by 6 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117)  
**Implemented by 1 software:** [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1546.009 — AppCert DLLs
<a id="t1546009"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/009)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppCertDLLs</code> Registry key under <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\</code> are loaded into every process that calls the ubiquitously used application programming interface (API) functions <code>CreateProcess</code>, <code>CreateProcessAsUser</code>, <code>CreateProcessWithLoginW</code>, <code>CreateProcessWithTokenW</code>, or <code>WinExec</code>. Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), this value can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. Malicious AppCert DLLs may also provide persistence by continuously being triggered by API activity.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (3):** `CM-7`, `SI-10`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for AppCert DLLs Persistence via Registry Injection  
**Implemented by 1 software:** [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196)  

---

### T1546.010 — AppInit DLLs
<a id="t1546010"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/010)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppInit_DLLs</code> value in the Registry keys <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> or <code>HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. Similar to Process Injection, these values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity. The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (5):** `CM-2`, `CM-7`, `SI-10`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Event Triggered Execution: AppInit DLLs (Windows)  
**Used by 1 threat groups:** [G0087 APT39](https://attack.mitre.org/groups/G0087)  
**Implemented by 3 software:** [S0098 T9000](https://attack.mitre.org/software/S0098), [S0107 Cherry Picker](https://attack.mitre.org/software/S0107), [S0458 Ramsay](https://attack.mitre.org/software/S0458)  

---

### T1546.011 — Application Shimming
<a id="t1546011"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/011)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses hooking to redirect the code as necessary in order to communicate with the OS. A list of all shims currently installed by the default Windows installer (sdbinst.exe) is kept in: * <code>%WINDIR%\AppPatch\sysmain.sdb</code> and * <code>hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb</code> Custom databases are stored in: * <code>%WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom</code> and * <code>hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom</code> To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002) (UAC and RedirectEXE), inject DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress). Utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc. Shims can also be abused to establish persistence by continuously being invoked by affected programs.

**ATT&CK mitigations (2):** [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (2):** `AC-6`, `SI-2`  
**ATT&CK detection strategy:** Detection Strategy for Application Shimming via sdbinst.exe and Registry Artifacts (Windows)  
**Used by 1 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046)  
**Implemented by 3 software:** [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0517 Pillowmint](https://attack.mitre.org/software/S0517)  

---

### T1546.012 — Image File Execution Options Injection
<a id="t1546012"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/012)  

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., <code>C:\dbg\ntsd.exe -g notepad.exe</code>). IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool. IFEOs are represented as <code>Debugger</code> values in the Registry under <code>HKLM\SOFTWARE{\Wow6432Node}\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable></code> where <code>&lt;executable&gt;</code> is the binary on which the debugger is attached. IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process). Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\</code>. Similar to [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), on Windows Vista and later as well as Windows Server 2008 and later, a Registry key may be modified that configures "cmd.exe," or another program that provides backdoor access, as a "debugger" for an accessibility program (ex: utilman.exe). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) will cause the "debugger" program to be executed with SYSTEM privileges. Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), these values may also be abused to obtain privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer. Installing IFEO mechanisms may also provide Persistence via continuous triggered invocation. Malware may also use IFEO to impair defenses by registering invalid debuggers that redirect and effectively disable various system and security applications.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for IFEO Injection on Windows  
**Implemented by 2 software:** [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0559 SUNBURST](https://attack.mitre.org/software/S0559)  

---

### T1546.013 — PowerShell Profile
<a id="t1546013"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/013)  

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile (<code>profile.ps1</code>) is a script that runs when [PowerShell](https://attack.mitre.org/techniques/T1059/001) starts and can be used as a logon script to customize user environments. [PowerShell](https://attack.mitre.org/techniques/T1059/001) supports several profiles depending on the user or host program. For example, there can be different profiles for [PowerShell](https://attack.mitre.org/techniques/T1059/001) host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or [PowerShell](https://attack.mitre.org/techniques/T1059/001) drives to gain persistence. Every time a user opens a [PowerShell](https://attack.mitre.org/techniques/T1059/001) session the modified script will be executed unless the <code>-NoProfile</code> flag is used when it is launched. An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CA-7`, `CM-10`, `CM-2`, `CM-6`, `IA-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for PowerShell Profile Persistence via profile.ps1 Modification  
**Used by 1 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010)  

---

### T1546.014 — Emond
<a id="t1546014"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/014)  

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place. The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path <code>/private/var/db/emondClients</code>, specified in the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) configuration file at<code>/System/Library/LaunchDaemons/com.apple.emond.plist</code>. Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication. Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) service.

**ATT&CK mitigations (1):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (6):** `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Event Triggered Execution via emond on macOS  

---

### T1546.015 — Component Object Model Hijacking
<a id="t1546015"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/015)  

Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry. Adversaries may use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead. An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection. One variation of COM hijacking involves abusing Type Libraries (TypeLibs), which provide metadata about COM objects, such as their interfaces and methods. Adversaries may modify Registry keys associated with TypeLibs to redirect legitimate COM object functionality to malicious scripts or payloads. Unlike traditional COM hijacking, which commonly uses local DLLs, this variation may leverage the "script:" moniker to execute remote scripts hosted on external servers. This approach enables stealthy execution of code while maintaining persistence, as the remote payload would be automatically downloaded whenever the hijacked COM object is accessed.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Windows COM Hijacking Detection via Registry and DLL Load Correlation  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  
**Implemented by 11 software:** [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0256 Mosquito](https://attack.mitre.org/software/S0256), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0679 Ferocious](https://attack.mitre.org/software/S0679), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1050 PcShare](https://attack.mitre.org/software/S1050), [S1064 SVCReady](https://attack.mitre.org/software/S1064)  

---

### T1546.016 — Installer Packages
<a id="t1546016"></a>

sub-technique of [T1546](/techniques/privilege-escalation.md#t1546) · **Tactics:** Privilege Escalation, Persistence · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1546/016)  

Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit elevated permissions when executed. Developers often use these scripts to prepare the environment for installation, check requirements, download dependencies, and remove files after installation. Using legitimate applications, adversaries have distributed applications with modified installer scripts to execute malicious content. When a user installs the application, they may be required to grant administrative permissions to allow the installation. At the end of the installation process of the legitimate application, content such as macOS `postinstall` scripts can be executed with the inherited elevated permissions. Adversaries can use these scripts to execute a malicious executable or install other malicious components (such as a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)) with the elevated permissions. Depending on the distribution, Linux versions of package installer scripts are sometimes called maintainer scripts or post installation scripts. These scripts can include `preinst`, `postinst`, `prerm`, `postrm` scripts and run as root when executed. For Windows, the Microsoft Installer services uses `.msi` files to manage the installing, updating, and uninstalling of applications. These installation routines may also include instructions to perform additional actions that may be abused by adversaries.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (7):** `AC-6`, `CA-7`, `CM-5`, `CM-6`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1546.016 - Event Triggered Execution via Installer Packages  
**Implemented by 1 software:** [S0584 AppleJeus](https://attack.mitre.org/software/S0584)  

---

### T1548 — Abuse Elevation Control Mechanism
<a id="t1548"></a>

**Tactics:** Privilege Escalation · **Platforms:** Linux, macOS, Windows, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548)  

Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

**ATT&CK mitigations (8):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (22):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SC-18`, `SC-34`, `SI-12`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Abuse Elevation Control Mechanism (T1548)  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 1 software:** [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130)  

---

### T1548.001 — Setuid and Setgid
<a id="t1548001"></a>

sub-technique of [T1548](/techniques/privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/001)  

An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively. Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges. Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications (i.e. [Linux and Mac Permissions](https://attack.mitre.org/techniques/T1222/002)). The <code>chmod</code> command can set these bits with bitmasking, <code>chmod 4777 [file]</code> or via shorthand naming, <code>chmod u+s [file]</code>. This will enable the setuid bit. To enable the setgid bit, <code>chmod 2775</code> and <code>chmod g+s</code> can be used. Adversaries can use this mechanism on their own malware to make sure they're able to execute in elevated contexts in the future. This abuse is often part of a "shell escape" or other actions to bypass an execution environment with restricted permissions. Alternatively, adversaries may choose to find and target vulnerable binaries with the setuid or setgid bits already enabled (i.e. [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)). The setuid and setguid bits are indicated with an "s" instead of an "x" when viewing a file's attributes via <code>ls -l</code>. The <code>find</code> command can also be used to search for such files. For example, <code>find / -perm +4000 2>/dev/null</code> can be used to find files with setuid set and <code>find / -perm +2000 2>/dev/null</code> may be used for setgid. Binaries that have these bits set may then be abused by adversaries.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (3):** `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Setuid/Setgid Privilege Abuse Detection (Linux/macOS)  
**Implemented by 2 software:** [S0276 Keydnap](https://attack.mitre.org/software/S0276), [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401)  

---

### T1548.002 — Bypass User Account Control
<a id="t1548002"></a>

sub-technique of [T1548](/techniques/privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/002)  

Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) objects without prompting the user through the UAC notification box. An example of this is use of [Rundll32](https://attack.mitre.org/techniques/T1218/011) to load a specifically crafted DLL which loads an auto-elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user. Many methods have been discovered to bypass UAC. The Github readme page for UACME contains an extensive list of methods that have been discovered and implemented, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as: * <code>eventvwr.exe</code> can auto-elevate and execute a specified binary or script. Another bypass is possible through some lateral movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on remote systems and default to high integrity.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `RA-5`, `SI-2`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1548.002 – Bypass User Account Control (UAC)  
**Used by 11 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 49 software:** [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0116 UACMe](https://attack.mitre.org/software/S0116), [S0129 AutoIt backdoor](https://attack.mitre.org/software/S0129), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0134 Downdelph](https://attack.mitre.org/software/S0134), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0254 PLAINTEE](https://attack.mitre.org/software/S0254), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0527 CSPY Downloader](https://attack.mitre.org/software/S0527), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0660 Clambling](https://attack.mitre.org/software/S0660), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1548.003 — Sudo and Sudo Caching
<a id="t1548003"></a>

sub-technique of [T1548](/techniques/privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/003)  

Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges. Within Linux and MacOS systems, sudo (sometimes referred to as "superuser do") allows users to perform commands from terminals with elevated privileges and to control who can perform these commands on the system. The <code>sudo</code> command "allows a system administrator to delegate authority to give certain users (or groups of users) the ability to run some (or all) commands as root or another user while providing an audit trail of the commands and their arguments." Since sudo was made for the system administrator, it has some useful configuration features such as a <code>timestamp_timeout</code>, which is the amount of time in minutes between instances of <code>sudo</code> before it will re-prompt for a password. This is because <code>sudo</code> has the ability to cache credentials for a period of time. Sudo creates (or touches) a file at <code>/var/db/sudo</code> with a timestamp of when sudo was last run to determine this timeout. Additionally, there is a <code>tty_tickets</code> variable that treats each new tty (terminal session) in isolation. This means that, for example, the sudo timeout of one tty will not affect another tty (you will have to type the password again). The sudoers file, <code>/etc/sudoers</code>, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the principle of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like <code>user1 ALL=(ALL) NOPASSWD: ALL</code>. Elevated privileges are required to edit this file though. Adversaries can also abuse poor configurations of these mechanisms to escalate privileges without needing the user's password. For example, <code>/var/db/sudo</code>'s timestamp can be monitored to see if it falls within the <code>timestamp_timeout</code> range. If it does, then malware can execute sudo commands without needing to supply the user's password. Additional, if <code>tty_tickets</code> is disabled, adversaries can do this from any tty for that user. In the wild, malware has disabled <code>tty_tickets</code> to potentially make scripting easier by issuing <code>echo \'Defaults !tty_tickets\' >> /etc/sudoers</code>. In order for this change to be reflected, the malware also issued <code>killall Terminal</code>. As of macOS Sierra, the sudoers file has <code>tty_tickets</code> enabled by default.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (13):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for Abuse of Sudo and Sudo Caching  
**Implemented by 3 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0281 Dok](https://attack.mitre.org/software/S0281)  

---

### T1548.004 — Elevated Execution with Prompt
<a id="t1548004"></a>

sub-technique of [T1548](/techniques/privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/004)  

Adversaries may leverage the <code>AuthorizationExecuteWithPrivileges</code> API to escalate privileges by prompting the user for credentials. The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating. This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified. Although this API is deprecated, it still fully functions in the latest releases of macOS. When calling this API, the user will be prompted to enter their credentials but no checks on the origin or integrity of the program are made. The program calling the API may also load world writable files which can be modified to perform malicious behavior with elevated privileges. Adversaries may abuse <code>AuthorizationExecuteWithPrivileges</code> to obtain root privileges in order to install malicious software on victims and install persistence mechanisms. This technique may be combined with [Masquerading](https://attack.mitre.org/techniques/T1036) to trick the user into granting escalated privileges to malicious code. This technique has also been shown to work by modifying legitimate programs present on the machine that make use of this API.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (11):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-18`, `SC-34`, `SI-12`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** macOS AuthorizationExecuteWithPrivileges Elevation Prompt Detection  
**Implemented by 1 software:** [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402)  

---

### T1548.005 — Temporary Elevated Cloud Access
<a id="t1548005"></a>

sub-technique of [T1548](/techniques/privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation · **Platforms:** IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/005)  

Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources. Many cloud environments allow administrators to grant user or service accounts permission to request just-in-time access to roles, impersonate other accounts, pass roles onto resources and services, or otherwise gain short-term access to a set of privileges that may be distinct from their own. Just-in-time access is a mechanism for granting additional roles to cloud accounts in a granular, temporary manner. This allows accounts to operate with only the permissions they need on a daily basis, and to request additional permissions as necessary. Sometimes just-in-time access requests are configured to require manual approval, while other times the desired permissions are automatically granted. Account impersonation allows user or service accounts to temporarily act with the permissions of another account. For example, in GCP users with the `iam.serviceAccountTokenCreator` role can create temporary access tokens or sign arbitrary payloads with the permissions of a service account, while service accounts with domain-wide delegation permission are permitted to impersonate Google Workspace accounts. In Exchange Online, the `ApplicationImpersonation` role allows a service account to use the permissions associated with specified user accounts. Many cloud environments also include mechanisms for users to pass roles to resources that allow them to perform tasks and authenticate to other services. While the user that creates the resource does not directly assume the role they pass to it, they may still be able to take advantage of the role's access -- for example, by configuring the resource to perform certain actions with the permissions it has been granted. In AWS, users with the `PassRole` permission can allow a service they create to assume a given role, while in GCP, users with the `iam.serviceAccountUser` role can attach a service account to a resource. While users require specific role assignments in order to use any of these features, cloud administrators may misconfigure permissions. This could result in escalation paths that allow adversaries to gain access to resources beyond what was originally intended. **Note:** this technique is distinct from [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003), which involves assigning permanent roles to accounts rather than abusing existing permissions structures to gain temporarily elevated access to resources. However, adversaries that compromise a sufficiently privileged account may grant another account they control [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003) that would allow them to also abuse these features. This may also allow for greater stealth than would be had by directly using the highly privileged account, especially when logs do not clarify when role impersonation is taking place.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `CM-5`  
**ATT&CK detection strategy:** Detection Strategy for Temporary Elevated Cloud Access Abuse (T1548.005)  

---

### T1548.006 — TCC Manipulation
<a id="t1548006"></a>

sub-technique of [T1548](/techniques/privilege-escalation.md#t1548) · **Tactics:** Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/006)  

Adversaries can manipulate or abuse the Transparency, Consent, & Control (TCC) service or database to grant malicious executables elevated permissions. TCC is a Privacy & Security macOS control mechanism used to determine if the running process has permission to access the data or services protected by TCC, such as screen sharing, camera, microphone, or Full Disk Access (FDA). When an application requests to access data or a service protected by TCC, the TCC daemon (`tccd`) checks the TCC database, located at `/Library/Application Support/com.apple.TCC/TCC.db` (and `~/` equivalent), and an overwrites file (if connected to an MDM) for existing permissions. If permissions do not exist, then the user is prompted to grant permission. Once permissions are granted, the database stores the application's permissions and will not prompt the user again unless reset. For example, when a web browser requests permissions to the user's webcam, once granted the web browser may not explicitly prompt the user again. Adversaries may access restricted data or services protected by TCC through abusing applications previously granted permissions through [Process Injection](https://attack.mitre.org/techniques/T1055) or executing a malicious binary using another application. For example, adversaries can use Finder, a macOS native app with FDA permissions, to execute a malicious [AppleScript](https://attack.mitre.org/techniques/T1059/002). When executing under the Finder App, the malicious [AppleScript](https://attack.mitre.org/techniques/T1059/002) inherits access to all files on the system without requiring a user prompt. When System Integrity Protection (SIP) is disabled, TCC protections are also disabled. For a system without SIP enabled, adversaries can manipulate the TCC database to add permissions to their malicious executable through loading an adversary controlled TCC database using environment variables and [Launchctl](https://attack.mitre.org/techniques/T1569/001).

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (17):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** TCC Database Manipulation via Launchctl and Unprotected SIP  
**Implemented by 1 software:** [S0658 XCSSET](https://attack.mitre.org/software/S0658)  

---

### T1611 — Escape to Host
<a id="t1611"></a>

**Tactics:** Privilege Escalation · **Platforms:** Windows, Linux, Containers, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1611)  

Adversaries may break out of a container or virtualized environment to gain access to the underlying host. This can allow an adversary access to other containerized or virtualized resources from the host level or to the host itself. In principle, containerized / virtualized resources should provide a clear separation of application functionality and be isolated from the host environment. There are multiple ways an adversary may escape from a container to a host environment. Examples include creating a container configured to mount the host’s filesystem using the bind parameter, which allows the adversary to drop payloads and execute control utilities such as cron on the host; utilizing a privileged container to run commands or load a malicious kernel module on the underlying host; or abusing system calls such as `unshare` and `keyctl` to escalate privileges and steal secrets. Additionally, an adversary may be able to exploit a compromised container with a mounted container management socket, such as `docker.sock`, to break out of the container via a [Container Administration Command](https://attack.mitre.org/techniques/T1609). Adversaries may also escape via [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), such as exploiting vulnerabilities in global symbolic links in order to access the root directory of a host machine. In ESXi environments, an adversary may exploit a vulnerability in order to escape from a virtual machine into the hypervisor. Gaining access to the host may provide the adversary with the opportunity to achieve follow-on objectives, such as establishing persistence, moving laterally within the environment, accessing other containers or virtual machines running on the host, or setting up a command and control channel on the host.

**ATT&CK mitigations (5):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (19):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-2`, `SC-3`, `SC-34`, `SC-39`, `SC-7`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Escape to Host  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 4 software:** [S0600 Doki](https://attack.mitre.org/software/S0600), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---
