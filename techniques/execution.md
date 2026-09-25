# Execution — Technique Detail

> Full detail pages for the **45 ATT&CK techniques** whose primary tactic is [Execution](https://attack.mitre.org/tactics/TA0002/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1047 — Windows Management Instrumentation
<a id="t1047"></a>

**Tactics:** Execution · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1047)  

Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is designed for programmers and is the infrastructure for management data and operations on Windows systems.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (17):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `RA-5`, `SC-3`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for WMI Execution Abuse on Windows  
**Used by 39 threat groups:** [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0112 Windshift](https://attack.mitre.org/groups/G0112), [G0114 Chimera](https://attack.mitre.org/groups/G0114) _(+15 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 88 software:** [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0151 HALFBAKED](https://attack.mitre.org/software/S0151), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0156 KOMPROGO](https://attack.mitre.org/software/S0156), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0241 RATANKBA](https://attack.mitre.org/software/S0241), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0256 Mosquito](https://attack.mitre.org/software/S0256), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0267 FELIXROOT](https://attack.mitre.org/software/S0267), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0339 Micropsia](https://attack.mitre.org/software/S0339), [S0340 Octopus](https://attack.mitre.org/software/S0340), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365) _(+64 more)_  

---

### T1053 — Scheduled Task/Job
<a id="t1053"></a>

**Tactics:** Execution, Persistence, Privilege Escalation · **Platforms:** Windows, Linux, macOS, Containers, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1053)  

Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `IA-8`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Cross-Platform Behavioral Detection of Scheduled Task/Job Abuse  
**Implemented by 1 software:** [S0447 Lokibot](https://attack.mitre.org/software/S0447)  

---

### T1053.002 — At
<a id="t1053002"></a>

sub-technique of [T1053](/techniques/execution.md#t1053) · **Tactics:** Execution, Persistence, Privilege Escalation · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1053/002)  

Adversaries may abuse the at utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Cross-Platform Detection of Scheduled Task/Job Abuse via `at` Utility  
**Used by 3 threat groups:** [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060)  
**Implemented by 3 software:** [S0110 at](https://attack.mitre.org/software/S0110), [S0233 MURKYTOP](https://attack.mitre.org/software/S0233), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488)  

---

### T1053.003 — Cron
<a id="t1053003"></a>

sub-technique of [T1053](/techniques/execution.md#t1053) · **Tactics:** Execution, Persistence, Privilege Escalation · **Platforms:** Linux, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1053/003)  

Adversaries may abuse the <code>cron</code> utility to perform task scheduling for initial or recurring execution of malicious code. The <code>cron</code> utility is a time-based job scheduler for Unix-like operating systems.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (9):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Cross-Platform Detection of Cron Job Abuse for Persistence and Execution  
**Used by 3 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G1023 APT5](https://attack.mitre.org/groups/G1023)  
**Implemented by 12 software:** [S0163 Janicab](https://attack.mitre.org/software/S0163), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0374 SpeakUp](https://attack.mitre.org/software/S0374), [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401), [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0588 GoldMax](https://attack.mitre.org/software/S0588), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S1107 NKAbuse](https://attack.mitre.org/software/S1107), [S1198 Gomir](https://attack.mitre.org/software/S1198)  

---

### T1053.005 — Scheduled Task
<a id="t1053005"></a>

sub-technique of [T1053](/techniques/execution.md#t1053) · **Tactics:** Execution, Persistence, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1053/005)  

Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `RA-5`, `SI-4`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1053005) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 54 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0075 Rancor](https://attack.mitre.org/groups/G0075), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080) _(+30 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 118 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0111 schtasks](https://attack.mitre.org/software/S0111), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0166 RemoteCMD](https://attack.mitre.org/software/S0166), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0189 ISMInjector](https://attack.mitre.org/software/S0189), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0237 GravityRAT](https://attack.mitre.org/software/S0237) _(+94 more)_  

---

### T1053.006 — Systemd Timers
<a id="t1053006"></a>

sub-technique of [T1053](/techniques/execution.md#t1053) · **Tactics:** Execution, Persistence, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1053/006)  

Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension <code>.timer</code> that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (10):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Systemd Timer Abuse for Scheduled Execution  

---

### T1053.007 — Container Orchestration Job
<a id="t1053007"></a>

sub-technique of [T1053](/techniques/execution.md#t1053) · **Tactics:** Execution, Persistence, Privilege Escalation · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1053/007)  

Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `IA-2`, `IA-8`  
**ATT&CK detection strategy:** Detection of Malicious Kubernetes CronJob Scheduling  

---

### T1059 — Command and Scripting Interpreter
<a id="t1059"></a>

**Tactics:** Execution · **Platforms:** ESXi, IaaS, Identity Provider, Linux, macOS, Network Devices, Office Suite, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059)  

Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.

**ATT&CK mitigations (9):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (23):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-8`, `IA-9`, `RA-5`, `SC-18`, `SI-10`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Command and Scripting Interpreter Abuse  
**Used by 17 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0107 Whitefly](https://attack.mitre.org/groups/G0107), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0124 Windigo](https://attack.mitre.org/groups/G0124), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035)  
**Implemented by 22 software:** [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0219 WINERACK](https://attack.mitre.org/software/S0219), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0374 SpeakUp](https://attack.mitre.org/software/S0374), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0460 Get2](https://attack.mitre.org/software/S0460), [S0486 Bonadan](https://attack.mitre.org/software/S0486), [S0487 Kessel](https://attack.mitre.org/software/S0487), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S0618 FIVEHANDS](https://attack.mitre.org/software/S0618), [S0695 Donut](https://attack.mitre.org/software/S0695), [S1110 SLIGHTPULSE](https://attack.mitre.org/software/S1110), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1151 ZeroCleare](https://attack.mitre.org/software/S1151), [S1154 VersaMem](https://attack.mitre.org/software/S1154), [S1192 NICECURL](https://attack.mitre.org/software/S1192), [S1227 StarProxy](https://attack.mitre.org/software/S1227)  

---

### T1059.001 — PowerShell
<a id="t1059001"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/001)  

Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code.

**ATT&CK mitigations (5):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (19):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `IA-8`, `IA-9`, `RA-5`, `SI-10`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1059001) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 83 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061) _(+59 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 124 software:** [S0037 HAMMERTOSS](https://attack.mitre.org/software/S0037), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0129 AutoIt backdoor](https://attack.mitre.org/software/S0129), [S0145 POWERSOURCE](https://attack.mitre.org/software/S0145), [S0150 POSHSPY](https://attack.mitre.org/software/S0150), [S0151 HALFBAKED](https://attack.mitre.org/software/S0151), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0186 DownPaper](https://attack.mitre.org/software/S0186), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0241 RATANKBA](https://attack.mitre.org/software/S0241), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0256 Mosquito](https://attack.mitre.org/software/S0256), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0269 QUADAGENT](https://attack.mitre.org/software/S0269), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0273 Socksbot](https://attack.mitre.org/software/S0273) _(+100 more)_  

---

### T1059.002 — AppleScript
<a id="t1059002"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/002)  

Adversaries may abuse AppleScript for execution. AppleScript is a macOS scripting language designed to control applications and parts of the OS via inter-application messages called AppleEvents. These AppleEvent messages can be sent independently or easily scripted with AppleScript.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045)  
**NIST 800-53 R5 controls (15):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-6`, `IA-9`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection of AppleScript-Based Execution on macOS  
**Implemented by 5 software:** [S0281 Dok](https://attack.mitre.org/software/S0281), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S1048 macOS.OSAMiner](https://attack.mitre.org/software/S1048), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153)  

---

### T1059.003 — Windows Command Shell
<a id="t1059003"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/003)  

Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (11):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-6`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Windows Command Shell Execution  
**Used by 71 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0028 Threat Group-1314](https://attack.mitre.org/groups/G0028), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0039 Suckfly](https://attack.mitre.org/groups/G0039), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060) _(+47 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 286 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0025 CALENDAR](https://attack.mitre.org/software/S0025), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0065 4H RAT](https://attack.mitre.org/software/S0065), [S0068 httpclient](https://attack.mitre.org/software/S0068), [S0069 BLACKCOFFEE](https://attack.mitre.org/software/S0069), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0071 hcdLoader](https://attack.mitre.org/software/S0071), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0080 Mivast](https://attack.mitre.org/software/S0080) _(+262 more)_  

---

### T1059.004 — Unix Shell
<a id="t1059004"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** ESXi, Linux, macOS, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/004)  

Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux, macOS, and ESXi systems, though many variations of the Unix shell exist (e.g. sh, ash, bash, zsh, etc.) depending on the specific OS or distribution.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (11):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-6`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Unix Shell Execution  
**Used by 10 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 45 software:** [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0077 CallMe](https://attack.mitre.org/software/S0077), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0220 Chaos](https://attack.mitre.org/software/S0220), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0369 CoinTicker](https://attack.mitre.org/software/S0369), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401), [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0410 Fysbis](https://attack.mitre.org/software/S0410), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0466 WindTail](https://attack.mitre.org/software/S0466), [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0502 Drovorub](https://attack.mitre.org/software/S0502), [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0600 Doki](https://attack.mitre.org/software/S0600), [S0601 Hildegard](https://attack.mitre.org/software/S0601) _(+21 more)_  

---

### T1059.005 — Visual Basic
<a id="t1059005"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/005)  

Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as Component Object Model and the Native API through the Windows API.

**ATT&CK mitigations (5):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (17):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-18`, `SI-10`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Visual Basic Execution (VBS/VBA/VBScript)  
**Used by 45 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0062 TA459](https://attack.mitre.org/groups/G0062), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0075 Rancor](https://attack.mitre.org/groups/G0075), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0090 WIRTE](https://attack.mitre.org/groups/G0090), [G0091 Silence](https://attack.mitre.org/groups/G0091) _(+21 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 67 software:** [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0228 NanHaiShu](https://attack.mitre.org/software/S0228), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0269 QUADAGENT](https://attack.mitre.org/software/S0269), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0343 Exaramel for Windows](https://attack.mitre.org/software/S0343), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0375 Remexi](https://attack.mitre.org/software/S0375), [S0380 StoneDrill](https://attack.mitre.org/software/S0380) _(+43 more)_  

---

### T1059.006 — Python
<a id="t1059006"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/006)  

Adversaries may abuse Python commands and scripts for execution. Python is a very popular scripting/programming language, with capabilities to perform many functions.

**ATT&CK mitigations (4):** [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (15):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `SI-10`, `SI-16`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Cross-Platform Behavioral Detection of Python Execution  
**Used by 17 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0095 Machete](https://attack.mitre.org/groups/G0095), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 34 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0276 Keydnap](https://attack.mitre.org/software/S0276), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0369 CoinTicker](https://attack.mitre.org/software/S0369), [S0374 SpeakUp](https://attack.mitre.org/software/S0374), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0459 MechaFlounder](https://attack.mitre.org/software/S0459), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0547 DropBook](https://attack.mitre.org/software/S0547), [S0581 IronNetInjector](https://attack.mitre.org/software/S0581), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0647 Turian](https://attack.mitre.org/software/S0647), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0695 Donut](https://attack.mitre.org/software/S0695), [S1032 PyDCrypt](https://attack.mitre.org/software/S1032) _(+10 more)_  

---

### T1059.007 — JavaScript
<a id="t1059007"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/007)  

Adversaries may abuse various implementations of JavaScript for execution. JavaScript (JS) is a platform-independent scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser.

**ATT&CK mitigations (4):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (16):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-18`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Cross-Platform Detection of JavaScript Execution Abuse  
**Used by 25 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1037 TA577](https://attack.mitre.org/groups/G1037), [G1038 TA578](https://attack.mitre.org/groups/G1038) _(+1 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 32 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0228 NanHaiShu](https://attack.mitre.org/software/S0228), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0417 GRIFFON](https://attack.mitre.org/software/S0417), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0634 EnvyScout](https://attack.mitre.org/software/S0634), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0646 SpicyOmelette](https://attack.mitre.org/software/S0646), [S0648 JSS Loader](https://attack.mitre.org/software/S0648), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S0695 Donut](https://attack.mitre.org/software/S0695), [S1075 KOPILUWAK](https://attack.mitre.org/software/S1075), [S1116 WARPWIRE](https://attack.mitre.org/software/S1116), [S1124 SocGholish](https://attack.mitre.org/software/S1124) _(+8 more)_  

---

### T1059.008 — Network Device CLI
<a id="t1059008"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/008)  

Adversaries may abuse scripting or built-in command line interpreters (CLI) on network devices to execute malicious command and payloads.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (15):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-8`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of CLI Abuse on Network Devices  
**Implemented by 1 software:** [S1186 Line Dancer](https://attack.mitre.org/software/S1186)  

---

### T1059.009 — Cloud API
<a id="t1059009"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** IaaS, Identity Provider, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/009)  

Adversaries may abuse cloud APIs to execute malicious commands. APIs available in cloud environments provide various functionalities and are a feature-rich method for programmatic access to nearly all aspects of a tenant.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (6):** `AC-2`, `AC-3`, `AC-6`, `CM-7`, `IA-2`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of Malicious Cloud API Scripting  
**Used by 3 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1059.010 — AutoHotKey & AutoIT
<a id="t1059010"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/010)  

Adversaries may execute commands and perform malicious tasks using AutoIT and AutoHotKey automation scripts. AutoIT and AutoHotkey (AHK) are scripting languages that enable users to automate Windows tasks.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for AutoHotKey & AutoIT Abuse  
**Used by 1 threat groups:** [G0087 APT39](https://attack.mitre.org/groups/G0087)  
**Implemented by 5 software:** [S0530 Melcoz](https://attack.mitre.org/software/S0530), [S1017 OutSteel](https://attack.mitre.org/software/S1017), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)  

---

### T1059.011 — Lua
<a id="t1059011"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** Linux, Network Devices, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/011)  

Adversaries may abuse Lua commands and scripts for execution. Lua is a cross-platform scripting and programming language primarily designed for embedded use in applications.

**ATT&CK mitigations (3):** [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (9):** `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-6`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Lua Scripting Abuse  
**Implemented by 5 software:** [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0396 EvilBunny](https://attack.mitre.org/software/S0396), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S1188 Line Runner](https://attack.mitre.org/software/S1188), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240)  

---

### T1059.012 — Hypervisor CLI
<a id="t1059012"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/012)  

Adversaries may abuse hypervisor command line interpreters (CLIs) to execute malicious commands. Hypervisor CLIs typically enable a wide variety of functionality for managing both the hypervisor itself and the guest virtual machines it hosts.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for ESXi Hypervisor CLI Abuse  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 3 software:** [S1073 Royal](https://attack.mitre.org/software/S1073), [S1096 Cheerscrypt](https://attack.mitre.org/software/S1096), [S1218 VIRTUALPIE](https://attack.mitre.org/software/S1218)  

---

### T1059.013 — Container CLI/API
<a id="t1059013"></a>

sub-technique of [T1059](/techniques/execution.md#t1059) · **Tactics:** Execution · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1059/013)  

Adversaries may abuse built-in CLI tools or API calls to execute malicious commands in containerized environments. The Docker CLI is used for managing containers via an exposed API point from the `dockerd` daemon.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Container CLI and API Abuse via Docker/Kubernetes (T1059.013)  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  

---

### T1072 — Software Deployment Tools
<a id="t1072"></a>

**Tactics:** Execution, Lateral Movement · **Platforms:** Linux, macOS, Network Devices, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1072)  

Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network. Configuration management and software deployment applications may be used in an enterprise network or cloud environment for routine administration purposes.

**ATT&CK mitigations (10):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (27):** `AC-12`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `SA-10`, `SA-9`, `SC-12`, `SC-17`, `SC-46`, `SC-7`, `SI-2`, `SI-23`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Adversary Abuse of Software Deployment Tools  
**Used by 6 threat groups:** [G0028 Threat Group-1314](https://attack.mitre.org/groups/G0028), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 1 software:** [S0041 Wiper](https://attack.mitre.org/software/S0041)  

---

### T1106 — Native API
<a id="t1106"></a>

**Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1106)  

Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (7):** `AC-6`, `CM-2`, `CM-6`, `CM-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of Native API Invocation via Unusual DLL Loads and Direct Syscalls  
**Used by 18 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 189 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0161 XAgentOSX](https://attack.mitre.org/software/S0161), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0256 Mosquito](https://attack.mitre.org/software/S0256), [S0259 InnaputRAT](https://attack.mitre.org/software/S0259), [S0260 InvisiMole](https://attack.mitre.org/software/S0260) _(+165 more)_  

---

### T1129 — Shared Modules
<a id="t1129"></a>

**Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1129)  

Adversaries may execute malicious payloads via loading shared modules. Shared modules are executable files that are loaded into processes to provide access to reusable code, such as specific custom functions or invoking OS API functions (i.e., Native API).

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (6):** `CM-2`, `CM-7`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavior-chain, platform-aware detection strategy for T1129 Shared Modules  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 21 software:** [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0415 BOOSTWRITE](https://attack.mitre.org/software/S0415), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0520 BLINDINGCAN](https://attack.mitre.org/software/S0520), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1154 VersaMem](https://attack.mitre.org/software/S1154), [S1185 LightSpy](https://attack.mitre.org/software/S1185)  

---

### T1203 — Exploitation for Client Execution
<a id="t1203"></a>

**Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1203)  

Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior.

**ATT&CK mitigations (3):** [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (16):** `AC-4`, `AC-6`, `CA-7`, `CM-8`, `SC-18`, `SC-2`, `SC-29`, `SC-3`, `SC-30`, `SC-39`, `SC-44`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Exploitation for Client Execution – cross-platform behavior chain (browser/Office/3rd-party apps)  
**Used by 41 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0005 APT12](https://attack.mitre.org/groups/G0005), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0062 TA459](https://attack.mitre.org/groups/G0062), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0066 Elderwood](https://attack.mitre.org/groups/G0066), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0089 The White Company](https://attack.mitre.org/groups/G0089) _(+17 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 14 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0243 DealersChoice](https://attack.mitre.org/software/S0243), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0374 SpeakUp](https://attack.mitre.org/software/S0374), [S0391 HAWKBALL](https://attack.mitre.org/software/S0391), [S0396 EvilBunny](https://attack.mitre.org/software/S0396), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0578 SUPERNOVA](https://attack.mitre.org/software/S0578), [S1065 Woody RAT](https://attack.mitre.org/software/S1065), [S1154 VersaMem](https://attack.mitre.org/software/S1154), [S1207 XLoader](https://attack.mitre.org/software/S1207)  

---

### T1204 — User Execution
<a id="t1204"></a>

**Tactics:** Execution · **Platforms:** Linux, Windows, macOS, IaaS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1204)  

An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of Phishing.

**ATT&CK mitigations (6):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (13):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-44`, `SC-7`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`, `SI-8`  
**ATT&CK detection strategy:** User Execution – multi-surface behavior chain (documents/links → helper/unpacker → LOLBIN/child → egress)  
**Used by 2 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  
**Implemented by 2 software:** [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)  

---

### T1204.001 — Malicious Link
<a id="t1204001"></a>

sub-technique of [T1204](/techniques/execution.md#t1204) · **Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1204/001)  

An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Link.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-44`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** User Execution – Malicious Link (click → suspicious egress → download/write → follow-on activity)  
**Used by 47 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0066 Elderwood](https://attack.mitre.org/groups/G0066), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0095 Machete](https://attack.mitre.org/groups/G0095) _(+23 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 28 software:** [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0435 PLEAD](https://attack.mitre.org/software/S0435), [S0436 TSCookie](https://attack.mitre.org/software/S0436), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0475 BackConfig](https://attack.mitre.org/software/S0475), [S0499 Hancitor](https://attack.mitre.org/software/S0499), [S0528 Javali](https://attack.mitre.org/software/S0528), [S0530 Melcoz](https://attack.mitre.org/software/S0530), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0561 GuLoader](https://attack.mitre.org/software/S0561), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0585 Kerrdown](https://attack.mitre.org/software/S0585), [S0644 ObliqueRAT](https://attack.mitre.org/software/S0644), [S0646 SpicyOmelette](https://attack.mitre.org/software/S0646), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669), [S1017 OutSteel](https://attack.mitre.org/software/S1017), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1030 Squirrelwaffle](https://attack.mitre.org/software/S1030), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1086 Snip3](https://attack.mitre.org/software/S1086) _(+4 more)_  

---

### T1204.002 — Malicious File
<a id="t1204002"></a>

sub-technique of [T1204](/techniques/execution.md#t1204) · **Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1204/002)  

An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Attachment.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (12):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-44`, `SC-7`, `SI-10`, `SI-3`, `SI-4`, `SI-7`, `SI-8`  
**ATT&CK detection strategy:** User Execution – Malicious File via download/open → spawn chain (T1204.002)  
**Used by 84 threat groups:** [G0005 APT12](https://attack.mitre.org/groups/G0005), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0013 APT30](https://attack.mitre.org/groups/G0013), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0048 RTM](https://attack.mitre.org/groups/G0048), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061) _(+60 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 90 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0340 Octopus](https://attack.mitre.org/software/S0340), [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0384 Dridex](https://attack.mitre.org/software/S0384), [S0389 JCry](https://attack.mitre.org/software/S0389), [S0390 SQLRat](https://attack.mitre.org/software/S0390), [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0433 Rifdoor](https://attack.mitre.org/software/S0433), [S0435 PLEAD](https://attack.mitre.org/software/S0435), [S0447 Lokibot](https://attack.mitre.org/software/S0447) _(+66 more)_  

---

### T1204.003 — Malicious Image
<a id="t1204003"></a>

sub-technique of [T1204](/techniques/execution.md#t1204) · **Tactics:** Execution · **Platforms:** IaaS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1204/003)  

Adversaries may rely on a user running a malicious image to facilitate execution. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be backdoored.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (16):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `RA-5`, `SC-44`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-7`, `SI-8`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** User Execution – Malicious Image (containers & IaaS) – pull/run → start → anomalous behavior (T1204.003)  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  

---

### T1204.004 — Malicious Copy and Paste
<a id="t1204004"></a>

sub-technique of [T1204](/techniques/execution.md#t1204) · **Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1204/004)  

An adversary may rely upon a user copying and pasting code in order to gain execution. Users may be subjected to social engineering to get them to copy and paste code directly into a Command and Scripting Interpreter.

**ATT&CK mitigations (3):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** User Execution – Malicious Copy & Paste (browser/email → shell with obfuscated one-liner) – T1204.004  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 1 software:** [S1229 Havoc](https://attack.mitre.org/software/S1229)  

---

### T1204.005 — Malicious Library
<a id="t1204005"></a>

sub-technique of [T1204](/techniques/execution.md#t1204) · **Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1204/005)  

Adversaries may rely on a user installing a malicious library to facilitate execution. Threat actors may Upload Malware to package managers such as NPM and PyPi, as well as to public code repositories such as GitHub.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** User-Initiated Malicious Library Installation via Package Manager (T1204.005)  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1559 — Inter-Process Communication
<a id="t1559"></a>

**Tactics:** Execution · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1559)  

Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution.

**ATT&CK mitigations (6):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (19):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-10`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SC-18`, `SC-3`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect Abuse of Inter-Process Communication (T1559)  
**Implemented by 14 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0537 HyperStack](https://attack.mitre.org/software/S0537), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1123 PITSTOP](https://attack.mitre.org/software/S1123), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1141 LunarWeb](https://attack.mitre.org/software/S1141), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1172 OilBooster](https://attack.mitre.org/software/S1172), [S1200 StealBit](https://attack.mitre.org/software/S1200), [S1229 Havoc](https://attack.mitre.org/software/S1229), [S1239 TONESHELL](https://attack.mitre.org/software/S1239), [S1244 Medusa Ransomware](https://attack.mitre.org/software/S1244)  

---

### T1559.001 — Component Object Model
<a id="t1559001"></a>

sub-technique of [T1559](/techniques/execution.md#t1559) · **Tactics:** Execution · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1559/001)  

Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `SC-18`, `SC-3`, `SC-7`, `SI-3`  
**ATT&CK detection strategy:** Detect Abuse of Component Object Model (T1559.001)  
**Used by 3 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 17 software:** [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0691 Neoichor](https://attack.mitre.org/software/S0691), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698), [S1015 Milan](https://attack.mitre.org/software/S1015), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1236 CLAIMLOADER](https://attack.mitre.org/software/S1236), [S1238 STATICPLUGIN](https://attack.mitre.org/software/S1238)  

---

### T1559.002 — Dynamic Data Exchange
<a id="t1559002"></a>

sub-technique of [T1559](/techniques/execution.md#t1559) · **Tactics:** Execution · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1559/002)  

Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications.

**ATT&CK mitigations (4):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (14):** `AC-4`, `AC-6`, `CM-10`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-18`, `SC-3`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect Abuse of Dynamic Data Exchange (T1559.002)  
**Used by 11 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0084 Gallmaker](https://attack.mitre.org/groups/G0084), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G1002 BITTER](https://attack.mitre.org/groups/G1002)  
**Implemented by 8 software:** [S0148 RTM](https://attack.mitre.org/software/S0148), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0391 HAWKBALL](https://attack.mitre.org/software/S0391), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0476 Valak](https://attack.mitre.org/software/S0476)  

---

### T1559.003 — XPC Services
<a id="t1559003"></a>

sub-technique of [T1559](/techniques/execution.md#t1559) · **Tactics:** Execution · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1559/003)  

Adversaries can provide malicious content to an XPC service daemon for local code execution. macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party application privileged helper tools.

**ATT&CK mitigations (1):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013)  
**NIST 800-53 R5 controls (7):** `CM-5`, `CM-6`, `CM-7`, `SA-10`, `SA-11`, `SA-8`, `SI-4`  
**ATT&CK detection strategy:** Detect Abuse of XPC Services (T1559.003)  

---

### T1569 — System Services
<a id="t1569"></a>

**Tactics:** Execution · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1569)  

Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services either locally or remotely.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for System Services across OS platforms.  

---

### T1569.001 — Launchctl
<a id="t1569001"></a>

sub-technique of [T1569](/techniques/execution.md#t1569) · **Tactics:** Execution · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1569/001)  

Adversaries may abuse launchctl to execute commands or programs. Launchctl interfaces with launchd, the service management framework for macOS. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-11`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection Strategy for System Services: Launchctl  
**Implemented by 6 software:** [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1048 macOS.OSAMiner](https://attack.mitre.org/software/S1048), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153)  

---

### T1569.002 — Service Execution
<a id="t1569002"></a>

sub-technique of [T1569](/techniques/execution.md#t1569) · **Tactics:** Execution · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1569/002)  

Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (<code>services.exe</code>) is an interface to manage and manipulate services.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for System Services Service Execution  
**Used by 16 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 51 software:** [S0029 PsExec](https://attack.mitre.org/software/S0029), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0039 Net](https://attack.mitre.org/software/S0039), [S0056 Net Crawler](https://attack.mitre.org/software/S0056), [S0123 xCmd](https://attack.mitre.org/software/S0123), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0166 RemoteCMD](https://attack.mitre.org/software/S0166), [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0191 Winexe](https://attack.mitre.org/software/S0191), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0238 Proxysvc](https://attack.mitre.org/software/S0238), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0398 HyperBro](https://attack.mitre.org/software/S0398) _(+27 more)_  

---

### T1569.003 — Systemctl
<a id="t1569003"></a>

sub-technique of [T1569](/techniques/execution.md#t1569) · **Tactics:** Execution · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1569/003)  

Adversaries may abuse systemctl to execute commands or programs. Systemctl is the primary interface for systemd, the Linux init system and service manager. Typically invoked from a shell, Systemctl can also be integrated into scripts or applications.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for System Services: Systemctl  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  

---

### T1609 — Container Administration Command
<a id="t1609"></a>

**Tactics:** Execution · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1609)  

Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-17`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Container Administration Command Abuse  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 4 software:** [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1648 — Serverless Execution
<a id="t1648"></a>

**Tactics:** Execution · **Platforms:** SaaS, IaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1648)  

Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments. Many cloud providers offer a variety of serverless resources, including compute engines, application integration services, and web servers.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-6`, `CM-6`, `CM-7`, `IA-2`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Serverless Execution (T1648)  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1651 — Cloud Administration Command
<a id="t1651"></a>

**Tactics:** Execution · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1651)  

Adversaries may abuse cloud management services to execute commands within virtual machines. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents.

**ATT&CK mitigations (1):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (6):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `IA-2`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Cloud Administration Command  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 2 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1674 — Input Injection
<a id="t1674"></a>

**Tactics:** Execution · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1674)  

Adversaries may simulate keystrokes on a victim’s computer by various means to perform any type of action on behalf of the user, such as launching the command interpreter using keyboard shortcuts, typing an inline script to be executed, or interacting directly with a GUI-based application.

**ATT&CK mitigations (2):** [M1034 Limit Hardware Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1034), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Input Injection  
**Used by 1 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046)  

---

### T1675 — ESXi Administration Command
<a id="t1675"></a>

**Tactics:** Execution · **Platforms:** ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1675)  

Adversaries may abuse ESXi administration services to execute commands on guest machines hosted within an ESXi virtual environment. Persistent background services on ESXi-hosted VMs, such as the VMware Tools Daemon Service, allow for remote management from the ESXi server.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for ESXi Administration Command  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 1 software:** [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217)  

---

### T1677 — Poisoned Pipeline Execution
<a id="t1677"></a>

**Tactics:** Execution · **Platforms:** SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1677)  

Adversaries may manipulate continuous integration / continuous development (CI/CD) processes by injecting malicious code into the build process.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Poisoned Pipeline Execution via SaaS CI/CD Workflows  

---

