# Defense Impairment: Technique Detail

> Full detail pages for the 56 ATT&CK techniques whose primary tactic is [Defense Impairment](https://attack.mitre.org/tactics/TA0112/) (ATT&CK Enterprise v19.2). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1112: Modify Registry
<a id="t1112"></a>

Tactics: Defense Impairment, Persistence, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1112)  

Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution. Access to specific areas of the Registry depends on account permissions, with some keys requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification. Other tools, such as remote access tools, may also contain functionality to interact with the Registry through the Windows API. The Registry may be modified in order to hide configuration information or malicious payloads via [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027). The Registry may also be modified to impair defenses, such as by enabling macros for all Microsoft Office products, allowing privilege escalation without alerting the user, increasing the maximum number of allowed outbound requests, and/or modifying systems to store plaintext credentials in memory. The Registry of a remote system may be modified to aid in execution of files as part of lateral movement. It requires the remote Registry service to be running on the target system. Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) for RPC communication. Finally, Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API. Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to maintain persistence.

ATT&CK mitigations (1): [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
NIST 800-53 R5 controls (3): `AC-6`, `CM-7`, `SI-7`  
ATT&CK detection strategy: Behavior-Based Registry Modification Detection on Windows  
Used by 29 threat groups: [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
Implemented by 139 software: [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0019 Regin](https://attack.mitre.org/software/S0019), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0075 Reg](https://attack.mitre.org/software/S0075), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0142 StreamEx](https://attack.mitre.org/software/S0142), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0157 SOUNDBITE](https://attack.mitre.org/software/S0157), [S0158 PHOREAL](https://attack.mitre.org/software/S0158), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0205 Naid](https://attack.mitre.org/software/S0205), [S0210 Nerex](https://attack.mitre.org/software/S0210), [S0229 Orz](https://attack.mitre.org/software/S0229), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0245 BADCALL](https://attack.mitre.org/software/S0245), [S0254 PLAINTEE](https://attack.mitre.org/software/S0254), [S0256 Mosquito](https://attack.mitre.org/software/S0256), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0261 Catchamas](https://attack.mitre.org/software/S0261), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0267 FELIXROOT](https://attack.mitre.org/software/S0267), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0269 QUADAGENT](https://attack.mitre.org/software/S0269), [S0271 KEYMARBLE](https://attack.mitre.org/software/S0271), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0343 Exaramel for Windows](https://attack.mitre.org/software/S0343), [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348), [S0350 zwShell](https://attack.mitre.org/software/S0350), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0397 LoJax](https://attack.mitre.org/software/S0397), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0441 PowerShower](https://attack.mitre.org/software/S0441), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0511 RegDuke](https://attack.mitre.org/software/S0511), [S0517 Pillowmint](https://attack.mitre.org/software/S0517), [S0518 PolyglotDuke](https://attack.mitre.org/software/S0518), [S0527 CSPY Downloader](https://attack.mitre.org/software/S0527), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0533 SLOTHFULMEDIA](https://attack.mitre.org/software/S0533), [S0537 HyperStack](https://attack.mitre.org/software/S0537), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0560 TEARDROP](https://attack.mitre.org/software/S0560), [S0568 EVILNUM](https://attack.mitre.org/software/S0568), [S0569 Explosive](https://attack.mitre.org/software/S0569), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0572 Caterpillar WebShell](https://attack.mitre.org/software/S0572), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0579 Waterbear](https://attack.mitre.org/software/S0579), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0589 Sibot](https://attack.mitre.org/software/S0589), [S0596 ShadowPad](https://attack.mitre.org/software/S0596), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0660 Clambling](https://attack.mitre.org/software/S0660), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S0664 Pandora](https://attack.mitre.org/software/S0664), [S0665 ThreatNeedle](https://attack.mitre.org/software/S0665), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0668 TinyTurla](https://attack.mitre.org/software/S0668), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S0674 CharmPower](https://attack.mitre.org/software/S0674), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S0679 Ferocious](https://attack.mitre.org/software/S0679), [S0691 Neoichor](https://attack.mitre.org/software/S0691), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1011 Tarrask](https://attack.mitre.org/software/S1011), [S1025 Amadey](https://attack.mitre.org/software/S1025), [S1033 DCSrv](https://attack.mitre.org/software/S1033), [S1047 Mori](https://attack.mitre.org/software/S1047), [S1050 PcShare](https://attack.mitre.org/software/S1050), [S1058 Prestige](https://attack.mitre.org/software/S1058), [S1059 metaMain](https://attack.mitre.org/software/S1059), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1090 NightClub](https://attack.mitre.org/software/S1090), [S1099 Samurai](https://attack.mitre.org/software/S1099), [S1131 NPPSPY](https://attack.mitre.org/software/S1131), [S1132 IPsec Helper](https://attack.mitre.org/software/S1132), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180), [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181), [S1190 Kapeka](https://attack.mitre.org/software/S1190), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1226 BOOKWORM](https://attack.mitre.org/software/S1226), [S1230 HIUPAN](https://attack.mitre.org/software/S1230), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1247 Embargo](https://attack.mitre.org/software/S1247), [S9023 HiddenFace](https://attack.mitre.org/software/S9023), [S9025 NOOPLDR](https://attack.mitre.org/software/S9025), [S9032 MuddyViper](https://attack.mitre.org/software/S9032)  

---

### T1207: Rogue Domain Controller
<a id="t1207"></a>

Tactics: Defense Impairment, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1207)  

Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC. Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys. Registering a rogue DC involves creating a new server and nTDSDSA objects in the Configuration partition of the AD schema, which requires Administrator privileges (either Domain or local to the DC) or the KRBTGT hash. This technique may bypass system logging and security monitors such as security information and event management (SIEM) products (since actions taken on a rogue DC may not be reported to these sensors). The technique may also be used to alter and delete replication and other associated metadata to obstruct forensic analysis. Adversaries may also utilize this technique to perform [SID-History Injection](https://attack.mitre.org/techniques/T1134/005) and/or manipulate AD objects (such as accounts, access control lists, schemas) to establish backdoors for Persistence.

ATT&CK mitigations: none mapped  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Rogue Domain Controller (DCShadow) Registration and Replication Abuse  
Implemented by 1 software: [S0002 Mimikatz](https://attack.mitre.org/software/S0002)  

---

### T1222: File and Directory Permissions Modification
<a id="t1222"></a>

Tactics: Defense Impairment, Platforms: ESXi, Linux, macOS, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1222)  

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.). Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory’s existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037), [Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004), or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574). Adversaries may also change permissions of symbolic links. For example, malware (particularly ransomware) may modify symbolic links and associated settings to enable access to files from local shortcuts with remote paths.

ATT&CK mitigations (2): [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
NIST 800-53 R5 controls (11): `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Multi-Platform File and Directory Permissions Modification Detection Strategy  
Implemented by 1 software: [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1222.001: Windows Permissions
<a id="t1222001"></a>

sub-technique of [T1222](/techniques/defense-impairment.md#t1222), Tactics: Defense Impairment, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1222/001)  

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.). Windows implements file and directory ACLs as Discretionary Access Control Lists (DACLs). Similar to a standard ACL, DACLs identifies the accounts that are allowed or denied access to a securable object. When an attempt is made to access a securable object, the system checks the access control entries in the DACL in order. If a matching entry is found, access to the object is granted. Otherwise, access is denied. Adversaries can interact with the DACLs using built-in Windows commands, such as `icacls`, `cacls`, `takeown`, and `attrib`, which can grant adversaries higher permissions on specific files and folders. Further, [PowerShell](https://attack.mitre.org/techniques/T1059/001) provides cmdlets that can be used to retrieve or modify file and directory DACLs. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037), or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).

ATT&CK mitigations (2): [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
NIST 800-53 R5 controls (11): `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Windows DACL Manipulation Behavioral Chain Detection Strategy  
Used by 2 threat groups: [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  
Implemented by 10 software: [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0693 CaddyWiper](https://attack.mitre.org/software/S0693), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180), [S9002 Diskpart](https://attack.mitre.org/software/S9002)  

---

### T1222.002: Linux and Mac Permissions
<a id="t1222002"></a>

sub-technique of [T1222](/techniques/defense-impairment.md#t1222), Tactics: Defense Impairment, Platforms: macOS, Linux, [ATT&CK](https://attack.mitre.org/techniques/T1222/002)  

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.). Most Linux and Linux-based platforms provide a standard set of permission groups (user, group, and other) and a standard set of permissions (read, write, and execute) that are applied to each group. While nuances of each platform’s permissions implementation may vary, most of the platforms provide two primary commands used to manipulate file and directory ACLs: <code>chown</code> (short for change owner), and <code>chmod</code> (short for change mode). Adversarial may use these commands to make themselves the owner of files and directories or change the mode if current permissions allow it. They could subsequently lock others out of the file. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004) or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).

ATT&CK mitigations (2): [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
NIST 800-53 R5 controls (11): `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Unix-like File Permission Manipulation Behavioral Chain Detection Strategy  
Used by 3 threat groups: [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
Implemented by 11 software: [S0281 Dok](https://attack.mitre.org/software/S0281), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1105 COATHANGER](https://attack.mitre.org/software/S1105), [S9013 DRYHOOK](https://attack.mitre.org/software/S9013)  

---

### T1484: Domain or Tenant Policy Modification
<a id="t1484"></a>

Tactics: Defense Impairment, Privilege Escalation, Platforms: Windows, Identity Provider, [ATT&CK](https://attack.mitre.org/techniques/T1484)  

Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments. Such services provide a centralized means of managing identity resources such as devices and accounts, and often include configuration settings that may apply between domains or tenants such as trust relationships, identity syncing, or identity federation. Modifications to domain or tenant settings may include altering domain Group Policy Objects (GPOs) in Microsoft Active Directory (AD) or changing trust settings for domains, including federation trusts relationships between domains or tenants. With sufficient permissions, adversaries can modify domain or tenant policy settings. Since configuration settings for these services apply to a large number of identity resources, there are a great number of potential attacks malicious outcomes that can stem from this abuse. Examples of such abuse include: * modifying GPOs to push a malicious [Scheduled Task](https://attack.mitre.org/techniques/T1053/005) to computers throughout the domain environment * modifying domain trusts to include an adversary-controlled domain, allowing adversaries to forge access tokens that will subsequently be accepted by victim domain resources * changing configuration settings within the AD environment to implement a [Rogue Domain Controller](https://attack.mitre.org/techniques/T1207). * adding new, adversary-controlled federated identity providers to identity tenants, allowing adversaries to authenticate as any user managed by the victim tenant Adversaries may temporarily modify domain or tenant policy, carry out a malicious action(s), and then revert the change to remove suspicious indicators.

ATT&CK mitigations (3): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (12): `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `RA-5`, `SI-4`  
ATT&CK detection strategy: Detection of Domain or Tenant Policy Modifications via AD and Identity Provider  

---

### T1484.001: Group Policy Modification
<a id="t1484001"></a>

sub-technique of [T1484](/techniques/defense-impairment.md#t1484), Tactics: Defense Impairment, Privilege Escalation, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1484/001)  

Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predictable network path `\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`. Like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs. It is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain. Malicious GPO modifications can be used to implement many other malicious behaviors such as [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Disable or Modify Tools](https://attack.mitre.org/techniques/T1685), [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105), [Create Account](https://attack.mitre.org/techniques/T1136), [Service Execution](https://attack.mitre.org/techniques/T1569/002), and more. Since GPOs can control so many user and machine settings in the AD environment, there are a great number of potential attacks that can stem from this GPO abuse. For example, publicly available scripts such as <code>New-GPOImmediateTask</code> can be leveraged to automate the creation of a malicious [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) by modifying GPO settings, in this case modifying <code>&lt;GPO_PATH&gt;\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml</code>. In some cases an adversary might modify specific user rights like SeEnableDelegationPrivilege, set in <code>&lt;GPO_PATH&gt;\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf</code>, to achieve a subtle AD backdoor with complete control of the domain because the user account under the adversary's control would then be able to modify GPOs.

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Group Policy Modifications via AD Object Changes and File Activity  
Used by 5 threat groups: [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053), [G1055 VOID MANTICORE](https://attack.mitre.org/groups/G1055)  
Implemented by 8 software: [S0363 Empire](https://attack.mitre.org/software/S0363), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1058 Prestige](https://attack.mitre.org/software/S1058), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1484.002: Trust Modification
<a id="t1484002"></a>

sub-technique of [T1484](/techniques/defense-impairment.md#t1484), Tactics: Defense Impairment, Privilege Escalation, Platforms: Identity Provider, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1484/002)  

Adversaries may add new domain trusts, modify the properties of existing domain trusts, or otherwise change the configuration of trust relationships between domains and tenants to evade defenses and/or elevate privileges.Trust details, such as whether or not user identities are federated, allow authentication and authorization properties to apply between domains or tenants for the purpose of accessing shared resources. These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains. Manipulating these trusts may allow an adversary to escalate privileges and/or evade defenses by modifying settings to add objects which they control. For example, in Microsoft Active Directory (AD) environments, this may be used to forge [SAML Tokens](https://attack.mitre.org/techniques/T1606/002) without the need to compromise the signing certificate to forge new credentials. Instead, an adversary can manipulate domain trusts to add their own signing certificate. An adversary may also convert an AD domain to a federated domain using Active Directory Federation Services (AD FS), which may enable malicious trust modifications such as altering the claim issuance rules to log in any valid set of credentials as a specified user. An adversary may also add a new federated identity provider to an identity tenant such as Okta or AWS IAM Identity Center, which may enable the adversary to authenticate as any user of the tenant. This may enable the threat actor to gain broad access into a variety of cloud-based services that leverage the identity tenant. For example, in AWS environments, an adversary that creates a new identity provider for an AWS Organization will be able to federate into all of the AWS Organization member accounts without creating identities for each of the member accounts.

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Trust Relationship Modifications in Domain or Tenant Policies  
Used by 2 threat groups: [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
Implemented by 1 software: [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1553: Subvert Trust Controls
<a id="t1553"></a>

Tactics: Defense Impairment, Platforms: Windows, macOS, Linux, [ATT&CK](https://attack.mitre.org/techniques/T1553)  

Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site. Adversaries may attempt to subvert these trust mechanisms. The method adversaries use will depend on the specific mechanism they seek to subvert. Adversaries may conduct [File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222) or [Modify Registry](https://attack.mitre.org/techniques/T1112) in support of subverting these controls. Adversaries may also create or steal code signing certificates to acquire trust on target systems.

ATT&CK mitigations (5): [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls (20): `AC-2`, `AC-3`, `AC-6`, `CM-10`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-7`, `IA-9`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-10`, `SI-2`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Subversion of Trust Controls via Certificate, Registry, and Attribute Manipulation  
Used by 1 threat groups: [G0001 Axiom](https://attack.mitre.org/groups/G0001)  
Implemented by 1 software: [S9008 Shai-Hulud](https://attack.mitre.org/software/S9008)  

---

### T1553.001: Gatekeeper Bypass
<a id="t1553001"></a>

sub-technique of [T1553](/techniques/defense-impairment.md#t1553), Tactics: Defense Impairment, Platforms: macOS, [ATT&CK](https://attack.mitre.org/techniques/T1553/001)  

Adversaries may modify file attributes and subvert Gatekeeper functionality to evade user prompts and execute untrusted programs. Gatekeeper is a set of technologies that act as layer of Apple’s security model to ensure only trusted applications are executed on a host. Gatekeeper was built on top of File Quarantine in Snow Leopard (10.6, 2009) and has grown to include Code Signing, security policy compliance, Notarization, and more. Gatekeeper also treats applications running for the first time differently than reopened applications. Based on an opt-in system, when files are downloaded an extended attribute (xattr) called `com.apple.quarantine` (also known as a quarantine flag) can be set on the file by the application performing the download. Launch Services opens the application in a suspended state. For first run applications with the quarantine flag set, Gatekeeper executes the following functions: 1. Checks extended attribute – Gatekeeper checks for the quarantine flag, then provides an alert prompt to the user to allow or deny execution. 2. Checks System Policies - Gatekeeper checks the system security policy, allowing execution of apps downloaded from either just the App Store or the App Store and identified developers. 3. Code Signing – Gatekeeper checks for a valid code signature from an Apple Developer ID. 4. Notarization - Using the `api.apple-cloudkit.com` API, Gatekeeper reaches out to Apple servers to verify or pull down the notarization ticket and ensure the ticket is not revoked. Users can override notarization, which will result in a prompt of executing an “unauthorized app” and the security policy will be modified. Adversaries can subvert one or multiple security controls within Gatekeeper checks through logic errors (e.g. [Exploitation for Stealth](https://attack.mitre.org/techniques/T1211)), unchecked file types, and external libraries. For example, prior to macOS 13 Ventura, code signing and notarization checks were only conducted on first launch, allowing adversaries to write malicious executables to previously opened applications in order to bypass Gatekeeper security checks. Applications and files loaded onto the system from a USB flash drive, optical disk, external hard drive, from a drive shared over the local network, or using the curl command may not set the quarantine flag. Additionally, it is possible to avoid setting the quarantine flag using [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).

ATT&CK mitigations (1): [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
NIST 800-53 R5 controls (6): `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Gatekeeper Bypass via Quarantine Flag and Trust Control Manipulation  
Implemented by 6 software: [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0369 CoinTicker](https://attack.mitre.org/software/S0369), [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153)  

---

### T1553.002: Code Signing
<a id="t1553002"></a>

sub-technique of [T1553](/techniques/defense-impairment.md#t1553), Tactics: Defense Impairment, Platforms: macOS, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1553/002)  

Adversaries may create, acquire, or steal code signing materials to sign their malware or tools. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. The certificates used during an operation may be created, acquired, or stolen by the adversary. Unlike [Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001), this activity will result in a valid signature. Code signing to verify software on first run can be used on modern Windows and macOS systems. It is not used on Linux due to the decentralized nature of the platform. Code signing certificates may be used to bypass security policies that require signed code to execute on a system.

ATT&CK mitigations: none mapped  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detect Suspicious or Malicious Code Signing Abuse  
Used by 28 threat groups: [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0039 Suckfly](https://attack.mitre.org/groups/G0039), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0044 Winnti Group](https://attack.mitre.org/groups/G0044), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1054 MirrorFace](https://attack.mitre.org/groups/G1054), [G1056 TeamPCP](https://attack.mitre.org/groups/G1056)  
Implemented by 53 software: [S0091 Epic](https://attack.mitre.org/software/S0091), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0163 Janicab](https://attack.mitre.org/software/S0163), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0210 Nerex](https://attack.mitre.org/software/S0210), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0284 More_eggs](https://attack.mitre.org/software/S0284), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0415 BOOSTWRITE](https://attack.mitre.org/software/S0415), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0475 BackConfig](https://attack.mitre.org/software/S0475), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0520 BLINDINGCAN](https://attack.mitre.org/software/S0520), [S0527 CSPY Downloader](https://attack.mitre.org/software/S0527), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0624 Ecipekac](https://attack.mitre.org/software/S0624), [S0646 SpicyOmelette](https://attack.mitre.org/software/S0646), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1151 ZeroCleare](https://attack.mitre.org/software/S1151), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1196 Troll Stealer](https://attack.mitre.org/software/S1196), [S1197 GoBear](https://attack.mitre.org/software/S1197), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1226 BOOKWORM](https://attack.mitre.org/software/S1226), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1232 SplatDropper](https://attack.mitre.org/software/S1232), [S1233 PAKLOG](https://attack.mitre.org/software/S1233), [S1235 CorKLOG](https://attack.mitre.org/software/S1235), [S1238 STATICPLUGIN](https://attack.mitre.org/software/S1238), [S1239 TONESHELL](https://attack.mitre.org/software/S1239), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S9024 SPAWNCHIMERA](https://attack.mitre.org/software/S9024)  

---

### T1553.003: SIP and Trust Provider Hijacking
<a id="t1553003"></a>

sub-technique of [T1553](/techniques/defense-impairment.md#t1553), Tactics: Defense Impairment, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1553/003)  

Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks. In user mode, Windows Authenticode digital signatures are used to verify a file's origin and integrity, variables that may be used to establish trust in signed code (ex: a driver with a valid Microsoft signature may be handled as safe). The signature validation process is handled via the WinVerifyTrust application programming interface (API) function, which accepts an inquiry and coordinates with the appropriate trust provider, which is responsible for validating parameters of a signature. Because of the varying executable file types and corresponding signature formats, Microsoft created software components called Subject Interface Packages (SIPs) to provide a layer of abstraction between API functions and files. SIPs are responsible for enabling API functions to create, retrieve, calculate, and verify signatures. Unique SIPs exist for most file formats (Executable, PowerShell, Installer, etc., with catalog signing providing a catch-all) and are identified by globally unique identifiers (GUIDs). Similar to [Code Signing](https://attack.mitre.org/techniques/T1553/002), adversaries may abuse this architecture to subvert trust controls and bypass security policies that allow only legitimately signed code to execute on a system. Adversaries may hijack SIP and trust provider components to mislead operating system and application control tools to classify malicious (or any) code as signed by: * Modifying the <code>Dll</code> and <code>FuncName</code> Registry values in <code>HKLM\SOFTWARE[\WOW6432Node\]Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{SIP_GUID}</code> that point to the dynamic link library (DLL) providing a SIP’s CryptSIPDllGetSignedDataMsg function, which retrieves an encoded digital certificate from a signed file. By pointing to a maliciously-crafted DLL with an exported function that always returns a known good signature value (ex: a Microsoft signature for Portable Executables) rather than the file’s real signature, an adversary can apply an acceptable signature value to all files using that SIP (although a hash mismatch will likely occur, invalidating the signature, since the hash returned by the function will not match the value computed from the file). * Modifying the <code>Dll</code> and <code>FuncName</code> Registry values in <code>HKLM\SOFTWARE\[WOW6432Node\]Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{SIP_GUID}</code> that point to the DLL providing a SIP’s CryptSIPDllVerifyIndirectData function, which validates a file’s computed hash against the signed hash value. By pointing to a maliciously-crafted DLL with an exported function that always returns TRUE (indicating that the validation was successful), an adversary can successfully validate any file (with a legitimate signature) using that SIP (with or without hijacking the previously mentioned CryptSIPDllGetSignedDataMsg function). This Registry value could also be redirected to a suitable exported function from an already present DLL, avoiding the requirement to drop and execute a new file on disk. * Modifying the <code>DLL</code> and <code>Function</code> Registry values in <code>HKLM\SOFTWARE\[WOW6432Node\]Microsoft\Cryptography\Providers\Trust\FinalPolicy\{trust provider GUID}</code> that point to the DLL providing a trust provider’s FinalPolicy function, which is where the decoded and parsed signature is checked and the majority of trust decisions are made. Similar to hijacking SIP’s CryptSIPDllVerifyIndirectData function, this value can be redirected to a suitable exported function from an already present DLL or a maliciously-crafted DLL (though the implementation of a trust provider is complex). * Note: The above hijacks are also possible without modifying the Registry via [DLL](https://attack.mitre.org/techniques/T1574/001) search order hijacking. Hijacking SIP or trust provider components can also enable persistent code execution, since these malicious components may be invoked by any application that performs code signing or signature validation.

ATT&CK mitigations (3): [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
NIST 800-53 R5 controls (10): `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detection Strategy for Subvert Trust Controls using SIP and Trust Provider Hijacking.  

---

### T1553.004: Install Root Certificate
<a id="t1553004"></a>

sub-technique of [T1553](/techniques/defense-impairment.md#t1553), Tactics: Defense Impairment, Platforms: Linux, macOS, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1553/004)  

Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website. Installation of a root certificate on a compromised system would give an adversary a way to degrade the security of that system. Adversaries have used this technique to avoid security warnings prompting users when compromised systems connect over HTTPS to adversary controlled web servers that spoof legitimate websites in order to collect login credentials. Atypical root certificates have also been pre-installed on systems by the manufacturer or in the software supply chain and were used in conjunction with malware/adware to provide [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) capability for intercepting information transmitted over secure TLS/SSL communications. Root certificates (and their associated chains) can also be cloned and reinstalled. Cloned certificate chains will carry many of the same metadata characteristics of the source and can be used to sign malicious code that may then bypass signature validation tools (ex: Sysinternals, antivirus, etc.) used to block execution and/or uncover artifacts of Persistence. In macOS, the Ay MaMi malware uses <code>/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /path/to/malicious/cert</code> to install a malicious certificate as a trusted root certificate into the system keychain.

ATT&CK mitigations (2): [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls (6): `CM-10`, `CM-6`, `CM-7`, `IA-9`, `SC-20`, `SI-4`  
ATT&CK detection strategy: Detection Strategy for Subvert Trust Controls via Install Root Certificate.  
Implemented by 5 software: [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0160 certutil](https://attack.mitre.org/software/S0160), [S0281 Dok](https://attack.mitre.org/software/S0281), [S9003 evilginx2](https://attack.mitre.org/software/S9003)  

---

### T1553.005: Mark-of-the-Web Bypass
<a id="t1553005"></a>

sub-technique of [T1553](/techniques/defense-impairment.md#t1553), Tactics: Defense Impairment, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1553/005)  

Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls. In Windows, when files are downloaded from the Internet, they are tagged with a hidden NTFS Alternate Data Stream (ADS) named <code>Zone.Identifier</code> with a specific value known as the MOTW. Files that are tagged with MOTW are protected and cannot perform certain actions. For example, starting in MS Office 10, if a MS Office file has the MOTW, it will open in Protected View. Executables tagged with the MOTW will be processed by Windows Defender SmartScreen that compares files with an allowlist of well-known executables. If the file is not known/trusted, SmartScreen will prevent the execution and warn the user not to run it. Adversaries may abuse container files such as compressed/archive (.arj,.gzip) and/or disk image (.iso,.vhd) file formats to deliver malicious payloads that may not be tagged with MOTW. Container files downloaded from the Internet will be marked with MOTW but the files within may not inherit the MOTW after the container files are extracted and/or mounted. MOTW is a NTFS feature and many container files do not support NTFS alternative data streams. After a container file is extracted and/or mounted, the files contained within them may be treated as local files on disk and run without protections.

ATT&CK mitigations (2): [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
NIST 800-53 R5 controls (6): `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Mark-of-the-Web (MOTW) Bypass via Container and Disk Image Files  
Used by 3 threat groups: [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092)  
Implemented by 2 software: [S0650 QakBot](https://attack.mitre.org/software/S0650), [S1025 Amadey](https://attack.mitre.org/software/S1025)  

---

### T1553.006: Code Signing Policy Modification
<a id="t1553006"></a>

sub-technique of [T1553](/techniques/defense-impairment.md#t1553), Tactics: Defense Impairment, Platforms: Windows, macOS, [ATT&CK](https://attack.mitre.org/techniques/T1553/006)  

Adversaries may modify code signing policies to enable execution of unsigned or self-signed code. Code signing provides a level of authenticity on a program from a developer and a guarantee that the program has not been tampered with. Security controls can include enforcement mechanisms to ensure that only valid, signed code can be run on an operating system. Some of these security controls may be enabled by default, such as Driver Signature Enforcement (DSE) on Windows or System Integrity Protection (SIP) on macOS. Other such controls may be disabled by default but are configurable through application controls, such as only allowing signed Dynamic-Link Libraries (DLLs) to execute on a system. Since it can be useful for developers to modify default signature enforcement policies during the development and testing of applications, disabling of these features may be possible with elevated permissions. Adversaries may modify code signing policies in a number of ways, including through use of command-line or GUI utilities, [Modify Registry](https://attack.mitre.org/techniques/T1112), rebooting the computer in a debug/recovery mode, or by altering the value of variables in kernel memory. Examples of commands that can modify the code signing policy of a system include <code>bcdedit.exe -set TESTSIGNING ON</code> on Windows and <code>csrutil disable</code> on macOS. Depending on the implementation, successful modification of a signing policy may require reboot of the compromised system. Additionally, some implementations can introduce visible artifacts for the user (ex: a watermark in the corner of the screen stating the system is in Test Mode). Adversaries may attempt to remove such artifacts. To gain access to kernel memory to modify variables related to signature checks, such as modifying <code>g_CiOptions</code> to disable Driver Signature Enforcement, adversaries may conduct [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) using a signed, but vulnerable driver.

ATT&CK mitigations (3): [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
NIST 800-53 R5 controls (13): `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-7`, `CM-8`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-7`  
ATT&CK detection strategy: Detect Code Signing Policy Modification (Windows & macOS)  
Used by 2 threat groups: [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0087 APT39](https://attack.mitre.org/groups/G0087)  
Implemented by 3 software: [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0664 Pandora](https://attack.mitre.org/software/S0664)  

---

### T1556: Modify Authentication Process
<a id="t1556"></a>

Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Windows, Linux, macOS, Network Devices, IaaS, SaaS, Office Suite, Identity Provider, [ATT&CK](https://attack.mitre.org/techniques/T1556)  

Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using [Valid Accounts](https://attack.mitre.org/techniques/T1078). Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.

ATT&CK mitigations (9): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (17): `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-13`, `IA-2`, `IA-5`, `SC-39`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Modification of Authentication Processes Across Platforms  
Used by 1 threat groups: [G1016 FIN13](https://attack.mitre.org/groups/G1016)  
Implemented by 4 software: [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0487 Kessel](https://attack.mitre.org/software/S0487), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S9013 DRYHOOK](https://attack.mitre.org/software/S9013)  

---

### T1556.001: Domain Controller Authentication
<a id="t1556001"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1556/001)  

Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts. Malware may be used to inject false credentials into the authentication process on a domain controller with the intent of creating a backdoor used to access any user’s account and/or credentials (ex: [Skeleton Key](https://attack.mitre.org/software/S0007)). Skeleton key works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system. Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the the skeleton key is erased from memory by a reboot of the domain controller). Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments.

ATT&CK mitigations (4): [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
NIST 800-53 R5 controls (14): `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-39`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Domain Controller Authentication Process Modification (Skeleton Key)  
Used by 1 threat groups: [G0114 Chimera](https://attack.mitre.org/groups/G0114)  
Implemented by 1 software: [S0007 Skeleton Key](https://attack.mitre.org/software/S0007)  

---

### T1556.002: Password Filter DLL
<a id="t1556002"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1556/002)  

Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts. Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter. Any potential changes cannot take effect until every registered filter acknowledges validation. Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains. To perform proper validation, filters must receive plain-text credentials from the LSA. A malicious password filter would receive these plain-text credentials every time a password request is made.

ATT&CK mitigations (1): [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
NIST 800-53 R5 controls (3): `CM-6`, `CM-7`, `SI-4`  
ATT&CK detection strategy: Detect Malicious Password Filter DLL Registration  
Used by 3 threat groups: [G0041 Strider](https://attack.mitre.org/groups/G0041), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G1054 MirrorFace](https://attack.mitre.org/groups/G1054)  
Implemented by 1 software: [S0125 Remsec](https://attack.mitre.org/software/S0125)  

---

### T1556.003: Pluggable Authentication Modules
<a id="t1556003"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Linux, macOS, [ATT&CK](https://attack.mitre.org/techniques/T1556/003)  

Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is <code>pam_unix.so</code>, which retrieves, sets, and verifies account authentication information in <code>/etc/passwd</code> and <code>/etc/shadow</code>. Adversaries may modify components of the PAM system to create backdoors. PAM components, such as <code>pam_unix.so</code>, can be patched to accept arbitrary adversary supplied values as legitimate credentials. Malicious modifications to the PAM system may also be abused to steal credentials. Adversaries may infect PAM resources with code to harvest user credentials, since the values exchanged with PAM components may be plain-text since PAM does not store passwords.

ATT&CK mitigations (2): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
NIST 800-53 R5 controls (12): `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Malicious Modification of Pluggable Authentication Modules (PAM)  
Implemented by 2 software: [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0468 Skidmap](https://attack.mitre.org/software/S0468)  

---

### T1556.004: Network Device Authentication
<a id="t1556004"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1556/004)  

Adversaries may use [Patch System Image](https://attack.mitre.org/techniques/T1601/001) to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices. [Modify System Image](https://attack.mitre.org/techniques/T1601) may include implanted code to the operating system for network devices to provide access for adversaries using a specific password. The modification includes a specific password which is implanted in the operating system image via the patch. Upon authentication attempts, the inserted code will first check to see if the user input is the password. If so, access is granted. Otherwise, the implanted code will pass the credentials on for verification of potentially valid credentials.

ATT&CK mitigations (2): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
NIST 800-53 R5 controls (13): `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Modification of Network Device Authentication via Patched System Images  
Implemented by 3 software: [S0519 SYNful Knock](https://attack.mitre.org/software/S0519), [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104), [S9013 DRYHOOK](https://attack.mitre.org/software/S9013)  

---

### T1556.005: Reversible Encryption
<a id="t1556005"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1556/005)  

An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The <code>AllowReversiblePasswordEncryption</code> property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it. If the property is enabled and/or a user changes their password after it is enabled, an adversary may be able to obtain the plaintext of passwords created/changed after the property was enabled. To decrypt the passwords, an adversary needs four components: 1. Encrypted password (<code>G$RADIUSCHAP</code>) from the Active Directory user-structure <code>userParameters</code> 2. 16 byte randomly-generated value (<code>G$RADIUSCHAPKEY</code>) also from <code>userParameters</code> 3. Global LSA secret (<code>G$MSRADIUSCHAPKEY</code>) 4. Static key hardcoded in the Remote Access Subauthentication DLL (<code>RASSFM.DLL</code>) With this information, an adversary may be able to reproduce the encryption key and subsequently decrypt the encrypted password value. An adversary may set this property at various scopes through Local Group Policy Editor, user properties, Fine-Grained Password Policy (FGPP), or via the ActiveDirectory [PowerShell](https://attack.mitre.org/techniques/T1059/001) module. For example, an adversary may implement and apply a FGPP to users or groups if the Domain Functional Level is set to "Windows Server 2008" or higher. In PowerShell, an adversary may make associated changes to user settings using commands similar to <code>Set-ADUser -AllowReversiblePasswordEncryption $true</code>.

ATT&CK mitigations (2): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
NIST 800-53 R5 controls (4): `AC-2`, `AC-5`, `AC-6`, `IA-5`  
ATT&CK detection strategy: Detect Modification of Authentication Process via Reversible Encryption  

---

### T1556.006: Multi-Factor Authentication
<a id="t1556006"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Windows, SaaS, IaaS, Linux, macOS, Office Suite, Identity Provider, [ATT&CK](https://attack.mitre.org/techniques/T1556/006)  

Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts. Once adversaries have gained access to a network by either compromising an account lacking MFA or by employing an MFA bypass method such as [Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621), adversaries may leverage their access to modify or completely disable MFA defenses. This can be accomplished by abusing legitimate features, such as excluding users from Azure AD Conditional Access Policies, registering a new yet vulnerable/adversary-controlled MFA method, or by manually patching MFA programs and configuration files to bypass expected functionality. For example, modifying the Windows hosts file (`C:\windows\system32\drivers\etc\hosts`) to redirect MFA calls to localhost instead of an MFA server may cause the MFA process to fail. If a "fail open" policy is in place, any otherwise successful authentication attempt may be granted access without enforcing MFA. Depending on the scope, goals, and privileges of the adversary, MFA defenses may be disabled for individual accounts or for all accounts tied to a larger group, such as all domain accounts in a victim's network environment.

ATT&CK mitigations (3): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (6): `AC-2`, `AC-3`, `AC-6`, `IA-11`, `IA-13`, `IA-2`  
ATT&CK detection strategy: Detect MFA Modification or Disabling Across Platforms  
Used by 1 threat groups: [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  
Implemented by 2 software: [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104)  

---

### T1556.007: Hybrid Identity
<a id="t1556007"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Windows, SaaS, IaaS, Office Suite, Identity Provider, [ATT&CK](https://attack.mitre.org/techniques/T1556/007)  

Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts. Many organizations maintain hybrid user and device identities that are shared between on-premises and cloud-based environments. These can be maintained in a number of ways. For example, Microsoft Entra ID includes three options for synchronizing identities between Active Directory and Entra ID: * Password Hash Synchronization (PHS), in which a privileged on-premises account synchronizes user password hashes between Active Directory and Entra ID, allowing authentication to Entra ID to take place entirely in the cloud * Pass Through Authentication (PTA), in which Entra ID authentication attempts are forwarded to an on-premises PTA agent, which validates the credentials against Active Directory * Active Directory Federation Services (AD FS), in which a trust relationship is established between Active Directory and Entra ID AD FS can also be used with other SaaS and cloud platforms such as AWS and GCP, which will hand off the authentication process to AD FS and receive a token containing the hybrid users’ identity and privileges. By modifying authentication processes tied to hybrid identities, an adversary may be able to establish persistent privileged access to cloud resources. For example, adversaries who compromise an on-premises server running a PTA agent may inject a malicious DLL into the `AzureADConnectAuthenticationAgentService` process that authorizes all attempts to authenticate to Entra ID, as well as records user credentials. In environments using AD FS, an adversary may edit the `Microsoft.IdentityServer.Servicehost` configuration file to load a malicious DLL that generates authentication tokens for any user with any set of claims, thereby bypassing multi-factor authentication and defined AD FS policies. In some cases, adversaries may be able to modify the hybrid identity authentication process from the cloud. For example, adversaries who compromise a Global Administrator account in an Entra ID tenant may be able to register a new PTA agent via the web console, similarly allowing them to harvest credentials and log into the Entra ID environment as any user.

ATT&CK mitigations (3): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (6): `AC-2`, `AC-3`, `AC-6`, `IA-11`, `IA-13`, `IA-2`  
ATT&CK detection strategy: Detect Hybrid Identity Authentication Process Modification  
Used by 1 threat groups: [G0016 APT29](https://attack.mitre.org/groups/G0016)  
Implemented by 1 software: [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1556.008: Network Provider DLL
<a id="t1556008"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1556/008)  

Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions. During the logon process, Winlogon (the interactive logon module) sends credentials to the local `mpnotify.exe` process via RPC. The `mpnotify.exe` process then shares the credentials in cleartext with registered credential managers when notifying that a logon event is happening. Adversaries can configure a malicious network provider DLL to receive credentials from `mpnotify.exe`. Once installed as a credential manager (via the Registry), a malicious DLL can receive and save credentials each time a user logs onto a Windows workstation or domain via the `NPLogonNotify()` function. Adversaries may target planting malicious network provider DLLs on systems known to have increased logon activity and/or administrator logon activity, such as servers and domain controllers.

ATT&CK mitigations (3): [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (9): `AC-3`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Network Provider DLL Registration and Credential Capture  

---

### T1556.009: Conditional Access Policies
<a id="t1556009"></a>

sub-technique of [T1556](/techniques/defense-impairment.md#t1556), Tactics: Defense Impairment, Persistence, Credential Access, Platforms: IaaS, Identity Provider, [ATT&CK](https://attack.mitre.org/techniques/T1556/009)  

Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts. Conditional access policies are additional verifications used by identity providers and identity and access management systems to determine whether a user should be granted access to a resource. For example, in Entra ID, Okta, and JumpCloud, users can be denied access to applications based on their IP address, device enrollment status, and use of multi-factor authentication. In some cases, identity providers may also support the use of risk-based metrics to deny sign-ins based on a variety of indicators. In AWS and GCP, IAM policies can contain `condition` attributes that verify arbitrary constraints such as the source IP, the date the request was made, and the nature of the resources or regions being requested. These measures help to prevent compromised credentials from resulting in unauthorized access to data or resources, as well as limit user permissions to only those required. By modifying conditional access policies, such as adding additional trusted IP ranges, removing [Multi-Factor Authentication](https://attack.mitre.org/techniques/T1556/006) requirements, or allowing additional [Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535), adversaries may be able to ensure persistent access to accounts and circumvent defensive measures.

ATT&CK mitigations (1): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
NIST 800-53 R5 controls (14): `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-13`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detect Conditional Access Policy Modification in Identity and Cloud Platforms  
Used by 2 threat groups: [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1578: Modify Cloud Compute Infrastructure
<a id="t1578"></a>

Tactics: Defense Impairment, Platforms: IaaS, [ATT&CK](https://attack.mitre.org/techniques/T1578)  

An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots. Permissions gained from the modification of infrastructure components may bypass restrictions that prevent access to existing infrastructure. Modifying infrastructure components may also allow an adversary to evade detection and remove evidence of their presence.

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (11): `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SI-4`  
ATT&CK detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure  

---

### T1578.001: Create Snapshot
<a id="t1578001"></a>

sub-technique of [T1578](/techniques/defense-impairment.md#t1578), Tactics: Defense Impairment, Platforms: IaaS, [ATT&CK](https://attack.mitre.org/techniques/T1578/001)  

An adversary may create a snapshot or data backup within a cloud account to evade defenses. A snapshot is a point-in-time copy of an existing cloud compute component such as a virtual machine (VM), virtual hard drive, or volume. An adversary may leverage permissions to create a snapshot in order to bypass restrictions that prevent access to existing compute service infrastructure, unlike in [Revert Cloud Instance](https://attack.mitre.org/techniques/T1578/004) where an adversary may revert to a snapshot to evade detection and remove evidence of their presence. An adversary may [Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002), mount one or more created snapshots to that instance, and then apply a policy that allows the adversary access to the created instance, such as a firewall policy that allows them inbound and outbound SSH access.

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (11): `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SI-4`  
ATT&CK detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Create Snapshot  
Implemented by 1 software: [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1578.002: Create Cloud Instance
<a id="t1578002"></a>

sub-technique of [T1578](/techniques/defense-impairment.md#t1578), Tactics: Defense Impairment, Platforms: IaaS, [ATT&CK](https://attack.mitre.org/techniques/T1578/002)  

An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses. Creating a new instance may allow an adversary to bypass firewall rules and permissions that exist on instances currently residing within an account. An adversary may [Create Snapshot](https://attack.mitre.org/techniques/T1578/001) of one or more volumes in an account, create a new instance, mount the snapshots, and then apply a less restrictive security policy to collect [Data from Local System](https://attack.mitre.org/techniques/T1005) or for [Remote Data Staging](https://attack.mitre.org/techniques/T1074/002). Creating a new instance may also allow an adversary to carry out malicious activity within an environment without affecting the execution of current running instances.

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (11): `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SI-4`  
ATT&CK detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Create Cloud Instance  
Used by 2 threat groups: [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1578.003: Delete Cloud Instance
<a id="t1578003"></a>

sub-technique of [T1578](/techniques/defense-impairment.md#t1578), Tactics: Defense Impairment, Platforms: IaaS, [ATT&CK](https://attack.mitre.org/techniques/T1578/003)  

An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence. Deleting an instance or virtual machine can remove valuable forensic artifacts and other evidence of suspicious behavior if the instance is not recoverable. An adversary may also [Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002) and later terminate the instance after achieving their objectives.

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (11): `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SI-4`  
ATT&CK detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Delete Cloud Instance  
Used by 2 threat groups: [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1578.004: Revert Cloud Instance
<a id="t1578004"></a>

sub-technique of [T1578](/techniques/defense-impairment.md#t1578), Tactics: Defense Impairment, Platforms: IaaS, [ATT&CK](https://attack.mitre.org/techniques/T1578/004)  

An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence. In highly virtualized environments, such as cloud-based infrastructure, this may be accomplished by restoring virtual machine (VM) or data storage snapshots through the cloud management dashboard or cloud APIs. Another variation of this technique is to utilize temporary storage attached to the compute instance. Most cloud providers provide various types of storage including persistent, local, and/or ephemeral, with the ephemeral types often reset upon stop/restart of the VM.

ATT&CK mitigations: none mapped  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Revert Cloud Instance  

---

### T1578.005: Modify Cloud Compute Configurations
<a id="t1578005"></a>

sub-technique of [T1578](/techniques/defense-impairment.md#t1578), Tactics: Defense Impairment, Platforms: IaaS, [ATT&CK](https://attack.mitre.org/techniques/T1578/005)  

Adversaries may modify settings that directly affect the size, locations, and resources available to cloud compute infrastructure in order to evade defenses. These settings may include service quotas, subscription associations, tenant-wide policies, or other configurations that impact available compute. Such modifications may allow adversaries to abuse the victim’s compute resources to achieve their goals, potentially without affecting the execution of running instances and/or revealing their activities to the victim. For example, cloud providers often limit customer usage of compute resources via quotas. Customers may request adjustments to these quotas to support increased computing needs, though these adjustments may require approval from the cloud provider. Adversaries who compromise a cloud environment may similarly request quota adjustments in order to support their activities, such as enabling additional [Resource Hijacking](https://attack.mitre.org/techniques/T1496) without raising suspicion by using up a victim’s entire quota. Adversaries may also increase allowed resource usage by modifying any tenant-wide policies that limit the sizes of deployed virtual machines. Adversaries may also modify settings that affect where cloud resources can be deployed, such as enabling [Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535).

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (5): `AC-2`, `AC-20`, `AC-3`, `AC-6`, `CM-3`  
ATT&CK detection strategy: Detection Strategy for Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations  

---

### T1599: Network Boundary Bridging
<a id="t1599"></a>

Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1599)  

Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks. Devices such as routers and firewalls can be used to create boundaries between trusted and untrusted networks. They achieve this by restricting traffic types to enforce organizational policy in an attempt to reduce the risk inherent in such connections. Restriction of traffic can be achieved by prohibiting IP addresses, layer 4 protocol ports, or through deep packet inspection to identify applications. To participate with the rest of the network, these devices can be directly addressable or transparent, but their mode of operation has no bearing on how the adversary can bypass them when compromised. When an adversary takes control of such a boundary device, they can bypass its policy enforcement to pass normally prohibited traffic across the trust boundary between the two separated networks without hinderance. By achieving sufficient rights on the device, an adversary can reconfigure the device to allow the traffic they want, allowing them to then further achieve goals such as command and control via [Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003) or exfiltration of data via [Traffic Duplication](https://attack.mitre.org/techniques/T1020/001). Adversaries may also target internal devices responsible for network segmentation and abuse these in conjunction with [Internal Proxy](https://attack.mitre.org/techniques/T1090/001) to achieve the same goals. In the cases where a border device separates two separate organizations, the adversary can also facilitate lateral movement into new victim environments.

ATT&CK mitigations (5): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043)  
NIST 800-53 R5 controls (18): `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-7`, `SI-10`, `SI-15`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detection Strategy for Network Boundary Bridging  
Used by 1 threat groups: [G0096 APT41](https://attack.mitre.org/groups/G0096)  

---

### T1599.001: Network Address Translation Traversal
<a id="t1599001"></a>

sub-technique of [T1599](/techniques/defense-impairment.md#t1599), Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1599/001)  

Adversaries may bridge network boundaries by modifying a network device’s Network Address Translation (NAT) configuration. Malicious modifications to NAT may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks. Network devices such as routers and firewalls that connect multiple networks together may implement NAT during the process of passing packets between networks. When performing NAT, the network device will rewrite the source and/or destination addresses of the IP address header. Some network designs require NAT for the packets to cross the border device. A typical example of this is environments where internal networks make use of non-Internet routable addresses. When an adversary gains control of a network boundary device, they may modify NAT configurations to send traffic between two separated networks, or to obscure their activities. In network designs that require NAT to function, such modifications enable the adversary to overcome inherent routing limitations that would normally prevent them from accessing protected systems behind the border device. In network designs that do not require NAT, adversaries may use address translation to further obscure their activities, as changing the addresses of packets that traverse a network boundary device can make monitoring data transmissions more challenging for defenders. Adversaries may use [Patch System Image](https://attack.mitre.org/techniques/T1601/001) to change the operating system of a network device, implementing their own custom NAT mechanisms to further obscure their activities.

ATT&CK mitigations (5): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043)  
NIST 800-53 R5 controls (18): `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-7`, `SI-10`, `SI-15`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detection Strategy for Network Address Translation Traversal  

---

### T1600: Weaken Encryption
<a id="t1600"></a>

Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1600)  

Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications. Encryption can be used to protect transmitted network traffic to maintain its confidentiality (protect against unauthorized disclosure) and integrity (protect against unauthorized changes). Encryption ciphers are used to convert a plaintext message to ciphertext and can be computationally intensive to decipher without the associated decryption key. Typically, longer keys increase the cost of cryptanalysis, or decryption without the key. Adversaries can compromise and manipulate devices that perform encryption of network traffic. For example, through behaviors such as [Modify System Image](https://attack.mitre.org/techniques/T1601), [Reduce Key Space](https://attack.mitre.org/techniques/T1600/001), and [Disable Crypto Hardware](https://attack.mitre.org/techniques/T1600/002), an adversary can negatively effect and/or eliminate a device’s ability to securely encrypt network traffic. This poses a greater risk of unauthorized disclosure and may help facilitate data manipulation, Credential Access, or Collection efforts.

ATT&CK mitigations: none mapped  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Weaken Encryption on Network Devices  

---

### T1600.001: Reduce Key Space
<a id="t1600001"></a>

sub-technique of [T1600](/techniques/defense-impairment.md#t1600), Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1600/001)  

Adversaries may reduce the level of effort required to decrypt data transmitted over the network by reducing the cipher strength of encrypted communications. Adversaries can weaken the encryption software on a compromised network device by reducing the key size used by the software to convert plaintext to ciphertext (e.g., from hundreds or thousands of bytes to just a couple of bytes). As a result, adversaries dramatically reduce the amount of effort needed to decrypt the protected information without the key. Adversaries may modify the key size used and other encryption parameters using specialized commands in a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) introduced to the system through [Modify System Image](https://attack.mitre.org/techniques/T1601) to change the configuration of the device.

ATT&CK mitigations: none mapped  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Weaken Encryption: Reduce Key Space on Network Devices  

---

### T1600.002: Disable Crypto Hardware
<a id="t1600002"></a>

sub-technique of [T1600](/techniques/defense-impairment.md#t1600), Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1600/002)  

Adversaries disable a network device’s dedicated hardware encryption, which may enable them to leverage weaknesses in software encryption in order to reduce the effort involved in collecting, manipulating, and exfiltrating transmitted data. Many network devices such as routers, switches, and firewalls, perform encryption on network traffic to secure transmission across networks. Often, these devices are equipped with special, dedicated encryption hardware to greatly increase the speed of the encryption process as well as to prevent malicious tampering. When an adversary takes control of such a device, they may disable the dedicated hardware, for example, through use of [Modify System Image](https://attack.mitre.org/techniques/T1601), forcing the use of software to perform encryption on general processors. This is typically used in conjunction with attacks to weaken the strength of the cipher in software (e.g., [Reduce Key Space](https://attack.mitre.org/techniques/T1600/001)).

ATT&CK mitigations: none mapped  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Weaken Encryption: Disable Crypto Hardware on Network Devices  

---

### T1601: Modify System Image
<a id="t1601"></a>

Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1601)  

Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves. On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file. To change the operating system, the adversary typically only needs to affect this one file, replacing or modifying it. This can either be done live in memory during system runtime for immediate effect, or in storage to implement the change on the next boot of the network device.

ATT&CK mitigations (6): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
NIST 800-53 R5 controls (24): `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
ATT&CK detection strategy: Detection Strategy for Modify System Image on Network Devices  
Implemented by 1 software: [S9013 DRYHOOK](https://attack.mitre.org/software/S9013)  

---

### T1601.001: Patch System Image
<a id="t1601001"></a>

sub-technique of [T1601](/techniques/defense-impairment.md#t1601), Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1601/001)  

Adversaries may modify the operating system of a network device to introduce new capabilities or weaken existing defenses. Some network devices are built with a monolithic architecture, where the entire operating system and most of the functionality of the device is contained within a single file. Adversaries may change this file in storage, to be loaded in a future boot, or in memory during runtime. To change the operating system in storage, the adversary will typically use the standard procedures available to device operators. This may involve downloading a new file via typical protocols used on network devices, such as TFTP, FTP, SCP, or a console connection. The original file may be overwritten, or a new file may be written alongside of it and the device reconfigured to boot to the compromised image. To change the operating system in memory, the adversary typically can use one of two methods. In the first, the adversary would make use of native debug commands in the original, unaltered running operating system that allow them to directly modify the relevant memory addresses containing the running operating system. This method typically requires administrative level access to the device. In the second method for changing the operating system in memory, the adversary would make use of the boot loader. The boot loader is the first piece of software that loads when the device starts that, in turn, will launch the operating system. Adversaries may use malicious code previously implanted in the boot loader, such as through the [ROMMONkit](https://attack.mitre.org/techniques/T1542/004) method, to directly manipulate running operating system code in memory. This malicious code in the bootloader provides the capability of direct memory manipulation to the adversary, allowing them to patch the live operating system during runtime. By modifying the instructions stored in the system image file, adversaries may either weaken existing defenses or provision new capabilities that the device did not have before. Examples of existing defenses that can be impeded include encryption, via [Weaken Encryption](https://attack.mitre.org/techniques/T1600), authentication, via [Network Device Authentication](https://attack.mitre.org/techniques/T1556/004), and perimeter defenses, via [Network Boundary Bridging](https://attack.mitre.org/techniques/T1599). Adding new capabilities for the adversary’s purpose include [Keylogging](https://attack.mitre.org/techniques/T1056/001), [Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003), and [Port Knocking](https://attack.mitre.org/techniques/T1205/001). Adversaries may also compromise existing commands in the operating system to produce false output to mislead defenders. When this method is used in conjunction with [Downgrade System Image](https://attack.mitre.org/techniques/T1601/002), one example of a compromised system command may include changing the output of the command that shows the version of the currently running operating system. By patching the operating system, the adversary can change this command to instead display the original, higher revision number that they replaced through the system downgrade. When the operating system is patched in storage, this can be achieved in either the resident storage (typically a form of flash memory, which is non-volatile) or via [TFTP Boot](https://attack.mitre.org/techniques/T1542/005). When the technique is performed on the running operating system in memory and not on the stored copy, this technique will not survive across reboots. However, live memory modification of the operating system can be combined with [ROMMONkit](https://attack.mitre.org/techniques/T1542/004) to achieve persistence.

ATT&CK mitigations (6): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
NIST 800-53 R5 controls (24): `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
ATT&CK detection strategy: Detection Strategy for Patch System Image on Network Devices  
Implemented by 1 software: [S0519 SYNful Knock](https://attack.mitre.org/software/S0519)  

---

### T1601.002: Downgrade System Image
<a id="t1601002"></a>

sub-technique of [T1601](/techniques/defense-impairment.md#t1601), Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1601/002)  

Adversaries may install an older version of the operating system of a network device to weaken security. Older operating system versions on network devices often have weaker encryption ciphers and, in general, fewer/less updated defensive features. On embedded devices, downgrading the version typically only requires replacing the operating system file in storage. With most embedded devices, this can be achieved by downloading a copy of the desired version of the operating system file and reconfiguring the device to boot from that file on next system restart. The adversary could then restart the device to implement the change immediately or they could wait until the next time the system restarts. Downgrading the system image to an older versions may allow an adversary to evade defenses by enabling behaviors such as [Weaken Encryption](https://attack.mitre.org/techniques/T1600). Downgrading of a system image can be done on its own, or it can be used in conjunction with [Patch System Image](https://attack.mitre.org/techniques/T1601/001).

ATT&CK mitigations (6): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
NIST 800-53 R5 controls (24): `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
ATT&CK detection strategy: Detection Strategy for Downgrade System Image on Network Devices  

---

### T1647: Plist File Modification
<a id="t1647"></a>

Tactics: Defense Impairment, Platforms: macOS, [ATT&CK](https://attack.mitre.org/techniques/T1647)  

Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses. macOS applications use plist files, such as the <code>info.plist</code> file, to store properties and configuration settings that inform the operating system how to handle the application at runtime. Plist files are structured metadata in key-value pairs formatted in XML based on Apple's Core Foundation DTD. Plist files can be saved in text or binary format. Adversaries can modify key-value pairs in plist files to influence system behaviors, such as hiding the execution of an application (i.e. [Hidden Window](https://attack.mitre.org/techniques/T1564/003)) or running additional commands for persistence (ex: [Launch Agent](https://attack.mitre.org/techniques/T1543/001)/[Launch Daemon](https://attack.mitre.org/techniques/T1543/004) or [Re-opened Applications](https://attack.mitre.org/techniques/T1547/007)). For example, adversaries can add a malicious application path to the `~/Library/Preferences/com.apple.dock.plist` file, which controls apps that appear in the Dock. Adversaries can also modify the <code>LSUIElement</code> key in an application’s <code>info.plist</code> file to run the app in the background. Adversaries can also insert key-value pairs to insert environment variables, such as <code>LSEnvironment</code>, to enable persistence via [Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006).

ATT&CK mitigations (1): [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013)  
NIST 800-53 R5 controls (15): `AC-16`, `AC-17`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `SA-10`, `SA-11`, `SA-8`, `SI-4`, `SI-7`  
ATT&CK detection strategy: Detection Strategy for Plist File Modification (T1647)  
Implemented by 2 software: [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153)  

---

### T1666: Modify Cloud Resource Hierarchy
<a id="t1666"></a>

Tactics: Defense Impairment, Platforms: IaaS, [ATT&CK](https://attack.mitre.org/techniques/T1666)  

Adversaries may attempt to modify hierarchical structures in infrastructure-as-a-service (IaaS) environments in order to evade defenses. IaaS environments often group resources into a hierarchy, enabling improved resource management and application of policies to relevant groups. Hierarchical structures differ among cloud providers. For example, in AWS environments, multiple accounts can be grouped under a single organization, while in Azure environments, multiple subscriptions can be grouped under a single management group. Adversaries may add, delete, or otherwise modify resource groups within an IaaS hierarchy. For example, in Azure environments, an adversary who has gained access to a Global Administrator account may create new subscriptions in which to deploy resources. They may also engage in subscription hijacking by transferring an existing pay-as-you-go subscription from a victim tenant to an adversary-controlled tenant. This will allow the adversary to use the victim’s compute resources without generating logs on the victim tenant. In AWS environments, adversaries with appropriate permissions in a given account may call the `LeaveOrganization` API, causing the account to be severed from the AWS Organization to which it was tied and removing any Service Control Policies, guardrails, or restrictions imposed upon it by its former Organization. Alternatively, adversaries may call the `CreateAccount` API in order to create a new account within an AWS Organization. This account will use the same payment methods registered to the payment account but may not be subject to existing detections or Service Control Policies.

ATT&CK mitigations (3): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls (1): `CM-3`  
ATT&CK detection strategy: Detection Strategy for Modify Cloud Resource Hierarchy  

---

### T1685: Disable or Modify Tools
<a id="t1685"></a>

Tactics: Defense Impairment, Platforms: Containers, ESXi, IaaS, Linux, macOS, Network Devices, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1685)  

Adversaries may disable, degrade, or tamper with security tools or applications (e.g., endpoint detection and response (EDR) tools, intrusion detection systems (IDS), antivirus, logging agents, sensors, etc.) to impair or reduce visibility of defensive capabilities. This may include stopping specific services, killing processes, modifying or deleting tool configuration files and Registry keys, or preventing tools from updating. This may also include impairing defenses more broadly by disrupting preventative, detection, and response mechanisms across host, network, and cloud environments. In addition to directly targeting tools, adversaries may block or manipulate indicators and telemetry used for detection. This includes maliciously disabling or redirecting sensors such as Event Tracing for Windows (ETW), modifying event log configurations (e.g., redirecting Security logs), or interfering with logging pipelines and forwarding mechanisms (e.g., SIEM ingestion). More advanced techniques include leveraging legitimate drivers or debugging mechanisms to render tools non-functional, bypassing anti-tampering protections, and targeting specific defenses such as Sysmon or cloud monitoring agents. Adversaries may also disrupt broader defensive operations, including update mechanisms, logging infrastructure (e.g., syslog), or event aggregation, further degrading an organization’s ability to detect and respond to malicious activity.

ATT&CK mitigations (7): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Impair Defenses Across Platforms; Detection of Impair Defenses through Disabled or Modified Tools across OS Platforms.; Detection Strategy for Impair Defenses Indicator Blocking  
Used by 32 threat groups: [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0024 Putter Panda](https://attack.mitre.org/groups/G0024), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052), [G1054 MirrorFace](https://attack.mitre.org/groups/G1054)  
Implemented by 87 software: [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0061 HDoor](https://attack.mitre.org/software/S0061), [S0130 Unknown Logger](https://attack.mitre.org/software/S0130), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0228 NanHaiShu](https://attack.mitre.org/software/S0228), [S0249 Gold Dragon](https://attack.mitre.org/software/S0249), [S0252 Brave Prince](https://attack.mitre.org/software/S0252), [S0253 RunningRAT](https://attack.mitre.org/software/S0253), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0477 Goopy](https://attack.mitre.org/software/S0477), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0579 Waterbear](https://attack.mitre.org/software/S0579), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0605 EKANS](https://attack.mitre.org/software/S0605), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0638 Babuk](https://attack.mitre.org/software/S0638), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0695 Donut](https://attack.mitre.org/software/S0695), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1048 macOS.OSAMiner](https://attack.mitre.org/software/S1048), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1065 Woody RAT](https://attack.mitre.org/software/S1065), [S1097 HUI Loader](https://attack.mitre.org/software/S1097), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1114 ZIPLINE](https://attack.mitre.org/software/S1114), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1169 Mango](https://attack.mitre.org/software/S1169), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1200 StealBit](https://attack.mitre.org/software/S1200), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1206 JumbledPath](https://attack.mitre.org/software/S1206), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1234 SplatCloak](https://attack.mitre.org/software/S1234), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1244 Medusa Ransomware](https://attack.mitre.org/software/S1244), [S9008 Shai-Hulud](https://attack.mitre.org/software/S9008), [S9013 DRYHOOK](https://attack.mitre.org/software/S9013), [S9014 PHASEJAM](https://attack.mitre.org/software/S9014), [S9017 DCRAT](https://attack.mitre.org/software/S9017), [S9019 PureCrypter](https://attack.mitre.org/software/S9019), [S9024 SPAWNCHIMERA](https://attack.mitre.org/software/S9024), [S9039 LazyWiper](https://attack.mitre.org/software/S9039)  

---

### T1685.001: Disable or Modify Windows Event Log
<a id="t1685001"></a>

sub-technique of [T1685](/techniques/defense-impairment.md#t1685), Tactics: Defense Impairment, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1685/001)  

Adversaries may disable or modify the Windows Event Log to limit data that can be leveraged for detections and audits. Windows Event Log records user and system activity such as login attempts and process creation. This data is used by security tools and analysts to generate detections. The EventLog service maintains event logs from various system components and applications. By default, the service automatically starts when a system powers on. An audit policy, maintained by the Local Security Policy (secpol.msc), defines which system events the EventLog service logs. Security audit policy settings can be changed by running secpol.msc, then navigating to `Security Settings\Local Policies\Audit Policy` for basic audit policy settings or `Security Settings\Advanced Audit Policy Configuration` for advanced audit policy settings. `auditpol.exe` may also be used to set audit policies. Adversaries may target system-wide logging or just that of a particular application. For example, the Windows EventLog service may be disabled using the `Set-Service -Name EventLog -Status Stopped` or `sc config eventlog start=disabled` commands (followed by manually stopping the service using `Stop-Service -Name EventLog`). Additionally, the service may be disabled by modifying the "Start" value in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog` then restarting the system for the change to take effect. There are several ways to disable the EventLog service via registry key modification. Without Administrator privileges, adversaries may modify the "Start" value in the key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security`, then reboot the system to disable the Security EventLog. With Administrator privilege, adversaries may modify the same values in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System` and `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application` to disable the entire EventLog. Additionally, adversaries may use `auditpol` and its sub-commands in a command prompt to disable auditing or clear the audit policy. To enable or disable a specified setting or audit category, adversaries may use the `/success` or `/failure` parameters. For example, `auditpol /set /category:"Account Logon" /success:disable /failure:disable` turns off auditing for the Account Logon category. To clear the audit policy, adversaries may run the following lines: `auditpol /clear /y` or `auditpol /remove /allusers`.

ATT&CK mitigations (4): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detect disabled Windows event logging  
Used by 2 threat groups: [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059)  
Implemented by 1 software: [S0645 Wevtutil](https://attack.mitre.org/software/S0645)  

---

### T1685.002: Disable or Modify Cloud Log
<a id="t1685002"></a>

sub-technique of [T1685](/techniques/defense-impairment.md#t1685), Tactics: Defense Impairment, Platforms: IaaS, SaaS, Identity Provider, Office Suite, [ATT&CK](https://attack.mitre.org/techniques/T1685/002)  

An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. Cloud environments allow for collection and analysis of audit and application logs that provide insight into what activities a user does within the environment. If an adversary has sufficient permissions, they can disable or modify logging to avoid detection of their activities. For example, in AWS an adversary may disable CloudWatch/CloudTrail integrations prior to conducting further malicious activity. They may alternatively tamper with logging functionality, for example, by removing any associated SNS topics, disabling multi-region logging, or disabling settings that validate and/or encrypt log files. In Office 365, an adversary may disable logging on mail collection activities for specific users by using the Set-MailboxAuditBypassAssociation cmdlet, by disabling M365 Advanced Auditing for the user, or by downgrading the user’s license from an Enterprise E5 to an Enterprise E3 license.

ATT&CK mitigations (1): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Disable or Modify Cloud Logs  
Used by 1 threat groups: [G0016 APT29](https://attack.mitre.org/groups/G0016)  
Implemented by 1 software: [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1685.003: Modify or Spoof Tool UI
<a id="t1685003"></a>

sub-technique of [T1685](/techniques/defense-impairment.md#t1685), Tactics: Defense Impairment, Platforms: Linux, macOS, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1685/003)  

Adversaries may spoof or manipulate security tool user interfaces (UIs) to falsely indicate tools are functioning normally and delay detection and response. Adversaries may present misleading or falsified security tool interfaces (UIs) that display normal or healthy status indicators, even when underlying security tools have been disabled, degraded, or otherwise tampered with. Security tools typically provide visibility into system health, alerting, and operational status; by misrepresenting this information, adversaries can undermine defender trust in these signals and obscure the true security posture of the system. This behavior is often used in conjunction with efforts to disable or modify tools, where adversaries first impair the functionality of defenses (e.g., EDR, logging agents) and then replace or mimic their interfaces to conceal the loss of visibility. By maintaining the appearance of normal operations, such as showing active protection, successful updates, or absence of threats, adversaries can delay investigation and response, enabling continued malicious activity. For example, adversaries may display a fake Windows Security interface or system tray icon indicating a “protected” or “healthy” state after disabling Windows Defender or related services.

ATT&CK mitigations (1): [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection for Spoofing Security Alerting across OS Platforms  
Implemented by 1 software: [S9014 PHASEJAM](https://attack.mitre.org/software/S9014)  

---

### T1685.004: Disable or Modify Linux Audit System Log
<a id="t1685004"></a>

sub-technique of [T1685](/techniques/defense-impairment.md#t1685), Tactics: Defense Impairment, Platforms: Linux, [ATT&CK](https://attack.mitre.org/techniques/T1685/004)  

Adversaries may disable or modify the Linux Audit system to hide malicious activity and avoid detection. Linux admins use the Linux Audit system to track security-relevant information on a system. The Linux Audit system operates at the kernel-level and maintains event logs on application and system activity such as process, network, file, and login events based on pre-configured rules. Often referred to as `auditd`, this is the name of the daemon used to write events to disk and is governed by the parameters set in the `audit.conf` configuration file. Two primary ways to configure the log generation rules are through the command line `auditctl` utility and the file `/etc/audit/audit.rules`, containing a sequence of `auditctl` commands loaded at boot time. With root privileges, adversaries may be able to ensure their activity is not logged through disabling the Audit system service, editing the configuration/rule files, or by hooking the Audit system library functions. Using the command line, adversaries can disable the Audit system service through killing processes associated with `auditd` daemon or use `systemctl` to stop the Audit service. Adversaries can also hook Audit system functions to disable logging or modify the rules contained in the `/etc/audit/audit.rules` or `audit.conf` files to ignore malicious activity.

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Disable or Modify Linux Audit System  
Implemented by 1 software: [S0377 Ebury](https://attack.mitre.org/software/S0377)  

---

### T1685.005: Clear Windows Event Logs
<a id="t1685005"></a>

sub-technique of [T1685](/techniques/defense-impairment.md#t1685), Tactics: Defense Impairment, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1685/005)  

Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit. With administrator privileges, the event logs can be cleared with the following utility commands: * `wevtutil cl system` * `wevtutil cl application` * `wevtutil cl security` These logs may also be cleared through other mechanisms, such as the event viewer GUI or PowerShell. For example, adversaries may use the PowerShell command `Remove-EventLog -LogName Security` to delete the Security EventLog and after reboot, disable future logging. Note: events may still be generated and logged in the.evtx file between the time the command is run and the reboot. Adversaries may also attempt to clear logs by directly deleting the stored log files within `C:\Windows\System32\winevt\logs\`.

ATT&CK mitigations (3): [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Event Log Clearing on Windows via Behavioral Chain  
Used by 14 threat groups: [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1054 MirrorFace](https://attack.mitre.org/groups/G1054)  
Implemented by 26 software: [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0253 RunningRAT](https://attack.mitre.org/software/S0253), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0645 Wevtutil](https://attack.mitre.org/software/S0645), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1685.006: Clear Linux or Mac System Logs
<a id="t1685006"></a>

sub-technique of [T1685](/techniques/defense-impairment.md#t1685), Tactics: Defense Impairment, Platforms: Linux, macOS, [ATT&CK](https://attack.mitre.org/techniques/T1685/006)  

Adversaries may clear system logs to hide evidence of an intrusion. macOS and Linux both keep track of system or user-initiated actions via system logs. The majority of native system logging is stored under the `/var/log/` directory. Subfolders in this directory categorize logs by their related functions, such as: * `/var/log/messages:`: General and system-related messages * `/var/log/secure or /var/log/auth.log`: Authentication logs * `/var/log/utmp or /var/log/wtmp`: Login records * `/var/log/kern.log`: Kernel logs * `/var/log/cron.log`: Crond logs * `/var/log/maillog`: Mail server logs * `/var/log/httpd/`: Web server access and error logs

ATT&CK mitigations (3): [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Behavioral Detection of Log File Clearing on Linux and macOS  
Used by 4 threat groups: [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
Implemented by 4 software: [S0279 Proton](https://attack.mitre.org/software/S0279), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1164 UPSTYLE](https://attack.mitre.org/software/S1164), [S1206 JumbledPath](https://attack.mitre.org/software/S1206)  

---

### T1686: Disable or Modify System Firewall
<a id="t1686"></a>

Tactics: Defense Impairment, Platforms: ESXi, Linux, macOS, Network Devices, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1686)  

Adversaries may disable or modify host-based or network firewalls to impair defensive mechanisms and enable further action. Once an adversary has gathered sufficient privileges, they can tamper with firewall services, policies, or rule sets to remove restrictions on inbound or outbound traffic. For example, this may include turning off firewall profiles, altering existing rules to permit previously blocked ports or protocols, or adding new rules that create covert communication paths (e.g., adding a new firewall rule for a well-known protocol (such as RDP) using a non-traditional and potentially less securitized port. Adversaries may disable or modify firewalls using different behaviors, depending on the platform. For example, in ESXi, firewall rules may be modified directly via the esxcli (e.g., via esxcli network firewall set) or via the vCenter user interface.

ATT&CK mitigations (4): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Disabled or Modified System Firewalls across OS Platforms.  
Used by 13 threat groups: [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
Implemented by 15 software: [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0088 Kasidet](https://attack.mitre.org/software/S0088), [S0108 netsh](https://attack.mitre.org/software/S0108), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S1032 PyDCrypt](https://attack.mitre.org/software/S1032), [S1161 BPFDoor](https://attack.mitre.org/software/S1161), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1211 Hannotog](https://attack.mitre.org/software/S1211), [S1223 THINCRUST](https://attack.mitre.org/software/S1223)  

---

### T1686.001: Cloud Firewall
<a id="t1686001"></a>

sub-technique of [T1686](/techniques/defense-impairment.md#t1686), Tactics: Defense Impairment, Platforms: IaaS, [ATT&CK](https://attack.mitre.org/techniques/T1686/001)  

Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources. Cloud environments typically utilize restrictive security groups and firewall rules that only allow network activity from trusted IP addresses via expected ports and protocols. An adversary with appropriate permissions may introduce new firewall rules or policies to allow access into a victim cloud environment and/or move laterally from the cloud control plane to the data plane. For example, an adversary may use a script or utility that creates new ingress rules in existing security groups (or creates new security groups entirely) to allow any TCP/IP connectivity to a cloud-hosted instance. They may also remove networking limitations to support traffic associated with malicious activity (such as cryptomining).

ATT&CK mitigations (2): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Disable or Modify Cloud Firewall  
Implemented by 1 software: [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1686.002: Network Device Firewall
<a id="t1686002"></a>

sub-technique of [T1686](/techniques/defense-impairment.md#t1686), Tactics: Defense Impairment, Platforms: Network Devices, [ATT&CK](https://attack.mitre.org/techniques/T1686/002)  

Adversaries may disable network device-based firewall mechanisms entirely or add, delete, or modify particular rules in order to bypass controls limiting network usage. Adversaries may obtain access to devices such as routers, switches, or other perimeter/network devices and change access control lists (ACLs), security zones, or policy rules to permit otherwise blocked traffic. For example, adversaries may add new network firewall rules to allow access to all internal network subnets without restrictions. Allowing access to internal network subsets may enable unrestricted inbound/outbound connectivity or open paths for command and control and lateral movement. Adversaries may obtain access to network device management interfaces via Valid Accounts or by exploiting vulnerabilities. In some cases, threat actors may target firewalls and other network infrastructure that are exposed to the internet by leveraging weaknesses in public-facing applications (Exploit Public-Facing Application). Adversaries may also modify host networking configurations that indirectly manipulate system firewalls, such as adjusting interface bandwidth or network connection request thresholds.

ATT&CK mitigations (3): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Unauthorized Network Firewall Rule Modification (T1562.013)  
Used by 1 threat groups: [G0082 APT38](https://attack.mitre.org/groups/G0082)  
Implemented by 2 software: [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687)  

---

### T1686.003: Windows Host Firewall
<a id="t1686003"></a>

sub-technique of [T1686](/techniques/defense-impairment.md#t1686), Tactics: Defense Impairment, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1686/003)  

Adversaries may disable or modify the Windows host firewall to bypass controls limiting network usage. This can include disabling the Windows host firewall entirely, suppressing specific profiles (domain, private, public), or adding, deleting, and modifying firewall rules to allow or restrict traffic. Adversaries may perform these modifications through multiple mechanisms depending on the Windows operating system and access level. For example, adversaries may use command-line utilities (e.g., `netsh advfirewall` or PowerShell cmdlets like `Set-NetFirewallProfile`, `New-NetFirewallRule`), Windows Registry modifications (e.g., altering firewall states and rule configurations via registry keys), or the Windows Control Panel to modify firewall settings through the Windows Security interface. By disabling or modifying Windows firewall services, adversaries may enable access to remote services, open ports for command and control traffic, or configure rules for further actions.

ATT&CK mitigations (4): [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
Used by 6 threat groups: [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1054 MirrorFace](https://attack.mitre.org/groups/G1054), [G1055 VOID MANTICORE](https://attack.mitre.org/groups/G1055)  
Implemented by 9 software: [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0245 BADCALL](https://attack.mitre.org/software/S0245), [S0246 HARDRAIN](https://attack.mitre.org/software/S0246), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181), [S9023 HiddenFace](https://attack.mitre.org/software/S9023)  

---

### T1687: Exploitation for Defense Impairment
<a id="t1687"></a>

Tactics: Defense Impairment, Platforms: IaaS, Linux, macOS, SaaS, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1687)  

Adversaries may exploit vulnerabilities in security software, infrastructure, or defensive components to degrade, disable, or otherwise continue to impair their ability to prevent, detect, or respond to malicious activity. Adversaries may exploit a system or application vulnerability to directly interfere with defensive mechanisms. Exploitation occurs when an adversary takes advantage of a programming error in software, services, or the operating system to execute adversary-controlled code, often with the goal of weakening or disabling protections. Vulnerabilities may exist in security tools such as antivirus, endpoint detection and response (EDR), firewalls, or other monitoring solutions. Adversaries may use prior reconnaissance or perform discovery activities (e.g., Software Discovery) to identify defensive tools present in an environment and target them for exploitation. Successful exploitation may allow adversaries to terminate security processes, disable protections, bypass enforcement mechanisms, or reduce the effectiveness of defensive controls. In some cases, vulnerabilities in cloud-based or SaaS infrastructure may also be leveraged to bypass built-in security boundaries or disrupt visibility and enforcement across environments.

ATT&CK mitigations: none mapped  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  

---

### T1688: Safe Mode Boot
<a id="t1688"></a>

Tactics: Defense Impairment, Platforms: Windows, [ATT&CK](https://attack.mitre.org/techniques/T1688)  

Adversaries may abuse Windows safe mode to disable endpoint defenses. Safe mode starts up the Windows operating system with a limited set of drivers and services. Third-party security software such as endpoint detection and response (EDR) tools may not start after booting Windows in safe mode. There are two versions of safe mode: Safe Mode and Safe Mode with Networking. It is possible to start additional services after a safe mode boot. Adversaries may abuse safe mode to disable endpoint defenses that may not start with a limited boot. Hosts can be forced into safe mode after the next reboot via modifications to Boot Configuration Data (BCD) stores, which are files that manage boot application settings. Adversaries may also add their malicious applications to the list of minimal services that start in safe mode by modifying relevant Registry values (i.e. Modify Registry). Malicious Component Object Model (COM) objects may also be registered and loaded in safe mode.

ATT&CK mitigations (2): [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Safe Mode Boot Abuse  
Implemented by 7 software: [S0496 REvil](https://attack.mitre.org/software/S0496), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1689: Downgrade Attack
<a id="t1689"></a>

Tactics: Defense Impairment, Platforms: macOS, Windows, Linux, [ATT&CK](https://attack.mitre.org/techniques/T1689)  

Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls. Downgrade attacks typically take advantage of a system’s backward compatibility to force it into less secure modes of operation. Adversaries may downgrade and use various less-secure versions of features of a system, such as Command and Scripting Interpreter or even network protocols that can be abused to enable Adversary-in-the-Middle or Network Sniffing. For example, PowerShell versions 5+ includes Script Block Logging (SBL), which can record executed script content. However, adversaries may attempt to execute a previous version of PowerShell that does not support SBL with the intent to impair defenses while running malicious scripts that may have otherwise been detected. Adversaries may similarly target network traffic to downgrade from an encrypted HTTPS connection to an unsecured HTTP connection that exposes network data in clear text. On Windows systems, adversaries may downgrade the boot manager to a vulnerable version that bypasses Secure Boot, granting the ability to disable various operating system security mechanisms.

ATT&CK mitigations (2): [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detecting Downgrade Attacks  
Implemented by 2 software: [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180)  

---

### T1690: Prevent Command History Logging
<a id="t1690"></a>

Tactics: Defense Impairment, Platforms: ESXi, Linux, macOS, Network Devices, Windows, [ATT&CK](https://attack.mitre.org/techniques/T1690)  

Adversaries may impair command history logging to hide commands they run on a compromised system. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they have done. On Linux and macOS, command history is tracked in a file pointed to by the environment variable `HISTFILE`. When a user logs off a system, this information is flushed to a file in the user's home directory called `~/.bash_history`. The `HISTCONTROL` environment variable keeps track of what should be saved by the history command and eventually into the `~/.bash_history` file when a user logs out. `HISTCONTROL` does not exist by default on macOS, but can be set by the user and will be respected. The `HISTFILE` environment variable is also used in some ESXi systems. Adversaries may clear the history environment variable (`unset HISTFILE`) or set the command history size to zero (`export HISTFILESIZE=0`) to prevent logging of commands. Additionally, `HISTCONTROL` can be configured to ignore commands that start with a space by simply setting it to "ignorespace". `HISTCONTROL` can also be set to ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set by default to "ignoreboth" which covers both of the previous examples. This means that " ls" will not be saved, but "ls" would be saved by history. Adversaries can abuse this to operate without leaving traces by simply prepending a space to all of their terminal commands. On Windows systems, the `PSReadLine` module tracks commands used in all PowerShell sessions and writes them to a file (`$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` by default). Adversaries may change where these logs are saved using `Set-PSReadLineOption -HistorySavePath {File Path}`. This will cause `ConsoleHost_history.txt` to stop receiving logs. Additionally, it is possible to turn off logging to this file using the PowerShell command `Set-PSReadlineOption -HistorySaveStyle SaveNothing`. Adversaries may also leverage a Network Device CLI on network devices to disable historical command logging (e.g. `no logging`).

ATT&CK mitigations (2): [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1039 Environment Variable Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1039)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection Strategy for Impair Defenses via Impair Command History Logging across OS platforms.  
Used by 4 threat groups: [G0082 APT38](https://attack.mitre.org/groups/G0082), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
Implemented by 6 software: [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1161 BPFDoor](https://attack.mitre.org/software/S1161), [S1186 Line Dancer](https://attack.mitre.org/software/S1186), [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217), [S9015 BRICKSTORM](https://attack.mitre.org/software/S9015), [S9024 SPAWNCHIMERA](https://attack.mitre.org/software/S9024)  

---
