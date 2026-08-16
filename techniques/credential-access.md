# Credential Access — Technique Detail

> Full detail pages for the **62 ATT&CK techniques** whose primary tactic is [Credential Access](https://attack.mitre.org/tactics/TA0006/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](README.md).

---

### T1003 — OS Credential Dumping
<a id="t1003"></a>

**Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003)  

Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures. Credentials can then be used to perform Lateral Movement and access restricted information.

**ATT&CK mitigations (9):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043)  
**NIST 800-53 R5 controls (22):** `AC-16`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CP-9`, `IA-2`, `IA-4`, `IA-5`, `SC-28`, `SC-39`, `SI-12`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Credential Dumping via Sensitive Memory and Registry Access Correlation  
**Used by 13 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0039 Suckfly](https://attack.mitre.org/groups/G0039), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 7 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0052 OnionDuke](https://attack.mitre.org/software/S0052), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0232 HOMEFRY](https://attack.mitre.org/software/S0232), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S1146 MgBot](https://attack.mitre.org/software/S1146)  

---

### T1003.001 — LSASS Memory
<a id="t1003001"></a>

sub-technique of [T1003](credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/001)  

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory.

**ATT&CK mitigations (7):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043)  
**NIST 800-53 R5 controls (19):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-3`, `SC-39`, `SI-16`, `SI-2`, `SI-3`, `SI-4`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1003001) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 42 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102) _(+18 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 26 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0005 Windows Credential Editor](https://attack.mitre.org/software/S0005), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0056 Net Crawler](https://attack.mitre.org/software/S0056), [S0121 Lslsass](https://attack.mitre.org/software/S0121), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692) _(+2 more)_  

---

### T1003.002 — Security Account Manager
<a id="t1003002"></a>

sub-technique of [T1003](credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/002)  

Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Credential Dumping from SAM via Registry Dump and Local File Access  
**Used by 13 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  
**Implemented by 15 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0006 pwdump](https://attack.mitre.org/software/S0006), [S0008 gsecdump](https://attack.mitre.org/software/S0008), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0080 Mivast](https://attack.mitre.org/software/S0080), [S0120 Fgdump](https://attack.mitre.org/software/S0120), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0371 POWERTON](https://attack.mitre.org/software/S0371), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S1022 IceApple](https://attack.mitre.org/software/S1022)  

---

### T1003.003 — NTDS
<a id="t1003003"></a>

sub-technique of [T1003](credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/003)  

Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (18):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CP-9`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of NTDS.dit Credential Dumping from Domain Controllers  
**Used by 17 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 4 software:** [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0404 esentutl](https://attack.mitre.org/software/S0404), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488)  

---

### T1003.004 — LSA Secrets
<a id="t1003004"></a>

sub-technique of [T1003](credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/004)  

Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts. LSA secrets are stored in the registry at <code>HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets</code>.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of LSA Secrets Dumping via Registry and Memory Extraction  
**Used by 10 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  
**Implemented by 9 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0008 gsecdump](https://attack.mitre.org/software/S0008), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1022 IceApple](https://attack.mitre.org/software/S1022)  

---

### T1003.005 — Cached Domain Credentials
<a id="t1003005"></a>

sub-technique of [T1003](credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/005)  

Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable. On Windows Vista and newer, the hash format is DCC2 (Domain Cached Credentials version 2) hash, also known as MS-Cache v2 hash.

**ATT&CK mitigations (5):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (17):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Cached Domain Credential Dumping via Local Hash Cache Access  
**Used by 4 threat groups:** [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077)  
**Implemented by 4 software:** [S0119 Cachedump](https://attack.mitre.org/software/S0119), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0439 Okrum](https://attack.mitre.org/software/S0439)  

---

### T1003.006 — DCSync
<a id="t1003006"></a>

sub-technique of [T1003](credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/006)  

Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.

**ATT&CK mitigations (3):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (16):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-4`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Unauthorized DCSync Operations via Replication API Abuse  
**Used by 4 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002)  

---

### T1003.007 — Proc Filesystem
<a id="t1003007"></a>

sub-technique of [T1003](credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/007)  

Adversaries may gather credentials from the proc filesystem or `/proc`. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detecting OS Credential Dumping via /proc Filesystem Access on Linux  
**Implemented by 3 software:** [S0179 MimiPenguin](https://attack.mitre.org/software/S0179), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S1109 PACEMAKER](https://attack.mitre.org/software/S1109)  

---

### T1003.008 — /etc/passwd and /etc/shadow
<a id="t1003008"></a>

sub-technique of [T1003](credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/008)  

Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Credential Access via /etc/passwd and /etc/shadow Parsing  
**Implemented by 1 software:** [S0349 LaZagne](https://attack.mitre.org/software/S0349)  

---

### T1040 — Network Sniffing
<a id="t1040"></a>

**Tactics:** Credential Access, Discovery · **Platforms:** Linux, macOS, Windows, Network Devices, IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1040)  

Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (12):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `CM-7`, `IA-2`, `IA-5`, `SC-4`, `SC-8`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Network Sniffing Across Platforms  
**Used by 8 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 16 software:** [S0019 Regin](https://attack.mitre.org/software/S0019), [S0174 Responder](https://attack.mitre.org/software/S0174), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0443 MESSAGETAP](https://attack.mitre.org/software/S0443), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0590 NBTscan](https://attack.mitre.org/software/S0590), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S1154 VersaMem](https://attack.mitre.org/software/S1154), [S1186 Line Dancer](https://attack.mitre.org/software/S1186), [S1203 J-magic](https://attack.mitre.org/software/S1203), [S1204 cd00r](https://attack.mitre.org/software/S1204), [S1206 JumbledPath](https://attack.mitre.org/software/S1206), [S1224 CASTLETAP](https://attack.mitre.org/software/S1224)  

---

### T1110 — Brute Force
<a id="t1110"></a>

**Tactics:** Credential Access · **Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, macOS, Network Devices, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110)  

Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1110) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 14 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 7 software:** [S0220 Chaos](https://attack.mitre.org/software/S0220), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0572 Caterpillar WebShell](https://attack.mitre.org/software/S0572), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0650 QakBot](https://attack.mitre.org/software/S0650)  

---

### T1110.001 — Password Guessing
<a id="t1110001"></a>

sub-technique of [T1110](credential-access.md#t1110) · **Tactics:** Credential Access · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Containers, Network Devices, Office Suite, Identity Provider, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110/001)  

Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism.

**ATT&CK mitigations (4):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Password Guessing via Multi-Source Authentication Failure Correlation  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 9 software:** [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0374 SpeakUp](https://attack.mitre.org/software/S0374), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698)  

---

### T1110.002 — Password Cracking
<a id="t1110002"></a>

sub-technique of [T1110](credential-access.md#t1110) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows, Network Devices, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110/002)  

Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. OS Credential Dumping can be used to obtain password hashes, this may only get an adversary so far when Pass the Hash is not an option.

**ATT&CK mitigations (2):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Post-Credential Dump Password Cracking Detection via Suspicious File Access and Hash Analysis Tools  
**Used by 4 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
**Implemented by 1 software:** [S0056 Net Crawler](https://attack.mitre.org/software/S0056)  

---

### T1110.003 — Password Spraying
<a id="t1110003"></a>

sub-technique of [T1110](credential-access.md#t1110) · **Tactics:** Credential Access · **Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110/003)  

Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain.

**ATT&CK mitigations (3):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Distributed Password Spraying via Authentication Failures Across Multiple Accounts  
**Used by 11 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1030 Agrius](https://attack.mitre.org/groups/G1030)  
**Implemented by 4 software:** [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362), [S0413 MailSniper](https://attack.mitre.org/software/S0413), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606)  

---

### T1110.004 — Credential Stuffing
<a id="t1110004"></a>

sub-technique of [T1110](credential-access.md#t1110) · **Tactics:** Credential Access · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Containers, Network Devices, Office Suite, Identity Provider, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110/004)  

Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Credential Stuffing Detection via Reused Breached Credentials Across Services  
**Used by 1 threat groups:** [G0114 Chimera](https://attack.mitre.org/groups/G0114)  
**Implemented by 1 software:** [S0266 TrickBot](https://attack.mitre.org/software/S0266)  

---

### T1111 — Multi-Factor Authentication Interception
<a id="t1111"></a>

**Tactics:** Credential Access · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1111)  

Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources.

**ATT&CK mitigations (1):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017)  
**NIST 800-53 R5 controls (9):** `AC-20`, `CA-7`, `CM-2`, `CM-6`, `IA-13`, `IA-2`, `IA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for MFA Interception via Input Capture and Smart Card Proxying  
**Used by 4 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 2 software:** [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104)  

---

### T1187 — Forced Authentication
<a id="t1187"></a>

**Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1187)  

Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.

**ATT&CK mitigations (2):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detect Forced SMB/WebDAV Authentication via lure files and outbound NTLM  
**Used by 2 threat groups:** [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0079 DarkHydrus](https://attack.mitre.org/groups/G0079)  
**Implemented by 1 software:** [S0634 EnvyScout](https://attack.mitre.org/software/S0634)  

---

### T1212 — Exploitation for Credential Access
<a id="t1212"></a>

**Tactics:** Credential Access · **Platforms:** Linux, Windows, macOS, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1212)  

Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.

**ATT&CK mitigations (5):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1019 Threat Intelligence Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1019), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (24):** `AC-2`, `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-8`, `IA-2`, `IA-5`, `RA-10`, `RA-5`, `SC-18`, `SC-2`, `SC-26`, `SC-3`, `SC-30`, `SC-35`, `SC-39`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-5`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Exploitation for Credential Access  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  

---

### T1528 — Steal Application Access Token
<a id="t1528"></a>

**Tactics:** Credential Access · **Platforms:** SaaS, Containers, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1528)  

Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (19):** `AC-10`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-13`, `IA-2`, `IA-4`, `IA-5`, `IA-8`, `RA-5`, `SA-11`, `SA-15`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1528 - Steal Application Access Token  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 2 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1539 — Steal Web Session Cookie
<a id="t1539"></a>

**Tactics:** Credential Access · **Platforms:** Linux, Office Suite, SaaS, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1539)  

An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.

**ATT&CK mitigations (6):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (10):** `AC-20`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Web Session Cookie Theft via File, Memory, and Network Artifacts  
**Used by 8 threat groups:** [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 16 software:** [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0568 EVILNUM](https://attack.mitre.org/software/S0568), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0657 BLUELIGHT](https://attack.mitre.org/software/S0657), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1140 Spica](https://attack.mitre.org/software/S1140), [S1146 MgBot](https://attack.mitre.org/software/S1146), [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240)  

---

### T1552 — Unsecured Credentials
<a id="t1552"></a>

**Tactics:** Credential Access · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Containers, Network Devices, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552)  

Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. Shell History), operating system or application-specific repositories (e.g.

**ATT&CK mitigations (11):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (32):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-3`, `IA-4`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-12`, `SC-28`, `SC-4`, `SC-7`, `SI-10`, `SI-12`, `SI-15`, `SI-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Access or Search for Unsecured Credentials Across Platforms  
**Used by 1 threat groups:** [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 4 software:** [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S1091 Pacu](https://attack.mitre.org/software/S1091), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1131 NPPSPY](https://attack.mitre.org/software/S1131)  

---

### T1552.001 — Credentials In Files
<a id="t1552001"></a>

sub-technique of [T1552](credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Containers, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/001)  

Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (17):** `AC-2`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-12`, `SC-28`, `SC-4`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Detect Access to Unsecured Credential Files Across Platforms  
**Used by 14 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 18 software:** [S0067 pngdowner](https://attack.mitre.org/software/S0067), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0117 XTunnel](https://attack.mitre.org/software/S0117), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0344 Azorult](https://attack.mitre.org/software/S0344), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183)  

---

### T1552.002 — Credentials in Registry
<a id="t1552002"></a>

sub-technique of [T1552](credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/002)  

Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (18):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-12`, `SC-28`, `SC-4`, `SI-4`  
**ATT&CK detection strategy:** Detect Credential Discovery via Windows Registry Enumeration  
**Used by 2 threat groups:** [G0050 APT32](https://attack.mitre.org/groups/G0050), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 7 software:** [S0075 Reg](https://attack.mitre.org/software/S0075), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0476 Valak](https://attack.mitre.org/software/S0476), [S1022 IceApple](https://attack.mitre.org/software/S1022), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183)  

---

### T1552.003 — Shell History
<a id="t1552003"></a>

sub-technique of [T1552](credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/003)  

Adversaries may search the command history on compromised systems for insecurely stored credentials. On Linux and macOS systems, shells such as Bash and Zsh keep track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user's history file.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (4):** `CM-6`, `CM-7`, `SC-28`, `SI-4`  
**ATT&CK detection strategy:** Detect Access and Parsing of .bash_history Files for Credential Harvesting  
**Implemented by 1 software:** [S0599 Kinsing](https://attack.mitre.org/software/S0599)  

---

### T1552.004 — Private Keys
<a id="t1552004"></a>

sub-technique of [T1552](credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/004)  

Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.

**ATT&CK mitigations (4):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-20`, `CA-7`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-12`, `SC-28`, `SC-4`, `SC-7`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Suspicious Access to Private Key Files and Export Attempts Across Platforms  
**Used by 5 threat groups:** [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 11 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1196 Troll Stealer](https://attack.mitre.org/software/S1196)  

---

### T1552.005 — Cloud Instance Metadata API
<a id="t1552005"></a>

sub-technique of [T1552](credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/005)  

Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.

**ATT&CK mitigations (3):** [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (14):** `AC-16`, `AC-17`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `IA-3`, `IA-4`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detect Access to Cloud Instance Metadata API (IaaS)  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 2 software:** [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1552.006 — Group Policy Preferences
<a id="t1552006"></a>

sub-technique of [T1552](credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/006)  

Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts. These group policies are stored in SYSVOL on a domain controller.

**ATT&CK mitigations (3):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-5`, `AC-6`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SI-2`, `SI-4`  
**ATT&CK detection strategy:** Detect Access and Decryption of Group Policy Preference (GPP) Credentials in SYSVOL  
**Used by 2 threat groups:** [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 2 software:** [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692)  

---

### T1552.007 — Container API
<a id="t1552007"></a>

sub-technique of [T1552](credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/007)  

Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035)  
**NIST 800-53 R5 controls (14):** `AC-17`, `AC-2`, `AC-23`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-46`, `SC-7`, `SC-8`  
**ATT&CK detection strategy:** Detect Abuse of Container APIs for Credential Access  
**Implemented by 1 software:** [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1552.008 — Chat Messages
<a id="t1552008"></a>

sub-technique of [T1552](credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** SaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/008)  

Adversaries may directly collect unsecured credentials stored or passed through user communication services.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (2):** `AC-4`, `SI-4`  
**ATT&CK detection strategy:** Detect Unsecured Credentials Shared in Chat Messages  
**Used by 1 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  

---

### T1555 — Credentials from Password Stores
<a id="t1555"></a>

**Tactics:** Credential Access · **Platforms:** IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555)  

Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (8):** `AC-20`, `AC-3`, `AC-6`, `CA-7`, `CM-3`, `IA-5`, `SI-2`, `SI-4`  
**ATT&CK detection strategy:** Detect Credentials Access from Password Stores  
**Used by 12 threat groups:** [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1026 Malteiro](https://attack.mitre.org/groups/G1026)  
**Implemented by 24 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0138 OLDBAIT](https://attack.mitre.org/software/S0138), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0435 PLEAD](https://attack.mitre.org/software/S0435), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1146 MgBot](https://attack.mitre.org/software/S1146), [S1156 Manjusaka](https://attack.mitre.org/software/S1156), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1555.001 — Keychain
<a id="t1555001"></a>

sub-technique of [T1555](credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/001)  

Adversaries may acquire credentials from Keychain. Keychain (or Keychain Services) is the macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure notes.

**ATT&CK mitigations (1):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (3):** `CA-7`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Detect Access to macOS Keychain for Credential Theft  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 10 software:** [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0278 iKitten](https://attack.mitre.org/software/S0278), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0690 Green Lambert](https://attack.mitre.org/software/S0690), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153), [S1185 LightSpy](https://attack.mitre.org/software/S1185), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1555.002 — Securityd Memory
<a id="t1555002"></a>

sub-technique of [T1555](credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/002)  

An adversary with root access may gather credentials by reading `securityd`’s memory. `securityd` is a service/daemon responsible for implementing security protocols such as encryption and authorization.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (5):** `AC-3`, `AC-6`, `CA-7`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Detect Suspicious Access to securityd Memory for Credential Extraction  
**Implemented by 1 software:** [S0276 Keydnap](https://attack.mitre.org/software/S0276)  

---

### T1555.003 — Credentials from Web Browsers
<a id="t1555003"></a>

sub-technique of [T1555](credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/003)  

Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Suspicious Access to Browser Credential Stores  
**Used by 23 threat groups:** [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0130 Ajax Security Team](https://attack.mitre.org/groups/G0130), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1026 Malteiro](https://attack.mitre.org/groups/G1026), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 62 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0130 Unknown Logger](https://attack.mitre.org/software/S0130), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0138 OLDBAIT](https://attack.mitre.org/software/S0138), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0161 XAgentOSX](https://attack.mitre.org/software/S0161), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331) _(+38 more)_  

---

### T1555.004 — Windows Credential Manager
<a id="t1555004"></a>

sub-technique of [T1555](credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/004)  

Adversaries may acquire credentials from the Windows Credential Manager. The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (previously known as Windows Vaults).

**ATT&CK mitigations (1):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (5):** `CM-2`, `CM-6`, `CM-7`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Detect Suspicious Access to Windows Credential Manager  
**Used by 4 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 9 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526), [S0629 RainyDay](https://attack.mitre.org/software/S0629), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692)  

---

### T1555.005 — Password Managers
<a id="t1555005"></a>

sub-technique of [T1555](credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/005)  

Adversaries may acquire user credentials from third-party password managers. Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a master password that unlocks the database.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `SI-2`, `SI-4`  
**ATT&CK detection strategy:** Detect Unauthorized Access to Password Managers  
**Used by 7 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 4 software:** [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0652 MarkiRAT](https://attack.mitre.org/software/S0652), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1555.006 — Cloud Secrets Management Stores
<a id="t1555006"></a>

sub-technique of [T1555](credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/006)  

Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault. Secrets managers support the secure centralized management of passwords, API keys, and other credential material.

**ATT&CK mitigations (1):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `CM-7`  
**ATT&CK detection strategy:** Detect Unauthorized Access to Cloud Secrets Management Stores  
**Used by 2 threat groups:** [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1556 — Modify Authentication Process
<a id="t1556"></a>

**Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Windows, Linux, macOS, Network Devices, IaaS, SaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556)  

Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.

**ATT&CK mitigations (9):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (17):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-13`, `IA-2`, `IA-5`, `SC-39`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Modification of Authentication Processes Across Platforms  
**Used by 1 threat groups:** [G1016 FIN13](https://attack.mitre.org/groups/G1016)  
**Implemented by 3 software:** [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0487 Kessel](https://attack.mitre.org/software/S0487), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692)  

---

### T1556.001 — Domain Controller Authentication
<a id="t1556001"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/001)  

Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-39`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Domain Controller Authentication Process Modification (Skeleton Key)  
**Used by 1 threat groups:** [G0114 Chimera](https://attack.mitre.org/groups/G0114)  
**Implemented by 1 software:** [S0007 Skeleton Key](https://attack.mitre.org/software/S0007)  

---

### T1556.002 — Password Filter DLL
<a id="t1556002"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/002)  

Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated. Windows password filters are password policy enforcement mechanisms for both domain and local accounts.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (3):** `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Detect Malicious Password Filter DLL Registration  
**Used by 2 threat groups:** [G0041 Strider](https://attack.mitre.org/groups/G0041), [G0049 OilRig](https://attack.mitre.org/groups/G0049)  
**Implemented by 1 software:** [S0125 Remsec](https://attack.mitre.org/software/S0125)  

---

### T1556.003 — Pluggable Authentication Modules
<a id="t1556003"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/003)  

Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Malicious Modification of Pluggable Authentication Modules (PAM)  
**Implemented by 2 software:** [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0468 Skidmap](https://attack.mitre.org/software/S0468)  

---

### T1556.004 — Network Device Authentication
<a id="t1556004"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/004)  

Adversaries may use Patch System Image to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Modification of Network Device Authentication via Patched System Images  
**Implemented by 2 software:** [S0519 SYNful Knock](https://attack.mitre.org/software/S0519), [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104)  

---

### T1556.005 — Reversible Encryption
<a id="t1556005"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/005)  

An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The <code>AllowReversiblePasswordEncryption</code> property specifies whether reversible password encryption for an account is enabled or disabled.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-5`, `AC-6`, `IA-5`  
**ATT&CK detection strategy:** Detect Modification of Authentication Process via Reversible Encryption  

---

### T1556.006 — Multi-Factor Authentication
<a id="t1556006"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/006)  

Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (6):** `AC-2`, `AC-3`, `AC-6`, `IA-11`, `IA-13`, `IA-2`  
**ATT&CK detection strategy:** Detect MFA Modification or Disabling Across Platforms  
**Used by 1 threat groups:** [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  
**Implemented by 2 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104)  

---

### T1556.007 — Hybrid Identity
<a id="t1556007"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Windows, SaaS, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/007)  

Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (6):** `AC-2`, `AC-3`, `AC-6`, `IA-11`, `IA-13`, `IA-2`  
**ATT&CK detection strategy:** Detect Hybrid Identity Authentication Process Modification  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1556.008 — Network Provider DLL
<a id="t1556008"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/008)  

Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions.

**ATT&CK mitigations (3):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Network Provider DLL Registration and Credential Capture  

---

### T1556.009 — Conditional Access Policies
<a id="t1556009"></a>

sub-technique of [T1556](credential-access.md#t1556) · **Tactics:** Credential Access, Defense Evasion, Persistence · **Platforms:** IaaS, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1556/009)  

Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts. Conditional access policies are additional verifications used by identity providers and identity and access management systems to determine whether a user should be granted access to a resource.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (14):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-13`, `IA-2`, `IA-5`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Conditional Access Policy Modification in Identity and Cloud Platforms  
**Used by 2 threat groups:** [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1557 — Adversary-in-the-Middle
<a id="t1557"></a>

**Tactics:** Credential Access, Collection · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557)  

Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as Network Sniffing, Transmitted Data Manipulation, or replay attacks (Exploitation for Credential Access).

**ATT&CK mitigations (7):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (24):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-23`, `SC-4`, `SC-46`, `SC-7`, `SC-8`, `SI-10`, `SI-12`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Adversary-in-the-Middle via Network and Configuration Anomalies  
**Used by 3 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  
**Implemented by 3 software:** [S0281 Dok](https://attack.mitre.org/software/S0281), [S1131 NPPSPY](https://attack.mitre.org/software/S1131), [S1188 Line Runner](https://attack.mitre.org/software/S1188)  

---

### T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay
<a id="t1557001"></a>

sub-technique of [T1557](credential-access.md#t1557) · **Tactics:** Credential Access, Collection · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557/001)  

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials.

**ATT&CK mitigations (4):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (15):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-23`, `SC-46`, `SC-7`, `SC-8`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect LLMNR/NBT-NS Poisoning and SMB Relay on Windows  
**Used by 2 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 5 software:** [S0174 Responder](https://attack.mitre.org/software/S0174), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378)  

---

### T1557.002 — ARP Cache Poisoning
<a id="t1557002"></a>

sub-technique of [T1557](credential-access.md#t1557) · **Tactics:** Credential Access, Collection · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557/002)  

Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.

**ATT&CK mitigations (6):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (22):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-23`, `SC-4`, `SC-7`, `SC-8`, `SI-10`, `SI-12`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect ARP Cache Poisoning Across Linux, Windows, and macOS  
**Used by 2 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014)  

---

### T1557.003 — DHCP Spoofing
<a id="t1557003"></a>

sub-technique of [T1557](credential-access.md#t1557) · **Tactics:** Credential Access, Collection · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557/003)  

Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (15):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-23`, `SC-46`, `SC-7`, `SC-8`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect DHCP Spoofing Across Linux, Windows, and macOS  

---

### T1557.004 — Evil Twin
<a id="t1557004"></a>

sub-technique of [T1557](credential-access.md#t1557) · **Tactics:** Credential Access, Collection · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557/004)  

Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on behaviors such as Network Sniffing, Transmitted Data Manipulation, or Input Capture.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (16):** `AC-18`, `AC-19`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-13`, `SC-23`, `SC-40`, `SC-46`, `SC-7`, `SC-8`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Evil Twin Wi-Fi Access Points on Network Devices  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  

---

### T1558 — Steal or Forge Kerberos Tickets
<a id="t1558"></a>

**Tactics:** Credential Access · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558)  

Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket. Kerberos is an authentication protocol widely used in modern Windows domain environments.

**ATT&CK mitigations (6):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Kerberos Ticket Theft or Forgery (T1558)  
**Used by 1 threat groups:** [G1024 Akira](https://attack.mitre.org/groups/G1024)  

---

### T1558.001 — Golden Ticket
<a id="t1558001"></a>

sub-technique of [T1558](credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/001)  

Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets enable adversaries to generate authentication material for any account in Active Directory.

**ATT&CK mitigations (2):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (9):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`  
**ATT&CK detection strategy:** Detect Forged Kerberos Golden Tickets (T1558.001)  
**Used by 1 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004)  
**Implemented by 4 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S1071 Rubeus](https://attack.mitre.org/software/S1071)  

---

### T1558.002 — Silver Ticket
<a id="t1558002"></a>

sub-technique of [T1558](credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/002)  

Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Forged Kerberos Silver Tickets (T1558.002)  
**Implemented by 4 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1071 Rubeus](https://attack.mitre.org/software/S1071)  

---

### T1558.003 — Kerberoasting
<a id="t1558003"></a>

sub-technique of [T1558](credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/003)  

Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force. Service principal names (SPNs) are used to uniquely identify each instance of a Windows service.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Kerberoasting Attempts (T1558.003)  
**Used by 3 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119)  
**Implemented by 6 software:** [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1071 Rubeus](https://attack.mitre.org/software/S1071)  

---

### T1558.004 — AS-REP Roasting
<a id="t1558004"></a>

sub-technique of [T1558](credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/004)  

Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by Password Cracking Kerberos messages. Preauthentication offers protection against offline Password Cracking.

**ATT&CK mitigations (3):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `CA-7`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect AS-REP Roasting Attempts (T1558.004)  
**Implemented by 1 software:** [S1071 Rubeus](https://attack.mitre.org/software/S1071)  

---

### T1558.005 — Ccache Files
<a id="t1558005"></a>

sub-technique of [T1558](credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/005)  

Adversaries may attempt to steal Kerberos tickets stored in credential cache files (or ccache). These files are used for short term storage of a user's active session credentials.

**ATT&CK mitigations (2):** [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (10):** `AC-2`, `AC-3`, `AC-6`, `CA-7`, `IA-2`, `IA-5`, `SC-4`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Kerberos Ccache File Theft or Abuse (T1558.005)  
**Implemented by 1 software:** [S0357 Impacket](https://attack.mitre.org/software/S0357)  

---

### T1606 — Forge Web Credentials
<a id="t1606"></a>

**Tactics:** Credential Access · **Platforms:** SaaS, Windows, macOS, Linux, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1606)  

Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `IA-13`, `SC-17`, `SI-2`  
**ATT&CK detection strategy:** Detection Strategy for Forged Web Credentials  

---

### T1606.001 — Web Cookies
<a id="t1606001"></a>

sub-technique of [T1606](credential-access.md#t1606) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows, SaaS, IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1606/001)  

Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and authorize user access.

**ATT&CK mitigations (2):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `SI-2`  
**ATT&CK detection strategy:** Detection Strategy for Forged Web Cookies  

---

### T1606.002 — SAML Tokens
<a id="t1606002"></a>

sub-technique of [T1606](credential-access.md#t1606) · **Tactics:** Credential Access · **Platforms:** SaaS, Windows, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1606/002)  

An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate. The default lifetime of a SAML token is one hour, but the validity period can be specified in the <code>NotOnOrAfter</code> value of the <code>conditions ...</code> element in a token.

**ATT&CK mitigations (4):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `IA-13`  
**ATT&CK detection strategy:** Detection Strategy for Forged SAML Tokens  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1621 — Multi-Factor Authentication Request Generation
<a id="t1621"></a>

**Tactics:** Credential Access · **Platforms:** Windows, Linux, macOS, IaaS, SaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1621)  

Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-6`, `CM-5`, `IA-13`, `IA-2`, `IA-3`, `IA-5`  
**ATT&CK detection strategy:** Detection Strategy for Multi-Factor Authentication Request Generation (T1621)  
**Used by 3 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1649 — Steal or Forge Authentication Certificates
<a id="t1649"></a>

**Tactics:** Credential Access · **Platforms:** Windows, Linux, macOS, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1649)  

Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material.

**ATT&CK mitigations (4):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (3):** `IA-13`, `IA-2`, `IA-5`  
**ATT&CK detection strategy:** Detection Strategy for Steal or Forge Authentication Certificates  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 2 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

