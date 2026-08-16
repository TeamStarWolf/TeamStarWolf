# Lateral Movement — Technique Detail

> Full detail pages for the **17 ATT&CK techniques** whose primary tactic is [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](README.md).

---

### T1021 — Remote Services
<a id="t1021"></a>

**Tactics:** Lateral Movement · **Platforms:** Linux, macOS, Windows, IaaS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021)  

Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user. In an enterprise environment, servers and workstations can be organized into domains.

**ATT&CK mitigations (6):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (14):** `AC-17`, `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for Remote Service Logins and Post-Access Activity  
**Used by 3 threat groups:** [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  
**Implemented by 4 software:** [S0437 Kivars](https://attack.mitre.org/software/S0437), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063)  

---

### T1021.001 — Remote Desktop Protocol
<a id="t1021001"></a>

sub-technique of [T1021](lateral-movement.md#t1021) · **Tactics:** Lateral Movement · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021/001)  

Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user. Remote desktop is a common feature in operating systems.

**ATT&CK mitigations (8):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (23):** `AC-11`, `AC-12`, `AC-17`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `AC-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `IA-5`, `IA-6`, `RA-5`, `SC-46`, `SC-7`, `SI-4`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1021001) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 35 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119) _(+11 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 17 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0350 zwShell](https://attack.mitre.org/software/S0350), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S0382 ServHelper](https://attack.mitre.org/software/S0382), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S1187 reGeorg](https://attack.mitre.org/software/S1187)  

---

### T1021.002 — SMB/Windows Admin Shares
<a id="t1021002"></a>

sub-technique of [T1021](lateral-movement.md#t1021) · **Tactics:** Lateral Movement · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021/002)  

Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user. SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (16):** `AC-17`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Multi-Event Detection for SMB Admin Share Lateral Movement  
**Used by 26 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0028 Threat Group-1314](https://attack.mitre.org/groups/G0028), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0071 Orangeworm](https://attack.mitre.org/groups/G0071), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1043 BlackByte](https://attack.mitre.org/groups/G1043) _(+2 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 30 software:** [S0019 Regin](https://attack.mitre.org/software/S0019), [S0029 PsExec](https://attack.mitre.org/software/S0029), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0039 Net](https://attack.mitre.org/software/S0039), [S0056 Net Crawler](https://attack.mitre.org/software/S0056), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0350 zwShell](https://attack.mitre.org/software/S0350), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0672 Zox](https://attack.mitre.org/software/S0672), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1073 Royal](https://attack.mitre.org/software/S1073) _(+6 more)_  

---

### T1021.003 — Distributed Component Object Model
<a id="t1021003"></a>

sub-technique of [T1021](lateral-movement.md#t1021) · **Tactics:** Lateral Movement · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021/003)  

Adversaries may use Valid Accounts to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048)  
**NIST 800-53 R5 controls (19):** `AC-17`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SC-18`, `SC-3`, `SC-46`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Multi-Event Behavioral Detection for DCOM-Based Remote Code Execution  
**Implemented by 3 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692)  

---

### T1021.004 — SSH
<a id="t1021004"></a>

sub-technique of [T1021](lateral-movement.md#t1021) · **Tactics:** Lateral Movement · **Platforms:** ESXi, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021/004)  

Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH). The adversary may then perform actions as the logged-on user. SSH is a protocol that allows authorized users to open remote shells on other computers.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (15):** `AC-17`, `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CM-2`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `IA-5`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of Remote SSH Logins Followed by Post-Login Execution  
**Used by 19 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0036 GCMAN](https://attack.mitre.org/groups/G0036), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 4 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S1187 reGeorg](https://attack.mitre.org/software/S1187)  

---

### T1021.005 — VNC
<a id="t1021005"></a>

sub-technique of [T1021](lateral-movement.md#t1021) · **Tactics:** Lateral Movement · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021/005)  

Adversaries may use Valid Accounts to remotely control machines using Virtual Network Computing (VNC).

**ATT&CK mitigations (4):** [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (22):** `AC-17`, `AC-2`, `AC-3`, `AC-4`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of Unauthorized VNC Remote Control Sessions  
**Used by 4 threat groups:** [G0036 GCMAN](https://attack.mitre.org/groups/G0036), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117)  
**Implemented by 7 software:** [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S1014 DanBot](https://attack.mitre.org/software/S1014), [S1160 Latrodectus](https://attack.mitre.org/software/S1160)  

---

### T1021.006 — Windows Remote Management
<a id="t1021006"></a>

sub-technique of [T1021](lateral-movement.md#t1021) · **Tactics:** Lateral Movement · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021/006)  

Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (16):** `AC-17`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SC-46`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of WinRM-Based Remote Access  
**Used by 5 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 3 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063)  

---

### T1021.007 — Cloud Services
<a id="t1021007"></a>

sub-technique of [T1021](lateral-movement.md#t1021) · **Tactics:** Lateral Movement · **Platforms:** IaaS, Identity Provider, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021/007)  

Adversaries may log into accessible cloud services within a compromised environment using Valid Accounts that are synchronized with or federated to on-premises user identities. The adversary may then perform management actions or access cloud-hosted resources as the logged-on user.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `IA-2`, `IA-5`  
**ATT&CK detection strategy:** Behavioral Detection of Remote Cloud Logins via Valid Accounts  
**Used by 3 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1021.008 — Direct Cloud VM Connections
<a id="t1021008"></a>

sub-technique of [T1021](lateral-movement.md#t1021) · **Tactics:** Lateral Movement · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1021/008)  

Adversaries may leverage Valid Accounts to log directly into accessible cloud hosted compute infrastructure through cloud native methods.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-17`, `AC-2`, `AC-20`, `AC-3`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection of Direct VM Console Access via Cloud-Native Methods  

---

### T1080 — Taint Shared Content
<a id="t1080"></a>

**Tactics:** Lateral Movement · **Platforms:** Windows, SaaS, Linux, macOS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1080)  

Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files.

**ATT&CK mitigations (4):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050)  
**NIST 800-53 R5 controls (10):** `AC-3`, `CA-7`, `CM-2`, `CM-7`, `SC-4`, `SC-7`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Tainted Content Written to Shared Storage  
**Used by 5 threat groups:** [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 7 software:** [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0133 Miner-C](https://attack.mitre.org/software/S0133), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0603 Stuxnet](https://attack.mitre.org/software/S0603)  

---

### T1091 — Replication Through Removable Media
<a id="t1091"></a>

**Tactics:** Lateral Movement, Initial Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1091)  

Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes.

**ATT&CK mitigations (3):** [M1034 Limit Hardware Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1034), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CM-6`, `CM-8`, `MP-7`, `RA-5`, `SC-41`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Removable Media Execution Chain Detection via File and Process Activity  
**Used by 8 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1007 Aoqin Dragon](https://attack.mitre.org/groups/G1007), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014)  
**Implemented by 20 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0028 SHIPSHAPE](https://attack.mitre.org/software/S0028), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0092 Agent.btz](https://attack.mitre.org/software/S0092), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0130 Unknown Logger](https://attack.mitre.org/software/S0130), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0143 Flame](https://attack.mitre.org/software/S0143), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0452 USBferry](https://attack.mitre.org/software/S0452), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S1074 ANDROMEDA](https://attack.mitre.org/software/S1074), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1230 HIUPAN](https://attack.mitre.org/software/S1230)  

---

### T1210 — Exploitation of Remote Services
<a id="t1210"></a>

**Tactics:** Lateral Movement · **Platforms:** Linux, Windows, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1210)  

Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.

**ATT&CK mitigations (8):** [M1016 Vulnerability Scanning](../ATTACK_MITIGATIONS_REFERENCE.md#m1016), [M1019 Threat Intelligence Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1019), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (31):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-2`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-8`, `RA-10`, `RA-5`, `SC-18`, `SC-2`, `SC-26`, `SC-29`, `SC-3`, `SC-30`, `SC-35`, `SC-39`, `SC-46`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-5`, `SI-7`  
**ATT&CK detection strategy:** Exploitation of Remote Services – multi-platform lateral movement detection  
**Used by 11 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006)  
**Implemented by 13 software:** [S0143 Flame](https://attack.mitre.org/software/S0143), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0650 QakBot](https://attack.mitre.org/software/S0650)  

---

### T1534 — Internal Spearphishing
<a id="t1534"></a>

**Tactics:** Lateral Movement · **Platforms:** Windows, macOS, Linux, SaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1534)  

After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Internal Spearphishing via Trusted Accounts  
**Used by 4 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1001 HEXANE](https://attack.mitre.org/groups/G1001)  

---

### T1563 — Remote Service Session Hijacking
<a id="t1563"></a>

**Tactics:** Lateral Movement · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1563)  

Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (19):** `AC-12`, `AC-17`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SC-46`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Detection of Remote Service Session Hijacking  

---

### T1563.001 — SSH Hijacking
<a id="t1563001"></a>

sub-technique of [T1563](lateral-movement.md#t1563) · **Tactics:** Lateral Movement · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1563/001)  

Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems.

**ATT&CK mitigations (4):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (17):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `RA-5`, `SC-12`, `SC-23`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for SSH Session Hijacking  
**Implemented by 1 software:** [S1220 MEDUSA](https://attack.mitre.org/software/S1220)  

---

### T1563.002 — RDP Hijacking
<a id="t1563002"></a>

sub-technique of [T1563](lateral-movement.md#t1563) · **Tactics:** Lateral Movement · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1563/002)  

Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system.

**ATT&CK mitigations (7):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (18):** `AC-11`, `AC-12`, `AC-17`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SC-46`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Detection fo Remote Service Session Hijacking for RDP.  
**Used by 1 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001)  
**Implemented by 1 software:** [S0366 WannaCry](https://attack.mitre.org/software/S0366)  

---

### T1570 — Lateral Tool Transfer
<a id="t1570"></a>

**Tactics:** Lateral Movement · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1570)  

Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., Ingress Tool Transfer) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (11):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Lateral Tool Transfer across OS platforms  
**Used by 19 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1007 Aoqin Dragon](https://attack.mitre.org/groups/G1007), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 25 software:** [S0029 PsExec](https://attack.mitre.org/software/S0029), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0095 ftp](https://attack.mitre.org/software/S0095), [S0106 cmd](https://attack.mitre.org/software/S0106), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0190 BITSAdmin](https://attack.mitre.org/software/S0190), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0361 Expand](https://attack.mitre.org/software/S0361), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0404 esentutl](https://attack.mitre.org/software/S0404), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698), [S1017 OutSteel](https://attack.mitre.org/software/S1017), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1132 IPsec Helper](https://attack.mitre.org/software/S1132), [S1139 INC Ransomware](https://attack.mitre.org/software/S1139), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180), [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217), [S1218 VIRTUALPIE](https://attack.mitre.org/software/S1218) _(+1 more)_  

---

