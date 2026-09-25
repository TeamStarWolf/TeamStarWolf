# Impact — Technique Detail

> Full detail pages for the **33 ATT&CK techniques** whose primary tactic is [Impact](https://attack.mitre.org/tactics/TA0040/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1485 — Data Destruction
<a id="t1485"></a>

**Tactics:** Impact · **Platforms:** Containers, ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1485)  

Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns  
**Used by 5 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 24 software:** [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0195 SDelete](https://attack.mitre.org/software/S0195), [S0238 Proxysvc](https://attack.mitre.org/software/S0238), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0364 RawDisk](https://attack.mitre.org/software/S0364), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0380 StoneDrill](https://attack.mitre.org/software/S0380), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0693 CaddyWiper](https://attack.mitre.org/software/S0693), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1125 AcidRain](https://attack.mitre.org/software/S1125), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1167 AcidPour](https://attack.mitre.org/software/S1167), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178)  

---

### T1485.001 — Lifecycle-Triggered Deletion
<a id="t1485001"></a>

sub-technique of [T1485](/techniques/impact.md#t1485) · **Tactics:** Impact · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1485/001)  

Adversaries may modify the lifecycle policies of a cloud storage bucket to destroy all objects stored within. Cloud storage buckets often allow users to set lifecycle policies to automate the migration, archival, or deletion of objects after a set period of time.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (6):** `AC-2`, `AC-3`, `AC-6`, `CP-10`, `CP-9`, `SI-7`  
**ATT&CK detection strategy:** Detection of Lifecycle Policy Modifications for Triggered Deletion in IaaS Cloud Storage  

---

### T1486 — Data Encrypted for Impact
<a id="t1486"></a>

**Tactics:** Impact · **Platforms:** ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1486)  

Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (11):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-6`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1486) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 17 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1050 Water Galura](https://attack.mitre.org/groups/G1050), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 61 software:** [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0370 SamSam](https://attack.mitre.org/software/S0370), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0389 JCry](https://attack.mitre.org/software/S0389), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0556 Pay2Key](https://attack.mitre.org/software/S0556), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0605 EKANS](https://attack.mitre.org/software/S0605), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606), [S0607 KillDisk](https://attack.mitre.org/software/S0607) _(+37 more)_  

---

### T1489 — Service Stop
<a id="t1489"></a>

**Tactics:** Impact · **Platforms:** ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1489)  

Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1060 Out-of-Band Communications Channel](../ATTACK_MITIGATIONS_REFERENCE.md#m1060)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-37`, `SC-46`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection for Service Stop across Platforms  
**Used by 6 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 44 software:** [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S0431 HotCroissant](https://attack.mitre.org/software/S0431), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0533 SLOTHFULMEDIA](https://attack.mitre.org/software/S0533), [S0556 Pay2Key](https://attack.mitre.org/software/S0556), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0582 LookBack](https://attack.mitre.org/software/S0582), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0605 EKANS](https://attack.mitre.org/software/S0605), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0625 Cuba](https://attack.mitre.org/software/S0625), [S0638 Babuk](https://attack.mitre.org/software/S0638), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0688 Meteor](https://attack.mitre.org/software/S0688) _(+20 more)_  

---

### T1490 — Inhibit System Recovery
<a id="t1490"></a>

**Tactics:** Impact · **Platforms:** Containers, ESXi, IaaS, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1490)  

Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-6`, `CM-7`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection for T1490 - Inhibit System Recovery  
**Used by 6 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 48 software:** [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0389 JCry](https://attack.mitre.org/software/S0389), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0605 EKANS](https://attack.mitre.org/software/S0605), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0616 DEATHRANSOM](https://attack.mitre.org/software/S0616), [S0617 HELLOKITTY](https://attack.mitre.org/software/S0617), [S0618 FIVEHANDS](https://attack.mitre.org/software/S0618), [S0638 Babuk](https://attack.mitre.org/software/S0638), [S0640 Avaddon](https://attack.mitre.org/software/S0640) _(+24 more)_  

---

### T1491 — Defacement
<a id="t1491"></a>

**Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1491)  

Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for Defacement include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Defacement via File and Web Content Modification Across Platforms  

---

### T1491.001 — Internal Defacement
<a id="t1491001"></a>

sub-technique of [T1491](/techniques/impact.md#t1491) · **Tactics:** Impact · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1491/001)  

An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites or server login messages, or directly to user systems with the replacement of the desktop wallpaper.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Internal Website and System Content Defacement via UI or Messaging Modifications  
**Used by 3 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 9 software:** [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1139 INC Ransomware](https://attack.mitre.org/software/S1139), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1491.002 — External Defacement
<a id="t1491002"></a>

sub-technique of [T1491](/techniques/impact.md#t1491) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1491/002)  

An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users. External Defacement may ultimately cause users to distrust the systems and to question/discredit the system’s integrity.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of External Website Defacement across Platforms  
**Used by 2 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  

---

### T1495 — Firmware Corruption
<a id="t1495"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1495)  

Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (16):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Firmware Modification via Flash Tool or Corrupted Firmware Upload  
**Implemented by 2 software:** [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606)  

---

### T1496 — Resource Hijacking
<a id="t1496"></a>

**Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS, Containers, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496)  

Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. Resource hijacking may take a number of different forms.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Resource Hijacking Detection Strategy  

---

### T1496.001 — Compute Hijacking
<a id="t1496001"></a>

sub-technique of [T1496](/techniques/impact.md#t1496) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496/001)  

Adversaries may leverage the compute resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. One common purpose for Compute Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Multi-Platform Behavioral Detection for Compute Hijacking  
**Used by 4 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 9 software:** [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0486 Bonadan](https://attack.mitre.org/software/S0486), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1496.002 — Bandwidth Hijacking
<a id="t1496002"></a>

sub-technique of [T1496](/techniques/impact.md#t1496) · **Tactics:** Impact · **Platforms:** Linux, Windows, macOS, IaaS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496/002)  

Adversaries may leverage the network bandwidth resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Excessive or Unauthorized Bandwidth Usage for Botnet, Proxyjacking, or Scanning Purposes  

---

### T1496.003 — SMS Pumping
<a id="t1496003"></a>

sub-technique of [T1496](/techniques/impact.md#t1496) · **Tactics:** Impact · **Platforms:** SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496/003)  

Adversaries may leverage messaging services for SMS pumping, which may impact system and/or hosted service availability.

**ATT&CK mitigations (1):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013)  
**NIST 800-53 R5 controls (1):** `SC-5`  
**ATT&CK detection strategy:** Detection Strategy for Resource Hijacking: SMS Pumping via SaaS Application Logs  

---

### T1496.004 — Cloud Service Hijacking
<a id="t1496004"></a>

sub-technique of [T1496](/techniques/impact.md#t1496) · **Tactics:** Impact · **Platforms:** SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496/004)  

Adversaries may leverage compromised software-as-a-service (SaaS) applications to complete resource-intensive tasks, which may impact hosted service availability.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Cloud Service Hijacking via SaaS Abuse  

---

### T1498 — Network Denial of Service
<a id="t1498"></a>

**Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1498)  

Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`  
**ATT&CK detection strategy:** Behavioral Detection of T1498 – Network Denial of Service Across Platforms  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  
**Implemented by 2 software:** [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S1107 NKAbuse](https://attack.mitre.org/software/S1107)  

---

### T1498.001 — Direct Network Flood
<a id="t1498001"></a>

sub-technique of [T1498](/techniques/impact.md#t1498) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1498/001)  

Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`  
**ATT&CK detection strategy:** Direct Network Flood Detection across IaaS, Linux, Windows, and macOS  

---

### T1498.002 — Reflection Amplification
<a id="t1498002"></a>

sub-technique of [T1498](/techniques/impact.md#t1498) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1498/002)  

Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address. This third-party server is commonly termed a reflector.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`  
**ATT&CK detection strategy:** Detection Strategy for Reflection Amplification DoS (T1498.002)  

---

### T1499 — Endpoint Denial of Service
<a id="t1499"></a>

**Tactics:** Impact · **Platforms:** Windows, Linux, macOS, Containers, IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499)  

Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Endpoint Resource Saturation and Crash Pattern Detection Across Platforms  
**Used by 1 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034)  
**Implemented by 2 software:** [S0052 OnionDuke](https://attack.mitre.org/software/S0052), [S0412 ZxShell](https://attack.mitre.org/software/S0412)  

---

### T1499.001 — OS Exhaustion Flood
<a id="t1499001"></a>

sub-technique of [T1499](/techniques/impact.md#t1499) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499/001)  

Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Endpoint DoS via OS Exhaustion Flood Detection Strategy  

---

### T1499.002 — Service Exhaustion Flood
<a id="t1499002"></a>

sub-technique of [T1499](/techniques/impact.md#t1499) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499/002)  

Adversaries may target the different network services provided by systems to conduct a denial of service (DoS). Adversaries often target the availability of DNS and web services, however others have been targeted as well.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Endpoint DoS via Service Exhaustion Flood  

---

### T1499.003 — Application Exhaustion Flood
<a id="t1499003"></a>

sub-technique of [T1499](/techniques/impact.md#t1499) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499/003)  

Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Application Exhaustion Flood Detection Across Platforms  

---

### T1499.004 — Application or System Exploitation
<a id="t1499004"></a>

sub-technique of [T1499](/techniques/impact.md#t1499) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499/004)  

Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent denial of service (DoS) condition.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Endpoint DoS via Application or System Exploitation  
**Implemented by 1 software:** [S0604 Industroyer](https://attack.mitre.org/software/S0604)  

---

### T1529 — System Shutdown/Reboot
<a id="t1529"></a>

**Tactics:** Impact · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1529)  

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Multi-Platform Shutdown or Reboot Detection via Execution and Host Status Events  
**Used by 4 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 23 software:** [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0582 LookBack](https://attack.mitre.org/software/S0582), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1033 DCSrv](https://attack.mitre.org/software/S1033), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1125 AcidRain](https://attack.mitre.org/software/S1125), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1136 BFG Agonizer](https://attack.mitre.org/software/S1136), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1167 AcidPour](https://attack.mitre.org/software/S1167), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1531 — Account Access Removal
<a id="t1531"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Windows, SaaS, IaaS, Office Suite, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1531)  

Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials, revoked permissions for SaaS platforms such as Sharepoint) to remove access to accounts.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Account Access Removal via Multi-Platform Audit Correlation  
**Used by 2 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1024 Akira](https://attack.mitre.org/groups/G1024)  
**Implemented by 4 software:** [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134)  

---

### T1561 — Disk Wipe
<a id="t1561"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1561)  

Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Disk Wipe via Direct Disk Access and Destructive Commands  

---

### T1561.001 — Disk Content Wipe
<a id="t1561001"></a>

sub-technique of [T1561](/techniques/impact.md#t1561) · **Tactics:** Impact · **Platforms:** Linux, Network Devices, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1561/001)  

Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources. Adversaries may partially or completely overwrite the contents of a storage device rendering the data irrecoverable through the storage interface.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Disk Content Wipe via Direct Access and Overwrite  
**Used by 2 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047)  
**Implemented by 13 software:** [S0364 RawDisk](https://attack.mitre.org/software/S0364), [S0380 StoneDrill](https://attack.mitre.org/software/S0380), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1010 VPNFilter](https://attack.mitre.org/software/S1010), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1125 AcidRain](https://attack.mitre.org/software/S1125), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134), [S1167 AcidPour](https://attack.mitre.org/software/S1167), [S1205 cipher.exe](https://attack.mitre.org/software/S1205)  

---

### T1561.002 — Disk Structure Wipe
<a id="t1561002"></a>

sub-technique of [T1561](/techniques/impact.md#t1561) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1561/002)  

Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Disk Structure Wipe via Boot/Partition Overwrite  
**Used by 5 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  
**Implemented by 11 software:** [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0364 RawDisk](https://attack.mitre.org/software/S0364), [S0380 StoneDrill](https://attack.mitre.org/software/S0380), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0693 CaddyWiper](https://attack.mitre.org/software/S0693), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1136 BFG Agonizer](https://attack.mitre.org/software/S1136), [S1151 ZeroCleare](https://attack.mitre.org/software/S1151)  

---

### T1565 — Data Manipulation
<a id="t1565"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1565)  

Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.

**ATT&CK mitigations (4):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (26):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `CP-10`, `CP-6`, `CP-7`, `CP-9`, `SC-28`, `SC-36`, `SC-4`, `SC-46`, `SC-7`, `SI-12`, `SI-16`, `SI-23`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Data Manipulation  
**Used by 1 threat groups:** [G1016 FIN13](https://attack.mitre.org/groups/G1016)  

---

### T1565.001 — Stored Data Manipulation
<a id="t1565001"></a>

sub-technique of [T1565](/techniques/impact.md#t1565) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1565/001)  

Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (23):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `CA-7`, `CM-2`, `CM-6`, `CM-8`, `CP-10`, `CP-6`, `CP-7`, `CP-9`, `SC-28`, `SC-36`, `SC-4`, `SC-7`, `SI-12`, `SI-16`, `SI-23`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Stored Data Manipulation across OS Platforms.  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  
**Implemented by 2 software:** [S0562 SUNSPOT](https://attack.mitre.org/software/S0562), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135)  

---

### T1565.002 — Transmitted Data Manipulation
<a id="t1565002"></a>

sub-technique of [T1565](/techniques/impact.md#t1565) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1565/002)  

Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data. By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making.

**ATT&CK mitigations (1):** [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (12):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `CM-2`, `CM-6`, `CM-8`, `SC-4`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy of Transmitted Data Manipulation  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  
**Implemented by 3 software:** [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0530 Melcoz](https://attack.mitre.org/software/S0530)  

---

### T1565.003 — Runtime Data Manipulation
<a id="t1565003"></a>

sub-technique of [T1565](/techniques/impact.md#t1565) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1565/003)  

Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data. By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030)  
**NIST 800-53 R5 controls (13):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `CP-9`, `SC-28`, `SC-4`, `SC-46`, `SC-7`, `SI-16`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Runtime Data Manipulation.  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  

---

### T1657 — Financial Theft
<a id="t1657"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1657)  

Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (2):** `AC-5`, `AC-6`  
**ATT&CK detection strategy:** Detection Strategy for Financial Theft  
**Used by 14 threat groups:** [G0083 SilverTerrier](https://attack.mitre.org/groups/G0083), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1026 Malteiro](https://attack.mitre.org/groups/G1026), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1049 AppleJeus](https://attack.mitre.org/groups/G1049), [G1050 Water Galura](https://attack.mitre.org/groups/G1050), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 5 software:** [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245), [S1246 BeaverTail](https://attack.mitre.org/software/S1246), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1667 — Email Bombing
<a id="t1667"></a>

**Tactics:** Impact · **Platforms:** Linux, Office Suite, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1667)  

Adversaries may flood targeted email addresses with an overwhelming volume of messages. This may bury legitimate emails in a flood of spam and disrupt business operations.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Email Bombing  
**Used by 1 threat groups:** [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  

---

