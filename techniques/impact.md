# Impact — Technique Detail

> Full detail pages for the **33 ATT&CK techniques** whose primary tactic is [Impact](https://attack.mitre.org/tactics/TA0040/) (ATT&CK Enterprise v19.2). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1485 — Data Destruction
<a id="t1485"></a>

**Tactics:** Impact · **Platforms:** Containers, ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1485)  

Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives. Common operating system file deletion commands such as <code>del</code> and <code>rm</code> often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) and [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) because individual files are destroyed rather than sections of a storage disk or the disk's logical structure. Adversaries may attempt to overwrite files and directories with randomly generated data to make it irrecoverable. In some cases politically oriented image files have been used to overwrite data. To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware designed for destroying data may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).. In cloud environments, adversaries may leverage access to delete cloud storage objects, machine images, database instances, and other infrastructure crucial to operations to damage an organization or their customers. Similarly, they may delete virtual machines from on-prem virtualized environments.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Data Destruction Across Platforms via Mass Overwrite and Deletion Patterns  
**Used by 5 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 24 software:** [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0195 SDelete](https://attack.mitre.org/software/S0195), [S0238 Proxysvc](https://attack.mitre.org/software/S0238), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0364 RawDisk](https://attack.mitre.org/software/S0364), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0380 StoneDrill](https://attack.mitre.org/software/S0380), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0693 CaddyWiper](https://attack.mitre.org/software/S0693), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1125 AcidRain](https://attack.mitre.org/software/S1125), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1167 AcidPour](https://attack.mitre.org/software/S1167), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178)  

---

### T1485.001 — Lifecycle-Triggered Deletion
<a id="t1485001"></a>

sub-technique of [T1485](/techniques/impact.md#t1485) · **Tactics:** Impact · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1485/001)  

Adversaries may modify the lifecycle policies of a cloud storage bucket to destroy all objects stored within. Cloud storage buckets often allow users to set lifecycle policies to automate the migration, archival, or deletion of objects after a set period of time. If a threat actor has sufficient permissions to modify these policies, they may be able to delete all objects at once. For example, in AWS environments, an adversary with the `PutLifecycleConfiguration` permission may use the `PutBucketLifecycle` API call to apply a lifecycle policy to an S3 bucket that deletes all objects in the bucket after one day. In addition to destroying data for purposes of extortion and [Financial Theft](https://attack.mitre.org/techniques/T1657), adversaries may also perform this action on buckets storing cloud logs for [Indicator Removal](https://attack.mitre.org/techniques/T1070).

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (6):** `AC-2`, `AC-3`, `AC-6`, `CP-10`, `CP-9`, `SI-7`  
**ATT&CK detection strategy:** Detection of Lifecycle Policy Modifications for Triggered Deletion in IaaS Cloud Storage  

---

### T1486 — Data Encrypted for Impact
<a id="t1486"></a>

**Tactics:** Impact · **Platforms:** ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1486)  

Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted. In the case of ransomware, it is typical that common user files like Office documents, PDFs, images, videos, audio, text, and source code files will be encrypted (and often renamed and/or tagged with specific file markers). Adversaries may need to first employ other behaviors, such as [File and Directory Permissions Modification](https://attack.mitre.org/techniques/T1222) or [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529), in order to unlock and/or gain access to manipulate these files. In some cases, adversaries may encrypt critical system files, disk partitions, and the MBR. Adversaries may also encrypt virtual machines hosted on ESXi or other hypervisors. To maximize impact on the target organization, malware designed for encrypting data may have worm-like features to propagate across a network by leveraging other attack techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002). Encryption malware may also leverage [Internal Defacement](https://attack.mitre.org/techniques/T1491/001), such as changing victim wallpapers or ESXi server login messages, or otherwise intimidate victims by sending ransom notes or other messages to connected printers (known as "print bombing"). In cloud environments, storage objects within compromised accounts may also be encrypted. For example, in AWS environments, adversaries may leverage services such as AWS’s Server-Side Encryption with Customer Provided Keys (SSE-C) to encrypt data.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (11):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-6`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Multi-Platform File Encryption for Impact  
**Used by 17 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1050 Water Galura](https://attack.mitre.org/groups/G1050), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 61 software:** [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0370 SamSam](https://attack.mitre.org/software/S0370), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0389 JCry](https://attack.mitre.org/software/S0389), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0556 Pay2Key](https://attack.mitre.org/software/S0556), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0605 EKANS](https://attack.mitre.org/software/S0605), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0616 DEATHRANSOM](https://attack.mitre.org/software/S0616), [S0617 HELLOKITTY](https://attack.mitre.org/software/S0617), [S0618 FIVEHANDS](https://attack.mitre.org/software/S0618), [S0625 Cuba](https://attack.mitre.org/software/S0625), [S0638 Babuk](https://attack.mitre.org/software/S0638), [S0639 Seth-Locker](https://attack.mitre.org/software/S0639), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0654 ProLock](https://attack.mitre.org/software/S0654), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S1033 DCSrv](https://attack.mitre.org/software/S1033), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1058 Prestige](https://attack.mitre.org/software/S1058), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1073 Royal](https://attack.mitre.org/software/S1073), [S1096 Cheerscrypt](https://attack.mitre.org/software/S1096), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1129 Akira](https://attack.mitre.org/software/S1129), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1137 Moneybird](https://attack.mitre.org/software/S1137), [S1139 INC Ransomware](https://attack.mitre.org/software/S1139), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1162 Playcrypt](https://attack.mitre.org/software/S1162), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180), [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181), [S1191 Megazord](https://attack.mitre.org/software/S1191), [S1194 Akira _v2](https://attack.mitre.org/software/S1194), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1244 Medusa Ransomware](https://attack.mitre.org/software/S1244), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1489 — Service Stop
<a id="t1489"></a>

**Tactics:** Impact · **Platforms:** ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1489)  

Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment. Adversaries may accomplish this by disabling individual services of high importance to an organization, such as <code>MSExchangeIS</code>, which will make Exchange content inaccessible. In some cases, adversaries may stop or disable many or all services to render systems unusable. Services or processes may not allow for modification of their data stores while running. Adversaries may stop services or processes in order to conduct [Data Destruction](https://attack.mitre.org/techniques/T1485) or [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) on the data stores of services like Exchange and SQL Server, or on virtual machines hosted on ESXi infrastructure. Threat actors may also disable or stop service in cloud environments. For example, by leveraging the `DisableAPIServiceAccess` API in AWS, a threat actor may prevent the service from creating service-linked roles on new accounts in the AWS Organization.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1060 Out-of-Band Communications Channel](../ATTACK_MITIGATIONS_REFERENCE.md#m1060)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-37`, `SC-46`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection for Service Stop across Platforms  
**Used by 6 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 44 software:** [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S0431 HotCroissant](https://attack.mitre.org/software/S0431), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0533 SLOTHFULMEDIA](https://attack.mitre.org/software/S0533), [S0556 Pay2Key](https://attack.mitre.org/software/S0556), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0582 LookBack](https://attack.mitre.org/software/S0582), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0605 EKANS](https://attack.mitre.org/software/S0605), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0625 Cuba](https://attack.mitre.org/software/S0625), [S0638 Babuk](https://attack.mitre.org/software/S0638), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1058 Prestige](https://attack.mitre.org/software/S1058), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1073 Royal](https://attack.mitre.org/software/S1073), [S1096 Cheerscrypt](https://attack.mitre.org/software/S1096), [S1139 INC Ransomware](https://attack.mitre.org/software/S1139), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181), [S1191 Megazord](https://attack.mitre.org/software/S1191), [S1194 Akira _v2](https://attack.mitre.org/software/S1194), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1211 Hannotog](https://attack.mitre.org/software/S1211), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1244 Medusa Ransomware](https://attack.mitre.org/software/S1244), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1490 — Inhibit System Recovery
<a id="t1490"></a>

**Tactics:** Impact · **Platforms:** Containers, ESXi, IaaS, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1490)  

Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery. This may deny access to available backups and recovery options. Operating systems may contain features that can help fix corrupted systems, such as a backup catalog, volume shadow copies, and automatic repair features. Adversaries may disable or delete system recovery features to augment the effects of [Data Destruction](https://attack.mitre.org/techniques/T1485) and [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486). Furthermore, adversaries may disable recovery notifications, then corrupt backups. A number of native Windows utilities have been used by adversaries to disable or delete system recovery features: * <code>vssadmin.exe</code> can be used to delete all volume shadow copies on a system - <code>vssadmin.exe delete shadows /all /quiet</code> * [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) can be used to delete volume shadow copies - <code>wmic shadowcopy delete</code> * <code>wbadmin.exe</code> can be used to delete the Windows Backup Catalog - <code>wbadmin.exe delete catalog -quiet</code> * <code>bcdedit.exe</code> can be used to disable automatic Windows recovery features by modifying boot configuration data - <code>bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no</code> * <code>REAgentC.exe</code> can be used to disable Windows Recovery Environment (WinRE) repair/recovery options of an infected system * <code>diskshadow.exe</code> can be used to delete all volume shadow copies on a system - <code>diskshadow delete shadows all</code> On network devices, adversaries may leverage [Disk Wipe](https://attack.mitre.org/techniques/T1561) to delete backup firmware images and reformat the file system, then [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) to reload the device. Together this activity may leave network devices completely inoperable and inhibit recovery operations. On ESXi servers, adversaries may delete or encrypt snapshots of virtual machines to support [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486), preventing them from being leveraged as backups (e.g., via ` vim-cmd vmsvc/snapshot.removeall`). Adversaries may also delete “online” backups that are connected to their network – whether via network storage media or through folders that sync to cloud services. In cloud environments, adversaries may disable versioning and backup policies and delete snapshots, database backups, machine images, and prior versions of objects designed to be used in disaster recovery scenarios.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-6`, `CM-7`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection for T1490 - Inhibit System Recovery  
**Used by 6 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 48 software:** [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0389 JCry](https://attack.mitre.org/software/S0389), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0605 EKANS](https://attack.mitre.org/software/S0605), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0616 DEATHRANSOM](https://attack.mitre.org/software/S0616), [S0617 HELLOKITTY](https://attack.mitre.org/software/S0617), [S0618 FIVEHANDS](https://attack.mitre.org/software/S0618), [S0638 Babuk](https://attack.mitre.org/software/S0638), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0654 ProLock](https://attack.mitre.org/software/S0654), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1058 Prestige](https://attack.mitre.org/software/S1058), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1073 Royal](https://attack.mitre.org/software/S1073), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1129 Akira](https://attack.mitre.org/software/S1129), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1136 BFG Agonizer](https://attack.mitre.org/software/S1136), [S1139 INC Ransomware](https://attack.mitre.org/software/S1139), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1162 Playcrypt](https://attack.mitre.org/software/S1162), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180), [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1244 Medusa Ransomware](https://attack.mitre.org/software/S1244), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1491 — Defacement
<a id="t1491"></a>

**Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1491)  

Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for [Defacement](https://attack.mitre.org/techniques/T1491) include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of [Defacement](https://attack.mitre.org/techniques/T1491) in order to cause user discomfort, or to pressure compliance with accompanying messages.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Defacement via File and Web Content Modification Across Platforms  

---

### T1491.001 — Internal Defacement
<a id="t1491001"></a>

sub-technique of [T1491](/techniques/impact.md#t1491) · **Tactics:** Impact · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1491/001)  

An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites or server login messages, or directly to user systems with the replacement of the desktop wallpaper. Disturbing or offensive images may be used as a part of [Internal Defacement](https://attack.mitre.org/techniques/T1491/001) in order to cause user discomfort, or to pressure compliance with accompanying messages. Since internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Internal Website and System Content Defacement via UI or Messaging Modifications  
**Used by 3 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 9 software:** [S0659 Diavol](https://attack.mitre.org/software/S0659), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1139 INC Ransomware](https://attack.mitre.org/software/S1139), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1491.002 — External Defacement
<a id="t1491002"></a>

sub-technique of [T1491](/techniques/impact.md#t1491) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1491/002)  

An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users. [External Defacement](https://attack.mitre.org/techniques/T1491/002) may ultimately cause users to distrust the systems and to question/discredit the system’s integrity. Externally-facing websites are a common victim of defacement; often targeted by adversary and hacktivist groups in order to push a political message or spread propaganda. [External Defacement](https://attack.mitre.org/techniques/T1491/002) may be used as a catalyst to trigger events, or as a response to actions taken by an organization or government. Similarly, website defacement may also be used as setup, or a precursor, for future attacks such as [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of External Website Defacement across Platforms  
**Used by 2 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  

---

### T1495 — Firmware Corruption
<a id="t1495"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1495)  

Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system. Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards. In general, adversaries may manipulate, overwrite, or corrupt firmware in order to deny the use of the system or devices. For example, corruption of firmware responsible for loading the operating system for network devices may render the network devices inoperable. Depending on the device, this attack may also result in [Data Destruction](https://attack.mitre.org/techniques/T1485).

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (16):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Firmware Modification via Flash Tool or Corrupted Firmware Upload  
**Implemented by 2 software:** [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606)  

---

### T1496 — Resource Hijacking
<a id="t1496"></a>

**Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS, Containers, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496)  

Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. Resource hijacking may take a number of different forms. For example, adversaries may: * Leverage compute resources in order to mine cryptocurrency * Sell network bandwidth to proxy networks * Generate SMS traffic for profit * Abuse cloud-based messaging services to send large quantities of spam messages In some cases, adversaries may leverage multiple types of Resource Hijacking at once.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Resource Hijacking Detection Strategy  

---

### T1496.001 — Compute Hijacking
<a id="t1496001"></a>

sub-technique of [T1496](/techniques/impact.md#t1496) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496/001)  

Adversaries may leverage the compute resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. One common purpose for [Compute Hijacking](https://attack.mitre.org/techniques/T1496/001) is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive. Servers and cloud-based systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for [Compute Hijacking](https://attack.mitre.org/techniques/T1496/001) and cryptocurrency mining. Containerized environments may also be targeted due to the ease of deployment via exposed APIs and the potential for scaling mining activities by deploying or compromising multiple containers within an environment or cluster. Additionally, some cryptocurrency mining malware identify then kill off processes for competing malware to ensure it’s not competing for resources.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Multi-Platform Behavioral Detection for Compute Hijacking  
**Used by 4 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 9 software:** [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0486 Bonadan](https://attack.mitre.org/software/S0486), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1496.002 — Bandwidth Hijacking
<a id="t1496002"></a>

sub-technique of [T1496](/techniques/impact.md#t1496) · **Tactics:** Impact · **Platforms:** Linux, Windows, macOS, IaaS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496/002)  

Adversaries may leverage the network bandwidth resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability. Adversaries may also use malware that leverages a system's network bandwidth as part of a botnet in order to facilitate [Network Denial of Service](https://attack.mitre.org/techniques/T1498) campaigns and/or to seed malicious torrents. Alternatively, they may engage in proxyjacking by selling use of the victims' network bandwidth and IP address to proxyware services. Finally, they may engage in internet-wide scanning in order to identify additional targets for compromise. In addition to incurring potential financial costs or availability disruptions, this technique may cause reputational damage if a victim’s bandwidth is used for illegal activities.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Excessive or Unauthorized Bandwidth Usage for Botnet, Proxyjacking, or Scanning Purposes  

---

### T1496.003 — SMS Pumping
<a id="t1496003"></a>

sub-technique of [T1496](/techniques/impact.md#t1496) · **Tactics:** Impact · **Platforms:** SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496/003)  

Adversaries may leverage messaging services for SMS pumping, which may impact system and/or hosted service availability. SMS pumping is a type of telecommunications fraud whereby a threat actor first obtains a set of phone numbers from a telecommunications provider, then leverages a victim’s messaging infrastructure to send large amounts of SMS messages to numbers in that set. By generating SMS traffic to their phone number set, a threat actor may earn payments from the telecommunications provider. Threat actors often use publicly available web forms, such as one-time password (OTP) or account verification fields, in order to generate SMS traffic. These fields may leverage services such as Twilio, AWS SNS, and Amazon Cognito in the background. In response to the large quantity of requests, SMS costs may increase and communication channels may become overwhelmed.

**ATT&CK mitigations (1):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013)  
**NIST 800-53 R5 controls (1):** `SC-5`  
**ATT&CK detection strategy:** Detection Strategy for Resource Hijacking: SMS Pumping via SaaS Application Logs  

---

### T1496.004 — Cloud Service Hijacking
<a id="t1496004"></a>

sub-technique of [T1496](/techniques/impact.md#t1496) · **Tactics:** Impact · **Platforms:** SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1496/004)  

Adversaries may leverage compromised software-as-a-service (SaaS) applications to complete resource-intensive tasks, which may impact hosted service availability. For example, adversaries may leverage email and messaging services, such as AWS Simple Email Service (SES), AWS Simple Notification Service (SNS), SendGrid, and Twilio, in order to send large quantities of spam / [Phishing](https://attack.mitre.org/techniques/T1566) emails and SMS messages. Alternatively, they may engage in LLMJacking by leveraging reverse proxies to hijack the power of cloud-hosted AI models. In some cases, adversaries may leverage services that the victim is already using. In others, particularly when the service is part of a larger cloud platform, they may first enable the service. Leveraging SaaS applications may cause the victim to incur significant financial costs, use up service quotas, and otherwise impact availability.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Cloud Service Hijacking via SaaS Abuse  

---

### T1498 — Network Denial of Service
<a id="t1498"></a>

**Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS, Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1498)  

Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion. A Network DoS will occur when the bandwidth capacity of the network connection to a system is exhausted due to the volume of malicious traffic directed at the resource or the network connections and network devices the resource relies on. For example, an adversary may send 10Gbps of traffic to a server that is hosted by a network with a 1Gbps connection to the internet. This traffic can be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS). To perform Network DoS attacks several aspects apply to multiple methods, including IP address spoofing, and botnets. Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices. For DoS attacks targeting the hosting system directly, see [Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499).

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`  
**ATT&CK detection strategy:** Behavioral Detection of T1498 – Network Denial of Service Across Platforms  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  
**Implemented by 2 software:** [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S1107 NKAbuse](https://attack.mitre.org/software/S1107)  

---

### T1498.001 — Direct Network Flood
<a id="t1498001"></a>

sub-technique of [T1498](/techniques/impact.md#t1498) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1498/001)  

Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. [Direct Network Flood](https://attack.mitre.org/techniques/T1498/001)s are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well. Botnets are commonly used to conduct network flooding attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global Internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for distributed DoS (DDoS), so many systems are used to generate the flood that each one only needs to send out a small amount of traffic to produce enough volume to saturate the target network. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS flooding attacks, such as the 2012 series of incidents that targeted major US banks.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`  
**ATT&CK detection strategy:** Direct Network Flood Detection across IaaS, Linux, Windows, and macOS  

---

### T1498.002 — Reflection Amplification
<a id="t1498002"></a>

sub-technique of [T1498](/techniques/impact.md#t1498) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1498/002)  

Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address. This third-party server is commonly termed a reflector. An adversary accomplishes a reflection attack by sending packets to reflectors with the spoofed address of the victim. Similar to Direct Network Floods, more than one system may be used to conduct the attack, or a botnet may be used. Likewise, one or more reflectors may be used to focus traffic on the target. This Network DoS attack may also reduce the availability and functionality of the targeted system(s) and network. Reflection attacks often take advantage of protocols with larger responses than requests in order to amplify their traffic, commonly known as a Reflection Amplification attack. Adversaries may be able to generate an increase in volume of attack traffic that is several orders of magnitude greater than the requests sent to the amplifiers. The extent of this increase will depending upon many variables, such as the protocol in question, the technique used, and the amplifying servers that actually produce the amplification in attack volume. Two prominent protocols that have enabled Reflection Amplification Floods are DNS and NTP, though the use of several others in the wild have been documented. In particular, the memcache protocol showed itself to be a powerful protocol, with amplification sizes up to 51,200 times the requesting packet.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`  
**ATT&CK detection strategy:** Detection Strategy for Reflection Amplification DoS (T1498.002)  

---

### T1499 — Endpoint Denial of Service
<a id="t1499"></a>

**Tactics:** Impact · **Platforms:** Windows, Linux, macOS, Containers, IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499)  

Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition. Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes and to support other malicious activities, including distraction, hacktivism, and extortion. An Endpoint DoS denies the availability of a service without saturating the network used to provide access to the service. Adversaries can target various layers of the application stack that is hosted on the system used to provide the service. These layers include the Operating Systems (OS), server applications such as web servers, DNS servers, databases, and the (typically web-based) applications that sit on top of them. Attacking each layer requires different techniques that take advantage of bottlenecks that are unique to the respective components. A DoS attack may be generated by a single system or multiple systems spread across the internet, which is commonly referred to as a distributed DoS (DDoS). To perform DoS attacks against endpoint resources, several aspects apply to multiple methods, including IP address spoofing and botnets. Adversaries may use the original IP address of an attacking system, or spoof the source IP address to make the attack traffic more difficult to trace back to the attacking system or to enable reflection. This can increase the difficulty defenders have in defending against the attack by reducing or eliminating the effectiveness of filtering by the source address on network defense devices. Botnets are commonly used to conduct DDoS attacks against networks and services. Large botnets can generate a significant amount of traffic from systems spread across the global internet. Adversaries may have the resources to build out and control their own botnet infrastructure or may rent time on an existing botnet to conduct an attack. In some of the worst cases for DDoS, so many systems are used to generate requests that each one only needs to send out a small amount of traffic to produce enough volume to exhaust the target's resources. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes exceedingly difficult. Botnets have been used in some of the most high-profile DDoS attacks, such as the 2012 series of incidents that targeted major US banks. In cases where traffic manipulation is used, there may be points in the global network (such as high traffic gateway routers) where packets can be altered and cause legitimate clients to execute code that directs network packets toward a target in high volume. This type of capability was previously used for the purposes of web censorship where client HTTP traffic was modified to include a reference to JavaScript that generated the DDoS code to overwhelm target web servers. For attacks attempting to saturate the providing network, see [Network Denial of Service](https://attack.mitre.org/techniques/T1498).

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Endpoint Resource Saturation and Crash Pattern Detection Across Platforms  
**Used by 1 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034)  
**Implemented by 2 software:** [S0052 OnionDuke](https://attack.mitre.org/software/S0052), [S0412 ZxShell](https://attack.mitre.org/software/S0412)  

---

### T1499.001 — OS Exhaustion Flood
<a id="t1499001"></a>

sub-technique of [T1499](/techniques/impact.md#t1499) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499/001)  

Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity. These attacks do not need to exhaust the actual resources on a system; the attacks may simply exhaust the limits and available resources that an OS self-imposes. Different ways to achieve this exist, including TCP state-exhaustion attacks such as SYN floods and ACK floods. With SYN floods, excessive amounts of SYN packets are sent, but the 3-way TCP handshake is never completed. Because each OS has a maximum number of concurrent TCP connections that it will allow, this can quickly exhaust the ability of the system to receive new requests for TCP connections, thus preventing access to any TCP service provided by the server. ACK floods leverage the stateful nature of the TCP protocol. A flood of ACK packets are sent to the target. This forces the OS to search its state table for a related TCP connection that has already been established. Because the ACK packets are for connections that do not exist, the OS will have to search the entire state table to confirm that no match exists. When it is necessary to do this for a large flood of packets, the computational requirements can cause the server to become sluggish and/or unresponsive, due to the work it must do to eliminate the rogue ACK packets. This greatly reduces the resources available for providing the targeted service.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Endpoint DoS via OS Exhaustion Flood Detection Strategy  

---

### T1499.002 — Service Exhaustion Flood
<a id="t1499002"></a>

sub-technique of [T1499](/techniques/impact.md#t1499) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499/002)  

Adversaries may target the different network services provided by systems to conduct a denial of service (DoS). Adversaries often target the availability of DNS and web services, however others have been targeted as well. Web server software can be attacked through a variety of means, some of which apply generally while others are specific to the software being used to provide the service. One example of this type of attack is known as a simple HTTP flood, where an adversary sends a large number of HTTP requests to a web server to overwhelm it and/or an application that runs on top of it. This flood relies on raw volume to accomplish the objective, exhausting any of the various resources required by the victim software to provide the service. Another variation, known as a SSL renegotiation attack, takes advantage of a protocol feature in SSL/TLS. The SSL/TLS protocol suite includes mechanisms for the client and server to agree on an encryption algorithm to use for subsequent secure connections. If SSL renegotiation is enabled, a request can be made for renegotiation of the crypto algorithm. In a renegotiation attack, the adversary establishes a SSL/TLS connection and then proceeds to make a series of renegotiation requests. Because the cryptographic renegotiation has a meaningful cost in computation cycles, this can cause an impact to the availability of the service when done in volume.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Endpoint DoS via Service Exhaustion Flood  

---

### T1499.003 — Application Exhaustion Flood
<a id="t1499003"></a>

sub-technique of [T1499](/techniques/impact.md#t1499) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499/003)  

Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive. Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Application Exhaustion Flood Detection Across Platforms  

---

### T1499.004 — Application or System Exploitation
<a id="t1499004"></a>

sub-technique of [T1499](/techniques/impact.md#t1499) · **Tactics:** Impact · **Platforms:** Windows, IaaS, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1499/004)  

Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent denial of service (DoS) condition. Adversaries may exploit known or zero-day vulnerabilities to crash applications and/or systems, which may also lead to dependent applications and/or systems to be in a DoS condition. Crashed or restarted applications or systems may also have other effects such as [Data Destruction](https://attack.mitre.org/techniques/T1485), [Firmware Corruption](https://attack.mitre.org/techniques/T1495), [Service Stop](https://attack.mitre.org/techniques/T1489) etc. which may further cause a DoS condition and deny availability to critical information, applications and/or systems.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Endpoint DoS via Application or System Exploitation  
**Implemented by 1 software:** [S0604 Industroyer](https://attack.mitre.org/software/S0604)  

---

### T1529 — System Shutdown/Reboot
<a id="t1529"></a>

**Tactics:** Impact · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1529)  

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer or network device via [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) (e.g. <code>reload</code>). They may also include shutdown/reboot of a virtual machine via hypervisor / cloud consoles or command line tools. Shutting down or rebooting systems may disrupt access to computer resources for legitimate users while also impeding incident response/recovery. Adversaries may also use Windows API functions, such as `InitializeSystemShutdownExW` or `ExitWindowsEx`, to force a system to shut down or reboot. Alternatively, the `NtRaiseHardError`or `ZwRaiseHardError` Windows API functions with the `ResponseOption` parameter set to `OptionShutdownSystem` may deliver a “blue screen of death” (BSOD) to a system. In order to leverage these API functions, an adversary may need to acquire `SeShutdownPrivilege` (e.g., via [Access Token Manipulation](https://attack.mitre.org/techniques/T1134)). In some cases, the system may not be able to boot again. Adversaries may attempt to shutdown/reboot a system after impacting it in other ways, such as [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) or [Inhibit System Recovery](https://attack.mitre.org/techniques/T1490), to hasten the intended effects on system availability.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Multi-Platform Shutdown or Reboot Detection via Execution and Host Status Events  
**Used by 4 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 23 software:** [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0582 LookBack](https://attack.mitre.org/software/S0582), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1033 DCSrv](https://attack.mitre.org/software/S1033), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1125 AcidRain](https://attack.mitre.org/software/S1125), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1136 BFG Agonizer](https://attack.mitre.org/software/S1136), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1167 AcidPour](https://attack.mitre.org/software/S1167), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1531 — Account Access Removal
<a id="t1531"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Windows, SaaS, IaaS, Office Suite, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1531)  

Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials, revoked permissions for SaaS platforms such as Sharepoint) to remove access to accounts. Adversaries may also subsequently log off and/or perform a [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) to set malicious changes into place. In Windows, [Net](https://attack.mitre.org/software/S0039) utility, <code>Set-LocalUser</code> and <code>Set-ADAccountPassword</code> [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlets may be used by adversaries to modify user accounts. Accounts could also be disabled by Group Policy. In Linux, the <code>passwd</code> utility may be used to change passwords. On ESXi servers, accounts can be removed or modified via esxcli (`system account set`, `system account remove`). Adversaries who use ransomware or similar attacks may first perform this and other Impact behaviors, such as [Data Destruction](https://attack.mitre.org/techniques/T1485) and [Defacement](https://attack.mitre.org/techniques/T1491), in order to impede incident response/recovery before completing the [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) objective.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Account Access Removal via Multi-Platform Audit Correlation  
**Used by 2 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1024 Akira](https://attack.mitre.org/groups/G1024)  
**Implemented by 4 software:** [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134)  

---

### T1561 — Disk Wipe
<a id="t1561"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1561)  

Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted. To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disks may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002). On network devices, adversaries may wipe configuration files and other data from the device using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `erase`.

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Disk Wipe via Direct Disk Access and Destructive Commands  

---

### T1561.001 — Disk Content Wipe
<a id="t1561001"></a>

sub-technique of [T1561](/techniques/impact.md#t1561) · **Tactics:** Impact · **Platforms:** Linux, Network Devices, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1561/001)  

Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources. Adversaries may partially or completely overwrite the contents of a storage device rendering the data irrecoverable through the storage interface. Instead of wiping specific disk structures or files, adversaries with destructive intent may wipe arbitrary portions of disk content. To wipe disk content, adversaries may acquire direct access to the hard drive in order to overwrite arbitrarily sized portions of disk with random data. Adversaries have also been observed leveraging third-party drivers like [RawDisk](https://attack.mitre.org/software/S0364) to directly access disk content. This behavior is distinct from [Data Destruction](https://attack.mitre.org/techniques/T1485) because sections of the disk are erased instead of individual files. To maximize impact on the target organization in operations where network-wide availability interruption is the goal, malware used for wiping disk content may have worm-like features to propagate across a network by leveraging additional techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Disk Content Wipe via Direct Access and Overwrite  
**Used by 2 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047)  
**Implemented by 13 software:** [S0364 RawDisk](https://attack.mitre.org/software/S0364), [S0380 StoneDrill](https://attack.mitre.org/software/S0380), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1010 VPNFilter](https://attack.mitre.org/software/S1010), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1125 AcidRain](https://attack.mitre.org/software/S1125), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134), [S1167 AcidPour](https://attack.mitre.org/software/S1167), [S1205 cipher.exe](https://attack.mitre.org/software/S1205)  

---

### T1561.002 — Disk Structure Wipe
<a id="t1561002"></a>

sub-technique of [T1561](/techniques/impact.md#t1561) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1561/002)  

Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources. Adversaries may attempt to render the system unable to boot by overwriting critical data located in structures such as the master boot record (MBR) or partition table. The data contained in disk structures may include the initial executable code for loading an operating system or the location of the file system partitions on disk. If this information is not present, the computer will not be able to load an operating system during the boot process, leaving the computer unavailable. [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) may be performed in isolation, or along with [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) if all sectors of a disk are wiped. On a network devices, adversaries may reformat the file system using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `format`. To maximize impact on the target organization, malware designed for destroying disk structures may have worm-like features to propagate across a network by leveraging other techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002).

**ATT&CK mitigations (1):** [M1053 Data Backup](../ATTACK_MITIGATIONS_REFERENCE.md#m1053)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CM-2`, `CP-10`, `CP-2`, `CP-7`, `CP-9`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Disk Structure Wipe via Boot/Partition Overwrite  
**Used by 5 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  
**Implemented by 11 software:** [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0364 RawDisk](https://attack.mitre.org/software/S0364), [S0380 StoneDrill](https://attack.mitre.org/software/S0380), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0693 CaddyWiper](https://attack.mitre.org/software/S0693), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1136 BFG Agonizer](https://attack.mitre.org/software/S1136), [S1151 ZeroCleare](https://attack.mitre.org/software/S1151)  

---

### T1565 — Data Manipulation
<a id="t1565"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1565)  

Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making. The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

**ATT&CK mitigations (4):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (26):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `CP-10`, `CP-6`, `CP-7`, `CP-9`, `SC-28`, `SC-36`, `SC-4`, `SC-46`, `SC-7`, `SI-12`, `SI-16`, `SI-23`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Data Manipulation  
**Used by 1 threat groups:** [G1016 FIN13](https://attack.mitre.org/groups/G1016)  

---

### T1565.001 — Stored Data Manipulation
<a id="t1565001"></a>

sub-technique of [T1565](/techniques/impact.md#t1565) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1565/001)  

Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data. By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making. Stored data could include a variety of file formats, such as Office files, databases, stored emails, and custom file formats. The type of modification and the impact it will have depends on the type of data as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (23):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `CA-7`, `CM-2`, `CM-6`, `CM-8`, `CP-10`, `CP-6`, `CP-7`, `CP-9`, `SC-28`, `SC-36`, `SC-4`, `SC-7`, `SI-12`, `SI-16`, `SI-23`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Stored Data Manipulation across OS Platforms.  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  
**Implemented by 2 software:** [S0562 SUNSPOT](https://attack.mitre.org/software/S0562), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135)  

---

### T1565.002 — Transmitted Data Manipulation
<a id="t1565002"></a>

sub-technique of [T1565](/techniques/impact.md#t1565) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1565/002)  

Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data. By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making. Manipulation may be possible over a network connection or between system processes where there is an opportunity deploy a tool that will intercept and change information. The type of modification and the impact it will have depends on the target transmission mechanism as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

**ATT&CK mitigations (1):** [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (12):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `CM-2`, `CM-6`, `CM-8`, `SC-4`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy of Transmitted Data Manipulation  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  
**Implemented by 3 software:** [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0530 Melcoz](https://attack.mitre.org/software/S0530)  

---

### T1565.003 — Runtime Data Manipulation
<a id="t1565003"></a>

sub-technique of [T1565](/techniques/impact.md#t1565) · **Tactics:** Impact · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1565/003)  

Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data. By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making. Adversaries may alter application binaries used to display data in order to cause runtime manipulations. Adversaries may also conduct [Change Default File Association](https://attack.mitre.org/techniques/T1546/001) and [Masquerading](https://attack.mitre.org/techniques/T1036) to cause a similar effect. The type of modification and the impact it will have depends on the target application and process as well as the goals and objectives of the adversary. For complex systems, an adversary would likely need special expertise and possibly access to specialized software related to the system that would typically be gained through a prolonged information gathering campaign in order to have the desired impact.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030)  
**NIST 800-53 R5 controls (13):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `CP-9`, `SC-28`, `SC-4`, `SC-46`, `SC-7`, `SI-16`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Runtime Data Manipulation.  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  

---

### T1657 — Financial Theft
<a id="t1657"></a>

**Tactics:** Impact · **Platforms:** Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1657)  

Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims. Financial theft is the ultimate objective of several popular campaign types including extortion by ransomware, business email compromise (BEC) and fraud, "pig butchering," bank hacking, and exploiting cryptocurrency networks. Adversaries may [Compromise Accounts](https://attack.mitre.org/techniques/T1586) to conduct unauthorized transfers of funds. In the case of business email compromise or email fraud, an adversary may utilize [Impersonation](https://attack.mitre.org/techniques/T1684/001) of a trusted entity. Once the social engineering is successful, victims can be deceived into sending money to financial accounts controlled by an adversary. This creates the potential for multiple victims (i.e., compromised accounts as well as the ultimate monetary loss) in incidents involving financial theft. Extortion by ransomware may occur, for example, when an adversary demands payment from a victim after [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) and [Exfiltration](https://attack.mitre.org/tactics/TA0010) of data, followed by threatening to leak sensitive data to the public unless payment is made to the adversary. Adversaries may use dedicated leak sites to distribute victim data. Due to the potentially immense business impact of financial theft, an adversary may abuse the possibility of financial theft and seeking monetary gain to divert attention from their true goals such as [Data Destruction](https://attack.mitre.org/techniques/T1485) and business disruption.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (2):** `AC-5`, `AC-6`  
**ATT&CK detection strategy:** Detection Strategy for Financial Theft  
**Used by 14 threat groups:** [G0083 SilverTerrier](https://attack.mitre.org/groups/G0083), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1026 Malteiro](https://attack.mitre.org/groups/G1026), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1049 AppleJeus](https://attack.mitre.org/groups/G1049), [G1050 Water Galura](https://attack.mitre.org/groups/G1050), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 5 software:** [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245), [S1246 BeaverTail](https://attack.mitre.org/software/S1246), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1667 — Email Bombing
<a id="t1667"></a>

**Tactics:** Impact · **Platforms:** Linux, Office Suite, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1667)  

Adversaries may flood targeted email addresses with an overwhelming volume of messages. This may bury legitimate emails in a flood of spam and disrupt business operations. An adversary may accomplish email bombing by leveraging an automated bot to register a targeted address for e-mail lists that do not validate new signups, such as online newsletters. The result can be a wave of thousands of e-mails that effectively overloads the victim’s inbox. By sending hundreds or thousands of e-mails in quick succession, adversaries may successfully divert attention away from and bury legitimate messages including security alerts, daily business processes like help desk tickets and client correspondence, or ongoing scams. This behavior can also be used as a tool of harassment. This behavior may be a precursor for [Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004). For example, an adversary may email bomb a target and then follow up with a phone call to fraudulently offer assistance. This social engineering may lead to the use of [Remote Access Software](https://attack.mitre.org/techniques/T1663) to steal credentials, deploy ransomware, conduct [Financial Theft](https://attack.mitre.org/techniques/T1657), or engage in other malicious activity.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Email Bombing  
**Used by 1 threat groups:** [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  

---
