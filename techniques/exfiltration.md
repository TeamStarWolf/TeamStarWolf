# Exfiltration — Technique Detail

> Full detail pages for the **19 ATT&CK techniques** whose primary tactic is [Exfiltration](https://attack.mitre.org/tactics/TA0010/) (ATT&CK Enterprise v19.2). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1011 — Exfiltration Over Other Network Medium
<a id="t1011"></a>

**Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1011)  

Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel. Adversaries may choose to do this if they have sufficient access or proximity, and the connection might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.

**ATT&CK mitigations (2):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (5):** `AC-18`, `CM-6`, `CM-7`, `SC-43`, `SI-4`  
**ATT&CK detection strategy:** Detection of Exfiltration Over Alternate Network Interfaces  

---

### T1011.001 — Exfiltration Over Bluetooth
<a id="t1011001"></a>

sub-technique of [T1011](/techniques/exfiltration.md#t1011) · **Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1011/001)  

Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel. Adversaries may choose to do this if they have sufficient access and proximity. Bluetooth connections might not be secured or defended as well as the primary Internet-connected channel because it is not routed through the same enterprise network.

**ATT&CK mitigations (2):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (8):** `AC-18`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Bluetooth-Based Data Exfiltration  
**Implemented by 1 software:** [S0143 Flame](https://attack.mitre.org/software/S0143)  

---

### T1020 — Automated Exfiltration
<a id="t1020"></a>

**Tactics:** Exfiltration · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1020)  

Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection. When automated exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Automated Exfiltration Detection Strategy  
**Used by 6 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 20 software:** [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0131 TINYTYPHON](https://attack.mitre.org/software/S0131), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0445 ShimRatReporter](https://attack.mitre.org/software/S0445), [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0538 Crutch](https://attack.mitre.org/software/S0538), [S0600 Doki](https://attack.mitre.org/software/S0600), [S0643 Peppy](https://attack.mitre.org/software/S0643), [S1017 OutSteel](https://attack.mitre.org/software/S1017), [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1166 Solar](https://attack.mitre.org/software/S1166), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1211 Hannotog](https://attack.mitre.org/software/S1211)  

---

### T1020.001 — Traffic Duplication
<a id="t1020001"></a>

sub-technique of [T1020](/techniques/exfiltration.md#t1020) · **Tactics:** Exfiltration · **Platforms:** Network Devices, IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1020/001)  

Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. Adversaries may abuse traffic mirroring to mirror or redirect network traffic through other infrastructure they control. Malicious modifications to network devices to enable traffic redirection may be possible through [ROMMONkit](https://attack.mitre.org/techniques/T1542/004) or [Patch System Image](https://attack.mitre.org/techniques/T1601/001). Many cloud-based environments also support traffic mirroring. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Adversaries may use traffic duplication in conjunction with [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Input Capture](https://attack.mitre.org/techniques/T1056), or [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) depending on the goals and objectives of the adversary.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-6`, `CA-3`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `SC-4`, `SC-7`, `SC-8`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Traffic Duplication via Mirroring in IaaS and Network Devices  

---

### T1029 — Scheduled Transfer
<a id="t1029"></a>

**Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1029)  

Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability. When scheduled exfiltration is used, other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041) or [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048).

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Scheduled Transfer and Recurrent Exfiltration Patterns  
**Used by 1 threat groups:** [G0126 Higaisa](https://attack.mitre.org/groups/G0126)  
**Implemented by 17 software:** [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0200 Dipsind](https://attack.mitre.org/software/S0200), [S0211 Linfo](https://attack.mitre.org/software/S0211), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0596 ShadowPad](https://attack.mitre.org/software/S0596), [S0667 Chrommme](https://attack.mitre.org/software/S0667), [S0668 TinyTurla](https://attack.mitre.org/software/S0668), [S0696 Flagpro](https://attack.mitre.org/software/S0696), [S1019 Shark](https://attack.mitre.org/software/S1019), [S1100 Ninja](https://attack.mitre.org/software/S1100)  

---

### T1030 — Data Transfer Size Limits
<a id="t1030"></a>

**Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1030)  

An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Data Transfer Size Limits and Chunked Exfiltration  
**Used by 5 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1040 Play](https://attack.mitre.org/groups/G1040)  
**Implemented by 14 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0150 POSHSPY](https://attack.mitre.org/software/S0150), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0487 Kessel](https://attack.mitre.org/software/S0487), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0644 ObliqueRAT](https://attack.mitre.org/software/S0644), [S0699 Mythic](https://attack.mitre.org/software/S0699), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1040 Rclone](https://attack.mitre.org/software/S1040), [S1141 LunarWeb](https://attack.mitre.org/software/S1141), [S1200 StealBit](https://attack.mitre.org/software/S1200)  

---

### T1041 — Exfiltration Over C2 Channel
<a id="t1041"></a>

**Tactics:** Exfiltration · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1041)  

Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (18):** `AC-16`, `AC-2`, `AC-20`, `AC-23`, `AC-3`, `AC-4`, `AC-6`, `CA-3`, `CA-7`, `SA-8`, `SA-9`, `SC-13`, `SC-28`, `SC-31`, `SC-7`, `SI-3`, `SI-4`, `SR-4`  
**ATT&CK detection strategy:** Detection Strategy for Exfiltration Over C2 Channel  
**Used by 25 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0142 Confucius](https://attack.mitre.org/groups/G0142), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 156 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0077 CallMe](https://attack.mitre.org/software/S0077), [S0078 Psylo](https://attack.mitre.org/software/S0078), [S0079 MobileOrder](https://attack.mitre.org/software/S0079), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0086 ZLib](https://attack.mitre.org/software/S0086), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0238 Proxysvc](https://attack.mitre.org/software/S0238), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0340 Octopus](https://attack.mitre.org/software/S0340), [S0351 Cannon](https://attack.mitre.org/software/S0351), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0375 Remexi](https://attack.mitre.org/software/S0375), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0391 HAWKBALL](https://attack.mitre.org/software/S0391), [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0431 HotCroissant](https://attack.mitre.org/software/S0431), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0441 PowerShower](https://attack.mitre.org/software/S0441), [S0445 ShimRatReporter](https://attack.mitre.org/software/S0445), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0448 Rising Sun](https://attack.mitre.org/software/S0448), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0459 MechaFlounder](https://attack.mitre.org/software/S0459), [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0477 Goopy](https://attack.mitre.org/software/S0477), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0487 Kessel](https://attack.mitre.org/software/S0487), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0493 GoldenSpy](https://attack.mitre.org/software/S0493), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0502 Drovorub](https://attack.mitre.org/software/S0502), [S0520 BLINDINGCAN](https://attack.mitre.org/software/S0520), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0533 SLOTHFULMEDIA](https://attack.mitre.org/software/S0533), [S0538 Crutch](https://attack.mitre.org/software/S0538), [S0543 Spark](https://attack.mitre.org/software/S0543), [S0568 EVILNUM](https://attack.mitre.org/software/S0568), [S0572 Caterpillar WebShell](https://attack.mitre.org/software/S0572), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0588 GoldMax](https://attack.mitre.org/software/S0588), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0600 Doki](https://attack.mitre.org/software/S0600), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0610 SideTwist](https://attack.mitre.org/software/S0610), [S0615 SombRAT](https://attack.mitre.org/software/S0615), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0632 GrimAgent](https://attack.mitre.org/software/S0632), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0651 BoxCaon](https://attack.mitre.org/software/S0651), [S0652 MarkiRAT](https://attack.mitre.org/software/S0652), [S0657 BLUELIGHT](https://attack.mitre.org/software/S0657), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S0667 Chrommme](https://attack.mitre.org/software/S0667), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0671 Tomiris](https://attack.mitre.org/software/S0671), [S0674 CharmPower](https://attack.mitre.org/software/S0674), [S0678 Torisma](https://attack.mitre.org/software/S0678), [S0680 LitePower](https://attack.mitre.org/software/S0680), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0696 Flagpro](https://attack.mitre.org/software/S0696), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1017 OutSteel](https://attack.mitre.org/software/S1017), [S1019 Shark](https://attack.mitre.org/software/S1019), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1021 DnsSystem](https://attack.mitre.org/software/S1021), [S1022 IceApple](https://attack.mitre.org/software/S1022), [S1024 CreepySnail](https://attack.mitre.org/software/S1024), [S1025 Amadey](https://attack.mitre.org/software/S1025), [S1026 Mongall](https://attack.mitre.org/software/S1026), [S1029 AuTo Stealer](https://attack.mitre.org/software/S1029), [S1030 Squirrelwaffle](https://attack.mitre.org/software/S1030), [S1031 PingPull](https://attack.mitre.org/software/S1031), [S1034 StrifeWater](https://attack.mitre.org/software/S1034), [S1037 STARWHALE](https://attack.mitre.org/software/S1037), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1042 SUGARDUMP](https://attack.mitre.org/software/S1042), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1050 PcShare](https://attack.mitre.org/software/S1050), [S1059 metaMain](https://attack.mitre.org/software/S1059), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1064 SVCReady](https://attack.mitre.org/software/S1064), [S1065 Woody RAT](https://attack.mitre.org/software/S1065), [S1075 KOPILUWAK](https://attack.mitre.org/software/S1075), [S1078 RotaJakiro](https://attack.mitre.org/software/S1078), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1089 SharpDisco](https://attack.mitre.org/software/S1089), [S1090 NightClub](https://attack.mitre.org/software/S1090), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1132 IPsec Helper](https://attack.mitre.org/software/S1132), [S1142 LunarMail](https://attack.mitre.org/software/S1142), [S1145 Pikabot](https://attack.mitre.org/software/S1145), [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153), [S1156 Manjusaka](https://attack.mitre.org/software/S1156), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1166 Solar](https://attack.mitre.org/software/S1166), [S1169 Mango](https://attack.mitre.org/software/S1169), [S1170 ODAgent](https://attack.mitre.org/software/S1170), [S1172 OilBooster](https://attack.mitre.org/software/S1172), [S1173 PowerExchange](https://attack.mitre.org/software/S1173), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1182 MagicRAT](https://attack.mitre.org/software/S1182), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1185 LightSpy](https://attack.mitre.org/software/S1185), [S1186 Line Dancer](https://attack.mitre.org/software/S1186), [S1188 Line Runner](https://attack.mitre.org/software/S1188), [S1196 Troll Stealer](https://attack.mitre.org/software/S1196), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1210 Sagerunex](https://attack.mitre.org/software/S1210), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245), [S1246 BeaverTail](https://attack.mitre.org/software/S1246), [S1248 XORIndex Loader](https://attack.mitre.org/software/S1248), [S1249 HexEval Loader](https://attack.mitre.org/software/S1249)  

---

### T1048 — Exfiltration Over Alternative Protocol
<a id="t1048"></a>

**Tactics:** Exfiltration · **Platforms:** ESXi, IaaS, Linux, macOS, Network Devices, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1048)  

Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) can be done using various common operating system utilities such as [Net](https://attack.mitre.org/software/S0039)/SMB or FTP. On macOS and Linux <code>curl</code> may be used to invoke protocols such as HTTP/S or FTP/S to exfiltrate data from a system. Many IaaS and SaaS platforms (such as Microsoft Exchange, Microsoft SharePoint, GitHub, and AWS S3) support the direct download of files, emails, source code, and other sensitive information via the web console or [Cloud API](https://attack.mitre.org/techniques/T1059/009).

**ATT&CK mitigations (6):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (23):** `AC-16`, `AC-2`, `AC-20`, `AC-23`, `AC-3`, `AC-4`, `AC-6`, `CA-3`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SA-8`, `SA-9`, `SC-28`, `SC-31`, `SC-46`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`, `SR-4`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for Exfiltration Over Alternative Protocol  
**Used by 2 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1040 Play](https://attack.mitre.org/groups/G1040)  
**Implemented by 7 software:** [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0503 FrameworkPOS](https://attack.mitre.org/software/S0503), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0641 Kobalos](https://attack.mitre.org/software/S0641), [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1048.001 — Exfiltration Over Symmetric Encrypted Non-C2 Protocol
<a id="t1048001"></a>

sub-technique of [T1048](/techniques/exfiltration.md#t1048) · **Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1048/001)  

Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Symmetric encryption algorithms are those that use shared or the same keys/secrets on each end of the channel. This requires an exchange or pre-arranged agreement/possession of the value used to encrypt and decrypt data. Network protocols that use asymmetric encryption often utilize symmetric encryption once keys are exchanged, but adversaries may opt to manually share keys and implement symmetric cryptographic algorithms (ex: RC4, AES) vice using mechanisms that are baked into a protocol. This may result in multiple layers of encryption (in protocols that are natively encrypted such as HTTPS) or encryption in protocols that not typically encrypted (such as HTTP or FTP).

**ATT&CK mitigations (3):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (12):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-46`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for Exfiltration Over Symmetric Encrypted Non-C2 Protocol  

---

### T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
<a id="t1048002"></a>

sub-technique of [T1048](/techniques/exfiltration.md#t1048) · **Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1048/002)  

Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Asymmetric encryption algorithms are those that use different keys on each end of the channel. Also known as public-key cryptography, this requires pairs of cryptographic keys that can encrypt/decrypt data from the corresponding key. Each end of the communication channels requires a private key (only in the procession of that entity) and the public key of the other entity. The public keys of each entity are exchanged before encrypted communications begin. Network protocols that use asymmetric encryption (such as HTTPS/TLS/SSL) often utilize symmetric encryption once keys are exchanged. Adversaries may opt to use these encrypted mechanisms that are baked into a protocol.

**ATT&CK mitigations (4):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (23):** `AC-16`, `AC-2`, `AC-20`, `AC-23`, `AC-3`, `AC-4`, `AC-6`, `CA-3`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SA-8`, `SA-9`, `SC-28`, `SC-31`, `SC-46`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`, `SR-4`  
**ATT&CK detection strategy:** Detection of Exfiltration Over Asymmetric Encrypted Non-C2 Protocol  
**Used by 3 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  
**Implemented by 2 software:** [S0483 IcedID](https://attack.mitre.org/software/S0483), [S1040 Rclone](https://attack.mitre.org/software/S1040)  

---

### T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol
<a id="t1048003"></a>

sub-technique of [T1048](/techniques/exfiltration.md#t1048) · **Tactics:** Exfiltration · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1048/003)  

Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server. Adversaries may opt to obfuscate this data, without the use of encryption, within network protocols that are natively unencrypted (such as HTTP, FTP, or DNS). This may include custom or publicly available encoding/compression algorithms (such as base64) as well as embedding data within protocol headers and fields.

**ATT&CK mitigations (4):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (23):** `AC-16`, `AC-2`, `AC-20`, `AC-23`, `AC-3`, `AC-4`, `AC-6`, `CA-3`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SA-8`, `SA-9`, `SC-13`, `SC-28`, `SC-31`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`, `SR-4`  
**ATT&CK detection strategy:** Detection of Exfiltration Over Unencrypted Non-C2 Protocol  
**Used by 11 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0076 Thrip](https://attack.mitre.org/groups/G0076), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 22 software:** [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0095 ftp](https://attack.mitre.org/software/S0095), [S0107 Cherry Picker](https://attack.mitre.org/software/S0107), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0190 BITSAdmin](https://attack.mitre.org/software/S0190), [S0212 CORALDECK](https://attack.mitre.org/software/S0212), [S0252 Brave Prince](https://attack.mitre.org/software/S0252), [S0281 Dok](https://attack.mitre.org/software/S0281), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0335 Carbon](https://attack.mitre.org/software/S0335), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0466 WindTail](https://attack.mitre.org/software/S0466), [S0487 Kessel](https://attack.mitre.org/software/S0487), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0674 CharmPower](https://attack.mitre.org/software/S0674), [S1040 Rclone](https://attack.mitre.org/software/S1040), [S1043 ccf32](https://attack.mitre.org/software/S1043), [S1116 WARPWIRE](https://attack.mitre.org/software/S1116), [S1124 SocGholish](https://attack.mitre.org/software/S1124), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1052 — Exfiltration Over Physical Medium
<a id="t1052"></a>

**Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1052)  

Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

**ATT&CK mitigations (3):** [M1034 Limit Hardware Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1034), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-2`, `AC-20`, `AC-23`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `MP-7`, `RA-5`, `SA-8`, `SC-28`, `SC-41`, `SI-3`, `SI-4`, `SR-4`  
**ATT&CK detection strategy:** Detection of Data Exfiltration via Removable Media  

---

### T1052.001 — Exfiltration over USB
<a id="t1052001"></a>

sub-technique of [T1052](/techniques/exfiltration.md#t1052) · **Tactics:** Exfiltration · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1052/001)  

Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.

**ATT&CK mitigations (3):** [M1034 Limit Hardware Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1034), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-2`, `AC-20`, `AC-23`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `MP-7`, `RA-5`, `SA-8`, `SC-28`, `SC-41`, `SI-3`, `SI-4`, `SR-4`  
**ATT&CK detection strategy:** Detection of USB-Based Data Exfiltration  
**Used by 2 threat groups:** [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 5 software:** [S0035 SPACESHIP](https://attack.mitre.org/software/S0035), [S0092 Agent.btz](https://attack.mitre.org/software/S0092), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0409 Machete](https://attack.mitre.org/software/S0409)  

---

### T1537 — Transfer Data to Cloud Account
<a id="t1537"></a>

**Tactics:** Exfiltration · **Platforms:** IaaS, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1537)  

Adversaries may exfiltrate data by transferring the data, including through sharing/syncing and creating backups of cloud environments, to another cloud account they control on the same service. A defender who is monitoring for large transfers to outside the cloud environment through normal file transfers or over command and control channels may not be watching for data transfers to another account within the same cloud provider. Such transfers may utilize existing cloud provider APIs and the internal address space of the cloud provider to blend into normal traffic or avoid data transfers over external network interfaces. Adversaries may also use cloud-native mechanisms to share victim data with adversary-controlled cloud accounts, such as creating anonymous file sharing links or, in Azure, a shared access signature (SAS) URI. Incidents have been observed where adversaries have created backups of cloud instances and transferred them to separate accounts.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (20):** `AC-16`, `AC-17`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-3`, `IA-4`, `IA-8`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Cross-Platform Detection of Data Transfer to Cloud Account  
**Used by 3 threat groups:** [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1567 — Exfiltration Over Web Service
<a id="t1567"></a>

**Tactics:** Exfiltration · **Platforms:** ESXi, Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1567)  

Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services. Web service providers also commonly use SSL/TLS encryption, giving adversaries an added level of protection.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (17):** `AC-16`, `AC-2`, `AC-20`, `AC-23`, `AC-3`, `AC-4`, `AC-6`, `CA-3`, `CA-7`, `SA-8`, `SA-9`, `SC-28`, `SC-31`, `SC-7`, `SI-3`, `SI-4`, `SR-4`  
**ATT&CK detection strategy:** Detection Strategy for Exfiltration Over Web Service  
**Used by 4 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 7 software:** [S0508 ngrok](https://attack.mitre.org/software/S0508), [S0547 DropBook](https://attack.mitre.org/software/S0547), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S1168 SampleCheck5000](https://attack.mitre.org/software/S1168), [S1171 OilCheck](https://attack.mitre.org/software/S1171), [S1179 Exbyte](https://attack.mitre.org/software/S1179), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1567.001 — Exfiltration to Code Repository
<a id="t1567001"></a>

sub-technique of [T1567](/techniques/exfiltration.md#t1567) · **Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1567/001)  

Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection. Exfiltration to a code repository can also provide a significant amount of cover to the adversary if it is a popular service already used by hosts within the network.

**ATT&CK mitigations (1):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021)  
**NIST 800-53 R5 controls (3):** `AC-20`, `AC-4`, `SC-7`  
**ATT&CK detection strategy:** Detection Strategy for Exfiltration to Code Repository  
**Implemented by 1 software:** [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1567.002 — Exfiltration to Cloud Storage
<a id="t1567002"></a>

sub-technique of [T1567](/techniques/exfiltration.md#t1567) · **Tactics:** Exfiltration · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1567/002)  

Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet. Examples of cloud storage services include Dropbox and Google Docs. Exfiltration to these cloud storage services can provide a significant amount of cover to the adversary if hosts within the network are already communicating with the service.

**ATT&CK mitigations (1):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021)  
**NIST 800-53 R5 controls (3):** `AC-20`, `AC-4`, `SC-7`  
**ATT&CK detection strategy:** Detection Strategy for Exfiltration to Cloud Storage  
**Used by 24 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0142 Confucius](https://attack.mitre.org/groups/G0142), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1005 POLONIUM](https://attack.mitre.org/groups/G1005), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 15 software:** [S0037 HAMMERTOSS](https://attack.mitre.org/software/S0037), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0340 Octopus](https://attack.mitre.org/software/S0340), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0538 Crutch](https://attack.mitre.org/software/S0538), [S0629 RainyDay](https://attack.mitre.org/software/S0629), [S0635 BoomBox](https://attack.mitre.org/software/S0635), [S0651 BoxCaon](https://attack.mitre.org/software/S0651), [S0660 Clambling](https://attack.mitre.org/software/S0660), [S1023 CreepyDrive](https://attack.mitre.org/software/S1023), [S1040 Rclone](https://attack.mitre.org/software/S1040), [S1102 Pcexter](https://attack.mitre.org/software/S1102), [S1170 ODAgent](https://attack.mitre.org/software/S1170), [S1172 OilBooster](https://attack.mitre.org/software/S1172), [S1222 RIFLESPINE](https://attack.mitre.org/software/S1222)  

---

### T1567.003 — Exfiltration to Text Storage Sites
<a id="t1567003"></a>

sub-technique of [T1567](/techniques/exfiltration.md#t1567) · **Tactics:** Exfiltration · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1567/003)  

Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as <code>pastebin[.]com</code>, are commonly used by developers to share code and other information. Text storage sites are often used to host malicious code for C2 communication (e.g., [Stage Capabilities](https://attack.mitre.org/techniques/T1608)), but adversaries may also use these sites to exfiltrate collected data. Furthermore, paid features and encryption options may allow adversaries to conceal and store data more securely. **Note:** This is distinct from [Exfiltration to Code Repository](https://attack.mitre.org/techniques/T1567/001), which highlight access to code repositories via APIs.

**ATT&CK mitigations (1):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021)  
**NIST 800-53 R5 controls (3):** `AC-17`, `AC-4`, `SC-7`  
**ATT&CK detection strategy:** Detection Strategy for Exfiltration to Text Storage Sites  

---

### T1567.004 — Exfiltration Over Webhook
<a id="t1567004"></a>

sub-technique of [T1567](/techniques/exfiltration.md#t1567) · **Tactics:** Exfiltration · **Platforms:** Windows, macOS, Linux, SaaS, Office Suite, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1567/004)  

Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server. Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello. When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application. Adversaries may link an adversary-owned environment to a victim-owned SaaS service to achieve repeated [Automated Exfiltration](https://attack.mitre.org/techniques/T1020) of emails, chat messages, and other data. Alternatively, instead of linking the webhook endpoint to a service, an adversary can manually post staged data directly to the URL in order to exfiltrate it. Access to webhook endpoints is often over HTTPS, which gives the adversary an additional level of protection. Exfiltration leveraging webhooks can also blend in with normal network traffic if the webhook endpoint points to a commonly used SaaS application or collaboration service.

**ATT&CK mitigations (1):** [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (3):** `AC-17`, `AC-4`, `SC-7`  
**ATT&CK detection strategy:** Detection Strategy for Exfiltration Over Webhook  

---
