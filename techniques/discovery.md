# Discovery — Technique Detail

> Full detail pages for the **43 ATT&CK techniques** whose primary tactic is [Discovery](https://attack.mitre.org/tactics/TA0007/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1007 — System Service Discovery
<a id="t1007"></a>

**Tactics:** Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1007)  

Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as <code>sc query</code>, <code>tasklist /svc</code>, <code>systemctl --type=service</code>, and <code>net start</code>.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of System Service Discovery Commands Across OS Platforms  
**Used by 14 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 51 software:** [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0039 Net](https://attack.mitre.org/software/S0039), [S0049 GeminiDuke](https://attack.mitre.org/software/S0049), [S0057 Tasklist](https://attack.mitre.org/software/S0057), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0086 ZLib](https://attack.mitre.org/software/S0086), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0219 WINERACK](https://attack.mitre.org/software/S0219), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0241 RATANKBA](https://attack.mitre.org/software/S0241), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0266 TrickBot](https://attack.mitre.org/software/S0266) _(+27 more)_  

---

### T1010 — Application Window Discovery
<a id="t1010"></a>

**Tactics:** Discovery · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1010)  

Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Application Window Enumeration via API or Scripting  
**Used by 3 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 32 software:** [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0033 NetTraveler](https://attack.mitre.org/software/S0033), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0157 SOUNDBITE](https://attack.mitre.org/software/S0157), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0219 WINERACK](https://attack.mitre.org/software/S0219), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0261 Catchamas](https://attack.mitre.org/software/S0261), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0375 Remexi](https://attack.mitre.org/software/S0375), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0431 HotCroissant](https://attack.mitre.org/software/S0431), [S0435 PLEAD](https://attack.mitre.org/software/S0435), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0454 Cadelspy](https://attack.mitre.org/software/S0454), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0456 Aria-body](https://attack.mitre.org/software/S0456), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673) _(+8 more)_  

---

### T1012 — Query Registry
<a id="t1012"></a>

**Tactics:** Discovery · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1012)  

Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. The Registry contains a significant amount of information about the operating system, configuration, software, and security.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Registry Query for Environmental Discovery  
**Used by 19 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 98 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0075 Reg](https://attack.mitre.org/software/S0075), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0145 POWERSOURCE](https://attack.mitre.org/software/S0145), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0155 WINDSHIELD](https://attack.mitre.org/software/S0155), [S0165 OSInfo](https://attack.mitre.org/software/S0165), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0186 DownPaper](https://attack.mitre.org/software/S0186), [S0194 PowerSploit](https://attack.mitre.org/software/S0194) _(+74 more)_  

---

### T1016 — System Network Configuration Discovery
<a id="t1016"></a>

**Tactics:** Discovery · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1016)  

Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of System Network Configuration Discovery  
**Used by 42 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114) _(+18 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 225 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0049 GeminiDuke](https://attack.mitre.org/software/S0049), [S0060 Sys10](https://attack.mitre.org/software/S0060), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0092 Agent.btz](https://attack.mitre.org/software/S0092), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0099 Arp](https://attack.mitre.org/software/S0099), [S0100 ipconfig](https://attack.mitre.org/software/S0100), [S0101 ifconfig](https://attack.mitre.org/software/S0101), [S0102 nbtstat](https://attack.mitre.org/software/S0102), [S0103 route](https://attack.mitre.org/software/S0103) _(+201 more)_  

---

### T1016.001 — Internet Connection Discovery
<a id="t1016001"></a>

sub-technique of [T1016](/techniques/discovery.md#t1016) · **Tactics:** Discovery · **Platforms:** Windows, Linux, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1016/001)  

Adversaries may check for Internet connectivity on compromised systems. This may be performed during automated discovery and can be accomplished in numerous ways such as using Ping, <code>tracert</code>, and GET requests to websites, or performing initial speed testing to confirm bandwidth.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Internet Connection Discovery  
**Used by 11 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1018 TA2541](https://attack.mitre.org/groups/G1018)  
**Implemented by 13 software:** [S0284 More_eggs](https://attack.mitre.org/software/S0284), [S0448 Rising Sun](https://attack.mitre.org/software/S0448), [S0597 GoldFinder](https://attack.mitre.org/software/S0597), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S0686 QuietSieve](https://attack.mitre.org/software/S0686), [S0691 Neoichor](https://attack.mitre.org/software/S0691), [S1049 SUGARUSH](https://attack.mitre.org/software/S1049), [S1065 Woody RAT](https://attack.mitre.org/software/S1065), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066), [S1107 NKAbuse](https://attack.mitre.org/software/S1107), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1229 Havoc](https://attack.mitre.org/software/S1229)  

---

### T1016.002 — Wi-Fi Discovery
<a id="t1016002"></a>

sub-technique of [T1016](/techniques/discovery.md#t1016) · **Tactics:** Discovery · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1016/002)  

Adversaries may search for information about Wi-Fi networks, such as network names and passwords, on compromised systems. Adversaries may use Wi-Fi information as part of Account Discovery, Remote System Discovery, and other discovery or Credential Access activity to support both ongoing and future campaigns.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Wi-Fi Discovery Activity  
**Used by 1 threat groups:** [G0059 Magic Hound](https://attack.mitre.org/groups/G0059)  
**Implemented by 5 software:** [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0674 CharmPower](https://attack.mitre.org/software/S0674), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228)  

---

### T1018 — Remote System Discovery
<a id="t1018"></a>

**Tactics:** Discovery · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1018)  

Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1018) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 39 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0114 Chimera](https://attack.mitre.org/groups/G0114) _(+15 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 52 software:** [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0039 Net](https://attack.mitre.org/software/S0039), [S0063 SHOTPUT](https://attack.mitre.org/software/S0063), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0097 Ping](https://attack.mitre.org/software/S0097), [S0099 Arp](https://attack.mitre.org/software/S0099), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0165 OSInfo](https://attack.mitre.org/software/S0165), [S0233 MURKYTOP](https://attack.mitre.org/software/S0233), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0241 RATANKBA](https://attack.mitre.org/software/S0241), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0248 yty](https://attack.mitre.org/software/S0248), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0335 Carbon](https://attack.mitre.org/software/S0335), [S0359 Nltest](https://attack.mitre.org/software/S0359), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0452 USBferry](https://attack.mitre.org/software/S0452) _(+28 more)_  

---

### T1033 — System Owner/User Discovery
<a id="t1033"></a>

**Tactics:** Discovery · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1033)  

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of User Discovery via Local and Remote Enumeration  
**Used by 38 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102) _(+14 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 186 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0059 WinMM](https://attack.mitre.org/software/S0059), [S0060 Sys10](https://attack.mitre.org/software/S0060), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0092 Agent.btz](https://attack.mitre.org/software/S0092), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0130 Unknown Logger](https://attack.mitre.org/software/S0130), [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0149 MoonWind](https://attack.mitre.org/software/S0149), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0155 WINDSHIELD](https://attack.mitre.org/software/S0155) _(+162 more)_  

---

### T1046 — Network Service Discovery
<a id="t1046"></a>

**Tactics:** Discovery · **Platforms:** Containers, IaaS, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1046)  

Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.

**ATT&CK mitigations (3):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-46`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for Network Service Discovery Across Platforms  
**Used by 31 threat groups:** [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0039 Suckfly](https://attack.mitre.org/groups/G0039), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003) _(+7 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 35 software:** [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0061 HDoor](https://attack.mitre.org/software/S0061), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0117 XTunnel](https://attack.mitre.org/software/S0117), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0233 MURKYTOP](https://attack.mitre.org/software/S0233), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0374 SpeakUp](https://attack.mitre.org/software/S0374), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0572 Caterpillar WebShell](https://attack.mitre.org/software/S0572), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0590 NBTscan](https://attack.mitre.org/software/S0590), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0604 Industroyer](https://attack.mitre.org/software/S0604) _(+11 more)_  

---

### T1049 — System Network Connections Discovery
<a id="t1049"></a>

**Tactics:** Discovery · **Platforms:** Windows, IaaS, Linux, macOS, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1049)  

Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of System Network Connections Discovery Across Platforms  
**Used by 32 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0138 Andariel](https://attack.mitre.org/groups/G0138), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139) _(+8 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 60 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0039 Net](https://attack.mitre.org/software/S0039), [S0063 SHOTPUT](https://attack.mitre.org/software/S0063), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0102 nbtstat](https://attack.mitre.org/software/S0102), [S0104 netstat](https://attack.mitre.org/software/S0104), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0165 OSInfo](https://attack.mitre.org/software/S0165), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0241 RATANKBA](https://attack.mitre.org/software/S0241), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0283 jRAT](https://attack.mitre.org/software/S0283) _(+36 more)_  

---

### T1057 — Process Discovery
<a id="t1057"></a>

**Tactics:** Discovery · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1057)  

Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated access may provide better process details.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Adversarial Process Discovery Behavior  
**Used by 40 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0044 Winnti Group](https://attack.mitre.org/groups/G0044), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0112 Windshift](https://attack.mitre.org/groups/G0112) _(+16 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 255 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0049 GeminiDuke](https://attack.mitre.org/software/S0049), [S0057 Tasklist](https://attack.mitre.org/software/S0057), [S0059 WinMM](https://attack.mitre.org/software/S0059), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0063 SHOTPUT](https://attack.mitre.org/software/S0063), [S0064 ELMER](https://attack.mitre.org/software/S0064), [S0065 4H RAT](https://attack.mitre.org/software/S0065), [S0069 BLACKCOFFEE](https://attack.mitre.org/software/S0069), [S0079 MobileOrder](https://attack.mitre.org/software/S0079), [S0081 Elise](https://attack.mitre.org/software/S0081) _(+231 more)_  

---

### T1069 — Permission Groups Discovery
<a id="t1069"></a>

**Tactics:** Discovery · **Platforms:** Containers, IaaS, Identity Provider, Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1069)  

Adversaries may attempt to discover group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Permission Groups Discovery  
**Used by 6 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 6 software:** [S0233 MURKYTOP](https://attack.mitre.org/software/S0233), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0335 Carbon](https://attack.mitre.org/software/S0335), [S0445 ShimRatReporter](https://attack.mitre.org/software/S0445), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0623 Siloscape](https://attack.mitre.org/software/S0623)  

---

### T1069.001 — Local Groups
<a id="t1069001"></a>

sub-technique of [T1069](/techniques/discovery.md#t1069) · **Tactics:** Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1069/001)  

Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Local Group Enumeration Across OS Platforms  
**Used by 7 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 21 software:** [S0039 Net](https://attack.mitre.org/software/S0039), [S0060 Sys10](https://attack.mitre.org/software/S0060), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0165 OSInfo](https://attack.mitre.org/software/S0165), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381), [S0521 BloodHound](https://attack.mitre.org/software/S0521), [S0572 Caterpillar WebShell](https://attack.mitre.org/software/S0572), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0696 Flagpro](https://attack.mitre.org/software/S0696), [S1141 LunarWeb](https://attack.mitre.org/software/S1141), [S1179 Exbyte](https://attack.mitre.org/software/S1179), [S1198 Gomir](https://attack.mitre.org/software/S1198)  

---

### T1069.002 — Domain Groups
<a id="t1069002"></a>

sub-technique of [T1069](/techniques/discovery.md#t1069) · **Tactics:** Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1069/002)  

Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Domain Group Discovery  
**Used by 13 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 21 software:** [S0039 Net](https://attack.mitre.org/software/S0039), [S0105 dsquery](https://attack.mitre.org/software/S0105), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0165 OSInfo](https://attack.mitre.org/software/S0165), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0417 GRIFFON](https://attack.mitre.org/software/S0417), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0514 WellMess](https://attack.mitre.org/software/S0514), [S0516 SoreFang](https://attack.mitre.org/software/S0516), [S0521 BloodHound](https://attack.mitre.org/software/S0521), [S0552 AdFind](https://attack.mitre.org/software/S0552), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1138 Gootloader](https://attack.mitre.org/software/S1138), [S1160 Latrodectus](https://attack.mitre.org/software/S1160)  

---

### T1069.003 — Cloud Groups
<a id="t1069003"></a>

sub-technique of [T1069](/techniques/discovery.md#t1069) · **Tactics:** Discovery · **Platforms:** SaaS, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1069/003)  

Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Cloud Group Enumeration via API and CLI Access  
**Implemented by 3 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S0684 ROADTools](https://attack.mitre.org/software/S0684), [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1082 — System Information Discovery
<a id="t1082"></a>

**Tactics:** Discovery · **Platforms:** ESXi, IaaS, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1082)  

An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** System Discovery via Native and Remote Utilities  
**Used by 55 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096) _(+31 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 336 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0043 BUBBLEWRAP](https://attack.mitre.org/software/S0043), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0059 WinMM](https://attack.mitre.org/software/S0059), [S0060 Sys10](https://attack.mitre.org/software/S0060), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0065 4H RAT](https://attack.mitre.org/software/S0065), [S0079 MobileOrder](https://attack.mitre.org/software/S0079), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085) _(+312 more)_  

---

### T1083 — File and Directory Discovery
<a id="t1083"></a>

**Tactics:** Discovery · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1083)  

Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Recursive Enumeration of Files and Directories Across Privilege Contexts  
**Used by 50 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0044 Winnti Group](https://attack.mitre.org/groups/G0044), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082) _(+26 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 295 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0035 SPACESHIP](https://attack.mitre.org/software/S0035), [S0036 FLASHFLOOD](https://attack.mitre.org/software/S0036), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0049 GeminiDuke](https://attack.mitre.org/software/S0049), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0055 RARSTONE](https://attack.mitre.org/software/S0055), [S0059 WinMM](https://attack.mitre.org/software/S0059), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0063 SHOTPUT](https://attack.mitre.org/software/S0063), [S0064 ELMER](https://attack.mitre.org/software/S0064), [S0065 4H RAT](https://attack.mitre.org/software/S0065), [S0066 3PARA RAT](https://attack.mitre.org/software/S0066), [S0069 BLACKCOFFEE](https://attack.mitre.org/software/S0069) _(+271 more)_  

---

### T1087 — Account Discovery
<a id="t1087"></a>

**Tactics:** Discovery · **Platforms:** ESXi, IaaS, Identity Provider, Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1087)  

Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (4):** `AC-2`, `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Enumeration of User or Account Information Across Platforms  
**Used by 3 threat groups:** [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016)  
**Implemented by 5 software:** [S0445 ShimRatReporter](https://attack.mitre.org/software/S0445), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1065 Woody RAT](https://attack.mitre.org/software/S1065), [S1229 Havoc](https://attack.mitre.org/software/S1229), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1087.001 — Local Account
<a id="t1087001"></a>

sub-technique of [T1087](/techniques/discovery.md#t1087) · **Tactics:** Discovery · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1087/001)  

Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (3):** `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Local Account Enumeration Across Host Platforms  
**Used by 18 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 44 software:** [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0039 Net](https://attack.mitre.org/software/S0039), [S0049 GeminiDuke](https://attack.mitre.org/software/S0049), [S0063 SHOTPUT](https://attack.mitre.org/software/S0063), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0165 OSInfo](https://attack.mitre.org/software/S0165), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0233 MURKYTOP](https://attack.mitre.org/software/S0233), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0241 RATANKBA](https://attack.mitre.org/software/S0241), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0363 Empire](https://attack.mitre.org/software/S0363) _(+20 more)_  

---

### T1087.002 — Domain Account
<a id="t1087002"></a>

sub-technique of [T1087](/techniques/discovery.md#t1087) · **Tactics:** Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1087/002)  

Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (3):** `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Domain Account Enumeration Across Platforms  
**Used by 27 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1039 RedCurl](https://attack.mitre.org/groups/G1039) _(+3 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 25 software:** [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0039 Net](https://attack.mitre.org/software/S0039), [S0105 dsquery](https://attack.mitre.org/software/S0105), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0165 OSInfo](https://attack.mitre.org/software/S0165), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0516 SoreFang](https://attack.mitre.org/software/S0516), [S0521 BloodHound](https://attack.mitre.org/software/S0521), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0552 AdFind](https://attack.mitre.org/software/S0552), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0635 BoomBox](https://attack.mitre.org/software/S0635), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1022 IceApple](https://attack.mitre.org/software/S1022), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1146 MgBot](https://attack.mitre.org/software/S1146), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159) _(+1 more)_  

---

### T1087.003 — Email Account
<a id="t1087003"></a>

sub-technique of [T1087](/techniques/discovery.md#t1087) · **Tactics:** Discovery · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1087/003)  

Adversaries may attempt to get a listing of email addresses and accounts. Adversaries may try to dump Exchange address lists such as global address lists (GALs).

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Enumeration of Global Address Lists via Email Account Discovery  
**Used by 4 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 8 software:** [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0358 Ruler](https://attack.mitre.org/software/S0358), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0413 MailSniper](https://attack.mitre.org/software/S0413), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0635 BoomBox](https://attack.mitre.org/software/S0635), [S0681 Lizar](https://attack.mitre.org/software/S0681)  

---

### T1087.004 — Cloud Account
<a id="t1087004"></a>

sub-technique of [T1087](/techniques/discovery.md#t1087) · **Tactics:** Discovery · **Platforms:** IaaS, Identity Provider, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1087/004)  

Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (6):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `IA-2`, `IA-8`  
**ATT&CK detection strategy:** Cloud Account Enumeration via API, CLI, and Scripting Interfaces  
**Used by 2 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 3 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S0684 ROADTools](https://attack.mitre.org/software/S0684), [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1120 — Peripheral Device Discovery
<a id="t1120"></a>

**Tactics:** Discovery · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1120)  

Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Peripheral Device Enumeration via System Utilities and API Calls  
**Used by 9 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0020 Equation](https://attack.mitre.org/groups/G0020), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 46 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0149 MoonWind](https://attack.mitre.org/software/S0149), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0452 USBferry](https://attack.mitre.org/software/S0452), [S0454 Cadelspy](https://attack.mitre.org/software/S0454), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481) _(+22 more)_  

---

### T1124 — System Time Discovery
<a id="t1124"></a>

**Tactics:** Discovery · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1124)  

An adversary may gather the system time and/or time zone settings from a local or remote system. The system time is set and stored by services, such as the Windows Time Service on Windows or <code>systemsetup</code> on macOS.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavior-chain, platform-aware detection strategy for T1124 System Time Discovery  
**Used by 13 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0089 The White Company](https://attack.mitre.org/groups/G0089), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 77 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0039 Net](https://attack.mitre.org/software/S0039), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0149 MoonWind](https://attack.mitre.org/software/S0149), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0238 Proxysvc](https://attack.mitre.org/software/S0238), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0267 FELIXROOT](https://attack.mitre.org/software/S0267), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0275 UPPERCUT](https://attack.mitre.org/software/S0275), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0335 Carbon](https://attack.mitre.org/software/S0335), [S0344 Azorult](https://attack.mitre.org/software/S0344) _(+53 more)_  

---

### T1135 — Network Share Discovery
<a id="t1135"></a>

**Tactics:** Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1135)  

Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (3):** `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Behavior-chain detection for T1135 Network Share Discovery across Windows, Linux, and macOS  
**Used by 16 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 57 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0039 Net](https://attack.mitre.org/software/S0039), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0165 OSInfo](https://attack.mitre.org/software/S0165), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0233 MURKYTOP](https://attack.mitre.org/software/S0233), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0575 Conti](https://attack.mitre.org/software/S0575), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606), [S0611 Clop](https://attack.mitre.org/software/S0611) _(+33 more)_  

---

### T1201 — Password Policy Discovery
<a id="t1201"></a>

**Tactics:** Discovery · **Platforms:** Windows, Linux, macOS, IaaS, Network Devices, Identity Provider, SaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1201)  

Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through Brute Force.

**ATT&CK mitigations (1):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (5):** `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Password Policy Discovery – cross-platform behavior-chain analytics  
**Used by 3 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0114 Chimera](https://attack.mitre.org/groups/G0114)  
**Implemented by 4 software:** [S0039 Net](https://attack.mitre.org/software/S0039), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488)  

---

### T1217 — Browser Information Discovery
<a id="t1217"></a>

**Tactics:** Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1217)  

Adversaries may enumerate information about browsers to learn more about compromised environments.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Local Browser Artifact Access for Reconnaissance  
**Used by 6 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036)  
**Implemented by 17 software:** [S0079 MobileOrder](https://attack.mitre.org/software/S0079), [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S1012 PowerLess](https://attack.mitre.org/software/S1012), [S1042 SUGARDUMP](https://attack.mitre.org/software/S1042), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153), [S1185 LightSpy](https://attack.mitre.org/software/S1185), [S1196 Troll Stealer](https://attack.mitre.org/software/S1196), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1482 — Domain Trust Discovery
<a id="t1482"></a>

**Tactics:** Discovery · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1482)  

Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.

**ATT&CK mitigations (2):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (9):** `AC-4`, `CM-2`, `CM-6`, `CM-7`, `RA-5`, `SA-17`, `SA-8`, `SC-46`, `SC-7`  
**ATT&CK detection strategy:** Detection of Domain Trust Discovery via API, Script, and CLI Enumeration  
**Used by 9 threat groups:** [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 19 software:** [S0105 dsquery](https://attack.mitre.org/software/S0105), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0359 Nltest](https://attack.mitre.org/software/S0359), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0521 BloodHound](https://attack.mitre.org/software/S0521), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0552 AdFind](https://attack.mitre.org/software/S0552), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1071 Rubeus](https://attack.mitre.org/software/S1071), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1124 SocGholish](https://attack.mitre.org/software/S1124), [S1145 Pikabot](https://attack.mitre.org/software/S1145), [S1146 MgBot](https://attack.mitre.org/software/S1146), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159), [S1160 Latrodectus](https://attack.mitre.org/software/S1160)  

---

### T1518 — Software Discovery
<a id="t1518"></a>

**Tactics:** Discovery · **Platforms:** ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1518)  

Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Multi-Platform Software Discovery Behavior Chain  
**Used by 11 threat groups:** [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0112 Windshift](https://attack.mitre.org/groups/G0112), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0124 Windigo](https://attack.mitre.org/groups/G0124), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 36 software:** [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0229 Orz](https://attack.mitre.org/software/S0229), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0384 Dridex](https://attack.mitre.org/software/S0384), [S0431 HotCroissant](https://attack.mitre.org/software/S0431), [S0445 ShimRatReporter](https://attack.mitre.org/software/S0445), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0472 down_new](https://attack.mitre.org/software/S0472), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0646 SpicyOmelette](https://attack.mitre.org/software/S0646), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0652 MarkiRAT](https://attack.mitre.org/software/S0652), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0674 CharmPower](https://attack.mitre.org/software/S0674), [S1042 SUGARDUMP](https://attack.mitre.org/software/S1042) _(+12 more)_  

---

### T1518.001 — Security Software Discovery
<a id="t1518001"></a>

sub-technique of [T1518](/techniques/discovery.md#t1518) · **Tactics:** Discovery · **Platforms:** IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1518/001)  

Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as cloud monitoring agents and anti-virus.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Security Software Discovery Across Platforms  
**Used by 27 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0089 The White Company](https://attack.mitre.org/groups/G0089), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0112 Windshift](https://attack.mitre.org/groups/G0112), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1026 Malteiro](https://attack.mitre.org/groups/G1026), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1043 BlackByte](https://attack.mitre.org/groups/G1043) _(+3 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 105 software:** [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0057 Tasklist](https://attack.mitre.org/software/S0057), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0088 Kasidet](https://attack.mitre.org/software/S0088), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0108 netsh](https://attack.mitre.org/software/S0108), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0142 StreamEx](https://attack.mitre.org/software/S0142), [S0143 Flame](https://attack.mitre.org/software/S0143), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0171 Felismus](https://attack.mitre.org/software/S0171), [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0249 Gold Dragon](https://attack.mitre.org/software/S0249), [S0256 Mosquito](https://attack.mitre.org/software/S0256) _(+81 more)_  

---

### T1518.002 — Backup Software Discovery
<a id="t1518002"></a>

sub-technique of [T1518](/techniques/discovery.md#t1518) · **Tactics:** Discovery · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1518/002)  

Adversaries may attempt to get a listing of backup software or configurations that are installed on a system. Adversaries may use this information to shape follow-on behaviors, such as Data Destruction, Inhibit System Recovery, or Data Encrypted for Impact.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Backup Software Discovery via CLI, Registry, and Process Inspection (T1518.002)  
**Used by 1 threat groups:** [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  

---

### T1526 — Cloud Service Discovery
<a id="t1526"></a>

**Tactics:** Discovery · **Platforms:** IaaS, Identity Provider, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1526)  

An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS).

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Cloud Service Discovery  
**Used by 1 threat groups:** [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 3 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S0684 ROADTools](https://attack.mitre.org/software/S0684), [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1538 — Cloud Service Dashboard
<a id="t1538"></a>

**Tactics:** Discovery · **Platforms:** IaaS, SaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1538)  

An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (6):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `IA-2`, `IA-8`  
**ATT&CK detection strategy:** Detection of Cloud Service Dashboard Usage via GUI-Based Cloud Access  
**Used by 1 threat groups:** [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1580 — Cloud Infrastructure Discovery
<a id="t1580"></a>

**Tactics:** Discovery · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1580)  

An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (5):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `IA-2`  
**ATT&CK detection strategy:** Detection Strategy for Cloud Infrastructure Discovery  
**Used by 2 threat groups:** [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1613 — Container and Resource Discovery
<a id="t1613"></a>

**Tactics:** Discovery · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1613)  

Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035)  
**NIST 800-53 R5 controls (10):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CM-6`, `CM-7`, `IA-2`, `SC-43`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Container and Resource Discovery  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 2 software:** [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1614 — System Location Discovery
<a id="t1614"></a>

**Tactics:** Discovery · **Platforms:** IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1614)  

Adversaries may gather information in an attempt to calculate the geographical location of a victim host.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for System Location Discovery  
**Used by 2 threat groups:** [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 18 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0632 GrimAgent](https://attack.mitre.org/software/S0632), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1025 Amadey](https://attack.mitre.org/software/S1025), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1124 SocGholish](https://attack.mitre.org/software/S1124), [S1138 Gootloader](https://attack.mitre.org/software/S1138), [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245), [S1248 XORIndex Loader](https://attack.mitre.org/software/S1248), [S1249 HexEval Loader](https://attack.mitre.org/software/S1249)  

---

### T1614.001 — System Language Discovery
<a id="t1614001"></a>

sub-technique of [T1614](/techniques/discovery.md#t1614) · **Tactics:** Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1614/001)  

Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host. This information may be used to shape follow-on behaviors, including whether the adversary infects the target and/or attempts specific actions.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for System Language Discovery  
**Used by 4 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G1026 Malteiro](https://attack.mitre.org/groups/G1026), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 31 software:** [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0543 Spark](https://attack.mitre.org/software/S0543), [S0546 SharpStage](https://attack.mitre.org/software/S0546), [S0547 DropBook](https://attack.mitre.org/software/S0547), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0616 DEATHRANSOM](https://attack.mitre.org/software/S0616), [S0625 Cuba](https://attack.mitre.org/software/S0625), [S0632 GrimAgent](https://attack.mitre.org/software/S0632), [S0640 Avaddon](https://attack.mitre.org/software/S0640), [S0652 MarkiRAT](https://attack.mitre.org/software/S0652), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0691 Neoichor](https://attack.mitre.org/software/S0691), [S0696 Flagpro](https://attack.mitre.org/software/S0696), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1138 Gootloader](https://attack.mitre.org/software/S1138), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153) _(+7 more)_  

---

### T1615 — Group Policy Discovery
<a id="t1615"></a>

**Tactics:** Discovery · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1615)  

Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection strategy for Group Policy Discovery on Windows  
**Used by 1 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010)  
**Implemented by 5 software:** [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0521 BloodHound](https://attack.mitre.org/software/S0521), [S1141 LunarWeb](https://attack.mitre.org/software/S1141), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159)  

---

### T1619 — Cloud Storage Object Discovery
<a id="t1619"></a>

**Tactics:** Discovery · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1619)  

Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (7):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection Strategy for Cloud Storage Object Discovery  
**Implemented by 2 software:** [S0683 Peirates](https://attack.mitre.org/software/S0683), [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1652 — Device Driver Discovery
<a id="t1652"></a>

**Tactics:** Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1652)  

Adversaries may attempt to enumerate local device drivers on a victim host. Information about device drivers may highlight various insights that shape follow-on behaviors, such as the function/purpose of the host, present security tools (i.e.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Device Driver Discovery  
**Used by 1 threat groups:** [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 3 software:** [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S1139 INC Ransomware](https://attack.mitre.org/software/S1139)  

---

### T1654 — Log Enumeration
<a id="t1654"></a>

**Tactics:** Discovery · **Platforms:** ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1654)  

Adversaries may enumerate system and service logs to find useful data.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-4`, `AC-6`  
**ATT&CK detection strategy:** Detection Strategy for Log Enumeration  
**Used by 5 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1023 APT5](https://attack.mitre.org/groups/G1023)  
**Implemented by 5 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159), [S1191 Megazord](https://attack.mitre.org/software/S1191), [S1194 Akira _v2](https://attack.mitre.org/software/S1194), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1673 — Virtual Machine Discovery
<a id="t1673"></a>

**Tactics:** Discovery · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1673)  

An adversary may attempt to enumerate running virtual machines (VMs) after gaining access to a host or hypervisor. For example, adversaries may enumerate a list of VMs on an ESXi hypervisor using a Hypervisor CLI such as `esxcli` or `vim-cmd` (e.g. `esxcli vm process list or vim-cmd vmsvc/getallvms`).

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Virtual Machine Discovery  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 3 software:** [S1096 Cheerscrypt](https://attack.mitre.org/software/S1096), [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1680 — Local Storage Discovery
<a id="t1680"></a>

**Tactics:** Discovery · **Platforms:** ESXi, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1680)  

Adversaries may enumerate local drives, disks, and/or volumes and their attributes like total or free space and volume serial number. This can be done to prepare for ransomware-related encryption, to perform Lateral Movement, or as a precursor to Direct Volume Access.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Local Storage Discovery via Drive Enumeration and Filesystem Probing  
**Used by 10 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0142 Confucius](https://attack.mitre.org/groups/G0142), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022)  
**Implemented by 86 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0137 CORESHELL](https://attack.mitre.org/software/S0137), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0181 FALLCHILL](https://attack.mitre.org/software/S0181), [S0208 Pasam](https://attack.mitre.org/software/S0208), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0238 Proxysvc](https://attack.mitre.org/software/S0238), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0248 yty](https://attack.mitre.org/software/S0248), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0253 RunningRAT](https://attack.mitre.org/software/S0253), [S0259 InnaputRAT](https://attack.mitre.org/software/S0259), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0267 FELIXROOT](https://attack.mitre.org/software/S0267), [S0271 KEYMARBLE](https://attack.mitre.org/software/S0271), [S0340 Octopus](https://attack.mitre.org/software/S0340), [S0351 Cannon](https://attack.mitre.org/software/S0351), [S0353 NOKKI](https://attack.mitre.org/software/S0353), [S0356 KONNI](https://attack.mitre.org/software/S0356) _(+62 more)_  

---

