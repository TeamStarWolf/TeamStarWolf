# Collection — Technique Detail

> Full detail pages for the **36 ATT&CK techniques** whose primary tactic is [Collection](https://attack.mitre.org/tactics/TA0009/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1005 — Data from Local System
<a id="t1005"></a>

**Tactics:** Collection · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1005)  

Adversaries may search local system sources, such as file systems, configuration files, local databases, virtual machine files, or process memory, to find files of interest and sensitive data prior to Exfiltration.

**ATT&CK mitigations (1):** [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (13):** `AC-16`, `AC-2`, `AC-23`, `AC-3`, `AC-6`, `CM-12`, `CP-9`, `SA-8`, `SC-13`, `SC-28`, `SC-38`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Local Data Collection Prior to Exfiltration  
**Used by 43 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087) _(+19 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 161 software:** [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0036 FLASHFLOOD](https://attack.mitre.org/software/S0036), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0079 MobileOrder](https://attack.mitre.org/software/S0079), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0169 RawPOS](https://attack.mitre.org/software/S0169), [S0193 Forfiles](https://attack.mitre.org/software/S0193), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0197 PUNCHTRACK](https://attack.mitre.org/software/S0197), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0208 Pasam](https://attack.mitre.org/software/S0208), [S0211 Linfo](https://attack.mitre.org/software/S0211), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223) _(+137 more)_  

---

### T1025 — Data from Removable Media
<a id="t1025"></a>

**Tactics:** Collection · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1025)  

Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration.

**ATT&CK mitigations (1):** [M1057 Data Loss Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1057)  
**NIST 800-53 R5 controls (15):** `AC-16`, `AC-2`, `AC-23`, `AC-3`, `AC-6`, `CM-12`, `CP-9`, `MP-7`, `SA-8`, `SC-13`, `SC-28`, `SC-38`, `SC-41`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Data Access and Collection from Removable Media  
**Used by 4 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049)  
**Implemented by 20 software:** [S0036 FLASHFLOOD](https://attack.mitre.org/software/S0036), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0456 Aria-body](https://attack.mitre.org/software/S0456), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0538 Crutch](https://attack.mitre.org/software/S0538), [S0569 Explosive](https://attack.mitre.org/software/S0569), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0644 ObliqueRAT](https://attack.mitre.org/software/S0644), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1146 MgBot](https://attack.mitre.org/software/S1146)  

---

### T1039 — Data from Network Shared Drive
<a id="t1039"></a>

**Tactics:** Collection · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1039)  

Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Data from Network Shared Drive  
**Used by 8 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 4 software:** [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0554 Egregor](https://attack.mitre.org/software/S0554)  

---

### T1056 — Input Capture
<a id="t1056"></a>

**Tactics:** Collection, Credential Access · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1056)  

Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Input Capture Across Platforms  
**Used by 3 threat groups:** [G0087 APT39](https://attack.mitre.org/groups/G0087), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  
**Implemented by 7 software:** [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0641 Kobalos](https://attack.mitre.org/software/S0641), [S1059 metaMain](https://attack.mitre.org/software/S1059), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1131 NPPSPY](https://attack.mitre.org/software/S1131), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1056.001 — Keylogging
<a id="t1056001"></a>

sub-technique of [T1056](/techniques/collection.md#t1056) · **Tactics:** Collection, Credential Access · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1056/001)  

Adversaries may log user keystrokes to intercept credentials as the user types them.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Keylogging Activity Across Platforms  
**Used by 26 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0043 Group5](https://attack.mitre.org/groups/G0043), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0130 Ajax Security Team](https://attack.mitre.org/groups/G0130), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017) _(+2 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 123 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0019 Regin](https://attack.mitre.org/software/S0019), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0033 NetTraveler](https://attack.mitre.org/software/S0033), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0072 OwaAuth](https://attack.mitre.org/software/S0072), [S0076 FakeM](https://attack.mitre.org/software/S0076), [S0088 Kasidet](https://attack.mitre.org/software/S0088), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0113 Prikormka](https://attack.mitre.org/software/S0113) _(+99 more)_  

---

### T1056.002 — GUI Input Capture
<a id="t1056002"></a>

sub-technique of [T1056](/techniques/collection.md#t1056) · **Tactics:** Collection, Credential Access · **Platforms:** macOS, Windows, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1056/002)  

Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt.

**ATT&CK mitigations (1):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017)  
**NIST 800-53 R5 controls (4):** `CA-7`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Spoofed GUI Credential Prompts  
**Used by 2 threat groups:** [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 11 software:** [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0276 Keydnap](https://attack.mitre.org/software/S0276), [S0278 iKitten](https://attack.mitre.org/software/S0278), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0281 Dok](https://attack.mitre.org/software/S0281), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153)  

---

### T1056.003 — Web Portal Capture
<a id="t1056003"></a>

sub-technique of [T1056](/techniques/collection.md#t1056) · **Tactics:** Collection, Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1056/003)  

Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.

**ATT&CK mitigations (1):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`  
**ATT&CK detection strategy:** Detection of Credential Harvesting via Web Portal Modification  
**Used by 1 threat groups:** [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035)  
**Implemented by 2 software:** [S1022 IceApple](https://attack.mitre.org/software/S1022), [S1116 WARPWIRE](https://attack.mitre.org/software/S1116)  

---

### T1056.004 — Credential API Hooking
<a id="t1056004"></a>

sub-technique of [T1056](/techniques/collection.md#t1056) · **Tactics:** Collection, Credential Access · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1056/004)  

Adversaries may hook into Windows application programming interface (API) functions and Linux system functions to collect user credentials. Malicious hooking mechanisms may capture API or function calls that include parameters that reveal user authentication credentials.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Credential Harvesting via API Hooking  
**Used by 1 threat groups:** [G0068 PLATINUM](https://attack.mitre.org/groups/G0068)  
**Implemented by 11 software:** [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0353 NOKKI](https://attack.mitre.org/software/S0353), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0416 RDFSNIFFER](https://attack.mitre.org/software/S0416), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S1154 VersaMem](https://attack.mitre.org/software/S1154)  

---

### T1074 — Data Staged
<a id="t1074"></a>

**Tactics:** Collection · **Platforms:** Windows, IaaS, Linux, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1074)  

Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Data Staging Prior to Exfiltration  
**Used by 4 threat groups:** [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032)  
**Implemented by 4 software:** [S0641 Kobalos](https://attack.mitre.org/software/S0641), [S1019 Shark](https://attack.mitre.org/software/S1019), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1076 QUIETCANARY](https://attack.mitre.org/software/S1076)  

---

### T1074.001 — Local Data Staging
<a id="t1074001"></a>

sub-technique of [T1074](/techniques/collection.md#t1074) · **Tactics:** Collection · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1074/001)  

Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Local Data Staging Prior to Exfiltration  
**Used by 27 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1023 APT5](https://attack.mitre.org/groups/G1023) _(+3 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 88 software:** [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0035 SPACESHIP](https://attack.mitre.org/software/S0035), [S0036 FLASHFLOOD](https://attack.mitre.org/software/S0036), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0149 MoonWind](https://attack.mitre.org/software/S0149), [S0169 RawPOS](https://attack.mitre.org/software/S0169), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0197 PUNCHTRACK](https://attack.mitre.org/software/S0197), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0247 NavRAT](https://attack.mitre.org/software/S0247), [S0249 Gold Dragon](https://attack.mitre.org/software/S0249) _(+64 more)_  

---

### T1074.002 — Remote Data Staging
<a id="t1074002"></a>

sub-technique of [T1074](/techniques/collection.md#t1074) · **Tactics:** Collection · **Platforms:** Windows, IaaS, Linux, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1074/002)  

Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as Archive Collected Data.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Remote Data Staging Prior to Exfiltration  
**Used by 10 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  
**Implemented by 1 software:** [S1043 ccf32](https://attack.mitre.org/software/S1043)  

---

### T1113 — Screen Capture
<a id="t1113"></a>

**Tactics:** Collection · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1113)  

Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Screen Capture via Commands and API Calls  
**Used by 18 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0043 Group5](https://attack.mitre.org/groups/G0043), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 148 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0086 ZLib](https://attack.mitre.org/software/S0086), [S0088 Kasidet](https://attack.mitre.org/software/S0088), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0143 Flame](https://attack.mitre.org/software/S0143), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0151 HALFBAKED](https://attack.mitre.org/software/S0151), [S0152 EvilGrab](https://attack.mitre.org/software/S0152) _(+124 more)_  

---

### T1114 — Email Collection
<a id="t1114"></a>

**Tactics:** Collection · **Platforms:** Windows, macOS, Linux, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1114)  

Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries.

**ATT&CK mitigations (4):** [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1060 Out-of-Band Communications Channel](../ATTACK_MITIGATIONS_REFERENCE.md#m1060)  
**NIST 800-53 R5 controls (15):** `AC-16`, `AC-17`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `SC-37`, `SC-7`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Email Collection via Local Email Access and Auto-Forwarding Behavior  
**Used by 4 threat groups:** [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  
**Implemented by 2 software:** [S0367 Emotet](https://attack.mitre.org/software/S0367), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201)  

---

### T1114.001 — Local Email Collection
<a id="t1114001"></a>

sub-technique of [T1114](/techniques/collection.md#t1114) · **Tactics:** Collection · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1114/001)  

Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files. Outlook stores data locally in offline data files with an extension of .ost.

**ATT&CK mitigations (2):** [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1060 Out-of-Band Communications Channel](../ATTACK_MITIGATIONS_REFERENCE.md#m1060)  
**NIST 800-53 R5 controls (9):** `AC-16`, `AC-17`, `AC-19`, `AC-20`, `AC-4`, `SC-37`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Local Email Collection via Outlook Data File Access and Command Line Tooling  
**Used by 6 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  
**Implemented by 11 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526), [S0594 Out1](https://attack.mitre.org/software/S0594), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S1142 LunarMail](https://attack.mitre.org/software/S1142)  

---

### T1114.002 — Remote Email Collection
<a id="t1114002"></a>

sub-technique of [T1114](/techniques/collection.md#t1114) · **Tactics:** Collection · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1114/002)  

Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network.

**ATT&CK mitigations (3):** [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1060 Out-of-Band Communications Channel](../ATTACK_MITIGATIONS_REFERENCE.md#m1060)  
**NIST 800-53 R5 controls (14):** `AC-16`, `AC-17`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `SC-37`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Remote Email Collection via Abnormal Login and Programmatic Access  
**Used by 12 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033)  
**Implemented by 4 software:** [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0413 MailSniper](https://attack.mitre.org/software/S0413), [S0476 Valak](https://attack.mitre.org/software/S0476)  

---

### T1114.003 — Email Forwarding Rule
<a id="t1114003"></a>

sub-technique of [T1114](/techniques/collection.md#t1114) · **Tactics:** Collection · **Platforms:** Linux, macOS, Office Suite, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1114/003)  

Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim’s organization to use as part of further exploits or operations.

**ATT&CK mitigations (4):** [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1060 Out-of-Band Communications Channel](../ATTACK_MITIGATIONS_REFERENCE.md#m1060)  
**NIST 800-53 R5 controls (12):** `AC-16`, `AC-17`, `AC-19`, `AC-20`, `AC-4`, `CM-6`, `SC-37`, `SC-43`, `SC-7`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Email Forwarding Rule Abuse Detection Across Platforms  
**Used by 5 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033)  

---

### T1115 — Clipboard Data
<a id="t1115"></a>

**Tactics:** Collection · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1115)  

Adversaries may collect data stored in the clipboard from users copying information within or between applications. For example, on Windows adversaries can access clipboard data by using <code>clip.exe</code> or <code>Get-Clipboard</code>.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Clipboard Data Access with Anomalous Context  
**Used by 3 threat groups:** [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087)  
**Implemented by 41 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0253 RunningRAT](https://attack.mitre.org/software/S0253), [S0257 VERMIN](https://attack.mitre.org/software/S0257), [S0261 Catchamas](https://attack.mitre.org/software/S0261), [S0282 MacSpy](https://attack.mitre.org/software/S0282), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0375 Remexi](https://attack.mitre.org/software/S0375), [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0454 Cadelspy](https://attack.mitre.org/software/S0454) _(+17 more)_  

---

### T1119 — Automated Collection
<a id="t1119"></a>

**Tactics:** Collection · **Platforms:** IaaS, Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1119)  

Once established within a system or network, an adversary may use automated techniques for collecting internal data.

**ATT&CK mitigations (2):** [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (17):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `CM-2`, `CM-6`, `CM-8`, `CP-6`, `CP-7`, `CP-9`, `SC-36`, `SC-4`, `SI-12`, `SI-23`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Automated File and API Collection Detection Across Platforms  
**Used by 20 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0142 Confucius](https://attack.mitre.org/groups/G0142), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 44 software:** [S0090 Rover](https://attack.mitre.org/software/S0090), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0238 Proxysvc](https://attack.mitre.org/software/S0238), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0257 VERMIN](https://attack.mitre.org/software/S0257), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0339 Micropsia](https://attack.mitre.org/software/S0339), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0443 MESSAGETAP](https://attack.mitre.org/software/S0443), [S0445 ShimRatReporter](https://attack.mitre.org/software/S0445), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0466 WindTail](https://attack.mitre.org/software/S0466) _(+20 more)_  

---

### T1123 — Audio Capture
<a id="t1123"></a>

**Tactics:** Collection · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1123)  

An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection Strategy for T1123 Audio Capture Across Windows, Linux, macOS  
**Used by 1 threat groups:** [G0067 APT37](https://attack.mitre.org/groups/G0067)  
**Implemented by 30 software:** [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0143 Flame](https://attack.mitre.org/software/S0143), [S0152 EvilGrab](https://attack.mitre.org/software/S0152), [S0163 Janicab](https://attack.mitre.org/software/S0163), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0213 DOGCALL](https://attack.mitre.org/software/S0213), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0257 VERMIN](https://attack.mitre.org/software/S0257), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0282 MacSpy](https://attack.mitre.org/software/S0282), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0338 Cobian RAT](https://attack.mitre.org/software/S0338), [S0339 Micropsia](https://attack.mitre.org/software/S0339), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0438 Attor](https://attack.mitre.org/software/S0438) _(+6 more)_  

---

### T1125 — Video Capture
<a id="t1125"></a>

**Tactics:** Collection · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1125)  

An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavior-chain, platform-aware detection strategy for T1125 Video Capture  
**Used by 3 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  
**Implemented by 31 software:** [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0152 EvilGrab](https://attack.mitre.org/software/S0152), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0338 Cobian RAT](https://attack.mitre.org/software/S0338), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0467 TajMahal](https://attack.mitre.org/software/S0467) _(+7 more)_  

---

### T1185 — Browser Session Hijacking
<a id="t1185"></a>

**Tactics:** Collection · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1185)  

Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (14):** `AC-10`, `AC-12`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `IA-2`, `SC-23`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect browser session hijacking via privilege, handle access, and remote thread into browsers  
**Used by 1 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  
**Implemented by 13 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0384 Dridex](https://attack.mitre.org/software/S0384), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0530 Melcoz](https://attack.mitre.org/software/S0530), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1207 XLoader](https://attack.mitre.org/software/S1207)  

---

### T1213 — Data from Information Repositories
<a id="t1213"></a>

**Tactics:** Collection · **Platforms:** Linux, Windows, macOS, SaaS, IaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1213)  

Adversaries may leverage information repositories to mine valuable information.

**ATT&CK mitigations (7):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054), [M1060 Out-of-Band Communications Channel](../ATTACK_MITIGATIONS_REFERENCE.md#m1060)  
**NIST 800-53 R5 controls (24):** `AC-16`, `AC-17`, `AC-2`, `AC-21`, `AC-23`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `IA-8`, `RA-5`, `SC-28`, `SC-37`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Abuse of Information Repositories for Data Collection  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  
**Implemented by 2 software:** [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1196 Troll Stealer](https://attack.mitre.org/software/S1196)  

---

### T1213.001 — Confluence
<a id="t1213001"></a>

sub-technique of [T1213](/techniques/collection.md#t1213) · **Tactics:** Collection · **Platforms:** SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1213/001)  

Adversaries may leverage Confluence repositories to mine valuable information.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (23):** `AC-16`, `AC-17`, `AC-2`, `AC-21`, `AC-23`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `IA-8`, `RA-5`, `SC-28`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Programmatic and Excessive Access to Confluence Documentation  
**Used by 1 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  

---

### T1213.002 — Sharepoint
<a id="t1213002"></a>

sub-technique of [T1213](/techniques/collection.md#t1213) · **Tactics:** Collection · **Platforms:** Windows, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1213/002)  

Adversaries may leverage the SharePoint repository as a source to mine valuable information. SharePoint will often contain useful information for an adversary to learn about the structure and functionality of the internal network and systems.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (23):** `AC-16`, `AC-17`, `AC-2`, `AC-21`, `AC-23`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `IA-8`, `RA-5`, `SC-28`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Abnormal SharePoint Data Mining by Privileged or Rare Users  
**Used by 6 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1024 Akira](https://attack.mitre.org/groups/G1024)  
**Implemented by 1 software:** [S0227 spwebmember](https://attack.mitre.org/software/S0227)  

---

### T1213.003 — Code Repositories
<a id="t1213003"></a>

sub-technique of [T1213](/techniques/collection.md#t1213) · **Tactics:** Collection · **Platforms:** SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1213/003)  

Adversaries may leverage code repositories to collect valuable information. Code repositories are tools/services that store source code and automate software builds. They may be hosted internally or privately on third party sites such as Github, GitLab, SourceForge, and BitBucket.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `IA-2`, `IA-9`, `RA-5`, `SA-10`, `SA-11`, `SA-15`, `SA-3`, `SA-8`, `SI-2`  
**ATT&CK detection strategy:** Detecting Bulk or Anomalous Access to Private Code Repositories via SaaS Platforms  
**Used by 3 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1213.004 — Customer Relationship Management Software
<a id="t1213004"></a>

sub-technique of [T1213](/techniques/collection.md#t1213) · **Tactics:** Collection · **Platforms:** SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1213/004)  

Adversaries may leverage Customer Relationship Management (CRM) software to mine valuable information. CRM software is used to assist organizations in tracking and managing customer interactions, as well as storing customer data.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (18):** `AC-16`, `AC-2`, `AC-21`, `AC-23`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `IA-8`, `SC-28`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Suspicious Access to CRM Data in SaaS Environments  

---

### T1213.005 — Messaging Applications
<a id="t1213005"></a>

sub-technique of [T1213](/techniques/collection.md#t1213) · **Tactics:** Collection · **Platforms:** SaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1213/005)  

Adversaries may leverage chat and messaging applications, such as Microsoft Teams, Google Chat, and Slack, to mine valuable information.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1060 Out-of-Band Communications Channel](../ATTACK_MITIGATIONS_REFERENCE.md#m1060)  
**NIST 800-53 R5 controls (24):** `AC-16`, `AC-17`, `AC-2`, `AC-21`, `AC-23`, `AC-3`, `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-4`, `IA-8`, `RA-5`, `SC-28`, `SC-37`, `SI-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Unauthorized Collection from Messaging Applications in SaaS and Office Environments  
**Used by 3 threat groups:** [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1213.006 — Databases
<a id="t1213006"></a>

sub-technique of [T1213](/techniques/collection.md#t1213) · **Tactics:** Collection · **Platforms:** Linux, Windows, macOS, IaaS, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1213/006)  

Adversaries may leverage databases to mine valuable information. These databases may be hosted on-premises or in the cloud (both in platform-as-a-service and software-as-a-service environments).

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Suspicious Database Access and Dump Activity Across Environments (T1213.006)  
**Used by 4 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  
**Implemented by 2 software:** [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S1146 MgBot](https://attack.mitre.org/software/S1146)  

---

### T1530 — Data from Cloud Storage
<a id="t1530"></a>

**Tactics:** Collection · **Platforms:** IaaS, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1530)  

Adversaries may access data from cloud storage. Many IaaS providers offer solutions for online data object storage such as Amazon S3, Azure Storage, and Google Cloud Storage.

**ATT&CK mitigations (6):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (32):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-3`, `IA-4`, `IA-5`, `IA-6`, `IA-8`, `RA-5`, `SC-28`, `SC-4`, `SC-7`, `SI-10`, `SI-12`, `SI-15`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Multi-Platform Cloud Storage Exfiltration Behavior Chain  
**Used by 5 threat groups:** [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 3 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S0683 Peirates](https://attack.mitre.org/software/S0683), [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1560 — Archive Collected Data
<a id="t1560"></a>

**Tactics:** Collection · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1560)  

An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network.

**ATT&CK mitigations (1):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (5):** `CM-2`, `RA-5`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect Archiving and Encryption of Collected Data (T1560)  
**Used by 13 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 41 software:** [S0010 Lurid](https://attack.mitre.org/software/S0010), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0249 Gold Dragon](https://attack.mitre.org/software/S0249), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0253 RunningRAT](https://attack.mitre.org/software/S0253), [S0257 VERMIN](https://attack.mitre.org/software/S0257), [S0267 FELIXROOT](https://attack.mitre.org/software/S0267), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0343 Exaramel for Windows](https://attack.mitre.org/software/S0343), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0375 Remexi](https://attack.mitre.org/software/S0375), [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0445 ShimRatReporter](https://attack.mitre.org/software/S0445), [S0454 Cadelspy](https://attack.mitre.org/software/S0454), [S0456 Aria-body](https://attack.mitre.org/software/S0456), [S0487 Kessel](https://attack.mitre.org/software/S0487) _(+17 more)_  

---

### T1560.001 — Archive via Utility
<a id="t1560001"></a>

sub-technique of [T1560](/techniques/collection.md#t1560) · **Tactics:** Collection · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1560/001)  

Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.

**ATT&CK mitigations (1):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (5):** `CM-2`, `RA-5`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect Archiving via Utility (T1560.001)  
**Used by 37 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0084 Gallmaker](https://attack.mitre.org/groups/G0084), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129) _(+13 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 31 software:** [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0160 certutil](https://attack.mitre.org/software/S0160), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0212 CORALDECK](https://attack.mitre.org/software/S0212), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0278 iKitten](https://attack.mitre.org/software/S0278), [S0339 Micropsia](https://attack.mitre.org/software/S0339), [S0340 Octopus](https://attack.mitre.org/software/S0340), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0441 PowerShower](https://attack.mitre.org/software/S0441), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0466 WindTail](https://attack.mitre.org/software/S0466), [S0538 Crutch](https://attack.mitre.org/software/S0538), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0647 Turian](https://attack.mitre.org/software/S0647), [S1022 IceApple](https://attack.mitre.org/software/S1022), [S1040 Rclone](https://attack.mitre.org/software/S1040), [S1043 ccf32](https://attack.mitre.org/software/S1043) _(+7 more)_  

---

### T1560.002 — Archive via Library
<a id="t1560002"></a>

sub-technique of [T1560](/techniques/collection.md#t1560) · **Tactics:** Collection · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1560/002)  

An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including Python rarfile , libzip , and zlib . Most libraries include functionality to encrypt and/or compress data.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Archiving via Library (T1560.002)  
**Used by 2 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032)  
**Implemented by 13 software:** [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0086 ZLib](https://attack.mitre.org/software/S0086), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0354 Denis](https://attack.mitre.org/software/S0354), [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0642 BADFLICK](https://attack.mitre.org/software/S0642), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1141 LunarWeb](https://attack.mitre.org/software/S1141)  

---

### T1560.003 — Archive via Custom Method
<a id="t1560003"></a>

sub-technique of [T1560](/techniques/collection.md#t1560) · **Tactics:** Collection · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1560/003)  

An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Archiving via Custom Method (T1560.003)  
**Used by 7 threat groups:** [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 31 software:** [S0035 SPACESHIP](https://attack.mitre.org/software/S0035), [S0036 FLASHFLOOD](https://attack.mitre.org/software/S0036), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0072 OwaAuth](https://attack.mitre.org/software/S0072), [S0092 Agent.btz](https://attack.mitre.org/software/S0092), [S0098 T9000](https://attack.mitre.org/software/S0098), [S0169 RawPOS](https://attack.mitre.org/software/S0169), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0258 RGDoor](https://attack.mitre.org/software/S0258), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0391 HAWKBALL](https://attack.mitre.org/software/S0391), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0443 MESSAGETAP](https://attack.mitre.org/software/S0443), [S0448 Rising Sun](https://attack.mitre.org/software/S0448), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0503 FrameworkPOS](https://attack.mitre.org/software/S0503), [S0603 Stuxnet](https://attack.mitre.org/software/S0603) _(+7 more)_  

---

### T1602 — Data from Configuration Repository
<a id="t1602"></a>

**Tactics:** Collection · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1602)  

Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.

**ATT&CK mitigations (6):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (25):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-3`, `IA-4`, `SC-28`, `SC-3`, `SC-4`, `SC-7`, `SC-8`, `SI-10`, `SI-12`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Data from Configuration Repository on Network Devices  

---

### T1602.001 — SNMP (MIB Dump)
<a id="t1602001"></a>

sub-technique of [T1602](/techniques/collection.md#t1602) · **Tactics:** Collection · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1602/001)  

Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP). The MIB is a configuration repository that stores variable information accessible via SNMP in the form of object identifiers (OID).

**ATT&CK mitigations (6):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (25):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-3`, `IA-4`, `SC-28`, `SC-3`, `SC-4`, `SC-7`, `SC-8`, `SI-10`, `SI-12`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for SNMP (MIB Dump) on Network Devices  

---

### T1602.002 — Network Device Configuration Dump
<a id="t1602002"></a>

sub-technique of [T1602](/techniques/collection.md#t1602) · **Tactics:** Collection · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1602/002)  

Adversaries may access network configuration files to collect sensitive data about the device and the network. The network configuration is a file containing parameters that determine the operation of the device.

**ATT&CK mitigations (6):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (25):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `IA-3`, `IA-4`, `SC-28`, `SC-3`, `SC-4`, `SC-7`, `SC-8`, `SI-10`, `SI-12`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Network Device Configuration Dump via Config Repositories  
**Used by 1 threat groups:** [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  

---

