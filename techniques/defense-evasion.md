# Defense Evasion — Technique Detail

> Full detail pages for the **183 ATT&CK techniques** whose primary tactic is [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1006 — Direct Volume Access
<a id="t1006"></a>

**Tactics:** Defense Evasion · **Platforms:** Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1006)  

Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Direct Volume Access for File System Evasion  
**Used by 2 threat groups:** [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 1 software:** [S0404 esentutl](https://attack.mitre.org/software/S0404)  

---

### T1014 — Rootkit
<a id="t1014"></a>

**Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1014)  

Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Kernel/User-Level Rootkit Behavior Across Platforms  
**Used by 6 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0044 Winnti Group](https://attack.mitre.org/groups/G0044), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 24 software:** [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0027 Zeroaccess](https://attack.mitre.org/software/S0027), [S0040 HTRAN](https://attack.mitre.org/software/S0040), [S0047 Hacking Team UEFI Rootkit](https://attack.mitre.org/software/S0047), [S0135 HIDEDRV](https://attack.mitre.org/software/S0135), [S0221 Umbreon](https://attack.mitre.org/software/S0221), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0394 HiddenWasp](https://attack.mitre.org/software/S0394), [S0397 LoJax](https://attack.mitre.org/software/S0397), [S0430 Winnti for Linux](https://attack.mitre.org/software/S0430), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0468 Skidmap](https://attack.mitre.org/software/S0468), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0502 Drovorub](https://attack.mitre.org/software/S0502), [S0572 Caterpillar WebShell](https://attack.mitre.org/software/S0572), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S1105 COATHANGER](https://attack.mitre.org/software/S1105), [S1186 Line Dancer](https://attack.mitre.org/software/S1186), [S1219 REPTILE](https://attack.mitre.org/software/S1219), [S1220 MEDUSA](https://attack.mitre.org/software/S1220)  

---

### T1027 — Obfuscated Files or Information
<a id="t1027"></a>

**Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027)  

Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (8):** `AC-3`, `CM-2`, `CM-6`, `CM-7`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1027) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 18 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0063 BlackOasis](https://attack.mitre.org/groups/G0063), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0084 Gallmaker](https://attack.mitre.org/groups/G0084), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0099 APT-C-36](https://attack.mitre.org/groups/G0099), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0112 Windshift](https://attack.mitre.org/groups/G0112), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 130 software:** [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0063 SHOTPUT](https://attack.mitre.org/software/S0063), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0117 XTunnel](https://attack.mitre.org/software/S0117), [S0124 Pisloader](https://attack.mitre.org/software/S0124), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0137 CORESHELL](https://attack.mitre.org/software/S0137), [S0138 OLDBAIT](https://attack.mitre.org/software/S0138), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0142 StreamEx](https://attack.mitre.org/software/S0142), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0150 POSHSPY](https://attack.mitre.org/software/S0150), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0187 Daserf](https://attack.mitre.org/software/S0187) _(+106 more)_  

---

### T1027.001 — Binary Padding
<a id="t1027001"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/001)  

Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This can be done without affecting the functionality or behavior of a binary, but can increase the size of the binary beyond what some security tools are capable of handling due to file size limitations.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Obfuscated Files or Information: Binary Padding  
**Used by 8 threat groups:** [G0002 Moafee](https://attack.mitre.org/groups/G0002), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G1024 Akira](https://attack.mitre.org/groups/G1024)  
**Implemented by 20 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0433 Rifdoor](https://attack.mitre.org/software/S0433), [S0477 Goopy](https://attack.mitre.org/software/S0477), [S0528 Javali](https://attack.mitre.org/software/S0528), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0586 TAINTEDSCRIBE](https://attack.mitre.org/software/S0586), [S0614 CostaBricks](https://attack.mitre.org/software/S0614), [S0632 GrimAgent](https://attack.mitre.org/software/S0632), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1086 Snip3](https://attack.mitre.org/software/S1086), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1185 LightSpy](https://attack.mitre.org/software/S1185), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1027.002 — Software Packing
<a id="t1027002"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/002)  

Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection.

**ATT&CK mitigations (1):** [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (4):** `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Obfuscated Binary Unpacking Detection via Behavioral Patterns  
**Used by 23 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0066 Elderwood](https://attack.mitre.org/groups/G0066), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0089 The White Company](https://attack.mitre.org/groups/G0089), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1007 Aoqin Dragon](https://attack.mitre.org/groups/G1007), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 72 software:** [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0248 yty](https://attack.mitre.org/software/S0248), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0257 VERMIN](https://attack.mitre.org/software/S0257), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0281 Dok](https://attack.mitre.org/software/S0281), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0356 KONNI](https://attack.mitre.org/software/S0356) _(+48 more)_  

---

### T1027.003 — Steganography
<a id="t1027003"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/003)  

Adversaries may use steganography techniques in order to prevent the detection of hidden information. Steganographic techniques can be used to hide data in digital media such as images, audio tracks, video clips, or text files. Duqu was an early example of malware that used steganography.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Steganographic Abuse in File & Script Execution  
**Used by 8 threat groups:** [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G0138 Andariel](https://attack.mitre.org/groups/G0138), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006)  
**Implemented by 19 software:** [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0231 Invoke-PSImage](https://attack.mitre.org/software/S0231), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0469 ABK](https://attack.mitre.org/software/S0469), [S0470 BBK](https://attack.mitre.org/software/S0470), [S0471 build_downer](https://attack.mitre.org/software/S0471), [S0473 Avenger](https://attack.mitre.org/software/S0473), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S0511 RegDuke](https://attack.mitre.org/software/S0511), [S0513 LiteDuke](https://attack.mitre.org/software/S0513), [S0518 PolyglotDuke](https://attack.mitre.org/software/S0518), [S0565 Raindrop](https://attack.mitre.org/software/S0565), [S0644 ObliqueRAT](https://attack.mitre.org/software/S0644), [S0654 ProLock](https://attack.mitre.org/software/S0654), [S0659 Diavol](https://attack.mitre.org/software/S0659), [S1145 Pikabot](https://attack.mitre.org/software/S1145)  

---

### T1027.004 — Compile After Delivery
<a id="t1027004"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/004)  

Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Compile After Delivery - Source Code to Executable Transformation  
**Used by 4 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  
**Implemented by 6 software:** [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S1099 Samurai](https://attack.mitre.org/software/S1099)  

---

### T1027.005 — Indicator Removal from Tools
<a id="t1027005"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/005)  

Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Indicator Removal from Tools - Post-AV Evasion Modification  
**Used by 7 threat groups:** [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 9 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0579 Waterbear](https://attack.mitre.org/software/S0579), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0650 QakBot](https://attack.mitre.org/software/S0650)  

---

### T1027.006 — HTML Smuggling
<a id="t1027006"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/006)  

Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign HTML files. HTML documents can store large binary objects known as JavaScript Blobs (immutable data that represents raw bytes) that can later be constructed into file-like objects.

**ATT&CK mitigations (1):** [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for HTML Smuggling via JavaScript Blob + Dynamic File Drop  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 2 software:** [S0634 EnvyScout](https://attack.mitre.org/software/S0634), [S0650 QakBot](https://attack.mitre.org/software/S0650)  

---

### T1027.007 — Dynamic API Resolution
<a id="t1027007"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/007)  

Adversaries may obfuscate then dynamically resolve API functions called by their malware in order to conceal malicious functionalities and impair defensive analysis.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (4):** `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Dynamic API Resolution via Hash-Based Function Lookups  
**Used by 2 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 13 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1099 Samurai](https://attack.mitre.org/software/S1099), [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1232 SplatDropper](https://attack.mitre.org/software/S1232), [S1236 CLAIMLOADER](https://attack.mitre.org/software/S1236), [S1237 CANONSTAGER](https://attack.mitre.org/software/S1237), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1027.008 — Stripped Payloads
<a id="t1027008"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** macOS, Linux, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/008)  

Adversaries may attempt to make a payload difficult to analyze by removing symbols, strings, and other human readable information. Scripts and executables may contain variables names and other strings that help developers document code functionality.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (4):** `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Stripped Payloads Across Platforms  
**Implemented by 2 software:** [S1048 macOS.OSAMiner](https://attack.mitre.org/software/S1048), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153)  

---

### T1027.009 — Embedded Payloads
<a id="t1027009"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/009)  

Adversaries may embed payloads within other files to conceal malicious content from defenses. Otherwise seemingly benign files (such as scripts and executables) may be abused to carry and obfuscate malicious payloads and content.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (4):** `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Embedded Payloads  
**Used by 3 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1037 TA577](https://attack.mitre.org/groups/G1037)  
**Implemented by 18 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0231 Invoke-PSImage](https://attack.mitre.org/software/S0231), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S1048 macOS.OSAMiner](https://attack.mitre.org/software/S1048), [S1052 DEADEYE](https://attack.mitre.org/software/S1052), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1134 DEADWOOD](https://attack.mitre.org/software/S1134), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1137 Moneybird](https://attack.mitre.org/software/S1137), [S1145 Pikabot](https://attack.mitre.org/software/S1145), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1158 DUSTPAN](https://attack.mitre.org/software/S1158), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159)  

---

### T1027.010 — Command Obfuscation
<a id="t1027010"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/010)  

Adversaries may obfuscate content during command execution to impede detection. Command-line obfuscation is a method of making strings and patterns within commands and scripts more difficult to signature and analyze.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (4):** `CM-6`, `SI-10`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Command Obfuscation  
**Used by 28 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143) _(+4 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 31 software:** [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0269 QUADAGENT](https://attack.mitre.org/software/S0269), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0277 FruitFly](https://attack.mitre.org/software/S0277), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0354 Denis](https://attack.mitre.org/software/S0354), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0390 SQLRat](https://attack.mitre.org/software/S0390), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0450 SHARPSTATS](https://attack.mitre.org/software/S0450), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0457 Netwalker](https://attack.mitre.org/software/S0457), [S0462 CARROTBAT](https://attack.mitre.org/software/S0462), [S0475 BackConfig](https://attack.mitre.org/software/S0475), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0589 Sibot](https://attack.mitre.org/software/S0589), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669) _(+7 more)_  

---

### T1027.011 — Fileless Storage
<a id="t1027011"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Windows, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/011)  

Adversaries may store data in "fileless" formats to conceal malicious activity from defenses. Fileless storage can be broadly defined as any format other than a file. Common examples of non-volatile fileless storage in Windows systems include the Windows Registry, event logs, or WMI repository.

**ATT&CK mitigations (1):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (1):** `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Fileless Storage via Registry, WMI, and Shared Memory  
**Used by 2 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0050 APT32](https://attack.mitre.org/groups/G0050)  
**Implemented by 27 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0256 Mosquito](https://attack.mitre.org/software/S0256), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0269 QUADAGENT](https://attack.mitre.org/software/S0269), [S0343 Exaramel for Windows](https://attack.mitre.org/software/S0343), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0511 RegDuke](https://attack.mitre.org/software/S0511), [S0517 Pillowmint](https://attack.mitre.org/software/S0517), [S0518 PolyglotDuke](https://attack.mitre.org/software/S0518), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0589 Sibot](https://attack.mitre.org/software/S0589), [S0596 ShadowPad](https://attack.mitre.org/software/S0596), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S0663 SysUpdate](https://attack.mitre.org/software/S0663), [S0665 ThreatNeedle](https://attack.mitre.org/software/S0665), [S0666 Gelsemium](https://attack.mitre.org/software/S0666) _(+3 more)_  

---

### T1027.012 — LNK Icon Smuggling
<a id="t1027012"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/012)  

Adversaries may smuggle commands to download malicious payloads past content filters by hiding them within otherwise seemingly benign windows shortcut files.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (2):** `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for LNK Icon Smuggling  
**Used by 3 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 1 software:** [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1027.013 — Encrypted/Encoded File
<a id="t1027013"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/013)  

Adversaries may encrypt or encode files to obfuscate strings, bytes, and other specific patterns to impede detection. Encrypting and/or encoding file content aims to conceal malicious artifacts within a file used in an intrusion.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (1):** `SI-3`  
**ATT&CK detection strategy:** Encrypted or Encoded File Payload Detection Strategy  
**Used by 37 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0024 Putter Panda](https://attack.mitre.org/groups/G0024), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0043 Group5](https://attack.mitre.org/groups/G0043), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0066 Elderwood](https://attack.mitre.org/groups/G0066), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0103 Mofang](https://attack.mitre.org/groups/G0103), [G0107 Whitefly](https://attack.mitre.org/groups/G0107), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117) _(+13 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 172 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0087 Hi-Zor](https://attack.mitre.org/software/S0087), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0131 TINYTYPHON](https://attack.mitre.org/software/S0131), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0213 DOGCALL](https://attack.mitre.org/software/S0213), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0228 NanHaiShu](https://attack.mitre.org/software/S0228), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0232 HOMEFRY](https://attack.mitre.org/software/S0232) _(+148 more)_  

---

### T1027.014 — Polymorphic Code
<a id="t1027014"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/014)  

Adversaries may utilize polymorphic code (also known as metamorphic or mutating code) to evade detection. Polymorphic code is a type of software capable of changing its runtime footprint during code execution.

**ATT&CK mitigations (2):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (1):** `SI-3`  
**ATT&CK detection strategy:** Detection Strategy for Polymorphic Code Mutation and Execution  
**Implemented by 1 software:** [S0574 BendyBear](https://attack.mitre.org/software/S0574)  

---

### T1027.015 — Compression
<a id="t1027015"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/015)  

Adversaries may use compression to obfuscate their payloads or files. Compressed file formats such as ZIP, gzip, 7z, and RAR can compress and archive multiple files together to make it easier and faster to transfer files.

**ATT&CK mitigations (1):** [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Compressed Payload Creation and Execution  
**Used by 7 threat groups:** [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0103 Mofang](https://attack.mitre.org/groups/G0103), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G1018 TA2541](https://attack.mitre.org/groups/G1018)  
**Implemented by 24 software:** [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0466 WindTail](https://attack.mitre.org/software/S0466), [S0499 Hancitor](https://attack.mitre.org/software/S0499), [S0517 Pillowmint](https://attack.mitre.org/software/S0517), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0585 Kerrdown](https://attack.mitre.org/software/S0585), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S0664 Pandora](https://attack.mitre.org/software/S0664), [S0665 ThreatNeedle](https://attack.mitre.org/software/S0665), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S0695 Donut](https://attack.mitre.org/software/S0695), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1050 PcShare](https://attack.mitre.org/software/S1050), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1099 Samurai](https://attack.mitre.org/software/S1099), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1124 SocGholish](https://attack.mitre.org/software/S1124), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1188 Line Runner](https://attack.mitre.org/software/S1188), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228)  

---

### T1027.016 — Junk Code Insertion
<a id="t1027016"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/016)  

Adversaries may use junk code / dead code to obfuscate a malware’s functionality. Junk code is code that either does not execute, or if it does execute, does not change the functionality of the code.

**ATT&CK mitigations (1):** [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Junk Code Obfuscation with Suspicious Execution Patterns  
**Used by 5 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 14 software:** [S0117 XTunnel](https://attack.mitre.org/software/S0117), [S0137 CORESHELL](https://attack.mitre.org/software/S0137), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0248 yty](https://attack.mitre.org/software/S0248), [S0370 SamSam](https://attack.mitre.org/software/S0370), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0477 Goopy](https://attack.mitre.org/software/S0477), [S0512 FatDuke](https://attack.mitre.org/software/S0512), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183)  

---

### T1027.017 — SVG Smuggling
<a id="t1027017"></a>

sub-technique of [T1027](/techniques/defense-evasion.md#t1027) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1027/017)  

Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign SVG files. SVGs, or Scalable Vector Graphics, are vector-based image files constructed using XML.

**ATT&CK mitigations (1):** [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for SVG Smuggling with Script Execution and Delivery Behavior  

---

### T1036 — Masquerading
<a id="t1036"></a>

**Tactics:** Defense Evasion · **Platforms:** Containers, ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036)  

Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation.

**ATT&CK mitigations (8):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `IA-9`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Masquerading Across Platforms via Metadata and Execution Discrepancy  
**Used by 20 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0112 Windshift](https://attack.mitre.org/groups/G0112), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0133 Nomadic Octopus](https://attack.mitre.org/groups/G0133), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1007 Aoqin Dragon](https://attack.mitre.org/groups/G1007), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 31 software:** [S0148 RTM](https://attack.mitre.org/software/S0148), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0466 WindTail](https://attack.mitre.org/software/S0466), [S0497 Dacls](https://attack.mitre.org/software/S0497), [S0565 Raindrop](https://attack.mitre.org/software/S0565), [S0615 SombRAT](https://attack.mitre.org/software/S0615), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0634 EnvyScout](https://attack.mitre.org/software/S0634), [S0635 BoomBox](https://attack.mitre.org/software/S0635), [S0637 NativeZone](https://attack.mitre.org/software/S0637), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S0682 TrailBlazer](https://attack.mitre.org/software/S0682), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0696 Flagpro](https://attack.mitre.org/software/S0696), [S1015 Milan](https://attack.mitre.org/software/S1015), [S1018 Saint Bot](https://attack.mitre.org/software/S1018) _(+7 more)_  

---

### T1036.001 — Invalid Code Signature
<a id="t1036001"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/001)  

Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with.

**ATT&CK mitigations (1):** [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045)  
**NIST 800-53 R5 controls (5):** `CM-2`, `CM-6`, `IA-9`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Invalid Code Signature Execution Detection via Metadata and Behavioral Context  
**Used by 2 threat groups:** [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0112 Windshift](https://attack.mitre.org/groups/G0112)  
**Implemented by 7 software:** [S0019 Regin](https://attack.mitre.org/software/S0019), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0466 WindTail](https://attack.mitre.org/software/S0466), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S1050 PcShare](https://attack.mitre.org/software/S1050), [S1234 SplatCloak](https://attack.mitre.org/software/S1234)  

---

### T1036.002 — Right-to-Left Override
<a id="t1036002"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/002)  

Adversaries may abuse the right-to-left override (RTLO or RLO) character (U+202E) to disguise a string and/or file name to make it appear benign. RTLO is a non-printing Unicode character that causes the text that follows it to be displayed in reverse.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Right-to-Left Override Masquerading Detection via Filename and Execution Context  
**Used by 5 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0029 Scarlet Mimic](https://attack.mitre.org/groups/G0029), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0137 Ferocious Kitten](https://attack.mitre.org/groups/G0137)  

---

### T1036.003 — Rename Legitimate Utilities
<a id="t1036003"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/003)  

Adversaries may rename legitimate / system utilities to try to evade security mechanisms concerning the usage of those utilities.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Renamed Legitimate Utility Execution with Metadata Mismatch and Suspicious Path  
**Used by 6 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  
**Implemented by 4 software:** [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183)  

---

### T1036.004 — Masquerade Task or Service
<a id="t1036004"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/004)  

Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign. Tasks/services executed by the Task Scheduler or systemd will typically be given a name and/or description. Windows services will have a service name as well as a display name.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Masqueraded Tasks or Services with Suspicious Naming and Execution  
**Used by 22 threat groups:** [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0099 APT-C-36](https://attack.mitre.org/groups/G0099), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 61 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0118 Nidiran](https://attack.mitre.org/software/S0118), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0169 RawPOS](https://attack.mitre.org/software/S0169), [S0178 Truvasys](https://attack.mitre.org/software/S0178), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0259 InnaputRAT](https://attack.mitre.org/software/S0259), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0261 Catchamas](https://attack.mitre.org/software/S0261), [S0343 Exaramel for Windows](https://attack.mitre.org/software/S0343), [S0345 Seasalt](https://attack.mitre.org/software/S0345), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0410 Fysbis](https://attack.mitre.org/software/S0410), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0444 ShimRat](https://attack.mitre.org/software/S0444) _(+37 more)_  

---

### T1036.005 — Match Legitimate Resource Name or Location
<a id="t1036005"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Containers, ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/005)  

Adversaries may match or approximate the name or location of legitimate files, Registry keys, or other resources when naming/placing them. This is done for the sake of evading defenses and observation.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `IA-9`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Masquerading via Legitimate Resource Name or Location  
**Used by 59 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081) _(+35 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 130 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0072 OwaAuth](https://attack.mitre.org/software/S0072), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0086 ZLib](https://attack.mitre.org/software/S0086), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0138 OLDBAIT](https://attack.mitre.org/software/S0138), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0171 Felismus](https://attack.mitre.org/software/S0171), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0188 Starloader](https://attack.mitre.org/software/S0188), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0259 InnaputRAT](https://attack.mitre.org/software/S0259), [S0260 InvisiMole](https://attack.mitre.org/software/S0260) _(+106 more)_  

---

### T1036.006 — Space after Filename
<a id="t1036006"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/006)  

Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Masquerading via Space After Filename - Behavioral Detection Strategy  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  
**Implemented by 1 software:** [S0276 Keydnap](https://attack.mitre.org/software/S0276)  

---

### T1036.007 — Double File Extension
<a id="t1036007"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/007)  

Adversaries may abuse a double extension in the filename as a means of masquerading the true file type. A file name may include a secondary file type extension that may cause only the first extension to be displayed (ex: <code>File.txt.exe</code> may render in some views as just <code>File.txt</code>).

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (6):** `CA-7`, `CM-2`, `CM-6`, `CM-7`, `IA-2`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Double File Extension Masquerading  
**Used by 2 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 3 software:** [S0534 Bazar](https://attack.mitre.org/software/S0534), [S1015 Milan](https://attack.mitre.org/software/S1015), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1036.008 — Masquerade File Type
<a id="t1036008"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/008)  

Adversaries may masquerade malicious payloads as legitimate files through changes to the payload's formatting, including the file’s signature, extension, icon, and contents. Various file types have a typical standard format, including how they are encoded and organized.

**ATT&CK mitigations (3):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (5):** `CM-7`, `SC-7`, `SI-10`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Masquerading via File Type Modification  
**Used by 3 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 11 software:** [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1074 ANDROMEDA](https://attack.mitre.org/software/S1074), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1182 MagicRAT](https://attack.mitre.org/software/S1182), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1190 Kapeka](https://attack.mitre.org/software/S1190), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1238 STATICPLUGIN](https://attack.mitre.org/software/S1238)  

---

### T1036.009 — Break Process Trees
<a id="t1036009"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/009)  

An adversary may attempt to evade process tree-based analysis by modifying executed malware's parent process ID (PPID).

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Masquerading via Breaking Process Trees  
**Implemented by 1 software:** [S1161 BPFDoor](https://attack.mitre.org/software/S1161)  

---

### T1036.010 — Masquerade Account Name
<a id="t1036010"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows, SaaS, IaaS, Containers, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/010)  

Adversaries may match or approximate the names of legitimate accounts to make newly created ones appear benign. This will typically occur during Create Account, although accounts may also be renamed at a later date.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (5):** `AC-2`, `AC-3`, `CM-6`, `IA-2`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Masquerading via Account Name Similarity  
**Used by 4 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  
**Implemented by 2 software:** [S0143 Flame](https://attack.mitre.org/software/S0143), [S0382 ServHelper](https://attack.mitre.org/software/S0382)  

---

### T1036.011 — Overwrite Process Arguments
<a id="t1036011"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/011)  

Adversaries may modify a process's in-memory arguments to change its name in order to appear as a legitimate or benign process. On Linux, the operating system stores command-line arguments in the process’s stack and passes them to the `main()` function as the `argv` array.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Overwritten Process Arguments Masquerading  
**Implemented by 1 software:** [S1161 BPFDoor](https://attack.mitre.org/software/S1161)  

---

### T1036.012 — Browser Fingerprint
<a id="t1036012"></a>

sub-technique of [T1036](/techniques/defense-evasion.md#t1036) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1036/012)  

Adversaries may attempt to blend in with legitimate traffic by spoofing browser and system attributes like operating system, system language, platform, user-agent string, resolution, time zone, etc.

**ATT&CK mitigations (1):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Spoofed User-Agent  
**Implemented by 1 software:** [S0512 FatDuke](https://attack.mitre.org/software/S0512)  

---

### T1055 — Process Injection
<a id="t1055"></a>

**Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055)  

Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1055) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 15 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047)  
**Implemented by 60 software:** [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0040 HTRAN](https://attack.mitre.org/software/S0040), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0176 Wingbird](https://attack.mitre.org/software/S0176), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0206 Wiarp](https://attack.mitre.org/software/S0206), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0247 NavRAT](https://attack.mitre.org/software/S0247), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0347 AuditCred](https://attack.mitre.org/software/S0347), [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0378 PoshC2](https://attack.mitre.org/software/S0378) _(+36 more)_  

---

### T1055.001 — Dynamic-link Library Injection
<a id="t1055001"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/001)  

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of DLL Injection via Windows API  
**Used by 9 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0024 Putter Panda](https://attack.mitre.org/groups/G0024), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G1026 Malteiro](https://attack.mitre.org/groups/G1026)  
**Implemented by 56 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0055 RARSTONE](https://attack.mitre.org/software/S0055), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0135 HIDEDRV](https://attack.mitre.org/software/S0135), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0241 RATANKBA](https://attack.mitre.org/software/S0241), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0273 Socksbot](https://attack.mitre.org/software/S0273), [S0335 Carbon](https://attack.mitre.org/software/S0335) _(+32 more)_  

---

### T1055.002 — Portable Executable Injection
<a id="t1055002"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/002)  

Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of PE Injection via Remote Memory Mapping  
**Used by 2 threat groups:** [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0106 Rocke](https://attack.mitre.org/groups/G0106)  
**Implemented by 10 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0330 Zeus Panda](https://attack.mitre.org/software/S0330), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1138 Gootloader](https://attack.mitre.org/software/S1138), [S1145 Pikabot](https://attack.mitre.org/software/S1145), [S1158 DUSTPAN](https://attack.mitre.org/software/S1158), [S1229 Havoc](https://attack.mitre.org/software/S1229)  

---

### T1055.003 — Thread Execution Hijacking
<a id="t1055003"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/003)  

Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of Thread Execution Hijacking via Thread Suspension and Context Switching  
**Implemented by 4 software:** [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0579 Waterbear](https://attack.mitre.org/software/S0579), [S1145 Pikabot](https://attack.mitre.org/software/S1145)  

---

### T1055.004 — Asynchronous Procedure Call
<a id="t1055004"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/004)  

Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of Asynchronous Procedure Call (APC) Injection via Remote Thread Queuing  
**Used by 1 threat groups:** [G0061 FIN8](https://attack.mitre.org/groups/G0061)  
**Implemented by 11 software:** [S0199 TURNEDUP](https://attack.mitre.org/software/S0199), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0517 Pillowmint](https://attack.mitre.org/software/S0517), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1085 Sardonic](https://attack.mitre.org/software/S1085), [S1207 XLoader](https://attack.mitre.org/software/S1207)  

---

### T1055.005 — Thread Local Storage
<a id="t1055005"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/005)  

Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for TLS Callback Injection via PE Memory Modification and Hollowing  
**Implemented by 2 software:** [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S1237 CANONSTAGER](https://attack.mitre.org/software/S1237)  

---

### T1055.008 — Ptrace System Calls
<a id="t1055008"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/008)  

Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Ptrace-Based Process Injection on Linux  
**Implemented by 1 software:** [S1109 PACEMAKER](https://attack.mitre.org/software/S1109)  

---

### T1055.009 — Proc Memory
<a id="t1055009"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/009)  

Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-6`, `CA-7`, `SC-18`, `SC-7`, `SI-16`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for /proc Memory Injection on Linux  

---

### T1055.011 — Extra Window Memory Injection
<a id="t1055011"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/011)  

Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Extra Window Memory (EWM) Injection on Windows  
**Implemented by 2 software:** [S0091 Epic](https://attack.mitre.org/software/S0091), [S0177 Power Loader](https://attack.mitre.org/software/S0177)  

---

### T1055.012 — Process Hollowing
<a id="t1055012"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/012)  

Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Process Hollowing on Windows  
**Used by 7 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 32 software:** [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0189 ISMInjector](https://attack.mitre.org/software/S0189), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0229 Orz](https://attack.mitre.org/software/S0229), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0344 Azorult](https://attack.mitre.org/software/S0344), [S0354 Denis](https://attack.mitre.org/software/S0354), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0660 Clambling](https://attack.mitre.org/software/S0660), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S0689 WhisperGate](https://attack.mitre.org/software/S0689) _(+8 more)_  

---

### T1055.013 — Process Doppelgänging
<a id="t1055013"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/013)  

Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelgänging is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Process Doppelgänging on Windows  
**Used by 1 threat groups:** [G0077 Leafminer](https://attack.mitre.org/groups/G0077)  
**Implemented by 2 software:** [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0534 Bazar](https://attack.mitre.org/software/S0534)  

---

### T1055.014 — VDSO Hijacking
<a id="t1055014"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/014)  

Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `AC-6`, `SC-18`, `SC-7`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for VDSO Hijacking on Linux  

---

### T1055.015 — ListPlanting
<a id="t1055015"></a>

sub-technique of [T1055](/techniques/defense-evasion.md#t1055) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1055/015)  

Adversaries may abuse list-view controls to inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. ListPlanting is a method of executing arbitrary code in the address space of a separate live process.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (1):** `SI-3`  
**ATT&CK detection strategy:** Detection Strategy for ListPlanting Injection on Windows  
**Implemented by 1 software:** [S0260 InvisiMole](https://attack.mitre.org/software/S0260)  

---

### T1070 — Indicator Removal
<a id="t1070"></a>

**Tactics:** Defense Evasion · **Platforms:** Containers, ESXi, Linux, macOS, Network Devices, Office Suite, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070)  

Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary’s actions.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (20):** `AC-16`, `AC-17`, `AC-18`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CP-6`, `CP-7`, `CP-9`, `SC-36`, `SC-4`, `SI-12`, `SI-23`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Indicator Removal Across Platforms  
**Used by 4 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 25 software:** [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0229 Orz](https://attack.mitre.org/software/S0229), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0448 Rising Sun](https://attack.mitre.org/software/S0448), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0461 SDBbot](https://attack.mitre.org/software/S0461), [S0527 CSPY Downloader](https://attack.mitre.org/software/S0527), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0568 EVILNUM](https://attack.mitre.org/software/S0568), [S0589 Sibot](https://attack.mitre.org/software/S0589), [S0596 ShadowPad](https://attack.mitre.org/software/S0596), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S0691 Neoichor](https://attack.mitre.org/software/S0691), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0695 Donut](https://attack.mitre.org/software/S0695), [S0696 Flagpro](https://attack.mitre.org/software/S0696), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1085 Sardonic](https://attack.mitre.org/software/S1085), [S1132 IPsec Helper](https://attack.mitre.org/software/S1132), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159) _(+1 more)_  

---

### T1070.001 — Clear Windows Event Logs
<a id="t1070001"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/001)  

Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CP-6`, `CP-7`, `CP-9`, `SC-36`, `SC-4`, `SI-12`, `SI-23`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Event Log Clearing on Windows via Behavioral Chain  
**Used by 13 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1040 Play](https://attack.mitre.org/groups/G1040)  
**Implemented by 26 software:** [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0253 RunningRAT](https://attack.mitre.org/software/S0253), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0645 Wevtutil](https://attack.mitre.org/software/S0645), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202) _(+2 more)_  

---

### T1070.002 — Clear Linux or Mac System Logs
<a id="t1070002"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/002)  

Adversaries may clear system logs to hide evidence of an intrusion. macOS and Linux both keep track of system or user-initiated actions via system logs. The majority of native system logging is stored under the <code>/var/log/</code> directory.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CP-6`, `CP-7`, `CP-9`, `SC-36`, `SC-4`, `SI-12`, `SI-23`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Log File Clearing on Linux and macOS  
**Used by 4 threat groups:** [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
**Implemented by 4 software:** [S0279 Proton](https://attack.mitre.org/software/S0279), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1164 UPSTYLE](https://attack.mitre.org/software/S1164), [S1206 JumbledPath](https://attack.mitre.org/software/S1206)  

---

### T1070.003 — Clear Command History
<a id="t1070003"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/003)  

In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1039 Environment Variable Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1039)  
**NIST 800-53 R5 controls (10):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Command History Clearing  
**Used by 8 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 3 software:** [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0641 Kobalos](https://attack.mitre.org/software/S0641), [S1203 J-magic](https://attack.mitre.org/software/S1203)  

---

### T1070.004 — File Deletion
<a id="t1070004"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/004)  

Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary (ex: Ingress Tool Transfer) may leave traces to indicate to what was done within a network and how.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Malicious File Deletion  
**Used by 46 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0043 Group5](https://attack.mitre.org/groups/G0043), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087) _(+22 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 239 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0067 pngdowner](https://attack.mitre.org/software/S0067), [S0069 BLACKCOFFEE](https://attack.mitre.org/software/S0069), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0087 Hi-Zor](https://attack.mitre.org/software/S0087), [S0091 Epic](https://attack.mitre.org/software/S0091), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0106 cmd](https://attack.mitre.org/software/S0106), [S0107 Cherry Picker](https://attack.mitre.org/software/S0107) _(+215 more)_  

---

### T1070.005 — Network Share Connection Removal
<a id="t1070005"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/005)  

Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and SMB/Windows Admin Shares connections can be removed when no longer needed.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavioral Detection of Network Share Connection Removal via CLI and SMB Disconnects  
**Used by 1 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027)  
**Implemented by 4 software:** [S0039 Net](https://attack.mitre.org/software/S0039), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159)  

---

### T1070.006 — Timestomp
<a id="t1070006"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/006)  

Adversaries may modify file time attributes to hide new files or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder and blend malicious files with legitimate files.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Cross-Platform Behavioral Detection of File Timestomping via Metadata Tampering  
**Used by 11 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 42 software:** [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0066 3PARA RAT](https://attack.mitre.org/software/S0066), [S0072 OwaAuth](https://attack.mitre.org/software/S0072), [S0078 Psylo](https://attack.mitre.org/software/S0078), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0136 USBStealer](https://attack.mitre.org/software/S0136), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0150 POSHSPY](https://attack.mitre.org/software/S0150), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0164 TDTESS](https://attack.mitre.org/software/S0164), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0181 FALLCHILL](https://attack.mitre.org/software/S0181), [S0185 SEASHARPEE](https://attack.mitre.org/software/S0185), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0393 PowerStallion](https://attack.mitre.org/software/S0393), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0520 BLINDINGCAN](https://attack.mitre.org/software/S0520) _(+18 more)_  

---

### T1070.007 — Clear Network Connection History and Configurations
<a id="t1070007"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/007)  

Adversaries may clear or remove evidence of malicious network connections in order to clean up traces of their operations.

**ATT&CK mitigations (2):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029)  
**NIST 800-53 R5 controls (10):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Network History and Configuration Tampering  
**Used by 2 threat groups:** [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 1 software:** [S0559 SUNBURST](https://attack.mitre.org/software/S0559)  

---

### T1070.008 — Clear Mailbox Data
<a id="t1070008"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Office Suite, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/008)  

Adversaries may modify mail and mail application data to remove evidence of their activity. Email applications allow users and other programs to export and delete mailbox data via command line tools or use of APIs.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (22):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CP-6`, `CP-7`, `CP-9`, `SC-36`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection of Mailbox Data and Log Deletion for Anti-Forensics  
**Used by 2 threat groups:** [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 2 software:** [S0477 Goopy](https://attack.mitre.org/software/S0477), [S1142 LunarMail](https://attack.mitre.org/software/S1142)  

---

### T1070.009 — Clear Persistence
<a id="t1070009"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/009)  

Adversaries may clear artifacts associated with previously established persistence on a host system to remove evidence of their activity.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1029 Remote Data Storage](../ATTACK_MITIGATIONS_REFERENCE.md#m1029)  
**NIST 800-53 R5 controls (10):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Persistence Artifact Removal Across Host Platforms  
**Implemented by 15 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0500 MCMD](https://attack.mitre.org/software/S0500), [S0517 Pillowmint](https://attack.mitre.org/software/S0517), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0632 GrimAgent](https://attack.mitre.org/software/S0632), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1132 IPsec Helper](https://attack.mitre.org/software/S1132), [S1190 Kapeka](https://attack.mitre.org/software/S1190), [S1232 SplatDropper](https://attack.mitre.org/software/S1232)  

---

### T1070.010 — Relocate Malware
<a id="t1070010"></a>

sub-technique of [T1070](/techniques/defense-evasion.md#t1070) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1070/010)  

Once a payload is delivered, adversaries may reproduce copies of the same malware on the victim system to remove evidence of their presence and/or avoid defenses. Copying malware payloads to new locations may also be combined with File Deletion to cleanup older artifacts.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (3):** `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Malware Relocation via Suspicious File Movement  

---

### T1078 — Valid Accounts
<a id="t1078"></a>

**Tactics:** Defense Evasion, Persistence, Privilege Escalation, Initial Access · **Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, macOS, Network Devices, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1078)  

Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

**ATT&CK mitigations (8):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (25):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-3`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `IA-12`, `IA-13`, `IA-2`, `IA-5`, `RA-5`, `SA-10`, `SA-11`, `SA-15`, `SA-17`, `SA-3`, `SA-4`, `SA-8`, `SC-28`, `SC-43`, `SC-7`, `SI-4`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1078) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 44 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0011 PittyTiger](https://attack.mitre.org/groups/G0011), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0039 Suckfly](https://attack.mitre.org/groups/G0039), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091) _(+20 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 6 software:** [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362), [S0567 Dtrack](https://attack.mitre.org/software/S0567), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0604 Industroyer](https://attack.mitre.org/software/S0604)  

---

### T1078.001 — Default Accounts
<a id="t1078001"></a>

sub-technique of [T1078](/techniques/defense-evasion.md#t1078) · **Tactics:** Defense Evasion, Persistence, Privilege Escalation, Initial Access · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Containers, Network Devices, Office Suite, Identity Provider, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1078/001)  

Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems.

**ATT&CK mitigations (2):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-5`, `AC-6`, `CA-7`, `SA-10`, `SA-11`, `SA-15`, `SA-16`, `SA-17`, `SA-3`, `SA-4`, `SA-8`, `SC-28`, `SI-4`  
**ATT&CK detection strategy:** Detection of Default Account Abuse Across Platforms  
**Used by 4 threat groups:** [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 2 software:** [S0537 HyperStack](https://attack.mitre.org/software/S0537), [S0603 Stuxnet](https://attack.mitre.org/software/S0603)  

---

### T1078.002 — Domain Accounts
<a id="t1078002"></a>

sub-technique of [T1078](/techniques/defense-evasion.md#t1078) · **Tactics:** Defense Evasion, Persistence, Privilege Escalation, Initial Access · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1078/002)  

Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CM-5`, `CM-6`, `IA-12`, `IA-13`, `IA-2`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Abuse of Domain Accounts  
**Used by 18 threat groups:** [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0028 Threat Group-1314](https://attack.mitre.org/groups/G0028), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 5 software:** [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S1024 CreepySnail](https://attack.mitre.org/software/S1024)  

---

### T1078.003 — Local Accounts
<a id="t1078003"></a>

sub-technique of [T1078](/techniques/defense-evasion.md#t1078) · **Tactics:** Defense Evasion, Persistence, Privilege Escalation, Initial Access · **Platforms:** Linux, macOS, Windows, Containers, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1078/003)  

Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (19):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `IA-12`, `IA-2`, `SA-10`, `SA-11`, `SA-15`, `SA-16`, `SA-17`, `SA-3`, `SA-4`, `SA-8`, `SC-28`, `SI-4`  
**ATT&CK detection strategy:** Detection of Local Account Abuse for Initial Access and Persistence  
**Used by 12 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047)  
**Implemented by 5 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0221 Umbreon](https://attack.mitre.org/software/S0221), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202)  

---

### T1078.004 — Cloud Accounts
<a id="t1078004"></a>

sub-technique of [T1078](/techniques/defense-evasion.md#t1078) · **Tactics:** Defense Evasion, Persistence, Privilege Escalation, Initial Access · **Platforms:** IaaS, Identity Provider, Office Suite, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1078/004)  

Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion.

**ATT&CK mitigations (7):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (24):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `IA-12`, `IA-13`, `IA-2`, `IA-5`, `SA-10`, `SA-11`, `SA-15`, `SA-17`, `SA-3`, `SA-4`, `SA-8`, `SC-28`, `SC-43`, `SI-4`  
**ATT&CK detection strategy:** Detection of Abused or Compromised Cloud Accounts for Access and Persistence  
**Used by 9 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 3 software:** [S0683 Peirates](https://attack.mitre.org/software/S0683), [S0684 ROADTools](https://attack.mitre.org/software/S0684), [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1112 — Modify Registry
<a id="t1112"></a>

**Tactics:** Defense Evasion, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1112)  

Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution. Access to specific areas of the Registry depends on account permissions, with some keys requiring administrator-level access.

**ATT&CK mitigations (1):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024)  
**NIST 800-53 R5 controls (3):** `AC-6`, `CM-7`, `SI-7`  
**ATT&CK detection strategy:** Behavior-Based Registry Modification Detection on Windows  
**Used by 29 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014) _(+5 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 136 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0019 Regin](https://attack.mitre.org/software/S0019), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0075 Reg](https://attack.mitre.org/software/S0075), [S0090 Rover](https://attack.mitre.org/software/S0090), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0142 StreamEx](https://attack.mitre.org/software/S0142), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0157 SOUNDBITE](https://attack.mitre.org/software/S0157), [S0158 PHOREAL](https://attack.mitre.org/software/S0158), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0205 Naid](https://attack.mitre.org/software/S0205), [S0210 Nerex](https://attack.mitre.org/software/S0210) _(+112 more)_  

---

### T1127 — Trusted Developer Utilities Proxy Execution
<a id="t1127"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1127)  

Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering.

**ATT&CK mitigations (3):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (8):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavior-chain, platform-aware detection strategy for T1127 Trusted Developer Utilities Proxy Execution (Windows)  

---

### T1127.001 — MSBuild
<a id="t1127001"></a>

sub-technique of [T1127](/techniques/defense-evasion.md#t1127) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1127/001)  

Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It handles XML formatted project files that define requirements for loading and building various platforms and configurations.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (5):** `CM-2`, `CM-6`, `CM-8`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Behavior-chain detection strategy for T1127.001 Trusted Developer Utilities Proxy Execution: MSBuild (Windows)  
**Implemented by 2 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1127.002 — ClickOnce
<a id="t1127002"></a>

sub-technique of [T1127](/techniques/defense-evasion.md#t1127) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1127/002)  

Adversaries may use ClickOnce applications (.appref-ms and .application files) to proxy execution of code through a trusted Windows utility.

**ATT&CK mitigations (3):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045)  
**NIST 800-53 R5 controls (10):** `AC-17`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-18`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavior-chain detection strategy for T1127.002 Trusted Developer Utilities Proxy Execution: ClickOnce (Windows)  

---

### T1127.003 — JamPlus
<a id="t1127003"></a>

sub-technique of [T1127](/techniques/defense-evasion.md#t1127) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1127/003)  

Adversaries may use `JamPlus` to proxy the execution of a malicious script. `JamPlus` is a build utility tool for code and data build systems. It works with several popular compilers and can be used for generating workspaces in code editors such as Visual Studio.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavior-chain detection strategy for T1127.003 Trusted Developer Utilities Proxy Execution: JamPlus (Windows)  

---

### T1134 — Access Token Manipulation
<a id="t1134"></a>

**Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1134)  

Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-13`, `IA-2`  
**ATT&CK detection strategy:** Behavior-chain detection for T1134 Access Token Manipulation on Windows  
**Used by 3 threat groups:** [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108)  
**Implemented by 19 software:** [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0203 Hydraq](https://attack.mitre.org/software/S0203), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0562 SUNSPOT](https://attack.mitre.org/software/S0562), [S0576 MegaCortex](https://attack.mitre.org/software/S0576), [S0607 KillDisk](https://attack.mitre.org/software/S0607), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0625 Cuba](https://attack.mitre.org/software/S0625), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1210 Sagerunex](https://attack.mitre.org/software/S1210), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1134.001 — Token Impersonation/Theft
<a id="t1134001"></a>

sub-technique of [T1134](/techniques/defense-evasion.md#t1134) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1134/001)  

Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls. For example, an adversary can duplicate an existing token using `DuplicateToken` or `DuplicateTokenEx`.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-13`, `IA-2`  
**ATT&CK detection strategy:** Behavior-chain detection for T1134.001 Access Token Manipulation: Token Impersonation/Theft on Windows  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0061 FIN8](https://attack.mitre.org/groups/G0061)  
**Implemented by 15 software:** [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0456 Aria-body](https://attack.mitre.org/software/S0456), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1011 Tarrask](https://attack.mitre.org/software/S1011), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1229 Havoc](https://attack.mitre.org/software/S1229)  

---

### T1134.002 — Create Process with Token
<a id="t1134002"></a>

sub-technique of [T1134](/techniques/defense-evasion.md#t1134) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1134/002)  

Adversaries may create a new process with an existing token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as <code>CreateProcessWithTokenW</code> and <code>runas</code>.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`  
**ATT&CK detection strategy:** Behavior-chain detection for T1134.002 Create Process with Token (Windows)  
**Used by 2 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032)  
**Implemented by 11 software:** [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0344 Azorult](https://attack.mitre.org/software/S0344), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0456 Aria-body](https://attack.mitre.org/software/S0456), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1134.003 — Make and Impersonate Token
<a id="t1134003"></a>

sub-technique of [T1134](/techniques/defense-evasion.md#t1134) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1134/003)  

Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls. For example, if an adversary has a username and password but the user is not logged onto the system the adversary can then create a logon session for the user using the `LogonUser` function.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-13`, `IA-2`  
**ATT&CK detection strategy:** Behavior‑chain detection for T1134.003 Make and Impersonate Token (Windows)  
**Used by 2 threat groups:** [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 3 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1060 Mafalda](https://attack.mitre.org/software/S1060)  

---

### T1134.004 — Parent PID Spoofing
<a id="t1134004"></a>

sub-technique of [T1134](/techniques/defense-evasion.md#t1134) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1134/004)  

Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Behavior-chain detection for T1134.004 Access Token Manipulation: Parent PID Spoofing (Windows)  
**Implemented by 4 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S1111 DarkGate](https://attack.mitre.org/software/S1111)  

---

### T1134.005 — SID-History Injection
<a id="t1134005"></a>

sub-technique of [T1134](/techniques/defense-evasion.md#t1134) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1134/005)  

Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens.

**ATT&CK mitigations (1):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015)  
**NIST 800-53 R5 controls (13):** `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-6`, `IA-13`, `SA-11`, `SA-17`, `SA-4`, `SA-8`, `SC-3`  
**ATT&CK detection strategy:** Behavior-chain detection for T1134.005 Access Token Manipulation: SID-History Injection (Windows)  
**Implemented by 2 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0363 Empire](https://attack.mitre.org/software/S0363)  

---

### T1140 — Deobfuscate/Decode Files or Information
<a id="t1140"></a>

**Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1140)  

Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Adversary Deobfuscation or Decoding of Files and Payloads  
**Used by 38 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0090 WIRTE](https://attack.mitre.org/groups/G0090), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0106 Rocke](https://attack.mitre.org/groups/G0106) _(+14 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 274 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0052 OnionDuke](https://attack.mitre.org/software/S0052), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0127 BBSRAT](https://attack.mitre.org/software/S0127), [S0140 Shamoon](https://attack.mitre.org/software/S0140), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0160 certutil](https://attack.mitre.org/software/S0160), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0188 Starloader](https://attack.mitre.org/software/S0188), [S0189 ISMInjector](https://attack.mitre.org/software/S0189), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0236 Kwampirs](https://attack.mitre.org/software/S0236) _(+250 more)_  

---

### T1197 — BITS Jobs
<a id="t1197"></a>

**Tactics:** Defense Evasion, Persistence · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1197)  

Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM).

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detect abuse of Windows BITS Jobs for download, execution and persistence  
**Used by 5 threat groups:** [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 8 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0190 BITSAdmin](https://attack.mitre.org/software/S0190), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0333 UBoatRAT](https://attack.mitre.org/software/S0333), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0652 MarkiRAT](https://attack.mitre.org/software/S0652), [S0654 ProLock](https://attack.mitre.org/software/S0654)  

---

### T1202 — Indirect Command Execution
<a id="t1202"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1202)  

Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking cmd.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Indirect Command Execution – Windows utility abuse behavior chain  
**Used by 2 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 2 software:** [S0193 Forfiles](https://attack.mitre.org/software/S0193), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379)  

---

### T1205 — Traffic Signaling
<a id="t1205"></a>

**Tactics:** Defense Evasion, Persistence, Command and Control · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1205)  

Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control.

**ATT&CK mitigations (2):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (9):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Traffic Signaling (Port-knock / magic-packet → firewall or service activation) – T1205  
**Used by 3 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 16 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0220 Chaos](https://attack.mitre.org/software/S0220), [S0221 Umbreon](https://attack.mitre.org/software/S0221), [S0430 Winnti for Linux](https://attack.mitre.org/software/S0430), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0519 SYNful Knock](https://attack.mitre.org/software/S0519), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0641 Kobalos](https://attack.mitre.org/software/S0641), [S0664 Pandora](https://attack.mitre.org/software/S0664), [S1114 ZIPLINE](https://attack.mitre.org/software/S1114), [S1118 BUSHWALK](https://attack.mitre.org/software/S1118), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1203 J-magic](https://attack.mitre.org/software/S1203), [S1219 REPTILE](https://attack.mitre.org/software/S1219), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1205.001 — Port Knocking
<a id="t1205001"></a>

sub-technique of [T1205](/techniques/defense-evasion.md#t1205) · **Tactics:** Defense Evasion, Persistence, Command and Control · **Platforms:** Linux, macOS, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1205/001)  

Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Port-knock → rule/daemon change → first successful connect (T1205.001)  
**Used by 2 threat groups:** [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 4 software:** [S1059 metaMain](https://attack.mitre.org/software/S1059), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1204 cd00r](https://attack.mitre.org/software/S1204), [S1219 REPTILE](https://attack.mitre.org/software/S1219)  

---

### T1205.002 — Socket Filters
<a id="t1205002"></a>

sub-technique of [T1205](/techniques/defense-evasion.md#t1205) · **Tactics:** Defense Evasion, Persistence, Command and Control · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1205/002)  

Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (2):** `AC-4`, `SI-4`  
**ATT&CK detection strategy:** Socket-filter trigger → on-host raw-socket activity → reverse connection (T1205.002)  
**Implemented by 4 software:** [S0587 Penquin](https://attack.mitre.org/software/S0587), [S1123 PITSTOP](https://attack.mitre.org/software/S1123), [S1161 BPFDoor](https://attack.mitre.org/software/S1161), [S1224 CASTLETAP](https://attack.mitre.org/software/S1224)  

---

### T1207 — Rogue Domain Controller
<a id="t1207"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1207)  

Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC).

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Rogue Domain Controller (DCShadow) Registration and Replication Abuse  
**Implemented by 1 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002)  

---

### T1211 — Exploitation for Defense Evasion
<a id="t1211"></a>

**Tactics:** Defense Evasion · **Platforms:** Linux, Windows, macOS, SaaS, IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1211)  

Adversaries may exploit a system or application vulnerability to bypass security features. Exploitation of a vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.

**ATT&CK mitigations (4):** [M1019 Threat Intelligence Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1019), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (22):** `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-8`, `RA-10`, `RA-5`, `SC-18`, `SC-2`, `SC-26`, `SC-29`, `SC-3`, `SC-30`, `SC-35`, `SC-39`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-5`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Exploitation for Defense Evasion  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047)  

---

### T1216 — System Script Proxy Execution
<a id="t1216"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1216)  

Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that have been downloaded from Microsoft or are default on Windows installations can be used to proxy execution of other files.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (6):** `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Script-Based Proxy Execution via Signed Microsoft Utilities  

---

### T1216.001 — PubPrn
<a id="t1216001"></a>

sub-technique of [T1216](/techniques/defense-evasion.md#t1216) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1216/001)  

Adversaries may use PubPrn to proxy execution of malicious remote files. PubPrn.vbs is a Visual Basic script that publishes a printer to Active Directory Domain Services. The script may be signed by Microsoft and is commonly executed through the Windows Command Shell via <code>Cscript.exe</code>.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls (6):** `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Remote Script Proxy Execution via PubPrn.vbs  
**Used by 1 threat groups:** [G0050 APT32](https://attack.mitre.org/groups/G0050)  

---

### T1216.002 — SyncAppvPublishingServer
<a id="t1216002"></a>

sub-technique of [T1216](/techniques/defense-evasion.md#t1216) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1216/002)  

Adversaries may abuse SyncAppvPublishingServer.vbs to proxy execution of malicious PowerShell commands. SyncAppvPublishingServer.vbs is a Visual Basic script associated with how Windows virtualizes applications (Microsoft Application Virtualization, or App-V).

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (4):** `CM-2`, `CM-6`, `CM-7`, `SI-7`  
**ATT&CK detection strategy:** Detecting PowerShell Execution via SyncAppvPublishingServer.vbs Proxy Abuse  

---

### T1218 — System Binary Proxy Execution
<a id="t1218"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218)  

Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries.

**ATT&CK mitigations (6):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050)  
**NIST 800-53 R5 controls (20):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-11`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `RA-5`, `SC-7`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Proxy Execution via Trusted Signed Binaries Across Platforms  
**Used by 2 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1218.001 — Compiled HTML File
<a id="t1218001"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/001)  

Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (10):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `SC-18`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Suspicious Compiled HTML File Execution via hh.exe  
**Used by 5 threat groups:** [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0096 APT41](https://attack.mitre.org/groups/G0096)  
**Implemented by 1 software:** [S0373 Astaroth](https://attack.mitre.org/software/S0373)  

---

### T1218.002 — Control Panel
<a id="t1218002"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/002)  

Adversaries may abuse control.exe to proxy execution of malicious payloads. The Windows Control Panel process binary (control.exe) handles execution of Control Panel items, which are utilities that allow users to view and adjust computer settings.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (11):** `AC-3`, `CA-7`, `CM-11`, `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Malicious Control Panel Item Execution via control.exe or Rundll32  
**Implemented by 2 software:** [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0260 InvisiMole](https://attack.mitre.org/software/S0260)  

---

### T1218.003 — CMSTP
<a id="t1218003"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/003)  

Adversaries may abuse CMSTP to proxy execution of malicious code. The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Malicious Profile Installation via CMSTP.exe  
**Used by 2 threat groups:** [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080)  
**Implemented by 2 software:** [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202)  

---

### T1218.004 — InstallUtil
<a id="t1218004"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/004)  

Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Malicious Code Execution via InstallUtil.exe  
**Used by 2 threat groups:** [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 4 software:** [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1155 Covenant](https://attack.mitre.org/software/S1155)  

---

### T1218.005 — Mshta
<a id="t1218005"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/005)  

Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Mshta-based Proxy Execution via Suspicious HTA or Script Invocation  
**Used by 17 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G0142 Confucius](https://attack.mitre.org/groups/G0142), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1018 TA2541](https://attack.mitre.org/groups/G1018)  
**Implemented by 11 software:** [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0228 NanHaiShu](https://attack.mitre.org/software/S0228), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S0414 BabyShark](https://attack.mitre.org/software/S0414), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0589 Sibot](https://attack.mitre.org/software/S0589), [S1155 Covenant](https://attack.mitre.org/software/S1155), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)  

---

### T1218.007 — Msiexec
<a id="t1218007"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/007)  

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi). The Msiexec.exe binary may also be digitally signed by Microsoft.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (9):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`  
**ATT&CK detection strategy:** Detection of Msiexec Abuse for Local, Network, and DLL Execution  
**Used by 6 threat groups:** [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0075 Rancor](https://attack.mitre.org/groups/G0075), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0095 Machete](https://attack.mitre.org/groups/G0095), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128)  
**Implemented by 21 software:** [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0528 Javali](https://attack.mitre.org/software/S0528), [S0530 Melcoz](https://attack.mitre.org/software/S0530), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0592 RemoteUtilities](https://attack.mitre.org/software/S0592), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S1052 DEADEYE](https://attack.mitre.org/software/S1052), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240)  

---

### T1218.008 — Odbcconf
<a id="t1218008"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/008)  

Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads. Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names. The Odbcconf.exe binary may be digitally signed by Microsoft.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Odbcconf Proxy Execution of Malicious DLLs  
**Used by 1 threat groups:** [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080)  
**Implemented by 2 software:** [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130)  

---

### T1218.009 — Regsvcs/Regasm
<a id="t1218009"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/009)  

Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are binaries that may be digitally signed by Microsoft.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting .NET COM Registration Abuse via Regsvcs/Regasm  
**Implemented by 1 software:** [S0331 Agent Tesla](https://attack.mitre.org/software/S0331)  

---

### T1218.010 — Regsvr32
<a id="t1218010"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/010)  

Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. The Regsvr32.exe binary may also be signed by Microsoft.

**ATT&CK mitigations (1):** [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050)  
**NIST 800-53 R5 controls (4):** `CA-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for System Binary Proxy Execution: Regsvr32  
**Used by 11 threat groups:** [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0090 WIRTE](https://attack.mitre.org/groups/G0090), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 23 software:** [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0087 Hi-Zor](https://attack.mitre.org/software/S0087), [S0229 Orz](https://attack.mitre.org/software/S0229), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0284 More_eggs](https://attack.mitre.org/software/S0284), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0384 Dridex](https://attack.mitre.org/software/S0384), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0568 EVILNUM](https://attack.mitre.org/software/S0568), [S0622 AppleSeed](https://attack.mitre.org/software/S0622), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1030 Squirrelwaffle](https://attack.mitre.org/software/S1030), [S1047 Mori](https://attack.mitre.org/software/S1047), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1155 Covenant](https://attack.mitre.org/software/S1155), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1218.011 — Rundll32
<a id="t1218011"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/011)  

Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. Shared Modules), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations.

**ATT&CK mitigations (1):** [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050)  
**NIST 800-53 R5 controls (4):** `CA-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1218.011 Rundll32 Abuse  
**Used by 26 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034), [G1039 RedCurl](https://attack.mitre.org/groups/G1039) _(+2 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 69 software:** [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0082 Emissary](https://attack.mitre.org/software/S0082), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0137 CORESHELL](https://attack.mitre.org/software/S0137), [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0142 StreamEx](https://attack.mitre.org/software/S0142), [S0143 Flame](https://attack.mitre.org/software/S0143), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196), [S0204 Briba](https://attack.mitre.org/software/S0204), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0255 DDKONG](https://attack.mitre.org/software/S0255) _(+45 more)_  

---

### T1218.012 — Verclsid
<a id="t1218012"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/012)  

Adversaries may abuse verclsid.exe to proxy execution of malicious code. Verclsid.exe is known as the Extension CLSID Verification Host and is responsible for verifying each shell extension before they are used by Windows Explorer or the Windows Shell. Adversaries may abuse verclsid.exe to execute malicious payloads.

**ATT&CK mitigations (3):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (16):** `AC-3`, `AC-4`, `CA-7`, `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-7`, `SI-10`, `SI-15`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1218.012 Verclsid Abuse  
**Implemented by 1 software:** [S0499 Hancitor](https://attack.mitre.org/software/S0499)  

---

### T1218.013 — Mavinject
<a id="t1218013"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/013)  

Adversaries may abuse mavinject.exe to proxy execution of malicious code. Mavinject.exe is the Microsoft Application Virtualization Injector, a Windows utility that can inject code into external processes as part of Microsoft Application Virtualization (App-V).

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Code Injection via mavinject.exe (App-V Injector)  
**Implemented by 1 software:** [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1218.014 — MMC
<a id="t1218014"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/014)  

Adversaries may abuse mmc.exe to proxy execution of malicious .msc files. Microsoft Management Console (MMC) is a binary that may be signed by Microsoft and is used in several ways in either its GUI or in a command prompt.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (11):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting MMC (.msc) Proxy Execution and Malicious COM Activation  
**Used by 1 threat groups:** [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  

---

### T1218.015 — Electron Applications
<a id="t1218015"></a>

sub-technique of [T1218](/techniques/defense-evasion.md#t1218) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1218/015)  

Adversaries may abuse components of the Electron framework to execute malicious code. The Electron framework hosts many common applications such as Signal, Slack, and Microsoft Teams.

**ATT&CK mitigations (3):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050)  
**NIST 800-53 R5 controls (18):** `AC-2`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-18`, `SC-34`, `SC-7`, `SI-10`, `SI-15`, `SI-16`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Electron Application Abuse for Proxy Execution  
**Implemented by 1 software:** [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)  

---

### T1220 — XSL Script Processing
<a id="t1220"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1220)  

Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (6):** `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect XSL Script Abuse via msxsl and wmic  
**Used by 2 threat groups:** [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0126 Higaisa](https://attack.mitre.org/groups/G0126)  
**Implemented by 1 software:** [S0373 Astaroth](https://attack.mitre.org/software/S0373)  

---

### T1221 — Template Injection
<a id="t1221"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1221)  

Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts. For example, Microsoft’s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt).

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (14):** `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-44`, `SC-7`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`, `SI-8`  
**ATT&CK detection strategy:** Template Injection Detection - Windows  
**Used by 7 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0079 DarkHydrus](https://attack.mitre.org/groups/G0079), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0142 Confucius](https://attack.mitre.org/groups/G0142)  
**Implemented by 2 software:** [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670)  

---

### T1222 — File and Directory Permissions Modification
<a id="t1222"></a>

**Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1222)  

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (11):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Multi-Platform File and Directory Permissions Modification Detection Strategy  
**Implemented by 1 software:** [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1222.001 — Windows File and Directory Permissions Modification
<a id="t1222001"></a>

sub-technique of [T1222](/techniques/defense-evasion.md#t1222) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1222/001)  

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (11):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Windows DACL Manipulation Behavioral Chain Detection Strategy  
**Used by 2 threat groups:** [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  
**Implemented by 9 software:** [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0446 Ryuk](https://attack.mitre.org/software/S0446), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S0693 CaddyWiper](https://attack.mitre.org/software/S0693), [S1068 BlackCat](https://attack.mitre.org/software/S1068), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180)  

---

### T1222.002 — Linux and Mac File and Directory Permissions Modification
<a id="t1222002"></a>

sub-technique of [T1222](/techniques/defense-evasion.md#t1222) · **Tactics:** Defense Evasion · **Platforms:** macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1222/002)  

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions.

**ATT&CK mitigations (2):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (11):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-5`, `CM-6`, `IA-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Unix-like File Permission Manipulation Behavioral Chain Detection Strategy  
**Used by 3 threat groups:** [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 10 software:** [S0281 Dok](https://attack.mitre.org/software/S0281), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1105 COATHANGER](https://attack.mitre.org/software/S1105)  

---

### T1480 — Execution Guardrails
<a id="t1480"></a>

**Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1480)  

Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary’s campaign.

**ATT&CK mitigations (1):** [M1055 Do Not Mitigate](../ATTACK_MITIGATIONS_REFERENCE.md#m1055)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Multi-Platform Execution Guardrails Environmental Validation Detection Strategy  
**Used by 3 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 33 software:** [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0562 SUNSPOT](https://attack.mitre.org/software/S0562), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0634 EnvyScout](https://attack.mitre.org/software/S0634), [S0635 BoomBox](https://attack.mitre.org/software/S0635), [S0636 VaporRage](https://attack.mitre.org/software/S0636), [S0637 NativeZone](https://attack.mitre.org/software/S0637), [S0678 Torisma](https://attack.mitre.org/software/S0678), [S1035 Small Sieve](https://attack.mitre.org/software/S1035), [S1052 DEADEYE](https://attack.mitre.org/software/S1052), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1133 Apostle](https://attack.mitre.org/software/S1133), [S1143 LunarLoader](https://attack.mitre.org/software/S1143), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150), [S1161 BPFDoor](https://attack.mitre.org/software/S1161), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1179 Exbyte](https://attack.mitre.org/software/S1179), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184), [S1185 LightSpy](https://attack.mitre.org/software/S1185) _(+9 more)_  

---

### T1480.001 — Environmental Keying
<a id="t1480001"></a>

sub-technique of [T1480](/techniques/defense-evasion.md#t1480) · **Tactics:** Defense Evasion · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1480/001)  

Adversaries may environmentally key payloads or other features of malware to evade defenses and constraint execution to a specific target environment.

**ATT&CK mitigations (1):** [M1055 Do Not Mitigate](../ATTACK_MITIGATIONS_REFERENCE.md#m1055)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Environmental Keying Discovery-to-Decryption Behavioral Chain Detection Strategy  
**Used by 2 threat groups:** [G0020 Equation](https://attack.mitre.org/groups/G0020), [G0096 APT41](https://attack.mitre.org/groups/G0096)  
**Implemented by 8 software:** [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0685 PowerPunch](https://attack.mitre.org/software/S0685), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1145 Pikabot](https://attack.mitre.org/software/S1145), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1480.002 — Mutual Exclusion
<a id="t1480002"></a>

sub-technique of [T1480](/techniques/defense-evasion.md#t1480) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1480/002)  

Adversaries may constrain execution or actions based on the presence of a mutex associated with malware. A mutex is a locking mechanism used to synchronize access to a resource. Only one thread or process can acquire a mutex at a given time.

**ATT&CK mitigations (1):** [M1055 Do Not Mitigate](../ATTACK_MITIGATIONS_REFERENCE.md#m1055)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Mutex-Based Execution Guardrails Across Platforms  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  
**Implemented by 15 software:** [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0562 SUNSPOT](https://attack.mitre.org/software/S0562), [S0632 GrimAgent](https://attack.mitre.org/software/S0632), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1161 BPFDoor](https://attack.mitre.org/software/S1161), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1196 Troll Stealer](https://attack.mitre.org/software/S1196), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1236 CLAIMLOADER](https://attack.mitre.org/software/S1236), [S1239 TONESHELL](https://attack.mitre.org/software/S1239), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1484 — Domain or Tenant Policy Modification
<a id="t1484"></a>

**Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1484)  

Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection of Domain or Tenant Policy Modifications via AD and Identity Provider  

---

### T1484.001 — Group Policy Modification
<a id="t1484001"></a>

sub-technique of [T1484](/techniques/defense-evasion.md#t1484) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1484/001)  

Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD).

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Group Policy Modifications via AD Object Changes and File Activity  
**Used by 4 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 8 software:** [S0363 Empire](https://attack.mitre.org/software/S0363), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1058 Prestige](https://attack.mitre.org/software/S1058), [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1484.002 — Trust Modification
<a id="t1484002"></a>

sub-technique of [T1484](/techniques/defense-evasion.md#t1484) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** Identity Provider, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1484/002)  

Adversaries may add new domain trusts, modify the properties of existing domain trusts, or otherwise change the configuration of trust relationships between domains and tenants to evade defenses and/or elevate privileges.Trust details, such as whether or not user identities are federated, allow authentication and autho…

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Trust Relationship Modifications in Domain or Tenant Policies  
**Used by 2 threat groups:** [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1497 — Virtualization/Sandbox Evasion
<a id="t1497"></a>

**Tactics:** Defense Evasion, Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1497)  

Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for T1497 Virtualization/Sandbox Evasion  
**Used by 3 threat groups:** [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 22 software:** [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0147 Pteranodon](https://attack.mitre.org/software/S0147), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0380 StoneDrill](https://attack.mitre.org/software/S0380), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0499 Hancitor](https://attack.mitre.org/software/S0499), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1030 Squirrelwaffle](https://attack.mitre.org/software/S1030), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240)  

---

### T1497.001 — System Checks
<a id="t1497001"></a>

sub-technique of [T1497](/techniques/defense-evasion.md#t1497) · **Tactics:** Defense Evasion, Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1497/001)  

Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Virtualization/Sandbox Evasion via System Checks across Windows, Linux, macOS  
**Used by 5 threat groups:** [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 59 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0182 FinFisher](https://attack.mitre.org/software/S0182), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0242 SynAck](https://attack.mitre.org/software/S0242), [S0248 yty](https://attack.mitre.org/software/S0248), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0264 OopsIE](https://attack.mitre.org/software/S0264), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0333 UBoatRAT](https://attack.mitre.org/software/S0333), [S0337 BadPatch](https://attack.mitre.org/software/S0337), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0354 Denis](https://attack.mitre.org/software/S0354), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0396 EvilBunny](https://attack.mitre.org/software/S0396), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0527 CSPY Downloader](https://attack.mitre.org/software/S0527) _(+35 more)_  

---

### T1497.002 — User Activity Based Checks
<a id="t1497002"></a>

sub-technique of [T1497](/techniques/defense-evasion.md#t1497) · **Tactics:** Defense Evasion, Discovery · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1497/002)  

Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect User Activity Based Sandbox Evasion via Input & Artifact Probing  
**Used by 2 threat groups:** [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0046 FIN7](https://attack.mitre.org/groups/G0046)  
**Implemented by 3 software:** [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0543 Spark](https://attack.mitre.org/software/S0543), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1497.003 — Time Based Checks
<a id="t1497003"></a>

sub-technique of [T1497](/techniques/defense-evasion.md#t1497) · **Tactics:** Defense Evasion, Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1497/003)  

Adversaries may employ various time-based methods to detect virtualization and analysis environments, particularly those that attempt to manipulate time mechanisms to simulate longer elapses of time. This may include enumerating time-based properties, such as uptime or the system clock.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Time-Based Evasion via Sleep, Timer Loops, and Delayed Execution  
**Implemented by 45 software:** [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0396 EvilBunny](https://attack.mitre.org/software/S0396), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0493 GoldenSpy](https://attack.mitre.org/software/S0493), [S0512 FatDuke](https://attack.mitre.org/software/S0512), [S0513 LiteDuke](https://attack.mitre.org/software/S0513), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0561 GuLoader](https://attack.mitre.org/software/S0561), [S0565 Raindrop](https://attack.mitre.org/software/S0565), [S0574 BendyBear](https://attack.mitre.org/software/S0574), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0588 GoldMax](https://attack.mitre.org/software/S0588), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0611 Clop](https://attack.mitre.org/software/S0611), [S0626 P8RAT](https://attack.mitre.org/software/S0626), [S0627 SodaMaster](https://attack.mitre.org/software/S0627), [S0632 GrimAgent](https://attack.mitre.org/software/S0632) _(+21 more)_  

---

### T1535 — Unused/Unsupported Cloud Regions
<a id="t1535"></a>

**Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1535)  

Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.

**ATT&CK mitigations (1):** [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (1):** `SC-23`  
**ATT&CK detection strategy:** Detection of Adversary Use of Unused or Unsupported Cloud Regions (IaaS)  

---

### T1542 — Pre-OS Boot
<a id="t1542"></a>

**Tactics:** Defense Evasion, Persistence · **Platforms:** Linux, Network Devices, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1542)  

Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.

**ATT&CK mitigations (5):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (19):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-8`, `IA-2`, `IA-7`, `IA-8`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SC-7`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1542 Pre-OS Boot  

---

### T1542.004 — ROMMONkit
<a id="t1542004"></a>

sub-technique of [T1542](/techniques/defense-evasion.md#t1542) · **Tactics:** Defense Evasion, Persistence · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1542/004)  

Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect.

**ATT&CK mitigations (3):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (19):** `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-7`, `RA-5`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SC-7`, `SI-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1542.004 Pre-OS Boot: ROMMONkit  

---

### T1542.005 — TFTP Boot
<a id="t1542005"></a>

sub-technique of [T1542](/techniques/defense-evasion.md#t1542) · **Tactics:** Defense Evasion, Persistence · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1542/005)  

Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server.

**ATT&CK mitigations (6):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (23):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-7`, `IA-8`, `RA-5`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SC-7`, `SI-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for T1542.005 Pre-OS Boot: TFTP Boot  

---

### T1550 — Use Alternate Authentication Material
<a id="t1550"></a>

**Tactics:** Defense Evasion, Lateral Movement · **Platforms:** Windows, SaaS, IaaS, Containers, Identity Provider, Office Suite, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1550)  

Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.

**ATT&CK mitigations (7):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for Use Alternate Authentication Material (T1550)  
**Implemented by 1 software:** [S0661 FoggyWeb](https://attack.mitre.org/software/S0661)  

---

### T1550.001 — Application Access Token
<a id="t1550001"></a>

sub-technique of [T1550](/techniques/defense-evasion.md#t1550) · **Tactics:** Defense Evasion, Lateral Movement · **Platforms:** SaaS, Containers, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1550/001)  

Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu of login credentials.

**ATT&CK mitigations (5):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (15):** `AC-16`, `AC-17`, `AC-19`, `AC-20`, `CM-10`, `CM-11`, `CM-2`, `CM-6`, `IA-2`, `IA-4`, `SC-28`, `SC-8`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavioral Detection Strategy for Use Alternate Authentication Material: Application Access Token (T1550.001)  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125)  
**Implemented by 2 software:** [S0683 Peirates](https://attack.mitre.org/software/S0683), [S1023 CreepyDrive](https://attack.mitre.org/software/S1023)  

---

### T1550.002 — Pass the Hash
<a id="t1550002"></a>

sub-technique of [T1550](/techniques/defense-evasion.md#t1550) · **Tactics:** Defense Evasion, Lateral Movement · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1550/002)  

Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1052 User Account Control](../ATTACK_MITIGATIONS_REFERENCE.md#m1052)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `IA-2`, `SI-2`  
**ATT&CK detection strategy:** Detection Strategy for T1550.002 - Pass the Hash (Windows)  
**Used by 11 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1016 FIN13](https://attack.mitre.org/groups/G1016)  
**Implemented by 8 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0122 Pass-The-Hash Toolkit](https://attack.mitre.org/software/S0122), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S1081 BADHATCH](https://attack.mitre.org/software/S1081)  

---

### T1550.003 — Pass the Ticket
<a id="t1550003"></a>

sub-technique of [T1550](/techniques/defense-evasion.md#t1550) · **Tactics:** Defense Evasion, Lateral Movement · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1550/003)  

Adversaries may “pass the ticket” using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password.

**ATT&CK mitigations (4):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1550.003 - Pass the Ticket (Windows)  
**Used by 3 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060)  
**Implemented by 3 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0192 Pupy](https://attack.mitre.org/software/S0192)  

---

### T1550.004 — Web Session Cookie
<a id="t1550004"></a>

sub-technique of [T1550](/techniques/defense-evasion.md#t1550) · **Tactics:** Defense Evasion, Lateral Movement · **Platforms:** SaaS, IaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1550/004)  

Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.

**ATT&CK mitigations (1):** [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (3):** `SC-23`, `SC-8`, `SI-7`  
**ATT&CK detection strategy:** Detect Use of Stolen Web Session Cookies Across Platforms  
**Used by 1 threat groups:** [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033)  

---

### T1553 — Subvert Trust Controls
<a id="t1553"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1553)  

Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust.

**ATT&CK mitigations (5):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (20):** `AC-2`, `AC-3`, `AC-6`, `CM-10`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-7`, `IA-9`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-10`, `SI-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Subversion of Trust Controls via Certificate, Registry, and Attribute Manipulation  
**Used by 1 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001)  

---

### T1553.001 — Gatekeeper Bypass
<a id="t1553001"></a>

sub-technique of [T1553](/techniques/defense-evasion.md#t1553) · **Tactics:** Defense Evasion · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1553/001)  

Adversaries may modify file attributes and subvert Gatekeeper functionality to evade user prompts and execute untrusted programs. Gatekeeper is a set of technologies that act as layer of Apple’s security model to ensure only trusted applications are executed on a host.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (6):** `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Gatekeeper Bypass via Quarantine Flag and Trust Control Manipulation  
**Implemented by 6 software:** [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0369 CoinTicker](https://attack.mitre.org/software/S0369), [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153)  

---

### T1553.002 — Code Signing
<a id="t1553002"></a>

sub-technique of [T1553](/techniques/defense-evasion.md#t1553) · **Tactics:** Defense Evasion · **Platforms:** macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1553/002)  

Adversaries may create, acquire, or steal code signing materials to sign their malware or tools. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Suspicious or Malicious Code Signing Abuse  
**Used by 26 threat groups:** [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0039 Suckfly](https://attack.mitre.org/groups/G0039), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0044 Winnti Group](https://attack.mitre.org/groups/G0044), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031) _(+2 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 52 software:** [S0091 Epic](https://attack.mitre.org/software/S0091), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0163 Janicab](https://attack.mitre.org/software/S0163), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0210 Nerex](https://attack.mitre.org/software/S0210), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0284 More_eggs](https://attack.mitre.org/software/S0284), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0415 BOOSTWRITE](https://attack.mitre.org/software/S0415), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0475 BackConfig](https://attack.mitre.org/software/S0475), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0501 PipeMon](https://attack.mitre.org/software/S0501), [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0520 BLINDINGCAN](https://attack.mitre.org/software/S0520), [S0527 CSPY Downloader](https://attack.mitre.org/software/S0527) _(+28 more)_  

---

### T1553.003 — SIP and Trust Provider Hijacking
<a id="t1553003"></a>

sub-technique of [T1553](/techniques/defense-evasion.md#t1553) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1553/003)  

Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Subvert Trust Controls using SIP and Trust Provider Hijacking.  

---

### T1553.004 — Install Root Certificate
<a id="t1553004"></a>

sub-technique of [T1553](/techniques/defense-evasion.md#t1553) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1553/004)  

Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA).

**ATT&CK mitigations (2):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (6):** `CM-10`, `CM-6`, `CM-7`, `IA-9`, `SC-20`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Subvert Trust Controls via Install Root Certificate.  
**Implemented by 4 software:** [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0160 certutil](https://attack.mitre.org/software/S0160), [S0281 Dok](https://attack.mitre.org/software/S0281)  

---

### T1553.005 — Mark-of-the-Web Bypass
<a id="t1553005"></a>

sub-technique of [T1553](/techniques/defense-evasion.md#t1553) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1553/005)  

Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls. In Windows, when files are downloaded from the Internet, they are tagged with a hidden NTFS Alternate Data Stream (ADS) named <code>Zone.Identifier</code> with a specific value known as the MOTW.

**ATT&CK mitigations (2):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (6):** `CM-2`, `CM-6`, `CM-7`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Mark-of-the-Web (MOTW) Bypass via Container and Disk Image Files  
**Used by 3 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092)  
**Implemented by 2 software:** [S0650 QakBot](https://attack.mitre.org/software/S0650), [S1025 Amadey](https://attack.mitre.org/software/S1025)  

---

### T1553.006 — Code Signing Policy Modification
<a id="t1553006"></a>

sub-technique of [T1553](/techniques/defense-evasion.md#t1553) · **Tactics:** Defense Evasion · **Platforms:** Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1553/006)  

Adversaries may modify code signing policies to enable execution of unsigned or self-signed code. Code signing provides a level of authenticity on a program from a developer and a guarantee that the program has not been tampered with.

**ATT&CK mitigations (3):** [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
**NIST 800-53 R5 controls (13):** `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-7`, `CM-8`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-7`  
**ATT&CK detection strategy:** Detect Code Signing Policy Modification (Windows & macOS)  
**Used by 2 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0087 APT39](https://attack.mitre.org/groups/G0087)  
**Implemented by 3 software:** [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0664 Pandora](https://attack.mitre.org/software/S0664)  

---

### T1562 — Impair Defenses
<a id="t1562"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows, IaaS, Linux, macOS, Containers, Network Devices, Identity Provider, Office Suite, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562)  

Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior.

**ATT&CK mitigations (7):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (16):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `RA-5`, `SC-8`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Impair Defenses Across Platforms  
**Used by 2 threat groups:** [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G1043 BlackByte](https://attack.mitre.org/groups/G1043)  
**Implemented by 3 software:** [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184), [S1206 JumbledPath](https://attack.mitre.org/software/S1206)  

---

### T1562.001 — Disable or Modify Tools
<a id="t1562001"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** Containers, IaaS, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/001)  

Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.

**ATT&CK mitigations (5):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Impair Defenses through Disabled or Modified Tools across OS Platforms.  
**Used by 30 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0024 Putter Panda](https://attack.mitre.org/groups/G0024), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032) _(+6 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 71 software:** [S0004 TinyZBot](https://attack.mitre.org/software/S0004), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0061 HDoor](https://attack.mitre.org/software/S0061), [S0130 Unknown Logger](https://attack.mitre.org/software/S0130), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0228 NanHaiShu](https://attack.mitre.org/software/S0228), [S0249 Gold Dragon](https://attack.mitre.org/software/S0249), [S0252 Brave Prince](https://attack.mitre.org/software/S0252), [S0253 RunningRAT](https://attack.mitre.org/software/S0253), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0372 LockerGoga](https://attack.mitre.org/software/S0372), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0400 RobbinHood](https://attack.mitre.org/software/S0400), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0446 Ryuk](https://attack.mitre.org/software/S0446) _(+47 more)_  

---

### T1562.002 — Disable Windows Event Logging
<a id="t1562002"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/002)  

Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more. This data is used by security tools and analysts to generate detections.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect disabled Windows event logging  
**Used by 2 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059)  
**Implemented by 1 software:** [S0645 Wevtutil](https://attack.mitre.org/software/S0645)  

---

### T1562.003 — Impair Command History Logging
<a id="t1562003"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/003)  

Adversaries may impair command history logging to hide commands they run on a compromised system. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.

**ATT&CK mitigations (2):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1039 Environment Variable Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1039)  
**NIST 800-53 R5 controls (4):** `CM-2`, `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Impair Defenses via Impair Command History Logging across OS platforms.  
**Used by 4 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 4 software:** [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1161 BPFDoor](https://attack.mitre.org/software/S1161), [S1186 Line Dancer](https://attack.mitre.org/software/S1186), [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217)  

---

### T1562.004 — Disable or Modify System Firewall
<a id="t1562004"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/004)  

Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1024 Restrict Registry Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1024), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of Disabled or Modified System Firewalls across OS Platforms.  
**Used by 17 threat groups:** [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 24 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0088 Kasidet](https://attack.mitre.org/software/S0088), [S0108 netsh](https://attack.mitre.org/software/S0108), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0245 BADCALL](https://attack.mitre.org/software/S0245), [S0246 HARDRAIN](https://attack.mitre.org/software/S0246), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0334 DarkComet](https://attack.mitre.org/software/S0334), [S0336 NanoCore](https://attack.mitre.org/software/S0336), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687), [S1032 PyDCrypt](https://attack.mitre.org/software/S1032), [S1161 BPFDoor](https://attack.mitre.org/software/S1161), [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178), [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181), [S1211 Hannotog](https://attack.mitre.org/software/S1211), [S1223 THINCRUST](https://attack.mitre.org/software/S1223)  

---

### T1562.006 — Indicator Blocking
<a id="t1562006"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** Windows, macOS, Linux, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/006)  

An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting or even disabling host-based sensors, such as Event Tracing for Windows (ETW), by tampering settings that control the collection and flow of event telemetry.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (17):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-10`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-9`, `SC-23`, `SC-8`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Impair Defenses Indicator Blocking  
**Used by 2 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1023 APT5](https://attack.mitre.org/groups/G1023)  
**Implemented by 8 software:** [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0579 Waterbear](https://attack.mitre.org/software/S0579), [S0697 HermeticWiper](https://attack.mitre.org/software/S0697), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1065 Woody RAT](https://attack.mitre.org/software/S1065), [S1097 HUI Loader](https://attack.mitre.org/software/S1097), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184), [S1200 StealBit](https://attack.mitre.org/software/S1200)  

---

### T1562.007 — Disable or Modify Cloud Firewall
<a id="t1562007"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/007)  

Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources. Cloud firewalls are separate from system firewalls that are described in Disable or Modify System Firewall.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (6):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection Strategy for Disable or Modify Cloud Firewall  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1562.008 — Disable or Modify Cloud Logs
<a id="t1562008"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** IaaS, SaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/008)  

An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. Cloud environments allow for collection and analysis of audit and application logs that provide insight into what activities a user does within the environment.

**ATT&CK mitigations (1):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-3`, `CM-5`, `IA-2`  
**ATT&CK detection strategy:** Detection Strategy for Disable or Modify Cloud Logs  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1562.009 — Safe Mode Boot
<a id="t1562009"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/009)  

Adversaries may abuse Windows safe mode to disable endpoint defenses. Safe mode starts up the Windows operating system with a limited set of drivers and services. Third-party security software such as endpoint detection and response (EDR) tools may not start after booting Windows in safe mode.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (13):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-10`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-9`, `SC-23`, `SC-8`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Safe Mode Boot Abuse  
**Implemented by 7 software:** [S0496 REvil](https://attack.mitre.org/software/S0496), [S1053 AvosLocker](https://attack.mitre.org/software/S1053), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1212 RansomHub](https://attack.mitre.org/software/S1212), [S1242 Qilin](https://attack.mitre.org/software/S1242), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1562.010 — Downgrade Attack
<a id="t1562010"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/010)  

Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls. Downgrade attacks typically take advantage of a system’s backward compatibility to force it into less secure modes of operation.

**ATT&CK mitigations (2):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (7):** `CM-2`, `CM-6`, `CM-7`, `RA-5`, `SC-8`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detecting Downgrade Attacks  
**Implemented by 2 software:** [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180)  

---

### T1562.011 — Spoof Security Alerting
<a id="t1562011"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/011)  

Adversaries may spoof security alerting from tools, presenting false evidence to impair defenders’ awareness of malicious activity. Messages produced by defensive tools contain information about potential security events as well as the functioning status of security software and the system.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (5):** `CM-5`, `CM-6`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection for Spoofing Security Alerting across OS Platforms  

---

### T1562.012 — Disable or Modify Linux Audit System
<a id="t1562012"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/012)  

Adversaries may disable or modify the Linux audit system to hide malicious activity and avoid detection. Linux admins use the Linux Audit system to track security-relevant information on a system.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `AC-6`, `CM-3`, `CM-5`, `CM-6`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Disable or Modify Linux Audit System  
**Implemented by 1 software:** [S0377 Ebury](https://attack.mitre.org/software/S0377)  

---

### T1562.013 — Disable or Modify Network Device Firewall
<a id="t1562013"></a>

sub-technique of [T1562](/techniques/defense-evasion.md#t1562) · **Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1562/013)  

Adversaries may disable network device-based firewall mechanisms entirely or add, delete, or modify particular rules in order to bypass controls limiting network usage.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Unauthorized Network Firewall Rule Modification (T1562.013)  
**Used by 1 threat groups:** [G0082 APT38](https://attack.mitre.org/groups/G0082)  
**Implemented by 1 software:** [S0531 Grandoreiro](https://attack.mitre.org/software/S0531)  

---

### T1564 — Hide Artifacts
<a id="t1564"></a>

**Tactics:** Defense Evasion · **Platforms:** Linux, Office Suite, Windows, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564)  

Adversaries may attempt to hide artifacts associated with their behaviors to evade detection.

**ATT&CK mitigations (4):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Hidden Artifacts Across Platforms  
**Implemented by 5 software:** [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S1011 Tarrask](https://attack.mitre.org/software/S1011), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066)  

---

### T1564.001 — Hidden Files and Directories
<a id="t1564001"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/001)  

Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Hidden Files and Directories  
**Used by 12 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 45 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0162 Komplex](https://attack.mitre.org/software/S0162), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0277 FruitFly](https://attack.mitre.org/software/S0277), [S0278 iKitten](https://attack.mitre.org/software/S0278), [S0282 MacSpy](https://attack.mitre.org/software/S0282), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0339 Micropsia](https://attack.mitre.org/software/S0339), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0369 CoinTicker](https://attack.mitre.org/software/S0369), [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0448 Rising Sun](https://attack.mitre.org/software/S0448), [S0451 LoudMiner](https://attack.mitre.org/software/S0451) _(+21 more)_  

---

### T1564.002 — Hidden Users
<a id="t1564002"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** macOS, Windows, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/002)  

Adversaries may use hidden users to hide the presence of user accounts they create or modify. Administrators may want to hide users when there are many user accounts on a given system or if they want to hide their administrative or other management accounts from other users.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (3):** `CM-6`, `CM-7`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Hidden User Accounts  
**Used by 2 threat groups:** [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  
**Implemented by 1 software:** [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649)  

---

### T1564.003 — Hidden Window
<a id="t1564003"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/003)  

Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden.

**ATT&CK mitigations (2):** [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls (3):** `CM-7`, `SI-10`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hidden Windows  
**Used by 16 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0009 Deep Panda](https://attack.mitre.org/groups/G0009), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0079 DarkHydrus](https://attack.mitre.org/groups/G0079), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0133 Nomadic Octopus](https://attack.mitre.org/groups/G0133), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 38 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0037 HAMMERTOSS](https://attack.mitre.org/software/S0037), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0360 BONDUPDATER](https://attack.mitre.org/software/S0360), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0431 HotCroissant](https://attack.mitre.org/software/S0431), [S0437 Kivars](https://attack.mitre.org/software/S0437), [S0441 PowerShower](https://attack.mitre.org/software/S0441), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0466 WindTail](https://attack.mitre.org/software/S0466), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0500 MCMD](https://attack.mitre.org/software/S0500), [S0625 Cuba](https://attack.mitre.org/software/S0625), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0686 QuietSieve](https://attack.mitre.org/software/S0686), [S0688 Meteor](https://attack.mitre.org/software/S0688), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692) _(+14 more)_  

---

### T1564.004 — NTFS File Attributes
<a id="t1564004"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/004)  

Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition.

**ATT&CK mitigations (1):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022)  
**NIST 800-53 R5 controls (6):** `AC-16`, `AC-3`, `CA-7`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for NTFS File Attribute Abuse (ADS/EAs)  
**Used by 1 threat groups:** [G0050 APT32](https://attack.mitre.org/groups/G0050)  
**Implemented by 15 software:** [S0019 Regin](https://attack.mitre.org/software/S0019), [S0027 Zeroaccess](https://attack.mitre.org/software/S0027), [S0139 PowerDuke](https://attack.mitre.org/software/S0139), [S0145 POWERSOURCE](https://attack.mitre.org/software/S0145), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0361 Expand](https://attack.mitre.org/software/S0361), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0397 LoJax](https://attack.mitre.org/software/S0397), [S0404 esentutl](https://attack.mitre.org/software/S0404), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0570 BitPaymer](https://attack.mitre.org/software/S0570), [S0612 WastedLocker](https://attack.mitre.org/software/S0612), [S1052 DEADEYE](https://attack.mitre.org/software/S1052), [S1160 Latrodectus](https://attack.mitre.org/software/S1160)  

---

### T1564.005 — Hidden File System
<a id="t1564005"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/005)  

Adversaries may use a hidden file system to conceal malicious activity from users and security tools. File systems provide a structure to store and access data from physical storage.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Hidden File System Abuse  
**Used by 2 threat groups:** [G0020 Equation](https://attack.mitre.org/groups/G0020), [G0041 Strider](https://attack.mitre.org/groups/G0041)  
**Implemented by 4 software:** [S0019 Regin](https://attack.mitre.org/software/S0019), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0114 BOOTRASH](https://attack.mitre.org/software/S0114), [S0126 ComRAT](https://attack.mitre.org/software/S0126)  

---

### T1564.006 — Run Virtual Instance
<a id="t1564006"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/006)  

Adversaries may carry out malicious operations using a virtual instance to avoid detection. A wide variety of virtualization technologies exist that allow for the emulation of a computer or computing environment.

**ATT&CK mitigations (3):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (7):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SI-10`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Hidden Virtual Instance Execution  
**Implemented by 3 software:** [S0449 Maze](https://attack.mitre.org/software/S0449), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481)  

---

### T1564.007 — VBA Stomping
<a id="t1564007"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/007)  

Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data. MS Office documents with embedded VBA content store source code inside of module streams.

**ATT&CK mitigations (1):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (4):** `CM-2`, `CM-6`, `CM-8`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for VBA Stomping  

---

### T1564.008 — Email Hiding Rules
<a id="t1564008"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Windows, Linux, macOS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/008)  

Adversaries may use email rules to hide inbound emails in a compromised user's mailbox. Many email clients allow users to create inbox rules for various email functions, including moving emails to other folders, marking emails as read, or deleting emails.

**ATT&CK mitigations (1):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CM-3`, `CM-5`, `CM-7`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Email Hiding Rules  
**Used by 2 threat groups:** [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1564.009 — Resource Forking
<a id="t1564009"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/009)  

Adversaries may abuse resource forks to hide malicious code or executables to evade detection and bypass security applications. A resource fork provides applications a structured way to store resources such as thumbnail images, menu definitions, icons, dialog boxes, and code.

**ATT&CK mitigations (1):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013)  
**NIST 800-53 R5 controls (13):** `CM-11`, `CM-2`, `CM-6`, `CM-7`, `SA-10`, `SC-4`, `SC-44`, `SC-6`, `SI-10`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Resource Forking on macOS  
**Implemented by 2 software:** [S0276 Keydnap](https://attack.mitre.org/software/S0276), [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402)  

---

### T1564.010 — Process Argument Spoofing
<a id="t1564010"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/010)  

Adversaries may attempt to hide process command-line arguments by overwriting process memory. Process command-line arguments are stored in the process environment block (PEB), a data structure used by Windows to store various information about/used by a process.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (3):** `CA-7`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Process Argument Spoofing on Windows  
**Implemented by 2 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0615 SombRAT](https://attack.mitre.org/software/S0615)  

---

### T1564.011 — Ignore Process Interrupts
<a id="t1564011"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/011)  

Adversaries may evade defensive mechanisms by executing commands that hide from process interrupt signals. Many operating systems use signals to deliver messages to control process behavior.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Ignore Process Interrupts  
**Used by 2 threat groups:** [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 4 software:** [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402), [S0588 GoldMax](https://attack.mitre.org/software/S0588), [S1161 BPFDoor](https://attack.mitre.org/software/S1161), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184)  

---

### T1564.012 — File/Path Exclusions
<a id="t1564012"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/012)  

Adversaries may attempt to hide their file-based artifacts by writing them to specific folders or file names excluded from antivirus (AV) scanning and other defensive capabilities.

**ATT&CK mitigations (2):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (1):** `SI-3`  
**ATT&CK detection strategy:** Detection Strategy for File/Path Exclusions  
**Used by 1 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010)  

---

### T1564.013 — Bind Mounts
<a id="t1564013"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/013)  

Adversaries may abuse bind mounts on file structures to hide their activity and artifacts from native utilities. A bind mount maps a directory or file from one location on the filesystem to another, similar to a shortcut on Windows.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Bind Mounts on Linux  

---

### T1564.014 — Extended Attributes
<a id="t1564014"></a>

sub-technique of [T1564](/techniques/defense-evasion.md#t1564) · **Tactics:** Defense Evasion · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1564/014)  

Adversaries may abuse extended attributes (xattrs) on macOS and Linux to hide their malicious data in order to evade detection. Extended attributes are key-value pairs of file and directory metadata used by both macOS and Linux.

**ATT&CK mitigations (1):** [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Extended Attributes Abuse  

---

### T1578 — Modify Cloud Compute Infrastructure
<a id="t1578"></a>

**Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1578)  

An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Modify Cloud Compute Infrastructure  

---

### T1578.001 — Create Snapshot
<a id="t1578001"></a>

sub-technique of [T1578](/techniques/defense-evasion.md#t1578) · **Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1578/001)  

An adversary may create a snapshot or data backup within a cloud account to evade defenses. A snapshot is a point-in-time copy of an existing cloud compute component such as a virtual machine (VM), virtual hard drive, or volume.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Modify Cloud Compute Infrastructure: Create Snapshot  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1578.002 — Create Cloud Instance
<a id="t1578002"></a>

sub-technique of [T1578](/techniques/defense-evasion.md#t1578) · **Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1578/002)  

An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses. Creating a new instance may allow an adversary to bypass firewall rules and permissions that exist on instances currently residing within an account.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Modify Cloud Compute Infrastructure: Create Cloud Instance  
**Used by 2 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1578.003 — Delete Cloud Instance
<a id="t1578003"></a>

sub-technique of [T1578](/techniques/defense-evasion.md#t1578) · **Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1578/003)  

An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence. Deleting an instance or virtual machine can remove valuable forensic artifacts and other evidence of suspicious behavior if the instance is not recoverable.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (11):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `IA-2`, `IA-4`, `IA-6`, `RA-5`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Modify Cloud Compute Infrastructure: Delete Cloud Instance  
**Used by 2 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1578.004 — Revert Cloud Instance
<a id="t1578004"></a>

sub-technique of [T1578](/techniques/defense-evasion.md#t1578) · **Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1578/004)  

An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Modify Cloud Compute Infrastructure: Revert Cloud Instance  

---

### T1578.005 — Modify Cloud Compute Configurations
<a id="t1578005"></a>

sub-technique of [T1578](/techniques/defense-evasion.md#t1578) · **Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1578/005)  

Adversaries may modify settings that directly affect the size, locations, and resources available to cloud compute infrastructure in order to evade defenses. These settings may include service quotas, subscription associations, tenant-wide policies, or other configurations that impact available compute.

**ATT&CK mitigations (2):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (5):** `AC-2`, `AC-20`, `AC-3`, `AC-6`, `CM-3`  
**ATT&CK detection strategy:** Detection Strategy for Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations  

---

### T1599 — Network Boundary Bridging
<a id="t1599"></a>

**Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1599)  

Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.

**ATT&CK mitigations (5):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043)  
**NIST 800-53 R5 controls (18):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-7`, `SI-10`, `SI-15`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Network Boundary Bridging  
**Used by 1 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096)  

---

### T1599.001 — Network Address Translation Traversal
<a id="t1599001"></a>

sub-technique of [T1599](/techniques/defense-evasion.md#t1599) · **Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1599/001)  

Adversaries may bridge network boundaries by modifying a network device’s Network Address Translation (NAT) configuration. Malicious modifications to NAT may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.

**ATT&CK mitigations (5):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043)  
**NIST 800-53 R5 controls (18):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-7`, `SI-10`, `SI-15`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Network Address Translation Traversal  

---

### T1600 — Weaken Encryption
<a id="t1600"></a>

**Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1600)  

Adversaries may compromise a network device’s encryption capability in order to bypass encryption that would otherwise protect data communications.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Weaken Encryption on Network Devices  

---

### T1600.001 — Reduce Key Space
<a id="t1600001"></a>

sub-technique of [T1600](/techniques/defense-evasion.md#t1600) · **Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1600/001)  

Adversaries may reduce the level of effort required to decrypt data transmitted over the network by reducing the cipher strength of encrypted communications.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Weaken Encryption: Reduce Key Space on Network Devices  

---

### T1600.002 — Disable Crypto Hardware
<a id="t1600002"></a>

sub-technique of [T1600](/techniques/defense-evasion.md#t1600) · **Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1600/002)  

Adversaries disable a network device’s dedicated hardware encryption, which may enable them to leverage weaknesses in software encryption in order to reduce the effort involved in collecting, manipulating, and exfiltrating transmitted data.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Weaken Encryption: Disable Crypto Hardware on Network Devices  

---

### T1601 — Modify System Image
<a id="t1601"></a>

**Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1601)  

Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves. On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.

**ATT&CK mitigations (6):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
**NIST 800-53 R5 controls (24):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for Modify System Image on Network Devices  

---

### T1601.001 — Patch System Image
<a id="t1601001"></a>

sub-technique of [T1601](/techniques/defense-evasion.md#t1601) · **Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1601/001)  

Adversaries may modify the operating system of a network device to introduce new capabilities or weaken existing defenses. Some network devices are built with a monolithic architecture, where the entire operating system and most of the functionality of the device is contained within a single file.

**ATT&CK mitigations (6):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
**NIST 800-53 R5 controls (24):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for Patch System Image on Network Devices  
**Implemented by 1 software:** [S0519 SYNful Knock](https://attack.mitre.org/software/S0519)  

---

### T1601.002 — Downgrade System Image
<a id="t1601002"></a>

sub-technique of [T1601](/techniques/defense-evasion.md#t1601) · **Tactics:** Defense Evasion · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1601/002)  

Adversaries may install an older version of the operating system of a network device to weaken security. Older operating system versions on network devices often have weaker encryption ciphers and, in general, fewer/less updated defensive features.

**ATT&CK mitigations (6):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1045 Code Signing](../ATTACK_MITIGATIONS_REFERENCE.md#m1045), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
**NIST 800-53 R5 controls (24):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-5`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Detection Strategy for Downgrade System Image on Network Devices  

---

### T1610 — Deploy Container
<a id="t1610"></a>

**Tactics:** Defense Evasion, Execution · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1610)  

Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (9):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CM-6`, `CM-7`, `IA-2`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Behavior-chain detection for T1610 Deploy Container across Docker & Kubernetes control/node planes  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 3 software:** [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0600 Doki](https://attack.mitre.org/software/S0600), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1612 — Build Image on Host
<a id="t1612"></a>

**Tactics:** Defense Evasion · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1612)  

Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry.

**ATT&CK mitigations (4):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (11):** `AC-17`, `AC-2`, `AC-3`, `AC-6`, `CM-2`, `CM-6`, `CM-7`, `RA-5`, `SA-11`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Build Image on Host  

---

### T1620 — Reflective Code Loading
<a id="t1620"></a>

**Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1620)  

Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads. Reflective loading involves allocating then executing payloads directly within the memory of the process, vice creating a thread or process backed by a file path on disk (e.g., Shared Modules).

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Reflective Code Loading  
**Used by 4 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  
**Implemented by 22 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0625 Cuba](https://attack.mitre.org/software/S0625), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S0695 Donut](https://attack.mitre.org/software/S0695), [S1022 IceApple](https://attack.mitre.org/software/S1022), [S1059 metaMain](https://attack.mitre.org/software/S1059), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1085 Sardonic](https://attack.mitre.org/software/S1085), [S1143 LunarLoader](https://attack.mitre.org/software/S1143), [S1145 Pikabot](https://attack.mitre.org/software/S1145), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)  

---

### T1622 — Debugger Evasion
<a id="t1622"></a>

**Tactics:** Defense Evasion, Discovery · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1622)  

Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (15):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-23`, `SC-46`, `SC-7`, `SC-8`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Debugger Evasion (T1622)  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 21 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0595 ThiefQuest](https://attack.mitre.org/software/S0595), [S0694 DRATzarus](https://attack.mitre.org/software/S0694), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066), [S1070 Black Basta](https://attack.mitre.org/software/S1070), [S1087 AsyncRAT](https://attack.mitre.org/software/S1087), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1145 Pikabot](https://attack.mitre.org/software/S1145), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183), [S1200 StealBit](https://attack.mitre.org/software/S1200), [S1202 LockBit 3.0](https://attack.mitre.org/software/S1202), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1647 — Plist File Modification
<a id="t1647"></a>

**Tactics:** Defense Evasion · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1647)  

Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses.

**ATT&CK mitigations (1):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013)  
**NIST 800-53 R5 controls (15):** `AC-16`, `AC-17`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `SA-10`, `SA-11`, `SA-8`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Plist File Modification (T1647)  
**Implemented by 2 software:** [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153)  

---

### T1656 — Impersonation
<a id="t1656"></a>

**Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1656)  

Adversaries may impersonate a trusted person or organization in order to persuade and trick a target into performing some action on their behalf.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1019 Threat Intelligence Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1019)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Impersonation  
**Used by 8 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 1 software:** [S1131 NPPSPY](https://attack.mitre.org/software/S1131)  

---

### T1666 — Modify Cloud Resource Hierarchy
<a id="t1666"></a>

**Tactics:** Defense Evasion · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1666)  

Adversaries may attempt to modify hierarchical structures in infrastructure-as-a-service (IaaS) environments in order to evade defenses. IaaS environments often group resources into a hierarchy, enabling improved resource management and application of policies to relevant groups.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (1):** `CM-3`  
**ATT&CK detection strategy:** Detection Strategy for Modify Cloud Resource Hierarchy  

---

### T1672 — Email Spoofing
<a id="t1672"></a>

**Tactics:** Defense Evasion · **Platforms:** Office Suite, Windows, macOS, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1672)  

Adversaries may fake, or spoof, a sender’s identity by modifying the value of relevant email headers in order to establish contact with victims under false pretenses. In addition to actual email content, email headers (such as the FROM header, which contains the email address of the sender) may also be modified.

**ATT&CK mitigations (1):** [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Email Spoofing  

---

### T1678 — Delay Execution
<a id="t1678"></a>

**Tactics:** Defense Evasion · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1678)  

Adversaries may employ various time-based methods to evade detection and analysis. These techniques often exploit system clocks, delays, or timing mechanisms to obscure malicious activity, blend in with benign activity, and avoid scrutiny.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Multi-Platform Detection Strategy for T1678 - Delay Execution  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 2 software:** [S1230 HIUPAN](https://attack.mitre.org/software/S1230), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1679 — Selective Exclusion
<a id="t1679"></a>

**Tactics:** Defense Evasion · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1679)  

Adversaries may intentionally exclude certain files, folders, directories, file types, or system components from encryption or tampering during a ransomware or malicious payload execution. Some file extensions that adversaries may avoid encrypting include `.dll`, `.exe`, and `.lnk`.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Selective Exclusion  
**Implemented by 3 software:** [S1244 Medusa Ransomware](https://attack.mitre.org/software/S1244), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245), [S1247 Embargo](https://attack.mitre.org/software/S1247)  

---

### T1548.006 — TCC Manipulation
<a id="t1548006"></a>

sub-technique of [T1548](/techniques/privilege-escalation.md#t1548) · **Tactics:** Defense Evasion, Privilege Escalation · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1548/006)  

Adversaries can manipulate or abuse the Transparency, Consent, & Control (TCC) service or database to grant malicious executables elevated permissions.

**ATT&CK mitigations (3):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (17):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** TCC Database Manipulation via Launchctl and Unprotected SIP  
**Implemented by 1 software:** [S0658 XCSSET](https://attack.mitre.org/software/S0658)  

---

