# Command and Control — Technique Detail

> Full detail pages for the **41 ATT&CK techniques** whose primary tactic is [Command and Control](https://attack.mitre.org/tactics/TA0011/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1001 — Data Obfuscation
<a id="t1001"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1001)  

Adversaries may obfuscate command and control traffic to make it more difficult to detect.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect Obfuscated C2 via Network Traffic Analysis  
**Used by 1 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047)  
**Implemented by 11 software:** [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S0533 SLOTHFULMEDIA](https://attack.mitre.org/software/S0533), [S0610 SideTwist](https://attack.mitre.org/software/S0610), [S0682 TrailBlazer](https://attack.mitre.org/software/S0682), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1120 FRAMESTING](https://attack.mitre.org/software/S1120), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183)  

---

### T1001.001 — Junk Data
<a id="t1001001"></a>

sub-technique of [T1001](/techniques/command-and-control.md#t1001) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1001/001)  

Adversaries may add junk data to protocols used for command and control to make detection more difficult. By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detecting Junk Data in C2 Channels via Behavioral Analysis  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  
**Implemented by 16 software:** [S0016 P2P ZeuS](https://attack.mitre.org/software/S0016), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0134 Downdelph](https://attack.mitre.org/software/S0134), [S0435 PLEAD](https://attack.mitre.org/software/S0435), [S0514 WellMess](https://attack.mitre.org/software/S0514), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0574 BendyBear](https://attack.mitre.org/software/S0574), [S0588 GoldMax](https://attack.mitre.org/software/S0588), [S0626 P8RAT](https://attack.mitre.org/software/S0626), [S0632 GrimAgent](https://attack.mitre.org/software/S0632), [S0647 Turian](https://attack.mitre.org/software/S0647), [S0682 TrailBlazer](https://attack.mitre.org/software/S0682), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1047 Mori](https://attack.mitre.org/software/S1047), [S1164 UPSTYLE](https://attack.mitre.org/software/S1164), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1001.002 — Steganography
<a id="t1001002"></a>

sub-technique of [T1001](/techniques/command-and-control.md#t1001) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1001/002)  

Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult. Steganographic techniques can be used to hide data in digital messages that are transferred between systems. This hidden information can be used for command and control of compromised systems.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detecting Steganographic Command and Control via File + Network Correlation  
**Used by 1 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001)  
**Implemented by 11 software:** [S0037 HAMMERTOSS](https://attack.mitre.org/software/S0037), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0230 ZeroT](https://attack.mitre.org/software/S0230), [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0672 Zox](https://attack.mitre.org/software/S0672), [S1141 LunarWeb](https://attack.mitre.org/software/S1141), [S1142 LunarMail](https://attack.mitre.org/software/S1142)  

---

### T1001.003 — Protocol or Service Impersonation
<a id="t1001003"></a>

sub-technique of [T1001](/techniques/command-and-control.md#t1001) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1001/003)  

Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, adversaries can make their command and control traffic blend in with legitimate network traffic.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detecting Protocol or Service Impersonation via Anomalous TLS, HTTP Header, and Port Mismatch Correlation  
**Used by 3 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 18 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0076 FakeM](https://attack.mitre.org/software/S0076), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0181 FALLCHILL](https://attack.mitre.org/software/S0181), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0245 BADCALL](https://attack.mitre.org/software/S0245), [S0246 HARDRAIN](https://attack.mitre.org/software/S0246), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0586 TAINTEDSCRIBE](https://attack.mitre.org/software/S0586), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1120 FRAMESTING](https://attack.mitre.org/software/S1120), [S1226 BOOKWORM](https://attack.mitre.org/software/S1226), [S1227 StarProxy](https://attack.mitre.org/software/S1227), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1008 — Fallback Channels
<a id="t1008"></a>

**Tactics:** Command and Control · **Platforms:** Linux, Windows, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1008)  

Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of Fallback or Alternate C2 Channels  
**Used by 5 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 47 software:** [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0058 SslMM](https://attack.mitre.org/software/S0058), [S0059 WinMM](https://attack.mitre.org/software/S0059), [S0062 DustySky](https://attack.mitre.org/software/S0062), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0117 XTunnel](https://attack.mitre.org/software/S0117), [S0211 Linfo](https://attack.mitre.org/software/S0211), [S0236 Kwampirs](https://attack.mitre.org/software/S0236), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0269 QUADAGENT](https://attack.mitre.org/software/S0269), [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401) _(+23 more)_  

---

### T1071 — Application Layer Protocol
<a id="t1071"></a>

**Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1071)  

Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (15):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-10`, `SC-20`, `SC-21`, `SC-22`, `SC-23`, `SC-31`, `SC-37`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Command and Control Over Application Layer Protocols  
**Used by 5 threat groups:** [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047)  
**Implemented by 10 software:** [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0660 Clambling](https://attack.mitre.org/software/S0660), [S1084 QUIETEXIT](https://attack.mitre.org/software/S1084), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1147 Nightdoor](https://attack.mitre.org/software/S1147)  

---

### T1071.001 — Web Protocols
<a id="t1071001"></a>

sub-technique of [T1071](/techniques/command-and-control.md#t1071) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1071/001)  

Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (15):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-10`, `SC-20`, `SC-21`, `SC-22`, `SC-23`, `SC-31`, `SC-37`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Web Protocol-Based C2 Over HTTP, HTTPS, or WebSockets  
**Used by 56 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0071 Orangeworm](https://attack.mitre.org/groups/G0071), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0075 Rancor](https://attack.mitre.org/groups/G0075), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0082 APT38](https://attack.mitre.org/groups/G0082) _(+32 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 329 software:** [S0003 RIPTIDE](https://attack.mitre.org/software/S0003), [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0019 Regin](https://attack.mitre.org/software/S0019), [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0037 HAMMERTOSS](https://attack.mitre.org/software/S0037), [S0042 LOWBALL](https://attack.mitre.org/software/S0042), [S0043 BUBBLEWRAP](https://attack.mitre.org/software/S0043), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0049 GeminiDuke](https://attack.mitre.org/software/S0049), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0052 OnionDuke](https://attack.mitre.org/software/S0052) _(+305 more)_  

---

### T1071.002 — File Transfer Protocols
<a id="t1071002"></a>

sub-technique of [T1071](/techniques/command-and-control.md#t1071) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1071/002)  

Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (15):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-10`, `SC-20`, `SC-21`, `SC-22`, `SC-23`, `SC-31`, `SC-37`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of File Transfer Protocol-Based C2 (FTP, FTPS, SMB, TFTP)  
**Used by 4 threat groups:** [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0083 SilverTerrier](https://attack.mitre.org/groups/G0083), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096)  
**Implemented by 19 software:** [S0019 Regin](https://attack.mitre.org/software/S0019), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0161 XAgentOSX](https://attack.mitre.org/software/S0161), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0353 NOKKI](https://attack.mitre.org/software/S0353), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0464 SYSCON](https://attack.mitre.org/software/S0464), [S0465 CARROTBALL](https://attack.mitre.org/software/S0465), [S0596 ShadowPad](https://attack.mitre.org/software/S0596), [S0699 Mythic](https://attack.mitre.org/software/S0699), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1088 Disco](https://attack.mitre.org/software/S1088), [S1089 SharpDisco](https://attack.mitre.org/software/S1089), [S1228 PUBLOAD](https://attack.mitre.org/software/S1228), [S1229 Havoc](https://attack.mitre.org/software/S1229)  

---

### T1071.003 — Mail Protocols
<a id="t1071003"></a>

sub-technique of [T1071](/techniques/command-and-control.md#t1071) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1071/003)  

Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (15):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-10`, `SC-20`, `SC-21`, `SC-22`, `SC-23`, `SC-31`, `SC-37`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Mail Protocol-Based C2 Activity (SMTP, IMAP, POP3)  
**Used by 6 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0083 SilverTerrier](https://attack.mitre.org/groups/G0083), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 20 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0137 CORESHELL](https://attack.mitre.org/software/S0137), [S0138 OLDBAIT](https://attack.mitre.org/software/S0138), [S0201 JPIN](https://attack.mitre.org/software/S0201), [S0247 NavRAT](https://attack.mitre.org/software/S0247), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0337 BadPatch](https://attack.mitre.org/software/S0337), [S0351 Cannon](https://attack.mitre.org/software/S0351), [S0395 LightNeuron](https://attack.mitre.org/software/S0395), [S0477 Goopy](https://attack.mitre.org/software/S0477), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S1042 SUGARDUMP](https://attack.mitre.org/software/S1042), [S1090 NightClub](https://attack.mitre.org/software/S1090), [S1142 LunarMail](https://attack.mitre.org/software/S1142), [S1152 IMAPLoader](https://attack.mitre.org/software/S1152), [S1173 PowerExchange](https://attack.mitre.org/software/S1173)  

---

### T1071.004 — DNS
<a id="t1071004"></a>

sub-technique of [T1071](/techniques/command-and-control.md#t1071) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, Network Devices, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1071/004)  

Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (18):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-10`, `SC-20`, `SC-21`, `SC-22`, `SC-23`, `SC-31`, `SC-37`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of DNS Tunneling and Application Layer Abuse  
**Used by 11 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  
**Implemented by 41 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0124 Pisloader](https://attack.mitre.org/software/S0124), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0145 POWERSOURCE](https://attack.mitre.org/software/S0145), [S0146 TEXTMATE](https://attack.mitre.org/software/S0146), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0157 SOUNDBITE](https://attack.mitre.org/software/S0157), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0228 NanHaiShu](https://attack.mitre.org/software/S0228), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0269 QUADAGENT](https://attack.mitre.org/software/S0269), [S0338 Cobian RAT](https://attack.mitre.org/software/S0338), [S0354 Denis](https://attack.mitre.org/software/S0354), [S0360 BONDUPDATER](https://attack.mitre.org/software/S0360), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0477 Goopy](https://attack.mitre.org/software/S0477), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S0504 Anchor](https://attack.mitre.org/software/S0504), [S0514 WellMess](https://attack.mitre.org/software/S0514), [S0559 SUNBURST](https://attack.mitre.org/software/S0559) _(+17 more)_  

---

### T1071.005 — Publish/Subscribe Protocols
<a id="t1071005"></a>

sub-technique of [T1071](/techniques/command-and-control.md#t1071) · **Tactics:** Command and Control · **Platforms:** macOS, Linux, Windows, Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1071/005)  

Adversaries may communicate using publish/subscribe (pub/sub) application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (4):** `AC-4`, `SC-31`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Behavioral Detection of Publish/Subscribe Protocol Misuse for C2  
**Implemented by 1 software:** [S0026 GLOOXMAIL](https://attack.mitre.org/software/S0026)  

---

### T1090 — Proxy
<a id="t1090"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1090)  

Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure.

**ATT&CK mitigations (3):** [M1020 SSL/TLS Inspection](../ATTACK_MITIGATIONS_REFERENCE.md#m1020), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (12):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SC-8`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Proxy Infrastructure Setup and Traffic Bridging  
**Used by 17 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0124 Windigo](https://attack.mitre.org/groups/G0124), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1005 POLONIUM](https://attack.mitre.org/groups/G1005), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 46 software:** [S0040 HTRAN](https://attack.mitre.org/software/S0040), [S0108 netsh](https://attack.mitre.org/software/S0108), [S0117 XTunnel](https://attack.mitre.org/software/S0117), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0207 Vasport](https://attack.mitre.org/software/S0207), [S0245 BADCALL](https://attack.mitre.org/software/S0245), [S0246 HARDRAIN](https://attack.mitre.org/software/S0246), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0273 Socksbot](https://attack.mitre.org/software/S0273), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0332 Remcos](https://attack.mitre.org/software/S0332), [S0347 AuditCred](https://attack.mitre.org/software/S0347), [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0384 Dridex](https://attack.mitre.org/software/S0384), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0435 PLEAD](https://attack.mitre.org/software/S0435), [S0436 TSCookie](https://attack.mitre.org/software/S0436), [S0456 Aria-body](https://attack.mitre.org/software/S0456), [S0461 SDBbot](https://attack.mitre.org/software/S0461) _(+22 more)_  

---

### T1090.001 — Internal Proxy
<a id="t1090001"></a>

sub-technique of [T1090](/techniques/command-and-control.md#t1090) · **Tactics:** Command and Control · **Platforms:** Linux, Network Devices, Windows, macOS, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1090/001)  

Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Internal Proxy Behavior via Lateral Host-to-Host C2 Relay  
**Used by 9 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0041 Strider](https://attack.mitre.org/groups/G0041), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047)  
**Implemented by 20 software:** [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0502 Drovorub](https://attack.mitre.org/software/S0502), [S0512 FatDuke](https://attack.mitre.org/software/S0512), [S0556 Pay2Key](https://attack.mitre.org/software/S0556), [S0603 Stuxnet](https://attack.mitre.org/software/S0603), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0699 Mythic](https://attack.mitre.org/software/S0699), [S1059 metaMain](https://attack.mitre.org/software/S1059), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1198 Gomir](https://attack.mitre.org/software/S1198), [S1227 StarProxy](https://attack.mitre.org/software/S1227)  

---

### T1090.002 — External Proxy
<a id="t1090002"></a>

sub-technique of [T1090](/techniques/command-and-control.md#t1090) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, Network Devices, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1090/002)  

Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including HTRAN, ZXProxy, and ZXPortMap.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** External Proxy Behavior via Outbound Relay to Intermediate Infrastructure  
**Used by 11 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131)  
**Implemented by 10 software:** [S0019 Regin](https://attack.mitre.org/software/S0019), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0444 ShimRat](https://attack.mitre.org/software/S0444), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0699 Mythic](https://attack.mitre.org/software/S0699), [S1084 QUIETEXIT](https://attack.mitre.org/software/S1084)  

---

### T1090.003 — Multi-hop Proxy
<a id="t1090003"></a>

sub-technique of [T1090](/techniques/command-and-control.md#t1090) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1090/003)  

Adversaries may chain together multiple proxies to disguise the source of malicious traffic. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy.

**ATT&CK mitigations (1):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`  
**ATT&CK detection strategy:** Multi-hop Proxy Behavior via Relay Node Chaining, Onion Routing, and Network Tunneling  
**Used by 11 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 20 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0183 Tor](https://attack.mitre.org/software/S0183), [S0276 Keydnap](https://attack.mitre.org/software/S0276), [S0281 Dok](https://attack.mitre.org/software/S0281), [S0282 MacSpy](https://attack.mitre.org/software/S0282), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0384 Dridex](https://attack.mitre.org/software/S0384), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0438 Attor](https://attack.mitre.org/software/S0438), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S0641 Kobalos](https://attack.mitre.org/software/S0641), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1106 NGLite](https://attack.mitre.org/software/S1106), [S1107 NKAbuse](https://attack.mitre.org/software/S1107), [S1144 FRP](https://attack.mitre.org/software/S1144), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184)  

---

### T1090.004 — Domain Fronting
<a id="t1090004"></a>

sub-technique of [T1090](/techniques/command-and-control.md#t1090) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1090/004)  

Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS.

**ATT&CK mitigations (1):** [M1020 SSL/TLS Inspection](../ATTACK_MITIGATIONS_REFERENCE.md#m1020)  
**NIST 800-53 R5 controls (1):** `SC-8`  
**ATT&CK detection strategy:** Domain Fronting Behavior via Mismatched TLS SNI and HTTP Host Headers  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 4 software:** [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0175 meek](https://attack.mitre.org/software/S0175), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S0699 Mythic](https://attack.mitre.org/software/S0699)  

---

### T1092 — Communication Through Removable Media
<a id="t1092"></a>

**Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1092)  

Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system.

**ATT&CK mitigations (2):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (8):** `CM-2`, `CM-6`, `CM-7`, `CM-8`, `MP-7`, `RA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Cross-host C2 via Removable Media Relay  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  
**Implemented by 2 software:** [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0136 USBStealer](https://attack.mitre.org/software/S0136)  

---

### T1095 — Non-Application Layer Protocol
<a id="t1095"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1095)  

Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.

**ATT&CK mitigations (4):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (11):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Non-Application Layer Protocols for C2  
**Used by 12 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1013 Metador](https://attack.mitre.org/groups/G1013), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 86 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0019 Regin](https://attack.mitre.org/software/S0019), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0043 BUBBLEWRAP](https://attack.mitre.org/software/S0043), [S0055 RARSTONE](https://attack.mitre.org/software/S0055), [S0076 FakeM](https://attack.mitre.org/software/S0076), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141), [S0149 MoonWind](https://attack.mitre.org/software/S0149), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0155 WINDSHIELD](https://attack.mitre.org/software/S0155), [S0158 PHOREAL](https://attack.mitre.org/software/S0158), [S0172 Reaver](https://attack.mitre.org/software/S0172), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0221 Umbreon](https://attack.mitre.org/software/S0221), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0260 InvisiMole](https://attack.mitre.org/software/S0260) _(+62 more)_  

---

### T1102 — Web Service
<a id="t1102"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1102)  

Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Suspicious Use of Web Services for C2  
**Used by 14 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 27 software:** [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0335 Carbon](https://attack.mitre.org/software/S0335), [S0508 ngrok](https://attack.mitre.org/software/S0508), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0546 SharpStage](https://attack.mitre.org/software/S0546), [S0547 DropBook](https://attack.mitre.org/software/S0547), [S0561 GuLoader](https://attack.mitre.org/software/S0561), [S0589 Sibot](https://attack.mitre.org/software/S0589), [S0600 Doki](https://attack.mitre.org/software/S0600), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0635 BoomBox](https://attack.mitre.org/software/S0635), [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S0674 CharmPower](https://attack.mitre.org/software/S0674), [S0689 WhisperGate](https://attack.mitre.org/software/S0689), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1066 DarkTortilla](https://attack.mitre.org/software/S1066), [S1081 BADHATCH](https://attack.mitre.org/software/S1081), [S1086 Snip3](https://attack.mitre.org/software/S1086), [S1124 SocGholish](https://attack.mitre.org/software/S1124), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1147 Nightdoor](https://attack.mitre.org/software/S1147), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1160 Latrodectus](https://attack.mitre.org/software/S1160) _(+3 more)_  

---

### T1102.001 — Dead Drop Resolver
<a id="t1102001"></a>

sub-technique of [T1102](/techniques/command-and-control.md#t1102) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1102/001)  

Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Web Service: Dead Drop Resolver  
**Used by 6 threat groups:** [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0048 RTM](https://attack.mitre.org/groups/G0048), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0106 Rocke](https://attack.mitre.org/groups/G0106)  
**Implemented by 15 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0069 BLACKCOFFEE](https://attack.mitre.org/software/S0069), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0518 PolyglotDuke](https://attack.mitre.org/software/S0518), [S0528 Javali](https://attack.mitre.org/software/S0528), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0674 CharmPower](https://attack.mitre.org/software/S0674), [S1051 KEYPLUG](https://attack.mitre.org/software/S1051), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1221 MOPSLED](https://attack.mitre.org/software/S1221)  

---

### T1102.002 — Bidirectional Communication
<a id="t1102002"></a>

sub-technique of [T1102](/techniques/command-and-control.md#t1102) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1102/002)  

Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect Bidirectional Web Service C2 Channels via Process & Network Correlation  
**Used by 16 threat groups:** [G0005 APT12](https://attack.mitre.org/groups/G0005), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1005 POLONIUM](https://attack.mitre.org/groups/G1005)  
**Implemented by 37 software:** [S0025 CALENDAR](https://attack.mitre.org/software/S0025), [S0026 GLOOXMAIL](https://attack.mitre.org/software/S0026), [S0042 LOWBALL](https://attack.mitre.org/software/S0042), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0054 CloudDuke](https://attack.mitre.org/software/S0054), [S0069 BLACKCOFFEE](https://attack.mitre.org/software/S0069), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0213 DOGCALL](https://attack.mitre.org/software/S0213), [S0215 KARAE](https://attack.mitre.org/software/S0215), [S0216 POORAIM](https://attack.mitre.org/software/S0216), [S0218 SLOWDRIFT](https://attack.mitre.org/software/S0218), [S0229 Orz](https://attack.mitre.org/software/S0229), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0244 Comnie](https://attack.mitre.org/software/S0244), [S0248 yty](https://attack.mitre.org/software/S0248), [S0265 Kazuar](https://attack.mitre.org/software/S0265), [S0270 RogueRobin](https://attack.mitre.org/software/S0270), [S0333 UBoatRAT](https://attack.mitre.org/software/S0333), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S0393 PowerStallion](https://attack.mitre.org/software/S0393), [S0511 RegDuke](https://attack.mitre.org/software/S0511), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531) _(+13 more)_  

---

### T1102.003 — One-Way Communication
<a id="t1102003"></a>

sub-technique of [T1102](/techniques/command-and-control.md#t1102) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1102/003)  

Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect One-Way Web Service Command Channels  
**Used by 2 threat groups:** [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0065 Leviathan](https://attack.mitre.org/groups/G0065)  
**Implemented by 6 software:** [S0037 HAMMERTOSS](https://attack.mitre.org/software/S0037), [S0052 OnionDuke](https://attack.mitre.org/software/S0052), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0568 EVILNUM](https://attack.mitre.org/software/S0568), [S1164 UPSTYLE](https://attack.mitre.org/software/S1164), [S1210 Sagerunex](https://attack.mitre.org/software/S1210)  

---

### T1104 — Multi-Stage Channels
<a id="t1104"></a>

**Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1104)  

Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect Multi-Stage Command and Control Channels  
**Used by 4 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0096 APT41](https://attack.mitre.org/groups/G0096)  
**Implemented by 10 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0069 BLACKCOFFEE](https://attack.mitre.org/software/S0069), [S0220 Chaos](https://attack.mitre.org/software/S0220), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S1086 Snip3](https://attack.mitre.org/software/S1086), [S1141 LunarWeb](https://attack.mitre.org/software/S1141), [S1160 Latrodectus](https://attack.mitre.org/software/S1160), [S1206 JumbledPath](https://attack.mitre.org/software/S1206)  

---

### T1105 — Ingress Tool Transfer
<a id="t1105"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1105)  

Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as ftp.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect Ingress Tool Transfers via Behavioral Chain  
**Used by 85 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0026 APT18](https://attack.mitre.org/groups/G0026), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0044 Winnti Group](https://attack.mitre.org/groups/G0044), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065) _(+61 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 385 software:** [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0024 Dyre](https://attack.mitre.org/software/S0024), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0042 LOWBALL](https://attack.mitre.org/software/S0042), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0054 CloudDuke](https://attack.mitre.org/software/S0054), [S0055 RARSTONE](https://attack.mitre.org/software/S0055), [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0077 CallMe](https://attack.mitre.org/software/S0077), [S0078 Psylo](https://attack.mitre.org/software/S0078), [S0079 MobileOrder](https://attack.mitre.org/software/S0079), [S0080 Mivast](https://attack.mitre.org/software/S0080), [S0081 Elise](https://attack.mitre.org/software/S0081) _(+361 more)_  

---

### T1132 — Data Encoding
<a id="t1132"></a>

**Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1132)  

Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Data Encoding in C2 Channels  
**Used by 1 threat groups:** [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047)  
**Implemented by 5 software:** [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0699 Mythic](https://attack.mitre.org/software/S0699)  

---

### T1132.001 — Standard Encoding
<a id="t1132001"></a>

sub-technique of [T1132](/techniques/command-and-control.md#t1132) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1132/001)  

Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavior-chain detection for T1132.001 Data Encoding: Standard Encoding (Base64/Hex/MIME) across Windows, Linux, macOS, ESXi  
**Used by 11 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 108 software:** [S0014 BS2005](https://attack.mitre.org/software/S0014), [S0015 Ixeshe](https://attack.mitre.org/software/S0015), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0081 Elise](https://attack.mitre.org/software/S0081), [S0083 Misdat](https://attack.mitre.org/software/S0083), [S0084 Mis-Type](https://attack.mitre.org/software/S0084), [S0085 S-Type](https://attack.mitre.org/software/S0085), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0124 Pisloader](https://attack.mitre.org/software/S0124), [S0128 BADNEWS](https://attack.mitre.org/software/S0128), [S0129 AutoIt backdoor](https://attack.mitre.org/software/S0129), [S0137 CORESHELL](https://attack.mitre.org/software/S0137), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0170 Helminth](https://attack.mitre.org/software/S0170), [S0171 Felismus](https://attack.mitre.org/software/S0171), [S0184 POWRUNER](https://attack.mitre.org/software/S0184), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0200 Dipsind](https://attack.mitre.org/software/S0200) _(+84 more)_  

---

### T1132.002 — Non-Standard Encoding
<a id="t1132002"></a>

sub-technique of [T1132](/techniques/command-and-control.md#t1132) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1132/002)  

Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a non-standard data encoding system that diverges from existing protocol specifications.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Behavior-chain detection for T1132.002 Data Encoding: Non-Standard Encoding across Windows, Linux, macOS, ESXi  
**Implemented by 16 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0031 BACKSPACE](https://attack.mitre.org/software/S0031), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0260 InvisiMole](https://attack.mitre.org/software/S0260), [S0346 OceanSalt](https://attack.mitre.org/software/S0346), [S0495 RDAT](https://attack.mitre.org/software/S0495), [S0596 ShadowPad](https://attack.mitre.org/software/S0596), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687), [S1035 Small Sieve](https://attack.mitre.org/software/S1035), [S1046 PowGoop](https://attack.mitre.org/software/S1046), [S1090 NightClub](https://attack.mitre.org/software/S1090), [S1100 Ninja](https://attack.mitre.org/software/S1100), [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149), [S1189 Neo-reGeorg](https://attack.mitre.org/software/S1189), [S1239 TONESHELL](https://attack.mitre.org/software/S1239)  

---

### T1219 — Remote Access Tools
<a id="t1219"></a>

**Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1219)  

An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network.

**ATT&CK mitigations (5):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1034 Limit Hardware Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1034), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (13):** `AC-17`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Behavior-Chain Detection for Remote Access Tools (Tool-Agnostic)  
**Used by 13 threat groups:** [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1024 Akira](https://attack.mitre.org/groups/G1024), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 7 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0384 Dridex](https://attack.mitre.org/software/S0384), [S0554 Egregor](https://attack.mitre.org/software/S0554), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1219.001 — IDE Tunneling
<a id="t1219001"></a>

sub-technique of [T1219](/techniques/command-and-control.md#t1219) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1219/001)  

Adversaries may abuse Integrated Development Environment (IDE) software with remote development features to establish an interactive command and control channel on target systems within a network.

**ATT&CK mitigations (1):** [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** IDE Tunneling Detection via Process, File, and Network Behaviors  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  

---

### T1219.002 — Remote Desktop Software
<a id="t1219002"></a>

sub-technique of [T1219](/techniques/command-and-control.md#t1219) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1219/002)  

An adversary may use legitimate desktop support software to establish an interactive command and control channel to target systems within networks.

**ATT&CK mitigations (3):** [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1038 Execution Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1038), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Remote Desktop Software Execution and Beaconing Detection  
**Used by 9 threat groups:** [G0048 RTM](https://attack.mitre.org/groups/G0048), [G0076 Thrip](https://attack.mitre.org/groups/G0076), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1219.003 — Remote Access Hardware
<a id="t1219003"></a>

sub-technique of [T1219](/techniques/command-and-control.md#t1219) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1219/003)  

An adversary may use legitimate remote access hardware to establish an interactive command and control channel to target systems within networks.

**ATT&CK mitigations (1):** [M1034 Limit Hardware Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1034)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Remote Access via USB Hardware (TinyPilot, PiKVM)  

---

### T1568 — Dynamic Resolution
<a id="t1568"></a>

**Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1568)  

Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `SC-20`, `SC-21`, `SC-22`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Dynamic Resolution across OS Platforms  
**Used by 6 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1042 RedEcho](https://attack.mitre.org/groups/G1042)  
**Implemented by 8 software:** [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0449 Maze](https://attack.mitre.org/software/S0449), [S0559 SUNBURST](https://attack.mitre.org/software/S0559), [S0666 Gelsemium](https://attack.mitre.org/software/S0666), [S0671 Tomiris](https://attack.mitre.org/software/S0671), [S1087 AsyncRAT](https://attack.mitre.org/software/S1087)  

---

### T1568.001 — Fast Flux DNS
<a id="t1568001"></a>

sub-technique of [T1568](/techniques/command-and-control.md#t1568) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1568/001)  

Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Dynamic Resolution using Fast Flux DNS  
**Used by 3 threat groups:** [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0092 TA505](https://attack.mitre.org/groups/G0092)  
**Implemented by 3 software:** [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S1025 Amadey](https://attack.mitre.org/software/S1025)  

---

### T1568.002 — Domain Generation Algorithms
<a id="t1568002"></a>

sub-technique of [T1568](/techniques/command-and-control.md#t1568) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1568/002)  

Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `SC-20`, `SC-21`, `SC-22`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Dynamic Resolution using Domain Generation Algorithms.  
**Used by 2 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0127 TA551](https://attack.mitre.org/groups/G0127)  
**Implemented by 20 software:** [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0051 MiniDuke](https://attack.mitre.org/software/S0051), [S0150 POSHSPY](https://attack.mitre.org/software/S0150), [S0222 CCBkdr](https://attack.mitre.org/software/S0222), [S0360 BONDUPDATER](https://attack.mitre.org/software/S0360), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0386 Ursnif](https://attack.mitre.org/software/S0386), [S0456 Aria-body](https://attack.mitre.org/software/S0456), [S0508 ngrok](https://attack.mitre.org/software/S0508), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0596 ShadowPad](https://attack.mitre.org/software/S0596), [S0600 Doki](https://attack.mitre.org/software/S0600), [S0608 Conficker](https://attack.mitre.org/software/S0608), [S0615 SombRAT](https://attack.mitre.org/software/S0615), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0673 DarkWatchman](https://attack.mitre.org/software/S0673), [S1015 Milan](https://attack.mitre.org/software/S1015), [S1019 Shark](https://attack.mitre.org/software/S1019)  

---

### T1568.003 — DNS Calculation
<a id="t1568003"></a>

sub-technique of [T1568](/techniques/command-and-control.md#t1568) · **Tactics:** Command and Control · **Platforms:** Linux, macOS, Windows, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1568/003)  

Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Dynamic Resolution through DNS Calculation  
**Used by 1 threat groups:** [G0005 APT12](https://attack.mitre.org/groups/G0005)  

---

### T1571 — Non-Standard Port
<a id="t1571"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1571)  

Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088 or port 587 as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.

**ATT&CK mitigations (2):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (8):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Non-Standard Ports  
**Used by 16 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0090 WIRTE](https://attack.mitre.org/groups/G0090), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0099 APT-C-36](https://attack.mitre.org/groups/G0099), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1042 RedEcho](https://attack.mitre.org/groups/G1042), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 37 software:** [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0149 MoonWind](https://attack.mitre.org/software/S0149), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0237 GravityRAT](https://attack.mitre.org/software/S0237), [S0239 Bankshot](https://attack.mitre.org/software/S0239), [S0245 BADCALL](https://attack.mitre.org/software/S0245), [S0246 HARDRAIN](https://attack.mitre.org/software/S0246), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0491 StrongPity](https://attack.mitre.org/software/S0491), [S0493 GoldenSpy](https://attack.mitre.org/software/S0493), [S0515 WellMail](https://attack.mitre.org/software/S0515), [S0574 BendyBear](https://attack.mitre.org/software/S0574), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687) _(+13 more)_  

---

### T1572 — Protocol Tunneling
<a id="t1572"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1572)  

Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (11):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Protocol Tunneling accross OS platforms.  
**Used by 14 threat groups:** [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
**Implemented by 18 software:** [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0173 FLIPSIDE](https://attack.mitre.org/software/S0173), [S0508 ngrok](https://attack.mitre.org/software/S0508), [S0604 Industroyer](https://attack.mitre.org/software/S0604), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687), [S0699 Mythic](https://attack.mitre.org/software/S0699), [S1015 Milan](https://attack.mitre.org/software/S1015), [S1020 Kevin](https://attack.mitre.org/software/S1020), [S1027 Heyoka Backdoor](https://attack.mitre.org/software/S1027), [S1044 FunnyDream](https://attack.mitre.org/software/S1044), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1141 LunarWeb](https://attack.mitre.org/software/S1141), [S1144 FRP](https://attack.mitre.org/software/S1144), [S1187 reGeorg](https://attack.mitre.org/software/S1187), [S1189 Neo-reGeorg](https://attack.mitre.org/software/S1189)  

---

### T1573 — Encrypted Channel
<a id="t1573"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1573)  

Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.

**ATT&CK mitigations (2):** [M1020 SSL/TLS Inspection](../ATTACK_MITIGATIONS_REFERENCE.md#m1020), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-12`, `SC-16`, `SC-23`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Encrypted Channel across OS Platforms  
**Used by 4 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G1002 BITTER](https://attack.mitre.org/groups/G1002)  
**Implemented by 11 software:** [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0498 Cryptoistic](https://attack.mitre.org/software/S0498), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0662 RCSession](https://attack.mitre.org/software/S0662), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S1012 PowerLess](https://attack.mitre.org/software/S1012), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1046 PowGoop](https://attack.mitre.org/software/S1046), [S1198 Gomir](https://attack.mitre.org/software/S1198)  

---

### T1573.001 — Symmetric Cryptography
<a id="t1573001"></a>

sub-technique of [T1573](/techniques/command-and-control.md#t1573) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1573/001)  

Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption.

**ATT&CK mitigations (1):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-12`, `SC-16`, `SC-23`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Encrypted Channel via Symmetric Cryptography across OS Platforms  
**Used by 14 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0126 Higaisa](https://attack.mitre.org/groups/G0126), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 159 software:** [S0003 RIPTIDE](https://attack.mitre.org/software/S0003), [S0009 Hikit](https://attack.mitre.org/software/S0009), [S0010 Lurid](https://attack.mitre.org/software/S0010), [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0012 PoisonIvy](https://attack.mitre.org/software/S0012), [S0013 PlugX](https://attack.mitre.org/software/S0013), [S0021 Derusbi](https://attack.mitre.org/software/S0021), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0032 gh0st RAT](https://attack.mitre.org/software/S0032), [S0034 NETEAGLE](https://attack.mitre.org/software/S0034), [S0037 HAMMERTOSS](https://attack.mitre.org/software/S0037), [S0038 Duqu](https://attack.mitre.org/software/S0038), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0053 SeaDuke](https://attack.mitre.org/software/S0053), [S0060 Sys10](https://attack.mitre.org/software/S0060), [S0065 4H RAT](https://attack.mitre.org/software/S0065), [S0066 3PARA RAT](https://attack.mitre.org/software/S0066), [S0068 httpclient](https://attack.mitre.org/software/S0068), [S0074 Sakula](https://attack.mitre.org/software/S0074), [S0076 FakeM](https://attack.mitre.org/software/S0076), [S0077 CallMe](https://attack.mitre.org/software/S0077) _(+135 more)_  

---

### T1573.002 — Asymmetric Cryptography
<a id="t1573002"></a>

sub-technique of [T1573](/techniques/command-and-control.md#t1573) · **Tactics:** Command and Control · **Platforms:** ESXi, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1573/002)  

Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.

**ATT&CK mitigations (2):** [M1020 SSL/TLS Inspection](../ATTACK_MITIGATIONS_REFERENCE.md#m1020), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-12`, `SC-16`, `SC-23`, `SC-7`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for Encrypted Channel via Asymmetric Cryptography across OS Platforms  
**Used by 11 threat groups:** [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1042 RedEcho](https://attack.mitre.org/groups/G1042), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 73 software:** [S0017 BISCUIT](https://attack.mitre.org/software/S0017), [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S0022 Uroburos](https://attack.mitre.org/software/S0022), [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023), [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045), [S0087 Hi-Zor](https://attack.mitre.org/software/S0087), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0117 XTunnel](https://attack.mitre.org/software/S0117), [S0126 ComRAT](https://attack.mitre.org/software/S0126), [S0150 POSHSPY](https://attack.mitre.org/software/S0150), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0168 Gazer](https://attack.mitre.org/software/S0168), [S0180 Volgmer](https://attack.mitre.org/software/S0180), [S0183 Tor](https://attack.mitre.org/software/S0183), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0202 adbupd](https://attack.mitre.org/software/S0202), [S0223 POWERSTATS](https://attack.mitre.org/software/S0223), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0335 Carbon](https://attack.mitre.org/software/S0335), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0366 WannaCry](https://attack.mitre.org/software/S0366), [S0382 ServHelper](https://attack.mitre.org/software/S0382) _(+49 more)_  

---

### T1665 — Hide Infrastructure
<a id="t1665"></a>

**Tactics:** Command and Control · **Platforms:** ESXi, Linux, Network Devices, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1665)  

Adversaries may manipulate network traffic in order to hide and evade detection of their C2 infrastructure.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Hide Infrastructure  
**Used by 2 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128)  
**Implemented by 3 software:** [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1164 UPSTYLE](https://attack.mitre.org/software/S1164), [S1206 JumbledPath](https://attack.mitre.org/software/S1206)  

---

