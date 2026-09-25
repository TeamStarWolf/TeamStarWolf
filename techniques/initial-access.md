# Initial Access — Technique Detail

> Full detail pages for the **15 ATT&CK techniques** whose primary tactic is [Initial Access](https://attack.mitre.org/tactics/TA0001/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1189 — Drive-by Compromise
<a id="t1189"></a>

**Tactics:** Initial Access · **Platforms:** Identity Provider, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1189)  

Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (18):** `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-8`, `SA-22`, `SC-18`, `SC-2`, `SC-29`, `SC-3`, `SC-30`, `SC-39`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Drive-by Compromise — Behavior-based, Multi-platform Detection Strategy (T1189)  
**Used by 31 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0048 RTM](https://attack.mitre.org/groups/G0048), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0066 Elderwood](https://attack.mitre.org/groups/G0066), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0095 Machete](https://attack.mitre.org/groups/G0095), [G0112 Windshift](https://attack.mitre.org/groups/G0112), [G0124 Windigo](https://attack.mitre.org/groups/G0124) _(+7 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 10 software:** [S0215 KARAE](https://attack.mitre.org/software/S0215), [S0216 POORAIM](https://attack.mitre.org/software/S0216), [S0451 LoudMiner](https://attack.mitre.org/software/S0451), [S0482 Bundlore](https://attack.mitre.org/software/S0482), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606), [S1086 Snip3](https://attack.mitre.org/software/S1086), [S1124 SocGholish](https://attack.mitre.org/software/S1124)  

---

### T1190 — Exploit Public-Facing Application
<a id="t1190"></a>

**Tactics:** Initial Access · **Platforms:** Containers, ESXi, IaaS, Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1190)  

Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.

**ATT&CK mitigations (8):** [M1016 Vulnerability Scanning](../ATTACK_MITIGATIONS_REFERENCE.md#m1016), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (29):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-2`, `CA-7`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `IA-2`, `IA-8`, `RA-10`, `RA-5`, `SA-8`, `SC-18`, `SC-2`, `SC-29`, `SC-3`, `SC-30`, `SC-39`, `SC-46`, `SC-7`, `SI-10`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1190) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 42 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0123 Volatile Cedar](https://attack.mitre.org/groups/G0123), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135) _(+18 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 8 software:** [S0224 Havij](https://attack.mitre.org/software/S0224), [S0225 sqlmap](https://attack.mitre.org/software/S0225), [S0412 ZxShell](https://attack.mitre.org/software/S0412), [S0516 SoreFang](https://attack.mitre.org/software/S0516), [S0623 Siloscape](https://attack.mitre.org/software/S0623), [S1105 COATHANGER](https://attack.mitre.org/software/S1105), [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1195 — Supply Chain Compromise
<a id="t1195"></a>

**Tactics:** Initial Access · **Platforms:** Linux, Windows, macOS, SaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1195)  

Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

**ATT&CK mitigations (6):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1016 Vulnerability Scanning](../ATTACK_MITIGATIONS_REFERENCE.md#m1016), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (22):** `AC-2`, `AC-3`, `AC-6`, `CA-2`, `CA-7`, `CM-11`, `CM-2`, `CM-3`, `CM-5`, `CM-6`, `CM-7`, `CM-8`, `RA-10`, `RA-5`, `SA-22`, `SI-2`, `SI-3`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Behavioral detection for Supply Chain Compromise (package/update tamper → install → first-run)  
**Used by 3 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  
**Implemented by 2 software:** [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213)  

---

### T1195.001 — Compromise Software Dependencies and Development Tools
<a id="t1195001"></a>

sub-technique of [T1195](/techniques/initial-access.md#t1195) · **Tactics:** Initial Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1195/001)  

Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly.

**ATT&CK mitigations (4):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1016 Vulnerability Scanning](../ATTACK_MITIGATIONS_REFERENCE.md#m1016), [M1033 Limit Software Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1033), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (18):** `CA-2`, `CA-7`, `CM-11`, `CM-5`, `CM-6`, `CM-7`, `RA-10`, `RA-5`, `SA-10`, `SA-11`, `SA-15`, `SA-22`, `SI-2`, `SI-4`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Supply-chain tamper in dependencies/dev-tools (manager→write/install→first-run→egress)  
**Implemented by 2 software:** [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1195.002 — Compromise Software Supply Chain
<a id="t1195002"></a>

sub-technique of [T1195](/techniques/initial-access.md#t1195) · **Tactics:** Initial Access · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1195/002)  

Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.

**ATT&CK mitigations (2):** [M1016 Vulnerability Scanning](../ATTACK_MITIGATIONS_REFERENCE.md#m1016), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (11):** `CA-2`, `CA-7`, `CM-11`, `CM-7`, `RA-10`, `RA-5`, `SA-22`, `SI-2`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Compromised software/update chain (installer/write → first-run/child → egress/signature anomaly)  
**Used by 9 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036)  
**Implemented by 3 software:** [S0222 CCBkdr](https://attack.mitre.org/software/S0222), [S0493 GoldenSpy](https://attack.mitre.org/software/S0493), [S0562 SUNSPOT](https://attack.mitre.org/software/S0562)  

---

### T1195.003 — Compromise Hardware Supply Chain
<a id="t1195003"></a>

sub-technique of [T1195](/techniques/initial-access.md#t1195) · **Tactics:** Initial Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1195/003)  

Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.

**ATT&CK mitigations (1):** [M1046 Boot Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1046)  
**NIST 800-53 R5 controls (14):** `CM-2`, `CM-3`, `CM-5`, `CM-8`, `IA-7`, `RA-9`, `SA-10`, `SA-11`, `SC-34`, `SI-2`, `SI-7`, `SR-11`, `SR-4`, `SR-5`  
**ATT&CK detection strategy:** Hardware Supply Chain Compromise Detection via Host Status & Boot Integrity Checks  

---

### T1199 — Trusted Relationship
<a id="t1199"></a>

**Tactics:** Initial Access · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Identity Provider, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1199)  

Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.

**ATT&CK mitigations (3):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (8):** `AC-3`, `AC-4`, `AC-6`, `AC-8`, `CM-6`, `CM-7`, `SC-46`, `SC-7`  
**ATT&CK detection strategy:** Detect abuse of Trusted Relationships (third-party and delegated admin access)  
**Used by 11 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1005 POLONIUM](https://attack.mitre.org/groups/G1005), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  

---

### T1200 — Hardware Additions
<a id="t1200"></a>

**Tactics:** Initial Access · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1200)  

Adversaries may physically introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access. Rather than just connecting and distributing payloads via removable storage (i.e.

**ATT&CK mitigations (2):** [M1034 Limit Hardware Installation](../ATTACK_MITIGATIONS_REFERENCE.md#m1034), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035)  
**NIST 800-53 R5 controls (5):** `AC-20`, `AC-3`, `AC-6`, `MP-7`, `SC-41`  
**ATT&CK detection strategy:** Detect unauthorized or suspicious Hardware Additions (USB/Thunderbolt/Network)  
**Used by 1 threat groups:** [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105)  

---

### T1566 — Phishing
<a id="t1566"></a>

**Tactics:** Initial Access · **Platforms:** Identity Provider, Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1566)  

Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary.

**ATT&CK mitigations (6):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (13):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `RA-5`, `SC-20`, `SC-44`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detection Strategy for Phishing across platforms.  
**Used by 6 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1049 AppleJeus](https://attack.mitre.org/groups/G1049)  
**Implemented by 3 software:** [S0009 Hikit](https://attack.mitre.org/software/S0009), [S1073 Royal](https://attack.mitre.org/software/S1073), [S1139 INC Ransomware](https://attack.mitre.org/software/S1139)  

---

### T1566.001 — Spearphishing Attachment
<a id="t1566001"></a>

sub-technique of [T1566](/techniques/initial-access.md#t1566) · **Tactics:** Initial Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1566/001)  

Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email.

**ATT&CK mitigations (7):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (12):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-8`  
**Detection:** ✅ ready-to-adapt queries in the [Technique Detection Library](../detections/TECHNIQUE_DETECTION_LIBRARY.md#t1566001) (Splunk · Elastic · Microsoft · Chronicle · CrowdStrike)  
**Used by 77 threat groups:** [G0005 APT12](https://attack.mitre.org/groups/G0005), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0012 Darkhotel](https://attack.mitre.org/groups/G0012), [G0013 APT30](https://attack.mitre.org/groups/G0013), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0018 admin@338](https://attack.mitre.org/groups/G0018), [G0019 Naikon](https://attack.mitre.org/groups/G0019), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0048 RTM](https://attack.mitre.org/groups/G0048), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0062 TA459](https://attack.mitre.org/groups/G0062) _(+53 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 55 software:** [S0011 Taidoor](https://attack.mitre.org/software/S0011), [S0148 RTM](https://attack.mitre.org/software/S0148), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0234 Bandook](https://attack.mitre.org/software/S0234), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0268 Bisonal](https://attack.mitre.org/software/S0268), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0340 Octopus](https://attack.mitre.org/software/S0340), [S0346 OceanSalt](https://attack.mitre.org/software/S0346), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0433 Rifdoor](https://attack.mitre.org/software/S0433), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0455 Metamorfo](https://attack.mitre.org/software/S0455), [S0458 Ramsay](https://attack.mitre.org/software/S0458), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0483 IcedID](https://attack.mitre.org/software/S0483), [S0496 REvil](https://attack.mitre.org/software/S0496), [S0499 Hancitor](https://attack.mitre.org/software/S0499), [S0520 BLINDINGCAN](https://attack.mitre.org/software/S0520) _(+31 more)_  

---

### T1566.002 — Spearphishing Link
<a id="t1566002"></a>

sub-technique of [T1566](/techniques/initial-access.md#t1566) · **Tactics:** Initial Access · **Platforms:** Identity Provider, Linux, macOS, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1566/002)  

Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detection Strategy for Spearphishing Links  
**Used by 43 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0066 Elderwood](https://attack.mitre.org/groups/G0066), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0085 FIN4](https://attack.mitre.org/groups/G0085), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0095 Machete](https://attack.mitre.org/groups/G0095), [G0098 BlackTech](https://attack.mitre.org/groups/G0098) _(+19 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 29 software:** [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0499 Hancitor](https://attack.mitre.org/software/S0499), [S0528 Javali](https://attack.mitre.org/software/S0528), [S0530 Melcoz](https://attack.mitre.org/software/S0530), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0534 Bazar](https://attack.mitre.org/software/S0534), [S0561 GuLoader](https://attack.mitre.org/software/S0561), [S0584 AppleJeus](https://attack.mitre.org/software/S0584), [S0585 Kerrdown](https://attack.mitre.org/software/S0585), [S0646 SpicyOmelette](https://attack.mitre.org/software/S0646), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1017 OutSteel](https://attack.mitre.org/software/S1017), [S1018 Saint Bot](https://attack.mitre.org/software/S1018), [S1030 Squirrelwaffle](https://attack.mitre.org/software/S1030), [S1039 Bumblebee](https://attack.mitre.org/software/S1039), [S1086 Snip3](https://attack.mitre.org/software/S1086), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1122 Mispadu](https://attack.mitre.org/software/S1122) _(+5 more)_  

---

### T1566.003 — Spearphishing via Service
<a id="t1566003"></a>

sub-technique of [T1566](/techniques/initial-access.md#t1566) · **Tactics:** Initial Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1566/003)  

Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems. Spearphishing via service is a specific variant of spearphishing.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1049 Antivirus/Antimalware](../ATTACK_MITIGATIONS_REFERENCE.md#m1049)  
**NIST 800-53 R5 controls (10):** `AC-2`, `AC-4`, `AC-6`, `CA-7`, `SC-44`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detection Strategy for Spearphishing via a Service across OS Platforms  
**Used by 14 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070), [G0112 Windshift](https://attack.mitre.org/groups/G0112), [G0130 Ajax Security Team](https://attack.mitre.org/groups/G0130), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1022 ToddyCat](https://attack.mitre.org/groups/G1022), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 1 software:** [S1100 Ninja](https://attack.mitre.org/software/S1100)  

---

### T1566.004 — Spearphishing Voice
<a id="t1566004"></a>

sub-technique of [T1566](/techniques/initial-access.md#t1566) · **Tactics:** Initial Access · **Platforms:** Linux, macOS, Windows, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1566/004)  

Adversaries may use voice communications to ultimately gain access to victim systems. Spearphishing voice is a specific variant of spearphishing.

**ATT&CK mitigations (1):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Spearphishing Voice across OS platforms  
**Used by 1 threat groups:** [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  

---

### T1659 — Content Injection
<a id="t1659"></a>

**Tactics:** Initial Access, Command and Control · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1659)  

Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic.

**ATT&CK mitigations (2):** [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (3):** `AC-17`, `AC-4`, `SC-7`  
**ATT&CK detection strategy:** Detection Strategy for Content Injection  
**Used by 1 threat groups:** [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019)  
**Implemented by 1 software:** [S1088 Disco](https://attack.mitre.org/software/S1088)  

---

### T1669 — Wi-Fi Networks
<a id="t1669"></a>

**Tactics:** Initial Access · **Platforms:** Linux, Network Devices, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1669)  

Adversaries may gain initial access to target systems by connecting to wireless networks. They may accomplish this by exploiting open Wi-Fi networks used by target devices or by accessing secured Wi-Fi networks — requiring Valid Accounts — belonging to a target organization.

**ATT&CK mitigations (3):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection Strategy for Wi-Fi Networks  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  

---

