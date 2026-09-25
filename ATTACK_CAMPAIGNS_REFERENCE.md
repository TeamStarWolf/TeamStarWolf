# ATT&CK Campaigns Reference

> The **52 intrusion campaigns** tracked in MITRE ATT&CK Enterprise (v18.1) — time-bounded sets of adversary activity with a shared objective. Each lists its active window, the techniques observed, the software used, and the threat group(s) it is attributed to. Pair with [Threat Group Profiles](THREAT_GROUP_PROFILES.md) and [Notable Incidents](NOTABLE_INCIDENTS.md).

Machine-readable: [`data/attack/campaigns.jsonl`](data/attack/campaigns.jsonl)

## All campaigns

| Campaign | First seen | Last seen | Techniques | Attributed to |
|---|---|---|--:|---|
| [C0059 Salesforce Data Exfiltration](#c0059-salesforce-data-exfiltration) | 2004-10 | 2025-09 | 18 | — |
| [C0002 Night Dragon](#c0002-night-dragon) | 2009-11 | 2011-02 | 29 | — |
| [C0016 Operation Dust Storm](#c0016-operation-dust-storm) | 2010-01 | 2016-02 | 17 | — |
| [C0023 Operation Ghost](#c0023-operation-ghost) | 2013-09 | 2019-10 | 8 | APT29 |
| [C0032 C0032](#c0032-c0032) | 2014-10 | 2017-01 | 17 | TEMP.Veles |
| [C0028 2015 Ukraine Electric Power Attack](#c0028-2015-ukraine-electric-power-attack) | 2015-12 | 2016-01 | 17 | Sandworm Team |
| [C0033 C0033](#c0033-c0033) | 2016-05 | 2023-01 | 0 | PROMETHIUM |
| [C0025 2016 Ukraine Electric Power Attack](#c0025-2016-ukraine-electric-power-attack) | 2016-12 | 2016-12 | 21 | Sandworm Team |
| [C0030 Triton Safety Instrumented System Attack](#c0030-triton-safety-instrumented-system-attack) | 2017-06 | 2017-08 | 10 | TEMP.Veles |
| [C0006 Operation Honeybee](#c0006-operation-honeybee) | 2017-08 | 2018-02 | 28 | — |
| [C0013 Operation Sharpshooter](#c0013-operation-sharpshooter) | 2017-09 | 2019-03 | 13 | — |
| [C0014 Operation Wocao](#c0014-operation-wocao) | 2017-12 | 2019-12 | 70 | — |
| [C0007 FunnyDream](#c0007-funnydream) | 2018-07 | 2020-11 | 14 | — |
| [C0021 C0021](#c0021-c0021) | 2018-11 | 2018-11 | 15 | — |
| [C0053 FLORAHOX Activity](#c0053-florahox-activity) | 2019-01 | 2024-05 | 6 | — |
| [C0052 SPACEHOP Activity](#c0052-spacehop-activity) | 2019-01 | 2024-05 | 4 | APT5, Ke3chang |
| [C0001 Frankenstein](#c0001-frankenstein) | 2019-01 | 2019-04 | 27 | — |
| [C0024 SolarWinds Compromise](#c0024-solarwinds-compromise) | 2019-08 | 2021-01 | 71 | APT29 |
| [C0022 Operation Dream Job](#c0022-operation-dream-job) | 2019-09 | 2020-08 | 55 | Lazarus Group |
| [C0004 CostaRicto](#c0004-costaricto) | 2019-10 | 2020-11 | 10 | — |
| [C0005 Operation Spalax](#c0005-operation-spalax) | 2019-11 | 2021-01 | 17 | — |
| [C0012 Operation CuckooBees](#c0012-operation-cuckoobees) | 2019-12 | 2022-05 | 33 | — |
| [C0010 C0010](#c0010-c0010) | 2020-12 | 2022-08 | 9 | — |
| [C0042 Outer Space](#c0042-outer-space) | 2021-01 | 2021-12 | 8 | OilRig |
| [C0043 Indian Critical Infrastructure Intrusions](#c0043-indian-critical-infrastructure-intrusions) | 2021-01 | 2022-04 | 8 | — |
| [C0038 HomeLand Justice](#c0038-homeland-justice) | 2021-05 | 2022-09 | 25 | HEXANE |
| [C0017 C0017](#c0017-c0017) | 2021-05 | 2022-02 | 29 | APT41 |
| [C0015 C0015](#c0015-c0015) | 2021-08 | 2021-08 | 34 | — |
| [C0011 C0011](#c0011-c0011) | 2021-12 | 2022-07 | 8 | Transparent Tribe |
| [C0044 Juicy Mix](#c0044-juicy-mix) | 2022-01 | 2022-12 | 14 | OilRig |
| [C0018 C0018](#c0018-c0018) | 2022-02 | 2022-03 | 19 | — |
| [C0051 APT28 Nearest Neighbor Campaign](#c0051-apt28-nearest-neighbor-campaign) | 2022-02 | 2024-11 | 18 | APT28 |
| [C0049 Leviathan Australian Intrusions](#c0049-leviathan-australian-intrusions) | 2022-04 | 2022-09 | 26 | Leviathan |
| [C0027 C0027](#c0027-c0027) | 2022-06 | 2022-12 | 28 | Scattered Spider |
| [C0034 2022 Ukraine Electric Power Attack](#c0034-2022-ukraine-electric-power-attack) | 2022-06 | 2022-10 | 10 | Sandworm Team |
| [C0026 C0026](#c0026-c0026) | 2022-08 | 2022-09 | 6 | — |
| [C0035 KV Botnet Activity](#c0035-kv-botnet-activity) | 2022-10 | 2024-01 | 20 | Volt Typhoon |
| [C0057 3CX Supply Chain Attack](#c0057-3cx-supply-chain-attack) | 2022-11 | 2023-03 | 22 | AppleJeus |
| [C0037 Water Curupira Pikabot Distribution](#c0037-water-curupira-pikabot-distribution) | 2023-01 | 2023-12 | 10 | — |
| [C0040 APT41 DUST](#c0040-apt41-dust) | 2023-01 | 2024-06 | 23 | APT41 |
| [C0050 J-magic Campaign](#c0050-j-magic-campaign) | 2023-06 | 2024-06 | 4 | — |
| [C0046 ArcaneDoor](#c0046-arcanedoor) | 2023-07 | 2024-04 | 25 | — |
| [C0047 RedDelta Modified PlugX Infection Chain Operations](#c0047-reddelta-modified-plugx-infection-chain-operations) | 2023-07 | 2024-12 | 22 | Mustang Panda |
| [C0055 Quad7 Activity](#c0055-quad7-activity) | 2023-08 | 2025-08 | 15 | — |
| [C0045 ShadowRay](#c0045-shadowray) | 2023-09 | 2024-03 | 10 | — |
| [C0029 Cutting Edge](#c0029-cutting-edge) | 2023-12 | 2024-02 | 31 | — |
| [C0041 FrostyGoop Incident](#c0041-frostygoop-incident) | 2024-01 | 2024-01 | 5 | — |
| [C0036 Pikabot Distribution February 2024](#c0036-pikabot-distribution-february-2024) | 2024-02 | 2024-02 | 4 | — |
| [C0048 Operation MidnightEclipse](#c0048-operation-midnighteclipse) | 2024-03 | 2024-04 | 17 | — |
| [C0039 Versa Director Zero Day Exploitation](#c0039-versa-director-zero-day-exploitation) | 2024-06 | 2024-08 | 8 | Volt Typhoon |
| [C0056 RedPenguin](#c0056-redpenguin) | 2024-07 | 2025-03 | 26 | UNC3886 |
| [C0058 SharePoint ToolShell Exploitation](#c0058-sharepoint-toolshell-exploitation) | 2025-07 | 2025-07 | 35 | — |

---

## Detailed profiles

### C0001 — Frankenstein
<a id="c0001"></a>

**Active:** 2019-01-01 → 2019-04-01 · **ATT&CK:** [C0001](https://attack.mitre.org/campaigns/C0001) · **27** techniques · **1** software  
**Attributed to:** unattributed  

Frankenstein was described by security researchers as a highly-targeted campaign conducted by moderately sophisticated and highly resourceful threat actors in early 2019. The unidentified actors primarily relied on open source tools, including Empire. The campaign name refers to the actors' ability to piece together several unrelated open-source tool components.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1119](https://attack.mitre.org/techniques/T1119) Automated Collection · [T1127.001](https://attack.mitre.org/techniques/T1127/001) MSBuild · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution

---

### C0002 — Night Dragon
<a id="c0002"></a>

**Active:** 2009-11-01 → 2011-02-01 · **ATT&CK:** [C0002](https://attack.mitre.org/campaigns/C0002) · **29** techniques · **5** software  
**Attributed to:** unattributed  

Night Dragon was a cyber espionage campaign that targeted oil, energy, and petrochemical companies, along with individuals and executives in Kazakhstan, Taiwan, Greece, and the United States. The unidentified threat actors searched for information related to oil and gas field production systems, financials, and collected data from SCADA systems. Based on the observed techniques, tools, and network activities, security researchers assessed the campaign involved a threat group based in China.

**Techniques:** [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.002](https://attack.mitre.org/techniques/T1074/002) Remote Data Staging · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1110.002](https://attack.mitre.org/techniques/T1110/002) Password Cracking · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1114.001](https://attack.mitre.org/techniques/T1114/001) Local Email Collection · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1219](https://attack.mitre.org/techniques/T1219) Remote Access Tools

---

### C0004 — CostaRicto
<a id="c0004"></a>

**Active:** 2019-10-01 → 2020-11-01 · **ATT&CK:** [C0004](https://attack.mitre.org/campaigns/C0004) · **10** techniques · **6** software  
**Attributed to:** unattributed  

CostaRicto was a suspected hacker-for-hire cyber espionage campaign that targeted multiple industries worldwide, with a large number being financial institutions. CostaRicto actors targeted organizations in Europe, the Americas, Asia, Australia, and Africa, with a large concentration in South Asia (especially India, Bangladesh, and Singapore), using custom malware, open source tools, and a complex network of proxies and SSH tunnels.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1572](https://attack.mitre.org/techniques/T1572) Protocol Tunneling · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool

---

### C0005 — Operation Spalax
<a id="c0005"></a>

**Active:** 2019-11-01 → 2021-01-01 · **ATT&CK:** [C0005](https://attack.mitre.org/campaigns/C0005) · **17** techniques · **2** software  
**Attributed to:** unattributed  

Operation Spalax was a campaign that primarily targeted Colombian government organizations and private companies, particularly those associated with the energy and metallurgical industries. The Operation Spalax threat actors distributed commodity malware and tools using generic phishing topics related to COVID-19, banking, and law enforcement action.

**Techniques:** [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.003](https://attack.mitre.org/techniques/T1027/003) Steganography · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1102](https://attack.mitre.org/techniques/T1102) Web Service · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1218.011](https://attack.mitre.org/techniques/T1218/011) Rundll32 · [T1497](https://attack.mitre.org/techniques/T1497) Virtualization/Sandbox Evasion · [T1566.001](https://attack.mitre.org/techniques/T1566/001) Spearphishing Attachment · [T1566.002](https://attack.mitre.org/techniques/T1566/002) Spearphishing Link · [T1568](https://attack.mitre.org/techniques/T1568) Dynamic Resolution · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1588.001](https://attack.mitre.org/techniques/T1588/001) Malware · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool · [T1608.001](https://attack.mitre.org/techniques/T1608/001) Upload Malware

---

### C0006 — Operation Honeybee
<a id="c0006"></a>

**Active:** 2017-08-01 → 2018-02-01 · **ATT&CK:** [C0006](https://attack.mitre.org/campaigns/C0006) · **28** techniques · **5** software  
**Attributed to:** unattributed  

Operation Honeybee was a campaign that targeted humanitarian aid and inter-Korean affairs organizations from at least late 2017 through early 2018. Operation Honeybee initially targeted South Korea, but expanded to include Vietnam, Singapore, Japan, Indonesia, Argentina, and Canada.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1543.003](https://attack.mitre.org/techniques/T1543/003) Windows Service · [T1548.002](https://attack.mitre.org/techniques/T1548/002) Bypass User Account Control

---

### C0007 — FunnyDream
<a id="c0007"></a>

**Active:** 2018-07-01 → 2020-11-01 · **ATT&CK:** [C0007](https://attack.mitre.org/campaigns/C0007) · **14** techniques · **8** software  
**Attributed to:** unattributed  

FunnyDream was a suspected Chinese cyber espionage campaign that targeted government and foreign organizations in Malaysia, the Philippines, Taiwan, Vietnam, and other parts of Southeast Asia. Security researchers linked the FunnyDream campaign to possible Chinese-speaking threat actors through the use of the Chinoxy backdoor and noted infrastructure overlap with the TAG-16 threat group.

**Techniques:** [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1560.001](https://attack.mitre.org/techniques/T1560/001) Archive via Utility · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1585.002](https://attack.mitre.org/techniques/T1585/002) Email Accounts · [T1588.001](https://attack.mitre.org/techniques/T1588/001) Malware · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool

---

### C0010 — C0010
<a id="c0010"></a>

**Active:** 2020-12-01 → 2022-08-01 · **ATT&CK:** [C0010](https://attack.mitre.org/campaigns/C0010) · **9** techniques · **2** software  
**Attributed to:** unattributed  

C0010 was a cyber espionage campaign conducted by UNC3890 that targeted Israeli shipping, government, aviation, energy, and healthcare organizations. Security researcher assess UNC3890 conducts operations in support of Iranian interests, and noted several limited technical connections to Iran, including PDB strings and Farsi language artifacts. C0010 began by at least late 2020, and was still ongoing as of mid-2022.

**Techniques:** [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1189](https://attack.mitre.org/techniques/T1189) Drive-by Compromise · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1584.001](https://attack.mitre.org/techniques/T1584/001) Domains · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool · [T1608.001](https://attack.mitre.org/techniques/T1608/001) Upload Malware · [T1608.002](https://attack.mitre.org/techniques/T1608/002) Upload Tool · [T1608.004](https://attack.mitre.org/techniques/T1608/004) Drive-by Target

---

### C0011 — C0011
<a id="c0011"></a>

**Active:** 2021-12-01 → 2022-07-01 · **ATT&CK:** [C0011](https://attack.mitre.org/campaigns/C0011) · **8** techniques · **1** software  
**Attributed to:** G0134 Transparent Tribe  

C0011 was a suspected cyber espionage campaign conducted by Transparent Tribe that targeted students at universities and colleges in India. Security researchers noted this campaign against students was a significant shift from Transparent Tribe's historic targeting Indian government, military, and think tank personnel, and assessed it was still ongoing as of July 2022.

**Techniques:** [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1566.001](https://attack.mitre.org/techniques/T1566/001) Spearphishing Attachment · [T1566.002](https://attack.mitre.org/techniques/T1566/002) Spearphishing Link · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1587.003](https://attack.mitre.org/techniques/T1587/003) Digital Certificates · [T1608.001](https://attack.mitre.org/techniques/T1608/001) Upload Malware

---

### C0012 — Operation CuckooBees
<a id="c0012"></a>

**Active:** 2019-12-01 → 2022-05-01 · **ATT&CK:** [C0012](https://attack.mitre.org/campaigns/C0012) · **33** techniques · **2** software  
**Attributed to:** unattributed  

Operation CuckooBees was a cyber espionage campaign targeting technology and manufacturing companies in East Asia, Western Europe, and North America since at least 2019. Security researchers noted the goal of Operation CuckooBees, which was still ongoing as of May 2022, was likely the theft of proprietary information, research and development documents, source code, and blueprints for various technologies.

**Techniques:** [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1069.001](https://attack.mitre.org/techniques/T1069/001) Local Groups · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account

---

### C0013 — Operation Sharpshooter
<a id="c0013"></a>

**Active:** 2017-09-01 → 2019-03-01 · **ATT&CK:** [C0013](https://attack.mitre.org/campaigns/C0013) · **13** techniques · **1** software  
**Attributed to:** unattributed  

Operation Sharpshooter was a global cyber espionage campaign that targeted nuclear, defense, government, energy, and financial companies, with many located in Germany, Turkey, the United Kingdom, and the United States. Security researchers noted the campaign shared many similarities with previous Lazarus Group operations, including fake job recruitment lures and shared malware code.

**Techniques:** [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1547.001](https://attack.mitre.org/techniques/T1547/001) Registry Run Keys / Startup Folder · [T1559.002](https://attack.mitre.org/techniques/T1559/002) Dynamic Data Exchange · [T1583.006](https://attack.mitre.org/techniques/T1583/006) Web Services · [T1584.004](https://attack.mitre.org/techniques/T1584/004) Server · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware · [T1608.001](https://attack.mitre.org/techniques/T1608/001) Upload Malware

---

### C0014 — Operation Wocao
<a id="c0014"></a>

**Active:** 2017-12-01 → 2019-12-01 · **ATT&CK:** [C0014](https://attack.mitre.org/campaigns/C0014) · **70** techniques · **9** software  
**Attributed to:** unattributed  

Operation Wocao was a cyber espionage campaign that targeted organizations around the world, including in Brazil, China, France, Germany, Italy, Mexico, Portugal, Spain, the United Kingdom, and the United States. The suspected China-based actors compromised government organizations and managed service providers, as well as aviation, construction, energy, finance, health care, insurance, offshore engineering, software development, and transportation companies.

**Techniques:** [T1001](https://attack.mitre.org/techniques/T1001) Data Obfuscation · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection

---

### C0015 — C0015
<a id="c0015"></a>

**Active:** 2021-08-01 → 2021-08-01 · **ATT&CK:** [C0015](https://attack.mitre.org/campaigns/C0015) · **34** techniques · **5** software  
**Attributed to:** unattributed  

C0015 was a ransomware intrusion during which the unidentified attackers used Bazar, Cobalt Strike, and Conti, along with other tools, over a 5 day period. Security researchers assessed the actors likely used the widely-circulated Conti ransomware playbook based on the observed pattern of activity and operator errors.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1030](https://attack.mitre.org/techniques/T1030) Data Transfer Size Limits · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1039](https://attack.mitre.org/techniques/T1039) Data from Network Shared Drive · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1069.001](https://attack.mitre.org/techniques/T1069/001) Local Groups · [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1124](https://attack.mitre.org/techniques/T1124) System Time Discovery

---

### C0016 — Operation Dust Storm
<a id="c0016"></a>

**Active:** 2010-01-01 → 2016-02-01 · **ATT&CK:** [C0016](https://attack.mitre.org/campaigns/C0016) · **17** techniques · **6** software  
**Attributed to:** unattributed  

Operation Dust Storm was a long-standing persistent cyber espionage campaign that targeted multiple industries in Japan, South Korea, the United States, Europe, and several Southeast Asian countries.

**Techniques:** [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1189](https://attack.mitre.org/techniques/T1189) Drive-by Compromise · [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1218.005](https://attack.mitre.org/techniques/T1218/005) Mshta · [T1518](https://attack.mitre.org/techniques/T1518) Software Discovery · [T1566.001](https://attack.mitre.org/techniques/T1566/001) Spearphishing Attachment · [T1566.002](https://attack.mitre.org/techniques/T1566/002) Spearphishing Link · [T1568](https://attack.mitre.org/techniques/T1568) Dynamic Resolution · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1585.002](https://attack.mitre.org/techniques/T1585/002) Email Accounts

---

### C0017 — C0017
<a id="c0017"></a>

**Active:** 2021-05-01 → 2022-02-01 · **ATT&CK:** [C0017](https://attack.mitre.org/campaigns/C0017) · **29** techniques · **6** software  
**Attributed to:** G0096 APT41  

C0017 was an APT41 campaign conducted between May 2021 and February 2022 that successfully compromised at least six U.S. state government networks through the exploitation of vulnerable Internet facing web applications. During C0017, APT41 was quick to adapt and use publicly-disclosed as well as zero-day vulnerabilities for initial access, and in at least two cases re-compromised victims following remediation efforts.

**Techniques:** [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1102](https://attack.mitre.org/techniques/T1102) Web Service · [T1102.001](https://attack.mitre.org/techniques/T1102/001) Dead Drop Resolver · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### C0018 — C0018
<a id="c0018"></a>

**Active:** 2022-02-01 → 2022-03-01 · **ATT&CK:** [C0018](https://attack.mitre.org/campaigns/C0018) · **19** techniques · **6** software  
**Attributed to:** unattributed  

C0018 was a month-long ransomware intrusion that successfully deployed AvosLocker onto a compromised network. The unidentified actors gained initial access to the victim network through an exposed server and used a variety of open-source tools prior to executing AvosLocker.

**Techniques:** [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1218.011](https://attack.mitre.org/techniques/T1218/011) Rundll32 · [T1219.002](https://attack.mitre.org/techniques/T1219/002) Remote Desktop Software · [T1486](https://attack.mitre.org/techniques/T1486) Data Encrypted for Impact · [T1570](https://attack.mitre.org/techniques/T1570) Lateral Tool Transfer · [T1571](https://attack.mitre.org/techniques/T1571) Non-Standard Port · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool

---

### C0021 — C0021
<a id="c0021"></a>

**Active:** 2018-11-01 → 2018-11-01 · **ATT&CK:** [C0021](https://attack.mitre.org/campaigns/C0021) · **15** techniques · **1** software  
**Attributed to:** unattributed  

C0021 was a spearphishing campaign conducted in November 2018 that targeted public sector institutions, non-governmental organizations (NGOs), educational institutions, and private-sector corporations in the oil and gas, chemical, and hospitality industries. The majority of targets were located in the US, particularly in and around Washington D.C., with other targets located in Europe, Hong Kong, India, and Canada.

**Techniques:** [T1027.009](https://attack.mitre.org/techniques/T1027/009) Embedded Payloads · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1218.011](https://attack.mitre.org/techniques/T1218/011) Rundll32 · [T1566.002](https://attack.mitre.org/techniques/T1566/002) Spearphishing Link · [T1573.002](https://attack.mitre.org/techniques/T1573/002) Asymmetric Cryptography · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1584.001](https://attack.mitre.org/techniques/T1584/001) Domains · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool · [T1608.001](https://attack.mitre.org/techniques/T1608/001) Upload Malware

---

### C0022 — Operation Dream Job
<a id="c0022"></a>

**Aliases:** Operation Dream Job, Operation North Star, Operation Interception  
**Active:** 2019-09-01 → 2020-08-01 · **ATT&CK:** [C0022](https://attack.mitre.org/campaigns/C0022) · **55** techniques · **3** software  
**Attributed to:** G0032 Lazarus Group  

Operation Dream Job was a cyber espionage operation likely conducted by Lazarus Group that targeted the defense, aerospace, government, and other sectors in the United States, Israel, Australia, Russia, and India. In at least one case, the cyber actors tried to monetize their network access to conduct a business email compromise (BEC) operation.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1087.002](https://attack.mitre.org/techniques/T1087/002) Domain Account · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1110](https://attack.mitre.org/techniques/T1110) Brute Force · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1218.010](https://attack.mitre.org/techniques/T1218/010) Regsvr32

---

### C0023 — Operation Ghost
<a id="c0023"></a>

**Active:** 2013-09-01 → 2019-10-01 · **ATT&CK:** [C0023](https://attack.mitre.org/campaigns/C0023) · **8** techniques · **5** software  
**Attributed to:** G0016 APT29  

Operation Ghost was an APT29 campaign starting in 2013 that included operations against ministries of foreign affairs in Europe and the Washington, D.C. embassy of a European Union country. During Operation Ghost, APT29 used new families of malware and leveraged web services, steganography, and unique C2 infrastructure for each victim.

**Techniques:** [T1001.002](https://attack.mitre.org/techniques/T1001/002) Steganography · [T1027.003](https://attack.mitre.org/techniques/T1027/003) Steganography · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1102.002](https://attack.mitre.org/techniques/T1102/002) Bidirectional Communication · [T1546.003](https://attack.mitre.org/techniques/T1546/003) Windows Management Instrumentation Event Subscription · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1585.001](https://attack.mitre.org/techniques/T1585/001) Social Media Accounts · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware

---

### C0024 — SolarWinds Compromise
<a id="c0024"></a>

**Active:** 2019-08-01 → 2021-01-01 · **ATT&CK:** [C0024](https://attack.mitre.org/campaigns/C0024) · **71** techniques · **11** software  
**Attributed to:** G0016 APT29  

The SolarWinds Compromise was a sophisticated supply chain cyber operation conducted by APT29 that was discovered in mid-December 2020. APT29 used customized malware to inject malicious code into the SolarWinds Orion software build process that was later distributed through a normal software update; they also used password spraying, token theft, API abuse, spear phishing, and other supply chain attacks to compromise user accounts and leverage their associated access.

**Techniques:** [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1048.002](https://attack.mitre.org/techniques/T1048/002) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1069](https://attack.mitre.org/techniques/T1069) Permission Groups Discovery · [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion

---

### C0025 — 2016 Ukraine Electric Power Attack
<a id="c0025"></a>

**Active:** 2016-12-01 → 2016-12-01 · **ATT&CK:** [C0025](https://attack.mitre.org/campaigns/C0025) · **21** techniques · **1** software  
**Attributed to:** G0034 Sandworm Team  

2016 Ukraine Electric Power Attack was a Sandworm Team campaign during which they used Industroyer malware to target and disrupt distribution substations within the Ukrainian power grid. This campaign was the second major public attack conducted against Ukraine by Sandworm Team.

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1036.010](https://attack.mitre.org/techniques/T1036/010) Masquerade Account Name · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1098](https://attack.mitre.org/techniques/T1098) Account Manipulation · [T1110](https://attack.mitre.org/techniques/T1110) Brute Force · [T1136](https://attack.mitre.org/techniques/T1136) Create Account · [T1136.002](https://attack.mitre.org/techniques/T1136/002) Domain Account · [T1505.001](https://attack.mitre.org/techniques/T1505/001) SQL Stored Procedures · [T1543.003](https://attack.mitre.org/techniques/T1543/003) Windows Service · [T1554](https://attack.mitre.org/techniques/T1554) Compromise Host Software Binary · [T1562.002](https://attack.mitre.org/techniques/T1562/002) Disable Windows Event Logging

---

### C0026 — C0026
<a id="c0026"></a>

**Active:** 2022-08-01 → 2022-09-01 · **ATT&CK:** [C0026](https://attack.mitre.org/campaigns/C0026) · **6** techniques · **6** software  
**Attributed to:** unattributed  

C0026 was a campaign identified in September 2022 that included the selective distribution of KOPILUWAK and QUIETCANARY malware to previous ANDROMEDA malware victims in Ukraine through re-registered ANDROMEDA C2 domains. Several tools and tactics used during C0026 were consistent with historic Turla operations.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1030](https://attack.mitre.org/techniques/T1030) Data Transfer Size Limits · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1560.001](https://attack.mitre.org/techniques/T1560/001) Archive via Utility · [T1568](https://attack.mitre.org/techniques/T1568) Dynamic Resolution · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains

---

### C0027 — C0027
<a id="c0027"></a>

**Active:** 2022-06-01 → 2022-12-01 · **ATT&CK:** [C0027](https://attack.mitre.org/campaigns/C0027) · **28** techniques · **1** software  
**Attributed to:** G1015 Scattered Spider  

C0027 was a financially-motivated campaign linked to Scattered Spider that targeted telecommunications and business process outsourcing (BPO) companies from at least June through December of 2022. During C0027 Scattered Spider used various forms of social engineering, performed SIM swapping, and attempted to leverage access from victim environments to mobile carrier networks.

**Techniques:** [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync · [T1021.007](https://attack.mitre.org/techniques/T1021/007) Cloud Services · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1069.003](https://attack.mitre.org/techniques/T1069/003) Cloud Groups · [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts · [T1087.003](https://attack.mitre.org/techniques/T1087/003) Email Account · [T1087.004](https://attack.mitre.org/techniques/T1087/004) Cloud Account · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1098.001](https://attack.mitre.org/techniques/T1098/001) Additional Cloud Credentials · [T1098.003](https://attack.mitre.org/techniques/T1098/003) Additional Cloud Roles · [T1098.005](https://attack.mitre.org/techniques/T1098/005) Device Registration · [T1102](https://attack.mitre.org/techniques/T1102) Web Service · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1213.002](https://attack.mitre.org/techniques/T1213/002) Sharepoint · [T1219.002](https://attack.mitre.org/techniques/T1219/002) Remote Desktop Software · [T1530](https://attack.mitre.org/techniques/T1530) Data from Cloud Storage · [T1566.004](https://attack.mitre.org/techniques/T1566/004) Spearphishing Voice

---

### C0028 — 2015 Ukraine Electric Power Attack
<a id="c0028"></a>

**Active:** 2015-12-01 → 2016-01-01 · **ATT&CK:** [C0028](https://attack.mitre.org/campaigns/C0028) · **17** techniques · **2** software  
**Attributed to:** G0034 Sandworm Team  

2015 Ukraine Electric Power Attack was a Sandworm Team campaign during which they used BlackEnergy (specifically BlackEnergy3) and KillDisk to target and disrupt transmission and distribution substations within the Ukrainian power grid. This campaign was the first major public attack conducted against the Ukrainian power grid by Sandworm Team.

**Techniques:** [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1136.002](https://attack.mitre.org/techniques/T1136/002) Domain Account · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1218.011](https://attack.mitre.org/techniques/T1218/011) Rundll32 · [T1562.001](https://attack.mitre.org/techniques/T1562/001) Disable or Modify Tools · [T1566.001](https://attack.mitre.org/techniques/T1566/001) Spearphishing Attachment · [T1570](https://attack.mitre.org/techniques/T1570) Lateral Tool Transfer

---

### C0029 — Cutting Edge
<a id="c0029"></a>

**Active:** 2023-12-01 → 2024-02-01 · **ATT&CK:** [C0029](https://attack.mitre.org/campaigns/C0029) · **31** techniques · **11** software  
**Attributed to:** unattributed  

Cutting Edge was a campaign conducted by suspected China-nexus espionage actors, variously identified as UNC5221/UTA0178 and UNC5325, that began as early as December 2023 with the exploitation of zero-day vulnerabilities in Ivanti Connect Secure (previously Pulse Secure) VPN appliances. Cutting Edge targeted the U.S. defense industrial base and multiple sectors globally including telecommunications, financial, aerospace, and technology.

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1056.003](https://attack.mitre.org/techniques/T1056/003) Web Portal Capture · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.006](https://attack.mitre.org/techniques/T1070/006) Timestomp · [T1071.004](https://attack.mitre.org/techniques/T1071/004) DNS · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### C0030 — Triton Safety Instrumented System Attack
<a id="c0030"></a>

**Active:** 2017-06-01 → 2017-08-01 · **ATT&CK:** [C0030](https://attack.mitre.org/campaigns/C0030) · **10** techniques · **1** software  
**Attributed to:** G0088 TEMP.Veles  

Triton Safety Instrumented System Attack was a campaign employed by TEMP.Veles which leveraged the Triton malware framework against a petrochemical organization. The malware and techniques used within this campaign targeted specific Triconex Safety Controllers within the environment. The incident was eventually discovered due to a safety trip that occurred as a result of an issue in the malware.

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1056.003](https://attack.mitre.org/techniques/T1056/003) Web Portal Capture · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1573](https://attack.mitre.org/techniques/T1573) Encrypted Channel · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool · [T1595](https://attack.mitre.org/techniques/T1595) Active Scanning

---

### C0032 — C0032
<a id="c0032"></a>

**Active:** 2014-10-01 → 2017-01-01 · **ATT&CK:** [C0032](https://attack.mitre.org/campaigns/C0032) · **17** techniques · **1** software  
**Attributed to:** G0088 TEMP.Veles  

C0032 was an extended campaign suspected to involve the Triton adversaries with related capabilities and techniques focused on gaining a foothold within IT environments. This campaign occurred in 2019 and was distinctly different from the Triton Safety Instrumented System Attack.

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.006](https://attack.mitre.org/techniques/T1070/006) Timestomp · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1505.003](https://attack.mitre.org/techniques/T1505/003) Web Shell · [T1546.012](https://attack.mitre.org/techniques/T1546/012) Image File Execution Options Injection · [T1571](https://attack.mitre.org/techniques/T1571) Non-Standard Port · [T1572](https://attack.mitre.org/techniques/T1572) Protocol Tunneling · [T1583.003](https://attack.mitre.org/techniques/T1583/003) Virtual Private Server · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool

---

### C0033 — C0033
<a id="c0033"></a>

**Active:** 2016-05-01 → 2023-01-01 · **ATT&CK:** [C0033](https://attack.mitre.org/campaigns/C0033) · **0** techniques · **1** software  
**Attributed to:** G0056 PROMETHIUM  

C0033 was a PROMETHIUM campaign during which they used StrongPity to target Android users. C0033 was the first publicly documented mobile campaign for PROMETHIUM, who previously used Windows-based techniques.

---

### C0034 — 2022 Ukraine Electric Power Attack
<a id="c0034"></a>

**Active:** 2022-06-01 → 2022-10-01 · **ATT&CK:** [C0034](https://attack.mitre.org/campaigns/C0034) · **10** techniques · **1** software  
**Attributed to:** G0034 Sandworm Team  

The 2022 Ukraine Electric Power Attack was a Sandworm Team campaign that used a combination of GOGETTER, Neo-REGEORG, CaddyWiper, and living of the land (LotL) techniques to gain access to a Ukrainian electric utility to send unauthorized commands from their SCADA system.

**Techniques:** [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1484.001](https://attack.mitre.org/techniques/T1484/001) Group Policy Modification · [T1485](https://attack.mitre.org/techniques/T1485) Data Destruction · [T1505.003](https://attack.mitre.org/techniques/T1505/003) Web Shell · [T1543.002](https://attack.mitre.org/techniques/T1543/002) Systemd Service · [T1570](https://attack.mitre.org/techniques/T1570) Lateral Tool Transfer · [T1572](https://attack.mitre.org/techniques/T1572) Protocol Tunneling

---

### C0035 — KV Botnet Activity
<a id="c0035"></a>

**Active:** 2022-10-01 → 2024-01-01 · **ATT&CK:** [C0035](https://attack.mitre.org/campaigns/C0035) · **20** techniques · **0** software  
**Attributed to:** G1017 Volt Typhoon  

KV Botnet Activity consisted of exploitation of primarily “end-of-life” small office-home office (SOHO) equipment from manufacturers such as Cisco, NETGEAR, and DrayTek. KV Botnet Activity was used by Volt Typhoon to obfuscate connectivity to victims in multiple critical infrastructure segments, including energy and telecommunication companies and entities based on the US territory of Guam.

**Techniques:** [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1055.009](https://attack.mitre.org/techniques/T1055/009) Proc Memory · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1222.002](https://attack.mitre.org/techniques/T1222/002) Linux and Mac File and Directory Permissions Modification · [T1518.001](https://attack.mitre.org/techniques/T1518/001) Security Software Discovery · [T1546](https://attack.mitre.org/techniques/T1546) Event Triggered Execution · [T1562.001](https://attack.mitre.org/techniques/T1562/001) Disable or Modify Tools · [T1564.013](https://attack.mitre.org/techniques/T1564/013) Bind Mounts · [T1571](https://attack.mitre.org/techniques/T1571) Non-Standard Port · [T1573](https://attack.mitre.org/techniques/T1573) Encrypted Channel · [T1583.003](https://attack.mitre.org/techniques/T1583/003) Virtual Private Server · [T1584.008](https://attack.mitre.org/techniques/T1584/008) Network Devices

---

### C0036 — Pikabot Distribution February 2024
<a id="c0036"></a>

**Active:** 2024-02-01 → 2024-02-01 · **ATT&CK:** [C0036](https://attack.mitre.org/campaigns/C0036) · **4** techniques · **1** software  
**Attributed to:** unattributed  

Pikabot was distributed in Pikabot Distribution February 2024 using malicious emails with embedded links leading to malicious ZIP archives requiring user interaction for follow-on infection. The version of Pikabot distributed featured significant changes over the 2023 variant, including reduced code complexity and simplified obfuscation mechanisms.

**Techniques:** [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1566.002](https://attack.mitre.org/techniques/T1566/002) Spearphishing Link · [T1574](https://attack.mitre.org/techniques/T1574) Hijack Execution Flow

---

### C0037 — Water Curupira Pikabot Distribution
<a id="c0037"></a>

**Active:** 2023-01-01 → 2023-12-01 · **ATT&CK:** [C0037](https://attack.mitre.org/campaigns/C0037) · **10** techniques · **3** software  
**Attributed to:** unattributed  

Pikabot was distributed in Water Curupira Pikabot Distribution throughout 2023 by an entity linked to BlackBasta ransomware deployment via email attachments. This activity followed the take-down of QakBot, with several technical overlaps and similarities with QakBot, indicating a possible connection. The identified activity led to the deployment of tools such as Cobalt Strike, while coinciding with campaigns delivering DarkGate and IcedID en route to ransomware deployment.

**Techniques:** [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1204](https://attack.mitre.org/techniques/T1204) User Execution · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1218.011](https://attack.mitre.org/techniques/T1218/011) Rundll32 · [T1566.001](https://attack.mitre.org/techniques/T1566/001) Spearphishing Attachment · [T1589.002](https://attack.mitre.org/techniques/T1589/002) Email Addresses

---

### C0038 — HomeLand Justice
<a id="c0038"></a>

**Active:** 2021-05-01 → 2022-09-01 · **ATT&CK:** [C0038](https://attack.mitre.org/campaigns/C0038) · **25** techniques · **7** software  
**Attributed to:** G1001 HEXANE  

HomeLand Justice was a disruptive campaign involving the use of ransomware, wiper malware, and sensitive information leaks conducted by Iranian state cyber actors against Albanian government networks in July and September 2022. Initial access for HomeLand Justice was established in May 2021 as threat actors subsequently moved laterally, exfiltrated sensitive information, and maintained persistence for approximately 14 months prior to the attacks.

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.001](https://attack.mitre.org/techniques/T1078/001) Default Accounts · [T1087.003](https://attack.mitre.org/techniques/T1087/003) Email Account · [T1098.002](https://attack.mitre.org/techniques/T1098/002) Additional Email Delegate Permissions · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1114.002](https://attack.mitre.org/techniques/T1114/002) Remote Email Collection · [T1134.001](https://attack.mitre.org/techniques/T1134/001) Token Impersonation/Theft · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1486](https://attack.mitre.org/techniques/T1486) Data Encrypted for Impact · [T1505.003](https://attack.mitre.org/techniques/T1505/003) Web Shell · [T1561.002](https://attack.mitre.org/techniques/T1561/002) Disk Structure Wipe

---

### C0039 — Versa Director Zero Day Exploitation
<a id="c0039"></a>

**Active:** 2024-06-01 → 2024-08-01 · **ATT&CK:** [C0039](https://attack.mitre.org/campaigns/C0039) · **8** techniques · **1** software  
**Attributed to:** G1017 Volt Typhoon  

Versa Director Zero Day Exploitation was conducted by Volt Typhoon from early June through August 2024 as zero-day exploitation of Versa Director servers controlling software-defined wide area network (SD-WAN) applications. Since tracked as CVE-2024-39717, exploitation focused on credential capture from compromised Versa Director servers at managed service providers (MSPs) and internet service providers (ISPs) to enable follow-on access to service provider clients.

**Techniques:** [T1056](https://attack.mitre.org/techniques/T1056) Input Capture · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1505.003](https://attack.mitre.org/techniques/T1505/003) Web Shell · [T1573.002](https://attack.mitre.org/techniques/T1573/002) Asymmetric Cryptography · [T1584.008](https://attack.mitre.org/techniques/T1584/008) Network Devices · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware

---

### C0040 — APT41 DUST
<a id="c0040"></a>

**Active:** 2023-01-31 → 2024-06-30 · **ATT&CK:** [C0040](https://attack.mitre.org/campaigns/C0040) · **23** techniques · **4** software  
**Attributed to:** G0096 APT41  

APT41 DUST was conducted by APT41 from 2023 to July 2024 against entities in Europe, Asia, and the Middle East. APT41 DUST targeted sectors such as shipping, logistics, and media for information gathering purposes. APT41 used previously-observed malware such as DUSTPAN as well as newly observed tools such as DUSTTRAP in APT41 DUST.

**Techniques:** [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1102](https://attack.mitre.org/techniques/T1102) Web Service · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1119](https://attack.mitre.org/techniques/T1119) Automated Collection · [T1213.006](https://attack.mitre.org/techniques/T1213/006) Databases · [T1505.003](https://attack.mitre.org/techniques/T1505/003) Web Shell · [T1543.003](https://attack.mitre.org/techniques/T1543/003) Windows Service · [T1553.002](https://attack.mitre.org/techniques/T1553/002) Code Signing · [T1560.001](https://attack.mitre.org/techniques/T1560/001) Archive via Utility · [T1567.002](https://attack.mitre.org/techniques/T1567/002) Exfiltration to Cloud Storage · [T1569.002](https://attack.mitre.org/techniques/T1569/002) Service Execution · [T1573.002](https://attack.mitre.org/techniques/T1573/002) Asymmetric Cryptography · [T1574.001](https://attack.mitre.org/techniques/T1574/001) DLL · [T1583.007](https://attack.mitre.org/techniques/T1583/007) Serverless · [T1586.003](https://attack.mitre.org/techniques/T1586/003) Cloud Accounts · [T1588.003](https://attack.mitre.org/techniques/T1588/003) Code Signing Certificates

---

### C0041 — FrostyGoop Incident
<a id="c0041"></a>

**Active:** 2024-01-01 → 2024-01-01 · **ATT&CK:** [C0041](https://attack.mitre.org/campaigns/C0041) · **5** techniques · **0** software  
**Attributed to:** unattributed  

FrostyGoop Incident took place in January 2024 against a municipal district heating company in Ukraine. Following initial access via likely exploitation of external facing services, FrostyGoop was used to manipulate ENCO control systems via legitimate Modbus commands to impact the delivery of heating services to Ukrainian civilians.

**Techniques:** [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1071](https://attack.mitre.org/techniques/T1071) Application Layer Protocol · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1505.003](https://attack.mitre.org/techniques/T1505/003) Web Shell · [T1562.010](https://attack.mitre.org/techniques/T1562/010) Downgrade Attack

---

### C0042 — Outer Space
<a id="c0042"></a>

**Active:** 2021-01-01 → 2021-12-01 · **ATT&CK:** [C0042](https://attack.mitre.org/campaigns/C0042) · **8** techniques · **2** software  
**Attributed to:** G0049 OilRig  

Outer Space was a campaign conducted by OilRig throughout 2021 that used the SampleCheck5000 downloader and Solar backdoor to target Israeli organizations.

**Techniques:** [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1217](https://attack.mitre.org/techniques/T1217) Browser Information Discovery · [T1584.004](https://attack.mitre.org/techniques/T1584/004) Server · [T1585.003](https://attack.mitre.org/techniques/T1585/003) Cloud Accounts · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware

---

### C0043 — Indian Critical Infrastructure Intrusions
<a id="c0043"></a>

**Active:** 2021-01-01 → 2022-04-01 · **ATT&CK:** [C0043](https://attack.mitre.org/campaigns/C0043) · **8** techniques · **2** software  
**Attributed to:** unattributed  

Indian Critical Infrastructure Intrusions is a sequence of intrusions from 2021 through early 2022 linked to People’s Republic of China (PRC) threat actors, particularly RedEcho and Threat Activity Group 38 (TAG38). The intrusions appear focused on IT system breach in Indian electric utility entities and logistics firms, as well as potentially managed service providers operating within India.

**Techniques:** [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1568](https://attack.mitre.org/techniques/T1568) Dynamic Resolution · [T1571](https://attack.mitre.org/techniques/T1571) Non-Standard Port · [T1573.002](https://attack.mitre.org/techniques/T1573/002) Asymmetric Cryptography · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains · [T1584](https://attack.mitre.org/techniques/T1584) Compromise Infrastructure · [T1588.004](https://attack.mitre.org/techniques/T1588/004) Digital Certificates · [T1599](https://attack.mitre.org/techniques/T1599) Network Boundary Bridging

---

### C0044 — Juicy Mix
<a id="c0044"></a>

**Active:** 2022-01-01 → 2022-12-01 · **ATT&CK:** [C0044](https://attack.mitre.org/campaigns/C0044) · **14** techniques · **1** software  
**Attributed to:** G0049 OilRig  

Juicy Mix was a campaign conducted by OilRig throughout 2022 that targeted Israeli organizations with the Mango backdoor.

**Techniques:** [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1132.001](https://attack.mitre.org/techniques/T1132/001) Standard Encoding · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1217](https://attack.mitre.org/techniques/T1217) Browser Information Discovery · [T1518](https://attack.mitre.org/techniques/T1518) Software Discovery · [T1555.003](https://attack.mitre.org/techniques/T1555/003) Credentials from Web Browsers · [T1555.004](https://attack.mitre.org/techniques/T1555/004) Windows Credential Manager · [T1584.004](https://attack.mitre.org/techniques/T1584/004) Server · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware

---

### C0045 — ShadowRay
<a id="c0045"></a>

**Active:** 2023-09-01 → 2024-03-01 · **ATT&CK:** [C0045](https://attack.mitre.org/campaigns/C0045) · **10** techniques · **0** software  
**Attributed to:** unattributed  

ShadowRay was a campaign that began in late 2023 targeting the education, cryptocurrency, biopharma, and other sectors through a vulnerability (CVE-2023-48022) in the Ray AI framework named ShadowRay. According to security researchers ShadowRay was the first known instance of AI workloads being activley exploited in the wild through vulnerabilities in AI infrastructure.

**Techniques:** [T1003.008](https://attack.mitre.org/techniques/T1003/008) /etc/passwd and /etc/shadow · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1496.001](https://attack.mitre.org/techniques/T1496/001) Compute Hijacking · [T1546.004](https://attack.mitre.org/techniques/T1546/004) Unix Shell Configuration Modification · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool

---

### C0046 — ArcaneDoor
<a id="c0046"></a>

**Active:** 2023-07-01 → 2024-04-01 · **ATT&CK:** [C0046](https://attack.mitre.org/campaigns/C0046) · **25** techniques · **2** software  
**Attributed to:** unattributed  

ArcaneDoor is a campaign targeting networking devices from Cisco and other vendors between July 2023 and April 2024, primarily focused on government and critical infrastructure networks. ArcaneDoor is associated with the deployment of the custom backdoors Line Runner and Line Dancer. ArcaneDoor is attributed to a group referred to as UAT4356 or STORM-1849, and is assessed to be a state-sponsored campaign.

**Techniques:** [T1014](https://attack.mitre.org/techniques/T1014) Rootkit · [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1037](https://attack.mitre.org/techniques/T1037) Boot or Logon Initialization Scripts · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1102.003](https://attack.mitre.org/techniques/T1102/003) One-Way Communication · [T1119](https://attack.mitre.org/techniques/T1119) Automated Collection · [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1556](https://attack.mitre.org/techniques/T1556) Modify Authentication Process · [T1557](https://attack.mitre.org/techniques/T1557) Adversary-in-the-Middle · [T1562.001](https://attack.mitre.org/techniques/T1562/001) Disable or Modify Tools · [T1562.003](https://attack.mitre.org/techniques/T1562/003) Impair Command History Logging

---

### C0047 — RedDelta Modified PlugX Infection Chain Operations
<a id="c0047"></a>

**Active:** 2023-07-01 → 2024-12-01 · **ATT&CK:** [C0047](https://attack.mitre.org/campaigns/C0047) · **22** techniques · **2** software  
**Attributed to:** G0129 Mustang Panda  

RedDelta Modified PlugX Infection Chain Operations was executed by Mustang Panda from mid-2023 through the end of 2024 against multiple entities in East and Southeast Asia. RedDelta Modified PlugX Infection Chain Operations involved phishing to deliver malicious files or links to users prompting follow-on installer downloads to load PlugX on victim machines in a persistent state.

**Techniques:** [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution · [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1218.007](https://attack.mitre.org/techniques/T1218/007) Msiexec · [T1218.014](https://attack.mitre.org/techniques/T1218/014) MMC · [T1480](https://attack.mitre.org/techniques/T1480) Execution Guardrails · [T1547.001](https://attack.mitre.org/techniques/T1547/001) Registry Run Keys / Startup Folder · [T1553.002](https://attack.mitre.org/techniques/T1553/002) Code Signing · [T1564.001](https://attack.mitre.org/techniques/T1564/001) Hidden Files and Directories · [T1566.001](https://attack.mitre.org/techniques/T1566/001) Spearphishing Attachment · [T1566.002](https://attack.mitre.org/techniques/T1566/002) Spearphishing Link · [T1574.001](https://attack.mitre.org/techniques/T1574/001) DLL · [T1583.001](https://attack.mitre.org/techniques/T1583/001) Domains

---

### C0048 — Operation MidnightEclipse
<a id="c0048"></a>

**Active:** 2024-03-01 → 2024-04-01 · **ATT&CK:** [C0048](https://attack.mitre.org/campaigns/C0048) · **17** techniques · **1** software  
**Attributed to:** unattributed  

Operation MidnightEclipse was a campaign conducted in March and April 2024 that involved initial exploit of zero-day vulnerability CVE-2024-3400, a critical command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS.

**Techniques:** [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management · [T1053.003](https://attack.mitre.org/techniques/T1053/003) Cron · [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1559](https://attack.mitre.org/techniques/T1559) Inter-Process Communication · [T1584.003](https://attack.mitre.org/techniques/T1584/003) Virtual Private Server · [T1584.006](https://attack.mitre.org/techniques/T1584/006) Web Services · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool

---

### C0049 — Leviathan Australian Intrusions
<a id="c0049"></a>

**Active:** 2022-04-01 → 2022-09-01 · **ATT&CK:** [C0049](https://attack.mitre.org/campaigns/C0049) · **26** techniques · **0** software  
**Attributed to:** G0065 Leviathan  

Leviathan Australian Intrusions consisted of at least two long-term intrusions against victims in Australia by Leviathan, relying on similar tradecraft such as external service exploitation followed by extensive credential capture and re-use to enable privilege escalation and lateral movement. Leviathan Australian Intrusions were focused on exfiltrating sensitive data including valid credentials for the victim organizations.

**Techniques:** [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1056](https://attack.mitre.org/techniques/T1056) Input Capture · [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1078.003](https://attack.mitre.org/techniques/T1078/003) Local Accounts · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1111](https://attack.mitre.org/techniques/T1111) Multi-Factor Authentication Interception · [T1135](https://attack.mitre.org/techniques/T1135) Network Share Discovery · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1212](https://attack.mitre.org/techniques/T1212) Exploitation for Credential Access · [T1213.006](https://attack.mitre.org/techniques/T1213/006) Databases · [T1482](https://attack.mitre.org/techniques/T1482) Domain Trust Discovery · [T1505.003](https://attack.mitre.org/techniques/T1505/003) Web Shell · [T1528](https://attack.mitre.org/techniques/T1528) Steal Application Access Token · [T1552](https://attack.mitre.org/techniques/T1552) Unsecured Credentials

---

### C0050 — J-magic Campaign
<a id="c0050"></a>

**Active:** 2023-06-01 → 2024-06-01 · **ATT&CK:** [C0050](https://attack.mitre.org/campaigns/C0050) · **4** techniques · **1** software  
**Attributed to:** unattributed  

The J-magic Campaign was active from mid-2023 to at least mid-2024 and featured the use of the J-magic backdoor, a custom cd00r variant tailored for use against Juniper routers. The J-magic Campaign targeted Junos OS routers serving as VPN gateways primarily in the semiconductor, energy, manufacturing, and IT sectors.

**Techniques:** [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1583.003](https://attack.mitre.org/techniques/T1583/003) Virtual Private Server · [T1587.003](https://attack.mitre.org/techniques/T1587/003) Digital Certificates · [T1588.001](https://attack.mitre.org/techniques/T1588/001) Malware

---

### C0051 — APT28 Nearest Neighbor Campaign
<a id="c0051"></a>

**Active:** 2022-02-01 → 2024-11-01 · **ATT&CK:** [C0051](https://attack.mitre.org/campaigns/C0051) · **18** techniques · **2** software  
**Attributed to:** G0007 APT28  

APT28 Nearest Neighbor Campaign was conducted by APT28 from early February 2022 to November 2024 against organizations and individuals with expertise on Ukraine. APT28 primarily leveraged living-off-the-land techniques, while leveraging the zero-day exploitation of CVE-2022-38028. Notably, APT28 leveraged Wi-Fi networks in close proximity to the intended target to gain initial access to the victim environment.

**Techniques:** [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS · [T1006](https://attack.mitre.org/techniques/T1006) Direct Volume Access · [T1016.002](https://attack.mitre.org/techniques/T1016/002) Wi-Fi Discovery · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1090.001](https://attack.mitre.org/techniques/T1090/001) Internal Proxy · [T1110.003](https://attack.mitre.org/techniques/T1110/003) Password Spraying · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1560.001](https://attack.mitre.org/techniques/T1560/001) Archive via Utility · [T1561.001](https://attack.mitre.org/techniques/T1561/001) Disk Content Wipe · [T1562.004](https://attack.mitre.org/techniques/T1562/004) Disable or Modify System Firewall · [T1567](https://attack.mitre.org/techniques/T1567) Exfiltration Over Web Service · [T1584](https://attack.mitre.org/techniques/T1584) Compromise Infrastructure · [T1669](https://attack.mitre.org/techniques/T1669) Wi-Fi Networks

---

### C0052 — SPACEHOP Activity
<a id="c0052"></a>

**Active:** 2019-01-01 → 2024-05-01 · **ATT&CK:** [C0052](https://attack.mitre.org/campaigns/C0052) · **4** techniques · **0** software  
**Attributed to:** G0004 Ke3chang, G1023 APT5  

SPACEHOP Activity is conducted through commercially leased Virtual Private Servers (VPS), otherwise known as provisioned Operational Relay Box (ORB) networks. The network leveraged for SPACEHOP Activity enabled China-nexus cyber threat actors – such as APT5 and Ke3chang – to perform network reconnaissance scanning and vulnerability exploitation. SPACEHOP Activity has historically targeted entities in North America, Europe, and the Middle East.

**Techniques:** [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1583.003](https://attack.mitre.org/techniques/T1583/003) Virtual Private Server · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool

---

### C0053 — FLORAHOX Activity
<a id="c0053"></a>

**Active:** 2019-01-01 → 2024-05-01 · **ATT&CK:** [C0053](https://attack.mitre.org/campaigns/C0053) · **6** techniques · **1** software  
**Attributed to:** unattributed  

FLORAHOX Activity is conducted using a hybrid operational relay box (ORB) network, which combines two types of infrastructure: compromised devices and leased Virtual Private Servers (VPS). The compromised devices include end-of-life routers and IoT devices, while VPS space is commercially leased and managed by ORB network administrators. This hybrid ORB network allows adversaries to proxy and obscure malicious traffic, making the source of the traffic more difficult to trace.

**Techniques:** [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell · [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1583.003](https://attack.mitre.org/techniques/T1583/003) Virtual Private Server · [T1584.008](https://attack.mitre.org/techniques/T1584/008) Network Devices

---

### C0055 — Quad7 Activity
<a id="c0055"></a>

**Active:** 2023-08-01 → 2025-08-01 · **ATT&CK:** [C0055](https://attack.mitre.org/campaigns/C0055) · **15** techniques · **1** software  
**Attributed to:** unattributed  

Quad7 Activity, also known as CovertNetwork-1658 or the 7777 Botnet, is a network of compromised small office/home office (SOHO) routers. The botnet was initially composed primarily of TP-Link routers and was named Quad7 due to compromised devices exposing TCP port 7777 with the distinctive banner <code>xlogin</code>. Later activity showed a significant increase in compromised Asus routers and the addition of new ports and banners, including TCP port 63256 displaying <code>alogin</code>.

**Techniques:** [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols · [T1090.002](https://attack.mitre.org/techniques/T1090/002) External Proxy · [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1110.003](https://attack.mitre.org/techniques/T1110/003) Password Spraying · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application · [T1562.001](https://attack.mitre.org/techniques/T1562/001) Disable or Modify Tools · [T1571](https://attack.mitre.org/techniques/T1571) Non-Standard Port · [T1584.005](https://attack.mitre.org/techniques/T1584/005) Botnet · [T1584.008](https://attack.mitre.org/techniques/T1584/008) Network Devices · [T1589.002](https://attack.mitre.org/techniques/T1589/002) Email Addresses · [T1665](https://attack.mitre.org/techniques/T1665) Hide Infrastructure

---

### C0056 — RedPenguin
<a id="c0056"></a>

**Active:** 2024-07-01 → 2025-03-01 · **ATT&CK:** [C0056](https://attack.mitre.org/campaigns/C0056) · **26** techniques · **2** software  
**Attributed to:** G1048 UNC3886  

The RedPenguin project was launched by Juniper in July 2024 to investigate reported malware infections of Juniper MX Series routers. RedPenguin activity was separately attributed to UNC3886 and included the deployment of multiple custom versions of the publicly-available TINYSHELL backdoor on Juniper routers.

**Techniques:** [T1014](https://attack.mitre.org/techniques/T1014) Rootkit · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell · [T1059.008](https://attack.mitre.org/techniques/T1059/008) Network Device CLI · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.007](https://attack.mitre.org/techniques/T1070/007) Clear Network Connection History and Configurations · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1104](https://attack.mitre.org/techniques/T1104) Multi-Stage Channels · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution

---

### C0057 — 3CX Supply Chain Attack
<a id="c0057"></a>

**Active:** 2022-11-01 → 2023-03-01 · **ATT&CK:** [C0057](https://attack.mitre.org/campaigns/C0057) · **22** techniques · **1** software  
**Attributed to:** G1049 AppleJeus  

The 3CX Supply Chain Attack was the first publicly reported case of one supply chain compromise triggering another, leading to a cascading, two-stage intrusion. The initial supply chain attack began when a 3CX employee downloaded and executed a trojanized, end-of-life version of the X_Trader trading software from Trading Technologies. This provided UNC4736, a threat cluster associated with AppleJeus, access to the 3CX environment.

**Techniques:** [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.009](https://attack.mitre.org/techniques/T1027/009) Embedded Payloads · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.002](https://attack.mitre.org/techniques/T1055/002) Portable Executable Injection · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts · [T1102.001](https://attack.mitre.org/techniques/T1102/001) Dead Drop Resolver · [T1189](https://attack.mitre.org/techniques/T1189) Drive-by Compromise · [T1195.002](https://attack.mitre.org/techniques/T1195/002) Compromise Software Supply Chain · [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution · [T1217](https://attack.mitre.org/techniques/T1217) Browser Information Discovery · [T1218.007](https://attack.mitre.org/techniques/T1218/007) Msiexec · [T1218.015](https://attack.mitre.org/techniques/T1218/015) Electron Applications · [T1543.004](https://attack.mitre.org/techniques/T1543/004) Launch Daemon · [T1546.016](https://attack.mitre.org/techniques/T1546/016) Installer Packages · [T1553.002](https://attack.mitre.org/techniques/T1553/002) Code Signing · [T1559](https://attack.mitre.org/techniques/T1559) Inter-Process Communication · [T1573.001](https://attack.mitre.org/techniques/T1573/001) Symmetric Cryptography · [T1574.001](https://attack.mitre.org/techniques/T1574/001) DLL

---

### C0058 — SharePoint ToolShell Exploitation
<a id="c0058"></a>

**Active:** 2025-07-01 → 2025-07-01 · **ATT&CK:** [C0058](https://attack.mitre.org/campaigns/C0058) · **35** techniques · **4** software  
**Attributed to:** unattributed  

The SharePoint ToolShell Exploitation campaign was conducted in July 2025 and encompassed the first waves of exploitation against incompletely patched spoofing (CVE-2025-49706) and remote code execution (CVE-2025-49704) vulnerabilities affecting on-premises Microsoft SharePoint servers.

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1119](https://attack.mitre.org/techniques/T1119) Automated Collection · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application

---

### C0059 — Salesforce Data Exfiltration
<a id="c0059"></a>

**Active:** 2004-10-01 → 2025-09-01 · **ATT&CK:** [C0059](https://attack.mitre.org/campaigns/C0059) · **18** techniques · **1** software  
**Attributed to:** unattributed  

The Salesforce Data Exfiltration campaign began in October 2024 with financially-motivated threat actor UNC6040 using Spearphishing Voice (vishing) to compromise corporate Salesforce instances for large-scale data theft and extortion. Following the initial data theft, victim organizations received extortion demands from a separate threat actor, UNC6240, who claimed to be the “ShinyHunters” group.

**Techniques:** [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy · [T1213.004](https://attack.mitre.org/techniques/T1213/004) Customer Relationship Management Software · [T1567](https://attack.mitre.org/techniques/T1567) Exfiltration Over Web Service · [T1585](https://attack.mitre.org/techniques/T1585) Establish Accounts · [T1585.002](https://attack.mitre.org/techniques/T1585/002) Email Accounts · [T1586.002](https://attack.mitre.org/techniques/T1586/002) Email Accounts · [T1587.001](https://attack.mitre.org/techniques/T1587/001) Malware · [T1588.002](https://attack.mitre.org/techniques/T1588/002) Tool · [T1598.004](https://attack.mitre.org/techniques/T1598/004) Spearphishing Voice · [T1608.005](https://attack.mitre.org/techniques/T1608/005) Link Target · [T1656](https://attack.mitre.org/techniques/T1656) Impersonation · [T1671](https://attack.mitre.org/techniques/T1671) Cloud Application Integration

---

