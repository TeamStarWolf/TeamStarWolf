# Threat Actor Reference

A quick-reference guide to notable advanced persistent threat (APT) groups, ransomware operators, and cybercriminal organizations, mapped to their known TTPs and ATT&CK groups. For deeper intelligence, use MISP, OpenCTI, or the ATT&CK Groups catalog.

> All ATT&CK group IDs link to the official MITRE ATT&CK catalog. Attribution is based on publicly reported intelligence and is subject to revision.

---

## Nation-State APTs

### China-Nexus

| Group | ATT&CK ID | Also Known As | Primary Targets | Notable Operations |
|---|---|---|---|---|
| APT1 | [G0006](https://attack.mitre.org/groups/G0006/) | Comment Crew, Shanghai Group | Aerospace, defense, energy, telecom | Mandiant APT1 report (2013) |
| APT10 | [G0045](https://attack.mitre.org/groups/G0045/) | Stone Panda, MenuPass, Potassium | MSPs, healthcare, government | Cloud Hopper — MSP supply chain (2017) |
| APT40 | [G0065](https://attack.mitre.org/groups/G0065/) | BRONZE MOHAWK, Kryptonite Panda | Maritime, defense, aviation, universities | Exploits N-day vulns rapidly after disclosure |
| APT41 | [G0096](https://attack.mitre.org/groups/G0096/) | Winnti, Barium, Double Dragon | Gaming, healthcare, telecom, financial | Dual espionage + financial crime; supply chain |
| Volt Typhoon | [G1017](https://attack.mitre.org/groups/G1017/) | Bronze Silhouette | US critical infrastructure | LOTL techniques; pre-positioning in US infrastructure |
| Salt Typhoon | — | — | US telecom carriers | Wiretap access to US carrier infrastructure (2024) |

**Common TTPs**: Spearphishing (T1566), Valid Accounts (T1078), Living off the Land (T1059), Web Shell (T1505.003), Supply chain compromise (T1195)

---

### Russia-Nexus

| Group | ATT&CK ID | Also Known As | Primary Targets | Notable Operations |
|---|---|---|---|---|
| APT28 | [G0007](https://attack.mitre.org/groups/G0007/) | Fancy Bear, STRONTIUM, Sofacy | Government, military, elections, NATO | DNC hack (2016), Olympic Destroyer, SolarWinds (adjacent) |
| APT29 | [G0016](https://attack.mitre.org/groups/G0016/) | Cozy Bear, NOBELIUM, The Dukes | Government, think tanks, healthcare | SolarWinds SUNBURST (2020), Microsoft breach (2024) |
| Sandworm | [G0034](https://attack.mitre.org/groups/G0034/) | Voodoo Bear, ELECTRUM | Critical infrastructure, Ukraine | NotPetya (2017), Ukraine power grid (2015/2016), Industroyer |
| Turla | [G0010](https://attack.mitre.org/groups/G0010/) | Snake, Venomous Bear, Waterbug | Governments, embassies, military | 25+ year campaign; satellite C2; Snake malware (dismantled 2023) |
| Gamaredon | [G0047](https://attack.mitre.org/groups/G0047/) | Primitive Bear, ACTINIUM | Ukraine government | High-volume spearphishing, persistent access to Ukrainian entities |

**Common TTPs**: Spearphishing (T1566), credential theft (T1003), supply chain (T1195), destructive malware (T1485), living off the land

---

### North Korea-Nexus

| Group | ATT&CK ID | Also Known As | Primary Targets | Notable Operations |
|---|---|---|---|---|
| Lazarus Group | [G0032](https://attack.mitre.org/groups/G0032/) | Hidden Cobra, Zinc, APT38 (financial subgroup) | Crypto, financial, defense | Sony hack (2014), Bangladesh Bank heist ($81M, 2016), WannaCry (2017) |
| Kimsuky | [G0094](https://attack.mitre.org/groups/G0094/) | Thallium, Black Banshee | Government, think tanks, South Korea, academia | Spearphishing for intelligence collection |
| Andariel | [G0138](https://attack.mitre.org/groups/G0138/) | Silent Chollima | Healthcare, defense, financial | Ransomware (Maui), ATM cashout schemes |

**Common TTPs**: Social engineering (T1566), credential theft, crypto theft (T1657), destructive malware, watering hole (T1189)

---

### Iran-Nexus

| Group | ATT&CK ID | Also Known As | Primary Targets | Notable Operations |
|---|---|---|---|---|
| APT33 | [G0064](https://attack.mitre.org/groups/G0064/) | Elfin, Refined Kitten | Aerospace, energy, petrochemical | Shamoon-adjacent; Saudi Arabia targeting |
| APT34 | [G0049](https://attack.mitre.org/groups/G0049/) | OilRig, Helix Kitten, CHRYSENE | Middle East financial, government, energy | DNSpionage, QUADAGENT backdoor |
| APT35 | [G0059](https://attack.mitre.org/groups/G0059/) | Charming Kitten, Phosphorus, TA453 | Journalists, activists, nuclear researchers | Password spray, phishing for credentials |
| Volt Typhoon lookalike | — | Cyber Av3ngers (IRGC) | US water/wastewater systems | Unitronics PLC exploitation (2023) |

**Common TTPs**: Password spray (T1110), spearphishing (T1566), web shell (T1505.003), DNS tunneling (T1071.004), destructive wipers

---

## Ransomware Groups

| Group | Status | Notable Attacks | Ransomware | Notes |
|---|---|---|---|---|
| LockBit | Disrupted (2024 Operation Cronos) | Royal Mail, ICBC, Boeing | LockBit 3.0 | Most prolific RaaS 2022–2024; rebuilt post-disruption |
| ALPHV / BlackCat | Dismantled (FBI, Dec 2023) | MGM Resorts ($100M+), Caesars, Change Healthcare | BlackCat/ALPHV | Rust-based ransomware; triple extortion |
| Clop | Active | MOVEit (2023 — 2,000+ orgs), GoAnywhere, Accellion | Cl0p | Specializes in MFT zero-day exploitation |
| Black Basta | Active | Ascension Health, BACnet organizations | Black Basta | Ex-Conti operators; QAKBOT distribution |
| RansomHub | Active | 200+ orgs (2024) | RansomHub | Launched Feb 2024; targeting critical infrastructure |
| Scattered Spider | Active | MGM Resorts, Caesars, ~130 orgs | ALPHV affiliate | Social engineering specialists; vishing IT helpdesks |
| Play | Active | Dallas, Oakland, Rackspace | Play | Targeting VMware ESXi vulnerabilities |
| Royal | Believed merged into BlackSuit | Dallas city government | Royal | Ex-Conti members; Batloader distribution |

**Common TTPs**: Initial access via T1566/T1133/T1190, credential access (T1003/T1110), lateral movement, data exfiltration before encryption (T1048), T1486 (encryption), T1489 (service stop), double/triple extortion

---

## Financial Crime Groups

| Group | ATT&CK ID | Specialty | Notable Operations |
|---|---|---|---|
| FIN7 | [G0046](https://attack.mitre.org/groups/G0046/) | POS malware, ransomware affiliate | Hundreds of US restaurant/hotel POS systems; Carbanak operator |
| FIN8 | [G0061](https://attack.mitre.org/groups/G0061/) | POS, financial sector | Sardonic backdoor; targeting Citrix/F5 vulnerabilities |
| Carbanak | [G0008](https://attack.mitre.org/groups/G0008/) | Bank fraud, SWIFT manipulation | ~$1B stolen from banks via SWIFT fraud |
| Evil Corp | [G0119](https://attack.mitre.org/groups/G0119/) | Banking trojans, ransomware | Dridex banking trojan, WastedLocker, Hades ransomware; OFAC-sanctioned |

---

## ATT&CK Group Catalog

MITRE maintains the authoritative group catalog at:

[https://attack.mitre.org/groups/](https://attack.mitre.org/groups/)

Use filters for country attribution, associated software, and technique mapping.

---

## Threat Intelligence Tools for Actor Tracking

| Tool | Type | Use |
|---|---|---|
| [MISP](https://www.misp-project.org/) | OSS | IOC sharing, event correlation, actor tagging |
| [OpenCTI](https://www.opencti.io/) | OSS | Structured intel, STIX 2.1, actor profiles |
| [Maltego](https://www.maltego.com/) | COM | Relationship graphing, attribution pivot |
| [Mandiant Advantage](https://www.mandiant.com/advantage) | COM | Premium threat intelligence feeds |
| [Recorded Future](https://www.recordedfuture.com/) | COM | Real-time threat intelligence, actor tracking |
| [Crowdstrike Intelligence](https://www.crowdstrike.com/adversary-intelligence/) | COM | Adversary intelligence, eCrime/nation-state |
| [VirusTotal Intelligence](https://www.virustotal.com/) | COM/Free | File/URL analysis, actor infrastructure tracking |
| [AlienVault OTX](https://otx.alienvault.com/) | Free | Community threat intelligence, IOC feeds |

---

## Key Intelligence Reports

| Report | Publisher | Significance |
|---|---|---|
| APT1 Report | Mandiant (2013) | First major public attribution to China PLA Unit 61398 |
| SUNBURST Analysis | Multiple (2020) | SolarWinds supply chain analysis; APT29/NOBELIUM |
| Viasat Hack | CISA/NCSC (2022) | Russian wiper attack on satellite during Ukraine invasion |
| Operation Cronos | NCA/FBI/Europol (2024) | LockBit infrastructure seizure and operator indictments |
| Scattered Spider Indictments | DOJ (2023) | English-speaking social engineering group indictments |
| CISA KEV Catalog | CISA (ongoing) | Known exploited vulnerabilities database |

---

## TLP and Sharing Frameworks

Threat intelligence is shared under the **Traffic Light Protocol (TLP)**:

| TLP Color | Sharing Scope |
|---|---|
| TLP:RED | Not for disclosure; restricted to named recipients only |
| TLP:AMBER | Limited to the organization and need-to-know clients |
| TLP:AMBER+STRICT | Limited to the organization only |
| TLP:GREEN | Community sharing; not publicly posted |
| TLP:WHITE / TLP:CLEAR | Unrestricted public sharing |

**Intelligence sharing platforms**: ISACs (sector-specific), MISP communities, FS-ISAC, MS-ISAC, CISA AIS (Automated Indicator Sharing)

---

## Related Resources
- [Threat Intelligence](disciplines/threat-intelligence.md) — full discipline page with tools and methodology
- [Detection Engineering](disciplines/detection-engineering.md) — building detections from actor TTPs
- [ATT&CK Navigator](navigator/) — visualize actor coverage against your controls
- [Incident Response](disciplines/incident-response.md) — responding to APT intrusions
- [Purple Teaming](disciplines/purple-teaming.md) — emulating actor TTPs for detection validation
