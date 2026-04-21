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
| APT28 | [G0007](https://attack.mitre.org/groups/G0007/) | Fancy Bear, STRONTIUM, Sofacy | Government, military, elections, NATO | DNC hack (2016), Bundestag hack (2015), Olympic Destroyer (2018) |
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
---

## Russian Threat Actors (Deep Dive)

### Sandworm (GRU Unit 74455)
- Attribution: Russian GRU, most destructive cyber unit in history
- Notable operations: Ukraine power grid (2015, 2016), NotPetya ($10B+ damage), Olympic Destroyer (Pyeongchang 2018 false flag), VPNFilter botnet (500K routers), Prestige ransomware (2022), Industroyer2 (2022), Cyclops Blink
- Signature TTPs: wiper malware, destructive ICS attacks, supply chain compromise, false flag operations mimicking other APT groups
- Primary targets: Ukrainian government/infrastructure, NATO countries, global collateral damage
- Detection: Monitoring for Industroyer IOCs, VPNFilter C2 domains, GRU infrastructure patterns

### APT28 / Fancy Bear (GRU Unit 26165)
- Attribution: Russian GRU military intelligence
- Notable operations: DNC hack (2016), Bundestag hack (2015), WADA Olympic doping records, SolarWinds supply chain (suspected), Fancy Bear anti-doping campaign
- Signature TTPs: X-Agent implant, Sofacy/CHOPSTICK malware, spearphishing with zero-days, credential harvesting, Responder tool usage
- Primary targets: Political parties, government agencies, defense contractors, sports/anti-doping organizations

### APT29 / Cozy Bear (SVR)
- Attribution: Russian SVR (Foreign Intelligence Service)
- Notable operations: DNC hack (2016), SolarWinds/SUNBURST (2020), COVID-19 vaccine research theft, Microsoft breach (2024 — Midnight Blizzard/Nobelium)
- Signature TTPs: SUNBURST backdoor, TEARDROP in-memory loader, WellMess, BEATDROP, Cobalt Strike with malleable C2, living-off-the-land, patient long-term access
- Primary targets: Government, defense, think tanks, pharma/biotech, cloud providers

### Turla (FSB)
- Attribution: Russian FSB
- Notable operations: Uroburos/Snake rootkit (30+ countries), Carbon backdoor, KazVar backdoor, hijacked Iranian APT infrastructure for operations
- Signature TTPs: Rootkit-level persistence, satellite C2, watering hole attacks, Snake malware framework, using compromised Komodo C2 from OilRig

---

## Chinese Threat Actors (Deep Dive)

### APT41 / Winnti Group (Double Dragon)
- Attribution: Chinese MSS-sponsored, dual nexus (espionage + cybercrime)
- Notable operations: BARIUM/LEAD supply chain attacks, video game gold farming, ShadowPad, 2020 DOJ indictment (five Chinese nationals), Pulse Secure VPN exploitation
- Signature TTPs: ShadowPad modular implant, Winnti malware, supply chain compromise of software vendors, DLL side-loading, rootkit deployment
- Primary targets: Healthcare, pharma, gaming, media, semiconductors

### Volt Typhoon (Vanguard Panda)
- Attribution: Chinese state-sponsored, PRC
- Notable operations: US critical infrastructure pre-positioning (2023-present), Guam military networks, living-off-the-land confirmed by CISA/NSA/FBI joint advisory
- Signature TTPs: Zero use of custom malware (LOL only), KV-Botnet SOHO router proxy network, LOTL (wmic, netsh, ntdsutil, certutil), web shells on edge devices
- Primary targets: US military bases, communications infrastructure, power grid, water — pre-positioning for potential conflict

### APT10 / Stone Panda / MenuPass
- Attribution: Chinese MSS (Tianjin State Security Bureau)
- Notable operations: Cloud Hopper (2016-2018) — massive MSP supply chain attack compromising hundreds of downstream enterprises, US Navy contractor breach (614GB stolen)
- Signature TTPs: MSP targeting for downstream access, PlugX/RedLeaves/UPPERCUT, spearphishing, VPN exploitation

---

## North Korean Threat Actors

### Lazarus Group (Bureau 121)
- Attribution: North Korean RGB (Reconnaissance General Bureau)
- Notable operations: Sony Pictures hack (2014), Bangladesh Bank SWIFT heist ($81M), WannaCry (2017), Crypto exchange thefts ($3B+ since 2017), Bybit hack (2025, $1.5B)
- Signature TTPs: Destructive wiper + SWIFT malware + ransomware across different operations, BLINDINGCAN, COPPERHEDGE, AppleJeus cryptocurrency theft tool
- Financial motivation: Crypto theft directly funds DPRK weapons programs

### APT38 (Financial crimes sub-unit)
- Specialized in SWIFT manipulation and bank heist operations
- $1.2B+ stolen from banks globally

---

## Iranian Threat Actors

### APT33 / Refined Kitten (IRGC)
- Notable operations: Shamoon wiper attacks against Saudi Arabia (2012, 2016-2017), TRITON/TRISIS ICS attack on Saudi petrochemical plant (shared with APT34)
- Signature TTPs: Shamoon wiper, StoneDrill, TURNEDUP backdoor, spearphishing via LinkedIn impersonation

### APT34 / OilRig (Ministry of Intelligence)
- Notable operations: DNS hijacking campaign, supply chain via IT providers, Turla/Snake C2 infrastructure hijacking, QUADAGENT, RDAT backdoor using Exchange email for C2
- Primary targets: Government, financial, energy sectors across Middle East

---

## Ransomware Groups Reference

| Group | Active Period | RaaS? | Notable Victims | Takedown Status | Key TTPs |
|---|---|---|---|---|---|
| LockBit | 2019–present | Yes | Royal Mail, ICBC, Boeing | Disrupted Feb 2024 (Op Cronos), rebuilt; operators indicted | Double extortion, affiliate model, ESXi attacks |
| ALPHV/BlackCat | 2021–2024 | Yes | MGM Resorts ($100M+), Change Healthcare | Disbanded 2024; FBI seized infra, exit scam | Rust-based ransomware, triple extortion |
| Conti | 2020–2022 | Yes | HSE Ireland, Broward County schools | Disbanded 2022; playbooks leaked; members joined BlackBasta/Royal | Cobalt Strike, Ryuk successor |
| REvil/Sodinokibi | 2019–2021 | Yes | Kaseya VSA (1500+ orgs), JBS Foods | Seized Nov 2021; members arrested in Russia (2022) | Supply chain, auction-based extortion |
| DarkSide/BlackMatter | 2020–2021 | Yes | Colonial Pipeline ($4.4M ransom) | Rebranded after Colonial Pipeline pressure; BlackMatter successor also shutdown | Affiliate RaaS, ESXi, double extortion |
| Cl0p | 2019–present | No (FIN11 nexus) | MOVEit campaign (2023, 2000+ orgs), GoAnywhere, Accellion | Active | MFT zero-day exploitation specialty |
| Scattered Spider / 0ktapus | 2022–present | Affiliate | MGM, Caesars, ~130 orgs | Members arrested 2023-2024 (English-speaking, UG) | Social engineering, MFA fatigue, helpdesk vishing |
| Akira | 2023–present | Yes | Stanford, Cisco | Active | Conti successor TTP overlap; ESXi attacks |
| Play | 2022–present | No | Dallas, Oakland, Rackspace | Active | VMware ESXi vulns, no public leak site initially |
| Black Basta | 2022–present | Yes | Ascension Health, BACnet orgs | Active | Ex-Conti operators; QakBot distribution |

---

## Hacktivists and Other Actors

- **Anonymous**: Decentralized collective with no persistent infrastructure. Key operations: Operation Payback (RIAA/MPAA 2010), HBGary Federal hack (2011 — exposed HB Gary's plans against WikiLeaks), OpRussia (2022 Ukraine war). Capability varies widely by participant.
- **Lapsus$**: South American teenager-led group (2021-2022). Hit Microsoft, Okta, Nvidia, Samsung, T-Mobile via social engineering and MFA fatigue attacks — no traditional malware. Several members arrested in UK and Brazil (2022).
- **GhostSec**: Initially anti-ISIS hacktivists; shifted to pro-Russian/anti-NATO stance during Ukraine war; associated with ransomware operations in 2023.
- **KillNet**: Pro-Russian hacktivist collective conducting DDoS campaigns against NATO member websites, hospitals, and government portals during Ukraine conflict. Limited persistent impact beyond availability disruption.
- **IT Army of Ukraine**: Volunteer cyber force targeting Russian infrastructure, organized via Telegram; coordinated DDoS and data exfiltration against Russian state entities.


---

## Related Resources
- [NOTABLE_INCIDENTS.md](NOTABLE_INCIDENTS.md) — timeline of major cyber incidents
- [MALWARE_FAMILIES.md](MALWARE_FAMILIES.md) — malware family reference by threat actor
- [IR_PLAYBOOKS.md](IR_PLAYBOOKS.md) — incident response playbooks for APT intrusions
- [DETECTION_RULES_REFERENCE.md](DETECTION_RULES_REFERENCE.md) — Sigma/YARA/Snort rules mapped to actor TTPs
- [Threat Intelligence](disciplines/threat-intelligence.md) — full discipline page with tools and methodology
- [Detection Engineering](disciplines/detection-engineering.md) — building detections from actor TTPs
- [ATT&CK Navigator](navigator/) — visualize actor coverage against your controls
- [Incident Response](disciplines/incident-response.md) — responding to APT intrusions
- [Purple Teaming](disciplines/purple-teaming.md) — emulating actor TTPs for detection validation
