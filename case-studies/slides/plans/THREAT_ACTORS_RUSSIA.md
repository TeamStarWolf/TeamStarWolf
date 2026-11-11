# Slide plan: Russia-Attributed Threat Actors: The Public Record

- Study: case-studies/THREAT_ACTORS_RUSSIA.md
- Cover title: Russia-Attributed / Threat Actors / The Public Record
- Subtitle: Three GRU units, the SVR, two FSB centers and a defense institute, 2003 to 2026
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/THREAT_ACTORS_RUSSIA.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Behind the nicknames, governments have named the paying customer

- Joint advisories map tracked groups to named units: GRU Units 26165, 74455 and 29155, the SVR, FSB Centers 16 and 18, and TsNIIKhM.
- The court record is deep: US grand juries charged GRU, FSB and TsNIIKhM personnel from 2018 to 2024.
- The way in is ordinary: all 26 advisory-named CVEs are in KEV, and a 2018 Cisco flaw was still exploited in 2025.
- The services overlap: ESET read the December 2025 Poland attack as Sandworm; CERT Polska saw Static Tundra overlap.
- Healthcare meets espionage, collateral damage and sector lists; hospital disruption came from criminals and hacktivists.
Caption: Grades: the government, court and ATT&CK record is Confirmed; press items and ATT&CK summaries of indictments are Reported.
Notes: Unit mapping from AA22-110A, AA23-129A, AA23-341A and AA24-249A [30][38][40][51]. Indictments [7][9][14][29][39][52]. KEV and Smart Install [92][56]. Poland: ESET at medium confidence, CERT Polska, then the UK-EU attribution to FSB Centre 16 in July 2026 [79][58][61]. Healthcare reading Inferred from [12][50][32][51][62][33][34].

## KEY FACTS | Seven named state bodies, six indictments and 330 techniques

Stat: 7 | state bodies governments name behind the groups
Stat: 6 | US indictments, 2018 to 2024
Stat: 26 | advisory-named CVEs, all in KEV
Stat: 330 | Enterprise techniques in the study layer
- Earliest dated activity: Snake development from late 2003, per nine agencies; APT28 and Turla since at least 2004.
- KEV marks 11 of the 26 CVEs for known ransomware campaign use.
- The 330 split: 252 recorded at group level, 41 only on campaigns, 37 only in advisories.
- Latest record: the UK-EU attribution of the Poland attack and the 19-agency router advisory, 13 July 2026.
Notes: Seven bodies: GRU Units 26165, 74455 and 29155, the SVR, FSB Centers 16 and 18, TsNIIKhM [30][51]. Indictments of 2018-07-13, 2018-10-03, 2020-10-15, announced 2022-03-24, 2023-12-05 and announced 2024-09-05 [7][9][14][29][39][52]. KEV catalog 2026.11.03 [92]. ATT&CK v20.0 footprint across nine groups, eight campaigns and eight advisories [100]. Earliest [38][80][83]. Latest [61][62].

## PART 1 | Governments draw the unit map, and vendor names hang off it

| Service | Unit as governments name it | Community names | ATT&CK |
|---|---|---|---|
| GRU | 85th GTsSS, Unit 26165 | APT28, Fancy Bear, Forest Blizzard | G0007 |
| GRU | GTsST, Unit 74455 | Sandworm, APT44, Seashell Blizzard | G0034 |
| GRU | 161st Center, Unit 29155 | Ember Bear, Cadet Blizzard | G1003 |
| SVR | Foreign Intelligence Service | APT29, Cozy Bear, Midnight Blizzard | G0016 |
| FSB | Center 16, Unit 71330 | Dragonfly, Berserk Bear; Turla and Snake | G0035, G0010 |
| FSB | Center 18, Unit 64829 | Star Blizzard, COLDRIVER | G1033 |
| MoD | TsNIIKhM | TEMP.Veles, the Triton operators | G0088 |
Caption: AA24-249A warns vendor names may not map one-to-one; the FBI calls Berserk Bear and Dragonfly related clusters.
Notes: Unit map [30][55][60][80][10][15][71][82][51][86][19][22][45][81][38][56][83][84][40][85][17]. Gamaredon tied to Center 18 by Ukraine's government only, Reported [85][99]. France names GRU Unit 20728 [53]. ATT&CK's own wording falls into four tiers, an Inferred reading of [80] to [90]. UAC-0056 sits on both Ember Bear and Saint Bear [93][86][51]; separate but related clusters [56].

## PART 2 | Three GRU units ran election hacks, grid attacks and WhisperGate

Left: Unit 26165 (APT28)
- Bundestag (2015), DNC and DCCC (2016), the OPCW (2018) and Paris 2024, per the UK.
- Jaguar Tooth on Cisco routers through CVE-2017-6742: about 250 Ukrainian victims.
- AA25-141A: logistics and technology firms in 13 countries since 2022.
Right: Units 74455 and 29155
- 74455: BlackEnergy (230,000 without power), Industroyer, NotPetya, Olympic Destroyer.
- 74455 likely supported the hacktivist front CARR (AA25-343A).
- 29155: WhisperGate from 13 January 2022; 14,000+ scans across 26+ NATO members.
Caption: Five Unit 29155 officers and a civilian are wanted; Rewards for Justice offers up to $10 million.
Notes: APT28 [60][36][37][55][59]; WADA and anti-doping [1][9][106]. Sandworm summarized from its home study SANDWORM_OPERATIONS.md [60][3][4][14][107][71][57]. Unit 29155 [51][52][86][31]; WhisperGate is not unique to the unit per AA24-249A [51].

## PART 2 | The SVR works identity, while the FSB works devices and inboxes

Left: SVR (APT29)
- SolarWinds: 16,000+ affected systems; the US named the SVR on 15 April 2021.
- COVID-19 vaccine research targeted in Canada, the US and the UK, 2020.
- TeamCity CVE-2023-42793 from September 2023: a few dozen companies.
- A password spray of a Microsoft legacy test tenant reached senior leadership email.
Right: FSB Centers 16 and 18
- Center 16 runs Snake, which nine agencies call the FSB's most sophisticated espionage tool.
- Center 16 copied router configurations through CVE-2018-0171 and SNMP, 2025 to 2026.
- Center 18's Star Blizzard steals session cookies that defeat ordinary MFA.
- Microsoft seized 66 Star Blizzard domains and DOJ 41 more in October 2024.
Notes: SVR [19][20][21][12][13][22][42][68][70][43][45][73][75]. Center 16 [38][56][62][61][74][77]. Center 18 [40][41][39][72][78]. Gamaredon, Center 18 per Ukraine only, Reported [85][99].

## PART 2 | Criminals and hacktivists sit right next to the state units

- Treasury calls Trickbot Russia-based, with members associated with the Russian Intelligence Services.
- Treasury designated Dmitry Khoroshev, leader of the Russia-based LockBit group, on 7 May 2024.
- HC3 says KillNet's ties to the FSB or SVR are unconfirmed.
- AA25-343A: Unit 74455 likely supported CARR, and the Kremlin-linked CISM created NoName057(16).
- Void Blizzard, Saint Bear and Winter Vivern are Russia-nexus, with no government-named service.
Caption: FIN5, Nomadic Octopus and RedCurl are described only by language, and language is not attribution.
Notes: Trickbot [34]. LockBit [48]. KillNet [33]. CARR and NoName057(16), targets water, food and agriculture, and energy [57]. Void Blizzard [76]; Saint Bear [88]; Winter Vivern [89]. Wizard Spider and Indrik Spider as ATT&CK records them, Reported [93].

## PART 3 | Twenty-three years of operations, from Snake to Polish wind farms

| Date | Event |
|---|---|
| Late 2003 | FSB begins developing Snake as "Uroburos" |
| Dec 2015 | Unit 74455's BlackEnergy attack; 230,000 lose power |
| 2016 | Unit 26165's DNC and DCCC intrusions |
| Jun 2017 | NotPetya; US and UK attribute it on 15 Feb 2018 |
| 2019 to 2021 | SVR SolarWinds compromise; 16,000+ systems |
| 2020 | APT29 targets COVID-19 vaccine research |
| 13 Jan 2022 | Unit 29155's WhisperGate against Ukraine |
| 24 Feb 2022 | Viasat KA-SAT disrupted about an hour before the invasion |
| 29 Dec 2025 | Poland: RTUs damaged at 30+ wind and PV farms |
| 13 Jul 2026 | UK-EU attribution to FSB Centre 16; joint sanctions |
Caption: Eras: quiet espionage, disruption (2015 to 2018), the SVR named (2019 to 2021), war and identity, then routers.
Notes: Rows [38][60][82][2][66][7][3][4][19][81][12][13][51][31][79][58][61][62][63]. Era reading from the study's own Part 3 summary. Poland record lives in ICS_ATTACKS_AND_ADVISORIES_2024_2026.md.

## PART 4 | Grand juries charged GRU, FSB and TsNIIKhM staff, no SVR officer

| Date | Court | Defendants | Conduct charged |
|---|---|---|---|
| 13 Jul 2018 | D.C. | 12 GRU officers | 2016 election hack-and-leak |
| 3 Oct 2018 | W.D. Pa. | 7 GRU officers | USADA, WADA and others |
| 15 Oct 2020 | W.D. Pa. | 6 GRU officers | Ukraine, NotPetya, Olympics |
| 24 Mar 2022 | Not stated | 4 government employees | Energy sector, safety systems |
| 5 Dec 2023 | N.D. Cal. | FSB officer and affiliate | Spear-phishing for intelligence |
| 5 Sep 2024 | Not stated | 5 Unit 29155 officers, civilian | WhisperGate; $10M reward |
Caption: Sanctions add TsNIIKhM (2020), six technology firms (2021) and 24 UK designations in the first joint UK-EU package (2026).
Notes: Indictments [7][8][9][106][14][107][29][39][52]; 2022-03-24 and 2024-09-05 are announcement dates. Justice Department releases did not load; the FBI wanted notices are cited instead. Sanctions [17][20][41][61][34][48]. Disruptions [44][72].

## PART 4 | Confidence firmed from "most likely" to formal attribution

| Date | Source | Actor and event | Wording |
|---|---|---|---|
| 27 Oct 2014 | FireEye | APT28 | "most likely" Russian government |
| 15 Feb 2018 | US and UK | Russian military, NotPetya | NCSC: almost certainly |
| 15 Apr 2021 | US and UK | SVR, SolarWinds | High confidence; highly likely |
| 20 Apr 2022 | Five Eyes | Unit map, AA22-110A | Center 16: almost certainly |
| 18 Apr 2023 | UK and US | Unit 26165, Jaguar Tooth | Almost certainly |
| 7 Dec 2023 | UK and partners | FSB Centre 18 | Almost certainly subordinate |
| 13 Jul 2026 | UK and EU | FSB Centre 16, Poland | Formal attribution |
Caption: Microsoft's breach posts said "Russian state-sponsored" and left naming the SVR to governments.
Notes: Statements [65][3][4][19][21][30][37][40][41][61][63][68]. The firming trend is Inferred. Storm-2372 moved from moderate-confidence Russia-aligned (2025) to a Midnight Blizzard sub-cluster (2026) [75]. Dragonfly moved from Symantec naming (2018) to Center 16 [5][30][61].

## PART 5 | All 26 advisory-named CVEs are in KEV, and old ones still work

Stat: 26 | CVEs in five advisories and an FBI notice
Stat: 11 | marked in KEV for known ransomware use
Stat: 13 | named in AA22-011A alone
Stat: 18 yrs | age of CVE-2008-4128 when KEV added it
- CVE-2018-0171 (Cisco Smart Install) was in KEV from 3 November 2021 and still exploited by FSB Center 16 in August 2025.
- The target class is the edge: VPNs, mail and collaboration, TeamCity, Dahua cameras, Cisco and TP-Link routers.
- Unit 26165 used the Outlook NTLM flaw CVE-2023-23397 (AA25-141A).
Caption: The gap was patching, not knowledge (Inferred).
Notes: Advisories [26][16][42][51][55][56]; KEV catalog version 2026.11.03 [92]. CVE-2008-4128 entered KEV on 13 July 2026 with AA26-194A [62]. Other primaries [37][97][59]. NCSC 2020 names four of the same CVEs for APT29 [12].

## PART 6 | Healthcare meets state espionage and criminal disruption

Stat: 90+ | KillNet DDoS attacks on 28 January 2023
Stat: 16+ | Conti attacks on US healthcare and first responders
Stat: 40,000 | Merck computers hit by NotPetya (Reported)
- APT29 targeted COVID-19 vaccine research in Canada, the US and the UK in 2020.
- SVR TeamCity exploitation reached billing and medical-device software makers.
- AA24-249A and AA26-194A list healthcare among target or most-at-risk sectors.
- Trickbot forced three Minnesota facilities to divert ambulances.
Caption: No government document opened attributes a disruptive hospital attack to a Russian state unit (Inferred).
Notes: KillNet wave, 55% on health systems [35]. Conti in a year [23]. Merck press account [104]. Vaccine research [12][13]. TeamCity [42]. Sector lists [26][51][62]. Trickbot [34]. NotPetya collateral per HC3 [32]. HSE review [25]. AA20-302A [18].

## MITRE MAPPINGS | 330 techniques, and six of eight advisories state T1190

| Id | Technique | Groups of 9 |
|---|---|---|
| T1005 | Data from Local System | 7 |
| T1059.001 | PowerShell | 7 |
| T1588.002 | Tool | 7 |
| T1566.001 | Spearphishing Attachment | 6 |
| T1105 | Ingress Tool Transfer | 6 |
| T1190 | Exploit Public-Facing Application | 5 |
Caption: Layer scores mark evidence: 100 advisory-named (154 of 330), 60 ATT&CK-recorded, 30 for the two inferences. MITRE notice in notes.
Notes: Most widely recorded across nine groups, ATT&CK v20.0 [101]. T1190 in six of eight advisories, an Inferred count. Tactic tally Stealth 49, Persistence 42, Privilege Escalation 36 [100]. Inferred T1602.002 and T1557 [56][62][77][59]. ICS techniques for Sandworm, Dragonfly and TEMP.Veles [95][100]. Revoked T1070.001 is now T1685.005 [100]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Patch the edge, retire old routers and close identity gaps

Left: Harden
- Patch KEV first, then every CVE these advisories name.
- Disable Smart Install, SNMPv1 and v2c and Telnet; block TCP 4786.
- Phishing-resistant MFA; disable dormant accounts; audit app-only mail rights.
- Block outbound SMB and NTLM; plan NTLM retirement.
Right: Watch
- Password spraying, impossible travel and atypical user agents.
- EDR going silent on mail servers and domain controllers.
- Memory analysis for kernel implants such as Snake.
- Unexpected controller reboots in OT.
Caption: Identity findings such as "account without MFA" belong in the same backlog as CVEs (Inferred).
Notes: Hardening [30][51][42][6][56][45][55][69]. Hunting [26][45][42][38][69]. Validation against each advisory's technique list [51][42]. VM reading Inferred from [26][51][55][42][56][92].

## CROSS-CUTTING THEMES | Attribution reaches the top rungs, yet the doors stay ordinary

- **Attribution is a ladder.** Units, officers and organisations are named; carry the rung with the name.
- **Services overlap.** Experienced analysts assigned the 2025 Poland attack to two different services.
- **The edge is the battlefield.** Routers, VPNs, mail, cameras and CI servers recur from 2018 to 2026.
- **Fronts and criminals blur the line.** CARR, Trickbot and KillNet sit beside the units.
- **Understated: patch debt and identity.** Old KEV entries, end-of-life gear and conditions with no CVE.
Notes: Ladder and overlap [79][58][61][51]. Edge, Inferred from Part 5. Fronts [57][34][33]. Patch debt [92][56][6][62]; identity [45][69]. Overstated: state units as hospital attackers, vendor names as units, KillNet's own claims [33][35][51][56]. Legal action has not stopped the tempo (Inferred).
