# Slide plan: APT41: The Public Record, 2012 to 2026

- Study: case-studies/APT41_PUBLIC_RECORD.md
- Cover title: APT41 / The Public Record / 2012 to 2026
- Subtitle: Espionage and profit, supply chains, cloud command channels and firmware, under a dozen names
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/APT41_PUBLIC_RECORD.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | One intrusion set has mixed espionage and crime since 2012

- Game studios lost source code and code-signing certificates in the early 2010s; software vendors' update channels shipped backdoors in 2017 and 2018.
- Three US indictments in 2019 and 2020 charged five men in China and two Malaysian businessmen over intrusions from about 2011 into 2020.
- FireEye assessed with high confidence that the group runs state-sponsored espionage alongside financially motivated activity.
- Its tradecraft holds steady: supply-chain compromise, stolen certificates, fast exploitation and, from 2022, command and control in mainstream cloud services.
- The name is not one thing: seven vendors and ATT&CK each draw the boundary in a different place.
Caption: Grades: court, ATT&CK and vendor records are Confirmed; press coverage of the arrests and the COVID relief fraud is Reported.
Notes: Early record [28][60]. Indictments [60][61][62]. FireEye high confidence [18]. Tradecraft each Confirmed in vendor primaries [22][23][25][56]; consistency across fourteen years is Inferred. Vendor boundaries [16][43][7][1]; the conclusion is Inferred. Evidence grade from the study's executive summary.

## KEY FACTS | Three indictments, an ATT&CK record and a dozen vendor names

Stat: 102 | technique and sub-technique IDs on ATT&CK G0096
Stat: 33 | ATT&CK software objects attributed to the group
Stat: 3 | US indictments, 2019 and 2020
Stat: 15 | exploited CVEs now in the KEV catalog
- ATT&CK object G0096, version 4.2; associated groups Wicked Panda, Brass Typhoon and BARIUM; campaigns C0017 and C0040.
- Active since at least 2012 (FireEye, ATT&CK); Google renamed it SPIRE CASTLE in July 2026.
- Latest public activity: the BlackX UEFI bootkit against diplomatic agencies in Central Asia (Kaspersky, medium confidence, 22 October 2026).
Notes: 102 IDs, 82 direct and 20 through campaigns [1][77]. 33 software objects [1]. Indictments of 15 August 2019, 11 August 2020 and 18 August 2020 [60][61][62]. KEV list: eleven CVEs plus four older Office and ActiveX CVEs [75]. SPIRE CASTLE [27]. BlackX [31].

## PART 1 | A dozen names, and each vendor draws the line differently

| Name | Vendor | What the vendor's page says |
|---|---|---|
| APT41 | FireEye, now Mandiant | Espionage plus profit, high confidence; activity from 2012 |
| SPIRE CASTLE, HOODOO | Google | New 2026 name for APT41; also tracked as HOODOO |
| Brass Typhoon (BARIUM) | Microsoft | Mapped to APT41; Leopard Typhoon (LEAD) is a separate row |
| Grayfly, Blackfly | Symantec | Grayfly is the espionage arm; Blackfly, the crime arm, tracked apart |
| Earth Baku | Trend Micro | Attacks under the alias APT41; Earth Longzhi a subgroup |
| BRONZE ATLAS | Secureworks | A wider cluster operating since at least 2007 |
Caption: ATT&CK keeps APT41, Winnti Group and Axiom as three objects and records the overlap in prose; a tool hit is a lead, not an attribution.
Notes: Vendor rows [18][27][23][16][43][45][39][40][46]. WICKED PANDA (CrowdStrike) [47]; RedGolf (Recorded Future) [48]; Group-IB alias list [49]; ESET Winnti Group [36][34][35][37]. ATT&CK associated groups and the Winnti Group overlap [1][5][7]. The boundary comparison is Inferred from the rows.

## PART 2 | Games and certificates came first, then two missions at once

Left: 2010 to 2014: games and certificates
- Kaspersky's 2013 report: at least 35 online-game companies hit, source code and code-signing certificates stolen.
- The 2019 indictment's video game conspiracy starts no later than November 2014.
- Game-company certificates still turn up in the 2024 DUST report.
Right: 2014 to 2019: espionage and profit together
- FireEye found the two motivations balanced concurrently from 2014 onward.
- Gaming operations peaked between 18:00 and 07:00 UTC+8, which FireEye called some indication of moonlighting.
- One intrusion stole data from a healthcare target while trying ransomware at a game studio.
Caption: The indictments add game-currency fraud, crypto-jacking and ransomware against a non-profit, a real estate developer and a Taiwanese energy company.
Notes: Kaspersky Winnti report [28]. Video game conspiracy [60]. DUST certificates [22]. Dual mission and the timing analysis, which FireEye cautions is not a daily schedule [18]. Indictment allegations [61][62].

## PART 2 | Software update channels shipped the backdoors

| Date | Target | FireEye rating (2019) | Other primaries |
|---|---|---|---|
| 2014-12 | Southeast Asian game distributor (SOGU) | Possibly APT41 or close affiliate | |
| 2017-03 | CCleaner | Unconfirmed APT41 | SentinelOne: "allegedly" BARIUM |
| 2017-07 | NetSarang (ShadowPad) | Confirmed APT41 | Kaspersky: no actor named |
| 2018-06 to 11 | ASUS Live Update (ShadowHammer) | Stage 1 unconfirmed; stage 2 confirmed | Kaspersky: no APT41 attribution |
| 2018-07 | Game distributor (CRACKSHOT) | Confirmed APT41 | |
| To 2019-03 | Two games and a platform in Asia | Not rated | ESET: likely Winnti Group |
Caption: Follow-on payloads were limited to chosen machines by matching individual system identifiers (FireEye).
Notes: Supply-chain table [18][52][29][32][33]. NetSarang nssock2.dll signed with NetSarang's own certificate [29]. Payload targeting [18]. The 2019 indictment also alleges a modified vendor's software, 2011 to 2018 [60].

## PART 2 | Indictments came in 2019 and 2020, and the tempo held

| Date | Event |
|---|---|
| 7 Aug 2019 | FireEye publishes APT41: A Dual Espionage and Cyber Crime Operation |
| 15 Aug 2019 | D.C. grand jury indicts Zhang Haoran and Tan Dailin |
| Early 2020 | Global exploitation wave against Citrix, Cisco and Zoho |
| Mar to May 2020 | Ransomware through Zoho access (indictment allegation) |
| Aug 2020 | Indictments of three Chengdu 404 staff and two SEA Gamer Mall executives |
| May 2021 to Feb 2022 | C0017: at least six US state government networks compromised |
| 2023 to mid-2024 | C0040, APT41 DUST, in shipping, logistics, media and technology |
Caption: HHS HC3 told the health sector in 2022 that the indictments did not hinder APT41 as it moved into 2021.
Notes: FireEye report [17][18]. Indictments [60][61][62]. 2020 wave [20][51]. Ransomware allegations [61]. Arrests in Malaysia Reported [63]. C0017 [21][2]. C0040 [22][3]. HC3 [65].

## PART 2 | Command moved into the cloud and implants into firmware

Left: Cloud-service command and control
- GC2 took commands from Google Sheets (HOODOO, 2022).
- TOUGHPROGRESS used Google Calendar (2024); Google took down the calendars.
- DUST-era data left through OneDrive (2023 to 2024).
- MoonWalk and GearDoor used Google Drive.
Right: Boot and firmware persistence
- ROCKBOOT: an MBR bootkit, deployed on a limited basis.
- MoonBounce: a UEFI implant in CORE_DXE, spring 2021.
- BlackX: a UEFI bootkit abusing CVE-2022-21894, early 2026.
Caption: Egress controls that trust Google, Microsoft and Cloudflare traffic by default miss this group's command channels.
Notes: GC2 [25]. TOUGHPROGRESS and the takedown [23]. OneDrive [22]. MoonWalk, Zscaler moderate confidence [53]; GearDoor, Check Point Silver Dragon, likely within the APT41 umbrella [56]. ROCKBOOT [18]. MoonBounce, medium to high confidence [30]. BlackX, medium confidence [31]. Egress point from the executive summary.

## PART 3 | One tool is not one actor: ShadowPad shows why

Stat: 8 | groups ATT&CK now links to ShadowPad
Stat: 15 | groups mapped to PlugX in the library data
Stat: 19+ | code-signing certificates abused (FireEye, 2019)
- ATT&CK says ShadowPad was first identified in the NetSarang compromise and was once thought to be APT41's alone.
- SentinelOne calls it a privately sold platform that succeeded PlugX in 2015.
- GTIG narrows the field: POISONPLUG.SHADOW appears restricted to APT41-associated clusters, protected by the ScatterBrain compiler.
Caption: A tool hit is a lead; variant-level detail can narrow the field.
Notes: ShadowPad groups [11]. PlugX in library data [77]. At least 19 certificates [18]; DUST certificates [22]. SentinelOne [52]. GTIG POISONPLUG.SHADOW and ScatterBrain [24].

## PART 4 | Exploitation runs in hours, and the KEV catalog can lag by years

Stat: 23 days | from Confluence CVE-2019-3396 disclosure to use
Stat: Hours | from the Log4Shell advisory to exploitation
Stat: ~3.5 yrs | from USAHerds zero-day use to KEV listing
- Citrix CVE-2019-19781, Pulse Secure CVE-2019-11510 and Zoho CVE-2020-10189 in the 2020 wave and indictment.
- USAHerds CVE-2021-44207: first exploited July 2021, vendor patch around 15 November 2021, added to KEV 23 December 2024.
- The driver flaw CVE-2019-16098 and the boot-manager flaw CVE-2022-21894 are not in KEV at all.
Caption: A KEV-only patch policy would have missed both the USAHerds window and the two flaws outside the catalog.
Notes: Confluence [18]. Log4Shell and USAHerds [21]. KEV dates and ransomware fields, catalog version 2026.11.03 [75]. NVD CWE fields [76]. 2020 wave and indictment [20][61]. The policy reading is Inferred from Part 4.

## PART 5 | Telecoms, healthcare and government recur as the map widens

- FireEye's cumulative 2012 to 2019 list covers healthcare, high tech, media, pharmaceuticals, telecoms, education and video games in 14 countries and Hong Kong.
- The 2020 indictment alleges over 100 victims, including universities in Hong Kong and Taiwan and government entities in Vietnam, India and the UK.
- MESSAGETAP read SMS traffic for chosen numbers on a telecom's servers in 2019.
- 2023 to 2024: shipping, logistics, media and automotive, mostly in Italy, Spain, Taiwan, Thailand, Turkey and the UK.
- Early 2026: diplomatic agencies in Tajikistan, Uzbekistan and Turkmenistan.
Caption: The geography widens from East and Southeast Asia to Europe, the Middle East and, by 2026, Central Asia (Inferred).
Notes: FireEye targets [18]. Indictment victims [61]. MESSAGETAP [19]. DUST [22]. BlackX [31]. Earth Baku expansion to Italy, Germany, the UAE and Qatar [42]. The widening reading is Inferred from the Part 5 table.

## PART 6 | Courts, advisories and takedowns are all on the record

Left: United States
- Three D.C. indictments: 19-cr-274, 1:20-cr-00158 and 1:20-cr-00166.
- The FBI lists five men as part of a group "known as APT 41 and BARIUM".
- CISA AA20-275A named APT41 exploiting Citrix, Cisco and Zoho.
- Microsoft's civil action 1:17-cv-1224, titled Barium.
Right: Elsewhere
- Taiwan's MJIB tied ransomware at CPC Corp to the Winnti Group in 2020.
- Singapore's IMDA summarized the TOUGHPROGRESS report for its sector.
- Germany's BfV warned industry of WinNTI attacks in 2019 without naming APT41.
- A GOV.UK search for APT41 returned no results.
Caption: The 2020 indictment alleges Jiang said in 2012 chats he was close to the Ministry of State Security; an allegation, not a finding of tasking.
Notes: Indictments [60][61][62]. FBI listing [64]. AA20-275A [66]. Microsoft civil action [59][16]. Taiwan, Reported [70]. IMDA [72]. BfV [73]; the APT41 link is Inferred. GOV.UK [74]. MSS chat allegation [61].

## MITRE MAPPINGS | 102 ATT&CK techniques, plus vendor-stated and inferred additions

| Id | Technique | Tie to the APT41 record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | C0017; the 2020 wave; Group-IB 2021 |
| T1195.002 | Compromise Software Supply Chain | FireEye 2019 report |
| T1553.002 | Code Signing | FireEye 2019; C0040 DUST |
| T1102.001 | Dead Drop Resolver | FireEye 2019; C0017 |
| T1542.003 | Bootkit | ROCKBOOT, FireEye 2019 |
| T1505.003 | Web Shell | C0017 and C0040 |
| T1102.002 | Bidirectional Communication | Inferred: Calendar, Sheets and Drive C2 |
Caption: Navigator layer scores: 100 for ATT&CK v20.0 records, 60 for vendor-stated IDs, 30 for this study's inferences. MITRE notice in the notes.
Notes: 102 group-page IDs, three parent techniques from the campaign pages, 8 vendor-stated and 11 inferred [1][2][3][53][56][72]. Tactic tally: Stealth 20, Persistence 13, Discovery 13, Execution 11, Command and Control 11 [1][77]. No Mobile or ICS technique is mapped [1]. Rows [18][20][21][22][49][23][25][53][56]. Revoked T1574.002 and T1562.001 shown as T1574.001 and T1685 [77]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Hunt the published artifacts and inspect the trusted channels

Left: Hunting leads from the primaries
- java.exe spawning cmd.exe or bitsadmin.exe; certutil downloads.
- schtasks /change on existing SYSTEM tasks; SAM and SYSTEM hive copies.
- ping to attacker subdomains carrying hex-encoded data.
- Tomcat Manager web shells; Google Calendar API traffic from workstations.
Right: Controls that hold
- Patch internet-facing apps on an exploitation clock, not a scoring clock.
- Baseline which hosts talk to Google, OneDrive and Cloudflare Workers.
- Treat code signing as a claim to verify; revoke abused certificates.
- Put firmware and boot integrity in scope for high-value hosts.
Caption: The library's D3FEND data has no countermeasure for code signing, DGAs or dead drop resolvers, so those need controls outside the mapping.
Notes: Leads [20][21][22][23][53]. Published YARA and detection content [20][21][22][23]. Recommendations from the study's top recommendations, Inferred from [21][75]. Certificates [18][22]. D3FEND gaps for T1553.002, T1588.003, T1568.002, T1102.001 [77]. Firmware countermeasures D3-SFV and D3-BA.

## CROSS-CUTTING THEMES | Attribution is a ladder, not a label

- **Carry the rung.** A grand jury's allegation, FireEye's "high confidence", Kaspersky's "medium" and Check Point's "likely" are different claims.
- **Names fragment faster than activity.** One intrusion can carry four names in four reports; check each vendor's boundary before merging indicators.
- **Trust relationships are the attack surface.** Update channels, signing certificates, customer accounts and cloud APIs all carried access or concealment.
- **Legal action did not change the tempo.** Indictments, arrests, a civil action and takedowns are on the record, and the reporting runs through 2026.
- **Know which count you use.** The ATT&CK group page shows 102 techniques, the library's direct relationship 82, because of campaign roll-up.
Notes: Confidence ladder [18][30][31][53][56][48]. Names, Inferred. Trust relationships [18][61][22][23]. Tempo, Inferred from the Part 2 timeline. Counts [1][77]. Shared tools [11][24].
