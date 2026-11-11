# Slide plan: China-Attributed Threat Actors: The Public Record

- Study: case-studies/THREAT_ACTORS_CHINA.md
- Cover title: China-Attributed / Threat Actors / The Public Record
- Subtitle: Military units, State Security bureaus and the companies that work for them, 2006 to 2026
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/THREAT_ACTORS_CHINA.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | "Chinese hackers" are dozens of clusters with named sponsors

- The sponsor picture is unusually specific: PLA units, five State Security bureaus, the Ministry of Public Security and twelve companies.
- Tradecraft moved to the network edge: routers, VPN concentrators and firewalls, then living off the land.
- The mission widened to pre-positioning: AA24-038A assessed with high confidence that Volt Typhoon was pre-positioning to disrupt OT in a crisis.
- Healthcare and life sciences recur, from Anthem in 2014 to a medical research campaign that ran into 2025.
Caption: Grades: indictments, sanctions and joint advisories are Confirmed; China's counter-narrative and some press accounts are Reported.
Notes: Sponsors and companies [18][20][21][24][28][35][42][52]. Edge shift [29][31][33][53]; 43 initial-access CVEs all in KEV [100]. AA24-038A, co-released with partners in Australia, Canada, the UK and New Zealand [33]. Healthcare [23][56][87][26][78][80]. Evidence grades from the executive summary.

## KEY FACTS | Forty-seven ATT&CK groups and a decade of charges

Stat: 47 | of 178 ATT&CK Enterprise groups attributed to China
Stat: 13 | US charging announcements, 2014 to 2025
Stat: 5 | Treasury designation actions, 2024 to 2025
Stat: 43 | advisory-named entry CVEs, all in KEV
- 320 distinct Enterprise techniques across 46 groups; the most shared is T1105 Ingress Tool Transfer (23 groups).
- Largest footprints: Mustang Panda (85 techniques), APT41 (82) and Volt Typhoon (81).
- Longest dwell: at least five years in some Volt Typhoon victims; a 393-day average across BRICKSTORM intrusions.
- Largest healthcare theft: about 78.8 million people's records from Anthem, 2014 to 2015.
Notes: Group counts at ATT&CK v20.0; Scarlet Mimic set aside for the technique analysis, leaving 46 [1][3]. Footprints [8][9][10]. Charging announcements, 19 May 2014 to 8 July 2025 [18][19][20][21][23][24][26][27][28][34][42][47][52]. OFAC actions, 25 March 2024 to 5 March 2025 [35][43][44][46][49]. KEV [100]. Dwell [33][70]. Anthem [23][89].

## PART 1 | ATT&CK names three PLA units and three MSS ties, hedging the rest

Left: Named sponsors in ATT&CK
- APT1 (G0006): PLA Unit 61398.
- Putter Panda (G0024): PLA Unit 61486, 12th Bureau.
- Naikon (G0019): Chengdu Military Region bureau, MUCD 78020.
- APT3, Leviathan and menuPass: tied to the MSS or its bureaus.
Right: Weak wording to carry forward
- Scarlet Mimic: motives overlap, not directly linked.
- Rocke: an alleged Chinese-speaking cryptojacker.
- LuminousMoth: Chinese-speaking; RedEcho: PRC-related.
- None of the 47 appears in the ICS or Mobile group files.
Caption: Eleven China-linked ATT&CK campaigns have no group object, from Night Dragon (2009) to an AI-orchestrated campaign (2025).
Notes: Inventory, 47 of 178 groups at commit e85b559 [1]. Sponsor wording [1]. ICS and Mobile [7]. Groups left out for target-only or no China wording, such as APT18 and Tropic Trooper [1]. Campaigns C0002 to C0062 [2]. MirrorFace under the menuPass umbrella [1].

## PART 2 | Governments name the PLA, five MSS bureaus and the MPS

| State body | Unit, bureau or company | Linked actor | First named |
|---|---|---|---|
| PLA | Unit 61398 | APT1 (G0006) | 19 May 2014 |
| PLA | 54th Research Institute | Equifax; no group | 10 Feb 2020 |
| MSS | Tianjin bureau, Huaying Haitai | APT10 (G0045) | 20 Dec 2018 |
| MSS | Hainan bureau, Hainan Xiandun | APT40 (G0065) | 19 Jul 2021 |
| MSS | Hubei bureau, Wuhan Xiaoruizhi | APT31 (G0128) | 25 Mar 2024 |
| MSS | Shanghai bureau, Shanghai Powerock | HAFNIUM (G0125) | 8 Jul 2025 |
| MPS | Sichuan Silence | Sophos zero-day | 10 Dec 2024 |
Caption: The Jiangsu bureau worked through recruited hackers and insiders; the other four bureaus through named companies.
Notes: Sponsor table [18][24][21][22][28][29][35][52][42][43]. Jiangsu officers Zha Rong and Chai Meng, 30 October 2018 [20]. Salt Typhoon companies linked to PLA units and the MSS [53][46]. i-Soon to MSS and MPS [47][48][96].

## PART 2 | Contractors and brokers carry much of the load

Stat: 43 | MSS or MPS bureaus i-Soon sold data to
Stat: 31 | provinces those bureaus covered
Stat: $75K | top price per inbox (from USD 10,000)
Stat: 260,000+ | devices in the Integrity Tech botnet
- Fronts set up by a bureau: Wuhan Xiaoruizhi (2010) and Hainan Xiandun.
- Firms selling services or data: i-Soon, Sichuan Silence and Zhou Shuai's Shanghai Heiying.
- Infrastructure vendors: Integrity Technology Group and the three Salt Typhoon companies.
- The FBI says the MSS and MPS use private InfoSec companies.
Caption: Sixteen agencies believe covert device networks serve most China-linked actors and are built by Chinese security firms.
Notes: Fronts [35][28]. i-Soon, 43 bureaus in 31 provinces at USD 10,000 to 75,000 per inbox [47]. Zhou Shuai and Shanghai Heiying [49]. Integrity Tech botnet over 260,000 devices as of June 2024 [39]. Salt Typhoon companies [53]. FBI March 2025 [48]. NCSC and 15 partners, April 2026 [74].

## PART 3 | Two decades of charges, advisories and disruptions

| Date | Event |
|---|---|
| 19 Feb 2013 | Mandiant ties APT1 to PLA Unit 61398 |
| 19 May 2014 | Five Unit 61398 officers indicted, 31 counts |
| 20 Dec 2018 | APT10 indictment; UK and allies name the MSS |
| 19 Jul 2021 | US, EU, UK and NATO attribute Exchange; APT40 unsealed |
| Dec 2023 | Court-authorized KV Botnet removal |
| 7 Feb 2024 | AA24-038A on Volt Typhoon pre-positioning |
| 5 Mar 2025 | i-Soon, MPS officers and APT27 actors charged |
| 27 Aug 2025 | AA25-239A: 23 agencies in 13 countries on Salt Typhoon |
| 8 Oct 2026 | AA26-281A on actors enabled by Integrity Tech |
Caption: The record runs from menuPass activity in 2006 to a GTIG report on ARMORY CASTLE in October 2026.
Notes: Rows [55][18][21][22][90][60][28][29][30][32][33][47][48][49][53][80][81]. menuPass since 2006 [16]. ARMORY CASTLE BeyondTrust zero-day [82]. Xu Zewei arrested in Milan on 3 July 2025 [52]; extradition Reported [92].

## PART 4 | The bureau cases set the template: indict, name, sanction

| Actor | ATT&CK | What the record shows |
|---|---|---|
| APT1 | G0006 | 141 victims since 2006; 3,000+ indicators; five officers indicted |
| APT10, menuPass | G0045 | MSPs and 45+ US tech firms; Cloud Hopper (BAE, 2017) |
| APT40, Leviathan | G0065 | Hainan bureau via Hainan Xiandun, 2011 to 2018 |
| APT31, ZIRCONIUM | G0128 | 14 years, 10,000+ emails; Czech attribution 2025 |
| APT27 and i-Soon | G0027, G0143 | Data sold to 43 bureaus; health systems targeted |
| HAFNIUM | G0125 | Exchange zero-days; 12,700+ US victims per FBI |
Caption: Equifax followed the same pattern with a different PLA body: about 145 million Americans' data.
Notes: APT1 [55][18]. APT10 [16][21][58][90][22]. APT40 [14][28][87][29][37]. APT31 [34][35][36][50][51][65]. APT27 and i-Soon [13][47][96][49]. HAFNIUM [59][60][30][52][69]. Equifax [24]. APT41 summarized from its home study [9][27][86].

## PART 4 | Volt Typhoon moved the mission to pre-positioning

Stat: 5+ yrs | footholds held in some victims
Stat: High | confidence of pre-positioning (AA24-038A)
Stat: Moderate | Microsoft's earlier confidence on intent
- Microsoft introduced it on 24 May 2023: active since mid-2021, targeting US critical infrastructure including Guam.
- Entry through internet-facing Fortinet devices; traffic proxied through compromised ASUS, Cisco, D-Link, NETGEAR and Zyxel SOHO gear.
- In December 2023 a court-authorized operation removed KV Botnet malware from hundreds of US routers, mostly end-of-life.
- Targets named in AA24-038A: Communications, Energy, Transportation and Water.
Caption: China's CVERC calls Volt Typhoon a US false flag, seen only through state media (Reported).
Notes: Microsoft [62]. AA23-144A [31]. KV Botnet and Wray's pre-positioning remark [32]. AA24-038A, CVE-2022-42475 on a FortiGate 300D [33]. ATT&CK campaigns C0035 and C0039 [10]. CVERC [63].

## PART 4 | Salt Typhoon, Flax Typhoon and UNC5221 live on the edge

Left: Telecoms and botnets
- Salt Typhoon took call records and court-ordered request data from multiple telecoms (FBI and CISA, Nov 2024).
- AA25-239A names three companies; no zero-day use was observed.
- Integrity Tech ran a botnet of over 260,000 devices, sold through KRLab; sanctioned by OFAC and the UK.
Right: Edge zero-days
- UNC5221 exploited Ivanti CVE-2025-0282 from mid-December 2024.
- BRICKSTORM intrusions averaged 393 days of dwell; CISA, NSA and Canada call it PRC state-sponsored.
- UNC3886 put TINYSHELL-based backdoors on Juniper MX routers in mid-2024.
Caption: Flax Typhoon, UNC5221 (now ARMORY CASTLE), Storm-0558 and UNC6508 have no ATT&CK group object.
Notes: Salt Typhoon [67][40][41][46][53][12]. Integrity Tech [38][39][44][74][80]. UNC5221 [68]. BRICKSTORM [70][73]. ARMORY CASTLE [82]. UNC3886 [71][15]. No group object [1][6]. UNC2814 and GRIDTIDE, 53 confirmed victims in 42 countries [75].

## PART 5 | Healthcare is a target for research and identity data

Stat: 78.8M | people's records stolen from Anthem
Stat: 4.5M | people in the Community Health Systems breach
Stat: 9 | ATT&CK groups with health or life-sciences targeting
- APT40 stole Ebola virus and vaccine research, 2011 to 2018.
- Li Xiaoyu, Dong Jiazhi and Xu Zewei targeted COVID-19 vaccine, testing and research work in 2020.
- UNC6508 broke into a medical research institution's REDCap server, 2023 to 2025 (GTIG, high confidence).
- AA26-281A in October 2026 names US Healthcare and Public Health victims.
Caption: No source here attributes a disruptive or ransomware attack on a hospital to a Chinese state actor (Inferred).
Notes: Anthem [23][89]. CHS, APT18 per HC3 Reported [56][83]. Nine groups [1]. APT40 [87][88]. COVID-19 [26][52][25][84]. UNC6508 [78]. AA26-281A [80]. HC3 briefings [83][85][86]. Volt Typhoon's named sectors exclude healthcare [33]. Absence of disruptive attacks Inferred from [1][23][56][78][86].

## PART 6 | Every one of the 43 advisory-named entry CVEs is in KEV

Stat: 43 | initial-access CVEs across five advisories
Stat: 29 | marked known for ransomware use
Stat: 21 | added on the catalog's first day
Stat: 48 hrs | AA24-190A window for internet-facing fixes
- AA22-158A names Cisco, Citrix, Fortinet, Pulse, QNAP and other network-device CVEs.
- AA25-239A names CVE-2024-21887, CVE-2024-3400, CVE-2023-20198, CVE-2023-20273 and CVE-2018-0171.
- Zero-days in vendor reports: Exchange (2021), Ivanti CVE-2025-0282, Juniper CVE-2025-21590 and BeyondTrust (2026).
Caption: The most shared software: Net (15 of 46 groups), Mimikatz (14), PlugX and Cobalt Strike (12 each).
Notes: KEV catalog version 2026.11.03, 1,767 entries; first day 3 November 2021 [100]. Advisories [97][99][33][37][53]. Zero-days [59][68][71][72][82]. Silk Typhoon CVE list [69]. Integrity Tech appendix of 67 CVE entries [39]. Shared software [3].

## PART 7 | Governments attribute in different degrees of confidence

| Date | Government | Confidence words |
|---|---|---|
| 20 Dec 2018 | UK and allies, APT10 | "highest level of probability" |
| 19 Jul 2021 | US with EU, UK, NATO, Exchange | "high degree of confidence" |
| 25 Mar 2024 | UK, APT31 and Electoral Commission | "almost certain"; "highly likely" |
| 8 Jan 2025 | Japan, MirrorFace | suspected Chinese involvement |
| 28 May 2025 | Czech Republic, APT31 | National attribution; "most likely" |
| 23 Apr 2026 | UK with 15 partners, covert networks | "believed" |
| 8 Oct 2026 | Seven countries, Integrity Tech | "consistent with" Flax Typhoon |
Caption: Three court-authorized or court-ordered actions took infrastructure away: NICKEL sites, KV Botnet and Integrity Tech.
Notes: Statements [22][60][36][65][45][50][51][74][80][81]. Japan's wording is the study's translation. Disruptions [61][32][38]; the August 2026 QTFY seizure affidavit [94], seizure count Reported [95]. OFAC [35][43][44][46][49].

## MITRE MAPPINGS | 77 advisory-named techniques, led by tool transfer

| Rank | Id | Technique | Groups of 46 |
|---|---|---|---|
| 1 | T1105 | Ingress Tool Transfer | 23 |
| 2 | T1059.001 | PowerShell | 21 |
| 3 | T1588.002 | Tool | 21 |
| 4 | T1059.003 | Windows Command Shell | 20 |
| 6 | T1566.001 | Spearphishing Attachment | 19 |
| 10 | T1190 | Exploit Public-Facing Application | 17 |
Caption: The Navigator layer holds 77 advisory-named techniques at score 100; no ICS or Mobile technique is bound. MITRE notice in notes.
Notes: Most shared, ATT&CK v20.0, 320 distinct techniques across 46 groups [3][101]. In the 15 closest-profiled groups, T1190 holds at 10 while phishing falls to 6 [3]; the shift reading is Inferred. Advisory techniques [29][31][33][37][53][97]. D3FEND: three advisories name 55 countermeasures, 40 with library pages [53][97][93][5]. CWE not bound (not checked). Revoked T1070.001 is now T1685.005 and T1562.004 is now T1686 [4]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Patch the edge first and watch network devices as hosts

Left: Watch
- Configuration drift on routers and firewalls; verify firmware and image hashes.
- NTDS.dit copying and LSASS access; every Security log clear.
- Living-off-the-land command lines, VPN impossible travel, web shells.
Right: Harden
- Patch internet-facing KEV entries within the 48-hour window.
- Replace end-of-life SOHO and edge equipment.
- Isolate management on its own VRF or out-of-band network.
- Hospitals: inventory REDCap and audit MSP and RMM access.
Caption: Zero-days such as CVE-2025-0282 are the residual risk; the advisories answer them with monitoring and isolation (Inferred).
Notes: Detection threads, an Inferred synthesis of [29][31][33][37][41][53][97]. Hardening [33][37][53][97][99][32][39]. VM view [37][100][68][82]. Hospitals [78][69][87][49].

## CROSS-CUTTING THEMES | Companies do the state's work, and the edge replaced the inbox

- **The state works through companies.** Fronts, contractors and infrastructure vendors recur across a decade of indictments and sanctions.
- **The edge replaced the inbox.** From spearphishing in AA21-200A to router CLIs and configuration dumps in AA25-239A.
- **Infrastructure is borrowed or bought.** Botnets and covert networks mean a source address says little about who is behind it.
- **Names disagree on the record.** Silk Typhoon is HAFNIUM to ATT&CK and Microsoft, but APT27 actors to the FBI.
- **Understated: dwell time and research theft.** Five-year footholds; the health record is research and identity data.
Notes: Companies [21][28][35][52][47][42][44][46]; sanctions as a lever Inferred from [52][92]. Edge [29][53]. Infrastructure [32][38][76][74]. Names [1][48][68][69][70][53]. Overstated: "Chinese hackers" as one actor, and novelty [41][53]. Dwell [33][70]. Health [87][23][78][80].
