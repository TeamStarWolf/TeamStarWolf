# China-Attributed Threat Actors: The Public Record

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [The SharePoint ToolShell Mass Exploitation](/case-studies/SHAREPOINT_TOOLSHELL_2025.md)

## Executive summary

When defenders, journalists and governments talk about "Chinese hackers", they are describing dozens of distinct clusters with different sponsors, different missions and very different evidence behind them. Some are military units named in a US indictment more than a decade ago. Some are Ministry of State Security bureaus working through front companies. Some are private contractors that sell stolen mailboxes by the inbox, and some are botnet operators whose customers are other hacking teams. This study pulls the public record on the main ones into one place: who the governments of the United States, the United Kingdom, Japan, the Czech Republic, Australia and their partners have named, on what date, with what confidence, and what the advisories say the actors actually did.

Four patterns stand out. First, the sponsor picture is now unusually specific. US charging documents, Treasury designations and joint advisories name PLA Unit 61398 and the PLA 54th Research Institute, five provincial or municipal State Security bureaus (Jiangsu, Tianjin, Hainan, Hubei, Shanghai), the Ministry of Public Security, and twelve companies that hacked, brokered data or ran infrastructure for them. Second, the tradecraft has moved to the network edge. The 2021 advisories still describe spearphishing and watering holes; the 2023 to 2025 advisories on Volt Typhoon and Salt Typhoon describe routers, VPN concentrators, firewalls and living off the land with built-in tools, and every one of the 43 initial-access CVEs named across five joint advisories is in CISA's Known Exploited Vulnerabilities catalog. Third, the purpose has widened from espionage to pre-positioning: in February 2024 a group of US and partner agencies assessed with high confidence that Volt Typhoon was positioning inside US critical infrastructure IT networks to disrupt operational technology in a crisis, with some footholds held for at least five years. Fourth, healthcare and life sciences appear throughout: from the 2014 Anthem and Community Health Systems breaches to Ebola and COVID-19 research theft, to a 2023 to 2025 campaign against medical research servers and an October 2026 advisory that names the Healthcare and Public Health sector among the targets.

Evidence grade: the indictments, sanctions, government attributions and joint advisories are **Confirmed** from the issuing agency's own page. Vendor attributions (Microsoft, Mandiant and Google Threat Intelligence Group, BAE Systems) are **Confirmed** where the vendor's own report was opened, and carry the vendor's own confidence words. The Chinese government's counter-narrative, two press accounts of an extradition and an arrest, and one press account of a 2026 seizure are **Reported**. Where this study draws its own conclusion, it is labelled **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| ATT&CK groups with a China attribution | 47 of 178 Enterprise groups in ATT&CK v20.0, as the library's data holds it; 46 once Scarlet Mimic (no government link) is set aside for the technique analysis [1][3] |
| ATT&CK for ICS and Mobile | None of the 47 appears in the ICS or Mobile group files [7] |
| Distinct Enterprise techniques across the 46 | 320; the most shared is T1105 Ingress Tool Transfer (23 groups) [3] |
| Largest technique footprints | Mustang Panda G0129 (85 techniques, 23 software), APT41 G0096 (82, 32), Volt Typhoon G1017 (81, 17) [8][9][10] |
| Sponsors named in government records | PLA Unit 61398 and the PLA 54th Research Institute; MSS State Security bureaus in Jiangsu, Tianjin, Hainan, Hubei and Shanghai; the Ministry of Public Security [18][20][21][24][28][35][42][52] |
| US charging announcements covered | 13, from 19 May 2014 (Unit 61398) to 8 July 2025 (Xu Zewei arrest) [18][19][20][21][23][24][26][27][28][34][42][47][52] |
| Treasury (OFAC) designations covered | 5 actions, 25 March 2024 to 5 March 2025 [35][43][44][46][49] |
| Court-authorized disruptions | KV Botnet (announced 31 January 2024) and the Integrity Technology Group botnet (18 September 2024); also Microsoft's court-ordered NICKEL website seizure (December 2021) [32][38][61] |
| Largest healthcare data theft in the record | About 78.8 million people's records from Anthem, 2014 to 2015 [23][89] |
| Exploited CVEs | 43 distinct initial-access CVEs across AA24-038A, AA25-239A, AA24-190A, AA22-158A and AA22-279A, all in CISA KEV; 29 marked known for ransomware use [100] |
| Longest dwell in the record | At least five years in some Volt Typhoon victims [33]; a 393-day average across BRICKSTORM intrusions [70] |
| Government time-to-mitigate benchmark | Patch or mitigate internet-facing devices within 48 hours (AA24-190A) [37] |

### Key findings

- **The sponsor is usually named, and it is usually the MSS.** Of the government attributions in this study, the Ministry of State Security or one of its bureaus is named for APT10, APT40, APT31, HAFNIUM-related activity, the Jiangsu turbofan case and the Salt Typhoon companies; the PLA is named for APT1, the Equifax intrusion and the AA25-239A companies; the Ministry of Public Security is named for Sichuan Silence and i-Soon (Confirmed [18][20][21][24][28][35][42][47][52][53]).
- **Contractors carry much of the load.** Huaying Haitai, Boyusec, Hainan Xiandun, Wuhan Xiaoruizhi, Shanghai Powerock, Sichuan Silence, i-Soon, Shanghai Heiying, Integrity Technology Group, Sichuan Juxinhe, Beijing Huanyu Tianqiong and Sichuan Zhixin Ruijie all appear in US or partner records, and the FBI says the MSS and MPS "weaponize" InfoSec companies (Confirmed [19][21][28][35][42][47][48][49][44][53]).
- **Edge devices are the front door.** Exploit Public-Facing Application (T1190) is named in five of the six advisories whose technique lists this study verified, and it holds at 10 of the 15 groups this study profiles most closely while phishing falls to 6 of 15 in that set (Confirmed [29][31][33][37][97][3]; the reading of the shift is Inferred).
- **Pre-positioning is the new mission.** Ten agencies in five countries assessed with high confidence that Volt Typhoon is pre-positioning to disrupt OT in Communications, Energy, Transportation and Water (Confirmed [33]). Microsoft's earlier view was moderate confidence on intent (Confirmed [62]).
- **Healthcare is a recurring target, mostly for intellectual property and identity data.** The record runs from Anthem and Community Health Systems (2014) through Ebola research theft and the targeting of HIV and COVID-19 research, to UNC6508's medical research campaign (2023 to 2025) and the Healthcare and Public Health sector named in AA26-281A (October 2026) (Confirmed [23][56][87][26][78][80]).
- **Names do not line up, and the disagreements are on the record.** The FBI lists Silk Typhoon as a name for the APT27 actors Yin Kecheng and Zhou Shuai; ATT&CK and Microsoft file Silk Typhoon under HAFNIUM; Google says UNC5221 is not Silk Typhoon while Microsoft lists a UNC5221 zero-day under Silk Typhoon (Confirmed [48][1][69][70]).
- **Some of the biggest names have no ATT&CK object.** Flax Typhoon, Storm-0558, UNC5221 (now ARMORY CASTLE), UNC2814, UNC6508 and Storm-2603 have no group page in the library; Microsoft's Linen Typhoon and Violet Typhoon are filed as aliases of G0027 Threat Group-3390 and G0128 ZIRCONIUM (Confirmed [1][6]).
- **Covert networks of compromised devices are now the default infrastructure.** Sixteen agencies say such networks are believed used by the majority of China-linked actors and are built by Chinese information security companies (Confirmed [74]).

### Top recommendations

1. **Run an edge-first patch queue.** Put internet-facing VPN, firewall, router and web application CVEs from the KEV catalog at the head of the queue, and measure time-to-mitigate against the 48-hour window in AA24-190A (Confirmed [37][100]; the program rule is Inferred).
2. **Treat network devices as monitored hosts.** Baseline running configurations, verify firmware and image hashes, put management on an isolated VRF or out-of-band network, and log AAA command accounting centrally, as AA25-239A asks (Confirmed [53]).
3. **Detect living off the land on identity infrastructure.** Enable process creation with command lines and deep PowerShell logging, alert on NTDS.dit copying through ESENT events and on every Security log clear, and review VPN and RDP logons for impossible travel (Confirmed [31][33]).
4. **Retire end-of-life SOHO and edge equipment.** The KV Botnet ran mostly on end-of-life Cisco and NetGear routers, and the Integrity Tech botnet passed 260,000 devices (Confirmed [32][39]).
5. **For hospitals and research institutions: inventory research applications and third-party access.** REDCap servers were the path in UNC6508's 2023 to 2025 campaign (Confirmed [78]), and Microsoft names healthcare among the sectors Silk Typhoon targets through stolen IT provider, RMM and MSP credentials (Confirmed [69]); audit mail transport and compliance rules, which UNC6508 abused to exfiltrate mail (Confirmed [78]).
6. **Read the attribution words, not just the name.** Record each source's confidence language ("almost certain", "highly likely", "moderate confidence", "suspected") alongside the actor name in threat intelligence tickets, because the sources disagree in degree (Confirmed [30][62][70][73]; the practice is Inferred).

## Scope and method

This study covers threat actors that governments or the ATT&CK knowledge base attribute to the People's Republic of China, from the earliest activity the record dates (2006) to October 2026. It draws on US Department of Justice releases, charging documents and an affidavit; FBI wanted notices and public service announcements; Treasury OFAC press releases; CISA, NSA and FBI joint advisories and their partner co-seals; UK government and NCSC statements; the Czech government and NUKIB; Japan's National Police Agency; the Congressional Research Service; HHS's Health Sector Cybersecurity Coordination Center (HC3) briefings; vendor primary reports from Microsoft, Mandiant, Google Threat Intelligence Group (GTIG) and BAE Systems; a Community Health Systems SEC filing; the live MITRE ATT&CK group pages and the library's own ATT&CK v20.0 data files. Every source was opened on 3 November 2026. Quotations are kept to a few words.

| Grade | Meaning |
|---|---|
| Confirmed | A primary source was opened: the government agency, court or regulator, the vendor that observed the activity, the victim's own filing, or the MITRE record itself |
| Reported | Known only through a secondary source, such as press coverage or state media, whose original was not opened |
| Demonstrated | A public reproduction exists. No item here is graded Demonstrated: this study describes actors, not vulnerabilities, and no exploit repository was opened |
| Inferred | This study's own reasoning from the cited facts, labelled where it appears |

**Which groups count as China-attributed.** The inventory in Part 1 includes an ATT&CK group only when its ATT&CK description attributes it to China, the PRC, a PRC body or a Chinese-speaking operator (Confirmed [1]). Groups that ATT&CK names China only as a target, and groups whose aliases follow Panda, Dragon or Typhoon naming but whose ATT&CK description carries no China wording, are listed separately and left out of the counts. Vendor reporting probably ties several of those to China, but that was not checked against a primary source here, so they are not described as China-attributed (Inferred [1]).

**Attribution language.** Each attribution is given in the source's own words: "almost certain", "highly likely", "high confidence", "moderate confidence", "suspected", "consistent with" and "linked to" are carried through. Where two sources disagree, the study says so in the text and in Cross-cutting themes.

**Home studies.** APT41 has its own companion study, APT41: The Public Record (in review); this study summarizes it in one paragraph. The 2025 SharePoint exploitation is covered in [The SharePoint ToolShell Mass Exploitation](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), and the 2021 Exchange mass exploitation in Operation Exchange Marauder.

**Tradecraft level.** Behavior is described at the level the advisories use: technique names and ATT&CK ids. No commands, payloads or exploit details are reproduced.

**ATT&CK version.** Technique ids and tactic names follow ATT&CK v20.0 as the library holds it. Since v19, ATT&CK splits the former Defense Evasion tactic into Stealth and Defense Impairment (Confirmed [101]). Older advisories cite two ids that v20.0 revokes: T1070.001 is now T1685.005 and T1562.004 is now T1686 (Confirmed [4]).

## Part 1: who ATT&CK attributes to China

### The inventory

The library's ATT&CK v20.0 Enterprise data (commit e85b559) holds 178 groups. Forty-seven of them have an ATT&CK description that attributes them to China, the PRC, a PRC body or a Chinese-speaking operator, and each has a generated page under [/mitre/groups/](/mitre/groups/README.md) (Confirmed [1]). The library's group records carry no first-seen or last-seen field, so the "since" years below come from ATT&CK's description text; campaign dates come from campaign objects (Confirmed [7]).

| Id | Name | What ATT&CK says about the sponsor or origin | Since (ATT&CK text) | Techniques | Software |
|---|---|---|---|---|---|
| [G0001](/mitre/groups/G0001.md) | Axiom | China attribution in the ATT&CK description | 2008 | 16 | 8 |
| [G0002](/mitre/groups/G0002.md) | Moafee | Guangdong Province ("Guandong" in ATT&CK) | not stated | 1 | 1 |
| [G0004](/mitre/groups/G0004.md) | Ke3chang | Actors operating out of China | 2010 | 46 | 11 |
| [G0005](/mitre/groups/G0005.md) | APT12 | China attribution in the ATT&CK description | not stated | 5 | 3 |
| [G0006](/mitre/groups/G0006.md) | APT1 | PLA GSD 3rd Department 2nd Bureau, Unit 61398 | not stated | 23 | 17 |
| [G0009](/mitre/groups/G0009.md) | Deep Panda | Suspected Chinese threat group; Anthem intrusion | not stated | 10 | 7 |
| [G0011](/mitre/groups/G0011.md) | PittyTiger | China attribution in the ATT&CK description | not stated | 2 | 5 |
| [G0013](/mitre/groups/G0013.md) | APT30 | China attribution in the ATT&CK description | not stated | 2 | 5 |
| [G0018](/mitre/groups/G0018.md) | admin@338 | China attribution in the ATT&CK description | not stated | 12 | 7 |
| [G0019](/mitre/groups/G0019.md) | Naikon | Chengdu Military Region Second Technical Reconnaissance Bureau, MUCD 78020 | 2010 | 14 | 15 |
| [G0022](/mitre/groups/G0022.md) | APT3 | Attributed by researchers to the MSS | not stated | 44 | 6 |
| [G0023](/mitre/groups/G0023.md) | APT16 | China attribution in the ATT&CK description | not stated | 1 | 1 |
| [G0024](/mitre/groups/G0024.md) | Putter Panda | PLA Unit 61486, 12th Bureau | not stated | 4 | 4 |
| [G0025](/mitre/groups/G0025.md) | APT17 | China attribution in the ATT&CK description | not stated | 2 | 1 |
| [G0027](/mitre/groups/G0027.md) | Threat Group-3390 (APT27) | Chinese threat group known for strategic web compromises | 2010 | 57 | 24 |
| [G0029](/mitre/groups/G0029.md) | Scarlet Mimic | Motives overlap the Chinese government; not directly linked | not stated | 1 | 4 |
| [G0039](/mitre/groups/G0039.md) | Suckfly | China attribution in the ATT&CK description | 2014 | 5 | 1 |
| [G0044](/mitre/groups/G0044.md) | Winnti Group | China attribution in the ATT&CK description | 2010 | 6 | 3 |
| [G0045](/mitre/groups/G0045.md) | menuPass (APT10) | Members acted with the MSS Tianjin State Security Bureau; Huaying Haitai | 2006 | 46 | 25 |
| [G0060](/mitre/groups/G0060.md) | BRONZE BUTLER | China attribution in the ATT&CK description | 2008 | 40 | 14 |
| [G0062](/mitre/groups/G0062.md) | TA459 | China attribution in the ATT&CK description | not stated | 5 | 4 |
| [G0065](/mitre/groups/G0065.md) | Leviathan (APT40) | MSS Hainan State Security Department and an affiliated front company | 2009 | 50 | 17 |
| [G0066](/mitre/groups/G0066.md) | Elderwood | China attribution in the ATT&CK description | not stated | 9 | 9 |
| [G0073](/mitre/groups/G0073.md) | APT19 | China attribution in the ATT&CK description | not stated | 21 | 2 |
| [G0093](/mitre/groups/G0093.md) | GALLIUM | Likely state-sponsored | 2012 | 31 | 16 |
| [G0096](/mitre/groups/G0096.md) | APT41 | Chinese state-sponsored espionage group with financially motivated operations | 2012 | 82 | 32 |
| [G0098](/mitre/groups/G0098.md) | BlackTech | China attribution in the ATT&CK description | 2013 | 14 | 6 |
| [G0103](/mitre/groups/G0103.md) | Mofang | China attribution in the ATT&CK description | May 2012 | 6 | 2 |
| [G0106](/mitre/groups/G0106.md) | Rocke | Alleged Chinese-speaking cryptojacker | not stated | 36 | 0 |
| [G0114](/mitre/groups/G0114.md) | Chimera | Suspected China-based threat group | 2018 | 59 | 6 |
| [G0125](/mitre/groups/G0125.md) | HAFNIUM | Likely state-sponsored, operating out of China | January 2021 | 44 | 6 |
| [G0128](/mitre/groups/G0128.md) | ZIRCONIUM (APT31) | China attribution in the ATT&CK description | 2017 | 29 | 0 |
| [G0129](/mitre/groups/G0129.md) | Mustang Panda | China-based cyber espionage threat actor | 2012 | 85 | 23 |
| [G0131](/mitre/groups/G0131.md) | Tonto Team | China attribution in the ATT&CK description | 2009 | 15 | 6 |
| [G0136](/mitre/groups/G0136.md) | IndigoZebra | China attribution in the ATT&CK description | 2014 | 7 | 3 |
| [G0143](/mitre/groups/G0143.md) | Aquatic Panda | China attribution in the ATT&CK description | May 2020 | 35 | 6 |
| [G1006](/mitre/groups/G1006.md) | Earth Lusca | China attribution in the ATT&CK description | April 2019 | 44 | 9 |
| [G1007](/mitre/groups/G1007.md) | Aoqin Dragon | China attribution in the ATT&CK description | 2013 | 9 | 2 |
| [G1014](/mitre/groups/G1014.md) | LuminousMoth | Chinese-speaking | October 2020 | 28 | 2 |
| [G1017](/mitre/groups/G1017.md) | Volt Typhoon | PRC state-sponsored | 2021 | 81 | 17 |
| [G1021](/mitre/groups/G1021.md) | Cinnamon Tempest | China-based ransomware operator | 2021 | 19 | 8 |
| [G1023](/mitre/groups/G1023.md) | APT5 | China attribution in the ATT&CK description | 2007 | 29 | 13 |
| [G1034](/mitre/groups/G1034.md) | Daggerfly | China attribution in the ATT&CK description | 2012 | 17 | 6 |
| [G1042](/mitre/groups/G1042.md) | RedEcho | PRC-related | not stated | 5 | 1 |
| [G1045](/mitre/groups/G1045.md) | Salt Typhoon | PRC state-backed | 2019 | 58 | 1 |
| [G1048](/mitre/groups/G1048.md) | UNC3886 | China-nexus cyberespionage group | 2022 | 49 | 8 |
| [G1054](/mitre/groups/G1054.md) | MirrorFace | PRC-aligned; a subgroup under the menuPass umbrella | 2019 | 43 | 16 |

Source for every row: the library's `groups.jsonl` and `group_profiles.jsonl` at ATT&CK v20.0, with the larger groups also checked on the live ATT&CK page (Confirmed [1][3][8][9][10][11][12][13][14][15][16][17]).

### What ATT&CK says about the sponsors

ATT&CK names specific military units for three groups. APT1 (G0006) is the PLA General Staff Department's 3rd Department 2nd Bureau, Unit 61398; Putter Panda (G0024) is Unit 61486 of the 12th Bureau; Naikon (G0019) is the Chengdu Military Region Second Technical Reconnaissance Bureau, Military Unit Cover Designator 78020 (Confirmed [1]).

ATT&CK ties three groups to the Ministry of State Security: APT3 (G0022) is attributed by researchers to the MSS, Leviathan (G0065) to the Hainan State Security Department, and menuPass (G0045) to the Tianjin State Security Bureau. MirrorFace (G1054), described as PRC-aligned and active since 2019, is placed as a subgroup under the menuPass umbrella, with campaign [C0060 Operation AkaiRyū](/mitre/campaigns/C0060.md) (June to September 2024, Japan and Central Europe) (Confirmed [1]).

Some attributions are weak by ATT&CK's own wording and should be labelled that way wherever they are repeated: Scarlet Mimic (motives overlap the Chinese government, not directly linked), Rocke (an alleged Chinese-speaking cryptojacker), LuminousMoth (Chinese-speaking), Moafee (Guangdong Province) and RedEcho (PRC-related) (Confirmed [1]). Cinnamon Tempest (G1021) is a China-based group active since at least 2021 that deploys Babuk-derived ransomware without an affiliate model; ATT&CK says it may be motivated by intellectual property theft or espionage rather than money (Confirmed [1]).

### Who is left out, and why

ATT&CK names China only as a target for Strider (G0041), APT37 (G0067), Kimsuky (G0094), Sidewinder (G0121), Higaisa (G0126) and BITTER (G1002) (Confirmed [1]). APT18 (G0026), Lotus Blossom (G0030), Tropic Trooper (G0081, which ATT&CK calls "unaffiliated") and DragonOK (G0017) carry Panda, Dragon or Typhoon style aliases but no China attribution in the ATT&CK description; Rancor (G0075), Thrip (G0076), Whitefly (G0107), BackdoorDiplomacy (G0135), ToddyCat (G1022), Velvet Ant (G1047) and Sowbug (G0054) have no country wording at all (Confirmed [1]). Vendor reporting likely ties several of these to China, but this study did not open a primary source that does, so they are not counted (Inferred [1]). APT18 returns in Part 5 because HHS's HC3 says it is believed responsible for the 2014 Community Health Systems breach (Reported [83]).

### Campaigns with no group attached

ATT&CK records eleven China-linked campaigns with no group object, each with a library page (Confirmed [2]):

| Campaign | Dates (ATT&CK) | What it is |
|---|---|---|
| [C0002 Night Dragon](/mitre/campaigns/C0002.md) | Nov 2009 to Feb 2011 | China-linked campaign in ATT&CK |
| [C0007 FunnyDream](/mitre/campaigns/C0007.md) | Jul 2018 to Nov 2020 | China-linked campaign in ATT&CK |
| [C0012 Operation CuckooBees](/mitre/campaigns/C0012.md) | Dec 2019 to May 2022 | Winnti, APT41 and BARIUM-affiliated actors |
| [C0014 Operation Wocao](/mitre/campaigns/C0014.md) | Dec 2017 to Dec 2019 | China-linked campaign in ATT&CK |
| [C0029 Cutting Edge](/mitre/campaigns/C0029.md) | Dec 2023 to Feb 2024 | Ivanti zero-days, UNC5221 and UNC5325 |
| [C0043 Indian Critical Infrastructure Intrusions](/mitre/campaigns/C0043.md) | Jan 2021 to Apr 2022 | RedEcho and TAG38 |
| [C0053 FLORAHOX Activity](/mitre/campaigns/C0053.md) | Jan 2019 to May 2024 | China-linked campaign in ATT&CK |
| [C0055 Quad7 Activity](/mitre/campaigns/C0055.md) | Aug 2023 to Aug 2025 | Storm-0940 |
| [C0058 SharePoint ToolShell Exploitation](/mitre/campaigns/C0058.md) | Jul 2025 | Storm-2603, TG-3390 and ZIRCONIUM; healthcare among the sectors |
| [C0061 Operation Digital Eye](/mitre/campaigns/C0061.md) | Jun to Jul 2024 | China-linked campaign in ATT&CK |
| [C0062 Anthropic AI-orchestrated Campaign](/mitre/campaigns/C0062.md) | Sep 2025 | GTG-1002 |

## Part 2: the sponsor structure

The government record now maps China's offensive cyber activity onto three state bodies and a ring of companies. The table lists every sponsor and company the record in this study names, with the document that names it.

| State body | Unit, bureau or company | Activity and library binding | First named in this record | Source |
|---|---|---|---|---|
| PLA | Unit 61398, Third Department | Five officers indicted; APT1 ([G0006](/mitre/groups/G0006.md)) | 19 May 2014 (Mandiant report 19 Feb 2013) | [18][55] |
| PLA | 54th Research Institute | Four members charged with the Equifax intrusion; no ATT&CK group bound | 10 Feb 2020 | [24] |
| PLA and MSS | Sichuan Juxinhe, Beijing Huanyu Tianqiong, Sichuan Zhixin Ruijie | Supply Chinese intelligence services; linked to PLA units and the MSS; Salt Typhoon cluster ([G1045](/mitre/groups/G1045.md)) | 27 Aug 2025 (Juxinhe sanctioned 17 Jan 2025) | [53][46] |
| MSS | Jiangsu State Security Department | Officers Zha Rong and Chai Meng; turbofan engine data, 2010 to 2015 | 30 Oct 2018 | [20] |
| MSS | Tianjin State Security Bureau, with Huaying Haitai | APT10, menuPass ([G0045](/mitre/groups/G0045.md)) | 20 Dec 2018 | [21][22] |
| MSS | Hainan State Security Department, with front company Hainan Xiandun | APT40, Leviathan ([G0065](/mitre/groups/G0065.md)) | 19 Jul 2021 (indictment returned May 2021) | [28][29] |
| MSS | Hubei State Security Department, with front company Wuhan Xiaoruizhi (set up 2010) | APT31, ZIRCONIUM ([G0128](/mitre/groups/G0128.md)) | 25 Mar 2024 | [35] |
| MSS | Shanghai State Security Bureau, with Shanghai Powerock | Xu Zewei and Zhang Yu; COVID-19 research and the HAFNIUM Exchange campaign ([G0125](/mitre/groups/G0125.md)) | 8 Jul 2025 | [52] |
| MSS (alleged, for personal gain and for the MSS) | Li Xiaoyu and Dong Jiazhi | Decade-long campaign including COVID-19 research | 21 Jul 2020 | [26] |
| MSS-affiliated | Yin Kecheng | Treasury Departmental Offices compromise; APT27 ([G0027](/mitre/groups/G0027.md)) | 17 Jan 2025 | [46][47] |
| MPS | Sichuan Silence (Chengdu) | Sophos firewall zero-day, CVE-2020-12271; services to the Ministry of Public Security; core clients are PRC intelligence services | 10 Dec 2024 | [42][43] |
| MSS and MPS | i-Soon (Anxun) | Sold data to at least 43 MSS or MPS bureaus in 31 provinces; Aquatic Panda ([G0143](/mitre/groups/G0143.md)) is among its industry names; Charcoal Typhoon is filed in ATT&CK under [G1006](/mitre/groups/G1006.md) | 5 Mar 2025 | [47][48][96] |
| CCP intelligence services (Treasury: "almost certainly") | Zhou Shuai, Shanghai Heiying | Data broker since at least 2018; APT27 ([G0027](/mitre/groups/G0027.md)) | 5 Mar 2025 | [49] |
| Not stated (company with PRC government links) | Integrity Technology Group (Beijing) | Botnet of over 260,000 devices; Flax Typhoon, RedJuliett, Ethereal Panda; no ATT&CK group | 18 Sep 2024 | [38][39][44] |
| Not stated in DOJ release | Guangzhou Bo Yu (Boyusec) | Moody's Analytics, Siemens, Trimble; the DOJ release does not use the APT3 label; the link to [G0022](/mitre/groups/G0022.md) is not checked here (Inferred) | 27 Nov 2017 | [19] |
| MSS and PLA as clients (press account of DOJ) | Nanjing Xinjiuwei Network Technology | Platforms behind a 2018 to 2026 campaign; domains seized | 26 Aug 2026 | [94][95] |

Two points about the table. First, the MSS presence is provincial: the record names bureaus in Jiangsu, Tianjin, Hainan, Hubei and Shanghai; four of them worked through a named company (Huaying Haitai, Hainan Xiandun, Wuhan Xiaoruizhi, Shanghai Powerock), and the Jiangsu officers worked through recruited hackers and insiders (Confirmed [20][21][28][35][52]). Second, the contractor relationship runs both ways. Some companies are fronts set up by a bureau (Wuhan Xiaoruizhi in 2010, Hainan Xiandun) (Confirmed [35][28]); others are commercial firms that sell services or stolen data to many bureaus, as i-Soon did to at least 43 bureaus at USD 10,000 to 75,000 per inbox (Confirmed [47]).

The FBI's March 2025 announcement states the model plainly: the MSS and MPS use private InfoSec companies, and it lists the industry names for i-Soon, including Aquatic Panda and Charcoal Typhoon (Confirmed [48]). In April 2026, NCSC and 15 partner agencies added that covert networks of compromised devices are believed used by the majority of China-linked actors and are built by Chinese information security companies; the UK had sanctioned Integrity Technology Group and one other company in December 2025 (Confirmed [74]).

## Part 3: the operational record

One row per dated event or report the verified record supports. "Actor" uses the library's group id where the source's actor maps to one; where it does not, the row says so.

| Date | Event | Actor and library binding | Grade | Source |
|---|---|---|---|---|
| 2006 onward | menuPass active since at least 2006; APT1 economic espionage since 2006 against 141 victims | [G0045](/mitre/groups/G0045.md), [G0006](/mitre/groups/G0006.md) | Confirmed | [16][55] |
| Nov 2009 to Feb 2011 | Night Dragon campaign | [C0002](/mitre/campaigns/C0002.md) | Confirmed | [2] |
| Dec 2009 (disclosed 12 Jan 2010) | Google discloses a targeted attack from China that stole intellectual property; at least twenty other large companies targeted; Gmail accounts of Chinese human rights activists a primary goal. No state attribution in the post | No ATT&CK binding | Confirmed | [54] |
| 2010 to 2015 | Jiangsu SSD officers and recruited hackers and insiders steal turbofan engine data via spearphishing, watering holes and domain hijacking | No ATT&CK binding | Confirmed | [20] |
| 2011 to May 2017 | Boyusec employees target Moody's Analytics, Siemens and Trimble | [G0022](/mitre/groups/G0022.md) by vendor reporting only, not checked here (Inferred) | Confirmed (DOJ); APT3 link Inferred, no vendor source opened | [19] |
| 2011 to 2018 | Hainan Xiandun runs APT40 operations, including Ebola, MERS, HIV/AIDS, Marburg and tularemia research | [G0065](/mitre/groups/G0065.md) | Confirmed | [28][87] |
| 19 Feb 2013 | Mandiant's APT1 report ties APT1 to PLA Unit 61398 and releases over 3,000 indicators | [G0006](/mitre/groups/G0006.md) | Confirmed | [55] |
| Feb 2014 to Jan 2015 | Anthem: data on about 78.8 million people stolen | [G0009](/mitre/groups/G0009.md) per ATT&CK; DOJ names no group | Confirmed | [23][89][1] |
| Apr and Jun 2014 | Community Health Systems: non-medical identification data on about 4.5 million people copied; the company and Mandiant believe an APT group originating from China was responsible | No group in the filing; APT18 per HC3 | Confirmed (filing); APT18 Reported | [56][83] |
| 19 May 2014 | W.D. Pa. indictment of five Unit 61398 officers, 31 counts, six US victims | [G0006](/mitre/groups/G0006.md) | Confirmed | [18] |
| 2015 | OPM breach; the House Oversight majority report names only "a foreign adversary" | No attribution on this primary | Confirmed | [57] |
| 2016 to 2017 | menuPass targets managed service providers | [G0045](/mitre/groups/G0045.md) | Confirmed | [16] |
| 4 Apr 2017 | BAE Systems attributes Operation Cloud Hopper against MSPs to APT10 | [G0045](/mitre/groups/G0045.md) | Confirmed | [58] |
| 27 Nov 2017 | DOJ charges three Boyusec employees | [G0022](/mitre/groups/G0022.md) by vendor reporting only, not checked here (Inferred) | Confirmed (DOJ); APT3 link Inferred | [19] |
| Dec 2017 to Dec 2019 | Operation Wocao | [C0014](/mitre/campaigns/C0014.md) | Confirmed | [2] |
| Jul 2018 to Nov 2020 | FunnyDream | [C0007](/mitre/campaigns/C0007.md) | Confirmed | [2] |
| 30 Oct 2018 | DOJ charges Jiangsu SSD officers Zha Rong and Chai Meng and their recruits | No ATT&CK binding | Confirmed | [20] |
| 20 Dec 2018 | APT10 indictment of Zhu Hua and Zhang Shilong; the UK and allies say APT10 acted for the MSS | [G0045](/mitre/groups/G0045.md) | Confirmed | [21][22][90] |
| Jan 2019 to May 2024 | SPACEHOP (APT5 and Ke3chang) and FLORAHOX | [C0052](/mitre/campaigns/C0052.md), [C0053](/mitre/campaigns/C0053.md) | Confirmed | [17][2] |
| Apr 2019 | Suspected Chinese espionage actors target a US cancer-research health center that APT41 spearphished in 2018 and APT22 targeted earlier | Unnamed; APT41 ([G0096](/mitre/groups/G0096.md)) spearphished the same center in 2018; APT22 has no ATT&CK object | Confirmed (HC3) | [83] |
| 9 May 2019 | Anthem indictment of Fujie Wang and a John Doe; no state direction alleged | [G0009](/mitre/groups/G0009.md) per ATT&CK | Confirmed | [23] |
| Dec 2019 to May 2022 | Operation CuckooBees | [C0012](/mitre/campaigns/C0012.md) | Confirmed | [2] |
| 2020 | Sichuan Silence uses a Sophos firewall zero-day (CVE-2020-12271) against about 81,000 firewalls | No ATT&CK binding | Confirmed | [42][43] |
| 10 Feb 2020 | Four PLA 54th Research Institute members charged over Equifax: about 145 million Americans' PII; about 34 servers in nearly 20 countries | No ATT&CK binding | Confirmed | [24] |
| Feb 2020 to Jun 2021 | Xu Zewei and Zhang Yu, directed by the Shanghai SSB, target COVID-19 research mailboxes and take part in the HAFNIUM Exchange campaign | [G0125](/mitre/groups/G0125.md) | Confirmed | [52] |
| 13 May 2020 | FBI and CISA warn that COVID-19 healthcare, pharmaceutical and research organizations are prime PRC targets | PRC actors, no group | Confirmed | [25][84] |
| 21 Jul 2020 | Li Xiaoyu and Dong Jiazhi indicted; COVID-19 vaccine, testing and treatment networks probed | No ATT&CK binding | Confirmed | [26] |
| 16 Sep 2020 | Five PRC nationals (APT41, Barium, Winnti) and two Malaysian businessmen charged; more than 100 victims | [G0096](/mitre/groups/G0096.md) | Confirmed | [27] |
| Jan 2021 to Apr 2022 | Indian critical infrastructure intrusions | [C0043](/mitre/campaigns/C0043.md); RedEcho ([G1042](/mitre/groups/G1042.md)) named in the campaign description | Confirmed | [2] |
| 2 Mar 2021 | Microsoft attributes Exchange zero-day exploitation to HAFNIUM with high confidence | [G0125](/mitre/groups/G0125.md) | Confirmed | [59] |
| May 2021 to Feb 2022 | APT41 campaign C0017 | [C0017](/mitre/campaigns/C0017.md) | Confirmed | [9] |
| mid-2021 | Volt Typhoon active (Microsoft); the Integrity Tech botnet starts | [G1017](/mitre/groups/G1017.md); Integrity Tech has no ATT&CK object | Confirmed | [62][39] |
| 2021 to 2022 | UK Electoral Commission highly likely compromised by a China state-affiliated entity; APT31 reconnaissance of UK parliamentarians in 2021 | [G0128](/mitre/groups/G0128.md) for the reconnaissance | Confirmed | [65] |
| 19 Jul 2021 | Coordinated attribution: the US with the EU, UK and NATO names MSS-affiliated actors for the Exchange campaign; DOJ unseals the APT40 indictment; AA21-200A and AA21-200B published | [G0125](/mitre/groups/G0125.md), [G0065](/mitre/groups/G0065.md), [G0128](/mitre/groups/G0128.md) | Confirmed | [60][28][29][30][93] |
| 6 Dec 2021 | Microsoft's Digital Crimes Unit seizes NICKEL websites under an EDVA court order | [G0004](/mitre/groups/G0004.md) | Confirmed | [61] |
| Apr to Sep 2022 | Leviathan Australian intrusions | [C0049](/mitre/campaigns/C0049.md) | Confirmed | [14] |
| 2022 onward | Campaign against an unclassified Czech Foreign Ministry network | [G0128](/mitre/groups/G0128.md) | Confirmed | [50][51] |
| 7 Jun 2022 | AA22-158A: PRC actors exploit telecoms and network devices | PRC actors, no group | Confirmed | [97] |
| 6 Oct 2022 | AA22-279A lists 20 CVEs exploited by PRC actors | PRC actors, no group | Confirmed | [99] |
| Oct 2022 to Jan 2024 | KV Botnet activity | [C0035](/mitre/campaigns/C0035.md) | Confirmed | [10] |
| Jan 2023 to Jun 2024 | APT41 DUST | [C0040](/mitre/campaigns/C0040.md) | Confirmed | [9] |
| 15 May 2023 | Storm-0558 forges tokens with an acquired MSA consumer signing key; mail at about 25 organizations | No ATT&CK object | Confirmed | [64] |
| 24 May 2023 | Microsoft and AA23-144A on Volt Typhoon living off the land | [G1017](/mitre/groups/G1017.md) | Confirmed | [62][31] |
| Jul 2023 to Dec 2024 | RedDelta modified PlugX infection chain | [C0047](/mitre/campaigns/C0047.md), [G0129](/mitre/groups/G0129.md) | Confirmed | [8] |
| Aug 2023 to Aug 2025 | Quad7 | [C0055](/mitre/campaigns/C0055.md) | Confirmed | [2] |
| 16 Aug 2023 | HC3 Threat Profile names the greatest China-based threats to US health | See Part 5 | Confirmed | [86] |
| Sep 2023 to Nov 2025 | UNC6508 REDCap campaign against medical research | No ATT&CK object | Confirmed | [78] |
| Dec 2023 | Court-authorized removal of KV Botnet malware from hundreds of US SOHO routers (announced 31 Jan 2024) | [G1017](/mitre/groups/G1017.md) | Confirmed | [32] |
| Dec 2023 to Feb 2024 | Cutting Edge, Ivanti zero-days | [C0029](/mitre/campaigns/C0029.md) | Confirmed | [2] |
| 7 Feb 2024 | AA24-038A: high confidence that Volt Typhoon is pre-positioning for OT disruption | [G1017](/mitre/groups/G1017.md) | Confirmed | [33] |
| 25 Mar 2024 | Seven APT31-linked nationals charged; OFAC sanctions Wuhan XRZ; UK sanctions and attributions | [G0128](/mitre/groups/G0128.md) | Confirmed | [34][35][36][65] |
| Jun to Aug 2024 | Versa Director zero-day exploitation | [C0039](/mitre/campaigns/C0039.md), [G1017](/mitre/groups/G1017.md) | Confirmed | [10] |
| Jun to Sep 2024 | Operation AkaiRyū; Operation Digital Eye (Jun to Jul) | [C0060](/mitre/campaigns/C0060.md), [C0061](/mitre/campaigns/C0061.md) | Confirmed | [1][2] |
| mid-2024 | TINYSHELL-based backdoors on Juniper MX routers (Mandiant, 11 Mar 2025); RedPenguin Jul 2024 to Mar 2025 | [G1048](/mitre/groups/G1048.md), [C0056](/mitre/campaigns/C0056.md) | Confirmed | [71][15] |
| 8 Jul 2024 | AA24-190A, eight-country advisory on APT40 | [G0065](/mitre/groups/G0065.md) | Confirmed | [37] |
| Sep 2024 | QTFY actors intrude at three DOE national laboratories, NIH and an HHS agency via an Ivanti Cloud Services Appliance zero-day | No ATT&CK binding | Confirmed | [94] |
| 18 Sep 2024 | Court-authorized disruption of the Integrity Tech botnet; FBI, CNMF and NSA advisory; NCSC and partners | Flax Typhoon, no ATT&CK object | Confirmed | [38][39][66] |
| Sep to Dec 2024 | Treasury network hack tied to Yin Kecheng | [G0027](/mitre/groups/G0027.md) | Confirmed | [47][49] |
| early Oct 2024 | Media first report Salt Typhoon in US telecoms (CRS) | [G1045](/mitre/groups/G1045.md) | Confirmed (CRS) | [67] |
| 14 Oct 2024 | China's CVERC calls Volt Typhoon a US false flag operation, seen through state media only | [G1017](/mitre/groups/G1017.md) | Reported | [63] |
| 13 Nov 2024 | FBI and CISA: PRC-affiliated actors compromised multiple telecom companies, including court-ordered law enforcement request data | No group named | Confirmed | [40] |
| 4 Dec 2024 | Enhanced Visibility and Hardening Guidance for Communications Infrastructure | No group named | Confirmed | [41] |
| 10 Dec 2024 | Guan Tianfeng indicted; OFAC designates Sichuan Silence | No ATT&CK binding | Confirmed | [42][43] |
| mid-Dec 2024 | Ivanti Connect Secure zero-day CVE-2025-0282 exploited by UNC5221 (Mandiant, 8 Jan 2025) | No ATT&CK object | Confirmed | [68] |
| 3 Jan 2025 | OFAC designates Integrity Technology Group | Flax Typhoon, no ATT&CK object | Confirmed | [44] |
| 8 Jan 2025 | Japan's NPA and NISC on MirrorFace, suspected Chinese involvement, since about 2019 | [G1054](/mitre/groups/G1054.md) | Confirmed | [45] |
| 17 Jan 2025 | OFAC sanctions Yin Kecheng and Sichuan Juxinhe | [G0027](/mitre/groups/G0027.md), [G1045](/mitre/groups/G1045.md) | Confirmed | [46] |
| 5 Mar 2025 | 12 people charged: eight i-Soon employees, two MPS officers and APT27 actors Yin Kecheng and Zhou Shuai; FBI PSA; OFAC on Zhou Shuai; Microsoft on Silk Typhoon | [G0027](/mitre/groups/G0027.md), [G0143](/mitre/groups/G0143.md), [G0125](/mitre/groups/G0125.md) | Confirmed | [47][48][49][69] |
| Mar 2025 onward | BRICKSTORM intrusions in legal, SaaS, BPO and technology; 393-day average dwell (GTIG, 24 Sep 2025) | No ATT&CK group object (UNC5221); BRICKSTORM is [S9015](/mitre/software/S9015.md) | Confirmed | [70] |
| 28 May 2025 | Czech national attribution of the Foreign Ministry campaign to APT31 | [G0128](/mitre/groups/G0128.md) | Confirmed | [50][51] |
| 3 Jul 2025 | Xu Zewei arrested in Milan (DOJ, 8 Jul 2025) | [G0125](/mitre/groups/G0125.md) | Confirmed | [52] |
| from 7 Jul 2025 | SharePoint exploitation by Linen Typhoon, Violet Typhoon and Storm-2603; Warlock ransomware from 18 Jul | [C0058](/mitre/campaigns/C0058.md); Linen Typhoon = [G0027](/mitre/groups/G0027.md), Violet Typhoon = [G0128](/mitre/groups/G0128.md) by ATT&CK alias; Storm-2603 has no object; home study [SharePoint ToolShell](/case-studies/SHAREPOINT_TOOLSHELL_2025.md) | Confirmed | [72][2] |
| 27 Aug 2025 | AA25-239A: 23 agencies in 13 countries on Salt Typhoon and three named companies | [G1045](/mitre/groups/G1045.md) | Confirmed | [53] |
| Sep 2025 | AI-orchestrated campaign attributed to GTG-1002 | [C0062](/mitre/campaigns/C0062.md) | Confirmed | [2] |
| 4 Dec 2025 | CISA, NSA and the Canadian Cyber Centre attribute BRICKSTORM to PRC state-sponsored actors | No ATT&CK group object; BRICKSTORM is [S9015](/mitre/software/S9015.md) | Confirmed | [73] |
| Dec 2025 | UK sanctions Integrity Technology Group and one other company | Flax Typhoon, no ATT&CK object | Confirmed | [74] |
| 25 Feb 2026 | GTIG disrupts UNC2814 and its GRIDTIDE backdoor | No ATT&CK object | Confirmed | [75] |
| 23 Apr 2026 | AA26-113A and NCSC at CYBERUK on covert networks of compromised devices | [G1017](/mitre/groups/G1017.md); Flax Typhoon | Confirmed | [76][77][74] |
| 25 Apr 2026 | Xu Zewei extradited to the US and held in Houston, per his lawyer | [G0125](/mitre/groups/G0125.md) | Reported | [92] |
| 15 Jun 2026 | GTIG publishes the UNC6508 REDCap campaign | No ATT&CK object | Confirmed | [78] |
| late Aug 2026 | ARMORY CASTLE (formerly UNC5221) exploits a BeyondTrust Remote Support zero-day (GTIG, 15 Oct 2026) | No ATT&CK object | Confirmed | [82] |
| 26 Aug 2026 | DOJ seizure affidavit against QTFY actors, described in the affidavit as Chinese hackers; press report three domains seized and the platforms run by Nanjing Xinjiuwei | No ATT&CK binding | Confirmed (affidavit); seizure count and company Reported | [94][95] |
| 8 Sep 2026 | AA26-251A on industrial-scale model distillation by China-based AI companies | Not an intrusion campaign | Confirmed | [79] |
| 8 Oct 2026 | AA26-281A and NCSC on actors enabled by Integrity Tech, including US Healthcare and Public Health victims | Flax Typhoon, no ATT&CK object | Confirmed | [80][81] |

## Part 4: the actors behind the headlines

### APT1 and the PLA (G0006)

APT1 is the case that set the template. Mandiant's report of 19 February 2013 linked the group to the PLA General Staff Department's 3rd Department, Military Cover Designator 61398, documented economic espionage since 2006 against 141 victims and released over 3,000 indicators (Confirmed [55]). Fifteen months later a W.D. Pa. grand jury indicted five officers of Unit 61398, Wang Dong, Sun Kailiang, Wen Xinyu, Huang Zhenyu and Gu Chunhui, on 31 counts covering six US victims in nuclear power, metals and solar: Westinghouse, SolarWorld, US Steel, ATI, the United Steelworkers and Alcoa (Confirmed [18]). ATT&CK records 23 techniques and 17 software for the group (Confirmed [3]). The Equifax case six years later followed the same pattern with a different PLA body: four members of the 54th Research Institute were charged with exploiting Apache Struts on Equifax's dispute portal, taking PII on about 145 million Americans, routing through about 34 servers in nearly 20 countries and wiping logs every day (Confirmed [24]).

### APT10, menuPass and Cloud Hopper (G0045)

menuPass has been active since at least 2006, and ATT&CK says its members acted with the MSS Tianjin State Security Bureau and worked for Huaying Haitai; its targets include healthcare and biotechnology with an emphasis on Japan, and managed service providers in 2016 and 2017 (Confirmed [16]). BAE Systems named the MSP campaign Operation Cloud Hopper on 4 April 2017 (Confirmed [58]). On 20 December 2018 DOJ charged Zhu Hua and Zhang Shilong with hacking MSPs and more than 45 US technology companies from about 2006 to 2018; the FBI notice adds MSPs with clients in at least 12 countries and PII of over 100,000 Navy personnel (Confirmed [21][90]). The same day the UK and its allies said APT10 acted for the MSS: NCSC assessed "with the highest level of probability" that APT10 ran the campaign (Confirmed [22]). MirrorFace (G1054) is now placed under the menuPass umbrella in ATT&CK, and Japan's National Police Agency and NISC described its campaign since about 2019 against Japanese organizations as suspected of Chinese involvement (this study's translation) and aimed at national security and advanced technology information (Confirmed [1][45]).

### APT40, Leviathan and Hainan Xiandun (G0065)

Leviathan is the best-documented MSS bureau operation in the record (Inferred). ATT&CK attributes it to the Hainan State Security Department and an affiliated front company, active since at least 2009 (Confirmed [14]). The S.D. Cal. indictment, returned in May 2021 and unsealed in July, names HSSD officers Ding Xiaoyang, Cheng Qingmin and Zhu Yunmin and hacker Wu Shurong, operating through Hainan Xiandun from 2011 to 2018 (Confirmed [28][87]). AA21-200A, published the same day, gives the TTPs: T1190, T1133, T1566.001 and T1566.002, T1189, T1078, T1505.003, T1090.003, T1572, T1560 and T1041 (Confirmed [29]). Three years later ASD's ACSC led an eight-country advisory, AA24-190A, attributing APT40 to the MSS and documenting rapid weaponization of public proof-of-concept exploits, web shells and SOHO relays; it cites the Hainan basing only as prior reporting, a weaker statement than AA21-200A (Confirmed [37]). ATT&CK records the 2022 Australian case studies as campaign [C0049](/mitre/campaigns/C0049.md) (Confirmed [14]).

### APT31, ZIRCONIUM and the Hubei bureau (G0128)

On 25 March 2024 the United States and the United Kingdom acted together. E.D.N.Y. charged seven APT31-linked PRC nationals, Ni Gaobin, Weng Ming, Cheng Feng, Peng Yaowen, Sun Xiaohui, Xiong Wang and Zhao Guangzong, over about 14 years of targeting critics, businesses and officials with more than 10,000 malicious emails (Confirmed [34]). OFAC sanctioned Wuhan Xiaoruizhi, a front company the MSS Hubei State Security Department set up in 2010, with Zhao and Ni; named victims include defense industrial base firms, a Texas energy company in 2018 and a California MSP, and targets included White House, Justice, Commerce, Treasury and State staff, Congress and naval schools (Confirmed [35]). NCSC assessed it almost certain that APT31 ran reconnaissance against UK parliamentarians in 2021, and that an unnamed China state-affiliated actor highly likely accessed Electoral Commission email and Electoral Register data in 2021 and 2022 (Confirmed [65][36]). On 28 May 2025 the Czech government named the PRC as responsible for a campaign since 2022 against an unclassified Foreign Ministry network, an institution designated as critical infrastructure, carried out by APT31 (Confirmed [50]); NUKIB says the attribution rests on joint analysis with Military Intelligence, the Office for Foreign Relations and Information and the Security Information Service (Confirmed [51]). ATT&CK also links ZIRCONIUM to 2020 US election targets and to campaign [C0053 FLORAHOX](/mitre/campaigns/C0053.md) (Confirmed [1][2]).

### APT27, i-Soon and the data brokers (G0027, G0143)

Threat Group-3390 (APT27, Emissary Panda, LuckyMouse, Linen Typhoon) is known for strategic web compromises since at least 2010 against aerospace, government, defense, technology, energy, manufacturing and gambling (Confirmed [13]). The March 2025 charges reframed it as part of a market. DOJ charged eight i-Soon employees, two Ministry of Public Security officers, and APT27 actors Yin Kecheng and Zhou Shuai; i-Soon allegedly sold data to at least 43 MSS or MPS bureaus in 31 provinces, and Yin and Zhou allegedly targeted victims including health care systems from 2013 to 2024 using PlugX (Confirmed [47]). The FBI's notice on i-Soon (tracked as Aquatic Panda) lists victims from about 2016 to 2023: a large US religious organization, PRC critics and dissidents, a state legislative body, US agencies, Asian foreign ministries and news organizations, with no healthcare victims named (Confirmed [96]). Treasury says Zhou has brokered stolen data since at least 2018, with victims including an academic health system affiliated with a university (Confirmed [49]).

### HAFNIUM, Silk Typhoon and the Exchange campaign (G0125)

Microsoft attributed exploitation of four Exchange Server zero-days (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and CVE-2021-27065) with high confidence to HAFNIUM on 2 March 2021, naming infectious disease researchers, law firms, higher education, defense contractors, think tanks and NGOs as targets (Confirmed [59]). On 19 July 2021 the US, joined by the EU, UK and NATO, attributed the campaign with a high degree of confidence to MSS-affiliated actors (Confirmed [60]); NCSC called it "almost certain" a Chinese state-backed actor was behind it (Confirmed [30]). The 2025 arrest of Xu Zewei in Milan connects the campaign to a named contractor: DOJ says the Shanghai SSB directed Xu, who worked at Shanghai Powerock, from February 2020 to June 2021, and the FBI says over 60,000 US entities were targeted and more than 12,700 victimized (Confirmed [52]). In March 2025 Microsoft described Silk Typhoon, its current name for HAFNIUM, abusing stolen API keys and credentials of IT providers since late 2024 to reach downstream tenants, with healthcare among the targets (Confirmed [69]).

The 2021 Exchange mass exploitation is covered in its own study, Operation Exchange Marauder; this section summarizes the actor record only.

### APT41 (G0096): summary of the home study

APT41 (Wicked Panda, Brass Typhoon, BARIUM) is assessed by researchers, per ATT&CK, as a Chinese state-sponsored espionage group that also runs financially motivated operations, active since at least 2012 and targeting industries including healthcare in 14 countries, with 82 techniques, 32 software and campaigns [C0017](/mitre/campaigns/C0017.md) (May 2021 to February 2022) and [C0040 APT41 DUST](/mitre/campaigns/C0040.md) (January 2023 to June 2024) (Confirmed [9]). DOJ charged five PRC nationals and two Malaysian businessmen in September 2020 over more than 100 victims (Confirmed [27]), and HC3 lists its health-sector attacks from 2014 to 2022 (Confirmed [86]). The full record, tooling and timeline are in APT41: The Public Record.

### Volt Typhoon and pre-positioning (G1017)

Microsoft introduced Volt Typhoon on 24 May 2023 as a China-based state-sponsored actor active since mid-2021, targeting US critical infrastructure including Guam, and assessed with moderate confidence that it was developing capabilities to disrupt US-Asia communications in a crisis (Confirmed [62]). Initial access came through internet-facing Fortinet FortiGuard devices, and traffic was proxied through compromised ASUS, Cisco, D-Link, NETGEAR and Zyxel SOHO devices (Confirmed [62]). AA23-144A, from NSA, CISA, FBI and the Five Eyes, described the same actor living off the land (Confirmed [31]). In December 2023 a court-authorized operation removed KV Botnet malware from hundreds of US SOHO routers, mostly end-of-life Cisco and NetGear devices, and FBI Director Wray described the activity as pre-positioning to cause harm in a conflict (Confirmed [32]). AA24-038A, from ten agencies in five countries, then assessed with high confidence that Volt Typhoon is pre-positioning on IT networks to reach and disrupt OT in Communications, Energy, Transportation and Water, with some footholds held at least five years; it names CVE-2022-42475 on a FortiGate 300D among the entry points (Confirmed [33]). ATT&CK records campaigns [C0035 KV Botnet Activity](/mitre/campaigns/C0035.md) and [C0039 Versa Director Zero Day Exploitation](/mitre/campaigns/C0039.md) and software including [S1144 FRP](/mitre/software/S1144.md) and [S1154 VersaMem](/mitre/software/S1154.md) (Confirmed [10]).

### Salt Typhoon and the telecoms (G1045)

The Congressional Research Service records that media first reported in early October 2024 that PRC state-sponsored hackers had infiltrated US telecoms and ISPs (Confirmed [67]). On 13 November 2024 the FBI and CISA confirmed PRC-affiliated actors had compromised multiple telecom companies, stealing customer call records, compromising private communications of a limited number of people in government or politics, and copying information subject to court-ordered law enforcement requests (Confirmed [40]). The December 2024 hardening guide said the exploitation matched existing weaknesses and no novel activity was observed (Confirmed [41]). Treasury sanctioned Sichuan Juxinhe in January 2025 for direct involvement in Salt Typhoon's exploitation of US telecoms (Confirmed [46]). AA25-239A, co-sealed by 23 agencies in 13 countries, names Sichuan Juxinhe, Beijing Huanyu Tianqiong and Sichuan Zhixin Ruijie, links them to PLA units and the MSS, and lists the initial-access CVEs: CVE-2024-21887 (with CVE-2023-46805), CVE-2024-3400, CVE-2023-20198, CVE-2023-20273 and CVE-2018-0171; zero-day use was not observed (Confirmed [53]). The live ATT&CK page lists one software entry, [S1206 JumbledPath](/mitre/software/S1206.md), and 58 Enterprise techniques matching the library exactly (Confirmed [12]).

### Flax Typhoon and Integrity Technology Group (no ATT&CK object)

Flax Typhoon is the clearest case of a Chinese company running infrastructure as a service (Inferred). A court-authorized operation in September 2024 disrupted a botnet of more than 200,000 consumer devices built and run by Integrity Technology Group, a publicly traded Beijing company, which sold access through a web application labelled KRLab; someone attempted a DDoS against the FBI's remediation infrastructure (Confirmed [38]). The FBI, CNMF and NSA advisory put the botnet at over 260,000 devices as of June 2024, active since mid-2021, with activity consistent with Flax Typhoon, RedJuliett and Ethereal Panda (Confirmed [39]). OFAC designated the company in January 2025 (Confirmed [44]), the UK sanctioned it in December 2025 (Confirmed [74]), and AA26-281A in October 2026 described actors enabled by Integrity Tech combining automated and hands-on tools against US Healthcare and Public Health, government, critical manufacturing and IT, plus healthcare systems in Southeast Asia (Confirmed [80]). ATT&CK has no group record for Flax Typhoon in the library data (Confirmed [39][6]).

### UNC5221, ARMORY CASTLE and the edge zero-days (no ATT&CK group object; BRICKSTORM is S9015)

Mandiant attributes exploitation of the Ivanti Connect Secure zero-day CVE-2025-0282, beginning mid-December 2024, to UNC5221, a suspected China-nexus espionage actor (Confirmed [68]). GTIG attributes BRICKSTORM intrusions to UNC5221 and related clusters, with a 393-day average dwell, and states it does not consider UNC5221 the same as Silk Typhoon (Confirmed [70]). CISA, NSA and the Canadian Cyber Centre went further in December 2025, attributing BRICKSTORM on VMware vCenter and Windows to PRC state-sponsored actors (Confirmed [73]). In October 2026 GTIG attributed late-August 2026 zero-day exploitation of BeyondTrust Remote Support, listed as CVE-2026-102764, to ARMORY CASTLE, its new name for UNC5221 (Confirmed [82]). ATT&CK records the 2023 to 2024 Ivanti activity as campaign [C0029 Cutting Edge](/mitre/campaigns/C0029.md) (Confirmed [2]).

### UNC3886 and the routers (G1048)

UNC3886 is a China-nexus espionage group active since at least 2022 that exploits edge and virtualization zero-days against defense, technology and telecoms in the US and Asia-Pacific (Confirmed [15]). Mandiant found TINYSHELL-based backdoors on Juniper MX routers in mid-2024, involving CVE-2025-21590 (Confirmed [71]), and ATT&CK records the activity as campaign [C0056 RedPenguin](/mitre/campaigns/C0056.md) (July 2024 to March 2025) (Confirmed [15]).

### The others

- **Mustang Panda (G0129)** has the largest footprint in ATT&CK: 85 techniques and 23 software, 15 aliases including RedDelta, BRONZE PRESIDENT, EARTH PRETA, TWILL TYPHOON and UNC6384, and campaign [C0047](/mitre/campaigns/C0047.md) (July 2023 to December 2024) (Confirmed [8]).
- **Chimera (G0114)** is a suspected China-based group targeting Taiwan's semiconductor industry and airline data since at least 2018; 59 techniques (Confirmed [11]).
- **Ke3chang (G0004)**, also APT15, NICKEL and Nylon Typhoon, targets oil, government, diplomatic, military and NGO organizations in the Americas and Europe since at least 2010 (Confirmed [17]); Microsoft's DCU seized its websites in December 2021, citing targets in the US and 28 other countries (Confirmed [61]).
- **APT3 (G0022)** is attributed by researchers to the MSS (Confirmed [1]); the Boyusec indictment names the company but not the APT3 label (Confirmed [19]).
- **Storm-0558** (now Antique Typhoon) is assessed with moderate confidence by Microsoft to be China-based; it accessed mail at about 25 organizations with forged tokens from May 2023 (Confirmed [64]). No ATT&CK object.
- **UNC2814**, a suspected PRC-nexus group tracked since 2017, used the GRIDTIDE backdoor with Google Sheets API command and control; GTIG counted 53 confirmed victims in 42 countries as of 18 February 2026, mainly telecoms and government, with no observed overlap with Salt Typhoon (Confirmed [75]).
- **Sichuan Silence** and Guan Tianfeng used the Sophos zero-day against about 81,000 firewalls; over 23,000 were in the US, 36 of them protecting critical infrastructure, and the malware was modified to deploy ransomware (Ragnarok) if victims remediated (Confirmed [42][43]).

## Part 5: healthcare and life sciences

### What the record shows

China-attributed actors have targeted healthcare, pharmaceuticals, medical devices and biomedical research for more than a decade, mostly for intellectual property and identity data rather than disruption. Nine groups in the ATT&CK data carry healthcare or life-sciences targeting in their descriptions: menuPass (healthcare, biotechnology), Leviathan (biomedical, healthcare), APT41 (healthcare), Tonto Team (healthcare), Deep Panda (Anthem), HAFNIUM (infectious disease researchers), APT19 (pharmaceutical), Earth Lusca (COVID-19 research) and BRONZE BUTLER (biotechnology), and campaign C0058 ToolShell lists healthcare among its sectors (Confirmed [1]).

This study opened three HHS Health Sector Cybersecurity Coordination Center (HC3) briefings on China-based threats to the Healthcare and Public Health (HPH) sector:

| Date | HC3 product | What it says | Source |
|---|---|---|---|
| 19 Nov 2020 | Threat briefing, Chinese state-sponsored cyber activity | At least 8 China-attributed APT groups have targeted HPH: APT41, APT24 (PittyTiger), APT22, APT20 (Twivy), APT18 (Wekby), APT10 (menuPass), APT9 (Nightshade Panda), APT1 (Unit 61398). APT22 targeted healthcare, biomedical and pharmaceutical organizations, including multi-year targeting of a cancer-research health center; APT9 was historically very active against pharmaceuticals and biotechnology; APT20 targeted healthcare and MSPs and bypassed VPN two-factor authentication; APT24 targeted healthcare in the US and Taiwan | [83] |
| 6 May 2021 | China's Five-Year Plans and the HPH | Chinese APTs that targeted HPH entities: APT1, APT10, APT18, APT41, APT24, Deep Panda, APT22, APT20, APT9. Ties targeting to the Five-Year Plans; APT10 targeted a Japanese pharmaceutical company in 2019 to 2020 | [85] |
| 16 Aug 2023 | Threat Profile, China-based threat actors | APT41, APT10, APT18 and APT22 are the greatest China-based threats to US HPH, with APT27 in the targeting matrix; APT18 targets biotech, pharmaceutical, cancer research and healthcare manufacturing since 2013 and is believed affiliated with the PLA Navy; APT10 used healthcare-themed phishing documents in Japan | [86] |

The ATT&CK binding for the HC3 names: [G0026 APT18](/mitre/groups/G0026.md), [G0045 menuPass](/mitre/groups/G0045.md), [G0096 APT41](/mitre/groups/G0096.md), [G0006 APT1](/mitre/groups/G0006.md), [G0009 Deep Panda](/mitre/groups/G0009.md) and [G0027 Threat Group-3390](/mitre/groups/G0027.md) have pages; APT22, APT20 and APT9 have no ATT&CK object (Confirmed [6]). HC3 equates APT22 with Suckfly and G0039, but ATT&CK lists no APT22 alias for G0039 Suckfly, so this study does not bind APT22 to G0039 (Inferred [86][1]). HC3 also equates APT24 with PittyTiger, but ATT&CK lists no APT24 alias for G0011, so this study does not bind APT24 to G0011 either (Inferred [83][1]). APT18 is in the library as G0026 but its ATT&CK description carries no China wording, which is why it sits outside the Part 1 counts (Confirmed [1]).

### The healthcare timeline

| Date | Event | Actor | Grade | Source |
|---|---|---|---|---|
| 2006 to 2018 | APT10 indictment lists target industries including healthcare, medical equipment, biotechnology and pharmaceutical manufacturing (the FBI wanted notice does not list healthcare) | [G0045](/mitre/groups/G0045.md) | Confirmed | [21][90] |
| 2011 to 2018 | APT40 steals Ebola virus and vaccine research, including genetic-sequencing technology; victims include a virus treatment and vaccine facility in California and Florida, a university school of medicine and NIH | [G0065](/mitre/groups/G0065.md) | Confirmed | [87][88] |
| Sep 2012 to Jul 2015 | APT40 overt acts: malware on a school-of-medicine system (Sep 2012) and on Research Facility A's Ebola program (Nov 2012, 25 Jul 2014); in 2015 the conspirators sought information on tularemia, Marburg vaccine, Ebola, US national health security and HIV/AIDS strategies | [G0065](/mitre/groups/G0065.md) | Confirmed | [87] |
| Feb 2014 to Jan 2015 | Anthem: about 78.8 million people's records, including health identification numbers and Social Security numbers; DOJ and the FBI allege a China-based hacking group but no state direction | [G0009](/mitre/groups/G0009.md) per ATT&CK | Confirmed | [23][89][1] |
| Apr and Jun 2014 | Community Health Systems: names, addresses, birthdates, phone numbers and SSNs of about 4.5 million people, no medical, clinical or card data; attributed to an APT group originating from China | No group in the filing; APT18 per HC3 | Confirmed (filing); APT18 Reported | [56][83] |
| Jul 2014 to 2022 | APT41 health-sector attacks: a medical devices subsidiary (2014 to 2016), a biotech being acquired (2015), a cancer-research center (2018), Citrix, Zoho and Cisco exploitation in health (2021), at least USD 20 million in COVID relief funds (2022) | [G0096](/mitre/groups/G0096.md); home study | Confirmed (HC3) | [86] |
| Apr 2019 | Suspected Chinese espionage actors target a US cancer-research health center | Unnamed; APT41 and APT22 earlier | Confirmed (HC3) | [83] |
| Jan to Jun 2020 | Li Xiaoyu and Dong Jiazhi: a Maryland biotech announcing COVID-19 vaccine work (Jan), a California biotech on COVID-19 antivirals (Feb), a California diagnostics firm making COVID-19 test kits (May), a Massachusetts cancer-treatment biotech (Jun) | No ATT&CK binding | Confirmed | [26][83] |
| Feb 2020 | Xu Zewei targets COVID-19 research mailboxes at a Texas university; press add immunologists and virologists | [G0125](/mitre/groups/G0125.md) | Confirmed (DOJ); detail Reported | [52][91] |
| 13 May 2020 | FBI and CISA: the FBI is investigating PRC targeting of US COVID-19 research for vaccine, treatment and testing data | PRC actors | Confirmed | [25][84] |
| 13 Aug 2020 | Medical Center 1 of Ohio reports an actor-leased server targeting its Pulse Secure VPN (CVE-2019-11510); a Missouri insurance agency was targeted via CVE-2019-19781 in Jan 2020 | QTFY actors, no ATT&CK binding | Confirmed | [94] |
| 2 Mar 2021 | HAFNIUM's targets include infectious disease researchers | [G0125](/mitre/groups/G0125.md) | Confirmed | [59][1] |
| 19 Jul 2021 | AA21-200A lists healthcare and biomedical among APT40's victims; AA21-200B names medical institutions among PRC targets | [G0065](/mitre/groups/G0065.md) | Confirmed | [29][93] |
| 2013 to 2024 | Yin Kecheng and Zhou Shuai target victims including health care systems; Zhou's victims include an academic health system | [G0027](/mitre/groups/G0027.md) | Confirmed | [47][49] |
| Sep 2023 to Nov 2025 | UNC6508 compromises a medical research institution's REDCap server, uses INFINITERED to capture credentials and abuses content compliance rules to exfiltrate mail; targets include clinical providers, academic medical centers, military health and health regulators in North America; GTIG grades the attribution high confidence | No ATT&CK object | Confirmed | [78] |
| Sep 2024 | QTFY actors intrude at NIH and an HHS agency via an Ivanti Cloud Services Appliance zero-day | No ATT&CK binding | Confirmed | [94] |
| late 2024 onward | Silk Typhoon targets healthcare among other sectors through IT providers, RMM companies and MSPs | [G0125](/mitre/groups/G0125.md) | Confirmed | [69] |
| Jul 2025 | SharePoint ToolShell exploitation, healthcare among the sectors | [C0058](/mitre/campaigns/C0058.md) | Confirmed | [2] |
| 23 Apr 2026 | AA26-113A highest-threat guidance on covert networks names healthcare with energy, transport, digital infrastructure and government | Covert networks | Confirmed | [76] |
| 26 Aug 2026 | Press account of DOJ: targets include US military networks, hospitals, power companies and defense contractors, 2018 to 2026 | QTFY actors | Reported | [95] |
| 8 Oct 2026 | AA26-281A: US Healthcare and Public Health victims, plus healthcare systems in Southeast Asia, with access since mid-January 2021 | Integrity Tech, Flax Typhoon | Confirmed | [80] |

### What the record does not show

Volt Typhoon, the actor most associated with disruption, does not list healthcare among its primary sectors: AA24-038A names Communications, Energy, Transportation Systems and Water and Wastewater (Confirmed [33]). Salt Typhoon targets telecommunications, government, transportation, lodging and military networks (Confirmed [53]). No source in this study attributes a disruptive or ransomware attack on a hospital to a Chinese state actor; the healthcare record is theft of research, identity data and mail (Inferred from [1][23][56][78][86]). The 2024 Change Healthcare ransomware attack, a criminal operation, is covered in its own study, Change Healthcare 2024. Sichuan Silence's plan to deploy ransomware if victims remediated, and Cinnamon Tempest's Babuk-derived ransomware, show the capability exists in the ecosystem (Confirmed [42][1]).

### The healthcare defender's watch list

Ranked by how recent and how health-specific the primary record is (Inferred ranking from the cited sources):

1. **UNC6508** for medical research institutions, academic medical centers, military health and regulators: REDCap and other research applications, credential capture, mail rule abuse [78].
2. **Actors enabled by Integrity Technology Group (Flax Typhoon and related)** for US HPH organizations: automated scanning and covert device networks [80][76].
3. **Silk Typhoon (HAFNIUM)** for any hospital that relies on an IT provider, MSP or RMM tool: stolen API keys and provider credentials [69].
4. **APT41** for medical devices, biotech and pharmaceuticals, per HC3 and its home study [86].
5. **APT40** for biomedical and infectious disease research [87][37].
6. **APT27 and the brokers (Yin, Zhou, i-Soon)** for health systems, especially university-affiliated ones [47][49].

## Part 6: tooling and exploited vulnerabilities

### Shared software

ATT&CK's software records show a shared toolkit across the China-attributed groups, dominated by built-in Windows tools and a few long-lived malware families (Confirmed [3]):

| Software | Type | Groups (of 46) | Notes |
|---|---|---|---|
| [S0039 Net](/mitre/software/S0039.md) | Tool | 15 | Built-in Windows tool |
| [S0002 Mimikatz](/mitre/software/S0002.md) | Tool | 14 | Credential dumping |
| [S0013 PlugX](/mitre/software/S0013.md) | Malware | 12 | Used by Yin and Zhou per DOJ [47] |
| [S0154 Cobalt Strike](/mitre/software/S0154.md) | Malware | 12 | Named in AA21-200B [93] |
| [S0012 PoisonIvy](/mitre/software/S0012.md) | Malware | 11 | |
| [S0057 Tasklist](/mitre/software/S0057.md) | Tool | 9 | Built-in |
| [S0029 PsExec](/mitre/software/S0029.md) | Tool | 8 | |
| [S0032 gh0st RAT](/mitre/software/S0032.md) | Malware | 7 | |
| [S0357 Impacket](/mitre/software/S0357.md) | Tool | 7 | |
| [S0596 ShadowPad](/mitre/software/S0596.md) | Malware | 7 | |
| [S0020 China Chopper](/mitre/software/S0020.md) | Malware | 6 | Web shell |

Volt Typhoon's ATT&CK record adds [S0108 netsh](/mitre/software/S0108.md), [S0359 Nltest](/mitre/software/S0359.md) and [S0645 Wevtutil](/mitre/software/S0645.md), all built in, plus FRP and VersaMem (Confirmed [10]). Salt Typhoon's single software entry is JumbledPath (Confirmed [12]). BRICKSTORM is in ATT&CK as [S9015](/mitre/software/S9015.md), with no group attached (Confirmed [3]). The vendor reports name further families with no ATT&CK object in the library data: GRIDTIDE, INFINITERED, SAWFLY and BARECLAW, and the TINYSHELL-based Juniper backdoors (Confirmed [70][75][78][82][71]).

### Exploited vulnerabilities

Five joint advisories name 43 distinct initial-access CVEs between them, and every one is in CISA's KEV catalog (version 2026.11.03, 1,767 entries); 29 are marked known for ransomware campaign use, 21 were added on 3 November 2021, the catalog's first day, and the most recent additions are CVE-2024-3400 (12 April 2024) and CVE-2024-21887 with CVE-2023-46805 (10 January 2024) (Confirmed [100]).

| Advisory | CVEs it names | Source |
|---|---|---|
| AA22-158A (7 Jun 2022), network devices | Cisco CVE-2018-0171, CVE-2019-15271, CVE-2019-1652; Citrix CVE-2019-19781; DrayTek CVE-2020-8515; D-Link CVE-2019-16920; Fortinet CVE-2018-13382; MikroTik CVE-2018-14847; Netgear CVE-2017-6862; Pulse CVE-2019-11510, CVE-2021-22893; QNAP CVE-2019-7192 to CVE-2019-7195; Zyxel CVE-2020-29583 | [97] |
| AA22-279A (6 Oct 2022), top 20 | Log4j CVE-2021-44228; Pulse CVE-2019-11510; GitLab CVE-2021-22205; Atlassian CVE-2022-26134 and CVE-2021-26084; Exchange CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065; F5 CVE-2020-5902 and CVE-2022-1388; vCenter CVE-2021-22005; Citrix CVE-2019-19781; Cisco HyperFlex CVE-2021-1497; Buffalo CVE-2021-20090; Hikvision CVE-2021-36260; Sitecore CVE-2021-42237; APISIX CVE-2022-24112; Zoho CVE-2021-40539; Apache HTTP CVE-2021-41773 | [99] |
| AA24-038A (7 Feb 2024), Volt Typhoon | CVE-2022-42475 on a FortiGate 300D; Fortinet, Ivanti Connect Secure, NETGEAR, Citrix and Cisco products | [33] |
| AA24-190A (8 Jul 2024), APT40 | CVE-2021-44228, CVE-2021-31207, CVE-2021-26084, CVE-2021-34523, CVE-2021-34473 | [37] |
| AA25-239A (27 Aug 2025), Salt Typhoon | CVE-2024-21887 (with CVE-2023-46805), CVE-2024-3400, CVE-2023-20198, CVE-2023-20273, CVE-2018-0171 | [53] |

Vendor reports add zero-days: the four Exchange CVEs (HAFNIUM, 2021) [59]; CVE-2025-0282 in Ivanti Connect Secure (UNC5221, December 2024) [68]; CVE-2025-21590 in Juniper Junos (UNC3886) [71]; the SharePoint chain CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 and CVE-2025-53771 (July 2025) [72]; and CVE-2026-102764 in BeyondTrust Remote Support (ARMORY CASTLE, August 2026) [82]. Microsoft lists CVE-2023-3519, CVE-2024-3400 and CVE-2025-0282 for Silk Typhoon (Confirmed [69]). The Log4Shell CVE is covered in its own study, [Log4Shell (CVE-2021-44228)](/case-studies/LOG4SHELL.md). The FBI, CNMF and NSA advisory on the Integrity Tech botnet lists 67 CVE entries in an appendix, many on devices that are likely still vendor-supported (Confirmed [39]).

## Part 7: the government record

### Attribution statements by government

| Date | Government | Statement | Confidence words | Source |
|---|---|---|---|---|
| 20 Dec 2018 | UK and allies | APT10 acted for the MSS; ran Cloud Hopper against MSPs since at least 2016 | "highest level of probability" for APT10; MSS relationship highly likely | [22] |
| 19 Jul 2021 | US with the EU, UK and NATO | Exchange zero-day campaign by MSS-affiliated actors; MSS-linked operators ran ransomware for profit | "high degree of confidence" | [60] |
| 19 Jul 2021 | UK | Exchange compromise by a Chinese state-backed actor; APT40 sponsored by the Hainan SSD; APT31 contractors for the MSS | "almost certain"; "highly likely"; "likely" (the press text is flat, the NCSC table is hedged) | [30] |
| 25 Mar 2024 | UK | APT31 reconnaissance of parliamentarians; Electoral Commission compromise by a China state-affiliated entity | "almost certain"; "highly likely" | [36][65] |
| 8 Jul 2024 | Australia with the US, UK, Canada, New Zealand, Germany, South Korea, Japan | APT40 conducts operations for the MSS | Assessment | [37] |
| 8 Jan 2025 | Japan (NPA, NISC) | MirrorFace campaign since about 2019 | suspected of Chinese involvement (this study's translation of the Japanese text) | [45] |
| 28 May 2025 | Czech Republic | PRC responsible for the Foreign Ministry campaign; APT31 carried it out | National attribution; NUKIB: "most likely" through APT31 | [50][51] |
| 27 Aug 2025 | 23 agencies in 13 countries | PRC state-sponsored actors; three companies supply PLA and MSS | Joint assessment | [53] |
| 4 Dec 2025 | US and Canada | BRICKSTORM by PRC state-sponsored actors | Attribution | [73] |
| 23 Apr 2026 | UK with 15 partners | Covert networks used by the majority of China-linked actors | "believed" | [74] |
| 8 Oct 2026 | US, UK, Australia, Canada, Japan, New Zealand, Spain | Actors enabled by Integrity Tech; activity "consistent with" Flax Typhoon, Ethereal Panda and Red Juliett | "consistent with" | [80][81] |

### Treasury sanctions

| Date | Designation | Tie | Source |
|---|---|---|---|
| 25 Mar 2024 | Wuhan Xiaoruizhi, Zhao Guangzong, Ni Gaobin | APT31, MSS Hubei SSD front | [35] |
| 10 Dec 2024 | Sichuan Silence, Guan Tianfeng | Sophos firewall campaign; PRC intelligence clients | [43] |
| 3 Jan 2025 | Integrity Technology Group | Flax Typhoon, summer 2022 to fall 2023 | [44] |
| 17 Jan 2025 | Yin Kecheng, Sichuan Juxinhe | Treasury compromise; Salt Typhoon | [46] |
| 5 Mar 2025 | Zhou Shuai, Shanghai Heiying | Data brokering since 2018 | [49] |

### Disruptions

Three court-authorized or court-ordered actions in the record took infrastructure away from China-attributed actors: Microsoft's seizure of NICKEL websites (December 2021) [61], the KV Botnet removal (December 2023) [32], and the Integrity Tech botnet disruption (September 2024) [38]. A fourth is the August 2026 DOJ seizure affidavit against QTFY actors, described in the affidavit as Chinese hackers (Confirmed [94]); press report three domains seized and the platforms run by Nanjing Xinjiuwei (Reported [95]). GTIG's disruption of UNC2814 in February 2026 was a private-sector action (Confirmed [75]).

### China's response

China's National Computer Virus Emergency Response Center and a national laboratory issued a third report in October 2024, after reports in April and July, calling Volt Typhoon a "political farce" and a US false flag operation. This study saw it only through PRC state media, not the report itself (Reported [63]).

## Part 8: the defender view

### What the advisories ask defenders to watch

Read together, the advisories converge on six detection threads (Inferred synthesis of [29][31][33][37][41][53][97]):

1. **Edge and network-device configuration drift and integrity**: compare running configurations to baselines; check ACLs, local accounts and routing tables; look for guest containers on network operating systems, management services on non-standard ports, TACACS+ to unapproved servers and unexpected GRE or IPsec tunnels; verify firmware and image hashes; capture live artifacts before eradication (Confirmed [53]). Techniques: T1584.008, T1602, T1599.
2. **NTDS and LSASS credential access**: ESENT application log events for NTDS.dit copying; LSASS protection and Credential Guard; attack surface reduction rules against LSASS theft and PsExec or WMI process creation (Confirmed [31][33][62]). Techniques: T1003.001, T1003.003.
3. **Living-off-the-land command lines**: process creation auditing with command line (event 4688), deep PowerShell logging and WMI tracing, against behavioral baselines (Confirmed [31][33]). The joint LOTL guidance warns that many organizations cannot yet tell LOTL activity from legitimate behavior, and AA23-144A warns not to assume findings are malicious without investigation (Confirmed [98][31]). Techniques: T1059.001, T1059.003, T1047.
4. **VPN and RDP logon anomalies**: impossible travel on VPN logons, RDP session review, logon success and failure review for password spraying (Confirmed [31][33]). Techniques: T1078, T1133, T1021.001, T1110.003.
5. **Web shells and execution from world-writable folders**: AA24-190A gives three Sigma rules for execution from world-writable locations, and AA24-038A asks for checks of world-writable folders for unexpected files (Confirmed [37][33]). Technique: T1505.003.
6. **Log clearing**: investigate every Security log clear (event 1102) (Confirmed [33]). Technique: T1685.005.

### What the advisories ask defenders to harden

- **Patch the edge first.** AA24-038A: prioritize known exploited vulnerabilities in internet-facing systems and the targeted appliances (Confirmed [33]). AA24-190A: patches or mitigations for internet-facing devices within 48 hours (Confirmed [37]). AA22-279A: patch KEV-first (Confirmed [99]).
- **Replace end-of-life devices.** Named in AA24-038A, AA24-190A, AA25-239A, AA22-158A and AA22-279A; most KV Botnet routers were end-of-life Cisco and NetGear devices (Confirmed [33][37][53][97][99][32]).
- **Isolate management.** An isolated management VRF or out-of-band network with default-deny ACLs; SSHv2 and SNMPv3 only; public-key authentication; disable Smart Install; block outbound traffic from management interfaces (Confirmed [53][97]). Keep SOHO and edge management interfaces off the internet (Confirmed [31][62]).
- **Phishing-resistant MFA and tiered administration.** No credentials stored on edge devices; reset krbtgt twice on suspected compromise; default-deny IT and OT segmentation (Confirmed [33]).
- **Centralized, encrypted logging**, including AAA command accounting on network devices and web, Windows event and proxy logs (Confirmed [53][37]).
- **For consumer and SOHO devices**: disable UPnP, remote management and file sharing; segment IoT; monitor traffic volume; patch firmware; replace default passwords (Confirmed [39]).

### The vulnerability-management view

For a VM program, the China advisories reduce to an edge-first rule: the KEV due-date queue for internet-facing VPN, firewall, router and web-application CVEs is the control most aligned with the record, and AA24-190A's 48-hour window is the government benchmark for time-to-mitigate (Inferred [37][100]). All 43 initial-access CVEs named across the five advisories are in KEV as of catalog version 2026.11.03 (Confirmed [100]), which means a program that closes KEV edge findings quickly covers the documented entry points; zero-day entries such as CVE-2025-0282 and the BeyondTrust flaw are the residual risk, and the advisories' answer to them is monitoring and isolation of the device rather than patch speed (Inferred [68][82][53]). Phishing still matters: Spearphishing Attachment is the sixth most shared technique across the 46 groups in ATT&CK's records (Confirmed [3]).

### For hospitals and research institutions

Apply the edge rule first, then the health-specific record (Inferred from Part 5):

- Inventory research applications such as REDCap, put them behind the same edge patching and authentication rules as clinical systems, and audit mail transport and compliance rules for changes that copy or forward mail (Confirmed [78] for the abuse; the control is Inferred).
- Review every IT service provider, MSP and RMM integration, rotate API keys and provider credentials, and log provider access to tenants (Confirmed [69] for the access path; the control is Inferred).
- Include academic medical centers' university networks in scope: the APT40 and Zhou Shuai records name university schools of medicine and academic health systems (Confirmed [87][49]).

## Part 9: MITRE mappings

This Part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND, with every id checked against the live MITRE page or the library's data files on 3 November 2026. None of the 47 China-attributed groups appears in the library's ATT&CK for ICS or Mobile group files, so there is no ICS or Mobile table (Confirmed [7]). Volt Typhoon's OT intent is an assessment about future disruption, not a recorded ICS technique (Confirmed [33]).

### ATT&CK Enterprise techniques named in government advisories

Each id below is named in at least one joint government advisory on PRC actors and checked against `data/attack/technique_profiles.jsonl` (Confirmed [101]). The advisories name more techniques than this table; it lists the subset this study verified. Ids that the source reported under an earlier ATT&CK version and that are revoked in v20.0 are shown under their successor from `data/attack/superseded_by.jsonl`.

| Id | Name | Tactic (v20.0) | Where it appears in the record | Source |
|---|---|---|---|---|
| [T1595.002](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | Reconnaissance | AA22-158A (PRC actors, network devices, 7 Jun 2022) | [97] |
| [T1584.005](/mitre/techniques/T1584-005.md) | Botnet | Resource Development | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1584.008](/mitre/techniques/T1584-008.md) | Network Devices | Resource Development | AA24-190A (APT40, 8 Jul 2024); AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [37][53] |
| [T1078](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | AA21-200A (APT40, 19 Jul 2021); AA24-038A (Volt Typhoon, 7 Feb 2024) | [29][33] |
| [T1078.002](/mitre/techniques/T1078-002.md) | Domain Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1133](/mitre/techniques/T1133.md) | External Remote Services | Persistence, Initial Access | AA21-200A (APT40, 19 Jul 2021); AA22-158A (PRC actors, network devices, 7 Jun 2022); AA24-038A (Volt Typhoon, 7 Feb 2024) | [29][97][33] |
| [T1189](/mitre/techniques/T1189.md) | Drive-by Compromise | Initial Access | AA21-200A (APT40, 19 Jul 2021) | [29] |
| [T1190](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | AA21-200A (APT40, 19 Jul 2021); AA22-158A (PRC actors, network devices, 7 Jun 2022); AA23-144A (Volt Typhoon, 24 May 2023); AA24-038A (Volt Typhoon, 7 Feb 2024); AA24-190A (APT40, 8 Jul 2024) | [29][97][31][33][37] |
| [T1199](/mitre/techniques/T1199.md) | Trusted Relationship | Initial Access | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1566.001](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | Initial Access | AA21-200A (APT40, 19 Jul 2021) | [29] |
| [T1566.002](/mitre/techniques/T1566-002.md) | Spearphishing Link | Initial Access | AA21-200A (APT40, 19 Jul 2021) | [29] |
| [T1047](/mitre/techniques/T1047.md) | Windows Management Instrumentation | Execution | AA23-144A (Volt Typhoon, 24 May 2023); AA24-038A (Volt Typhoon, 7 Feb 2024) | [31][33] |
| [T1059.001](/mitre/techniques/T1059-001.md) | PowerShell | Execution | AA23-144A (Volt Typhoon, 24 May 2023); AA24-038A (Volt Typhoon, 7 Feb 2024) | [31][33] |
| [T1059.003](/mitre/techniques/T1059-003.md) | Windows Command Shell | Execution | AA23-144A (Volt Typhoon, 24 May 2023) | [31] |
| [T1059.008](/mitre/techniques/T1059-008.md) | Network Device CLI | Execution | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1072](/mitre/techniques/T1072.md) | Software Deployment Tools | Execution, Lateral Movement | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1609](/mitre/techniques/T1609.md) | Container Administration Command | Execution | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1610](/mitre/techniques/T1610.md) | Deploy Container | Execution | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1098.004](/mitre/techniques/T1098-004.md) | SSH Authorized Keys | Persistence, Privilege Escalation | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1505.003](/mitre/techniques/T1505-003.md) | Web Shell | Persistence | AA21-200A (APT40, 19 Jul 2021); AA23-144A (Volt Typhoon, 24 May 2023); AA24-190A (APT40, 8 Jul 2024) | [29][31][37] |
| [T1543.005](/mitre/techniques/T1543-005.md) | Container Service | Persistence, Privilege Escalation | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1556](/mitre/techniques/T1556.md) | Modify Authentication Process | Defense Impairment, Persistence, Credential Access | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1006](/mitre/techniques/T1006.md) | Direct Volume Access | Stealth | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1036.005](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | Stealth | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1070.009](/mitre/techniques/T1070-009.md) | Clear Persistence | Stealth | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1218](/mitre/techniques/T1218.md) | System Binary Proxy Execution | Stealth | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1599](/mitre/techniques/T1599.md) | Network Boundary Bridging | Defense Impairment | AA22-158A (PRC actors, network devices, 7 Jun 2022); AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [97][53] |
| [T1685.005](/mitre/techniques/T1685-005.md) | Clear Windows Event Logs (reported as T1070.001, revoked in v20.0) | Defense Impairment | AA23-144A (Volt Typhoon, 24 May 2023); AA24-038A (Volt Typhoon, 7 Feb 2024) | [31][33][4] |
| [T1686](/mitre/techniques/T1686.md) | Disable or Modify System Firewall (reported as T1562.004, revoked in v20.0) | Defense Impairment | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53][4] |
| [T1003.001](/mitre/techniques/T1003-001.md) | LSASS Memory | Credential Access | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1003.003](/mitre/techniques/T1003-003.md) | NTDS | Credential Access | AA23-144A (Volt Typhoon, 24 May 2023); AA24-038A (Volt Typhoon, 7 Feb 2024) | [31][33] |
| [T1040](/mitre/techniques/T1040.md) | Network Sniffing | Credential Access, Discovery | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1056.003](/mitre/techniques/T1056-003.md) | Web Portal Capture | Collection, Credential Access | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1110.003](/mitre/techniques/T1110-003.md) | Password Spraying | Credential Access | AA23-144A (Volt Typhoon, 24 May 2023) | [31] |
| [T1111](/mitre/techniques/T1111.md) | Multi-Factor Authentication Interception | Credential Access | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1528](/mitre/techniques/T1528.md) | Steal Application Access Token | Credential Access | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1539](/mitre/techniques/T1539.md) | Steal Web Session Cookie | Credential Access | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1555](/mitre/techniques/T1555.md) | Credentials from Password Stores | Credential Access | AA23-144A (Volt Typhoon, 24 May 2023) | [31] |
| [T1558.003](/mitre/techniques/T1558-003.md) | Kerberoasting | Credential Access | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1069.001](/mitre/techniques/T1069-001.md) | Local Groups | Discovery | AA23-144A (Volt Typhoon, 24 May 2023) | [31] |
| [T1069.002](/mitre/techniques/T1069-002.md) | Domain Groups | Discovery | AA23-144A (Volt Typhoon, 24 May 2023) | [31] |
| [T1654](/mitre/techniques/T1654.md) | Log Enumeration | Discovery | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1021.001](/mitre/techniques/T1021-001.md) | Remote Desktop Protocol | Lateral Movement | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1021.002](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | Lateral Movement | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1021.007](/mitre/techniques/T1021-007.md) | Cloud Services | Lateral Movement | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1563.002](/mitre/techniques/T1563-002.md) | RDP Hijacking | Lateral Movement | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1560](/mitre/techniques/T1560.md) | Archive Collected Data | Collection | AA21-200A (APT40, 19 Jul 2021) | [29] |
| [T1560.001](/mitre/techniques/T1560-001.md) | Archive via Utility | Collection | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1602.001](/mitre/techniques/T1602-001.md) | SNMP (MIB Dump) | Collection | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1602.002](/mitre/techniques/T1602-002.md) | Network Device Configuration Dump | Collection | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |
| [T1001.003](/mitre/techniques/T1001-003.md) | Protocol or Service Impersonation | Command and Control | AA24-190A (APT40, 8 Jul 2024) | [37] |
| [T1090.001](/mitre/techniques/T1090-001.md) | Internal Proxy | Command and Control | AA24-038A (Volt Typhoon, 7 Feb 2024) | [33] |
| [T1090.002](/mitre/techniques/T1090-002.md) | External Proxy | Command and Control | AA23-144A (Volt Typhoon, 24 May 2023) | [31] |
| [T1090.003](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | Command and Control | AA21-200A (APT40, 19 Jul 2021); AA24-038A (Volt Typhoon, 7 Feb 2024); AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [29][33][53] |
| [T1572](/mitre/techniques/T1572.md) | Protocol Tunneling | Command and Control | AA21-200A (APT40, 19 Jul 2021); AA22-158A (PRC actors, network devices, 7 Jun 2022); AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [29][97][53] |
| [T1020.001](/mitre/techniques/T1020-001.md) | Traffic Duplication | Exfiltration | AA22-158A (PRC actors, network devices, 7 Jun 2022) | [97] |
| [T1041](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | Exfiltration | AA21-200A (APT40, 19 Jul 2021); AA24-190A (APT40, 8 Jul 2024) | [29][37] |
| [T1048.003](/mitre/techniques/T1048-003.md) | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | AA25-239A (Salt Typhoon cluster, 27 Aug 2025) | [53] |

### ATT&CK Enterprise techniques most shared across China-attributed groups

ATT&CK v20.0 records 320 distinct Enterprise techniques across the 46 groups (Scarlet Mimic set aside); this table gives the 30 most shared, with the number of groups and whether a verified advisory names the same id (Confirmed [3]; names and tactics [101]). The counts reflect how much has been reported about each group, not how often each technique is used (Inferred [3]).

| Rank | Id | Name | Tactic (v20.0) | Groups | In an advisory above |
|---|---|---|---|---|---|
| 1 | [T1105](/mitre/techniques/T1105.md) | Ingress Tool Transfer | Command and Control | 23 | no |
| 2 | [T1059.001](/mitre/techniques/T1059-001.md) | PowerShell | Execution | 21 | yes |
| 3 | [T1588.002](/mitre/techniques/T1588-002.md) | Tool | Resource Development | 21 | no |
| 4 | [T1059.003](/mitre/techniques/T1059-003.md) | Windows Command Shell | Execution | 20 | yes |
| 5 | [T1204.002](/mitre/techniques/T1204-002.md) | Malicious File | Execution | 19 | no |
| 6 | [T1566.001](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | Initial Access | 19 | yes |
| 7 | [T1016](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | 18 | no |
| 8 | [T1574.001](/mitre/techniques/T1574-001.md) | DLL | Stealth, Execution | 18 | no |
| 9 | [T1018](/mitre/techniques/T1018.md) | Remote System Discovery | Discovery | 17 | no |
| 10 | [T1190](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | 17 | yes |
| 11 | [T1003.001](/mitre/techniques/T1003-001.md) | LSASS Memory | Credential Access | 16 | yes |
| 12 | [T1083](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | 16 | no |
| 13 | [T1560.001](/mitre/techniques/T1560-001.md) | Archive via Utility | Collection | 16 | yes |
| 14 | [T1005](/mitre/techniques/T1005.md) | Data from Local System | Collection | 15 | no |
| 15 | [T1036.005](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | Stealth | 15 | yes |
| 16 | [T1203](/mitre/techniques/T1203.md) | Exploitation for Client Execution | Execution | 15 | no |
| 17 | [T1033](/mitre/techniques/T1033.md) | System Owner/User Discovery | Discovery | 14 | no |
| 18 | [T1047](/mitre/techniques/T1047.md) | Windows Management Instrumentation | Execution | 14 | yes |
| 19 | [T1057](/mitre/techniques/T1057.md) | Process Discovery | Discovery | 14 | no |
| 20 | [T1078](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | 14 | yes |
| 21 | [T1049](/mitre/techniques/T1049.md) | System Network Connections Discovery | Discovery | 13 | no |
| 22 | [T1070.004](/mitre/techniques/T1070-004.md) | File Deletion | Stealth | 13 | no |
| 23 | [T1071.001](/mitre/techniques/T1071-001.md) | Web Protocols | Command and Control | 13 | no |
| 24 | [T1547.001](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | 13 | no |
| 25 | [T1021.001](/mitre/techniques/T1021-001.md) | Remote Desktop Protocol | Lateral Movement | 12 | yes |
| 26 | [T1082](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | 12 | no |
| 27 | [T1140](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | Stealth | 12 | no |
| 28 | [T1046](/mitre/techniques/T1046.md) | Network Service Discovery | Discovery | 11 | no |
| 29 | [T1053.005](/mitre/techniques/T1053-005.md) | Scheduled Task | Execution, Persistence, Privilege Escalation | 11 | no |
| 30 | [T1566.002](/mitre/techniques/T1566-002.md) | Spearphishing Link | Initial Access | 11 | yes |

In the 15 groups this study profiles most closely (G0004, G0006, G0022, G0027, G0045, G0065, G0096, G0125, G0128, G0129, G0143, G1017, G1023, G1045, G1048) the leaders are T1059.003 (13 groups), T1003.001 (12), T1105 (12), T1016 (11), T1560.001 (11), T1059.001 (11), T1005 (10) and T1190 (10), across 286 distinct techniques (Confirmed [3]). Spearphishing Attachment is recorded for 19 of the 46 groups in the full set but for only 6 of these 15, while T1190 holds at 10 of 15: the groups with recent advisories lean on edge and public-facing exploitation (Inferred [3]).

### ATT&CK groups

| Group | Id and library page | Government or vendor record in this study | Source |
|---|---|---|---|
| APT1 | [G0006](/mitre/groups/G0006.md) | Unit 61398 indictment, 2014; Mandiant, 2013 | [18][55] |
| menuPass (APT10) | [G0045](/mitre/groups/G0045.md) | Indictment and UK attribution, 2018; BAE, 2017 | [21][22][58] |
| Leviathan (APT40) | [G0065](/mitre/groups/G0065.md) | Indictment, AA21-200A, 2021; AA24-190A, 2024 | [28][29][37] |
| ZIRCONIUM (APT31) | [G0128](/mitre/groups/G0128.md) | Indictment, OFAC, UK, 2024; Czech attribution, 2025 | [34][35][36][50] |
| Threat Group-3390 (APT27) | [G0027](/mitre/groups/G0027.md) | i-Soon and APT27 charges, OFAC, 2025 | [47][49] |
| HAFNIUM (Silk Typhoon) | [G0125](/mitre/groups/G0125.md) | Microsoft, 2021 and 2025; US, UK attribution 2021; Xu Zewei, 2025 | [59][60][30][52][69] |
| APT41 | [G0096](/mitre/groups/G0096.md) | Charges, 2020; home study | [27] |
| Volt Typhoon | [G1017](/mitre/groups/G1017.md) | AA23-144A, AA24-038A, KV Botnet disruption | [31][32][33] |
| Salt Typhoon | [G1045](/mitre/groups/G1045.md) | FBI and CISA statement, OFAC, AA25-239A | [40][46][53] |
| UNC3886 | [G1048](/mitre/groups/G1048.md) | Mandiant, 2025 | [71] |
| Ke3chang (NICKEL) | [G0004](/mitre/groups/G0004.md) | Microsoft DCU seizure, 2021 | [61] |
| APT3 | [G0022](/mitre/groups/G0022.md) | ATT&CK: attributed by researchers to the MSS [1]; Boyusec charges, 2017, do not name APT3 [19] | [1][19] |
| Deep Panda | [G0009](/mitre/groups/G0009.md) | Anthem per ATT&CK; Anthem indictment names no group | [1][23] |
| Aquatic Panda | [G0143](/mitre/groups/G0143.md) | i-Soon industry name, FBI 2025 | [48][96] |
| MirrorFace | [G1054](/mitre/groups/G1054.md) | Japan NPA and NISC, 2025 | [45] |
| Mustang Panda | [G0129](/mitre/groups/G0129.md) | ATT&CK record | [8] |
| Chimera | [G0114](/mitre/groups/G0114.md) | ATT&CK record | [11] |
| APT5 | [G1023](/mitre/groups/G1023.md) | ATT&CK record (SPACEHOP) | [1][17] |
| PittyTiger | [G0011](/mitre/groups/G0011.md) | ATT&CK record; HC3 equates it with APT24, not bound here | [1][83] |
| APT18 | [G0026](/mitre/groups/G0026.md) | HC3; no China wording in ATT&CK | [83][86][1] |

Actors in the record with no ATT&CK group object in the library: Flax Typhoon, Storm-0558, UNC5221 (ARMORY CASTLE), UNC2814, UNC6508, Storm-2603, APT22, APT20, APT9 and APT24 (Confirmed [1][6]). Linen Typhoon and Violet Typhoon are aliases of G0027 and G0128 (Confirmed [1]). All other groups in Part 1 have a page under /mitre/groups/.

### ATT&CK campaigns

| Campaign | Id and library page | Dates | Group | Source |
|---|---|---|---|---|
| APT41 campaign | [C0017](/mitre/campaigns/C0017.md) | May 2021 to Feb 2022 | G0096 | [9] |
| APT41 DUST | [C0040](/mitre/campaigns/C0040.md) | Jan 2023 to Jun 2024 | G0096 | [9] |
| KV Botnet Activity | [C0035](/mitre/campaigns/C0035.md) | Oct 2022 to Jan 2024 | G1017 | [10] |
| Versa Director Zero Day Exploitation | [C0039](/mitre/campaigns/C0039.md) | Jun to Aug 2024 | G1017 | [10] |
| Leviathan Australian Intrusions | [C0049](/mitre/campaigns/C0049.md) | Apr to Sep 2022 | G0065 | [14] |
| RedDelta Modified PlugX Infection Chain Operations | [C0047](/mitre/campaigns/C0047.md) | Jul 2023 to Dec 2024 | G0129 | [8] |
| SPACEHOP Activity | [C0052](/mitre/campaigns/C0052.md) | Jan 2019 to May 2024 | G1023, G0004 | [17] |
| RedPenguin | [C0056](/mitre/campaigns/C0056.md) | Jul 2024 to Mar 2025 | G1048 | [15] |
| Operation AkaiRyū | [C0060](/mitre/campaigns/C0060.md) | Jun to Sep 2024 | G1054 (ATT&CK places MirrorFace under the menuPass umbrella; no G0045 link on the campaign) | [1] |
| Indian Critical Infrastructure Intrusions | [C0043](/mitre/campaigns/C0043.md) | Jan 2021 to Apr 2022 | none attached; the description names RedEcho (G1042) and TAG38 | [2] |
| SharePoint ToolShell Exploitation | [C0058](/mitre/campaigns/C0058.md) | Jul 2025 | G0027, G0128 | [2] |
| Night Dragon, FunnyDream, CuckooBees, Wocao, Cutting Edge, FLORAHOX, Quad7, Digital Eye, AI-orchestrated campaign | [C0002](/mitre/campaigns/C0002.md), [C0007](/mitre/campaigns/C0007.md), [C0012](/mitre/campaigns/C0012.md), [C0014](/mitre/campaigns/C0014.md), [C0029](/mitre/campaigns/C0029.md), [C0053](/mitre/campaigns/C0053.md), [C0055](/mitre/campaigns/C0055.md), [C0061](/mitre/campaigns/C0061.md), [C0062](/mitre/campaigns/C0062.md) | See Part 1 | No group object (C0053 is linked to ZIRCONIUM in the library data) | [2] |

### ATT&CK software

The shared-software table in Part 6 links each id. Additional software bound by the record: [S1206 JumbledPath](/mitre/software/S1206.md) (Salt Typhoon), [S1144 FRP](/mitre/software/S1144.md), [S1154 VersaMem](/mitre/software/S1154.md), [S0108 netsh](/mitre/software/S0108.md), [S0359 Nltest](/mitre/software/S0359.md) and [S0645 Wevtutil](/mitre/software/S0645.md) (Volt Typhoon) (Confirmed [10][12]), and [S9015 BRICKSTORM](/mitre/software/S9015.md) (UNC5221, BRICKSTORM [70][73]; no group attached in ATT&CK, Confirmed [3]).

### CAPEC and CWE

No advisory or vendor report in this study names a CAPEC pattern. The CAPEC entries below are the library's own technique-to-CAPEC mappings in `technique_profiles.jsonl` for the advisory techniques in this Part, limited to those that describe a behavior the record shows (Confirmed [101] for the mapping; the selection is Inferred). Other library mappings for these techniques (for example CAPEC-665 for T1556, CAPEC-187 and CAPEC-657 for T1072) describe mechanisms not in the record and are left out.

| CAPEC | Name | Technique it maps to | Where the behavior appears |
|---|---|---|---|
| [CAPEC-163](/mitre/capec/CAPEC-163.md) | Spear Phishing | T1566.001, T1566.002 | AA21-200A [29] |
| [CAPEC-555](/mitre/capec/CAPEC-555.md) | Remote Services with Stolen Credentials | T1133 | AA21-200A, AA22-158A, AA24-038A [29][97][33] |
| [CAPEC-560](/mitre/capec/CAPEC-560.md) | Use of Known Domain Credentials | T1078 | AA21-200A, AA24-038A [29][33] |
| [CAPEC-650](/mitre/capec/CAPEC-650.md) | Upload a Web Shell to a Web Server | T1505.003 | AA21-200A, AA23-144A, AA24-190A [29][31][37] |
| [CAPEC-565](/mitre/capec/CAPEC-565.md) | Password Spraying | T1110.003 | AA23-144A [31] |
| [CAPEC-509](/mitre/capec/CAPEC-509.md) | Kerberoasting | T1558.003 | AA24-190A [37] |
| [CAPEC-561](/mitre/capec/CAPEC-561.md) | Windows Admin Shares with Stolen Credentials | T1021.002 | AA24-190A [37] |
| [CAPEC-31](/mitre/capec/CAPEC-31.md) | Accessing/Intercepting/Modifying HTTP Cookies | T1539 | AA24-190A [37] |
| [CAPEC-158](/mitre/capec/CAPEC-158.md) | Sniffing Network Traffic | T1040 | AA25-239A [53] |
| [CAPEC-700](/mitre/capec/CAPEC-700.md) | Network Boundary Bridging | T1599 | AA22-158A, AA25-239A [97][53] |

CWE: the weakness class of each named CVE is set by its NVD record, and those records were not opened for this study, so no CWE ids are bound here (not checked). The CVE-level CWE for Log4Shell is in [the Log4Shell study](/case-studies/LOG4SHELL.md).

### D3FEND countermeasures

Three advisories map their mitigations to D3FEND: AA25-239A (Appendix C, D3FEND v1.2.0), AA22-158A and AA21-200B (Confirmed [53][97][93]). The table lists 22 of the 39 advisory-named countermeasures that have a library page, chosen because they map to techniques in this Part's advisory table, with the techniques in this Part's advisory table that the library's `d3fend_countermeasures.jsonl` maps to each (Confirmed [5]). Fifteen advisory-named countermeasures are absent: D3-PM Platform Monitoring, D3-NI Network Isolation, D3-NTA Network Traffic Analysis, D3-FCR, D3-PA, D3-SEA, D3-OSM, D3-FAPA, D3-UBA, D3-ANET, D3-JFAPA, D3-AH, D3-PH, D3-TAAN and D3-MAC are named by the advisories but absent from the library's D3FEND 1.6.0 data, so they are not linked (Confirmed [5]). AA21-200B itself cautions that its D3FEND mapping may not match automated mappings (Confirmed [93]).

| Countermeasure | Id | D3FEND tactic | Named in | Library-mapped techniques from this study | Source |
|---|---|---|---|---|---|
| [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md) | D3-NTCD | Detect | AA25-239A | 15, including T1190, T1199, T1572, T1090.003, T1048.003 | [53][5] |
| [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) | D3-OTF | Isolate | AA25-239A, AA21-200B | T1048.003, T1090.002, T1090.003, T1572 | [53][93][5] |
| [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) | D3-ACH | Harden | AA25-239A | none in this set | [53][5] |
| [Change Default Password](/mitre/d3fend/change-default-password.md) | D3-CDP | Harden | AA25-239A (the advisory's rendered page shows D3-CFP; the library id is D3-CDP) | T1078, T1078.002, T1110.003 | [53][5] |
| [Credential Hardening](/mitre/d3fend/credential-hardening.md) | D3-CH | Harden | AA25-239A, AA21-200B | T1003.003, T1110.003, T1528, T1539 | [53][93][5] |
| [Software Update](/mitre/d3fend/software-update.md) | D3-SU | Harden | AA25-239A, AA22-158A, AA21-200B | T1056.003, T1072 | [53][97][93][5] |
| [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) | D3-ITF | Isolate | AA25-239A, AA21-200B | T1190, T1566.001, T1566.002 | [53][93][5] |
| [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) | D3-MFA | Harden | AA22-158A, AA21-200B | T1003.003, T1110.003, T1528, T1539 | [97][93][5] |
| [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) | D3-SPP | Harden | AA22-158A | T1110.003 | [97][5] |
| [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) | D3-CAA | Detect | AA21-200B | T1047, T1090.001, T1110.003, T1199 | [93][5] |
| [Process Lineage Analysis](/mitre/d3fend/process-lineage-analysis.md) | D3-PLA | Detect | AA21-200B | T1003.001, T1505.003, T1556 | [93][5] |
| [Process Spawn Analysis](/mitre/d3fend/process-spawn-analysis.md) | D3-PSA | Detect | AA21-200B | T1003.001, T1047, T1505.003, T1556 | [93][5] |
| [Administrative Network Activity Analysis](/mitre/d3fend/administrative-network-activity-analysis.md) | D3-ANAA | Detect | AA21-200B | T1047, T1110.003 | [93][5] |
| [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md) | D3-RPA | Detect | AA21-200B | T1048.003, T1090.002, T1090.003, T1572 | [93][5] |
| [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) | D3-UGLPA | Detect | AA21-200B | 15, the same set as D3-NTCD | [93][5] |
| [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) | D3-RTSD | Detect | AA21-200B | 15, the same set as D3-NTCD | [93][5] |
| [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md) | D3-DNSTA | Detect | AA21-200B | T1040 | [93][5] |
| [Message Authentication](/mitre/d3fend/message-authentication.md) | D3-MAN | Harden | AA21-200B | none in this set | [93][5] |
| [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) | D3-EAL | Isolate | AA21-200B | T1047, T1505.003 | [93][5] |
| [Executable Denylisting](/mitre/d3fend/executable-denylisting.md) | D3-EDL | Isolate | AA21-200B | T1047, T1505.003 | [93][5] |
| [DNS Denylisting](/mitre/d3fend/dns-denylisting.md) | D3-DNSDL | Isolate | AA21-200B | none in this set | [93][5] |
| [Hardware-based Process Isolation](/mitre/d3fend/hardware-based-process-isolation.md) | D3-HBPI | Isolate | AA21-200B | T1003.001, T1047, T1505.003, T1556 | [93][5] |

A note on the automated join. Joining the 30 most shared techniques to the library's `technique_to_d3fend.jsonl` is dominated by generic file-artifact countermeasures (Content Filtering, File Analysis and File Integrity Monitoring each cover 15 of the 30), and four of the 30 (T1588.002, T1059.001, T1059.003, T1046) have no mapping at all; the advisory-named countermeasures above are the better guide, and the automated join is secondary (Inferred [5]). The three countermeasures that map to the same 15 techniques (D3-NTCD, D3-UGLPA, D3-RTSD) show the same effect: they map to network-facing techniques broadly rather than to these specific advisories (Inferred [5]).

### Navigator layer

The study's techniques are saved as an ATT&CK Navigator layer, [navigator/library-layers/threat-actors-china.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/threat-actors-china.json), listed on [the Navigator layers page](/navigator/index.md). It is pinned to ATT&CK v20 and holds 77 techniques: the 58 named in the six government advisories in this Part, scored 100, and the 19 of the 30 most shared techniques that no verified advisory names, scored 60. Each entry's comment names the source numbers above.

## Cross-cutting themes

- **The state works through companies.** Front companies (Hainan Xiandun, Wuhan Xiaoruizhi), contractors (Huaying Haitai, Shanghai Powerock, i-Soon, Sichuan Silence) and infrastructure vendors (Integrity Tech, Sichuan Juxinhe) recur across a decade of indictments and sanctions (Confirmed [21][28][35][52][47][42][44][46]). Sanctions now target the companies directly, a lever that does not depend on a defendant travelling to a country that will extradite, as Xu Zewei did (Inferred from [52][92]).
- **The edge replaced the inbox.** From spearphishing and watering holes in AA21-200A to network-device CLI, container services on routers and configuration dumps in AA25-239A, the advisories trace the move to devices that most security tools do not watch (Confirmed [29][53]; the trend reading is Inferred).
- **Infrastructure is borrowed or bought, not built.** KV Botnet, the Integrity Tech botnet, Raptor Train (over 200,000 devices in 2024) and the covert networks NCSC describes mean an intrusion's source address says little about who is behind it (Confirmed [32][38][76][74]; the consequence is Inferred).
- **Names are a mess, and the sources disagree on the record.** Silk Typhoon sits under HAFNIUM in ATT&CK and Microsoft but under APT27 actors in the FBI's PSA; GTIG says UNC5221 is not Silk Typhoon while Microsoft lists UNC5221's zero-day for Silk Typhoon; AA25-239A says the Salt Typhoon vendor names partially overlap and are not one to one (Confirmed [1][48][69][70][53]). Map names to ids, and carry the source with every mapping (Inferred). See [Threat Actors](/THREAT_ACTORS.md).
- **Healthcare is an intelligence target first.** The record is research theft, identity data and mail, with ransomware capability present in the ecosystem but no state-attributed disruptive hospital attack in these sources (Inferred from Part 5).

### Where the sources disagree

| Question | One source | Another source |
|---|---|---|
| When Volt Typhoon started | Microsoft: mid-2021 [62]; ATT&CK: since at least 2021 [10] | AA24-038A: footholds of at least five years in some victims [33] |
| Volt Typhoon's intent | Microsoft: moderate confidence on developing disruption capability [62] | AA24-038A: high confidence of pre-positioning for OT disruption [33] |
| When Salt Typhoon started | Treasury and ATT&CK: since at least 2019 [46][12] | AA25-239A: since at least 2021 [53] |
| Who Silk Typhoon is | ATT&CK and Microsoft: HAFNIUM [1][69] | FBI PSA: a name for APT27 actors Yin and Zhou [48] |
| CVE-2025-0282 | Microsoft: in Silk Typhoon's zero-days [69] | Mandiant and GTIG: UNC5221, which is not Silk Typhoon [68][70] |
| BRICKSTORM | GTIG: suspected China-nexus [70] | CISA, NSA and the Cyber Centre: PRC state-sponsored [73] |
| APT40's Hainan basing | AA21-200A: stated [29] | AA24-190A: cited as prior reporting [37] |
| APT10 and healthcare | DOJ release: healthcare among target industries [21] | FBI wanted notice: healthcare not listed [90] |
| OPM 2015 | Not checked: this study opened no source that names China for OPM | House Oversight report: "a foreign adversary" only [57] |
| Who Charcoal Typhoon is | ATT&CK: alias of Earth Lusca G1006 [1] | FBI PSA: an industry name for i-Soon [48] |
| GRIDTIDE reach | GTIG body: 53 confirmed victims in 42 countries, plus 20 more countries | The same post's conclusion: over 70 countries [75] |
| Volt Typhoon itself | Ten agencies in five countries [33] | China's CVERC: a US false flag (Reported) [63] |

### What is overstated and what is understated

- **Overstated: "Chinese hackers" as one actor.** The record names separate PLA, MSS and MPS lines, provincial bureaus, contractors and brokers with different missions (Confirmed [18][21][35][42][47]). Treating them as one blurs which defenses matter (Inferred).
- **Overstated: novelty.** The telecom guidance found that exploitation matched existing weaknesses and observed no novel activity, and AA25-239A observed no zero-day use (Confirmed [41][53]).
- **Understated: dwell time.** Five-year footholds and a 393-day average dwell mean a clean scan today says little about the last year (Confirmed [33][70]; the reading is Inferred).
- **Understated: health research as a target.** The healthcare focus usually falls on ransomware (Inferred); the state-attributed record is research and identity data theft from 2011 to 2025 (Confirmed [87][23][78][80]).

## Sources

All sources were opened on 3 November 2026. "Primary" means the organization that published the fact; grades apply to the source as used here. The library data files are at commit e85b559 or current main.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | TeamStarWolf library, ATT&CK v20.0 groups data (`groups.jsonl`) | [github.com/TeamStarWolf/TeamStarWolf/.../data/attack/groups.jsonl](https://github.com/TeamStarWolf/TeamStarWolf/blob/e85b5594301fe061043fe92040135252c97b695d/data/attack/groups.jsonl) | 2026-11-03 | Confirmed |
| 2 | TeamStarWolf library, campaign data (`campaign_profiles.jsonl`, `campaigns.jsonl`) | [github.com/TeamStarWolf/TeamStarWolf/.../data/attack/campaign_profiles.jsonl](https://github.com/TeamStarWolf/TeamStarWolf/blob/e85b5594301fe061043fe92040135252c97b695d/data/attack/campaign_profiles.jsonl) | 2026-11-03 | Confirmed |
| 3 | TeamStarWolf library, group technique and software data (`group_to_technique.jsonl`, `group_profiles.jsonl`) | [github.com/TeamStarWolf/TeamStarWolf/.../data/attack/group_to_technique.jsonl](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/group_to_technique.jsonl) | 2026-11-03 | Confirmed |
| 4 | TeamStarWolf library, revoked ATT&CK ids (`superseded_by.jsonl`) | [github.com/TeamStarWolf/TeamStarWolf/.../data/attack/superseded_by.jsonl](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/superseded_by.jsonl) | 2026-11-03 | Confirmed |
| 5 | TeamStarWolf library, D3FEND data (`d3fend_countermeasures.jsonl`, `technique_to_d3fend.jsonl`) | [github.com/TeamStarWolf/TeamStarWolf/.../data/attack/d3fend_countermeasures.jsonl](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/d3fend_countermeasures.jsonl) | 2026-11-03 | Confirmed |
| 6 | TeamStarWolf library, generated group pages (`mitre/groups/`) | [github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/groups](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/groups) | 2026-11-03 | Confirmed |
| 7 | TeamStarWolf library, ATT&CK data tree including ICS and Mobile | [github.com/TeamStarWolf/TeamStarWolf/tree/.../data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/e85b5594301fe061043fe92040135252c97b695d/data/attack) | 2026-11-03 | Confirmed |
| 8 | MITRE ATT&CK, G0129 Mustang Panda | [attack.mitre.org/groups/G0129](https://attack.mitre.org/groups/G0129/) | 2026-11-03 | Confirmed |
| 9 | MITRE ATT&CK, G0096 APT41 | [attack.mitre.org/groups/G0096](https://attack.mitre.org/groups/G0096/) | 2026-11-03 | Confirmed |
| 10 | MITRE ATT&CK, G1017 Volt Typhoon | [attack.mitre.org/groups/G1017](https://attack.mitre.org/groups/G1017/) | 2026-11-03 | Confirmed |
| 11 | MITRE ATT&CK, G0114 Chimera | [attack.mitre.org/groups/G0114](https://attack.mitre.org/groups/G0114/) | 2026-11-03 | Confirmed |
| 12 | MITRE ATT&CK, G1045 Salt Typhoon | [attack.mitre.org/groups/G1045](https://attack.mitre.org/groups/G1045/) | 2026-11-03 | Confirmed |
| 13 | MITRE ATT&CK, G0027 Threat Group-3390 | [attack.mitre.org/groups/G0027](https://attack.mitre.org/groups/G0027/) | 2026-11-03 | Confirmed |
| 14 | MITRE ATT&CK, G0065 Leviathan | [attack.mitre.org/groups/G0065](https://attack.mitre.org/groups/G0065/) | 2026-11-03 | Confirmed |
| 15 | MITRE ATT&CK, G1048 UNC3886 | [attack.mitre.org/groups/G1048](https://attack.mitre.org/groups/G1048/) | 2026-11-03 | Confirmed |
| 16 | MITRE ATT&CK, G0045 menuPass | [attack.mitre.org/groups/G0045](https://attack.mitre.org/groups/G0045/) | 2026-11-03 | Confirmed |
| 17 | MITRE ATT&CK, G0004 Ke3chang | [attack.mitre.org/groups/G0004](https://attack.mitre.org/groups/G0004/) | 2026-11-03 | Confirmed |
| 18 | US DOJ, five Chinese military hackers charged, 19 May 2014 | [justice.gov/opa/pr/us-charges-five-chinese-military-hackers...](https://www.justice.gov/opa/pr/us-charges-five-chinese-military-hackers-cyber-espionage-against-us-corporations-and-labor) | 2026-11-03 | Confirmed |
| 19 | US DOJ, three Boyusec employees charged, 27 Nov 2017 | [justice.gov/archives/opa/pr/us-charges-three-chinese-hackers...](https://www.justice.gov/archives/opa/pr/us-charges-three-chinese-hackers-who-work-internet-security-firm-hacking-three-corporations) | 2026-11-03 | Confirmed |
| 20 | US DOJ, Jiangsu MSS officers and recruits charged, 30 Oct 2018 | [justice.gov/archives/opa/pr/chinese-intelligence-officers...](https://www.justice.gov/archives/opa/pr/chinese-intelligence-officers-and-their-recruited-hackers-and-insiders-conspired-steal) | 2026-11-03 | Confirmed |
| 21 | US DOJ, two APT10 hackers charged, 20 Dec 2018 | [justice.gov/archives/opa/pr/two-chinese-hackers-associated-ministry-state-security...](https://www.justice.gov/archives/opa/pr/two-chinese-hackers-associated-ministry-state-security-charged-global-computer-intrusion) | 2026-11-03 | Confirmed |
| 22 | UK Government, UK and allies reveal global scale of Chinese cyber campaign, 20 Dec 2018 | [gov.uk/government/news/uk-and-allies-reveal-global-scale-of-chinese-cyber-campaign](https://www.gov.uk/government/news/uk-and-allies-reveal-global-scale-of-chinese-cyber-campaign) | 2026-11-03 | Confirmed |
| 23 | US DOJ, Anthem-era indictment of a China-based hacking group member, 9 May 2019 | [justice.gov/archives/opa/pr/member-sophisticated-china-based-hacking-group...](https://www.justice.gov/archives/opa/pr/member-sophisticated-china-based-hacking-group-indicted-series-computer-intrusions-including) | 2026-11-03 | Confirmed |
| 24 | US DOJ, PLA members charged over Equifax, 10 Feb 2020 | [justice.gov/archives/opa/pr/chinese-military-personnel-charged...](https://www.justice.gov/archives/opa/pr/chinese-military-personnel-charged-computer-fraud-economic-espionage-and-wire-fraud-hacking) | 2026-11-03 | Confirmed |
| 25 | CISA, FBI and CISA warn against Chinese targeting of COVID-19 research, 13 May 2020 | [cisa.gov/news-events/news/fbi-and-cisa-warn-against-chinese-targeting...](https://www.cisa.gov/news-events/news/fbi-and-cisa-warn-against-chinese-targeting-covid-19-research-organizations) | 2026-11-03 | Confirmed |
| 26 | US DOJ, Li Xiaoyu and Dong Jiazhi charged, 21 Jul 2020 | [justice.gov/archives/opa/pr/two-chinese-hackers-working-ministry-state-security...](https://www.justice.gov/archives/opa/pr/two-chinese-hackers-working-ministry-state-security-charged-global-computer-intrusion) | 2026-11-03 | Confirmed |
| 27 | US DOJ, seven defendants including APT41 actors charged, 16 Sep 2020 | [justice.gov/archives/opa/pr/seven-international-cyber-defendants...](https://www.justice.gov/archives/opa/pr/seven-international-cyber-defendants-including-apt41-actors-charged-connection-computer) | 2026-11-03 | Confirmed |
| 28 | US DOJ, four APT40 nationals charged, 19 Jul 2021 | [justice.gov/archives/opa/pr/four-chinese-nationals-working-ministry-state-security...](https://www.justice.gov/archives/opa/pr/four-chinese-nationals-working-ministry-state-security-charged-global-computer-intrusion) | 2026-11-03 | Confirmed |
| 29 | CISA and FBI, AA21-200A, APT40 TTPs, 19 Jul 2021 | [cisa.gov/news-events/cybersecurity-advisories/aa21-200a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a) | 2026-11-03 | Confirmed |
| 30 | UK Government, UK and allies hold Chinese state responsible, 19 Jul 2021 | [gov.uk/government/news/uk-and-allies-hold-chinese-state-responsible...](https://www.gov.uk/government/news/uk-and-allies-hold-chinese-state-responsible-for-a-pervasive-pattern-of-hacking) | 2026-11-03 | Confirmed |
| 31 | NSA, CISA, FBI and partners, AA23-144A, Volt Typhoon, 24 May 2023 | [cisa.gov/news-events/cybersecurity-advisories/aa23-144a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a) | 2026-11-03 | Confirmed |
| 32 | US DOJ, KV Botnet disruption, 31 Jan 2024 | [justice.gov/archives/opa/pr/us-government-disrupts-botnet...](https://www.justice.gov/archives/opa/pr/us-government-disrupts-botnet-peoples-republic-china-used-conceal-hacking-critical) | 2026-11-03 | Confirmed |
| 33 | CISA and partners, AA24-038A, Volt Typhoon pre-positioning, 7 Feb 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa24-038a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) | 2026-11-03 | Confirmed |
| 34 | US DOJ, seven APT31-linked hackers charged, 25 Mar 2024 | [justice.gov/archives/opa/pr/seven-hackers-associated-chinese-government...](https://www.justice.gov/archives/opa/pr/seven-hackers-associated-chinese-government-charged-computer-intrusions-targeting-perceived) | 2026-11-03 | Confirmed |
| 35 | US Treasury, OFAC sanctions on Wuhan Xiaoruizhi and APT31 actors, 25 Mar 2024 | [home.treasury.gov/news/press-releases/jy2205](https://home.treasury.gov/news/press-releases/jy2205) | 2026-11-03 | Confirmed |
| 36 | UK Government, China state-affiliated organisations and individuals held responsible, 25 Mar 2024 | [gov.uk/government/news/uk-holds-china-state-affiliated-organisations...](https://www.gov.uk/government/news/uk-holds-china-state-affiliated-organisations-and-individuals-responsible-for-malicious-cyber-activity) | 2026-11-03 | Confirmed |
| 37 | ASD's ACSC and partners, AA24-190A, APT40, 8 Jul 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa24-190a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-190a) | 2026-11-03 | Confirmed |
| 38 | US DOJ, court-authorized disruption of the Integrity Tech botnet, 18 Sep 2024 | [justice.gov/archives/opa/pr/court-authorized-operation-disrupts-worldwide-botnet...](https://www.justice.gov/archives/opa/pr/court-authorized-operation-disrupts-worldwide-botnet-used-peoples-republic-china-state) | 2026-11-03 | Confirmed |
| 39 | FBI, CNMF and NSA, JCSA-20240918-001, Integrity Tech botnet | [ic3.gov/CSA/2024/240918.pdf](https://www.ic3.gov/CSA/2024/240918.pdf) | 2026-11-03 | Confirmed |
| 40 | FBI and CISA, joint statement on PRC targeting of commercial telecommunications, 13 Nov 2024 | [cisa.gov/news-events/news/joint-statement-fbi-and-cisa...](https://www.cisa.gov/news-events/news/joint-statement-fbi-and-cisa-peoples-republic-china-prc-targeting-commercial-telecommunications) | 2026-11-03 | Confirmed |
| 41 | CISA and partners, Enhanced Visibility and Hardening Guidance for Communications Infrastructure, 4 Dec 2024 | [cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance...](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure) | 2026-11-03 | Confirmed |
| 42 | US DOJ, Guan Tianfeng charged, 10 Dec 2024 | [justice.gov/archives/opa/pr/china-based-hacker-charged...](https://www.justice.gov/archives/opa/pr/china-based-hacker-charged-conspiring-develop-and-deploy-malware-exploited-tens-thousands) | 2026-11-03 | Confirmed |
| 43 | US Treasury, OFAC designates Sichuan Silence and Guan Tianfeng, 10 Dec 2024 | [home.treasury.gov/news/press-releases/jy2742](https://home.treasury.gov/news/press-releases/jy2742) | 2026-11-03 | Confirmed |
| 44 | US Treasury, OFAC designates Integrity Technology Group, 3 Jan 2025 | [home.treasury.gov/news/press-releases/jy2769](https://home.treasury.gov/news/press-releases/jy2769) | 2026-11-03 | Confirmed |
| 45 | Japan National Police Agency, MirrorFace caution, 8 Jan 2025 | [npa.go.jp/bureau/cyber/koho/caution/caution20250108.html](https://www.npa.go.jp/bureau/cyber/koho/caution/caution20250108.html) | 2026-11-03 | Confirmed |
| 46 | US Treasury, OFAC sanctions Yin Kecheng and Sichuan Juxinhe, 17 Jan 2025 | [home.treasury.gov/news/press-releases/jy2792](https://home.treasury.gov/news/press-releases/jy2792) | 2026-11-03 | Confirmed |
| 47 | US DOJ, 12 Chinese contract hackers and law enforcement officers charged, 5 Mar 2025 | [justice.gov/opa/pr/justice-department-charges-12-chinese-contract-hackers...](https://www.justice.gov/opa/pr/justice-department-charges-12-chinese-contract-hackers-and-law-enforcement-officers-global) | 2026-11-03 | Confirmed |
| 48 | FBI, public service announcement PSA250305 | [ic3.gov/PSA/2025/PSA250305](https://www.ic3.gov/PSA/2025/PSA250305) | 2026-11-03 | Confirmed |
| 49 | US Treasury, OFAC designates Zhou Shuai and Shanghai Heiying, 5 Mar 2025 | [home.treasury.gov/news/press-releases/sb0042](https://home.treasury.gov/news/press-releases/sb0042) | 2026-11-03 | Confirmed |
| 50 | Czech Ministry of Foreign Affairs, statement by the Government of the Czech Republic, 28 May 2025 | [mzv.gov.cz/.../statement_by_the_government_of_the_czech.html](https://mzv.gov.cz/jnp/en/issues_and_press/press_releases/statement_by_the_government_of_the_czech.html) | 2026-11-03 | Confirmed |
| 51 | NUKIB, Czech government attributes cyberattacks to China, 28 May 2025 | [nukib.gov.cz/en/infoservis-en/news/2263-...](https://nukib.gov.cz/en/infoservis-en/news/2263-the-czech-government-has-publicly-attributed-cyberattacks-to-china-actor-apt31-linked-to-the-chinese-ministry-of-state-security-has-targeted-the-infrastructure-of-the-czech-ministry-of-foreign-affairs) | 2026-11-03 | Confirmed |
| 52 | US DOJ, arrest of a Chinese state-sponsored contract hacker (Xu Zewei), 8 Jul 2025 | [justice.gov/opa/pr/justice-department-announces-arrest-prolific-chinese...](https://www.justice.gov/opa/pr/justice-department-announces-arrest-prolific-chinese-state-sponsored-contract-hacker) | 2026-11-03 | Confirmed |
| 53 | NSA, CISA, FBI, DC3 and partners, AA25-239A, Salt Typhoon cluster, 27 Aug 2025 | [cisa.gov/news-events/cybersecurity-advisories/aa25-239a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a) | 2026-11-03 | Confirmed |
| 54 | Google, "A new approach to China", 12 Jan 2010 | [googleblog.blogspot.com/2010/01/new-approach-to-china.html](https://googleblog.blogspot.com/2010/01/new-approach-to-china.html) | 2026-11-03 | Confirmed |
| 55 | Mandiant, APT1 report announcement, 19 Feb 2013 | [cloud.google.com/blog/topics/threat-intelligence/mandiant-exposes-apt1...](https://cloud.google.com/blog/topics/threat-intelligence/mandiant-exposes-apt1-chinas-cyber-espionage-units/) | 2026-11-03 | Confirmed |
| 56 | Community Health Systems, Form 8-K, filed 18 Aug 2014 | `https://www.sec.gov/Archives/edgar/data/1108109/000119312514312504/d776541d8k.htm` | 2026-11-03 | Confirmed |
| 57 | House Oversight Committee, OPM data breach majority report, 7 Sep 2016 | [oversight.house.gov/report/opm-data-breach...](https://oversight.house.gov/report/opm-data-breach-government-jeopardized-national-security-generation/) | 2026-11-03 | Confirmed |
| 58 | BAE Systems, APT10 Operation Cloud Hopper, 4 Apr 2017 | [baesystems.com/en-uk/insight/apt10-operation-cloud-hopper](https://www.baesystems.com/en-uk/insight/apt10-operation-cloud-hopper) | 2026-11-03 | Confirmed |
| 59 | Microsoft, HAFNIUM targeting Exchange servers, 2 Mar 2021 | [microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/) | 2026-11-03 | Confirmed |
| 60 | The White House (archived), US joined by allies attributes malicious cyber activity to the PRC, 19 Jul 2021 | [bidenwhitehouse.archives.gov/.../2021/07/19/...](https://bidenwhitehouse.archives.gov/briefing-room/statements-releases/2021/07/19/the-united-states-joined-by-allies-and-partners-attributes-malicious-cyber-activity-and-irresponsible-state-behavior-to-the-peoples-republic-of-china/) | 2026-11-03 | Confirmed |
| 61 | Microsoft, Digital Crimes Unit action against NICKEL, 6 Dec 2021 | [blogs.microsoft.com/on-the-issues/2021/12/06/cyberattacks-nickel-dcu-china](https://blogs.microsoft.com/on-the-issues/2021/12/06/cyberattacks-nickel-dcu-china/) | 2026-11-03 | Confirmed |
| 62 | Microsoft, Volt Typhoon targets US critical infrastructure, 24 May 2023 | [microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon...](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/) | 2026-11-03 | Confirmed |
| 63 | CGTN (PRC state media), report on CVERC's third Volt Typhoon report, 14 Oct 2024 | [news.cgtn.com/news/2024-10-14/...](https://news.cgtn.com/news/2024-10-14/Report-denounces-Volt-Typhoon-as-a-political-farce-staged-by-U-S--1xGxYz1JdVS/share_amp.html) | 2026-11-03 | Reported |
| 64 | Microsoft, analysis of Storm-0558 techniques, 14 Jul 2023 | [microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558...](https://www.microsoft.com/en-us/security/blog/2023/07/14/analysis-of-storm-0558-techniques-for-unauthorized-email-access/) | 2026-11-03 | Confirmed |
| 65 | NCSC, China state-affiliated actors target UK democratic institutions, 25 Mar 2024 | [ncsc.gov.uk/news/china-state-affiliated-actors-target-uk-democratic-institutions-parliamentarians](https://www.ncsc.gov.uk/news/china-state-affiliated-actors-target-uk-democratic-institutions-parliamentarians) | 2026-11-03 | Confirmed |
| 66 | NCSC, advice to counter a China-linked campaign targeting thousands of devices, 18 Sep 2024 | [ncsc.gov.uk/news/ncsc-and-partners-issue-advice...](https://www.ncsc.gov.uk/news/ncsc-and-partners-issue-advice-to-counter-china-linked-campaign-targeting-thousands-of-devices) | 2026-11-03 | Confirmed |
| 67 | Congressional Research Service, IF12798, updated 23 Jan 2025 | [congress.gov/crs_external_products/IF/HTML/IF12798.web.html](https://www.congress.gov/crs_external_products/IF/HTML/IF12798.web.html) | 2026-11-03 | Confirmed |
| 68 | Mandiant, Ivanti Connect Secure VPN zero-day, 8 Jan 2025 | [cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day](https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day) | 2026-11-03 | Confirmed |
| 69 | Microsoft, Silk Typhoon targeting IT supply chain, 5 Mar 2025 | [microsoft.com/en-us/security/blog/2025/03/05/silk-typhoon-targeting-it-supply-chain](https://www.microsoft.com/en-us/security/blog/2025/03/05/silk-typhoon-targeting-it-supply-chain/) | 2026-11-03 | Confirmed |
| 70 | Google Threat Intelligence Group, BRICKSTORM espionage campaign, 24 Sep 2025 | [cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign](https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign) | 2026-11-03 | Confirmed |
| 71 | Mandiant, China-nexus espionage targets Juniper routers, 11 Mar 2025 | [cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers) | 2026-11-03 | Confirmed |
| 72 | Microsoft, disrupting active exploitation of on-premises SharePoint, 22 Jul 2025 | [microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation...](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/) | 2026-11-03 | Confirmed |
| 73 | CISA, NSA and the Cyber Centre warn of BRICKSTORM, 4 Dec 2025 | [cisa.gov/news-events/news/cisa-nsa-and-cyber-centre-warn...](https://www.cisa.gov/news-events/news/cisa-nsa-and-cyber-centre-warn-critical-infrastructure-brickstorm-malware-used-peoples-republic) | 2026-11-03 | Confirmed |
| 74 | NCSC, international cyber agencies' advice on China-linked covert networks, 23 Apr 2026 | [ncsc.gov.uk/news/international-cyber-agencies-fresh-advice...](https://www.ncsc.gov.uk/news/international-cyber-agencies-fresh-advice-defend-against-china-linked-covert-networks) | 2026-11-03 | Confirmed |
| 75 | Google Threat Intelligence Group, disrupting the GRIDTIDE espionage campaign, 25 Feb 2026 | [cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-gridtide-global-espionage-campaign) | 2026-11-03 | Confirmed |
| 76 | NCSC, defending against China-nexus covert networks of compromised devices, 23 Apr 2026 | [ncsc.gov.uk/news/defending-against-china-nexus-covert-networks...](https://www.ncsc.gov.uk/news/defending-against-china-nexus-covert-networks-of-compromised-devices) | 2026-11-03 | Confirmed |
| 77 | CISA, AA26-113A, China-nexus covert networks, 23 Apr 2026 | [cisa.gov/news-events/cybersecurity-advisories/aa26-113a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-113a) | 2026-11-03 | Confirmed |
| 78 | Google Threat Intelligence Group, PRC targets US medical research, 15 Jun 2026 | [cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research](https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research) | 2026-11-03 | Confirmed |
| 79 | NSA, CISA and FBI, AA26-251A, model distillation campaigns, 8 Sep 2026 | [cisa.gov/news-events/cybersecurity-advisories/aa26-251a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a) | 2026-11-03 | Confirmed |
| 80 | CISA and partners, AA26-281A, actors enabled by Integrity Technology Group, 8 Oct 2026 | [cisa.gov/news-events/cybersecurity-advisories/aa26-281a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a) | 2026-11-03 | Confirmed |
| 81 | NCSC, China-linked actors called out for targeting sensitive data, 8 Oct 2026 | [ncsc.gov.uk/news/china-linked-actors-called-out...](https://www.ncsc.gov.uk/news/china-linked-actors-called-out-by-uk-and-international-partners-for-targeting-sensitive-data) | 2026-11-03 | Confirmed |
| 82 | Google Threat Intelligence Group, ARMORY CASTLE exploits BeyondTrust, 15 Oct 2026 | [cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust/) | 2026-11-03 | Confirmed |
| 83 | HHS HC3, threat briefing on Chinese state-sponsored cyber activity, 19 Nov 2020 (AHA-hosted copy) | [aha.org/system/files/media/file/2020/11/hc3-threat-briefing...](https://www.aha.org/system/files/media/file/2020/11/hc3-threat-briefing-tlp-white-chinese-state-sponsored-cyber-activity-november-19-2020.pdf) | 2026-11-03 | Confirmed |
| 84 | FBI and CISA, PSA on PRC targeting of COVID-19 research, May 2020 (AHA-hosted copy) | [aha.org/system/files/media/file/2020/05/Joint_FBI-CISA_PSA...](https://www.aha.org/system/files/media/file/2020/05/Joint_FBI-CISA_PSA_China_Cyber-COVID-19_05082020_FINAL4.pdf) | 2026-11-03 | Confirmed |
| 85 | HHS HC3, China's Five-Year Plans and the HPH, 6 May 2021 (AHA-hosted copy) | [aha.org/system/files/media/file/2021/05/HC3_Threat_Brief...](https://www.aha.org/system/files/media/file/2021/05/HC3_Threat_Brief_TLPWHITE_20210506_China_FYP_and_the_HPH.pdf) | 2026-11-03 | Confirmed |
| 86 | HHS HC3, Threat Profile on China-based threat actors, 16 Aug 2023 (AHA-hosted copy) | [aha.org/system/files/media/file/2023/08/Hc3-tlp-clear-threat-profile...](https://www.aha.org/system/files/media/file/2023/08/Hc3-tlp-clear-threat-profile-china-based-threat-actors-8-16-23.pdf) | 2026-11-03 | Confirmed |
| 87 | US DOJ, APT40 indictment (S.D. Cal., returned 28 May 2021) | [justice.gov/opa/press-release/file/1412916/download](https://www.justice.gov/opa/press-release/file/1412916/download) | 2026-11-03 | Confirmed |
| 88 | FBI, APT 40 cyber espionage activities wanted notice | [fbi.gov/wanted/cyber/apt-40-cyber-espionage-activities](https://www.fbi.gov/wanted/cyber/apt-40-cyber-espionage-activities) | 2026-11-03 | Confirmed |
| 89 | FBI, Fujie Wang wanted notice | [fbi.gov/wanted/cyber/fujie-wang](https://www.fbi.gov/wanted/cyber/fujie-wang) | 2026-11-03 | Confirmed |
| 90 | FBI, APT 10 Group wanted notice | [fbi.gov/wanted/cyber/apt-10-group](https://www.fbi.gov/wanted/cyber/apt-10-group) | 2026-11-03 | Confirmed |
| 91 | The Record, Chinese national arrested in Italy over HAFNIUM and COVID research hacking | [therecord.media/chinese-national-arrested-italy-hafnium-covid](https://therecord.media/chinese-national-arrested-italy-hafnium-covid) | 2026-11-03 | Reported |
| 92 | The Record, Chinese hacker extradited from Italy | [therecord.media/chinese-hacker-italy-extradited](https://therecord.media/chinese-hacker-italy-extradited) | 2026-11-03 | Reported |
| 93 | NSA, CISA and FBI, AA21-200B, Chinese state-sponsored cyber operations (archived) | [cisa.gov/news-events/cybersecurity-advisories/aa21-200b](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200b) | 2026-11-03 | Confirmed |
| 94 | US DOJ, domain seizure affidavit (QScan, QTRouter and QTFY actors), Aug 2026 | [justice.gov/d9/2026-08/domain_seizures_affidavit_0.pdf](https://www.justice.gov/d9/2026-08/domain_seizures_affidavit_0.pdf) | 2026-11-03 | Confirmed |
| 95 | CNN via CP24, US says Chinese hackers hit hospitals, NASA, Senate and more, 26 Aug 2026 | [cp24.com/news/world/2026/08/26/...](https://cp24.com/news/world/2026/08/26/us-says-chinese-hackers-hit-hospitals-nasa-senate-and-more) | 2026-11-03 | Reported |
| 96 | FBI, Aquatic Panda cyber threat actors wanted notice | [fbi.gov/wanted/cyber/aquatic-panda-cyber-threat-actors](https://www.fbi.gov/wanted/cyber/aquatic-panda-cyber-threat-actors) | 2026-11-03 | Confirmed |
| 97 | NSA, CISA and FBI, AA22-158A, PRC exploitation of telecoms and network devices, 7 Jun 2022 | [cisa.gov/news-events/cybersecurity-advisories/aa22-158a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-158a) | 2026-11-03 | Confirmed |
| 98 | CISA and partners, Identifying and Mitigating Living Off the Land Techniques, 7 Feb 2024 | [cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques](https://www.cisa.gov/resources-tools/resources/identifying-and-mitigating-living-land-techniques) | 2026-11-03 | Confirmed |
| 99 | NSA, CISA and FBI, AA22-279A, top CVEs exploited by PRC actors, 6 Oct 2022 | [cisa.gov/news-events/cybersecurity-advisories/aa22-279a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-279a) | 2026-11-03 | Confirmed |
| 100 | CISA, Known Exploited Vulnerabilities catalog, JSON feed (version 2026.11.03) | [cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-03 | Confirmed |
| 101 | TeamStarWolf library, ATT&CK v20.0 technique data with tactics and CAPEC mappings (`technique_profiles.jsonl`) | [github.com/TeamStarWolf/TeamStarWolf/.../data/attack/technique_profiles.jsonl](https://github.com/TeamStarWolf/TeamStarWolf/blob/e85b5594301fe061043fe92040135252c97b695d/data/attack/technique_profiles.jsonl) | 2026-11-03 | Confirmed |

## Related references

- [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md)
- Other case studies: [The SharePoint ToolShell Mass Exploitation](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [Log4Shell (CVE-2021-44228)](/case-studies/LOG4SHELL.md); companion studies in review, linked once they are published: APT41: The Public Record, Operation Exchange Marauder, Change Healthcare 2024, Sandworm Operations, SolarWinds SUNBURST, Stuxnet
- Groups: [G0006 APT1](/mitre/groups/G0006.md), [G0045 menuPass](/mitre/groups/G0045.md), [G0065 Leviathan](/mitre/groups/G0065.md), [G0128 ZIRCONIUM](/mitre/groups/G0128.md), [G0027 Threat Group-3390](/mitre/groups/G0027.md), [G0125 HAFNIUM](/mitre/groups/G0125.md), [G0096 APT41](/mitre/groups/G0096.md), [G1017 Volt Typhoon](/mitre/groups/G1017.md), [G1045 Salt Typhoon](/mitre/groups/G1045.md), [G1048 UNC3886](/mitre/groups/G1048.md), [G0004 Ke3chang](/mitre/groups/G0004.md), [G0022 APT3](/mitre/groups/G0022.md), [G0009 Deep Panda](/mitre/groups/G0009.md), [G0143 Aquatic Panda](/mitre/groups/G0143.md), [G1054 MirrorFace](/mitre/groups/G1054.md), [G0129 Mustang Panda](/mitre/groups/G0129.md), [G0114 Chimera](/mitre/groups/G0114.md), [G1023 APT5](/mitre/groups/G1023.md), [G0011 PittyTiger](/mitre/groups/G0011.md), [G0026 APT18](/mitre/groups/G0026.md)
- Campaigns: [C0017](/mitre/campaigns/C0017.md), [C0040](/mitre/campaigns/C0040.md), [C0035](/mitre/campaigns/C0035.md), [C0039](/mitre/campaigns/C0039.md), [C0049](/mitre/campaigns/C0049.md), [C0047](/mitre/campaigns/C0047.md), [C0052](/mitre/campaigns/C0052.md), [C0056](/mitre/campaigns/C0056.md), [C0058](/mitre/campaigns/C0058.md), [C0060](/mitre/campaigns/C0060.md), [C0029](/mitre/campaigns/C0029.md), [C0012](/mitre/campaigns/C0012.md)
- Software: [S0013 PlugX](/mitre/software/S0013.md), [S0596 ShadowPad](/mitre/software/S0596.md), [S0154 Cobalt Strike](/mitre/software/S0154.md), [S0002 Mimikatz](/mitre/software/S0002.md), [S0020 China Chopper](/mitre/software/S0020.md), [S0032 gh0st RAT](/mitre/software/S0032.md), [S1206 JumbledPath](/mitre/software/S1206.md), [S1144 FRP](/mitre/software/S1144.md), [S1154 VersaMem](/mitre/software/S1154.md), [S9015 BRICKSTORM](/mitre/software/S9015.md)
- Techniques: [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1584.008 Network Devices](/mitre/techniques/T1584-008.md), [T1505.003 Web Shell](/mitre/techniques/T1505-003.md), [T1003.003 NTDS](/mitre/techniques/T1003-003.md), [T1090.003 Multi-hop Proxy](/mitre/techniques/T1090-003.md), [T1059.008 Network Device CLI](/mitre/techniques/T1059-008.md), [T1602.002 Network Device Configuration Dump](/mitre/techniques/T1602-002.md), [T1685.005 Clear Windows Event Logs](/mitre/techniques/T1685-005.md)
- D3FEND: [Software Update](/mitre/d3fend/software-update.md), [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md), [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [threat-actors-china.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/threat-actors-china.json)
