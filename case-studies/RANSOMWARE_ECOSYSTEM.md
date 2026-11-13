# The Ransomware Ecosystem: The Public Record, 2019 to 2026

*A TeamStarWolf case study. Published 11 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Ransomware Defense](/RANSOMWARE_DEFENSE_REFERENCE.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [Notable Incidents](/NOTABLE_INCIDENTS.md), [CVE Reference](/CVE_REFERENCE.md), [Edge Device Security](/EDGE_DEVICE_SECURITY_REFERENCE.md), [The Change Healthcare Attack of 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [The Cl0p MOVEit Breach](/case-studies/CL0P_FILE_TRANSFER_2023.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Security leaders, incident responders, threat intelligence analysts and vulnerability management teams

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 91 min (20,837 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need the dated public record of the ransomware business from 2019 to 2026, you are deciding which remote-access, edge and backup controls to fund first, or you want the brands, advisories and ATT&CK objects in one place

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 2: the operational record](#part-2-the-operational-record), [Part 9: the defender view](#part-9-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md), [Respond to a Ransomware Incident](/guides/RESPOND_TO_RANSOMWARE.md), [Edge Device Security](/EDGE_DEVICE_SECURITY_REFERENCE.md), [The Change Healthcare Attack of 2024](/case-studies/CHANGE_HEALTHCARE_2024.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

For the people who run hospital networks, school districts, water plants, car dealerships and city halls, ransomware stopped being a virus and became an industry between 2019 and 2026. In October 2020 three US agencies warned hospitals that loader malware was handing their networks to Ryuk and Conti operators (Confirmed [1]). By 2021, by the account of five agencies in three countries, ransomware was a professional market: developers rented their encryptors to affiliates, and separate services negotiated payments, helped victims pay and settled disputes between criminals (Confirmed [5]). Colonial Pipeline halted its pipeline operations on 7 May 2021 (Confirmed [62][71]). Ireland's national health service found 80 percent of its environment encrypted a week later (Confirmed [83]). In 2025 the Jaguar Land Rover incident, which the UK Cyber Monitoring Centre says appears to be the most economically damaging cyber event to hit the UK, cost an estimated £1.9 billion; the CMC calls it a malicious cyber incident, not ransomware (Confirmed [102]).

The record now shows the business from several sides at once. Government advisories describe how each brand gets in and what it does once inside (Confirmed [11][15][23][24][27][29][30]). Sanctions, indictments and police operations name the people behind LockBit, Conti, Trickbot, Hive and Scattered Spider (Confirmed [45][46][47][49][56][60]). Regulators and payment data show what the business earns. FinCEN counted more than $2.1 billion in reported payments for 2022 to 2024 (Confirmed [96]), and Chainalysis put on-chain payments above $1 billion in 2023, its record year (Reported [104]). Victims' own filings show what it costs them: an estimated $100 million hit at MGM Resorts (Confirmed [77]), auto dealers working on paper after CDK Global's systems went down (Confirmed [73][74]), and airports falling back to manual passenger processing (Confirmed [76]).

Three findings stand out. First, the way in is usually ordinary. VPNs and remote-access portals without multifactor authentication, unpatched edge appliances and talked-into-it help desks recur across the advisories and testimony from 2021 to 2026 (Confirmed [17][23][30][70][71]; Inferred for the pattern). Second, law enforcement now routinely reaches inside these groups. The FBI ran inside Hive from late July 2022 until the takedown in January 2023 (Confirmed [64]); the UK National Crime Agency took over LockBit's own systems and identified 194 affiliates (Confirmed [57][58]); and the two men the NCA calls leading members of Scattered Spider were sentenced in July 2026 (Confirmed [60]). Third, fewer victims pay. Coveware's share of clients paying fell to record lows through 2025 and 2026 (Reported [110][113]), and Chainalysis estimates 2025 payments a little below 2024 even as claimed victims rose about 50 percent (Reported [106]).

This study is the library's dated record of the ecosystem as a whole. Single incidents that have their own study are summarized in a paragraph and linked: [the Change Healthcare attack](/case-studies/CHANGE_HEALTHCARE_2024.md) and [the Cl0p MOVEit campaign](/case-studies/CL0P_FILE_TRANSFER_2023.md). The 2019, 2020 and 2021 waves are told year by year in [The Year 2019 in Intrusions](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions](/case-studies/CHRONICLE_2020.md) and [The Year 2021 in Intrusions](/case-studies/CHRONICLE_2021.md).

### Key facts at a glance

| Item | Detail | Grade |
|---|---|---|
| Period | May 2019 (Maze discovered) to 10 November 2026 (CISA KEV catalog version 2026.11.10) | Reported [158]; Confirmed [32] |
| Business model | Ransomware-as-a-service with affiliates, initial access brokers, and outsourced negotiation, payment and dispute services | Confirmed [5][27][29] |
| Most deployed variant, 2022 | LockBit, per seven national agencies; about 1,700 US attacks since 2020 and about $91 million in US ransoms paid | Confirmed [15] |
| Costliest strain documented by 2022 | Conti: over 1,000 victims and payouts over $150 million as of January 2022 (FBI) | Confirmed [54] |
| Largest takedown | Operation Cronos, 20 Feb 2024: the NCA took control of LockBit's admin environment and leak site, obtained its source code and more than 1,000 decryption keys | Confirmed [57][58] |
| Named leaders | Dmitry Khoroshev (LockBitSupp), sanctioned 7 May 2024; Mikhail Matveev (Hive, LockBit, Babuk), sanctioned 16 May 2023; 18 Trickbot members sanctioned in 2023 (7 in February, 11 in September) | Confirmed [49][47][45][46] |
| Payments | FinCEN: about $1.1 billion in 2023 and about $734 million in 2024 from US Bank Secrecy Act reports | Confirmed [96] |
| Payment rate | Coveware: a new record low in Q2 2026, ticking up slightly in Q3 2026 while staying near historic lows | Reported [113][114] |
| Ransomware-flagged KEV entries | 361 of 1,779 entries in KEV catalog version 2026.11.10 carry "Known" ransomware campaign use; Microsoft 117, Fortinet 14, SonicWall 13, Oracle 13, Ivanti 12 | Confirmed [32]; Demonstrated (counted from the feed) |
| Most damaging UK cyber event (CMC: appears to be) | Jaguar Land Rover, late August 2025: Category 3, £1.9 billion (range £1.6 to £2.1 billion), over 5,000 UK organisations affected; the Cyber Monitoring Centre does not call it ransomware | Confirmed [102] |
| Newest advisories | Gunra (AA26-222A, 10 Aug 2026) and SafePay (AA26-293A, 20 Oct 2026, at least 600 victims) | Confirmed [29][30] |
| Mandatory reporting | US CIRCIA final rule sent for OIRA review 1 Oct 2026; reporting not yet required. UK targeted payment ban not yet legislated | Confirmed [37][34][93] |
| ATT&CK objects | Groups G0102 Wizard Spider, G0092 TA505, G1015 Scattered Spider, G1024 Akira, G1040 Play, G1046 Storm-1811, G1050 Water Galura, G1051 Medusa Group and others; software S0575 Conti, S1202 LockBit 3.0, S1068 BlackCat, S1070 Black Basta, S1073 Royal, S1212 RansomHub, S1242 Qilin and others. No objects for BlackSuit, DragonForce, Rhysida, Interlock, Phobos, Ghost, Gunra or SafePay | Confirmed [145] to [157][161] |
| This study's MITRE binding | 52 Enterprise technique rows, 3 ATT&CK for ICS rows, 63 group, software and campaign objects, CWE records for nine CVEs with CAPEC pairs where the library's data supports them, and two Navigator layers (Part 10) | Confirmed [161] |

### Key findings

- **Ransomware is a supply chain of specialists.** Developers rent the encryptor; affiliates break in; brokers sell access; negotiators and payment helpers take a cut (Confirmed [5]). Medusa pays brokers $100 to $1 million for access (Confirmed [27]), and Gunra recruits penetration testers for a share of the ransom (Confirmed [29]). Conti differed: the FBI and CISA said it likely paid its deployers a wage (Confirmed [4]).
- **Brands die; people move.** Conti's members split into Zeon, Black Basta and Quantum, which became Royal and then BlackSuit (Reported [118]). RansomHub drew affiliates from LockBit and ALPHV (Confirmed [25]). Gunra appears to be built on Conti's leaked 2022 source code (Confirmed [29]). A brand name is therefore weak evidence of who is behind an attack (Inferred from [11][25][118]).
- **The front door is remote access.** Akira entered mainly through VPNs without MFA (Confirmed [23]). Colonial Pipeline's attacker used a legacy VPN profile that was not meant to be in use (Confirmed [71]). Change Healthcare's attacker logged in to a Citrix portal without MFA (Confirmed [70]). Verizon counted edge devices and VPNs as 22 percent of exploitation targets in its 2025 report, up from 3 percent (Reported [117]).
- **Extortion no longer needs encryption.** Maze began posting stolen data in 2019 (Reported [158]). CL0P's file-transfer campaigns since 2021 relied mostly on theft rather than encryption (Confirmed [14]). BianLian moved to exfiltration-only extortion by January 2024 (Confirmed [13]). Backups do not answer this kind of attack (Confirmed [14]; Inferred for the general point).
- **Law enforcement learned to work from the inside.** The FBI penetrated Hive from late July 2022 and handed out decryption keys that averted about $130 million in ransoms (Confirmed [64]). Cronos showed LockBit kept victims' data even after payment (Confirmed [56][57]). After Cronos, active LockBit affiliates fell to 69 and UK monthly LockBit attacks fell 73 percent (Confirmed [56]).
- **Payment figures move.** Chainalysis first put 2024 payments at $813.55 million and later revised them to $892 million (Reported [105][106]). FinCEN and Chainalysis measure different things and disagree for both 2023 and 2024 (Confirmed [96]; Reported [105]; Inferred for the comparison). Cite each figure with its report date.
- **Healthcare is the sector the record keeps returning to.** HHS's own analysts tracked 730 attacks on the health sector worldwide in six months to mid-March 2024, nearly half of them ransomware (Confirmed [86]). After the December 2023 disruption, ALPHV's administrator told affiliates to target hospitals (Confirmed [20]).

### Top recommendations

1. **Put phishing-resistant MFA on every VPN, remote-desktop gateway and remote-management portal, and find the ones nobody owns.** The joint guide asks for MFA on all VPN connections and phishing-resistant MFA for all services (Confirmed [31]); Akira and Change came through remote access without it, and Colonial's attacker used a legacy VPN profile that was not meant to be in use (Confirmed [23][70][71]).
2. **Patch internet-facing appliances on the KEV clock.** CISA advised patching internet-facing KEV entries within 24 to 48 hours after Citrix Bleed (Confirmed [18]). Treat the KEV ransomware flag as a priority signal, because some ransomware use of edge flaws appears only there (Confirmed [32]; Inferred from [22][32]).
3. **Keep offline, encrypted, tested backups out of the production identity plane.** In 94 percent of attacks in Sophos's 2024 survey, criminals tried to compromise backups (Reported [115]). The joint guide and the BlackSuit advisory both call for offline, encrypted backups (Confirmed [31][11]).
4. **Harden the help desk.** Require identity checks that a caller cannot talk past before resetting a password or moving MFA (Confirmed [17] for the tradecraft; Inferred for the control).
5. **Watch for the tools, not just the malware.** Remote-management software and RClone to cloud storage recur across the advisories (Confirmed [24][27][30]; Inferred for the pattern). Allowlist remote-access tools and alert on new ones, as the Scattered Spider advisory recommends (Confirmed [17]).
6. **Plan for theft without encryption.** Decide in advance how you will handle a data-only extortion demand, because backups do not answer it and paying does not guarantee deletion (Confirmed [14][56][78]; Inferred for the plan).

## Scope and method

This study covers the ransomware ecosystem from the discovery of Maze, an early leak-site extortion brand, in May 2019 to the KEV catalog of 10 November 2026: how the business is organized, the dated record of attacks, advisories and law-enforcement actions, the brands and the ATT&CK objects that track them, the tradecraft at the level the advisories describe it, the exploited vulnerabilities, the sectors hit, the government and policy record, the money, and the defender view. It draws on joint #StopRansomware and other CISA advisories, the KEV catalog and NVD records, Treasury, State Department, NCA, HSI, Europol and Eurojust releases, Justice Department releases read through Wayback Machine snapshots, congressional testimony, SEC filings, regulators' and auditors' reports (FinCEN, IC3, GAO, NAIC, HHS, EPA), the UK Cyber Monitoring Centre, industry data reports, and press reporting where no primary could be opened. Every source was opened on 11 November 2026. MITRE ids were checked against the live ATT&CK site or the library's data files on that date.

Two studies are the home for events this one only summarizes: [the Change Healthcare attack](/case-studies/CHANGE_HEALTHCARE_2024.md) and [the Cl0p file-transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md). The study describes tradecraft at the level the advisories use: technique names and ids. It reproduces no commands, payloads, exploit details or ransom notes.

| Grade | Meaning |
|---|---|
| Confirmed | A primary source was opened: a government advisory, sanction, indictment or court record, a regulator's or auditor's report, a company's own filing, testimony or statement, a CVE or KEV record, a vendor's security advisory, or the MITRE record itself |
| Reported | Known only from a secondary source, such as press coverage, or from a single company's account that no primary corroborates. Industry data reports (Chainalysis, Coveware, Sophos, Verizon, Microsoft) are graded Reported: each is one company's measurement of its own dataset |
| Demonstrated | Reproduced by a count or query anyone can rerun against a public dataset (the KEV feed, an EDGAR full-text search) |
| Inferred | This study's own reasoning from the cited facts, labelled where it appears |

Four rules matter for this topic. First, attribution words are carried exactly as each source used them: "claimed", "believes", "associated with" and "attributed to" are different claims. Second, victim counts and dollar figures are reported as the source states them, with the date, because every series in this field is revised. Third, a leak-site claim is the actor's claim, not evidence of theft (Inferred; the Ghost advisory records leak threats from actors who seldom steal much, Confirmed [26]). Fourth, when ATT&CK revoked an id that an advisory printed, the study shows the live successor and names the printed id.

## Part 1: how the business works

### Ransomware-as-a-service

The advisories describe the same division of labor from 2021 onward. In February 2022 the FBI, CISA and NSA, with the UK NCSC and the Australian Cyber Security Centre, said the market had become increasingly professional during 2021. Ransomware-as-a-service had spread, and independent services had appeared to negotiate payments, help victims make them and arbitrate disputes between criminals (Confirmed [5]). The same advisory recorded "big game" targeting in the first half of 2021 and attacks timed to holidays and weekends (Confirmed [5]).

The roles recur in later advisories:

| Role | What the record says | Source | Grade |
|---|---|---|---|
| Developer and operator | Builds the encryptor, runs the panel and leak site. Water Galura (G1050) handles payloads, negotiations and leak publication for Qilin affiliates recruited on Russian-language forums | [156] | Confirmed |
| Affiliate | Breaks in and deploys. LockBit's affiliate base was large and unconnected, so its tactics vary widely (AA23-165A) | [15] | Confirmed |
| Initial access broker | Sells a way in. Medusa recruits brokers on forums and pays $100 to $1 million, sometimes for exclusivity; most brokers work for several variants (AA25-071A) | [27] | Confirmed |
| Recruited specialist | Gunra recruits penetration testers as access brokers for a share of the ransom (AA26-222A) | [29] | Confirmed |
| Salaried deployer | Conti likely paid deployers a wage rather than an affiliate percentage (AA21-265A) | [4] | Confirmed |
| Negotiator and payment helper | Independent services negotiate, help pay and arbitrate (AA22-040A). In 2025 a former negotiator and a former incident-response manager were charged with deploying ALPHV, and in October 2026 the FBI arrested a negotiation-firm executive on extortion charges | [5][119][123] | Confirmed for the services; Reported for the charges |
| Infrastructure provider | Bulletproof hosters: Zservers leased infrastructure to LockBit affiliates (sanctioned 11 Feb 2025); Aeza Group hosted BianLian and RedLine panels (sanctioned 1 Jul 2025) | [50][51] | Confirmed |

Gunra's January 2026 program shows how packaged the model has become: a panel, a builder, cross-platform lockers and documentation, advertised on dark-web forums (Confirmed [29]). The NCA's view from inside LockBit shows how uneven the economics are. Of 194 affiliates identified up to February 2024, 148 built attacks, 119 negotiated with victims, and up to 114 never received a ransom (Confirmed [56]).

### Extortion, from one lever to several

Encryption was the original lever. Maze, discovered in May 2019, stole data before encrypting and posted it online to pressure victims, by ATT&CK's account (Reported [158]). By 2021 the agencies were describing triple extortion: encryption, data theft, and threats to disrupt the victim's internet access or tell its partners and suppliers (Confirmed [5]). ATT&CK now covers ransom demands backed by a leak threat, and the leak sites themselves, under T1657 Financial Theft (Confirmed [159]).

The leak site became the shop window. Black Basta gave victims 10 to 12 days before posting their data to its "Basta News" site (Confirmed [24]). RansomHub's affiliates set deadlines of 3 to 90 days (Confirmed [25]). Medusa's leak site runs countdown timers, and a victim can pay $10,000 to add a day (Confirmed [27]). Gunra's Tor site also sells datasets (Confirmed [29]). Black Basta's notes carry a code and an onion contact address rather than a demand, leaving the price to the negotiation (Confirmed [24]).

Some operations dropped encryption entirely. CL0P's campaigns since 2021 relied mostly on data exfiltration (Confirmed [14]). BianLian moved mainly to exfiltration-based extortion around January 2023, by the FBI's account, and exclusively around January 2024, by the Australian Signals Directorate's (Confirmed [13]). Some ALPHV affiliates extorted without encrypting (Confirmed [20]), and Scattered Spider often exfiltrates and extorts without ransomware (Confirmed [17]).

### Where the actors are

Treasury, citing FinCEN analysis, said 75 percent of ransomware-related incidents reported from July to December 2021 were linked to Russia, its proxies or persons acting on its behalf (Confirmed [47]). For the Russia-based groups in the library's record, see [Russia-Attributed Threat Actors](/case-studies/THREAT_ACTORS_RUSSIA.md). The record also shows ransomware from elsewhere: Ghost (Cring) actors are located in China (Confirmed [26]), North Korean state-sponsored actors used Maui ransomware against health-sector organizations from May 2021 (Confirmed [6]; their wider record is in [North Korea-Attributed Threat Actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md)), and the Scattered Spider members in this record were charged in the UK and sentenced by a British court (Confirmed [59][60]), with four people aged 17 to 20 arrested in the UK over the 2025 retail attacks (Reported [131]). For the Chinese state actors in the library's record, see [China-Attributed Threat Actors](/case-studies/THREAT_ACTORS_CHINA.md).

### Brands and the ATT&CK objects that track them

ATT&CK models most ransomware brands as software, not groups; this study reads that as reflecting brands used by many affiliates (Inferred). Only a few operators have a group object (Confirmed [145] to [157][161]).

| Brand (aliases in the record) | Active, per the record | ATT&CK group | ATT&CK software | Main advisory | Source |
|---|---|---|---|---|---|
| Ryuk | 2020 in the record | [Wizard Spider, G0102](/mitre/groups/G0102.md) | [Ryuk, S0446](/mitre/software/S0446.md) | AA20-302A | [1][145] |
| Conti | 2021 to 2022 in the record | [Wizard Spider, G0102](/mitre/groups/G0102.md) | [Conti, S0575](/mitre/software/S0575.md) | AA21-265A | [4][145] |
| REvil (Sodinokibi) | 2021 | [GOLD SOUTHFIELD, G0115](/mitre/groups/G0115.md) | [REvil, S0496](/mitre/software/S0496.md) | (none opened) | [63][157][161] |
| Maze | from May 2019 | none | [Maze, S0449](/mitre/software/S0449.md) | (none opened) | [158] |
| LockBit (LockBit 2.0, LockBit 3.0, LockBit Black) | from January 2020 | none | [LockBit 2.0, S1199](/mitre/software/S1199.md); [LockBit 3.0, S1202](/mitre/software/S1202.md) | AA23-075A, AA23-165A, AA23-325A | [12][15][18][148] |
| ALPHV (BlackCat, Noberus) | to March 2024 | none | [BlackCat, S1068](/mitre/software/S1068.md) | AA23-353A | [20][149] |
| CL0P | from 2020 | [TA505, G0092](/mitre/groups/G0092.md) | [Clop, S0611](/mitre/software/S0611.md) | AA23-158A | [14][150] |
| Hive | June 2021 to January 2023 | none | none | AA22-321A | [9][161] |
| Royal, then BlackSuit | Royal about September 2022 to June 2023; BlackSuit to the August 2025 takedown | none | [Royal, S1073](/mitre/software/S1073.md); no BlackSuit object | AA23-061A | [11][147] |
| Black Basta | from April 2022 | [Storm-1811, G1046](/mitre/groups/G1046.md) (linked to deployment) | [Black Basta, S1070](/mitre/software/S1070.md) | AA24-131A | [24][146] |
| Akira (Storm-1567, Howling Scorpius, Punk Spider, Gold Sahara) | advisory of April 2024, updated November 2025 | [Akira, G1024](/mitre/groups/G1024.md) | [Akira, S1129](/mitre/software/S1129.md); [Akira _v2, S1194](/mitre/software/S1194.md) | AA24-109A | [23][151] |
| Play (Playcrypt) | from June 2022 | [Play, G1040](/mitre/groups/G1040.md) | [Playcrypt, S1162](/mitre/software/S1162.md) | AA23-352A | [19][153] |
| RansomHub (formerly Cyclops and Knight) | from February 2024 | none | [RansomHub, S1212](/mitre/software/S1212.md) | AA24-242A | [25][152] |
| Medusa | from June 2021 | [Medusa Group, G1051](/mitre/groups/G1051.md) | [Medusa Ransomware, S1244](/mitre/software/S1244.md) (not S1220, an unrelated Linux rootkit) | AA25-071A | [27][154] |
| Scattered Spider (Roasted 0ktapus, Octo Tempest, Storm-0875, UNC3944) | advisory of November 2023; DragonForce deployments by 2025 | [Scattered Spider, G1015](/mitre/groups/G1015.md) | no DragonForce object | AA23-320A | [17][155] |
| Qilin (Agenda) | 2024 to 2026 | [Water Galura, G1050](/mitre/groups/G1050.md) | [Qilin, S1242](/mitre/software/S1242.md) | none listed | [156] |
| INC | 2026 (PAN-OS exploitation) | [INC Ransom, G1032](/mitre/groups/G1032.md) | [INC Ransomware, S1139](/mitre/software/S1139.md) | none opened | [157][134] |
| AvosLocker | on CISA's list | none | [AvosLocker, S1053](/mitre/software/S1053.md); campaign [C0018](/mitre/campaigns/C0018.md) | listed by CISA | [7][161] |
| Rhysida | from May 2023 | none | none | AA23-319A | [16] |
| Phobos | from May 2019 | none | none | AA24-060A | [21] |
| Ghost (Cring, Crypt3r, Phantom, Strike, Hello, Wickrme, HsHarada, Rapture) | from early 2021 | none | none | AA25-050A | [26] |
| Interlock | from late September 2024 | none | none | AA25-203A | [28] |
| Gunra | from April 2025 | none | none | AA26-222A | [29] |
| SafePay | from August 2024 | none | none | AA26-293A | [30] |

ATT&CK v20 also has objects for BlackByte ([G1043](/mitre/groups/G1043.md)), Storm-0501 ([G1053](/mitre/groups/G1053.md)), Cinnamon Tempest ([G1021](/mitre/groups/G1021.md)) and Embargo ([S1247](/mitre/software/S1247.md)) (Confirmed [157]). It has none for DragonForce, BlackSuit, Rhysida, Interlock, Phobos or 8Base, Ghost or Cring, Gunra or SafePay (Confirmed [157][161]), so those brands are described in this study but cannot be bound by id.

## Part 2: the operational record

One row per dated event, advisory, action or report. Incidents with their own study carry a link.

| Date | Event | Source | Grade |
|---|---|---|---|
| May 2019 | Maze discovered; ATT&CK says its operators steal data before encrypting and post it online (S0449) | [158] | Reported |
| May 2019 onward | Phobos incidents against state, local, tribal and territorial governments reported to MS-ISAC | [21] | Confirmed |
| 2019 | An Alabama hospital ransomware attack that may have contributed to a baby's death, as HHS later cited it | [88] | Reported |
| May 2019 | Fortinet fixes the FortiOS SSL-VPN path traversal CVE-2018-13379 | [42] | Confirmed |
| Jan 2020 | LockBit begins operating as an affiliate-based RaaS | [12] | Confirmed |
| Sep 2020 | A New Jersey water utility hit by a potential Makop variant | [3] | Confirmed |
| 27 Sep 2020 | Universal Health Services suspends user access to its US IT applications after an IT security incident; about $67 million pre-tax impact for 2020. The filing does not name ransomware. The year's record is in [The Year 2020 in Intrusions](/case-studies/CHRONICLE_2020.md) | [80] | Confirmed |
| 28 Oct 2020 | CISA, FBI and HHS (AA20-302A) warn that TrickBot and BazarLoader against hospitals often lead to Ryuk and Conti | [1] | Confirmed |
| 10 Dec 2020 | K-12 schools are 57 percent of ransomware incidents reported to MS-ISAC in August and September, up from 28 percent; advisory AA20-345A follows | [2] | Confirmed |
| 2020 to 2021 | CL0P mass-exploits Accellion FTA, the first of its file-transfer campaigns | [14] | Confirmed |
| Early 2021 | Ghost (Cring) actors located in China begin exploiting outdated internet-facing software, eventually in more than 70 countries | [26] | Confirmed |
| Mar 2021 | A Nevada water system loses SCADA and backup systems to an unknown variant | [3] | Confirmed |
| 16 Mar to 14 May 2021 | Ireland's Health Service Executive: a phishing email with a malicious spreadsheet, access on 18 March, about eight weeks inside, Conti detonated on 14 May; 80 percent of the environment encrypted | [83] | Confirmed |
| 7 May 2021 | Colonial Pipeline: a ransom note found just before 5 a.m. EDT; operations halted; about 75 bitcoin paid | [62][71][33] | Confirmed |
| From May 2021 | North Korean state-sponsored actors use Maui ransomware against health-sector organizations | [6] | Confirmed |
| Jun 2021 | Medusa and Hive both first identified | [27][9] | Confirmed |
| 7 Jun 2021 | DOJ seizes 63.7 bitcoins, about $2.3 million, traced to the Colonial payment | [62] | Confirmed |
| Jul 2021 | A Maine wastewater plant moves to manual operation after ZuCaNo ransomware reaches a SCADA computer through remote access | [3] | Confirmed |
| 2 Jul 2021 | Kaseya VSA attack, later charged as a Sodinokibi/REvil attack; NVD says CVE-2021-30116 was exploited in the wild that month; about 50 of Kaseya's customers and 800 to 1,500 downstream businesses compromised, by Kaseya's count | [44][38][63] | Confirmed |
| Aug 2021 | A California water system loses three SCADA servers to Ghost ransomware | [3] | Confirmed |
| 8 Sep 2021 | Fortinet: an actor discloses SSL-VPN access data for 87,000 FortiGate devices, harvested from systems unpatched against CVE-2018-13379 | [42] | Confirmed |
| 21 Sep 2021 | OFAC updates its advisory on the sanctions risk of paying ransoms and designates the SUEX exchange | [52][53] | Confirmed |
| 22 Sep 2021 | CISA and FBI Conti alert: more than 400 attacks, later updated to more than 1,000 | [4] | Confirmed |
| 14 Oct 2021 | AA21-287A on ransomware at water and wastewater systems | [3] | Confirmed |
| 3 Nov 2021 | KEV adds CVE-2019-19781 (now flagged for known ransomware use) and CVE-2021-30116 | [32][38] | Confirmed |
| 8 Nov 2021 | DOJ charges Yaroslav Vasinskyi over the Kaseya attack and seizes $6.1 million traceable to Yevgeniy Polyanin | [63] | Confirmed |
| Jul to Dec 2021 | 75 percent of reported ransomware incidents linked to Russia, per FinCEN analysis cited by Treasury | [47] | Confirmed |
| 2021 | North Carolina bars state agencies and local governments from paying ransoms (G.S. 143-800) | [91] | Confirmed |
| 9 to 10 Feb 2022 | Five-agency advisory AA22-040A describes the professional RaaS market of 2021 | [5] | Confirmed |
| Feb 2022 | After Conti backs Russia's invasion of Ukraine, about two years of its internal chat logs leak | [124] | Reported |
| Mar 2022 | CIRCIA enacted | [36] | Confirmed |
| Apr 2022 | Conti attacks the Government of Costa Rica; Black Basta first identified | [54][24] | Confirmed |
| 6 May 2022 | State Department offers up to $10 million for Conti leaders and up to $5 million for any participant | [54] | Confirmed |
| 8 May 2022 | Costa Rica declares a national emergency across its public sector | [126] | Reported |
| Jun 2022 | Play and Daixin Team become active | [19][8] | Confirmed |
| 2022 | Florida bars state agencies, counties and municipalities from paying ransoms (s. 282.3186) | [92] | Confirmed |
| 21 Jun 2022 | GAO: insurers exclude cyber warfare and infrastructure outages to limit systemic losses | [98] | Confirmed |
| 6 Jul 2022 | AA22-187A on North Korea's Maui ransomware | [6] | Confirmed |
| Late Jul 2022 | The FBI penetrates Hive's network | [64][55] | Confirmed |
| 11 Aug 2022 | A second $10 million Conti reward, for five named associates | [125] | Reported |
| 16 Aug 2022 | Lloyd's requires a state-backed cyber-attack exclusion in standalone cyber policies from 31 Mar 2023 | [99] | Confirmed |
| Sep 2022 | Royal ransomware in use (to about June 2023) | [11] | Confirmed |
| 6 to 8 Sep 2022 | AA22-249A: Vice Society disproportionately targets K-12 education | [7] | Confirmed |
| 21 Oct 2022 | AA22-294A on Daixin Team against health care | [8] | Confirmed |
| 17 Nov 2022 | AA22-321A: Hive has hit over 1,300 companies and received about $100 million | [9] | Confirmed |
| Jan 2023 | BianLian moves mainly to exfiltration-based extortion (exclusively by January 2024) | [13] | Confirmed |
| 26 Jan 2023 | DOJ announces the Hive disruption: over 300 keys to victims under attack, over 1,000 to earlier victims, about $130 million in demands averted | [64] | Confirmed |
| Early 2023 | CL0P exploits GoAnywhere MFT CVE-2023-0669 (about 130 claimed victims) | [14] | Confirmed |
| 4 Feb 2023 | Lehigh Valley Health Network discovers an ALPHV attack | [142] | Reported |
| 8 Feb 2023 | AA23-039A ESXiArgs recovery guidance: more than 3,800 servers compromised | [10] | Confirmed |
| 9 Feb 2023 | US and UK sanction seven Trickbot members, the UK's first sanctions of this kind | [45] | Confirmed |
| Feb 2023 | ALPHV's "Sphynx" update encrypts Windows, Linux and VMware | [20] | Confirmed |
| 2 Mar 2023 | AA23-061A on Royal | [11] | Confirmed |
| 16 Mar 2023 | AA23-075A on LockBit 3.0 | [12] | Confirmed |
| 7 Apr to 3 May 2023 | City of Dallas: Royal surveillance from 7 April, about 1.169 TB exfiltrated, ransomware deployed on 3 May | [85] | Confirmed |
| May 2023 | Rhysida deployments begin | [16] | Confirmed |
| 16 May 2023 | Treasury sanctions Mikhail Matveev for roles in Hive, LockBit and Babuk | [47] | Confirmed |
| 27 May 2023 | CL0P begins exploiting MOVEit Transfer CVE-2023-34362. Home study: [The Cl0p MOVEit Breach](/case-studies/CL0P_FILE_TRANSFER_2023.md) | [14] | Confirmed |
| 14 Jun 2023 | Seven-nation advisory AA23-165A: LockBit the most deployed variant of 2022 | [15] | Confirmed |
| 26 Jul 2023 | SEC adopts Form 8-K Item 1.05 for material cybersecurity incidents | [81] | Confirmed |
| 7 Sep 2023 | US and UK sanction eleven more Trickbot members; DOJ unseals indictments against nine Trickbot and Conti defendants | [46] | Confirmed |
| 7 to 14 Sep 2023 | Caesars determines its loyalty database was copied after social engineering of an outsourced IT vendor | [78] | Confirmed |
| Sep 2023 | MGM Resorts cybersecurity issue; about $100 million Adjusted Property EBITDAR impact (8-K, 5 Oct 2023) | [77] | Confirmed |
| Sep 2023 | The joint #StopRansomware Guide is updated | [31] | Confirmed |
| 10 to 18 Oct 2023 | NVD publishes Citrix Bleed CVE-2023-4966; KEV adds it on 18 October | [39] | Confirmed |
| Nov 2023 | LockBit attack on ICBC's US broker-dealer affects settlement of over $9 billion in Treasury-backed assets | [48] | Confirmed |
| 15 Nov 2023 | AA23-319A on Rhysida | [16] | Confirmed |
| 16 Nov 2023 | AA23-320A on Scattered Spider | [17] | Confirmed |
| 21 Nov 2023 | AA23-325A: LockBit 3.0 affiliates exploit Citrix Bleed; Boeing's parts business the observed victim | [18] | Confirmed |
| 18 Dec 2023 | AA23-352A on Play; SEC 8-K compliance date | [19][81] | Confirmed |
| 19 Dec 2023 | DOJ disrupts ALPHV: a decryption tool for over 500 victims, about $68 million in demands avoided; AA23-353A published | [65][20] | Confirmed |
| 10 Jan 2024 | KEV adds Ivanti CVE-2023-46805 and CVE-2024-21887, later flagged for ransomware use | [32] | Confirmed |
| 7 Feb 2024 | Chainalysis: ransomware payments passed $1 billion in 2023 | [104] | Reported |
| 8 Feb 2024 | State Department offers up to $10 million for Hive leaders | [55] | Confirmed |
| 12 to 21 Feb 2024 | Change Healthcare: login to a Citrix portal without MFA on 12 February, ransomware on 21 February. Home study: [The Change Healthcare Attack of 2024](/case-studies/CHANGE_HEALTHCARE_2024.md) | [70] | Confirmed |
| 20 Feb 2024 | Operation Cronos: the NCA takes control of LockBit; Treasury sanctions two LockBit affiliates | [57][58][48] | Confirmed |
| 29 Feb 2024 | AA24-060A on Phobos and AA24-060B on Ivanti Connect Secure | [21][22] | Confirmed |
| 5 Mar 2024 | ALPHV posts an apparently fake seizure notice and shuts down | [127] | Reported |
| 4 Apr 2024 | CISA publishes the CIRCIA proposed rule | [36] | Confirmed |
| 5 Apr 2024 | HHS HC3 note: 730 attacks on the health sector worldwide in six months | [86] | Confirmed |
| 18 Apr 2024 | AA24-109A on Akira | [23] | Confirmed |
| 7 May 2024 | LockBitSupp unmasked as Dmitry Khoroshev and sanctioned by the US, UK and Australia | [49][56] | Confirmed |
| 8 May 2024 | Ascension detects unauthorized activity; about 5.6 million people later notified | [140] | Reported |
| 10 May 2024 | AA24-131A on Black Basta | [24] | Confirmed |
| 20 May 2024 | EPA enforcement alert on drinking-water cybersecurity | [89] | Confirmed |
| 30 May 2024 | Operation Endgame phase 1 against the loaders | [67] | Confirmed |
| 3 Jun 2024 | Qilin attacks Synnovis, pathology provider to London NHS trusts | [128] | Reported |
| 19 Jun 2024 | CDK Global suspends systems; dealer groups file 8-Ks | [73][74] | Confirmed |
| 29 Jul 2024 | Microsoft reports ransomware operators exploiting ESXi CVE-2024-37085 | [43] | Confirmed |
| 7 Aug 2024 | AA23-061A updated for the BlackSuit rebrand | [11] | Confirmed |
| Aug 2024 | SafePay becomes highly active | [30] | Confirmed |
| 29 Aug 2024 | AA24-242A on RansomHub | [25] | Confirmed |
| 31 Aug 2024 | Transport for London intrusion | [59] | Confirmed |
| Late Sep 2024 | Interlock first seen | [28] | Confirmed |
| Oct 2024 | Third Cronos phase: four arrests and sanctions against affiliates | [66] | Confirmed |
| 3 Oct 2024 | American Water learns of unauthorized activity; no water facilities believed affected | [79] | Confirmed |
| Nov 2024 | CISA's pre-ransomware notifications reach 2,131 for the year | [35] | Reported |
| 6 Jan 2025 | HHS publishes the HIPAA Security Rule proposal | [88] | Confirmed |
| 5 Feb 2025 | Chainalysis: 2024 payments about $813.55 million, 35 percent below 2023 | [105] | Reported |
| 11 Feb 2025 | US, UK and Australia sanction the Zservers bulletproof hoster | [50] | Confirmed |
| 19 Feb 2025 | AA25-050A on Ghost (Cring) | [26] | Confirmed |
| 12 Mar 2025 | AA25-071A on Medusa | [27] | Confirmed |
| Apr 2025 | Gunra appears, apparently built on leaked Conti code; the IC3 2024 report is published | [29][95] | Confirmed |
| Apr 2025 | Ransomware incidents at Marks & Spencer and Co-op, rated one Category 2 event at £270 to £440 million | [101] | Confirmed |
| 12 Apr 2025 | DaVita: ransomware encrypts parts of its network | [75] | Confirmed |
| 19 to 22 May 2025 | Operation Endgame 2.0: 300 servers down, 20 arrest warrants | [69] | Confirmed |
| 20 May 2025 | Kettering Health incident it believes Interlock carried out | [84] | Confirmed |
| 30 May 2025 | Australia's ransomware payment reporting duty takes effect | [130] | Reported |
| 1 Jul 2025 | Treasury sanctions the Aeza Group bulletproof hoster | [51] | Confirmed |
| 10 Jul 2025 | NCA arrests four people over the M&S, Co-op and Harrods attacks | [120][131] | Reported |
| 22 Jul 2025 | AA25-203A on Interlock; UK government response on ransomware legislation | [28][93] | Confirmed |
| 29 Jul 2025 | AA23-320A updated: per trusted third parties, Scattered Spider now deploys DragonForce | [17] | Confirmed |
| 7 Aug 2025 | HSI announces Operation Checkmate against BlackSuit | [61] | Confirmed |
| Late Aug 2025 | Jaguar Land Rover incident, Category 3, £1.9 billion | [102] | Confirmed |
| 18 Sep 2025 | NCA charges Thalha Jubair and Owen Flowers over the TfL intrusion | [59] | Confirmed |
| 19 Sep 2025 | RTX: ransomware on systems supporting MUSE airport passenger processing | [76] | Confirmed |
| 29 Sep 2025 | Asahi's Japanese operations hit; Qilin claims it | [132] | Reported |
| 4 to 6 Oct 2025 | Oracle Security Alert for E-Business Suite CVE-2025-61882; KEV adds it | [41] | Confirmed |
| Oct 2025 | CISA misses the statutory deadline to finalize CIRCIA | [129] | Reported |
| 4 Nov 2025 | A former ransomware negotiator and a former incident-response manager charged with deploying ALPHV | [119] | Reported |
| 10 to 13 Nov 2025 | Operation Endgame takes down 1,025 servers (Rhadamanthys, VenomRAT, Elysium) | [67] | Confirmed |
| 13 Nov 2025 | AA24-109A updated: Akira about $244.17 million in proceeds | [23] | Confirmed |
| Dec 2025 | FinCEN financial trend analysis covering 2022 to 2024 | [96] | Confirmed |
| Jan 2026 | Gunra launches a formal RaaS affiliate program | [29] | Confirmed |
| 21 Jan 2026 | Oleg Nefedov, alleged Black Basta founder, added to Europol and INTERPOL most-wanted lists | [118] | Reported |
| 3 Feb 2026 | Coveware Q4 2025: payment rate about 20 percent | [111] | Reported |
| 26 Feb 2026 | Chainalysis: 2025 payments above $820 million | [106] | Reported |
| Late Apr to May 2026 | Instructure's Canvas platform: data exfiltrated, platform disrupted, ransom paid | [103] | Confirmed |
| Jun to Oct 2026 | Qilin and INC exploit PAN-OS GlobalProtect CVE-2026-0257 ([case study](/case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md)) | [134] | Reported |
| 15 to 18 Jun 2026 | CISA holds four CIRCIA town halls | [34] | Confirmed |
| 24 Jun 2026 | Operation Endgame season 3 against SocGholish, Amadey and StealC | [68] | Confirmed |
| 8 Jul 2026 | HIPAA Security Rule final action pushed to no earlier than July 2027 | [141] | Reported |
| 16 Jul 2026 | Jubair and Flowers each sentenced to five years six months | [60] | Confirmed |
| 10 Aug 2026 | AA26-222A on Gunra | [29] | Confirmed |
| 18 Aug 2026 | AA25-071A updated: Medusa over 500 victims | [27] | Confirmed |
| 10 to 19 Sep 2026 | 3AM affiliate encrypts about 37 machines at a UK school estate | [139] | Reported |
| 30 Sep 2026 | Operation KillSwitch seizes KillSec's leak site | [133][122] | Reported |
| 1 Oct 2026 | CIRCIA final rule received for OIRA review | [37] | Confirmed |
| 8 Oct 2026 | FBI arrests a ransomware-negotiation executive in its ShinyHunters investigation | [123] | Reported |
| 20 Oct 2026 | AA26-293A on SafePay; GMO finds an intrusion in its Onamae Desktop Cloud | [30][135] | Confirmed; Reported for GMO |
| 26 Oct 2026 | UNM Health diverts ambulances; South Carolina and ONCD launch Project Lifeline 250 for rural hospitals | [136][90] | Reported; Confirmed for the pilot |
| 27 Oct 2026 | Artem Stryzhak, a Nefilim and Hive affiliate, sentenced to 70 months | [121] | Reported |
| 29 Oct 2026 | HHS OCR settles with Lehigh Valley Health Network for $800,000 | [142] | Reported |
| 4 Nov 2026 | Queens Public Library confirms ransomware disruption | [137] | Reported |
| 9 Nov 2026 | Vanderbilt University confirms an incident claimed by BYOD | [138] | Reported |
| 10 Nov 2026 | KEV catalog version 2026.11.10: 361 of 1,779 entries flagged for ransomware use | [32] | Confirmed; Demonstrated |

## Part 3: the brands

Each profile below gives what the government record says, then what the ATT&CK record adds. Brands appear roughly in the order they became prominent.

### Wizard Spider: TrickBot, Ryuk and Conti (G0102)

ATT&CK tracks the operators behind TrickBot, Ryuk and Conti as [Wizard Spider (G0102)](/mitre/groups/G0102.md), with software [Conti (S0575)](/mitre/software/S0575.md), [TrickBot (S0266)](/mitre/software/S0266.md), [Ryuk (S0446)](/mitre/software/S0446.md) and [Bazar (S0534)](/mitre/software/S0534.md) (Confirmed [145]). ATT&CK's campaign [C0015](/mitre/campaigns/C0015.md), by unidentified attackers, is a five-day intrusion using Bazar, Cobalt Strike and Conti (Confirmed [145][161]).

The government record runs from warning to sanctions. In October 2020 CISA, FBI and HHS said Ryuk was typically deployed as a TrickBot payload against hospitals (Confirmed [1]). In September 2021 CISA and the FBI counted more than 400 Conti attacks, a figure they later updated to more than 1,000. Conti was delivered through TrickBot, IcedID and Cobalt Strike (Confirmed [4]). The State Department's reward offer of May 2022 cited the FBI's estimate of over 1,000 victims and payouts above $150 million as of January 2022, which made Conti the costliest strain documented to that date. The same offer recorded Conti's April 2022 attack on the Government of Costa Rica (Confirmed [54]). Press reporting adds that Conti's internal chats leaked in February 2022 after it backed Russia's invasion of Ukraine, and that the Costa Rica attack crippled customs and tax platforms during the presidential transition (Reported [124]). In 2023 the US and UK sanctioned seven Trickbot members in February and eleven more in September, and the Justice Department unsealed indictments against nine people tied to Trickbot and Conti (Confirmed [45][46]).

Conti did not end with its brand. Press reporting on German and Ukrainian police action in January 2026 says Conti members split into Zeon, Black Basta and Quantum, and that Quantum became Royal and then BlackSuit; the police notices were not opened (Reported [118]). Gunra, which appeared in April 2025, appears to be based on or significantly influenced by Conti's leaked 2022 source code, by the agencies' account (Confirmed [29]). The Akira advisory says Akira may connect to the defunct Conti (Confirmed [23]).

### LockBit (S1199, S1202)

LockBit worked as an affiliate-based RaaS from January 2020. LockBit 3.0, also called LockBit Black, continued LockBit 2.0 and shares similarities with BlackMatter and BlackCat (Confirmed [12]). Seven national agencies called it the most deployed ransomware variant worldwide in 2022. They counted about 1,700 US attacks since 2020, about $91 million in US ransoms paid, and 1,653 alleged victims on its leak sites up to the first quarter of 2023 (Confirmed [15]). Its affiliate base was large and unconnected, so its tactics varied widely; the advisory lists dozens of abused freeware and open-source tools plus LockBit's own StealBit exfiltration tool (Confirmed [15]). In November 2023 LockBit 3.0 affiliates exploited Citrix Bleed (Confirmed [18]), and LockBit was named for the attack on ICBC's US broker-dealer, which affected settlement of over $9 billion in Treasury-backed assets (Confirmed [48]).

Operation Cronos is told in Part 7. Its numbers belong here. The NCA counted more than 7,000 attacks built on LockBit's platform from June 2022 to February 2024, more than 100 hospitals and healthcare companies targeted, and at least 2,110 victims in negotiation (Confirmed [56]). Its Cronos page says LockBit was responsible for 25 percent of ransomware attacks in 2023 to 2024 (Confirmed [58]). Per the Justice Department, as relayed by Treasury, LockBit targeted over 2,500 victims and received more than $500 million in ransoms (Confirmed [49]).

ATT&CK records [LockBit 2.0 (S1199)](/mitre/software/S1199.md) and [LockBit 3.0 (S1202)](/mitre/software/S1202.md) as software and has no LockBit group object (Confirmed [148]). StealBit has its own entry, [S1200](/mitre/software/S1200.md) (Confirmed [161]).

### ALPHV, also BlackCat (S1068)

The ALPHV advisory, first published 19 December 2023 and updated 27 February 2024, records the brand's turn against hospitals. After the December 2023 law-enforcement action, ALPHV's administrator urged affiliates to target hospitals, and healthcare became the most victimized sector among nearly 70 victims leaked from mid-December (Confirmed [20]). Its February 2023 "Sphynx" update encrypts Windows, Linux and VMware instances, and some affiliates extort without encrypting (Confirmed [20]). Affiliates posed as IT or help-desk staff by phone or SMS to obtain credentials and used an adversary-in-the-middle framework to capture MFA codes and session cookies (Confirmed [20]).

The Justice Department's December 2023 disruption gave over 500 victims a decryption tool, avoided about $68 million in demands and seized several ALPHV websites; it said ALPHV had targeted more than 1,000 victims (Confirmed [65]). ALPHV's best-known attack came two months later.

**Change Healthcare (summary; home study [The Change Healthcare Attack of 2024](/case-studies/CHANGE_HEALTHCARE_2024.md)).** On 12 February 2024 criminals used compromised credentials to reach a Change Healthcare Citrix portal that had no multifactor authentication, moved laterally, exfiltrated data, and deployed ransomware on 21 February; an actor calling itself ALPHV or BlackCat claimed it, and UnitedHealth Group's chief executive testified that "the decision to pay a ransom was mine" (Confirmed [70]). The company's first SEC filing called the actor "suspected nation-state associated" (Confirmed [72]). On 5 March 2024 ALPHV posted an apparently fake seizure notice and shut down, an affiliate complained it had been cut out of the payment, and a Justice Department spokesperson said it was not an official law-enforcement action (Reported [127]). The widely cited $22 million figure began as an attacker claim (Reported [143]).

Coveware says BlackCat "disappeared in a likely exit scam" (Reported [107]). Two afterwords tie the brand to people paid to fight it. A federal indictment unsealed in the Southern District of Florida charged a former ransomware negotiator and a former incident-response manager with deploying ALPHV against at least five US victims (Reported [119]). HHS's Office for Civil Rights settled its investigation of Lehigh Valley Health Network, an ALPHV victim of February 2023, for $800,000 in October 2026 (Reported [142]). ATT&CK records BlackCat as [S1068](/mitre/software/S1068.md), with no ALPHV group object (Confirmed [149]).

### CL0P and TA505 (G0092, S0611)

**The file-transfer campaigns (summary; home study [The Cl0p MOVEit Breach](/case-studies/CL0P_FILE_TRANSFER_2023.md)).** The FBI and CISA call the operation the CL0P Ransomware Gang, also known as TA505. From 27 May 2023 it exploited the MOVEit Transfer zero-day CVE-2023-34362, a SQL injection (CWE-89), and installed the LEMURLOOT web shell. Its earlier zero-day campaigns hit Accellion FTA in 2020 to 2021 and GoAnywhere MFT in early 2023, where it claimed about 130 victims (Confirmed [14]). The advisory says CL0P's campaigns since 2021 relied mostly on data exfiltration rather than encryption (Confirmed [14]). In October 2025 Oracle issued a Security Alert for E-Business Suite CVE-2025-61882 (Confirmed [41]); Coveware reports that CL0P's 2025 Oracle campaign drew some of the lowest engagement and monetization of any CL0P campaign (Reported [111]). ATT&CK tracks [TA505 (G0092)](/mitre/groups/G0092.md) and [Clop (S0611)](/mitre/software/S0611.md) (Confirmed [150]).

### Hive

Hive was active from June 2021. By November 2022 it had victimized over 1,300 companies and received about $100 million, with the health sector especially affected (Confirmed [9]). The FBI penetrated Hive's network in late July 2022. When the Justice Department announced the disruption on 26 January 2023, it said the FBI had given over 300 decryption keys to victims under attack and over 1,000 to earlier victims, averting about $130 million in demands, and that Hive had targeted more than 1,500 victims in over 80 countries and received over $100 million (Confirmed [64]). Chainalysis later estimated the infiltration may have averted at least $210.4 million (Reported [104]). The State Department offered up to $10 million for Hive's leaders in February 2024 (Confirmed [55]). Treasury sanctioned Mikhail Matveev in May 2023 for roles in Hive, LockBit and [Babuk (S0638)](/mitre/software/S0638.md) (Confirmed [47][161]). Artem Stryzhak, a Nefilim and later Hive affiliate who paid Nefilim's administrators a 20 percent fee, was sentenced to 70 months in October 2026; the indicted administrator Volodymyr Tymoshchuk, also accused over [LockerGoga (S0372)](/mitre/software/S0372.md) and [MegaCortex (S0576)](/mitre/software/S0576.md), remains at large (Reported [121]; Confirmed [161] for the ids). ATT&CK has no Hive object (Confirmed [161]).

### Royal and BlackSuit (S1073)

Royal was used from about September 2022 to June 2023. CISA updated its Royal advisory on 7 August 2024 for the rebrand to BlackSuit, which it calls an evolution of Royal on the basis of shared code. BlackSuit demands typically ran $1 million to $10 million, with over $500 million demanded in total and a largest single demand of $60 million. Its actors may buy access from brokers and use VPN credentials from stealer logs (Confirmed [11]). The City of Dallas attack of 2023 shows the pattern in one victim: Royal began surveillance on 7 April through a service domain account and legitimate remote-management tools, took about 1.169 TB, and deployed ransomware on 3 May; 30,253 people were notified (Confirmed [85]).

On 7 August 2025 Homeland Security Investigations announced Operation Checkmate, a takedown of BlackSuit infrastructure coordinated through a Europol J-CAT initiative with the NCA and German, Irish, Ukrainian, Lithuanian, French and Canadian partners. It said Royal and BlackSuit had compromised over 450 known US victims and received more than $370 million at present-day cryptocurrency valuations since 2022 (Confirmed [61]). The dealer groups' 8-K filings on the CDK Global outage of June 2024 name neither ransomware nor BlackSuit (Confirmed [73][74]). ATT&CK records [Royal (S1073)](/mitre/software/S1073.md) and has no BlackSuit object (Confirmed [147]).

### Black Basta (S1070) and Storm-1811 (G1046)

Black Basta was first identified in April 2022. By May 2024 its affiliates had hit at least 12 of 16 critical infrastructure sectors and over 500 organizations worldwide, using double extortion (Confirmed [24]). Affiliates exfiltrated with RClone before encrypting (Confirmed [24]). From May 2024 they used email bombing followed by fake tech-support calls, later over Microsoft Teams, to get users to install remote-support tools; they had exploited the ConnectWise ScreenConnect flaw CVE-2024-1709 since February 2024 (Confirmed [24]). ATT&CK tracks the entity linked to Black Basta deployment as [Storm-1811 (G1046)](/mitre/groups/G1046.md), known for email flooding and help-desk social engineering, and the encryptor as [Black Basta (S1070)](/mitre/software/S1070.md) (Confirmed [146]). In January 2026 Oleg Nefedov, named as Black Basta's alleged founder and leader since 2022, was added to Europol and INTERPOL most-wanted lists after police searches in Ukraine (Reported [118]). Ascension's May 2024 attack has been attributed to Black Basta in the press, but Ascension has not confirmed it (Reported [140]).

### Akira (G1024, S1129, S1194)

The multinational Akira advisory, first issued 18 April 2024 and updated 13 November 2025, associates Akira with Storm-1567, Howling Scorpius, Punk Spider and Gold Sahara and says it may connect to the defunct Conti (Confirmed [23]). Akira had claimed about $244.17 million in ransom proceeds as of late September 2025. It got in mostly through VPN services without MFA, with credentials possibly bought from brokers, and through Cisco CVE-2020-3259 and CVE-2023-20269 and SonicWall CVE-2024-40766; the advisory also cites Veeam CVE-2023-27532 and CVE-2024-40711 and ESXi CVE-2024-37085. In some incidents exfiltration began about two hours after initial access (Confirmed [23]). ATT&CK records the group [Akira (G1024)](/mitre/groups/G1024.md) and the software [Akira (S1129)](/mitre/software/S1129.md) and [Akira _v2 (S1194)](/mitre/software/S1194.md) (Confirmed [151]). The IC3 2024 report ranked Akira first among variants by complaint count (Confirmed [95]), and FinCEN's 2022 to 2024 data puts it first by incidents, at 376 (Confirmed [96]).

### Play (G1040, S1162)

Play, or Playcrypt, has been active since June 2022, was among the most active groups of 2024, and had affected about 900 entities by May 2025. The agencies presume it is a closed group rather than an affiliate program (Confirmed [19]). It uses intermittent encryption, and its ESXi variant powers off virtual machines before encrypting them (Confirmed [19]). ATT&CK records [Play (G1040)](/mitre/groups/G1040.md) and [Playcrypt (S1162)](/mitre/software/S1162.md) (Confirmed [153]).

### RansomHub (S1212)

RansomHub, formerly Cyclops and Knight, drew affiliates from LockBit and ALPHV and had at least 210 victims from February to August 2024 (Confirmed [25]). Its notes gave victims 3 to 90 days depending on the affiliate (Confirmed [25]). ATT&CK records it as software, [S1212](/mitre/software/S1212.md), and notes a possible purchase and rebrand of Knight resources (Confirmed [152]). In April 2024 RansomHub posted Change Healthcare data with a sale deadline, as press reported; the home study has that record and grades it Reported ([Change Healthcare](/case-studies/CHANGE_HEALTHCARE_2024.md)).

### Medusa (G1051, S1244)

Medusa was first identified in June 2021 and had over 500 victims as of April 2026. Its developers and affiliates double-extort; it recruits initial access brokers on forums and pays them $100 to $1 million (Confirmed [27]). The advisory describes a victim who had already paid receiving a second demand from another actor, which it calls possible triple extortion or internal dysfunction (Confirmed [27]). ATT&CK tracks [Medusa Group (G1051)](/mitre/groups/G1051.md) and [Medusa Ransomware (S1244)](/mitre/software/S1244.md); [S1220 MEDUSA](/mitre/software/S1220.md) is an unrelated open-source Linux rootkit (Confirmed [154][161]). Coveware reports a Medusa affiliate trying to recruit an insider for network access in 2025 (Reported [110]).

### Scattered Spider (G1015) and DragonForce

Scattered Spider targets large companies and the IT help desks they contract, with SIM swaps, layered social engineering and calls to the help desk to reset passwords or move MFA to devices the actors control (Confirmed [17]). The July 2025 update says that, per trusted third parties, the actors now deploy DragonForce ransomware against VMware ESXi servers, sometimes after exfiltration, and look for Snowflake access to pull data in bulk (Confirmed [17]). ATT&CK records the group as [Scattered Spider (G1015)](/mitre/groups/G1015.md), with aliases Roasted 0ktapus, Octo Tempest, Storm-0875 and UNC3944, and has no DragonForce object (Confirmed [155]).

The UK record carries the furthest prosecution of the group in this study's sources (Inferred). The NCA arrested four people on 10 July 2025 over the April 2025 attacks on Marks & Spencer, Co-op and Harrods, which industry and law enforcement attribute to Scattered Spider (Reported [120][131]). On 18 September 2025 it charged Thalha Jubair and Owen Flowers over the 31 August 2024 intrusion at Transport for London, which investigators believe Scattered Spider members carried out; Flowers was also charged over attacks on SSM Health Care and Sutter Health (Confirmed [59]). On 16 July 2026 both were sentenced to five years six months after guilty pleas. The NCA called them leading members, said the case effectively halted the group, and reported that Microsoft confirmed the arrests materially degraded it; TfL reported £29 million in losses (Confirmed [60]). Caesars' September 2023 filing attributes its incident to social engineering of an outsourced IT support vendor (Confirmed [78]), and MGM reported a cybersecurity issue the same month (Confirmed [77]); this study's sources do not tie either incident to Scattered Spider by a primary record (Inferred from [77][78]).

### Qilin (S1242) and Water Galura (G1050)

ATT&CK records Qilin (also Agenda) as [S1242](/mitre/software/S1242.md) and its operators as [Water Galura (G1050)](/mitre/groups/G1050.md), also GOLD FEATHER, who handle payloads, negotiations and leak publication for affiliates recruited on Russian-language forums. CISA's #StopRansomware list, as checked on 11 November 2026, has no Qilin advisory (Confirmed [7]). The record of Qilin's attacks is mostly press: Synnovis in June 2024, with NHS England figures of 10,152 outpatient appointments and 1,710 elective procedures postponed (Reported [128]); Asahi in September 2025 (Reported [132]); and exploitation, with INC, of the PAN-OS GlobalProtect authentication bypass CVE-2026-0257 since June 2026, per Unit 42 as relayed by The Register (Reported [134]). The library's [ICS attacks study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) also records Asahi.

### The other advisories

- **Rhysida**: deployed from May 2023, mainly against education, healthcare, manufacturing, IT and government as targets of opportunity; actors commonly logged in to VPNs with valid credentials where MFA was absent (Confirmed [16]).
- **Phobos**: RaaS, with state and local government incidents reported to MS-ISAC since May 2019 (Confirmed [21]).
- **Ghost (Cring)**: China-located actors since early 2021, exploiting outdated internet-facing software in more than 70 countries, under many names (Confirmed [26]). Their notes threaten to sell data, but the advisory says they do not often steal much (Confirmed [26]).
- **Interlock**: first seen late September 2024; drive-by downloads from compromised sites and ClickFix-style lures for initial access, Windows and Linux encryptors for virtual machines, double extortion (Confirmed [28]). Kettering Health believes Interlock carried out its May 2025 incident (Confirmed [84]).
- **Gunra**: appeared in April 2025, based on or significantly influenced by leaked Conti code, by the agencies' account, and launched a formal RaaS program in January 2026, with opening demands over tens of millions of dollars (Confirmed [29]).
- **SafePay**: highly active since August 2024 with at least 600 victims; CISA calls it "among the most active ransomware groups in 2026" (Confirmed [30]).
- **Vice Society, AvosLocker, Snatch and BianLian** are also on CISA's #StopRansomware list (Confirmed [7]). ATT&CK campaign [C0018](/mitre/campaigns/C0018.md) is a month-long [AvosLocker (S1053)](/mitre/software/S1053.md) intrusion (Confirmed [7][161]).
- **Daixin Team**: active from June 2022 against health care (Confirmed [8]).
- **Maui**: North Korean state-sponsored ransomware against health-sector organizations from May 2021 (Confirmed [6]).
- **KillSec**: a RaaS active since 2024; Operation KillSwitch seized its leak site and five servers, made three provisional arrests and identified a 16-year-old as the suspected main operator (Reported [122][133]).
- **Byod and 3AM**: Byod claimed the October 2026 UNM Health attack and the November 2026 Vanderbilt incident (Reported [136][138]); a 3AM affiliate hit a UK school estate in September 2026 in what Bitdefender suspects was an AI-assisted attack (Reported [139]).

## Part 4: tradecraft at the level of the advisories

This Part describes behavior as the advisories describe it, by technique name. Part 10 binds the ids.

### Getting in: edge devices and remote access

Phishing, stolen or brute-forced RDP credentials and software vulnerabilities were the top three initial infection vectors in 2021, per the five-agency advisory (Confirmed [5]). The later advisories show the weight moving to edge devices and remote access.

- **VPNs without MFA.** Akira entered mainly through VPN services with no MFA configured (Confirmed [23]). Rhysida and Daixin used valid VPN credentials where MFA was absent, Daixin on a legacy VPN with likely phished credentials (Confirmed [16][8]). Colonial Pipeline's attacker used a legacy VPN profile that was not intended to be in use (Confirmed [71]). SafePay came in through VPNs with phished accounts and Mullvad exit addresses, as well as edge-device exploitation and brute force (Confirmed [30]).
- **Edge appliance exploits.** The advisories name Fortinet, Citrix, Cisco, SonicWall, Ivanti, Palo Alto Networks and others (Part 5). Gunra got in mainly by exploiting FortiGate authentication bypasses, also using default SSL-VPN admin credentials on devices without account lockout and planting a rogue persistent super-user on FortiOS (Confirmed [29]).
- **Credentials harvested before the patch.** In September 2021 Fortinet said an actor had disclosed SSL-VPN access data for 87,000 FortiGate devices harvested from systems still unpatched against CVE-2018-13379, which had been fixed in May 2019, and advised organization-wide password resets and MFA (Confirmed [42]).
- **Session theft.** LockBit 3.0 affiliates used Citrix Bleed to hijack valid sessions, bypassing passwords and MFA (Confirmed [18]).
- **Stealer logs and brokers.** BlackSuit actors may use VPN credentials from stealer logs and access from brokers (Confirmed [11]). Verizon found that 54 percent of victims disclosed by ransomware actors in 2024 had their domains in infostealer credential dumps (Reported [117]).
- **Drive-by and copy-paste lures.** Interlock used drive-by downloads and ClickFix-style lures that trick the user into running a command themselves (Confirmed [28]).

### Getting in: people

- **Help desks.** Scattered Spider calls help desks posing as employees to reset passwords and move MFA (Confirmed [17]). ALPHV affiliates posed as IT or help-desk staff (Confirmed [20]). Caesars attributes its incident to social engineering of an outsourced IT support vendor (Confirmed [78]).
- **MFA fatigue and SIM swaps.** Scattered Spider uses repeated MFA prompts, SIM swaps, and phishing and smishing on lookalike domains (Confirmed [17]).
- **Email bombing then a phone call.** Black Basta affiliates flood a user's inbox and then call, later over Microsoft Teams, offering help and asking the user to install AnyDesk or Quick Assist (Confirmed [24]).
- **Insiders.** Coveware reported a Medusa affiliate trying to recruit an insider for network access in 2025 (Reported [110]).

### Inside: living off the land

The advisories name dual-use tools far more often than custom malware (Inferred). LockBit's advisory lists dozens of freeware and open-source tools, including [AdFind (S0552)](/mitre/software/S0552.md), AnyDesk, [BloodHound (S0521)](/mitre/software/S0521.md), [Impacket (S0357)](/mitre/software/S0357.md), [Mimikatz (S0002)](/mitre/software/S0002.md), [PsExec (S0029)](/mitre/software/S0029.md), [Rclone (S1040)](/mitre/software/S1040.md) and ScreenConnect ([ConnectWise, S0591](/mitre/software/S0591.md)), alongside its own StealBit (Confirmed [15]; Confirmed [161] for the ids). Medusa's advisory names PowerShell, cmd, WMI, certutil and PsExec, and remote-management products from AnyDesk, Atera, ConnectWise, N-able, SimpleHelp, Splashtop and BeyondTrust (Confirmed [27]). The recurring pattern across the Black Basta, Akira, RansomHub, LockBit, Medusa, Gunra and SafePay advisories is RClone plus a cloud or file-sharing service for exfiltration, and legitimate remote-access tools for persistence and command and control (Inferred from [15][23][24][25][27][29][30]).

### Taking the data

Exfiltration comes before encryption in almost every advisory since 2023 (Inferred). Black Basta used RClone (Confirmed [24]). SafePay archives data with 7-Zip or WinRAR and sends it out with RClone, OneDrive or Backblaze before encrypting (Confirmed [30]). Gunra pulled data from OneDrive and SharePoint and sent it to Mega, reaching tens of terabytes in at least one case (Confirmed [29]). Scattered Spider looks for Snowflake access to pull data in bulk (Confirmed [17]). The Dallas attackers took about 1.169 TB over nearly four weeks before deploying ransomware (Confirmed [85]).

### Hitting the hypervisor

Encrypting the virtualization layer takes down every server on it at once (Inferred). The ESXiArgs wave of February 2023 compromised more than 3,800 servers worldwide, likely unpatched or end-of-life ESXi hosts; CISA's guidance names no CVE and advises disabling SLP (Confirmed [10]). The CVE often tied to ESXiArgs, CVE-2021-21974, is an OpenSLP heap overflow that is not in the KEV catalog, and the link appears only in secondary reporting (Confirmed [40]). In July 2024 Microsoft described CVE-2024-37085, in which domain-joined ESXi grants full admin rights to a domain group named "ESX Admins" without validating it. Storm-0506, Storm-1175, Octo Tempest and Manatee Tempest used it with Akira and Black Basta encryptors, and Microsoft's incident-response engagements involving ESXi more than doubled in three years (Confirmed [43]). Octo Tempest is an ATT&CK alias of [Scattered Spider (G1015)](/mitre/groups/G1015.md) and Manatee Tempest an alias of [Indrik Spider (G0119)](/mitre/groups/G0119.md) in the library's data (Confirmed [155][161]). ALPHV's Sphynx, Play's ESXi variant, Interlock and DragonForce all encrypt virtual machines (Confirmed [20][19][28][17]).

### Breaking recovery and defenses

The 2020 hospital advisory already listed inhibiting system recovery, stopping services and disabling security tools (Confirmed [1]). The Black Basta advisory lists inhibiting recovery and disabling tools (Confirmed [24]). In 94 percent of attacks in Sophos's 2024 survey, criminals tried to compromise backups, and 57 percent of those attempts succeeded (Reported [115]). The home study records the chief executive's testimony that the attack reached both the primary and the backup environments ([Change Healthcare](/case-studies/CHANGE_HEALTHCARE_2024.md)).

### Disruption without encryption

The agencies' 2021 description of triple extortion included threats to disrupt the victim's internet access (Confirmed [5]). Colonial Pipeline shows the other kind of disruption: the operator halted its pipeline as a precaution after the ransom note appeared on an IT system (Confirmed [71]). That was an IT incident whose dependencies stopped operational technology, not a compromise of the pipeline's control systems (Confirmed [71]).

### Automation

The only suspected AI-assisted ransomware intrusion in this study's sources is the September 2026 3AM attack on a UK school estate, where Bitdefender suspects AI-generated commands and an automated agent loop (Reported [139]). One vendor's suspicion is not yet a pattern (Inferred). For the wider record on AI in attacks, see [AI Threats in the Cybersecurity Industry](/case-studies/AI_THREATS_2026.md).

## Part 5: exploited vulnerabilities

The ransomware advisories name the CVEs they observed. KEV records whether CISA knows of ransomware use. Neither is complete, and the gap between them is a finding of its own.

| CVE | Product | Weakness (as recorded) | KEV and ransomware flag | Named with | Source | Grade |
|---|---|---|---|---|---|---|
| CVE-2018-13379 | FortiOS SSL-VPN | Path traversal, CWE-22 | Added 3 Nov 2021; Known | LockBit, Play, Ghost; 87,000 device credentials leaked | [15][19][26][32][42] | Confirmed |
| CVE-2019-19781 | Citrix ADC and Gateway | Directory traversal, CWE-22 | Added 3 Nov 2021; Known | 2019 and 2020 waves ([CHRONICLE_2019](/case-studies/CHRONICLE_2019.md)) | [32] | Confirmed |
| CVE-2020-12812 | FortiOS | not cited | Added 3 Nov 2021; Known | Hive, Play | [9][19][32] | Confirmed |
| CVE-2020-3259 | Cisco ASA and FTD | not cited | Known | Akira, SafePay | [23][30][32] | Confirmed |
| CVE-2021-30116 | Kaseya VSA | Credential disclosure, CWE-522 | Added 3 Nov 2021; Known | REvil's Kaseya attack, July 2021 | [32][38][63] | Confirmed |
| CVE-2021-21974 | VMware ESXi (OpenSLP) | Heap overflow, CWE-787 | Not in KEV catalog 2026.11.10 | ESXiArgs, in secondary reporting only | [40][10] | Confirmed |
| CVE-2021-34473, -34523, -31207 | Exchange (ProxyShell) | not cited | not cited | Hive, Ghost ([Exchange study](/case-studies/EXCHANGE_MARAUDER_2021.md)) | [9][26] | Confirmed |
| CVE-2022-41040, -41082 | Exchange (ProxyNotShell) | not cited | not cited | Play | [19] | Confirmed |
| CVE-2023-0669 | GoAnywhere MFT | not cited | Known | CL0P, early 2023 | [14][32] | Confirmed |
| CVE-2023-34362 | MOVEit Transfer | SQL injection, CWE-89 | Known | CL0P, from 27 May 2023 ([CL0P study](/case-studies/CL0P_FILE_TRANSFER_2023.md)) | [14][32] | Confirmed |
| CVE-2023-3519 | Citrix ADC and Gateway | not cited | Known (one of seven Citrix entries) | RansomHub | [25][32] | Confirmed |
| CVE-2023-4966 | NetScaler ADC and Gateway (Citrix Bleed) | CWE-119 per Citrix as CNA; NVD-CWE-noinfo per NVD | Added 18 Oct 2023; Known | LockBit 3.0 | [18][39] | Confirmed |
| CVE-2023-20269 | Cisco ASA and FTD | not cited | Known | Akira, SafePay | [23][30][32] | Confirmed |
| CVE-2023-27532 | Veeam Backup and Replication | not cited | Added 22 Aug 2023; Known | Akira, SafePay | [23][30][32] | Confirmed |
| CVE-2023-27997 | FortiOS | not cited | Known | RansomHub | [25][32] | Confirmed |
| CVE-2023-46805, CVE-2024-21887 | Ivanti Connect Secure | not cited | Added 10 Jan 2024; Known | No ransomware advisory names them | [22][32] | Confirmed; Inferred for the gap |
| CVE-2024-1709 | ConnectWise ScreenConnect | not cited | Known | Black Basta, from Feb 2024 | [24][32] | Confirmed |
| CVE-2024-37085 | VMware ESXi | Authentication flaw ("ESX Admins" group) | Added 30 Jul 2024; Known | Akira, Black Basta | [43][23][32] | Confirmed |
| CVE-2024-40711 | Veeam Backup and Replication | not cited | Added 17 Oct 2024; Known | Akira, SafePay | [23][30][32] | Confirmed |
| CVE-2024-40766 | SonicWall SonicOS | not cited | Known | Akira, SafePay | [23][30][32] | Confirmed |
| CVE-2024-55591, CVE-2025-24472 | FortiOS and FortiProxy | Authentication bypass, CWE-288 | Known (Fortinet set) | Gunra | [29][32] | Confirmed |
| CVE-2024-57727 | SimpleHelp | not cited | Added 13 Feb 2025; Known | Play, after its 16 Jan 2025 disclosure | [19][32] | Confirmed |
| CVE-2025-0282 | Ivanti Connect Secure | not cited | Added 8 Jan 2025; Known | No ransomware advisory names it | [32] | Confirmed |
| CVE-2025-61882 | Oracle E-Business Suite | CWE-287 per NVD | Added 6 Oct 2025; Known | CL0P's 2025 Oracle EBS campaign; the alert names no actor | [32][41][111] | Confirmed for the alert; Reported for CL0P's campaign; Inferred that the campaign used this CVE |
| CVE-2026-0257 | PAN-OS GlobalProtect | Authentication bypass | Added 29 May 2026; Known | Qilin and INC, from June 2026 | [32][134] | Confirmed for the KEV flag [32]; Reported for Qilin and INC [134] |
| CVE-2017-0144, CVE-2020-1472 | Windows SMBv1, Netlogon | not cited | not cited | RansomHub | [25] | Confirmed |
| CVE-2010-2861, CVE-2009-3960, CVE-2019-0604 | ColdFusion, SharePoint | not cited | not cited | Ghost | [26] | Confirmed |

What the table shows:

- **Edge first.** Of the products named, most are VPNs, firewalls, remote-access gateways and file-transfer servers that face the internet (Inferred from the table). Verizon's 2025 report puts edge devices and VPNs at 22 percent of exploitation targets, up from 3 percent, and says only about 54 percent of those edge vulnerabilities were fully remediated during the year, at a median of 32 days (Reported [117]).
- **Ransomware through a SharePoint exploit chain.** The library's [SharePoint ToolShell study](/case-studies/SHAREPOINT_TOOLSHELL_2025.md) records Microsoft attributing Warlock and LockBit deployments on compromised on-premises SharePoint servers in July 2025 to Storm-2603; no ransomware advisory in this study's sources names those CVEs (Reported here from the home study, which carries the primaries; Inferred for the gap).
- **Old flaws keep working.** Ghost used ColdFusion flaws from 2009 and 2010 in an advisory dated 2025 (Confirmed [26]). CVE-2018-13379, fixed in May 2019, appears in the LockBit, Play and Ghost advisories (Confirmed [15]).
- **The same set, two brands.** SafePay's advisory lists the same Cisco, Veeam and SonicWall CVEs as Akira's (Confirmed [30][23]). Shared CVE lists are what you would expect when access brokers sell to several brands (Inferred from [27][30]).
- **The KEV flag is sometimes the only public sign.** KEV flags Ivanti CVE-2023-46805, CVE-2024-21887 and CVE-2025-0282 for known ransomware use, and twelve Ivanti entries carry the flag, yet the joint Ivanti advisory does not mention ransomware, and ATT&CK's [Cutting Edge campaign (C0029)](/mitre/campaigns/C0029.md) attributes the December 2023 wave to suspected China-nexus espionage actors (Confirmed [22][32][161]; Inferred for the conclusion).
- **The flag counts.** In catalog version 2026.11.10, 361 of 1,779 entries carry "Known" ransomware use: Microsoft 117, Fortinet 14, SonicWall 13, Oracle 13, Ivanti 12, Adobe 11, VMware 9, Cisco 7 and Citrix 7 (Confirmed [32]). These counts were computed from the feed, and a recount from the same catalog version on 11 November 2026 gave the same totals (Demonstrated [32]).

## Part 6: targets by sector and geography

### Healthcare

Healthcare is the sector the government record names most often (Inferred). HHS's analysts tracked 730 attacks on the health sector worldwide in the six months to mid-March 2024, more than 530 in the US, nearly half of them ransomware. Their top ten groups were LockBit 3.0, ALPHV, BianLian, Akira, BlackSuit, Hunters International, Medusa, NoEscape, INC Ransom and Meow (Confirmed [86]). The FBI's 2023 report counted 249 ransomware complaints from health care, the most of any critical infrastructure sector (Confirmed [94]). HHS's 2025 HIPAA proposal says that from 2018 to 2023 ransomware in large-breach reports rose 264 percent, and that ransomware against US health care rose 128 percent from 2022 to 2023 (Confirmed [88]).

Advisories that name the health sector run from 2020 to 2026: TrickBot and Ryuk (AA20-302A), Maui (AA22-187A), Daixin (AA22-294A), Hive (AA22-321A), ALPHV after December 2023 (AA23-353A), Black Basta, which called health care an attractive target (AA24-131A), and Gunra, which lists health care first among its leak-site sectors (AA26-222A) (Confirmed [1][6][8][9][20][24][29]). HHS co-authored the Interlock advisory, though its targeting text is general (Confirmed [28]), and the SafePay advisory does not single out health care (Confirmed [30]). The actors that hit hospitals are profiled one by one in [Healthcare Threat Actor Watchlist, 2023 to 2026](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md).

| Date | Victim | What the primary record says | Source | Grade |
|---|---|---|---|---|
| 27 Sep 2020 | Universal Health Services | US IT applications suspended; about $67 million pre-tax impact; the filing does not name ransomware | [80] | Confirmed |
| 14 May 2021 | Ireland's Health Service Executive | Conti after about eight weeks inside; 80 percent of the environment encrypted | [83] | Confirmed |
| 4 Feb 2023 | Lehigh Valley Health Network | ALPHV attack affecting 248,359 people; $800,000 OCR settlement in October 2026 | [142] | Reported |
| 21 Feb 2024 | Change Healthcare | Ransomware after a login without MFA; first filing said "suspected nation-state" ([home study](/case-studies/CHANGE_HEALTHCARE_2024.md)) | [70][72] | Confirmed |
| 8 May 2024 | Ascension | Unauthorized activity; about 5.6 million notified; Black Basta attribution unconfirmed | [140] | Reported |
| 3 Jun 2024 | Synnovis (London NHS pathology) | Qilin; thousands of appointments and procedures postponed | [128] | Reported |
| 12 Apr 2025 | DaVita | Ransomware encrypted parts of the network; patient care continued | [75] | Confirmed |
| 20 May 2025 | Kettering Health | Incident it believes Interlock carried out; phones, scheduling and billing affected | [84] | Confirmed |
| 26 Oct 2026 | UNM Health | Ambulances diverted and outpatient surgeries suspended; Byod claimed 36,000 systems, an actor claim | [136] | Reported |

The regulatory response is mostly proposals. HHS's voluntary Healthcare and Public Health Cybersecurity Performance Goals set 10 essential goals (among them mitigating known vulnerabilities, email security, MFA and vendor requirements) and 10 enhanced goals (among them asset inventory, segmentation and centralized logging) (Confirmed [87]). The HIPAA Security Rule proposal of 6 January 2025 says regulated entities treat "addressable" specifications as optional (Confirmed [88]); final action is now expected no earlier than July 2027 (Reported [141]). HHS's Office for Civil Rights has used enforcement instead: the Lehigh Valley settlement was its 22nd ransomware action (Reported [142]). On 26 October 2026 the Office of the National Cyber Director and South Carolina launched Project Lifeline 250, a six-month no-cost pilot for rural hospitals covering network defense, physical backup devices after an incident and replacement of high-risk legacy devices (Confirmed [90]).

### Water and other critical infrastructure

The 2021 water advisory lists four ransomware incidents at water and wastewater systems: Ghost on three SCADA servers in California (August 2021), ZuCaNo reaching a wastewater SCADA computer through remote access in Maine, which then ran manually (July 2021), an unknown variant hitting SCADA and backups in Nevada (March 2021), and a potential Makop infection in New Jersey (September 2020) (Confirmed [3]). EPA's May 2024 alert found over 70 percent of drinking-water systems inspected since September 2023 violated basic Safe Drinking Water Act Section 1433 requirements for risk and resilience assessments and emergency response plans; the alert names state and hacktivist actors, not ransomware (Confirmed [89]). American Water's October 2024 filing reports unauthorized activity, believes no water or wastewater facilities were affected, and does not call it ransomware (Confirmed [79]). For the operational-technology record in water and energy, see [ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md).

The FBI's 2024 report calls ransomware the most pervasive threat to critical infrastructure, with complaints up 9 percent from 2023, and counts 4,878 complaints from critical infrastructure organizations (Confirmed [95]).

### Education and libraries

K-12 schools were 57 percent of ransomware incidents reported to MS-ISAC in August and September 2020, up from 28 percent from January to July; the top variants were Ryuk, Maze, Nefilim, AKO and Sodinokibi (Confirmed [2]). In September 2022 the agencies said Vice Society was disproportionately targeting education, especially K-12, with Hello Kitty/Five Hands and Zeppelin payloads (Confirmed [7]). Instructure paid an undisclosed ransom after its Canvas platform was breached in late April 2026; about 160 UK higher-education institutions were affected (Confirmed [103]). Vanderbilt University and Queens Public Library reported incidents in November 2026 (Reported [137][138]).

### Local and national government

The City of Dallas report is the most detailed local-government record: Royal inside for about four weeks, about 1.169 TB taken, 30,253 people notified (26,212 Texans), and $8.5 million approved for remediation (Confirmed [85]). Costa Rica is the national case: Conti claimed a wide-ranging attack during the 2022 presidential transition, and the government declared a public-sector emergency on 8 May 2022 (Confirmed [54]; Reported [124][126]). North Carolina and Florida bar their public bodies from paying (Confirmed [91][92]). The 2019 Texas municipal wave is in [The Year 2019 in Intrusions](/case-studies/CHRONICLE_2019.md).

### Business: supply-chain and single points of failure

- **Managed service providers.** The Kaseya VSA attack of 2 July 2021 reached about 50 of Kaseya's more than 35,000 customers and, through them, about 800 to 1,500 of the businesses they manage, by Kaseya's count (Confirmed [44]).
- **Auto dealers.** On 19 June 2024 CDK Global suspended systems after a cybersecurity incident; Sonic Automotive's dealer management system and CRM were disrupted and AutoNation's locations stayed open on manual processes. EDGAR lists nine 8-Ks citing CDK Global filed 21 to 26 June 2024 (Confirmed [73][74]).
- **Airports.** RTX reported a "product cybersecurity incident involving ransomware" on systems supporting MUSE passenger processing on 19 September 2025; airports moved to backup or manual processes, and RTX called it not material (Confirmed [76]).
- **Retail and manufacturing.** The Cyber Monitoring Centre treated the April 2025 incidents at Marks & Spencer and Co-op as one Category 2 systemic event estimated at £270 to £440 million, noting one actor claimed both (Confirmed [101]). It rated Jaguar Land Rover Category 3 at £1.9 billion (Confirmed [102]).
- **Casinos and finance.** MGM estimated about $100 million in lost Adjusted Property EBITDAR (Confirmed [77]); LockBit's ICBC attack affected settlement of over $9 billion in Treasury-backed assets (Confirmed [48]).
- **Hosting.** In October 2026 GMO found an intrusion in its Onamae Desktop Cloud that may have planted malware on up to 26,739 customer servers, and refused a demand of about ¥8 billion (Reported [135]).
- **SaaS supply chain.** Coveware describes the June 2026 compromise of the Klue SaaS platform by the Icarus group (Reported [113]).

### Geography

The law-enforcement actions in this record involve agencies in the US, the UK, Australia, Germany, Ukraine, Poland, France, Spain, Ireland, Lithuania, Canada and Greece (Confirmed [49][57][61][66][67]; Reported [118][122]). The victims named in this study are in the US, the UK, Ireland, Costa Rica and Japan (Confirmed [83][54][101]; Reported [132][135]). Ghost alone reached more than 70 countries and Hive more than 80 (Confirmed [26][64]).

## Part 7: the government record

### Sanctions, indictments and rewards

| Date | Action | Who | Source | Grade |
|---|---|---|---|---|
| 21 Sep 2021 | OFAC updated advisory on paying ransoms; designation of the SUEX OTC exchange | Facilitators and payers | [52][53] | Confirmed |
| 8 Nov 2021 | Indictment unsealed; $6.1 million seized | Yaroslav Vasinskyi (Kaseya attack); Yevgeniy Polyanin (funds) | [63] | Confirmed |
| 6 May 2022 | Rewards: up to $10 million for leaders, $5 million for participants | Conti | [54] | Confirmed |
| 11 Aug 2022 | Second $10 million reward | Five named Conti associates | [125] | Reported |
| 9 Feb 2023 | Joint US and UK sanctions, the UK's first of this kind (OFAC with the FCDO, NCA and HM Treasury) | Seven Trickbot members | [45] | Confirmed |
| 16 May 2023 | Sanctions; indictments in New Jersey and Washington, DC; up to $10 million reward | Mikhail Matveev (Hive, LockBit, Babuk) | [47] | Confirmed |
| 7 Sep 2023 | Joint US and UK sanctions; indictments against nine defendants, seven designated that day | Eleven Trickbot members; Trickbot and Conti defendants | [46] | Confirmed |
| 8 Feb 2024 | Rewards: up to $10 million for leaders, $5 million for participants | Hive | [55] | Confirmed |
| 20 Feb 2024 | Sanctions, the first action with DOJ, FBI and partners against LockBit | Ivan Kondratiev (leader of the affiliate sub-group National Hazard Society, with ties to REvil, RansomEXX and Avaddon) and Artur Sungatov | [48] | Confirmed |
| 7 May 2024 | US, UK and Australian sanctions; indictment; up to $10 million reward | Dmitry Khoroshev, LockBitSupp | [49][56] | Confirmed |
| 11 Feb 2025 | US, Australian and UK sanctions | Zservers and two administrators | [50] | Confirmed |
| 1 Jul 2025 | Sanctions | Aeza Group, two affiliates, four leaders and a UK front company | [51] | Confirmed |
| 18 Sep 2025 | Charges | Thalha Jubair and Owen Flowers (TfL, SSM Health Care, Sutter Health) | [59] | Confirmed |
| 4 Nov 2025 | Indictment, Southern District of Florida | A former ransomware negotiator and a former incident-response manager | [119] | Reported |
| 16 Jul 2026 | Sentences of five years six months each | Jubair and Flowers | [60] | Confirmed |
| 8 Oct 2026 | Arrest on extortion and conspiracy charges in the ShinyHunters ([G1057](/mitre/groups/G1057.md)) investigation | A ransomware-negotiation executive | [123] | Reported |
| 27 Oct 2026 | Sentence of 70 months | Artem Stryzhak (Nefilim, Hive) | [121] | Reported |

Avaddon has an ATT&CK software entry, [S0640](/mitre/software/S0640.md) (Confirmed [161]).

### Disruptions and takedowns

- **Hive, 26 January 2023.** The FBI was inside the network from late July 2022, gave over 300 keys to victims under attack and over 1,000 to earlier victims, and averted about $130 million in demands (Confirmed [64]). FBI Director Wray said only about 20 percent of Hive's victims had reported to law enforcement; one other outlet reported 40 percent (Reported [144]).
- **ALPHV, 19 December 2023.** A decryption tool for over 500 victims, about $68 million in demands avoided, several sites seized (Confirmed [65]). The brand came back, urged attacks on hospitals and then vanished in March 2024 (Confirmed [20]; Reported [127]).
- **LockBit, Operation Cronos, from 20 February 2024.** The NCA, working with the FBI and partners from nine other countries, took control of LockBit's primary admin environment and leak site and obtained its source code. Stealbit infrastructure in three countries was seized, 28 affiliate servers taken down, two people arrested in Poland and Ukraine, more than 200 crypto accounts frozen and more than 1,000 decryption keys obtained (Confirmed [57]). The NCA replaced the leak site with posts exposing the operation, then took it down (Confirmed [58]). Data on LockBit's systems included data from victims who had paid (Confirmed [57]). A second phase on 7 May 2024 unmasked LockBitSupp (Confirmed [56]); a third in October 2024 brought four arrests by France, the UK and Spain and sanctions against affiliates, by Europol's title for it (Confirmed [66]). By May 2024 active affiliates had fallen to 69 and UK monthly LockBit attacks were down 73 percent (Confirmed [56]); Chainalysis put LockBit's second-half 2024 payments down about 79 percent (Reported [105]).
- **Operation Endgame, from May 2024.** The first phase, announced 30 May 2024, dismantled botnets including IcedID, SystemBC, Pikabot, Smokeloader and Bumblebee, with four arrests and over 100 servers taken down (Confirmed [67]). Endgame 2.0, 19 to 22 May 2025, identified 37 suspects, obtained 20 arrest warrants, took down over 300 servers and seized €3.5 million, against Bumblebee, Latrodectus, Qakbot, DanaBot, HijackLoader, Trickbot and WarmCookie (Confirmed [69]). On 10 to 13 November 2025 it took down 1,025 servers across Rhadamanthys, VenomRAT and Elysium (Confirmed [67]). Season 3, announced 24 June 2026, targeted SocGholish, Amadey and StealC, actioned 326 servers and restricted over €41 million in crypto assets (Confirmed [68]). Several of these loaders have ATT&CK entries: [IcedID (S0483)](/mitre/software/S0483.md), [SystemBC (S9001)](/mitre/software/S9001.md), [Pikabot (S1145)](/mitre/software/S1145.md), [Bumblebee (S1039)](/mitre/software/S1039.md), [Latrodectus (S1160)](/mitre/software/S1160.md), [QakBot (S0650)](/mitre/software/S0650.md), [TrickBot (S0266)](/mitre/software/S0266.md), [SocGholish (S1124)](/mitre/software/S1124.md) and [Amadey (S1025)](/mitre/software/S1025.md) (Confirmed [161]).
- **BlackSuit, Operation Checkmate, 7 August 2025.** Infrastructure taken down through a Europol J-CAT initiative (Confirmed [61]).
- **KillSec, Operation KillSwitch, 30 September 2026.** Led by the Hamburg state police with Europol and Eurojust support: the leak site and at least 110 TB of data secured, three provisional arrests (Reported [133][122]).

The record shows disruption working and not ending the trade. LockBit kept posting victims after Cronos, up to 68 percent of them repeat or fabricated by the analysts Chainalysis quotes (Reported [105]), and ALPHV came back after the December 2023 action before vanishing in March 2024 (Confirmed [20]; Reported [127]). The NCA's own figures show a sharp drop in LockBit attacks without an end to them (Confirmed [56]).

### Reporting and payment rules

| Jurisdiction | Rule | Status on 11 Nov 2026 | Source | Grade |
|---|---|---|---|---|
| US federal (OFAC) | Paying a sanctioned party risks a violation; offline backups, IR plans, training, authentication and prompt reporting are mitigating factors; the government strongly discourages paying | In force since 21 Sep 2021 | [53] | Confirmed |
| US federal (CIRCIA) | 72-hour reporting of covered incidents and 24-hour reporting of ransom payments | Enacted March 2022; proposed rule 4 Apr 2024; final rule at OIRA since 1 Oct 2026; reporting not yet required; the October 2025 statutory deadline was missed | [36][34][37][129] | Confirmed; Reported for the missed deadline |
| US federal (SEC) | Form 8-K Item 1.05: material incidents disclosed within four business days of the materiality determination | Compliance from 18 Dec 2023 | [81] | Confirmed |
| US federal (HIPAA) | Security Rule overhaul | Proposed 6 Jan 2025; final action no earlier than July 2027 | [88][141] | Confirmed; Reported for the date |
| North Carolina | State agencies and local governments may not pay or communicate with a ransomware actor; must consult NCDIT | In force (S.L. 2021-180) | [91] | Confirmed |
| Florida | State agencies, counties and municipalities may not pay | In force (ch. 2022-220) | [92] | Confirmed |
| United Kingdom | Targeted payment ban for the public sector and regulated critical national infrastructure; payment prevention regime; mandatory reporting | Government response 22 Jul 2025; 72 percent of 273 respondents backed the targeted ban; legislation not yet in place | [93] | Confirmed |
| Australia | Ransomware payment reporting within 72 hours (Cyber Security Act 2024, Part 3) | In effect from 30 May 2025 | [130] | Reported |
| Lloyd's market | State-backed cyber-attack exclusion in standalone cyber policies | Required from 31 Mar 2023 | [99] | Confirmed |

## Part 8: the money

### Payment totals

Two series dominate, and they measure different things (Inferred from [96][106]).

| Year | FinCEN (US Bank Secrecy Act reports) | Chainalysis (on-chain, as first and later reported) | Source |
|---|---|---|---|
| 2022 | Median payment $124,097 | $567 million (revised in the Feb 2024 report) | [96][104] |
| 2023 | 1,512 incidents, about $1.1 billion (+77 percent); median $175,000 | Over $1 billion (Feb 2024); $1.25 billion (Feb 2025) | [96][104][105] |
| 2024 | 1,476 incidents, about $734 million; median $155,257 | About $813.55 million (Feb 2025); $892 million (Feb 2026) | [96][105][106] |
| 2025 | not covered | More than $820 million, expected to approach or exceed $900 million (Feb 2026) | [106] |

FinCEN's figures come from financial institutions' reports and include attempted transactions; for 2022 to 2024 it counts 7,395 reports on 4,194 incidents and more than $2.1 billion, against about $2.4 billion for 2013 to 2021 (Confirmed [96]). Chainalysis counts what it can attribute on chain, and its totals rise as more payments are attributed: its 2024 figure went from $813.55 million to $892 million in a year (Reported [105][106]; Inferred for the pattern). Compare a first estimate with a first estimate, and cite the report date with every figure (Inferred from [104][105][106]).

FinCEN's variant table for 2022 to 2024 ranks ten variants by incidents: Akira first (376, about $120.9 million), then ALPHV/BlackCat (353, about $395.3 million), LockBit (353, about $252.4 million), Phobos (202, about $13.3 million), Black Basta (171, about $137.7 million), Medusa (120, about $23.5 million) and BianLian (119, about $39.3 million), followed by Royal, BlackSuit and Hive. By amount paid, the top industries were financial services (about $365.6 million), health care (about $305.4 million) and manufacturing (about $284.6 million) (Confirmed [96]).

### Who pays, and how much

| Period | Payment rate | Average | Median | Source | Grade |
|---|---|---|---|---|---|
| Q1 2024 | 28 percent, a record low at the time | | | [107] | Reported |
| Q4 2024 | 25 percent, an all-time low at the time; 41 percent of exfiltration-only victims paid | $553,959 | $110,890 | [108] | Reported |
| Q3 2025 | 23 percent (19 percent for exfiltration-only) | $376,941 | $140,000 | [110] | Reported |
| Q4 2025 | About 20 percent, a new low | $591,988 | $325,000 | [111] | Reported |
| Q1 2026 | 23 percent | $680,081 | $300,750 | [112] | Reported |
| Q2 2026 | A new record low; exfiltration-only rate 15 percent | $1,880,612 (+176 percent) | $150,000 (-50 percent) | [113] | Reported |
| Q3 2026 | Up slightly, near historic lows; nearly 80 percent of exfiltration-only incidents resolved without payment | $1,025,278 (-45 percent) | $400,000 (+167 percent) | [114] | Reported |

All rows are Coveware's figures from its own case data. Other measures point the same way. Chainalysis says the share of ransoms paid may have fallen to 28 percent in 2025 while the median payment rose 368 percent to $59,556 and claimed victims rose 50 percent (Reported [106]). Verizon's 2025 report finds 64 percent of victims did not pay, up from 50 percent two years earlier, with a median payment of $115,000 (Reported [117]). The NAIC's 2026 report cites industry data that a record 86 percent of businesses hit refused to pay (Reported [100]).

Initial access brokers received at least $14 million in 2025, per Chainalysis (Reported [106]).

### Losses that are not ransoms

Where both figures are public, the ransom is the smaller number (Inferred). The FBI's 2024 report records $12,473,156 in reported ransomware losses from 3,156 complaints, and IC3 itself calls the resulting loss rate artificially low because the figure excludes lost business, time and remediation (Confirmed [95]). Sophos's 2024 survey put average recovery cost, excluding ransom, at $2.73 million (Reported [115]). The Jaguar Land Rover estimate of £1.9 billion, the M&S and Co-op range of £270 to £440 million, MGM's $100 million and Dallas's $8.5 million remediation budget are all costs of disruption (Confirmed [102][101][77][85]).

### Insurance

GAO found in 2021 that one broker's clients' take-up of cyber insurance rose from 26 percent in 2016 to 47 percent in 2020, that more than half saw prices rise 10 to 30 percent in late 2020, and that insurers cut limits for sectors such as health care and education (Confirmed [97]). In 2022 GAO found insurers limiting systemic exposure by excluding cyber warfare and infrastructure outages (Confirmed [98]). Lloyd's required state-backed attack exclusions from March 2023 (Confirmed [99]). The NAIC's 2026 report puts US cyber direct written premium at about $9.46 billion in 2025, up 3.5 percent after 2024's first-ever contraction, with a 2025 loss ratio of 53, the highest since the pandemic-era ransomware spike, during eight straight quarters of rate cuts (Confirmed [100]). OFAC lists cyber insurers among the facilitators who may face sanctions risk (Confirmed [53]).

## Part 9: the defender view

### The controls the record keeps naming

1. **MFA on every remote-access path, phishing-resistant where possible.** It is the most repeated finding: Akira, Rhysida, Daixin and Change Healthcare came in through remote access without MFA, and Colonial through a legacy VPN profile not meant to be in use; its CEO's testimony does not address MFA (Confirmed [23][16][8][70][71]). The joint guide asks for phishing-resistant MFA for all services and MFA on all VPN connections (Confirmed [31]); the Scattered Spider advisory names FIDO/WebAuthn or PKI-based MFA (Confirmed [17]). Citrix Bleed is the caveat: a stolen session bypasses MFA, so patching and session termination matter as much (Confirmed [18]).
2. **Offline, encrypted, immutable, tested backups.** The joint guide and the BlackSuit advisory both ask for them (Confirmed [31][11]). Sophos's survey shows why: criminals tried to compromise backups in 94 percent of attacks (Reported [115]). Backups do nothing against theft-only extortion (Confirmed [14]; Inferred for the general point).
3. **Patch the edge on the KEV clock.** CISA advised patching internet-facing KEV entries within 24 to 48 hours (Confirmed [18]). Verizon found only about 54 percent of edge vulnerabilities fully remediated during the year, at a median of 32 days (Reported [117]).
4. **Managed devices and EDR everywhere.** Microsoft found over 90 percent of attacks that reached the ransom stage used unmanaged devices for initial access or remote encryption, and that attacks reaching encryption fell threefold over two years with automatic attack disruption (Reported [116]). The joint guide asks for application allowlisting or EDR (Confirmed [31]).
5. **Segmentation, including IT from OT.** The joint guide asks for it (Confirmed [31]). Colonial's precautionary shutdown shows the cost of not knowing what depends on what (Confirmed [71]; Inferred for the lesson).
6. **Help-desk identity checks and allowlisted remote-access tools.** The Scattered Spider advisory recommends allowlisting remote-access tools (Confirmed [17]); the help-desk and Teams pretexts in Part 4 are the reason (Confirmed [17][24]).
7. **Restrict RDP, scripting and PowerShell, and keep logs.** BianLian's advisory puts these first and asks for 180 days of logs (Confirmed [13]).

### The vulnerability-management view

The KEV catalog's ransomware flag is the field that most directly connects a CVE to ransomware use. In catalog version 2026.11.10, 361 of 1,779 entries carry it, and the edge and file-transfer CVEs at the center of the Akira, LockBit, CL0P and Black Basta advisories (CVE-2023-4966, CVE-2023-20269, CVE-2020-3259, CVE-2024-40766, CVE-2023-34362, CVE-2019-19781, CVE-2018-13379, CVE-2024-1709 and CVE-2023-0669) are all flagged (Confirmed [32]). Three practical rules follow from the record (Inferred from [22][32][40][117]):

- **Treat a ransomware-flagged KEV entry on an internet-facing device as an emergency.** The Ivanti entries show that the flag can be the only public sign of ransomware use (Confirmed [22][32]).
- **Do not rely on KEV alone.** CVE-2021-21974, tied to ESXiArgs in secondary reporting, is not in the catalog (Confirmed [40]).
- **After patching an edge device, rotate its credentials and check for persistence.** Credentials harvested from devices still unpatched against the May 2019 FortiOS fix were disclosed in September 2021 (Confirmed [42]), and the joint Ivanti advisory found the vendor's integrity checker unreliable and showed root persistence surviving a factory reset in a lab (Confirmed [22]).

The library's [Edge Device Security](/EDGE_DEVICE_SECURITY_REFERENCE.md) and [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md) references carry the controls.

### Disclosure and early warning

Early disclosures get revised. UnitedHealth's first 8-K described a "suspected nation-state associated" actor; testimony later attributed the attack to the criminal ALPHV (Confirmed [72][70]). An EDGAR full-text search of 8-Ks from 18 December 2023 to 10 November 2026 returns 2,381 hits for "ransomware", but only a handful of the first 400 carry Item 1.05, so Item 1.05 filings are a small, self-selected slice of incidents (Demonstrated [82]). Several victims' filings do not use the word ransomware (Confirmed [79][80]). CISA's pre-ransomware notification initiative sent 2,131 notifications in 2024 and 3,368 since it began; no public data says what they prevented (Reported [35]).

### Paying

The OFAC advisory strongly discourages payment (Confirmed [53]). The record gives defenders three reasons beyond law. LockBit did not routinely delete stolen data after payment (Confirmed [56]). Caesars could not guarantee the stolen data had been deleted (Confirmed [78]). One Medusa victim who had paid received a second demand from another actor, which the advisory calls possible triple extortion or internal dysfunction (Confirmed [27]). Coveware's Q3 2026 report says nearly 80 percent of exfiltration-only incidents were resolved without payment (Reported [114]).

### Where to start

- [Respond to a Ransomware Incident](/guides/RESPOND_TO_RANSOMWARE.md) and [Run a Ransomware Tabletop Exercise](/guides/RUN_A_RANSOMWARE_TABLETOP.md) for the first steps and the rehearsal.
- [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md) for the control set.
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) for the response plan.
- [Identity Security](/IDENTITY_SECURITY_REFERENCE.md) and [Identity and Access Management](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) for MFA and help-desk processes.
- [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md) and [ICS and OT Security](/ICS_OT_SECURITY_REFERENCE.md) for the two sectors the record names most.

## Part 10: MITRE mappings

This Part binds the verified record to MITRE ATT&CK v20.0, CAPEC, CWE and D3FEND. Every id was checked on 11 November 2026 against the live ATT&CK site or the library's data files (Confirmed [145] to [161]). Tactics are those of the library's technique profiles for v20.0. "Printed" means an opened source prints the id; "assigned" means the source describes the behavior and this study chose the id.

### ATT&CK Enterprise techniques

| Id | Name | Tactic (v20.0) | Where it appears in the record | Source | Grade |
|---|---|---|---|---|---|
| [T1598](/mitre/techniques/T1598.md) | Phishing for Information | Reconnaissance | ALPHV affiliates pose as IT staff to obtain credentials (AA23-353A, Dec 2023) | [20] | Confirmed (printed in [20]) |
| [T1598.002](/mitre/techniques/T1598-002.md) | Spearphishing Attachment | Reconnaissance | Daixin Team (AA22-294A, Oct 2022) | [8] | Confirmed (printed) |
| [T1189](/mitre/techniques/T1189.md) | Drive-by Compromise | Initial Access | Interlock (AA25-203A, Jul 2025) | [28] | Confirmed (printed) |
| [T1190](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | Initial Access | Daixin (Oct 2022); Black Basta and ScreenConnect (May 2024); also MOVEit, Citrix Bleed, FortiOS and the CVEs of Part 5 | [8][24][14][18][29] | Confirmed (printed in [8][24]) |
| [T1133](/mitre/techniques/T1133.md) | External Remote Services | Persistence, Initial Access | VPNs without MFA: Akira (2024 to 2025), Rhysida, Change Healthcare's Citrix portal (Feb 2024); Colonial's legacy VPN profile (May 2021) | [71][23][16][70][29] | Confirmed (printed in [23][29]) |
| [T1078](/mitre/techniques/T1078.md) | Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Daixin (Oct 2022); Black Basta (May 2024) | [8][24] | Confirmed (printed) |
| [T1199](/mitre/techniques/T1199.md) | Trusted Relationship | Initial Access | Kaseya VSA reached customers through their managed service providers (Jul 2021); MSP targeting (AA22-040A) | [44][5] | Inferred (assigned) |
| [T1566](/mitre/techniques/T1566.md) | Phishing | Initial Access | Black Basta (AA24-131A); a top vector of 2021 (AA22-040A); HSE (Mar 2021) | [24][5][83] | Confirmed (printed in [24]) |
| [T1566.004](/mitre/techniques/T1566-004.md) | Spearphishing Voice | Initial Access | Black Basta tech-support calls (AA24-131A, Nov 2024 update); Scattered Spider help-desk calls | [24][17] | Confirmed (printed in [24]) |
| [T1059.001](/mitre/techniques/T1059-001.md) | PowerShell | Execution | Black Basta (AA24-131A) | [24] | Confirmed (printed) |
| [T1059.003](/mitre/techniques/T1059-003.md) | Windows Command Shell | Execution | TrickBot and Ryuk (AA20-302A, Oct 2020) | [1] | Confirmed (printed) |
| [T1059.008](/mitre/techniques/T1059-008.md) | Network Device CLI | Execution | Maui (AA22-187A, Jul 2022), as printed | [6] | Confirmed (printed) |
| [T1106](/mitre/techniques/T1106.md) | Native API | Execution | AA20-302A | [1] | Confirmed (printed) |
| [T1204](/mitre/techniques/T1204.md) | User Execution | Execution | Black Basta (AA24-131A) | [24] | Confirmed (printed) |
| [T1204.004](/mitre/techniques/T1204-004.md) | Malicious Copy and Paste | Execution | Interlock ClickFix-style lures (AA25-203A) | [28] | Confirmed (printed) |
| [T1547.001](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | AA20-302A, printed as "T1047.001" with a link to T1547.001 | [1] | Confirmed (printed) |
| [T1098](/mitre/techniques/T1098.md) | Account Manipulation | Persistence, Privilege Escalation | Daixin (AA22-294A); Gunra's rogue FortiOS super-user (AA26-222A) | [8][29] | Confirmed (printed in [8]) |
| [T1505.003](/mitre/techniques/T1505-003.md) | Web Shell | Persistence | LEMURLOOT on MOVEit servers (from 27 May 2023) | [14] | Confirmed (printed in [14]) |
| [T1068](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | Black Basta (AA24-131A) | [24] | Confirmed (printed) |
| [T1055](/mitre/techniques/T1055.md) | Process Injection | Stealth, Privilege Escalation | AA20-302A | [1] | Confirmed (printed) |
| [T1134](/mitre/techniques/T1134.md) | Access Token Manipulation | Stealth, Privilege Escalation | AA20-302A | [1] | Confirmed (printed) |
| [T1036](/mitre/techniques/T1036.md) | Masquerading | Stealth | Black Basta (AA24-131A) | [24] | Confirmed (printed) |
| [T1036.005](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | Stealth | AA20-302A | [1] | Confirmed (printed) |
| [T1684.001](/mitre/techniques/T1684-001.md) | Impersonation | Stealth | Scattered Spider (AA23-320A), printed as revoked T1656 | [17][160][161] | Confirmed (printed id, successor from the library) |
| [T1685](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | Printed as revoked T1562.001 in AA20-302A and AA24-131A; as T1685 in the Gunra and SafePay advisories (2026) | [1][24][29][30][160] | Confirmed |
| [T1685.005](/mitre/techniques/T1685-005.md) | Clear Windows Event Logs | Defense Impairment | Advisory id T1070.001, revoked and mapped here by the library | [160][161] | Confirmed (successor mapping) |
| [T1686](/mitre/techniques/T1686.md) | Disable or Modify System Firewall | Defense Impairment | Advisory id T1562.004, revoked and mapped here by the library | [160][161] | Confirmed (successor mapping) |
| [T1556.006](/mitre/techniques/T1556-006.md) | Multi-Factor Authentication | Defense Impairment, Persistence, Credential Access | Citrix Bleed session hijacking bypasses MFA (AA23-325A, Nov 2023) | [18] | Confirmed (printed) |
| [T1003](/mitre/techniques/T1003.md) | OS Credential Dumping | Credential Access | Daixin (AA22-294A) | [8] | Confirmed (printed) |
| [T1110](/mitre/techniques/T1110.md) | Brute Force | Credential Access | Brute-forced RDP credentials (AA22-040A); SafePay (AA26-293A) | [5][30] | Confirmed (printed in [30]) |
| [T1539](/mitre/techniques/T1539.md) | Steal Web Session Cookie | Credential Access | Citrix Bleed (AA23-325A) | [18] | Confirmed (printed) |
| [T1557](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | Credential Access, Collection | ALPHV affiliates capture MFA codes and session cookies (AA23-353A) | [20] | Confirmed (printed in [20]) |
| [T1621](/mitre/techniques/T1621.md) | Multi-Factor Authentication Request Generation | Credential Access | Scattered Spider MFA fatigue (AA23-320A) | [17] | Confirmed (printed) |
| [T1016](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | AA20-302A | [1] | Confirmed (printed) |
| [T1057](/mitre/techniques/T1057.md) | Process Discovery | Discovery | AA20-302A | [1] | Confirmed (printed) |
| [T1082](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | AA23-325A | [18] | Confirmed (printed) |
| [T1083](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | AA20-302A | [1] | Confirmed (printed) |
| [T1550.002](/mitre/techniques/T1550-002.md) | Pass the Hash | Lateral Movement | Daixin (AA22-294A) | [8] | Confirmed (printed) |
| [T1563](/mitre/techniques/T1563.md) | Remote Service Session Hijacking | Lateral Movement | Citrix Bleed (AA23-325A text) | [18] | Confirmed (printed) |
| [T1563.001](/mitre/techniques/T1563-001.md) | SSH Hijacking | Lateral Movement | Daixin (AA22-294A) | [8] | Confirmed (printed) |
| [T1563.002](/mitre/techniques/T1563-002.md) | RDP Hijacking | Lateral Movement | Daixin (AA22-294A) | [8] | Confirmed (printed) |
| [T1560.001](/mitre/techniques/T1560-001.md) | Archive via Utility | Collection | SafePay archives with 7-Zip and WinRAR before exfiltration (AA26-293A) | [30] | Confirmed (printed in [30]) |
| [T1530](/mitre/techniques/T1530.md) | Data from Cloud Storage | Collection | Scattered Spider bulk pulls from Snowflake (2025 update); Gunra from OneDrive (2026) | [17][29] | Confirmed (printed in [17][29]) |
| [T1213.002](/mitre/techniques/T1213-002.md) | Sharepoint | Collection | Gunra pulled data from SharePoint (AA26-222A) | [29] | Inferred (assigned) |
| [T1219](/mitre/techniques/T1219.md) | Remote Access Tools | Command and Control | AnyDesk and Quick Assist (Black Basta); RMM products (Medusa); legitimate remote-management tools at Dallas (2023); recurring across advisories | [24][27][85] | Confirmed (printed in [27]) |
| [T1567](/mitre/techniques/T1567.md) | Exfiltration Over Web Service | Exfiltration | Daixin (AA22-294A) | [8] | Confirmed (printed) |
| [T1567.002](/mitre/techniques/T1567-002.md) | Exfiltration to Cloud Storage | Exfiltration | RClone to Mega (Gunra) and to OneDrive or Backblaze (SafePay); RClone by Black Basta | [29][30][24] | Inferred (assigned) |
| [T1486](/mitre/techniques/T1486.md) | Data Encrypted for Impact | Impact | AA20-302A; Maui (AA22-187A); Daixin; Black Basta; every encrypting advisory in this study | [1][6][8][24] | Confirmed (printed) |
| [T1490](/mitre/techniques/T1490.md) | Inhibit System Recovery | Impact | AA20-302A; Black Basta (AA24-131A); backup targeting in 94 percent of surveyed attacks | [1][24][115] | Confirmed (printed in [1][24]) |
| [T1489](/mitre/techniques/T1489.md) | Service Stop | Impact | AA20-302A | [1] | Confirmed (printed) |
| [T1529](/mitre/techniques/T1529.md) | System Shutdown/Reboot | Impact | Play's ESXi variant powers off virtual machines before encrypting (AA23-352A) | [19] | Inferred (assigned) |
| [T1657](/mitre/techniques/T1657.md) | Financial Theft | Impact | Demands backed by leak threats and leak sites (ATT&CK's own scope); Black Basta, RansomHub and Medusa leak-site deadlines | [159][24][25][27] | Confirmed |

Steps the record describes but this study does not bind:

- **SIM swapping** by Scattered Spider is an ATT&CK for Mobile technique and is outside the Enterprise table (Confirmed [17]; Inferred for the domain).
- **Hypervisor encryption** (Sphynx, Play, Interlock, DragonForce) is covered by T1486 above; no opened source prints an ESXi-specific technique id for these brands (Inferred from [17][19][20][28]).
- **Exfiltration by StealBit** is a named tool, not a technique; it is listed with the software below.

### ATT&CK for ICS techniques

The record touches industrial systems only through IT-side ransomware that stopped operations. These rows are this study's assignments.

| Id | Name | Tactic | Where it appears in the record | Source | Grade |
|---|---|---|---|---|---|
| [T0828](https://attack.mitre.org/techniques/T0828/) | Loss of Productivity and Revenue | Impact | Colonial Pipeline halted pipeline operations as a precaution after ransomware on its IT network, 7 May 2021 | [71][62] | Inferred (assigned) |
| [T0826](https://attack.mitre.org/techniques/T0826/) | Loss of Availability | Impact | Ransomware encrypted SCADA servers at California (Aug 2021) and Nevada (Mar 2021) water systems | [3] | Inferred (assigned) |
| [T0822](https://attack.mitre.org/techniques/T0822/) | External Remote Services | Initial Access | ZuCaNo reached a Maine wastewater SCADA computer through remote access (Jul 2021) | [3] | Inferred (assigned) |

The names and tactics match `data/attack/ics/technique_profiles.jsonl` (Confirmed [161]). The library's [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md) covers the ICS matrix.

### ATT&CK groups, software and campaigns

| Object | Id | Role in the record | Source |
|---|---|---|---|
| [Wizard Spider](/mitre/groups/G0102.md) | G0102 | TrickBot, Ryuk and Conti operators | [145] |
| [TA505](/mitre/groups/G0092.md) | G0092 | CL0P's operators | [150] |
| [GOLD SOUTHFIELD](/mitre/groups/G0115.md) | G0115 | REvil's operators | [157] |
| [Indrik Spider](/mitre/groups/G0119.md) | G0119 | Alias Manatee Tempest, named by Microsoft for ESXi CVE-2024-37085 | [43][161] |
| [Scattered Spider](/mitre/groups/G1015.md) | G1015 | Help-desk social engineering; DragonForce deployments | [155] |
| [Cinnamon Tempest](/mitre/groups/G1021.md) | G1021 | RaaS-era actor listed by ATT&CK | [157] |
| [Akira](/mitre/groups/G1024.md) | G1024 | Akira operators | [151] |
| [INC Ransom](/mitre/groups/G1032.md) | G1032 | INC operators; PAN-OS exploitation in 2026 | [157][134] |
| [Play](/mitre/groups/G1040.md) | G1040 | Play operators | [153] |
| [BlackByte](/mitre/groups/G1043.md) | G1043 | RaaS-era actor listed by ATT&CK | [157] |
| [Storm-1811](/mitre/groups/G1046.md) | G1046 | Linked to Black Basta deployment | [146] |
| [Water Galura](/mitre/groups/G1050.md) | G1050 | Qilin's operators | [156] |
| [Medusa Group](/mitre/groups/G1051.md) | G1051 | Medusa operators | [154] |
| [Storm-0501](/mitre/groups/G1053.md) | G1053 | RaaS-era actor listed by ATT&CK | [157] |
| [ShinyHunters](/mitre/groups/G1057.md) | G1057 | Subject of the FBI investigation in which a negotiation executive was arrested | [123] |
| [FIN6](/mitre/groups/G0037.md), [FIN7](/mitre/groups/G0046.md) | G0037, G0046 | Associated with Maze by ATT&CK | [158][161] |
| [Ryuk](/mitre/software/S0446.md) | S0446 | 2020 hospital wave | [1][145] |
| [Conti](/mitre/software/S0575.md) | S0575 | Wizard Spider's RaaS | [4][145] |
| [TrickBot](/mitre/software/S0266.md) | S0266 | Loader; sanctions 2023; Endgame 2.0 | [1][45][69] |
| [Bazar](/mitre/software/S0534.md) | S0534 | Loader in C0015 | [145] |
| [IcedID](/mitre/software/S0483.md) | S0483 | Conti delivery; Endgame 2024 | [4][67] |
| [REvil](/mitre/software/S0496.md) | S0496 | Kaseya attack, July 2021 | [63][157] |
| [Maze](/mitre/software/S0449.md) | S0449 | Data theft and posting to extort; discovered May 2019 | [158] |
| [Babuk](/mitre/software/S0638.md) | S0638 | Matveev sanctions | [47][161] |
| [Avaddon](/mitre/software/S0640.md) | S0640 | Kondratiev's ties | [48][161] |
| [LockerGoga](/mitre/software/S0372.md), [MegaCortex](/mitre/software/S0576.md) | S0372, S0576 | Tymoshchuk accusations | [121][161] |
| [HELLOKITTY](/mitre/software/S0617.md) | S0617 | Vice Society payload (Hello Kitty/Five Hands) | [7][161] |
| [Clop](/mitre/software/S0611.md) | S0611 | File-transfer campaigns | [14][150] |
| [LockBit 2.0](/mitre/software/S1199.md) | S1199 | LockBit | [148] |
| [LockBit 3.0](/mitre/software/S1202.md) | S1202 | LockBit Black | [12][148] |
| [StealBit](/mitre/software/S1200.md) | S1200 | LockBit's exfiltration tool | [15][161] |
| [BlackCat](/mitre/software/S1068.md) | S1068 | ALPHV, Noberus | [20][149] |
| [Black Basta](/mitre/software/S1070.md) | S1070 | Black Basta | [24][146] |
| [Royal](/mitre/software/S1073.md) | S1073 | Royal, predecessor of BlackSuit | [11][147] |
| [Akira](/mitre/software/S1129.md), [Akira _v2](/mitre/software/S1194.md) | S1129, S1194 | Akira encryptors | [151] |
| [Playcrypt](/mitre/software/S1162.md) | S1162 | Play | [153] |
| [RansomHub](/mitre/software/S1212.md) | S1212 | RansomHub | [25][152] |
| [Medusa Ransomware](/mitre/software/S1244.md) | S1244 | Medusa (not S1220) | [154] |
| [Qilin](/mitre/software/S1242.md) | S1242 | Qilin, Agenda | [156] |
| [INC Ransomware](/mitre/software/S1139.md) | S1139 | INC | [157] |
| [Embargo](/mitre/software/S1247.md) | S1247 | RaaS-era software listed by ATT&CK | [157] |
| [AvosLocker](/mitre/software/S1053.md) | S1053 | On CISA's list; campaign C0018 | [7][161] |
| [AdFind](/mitre/software/S0552.md), [BloodHound](/mitre/software/S0521.md), [Impacket](/mitre/software/S0357.md), [Mimikatz](/mitre/software/S0002.md), [PsExec](/mitre/software/S0029.md), [Rclone](/mitre/software/S1040.md), [ConnectWise](/mitre/software/S0591.md) | S0552, S0521, S0357, S0002, S0029, S1040, S0591 | Dual-use tools in the LockBit advisory | [15][161] |
| [SystemBC](/mitre/software/S9001.md), [Pikabot](/mitre/software/S1145.md), [Bumblebee](/mitre/software/S1039.md), [Latrodectus](/mitre/software/S1160.md), [QakBot](/mitre/software/S0650.md), [SocGholish](/mitre/software/S1124.md), [Amadey](/mitre/software/S1025.md) | S9001, S1145, S1039, S1160, S0650, S1124, S1025 | Operation Endgame targets (Eurojust spells Latrodectus "Lactrodectus") | [67][68][69][161] |
| [RedLine Stealer](/mitre/software/S1240.md) | S1240 | Hosted by sanctioned Aeza Group | [51][161] |
| [C0015](/mitre/campaigns/C0015.md) | C0015 | Five-day Bazar, Cobalt Strike and Conti intrusion by unidentified attackers | [145][161] |
| [C0018](/mitre/campaigns/C0018.md) | C0018 | Month-long AvosLocker intrusion | [7][161] |
| [Cutting Edge](/mitre/campaigns/C0029.md) | C0029 | Ivanti exploitation attributed to suspected China-nexus espionage actors; the counterpoint to KEV's ransomware flag | [161][32] |

ATT&CK v20 has no objects for DragonForce, BlackSuit, Hive, Rhysida, Interlock, Phobos, 8Base, Ghost or Cring, Gunra, SafePay or KillSec (Confirmed [157][161]).

### Mitigations

| Mitigation | Id | Techniques it covers in the library's data | Source |
|---|---|---|---|
| [Multi-factor Authentication](/mitre/mitigations/M1032.md) | M1032 | T1078, T1133, T1110, T1539, T1621, T1556.006, T1530 | [161] |
| [Data Backup](/mitre/mitigations/M1053.md) | M1053 | T1486, T1490 | [161] |
| [Network Segmentation](/mitre/mitigations/M1030.md) | M1030 | T1133, T1190, T1563 | [161] |
| [Update Software](/mitre/mitigations/M1051.md) | M1051 | T1190, T1539, T1189 | [161] |
| [User Training](/mitre/mitigations/M1017.md) | M1017 | T1566, T1566.004, T1621, T1189, T1657 | [161] |
| [Execution Prevention](/mitre/mitigations/M1038.md) | M1038 | T1219, T1490 | [161] |
| [Disable or Remove Feature or Program](/mitre/mitigations/M1042.md) | M1042 | T1133, T1219, T1563 | [161] |
| [Filter Network Traffic](/mitre/mitigations/M1037.md) | M1037 | T1190, T1219, T1530 | [161] |

### CAPEC and CWE

| CVE or technique | CWE (as recorded) | CAPEC (library data) | Fit | Source | Grade |
|---|---|---|---|---|---|
| CVE-2018-13379 FortiOS; CVE-2019-19781 Citrix | CWE-22 Improper Limitation of a Pathname to a Restricted Directory | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal | Both are path traversal flaws | [15][32][161] | Confirmed for the CWE and the CWE-to-CAPEC link; Inferred for the fit |
| CVE-2023-34362 MOVEit | CWE-89 Improper Neutralization of Special Elements used in an SQL Command | [CAPEC-66](/mitre/capec/CAPEC-66.md) SQL Injection | SQL injection | [14][161] | Confirmed; Inferred for the fit |
| CVE-2023-4966 Citrix Bleed | CWE-119 (Citrix as CNA); NVD-CWE-noinfo (NVD) | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers; [CAPEC-593](/mitre/capec/CAPEC-593.md) Session Hijacking (the library's mapping for T1563) | The flaw leaks memory; the abuse is session hijacking | [39][18][161] | Confirmed for the ids; Inferred for the fit |
| CVE-2021-30116 Kaseya VSA | CWE-522 Insufficiently Protected Credentials | [CAPEC-555](/mitre/capec/CAPEC-555.md) Remote Services with Stolen Credentials; [CAPEC-560](/mitre/capec/CAPEC-560.md) Use of Known Domain Credentials | Both CAPECs list CWE-522 in the library's data | [38][161] | Confirmed; Inferred for the fit |
| CVE-2025-61882 Oracle EBS | CWE-287 Improper Authentication (NVD) | [CAPEC-115](/mitre/capec/CAPEC-115.md) Authentication Bypass | CAPEC-115 lists CWE-287 | [41][161] | Confirmed; Inferred for the fit |
| CVE-2024-55591, CVE-2025-24472 FortiOS | CWE-288 Authentication Bypass Using an Alternate Path or Channel (per AA26-222A) | none bound: the CAPECs that list CWE-288 in the library's data (CAPEC-127, CAPEC-665) do not fit | | [29][161] | Confirmed for the CWE |
| CVE-2021-21974 ESXi OpenSLP | CWE-787 Out-of-bounds Write | none: no CAPEC lists CWE-787 in the library's data | | [40][161] | Confirmed |
| T1078 Valid Accounts | | [CAPEC-560](/mitre/capec/CAPEC-560.md) | Library technique-to-CAPEC mapping | [161] | Confirmed |
| T1133 External Remote Services | CWE-308 Use of Single-factor Authentication is listed by CAPEC-555 | [CAPEC-555](/mitre/capec/CAPEC-555.md) | VPNs without MFA | [161][23] | Confirmed for the mapping; Inferred for the fit |
| T1566 Phishing | | [CAPEC-98](/mitre/capec/CAPEC-98.md) Phishing | Library mapping | [161] | Confirmed |
| T1110 Brute Force | | [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force | Library mapping | [161] | Confirmed |
| T1539 Steal Web Session Cookie | | [CAPEC-21](/mitre/capec/CAPEC-21.md) Exploitation of Trusted Identifiers | Library mapping | [161] | Confirmed |
| T1563 Remote Service Session Hijacking | | [CAPEC-593](/mitre/capec/CAPEC-593.md) Session Hijacking | Library mapping | [161] | Confirmed |
| T1556.006 Multi-Factor Authentication | | [CAPEC-578](/mitre/capec/CAPEC-578.md) Disable Security Software | Library mapping | [161] | Confirmed |
| T1530 Data from Cloud Storage | | [CAPEC-150](/mitre/capec/CAPEC-150.md) Collect Data from Common Resource Locations | Library mapping | [161] | Confirmed |

See the [CWE Reference](/CWE_REFERENCE.md) and the [CAPEC Reference](/CAPEC_REFERENCE.md).

### D3FEND countermeasures

The library's `data/attack/technique_to_d3fend.jsonl` maps these countermeasures to the bound techniques, among others; the table lists the ones the record's guidance matches (Confirmed [161]).

| Countermeasure | D3FEND tactic | Library mapping | Guidance in the record it matches | Source |
|---|---|---|---|---|
| [Restore File](/mitre/d3fend/restore-file.md) | Restore | T1486 | Restore from offline backups | [161][31] |
| [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) | Detect | T1486 | Detect mass encryption | [161] |
| [Decoy File](/mitre/d3fend/decoy-file.md) | Deceive | T1486 | Early warning of encryption | [161] |
| [Remote File Access Mediation](/mitre/d3fend/remote-file-access-mediation.md) | Isolate | T1486 | Limit network file access | [161] |
| [Restore Configuration](/mitre/d3fend/restore-configuration.md), [Restore Software](/mitre/d3fend/restore-software.md) | Restore | T1490 | Rebuild after recovery features are destroyed | [161] |
| [Software Update](/mitre/d3fend/software-update.md) | Harden | T1490 | Patching | [161][18] |
| [Session Termination](/mitre/d3fend/session-termination.md) | Evict | T1133, T1563 | Kill sessions after Citrix Bleed | [161][18] |
| [Account Locking](/mitre/d3fend/account-locking.md) | Evict | T1078 | Lockout on SSL-VPN accounts (Gunra used devices without it) | [161][29] |
| [Agent Authentication](/mitre/d3fend/agent-authentication.md) | Harden | T1078 | Stronger authentication on remote access | [161][31] |
| [User Account Permissions](/mitre/d3fend/user-account-permissions.md) | Isolate | T1078 | Least privilege for service and support accounts | [161][85] |
| [Restore User Account Access](/mitre/d3fend/restore-user-account-access.md) | Restore | T1078 | Organization-wide password resets after credential dumps | [161][42] |
| [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) | Isolate | T1190 | Limit exposure of edge services | [161] |
| [User Geolocation Logon Pattern Analysis](/mitre/d3fend/user-geolocation-logon-pattern-analysis.md) | Detect | T1190, T1219, T1567.002 | Logins from VPN exit addresses (SafePay used Mullvad) | [161][30] |
| [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) | Isolate | T1219, T1567.002 | Block unapproved remote-access tools and cloud uploads | [161][17] |
| [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) | Harden | T1539 | Phishing-resistant MFA | [161][31] |
| [Credential Revocation](/mitre/d3fend/credential-revocation.md), [Authentication Cache Invalidation](/mitre/d3fend/authentication-cache-invalidation.md) | Evict | T1539 | Revoke stolen sessions and tokens | [161] |

The library's D3FEND data maps D3FEND Multi-factor Authentication to T1539 but not to T1078 or T1133, and has no D3FEND mapping for T1110, T1566, T1556.006 or T1657 (Confirmed [161]). The control the record names most often therefore has no D3FEND binding to the entry techniques it defends (Inferred).

### Navigator layers

The study's Enterprise techniques are saved as an ATT&CK Navigator layer, [ransomware-ecosystem-2019-2026.json on GitHub](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/ransomware-ecosystem-2019-2026.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https%3A%2F%2Fraw.githubusercontent.com%2FTeamStarWolf%2FTeamStarWolf%2Fmain%2Fnavigator%2Flibrary-layers%2Fransomware-ecosystem-2019-2026.json)), and the three ICS rows as [ransomware-ecosystem-2019-2026-ics.json on GitHub](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/ransomware-ecosystem-2019-2026-ics.json). Both are listed on [the Navigator layers page](/navigator/index.md) and pinned to ATT&CK v20. Scores show the basis, not severity: 100 where an opened source prints the id, 70 where this study assigns it. Each entry's comment names its source numbers. The library's general [Ransomware TTPs](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/ransomware-ttps.json) layer and the computed [Ransomware Family Techniques](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/computed/ransomware-family.json) layer are useful comparisons.

## Cross-cutting themes

- **The access economy is the real market.** Brokers, stealer logs and leaked VPN credentials sit behind most of the entry points in the advisories (Confirmed [11][27][42]; Reported [106][117]; Inferred for the theme). See [Identity Security](/IDENTITY_SECURITY_REFERENCE.md).
- **The edge is where defense starts.** Fortinet, Citrix, Cisco, SonicWall and Ivanti devices recur across six years of advisories and KEV flags (Confirmed [32]; Inferred for the theme). See [Edge Device Security](/EDGE_DEVICE_SECURITY_REFERENCE.md).
- **Concentration multiplies harm.** Kaseya's MSPs, CDK's dealers, Change Healthcare's payments, Synnovis's pathology and RTX's airport software each turned one intrusion into a sector outage (Confirmed [44][73][70][76]; Reported [128]). See [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md).
- **Law enforcement shapes the market.** Hive, ALPHV and LockBit disruptions coincide with falling payments in FinCEN's 2024 data and Chainalysis's 2024 estimate (Confirmed [96]; Reported [105]; Inferred for the link).
- **The victims' count is not the attackers' count.** Leak sites inflate (LockBit's repeat and fabricated posts) and victims under-report (Hive's 20 percent) (Reported [105][144]).

### Where the sources disagree

- **When ALPHV exited.** CyberScoop and Coveware date the exit to March 2024 (Reported [127][107]); Chainalysis's 2025 report dates it to January 2024, which conflicts with the March record (Reported [105][107]).
- **What Hive cost and saved.** The Justice Department says the FBI averted about $130 million (Confirmed [64]); Chainalysis estimates at least $210.4 million (Reported [104]).
- **How many Hive victims reported.** About 20 percent per FBI Director Wray, 40 percent per another outlet (Reported [144]).
- **Payment totals.** FinCEN puts 2023 at about $1.1 billion and 2024 at about $734 million (Confirmed [96]); Chainalysis puts them at $1.25 billion and $892 million (Reported [105][106]).
- **LockBit's size.** About 1,700 US attacks (AA23-165A), more than 7,000 attacks built (NCA), over 2,500 victims (DOJ via Treasury), 25 percent of all attacks in 2023 to 2024 (NCA's Cronos page) (Confirmed [15][56][49][58]). Each counts something different.
- **Akira's take.** About $244.17 million claimed by September 2025 (Confirmed [23]) against about $120.9 million in US-reported payments for 2022 to 2024 (Confirmed [96]).
- **The share of victims who pay.** 20 to 28 percent by Coveware's and Chainalysis's 2025 measures, 36 percent by Verizon's 2024 data, 14 percent by the industry figure NAIC cites (Reported [111][106][117][100]; Inferred for the 36 and 14 percent complements).

### What is overstated and what is understated

- **Overstated: a leak-site threat as proof of theft.** Ghost's notes threaten to sell data, but the advisory says Ghost rarely steals much (Confirmed [26]). Byod claimed 36,000 systems at UNM Health (Reported [136]).
- **Overstated: one brand, one group.** Most "same group renamed" links rest on code similarity and leak-site behavior; CISA's BlackSuit-is-Royal judgment is code-based, and affiliates move between brands (Confirmed [11][25]; Inferred).
- **Overstated: early attribution.** Change Healthcare's "suspected nation-state" became ALPHV (Confirmed [72][70]); Ascension's Black Basta attribution was never confirmed by Ascension (Reported [140]).
- **Overstated: a single total for payments.** The series disagree and keep moving (Confirmed [96]; Reported [105][106]; Inferred).
- **Overstated: a takedown as the end.** LockBit kept posting after Cronos (Reported [105]); ALPHV returned after December 2023 (Confirmed [20]).
- **Understated: unreported incidents.** About 20 percent of Hive victims reported (Reported [144]), IC3 calls its loss rate artificially low (Confirmed [95]), and neither CIRCIA nor UK mandatory reporting was in force on 11 November 2026 (Confirmed [34][93]). Affiliate churn hides people behind new names: Coveware describes a fragmented market with a "dwindling contingent of ransomware affiliates" and lone actors at 9 percent market share in Q1 2025, up from 8 percent in Q4 2024 (Reported [109][108]).
- **Understated: theft-only extortion.** Encryption-centred metrics miss it and backups do not answer it (Confirmed [13][14]; Inferred).
- **Understated: ransomware use of edge flaws.** For Ivanti it shows up only as a KEV flag, and the CVE tied to ESXiArgs is not in KEV at all (Confirmed [22][32][40]; Inferred).
- **Understated: dwell time and downstream harm.** Eight weeks inside HSE, about four at Dallas (Confirmed [83][85]); diverted ambulances and cancelled procedures that never appear in breach counts (Reported [136][128]; Inferred).
- **Understated: cost beyond the ransom.** Jaguar Land Rover's £1.9 billion has no public ransom figure at all (Confirmed [102]).

## Sources

All sources were opened on 11 November 2026. "Primary" means the organization that published the fact; grades apply to the source as used here. Addresses shown as code rather than as links refuse automated link checkers: the sec.gov filings, the EDGAR full-text search and the MinterEllison article open in a browser. Justice Department releases were read through Wayback Machine snapshots because justice.gov serves a bot check to scripted clients.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CISA, FBI and HHS, AA20-302A, ransomware activity targeting the healthcare and public health sector, 28 Oct 2020 | [cisa.gov/news-events/cybersecurity-advisories/aa20-302a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a) | 2026-11-11 | Confirmed |
| 2 | FBI, CISA and MS-ISAC, AA20-345A, cyber actors target K-12 distance learning, 10 Dec 2020 | [cisa.gov/news-events/cybersecurity-advisories/aa20-345a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-345a) | 2026-11-11 | Confirmed |
| 3 | FBI, CISA, EPA and NSA, AA21-287A, ongoing cyber threats to US water and wastewater systems, 14 Oct 2021 | [cisa.gov/news-events/cybersecurity-advisories/aa21-287a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-287a) | 2026-11-11 | Confirmed |
| 4 | CISA and FBI, Conti ransomware alert (AA21-265A), 22 Sep 2021, revised 9 Mar 2022 | [cisa.gov/news-events/alerts/2021/09/22/conti-ransomware](https://www.cisa.gov/news-events/alerts/2021/09/22/conti-ransomware) | 2026-11-11 | Confirmed |
| 5 | FBI, CISA, NSA, ACSC and NCSC-UK, AA22-040A, 2021 trends show increased globalized threat of ransomware, last revised 10 Feb 2022 | [cisa.gov/news-events/cybersecurity-advisories/aa22-040a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-040a) | 2026-11-11 | Confirmed |
| 6 | FBI, CISA and Treasury, AA22-187A, North Korean state-sponsored actors use Maui ransomware, 6 Jul 2022 | [cisa.gov/news-events/cybersecurity-advisories/aa22-187a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-187a) | 2026-11-11 | Confirmed |
| 7 | FBI, CISA and MS-ISAC, AA22-249A, #StopRansomware: Vice Society, last revised 8 Sep 2022 (and CISA's #StopRansomware advisory list) | [cisa.gov/news-events/cybersecurity-advisories/aa22-249a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-249a) | 2026-11-11 | Confirmed |
| 8 | FBI, CISA and HHS, AA22-294A, #StopRansomware: Daixin Team, 21 Oct 2022 | [cisa.gov/news-events/cybersecurity-advisories/aa22-294a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-294a) | 2026-11-11 | Confirmed |
| 9 | FBI, CISA and HHS, AA22-321A, #StopRansomware: Hive, 17 Nov 2022 | [cisa.gov/news-events/cybersecurity-advisories/aa22-321a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a) | 2026-11-11 | Confirmed |
| 10 | CISA and FBI, AA23-039A, ESXiArgs ransomware virtual machine recovery guidance, 8 Feb 2023 | [cisa.gov/news-events/cybersecurity-advisories/aa23-039a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-039a) | 2026-11-11 | Confirmed |
| 11 | CISA and FBI, AA23-061A, #StopRansomware: BlackSuit (Royal), 2 Mar 2023, updated 7 Aug 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa23-061a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a) | 2026-11-11 | Confirmed |
| 12 | FBI, CISA and MS-ISAC, AA23-075A, #StopRansomware: LockBit 3.0, 16 Mar 2023 | [cisa.gov/news-events/cybersecurity-advisories/aa23-075a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a) | 2026-11-11 | Confirmed |
| 13 | FBI, CISA and ASD's ACSC, AA23-136A, #StopRansomware: BianLian, 16 May 2023, revised 20 Nov 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa23-136a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a) | 2026-11-11 | Confirmed |
| 14 | FBI and CISA, AA23-158A, #StopRansomware: CL0P exploits MOVEit CVE-2023-34362, 7 Jun 2023 | [cisa.gov/news-events/cybersecurity-advisories/aa23-158a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a) | 2026-11-11 | Confirmed |
| 15 | CISA, FBI, MS-ISAC and partners in six other countries, AA23-165A, understanding LockBit, 14 Jun 2023 | [cisa.gov/news-events/cybersecurity-advisories/aa23-165a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a) | 2026-11-11 | Confirmed |
| 16 | FBI, CISA and MS-ISAC, AA23-319A, #StopRansomware: Rhysida, 15 Nov 2023, updated 30 Apr 2025 | [cisa.gov/news-events/cybersecurity-advisories/aa23-319a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a) | 2026-11-11 | Confirmed |
| 17 | FBI, CISA and partners, AA23-320A, Scattered Spider, 16 Nov 2023, updated 29 Jul 2025 | [cisa.gov/news-events/cybersecurity-advisories/aa23-320a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) | 2026-11-11 | Confirmed |
| 18 | CISA and FBI, AA23-325A, LockBit 3.0 affiliates exploit Citrix Bleed, 21 Nov 2023 | [cisa.gov/news-events/cybersecurity-advisories/aa23-325a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) | 2026-11-11 | Confirmed |
| 19 | FBI, CISA and ASD's ACSC, AA23-352A, #StopRansomware: Play, 18 Dec 2023, updated 4 Jun 2025 | [cisa.gov/news-events/cybersecurity-advisories/aa23-352a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a) | 2026-11-11 | Confirmed |
| 20 | FBI, CISA and HHS, AA23-353A, #StopRansomware: ALPHV Blackcat, 19 Dec 2023, updated 27 Feb 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa23-353a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a) | 2026-11-11 | Confirmed |
| 21 | CISA, FBI and MS-ISAC, AA24-060A, #StopRansomware: Phobos, 29 Feb 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa24-060a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a) | 2026-11-11 | Confirmed |
| 22 | CISA and partners, AA24-060B, Ivanti Connect Secure and Policy Secure exploitation, 29 Feb 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa24-060b](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b) | 2026-11-11 | Confirmed |
| 23 | FBI, CISA and partners, AA24-109A, #StopRansomware: Akira, 18 Apr 2024, updated 13 Nov 2025 | [cisa.gov/news-events/cybersecurity-advisories/aa24-109a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) | 2026-11-11 | Confirmed |
| 24 | CISA, FBI, HHS and MS-ISAC, AA24-131A, #StopRansomware: Black Basta, 10 May 2024, updated 8 Nov 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa24-131a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a) | 2026-11-11 | Confirmed |
| 25 | FBI, CISA, MS-ISAC and HHS, AA24-242A, #StopRansomware: RansomHub, 29 Aug 2024 | [cisa.gov/news-events/cybersecurity-advisories/aa24-242a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a) | 2026-11-11 | Confirmed |
| 26 | FBI, CISA and MS-ISAC, AA25-050A, #StopRansomware: Ghost (Cring), 19 Feb 2025 | [cisa.gov/news-events/cybersecurity-advisories/aa25-050a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-050a) | 2026-11-11 | Confirmed |
| 27 | FBI, CISA and HHS, AA25-071A, #StopRansomware: Medusa, 12 Mar 2025, updated 18 Aug 2026 | [cisa.gov/news-events/cybersecurity-advisories/aa25-071a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) | 2026-11-11 | Confirmed |
| 28 | FBI, CISA, HHS and MS-ISAC, AA25-203A, #StopRansomware: Interlock, 22 Jul 2025 | [cisa.gov/news-events/cybersecurity-advisories/aa25-203a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a) | 2026-11-11 | Confirmed |
| 29 | FBI, CISA, DC3, NSA, USSS and Korea's KNPA, AA26-222A, #StopRansomware: Gunra, 10 Aug 2026 | [cisa.gov/news-events/cybersecurity-advisories/aa26-222a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a) | 2026-11-11 | Confirmed |
| 30 | FBI, CISA, USSS, LKA Rheinland-Pfalz, NCA and NWROCU, AA26-293A, #StopRansomware: SafePay, 20 Oct 2026 | [cisa.gov/news-events/cybersecurity-advisories/aa26-293a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a) | 2026-11-11 | Confirmed |
| 31 | CISA and partners, #StopRansomware Guide, September 2023 update | [cisa.gov/stopransomware/ransomware-guide](https://www.cisa.gov/stopransomware/ransomware-guide) | 2026-11-11 | Confirmed |
| 32 | CISA, Known Exploited Vulnerabilities catalog, JSON feed, catalog version 2026.11.10 | [cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | 2026-11-11 | Confirmed; counts Demonstrated |
| 33 | CISA, the attack on Colonial Pipeline: what we've learned and what we've done over the past two years | [cisa.gov/news-events/news/attack-colonial-pipeline-what-weve-learned-what-weve-done-over-past-two-years](https://www.cisa.gov/news-events/news/attack-colonial-pipeline-what-weve-learned-what-weve-done-over-past-two-years) | 2026-11-11 | Confirmed |
| 34 | CISA, Cyber Incident Reporting for Critical Infrastructure Act of 2022 (CIRCIA) page | [cisa.gov/topics/.../cyber-incident-reporting-critical-infrastructure-act-2022-circia](https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/cyber-incident-reporting-critical-infrastructure-act-2022-circia) | 2026-11-11 | Confirmed |
| 35 | CISA, 2024 Year in Review | [cisa.gov/about/2024YIR](https://www.cisa.gov/about/2024YIR) | 2026-11-11 | Reported (agency self-report) |
| 36 | Federal Register, CIRCIA reporting requirements, proposed rule, 89 FR 23644, 4 Apr 2024 | [federalregister.gov/documents/2024/04/04/2024-06526/...](https://www.federalregister.gov/documents/2024/04/04/2024-06526/cyber-incident-reporting-for-critical-infrastructure-act-circia-reporting-requirements) | 2026-11-11 | Confirmed |
| 37 | Reginfo.gov, OIRA review record, RIN 1670-AA04, CIRCIA final rule | [reginfo.gov/public/do/eoDetails?rrid=1550967](https://www.reginfo.gov/public/do/eoDetails?rrid=1550967) | 2026-11-11 | Confirmed |
| 38 | NVD API record, CVE-2021-30116 (Kaseya VSA) | [services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-30116](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-30116) | 2026-11-11 | Confirmed |
| 39 | NVD API record, CVE-2023-4966 (Citrix Bleed) | [services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-4966](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-4966) | 2026-11-11 | Confirmed |
| 40 | NVD API record, CVE-2021-21974 (ESXi OpenSLP) | [services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21974](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21974) | 2026-11-11 | Confirmed |
| 41 | Oracle, Security Alert CVE-2025-61882, 4 Oct 2025, revised 6 Oct 2025 | [oracle.com/security-alerts/alert-cve-2025-61882.html](https://www.oracle.com/security-alerts/alert-cve-2025-61882.html) | 2026-11-11 | Confirmed |
| 42 | Fortinet PSIRT, malicious actor discloses FortiGate SSL-VPN credentials, 8 Sep 2021 | [fortinet.com/blog/psirt-blogs/malicious-actor-discloses-fortigate-ssl-vpn-credentials](https://www.fortinet.com/blog/psirt-blogs/malicious-actor-discloses-fortigate-ssl-vpn-credentials) | 2026-11-11 | Confirmed |
| 43 | Microsoft Security Blog, ransomware operators exploit ESXi hypervisor vulnerability for mass encryption, 29 Jul 2024 | [microsoft.com/en-us/security/blog/2024/07/29/...](https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/) | 2026-11-11 | Confirmed |
| 44 | Kaseya, press release, 5 Jul 2021 | [kaseya.com/press-release/kaseya-responds-swiftly-to-sophisticated-cyberattack-...](https://www.kaseya.com/press-release/kaseya-responds-swiftly-to-sophisticated-cyberattack-mitigating-global-disruption-to-customers/) | 2026-11-11 | Confirmed |
| 45 | US Treasury, press release JY1256, US and UK sanction Trickbot members, 9 Feb 2023 | [home.treasury.gov/news/press-releases/jy1256](https://home.treasury.gov/news/press-releases/jy1256) | 2026-11-11 | Confirmed |
| 46 | US Treasury, press release JY1714, 7 Sep 2023 | [home.treasury.gov/news/press-releases/jy1714](https://home.treasury.gov/news/press-releases/jy1714) | 2026-11-11 | Confirmed |
| 47 | US Treasury, press release JY1486, sanctions on Mikhail Matveev, 16 May 2023 | [home.treasury.gov/news/press-releases/jy1486](https://home.treasury.gov/news/press-releases/jy1486) | 2026-11-11 | Confirmed |
| 48 | US Treasury, press release JY2114, LockBit affiliates sanctioned, 20 Feb 2024 | [home.treasury.gov/news/press-releases/jy2114](https://home.treasury.gov/news/press-releases/jy2114) | 2026-11-11 | Confirmed |
| 49 | US Treasury, press release JY2326, LockBitSupp sanctioned, 7 May 2024 | [home.treasury.gov/news/press-releases/jy2326](https://home.treasury.gov/news/press-releases/jy2326) | 2026-11-11 | Confirmed |
| 50 | US Treasury, press release SB0018, Zservers sanctioned, 11 Feb 2025 | [home.treasury.gov/news/press-releases/sb0018](https://home.treasury.gov/news/press-releases/sb0018) | 2026-11-11 | Confirmed |
| 51 | US Treasury, press release SB0185, Aeza Group sanctioned, 1 Jul 2025 | [home.treasury.gov/news/press-releases/sb0185](https://home.treasury.gov/news/press-releases/sb0185) | 2026-11-11 | Confirmed |
| 52 | OFAC, recent actions, 21 Sep 2021 | [ofac.treasury.gov/recent-actions/20210921](https://ofac.treasury.gov/recent-actions/20210921) | 2026-11-11 | Confirmed |
| 53 | OFAC, updated advisory on potential sanctions risks for facilitating ransomware payments, 21 Sep 2021 | [ofac.treasury.gov/media/912981/download](https://ofac.treasury.gov/media/912981/download) | 2026-11-11 | Confirmed |
| 54 | US Department of State (2021 to 2025 archive), reward offers for Conti co-conspirators, 6 May 2022 | [2021-2025.state.gov/reward-offers-for-information-to-bring-conti-ransomware-variant-co-conspirators-to-justice](https://2021-2025.state.gov/reward-offers-for-information-to-bring-conti-ransomware-variant-co-conspirators-to-justice/) | 2026-11-11 | Confirmed |
| 55 | US Department of State (2021 to 2025 archive), reward offers for Hive co-conspirators, 8 Feb 2024 | [2021-2025.state.gov/reward-offers-for-information-to-bring-hive-ransomware-variant-co-conspirators-to-justice](https://2021-2025.state.gov/reward-offers-for-information-to-bring-hive-ransomware-variant-co-conspirators-to-justice/) | 2026-11-11 | Confirmed |
| 56 | UK National Crime Agency, LockBit leader unmasked and sanctioned, 7 May 2024 | [nationalcrimeagency.gov.uk/news/lockbit-leader-unmasked-and-sanctioned](https://www.nationalcrimeagency.gov.uk/news/lockbit-leader-unmasked-and-sanctioned) | 2026-11-11 | Confirmed |
| 57 | UK National Crime Agency, international investigation disrupts the world's most harmful ransomware group, 20 Feb 2024 | [nationalcrimeagency.gov.uk/news/nca-leads-international-investigation-targeting-worlds-most-harmful-ransomware-group](https://nationalcrimeagency.gov.uk/news/nca-leads-international-investigation-targeting-worlds-most-harmful-ransomware-group) | 2026-11-11 | Confirmed |
| 58 | UK National Crime Agency, the disruption of LockBit with Operation Cronos (undated page; images labelled February 2024) | [nationalcrimeagency.gov.uk/the-nca-announces-the-disruption-of-lockbit-with-operation-cronos](https://www.nationalcrimeagency.gov.uk/the-nca-announces-the-disruption-of-lockbit-with-operation-cronos) | 2026-11-11 | Confirmed |
| 59 | UK National Crime Agency newsroom, two charged for TfL cyber attack, 18 Sep 2025 | [nca-newsroom.prgloo.com/news/two-charged-for-tfl-cyber-attack](https://nca-newsroom.prgloo.com/news/two-charged-for-tfl-cyber-attack) | 2026-11-11 | Confirmed |
| 60 | UK National Crime Agency, two sentenced for hacking Transport for London, 16 Jul 2026 | [nationalcrimeagency.gov.uk/news/two-sentenced-for-hacking-transport-for-london-...](https://www.nationalcrimeagency.gov.uk/news/two-sentenced-for-hacking-transport-for-london-in-uk-s-biggest-ever-cyber-crime-case) | 2026-11-11 | Confirmed |
| 61 | US Immigration and Customs Enforcement (HSI), international takedown of BlackSuit ransomware infrastructure, 7 Aug 2025 | [ice.gov/news/releases/ice-washington-dc-leads-international-takedown-blacksuit-ransomware-infrastructure](https://www.ice.gov/news/releases/ice-washington-dc-leads-international-takedown-blacksuit-ransomware-infrastructure) | 2026-11-11 | Confirmed |
| 62 | US Department of Justice, seizure of $2.3 million paid to DarkSide, 7 Jun 2021 (Wayback Machine snapshot) | [web.archive.org/web/2021id_/www.justice.gov/opa/pr/department-justice-seizes-23-million-...](https://web.archive.org/web/2021id_/https://www.justice.gov/opa/pr/department-justice-seizes-23-million-cryptocurrency-paid-ransomware-extortionists-darkside) | 2026-11-11 | Confirmed |
| 63 | US Department of Justice, Ukrainian arrested and charged with ransomware attack on Kaseya, 8 Nov 2021 (Wayback Machine snapshot) | [web.archive.org/web/2021id_/www.justice.gov/opa/pr/ukrainian-arrested-and-charged-ransomware-attack-kaseya](https://web.archive.org/web/2021id_/https://www.justice.gov/opa/pr/ukrainian-arrested-and-charged-ransomware-attack-kaseya) | 2026-11-11 | Confirmed |
| 64 | US Department of Justice, disruption of the Hive ransomware variant, 26 Jan 2023 (Wayback Machine snapshot) | [web.archive.org/web/2023id_/www.justice.gov/opa/pr/us-department-justice-disrupts-hive-ransomware-variant](https://web.archive.org/web/2023id_/https://www.justice.gov/opa/pr/us-department-justice-disrupts-hive-ransomware-variant) | 2026-11-11 | Confirmed |
| 65 | US Department of Justice, disruption of the ALPHV/BlackCat ransomware variant, 19 Dec 2023 (Wayback Machine snapshot) | [web.archive.org/web/2023id_/www.justice.gov/opa/pr/justice-department-disrupts-prolific-alphvblackcat-ransomware-variant](https://web.archive.org/web/2023id_/https://www.justice.gov/opa/pr/justice-department-disrupts-prolific-alphvblackcat-ransomware-variant) | 2026-11-11 | Confirmed |
| 66 | Europol, "LockBit power cut: four new arrests and financial sanctions against affiliates", October 2024 (title only rendered) | [europol.europa.eu/media-press/newsroom/news/lockbit-power-cut-...](https://europol.europa.eu/media-press/newsroom/news/lockbit-power-cut-four-new-arrests-and-financial-sanctions-against-affiliates) | 2026-11-11 | Confirmed (title only) |
| 67 | Operation Endgame, news page (phases of 30 May 2024 and 10 to 13 Nov 2025) | [operation-endgame.com/news](https://operation-endgame.com/news/) | 2026-11-11 | Confirmed |
| 68 | Operation Endgame, home page (season 3, 24 Jun 2026) | [operation-endgame.com](https://operation-endgame.com/) | 2026-11-11 | Confirmed |
| 69 | Eurojust, coordinated action to take down the most dangerous malware variants, 23 May 2025 | [eurojust.europa.eu/news/coordinated-action-take-down-most-dangerous-malware-variants](https://www.eurojust.europa.eu/news/coordinated-action-take-down-most-dangerous-malware-variants) | 2026-11-11 | Confirmed |
| 70 | Andrew Witty, written testimony, Senate Finance Committee, 1 May 2024 | [finance.senate.gov/imo/media/doc/0501_witty_testimony.pdf](https://www.finance.senate.gov/imo/media/doc/0501_witty_testimony.pdf) | 2026-11-11 | Confirmed |
| 71 | Joseph Blount, written testimony, Senate Homeland Security and Governmental Affairs Committee, 8 Jun 2021 | [hsgac.senate.gov/wp-content/uploads/imo/media/doc/Testimony-Blount-2021-06-08.pdf](https://www.hsgac.senate.gov/wp-content/uploads/imo/media/doc/Testimony-Blount-2021-06-08.pdf) | 2026-11-11 | Confirmed |
| 72 | UnitedHealth Group, Form 8-K, Item 1.05, event 21 Feb 2024 | `https://www.sec.gov/Archives/edgar/data/731766/000073176624000045/unh-20240221.htm` | 2026-11-11 | Confirmed |
| 73 | Sonic Automotive, Form 8-K, event 19 Jun 2024 | `https://www.sec.gov/Archives/edgar/data/1043509/000104350924000059/sah-20240619.htm` | 2026-11-11 | Confirmed |
| 74 | AutoNation, Form 8-K, event 19 Jun 2024 | `https://www.sec.gov/Archives/edgar/data/350698/000035069824000078/an-20240619.htm` | 2026-11-11 | Confirmed |
| 75 | DaVita, Form 8-K, April 2025 | `https://www.sec.gov/Archives/edgar/data/927066/000119312525079593/d948299d8k.htm` | 2026-11-11 | Confirmed |
| 76 | RTX, Form 8-K, event 19 Sep 2025 | `https://www.sec.gov/Archives/edgar/data/101829/000010182925000036/rtx-20250919.htm` | 2026-11-11 | Confirmed |
| 77 | MGM Resorts International, Form 8-K, 5 Oct 2023 | `https://www.sec.gov/Archives/edgar/data/789570/000119312523251667/d461062d8k.htm` | 2026-11-11 | Confirmed |
| 78 | Caesars Entertainment, Form 8-K, Item 8.01, 14 Sep 2023 | `https://www.sec.gov/Archives/edgar/data/1590895/000119312523235015/d537840d8k.htm` | 2026-11-11 | Confirmed |
| 79 | American Water Works, Form 8-K, October 2024 | `https://www.sec.gov/Archives/edgar/data/1410636/000119312524233300/d869346d8k.htm` | 2026-11-11 | Confirmed |
| 80 | Universal Health Services, Exhibit 99.1 (2020 results release) | `https://www.sec.gov/Archives/edgar/data/352915/000156459021008858/uhs-ex991_6.htm` | 2026-11-11 | Confirmed |
| 81 | SEC, press release 2023-139, cybersecurity risk management and incident disclosure rules, 26 Jul 2023 | `https://www.sec.gov/newsroom/press-releases/2023-139` | 2026-11-11 | Confirmed |
| 82 | SEC EDGAR full-text search, "ransomware" in 8-Ks, 18 Dec 2023 to 10 Nov 2026 | `https://efts.sec.gov/LATEST/search-index?q=ransomware&forms=8-K&dateRange=custom&startdt=2023-12-18&enddt=2026-11-10` | 2026-11-11 | Demonstrated |
| 83 | PwC, conti cyber attack on the HSE, independent post-incident review, 3 Dec 2021 | [about.hse.ie/api/v2/download-file/file_based_publications/conti_cyber_attack_on_the_hse_full_report.pdf](https://about.hse.ie/api/v2/download-file/file_based_publications/conti_cyber_attack_on_the_hse_full_report.pdf) | 2026-11-11 | Confirmed |
| 84 | Kettering Health, cybersecurity incident FAQ | [ketteringhealth.org/cybersecurity-incident-faq](https://ketteringhealth.org/cybersecurity-incident-faq/) | 2026-11-11 | Confirmed |
| 85 | City of Dallas, ransomware incident May 2023: incident remediation efforts and resolution | [dallascityhall.com/DCH%20Documents/dallas-ransomware-incident-may-2023-...pdf](https://dallascityhall.com/DCH%20Documents/dallas-ransomware-incident-may-2023-incident-remediation-efforts-and-resolution.pdf) | 2026-11-11 | Confirmed |
| 86 | HHS HC3, analyst note 202404051700, top ten most active ransomware groups (AHA-hosted copy) | [aha.org/system/files/media/file/2024/04/HC3-tlp-clear-analyst-note-...pdf](https://www.aha.org/system/files/media/file/2024/04/HC3-tlp-clear-analyst-note-top-10-most-active-ransomware-groups-4-10-24.pdf) | 2026-11-11 | Confirmed |
| 87 | HHS, Healthcare and Public Health Cybersecurity Performance Goals | [hhscyber.hhs.gov/cybersecurity-performance-goals.html](https://hhscyber.hhs.gov/cybersecurity-performance-goals.html) | 2026-11-11 | Confirmed |
| 88 | HHS OCR, HIPAA Security Rule proposed rule, 90 FR 898, 6 Jan 2025 (govinfo) | [govinfo.gov/content/pkg/FR-2025-01-06/html/2024-30983.htm](https://www.govinfo.gov/content/pkg/FR-2025-01-06/html/2024-30983.htm) | 2026-11-11 | Confirmed; Reported for the 2019 Alabama case it cites |
| 89 | EPA, enforcement alert: drinking water systems to address cybersecurity vulnerabilities, May 2024 | [epa.gov/enforcement/enforcement-alert-drinking-water-systems-address-cybersecurity-vulnerabilities](https://www.epa.gov/enforcement/enforcement-alert-drinking-water-systems-address-cybersecurity-vulnerabilities) | 2026-11-11 | Confirmed |
| 90 | Office of the Governor of South Carolina, Project Lifeline launch, 26 Oct 2026 | [governor.sc.gov/news/2026-10/gov-mcmaster-white-house-national-cyber-director-cairncross-launch-project-lifeline](https://governor.sc.gov/news/2026-10/gov-mcmaster-white-house-national-cyber-director-cairncross-launch-project-lifeline) | 2026-11-11 | Confirmed |
| 91 | North Carolina General Statutes, G.S. 143-800 | [ncleg.gov/EnactedLegislation/Statutes/HTML/BySection/Chapter_143/GS_143-800.html](https://www.ncleg.gov/EnactedLegislation/Statutes/HTML/BySection/Chapter_143/GS_143-800.html) | 2026-11-11 | Confirmed |
| 92 | Florida Statutes, s. 282.3186 (2024) | [flsenate.gov/Laws/Statutes/2024/282.3186](https://www.flsenate.gov/Laws/Statutes/2024/282.3186) | 2026-11-11 | Confirmed |
| 93 | UK Home Office, government response to the ransomware legislative proposals, 22 Jul 2025 | [gov.uk/government/consultations/ransomware-proposals-.../government-response-...-accessible](https://www.gov.uk/government/consultations/ransomware-proposals-to-increase-incident-reporting-and-reduce-payments-to-criminals/outcome/government-response-to-ransomware-legislative-proposals-reducing-payments-to-cyber-criminals-and-increasing-incident-reporting-accessible) | 2026-11-11 | Confirmed |
| 94 | FBI IC3, 2023 Internet Crime Report | [ic3.gov/AnnualReport/Reports/2023_IC3Report.pdf](https://www.ic3.gov/AnnualReport/Reports/2023_IC3Report.pdf) | 2026-11-11 | Confirmed |
| 95 | FBI IC3, 2024 Internet Crime Report | [ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf](https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf) | 2026-11-11 | Confirmed |
| 96 | FinCEN, financial trend analysis: ransomware, 2022 to 2024, December 2025 | [fincen.gov/system/files/2025-12/FTA-Ransomware.pdf](https://www.fincen.gov/system/files/2025-12/FTA-Ransomware.pdf) | 2026-11-11 | Confirmed |
| 97 | GAO-21-477, cyber insurance, 20 May 2021 | [gao.gov/products/gao-21-477](https://www.gao.gov/products/gao-21-477) | 2026-11-11 | Confirmed |
| 98 | GAO-22-104256, cyber insurance and systemic risk, 21 Jun 2022 | [gao.gov/products/gao-22-104256](https://www.gao.gov/products/gao-22-104256) | 2026-11-11 | Confirmed |
| 99 | Lloyd's, Market Bulletin Y5381, state-backed cyber-attack exclusions, 16 Aug 2022 | [assets.lloyds.com/media/35926dc8-.../Y5381 Market Bulletin - Cyber-attack exclusions.pdf](https://assets.lloyds.com/media/35926dc8-c885-497b-aed8-6d2f87c1415d/Y5381%20Market%20Bulletin%20-%20Cyber-attack%20exclusions.pdf) | 2026-11-11 | Confirmed |
| 100 | NAIC, report on the cybersecurity insurance market, October 2026 (2025 reporting year) | [content.naic.org/sites/default/files/2026-report-cybersecurity-insurance-market.pdf](https://content.naic.org/sites/default/files/2026-report-cybersecurity-insurance-market.pdf) | 2026-11-11 | Confirmed for NAIC's own premium data; Reported for the industry refusal figure it cites |
| 101 | Cyber Monitoring Centre, statement on ransomware incidents in the retail sector, 20 Jun 2025 | [cybermonitoringcentre.com/2025/06/20/...](https://cybermonitoringcentre.com/2025/06/20/cyber-monitoring-centre-statement-on-ransomware-incidents-in-the-retail-sector-june-2025/) | 2026-11-11 | Confirmed |
| 102 | Cyber Monitoring Centre, statement on the Jaguar Land Rover cyber incident, 22 Oct 2025 | [cybermonitoringcentre.com/2025/10/22/...](https://cybermonitoringcentre.com/2025/10/22/cyber-monitoring-centre-statement-on-the-jaguar-land-rovercyber-incident-october-2025/) | 2026-11-11 | Confirmed |
| 103 | Cyber Monitoring Centre, statement on the Canvas cyber incident, 25 Jun 2026 | [cybermonitoringcentre.com/2026/06/25/statement-canvas-cyber-incident-june-2026](https://cybermonitoringcentre.com/2026/06/25/statement-canvas-cyber-incident-june-2026/) | 2026-11-11 | Confirmed |
| 104 | Chainalysis, ransomware 2024 (2023 data), 7 Feb 2024 | [chainalysis.com/blog/ransomware-2024](https://www.chainalysis.com/blog/ransomware-2024/) | 2026-11-11 | Reported |
| 105 | Chainalysis, ransomware 2025 (2024 data), 5 Feb 2025 | [chainalysis.com/blog/crypto-crime-ransomware-victim-extortion-2025](https://www.chainalysis.com/blog/crypto-crime-ransomware-victim-extortion-2025/) | 2026-11-11 | Reported |
| 106 | Chainalysis, ransomware 2026 (2025 data), 26 Feb 2026 | [chainalysis.com/blog/crypto-ransomware-2026](https://www.chainalysis.com/blog/crypto-ransomware-2026/) | 2026-11-11 | Reported |
| 107 | Coveware, Q1 2024 report, 17 Apr 2024 | [coveware.com/2024/04/raas-devs-hurt-their-credibility-by-cheating-affiliates-in-q1-2024](https://coveware.com/2024/04/raas-devs-hurt-their-credibility-by-cheating-affiliates-in-q1-2024/) | 2026-11-11 | Reported |
| 108 | Coveware, Q4 2024 report, 4 Feb 2025 | [coveware.com/2025/02/q4-report](https://coveware.com/2025/02/q4-report/) | 2026-11-11 | Reported |
| 109 | Coveware, Q1 2025 report on the organizational structure of ransomware groups, May 2025 | [coveware.com/2025/05/the-organizational-structure-of-ransomware-threat-actor-groups-...](https://coveware.com/2025/05/the-organizational-structure-of-ransomware-threat-actor-groups-is-evolving-before-our-eyes/) | 2026-11-11 | Reported |
| 110 | Coveware, Q3 2025 report, 24 Oct 2025 | [coveware.com/2025/10/insider-threats-loom-while-ransom-payment-rates-plummet](https://coveware.com/2025/10/insider-threats-loom-while-ransom-payment-rates-plummet/) | 2026-11-11 | Reported |
| 111 | Coveware, Q4 2025 report, 3 Feb 2026 | [coveware.com/2026/02/why-zero-day-downstream-mass-data-extortion-campaigns-are-losing-their-bite](https://coveware.com/2026/02/why-zero-day-downstream-mass-data-extortion-campaigns-are-losing-their-bite/) | 2026-11-11 | Reported |
| 112 | Coveware, Q1 2026 report, 30 Apr 2026 | [coveware.com/2026/04/patch-management-goes-from-hard-to-ludicrous-in-the-agentic-ai-era](https://coveware.com/2026/04/patch-management-goes-from-hard-to-ludicrous-in-the-agentic-ai-era/) | 2026-11-11 | Reported |
| 113 | Coveware, Q2 2026 report, 29 Jul 2026 | [coveware.com/2026/07/adverse-cyber-extortions-are-more-common-than-commonly-advised](https://coveware.com/2026/07/adverse-cyber-extortions-are-more-common-than-commonly-advised/) | 2026-11-11 | Reported |
| 114 | Coveware, Q3 2026 report, 28 Oct 2026 | [coveware.com/2026/10/the-silent-ransom-group-leak-shows-why-paying-for-silence-fails](https://coveware.com/2026/10/the-silent-ransom-group-leak-shows-why-paying-for-silence-fails/) | 2026-11-11 | Reported |
| 115 | Sophos, State of Ransomware 2024, press release, April 2024 | [sophos.com/en-us/press/press-releases/2024/04/...](https://sophos.com/en-us/press/press-releases/2024/04/ransomware-payments-increase-500-last-year-finds-sophos-state) | 2026-11-11 | Reported |
| 116 | Microsoft, ten essential insights from the Microsoft Digital Defense Report 2024 | [microsoft.com/en-ie/security/security-insider/intelligence-reports/...](https://www.microsoft.com/en-ie/security/security-insider/intelligence-reports/10-essential-insights-from-the-microsoft-digital-defense-report-2024) | 2026-11-11 | Reported |
| 117 | Verizon, 2025 Data Breach Investigations Report, executive summary | [verizon.com/business/resources/T6de/reports/2025-dbir-executive-summary.pdf](https://www.verizon.com/business/resources/T6de/reports/2025-dbir-executive-summary.pdf) | 2026-11-11 | Reported |
| 118 | CyberScoop, Black Basta leader added to the Europol most-wanted list, January 2026 | [cyberscoop.com/black-basta-leader-europol-most-wanted-list](https://cyberscoop.com/black-basta-leader-europol-most-wanted-list/) | 2026-11-11 | Reported |
| 119 | Help Net Security, ransomware negotiator charged over ALPHV/BlackCat attacks, 4 Nov 2025 | [helpnetsecurity.com/2025/11/04/ransomware-negotiator-alphv-blackcat-ransomware](https://www.helpnetsecurity.com/2025/11/04/ransomware-negotiator-alphv-blackcat-ransomware/) | 2026-11-11 | Reported |
| 120 | CyberScoop, UK arrests over the Marks & Spencer attacks, July 2025 | [cyberscoop.com/scattered-spider-arrests-uk-nca-marks-and-spencer](https://cyberscoop.com/scattered-spider-arrests-uk-nca-marks-and-spencer/) | 2026-11-11 | Reported |
| 121 | The Record, Nefilim and Hive operator sentenced to 70 months, 27 Oct 2026 | [therecord.media/nefilim-hive-ransomware-operator-70-months-prison](https://therecord.media/nefilim-hive-ransomware-operator-70-months-prison) | 2026-11-11 | Reported |
| 122 | Infosecurity Magazine, police target KillSec ransomware, October 2026 | [infosecurity-magazine.com/news/police-target-killsec-ransomware](https://www.infosecurity-magazine.com/news/police-target-killsec-ransomware/) | 2026-11-11 | Reported |
| 123 | Krebs on Security, FBI arrests founder of ransomware negotiation firm, October 2026 | [krebsonsecurity.com/2026/10/fbi-arrests-founder-of-ransomware-negotiation-firm](https://krebsonsecurity.com/2026/10/fbi-arrests-founder-of-ransomware-negotiation-firm/) | 2026-11-11 | Reported |
| 124 | The Record, State Department offering $10 million reward for information about Conti members, May 2022 | [therecord.media/us-state-department-offering-10-million-reward-for-information-about-conti-members](https://therecord.media/us-state-department-offering-10-million-reward-for-information-about-conti-members/) | 2026-11-11 | Reported |
| 125 | CyberScoop, second Conti reward, August 2022 | [cyberscoop.com/conti-state-department-reward](https://www.cyberscoop.com/conti-state-department-reward/) | 2026-11-11 | Reported |
| 126 | Observador (Costa Rica), emergency decree on the Conti attacks, May 2022 | [observador.cr/decreto-de-emergencia-suma-a-presidencia-y-cne-a-atender-crisis-de-los-hackeos-por-conti](https://observador.cr/decreto-de-emergencia-suma-a-presidencia-y-cne-a-atender-crisis-de-los-hackeos-por-conti/) | 2026-11-11 | Reported |
| 127 | CyberScoop, ransomware group behind the Change Healthcare attack goes dark, March 2024 | [cyberscoop.com/ransomware-group-behind-change-healthcare-attack-goes-dark](https://cyberscoop.com/ransomware-group-behind-change-healthcare-attack-goes-dark/) | 2026-11-11 | Reported |
| 128 | Synnovis, cyberattack statement (the address redirects; the NHS England figures are as circulated by the press) | [synnovis.co.uk/news-and-events/synnovis-cyberattack-statement](https://www.synnovis.co.uk/news-and-events/synnovis-cyberattack-statement) | 2026-11-11 | Reported |
| 129 | Infosecurity Magazine, CISA incident reporting form and CIRCIA, 10 Nov 2026 | [infosecurity-magazine.com/news/cisa-incident-reporting-form-circia](https://www.infosecurity-magazine.com/news/cisa-incident-reporting-form-circia/) | 2026-11-11 | Reported |
| 130 | MinterEllison, mandatory ransomware payment reporting obligations in force, 2025 | `https://www.minterellison.com/articles/mandatory-ransomware-payment-reporting-obligations-in-force` | 2026-11-11 | Reported |
| 131 | BleepingComputer, four arrested in UK over M&S, Co-op and Harrods attacks, July 2025 | [bleepingcomputer.com/news/security/four-arrested-in-uk-over-mands-co-op-harrods-cyberattacks](https://www.bleepingcomputer.com/news/security/four-arrested-in-uk-over-mands-co-op-harrods-cyberattacks/) | 2026-11-11 | Reported |
| 132 | Computer Weekly, Qilin gang claims cyber attack on Japanese brewing giant, 2025 | [computerweekly.com/news/366632317/Qilin-gang-claims-cyber-attack-on-Japanese-brewing-giant](https://www.computerweekly.com/news/366632317/Qilin-gang-claims-cyber-attack-on-Japanese-brewing-giant) | 2026-11-11 | Reported |
| 133 | Group-IB, Operation KillSwitch press release, 1 Oct 2026 (a participating vendor) | [group-ib.com/media-center/press-releases/operation-killswitch-killsec](https://www.group-ib.com/media-center/press-releases/operation-killswitch-killsec/) | 2026-11-11 | Reported |
| 134 | The Register, PAN-OS under attack from multiple ransomware groups since June, 20 Oct 2026 | [theregister.com/cyber-crime/2026/10/20/...](https://www.theregister.com/cyber-crime/2026/10/20/palo-altos-firewall-os-has-been-under-attack-from-multiple-ransomware-groups-since-june/5304226) | 2026-11-11 | Reported |
| 135 | BleepingComputer, Japan's GMO urges customers to shut down PCs amid ransomware threat, October 2026 | [bleepingcomputer.com/news/security/japans-gmo-urges-customers-to-shut-down-pcs-amid-ransomware-threat](https://www.bleepingcomputer.com/news/security/japans-gmo-urges-customers-to-shut-down-pcs-amid-ransomware-threat/) | 2026-11-11 | Reported |
| 136 | BleepingComputer, UNM Health ransomware attack disrupts patient care, October 2026 | [bleepingcomputer.com/news/security/unm-health-ransomware-attack-disrupts-patient-care-surgeries](https://www.bleepingcomputer.com/news/security/unm-health-ransomware-attack-disrupts-patient-care-surgeries/) | 2026-11-11 | Reported |
| 137 | The Record, Queens library ransomware causes disruptions, November 2026 | [therecord.media/queens-library-ransomware-causes-disruptions](https://therecord.media/queens-library-ransomware-causes-disruptions) | 2026-11-11 | Reported |
| 138 | BleepingComputer, Vanderbilt University hit in BYOD ransomware attack, November 2026 | [bleepingcomputer.com/news/security/vanderbilt-university-hit-in-byod-ransomware-attack-data-theft-claimed](https://www.bleepingcomputer.com/news/security/vanderbilt-university-hit-in-byod-ransomware-attack-data-theft-claimed/) | 2026-11-11 | Reported |
| 139 | BleepingComputer, UK school estate hit by 3AM ransomware in suspected AI-assisted attack, 2026 | [bleepingcomputer.com/news/security/uk-school-estate-hit-by-3am-ransomware-in-suspected-ai-assisted-attack](https://www.bleepingcomputer.com/news/security/uk-school-estate-hit-by-3am-ransomware-in-suspected-ai-assisted-attack/) | 2026-11-11 | Reported |
| 140 | Infosecurity Magazine, ransomware data of Ascension patients | [infosecurity-magazine.com/news/ransomware-data-ascesnion-patients](https://www.infosecurity-magazine.com/news/ransomware-data-ascesnion-patients/) | 2026-11-11 | Reported |
| 141 | GovInfoSecurity, feds delay planned HIPAA Security Rule overhaul to mid-2027, July 2026 | [govinfosecurity.com/feds-delay-planned-hipaa-security-rule-overhaul-to-mid-2027-a-32177](https://www.govinfosecurity.com/feds-delay-planned-hipaa-security-rule-overhaul-to-mid-2027-a-32177) | 2026-11-11 | Reported |
| 142 | Paubox, Lehigh Valley Health Network settles alleged HIPAA violation for $800K, October 2026 | [paubox.com/blog/lehigh-valley-health-network-settles-alleged-hipaa-violation-for-800k](https://www.paubox.com/blog/lehigh-valley-health-network-settles-alleged-hipaa-violation-for-800k) | 2026-11-11 | Reported |
| 143 | BankInfoSecurity, UHG CEO testifies to lawmakers, 30 Apr 2024 | [bankinfosecurity.com/uhg-ceo-testifies-to-lawmakers-a-24977](https://www.bankinfosecurity.com/uhg-ceo-testifies-to-lawmakers-a-24977) | 2026-11-11 | Reported |
| 144 | The Record, DOJ and FBI take down Hive after months inside gang systems, 26 Jan 2023 | [therecord.media/we-hacked-the-hackers-doj-fbi-take-down-hive-...](https://therecord.media/we-hacked-the-hackers-doj-fbi-take-down-hive-ransomware-after-spending-months-inside-gang-systems) | 2026-11-11 | Reported |
| 145 | MITRE ATT&CK, group G0102 Wizard Spider | [attack.mitre.org/groups/G0102](https://attack.mitre.org/groups/G0102/) | 2026-11-11 | Confirmed |
| 146 | MITRE ATT&CK, group G1046 Storm-1811 | [attack.mitre.org/groups/G1046](https://attack.mitre.org/groups/G1046/) | 2026-11-11 | Confirmed |
| 147 | MITRE ATT&CK, software S1073 Royal | [attack.mitre.org/software/S1073](https://attack.mitre.org/software/S1073/) | 2026-11-11 | Confirmed |
| 148 | MITRE ATT&CK, software S1202 LockBit 3.0 | [attack.mitre.org/software/S1202](https://attack.mitre.org/software/S1202/) | 2026-11-11 | Confirmed |
| 149 | MITRE ATT&CK, software S1068 BlackCat | [attack.mitre.org/software/S1068](https://attack.mitre.org/software/S1068/) | 2026-11-11 | Confirmed |
| 150 | MITRE ATT&CK, group G0092 TA505 | [attack.mitre.org/groups/G0092](https://attack.mitre.org/groups/G0092/) | 2026-11-11 | Confirmed |
| 151 | MITRE ATT&CK, group G1024 Akira | [attack.mitre.org/groups/G1024](https://attack.mitre.org/groups/G1024/) | 2026-11-11 | Confirmed |
| 152 | MITRE ATT&CK, software S1212 RansomHub | [attack.mitre.org/software/S1212](https://attack.mitre.org/software/S1212/) | 2026-11-11 | Confirmed |
| 153 | MITRE ATT&CK, group G1040 Play | [attack.mitre.org/groups/G1040](https://attack.mitre.org/groups/G1040/) | 2026-11-11 | Confirmed |
| 154 | MITRE ATT&CK, software S1244 Medusa Ransomware | [attack.mitre.org/software/S1244](https://attack.mitre.org/software/S1244/) | 2026-11-11 | Confirmed |
| 155 | MITRE ATT&CK, group G1015 Scattered Spider | [attack.mitre.org/groups/G1015](https://attack.mitre.org/groups/G1015/) | 2026-11-11 | Confirmed |
| 156 | MITRE ATT&CK, group G1050 Water Galura | [attack.mitre.org/groups/G1050](https://attack.mitre.org/groups/G1050/) | 2026-11-11 | Confirmed |
| 157 | MITRE ATT&CK, group G1032 INC Ransom, with the other RaaS-era objects checked the same day | [attack.mitre.org/groups/G1032](https://attack.mitre.org/groups/G1032/) | 2026-11-11 | Confirmed |
| 158 | MITRE ATT&CK, software S0449 Maze | [attack.mitre.org/software/S0449](https://attack.mitre.org/software/S0449/) | 2026-11-11 | Reported (ATT&CK's summary of vendor reporting) |
| 159 | MITRE ATT&CK, technique T1657 Financial Theft | [attack.mitre.org/techniques/T1657](https://attack.mitre.org/techniques/T1657/) | 2026-11-11 | Confirmed |
| 160 | MITRE ATT&CK, technique T1685 Disable or Modify Tools (Defense Impairment) | [attack.mitre.org/techniques/T1685](https://attack.mitre.org/techniques/T1685/) | 2026-11-11 | Confirmed |
| 161 | TeamStarWolf library data on main: `data/attack/` (technique profiles, groups, software, campaigns, superseded_by, technique_to_d3fend), `data/attack/ics/technique_profiles.jsonl`, `data/weaknesses/` (CWE and CAPEC) and the generated `mitre/` pages | [github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack](https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack) | 2026-11-11 | Confirmed |

Not opened: the Justice Department's LockBit release of February 2024 (bot check; its Wayback snapshot returned 403), the FBI's Colonial Pipeline statement (403), the State Department's ALPHV and LockBit reward pages (error pages), Europol's Cronos release (script-rendered, no body text), NHS England's Synnovis page (empty), Asahi's own statements (not found in its newsroom), the NCA's July 2025 retail-arrests release, the HHS releases on the performance goals and the Lehigh Valley settlement (403), and the Costa Rican emergency decree in La Gaceta.

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Threat Actors](/THREAT_ACTORS.md)
- [Malware Families](/MALWARE_FAMILIES.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [CVE Reference](/CVE_REFERENCE.md)
- [Ransomware Defense Reference](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Edge Device Security](/EDGE_DEVICE_SECURITY_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md)
- [Identity and Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)
- [Healthcare Security Reference](/HEALTHCARE_SECURITY_REFERENCE.md)
- [ICS and OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md)
- [Threat Report Almanac](/THREAT_REPORT_ALMANAC.md)
- [ATT&CK Software Reference](/ATTACK_SOFTWARE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md)
- [CAPEC Reference](/CAPEC_REFERENCE.md)
- [D3FEND Reference](/D3FEND_REFERENCE.md)
- Case studies: [Russia-Attributed Threat Actors](/case-studies/THREAT_ACTORS_RUSSIA.md), [The SharePoint ToolShell Mass Exploitation](/case-studies/SHAREPOINT_TOOLSHELL_2025.md), [The Change Healthcare Attack of 2024](/case-studies/CHANGE_HEALTHCARE_2024.md), [The Cl0p MOVEit Breach](/case-studies/CL0P_FILE_TRANSFER_2023.md), [The Year 2019 in Intrusions](/case-studies/CHRONICLE_2019.md), [The Year 2020 in Intrusions](/case-studies/CHRONICLE_2020.md), [The Year 2021 in Intrusions](/case-studies/CHRONICLE_2021.md), [North Korea-Attributed Threat Actors](/case-studies/THREAT_ACTORS_NORTH_KOREA.md), [Healthcare Threat Actor Watchlist, 2023 to 2026](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md), [Operation Exchange Marauder](/case-studies/EXCHANGE_MARAUDER_2021.md), [ICS Attacks and Advisories, 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), [China-Attributed Threat Actors](/case-studies/THREAT_ACTORS_CHINA.md), [AI Threats in the Cybersecurity Industry](/case-studies/AI_THREATS_2026.md), [Log4Shell](/case-studies/LOG4SHELL.md), [SolarWinds and SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Groups: [G0102 Wizard Spider](/mitre/groups/G0102.md), [G0092 TA505](/mitre/groups/G0092.md), [G0115 GOLD SOUTHFIELD](/mitre/groups/G0115.md), [G1015 Scattered Spider](/mitre/groups/G1015.md), [G1024 Akira](/mitre/groups/G1024.md), [G1040 Play](/mitre/groups/G1040.md), [G1046 Storm-1811](/mitre/groups/G1046.md), [G1050 Water Galura](/mitre/groups/G1050.md), [G1051 Medusa Group](/mitre/groups/G1051.md), [G1032 INC Ransom](/mitre/groups/G1032.md), [G0119 Indrik Spider](/mitre/groups/G0119.md)
- Software: [S0575 Conti](/mitre/software/S0575.md), [S0446 Ryuk](/mitre/software/S0446.md), [S0266 TrickBot](/mitre/software/S0266.md), [S1202 LockBit 3.0](/mitre/software/S1202.md), [S1199 LockBit 2.0](/mitre/software/S1199.md), [S1068 BlackCat](/mitre/software/S1068.md), [S0611 Clop](/mitre/software/S0611.md), [S1070 Black Basta](/mitre/software/S1070.md), [S1073 Royal](/mitre/software/S1073.md), [S1129 Akira](/mitre/software/S1129.md), [S1162 Playcrypt](/mitre/software/S1162.md), [S1212 RansomHub](/mitre/software/S1212.md), [S1244 Medusa Ransomware](/mitre/software/S1244.md), [S1242 Qilin](/mitre/software/S1242.md), [S0496 REvil](/mitre/software/S0496.md), [S0449 Maze](/mitre/software/S0449.md)
- Campaigns: [C0015](/mitre/campaigns/C0015.md), [C0018](/mitre/campaigns/C0018.md), [C0029 Cutting Edge](/mitre/campaigns/C0029.md)
- Techniques: [T1486 Data Encrypted for Impact](/mitre/techniques/T1486.md), [T1490 Inhibit System Recovery](/mitre/techniques/T1490.md), [T1657 Financial Theft](/mitre/techniques/T1657.md), [T1133 External Remote Services](/mitre/techniques/T1133.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1219 Remote Access Tools](/mitre/techniques/T1219.md), [T1567.002 Exfiltration to Cloud Storage](/mitre/techniques/T1567-002.md), [T1685 Disable or Modify Tools](/mitre/techniques/T1685.md)
- Mitigations: [M1032 Multi-factor Authentication](/mitre/mitigations/M1032.md), [M1053 Data Backup](/mitre/mitigations/M1053.md), [M1030 Network Segmentation](/mitre/mitigations/M1030.md), [M1051 Update Software](/mitre/mitigations/M1051.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [ransomware-ecosystem-2019-2026.json on GitHub](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/ransomware-ecosystem-2019-2026.json)
