# Slide plan: The Ransomware Ecosystem: The Public Record, 2019 to 2026

- Study: case-studies/RANSOMWARE_ECOSYSTEM.md
- Cover title: The Ransomware Ecosystem / The Public Record / 2019 to 2026
- Subtitle: A criminal industry of specialists, read from advisories, sanctions and filings
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/RANSOMWARE_ECOSYSTEM.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Ransomware stopped being a virus and became an industry

- In October 2020 three US agencies warned hospitals that loaders were handing their networks to Ryuk and Conti operators.
- By 2021 five agencies in three countries described a professional market of developers, affiliates and paid services.
- Colonial Pipeline halted operations on 7 May 2021; Ireland's health service found 80 percent of its environment encrypted a week later.
- The way in is usually ordinary: remote access without MFA, unpatched edge devices and talked-into-it help desks.
- Law enforcement now works from inside the groups, and fewer victims pay.
Caption: Grades: advisories, sanctions, court records and filings are Confirmed; industry data reports are Reported.
Notes: Hospitals [1]. Market [5]. Colonial [62][71]; HSE [83]. Entry pattern Confirmed [17][23][30][70][71], Inferred for the pattern. Hive [64], Cronos [57][58], Scattered Spider sentences [60]. Payment rates Reported [110][113][106].

## KEY FACTS | Billions paid, thousands of victims, one market

Stat: $2.1B+ | US payments reported, 2022 to 2024 (FinCEN)
Stat: ~1,700 | US LockBit attacks since 2020 (AA23-165A)
Stat: 361 | of 1,779 KEV entries flagged for ransomware use
Stat: £1.9B | Jaguar Land Rover, costliest UK event (CMC)
- Conti: over 1,000 victims and payouts over $150 million as of January 2022, by the FBI's count.
- Operation Cronos, 20 Feb 2024: the NCA took control of LockBit and obtained over 1,000 decryption keys.
- Newest advisories: Gunra (AA26-222A, 10 Aug 2026) and SafePay (AA26-293A, 20 Oct 2026).
Caption: The Cyber Monitoring Centre calls Jaguar Land Rover a malicious cyber incident, not ransomware.
Notes: FinCEN [96]. LockBit [15]. KEV catalog version 2026.11.10, counted from the feed, Confirmed and Demonstrated [32]. JLR [102]. Conti [54]. Cronos [57][58]. Gunra [29]; SafePay [30].

## PART 1 | A supply chain of specialists, not a lone gang

| Role | What the record says |
|---|---|
| Developer and operator | Builds the encryptor, runs the panel and leak site (Water Galura for Qilin) |
| Affiliate | Breaks in and deploys; LockBit's affiliates were many and unconnected |
| Initial access broker | Sells a way in; Medusa pays $100 to $1 million |
| Recruited specialist | Gunra recruits penetration testers for a share of the ransom |
| Salaried deployer | Conti likely paid deployers a wage |
| Negotiator and payment helper | Independent services negotiate, help pay and arbitrate |
| Infrastructure provider | Bulletproof hosters Zservers and Aeza Group, both sanctioned |
Caption: Of 194 LockBit affiliates the NCA identified, up to 114 never received a ransom.
Notes: Roles [156][15][27][29][4][5][50][51]. The NCA's view from inside LockBit [56]. Gunra's January 2026 program: panel, builder, lockers and documentation [29].

## PART 1 | Extortion moved from one lever to several

Left: How the pressure grew
- Maze, discovered May 2019, stole data before encrypting and posted it.
- By 2021 the agencies described triple extortion: encryption, theft and threats to customers or internet access.
- Leak sites became the shop window: Black Basta gave 10 to 12 days, RansomHub 3 to 90.
- Medusa's countdown timers let a victim pay $10,000 to add a day.
Right: Encryption became optional
- CL0P's campaigns since 2021 relied mostly on data theft.
- BianLian moved to exfiltration-only extortion by January 2024.
- Some ALPHV affiliates and Scattered Spider extort without encrypting.
- Backups do not answer an attack that only steals.
Caption: ATT&CK now covers ransom demands backed by a leak threat, and leak sites, under T1657 Financial Theft.
Notes: Maze Reported [158]. Triple extortion [5]. Leak sites [24][25][27]. CL0P [14]; BianLian [13]; ALPHV [20]; Scattered Spider [17]. Backups point Confirmed [14], Inferred for the general point. T1657 [159].

## PART 2 | Seven years of the record in ten dates

| Date | Event |
|---|---|
| 28 Oct 2020 | AA20-302A: TrickBot and BazarLoader against hospitals lead to Ryuk and Conti |
| 7 May 2021 | Colonial Pipeline halts operations; about 75 bitcoin paid |
| 2 Jul 2021 | Kaseya VSA attack, later charged as REvil |
| 26 Jan 2023 | Hive disrupted after the FBI ran inside its network |
| 27 May 2023 | CL0P begins exploiting MOVEit Transfer |
| 20 Feb 2024 | Operation Cronos takes control of LockBit |
| 21 Feb 2024 | Change Healthcare encrypted after a login without MFA |
| Late Aug 2025 | Jaguar Land Rover incident, Category 3 |
| 16 Jul 2026 | Two leading Scattered Spider members sentenced |
| 10 Nov 2026 | 361 KEV entries flagged for ransomware use |
Caption: Change Healthcare and MOVEit have their own studies in the library; this one summarizes them.
Notes: [1][62][71][33][44][63][64][14][57][58][70][102][60][32]. Home studies: CHANGE_HEALTHCARE_2024.md and CL0P_FILE_TRANSFER_2023.md.

## PART 3 | Brands die; people move

- Conti's members split into Zeon, Black Basta and Quantum, which became Royal and then BlackSuit (press reporting).
- RansomHub drew its affiliates from LockBit and ALPHV.
- Gunra appears to be built on Conti's leaked 2022 source code, by the agencies' account.
- CISA's judgment that BlackSuit is Royal rests on shared code.
- ATT&CK models most brands as software, not groups: LockBit, BlackCat and RansomHub have no group object.
Caption: A brand name is weak evidence of who is behind an attack.
Notes: Conti lineage Reported [118]. RansomHub [25]. Gunra [29]. BlackSuit [11]. ATT&CK objects [145] to [157][161]. No objects for BlackSuit, DragonForce, Rhysida, Interlock, Phobos, Ghost, Gunra or SafePay [157][161]. Inference from [11][25][118].

## PART 4 | The front door is remote access and the edge

Left: Edge devices and remote access
- Akira entered mainly through VPNs without MFA.
- Colonial's attacker used a legacy VPN profile not meant to be in use.
- LockBit 3.0 affiliates used Citrix Bleed to hijack sessions past MFA.
- Gunra exploited FortiGate authentication bypasses.
Right: People
- Scattered Spider calls help desks to reset passwords and move MFA.
- Black Basta floods inboxes, then calls offering help.
- ALPHV affiliates posed as IT staff by phone or SMS.
- Interlock uses ClickFix-style copy-paste lures.
Caption: Inside, the advisories name dual-use tools far more often than custom malware: RClone, PsExec and remote-management software.
Notes: Akira [23]. Colonial [71]. Citrix Bleed [18]. Gunra [29]. Scattered Spider [17]. Black Basta [24]. ALPHV [20]. Interlock [28]. Living off the land Inferred from [15][23][24][25][27][29][30].

## PART 5 | The CVEs the advisories name are mostly edge devices

| CVE | Product | Named with |
|---|---|---|
| CVE-2018-13379 | FortiOS SSL-VPN | LockBit, Play, Ghost |
| CVE-2023-4966 | NetScaler (Citrix Bleed) | LockBit 3.0 |
| CVE-2023-34362 | MOVEit Transfer | CL0P |
| CVE-2024-40766 | SonicWall SonicOS | Akira, SafePay |
| CVE-2024-37085 | VMware ESXi | Akira, Black Basta |
| CVE-2024-1709 | ScreenConnect | Black Basta |
| CVE-2026-0257 | PAN-OS GlobalProtect | Qilin and INC (press) |
Caption: KEV flags Ivanti flaws for ransomware use that no ransomware advisory names; the ESXiArgs CVE is not in KEV at all.
Notes: Table [15][19][26][32][18][39][14][23][30][43][24][134]. Ivanti [22][32]; Cutting Edge C0029 [161]. ESXiArgs CVE-2021-21974 [40][10]. KEV counts by vendor: Microsoft 117, Fortinet 14, SonicWall 13, Oracle 13, Ivanti 12 [32].

## PART 6 | Hospitals lead the record; schools, water and cities follow

Stat: 730 | health-sector attacks in six months to Mar 2024
Stat: 249 | health care ransomware complaints to the FBI in 2023
Stat: 80% | of Ireland's HSE environment encrypted, May 2021
- After the December 2023 disruption, ALPHV's administrator told affiliates to target hospitals.
- Water systems lost SCADA servers to ransomware in Nevada and California in 2021.
- Instructure paid a ransom in 2026; Dallas spent $8.5 million on remediation after Royal.
Caption: HHS's HIPAA Security Rule overhaul is still a proposal; final action is not expected before July 2027.
Notes: HHS HC3 [86]. IC3 2023 [94]. HSE [83]. ALPHV [20]. Water [3]. Instructure [103]. Dallas [85]. HIPAA proposal [88]; date Reported [141].

## PART 7 | Law enforcement learned to work from the inside

- **Hive:** the FBI was inside from late July 2022 and handed out keys that averted about $130 million in demands.
- **ALPHV:** a decryption tool for over 500 victims in December 2023; the brand returned, then vanished in March 2024.
- **LockBit:** Cronos showed LockBit kept victims' data after payment; active affiliates fell to 69.
- **People:** LockBitSupp, Matveev and 18 Trickbot members sanctioned; two Scattered Spider members sentenced.
- **Loaders:** Operation Endgame took down IcedID, SystemBC, Pikabot, Bumblebee and later SocGholish and Amadey servers.
Caption: Disruption works without ending the trade: LockBit kept posting victims after Cronos.
Notes: Hive [64]. ALPHV [65][20]; exit Reported [127]. Cronos [56][57][58]. Sanctions [49][47][45][46]. Sentences [60]. Endgame [67][68][69]. Post-Cronos posting Reported [105].

## PART 8 | Fewer victims pay, and every total gets revised

| Year | FinCEN (US reports) | Chainalysis (on chain) |
|---|---|---|
| 2023 | About $1.1 billion | Over $1 billion, later $1.25 billion |
| 2024 | About $734 million | $813.55 million, later $892 million |
| 2025 | not covered | Over $820 million |
Caption: Coveware's share of clients paying hit a record low in Q2 2026 and stayed near it in Q3.
Notes: FinCEN [96]. Chainalysis Reported [104][105][106]. Coveware Reported [110][111][113][114]. The two series measure different things; cite each figure with its report date (Inferred from [96][106]). Losses beyond ransoms: IC3 calls its loss rate artificially low [95].

## DEFENDER VIEW | The controls the record keeps naming

Left: Keep them out
- Phishing-resistant MFA on every VPN, remote-desktop and remote-management path.
- Patch internet-facing KEV entries within 24 to 48 hours.
- After patching an edge device, rotate its credentials and check for persistence.
- Identity checks a caller cannot talk past at the help desk.
Right: Limit the damage
- Offline, encrypted, tested backups outside the production identity plane.
- Allowlist remote-access tools and alert on new ones.
- Segment IT from OT and know what depends on what.
- Plan for data-only extortion before it happens.
Caption: Paying does not guarantee deletion: LockBit kept data from victims who paid.
Notes: MFA [31][23][70][71]. KEV clock [18]. Credential rotation [42][22]. Help desk [17], Inferred for the control. Backups [31][11]; backup targeting Reported [115]. Allowlisting [17]. Segmentation [31][71]. Data-only extortion [14][56][78].

## MITRE MAPPINGS | 52 Enterprise techniques, 3 ICS, 63 objects

| Id | Technique | Where it appears in the record |
|---|---|---|
| T1133 | External Remote Services | VPNs without MFA (Akira, Colonial, Change) |
| T1190 | Exploit Public-Facing Application | Edge and file-transfer CVEs |
| T1566.004 | Spearphishing Voice | Black Basta and Scattered Spider calls |
| T1567.002 | Exfiltration to Cloud Storage | RClone to Mega, OneDrive and Backblaze |
| T1486 | Data Encrypted for Impact | Every encrypting advisory |
| T1657 | Financial Theft | Ransom demands backed by leak sites |
Caption: Two Navigator layers, Enterprise and ICS, pinned to ATT&CK v20. MITRE notice in the notes.
Notes: Rows [71][23][70][8][24][14][17][29][30][1][159]. Groups include G0102 Wizard Spider, G0092 TA505, G1015 Scattered Spider, G1024 Akira, G1040 Play, G1046 Storm-1811, G1050 Water Galura, G1051 Medusa Group; software S0575 Conti, S1202 LockBit 3.0, S1068 BlackCat, S1070 Black Basta, S1212 RansomHub, S1242 Qilin [145] to [157][161]. ICS: T0828, T0826, T0822. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What is overstated and what is understated

Left: Overstated
- A leak-site threat as proof of theft.
- One brand, one group.
- Early attribution, such as Change Healthcare's "suspected nation-state".
- A single total for payments, or a takedown as the end.
Right: Understated
- Unreported incidents: about 20 percent of Hive victims reported.
- Theft-only extortion, which encryption metrics miss.
- Ransomware use of edge flaws seen only in KEV.
- Cost beyond the ransom: diverted ambulances and halted factories.
Caption: Concentration multiplies harm: Kaseya, CDK, Change Healthcare and RTX each turned one intrusion into a sector outage.
Notes: Ghost [26]; Byod claim Reported [136]. Brands [11][25]. Change [72][70]; Ascension Reported [140]. Totals [96][105][106]. Hive reporting Reported [144]. Theft-only [13][14]. KEV [22][32][40]. Costs [102][136][128]. Concentration [44][73][70][76].
