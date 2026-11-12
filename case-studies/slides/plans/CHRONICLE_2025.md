# Slide plan: The Year 2025 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2025.md
- Cover title: The Year 2025 / in Intrusions / A Dated Record
- Subtitle: The trusted connection became the way in
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2025.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The edge, the integration and the build pipeline opened 2025

- **The edge kept falling:** Ivanti twice, FortiOS, Cisco ASA, Citrix, SonicWall's cloud backups, F5 and Cisco AsyncOS.
- **The integration nobody watched:** stolen Drift OAuth tokens, a modified Salesforce app, a backup vendor's client secrets.
- **The build pipeline:** a compromised GitHub Action, an AI coding extension release and a self-replicating npm worm.
- **The largest theft was not ransomware:** about US$1.5 billion from Bybit, attributed by the FBI to North Korea.
- **Governments answered:** three emergency directives, sanctions, takedowns, charges and a UN convention.
Caption: Grades: agencies, victims, vendors, CVE, NVD and KEV records Confirmed; vendor estimates Reported; data checks Demonstrated.
Notes: Edge [1][28][6][98][2][91][79][125]. Integration [78][56][46]. Build pipeline [25][71][96]. Bybit [14]. Government record, Part 12 of the study [76][98][111][115].

## KEY FACTS | 245 KEV additions, 90 zero-days, three emergency directives

Stat: 245 | KEV entries added in 2025, 31 ransomware-flagged
Stat: 90 | zero-days exploited in the wild, GTIG count
Stat: 48% | of zero-days hit enterprise software and appliances
Stat: US$1.5B | stolen from Bybit, per the FBI
- Emergency directives: ED 25-02 on Exchange hybrid, ED 25-03 on Cisco ASA and Firepower, ED 26-01 on F5.
- Old bugs: 94 of the 245 KEV additions carry pre-2025 CVE ids and 23 carry pre-2020 ids.
- MITRE binding: 122 Enterprise and 3 ICS technique rows, 53 objects with library pages, two Navigator layers.
Notes: KEV counts computed from catalog version 2026.11.10; the ransomware flag is current, not as listed [2]. GTIG [130]. Bybit [14]. Directives [76][98][111]. MITRE counts from Part 15 of the study.

## PART 1 | The year in date order, from FortiOS to the UN convention

| Date | Event |
|---|---|
| 14 Jan | FortiOS CVE-2024-55591 exploited; KEV the same day |
| 21 Feb | About US$1.5 billion stolen from Bybit |
| 11 Mar | reviewdog compromised, then tj-actions |
| 21 May | Lumma disrupted; AA25-141A on APT28 |
| 7 Jul | SharePoint ToolShell exploitation begins |
| 8 Aug | UNC6395 uses stolen Drift OAuth tokens |
| 27 Aug | AA25-239A on Salt Typhoon-linked actors |
| Sep | The Shai-Hulud worm on npm |
| 25 Sep | ED 25-03 on Cisco ASA and Firepower |
| 15 Oct | F5 files its 8-K; ED 26-01 |
| 25 Oct | UN Convention against Cybercrime opens for signature |
Notes: FortiOS [6][2]. Bybit [14]. tj-actions [25][24]. Lumma [41][42]; APT28 [44]. ToolShell, home study [63][64]. Drift [78]. AA25-239A [85]. Shai-Hulud, home study npm supply-chain attacks [96]. ED 25-03 [98]. F5 [79][111]. UN [115].

## PART 2 | The edge appliances fell, and fixes did not end the compromise

Left: The appliances
- Ivanti Connect Secure: zero-days from mid-December 2024 and mid-March.
- Cisco ASA: read-only memory altered to persist through reboot.
- F5: BIG-IP source code and vulnerability information taken.
- SonicWall: cloud backups of all service users accessed.
Right: What the record asked
- Run both integrity checks; factory reset on failure.
- Core dumps within a day, then a hard power removal.
- Prove the patch: some were below the fixed versions.
- Disconnect devices past end of support.
Notes: Ivanti [1][28]. Cisco ASA [98][99][101][119]. F5 [79][111][112]. SonicWall [91]. Juniper and UNC3886 [22]. Citrix [2][128]. Cisco AsyncOS [125]. Static Tundra [82].

## PART 3 | The server and application year put old flaws beside new ones

| CVE | Product | What happened | KEV added |
|---|---|---|---|
| CVE-2025-0282 | Ivanti Connect Secure | Stack-based overflow, zero-day | 2025-01-08 |
| CVE-2025-31324 | SAP NetWeaver | Unrestricted file upload | 2025-04-29 |
| CVE-2025-53770 | SharePoint | Deserialization, ToolShell | 2025-07-20 |
| CVE-2025-10035 | GoAnywhere MFT | Deserialization, Medusa affiliate | 2025-09-29 |
| CVE-2025-61882 | Oracle E-Business Suite | Zero-day, Cl0p-branded extortion | 2025-10-06 |
| CVE-2025-59287 | WSUS | Deserialization, CVSS 9.8 | 2025-10-24 |
| CVE-2025-55182 | React Server Components | Remote code execution, CVSS 10.0 | 2025-12-05 |
Caption: Exchange hybrid CVE-2025-53786 and SharePoint CVE-2025-53771 are not in KEV.
Notes: Rows [1][2][128][114][63][65][93][94][80][107][113][123]. ToolShell, home study SharePoint ToolShell [63]. Exchange hybrid [76]. The KEV dates and ransomware flags from catalog 2026.11.10 [2].

## PART 4 | China sat in telecom backbones; its contract hackers were charged

- **Salt Typhoon-linked actors** compromised backbone routers worldwide with known CVEs; no zero-days were observed (AA25-239A).
- **The contract hackers:** the DOJ charged eight i-Soon employees, two MPS officers and APT27 actors on 5 March.
- **Silk Typhoon** shifted to the IT supply chain and used stolen API keys to reach customer tenants.
- **Sanctions** on Integrity Technology Group, Sichuan Juxinhe and Yin Kecheng.
- **BRICKSTORM** gave PRC state-sponsored actors long-term persistence (CISA, NSA and the Canadian Cyber Centre).
Caption: The AI-orchestrated campaign Anthropic disrupted is told in the AI threats study.
Notes: AA25-239A [85][86]. Charges [17]. Silk Typhoon [19]. Sanctions [3][4]. BRICKSTORM [124]. UNC3886 [22]. AI campaign, home study AI threats [103]. Wider record, home study China-attributed actors.

## PART 5 | Russia targeted aid logistics, old routers and embassies

Left: Military and security services
- APT28 targeted Western logistics and IT firms aiding Ukraine.
- FSB Center 16 exploited a 2018 Cisco Smart Install flaw.
- Secret Blizzard delivered ApolloShadow to embassies in Moscow.
- PathWiper hit a Ukrainian critical infrastructure entity.
Right: Hacktivists and OT
- AA25-343A: pro-Russia hacktivists reached OT through VNC.
- Impacts included physical damage.
- Water, food and agriculture, and energy were named.
- Poland's December wiper attacks are campaign C0063.
Notes: APT28 [44]. Static Tundra [82][81]. Secret Blizzard [73]. PathWiper [50]. Hacktivists, home study ICS attacks and advisories [126]. Poland [134]. Wider record, home studies Russia-attributed actors and Sandworm.

## PART 6 | North Korea took US$1.5 billion; Iran was a warning

- **Bybit:** the FBI attributes the theft of about US$1.5 billion to North Korea and calls the activity TraderTraitor, not Lazarus.
- **The IT workers:** coordinated DOJ actions on 30 June against North Korean remote IT worker schemes.
- **Iran:** CISA, the FBI, DC3 and NSA warned that Iranian actors may target US networks, with no coordinated campaign observed then.
Caption: Chainalysis's "largest digital heist" is its own ranking (Reported).
Notes: Bybit [14]; Chainalysis Reported [15]. IT workers [59]. Iran [58]. Home studies North Korea-attributed actors and Iran-attributed actors.

## PART 7 | Identity, SaaS and the help desk were the new perimeter

- **UNC6040** talked staff into authorizing a modified Salesforce Data Loader app, including at Google.
- **UNC6395** exported Salesforce data with OAuth tokens stolen from the Salesloft Drift app; not a Salesforce flaw.
- **Commvault Metallic** client secrets may have been taken.
- **Coinbase and Discord:** an actor paid Coinbase's overseas support staff; Discord's customer-service vendor was compromised.
- **Scattered Spider** impersonated staff to the help desk to reset passwords and MFA.
Caption: Storm-0501 destroyed data and backups with cloud-native capabilities, without traditional ransomware.
Notes: UNC6040 [56][90]. Drift [78]. Commvault [46]. Coinbase [39]. Discord [105]. Scattered Spider [72][92]. Storm-0501 [87]. The cloud security incidents study is the intended home for the SaaS record.

## PART 8 | Ransomware advisories, filings and takedowns

Left: The advisories
- Ghost (Cring) entered through flaws from 2009 to 2021.
- Medusa: over 500 victims by April 2026.
- Interlock used drive-by compromise and ClickFix.
- Akira: about US$244.17 million in claimed proceeds.
Right: Enforcement and the money
- Operation Endgame hit droppers in May and November.
- Lumma: about 2,300 domains seized under court order.
- Garantex taken down; Grinex designated.
- UK plan to ban public-sector ransom payments.
Notes: Ghost [13]. Medusa [23]. Interlock [69]. Akira [120]. Endgame [45][117]. Lumma [41][42]. Garantex [21][77]. UK [70]. IC3 [131]. Victims' 8-K filings, Part 8 of the study. Home study for the ransomware record: The Ransomware Ecosystem.

## PART 9 | The build pipeline ran on tokens

- **tj-actions and reviewdog:** a compromised GitHub Action leaked secrets into public build logs.
- **Amazon Q Developer:** an over-scoped token let an outsider's code into release v1.84.
- **Nx:** malicious releases collected credentials, abusing AI coding CLIs.
- **Shai-Hulud:** a worm republished over 500 npm packages and returned in November with a destructive fallback.
- **F5:** a theft of source code and knowledge, not a poisoned update.
Caption: The pattern is SaaS-to-SaaS OAuth trust and token scoping in CI (Inferred).
Notes: tj-actions [25][24]. Amazon Q [71]. Nx [84]; Snyk Reported [89]. Shai-Hulud, home study npm supply-chain attacks [96][122]. F5 [112]. Pattern [78][46][25][71][83].

## PART 12 | Governments used directives, sanctions, charges and treaties

- **Three emergency directives:** ED 25-02, ED 25-03 and ED 26-01.
- **Sanctions:** Integrity Technology Group, Sichuan Juxinhe, Zservers, Funnull, Aeza Group, Garantex and Grinex, Media Land.
- **US orders:** EO 14144 on secure software attestations, amended by EO 14306.
- **The UK:** ransomware payment measures and the Cyber Security and Resilience Bill.
- **The UN:** the Convention against Cybercrime opened for signature in Hanoi.
Notes: Directives [76][98][119][111]. Sanctions [3][4][12][18][47][60][77][121]. Orders [7][53]. UK [70][109][118]. UN [115]. AI and the attacker, home study AI threats [75][103][116].

## MITRE MAPPINGS | 122 Enterprise rows, edge entry and stolen trust at the centre

| Id | Technique | 2025 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Ivanti, SharePoint, GoAnywhere |
| T1199 | Trusted Relationship | Discord's vendor, Salesforce |
| T1566.004 | Spearphishing Voice | Scattered Spider, UNC6040 |
| T1528 | Steal Application Access Token | Salesloft Drift tokens |
| T1195.001 | Compromise Software Dependencies and Development Tools | tj-actions, Nx, Shai-Hulud |
| T1542.001 | System Firmware | Cisco ASA read-only memory |
| T1486 | Data Encrypted for Impact | Medusa, Interlock, Akira |
Caption: ATT&CK v20.0 ids; revoked advisory ids mapped through superseded_by.jsonl; two Navigator layers. MITRE notice in the notes.
Notes: Rows from Part 15 of the study [85][72][105][78][56][25][96][98][23][69][120]. Basis scores in the layers: 100 Source, 70 Behavior, 40 Inferred. T1562.001 maps to T1685, T1562.004 to T1686, T1656 to T1684.001 and T1070.001 to T1685.005 [132]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Prove the patch, govern integrations, pin the pipeline

Left: What 2025 taught
- Patch the edge on the KEV clock, then prove the patch.
- Isolate the network-device management plane.
- Treat integration tokens and client secrets as credentials.
- Pin actions and packages; scope CI tokens to the job.
Right: Where to look
- Integrity-check failures and configuration exports on appliances.
- New connected apps and bulk API exports from CRM tenants.
- Phone-requested MFA resets followed by new devices.
- Workflows that print secrets; unpinned third-party actions.
Caption: Offline, immutable backups keep recovery out of reach of a compromised cloud identity.
Notes: Recommendations [98][119][1][85][78][46][25][96][71], with the generalizations Inferred. Hunting cues [1][85][82][98][56][78][72][25][84]; the cues are the study's reading. Backups [72][87].

## CROSS-CUTTING THEMES | Headlines overstated some breaches and understated old flaws

- **Overstated:** "Salesforce was breached"; GTIG says the Drift theft was not a platform flaw.
- **Overstated:** F5 as a supply chain compromise, Bybit as a Lazarus operation, and autonomous AI attacks.
- **Understated:** old vulnerabilities; 94 of 245 KEV additions carry pre-2025 ids.
- **Understated:** incident counts, which the NCSC says are not mandatory to report.
- **Understated:** incomplete patching; CISA found Cisco ASA owners below the fixed versions.
Notes: Salesforce [78][56]. F5 [112]. Bybit [14][15]. AI [103][116]. Old flaws [2][85][81][13]. Counts [110][131]. Patching [119]. The themes are the study's reading (Inferred).
