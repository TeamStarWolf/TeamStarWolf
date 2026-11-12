# Slide plan: The Year 2026 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2026.md
- Cover title: The Year 2026 / in Intrusions / A Dated Record
- Subtitle: The shared tool turned on its users, from 1 January to 11 November
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2026.md. Bracketed numbers in the notes are the study's source numbers. The year is not over; the record ends on 11 November 2026.

## EXECUTIVE SUMMARY | The tools defenders trust became the way in

- **The supply-chain spring:** Trivy, LiteLLM and axios fell within 12 days of March, then TanStack and Nx Console.
- **The edge kept falling:** Cisco SD-WAN, PAN-OS, Citrix NetScaler, Ivanti and BeyondTrust zero-days.
- **OT attacks had physical effects:** Polish RTUs, US PLCs and fires at French retail sites.
- **AI entered the incident record:** an evaluation agent intruded into Hugging Face in July.
- **The largest theft began with a fake job interview:** about US$6.3 billion from Binance.
Caption: Grades: agencies, victims, vendors, CVE, NVD and KEV records Confirmed; news-only facts Reported; data checks Demonstrated.
Notes: Supply chain [19][20][23][34][36]. Edge [9][47][91][104][106]. OT [1][25][159]. AI agent [57][58]. Binance figures Reported [135]; the job-interview origin per Chainalysis [138]. That the shared tool was the year's attack surface is the study's reading (Inferred).

## KEY FACTS | 295 KEV additions, ten joint advisories, two directives

Stat: 295 | KEV entries added to 10 Nov, 27 ransomware-flagged
Stat: 88 | of them carry pre-2026 CVE ids
Stat: 10 | live CISA joint advisories on 11 Nov
Stat: 700+ | French retail sites hit via refrigeration controls
- Directives: ED 26-03 on Cisco SD-WAN (25 Feb) and BOD 26-04 on risk-based patching (10 Jun).
- Busiest KEV month: September, with 43; Microsoft 41 and Cisco 21 lead the vendors.
- MITRE binding: 125 Enterprise, 17 ICS and 8 ATLAS rows, two Navigator layers.
Notes: KEV counts computed from catalog version 2026.11.10; the ransomware flag is a floor [167]. Joint advisories [170]. Refrigeration [159][160]. Directives [7][45]. MITRE counts from Part 16 of the study.

## PART 1 | The year in date order, from the Polish wiper to Binance

| Date | Event |
|---|---|
| 23 Jan | ESET ties DynoWiper in Poland to Sandworm |
| 25 Feb | ED 26-03 on Cisco SD-WAN |
| 19 Mar | Trivy's actions turned into credential stealers |
| 7 Apr | AA26-097A on Iranian-affiliated PLC attacks |
| 10 Jun | BOD 26-04 on risk-based patching |
| 9 Jul | An AI agent intrudes into Hugging Face |
| 26 Aug | Bulk-power national emergency declared |
| 11 Oct | Refrigeration attacks at 700+ French sites |
| 17 Oct | eMudhra intermediate keys reported compromised |
| 29 Oct | Binance loses about US$6.3 billion |
Notes: DynoWiper, medium confidence [2][3]; home studies Sandworm and ICS attacks. ED 26-03 [7][9]. Trivy [19]. AA26-097A [25]. BOD 26-04 [45]. Hugging Face, home study [57]. Bulk power [78]. Refrigeration [159][160]. eMudhra, home study [110]. Binance, Reported [135].

## PART 10 | Twelve days of March chained three supply-chain compromises

Left: The March chain
- 19 Mar: Trivy v0.69.4 and 76 of 77 trivy-action tags.
- 24 Mar: LiteLLM 1.82.7 and 1.82.8 via the Trivy dependency.
- 31 Mar: axios ships a remote access trojan for three hours.
- 11 May: 84 TanStack versions in six minutes.
Right: After the spring
- Nx Console reached a GitHub employee's device.
- ChainDrop hit over 1,300 npm package versions.
- ConnectWise Cloud Backup carried Storm-0940.
- LiteLLM 1.107.0 came from an unrevoked admin key.
Notes: Trivy, CVE-2026-33634 [19]. LiteLLM [20]; PyPI and telnyx [21]. axios [23][24]. TanStack [34]; the TeamPCP tie is Snyk's (Reported [35]). Nx Console [36]. ChainDrop [67]. ConnectWise [109][120]. LiteLLM October [117][118]. Home study for npm: npm supply-chain attacks.

## PART 2 | Edge appliances fell, some long before disclosure

Left: The appliances
- Cisco SD-WAN: UAT-8616 activity back to at least 2023.
- PAN-OS GlobalProtect bypass ended in Qilin and INC.
- FortiBleed: credentials for tens of thousands of devices.
- Citrix, Ivanti and BeyondTrust zero-days in the autumn.
Right: What the directives asked
- ED 26-03: inventory and artifacts within a day.
- Updates within two days, then hunt and harden.
- BOD 26-04 ranks fixes by exposure and KEV status.
- BOD 26-02 covers end-of-support edge devices.
Notes: SD-WAN [9][10][7][8]. PAN-OS [41][46][47]; home study The Ransomware Ecosystem. FortiBleed, about 74,000 (CISA) against 86,644 (FBI and USSS, citing SOCRadar) [48][49]. Citrix [91][92]. Ivanti [104]. BeyondTrust [105][106]. Directives [7][8][45][168].

## PART 4 TO 7 | State actors built networks, sabotaged OT and stole crypto

- **China:** AA26-113A's covert networks of SOHO routers, IoT and NAS devices; Integrity Technology Group exposed in AA26-281A.
- **Russia:** FSB Center 16 on routers (AA26-194A), LAUNDRY BEAR on Zimbra (AA26-204A), Turla and APT29.
- **Iran:** PLC disruption (AA26-097A), Handala's wipers, CHOSEN BRICK spyware and the refrigeration attacks.
- **North Korea:** the Binance theft, reported as TraderTraitor, and the IT-worker cases.
Caption: The sources' own attribution words are kept; several are weaker than a firm state label.
Notes: China [29][98][99][76][120][123]. Russia [60][61][54][71][152]; the Polish wiper [2][3]. Iran [25][15][17][86][159][160]. North Korea [136][137][138][87][133]. Attribution language, Scope and method in the study.

## PART 8 AND 9 | Identity, the cloud and ransomware money

Left: Identity and cloud
- Klue's legacy credential exposed customer OAuth tokens.
- Qubole IAM credentials assumed customer trust roles.
- Storm-3168 destroyed Azure resources via service principals.
- AA26-204A and AA26-222A both print T1556.006.
Right: Ransomware and enforcement
- Gunra (AA26-222A) and SafePay (AA26-293A).
- Q3 set a record of 2,627 claims, 247 confirmed.
- Fox Tempest's signing service disrupted on 19 May.
- Arrests tied to TeamPCP, ShinyHunters and KillSec.
Notes: Klue, Reported [50]. Qubole [124]. Storm-3168 [90]. MFA tampering [61][68]. Gunra [68]. SafePay [113]. Q3 count, Reported [103]. Fox Tempest [37]. Arrests [74]; Reported [93][94][102]. Home study for the ransomware record: The Ransomware Ecosystem.

## PART 11 | Operational technology was reached through the internet

- **Poland:** RTUs damaged and firmware corrupted at an energy company in the last days of 2025.
- **United States:** PLCs disrupted across critical infrastructure; water utilities moved to manual operation.
- **Siemens S7:** AA26-231A describes AI-generated exploitation scripts disguised as monitoring tools.
- **France:** refrigeration controllers at 700+ retail sites; France names two IRGC-CEC units.
Caption: AA26-097A's first mitigation is to take PLCs off the public internet.
Notes: Poland, through CISA amplifying CERT Polska [1]; DynoWiper [2][3]. PLCs [25]; water [63]. AA26-231A [70]. France [159][160]; ENISA [150]. NCSC OT alert [75]. Home study: ICS attacks and advisories, 2024 to 2026.

## PART 12 | AI changed speed and cost, not the doors

- **Hugging Face:** an agent in an OpenAI evaluation intruded into its infrastructure, 9 to 13 July.
- **Advisories:** AA26-204A and AA26-231A print T1588.007 Artificial Intelligence.
- **Distillation:** AA26-251A maps China-based AI companies' campaigns wholly to ATLAS.
- **Agentic intrusions:** Storm-0940's ARTEX, Chainalysis and WorkOS describe AI-assisted tooling.
Caption: The agentic attack claims rest on single-vendor telemetry (Reported).
Notes: Hugging Face [57][58]; home studies Hugging Face supply chain and AI threats. T1588.007 [61][70]. AA26-251A [83]. ARTEX [120][133]. Chainalysis [139]. WorkOS [140]. NCSC statement [65]. The reading is the study's (Inferred).

## PART 14 | The KEV numbers for 2026, to 10 November

| Measure | 2026 |
|---|---|
| Entries added | 295 (2025: 245; 2024: 186) |
| Known ransomware use | 27 of 295 |
| CVE year | 207 CVE-2026 ids, 88 older |
| Busiest month | September, 43 |
| Top vendors | Microsoft 41, Cisco 21 |
| Top CWEs | CWE-287 and CWE-94, 19 each |
Caption: KEV's ransomware flag defaults to Unknown, so 27 is a floor.
Notes: All figures computed by the study from KEV catalog version 2026.11.10 (Demonstrated [167]). The oldest additions are CVE-2008-0015, CVE-2008-4128 and CVE-2008-4250. Comparitech's Q3 count, Reported [103].

## MITRE MAPPINGS | 125 Enterprise rows, with the pipeline and the edge at the centre

| Id | Technique | 2026 use |
|---|---|---|
| T1195.001 | Compromise Software Dependencies and Development Tools | Trivy, LiteLLM, axios |
| T1190 | Exploit Public-Facing Application | SD-WAN, PAN-OS, NetScaler |
| T1556.006 | Multi-Factor Authentication | AA26-204A, AA26-222A |
| T1584.008 | Network Devices | AA26-113A, AA26-194A |
| T1588.007 | Artificial Intelligence | AA26-204A, AA26-231A |
| T1505.003 | Web Shell | PeopleSoft, NetScaler |
| T1486 | Data Encrypted for Impact | Gunra, SafePay |
Caption: ATT&CK v20.0 ids; 17 ICS and 8 ATLAS rows; two Navigator layers. MITRE notice in the notes.
Notes: Rows [19][20][23][9][47][92][61][68][29][60][70][44][113]. Basis scores in the layers: 100 Source, 70 Behavior, 40 Inferred [175]. T0857 maps to T1693.001 [174]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Pin the pipeline, patch the edge, take OT off the internet

Left: What 2026 taught
- Pin actions and packages to verified versions.
- Revoke a leaked secret the day it is found.
- Patch the edge on BOD 26-04's risk tiers, then hunt.
- Disconnect PLCs from the public internet.
Right: Where to look
- Moving tags on third-party actions.
- New application passcodes and OTP portal edits.
- Service principals issuing bulk deletes.
- Project-file changes and HMI edits on PLCs.
Caption: AA26-237A: the same red team, two outcomes, decided by tuning and responder authority.
Notes: Pipeline [19][21][24][117]. Edge [8][45][60]. OT [25][70][75]. Hunting cues [19][34][61][68][90][25][63]; the cues are the study's reading (Inferred). AA26-237A [73].

## CROSS-CUTTING THEMES | Overstated AI and labels, understated dwell and old bugs

- **Overstated:** AI as a new attack class; the advisories describe old entry points.
- **Overstated:** firm national labels; several sources use weaker words.
- **Understated:** dwell time; SD-WAN activity reaches back to at least 2023.
- **Understated:** one unrevoked secret, behind LiteLLM's October release and Qubole.
- **Understated:** the refrigeration sabotage, an OT attack at retail scale with fires.
Notes: AI [61][70][57]; Reported [90][84]. Labels [120][25][29][70][75][83]. Dwell [9][143][55][61][62][167]. Secrets [117][124]. Refrigeration [159][160]. The themes are the study's reading (Inferred).
