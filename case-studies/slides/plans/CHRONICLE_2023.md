# Slide plan: The Year 2023 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2023.md
- Cover title: The Year 2023 / in Intrusions / A Dated Record
- Subtitle: The edge gave way, and identity and sessions decided the year
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2023.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The edge gave way, and stolen sessions outlived the patches

- **Edge and file-transfer products fell:** GoAnywhere, Barracuda ESG, MOVEit, NetScaler, Ivanti, Cisco IOS XE.
- **Patching was not enough:** Barracuda told customers to replace exploited appliances, whatever their patch level.
- **Identity was the second story:** forged tokens, Citrix Bleed sessions, Okta's support files, help-desk calls.
- **State actors pre-positioned:** Volt Typhoon in US critical infrastructure, CyberAv3ngers on water PLCs.
- **Police went after infrastructure:** Hive, Genesis Market, QakBot and Ragnar Locker were taken down.
Caption: Grades: agencies, victims, vendors, CVE, NVD and KEV records Confirmed; vendor annual estimates Reported; data checks Demonstrated.
Notes: Edge [4][25][30][44][45][62]. Barracuda replacement order [26]. Identity [35][69][65][77]. Pre-positioning [28][29][79]. Takedowns [96][98][51][100]. That edge devices were the main way in is the study's reading (Inferred).

## KEY FACTS | 187 KEV additions, 97 zero-days, over a billion in ransom

Stat: 187 | KEV entries added in 2023, 121 of them 2023 ids
Stat: 97 | zero-days exploited in the wild (TAG and Mandiant)
Stat: $1B+ | ransomware payments, a Chainalysis estimate
Stat: 123 | Enterprise technique rows, plus 12 ICS
- Storm-0558 reached about 25 organizations per Microsoft, 22 per the CSRB.
- AA24-317A's most exploited list is led by Citrix, Cisco, FortiOS and MOVEit flaws.
- IC3 counted adjusted ransomware losses just over $59.6 million, which it calls artificially low.
Notes: KEV counts computed from catalog version 2026.11.10 [89]. Zero-days [116]. Chainalysis, Reported [88]. Storm-0558 [35][39]. Most exploited [115]. IC3 [120]. MITRE binding counts from Part 13 of the study.

## PART 1 | The year in date order, from GoAnywhere to the water PLCs

| Date | Event |
|---|---|
| 18 Jan | GoAnywhere MFT zero-day in use |
| 26 Jan | Hive infrastructure shut down |
| 14 Mar | Outlook CVE-2023-23397 patched |
| 30 Mar | 3CX warns of a trojanized desktop app |
| 15 May | Storm-0558 starts using forged tokens |
| 24 May | AA23-144A on Volt Typhoon |
| 27 May | MOVEit Transfer first exploited |
| 26 Jul | SEC adopts incident disclosure rules |
| 10 Oct | Citrix Bleed fixed; Rapid Reset in KEV |
| 22 Nov | CyberAv3ngers reach Unitronics PLCs |
Notes: GoAnywhere [4]. Hive [96]. Outlook [12][89]. 3CX [15][18]. Storm-0558 [35]. Volt Typhoon [28][29]. MOVEit [30][31]. SEC [46]. Citrix Bleed and Rapid Reset [69][89][48]. CyberAv3ngers [78][79]. MGM and Caesars [57][56].

## PART 2 | The edge-device and file-transfer year

| CVE | Product | What happened | KEV added |
|---|---|---|---|
| CVE-2023-0669 | GoAnywhere MFT | Zero-day from 18 Jan | 2023-02-10 |
| CVE-2023-2868 | Barracuda ESG | Exploited from Oct 2022 | 2023-05-26 |
| CVE-2023-34362 | MOVEit Transfer | SQL injection, Cl0p | 2023-06-02 |
| CVE-2023-3519 | NetScaler ADC | Zero-day in June | 2023-07-19 |
| CVE-2023-35078 | Ivanti EPMM | Zero-day from April | 2023-07-25 |
| CVE-2023-20198 | Cisco IOS XE | Admin account creation | 2023-10-16 |
| CVE-2023-4966 | Citrix Bleed | Session hijacking | 2023-10-18 |
Caption: MOVEit's full story is told in the Cl0p file-transfer study; this deck gives it one row.
Notes: Rows [4][103][25][108][104][31][44][109][45][110][62][107][69][105][89]. Confluence, TeamCity and ActiveMQ [68][113][106][114]. Most exploited [115]. Home study: the Cl0p MOVEit breach and the file-transfer extortion playbook.

## PART 3 | China stole mail through a signing key and pre-positioned at home

Left: Espionage
- Storm-0558 forged tokens with an acquired MSA signing key.
- The State Department caught it with a mailbox access log.
- UNC4841 held Barracuda appliances from October 2022.
- UNC3886 used a VMware Tools zero-day on ESXi hosts.
Right: Pre-positioning
- Volt Typhoon lived off the land in US critical infrastructure.
- It routed traffic through small office and home devices.
- Microsoft saw capability to disrupt US to Asia links.
- BlackTech pivoted from subsidiary routers to headquarters.
Notes: Storm-0558 [35][36][38][39]. UNC4841 [27]. UNC3886 [91]. Volt Typhoon [28][29]. BlackTech [60]. Home study: China-attributed threat actors.

## PART 4 | Russia was named unit by unit, and a Sandworm outage surfaced

- **Snake:** AA23-129A attributed it to a known unit within FSB Center 16 (9 May).
- **Star Blizzard:** almost certainly subordinate to FSB Centre 18 (AA23-341A, 7 December).
- **The SVR:** exploited JetBrains TeamCity from late September (AA23-347A, 13 December).
- **APT28:** Jaguar Tooth on Cisco routers through an old SNMP flaw (18 April).
- **Sandworm:** Mandiant disclosed the October 2022 substation outage on 9 November.
Caption: SektorCERT reported a coordinated attack on 22 Danish energy companies through Zyxel firewalls in May.
Notes: Snake [22]. Star Blizzard [81]. SVR [82]. Midnight Blizzard Teams lures [94]. APT28 [90]. Outlook, Russia-based actor not bound to APT28 [12]. Sandworm [75]. Denmark [23]. Home studies: Russia-attributed threat actors; Sandworm.

## PART 5 | North Korea went after the supply chain, Iran after water

Left: North Korea
- The FBI tied the $100M Horizon bridge theft to Lazarus.
- 3CX was the first supply-chain attack seen to lead to another.
- JumpCloud was spear-phished; under five customers hit.
- Kimsuky posed as journalists; OFAC designated it.
Right: Iran
- CyberAv3ngers reached Unitronics PLCs at US water sites.
- The PLCs were internet-exposed with default passwords.
- Peach Sandstorm password-sprayed from February to July.
- No known risk to drinking water at the first site.
Notes: Horizon [5]. 3CX and X_TRADER [15][17][18]. JumpCloud [42][41]. Kimsuky [92][93]. CyberAv3ngers [78][79]. Peach Sandstorm [95]. Home studies: North Korea-attributed and Iran-attributed threat actors.

## PART 6 | Sessions, tokens and the help desk opened the doors

- **Citrix Bleed:** sessions stolen before the patch kept working after it.
- **Okta:** a saved service account credential opened the support case system; 134 customers' files were viewed.
- **The casinos:** Caesars disclosed social engineering of an outsourced IT support vendor.
- **Scattered Spider:** help-desk calls, SIM swaps and MFA fatigue (AA23-320A).
- **23andMe:** credential stuffing on about 14,000 accounts reached millions of profiles.
Caption: Each of these let an actor skip a login; session and token revocation answers all of them (Inferred).
Notes: Citrix Bleed [69]. Okta [64][65]. Caesars and MGM [56][57]; the MGM actor link is Reported [88]. Scattered Spider [77]. ALPHV affiliates [85]. 23andMe [66][67]. CircleCI [102].

## PART 7 | A ransomware advisory most months, and takedowns of the plumbing

- **Advisories:** ESXiArgs, Royal, LockBit 3.0, BianLian, CL0P, Truebot, Snatch, AvosLocker, Rhysida, Play, ALPHV.
- **Victims filed 8-Ks:** DISH, Clorox and Johnson Controls; the British Library was hit in October.
- **Takedowns:** Hive (January), Genesis Market (April), QakBot (August), Ragnar Locker (October).
- **Sanctions:** 18 Trickbot members and Mikhail Matveev.
- **Policy:** 50 Counter Ransomware Initiative members said governments should not pay.
Notes: Advisories [6][11][13][24][31][40][59][71][76][84][85]. Filings [9][47][61]. British Library [72][73]. Takedowns [96][98][51][52][100]. Sanctions [97][101][99]. CRI [128]. Home study for the ransomware record: The Ransomware Ecosystem.

## PART 8 | Supply chain, cloud exposure and record floods

Left: Supply chain and cloud
- 3CX, JumpCloud and CircleCI reached customers.
- Ledger Connect Kit was exploited for under two hours.
- A Microsoft SAS token exposed internal storage.
- Storm-0558 ran through the provider's own keys.
Right: Denial of service
- Storm-1359 floods hit some Microsoft services.
- Rapid Reset peaked above 201 million requests a second.
- Google mitigated a 398 million request-a-second peak.
- CVE-2023-44487 went into KEV on 10 October.
Notes: Supply chain [17][42][102][83]. SAS token [58]. Storm-0558 [39]. Storm-1359 [33]. Rapid Reset [48][49][50][112][89].

## PART 11 | Governments moved liability and disclosure onto companies

- **National Cybersecurity Strategy,** 2 March: shift liability toward software makers.
- **SEC rules,** 26 July: material incidents on Form 8-K Item 1.05 within four business days.
- **SEC charges** against SolarWinds and its CISO, 30 October.
- **Executive orders:** commercial spyware (27 March) and AI, EO 14110 (30 October).
- **NIST CSF 2.0 draft,** 8 August, added Govern; NIS2 entered into force in January.
Notes: Strategy [122]. Secure by Design [125]. SEC rules [46]; Microsoft's January 2024 8-K [87]. SolarWinds charges [74]. Spyware EO [124]. EO 14110 [127]. CSF 2.0 [126]. NIS2 [121]. Ransomware Vulnerability Warning Pilot [123].

## MITRE MAPPINGS | 123 Enterprise rows and 12 ICS, entry and identity at the centre

| Id | Technique | 2023 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | The edge-device year |
| T1505.003 | Server Software Component: Web Shell | MOVEit, NetScaler |
| T1539 | Steal Web Session Cookie | Citrix Bleed, Star Blizzard |
| T1606 | Forge Web Credentials | Storm-0558 (Inferred) |
| T1621 | Multi-Factor Authentication Request Generation | Scattered Spider |
| T1195.002 | Compromise Software Supply Chain | 3CX |
| T0883 | Internet Accessible Device (ICS) | Unitronics PLCs |
Caption: ATT&CK v20.0 ids; revoked advisory ids mapped through superseded_by.jsonl; two Navigator layers. MITRE notice in the notes.
Notes: Rows [28][31][44][69][81][36][77][17][131]. Basis scores in the layers: 100 Source, 70 Behavior, 40 Inferred [134]. T1574.002, T1070.001, T1562.001 and T1656 in the advisories are revoked in v20.0 and map to their successors [134]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Patch from KEV, then assume the appliance is lost

Left: What 2023 taught
- Treat edge appliances as tier-zero, with a replacement plan.
- Revoke sessions and tokens, not just passwords.
- Make MFA phishing-resistant and harden the help desk.
- Keep the logs that would show an identity provider's failure.
Right: Where to look
- New admin accounts on network devices and servers.
- Sessions reused from new places after a patch.
- ntdsutil, WMI and netsh on domain controllers.
- PLCs reachable from the internet with default passwords.
Caption: M-Trends measured a 10-day median dwell time in 2023; Barracuda ESG exploitation ran for seven months.
Notes: Recommendations [26][70][69][82][65][77][37][39][28][78][79], with the generalizations Inferred. Hunting cues [62][68][31][44][60][37][69][77][82][28][1]; the cues are the study's reading. M-Trends, Reported [118]. Barracuda [25].

## CROSS-CUTTING THEMES | The edge was the way in, and first numbers misled

- **Edge appliances were the main entry:** five of the top six on AA24-317A are edge or file-transfer products.
- **Identity and sessions beat patching:** Citrix Bleed, forged tokens and help-desk calls.
- **Overstated:** advisory ATT&CK tables as complete, MGM's $100M as a ransom, actor names for the casinos.
- **Understated:** ransomware money, cloud intrusions without premium logs, and dwell time for stealthy actors.
- **Discrepancy:** Microsoft counted about 25 Storm-0558 victims; the CSRB counted 22 organizations.
Notes: Edge [115]. Identity [69][36][77][85]. Overstated [134][57][34][88][56][77]. Understated [120][88][39][118][25][28]. Discrepancies [35][39]. The themes are the study's reading (Inferred).
