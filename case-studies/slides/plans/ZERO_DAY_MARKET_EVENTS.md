# Slide plan: The Zero-Day Trade and Its Fallout: The Events in This Is How They Tell Me the World Ends

- Study: case-studies/ZERO_DAY_MARKET_EVENTS.md
- Cover title: The Zero-Day Trade / and Its Fallout
- Subtitle: The events in This Is How They Tell Me the World Ends, checked against the primary record
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/ZERO_DAY_MARKET_EVENTS.md. The book was not opened; its scope comes from two reviews and the publisher [2][5][6], graded Reported. Every other figure comes from vendor advisories, lab reports, court filings, government statements and the KEV catalog. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Leaked exploits did more harm than purchased ones

- **Five threads:** an open market, Aurora, two tooling leaks, commercial spyware, and policy and law.
- **Leaked exploits were used within weeks:** Hacking Team in 2015, the Shadow Brokers in 2017.
- **Patched bugs did the widest damage:** MS17-010 shipped 59 days before WannaCry.
- **Spyware was documented phone by phone** by Citizen Lab, Amnesty, Lookout and Project Zero.
- **The NSA origin is Reported:** Microsoft says so; the US government briefing named no source.
Caption: Grades: technical facts, dates and official actions Confirmed; prices and the book's disputed claims Reported.
Notes: Executive summary and key findings. Market [11][12]; Aurora [85][91][95]; leaks [18][20][56][57][60]; spyware [13][35][39][41]; policy [28][42][45][47][48][103]. NSA origin [67][71]. The leaked-versus-purchased reading is the study's inference from Confirmed dates.

## KEY FACTS | A million-dollar iPhone bounty and 300,000 infected computers

Stat: $1M | Zerodium's bounty per iOS 9 chain, 2015
Stat: 59 days | from MS17-010 to WannaCry Version 2
Stat: ~300,000 | computers in 150+ countries, per Treasury
Stat: $112M+ | NHS cost of WannaCry, per Treasury
- The Zero Day Initiative, founded in 2005, reports 15,000+ vulnerabilities disclosed since 2007.
- NotPetya: losses near $1 billion across three named US victims, per the GRU indictment.
- ATT&CK has no object for EternalBlue, DoublePulsar or the Shadow Brokers.
Notes: Zerodium's archived page [12]; ZDI [11]; affidavit for the 59 days [57]; Treasury [69]; GRU indictment [78]; ATT&CK [81][114]. The book: Bloomsbury, 9 February 2021, 528 pp. [2]; 2021 FT and McKinsey Business Book of the Year [3].

## PART 3 | The zero-day market posted its prices in the open

- **Zero Day Initiative, 2005:** rewards researchers and routes zero-days privately to vendors.
- **Chromium rewards, 28 January 2010:** a $500 base and $1,337 for severe or clever bugs.
- **Zerodium, October 2015:** $1 million per iOS 9 chain, $3 million in all, open to 31 October.
- **A chain had to beat** ASLR, the sandbox, rootless, code signing and the bootchain.
- **Reported only:** a $1 million Zerodium purchase in November 2015; 300 Pegasus licenses for $8 million.
Caption: Citizen Lab named 21 suspected Hacking Team government users in 2014; Bossert said the US discloses about 90 percent.
Notes: Part 3. ZDI [11]; Chromium [91]; Zerodium's own archived page [12], Confirmed. Purchase via Citizen Lab citing others [13] and license prices via Lookout citing news [14], Reported. Hacking Team users [16]; Bossert [71], Confirmed that he said so.

## PART 4 | Aurora was patched in seven days, and bounties followed

| Date | Event |
|---|---|
| Mid-Dec 2009 | Google detects a targeted attack from China |
| 12 Jan 2010 | Google discloses: 20+ companies targeted, two Gmail accounts reached |
| 14 Jan 2010 | Microsoft Security Advisory 979352 for the IE flaw |
| 21 Jan 2010 | MS10-002 fixes CVE-2010-0249, a use-after-free |
| 28 Jan 2010 | Chromium launches its vulnerability reward program |
| 22 Mar 2010 | Google.cn users redirected to Google.com.hk |
| 15 Jul 2014 | Google announces Project Zero |
Caption: ATT&CK credits G0066 Elderwood; reading Project Zero as Aurora's legacy is Inferred. KEV added the IE flaw in 2026.
Notes: Google [85][92]; NVD [86]; Microsoft [87][88]; Google rewards and Project Zero [91][93][95]; Elderwood and Hydraq [96][97]. KEV added CVE-2010-0249 on 20 May 2026 [22]. McAfee's 34 companies and the attack dates [89] are Reported.

## PART 5 | Kaspersky tied the Shadow Brokers dumps to Equation code

- **Equation, February 2015:** samples from 2002, domains from 1996, a hard-drive firmware module.
- **13 August 2016:** about 300 MB of firewall exploits released; newest timestamps October 2013.
- **347 RC5 and RC6 implementations** match Equation code; Kaspersky could not say who leaked them.
- **Cisco published its EXTRABACON advisory** on 17 August; MSRC mapped the 2017 Windows tools to MS17-010.
- **Buckeye used a DoublePulsar variant** from March 2016, per Symantec, a year before the release.
Caption: No record opened charges anyone as the Shadow Brokers; the NSA origin rests on Microsoft's statement.
Notes: Kaspersky [49][50]; Cisco [51][52]; MSRC triage [60]; Symantec on Buckeye [117]. KEV added CVE-2016-6366 and CVE-2016-6367 on 24 May 2022 [23]. Microsoft [67]; the US briefing [71]. The ATT&CK G0020 page does not mention the Shadow Brokers [114]. The leak events have their home in the Shadow Brokers and Vault 7 study.

## PART 6 | EternalBlue was patched in March, leaked in April, a worm in May

| Date | Event |
|---|---|
| 14 Mar 2017 | MS17-010 fixes five SMBv1 code execution bugs |
| 14 Apr 2017 | Shadow Brokers release the Windows archive (15 April in the FBI affidavit) |
| 9 May 2017 | RiskSense releases reverse-engineered EternalBlue code |
| 12 May 2017 | WannaCry Version 2 adds the SMB worm; the kill-switch domain is registered |
| 13 May 2017 | Microsoft ships fixes for XP, Windows 8 and Server 2003 |
| 19 Dec 2017 | The US, the UK and four partners attribute WannaCry to North Korea |
Caption: Versions 0 and 1, from February to April 2017, spread with stolen credentials before the worm was added.
Notes: MS17-010 [56]; Cisco's release date [52] and the affidavit [57]; RiskSense code [57], Demonstrated; Talos, US-CERT and Hutchins [63][64][65]; Microsoft [66]; attribution [71][72]. NVD scores CVE-2017-0144 at CVSS 3.1 8.8 with no CWE [61].

## PART 6 | WannaCry's NHS toll fell on unpatched and unsupported Windows

Stat: 81 of 236 | English NHS trusts affected, per the NAO
Stat: 603 | NHS organisations infected, 595 of them GP practices
Stat: 19,000+ | appointments estimated cancelled
- **The NAO found** the infected NHS bodies ran unpatched or unsupported Windows.
- **The worm** scanned TCP 445, exploited EternalBlue and ran through DoublePulsar.
- **Hutchins registered** the domain the sample checked; TA17-132A advises not blocking it.
- **No NHS body paid,** and payers do not appear to have been able to decrypt.
Notes: UK National Audit Office [68]; FBI affidavit [57]; Talos [63]; Hutchins [65]; TA17-132A [64]. 6,912 cancelled appointments were identified [68]. The FBI affidavit gives at least 80 of 236 trusts and 1,220 diagnostic devices [57].

## PART 7 | NotPetya used EternalBlue only after credential theft failed

- **27 June 2017:** first infections through the M.E.Doc updater; 12,500+ machines hit in Ukraine.
- **Backdoored updates** on 14 April, 15 May and 22 June 2017, per Talos.
- **Spread order:** credential theft first, then EternalBlue or EternalRomance if both other methods failed.
- **ESET:** the SMB exploit hit only the local address space; foreign victims had VPN links into Ukraine.
- **Losses near $1 billion,** including about $400 million at TNT Express.
Caption: Six GRU Unit 74455 officers were indicted in October 2020; the full record is in the Sandworm study.
Notes: Microsoft [74]; Talos [118]; GRU indictment [78]; ESET [119]; US and UK attribution [76][77]. Crediting all of NotPetya's reach to the leaked exploit overstates it, Inferred.

## PART 8 | Hacking Team's leak put Flash zero-days in the wild that month

- **5 July 2015:** the breach goes public; about 400 GB, announced on the company's own Twitter account.
- **8 July 2015:** WikiLeaks publishes more than 1 million searchable Hacking Team e-mails.
- **Flash CVE-2015-5119, -5122 and -5123** were exploited in the wild in July 2015.
- **The leak confirmed** Ethiopia, Sudan, Saudi Arabia and Kazakhstan as clients.
- **It also fed later research:** Citizen Lab used NSO documents found in it in 2016.
Caption: KEV added CVE-2015-5119 on 3 March 2022, and CVE-2015-5122 and CVE-2015-5123 on 13 April 2022.
Notes: CERT/CC [18][19]; Citizen Lab [16][25]; WikiLeaks [24]; NVD [20]; KEV [22]. MS15-077 fixed CVE-2015-2387 on 14 July 2015 [21]; its link to the leak is not checked. Citizen Lab's 2016 Mansoor report [13].

## PART 8 | Pegasus was documented phone by phone, 2016 to 2021

| When | What | Record |
|---|---|---|
| Aug 2016 | Trident chain sent to Ahmed Mansoor | iOS 9.3.5 in about 15 days |
| 2016 to 2018 | Hide and Seek: 36 Pegasus systems, 45 countries | Citizen Lab scan |
| Jul to Aug 2020 | KISMET zero-click on 36 Al Jazeera phones | Citizen Lab |
| Jul 2021 | Megalodon on a fully patched iPhone 12 | Amnesty, with the MVT |
| Sep 2021 | FORCEDENTRY, CVE-2021-30860 | iOS 14.8; Project Zero |
| Nov 2021 | Entity List; Apple sues NSO | Commerce; Apple |
Caption: Project Zero judged NSO's capability comparable to a handful of nation states.
Notes: Citizen Lab and Lookout [13][14]; Apple [15][40]; Hide and Seek [32]; KISMET [34]; Amnesty [35]; FORCEDENTRY [39]; Project Zero [41]; Entity List [45]; Apple's suit [42]. Candiru: at least 100 victims in ten countries [38].

## PART 9 | Baltimore's court record names no EternalBlue

Left: The claim (Reported)
- NYT, 25 May 2019: Baltimore tied to EternalBlue.
- The NYT page could not be opened.
- Graham: the book concedes the point.
- Howard: only that analysts found evidence.
Right: The record (Confirmed)
- Indictment filed 4 April 2024.
- Access from about 3 to 7 May 2019.
- Generic tools, admin accounts; no SMB.
- Plea, 27 May 2025: over $19M lost.
- RobbinHood (S0400) has no T1210.
Caption: Absence from an indictment qualifies the reporting but does not prove a negative (Inferred).
Notes: The NYT story via Graham and Wikipedia [8][10]; Graham's review [7]; Howard [5], all Reported. Robbinhood indictment [108] and plea release [109], Confirmed; the indictment names no EternalBlue, SMB or NSA tool. Library data [81].

## PART 10 | Policy moved from a blog post to sanctions in ten years

| Date | Action |
|---|---|
| 28 Apr 2014 | White House: disclosure is in the national interest in most cases |
| 15 Nov 2017 | Vulnerabilities Equities Policy charter: a presumption of disclosure |
| 4 Nov 2021 | Entity List: NSO, Candiru, Positive Technologies and a Singapore firm |
| 8 Nov 2021 | Ninth Circuit rejects NSO's immunity defense |
| 27 Mar 2023 | EO 14093 bars US government use of risky commercial spyware |
| 5 Mar 2024 | OFAC designates Intellexa's founder and five entities, Cytrox among them |
Caption: The Supreme Court denied NSO's petition on 9 January 2023. That each step went further is Inferred.
Notes: [110][103][45][46][28][29][47][48], Confirmed for each action. OFAC designated Tal Dilian, one other individual and five entities [48]. The escalation reading is the study's inference.

## MITRE MAPPINGS | ATT&CK maps the behavior, not EternalBlue's provenance

| Id | Technique | Where it appears |
|---|---|---|
| T1210 | Exploitation of Remote Services | WannaCry, NotPetya, Bad Rabbit |
| T1195.002 | Compromise Software Supply Chain | NotPetya via M.E.Doc |
| T1486 | Data Encrypted for Impact | WannaCry, NotPetya, RobbinHood |
| T1203 | Exploitation for Client Execution | Aurora; the Flash bugs (Inferred) |
| T1542.002 | Component Firmware | Equation's hard-drive module |
| T1588.005 | Obtain Capabilities: Exploits | Lazarus, Buckeye (Inferred) |
Caption: 75 Enterprise rows, 15 Mobile techniques for Pegasus (S0289) and 5 ICS; no object for EternalBlue or the leak.
Notes: Part 12, ATT&CK v20.0. Groups G0066, G0020, G0022, G0032, G0034, G0038; software S0366, S0368, S0606, S0140, S0203, S0047, S0182 [81][114]. Enterprise and ICS Navigator layers. CAPEC-186 via T1195.002, Inferred for NotPetya [82][118]. Not an official MITRE mapping. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Patched bugs did the widest damage, so patch on a clock

Left: Exposure windows
- Advisory 979352 to MS10-002: 7 days.
- Mansoor lure to iOS 9.3.5: about 15 days.
- MS17-010 to the Windows leak: 31 days.
- RiskSense code to WannaCry: 3 days.
- MS17-010 to NotPetya: 105 days.
Right: What the sources say to do
- Patch, disable SMBv1, block SMB at the edge.
- Do not block the kill-switch domain.
- Treat the update channel as an attack path.
- Keep offline backups; plan restores.
- Give at-risk staff a mobile forensics path.
Caption: Every MS17-010 CVE is now in KEV with known ransomware use; track KEV, but do not wait for it.
Notes: Exposure windows [56][52][57][74][87][88][13][15]. Advice [56][64][118][75][35][120]. KEV ransomware flags [22]. ATT&CK M1051 Update Software and M1042 Disable or Remove Feature or Program [80]. "Do not wait for it" is Inferred from the 1,794-day gap reflecting KEV's late-2021 launch.

## CROSS-CUTTING THEMES | Leaks outran the market, and patch latency did the damage

- **The leak was faster than the market:** free exploits were in the wild within weeks.
- **Patched is not protected:** MS17-010 predated the leak by 31 days and WannaCry by 59.
- **Evidence beat assertion** in the spyware story: captured exploits, vendor credits, court rulings.
- **ATT&CK describes behavior, not provenance:** the leak-to-worm lineage lives in court records.
- **The policy record grew teeth,** from a 2014 blog post to 2024 sanctions.
Notes: Cross-cutting themes [12][13][18][20][28][39][40][41][45][47][48][52][56][57][68][81][103][110][114]. All are the study's reading, graded Inferred. Overstated: the leaked exploit as the cause of every outbreak [78][108]; Graham cites the DBIR on rare zero-day use [7], Reported.
