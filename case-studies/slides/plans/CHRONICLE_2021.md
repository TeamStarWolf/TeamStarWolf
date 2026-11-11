# Slide plan: The Year 2021 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2021.md
- Cover title: The Year 2021 / in Intrusions / A Dated Record
- Subtitle: The edge gave way, ransomware met policy, and the KEV catalog arrived
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2021.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The edge gave way, and governments answered with deadlines

- **The edge was the front door.** Nine internet-facing products were exploited for first access, most as zero-days or within weeks of a fix.
- **Zero-days, then everyone.** ESET counted at least 10 groups on Exchange servers, four of them before the 2 March patch.
- **Ransomware became a national-security problem:** Colonial Pipeline, Ireland's HSE, JBS and Kaseya VSA.
- **Identity was the second front:** a Pulse MFA bypass, Nobelium password spraying and FoggyWeb on AD FS.
- **Governments published deadlines:** four emergency directives, Executive Order 14028 and the KEV catalog.
Caption: Grades: agencies, victims, vendors and CVE, NVD and KEV records Confirmed; secondary figures Reported; cloud research Demonstrated.
Notes: Nine products: Exchange, Pulse, Fortinet, SonicWall, Accellion, Serv-U, ManageEngine, Confluence, Kaseya VSA [1][5][25][76][39][20][21][81][51]. ESET [64]; later ransomware, botnet and miner on Exchange [3]. Colonial [45], HSE [47], JBS [48][49], Kaseya [51]. Identity [5][15][16]. Directives [2][6][71][73]; EO 14028 [36]; BOD 22-01 [37].

## KEY FACTS | Four directives, four state attributions and a new catalog

Stat: 4 | CISA emergency directives tied to 2021 flaws
Stat: 4 | state attributions made public by governments
Stat: 311 | KEV entries in today's feed added during 2021
Stat: 93 | Enterprise technique rows in this study, plus 3 ICS
- Attributions: Lazarus for the DPRK (17 Feb), the SVR (15 Apr), the MSS (19 Jul), an Iranian APT (17 Nov).
- Policy landmarks: EO 14028 (12 May), SBOM minimum elements (12 Jul), BOD 22-01 and KEV (3 Nov).
- AA22-117A ranked Log4Shell first among the top routinely exploited flaws of 2021.
Notes: Directives ED 21-02, 21-03, 21-04 and 22-02 [2][6][71][73]. Attributions [31][9][4][18][25]. KEV figures computed from catalog version 2026.11.03: 287 entries dated 3 November 2021, 107 of them CVE-2021 ids; 311 added during 2021 [41]. Policy [36][121][37]. Top flaws [74]. MITRE binding counts from Part 9 of the study.

## PART 1 | The year in date order, from ProxyLogon to Log4Shell

| Date | Event |
|---|---|
| 2 Mar | Microsoft ships Exchange fixes and names HAFNIUM |
| 15 Apr | The White House names the SVR for SolarWinds |
| 19 Apr | Mandiant reveals the Pulse zero-day CVE-2021-22893 |
| 7 May | Colonial shuts all 5,500 miles of pipeline by 6:10 AM |
| 14 May | Human-operated Conti forces most HSE systems offline |
| 2 Jul | REvil reaches Kaseya VSA customers |
| 19 Jul | US, EU, UK and NATO tie the Exchange zero-days to the MSS |
| 13 Sep | Citizen Lab discloses FORCEDENTRY; Apple patches |
| 3 Nov | BOD 22-01 creates the KEV catalog |
| 10 Dec | Log4Shell published and added to KEV the same day |
Notes: Exchange [1][63]. SVR [9]. Pulse [5]. Colonial [45]. HSE [47]. Kaseya [51]. July attribution [4][18]. FORCEDENTRY [34]. BOD 22-01 [37][41]. Log4Shell [72][41].

## PART 2 | China and Russia went through the edge and the identity layer

Left: China
- HAFNIUM exploited four Exchange flaws before the 2 March patch.
- UNC2630 hit Pulse appliances; Mandiant suspected a China link.
- DEV-0322 used a Serv-U zero-day against the defense base.
- Microsoft seized NICKEL websites under a court order.
Right: Russia
- The SVR was named for SolarWinds; 10 diplomats expelled.
- NOBELIUM spoofed USAID through a Constant Contact account.
- FoggyWeb sent out AD FS token-signing certificates.
- Resellers targeted: 22,868 attacks on 609 customers.
Notes: HAFNIUM [1]; ESET, at least 10 groups [64]. UNC2630, link to APT5 unconfirmed by Mandiant [5]. DEV-0322 [20]. NICKEL, court order 2 December [22]. SVR attribution and sanctions [9][10]. NOBELIUM mail, about 3,000 accounts per Microsoft, more than 7,000 per AA21-148A [12][14]. FoggyWeb [16]. Resellers, 1 July to 19 October [17].

## PART 2 | Iran and North Korea hunted people, and spyware was caught

Left: Iran and North Korea
- AA21-321A tied Fortinet and ProxyShell use to an Iranian APT.
- It reached a US children's hospital's environmental controls.
- ZINC lured researchers with a booby-trapped Visual Studio project.
- AA21-048A: seven AppleJeus versions, targets in 32 countries.
Right: Commercial spyware
- FORCEDENTRY: a zero-click iMessage exploit, in use since February.
- Apple patched CVE-2021-30860 the same day, 13 September.
- Apple sued NSO Group on 23 November.
- About 50,000 Pegasus numbers show selection, not infection.
Notes: Iran [25]; Microsoft on PHOSPHORUS, CURIUM and DEV-0343 [26]; SpoofedScholars [27]. ZINC [29][30]; the Lazarus link is Inferred through the alias table [134]. AppleJeus [31]. FORCEDENTRY [34]. Lawsuit [35]. Pegasus Project [32][33].

## PART 3 | Ransomware shut a pipeline, a health service and a meat producer

Stat: 5,500 mi | Colonial pipeline shut by 6:10 AM on 7 May
Stat: $11M | paid by JBS USA, in equivalent
Stat: <1,500 | downstream businesses hit through Kaseya VSA
- Colonial's attacker is believed to have used a legacy VPN profile not meant to be in use.
- AA21-131A found no sign that Colonial's operational technology was directly affected.
- Human-operated Conti forced the shutdown of most of Ireland's HSE systems on 14 May.
Notes: Colonial testimony, note found before 5:00 AM, restart 12 May [45]; FBI on DarkSide [44]; AA21-131A [46]. JBS, FBI attribution to REvil [48]; payment [49]. Kaseya, fewer than 60 direct customers [51]. HSE and the Department of Health [47].

## PART 3 | Kaseya's own deployment function pushed REvil to MSP customers

- **Zero-days bypassed authentication;** standard VSA functionality then pushed ransomware to endpoints.
- **DIVD had reported seven VSA flaws in April;** three were still open on 2 July.
- **Fewer than 60 direct customers,** all on-premises, and fewer than 1,500 downstream businesses.
- **The patch shipped 11 July;** a universal decryptor came from a third party, and Kaseya said it paid no ransom.
Caption: That MSP customers were reached through a trusted relationship and a deployment tool is the study's mapping (Inferred).
Notes: Technical details, no evidence the VSA codebase was modified [52]. DIVD disclosure and case [53][54]. Counts, patch, decryptor read as 21 or 22 July, no ransom [51]. CVE-2021-30116, CWE-522, KEV known ransomware use [55]. CISA guidance [56].

## PART 3 | Treasury followed the ransom money to the exchanges

- **SUEX,** 21 September: Treasury's first designation of a virtual currency exchange.
- **Chatex and two REvil affiliates,** 8 November, with rewards of up to $10 million for REvil leaders.
- **The Ransomware Task Force** published 48 recommendations on 21 April.
- **AA21-265A** counted more than 400 Conti attacks, later updated to more than 1,000.
- **BlackMatter,** a possible DarkSide rebrand, demanded $80,000 to $15,000,000.
Notes: SUEX moved proceeds of at least eight ransomware variants [59]. Chatex, Vasinskyi and Polyanin; State rewards [61]. Task Force [42]; third-party ransom figures Reported [43]. Conti advisory [58]; playbook leak [57]. BlackMatter [60].

## PART 4 | Mail, VPN and management servers fell, many before a fix existed

| CVE | Product | First exploitation | KEV added |
|---|---|---|---|
| CVE-2021-26855 | Exchange (ProxyLogon) | Before the 2 Mar patch | 2021-11-03 |
| CVE-2021-22893 | Pulse Connect Secure | Zero-day, 19 Apr | 2021-11-03 |
| CVE-2021-34527 | Print Spooler | At publication, 1 Jul | 2021-11-03 |
| CVE-2021-30116 | Kaseya VSA | 2 Jul | 2021-11-03 |
| CVE-2021-34473 | Exchange (ProxyShell) | Warned 21 Aug | 2021-11-03 |
| CVE-2021-40539 | ManageEngine ADSelfService | From August | 2021-11-03 |
| CVE-2021-44228 | Apache Log4j | December | 2021-12-10 |
Caption: A KEV date of 3 November 2021 means "in the first load", not "first exploited that day".
Notes: Rows [1][63][41][5][8][70][55][67][25][28][21][72]. AA22-117A top list [74]. KEV due dates do not follow the year rule: ProxyLogon and CVE-2021-34527 six months, ProxyShell and Confluence two weeks [41]. Fortinet reset-after-patch advice, 87,000 devices [78].

## PART 5 | Supply chain and cloud flaws reached signing keys and tenants

Left: Supply chain
- Codecov's uploader was altered in 108 windows, 31 Jan to 1 Apr.
- HashiCorp rotated a GPG release-signing key exposed through it.
- Two malicious commits hit php-src under core developers' names.
- ua-parser-js 0.7.29, 0.8.0 and 1.0.0 carried malicious code.
Right: Cloud and data
- ChaosDB: Cosmos DB keys gave cross-tenant access (Demonstrated).
- OMIGOD: unauthenticated root code execution in Azure OMI, 9.8.
- T-Mobile: about 7.8 million current postpaid accounts exposed.
- Power Apps portals exposed 38 million records.
Notes: Codecov [90]. HashiCorp [91]. php-src [93]. ua-parser-js [108][109]. ChaosDB [101][102]. OMIGOD [104][105]. T-Mobile, plus just over 40 million former or prospective customers [99][100]. UpGuard [103].

## PART 6 | Colonial stopped by choice, and pipeline rules followed in weeks

- **Water facility, 5 February:** the sodium hydroxide setting was raised through SCADA; staff reversed it.
- **The advisory as published today** says the FBI could not confirm a targeted intrusion.
- **Colonial's OT** was not directly affected; the shutdown was the company's own decision.
- **TSA directives:** incident reporting and a 24/7 coordinator (27 May), then ransomware mitigations (20 Jul).
- **The 28 July memorandum** created the Industrial Control Systems Cybersecurity Initiative.
Notes: Water facility, AA21-042A [92]. Colonial [46][45]; the planning lesson is Inferred. TSA Security Directives 1 and 2 [126][127]. National Security Memorandum [130]. Iranian access to a children's hospital control network [25].

## PART 7 | Four emergency directives, then a catalog with due dates

- EO 14028 set zero trust plans, MFA, SBOMs and the Cyber Safety Review Board.
| Directive | Issued | Subject |
|---|---|---|
| ED 21-02 | 3 Mar 2021 | On-premises Exchange |
| ED 21-03 | 20 Apr 2021 | Pulse Connect Secure |
| ED 21-04 | 13 Jul 2021 | Windows Print Spooler |
| BOD 22-01 | 3 Nov 2021 | Known Exploited Vulnerabilities catalog |
| ED 22-02 | 17 Dec 2021 | Apache Log4j |
Caption: The first three directives closed on 8 January 2026; BOD 22-01 is now superseded by BOD 26-04.
Notes: EO 14028 [36]. Directives [2][6][71][73]. BOD 22-01: two weeks for 2021 CVEs, six months for older ones [37]. Closure [2][6][71]. Bank regulators' 36-hour rule [128]. CIRCIA final rule not issued [129].

## MITRE MAPPINGS | 93 Enterprise rows and 3 ICS, with T1190 at the front

| Id | Technique | 2021 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Exchange, Pulse, Serv-U, Kaseya |
| T1505.003 | Web Shell | HAFNIUM, DEWMODE, ManageEngine |
| T1556.004 | Network Device Authentication | Pulse backdoor password |
| T1110.003 | Password Spraying | SVR, NOBELIUM, DEV-0343 |
| T1072 | Software Deployment Tools | VSA pushed ransomware |
| T1486 | Data Encrypted for Impact | DarkSide, Conti, REvil, BlackMatter |
| T0836 | Modify Parameter (ICS) | Sodium hydroxide setting raised |
Caption: ATT&CK v20.0 ids; 42 group, software and campaign objects; two Navigator layers. MITRE notice in the notes.
Notes: Rows [5][19][21][46][25][1][20][39][76][81][51][11][15][26][52][58][60][92]. Basis scores in the layers: 100 Source, 70 Behavior, 40 Inferred [135]. Two ids printed in 2021 advisories are left out: one the v20.0 Enterprise data does not carry and one deprecated [19][31][134]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Patching closes the door but does not evict the intruder

Left: What 2021 taught
- Treat internet-facing access products as tier-zero assets.
- Assume a patched edge device may already be owned.
- Give every remote-access path an owner, MFA and a review date.
- Guard remote-management and CI tools like domain controllers.
Right: Where to look
- Shells spawned by web servers and appliances, such as Serv-U.exe.
- A renamed certutil decoding an agent on managed hosts.
- A new version.dll beside the AD FS service.
- A checksum mismatch on a downloaded CI script.
Caption: ED 21-02 required Test-ProxyLogon.ps1 runs, ED 21-03 the Pulse Integrity Tool; Fortinet said reset passwords after patching.
Notes: Recommendations [37][74][6][78][2][45][52][16][17][15], with the generalizations Inferred. Hunting cues [20][21][1][52][12][16][90][108]. Ransomware readiness [46][58][60].

## CROSS-CUTTING THEMES | Exploitation came first, and attribution arrived months later

- **Exploit first, attribute later:** Exchange in March, the MSS named in July; Fortinet scanning in March, Iran named in November.
- **Concentration risk:** one MSP tool, one CI script and resellers' admin rights reached their customers.
- **Ransomware met policy:** pipeline directives within three weeks, exchange sanctions by November.
- **The KEV idea outlasted its directive,** which is now revoked and superseded by BOD 26-04.
- **Overstated:** the water facility as a proven targeted attack, and the Pegasus list as a victim count.
Notes: Attribution lag [1][4][77][25]. Concentration [51][91][17]. Policy [126][59][61]. KEV [37][41]. Overstated [92][32][33]; understated: edge persistence and identity [5][78][16][17]. The defender readings are Inferred.
