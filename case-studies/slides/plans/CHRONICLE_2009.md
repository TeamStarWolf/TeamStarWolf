# Slide plan: The Year 2009 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2009.md
- Cover title: The Year 2009 / in Intrusions / A Dated Record
- Subtitle: Conficker's response, poisoned documents and the espionage reports
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2009.md, told from Microsoft bulletins and advisories, US-CERT alerts in CISA's archive, CERT/CC vulnerability notes, Adobe's advisories, CVE and NVD records and the KEV catalog, Heartland's SEC filings, FBI stories, the Federal Register, the White House archive, the Secretary of Defense memorandum, the UK Cabinet Office and House of Commons records, the GhostNet, Shadows in the Cloud and Cambridge reports, Google's disclosure, Symantec, McAfee and Kaspersky reports, NIST, IETF and MITRE records and ATT&CK's object pages. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | 2009 was the response to a 2008 worm

- **Worm:** Conficker's flaw is from 2008; the coalition, alert and fixes are 2009.
- **Documents:** Adobe and Office flaws were exploited at or before their fixes.
- **Card theft:** Heartland's disclosure, the ATM cash-out and Phish Phry.
- **Espionage:** GhostNet, Night Dragon and Aurora, documented by researchers.
- **Offices:** a White House coordinator, US Cyber Command and a UK strategy.
Caption: Grades: bulletins, alerts, filings and FBI stories Confirmed; The Register graded Reported.
Notes: Conficker [7][10][5][6]. Documents [14][40][66][17][25][26][35]. Heartland [1][3]; ATM cash-out [54]; Phish Phry [53]. GhostNet [20][21]; Night Dragon [61][62]; Aurora [70][74]. Offices [28][32][33].

## KEY FACTS | Four numbers from the primary record

Stat: 1,295 | infected hosts GhostNet found in 103 countries
Stat: $250K | Microsoft's reward for Conficker's authors
Stat: 5,778 | CVE records NVD published in 2009
Stat: 15 | CVE-2009 ids in CISA's KEV catalog today
- MS08-067 had been out five months when US-CERT's alert named it.
- Heartland's reserve: USD 99.9 million unpaid at the end of 2009.
- Seven ids tied to 2009 events entered KEV in 2026.
Notes: GhostNet [20]. Reward [5]. NVD count [89]. KEV [88]. MS08-067 and the alert [7][6]. Heartland [3]. KEV 2026 additions [88].

## PART 1 | The year in date order, from Heartland to Aurora

| Date | Event |
|---|---|
| 20 Jan | Heartland discloses; AutoRun alert |
| 12 Feb | Conficker coalition and reward |
| 17 Feb | HITECH Act enacted |
| 28 Mar | Tracking GhostNet published |
| 29 Mar | US-CERT TA09-088A, Conficker |
| 29 May | White House cyber office |
| 23 Jun | Stuxnet wave 1; Cyber Command memo |
| 25 Jun | UK Cyber Security Strategy |
| 7 Oct | Operation Phish Phry |
| Nov | Night Dragon first seen |
| 5 Nov | TLS renegotiation flaw public |
| Mid-Dec | Google detects Aurora |
Notes: Heartland [1]; AutoRun [4]. Coalition [5]. HITECH [18]. GhostNet [20]. TA09-088A [6]. White House [28]. Stuxnet [29]; Cyber Command [32]. UK [33]. Phish Phry [53]. Night Dragon [61]. TLS [58]. Aurora [70].

## PART 2 | Conficker: the flaw was 2008, the response was 2009

Left: The 2008 frame
- MS08-067 on 23 Oct 2008.
- Limited attacks at release.
- First detected Oct 2008.
- A wormable Server flaw.
Right: The 2009 response
- Coalition and reward, 12 Feb.
- TA09-088A, 29 Mar.
- New variant, 9 Apr.
- AutoPlay fix, 25 Aug.
Caption: CISA added CVE-2008-4250 to its KEV catalog on 20 May 2026.
Notes: Part 2. MS08-067 [7]; NVD [8]; ATT&CK's S0608 [10]. Coalition and reward [5]. Alert and 9 Apr variant [6]. AutoRun alert and AutoPlay fix [4][11]. KEV [88].

## PART 2 | Documents and plug-ins carried the attacks

| CVE | Product | Fix |
|---|---|---|
| CVE-2009-0658 | Adobe Reader, JBIG2 | Reader 9.1, 10 Mar |
| CVE-2009-0238 | Microsoft Excel | MS09-009, 14 Apr |
| CVE-2009-0556 | Microsoft PowerPoint | MS09-017, 12 May |
| CVE-2009-1537 | DirectShow | MS09-028, 14 Jul |
| CVE-2008-0015 | Video ActiveX control | MS09-032, 14 Jul |
| CVE-2009-1862 | Flash and Reader | APSB09-10 |
| CVE-2009-3459 | Adobe Reader | APSB09-15, 13 Oct |
| CVE-2009-4324 | Adobe Reader | Planned Jan 2010 |
Caption: Each was exploited at or before its fix, per the vendor, CERT/CC or NVD.
Notes: Part 2. JBIG2 [14][13][15]. Excel [17]. PowerPoint [25]. DirectShow [26][27]. Video ActiveX [34][35][36]. Flash [40][39]. Reader heap overflow [99][100]. Reader Doc.media.newPlayer [66][65][67]. KEV dates [88].

## PART 2 | Disclosed before the fix, and the trust layer cracked

- **SMBv2:** public on 8 Sep, a workaround offered, fixed by MS09-050 on 13 Oct.
- **IIS FTP:** public on 1 Sep, limited targeted attacks, fixed by MS09-053.
- **NUL in certificates:** CVE-2009-2408 enabled man-in-the-middle spoofing.
- **TLS renegotiation:** public on 5 Nov; RFC 5746 closed it in Feb 2010.
- **Volume:** 74 bulletins by numbering and 5,778 CVE records from NVD.
Caption: The sources opened record no exploitation of the two trust-layer flaws.
Notes: Part 2. SMBv2 [45][46]. IIS FTP [44][98]. NUL certificate flaw [41]. TLS renegotiation [58][59][60]. Bulletins [12][64]. NVD count [89].

## PART 3 | Card theft and the crime record

Left: Heartland
- Disclosed on 20 Jan.
- Card brands alerted it.
- In-transit card data.
- $99.9M reserve unpaid.
Right: The FBI's cases
- ATM cash-out: $9M+.
- Phish Phry: ~100 charged.
- IC3: 275,284 complaints.
- Spear phishing warning.
Caption: Charges are allegations; Heartland and Wyndham are summarized from E-Commerce Threats.
Notes: Part 3. Heartland [1][2][3]. Wyndham [92]. ATM cash-out [54]. Phish Phry [53][55]. IC3 [56]. Spear phishing warning [57]. Max Butler [91].

## PART 4 | Researchers documented espionage and mostly named no state

- **GhostNet:** 1,295 hosts in 103 countries; the operators are unknown.
- **Cambridge:** names agents of the Chinese government, as its authors' view.
- **Shadow Network:** 1,500 letters taken; control over ordinary web services.
- **Night Dragon:** energy firms from November; McAfee has no direct evidence.
- **Aurora:** detected in mid-December, disclosed on 12 January 2010.
Caption: ATT&CK says Elderwood was "reportedly" responsible for Aurora; Google names no state.
Notes: Part 4. GhostNet [20][21]. Cambridge [22]. Shadow Network [68]. Night Dragon [61][62]. Aurora [70][71][72][74][75].

## PART 4 | Stuxnet, Equation and the groups dated to 2009

Left: Dated events
- Stuxnet 1.x sample, June.
- Wave 1 infection, 23 Jun.
- MS09-025, 9 Jun.
- Houston disk (Inferred).
Right: Dated later
- Lazarus Group, Andariel.
- Sandworm, Leviathan.
- Tonto Team, APT18.
- HIDDEN COBRA, 2017.
Caption: "Since at least 2009" was written years later; it is not a 2009 record.
Notes: Part 4. Stuxnet [29][96]. MS09-025 [30]; Fanny [31]. Houston disk [31]. Groups [78][79][80][81][82][83][84][85][86]. TA17-164A [77].

## PART 5 | Governments organized for cyber in one year

| Date | Event | Grade |
|---|---|---|
| 17 Feb | HITECH Act enacted | Confirmed |
| 1 Apr | S.773 introduced | Confirmed |
| 29 May | White House cyber office | Confirmed |
| 23 Jun | US Cyber Command memo | Confirmed |
| 25 Jun | UK Cyber Security Strategy | Confirmed |
| 24 Aug | HHS breach rule | Confirmed |
| 25 Aug | FTC breach rule | Confirmed |
| Aug | NIST SP 800-53 Rev. 3 | Confirmed |
| 22 Dec | Coordinator named | Confirmed |
Notes: Part 5. HITECH [18]. S.773 [23][24]. White House [28]. Cyber Command [32]. UK [33]. HHS [18]. FTC [19]. SP 800-53 [42]. Coordinator [69]. CWE and CAPEC releases [49][50][51]; SHA-3 [43].

## MITRE MAPPINGS | 60 Enterprise techniques, 56 listed by ATT&CK objects

| Id | Technique | 2009 use |
|---|---|---|
| T1210 | Exploitation of Remote Services | Conficker |
| T1091 | Replication Through Removable Media | Conficker |
| T1568.002 | Domain Generation Algorithms | Conficker |
| T1203 | Exploitation for Client Execution | Documents |
| T1566.001 | Spearphishing Attachment | GhostNet |
| T1102 | Web Service | Shadow Network |
| T1657 | Financial Theft | ATM cash-out |
Caption: ATT&CK v20.0 ids from S0608, S0203, G0066 and C0002, with their dating caveats.
Notes: Part 7. Rows [10][6][5][74][14][21][68][54]. Basis scores in the layer: 100 Listed, 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2009 lessons still apply

Left: What 2009 taught
- Measure patch age.
- Disable AutoRun by policy.
- Act on advisories.
- Encrypt card data in transit.
Right: What still applies
- Watch records that move money.
- Train on inside-informed lures.
- Watch web-service C2.
- KEV dates are not event dates.
Notes: Top recommendations and Part 6. Patch age [6][7]. AutoRun [4][11]. Advisories [14][40][66][17][25][26][45]. Encryption [3]. Money records [54]. Lures [57]. Web-service C2 [68]. KEV [88].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- Conficker's 1 April date.
- Conficker's damage.
- Aurora as a 2009 event.
- "Chinese state hacking".
Right: Understated
- The document-exploit wave.
- Removable media.
- The trust layer.
- Groups begun in 2009.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [6][7][5][70][74][20][68][62][22]. Understated [88][14][17][4][11][29][96][41][58][60][78][77]. Cross-cutting themes and the overstated and understated passage.
