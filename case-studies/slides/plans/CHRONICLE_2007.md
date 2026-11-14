# Slide plan: The Year 2007 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2007.md
- Cover title: The Year 2007 / in Intrusions / A Dated Record
- Subtitle: Storm, Estonia and the flaw with no patch
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2007.md, told from Microsoft bulletins and advisories, US-CERT alerts in CISA's archive, CERT/CC vulnerability notes, CVE and NVD records and the KEV catalog, SEC filings, the Canadian privacy commissioners' TJX report, FTC, Justice Department and FBI releases, Hansard, the Federal Register, OMB, NATO and CCDCOE records, NIST, FIRST, RFC Editor, OWASP and MITRE records, and the later vendor reports that date espionage tools to 2007. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year of Storm and Estonia

- **Botnets:** Storm hid its second stage behind a peer-to-peer network.
- **Estonia:** three weeks of floods drew a prime minister's accusation.
- **Flaws:** Word, Excel, the animated cursor and DNS RPC were exploited at release.
- **Losses:** TJX's filings, an insider sale at Certegy and HMRC's lost discs.
- **State:** press reports at the time; vendor dates for APT1 and APT28 later.
Caption: Grades: bulletins, alerts, filings, releases and statutes Confirmed; CCDCOE and press Reported.
Notes: Storm [1]. Estonia [40][41][42]. Exploited at release [11][12][19][23]. TJX [2][4]; Certegy [50]; HMRC [53]. Press [54][56][57]; later reports [60][66].

## KEY FACTS | Four numbers from the primary record

Stat: 45.6M | cards in the table of TJX's 10-K
Stat: 25M | people on HMRC's two lost discs
Stat: 1M+ | victim IP addresses found by Operation Bot Roast
Stat: 3 | CVE-2007 ids in CISA's KEV catalog today
- The Canadian commissioners put TJX's total at about 45 million.
- Certegy's insider sale involved about 2.3 million records.
- KEV added the Excel flaw CVE-2007-0671 in August 2025.
Notes: TJX [4][5]. HMRC [53]. Bot Roast [47]. KEV [37]. Certegy [50]. Excel [13][37].

## PART 1 | The year in date order, from Storm to the lost discs

| Date | Event |
|---|---|
| 12 Jan | Storm floods anti-spam sites |
| 17 Jan | TJX announces its intrusion |
| 13 Feb | MS07-014 and MS07-015 |
| 28 Feb | TA07-059A, Solaris telnet worm |
| 3 Apr | MS07-017, animated cursor |
| 27 Apr | Estonia attacks begin |
| 8 May | MS07-029, DNS Server RPC |
| 22 May | OMB M-07-16 |
| 13 Jun | Operation Bot Roast |
| 20 Jun | CVSS v2 released |
| 15 Nov | Stuxnet 0.5 submitted to a scanner |
| 20 Nov | HMRC discs reported missing |
Notes: Storm [1]. TJX [2]. Office [11][12]. Solaris [14]. Cursor [19]. Estonia [40]. DNS RPC [23]. M-07-16 [75]. Bot Roast [47]. CVSS [83]. Stuxnet 0.5 [62]. HMRC [53].

## PART 2 | Storm and the botnet economy

Left: Storm
- Dropped by an e-mail virus.
- Second stage found via Overnet.
- SYN and ICMP floods.
- No size in the primary.
Right: The cases
- Soloway arrested on 30 May.
- Bot Roast I on 13 June.
- Bot Roast II on 29 November.
- Over $20 million in losses.
Caption: Indictments are allegations; SecureWorks' Spamhaus reading is graded Reported.
Notes: Part 2. Storm [1]. Soloway [46]. Bot Roast [47][48][49].

## PART 3 | Estonia, April and May 2007

- **Timeline:** late 27 April to 18 May, government sites first, then media and banks.
- **Methods:** DDoS, defacements, DNS attacks and spam, from 178 countries.
- **Banks:** Hansapank's online banking down for hours on 9 and 10 May.
- **Law:** one conviction for ping floods; Russia refused legal assistance in 2008.
- **NATO:** first cyber defence policy in January 2008; CCDCOE founded in May 2008.
Caption: The timeline is from CCDCOE analyses (Reported); this study is the library's home for Estonia 2007.
Notes: Part 3. Timeline and methods [40][41]. Attribution [42][43]. Legal record [40]. NATO [45]; CCDCOE [44].

## PART 4 | The vulnerability record

- **Office:** MS07-014 (Word) and MS07-015 (Excel), both exploited at release.
- **Solaris:** a worm logged in through the telnet daemon as adm or lp.
- **Animated cursor:** public on 29 March, fixed out of cycle on 3 April.
- **DNS Server RPC:** exploited with no complete fix until MS07-029.
- **PDF and URI:** malicious PDFs reached a Windows URI flaw in October.
Caption: Of 69 bulletins, four opened here say a flaw was exploited at release.
Notes: Part 4. Office [11][12][13]. Solaris [14][15]. Cursor [16][17][18][19][20]. DNS RPC [21][22][23][24]. URI [29][30]. Count [38].

## PART 5 | The corporate and data-loss record

Left: Intrusions
- TJX in from July 2005.
- WEP and unencrypted card data.
- Visa settlement up to $40.9M.
- TD Ameritrade's unauthorized code.
Right: No intrusion
- Certegy: an insider's sale.
- About 2.3 million records.
- HMRC: discs lost in the post.
- 25 million people affected.
Caption: TJX and Max Butler are summarized from their home studies; filings are the company's own account.
Notes: Part 5. TJX [2][3][4][5][7]. TD Ameritrade [51]. Certegy [50]. HMRC [53]. Butler [52].

## PART 6 | The state record, in two layers

Left: Reported in 2007
- Germany's Chancellery, Spiegel.
- The Pentagon, BBC via the FT.
- Whitehall, the Guardian.
- MI5's letter to 300 firms.
Right: Dated by later records
- APT1 and BISCUIT, Mandiant.
- APT28, FireEye.
- Darkhotel, Red October, Careto.
- Stuxnet 0.5, Symantec.
Caption: China denied three of the four 2007 reports; most later vendor reports name no state.
Notes: Part 6. Press [54][55][56][57][58]. Testimony [43]. APT1 [60][61]. APT28 [66][67]. Darkhotel [69][70]; Red October [71]; Careto [72]. Stuxnet 0.5 [62].

## PART 8 | Law, regulation and standards

| Date | Event | Grade |
|---|---|---|
| 20 Feb | NIST SP 800-94 | Confirmed |
| 17 Mar | CAPEC companion website | Confirmed |
| 9 Apr | CFATS cyber standard | Confirmed |
| May | RFC 4871, DKIM | Confirmed |
| 22 May | OMB M-07-16 | Confirmed |
| 20 Jun | CVSS v2 | Confirmed |
| 6 Aug | FERC CIP proposal | Confirmed |
| 2 Nov | SHA-3 competition | Confirmed |
| 9 Nov | Red Flags final rules | Confirmed |
Notes: Parts 7 and 8. SP 800-94 [85]. CAPEC [91][93]. CFATS [76]. DKIM [84]. M-07-16 [75]. CVSS [83]. FERC [77]. SHA-3 [89]. Red Flags [80].

## MITRE MAPPINGS | 17 Enterprise techniques, every one a later mapping

| Id | Technique | 2007 use |
|---|---|---|
| T1203 | Exploitation for Client Execution | Office, cursor |
| T1210 | Exploitation of Remote Services | DNS RPC, Solaris |
| T1584.005 | Botnet | Storm, Bot Roast |
| T1498.001 | Direct Network Flood | Storm, Estonia |
| T1669 | Wi-Fi Networks | TJX |
| T1040 | Network Sniffing | TJX |
| T0873 | Project File Infection (ICS) | Stuxnet 0.5 |
Caption: ATT&CK v20.0 ids; APT1's object-level techniques sit in their own table.
Notes: Part 9. Rows [11][12][18][21][14][1][47][40][5][4][62]. Basis scores in the layers: 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2007 lessons still apply

Left: What 2007 taught
- Plan for the unpatched flaw.
- Distrust outside documents.
- Turn off old remote logins.
- Encrypt the card path.
Right: What still applies
- Watch database insiders.
- Track physical media.
- Plan DDoS with upstreams.
- Authenticate your mail.
Notes: Top recommendations and Part 8. Unpatched [16][18][21]. Documents [11][12][29]. Telnet [14]. Card path [5][4]. Insiders [50]. Media [53]. DDoS [40]. Mail [84][32].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- Storm's size.
- Estonia as a cyberwar.
- The PLA claims.
- A 2007 Dual_EC backdoor.
Right: Understated
- The standards plumbing.
- The KEV tail.
- Insider and paper losses.
- 2007 as a rules year.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [1][40][42][45][54][56][57][88]. Understated [83][84][85][86][89][91][93][37][50][53][75][80][76][77]. Cross-cutting themes and the overstated and understated passage.
