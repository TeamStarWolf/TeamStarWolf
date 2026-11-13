# Slide plan: The Year 2005 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2005.md
- Cover title: The Year 2005 / in Intrusions / A Dated Record
- Subtitle: The breach letter arrives, and regulators start to write the standard
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2005.md, told from SEC filings, FTC complaints, orders and releases, Justice Department and FBI releases, Microsoft bulletins and advisories, US-CERT alerts in CISA's archive, CERT/CC vulnerability notes, CVE and NVD records, bank regulators' issuances, statutes, NIST, ISO, RFC Editor, FIRST and MITRE records, and the later government and vendor reports that date state tools to 2005. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year the breach letter arrived

- **Brokers:** ChoicePoint and LexisNexis lost data through customer accounts.
- **Cards:** DSW, BJ's and CardSystems lost card data to real intrusions.
- **Regulators:** the FTC treated weak security as an unfair practice.
- **Flaws:** Zotob followed MS05-039; the WMF flaw was exploited before a patch.
- **State:** TA05-189A warned of targeted trojan e-mail aimed at US data.
Caption: Grades: filings, FTC, Justice, CERT, vendor and statute records Confirmed; press Reported.
Notes: Brokers [1][5][6][8][9]. Cards [10][11][14][15]. FTC [13][14][16][7]. Zotob [19][24]; WMF [34][38]. TA05-189A [43].

## KEY FACTS | Four numbers from the primary record

Stat: 145,000 | ChoicePoint consumers notified, by its 10-K
Stat: 1.4M | cards in DSW's 108-store theft
Stat: 5,010 | CVE records NVD published in 2005
Stat: 31 | ATT&CK Enterprise technique rows, all later mappings
- The FTC's complaint puts ChoicePoint's total at 163,000.
- CVE ids were cited at the time in the CAN- candidate form.
- CWE came in 2006 and CAPEC in 2007; PLOVER was the 2005 catalog.
Notes: ChoicePoint [1][5]. DSW [11]. NVD count [41]. Part 9 for the technique rows. CAN form [19][22]. CWE and CAPEC [80][81].

## PART 1 | The year in date order, from ChoicePoint to the WMF flaw

| Date | Event |
|---|---|
| Feb | ChoicePoint's first notices |
| 8 Mar | DSW card-data theft announced |
| 9 Mar | LexisNexis/Seisint misuse reported |
| 16 Jun | FTC settles with BJ's |
| 29 Jun | TA05-180A, VERITAS exploited |
| Jul | TJX's intruder first gets in |
| 8 Jul | TA05-189A, targeted trojan e-mail |
| 9 Aug | MS05-039, Plug and Play |
| 25 Aug | Zotob and Mytob arrests |
| 3 Nov | Ancheta arrested |
| 15 Nov | VU#312073, Sony BMG XCP |
| 28 Dec | TA05-362A, the WMF flaw |
Notes: ChoicePoint [5][1]. DSW [10]. LexisNexis [8]. BJ's [14]. VERITAS [25]. TJX [17]. TA05-189A [43]. MS05-039 [19]. Zotob [24]. Ancheta [50]. XCP [31]. WMF [34].

## PART 2 | Front-door losses and card-data intrusions

Left: Through approved accounts
- ChoicePoint: fraudulent applicants.
- LexisNexis: misused customer IDs.
- No network intrusion in either.
- Notices under California law.
Right: Through the network
- CardSystems: SQL injection.
- Exfiltration every four days.
- BJ's and DSW: defaults, wireless.
- TJX: in from July 2005.
Caption: FTC complaints are allegations; TJX and the Gonzalez ring are summarized from their home study.
Notes: Part 2. ChoicePoint [1][5][6]. LexisNexis [8][9]. CardSystems [15][16]. BJ's [14]; DSW [13]. TJX [17][18][91].

## PART 3 | The vulnerability record

- **MS05-039:** Plug and Play overflow, remote mainly on Windows 2000.
- **VERITAS:** an exploited Remote Agent flaw, then hard-coded NDMP credentials.
- **Cisco IOS:** an IPv6 packet flaw disclosed at Black Hat.
- **Sony BMG:** XCP hid itself like a rootkit and shipped an unsafe uninstaller.
- **WMF:** exploited against patched XP SP2; MS06-001 out of cycle on 5 Jan 2006.
Caption: NVD gives a specific CWE for two of the four 2005 CVEs checked.
Notes: Part 3. MS05-039 [19][21][22]. VERITAS [25][26][27]. Cisco [28][29][30]. XCP [31][32][33]. WMF [34][35][36][37][38].

## PART 4 | Worms, botnets and the web

Left: Worms
- Zotob and Mytob via MS05-039.
- Arrests in Morocco and Turkey.
- Samy on MySpace, author's account.
- Sasser's author convicted.
Right: Botnets
- Ancheta's rxbot botnets.
- Access sold for DDoS and spam.
- Adware paid per machine.
- 57 months in May 2006.
Caption: No 2005 worm, botnet or rootkit has an ATT&CK software object; the techniques are bound instead.
Notes: Part 4. Zotob [24][23][21]. Samy [42], Reported. Sasser [61], Reported. Ancheta [50][51]. Library software data [85].

## PART 5 | The state record, mostly written later

Left: In the 2005 record
- TA05-189A targeted trojan e-mail.
- Spoofed, work-themed messages.
- Titan Rain, TIME, Reported.
- Athens wiretaps, Reported.
Right: Dated by later records
- Snake in use after early 2004.
- Turla and Uroburos bound.
- EQUATIONDRUG, 2003 to 2013.
- Equation bound with a caveat.
Caption: TA05-189A names no actor; Titan Rain's attribution is hedged in TIME's own account.
Notes: Part 5. TA05-189A [43]. Titan Rain [44]. Athens [45]. Snake [46][47]. Equation [48][49].

## PART 6 | Crime and prosecutions

- **Phones and accounts:** Jacobsen's T-Mobile plea; a juvenile's 15-month spree.
- **Old conduct, new sentences:** Jiang's keylogger, the RPCSDBOT juvenile, Lyttle.
- **Extortion:** Greco's threats against MySpace.com after 1.5 million spam messages.
- **Piracy:** Operation Site Down, more than 90 searches in 11 countries.
- **Card fraud:** six Shadowcrew pleas; Butler's hacking alleged from mid-2005.
Caption: Indictments and complaints are allegations; Shadowcrew and Butler are summarized from their home study.
Notes: Part 6. Jacobsen [53]; juvenile [52]. Jiang [57]; RPCSDBOT [55]; Lyttle [56]. Greco [54]. Site Down [60]. Shadowcrew [58]; Butler [59][92].

## PART 7 | Law, regulation and standards

| Date | Event | Grade |
|---|---|---|
| 25 Feb | FIPS 201 | Confirmed |
| 28 Feb | NIST SP 800-53 | Confirmed |
| 29 Mar | Interagency breach-response guidance | Confirmed |
| 14 Apr | OCC Bulletin 2005-13; FIRST takes CVSS | Confirmed |
| 8 Aug | Energy Policy Act | Confirmed |
| 12 Oct | FFIEC authentication guidance | Confirmed |
| 14 Oct | ISO/IEC 27001:2005 | Confirmed |
| 16 Nov | NIST SP 800-40 Version 2 | Confirmed |
| Dec | RFC 4301 | Confirmed |
Notes: Part 7. FIPS 201 [69]. SP 800-53 [68]. Interagency guidance [63]. OCC [64]; CVSS [78]. Energy Policy Act [66]. FFIEC [65]. ISO/IEC 27001 [74]. SP 800-40 [70]. RFC 4301 [76].

## MITRE MAPPINGS | 31 Enterprise techniques, every one a later mapping

| Id | Technique | 2005 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | CardSystems |
| T1029 | Scheduled Transfer | CardSystems |
| T1078.001 | Default Accounts | BJ's, DSW |
| T1210 | Exploitation of Remote Services | Zotob |
| T1203 | Exploitation for Client Execution | WMF |
| T1014 | Rootkit | Sony BMG XCP |
| T1566.001 | Spearphishing Attachment | TA05-189A |
Caption: ATT&CK v20.0 ids; Equation's object-level techniques sit in their own table.
Notes: Part 9. Rows [15][14][13][21][22][34][31][43]. Basis scores in the layer: 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2005 lessons still apply

Left: What 2005 taught
- Vet the customer.
- Keep less card data.
- Change every default.
- Test for SQL injection.
Right: What still applies
- Segment wireless.
- Watch outbound traffic.
- Treat backup agents as exposed.
- Plan for an unpatched flaw.
Notes: Top recommendations and Part 8. Customers [4][6]. Retention [14][13][15]. Defaults [14][13][27]. SQL injection [16]. Wireless [13]. Egress [15]. Backup agents [25]. WMF [34][38].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- The broker losses as hacks.
- Zotob as Internet-scale.
- Titan Rain as confirmed.
- Round breach counts.
Right: Understated
- The processor as weak point.
- Retention.
- Backup software.
- TA05-189A.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [6][9][24][23][19][44][1][5][10][11][15]. Understated [15][11][14][13][25][27][43]. Cross-cutting themes and the overstated and understated passage.
