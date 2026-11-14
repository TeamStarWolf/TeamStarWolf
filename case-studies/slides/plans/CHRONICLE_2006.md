# Slide plan: The Year 2006 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2006.md
- Cover title: The Year 2006 / in Intrusions / A Dated Record
- Subtitle: A stolen laptop, the Office zero-days, and espionage dated in hindsight
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2006.md, told from Microsoft bulletins and advisories, CERT/CC vulnerability notes, US-CERT alerts in CISA's archive, CVE, NVD and KEV records, VA, Inspector General, GAO and OMB records, Justice Department and FTC releases, SEC filings by ChoicePoint, HP and TJX, NIST, IETF and MITRE records, and the later Mandiant, McAfee and Justice Department records that date espionage to 2006. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A burglary made the headlines, documents did the damage

- **Loss:** a VA analyst's laptop and drive, stolen in a burglary, held data on up to 26.5 million veterans.
- **Exploits:** WMF, Word, Excel, PowerPoint and VML flaws were exploited before their fixes.
- **Espionage:** APT1, menuPass and Shady RAT all start in 2006, in records published later.
- **Card data:** TJX's intruder intercepted authorization traffic through the year.
- **Crime:** Ancheta and Maxwell sentenced or convicted for botnets, one disrupting a hospital.
Caption: Grades: vendor, government, court and filing records Confirmed; press and malware write-ups Reported.
Notes: VA [20][22][25]. Exploits [3][28][34][39][41]. Espionage [61][66][68]. TJX [56][54]. Botnets [26][15].

## KEY FACTS | Four numbers from the primary record

Stat: 26.5M | veterans and some spouses in the VA data, at most
Stat: 9 | bulletins opened here with a flaw exploited at release
Stat: 6,659 | CVE records NVD published in 2006
Stat: 2 | CVE-2006 ids in CISA's KEV catalog today
- Microsoft broke its monthly cycle twice, for WMF and VML.
- NVD lists a CWE for most of the 2006 records checked.
- No 2006 record carries an ATT&CK id; every binding is later.
Notes: VA [20]. Bulletins [3][18][28][34][35][39][41][43][44]. NVD count [50], Demonstrated. KEV [32]. Out of cycle [3][41], Inferred. CWE [5][31][37][42][46].

## PART 1 | The year in date order, from WMF to TJX

| Date | Event |
|---|---|
| 5 Jan | MS06-001, the WMF fix, out of cycle |
| 26 Jan | FTC's ChoicePoint settlement |
| 3 Feb | Mywife.E's first file corruption |
| 3 May | VA laptop and drive stolen |
| 8 May | Ancheta sentenced to 57 months |
| 19 May | Word zero-day reported |
| 23 Jun | OMB M-06-16 on encryption |
| Jul | APT1 seen using WEBC2 |
| 8 Aug | MS06-040, the Server service |
| 6 Sep | HP discloses pretexting |
| 26 Sep | MS06-055, the VML fix |
| 18 Dec | TJX finds the intruder |
Notes: WMF [3][4]. ChoicePoint [10][9]. Mywife.E [6]. VA [13][25]. Ancheta [26]. Word [29][100][31]. M-06-16 [75]. WEBC2 [61][64]. MS06-040 [35]. HP [51]. VML [41]. TJX [54].

## PART 2 | The government lost data, mostly on media

- **VA:** burglary on 3 May; Secretary told 16 May; public 22 May; recovered 28 June.
- **USDA:** a contractor released CDs on about 350,000 tobacco program participants.
- **Marine Corps:** a thumb drive with data on 207,570 enlisted Marines.
- **Others:** an Education CD, a CMS laptop and a DOT Inspector General laptop.
- **Policy:** the Identity Theft Task Force, M-06-16 encryption and M-06-19 one-hour reporting.
Caption: The Inspector General found VA's notice neither appropriate nor timely.
Notes: Part 2. VA [20][21][22][25][13]. Other losses [13]. Task Force [74]. M-06-16 [75]. M-06-19 [76].

## PART 3 | Office files and web pages carried the exploits

Left: Exploited at release
- WMF (MS06-001), 5 Jan.
- IE createTextRange, Apr.
- Word, Excel, PowerPoint.
- VML and WebViewFolderIcon.
Right: The network side
- MS06-040 Server service.
- IRCBot.ST spread with it.
- Block TCP 139 and 445.
- Sendmail and AirPort notes.
Caption: The targeted Word attack in May is graded Reported, from the SANS Internet Storm Center.
Notes: Part 3. WMF [1][3]. IE [18]. Word [28][30]. Excel [34]. PowerPoint [39][44]. VML [41]. WebViewFolderIcon [43]. MS06-040 [35][36]. IRCBot.ST [38], Reported. Sendmail [47]. AirPort [48].

## PART 4 | Malware, botnets and the year's prosecutions

- **Mywife.E:** corrupted documents on the 3rd of each month and disabled security software.
- **Ancheta:** sold botnet access for DDoS and spam; 57 months.
- **Maxwell:** an adware botnet that disrupted a Seattle hospital; pleaded guilty 4 May.
- **Levine:** 96 months for more than one billion Acxiom records.
- **McKinnon:** extradition ordered 4 July.
Caption: Indictments are allegations; Gpcode is described but undated, so it is left off the timeline.
Notes: Part 4. Mywife.E [6][7]. Ancheta [26]. Maxwell [14][15]. Levine [17]. McKinnon [27]. Gpcode [8], Reported.

## PART 5 | The corporate record

| Date | Event | Grade |
|---|---|---|
| 26 Jan | ChoicePoint: $10M penalty, $5M redress | Confirmed |
| 23 Feb | CardSystems settlement | Confirmed |
| 6 Sep | HP 8-K: pretexting used for phone records | Confirmed |
| 2006 | PCI Security Standards Council founded | Confirmed |
| May to Dec | TJX authorization traffic intercepted | Confirmed |
| 18 Dec | TJX finds suspicious software | Confirmed |
Notes: Part 5. ChoicePoint [10][9][11]. CardSystems [12]. HP [51][52][53]. PCI Council [82]. TJX [56][54][55]. TJX's home study is E-Commerce Threats [91].

## PART 6 | The state record was written in arrears

Left: Dated by later records
- APT1 seen from 2006.
- WEBC2 from July 2006.
- APT10 campaign, about 2006.
- Shady RAT from mid-2006.
Right: Caveats
- Mandiant's visibility, not a start.
- Indictments are allegations.
- McAfee names no country.
- Athens wiretaps Reported.
Caption: APT1, WEBC2, menuPass and PoisonIvy are bound with their dating caveats.
Notes: Part 6. APT1 [61][62][63]. WEBC2 [64]. APT10 and menuPass [65][66][67]. Shady RAT [68]. Athens [69][70], Reported.

## PART 7 | Industry, law and standards

| Date | Event | Grade |
|---|---|---|
| Feb | Cyber Storm I exercise | Confirmed |
| 1 Mar | FIPS 200 | Confirmed |
| 15 Mar | EU Data Retention Directive | Confirmed |
| Apr | RFC 4346, TLS 1.1 | Confirmed |
| 26 May | Vista Beta 2 with ASLR on | Confirmed |
| Aug | Browns Ferry shutdown, not an attack | Confirmed |
| 13 Sep | NIST SP 800-92, log management | Confirmed |
| 8 Nov | UK Police and Justice Act | Confirmed |
| 19 Dec | NIST SP 800-53 Revision 1 | Confirmed |
| 2006 | First CWE List | Confirmed |
Notes: Parts 7 and 8. Cyber Storm [16]. FIPS 200 [77]. Data Retention [83]. TLS 1.1 [86]. Vista [87]. Browns Ferry and Harrisburg [71]. SP 800-92 [79]. Police and Justice Act [84]. SP 800-53 [78]. CWE [88].

## MITRE MAPPINGS | 20 Enterprise techniques, every one a later mapping

| Id | Technique | 2006 use |
|---|---|---|
| T1203 | Exploitation for Client Execution | Office, WMF, VML |
| T1566.001 | Spearphishing Attachment | APT10, Shady RAT |
| T1210 | Exploitation of Remote Services | MS06-040 |
| T1584.005 | Botnet | Ancheta, Maxwell |
| T1485 | Data Destruction | Mywife.E |
| T1040 | Network Sniffing | TJX |
| T1583.001 | Domains | APT1 |
Caption: ATT&CK v20.0 ids; group-level techniques for APT1 and menuPass sit in their own table.
Notes: Part 9. Rows [3][28][41][66][68][35][26][14][6][56][61][63]. Basis scores in the layer: 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2006 lessons still apply

Left: What 2006 taught
- Encrypt what leaves.
- Plan the notice chain.
- Distrust outside files.
- Block what bulletins say.
Right: What still applies
- Memory protections on.
- Watch the card path.
- No blank passwords.
- Keep the logs.
Notes: Top recommendations and Part 8. Encryption [75]. Notice [25][76]. Office files [28][34][39]. Blocking [35]. DEP and ASLR [87]. Card path [56]. Passwords [6]. Logs [79].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- The VA theft as a hack.
- CVE count as risk.
- 2006 as APT1's start.
- Shady RAT as attribution.
Right: Understated
- Office as attack surface.
- Out-of-cycle releases.
- TJX's year of interception.
- The basics that arrived.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [20][25][50][32][61][68]. Understated [28][34][39][44][3][41][56][54][87][79][80][88]. Cross-cutting themes and the overstated and understated passage.
