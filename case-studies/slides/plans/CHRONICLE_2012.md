# Slide plan: The Year 2012 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2012.md
- Cover title: The Year 2012 / in Intrusions / A Dated Record
- Subtitle: Flame, forged certificates, wipers and the year the banks were flooded
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2012.md, told from Microsoft bulletins, advisories and MSRC posts, US-CERT and ICS-CERT alerts in CISA's archive, CERT/CC vulnerability notes, CVE, NVD and KEV records, Kaspersky's, CrySyS Lab's, Symantec's and Mandiant's reports, company SEC filings, Justice Department, FBI and FTC releases, the 2014 and 2016 indictments, and NIST, IETF, MITRE, European Commission and congressional records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | One search for a wiper found two espionage toolkits

- **Flame:** the ITU's request to find the wiper that hit Iran led Kaspersky to Flame on 28 May.
- **Certificates:** Microsoft revoked three of its own intermediate CAs on 3 June.
- **Wipers:** Wiper hit Iran in April; Kaspersky analysed Shamoon on 16 August.
- **Banks:** online banking was flooded all autumn; an indictment named Iranians in 2016.
- **Clients:** Java, Internet Explorer, Office and Flash flaws were exploited at or before their fixes.
Caption: Grades: vendor, government and court records Confirmed; Doctor Web's counts and KrebsOnSecurity Reported.
Notes: Flame [19][20]. Certificates [23][26]. Wipers [19][39]. Banks [52][53][56][57]. Clients [14][30][38][41][49].

## KEY FACTS | Four numbers from the primary record

Stat: 83 | Microsoft bulletins, MS12-001 to MS12-083
Stat: 5,351 | CVE records NVD published in 2012
Stat: 22 | CVE-2012 ids in CISA's KEV catalog today
Stat: 140 | Gbps, about, at the peak of the bank DDoS, as alleged
- Five of the 22 KEV entries are flagged for known ransomware use.
- KEV added the year's entries from November 2021 to April 2026.
- No 2012 record carries an ATT&CK id; every binding is later.
Notes: Bulletins [72], count Inferred. CVE volume [108]. KEV [55]. DDoS [57], as alleged. ATT&CK objects created 2017 [22][40].

## PART 1 | The year in date order, from Megaupload to WCIT-12

| Date | Event |
|---|---|
| 19 Jan | Megaupload arrests in Auckland |
| 23 Mar | Operation b71 seizes Zeus servers |
| 30 Mar | Global Payments 8-K |
| 10 Apr | MS12-027, CVE-2012-0158 |
| 28 May | Kaspersky publishes Flame |
| 3 Jun | Advisory 2718704 |
| 26 Jun | Card Shop arrests; FTC sues Wyndham |
| 31 Jul | Dropbox account takeovers |
| 16 Aug | Kaspersky analyses Shamoon |
| 27 Aug | TA12-240A on Java 7 |
| 6 Sep | Symantec's Elderwood Project |
| 3 Dec | WCIT-12 opens in Dubai |
Notes: Megaupload [1]. b71 [12]. Global Payments [8]. MS12-027 [14]. Flame [20]. Advisory [23]. Card Shop [32]. Wyndham [80]. Dropbox [35]. Shamoon [39]. Java [41]. Elderwood [46]. WCIT-12 [93].

## PART 2 | Flame, Gauss and a forged Microsoft certificate

- **Flame:** in use since at least August 2010, about 20 times larger than Stuxnet.
- **CrySyS:** published its own report, sKyWIper, three days later.
- **Advisory 2718704:** three Microsoft CAs revoked; the advisory does not name Flame.
- **Collision:** MSRC says an MD5 collision made a licensing certificate sign code.
- **Gauss:** built on the Flame platform, it stole Lebanese banking credentials.
Caption: The Stuxnet study is the home; this deck records the 2012 dates.
Notes: Part 2. Flame [20][21]. Advisory [23][25]. Collision [26]. Gauss [36][37]. Home study [115].

## PART 3 | Wipers arrived and attribution stayed thin

Left: The record
- Wiper in Iran, 21 to 30 Apr.
- No complete Wiper sample.
- Shamoon overwrites the MBR.
- A signed raw-disk driver.
Right: The limits
- Kaspersky names no victim.
- Shamoon "more likely" a copycat.
- ATT&CK's attribution is Reported.
- Aramco named only from 2017.
Caption: Only two of Shamoon's 24 ATT&CK techniques cite the 2012 report.
Notes: Part 3. Wiper [19]. Shamoon [39]. ATT&CK [40]. Home studies [115].

## PART 4 | Espionage was reported, and charged years later

| Date | Event | Grade |
|---|---|---|
| 31 Jan | USW e-mails stolen, as alleged | Confirmed (as alleged) |
| 18 Apr | APT1 phishes Mandiant staff | Confirmed |
| Jul | First known access to OPM | Confirmed |
| 17 Jul | Madi campaign published | Confirmed |
| 6 Sep | Elderwood's four 2012 zero-days | Confirmed |
| 10 Sep | Telvent breach | Reported |
| Oct | Red October investigation begins | Confirmed |
Notes: Part 4. PLA indictment [60]. APT1 [58]. OPM [81]. Madi [34]. Elderwood [46][45]. Telvent [84][58]. Red October [63].

## PART 5 | Banks were flooded; the indictment came in 2016

- **Campaign:** sporadic from about December 2011, near-weekly from September 2012, as alleged.
- **Scale:** up to about 140 Gbps against at least 46 institutions over 176 days, as alleged.
- **Filings:** PNC and Capital One described disruption and named no attacker.
- **Hacktivism:** after Megaupload, Anonymous used HTTP GET and UDP floods.
Caption: The Iran study is the home for the 2011 to 2013 financial-sector DDoS.
Notes: Part 5. Indictment [56][57]. Filings [52][53]. TA12-024A [2]. Home study [115].

## PART 6 | Breaches became filings

| Date | Event | Grade |
|---|---|---|
| 30 Mar | Global Payments self-reports | Confirmed |
| 26 Jul | USD 84.4 million pre-tax charge | Confirmed |
| Jun | LinkedIn: 6.5 million passwords | Confirmed |
| 31 Jul | Dropbox: reused passwords | Confirmed |
| 24 Oct | Barnes & Noble PIN pads | Confirmed |
| 26 Jun | FTC sues Wyndham | Confirmed (as alleged) |
Notes: Part 6. Global Payments [8][9][10][11]. LinkedIn [28][29]. Dropbox [35]. Barnes & Noble [54]. Wyndham [80].

## PART 7 | Clients were the front door

Left: Exploited at or before the fix
- Office common controls, Apr.
- XML Core Services, Jun.
- Flash in a Word file, Aug.
- Java 7, Aug.
- Internet Explorer, Sep.
Right: The KEV tail
- 22 CVE-2012 entries.
- Added 2021 to 2026.
- Five with ransomware use.
- Three are Java flaws.
Caption: KEV dates are additions, not exploitation dates.
Notes: Part 7. Exploited [14][30][38][41][49]. KEV [55]. Java [16][41][55].

## PART 8 | Takedowns went to court

| Date | Event | Grade |
|---|---|---|
| 5 Jan | Megaupload indicted in E.D. Va. | Confirmed (as charged) |
| 6 Mar | LulzSec and AntiSec charges | Confirmed (as charged) |
| 23 Mar | Zeus-family servers seized | Confirmed |
| 26 Jun | Operation Card Shop, 24 arrests | Confirmed |
| 9 Jul | DNSChanger servers due off | Confirmed |
| 9 Aug | FBI warns of Reveton | Confirmed |
| 10 Sep | Microsoft's Nitol order | Confirmed |
Notes: Part 8. Megaupload [1]. Hacktivists [6][7]. b71 [12]. Card Shop [32]. DNSChanger [3][4][5]. Reveton [77]. Nitol [13].

## PART 9 | Trust and standards were rebuilt

| Date | Event | Grade |
|---|---|---|
| 6 Mar | FIPS 180-4 | Confirmed |
| 26 Apr | House passes CISPA | Confirmed |
| 2 Aug | Senate cloture fails on S. 3414 | Confirmed |
| 14 Aug | Windows rejects RSA keys under 1024 bits | Confirmed |
| Aug | RFC 6698, DANE | Confirmed |
| 2 Oct | NIST selects Keccak as SHA-3 | Confirmed |
| Nov | RFC 6797, HSTS | Confirmed |
Notes: Part 10 and the certificate record. FIPS 180-4 [94]. CISPA [89]. Senate [90]. Key length [103]. DANE [97]. SHA-3 [95]. HSTS [99].

## CROSS-CUTTING THEMES | What the year's record shows

- **Trust:** a forged Microsoft certificate signed code as HSTS, DANE and SHA-3 arrived.
- **Clients:** Java, Internet Explorer, Office and Flash were the year's front door.
- **Espionage and destruction:** Flame, Gauss, Wiper and Shamoon all surfaced from May to August.
- **Attribution lagged:** the bank DDoS was charged in 2016 and the PLA thefts in 2014.
- **Courts:** Megaupload, DNSChanger, Zeus and Nitol were each handled by a court order.
Caption: The themes are the study's reading of the record (Inferred).
Notes: Cross-cutting themes. Trust [26][51][99][97][95]. Clients [14][30][38][41][49]. Surfaced [20][37][19][39]. Attribution [56][59][58][81]. Courts [1][3][12][13].

## MITRE MAPPINGS | 36 Enterprise techniques, every one a later mapping

| Id | Technique | 2012 use |
|---|---|---|
| T1091 | Replication Through Removable Media | Flame, Gauss |
| T1123 | Audio Capture | Flame |
| T1561.002 | Disk Structure Wipe | Shamoon |
| T1189 | Drive-by Compromise | Elderwood |
| T1588.004 | Digital Certificates | Advisory 2718704 |
| T1110.004 | Credential Stuffing | Dropbox |
| T1498 | Network Denial of Service | Bank DDoS |
Caption: ATT&CK v20.0 ids; 22 are listed by ATT&CK for S0143, S0140, G0066 or G0006; two ICS ids for Flame sit in the study's table.
Notes: Part 12. Rows [22][37][40][45][23][35][57]. Basis scores in the layer: 100 Listed, 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2012 lessons still apply

Left: What 2012 taught
- Remove Java from browsers.
- Workaround before fix.
- Inventory trusted CAs.
- Find weak keys.
Right: What still applies
- MFA stops reuse.
- Plan DDoS capacity.
- Backups out of reach.
- Inspect card hardware.
Notes: Top recommendations and Part 11. Java [41][55]. Workarounds [47][30][31]. CAs [23][33][51]. Keys [103]. Dropbox [35]. DDoS [57][52][53]. Backups [86][19][39]. Card hardware [54][9].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- 2718704 naming Flame.
- Aramco as a 2012 finding.
- Iranian attribution of wipers.
- Dollar and infection counts.
Right: Understated
- Dwell and delay.
- The KEV tail.
- Industrial exposure.
- The policy split.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [23][24][39][40][115][1][32][12][16][37]. Understated [81][80][55][82][83][84][89][90]. Cross-cutting themes and the overstated and understated passage.
