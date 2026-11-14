# Slide plan: The Year 2010 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2010.md
- Cover title: The Year 2010 / in Intrusions / A Dated Record
- Subtitle: Aurora, a USB worm in the control room, and the year encryption became the default
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2010.md, told from Google's disclosures, Microsoft bulletins and advisories, CERT/CC vulnerability notes, US-CERT alerts and ICS-CERT advisories in CISA's archive, CVE, NVD and KEV records, Mozilla's and Symantec's records, Justice Department and FBI releases, the Shadows in the Cloud report, the US-China Economic and Security Review Commission's 2010 report, the Deputy Secretary of Defense's Foreign Affairs article, and NIST, IETF, DHS and UK government records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year's headlines were disclosures of earlier attacks

- **Aurora:** Google disclosed a December 2009 attack on 12 January; MS10-002 fixed the flaw on 21 January.
- **Stuxnet:** a USB-borne worm went after Siemens control software; MS10-046 shipped on 2 August.
- **Crime:** Butler got 13 years, Gonzalez 20, and New York charged 37 Zeus defendants in a day.
- **Espionage:** researchers and a commission documented it without a state finding.
- **Defaults:** Gmail HTTPS, HTTPS Everywhere, RFC 5746 and the signed root all date from 2010.
Caption: Grades: vendor, government and court records Confirmed; press relays of Iranian statements Reported.
Notes: Aurora [1][4]. Stuxnet [22][25][30]. Crime [13][66][42]. Espionage [18][10]. Defaults [76][77][70][73].

## KEY FACTS | Four numbers from the primary record

Stat: 106 | Microsoft bulletins, MS10-001 to MS10-106
Stat: 13 | flaws exploited at or before their fix
Stat: 17 | days, at least, with no fix for the shortcut flaw
Stat: 23 | CVE-2010 ids in CISA's KEV catalog today
- KEV added CVE-2010-0249, the Aurora flaw, on 20 May 2026.
- Four of the 23 KEV entries are flagged for known ransomware use.
- No 2010 record carries an ATT&CK id; every binding is later.
Notes: Bulletins [49][50], count Inferred. Exploited [4][52][21][25][31][53][39][55][45][56][60][62][63]. Shortcut flaw [24][25][26], count Inferred. KEV [8].

## PART 1 | The year in date order, from Aurora to PayPal

| Date | Event |
|---|---|
| 12 Jan | Google discloses Aurora |
| 21 Jan | MS10-002 fixes the IE flaw |
| 22 Feb | Waledac's 277 domains cut off |
| 25 Mar | Gonzalez sentenced to 20 years |
| 6 Apr | Shadows in the Cloud published |
| 8 Apr | China Telecom route event |
| 17 Jun | VirusBlokAda reports Stuxnet |
| 16 Jul | Advisory 2286198, shortcut flaw |
| 2 Aug | MS10-046 out of band |
| 1 Sep | Buckshot Yankee disclosed |
| 30 Sep | 37 Zeus defendants charged |
| 24 Oct | Firesheep released |
Notes: Aurora [1][4]. Waledac [15]. Gonzalez [66]. Shadows [18]. Routes [10]. Stuxnet [30][24][25]. Buckshot Yankee [38]. Zeus [42]. Firesheep [68].

## PART 2 | Browsers and documents were exploited all year

Left: Exploited at release
- IE: Aurora, then two more.
- Firefox 3.6 in October.
- Reader and Flash, four flaws.
- Office RTF in November.
Right: The KEV tail
- 23 CVE-2010 entries.
- Two added in 2026.
- JBoss, ColdFusion, Exim.
- Four tied to ransomware.
Caption: Adobe's fixes were not opened; the Adobe rows rest on the CVE records.
Notes: Part 2. IE [4][52][45]. Firefox [56]. Reader and Flash [60][62][63][58]. Office [54]. KEV [8][59][61][64].

## PART 3 | Stuxnet reached the control room by USB

- **Spread:** a crafted shortcut on a USB drive ran code when viewed, without AutoRun.
- **Target:** ICS-CERT said the trojan interacted with Siemens SIMATIC WinCC and STEP 7.
- **Flaws:** MS08-067 and four zero-days, with drivers signed by two revoked certificates.
- **Scale:** about 100,000 infected hosts, roughly 60 percent in Iran, per Symantec.
- **Advice:** disable AutoRun and shortcut icons, least privilege, care with USB drives.
Caption: The Stuxnet study is the home; this deck records the 2010 dates.
Notes: Part 3. Shortcut flaw [23][24]. ICS-CERT [22][28][29]. Symantec [30]. Hard-coded password [33]. Home study [87].

## PART 4 | Prosecution caught up with the carding era

| Date | Event | Grade |
|---|---|---|
| 12 Feb | Butler sentenced to 13 years | Confirmed |
| 22 Feb | Waledac restraining order | Confirmed |
| 25 Mar | Gonzalez sentenced to 20 years | Confirmed |
| Feb, Jul | Mariposa arrests in Spain, Slovenia | Confirmed |
| 30 Sep | SDNY charges 37 Zeus defendants | Confirmed |
| 1 Oct | FBI's Operation Trident Breach | Confirmed |
| 6 to 10 Dec | PayPal attacks, as later charged | Confirmed |
Notes: Part 4. Butler [13][14]. Waledac [15]. Gonzalez [66][67]. Mariposa [16]. Zeus [42][43][44]. PayPal [46].

## PART 5 | Espionage was documented, not attributed

Left: The record
- Aurora: "from China".
- Shadows: Dalai Lama, India.
- Routes diverted 18 minutes.
- Night Dragon on energy.
Right: The limits
- Google names no state.
- Chengdu is circumstantial.
- USCC assesses, not finds.
- Night Dragon unidentified.
Caption: Elderwood, Hydraq and Night Dragon are bound with ATT&CK's own caveats.
Notes: Part 5. Aurora [1][10][11][12]. Shadows [18][19]. Routes [10]. Night Dragon [47]. Buckshot Yankee [38].

## PART 6 | The web's defaults moved

| Date | Event | Grade |
|---|---|---|
| 12 Jan | Gmail HTTPS on by default | Confirmed |
| 28 Jan | Chromium bug rewards | Confirmed |
| Feb | RFC 5746, TLS renegotiation | Confirmed |
| 5 to 9 Apr | Apache JIRA attack | Confirmed |
| 17 Jun | HTTPS Everywhere | Confirmed |
| 15 Jul | Signed DNS root trust anchor | Confirmed |
| 21 Sep | Twitter onMouseOver | Confirmed |
| 24 Oct | Firesheep | Confirmed |
Notes: Part 6. Gmail [76]. Chromium [74]. RFC 5746 [70]. Apache [17]. HTTPS Everywhere [77]. Root [73]. Twitter [41]. Firesheep [68].

## PART 7 | Governments organized and wrote standards

| Date | Event | Grade |
|---|---|---|
| Feb | NIST SP 800-37 Revision 1 | Confirmed |
| 29 Mar | 2010 CWE/SANS Top 25 | Confirmed |
| Apr | OWASP Top 10 2010 | Confirmed |
| May | US Cyber Command operating | Confirmed |
| 31 Aug | NISTIR 7628, smart grid | Confirmed |
| 27 Sep | Cyber Storm III begins | Confirmed |
| 19 Oct | UK review: GBP 650M for cyber | Confirmed |
Notes: Part 7. SP 800-37 [69]. Top 25 [71]. OWASP [72], release day approximate. Cyber Command [38]. NISTIR 7628 [78]. Cyber Storm III [79]. UK review [80].

## CROSS-CUTTING THEMES | What the year's record shows

- **Disclosures:** Aurora, Buckshot Yankee and Stuxnet all surfaced in 2010 from earlier events.
- **Removable media:** a flash drive and a USB worm both crossed into protected networks.
- **Places, not perpetrators:** Google, the Shadows report and the USCC stop short of a state finding.
- **Courts:** a civil order cut off Waledac; Zeus cases ran in four countries.
- **Defaults:** encryption and integrity moved from opt-in toward on by default.
Caption: The themes are the study's reading of the record (Inferred).
Notes: Cross-cutting themes. Disclosures [1][38][34]. Removable media [38][22]. Attribution [1][18][10]. Courts [15][16][43]. Defaults [76][77][70][73][68].

## MITRE MAPPINGS | 71 Enterprise techniques, every one a later mapping

| Id | Technique | 2010 use |
|---|---|---|
| T1203 | Exploitation for Client Execution | Aurora, Reader |
| T1091 | Replication Through Removable Media | Stuxnet |
| T1189 | Drive-by Compromise | Elderwood |
| T1102 | Web Service | Shadows C2 |
| T1539 | Steal Web Session Cookie | Apache JIRA |
| T1056.001 | Keylogging | Zeus |
| T1498 | Network Denial of Service | PayPal |
Caption: ATT&CK v20.0 ids; 58 are listed by ATT&CK for G0066, S0203, C0002 or S0603; ten ICS ids sit in their own layer.
Notes: Part 9. Rows [11][4][34][22][18][17][42][46]. Basis scores in the layers: 100 Listed, 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2010 lessons still apply

Left: What 2010 taught
- USB is an entry point.
- Workaround before fix.
- "Targeted" is urgent.
- Encrypt the session.
Right: What still applies
- No hard-coded passwords.
- Patch old middleware.
- Watch banking logins.
- Lock admin consoles.
Notes: Top recommendations and Part 8. USB [22][23]. Workarounds [24][25]. Advisories [3][24][39][45]. Sessions [68]. Credentials [33]. Middleware [8][59][61][64]. Zeus [42][43]. Apache [17].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- Aurora as one exploit.
- "Chinese state" findings.
- The route event as a hijack.
- Botnet and theft totals.
Right: Understated
- The KEV tail.
- The year's new defaults.
- The AT&T exposure.
- Buckshot Yankee.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [1][11][12][18][10][16][15][43]. Understated [8][73][76][70][20][38]. Cross-cutting themes and the overstated and understated passage.
