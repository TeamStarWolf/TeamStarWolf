# Slide plan: The Year 2004 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2004.md
- Cover title: The Year 2004 / in Intrusions / A Dated Record
- Subtitle: A mail storm, a destructive worm, and defaults that started to do the work
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2004.md, told from the CERT/CC advisories and vulnerability notes, US-CERT alerts in CISA's archive, Microsoft bulletins and statements, F-Secure's virus descriptions, CAIDA's Witty analysis, CVE and NVD records, Justice Department, FTC and Secret Service releases, statutes, NIST, IEEE and RFC Editor records, and the later government and vendor reports that date state tools to 2004. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | A mail storm, then the worms came back

- **Mail:** Bagle, MyDoom and Netsky hit home users and sites from January.
- **Worms:** Witty wiped disks of ISS security software; Sasser rode the LSASS flaw.
- **Web:** Download.Ject turned trusted IIS servers into drive-by sources.
- **Crime:** CAN-SPAM, Fastlink, Web Snare and Shadowcrew met organized fraud.
- **Defaults:** XP SP2 turned the firewall on and added DEP.
Caption: Grades: CERT, US-CERT, vendor, Justice, FTC and statute records Confirmed; press Reported.
Notes: Mail [34][1][32][41][36]. Witty [37][38]; Sasser [43][41][9]. Download.Ject [44][16][18]. CAN-SPAM [56][57]; Fastlink [62]; Web Snare [69]; Shadowcrew [71][72]. XP SP2 [49][50][52].

## KEY FACTS | Four numbers from the primary record

Stat: 2 | CERT/CC advisories, against 28 in 2003
Stat: 12,000 | Witty hosts, every one running ISS software
Stat: 108 | months for Lowe's, then a record federal hacking term
Stat: 22 | ATT&CK Enterprise technique rows, all later mappings
- CVE ids were cited at the time in the CAN- candidate form.
- NVD gives a specific CWE for one of nine 2004-era records checked.
- CWE, CAPEC and CVSS custody came later: 2006, 2007 and 2005.
Notes: CERT advisories [1][2]. Witty [37]. Lowe's [74]. Part 8 for the technique rows. CAN form [9][13]. CWE [13][128][7][40][129][21][22][31][4]. CWE, CAPEC and CVSS [98][99][100].

## PART 1 | The year in date order, from H.323 to Santy

| Date | Event |
|---|---|
| 13 Jan | CA-2004-01, H.323 flaws |
| 27 Jan | CA-2004-02, Bagle and MyDoom |
| 28 Jan | MyDoom.B, the first DHS alert |
| 19 Mar | Witty begins |
| 13 Apr | MS04-011, the LSASS fix |
| 8 May | Sasser arrest announced |
| 24 Jun | Download.Ject response |
| 24 Jul | IEEE 802.11i published |
| 6 Aug | Windows XP SP2 to manufacturing |
| 26 Aug | Operation Web Snare |
| 28 Oct | Shadowcrew and Firewall |
| 21 Dec | TA04-356A, Santy.A |
Notes: CA-2004-01 [1][3]. CA-2004-02 [1]. MyDoom.B [32][33]. Witty [37]. MS04-011 [9]. Sasser [41]. Download.Ject [44]. 802.11i [92]. XP SP2 [49]. Web Snare [69]. Shadowcrew [71][72]. Santy.A [28].

## PART 2 | Parsers and browsers carried the critical flaws

- **CERT/CC:** two numbered advisories, then US-CERT's alert series took over.
- **Parsers:** ASN.1, H.323, JPEG in GDI+ and PNG in libpng.
- **LSASS:** MS04-011 fixed the overrun that Sasser later used.
- **Browsers:** MS04-025 and MS04-040 fixed flaws already exploited.
- **Infrastructure:** TCP session resets against BGP and a CVS heap overflow.
Caption: That the numbered series ended in 2004 is the study's reading (Inferred).
Notes: Part 2. CERT/CC [1][2]. Parsers [5][9][1][19][22]. LSASS [9][11][12][13]. Browsers [18][25]. TCP resets [14]; CVS [15].

## PART 3 | Witty struck the defenders' own tools

- **Start:** about 20:45 PST on 19 March, the day after the flaw was announced.
- **Target:** the ISS Protocol Analysis Module in RealSecure, Proventia and BlackICE.
- **Speed:** about 110 hosts in ten seconds, peak after about 45 minutes.
- **Payload:** data written to random disk locations.
- **Effect:** half the infected hosts inactive within 12 hours.
Caption: CAIDA calls Witty the first widely propagated Internet worm with a destructive payload.
Notes: Part 3. CAIDA's analysis [37]. VU#947254 [38]. CVE-2004-0362 [39][40].

## PART 3 | Mail, network worms and the web

Left: Mail and network
- Bagle, MyDoom, Netsky by mail.
- Phatbot through Windows flaws.
- Sasser on TCP 445 via LSASS.
- Arrest within seven days.
Right: Web and phone
- Download.Ject via IIS and IE.
- Bofra through e-mailed links.
- Santy.A against phpBB forums.
- Cabir on Symbian over Bluetooth.
Caption: No 2004 worm has an ATT&CK software object; the techniques are bound instead.
Notes: Part 3. Bagle [34]; MyDoom [35][32][33]; Netsky [41]. Phatbot [36]. Sasser [43][41]. Download.Ject [44][16][17]. Bofra [23][24][25]. Santy.A [27][28]. Cabir [47]. Library software data [121].

## PART 4 | The state record was written in hindsight

Left: Dated by later records
- Snake finished about early 2004.
- APT1 persona and first domain.
- EquationLaser compiled 18 Oct.
- Government, Mandiant, Kaspersky.
Right: Reported or undated
- Titan Rain, TIME in 2005.
- Athens wiretaps, 2007 and 2015.
- APT28 since at least 2004.
- Darkhotel since at least 2004.
Caption: Turla, Uroburos, APT1, WEBC2, Equation, APT28 and Darkhotel are bound with dating caveats.
Notes: Part 4. Snake [102][103][104]. APT1 [107][108]. EquationLaser [113][114]. Titan Rain [110], Reported. Athens [111][112], Reported. APT28 [105][106]. Darkhotel [116][117].

## PART 5 | Crime organized, and so did the response

- **Spam:** CAN-SPAM in effect 1 January; first criminal charges 29 April.
- **Piracy:** Operation Fastlink and Operation Digital Gridlock.
- **Web Snare:** more than 160 investigations; hired DDoS against competitors.
- **Shadowcrew:** a 62-count indictment and Operation Firewall arrests, 28 October.
- **Lowe's:** 108 months for a wireless card-capture conspiracy.
Caption: Indictments and complaints are allegations; Web Snare's loss figure is an estimate.
Notes: Part 5. CAN-SPAM [56][57][58][59]. Fastlink [62]; Digital Gridlock [68]. Web Snare [69]. Shadowcrew [71][72]. Lowe's [74]. Bookmaker extortion [64], Reported.

## PART 6 | Law, policy and standards

| Date | Event | Grade |
|---|---|---|
| 1 Jan | CAN-SPAM in effect | Confirmed |
| Jan | NIST SP 800-61 | Confirmed |
| Feb | FIPS 199 | Confirmed |
| May | NIST SP 800-37 | Confirmed |
| 15 Jul | Identity Theft Penalty Enhancement Act | Confirmed |
| 24 Jul | IEEE 802.11i | Confirmed |
| 16 Aug | MD5 collisions paper | Confirmed |
| 27 Aug | HSPD-12 | Confirmed |
| 17 Dec | Intelligence Reform Act | Confirmed |
Notes: Part 6. CAN-SPAM [56]. SP 800-61 [78]. FIPS 199 [79]. SP 800-37 [82]. Identity theft [87][88]. 802.11i [92]. MD5 [97]. HSPD-12 [89]. Intelligence Reform [90].

## MITRE MAPPINGS | 22 Enterprise techniques, every one a later mapping

| Id | Technique | 2004 use |
|---|---|---|
| T1566.001 | Spearphishing Attachment | Bagle, MyDoom |
| T1210 | Exploitation of Remote Services | Sasser, Witty |
| T1190 | Exploit Public-Facing Application | Witty, Santy.A |
| T1189 | Drive-by Compromise | Download.Ject |
| T1561.001 | Disk Content Wipe | Witty |
| T1669 | Wi-Fi Networks | Lowe's |
| T1583.001 | Domains | APT1 |
Caption: ATT&CK v20.0 ids; object-level techniques for Snake, WEBC2 and Equation sit in their own table.
Notes: Part 8. Rows [1][32][43][37][38][28][44][74][107][108]. Basis scores in the layer: 100 Listed, 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2004 lessons still apply

Left: What 2004 taught
- Mitigate before the patch.
- Patch security tools first.
- Filter mail at the gateway.
- Encrypt wireless.
Right: What still applies
- Protections on by default.
- Guard code repositories.
- Filter spoofed sources.
- Plan for session resets.
Notes: Top recommendations and Part 7. Pre-patch [18][25][44]. Security tools [37]. Gateway [1]. Wireless [92][77]. Defaults [50][52]. Repositories [15]. Spoofing [94]. Session resets [14].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- 2004 as only a worm year.
- Download.Ject as a worm.
- Titan Rain as confirmed.
- Round loss figures.
Right: Understated
- Exploits before the fix.
- Witty's destruction.
- Wireless as the way in.
- 2004 as a standards year.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [1][32][36][44][110][69][71][72]. Understated [18][25][37][74][61][77][78][79][82]. Cross-cutting themes and the overstated and understated passage.
