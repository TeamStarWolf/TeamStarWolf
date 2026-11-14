# Slide plan: The Year 2008 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2008.md
- Cover title: The Year 2008 / in Intrusions / A Dated Record
- Subtitle: A wormable flaw, weak foundations and a state record written later
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2008.md, told from Microsoft bulletins, advisories and support articles, CERT/CC vulnerability notes and US-CERT alerts in CISA's archive, CVE, NVD and KEV records, Debian's advisory, Justice Department, FBI and FTC releases, court opinions, SEC filings, the CCDCOE report, the Cambridge and Citizen Lab reports, NIST, IETF, PCI Council, FERC, OMB, NATO and MITRE records, and the vendor reports from 2014 to 2017 that date state tools to 2008. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year of MS08-067

- **Worm:** MS08-067 shipped out of band and was already exploited.
- **Web:** mass SQL injection hit sites, not a product flaw.
- **Foundations:** Debian's RNG, DNS cache poisoning and MD5 certificates.
- **Cards:** Hannaford, the Gonzalez ring and Heartland, found by the networks.
- **State:** Buckshot Yankee and Georgia, mostly written later.
Caption: Grades: vendor, CERT, court, Justice and government records Confirmed; ATT&CK's Conficker date Reported.
Notes: MS08-067 [16][17][18]; Conficker [20][21]. SQL injection [7]. Debian [3][5]; DNS [8][9]; MD5 [28][30]. Cards [56][51][12]. Lynn [23]; Georgia [38].

## KEY FACTS | Four numbers from the primary record

Stat: 40M+ | card numbers in the Gonzalez ring charges
Stat: 56 | arrests when the DarkMarket sting closed
Stat: 6 | CVE-2008 ids in CISA's KEV catalog
Stat: 33 | Enterprise techniques, all later mappings
- CVE-2008-4250 entered KEV on 20 May 2026.
- Hannaford's 4.2 million cards are the plaintiffs' allegation.
- CWE reached version 1.0 in September 2008.
Notes: Gonzalez ring [51]. DarkMarket [15]. KEV [19]. Part 7 for the technique rows. Hannaford [56]. CWE [59].

## PART 1 | The year in date order, from CNCI to the rogue CA

| Date | Event |
|---|---|
| Jan | CNCI; NATO cyber defence policy |
| 24 Feb | YouTube prefix hijack |
| 17 Mar | Hannaford announces its breach |
| 13 May | Debian OpenSSL advisory |
| 24 Jun | SQL injection advisory 954462 |
| 8 Jul | DNS cache poisoning fixes |
| 5 Aug | Gonzalez ring charged |
| 8 Aug | Attacks on Georgia begin |
| 1 Oct | PCI DSS 1.2 |
| 20 Oct | DarkMarket sting ends |
| 23 Oct | MS08-067 out of band |
| 30 Dec | MD5 rogue CA research |
Notes: Part 1. CNCI [1]; NATO [66]. YouTube [2]. Hannaford [56]. Debian [5]. Advisory 954462 [7]. DNS [8][9]. Gonzalez [51]. Georgia [38]. PCI DSS [13]. DarkMarket [15]. MS08-067 [16][17]. MD5 [28][30].

## PART 2 | The vulnerability record

- **Debian:** a predictable RNG; upgrade, then regenerate every key.
- **SQL injection:** sites that did not validate input; no CVE id.
- **DNS:** port randomization reduced the risk; DNSSEC was the full fix.
- **MS08-067:** wormable, exploited, then Conficker by ATT&CK's date.
- **Browser and Reader:** util.printf() and IE data binding; MS08-078 out of band.
Caption: Six CVE-2008 ids reached KEV between 2022 and 2026, 14 to 18 years after the events.
Notes: Part 2. Debian [3][4][5]. SQL injection [7]. DNS [8][9][10]. MS08-067 [16][17][18][20][21]. Reader [22]; IE [25][26][27]. KEV [19].

## PART 3 | Card theft and the crime record

Left: Card theft
- Hannaford, from Dec 2007.
- Wyndham, via a hotel network.
- Gonzalez ring: wardriving, sniffers.
- Heartland, breached in 2008.
Right: Prosecutions
- Ralsky spam indictment.
- US and Romania card fraud.
- Walker and Gembe DDoS.
- DarkMarket, 56 arrests.
Caption: Indictments and the courts' recitals are allegations; TJX, Heartland and Wyndham are summarized from their home study.
Notes: Part 3. Hannaford [56]. Wyndham [57]. Gonzalez [51][49]. Heartland [12]. Ralsky [48]. Romania [50]. Walker and Gembe [14]. DarkMarket [15].

## PART 4 | The state record

Left: Known in or near 2008
- Georgia, 8 to 28 Aug.
- Belarus floods; Lithuania defacements.
- The Dalai Lama's office.
- CCDCOE: origin undetermined.
Right: Written later
- Buckshot Yankee, told in 2010.
- Fanny compiled Jul 2008.
- Regin's GSM log, Apr to May.
- Early Stuxnet components.
Caption: Lynn names neither malware nor a country; the Agent.btz tie is ATT&CK's "reportedly".
Notes: Part 4. Georgia, Belarus and Lithuania [38]. OHHDL [35][36]. Lynn [23]; Agent.btz [24][33]. Fanny [39]. Regin [42]. Lamberts [43]. Stuxnet [41].

## PART 5 | Internet infrastructure and industrial systems

- **YouTube:** Pakistan Telecom's /24 announcement, propagated by PCCW, 24 Feb.
- **Routing, not intrusion:** no CVE and no ATT&CK technique fits.
- **Grid:** FERC Order No. 706 approved eight NERC CIP standards.
- **Nuclear:** FERC proposed the same standards for non-NRC plant facilities.
- **Hatch:** a software update tripped a 48-hour shutdown (Reported).
Caption: No 2008 event in the record is an ICS intrusion; no ATT&CK for ICS layer is saved.
Notes: Part 5. YouTube [2]. FERC [60][61]. Hatch [62], Reported. EU directive [65]. ICS rows [20][76].

## PART 6 | Law, policy and standards

| Date | Event | Grade |
|---|---|---|
| Jan | CNCI and NATO's cyber defence policy | Confirmed |
| 7 Feb | FERC Order No. 706, NERC CIP | Confirmed |
| 24 Feb | YouTube prefix hijack | Confirmed |
| 14 May | CCDCOE established | Confirmed |
| Aug | TLS 1.2; OMB DNSSEC mandate | Confirmed |
| 9 Sep | CWE 1.0 | Confirmed |
| 26 Sep | Public Law 110-326 | Confirmed |
| 1 Oct | PCI DSS 1.2 | Confirmed |
| 8 Dec | CSIS report; EU directive | Confirmed |
Notes: Part 6. CNCI [1]; NATO [66]. FERC [60]. YouTube [2]. CCDCOE [67]. TLS [69]; OMB [70]. CWE [59]. PL 110-326 [63]. PCI DSS [13]. CSIS [64]; directive [65].

## MITRE MAPPINGS | 33 Enterprise techniques, every one a later mapping

| Id | Technique | 2008 use |
|---|---|---|
| T1210 | Exploitation of Remote Services | MS08-067, Conficker |
| T1091 | Replication Through Removable Media | Agent.btz, Fanny |
| T1190 | Exploit Public-Facing Application | SQL injection wave |
| T1203 | Exploitation for Client Execution | IE data binding |
| T1566.001 | Spearphishing Attachment | Dalai Lama's office |
| T1669 | Wi-Fi Networks | Gonzalez ring |
| T1040 | Network Sniffing | Retail sniffers |
Caption: ATT&CK v20.0 ids; Conficker and Agent.btz rows are listed by ATT&CK, the rest assigned by the study.
Notes: Part 7. Rows [20][16][24][39][7][26][35][51]. Basis scores in the layer: 100 Listed, 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2008 lessons still apply

Left: What 2008 taught
- Patch out of band.
- Rotate keys after RNG flaws.
- Fix injection in your code.
- Randomize DNS source ports.
Right: What still applies
- Control removable media.
- Segment store networks.
- Limit admin guessing.
- Retire weak hashes.
Notes: Top recommendations and Part 6. MS08-067 [16][17]. Debian [5]. Injection [7]. DNS [8]. Removable media [21][39]. Networks [51][57]. Guessing [57][21]. MD5 [29][30].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- DNS as broken.
- The rogue CA as an attack.
- Turla and the Pentagon.
- Georgia as the first cyberwar.
Right: Understated
- The SQL injection wave.
- The defender plumbing.
- Belarus and Lithuania.
- The KEV tail.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [8][70][29][30][23][24][33][38]. Understated [7][59][71][68][74][69][1][38][19]. Cross-cutting themes and the overstated and understated passage.

## DISCREPANCIES | Where the record disagrees

- **Conficker's month:** October per ATT&CK, from secondary sources.
- **MS08-067:** "limited, targeted attacks" against "exploited in the wild".
- **Debian's start:** a version, a date and a range in three records.
- **Agent.btz:** origins 2007, "reportedly" 2008, and no name from Lynn.
- **Georgia and GhostNet:** attribution differs by source.
Caption: Each row names the sources that disagree; the study does not resolve them.
Notes: Discrepancies in the record. Conficker [20][18]. MS08-067 [16][17]. Debian [5][3][4]. Agent.btz [33][24][23]. Georgia [38][11]; GhostNet [35][36].
