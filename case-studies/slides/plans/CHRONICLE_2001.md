# Slide plan: The Year 2001 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2001.md
- Cover title: The Year 2001 / in Intrusions / A Dated Record
- Subtitle: The patch came first, the worms came anyway, and a certificate authority signed for an impostor
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2001.md, told from the CERT/CC advisories and incident notes, Microsoft bulletins, CVE and NVD records, CAIDA's measurements, Justice Department releases, court opinions, GAO testimony, executive orders, statutes, the Council of Europe treaty, European Parliament records and the NIST, ISO and RFC Editor records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The worm year ran on known flaws

- **The patch existed first:** MS01-033 came about four weeks before Code Red.
- **Worms reused footholds:** Leaves, cheese and Nimda went after back doors others left.
- **Unix carried the record:** ramen, the BIND kits, snmpXdmid, sadmind and SSH1.
- **Trust failed:** VeriSign issued two "Microsoft Corporation" certificates to an impostor.
- **Law moved after September:** the PATRIOT Act, two executive orders and Budapest.
Caption: Grades: CERT, Microsoft, CAIDA, Justice, courts, GAO, statutes and NIST Confirmed; relayed figures Reported.
Notes: MS01-033 [8], Code Red [1][15]; the interval is Inferred. Leaves, cheese [2]; Nimda [1]. Unix record [1][2]. Certificates [4][1]. PATRIOT Act [33][34], EO 13228 [36], EO 13231 [37], Budapest [35].

## KEY FACTS | Four numbers from the primary record

Stat: 37 | CERT/CC advisories, CA-2001-01 to CA-2001-37
Stat: 15 | CERT/CC incident notes, IN-2001-01 to IN-2001-15
Stat: 359,104 | hosts infected by Code-Red v2 in under 14 hours
Stat: 12 | ATT&CK for ICS techniques listed for campaign C0020
- CAIDA measured more than 2,000 new Code Red hosts a minute at the peak on 19 July.
- NVD gives no specific CWE for any of the year's CVEs checked.
- CWE, CAPEC and ATT&CK came later: every Enterprise id is a later mapping.
Notes: CERT compilations [1][2], advisory index [3]. CAIDA [15][16]. C0020 [73]. NVD records [13][14]. CWE, CAPEC and ATT&CK history [57][58][59].

## PART 1 | The year in date order, from Interbase to UPnP

| Date | Event |
|---|---|
| 10 Jan | CA-2001-01 Interbase back door account |
| 18 Jan | IN-2001-01 ramen toolkit |
| 29 Jan | Bogus Microsoft certificates issued |
| 12 Feb | Anna Kournikova |
| 30 Mar | snmpXdmid and the BIND kits |
| 8 May | sadmind/IIS worm |
| 18 Jun | MS01-033 idq.dll overflow |
| 19 Jul | Code-Red v2 spreads |
| 18 Sep | Nimda |
| 26 Oct | PATRIOT Act |
| 23 Nov | Budapest Convention |
| 20 Dec | MS01-059 UPnP overflow |
Notes: CA-2001-01 [1]. IN-2001-01 [2]. Certificates [4]. CA-2001-03 [1]. CA-2001-05 [1], IN-2001-03 [2]. CA-2001-11 [1]. MS01-033 [8]. CAIDA [16], CA-2001-19 [1]. CA-2001-26 [1]. PATRIOT Act [33][34]. Budapest [35]. MS01-059 [10], CA-2001-37 [1].

## PART 2 | The fix came before the worm

- **MS01-033:** the idq.dll fix shipped on 18 June; Code Red followed in mid-July.
- **sadmind/IIS:** a two-year-old Solaris flaw and a seven-month-old IIS flaw.
- **Nimda's mail path:** an Internet Explorer flaw patched on 29 March.
- **SSH1:** a flaw on record since March, exploited in November and December.
- **Defaults:** IIS on Windows 2000 Server, snmpXdmid on Solaris, UPnP on Windows XP.
Caption: That the large outbreaks used known flaws, not new ones, is the study's reading (Inferred).
Notes: Part 2. MS01-033 [8]. CA-2001-11 [1], MS00-078 [11]. MS01-020 [5]. IN-2001-12, CA-2001-35 [2][1], NVD [13]. Defaults [8][1][10].

## PART 3 | Worms built on each other's footholds

Left: The Windows worms
- Code Red and Code Red II.
- Nimda's five paths.
- Sircam, Klez, BadTrans, Goner.
- Kaiten on null sa passwords.
Right: The Unix worms and kits
- ramen through format strings.
- BIND kits and the lion toolkit.
- snmpXdmid, then Carko.
- cheese on old root shells.
Caption: No ATT&CK software object exists for any of these worms; the techniques are bound instead.
Notes: Part 3. CA-2001-19, CA-2001-23, CA-2001-26 [1]. IN-2001-09, IN-2001-13, IN-2001-14, IN-2001-15 [2]. Klez [60]. IN-2001-01, IN-2001-03, IN-2001-04, IN-2001-05 [2]. Library software data [76][78]. Home study for Code Red, Nimda and Klez: the dot-com era study [83].

## PART 4 | A certificate authority signed for an impostor

- **29 and 30 January:** VeriSign issues two Class 3 code-signing certificates.
- **The name:** "Microsoft Corporation", requested by someone posing as an employee.
- **The gap:** no CRL distribution point, so clients could not check revocation.
- **The fix:** MS01-017 shipped a local CRL and a revocation handler.
- **No CVE:** and no record of code actually signed with the certificates.
Caption: The study binds the acquisition (T1588.003), not signed malware (Inferred).
Notes: Part 4. MS01-017 [4]. CA-2001-04 [1]. The eMudhra study takes up the same trust question in 2026.

## PART 5 | The state record is law and litigation

Left: What is on the record
- ECHELON report and resolution.
- Scarfo keystroke logger upheld.
- Remote copying from Russia upheld.
- PATRIOT Act surveillance sections.
Right: What is not
- No ATT&CK group dated to 2001.
- Equation's date is from 2015.
- Moonlight Maze link unproven.
- Regin is not a 2001 object.
Caption: Kaspersky names no country behind Equation; the state link is the library's reading.
Notes: Part 5. ECHELON [65][66][67]. Scarfo [68][69]. Gorshkov ruling [21]. PATRIOT Act [33]. Group dates [75]. Equation [61][62][63]. Moonlight Maze [64], Reported. Regin [95]. United States study [84].

## PART 6 AND 7 | Prosecutions and the year's law

| Date | Event | Grade |
|---|---|---|
| 1 Feb | Interagency GLBA safeguards rule | Confirmed |
| 14 Apr | HIPAA privacy rule effective | Confirmed |
| 25 Apr | GAO-01-323 on NIPC | Confirmed |
| 28 Aug | Sklyarov indicted under the DMCA | Confirmed |
| 9 Oct | Gorshkov convicted in Seattle | Confirmed |
| 16 Oct | Executive Order 13231 | Confirmed |
| 22 Oct | AIPAC intrusion indictment | Confirmed |
| 26 Nov | Cisco insiders sentenced | Confirmed |
| 11 Dec | Operations Buccaneer and partners | Confirmed |
| 14 Dec | UK Anti-terrorism, Crime and Security Act | Confirmed |
Notes: GLBA [40]. HIPAA [39]. GAO [19]. Sklyarov [22]. Gorshkov [20]. EO 13231 [37]. AIPAC [24]. Cisco [26]. Operations [28][29]. UK Act [38].

## PART 8 | Cryptography and standards

- **AES:** FIPS 197 published on 26 November, binding from May 2002.
- **Modules:** FIPS 140-2 published on 25 May.
- **Detection:** NIST SP 800-31 on intrusion detection in November.
- **Filtering and logging:** OpenBSD 3.0 with PF, and RFC 3164 on syslog.
- **Application security:** OWASP launched on 1 December.
Notes: FIPS 197 [43][44]. FIPS 140-2 [46]. SP 800-31 [47]. OpenBSD [53]. RFC 3164 [52]. OWASP [51]. RC4 paper [55].

## PART 9 | Maroochy Shire: the sentence

Left: The record
- Intrusion 9 Feb to 23 Apr 2000.
- About 150 pumping stations.
- Private two-way radio network.
- Sentenced 31 October 2001.
Right: The ATT&CK record
- Campaign C0020.
- 12 ICS techniques listed.
- No library campaign page.
- Volume figure is ATT&CK's.
Caption: The 2000 chronicle is the home for the intrusion; this study records the sentence.
Notes: Part 9. R v Boden [72]. ATT&CK campaign C0020 [73]. Library ICS data [88].

## MITRE MAPPINGS | 27 later Enterprise mappings, 12 ICS ids ATT&CK lists

| Id | Technique | 2001 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Code Red, ramen |
| T1210 | Exploitation of Remote Services | sadmind, SSH1 |
| T1080 | Taint Shared Content | Nimda, Sircam |
| T1588.003 | Code Signing Certificates | VeriSign certificates |
| T1078.001 | Default Accounts | Kaiten |
| T1498.001 | Direct Network Flood | Code Red |
| T0848 | Rogue Master | Maroochy, C0020 |
| T0878 | Alarm Suppression | Maroochy, C0020 |
Caption: ATT&CK v20.0 ids; Equation G0020 is bound with a caveat. MITRE notice in the notes.
Notes: Part 11. Rows [1][2][4][73]. Basis scores in the Enterprise layer: 70 Described, 40 Inferred; the ICS layer scores 100 because ATT&CK lists the ids. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2001 fixes are still the first fixes

Left: What 2001 taught
- Patch faster than the worm.
- Reinstall after a worm.
- Filter both directions.
- Close null passwords.
Right: What still applies
- Defaults are decisions.
- A reboot is not a cleanup.
- Security products need patching.
- Revocation must be checkable.
Notes: Top recommendations and Part 10. MS01-033 [8]. CA-2001-26 [1]. MS01-059 [10]. IN-2001-13 [2]. Code Red II [15]. CA-2001-17, CA-2001-25 [1]. MS01-017 [4].

## OVERSTATED AND UNDERSTATED | Memory kept the worms

Left: Overstated
- Any single Code Red number.
- "The firewall fixes it".
- Equation "began in 2001".
- Any Enterprise id on 2001.
Right: Understated
- The Unix record.
- The revocation gap.
- The standards work.
- The FBI's own operations.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [1][16][17][9][61][62][57][58][59][13]. Understated [1][2][4][43][46][47][51][52][53][68][21]. Cross-cutting themes and the overstated and understated passage.
