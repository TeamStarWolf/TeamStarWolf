# Slide plan: The Year 2000 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2000.md
- Cover title: The Year 2000 / in Intrusions / A Dated Record
- Subtitle: Compromised servers fed the floods, a worm rode trust, and an insider attacked a sewerage system
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2000.md, told from the CERT/CC advisories and incident notes, Microsoft bulletins, NVD and CVE records, Justice Department releases, the Queensland Court of Appeal's judgment in R v Boden, GAO testimony, presidential documents, statutes, Federal Register rules, European Parliament records and the NIST, ISO and RFC Editor records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Compromised servers were the raw material

- **Agent pools:** CA-2000-01 says DDoS tools depend on hosts first compromised through known flaws.
- **Server flaws:** BIND, wu-ftpd, rpc.statd, IRIX telnetd and LPRng were exploited in the field.
- **Love Letter:** trust and a hidden extension, not a new flaw, carried it to 500,000 systems.
- **Maroochy:** a former site supervisor attacked a sewerage control system he had helped install.
- **Law:** GISRA, the GLB and HIPAA privacy rules and ESIGN all date to 2000.
Caption: Grades: CERT, Microsoft, Justice, the court, GAO, statutes, NIST and RFC records Confirmed; press Reported.
Notes: CA-2000-01 and the server advisories [1]; incident notes [2]. Love Letter [1], IN-2000-07 [2]. Maroochy judgment [50], C0020 [51]. GISRA [43], GLB rule [67], HIPAA rule [77], ESIGN [69]. February attacks [45][46], Reported.

## KEY FACTS | Four numbers from the primary record

Stat: 22 | CERT/CC advisories, CA-2000-01 to CA-2000-22
Stat: 100 | Microsoft bulletins, MS00-001 to MS00-100
Stat: 500,000 | Love Letter systems at 650 sites by 8 May
Stat: 12 | ATT&CK for ICS techniques listed for campaign C0020
- About 10.5 hours passed between NIPC's first notice and CERT/CC's advisory on 4 May.
- NVD gives no specific CWE for any of the year's flaws checked.
- CWE, CAPEC and ATT&CK came later: every Enterprise id is a later mapping.
Notes: CERT compilation [1]. Microsoft count [15], Demonstrated (inferred from the numbering). CA-2000-04 [1]. C0020 [51]. GAO timeline [41]. NVD records [5][8][10][11][12]. CWE and CAPEC history [92][93].

## PART 1 | The year in date order, from Stacheldraht to LPRng

| Date | Event |
|---|---|
| 3 Jan | CA-2000-01 Stacheldraht agents |
| 7 Feb | Yahoo unreachable (press) |
| 9 Feb | Maroochy attacks begin |
| 15 Apr | Mafiaboy arrested |
| 23 Apr | Maroochy alarms disabled; Boden stopped |
| 4 May | Love Letter and CA-2000-04 |
| 7 Jul | CA-2000-13 wu-ftpd |
| 18 Aug | CA-2000-17 rpc.statd |
| 15 Sep | IN-2000-10 mass exploitation |
| 2 Oct | Rijndael chosen for AES |
| 30 Oct | GISRA enacted |
| 12 Dec | CA-2000-22 LPRng |
Notes: CA-2000-01 [1]. Yahoo [45], Reported. Maroochy [50][51]. Mafiaboy [35]. Love Letter [1][41]. CA-2000-13 [1][5]. CA-2000-17 [1][7]. IN-2000-10 [2]. AES [71][72]. GISRA [43]. CA-2000-22 [1][12].

## PART 2 | Servers nobody meant to run

- **BIND:** daily compromises through the NXT flaw, even on hosts never meant as DNS servers.
- **wu-ftpd and rpc.statd:** format strings exploited for remote root in July and August.
- **Defaults:** rpc.statd was often installed and enabled by default.
- **IIS:** MS00-078 needed no new patch; MS00-057 already fixed it.
- **CVE dates lag:** one flaw carries a bulletin date, an NVD date and a CVE.org date.
Caption: That root daemons were the year's main way in is the study's reading of the advisories (Inferred).
Notes: Part 2. CA-2000-03, CA-2000-13, CA-2000-17, CA-2000-22 [1]. IN-2000-09, IN-2000-10 [2]. MS00-078 [14], MS00-057 [13]. NVD [10], CVE.org [108][109].

## PART 3 | The agent pools grew all year

Left: The tools
- Stacheldraht in January.
- Windows trinoo from 16 February.
- mstream in late April.
- Nameserver amplification.
Right: What CERT saw
- Over 100 agent connections at one site.
- Back Orifice beside trinoo.
- Hundreds of hosts per incident.
- Worm-like tools in development.
Caption: The February outages rest on press reports; that they drew on these pools is the study's reading.
Notes: Part 3. CA-2000-01 [1]. IN-2000-01, IN-2000-04, IN-2000-05, IN-2000-10 [2]. February attacks [45][46], Reported; AG statement [35]. Home study: the dot-com era study [102].

## PART 4 | Malware rode trust and defaults

- **Love Letter:** mailed itself to the whole Outlook address book and overwrote files.
- **Hidden extensions:** Windows hid the real file type behind a double extension.
- **Open shares:** network.vbs and the 911 worm spread through shares exposed to the Internet.
- **BubbleBoy and kak:** a control wrongly marked safe for scripting ran code from HTML mail.
- **No prosecution:** the Philippine law came after Love Letter and could not reach it.
Caption: No ATT&CK software object exists for any of these; the techniques are bound instead.
Notes: Part 4. CA-2000-04 [1]. IN-2000-02, IN-2000-03, IN-2000-06, IN-2000-07 [2]. RA 8792 [49]; dismissal [47], Reported. Library software data [95].

## PART 9 | Maroochy Shire: an insider and a radio network

Left: The record
- About 150 pumping stations.
- A private two-way radio network.
- Data altered, 9 Feb to 23 Apr.
- Raw sewage escaped.
Right: The insider
- Former site supervisor.
- Resigned in December 1999.
- Stolen PDS Compact 500.
- Configuration laptop in his car.
Caption: ATT&CK's 800,000-litre figure comes from a paper not opened here; the judgment gives no volume.
Notes: Part 9. R v Boden, Queensland Court of Appeal, 10 May 2002 [50]. ATT&CK campaign C0020, Maroochy Water Breach [51], Reported for the volume. Library ICS data [99][100].

## PART 5 | The state record is a visibility gap

Left: What is on the record
- Moonlight Maze's tail, by one account.
- ECHELON inquiry referral, 5 July.
- Carnivore public and reviewed.
- Russia's Information Security Doctrine.
Right: What is not
- No ATT&CK group dated to 2000.
- Equation not placed in 2000.
- Turla link called premature.
- No library actor study starts in 2000.
Caption: The FBI copied data from two computers in Russia over the Internet after the Seattle arrests.
Notes: Part 5. Moonlight Maze [52] Confirmed, [53][54] Reported. ECHELON [60][61]. Carnivore [63] Confirmed, [64] Reported. Doctrine [65]. Gorshkov case [29]. Turla [55], Equation [57][58][59]. Actor studies [103][104][105].

## PART 6 AND 7 | Prosecutions and the year's law

| Date | Event | Grade |
|---|---|---|
| 7 Jan | National plan to defend cyberspace | Confirmed |
| 9 May | Lloyd convicted over the Omega timebomb | Confirmed |
| 24 May | FTC Gramm-Leach-Bliley privacy rule | Confirmed |
| 30 Jun | ESIGN enacted | Confirmed |
| 28 Jul | UK Regulation of Investigatory Powers Act | Confirmed |
| 10 Aug | Bloomberg extortion arrests in London | Confirmed |
| 21 Sep | c0mrade sentenced | Confirmed |
| 30 Oct | GISRA enacted | Confirmed |
| 10 Nov | Gorshkov and Ivanov arrested | Confirmed |
| 28 Dec | HIPAA privacy rule published | Confirmed |
Notes: National plan [38]. Lloyd [21]. GLB rule [67]. ESIGN [69]. RIPA [80]. Bloomberg [26]. c0mrade [27][28]. GISRA [43]. Gorshkov and Ivanov [29]. HIPAA rule [77].

## PART 8 | Cryptography and standards

- **AES:** NIST announced Rijndael as the proposed standard on 2 October.
- **RSA:** the RSA patent reached its anticipated expiration on 20 September.
- **BCP 38:** RFC 2827 replaced RFC 2267 ingress filtering in May.
- **HTTP over TLS:** RFC 2818 and RFC 2817 were published in May.
- **Management:** ISO/IEC 17799:2000 was published in December.
Notes: AES [71][72], FIPS 197 [73]. RSA patent [89]. RFC 2827 [83]. RFC 2818 [84], RFC 2817 [85]. ISO/IEC 17799 [90]. FIPS 186-2 [82].

## MITRE MAPPINGS | 31 later Enterprise mappings, 12 ICS ids ATT&CK lists

| Id | Technique | 2000 use |
|---|---|---|
| T1566.001 | Spearphishing Attachment | Love Letter |
| T1036.007 | Double File Extension | IN-2000-07 |
| T1190 | Exploit Public-Facing Application | wu-ftpd, rpc.statd, LPRng |
| T1584.005 | Botnet | Stacheldraht, trinoo |
| T1498.002 | Reflection Amplification | IN-2000-04 |
| T1080 | Taint Shared Content | network.vbs |
| T0848 | Rogue Master | Maroochy, C0020 |
| T0878 | Alarm Suppression | Maroochy, C0020 |
Caption: ATT&CK v20.0 ids; C0020 is the only object bound. MITRE notice in the notes.
Notes: Part 11. Rows [1][2][51]. Basis scores in the Enterprise layer: 70 Described, 50 Reported, 40 Inferred; the ICS layer scores 100 because ATT&CK lists the ids. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2000 fixes are still the first fixes

Left: What 2000 taught
- Patch the server you forgot.
- Filter spoofed traffic at the edge.
- Show file extensions.
- Close open shares.
Right: What still applies
- Defaults are decisions.
- Know which patch covers a flaw.
- Revoke access when people leave.
- Build the reporting path first.
Notes: Top recommendations and Part 10. CA-2000-03 and IN-2000-10 [1][2]. BCP 38 [83]. IN-2000-07 [2]. MS00-078 and MS00-057 [14][13]. Maroochy [50], Omega [21]. GAO [41][42].

## OVERSTATED AND UNDERSTATED | Memory kept the loud weeks

Left: Overstated
- Love Letter as the year's story.
- The February outage details.
- Moonlight Maze in 2000.
- Any Enterprise id on a 2000 event.
Right: Understated
- Daily server compromises.
- The standards work.
- Undisclosed intrusions.
- Maroochy itself.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [1][41][45][46][35][53][52][92][93]. Understated [1][2][83][84][90][82][71][44][51][100]. Cross-cutting themes and the overstated and understated passage.
