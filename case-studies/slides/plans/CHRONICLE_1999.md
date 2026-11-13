# Slide plan: The Year 1999 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_1999.md
- Cover title: The Year 1999 / in Intrusions / A Dated Record
- Subtitle: Mail-borne malware, quiet server compromise and the first DDoS networks
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_1999.md, told from the CERT/CC advisories and incident notes, Microsoft bulletins, CVE and NVD records, Justice Department and SEC releases, congressional testimony, GAO and NTSB reports, statutes, Federal Register rules and the NIST, ISO and RFC Editor records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Two fronts: the user and the server

- **Malware:** Melissa, Happy99 and ExploreZip needed a user to open something.
- **Servers:** twelve of the 17 advisories concern server software and insecure defaults.
- **Supply chain:** TCP Wrappers and util-linux were trojaned on FTP servers in January.
- **DDoS:** trinoo, TFN and TFN2K turned compromised hosts into a weapon.
- **Espionage:** Moonlight Maze dropped its monitored relay after the press found it.
Caption: Grades: CERT, Microsoft, Justice, GAO, NTSB, statutes and NIST records Confirmed; press Reported.
Notes: Advisories [1]; incident notes [2]; count by topic [3], Inferred. Melissa [1][33]. Supply chain [1]. trinoo and TFN [2]; TFN2K [1]. Moonlight Maze [36] Confirmed, [37] Reported.

## KEY FACTS | Four numbers from the primary record

Stat: 17 | CERT/CC advisories, CA-1999-01 to CA-1999-17
Stat: 8 | CERT/CC incident notes, IN-99-01 to IN-99-08
Stat: 321 | records on the CVE List at its September launch
Stat: 22h 15m | to break DES Challenge III in January
- Melissa reached more than 100,000 computers at more than 300 organizations by 29 March.
- Many of the year's exploited flaws had their CVE records published in 2000.
- CWE, CAPEC and ATT&CK came later: 2006, 2007 and 2013.
Notes: CERT compilations [1][2]. CVE launch [4][5]. DES Challenge III [63][64]. Melissa [33]. CVE dates [7][10]. CWE [72]; CAPEC [73]; ATT&CK [74].

## PART 1 | The year in date order, from trojaned source to TFN2K

| Date | Event |
|---|---|
| 19 Jan | DES Challenge III broken |
| 21 Jan | CA-1999-01 trojaned TCP Wrappers |
| 23 Feb | DoD: 80 to 100 events a day |
| 27 Mar | CA-1999-04 Melissa |
| 22 Apr | IN-99-03 CIH |
| 10 Jun | CA-1999-06 ExploreZip |
| 22 Jul | IN-99-04 scripted RPC attacks |
| Sep | CVE List launches |
| 12 Nov | Gramm-Leach-Bliley Act |
| 18 Nov | IN-99-07 trinoo and TFN |
| 28 Dec | CA-1999-17 TFN2K |
Notes: DES Challenge III [63][64]. CA-1999-01 [1]. Hamre [39]. CA-1999-04 [1]. IN-99-03 [2]. CA-1999-06 [1]. IN-99-04 [2]. CVE [4][5]. GLBA [54][55]. IN-99-07 [2]. CA-1999-17 [1].

## PART 2 | Server daemons stayed the quiet way in

- **Remote root:** statd, cmsd, amd, WU-FTPD, BIND, sshd and sadmind in one year.
- **IIS:** the .HTR overflow had attacked sites and a public tool within a day.
- **Old fix, new compromises:** MDAC RDS was fixed by configuration in July 1998.
- **Microsoft:** bulletins MS99-001 to MS99-061; no Patch Tuesday yet.
- **CVE came late:** many 1999 records were published in 2000.
Caption: That servers were the larger front is the study's reading of the advisories (Inferred).
Notes: Part 2. The 17 advisories [1][3]. MS99-019 [13]. MS99-025 [14], IN-99-08 [2]. Microsoft count [11], Inferred. CVE Services and NVD [7][8][9][10].

## PART 3 | Scripts and the first DDoS networks

Left: What CERT saw
- January: sscan announced.
- July: RPC flaws chained.
- October: distributed sniffers.
- November: trinoo and TFN.
Right: TFN2K, 28 December
- Spoofed sources.
- UDP, TCP and ICMP floods.
- Decoy packets.
- MacOS 9 amplification, about 37.5x.
Caption: CA-1999-17 recommends RFC 2267 ingress filtering and says what it does not stop.
Notes: Part 3. IN-99-01, IN-99-04, IN-99-06, IN-99-07 [2]. CA-1999-17 [1]. RFC 2267 [69].

## PART 4 | Malware rode mail, shares and macros

- **Melissa:** a Word macro that mailed itself and lowered macro security.
- **Happy99:** sends itself as an attachment after every email the user sends.
- **CIH:** tries to erase the hard drive and overwrite the BIOS.
- **ExploreZip:** zeroes Office and source files and spreads to shares.
- **BubbleBoy:** demonstrates the scriptlet.typelib flaw, MS99-032.
Caption: No ATT&CK software object exists for any of these; the techniques are bound instead.
Notes: CA-1999-04 [1]. IN-99-02 [2]. IN-99-03 [2]. CA-1999-06 [1]. CVE-1999-0668 [9], MS99-032 [15]. Back Orifice 2000 [17]. Library software data [80].

## PART 5 | The state record: one lost relay, two waves of hacktivism

Left: Moonlight Maze
- Intrusions from at least 1996.
- A monitored UK relay, HRTest.
- About 1,600 unique addresses.
- Turla link called premature.
Right: Hacktivism
- Kosovo: NATO servers attacked.
- Belgrade embassy: US sites defaced.
- Taiwan sites defaced in August.
- No state control shown.
Caption: Equation is not placed in 1999; the Cox Committee report describes no network intrusion.
Notes: Moonlight Maze [36] Confirmed, [37] Reported. Turla [44], Penquin [45]. Kosovo [40]. Red Hacker Alliance and Taiwan [42], Reported. Equation [43][46]. Cox [48].

## PART 6 | Prosecutors had a busy year

- **Mitnick:** global plea in March, sentenced to 46 months in August.
- **David L. Smith:** arrested for Melissa on 1 April, pleaded guilty 9 December.
- **Defacers:** Burns, Davis and the White House web attack.
- **c0mrade:** 13 NASA computers and a router intercepting DTRA messages.
- **Fraud:** the Phone Masters, Hoke's fake Bloomberg page and CD Universe.
Caption: The DOJ index lists six computer intrusion releases for 1999.
Notes: Index [28]. Mitnick [21]. Smith [22][31]. Burns [19], Davis [23]. c0mrade [26]. Phone Masters [25]. Hoke [76][77]. CD Universe [78].

## PART 7 | Law, privacy and cryptography

| Date | Event | Grade |
|---|---|---|
| 19 Jan | DES Challenge III | Confirmed |
| 20 Jul | Y2K Act | Confirmed |
| 5 Aug | Executive Order 13133 | Confirmed |
| 16 Sep | New encryption export policy | Confirmed |
| 26 Sep | OpenSSH imported into OpenBSD | Confirmed |
| 20 Oct | FTC final COPPA Rule | Confirmed |
| 25 Oct | FIPS 46-3, Triple DES | Confirmed |
| 3 Nov | HHS proposed health privacy rule | Confirmed |
| 12 Nov | Gramm-Leach-Bliley Act | Confirmed |
Notes: DES Challenge III [63]. Y2K Act [60]. EO 13133 [57]. Export policy [62]. OpenSSH [71]. COPPA [58]. FIPS 46-3 [65]. HHS [59]. GLBA [54][55].

## PART 8 | Bellingham was not an intrusion

- **10 June:** the Olympic Pipe Line rupture killed three people.
- **SCADA:** the system slowed during database work on the live host.
- **NTSB:** found no evidence that an intrusion caused the slowdown.
- **Exposure:** the host was reachable by dial-in modem with no access monitoring.
- **Lesson:** keep control systems off the business network and off live development.
Caption: No ATT&CK for ICS technique is bound; the exposure is noted only.
Notes: NTSB PAR-02/02 [53]. Part 9 and the ICS row in Part 11. ICS data [87].

## MITRE MAPPINGS | 36 Enterprise techniques, every one a later mapping

| Id | Technique | 1999 use |
|---|---|---|
| T1195.002 | Compromise Software Supply Chain | TCP Wrappers, util-linux |
| T1059.005 | Visual Basic | Melissa |
| T1495 | Firmware Corruption | CIH |
| T1080 | Taint Shared Content | ExploreZip |
| T1190 | Exploit Public-Facing Application | IIS, MDAC RDS, WU-FTPD |
| T1040 | Network Sniffing | IN-99-06 |
| T1498.002 | Reflection Amplification | TFN2K, MacOS 9 |
| T1090.003 | Multi-hop Proxy | Moonlight Maze relay |
Caption: ATT&CK v20.0 ids; no ICS row and no group, software or campaign object. MITRE notice in the notes.
Notes: Part 11. Rows [1][2][13][36]. Basis scores in the layer: 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 1999 fixes are still the first fixes

Left: What 1999 taught
- Verify source before building.
- Treat macros as code.
- Turn off unneeded RPC.
- Apply configuration fixes.
Right: What still applies
- Filter spoofed traffic.
- Encrypt management sessions.
- Separate control systems.
- Retire weak keys.
Notes: Top recommendations and Part 10. CA-1999-01 and CA-1999-02 [1]. CA-1999-04 [1]. IN-99-04 [2]. MS99-025 [14], IN-99-08 [2]. CA-1999-17 [1], RFC 2267 [69]. IN-99-06 [2]. NTSB [53]. FIPS 46-3 [65].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- 1999 as the mass-mailer year.
- Melissa's damage figures.
- Moonlight Maze "is Turla".
- Bellingham as a cyberattack.
Right: Understated
- Quiet server compromise.
- Patch and configuration lag.
- The policy record.
- The CVE lag.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [3][22][33][35][36][37][44][45][53]. Understated [1][2][14][54][58][59][4][7]. Cross-cutting themes and the overstated and understated passage.
