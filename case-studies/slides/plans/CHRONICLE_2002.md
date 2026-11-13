# Slide plan: The Year 2002 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2002.md
- Cover title: The Year 2002 / in Intrusions / A Dated Record
- Subtitle: Trojaned source, worms that followed the fix, and security written into law
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2002.md, told from the CERT/CC advisories and incident notes, Microsoft, Apache, OpenSSL and OpenSSH advisories, F-Secure's virus descriptions, CVE, NVD and KEV records, the root server operators' report, Justice Department and FTC releases, statutes and the Federal Register, NIST and RFC Editor records and the Queensland Court of Appeal's judgment. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Check the signature before you build

- **Supply chain:** OpenSSH, Sendmail and tcpdump source were trojaned on their own servers.
- **Worms:** Slapper, Scalper, Spida, Opaserv and Bugbear followed fixes or weak passwords.
- **Infrastructure:** all thirteen root servers were flooded on 21 October.
- **Crime:** McKinnon indicted, Lamo in the New York Times, Cummings arrested.
- **Law:** FTC security orders, California SB 1386 and FISMA, enacted twice.
Caption: Grades: CERT, vendor, court, Justice, FTC, statute and NIST records Confirmed; press Reported.
Notes: Trojans [1][23]. Slapper [1][28]; Scalper [28][29]; Spida [4]; Opaserv [31][19]; Bugbear [30]. Root servers [45]. McKinnon [40][41]; Lamo [35]; Cummings [42]. FTC [46][47][48]; SB 1386 [49]; FISMA [52][55].

## KEY FACTS | Four numbers from the primary record

Stat: 37 | CERT/CC advisories, CA-2002-01 to CA-2002-37
Stat: 3 | open-source distributions trojaned at the source
Stat: 13 | DNS root servers flooded at once on 21 October
Stat: 92 | US military and NASA computers in the indictment
- CVE ids were still issued in the candidate form CAN-2002-xxxx.
- CVE-2002-0367 (MS02-024) is the only 2002 CVE in CISA's KEV catalog.
- CWE, CAPEC and ATT&CK came later: 2006, 2007 and 2013.
Notes: CERT advisories [1][2][3]. Trojans [1][23]. Root servers [45]. McKinnon [40]. CAN form [1][17][22]. KEV [14][101]. CWE [81]; CAPEC [82]; ATT&CK [83].

## PART 1 | The year in date order, from dtspcd to the last advisory

| Date | Event |
|---|---|
| 14 Jan | CA-2002-01 dtspcd exploited |
| 12 Feb | CA-2002-03 SNMPv1 |
| 22 May | IN-2002-04 Spida |
| 26 Jun | OpenSSH challenge-response |
| 30 Jul | OpenSSL advisory |
| 1 Aug | CA-2002-24 trojaned OpenSSH |
| 14 Sep | CA-2002-27 Slapper |
| 25 Sep | California SB 1386 approved |
| 8 Oct | CA-2002-28 trojaned Sendmail |
| 21 Oct | Root server flood |
| 13 Nov | CA-2002-30 trojaned tcpdump |
| 17 Dec | E-Government Act, FISMA |
Notes: CA-2002-01 [1][6]. CA-2002-03 [1][8]. IN-2002-04 [4]. OpenSSH [25][1]. OpenSSL [22]. CA-2002-24 [1][23]. CA-2002-27 [1][28]. SB 1386 [49]. CA-2002-28 [1]. Root servers [45]. CA-2002-30 [1]. E-Government Act [55][56].

## PART 2 | Fixes came first, and some were safe defaults

- **Exploited:** CDE dtspcd on Solaris in January, Kerberos kadmind in October.
- **Apache:** chunked encoding disclosed 17 June, fixed in 1.3.26 the next day.
- **OpenSSL:** four overflows from a DARPA-funded review, fixed 30 July.
- **OpenSSH:** privilege separation on by default five days before the advisory.
- **Microsoft:** MS02-001 to MS02-072; MS02-039 later protected against Slammer.
Caption: That safe defaults bought time before patches is the study's reading (Inferred).
Notes: Part 2. CA-2002-01, CA-2002-29 [1]. Apache [20][21]. OpenSSL [22]. OpenSSH 3.3 [24], advisory [25]. Microsoft [15][17][18]; series count Inferred.

## PART 3 | Three trojaned distributions in four months

| Window | Distribution | Advisory |
|---|---|---|
| 30 or 31 Jul to 1 Aug | OpenSSH 3.4p1, 3.4, 3.2.2p1 | CA-2002-24 |
| About 28 Sep to 6 Oct | Sendmail 8.12.6 | CA-2002-28 |
| 11 to 13 Nov | tcpdump 3.6.2, 3.7.1, libpcap 0.7.1 | CA-2002-30 |
Caption: Each ran at build time and called a fixed host; CERT's fix was checksums and PGP signatures.
Notes: Part 3. Windows and advisories [1][23]. The comparison across the three is Inferred. No exploit or payload detail is reproduced.

## PART 4 | The worm year

Left: Servers
- Slapper: Apache with mod_ssl.
- Scalper: Apache chunked encoding.
- Spida: null or weak sa passwords.
- Opaserv: a two-year-old share flaw.
Right: Users
- Myparty and Gibe by mail.
- Chat-borne DoS agents.
- Frethem through IE rendering.
- Bugbear with a keylogger.
Caption: No ATT&CK software object exists for these worms; the techniques are bound instead.
Notes: Part 4. Slapper [1][28]. Scalper [29]; month Reported [28]. Spida [4]. Opaserv [31][19]. Myparty, Gibe, IN-2002-03, Frethem [4]. Bugbear [30]. Library software data [96].

## PART 5 | Infrastructure: the core held

- **21 October:** all thirteen root servers flooded for about an hour and a quarter.
- **Impact:** the operators knew of no errors visible to end users.
- **SNMP:** the PROTOS suite found flaws across many vendors' SNMPv1.
- **DNS and SSH:** BIND, resolver libraries and many SSH implementations.
- **Switches:** an OmniSwitch shipped with a password-less telnet server listening.
Caption: The government's later account says some root servers were degraded or disrupted.
Notes: Part 5. Root servers [45][57]. CA-2002-03 [1][8]. CA-2002-15, CA-2002-19, CA-2002-31, CA-2002-36 [1]. CA-2002-32 [1][3].

## PART 6 | The state record is a visibility gap

Left: What is dated
- Equation samples compiled in 2002.
- Dated by Kaspersky in 2015.
- McKinnon: an individual case.
- No foreign state alleged.
Right: What is not
- Moonlight Maze successor toolkit.
- Early Penquin Turla code.
- Titan Rain begins in 2003.
- No 2002 campaign object.
Caption: Equation G0020 is bound with its 2015 dating caveat; Turla and Penquin are context only.
Notes: Part 6. Equation [76][78]. McKinnon [40]. Moonlight Maze and Penquin [77], Reported. Titan Rain [80], Reported. Turla [79]. Library data [95][96].

## PART 7 | Crime: databases, the military and an insider

- **Lamo:** into the New York Times network and its Op-Ed database, 26 February.
- **McKinnon:** indicted over 92 military and NASA computers, November.
- **Cummings:** credit reports on more than 30,000 people, arrested 25 November.
- **Jiang:** password-recording software at a Manhattan Kinko's.
- **Sentences:** Smith for Melissa (1 May) and Gorshkov (4 October).
Caption: "Largest identity theft case in US history" is the prosecutors' framing at arrest.
Notes: Part 7. Lamo [35][36]. McKinnon [40][41]. Cummings [42]. Jiang [44]. Smith [37]. Gorshkov [38].

## PART 8 | Law, regulation and standards

| Date | Event | Grade |
|---|---|---|
| 18 Jan | FTC Eli Lilly order | Confirmed |
| 6 Mar | FIPS 198, HMAC | Confirmed |
| 23 May | FTC Safeguards Rule | Confirmed |
| 30 Jul | Sarbanes-Oxley Act | Confirmed |
| Aug | FIPS 180-2, SHA-256 | Confirmed |
| 8 Aug | FTC Passport order | Confirmed |
| 25 Sep | California SB 1386 | Confirmed |
| 25 Nov | Homeland Security Act | Confirmed |
| 17 Dec | E-Government Act, FISMA | Confirmed |
Notes: Part 8. Eli Lilly [46]. FIPS 198 [60]. Safeguards Rule [48]. SOX [50][51]. FIPS 180-2 [62]. Passport [47]. SB 1386 [49]. Homeland Security Act [52][53]. E-Government Act [55][56].

## PART 9 | Maroochy: the appeal, not the attack

- **10 May 2002:** the Queensland Court of Appeal decided R v Boden.
- **The crime:** 9 February to 23 April 2000, about 150 pumping stations by radio.
- **Outcome:** counts 21 to 26 set aside; the two-year sentence stood.
- **ATT&CK for ICS:** campaign C0020, Maroochy Water Breach, lists 12 techniques.
- **No new layer:** the 2002 record adds no new activity.
Caption: The library has no ICS campaign page; C0020 links to ATT&CK.
Notes: Part 9. R v Boden [72]. C0020 [73]. ICS data [98].

## MITRE MAPPINGS | 27 Enterprise techniques, every one a later mapping

| Id | Technique | 2002 use |
|---|---|---|
| T1195.002 | Compromise Software Supply Chain | OpenSSH, Sendmail, tcpdump |
| T1190 | Exploit Public-Facing Application | dtspcd, Slapper, Scalper |
| T1210 | Exploitation of Remote Services | Slapper, Opaserv |
| T1078.001 | Default Accounts | Spida |
| T1498.001 | Direct Network Flood | Root servers |
| T1056.001 | Keylogging | Bugbear, Jiang |
| T1485 | Data Destruction | McKinnon |
Caption: ATT&CK v20.0 ids; Equation G0020 and the ICS techniques of C0020 sit in their own tables.
Notes: Part 11. Rows [1][4][28][30][40][44][45]. Basis scores in the layer: 70 Described, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2002 lessons still apply

Left: What 2002 taught
- Verify what you build.
- Watch build hosts' traffic.
- Measure fix to worm.
- Remove default passwords.
Right: What still applies
- Safe defaults buy time.
- Rebuild after library fixes.
- Filter by port and role.
- Plan capacity for floods.
Notes: Top recommendations and Part 10. Verification [1][23]. Build hosts [1]. Fix to worm [22][28]. Spida [4]. Safe defaults [24][25][17]. Rebuild [22]. Filtering [17][1]. Capacity [45].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- 37 advisories as the whole year.
- Slammer as a 2002 event.
- The root flood as an outage.
- Equation as a named agency.
Right: Understated
- Open-source supply chain.
- Cryptographic standards.
- Safe defaults.
- Network device flaws.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [1][2][17][45][57][76][77]. Understated [1][62][60][71][70][24][25][3]. Cross-cutting themes and the overstated and understated passage.
