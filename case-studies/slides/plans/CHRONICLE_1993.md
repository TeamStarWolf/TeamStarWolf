# Slide plan: The Year 1993 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_1993.md
- Cover title: The Year 1993 / in Intrusions / A Dated Record
- Subtitle: Mail and file servers, the first trials and viruses that changed shape
- Published: 12 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_1993.md, told from the CERT/CC advisories, court records, GAO products, statutes, NIST and RFC records, the Swiss parliament's report and Virus Bulletin. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year's record is servers, courts, viruses and policy

- **Network services were the front door:** sendmail, gopher and anonymous FTP drew CERT's warnings.
- **Scanning went public:** a free tool aggregated known checks, and CERT expected malicious use.
- **The law was tested:** the first major Computer Misuse Act trial ended in acquittal.
- **Viruses learned to change shape:** polymorphic engines and kits reached the wild.
- **Encryption became a policy fight:** Clipper, key escrow and the PGP investigation.
Caption: Grades: CERT advisories, courts, GAO, statutes, NIST and RFCs Confirmed; prosecutions and the virus record Reported.
Notes: Advisories [2][7][8][11]. Bedworth [24]. Polymorphism [32][38][31][36]. Clipper [48][51]. Zimmermann [58]. No CVE or ATT&CK id existed in 1993 [92][95].

## KEY FACTS | Four numbers from the 1993 record

Stat: 19 | CERT/CC advisories, CA-93:01 to CA-93:19
Stat: 3 | of them say attackers already used the flaw
Stat: 1,334 | incidents reported to CERT/CC (773 in 1992)
Stat: 115 | attacks reported by Defense installations
- DISA's own test attacks succeeded 65 percent of the time; about 4 percent were detected.
- The IRS audit found 368 employees in one region browsing taxpayer accounts.
- Three national computer-crime laws were published, enacted or in force in 1993.
Notes: Advisories [1][2][8]. CERT incident counts, from a reprint of the CERT table (Reported) [20]. Defense counts and DISA tests [66]. IRS hearing [46]. Laws [59][60][61][62].

## PART 1 | The year in date order, from SunOS to sendmail

| Date | Event |
|---|---|
| 3 Feb | CA-93:03: attackers use SunOS permissions |
| 12 Mar | Steve Jackson Games decision |
| 17 Mar | Bedworth acquitted at Southwark |
| 16 Apr | Clipper Chip announced |
| 14 May | Infected PKUNZIP broadcast |
| 14 Jul | CA-93:10 Anonymous FTP Activity |
| 4 Aug | Senate hearing on IRS browsing |
| 30 Sep | CA-93:14 Internet Security Scanner |
| 21 Oct | CA-93:15: sendmail actively exploited |
| 3 Nov | Phiber Optik sentenced |
| 16 Nov | Bugtraq archive opens |
Notes: CERT [2][7][11]. Steve Jackson Games [22]. Bedworth [24]. Clipper [48]. Channel Videodat [35]. IRS [46]. Abene [28][26]. Bugtraq [19].

## PART 2 | CERT's advisories mapped the attack surface

Left: In use by attackers
- CA-93:03 SunOS default permissions.
- CA-93:11 gopher: password files taken.
- CA-93:15 Sun sendmail, actively exploited.
- CA-93:10 continuous anonymous FTP abuse.
Right: Exposure only
- CA-93:06 wuarchive ftpd: any account.
- CA-93:16 sendmail, most versions.
- CA-93:17 setuid xterm gives root.
- CA-93:12 NetWare writes passwords to disk.
Caption: No CVE record exists for any 1993 advisory; the CVE list began in 1999.
Notes: Advisories [2][3][4][7][8][9][12][13][14]. CVE history [92]. CA-94:01 of February 1994, network monitoring, is a boundary record [17][18].

## PART 2 | A free scanner raised the level of threat

- **30 September:** the Internet Security Scanner was posted to comp.sources.misc.
- **It checked every host in a range** for default accounts, sendmail debug, FTP and NFS.
- **CERT said none of its checks was new,** but their aggregation was a higher level of threat.
- **CERT expected** it to be used to locate vulnerable hosts for malicious reasons.
- **The same class of tool** is what defenders run against themselves today.
Caption: The last line is the study's reading (Inferred).
Notes: CA-93:14 as distributed to the NANOG list [11]; SEI compilation [2].

## PART 3 | The first trials under new computer-crime laws

Left: United Kingdom
- Bedworth acquitted on 17 March.
- Woods and Strickland jailed six months.
- First custodial sentences under the Act.
- A logic-bomb conviction in July.
Right: United States and Australia
- Masters of Deception sentences close.
- Phiber Optik: a year and a day.
- Poulsen indicted on 19 counts.
- The Realm pleas in Melbourne.
Caption: Every prosecution here rests on press reports or their reprints (Reported).
Notes: Bedworth [24][33]. Woods and Strickland [35][27]. Whitaker [36]. MOD [25][27][28][26]. Poulsen [27]. The Realm [28].

## PART 3 | Insiders with legitimate access drew official scrutiny

- **4 August:** a Senate hearing heard IRS staff browsed records of friends and celebrities.
- **368 employees** in one region monitored accounts without a work reason.
- **The audit covered one command code of 56,** used by about 6,300 staff.
- **28 July:** GAO told Congress the FBI's NCIC was misused by authorized users.
- **GAO asked for legislation** with criminal sanctions.
Caption: The year's documented data misuse was insiders, not outside intruders (Inferred).
Notes: Senate hearing [46]. GAO T-GGD-93-41 [47].

## PART 4 | Polymorphic viruses left the laboratory

| Date | Event |
|---|---|
| Feb | G2 construction kit released |
| Mar | Tremor analysed, widespread in Germany |
| 14 May | Tremor in a broadcast PKUNZIP |
| 29 Jun | Yankee Doodle on Sizewell B's office LAN |
| 15 Jul | CARO WILDList |
| Aug | DAME engine source published |
| Sep | First Mutation Engine virus in the wild |
Caption: Sizewell B's control and safety systems were separate, the site said (Reported).
Notes: G2 [31]. Tremor [32][42]. Channel Videodat [35]. Sizewell B [40]. WILDList [41]. DAME [36]. Coffeeshop and SatanBug [38]. TridenT [43].

## PART 5 | No state hacking campaign is on the 1993 record

Left: What the record holds
- AFIWC formed on 10 September.
- Clipper and key escrow from April.
- Crypto AG's German owners leave.
- Swiss intelligence learns the truth.
Right: What it does not
- No state intrusion campaign dated 1993.
- Moonlight Maze is dated from 1996.
- ATT&CK records no group before 2004.
- French espionage claims rest on press.
Notes: AFIWC [65][66]. Clipper [48][49][51]. Crypto AG, Swiss parliamentary report [71]. Moonlight Maze [74]. Turla G0010 [76]; library data [97]. French claims [72][73].

## PART 6 | Laws and standards that defenders still use

| Date | Instrument |
|---|---|
| Feb | PEM, RFC 1421 to 1424 |
| 1 Mar | Dutch computer-crime law in force |
| 11 May | FIPS 180 Secure Hash Standard |
| 30 Aug | Singapore Computer Misuse Act in force |
| Sep | Kerberos V5, RFC 1510 |
| 5 Oct | FIPS 181 Automated Password Generator |
| 23 Dec | Italy's Law No. 547 |
| 30 Dec | FIPS 46-2 Data Encryption Standard |
Notes: Netherlands [59][60]. PEM [81][82]. FIPS 180 [53]. Singapore [61]. Kerberos [83][84]. FIPS 181 [55]. Italy [62][63]. FIPS 46-2 [54].

## MITRE MAPPINGS | Seventeen later mappings, none printed by a 1993 source

| Id | Technique | 1993 record |
|---|---|---|
| T1595.002 | Vulnerability Scanning | CA-93:14 scanner |
| T1078.001 | Default Accounts | Scanner checks, SCO |
| T1110.001 | Password Guessing | Bedworth (Reported) |
| T1190 | Exploit Public-Facing Application | sendmail, gopher, ftpd |
| T1068 | Exploitation for Privilege Escalation | xterm, modload |
| T1040 | Network Sniffing | CA-94:01 (boundary) |
| T1027.014 | Polymorphic Code | Tremor, G2, DAME |
Caption: ATT&CK v20.0 ids; no group, software or campaign object for any 1993 actor; one Navigator layer.
Notes: Rows [11][10][24][2][8][12][14][15][17][32][31][36]. Basis scores in the layer: 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 1993 controls are still the first controls

Left: What 1993 taught
- Remove default and guest accounts.
- Patch every network daemon.
- Strip privileges programs do not need.
- Stop sending credentials in the clear.
Right: What was built that year
- TIS Firewall Toolkit v1.0.
- Tripwire file integrity checking.
- NIDES intrusion detection research.
- The WildList and MS-DOS 6 anti-virus.
Caption: Reading the year's standards and tools as the answer is the study's (Inferred).
Notes: Recommendations [11][3][12][14][15][17][84]. FWTK [77][78]. Tripwire [79]. NIDES [80]. WildList [41]. MS-DOS 6 [45].

## CROSS-CUTTING THEMES | What is overstated and what is understated

- **Overstated:** 1993 as a year of state hacking; Sizewell B as a reactor risk.
- **Overstated:** CERT's incident count as a measure of attack volume.
- **Overstated:** Clipper as mandatory; virus authors' own claims.
- **Understated:** active exploitation months before the 1994 sniffing wave.
- **Understated:** insider misuse, the legal groundwork and Crypto AG's turning points.
Notes: State hacking [66][97][74]. Sizewell B [40]. Counts [20][21][66]. Clipper [48][51]. Virus claims [39]. Exploitation [2][8][17]. Insiders [46][47]. Laws [59][61][62]. Crypto AG [71]. The readings are the study's (Inferred).
