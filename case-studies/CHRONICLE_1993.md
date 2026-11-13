# The Year 1993 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 12 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md) · Home studies for events summarized here: [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md) (the AIDS Trojan), [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Steve Jackson Games), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (the first Bugtraq month, Moonlight Maze), [Five Hacks and Why They Worked](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) (the Dark Avenger and the Mutation Engine) · Series: [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the later years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security leaders and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 57 min (13,013 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of 1993, you need the CERT advisories, the first Computer Misuse Act trials, the polymorphic virus record and the Clipper debate side by side, or you want to see which defender lessons were already on the record before CVE and ATT&CK existed

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 7: the defender view](#part-7-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Anyone who ran a Unix host on the Internet in 1993 remembers the year by its mail and file servers. The Computer Emergency Response Team Coordination Center (CERT/CC) issued 19 advisories that year, and three of them said attackers were already using the flaw or class of flaw they described: incorrect default permissions in SunOS, the UMN gopher server, and Sun's sendmail [1][2][8]. In July CERT described a "continuous stream" of abuse of anonymous FTP areas, from compromise to deliberate disk filling to the trading of pirated software [2][7]. In September a free tool, the Internet Security Scanner, was posted to a public newsgroup; CERT said none of its checks was new, but that putting them into one automated tool raised the level of threat [2][11]. CERT counted 1,334 incidents reported to it in 1993, up from 773 the year before [20], and US Defense installations officially reported 115 attacks, up from 53 [66].

Away from the servers, the year's record is courts, viruses and policy. A federal judge in Texas ruled on 12 March that the Secret Service had broken two federal privacy statutes when it seized Steve Jackson Games' computers in 1990 [22]. In London the first major trial under the Computer Misuse Act 1990 ended in an acquittal on a computer-addiction defence, while two co-defendants who pleaded guilty went to prison [24][35]. In New York the Masters of Deception cases closed with prison terms for all four defendants who were sentenced [25][27][28]. Polymorphic viruses moved from the laboratory into circulation, and a German data-broadcast service transmitted an infected copy of a common utility to its subscribers [32][35][38]. In April the White House announced the Clipper Chip key-escrow initiative [48]; in October the author of PGP told Congress he was the target of a criminal investigation into how his software had spread abroad [58].

This study is the dated record of that year, built only from sources opened on 12 November 2026. Six parts cover the timeline, the vulnerability advisories, crime and prosecutions, viruses, the state and intelligence record, and the government's laws and standards; a seventh gives the defender view, and an eighth maps the record to MITRE frameworks. Every row carries its date, the source that supports it and an evidence grade.

No identifier system that defenders use today existed in 1993. The CVE list began in 1999, CWE in 2006, CAPEC in 2007, ATT&CK's public release came in 2015 and D3FEND in 2021 [92][93][94][95][96]. Every advisory below is named by its CERT number, and every MITRE id in Part 8 is a later mapping made by this study, labelled as such.

Evidence grade: CERT/CC advisory texts, the court decision, GAO products, the congressional hearing record, White House releases, statutes, NIST and RFC Editor records, and the Swiss parliamentary report are **Confirmed**. Facts that rest only on press accounts or their reprints in *Phrack*, the EFF archive or *Virus Bulletin* (the prosecutions in the United Kingdom, New York, Los Angeles and Melbourne, the Connecticut ATM scam, most of the virus record) are **Reported** and attributed. Where this study draws its own conclusion, it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 1993, plus boundary records that close or explain a 1993 event (CERT advisory CA-94:01 of 3 February 1994, the GAO's 1996 count of Defense attacks, FIPS 185 of February 1994) |
| CERT/CC advisories | 19, CA-93:01 to CA-93:19, now republished by SEI as CA-1993-01 to CA-1993-19 (Confirmed [1][2]) |
| Flaws CERT said attackers were using | SunOS 4.1.x default permissions, "an increasing number of attackers" (CA-93:03); UMN gopher, used to obtain password files (CA-93:11); Sun sendmail, "being actively exploited" (CA-93:15) (Confirmed [2][8]) |
| Incidents reported to CERT/CC | 1,334 in 1993, against 773 in 1992 and 2,340 in 1994 (Reported, reprint of the CERT table [20]) |
| Attacks reported by Defense installations | 115 in 1993, against 53 in 1992 and 255 in 1994, from DISA data (Confirmed [66]) |
| Landmark ruling | *Steve Jackson Games v. US Secret Service*, W.D. Tex., 12 March 1993: Privacy Protection Act and Stored Communications Act violated, no Wiretap Act liability (Confirmed [22][23]) |
| First custodial sentences under the UK Computer Misuse Act | Neil Woods and Karl Strickland, six months each, after guilty pleas; their co-defendant Paul Bedworth was acquitted on 17 March (Reported [24][27][35]) |
| New national computer-crime laws | Netherlands (in force 1 March), Singapore (in force 30 August), Italy (enacted 23 December, in force 14 January 1994) (Confirmed [59][60][61][62]) |
| Encryption policy | Clipper Chip key-escrow initiative announced 16 April; Escrowed Encryption Standard proposed 30 July, approved as FIPS 185 on 9 February 1994 (Confirmed [48][51][52]) |
| Security standards | FIPS 180 Secure Hash Standard (11 May), FIPS 181 Automated Password Generator (5 October), FIPS 46-2 DES (30 December); RFC 1421 to 1424 PEM (February); RFC 1510 Kerberos V5 (September) (Confirmed [53][55][54][81][83]) |
| Free tools and lists | Internet Security Scanner (30 September), TIS Firewall Toolkit v1.0 (October), Tripwire technical report (November), the CARO WildList of 15 July (Confirmed [11][77][79][41]) |
| State record | No opened government, court or vendor record attributes a state intrusion campaign to 1993 (Inferred [66][97]); the year holds doctrine and institutions, the Clipper initiative, and turning points in the Crypto AG signals-intelligence operation (Confirmed [65][67][48][71]) |
| This study's MITRE binding | 17 ATT&CK Enterprise technique rows, every one a later mapping; no ICS row; no group, software or campaign object for any 1993 actor; seven CWE and eleven CAPEC entries; D3FEND pairings from the library's data; one Navigator layer (Part 8) |

### Key findings

- **Servers that faced the network were the front door (Inferred).** The advisories CERT graded as in use by attackers all concern services or files reachable by outsiders or ordinary users: sendmail, gopher, anonymous FTP, default permissions (Confirmed [2][7][8]). CERT said anyone, remote or local, could potentially gain any account on wuarchive ftpd, "including root" (Confirmed [3][4]).
- **Scanning was automated and published.** CA-93:14 says the Internet Security Scanner interrogated every host in an address range for known weaknesses, and that the aggregation of known checks in a widely available tool "represents a higher level of threat" (Confirmed [11][2]).
- **Accounts and passwords were the weak layer.** The scanner checked for default guest, bbs and lp accounts and tried to retrieve NIS password files (Confirmed [11]); NetWare 4.0 could write a user's password to disk (Confirmed [9]); Bedworth reached dozens of hosts by password guessing and known DEC VAX weaknesses, the press reported (Reported [24]). The same year's standards included Kerberos V5, PEM and an automated password generator (Confirmed [84][82][55]); reading them as the answer is this study's (Inferred).
- **The law was tested in court and found uneven.** The UK's first major Computer Misuse Act trial ended in acquittal while the defendants who pleaded guilty were jailed (Reported [24][35]); a US court found the government itself had broken the Privacy Protection Act and Stored Communications Act (Confirmed [22]).
- **Insiders with legitimate access drew detailed official scrutiny (Inferred).** A Senate hearing heard that 368 IRS employees in one region had browsed taxpayer accounts without a work reason (Confirmed [46]), and the GAO told Congress the FBI's NCIC was being misused by authorized users, including sales to private investigators (Confirmed [47]).
- **Viruses learned to change shape.** *Virus Bulletin* reported the first Mutation Engine virus found in the wild, the polymorphic Tremor spreading in Germany, and polymorphic kits and engines circulating (Reported [38][32][31][36]); F-Secure dates the TridenT Polymorphic Engine to 1992 (Reported [43]).
- **No state hacking campaign is on the record for 1993.** The earliest state-linked campaign in the vendor record opened, Moonlight Maze, is dated from 1996 (Reported [74]); ATT&CK records no group activity before 2004 (Confirmed [76]; Demonstrated [97]).

### Top recommendations

1. **Remove default and guest accounts, and make passwords hard to guess.** CA-93:14's scanner looked first for default accounts (Confirmed [11]); NIST's FIPS 181 automated the generation of passwords the same year (Confirmed [55]). The [2016 chronicle](/case-studies/CHRONICLE_2016.md) opens its own recommendations with the same advice (Demonstrated [106]).
2. **Treat every network daemon as perimeter software and keep it current.** CERT's fixes for 1993's remote flaws were new versions: wu-ftpd 2.0 for the wuarchive server, and sendmail 8.6.4, which CERT did not believe affected by CA-93:16 (Confirmed [3][12]).
3. **Strip privileges a program does not need.** The setuid xterm, modload and loadmodule advisories each gave a local user root through a privileged program (Confirmed [14][15][2]).
4. **Stop sending credentials in the clear.** CA-94:01 found intruders had captured access information for tens of thousands of systems by watching network traffic (Confirmed [17][18]); Kerberos V5, published in 1993, authenticates principals without sending reusable passwords in the clear (Confirmed [84]); PEM did the same for mail (Confirmed [82]); tying them to the 1994 sniffing is this study's reading (Inferred).
5. **Keep an integrity baseline of the files that matter.** Tripwire, described in November 1993, compares a chosen set of files with stored signatures (Confirmed [79]); the library pairs File Integrity Monitoring with password-file theft (Demonstrated [100]).
6. **Scan yourself before someone else does.** The scanner CERT warned about in September was the same class of tool defenders use today (Inferred [11]).
7. **Audit what insiders do with legitimate access.** The IRS audit covered one command code out of 56, used by about 6,300 staff, and still found hundreds of browsers (Confirmed [46]); GAO asked for criminal sanctions for NCIC misuse (Confirmed [47]).
8. **Check what arrives through trusted distribution channels.** Channel Videodat broadcast an infected utility to a claimed 60,000 subscribers alongside a virus scanner (Reported [35]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions and policy dated to 1993, plus the later records that close or explain a 1993 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every event graded, numbers as the source states them.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record (a CERT/CC advisory as SEI publishes it or as distributed in 1993, a court decision, a GAO product, a congressional hearing record or testimony, a White House release, a statute, a NIST or RFC Editor record, a parliamentary report, the vendor's own description, or a live ATT&CK page) was opened on 12 November 2026 and states the fact |
| Reported | Only a secondary source was opened: press, wire stories and their reprints in *Phrack*, *Computer Underground Digest* or the EFF archive; *Virus Bulletin*; retrospectives by participants. The source is named in the text |
| Demonstrated | The study opened the archive or data file and saw the fact directly (the Bugtraq archive, the library's data files) |
| Inferred | The study's own reasoning, labelled where it appears. Every MITRE id bound to a 1993 event is Inferred as to the binding |

Limits that a reader should know:

- **No CVE, no ATT&CK.** The 1993 record has no CVE ids (the list began in 1999) and no ATT&CK ids (first model 2013, public 2015) [92][95]. Legacy CVE-1999 entries that may cover some of these flaws were not checked. Every technique id in Part 8 is this study's later mapping (Inferred [97][98]).
- **Copies of the advisories.** SEI's 1993 compilation was the main text [1][2]; individual advisories were also read from 1993 mailing-list distributions (NANOG, a NECTEC forwarding archive, RISKS) and a text-file mirror, with dates cross-checked against SEI [3][4][11][12][13][17][18]. These are graded as the primary they copy.
- **The prosecutions are press-reported.** No court record was opened for the UK, New York, Los Angeles or Melbourne cases; each rests on contemporary news or its reprint [24][25][26][27][28]. Dates differ by a day or more across reports and are given as each source gives them.
- **Pages that did not open.** The cypherpunks archive (HTTP 522), a 1993 Roanoke Times page (410), the DEF CON 1 page (connection reset), an NSA D3FEND release (403), CERT's own statistics page (429), several DTIC copies of military doctrine (403) and the GAO landing page for AIMD-96-84 (the PDF opened) were not available. DEF CON 1 is therefore not recorded; the text of CJCS MOP 30 was not opened and is cited through later documents.
- **Home studies.** The Steve Jackson Games case lives in the [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md); the [pre-Internet study](/case-studies/PRE_INTERNET_THREATS.md) carries its 1993 judgment as a timeline row; the AIDS Trojan in the [pre-Internet study](/case-studies/PRE_INTERNET_THREATS.md); the first USENET "spam" and the first Bugtraq month in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); the Dark Avenger and the Mutation Engine in the [Fancy Bear Goes Phishing study](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md). Each is summarized here in a paragraph.
- **Tradecraft is described at advisory level.** Advisory names, affected products and impact, and technique names and ids. CERT's 1993 advisories contain shell checks and configuration lines; none is reproduced here.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1993-01 | Canadian Trusted Computer Product Evaluation Criteria, Version 3.0e, issued by the Canadian System Security Centre of the Communications Security Establishment | Standards | Confirmed | [90] |
| 1993-01 | Crypto AG sales engineer Hans Buehler returns to Switzerland after nine months' detention in Iran and is questioned by the Swiss federal police about the espionage accusations made in Iran | State | Confirmed | [71] |
| 1993-01-13 | CA-93:01 Revised HP NIS ypbind: root on any vendor's NIS host can gain root on HP-UX clients running HP's ypbind; supersedes CA-92:17 | Vulnerability | Confirmed | [2] |
| 1993-01-21 | CA-93:02 NeXT NetInfo _writers: default settings allow root through printer and fax directories, NeXTSTEP through 3.0 | Vulnerability | Confirmed | [2] |
| 1993-01-21 | Netherlands' Wet computercriminaliteit published as Staatsblad 1993, 33, adding computer trespass (art. 138a Sr) and unlawful change or deletion of data (art. 350a) | Law | Confirmed | [59] |
| 1993-02 | RFC 1421 to 1424, Privacy Enhancement for Internet Electronic Mail (PEM), published | Standards | Confirmed | [81][82] |
| 1993-02 | Phalcon/Skism releases the G2 semi-polymorphic virus construction kit, credited to "Dark Angel" | Malware | Reported | [31] |
| 1993-02-03 | CA-93:03 SunOS 4.1 to 4.1.3 default file permissions may give local users root; CERT sees "an increasing number of attackers" exploiting them | Vulnerability | Confirmed | [2] |
| 1993-02-18 | CA-93:04 Commodore Amiga UNIX finger: non-privileged users can read unauthorized files (SEI copy is the revised 04a) | Vulnerability | Confirmed | [2] |
| 1993-02-24 | CA-93:05 OpenVMS V5.0 to V5.5-2 and OpenVMS AXP V1.0: an authorized unprivileged user could gain full privileges; fixed in V6.0 and AXP V1.5 | Vulnerability | Confirmed | [2] |
| 1993-03 | Lunt and Anderson, SRI International: requirements specification for the Next-Generation Intrusion Detection Expert System (NIDES), with statistical and rule-based components | Defense | Confirmed | [80] |
| 1993-03 | *Virus Bulletin* analyses Tremor, polymorphic, "relatively widespread" in Germany and aimed at resident anti-virus monitors | Malware | Reported | [32] |
| 1993-03-01 | Dutch computer-crime law enters into force | Law | Confirmed | [60] |
| 1993-03-08 | CJCS Memorandum of Policy 30, "Command and Control Warfare", dated (as cited in a 1996 Marine Corps order) | State | Confirmed | [67] |
| 1993-03-12 | *Steve Jackson Games v. US Secret Service* decided (W.D. Tex., Judge Sam Sparks): Privacy Protection Act and Stored Communications Act violated, no Wiretap Act liability; the search was on 1 March 1990. Home: [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Courts | Confirmed | [22][23] |
| 1993-03-17 | Paul Bedworth, 19, acquitted at Southwark Crown Court after a four-week Computer Misuse Act trial on a computer-addiction defence | Courts | Reported | [24] |
| 1993-03-17 | Masters of Deception: Elias Ladopoulos and Paul Stira plead guilty to conspiracy | Courts | Reported | [25] |
| 1993-03-31 | Joel Furr's first USENET use of "spam" for net abuse. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Culture | Reported (as graded in the home study [105]) | [105] |
| 1993-04 | RFC 1446, security protocols for SNMPv2 | Standards | Confirmed | [86] |
| 1993-04-09 | CA-93:06 wuarchive ftpd before 8 April 1993: anyone, remote or local, could gain any account including root; fix is wu-ftpd 2.0 | Vulnerability | Confirmed | [3][4] |
| 1993-04-15 | Presidential directive "Public Encryption Management" (EPIC FOIA copy) tells the Attorney General to request installation of key-escrow microcircuits | Policy | Confirmed | [49] |
| 1993-04-16 | White House announces the voluntary Clipper Chip key-escrow initiative; PDD-5 copy dated the same day | Policy | Confirmed | [48][50] |
| 1993-04-18 | Knight-Ridder reports a purported French intelligence tasking document naming 49 high-tech companies, 24 financial institutions and six US agencies; France's embassy disputes it | State | Reported | [72] |
| 1993-04-21 to 22 | 19-count federal indictment in Los Angeles against Kevin Poulsen and two others: radio-contest rigging, wiretaps, DMV and Pacific Bell access; co-defendants plead guilty and cooperate | Courts | Reported | [27] |
| 1993-04-22 | CA-93:07 Cisco routers set to block IP source routing could still pass source-routed packets (8.2 to 9.17) | Vulnerability | Confirmed | [5][2] |
| 1993-04-26 | AP reports China executed Shi Biao, a bank accountant, for computer-aided forgery of deposits worth about $192,000 | Crime | Reported | [27] |
| 1993-05 | A Rome court convicts Dr Joseph Popp in absentia of attempted extortion over the AIDS diskette: two and a half years. Home: [pre-Internet study](/case-studies/PRE_INTERNET_THREATS.md) | Courts | Reported | [34] |
| 1993-05 | Treasury's Bureau of the Public Debt bulletin board in Parkersburg, West Virginia, restricted after offering virus code and hacker tools to at least 1,000 callers for over a year | Government, malware | Reported | [27][37] |
| 1993-05 | A real ATM placed in a Connecticut mall for about two weeks records card numbers and PINs; AP says it was thought to have netted roughly $60,000 | Crime, finance | Reported | [27] |
| 1993-05-03 | *Christian Science Monitor*: the CIA warned Hughes Aircraft and 48 other US companies of French espionage; France denies it | State | Reported | [73] |
| 1993-05-11 | NIST publishes FIPS 180, Secure Hash Standard | Standards | Confirmed | [53] |
| 1993-05-14 | Channel Videodat broadcasts a Tremor-infected PKUNZIP, sent with McAfee SCAN, to a claimed 60,000 subscribers; a clean copy follows two hours later | Malware, supply chain | Reported | [35] |
| 1993-05-21 (inferred) | Neil Woods and Karl Strickland jailed six months each under the Computer Misuse Act, the first custodial sentences under the Act | Courts | Reported | [35][27] |
| 1993-05-24 | CA-93:08 SCO /bin/passwd could deny legitimate users login; no unauthorized access | Vulnerability | Confirmed | [6][2] |
| 1993-06-04 | John Lee of Masters of Deception sentenced to a year and a day plus 200 hours' service | Courts | Reported | [27] |
| 1993-06-09 | House Subcommittee on Telecommunications and Finance hears testimony on network security and toll fraud from 2600's editor | Government | Reported | [30] |
| 1993-06-11 | CA-93:09 SunOS and Solaris expreserve | Vulnerability | Confirmed | [2] |
| 1993-06-18 | Joint COMSEC Monitoring Activity concept of operations dated (as recorded in JP 3-13.1) | State | Confirmed | [68] |
| 1993-06-29 | The Yankee Doodle virus infects the construction-team office LAN at the Sizewell B nuclear site; the site says control and safety systems were separate | Malware, energy | Reported | [40] |
| 1993-06-30 | Secret Service arrests Alan Scott Pace and Gerald Greenfield in the Connecticut ATM scam | Crime | Reported | [29] |
| 1993-07 | RFC 1492 documents TACACS | Standards | Confirmed | [87] |
| 1993-07-02 | Mark Abene ("Phiber Optik") pleads guilty to conspiracy and unauthorized access, last of five MOD defendants to plead | Courts | Reported | [27] |
| 1993-07-14 | CA-93:10 Anonymous FTP Activity: misconfiguration leading to compromise, disk-filling denial of service, writable areas used to trade pirated software and stolen password files | Vulnerability | Confirmed | [7][2] |
| 1993-07-15 | CARO WILDList, (c)1993 Joe Wells: viruses reported in the wild by two or more CARO members | Defense, malware | Confirmed | [41] |
| 1993-07-21 | Programmer Alfred Whitaker convicted at Scunthorpe Magistrates Court under the Computer Misuse Act for a payment-triggered logic bomb | Courts | Reported | [36] |
| 1993-07-28 | GAO testimony T-GGD-93-41: the FBI's NCIC is vulnerable to misuse by authorized insiders; legislation urged | Government | Confirmed | [47] |
| 1993-07 (late) | Ladopoulos and Stira sentenced to six months in prison, six months home detention and 750 hours' service | Courts | Reported | [25][36] |
| 1993-07-30 | NIST proposes the Escrowed Encryption Standard (58 FR 40791) | Policy | Confirmed | [51] |
| 1993-08 | *40Hex* publishes source for the DAME polymorphic engine | Malware | Reported | [36] |
| 1993-08-04 | Senate Governmental Affairs hearing "Auditing the Auditors": IRS staff browsing taxpayer records | Government | Confirmed | [46] |
| 1993-08-09 | CA-93:11 UMN gopher and gopher+: remote access to the client account and in some configurations root; intruders used the flaws to obtain password files | Vulnerability | Confirmed | [8][2] |
| 1993-08-22 to 23 | Melbourne: "The Realm" defendants Nahshon Even-Chaim (15 charges) and David Woodcock (two counts) plead guilty | Courts | Reported | [28] |
| 1993-08-30 | Singapore's Computer Misuse Act (Act 19 of 1993) in force | Law | Confirmed | [61] |
| 1993-09 | RFC 1510 Kerberos V5; RFC 1508 GSS-API; RFC 1507 DASS; RFC 1511 | Standards | Confirmed | [83][84][85] |
| 1993-09 | UK DTI working group's Code of Practice for Information Security Management, later the basis of BS 7799 | Standards | Reported | [91] |
| 1993-09 | Coffeeshop, the first Mutation Engine virus found in the wild (South Africa); SatanBug spreading in the US | Malware | Reported | [38] |
| 1993-09 (autumn) | Swiss Strategic Intelligence Service learns Crypto AG is owned by US and German intelligence and exports weak devices | State | Confirmed | [71] |
| 1993-09-08 | Swiss Federal Council message on a new Military Act proposes a legal basis for foreign intelligence | State | Confirmed | [71] |
| 1993-09-10 | The Air Force Electronic Warfare Center is redesignated the Air Force Information Warfare Center at Kelly AFB | State | Confirmed | [65] |
| 1993-09-15 | NII Agenda for Action: trustworthy and secure networks are essential | Policy | Confirmed | [56] |
| 1993-09-16 | CA-93:12 Novell NetWare 4.0 and 4.01 LOGIN.EXE could write a user's name and password to disk | Vulnerability | Confirmed | [9][2] |
| 1993-09-17 | CA-93:13 SCO home directories expose the dos and asg accounts and possibly root | Vulnerability | Confirmed | [10][2] |
| 1993-09-30 | CA-93:14 Internet Security Scanner posted to comp.sources.misc; CERT expects malicious use | Vulnerability, tools | Confirmed | [11][2] |
| 1993-10 | RFC 1535 describes a flaw in DNS resolver search heuristics for partial names | Standards | Confirmed | [88] |
| 1993-10 | Rockwell International reports hundreds of virus incidents over five years | Malware | Reported | [38] |
| 1993-10-01 | An 18-year-old in Creve Coeur, Missouri, arrested on a state misdemeanor charge over a federal appeals court's files and calls charged to a bank | Crime | Reported | [28] |
| 1993-10-01 and 20 | TIS makes Firewall Toolkit v1.0 freely available (1 October, per its developers); announcement dated 20 October | Defense | Confirmed (announcement); Reported (1 October) | [77][78] |
| 1993-10-05 | NIST publishes FIPS 181, Automated Password Generator | Standards | Confirmed | [55] |
| 1993-10-12 | Philip Zimmermann tells a House subcommittee he is a target of a US Customs criminal investigation into PGP's spread abroad | Policy | Confirmed | [58] |
| 1993-10-21 | CA-93:15 Sun sendmail, tar and /dev/audio; the sendmail flaw is "being actively exploited" | Vulnerability | Confirmed | [2] |
| 1993-11 | Tripwire technical report, Purdue CSD-TR-93-071 | Defense | Confirmed | [79] |
| 1993-11 | Cyber Riot, a Windows 3.1 virus, sent to Central Point by "The Chicago 7" | Malware | Reported | [39] |
| 1993-11 | About 250 variants of old viruses modified to evade McAfee SCAN sent to researchers as PART1.ZIP | Malware | Reported | [39][40] |
| 1993-11-03 | Abene sentenced to a year and a day in federal court in Manhattan | Courts | Reported | [28][26] |
| 1993-11-04 | CA-93:16 sendmail: most versions let remote or local users run programs as any user other than root | Vulnerability | Confirmed | [12][13] |
| 1993-11-04 | GAO OSI-94-2, "Communications Privacy: Federal Policy and Actions" | Policy | Confirmed | [57] |
| 1993-11-11 | CA-93:17 xterm logging: setuid xterm (X11R5 and earlier) gives local users root | Vulnerability | Confirmed | [14][2] |
| 1993-11-16 | The seclists.org Bugtraq archive opens with a thread on CA-93:17. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Disclosure | Demonstrated | [19][105] |
| 1993-11-25 | Metropolitan Police, IBM UK and PC Plus launch "Don't let them get away with IT" | Law enforcement | Reported | [40] |
| 1993-12 | *Virus Bulletin* publishes the first list from Joe Wells's in-the-wild cooperative | Malware, defense | Reported | [40] |
| 1993-12 (end) | The German intelligence service withdraws from Crypto AG, per the MINERVA account summarized by the Swiss parliament | State | Confirmed | [71] |
| 1993-12-15 | CA-93:18 SunOS and Solbourne modload and loadmodule: local root | Vulnerability | Confirmed | [15][2] |
| 1993-12-16 | CA-93:19 Solaris startup: physical console access gives root when fsck fails | Vulnerability | Confirmed | [16][2] |
| 1993-12-23 | Italy's Law No. 547 on computer crime (in force 14 January 1994) | Law | Confirmed | [62][63] |
| 1993-12-30 | NIST publishes FIPS 46-2, Data Encryption Standard | Standards | Confirmed | [54] |
| 1994-02-03 (boundary) | CA-94:01: intruders had captured access information for tens of thousands of systems by network monitoring. Belongs to the 1994 record | Vulnerability | Confirmed | [17][18][12] |

## Part 2: the vulnerability record

### The 19 advisories

CERT/CC issued 19 advisories in 1993; SEI republishes them in one compilation "for historical purposes" (Confirmed [1][2]). The impact column gives CERT's own words where quoted and its substance otherwise. No CVE record exists for any of them [92].

| Advisory | Date | Product | Impact as CERT states it | Grade | Sources |
|---|---|---|---|---|---|
| CA-93:01 | 13 Jan | HP-UX NIS ypbind (revised; supersedes CA-92:17) | root on any vendor's NIS can gain root on HP-UX clients; local users too | Confirmed | [2] |
| CA-93:02 | 21 Jan | NeXT NetInfo _writers, NeXTSTEP through 3.0 | default settings allow root via printer and fax directories | Confirmed | [2] |
| CA-93:03 | 3 Feb | SunOS 4.1 to 4.1.3 default file permissions | local root; "an increasing number of attackers exploit these problems" | Confirmed | [2] |
| CA-93:04 | 18 Feb (04a) | Commodore Amiga UNIX finger | non-privileged users read unauthorized files | Confirmed | [2] |
| CA-93:05 | 24 Feb | OpenVMS V5.0 to V5.5-2, OpenVMS AXP V1.0 | authorized unprivileged user to full privileges; text from Digital's Software Security Response Team | Confirmed | [2] |
| CA-93:06 | 9 Apr | wuarchive ftpd before 8 Apr 1993 | anyone, remote or local, could gain any account including root; no exploitation reported | Confirmed | [3][4][2] |
| CA-93:07 | 22 Apr | Cisco routers, 8.2 to 9.17 | source-routed packets passed when configured to block them; fixed in 8.3(7.2), 9.0(5), 9.1(4), 9.17(2.1) | Confirmed | [5][2] |
| CA-93:08 | 24 May | SCO /bin/passwd | denial of legitimate logins, no unauthorized access | Confirmed | [6][2] |
| CA-93:09 | 11 Jun | SunOS and Solaris expreserve | local privilege escalation | Confirmed | [2] |
| CA-93:10 | 14 Jul | Anonymous FTP areas | misconfiguration leading to compromise; disk-filling denial of service; writable areas used for pirated software and stolen password files | Confirmed | [7][2] |
| CA-93:11 | 9 Aug | UMN gopher and gopher+ before 6 Aug 1993 | remote access to the client account and in some configurations root; intruders used the flaws to obtain password files | Confirmed | [8][2] |
| CA-93:12 | 16 Sep | Novell NetWare 4.0 and 4.01 LOGIN.EXE | user name and password could be written to disk; Novell issued a security-enhanced LOGIN.EXE | Confirmed | [9][2] |
| CA-93:13 | 17 Sep | SCO UNIX and Open Desktop home directories | dos and asg accounts exposed; potential root | Confirmed | [10][2] |
| CA-93:14 | 30 Sep | Internet Security Scanner | none of the checks new, but aggregation in a widely available tool is "a higher level of threat"; likely malicious use | Confirmed | [11][2] |
| CA-93:15 | 21 Oct | Sun /usr/lib/sendmail, /bin/tar, /dev/audio | sendmail lets remote users gain access and "is being actively exploited" | Confirmed | [2] |
| CA-93:16 | 4 Nov | sendmail, most versions | remote or local users run programs as any user other than root, reachable through intermediate mail hosts; no complete patches at issue; 8.6.4 not believed affected | Confirmed | [12][13] |
| CA-93:17 | 11 Nov | setuid or setgid xterm, X11R5 and earlier | local users create or modify any file; root | Confirmed | [14][2] |
| CA-93:18 | 15 Dec | SunOS 4.1.x modload, OpenWindows 3.0 loadmodule (sun4, Solbourne) | local user runs a program as root | Confirmed | [15][2] |
| CA-93:19 | 16 Dec | Solaris 2.x startup | physical console access at boot gives root when fsck fails | Confirmed | [16][2] |

CA-93:15's sendmail portion was superseded by CA-93:16, which was itself later superseded by CA-96:20, CA-96:24 and CA-96:25 (Confirmed [2]). With no shared identifier, one flaw could carry several advisory numbers over three years (Inferred).

### What the advisories say about attackers

Three advisories carry CERT's own statement that attackers were using the class of flaw: CA-93:03 (an increasing number of attackers), CA-93:11 (intruders known to have obtained password files) and CA-93:15 (sendmail "being actively exploited") (Confirmed [2][8]). CA-93:10 describes continuous abuse rather than a flaw (Confirmed [7]). The rest describe exposure only. *Virus Bulletin* reported a CIAC alert on the same NetWare 4 login flaw and called it embarrassing for Novell, given the release's security emphasis (Reported [38]).

### The scanner

CA-93:14 is the year's most forward-looking advisory. The Internet Security Scanner, posted to comp.sources.misc, interrogated every host in an IP range for common weaknesses without trying to gain access. Its checks, as CERT lists them, covered default guest, bbs and lp accounts, a mail alias, sendmail debug commands, anonymous FTP configuration, retrieval of the NIS password file and NFS exports (Confirmed [11]). CERT judged it likely to be used "to locate vulnerable hosts for malicious reasons" (Confirmed [11]). The checklist matches the weaknesses CERT's other 1993 advisories describe: default accounts, mail and FTP services, password files and NFS (Inferred [2][11]).

### The edge of the year

On 3 February 1994 CA-94:01 reported a "dramatic increase" in network monitoring attacks in the previous week: intruders, after gaining root, had captured access information for tens of thousands of systems, and FTP, telnet and rlogin sessions were at risk (Confirmed [17][18]). The advisory attributes the activity to no state (Confirmed [18]). It belongs to the 1994 record. That the capture was under way before the advisory, and so partly in 1993, is this study's reading of "already captured" (Inferred).

### Disclosure culture

The seclists.org Bugtraq archive opens on 16 November 1993 with a thread on CA-93:17, followed on 17 November by "CERT Advisories wanted" (Demonstrated [19]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Bugtraq and the disclosure debates that followed; it already carries this row (Demonstrated [105]).

### Counting incidents

A reprint of CERT/CC's statistics gives 1,334 incidents reported in 1993, 773 in 1992 and 2,340 in 1994, with 19 advisories in 1993, 21 in 1992 and 15 in 1994 (Reported [20]). CERT later said incident counts "provide little information" and stopped publishing them in 2004 (Reported [20]). Howard's 1997 thesis, analysing 4,299 incidents reported to CERT/CC from 1989 to 1995, estimated that an above-average incident had roughly a 1 in 2.6 chance of being reported and that, apart from denial of service, incidents fell relative to the size of the Internet (Reported [21]).

## Part 3: crime and prosecutions

### The United Kingdom: the first Computer Misuse Act trials

On 17 March 1993 Paul Bedworth, 19, was acquitted at Southwark Crown Court after a four-week trial, the first major case under the Computer Misuse Act 1990 (Reported [24]). The defence argued computer obsession or addiction. The charges related to a Lloyds Bank computer, BT's network and a European Community system in Luxembourg, and Newsbytes reported that he reached dozens of hosts by password guessing and known DEC VAX weaknesses (Reported [24]). *Virus Bulletin*'s April editorial called the verdict a disaster for the prosecution and reported that the Computer Crime Unit had used a conspiracy charge so the group could be tried together (Reported [33]).

His co-defendants Neil Woods and Karl Strickland pleaded guilty and were jailed for six months each, the first custodial sentences under the Act; Judge Michael Harris said the sentences were to penalise and deter (Reported [35][27]). The press said they had penetrated systems in 15 countries (Reported [27]). In July programmer Alfred Whitaker was convicted at Scunthorpe Magistrates Court under the Act for making stock-control software he wrote for Protech stop working after a date unless he was paid; he received a two-year conditional discharge (Reported [36]). On 25 November the Metropolitan Police, IBM UK and the magazine PC Plus launched a computer-crime prevention campaign, "Don't let them get away with IT"; the Computer Crime Unit was described as a handful of officers (Reported [40]).

### New York: the Masters of Deception cases close

| Date | Event | Grade | Sources |
|---|---|---|---|
| 1992-12-03 | John Lee ("Corrupt") pleads guilty to conspiracy | Reported | [27] |
| 1993-03-17 | Elias Ladopoulos ("Acid Phreak") and Paul Stira ("Scorpion") plead guilty to conspiracy | Reported | [25] |
| 1993-06-04 | Lee sentenced to a year and a day plus 200 hours' service (Judge Richard Owen). The indictment as reported alleged intrusions at Southwestern Bell, New York Telephone, Pacific Bell, US West and Martin Marietta, a $370,000 Southwestern Bell loss and 176 TRW credit reports | Reported | [27] |
| 1993-07-02 | Mark Abene ("Phiber Optik") pleads guilty to one conspiracy count and one unauthorized-access count, the last of five MOD defendants to plead | Reported | [27] |
| 1993-07 (late) | Ladopoulos and Stira sentenced to six months in prison, six months' home detention and 750 hours of community service; US Attorney Mary White told the court MOD had entered systems of phone companies, banks, credit reporting services and educational institutions | Reported | [25][36] |
| 1993-11-03 | Abene sentenced by Judge Louis Stanton to a year and a day; the *Village Voice* adds three years' probation and 600 hours' service; Julio Fernandez cooperated | Reported | [28][26] |

### Los Angeles: Kevin Poulsen

A new 19-count federal indictment in Los Angeles, reported on 22 April, charged Kevin Poulsen with rigging contests at three radio stations, wiretapping, and access to California DMV and Pacific Bell systems; as reported, it also alleged access to information on FBI wiretaps. Co-defendants Ronald Austin and Justin Tanner Peterson pleaded guilty and agreed to cooperate (Reported [27]). The *Los Angeles Times* reported in September that his federal trials were set for October in San Jose and Los Angeles, without an outcome (Reported [28]). The [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) covers Poulsen's later career as an author.

### Australia: The Realm

In Melbourne, Nahshon Even-Chaim pleaded guilty to 15 charges of unauthorized access, alteration and deletion, and David Woodcock to two counts; Richard Martin Jones had been sentenced earlier, and the arrests dated to April 1990 (Reported [28]).

### Steve Jackson Games (summary)

On 12 March 1993 Judge Sam Sparks (W.D. Tex., Austin, No. A 91 CA 346 SS, 816 F.Supp. 432) held that the Secret Service violated the Privacy Protection Act and the Stored Communications Act in its 1 March 1990 seizure at Steve Jackson Games. The court awarded $8,781 in expenses and $42,259 in economic damages under the Privacy Protection Act, and $1,000 in statutory damages per plaintiff under the Stored Communications Act; the Wiretap Act claim failed because there was no "interception" (Confirmed [22][23]). The [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) is the home for the case, with the Fifth Circuit's 1994 ruling, and the [pre-Internet study](/case-studies/PRE_INTERNET_THREATS.md) carries the 1993 judgment in its timeline.

### Fraud and other crime

A real ATM placed in a Connecticut mall for about two weeks recorded card numbers and PINs; AP reported the scheme was thought to have netted roughly $60,000, withdrawn from a few hundred accounts and a Secret Service estimate of 2,000 to 3,000 accounts recorded (Reported [27]). The Secret Service arrested Alan Scott Pace, 30, and Gerald Greenfield, 50, on 30 June (Reported [29]). The [e-commerce threats study](/case-studies/ECOMMERCE_THREATS.md) picks up payment-card fraud from 1999.

AP reported on 26 April that China had executed Shi Biao, an Agricultural Bank of China accountant in Jilin, for computer-aided forgery of deposits in 1991 worth about $192,000; this rests on a single wire report (Reported [27]). In October an 18-year-old in Creve Coeur, Missouri, was arrested on a state misdemeanor charge for allegedly accessing a federal appeals court's files and charging calls to Mercantile Bank (Reported [28]).

### Insiders with legitimate access

The year's most detailed official record of data misuse concerns insiders (Inferred). At the Senate Governmental Affairs hearing "Auditing the Auditors" on 4 August, Chairman Glenn said IRS employees had browsed the records of friends, relatives, neighbors and celebrities. Comptroller General Bowsher, reading an IRS internal audit, cited 368 Southeast Region employees who monitored accounts without a work reason (289 referred for discipline, 79 to internal security) and four who prepared fraudulent returns; the audit covered one command code out of 56, used by about 6,300 staff (Confirmed [46]). On 28 July GAO told Congress the FBI's National Crime Information Center was vulnerable to misuse by authorized insiders, including disclosure to private investigators for money, that misusers were generally not prosecuted, and that legislation with criminal sanctions was needed (Confirmed [47]).

### Congress and the hacker community

On 9 June the House Subcommittee on Telecommunications and Finance held a hearing on network security and toll fraud at which Emmanuel Goldstein, editor of 2600, testified that hacking itself is not crime and new computer-crime laws are unnecessary (Reported, testimony as reprinted [30]).

## Part 4: viruses and malware

### Polymorphism leaves the laboratory

| Date | Event | Grade | Sources |
|---|---|---|---|
| 1992 | TridenT Polymorphic Engine written by Masud Khafir of the Dutch TridenT group; Girafe the first virus to use it | Reported (F-Secure description) | [43] |
| Early 1993 | TridenT appears, with the Nuke Encryption Device and Tremor; seven polymorphic code generators known by the end of 1993; XTREE leaves the anti-virus business | Reported | [44] |
| 1993-02 | Phalcon/Skism's G2 semi-polymorphic construction kit, credited to "Dark Angel" | Reported | [31] |
| 1993-03 | Tremor analysed: polymorphic, relatively widespread in Germany, attacks resident anti-virus monitors including Central Point's | Reported | [32] |
| 1993-08 | *40Hex* publishes source for Dark Angel's Multiple Encryptor (DAME) | Reported | [36] |
| 1993-09 to 10 | Coffeeshop, first Mutation Engine virus found in the wild (South Africa); STB reported from Canada; SatanBug spreading rapidly in the US | Reported | [38] |

The Mutation Engine and its author, the Dark Avenger, are covered in the [Fancy Bear Goes Phishing study](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md); this record adds only its first sighting in the wild.

### A broadcast supply-chain infection

On 6 May the Micro-BIT Virus Centre received a report of a Tremor infection traced to Channel Videodat, a German service that broadcast software in the television signal to a claimed 60,000 subscribers. On 14 May at 14:00 the service transmitted a Tremor-infected PKUNZIP, sent alongside McAfee SCAN, and replaced it with a clean copy two hours later (Reported [35]). F-Secure's description names a Dusseldorf software shop that supplied Channel Videodat as the source, but dates Tremor's first sighting to late 1993 and its spread to May 1994 (Reported [42]); this study follows *Virus Bulletin*'s contemporaneous March and June 1993 issues (Inferred [32][35]).

### Sizewell B

On 29 June the Yankee Doodle virus infected the construction team's office LAN at Nuclear Electric's Sizewell B site. The site said plant control and safety systems were separate and unaffected; national press coverage followed in November, and *Virus Bulletin*'s site visit called the press treatment "fiction, all too loosely based on fact" (Reported [40]). No primary record opened dates an industrial-control or utility cyber incident to 1993 (Inferred [56]).

### Claims, kits and corporate losses

- A Windows 3.1 virus, Cyber Riot, which infects KRNL386.EXE, was sent to Central Point by a group calling itself The Chicago 7, which claimed 15,000 infected PCs without corroboration (Reported [39]).
- A collection signed "Neuron", PART1.ZIP, of variants of old viruses modified to evade McAfee SCAN, reached researchers in autumn; *Virus Bulletin* counted about 250 in November and 266 files in December, of which SCAN version 109 later identified 236; none was known in the wild (Reported [39][40]).
- Rockwell International reported hundreds of virus incidents over five years, with recent infections making sizeable LANs in two business units unavailable (Reported [38]).
- *Virus Bulletin*'s 1993 prevalence tables were led by the Form boot-sector virus (17 of 62 reports in June), followed by New Zealand 2 (Stoned), Spanish Telecom and Tequila (Reported [36]).

### The anti-virus side

The CARO WILDList of 15 July 1993, (c)1993 Joe Wells, lists a virus when two or more CARO members report it in the wild; its reporters include Solomon, Chess, Kaspersky, Skulason, Wells and Bontchev, and its entries include Stoned variants, Tequila, Yankee Doodle and V-Sign (Confirmed [41]). In December *Virus Bulletin* published the first list from the cooperative led by Symantec's Joe Wells, the beginning of the WildList (Reported [40]). The MS-DOS 6 User's Guide, (c)1993, says MS-DOS 6 includes Anti-Virus for MS-DOS and Windows, detecting more than 800 viruses, and the VSafe resident monitor; MSAV is (c)1992 to 1993 Central Point Software (Confirmed [45]). The March 1993 release month was not checked against a Microsoft primary.

### The AIDS Trojan conviction (summary)

A court in Rome found Dr Joseph Popp guilty in absentia of attempted extortion over the AIDS diskette and sentenced him to two and a half years, the first successful case against him (Reported [34]). The [pre-Internet study](/case-studies/PRE_INTERNET_THREATS.md) is the home for the AIDS Trojan.

## Part 5: the state and intelligence record

### No state intrusion campaign on the record

No government, court or vendor record opened for this study attributes a state-actor computer intrusion campaign to calendar 1993 (Inferred [66][97]). The earliest state-linked campaign in the vendor record opened is Moonlight Maze: Kaspersky and King's College researchers say that in 1996 someone was rummaging through military, research and university networks, with samples compiled as far back as late 1996, and that a conclusion on a Turla link is premature (Reported [74]). Kaspersky says some Equation group command servers appear to have been registered as early as 1996 and that it is not known when the group began (Reported [75]). The live ATT&CK page for Turla (G0010) dates its victims "since at least 2004" (Confirmed [76]), and the library's ATT&CK data records no group, campaign or software activity before 2004 (Demonstrated [97]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Moonlight Maze; the [United States-attributed actors study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) for Equation; the [Russia-attributed actors study](/case-studies/THREAT_ACTORS_RUSSIA.md) for Turla.

The earliest US government record opened that raises possible foreign direction of an intrusion concerns the March and April 1994 Rome Laboratory intrusions: Air Force officials told GAO that at least one hacker may have been working for a foreign country, and one attacker was never caught (Confirmed that GAO reports the statement [66]). A Senate subcommittee minority staff statement of 1996 says the British teenager "Datastream" acted at the direction of an unknown "Kuji"; it is a staff statement, not a court finding (Confirmed [69]).

### Doctrine and institutions

| Date | Event | Grade | Sources |
|---|---|---|---|
| 1992-12 | DoD's defensive information warfare program begins through Defense Directive 3600.1; DISA's Vulnerability Analysis and Assessment Program begins in 1992 | Confirmed | [66] |
| 1993-03-03 and 08 | CJCS MOP 6 (Electronic Warfare) and MOP 30 (Command and Control Warfare) dated, as a 1996 Marine Corps order cites them; JP 3-13.1 says MOP 30 gives joint policy for command and control warfare | Confirmed (citations; MOP 30 text not opened) | [67][68] |
| 1993-06-18 | Joint COMSEC Monitoring Activity concept of operations dated | Confirmed | [68] |
| 1993-09-10 | The Air Force Electronic Warfare Center becomes the Air Force Information Warfare Center at Kelly AFB, adding the Securities Directorate of the AF Cryptologic Support Center and intelligence capability from Air Force Intelligence Command, in response to Desert Storm lessons | Confirmed | [65] |
| 1993 | GAO: AFIWC, with its Computer Emergency Response Team and Countermeasures Engineering Team, established in 1993; the Navy's FIWC followed in 1995 and the Army's LIWA in 1996 | Confirmed | [66] |
| 1993 | Defense installations officially report 115 attacks (53 in 1992, 255 in 1994) | Confirmed | [66] |

DISA's own testing puts those counts in proportion. By 1996 its assessment program had run 38,000 test attacks against Defense systems, succeeding 65 percent of the time, and about 4 percent of the successful attacks were detected by the targets (Confirmed [66]). The reported 115 attacks of 1993 were therefore a floor, not a measure (Inferred [66]). *Air Force Magazine* later said AFIWC had been running since 1993 and that its experts were crucial in cracking the Datastream case (Reported [70]).

### Clipper and key escrow

A presidential directive, "Public Encryption Management", told the Attorney General to request manufacturers to install government-developed key-escrow microcircuits, to arrange escrow holders and to buy devices, and told Commerce to start key-escrow procurement standards (Confirmed, EPIC FOIA copy dated 15 April [49]; FAS copy of PDD-5 [50]). On 16 April the White House announced the voluntary Clipper Chip, developed by "government engineers", with two keys per device deposited in two escrow databases set up by the Attorney General and accessible only with legal wiretap authority; the statement does not name NSA (Confirmed [48]). The Escrowed Encryption Standard followed as a proposal on 30 July and as FIPS 185 on 9 February 1994, and the 1994 notice calls its use "totally voluntary" (Confirmed [51][52]).

### Crypto AG

A long-running state signals operation reached its turning points in 1993, by the account of the Swiss parliament's oversight delegation. Its 2020 report, summarizing the US "MINERVA" history, says Crypto AG passed into joint ownership of US services and the German intelligence service in 1970, and that the German side withdrew at the end of 1993 (Confirmed [71]). Sales engineer Hans Buehler returned in January 1993 from nine months' detention in Iran and was questioned that month by the federal police about the espionage accusations made against him; in spring Crypto AG ended his employment and the media took up the case (Confirmed [71]). From autumn 1993 the Swiss Strategic Intelligence Service obtained reliable information that the firm was owned by American and German intelligence and exported weak devices that could be broken with realistic effort, and set out to break them itself; the report finds this should not have been withheld from political leadership (Confirmed [71]). No specific legal basis for that collection existed; the Federal Council's 8 September message on a new Military Act proposed one, in force on 19 June 1995 (Confirmed [71]). ATT&CK has no object for the operation; any supply-chain technique label would be this study's alone, and none is bound (Inferred [97]).

### Alleged French economic espionage

Knight-Ridder reported on 18 April a 21-page unsigned, undated document stamped "Defense Confidential", attributed to French intelligence, listing 49 high-tech companies, 24 financial institutions and six US agencies as targets; unnamed US officials considered it authentic, and a French Embassy spokesman said nothing in it showed French government offices released it (Reported [72]). The *Christian Science Monitor* reported on 3 May that the CIA had warned Hughes Aircraft and 48 other companies, that Hughes skipped the Paris Air Show, and that France denied involvement (Reported [73]). No primary record of the document was opened.

## Part 6: the government record

### Law

| Date | Jurisdiction | Instrument | Grade | Sources |
|---|---|---|---|---|
| 1993-01-21; in force 1993-03-01 | Netherlands | Wet computercriminaliteit (law of 23 December 1992), Staatsblad 1993, 33: computer trespass where a security measure is broken or access is gained by technical means or false signals (art. 138a Sr); unlawful change or deletion of data (art. 350a) | Confirmed | [59][60] |
| 1993-08-30 | Singapore | Computer Misuse Act, Act 19 of 1993, in force | Confirmed | [61] |
| 1993-12-23; in force 1994-01-14 | Italy | Law No. 547 on computer crime, Gazzetta Ufficiale n. 305 of 30 December 1993; art. 1 extends "violence against property" to altering software or disrupting an IT system; WIPO Lex lists offences for unauthorized access, trafficking in access codes, distributing harmful programs, interception and computer fraud (article numbers not verified) | Confirmed | [62][63] |

### Policy

On 15 September the Information Infrastructure Task Force, chaired by Commerce Secretary Ron Brown, issued the National Information Infrastructure Agenda for Action. It says trustworthy and secure networks are essential, and its action items cover a privacy work plan, a review of encryption policy, and network reliability work through the National Communications System (23 agencies), the FCC's Network Reliability Council and NSTAC (Confirmed [56]). GAO's report OSI-94-2, "Communications Privacy: Federal Policy and Actions", dated 4 November and released the next day at a congressional request, covers privacy against economic espionage, federal authority over cryptographic standards, NSA and State Department export controls on encryption, and the FBI's digital telephony proposal; its findings were not opened (Confirmed [57]).

On 12 October Philip Zimmermann told the House Subcommittee on Economic Policy, Trade and the Environment that PGP was published in the United States as freeware in June 1991, that US Customs was investigating how it spread abroad, that he was a target of that criminal investigation, and that export controls were ineffective (Confirmed [58]).

### Standards

| Date | Standard | Grade | Sources |
|---|---|---|---|
| 1993-01 | Canadian Trusted Computer Product Evaluation Criteria v3.0e (CSE) | Confirmed | [90] |
| 1993-02 | RFC 1421 to 1424, PEM: message encryption and authentication, certificate-based key management, algorithms, key certification (now Historic) | Confirmed | [81][82] |
| 1993-04 | RFC 1446, SNMPv2 security protocols | Confirmed | [86] |
| 1993-05-11 | FIPS 180 Secure Hash Standard (withdrawn 17 April 1995, superseded by FIPS 180-1) | Confirmed | [53] |
| 1993-07 | RFC 1492, TACACS | Confirmed | [87] |
| 1993-09 | RFC 1510, Kerberos V5 (Kohl, DEC; Neuman, ISI): verifies principals on an open network without trusting host addresses; V4 then in production at MIT Project Athena; now Historic, obsoleted by RFC 4120 and RFC 6649 | Confirmed | [83][84] |
| 1993-09 | RFC 1508 GSS-API, RFC 1511 Common Authentication Technology Overview, RFC 1507 DASS | Confirmed | [85] |
| 1993-09 | UK DTI Code of Practice for Information Security Management, later the basis of BS 7799 (1995) (no DTI or BSI primary opened) | Reported | [91] |
| 1993-10 | RFC 1535, a security flaw in DNS resolver search heuristics for partial names, with a correction | Confirmed | [88] |
| 1993-10-05 | FIPS 181 Automated Password Generator | Confirmed | [55] |
| 1993-12-30 | FIPS 46-2 Data Encryption Standard (supersedes FIPS 46-1 of 1988; withdrawn 25 October 1999) | Confirmed | [54] |

Web transport encryption did not exist in 1993: SSL 2 is cited as a February 1995 specification and TLS 1.0 is RFC 2246 of January 1999 (Inferred from the dates [89]).

### Incident response teams

Australia's SERT was formed in 1993 by the University of Queensland, Queensland University of Technology and Griffith University; AusCERT began under that name on 1 April 1994 with AARNet (Confirmed [64]). The Air Force's information warfare center carried its own Computer Emergency Response Team (Confirmed [66]).

## Part 7: the defender view

**The defender's toolkit was born in public, and CERT expected one of those tools, the scanner, to serve attackers (Inferred from [11]).** TIS announced Version 1.0 of its Firewall Toolkit in October: C source for BSD-derived Unix with FTP, rlogin and telnet application proxies, user authentication management, compartmented SMTP and logging, available by anonymous FTP with a US-only directory for export-controlled parts (Confirmed [77]). Its developers say TIS built it under an ARPA contract, made it freely available under license on 1 October, kept the commercial rights and based the Gauntlet firewall on it; Ranum's claim that a DEC system was the first commercial Internet firewall is his own account (Reported [78]). The same autumn, CERT warned that a free scanner would be used to find vulnerable hosts (Confirmed [11]). The firewalls of 1993 were application gateways and screening routers, not stateful inspection (Inferred [77][78]).

**Integrity checking and intrusion detection arrived as research.** Kim and Spafford's Tripwire report of November 1993 describes a no-cost checker that monitors a chosen set of files with interchangeable signature routines and was in use on thousands of machines (Confirmed [79]). SRI's NIDES requirements of March 1993 specify statistical and rule-based components (Confirmed [80]). The library's D3FEND data has File Integrity Monitoring, the counterpart of Tripwire, but none of the D3FEND names that would describe NIDES-style behavior analysis, so NIDES has no library page to link (Demonstrated [104]).

**Authentication was the battlefront.** The scanner's first checks were default accounts and the NIS password file (Confirmed [11]); NetWare 4.0 leaked passwords to disk (Confirmed [9]); the sniffing reported in CA-94:01 captured cleartext logins (Confirmed [17]). Kerberos V5, GSS-API, PEM and FIPS 181 were published the same year (Confirmed [84][85][82][55]); calling them answers is this study's reading (Inferred).

**Anti-virus scaled through cooperation.** CARO members began pooling in-the-wild reports in the WildList (Confirmed [41]), and MS-DOS 6 shipped with anti-virus programs for DOS and Windows (Confirmed [45]). Viruses, the harm most PC users met, sat outside CERT's Unix-centred advisory stream (Inferred [2][41]).

**Insider misuse needed audit, not perimeter.** The IRS case turned on monitoring one command code (Confirmed [46]); GAO wanted criminal sanctions for NCIC misuse (Confirmed [47]). No firewall or scanner of 1993 addressed either (Inferred).

**The same controls recur.** The 1993 advisories already point to removing default accounts, patching network daemons, stripping unneeded privilege, encrypting credentials and monitoring file integrity (Inferred [2][11][79]); the [2016 chronicle](/case-studies/CHRONICLE_2016.md) closes its defender view with a list led by credential hygiene and MFA, with patching among six controls (Demonstrated [106]).

## Part 8: MITRE mappings

No 1993 record carries an ATT&CK, CWE or CAPEC id: CVE began in 1999, CWE's first list in 2006, CAPEC in 2007, ATT&CK's public release in May 2015 with 96 techniques, and D3FEND's research was funded by the NSA Cybersecurity Directorate and announced in 2021 (Confirmed [92][93][94][95]; D3FEND date Reported [96]). Every binding below is therefore this study's later mapping (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `technique_to_d3fend.jsonl`, `d3fend_countermeasures.jsonl`, `software.jsonl`, `data/weaknesses/cwe.jsonl`, `capec.jsonl`) and the generated pages under `mitre/` on 12 November 2026 [97][98][99][100][101][102][103][104]. Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md) (Demonstrated [106]): **Described** means a primary source describes the behavior and this study assigns the id; **Reported** means only a secondary source supports the behavior; **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading. No row is **Listed**, because no 1993 source prints an id.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1595.001`](/mitre/techniques/T1595-001.md) | Scanning IP Blocks | reconnaissance | Described | CA-93:14, 30 Sep 1993: the scanner checks every host in an IP range | [11][99] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | reconnaissance | Described | CA-93:14: known weaknesses checked in one automated tool | [11][2][98] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Described | CA-93:14: probing of mail, FTP, NIS and NFS services | [11][99] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Reported | Bedworth's use of accounts on remote hosts, reported at his 17 Mar 1993 acquittal | [24] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Default Accounts | stealth, persistence, privilege-escalation, initial-access | Described | CA-93:14 checks for default guest, bbs and lp accounts; CA-93:13 (17 Sep) exposes SCO's dos and asg accounts | [11][10][98] |
| [`T1110.001`](/mitre/techniques/T1110-001.md) | Password Guessing | credential-access | Described | CA-93:14 default-account checks; Bedworth's password guessing (Reported) | [11][24] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | CA-93:06 wuarchive ftpd (9 Apr); CA-93:11 gopher (9 Aug); CA-93:15 sendmail "actively exploited" (21 Oct); CA-93:16 sendmail (4 Nov); CA-93:14 sendmail debug commands | [3][4][8][2][12][13][11] |
| [`T1003.008`](/mitre/techniques/T1003-008.md) | /etc/passwd and /etc/shadow | credential-access | Described | CA-93:14 NIS password-file retrieval; CA-93:11 intruders obtain password files through gopher (this second tie is the study's reading) | [11][8] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | discovery | Described | CA-93:14 NFS export checks | [11] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Described | CA-93:09 expreserve (11 Jun); CA-93:17 xterm (11 Nov); CA-93:18 modload and loadmodule (15 Dec) | [2][14][15][98] |
| [`T1548.001`](/mitre/techniques/T1548-001.md) | Setuid and Setgid | privilege-escalation | Inferred | CA-93:17: the flaw sits in a setuid or setgid xterm; the binding to setuid abuse is this study's reading | [14][2][98] |
| [`T1499`](/mitre/techniques/T1499.md) | Endpoint Denial of Service | impact | Described | CA-93:10 (14 Jul): deliberate filling of anonymous FTP disks | [7][2][98] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | Boundary event: CA-94:01 (3 Feb 1994), access information for tens of thousands of systems captured | [17][18] |
| [`T1027.014`](/mitre/techniques/T1027-014.md) | Polymorphic Code | stealth | Reported | TridenT Polymorphic Engine (F-Secure description); Tremor (Mar), G2 (Feb), DAME (Aug), Coffeeshop and SatanBug (Sep to Oct) reported | [43][32][31][36][38][98] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | initial-access | Reported | Channel Videodat broadcasts a Tremor-infected PKUNZIP, 14 May 1993 | [35][98] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | lateral-movement, initial-access | Inferred | Boot-sector viruses on the 15 Jul WildList (Stoned variants) and leading *Virus Bulletin*'s prevalence tables (Form) | [41][36][98] |
| [`T1542.003`](/mitre/techniques/T1542-003.md) | Bootkit | stealth, persistence | Inferred | The same boot-sector viruses | [41][36][103] |

Left out on purpose: the Connecticut ATM scam, a physical card-capture fraud with no Enterprise technique equivalent; the IRS and NCIC insider misuse, because the records describe browsing by authorized users without enough detail to choose a technique; the Crypto AG operation, because no ATT&CK object maps it and a supply-chain label would be this study's alone; the Cisco source-routing flaw (CA-93:07) and the NetWare password-to-disk flaw (CA-93:12), which describe exposure without an attack the sources describe (Inferred).

### ATT&CK for ICS techniques

None. The only 1993 event near an industrial site, the Sizewell B infection, reached an office LAN, not control or safety systems (Reported [40]), and no primary record opened dates an industrial-control cyber incident to 1993 (Inferred [56]). No ICS layer is published.

### ATT&CK groups, software and campaigns

No ATT&CK group, software or campaign object covers any 1993 actor or tool: the library's `software.jsonl` has no entry for Stoned, sendmail or the Internet Security Scanner, and its group, campaign and software data record no activity before 2004 (Demonstrated [97][103]). Three objects enter only as later context for Part 5:

| Id | Object (library name) | Why it appears | Grade | Sources |
|---|---|---|---|---|
| [G0010](/mitre/groups/G0010.md) | Turla | ATT&CK dates its victims since at least 2004 and attributes it to Russia's FSB; the Moonlight Maze link is unproven in the researchers' own words | Confirmed (ATT&CK page); lineage Reported | [76][74] |
| [G0020](/mitre/groups/G0020.md) | Equation | Kaspersky says some command servers may date to 1996; ATT&CK's description gives no start year | Reported (dates); Demonstrated (no start year) | [75][97] |
| [S0587](/mitre/software/S0587.md) | Penquin | The Moonlight Maze lineage researchers examined; no 1993 tie | Demonstrated (page exists) | [97][74] |

### CWE and CAPEC

No CWE is listed by any record for a 1993 flaw; each row below is this study's binding (Inferred). The CAPEC column gives the attack patterns the library's data relates to that CWE, or that ATT&CK relates to the matching technique, and says so where the pairing is this study's own [99][101][102].

| CWE | Weakness (library name) | 1993 record | CAPEC |
|---|---|---|---|
| CWE-1392 | Use of Default Credentials | CA-93:14 default accounts; CA-93:13 SCO accounts | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords, which ATT&CK relates to T1078.001 (the library's CWE-1392 entry relates no CAPEC) |
| CWE-521 | Weak Password Requirements | Bedworth's password guessing; CA-93:14 | [CAPEC-49](/mitre/capec/CAPEC-49.md) Password Brute Forcing and [CAPEC-70](/mitre/capec/CAPEC-70.md), both related to CWE-521 in the library's data |
| CWE-489 | Active Debug Code | CA-93:14 sendmail debug commands | [CAPEC-121](/mitre/capec/CAPEC-121.md) Exploit Non-Production Interfaces, which lists CWE-489 |
| CWE-284 | Improper Access Control | CA-93:06 wuarchive ftpd access-control flaw | [CAPEC-1](/mitre/capec/CAPEC-1.md) Accessing Functionality Not Properly Constrained by ACLs (this study's pairing; the library's CAPEC-1 relates CWE-732 and others, not CWE-284) |
| CWE-250 | Execution with Unnecessary Privileges | CA-93:17 setuid xterm | [CAPEC-69](/mitre/capec/CAPEC-69.md) Target Programs with Elevated Privileges, which the library relates to CWE-250 |
| CWE-319 | Cleartext Transmission of Sensitive Information | CA-94:01 sniffing (boundary) | [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic, which ATT&CK relates to T1040, and [CAPEC-157](/mitre/capec/CAPEC-157.md) Sniffing Attacks (both relate CWE-311 in the library's data) |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | The WildList's boot-sector and file viruses | none in library data |

Patterns without a CWE row: [CAPEC-310](/mitre/capec/CAPEC-310.md) Scanning for Vulnerable Software, [CAPEC-300](/mitre/capec/CAPEC-300.md) Port Scanning (which ATT&CK relates to T1046) and [CAPEC-169](/mitre/capec/CAPEC-169.md) Footprinting (related to T1595) for the scanner; [CAPEC-643](/mitre/capec/CAPEC-643.md) Identify Shared Files/Directories on System, which ATT&CK relates to T1135, for the NFS checks (Inferred bindings [99][101]).

### D3FEND countermeasures

Pairings come from `data/attack/technique_to_d3fend.jsonl` unless the row says the pairing is this study's; every page exists under `/mitre/d3fend/` [100][104].

| Technique from the record | D3FEND countermeasures | 1993 analogue |
|---|---|---|
| T1078.001 Default Accounts | [Change Default Password](/mitre/d3fend/change-default-password.md), [Account Locking](/mitre/d3fend/account-locking.md) (library pairings) | Removing guest and default accounts, as CA-93:14's checks imply [11] |
| T1110.001 Password Guessing | [Strong Password Policy](/mitre/d3fend/strong-password-policy.md), [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md), [One-time Password](/mitre/d3fend/one-time-password.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md) (library pairings) | FIPS 181 generated passwords [55] |
| T1190 Exploit Public-Facing Application | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (library pairings); [Software Update](/mitre/d3fend/software-update.md) (this study's pairing) | The FWTK application proxies; wu-ftpd 2.0 and sendmail 8.6.4 [77][3][12] |
| T1190, sendmail debug commands | [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) (this study's pairing; the library does not map it to T1190) | Disabling debug interfaces [11] |
| T1003.008 /etc/passwd and /etc/shadow | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Local File Permissions](/mitre/d3fend/local-file-permissions.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md) (library pairings) | Tripwire is the File Integrity Monitoring counterpart [79] |
| T1542.003 Bootkit | [Bootloader Authentication](/mitre/d3fend/bootloader-authentication.md), [Software Update](/mitre/d3fend/software-update.md) (library pairings) | No 1993 counterpart in the record |
| T1091 and T1542.003, the virus record | [File Analysis](/mitre/d3fend/file-analysis.md), [Emulated File Analysis](/mitre/d3fend/emulated-file-analysis.md) (this study's pairing; the library maps neither to these techniques); [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (library pairing for T1091) | MSAV and VSafe in MS-DOS 6; scanners [45] |
| T1040 Network Sniffing | The library maps only DNS Traffic Analysis. [Message Encryption](/mitre/d3fend/message-encryption.md), [Message Authentication](/mitre/d3fend/message-authentication.md) and [Credential Transmission Scoping](/mitre/d3fend/credential-transmission-scoping.md) are concept matches only | PEM and Kerberos V5 [82][84] |

The library's D3FEND pairings for T1068 are memory-safety hardenings, which do not describe a fix for a setuid program's file logging, so no countermeasure is bound for that row (Inferred [100]). The library's data has no D3FEND pairing for T1595.002, T1046, T1499, T1027.014 or T1135, and none is invented here [100]. These names are absent from the library's D3FEND data and are not bound: User Behavior Analysis, File Hashing, Encrypted Tunnels, Network Traffic Analysis and Authentication Event Thresholding (Demonstrated [104]).

### Navigator layer

The study's techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-1993.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1993.json), listing the 17 techniques in the Enterprise table under each tactic they carry in v20.0, and listed on [the Navigator layers page](/navigator/index.md). Scores show the basis, not severity, in the house scale set by the 2016 chronicle (Demonstrated [106]): 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping; no entry scores 100, because no 1993 source prints an id. Each entry's comment names the source numbers in the Sources table below. No ICS layer is needed.

## Cross-cutting themes

**Network services were the attack surface.** The advisories CERT tied to attacker activity concern mail, gopher, FTP and file permissions (Confirmed [2][7][8]), and the scanner of September automated the search for them (Confirmed [11]). The attack surface of later years grew, but an early map of it is in this year's advisories (Inferred).

**Tools cut both ways.** The scanner, the firewall toolkit and Tripwire were all free and public (Confirmed [11][77][79]), and CERT said the scanner would be used maliciously (Confirmed [11]). The policy question of who should publish security tools was already posed in 1993 (Inferred).

**Encryption became a policy fight.** Clipper and key escrow (Confirmed [48][49][51]), the PGP investigation (Confirmed [58]), GAO's review of export controls (Confirmed [57]) and turning points in the Crypto AG operation (Confirmed [71]) all date to the same year. The last shows US and German intelligence owning a cipher supplier whose exported devices were weak (Confirmed [71]), while the public debate concerned escrowed keys (Inferred).

**The law caught up unevenly.** Three national computer-crime statutes were published, enacted or brought into force in 1993: the Dutch law of December 1992 (in force 1 March), Singapore's (in force 30 August) and Italy's (enacted 23 December, in force 1994) (Confirmed [59][60][61][62]); the UK's first major trial under its 1990 Act ended in acquittal while guilty pleas led to prison (Reported [24][35]); and a US court found the government had broken privacy statutes in a computer seizure (Confirmed [22]).

**Insiders were the documented data breach.** The year's government record of personal-data misuse is IRS and NCIC staff using legitimate access (Confirmed [46][47]), not outside intruders (Inferred).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: 1993 as a year of state hacking.** No opened record attributes a state intrusion campaign to 1993 [66][97]; the earliest in the vendor record, Moonlight Maze, is dated from 1996 [74]. JP 3-13.1 places CERT's warning about stolen Internet passwords in 1993, but the advisory is dated 3 February 1994 [68][18].
- **Overstated: Sizewell B.** National press implied a risk to the reactor; *Virus Bulletin*'s site visit found an office LAN infection [40].
- **Overstated: CERT's incident count as a measure of attack volume.** CERT later said counts provide little information [20], and Howard estimated that many incidents went unreported [21]; DISA's tests show only about 4 percent of successful attacks were detected [66].
- **Overstated: Clipper as mandatory.** The April statement and FIPS 185 both call it voluntary [48][51].
- **Overstated: the virus claims of their authors.** The Chicago 7's 15,000 infected PCs are uncorroborated [39]; PART1.ZIP's variants were not known in the wild [39].
- **Overstated: "firsts" in retrospectives.** Ranum's first commercial firewall claim is his own account [78].
- **Overstated: any ATT&CK, CWE or CAPEC id on a 1993 event.** None of those programs existed until 1999 to 2015 [92][93][94][95].
- **Understated: active exploitation in 1993.** CERT said sendmail was being actively exploited and that intruders used gopher flaws to obtain password files, months before the 1994 sniffing wave [2][8][17].
- **Understated: insider misuse of government databases.** Two federal records in one year [46][47] sit outside most hacker-era histories.
- **Understated: the legal and standards groundwork.** Three national computer-crime statutes published, enacted or in force in 1993, SHA, the DES reaffirmation, PEM and Kerberos V5 all date to 1993 [59][61][62][53][54][82][84].
- **Understated: Crypto AG.** Its 1993 turning points, the German exit and Swiss intelligence learning of the ownership, come from a parliamentary report published only in 2020 [71].
- **Understated: PC viruses.** They were the harm most users met, but they sit outside CERT's Unix-centred advisories; the WildList and *Virus Bulletin* carry them [41][2].

### Discrepancies in the record

- **Steve Jackson Games damages.** The decision awards $8,781 plus $42,259 under the Privacy Protection Act, $51,040 in all, the figure the [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) reports from the Fifth Circuit opinion (Inferred sum from [22]; Fifth Circuit figure as recorded in the home study), plus $1,000 per plaintiff under the Stored Communications Act [22]. One reading of the same decision gives about $52,040 to the company, which matches $51,040 plus the company's own $1,000 statutory award (Inferred [22]). The sum likely resolves the damages discrepancy that the [pre-Internet study](/case-studies/PRE_INTERNET_THREATS.md) flags between the two opinions; that is for the home study to settle (Inferred).
- **Woods and Strickland's sentencing date.** A Guardian item of 22 May saying "yesterday" places it on 21 May (Inferred); *Virus Bulletin* reported it in its June issue, and a Vancouver Sun reprint dates its report 4 June [35][27].
- **The Poulsen indictment.** The indictment was filed on 21 April by one reading and reported on 22 April [27].
- **The Realm pleas.** Dated about 22 August in one reading of The Age's 23 August report [28].
- **John Lee's sentence.** A year and a day (Reuters, Newsday in *Phrack* 43) against "one year, boot camp" in Newsday's November summary [27][28].
- **Tremor's dates.** *Virus Bulletin* analysed Tremor in March 1993 and reported the broadcast in June 1993; F-Secure dates its first sighting to late 1993 and its spread to May 1994 [32][35][42].
- **PART1.ZIP.** About 250 variants (*Virus Bulletin*, November) against 266 files (*Virus Bulletin*, December) [39][40].
- **The first WildList.** The CARO WILDList page is dated 15 July 1993 [41]; *Virus Bulletin*'s December issue describes publishing the first list from Wells's cooperative [40]. Both are given.
- **The key-escrow directive's date.** The EPIC FOIA copy is dated 15 April 1993 [49]; the FAS copy of PDD-5 is dated with the 16 April announcement [50].
- **The German exit from Crypto AG.** Secondary accounts disagree (1993 or mid-1994); this study uses the Swiss parliament's wording, the end of 1993 per the MINERVA report [71].
- **The Yankee virus's name.** "Yankee Doodle" in one *Virus Bulletin* account and on the WildList, "Yankee" in another [40][41].
- **CA-93:04's date.** The SEI copy is the revised 04a of 18 February [2].

## Sources

All sources were opened on 12 November 2026. Grade is the source's evidence grade as used in this study.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "1993 CERT Advisories" (compilation page, dated 31 Dec 1993) | https://www.sei.cmu.edu/library/1993-cert-advisories/ | 2026-11-12 | Confirmed |
| 2 | CMU SEI, CA-1993-01 to CA-1993-19 (PDF of all 19 advisories) | https://www.sei.cmu.edu/documents/516/1993_019_001_496248.pdf | 2026-11-12 | Confirmed |
| 3 | CERT/CC, CA-93:06 wuarchive ftpd (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0060.txt | 2026-11-12 | Confirmed |
| 4 | CERT/CC, CA-93:06, as distributed to the NANOG list | https://lists.nanog.org/archives/list/test@lists.nanog.org/thread/V22XDTFLWO5SJ52HGPKXRE7K4DQ2TWHQ | 2026-11-12 | Confirmed |
| 5 | CERT/CC, CA-93:07 Cisco IP source routing (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0061.txt | 2026-11-12 | Confirmed |
| 6 | CERT/CC, CA-93:08 SCO /bin/passwd (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0062.txt | 2026-11-12 | Confirmed |
| 7 | CERT/CC, CA-93:10 Anonymous FTP Activity (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0063.txt | 2026-11-12 | Confirmed |
| 8 | CERT/CC, CA-93:11 UMN gopher (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0064.txt | 2026-11-12 | Confirmed |
| 9 | CERT/CC, CA-93:12 Novell LOGIN.EXE (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0065.txt | 2026-11-12 | Confirmed |
| 10 | CERT/CC, CA-93:13 SCO home directories (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0067.txt | 2026-11-12 | Confirmed |
| 11 | CERT/CC, CA-93:14 Internet Security Scanner, as distributed to the NANOG list, 30 Sep 1993 | https://lists.nanog.org/archives/list/test@lists.nanog.org/thread/JFEG3UJRTFL375T7AA4TZBFFF7IZYZ2N | 2026-11-12 | Confirmed |
| 12 | NECTEC mail archive, forwarded copies of CA-93:16 sendmail and CA-94:01 | https://www.nectec.or.th/users/htk/cert | 2026-11-12 | Confirmed |
| 13 | CERT/CC, CA-93:16 sendmail, as distributed to the NANOG list | https://lists.nanog.org/archives/list/test@lists.nanog.org/thread/FWASVGL4A7OHTB5OP6CILG5VM5I4DMXG/ | 2026-11-12 | Confirmed |
| 14 | CERT/CC, CA-93:17 xterm logging (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0070.txt | 2026-11-12 | Confirmed |
| 15 | CERT/CC, CA-93:18 SunOS and Solbourne loadmodule and modload (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0071.txt | 2026-11-12 | Confirmed |
| 16 | CERT/CC, CA-93:19 Solaris system startup (text-file mirror) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0072.txt | 2026-11-12 | Confirmed |
| 17 | CERT/CC, CA-94:01 Ongoing Network Monitoring Attacks, as distributed to the NANOG list | https://lists.nanog.org/archives/list/test@lists.nanog.org/thread/JQFJLNSVX3SHMUY5FP3IC2664JA4OQQG/ | 2026-11-12 | Confirmed |
| 18 | RISKS Digest 15.45, 8 Feb 1994, reprinting CA-94:01 | https://catless.ncl.ac.uk/Risks/15/45 | 2026-11-12 | Confirmed |
| 19 | seclists.org, Bugtraq archive, November 1993 | https://seclists.org/bugtraq/1993/Nov/ | 2026-11-12 | Demonstrated |
| 20 | CdrInfo, CERT/CC Statistics 1988 to 2004 (reprint of the CERT/CC table) | https://cdrinfo.com/d7/content/certcc-statistics-1988-2004 | 2026-11-12 | Reported |
| 21 | CERIAS, J. D. Howard, analysis of security incidents on the Internet 1989 to 1995 (CMU PhD thesis, 7 Apr 1997) | https://cerias.purdue.edu/apps/reports_and_papers/view/1534 | 2026-11-12 | Reported |
| 22 | *Steve Jackson Games v. US Secret Service*, W.D. Tex., decision of 12 Mar 1993 (text reproduced by Steve Jackson Games) | https://www.sjgames.com/SS/decision-text.html | 2026-11-12 | Confirmed |
| 23 | Leagle, 816 F.Supp. 432 (W.D. Tex. 1993), reporter header | https://leagle.com/decision/19931248816fsupp43211195 | 2026-11-12 | Confirmed |
| 24 | Newsbytes (Steve Gold), "UK court acquits teenage hacker", 17 Mar 1993, EFF archive | https://w2.eff.org/Net_culture/Hackers/uk_court_acquits_teenage_hacker.article | 2026-11-12 | Reported |
| 25 | John F. McMullen (Newsbytes), "Reflections on Hacker Sentencing", 29 Jul 1993, EFF archive | https://w2.eff.org/Net_culture/Hackers/sentencing_hacker.article | 2026-11-12 | Reported |
| 26 | Julian Dibbell, "The Prisoner: Phiber Optik Goes Directly to Jail", *Village Voice*, 11 Jan 1994, EFF archive | https://w2.eff.org/Net_culture/Hackers/phiber_jailed.article | 2026-11-12 | Reported |
| 27 | *Phrack* 43, Phrack World News (reprints of 1993 press: AP, Reuters, Newsday, San Francisco Chronicle, Vancouver Sun, Washington Post) | https://phrack.org/issues/43/phrack-world-news.html | 2026-11-12 | Reported |
| 28 | *Phrack* 44, Phrack World News (reprints of 1993 press: Newsday, The Age, St. Louis Post-Dispatch, Los Angeles Times) | https://phrack.org/issues/44/phrack-world-news.html | 2026-11-12 | Reported |
| 29 | *American Banker*, "2 arrested in shopping center ATM scam", 30 Jun 1993 | https://www.americanbanker.com/news/2-arrested-in-shopping-center-atm-scam | 2026-11-12 | Reported |
| 30 | Emmanuel Goldstein, written testimony to the House Subcommittee on Telecommunications and Finance, 9 Jun 1993 (from *Computer Underground Digest* 5.43), EFF archive | https://w2.eff.org/Privacy/Security/goldstein.testimony | 2026-11-12 | Reported |
| 31 | *Virus Bulletin*, February 1993 | https://www.virusbulletin.com/uploads/pdf/magazine/1993/199302.pdf | 2026-11-12 | Reported |
| 32 | *Virus Bulletin*, March 1993 | https://www.virusbulletin.com/uploads/pdf/magazine/1993/199303.pdf | 2026-11-12 | Reported |
| 33 | *Virus Bulletin*, April 1993 | https://www.virusbulletin.com/uploads/pdf/magazine/1993/199304.pdf | 2026-11-12 | Reported |
| 34 | *Virus Bulletin*, May 1993 | https://virusbulletin.com/uploads/pdf/magazine/1993/199305.pdf | 2026-11-12 | Reported |
| 35 | *Virus Bulletin*, June 1993 | https://virusbulletin.com/uploads/pdf/magazine/1993/199306.pdf | 2026-11-12 | Reported |
| 36 | *Virus Bulletin*, August 1993 | https://www.virusbulletin.com/uploads/pdf/magazine/1993/199308.pdf | 2026-11-12 | Reported |
| 37 | *Virus Bulletin*, September 1993 | https://www.virusbulletin.com/uploads/pdf/magazine/1993/199309.pdf | 2026-11-12 | Reported |
| 38 | *Virus Bulletin*, October 1993 | https://www.virusbulletin.com/uploads/pdf/magazine/1993/199310.pdf | 2026-11-12 | Reported |
| 39 | *Virus Bulletin*, November 1993 | https://virusbulletin.com/uploads/pdf/magazine/1993/199311.pdf | 2026-11-12 | Reported |
| 40 | *Virus Bulletin*, December 1993 | https://www.virusbulletin.com/uploads/pdf/magazine/1993/199312.pdf | 2026-11-12 | Reported |
| 41 | *Virus Bulletin*, CARO WILDList, 15 Jul 1993 | https://www.virusbulletin.com/resources/wildlists/1993/07 | 2026-11-12 | Confirmed |
| 42 | F-Secure, threat description: Tremor | https://www.f-secure.com/v-descs/tremor.shtml | 2026-11-12 | Reported |
| 43 | F-Secure, threat description: TridenT Polymorphic Engine | https://www.f-secure.com/v-descs/tpe.shtml | 2026-11-12 | Reported |
| 44 | cknow.com, "1993 Polymorphics and Engines" (material credited to Dr. Solomon's Software) | https://cknow.com/cms/?p=720 | 2026-11-12 | Reported |
| 45 | Microsoft, MS-DOS 6 User's Guide, (c)1993 (bitsavers copy) | https://ftp.mirrorservice.org/sites/www.bitsavers.org/pdf/microsoft/msdos_6/424-10009_MSDOS_6_Users_Guide_199303.pdf | 2026-11-12 | Confirmed |
| 46 | US Senate Committee on Governmental Affairs, "Auditing the Auditors" hearing, 4 Aug 1993 (Internet Archive scan) | https://archive.org/details/auditingauditors00unit | 2026-11-12 | Confirmed |
| 47 | GAO, T-GGD-93-41, National Crime Information Center: Legislation Needed to Deter Misuse of Criminal Justice Information, 28 Jul 1993 | `https://www.gao.gov/products/t-ggd-93-41` | 2026-11-12 | Confirmed |
| 48 | The White House, Office of the Press Secretary, statement on the Clipper Chip encryption initiative, 16 Apr 1993 (NARA archive) | https://clintonwhitehouse6.archives.gov/1993/04/1993-04-16-press-release-on-clipper-chip-encryption-initiative.html | 2026-11-12 | Confirmed |
| 49 | Presidential directive "Public Encryption Management", 15 Apr 1993 (EPIC FOIA copy, MIT 6.805 transcription) | https://groups.csail.mit.edu/mac/classes/6.805/articles/crypto/clipper-directive.html | 2026-11-12 | Confirmed |
| 50 | Presidential Decision Directive 5, "Public Encryption Management" (FAS copy) | https://irp.fas.org/offdocs/pdd5.htm | 2026-11-12 | Confirmed |
| 51 | Federal Register, 9 Feb 1994, approval of FIPS 185 Escrowed Encryption Standard (citing the 30 Jul 1993 proposal, 58 FR 40791) | https://www.govinfo.gov/content/pkg/FR-1994-02-09/html/94-2919.htm | 2026-11-12 | Confirmed |
| 52 | NIST CSRC, FIPS 185 Escrowed Encryption Standard | https://csrc.nist.gov/pubs/fips/185/final | 2026-11-12 | Confirmed |
| 53 | NIST CSRC, FIPS 180 Secure Hash Standard | https://csrc.nist.gov/pubs/fips/180/final | 2026-11-12 | Confirmed |
| 54 | NIST CSRC, FIPS 46-2 Data Encryption Standard | https://csrc.nist.gov/pubs/fips/46-2/final | 2026-11-12 | Confirmed |
| 55 | NIST CSRC, FIPS 181 Automated Password Generator | https://csrc.nist.gov/pubs/fips/181/final | 2026-11-12 | Confirmed |
| 56 | Information Infrastructure Task Force, The National Information Infrastructure: Agenda for Action, 15 Sep 1993 (NARA archive) | https://clintonwhitehouse6.archives.gov/1993/09/1993-09-15-the-national-information-infrastructure-agenda-for-action.html | 2026-11-12 | Confirmed |
| 57 | GAO, OSI-94-2, Communications Privacy: Federal Policy and Actions, 4 Nov 1993 | `https://www.gao.gov/products/osi-94-2` | 2026-11-12 | Confirmed |
| 58 | Testimony of Philip Zimmermann, House Subcommittee for Economic Policy, Trade and the Environment, 12 Oct 1993 (FAS copy) | https://irp.fas.org/congress/1993_hr/931012_zimmerman.htm | 2026-11-12 | Confirmed |
| 59 | Staatsblad 1993, 33, Wet computercriminaliteit | https://zoek.officielebekendmakingen.nl/stb-1993-33.pdf | 2026-11-12 | Confirmed |
| 60 | Netherlands Ministry of Justice, explanatory memorandum on a later computer-crime bill (entry into force of the 1993 law) | https://internetconsultatie.nl/wetsvoorstel_versterking_bestrijding_computercriminaliteit/document/199 | 2026-11-12 | Confirmed |
| 61 | Singapore Statutes Online, Computer Misuse Act 1993 | `https://sso.agc.gov.sg/Act/CMA1993` | 2026-11-12 | Confirmed |
| 62 | Normattiva, Legge 23 dicembre 1993, n. 547 | https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:legge:1993-12-23;547 | 2026-11-12 | Confirmed |
| 63 | WIPO Lex, Italy, Law No. 547 of 23 December 1993 | https://www.wipo.int/wipolex/en/legislation/details/2532 | 2026-11-12 | Confirmed |
| 64 | AusCERT, "25 years of AusCERT", 8 Mar 2018 | https://auscert.org.au/blogs/2018-03-08-25-years-auscert | 2026-11-12 | Confirmed |
| 65 | US Air Force, 688th Cyberspace Wing unit history (National Security Archive) | https://nsarchive.gwu.edu/sites/default/files/documents/5626438/U-S-Air-Force-688th-Cyberspace-Wing-History.pdf | 2026-11-12 | Confirmed |
| 66 | GAO, AIMD-96-84, Information Security: Computer Attacks at Department of Defense Pose Increasing Risks, 21 May 1996 | `https://www.gao.gov/assets/aimd-96-84.pdf` | 2026-11-12 | Confirmed |
| 67 | US Marine Corps, MCO 3430.2B, 22 Apr 1996 (citing CJCS MOP 6 and MOP 30) | https://www.globalsecurity.org/military/library/policy/usmc/mco/3430-2/mco3430-2b.pdf | 2026-11-12 | Confirmed |
| 68 | Joint Pub 3-13.1, Joint Doctrine for Command and Control Warfare, 7 Feb 1996 | https://edocs.nps.edu/dodpubs/topic/jointpubs/JP3/JP3_13.1_960207.pdf | 2026-11-12 | Confirmed |
| 69 | US Senate Permanent Subcommittee on Investigations, minority staff statement, 5 Jun 1996 (FAS copy) | https://irp.fas.org/congress/1996_hr/s9606053.htm | 2026-11-12 | Confirmed |
| 70 | *Air Force Magazine*, March 1997 | https://www.airandspaceforces.com/article/0397sweepers/ | 2026-11-12 | Reported |
| 71 | Swiss Parliament, GPDel inspection report on Crypto AG, 10 Nov 2020 | https://www.parlament.ch/centers/documents/de/bericht-gpdel-2020-11-10-d.pdf | 2026-11-12 | Confirmed |
| 72 | *Seattle Times* (Knight-Ridder), "Boeing called a target of French spy effort", 18 Apr 1993 | https://archive.seattletimes.com/archive/19930418/1696416/boeing-called-a-target-of-french-spy-effort | 2026-11-12 | Reported |
| 73 | *Christian Science Monitor*, 3 May 1993 | https://proof.csmonitor.com/1993/0503/03082.html | 2026-11-12 | Reported |
| 74 | Kaspersky (Securelist) with King's College London, "Penquin's Moonlit Maze", 3 Apr 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Reported |
| 75 | Kaspersky (Securelist), report on the Equation group, 16 Feb 2015 | https://securelist.com/the-equation-group/68750/ | 2026-11-12 | Reported |
| 76 | MITRE ATT&CK, group G0010 Turla (live page) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 77 | TIS Firewall Toolkit Version 1.0 announcement, 20 Oct 1993 (avolio.com copy; the host's TLS certificate does not match its name, so the address is given as text) | `https://avolio.com/fwtkv1-0announcement/` | 2026-11-12 | Confirmed |
| 78 | Ranum and Avolio, history of the TIS Firewall Toolkit (retrospective; same host as source 77) | `https://avolio.com/fwtk-history/` | 2026-11-12 | Reported |
| 79 | Kim and Spafford, "The Design and Implementation of Tripwire: A File System Integrity Checker", Purdue CSD-TR-93-071, Nov 1993 | https://docs.lib.purdue.edu/cstech/1084 | 2026-11-12 | Confirmed |
| 80 | Lunt and Anderson, NIDES software requirements specification, SRI International, Mar 1993 (CERIAS catalog record) | https://www.cerias.purdue.edu/apps/reports_and_papers/view/1664 | 2026-11-12 | Confirmed |
| 81 | RFC Editor, RFC 1421 information page | https://www.rfc-editor.org/info/rfc1421 | 2026-11-12 | Confirmed |
| 82 | RFC 1421, Privacy Enhancement for Internet Electronic Mail: Part I (text) | https://www.rfc-editor.org/rfc/rfc1421.txt | 2026-11-12 | Confirmed |
| 83 | RFC Editor, RFC 1510 information page | https://www.rfc-editor.org/info/rfc1510 | 2026-11-12 | Confirmed |
| 84 | RFC 1510, The Kerberos Network Authentication Service (V5) (text) | https://www.rfc-editor.org/rfc/rfc1510.txt | 2026-11-12 | Confirmed |
| 85 | RFC 1508, Generic Security Service Application Program Interface | https://www.rfc-editor.org/rfc/rfc1508.txt | 2026-11-12 | Confirmed |
| 86 | RFC 1446, Security Protocols for version 2 of SNMP | https://www.rfc-editor.org/rfc/rfc1446.txt | 2026-11-12 | Confirmed |
| 87 | RFC 1492, An Access Control Protocol, Sometimes Called TACACS | https://www.rfc-editor.org/rfc/rfc1492.txt | 2026-11-12 | Confirmed |
| 88 | RFC 1535, A Security Problem and Proposed Correction With Widely Deployed DNS Software | https://www.rfc-editor.org/rfc/rfc1535.txt | 2026-11-12 | Confirmed |
| 89 | RFC 2246, The TLS Protocol Version 1.0 | https://www.rfc-editor.org/rfc/rfc2246.txt | 2026-11-12 | Confirmed |
| 90 | Canadian Trusted Computer Product Evaluation Criteria v3.0e, Jan 1993 (FIRST 1994 CD archive copy) | https://discmaster.textfiles.com/file/12178/Forum_of_Incident_Response_and_Security_Teams_FIRST_October_1994.iso/papers/criteria/ctcpec1.ps/ctcpec1.pdf | 2026-11-12 | Confirmed |
| 91 | Johansson, University of Helsinki seminar paper on BS 7799, 2003 | https://cs.helsinki.fi/group/turvasem/papers/johansson_bs7799.pdf | 2026-11-12 | Reported |
| 92 | CVE, history of the CVE program (archived about page) | https://www.cve.org/Resources/Media/Archives/OldWebsite/about/history.html | 2026-11-12 | Confirmed |
| 93 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 94 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 95 | MITRE, ATT&CK Design and Philosophy, March 2020 | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | 2026-11-12 | Confirmed |
| 96 | MITRE D3FEND, about (funding); the 22 Jun 2021 announcement date rests on secondary coverage | https://d3fend.mitre.org/about/ | 2026-11-12 | Reported |
| 97 | TeamStarWolf library, main branch, `data/attack/` (groups, campaigns, software) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-12 | Demonstrated |
| 98 | TeamStarWolf library, main branch, `mitre/techniques/` | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/techniques | 2026-11-12 | Demonstrated |
| 99 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_profiles.jsonl | 2026-11-12 | Demonstrated |
| 100 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_to_d3fend.jsonl | 2026-11-12 | Demonstrated |
| 101 | TeamStarWolf library, `data/weaknesses/capec.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/capec.jsonl | 2026-11-12 | Demonstrated |
| 102 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/cwe.jsonl | 2026-11-12 | Demonstrated |
| 103 | TeamStarWolf library, `data/attack/software.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/software.jsonl | 2026-11-12 | Demonstrated |
| 104 | TeamStarWolf library, `data/attack/d3fend_countermeasures.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/d3fend_countermeasures.jsonl | 2026-11-12 | Demonstrated |
| 105 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` (its 1993 rows) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-12 | Demonstrated |
| 106 | TeamStarWolf library, `case-studies/CHRONICLE_2016.md` (Part 9 basis and score scale) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/case-studies/CHRONICLE_2016.md | 2026-11-12 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md)
- Home studies: [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [Five Hacks and Why They Worked](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md) (his case is not among this year's sources); [The Cuckoo's Egg Intrusion](/case-studies/CUCKOOS_EGG_1986.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [United States-attributed actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md)
- Series: [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Groups (later context only): [G0010 Turla](/mitre/groups/G0010.md), [G0020 Equation](/mitre/groups/G0020.md) · Software: [S0587 Penquin](/mitre/software/S0587.md)
- Techniques: [T1595.002 Vulnerability Scanning](/mitre/techniques/T1595-002.md), [T1078.001 Default Accounts](/mitre/techniques/T1078-001.md), [T1110.001 Password Guessing](/mitre/techniques/T1110-001.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1003.008 /etc/passwd and /etc/shadow](/mitre/techniques/T1003-008.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1548.001 Setuid and Setgid](/mitre/techniques/T1548-001.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1027.014 Polymorphic Code](/mitre/techniques/T1027-014.md), [T1195.002 Compromise Software Supply Chain](/mitre/techniques/T1195-002.md), [T1091 Replication Through Removable Media](/mitre/techniques/T1091.md)
- CAPEC: [CAPEC-70](/mitre/capec/CAPEC-70.md), [CAPEC-49](/mitre/capec/CAPEC-49.md), [CAPEC-121](/mitre/capec/CAPEC-121.md), [CAPEC-310](/mitre/capec/CAPEC-310.md), [CAPEC-158](/mitre/capec/CAPEC-158.md)
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-1993.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1993.json)
