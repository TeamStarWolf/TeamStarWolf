# The Year 1995 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 12 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md) · Home studies for events summarized here: [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md) (the Christmas Day 1994 intrusion and the February 1995 arrest), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (the cash-management transfers and the March 1995 arrest in London), [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) (bug bounties from 2005 on), [NSA and CIA Tool Leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md) (the Equation group), [The Year 1994 in Intrusions](/case-studies/CHRONICLE_1994.md) (the Rome Laboratory intrusions) · Series: [The Year 1994 in Intrusions](/case-studies/CHRONICLE_1994.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the later years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 62 min (14,373 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 1995, you need the IP spoofing campaign, SATAN, the December wave and the Harvard wiretap case side by side with the year's CERT advisories and government record, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 9: the defender view](#part-9-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md), [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md), [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

For the people who ran Unix networks in 1995, the year opened and closed with CERT warnings about attacks that got past host trust and passwords altogether (Inferred). On 23 January the CERT Coordination Center (CERT/CC) warned that intruders were forging source IP addresses to beat services that trusted a host by its address, and that once they had root on SunOS 4.1.x they were using a kernel tool to take over open terminal and login sessions, one-time passwords included (Confirmed [1][3]). The best-known case was the Christmas Day 1994 attack on Tsutomu Shimomura's systems, which he set out on Usenet on 25 January (Confirmed [4]). In late June CERT counted 170 IP spoofing attacks in a few weeks, at least 80 of them against name servers, routers and other network operation systems, and said they were largely successful (Confirmed [13]). On 18 December it reported that hundreds of sites had been attacked over the preceding weeks, many with root compromise, by intruders who scanned automatically for NFS and NIS weaknesses, installed Trojan horses and packet sniffers, and used only flaws CERT had already published advisories for (Confirmed [1]).

Between those warnings the tools changed hands. SATAN, a free scanner that probed finger, NFS, NIS, ftp and rexd and could wander outside its operator's domain, went public on 5 April; CERT reviewed it in advance and warned it was likely to be used to find vulnerable hosts for malicious reasons (Confirmed [1][69]; Reported [11]). In September *Virus Bulletin* described Winword.Concept, a macro virus that spreads through Microsoft Word documents on any platform that runs Word, and reported it on a ServerWare CD sent to more than 5,500 Windows NT users, on a Microsoft compatibility-test CD sent to hardware makers and on a disk handed out at a DEC users' conference in Dublin (Reported [18][19][20]). Researchers broke a 40-bit export SSL session in August, showed in September that Netscape's SSL keys were predictable because of how its random number generator was seeded, and in December published timing attacks that recover secret keys (Demonstrated [14][32][39]). In October Netscape announced a $1,000 "Bugs Bounty", ten years before the earliest bounty in the library's [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) (Reported [36]; Demonstrated [93]).

The year's best-documented intrusion into Defense systems is the work of an intruder from Argentina. In late August the Navy detected an intrusion traced to a Harvard host; investigators ran what the Justice Department calls the first court-ordered wiretap on a computer network for the last two months of the year, and Argentine authorities seized the intruder's equipment in Buenos Aires on 28 December (Confirmed [16]). GAO later wrote that DISA data imply the Department of Defense may have had as many as 250,000 attacks in 1995, an extrapolation set against 559 attacks officially reported (Confirmed [40]). Around it sit the arrest of Kevin Mitnick on 15 February (home: the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md)), the London arrest in March of the man behind the 1994 cash-management transfers (home: the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md)), a Secret Service bulletin-board sting, and the first prison sentence in the United Kingdom for writing and spreading viruses (Confirmed [5][10][25]; Reported [21][22][23]).

Defenders gained new tools the same year. SSH 1.0 was announced in July as a free replacement for rlogin, rsh and rcp (Confirmed [77]); the S/KEY one-time password system was published as RFC 1760 in February (Confirmed [78]); the first IPsec standards-track RFCs appeared in August (Confirmed [66]); NIST issued SHA-1 in FIPS 180-1 and its computer security handbook (Confirmed [61][64]); the British Standards Institution published BS 7799-1, an information security management code of practice (Confirmed [82]); and the European Union adopted its data protection directive, whose Article 17 requires security measures (Confirmed [60]).

This study is the dated record of that year, built only from sources opened on 12 November 2026. Eight parts cover the timeline, the 18 CERT advisories, the Defense record, crime and prosecutions, viruses, the cryptography breaks and the first browser bounty, the state and intelligence record, and the government's laws and standards; a ninth gives the defender view and a tenth maps the record to MITRE frameworks.

No identifier system that defenders use today existed in 1995. CVE began in 1999, CWE's first release came in 2006, CAPEC in 2007 and ATT&CK's public release in May 2015 (Confirmed [72][83][84][85]). The year's own vulnerability identifiers are CERT's advisory numbers, CA-95:01 to CA-95:18 (Confirmed [1][2]). Several of those flaws were later given back-dated CVE-1999 records, which Part 2 lists; every ATT&CK id in Part 10 is this study's later mapping, labelled as such.

Evidence grade: CERT/CC and CIAC texts, GAO reports, Justice Department and US Attorney releases, FBI histories, court opinions, statutes, NIST, RFC Editor, BSI and NVD records and the researchers' own posts and papers are **Confirmed**. Facts that rest on *Virus Bulletin*, press digests such as Edupage, newspaper accounts and later retrospectives are **Reported** and attributed. A researcher's public break of a challenge or product is **Demonstrated**, as is a query or data file this study ran or opened itself. Where the study draws its own conclusion it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 1995, plus boundary records that close or explain a 1995 event (Shimomura's post on a 25 December 1994 attack, the March 1996 Ardita complaint, GAO/AIMD-96-84 of May 1996, the 1996 and 1997 appeals, the 1998 pleas, the 1999 Mitnick sentence) |
| CERT/CC advisories | 18, CA-95:01 to CA-95:18, republished by SEI as CA-1995-01 to CA-1995-18; first issued 23 January, last 18 December (Confirmed [1][2]) |
| Flaws CERT said attackers were using | IP spoofing and session hijacking (CA-95:01), Sun sendmail -oR (CA-95:11), loadmodule (CA-95:12), syslog via sendmail (CA-95:13), SGI default accounts (CA-95:15), wu-ftpd SITE EXEC (CA-95:16), rpc.ypupdated (CA-95:17, exploit posted to newsgroups) and the December wave (CA-95:18) (Confirmed [1]) |
| Attacks on network infrastructure | 170 IP spoofing attacks in a few weeks, at least 80 of the known targets name servers, routers and other network operation systems (CERT heads-up of 29 June, resent 21 July) (Confirmed [13]) |
| Largest breach wave | CA-95:18, 18 December: hundreds of sites attacked, many root compromises, more believed undetected; every flaw used already advised (Confirmed [1]) |
| Incidents and vulnerabilities reported to CERT/CC | 2,412 incident reports (2,341 in 1994), 32,084 e-mail messages and 3,428 hotline calls (Confirmed [44]); 171 vulnerabilities, the first year of that series (Confirmed [43]) |
| Defense attacks | 559 officially reported in 1995 (255 in 1994); DISA's extrapolated estimate of as many as 250,000 (Confirmed [40][41]) |
| Landmark investigation | Harvard FAS host used as a base against the Naval Research Laboratory, NASA JPL and Ames, Los Alamos and the Navy's NCCOSC; first court-ordered wiretap on a computer network, last two months of 1995 (Confirmed [16]) |
| Malware | Winword.Concept, the first Word macro virus seen spreading, analysed in September; shipped on three sets of distributed media (Reported [18][19][20]) |
| Cryptography | 40-bit export SSL broken by brute force, 15 to 16 August; Netscape seed prediction, 17 September; Kocher's timing attacks, 10 December (Demonstrated [14][35][32][39]) |
| Bug bounty | Netscape "Bugs Bounty", $1,000 for a major security bug in the Navigator 2.0 beta (WSJ, 11 October, via Edupage) (Reported [36]) |
| Standards and law | S/KEY RFC 1760 (Feb), BS 7799-1 (15 Feb), FIPS 180-1 SHA-1 (17 Apr), Paperwork Reduction Act (22 May), SSH 1.0 (12 Jul), IPsec RFCs 1825 to 1829 (Aug), EU Directive 95/46/EC (24 Oct), NIST SP 800-12 (Oct) (Confirmed [78][82][61][63][77][66][60][64]) |
| State record | No opened record attributes a 1995 intrusion to a state (Inferred); ATT&CK records no group, software or campaign activity in 1995 (Confirmed [91]); the state story is law, doctrine and signals intelligence (Confirmed [47][52]; Reported [56]) |
| This study's MITRE binding | 18 ATT&CK Enterprise technique rows, every one a later mapping; no ICS row; no group, software or campaign object; fifteen CWE and sixteen CAPEC entries; D3FEND pairings from the library's data; one Navigator layer (Part 10) |

### Key findings

- **Trust by address failed in public.** CERT's first advisory of the year said forged source addresses gave intruders user and possibly root access to services that authenticated by IP address, and that a kernel tool let them take over sessions after root (Confirmed [1][3]). By June CERT had reports of 170 IP spoofing attacks in a few weeks, and at least 80 of the targets it knew of were name servers, routers and other network operation systems (Confirmed [13]).
- **Mass exploitation of known flaws arrived with automation.** CA-95:18 describes automated scanning for NFS and NIS weaknesses across hundreds of sites, and CERT says every vulnerability used was already covered by its advisories (Confirmed [1]). It is the earliest CERT record this study found of the patch-latency problem at scale (Inferred).
- **Scanners became dual-use public tools.** SATAN's authors described it as a two-edged sword that reports problems without exploiting them; CERT reviewed it before release and pointed sites to COPS, ISS, TCP wrappers, the TAMU package and Swatch, and CIAC announced its Courtney detector in the bulletin that recorded the release (Confirmed [70][1][69]).
- **Documents became carriers.** Concept made the advice "you cannot get a virus by reading your mail" untrue for Word-based mail, and it spread on CDs and disks from known vendors in the same month that *Virus Bulletin*'s editor was raising the case for scanning .DOC and .DOT files (Reported [18][19][20]).
- **The cryptography that e-commerce relied on was tested in the open.** Export-grade 40-bit SSL fell to brute force, Netscape's 128-bit keys proved predictable because of their seed, and Kocher showed keys leak through timing (Demonstrated [14][32][39]). None of the breaks is recorded as used against live customer traffic (Inferred).
- **Defenders saw almost nothing.** DISA's test attacks succeeded 65 percent of the time and target organizations detected about 4 percent of the successes (Confirmed [41]); CERT believed more sites in the December wave had been hit than knew it (Confirmed [1]).
- **The year's state story was law, doctrine and signals intelligence, not intrusions.** Russia's FSB law, the Venona release, press reports on Crypto AG, the Air Force's information-warfare doctrine and RAND's exercises all date to 1995, the doctrine paper by *Air Force Magazine*'s account; no record opened ties a 1995 intrusion to a state (Confirmed [47][52][41]; Reported [50][56]; Inferred).

### Top recommendations

1. **Never authenticate by network address alone.** CA-95:01 named SunRPC and NFS, the BSD r-commands, some wrapped services and X as vulnerable, said Kerberos services were not, and told sites to filter forged source addresses at the external router in both directions (Confirmed [1][3]).
2. **Patch what is already advised, fast.** Every flaw in the December wave was covered by an earlier advisory (Confirmed [1]). Scanning tools find unpatched hosts for attackers and defenders alike (Confirmed [1][70]).
3. **Scan yourself before someone else does, and watch for scans.** CERT recommended COPS, ISS, TCP wrappers, the TAMU package and Swatch alongside its SATAN review and noted that many UNIX daemons log too little (Confirmed [1]); CIAC's Courtney flagged hosts probing SATAN's ports (Confirmed [69]).
4. **Change default credentials before a system goes on the network.** SGI shipped IRIX with password-less accounts for plug-and-play installs, and intruders knew them (Confirmed [1]).
5. **Replace cleartext remote logins.** SSH 1.0 and S/KEY both appeared in 1995 to answer sniffing and spoofing (Confirmed [77][78]).
6. **Treat documents as code.** Concept ran through Word's auto-run macros, and *Virus Bulletin*'s editor raised scanning .DOC and .DOT files that same month (Reported [18]).
7. **Have security code reviewed by outsiders and pay people who find flaws.** Goldberg and Wagner's lesson from the Netscape break was outside peer review (Confirmed [32]); Netscape's bounty paid finders that year (Reported [38]).
8. **Plan lawful monitoring before an incident.** The Harvard investigation needed a court order to watch one host for two months (Confirmed [16]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, cryptography and policy dated to 1995, plus the later records that close or explain a 1995 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every event graded, numbers as the source states them.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record (a CERT/CC advisory as SEI publishes it or as distributed in 1995, a CIAC bulletin, a GAO report, a Justice Department or US Attorney release, an FBI history, a court opinion or complaint, a statute, a NIST, RFC Editor, BSI or NVD record, the researcher's or vendor's own post or paper, a live ATT&CK page, or the library's data files as the record of what the library holds) was opened on 12 November 2026 and states the fact |
| Reported | Only a secondary source was opened: *Virus Bulletin*, press digests such as Edupage, newspaper and wire stories and their reprints, retrospectives and vendor research about other parties. The source is named in the text |
| Demonstrated | A researcher publicly showed that an attack works against a real product or challenge (the 1995 SSL breaks, Kocher's timing attacks), or this study ran the query or opened the data itself and saw the result (the NVD date query, the library's data files) |
| Inferred | The study's own reasoning, labelled where it appears. Every MITRE id bound to a 1995 event is Inferred as to the binding |

Limits that a reader should know:

- **No contemporaneous CVE, no ATT&CK.** No 1995 record carries a CVE id or an ATT&CK id; CVE began in 1999 with 321 original entries and a public launch in September 1999 (Confirmed [72]). NVD now returns 25 records with 1995 published dates, all CVE-1999 ids assigned later and back-dated, all with the weakness NVD-CWE-Other (Demonstrated [73]). Part 2 pairs some of them with advisories by date and description (Inferred [74]).
- **The advisory text.** SEI's 1995 compilation is the main text for all 18 advisories [1][2]. CA-95:01 was also read in its January 1995 NANOG distribution [3], and the June heads-up on spoofing in its NANOG copy [13].
- **The Defense record.** GAO/AIMD-96-84 is read in two forms, the govinfo HTML and GAO's PDF, with GAO's product page for the release date [40][41][42]. The Ardita releases were read on the Justice Department's site and in the Federation of American Scientists mirror [15][16][17].
- **Malware rests on *Virus Bulletin*.** Microsoft's own 1995 notice on Concept was not opened; the shipping incidents rest on *Virus Bulletin* and are Reported [19][20]. The WildList, a list of positively identified samples from named participants, is graded Confirmed as the record of what it lists [24].
- **Press digests.** Netscape's own press releases on the seed fix and the Bugs Bounty were not opened; the bounty rests on Edupage digests of the *Wall Street Journal* relayed to Bugtraq and on Kocher's own post [36][37][38][39].
- **Pages that did not open.** RAND's own page for its 1995 exercise report and the *Washington Post*'s original Crypto AG page refused access; GAO's account of the exercises and a reprint of the *Post* story were used [41][51].
- **People.** Defendants named in releases whose outcomes this study did not check are not named: the Operation Cybersnare defendants and the student charged over the Monmouth mail bomb. Named people are those who pleaded guilty or were convicted, or whose appeals are published.
- **Home studies.** The Christmas Day 1994 intrusion and the Mitnick arrest live in the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md); the cash-management transfers and the March 1995 arrest in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); the Equation group in the [tool leaks study](/case-studies/NSA_CIA_TOOL_LEAKS.md); the Rome Laboratory intrusions of 1994 in the [1994 chronicle](/case-studies/CHRONICLE_1994.md). Each is summarized here in a paragraph. The [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) dates bounties from 2005, and the era studies on main do not cover SATAN, SSH, Concept, the Goldberg and Wagner break, Kocher, BS 7799 or IPsec, so this chronicle is their home (Demonstrated [93]).
- **Tradecraft is described at advisory level.** Advisory names, affected products and impact, and technique names and ids. The 1995 advisories carry detection commands and patch checks, and exploit programs circulated for several of the flaws; none is reproduced here.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1995-01 to 06 | RAND runs "The Day After..." information-warfare exercises for OSD C3I: an adversary attacks banks, rail, telephone and military systems in a year-2000 scenario; no adequate tactical warning system found | Policy, exercise | Confirmed | [41][40] |
| 1995-01 | Secret Service undercover bulletin board "Celco 51" begins operating in Bergen County, New Jersey | Crime | Confirmed | [25] |
| 1995-01-11 | Boundary: Shimomura presents the Christmas Day attack at CMAD 3. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Intrusion | Confirmed | [4] |
| 1995-01-20 | Air Force Information Warfare Center's "Final Report, A Technical Analysis of the Rome Laboratory Attacks" dated (as GAO cites it) | Defense | Confirmed | [41] |
| 1995-01-23 | CA-95:01 IP Spoofing Attacks and Hijacked Terminal Connections | Vulnerability, intrusion | Confirmed | [1][3] |
| 1995-01-25 | Shimomura's Usenet post: the attack began about 14:09:32 PST on 25 December 1994 with source address spoofing and sequence-number prediction, then hijacked a connection with a loadable kernel STREAMS module | Intrusion | Confirmed | [4] |
| 1995-01-26 | CA-95:02 timing windows in BSD 4.3-based /bin/mail | Vulnerability | Confirmed | [1] |
| 1995-02 | RFC 1760 documents the S/KEY one-time password system | Standards | Confirmed | [78] |
| 1995-02 | SSL 2.0 specification (Hickman), as RFC 6101 dates it | Standards | Confirmed | [81] |
| 1995-02 | NIST SP 800-11 on FCC Open Network Architecture and national security emergency preparedness telecom security | Standards | Confirmed | [65] |
| 1995-02-08 | anon.penet.fi account disclosed to Finnish police under a search warrant obtained for the Church of Scientology, as a secondary history dates it | Privacy, courts | Reported | [8] |
| 1995-02-15 | FBI and the Raleigh-Durham Fugitive Task Force arrest Kevin Mitnick at 1:30 a.m. after a two-week electronic manhunt. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Confirmed | [5][6] |
| 1995-02-15 | BSI publishes BS 7799-1:1995, Information security management code of practice | Standards | Confirmed | [82] |
| 1995-02-17 | CA-95:04 NCSA HTTP Daemon 1.3 for UNIX executes commands for remote users | Vulnerability | Confirmed | [1] |
| 1995-02-21 | *Bernstein v. Department of State* filed, N.D. Cal. No. C 95-0582-MHP, challenging export licensing of encryption source code | Courts, cryptography | Confirmed (date Inferred) | [9] |
| 1995-02-21 | The anon.penet.fi operator's statement (dated 20 February) says the identity of a poster was handed over with the help of Finnish police | Privacy | Confirmed | [7] |
| 1995-02-22 | CA-95:05 sendmail vulnerabilities, including an IDENT support flaw allowing remote access | Vulnerability | Confirmed | [1] |
| 1995-02-22 | State Duma adopts the law "On the Federal Security Service" | State | Confirmed | [47] |
| 1995-02-22 | *Le Monde* reports France's request that five Americans, four of them diplomats, leave over alleged political and economic espionage | State | Reported | [53] |
| 1995-03 | Vladimir Levin lured to London and arrested over the 1994 cash-management transfers. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime | Confirmed | [10] |
| 1995-03-03 | CA-95:03a Telnet encryption flaw in BSD clients using Kerberos V4 | Vulnerability | Confirmed | [1] |
| 1995-03-08 | SATAN authors' summary posted: reports problems without exploiting them, a "two-edged sword" | Tools | Confirmed | [70] |
| 1995-03-27 | Justin Tanner Petersen pleads guilty to conspiracy to commit computer and wire fraud while a fugitive | Courts | Confirmed | [29] |
| 1995-04-03 | CA-95:06 SATAN review (beta 0.51; updated 11 April for 1.1.1) | Tools | Confirmed | [1] |
| 1995-04-03 | Federal Law No. 40-FZ "On the Federal Security Service" dated | State | Confirmed | [47] |
| 1995-04-05 | SATAN released (scheduled 16:00 MET on ftp.win.tue.nl); CIAC bulletin F-20 records the release and announces Courtney | Tools, defense | Confirmed, Reported | [69][11] |
| 1995-04-17 | FIPS 180-1 Secure Hash Standard (SHA-1) issued, effective 2 October | Standards | Confirmed | [61][62] |
| 1995-04-21 | CA-95:07a SATAN 1.0 and earlier could leak its session key | Tools, vulnerability | Confirmed | [1] |
| 1995-05 | Christopher Pile pleads guilty at Plymouth Crown Court | Courts, malware | Reported | [21][22] |
| 1995-05-22 | Paperwork Reduction Act of 1995, Pub. L. 104-13: agencies to afford security protections commensurate with risk | Law | Confirmed | [63] |
| 1995-06-21 | PDD-39 "U.S. Policy on Counterterrorism", with a part on reducing US vulnerabilities | Policy | Confirmed | [67] |
| 1995-06-29 | Justice Department: Administration and Senators introduce computer crime legislation defining a "protected computer"; cites CERT figures of 498 percent growth in intrusions | Law | Confirmed | [12] |
| 1995-06-29 | CERT/CC heads-up "Continued IP Spoofing Attacks": 170 attacks, at least 80 targets network infrastructure (resent 21 July) | Intrusion | Confirmed | [13] |
| 1995-07-11 | CIA releases the first 49 Venona translations | State | Confirmed | [52] |
| 1995-07-12 | Tatu Ylonen announces SSH 1.0 (reposted to Bugtraq 18 July) | Defense | Confirmed | [77] |
| 1995-07-14 | Hal Finney posts an SSL challenge, a recorded Netscape session under RC4-128-EXPORT-40 (17 July in Doligez's announcement as forwarded to Bugtraq) | Cryptography | Reported | [35][14] |
| 1995-08 | RFCs 1825 to 1829, the first IPsec standards-track documents | Standards | Confirmed | [66] |
| 1995-08 (late) | Navy NCCOSC detects an intrusion into sensitive but unclassified research files, traced to Harvard's FAS host | Intrusion, Defense | Confirmed | [16] |
| 1995-08-15 | Doligez breaks Finney's challenge by brute force; Byers and Young, with Back, broke it about two hours earlier | Cryptography | Demonstrated, Reported | [35][14] |
| 1995-08-16 | Doligez's announcement, forwarded to Bugtraq 16 August: about 120 workstations and some parallel computers, a little more than half the keyspace in 8 days | Cryptography | Demonstrated | [14] |
| 1995-08-17 | Netscape's official response puts the cost of the break at about $10,000, a figure Doligez disputes | Cryptography | Reported | [35] |
| 1995-08-17 | CA-95:08 sendmail version 5 and IDA sendmail: privileges up to root | Vulnerability | Confirmed | [1] |
| 1995-08-24 | A volunteer ring organized by Back and Brooks breaks Finney's second challenge in under 32 hours | Cryptography | Reported | [35] |
| 1995-08-29 | CA-95:09 Solaris 2.x ps race condition in /tmp; exploit published | Vulnerability | Confirmed | [1] |
| 1995-08-31 | CA-95:10 ghostscript -dSAFER bypass, versions 2.6 to 3.22 beta | Vulnerability | Confirmed | [1] |
| 1995-09 | *Virus Bulletin* analyses Winword.Concept; the WildList charts it from five participants | Malware | Reported | [18][24] |
| 1995-09 (second week) | DEC disk given to delegates at the DECUS conference in Dublin carries Concept | Malware, supply chain | Reported | [20] |
| 1995-09 (mid) | Second Word macro virus, Nuclear, found on an FTP site inside an archive posing as a Microsoft file about Concept | Malware | Reported | [20] |
| 1995-09 (end) | ServerWare CD with Concept-infected documents shipped to more than 5,500 Windows NT users; Microsoft admits shipping Concept to OEMs on a compatibility-test CD | Malware, supply chain | Reported | [19] |
| 1995-09-11 | Operation Cybersnare announced: six arrests, more than 20 systems seized in seven states | Crime | Confirmed | [25] |
| 1995-09-17 | Goldberg and Wagner announce that Netscape's SSL seed can be guessed (forwarded to Bugtraq 18 September) | Cryptography | Demonstrated | [32][33] |
| 1995-09-19 | CA-95:11 Sun sendmail -oR on SunOS 4.1.x, widely known and actively exploited | Vulnerability | Confirmed | [1] |
| 1995-09-20 | Wagner's sci.crypt post: no more than 47 bits of seed entropy; sessions breakable in about a minute from a local account | Cryptography | Demonstrated | [34] |
| 1995-10 | RFC 1858 on IP fragment filtering; RFCs 1847, 1848 and 1864 on MIME security | Standards | Confirmed | [79][80] |
| 1995-10 | NIST SP 800-12, the computer security handbook, and SP 800-13 on telecommunications management networks | Standards | Confirmed | [64][65] |
| 1995-10 | WildList fixes the CARO name Concept, nine participants; *Virus Bulletin* prevalence table shows six Concept reports | Malware | Confirmed, Reported | [24][20] |
| 1995-10-11 | Netscape "Bugs Bounty": $1,000 to the first finder of a major security bug in its browser beta (WSJ via Edupage) | Disclosure | Reported | [36][37] |
| 1995-10-13 | NVD published date of CVE-1999-0073, a telnet environment-variable flaw, three weeks before CA-95:14 | Vulnerability | Confirmed | [73][75] |
| 1995-10-18 | CA-95:12 SunOS 4.1.x loadmodule local root; exploitation script in use | Vulnerability | Confirmed | [1] |
| 1995-10-19 | CA-95:13 syslog(3) buffer problem in virtually all UNIX versions, exploited via sendmail | Vulnerability | Confirmed | [1] |
| 1995-10-24 | EU Directive 95/46/EC on personal data adopted (published 23 November) | Law | Confirmed | [60] |
| 1995-11 and 12 | Court-ordered wiretap on the Harvard FAS host, the first on a computer network | Intrusion, courts | Confirmed | [16] |
| 1995-11-01 | CA-95:14 telnetd Environment Option on systems with shared libraries | Vulnerability | Confirmed | [1] |
| 1995-11-08 | CA-95:15 SGI IRIX lp and other accounts shipped without passwords | Vulnerability | Confirmed | [1] |
| 1995-11-15 | Pile sentenced at Exeter Crown Court to 18 months, the first UK custodial sentence for writing and spreading viruses | Courts, malware | Reported | [21][22][23] |
| 1995-11-20 | E-mail bomb of about 24,000 messages crashes Monmouth University's mail system; a student is charged on 28 November | Crime | Confirmed | [26] |
| 1995-11-27 | Petersen sentenced to 41 months, 3 years' supervised release and about $40,000 restitution | Courts | Confirmed | [29] |
| 1995-11-30 | CA-95:16 wu-ftpd SITE EXEC misconfiguration in Linux distributions, actively exploited | Vulnerability | Confirmed | [1] |
| 1995-12 | DoD Defensive Information Warfare Management Plan sets a protect, detect, react approach | Policy | Confirmed | [40] |
| 1995-12-10 | Paul Kocher releases a preliminary paper on timing attacks against RSA, fixed-exponent Diffie-Hellman and DSS | Cryptography | Demonstrated | [39] |
| 1995-12-10 | *Baltimore Sun* story suggests the NSA helped rig Crypto AG cipher machines; Crypto AG denies it | State | Reported | [50] |
| 1995-12-11 | WSJ: Netscape paid two finders $1,000 each and gave gifts to 50 other contestants | Disclosure | Reported | [38] |
| 1995-12-12 | CA-95:17 rpc.ypupdated remote execution on NIS servers; exploit posted to newsgroups | Vulnerability | Confirmed | [1] |
| 1995-12-18 | CA-95:18 Widespread Attacks on Internet Sites | Intrusion | Confirmed | [1] |
| 1995-12-18 | Former IRS employee Richard Czubinski convicted in Boston for browsing taxpayer records | Courts, insider | Confirmed | [27] |
| 1995-12-21 | Strano Network's "Net'Strike" call: participants to reload French government sites for an hour in protest at nuclear testing | Protest | Confirmed | [46] |
| 1995-12-28 | Argentine authorities seize the Harvard intruder's equipment in Buenos Aires | Intrusion, courts | Confirmed | [16] |
| 1996-03-29 | Boundary: Justice Department announces the complaint against Julio Cesar Ardita | Courts | Confirmed | [15][16] |
| 1996-05-22 | Boundary: GAO/AIMD-96-84 released, holding the 1995 Defense figures | Government | Confirmed | [42] |
| 1996-10-22 | Boundary: Ninth Circuit affirms Petersen's sentence, 98 F.3d 502 | Courts | Confirmed | [29] |
| 1997-02-21 | Boundary: First Circuit reverses all of Czubinski's counts, 106 F.3d 1069 | Courts | Confirmed | [28] |
| 1998-01 | Boundary: Levin pleads guilty | Courts | Confirmed | [10] |
| 1998-05-19 | Boundary: Ardita pleads guilty in Boston | Courts | Confirmed | [17] |
| 1999-08-09 | Boundary: Mitnick sentenced to 46 months. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Courts | Confirmed | [31] |

## Part 2: the vulnerability record

### The 18 advisories

CERT/CC issued 18 advisories in 1995, CA-95:01 to CA-95:18; SEI republishes them as "1995 CERT Advisories" in its archive (Confirmed [1][2]). The impact column gives CERT's substance and its own words where quoted. The "Later CVE" column gives NVD records that match the advisory by date and description; the pairing is this study's (Inferred [74][75]).

| Advisory | Date | Product | Impact as CERT states it | Later CVE | Grade | Sources |
|---|---|---|---|---|---|---|
| CA-95:01 | 23 Jan | Services that authenticate by IP address (SunRPC and NFS, BSD r-commands, wrapped services, X); SunOS 4.1.x kernel after root | Forged source addresses give user and possibly root access without source routing; a separate tool takes over open terminal and login sessions, bypassing one-time passwords; Kerberos services not vulnerable; spoofing portion later superseded by CA-96.21 | CVE-1999-0077 (predictable TCP sequence numbers, NVD date 1 Jan 1995) | Confirmed | [1][3][75] |
| CA-95:02 | 26 Jan | BSD 4.3-based /bin/mail | Timing windows through publicly writable directories; supersedes CA-91.01a and CA-91.13 | none found | Confirmed | [1] |
| CA-95:03a | 3 Mar | BSD Telnet clients with the experimental encryption option and Kerberos V4 | A flaw that substantially reduces the effectiveness of the encryption; supersedes CA-95:03 | CVE-1999-1098 [73] | Confirmed | [1][73] |
| CA-95:04 | 17 Feb | NCSA HTTP Daemon 1.3 for UNIX | Can be made to execute commands, giving remote users the httpd account; NCSA's text calls it a buffer overflow; a program breaking into HP systems running the precompiled binary had been published | CVE-1999-0235 [73] | Confirmed | [1][73] |
| CA-95:05 | 22 Feb | sendmail | Several problems, including an IDENT (RFC 1413) support flaw allowing remote unauthorized access; supersedes CA-94:12; later superseded by CA-96.20 | none found | Confirmed | [1] |
| CA-95:06 | 3 Apr | SATAN (beta 0.51, then 1.1.1) | A network testing tool probing finger, NFS, NIS, ftp and rexd, with an exploratory mode that can reach hosts outside the operator's domain; likely to be used to find vulnerable hosts for malicious reasons | CVE-1999-0151 (with CA-95:07a) [73] | Confirmed | [1][73] |
| CA-95:07a | 21 Apr | SATAN 1.0 and earlier | Session key protecting SATAN's processes could leak, depending on configuration and browser; fixed in 1.1; corrects two statements in CA-95:07 | CVE-1999-0151 [73] | Confirmed | [1][73] |
| CA-95:08 | 17 Aug | sendmail version 5, all IDA sendmail and some vendor releases | Create or append files or execute programs, up to root; move to sendmail 8.6.12 | CVE-1999-0203 [73] | Confirmed | [1][73] |
| CA-95:09 | 29 Aug | Solaris 2.x ps | Race condition through a data file in world-writable /tmp gives local root; text from AUSCERT AA-95.07; exploit published | CVE-1999-0164 [73] | Confirmed | [1][73] |
| CA-95:10 | 31 Aug | ghostscript 2.6 to 3.22 beta | -dSAFER bypass lets a booby-trapped PostScript file, for example on a web page, execute commands and modify files; fixed in 4.01 with -dSAFER as default; content from DFN-CERT and NASIRC | CVE-1999-0155 [73] | Confirmed | [1][73] |
| CA-95:11 | 19 Sep | Sun sendmail on SunOS 4.1.x | -oR problem "widely known" and actively exploited; later superseded by CA-96.20 | none found | Confirmed | [1] |
| CA-95:12 | 18 Oct | SunOS 4.1.x loadmodule | Environment-sanitizing flaw gives local root; an exploitation script was public and used | none found | Confirmed | [1] |
| CA-95:13 | 19 Oct | syslog(3) in virtually all UNIX versions (not Sony NEWS-OS 6.X, Solaris 2.5 or Linux libc 4.7.2) | No range checking on an internal buffer, which can be overflowed to run arbitrary programs; exploited with a script aimed at sendmail; workaround sendmail 8.7.1 | CVE-1999-0099 | Confirmed | [1][74] |
| CA-95:14 | 1 Nov | telnet daemons supporting the RFC 1408/1572 Environment Option on systems with shared libraries | Vulnerable; Borman telnet packages older than 23 October 1995 may be affected | CVE-1999-0073 (NVD date 13 Oct 1995) [73] | Confirmed | [1][73][75] |
| CA-95:15 | 8 Nov | SGI IRIX | lp and other accounts shipped without passwords for plug-and-play installation, well known to intruders; several incidents | none found | Confirmed | [1] |
| CA-95:16 | 30 Nov | wu-ftpd 2.4 binaries in Slackware 2.0 to 2.3, Yggdrasil Fall 94 and Debian | SITE EXEC configuration lets any user with an FTP login gain root; actively exploited; the standard source is not vulnerable | CVE-1999-0080 [73] | Confirmed | [1][73] |
| CA-95:17 | 12 Dec | rpc.ypupdated on NIS master and slave servers | Remote users execute arbitrary programs; exploitation program posted to several newsgroups | CVE-1999-0208 [73] | Confirmed | [1][73] |
| CA-95:18 | 18 Dec | Internet sites generally | Hundreds of sites attacked, many root compromises; automated NFS and NIS scanning, rpc.ypupdated and loadmodule, Trojan horses, packet sniffers, IP spoofing; includes Incident Reporting Form v3.0 | not applicable | Confirmed | [1] |

### What the advisories say about attackers

Read in order, the 18 advisories show attackers moving from hand-crafted intrusions to tooling. CA-95:01 describes two separate tools, one for spoofing and one for hijacking sessions after root (Confirmed [3]). From February on, CERT repeatedly reports that an exploit program or script was already published or in use before the advisory: NCSA httpd on HP systems (CA-95:04), ps on Solaris (CA-95:09), loadmodule (CA-95:12), syslog through sendmail (CA-95:13, a script in use) and rpc.ypupdated (CA-95:17) (Confirmed [1]). Two advisories describe misconfigurations shipped by vendors or distributors rather than code bugs: SGI's password-less accounts (CA-95:15) and wu-ftpd binaries built with a dangerous option while the standard source was safe (CA-95:16) (Confirmed [1]). One describes a flaw in a defender's tool, SATAN itself (CA-95:07a), and one a bypass of a safety mode, ghostscript's -dSAFER (CA-95:10) (Confirmed [1]).

### Spoofing moves to the infrastructure

CA-95:01 told sites how to filter forged traffic at the external router, inbound and outbound, and named netlog for detection (Confirmed [1][3]). Five months later CERT sent a heads-up to network operators: 170 IP spoofing attacks against Internet sites internationally in the preceding few weeks, at least 80 of the known targets name servers, routers and other network operation systems, and the attacks largely successful (Confirmed [13]). The heads-up was sent on 29 June and resent on 21 July (Confirmed [13]). The predictable-sequence-number weakness behind the attack has a later NVD record, CVE-1999-0077, whose published date is 1 January 1995 (Confirmed [75]).

### The December wave

CA-95:18, issued a week before Christmas, describes the largest breach event in the year's CERT record (Inferred): hundreds of sites attacked over the preceding weeks, many with root compromise, and more believed undetected (Confirmed [1]). The intruders used automated tools to scan for NFS and NIS weaknesses, exploited rpc.ypupdated (advised six days earlier) and loadmodule (advised in October), installed Trojan horse programs and packet sniffers, and launched IP spoofing attacks; CERT says every vulnerability used was already covered by its advisories (Confirmed [1]). No victim is named in the record, and no study on main covers the wave (Demonstrated [93]). It is the earliest documented case this study found of what defenders now call mass exploitation of known flaws (Inferred).

### SATAN and the scanner debate

SATAN's authors summarized the tool in March: it recognizes common network-related problems and reports them without exploiting them, offers a tutorial and fix for each, builds on their December 1993 paper "Improving the Security of Your Site by Breaking Into it", finds problems on any network above a few dozen systems, and is a two-edged sword (Confirmed [70]). A Bugtraq post scheduled the first official release for 5 April at 16:00 MET on ftp.win.tue.nl (Reported [11]); CIAC's bulletin F-20 of the same day records the release, says each IP address in a subdomain is scanned systematically, and announces CIAC's Courtney, which watches for connections to SATAN-probed ports and reports the host (Confirmed [69]). Purdue's COAST archive lists the year's other detectors: NATAS, Gabriel and a COAST port-scan detector (Confirmed [71]). CERT's review said the vulnerabilities SATAN checks for were not new, but an easy and widely available tool raised the threat to sites that had not patched; that scans appear as heavy port and service sweeps in a short time; and that preventive action matters most (Confirmed [1]). Three weeks later SATAN needed its own fix (CA-95:07a) (Confirmed [1]).

### The later CVE record

CVE began in January 1999 with a Purdue workshop and 321 original entries and launched publicly in September 1999 (Confirmed [72]). An NVD query for records published in 1995 returns 25 records, all CVE-1999 ids assigned later and back-dated, all with the weakness NVD-CWE-Other (Demonstrated [73]). Nine advisories match later records by date and description, listed in the table above; the pairing is this study's (Inferred [74]). The dates are not always event dates: CVE-1999-1080 carries an NVD published date of 10 May 1995 but describes rmmount in SunOS 5.7, a later product, so its 1995 date is an artifact of back-filling (Inferred [76]).

### Counting incidents

CERT/CC's own table records 2,412 incident reports in 1995 against 2,341 in 1994, plus 32,084 e-mail messages and 3,428 hotline calls; CERT says incident growth slowed for the first time, partly because constituency response teams were now taking reports, and that the table does not show the rising sophistication of intruder toolkits (Confirmed [44]). The archived CERT statistics page records 171 vulnerabilities reported in 1995, the first year of that series (Confirmed [43]). The Justice Department's June release cites CERT for a 498 percent rise in reported intrusions and a 702 percent rise in affected sites over four years (Confirmed [12]).

## Part 3: the Defense record and the Harvard wiretap

### Counting attacks on Defense systems

GAO's report AIMD-96-84, "Information Security: Computer Attacks at Department of Defense Pose Increasing Risks", was released on 22 May 1996 after a review that ran from September 1995 to April 1996 (Confirmed [42]). It gives the officially reported attack counts from DISA data: 53 in 1992, 115 in 1993, 255 in 1994 and 559 in 1995 (Confirmed [41]). It also says DISA data imply Defense "may have experienced about 250,000 attacks last year", meaning 1995, and that the exact number cannot be determined because most attacks are not detected or reported (Confirmed [41][40]).

The estimate rests on DISA's Vulnerability Analysis and Assessment Program. Since 1992 it had run 38,000 test attacks on Defense systems, gaining access 65 percent of the time; the target organizations detected only 988 of the successful attacks, about 4 percent, and reported 267 of those, about 27 percent (Confirmed [41]). GAO's summary is that only about 1 in 150 attacks was detected and reported (Confirmed [40]). GAO states the ratio two ways: about 1 in 150 attacks detected and reported in its summary, and about 1 in 150 successful test attacks drawing an active defensive response in chapter 2 (Confirmed [40]). Its own counts give 267 of about 24,700 successful attacks, nearer 1 in 92, so the 1 in 150 is best read as DISA's rounded estimate (Inferred). NSA acknowledged to GAO that potential adversaries were building knowledge of how to attack US systems, and the Energy Department and NSA estimated that more than 120 countries had established computer attack capabilities (Confirmed [41]).

### Rome Laboratory, reported in 1995

The Rome Laboratory intrusions were a 1994 event: in March and April 1994 a British hacker and an unidentified hacker made more than 150 intrusions on the Air Force's Rome Laboratory, using Trojan horses and sniffers, routing through South American phone switches and US commercial sites, and masquerading as a trusted user to attack NASA Goddard, Wright-Patterson Air Force Base and Defense contractors (Confirmed [41]). The Air Force Information Warfare Center's final technical analysis is dated 20 January 1995, as GAO cites it (Confirmed [41]). Air Force officials told GAO that at least one hacker "may have been working for a foreign country"; no state is named and the record does not establish it (Reported [41]). The [1994 chronicle](/case-studies/CHRONICLE_1994.md) is the home for the intrusions themselves.

### The Harvard intruder

In late August 1995 the Naval Command, Control and Ocean Surveillance Center (NCCOSC) detected an intrusion into its network of sensitive but unclassified research files, and traced it to a host at Harvard's Faculty of Arts and Sciences (FAS) (Confirmed [16]). The 1998 release says Defense detected the intrusions in summer 1995 (Confirmed [17]). The intruder used stolen accounts on the Harvard host, which had about 16,500 accounts, as a base, captured passwords with intercepting programs, and reached the Naval Research Laboratory, NASA's Jet Propulsion Laboratory and Ames Research Center, Los Alamos and NCCOSC; he tried without success to enter the Army Research Laboratory, and he was not accused of obtaining classified information (Confirmed [16]).

A federal judge in Boston authorized a wiretap of the Harvard host for the last two months of 1995. NCIS and the FBI ran it, and the Justice Department called it the first court-ordered wiretap on a computer network (Confirmed [16]). It identified a 21-year-old in Buenos Aires using the handle "griton". Acting on information from Telecom Argentina, Argentine authorities seized his files and equipment on 28 December 1995 (Confirmed [16]). The complaint against Julio Cesar Ardita was announced on 29 March 1996 (Confirmed [15][16]). GAO's account says an attacker from Argentina went through a US university system into the Naval Research Laboratory, other Defense installations, NASA and Los Alamos "in 1995 and 1996", and that the Navy could not determine what was compromised (Confirmed [40][41]).

Ardita returned to Boston voluntarily, because the extradition treaty did not allow his extradition, and pleaded guilty on 19 May 1998 to intercepting communications over a military computer and damaging files on a second; the parties jointly recommended three years' probation and a $5,000 fine (Confirmed [17]). The record presents him as an individual intruder, not a state actor (Confirmed [16]).

### The Defense response

GAO records that Defense named information systems security a system weakness in its fiscal 1995 Annual Statement of Assurance; that the Navy set up its Fleet Information Warfare Center in 1995, asking for 30 positions and receiving 3; and that Defense's December 1995 Defensive Information Warfare Management Plan set out a protect, detect and react approach (Confirmed [40]). Between January and June, at the request of OSD C3I, RAND ran "The Day After..." exercises in which an adversary attacked banks, rail, telephones and military systems in a year-2000 scenario, including attacks on bank ATMs and a logic bomb misrouting a freight train; the exercises found no adequate tactical warning system to tell information-warfare attacks from accidents (Confirmed [41][40]). It was an exercise, not an incident (Confirmed [40]).

## Part 4: crime and prosecutions

### The Christmas Day intrusion and the arrest (summary)

Tsutomu Shimomura's Usenet post of 25 January 1995 says the attack on his systems began about 14:09:32 PST on 25 December 1994, used IP source address spoofing and TCP sequence-number prediction to reach a diskless X-terminal workstation, and then hijacked an existing connection with a loadable kernel STREAMS module; he had presented it at CMAD 3 on 11 January (Confirmed [4]). On 15 February the Justice Department announced that FBI agents and the Raleigh-Durham Fugitive Task Force had arrested Kevin Mitnick at 1:30 a.m. after a two-week electronic manhunt, on a probation violation, alleging attacks on corporations and communications carriers in California, Colorado and North Carolina, with the San Diego Supercomputer Center and Shimomura assisting (Confirmed [5][6]). He later received 22 months for the cloned phones found at that arrest and for violating supervised release, and on 9 August 1999 46 months on wire fraud, computer fraud and interception counts (Confirmed [31]). The [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) is the home for all of it.

### The cash-management transfers (summary)

The FBI says its case began in July 1994, when a major US bank's cash-management system was accessed with compromised valid user IDs and passwords over the telecommunications network; about 40 illegal transfers between late June and October 1994 came to more than $10 million, and the hack "didn't involve the Internet" (Confirmed [10]). In March 1995 Vladimir Levin was lured to London, arrested and later extradited; he pleaded guilty in January 1998 (Confirmed [10]). The case agent joined San Francisco's newly formed computer intrusion squad in 1995 (Confirmed [10]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home and grades its own arrest date Reported; the FBI history confirms the month.

### Operation Cybersnare

On 11 September the US Attorney in New Jersey and the Secret Service announced Operation Cybersnare: an undercover agent had run a bulletin board called "Celco 51" in Bergen County since January, and the seven-state investigation led to six arrests and the seizure of more than 20 computer systems (Confirmed [25]). The targets allegedly trafficked in stolen cellular telephone ESN and MIN data, cloning equipment and stolen credit card data, and two were charged with conspiring to break into an Oregon cellular carrier's computer system; the release calls it the first successful sting of its kind (Confirmed [25]). It also says intruders had in recent years broken into carriers' systems to steal blocks of ESN and MIN pairs for cloning phones (Confirmed [25]). The defendants' outcomes were not checked, so they are not named here.

### Agent Steal

Justin Tanner Petersen, "Agent Steal", pleaded guilty on 27 March 1995 to conspiracy to commit computer and wire fraud committed while a fugitive, including an attempted $150,000 wire transfer from Heller Financial; on 27 November he was sentenced to 41 months, three years of supervised release and about $40,000 restitution, with an enhancement for the special skill of his computer abilities, and the Ninth Circuit affirmed on 22 October 1996 (Confirmed [29]). The *Los Angeles Times* called the term the second-stiffest sentence ever for similar crimes and recalled that he had earlier rigged Los Angeles radio-station phone lines with Kevin Poulsen (Reported [30]).

### An insider and an appeal

On 18 December Richard Czubinski, a former IRS employee, was convicted in Boston on nine wire-fraud and four computer-fraud counts for browsing confidential taxpayer records (Confirmed [27]). In February 1997 the First Circuit reversed every count for insufficient evidence, holding that unauthorized browsing alone did not meet the wire and computer fraud statutes (Confirmed [28]).

### The mail bomb

A Monmouth University student was charged under 18 U.S.C. 1030(a)(5) after an e-mail bomb of about 24,000 messages, sent on 20 November, crashed the university's mail system; the charge was announced on 28 November (Confirmed [26]).

### Law for the next cases

On 29 June the Justice Department announced that the Administration and Senators Kyl, Leahy and Grassley had introduced computer crime legislation defining a "protected computer", citing CERT's growth figures (Confirmed [12]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) covers the computer-fraud amendments of the period.

### Anonymity under legal pressure

The operator of anon.penet.fi, a Finnish anonymous posting service, issued a statement dated 20 February and posted 21 February saying that the Church of Scientology, helped by Finnish police, had obtained the identity of a person who had posted material about the Church anonymously (Confirmed [7]). A secondary history says Church lawyers used Interpol and the Finnish police in early February and that the operator revealed the account under a search warrant on 8 February (Reported [8]). It is an early record of a legal demand, rather than an intrusion, unmasking an online pseudonym (Inferred).

### Protest by page load

Strano Network's call for the first "Net'Strike" asked participants to load French government sites, and the OECD Nuclear Energy Agency, repeatedly from 6 to 7 p.m. French time on 21 December, in protest at French nuclear testing (Confirmed [46]). Its actual effect was not verified from any primary record (Confirmed [46]). It is a forerunner of the mass-request protests later called hacktivist denial of service (Inferred).

## Part 5: viruses and the move to documents

### Concept

*Virus Bulletin*'s September 1995 analysis of Winword.Concept, written by Sarah Gordon, describes the first Word macro virus seen spreading: it adds itself to Word templates through auto-run macros, uses the global template NORMAL.DOT, works on any platform where Microsoft Word runs, and carries no destructive payload (Reported [18]). The analysis says the virus abuses Word's auto-open macro and the lack of any privilege concept, so the advice that "you cannot get a virus by reading your mail" no longer holds for mail clients that use Word; the editorial in the same issue raises scanning .DOC and .DOT files (Reported [18]).

### Concept on trusted media

*Virus Bulletin* reported three distributions of Concept on media from known vendors within weeks (Reported [19][20]):

- A ServerWare CD, "Snap-On Tools for Windows NT Professional", carrying infected documents and shipped to more than 5,500 Windows NT users at the end of September (Reported [19]).
- Microsoft's "Windows 95 Software Compatibility Test" CD, version 4.0, sent to OEMs; *Virus Bulletin* reports that Microsoft admitted shipping the virus on it (Reported [19]).
- A Digital Equipment Corporation disk handed to delegates at the DECUS conference in Dublin in the second week of September (Reported [20]).

### The second macro virus and the count

In mid-September a second Word macro virus, Nuclear, turned up on an FTP site inside an archive that posed as a Microsoft information file about Concept (Reported [20]). Concept appears in *Virus Bulletin*'s prevalence tables at 5 of 138 reports in August, 6 in October and 12 in November (Reported [19][20]). The WildList, which counts only positively identified samples and shows which viruses are in the wild rather than how common they are, charted Winword.Concept from five participants in September and fixed its CARO name as Concept in October with nine participants (ten in November) (Confirmed [24]).

### The Black Baron sentenced

Christopher Pile, the "Black Baron", wrote the SMEG polymorphic engine and the Pathogen and Queeg viruses (Reported [21][22]). *Virus Bulletin*'s accounts say he pleaded guilty at Plymouth Crown Court in May to ten charges under Sections 2 and 3 of the Computer Misuse Act and one of incitement, and that on 15 November at Exeter Crown Court he received six months concurrent on the ten counts and twelve months consecutive for incitement, eighteen months in all (Reported [21][22]). It is described as the first custodial sentence in the United Kingdom for writing and distributing viruses, and Microprose put its own costs above GBP 250,000 (Reported [23][21]).

## Part 6: cryptography breaks and the first browser bounty

### Export-grade SSL falls

US export rules limited the SSL encryption Netscape could ship abroad to 40-bit keys (Inferred from [32]). On 14 July, by Damien Doligez's own chronology, Hal Finney posted a challenge: a recorded Netscape session encrypted with RC4-128-EXPORT-40 (Reported [35]). Doligez found the key on about 120 workstations and a few parallel computers at INRIA, Ecole Polytechnique and ENS, after scanning a little more than half the keyspace in 8 days, and announced it on 15 August; the Bugtraq forward of his announcement is dated 16 August (Demonstrated [35][14]). David Byers and Eric Young, working with Adam Back, had broken it about two hours earlier, by Doligez's account (Reported [35]). Netscape's official response of 17 August, as Doligez records it, estimated the cost of a break at about $10,000, a figure he disputes (Reported [35]). A volunteer ring organized by Back and Piete Brooks broke a second challenge in under 32 hours from 24 August (Reported [35]). Goldberg and Wagner later wrote that several researchers recovered such traffic "in as few as 30 hours" on spare CPU time and that export rules made the weakness unfixable (Reported [32]).

### Netscape's random seed

On 17 September Ian Goldberg and David Wagner announced that Netscape's SSL session keys could be predicted (Demonstrated [33][32]). Their *Dr. Dobb's Journal* article shows that Navigator 1.1 seeded its random number generator from the time of day, the process ID and the parent process ID, which made both 40-bit and 128-bit keys predictable; it was tested on UNIX versions, and Netscape confirmed the Windows and Mac versions were affected (Confirmed [32]). Wagner's sci.crypt post of 20 September says the seed had no more than 47 bits of entropy and that an attacker with a local account could break a session in about a minute on one machine (Demonstrated [34]). Netscape fixed it in the Navigator 1.22 Security Update and 2.0 beta1 (Confirmed [32]). The authors' lesson was that security code needs outside peer review (Confirmed [32]).

### Timing attacks

On 10 December Paul Kocher released a preliminary paper showing that secret keys can be recovered by measuring how long cryptographic operations take, with attacks on RSA, fixed-exponent Diffie-Hellman and DSS; he released the draft early to alert the community (Demonstrated [39]). Timing is one of the side channels defenders still have to manage in cryptographic code (Inferred).

### The Bugs Bounty

An Edupage digest of 12 October, citing the *Wall Street Journal* of 11 October and relayed to Bugtraq, reports that Netscape announced a "Bugs Bounty" paying $1,000 to the first person to find a major security bug in the new beta of its browser (Reported [36][37]). The *Wall Street Journal* of 11 December reported that Netscape had paid two finders $1,000 each and given gifts to 50 other contestants (Reported [38]). Kocher's own post says Netscape awarded him a $1,000 bugs bounty prize (Confirmed [39]), and Goldberg replied on 18 December that he and Wagner had received nothing from Netscape for the seed finding (Reported [38]). The library's [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) dates bug bounties from the Zero Day Initiative in 2005; this record is ten years earlier (Demonstrated [93]).

### Export controls in court

On 21 February (the date the archive file is named for; the copy opened has a blank date line, Inferred) a UC Berkeley graduate student, with the Electronic Frontier Foundation, filed *Bernstein v. United States Department of State*, N.D. Cal. No. C 95-0582-MHP, challenging the licensing of his Snuffle encryption paper and program under the Arms Export Control Act and ITAR as a prior restraint under the First Amendment, with Fifth Amendment and APA claims (Confirmed [9]). It is the policy setting for the 40-bit breaks later in the year (Inferred).

## Part 7: the state and intelligence record

### No state intrusion campaign on the record

No government, court or vendor record opened attributes a 1995 intrusion to a state (Inferred). The library's ATT&CK v20 data has no group, software or campaign activity in 1995: the earliest campaign first_seen is C0002 Night Dragon in November 2009, and no group description dates activity before 2004 (Confirmed [91]). ATT&CK dates Turla ([G0010](/mitre/groups/G0010.md)), which it attributes to Russia's FSB, from "at least 2004" and does not mention the 1990s (Confirmed [48]). Its Equation entry ([G0020](/mitre/groups/G0020.md)) gives no start year and names no sponsor (Confirmed [49]); Kaspersky says some Equation command-and-control domains were registered as early as 1996 (Reported [57]). Kaspersky and King's College London date Moonlight Maze to 1996, with samples back to late 1996, and call a Turla link circumstantial (Reported [58]); the National Security Archive's index lists no 1995 item and begins Moonlight Maze with a Navy incident report of 10 October 1996 (Reported [59]). The [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) and the [tool leaks study](/case-studies/NSA_CIA_TOOL_LEAKS.md) are the homes for those groups.

### Russia's FSB law

Federal Law No. 40-FZ "On the Federal Security Service" was adopted by the State Duma on 22 February 1995 and is dated 3 April 1995, the legal founding of the FSB; the Council of Europe translation opened is of the law as amended to 2011 (Confirmed [47]).

### Venona

On 11 July, at CIA Headquarters, Director of Central Intelligence John Deutch released the first 49 Venona translations, 1940s Soviet KGB and GRU messages on atomic-bomb espionage, with more than 2,200 to follow and the next release set for September (Confirmed [52]).

### Crypto AG

In December the *Baltimore Sun* ran a series on the NSA; a 10 December story suggested the NSA helped rig Crypto AG cipher machines sold to foreign governments, and Crypto AG denied it (Reported [50]). The *Washington Post*'s 2020 account, drawing on a CIA history, says the CIA and West Germany's BND had bought Crypto AG in June 1970, the CIA bought out the BND share on 9 September 1993, Iran had detained a Crypto AG salesman in 1992, and the 1995 series led at least half a dozen countries, among them Argentina, Italy, Saudi Arabia, Egypt and Indonesia, to cancel or suspend contracts while Iran resumed purchases (Reported [51]).

### France and economic espionage

On 22 February *Le Monde* reported France's request that five Americans, four of them diplomats, leave the country over alleged political and economic espionage; US officials blamed the Interior Minister for making it public (Reported [53]). The *Christian Science Monitor* reported that French trade-talk and telecommunications positions were the main targets, and that the CIA had warned 49 US defense firms in 1993 that French intelligence was seeking their technology (Reported [54]). No computer or telecom intrusion is described (Reported [53]).

### Doctrine

The US Air Force paper "Cornerstones of Information Warfare", signed by General Fogleman and Secretary Widnall, defines information warfare as any action to deny, exploit, corrupt or destroy the enemy's information and its functions (Confirmed [55]); the archived PDF carries no printed date, and *Air Force Magazine* says it appeared in 1995 (Reported [56]). PDD-39, "U.S. Policy on Counterterrorism", a Secret directive of 21 June 1995, has parts on reducing US vulnerabilities, deterrence, response and weapons of mass destruction (Confirmed [67]). Under it, the Attorney General chaired a Cabinet Committee that reviewed the vulnerability of critical national infrastructure to terrorism, including electronic "cyber" attacks; her memo on that group is dated 14 March 1996, and the working group should not be dated to 1995 (Confirmed [68]).

## Part 8: the government record

### Law

| Date | Instrument | What it does | Grade | Sources |
|---|---|---|---|---|
| 22 May 1995 | Paperwork Reduction Act of 1995, Pub. L. 104-13 | 44 U.S.C. 3504(g) and 3506(g): OMB and every agency identify and afford security protections commensurate with the risk and magnitude of harm, consistent with the Computer Security Act of 1987 | Confirmed | [63] |
| 29 Jun 1995 | Computer crime bill (Administration with Senators Kyl, Leahy and Grassley) | Defines a "protected computer" | Confirmed | [12] |
| 24 Oct 1995 | EU Directive 95/46/EC (OJ L 281, 23 Nov 1995) | Article 17 requires appropriate technical and organizational security measures, notably for network transmission; Article 32 gives member states three years to comply | Confirmed | [60] |
| 21 Feb 1995 | *Bernstein v. Department of State* complaint | Challenges export licensing of encryption source code | Confirmed (date Inferred) | [9] |

### Standards

| Date | Standard | Content | Grade | Sources |
|---|---|---|---|---|
| Feb 1995 | RFC 1760 (Bellcore) | S/KEY one-time passwords: only a single-use password crosses the network | Confirmed | [78] |
| Feb 1995 | NIST SP 800-11 | FCC Open Network Architecture and national security emergency preparedness telecom security; later withdrawn | Confirmed | [65] |
| 15 Feb 1995 | BS 7799-1:1995 (BSI committee IST/33) | Information security management code of practice; withdrawn 15 May 1999 when superseded by BS 7799-1:1999 | Confirmed | [82] |
| 17 Apr 1995 | FIPS 180-1 | SHA-1, a revision of FIPS 180 (11 May 1993) adding a circular left shift that NIST says improves security; required with DSA; effective 2 October 1995; withdrawn 1 August 2002 | Confirmed | [61][62] |
| Aug 1995 | RFC 1825 to RFC 1829 | Security Architecture for IP (IPv4 and IPv6; IPv6 hosts must implement AH with keyed MD5), AH, ESP, keyed MD5, ESP DES-CBC; RFCs 1851 and 1852 followed as experimental in September | Confirmed | [66] |
| Oct 1995 | RFC 1858 | IP fragmentation can hide TCP packets from router and host filters; two attack methods and their remedies | Confirmed | [79] |
| Oct 1995 | RFC 1847, RFC 1848, RFC 1864 | Security multiparts for MIME, MIME Object Security Services, the Content-MD5 header | Confirmed | [80] |
| Oct 1995 | NIST SP 800-12, "An Introduction to Computer Security: The NIST Handbook" | Withdrawn 22 June 2017, superseded by Rev. 1 | Confirmed | [64] |
| Oct 1995 | NIST SP 800-13 | Telecommunications security guidelines for telecommunications management networks; later withdrawn | Confirmed | [65] |

## Part 9: the defender view

**Encrypt the session, not just the password (Inferred from [77][78][66]).** SSH 1.0, announced by Tatu Ylonen on 12 July, replaced rlogin, rsh and rcp with RSA host and user authentication, automatic encryption and X11 and port forwarding, and was aimed explicitly at IP, DNS and routing spoofing and password sniffing (Confirmed [77]). S/KEY answered sniffing for sites that kept cleartext protocols (Confirmed [78]), and the August IPsec RFCs set out security at the IP layer itself (Confirmed [66]). CA-95:01's warning that session hijacking bypassed one-time passwords showed why a one-time password alone was not enough (Confirmed [3]; Inferred).

**Filter forged addresses at the border.** CERT's remedy for spoofing was inbound and outbound source-address filtering at the external router (Confirmed [3]). RFC 1858 in October warned that IP fragments could carry TCP packets past such filters (Confirmed [79]).

**Detect the scan.** CIAC announced Courtney the day SATAN was released (Confirmed [69]), and Purdue's COAST archive lists NATAS, Gabriel and a COAST port-scan detector among the year's SATAN detectors (Confirmed [71]). CERT noted that scans show as heavy sweeps of ports and services in a short time and that many daemons log too little to see them (Confirmed [1]).

**Fix defaults and builds, not just code.** SGI's password-less accounts and the Linux wu-ftpd builds were shipped configurations, and CERT's fixes were passwords and rebuilt binaries (Confirmed [1]).

**Watch the documents.** Concept's spread on vendor media meant scanners had to look inside documents and templates (Reported [18][19]).

**Manage security as a program.** BS 7799 and the NIST handbook gave organizations a code of practice and a reference text in the same year (Confirmed [82][64]); the Paperwork Reduction Act required protections commensurate with risk, and the EU directive required appropriate technical and organizational security measures (Confirmed [63][60]).

**Assume you will not see most attacks.** DISA's tests found about 4 percent of successful intrusions detected (Confirmed [41]); the Harvard case came to light when a Navy center detected an intrusion in late August and traced it (Confirmed [16]).

## Part 10: MITRE mappings

No 1995 record carries an ATT&CK, CAPEC or CWE id: CVE began in 1999, MITRE began categorizing weaknesses alongside it and released the first CWE in 2006, CAPEC was first released in 2007, and the first ATT&CK model was built in September 2013 and released publicly in May 2015 with 96 techniques; the D3FEND site names the NSA as its sponsor (Confirmed [72][83][84][85][86]). Every binding below is therefore this study's later mapping (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `technique_to_d3fend.jsonl`, `campaigns.jsonl`, `data/weaknesses/cwe.jsonl`, `capec.jsonl`) and the generated pages under `mitre/` on 12 November 2026 (Demonstrated [87][88][89][90][91][92]). Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md): **Described** means a primary source describes the behavior and this study assigns the id; **Reported** means only a secondary source supports the behavior; **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading. No row is **Listed**, because no 1995 source prints an id.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | reconnaissance | Described | CA-95:18 automated scanning for NFS and NIS weaknesses, 18 Dec; SATAN released 5 Apr, which CERT expected to be used to find vulnerable hosts | [1][69] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Described | SATAN probes finger, NFS, NIS, ftp and rexd (CA-95:06, 3 Apr); CA-95:18 scanning | [1][70] |
| [`T1563`](/mitre/techniques/T1563.md) | Remote Service Session Hijacking | lateral-movement | Described | CA-95:01, 23 Jan: tool takes over open terminal and login sessions; the 25 Dec 1994 hijack published 25 Jan. The [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) binds it too | [3][4] |
| [`T1547.006`](/mitre/techniques/T1547-006.md) | Kernel Modules and Extensions | persistence, privilege-escalation | Described | CA-95:01: the session tool modifies the SunOS 4.1.x kernel; Shimomura's loadable kernel STREAMS module | [3][4] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | CA-95:18 packet sniffers, 18 Dec; the Harvard intruder's password-intercepting programs, Aug to Dec | [1][16] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Stolen Harvard FAS accounts used against Navy, NASA and Los Alamos systems, Aug to Dec; the 1994 cash-management transfers through compromised user IDs (arrest Mar 1995) | [16][10] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Default Accounts | stealth, persistence, privilege-escalation, initial-access | Described | CA-95:15, 8 Nov: SGI IRIX lp and other accounts shipped without passwords, known to intruders | [1] |
| [`T1090.003`](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | command-and-control | Inferred | The Harvard host used as a base for intrusions elsewhere (a weak tie: the record describes staging, not a proxy chain) | [16] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | CA-95:04 NCSA httpd (17 Feb), CA-95:05 sendmail IDENT (22 Feb), CA-95:08 sendmail v5 (17 Aug), CA-95:16 wu-ftpd (30 Nov), CA-95:17 rpc.ypupdated (12 Dec) | [1] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Inferred | rpc.ypupdated and NFS weaknesses exploited across sites in the December wave | [1] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | CA-95:10, 31 Aug: a booby-trapped PostScript file executes commands through ghostscript | [1] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Described | CA-95:02 /bin/mail (26 Jan), CA-95:09 ps (29 Aug), CA-95:11 sendmail -oR (19 Sep), CA-95:12 loadmodule (18 Oct), CA-95:13 syslog (19 Oct) | [1] |
| [`T1574.006`](/mitre/techniques/T1574-006.md) | Dynamic Linker Hijacking | stealth, execution | Inferred | CA-95:14, 1 Nov: telnetd environment option on systems with shared libraries (the advisory text opened does not spell out the linker mechanism) | [1] |
| [`T1554`](/mitre/techniques/T1554.md) | Compromise Host Software Binary | persistence | Described | CA-95:18 Trojan horse programs installed after root | [1] |
| [`T1137.001`](/mitre/techniques/T1137-001.md) | Office Template Macros | persistence | Reported | Concept adds itself to Word templates, including NORMAL.DOT, through auto-run macros, Sep | [18] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Reported | Concept runs when a user opens an infected document, including documents on shipped CDs and disks, Sep | [18][19][20] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Inferred | Net'Strike call for repeated loading of French government sites, 21 Dec (effect not verified) | [46] |
| [`T1499`](/mitre/techniques/T1499.md) | Endpoint Denial of Service | impact | Inferred | About 24,000 e-mail messages crash Monmouth University's mail system, 20 Nov | [26] |

Left out on purpose: the 40-bit SSL brute force, the Netscape seed prediction and Kocher's timing attacks, which are cryptanalysis against keys rather than adversary behavior ATT&CK models (T1110 Brute Force covers guessing account credentials, not session keys); the Cybersnare intrusion charge and the Czubinski browsing case, whose records give no technique detail beyond access; the anon.penet.fi disclosure, a legal process; and Pile's viruses, which *Virus Bulletin* describes by engine and name without a delivery path the record confirms (Inferred).

### ATT&CK for ICS techniques

None. No 1995 intrusion into an industrial control system appears in any primary opened; the closest record is the Cybersnare release on carriers' computer systems, which concerns telephone accounts, not control systems (Confirmed [25]; Inferred). No ICS layer is published.

### ATT&CK groups, software and campaigns

None. ATT&CK records no group, software or campaign activity in 1995: the earliest campaign in the library's v20 data begins in November 2009, and no group description dates activity before 2004 (Confirmed [91]). Turla ([G0010](/mitre/groups/G0010.md)) and Equation ([G0020](/mitre/groups/G0020.md)) are named in Part 7 only to show that their recorded histories begin after 1995 (Confirmed [48][49]). Ardita, Pile, Concept, Nuclear, SATAN and the December wave's toolkit have no ATT&CK objects (Inferred [91]).

### CWE and CAPEC

No 1995 record lists a CWE: the 25 back-dated NVD records carry NVD-CWE-Other (Demonstrated [73]). Every row below is this study's binding (Inferred). The CAPEC column says which pairings the library's data makes and which are this study's own [88][89].

| CWE | Weakness (library name) | 1995 record | CAPEC |
|---|---|---|---|
| CWE-290, CWE-291, CWE-940 | Authentication Bypass by Spoofing; Reliance on IP Address for Authentication; Improper Verification of Source of a Communication Channel | CA-95:01 address-based trust; the June spoofing wave | [CAPEC-151](/mitre/capec/CAPEC-151.md) Identity Spoofing (the library relates it to CWE-287); [CAPEC-324](/mitre/capec/CAPEC-324.md) TCP (ISN) Sequence Predictability Probe (the library relates it to CWE-200); [CAPEC-94](/mitre/capec/CAPEC-94.md) Adversary in the Middle (AiTM) (the library relates it to CWE-290 and T1557); [CAPEC-593](/mitre/capec/CAPEC-593.md) Session Hijacking (the library relates it to T1563) |
| none bound | (sniffing) | CA-95:18 packet sniffers; the Harvard password interception | [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (the library relates it to T1040) |
| none bound | (scanning) | SATAN; CA-95:18 scanning | [CAPEC-310](/mitre/capec/CAPEC-310.md) Scanning for Vulnerable Software (this study's pairing); [CAPEC-300](/mitre/capec/CAPEC-300.md) Port Scanning (the library relates it to T1046) |
| CWE-120 | Buffer Copy without Checking Size of Input | CA-95:04 NCSA httpd (NCSA calls it a buffer overflow); CA-95:13 syslog | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers (the library relates it to CWE-120) |
| CWE-367, CWE-379 | Time-of-check Time-of-use (TOCTOU) Race Condition; Creation of Temporary File in Directory with Insecure Permissions | CA-95:09 Solaris ps in /tmp; CA-95:02 /bin/mail timing windows | [CAPEC-29](/mitre/capec/CAPEC-29.md) Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions (the library relates it to CWE-367); [CAPEC-149](/mitre/capec/CAPEC-149.md) Explore for Predictable Temporary File Names (the library relates it to CWE-377) |
| CWE-454 | External Initialization of Trusted Variables or Data Stores | CA-95:14 telnetd environment option | [CAPEC-13](/mitre/capec/CAPEC-13.md) Subverting Environment Variable Values (the library relates it to T1574.006) |
| CWE-258, CWE-1188 | Empty Password in Configuration File; Initialization of a Resource with an Insecure Default | CA-95:15 SGI IRIX accounts without passwords | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords (the library relates it to T1078.001) |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | Concept and Nuclear | [CAPEC-562](/mitre/capec/CAPEC-562.md) Modify Shared File (this study's pairing; the library relates it to CWE-284 and T1080) |
| CWE-337, CWE-338, CWE-330 | Predictable Seed in Pseudo-Random Number Generator (PRNG); Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG); Use of Insufficiently Random Values | Netscape seed from time, process ID and parent process ID | [CAPEC-59](/mitre/capec/CAPEC-59.md) Session Credential Falsification through Prediction (the library relates it to CWE-290 and CWE-330); [CAPEC-485](/mitre/capec/CAPEC-485.md) Signature Spoofing by Key Recreation (the library relates it to CWE-330) |
| CWE-326 | Inadequate Encryption Strength | 40-bit export SSL challenges | [CAPEC-20](/mitre/capec/CAPEC-20.md) Encryption Brute Forcing (the library relates it to CWE-326) |
| CWE-208 | Observable Timing Discrepancy | Kocher's timing attacks | No clean CAPEC fit in the library's data; none is assigned |

### D3FEND countermeasures

Pairings come from `data/attack/technique_to_d3fend.jsonl` unless the row says the pairing is this study's; every page exists under `/mitre/d3fend/` (Demonstrated [90][92]).

| Technique from the record | D3FEND countermeasures | 1995 analogue |
|---|---|---|
| T1563 Remote Service Session Hijacking | [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md), [Session Termination](/mitre/d3fend/session-termination.md) (library pairings). [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) and [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) are concept matches for CERT's spoofing remedy | CA-95:01 source-address filtering at the external router; netlog [3] |
| T1040 Network Sniffing | The library maps only [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md). [One-time Password](/mitre/d3fend/one-time-password.md) and [Message Encryption](/mitre/d3fend/message-encryption.md) are concept matches the library does not map to T1040 | S/KEY (RFC 1760); SSH 1.0 [78][77] |
| T1078 Valid Accounts and T1078.001 Default Accounts | [Change Default Password](/mitre/d3fend/change-default-password.md), [Account Locking](/mitre/d3fend/account-locking.md) (library pairings) | SGI's documentation already advised setting passwords on the shipped accounts [1] |
| T1190 and T1210 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (library pairing for T1190) and [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (library pairing for both) | Vendor patches and upgrades named in each advisory [1] |
| T1068 and T1203 | The library's pairings are memory-safety hardenings, such as [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) and [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md); none is recorded in the 1995 advisories, whose fixes were patches and upgrades (Inferred) | ghostscript 4.01 with -dSAFER on by default; sendmail 8.6.12 and 8.7.1 [1] |
| T1574.006 Dynamic Linker Hijacking | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Local File Permissions](/mitre/d3fend/local-file-permissions.md), [System File Analysis](/mitre/d3fend/system-file-analysis.md) (library pairings) | Updated telnet daemons [1] |
| T1554 Compromise Host Software Binary | [Software Update](/mitre/d3fend/software-update.md) and the library's other pairings | CA-95:18's recovery advice and incident reporting form [1] |
| T1547.006 Kernel Modules and Extensions | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Local File Permissions](/mitre/d3fend/local-file-permissions.md) (library pairings) | No 1995 counterpart in the record |
| T1090.003 Multi-hop Proxy | [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md), [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (library pairings) | The court-ordered wiretap on the Harvard host [16] |
| T1137.001 Office Template Macros and T1204.002 Malicious File | [File Analysis](/mitre/d3fend/file-analysis.md), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md), [Emulated File Analysis](/mitre/d3fend/emulated-file-analysis.md), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (library pairings) | Scanning .DOC and .DOT files, as *Virus Bulletin*'s editor urged [18] |

The library's data has no D3FEND pairing for T1595.002, T1046, T1498 or T1499, and none is invented here (Demonstrated [90]).

### Navigator layer

The study's techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-1995.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1995.json), listing the 18 techniques in the Enterprise table under each tactic they carry in v20.0, and listed on [the Navigator layers page](/navigator/index.md) (Demonstrated [94]). Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping; no entry scores 100, because no 1995 source prints an id. Each entry's comment names the source numbers in the Sources table below. No ICS layer is needed.

## Cross-cutting themes

**Trust by address broke, first on hosts and then on the network itself.** CA-95:01 in January, the June heads-up on spoofing against routers and name servers and the December wave all used the same weakness (Confirmed [3][13][1]). SSH, S/KEY and IPsec arrived the same year (Confirmed [77][78][66]).

**Automation changed the economics of attack.** A public scanner in April, published exploit scripts for local root through the autumn and automated scanning in December made known flaws dangerous on a schedule set by attackers rather than by patch cycles (Confirmed [1][69]; Inferred). The same pattern runs through the [Log4Shell](/case-studies/LOG4SHELL.md) and [Cl0p file transfer](/case-studies/CL0P_FILE_TRANSFER_2023.md) studies decades later (Inferred).

**Trusted distribution carried malicious code.** Concept arrived on CDs and disks from a software vendor, an operating system maker's test kit and a computer maker's conference handout (Reported [19][20]). The supply-chain class recurs in the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies (Inferred).

**Commerce's cryptography was tested by volunteers.** The export-grade, seed and timing breaks all came from researchers and students working in public, and the first browser bounty followed (Demonstrated [14][32][39]; Reported [36]).

**The law caught up one case at a time.** The first computer-network wiretap, a protected-computer bill, a reversed insider conviction and the first UK prison sentence for virus writing all date to 1995 or arise from it (Confirmed [16][12][28]; Reported [21]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: "250,000 attacks on the Pentagon in 1995".** It is DISA's extrapolation from test detection rates; the officially reported count was 559 [40][41]. GAO's own text gives about 1 in 150 detected and reported [40].
- **Overstated: the 1995 SSL breaks as attacks on shoppers.** Doligez and the volunteer ring broke published challenge transcripts, and Goldberg and Wagner showed predictability in a version that Netscape fixed; no record opened shows live customer transactions decrypted [35][32].
- **Overstated: Concept "on the Windows 95 CD".** *Virus Bulletin* places it on a compatibility-test CD sent to OEMs, a ServerWare CD and a DEC conference disk, not on the retail product [19][20].
- **Overstated: Mitnick as the year's defining intrusion.** The Justice Department's arrest release charges a probation violation and alleges attacks on companies and carriers; the year's larger events in the record are the spoofing campaign and the December wave [5][13][1].
- **Overstated: Rome Laboratory or Moonlight Maze as 1995 state operations.** Rome was 1994 and its foreign link rests on officials' "may have been" [41]; Moonlight Maze's earliest dates are 1996 [58][59].
- **Overstated: "first" claims.** The first computer-network wiretap and the first sting of its kind are the Justice Department's and the US Attorney's own descriptions [16][25]; "first UK custodial sentence" for virus writing rests on *Virus Bulletin* [23].
- **Overstated: CVE records dated 1995.** NVD's 25 records with 1995 dates were back-filled after CVE began in 1999, and CVE-1999-1080 has a 1995 date it cannot have [73][76].
- **Overstated: any ATT&CK, CWE or CAPEC id on a 1995 event.** None of those programs existed until 1999 to 2015 [72][83][84][85].
- **Understated: IP spoofing against infrastructure.** 170 attacks, with at least 80 of the known targets name servers, routers and other network operation systems, in a CERT heads-up sent to network operators rather than issued as a numbered advisory [13].
- **Understated: the December wave.** Hundreds of sites, many root compromises, all through already-advised flaws, and no home study before this one [1].
- **Understated: the Harvard case.** It began in August 1995, produced the first court-ordered wiretap on a computer network and surfaced only in March 1996 [16][15].
- **Understated: how little defenders saw.** About 4 percent of DISA's successful test intrusions were detected [41].
- **Understated: the bug bounty's age.** Netscape paid researchers in 1995, ten years before the library's earliest bounty record [38][39][93].
- **Understated: the year's state story is law, doctrine and signals intelligence.** The FSB law, Venona, Crypto AG, Cornerstones and the RAND exercises, not intrusions [47][52][50][55][41].

### Discrepancies in the record

- **Finney's challenge date.** 14 July in Doligez's chronology against 17 July in his announcement as forwarded to Bugtraq [35][14].
- **The 40-bit break.** Announced 15 August on cypherpunks, as the chronology and the Goldberg and Wagner reference list give it, against a Bugtraq copy dated 16 August [35][32][14].
- **Pile's sentence.** 15 November in the article text of *Virus Bulletin*'s December 1995 issue, 17 November on its cover, and a hearing set for 17 November in Bates's February 1996 account; ten Computer Misuse Act charges plus incitement in one account, eleven offences in another (the same count) [21][22][23].
- **The 1994 CERT incident count.** 2,341 in CERT's table as mirrored by ORNL against 2,340 in a reprint [44][45].
- **When the Harvard intrusions were detected.** "Late August 1995" in the 1996 release, "summer 1995" in the 1998 release and "in 1995 and 1996" in GAO's account [16][17][40].
- **The bounty payouts.** The WSJ reports two finders paid $1,000 each; Kocher's post says he received a $1,000 prize; Goldberg says he and Wagner received nothing [38][39].
- **The Bernstein filing date.** The date line on the complaint copy opened is blank; 21 February 1995 is the date its archive file is named for (Inferred) [9].
- **Cornerstones of Information Warfare.** No printed date on the archived PDF; *Air Force Magazine* gives 1995 [55][56].
- **The London arrest.** The FBI gives March 1995; the dot-com era study gives a day in March and grades it Reported [10].

## Sources

All sources were opened on 12 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers or answer them too slowly (the MIT mailing-list archive, the gao.gov pages, EUR-Lex and the NVD API queries); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "1995 CERT Advisories" (compilation, CA-1995-01 to CA-1995-18) | https://www.sei.cmu.edu/documents/502/1995_019_001_496168.pdf | 2026-11-12 | Confirmed |
| 2 | CMU SEI, "1995 CERT Advisories" (landing page) | https://www.sei.cmu.edu/library/1995-cert-advisories/ | 2026-11-12 | Confirmed |
| 3 | CERT/CC, CA-95:01 IP Spoofing Attacks and Hijacked Terminal Connections (NANOG distribution, January 1995) | https://seclists.org/nanog/1995/Jan/47 | 2026-11-12 | Confirmed |
| 4 | Tsutomu Shimomura, technical details of the attack, Usenet, 25 January 1995 | https://aeb.win.tue.nl/linux/hh/shimomura-25jan95.txt | 2026-11-12 | Confirmed |
| 5 | US Department of Justice, release #089, 15 February 1995 (Mitnick arrest) | https://www.justice.gov/opa/pr/Pre_96/February95/89.txt.html | 2026-11-12 | Confirmed |
| 6 | US Department of Justice, release #089, 15 February 1995 (archive copy) | https://www.justice.gov/archive/opa/pr/Pre_96/February95/89.txt.html | 2026-11-12 | Confirmed |
| 7 | anon.penet.fi operator, press release dated 20 February 1995 | https://spaink.net/cos/rnewman/anon/julf-press-rel.txt | 2026-11-12 | Confirmed |
| 8 | History of the anon.penet.fi case (secondary) | https://spaink.net/cos/rnewman/anon/penet.html | 2026-11-12 | Reported |
| 9 | *Bernstein v. US Department of State*, complaint, N.D. Cal. No. C 95-0582-MHP | https://eff.org/files/filenode/bernstein/950221.complaint.html | 2026-11-12 | Confirmed |
| 10 | FBI, "A Byte Out of History: $10 Million Hack, 1994-Style" (31 January 2014) | https://www.fbi.gov/news/stories/a-byte-out-of-history-10-million-hack | 2026-11-12 | Confirmed |
| 11 | Bugtraq post of 31 March 1995 on SATAN's release schedule | `https://diswww.mit.edu/menelaus/bt/1357` | 2026-11-12 | Reported |
| 12 | US Department of Justice, release of 29 June 1995 on computer crime legislation | https://www.justice.gov/archive/opa/pr/Pre_96/June95/370.txt.html | 2026-11-12 | Confirmed |
| 13 | CERT/CC, "Continued IP Spoofing Attacks" heads-up (29 June 1995, resent 21 July 1995), NANOG copy | `https://diswww.mit.edu/charon/nanog/21` | 2026-11-12 | Confirmed |
| 14 | Bugtraq forward, 16 August 1995, of Damien Doligez's signed announcement that the SSL challenge was broken | https://seclists.org/bugtraq/1995/Aug/45 | 2026-11-12 | Demonstrated |
| 15 | US Department of Justice, release 96-146, 29 March 1996 (Ardita complaint) | https://www.justice.gov/opa/pr/1996/March96/146.txt | 2026-11-12 | Confirmed |
| 16 | US Department of Justice, release 96-146, 29 March 1996 (FAS mirror) | https://irp.fas.org/news/1996/146.htm | 2026-11-12 | Confirmed |
| 17 | US Attorney, District of Massachusetts, release of 19 May 1998 (Ardita plea), FAS mirror | https://irp.fas.org/news/1998/05/arditasnt.htm | 2026-11-12 | Confirmed |
| 18 | *Virus Bulletin*, September 1995 (Winword.Concept analysis, Sarah Gordon; editorial) | https://www.virusbulletin.com/uploads/pdf/magazine/1995/199509.pdf | 2026-11-12 | Reported |
| 19 | *Virus Bulletin*, October 1995 (ServerWare and Microsoft CDs; August prevalence table) | https://www.virusbulletin.com/uploads/pdf/magazine/1995/199510.pdf | 2026-11-12 | Reported |
| 20 | *Virus Bulletin*, November 1995 (DECUS disk; Nuclear; prevalence tables) | https://www.virusbulletin.com/uploads/pdf/magazine/1995/199511.pdf | 2026-11-12 | Reported |
| 21 | *Virus Bulletin*, December 1995 (Pile sentence) | https://www.virusbulletin.com/uploads/pdf/magazine/1995/199512.pdf | 2026-11-12 | Reported |
| 22 | Jim Bates, "Regina v Christopher Pile: the inside story", *Virus Bulletin*, February 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199602-feature-JimBates.pdf | 2026-11-12 | Reported |
| 23 | *Virus Bulletin*, "Throwback Thursday: Regina v Christopher Pile" (April 2015 republication of the February 1996 article) | https://www.virusbulletin.com/virusbulletin/2015/04/throwback-thursday-regina-v-christopher-pile-inside-story-february-1996/ | 2026-11-12 | Reported |
| 24 | The WildList, October 1995 | https://www.virusbulletin.com/resources/wildlists/1995/10 | 2026-11-12 | Confirmed |
| 25 | US Attorney, District of New Jersey, release of 11 September 1995 (Operation Cybersnare), FAS mirror | https://irp.fas.org/news/1995/nj62_txt.html | 2026-11-12 | Confirmed |
| 26 | US Attorney, District of New Jersey, release of 28 November 1995 (Monmouth University mail bomb), FAS mirror | https://irp.fas.org/news/1995/nj139_txt.html | 2026-11-12 | Confirmed |
| 27 | US Attorney, District of Massachusetts, release of 18 December 1995 (Czubinski conviction), FAS mirror | https://irp.fas.org/news/1995/mass265.html | 2026-11-12 | Confirmed |
| 28 | *United States v. Czubinski*, 106 F.3d 1069 (1st Cir. 1997) | https://openjurist.org/106/f3d/1069 | 2026-11-12 | Confirmed |
| 29 | *United States v. Petersen*, 98 F.3d 502 (9th Cir. 1996) | https://law.justia.com/cases/federal/appellate-courts/F3/98/502/520959/ | 2026-11-12 | Confirmed |
| 30 | *Los Angeles Times*, 28 November 1995, on Petersen's sentence (archived reprint) | https://discmaster.textfiles.com/view/7506/hackers_encyclopedia.iso/etc/hacklaw/petersen.tx2 | 2026-11-12 | Reported |
| 31 | US Department of Justice, Computer Crime and Intellectual Property Section, Mitnick case page (UNT web archive) | https://webarchive.library.unt.edu/eot2008/20080916032623/http:/www.cybercrime.gov/mitnick.htm | 2026-11-12 | Confirmed |
| 32 | Ian Goldberg and David Wagner, "Randomness and the Netscape Browser", *Dr. Dobb's Journal*, January 1996 | https://people.eecs.berkeley.edu/~daw/papers/ddj-netscape.html | 2026-11-12 | Confirmed |
| 33 | Bugtraq forward, 18 September 1995, of Ian Goldberg's cypherpunks post of 17 September 1995 | `https://diswww.mit.edu/menelaus/bt/2251` | 2026-11-12 | Confirmed |
| 34 | David Wagner, sci.crypt post of 20 September 1995 on the Netscape break | https://people.eecs.berkeley.edu/~daw/my-posts/netscape-cracked | 2026-11-12 | Demonstrated |
| 35 | Damien Doligez, SSL challenge chronology | https://gallium.inria.fr/~doligez/ssl/ | 2026-11-12 | Demonstrated |
| 36 | Edupage, 12 October 1995, relayed to Bugtraq (Netscape Bugs Bounty, citing WSJ 11 October 1995) | https://seclists.org/bugtraq/1995/Oct/12 | 2026-11-12 | Reported |
| 37 | Edupage, 12 October 1995, relayed to Bugtraq 13 October 1995 (second archive) | `https://diswww.mit.edu/menelaus/bt/2304` | 2026-11-12 | Reported |
| 38 | Cypherpunks thread, 18 December 1995 (WSJ 11 December 1995 on bounty payouts; Goldberg's reply) | `https://diswww.mit.edu/menelaus/cpunks/45587` | 2026-11-12 | Reported |
| 39 | Paul Kocher, announcement of timing attacks, cypherpunks, 10 December 1995 | `https://diswww.mit.edu/menelaus/cpunks/45133` | 2026-11-12 | Confirmed |
| 40 | GAO/AIMD-96-84, "Information Security: Computer Attacks at Department of Defense Pose Increasing Risks" (govinfo HTML) | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-96-84/html/GAOREPORTS-AIMD-96-84.htm | 2026-11-12 | Confirmed |
| 41 | GAO/AIMD-96-84 (GAO PDF) | `https://www.gao.gov/assets/aimd-96-84.pdf` | 2026-11-12 | Confirmed |
| 42 | GAO, product page for AIMD-96-84 | `https://www.gao.gov/products/aimd-96-84` | 2026-11-12 | Confirmed |
| 43 | CERT/CC statistics page (Internet Archive copy, 31 December 2005) | http://web.archive.org/web/20051231042423/http://www.cert.org:80/stats/cert_stats.html | 2026-11-12 | Confirmed |
| 44 | CERT/CC statistics table, ORNL mirror (UNT web archive) | https://webarchive.library.unt.edu/eot2008/20080920153058/http:/www.csm.ornl.gov/~dunigan/certstats.txt | 2026-11-12 | Confirmed |
| 45 | CDRInfo, "CERT/CC Statistics 1988-2004" (reprint) | https://cdrinfo.com/d7/content/certcc-statistics-1988-2004 | 2026-11-12 | Reported |
| 46 | Strano Network, call for the Net'Strike of 21 December 1995 (nettime archive) | https://nettime.org/Lists-Archives/nettime-l-9601/msg00000.html | 2026-11-12 | Confirmed |
| 47 | Federal Law No. 40-FZ "On the Federal Security Service" (Council of Europe translation, as amended to 2011) | https://policehumanrightsresources.org/content/uploads/2016/08/Federal-Law-on-Federal-Security-Service-Russia-1995.pdf | 2026-11-12 | Confirmed |
| 48 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 49 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 50 | Interesting-People list, December 1995, summary of the *Baltimore Sun* NSA series | https://seclists.org/interesting-people/1995/Dec/43 | 2026-11-12 | Reported |
| 51 | *Washington Post* (Greg Miller, 11 February 2020), reprinted by the *Anchorage Daily News*, on Crypto AG | https://www.adn.com/nation-world/2020/02/11/intelligence-coup-of-the-century-how-the-cia-was-able-to-read-encrypted-messages-of-allies-and-adversaries-for-decades/ | 2026-11-12 | Reported |
| 52 | CIA, release of 11 July 1995 on the Venona translations (FAS mirror) | https://irp.fas.org/cia/news/pr71195.html | 2026-11-12 | Confirmed |
| 53 | *Washington Post*, 7 March 1995 (USIA wire copy, FAS mirror), on the French expulsion request | https://irp.fas.org/news/1995/22741615-22747425.htm | 2026-11-12 | Reported |
| 54 | *Christian Science Monitor*, 27 February 1995 | https://csmonitor.com/1995/0227/27013.html | 2026-11-12 | Reported |
| 55 | US Air Force, "Cornerstones of Information Warfare" (National Security Archive copy) | https://nsarchive.gwu.edu/sites/default/files/documents/4164297/United-States-Air-Force-Cornerstones-of.pdf | 2026-11-12 | Confirmed |
| 56 | John T. Correll, *Air Force Magazine* | https://www.airandspaceforces.com/article/1296edit/ | 2026-11-12 | Reported |
| 57 | Kaspersky, "Equation: The Death Star of Malware Galaxy" (16 February 2015) | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-12 | Reported |
| 58 | Kaspersky and King's College London, "Penquin's Moonlit Maze" (3 April 2017) | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Reported |
| 59 | National Security Archive, Cyber Vault key events index (29 June 2019) | https://nsarchive.gwu.edu/news/cyber-vault/2019-06-29/fierce-domain-documents-key-events-cyber-history | 2026-11-12 | Reported |
| 60 | Directive 95/46/EC of 24 October 1995 (EUR-Lex) | `https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:31995L0046` | 2026-11-12 | Confirmed |
| 61 | NIST, FIPS 180-1, Secure Hash Standard (PDF) | https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf | 2026-11-12 | Confirmed |
| 62 | NIST CSRC, FIPS 180-1 publication record | https://csrc.nist.gov/pubs/fips/180-1/final | 2026-11-12 | Confirmed |
| 63 | Paperwork Reduction Act of 1995, Pub. L. 104-13 | https://www.govinfo.gov/content/pkg/PLAW-104publ13/html/PLAW-104publ13.htm | 2026-11-12 | Confirmed |
| 64 | NIST CSRC, SP 800-12, An Introduction to Computer Security: The NIST Handbook | https://csrc.nist.gov/pubs/sp/800/12/final | 2026-11-12 | Confirmed |
| 65 | NIST CSRC, SP 800-13 publication record (with SP 800-11) | https://csrc.nist.gov/pubs/sp/800/13/final | 2026-11-12 | Confirmed |
| 66 | RFC 1825, Security Architecture for the Internet Protocol (Atkinson, NRL, August 1995), with RFCs 1826 to 1829 | https://www.rfc-editor.org/rfc/rfc1825.txt | 2026-11-12 | Confirmed |
| 67 | National Security Archive, PDD-39 "U.S. Policy on Counterterrorism", 21 June 1995 (record) | https://nsarchive.gwu.edu/document/34249-document-8-pdd-39-us-policy-counterterrorism-june-21-1995-secret | 2026-11-12 | Confirmed |
| 68 | Attorney General, memo of 14 March 1996 on critical infrastructure (EPIC archive) | https://archive.epic.org/security/infowar/reno_memo.html | 2026-11-12 | Confirmed |
| 69 | CIAC Information Bulletin F-20, 5 April 1995 (SATAN; Courtney) | `https://diswww.mit.edu/menelaus.MIT.EDU/ids/62` | 2026-11-12 | Confirmed |
| 70 | SATAN authors' summary (USENET extract, 8 March 1995) | http://www.porcupine.org/satan/summary.html | 2026-11-12 | Confirmed |
| 71 | Purdue CERIAS, COAST archive on SATAN detectors | https://www.cerias.purdue.edu/site/about/history/coast/satan.php | 2026-11-12 | Confirmed |
| 72 | CVE, history page (archived old website) | https://www.cve.org/Resources/Media/Archives/OldWebsite/about/history.html | 2026-11-12 | Confirmed |
| 73 | NVD API queries, records published in 1995 (three 120-day windows, 7 + 6 + 12 = 25) | `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=1995-01-01T00:00:00.000&pubEndDate=1995-04-30T23:59:59.999` ; `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=1995-05-01T00:00:00.000&pubEndDate=1995-08-28T23:59:59.999` ; `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=1995-08-29T00:00:00.000&pubEndDate=1995-12-26T23:59:59.999` | 2026-11-12 | Demonstrated |
| 74 | NVD, CVE-1999-0099 (with the advisory pairings in Part 2) | https://nvd.nist.gov/vuln/detail/CVE-1999-0099 | 2026-11-12 | Confirmed |
| 75 | NVD, CVE-1999-0077 (with CVE-1999-0073) | https://nvd.nist.gov/vuln/detail/CVE-1999-0077 | 2026-11-12 | Confirmed |
| 76 | NVD, CVE-1999-1080 | https://nvd.nist.gov/vuln/detail/CVE-1999-1080 | 2026-11-12 | Confirmed |
| 77 | Tatu Ylonen, SSH 1.0 announcement (12 July 1995, reposted to Bugtraq 18 July 1995) | https://seclists.org/bugtraq/1995/Jul/72 | 2026-11-12 | Confirmed |
| 78 | RFC 1760, The S/KEY One-Time Password System (February 1995) | https://www.rfc-editor.org/rfc/rfc1760.txt | 2026-11-12 | Confirmed |
| 79 | RFC 1858, Security Considerations for IP Fragment Filtering (October 1995) | https://www.rfc-editor.org/rfc/rfc1858.txt | 2026-11-12 | Confirmed |
| 80 | RFC 1847, Security Multiparts for MIME (October 1995), with RFCs 1848 and 1864 | https://www.rfc-editor.org/rfc/rfc1847.txt | 2026-11-12 | Confirmed |
| 81 | RFC 6101, The Secure Sockets Layer (SSL) Protocol Version 3.0 (historical dates) | https://www.rfc-editor.org/rfc/rfc6101.txt | 2026-11-12 | Confirmed |
| 82 | BSI, BS 7799-1:1995 product record | https://knowledge.bsigroup.com/products/information-security-management-code-of-practice-for-information-security-management-systems | 2026-11-12 | Confirmed |
| 83 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 84 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 85 | MITRE ATT&CK, Design and Philosophy (March 2020) | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | 2026-11-12 | Confirmed |
| 86 | MITRE D3FEND, about | https://d3fend.mitre.org/about/ | 2026-11-12 | Confirmed |
| 87 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_profiles.jsonl | 2026-11-12 | Demonstrated |
| 88 | TeamStarWolf library, `data/weaknesses/capec.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/capec.jsonl | 2026-11-12 | Demonstrated |
| 89 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/cwe.jsonl | 2026-11-12 | Demonstrated |
| 90 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_to_d3fend.jsonl | 2026-11-12 | Demonstrated |
| 91 | TeamStarWolf library, `data/attack/campaigns.jsonl` (with the group profiles) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/campaigns.jsonl | 2026-11-12 | Confirmed |
| 92 | TeamStarWolf library, main branch, `mitre/` | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12 | Demonstrated |
| 93 | TeamStarWolf library, `case-studies/ZERO_DAY_MARKET_EVENTS.md` and the era studies on main | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/case-studies/ZERO_DAY_MARKET_EVENTS.md | 2026-11-12 | Demonstrated |
| 94 | TeamStarWolf library, main branch, `navigator/library-layers/` | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-12 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md)
- Home studies: [The Year 1994 in Intrusions](/case-studies/CHRONICLE_1994.md) (the Rome Laboratory intrusions); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [NSA and CIA Tool Leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [The Cuckoo's Egg Intrusion](/case-studies/CUCKOOS_EGG_1986.md) (an earlier intrusion into US military and research networks); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Log4Shell](/case-studies/LOG4SHELL.md); [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1595.002 Vulnerability Scanning](/mitre/techniques/T1595-002.md), [T1046 Network Service Discovery](/mitre/techniques/T1046.md), [T1563 Remote Service Session Hijacking](/mitre/techniques/T1563.md), [T1547.006 Kernel Modules and Extensions](/mitre/techniques/T1547-006.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1078.001 Default Accounts](/mitre/techniques/T1078-001.md), [T1090.003 Multi-hop Proxy](/mitre/techniques/T1090-003.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1574.006 Dynamic Linker Hijacking](/mitre/techniques/T1574-006.md), [T1554 Compromise Host Software Binary](/mitre/techniques/T1554.md), [T1137.001 Office Template Macros](/mitre/techniques/T1137-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1498 Network Denial of Service](/mitre/techniques/T1498.md), [T1499 Endpoint Denial of Service](/mitre/techniques/T1499.md)
- CAPEC: [CAPEC-151](/mitre/capec/CAPEC-151.md), [CAPEC-324](/mitre/capec/CAPEC-324.md), [CAPEC-593](/mitre/capec/CAPEC-593.md), [CAPEC-158](/mitre/capec/CAPEC-158.md), [CAPEC-300](/mitre/capec/CAPEC-300.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-70](/mitre/capec/CAPEC-70.md), [CAPEC-59](/mitre/capec/CAPEC-59.md), [CAPEC-20](/mitre/capec/CAPEC-20.md)
- Groups, software and campaigns: none bound for 1995 (Part 10); Turla [G0010](/mitre/groups/G0010.md) and Equation [G0020](/mitre/groups/G0020.md) for their recorded start dates
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-1995.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1995.json)
