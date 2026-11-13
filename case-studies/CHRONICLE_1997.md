# The Year 1997 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md) · Home studies for events summarized here: [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md) (the June 1997 sentence), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Moonlight Maze, 1996 to 1999, and the 1998 Solar Sunrise intrusions), [United States: the public record](/case-studies/THREAT_ACTORS_UNITED_STATES.md) and [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) (Equation group infrastructure from 1996) · Series: [The Year 1996 in Intrusions](/case-studies/CHRONICLE_1996.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 63 min (14,381 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 1997, you need the year's mass scans, network-facing root flaws, web scripts and macro viruses side by side with the CERT advisories, Eligible Receiver and the year's law, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 10: the defender view](#part-10-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

For the people who ran Unix mail, news and web servers in 1997, the year's problem was scale (Inferred). The CERT Coordination Center (CERT/CC) handled 2,134 incidents, fewer than the 2,573 of 1996, yet counted more than 146,484 sites affected, against more than 10,700 a year earlier (Confirmed [3][4]). Its annual report lists first that intruders ran "large-scale, automated scans" for a remote root flaw in the University of Washington IMAP and POP servers, and that there were "widespread, large-scale attacks" on news (NNTP) servers running InterNetNews (INN) (Confirmed [3]). In the fourth quarter, 13 percent of the incidents reported to CERT/CC involved a root compromise, many of them on systems left unpatched or misconfigured, exploited through well-known vulnerabilities for which CERT advisories had already been published (Confirmed [3]).

CERT/CC numbered 28 advisories in its 1997 series, CA-97.01 to CA-97.28 (Confirmed [1][2][3]). Remote root came through daemons that ran as root and faced the network: talkd trusted crafted DNS data (27 January), sendmail 8.8.3 and 8.8.4 overflowed on MIME conversion even behind firewalls (28 January), INN ran commands from crafted control messages (20 February), the IMAP and POP servers overflowed at login (7 April) and statd gave root without an account (5 December) (Confirmed [1]). Local root came through set-uid utilities: suidperl and lpr were "being actively exploited" by May and June, and the six SGI IRIX overflows advised in July were, by the annual report, exploited in many incidents (Confirmed [1][3]). Web scripts were the third path. CERT warned about nph-test-cgi in February, webdist.cgi in May, Count.cgi in November and, in CA-97.25, about every CGI script that passes user input to a shell, saying the problem "lies in how the scripts are written" and not in the languages (Confirmed [1]). The year closed with Teardrop and Land, two "widely available" crash tools, and with Cisco's own advisory on Land (Confirmed [1][5]).

The year's state record is an exercise, a commission and a campaign nobody had yet seen. In June the Joint Staff ran Eligible Receiver 97, whose declassified tasking assumes Iran, North Korea and Cuba as scenario adversaries (Confirmed [37][38]); in the National Security Archive's account an NSA Red Team played those forces against Defense command and control and civilian infrastructure with off-the-shelf tools (Reported [37]). In October the President's Commission on Critical Infrastructure Protection issued *Critical Foundations*, which found no imminent national crisis but steadily increasing vulnerability (Confirmed [34][35][36]). Moonlight Maze, which later research dates from 1996 to 1999, was running across the whole year with no dated 1997 event in the public record; its home is the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Confirmed [42]).

Office 97 shipped in January with a new macro language, and by October macro viruses made up about half of the named reports in *Virus Bulletin*'s prevalence table, with WM/CAP.A alone at 20.8 percent (Confirmed [19]; Demonstrated [24]). A Linux user reported a Bliss infection on the BugTraq list, which Virus Bulletin judged the first sign of that virus infecting real systems, and Virus Bulletin wrote that no Win32 virus had worked under Windows NT until Win32.Cabanas late in the year (Confirmed [20][23]). The law moved too: the Supreme Court struck down the Communications Decency Act's indecency provisions in June, the Bernstein court held parts of the encryption export rules unconstitutional in August and then stayed its own ruling, the G8 justice ministers agreed on 24-hour high-tech crime contacts in December, and the No Electronic Theft Act became law on 16 December (Confirmed [51][49][50][55][56][30]).

This study is the dated record of that year, built only from sources opened on 12 and 13 November 2026. Nine parts cover the timeline, the CERT/CC advisories and the later CVE record, scanning and attack knowledge, crime and prosecutions, web incidents and defacements, viruses, the state and exercise record, law and policy, and standards; a tenth gives the defender view and an eleventh maps the record to MITRE frameworks.

No identifier system defenders use today existed in 1997. CVE began in 1999, the first CWE release came in 2006, CAPEC in 2007 and the public ATT&CK release in May 2015 (Confirmed [11][78][79][80]). The year's own vulnerability identifiers are CERT's advisory numbers. NVD now returns 253 records with 1997 published dates, every one a CVE-1999 id assigned later (Demonstrated [9]). Every ATT&CK id in Part 11 is this study's later mapping, labelled as such.

Evidence grade: CERT/CC advisories and its annual report, vendor advisories, CVE and NVD records, statutes, court opinions, executive and congressional documents, Justice Department releases, declassified Joint Staff documents, NIST, RFC Editor and IETF records, the researchers' own posts, MITRE's own pages and *Virus Bulletin*'s own editorials, analyses and tables are **Confirmed**. Facts that rest on newspaper and wire stories relayed through the RISKS Digest, a book's companion site, the National Security Archive's analysis of documents it posts, or *Virus Bulletin*'s report of what others said are **Reported** and attributed. A query or data file this study ran or opened itself is **Demonstrated**. Where the study draws its own conclusion it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 1997, plus boundary records that open or close a 1997 event (the December 1996 Air Force defacement, the January 1998 issue date printed for CA-97.23, the 1998 Mitnick appeal, the 1998 Solar Sunrise release, the 1999 CVE records, the 2015 and 2017 research on Equation and Moonlight Maze) |
| CERT/CC advisories | 28, CA-97.01 (6 Jan) to CA-97.28 (16 Dec), with CA-97.23 printed as issued 15 Jan 1998; 16 vendor-initiated bulletins; six CERT Summaries, two of them special editions on large-scale attacks (Confirmed [1][3]) |
| CERT/CC workload | 39,626 e-mail messages, 1,058 hotline calls, 326 vulnerability reports, 2,134 incidents, more than 146,484 sites affected; 13 percent of fourth-quarter incidents involved root compromise (Confirmed [3][4]) |
| Mass exploitation | IMAP and POP (CA-97.09, 7 Apr) scanned for all year; INN (CA-97.08, 20 Feb) under widespread attack; phf and other CGI scripts still exploited (Confirmed [1][3]) |
| Denial of service | More frequent and varied, with IP spoofing and UDP packet storms (Confirmed [3]); Land against Cisco devices (21 Nov) and Teardrop and Land in CA-97.28 (16 Dec) (Confirmed [5][1]) |
| Attack knowledge | Phrack 51 introduces the nmap port scanner, 1 Sep (Confirmed [13]) |
| Crime | Credit-card data on more than 100,000 accounts sold to undercover FBI agents, arrest 21 May, guilty plea by 26 Aug (Reported [69][73]); an AOL phishing e-mail in August (Reported [73]) |
| Web incidents | NASA home page replaced (4 to 5 Mar), Microsoft's site disrupted (about 22 Jun), Yahoo altered (early Dec) (Reported [65][70][77]) |
| Malware | Office 97 and VBA5 (16 Jan); Bliss on Linux (Feb); ShareFun mailing itself through Microsoft Mail (Feb); WM/CAP.A leads the October table; Win32.Cabanas runs under NT (late 1997) (Confirmed [19][20][14][24][23][16]) |
| State and exercise record | Eligible Receiver 97 (Joint Staff documents of 9 to 11 June); *Critical Foundations* (October); Moonlight Maze running, with no dated 1997 event (Confirmed [37][38][35][42]) |
| Law and policy | Reno v. ACLU (26 Jun); Framework for Global Electronic Commerce (1 Jul); Bernstein ruling (25 Aug) and stay (28 Aug); H.R. 1903 passes the House (16 Sep); G8 high-tech crime meeting (9 to 10 Dec); NET Act (16 Dec) (Confirmed [51][52][49][50][54][55][56][30]) |
| Standards | AES announced (2 Jan) and called for (12 Sep); FIPS 196 (18 Feb); DNSSEC, HMAC, cookies and the Site Security Handbook among the year's RFCs (Confirmed [48][61][57]) |
| This study's MITRE binding | 22 ATT&CK Enterprise technique rows, every one a later mapping; no ICS row; no group, software or campaign object; 16 CWE ids; 17 CAPEC entries paired (CAPEC-25 named and rejected); D3FEND pairings from the library's data; one Navigator layer (Part 11) |

### Key findings

- **Mass scanning set the shape of the year.** CERT/CC's own report puts automated IMAP scans and widespread INN attacks at the top of its activity list, and its affected-site count rose fourteen-fold while incidents fell (Confirmed [3][4]). The count is undefined in the report, and that it reflects scan targets rather than compromised hosts is this study's reading (Inferred).
- **Root ran on the network edge.** sendmail, IMAP and POP, INN, talkd and statd all ran as root and faced the network, and each gave remote command execution in 1997 (Confirmed [1]). Firewalls were not a full answer: CERT said the sendmail and INN flaws could reach servers behind them, and the JavaScript flaw of July worked behind a firewall and on HTTPS pages (Confirmed [1]).
- **Patching was the defense and the gap.** Many of the daily root compromises traced to unpatched or misconfigured systems with CERT advisories already published, and CERT/CC began arguing that only defensive engineering would end "the expensive, and often haphazard, reactive use of patches" (Confirmed [3]).
- **The web script was a front door.** Four of the year's advisories concern CGI scripts, and CA-97.25 placed the fault in how scripts were written (Confirmed [1]).
- **Trust in names failed again.** BIND cache poisoning was "now being exploited" in August, and talkd turned crafted DNS data into remote root in January (Confirmed [1]).
- **Malware followed Office.** Macro viruses went from about a quarter of *Virus Bulletin*'s named reports in October 1996 to about half in October 1997, and a Word virus used the mail client's address list to spread in February (Demonstrated [24]; Confirmed [14]).
- **The state story was an exercise.** Eligible Receiver tested Defense networks with a red team; the states in it were scenario roles, not attackers (Confirmed [38]). No opened primary attributes a 1997 intrusion to a state (Inferred).
- **Policy organized around infrastructure.** GAO named federal information security a government-wide high-risk area in February, and *Critical Foundations* called for information sharing and a real-time warning capability in October (Confirmed [36][34]).

### Top recommendations

1. **Patch or turn off network daemons that run as root.** CERT's advice for IMAP and POP was to patch or upgrade, and otherwise disable the services; for rlogin, patch or turn it off or wrap it (Confirmed [1]).
2. **Remove what the web server does not need.** CERT told sites to remove nph-test-cgi and check every cgi-bin directory (Confirmed [1]).
3. **Treat user input in scripts as hostile.** CA-97.25 put the fault in the scripts, not the languages, and CERT issued a tech tip on sanitizing input (Confirmed [1]).
4. **Filter spoofed traffic in both directions.** For Land, CERT advised filtering spoofed packets and dropping outbound packets whose source is not internal (Confirmed [1]).
5. **Audit set-uid programs.** CERT's fallback for the X Toolkit flaw was to remove set-uid and set-gid bits until a fix was in place (Confirmed [1]).
6. **Do not let names stand in for identity.** Upgrade resolvers past known cache-poisoning flaws; BIND 4.9.6 fixed the one exploited in 1997 (Confirmed [1]).
7. **Treat documents as code.** Office 97 disabled WordBasic macros by default on opening, while converted VBA5 macros escaped the anti-virus products of the day (Confirmed [19]).
8. **Look for the signs of an intrusion, not only the headline attack.** CERT/CC published its Intruder Detection Checklist and its first security improvement module, Detecting Signs of Intrusion, and distributed Tripwire, MD5 and TCP wrappers (Confirmed [3]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, cryptography and policy dated to 1997, plus the later records that open, close or explain a 1997 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every event graded, numbers as the source states them.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record (a CERT/CC advisory as SEI publishes it, CERT/CC's annual report, a vendor advisory, a CVE or NVD record, a statute, a court opinion, a Justice Department release, a White House or GAO document, a declassified Joint Staff document, a NIST, RFC Editor or IETF record, the researcher's or vendor's own publication, *Virus Bulletin*'s own editorial, analysis or table, a live ATT&CK page, or the library's data files as the record of what the library holds) was opened on 12 or 13 November 2026 and states the fact |
| Reported | Only a secondary source was opened: newspaper, wire and trade-press stories relayed through the RISKS Digest, a book's companion site, the National Security Archive's own analysis of documents it hosts, or *Virus Bulletin* relaying claims from others. The source is named in the text |
| Demonstrated | This study ran the query or opened the data itself and saw the result (the NVD date queries, the prevalence sum, the library's data files and page tree) |
| Inferred | The study's own reasoning, labelled where it appears. Every MITRE id bound to a 1997 event is Inferred as to the binding |

Limits a reader should know:

- **No contemporaneous CVE, no ATT&CK.** No 1997 record carries a CVE id or an ATT&CK id. CVE began with Mann and Christey's white paper at a Purdue workshop on 21 to 22 January 1999, started with 321 entries and launched publicly in September 1999 (Confirmed [11]). NVD's 253 records with 1997 dates were assigned later, and Part 2 pairs some of them with advisories by date and description (Demonstrated [9]; Inferred [10]).
- **The advisory text.** SEI's compilation "1997 CERT Advisories" (186 pp.) is the text for all 28 advisories, and SEI's landing page counts 28 [1][2]. The compilation prints CA-97.23 with an original issue date of 15 January 1998, while CERT/CC's annual report lists it among the advisories published in 1997; this study gives both and does not resolve them (Confirmed [1][3]).
- **RISKS and the trade press.** Most of the year's named incidents survive as press items abstracted in the RISKS Digest, graded Reported and attributed to the paper or wire service the digest names [62] to [77]. The Justice Department press releases for the 1997 card-data case and the Forbes case were not opened, so those rows rest on the press.
- **People.** Defendants whose outcomes this study did not check are not named: the fired California contractor and the former Forbes employee are two. Named people are those who were sentenced, fined or pleaded guilty, parties in published court opinions, officials and researchers credited in the record.
- **The Eligible Receiver record.** The Joint Staff documents carry dates and are Confirmed for those dates and their text; the National Security Archive's account of what happened, and its quotations from a scanned and heavily redacted observation report, are Reported [37][38][39].
- **Home studies.** Mitnick's sentence lives in the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md); Moonlight Maze and Solar Sunrise in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); the Equation group in the [United States study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) and the [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md). Each is summarized here in a paragraph. A search of the era studies on main found no 1997 row in the dot-com era, e-commerce, zero-day market, pre-internet, cybercrime books, hacker and the state, United States or Russia studies, only the Mitnick sentence, so this chronicle is the home for every other 1997 event below (Demonstrated [47]).
- **Tradecraft is described at advisory level.** Advisory names, affected products and impact, and technique names and ids. The 1997 advisories carry patch checks, wrapper code and filter rules, and the Phrack article ships a tool; none is reproduced here.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1996-12-29 (prologue) | US Air Force main web page (af.mil) altered, after earlier alterations of Justice Department, CIA and NASA pages; a 1996 event that opens the next year's defacement record | Defacement | Reported | [62] |
| 1997-01 | CERT/CC staff submit a report to the President's Commission on Critical Infrastructure Protection (PCCIP) on Internet threats | Policy | Confirmed | [3] |
| 1997-01-02 | NIST announces the start of Advanced Encryption Standard development | Cryptography | Confirmed | [48] |
| 1997-01-06 | CA-97.01: multi-platform Unix FLEXlm license daemon flaws allow file creation and program execution as the FLEXlm user; reprint of AUSCERT AA-96.03 | Vulnerability | Confirmed | [1] |
| 1997-01-07 | CA-97.02: HP-UX newgrp buffer overrun to root; a 4 April update records reports of exploitation | Vulnerability | Confirmed | [1] |
| 1997-01-08 | CA-97.03: IRIX csetup; local users create or overwrite arbitrary files and ultimately gain root; exploitation information public; joint CERT/CC and AUSCERT advisory | Vulnerability | Confirmed | [1][2] |
| ~1997-01-09 | A fired subcontractor on a California Department of Information Technology system is arrested on three felony charges for allegedly trying to destroy it, suspected of building a remote backdoor (outcome not checked) | Insider, state government | Reported | [63] |
| 1997-01-16 | Office 97 reaches North American shops with VBA5 in every application | Malware | Confirmed | [19] |
| 1997-01-27 | CA-97.04: talkd turns crafted DNS data into remote root; a public script exists and CERT has reports of root compromises | Vulnerability | Confirmed | [1] |
| 1997-01-28 | CA-97.05: MIME conversion buffer overflow in sendmail 8.8.3 and 8.8.4, exploitable despite firewalls; fixed in 8.8.5 | Vulnerability, mail | Confirmed | [1] |
| 1997-01 | RFC 2065 DNS Security Extensions; RFC 2069 HTTP Digest Access Authentication | Standards | Confirmed | [57] |
| 1997-02 | GAO's High-Risk Series (GAO/HR-97-9) designates federal information security a new government-wide high-risk area | Policy | Confirmed | [36] |
| 1997-02 | WordMacro/ShareFun found in the wild in the USA; it mails an infected attachment to three random entries in the local Microsoft Mail alias list | Malware | Confirmed | [14] |
| 1997-02 (early) | A Linux user reports a Bliss infection on the BugTraq list; *Virus Bulletin* rebuts a "first Linux virus" press release but says Linux users were at risk basically for the first time | Malware | Confirmed | [20] |
| 1997-02 (posted 11 Feb) | On German TV, hackers linked to the Chaos Computer Club show a hostile ActiveX control that, when its page is visited in Internet Explorer, drives Quicken to create a transfer to their account | Web, finance | Reported | [64] |
| 1997-02 | RFC 2104 HMAC; RFC 2109 HTTP State Management (cookies) | Standards | Confirmed | [57] |
| 1997-02-03 | *CompuServe Inc. v. Cyber Promotions, Inc.* (S.D. Ohio): preliminary injunction against a bulk unsolicited e-mail sender; CompuServe's technical blocking had failed | Courts | Confirmed | [26] |
| 1997-02-06 | CA-97.06: rlogin copies the TERM variable into a buffer without due care; local root | Vulnerability | Confirmed | [1] |
| 1997-02-18 | CA-97.07: nph-test-cgi lets web clients list files they should not see, issued because of ongoing activity; phf (CA-96.06) still exploited | Vulnerability, web | Confirmed | [1] |
| 1997-02-18 | FIPS 196, Entity Authentication Using Public Key Cryptography | Standards | Confirmed | [61] |
| 1997-02-20 | CA-97.08: INN before 1.5.1 runs attacker commands from crafted control messages that pass through firewalls; numerous exploitation reports by the 17 to 18 March updates | Vulnerability, news | Confirmed | [1] |
| 1997-02-20 | IETF Secure Shell (secsh) working group starts (proposed 14 Feb) | Standards | Confirmed | [60] |
| 1997-02-21 | *United States v. Czubinski* (1st Cir.): an IRS employee's wire fraud and 18 U.S.C. 1030(a)(4) convictions reversed; browsing taxpayer files without more cannot sustain the felony | Courts | Confirmed | [25] |
| 1997-02-27 | The PCCIP comments desk posts the Commission's remit to RISKS: eight infrastructures from telecommunications to continuity of government | Policy | Confirmed | [33] |
| 1997-03-03 to 05 | IAB Security Architecture Workshop at Bell Labs, Murray Hill (reported in RFC 2316, 1998) | Standards | Confirmed | [59] |
| 1997-03-04/05 | NASA's home page replaced overnight with a message from a group calling itself H4G1S; site taken offline | Defacement | Reported | [65] |
| reported 1997-03-07 | FBI: a Swedish intruder dialed into 11 north Florida 911 systems, tying up lines and connecting operators to each other; misdemeanor conviction in Sweden | Emergency services | Reported | [66] |
| 1997-03-23 (disclosure) | A former Department of Energy security head tells the BBC that intruders from Eindhoven entered systems at 34 US military sites during the Gulf War; the intrusions date from 1990 to 1991 | Military | Reported | [67] |
| 1997-04 | IITF draft paper on options for promoting privacy on the national information infrastructure, issued for comment | Policy | Confirmed | [53] |
| 1997-04 | RFC 2138 RADIUS | Standards | Confirmed | [57] |
| 1997-04-07 | CA-97.09: login overflow in the University of Washington IMAP and POP servers gives remote root; intrusions still reported at the 4 Aug update; large-scale automated scans all year | Vulnerability, mail | Confirmed | [1][3] |
| 1997-04-21/22 | A dismissed Forbes employee breaks into Forbes systems and sabotages them, as federal prosecutors later charge; the company puts damage above $100,000 (outcome not checked) | Insider, media | Reported | [75] |
| 1997-04-24 | CA-97.10: buffer overflow in libraries using the Natural Language Service | Vulnerability | Confirmed | [1] |
| 1997-04 (late) | A hard drive stolen from Levi Strauss holds records on about 20,000 current and 20,000 former employees, including SSNs and some retiree bank account numbers | Breach, retail | Reported | [68] |
| 1997-05-01 | CA-97.11: X Toolkit (libXt) overflow; fix X11R6.3 or remove set-uid and set-gid bits | Vulnerability | Confirmed | [1] |
| 1997-05-06 | CA-97.12: IRIX webdist.cgi lets local and remote users run commands; joint CERT/CC and AUSCERT advisory | Vulnerability, web | Confirmed | [1] |
| 1997-05-07 | CA-97.13: xlock overflow | Vulnerability | Confirmed | [1] |
| 1997-05 | *Virus Bulletin* reviews NetShield for NT and runs its second Windows 95 comparative | Defense | Confirmed | [21] |
| 1997-05-21 | CA-97.14: metamail lets a MIME sender make the receiver run a command | Vulnerability, mail | Confirmed | [1] |
| 1997-05-21 | Carlos Felipe Salgado Jr. arrested at San Francisco Airport after selling undercover FBI agents data on more than 100,000 credit-card accounts for $260,000 | Crime, payments | Reported | [69] |
| 1997-05-28 | CA-97.15: SGI login LOCKOUT | Vulnerability | Confirmed | [1] |
| 1997-05-29 | CA-97.16: ftpd signal handling; CA-97.17: suidperl overflow, "being actively exploited" | Vulnerability | Confirmed | [1] |
| 1997-06 | 9th FIRST conference, Bristol: 159 people from 23 countries | Response community | Confirmed | [3] |
| 1997-06 | *Virus Bulletin*, citing French sources: all the major French corporations seem to have contracted WM/CAP.A, some with more than 8,000 infected files | Malware | Reported | [22] |
| 1997-06-09 to 11 | Eligible Receiver 97: Joint Staff Crisis Action Team activated 9 Jun; J-5 tasking 10 Jun; "National Pride Update" 11 Jun | Exercise, Defense | Confirmed | [37][38] |
| 1997-06-12 | CA-97.18: at(1) overflow; any user can run commands as root | Vulnerability | Confirmed | [1] |
| ~1997-06-22 | Microsoft's web site disrupted for about 10 minutes by an intruder using a flaw in Microsoft's own server software; Microsoft posts a fix | Web | Reported | [70] |
| 1997-06-25 | CA-97.19: BSD lpr overrun; exploit public for some time, now actively exploited | Vulnerability | Confirmed | [1] |
| by 1997-06-26 | RSA's 56-bit DES challenge key recovered after about four months, searching about a quarter of the keyspace | Cryptography | Reported | [70] |
| 1997-06-26 | *Reno v. ACLU*: the Communications Decency Act's indecent transmission and patently offensive display provisions abridge free speech | Courts | Confirmed | [51] |
| 1997-06-27 | Kevin Mitnick sentenced to 22 months. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Reported | [27][29] |
| 1997-07-01 | White House releases *A Framework for Global Electronic Commerce* with a presidential directive | Policy | Confirmed | [52][53] |
| 1997-07-01 (NVD date) | CVE-1999-0153, WinNuke: Windows 95 and NT denial of service through out-of-band data on the NetBIOS port, carries this bulk NVD date | Vulnerability (later record) | Confirmed | [8][12] |
| 1997-07-08 | CA-97.20: JavaScript in several browsers lets a site monitor a user's web activity, behind a firewall and on HTTPS pages | Vulnerability, browser | Confirmed | [1] |
| ~1997-07-10 | More than 2,300 ESPN SportsZone and NBA.com customers receive anonymous e-mail showing the last eight digits of their card numbers; no fraud reported | E-commerce | Reported | [71] |
| 1997-07-16 | CA-97.21: six IRIX overflows (df, pset, eject, login/scheme, ordist, xlock), exploited in many incidents | Vulnerability | Confirmed | [1][3] |
| 1997-08-13 | CA-97.22: BIND before 4.9.6, cache poisoning "now being exploited"; supersedes CA-96.02 | Vulnerability, DNS | Confirmed | [1] |
| ~1997-08-17 | Sweden's "Crack a Mac" contest server broken through a third-party web plug-in, patched in a little over 24 hours | Web | Reported | [72] |
| 1997-08-19 | NASDAQ unreachable for most Internet users for several hours after an InterNIC clerical error; an outage, not an attack | DNS registry | Reported | [73] |
| 1997-08 | AOL subscribers receive e-mail posing as AOL Member Services, linking to a fake chairman's letter asking for card numbers | Phishing | Reported | [73] |
| 1997-08 (by 26 Aug) | Salgado pleads guilty before trial | Crime | Reported | [73] |
| 1997-08-25 | *Bernstein v. Department of State* (N.D. Cal.): parts of the encryption software export controls held unconstitutional | Courts, cryptography | Confirmed | [49] |
| 1997-08-28 | The Bernstein court stays its ruling to 8 September and limits it, pending appeal, to the plaintiff and his program | Courts, cryptography | Confirmed | [50] |
| 1997-09 | RFC 2196 Site Security Handbook (FYI 8), obsoleting RFC 1244 | Standards | Confirmed | [57] |
| 1997-09-01 | Phrack 51: "The Art of Port Scanning" introduces nmap | Attack knowledge | Confirmed | [13] |
| 1997-09-12 | NIST's formal call for AES candidate algorithms | Cryptography | Confirmed | [48] |
| 1997-09-16 | The House passes H.R. 1903, the Computer Security Enhancement Act of 1997 (enactment not checked) | Law | Confirmed | [54] |
| 1997-10 | PCCIP issues *Critical Foundations: Protecting America's Infrastructures* | Policy | Confirmed | [34][35][36] |
| 1997-10 | *Virus Bulletin* prevalence table: 697 reports, WM/CAP.A first with 145 | Malware | Confirmed | [24] |
| 1997-10 | RFC 2222 SASL; RFC 2228 FTP Security Extensions | Standards | Confirmed | [57] |
| 1997-11 | Esperanto discovered, its Mac version the first new Mac virus in over two years; *Virus Bulletin* analyses Win32.Cabanas | Malware | Confirmed | [15][23] |
| 1997-11-05 | CA-97.24: Count.cgi overrun lets attackers run commands; from AUSCERT AA-97.27 of 31 Oct | Vulnerability, web | Confirmed | [1] |
| 1997-11-10 | CA-97.25: sanitizing user-supplied data in CGI scripts | Vulnerability, web | Confirmed | [1] |
| ~1997-11-10/11 | Pentium and Pentium MMX "F00F" flaw: one unprivileged instruction can halt the processor; Intel confirms malicious code could crash a system | Hardware | Reported | [74] |
| 1997-11-21 | UK: charges of unauthorised access and modification at Griffiss AFB and Lockheed against Kuji, an alleged associate of Richard Pryce ("Datastream Cowboy"), dropped (PA News, 21 Nov); Pryce had been fined 1,200 pounds earlier in the year | Courts | Reported | [76] |
| ~1997-11 | Senate Permanent Subcommittee on Investigations investigators estimate hackers cost businesses about $800 million worldwide in 1995 | Policy | Reported | [75] |
| 1997-11-20/21 | FedCIRC's first Annual Workshop | Response community | Confirmed | [3] |
| 1997-11-21 | Cisco advisory: the public land.c program denies service on IOS routers, Catalyst switches and other devices; Cisco has multiple reports | Vulnerability | Confirmed | [5] |
| ~1997-11-24 | Federal prosecutors in New York charge the former Forbes employee | Courts | Reported | [75] |
| 1997-12-05 | CA-97.26: statd overrun gives root locally and remotely without an account | Vulnerability | Confirmed | [1] |
| early 1997-12 | Yahoo's site altered for several minutes with a note demanding Mitnick's release and claiming a "logic bomb/worm"; no virus found | Defacement | Reported | [77] |
| 1997-12-09/10 | G8 Justice and Interior Ministers hold their first meeting on transnational high-tech crime; Attorney General's statement of commitments | Policy | Confirmed | [55][56] |
| 1997-12-10 | CA-97.27: FTP bounce | Vulnerability | Confirmed | [1] |
| 1997-12-16 | CA-97.28: Teardrop and Land; several sites attacked; no workaround for Teardrop | Vulnerability, availability | Confirmed | [1] |
| 1997-12-16 | No Electronic Theft (NET) Act, Pub. L. 105-147 | Law | Confirmed | [30] |
| 1996 to 1999 | Moonlight Maze intrusions into mainly US military, research and university networks; no dated 1997 event. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Espionage | Confirmed | [42] |
| 1998-01-15 (as printed) | CA-97.23: rdist overflow to root, numbered in the 1997 series | Vulnerability | Confirmed | [1][3] |
| 1998-03-18 (boundary) | Justice Department release on Solar Sunrise (Confirmed [41]); a later Joint Chiefs briefing, as the Archive describes it, says Solar Sunrise confirmed Eligible Receiver's findings (Reported [40]). Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Defense | Confirmed [41]; Reported [40] | [41][40] |
| 1998-05-20 (boundary) | Ninth Circuit affirms Mitnick's sentence and supervised-release conditions | Courts | Confirmed | [28] |

## Part 2: the vulnerability record

### The 28 advisories

CERT/CC issued 28 advisories in its 1997 series; SEI's landing page counts 28 and its compilation holds the text (Confirmed [1][2]). CERT/CC's annual report adds 16 vendor-initiated bulletins and six CERT Summaries, two of them special editions on widespread, large-scale attacks: CS-97.02 on INN and CS-97.04 on IMAP (Confirmed [3]). The impact column gives CERT's substance. The "Later CVE" column gives NVD or CVE records that match the advisory by date and description; the pairing is this study's except for CVE-1999-0039, whose record cites CA-1997-12 itself, and only the pairs this study checked are listed (Confirmed [6][8]; Inferred [10]).

| Advisory | Date | Product | Impact as CERT states it | Later CVE | Grade | Sources |
|---|---|---|---|---|---|---|
| CA-97.01 | 6 Jan | Unix FLEXlm license manager | File creation and program execution as the FLEXlm user; vendors had configured the daemon to run as root; reprint of AUSCERT AA-96.03 of 19 Sep 1996 | not paired here | Confirmed | [1] |
| CA-97.02 | 7 Jan | HP-UX newgrp | Buffer overrun to root; exploitation reported by the 4 Apr update | not paired here | Confirmed | [1] |
| CA-97.03 | 8 Jan | IRIX csetup | Local users create or overwrite arbitrary files and ultimately gain root; exploitation information public; joint CERT/CC and AUSCERT advisory | not paired here | Confirmed | [1][2] |
| CA-97.04 | 27 Jan | talkd | Crafted DNS data gives remote root; public script; reports of root compromises; CERT also addresses the general problem of trusting network-supplied host data | CVE-1999-0048 | Confirmed | [1][6] |
| CA-97.05 | 28 Jan | sendmail 8.8.3 and 8.8.4 | MIME conversion overflow introduced in 8.8.3; a crafted e-mail runs commands as root; exploitable despite firewalls; fixed in 8.8.5 | CVE-1999-0047 | Confirmed | [1][6] |
| CA-97.06 | 6 Feb | rlogin | TERM copied into a buffer without due care; rlogin is set-uid root, so local root; patch, or turn off or wrap rlogin | CVE-1999-0046 (CWE-120 in NVD) | Confirmed | [1][10] |
| CA-97.07 | 18 Feb | nph-test-cgi shipped with some web servers | Remote users list files they are not authorized to see; issued for ongoing activity; phf still exploited; remove the script and check every cgi-bin directory | CVE-1999-0045 | Confirmed | [1][6] |
| CA-97.08 | 20 Feb | INN 1.5 and earlier | Crafted control messages run commands on the news server and can reach servers behind firewalls; numerous exploitation reports | CVE-1999-0043 | Confirmed | [1][6] |
| CA-97.09 | 7 Apr | University of Washington IMAP and POP | Login overflow gives remote root; intrusions still reported at the 4 Aug update; patch or upgrade to IMAP4rev1, else disable | CVE-1999-0042 | Confirmed | [1][6] |
| CA-97.10 | 24 Apr | Libraries using the Natural Language Service | Buffer overflow to root | CVE-1999-0041 (NVD date 13 Feb) | Confirmed | [1][10] |
| CA-97.11 | 1 May | X Toolkit (libXt) | Overflow in set-uid and set-gid X programs; fix X11R6.3 or remove the bits | not paired here | Confirmed | [1] |
| CA-97.12 | 6 May | IRIX webdist.cgi | Local and remote users run commands; joint CERT/CC and AUSCERT advisory | CVE-1999-0039 (record cites CA-1997-12; CWE-77 in NVD) | Confirmed | [1][6][9] |
| CA-97.13 | 7 May | xlock | Overflow to root | not paired here | Confirmed | [1] |
| CA-97.14 | 21 May | metamail through 2.7 | A MIME sender makes the receiver run a command | not paired here | Confirmed | [1] |
| CA-97.15 | 28 May | SGI login LOCKOUT | Local privilege flaw | not paired here | Confirmed | [1] |
| CA-97.16 | 29 May | ftpd signal handling | Regular and anonymous users read or write files as root | not paired here | Confirmed | [1] |
| CA-97.17 | 29 May | suidperl in Perl 4 and 5 | Overflow gives local root; being actively exploited | CVE-1999-0034 | Confirmed | [1][6] |
| CA-97.18 | 12 Jun | at(1) | Overflow; any user runs commands as root | not paired here | Confirmed | [1] |
| CA-97.19 | 25 Jun | BSD lpr | Overrun to local root; exploit public for some time, recently actively exploited; reprint of AUSCERT AA-96.12 | CVE-1999-0032 | Confirmed | [1][6] |
| CA-97.20 | 8 Jul | JavaScript in several browsers | A script monitors URLs visited, form data including passwords, and cookie values beyond its page, behind firewalls and on HTTPS pages; patch or disable JavaScript | CVE-1999-0031 | Confirmed | [1][6][10] |
| CA-97.21 | 16 Jul | IRIX df, pset, eject, login/scheme, ordist, xlock | Six overflows; exploited in many incidents, by the annual report | not paired here | Confirmed | [1][3] |
| CA-97.22 | 13 Aug | BIND before 4.9.6 | Cache poisoning now being exploited; with the mapping changed, traffic between hosts may be inspected, captured or corrupted; supersedes CA-96.02 | CVE-1999-0024 | Confirmed | [1][6][8] |
| CA-97.23 | 15 Jan 1998 as printed | rdist | Overflow to root; numbered in the 1997 series | not paired here | Confirmed | [1][3] |
| CA-97.24 | 5 Nov | Count.cgi | Overrun in a very widely used hit counter lets attackers run commands; from AUSCERT AA-97.27 of 31 Oct | CVE-1999-0021 | Confirmed | [1][6] |
| CA-97.25 | 10 Nov | CGI scripts that pass user data to a shell | Attackers run commands as the web server user; the problem lies in how scripts are written, not in the languages | not paired here | Confirmed | [1] |
| CA-97.26 | 5 Dec | statd | Overrun gives root locally and remotely without an account; from AUSCERT AA-97.29 | CVE-1999-0018 | Confirmed | [1][6] |
| CA-97.27 | 10 Dec | FTP servers | The PORT command makes a server open connections to ports of the attacker's choosing on hosts the attacker cannot reach; RFC compliant behavior discussed for several years | CVE-1999-0017 | Confirmed | [1][6][10] |
| CA-97.28 | 16 Dec | IP stacks | Teardrop (overlapping fragments, no workaround) and Land (a spoofed SYN whose source equals its destination); several sites attacked; filter spoofed packets for Land; vendor appendix lists Microsoft post-SP3 Windows NT 4.0 hotfixes | CVE-1999-0015 (Teardrop), CVE-1999-0016 (Land) | Confirmed | [1][6][8] |

### What the advisories say about attackers

Read in order, the 28 advisories split into four groups (Inferred). Network daemons that run as root, sendmail, INN, IMAP and POP, talkd and statd, give remote command execution, most of it with exploitation already reported (Confirmed [1]). Set-uid utilities, newgrp, csetup, rlogin, NLS libraries, libXt, xlock, SGI login, ftpd, suidperl, at, lpr, the six IRIX programs and rdist, give local root, and CERT notes public exploit information for most of them (Confirmed [1]). Web scripts, nph-test-cgi, webdist.cgi, Count.cgi and badly written CGI scripts in general, let a remote visitor list files or run commands (Confirmed [1]). The rest concern trust and availability: BIND cache poisoning, the JavaScript flaw, FTP bounce, and Teardrop and Land (Confirmed [1]).

Australia's AUSCERT supplied the text or the joint authorship of at least ten: FLEXlm, newgrp, csetup, talkd, SGI login, ftpd, webdist.cgi, lpr, Count.cgi and statd (Confirmed [1]). The FLEXlm case is a reminder that vendors shipped the daemon configured to run as root, sometimes without the administrator knowing it was installed (Confirmed [1]).

### Mail and news through the firewall

The year's remote root flaws in mail and news share one property CERT spelled out: the traffic is supposed to pass the firewall. CA-97.05 warned that the sendmail MIME overflow could be exploited despite firewalls, and CA-97.08 that crafted INN control messages could reach news servers behind them (Confirmed [1]). CA-97.14 extended the problem to the mail client, where metamail would run a command chosen by the sender (Confirmed [1]). The annual report's activity list puts the IMAP and INN waves first and second, with a special CERT Summary for each (Confirmed [3]).

### The web script as front door

The annual report says CGI scripts continued to be exploited in 1997 as in 1996, phf the most reported, first to fetch password files and now to run "a broad range of commands", with php also exploited (Confirmed [3]). CERT issued four web-script advisories that year: nph-test-cgi in February, webdist.cgi in May, Count.cgi in November and CA-97.25 on sanitizing user input, with a tech tip on how to do it (Confirmed [1]). Later CVE records carry CWE-77 for webdist.cgi (Demonstrated [9]).

### Trust in names and in pages

CA-97.04 turned DNS data into remote root through talkd, and CERT used the advisory to warn about the general problem of trusting host data that arrives over the network (Confirmed [1]). In August CA-97.22 reported that BIND cache poisoning was being exploited and that, once a name-to-address mapping is changed, traffic between hosts may be inspected, captured or corrupted (Confirmed [1]). The later CVE record describes the flaw as poisoning by predictable query IDs (Confirmed [10]). In July CA-97.20 showed the same failure in the browser: a script could watch URLs visited, form data and cookies outside its own page, on HTTPS pages and behind firewalls (Confirmed [1]). The German ActiveX demonstration in February, as relayed in RISKS, made the point for signed controls and personal finance software (Reported [64]).

### Availability

CERT/CC's annual report describes denial-of-service reports as "more frequent and varied", with intruders using IP spoofing to hide where packets came from, and UDP packet storms; CERT published a Denial of Service tech tip (Confirmed [3]). Cisco's advisory of 21 November said the public land.c program could deny service on classic IOS routers, IOS/700 devices (which needed a physical reset), Catalyst 5000 and 2900 switches and BPX and IGX management ports, while PIX and Centri were not affected; Cisco had multiple reports (Confirmed [5]). CA-97.28 on 16 December covered Teardrop and Land, two widely available tools, with several reports of sites attacked: Land could be stopped by filtering spoofed packets, Teardrop had no workaround, and CERT recommended that sites and providers drop outgoing packets whose source address is not internal, citing the ingress filtering paper that RFC 2267 published in January 1998 (Confirmed [1][58]). NVD's record for WinNuke, a Windows 95 and NT crash through out-of-band data on the NetBIOS port, carries a bulk 1 July 1997 date; Microsoft's numbered bulletins begin only with MS98-001 on 1 June 1998 (Confirmed [8][12]).

### The later CVE record

NVD API queries for records published in 1997 return 253, all CVE-1999 ids, one of them rejected; 41 carry the date 1 January and 17 the date 1 July, which look like bulk placeholders; only 16 carry a specific CWE; and 36 name Windows, IIS, Internet Explorer, NetBIOS or Outlook (Demonstrated [9]). The specific CWEs NVD lists on 1997-dated records include CWE-120, CWE-119, CWE-125, CWE-77 and CWE-364 (Demonstrated [9]). NVD's dates follow disclosure loosely: CVE-1999-0015 (Teardrop) is dated 16 December 1997, CVE-1999-0016 (Land) 1 December, CVE-1999-0024 (BIND) 13 August and CVE-1999-0153 (WinNuke) 1 July, each with CWE NVD-CWE-Other and a CVSS v2 score of 5.0 (Confirmed [8]). Some dates come before the advisory: the NLS record is dated 13 February, ten weeks before CA-97.10 (Inferred [10]). One record that looks like 1997 is not: CVE-1999-0278, the IIS ::$DATA source disclosure, is dated 30 March 1998 and cites MS98-003 (Confirmed [7]).

### Counting incidents

From January through December 1997 CERT/CC received 39,626 e-mail messages and 1,058 hotline calls, received 326 vulnerability reports and handled 2,134 incidents affecting more than 146,484 sites; in 1996 the figures were 2,573 incidents and more than 10,700 sites (Confirmed [3][4]). The report lists the year's intruder activity in eight items: IMAP scans, denial of service, CGI exploits, INN attacks, daily root compromises (13 percent of fourth-quarter incidents), Linux root compromises on unpatched systems, more IRIX overflow exploitation, and IRC clients or servers installed after root compromise (Confirmed [3]). These are reports handled, not attacks, and the site count is not defined in the report (Inferred).

## Part 3: scanning and attack knowledge

The IMAP wave was the first activity CERT/CC named for 1997, and it describes "large-scale, automated scans against many networks" (Confirmed [3]). On 1 September Phrack 51 carried Fyodor's "The Art of Port Scanning", which introduced nmap, a Linux port scanner distributed as source, and listed its scan types: TCP connect, SYN, FIN, FTP bounce, fragmented, UDP, ICMP ping sweep and reverse-ident scanning (Confirmed [13]). It is described here at title level only. The FTP bounce scan appeared three months before CERT's FTP bounce advisory, a protocol behavior CERT said had been discussed for several years and was RFC compliant (Confirmed [13][1]); that a design weakness became a scanner feature the same year is this study's reading (Inferred).

Public exploit code ran ahead of the fixes. CERT notes a public script or public exploit information for talkd, newgrp, lpr, the IRIX set and most of the local root flaws, and the annual report says many of the daily root compromises were on systems whose advisories were already out (Confirmed [1][3]). Intruders who got root installed IRC clients or servers (Confirmed [3]).

## Part 4: crime, insiders and prosecutions

### Card data and phishing

On 21 May 1997 Carlos Felipe Salgado Jr. was arrested at San Francisco Airport after selling undercover FBI agents data on more than 100,000 credit-card accounts for $260,000; the *San Francisco Chronicle*, as relayed in RISKS, said the data was taken by hacking company databases or by sniffing traffic at a San Diego provider (Reported [69]). The AP reported on 26 August that he had pleaded guilty before trial, facing a reported maximum of 30 years and $1 million (Reported [73]). In July more than 2,300 customers of ESPN SportsZone and NBA.com received anonymous e-mail showing the last eight digits of their card numbers and calling the sites' security careless; no fraud was reported (Reported [71]). In August AOL subscribers received e-mail posing as AOL Member Services that linked to a fake letter from the chairman asking for name, address, phone and card number, an early phishing campaign in the *Washington Post*'s account (Reported [73]). The library's [e-commerce threats study](/case-studies/ECOMMERCE_THREATS.md) takes the payment-card story from 1999; these three items are its 1997 antecedents (Inferred).

### Insiders

A fired subcontractor on a California Department of Information Technology system was arrested in January on three felony charges for allegedly trying to destroy it, and was suspected of building a remote backdoor (Reported [63]). Federal prosecutors in New York charged in November that a former Forbes employee, dismissed on 21 April 1997, broke into the company's systems and sabotaged them; Forbes estimated the damage at more than $100,000, and the defendant denied the charges (Reported [75]). Late in April a hard drive stolen from Levi Strauss held records on about 20,000 current and 20,000 former employees, including SSNs, birth dates and some retiree bank account numbers (Reported [68]).

### Emergency services

The FBI reported in March that a Swedish intruder had dialed into 11 north Florida 911 systems, tying up lines and connecting operators to each other; he was convicted of a misdemeanor in Sweden, which had no electronic-intrusion law (Reported [66]).

### The courts

*United States v. Czubinski*, decided by the First Circuit on 21 February 1997, reversed an IRS employee's conviction on nine wire fraud and four 18 U.S.C. 1030(a)(4) counts: unauthorized browsing of taxpayer files, without more, could not sustain the felony (Confirmed [25]). *CompuServe Inc. v. Cyber Promotions, Inc.*, decided on 3 February, extended the October 1996 temporary restraining order into a preliminary injunction against a bulk unsolicited e-mail sender after CompuServe's technical blocking had failed (Confirmed [26]). In the UK, the charges over the Griffiss AFB and Lockheed intrusions against the defendant known as Kuji were dropped in November, while Richard Pryce ("Datastream Cowboy") had been fined 1,200 pounds earlier in the year (Reported [76]).

### Mitnick (summary)

Kevin Mitnick's case is told in the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md), which carries the 1997 row. On 27 June 1997 he was sentenced to 22 months, 14 for violating his 1989 supervised release and 8 for the North Carolina access device fraud (Reported [27][29]). The Ninth Circuit affirmed the sentence and its supervised-release conditions, entered on his 18 U.S.C. 1029(a)(3) guilty plea, on 20 May 1998 (Confirmed [28]). In December an intruder altered Yahoo's page for several minutes with a note demanding his release (Part 5).

### Copyright and the cost estimates

The No Electronic Theft Act of 16 December 1997 made willful reproduction or distribution of copyrighted works, including by electronic means, a crime without a commercial motive where the retail value passes $1,000 in 180 days, and defined "financial gain" to include receiving other copyrighted works (Confirmed [30][31]). Senate investigators' estimate that hackers cost businesses about $800 million worldwide in 1995, more than $400 million in the US, and that few breaches are reported, reached RISKS in November with its date lost in the digest (Reported [75]).

## Part 5: web incidents and defacements

The defacement run that had hit the Justice Department, the CIA, NASA and the Air Force in 1996 (Reported [62]) went on in 1997 (Reported [65][70][77]). On the night of 4 to 5 March NASA's home page was replaced with a message from a group calling itself H4G1S promising attacks on "corporate America", and the site was taken offline (Reported [65]). Around 22 June an intruder disrupted Microsoft's web site for about 10 minutes through a flaw in Microsoft's own server software, and Microsoft posted a fix (Reported [70]). In August the Swedish "Crack a Mac" contest server, with a prize of 100,000 kronor, was broken through a hole in a third-party web plug-in that was patched in a little over a day (Reported [72]). In early December Yahoo's page was altered for several minutes with a note demanding Mitnick's release and claiming a "logic bomb/worm"; no virus was found and the hole was patched (Reported [77]).

Two web events were not attacks but belong in the record. On German television in February, hackers linked to the Chaos Computer Club showed an ActiveX control that, when its page was visited in Internet Explorer, drove Quicken to set up a transfer to their account; Microsoft Germany suggested disabling ActiveX for electronic fund transfer (Reported [64]). On 19 August an InterNIC clerical error made NASDAQ unreachable for most Internet users for several hours (Reported [73]).

## Part 6: viruses

### Office 97 changes the macro problem

*Virus Bulletin*'s February editorial reported that Office 97 reached North American shops on 16 January with VBA5 in every application. Word 8.0 refused to convert recognized Concept and Wazzu variants and by default warned about, and disabled, WordBasic macros on opening, but macros converted to VBA5 would not be detected by the anti-virus products of the day (Confirmed [19]). F-Secure's record calls WM/Concept extremely widespread from 1995 to 1997 (Confirmed [18]).

### The year in samples

- **ShareFun.** Loosely based on Wazzu and found in the wild in the USA in February, it mailed an infected attachment to three random entries in the local Microsoft Mail alias list when Mail was running (Confirmed [14]). It is described here at the level of the vendor record.
- **Bliss.** In early February a Linux user reported a Bliss infection on BugTraq; *Virus Bulletin* rebutted a vendor's "first Linux virus" press release but said Linux users were, basically for the first time, at risk (Confirmed [20]).
- **WM/CAP.** Reported in the wild in several countries in 1997 (Confirmed [17]). *Virus Bulletin* said, citing French sources, that in June all the major French corporations seemed to have contracted WM/CAP.A, some with more than 8,000 infected files (Reported [22]).
- **Esperanto.** It infected DOS, Windows 3.x and Windows 95 and NT executables and carried a Mac dropper; its Mac version was the first new Mac virus in over two years when found in November (Confirmed [15]).
- **Win32.Cabanas.** In November *Virus Bulletin* wrote that 1997 seemed to be the year of the Windows 95 virus breakthrough and that no Win32 virus had worked under Windows NT until Cabanas, written by the author of WM/CAP, a member of the 29A group (Confirmed [23]). F-Secure's record calls it a roughly 3,000-byte virus for NT, 95 and Win32s, found late in 1997 and not known in the wild (Confirmed [16]).

### Prevalence

*Virus Bulletin*'s October 1997 table holds 697 reports with WM/CAP.A first at 145 (20.8 percent) (Confirmed [24]). The named macro rows add to 348 of 697, about 50 percent, against about 26 percent in October 1996 (Demonstrated [24]). The defensive market moved with it: *Virus Bulletin* reviewed anti-virus products for Windows NT in January, March and May and ran its second Windows 95 comparative in May, measuring on-access scanning overhead (Confirmed [21]).

## Part 7: the state and exercise record

### Eligible Receiver 97

A Joint Chiefs of Staff J-5 tasking dated 10 June 1997, declassified and marked EXERCISE on every page, set the scenario: more than a dozen electronic attacks on US power systems over the previous days, and physical attacks on satellite tracking sites in Guam and Hawaii in which four civilian hostages were taken. It asked for response options on the assumption that Iran, North Korea and Cuba were linked; the states are scenario roles, not real attackers (Confirmed [38]). The National Security Archive catalogues Crisis Action Team activation orders and memos dated 9 and 10 June, a "National Pride Update" of 11 June and JCS briefing slides titled "Eligible Receiver 97-1" (Confirmed [37]).

In the Archive's account an NSA Red Team played North Korean, Iranian and Cuban forces against an interagency Blue Team, aimed at critical infrastructure and military command and control in three phases (infrastructure, command and control, and kinetic attacks, including a simulated hijacking at sea of the MV National Pride), and used off-the-shelf equipment and tools commonly available on the Internet (Reported [37]). The Red Team's targeting officer said in the NSA after-action video that the Blue Team was on the run by the third day and that the Red Team had played only about 30 percent of what it could have, and the Archive says the penetration was enough to "significantly affect" command and control (Reported [37]). The heavily redacted Final Observation Report, as the Archive transcribes it, says power systems and DoD computer systems were attacked in the simulation, that the red team exploited simple passwords, improper network configuration and poor operational security around system IP names, and that DoD and Justice Department goals conflicted over captured material; the PDF is a scanned image, so these quotes are as the Archive gives them (Reported [39]). A separate memo set the National Reconnaissance Office's objective as testing its recovery from an interruption to national systems data flow (Reported [39]).

The Archive, citing Jason Healey's *A Fierce Domain*, credits the exercise with the INFOCON scheme, with Joint Task Force Computer Network Defense in December 1998 and eventually with US Cyber Command, and says its results were briefed to the writers of the PCCIP report (Reported [37]). A Joint Chiefs presentation of about 1999 says the real February 1998 Solar Sunrise intrusions "Confirmed ELIGIBLE RECEIVER findings", among them unresolved legal issues and no effective indications and warning (Reported [40]). The Justice Department's release of 18 March 1998 on Solar Sunrise said no classified information was compromised and there was no sign of a state-sponsored campaign; that case has its home in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Confirmed [41]).

### Moonlight Maze (summary)

Moonlight Maze is told in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md). Kaspersky's GReAT and King's College London report that from 1996 its operators were rummaging through military, research and university networks, mainly in the US, with samples compiled as far back as late 1996 and a visibility window of 1998 to 1999; their post does not mention 1997 (Confirmed [42]). They report victims including the Pentagon, NASA and the Department of Energy (Reported [42]). They name no country, call the link to Turla, "a prolific Russian-speaking group", circumstantial and say a conclusion is premature (Confirmed [42]). ATT&CK's [Turla page (G0010)](/mitre/groups/G0010.md) dates the group's victims from at least 2004 and does not mention Moonlight Maze (Confirmed [44]). 1997 falls inside the campaign's span with no dated event, so no technique in Part 11 rests on it (Inferred [47]).

### Equation (summary)

The Equation group's record is in the [United States study](/case-studies/THREAT_ACTORS_UNITED_STATES.md), and the [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) records its earliest infrastructure. Kaspersky reported in February 2015 a command-and-control domain registered in August 2001, earliest samples compiled in 2002 and other C&C domains registered as early as 1996, which "could indicate" activity over almost two decades; it names no country and dates nothing to 1997 (Confirmed [43]). ATT&CK's [Equation page (G0020)](/mitre/groups/G0020.md) lists four techniques, T1480.001, T1564.005, T1120 and T1542.002, and gives no start year; none is evidenced for 1997 (Confirmed [45]).

### A disclosure about 1990 to 1991

In March 1997 a former Department of Energy security head, Eugene Schultz, told the BBC that Gulf War era intruders from Eindhoven had entered systems at 34 US military sites and offered the data to Iraq (Reported [67]). The intrusions date from 1990 to 1991; 1997 is only the date of the account.

No opened primary attributes a 1997 intrusion to a state (Inferred).

## Part 8: law and policy

### Critical infrastructure

Executive Order 13010 of 15 July 1996 had created the PCCIP and named eight critical infrastructures, separating physical from cyber threats (Confirmed [32]). On 27 February 1997 the Commission's comments desk posted its remit to RISKS: telecommunications, transportation, electric power, oil and gas, banking and finance, water, emergency services and continuity of government (Confirmed [33]). CERT/CC staff sent the Commission a report on Internet threats in January (Confirmed [3]). The Commission issued *Critical Foundations: Protecting America's Infrastructures* in October 1997, as the White House PDD-63 fact sheet of May 1998 and a GAO report of September 1998 both record (Confirmed [35][36]). The government library abstract of the 192 pp. report says the Commission found no immediate threat sufficient to warrant fear of imminent national crisis but steadily increasing vulnerability, and recommended information sharing between owners and government, clearinghouses, a real-time attack-warning capability, education, legal streamlining and government-led research (Confirmed [34]). GAO summarizes the report as saying the federal government must lead by example and recommending better government systems security, encryption, risk assessment methods, performance measures and threat assessment as a foreign intelligence priority (Confirmed [36]). The report itself was not opened.

### Federal security as a high-risk area

In its February 1997 High-Risk Series GAO designated federal information security a new government-wide high-risk area; during the year the CIO Council made information security one of six priority areas and late in the year set up a Security Committee (Confirmed [36]). On 16 September the House passed H.R. 1903, the Computer Security Enhancement Act of 1997, amending the NIST Act; its findings say encryption development should be driven by the market (Confirmed [54]). Whether it was enacted was not checked.

### The Internet, speech and commerce

On 26 June the Supreme Court decided *Reno v. ACLU*, holding that the Communications Decency Act's indecent transmission and patently offensive display provisions abridge the freedom of speech (Confirmed [51]). On 1 July the White House released *A Framework for Global Electronic Commerce* with a presidential directive and a message to Internet users; its Security principle asks for secure networks, protected attached systems, authentication and confidentiality, encourages a voluntary, market-driven key management infrastructure and calls strong encryption a double-edged sword (Confirmed [52]). The Framework records that the IITF's Information Policy Committee had issued a draft paper on promoting privacy on the national information infrastructure in April (Confirmed [53]).

### Encryption export

On 25 August the district court in San Francisco ruled in *Bernstein v. Department of State* that parts of the export controls on encryption software are unconstitutional; the next day the Justice Department said it was reviewing the ruling, that the controls stayed in place, and pointed to the 1996 *Karn* decision upholding them (Confirmed [49]). On the evening of 28 August Judge Marilyn Hall Patel stayed her ruling to 8 September and said that, pending appeal, she would limit its effect to the plaintiff and his program (Confirmed [50]).

### Crossing borders

On 9 December the Justice Department announced the first meeting of the Justice and Interior Ministers of the Eight on transnational high-tech crime (Confirmed [55]). The Attorney General's statement of 10 December lists the commitments: trained high-tech crime staff, 24-hour points of contact, faster tracing of network attacks, prosecution of nationals who cannot be extradited, preservation of electronic evidence, review of computer crime laws and work with industry (Confirmed [56]).

### Copyright

The NET Act, Pub. L. 105-147 (H.R. 2265), enacted on 16 December, is described in Part 4 (Confirmed [30]).

## Part 9: cryptography, standards and the response community

- **AES.** NIST announced the AES development effort on 2 January and issued its formal call for algorithms on 12 September: unclassified, publicly disclosed, royalty-free worldwide symmetric block ciphers with 128-bit blocks and 128, 192 and 256-bit keys (Confirmed [48]).
- **DES challenge.** RSA's 56-bit DES challenge key was recovered by late June after about four months of brute force, searching about a quarter of the keyspace, as relayed in RISKS (Reported [70]).
- **FIPS 196**, Entity Authentication Using Public Key Cryptography, with two challenge-response protocols, published 18 February and withdrawn in 2015 (Confirmed [61]). NIST SP 800-15 is dated January 1998 and is not a 1997 record (Confirmed [61]).
- **RFCs.** RFC 2065 DNS Security Extensions and RFC 2069 HTTP Digest Access Authentication (January); RFC 2104 HMAC and RFC 2109 HTTP State Management, the cookie specification (February); RFC 2138 RADIUS (April); RFC 2196 Site Security Handbook, FYI 8, edited at SEI and obsoleting RFC 1244 (September); RFC 2222 SASL and RFC 2228 FTP Security Extensions (October) (Confirmed [57]). RFC 2267 on ingress filtering (January 1998), TLS 1.0 in RFC 2246 (January 1999) and RFC 2350 (June 1998) are not 1997 records, though CERT cited the ingress paper in December 1997 (Confirmed [58]).
- **IAB workshop.** The IAB Security Architecture Workshop met on 3 to 5 March at Bell Labs, Murray Hill, with a CERT/CC staff member among 25 participants (Confirmed [59][3]).
- **Secure Shell.** The IETF secsh working group was proposed on 14 February and started on 20 February (Confirmed [60]).
- **Response teams.** The 9th FIRST conference met in Bristol in June with 159 people from 23 countries, and FIRST had 66 member teams by December (Confirmed [3]). FedCIRC, set up in 1996 by NIST, CERT/CC and CIAC, held a two-day Intrusion Detection Workshop for federal agencies and its first Annual Workshop on 20 to 21 November (Confirmed [3]).
- **Hardware.** The Pentium "F00F" flaw let a single unprivileged instruction halt the processor, and Intel confirmed that malicious code could crash a system (Reported [74]).

## Part 10: the defender view

The year's defensive record is mostly CERT's remediation advice, its own new programs, and the standards that followed the attacks (Inferred).

**Patch the network-facing daemons first.** sendmail 8.8.5, BIND 4.9.6, IMAP4rev1 and INN 1.5.1 closed the year's largest remote root holes; where an upgrade was not possible, CERT's advice was to disable the service (Confirmed [1]).

**Remove and rewrite web scripts.** Remove nph-test-cgi and check every cgi-bin directory; sanitize user input in scripts, because the fault is in the script (Confirmed [1]).

**Reduce set-uid exposure.** Patch the local root flaws and, where no patch exists, remove set-uid and set-gid bits or turn off or wrap the program (Confirmed [1]).

**Filter at the edge, both ways.** CA-97.28 asked sites and providers to drop spoofed inbound packets and outbound packets whose source is not internal; Teardrop still had no workaround (Confirmed [1]).

**Limit active content.** CERT advised patching or disabling JavaScript, and Microsoft Germany suggested disabling ActiveX for fund transfers (Confirmed [1]; Reported [64]).

**Scan documents.** Office 97 disabled WordBasic macros on opening, and *Virus Bulletin*'s reviews moved to Windows NT and on-access scanning (Confirmed [19][21]).

**Detect and verify.** CERT/CC published its Intruder Detection Checklist and its first two security improvement modules, Detecting Signs of Intrusion (SEI-SIM-001) and Security for a Public Web Site (SEI-SIM-002), and distributed Tripwire, MD5 and TCP wrappers (Confirmed [3]). FedCIRC's Intrusion Detection Workshop is the year's only primary trace of intrusion detection as a federal program in the record opened (Confirmed [3]; Inferred).

**Build it right.** CERT/CC said it had begun to identify the engineering and administration practices that create vulnerabilities, because only defensive development would reduce the haphazard, reactive use of patches, and that it was working with more than 40 vendors on as-shipped security (Confirmed [3]).

**Test the organization.** Eligible Receiver's findings, as the Archive gives them, were simple passwords, poorly configured networks and no effective indications and warning (Reported [39][40]).

## Part 11: MITRE mappings

No 1997 record carries an ATT&CK, CAPEC or CWE id: CVE began in 1999; MITRE's first CWE release came in 2006; CAPEC was first released in 2007 under the DHS Software Assurance initiative; and ATT&CK's first model dates from September 2013, with a public release in May 2015 of 96 techniques (Confirmed [11][78][79][80]). D3FEND is funded by the NSA Cybersecurity Directorate and managed by the MITRE-operated National Security Engineering Center (Confirmed [81]). Every binding below is therefore this study's later mapping (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `technique_to_d3fend.jsonl`, `data/weaknesses/cwe.jsonl`, `capec.jsonl`) and the generated pages under `mitre/` on 12 and 13 November 2026 (Demonstrated [82][83][84][85][46]). Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md): **Described** means a primary source describes the behavior and this study assigns the id; **Reported** means only a secondary source supports the behavior; **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading. No row is **Listed**, because no 1997 source prints an id.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | reconnaissance | Described | Large-scale automated scans for the IMAP and POP flaw, all year (CA-97.09, 7 Apr; CS-97.04) | [3][1] |
| [`T1595.001`](/mitre/techniques/T1595-001.md) | Scanning IP Blocks | reconnaissance | Inferred | The same scans, run "against many networks" | [3] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Inferred | nmap published in Phrack 51, 1 Sep (a tool's publication, not a dated intrusion) | [13] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | sendmail MIME (28 Jan), nph-test-cgi (18 Feb), INN (20 Feb), IMAP and POP (7 Apr), webdist.cgi (6 May), Count.cgi (5 Nov), CGI input (10 Nov); phf still exploited | [1][3] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Inferred | talkd (27 Jan) and statd (5 Dec) give remote root (the record names no lateral movement) | [1] |
| [`T1059.004`](/mitre/techniques/T1059-004.md) | Unix Shell | execution | Described | Commands run on news and web servers through INN control messages, webdist.cgi and unsanitized CGI input | [1] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Described | newgrp (7 Jan), rlogin (6 Feb), xlock (7 May), suidperl (29 May), at (12 Jun), lpr (25 Jun), the IRIX set (16 Jul), statd (5 Dec) | [1][3] |
| [`T1548.001`](/mitre/techniques/T1548-001.md) | Setuid and Setgid | privilege-escalation | Inferred | Set-uid root programs abused, and CERT's fallback of removing the bits (libXt, 1 May) | [1] |
| [`T1499.004`](/mitre/techniques/T1499-004.md) | Application or System Exploitation | impact | Described | Land against Cisco devices (21 Nov); Teardrop and Land (16 Dec); WinNuke (NVD record dated 1 Jul) | [5][1][8] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | UDP packet storms and spoofed denial-of-service reports through the year | [3] |
| [`T1557`](/mitre/techniques/T1557.md) | Adversary-in-the-Middle | credential-access, collection | Inferred | BIND cache poisoning, so traffic may be inspected, captured or corrupted (13 Aug; a loose fit at the parent) | [1] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Inferred | A visited page's script watches the user (CA-97.20, 8 Jul); the hostile ActiveX demonstration (Feb, Reported) | [1][64] |
| [`T1185`](/mitre/techniques/T1185.md) | Browser Session Hijacking | collection | Inferred | CA-97.20: URLs visited and form data read outside the page's context | [1] |
| [`T1539`](/mitre/techniques/T1539.md) | Steal Web Session Cookie | credential-access | Inferred | CA-97.20: cookie values read outside the page's context | [1] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | metamail runs a command chosen by the sender (21 May) | [1] |
| [`T1090`](/mitre/techniques/T1090.md) | Proxy | command-and-control | Inferred | FTP bounce: a server opens connections the attacker cannot make directly (10 Dec; a loose fit) | [1] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | ShareFun spreads through infected attachments (Feb); WM/CAP in the wild | [14][17] |
| [`T1137.001`](/mitre/techniques/T1137-001.md) | Office Template Macros | persistence | Inferred | Word macro viruses led by WM/CAP.A (October table; the template mechanism is not described in the sources opened) | [24] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Inferred | IRC clients or servers installed after root compromise | [3] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | impact | Reported | NASA (4 to 5 Mar), Yahoo (early Dec) | [65][77] |
| [`T1598`](/mitre/techniques/T1598.md) | Phishing for Information | reconnaissance | Reported | E-mail posing as AOL Member Services asks for card numbers (Aug) | [73] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Reported | Card data reportedly taken in part by sniffing a San Diego provider (arrest 21 May) | [69] |

Left out on purpose: T1584.002 DNS Server, which the library links to DNS cache poisoning through CAPEC-142 but which describes acquiring a server, not corrupting a victim's resolver (Inferred [83]); the Microsoft site disruption, whose source does not say what was done; the Forbes and California insider cases, whose sources say sabotage without saying how; the F00F flaw and the DES challenge, which are a processor bug and cryptanalysis rather than adversary behavior ATT&CK models; the Florida 911 case, whose method beyond dialing in is not given; and Eligible Receiver, a red-team exercise whose redacted record names no technique and which is not an adversary operation (Inferred).

### ATT&CK for ICS techniques

None. Eligible Receiver's scenario includes attacks on power systems, but they were exercise injects, and no 1997 intrusion into an industrial control system appears in any primary opened (Confirmed [38]; Inferred). No ICS layer is published.

### ATT&CK groups, software and campaigns

None. The library's ATT&CK data holds no Moonlight Maze or Eligible Receiver object in its campaigns, groups or software files (Confirmed [46]). Moonlight Maze reaches an ATT&CK id only through the unproven Turla lineage: the [Turla page (G0010)](/mitre/groups/G0010.md) dates the group from at least 2004, lists [Penquin (S0587)](/mitre/software/S0587.md) and does not mention Moonlight Maze (Confirmed [44]). The library's home study maps Multi-hop Proxy and compromised servers to Moonlight Maze relays dated 1998 to 1999, not 1997 (Inferred [47]). [Equation (G0020)](/mitre/groups/G0020.md) is named only for the infrastructure its home studies record from 1996 (Confirmed [43][45]). One name collision needs a warning: the library's software page `S0560` TEARDROP is a memory-only dropper from the SolarWinds intrusion, not the 1997 fragmentation tool, and this study does not link it (Inferred [86]). Salgado, ShareFun, CAP, Cabanas, Esperanto, Bliss, nmap, Teardrop and Land have no ATT&CK objects (Inferred).

### CWE and CAPEC

Rows marked "as NVD lists it" use the CWE that NVD prints on the later CVE-1999 record (Demonstrated [9]; Confirmed [10]). Every other CWE is this study's binding (Inferred). The CAPEC column says which pairings the library's data makes and which are this study's own [83][85].

| CWE | Weakness (library name) | 1997 record | CAPEC |
|---|---|---|---|
| CWE-120 | Buffer Copy without Checking Size of Input (as NVD lists it for rlogin; this study's binding for xlock) | CA-97.06 rlogin TERM, 6 Feb; CA-97.13 xlock, 7 May | [CAPEC-10](/mitre/capec/CAPEC-10.md) Buffer Overflow via Environment Variables and [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers (the library relates both to CWE-120) |
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer (NVD lists it on 1997-dated records; this study's binding for the IRIX overflows) | CA-97.21, 16 Jul | [CAPEC-100](/mitre/capec/CAPEC-100.md) (the library relates it to CWE-119) |
| CWE-125 | Out-of-bounds Read (NVD lists it on 1997-dated records; this study's binding for the IRIX set) | CA-97.21, 16 Jul | None assigned |
| CWE-120, CWE-119 | (this study's binding) | CA-97.05 sendmail MIME conversion, 28 Jan | [CAPEC-42](/mitre/capec/CAPEC-42.md) MIME Conversion (the library relates it to CWE-120, CWE-119, CWE-74 and CWE-20) |
| CWE-77 | Improper Neutralization of Special Elements used in a Command (as NVD lists it for webdist.cgi) | CA-97.12, 6 May | [CAPEC-88](/mitre/capec/CAPEC-88.md) OS Command Injection as the nearest library pattern (this study's pairing) |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command | CA-97.25 CGI input, 10 Nov; CA-97.14 metamail, 21 May; CA-97.08 INN, 20 Feb | [CAPEC-88](/mitre/capec/CAPEC-88.md) (the library relates it to CWE-78) |
| CWE-364 | Signal Handler Race Condition (as NVD lists it for ftpd) | CA-97.16, 29 May | [CAPEC-26](/mitre/capec/CAPEC-26.md) Leveraging Race Conditions (this study's pairing; the library does not relate it to CWE-364) |
| CWE-250 | Execution with Unnecessary Privileges | CA-97.01 FLEXlm run as root; the set-uid root programs | [CAPEC-69](/mitre/capec/CAPEC-69.md) Target Programs with Elevated Privileges (the library relates it to CWE-250) |
| CWE-330 | Use of Insufficiently Random Values | CA-97.22 BIND, poisoning by predictable query IDs in the later record, 13 Aug | [CAPEC-142](/mitre/capec/CAPEC-142.md) DNS Cache Poisoning (the library relates it to CWE-345 and CWE-350 among others, not to CWE-330) |
| CWE-345, CWE-350 | Insufficient Verification of Data Authenticity; Reliance on Reverse DNS Resolution for a Security-Critical Action | CA-97.22 BIND; CA-97.04 talkd's trust in DNS data, 27 Jan | [CAPEC-142](/mitre/capec/CAPEC-142.md) (the library relates it to both) |
| CWE-346 | Origin Validation Error | CA-97.20 JavaScript, 8 Jul | [CAPEC-31](/mitre/capec/CAPEC-31.md) Accessing/Intercepting/Modifying HTTP Cookies (the library links it to T1539; the CWE pairing is this study's) |
| CWE-441 | Unintended Proxy or Intermediary | CA-97.27 FTP bounce, 10 Dec | No library pattern names FTP bounce; none is assigned |
| CWE-20 | Improper Input Validation (NVD lists NVD-CWE-Other for Teardrop and Land) | CA-97.28, 16 Dec; Cisco, 21 Nov | No library pattern fits: [CAPEC-25](/mitre/capec/CAPEC-25.md) Forced Deadlock is the library's only CAPEC for T1499.004 and does not describe fragment overlap or a self-addressed SYN; none is assigned |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | CA-97.07 nph-test-cgi file listing, 18 Feb; nmap's scan types, 1 Sep | [CAPEC-300](/mitre/capec/CAPEC-300.md) Port Scanning (links T1046), [CAPEC-287](/mitre/capec/CAPEC-287.md) TCP SYN Scan, [CAPEC-301](/mitre/capec/CAPEC-301.md) TCP Connect Scan, [CAPEC-302](/mitre/capec/CAPEC-302.md) TCP FIN Scan, [CAPEC-308](/mitre/capec/CAPEC-308.md) UDP Scan, [CAPEC-169](/mitre/capec/CAPEC-169.md) Footprinting (links T1595); the library relates each to CWE-200 |
| CWE-770 | Allocation of Resources Without Limits or Throttling | UDP packet storms and spoofed floods | [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding (the library relates it to CWE-770, T1498.001 and T1499) |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | ShareFun, CAP, Esperanto, Cabanas, Bliss | No clean CAPEC fit; none is assigned |
| none bound | (sniffing; phishing) | Salgado's reported sniffing; the AOL e-mail | [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (links T1040); [CAPEC-98](/mitre/capec/CAPEC-98.md) Phishing (links T1566 and T1598) |

NVD also lists CWE-17, CWE-255 and CWE-264 on four 1997-dated records; they are categories absent from the library's CWE data and are not linked (Demonstrated [9][85]).

### D3FEND countermeasures

Pairings come from `data/attack/technique_to_d3fend.jsonl` unless the row says the pairing is this study's; every page exists under `/mitre/d3fend/` (Demonstrated [84][46]).

| Technique from the record | D3FEND countermeasures | 1997 analogue |
|---|---|---|
| T1190 Exploit Public-Facing Application | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (library pairings); [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) is a concept match for removing nph-test-cgi and disabling IMAP and POP (this study's pairing) | Upgrades to sendmail 8.8.5, INN 1.5.1 and IMAP4rev1; script removal [1] |
| T1210 Exploitation of Remote Services | [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md), [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md) (library pairings) | Patches for talkd and statd [1] |
| T1068 and T1203 | [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md), [Process Code Segment Verification](/mitre/d3fend/process-code-segment-verification.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (library pairings); none appears in the 1997 advisories, whose fixes were patches (Inferred) | Vendor patches for the local root flaws and metamail [1] |
| T1548.001 Setuid and Setgid | [Access Modeling](/mitre/d3fend/access-modeling.md), [Configuration Inventory](/mitre/d3fend/configuration-inventory.md), [Restore Configuration](/mitre/d3fend/restore-configuration.md) (library pairings); [Local File Permissions](/mitre/d3fend/local-file-permissions.md) is a concept match for the set-uid audit (this study's pairing) | Removing set-uid and set-gid bits from X programs [1] |
| T1499.004 Application or System Exploitation | The library has no pairing. [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) and [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) are concept matches for CERT's spoofed-source filtering against Land (this study's pairings) | CA-97.28 filtering; Microsoft NT 4.0 hotfixes; Cisco fixes [1][5] |
| T1498.001 Direct Network Flood | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) (library pairings) | CERT's Denial of Service tech tip [3] |
| T1557 Adversary-in-the-Middle | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md) (library pairings); [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md) is a concept match the library maps to T1040, not T1557 | BIND 4.9.6; DNSSEC published as RFC 2065 [1][57] |
| T1189 and T1185 | [URL Analysis](/mitre/d3fend/url-analysis.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (library pairings for T1189); [Content Filtering](/mitre/d3fend/content-filtering.md) is a concept match for disabling JavaScript and ActiveX (this study's pairing) | CA-97.20 patch or disable JavaScript [1] |
| T1539 Steal Web Session Cookie | [Credential Hardening](/mitre/d3fend/credential-hardening.md), [Credential Revocation](/mitre/d3fend/credential-revocation.md), [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) (library pairings) | No 1997 counterpart in the record |
| T1204.002 and T1137.001 | [File Analysis](/mitre/d3fend/file-analysis.md), [Content Filtering](/mitre/d3fend/content-filtering.md), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md), [Emulated File Analysis](/mitre/d3fend/emulated-file-analysis.md) (library pairings) | Anti-virus scanning; Office 97 disabling WordBasic macros on opening [19][21] |
| T1105 Ingress Tool Transfer | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md) (library pairings) | CERT's Intruder Detection Checklist [3] |
| T1491.002 External Defacement | [Decoy Network Resource](/mitre/d3fend/decoy-network-resource.md), [Network Resource Access Mediation](/mitre/d3fend/network-resource-access-mediation.md) (library pairings) | CERT/CC's Security for a Public Web Site module [3] |
| T1040 Network Sniffing | The library maps only [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md). [One-time Password](/mitre/d3fend/one-time-password.md) is a concept match the library does not map to T1040 | The secsh working group, February [60] |

The library's data has no D3FEND pairing for T1595, T1046, T1059.004, T1090, T1499.004 or T1598, and none is invented here beyond the concept matches labelled above (Demonstrated [84]).

### Navigator layer

The study's techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-1997.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1997.json), listing the 22 techniques in the Enterprise table under each tactic they carry in v20.0, and listed on [the Navigator layers page](/navigator/index.md). Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping; no entry scores 100, because no 1997 source prints an id. Each entry's comment names the source numbers in the Sources table below. No ICS layer is needed.

## Cross-cutting themes

**Scale replaced the single intruder.** The year's headline activity was automated scanning for one mail-server flaw and mass attacks on news servers, and a general-purpose scanner went public in September (Confirmed [3][13]). The same pattern of mass exploitation after disclosure recurs in [Log4Shell](/case-studies/LOG4SHELL.md) and the [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md) (Inferred).

**Services that ran as root carried the risk.** Remote root came from daemons doing their normal job, and CERT's advice was to patch them or turn them off (Confirmed [1]). CERT/CC's call for defensive engineering instead of reactive patching is a theme the library's [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md) page takes up (Confirmed [3]; Inferred).

**The firewall was not the perimeter.** Mail, news and browser flaws reached hosts behind firewalls because the traffic they rode was allowed (Confirmed [1]).

**Documents became programs.** Office 97 shipped one macro language across the suite, and within a year macro viruses filled half of the named prevalence reports (Confirmed [19]; Demonstrated [24]). Trusted channels that carry code recur in the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies (Inferred).

**Government rehearsed and reorganized.** GAO's high-risk designation in February, Eligible Receiver in June and *Critical Foundations* in October all point the same way: toward warning, information sharing and defense of infrastructure (Confirmed [36][38][34]). Later infrastructure attacks run through the [Stuxnet study](/case-studies/STUXNET.md) and the [ICS attacks and advisories study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) (Inferred).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: "146,484 sites affected".** It is a fourteen-fold jump from 1996 while incidents fell, and the report does not define it; it probably counts targets of reported mass scans, not compromised hosts [3][4].
- **Overstated: CVE records dated 1997.** NVD's 253 records with 1997 dates were assigned after CVE began in 1999; 58 sit on two placeholder dates and some precede their advisories [9][10][11].
- **Overstated: any ATT&CK, CWE or CAPEC id on a 1997 event.** None of those programs existed until 2006 to 2015 [78][79][80].
- **Overstated: Eligible Receiver as a foreign attack.** North Korea, Iran and Cuba were scenario roles played by an NSA Red Team, and much of what is known about the results comes from later recollection and a redacted report [37][38][39].
- **Overstated: Moonlight Maze as a Russian operation in 1997.** The researchers who hold the evidence name no country, call the Turla link premature and date nothing to 1997 [42].
- **Overstated: the press figures.** Forbes's damage is the company's estimate, the $800 million is an investigators' estimate for 1995, and the Yahoo "logic bomb" was found not to exist [75][77].
- **Overstated: "first" claims.** The first Linux virus claim was rebutted by *Virus Bulletin* itself, and "first new Mac virus in over two years" and "the year of the Windows 95 virus breakthrough" are vendor and trade-press descriptions [20][15][23].
- **Overstated: Teardrop as the year's story.** CERT records several reports of sites attacked; root compromises through Unix daemons were far more numerous [1][3].
- **Understated: Microsoft platforms.** CERT's 28 advisories are almost all Unix, with only the JavaScript advisory touching Internet Explorer, yet 36 NVD records dated 1997 name Windows, IIS, Internet Explorer, NetBIOS or Outlook, and Microsoft's numbered bulletins begin only in June 1998 [1][9][12].
- **Understated: the CGI layer.** Four advisories in one year made web scripts a main way in, two years before CVE existed [1].
- **Understated: macro viruses.** The largest change users met, macro viruses passing half of the named reports, lives in the trade press and vendor virus descriptions, not in CERT/CC's advisories or annual report [24][14][17].
- **Understated: what was not seen.** Moonlight Maze ran across the year unseen, and Eligible Receiver stayed classified for years [42][37].
- **Understated: the defenders' tools.** Commercial firewall and intrusion detection products of the year are not in the primary record opened; FedCIRC's workshop and CERT/CC's detection module are the only traces [3].

### Discrepancies in the record

- **CA-97.23.** The SEI compilation prints its original issue date as 15 January 1998; CERT/CC's annual report lists it among 1997 advisories [1][3].
- **The Yahoo date.** The digest says "Monday night" and cites a *New York Times* Cybertimes story dated 7 December 1997, a Sunday; 8 December is likely but not confirmed [77].
- **NVD dates.** CVE-1999-0016 (Land) is dated 1 December, ten days after Cisco's advisory of 21 November and two weeks before CERT's of 16 December; the NLS record is dated 13 February against CA-97.10 on 24 April [8][10][5][1].
- **The PCCIP month.** The government library abstract gives only 1997; the PDD-63 fact sheet and GAO give October 1997 [34][35][36].
- **The Senate cost estimate.** The RISKS item's date was lost in the digest; it appears in a November 1997 issue and refers to 1995 [75].
- **Mitnick's sentence.** The 27 June 1997 date and terms rest on a book's companion site; the 1998 appeal decision is the primary record [27][28].
- **The Final Observation Report.** Its quotations come from the Archive's transcription of a scanned document whose page text was not checked [39].

## Sources

All sources were opened on 12 or 13 November 2026 as listed. Grade is the source's evidence grade as used in this study.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "1997 CERT Advisories" (compilation, CA-1997-01 to CA-1997-28) | https://www.sei.cmu.edu/documents/504/1997_019_001_496176.pdf | 2026-11-13 | Confirmed |
| 2 | CMU SEI, "1997 CERT Advisories" (landing page) | https://www.sei.cmu.edu/library/1997-cert-advisories/ | 2026-11-13 | Confirmed |
| 3 | CERT Coordination Center, 1997 Annual Report | https://www.sei.cmu.edu/documents/2336/1998_001_001_83538.pdf | 2026-11-12 | Confirmed |
| 4 | CMU SEI, CERT Coordination Center 1997 annual report summary | https://www.sei.cmu.edu/library/cert-coordination-center-1997-annual-report-summary/ | 2026-11-12 | Confirmed |
| 5 | Cisco Security Advisory cisco-sa-19971121-land, TCP Loopback DoS Attack (land.c) and Cisco Devices | https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-19971121-land | 2026-11-13 | Confirmed |
| 6 | CVE Program, cvelistV5 record CVE-1999-0016 (and the other CVE-1999 records named in Part 2) | https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/1999/0xxx/CVE-1999-0016.json | 2026-11-13 | Confirmed (records); Inferred (pairing, except CVE-1999-0039) |
| 7 | CVE Program, cvelistV5 record CVE-1999-0278 | https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/1999/0xxx/CVE-1999-0278.json | 2026-11-13 | Confirmed |
| 8 | NVD API, CVE-1999-0016 (and CVE-1999-0015, -0024, -0153) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-0016 | 2026-11-13 | Confirmed |
| 9 | NVD API, records published in 1997 (first of four date windows) | https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=1997-01-01T00:00:00.000&pubEndDate=1997-04-30T23:59:59.999 | 2026-11-12 | Demonstrated |
| 10 | NVD, CVE-1999-0015 (and the paired records named in Part 2) | https://nvd.nist.gov/vuln/detail/CVE-1999-0015 | 2026-11-12 | Confirmed (records); Inferred (pairing) |
| 11 | CVE, history (archived old website) | https://www.cve.org/Resources/Media/Archives/OldWebsite/about/history.html | 2026-11-12 | Confirmed |
| 12 | Microsoft Security Bulletin MS98-001 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-001 | 2026-11-12 | Confirmed |
| 13 | Phrack 51, "The Art of Port Scanning" | https://phrack.org/issues/51/the-art-of-scanning.html | 2026-11-12 | Confirmed |
| 14 | F-Secure, WordMacro/ShareFun | https://www.f-secure.com/v-descs/sharefun | 2026-11-13 | Confirmed |
| 15 | F-Secure, Esperanto | https://www.f-secure.com/v-descs/esperant | 2026-11-13 | Confirmed |
| 16 | F-Secure, Win32.Cabanas | https://www.f-secure.com/v-descs/cabanas | 2026-11-13 | Confirmed (record); Reported (authorship) |
| 17 | F-Secure, WordMacro/CAP | https://www.f-secure.com/v-descs/cap | 2026-11-13 | Confirmed |
| 18 | F-Secure, WM/Concept | https://www.f-secure.com/v-descs/concept | 2026-11-13 | Confirmed |
| 19 | *Virus Bulletin*, February 1997 | https://www.virusbulletin.com/uploads/pdf/magazine/1997/199702.pdf | 2026-11-12 | Confirmed |
| 20 | *Virus Bulletin*, March 1997 | https://www.virusbulletin.com/uploads/pdf/magazine/1997/199703.pdf | 2026-11-12 | Confirmed |
| 21 | *Virus Bulletin*, May 1997 (with the January and March reviews named in Part 6) | https://www.virusbulletin.com/uploads/pdf/magazine/1997/199705.pdf | 2026-11-12 | Confirmed |
| 22 | *Virus Bulletin*, August 1997 | https://www.virusbulletin.com/uploads/pdf/magazine/1997/199708.pdf | 2026-11-12 | Reported |
| 23 | *Virus Bulletin*, November 1997 | https://www.virusbulletin.com/uploads/pdf/magazine/1997/199711.pdf | 2026-11-12 | Confirmed |
| 24 | *Virus Bulletin*, December 1997 (October prevalence table) | https://www.virusbulletin.com/uploads/pdf/magazine/1997/199712.pdf | 2026-11-12 | Confirmed (table); Demonstrated (sum) |
| 25 | *United States v. Czubinski*, 106 F.3d 1069 (1st Cir. 1997) | https://openjurist.org/106/f3d/1069 | 2026-11-13 | Confirmed |
| 26 | *CompuServe Inc. v. Cyber Promotions, Inc.*, 962 F. Supp. 1015 (S.D. Ohio 1997) | https://openjurist.org/962/fsupp/1015 | 2026-11-13 | Confirmed |
| 27 | Takedown.com timeline (book companion site) | https://www.takedown.com/timeline/index_current.html | 2026-11-12 | Reported |
| 28 | *United States v. Mitnick*, 145 F.3d 1342 (9th Cir. 1998) | https://law.justia.com/cases/federal/appellate-courts/F3/145/1342/470528/ | 2026-11-12 | Confirmed |
| 29 | TeamStarWolf library, `case-studies/MITNICK_INTRUSIONS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/MITNICK_INTRUSIONS.md | 2026-11-13 | Reported (relays source 27) |
| 30 | Pub. L. 105-147, No Electronic Theft (NET) Act (HTML) | https://www.govinfo.gov/content/pkg/PLAW-105publ147/html/PLAW-105publ147.htm | 2026-11-12 | Confirmed |
| 31 | Pub. L. 105-147 (PDF) | https://www.govinfo.gov/content/pkg/PLAW-105publ147/pdf/PLAW-105publ147.pdf | 2026-11-12 | Confirmed |
| 32 | Executive Order 13010, Federal Register, 17 July 1996 (PDF) | https://www.govinfo.gov/content/pkg/FR-1996-07-17/pdf/96-18351.pdf | 2026-11-12 | Confirmed |
| 33 | RISKS Digest 18.89, PCCIP remit posted by the Commission's comments desk, 27 February 1997 | https://catless.ncl.ac.uk/Risks/18/89/ | 2026-11-12 | Confirmed |
| 34 | NCJRS abstract, PCCIP, *Critical Foundations: Protecting America's Infrastructures* (NCJ 189721) | https://www.ojp.gov/ncjrs/virtual-library/abstracts/critical-foundations-protecting-americas-infrastructures | 2026-11-12 | Confirmed |
| 35 | White House fact sheet on PDD-63, 22 May 1998 (FAS mirror) | https://irp.fas.org/offdocs/pdd-63.htm | 2026-11-12 | Confirmed |
| 36 | GAO/AIMD-98-92, September 1998 | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-98-92/pdf/GAOREPORTS-AIMD-98-92.pdf | 2026-11-12 | Confirmed |
| 37 | National Security Archive, "Eligible Receiver 97", 1 August 2018 | https://nsarchive.gwu.edu/briefing-book/cyber-vault/2018-08-01/eligible-receiver-97-seminal-dod-cyber-exercise-included-mock-terror-strikes-hostage-simulations | 2026-11-12 | Confirmed (document list and dates); Reported (analysis) |
| 38 | Joint Chiefs of Staff J-5 Tasking, 10 June 1997 (declassified) | https://nsarchive.gwu.edu/sites/default/files/documents/4618342/Document-6-Joint-Chiefs-of-Staff-J-5-Tasking.pdf | 2026-11-12 | Confirmed |
| 39 | National Security Archive, "Eligible Receiver 97 Final Observation Report, Part 2", 15 February 2021 | https://nsarchive.gwu.edu/briefing-book/cyber-vault/2021-02-15/eligible-receiver-97-final-observation-report-part-2 | 2026-11-12 | Reported |
| 40 | National Security Archive, "Solar Sunrise after 25 years", 28 February 2023 | https://nsarchive.gwu.edu/briefing-book/cyber-vault/2023-02-28/solar-sunrise-after-25-years-are-we-25-years-wiser | 2026-11-12 | Reported |
| 41 | US Department of Justice, Solar Sunrise release, 18 March 1998 | https://www.justice.gov/archive/opa/pr/1998/March/125.htm.html | 2026-11-12 | Confirmed |
| 42 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze", 3 April 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Confirmed (findings); Reported (victims) |
| 43 | Kaspersky, "Equation: The Death Star of Malware Galaxy", 16 February 2015 | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-12 | Confirmed |
| 44 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 45 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 46 | TeamStarWolf library, main branch, `data/attack/` and the `mitre/` page tree | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-13 | Confirmed |
| 47 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` (and the other era studies searched for 1997) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-12 | Demonstrated (search); Inferred (binding) |
| 48 | NIST CSRC, AES development (archived project) | https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/archived-crypto-projects/aes-development | 2026-11-12 | Confirmed |
| 49 | US Department of Justice, statement on the Bernstein ruling, 26 August 1997 | https://www.justice.gov/archive/opa/pr/1997/August97/351cr.htm | 2026-11-12 | Confirmed |
| 50 | US Department of Justice, Bernstein stay, 29 August 1997 | https://www.justice.gov/archive/opa/pr/1997/August97/354civ.htm | 2026-11-12 | Confirmed |
| 51 | *Reno v. ACLU*, 521 U.S. 844 (1997), syllabus (Cornell LII) | https://www.law.cornell.edu/supct/html/96-511.ZS.html | 2026-11-12 | Confirmed |
| 52 | White House, presidential directive on electronic commerce, 1 July 1997 | https://clintonwhitehouse4.archives.gov/WH/New/Commerce/directive.html | 2026-11-12 | Confirmed |
| 53 | White House, *A Framework for Global Electronic Commerce* | https://clintonwhitehouse4.archives.gov/WH/New/Commerce/read.html | 2026-11-12 | Confirmed |
| 54 | H.R. 1903, Computer Security Enhancement Act of 1997 (engrossed in the House) | https://www.govinfo.gov/content/pkg/BILLS-105hr1903eh/html/BILLS-105hr1903eh.htm | 2026-11-12 | Confirmed |
| 55 | US Department of Justice, G8 ministers' meeting announcement, 9 December 1997 | https://www.justice.gov/archive/opa/pr/1997/December97/519ag.html | 2026-11-12 | Confirmed |
| 56 | US Department of Justice, Attorney General's statement, 10 December 1997 | https://www.justice.gov/archive/opa/pr/1997/December97/518cr.html | 2026-11-12 | Confirmed |
| 57 | RFC 2196, Site Security Handbook (with the other 1997 RFC headers named in Part 9) | https://www.rfc-editor.org/rfc/rfc2196.txt | 2026-11-12 | Confirmed |
| 58 | RFC 2267, Network Ingress Filtering (January 1998) | https://www.rfc-editor.org/rfc/rfc2267.txt | 2026-11-12 | Confirmed |
| 59 | RFC 2316, Report of the IAB Security Architecture Workshop | https://www.rfc-editor.org/rfc/rfc2316.txt | 2026-11-12 | Confirmed |
| 60 | IETF Datatracker, secsh working group history | https://datatracker.ietf.org/group/secsh/history/ | 2026-11-12 | Confirmed |
| 61 | NIST, FIPS 196 (with the SP 800-15 page for its date) | https://csrc.nist.gov/pubs/fips/196/final | 2026-11-12 | Confirmed |
| 62 | RISKS Digest 18.74, US Air Force web page (*New York Times*, 30 December 1996) | https://catless.ncl.ac.uk/Risks/18/74/ | 2026-11-12 | Reported |
| 63 | RISKS Digest 18.75, fired contractor arrested (*San Francisco Chronicle*, 9 January 1997) | https://catless.ncl.ac.uk/Risks/18/75/ | 2026-11-12 | Reported |
| 64 | RISKS Digest 18.82, hostile ActiveX control demonstrated (11 February 1997) | https://catless.ncl.ac.uk/Risks/18/82/ | 2026-11-12 | Reported |
| 65 | RISKS Digest 18.88, NASA web site (5 March 1997) | https://catless.ncl.ac.uk/Risks/18/88/ | 2026-11-12 | Reported |
| 66 | RISKS Digest 18.90, Florida 911 systems (Edupage, citing the *Tampa Tribune*) | https://catless.ncl.ac.uk/Risks/18/90/ | 2026-11-12 | Reported |
| 67 | RISKS Digest 18.94, Gulf War intrusions disclosed (Edupage, citing the *Telegraph*, 23 March 1997) | https://catless.ncl.ac.uk/Risks/18/94/ | 2026-11-12 | Reported |
| 68 | RISKS Digest 19.12, Levi Strauss personnel data stolen (*San Francisco Chronicle*, 29 to 30 April 1997) | https://catless.ncl.ac.uk/Risks/19/12/ | 2026-11-12 | Reported |
| 69 | RISKS Digest 19.19, FBI sting on credit-card data sale (*San Francisco Chronicle*, 22 to 23 May 1997) | https://catless.ncl.ac.uk/Risks/19/19/ | 2026-11-12 | Reported |
| 70 | RISKS Digest 19.23, Microsoft web site interrupted (*Wall Street Journal*, 23 June 1997) and the DES challenge (26 June 1997) | https://catless.ncl.ac.uk/Risks/19/23/ | 2026-11-12 | Reported |
| 71 | RISKS Digest 19.24, credit-card numbers taken from the Web (AP, 11 July 1997) | https://catless.ncl.ac.uk/Risks/19/24/ | 2026-11-12 | Reported |
| 72 | RISKS Digest 19.31, "Crack a Mac" server cracked (18 August 1997) | https://catless.ncl.ac.uk/Risks/19/31/ | 2026-11-12 | Reported |
| 73 | RISKS Digest 19.34, guilty plea (AP, 26 August 1997), AOL e-mail scam (*Washington Post*, 26 August 1997) and NASDAQ outage (*Inter@ctive Week*, 21 August 1997) | https://catless.ncl.ac.uk/Risks/19/34/ | 2026-11-12 | Reported |
| 74 | RISKS Digest 19.45, Pentium flaw (*Wall Street Journal*, 11 November 1997) | https://catless.ncl.ac.uk/Risks/19/45/ | 2026-11-12 | Reported |
| 75 | RISKS Digest 19.47, Forbes sabotage charge (*New York Times*, 25 November 1997) and the Senate investigators' cost estimate | https://catless.ncl.ac.uk/Risks/19/47/ | 2026-11-12 | Reported |
| 76 | RISKS Digest 19.48, UK charges dropped (PA News) | https://catless.ncl.ac.uk/Risks/19/48/ | 2026-11-12 | Reported |
| 77 | RISKS Digest 19.50, Yahoo page altered (Edupage, citing *New York Times* Cybertimes, 7 December 1997) | https://catless.ncl.ac.uk/Risks/19/50/ | 2026-11-12 | Reported |
| 78 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 79 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 80 | MITRE ATT&CK, Design and Philosophy (March 2020) | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | 2026-11-12 | Confirmed |
| 81 | MITRE D3FEND, about | https://d3fend.mitre.org/about/ | 2026-11-12 | Confirmed |
| 82 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_profiles.jsonl | 2026-11-13 | Demonstrated |
| 83 | TeamStarWolf library, `data/weaknesses/capec.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/capec.jsonl | 2026-11-13 | Demonstrated |
| 84 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_to_d3fend.jsonl | 2026-11-13 | Demonstrated |
| 85 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/cwe.jsonl | 2026-11-13 | Demonstrated |
| 86 | TeamStarWolf library, `mitre/software/S0560.md` (name collision only) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/software/S0560.md | 2026-11-13 | Inferred |
| 87 | TeamStarWolf library, main branch, `navigator/library-layers/` (the folder where this study's layer is saved; not evidence) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-13 | Location only |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md)
- Home studies: [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [United States: the public record](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [NSA and CIA Tool Leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [The Cuckoo's Egg Intrusion](/case-studies/CUCKOOS_EGG_1986.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Hacker and the State cases](/case-studies/HACKER_AND_THE_STATE_CASES.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1595.002 Vulnerability Scanning](/mitre/techniques/T1595-002.md), [T1595.001 Scanning IP Blocks](/mitre/techniques/T1595-001.md), [T1046 Network Service Discovery](/mitre/techniques/T1046.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1059.004 Unix Shell](/mitre/techniques/T1059-004.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1548.001 Setuid and Setgid](/mitre/techniques/T1548-001.md), [T1499.004 Application or System Exploitation](/mitre/techniques/T1499-004.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1557 Adversary-in-the-Middle](/mitre/techniques/T1557.md), [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1185 Browser Session Hijacking](/mitre/techniques/T1185.md), [T1539 Steal Web Session Cookie](/mitre/techniques/T1539.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1090 Proxy](/mitre/techniques/T1090.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1137.001 Office Template Macros](/mitre/techniques/T1137-001.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1491.002 External Defacement](/mitre/techniques/T1491-002.md), [T1598 Phishing for Information](/mitre/techniques/T1598.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md)
- CAPEC: [CAPEC-10](/mitre/capec/CAPEC-10.md), [CAPEC-25](/mitre/capec/CAPEC-25.md), [CAPEC-26](/mitre/capec/CAPEC-26.md), [CAPEC-31](/mitre/capec/CAPEC-31.md), [CAPEC-42](/mitre/capec/CAPEC-42.md), [CAPEC-69](/mitre/capec/CAPEC-69.md), [CAPEC-88](/mitre/capec/CAPEC-88.md), [CAPEC-98](/mitre/capec/CAPEC-98.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-142](/mitre/capec/CAPEC-142.md), [CAPEC-158](/mitre/capec/CAPEC-158.md), [CAPEC-169](/mitre/capec/CAPEC-169.md), [CAPEC-287](/mitre/capec/CAPEC-287.md), [CAPEC-300](/mitre/capec/CAPEC-300.md), [CAPEC-301](/mitre/capec/CAPEC-301.md), [CAPEC-302](/mitre/capec/CAPEC-302.md), [CAPEC-308](/mitre/capec/CAPEC-308.md)
- Groups, software and campaigns: none bound for 1997 (Part 11); Turla [G0010](/mitre/groups/G0010.md) and Penquin [S0587](/mitre/software/S0587.md) for their recorded start dates; Equation [G0020](/mitre/groups/G0020.md) for its infrastructure as the home studies record it
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-1997.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1997.json)
