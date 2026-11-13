# The Year 1996 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 12 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md) · Home studies for events summarized here: [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md) (the April 1996 plea and the September 1996 Los Angeles indictment), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (the cash-management transfer ring, Moonlight Maze from 1996 and the October 1996 amendment of 18 U.S.C. 1030), [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) (Equation group domains registered from 1996) · Series: [The Year 1994 in Intrusions](/case-studies/CHRONICLE_1994.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 67 min (15,468 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 1996, you need the year's floods, the web's new attack paths and the CERT advisories side by side with the Defense record and the year's law, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 10: the defender view](#part-10-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md), [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

For the people running Internet servers in 1996, the year's new problem was staying up (Inferred). In September the CERT Coordination Center (CERT/CC) warned that two underground magazines had published code for TCP SYN flooding, that the code was being used against Internet sites, and that there was as yet no complete solution (Confirmed [1]). The same month repeated SYN floods of up to 150 bogus requests a second virtually shut down Panix, a New York public-access provider, and in December a flood of 200 a second took more than 3,000 sites hosted by WebCom off the air for 40 hours on a shopping weekend (Reported [57][63]). CERT had opened the year with a UDP "packet storm" advisory in February and closed it with oversized ping packets that crash, freeze or reboot systems in December (Confirmed [1]).

In all CERT issued 27 advisories that year, CA-96.01 to CA-96.27 (Confirmed [2]). Web servers and browsers became code-execution paths in both directions. The example "phf" CGI program shipped with NCSA httpd and Apache was being actively exploited by March, CERT told sites in May never to put shell or Perl interpreters in a CGI directory, and Princeton researchers showed in February that Netscape Navigator 2.0's Java let a hostile applet reach hosts behind a firewall, and in March CERT reported bytecode verifier weaknesses that could let a malicious applet do anything the user could, with no exploitation reported (Demonstrated [49]; Confirmed [1]). About half the year's advisories were local root or arbitrary file overwrite flaws, most with exploits already public or exploitation already reported, and sendmail alone took three (Confirmed [1]). In November Phrack published Aleph One's "Smashing The Stack For Fun And Profit", which opens by noting a large recent increase in buffer overflow bugs being found and exploited (Confirmed [74]).

The year's public record of attacks on government was written in Washington. On 29 March the Justice Department charged a 21-year-old from Buenos Aires who had used a Harvard host as a staging point into Navy, NASA and Los Alamos systems, a case built on what it called the first court-ordered wiretap on a computer network (Confirmed [4][5]). On 22 May GAO reported that Defense data implied as many as 250,000 attacks on its systems in 1995, an extrapolation from the Defense Information Systems Agency's own test attacks, which succeeded 65 percent of the time; only about 4 percent of the successful ones were detected (Confirmed [7][8]). Senate hearings followed in May and June, and on 25 June the Director of Central Intelligence said his greatest concern was a coordinated attack on infrastructure (Confirmed [11][12]). Intruders then defaced the Justice Department's web site in August, the CIA's in September and an Air Force site in December (Reported [55][58][64][75][76][79]).

The law changed with it. The Telecommunications Act, whose Title V is the Communications Decency Act the Justice Department defacement protested, became law on 8 February; HIPAA directed the adoption of security standards for health information on 21 August; and on 11 October Pub. L. 104-294 created the federal economic espionage offense and, in its Title II, rewrote 18 U.S.C. 1030 around the "protected computer" and added an extortion offense (Confirmed [27][25][20]). Executive Order 13010 of 15 July created the President's Commission on Critical Infrastructure Protection and defined "cyber threats" to infrastructure (Confirmed [17][18]). The SSL 3.0 version that later became the basis for TLS is dated 18 November, the IETF's TLS working group started in May, and NIST published SP 800-14, its baseline principles for IT security programs, in September (Confirmed [86][87][90]).

Viruses followed the new platforms. *Virus Bulletin* described the first Windows 95 virus in February and the first Excel macro virus found in the wild in August, and reported that the Wazzu Word macro virus had shipped on a Microsoft CD (Reported [66][69][71]). By October, macro viruses made up about a quarter of the reports in its prevalence table (Demonstrated [72]).

This study is the dated record of that year, built only from sources opened on 12 November 2026. Nine parts cover the timeline, the 27 CERT advisories, the Defense record and the Harvard case, crime and prosecutions, the web defacements, viruses, cryptography and transport security, the state and intelligence record, and the government's laws, orders and standards; a tenth gives the defender view and an eleventh maps the record to MITRE frameworks.

No identifier system defenders use today existed in 1996. CVE began in 1999, the first CWE release came in 2006, CAPEC in 2007 and the public ATT&CK release in May 2015 (Confirmed [81][91][92][93]). The year's own vulnerability identifiers are CERT's advisory numbers. Some of those flaws were later given back-dated CVE-1999 records, which Part 2 lists; every ATT&CK id in Part 11 is this study's later mapping, labelled as such.

Evidence grade: CERT/CC texts, GAO reports, Justice Department releases, congressional testimony and statements, statutes, executive orders, court orders, NIST, RFC Editor, IETF and NVD records, MITRE's own pages and the researchers' own posts are **Confirmed**. Facts that rest on *Virus Bulletin*, press digests such as Edupage, newspaper and trade-press accounts relayed through the RISKS Digest, and later retrospectives are **Reported** and attributed. A researcher's public showing that an attack works is **Demonstrated**, as is a query or data file this study ran or opened itself. Where the study draws its own conclusion it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 1996, plus boundary records that close or explain a 1996 event (the 1998 Ardita plea, the 2002 Omega Engineering sentencing, the 1997 accounts of the Air Force defacement and the defacement mirrors, the 1999 CVE records, the 2017 Moonlight Maze research) |
| CERT/CC advisories | 27, CA-96.01 (8 Feb) to CA-96.27 (19 Dec), republished by SEI as "1996 CERT Advisories" (Confirmed [1][2]) |
| Denial of service | UDP packet storm (CA-96.01, 8 Feb), SYN flooding with no complete solution (CA-96.21, 19 Sep), oversized ping (CA-96.26, 18 Dec) (Confirmed [1]); Panix in September and WebCom in December (Reported [57][63]) |
| Web as attack path | phf and the NCSA/Apache example CGI code, actively exploited (CA-96.06, 20 Mar); interpreters in CGI directories (CA-96.11, 29 May); Java applet connections and bytecode verifier (CA-96.05, 5 Mar; CA-96.07, 29 Mar) (Confirmed [1]) |
| Incidents handled by CERT/CC | 2,573 incidents affecting more than 10,700 sites; 345 vulnerability reports; 31,268 e-mail messages and 2,062 hotline calls (Confirmed [3]) |
| Defense attacks | As many as 250,000 in 1995 by DISA's extrapolation; 559 officially reported in 1995 (Confirmed [7][10]) |
| Landmark investigation | Harvard FAS host used against the Naval Research Laboratory, NASA JPL and Ames, Los Alamos and the Navy's NCCOSC; first court-ordered wiretap on a computer network; complaint 29 March (Confirmed [4][5]) |
| Defacements | Justice Department (16 or 17 Aug), CIA (18 or 19 Sep), Air Force placeholder site (29 Dec) (Reported [55][58][75][76][79]) |
| Insider sabotage | Omega Engineering time bomb, 30 July, at least $10 million in sales and future contracts, as the indictment stated (Confirmed [38]) |
| Malware | Boza, which Virus Bulletin called the first Windows 95 virus (Feb); Hare.7610 (sample end of May); Laroux, in Virus Bulletin's words the first Excel virus in the wild (Jul to Aug); Wazzu on a Microsoft CD (Sep) (Reported [66][69][70][71]) |
| Cryptography | 40-bit export SSL session broken at a claimed cost of $584 (Jan); Kerberos 4 session keys breakable in minutes (Feb); fault attacks on smart cards (Sep) and DES (Oct); SSL 3.0 (18 Nov) (Reported [48][59]; Confirmed [1][86]; Demonstrated [61]) |
| Law and orders | Telecommunications Act with the Communications Decency Act (8 Feb); Clinger-Cohen (10 Feb); EO 13010 (15 Jul); HIPAA (21 Aug); Economic Espionage Act and National Information Infrastructure Protection Act (11 Oct); EO 13026 on encryption export (15 Nov) (Confirmed [27][28][18][25][20][31]) |
| State record | No opened primary attributes a 1996 intrusion to a state (Inferred); Moonlight Maze is dated from 1996 by later research and its tie to any ATT&CK group is unproven (Reported [40][41]) |
| This study's MITRE binding | 20 ATT&CK Enterprise technique rows, every one a later mapping; no ICS row; no group, software or campaign object; thirteen CWE and eleven CAPEC entries; D3FEND pairings from the library's data; one Navigator layer (Part 11) |

### Key findings

- **Denial of service became routine and had no fix.** CERT said of SYN flooding that there was as yet no complete solution and that only input source filtering can validate where a packet came from (Confirmed [1]). Published code, a public-access provider knocked out in September and a web host down for 40 hours in December show the attack moving from paper to practice in one year (Confirmed [1][73]; Reported [57][63]).
- **The web opened in both directions.** Server-side example code and misplaced interpreters let intruders run commands on web servers, and early Netscape and other server documentation had recommended the unsafe layout (Confirmed [1]). Client-side, Java applets reached past firewalls in Princeton's demonstration, though CERT had no reports of exploitation of the verifier flaw (Demonstrated [49]; Confirmed [1]).
- **Exploit knowledge was published faster than fixes.** Most of the year's local root advisories note public exploits or reported exploitation, and the November Phrack article explained stack overflows step by step (Confirmed [1][74]); that it made the class teachable is this study's reading (Inferred).
- **Defenders saw almost nothing.** GAO's own figures say about 4 percent of DISA's successful test attacks were detected and about 27 percent of those reported, about 1 in 150 drawing a defensive response (Confirmed [8]). Every incident count of the year is therefore a floor (Inferred).
- **The headline numbers were extrapolations.** The 250,000 Defense attacks figure is an estimate from tests, and an AP story put Pentagon break-ins at more than 160,000 a year; a viewer of the hearing noted in RISKS that the 65 percent figure was DISA's own test success rate (Confirmed [7]; Reported [52]).
- **Federal web pages became protest boards.** The Justice Department, CIA and Air Force sites were altered within five months, mirrors kept copies alive after the pages came down, and a survey released after the first attack found most agencies had no security or incident-response policy (Reported [75][76][78][79]).
- **Policy caught up with the year.** EO 13010 named "cyber threats" to infrastructure, HIPAA wrote security safeguards into health law, and the 1996 amendments extended federal computer crime law to any "protected computer" used in interstate or foreign commerce or communication (Confirmed [18][25][20]).
- **The year's state story is testimony, not attribution.** The DCI described foreign doctrine and a classified report on threats to the telephone network and SCADA systems but named no state program and no attributed intrusion (Confirmed [12]). Moonlight Maze, dated from 1996 by research published in 2017, has its home in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Confirmed [40]).

### Top recommendations

1. **Filter forged source addresses at the network edge.** CERT strongly urged ISPs to drop inbound packets claiming internal sources and outbound packets not carrying them, while noting that the filters do not stop all SYN attacks (Confirmed [1]).
2. **Turn off what you do not use.** CA-96.01 told sites to disable chargen, echo and other unused UDP services and to block UDP below port 900 at the firewall except needed services such as DNS (Confirmed [1]).
3. **Strip web servers of sample code and interpreters.** The phf example program and interpreters in CGI directories were both exploited in 1996 (Confirmed [1]).
4. **Do not let names stand in for identity.** BIND flaws made DNS data unreliable, CERT warned that corrupt data could reach any service that reuses it, and applets were trusted by host name rather than address (Confirmed [1]).
5. **Patch local privilege flaws quickly.** Public scripts preceded most of the year's local root advisories (Confirmed [1]).
6. **Build detection and reporting before counting attacks.** GAO recommended mandatory incident reporting, risk assessments, training, and monitoring and protection technology such as firewalls, smart cards and network monitoring (Confirmed [8]).
7. **Treat documents and vendor media as untrusted.** Wazzu arrived on a Microsoft CD and Laroux circulated before anyone noticed it (Reported [71][69]).
8. **Plan lawful monitoring before an incident.** The Harvard investigation needed a court order because the system displayed no monitoring banner (Confirmed [5]).
9. **Treat a departing administrator's access as an incident window.** The Omega Engineering time bomb went off 20 days after the employee who planted it was terminated (Confirmed [38]; Inferred for the lesson).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, cryptography and policy dated to 1996, plus the later records that close or explain a 1996 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every event graded, numbers as the source states them.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record (a CERT/CC advisory as SEI publishes it, a GAO report, a Justice Department release, congressional testimony or a committee statement, a statute, an executive order, a court order, a NIST, RFC Editor, IETF, CVE or NVD record, the researcher's or vendor's own publication, a live ATT&CK page, or the library's data files as the record of what the library holds) was opened on 12 November 2026 and states the fact |
| Reported | Only a secondary source was opened: *Virus Bulletin*, press digests such as Edupage, newspaper, wire and trade-press stories and their reprints in the RISKS Digest, a book's companion site, or a committee statement relaying an allegation. The source is named in the text |
| Demonstrated | A researcher publicly showed that an attack works against a real product (the Princeton Java work, the Biham and Shamir DES fault attack), or this study ran the query or opened the data itself and saw the result (the NVD date query, the prevalence sum, the library's data files) |
| Inferred | The study's own reasoning, labelled where it appears. Every MITRE id bound to a 1996 event is Inferred as to the binding |

Limits that a reader should know:

- **No contemporaneous CVE, no ATT&CK.** No 1996 record carries a CVE id or an ATT&CK id; CVE began with a white paper presented at Purdue in January 1999, started with 321 entries and launched publicly in September 1999 (Confirmed [81]). NVD now returns 75 records with 1996 published dates, all CVE-1999 ids assigned later (Demonstrated [82]). Part 2 pairs some of them with advisories by date and description (Inferred [83]).
- **The advisory text.** SEI's 1996 compilation is the text for all 27 advisories [1][2]. Its table of contents mislabels CA-96.27 with the CA-96.26 ping title; this study follows the advisory body (Confirmed [1]).
- **The Defense record.** GAO/AIMD-96-84 is read in three forms (govinfo HTML and PDF, and the Federation of American Scientists mirror) with GAO's product page for the release date [7][8][9][10]. The Senate hearings are read in the FAS archive [11] to [16].
- **Malware rests on *Virus Bulletin*.** It is graded Reported as in the earlier chronicles; the share of macro viruses in its October table is this study's own sum and is Demonstrated [72].
- **RISKS and the trade press.** Many 1996 events survive mainly as press items relayed through the RISKS Digest; they are graded Reported and attributed to the paper or wire service named in the digest [47] to [64]. Three press claims (the Sunday Times extortion story, the Sunday Times story on US intelligence and European institutions, and the Czech bank losses) have no primary record and are carried only as unverified claims.
- **People.** Defendants whose outcomes this study did not check are not named: the help-desk employee charged over the New England manufacturer's data loss is one. Named people are those who pleaded guilty or were convicted, researchers credited in the record, and officials testifying.
- **Home studies.** The Mitnick plea and indictment live in the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md); the cash-management transfer ring, Moonlight Maze and the CFAA amendment history in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); the Equation group in the [tool leaks study](/case-studies/NSA_CIA_TOOL_LEAKS.md) and the [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md). Each is summarized here in a paragraph. The era studies on main do not cover CA-96.21, phf, Smashing the Stack, the ping of death, the Java advisories, Boza, Laroux, HIPAA, EO 13010, SSL 3.0 or GAO/AIMD-96-84, so this chronicle is their home (Demonstrated [45]).
- **Tradecraft is described at advisory level.** Advisory names, affected products and impact, and technique names and ids. The 1996 advisories carry detection commands, patch checks and filter rules, and the Phrack articles carry full attack source code; none is reproduced here.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1995-11 (context) | Christopher Pile's 18-month sentence, which *Virus Bulletin*'s January 1996 editorial calls the first UK custodial sentence for writing and distributing viruses | Malware, courts | Reported | [65] |
| 1995-12-28 (boundary) | Argentine authorities seize the Harvard intruder's equipment in Buenos Aires | Intrusion | Confirmed | [4][5] |
| 1996-01-04 | Reuters: a co-conspirator in the cash-management transfer ring pleads guilty in New York; the ring's leader, arrested at Heathrow, awaits extradition. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime, finance | Reported | [47] |
| 1996-01-10 | ICE press release: an MIT undergraduate broke a Netscape export-grade 40-bit RC4 SSL session in under eight days on one graphics computer, a cost the vendor put at $584 per session against Netscape's $10,000 figure | Cryptography | Reported | [48] |
| 1996-02 | *Virus Bulletin* analyses the first Windows 95 virus (Boza, also V32; self-named Bizatch, credited to Quantum of VLAD), a non-resident PE file infector not believed to be in the wild | Malware | Reported | [66][67] |
| 1996-02 | RFC 1918, Address Allocation for Private Internets (BCP 5) | Standards | Confirmed | [89] |
| 1996-02-08 | CA-96.01 UDP Port Denial-of-Service Attack (UDP packet storm between chargen and echo, typically with IP spoofing) | Vulnerability, availability | Confirmed | [1] |
| 1996-02-08 | Telecommunications Act of 1996, Pub. L. 104-104, approved; Title V is the Communications Decency Act | Law | Confirmed | [27] |
| 1996-02-10 | Information Technology Management Reform Act (Clinger-Cohen), Division E of Pub. L. 104-106, approved; section 5125 requires an agency Chief Information Officer | Law | Confirmed | [28] |
| 1996-02-15 | CA-96.02 BIND Version 4.9.3: flaws being exploited by the intruder community to make DNS information unreliable | Vulnerability | Confirmed | [1] |
| 1996-02-18 | Drew Dean of Princeton posts that Navigator 2.0 and JDK 1.0 do not enforce the applet connect-back rule, so a hostile applet can reach any host, including behind a firewall | Research | Demonstrated | [49] |
| 1996-02-21 | CA-96.03 Kerberos 4 key server: weak random number generator; session key breakable in at most 2 to 4 minutes; intruders can masquerade as authorized users | Vulnerability | Confirmed | [1] |
| 1996-02-22 | CA-96.04 Corrupt Information from Network Servers: intruders corrupt data supplied by DNS servers | Vulnerability | Confirmed | [1] |
| 1996-02-27 | BerkshireNet, a Pittsfield, Massachusetts provider: an intruder masquerading as the administrator plants racist messages, erases data on two computers and shuts the system down for about 12 hours | Intrusion | Reported | [50] |
| 1996-03 | RFC 1928 and RFC 1929, SOCKS version 5 and its username and password authentication | Standards | Confirmed | [89] |
| 1996-03-05 | CA-96.05 Java Implementations Can Allow Connections to an Arbitrary Host; Netscape 2.01 fixes; CERT credits Dean, Felten and Wallach of Princeton | Vulnerability | Confirmed | [1] |
| 1996-03-14 | Attorney General memo: under PDD-39 she chairs a Cabinet Committee on critical infrastructure vulnerability covering physical and "cyber" attacks | Policy | Confirmed | [36] |
| 1996-03-20 | CA-96.06 (reprint of AUSCERT AA-96.01 of 14 Mar): escape_shell_cmd() in NCSA httpd 1.5a-export and Apache 1.0.3 example CGI code, including phf, actively exploited | Vulnerability | Confirmed | [1] |
| 1996-03-29 | Justice Department complaint against Julio Cesar Ardita, 21, of Buenos Aires: first court-ordered wiretap on a computer network | Intrusion, courts | Confirmed | [4][5] |
| 1996-03-29 | CA-96.07 Weaknesses in Java Bytecode Verifier (JDK 1.0 and 1.0.1; Navigator 2.0 and 2.01); no exploitation reported | Vulnerability | Confirmed | [1] |
| 1996-04-02 to 03 | Wassenaar Arrangement inaugural Plenary, suspended | Policy | Confirmed | [30] |
| 1996-04-15 | *Bernstein v. US Department of State*: motion to dismiss denied; source code supports a colorable First Amendment claim | Courts, cryptography | Confirmed | [33] |
| 1996-04-18 | CA-96.08 pcnfsd (reported by Avalon Security Research), being exploited | Vulnerability | Confirmed | [1] |
| 1996-04-22 | Mitnick pleads guilty to one count of access device fraud (North Carolina case). Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Reported | [39] |
| 1996-04-24 | CA-96.09 rpc.statd, being exploited; can create or remove any file root can | Vulnerability | Confirmed | [1] |
| 1996-04-27 | Cambridge University: research files reached via the Internet; up to 10,000 users told to change passwords after an inter-university monitor detected a rogue program | Intrusion | Reported | [51] |
| 1996-05 | RFC 1948, Defending Against Sequence Number Attacks (Bellovin); RFC 1938 One-Time Password System; RFC 1945 HTTP/1.0 | Standards | Confirmed | [88][89] |
| 1996-05 (end) | *Virus Bulletin* receives a sample of Hare.7610, a multipartite virus set to overwrite hard drives on 22 August and 22 September | Malware | Reported | [69] |
| 1996-05-22 | GAO/AIMD-96-84, "Computer Attacks at Department of Defense Pose Increasing Risks", released; Senate Permanent Subcommittee on Investigations (PSI) hearing on National Information System Security | Defense, policy | Confirmed | [7][9][11] |
| 1996-05-22 | AP account of the hearing: hackers infiltrate Pentagon computers more than 160,000 times a year; a RISKS reader who watched notes the 65 percent figure was DISA's own test rate | Defense | Reported | [52] |
| 1996-05-24 | IETF Transport Layer Security working group starts (proposed 7 May) | Standards | Confirmed | [87] |
| 1996-05-28 | CA-96.10 NIS+ configuration (Solaris 2.5): any user with valid NIS+ credentials can gain root | Vulnerability | Confirmed | [1] |
| 1996-05-29 | CA-96.11 Interpreters in CGI bin Directories | Vulnerability | Confirmed | [1] |
| 1996-06 | *Virus Bulletin* interview: an anti-virus developer rates Java viruses a bigger coming threat than macro viruses | Malware | Reported | [68] |
| 1996-06 | RFC 1964, Kerberos V5 GSS-API mechanism | Standards | Confirmed | [89] |
| 1996-06-02 | *Sunday Times* claims City of London and US institutions paid up to 400m pounds to extortion gangs in more than 40 attacks since 1993; no primary record found | Crime (unverified) | Reported | [53] |
| 1996-06-05 | PSI hearing, Security in Cyberspace: CERT/CC testimony, Senator Nunn's statement and the minority staff statement | Policy | Confirmed | [14][15][16] |
| 1996-06-25 | PSI hearing, Foreign Information Warfare Activities: DCI John Deutch testifies | Policy, intelligence | Confirmed | [11][12] |
| 1996-06-26 | CA-96.12 suidperl: local root | Vulnerability | Confirmed | [1] |
| 1996-07 | Phrack 48's "Project Neptune" by daemon9, route and infinity: a SYN flooding analysis with attack code, dated July 1996 in its own header | Attack knowledge | Confirmed | [73] |
| 1996-07 (end) | Laroux, the first Excel macro virus, discovered already in the wild, with no payload | Malware | Reported | [70][69] |
| 1996-07-09 | CA-96.13 dip on Linux: several reports of exploitation; script public | Vulnerability | Confirmed | [1] |
| 1996-07-11 to 12 | Wassenaar Arrangement Initial Elements adopted | Policy | Confirmed | [30] |
| 1996-07-15 | Executive Order 13010, Critical Infrastructure Protection (61 FR 37347, 17 Jul) | Policy | Confirmed | [17][18][19] |
| 1996-07-24 | CA-96.14 rdist: exploitation script widely available | Vulnerability | Confirmed | [1] |
| 1996-07-30 | Omega Engineering: a time bomb planted by an administrator terminated on 10 July permanently deletes the company's manufacturing programs | Insider, manufacturing | Confirmed | [38] |
| 1996-07-31 | CA-96.15 Solaris 2.5 KCMS, exploited | Vulnerability | Confirmed | [1] |
| 1996-08 | RFC 1994, PPP CHAP | Standards | Confirmed | [89] |
| 1996-08-04 | *Sunday Times* claims US intelligence hacked European Parliament and Commission systems for trade advantage; no primary record found | State (unverified) | Reported | [54] |
| 1996-08-05 to 15 | CA-96.16 Solaris admintool (5 Aug), CA-96.17 Solaris vold (6 Aug), CA-96.18 fm_fls (14 Aug), CA-96.19 expreserve (15 Aug) | Vulnerability | Confirmed | [1] |
| 1996-08-16 or 17 | Justice Department web site altered with swastikas, obscene images and criticism of the Communications Decency Act; site shut down | Defacement | Reported | [55][75] |
| 1996-08 (late) | Computer Security Institute survey of 77 agencies released days after the Justice Department attack | Policy | Reported | [75] |
| 1996-08-21 | HIPAA, Pub. L. 104-191, approved; section 1173(d) security standards | Law, health | Confirmed | [25][26] |
| 1996-08-21 | Netcom mailing lists halted from 5:30 pm PDT after a user subscribed to many lists retaliates with a bounce loop to every subscriber | Availability | Reported | [56] |
| 1996-09 | NIST SP 800-14, Generally Accepted Principles and Practices for Securing IT Systems | Standards | Confirmed | [90] |
| 1996-09 | Wazzu on Microsoft's September Solution Provider CD | Malware, supply | Reported | [71] |
| 1996-09 (early) | Panix virtually shut down by repeated SYN floods of up to 150 bogus requests a second (WSJ, 12 Sep); Panix staff confirm on 13 Sep | Availability | Reported | [57] |
| 1996-09-16 | A New England manufacturer loses all computer data for 15 hours from 11 pm; a contract help-desk employee is charged with planting a virus and denies it (outcome not checked) | Insider | Reported | [59] |
| 1996-09-18 | CA-96.20 sendmail up to 8.7.5: local users to the default user and to root | Vulnerability | Confirmed | [1] |
| 1996-09-18 or 19 | CIA web site altered by a Swedish group; pulled; the Justice Department site reopens the same day the CIA pulls its page | Defacement | Reported | [58][76][77] |
| 1996-09-19 | CA-96.21 TCP SYN Flooding and IP Spoofing Attacks | Vulnerability, availability | Confirmed | [1] |
| 1996-09-20 | Edupage: S 982 passes the Senate; Senator Leahy cites a Carnegie Mellon report of more than 12,000 computers attacked in more than 2,400 incidents in 1995 | Law | Reported | [58] |
| 1996-09-26 | NYT (via RISKS): Bellcore's Boneh, DeMillo and Lipton announce fault-induced attacks on public-key smart-card computations | Cryptography | Reported | [59] |
| 1996-09-26 | Mitnick indicted in Los Angeles on 25 counts; a co-defendant charged on 14. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Reported | [39] |
| 1996-10 | Wazzu on a CD given away at the ORBIT show in Basel; downloadable from Microsoft's Swiss site for at least five days after a warning (Brunnstein) | Malware, supply | Reported | [71][60] |
| 1996-10 | *Virus Bulletin* prevalence table, 712 reports: Form.A, AntiEXE.A and Concept lead | Malware | Reported | [72] |
| 1996-10 | RFC 2015 MIME Security with PGP; RFC 2040 RC5 algorithms | Standards | Confirmed | [89] |
| 1996-10 (claim) | Newsletter claim from an INVEX interview (22 to 26 Oct) that intruders stole 50 million Kc from unnamed Czech banks; flagged unchecked | Crime (unverified) | Reported | [62] |
| 1996-10-08 | CA-96.22 two GNU bash flaws (content from IBM-ERS) | Vulnerability | Confirmed | [1] |
| 1996-10-11 | Pub. L. 104-294 approved: Economic Espionage Act (Title I) and National Information Infrastructure Protection Act (Title II) | Law | Confirmed | [20][21][22] |
| 1996-10-18 | Biham and Shamir extend fault attacks to secret-key ciphers: a DES key recovered on a PC from fewer than 200 faulty ciphertexts | Cryptography | Demonstrated | [61] |
| 1996-10-28 | CA-96.23 WorkMan set-uid root (content from IBM-ERS) | Vulnerability | Confirmed | [1] |
| 1996-11-01 | Wassenaar control lists and information exchange take effect | Policy | Confirmed | [30] |
| 1996-11-08 | Phrack 49: Aleph One, "Smashing The Stack For Fun And Profit" | Attack knowledge | Confirmed | [74] |
| 1996-11-15 | Executive Order 13026, Administration of Export Controls on Encryption Products (61 FR 58767, 19 Nov) | Policy, cryptography | Confirmed | [31][32] |
| 1996-11-18 | The SSL 3.0 version that RFC 6101 records | Standards | Confirmed | [86] |
| 1996-11-21 | CA-96.24 sendmail daemon mode 8.7 to 8.8.2: any local user to root; exploitation details widely distributed | Vulnerability | Confirmed | [1] |
| 1996-12-06 | *Bernstein*: certain ITAR provisions held invalid as a prior restraint on cryptographic speech (entered 16 Dec) | Courts, cryptography | Confirmed | [34] |
| 1996-12-10 | CA-96.25 sendmail group permissions | Vulnerability | Confirmed | [1] |
| 1996-12-12 to 13 | First operational Wassenaar Plenary | Policy | Confirmed | [30] |
| 1996-12-14 | WebCom hit by a SYN flood of 200 a second from just after midnight; more than 3,000 sites down for 40 hours | Availability, e-commerce | Reported | [63] |
| 1996-12-16 | US Parole Commission approves computer and Internet restrictions for high-risk parolees | Courts | Confirmed | [37] |
| 1996-12-18 | CA-96.26 Denial-of-Service Attack via ping: oversized ICMP datagrams crash, freeze or reboot systems | Vulnerability, availability | Confirmed | [1] |
| 1996-12-19 | CA-96.27, reprint of AUSCERT AA-96.04 (11 Oct): HP SD-UX installation programs, local root | Vulnerability | Confirmed | [1] |
| 1996-12-29 | Air Force placeholder site at af.mil altered; DTIC shuts down all 80 servers supporting Defense web sites as a precaution | Defacement | Reported | [64][79] |
| 1996 (from) | Moonlight Maze intrusions into mainly US military, research and university networks begin, by later research; samples compiled as far back as late 1996. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Espionage | Reported | [40] |
| 1996 | Some Equation group command-and-control domains registered, as the library's [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) records | Espionage | Reported | [100] |
| 1996 | National Research Council, "Cryptography's Role in Securing the Information Society" | Policy, cryptography | Confirmed | [35] |
| 1998-05-19 (boundary) | Ardita returns voluntarily to plead guilty in Boston; he could not be extradited under the treaty then in force | Courts | Reported | [6] |
| 2002-02-26 (boundary) | Omega Engineering defendant, convicted 9 May 2000, sentenced to 41 months | Courts | Confirmed | [38] |

## Part 2: the vulnerability record

### The 27 advisories

CERT/CC issued 27 advisories in 1996, CA-96.01 to CA-96.27; SEI republishes them as "1996 CERT Advisories" and its abstract counts 27 (Confirmed [1][2]). The impact column gives CERT's substance. The "Later CVE" column gives NVD records that match the advisory by date and description; the pairing is this study's, and only the pairs this study checked are listed (Inferred [83]).

| Advisory | Date | Product | Impact as CERT states it | Later CVE | Grade | Sources |
|---|---|---|---|---|---|---|
| CA-96.01 | 8 Feb | chargen, echo and other UDP services | A UDP packet storm on one host or between two; attacks typically involve IP spoofing; disable the services, block UDP below 900 at the firewall except needed services such as DNS, proxy what is required, monitor | CVE-1999-0103 | Confirmed | [1][83] |
| CA-96.02 | 15 Feb | BIND before 4.9.3 | Flaws being exploited by the intruder community to make DNS information unreliable; rlogin, rsh, xhost and NFS trust DNS for authentication; later superseded by CA-97.22 | not paired here | Confirmed | [1] |
| CA-96.03 | 21 Feb | Kerberos Version 4 key server (and Kerberos 5 in V4 compatibility mode) | Weak random number generator; session key breakable in at most 2 to 4 minutes; intruders can masquerade as authorized users | CVE-1999-0143 | Confirmed | [1][83] |
| CA-96.04 | 22 Feb | Any service that reuses data from network servers, DNS first | Intruders corrupt data supplied by DNS servers; CERT points to host name and address validation per RFC 952 and RFC 1123 | not paired here | Confirmed | [1] |
| CA-96.05 | 5 Mar | Netscape Navigator 2.0, Sun JDK 1.0 | An applet can connect to any address tied to its origin host name, so with DNS subversion it can reach hosts behind a firewall; Netscape 2.01 fixes; workaround disable Java or refuse .class files at a proxy | CVE-1999-0142 | Confirmed | [1][83] |
| CA-96.06 | 20 Mar | NCSA httpd 1.5a-export and Apache 1.0.3 example CGI code, including phf | escape_shell_cmd() fails to stop shell exploitation; being actively exploited; reprint of AUSCERT AA-96.01 of 14 Mar | CVE-1999-0067 (CWE-78 in NVD) | Confirmed | [1][83][85] |
| CA-96.07 | 29 Mar | JDK 1.0 and 1.0.1; Navigator 2.0 and 2.01 | Bytecode verifier weaknesses let a malicious applet on a booby-trapped page do anything the user can; no exploitation reported; disable Java until patched | CVE-1999-0141 | Confirmed | [1][83] |
| CA-96.08 | 18 Apr | pcnfsd | Two vulnerabilities reported by Avalon Security Research, being exploited | not paired here | Confirmed | [1] |
| CA-96.09 | 24 Apr | rpc.statd | Being exploited; can create or remove any file root can | not paired here | Confirmed | [1] |
| CA-96.10 | 28 May | NIS+ installations created on Solaris 2.5 | passwd table access rights left insecure; any user with valid NIS+ credentials can gain root; reprint of AUSCERT AA-96.02a | not paired here | Confirmed | [1] |
| CA-96.11 | 29 May | Web servers with interpreters such as /bin/sh or Perl in the CGI bin directory | Intruders can run arbitrary commands; early Netscape and other documentation had recommended the layout; never put interpreters there | CVE-1999-0509 (CWE-94 in NVD) | Confirmed | [1][82] |
| CA-96.12 | 26 Jun | suidperl | Local root | not paired here | Confirmed | [1] |
| CA-96.13 | 9 Jul | dip on Linux up to 3.3.7n | Several reports of exploitation; an x86 script public | not paired here | Confirmed | [1] |
| CA-96.14 | 24 Jul | rdist | Exploitation script widely available | not paired here | Confirmed | [1] |
| CA-96.15 | 31 Jul | Solaris 2.5 KCMS programs | Exploited | not paired here | Confirmed | [1] |
| CA-96.16 | 5 Aug | Solaris admintool | Local privilege flaw | not paired here | Confirmed | [1] |
| CA-96.17 | 6 Aug | Solaris vold | Local privilege flaw | not paired here | Confirmed | [1] |
| CA-96.18 | 14 Aug | Adobe FrameMaker fm_fls | Local file overwrite toward root; scripts public | not paired here | Confirmed | [1] |
| CA-96.19 | 15 Aug | expreserve | An old and widely unpatched local flaw | not paired here | Confirmed | [1] |
| CA-96.20 | 18 Sep | sendmail up to 8.7.5 | Two flaws; local users to the default user and to root; fix 8.7.6 | not paired here | Confirmed | [1] |
| CA-96.21 | 19 Sep | Any system offering TCP services | SYN flooding code published in two underground magazines and actively used; no complete solution; ISPs urged to filter spoofed sources; supersedes the IP spoofing part of CA-95.01 | CVE-1999-0116 | Confirmed | [1][83] |
| CA-96.22 | 8 Oct | GNU bash | Two flaws (yy_string_get, yy_readline_get); one character treated as a command separator; content from IBM-ERS | not paired here | Confirmed | [1] |
| CA-96.23 | 28 Oct | WorkMan CD player program | Set-uid root lets any file be made world-writable; content from IBM-ERS | not paired here | Confirmed | [1] |
| CA-96.24 | 21 Nov | sendmail 8.7 to 8.8.2 in daemon mode | Any local user to root; exploitation details widely distributed; fix 8.8.3 | not paired here | Confirmed | [1] |
| CA-96.25 | 10 Dec | sendmail version 8 | Group permissions problem; fix 8.8.4 | not paired here | Confirmed | [1] |
| CA-96.26 | 18 Dec | Systems receiving oversized ICMP datagrams | Crash, freeze or reboot; exploitation details widely distributed; check a crashed router or firewall's running configuration because the crash may be part of a multistage attack | CVE-1999-0128 | Confirmed | [1][80][83] |
| CA-96.27 | 19 Dec | HP SD-UX software installation programs | Local root; reprint of AUSCERT AA-96.04 of 11 Oct; the SEI table of contents mislabels it with the ping title | not paired here | Confirmed | [1] |

### What the advisories say about attackers

Read in order, the 27 advisories split three ways (Inferred). Three are pure denial of service: the UDP storm in February, SYN flooding in September and the oversized ping in December (Confirmed [1]). Six concern trust in data that arrives over the network or code that runs on the web: BIND, corrupt DNS data, the two Java advisories, phf and interpreters in CGI directories (Confirmed [1]). About half cover local root or arbitrary file overwrite, from suidperl in June to HP's SD-UX in December, most with exploits already public or exploitation already reported; expreserve was, in CERT's description, an old flaw that remained widely unpatched (Confirmed [1]). Sendmail alone needed three advisories, with fixes in 8.7.6, 8.8.3 and 8.8.4 (Confirmed [1]). Australia's AUSCERT supplied the text of at least three of them and IBM's emergency response service two, an early sign of the coordination between response teams that CERT's annual counts rest on (Confirmed [1]; Inferred).

### Denial of service in three steps

**February, the UDP storm.** CA-96.01 describes programs that set chargen and echo answering each other, on one host or between two, until the network fills; CERT advised disabling both and other unused UDP services and blocking UDP below port 900 at the firewall except needed services such as DNS (Confirmed [1]).

**September, SYN flooding.** CA-96.21 reports that two underground magazines had recently published code for half-open TCP connection attacks and that the code was being used against sites (Confirmed [1]). Any system offering TCP services was exposed, routers included; spoofed source addresses hide the attacker, so only input source filtering can validate a packet's source; many connections in the SYN_RECEIVED state signal an attack; and CERT strongly urged ISPs to filter inbound packets claiming internal sources and outbound packets that did not carry them, while saying the filters do not stop all SYN attacks and that there was as yet no complete solution (Confirmed [1]). Phrack 48's "Project Neptune", dated July 1996 in its own header, is a full SYN flooding analysis with traces, attack code and a prevention section, and is probably one of the two magazines CERT left unnamed (Confirmed [73]; Inferred). The victims of the year show what that meant. Panix was virtually shut down in early September by repeated floods of up to 150 bogus requests a second, as the *Wall Street Journal* reported on 12 September and Panix staff confirmed on 13 September (Reported [57]). WebCom, a large web host, was hit from just after midnight on Saturday 14 December by a flood of 200 a second; more than 3,000 hosted sites were down for 40 hours on a shopping weekend, and the trail ran through PSINet and MCI to CANet in Ontario and BC.Net until MCI blocked the upstream traffic (Reported [63]). The weekend-shopping loss is the e-commerce side of the story the library's [e-commerce threats study](/case-studies/ECOMMERCE_THREATS.md) takes up for later years (Inferred).

**December, the ping of death.** CA-96.26 reports oversized ICMP datagrams sent with ping that crash, freeze or reboot some systems, with exploitation details widely distributed; CERT advised checking the running configuration of any router or firewall that crashed, because the crash might be part of a larger multistage attack, and then patching (Confirmed [1]). The later CVE records for the two attack classes were published on 29 September 1999 as CVE-1999-0116, "aka SYN flood", and CVE-1999-0128, "aka Ping o' Death", with no problem type listed (Confirmed [80][83]).

### The web opens in both directions

On the server side, AUSCERT's March alert, reprinted by CERT on 20 March, said the escape_shell_cmd() function in the example CGI code shipped with NCSA httpd 1.5a-export and Apache 1.0.3, including the phf program, failed to stop shell exploitation and was being actively exploited (Confirmed [1]). In May CERT added that placing interpreters such as /bin/sh or Perl in a server's CGI bin directory let intruders run arbitrary commands, and that early Netscape and other server documentation had recommended exactly that layout (Confirmed [1]). NVD's later records for the two carry CWE-78 (CVE-1999-0067, phf) and CWE-94 (CVE-1999-0509) (Demonstrated [82]; Confirmed [85]).

On the client side, Drew Dean posted on 18 February that Navigator 2.0 and JDK 1.0 did not enforce the rule that an applet may connect back only to its origin, so a malicious applet could reach any host, including one behind a firewall; the Princeton group's proof of concept used an old sendmail bug (Demonstrated [49]). CA-96.05 on 5 March credited Dean, Felten and Wallach and said the flaw let an applet connect to any address tied to its origin host name, so DNS subversion could aim it anywhere; Netscape 2.01 fixed it, and the workaround was to disable Java or refuse .class files at an HTTP proxy (Confirmed [1]). CA-96.07 on 29 March reported weaknesses in the bytecode verifier that let a malicious applet on a booby-trapped page do anything the user could, with no exploitation reported (Confirmed [1]). In June an anti-virus developer told *Virus Bulletin* that Java viruses would be a bigger problem than macro viruses because every browser would run Java (Reported [68]); the macro viruses, not Java, filled the prevalence tables that year (Reported [72]; Inferred).

### Trust in names fails

CA-96.02 said BIND flaws fixed in 4.9.3 were well known and being exploited to make DNS information unreliable, and that rlogin, rsh, xhost and NFS relied on DNS for authentication; the remedy was BIND 4.9.3 or blocking and disabling DNS name-based authentication (Confirmed [1]). A week later CA-96.04 reported intruders corrupting data supplied by DNS servers and warned that the problem applied to any network service whose data is received and then used, pointing to host name and address validation routines based on RFC 952 and RFC 1123 (Confirmed [1]). The Java connection flaw in March was the same failure in a browser: an applet trusted by name rather than by address (Confirmed [1]; Inferred).

### Local root and the stack

The June to August run of advisories, suidperl, dip, rdist, KCMS, admintool, vold, fm_fls and expreserve, is the year's largest cluster, and in most of them CERT reports exploitation or a public script by the time of the advisory (Confirmed [1]). Phrack 49, dated 8 November, carried Aleph One's "Smashing The Stack For Fun And Profit", which notes a large recent increase in buffer overflow vulnerabilities being discovered and exploited, naming syslog, splitvt, sendmail 8.7.5, mount, Xt and at, and explains how stack overflows work on Linux x86 (Confirmed [74]). It is described here at title level only. Its publication put the dominant exploit class of the next decade in print (Inferred).

### The later CVE record

CVE began with Mann and Christey's white paper at Purdue on 21 to 22 January 1999, started with 321 entries and launched publicly in September 1999 (Confirmed [81]). NVD API queries for records published in 1996 return 75 records, all CVE-1999 ids assigned later, one of them rejected (CVE-1999-0335); only five carry a specific CWE: CVE-1999-0067 and CVE-1999-0043 with CWE-78, CVE-1999-0509 with CWE-94, CVE-1999-0022 with CWE-125 and CVE-1999-1383 with CWE-264 (Demonstrated [82]). Eight advisories match later records by date and text, listed in the table above (Inferred [83]). NVD's 1996 dates are not event dates: CVE-1999-1309, a sendmail flaw fixed before 8.6.7 years earlier, is dated 30 August 1996, and CVE-1999-0142, -0130 and -0129 are dated days before their CERT advisories (Inferred [84]).

### Counting incidents

CERT/CC's 1996 summary records 2,573 incidents handled, more than 10,700 sites affected, 345 vulnerability reports, 31,268 e-mail messages and 2,062 hotline calls (Confirmed [3]). In testimony on 5 June CERT/CC gave 132 incidents in 1989 and more than 2,400 in 1995; of 346 incidents closed in the first quarter of 1996, 7.5 percent involved sniffers, spoofing and infrastructure attacks and 20 percent were total super-user compromises, and vulnerability reports had risen from 35 a quarter in 1995 to 65 and 92 in the last two quarters (Confirmed [16]). Senator Leahy, citing a Carnegie Mellon report, put the 1995 figure at more than 12,000 computers attacked in more than 2,400 incidents (Reported [58]). These are reports handled, not attacks, and GAO's detection figures in Part 3 say most attacks were never reported (Inferred).

## Part 3: the Defense record and the Harvard case

### Counting attacks on Defense systems

GAO released AIMD-96-84, "Information Security: Computer Attacks at Department of Defense Pose Increasing Risks", on 22 May 1996 (Confirmed [9]). It says DISA data imply Defense "may have experienced as many as 250,000 attacks last year", successful 65 percent of the time (Confirmed [7]). The basis is DISA's own program of 38,000 test attacks since 1992: access was gained 65 percent of the time, only 988 successes (about 4 percent) were detected and 267 of those (about 27 percent) reported, so about 1 in 150 drew a defensive response (Confirmed [8][10]). Reported incidents rose from 53 in 1992 to 115, 255 and 559 in 1995 (Confirmed [7]). GAO's summary and body give different ratios for the response rate, 1 in 500 and about 1 in 150 (Confirmed [10]). It also reports a Department of Energy and NSA estimate that more than 120 countries had or were developing computer attack capabilities (Reported [10]). GAO recommended department-wide policy with mandatory incident reporting, routine risk assessments, training, and monitoring and protection technology including firewalls, smart cards and network monitoring (Confirmed [8]).

The AP's account of the same day said hackers infiltrate Pentagon computers more than 160,000 times a year; a RISKS contributor who watched the testimony pointed out that the 65 percent figure was DISA's test success rate, not real attacks (Reported [52]).

### Rome Laboratory, told again in 1996

The best-documented Defense intrusion in the 1996 hearings happened in 1994. GAO describes more than 150 intrusions at Rome Laboratory in March and April 1994 by two hackers using Trojan horses and sniffers, routed through South American telephone switches and US commercial sites, who controlled support systems for several days, at a cost of over $500,000 (Confirmed [7][8]). Air Force officials told GAO at least one hacker may have been working for a foreign country; no state is named, and one attacker was never caught (Confirmed [10]). The PSI minority staff statement dates the first penetration to 23 March 1994 and its discovery to 28 March, counts seven systems penetrated, 30 systems compromised through sniffers and more than 100 accounts, and says Rome Lab was then used as a launching platform (Confirmed [14]). The same statement names an unknown third party, "Kuji", directing "Datastream" (Reported [13]).

### The Harvard intruder

The Justice Department release of Friday 29 March 1996 announced a criminal complaint and arrest warrant against Julio Cesar Ardita, 21, of Buenos Aires (Confirmed [4][5]). He had reached a Harvard Faculty of Arts and Sciences host by modem bank and the Internet, stolen accounts and passwords, and used the host as a staging point into the Naval Research Laboratory, NASA's Jet Propulsion Laboratory and Ames Research Center, Los Alamos and the Naval Command Control and Ocean Surveillance Center (Confirmed [4][5]). Investigators ran what the Department calls the first court-ordered wiretap on a computer network over the last two months of 1995; a court order was needed because the system posted no monitoring banner, and investigators profiled the "signature programs he used to intercept passwords" (Confirmed [5][4]). He was not accused of obtaining classified information (Confirmed [5]). The complaint, issued by Magistrate Judge Marianne Bowler, charged fraudulent possession of passwords and other access devices, destructive activity in connection with computers, and illegal interception of electronic communications; Argentine authorities had seized his equipment on 28 December 1995 (Confirmed [4]). GAO describes an Argentine attacker's use of a US university in 1995 and 1996 (Confirmed [7]), which this study takes to be the same case (Inferred). In May 1998 he returned voluntarily to plead guilty in Boston, since he could not be extradited under the treaty then in force (Reported [6]).

### The Senate hearings

The Senate Permanent Subcommittee on Investigations held three hearings: National Information System Security on 22 May, Security in Cyberspace on 5 June and Foreign Information Warfare Activities Against the United States on 25 June (Confirmed [11]). Senator Nunn's opening statement on 5 June said the intelligence community had few analysts dedicated to the problem, cited GAO's 250,000 figure and a CSI and FBI survey in which 42 percent reported unauthorized access, and referred to the Critical Information Working Group under Deputy Attorney General Jamie Gorelick (Confirmed [15]). The minority staff statement covered the national information infrastructure's dependency, the lack of a security culture, the lack of detection and reporting, and recommendations (Confirmed [14]); its threat section rests, in its own words, on limited data (Reported [13]).

## Part 4: crime and prosecutions

### The cash-management transfer ring (summary)

The ring that moved money out of a major US bank's cash management system in 1994 is told in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md). In 1996 the case was in court: Reuters reported on 4 January that a co-conspirator had pleaded guilty in New York and that the ring's leader, arrested at Heathrow, was awaiting extradition (Reported [47]). The PSI staff statement in June counted 1994 losses of $400,000 to hackers in St. Petersburg (Reported [13]).

### Mitnick (summary)

Kevin Mitnick's case is told in the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md). In 1996 he pleaded guilty on 22 April to one count of access device fraud in the North Carolina case and was indicted in Los Angeles on 26 September on 25 counts of access device, wire and computer fraud, with a co-defendant charged on 14 of them (Reported [39]).

### Insider sabotage at Omega Engineering

The year's best-documented insider case surfaced in court only later. By the count on which he was convicted, Timothy Allen Lloyd, terminated on 10 July 1996, activated on 30 July a time bomb that permanently deleted all of Omega Engineering's manufacturing software programs; the indictment put the loss at at least $10 million in sales and future contracts; he was convicted on 9 May 2000 and sentenced on 26 February 2002 to 41 months (Confirmed [38]). A second insider charge of the year is less certain: a New England manufacturer lost all its computer data for 15 hours from 11 pm on 16 September, and a contract help-desk employee was charged with planting a virus and denied it; the outcome was not checked and the person is not named here (Reported [59]).

### Intrusions at a provider and a university

On 27 February an intruder masquerading as the administrator of BerkshireNet, a Pittsfield, Massachusetts provider, planted racist messages, erased data on two computers and shut the system down for about 12 hours (Reported [50]). On 27 April the *Daily Mail* reported that research files at Cambridge University had been reached via the Internet and that up to 10,000 users were told to change their passwords after an inter-university network monitor detected a rogue program (Reported [51]).

### Abuse of a mail system

From 5:30 pm PDT on 21 August Netcom halted its mailing lists after a user who had been subscribed to many lists retaliated with a loop of bounce messages to every subscriber (Reported [56]).

### Supervision after release

On 16 December the Justice Department announced that the US Parole Commission had approved special conditions restricting high-risk parolees' computer and Internet use: prior approval to use online services, a ban on encryption, unannounced examinations, and monitoring equipment at the parolee's expense (Confirmed [37]).

### Claims without a record

Three widely relayed 1996 stories have no primary record in this study. The *Sunday Times* of 2 June claimed City of London and US institutions had paid up to 400m pounds to extortion gangs in more than 40 attacks since 1993 (Reported [53]). The *Sunday Times* of 4 August claimed US intelligence had hacked European Parliament and Commission systems for trade advantage (Reported [54]). A November newsletter relayed an interview claim that intruders stole 50 million Kc, about $1.9 million, from unnamed Czech banks, and its contributor flagged it as unchecked (Reported [62]). None is used for a finding.

## Part 5: the defacements

### The Justice Department, August

Intruders replaced the Justice Department's home page with swastikas, obscene images and criticism of the Communications Decency Act; the St. Petersburg Times account relayed by Edupage says it was found on Saturday morning, 17 August, and the site was shut down, while *Federal Computer Week* dates the break-in to 16 August and says the Department had not determined how they got in (Reported [55][75]). The Act it protested is Title V of the Telecommunications Act of 1996 (Confirmed [27]). Days later the Computer Security Institute released a survey of 77 government agencies: about 57 percent had no policies for securing systems or responding to attacks, 6 percent did not know, and nearly 39 percent reported unauthorized use (Reported [75]).

### The CIA, September

On 18 September, by the *San Francisco Chronicle*'s account, a group of Swedish intruders altered the CIA's site to read "Central Stupidity Agency"; the CIA pulled it the next day, the same day the Justice Department reopened its site (Reported [58]). *Federal Computer Week* dates the change to early Thursday 19 September, with links redirected and the Director's photograph replaced, the site down shortly after 7:30 a.m., and the CIA saying it was a stand-alone system with no links to classified files (Reported [76]). *Government Executive* reported the hacked version up about 12 hours and the group calling itself "Power Through Resistance", protesting a Swedish court case against other hackers (Reported [77]). Both the Justice Department and CIA pages were copied and mirrored before they were removed; one mirror drew 50,000 views on its first day (Reported [78]).

### The Air Force, December

On Sunday 29 December intruders altered an af.mil placeholder site meant to redirect to Air Force Link; the Defense Technical Information Center shut down all 80 servers supporting Defense web sites, DefenseLink included, as a precaution, the Air Force cited "administrative snafus", and DTIC's servers hosting Air Force Link were not penetrated (Reported [79]). The *New York Times* account relayed in RISKS has an Air Force spokesman suggesting access was limited to one PC and notes that NASA pages had been altered earlier (Reported [64]).

## Part 6: viruses follow the platforms

### Boza, the first Windows 95 virus

*Virus Bulletin*'s February issue analysed the first Windows 95 virus, proposing the names V32 and Boza; it called itself Bizatch and credited Quantum of the VLAD group, and it was a simple non-resident, direct-action PE file infector not believed to be in the wild (Reported [66]). The March editorial said it had been compared to the 1992 Michelangelo scare and had drawn a media frenzy, but it was not in the wild, was largely uninteresting and destroyed no data; it drew attention only because it was the first, and to the question whether Windows 95 was protected VB answered that it was "not protected, just different" (Reported [67]).

### Hare

*Virus Bulletin* received a sample of Hare.7610 (also Krsna) at the end of May and in August described a multipartite, slow-polymorphic, encrypted virus, the largest non-Windows virus then in the wild, set to overwrite hard drives on 22 August and 22 September and seeded through Usenet groups (Reported [69]). It reported it in the wild in Canada, Russia, the Netherlands, Switzerland, the UK and the USA, and elsewhere in Australia, Europe and North America (Reported [69]).

### Laroux and the macro year

Laroux, written in VBA, is the first Excel virus found in the wild; it was discovered at the end of July, has no payload, and, like Concept, circulated before anyone noticed it (Reported [69][70]). VB noted that Excel's VBA could do far more than Word's WordBasic and that Excel's binary format made detection harder (Reported [69]). The Wazzu Word macro virus was shipped on Microsoft's September Solution Provider CD and on a CD given away at the ORBIT show in Basel (Reported [71]); Klaus Brunnstein reported first-hand that the infected document stayed downloadable from Microsoft's Swiss site for at least five days after a warning (Reported [60]). In VB's October prevalence table of 712 reports, the boot viruses Form.A (8.4 percent) and AntiEXE.A (7.3 percent) led, Concept was third (6.6 percent), MDMA had 5.5 and Wazzu 5.1 (Reported [72]). The macro rows, Concept, MDMA, Wazzu, Imposter, Npad, Assistant, Laroux and Irish, add up to 185 reports, about 26 percent (Demonstrated [72]).

### The courts

*Virus Bulletin*'s January editorial called Christopher Pile's November 1995 sentence of 18 months the first custodial sentence in the UK for writing and distributing viruses (Reported [65]).

## Part 7: cryptography and transport security

### Export-grade SSL and fault attacks

On 10 January a vendor press release said an MIT undergraduate had broken a Netscape export-grade 40-bit RC4 SSL session in under eight days on one graphics computer, and put the cost at $584 a session against Netscape's own $10,000 figure (Reported [48]). On 26 September the *New York Times* reported Bellcore researchers Boneh, DeMillo and Lipton's announcement of fault-induced attacks on public-key computations in smart cards (Reported [59]). On 18 October Biham and Shamir extended fault attacks to secret-key ciphers and recovered a DES key on a PC from fewer than 200 faulty ciphertexts (Demonstrated [61]). In February CERT's Kerberos 4 advisory had already shown how a weak random number generator undoes a protocol: session keys breakable in at most 2 to 4 minutes (Confirmed [1]).

### SSL 3.0 and the start of TLS

RFC 6101, published in 2011 for the historical record, documents "the November 18, 1996, version" of SSL 3.0 and calls it the basis for TLS (Confirmed [86]). The IETF's TLS working group was proposed on 7 May 1996 and started on 24 May; the Secure Shell working group did not start until 20 February 1997 (Confirmed [87]). RFC 1948, Bellovin's May 1996 memo, cites CA-95:01 on the 1995 spoofing attacks and proposes a separate initial sequence number space for each connection built from a clock and a keyed hash, so attackers cannot predict sequence numbers (Confirmed [88]).

### Export control and the courts

In *Bernstein v. US Department of State*, the Northern District of California denied the government's motion to dismiss on 15 April, finding that source code supports a colorable First Amendment claim, and on 6 December (entered 16 December) held certain ITAR provisions invalid as a prior restraint on cryptographic speech, denying a preliminary injunction without prejudice (Confirmed [33][34]). Executive Order 13026 of 15 November set the terms for encryption items moving from the State Department's Munitions List Category XIII to the Commerce Control List under the Export Administration Regulations: interagency license review, encryption software not treated as technology, controls that may promote key recovery, and foreign-availability provisions disapplied (Confirmed [31][32]). The Wassenaar Arrangement, agreed in December 1995, adopted its Initial Elements on 11 to 12 July 1996, began control lists and information exchange on 1 November and held its first operational Plenary on 12 to 13 December; its dual-use list includes Category 5 Part 2, Information Security (Confirmed [30]). The National Research Council's study "Cryptography's Role in Securing the Information Society" was published the same year (Confirmed [35]).

## Part 8: the state and intelligence record

### No state intrusion on the record

No primary opened for this study attributes a 1996 intrusion to a state (Inferred). The DCI's testimony of 25 June said a number of countries were developing doctrine, strategies and tools for information attack, mostly for battlefield information dominance; he named no state program and no attributed intrusion, said hackers might be supplying expertise to Iran and Libya, and said the source and purpose of bank intrusions were not fully understood (Confirmed [12]). He described well-publicized diversions of funds by false bank wires, embezzlement and credit card fraud as apparently isolated and limited to theft, and said obtaining intrusion data from US banks and telecommunications companies had been a problem (Confirmed [12]). His greatest concern was a coordinated information-warfare attack on electric power distribution, air traffic control or finance; in summer 1995 the National Intelligence Council had produced a classified report, the first of its kind, on foreign efforts to attack the US public switched telephone network and SCADA systems (Confirmed [12]). No 1996 intrusion into an industrial control system appears in any primary opened (Inferred). The concern later became an operational record in [Stuxnet](/case-studies/STUXNET.md) and the attacks in the [ICS study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) (Inferred).

The PSI minority staff statement of 5 June relays, qualified "if true", an allegation from subcommittee sources that an unnamed foreign government sponsored a hacker bulletin board to collect other governments' passwords (Reported [13]). It recalls the Hanover hackers who reportedly worked for the KGB, whose case is told in [The Cuckoo's Egg Intrusion](/case-studies/CUCKOOS_EGG_1986.md), and warns that apparently domestic attacks may originate abroad (Reported [13]). The *Sunday Times* story about US intelligence and European institutions has no primary record (Reported [54]).

### Moonlight Maze (summary)

Moonlight Maze has its home in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), section 2.4. Kaspersky's GReAT and King's College London researchers wrote in April 2017 that in 1996 an actor was rummaging through mainly US military, research and university networks (Reported [40]; their evidence spans 1998 to 1999, plus samples apparently compiled as far back as late 1996). They name the Pentagon, NASA and the Department of Energy among the victims and relay investigators' remark that the printed stolen material would stand three times taller than the Washington Monument (Reported [40]). They call their hypothesis linking Moonlight Maze to Turla circumstantial and a conclusion premature; sources told Thomas Rid the actor evolved into modern Turla, which is unverified, and the researchers trace Penquin Turla to the LOKI2 code base published in Phrack in the late 1990s (Reported [40]). Kaspersky's blog the same day describes the actor as active since at least 1996 and says several independent experts associate it with Turla's authors (Reported [41]). ATT&CK's Turla page ([G0010](/mitre/groups/G0010.md)) attributes the group to Russia's FSB, active since at least 2004, and does not mention Moonlight Maze or 1996; its Penquin page ([S0587](/mitre/software/S0587.md)) dates Turla's use of Penquin against Linux from at least 2014 (Confirmed [42][43]). The Russia-attributed actors are covered in the [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md).

### Equation infrastructure (summary)

The library's [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) records, on Kaspersky's 2015 report, that some Equation group command-and-control domains were registered as early as 1996 (Reported [100]); the group's tools and their leak are told in the [tool leaks study](/case-studies/NSA_CIA_TOOL_LEAKS.md). No 1996 operation is attributed through them in any record this study opened (Inferred).

## Part 9: the government record

### Law

- **Telecommunications Act of 1996**, Pub. L. 104-104, approved 8 February; Title V is the Communications Decency Act (Confirmed [27]).
- **Information Technology Management Reform Act of 1996** (Clinger-Cohen), Division E of Pub. L. 104-106, approved 10 February; section 5125 requires an agency Chief Information Officer responsible for IT architecture and information resources management (Confirmed [28]).
- **HIPAA**, Pub. L. 104-191, approved 21 August: section 1173(d) requires security standards for health information and "reasonable and appropriate administrative, technical, and physical safeguards", weighing technical capability, cost, training, the value of audit trails in computerized records and the needs of small and rural providers; section 1177 creates a wrongful-disclosure offense, up to $50,000 and one year, and up to $250,000 and ten years for sale or commercial advantage (Confirmed [25][26]). The health-sector consequences decades later run through the [Change Healthcare study](/case-studies/CHANGE_HEALTHCARE_2024.md) and the [healthcare watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md) (Inferred).
- **Economic Espionage Act of 1996**, Title I of Pub. L. 104-294, approved 11 October: 18 U.S.C. 1831, economic espionage benefiting a foreign government, instrumentality or agent, up to 15 years; 1832, theft of trade secrets, up to 10 years (Confirmed [20][23]).
- **National Information Infrastructure Protection Act of 1996**, Title II of the same law: 18 U.S.C. 1030 now protects any "protected computer", including any computer used in interstate or foreign commerce or communication, in place of the "Federal interest computer"; damage offenses in three tiers, with damage defined by a $5,000 one-year threshold or medical, injury or public-safety effects; a new (a)(7) offense for extortion threats; and revised (a)(1) on protected national security information (Confirmed [20][22][24]). H.R. 3723 passed the House on 17 September and the Senate on 18 September (Confirmed [20]). The CFAA's longer history is in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Confirmed [44]).

### Orders and policy

- **Attorney General memo, 14 March.** Under PDD-39 the Attorney General chaired a Cabinet Committee to review critical infrastructure vulnerability to physical and "cyber" attack; the Critical Infrastructure Working Group recommended a full-time task force in the Executive Office of the President with a private-sector lead, and an interim FBI-chaired interagency group in the Justice Department (Confirmed [36]).
- **Executive Order 13010, 15 July** (61 FR 37347, 17 July): names eight critical infrastructures, defines cyber threats as electronic, radio-frequency or computer-based attacks on the information or communications components that control them, says government and the private sector must work together, and creates the President's Commission on Critical Infrastructure Protection and an interim Infrastructure Protection Task Force in the Justice Department chaired by the FBI (Confirmed [17][18][19]).
- **Executive Order 13026, 15 November** on encryption exports (Part 7) (Confirmed [31]).
- **US Parole Commission conditions, 16 December** (Part 4) (Confirmed [37]).

### Standards

- **NIST SP 800-14**, Generally Accepted Principles and Practices for Securing Information Technology Systems (Swanson and Guttman), September 1996, a baseline for establishing and reviewing IT security programs; withdrawn on 16 March 2018 (Confirmed [90]).
- **OMB Circular A-130, Appendix III**, Security of Federal Automated Information Resources: security plans, an incident response capability, control reviews at least every three years and written management authorization to process; it replaces the 1985 version. The page opened does not state its 1996 revision date (Confirmed [29]; not checked for the date).
- **RFCs.** RFC 1918 private addressing (February, BCP 5); RFC 1928 and 1929 SOCKS 5 and its authentication (March); RFC 1938 One-Time Password System (May, Standards Track, successor to S/KEY); RFC 1945 HTTP/1.0 (May); RFC 1948 sequence number defenses (May); RFC 1964 Kerberos V5 GSS-API (June); RFC 1994 PPP CHAP (August); RFC 2015 MIME security with PGP and RFC 2040 RC5 (October). DNSSEC (RFC 2065) and HMAC (RFC 2104) followed in January and February 1997 (Confirmed [88][89]).

## Part 10: the defender view

The year's defensive record is mostly CERT's remediation advice, GAO's recommendations and new standards, read against the attacks that prompted them (Inferred).

**Filter at the edge, in both directions.** CA-96.21's ingress and egress filtering was the only control CERT could name against spoofed SYN floods, and CERT said plainly that it would not stop them all (Confirmed [1]). WebCom's outage ended when an upstream carrier blocked the traffic, which is the same control applied one network further out (Reported [63]; Inferred).

**Reduce the attack surface.** Disable chargen, echo and unused UDP services; remove example CGI programs such as phf; never place interpreters in CGI directories, whatever vendor documentation says (Confirmed [1]).

**Stop trusting the network for identity.** Upgrade to BIND 4.9.3 or turn off DNS name-based authentication; validate host names and addresses before reuse; bind applet connections to numeric addresses (Confirmed [1]). RFC 1948 hardened sequence numbers against prediction, and RFC 1938 standardized one-time passwords against sniffing (Confirmed [88][89]).

**Patch local privilege flaws as if they were remote.** Most of the year's local root advisories came with public scripts, and sendmail needed three upgrades in three months (Confirmed [1]).

**Expect a crash to be part of an attack.** CERT's ping advisory told sites to check a crashed router's or firewall's running configuration before patching (Confirmed [1]).

**Detect, report and count.** GAO found about 4 percent of successful test intrusions detected and recommended mandatory incident reporting, risk assessments, training and monitoring technology (Confirmed [8]); OMB's Appendix III requires an incident response capability (Confirmed [29]); HIPAA names audit trails among the factors for health security standards (Confirmed [25]).

**Reset credentials after an intrusion.** Cambridge told up to 10,000 users to change passwords once a monitor found a rogue program (Reported [51]).

**Monitor lawfully.** The Ardita wiretap needed a court order because the Harvard system displayed no banner (Confirmed [5]).

**Watch insiders at the exit.** The Omega time bomb went off 20 days after termination (Confirmed [38]; Inferred for the lesson).

## Part 11: MITRE mappings

No 1996 record carries an ATT&CK, CAPEC or CWE id: CVE began in 1999; MITRE's first CWE release came in 2006; CAPEC, established under the DHS Software Assurance initiative, was first released in 2007; and ATT&CK's first model dates from September 2013, with a public release in May 2015 of 96 techniques (Confirmed [81][91][92][93]). D3FEND is funded by the NSA Cybersecurity Directorate and managed by MITRE-operated NSEC (Confirmed [94]). Every binding below is therefore this study's later mapping (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `technique_to_d3fend.jsonl`, `data/weaknesses/cwe.jsonl`, `capec.jsonl`) and the generated pages under `mitre/` on 12 November 2026 (Demonstrated [46][95][96][97][98]). Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md): **Described** means a primary source describes the behavior and this study assigns the id; **Reported** means only a secondary source supports the behavior; **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading. No row is **Listed**, because no 1996 source prints an id.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1499.001`](/mitre/techniques/T1499-001.md) | OS Exhaustion Flood | impact | Described | CA-96.21 SYN flooding, 19 Sep (the library's text names SYN floods); Panix, early Sep; WebCom, 14 Dec | [1][57][63][95] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | CA-96.01 UDP packet storm, 8 Feb | [1] |
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | impact | Inferred | CA-96.01: two services answering each other with spoofed sources (a stretch) | [1] |
| [`T1499.004`](/mitre/techniques/T1499-004.md) | Application or System Exploitation | impact | Described | CA-96.26 oversized ping crashes, freezes or reboots systems, 18 Dec | [1] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | impact | Reported | Justice Department, 16 or 17 Aug; CIA, 18 or 19 Sep; Air Force placeholder site, 29 Dec | [55][58][64][75][76][79] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | CA-96.06 phf and example CGI code, actively exploited, 20 Mar; CA-96.11 interpreters in CGI directories, 29 May | [1] |
| [`T1059.004`](/mitre/techniques/T1059-004.md) | Unix Shell | execution | Inferred | Commands run through the shell on web servers via phf and interpreters in CGI directories | [1] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Described | CA-96.12 to CA-96.19 (26 Jun to 15 Aug), CA-96.20 and CA-96.24 sendmail (18 Sep, 21 Nov), CA-96.22 bash (8 Oct), CA-96.27 SD-UX (19 Dec); Phrack 49, 8 Nov | [1][74] |
| [`T1548.001`](/mitre/techniques/T1548-001.md) | Setuid and Setgid | privilege-escalation | Inferred | Abuse of setuid programs: fm_fls (14 Aug), WorkMan (28 Oct) | [1] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Stolen Harvard FAS accounts used against Navy, NASA and Los Alamos systems (complaint 29 Mar); BerkshireNet intruder masquerading as the administrator, 27 Feb | [4][5][50] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | The Harvard intruder's password-intercepting programs; sniffers in 7.5 percent of CERT's Q1 1996 closed incidents (with spoofing and infrastructure attacks); Rome Laboratory sniffers (1994, reported 22 May and 5 Jun) | [4][16][7][14] |
| [`T1090.003`](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | command-and-control | Inferred | The Harvard host used as a staging point into other networks (a weak tie: the record describes staging, not a proxy chain) | [4][5] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Described | CA-96.07: a booby-trapped page compromises visitors through the bytecode verifier, 29 Mar (no exploitation reported); the Princeton demonstration, 18 Feb | [1][49] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | CA-96.07: a malicious applet can do anything the user can, 29 Mar | [1] |
| [`T1137.001`](/mitre/techniques/T1137-001.md) | Office Template Macros | persistence | Inferred | Concept, Wazzu and Laroux among the year's prevalent macro viruses (their template mechanism is not described in the sources opened) | [69][72] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Inferred | Macro viruses spread through shared and shipped documents, including Wazzu on Microsoft and ORBIT CDs | [71][60] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Visual Basic | execution | Reported | Laroux written in VBA, Jul to Aug | [69] |
| [`T1542.003`](/mitre/techniques/T1542-003.md) | Bootkit | stealth, persistence | Inferred | Hare.7610, a multipartite virus (multipartite implies boot-record infection; the sources opened do not spell it out) | [69] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Content Wipe | impact | Reported | Hare.7610 set to overwrite hard drives on 22 Aug and 22 Sep | [69] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Described | Omega Engineering time bomb deletes manufacturing programs, 30 Jul; BerkshireNet data erased, 27 Feb | [38][50] |

Left out on purpose: the 40-bit SSL break and the smart card and DES fault attacks, which are cryptanalysis rather than adversary behavior ATT&CK models; the Kerberos 4 session-key weakness, for which T1110 Brute Force (credential guessing) is too loose a fit; the DNS data corruption of CA-96.02 and CA-96.04, for which the library's only DNS cache poisoning link is T1584.002 DNS Server, a resource-development technique that does not describe corrupting a victim's resolver (Inferred [96]); the BerkshireNet shutdown, whose source does not say how it was done; the Netcom bounce loop, a mail-list abuse no technique describes well; and Boza, which VB says was not in the wild (Inferred).

### ATT&CK for ICS techniques

None. The DCI described a classified 1995 report on foreign efforts against the public switched telephone network and SCADA systems, but no 1996 intrusion into an industrial control system appears in any primary opened (Confirmed [12]; Inferred). No ICS layer is published.

### ATT&CK groups, software and campaigns

None. No ATT&CK group, software or campaign object records a 1996 operation (Inferred [42][43][44]). Moonlight Maze reaches an ATT&CK id only through the unproven Turla lineage: the Turla page ([G0010](/mitre/groups/G0010.md)) dates the group from at least 2004 and the Penquin page ([S0587](/mitre/software/S0587.md)) from at least 2014, and neither mentions Moonlight Maze or 1996 (Confirmed [42][43]). The library's home study maps Multi-hop Proxy and compromised servers to Moonlight Maze relays dated 1998 to 1999, not 1996, so no technique row here rests on a 1996 state event (Inferred [44]). Equation ([G0020](/mitre/groups/G0020.md)) is named only for the 1996 domain registrations its home study records (Reported [100]). Ardita, the Omega defendant, Boza, Hare, Laroux, Wazzu and the 1996 SYN flood tools have no ATT&CK objects (Inferred).

### CWE and CAPEC

Five of NVD's back-dated 1996 records carry a specific CWE (Demonstrated [82]); the rows marked "as NVD lists it" use those. Every other row is this study's binding (Inferred). The CAPEC column says which pairings the library's data makes and which are this study's own [96][98].

| CWE | Weakness (library name) | 1996 record | CAPEC |
|---|---|---|---|
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command (as NVD lists it for CVE-1999-0067) | CA-96.06 phf and escape_shell_cmd(), 20 Mar | [CAPEC-88](/mitre/capec/CAPEC-88.md) OS Command Injection (the library relates it to CWE-78) |
| CWE-94 | Improper Control of Generation of Code (as NVD lists it for CVE-1999-0509) | CA-96.11 interpreters in CGI directories, 29 May | [CAPEC-88](/mitre/capec/CAPEC-88.md) as the nearest library pattern (this study's pairing) |
| CWE-770 | Allocation of Resources Without Limits or Throttling | CA-96.21 SYN flooding; CA-96.01 UDP storm; CA-96.26 oversized ping | [CAPEC-482](/mitre/capec/CAPEC-482.md) TCP Flood (the library relates it to CWE-770, T1498.001, T1499.001 and T1499.002); [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding (the library relates it to CWE-770, T1498.001 and T1499); [CAPEC-490](/mitre/capec/CAPEC-490.md) Amplification (the library relates it to T1498.002); [CAPEC-496](/mitre/capec/CAPEC-496.md) ICMP Fragmentation (the library relates it to CWE-770, with no ATT&CK link) |
| CWE-121, CWE-120 | Stack-based Buffer Overflow; Buffer Copy without Checking Size of Input | Local root overflows of mid-1996; Phrack 49, 8 Nov | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers (the library relates it to CWE-120) |
| CWE-250 | Execution with Unnecessary Privileges | Set-uid programs in CA-96.12 to CA-96.23 | [CAPEC-69](/mitre/capec/CAPEC-69.md) Target Programs with Elevated Privileges (the library relates it to CWE-250) |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | fm_fls (14 Aug), WorkMan (28 Oct), NIS+ passwd table (28 May) | [CAPEC-233](/mitre/capec/CAPEC-233.md) Privilege Escalation (the library relates it to T1548) |
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | CA-96.03 Kerberos 4 session keys, 21 Feb | [CAPEC-59](/mitre/capec/CAPEC-59.md) Session Credential Falsification through Prediction (the library relates it to CWE-330) |
| CWE-346, CWE-693 | Origin Validation Error; Protection Mechanism Failure | CA-96.05 applet connections trusted by host name; CA-96.07 bytecode verifier | The library relates CWE-346 to CAPEC-59 and CAPEC-142 and CWE-693 to CAPEC-59; neither pattern describes an applet's connection rule or a bytecode verifier, so none is assigned (this study's judgement) |
| CWE-350, CWE-348 | Reliance on Reverse DNS Resolution for a Security-Critical Action; Use of Less Trusted Source | CA-96.02 DNS-based authentication; CA-96.04 corrupt DNS data | [CAPEC-142](/mitre/capec/CAPEC-142.md) DNS Cache Poisoning (the library relates it to CWE-348 and CWE-350) |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | Boza, Hare, Laroux, Wazzu | No clean CAPEC fit; none is assigned |
| none bound | (sniffing) | The Harvard password interception; Rome Laboratory sniffers | [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (the library relates it to T1040) |

NVD also lists CWE-125 for CVE-1999-0022 and CWE-264 for CVE-1999-1383; this study does not pair either record with a 1996 advisory, and CWE-264 is a category absent from the library's CWE data (Demonstrated [82][98]).

### D3FEND countermeasures

Pairings come from `data/attack/technique_to_d3fend.jsonl` unless the row says the pairing is this study's; every page exists under `/mitre/d3fend/` (Demonstrated [97][46]).

| Technique from the record | D3FEND countermeasures | 1996 analogue |
|---|---|---|
| T1499.001 OS Exhaustion Flood | The library has no pairing. [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) and [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) are concept matches for CERT's ingress and egress filters, and [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) for its SYN_RECEIVED count (this study's pairings) | CA-96.21 ISP filtering; vendor kernel hardening [1] |
| T1498.001 and T1498.002 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) (library pairings) | CA-96.01: disable chargen and echo, block UDP below 900 at the firewall [1] |
| T1499.004 Application or System Exploitation | The library has no pairing, and none is invented here | CA-96.26 vendor patches and a configuration check of crashed routers [1] |
| T1190 Exploit Public-Facing Application | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (library pairings); [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) is a concept match for removing phf and interpreters (this study's pairing) | CA-96.06 and CA-96.11 [1] |
| T1068 Exploitation for Privilege Escalation | [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (library pairings); none appears in the 1996 advisories, whose fixes were patches and upgrades (Inferred) | sendmail 8.7.6, 8.8.3 and 8.8.4; vendor patches [1] |
| T1548.001 Setuid and Setgid | [Access Modeling](/mitre/d3fend/access-modeling.md), [Configuration Inventory](/mitre/d3fend/configuration-inventory.md), [Restore Configuration](/mitre/d3fend/restore-configuration.md) (library pairings) | Removing set-uid bits from fm_fls and WorkMan [1] |
| T1078 Valid Accounts | [Account Locking](/mitre/d3fend/account-locking.md), [Change Default Password](/mitre/d3fend/change-default-password.md), [User Account Permissions](/mitre/d3fend/user-account-permissions.md) (library pairings) | Cambridge's password reset for up to 10,000 users [51] |
| T1040 Network Sniffing | The library maps only [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md). [One-time Password](/mitre/d3fend/one-time-password.md) is a concept match the library does not map to T1040 | RFC 1938 One-Time Password System, May 1996 [89] |
| T1090.003 Multi-hop Proxy | [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md), [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (library pairings) | The court-ordered wiretap on the Harvard host [5] |
| T1189 and T1203 | [URL Analysis](/mitre/d3fend/url-analysis.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (library pairings); [Content Filtering](/mitre/d3fend/content-filtering.md) is a concept match for refusing .class files at a proxy (this study's pairing) | CA-96.05 and CA-96.07: disable Java or filter applets [1] |
| T1137.001, T1204.002 | [File Analysis](/mitre/d3fend/file-analysis.md), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md), [Emulated File Analysis](/mitre/d3fend/emulated-file-analysis.md), [Content Filtering](/mitre/d3fend/content-filtering.md) (library pairings) | Anti-virus scanning of documents and templates [72] |
| T1542.003 Bootkit | [Bootloader Authentication](/mitre/d3fend/bootloader-authentication.md), [Software Update](/mitre/d3fend/software-update.md) (library pairings) | No 1996 counterpart in the record |
| T1561.001 Disk Content Wipe | [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) (library pairing) | No 1996 counterpart in the record |
| T1491.002 External Defacement | [Decoy Network Resource](/mitre/d3fend/decoy-network-resource.md), [Network Resource Access Mediation](/mitre/d3fend/network-resource-access-mediation.md) (library pairings) | DTIC's precautionary shutdown of 80 servers [79] |

The library's data has no D3FEND pairing for T1499.001, T1499.004, T1485, T1059.004 or T1059.005, and none is invented here beyond the concept matches labelled above (Demonstrated [97]).

### Navigator layer

The study's techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-1996.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1996.json) (saved beside the other hand-authored layers [99]), listing the 20 techniques in the Enterprise table under each tactic they carry in v20.0, and listed on [the Navigator layers page](/navigator/index.md). Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping; no entry scores 100, because no 1996 source prints an id. Each entry's comment names the source numbers in the Sources table below. No ICS layer is needed.

## Cross-cutting themes

**Availability became the attack surface.** Three of the 27 advisories are pure denial of service, CERT said SYN flooding had no complete solution, and the floods that hit Panix and WebCom came within months of the code's publication (Confirmed [1][73]; Reported [57][63]). The same economics drive the floods and botnets in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) and the [ransomware ecosystem study](/case-studies/RANSOMWARE_ECOSYSTEM.md) (Inferred).

**Attack knowledge was published in full.** Project Neptune in July and Smashing the Stack in November put working technique in print, and most local root advisories followed a public script (Confirmed [73][74][1]). Mass exploitation after disclosure recurs in [Log4Shell](/case-studies/LOG4SHELL.md) and the [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md) (Inferred).

**Trusted distribution carried malicious code again.** Wazzu shipped on a Microsoft CD and on a CD handed out at a trade show (Reported [71][60]). The class recurs in the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies (Inferred).

**Government learned it could not see.** GAO's 4 percent detection figure, the CSI survey's 57 percent of agencies without policies and CERT's rising vulnerability reports all landed between May and August (Confirmed [8][16]; Reported [75]).

**The law moved from federal computers to every connected computer.** The "protected computer", HIPAA's safeguards, EO 13010's "cyber threats" and the economic espionage offense all date to 1996 (Confirmed [20][25][18][23]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: "250,000 attacks on the Pentagon".** It is DISA's extrapolation from its own 38,000 test attacks; the officially reported count for 1995 was 559, and the AP's "more than 160,000 times a year" and the 65 percent figure are not counts of real attacks [7][8][52].
- **Overstated: the press claims of extortion, bank thefts and EU espionage.** The 400m pound extortion story, the Czech bank losses and the US-intelligence-in-Brussels story have no court record, regulator notice or victim statement in the record opened [53][54][62].
- **Overstated: the defacements as deep intrusions.** They were public web pages; the CIA said its site was stand-alone with no links to classified files, an Air Force spokesman suggested access was limited to one PC, and DTIC's own servers were not penetrated [76][64][79].
- **Overstated: Boza.** It was compared to Michelangelo and drew a media frenzy, but *Virus Bulletin* said it was not in the wild and destroyed nothing [67].
- **Overstated: "first" claims.** First Windows 95 virus, first Excel virus in the wild and first custodial virus sentence are *Virus Bulletin*'s descriptions; first computer-network wiretap is the Justice Department's [66][69][65][4].
- **Overstated: CVE records dated 1996.** NVD's 75 records with 1996 dates were back-filled after CVE began in 1999, and some carry dates before their advisories or years after their fixes [82][84].
- **Overstated: any ATT&CK, CWE or CAPEC id on a 1996 event.** None of those programs existed until 2006 to 2015 [91][92][93].
- **Understated: denial of service.** SYN flood code was published, used and unfixable in the same year, and took a host with more than 3,000 sites down for 40 hours [1][73][63].
- **Understated: how little was seen.** About 1 in 150 successful test intrusions drew a defensive response, so every count of the year is a floor [8].
- **Understated: local root.** About half the advisories, most with public scripts, drew little attention beside the defacements and floods [1].
- **Understated: the insider.** The Omega time bomb cost at least $10 million in sales and future contracts by the indictment's figure, and the case was not tried until 2000 [38].
- **Understated: Moonlight Maze.** It began around 1996 by later research and was not public for years [40].
- **Understated: the policy year.** EO 13010, HIPAA's security standards, the protected-computer amendment, the economic espionage offense, EO 13026 and Wassenaar's start all fall in one year [18][25][20][31][30].

### Discrepancies in the record

- **The Justice Department defacement date.** 16 August in *Federal Computer Week*, found on Saturday morning 17 August in the account relayed by Edupage [75][55].
- **The CIA defacement date and duration.** 18 September and pulled the next day by the *San Francisco Chronicle*; early Thursday 19 September and down shortly after 7:30 a.m. by *Federal Computer Week*; up about 12 hours by *Government Executive* [58][76][77].
- **The Netcom outage.** The provider notice dates the halt to 21 August; the RISKS item reporting it is dated 23 August [56].
- **Phrack 48.** "Project Neptune" is dated July 1996 in its own header, while the phrack.org index dates issue 48 to "1996-01-09", whose day and month order is unclear [73].
- **GAO's response ratio.** 1 in 500 in the report's summary, about 1 in 150 in its body [10].
- **Hare's geography.** Canada, Russia, the Netherlands, Switzerland, the UK and the USA in one passage; Australia, Europe and North America in another [69].
- **Laroux's discovery.** The end of July in *Virus Bulletin*'s September editorial; reported in its August issue as already in the wild [70][69].
- **CA-96.27.** The SEI table of contents gives it the ping title of CA-96.26; the advisory body is the HP SD-UX reprint [1].
- **EO 13026.** One reading of the order says it moved encryption products to the Commerce Control List; another says it sets the conditions for items moved and makes no transfer itself [32][31].
- **The Bernstein order.** Dated 6 December, entered 16 December [34].
- **WebCom's start date.** The AP account says the Saturday before its 17 December story; 14 December is this study's inference [63].
- **Moonlight Maze's start.** Dated 1996 by the researchers, whose logs span 1998 to 1999 plus samples compiled from late 1996 [40].

## Sources

All sources were opened on 12 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links do not suit automated link checkers (the gao.gov product page refuses them and the NVD API query is rate-limited); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "1996 CERT Advisories" (compilation, CA-1996-01 to CA-1996-27) | https://www.sei.cmu.edu/documents/503/1996_019_001_496172.pdf | 2026-11-12 | Confirmed |
| 2 | CMU SEI, "1996 CERT Advisories" (landing page) | https://www.sei.cmu.edu/library/1996-cert-advisories/ | 2026-11-12 | Confirmed |
| 3 | CMU SEI, CERT Coordination Center 1996 annual report summary | https://www.sei.cmu.edu/library/cert-coordination-center-1996-annual-report-summary/ | 2026-11-12 | Confirmed |
| 4 | US Department of Justice, release #146, 29 March 1996 (Ardita complaint) | https://www.justice.gov/opa/pr/1996/March96/146.txt | 2026-11-12 | Confirmed |
| 5 | US Department of Justice, release #146, 29 March 1996 (FAS mirror) | https://irp.fas.org/news/1996/146.htm | 2026-11-12 | Confirmed |
| 6 | US Department of Justice, Ardita plea release, May 1998 (FAS mirror) | https://irp.fas.org/news/1998/05/arditasnt.htm | 2026-11-12 | Reported |
| 7 | GAO/AIMD-96-84, Computer Attacks at Department of Defense Pose Increasing Risks (govinfo HTML) | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-96-84/html/GAOREPORTS-AIMD-96-84.htm | 2026-11-12 | Confirmed |
| 8 | GAO/AIMD-96-84 (govinfo PDF) | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-96-84/pdf/GAOREPORTS-AIMD-96-84.pdf | 2026-11-12 | Confirmed |
| 9 | GAO, AIMD-96-84 product page | `https://www.gao.gov/products/aimd-96-84` | 2026-11-12 | Confirmed |
| 10 | GAO/AIMD-96-84 (FAS mirror) | https://irp.fas.org/gao/aim96084.htm | 2026-11-12 | Confirmed |
| 11 | FAS Intelligence Resource Program, cyber threat hearings index (1996 PSI hearings) | https://irp.fas.org/threat/cyber/ | 2026-11-12 | Confirmed |
| 12 | John Deutch, DCI, testimony to the Senate PSI, 25 June 1996 | https://irp.fas.org/congress/1996_hr/s960625d.htm | 2026-11-12 | Confirmed |
| 13 | Senate PSI minority staff statement, 5 June 1996, Part III, The Threat (allegations relayed) | https://irp.fas.org/congress/1996_hr/s9606053.htm | 2026-11-12 | Reported |
| 14 | Senate PSI minority staff statement, 5 June 1996, with Appendix B on Rome Laboratory | https://irp.fas.org/congress/1996_hr/s960605b.htm | 2026-11-12 | Confirmed |
| 15 | Senator Nunn, opening statement, 5 June 1996 | https://irp.fas.org/congress/1996_hr/s960605n.htm | 2026-11-12 | Confirmed |
| 16 | CERT/CC testimony to the Senate PSI, 5 June 1996 | https://irp.fas.org/congress/1996_hr/s960605m.htm | 2026-11-12 | Confirmed |
| 17 | Executive Order 13010, Critical Infrastructure Protection (American Presidency Project) | https://www.presidency.ucsb.edu/documents/executive-order-13010-critical-infrastructure-protection | 2026-11-12 | Confirmed |
| 18 | Executive Order 13010, Federal Register, 17 July 1996 (HTML) | https://www.govinfo.gov/content/pkg/FR-1996-07-17/html/96-18351.htm | 2026-11-12 | Confirmed |
| 19 | Executive Order 13010, Federal Register, 17 July 1996 (PDF) | https://www.govinfo.gov/content/pkg/FR-1996-07-17/pdf/96-18351.pdf | 2026-11-12 | Confirmed |
| 20 | Pub. L. 104-294, Economic Espionage Act of 1996 (HTML) | https://www.govinfo.gov/content/pkg/PLAW-104publ294/html/PLAW-104publ294.htm | 2026-11-12 | Confirmed |
| 21 | Pub. L. 104-294 (PDF) | https://www.govinfo.gov/content/pkg/PLAW-104publ294/pdf/PLAW-104publ294.pdf | 2026-11-12 | Confirmed |
| 22 | Cornell LII, 18 U.S.C. 1030 with amendment notes | https://www.law.cornell.edu/uscode/text/18/1030 | 2026-11-12 | Confirmed |
| 23 | US Code, 18 U.S.C. 1831 (govinfo, 2024 edition) | https://www.govinfo.gov/content/pkg/USCODE-2024-title18/html/USCODE-2024-title18-partI-chap90-sec1831.htm | 2026-11-12 | Confirmed |
| 24 | US Code, 18 U.S.C. 1030 (govinfo, 2024 edition) | https://www.govinfo.gov/content/pkg/USCODE-2024-title18/html/USCODE-2024-title18-partI-chap47-sec1030.htm | 2026-11-12 | Confirmed |
| 25 | Pub. L. 104-191, HIPAA (HTML) | https://www.govinfo.gov/content/pkg/PLAW-104publ191/html/PLAW-104publ191.htm | 2026-11-12 | Confirmed |
| 26 | Pub. L. 104-191, HIPAA (PDF) | https://www.govinfo.gov/content/pkg/PLAW-104publ191/pdf/PLAW-104publ191.pdf | 2026-11-12 | Confirmed |
| 27 | Pub. L. 104-104, Telecommunications Act of 1996 | https://www.govinfo.gov/content/pkg/PLAW-104publ104/html/PLAW-104publ104.htm | 2026-11-12 | Confirmed |
| 28 | Pub. L. 104-106, Division E, Information Technology Management Reform Act of 1996 | https://www.govinfo.gov/content/pkg/PLAW-104publ106/html/PLAW-104publ106.htm | 2026-11-12 | Confirmed |
| 29 | OMB Circular A-130, Appendix III | https://obamawhitehouse.archives.gov/omb/circulars_a130_a130appendix_iii | 2026-11-12 | Confirmed |
| 30 | Wassenaar Arrangement, About us | https://www.wassenaar.org/about-us/ | 2026-11-12 | Confirmed |
| 31 | Executive Order 13026, Federal Register, 19 November 1996 (HTML) | https://www.govinfo.gov/content/pkg/FR-1996-11-19/html/96-29692.htm | 2026-11-12 | Confirmed |
| 32 | Executive Order 13026, Federal Register, 19 November 1996 (PDF) | https://www.govinfo.gov/content/pkg/FR-1996-11-19/pdf/96-29692.pdf | 2026-11-12 | Confirmed |
| 33 | *Bernstein v. US Department of State*, order of 15 April 1996 | https://cr.yp.to/export/1996/0415-order.txt | 2026-11-12 | Confirmed |
| 34 | *Bernstein v. US Department of State*, memorandum and order of 6 December 1996 | https://cr.yp.to/export/1996/1206-order.txt | 2026-11-12 | Confirmed |
| 35 | National Research Council, Cryptography's Role in Securing the Information Society (1996) | https://nap.nationalacademies.org/catalog/5131/cryptographys-role-in-securing-the-information-society | 2026-11-12 | Confirmed |
| 36 | Attorney General memorandum on critical infrastructure, 14 March 1996 (EPIC archive) | https://archive.epic.org/security/infowar/reno_memo.html | 2026-11-12 | Confirmed |
| 37 | US Department of Justice, US Parole Commission release, December 1996 | https://www.justice.gov/archive/opa/pr/1996/Dec96/592usp.htm | 2026-11-12 | Confirmed |
| 38 | US Department of Justice, Omega Engineering sentencing release, 26 February 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/lloydSent.htm | 2026-11-12 | Confirmed |
| 39 | Takedown.com timeline, 1995 to 2000 (book companion site) | https://www.takedown.com/timeline/index_current.html | 2026-11-12 | Reported |
| 40 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze", 3 April 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Reported (1996 start and attribution); Confirmed (1998 to 1999 findings) |
| 41 | Kaspersky blog, "Moonlight Maze: lessons from history", 3 April 2017 | https://www.kaspersky.com/blog/moonlight-maze-the-lessons/6713/ | 2026-11-12 | Reported |
| 42 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 43 | MITRE ATT&CK, Penquin (S0587) | https://attack.mitre.org/software/S0587/ | 2026-11-12 | Confirmed |
| 44 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-12 | Confirmed |
| 45 | TeamStarWolf library, the era studies on main (`DOTCOM_ERA_CYBER_EVENTS.md`, `MITNICK_INTRUSIONS.md`, `ZERO_DAY_MARKET_EVENTS.md`) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-12 | Demonstrated |
| 46 | TeamStarWolf library, main branch, `mitre/techniques/` | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/techniques | 2026-11-12 | Demonstrated |
| 47 | RISKS Digest 17.61, "The Citibank hack, continued" (Reuters, 4 January 1996) | https://catless.ncl.ac.uk/Risks/17/61#subj4 | 2026-11-12 | Reported |
| 48 | RISKS Digest 17.65, cost to crack Netscape security (ICE press release, 10 January 1996) | https://catless.ncl.ac.uk/Risks/17/65#subj5 | 2026-11-12 | Reported |
| 49 | RISKS Digest 17.77, Drew Dean, "Java security problems", 18 February 1996 | https://catless.ncl.ac.uk/Risks/17/77#subj5 | 2026-11-12 | Demonstrated |
| 50 | RISKS Digest 17.83, BerkshireNet intrusion | https://catless.ncl.ac.uk/Risks/17/83#subj2 | 2026-11-12 | Reported |
| 51 | RISKS Digest 18.9, Cambridge University systems (Daily Mail, 27 April 1996) | https://catless.ncl.ac.uk/Risks/18/9#subj3 | 2026-11-12 | Reported |
| 52 | RISKS Digest 18.15, Senate hearing and GAO report (AP, 22 May 1996) | https://catless.ncl.ac.uk/Risks/18/15#subj6 | 2026-11-12 | Reported |
| 53 | RISKS Digest 18.17, Sunday Times extortion claim (2 June 1996) | https://catless.ncl.ac.uk/Risks/18/17#subj6 | 2026-11-12 | Reported |
| 54 | RISKS Digest 18.30, Sunday Times claim on European institutions (4 August 1996) | https://catless.ncl.ac.uk/Risks/18/30#subj7 | 2026-11-12 | Reported |
| 55 | RISKS Digest 18.35, Justice Department web site (Edupage, 18 August 1996) | https://catless.ncl.ac.uk/Risks/18/35#subj1 | 2026-11-12 | Reported |
| 56 | RISKS Digest 18.38, Netcom listservers (netcom.announce) | https://catless.ncl.ac.uk/Risks/18/38#subj4 | 2026-11-12 | Reported |
| 57 | RISKS Digest 18.45, Panix SYN flood (WSJ via Edupage; Panix staff, 13 September 1996) | https://catless.ncl.ac.uk/Risks/18/45#subj1 | 2026-11-12 | Reported |
| 58 | RISKS Digest 18.49, CIA home page (San Francisco Chronicle, 20 September 1996) and S 982 (Edupage, 24 September 1996) | https://catless.ncl.ac.uk/Risks/18/49 | 2026-11-12 | Reported |
| 59 | RISKS Digest 18.50, New England manufacturer data loss and Bellcore smart card attacks | https://catless.ncl.ac.uk/Risks/18/50 | 2026-11-12 | Reported |
| 60 | RISKS Digest 18.53, Klaus Brunnstein on WAZZU.A at ORBIT | https://catless.ncl.ac.uk/Risks/18/53 | 2026-11-12 | Reported |
| 61 | RISKS Digest 18.54, Biham and Shamir, DES fault attack, 18 October 1996 | https://catless.ncl.ac.uk/Risks/18/54#subj1 | 2026-11-12 | Demonstrated |
| 62 | RISKS Digest 18.64, Czech bank claim (November 1996 newsletter) | https://catless.ncl.ac.uk/Risks/18/64#subj6 | 2026-11-12 | Reported |
| 63 | RISKS Digest 18.69, WebCom denial of service (AP, 17 December 1996) | https://catless.ncl.ac.uk/Risks/18/69#subj3 | 2026-11-12 | Reported |
| 64 | RISKS Digest 18.74, US Air Force web page (New York Times, 30 December 1996) | https://catless.ncl.ac.uk/Risks/18/74#subj1 | 2026-11-12 | Reported |
| 65 | *Virus Bulletin*, January 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199601.pdf | 2026-11-12 | Reported |
| 66 | *Virus Bulletin*, February 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199602.pdf | 2026-11-12 | Reported |
| 67 | *Virus Bulletin*, March 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199603.pdf | 2026-11-12 | Reported |
| 68 | *Virus Bulletin*, June 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199606.pdf | 2026-11-12 | Reported |
| 69 | *Virus Bulletin*, August 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199608.pdf | 2026-11-12 | Reported |
| 70 | *Virus Bulletin*, September 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199609.pdf | 2026-11-12 | Reported |
| 71 | *Virus Bulletin*, November 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199611.pdf | 2026-11-12 | Reported |
| 72 | *Virus Bulletin*, December 1996 (October prevalence table) | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199612.pdf | 2026-11-12 | Reported (table); Demonstrated (sum) |
| 73 | Phrack 48, "Project Neptune" | https://phrack.org/issues/48/project-neptune.html | 2026-11-12 | Confirmed |
| 74 | Phrack 49, "Smashing The Stack For Fun And Profit" | https://phrack.org/issues/49/smashing-the-stack-for-fun-and-profit.html | 2026-11-12 | Confirmed |
| 75 | *Federal Computer Week*, study pans federal security as attack hits Justice site, 25 August 1996 | https://nextgov.com/digital-government/1996/08/study-pans-fed-security-role-as-attack-hits-justice-site/255947 | 2026-11-12 | Reported |
| 76 | *Federal Computer Week*, hackers attack CIA home page, September 1996 | https://nextgov.com/digital-government/1996/09/hackers-attack-cia-home-page/245753 | 2026-11-12 | Reported |
| 77 | *Government Executive*, CIA web site hacked, 20 September 1996 | https://govexec.com/federal-news/1996/09/cia-web-site-hacked/940 | 2026-11-12 | Reported |
| 78 | *Government Executive*, "Forever Hacked", 27 February 1997 | https://govexec.com/federal-news/1997/02/forever-hacked/173 | 2026-11-12 | Reported |
| 79 | *Federal Computer Week*, hackers' attack on Air Force blunted, 5 January 1997 | https://www.nextgov.com/digital-government/1997/01/hackers-attack-on-af-blunted/240154 | 2026-11-12 | Reported |
| 80 | CVE record CVE-1999-0128 (CVE Services API) | https://cveawg.mitre.org/api/cve/CVE-1999-0128 | 2026-11-12 | Confirmed |
| 81 | CVE, history (archived old website) | https://www.cve.org/Resources/Media/Archives/OldWebsite/about/history.html | 2026-11-12 | Confirmed |
| 82 | NVD API, records published in 1996 (first of four date windows) | `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=1996-01-01T00:00:00.000&pubEndDate=1996-04-29T23:59:59.999` | 2026-11-12 | Demonstrated |
| 83 | NVD, CVE-1999-0116 (and the paired records named in Part 2) | https://nvd.nist.gov/vuln/detail/CVE-1999-0116 | 2026-11-12 | Confirmed (records); Inferred (pairing) |
| 84 | NVD, CVE-1999-1309 | https://nvd.nist.gov/vuln/detail/CVE-1999-1309 | 2026-11-12 | Confirmed (record); Inferred (date reading) |
| 85 | NVD, CVE-1999-0067 | https://nvd.nist.gov/vuln/detail/CVE-1999-0067 | 2026-11-12 | Confirmed |
| 86 | RFC 6101, The Secure Sockets Layer (SSL) Protocol Version 3.0 | https://www.rfc-editor.org/rfc/rfc6101.txt | 2026-11-12 | Confirmed |
| 87 | IETF Datatracker, TLS working group history | https://datatracker.ietf.org/group/tls/history/ | 2026-11-12 | Confirmed |
| 88 | RFC 1948, Defending Against Sequence Number Attacks | https://www.rfc-editor.org/rfc/rfc1948.txt | 2026-11-12 | Confirmed |
| 89 | RFC 1938, A One-Time Password System (with the other 1996 RFC headers named in Part 9) | https://www.rfc-editor.org/rfc/rfc1938.txt | 2026-11-12 | Confirmed |
| 90 | NIST SP 800-14 | https://csrc.nist.gov/pubs/sp/800/14/final | 2026-11-12 | Confirmed |
| 91 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 92 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 93 | MITRE ATT&CK, Design and Philosophy (March 2020) | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | 2026-11-12 | Confirmed |
| 94 | MITRE D3FEND, about | https://d3fend.mitre.org/about/ | 2026-11-12 | Confirmed |
| 95 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_profiles.jsonl | 2026-11-12 | Demonstrated |
| 96 | TeamStarWolf library, `data/weaknesses/capec.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/capec.jsonl | 2026-11-12 | Demonstrated |
| 97 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_to_d3fend.jsonl | 2026-11-12 | Demonstrated |
| 98 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/cwe.jsonl | 2026-11-12 | Demonstrated |
| 99 | TeamStarWolf library, main branch, `navigator/library-layers/` (the folder where this study's layer is saved; not evidence) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-12 | Location only |
| 100 | TeamStarWolf library, `case-studies/ZERO_DAY_MARKET_EVENTS.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/ZERO_DAY_MARKET_EVENTS.md | 2026-11-12 | Reported (relays Kaspersky) |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md)
- Home studies: [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [NSA and CIA Tool Leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [The Cuckoo's Egg Intrusion](/case-studies/CUCKOOS_EGG_1986.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [Ransomware ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [Change Healthcare](/case-studies/CHANGE_HEALTHCARE_2024.md); [Healthcare threat watchlist](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1499.001 OS Exhaustion Flood](/mitre/techniques/T1499-001.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1498.002 Reflection Amplification](/mitre/techniques/T1498-002.md), [T1499.004 Application or System Exploitation](/mitre/techniques/T1499-004.md), [T1491.002 External Defacement](/mitre/techniques/T1491-002.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1059.004 Unix Shell](/mitre/techniques/T1059-004.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1548.001 Setuid and Setgid](/mitre/techniques/T1548-001.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1090.003 Multi-hop Proxy](/mitre/techniques/T1090-003.md), [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1137.001 Office Template Macros](/mitre/techniques/T1137-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1059.005 Visual Basic](/mitre/techniques/T1059-005.md), [T1542.003 Bootkit](/mitre/techniques/T1542-003.md), [T1561.001 Disk Content Wipe](/mitre/techniques/T1561-001.md), [T1485 Data Destruction](/mitre/techniques/T1485.md)
- CAPEC: [CAPEC-88](/mitre/capec/CAPEC-88.md), [CAPEC-482](/mitre/capec/CAPEC-482.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-490](/mitre/capec/CAPEC-490.md), [CAPEC-496](/mitre/capec/CAPEC-496.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-69](/mitre/capec/CAPEC-69.md), [CAPEC-233](/mitre/capec/CAPEC-233.md), [CAPEC-59](/mitre/capec/CAPEC-59.md), [CAPEC-142](/mitre/capec/CAPEC-142.md), [CAPEC-158](/mitre/capec/CAPEC-158.md)
- Groups, software and campaigns: none bound for 1996 (Part 11); Turla [G0010](/mitre/groups/G0010.md) and Penquin [S0587](/mitre/software/S0587.md) for their recorded start dates; Equation [G0020](/mitre/groups/G0020.md) for its 1996 domains as the home study records them
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-1996.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1996.json)
