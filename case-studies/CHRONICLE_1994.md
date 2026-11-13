# The Year 1994 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 12 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md) · Home studies for events summarized here: [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (the 1994 bank transfers, the Green Card posting, the 1994 computer-fraud amendment), [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md) (the Christmas Day 1994 intrusion), [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Steve Jackson Games on appeal), [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md) (the 1990 raid behind the appeal) · Series: [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the later years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 63 min (14,400 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 1994, you need the sniffer wave, the Rome Laboratory intrusions and the year's CERT advisories side by side with their government record, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 8: the defender view](#part-8-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md), [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

People who ran Unix systems on the Internet in 1994 remember the year by its passwords. On 3 February the Computer Emergency Response Team Coordination Center (CERT/CC) warned that intruders had put network sniffers on compromised hosts, including some service providers' machines, and had already captured access information for tens of thousands of systems by recording the start of new FTP, telnet and rlogin sessions [1][3]. CERT's short-term advice was to change passwords; its long-term advice was to stop sending reusable passwords in the clear [1][3]. Six weeks later it published MD5 checksums for SunOS files because intruders with root were swapping system programs for Trojan horses built to fool the old checksum tool [6]. Twice in the same year someone slipped a back door into the source code of a widely used program: the wuarchive FTP server in April and the ircII chat client, whose corrupt copies were on FTP sites from May until CERT's October warning [1][8][17].

The year's largest documented intrusion hit the US Air Force's Rome Laboratory in New York. Between 23 March and mid-April two intruders using the handles "Datastream Cowboy" and "Kuji" made more than 150 known intrusions in 26 days, put sniffers on seven systems, compromised 30 systems and more than 100 accounts, and reached from Rome into the Army Corps of Engineers, NASA Goddard, Wright-Patterson Air Force Base, an aerospace contractor, a NATO site and a South Korean nuclear research institute [24][22]. New Scotland Yard arrested the 16-year-old Datastream Cowboy on 12 May; the 1996 Senate record says Kuji had never been identified [24]. In December the US Naval Academy was penetrated from Great Britain, Finland, Canada and two US universities, and more than 12,000 passwords were changed [22]. Defense installations officially reported 255 attacks in 1994, against 115 the year before [22].

Around those cases sit a $10 million bank fraud run through stolen cash-management passwords, which the FBI notes did not use the Internet [27]; a computer-fraud amendment and a wiretap-capability law in the United States [46][45]; the Clipper key-escrow standard and the August paper showing its law-enforcement field could be bypassed [34][37]; the arrest of a CIA officer spying for Russia [28]; a run of polymorphic viruses and a virus hoax that federal responders had to debunk [69][74][62]; and, in December, a commercial web server with Secure Sockets Layer that Netscape described as the first secure server software for the Internet [97].

This study is the dated record of that year, built only from sources opened on 12 November 2026. Seven parts cover the timeline, the vulnerability advisories, the Rome Laboratory case (which has no other home in the library), crime and prosecutions, viruses, the state and intelligence record and the government's laws and standards; an eighth gives the defender view, and a ninth maps the record to MITRE frameworks. Every row carries its date, the source that supports it and an evidence grade.

No identifier system defenders use today existed in 1994. CVE began in 1999, CWE's first list in 2006, CAPEC in 2007 and ATT&CK's public release in 2015 [81][101][102][103]. The year's own identifiers are CERT's advisory numbers, CA-94:01 to CA-94:15 (Inferred [2]). Some of those flaws were later given back-dated CVE-1999 records, which Part 2 lists; every ATT&CK id in Part 9 is this study's later mapping, labelled as such.

Evidence grade: CERT/CC advisory texts, GAO and Senate records, FBI histories, court opinions, statutes, Federal Register notices, NIST and RFC Editor records, NVD records, the researchers' own papers and posts and the vendors' own descriptions are **Confirmed**. Facts that rest only on press accounts or their reprints in *Phrack*, on *Virus Bulletin* or on later retrospectives (most prosecutions, the press-reported password ring, most of the virus record, the names of the Rome intruders) are **Reported** and attributed. Where this study draws its own conclusion, it says **Inferred**; the one archive query this study ran itself is **Demonstrated**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 1994, plus boundary records that close or explain a 1994 event (CERT advisory CA-95:01 of 23 January 1995, Shimomura's posts of January 1995, the GAO report of May 1996 and the Senate hearing of June 1996) |
| CERT/CC advisories | 15, CA-94:01 to CA-94:15, now republished by SEI as CA-1994-01 to CA-1994-15 (Confirmed [1][2]) |
| Flaws CERT said attackers were using | rpc.mountd (CA-94:02), rdist (CA-94:04), writable utmp (CA-94:06), the ircII source Trojan (CA-94:14), NFS (CA-94:15) (Confirmed [1][4][7][17][18][21]); sendmail debug, with an exploitation script in circulation (CA-94:12) (Confirmed [14]) |
| Credentials captured by sniffers | Access information for "tens of thousands of systems", CERT's own estimate (Confirmed [1][3]) |
| Largest documented intrusion | Rome Laboratory, Griffiss Air Force Base: more than 150 known intrusions in 26 days, 30 systems and more than 100 accounts compromised (Confirmed [24][22]) |
| Cost of Rome Laboratory | $211,722 in the Air Force's 31 October 1994 damage assessment, excluding investigation; over $500,000 in the Air Force Information Warfare Center estimate GAO cites (Confirmed [24][22]) |
| Attacks reported by Defense installations | 255 in 1994, against 115 in 1993 and 559 in 1995 (Confirmed [22]) |
| Incidents reported to CERT/CC | 2,340 in 1994, against 1,334 in 1993 (Reported, reprint of the CERT table [77]); the CERT testimony opened gives no 1994 figure (Confirmed [25]) |
| Software supply chain | Intruder-modified source of wuarchive ftpd 2.2 and 2.1f (CA-94:07, 6 April) and ircII 2.2.9 (CA-94:14, 19 October, corrupt since May) (Confirmed [1][8][17]) |
| US law | Computer-fraud amendment in Pub. L. 103-322, 13 September; CALEA, Pub. L. 103-414, 25 October (Confirmed [46][47][45]) |
| Landmark ruling | *Steve Jackson Games v. US Secret Service*, Fifth Circuit, 31 October: seizing stored, unread e-mail is not an interception under the Wiretap Act (Confirmed [49][50]) |
| Encryption policy | FIPS 185 Escrowed Encryption Standard published 9 February, effective 11 March; Blaze's "Protocol Failure" paper dated 20 August (Confirmed [34][37]) |
| State record | No opened government, court or vendor record attributes a 1994 intrusion to a state (Inferred); no ATT&CK object covers the 1990s (Confirmed [109]); the year's state story is a human mole (Ames) and policy (Clipper, CALEA, the Joint Security Commission) (Confirmed [28][34][45][29]) |
| This study's MITRE binding | 19 ATT&CK Enterprise technique rows, every one a later mapping; no ICS row; no group, software or campaign object; eleven CWE rows (one listed by NVD) and fourteen CAPEC entries; D3FEND pairings from the library's data; one Navigator layer (Part 9) |

### Key findings

- **Cleartext passwords failed at Internet scale.** One CERT advisory reported tens of thousands of systems' access information captured by sniffers (Confirmed [1][3]); sniffers were the tool at Rome Laboratory and the Naval Academy (Confirmed [24][22]); and RFC 1704 cited the CERT advisory for the point that passwords open to passive attack are not strong enough for the Internet (Confirmed [93]).
- **Attackers replaced the software defenders trusted.** CA-94:05 says intruders built Trojan horses to match the weak "sum" checksum (Confirmed [6]); CA-94:07 and CA-94:14 describe back doors added to two programs' source distributions (Confirmed [8][17]). A later CVE record, CVE-1999-0661, groups the two 1994 source Trojans with later distribution-point compromises (Confirmed [85]).
- **The year's largest intrusion was two people, one never identified.** Rome Laboratory's intruders were a 16-year-old in the United Kingdom and a second person the US investigation had not identified by June 1996 (Confirmed [24]). Air Force officials told GAO that at least one "may have been working for a foreign country"; no record opened confirms it (Inferred).
- **Attribution was hard even when the data was in hand.** Investigators briefly feared the Korean nuclear research data had come from North Korea during nuclear negotiations; it was South Korean (Confirmed [24]). Data moved toward Latvia, and the Senate record says it was still unknown whether NASA's data was meant to go there (Confirmed [24]), and it describes the Latvian system as apparently a conduit used to avoid identification (Confirmed [24]).
- **The biggest theft of the year was not on the Internet.** The FBI says the $10 million cash-management fraud ran through compromised valid user IDs and passwords over the telecommunications network and "didn't involve the Internet" (Confirmed [27]).
- **Insiders were in more of the year's cases than the headlines suggest (Inferred).** The press reported an MCI switch engineer charged over stolen calling-card numbers and a temporary worker at BT taking sensitive numbers (Reported [76][60]).
- **The defender's toolkit took its modern shape.** In 1994 CERT made integrity checking (MD5, Tripwire) and one-time passwords its standard advice, and NIST published a firewall primer and FIPS 190 on stronger authentication (Confirmed [3][6][44][41]); Netscape shipped SSL on a commercial server in December (Confirmed [97]).

### Top recommendations

1. **Never send reusable passwords in the clear.** CERT's long-term fix in CA-94:01 is the same advice defenders give today, and its Appendix B pointed to one-time passwords (Confirmed [1][3]). FIPS 190 said password-only authentication often fails to protect (Confirmed [41]).
2. **Keep a trusted baseline of system binaries and compare against it.** CA-94:05 and CA-94:01 recommended MD5, Tripwire and comparison against a pre-intrusion copy, and warned that a checksum built for accidental change will not catch a deliberate one (Confirmed [6][3]).
3. **Verify the source you build from.** Two 1994 back doors arrived in source code fetched from FTP sites; CERT's fix was a clean release, verified checksums or disabling the service (Confirmed [8][17][1]). The [npm supply-chain study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) and the [xz Utils study](/case-studies/XZ_UTILS_BACKDOOR_2024.md) record the same pattern decades later (Inferred).
4. **Filter what the outside world can reach.** CA-94:15 advised blocking the portmapper and NFS ports at the border, and said this does not protect against inside attackers (Confirmed [18]); CA-94:11 noted that firewalls and TCP wrappers did not stop the Majordomo flaw (Confirmed [13]).
5. **Remove privileges a program does not need.** CA-94:03's workaround removed setuid bits; CA-94:06 shows a world-writable file that privileged programs trusted (Confirmed [5][7]).
6. **Put a legal banner on systems and plan monitoring before an incident.** At Rome Laboratory a logon banner let investigators monitor keystrokes without a court order (Confirmed [24]).
7. **Watch for intrusions you cannot see yet.** GAO says the Air Force did not know of the Rome intrusion for at least three days (Confirmed [22]), and Rome's own staff found it only when they found a sniffer five days after the first penetration (Confirmed [24]).
8. **Check warnings before you forward them.** The "Good Times" warning described a virus that did not exist; CIAC said reading mail alone cannot infect a computer (Confirmed [63]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions and policy dated to 1994, plus the later records that close or explain a 1994 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every event graded, numbers as the source states them.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record (a CERT/CC advisory as SEI publishes it or as distributed in 1994, a GAO report, a Senate staff statement or testimony, an FBI history, a court opinion, a statute, a Federal Register notice, a NIST, RFC Editor or NVD record, the researcher's or victim's own paper or post, a vendor's own description, or the library's data files as the record of what the library holds) was opened on 12 November 2026 and states the fact |
| Reported | Only a secondary source was opened: press and wire stories and their reprints in *Phrack*; *Virus Bulletin*; later retrospectives. The source is named in the text |
| Demonstrated | The study ran the query or opened the data itself and saw the result (the NVD date query) |
| Inferred | The study's own reasoning, labelled where it appears. Every MITRE id bound to a 1994 event is Inferred as to the binding |

Limits that a reader should know:

- **No contemporaneous CVE, no ATT&CK.** No 1994 record carries a CVE id or an ATT&CK id; CERT's advisory numbers are the year's identifiers (Inferred [2]). NVD now shows 25 live records with 1994 published dates, all CVE-1999 or CVE-2000 ids assigned years later and back-dated (Demonstrated [82]); Part 2 pairs some of them with advisories by date and description.
- **Copies of the advisories.** SEI's 1994 compilation is the main text [1][2]; individual advisories were also read from archived 1994 distributions (a text-file mirror, NANOG and seclists copies, an FTP-archive mirror) and cross-checked against SEI [3] to [21]. These are graded as the primary they copy.
- **The Rome Laboratory record.** The Senate Permanent Subcommittee on Investigations minority staff statement of June 1996 and GAO/AIMD-96-84 are the primaries [24][22][23]. Neither gives the intruders' real names; the Senate statement uses only their handles. The names in Part 3 come from a 2024 retrospective by ISC2 and are Reported [26]. The Air Force Information Warfare Center's technical analysis, cited by GAO, was not opened.
- **The prosecutions are mostly press-reported.** Court records were opened for *LaMacchia* and *Steve Jackson Games* [51][52][49][50]; the other cases rest on contemporary news or its reprint [57][58][59][60][61][76].
- **Pages that did not open.** A Check Point history post (403), a cypherpunks archive copy of the RSA-129 announcement (522), NIST's FIPS 140-1 page (404), a mailing-list copy of a report on a GE breach (404), and the congress.gov and FCC CALEA pages (403) were not available; the Federal Register, the Statutes at Large and the sci.math copy were used instead, and the GE breach is not recorded. CNN's 1998 report of the bank-fraud sentence was seen only in a search summary and is not used.
- **Home studies.** The bank transfers, the Green Card posting and the 1994 computer-fraud amendment live in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); the Christmas Day 1994 intrusion in the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md); the Fifth Circuit's *Steve Jackson Games* opinion in the [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md), with the 1990 raid in the [pre-Internet study](/case-studies/PRE_INTERNET_THREATS.md). Each is summarized here in a paragraph. No study on main covers Rome Laboratory, Clipper, CALEA or Ames (Demonstrated: search of case-studies/ on main [113]), so this chronicle is their home.
- **Tradecraft is described at advisory level.** Advisory names, affected products and impact, and technique names and ids. The 1994 advisories contain shell checks, a test that reveals the wu-ftpd back door and search strings for the ircII back door; none is reproduced here.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1994-01 | *Virus Bulletin* reports two shareware CD-ROMs shipped with viruses (Software Vault Collection 2 with PS-MPC.Math-test; Night Owl #10 with Lapse); an alert about an Apple Sweden distributor CD was a false positive | Malware, supply chain | Reported | [65] |
| 1994-01-04 | Judge Ronald Whyte suppresses storage-locker tapes in the San Jose Poulsen case (LA Times and UPI via *Phrack*) | Courts | Reported | [58] |
| 1994-01-11 | Federal Register approves FIPS 140-1, Security Requirements for Cryptographic Modules, four security levels; the notice gives two effective dates | Standards | Confirmed | [40] |
| 1994-01-18 | First major USENET mass posting, as Templeton dates it | Culture | Reported | [55] |
| 1994-02 | RFC 1579, Firewall-Friendly FTP (Bellovin): clients should use passive mode so packet filters can handle the data channel | Standards | Confirmed | [90] |
| 1994-02 | Two men already convicted of hacking Boeing and federal court computers plead guilty to felony charges over stolen card numbers and altered cellular phones | Courts | Reported | [66] |
| 1994-02-03 | CA-94:01 Ongoing Network Monitoring Attacks: sniffers on root-compromised SunOS 4.x and Solbourne hosts; access information for tens of thousands of systems captured | Vulnerability, intrusion | Confirmed | [1][3] |
| 1994-02-04 | AP reports the CERT warning, saying the sniffer recorded the first 128 keystrokes of new connections | Intrusion | Reported | [58] |
| 1994-02-08 to 10 | IAB Workshop on Security in the Internet Architecture at USC ISI, with a section on firewall architecture (report published as RFC 1636 in June) | Standards | Confirmed | [91] |
| 1994-02-09 | FIPS 185, the Escrowed Encryption Standard (Clipper), approved and published, effective 11 March, voluntary | Policy | Confirmed | [34][36] |
| 1994-02-10 | AFP: the VCL virus construction kit found in Italy; ISTINFORM says about 100 Italian enterprises contaminated | Malware | Reported | [59] |
| 1994-02-14 | CA-94:02 revised SunOS rpc.mountd patch, superseding CA-91:09 and CA-92:12; "currently being exploited" | Vulnerability | Confirmed | [1][4] |
| 1994-02-21 | FBI arrests CIA officer Aldrich Ames in Arlington, Virginia | State | Confirmed | [28] |
| 1994-02-24 | CA-94:03 IBM AIX performance tools: local root | Vulnerability | Confirmed | [1][5] |
| 1994-02-27 | Lillehammer Olympics: default birthdate passwords leave Tonya Harding's e-mail on the Games messaging system readable to journalists | Intrusion | Reported | [58] |
| 1994-02-28 | Joint Security Commission report "Redefining Security" delivered to the Secretary of Defense and the DCI | Policy | Confirmed | [29][30] |
| 1994-03 | Malcolm Farquharson jailed six months under the UK Computer Misuse Act for obtaining data by phoning an employee, without touching a computer | Courts | Reported | [67] |
| 1994-03-01 | Newsday: an 18-year-old took 103 student passwords at Polytechnic University and NYU's Courant Institute; a group called The Posse suspected in wider break-ins | Intrusion | Reported | [58] |
| 1994-03-17 | CA-94:04 SunOS rdist: local root; actively exploited | Vulnerability | Confirmed | [1] |
| 1994-03-18 | CA-94:05 MD5 Checksums, in response to Trojaned system files | Vulnerability, defense | Confirmed | [1][6] |
| 1994-03-21 | CA-94:06 writable /etc/utmp: any user to root; actively exploited | Vulnerability | Confirmed | [1][7] |
| 1994-03-23 | Rome Laboratory first penetrated, per audit logs | Intrusion | Confirmed | [24] |
| 1994-03-28 | Rome Laboratory staff find a sniffer | Intrusion | Confirmed | [24] |
| 1994-03-30 | Army Corps of Engineers systems in Vicksburg, Mississippi attacked from Rome Laboratory | Intrusion | Confirmed | [24] |
| 1994-04 | Datastream Cowboy copies data from a Korean Atomic Research Institute system to Rome; officials determine it is South Korean | Intrusion | Confirmed | [24] |
| 1994-04 | Logic bomb found in the DOS boot sector of PCs shipped by Melbourne firm IPEX, set to fire five months after formatting | Malware, supply chain | Reported | [68] |
| 1994-04-05 | An informant reports an e-mail from Datastream Cowboy, a 16-year-old in the United Kingdom | Intrusion | Confirmed | [24] |
| 1994-04-06 | CA-94:07 wuarchive ftpd Trojan Horse in versions 2.2 and 2.1f; updated 7 April | Supply chain | Confirmed | [1][8] |
| 1994-04-07 | MIT student David LaMacchia indicted for wire-fraud conspiracy over the Cynosure bulletin board | Courts | Confirmed | [51][52] |
| 1994-04-10 to 19 | Rome intruders reach an aerospace contractor, scan Brookhaven (12 April), connect to NASA Goddard via Seattle and Latvia (transfer cut off 14 April), move data from Wright-Patterson, scan NATO HQ (15 April), compromise a SHAPE Technical Center system | Intrusion | Confirmed | [24] |
| 1994-04-12 | Canter and Siegel post a Green Card Lottery advertisement to more than 5,500 newsgroups. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Culture | Reported | [56][55] |
| 1994-04-14 | CA-94:08 ftpd SITE EXEC (remote or local root) and a race condition | Vulnerability | Confirmed | [1][9][10] |
| 1994-04-26 | Atkins, Graff, Lenstra and Leyland announce the factorization of RSA-129 | Cryptography | Confirmed | [98] |
| 1994-04-28 | Aldrich and Rosario Ames plead guilty; he is sentenced to life without parole | State | Confirmed | [28] |
| 1994-05 | Trojaned ircII 2.2.9 source available on FTP sites "as early as May" | Supply chain | Confirmed | [1][17] |
| 1994-05 | One_Half discovered, as F-Secure dates it | Malware | Confirmed | [74] |
| 1994-05-12 | New Scotland Yard searches Datastream Cowboy's home, arrests and interviews him, releases him on bail | Courts, intrusion | Confirmed | [24] |
| 1994-05-19 | Federal Register approves FIPS 186, the Digital Signature Standard, effective 1 December | Standards | Confirmed | [38][39] |
| 1994-05-23 | CA-94:09 /bin/login on IBM AIX 3 and Linux: remote root | Vulnerability | Confirmed | [1][11] |
| 1994-05-24 | *Atlanta Journal-Constitution*: a ring stole more than 100,000 passwords; at least 30 major systems found sniffers; FBI investigating since February | Intrusion | Reported | [59] |
| 1994-06 | Canter and Siegel's second run prompts the first cancelbot | Culture | Reported | [56] |
| 1994-06-03 | CA-94:10 IBM AIX bsh batch queue | Vulnerability | Confirmed | [1][12] |
| 1994-06-09 | CA-94:11 Majordomo up to 1.91, reachable behind firewalls and TCP wrappers | Vulnerability | Confirmed | [1][13] |
| 1994-06-14 | Kevin Poulsen pleads guilty in Los Angeles over rigged radio contests | Courts | Reported | [57] |
| 1994-06-17 | Kumar and Spafford, Purdue COAST: pattern matching for misuse intrusion detection | Defense | Confirmed | [100] |
| 1994-06-24 to 25 | Bangemann report on the information society prepared for the Corfu European Council (context; the CORDIS summary does not mention security) | Policy | Confirmed | [80] |
| 1994-06 (late) to 1994-10 | About 40 illegal transfers totalling more than $10 million from a major US bank's cash management system. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime, finance | Confirmed | [27] |
| 1994-07 | NIST SP 800-7, Security in Open Systems | Standards | Confirmed | [43] |
| 1994-07 | *Virus Bulletin* reports a suspected author of the Pathogen virus arrested by New Scotland Yard's Computer Crime Unit and Devon and Cornwall police and bailed | Courts, malware | Reported | [69] |
| 1994-07 | The FBI opens the bank case after corporate customers find $400,000 missing | Crime, finance | Confirmed | [27] |
| 1994-07-05 | *New York Times* runs "Fugitive Hacker Baffles FBI With Technical Guile" on Mitnick (headline only, via *Phrack*). Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Reported | [59] |
| 1994-07-13 | Police search Christopher Pile's home under a Computer Misuse Act warrant and arrest him in Plymouth (participant's account) | Courts, malware | Reported | [72] |
| 1994-07-13 | Lawrence Livermore confirms a lab computer was used to store and distribute more than 1,000 pornographic images and shuts it down | Insider | Reported | [59] |
| 1994-07-14 | CA-94:12 sendmail debug and error-header flaws: local root and arbitrary file read | Vulnerability | Confirmed | [1][14][15] |
| 1994-07-24 | KAOS4 virus posted to a Usenet binaries newsgroup | Malware | Confirmed | [73] |
| 1994-08 | RFC 1675, Security Concerns for IPng (Bellovin) | Standards | Confirmed | [92] |
| 1994-08-11 | CA-94:13 SGI IRIX help system: root for a logged-in or console user | Vulnerability | Confirmed | [1][16] |
| 1994-08-11 | A Philadelphia buyer uses encryption to send a Visa number to NetMarket for a $12.48 CD | E-commerce | Reported | [79] |
| 1994-08-20 | Matt Blaze dates "Protocol Failure in the Escrowed Encryption Standard" | Cryptography, policy | Confirmed | [37] |
| 1994-08-29 | Justin Tanner Petersen ("Agent Steal"), an FBI informant on the run since 18 October 1993, captured in Westwood, Los Angeles | Courts | Reported | [59] |
| 1994-09 | OTA report OTA-TCT-606, Information Security and Privacy in Network Environments | Policy | Confirmed | [32][33] |
| 1994-09 | MCI switch engineer Ivy James Lay charged over stolen calling-card numbers used for at least $50 million in calls | Insider, crime | Reported | [76] |
| 1994-09 | Members of the UK virus-writing group ARCV receive police cautions rather than prosecution | Courts, malware | Reported | [70] |
| 1994-09-01 | The WildList of PC viruses in the wild, compiled from 16 virus professionals | Malware, defense | Confirmed | [75] |
| 1994-09-13 | Pub. L. 103-322, title XXIX, sec. 290001, amends 18 U.S.C. 1030 and adds a civil action. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Law | Confirmed | [46][47] |
| 1994-09-16 | PDD-29, Security Policy Coordination, signed | Policy | Confirmed | [31] |
| 1994-09-28 | FIPS 190, advanced authentication technology alternatives | Standards | Confirmed | [41] |
| 1994-10 | RFC 1704, On Internet Authentication, cites CA-94:01 | Standards | Confirmed | [93] |
| 1994-10 | Defense Science Board report "Information Architecture for the Battlefield", quoted by GAO on threats beyond hackers | Policy | Confirmed | [22] |
| 1994-10-19 | CA-94:14 Trojan horse in ircII 2.2.9: back door into IRC users' accounts, actively exploited | Supply chain | Confirmed | [1][17] |
| 1994-10-20 | Rosario Ames sentenced to 63 months | State | Confirmed | [28] |
| 1994-10-25 | CALEA, Pub. L. 103-414, enacted | Law | Confirmed | [45] |
| 1994-10-31 | *Steve Jackson Games v. US Secret Service* decided by the Fifth Circuit. Home: [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Courts | Confirmed | [49][50] |
| 1994-10-31 | Air Force damage assessment puts the Rome Laboratory loss at $211,722 | Intrusion | Confirmed | [24] |
| 1994-11 | Blaze's paper presented at the ACM Conference on Computer and Communications Security | Cryptography | Confirmed | [37] |
| 1994-11-03 | UK Criminal Justice and Public Order Act 1994 receives Royal Assent; section 161 adds offences for procuring and selling computer-held personal data | Law | Confirmed | [48] |
| 1994-11-09 | FIPS 191, Guideline for the Analysis of Local Area Network Security | Standards | Confirmed | [42] |
| 1994-11-20 to 22 | Shor's quantum algorithms for factoring and discrete logarithms appear in the 35th FOCS proceedings | Cryptography | Confirmed | [99] |
| 1994-11-24 | Thanksgiving weekend: journalists Josh Quittner and Michelle Slatalla have their mailbox flooded and phone forwarded; manifesto signed "Internet Liberation Front" | Intrusion | Reported | [61] |
| 1994-11-24 | *The Independent* reports BT records of sensitive numbers taken via a temporary worker (*Phrack* summary) | Insider | Reported | [60] |
| 1994-12 | US Naval Academy penetrated from Great Britain, Finland, Canada and two US universities | Intrusion | Confirmed | [22][23] |
| 1994-12 | NIST SP 800-10, an introduction to Internet firewalls | Standards, defense | Confirmed | [44] |
| 1994-12 | RFC 1750 on randomness; RFC 1731 and RFC 1734 on IMAP4 and POP3 authentication | Standards | Confirmed | [94][95] |
| 1994-12 | In Bergen, Norway, an 18-year-old charged with uploading viruses to a public BBS | Courts, malware | Reported | [71] |
| 1994-12-06 | CIAC Notes 94-04 declares the "Good Times" virus warning a hoax | Malware, hoax | Confirmed | [62][63] |
| 1994-12-12 | TidBITS reports the hoax, citing CIAC | Malware, hoax | Reported | [64] |
| 1994-12-15 | Netscape announces Navigator 1.0 and the Netsite servers; the Commerce Server includes SSL | Defense, e-commerce | Confirmed | [97] |
| 1994-12-19 | CA-94:15 NFS vulnerabilities: rising root compromises from widely distributed tools | Vulnerability | Confirmed | [1][18] |
| 1994-12-25 | IP spoofing attack on Tsutomu Shimomura's systems begins about 14:09 PST. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Intrusion | Confirmed | [53][54] |
| 1994-12-28 | *United States v. LaMacchia* dismissed under *Dowling* | Courts | Confirmed | [51][52] |
| 1994 (year) | FireWall-1 first shown publicly at NetWorld+Interop, Las Vegas; OEM agreement with Sun (The Register, 2013) | Defense | Reported | [89] |
| 1994 (year) | A 27-year-old breaks into Salt River Project computers; he could not have controlled any dams (Network World, 2010) | Infrastructure | Reported | [78] |
| 1995-01-11 | Boundary: Shimomura presents the Christmas attack at CMAD 3 | Intrusion | Confirmed | [53] |
| 1995-01-23 | Boundary: CA-95:01, IP Spoofing Attacks and Hijacked Terminal Connections | Vulnerability | Confirmed | [19][20] |
| 1995-03 | Boundary: Vladimir Levin arrested in London over the 1994 transfers; he pleads guilty in January 1998 | Courts | Confirmed | [27] |
| 1995-11 | Boundary: Pile sentenced at Exeter Crown Court to eighteen months after pleading guilty to eleven charges | Courts | Reported | [72] |
| 1996-05-22 and 1996-06-05 | Boundary: GAO/AIMD-96-84 and the Senate hearing that hold the Rome Laboratory record | Government | Confirmed | [22][24] |

## Part 2: the vulnerability record

### The 15 advisories

CERT/CC issued 15 advisories in 1994, CA-94:01 to CA-94:15; SEI republishes them as "1994 CERT Advisories" in its 1988 to 2004 collection (Confirmed [1][2]). The impact column gives CERT's own words where quoted and its substance otherwise. The "Later CVE" column gives NVD records that match the advisory by date and description; the pairing is this study's (Inferred [82][83]).

| Advisory | Date | Product | Impact as CERT states it | Later CVE | Grade | Sources |
|---|---|---|---|---|---|---|
| CA-94:01 | 3 Feb | Network monitoring on SunOS 4.x and Solbourne (/dev/nit) | "dramatic increase" in sniffer reports; access information for tens of thousands of systems; Trojan horse system programs installed | none | Confirmed | [1][3] |
| CA-94:02 | 14 Feb | SunOS 4.1.1 to 4.1.3c rpc.mountd (revised patch) | overlong export or netgroup lists trigger the flaw; "currently being exploited"; supersedes CA-91:09 and CA-92:12 | CVE-1999-0211 | Confirmed | [1][4] |
| CA-94:03 | 24 Feb | IBM AIX 3.2.4 with PTFs U420020 or U422510, all AIX 3.2.5 performance tools | local root; workaround removes setuid bits | CVE-1999-0338 | Confirmed | [1][5] |
| CA-94:04 | 17 Mar | SunOS rdist | local root; "being actively exploited", with a pointer to CA-94:01; later superseded by CA-1996-14 | none paired | Confirmed | [1][21] |
| CA-94:05 | 18 Mar | MD5 checksums for SunOS files | issued because root intruders built Trojan horses to match the "sum" checksum | none | Confirmed | [1][6] |
| CA-94:06 | 21 Mar | Writable /etc/utmp, SunOS 4.1.x and Solaris 1.1.1 | any user account to root; "actively exploited" | CVE-1999-0120 | Confirmed | [1][7] |
| CA-94:07 | 6 Apr (updated 7 Apr) | wuarchive ftpd 2.2 and 2.1f source | intruder-modified copies carry a root back door; install 2.3 or disable FTP | CVE-1999-0661 (grouped) | Confirmed | [1][8] |
| CA-94:08 | 14 Apr | wuarchive ftpd 2.0 to 2.3, DECWRL ftpd before 5.93, BSDI ftpd 1.1 before patch 5 | SITE EXEC gives remote or local root; a race condition gives local root; both "widely known"; checksums published for wu-ftpd 2.4 | none paired | Confirmed | [1][9][10] |
| CA-94:09 | 23 May | /bin/login, IBM AIX 3 and Linux | remote root; AIX workaround disables the rlogin daemon | CVE-1999-0113 (CWE-88 per NVD) | Confirmed | [1][11] |
| CA-94:10 | 3 Jun | IBM AIX 3.2 and earlier bsh batch queue | with network printing enabled, remote and local users gain a privileged account | CVE-1999-0337 | Confirmed | [1][12] |
| CA-94:11 | 9 Jun | Majordomo up to 1.91 | the Majordomo account and arbitrary commands, "even if the site has firewalls and TCP wrappers"; fix 1.92 | CVE-1999-0207 | Confirmed | [1][13] |
| CA-94:12 | 14 Jul | sendmail (some vendors) | debug option gives local root, with an exploitation script circulating; error-header option lets local users read any file; later superseded by CA-1996-20, 24 and 25 | CVE-1999-1309 (probable; dates differ) | Confirmed | [1][14][15] |
| CA-94:13 | 11 Aug | SGI IRIX 5.1.x and 5.2 help system and print manager | root for a logged-in user or at the console; "widely discussed in public forums" | CVE-1999-1219 | Confirmed | [1][16] |
| CA-94:14 | 19 Oct | ircII 2.2.9 source | back door into the account running the client; corrupt from May; actively exploited; fix ircII 2.6 | CVE-1999-0661 (grouped) | Confirmed | [1][17] |
| CA-94:15 | 19 Dec | NFS | rising root compromises from widely distributed tools; worst case remote root; filter the portmapper (111) and nfsd (2049) | none paired | Confirmed | [1][18] |

### What the advisories say about attackers

Six of the year's fifteen advisories carry CERT's own statement that attackers were already using the flaw or class of flaw: rpc.mountd ("currently being exploited"), rdist and utmp (tied to the sniffer attacks), sendmail (an exploitation script "circulating and being used"), the ircII Trojan ("actively exploited") and NFS (rising compromises from widely distributed tools) (Confirmed [1][4][7][14][17][18][21]). CA-94:08 and CA-94:13 say their flaws were widely known or widely discussed (Confirmed [9][16]). The pattern is that root was gained through a known local flaw, a sniffer was installed, and the captured passwords opened the next host (Inferred [3][21]).

### Trojaned binaries and checksums

CA-94:01 says intruders installed Trojan horse versions of system programs once they had root (Confirmed [3]). CA-94:05 followed on 18 March: CERT published MD5 checksums for SunOS files because intruders were modifying their Trojan horses to carry the same checksum as the original under the standard UNIX "sum" program, which was designed to catch accidental, not deliberate, change; CERT urged sites to install MD5 and validate system software, and recommended integrity tools such as Tripwire (Confirmed [6][1]). In April CERT also published MD5 checksums for the fixed wu-ftpd 2.4 distribution (Confirmed [9]). Integrity checking had become CERT's standard answer to Trojaned binaries within a single year (Confirmed [1]; the framing is Inferred).

### Two source-code Trojans

On 6 April CA-94:07 reported that an intruder had modified some copies of the source for wuarchive ftpd versions 2.2 and 2.1f to contain a Trojan horse giving root access; the 7 April update said the back door accepted a password for any user name other than anonymous (Confirmed [8][1]). On 19 October CA-94:14 reported that some copies of the ircII 2.2.9 IRC client source carried a back door into the accounts of people running it, that corrupt copies had been on many FTP sites as early as May, and that intruders were actively exploiting it (Confirmed [1][17]). Exposure therefore ran about five months before notice (Inferred [17]). NVD's CVE-1999-0661 covers software replaced with a Trojan horse at a distribution point and names wuarchive ftpd 2.2 and 2.1f and ircII 2.2.9 alongside later cases such as TCP Wrappers 7.6 and OpenSSH 3.4p1 (Confirmed [85]). Both 1994 cases are early software supply-chain compromises in the advisory record; the [npm supply-chain study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), the [Hugging Face study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), the [xz Utils study](/case-studies/XZ_UTILS_BACKDOOR_2024.md) and the [SolarWinds study](/case-studies/SOLARWINDS_SUNBURST.md) carry the same class of attack decades later (Inferred).

### The later CVE record

CVE did not exist in 1994: the concept workshop met at Purdue on 21 and 22 January 1999, the list opened with 321 entries and launched publicly in September 1999 (Confirmed [81]). An NVD query for published dates in 1994 returns 26 records, 25 live and one rejected duplicate, all CVE-1999 or CVE-2000 ids assigned later and back-dated to advisory or bulletin dates; all but one carry NVD-CWE-Other or noinfo (Demonstrated [82]). The exception is CVE-1999-0113, the CA-94:09 login flaw, which NVD dates 23 May 1994 and lists under CWE-88, Improper Neutralization of Argument Delimiters in a Command (Confirmed [84]). One record shows the limits of the back-dating: CVE-2000-0508 carries an NVD published date of 19 December 1994, the date of CA-94:15, but describes rpc.lockd in Red Hat Linux 6.1 and 6.2, so the date cannot be a 1994 event (Inferred [86]). CVE-1999-1309 (sendmail before 8.6.7, local root through a large debug value) probably records the CA-94:12 debug flaw, but NVD dates it 30 August 1996 (Inferred [87]).

### The edge of the year

On 25 December 1994, at about 14:09 PST, an attack on Tsutomu Shimomura's systems began with probes from toad.com (Confirmed [53]). His own post of 25 January 1995 says the attacker used IP source-address spoofing with TCP sequence-number prediction against a diskless Solaris 1 workstation, then, after gaining root, hijacked an existing session with a loadable kernel STREAMS module; he wrote it to correct a *New York Times* article and CERT's advisory (Confirmed [54]). That advisory, CA-95:01 of 23 January 1995, described spoofed source addresses used against IP-address-based authentication and dynamic kernel modification on SunOS 4.1.x to take over open terminal sessions (Confirmed [19][20]). The [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) is the home for the intrusion, the attribution and the arrest that followed; it already binds T1595, T1046, T1499.001, T1199, T1098, T1563, CAPEC-593 and CAPEC-482 to it (Demonstrated [112]).

### Counting incidents

A reprint of CERT/CC's statistics gives 2,340 incidents reported in 1994, up from 1,334 in 1993, and 2,412 in 1995 (Reported [77]); CERT later said such counts provide little information about scope and impact (Reported [77]). In June 1996 Senate testimony, CERT/CC's manager gave 132 incidents for 1989 and over 2,400 for 1995 and listed the fifteen 1994 advisories, but gave no 1994 count (Confirmed [25]). The 1994 figure therefore rests on the reprint alone.

## Part 3: Rome Laboratory and the Defense record

No study on main covers the Rome Laboratory intrusions: the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) begins its period with the 1994 bank transfers but has no Rome Laboratory text (Demonstrated [113]). This part is the home.

### What Rome Laboratory was

Rome Laboratory, at Griffiss Air Force Base in New York, did the Air Force's command-and-control research and relied heavily on the Internet; one compromised air tasking order research project represented more than three years of research and $4 million (Confirmed [22]). No 1994 intrusion into an industrial control system was found in any primary opened (Inferred); GAO describes Rome's affected systems as support systems and research data (Confirmed [22]).

### The intrusion, day by day

| Date | Event | Grade | Sources |
|---|---|---|---|
| 1994-03-23 | First penetration of Rome Laboratory systems, per audit logs | Confirmed | [24] |
| 1994-03-28 | Staff discover a sniffer; the intrusion is found five days after it began | Confirmed | [24] |
| 1994-03 to 04 | Two intruders gain full access to seven systems; sniffers on them compromise 30 systems and more than 100 user accounts; password files located and copied by the intruders' scanning tool; mail read, copied and deleted; battlefield simulation data copied | Confirmed | [24] |
| 1994-03-30 | Army Corps of Engineers systems in Vicksburg attacked from Rome Laboratory; monitoring shows the handles Datastream (also spelled Datastrean) and Kuji | Confirmed | [24] |
| 1994-04 | Datastream Cowboy reaches a Korean Atomic Research Institute system and moves its data to Rome; investigators briefly fear it is North Korean, during nuclear negotiations, and within hours determine it is South Korean | Confirmed | [24] |
| 1994-04-05 | An informant reports an e-mail from Datastream Cowboy, a 16-year-old in the United Kingdom | Confirmed | [24] |
| 1994-04-10 to 19 | Intruders reach an aerospace contractor's systems with captured credentials, move data from Wright-Patterson's National Aero-Space Plane office and compromise a SHAPE Technical Center system | Confirmed | [24] |
| 1994-04-12 | Brookhaven National Laboratory scanned | Confirmed | [24] |
| 1994-04-14 | Kuji connects to NASA Goddard via Seattle and Latvia; a transfer from Goddard is cut off | Confirmed | [24] |
| 1994-04-15 | NATO HQ in Brussels and Wright-Patterson Air Force Base scanned | Confirmed | [24] |
| 1994-04 | A logon banner lets investigators monitor keystrokes without a court order | Confirmed | [24] |
| 1994-05-12 | New Scotland Yard searches Datastream Cowboy's home, arrests and interviews him, and releases him on bail; over 150 known intrusions in 26 days | Confirmed | [24] |
| 1994-10-31 | Air Force damage assessment: $211,722, excluding investigation, recovery and monitoring | Confirmed | [24] |
| 1996-05-22 | GAO/AIMD-96-84: more than 150 intrusions by a British hacker and an unidentified hacker using Trojan horses and sniffers, routed through phone switches in South America and commercial sites on both US coasts; air tasking order research data copied; over $500,000 at Rome alone | Confirmed | [22][23] |
| 1996-06-05 | Senate PSI minority staff statement: Datastream pending prosecution in the United Kingdom; Kuji never identified | Confirmed | [24] |

GAO adds that the intruders seized control of support systems for several days, established links to foreign Internet sites and, masquerading as a trusted Rome user, attacked other government systems; NASA Goddard, Wright-Patterson and defense contractors were among them (Confirmed [23][22]). It also says the Air Force did not know it was under attack for at least three days (Confirmed [22]). The Senate record says data moved from NASA Goddard and Wright-Patterson toward Latvia, that Kuji connected from Latvia, and that whether the NASA data was destined for Latvia was still unknown in 1996 (Confirmed [24]).

### Who the intruders were

Neither the GAO report nor the Senate statement gives the intruders' real names (Confirmed [24][22]). A 2024 ISC2 retrospective names Datastream Cowboy as Richard Pryce, convicted under the Computer Misuse Act and fined, and Kuji as Mathew Bevan, then 21, caught about two years later, with the case later dropped by the Crown Prosecution Service; it says there were no US charges (Reported [26]). The two fit if the identification came after the June 1996 hearing, which "two years later" allows (Inferred [24][26]).

### The foreign-power question

Air Force officials told GAO that at least one of the intruders "may have been working for a foreign country" interested in military research data (Confirmed [23]). That is a possibility stated by officials; no record opened confirms foreign sponsorship (Inferred). The two moments in the record that looked like state activity, the Korean nuclear research data and the Latvian connection, were resolved as South Korean in the first case; in the second the Senate record calls the Latvian system apparently a conduit, though where the NASA data was going stayed unknown (Confirmed [24]). The identified intruder was 16 (Confirmed [24]). Rome Laboratory is the year's suspected-state scare that the record does not support (Inferred).

### The Naval Academy and the wider count

In December 1994 the US Naval Academy was penetrated from Great Britain, Finland, Canada and two US universities: 24 servers accessed, sniffers on eight, a main router compromised and more than 12,000 passwords changed; the attackers were not identified and no state attribution was made (Confirmed [22][23]). Defense Information Systems Agency figures that GAO reports show officially reported attacks on Defense installations rising from 53 in 1992 to 115 in 1993, 255 in 1994 and 559 in 1995 (Confirmed [22][23]). GAO quotes the Defense Science Board's October 1994 report "Information Architecture for the Battlefield" on threats beyond hackers, and the Joint Security Commission's February 1994 report on under-resourced security work (Confirmed [22]).

## Part 4: crime and prosecutions

### The sniffer ring in the press

On 4 February AP reported CERT's warning, saying the sniffer recorded the first 128 keystrokes of new connections (Reported [58]); CERT's own text says the same of FTP, telnet and rlogin sessions (Confirmed [1]). On 1 March Newsday reported that an 18-year-old had taken 103 student passwords at Polytechnic University and NYU's Courant Institute, and that a group called The Posse was suspected in the wider break-ins, which it put at over 10,000 passwords (Reported [58]). On 24 May the *Atlanta Journal-Constitution* reported that a ring had stolen more than 100,000 passwords, that at least 30 major systems had found sniffers and that the FBI had been investigating since February; CERT's manager called the intruders loosely knit but fairly organized, and a source quoted by the paper said sniffer code had appeared in *Phrack* on 1 April (Reported [59]). None of the press counts is tied to a primary figure; CERT's own estimate is "tens of thousands of systems" (Confirmed [1]).

### The bank transfers (summary)

The FBI's own history says the case opened in July 1994 when corporate customers of "a major U.S. bank" found $400,000 missing. About 40 illegal transfers from late June through October, totalling more than $10 million and mostly to overseas accounts, were made by compromising valid user IDs and passwords on the bank's cash management system over the telecommunications network; the FBI notes the hack did not involve the Internet. A Russian couple was arrested in San Francisco, Russian authorities cooperated, and Vladimir Levin was arrested in London in March 1995, extradited, and pleaded guilty in January 1998 (Confirmed [27]). The FBI page does not name the bank; the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) names Citibank on Britannica's secondary account (Reported [113]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home; it currently grades the case Reported and has no DOJ or court record, and the FBI account here is a stronger primary it can use (Confirmed [113][27]).

### LaMacchia and the Cynosure board

On 7 April 1994 a federal grand jury in Massachusetts indicted MIT student David LaMacchia on one count of conspiracy to commit wire fraud over the "Cynosure" bulletin board, used to distribute copyrighted software, with alleged losses of more than $1 million and no personal benefit alleged (Confirmed [51][52]). On 28 December Judge Richard Stearns dismissed the case under *Dowling v. United States* (Confirmed [52][51]).

### Kevin Poulsen and Agent Steal

On 4 January Judge Ronald Whyte suppressed storage-locker tapes in the San Jose case against Kevin Poulsen, as the *Los Angeles Times* and UPI reported (Reported [58]). On 14 June Poulsen pleaded guilty in federal court in Los Angeles to computer fraud, interception of wire communications, mail fraud, money laundering and obstruction of justice for rigging KIIS-FM and KPWR-FM call-in contests, including two Porsches; sentencing was set for 17 October and a separate San Francisco case was pending (Reported [57]). No study on main covers Poulsen's own case, so this chronicle records the 1994 plea; the [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) covers his later book *Kingpin*. On 29 August, *Phrack* reported, Justin Tanner Petersen ("Agent Steal"), an FBI informant who had fled on 18 October 1993 after admitting new crimes, was captured in Westwood after ten months on the run (Reported [59]).

### The Christmas Day intrusion and the fugitive (summary)

The *New York Times* ran "Fugitive Hacker Baffles FBI With Technical Guile" on 5 July, which *Phrack* reprinted only as a headline (Reported [59]). The 25 December attack on Shimomura's systems is described in Part 2 from his own accounts (Confirmed [53][54]). The [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) is the home for both.

### The Internet Liberation Front

Over the Thanksgiving weekend of 1994 the journalists Josh Quittner and Michelle Slatalla had their mailbox flooded and their phone forwarded; *TIME* reported that the sender had broken into IBM, Sprint and the Pipeline at root level and that the manifesto was signed "Internet Liberation Front" (Reported [61]).

### Insiders and default passwords

MCI switch engineer Ivy James Lay was charged with stealing calling-card numbers used for at least $50 million in calls; the *New York Times* put the numbers at about 60,000 and the *Los Angeles Daily News* at 100,000 (Reported [76]). *The Independent* reported that BT records of sensitive numbers, including the Royal Family's and the intelligence services', were taken via a temporary worker and that BT admitted failings; only *Phrack*'s summary was opened (Reported [60]). Lawrence Livermore confirmed that a laboratory computer had been used to store and distribute more than 1,000 pornographic images and shut it down after a *Los Angeles Times* reporter's tip (Reported [59]). At the Lillehammer Olympics, default birthdate passwords left Tonya Harding's e-mail on the Games messaging system readable to journalists (Reported [58]).

### Other cases

In February *Virus Bulletin* reported that two men already convicted of hacking Boeing and federal court computers pleaded guilty to felony charges over stolen card numbers and altered cellular phones (Reported [66]). In March it reported that Malcolm Farquharson had been jailed for six months under the UK Computer Misuse Act for obtaining data by phoning an HL Communications employee, without touching a computer (Reported [67]). The UK's Criminal Justice and Public Order Act later that year added offences aimed at exactly that kind of procurement of personal data (Confirmed [48]; the link is Inferred).

### The Green Card posting (summary)

Brad Templeton dates the first major USENET mass posting to 18 January 1994 and Canter and Siegel's Green Card Lottery posting to every newsgroup to April 1994 (Reported [55]). A later retrospective gives 12 April and more than 5,500 newsgroups, says complaints flooded their provider, Internet Direct, which ended the account, and that a second run in June prompted the first cancelbot; Canter was disbarred in Tennessee in 1997 (Reported [56]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home and gives 12 April.

### A utility story that grew in the retelling

In 1994 a hacker broke into Salt River Project computers serving the Phoenix area; M. E. Kabay wrote in 2010 that he was 27, not the "12-year-old" of the later Roosevelt Dam story, that he could not have controlled any dams, and that investigators concluded no lives or property were threatened (Reported [78]). No court record or utility statement was opened.

## Part 5: viruses and malware

### Pathogen and the Black Baron

*Virus Bulletin*'s August issue described Pathogen, a polymorphic virus using the SMEG engine and signed "The Black Baron", found in the wild in the United Kingdom early in 1994 and missed by leading scanners. It judged the publicity overblown, at most about 15 sites, and reported that New Scotland Yard's Computer Crime Unit and Devon and Cornwall police had arrested a suspected author, who was bailed, appeared in court and was re-bailed to 10 January 1995 (Reported [69]). Jim Bates's 1996 participant account names him as Christopher Pile, author of SMEG and the Pathogen and Queeg viruses: police searched his home under a Computer Misuse Act warrant on 13 July 1994 and arrested him in Plymouth; the offences ran from October 1993 to April 1994; he pleaded guilty to eleven charges and was sentenced at Exeter Crown Court in November 1995 to eighteen months (Reported [72]).

### One_Half and KAOS4

One_Half, also called Slovak Bomber, Explosion-II or Freelove, is a multipartite, polymorphic stealth virus that infects the master boot record and COM and EXE files; on each boot it encrypts two more disk cylinders and decrypts them on the fly, so careless removal loses data. F-Secure dates its discovery to May 1994 (Confirmed [74]). KAOS4, a non-resident COM and EXE infector that spreads only when an infected file is run, was posted on 24 July 1994 to a Usenet binaries newsgroup, and incidents were reported in the United States, Germany, Austria, Norway and Finland (Confirmed [73]).

### Infected media and kits

In January *Virus Bulletin* reported two shareware CD-ROMs shipped with viruses, Software Vault Collection 2 with PS-MPC.Math-test and Night Owl #10 with Lapse, and an Apple Sweden distributor alert that turned out to be a false positive (Reported [65]). In April it reported a logic bomb in the DOS boot sector of PCs shipped by the Melbourne firm IPEX, with an altered FORMAT program, set to fire five months after formatting (Reported [68]). In February AFP reported the VCL virus construction kit found in Italy, with ISTINFORM saying about 100 Italian enterprises were contaminated (Reported [59]).

### Writers in court

Members of the UK virus-writing group ARCV were given police cautions rather than prosecuted, and no victims of their viruses were identified (Reported [70]). In Bergen, Norway, an 18-year-old was charged with uploading viruses to a public bulletin board (Reported [71]).

### The WildList and the Good Times hoax

The WildList of 1 September 1994 compiled PC viruses in the wild from 16 virus professionals, including Solomon, IBM, Kaspersky, F-Prot, Symantec and Bontchev; a virus is charted only when two or more report a positively identified sample, and the list says it is not a measure of how common a virus is. Entries include Form.A, Dir-II.A and Cascade (Confirmed [75]). On 6 December CIAC Notes 94-04 from the US Department of Energy's Computer Incident Advisory Capability declared the "Good Times" e-mail virus warning a hoax and urban legend begun by an America Online user and a university student, and said no virus can infect a computer just by reading mail (Confirmed [63][62]). A later CIAC note, 95-09, says CIAC confirmed with the FCC that the FCC reference in a later version of the warning was fabricated (Confirmed [62]). TidBITS reported the hoax on 12 December, citing CIAC (Reported [64]).

## Part 6: the state and intelligence record

### No state intrusion campaign on the record

No government, court or vendor record opened attributes any 1994 computer intrusion to a state actor (Inferred). No ATT&CK v20.0 group, software or campaign object in the library's data mentions any year from 1990 to 1999, so no G, S or C id binds to a 1994 event (Confirmed [109]). The nearest the record comes is the Air Force officials' remark about Rome Laboratory (Part 3), which no record confirms (Inferred).

### A human mole

On 21 February 1994 the FBI arrested Aldrich Ames, a 31-year CIA veteran who had spied for the Russians since 1985, in Arlington, Virginia, after a ten-month investigation opened in May 1993 (Confirmed [28]). Ames and his wife Rosario pleaded guilty on 28 April; he was sentenced to life without parole and she, on 20 October, to 63 months. He compromised CIA and FBI human sources, some of whom were executed (Confirmed [28]).

### The Joint Security Commission and PDD-29

The Joint Security Commission's report "Redefining Security", dated 28 February 1994 and addressed to Secretary of Defense Perry and Director of Central Intelligence Woolsey (the commission was convened on 11 June 1993), singles out information systems security and personnel security as the areas needing added requirements and finds information systems security lagging the technology it protects (Confirmed [29]). Its chapter 8 records more than 4,000 hacker attacks detected on one government system in a single three-month period, and warns that an unclassified vulnerability database could be used by hackers and foreign intelligence agents (Confirmed [30]). PDD-29, "Security Policy Coordination", signed on 16 September, made the Joint Security Executive Committee the Security Policy Board, abolished the National Advisory Group for Security Countermeasures, and cites interconnected computers among evolving threats (Confirmed [31]).

### Clipper and its protocol failure

The Secretary of Commerce approved FIPS 185, the Escrowed Encryption Standard, published on 9 February 1994 and effective 11 March for voluntary use: the classified SKIPJACK algorithm with escrowed keys to assist law enforcement and other agencies acting under legal authority, and a Law Enforcement Access Field (LEAF) whose creation method is referenced but not specified; NIST's response to comments states that NSA developed its technical basis (Confirmed [34][36][35]). On 20 August Matt Blaze of AT&T Bell Laboratories dated "Protocol Failure in the Escrowed Encryption Standard", a pre-print for the ACM Conference on Computer and Communications Security in November. Working at the protocol level on a prototype PCMCIA device, without cryptanalysis or hardware reverse engineering, it described techniques that let EES devices communicate without transmitting a valid LEAF, whose integrity check is a 16-bit checksum (Confirmed [37]). NIST withdrew FIPS 185 as obsolete on 19 October 2015 (Confirmed [36]; the CSRC landing page date was not re-read, Reported [35]).

### CALEA

The Communications Assistance for Law Enforcement Act, Pub. L. 103-414 (H.R. 4922, 108 Stat. 4279), was approved on 25 October 1994. It requires carriers to be able to isolate and deliver intercepted communications and call-identifying information to the government under court order or other lawful authorization, and says a carrier is not responsible for decrypting subscriber-encrypted communications unless it provided the encryption and holds the means to decrypt (Confirmed [45]).

### The OTA report

The Office of Technology Assessment's September 1994 report OTA-TCT-606, "Information Security and Privacy in Network Environments", prepared for the Senate Governmental Affairs Committee and the House Telecommunications and Finance Subcommittee, found that the 1989 NIST and NSA memorandum appears to cede more authority to NSA than the Computer Security Act envisioned, recorded heavy criticism of the Escrowed Encryption Standard and offered options including a hold on key-escrow deployment (Confirmed [32]). Its identifiers are OTA-TCT-606, GPO stock number 052-003-01387-8 and NTIS PB95-109203 (Confirmed [33]).

## Part 7: the government record

### Law

| Date | Instrument | What it did | Grade | Sources |
|---|---|---|---|---|
| 1994-09-13 | Pub. L. 103-322, title XXIX, sec. 290001(b) to (f), 108 Stat. 2097 to 2099 | Rewrote 18 U.S.C. 1030(a)(5), added (c)(4), added subsection (g), a civil action for anyone who suffers damage or loss, and added subsection (h). Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md). The short title was not checked | Confirmed | [46][47] |
| 1994-10-25 | CALEA, Pub. L. 103-414 | Lawful-interception capability for carriers (Part 6) | Confirmed | [45] |
| 1994-10-31 | *Steve Jackson Games v. US Secret Service*, 5th Cir. No. 93-8661 (Barksdale, J.) | Affirmed: seizing a bulletin-board computer holding stored, unread e-mail is not an "intercept" under the Wiretap Act; the stored-communications provisions govern. The raid was on 1 March 1990 | Confirmed | [49][50] |
| 1994-11-03 | UK Criminal Justice and Public Order Act 1994, section 161 | Adds offences to the Data Protection Act 1984: procuring disclosure of computer-held personal information in breach of the Act, selling it, and offering it for sale | Confirmed | [48] |
| 1994-12-28 | *United States v. LaMacchia*, D. Mass., Crim. No. 94-10092-RGS | Wire-fraud conspiracy charge over a software-sharing board dismissed under *Dowling* | Confirmed | [51][52] |

*Steve Jackson Games* (summary). The Fifth Circuit's opinion closes the case whose 1993 trial judgment and 1990 raid are recorded elsewhere in the library. The [four books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) is its home, and the [pre-Internet study](/case-studies/PRE_INTERNET_THREATS.md) carries the raid; this row is the 1994 decision only (Confirmed [49][50]).

### Standards

| Date | Standard | Substance | Grade | Sources |
|---|---|---|---|---|
| 1994-01-11 | FIPS 140-1, Security Requirements for Cryptographic Modules | Four security levels, superseding FIPS 140; the notice says "effective on January 11, 1994" in its header and 30 June 1994 in its schedule | Confirmed | [40] |
| 1994-02-09 | FIPS 185, Escrowed Encryption Standard | Part 6 | Confirmed | [34][36] |
| 1994-05-19 | FIPS 186, Digital Signature Standard | DSA with the FIPS 180 hash; effective 1 December; 109 organizations and individuals commented; NIST found no valid patent claims; withdrawn 30 December 1996 | Confirmed | [38][39] |
| 1994-07 | NIST SP 800-7, Security in Open Systems | For programmers building telecommunications software on POSIX and OSI platforms | Confirmed | [43] |
| 1994-09-28 | FIPS 190, Advanced Authentication Technology Alternatives | Password-only authentication often fails to protect; tokens and biometrics recommended in combination | Confirmed | [41] |
| 1994-11-09 | FIPS 191, Analysis of Local Area Network Security | LAN security analysis guideline | Confirmed | [42] |
| 1994-12 | NIST SP 800-10, Keeping Your Site Comfortably Secure: An Introduction to Internet Firewalls | Firewall components, access policies and purchasing; withdrawn 2015 | Confirmed | [44] |
| 1994-02 | RFC 1579, Firewall-Friendly FTP | Passive-mode FTP for packet-filter firewalls | Confirmed | [90] |
| 1994-06 | RFC 1636, IAB Workshop on Security in the Internet Architecture | Workshop of 8 to 10 February; firewall architecture section | Confirmed | [91] |
| 1994-08 | RFC 1675, Security Concerns for IPng | IPng must not make security worse than IPv4; firewalls "very much a feature" of the Internet | Confirmed | [92] |
| 1994-10 | RFC 1704, On Internet Authentication | Cites CA-94:01: passwords open to passive attack are not strong enough | Confirmed | [93] |
| 1994-12 | RFC 1750, Randomness Recommendations for Security | Pseudo-random generation of keys and passwords can yield "pseudo-security" | Confirmed | [94] |
| 1994-12 | RFC 1731 and RFC 1734 | IMAP4 and POP3 authentication mechanisms on the standards track | Confirmed | [95] |

### Europe

The Bangemann report, "Europe and the Global Information Society", was prepared for the Corfu European Council of 24 and 25 June 1994; the CORDIS summary does not mention security or privacy (Confirmed [80]). It is context for the information-society policy that followed, not a security record (Inferred).

## Part 8: the defender view

**The password was shown to be broken on the wire, and the answers arrived the same year (Inferred from [3][41][93][95]).** CA-94:01 told sites to change passwords on network-accessed accounts, recommended CERT's cpm tool to detect interfaces in promiscuous mode, comparison of binaries against a baseline with cmp, MD5 or Tripwire, COPS and TCP wrappers, and pointed in an appendix to one-time passwords such as S/KEY and commercial tokens (Confirmed [3]). FIPS 190 in September, RFC 1704 in October and the IMAP4 and POP3 authentication RFCs in December all pushed the same direction (Confirmed [41][93][95]).

**Integrity checking became basic hygiene.** CERT's answer to Trojaned binaries was MD5 (CA-94:05), Tripwire and comparison against baselines, and the cpm tool for promiscuous interfaces (CA-94:01) (Confirmed [1][3][6]).

**The firewall went commercial and got a federal primer.** Check Point's stateful-inspection patent, inventor Gil Shwed, was filed on 15 December 1993 and granted on 25 February 1997 (Confirmed [88]). The Register reported in 2013 that FireWall-1 first appeared publicly at NetWorld+Interop in Las Vegas in 1994, winning best of show, and that Check Point signed an OEM deal with Sun that year (Reported [89]). Bellovin's RFC 1579 adapted FTP to packet filters, the IAB workshop report described application-layer and IP-layer firewalls, and NIST published its firewall introduction in December (Confirmed [90][91][44]). Cheswick and Bellovin's *Firewalls and Internet Security* (Addison-Wesley, 1994), with its chapter "An Evening with Berferd", is cited in RFC 1704 (Confirmed [93]). The same year's advisories marked the limits: Majordomo was reachable behind firewalls and TCP wrappers, and NFS filtering did not stop inside attackers (Confirmed [13][18]).

**Commerce brought transport encryption.** On 15 December Netscape announced Navigator 1.0 and the Netsite servers; the $5,000 Netsite Commerce Server incorporated Netscape's Secure Sockets Layer, based on RSA Data Security technology, for channel encryption and server authentication, and was described as the first secure server software for the Internet (Confirmed [97]). RFC 6101 dates the SSL 2.0 specification to February 1995, so the product shipped before a published protocol document (Confirmed [96]; Inferred). In August the *New York Times* had reported a NetMarket buyer in Philadelphia sending an encrypted Visa number to pay $12.48 plus shipping for a Sting CD; the claim to the first secure online purchase is contested (Reported [79]). The [e-commerce threats study](/case-studies/ECOMMERCE_THREATS.md) begins its record in 1999.

**Intrusion detection was research.** Kumar and Spafford's Purdue COAST report of June classified misuse-detection signatures and presented a matching model based on Colored Petri Nets (Confirmed [100]).

**Cryptography moved under defenders' feet.** In April, about 600 volunteers in more than 20 countries finished factoring RSA-129 after about 5,000 MIPS-years of sieving over eight months (Confirmed [98]). In November, Shor's polynomial-time quantum algorithms for factoring and discrete logarithms appeared in the FOCS proceedings (Confirmed [99]). Both bear on the key lengths and the post-quantum planning defenders still work through (Inferred).

## Part 9: MITRE mappings

No 1994 record carries an ATT&CK or CAPEC id, and only one later NVD record carries a specific CWE: CVE began in 1999, CWE's first list in 2006, CAPEC in 2007 and ATT&CK's first model in September 2013, public in May 2015 with 96 techniques; D3FEND is funded by the NSA Cybersecurity Directorate (Confirmed [81][101][102][103][104]). Every binding below is therefore this study's later mapping (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `technique_to_d3fend.jsonl`, `group_profiles.jsonl`, `data/weaknesses/cwe.jsonl`, `capec.jsonl`) and the generated pages under `mitre/` on 12 November 2026 [105][106][107][108][109][110]. Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md): **Described** means a primary source describes the behavior and this study assigns the id; **Reported** means only a secondary source supports the behavior; **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading. No row is **Listed**, because no 1994 source prints an id.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | CA-94:01, 3 Feb 1994; Rome Laboratory sniffer found 28 Mar; Naval Academy sniffers on eight servers, Dec | [1][3][24][22] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Bank cash-management transfers, late Jun to Oct, through compromised valid user IDs and passwords; Rome intruders use captured credentials on an aerospace contractor (Apr) and masquerade as a trusted Rome user | [27][24][23] |
| [`T1110.002`](/mitre/techniques/T1110-002.md) | Password Cracking | credential-access | Inferred | Rome intruders' scanning tool locates and copies password files; a password-file theft attempted at Wright-Patterson, 14 Apr (cracking is the Senate record's general explanation, not an observed act) | [24] |
| [`T1090.003`](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | command-and-control | Described | Rome intruders route through South American phone switches and US commercial sites; NASA Goddard reached via Seattle and Latvia, 14 Apr | [22][24] |
| [`T1595`](/mitre/techniques/T1595.md) | Active Scanning | reconnaissance | Described | Rome intruders scan Brookhaven (12 Apr) and NATO HQ (15 Apr) | [24] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Inferred | The same scans; the record does not say which services were probed | [24] |
| [`T1005`](/mitre/techniques/T1005.md) | Data from Local System | collection | Described | Rome battlefield simulation and air tasking order research data copied; Korean Atomic Research Institute data moved to Rome, Apr | [24][22] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | initial-access | Described | CA-94:07 wuarchive ftpd source, 6 Apr; CA-94:14 ircII 2.2.9 source, 19 Oct (corrupt since May); later grouped in CVE-1999-0661 | [8][17][1][85] |
| [`T1554`](/mitre/techniques/T1554.md) | Compromise Host Software Binary | persistence | Described | CA-94:01 Trojan horse system programs; CA-94:05, 18 Mar, Trojans built to match the "sum" checksum | [3][6] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Described | CA-94:03 (24 Feb), CA-94:04 (17 Mar), CA-94:06 (21 Mar), CA-94:08 race (14 Apr), CA-94:12 (14 Jul), CA-94:13 (11 Aug) | [1][5][7][9][14][16] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | CA-94:02 mountd (14 Feb), CA-94:08 SITE EXEC (14 Apr), CA-94:09 login (23 May), CA-94:10 bsh (3 Jun), CA-94:11 Majordomo (9 Jun), CA-94:15 NFS (19 Dec) | [4][9][11][12][13][18] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Inferred | CA-94:15 NFS tools; CERT notes border filtering does not protect against inside attacks | [18] |
| [`T1563`](/mitre/techniques/T1563.md) | Remote Service Session Hijacking | lateral-movement | Described | 25 Dec intrusion: an existing session hijacked after root; CA-95:01 (boundary). The [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) binds it too | [54][19][112] |
| [`T1547.006`](/mitre/techniques/T1547-006.md) | Kernel Modules and Extensions | persistence, privilege-escalation | Described | 25 Dec: a loadable kernel STREAMS module; CA-95:01: dynamic kernel modification on SunOS 4.1.x | [54][19] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | KAOS4, posted 24 Jul, spreads only when an infected file is run | [73] |
| [`T1542.003`](/mitre/techniques/T1542-003.md) | Bootkit | stealth, persistence | Described | One_Half infects the master boot record (May per F-Secure); boot viruses such as Form.A on the 1 Sep WildList (that tie is Inferred) | [74][75] |
| [`T1027.014`](/mitre/techniques/T1027-014.md) | Polymorphic Code | stealth | Described | One_Half is polymorphic (Confirmed); Pathogen and the SMEG engine (Reported) | [74][69] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | lateral-movement, initial-access | Inferred | Boot-sector and file viruses on the 1 Sep WildList | [75] |
| [`T1486`](/mitre/techniques/T1486.md) | Data Encrypted for Impact | impact | Inferred | One_Half encrypts two more disk cylinders on each boot; a stretch, since it decrypts on the fly and makes no demand | [74] |

Left out on purpose: the bank transfers' wire movements and the MCI and BT insider cases and the Livermore misuse case, because the records describe access by people with legitimate or stolen accounts without enough detail beyond T1078; the Internet Liberation Front's mailbox flooding and phone forwarding, a press account only; the Clipper LEAF bypass, a protocol design failure rather than an intrusion; the Good Times hoax, which describes no code; and the IPEX logic bomb and the infected CD-ROMs, which are press-reported and have no confirmed delivery path (Inferred).

### ATT&CK for ICS techniques

None. No 1994 intrusion into an industrial control system appears in any primary opened (Inferred); the Salt River Project break-in is press-reported, and the account says the intruder could not have controlled any dams (Reported [78]). No ICS layer is published.

### ATT&CK groups, software and campaigns

None. No ATT&CK v20.0 group, software or campaign object in the library's data (groups, group profiles, campaigns, campaign profiles, software profiles) mentions any year from 1990 to 1999 (Confirmed [109]), and no record opened attributes a 1994 intrusion to a state or to a named group with an ATT&CK object (Inferred). Datastream Cowboy, Kuji, the Black Baron and the ARCV group have no ATT&CK objects; neither do One_Half, KAOS4, Pathogen or the 1994 sniffer (Inferred [109]).

### CWE and CAPEC

One CWE is listed by a record for a 1994 flaw: NVD's CWE-88 on CVE-1999-0113, the CA-94:09 login flaw (Confirmed [84]). Every other row is this study's binding (Inferred). The CAPEC column gives the attack patterns the library's data relates to that CWE or to the matching technique, and says so where the pairing is this study's own [107][108].

| CWE | Weakness (library name) | 1994 record | CAPEC |
|---|---|---|---|
| CWE-319 | Cleartext Transmission of Sensitive Information | CA-94:01 sniffing of FTP, telnet and rlogin logins | [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (the library relates it to T1040) and [CAPEC-65](/mitre/capec/CAPEC-65.md) Sniff Application Code (the library relates it to CWE-319 and T1040) |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | CA-94:06 writable utmp; the replaced binaries of CA-94:01 and CA-94:05 | [CAPEC-642](/mitre/capec/CAPEC-642.md) Replace Binaries (the library relates it to CWE-732 and T1554) |
| CWE-354 | Improper Validation of Integrity Check Value | CA-94:05 Trojans built to match the "sum" checksum | [CAPEC-145](/mitre/capec/CAPEC-145.md) Checksum Spoofing (the library relates it to CWE-354) |
| CWE-506 | Embedded Malicious Code | CA-94:07 wuarchive ftpd and CA-94:14 ircII source Trojans | [CAPEC-442](/mitre/capec/CAPEC-442.md) Infected Software (the library relates it to CWE-506 and T1195.002) |
| CWE-494 | Download of Code Without Integrity Check | The same two Trojans, fetched from FTP sites | [CAPEC-184](/mitre/capec/CAPEC-184.md) Software Integrity Attack (the library relates it to CWE-494) |
| CWE-88 | Improper Neutralization of Argument Delimiters in a Command | CA-94:09 /bin/login, as NVD lists it for CVE-1999-0113 (Confirmed [84]) | [CAPEC-88](/mitre/capec/CAPEC-88.md) OS Command Injection (the library relates it to CWE-88 and CWE-78); [CAPEC-6](/mitre/capec/CAPEC-6.md) Argument Injection (a name fit; the library relates it to CWE-78, not CWE-88) |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command | CA-94:11 Majordomo arbitrary commands | [CAPEC-88](/mitre/capec/CAPEC-88.md) and [CAPEC-6](/mitre/capec/CAPEC-6.md), both related to CWE-78 in the library's data |
| CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization | CA-94:08 ftpd race condition | [CAPEC-26](/mitre/capec/CAPEC-26.md), the library's race-condition attack pattern (related to CWE-362 in the library's data) |
| CWE-250 | Execution with Unnecessary Privileges | CA-94:03 setuid performance tools | [CAPEC-233](/mitre/capec/CAPEC-233.md) Privilege Escalation (this study's pairing; the library relates it to CWE-269 and T1548) |
| CWE-290 | Authentication Bypass by Spoofing | 25 Dec intrusion; CA-95:01 address-based trust | [CAPEC-324](/mitre/capec/CAPEC-324.md) TCP (ISN) Sequence Predictability Probe (this study's pairing; the library relates it to CWE-200); the home study's [CAPEC-593](/mitre/capec/CAPEC-593.md) Session Hijacking (the library relates it to T1563) and [CAPEC-482](/mitre/capec/CAPEC-482.md) TCP Flood |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | One_Half, KAOS4, Pathogen and the WildList viruses | [CAPEC-552](/mitre/capec/CAPEC-552.md) Install Rootkit (the library relates it to T1542.003 and T1547.006, not to CWE-509) |

### D3FEND countermeasures

Pairings come from `data/attack/technique_to_d3fend.jsonl` unless the row says the pairing is this study's; every page exists under `/mitre/d3fend/` [106][110].

| Technique from the record | D3FEND countermeasures | 1994 analogue |
|---|---|---|
| T1040 Network Sniffing | The library maps only [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md). [One-time Password](/mitre/d3fend/one-time-password.md), [Message Encryption](/mitre/d3fend/message-encryption.md) and [Credential Transmission Scoping](/mitre/d3fend/credential-transmission-scoping.md) are concept matches only | CA-94:01 Appendix B on S/KEY and tokens; FIPS 190; RFC 1704, 1731 and 1734 [3][41][93][95] |
| T1078 Valid Accounts and T1110.002 Password Cracking | [Account Locking](/mitre/d3fend/account-locking.md) and [Change Default Password](/mitre/d3fend/change-default-password.md) (library pairings for T1078); [One-time Password](/mitre/d3fend/one-time-password.md), [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md), [Credential Rotation](/mitre/d3fend/credential-rotation.md), [Password Rotation](/mitre/d3fend/password-rotation.md) and [Strong Password Policy](/mitre/d3fend/strong-password-policy.md) (library pairings for T1110.002) | CERT's advice to change passwords on every network-accessed account; the Naval Academy's 12,000 password changes [3][22] |
| T1554 Compromise Host Software Binary | [Software Update](/mitre/d3fend/software-update.md), [Restore Software](/mitre/d3fend/restore-software.md), [Software Inventory](/mitre/d3fend/software-inventory.md), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) (library pairings). [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) and [System File Analysis](/mitre/d3fend/system-file-analysis.md) are concept matches the library does not map to T1554 | MD5 checksums, Tripwire, cmp against a baseline [6][3] |
| T1195.002 Compromise Software Supply Chain | [Software Update](/mitre/d3fend/software-update.md), [Restore Software](/mitre/d3fend/restore-software.md), [Software Inventory](/mitre/d3fend/software-inventory.md), [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md) (library pairings) | Install wu-ftpd 2.3 or ircII 2.6, verify checksums, or disable the service [8][17] |
| T1190 and T1210 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (library pairing for T1190) and [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (library pairing for both) | CA-94:15 filtering of ports 111 and 2049 and Venema's portmapper [18] |
| T1068 Exploitation for Privilege Escalation | The library's pairings are memory-safety hardenings that do not describe these fixes. [Local File Permissions](/mitre/d3fend/local-file-permissions.md) is a concept match only | CA-94:03 removal of setuid bits; CA-94:06 utmp permissions [5][7] |
| T1090.003 Multi-hop Proxy | [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md), [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (library pairings) | Rome's monitoring under a logon banner [24] |
| T1563 Remote Service Session Hijacking | [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md), [Session Termination](/mitre/d3fend/session-termination.md) (library pairings) | Shimomura's own log analysis [54] |
| T1547.006 Kernel Modules and Extensions | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Local File Permissions](/mitre/d3fend/local-file-permissions.md) (library pairings) | No 1994 counterpart in the record |
| T1204.002 Malicious File and T1542.003 Bootkit | [File Analysis](/mitre/d3fend/file-analysis.md), [Emulated File Analysis](/mitre/d3fend/emulated-file-analysis.md), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (library pairings for T1204.002); [Bootloader Authentication](/mitre/d3fend/bootloader-authentication.md) (library pairing for T1542.003) | Virus scanners and the WildList [75] |
| T1091 Replication Through Removable Media | [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) (library pairing) | No 1994 counterpart in the record |

The library's data has no D3FEND pairing for T1046, T1595 or T1027.014, and none is invented here [106].

### Navigator layer

The study's techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-1994.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1994.json) (saved beside the other hand-authored layers [111]), listing the 19 techniques in the Enterprise table under each tactic they carry in v20.0, and listed on [the Navigator layers page](/navigator/index.md). Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping; no entry scores 100, because no 1994 source prints an id. Each entry's comment names the source numbers in the Sources table below. No ICS layer is needed.

## Cross-cutting themes

**The password broke on the wire.** One advisory's "tens of thousands of systems" (Confirmed [1][3]), the sniffers at Rome and Annapolis (Confirmed [24][22]) and RFC 1704's citation of the CERT advisory (Confirmed [93]) make 1994 the year cleartext reusable passwords were shown to fail at Internet scale (Inferred). One-time passwords, FIPS 190 and new mail-authentication RFCs followed within months (Confirmed [3][41][95]).

**Trust in software became something to check.** Trojaned binaries built to defeat a weak checksum (Confirmed [6]) and two back-doored source releases (Confirmed [8][17]) pushed MD5, Tripwire and published checksums into routine practice (Confirmed [1][6][9]). The same supply-chain class runs through the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies (Inferred).

**Attribution was hard at small scale too.** Two intruders, one 16, made Rome Laboratory look like a foreign operation to officials, and the record still could not say where the NASA data was going (Confirmed [23][24]). The questions the [state-actor studies](/case-studies/THREAT_ACTORS_RUSSIA.md) ask of later years were already being asked in 1994 (Inferred).

**Encryption policy and cryptanalysis collided.** FIPS 185 (February), Blaze's LEAF bypass (August), CALEA (October), the OTA's criticism of key escrow (September), RSA-129 (April) and Shor's algorithm (November) all date to one year (Confirmed [34][37][45][32][98][99]).

**Insiders and the phone network carried much of the year's crime (Inferred).** The largest theft ran over the telecommunications network, not the Internet (Confirmed [27]); the MCI and BT cases involved people with legitimate access (Reported [76][60]); and the UK's new data offences targeted procurement of personal data (Confirmed [48]).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: Rome Laboratory as foreign espionage.** The only state framing in the record is officials' "may have been working for a foreign country" [23]; the identified intruder was 16 [24].
- **Overstated: the cost of Rome Laboratory in headline use.** The Air Force's $211,722 damage assessment and the over $500,000 estimate GAO cites measure different things [24][22].
- **Overstated: press counts of stolen passwords.** Newsday's 10,000 and the *Atlanta Journal-Constitution*'s 100,000 are not tied to a primary figure [58][59]; CERT's own estimate is tens of thousands of systems [1].
- **Overstated: the 1994 bank fraud as an Internet bank robbery.** The FBI says it did not involve the Internet; more than $10 million is its total for about 40 illegal transfers, the case surfaced at $400,000 missing, and the bank froze the overseas accounts so no more could be withdrawn [27].
- **Overstated: the Pathogen panic and the Good Times scare.** *Virus Bulletin* put Pathogen at about 15 sites [69]; Good Times did not exist [63].
- **Overstated: the Salt River Project dam story.** The intruder was 27 and could not have controlled any dams, the 2010 account says [78].
- **Overstated: CVE records dated 1994.** NVD's 25 live 1994-dated records were back-filled after CVE began in 1999, almost all have no specific CWE, and one, CVE-2000-0508, has a 1994 date it cannot have [82][86].
- **Overstated: CERT's incident count and vendor "firsts".** CERT itself called counts of little use [77]; "the first secure server software for the Internet" is Netscape's own description [97], and FireWall-1's 1994 debut rests on a 2013 press profile [89].
- **Overstated: any ATT&CK, CWE or CAPEC id on a 1994 event.** None of those programs existed until 1999 to 2015 [81][101][102][103].
- **Understated: the sniffer wave.** The year's largest credential compromise by CERT's own count has no named victim and no home study before this one [1][3].
- **Understated: the 1994 source Trojans.** wuarchive ftpd and ircII are early software supply-chain compromises, and the ircII Trojan circulated about five months before the advisory [8][17].
- **Understated: the Naval Academy compromise.** Unidentified attackers coming from three countries and two US universities forced more than 12,000 password changes, and the case is little known [22].
- **Understated: PC viruses.** CERT's Unix-centred advisories omit the problem the WildList's 16 reporters tracked [75][1].
- **Understated: local-root flaws.** They make up much of the year's advisories but get little attention next to the headline intrusions, though they were how sniffers got installed [1][3].
- **Understated: the year's state story is people and policy.** Ames, the Joint Security Commission, Clipper and CALEA, not intrusions [28][29][34][45].

### Discrepancies in the record

- **Rome Laboratory cost.** $211,722 (Air Force damage assessment, 31 October 1994, excluding investigation) against over $500,000 (Air Force Information Warfare Center, as GAO cites it); different scopes [24][22].
- **Kuji's identity.** The Senate record of June 1996 says Kuji was never identified [24]; the 2024 ISC2 retrospective names him and says he was caught about two years later [26]; the dates are compatible if he was caught after June 1996.
- **Password counts.** Over 10,000 (Newsday) against more than 100,000 (*Atlanta Journal-Constitution*) [58][59].
- **MCI calling-card numbers.** About 60,000 (*New York Times*) against 100,000 (*Los Angeles Daily News*) [76].
- **FIPS 140-1's effective date.** 11 January 1994 in the notice's header, 30 June 1994 in its implementation schedule [40].
- **The Green Card posting.** Templeton gives April 1994; the dot-com era study and a later retrospective give 12 April [55][56].
- **CA-94:12 and CVE-1999-1309.** The probable later record is dated 30 August 1996, two years after the advisory [87].
- **The 1994 CERT incident count.** 2,340 in a reprint of CERT's table; no 1994 figure in CERT's 1996 Senate testimony [77][25].
- **The Black Baron case.** *Virus Bulletin*'s 1994 account has a suspected author arrested and bailed; Bates's 1996 account dates the warrant to 13 July 1994 and the sentence to November 1995 [69][72].
- **The wuarchive fix.** CA-94:07 named version 2.3; a week later CA-94:08 published checksums for 2.4 [8][9].

## Sources

All sources were opened on 12 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the gao.gov PDF and the NVD API query); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "1994 CERT Advisories" (compilation, CA-1994-01 to CA-1994-15) | https://www.sei.cmu.edu/documents/517/1994_019_001_496252.pdf | 2026-11-12 | Confirmed |
| 2 | CMU SEI, "1994 CERT Advisories" (landing page) | https://www.sei.cmu.edu/library/1994-cert-advisories/ | 2026-11-12 | Confirmed |
| 3 | CERT/CC, CA-94:01 Ongoing Network Monitoring Attacks (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0073.txt | 2026-11-12 | Confirmed |
| 4 | CERT/CC, CA-94:02 Revised Patch for SunOS rpc.mountd (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0075.txt | 2026-11-12 | Confirmed |
| 5 | CERT/CC, CA-94:03 IBM AIX performance tools (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0076.txt | 2026-11-12 | Confirmed |
| 6 | CERT/CC, CA-94:05 MD5 Checksums (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0077.txt | 2026-11-12 | Confirmed |
| 7 | CERT/CC, CA-94:06 Writable /etc/utmp (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0078.txt | 2026-11-12 | Confirmed |
| 8 | CERT/CC, CA-94:07 wuarchive ftpd Trojan Horse (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0079.txt | 2026-11-12 | Confirmed |
| 9 | CERT/CC, CA-94:08 ftpd Vulnerabilities (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0080.txt | 2026-11-12 | Confirmed |
| 10 | CERT/CC, CA-94:08 ftpd Vulnerabilities (FTP-archive mirror) | https://www.scnresearch.com/pub/security/CERT/cert_advisories/CA-94:08.ftpd.vulnerabilities | 2026-11-12 | Confirmed |
| 11 | CERT/CC, CA-94:09 /bin/login Vulnerability (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0081.txt | 2026-11-12 | Confirmed |
| 12 | CERT/CC, CA-94:10 IBM AIX bsh batch queue (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0083.txt | 2026-11-12 | Confirmed |
| 13 | CERT/CC, CA-94:11 Majordomo (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0084.txt | 2026-11-12 | Confirmed |
| 14 | CERT/CC, CA-94:12 Sendmail Vulnerabilities (NANOG distribution, seclists archive) | https://seclists.org/nanog/1994/Jul/17 | 2026-11-12 | Confirmed |
| 15 | CERT/CC, CA-94:12 Sendmail Vulnerabilities (FTP-archive mirror) | https://www.scnresearch.com/pub/security/CERT/cert_advisories/CA-94:12.sendmail.vulnerabilities | 2026-11-12 | Confirmed |
| 16 | CERT/CC, CA-94:13 SGI IRIX help system (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0085.txt | 2026-11-12 | Confirmed |
| 17 | CERT/CC, CA-94:14 Trojan Horse in IRC Client for UNIX (NANOG archive) | https://lists.nanog.org/archives/list/test@lists.nanog.org/thread/TQUNWWQIZBI4JN5XQ4QKNKPNHSJKCSNA/ | 2026-11-12 | Confirmed |
| 18 | CERT/CC, CA-94:15 NFS Vulnerabilities (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0087.txt | 2026-11-12 | Confirmed |
| 19 | CERT/CC, CA-95:01 IP Spoofing Attacks and Hijacked Terminal Connections (archived text) | https://mirror.cyberbits.eu/textfiles.com/internet/CERT/cert0088.txt | 2026-11-12 | Confirmed |
| 20 | CERT/CC, CA-95:01 (FTP-archive mirror) | https://www.scnresearch.com/pub/security/CERT/cert_advisories/CA-95:01.IP.spoofing | 2026-11-12 | Confirmed |
| 21 | CERT/CC, CA-94:04 SunOS /usr/ucb/rdist Vulnerability (FTP-archive mirror) | https://www.scnresearch.com/pub/security/CERT/cert_advisories/CA-94:04.SunOS.rdist.vulnerability | 2026-11-12 | Confirmed |
| 22 | GAO, AIMD-96-84, Information Security: Computer Attacks at Department of Defense Pose Increasing Risks, 22 May 1996 (govinfo text) | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-96-84/html/GAOREPORTS-AIMD-96-84.htm | 2026-11-12 | Confirmed |
| 23 | GAO, AIMD-96-84 (PDF) | `https://www.gao.gov/assets/aimd-96-84.pdf` | 2026-11-12 | Confirmed |
| 24 | US Senate Permanent Subcommittee on Investigations, minority staff statement, hearing of 5 June 1996 (Rome Laboratory case study) | https://irp.fas.org/congress/1996_hr/s960605b.htm | 2026-11-12 | Confirmed |
| 25 | Testimony of the CERT/CC manager, Senate hearing of 5 June 1996 | https://irp.fas.org/congress/1996_hr/s960605m.htm | 2026-11-12 | Confirmed |
| 26 | ISC2 Insights, "30 Years After 2 Kids Broke into the Air Force", September 2024 | https://www.isc2.org/Insights/2024/09/CISSP30-30-Years-After-2-Kids-Broke-into-the-Air-Force | 2026-11-12 | Reported |
| 27 | FBI, "A Byte Out of History: $10 Million Hack, 1994-Style" | https://www.fbi.gov/news/stories/a-byte-out-of-history-10-million-hack | 2026-11-12 | Confirmed |
| 28 | FBI, Famous Cases: Aldrich Ames | https://www.fbi.gov/history/famous-cases/aldrich-ames | 2026-11-12 | Confirmed |
| 29 | Joint Security Commission, "Redefining Security", 28 February 1994 (FAS copy; also read at index.html) | https://sgp.fas.org/library/jsc/ | 2026-11-12 | Confirmed |
| 30 | Joint Security Commission, chapter 8 | https://sgp.fas.org/library/jsc/chap8.html | 2026-11-12 | Confirmed |
| 31 | PDD-29, Security Policy Coordination, 16 September 1994 (FAS copy) | https://sgp.fas.org/spb/pdd29.html | 2026-11-12 | Confirmed |
| 32 | OTA, Information Security and Privacy in Network Environments, OTA-TCT-606, September 1994 (summary text) | https://groups.csail.mit.edu/mac/classes/6.805/articles/crypto/ota-infosec/8pager.txt | 2026-11-12 | Confirmed |
| 33 | Princeton OTA archive, OTA-TCT-606 index | https://www.princeton.edu/~ota/disk1/1994/9416_n.html | 2026-11-12 | Confirmed |
| 34 | Federal Register, approval of FIPS 185, 9 February 1994 (Doc. 94-2919) | https://www.govinfo.gov/content/pkg/FR-1994-02-09/html/94-2919.htm | 2026-11-12 | Confirmed |
| 35 | NIST CSRC, FIPS 185 landing page (withdrawal date from a search summary, not re-read) | https://csrc.nist.gov/pubs/fips/185/final | 2026-11-12 | Reported |
| 36 | NIST, FIPS 185 (PDF) | https://csrc.nist.gov/files/pubs/fips/185/final/docs/fips185.pdf | 2026-11-12 | Confirmed |
| 37 | Matt Blaze, "Protocol Failure in the Escrowed Encryption Standard", 20 August 1994 | https://www.mattblaze.org/papers/eesproto.pdf | 2026-11-12 | Confirmed |
| 38 | Federal Register, approval of FIPS 186, 19 May 1994 (Doc. 94-12218) | https://www.govinfo.gov/content/pkg/FR-1994-05-19/html/94-12218.htm | 2026-11-12 | Confirmed |
| 39 | NIST CSRC, FIPS 186 | https://csrc.nist.gov/pubs/fips/186/final | 2026-11-12 | Confirmed |
| 40 | Federal Register, approval of FIPS 140-1, 11 January 1994 (Doc. 94-539) | https://www.govinfo.gov/content/pkg/FR-1994-01-11/html/94-539.htm | 2026-11-12 | Confirmed |
| 41 | NIST CSRC, FIPS 190 | https://csrc.nist.gov/pubs/fips/190/final | 2026-11-12 | Confirmed |
| 42 | NIST CSRC, FIPS 191 | https://csrc.nist.gov/pubs/fips/191/final | 2026-11-12 | Confirmed |
| 43 | NIST CSRC, SP 800-7 | https://csrc.nist.gov/pubs/sp/800/7/final | 2026-11-12 | Confirmed |
| 44 | NIST CSRC, SP 800-10 | https://csrc.nist.gov/pubs/sp/800/10/final | 2026-11-12 | Confirmed |
| 45 | Communications Assistance for Law Enforcement Act, Pub. L. 103-414, 108 Stat. 4279 | https://www.govinfo.gov/content/pkg/STATUTE-108/pdf/STATUTE-108-Pg4279.pdf | 2026-11-12 | Confirmed |
| 46 | 18 U.S.C. 1030 with amendment notes (Cornell LII) | https://www.law.cornell.edu/uscode/text/18/1030 | 2026-11-12 | Confirmed |
| 47 | 18 U.S.C. 1030, US Code 2011 edition (govinfo) | https://www.govinfo.gov/content/pkg/USCODE-2011-title18/html/USCODE-2011-title18-partI-chap47-sec1030.htm | 2026-11-12 | Confirmed |
| 48 | UK Criminal Justice and Public Order Act 1994, section 161 as enacted | https://www.legislation.gov.uk/ukpga/1994/33/section/161/enacted | 2026-11-12 | Confirmed |
| 49 | *Steve Jackson Games v. US Secret Service*, 5th Cir. opinion (reprint; also opened at the http address) | https://www.sjgames.com/SS/appeal-opinion.html | 2026-11-12 | Confirmed |
| 50 | *Steve Jackson Games v. US Secret Service*, 36 F.3d 457 (Justia) | https://law.justia.com/cases/federal/appellate-courts/F3/36/457/563168/ | 2026-11-12 | Confirmed |
| 51 | *United States v. LaMacchia*, D. Mass., 28 December 1994 (opinion text) | https://digital-law-online.info/cases/33PQ2D1978.htm | 2026-11-12 | Confirmed |
| 52 | *United States v. LaMacchia* (opinion text, second copy) | https://www.nicholasjohnson.org/cls00/LaMacchi.html | 2026-11-12 | Confirmed |
| 53 | Tsutomu Shimomura, technical details of the attack presented at CMAD 3, January 1995 | https://pld.cs.luc.edu/courses/447/sum08/class7/shimomura.text | 2026-11-12 | Confirmed |
| 54 | Tsutomu Shimomura, post of 25 January 1995 | https://aeb.win.tue.nl/linux/hh/shimomura-25jan95.txt | 2026-11-12 | Confirmed |
| 55 | Brad Templeton, origin of the term "spam" | https://www.templetons.com/brad/spamterm.html | 2026-11-12 | Reported |
| 56 | Today I Found Out, the first mass commercial Internet spam campaign, April 2012 | https://www.todayifoundout.com/index.php/2012/04/this-day-in-history-the-first-mass-commercial-internet-spam-campaign-is-launched/ | 2026-11-12 | Reported |
| 57 | UPI, "Hacker pleads guilty to fraud", 14 June 1994 | https://www.upi.com/Archives/1994/06/14/Hacker-pleads-guilty-to-fraud/7490771566400/ | 2026-11-12 | Reported |
| 58 | *Phrack* 45, Phrack World News (reprints of AP, Newsday, LA Times, UPI and Olympics coverage) | https://phrack.org/issues/45/phrack-world-news.html | 2026-11-12 | Reported |
| 59 | *Phrack* 46, Phrack World News (reprints of the *Atlanta Journal-Constitution*, AFP, LA Times, NYT and other coverage) | https://phrack.org/issues/46/phrack-world-news.html | 2026-11-12 | Reported |
| 60 | *Phrack* 47, Phrack World News (summary of *The Independent* on BT) | https://phrack.org/issues/47/phrack-world-news.html | 2026-11-12 | Reported |
| 61 | *TIME*, "Terror on the Internet" (page 1) | https://content.time.com/time/subscriber/article/0,33009,981986-1,00.html | 2026-11-12 | Reported |
| 62 | CIAC Notes 94-04 and 95-09 on Good Times (Bugtraq archive copy) | https://seclists.org/bugtraq/1994/Dec/109 | 2026-11-12 | Confirmed |
| 63 | CIAC Notes 94-04, Good Times hoax (mirror) | https://www.mathematik.uni-ulm.de/admin/kettenbriefe/ciac-good-times.html | 2026-11-12 | Confirmed |
| 64 | TidBITS, "Relax, It's a Hoax", 12 December 1994 | https://tidbits.com/1994/12/12/relax-its-a-hoax/ | 2026-11-12 | Reported |
| 65 | *Virus Bulletin*, January 1994 | https://www.virusbulletin.com/uploads/pdf/magazine/1994/199401.pdf | 2026-11-12 | Reported |
| 66 | *Virus Bulletin*, February 1994 | https://www.virusbulletin.com/uploads/pdf/magazine/1994/199402.pdf | 2026-11-12 | Reported |
| 67 | *Virus Bulletin*, March 1994 | https://www.virusbulletin.com/uploads/pdf/magazine/1994/199403.pdf | 2026-11-12 | Reported |
| 68 | *Virus Bulletin*, May 1994 | https://www.virusbulletin.com/uploads/pdf/magazine/1994/199405.pdf | 2026-11-12 | Reported |
| 69 | *Virus Bulletin*, August 1994 | https://www.virusbulletin.com/uploads/pdf/magazine/1994/199408.pdf | 2026-11-12 | Reported |
| 70 | *Virus Bulletin*, September 1994 | https://www.virusbulletin.com/uploads/pdf/magazine/1994/199409.pdf | 2026-11-12 | Reported |
| 71 | *Virus Bulletin*, December 1994 | https://www.virusbulletin.com/uploads/pdf/magazine/1994/199412.pdf | 2026-11-12 | Reported |
| 72 | Jim Bates, "Regina v Christopher Pile: The Inside Story", *Virus Bulletin*, February 1996 | https://www.virusbulletin.com/uploads/pdf/magazine/1996/199602-feature-JimBates.pdf | 2026-11-12 | Reported |
| 73 | F-Secure, KAOS4 description | https://www.f-secure.com/v-descs/kaos4.shtml | 2026-11-12 | Confirmed |
| 74 | F-Secure, One_Half description | https://www.f-secure.com/v-descs/one-half.shtml | 2026-11-12 | Confirmed |
| 75 | The WildList, 1 September 1994 (Virus Bulletin archive) | https://www.virusbulletin.com/resources/wildlists/1994/09 | 2026-11-12 | Confirmed |
| 76 | *New York Times* report on the MCI calling-card case (text archive copy) | https://sunsite2.icm.edu.pl/pub/graphics/demos/resources/docs/scener_busts/nytimes.txt | 2026-11-12 | Reported |
| 77 | CERT/CC statistics 1988 to 2004 (reprint) | https://cdrinfo.com/d7/content/certcc-statistics-1988-2004 | 2026-11-12 | Reported |
| 78 | M. E. Kabay, "Attacks on power systems: hackers, malware", Network World, 13 September 2010 | https://www.networkworld.com/article/2217684/attacks-on-power-systems--hackers--malware.html | 2026-11-12 | Reported |
| 79 | Peter H. Lewis, "Attention Shoppers: Internet Is Open", *New York Times*, 12 August 1994 | https://www.nytimes.com/1994/08/12/business/attention-shoppers-internet-is-open.html | 2026-11-12 | Reported |
| 80 | CORDIS, Bangemann report summary | https://cordis.europa.eu/article/id/2730-bangemann-report-europe-and-the-global-information-society | 2026-11-12 | Confirmed |
| 81 | CVE, history of the CVE program (archived about page) | https://www.cve.org/Resources/Media/Archives/OldWebsite/about/history.html | 2026-11-12 | Confirmed |
| 82 | NVD CVE API, records published 1 January to 30 April 1994 (with three further windows to 31 December) | `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=1994-01-01T00:00:00.000&pubEndDate=1994-04-30T23:59:59.999` | 2026-11-12 | Demonstrated |
| 83 | NVD, CVE-1999-0207 (with CVE-1999-0211, 0338, 0120, 0337 and 1219 opened by id) | https://nvd.nist.gov/vuln/detail/CVE-1999-0207 | 2026-11-12 | Confirmed |
| 84 | NVD, CVE-1999-0113 | https://nvd.nist.gov/vuln/detail/CVE-1999-0113 | 2026-11-12 | Confirmed |
| 85 | NVD, CVE-1999-0661 | https://nvd.nist.gov/vuln/detail/CVE-1999-0661 | 2026-11-12 | Confirmed |
| 86 | NVD, CVE-2000-0508 | https://nvd.nist.gov/vuln/detail/CVE-2000-0508 | 2026-11-12 | Confirmed |
| 87 | NVD, CVE-1999-1309 | https://nvd.nist.gov/vuln/detail/CVE-1999-1309 | 2026-11-12 | Confirmed |
| 88 | US Patent 5,606,668 (Google Patents) | https://patents.google.com/patent/US5606668A/en | 2026-11-12 | Confirmed |
| 89 | John Leyden, Check Point profile, The Register, 23 April 2013 | https://www.theregister.com/2013/04/23/check_point_profile/ | 2026-11-12 | Reported |
| 90 | RFC 1579, Firewall-Friendly FTP | https://www.rfc-editor.org/rfc/rfc1579.txt | 2026-11-12 | Confirmed |
| 91 | RFC 1636, Report of the IAB Workshop on Security in the Internet Architecture | https://www.rfc-editor.org/rfc/rfc1636.txt | 2026-11-12 | Confirmed |
| 92 | RFC 1675, Security Concerns for IPng | https://www.rfc-editor.org/rfc/rfc1675.txt | 2026-11-12 | Confirmed |
| 93 | RFC 1704, On Internet Authentication | https://www.rfc-editor.org/rfc/rfc1704.txt | 2026-11-12 | Confirmed |
| 94 | RFC 1750, Randomness Recommendations for Security | https://www.rfc-editor.org/rfc/rfc1750.txt | 2026-11-12 | Confirmed |
| 95 | RFC 1734, POP3 AUTHentication command (RFC 1731 read alongside) | https://www.rfc-editor.org/rfc/rfc1734.txt | 2026-11-12 | Confirmed |
| 96 | RFC 6101, The Secure Sockets Layer (SSL) Protocol Version 3.0 | https://www.rfc-editor.org/rfc/rfc6101.txt | 2026-11-12 | Confirmed |
| 97 | Netscape press release of 15 December 1994, reposted to www-talk | https://ksi.cpsc.ucalgary.ca/archives/WWW-TALK/www-talk-1994q4/1135.html | 2026-11-12 | Confirmed |
| 98 | Atkins, Graff, Lenstra and Leyland, RSA-129 announcement, sci.math, 26 April 1994 | https://groups.google.com/g/sci.math/c/9-A8sngH7ag | 2026-11-12 | Confirmed |
| 99 | Peter Shor, polynomial-time algorithms for prime factorization and discrete logarithms (arXiv record) | https://arxiv.org/abs/quant-ph/9508027 | 2026-11-12 | Confirmed |
| 100 | Kumar and Spafford, "An Application of Pattern Matching in Intrusion Detection", COAST TR 94-07 | https://www.cerias.purdue.edu/techreports-ssl/public/94-07.pdf | 2026-11-12 | Confirmed |
| 101 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 102 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 103 | MITRE, ATT&CK Design and Philosophy, March 2020 | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | 2026-11-12 | Confirmed |
| 104 | MITRE D3FEND, about | https://d3fend.mitre.org/about/ | 2026-11-12 | Confirmed |
| 105 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_profiles.jsonl | 2026-11-12 | Demonstrated |
| 106 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_to_d3fend.jsonl | 2026-11-12 | Demonstrated |
| 107 | TeamStarWolf library, `data/weaknesses/capec.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/capec.jsonl | 2026-11-12 | Demonstrated |
| 108 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/cwe.jsonl | 2026-11-12 | Demonstrated |
| 109 | TeamStarWolf library, `data/attack/group_profiles.jsonl` (with groups, campaigns, campaign profiles and software profiles) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/group_profiles.jsonl | 2026-11-12 | Confirmed |
| 110 | TeamStarWolf library, main branch, `mitre/techniques/` | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/techniques | 2026-11-12 | Demonstrated |
| 111 | TeamStarWolf library, main branch, `navigator/library-layers/` | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-12 | Demonstrated |
| 112 | TeamStarWolf library, `case-studies/MITNICK_INTRUSIONS.md` (Part 4 mappings) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/case-studies/MITNICK_INTRUSIONS.md | 2026-11-12 | Demonstrated |
| 113 | TeamStarWolf library, case-studies/ on main (search for Rome Laboratory, Clipper, CALEA, Ames; DOTCOM_ERA_CYBER_EVENTS.md 1994 rows) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/case-studies | 2026-11-12 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md)
- Home studies: [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [Cybercrime and Hacktivism in Four Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [The Cuckoo's Egg Intrusion](/case-studies/CUCKOOS_EGG_1986.md) (an earlier intrusion into US military and research networks); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md)
- Series: [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1110.002 Password Cracking](/mitre/techniques/T1110-002.md), [T1090.003 Multi-hop Proxy](/mitre/techniques/T1090-003.md), [T1595 Active Scanning](/mitre/techniques/T1595.md), [T1005 Data from Local System](/mitre/techniques/T1005.md), [T1195.002 Compromise Software Supply Chain](/mitre/techniques/T1195-002.md), [T1554 Compromise Host Software Binary](/mitre/techniques/T1554.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1563 Remote Service Session Hijacking](/mitre/techniques/T1563.md), [T1547.006 Kernel Modules and Extensions](/mitre/techniques/T1547-006.md), [T1542.003 Bootkit](/mitre/techniques/T1542-003.md), [T1027.014 Polymorphic Code](/mitre/techniques/T1027-014.md)
- CAPEC: [CAPEC-158](/mitre/capec/CAPEC-158.md), [CAPEC-642](/mitre/capec/CAPEC-642.md), [CAPEC-145](/mitre/capec/CAPEC-145.md), [CAPEC-442](/mitre/capec/CAPEC-442.md), [CAPEC-88](/mitre/capec/CAPEC-88.md), [CAPEC-593](/mitre/capec/CAPEC-593.md)
- Groups, software and campaigns: none bound for 1994 (Part 9)
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-1994.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1994.json)
