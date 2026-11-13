# The Year 1998 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source opened on 12 or 13 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md) · Home studies for events summarized here: [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Solar Sunrise, Moonlight Maze, the L0pht hearing, Back Orifice, PDD-63 and CIH), [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md) (the May 1998 appeal), [The Cybercrime Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Max Butler's June 1998 BIND worm) and [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Turla's record) · Series: [The Year 1996 in Intrusions](/case-studies/CHRONICLE_1996.md), [The Year 1997 in Intrusions](/case-studies/CHRONICLE_1997.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 62 min (14,341 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 1998, you need the year's CERT advisories and incident notes, mscan and the scripted mountd attacks, Back Orifice and CIH side by side with Solar Sunrise, Moonlight Maze and the government's answer, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 10: the defender view](#part-10-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md), [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

For anyone who ran a Unix or Linux server in 1998, the year's threat was a script, not a person (Inferred). CERT/CC's incident notes trace the shift through the year. In May intruders swept TCP port 1 looking for IRIX machines and logged in to default accounts that had no passwords (Confirmed [2]). In late June a multi-vulnerability scanner was released in public and was soon in widespread use; CERT later named it mscan and said it was used against a large number of sites in the second half of 1998 (Confirmed [2][3]). In July one compromised host held 186,126 accounts with encrypted passwords collected from other sites, and the intruder had already cracked 47,642 of them (Confirmed [2]). In December CERT described scripted tools that scanned for the portmapper, picked out Linux hosts, exploited the NFS mountd flaw advised in October, added a passwordless privileged account and logged each host they took (Confirmed [2]).

CERT/CC issued 13 advisories in 1998, CA-1998-01 to CA-1998-13, and seven incident notes, IN-98.01 to IN-98-07 (Confirmed [1][2]). Five advisory titles name a buffer overflow: NIS+, POP, IMAP, MIME-aware mail and news clients, and mountd (Confirmed [1]). CERT recorded exploitation in the wild for qpopper in July, for the ToolTalk database server in September and for mountd in October, and the year opened and closed with denial of service: continuing smurf floods amplified through broadcast addresses in January, and crafted packets that crash BSD-derived TCP/IP stacks in December (Confirmed [1]). Microsoft's numbered bulletins for the year run from MS98-001 on 1 June to MS98-020 on 23 December, twenty in all (Confirmed [13]; Demonstrated [13]).

The state record holds an attribution scare and a campaign nobody yet understood. Solar Sunrise, the February intrusions into unclassified Defense systems, came while the United States prepared for possible action against Iraq, and within weeks the Justice Department announced the arrest of an Israeli citizen and searches of the homes of two California teenagers (Confirmed [27]); GlobalSecurity.org describes the Israeli as a teenager (Reported [31]). The Justice Department said there was no indication of an organized military or state-sponsored campaign (Confirmed [27]). Moonlight Maze ran through the year: the FBI investigation began in July under that code name, and a compromised UK server used as a relay was turned into a monitoring point for about six months, until the operators left after the first publicity in early March 1999 (Reported [73]; Confirmed [72]). The government also built its answer: the Attorney General unveiled the National Infrastructure Protection Center on 27 February, the Senate heard seven L0pht members on 19 May, and PDD-63 set the critical infrastructure structure on 22 May (Confirmed [28][35][38]).

Two pieces of research changed defense for decades (Inferred). Daniel Bleichenbacher's chosen-ciphertext attack on PKCS #1 produced a CERT advisory and a Microsoft bulletin on the same day, 26 June, then a revised PKCS #1 in October and a countermeasure written into TLS 1.0 in January 1999 (Confirmed [1][14][63][65]). StackGuard was presented at the 7th USENIX Security Symposium (Confirmed [67]); this study reads it as the origin of the stack canary (Inferred). The year also produced a dense legal record: the DMCA, the Identity Theft and Assumption Deterrence Act, the Children's Online Privacy Protection Act, the UK Data Protection Act 1998 and UN General Assembly resolution 53/70 on information and telecommunications in the context of international security (Confirmed [47][48][46][50][60]).

This study is the dated record of that year, built only from sources opened on 12 and 13 November 2026. Ten parts cover the timeline, the advisory record, scanning and mass exploitation, malware and remote access tools, the state record, crime and prosecutions, law and policy, cryptography, standards and defender research, and the defender view; an eleventh maps the record to MITRE frameworks.

None of today's shared identifier systems (CVE, CWE, CAPEC, ATT&CK) existed in 1998. The CVE white paper is dated 8 January 1999 and the List launched in September 1999; the first CWE release came in 2006, CAPEC in 2007, and MITRE started ATT&CK in 2013 (Confirmed [78][79][80][81][82]). The year's own identifiers are CERT advisory and incident note numbers and Microsoft bulletin numbers. Every 1998 flaw this study pairs with a CVE carries a CVE-1999 id assigned later, and every ATT&CK id in Part 11 is this study's later mapping (Confirmed [4]; Inferred).

Evidence grade: CERT/CC advisories and incident notes, vendor bulletins and virus descriptions, CVE and NVD records, statutes, Federal Register rules, court opinions, Justice Department releases, White House directives and fact sheets, GAO reports, congressional records, international texts, NIST and RFC Editor records, the researchers' and tool authors' own publications, MITRE's own pages and the library's data files are **Confirmed**. Facts that rest on newspapers, GlobalSecurity.org, a vendor's estimate or a researcher's relay of an investigation it did not run are **Reported** and attributed. A query or file check this study ran itself is **Demonstrated**. Where the study draws its own conclusion it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 1998, plus boundary records that open or close a 1998 event (the 1996 start of Moonlight Maze, the 1999 CERT incident notes, TLS 1.0 and the CVE launch, the 2001 sentences, the 2017 Moonlight Maze research) |
| CERT/CC output | 13 advisories, CA-1998-01 (5 Jan) to CA-1998-13 (21 Dec); 7 incident notes, IN-98.01 (13 May) to IN-98-07 (22 Dec) (Confirmed [1][2]) |
| Exploited in the wild, per CERT | qpopper (14 Jul), ToolTalk rpc.ttdbserverd (3 Sep, reprinting NAI-29 of 31 Aug), NFS mountd (12 Oct); smurf floods continuing (5 Jan) (Confirmed [1]) |
| Mass exploitation | IRIX default-account sweeps (May), mscan (from late June), a 186,126-account password haul (Jul), scripted mountd attacks (Dec) (Confirmed [2][3]) |
| Microsoft | Twenty numbered bulletins, MS98-001 (1 Jun) to MS98-020 (23 Dec); MS98-010 on Back Orifice (4 Aug) (Confirmed [13][19]; Demonstrated [13]) |
| Malware and tools | CIH found in Taiwan (early Jun); Marburg on magazine cover CDs (Jul to Aug); Back Orifice released at DEF CON VI (1 Aug); Remote Explorer on Windows NT (22 Dec) (Confirmed [25][26][22][2]) |
| State record | Solar Sunrise (1 to 26 Feb) and the Tenenbaum arrest (18 Mar); Moonlight Maze investigation named (Jul) and relay monitored (late 1998 to Mar 1999) (Confirmed [27][72]; Reported [31][73]) |
| Government response | NIPC unveiled (27 Feb); L0pht hearing (19 May); PDD-62 and PDD-63 (22 May); GAO finds weaknesses at all 24 largest agencies (23 Sep) (Confirmed [28][35][38][40][41]) |
| Law | Y2K disclosure act (19 Oct); COPPA and GPEA (21 Oct); DMCA (28 Oct); ITADA (30 Oct); UK Data Protection Act (16 Jul); UN resolution 53/70 (4 Dec) (Confirmed [49][46][47][48][50][60]) |
| Cryptography | Bleichenbacher's PKCS #1 attack (26 Jun advisories); EFF DES Cracker (17 Jul release); 15 AES candidates (20 Aug); 56-bit export easing (31 Dec rule) (Confirmed [1][14][51][53][55]) |
| Standards and research | RFC 2267 ingress filtering (Jan); RFC 2350 (Jun); RFC 2437 (Oct); RFC 2401 IPsec (Nov); SP 800-18 (Dec); StackGuard; the DARPA intrusion detection evaluation (Feb to Dec) (Confirmed [61][62][63][64][66][67][68]) |
| This study's MITRE binding | 29 ATT&CK Enterprise technique rows, every one a later mapping; no ICS row; no group, software or campaign object bound; 16 CWE ids; 13 CAPEC entries; D3FEND pairings from the library's data; one Navigator layer (Part 11) |

### Key findings

- **Automation was the year's volume story.** CERT's incident notes move from manual default-account logins in May to a public multi-vulnerability scanner in June and fully scripted scan, exploit and backdoor runs in December (Confirmed [2][3]). Each step cut the time between an advisory and mass compromise (Inferred).
- **Network daemons that ran as root were the way in.** BIND, NIS+, qpopper, IMAP, ToolTalk and mountd each gave remote privileged access in 1998, and three of them were exploited in the wild by CERT's own account (Confirmed [1]).
- **The state attack that was not.** Solar Sunrise looked like a state operation during an Iraq crisis. Within weeks DOJ announced an arrest in Israel and searches of two California teenagers' homes, and said there was no indication of state sponsorship (Confirmed [27]); GlobalSecurity.org names the attackers as two California teenagers and one Israeli teenager (Reported [31]).
- **The state operation nobody saw whole.** Moonlight Maze is known mostly through one administrator's preserved relay logs, analysed by researchers in 2017, and those researchers call a link to Turla premature (Confirmed [72]; Reported [73]).
- **A remote access tool started a threat-model argument.** cDc released Back Orifice as a Windows remote control with keystroke logging and screen capture; Microsoft's bulletin said it exploited no Windows flaw and needed the user to install it (Confirmed [22][23][19]).
- **Supply chains carried malware.** CIH spread through pirated software and later through commercial channels, and Marburg reached users on magazine cover CDs and a game's master CD (Confirmed [25][26]).
- **The best-documented breaches were authorized tests.** GAO's own testers reached sensitive State Department data, and the HHS Inspector General showed Medicare managed care production files could be modified (Confirmed [43][41]).
- **Cryptography was broken in public and repaired in standards.** Bleichenbacher's oracle reached RFC 2437 and TLS 1.0, and EFF's DES Cracker preceded the US easing of 56-bit exports by months (Confirmed [63][65][51][55]).

### Top recommendations

1. **Stop amplifiers and spoofed traffic at every router.** CA-1998-01 told sites to disable IP-directed broadcasts on every router, not only at the edge, and to apply ingress filtering as RFC 2267 describes (Confirmed [1][61]).
2. **Patch or disable network services that run as root.** BIND, NIS+, qpopper, IMAP, ToolTalk and mountd each had a remote root flaw in one year; the services a host does not need are the cheapest to fix (Confirmed [1]; Inferred).
3. **Remove default accounts or give them passwords.** IN-98.01's automated logins worked only because guest, lp and demos had no passwords (Confirmed [2]).
4. **Assume collected password files will be cracked.** A single compromised host held 186,126 accounts and more than a quarter were already cracked; strong password policy and one-time passwords limit the haul (Confirmed [2]; Inferred).
5. **Do not let an error message become an oracle.** RFC 2437 recommends OAEP for new applications, and TLS 1.0 tells servers to behave the same whether or not the RSA block is correctly formatted (Confirmed [63][65]).
6. **Build overflow defenses into the compiler.** StackGuard detected and stopped stack-smashing attacks with little performance cost and no source changes (Confirmed [67]).
7. **Control what users can install and what can call out.** MS98-010 advised signed software, blocking unsigned programs at the proxy or firewall, and auditing (Confirmed [19]).
8. **Verify software that arrives on trusted media.** CIH shipped on cover CDs and a firmware updater, and Marburg on a game master CD (Confirmed [25][26]).
9. **Publish how incidents reach you.** RFC 2350 gives a response team a template for its charter, policies, contacts and services (Confirmed [62]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, cryptography, standards and policy dated to 1998, plus the later records that open, close or explain a 1998 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every event graded, numbers as the source states them.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record (a CERT/CC advisory or incident note as SEI publishes it, a vendor bulletin or virus description, a CVE or NVD record, a statute, a Federal Register rule, a court opinion, a Justice Department release, a White House directive or fact sheet, a GAO report, a congressional page, an international text, a NIST or RFC Editor record, the researcher's or tool author's own publication, a live ATT&CK page, or the library's data files as the record of what the library holds) was opened on 12 or 13 November 2026 and states the fact |
| Reported | Only a secondary source was opened: the Los Angeles Times, The Register, GlobalSecurity.org, a vendor's estimate, or researchers relaying an investigation they did not run. The source is named in the text |
| Demonstrated | This study ran the query or opened the data itself and saw the result (the Microsoft bulletin probe, the CVE Services record dates, the library's data files and page tree) |
| Inferred | The study's own reasoning, labelled where it appears. Every MITRE id bound to a 1998 event is Inferred as to the binding |

Limits a reader should know:

- **No contemporaneous CVE, no ATT&CK.** No 1998 record carries a CVE id or an ATT&CK id. The 1998 advisories carry CVE-1999 ids assigned in 1999, and NVD back-dates their published field to the advisory dates: CVE-1999-0513 (smurf) reads 1998-01-05 and CVE-1999-0002 (mountd) reads 1998-10-12 (Confirmed [4][9]). The CVE record itself can show a different date (Part 2).
- **The CERT text.** SEI's compilations "1998 CERT Advisories" and "1998 CERT Incident Notes" are the texts for every CA-1998 and IN-98 item cited here [1][2]. CERT/CC's 1998 annual report and its incident statistics were not opened, so this study gives no 1998 incident count.
- **Microsoft's count.** The twenty bulletins are counted from Microsoft Learn: MS98-001 and MS98-020 were opened, and MS98-021 returns 404 (Demonstrated [13]).
- **The press record.** The Los Angeles Times, The Register and GlobalSecurity.org carry the Solar Sunrise details beyond DOJ's release and the later Tenenbaum and Butler sentences; those rows are Reported [31][32][33][34].
- **What was not found.** No 1998 consumer data breach or card compromise could be confirmed from a primary opened for this study (Inferred [41]). Events for which no source was opened are left out; their absence here is not evidence that nothing happened.
- **People.** Named people are those whom an opened source names in a court, prosecution, policy or research role, or who published under their own name or handle. The two California teenagers are not named.
- **Home studies.** Solar Sunrise (section 2.3), Moonlight Maze (2.4), the L0pht hearing (2.5), Back Orifice (2.6), CIH (3.1) and PDD-63 (5.3) live in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); the Ninth Circuit's 20 May 1998 ruling in the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md); Max Butler's June 1998 worm in the [cybercrime books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Confirmed [89][91]; Reported [90]). Each is summarized here in a paragraph and linked. This chronicle is the home for the rest of the 1998 record below.
- **Tradecraft is described at advisory level.** Advisory names, affected products and impact, and technique names and ids. The 1998 advisories and the Phrack article carry patch checks, filter rules and attack details; none is reproduced here.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1996-10 to 1999 (frame) | Moonlight Maze intrusions, detected from October 1996 in the researchers' timeline, run through 1998 against military, NASA and Department of Energy networks. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Espionage | Reported | [73] |
| 1998-01 | RFC 2267, Network Ingress Filtering: drop forged-source packets at the edge, aimed at SYN floods and ICMP broadcast (smurf) floods | Standards | Confirmed | [61] |
| 1998-01-05 | CA-1998-01: NSPs, ISPs and other sites report continuing smurf attacks, forged ICMP echo requests to broadcast addresses causing congestion or outages; attacks continuing from late 1997 | Availability, telecom | Confirmed | [1][4] |
| 1998-01-21 | CA-1998-02: CDE dtappgather lets a local user gain privileged access or deny service | Vulnerability | Confirmed | [1] |
| 1998-01-22 | CA-1998-03: ssh-agent, reprinting Secure Networks advisory SNI-23 of 20 January | Vulnerability | Confirmed | [1] |
| 1998-02 to 1998-12 | 1998 DARPA Intrusion Detection Evaluation at MIT Lincoln Laboratory: sample data in February, guidelines in March, a four-hour subset in May, results talks in December | Defender research | Confirmed | [68] |
| 1998-02-01 to 26 | Solar Sunrise: at least eleven attacks on Air Force, Navy and Marine Corps unclassified systems through a well-known operating-system flaw, with a probe, exploit, sniffer, return-to-collect profile. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Defense | Reported | [31] |
| 1998-02-06 | CA-1998-04: files protected only by the web server reachable through long file names on Windows-based web servers | Vulnerability, web | Confirmed | [1] |
| 1998-02-27 | Attorney General Reno unveils the National Infrastructure Protection Center (NIPC) at Lawrence Livermore National Laboratory; DOJ asks Congress for $64 million more | Policy | Confirmed | [28] |
| 1998-03-18 | DOJ 98-125: the Israeli National Police arrest Ehud Tenenbaum (DOJ spells it Tenebaum); no classified information compromised; no indication of a state-sponsored campaign; FBI searches two California teenagers' homes | Defense, law enforcement | Confirmed | [27] |
| 1998-04 | HHS Inspector General finds that auditors could reach the HCFA (Medicare) mainframe database and modify managed care production files, as GAO relays it | Healthcare, government | Confirmed | [41] |
| 1998-04-08 | CA-1998-05: three BIND problems, including an inverse query overrun in BIND 4.9 and BIND 8 that gives a remote intruder root on the name server | Vulnerability, DNS | Confirmed | [1][5] |
| 1998-04-27 | Los Angeles Times: Deputy Defense Secretary John Hamre called the February intrusions the "most organized and systematic attack" to date on Pentagon systems | Defense | Reported | [32] |
| 1998-05-01 | GAO/AIMD-98-68, executive guide on information security management drawn from leading organizations | Government | Confirmed | [44] |
| 1998-05-13 | IN-98.01: widespread scans of TCP port 1 hunting IRIX hosts, automated logins to unpassworded default accounts and more IRIX root compromises | Scanning | Confirmed | [2] |
| 1998-05-17 | G8 Birmingham communique commits to rapid implementation of the ten principles and ten-point action plan on high-tech crime | Policy, international | Confirmed | [58] |
| 1998-05-18 | GAO/AIMD-98-155 finds FAA ineffective in every critical computer security area reviewed for air traffic control; GAO/AIMD-98-145 reports GAO's penetration tests reached sensitive State Department data | Government, aviation | Confirmed | [42][43] |
| 1998-05-19 | Senate Governmental Affairs hearing "Weak Computer Security in Government: Is the Public at Risk?" with seven L0pht members and Peter G. Neumann. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Policy | Confirmed | [35][36] |
| 1998-05-20 | Ninth Circuit affirms Kevin Mitnick's sentence and supervised-release conditions. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Courts | Confirmed | [37] |
| 1998-05-20 | WTO Declaration on Global Electronic Commerce: a work programme and no customs duties on electronic transmissions | Policy, international | Confirmed | [59] |
| 1998-05-22 | PDD-63, Critical Infrastructure Protection, and PDD-62 on unconventional threats to the homeland | Policy | Confirmed | [38][39][40] |
| 1998-06 | FTC "Privacy Online: A Report to Congress": upward of 85 percent of sites surveyed collect personal information, 14 percent of a random sample give any notice | Privacy | Confirmed | [45] |
| 1998-06 | RFC 2350 / BCP 21, Expectations for Computer Security Incident Response | Standards | Confirmed | [62] |
| 1998-06 (early) | CIH first found in Taiwan, then worldwide through pirated software | Malware | Confirmed | [25] |
| 1998-06 | Max Butler launches a strain of the ADM BIND worm that closed the hole and left a back door on hundreds of military and defense contractor systems. Home: [cybercrime books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Crime, defense | Reported | [34][90] |
| 1998-06-01 | MS98-001: Windows NT lets non-administrators create local groups on a domain; the first bulletin of the MS98 series | Vendor | Confirmed | [13] |
| 1998-06-09 | CA-1998-06: buffer overflow in NIS+ rpc.nisd, reported by Internet Security Systems | Vulnerability | Confirmed | [1][7] |
| 1998-06-26 | CA-1998-07: a PKCS #1 flaw lets a sophisticated intruder recover information from SSL sessions; MS98-002 the same day credits Daniel Bleichenbacher of Bell Labs | Vulnerability, cryptography | Confirmed | [1][14] |
| 1998-07 | FBI investigation begins under the code name MOONLIGHT MAZE, in the researchers' timeline | Espionage | Reported | [73] |
| 1998-07 | Marburg virus on the July PC Gamer UK cover CD | Malware, supply chain | Confirmed | [26] |
| 1998-07-01 | DOJ Antitrust Division approves Securities Industry Association members' exchange of Year 2000 information | Y2K | Confirmed | [30] |
| 1998-07-02 | IN-98.02: a scanning tool released the week before is in widespread intruder use; MS98-003: web clients can read NTFS file contents on IIS | Scanning, web | Confirmed | [2][15] |
| 1998-07-14 | CA-1998-08: qpopper overflows exploited for privileged access; MS98-004: RDS DataFactory in IIS 4.0 opens OLE DB data sources to Internet clients | Vulnerability, mail, web | Confirmed | [1][16] |
| 1998-07-16 | IN-98.03: a compromised host holds 186,126 accounts with encrypted passwords, 47,642 cracked | Credentials | Confirmed | [2] |
| 1998-07-16 | UK Data Protection Act 1998 | Law, UK | Confirmed | [50] |
| 1998-07-17 | EFF releases its account of the DES Cracker winning RSA's DES Challenge II in under three days | Cryptography | Confirmed | [51] |
| 1998-07-20 | CA-1998-09: overflow in IMAP servers built on University of Washington code that handles SASL authentication | Vulnerability, mail | Confirmed | [1][8] |
| 1998-07-21 | cDc announces Back Orifice by Sir Dystic for DEF CON VI | Malware, tools | Confirmed | [22] |
| 1998-07-27 | MS98-008: long attachment file names in Microsoft mail clients; MS98-009: NT privilege elevation exploited by the published sechole program | Vendor | Confirmed | [17][18] |
| 1998-08-01 | Back Orifice released at DEF CON VI, Las Vegas. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Malware, tools | Confirmed | [22][23] |
| 1998-08-04 | MS98-010: Microsoft says Back Orifice exploits no Windows security issue (updated 12 Aug) | Vendor | Confirmed | [19] |
| 1998-08-11 | CA-1998-10: buffer overflow in MIME-aware mail and news clients; no successful exploitation reported at publication | Vulnerability, mail | Confirmed | [1] |
| 1998-08-12 | HHS proposes HIPAA Security and Electronic Signature Standards; MGM issues a statement on Marburg on the WarGames master CD | Healthcare; malware | Confirmed | [56][26] |
| 1998-08-18 | MS98-012: fixes for several security issues in Microsoft's PPTP | Vendor | Confirmed | [20] |
| 1998-08-20 | NIST announces fifteen AES candidate algorithms | Cryptography | Confirmed | [53] |
| 1998-08-31 / 09-03 | NAI advisory 29, reprinted as CA-1998-11: ToolTalk rpc.ttdbserverd stack overflow gives remote root and is "being actively exploited" | Vulnerability | Confirmed | [1] |
| 1998-09-16 | The Administration's encryption policy update, announced; implemented by the 31 December rule | Cryptography | Confirmed | [55] |
| 1998-09-22 | BXA interim rule: non-recoverable encryption of any key length for banks and financial institutions in specified countries | Cryptography | Confirmed | [54] |
| 1998-09-23 | GAO/AIMD-98-92: significant weaknesses in each of the 24 largest federal agencies; GAO testifies the same day | Government | Confirmed | [41] |
| 1998-09-29 | IN-98.04: stealth and architecture-mapping scans; NSWC Dahlgren suggests coordinated intruders | Scanning, defense | Confirmed | [2] |
| 1998-10 | RFC 2437, PKCS #1 v2.0: OAEP recommended for new applications | Cryptography | Confirmed | [63] |
| 1998-10-12 | CA-1998-12: NFS mountd overflow, mainly on Linux; intruders actively compromising systems and scanning at scale | Vulnerability | Confirmed | [1][9] |
| 1998-10-19 | Year 2000 Information and Readiness Disclosure Act, Pub. L. 105-271 | Law, Y2K | Confirmed | [49] |
| 1998-10-21 | COPPA (Title XIII of Division C) and the Government Paperwork Elimination Act (Title XVII) in Pub. L. 105-277 | Law, privacy | Confirmed | [46] |
| 1998-10-23 | MS98-016: "Dotless IP Address" zone confusion in Internet Explorer 4, delivered to Windows 98 through Windows Update | Vendor | Confirmed | [21] |
| 1998-10-28 | Digital Millennium Copyright Act, Pub. L. 105-304 | Law | Confirmed | [47] |
| 1998-10-30 | Identity Theft and Assumption Deterrence Act, Pub. L. 105-318 | Law | Confirmed | [48] |
| 1998-11 | RFC 2401, Security Architecture for the Internet Protocol (IPsec) | Standards | Confirmed | [64] |
| 1998-11-24 | IN-98-05: IMAP probes with spoofed source addresses, the true origin often another compromised host on the same network | Scanning | Confirmed | [2] |
| late 1998 to 1999-03 | A UK Solaris server, HRTest, serves as a Moonlight Maze relay and is turned into a monitoring point with the Metropolitan Police and the FBI | Espionage | Confirmed | [72][73] |
| 1998-12 | NIST SP 800-18, Guide for Developing Security Plans for Information Technology Systems | Standards | Confirmed | [66] |
| 1998-12-04 | UN General Assembly resolution 53/70 on information and telecommunications in the context of international security | Policy, international | Confirmed | [60] |
| 1998-12-09 | IN-98-06: scripted tools scan TCP 111, fingerprint Linux, exploit mountd and leave a passwordless privileged account | Mass exploitation | Confirmed | [2] |
| 1998-12-15 | FIPS 186-1 approved as an interim final Digital Signature Standard allowing DSA and ANSI X9.31 (RSA) | Cryptography | Confirmed | [57] |
| 1998-12-17 | Operation Double Barrel: 795 people charged in a 30-month telemarketing fraud operation | Crime | Confirmed | [29] |
| 1998-12-21 | CA-1998-13: crafted packet sequences crash or hang some BSD-derived TCP/IP stacks | Availability | Confirmed | [1] |
| 1998-12-22 | IN-98-07: the Windows NT Remote Explorer (RICHS) virus | Malware | Confirmed | [2] |
| 1998-12-23 | MS98-020: Internet Explorer window spoofing, the year's last bulletin | Vendor | Confirmed | [13] |
| 1998-12-25 | Phrack 54, "NT Web Technology Vulnerabilities", describes appending SQL commands to database queries through web input | Attack knowledge | Confirmed | [71] |
| 1998-12-31 | BXA interim rule allows 56-bit DES-equivalent exports under License Exception ENC to all but seven destinations | Cryptography | Confirmed | [55] |
| 1998 (USENIX Security) | StackGuard presented at the 7th USENIX Security Symposium, San Antonio | Defender research | Confirmed | [67] |
| 1998 (CRYPTO '98) | Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1" | Cryptography | Confirmed | [69] |
| 1999-01 (boundary) | RFC 2246, TLS 1.0, cites Bleichenbacher and specifies the countermeasure | Standards | Confirmed | [65] |
| 1999-01-08 (boundary) | Mann and Christey, "Towards a Common Enumeration of Vulnerabilities" | Vulnerability naming | Confirmed | [78] |
| 1999-01-28 (boundary) | IN-99-01 names the IN-98.02 tool as mscan | Scanning | Confirmed | [3] |
| 1999-02 (boundary) | Tenenbaum indicted under Israeli computer crime law | Courts | Reported | [33] |
| 1999-03 (boundary) | Moonlight Maze operators abandon the London relay after the first publicity | Espionage | Confirmed | [72] |
| 1999-04-22 (boundary) | IN-99-03: CERT's first record of CIH | Malware | Confirmed | [3] |
| 2001-05-21 and 2001-06 (boundary) | Butler sentenced to 18 months; Tenenbaum sentenced in Israel | Courts | Reported | [34][33] |

## Part 2: the vulnerability record

### The 13 advisories

CERT/CC issued 13 advisories in its 1998 series (Confirmed [1]). The "Later CVE" column gives the NVD record that matches each advisory by date or description; the pairing is this study's unless NVD links the advisory or a bulletin itself (Confirmed [4][5][7][8][9][10]; Inferred [6]).

| Advisory | Date | Product | Impact as CERT states it | Later CVE | Grade | Sources |
|---|---|---|---|---|---|---|
| CA-1998-01 | 5 Jan | IP networks (smurf) | Continuing denial-of-service attacks using forged ICMP echo requests sent to IP broadcast addresses, amplified through intermediary networks; congestion or outages at NSPs, ISPs and other sites. Disable IP-directed broadcasts on every router and apply RFC 2267 ingress filtering | CVE-1999-0513 (NVD published 1998-01-05) | Confirmed | [1][4] |
| CA-1998-02 | 21 Jan | CDE dtappgather | A local user gains privileged access or causes denial of service | not paired here | Confirmed | [1] |
| CA-1998-03 | 22 Jan | ssh-agent | Reprint of Secure Networks advisory SNI-23 of 20 January | CVE-1999-0013 (CWE-522 in NVD), by description (Inferred) | Confirmed | [1][93] |
| CA-1998-04 | 6 Feb | Windows-based web servers | Files protected only by the web server reachable through long (non-8.3) file names; exploitation described on public mailing lists | CVE-1999-0012 (CWE-290 in NVD), by description (Inferred) | Confirmed | [1][93] |
| CA-1998-05 | 8 Apr | BIND 4.9 and BIND 8 | Inverse query buffer overrun gives a remote intruder root on the name server; two denial-of-service problems | CVE-1999-0009 (NVD published 1998-04-08); CVE-1999-0010 and -0011 for the denial-of-service issues, by description | Confirmed (records); Inferred (pairing) | [1][5][6] |
| CA-1998-06 | 9 Jun | NIS+ rpc.nisd | Buffer overflow, reported to CERT by Internet Security Systems | CVE-1999-0008 (NVD published 1998-06-08) | Confirmed | [1][7] |
| CA-1998-07 | 26 Jun | PKCS #1 in SSL implementations | A sophisticated intruder may recover information from SSL-encrypted sessions through repeated session attempts | CVE-1999-0007 (CWE-327 in NVD; references MS98-002) | Confirmed | [1][14][93] |
| CA-1998-08 | 14 Jul | qpopper-based POP servers | Buffer overflows give remote root; CERT had reports of incidents in which the flaw was exploited to gain privileged access | CVE-1999-0006, by description (Inferred) | Confirmed | [1][93] |
| CA-1998-09 | 20 Jul | IMAP servers using University of Washington code for SASL authentication | Buffer overflow | CVE-1999-0005 (NVD published 1998-07-20), by description | Confirmed | [1][8] |
| CA-1998-10 | 11 Aug | MIME-aware mail and news clients | Buffer overflow found by Marko Laakso and Ari Takanen of the University of Oulu Secure Programming Group; no reports of successful exploitation at publication | CVE-1999-0004 (NVD links MS98-008) | Confirmed | [1][17][93] |
| CA-1998-11 | 3 Sep | ToolTalk rpc.ttdbserverd on CDE systems | Reprint of NAI advisory 29 of 31 August: stack overflow gives remote superuser code execution and "is being actively exploited by attackers on the Internet" | CVE-1999-0003 (NVD published date reads 1998-04-01; see Discrepancies) | Confirmed (records); Inferred (pairing) | [1][10] |
| CA-1998-12 | 12 Oct | NFS mountd, mainly Linux | Remote root without an account; intruders actively using it and running large-scale scans | CVE-1999-0002 (CWE-119 in NVD; NVD published 1998-10-12) | Confirmed | [1][9][11] |
| CA-1998-13 | 21 Dec | Some BSD-derived TCP/IP stacks | Crafted packet sequences crash or hang systems; no access needed; source spoofing hides the origin and broadcast widens the effect; compared to Teardrop and Land (CA-97.28) | CVE-1999-0001 (CWE-20 in NVD), by description (Inferred) | Confirmed | [1][93] |

### What the advisories say about attackers

Read in order, the advisories fall into three groups (Inferred). Network daemons that run with root privileges, BIND, NIS+, qpopper, IMAP, ToolTalk and mountd, give remote privileged access, and CERT records exploitation for three of them (Confirmed [1]). Client and protocol flaws, the MIME overflow and the PKCS #1 oracle, needed a victim to read mail or an attacker to run many sessions, and CERT had no reports of successful exploitation of the MIME flaw at publication (Confirmed [1]). Availability attacks frame the year: smurf at the start, BSD stack crashes at the end (Confirmed [1]). Read as a set, the advice comes down to installing vendor patches and, where none exists, turning the service off or filtering it (Inferred [1]).

### Microsoft's first numbered year

Microsoft's numbered bulletins begin with MS98-001 on 1 June 1998, a Windows NT default that let non-administrative users create local groups on a domain, and run to MS98-020 on 23 December, an Internet Explorer window spoofing flaw; MS98-021 returns 404 on Microsoft Learn (Confirmed [13]; Demonstrated [13]). That MS98-001 opens the numbered series is this study's reading of the numbering (Inferred). The bulletins opened for this study:

| Bulletin | Date | Subject | Note | Sources |
|---|---|---|---|---|
| MS98-001 | 1 Jun | Non-administrative creation of local groups on a domain | First of the numbered series | [13] |
| MS98-002 | 26 Jun | SSL "error message" vulnerability in secured internet servers | Credits Daniel Bleichenbacher of Bell Labs, notified through RSA; same day as CA-1998-07; CVE-1999-0007 | [14] |
| MS98-003 | 2 Jul | Web clients can read the contents of NTFS files on IIS | Reported by Paul Ashton on NTBugtraq; later CVE-1999-0278 | [15][12] |
| MS98-004 | 14 Jul | RDS DataFactory in MDAC, installed by default with IIS 4.0, lets Internet clients reach OLE DB data sources | CERT IN-99-08 (December 1999) later reported IIS servers compromised through it and said it was discussed as early as 22 April 1998; later CVE-1999-1011 | [16][3][12] |
| MS98-008 | 27 Jul | Long attachment file names in Microsoft mail clients | Reported by AUSCERT, OUSPG and NTBugtraq; CVE-1999-0004 | [17] |
| MS98-009 | 27 Jul | Windows NT privilege elevation | Exploited by the sechole program published on the Internet | [18] |
| MS98-010 | 4 Aug (updated 12 Aug) | Back Orifice | Says it exposes no Windows security issue (Part 4) | [19] |
| MS98-012 | 18 Aug | Several security issues in Microsoft's PPTP | Patches | [20] |
| MS98-016 | 23 Oct | "Dotless IP Address" zone confusion in Internet Explorer 4 | Delivered to Windows 98 through Windows Update Critical Updates; later CVE-1999-1087 | [21] |
| MS98-020 | 23 Dec | Internet Explorer window spoofing | Last bulletin of the year | [13] |

The 1998 bulletins mark two changes in how fixes reached users (Inferred). The PKCS #1 bulletin shipped the same day as CERT's advisory, an early coordinated disclosure, and MS98-016 was delivered to Windows 98 users through Windows Update Critical Updates (Confirmed [1][14][21]).

### The later CVE record

CVE did not exist in 1998, and its own founding paper describes why it was needed: Mann and Christey's white paper of 8 January 1999 says scanners and intrusion detection systems inside MITRE named the same flaw differently (Confirmed [78]). The paper went to the 2nd Workshop on Research with Security Vulnerability Databases at Purdue on 21 to 22 January 1999, the List started with 321 records and launched publicly in September 1999, and by December 2000 29 organizations had declared compatibility for 43 products (Confirmed [79]). The 1998 flaws therefore carry CVE-1999 ids. Two dating systems coexist: NVD back-dates its published field to the advisory date (CVE-1999-0513 reads 5 January 1998, CVE-1999-0009 8 April, CVE-1999-0008 8 June, CVE-1999-0005 20 July, CVE-1999-0002 12 October), while the CVE Services records for CVE-1999-0007 and CVE-1999-0278 show 29 September 1999, the month the List launched, and CVE-1999-1011 shows 2 June 2000 (Confirmed [4][5][7][8][9]; Demonstrated [12]). MS98-016's CVE-1999-1087 record was published on 9 March 2002 (Confirmed [21]). A count of "1998 CVEs" by any one of these dates measures the database, not the year (Inferred).

## Part 3: scanning and mass exploitation

CERT/CC's seven 1998 incident notes are the year's record of what intruders did at scale, and read together they show the step from manual work to scripts (Confirmed [2]; Inferred).

| Note | Date | What CERT reported | Grade | Sources |
|---|---|---|---|---|
| IN-98.01 | 13 May | Over the preceding couple of weeks, widespread scans of TCP port 1 (tcpmux), some from root-compromised sites, hunting IRIX machines; automated logins to the unpassworded default accounts guest, lp and demos; more IRIX root compromises | Confirmed | [2] |
| IN-98.02 | 2 Jul | A new tool released the previous week scans through DNS zone transfers or brute-force IP ranges and tests statd, imap and pop, IRIX passwordless accounts, BIND and cgi-bin flaws; numerous reports of widespread use. IN-99-01 later names it mscan and says it was widely used against a large number of sites in the second half of 1998 | Confirmed | [2][3] |
| IN-98.03 | 16 Jul | A compromised system held 186,126 accounts with encrypted passwords, mostly gathered from other sites, 47,642 already guessed with a cracking tool, alongside passwords apparently captured by sniffing | Confirmed | [2] |
| IN-98.04 | 29 Sep | Stealth scanning (inverse mapping) and operating-system and architecture fingerprinting; the Naval Surface Warfare Center Dahlgren Division's information that multiple intruders may be acting in a coordinated effort | Confirmed | [2] |
| IN-98-05 | 24 Nov | IMAP-style probes with spoofed source addresses; the true origin often another compromised host on the same network, possibly sniffing the replies | Confirmed | [2] |
| IN-98-06 | 9 Dec | Scripted tools scan TCP 111, identify Linux hosts, exploit the mountd flaw of CA-1998-12, create a passwordless privileged account and log each compromised host | Confirmed | [2] |
| IN-98-07 | 22 Dec | The Windows NT Remote Explorer (RICHS) virus (Part 4) | Confirmed | [2] |

The pattern runs in one direction (Inferred). In May the scans found hosts and the logins used accounts nobody had locked. In June a single public tool tested several flaws at once. By December a script carried out every step of an intrusion that CERT's October advisory had described, from discovery to a persistent account, and kept a list of its successes (Confirmed [2][1]). CA-1998-12 already reported large-scale scanning for mountd two months before IN-98-06 described the full script (Confirmed [1]).

The July password haul shows what the scanners fed (Inferred). One host held credentials collected from many other sites, and more than one in four had already been cracked (Confirmed [2]). The library's pages on [T1110.002 Password Cracking](/mitre/techniques/T1110-002.md) and [T1040 Network Sniffing](/mitre/techniques/T1040.md) carry the later technique records for both halves of that haul.

### The worm that patched

Max Butler's June 1998 worm is, in this study's reading, the year's clearest case of mass exploitation by one person (Inferred). The Register reported in 2001 that he launched a strain of the ADM BIND worm that closed the BIND hole on each system it reached but left a secret back door, and that it crawled through hundreds of military and defense contractor computers over a few days; he was sentenced on 21 May 2001 to 18 months (Reported [34]). The [cybercrime books study](/case-studies/CYBERCRIME_FOUR_BOOKS.md) is the home for his story and grades it the same way (Reported [90]).

## Part 4: malware and remote access tools

### Back Orifice (summary)

Back Orifice is told in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), section 2.6 (Confirmed [89]). Cult of the Dead Cow's press release of 21 July 1998 announced that Back Orifice, by Sir Dystic, would be released at DEF CON VI in Las Vegas on 1 August, and described a remote tool for Windows that controls the file system, registry, passwords, network and processes, with screen and video capture, an HTTP server, a packet sniffer and keystroke logging (Confirmed [22]). cDc's tool page says the server installs itself, does not show in the task list, reruns at startup, can be attached to another Windows executable, logs keystrokes and retrieves cached passwords (Confirmed [23]). F-Secure says it was typically sent as an e-mail attachment and detects it as Trojan.Win32.BO (Confirmed [24]).

Microsoft's MS98-010, published 4 August and updated 12 August, took the position that Back Orifice exposes no security issue in Windows, Windows NT or BackOffice: the user must install it, the attacker must know the user's IP address and connect directly, a properly configured firewall defeats the connection, and it does not run on Windows NT Server (Confirmed [19]). The bulletin advised signed software, blocking unsigned programs at the proxy or firewall, and auditing, and listed keystroke capture, screen capture and remote file transfer among the claimed capabilities (Confirmed [19]). The argument between the two documents is about the threat model, not the facts: both describe a program that does what its operator asks once a user runs it (Inferred).

### CIH (summary)

CIH's home is the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), section 3.1, which dates it by its 1999 payload (Confirmed [89]). F-Secure records that CIH was first found in Taiwan in early June 1998 and spread worldwide through pirated software; it infects Windows 95 and 98 EXE files, overwrites hard-disk data and tries to overwrite the flash BIOS (Confirmed [25]). At least four warez groups were infected in the summer of 1998, and CIH later shipped through commercial channels: gaming-magazine cover CDs, an Origin Systems download, a Yamaha CD-R400 firmware updater and IBM Aptiva PCs in March 1999 (Confirmed [25]). CERT's own record begins only with IN-99-03 on 22 April 1999, which says some variants activate on 26 April 1999 and some on the 26th of every month, and that the payload tries to erase the hard drive and overwrite the system BIOS (Confirmed [3]). The year 1998 is when CIH spread; 1999 is when it struck (Inferred).

### Marburg

F-Secure records that the polymorphic Win95/Marburg virus reached users on the July 1998 PC Gamer UK cover CD, the PC Power Play (Australia) CD and the master CD of MGM's WarGames game, and that MGM issued a statement on 12 August 1998 (Confirmed [26]). With CIH, it is the year's evidence that trusted distribution media could carry malware to users who never visited a warez site (Inferred).

### Remote Explorer

CERT's IN-98-07 of 22 December described the Windows NT Remote Explorer (RICHS) virus: when run by a local administrator it can install itself as an NT service, impersonate later logons including domain administrators, and use those privileges to infect files across the network (Confirmed [2]). CERT had no first-hand reports, only one second-hand report of about 50 infected NT servers (Confirmed [2]).

### No ATT&CK software objects

The library's ATT&CK data holds no software object for Back Orifice, CIH, Marburg or Remote Explorer, so the tools are bound to techniques only (Confirmed [85]; Part 11).

## Part 5: the state record

### Solar Sunrise (summary)

Solar Sunrise's home is the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), section 2.3 (Confirmed [89]). GlobalSecurity.org describes attacks on Defense networks from 1 to 26 February 1998 through a well-known operating-system vulnerability, with at least eleven attacks following one profile (probe, exploit, implant a sniffer, return to collect) against Air Force, Navy and Marine Corps computers; the traffic appeared to come from Israel, the UAE, France, Taiwan and Germany, the attackers obtained hundreds of network passwords, and suspicion fell on Iraq, foreign intelligence services or nation states because the US was preparing for possible action against Iraq (Reported [31]). The same page says Solar Sunrise confirmed the findings of the Eligible Receiver exercise (no effective indications and warning, insufficient intrusion detection, threat identification a problem) and that DoD set up a 24-hour watch and installed intrusion detection on key nodes (Reported [31]).

The Justice Department's release of 18 March 1998 is the primary record. The Israeli National Police arrested Ehud Tenenbaum (DOJ spells it Tenebaum) for illegally accessing Israeli and US government computers and hundreds of commercial and educational systems, after several weeks of investigation into the February intrusions; the announcement was made with the FBI, AFOSI, NASA and NCIS (Confirmed [27]). DOJ said no classified information was compromised and there was no indication that the attacks were part of an organized military or state-sponsored campaign; FBI agents searched the homes of two California teenagers believed responsible for some of the intrusions (Confirmed [27]). DOJ formally asked the Israeli Ministry of Justice for legal assistance, US agents travelled to Israel with evidence, US investigators gave Israel evidence of crimes against Israeli systems, and CCIPS chief Scott Charney credited interagency cooperation (Confirmed [27]). GAO's September report relays the NSA Director's statement that the February attackers used tools readily available on Internet bulletin boards, and records that DOD announced in March that it had identified a series of organized intrusions (Confirmed [41]).

The press filled in the rest. The Los Angeles Times reported on 27 April that Deputy Defense Secretary John Hamre had called the intrusions the "most organized and systematic attack" to date on Pentagon systems, that the intruders entered unclassified networks including payroll and personnel databases over three weeks in February, that Tenenbaum was suspected of breaking into as many as 700 sites, and that he had not been charged (Reported [32]). The Register reported in 2001 that he was indicted under Israeli law in February 1999 and sentenced in June 2001 to six months of community service, a year of probation and a two-year suspended sentence, and that the California teenagers received probation (Reported [33]).

### Moonlight Maze (summary)

Moonlight Maze's home is the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), section 2.4 (Confirmed [89]). What is known in public comes mostly from Kaspersky GReAT and King's College London researchers, who analysed preserved logs and binaries from a UK Solaris relay named HRTest, spanning 1998 to 1999, with samples compiled as far back as late 1996 for SPARC Solaris and MIPS IRIX (Confirmed [72]). Working with the Metropolitan Police and the FBI, the server's administrator turned the relay into a monitoring point for about six months, until the attackers abandoned it after the first publicity in early March 1999 (Confirmed [72]).

The researchers' timeline puts the start of the FBI investigation under the code name MOONLIGHT MAZE in July 1998, with ABC revealing it in March 1999, an FBI task force travelling to Moscow in April 1999 and later code names STORM CLOUD and MAKERS MARK; by mid-1998, they say, FBI and DoD investigators had forensic evidence pointing to Russian ISPs (Reported [73]). The official record of the investigation was not opened. The victims they name include Wright-Patterson and Kelly Air Force Bases, the Army Research Lab, Naval Sea Systems Command at Indian Head, NASA and Department of Energy laboratories (Reported [73][72]).

The technical findings are the researchers' own work on recovered data (Confirmed [73]). Two files taken from the US Navy through the London relay in 1998 showed satellite tracks used for oceanic research. The operators built sniffers from tcpdump, libpcap and a 1994 rootkit called solsniffer, logging telnet, pop3, ftp and rlogin connections. The LOKI2 covert-channel backdoor, published in Phrack in 1996 and 1997, tunnels traffic through protocols such as ICMP; it received the most sustained development in the 1997 to 1999 samples, and the developers added a utmp log cleaner. The binaries borrowed code and exploits from forums and security mailing lists, and the operators relayed through hacked servers. The binaries also carry poor English, consistent use of the transliterated Russian word "vnuk", compile paths naming users Max, Iron and Rinat, and a client named spy_cli.c; the researchers read these as signs of espionage rather than hacking for fun, and that reading is theirs (Reported [73]).

Attribution stays open. The researchers say more hard technical evidence is needed to confirm that Moonlight Maze is Turla: they call the provenance likely, say one link is missing, which they believe is Storm Cloud, and cite a 2001 Wall Street Journal report that LOKI2 was at the base of Storm Cloud (Reported [73]). Their blog calls a Moonlight Maze to Turla conclusion "simply premature", describes Turla only as a Russian-speaking group and does not itself attribute Moonlight Maze to the Russian government (Confirmed [72]). ATT&CK's [Turla page (G0010)](/mitre/groups/G0010.md) attributes the group to Russia's FSB with victims since at least 2004, and its [Penquin page (S0587)](/mitre/software/S0587.md) dates that Linux RAT from at least 2014; neither mentions Moonlight Maze (Confirmed [75][76]). The [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) is the home for Turla's record.

### Equation: not placed in 1998

Kaspersky's February 2015 Equation Group Q&A says the group's operations date back to 2001 and perhaps as early as 1996, with EQUATIONLASER used around 2001 to 2004 on Windows 95 and 98; this is a vendor estimate, and it gives no dated 1998 operation (Reported [74]). ATT&CK's [Equation page (G0020)](/mitre/groups/G0020.md) gives no start year and no 1998 activity (Confirmed [77]). This study does not place Equation in 1998. Its record lives in the [United States study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) and the [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md).

### The government builds its answer

The NIPC came first. On 27 February 1998 Attorney General Reno unveiled the National Infrastructure Protection Center at Lawrence Livermore National Laboratory; DOJ described it as an outgrowth of the FBI's Computer Investigations and Infrastructure Threat Assessment Center, set up after the President's Commission on Critical Infrastructure Protection reported, to detect, prevent and respond to cyber and physical attacks on critical infrastructures, and asked Congress for $64 million in increased funding (Confirmed [28]).

The L0pht hearing came next (summary; home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), section 2.5). On 19 May 1998 the Senate Committee on Governmental Affairs held "Weak Computer Security in Government: Is the Public at Risk?" in 342 Dirksen, with seven L0pht Heavy Industries members listed by handle (Brian Oblivion, Kingpin, Mudge, Space Rogue, Stefan Von Neumann, Tan and Weld Pond) and Peter G. Neumann of SRI International (Confirmed [35]). Chairman Fred Thompson's prepared statement called it the first of a series of hearings on federal computer security, said the nation cannot wait for the "Pearl Harbor" of the information age, and described L0pht as a "hacker think tank" (Confirmed [36]).

PDD-63 came three days later (summary; home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), section 5.3). The directive, dated 22 May 1998, authorized the FBI to expand into a full-scale NIPC as the national threat assessment, warning, vulnerability and investigation entity, staffed by FBI and Secret Service investigators with representatives from DoD, the Intelligence Community and the lead agencies, sanitizing law enforcement and intelligence information for its reports; it set an initial operating capability no later than 2000 and full protective ability within five years (Confirmed [38]). The White House fact sheet adds a National Coordinator, private-sector Information Sharing and Analysis Centers modeled on the CDC, a National Infrastructure Assurance Council and a Critical Infrastructure Assurance Office, goals of increased security for government systems by 2000 and a secure information infrastructure by 2003, and reliance on voluntary private participation with privacy rights protected (Confirmed [39]). PDD-62, the same day, established the Office of the National Coordinator for Security, Infrastructure Protection and Counter-Terrorism within the NSC, and its fact sheet warns that adversaries may attack the economy and critical infrastructure using advanced computer technology (Confirmed [40]).

### The audit record

The year's best-documented compromises are authorized tests: GAO's penetration of State Department systems and the HHS Inspector General's Medicare tests, set beside GAO's audit findings (Inferred [41][43]).

| Report | Date | Finding | Grade | Sources |
|---|---|---|---|---|
| GAO/AIMD-98-68 | 1 May | Executive guide drawn from leading organizations; information security on GAO's high-risk list since February 1997; poor security program management an underlying cause of federal weaknesses | Confirmed | [44] |
| GAO/AIMD-98-155 | 18 May | FAA ineffective in all critical air traffic control computer security areas reviewed; an October 1996 assessment analyzed threats, vulnerabilities and safeguards for only 3 of 90 operational ATC systems, and only one of nine ATC telecommunications networks had been analyzed | Confirmed | [42] |
| GAO/AIMD-98-145 | 18 May | GAO's penetration tests reached sensitive information on State Department sensitive-but-unclassified systems, and GAO could have performed system administration actions; Internet security the only area with adequate controls; no regular penetration testing or central incident tracking | Confirmed | [43] |
| HHS Inspector General, as GAO relays it | April | Auditors could reach the HCFA (Medicare) mainframe database and modify managed care production files; contractor staff could potentially browse data on individuals | Confirmed | [41] |
| GAO/AIMD-98-92 and GAO/T-AIMD-98-312 | 23 Sep | Significant information security weaknesses in each of the 24 largest federal agencies, with inadequately restricted access to sensitive data the most common; many intrusions may be going undetected; a governmentwide strategy needed; testimony the same day before the Senate Committee on Governmental Affairs | Confirmed | [41] |

## Part 6: crime and prosecutions

### Kevin Mitnick (summary)

Mitnick's case is told in the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) (Confirmed [91]). On 20 May 1998 the Ninth Circuit (*United States v. Mitnick*, 145 F.3d 1342) affirmed his sentence on the 18 U.S.C. 1029(a)(3) plea and the supervised-release conditions restricting computers, computer-related equipment and cellular telephones, rejecting First Amendment and vagueness challenges (Confirmed [37]).

### Solar Sunrise and Max Butler

Two of the year's intrusion cases ended in sentences in 2001, as The Register reported: Tenenbaum's (Part 5) and Butler's (Part 3) (Reported [33][34]). The California teenagers' outcome is reported only as probation (Reported [33]).

### Fraud at scale

On 17 December 1998 the Justice Department announced Operation Double Barrel, a 30-month undercover operation coordinated by the FBI against telemarketing fraud, which charged 795 individuals in 218 federal criminal cases and 194 state cases (Confirmed [29]). It was not a computer case, and it is here because it is the year's largest fraud prosecution in the record opened and it was announced seven weeks after the identity theft law below was approved (Inferred).

### Identity theft becomes a federal crime

The Identity Theft and Assumption Deterrence Act of 1998, Public Law 105-318 (H.R. 4151), was approved on 30 October 1998 (Confirmed [48]). It added 18 U.S.C. 1028(a)(7), making it an offense to knowingly transfer or use, without lawful authority, another person's means of identification to commit unlawful activity, and it directed the Federal Trade Commission to set up within one year a central log of identity theft complaints, with information for victims and referrals (Confirmed [48]). The library's [e-commerce threats study](/case-studies/ECOMMERCE_THREATS.md) takes the payment and identity fraud story from 1999 (Inferred).

### Circumvention and research

The Digital Millennium Copyright Act, Public Law 105-304 (H.R. 2281), was approved on 28 October 1998 (Confirmed [47]). It added 17 U.S.C. 1201, which bars circumventing a technological protection measure, and 1204, criminal penalties (Confirmed [47]). Section 1201 carries exemptions for good-faith encryption research (1201(g)) and for security testing (1201(j)); security testing requires the authorization of the owner or operator, and the exemption does not shield violations of 18 U.S.C. 1030 (Confirmed [47]). The researchers who found the year's flaws worked under that line from then on (Inferred).

## Part 7: law, policy and privacy

### Privacy

The FTC's June 1998 report "Privacy Online: A Report to Congress" surveyed over 1,400 web sites (Confirmed [45]). Upward of 85 percent collected personal information, only 14 percent of a random sample gave any notice of their information practices and about 2 percent had a full privacy policy; 89 percent of children's sites collected personal information from children and 23 percent told children to seek parental permission, and the FTC recommended that Congress legislate to put parents in control (Confirmed [45]). The Children's Online Privacy Protection Act of 1998 was enacted as Title XIII of Division C of Public Law 105-277, signed on 21 October 1998, four months after the report (Confirmed [46]). The same law carried the Government Paperwork Elimination Act as Title XVII, with procedures for executive agencies to use and accept electronic signatures (Confirmed [46]).

In the United Kingdom, the Data Protection Act 1998 (1998 c. 29), an Act to regulate the processing of information relating to individuals, is dated 16 July 1998 (Confirmed [50]). In health care, HHS proposed the HIPAA Security and Electronic Signature Standards on 12 August 1998 for electronic individual health information held by health plans, clearinghouses and providers (Confirmed [56]).

### The Year 2000 problem

The Year 2000 Information and Readiness Disclosure Act, Public Law 105-271, approved on 19 October 1998, limits the use of Year 2000 readiness disclosures as evidence, grants a temporary antitrust exemption and sets up a national information clearinghouse; its findings say date failures could incapacitate markets, utilities, government, safety and defense systems (Confirmed [49]). On 1 July the Justice Department's Antitrust Division had approved the Securities Industry Association's plan for members and their computer services suppliers to exchange Year 2000 information (Confirmed [30]). The G8 Birmingham communique of 17 May committed leaders to urgent action and information sharing on the problem (Confirmed [58]).

### International

| Text | Date | Substance | Grade | Sources |
|---|---|---|---|---|
| G8 Birmingham communique | 17 May | Implement rapidly the ministers' ten principles and ten-point action plan on high-tech crime; work with industry on a legal framework for electronic evidence; urgent action on Year 2000 | Confirmed | [58] |
| WTO Declaration on Global Electronic Commerce, WT/MIN(98)/DEC/2 | 20 May | A work programme on trade-related electronic commerce; members continue not imposing customs duties on electronic transmissions | Confirmed | [59] |
| UN General Assembly resolution 53/70 | 4 Dec | Adopted at the 79th plenary meeting: member states to consider information security threats; views invited on definitions of unauthorized interference or misuse and on principles to combat information terrorism and criminality; the item placed on the 54th session agenda. Which state sponsored the draft was not checked | Confirmed | [60] |

## Part 8: cryptography

### Bleichenbacher's oracle

Daniel Bleichenbacher of Bell Labs showed at CRYPTO '98 that an oracle returning one bit, whether a ciphertext is PKCS #1 conformant, lets an attacker perform the RSA private-key operation; he named SSL 3.0 as susceptible, and his experiments needed between 300 thousand and 2 million queries (Confirmed [69]). CERT's CA-1998-07 and Microsoft's MS98-002 were published the same day, 26 June 1998, MS98-002 crediting Bleichenbacher and noting that RSA notified Microsoft (Confirmed [1][14]). The standards changed within months. RFC 2437, PKCS #1 v2.0 by Kaliski and Staddon of RSA Laboratories (October 1998), cites the attack and recommends RSAES-OAEP for new applications (Confirmed [63]). RFC 2246, TLS 1.0 (January 1999), cites Bleichenbacher and tells servers to act identically whether or not the RSA block is correctly encoded, using a random premaster secret on failure (Confirmed [65]). The same class of padding oracle returns in later protocol attacks, which is why CAPEC-463 and CWE-203 appear in Part 11 (Inferred).

### The end of DES

EFF's release of 17 July 1998 says its DES Cracker, built for under $250,000, won RSA's DES Challenge II in under three days, against a previous record of 39 days; EFF called it the first unclassified hardware for cracking DES and argued that DES-level policy put critical infrastructures at risk (Confirmed [51]). EFF's current press page gives the search time as 56 hours and says the result contradicted government claims about DES strength (Confirmed [52]). On 20 August NIST announced fifteen AES candidate algorithms at the First AES Candidate Conference, after a formal call issued on 12 September 1997, and requested Round 1 comments in the Federal Register on 14 September (Confirmed [53]).

### Export rules and signatures

The Bureau of Export Administration eased encryption exports twice. Its interim rule of 22 September (63 FR 50516) set a licensing policy for general-purpose non-recoverable encryption of any key length for banks and financial institutions in specified countries (Confirmed [54]). Its rule of 31 December (63 FR 72156) implemented the Administration's 16 September policy update: 56-bit DES-equivalent encryption under License Exception ENC to all destinations except Cuba, Iran, Iraq, Libya, North Korea, Sudan and Syria, easier exports to subsidiaries, insurers, health users and on-line merchants, and a promise to update the rules for Wassenaar Arrangement changes (Confirmed [55]). The US eased 56-bit exports within months of EFF breaking 56-bit DES in under three days (Inferred [51][55]). On 15 December Commerce approved FIPS 186-1, the Digital Signature Standard, as an interim final standard allowing both DSA and ANSI X9.31 (RSA) signatures for federal use (Confirmed [57]).

## Part 9: standards and defender research

| Work | Date | Substance | Grade | Sources |
|---|---|---|---|---|
| RFC 2267, Network Ingress Filtering (Ferguson, Cisco; Senie, BlazeNet) | Jan | Drop forged-source packets at network edges, aimed at SYN floods and ICMP broadcast floods; later obsoleted by RFC 2827 | Confirmed | [61] |
| 1998 DARPA Intrusion Detection Evaluation (MIT Lincoln Laboratory) | Feb to Dec | Seven weeks of training and two weeks of test data mixing attacks into background traffic (tcpdump, BSM audit, file system dumps); AFRL hosted the real-time testbed | Confirmed | [68] |
| RFC 2350 / BCP 21 (Brownlee, Univ. of Auckland; Guttman, Sun) | Jun | A template a CSIRT publishes so its constituency knows its charter, policies, contacts and services | Confirmed | [62] |
| StackGuard (Cowan and colleagues, OGI; Hinton, Ryerson), 7th USENIX Security Symposium | 1998 | A compiler technique that detects and prevents stack-smashing buffer overflows with little performance cost and no source changes; read here as the origin of stack canaries (Inferred) | Confirmed | [67] |
| RFC 2437, PKCS #1 v2.0 | Oct | OAEP recommended for new applications, citing Bleichenbacher | Confirmed | [63] |
| RFC 2401, Security Architecture for the Internet Protocol (Kent, BBN; Atkinson, @Home) | Nov | The IPsec architecture (AH, ESP, security associations, key management); obsoletes RFC 1825, later obsoleted by RFC 4301 | Confirmed | [64] |
| NIST SP 800-18 (Swanson and the Federal Computer Security Program Managers' Forum Working Group) | Dec | Guide for Developing Security Plans for Information Technology Systems; withdrawn 24 February 2006 and superseded by Rev. 1 | Confirmed | [66] |
| Phrack 54, "NT Web Technology Vulnerabilities" by rain.forest.puppy | 25 Dec | Describes appending SQL commands to database queries through web input, the class now called SQL injection, without using that term; that it was the first public description is not verified | Confirmed | [71] |

Roesch's Snort paper at LISA '99 cites three 1998 defender works: SHADOW (Northcutt and others, NSWC Dahlgren), the Deception Toolkit (Fred Cohen) and Ptacek and Newsham's "Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection" (Secure Networks) (Reported [70]). The paper does not date Snort's first release, so this study does not place Snort in 1998 (Confirmed [70]). Between the DARPA evaluation and the Ptacek and Newsham critique, network intrusion detection gained a benchmark and a known weakness in the same year (Inferred).

## Part 10: the defender view

What a defender in 1998 could do, from the year's own record, and how it maps to today's practice.

**Filter at the edge and inside.** CA-1998-01's advice to disable directed broadcasts on every router and RFC 2267's ingress filtering are still the answer to reflection floods; the library's D3FEND data pairs [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) and [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) with T1498.001 and T1498.002 (Confirmed [1][61]; Demonstrated [86]).

**Patch the services attackers scan for.** IN-98-06 shows that the gap between an advisory and a script that uses it could be under two months; patching mountd in October was the defense against December's script (Confirmed [1][2]; Inferred).

**Close default accounts.** IN-98.01's accounts had no passwords; the library pairs [Change Default Password](/mitre/d3fend/change-default-password.md) and [User Account Permissions](/mitre/d3fend/user-account-permissions.md) with T1078.001 (Confirmed [2]; Demonstrated [86]).

**Expect credential theft at scale.** The 186,126-account haul argues for strong passwords and for credentials that are worthless when stolen; the library pairs [Strong Password Policy](/mitre/d3fend/strong-password-policy.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md), [One-time Password](/mitre/d3fend/one-time-password.md) and [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) with T1110.002 (Confirmed [2]; Demonstrated [86]).

**Harden the binary.** StackGuard introduced in 1998 what D3FEND now calls [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), which the library pairs with T1068 and T1203 (Confirmed [67]; Demonstrated [86]).

**Control execution and egress.** MS98-010's advice to block unsigned programs at the proxy or firewall matches the library's pairings of [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) with T1204.002 and [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) with T1219 (Confirmed [19]; Demonstrated [86]).

**Trust media less.** CIH and Marburg arrived on cover CDs and in a firmware updater; the library pairs [Software Inventory](/mitre/d3fend/software-inventory.md) and [Software Update](/mitre/d3fend/software-update.md) with T1195.002, and MS98-016 shows Windows Update delivering a fix to Windows 98 users the same year (Confirmed [25][26][21]; Demonstrated [86]).

**Measure detection.** The DARPA evaluation gave intrusion detection a shared dataset, and Ptacek and Newsham showed how a network sensor could be evaded (Confirmed [68]; Reported [70]).

**Run the response function in the open.** RFC 2350 told constituencies what to expect of a response team, and the NIPC and the ISAC model gave the federal government and the private sector a place to share warnings (Confirmed [62][38][39]).

## Part 11: MITRE mappings

No 1998 record carries an ATT&CK, CAPEC or CWE id: CVE began in 1999; MITRE began categorizing weaknesses around 1999 and released the first CWE List in 2006; CAPEC was established by DHS under its Software Assurance initiative and first released in 2007; and MITRE started ATT&CK in 2013 (Confirmed [78][79][80][81][82]). D3FEND is funded by the NSA Cybersecurity Directorate; its first release date was not checked (Confirmed [83]). Every binding below is therefore this study's later mapping (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `software.jsonl`, `technique_to_d3fend.jsonl`, `data/weaknesses/cwe.jsonl` and `capec.jsonl`) and the generated pages under `mitre/` on 12 and 13 November 2026 (Demonstrated [84][85][86][87][88]). Names and tactics are those of ATT&CK v20.0 as the library carries them. T1562 is revoked in v20.0 and maps to T1685; it is not used, and the log cleaner is bound under the v20.0 id T1685.006 Clear Linux or Mac System Logs (Demonstrated [84]).

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md): **Described** means a primary source describes the behavior and this study assigns the id; **Reported** means only a secondary source supports the behavior; **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading. No row is **Listed**, because no 1998 source prints an id.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | impact | Described | Smurf floods through broadcast addresses (CA-1998-01, 5 Jan) | [1][4] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Inferred | Spoofed-source floods RFC 2267 targets (Jan) | [61][1] |
| [`T1499.004`](/mitre/techniques/T1499-004.md) | Application or System Exploitation | impact | Described | Crafted packet sequences crash BSD-derived stacks (CA-1998-13, 21 Dec) | [1] |
| [`T1595.001`](/mitre/techniques/T1595-001.md) | Scanning IP Blocks | reconnaissance | Described | tcpmux sweeps for IRIX (IN-98.01, 13 May); inverse mapping (IN-98.04, 29 Sep) | [2] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | reconnaissance | Described | mscan (IN-98.02, 2 Jul); large-scale mountd scans (CA-1998-12, 12 Oct); scripted scans (IN-98-06, 9 Dec); Solar Sunrise probes (Feb, Reported) | [2][3][1][31] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Described | Portmapper (TCP 111) scans and Linux fingerprinting (IN-98-06, 9 Dec) | [2] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Default Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Automated logins to unpassworded guest, lp and demos (IN-98.01, 13 May) | [2] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | qpopper (14 Jul), ToolTalk (31 Aug / 3 Sep), mountd (12 Oct) exploited; BIND (8 Apr); RDS DataFactory (MS98-004, 14 Jul; compromises reported in IN-99-08); Solar Sunrise (Feb, Reported); Max Butler's worm (Jun, Reported) | [1][16][3][31][34] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Described | CDE dtappgather (CA-1998-02, 21 Jan); sechole (MS98-009, 27 Jul) | [1][18] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Inferred | MIME-aware mail client overflow (CA-1998-10, 11 Aug; MS98-008, 27 Jul); a flaw with no exploitation reported at publication | [1][17] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | Sniffed passwords on the compromised host (IN-98.03, 16 Jul); Moonlight Maze sniffers (1998 to 1999); Solar Sunrise sniffer implants (Feb, Reported) | [2][73][31] |
| [`T1110.002`](/mitre/techniques/T1110-002.md) | Password Cracking | credential-access | Described | 47,642 of 186,126 collected passwords cracked (IN-98.03, 16 Jul) | [2] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | command-and-control | Described | Back Orifice (announced 21 Jul, released 1 Aug; MS98-010, 4 Aug) | [22][23][19] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Described | Back Orifice keystroke logging | [22][23][19] |
| [`T1113`](/mitre/techniques/T1113.md) | Screen Capture | collection | Described | Back Orifice screen capture | [22][19] |
| [`T1555`](/mitre/techniques/T1555.md) | Credentials from Password Stores | credential-access | Inferred | Back Orifice retrieval of cached passwords (the store is not named) | [23] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Described | Back Orifice remote file transfer (MS98-010) | [19] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | Back Orifice requires the user to install it and was typically sent as an e-mail attachment | [19][24] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Windows Service | persistence, privilege-escalation | Described | Remote Explorer installs itself as an NT service (IN-98-07, 22 Dec) | [2] |
| [`T1134.001`](/mitre/techniques/T1134-001.md) | Token Impersonation/Theft | stealth, privilege-escalation | Inferred | Remote Explorer impersonates later logons, including domain administrators (IN-98-07) | [2] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | lateral-movement | Inferred | Remote Explorer infects files across the network (IN-98-07) | [2] |
| [`T1495`](/mitre/techniques/T1495.md) | Firmware Corruption | impact | Described | CIH tries to overwrite the flash BIOS (found Jun 1998; payload dated 26 Apr 1999) | [25][3] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Described | CIH overwrites hard-disk data | [25][3] |
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | initial-access | Described | CIH on cover CDs, a download and a firmware updater; Marburg on cover CDs and a game master CD (Jul to Aug) | [25][26] |
| [`T1090.003`](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | command-and-control | Described | Moonlight Maze operators relay through hacked servers, including HRTest (late 1998 to Mar 1999) | [72][73] |
| [`T1584.004`](/mitre/techniques/T1584-004.md) | Server | resource-development | Described | The HRTest relay, a compromised UK Solaris server | [72][73] |
| [`T1095`](/mitre/techniques/T1095.md) | Non-Application Layer Protocol | command-and-control | Described | LOKI2 tunnelling through protocols such as ICMP (samples 1997 to 1999) | [73] |
| [`T1685.006`](/mitre/techniques/T1685-006.md) | Clear Linux or Mac System Logs | defense-impairment | Described | The utmp log cleaner added to LOKI2 | [73] |
| [`T1588.005`](/mitre/techniques/T1588-005.md) | Exploits | resource-development | Described | Moonlight Maze binaries borrowing exploits from forums and mailing lists | [73] |

Left out on purpose: the GAO and Inspector General findings, which are authorized tests and control weaknesses, not adversary behavior (Inferred [41]); the DES Cracker and Bleichenbacher's oracle, which are research and are bound through CAPEC and CWE instead; Operation Double Barrel, a telemarketing fraud case with no computer technique in the source; the Phrack 54 injection class, which is a technique description rather than a dated intrusion and is bound through CWE-89 and CAPEC-66; T1003.002 Security Account Manager, T1561.002 Disk Structure Wipe and T1547.001 Registry Run Keys, for which no 1998 primary opened describes the mechanism; and T1600.001 Reduce Key Space, since no 1998 actor weakened a victim's encryption (Inferred [84]).

### ATT&CK for ICS techniques

None. No 1998 intrusion into an industrial control system appears in any primary opened; GAO's air traffic control report concerns control weaknesses, not an attack (Confirmed [42]; Inferred). No ICS layer is published.

### ATT&CK groups, software and campaigns

None bound. The library's ATT&CK data holds no software object for Back Orifice, CIH, Marburg, Remote Explorer or mscan, and no group or campaign object for Solar Sunrise or Moonlight Maze (Confirmed [85]; Demonstrated [84]). Moonlight Maze reaches an ATT&CK id only through the unproven Turla lineage the Kaspersky and King's College researchers propose and call premature: [Turla (G0010)](/mitre/groups/G0010.md) dates the group from at least 2004 and [Penquin (S0587)](/mitre/software/S0587.md) from at least 2014, and neither page mentions Moonlight Maze (Confirmed [75][76][72]). [Equation (G0020)](/mitre/groups/G0020.md) is not placed in 1998 (Confirmed [77]; Reported [74]). These pages are linked for context, not as 1998 bindings.

### CWE and CAPEC

Rows marked "as NVD lists it" use the CWE that NVD prints on the later CVE-1999 record (Confirmed [9][93]; Inferred for the description pairings in Part 2). Every other CWE is this study's binding (Inferred). Names are those in the library's CWE and CAPEC data, and the CAPEC column says which pairings the library makes and which are this study's (Demonstrated [87][88]; Inferred for this study's pairings).

| CWE | Weakness (library name) | 1998 record | CAPEC |
|---|---|---|---|
| CWE-406 | Insufficient Control of Network Message Volume (Network Amplification) | Smurf, CA-1998-01, 5 Jan | [CAPEC-490](/mitre/capec/CAPEC-490.md) Amplification (this study's pairing; the library links CAPEC-490 to T1498.002) |
| CWE-400 | Uncontrolled Resource Consumption | Smurf floods; MS98-001's unbounded group creation, 1 Jun | [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding (this study's pairing; the library links CAPEC-125 to T1498.001 and T1499) |
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer (as NVD lists it for mountd) | CA-1998-12, 12 Oct | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers |
| CWE-120, CWE-121 | Buffer Copy without Checking Size of Input; Stack-based Buffer Overflow (this study's binding) | The overflow advisories: NIS+, qpopper, IMAP, MIME clients, ToolTalk; the class StackGuard addresses | [CAPEC-100](/mitre/capec/CAPEC-100.md); CAPEC-100 is the library's pairing for CWE-120; CWE-121 has none |
| CWE-20 | Improper Input Validation (as NVD lists it for CVE-1999-0001) | CA-1998-13, 21 Dec | None assigned |
| CWE-522 | Insufficiently Protected Credentials (as NVD lists it for CVE-1999-0013) | CA-1998-03 ssh-agent, 22 Jan | None assigned |
| CWE-290 | Authentication Bypass by Spoofing (as NVD lists it for CVE-1999-0012) | CA-1998-04 long file names, 6 Feb | None assigned |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm (as NVD lists it for CVE-1999-0007; this study's binding for the DES Cracker) | CA-1998-07 and MS98-002, 26 Jun; DES Cracker, 17 Jul | [CAPEC-463](/mitre/capec/CAPEC-463.md) Padding Oracle Crypto Attack for PKCS #1 (this study's pairing); [CAPEC-97](/mitre/capec/CAPEC-97.md) Cryptanalysis and [CAPEC-20](/mitre/capec/CAPEC-20.md) Encryption Brute Forcing for DES (library pairings) |
| CWE-780, CWE-203 | Use of RSA Algorithm without OAEP; Observable Discrepancy | Bleichenbacher's oracle, answered by RFC 2437 (OAEP) and RFC 2246 (identical behavior) | [CAPEC-463](/mitre/capec/CAPEC-463.md) (this study's pairing) |
| CWE-326 | Inadequate Encryption Strength | DES Cracker, 17 Jul; the 56-bit export rule, 31 Dec | [CAPEC-20](/mitre/capec/CAPEC-20.md) (library pairing) |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | Phrack 54, 25 Dec | [CAPEC-66](/mitre/capec/CAPEC-66.md) SQL Injection |
| CWE-276 | Incorrect Default Permissions | MS98-001, 1 Jun | None assigned |
| CWE-1392 | Use of Default Credentials | IRIX guest, lp and demos without passwords, IN-98.01, 13 May | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords (this study's pairing; the library links CAPEC-70 to T1078.001) |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | CIH, Marburg, Remote Explorer, the Butler worm | None assigned |
| none bound | (password cracking; sniffing; scanning) | IN-98.03 haul; Moonlight Maze sniffers; mscan and IN-98-06 | [CAPEC-55](/mitre/capec/CAPEC-55.md) Rainbow Table Password Cracking (links T1110.002) and [CAPEC-112](/mitre/capec/CAPEC-112.md) Brute Force (links T1110); [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (links T1040); [CAPEC-300](/mitre/capec/CAPEC-300.md) Port Scanning (links T1046) and [CAPEC-169](/mitre/capec/CAPEC-169.md) Footprinting (links T1595) |

### D3FEND countermeasures

Pairings come from `data/attack/technique_to_d3fend.jsonl` unless the row says the pairing is this study's; every page exists under `/mitre/d3fend/` (Demonstrated [86]).

| Technique from the record | D3FEND countermeasures | 1998 analogue |
|---|---|---|
| T1498.002 and T1498.001 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md), [Protocol Metadata Anomaly Detection](/mitre/d3fend/protocol-metadata-anomaly-detection.md) | CA-1998-01 directed-broadcast shutdown; RFC 2267 ingress filtering [1][61] |
| T1190 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md), [Database Query String Analysis](/mitre/d3fend/database-query-string-analysis.md), [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md) | Vendor patches for BIND, qpopper, IMAP, ToolTalk and mountd; the Phrack 54 injection class [1][71] |
| T1068 and T1203 | [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md), [Shadow Stack Comparisons](/mitre/d3fend/shadow-stack-comparisons.md), [Memory Boundary Tracking](/mitre/d3fend/memory-boundary-tracking.md), [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) | StackGuard, 1998 [67] |
| T1078.001 | [Change Default Password](/mitre/d3fend/change-default-password.md), [User Account Permissions](/mitre/d3fend/user-account-permissions.md) | Passwords on the IRIX default accounts [2] |
| T1110.002 | [Strong Password Policy](/mitre/d3fend/strong-password-policy.md), [Credential Hardening](/mitre/d3fend/credential-hardening.md), [One-time Password](/mitre/d3fend/one-time-password.md), [Multi-factor Authentication](/mitre/d3fend/multi-factor-authentication.md) | No 1998 counterpart in the record beyond CERT's report [2] |
| T1040 | The library maps only [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md). [Message Encryption](/mitre/d3fend/message-encryption.md) is a concept match for IPsec (this study's pairing) | RFC 2401, November [64] |
| T1219, T1105, T1095 and T1090.003 | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md), [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md), [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) | MS98-010's firewall advice; the HRTest administrator's monitoring [19][72] |
| T1204.002 | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md), [File Analysis](/mitre/d3fend/file-analysis.md), [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md), [Content Filtering](/mitre/d3fend/content-filtering.md) | MS98-010: block unsigned programs at the proxy or firewall [19] |
| T1543.003 | [System Configuration Permissions](/mitre/d3fend/system-configuration-permissions.md) | No 1998 counterpart in the record [2] |
| T1080 | [Decoy Network Resource](/mitre/d3fend/decoy-network-resource.md), [Network Resource Access Mediation](/mitre/d3fend/network-resource-access-mediation.md) | No 1998 counterpart in the record [2] |
| T1195.002 | [Software Inventory](/mitre/d3fend/software-inventory.md), [Software Update](/mitre/d3fend/software-update.md) | Windows Update delivery of MS98-016 [21] |
| T1685.006 | The library has no pairing. [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) and [System File Analysis](/mitre/d3fend/system-file-analysis.md) are concept matches for cleared logs (this study's pairing) | No 1998 counterpart in the record [73] |
| T1495 | The library has no pairing. [Firmware Verification](/mitre/d3fend/firmware-verification.md) is a concept match for CIH (this study's pairing) | No 1998 counterpart in the record [25] |

The library's data has no D3FEND pairing for T1595.002, T1046, T1499, T1499.004, T1495, T1485, T1584.004 or T1685.006, and none is invented here beyond the concept matches labelled above (Demonstrated [86]).

### Navigator layer

The study's techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-1998.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1998.json), listing the 29 techniques in the Enterprise table under each tactic they carry in v20.0, and listed on [the Navigator layers page](/navigator/index.md) [92]. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping; no entry scores 100, because no 1998 source prints an id. Each entry's comment names the source numbers in the Sources table below. No ICS layer is needed.

## Cross-cutting themes

**The script replaced the intruder.** CERT's incident notes run from manual logins in May to a full scan, exploit and backdoor script in December (Confirmed [2]). The same pattern of mass exploitation after disclosure recurs in [Log4Shell](/case-studies/LOG4SHELL.md) and the [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md) (Inferred).

**Attribution under pressure.** Solar Sunrise arrived during an Iraq crisis and, by DOJ's account, involved no state sponsor (Confirmed [27]); GlobalSecurity.org says the attackers were three teenagers (Reported [31]). Moonlight Maze was a long-running campaign whose attribution is still open (Confirmed [72]; Reported [73]). The library's [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) and [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) show how much more evidence a confident attribution now carries (Inferred).

**Trusted channels carried code.** CIH and Marburg arrived on magazine CDs and in a vendor's firmware updater, and Back Orifice could ride inside another executable (Confirmed [25][26][23]). The same trust failure recurs in the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies (Inferred).

**Government organized around infrastructure.** NIPC in February, PDD-63 in May and GAO's 24-agency finding in September all point toward warning, sharing and defending critical systems (Confirmed [28][38][41]). Later infrastructure attacks run through the [Stuxnet study](/case-studies/STUXNET.md) and the [ICS attacks and advisories study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) (Inferred).

**Research reached standards fast.** Bleichenbacher's oracle reached PKCS #1 in four months and TLS in seven (Confirmed [1][63][65]); StackGuard is, in this study's reading, the origin of the countermeasure D3FEND now calls Stack Frame Canary Validation (Inferred [67]). Root causes of the overflow and oracle classes are discussed on the library's [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md) page (Inferred).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: Solar Sunrise as a state attack.** Within weeks DOJ found no indication of an organized military or state-sponsored campaign [27], and GlobalSecurity.org says the attackers were teenagers [31].
- **Overstated: Moonlight Maze "is Turla".** The researchers who hold the evidence call the conclusion premature, and ATT&CK's Turla and Penquin pages are silent on it [72][73][75][76].
- **Overstated: Back Orifice as a Windows vulnerability, and as no risk at all.** Microsoft is right that it exploited no flaw, and MS98-010's statement that careful users "are not at risk" is a vendor position: the same bulletin lists keystroke capture and remote file transfer, and cDc's own page says it hid from the task list and could ride inside another program [19][23].
- **Overstated: tidy "firsts".** That Phrack 54 was the first public description of SQL injection, and that Snort was released in December 1998, are not established by the primaries opened [71][70].
- **Overstated: "1998 CVEs".** Retroactive CVE-1999 numbering, and two dating systems that disagree, make any 1998 CVE count an artifact of the database [4][12].
- **Overstated: any ATT&CK, CWE or CAPEC id on a 1998 event.** None of those programs existed until 2006 to 2013, and the Navigator layer reflects later naming, not 1998 understanding [80][81][82].
- **Understated: the automation of the Unix and Linux attack.** The year's real volume story is in CERT's incident notes on mscan, mountd and default accounts, not in the headline cases [2][3].
- **Understated: Moonlight Maze itself.** The public technical record rests mostly on one administrator's preserved relay logs, and the official record was not opened [72][73].
- **Understated: the audit record.** GAO showed weaknesses in all 24 largest agencies and its testers reached State Department data; these authorized tests are the best-documented compromises of the year [41][43].
- **Understated: standards work.** RFC 2267 (later obsoleted by RFC 2827), RFC 2350 and SP 800-18 get little attention next to the year's incidents [61][62][66].
- **Understated: advisory volume.** CERT's 13 advisories and Microsoft's 20 bulletins are a floor; vendors and mailing lists carried more, which this study did not count [1][13].
- **Understated: the breach record's gaps.** No 1998 consumer data breach could be confirmed from a primary opened, which says more about what was disclosed then than about what happened [41][45].

### Discrepancies in the record

- **CVE-1999-0003.** It matches CA-1998-11 by description, but its NVD published date reads 1 April 1998, five months before NAI-29 and the CERT advisory; this study records the difference and does not resolve it [10][1].
- **Two CVE dates.** NVD gives CVE-1999-0002 the advisory date of 12 October 1998, while the CVE Services records for CVE-1999-0007 and CVE-1999-0278 show 29 September 1999 and CVE-1999-1011 shows 2 June 2000 [9][12].
- **The DES Cracker date.** EFF's 1998 release is dated 17 July and says the challenge was won that week; EFF's current press page carries a 2016 CMS date and gives no 1998 date [51][52].
- **The name.** DOJ's release spells the Israeli defendant "Tenebaum"; the Los Angeles Times, The Register and later sources spell it Tenenbaum [27][32][33].
- **Moonlight Maze dates.** The researchers' whitepaper dates detection to October 1996 and the FBI investigation to July 1998; the blog dates the relay logs to 1998 to 1999 and the samples to late 1996 [73][72].
- **CIH's first appearance.** F-Secure records June 1998 in Taiwan; CERT's first note is April 1999; the library's home study dates it by the 1999 payload [25][3][89].

## Sources

All sources were opened on 12 or 13 November 2026 as listed. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the NVD API queries and the ftc.gov report); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "1998 CERT Advisories" (compilation, CA-1998-01 to CA-1998-13) | https://www.sei.cmu.edu/documents/505/1998_019_001_496180.pdf | 2026-11-13 | Confirmed |
| 2 | CMU SEI, "1998 CERT Incident Notes" (compilation, IN-98.01 to IN-98-07) | https://www.sei.cmu.edu/documents/519/1998_019_001_496438.pdf | 2026-11-13 | Confirmed |
| 3 | CMU SEI, "1999 CERT Incident Notes" (IN-99-01, IN-99-03, IN-99-08) | https://www.sei.cmu.edu/documents/520/1999_019_001_496442.pdf | 2026-11-13 | Confirmed |
| 4 | NVD, CVE-1999-0513 | https://nvd.nist.gov/vuln/detail/CVE-1999-0513 | 2026-11-12 | Confirmed |
| 5 | NVD, CVE-1999-0009 | https://nvd.nist.gov/vuln/detail/CVE-1999-0009 | 2026-11-12 | Confirmed |
| 6 | NVD API, CVE-1999-0009 (with CVE-1999-0010 and -0011) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-0009` | 2026-11-13 | Confirmed (records); Inferred (pairing) |
| 7 | NVD, CVE-1999-0008 | https://nvd.nist.gov/vuln/detail/CVE-1999-0008 | 2026-11-12 | Confirmed |
| 8 | NVD, CVE-1999-0005 | https://nvd.nist.gov/vuln/detail/CVE-1999-0005 | 2026-11-12 | Confirmed |
| 9 | NVD, CVE-1999-0002 | https://nvd.nist.gov/vuln/detail/CVE-1999-0002 | 2026-11-12 | Confirmed |
| 10 | NVD API, CVE-1999-0003 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-0003` | 2026-11-13 | Confirmed (record); Inferred (pairing) |
| 11 | NVD API, CVE-1999-0002 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-0002` | 2026-11-13 | Confirmed |
| 12 | CVE Services API, CVE-1999-0007 (with CVE-1999-0278 and CVE-1999-1011) | https://cveawg.mitre.org/api/cve/CVE-1999-0007 | 2026-11-12 | Demonstrated |
| 13 | Microsoft Security Bulletin MS98-001 (with MS98-020 and the MS98-021 probe) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-001 | 2026-11-13 | Confirmed; Demonstrated (count) |
| 14 | Microsoft Security Bulletin MS98-002 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-002 | 2026-11-13 | Confirmed |
| 15 | Microsoft Security Bulletin MS98-003 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-003 | 2026-11-13 | Confirmed |
| 16 | Microsoft Security Bulletin MS98-004 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-004 | 2026-11-12 | Confirmed |
| 17 | Microsoft Security Bulletin MS98-008 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-008 | 2026-11-13 | Confirmed |
| 18 | Microsoft Security Bulletin MS98-009 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-009 | 2026-11-13 | Confirmed |
| 19 | Microsoft Security Bulletin MS98-010 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-010 | 2026-11-13 | Confirmed (vendor position) |
| 20 | Microsoft Security Bulletin MS98-012 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-012 | 2026-11-13 | Confirmed |
| 21 | Microsoft Security Bulletin MS98-016 (with the CVE-1999-1087 record) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1998/ms98-016 | 2026-11-12 | Confirmed |
| 22 | Cult of the Dead Cow, Back Orifice press release, 21 July 1998 (also as text) | https://cultdeadcow.com/news/back_orifice.html | 2026-11-13 | Confirmed (the author's own statements) |
| 23 | Cult of the Dead Cow, Back Orifice tool page | https://cultdeadcow.com/tools/bo.html | 2026-11-13 | Confirmed (the author's own statements) |
| 24 | F-Secure, Back Orifice | https://www.f-secure.com/v-descs/backori.shtml | 2026-11-13 | Confirmed |
| 25 | F-Secure, CIH | https://www.f-secure.com/v-descs/cih.shtml | 2026-11-13 | Confirmed |
| 26 | F-Secure, Marburg | https://www.f-secure.com/v-descs/marburg.shtml | 2026-11-13 | Confirmed |
| 27 | US Department of Justice, release 98-125, 18 March 1998 | https://www.justice.gov/archive/opa/pr/1998/March/125.htm.html | 2026-11-13 | Confirmed |
| 28 | US Department of Justice, release 98-088 (NIPC), 27 February 1998 | https://www.justice.gov/archive/opa/pr/1998/February/088.htm.html | 2026-11-13 | Confirmed |
| 29 | US Department of Justice, Operation Double Barrel, 17 December 1998 | https://www.justice.gov/archive/opa/pr/1998/December/596cr.htm | 2026-11-13 | Confirmed |
| 30 | US Department of Justice, Antitrust Division Year 2000 business review, 1 July 1998 | https://www.justice.gov/archive/opa/pr/1998/July/311at.html | 2026-11-12 | Confirmed |
| 31 | GlobalSecurity.org, Solar Sunrise | https://www.globalsecurity.org/military/ops/solar-sunrise.htm | 2026-11-13 | Reported |
| 32 | Los Angeles Times, 27 April 1998 | https://www.latimes.com/archives/la-xpm-1998-apr-27-mn-43491-story.html | 2026-11-12 | Reported |
| 33 | The Register, Solar Sunrise sentencing, 15 June 2001 | https://www.theregister.com/offbeat/2001/06/15/solar-sunrise-hacker-analyzer-escapes-jail/941723 | 2026-11-12 | Reported |
| 34 | The Register, Max Vision sentencing, 22 May 2001 | https://www.theregister.com/2001/05/22/whitehat_max_vision_gets/ | 2026-11-12 | Reported |
| 35 | US Senate HSGAC, "Weak Computer Security in Government: Is the Public at Risk?", 19 May 1998 | https://www.hsgac.senate.gov/hearings/weak-computer-security-in-government-is-the-public-at-risk/ | 2026-11-12 | Confirmed |
| 36 | Senator Fred Thompson, prepared statement, 19 May 1998 | https://www.hsgac.senate.gov/wp-content/uploads/imo/media/doc/thompson051998.pdf | 2026-11-12 | Confirmed |
| 37 | *United States v. Mitnick*, 145 F.3d 1342 (9th Cir. 1998) | https://law.justia.com/cases/federal/appellate-courts/F3/145/1342/470528/ | 2026-11-13 | Confirmed |
| 38 | PDD/NSC-63, Critical Infrastructure Protection, 22 May 1998 (FAS copy) | https://irp.fas.org/offdocs/pdd/pdd-63.htm | 2026-11-13 | Confirmed |
| 39 | White House fact sheet on PDD-63, 22 May 1998 (FAS copy) | https://irp.fas.org/offdocs/pdd-63.htm | 2026-11-12 | Confirmed |
| 40 | White House fact sheet on PDD-62, 22 May 1998 (FAS copy) | https://irp.fas.org/offdocs/pdd-62.htm | 2026-11-12 | Confirmed |
| 41 | GAO/AIMD-98-92, 23 September 1998 | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-98-92/html/GAOREPORTS-AIMD-98-92.htm | 2026-11-12 | Confirmed |
| 42 | GAO/AIMD-98-155, 18 May 1998 | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-98-155/html/GAOREPORTS-AIMD-98-155.htm | 2026-11-12 | Confirmed |
| 43 | GAO/AIMD-98-145, 18 May 1998 | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-98-145/html/GAOREPORTS-AIMD-98-145.htm | 2026-11-12 | Confirmed |
| 44 | GAO/AIMD-98-68, 1 May 1998 | https://www.govinfo.gov/content/pkg/GAOREPORTS-AIMD-98-68/html/GAOREPORTS-AIMD-98-68.htm | 2026-11-12 | Confirmed |
| 45 | FTC, "Privacy Online: A Report to Congress", June 1998 | `https://www.ftc.gov/sites/default/files/documents/reports/privacy-online-report-congress/priv-23a.pdf` | 2026-11-12 | Confirmed |
| 46 | Pub. L. 105-277 (COPPA, Government Paperwork Elimination Act) | https://www.govinfo.gov/content/pkg/PLAW-105publ277/html/PLAW-105publ277.htm | 2026-11-12 | Confirmed |
| 47 | Pub. L. 105-304, Digital Millennium Copyright Act | https://www.govinfo.gov/content/pkg/PLAW-105publ304/html/PLAW-105publ304.htm | 2026-11-13 | Confirmed |
| 48 | Pub. L. 105-318, Identity Theft and Assumption Deterrence Act | https://www.govinfo.gov/content/pkg/PLAW-105publ318/html/PLAW-105publ318.htm | 2026-11-13 | Confirmed |
| 49 | Pub. L. 105-271, Year 2000 Information and Readiness Disclosure Act | https://www.govinfo.gov/content/pkg/PLAW-105publ271/html/PLAW-105publ271.htm | 2026-11-12 | Confirmed |
| 50 | UK Data Protection Act 1998 (1998 c. 29), as enacted | https://www.legislation.gov.uk/ukpga/1998/29/introduction/enacted | 2026-11-12 | Confirmed |
| 51 | EFF, DES Cracker press release, 17 July 1998 | https://w2.eff.org/Privacy/Crypto/Crypto_misc/DESCracker/HTML/19980716_eff_descracker_pressrel.html | 2026-11-12 | Confirmed (EFF's account of its own result) |
| 52 | EFF, "EFF DES Cracker Machine Brings Honesty to Crypto Debate" (current page) | https://www.eff.org/press/releases/eff-des-cracker-machine-brings-honesty-crypto-debate | 2026-11-12 | Confirmed |
| 53 | NIST CSRC, AES development (archived project) | https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/archived-crypto-projects/aes-development | 2026-11-12 | Confirmed |
| 54 | Federal Register, "Encryption Items", 63 FR 50516, 22 September 1998 | https://www.federalregister.gov/documents/1998/09/22/98-25096/encryption-items | 2026-11-12 | Confirmed |
| 55 | Federal Register, "Encryption Items", 63 FR 72156, 31 December 1998 | https://www.govinfo.gov/content/pkg/FR-1998-12-31/html/98-34669.htm | 2026-11-12 | Confirmed |
| 56 | Federal Register, "Security and Electronic Signature Standards", 63 FR 43242, 12 August 1998 | https://www.federalregister.gov/documents/1998/08/12/98-21601/security-and-electronic-signature-standards | 2026-11-12 | Confirmed |
| 57 | Federal Register, approval of FIPS 186-1, 63 FR 69049, 15 December 1998 | https://www.federalregister.gov/documents/1998/12/15/98-33167/announcing-approval-of-federal-information-processing-standard-186-1-digital-signature-standard-and | 2026-11-12 | Confirmed |
| 58 | G8 Birmingham Summit communique, 17 May 1998 (University of Toronto G8 Information Centre) | http://www.g8.utoronto.ca/summit/1998birmingham/finalcom.htm | 2026-11-12 | Confirmed |
| 59 | WTO, Declaration on Global Electronic Commerce, WT/MIN(98)/DEC/2 | https://www.wto.org/english/tratop_e/ecom_e/mindec1_e.htm | 2026-11-12 | Confirmed |
| 60 | UN General Assembly resolution 53/70 | https://documents.un.org/doc/undoc/gen/n99/760/03/pdf/n9976003.pdf | 2026-11-12 | Confirmed |
| 61 | RFC 2267, Network Ingress Filtering | https://www.rfc-editor.org/rfc/rfc2267 | 2026-11-12 | Confirmed |
| 62 | RFC 2350 / BCP 21, Expectations for Computer Security Incident Response | https://www.rfc-editor.org/rfc/rfc2350 | 2026-11-12 | Confirmed |
| 63 | RFC 2437, PKCS #1 v2.0 | https://www.rfc-editor.org/rfc/rfc2437 | 2026-11-12 | Confirmed |
| 64 | RFC 2401, Security Architecture for the Internet Protocol | https://www.rfc-editor.org/rfc/rfc2401 | 2026-11-12 | Confirmed |
| 65 | RFC 2246, The TLS Protocol Version 1.0 | https://www.rfc-editor.org/rfc/rfc2246 | 2026-11-12 | Confirmed |
| 66 | NIST SP 800-18 (withdrawn) | https://csrc.nist.gov/pubs/sp/800/18/final | 2026-11-12 | Confirmed |
| 67 | Cowan and others, StackGuard, 7th USENIX Security Symposium | https://www.usenix.org/legacy/publications/library/proceedings/sec98/cowan.html | 2026-11-12 | Confirmed |
| 68 | MIT Lincoln Laboratory, 1998 DARPA Intrusion Detection Evaluation Dataset | https://www.ll.mit.edu/r-d/datasets/1998-darpa-intrusion-detection-evaluation-dataset | 2026-11-12 | Confirmed |
| 69 | Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1" (CRYPTO '98) | https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf | 2026-11-12 | Confirmed |
| 70 | Roesch, "Snort: Lightweight Intrusion Detection for Networks", LISA '99 | https://www.usenix.org/legacy/events/lisa99/full_papers/roesch/roesch.pdf | 2026-11-12 | Confirmed (the paper); Reported (the 1998 works it cites) |
| 71 | Phrack 54, "NT Web Technology Vulnerabilities" | https://phrack.org/issues/54/nt-web-technology-vulnerabilities.html | 2026-11-12 | Confirmed |
| 72 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze", Securelist, 3 April 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-13 | Confirmed (findings); Reported (victims) |
| 73 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze" (whitepaper PDF) | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf | 2026-11-13 | Confirmed (technical findings); Reported (investigation timeline, victims, attribution) |
| 74 | Kaspersky, "Equation Group: Questions and Answers", February 2015 | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf | 2026-11-13 | Reported (vendor estimate) |
| 75 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-13 | Confirmed |
| 76 | MITRE ATT&CK, Penquin (S0587) | https://attack.mitre.org/software/S0587/ | 2026-11-13 | Confirmed |
| 77 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-13 | Confirmed |
| 78 | Mann and Christey, "Towards a Common Enumeration of Vulnerabilities", 8 January 1999 | https://www.cve.org/Resources/General/Towards-a-Common-Enumeration-of-Vulnerabilities.pdf | 2026-11-12 | Confirmed |
| 79 | CVE Program, History page source (cve-website repository) | https://github.com/CVEProject/cve-website/blob/dev/src/views/About/History.vue | 2026-11-12 | Confirmed |
| 80 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 81 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 82 | MITRE ATT&CK, FAQ | https://attack.mitre.org/resources/faq/ | 2026-11-12 | Confirmed |
| 83 | MITRE D3FEND, about | https://d3fend.mitre.org/about/ | 2026-11-12 | Confirmed |
| 84 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` (with the `mitre/techniques/` page tree) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_profiles.jsonl | 2026-11-13 | Demonstrated |
| 85 | TeamStarWolf library, `data/attack/software.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/software.jsonl | 2026-11-13 | Confirmed |
| 86 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` (with the `mitre/d3fend/` page tree) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/attack/technique_to_d3fend.jsonl | 2026-11-13 | Demonstrated |
| 87 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/cwe.jsonl | 2026-11-13 | Demonstrated |
| 88 | TeamStarWolf library, `data/weaknesses/capec.jsonl` (with the `mitre/capec/` page tree) | https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/data/weaknesses/capec.jsonl | 2026-11-13 | Demonstrated |
| 89 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-13 | Confirmed (the library's record) |
| 90 | TeamStarWolf library, `case-studies/CYBERCRIME_FOUR_BOOKS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/CYBERCRIME_FOUR_BOOKS.md | 2026-11-12 | Reported (relays source 34) |
| 91 | TeamStarWolf library, `case-studies/MITNICK_INTRUSIONS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/MITNICK_INTRUSIONS.md | 2026-11-12 | Confirmed (the library's record) |
| 92 | TeamStarWolf library, main branch, `navigator/library-layers/` (the folder where this study's layer is saved; not evidence) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-13 | Demonstrated (location) |
| 93 | NVD API, CVE-1999-0001, CVE-1999-0004, CVE-1999-0006, CVE-1999-0007, CVE-1999-0012 and CVE-1999-0013 (CWE-20, NVD-CWE-Other, NVD-CWE-Other with CWE-125, CWE-327, CWE-290, CWE-522) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-0001` (and the same query for each id) | 2026-11-13 | Confirmed (records); Inferred (description pairings) |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md)
- Home studies: [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [The Cybercrime Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [United States: the public record](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1498.002 Reflection Amplification](/mitre/techniques/T1498-002.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1499.004 Application or System Exploitation](/mitre/techniques/T1499-004.md), [T1595.001 Scanning IP Blocks](/mitre/techniques/T1595-001.md), [T1595.002 Vulnerability Scanning](/mitre/techniques/T1595-002.md), [T1046 Network Service Discovery](/mitre/techniques/T1046.md), [T1078.001 Default Accounts](/mitre/techniques/T1078-001.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1110.002 Password Cracking](/mitre/techniques/T1110-002.md), [T1219 Remote Access Tools](/mitre/techniques/T1219.md), [T1056.001 Keylogging](/mitre/techniques/T1056-001.md), [T1113 Screen Capture](/mitre/techniques/T1113.md), [T1555 Credentials from Password Stores](/mitre/techniques/T1555.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1543.003 Windows Service](/mitre/techniques/T1543-003.md), [T1134.001 Token Impersonation/Theft](/mitre/techniques/T1134-001.md), [T1080 Taint Shared Content](/mitre/techniques/T1080.md), [T1495 Firmware Corruption](/mitre/techniques/T1495.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1195.002 Compromise Software Supply Chain](/mitre/techniques/T1195-002.md), [T1090.003 Multi-hop Proxy](/mitre/techniques/T1090-003.md), [T1584.004 Server](/mitre/techniques/T1584-004.md), [T1095 Non-Application Layer Protocol](/mitre/techniques/T1095.md), [T1685.006 Clear Linux or Mac System Logs](/mitre/techniques/T1685-006.md), [T1588.005 Exploits](/mitre/techniques/T1588-005.md)
- CAPEC: [CAPEC-20](/mitre/capec/CAPEC-20.md), [CAPEC-55](/mitre/capec/CAPEC-55.md), [CAPEC-66](/mitre/capec/CAPEC-66.md), [CAPEC-70](/mitre/capec/CAPEC-70.md), [CAPEC-97](/mitre/capec/CAPEC-97.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-112](/mitre/capec/CAPEC-112.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-158](/mitre/capec/CAPEC-158.md), [CAPEC-169](/mitre/capec/CAPEC-169.md), [CAPEC-300](/mitre/capec/CAPEC-300.md), [CAPEC-463](/mitre/capec/CAPEC-463.md), [CAPEC-490](/mitre/capec/CAPEC-490.md)
- Groups, software and campaigns: none bound for 1998 (Part 11); Turla [G0010](/mitre/groups/G0010.md) and Penquin [S0587](/mitre/software/S0587.md) for the proposed and unproven Moonlight Maze lineage; Equation [G0020](/mitre/groups/G0020.md), not placed in 1998
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-1998.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1998.json)
