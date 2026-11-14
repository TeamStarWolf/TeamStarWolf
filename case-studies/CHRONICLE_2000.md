# The Year 2000 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source opened on 12 or 13 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md) · Home studies for events summarized here: [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Love Letter, the February denial-of-service attacks, the Mafiaboy arrest, CD Universe, Egghead.com, Gorshkov and Ivanov, Moonlight Maze), [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md) (his March 2000 Senate testimony and the c0mrade sentence), [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Turla), [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) (Equation) and [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md) · Series: [The Year 1997 in Intrusions](/case-studies/CHRONICLE_1997.md), [The Year 1998 in Intrusions](/case-studies/CHRONICLE_1998.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, ICS defenders and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 65 min (14,880 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2000, you need the year's CERT advisories and incident notes, the DDoS agent pools and Love Letter side by side with the Maroochy Shire attack, ECHELON, Carnivore and the year's new law, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 9: the industrial record](#part-9-the-industrial-record)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md), [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

People remember 2000 for two loud weeks: the February attacks on Yahoo, Amazon.com, eBay, Buy.com and CNN's site, and the Love Letter (ILOVEYOU) worm in May (Reported [45][46]; Confirmed [1]). The record backs both, with different strengths. Yahoo was unreachable for about three hours on Monday 7 February, and on Tuesday 8 February Amazon.com, eBay, Buy.com and CNN Interactive were hit; both days rest on press reports (Reported [45][46]). One week later the President met technology leaders and security experts at the White House, citing "the disruptions at several websites last week" (Confirmed [39]). The RCMP arrested a 15-year-old known as "mafia boy" in Montreal on 15 April, charged over the attack on CNN's site (Confirmed [35]). Love Letter is a primary-record event: CERT/CC's CA-2000-04 (4 May, revised 9 May) says that by 5 pm EDT on 8 May more than 650 sites had reported more than 500,000 affected systems (Confirmed [1]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for both events (Confirmed [102]).

The quieter record matters more to defenders. CERT/CC issued 22 advisories in 2000, CA-2000-01 on 3 January to CA-2000-22 on 12 December (Confirmed [1]). The first warned that distributed denial-of-service tools depend on intruders first compromising hosts through known flaws, and reported Stacheldraht on multiple compromised hosts (Confirmed [1]). Through the year CERT reported continuing daily compromises of unpatched BIND servers through a 1999 flaw (26 April), exploitation of wu-ftpd "site exec" (7 July) and rpc.statd (18 August), and widespread automated exploitation of both, with hundreds of hosts compromised in single incidents, mostly Red Hat Linux (15 September) (Confirmed [1][2]). The year closed with LPRng (12 December) (Confirmed [1]). Between these, the incident notes record Windows-based DDoS agents (from 16 February), nameservers used as flood amplifiers (28 April) and the mstream DDoS tool (late April) (Confirmed [2]).

One record from 2000 stands apart. Between 9 February and 23 April 2000, Vitek Boden, a former site supervisor for the contractor that installed the Maroochy Shire Council sewerage control system in Queensland, accessed computers controlling that system, altering pumping-station data and causing malfunctions (the Crown case); the judgment records an intruder disabling alarms under another station's identity and the PDS computer in Boden's car programmed as that station (Confirmed [50]). The Queensland Court of Appeal's judgment records a pumping station overflow and raw sewage escaping (Confirmed [50]). ATT&CK for ICS records the event as campaign C0020, Maroochy Water Breach, with 12 techniques (Confirmed [51]). It is the earliest event in this series that ATT&CK itself names as a campaign (Inferred).

The state record is thin, and the gap is in visibility, not necessarily activity (Inferred [52][55][103][104][105]). Moonlight Maze, which the researchers date from 1996, may have run into early 2000 by one account: PBS Frontline says the probing ran "for nearly two years" from March 1998 (Reported [53]). The European Parliament announced the committee referral on the ECHELON interception system (5 July), the FBI's Carnivore tool became public (11 July, per EPIC) and was reviewed (8 December), and Russia adopted an Information Security Doctrine (9 September) (Confirmed [60][63][65]; Reported [64]). After the Seattle arrests of Gorshkov and Ivanov, the FBI reached into two computers in Russia over the Internet and copied their data (Confirmed [29]).

The law moved fast. The year brought the national plan to defend America's cyberspace (January), the Government Information Security Reform Act (30 October) and the HIPAA privacy rule (28 December). The GLB privacy rules and Regulation S-P, ESIGN, Safe Harbor, PIPEDA in Canada, and the UK's RIPA and Terrorism Act also date to 2000 (Confirmed [38][43][77][67][68][69][70][81][80][79]). In cryptography, NIST picked Rijndael as the proposed AES on 2 October, and the RSA patent expired on 20 September (Confirmed [71][72][89]).

This study is the dated record of that year, built only from sources opened on 12 and 13 November 2026. Ten parts cover the timeline, the vulnerability record, mass exploitation and DDoS, malware, the state record, crime and prosecutions, law and policy, cryptography and standards, the industrial record and the defender view. An eleventh part maps the record to MITRE frameworks.

2000 has CVE ids, but several of the records checked here were published after the event, and NVD gives no specific CWE for any of the year's flaws checked here (Confirmed [5][8][10][11][12]). No CWE id existed before 2006 and no CAPEC id before 2007 (Confirmed [92][93]). ATT&CK did not exist in 2000 (Inferred). Every ATT&CK Enterprise, CWE, CAPEC and D3FEND id in Part 11 is therefore this study's later mapping (Inferred). The exception is the ICS table, where ATT&CK itself lists the techniques for the Maroochy campaign (Confirmed [51]).

Evidence grades: CERT/CC advisories and incident notes, vendor bulletins, CVE and NVD records, statutes, Federal Register notices, court judgments, Justice Department releases and archived CCIPS pages, presidential documents, congressional hearings, GAO testimony, SEC filings, European Parliament records, NIST, ISO and RFC Editor records, researchers' own technical findings, MITRE's own pages and the library's data files are **Confirmed**. Facts that rest on newspapers, broadcasters, EPIC's account of its own litigation, or a researcher's relay of an investigation it did not run are **Reported** and attributed. A query or data check this study ran itself is **Demonstrated**. Where the study draws its own conclusion it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2000, plus the boundary records that open or close a 2000 event: the Omega timebomb (1996), Gregory's fraud (from 1997), Moonlight Maze (from 1996), Iffih, c0mrade and HV2K (1999), and the 2001 to 2003 sentences, appeal and EP vote |
| CERT/CC output | 22 advisories, CA-2000-01 (3 Jan) to CA-2000-22 (12 Dec); incident notes cited here run IN-2000-01 (28 Feb) to IN-2000-10 (15 Sep) (Confirmed [1][2]) |
| Exploited in the wild, per CERT | BIND NXT (CA-2000-03, 26 Apr); wu-ftpd site exec (CA-2000-13, 7 Jul); rpc.statd (CA-2000-17, 18 Aug); IRIX telnetd (IN-2000-09, 31 Aug); rpc.statd and wu-ftpd at scale (IN-2000-10, 15 Sep); LPRng (CA-2000-22, 12 Dec) (Confirmed [1][2]) |
| Detection guidance | MS00-078 (17 Oct): IIS logs show successful exploitation as a successful GET climbing out of the web root; no in-the-wild exploitation stated (Confirmed [14]) |
| Malware | Windows trinoo "service.exe" (from 16 Feb); network.vbs (3 Mar); 911 worm (4 Apr); Love Letter (4 May; more than 500,000 systems reported by 8 May); BubbleBoy and kak (6 Jun); Timofonica and CoolNote (19 Jun) (Confirmed [1][2]) |
| DDoS | Stacheldraht (3 Jan); February attacks on Yahoo, Amazon.com, eBay, Buy.com and CNN (7 to 8 Feb, Reported); DNS amplification (28 Apr); mstream (late Apr) (Confirmed [1][2]; Reported [45][46]) |
| Industrial | Maroochy Shire sewerage system, 9 Feb to 23 Apr; ATT&CK for ICS campaign C0020 (Confirmed [50][51]) |
| Microsoft | Bulletins MS00-001 to MS00-100 (22 Dec); 100 inferred from the numbering (Demonstrated [15]) |
| State record | Moonlight Maze tail (Reported); ECHELON inquiry referral (5 Jul); Carnivore public (11 Jul, Reported) and reviewed (8 Dec); Russia's Information Security Doctrine (9 Sep); FBI remote access to Russian computers (Nov) (Confirmed [60][63][65][29]; Reported [53][64]) |
| Prosecutions | Iffih charged (23 Feb); Gregory plea (12 Apr) and sentence (6 Sep); Mafiaboy arrest (15 Apr); Lloyd verdict (9 May); Miffleton sentence (24 Jul); Bloomberg extortion arrests (10 Aug); c0mrade sentence (21 Sep); Sanford indicted (10 Oct) and plea (6 Dec); Diekman custody (21 Sep) and plea (6 Nov); Gorshkov and Ivanov arrests (10 Nov); Torricelli plea (1 Dec) (Confirmed [16] to [30], [35]) |
| Law and policy | National plan (7 Jan); encryption export rule (14 Jan); PIPEDA (13 Apr); GLB privacy rule (24 May); Reg S-P (29 Jun); ESIGN (30 Jun); Safe Harbor (24 Jul); UK ECA, Terrorism Act, RIPA; GISRA (30 Oct); OMB A-130 (12 Dec); CIPA (21 Dec); HIPAA privacy rule (28 Dec) (Confirmed [38][66][81][67][68][69][70][78][79][80][43][74][76][77]) |
| Cryptography and standards | FIPS 186-2 (27 Jan); RFC 2817, 2818, 2827 (BCP 38) and 2828 (May); SP 800-23 (Aug); RSA patent expiry (20 Sep); Rijndael chosen (2 Oct); SP 800-25 (Oct); ISO/IEC 17799 (Dec) (Confirmed [82][83][84][85][86][87][88][89][71][72][90]) |
| This study's MITRE binding | 31 ATT&CK Enterprise technique rows, every one a later mapping; 12 ATT&CK for ICS rows listed by ATT&CK for C0020; one campaign object (C0020); no group or software object; 5 CWE ids plus NVD-CWE-Other; 8 CAPEC entries; D3FEND pairings from the library's data; two Navigator layers (Part 11) |

### Key findings

- **Compromised servers were the raw material.** CA-2000-01 says the DDoS tools depend on intruders first compromising hosts, and the year's server advisories (BIND, wu-ftpd, rpc.statd, LPRng, IRIX telnetd) describe compromises of the kind CA-2000-01 says the tools depend on (Confirmed [1][2]); that these hosts fed the agent pools is this study's reading (Inferred). The February attacks were the visible end of a pipeline that CERT had described in January (Inferred).
- **Defaults contributed.** IN-2000-10 says insecure default configurations that enabled rpc.statd contributed to hundreds of compromises in single incidents; CA-2000-17 notes that rpc.statd is often installed by default (Confirmed [1][2]). CERT added that intruders may be developing worm-like tools (Confirmed [2]).
- **Love Letter succeeded through trust and a hidden extension, not a new flaw.** CA-2000-04 lists mail to the whole Outlook address book, IRC, shared file systems and Usenet as its paths. IN-2000-07 names Love Letter as the first major attack to hide a script behind a double file extension (Confirmed [1][2]; that it used no new flaw is Inferred).
- **Coordination was the weakness GAO named.** GAO told Congress that NIPC issued a brief notice at 11:00 am on 4 May and CERT/CC posted its advisory at about 9:30 pm. GAO also said the virus highlighted the need for better alert and coordination capabilities (Confirmed [41][42]).
- **A control system was attacked by someone who knew it.** Boden had supervised the Maroochy installation for about two years, and when stopped he had a Hunter Watertech PDS Compact 500 and a laptop with the company's configuration software (Confirmed [50]). The insider-knowledge pattern repeats in the Omega Engineering timebomb, decided the same year (Confirmed [21]).
- **The case outran the law.** The Philippines enacted its Electronic Commerce Act on 14 June, after Love Letter (Confirmed [49]). The New York Times reported that charges against the suspect were dismissed in August for insufficient evidence, and that the new law could not apply to a program released before it passed (Reported [47]).
- **The state record is a visibility gap.** No ATT&CK group checked here, and none of the library's actor studies, dates state intrusion activity to calendar 2000. The year's state record is surveillance law and policy, plus the tail of Moonlight Maze (Confirmed [55][57][103][104][105]; Inferred).
- **The FBI collected evidence across a border over the Internet.** After the Seattle arrests it obtained access via the Internet to two computers in Russia and copied their data, then examined it under a US magistrate's warrant; the court denied the challenge in May 2001 (Confirmed [29]).

### Top recommendations

1. **Patch the server you forgot you were running.** CA-2000-03 says machines not intended as DNS servers were compromised through BIND, and IN-2000-10 points to rpc.statd enabled by default (Confirmed [1][2]). Inventory listening services and turn off the ones a host does not need.
2. **Filter spoofed traffic at the edge.** CA-2000-01 urged RFC 2267 ingress filtering; RFC 2827 (BCP 38), published in May 2000, replaced it (Confirmed [1][83]). The same filtering would have limited the spoofed DNS requests of IN-2000-04 (Inferred [2]).
3. **Show file extensions and turn off script hosts that users do not need.** CERT's Love Letter defenses were updated anti-virus, disabling Windows Scripting Host and Active Scripting in Internet Explorer, disabling automatic IRC DCC, filtering at the mail transfer agent and care with attachments (Confirmed [1]). IN-2000-07 explains why hidden extensions mattered (Confirmed [2]).
4. **Do not rely on subject-line filters.** CERT warned that they fail once the subject changes, and GAO, citing JTF-CND, reported at least 14 variants by the weekend (Confirmed [1][41]).
5. **Close open shares.** network.vbs and the 911 worm spread through Windows shares exposed to the Internet (Confirmed [2]).
6. **Know which patch already covers a new flaw.** MS00-078 needed no new patch because the August MS00-057 patch already eliminated it (Confirmed [14][13]). A site that had applied MS00-057 was already protected; one that had not was open to a flaw that Microsoft says shows in IIS logs as a successful request (Confirmed [14]; Inferred).
7. **Revoke access when people leave, and control engineering equipment.** Boden used stolen engineering equipment and knowledge of a system he had supervised, and Lloyd's timebomb ran two weeks after he was fired (Confirmed [50][51][21]).
8. **Build the reporting path before the outbreak.** GAO's timeline shows about ten and a half hours between NIPC's first notice and CERT/CC's advisory on 4 May (Confirmed [41]; Inferred).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, surveillance, cryptography, standards and policy dated to 2000, plus the later records that open, close or explain a 2000 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, numbers as the source states them. Sources were opened on 12 and 13 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a CERT/CC advisory or incident note as SEI publishes it, a vendor bulletin, a CVE or NVD record, a statute, a Federal Register notice, a court judgment, a Justice Department release or an archived CCIPS page, a presidential document, a congressional hearing, GAO testimony, an SEC filing, a European Parliament record, a NIST, ISO or RFC Editor record, a researcher's own technical finding, a live ATT&CK page, or the library's data files as the record of what the library holds |
| Reported | Only a secondary source was opened: CNN, the New York Times, PBS Frontline, EPIC's account of its own FOIA case, or researchers relaying victims and attribution from an investigation they did not run. The source is named in the text |
| Demonstrated | This study ran the query or opened the data itself and saw the result (the Microsoft bulletin probes, the library's data files and page tree) |
| Inferred | The study's own reasoning, labelled where it appears. Every ATT&CK Enterprise, CWE and CAPEC id bound to a 2000 event is Inferred as to the binding |

Limits a reader should know:

- **CVE dates lag events.** NVD's published date for CVE-2000-0884 is 19 December 2000, two months after Microsoft's MS00-078 bulletin of 17 October. NVD dates are list-entry dates, not disclosure dates (Confirmed [10]). CVE.org's datePublished values differ again: 22 January 2001 for CVE-2000-0884, 7 May 2001 for CVE-2000-0573 and 13 October 2000 for CVE-2000-0666 (Confirmed [108][109][9]). A count of "2000 CVEs" is an artifact of the databases, not a measure of the year (Inferred).
- **No contemporaneous ATT&CK, CWE or CAPEC.** MITRE began categorizing weaknesses in 1999; the first CWE List came in 2006 and CAPEC in 2007 (Confirmed [92][93]). ATT&CK did not exist in 2000 (Inferred).
- **The CERT text.** SEI's compilations of the 2000 CERT advisories and incident notes are the texts for every CA-2000 and IN-2000 item cited here [1][2], with SEI's 2000 advisory index for the titles [3][4]. CERT/CC's 2000 incident statistics were not opened, so this study gives no 2000 incident count.
- **Microsoft's count.** MS00-100 (Malformed Web Form Submission) is dated 22 December 2000, and MS00-101 and MS00-102 return 404 on Microsoft Learn; the total of 100 is inferred from the numbering (Demonstrated [15]).
- **The press record.** The February 2000 outages at Yahoo, Amazon.com, eBay, Buy.com and CNN, the CD Universe extortion and the dismissal of the Love Letter charges rest on CNN and the New York Times and are graded Reported [45][46][47][48]. The private and foreign Love Letter victims GAO names come from media reports, and GAO itself says the federal penetrations were "reportedly" so; those are Reported [41].
- **What was not checked.** The October 2000 Microsoft corporate network intrusion, the Western Union card exposure, Raphael Gray ("Curador"), the Israeli-Palestinian defacement campaigns from October 2000 and the MITRE 2008 Maroochy case study that ATT&CK cites were not opened from a primary. They are left out, or limited to what an opened record says. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1996 onward (frame) | Moonlight Maze: someone goes through military, research and university networks, mainly in the United States; named victims include the Pentagon, NASA and the Department of Energy. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Espionage | Reported | [52] |
| late 1996 | Earliest apparent compile dates of recovered Moonlight Maze samples, mostly for SPARC Solaris and MIPS IRIX | Espionage | Confirmed | [52] |
| 1996-07-30 | Timothy Allen Lloyd, two weeks after being fired, activates a software timebomb that deletes all of Omega Engineering's manufacturing programs; damage and losses above $10 million | Insider | Confirmed | [21] |
| 1997 to 1999-05 | Patrick Gregory ("MostHateD") uses stolen teleconference access from AT&T, MCI, Sprint, Latitude and others to coordinate attacks | Crime | Confirmed | [19] |
| 1998-03 to about early 2000 | Moonlight Maze probing runs "for nearly two years" by PBS Frontline's account; DoD traced it to a mainframe in the former Soviet Union | Espionage | Reported | [53] |
| 1998 to 1999-03 | The UK relay HRTest serves as a monitoring point for about six months; operators abandon it after the first publicity in early March 1999 | Espionage | Confirmed | [52] |
| 1999-04 to 1999-08 | Ikenna Iffih reaches a Defense Logistics Agency computer through a hijacked account and telnet proxy, damages ISP Zebra Marketing Online Services, then controls a NASA research web server and installs a sniffer | Intrusion | Confirmed | [18] |
| 1999-06 and 1999-08-23 to 10-27 | c0mrade enters 13 NASA Marshall computers and takes $1.7 million of ISS software; later backdoors a router used by DTRA and intercepts more than 3,300 messages | Intrusion | Confirmed | [27] |
| 1999-11 to 2000-01 | Robert Russell Sanford and HV2K deface USPS, State of Texas, Canadian Department of Defence and Glinn Publishing systems | Defacement | Confirmed | [16] |
| 1999-12-03 | Boden's resignation from Hunter Watertech takes effect | Industrial | Confirmed | [50] |
| 2000-01 (mid) | Hunter Watertech completes the Maroochy installation: about 150 pumping stations on a private two-way radio network | Industrial | Confirmed | [50] |
| 2000-01-03 | CA-2000-01 (CERT/CC and FedCIRC): Stacheldraht on multiple compromised hosts; one organization sees more than 100 connections consistent with agents | DDoS | Confirmed | [1][3] |
| 2000-01-07 | The President announces the national plan to defend America's cyberspace, the product of a three-year effort | Policy | Confirmed | [38] |
| 2000-01-10 | Attorney General Reno proposes a 24/7 state cyber-crime network, regional forensic labs and a law-enforcement clearinghouse | Policy | Confirmed | [31] |
| 2000-01-10 | New York Times: an intruder tried to extort $100,000 from CD Universe and released card numbers after refusal. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Extortion | Reported | [48] |
| 2000-01-14 | BXA "Revisions to Encryption Items" (65 FR 2492) | Cryptography | Confirmed | [66] |
| 2000-01-27 | NIST publishes FIPS 186-2, Digital Signature Standard | Cryptography | Confirmed | [82] |
| 2000-01-31 and 02-04 | FBI declaration and a C.D. Cal. order on a Carnivore installation at Earthlink, per EPIC's list of FOIA releases | Surveillance | Reported | [64] |
| 2000-02-02 | CA-2000-02, malicious HTML tags in client web requests (cross-site scripting); no exploitation reported | Vulnerability | Confirmed | [1] |
| 2000-02-07 | Yahoo and its companion sites unreachable for about three hours. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | DDoS | Reported | [45] |
| 2000-02-08 | Denial-of-service attacks on Amazon.com, eBay, Buy.com and CNN Interactive; CNN.com slowed for nearly two hours | DDoS | Reported | [46] |
| 2000-02-09 to 04-23 | Boden alters data at Maroochy pumping stations, causing malfunctions (Crown case); ATT&CK C0020 first and last seen February and April 2000 | Industrial | Confirmed | [50][51] |
| 2000-02-15 | White House meeting with industry leaders and security experts; $2 billion requested, $9 million at once, industry to create an information-sharing mechanism | Policy | Confirmed | [39] |
| 2000-02-16 | First reports of "service.exe", a Windows version of trinoo, with Back Orifice on the same machines (IN-2000-01, 28 Feb) | DDoS | Confirmed | [2] |
| 2000-02-23 | Iffih charged in Boston | Crime | Confirmed | [18] |
| 2000-02-29 | Hunter Watertech configuration software re-installed on the laptop later found in Boden's car | Industrial | Confirmed | [50] |
| 2000-03-02 | Senate Governmental Affairs hearing "Cyber Attack: Is the Government Safe?" with Kevin Mitnick. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Government | Confirmed | [40] |
| 2000-03-03 | IN-2000-02: exploitation of Windows shares exposed to the Internet; network.vbs scans random /24 blocks | Malware | Confirmed | [2] |
| 2000-03-09 | "The Electronic Frontier", report of the President's Working Group on Unlawful Conduct on the Internet | Policy | Confirmed | [32] |
| 2000-03-13 | CCIPS launches www.cybercrime.gov | Policy | Confirmed | [33] |
| 2000-03-16 | Investigator talks to a bogus "pump station 14" at Maroochy and is shut out of the network briefly | Industrial | Confirmed | [50] |
| 2000-04-04 | IN-2000-03: the 911 worm spreads through unprotected Windows 98 shares; only second-hand reports | Malware | Confirmed | [2] |
| 2000-04-05 | Reno addresses a law enforcement and industry conference at Stanford | Policy | Confirmed | [34] |
| 2000-04-05 | FBI "FISA Mistakes" memo, which EPIC says describes Carnivore interfering with a bin Laden investigation | Surveillance | Reported | [64] |
| 2000-04-12 | Gregory pleads guilty in N.D. Tex. | Crime | Confirmed | [19] |
| 2000-04-13 | Canada's PIPEDA (S.C. 2000, c. 5) assented to | Law | Confirmed | [81] |
| 2000-04-15 | RCMP arrests "mafia boy" in Montreal over the CNN attack (AG statement, 19 Apr). Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime | Confirmed | [35] |
| 2000-04-23 | Alarms disabled at four Maroochy pumping stations using station 4's identity; Boden's vehicle stopped at about 10 pm | Industrial | Confirmed | [50] |
| 2000-04-26 | CA-2000-03: continuing daily compromises of unpatched BIND through the NXT flaw | Mass exploitation | Confirmed | [1] |
| 2000-04-28 | IN-2000-04: nameservers used for spoofed-source amplification floods | DDoS | Confirmed | [2] |
| 2000-04 (late) | mstream DDoS tool found (IN-2000-05, 2 May) | DDoS | Confirmed | [2] |
| 2000-05 | RFC 2827 (BCP 38), RFC 2818, RFC 2817 and RFC 2828 published | Standards | Confirmed | [83][84][85][86] |
| 2000-05-04 | Love Letter first reported in Asia; NIPC notice at 11:00 am; CERT/CC advisory CA-2000-04 at about 9:30 pm | Malware | Confirmed | [1][41] |
| 2000-05-08 | More than 650 sites report more than 500,000 affected systems by 5 pm EDT | Malware | Confirmed | [1] |
| 2000-05-08 | Internet Fraud Complaint Center opens | Policy | Confirmed | [36] |
| 2000-05-09 | Lloyd convicted by a jury in D.N.J. | Crime | Confirmed | [21] |
| 2000-05-10 | GAO testimony T-AIMD-00-171 on Love Letter | Government | Confirmed | [41] |
| 2000-05-12 to 06-19 | CA-2000-05 to CA-2000-12: Netscape SSL validation, Kerberos overflows, Office UA control, PGP 5.0 keys, IE warnings, MIT Kerberos DoS, HHCtrl | Vulnerability | Confirmed | [1] |
| 2000-05-15 | AES Round 2 comments close | Cryptography | Confirmed | [71] |
| 2000-05-18 | GAO testimony T-AIMD-00-181 on alert and coordination | Government | Confirmed | [42] |
| 2000-05-24 | FTC final Gramm-Leach-Bliley privacy rule | Law | Confirmed | [67] |
| 2000-05-25 | UK Electronic Communications Act 2000 | Law | Confirmed | [78] |
| 2000-06-06 | IN-2000-06: BubbleBoy and kak exploit the Scriptlet.Typelib control through HTML mail | Malware | Confirmed | [2] |
| 2000-06-14 | Philippine Republic Act 8792, the Electronic Commerce Act | Law | Confirmed | [49] |
| 2000-06-19 | IN-2000-07: hidden file extensions (Love Letter, Timofonica, CoolNote, a downloader) | Malware | Confirmed | [2] |
| 2000-06-21 | IN-2000-08: chat clients and network security | Defender | Confirmed | [2] |
| 2000-06-29 | SEC adopts Regulation S-P | Law | Confirmed | [68] |
| 2000-06-30 | ESIGN, Pub. L. 106-229 | Law | Confirmed | [69] |
| 2000-07-05 | European Parliament announces the committee referral on ECHELON | Surveillance | Confirmed | [60] |
| 2000-07-07 | CA-2000-13: wu-ftpd site exec (CVE-2000-0573) and setproctitle() format strings; remote root exploitation reported | Vulnerability | Confirmed | [1][5] |
| 2000-07-11 and 12 | Carnivore widely reported; EPIC files a FOIA request the next day | Surveillance | Reported | [64] |
| 2000-07-20 | UK Terrorism Act 2000, with serious interference with an electronic system inside the definition | Law | Confirmed | [79] |
| 2000-07-24 | Andrew Miffleton sentenced to 21 months | Crime | Confirmed | [23] |
| 2000-07-24 | Commerce issues the Safe Harbor Privacy Principles | Law | Confirmed | [70] |
| 2000-07-26 | CA-2000-14: Outlook cache bypass (MS00-046, CVE-2000-0621) | Vulnerability | Confirmed | [1][111] |
| 2000-07-26 | Jason Diekman ("Shadow Knight") charged | Crime | Confirmed | [24] |
| 2000-07-28 | UK Regulation of Investigatory Powers Act 2000 | Law | Confirmed | [80] |
| 2000-08-02 | Emergency hearing in EPIC's Carnivore FOIA case | Surveillance | Reported | [64] |
| 2000-08-10 | MS00-057, IIS file permission canonicalization (CVE-2000-0770) | Vulnerability | Confirmed | [13] |
| 2000-08-10 | Oleg Zezov and Igor Yarimaka arrested in London over a $200,000 demand to Bloomberg | Extortion | Confirmed | [26] |
| 2000-08-10 to 24 | CA-2000-15, -16 and -18: Netscape Java, IE OBJECT tag, PGP ADKs | Vulnerability | Confirmed | [1] |
| 2000-08-18 | CA-2000-17: rpc.statd exploited (CVE-2000-0666) | Vulnerability | Confirmed | [1][7] |
| 2000-08-21 | Philippine charges in the Love Letter case dismissed | Crime | Reported | [47] |
| 2000-08 | NIST SP 800-23 published | Standards | Confirmed | [87] |
| 2000-08-31 | IN-2000-09: IRIX telnetd actively exploited | Mass exploitation | Confirmed | [2] |
| 2000-09-06 | Gregory sentenced to 26 months | Crime | Confirmed | [20] |
| 2000-09-09 | Russia's Information Security Doctrine approved (No. Pr-1895) | Policy | Confirmed | [65] |
| 2000-09-15 | IN-2000-10: widespread automated exploitation of rpc.statd and wu-ftpd | Mass exploitation | Confirmed | [2] |
| 2000-09-20 | RSA patent US 4,405,829 anticipated expiration | Cryptography | Confirmed | [89] |
| 2000-09-21 | c0mrade sentenced to six months, the first juvenile hacker to serve time. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Confirmed | [27][28] |
| 2000-09-21 | Diekman taken into federal custody | Crime | Confirmed | [24] |
| 2000-09-26 | DOJ selects IIT Research Institute to review Carnivore | Surveillance | Confirmed | [37] |
| 2000-10 | NIST SP 800-25 published | Standards | Confirmed | [88] |
| 2000-10-02 | Rijndael announced as the proposed AES | Cryptography | Confirmed | [71][72] |
| 2000-10-10 | Sanford indicted in Dallas County | Crime | Confirmed | [16] |
| 2000-10-17 | MS00-078, IIS 4.0 and 5.0 Web Server Folder Traversal (CVE-2000-0884) | Vulnerability | Confirmed | [14] |
| 2000-10-24 and 25 | Sun Security Bulletin 198 and CA-2000-19: two Sun browser certificates possibly compromised and revoked | PKI | Confirmed | [1] |
| 2000-10-30 | Government Information Security Reform Act, in Pub. L. 106-398 | Law | Confirmed | [43] |
| 2000-11-06 | Diekman pleads guilty (release dated 7 Nov) | Crime | Confirmed | [25] |
| 2000-11-10 | Gorshkov and Ivanov arrested in Seattle after a recorded meeting with the FBI's undercover "Invita". Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime | Confirmed | [29] |
| 2000-11 (days later) | FBI obtains access via the Internet to two computers in Russia and copies their data | State | Confirmed | [29] |
| 2000-11-13 | CA-2000-20: BIND 8.2 to 8.2.2-P6 DoS bugs (CVE-2000-0887, CVE-2000-0888); GLB privacy rule and Reg S-P take effect | Vulnerability; Law | Confirmed | [1][11][67][68] |
| 2000-11-30 | CA-2000-21: TCP/IP stack resource exhaustion ("Naptha") | Vulnerability | Confirmed | [1] |
| 2000-12 | Egghead.com breached by hackers, per its 10-K. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Breach | Confirmed | [44] |
| 2000-12 | ISO/IEC 17799:2000 published; 29 organizations have declared CVE compatibility for 43 products | Standards | Confirmed | [90][91] |
| 2000-12-01 | Raymond Torricelli pleads guilty to breaking into two NASA JPL computers in 1998, and to intercepting usernames and passwords on a San Jose State University computer | Crime | Confirmed | [22] |
| 2000-12-06 | Sanford pleads guilty to six felony breach counts and one aggravated theft count | Crime | Confirmed | [17] |
| 2000-12-08 | IITRI final report on Carnivore | Surveillance | Confirmed | [63] |
| 2000-12-12 | CA-2000-22: LPRng format strings; probing of 515/tcp and some compromises | Vulnerability | Confirmed | [1][12] |
| 2000-12-12 | OMB revises Circular A-130 | Policy | Confirmed | [74] |
| 2000-12-19 | NVD published date of CVE-2000-0884 | Vulnerability | Confirmed | [10] |
| 2000-12-20 | Executive Order 13181 on health information in oversight investigations | Law | Confirmed | [75] |
| 2000-12-21 | Children's Internet Protection Act, in Pub. L. 106-554 | Law | Confirmed | [76] |
| 2000-12-22 | MS00-100, Microsoft's last bulletin of the year | Vulnerability | Demonstrated | [15] |
| 2000-12-28 | HHS HIPAA privacy rule published | Law | Confirmed | [77] |
| 2001-01-09 (boundary) | NVD publishes CVE-2000-1039 (Naptha) | Vulnerability | Confirmed | [110] |
| 2001-05-23 (boundary) | Chief Judge Coughenour denies the challenge to the FBI's remote copying | State | Confirmed | [29] |
| 2001-07-03 and 09-05 (boundary) | ECHELON report A5-0264/2001 tabled; Parliament adopts the resolution 367 to 154, 34 abstentions | Surveillance | Confirmed | [60][62] |
| 2001-10-31 (boundary) | Boden sentenced; longest term two years | Industrial | Confirmed | [50] |
| 2001-11-26 (boundary) | FIPS 197 (AES) published | Cryptography | Confirmed | [73] |
| 2002-05-10 (boundary) | Queensland Court of Appeal sets aside counts 21 to 26 and refuses leave on sentence | Industrial | Confirmed | [50] |
| 2002-10-04 (boundary) | Gorshkov sentenced to 36 months | Crime | Confirmed | [29] |
| 2003 (boundary) | The story of Moonlight Maze's successor, "Storm Cloud", leaks | Espionage | Reported | [52] |
| 2003-07-25 (boundary) | Ivanov sentenced to 48 months | Crime | Confirmed | [30] |
| 2016-12-05 (boundary) | Kremlin Decree No. 646 voids the 2000 doctrine | Policy | Confirmed | [65] |
| 2017-04-03 (boundary) | Kaspersky GReAT and King's College London publish "Penquin's Moonlit Maze" | Espionage | Confirmed | [52] |

## Part 2: the vulnerability record

### The 22 advisories

CERT/CC issued 22 advisories in 2000 (Confirmed [1][3]). Grouped by topic (the grouping is this study's; the advisory texts are SEI's compilation) (Confirmed [1]; grouping Inferred):

- **Denial of service and DDoS tools.** CA-2000-01 (3 Jan), with FedCIRC: DDoS tools depend on compromising hosts first; patch and apply RFC 2267 ingress filtering. CA-2000-20 (13 Nov): BIND 8.2 to 8.2.2-P6 "zxfr" (CVE-2000-0887) and "srv" (CVE-2000-0888) bugs. CA-2000-21 (30 Nov): TCP/IP stack resource exhaustion that BindView RAZOR named Naptha (CAN-2000-1039).
- **Server compromise.** CA-2000-03 (26 Apr): regular daily reports of BIND compromises through the 1999 NXT flaw (CA-99-14), including machines not meant to be DNS servers, with inetd backdoors, modified startup files and trojaned sshd and login. CA-2000-13 (7 Jul): wu-ftpd 2.6.0 and earlier "site exec" and missing setproctitle() format strings, with remote root exploitation reported. The advisory says the site exec flaw appears to have been in wu-ftpd since version 2.0. CA-2000-17 (18 Aug): rpc.statd passes user data to syslog() as a format string, is installed by default in several Linux distributions and was being exploited. CA-2000-22 (12 Dec): LPRng format strings reachable on 515/tcp, with extensive probing and some compromises.
- **Malicious code.** CA-2000-04 (4 May, revised 9 May): Love Letter.
- **Web and client software.** CA-2000-02 (2 Feb): malicious HTML tags in client web requests, "also described as cross-site scripting", published jointly by CERT/CC, DoD-CERT, JTF-CND, FedCIRC and NIPC, with no exploitation reported at publication. CA-2000-05 (12 May): Netscape Navigator 4.72, 4.61 and 4.07 improperly validate SSL sessions. CA-2000-07 (24 May): the Office 2000 UA ActiveX control marked safe for scripting. CA-2000-08 (26 May) and CA-2000-10 (6 Jun): inconsistent warnings in Netscape and IE. CA-2000-12 (19 Jun): the HHCtrl control lets local CHM files execute code, with an incomplete Microsoft patch. CA-2000-14 (26 Jul): the Outlook and Outlook Express cache bypass, MS00-046, which lets HTML mail read and store local files (CVE-2000-0621; Confirmed [111]). CA-2000-15 (10 Aug): Netscape Java applets read protected resources. CA-2000-16 (11 Aug): IE Script, Access and OBJECT tag.
- **Authentication and cryptography.** CA-2000-06 (17 May): Kerberos authenticated-service buffer overflows allowing remote root and possible KDC compromise. CA-2000-11 (9 Jun): MIT Kerberos DoS. CA-2000-09 (30 May): PGP 5.0 weak key generation. CA-2000-18 (24 Aug): PGP may encrypt to unauthorized Additional Decryption Keys. CA-2000-19 (25 Oct): Sun's revocation of two possibly compromised browser certificates.

### What the record says about attackers

In five cases a CERT text from 2000 says the flaw was being used against real systems: BIND NXT, wu-ftpd site exec, rpc.statd, IRIX telnetd and LPRng (Confirmed [1][2]). Microsoft's MS00-078 adds that IIS logs show successful exploitation as a successful GET request whose path climbs out of the web root (Confirmed [14]). For CA-2000-02 CERT said no malicious exploitation had been reported at publication (Confirmed [1]). For the Kerberos, PGP, Netscape and BIND DoS advisories this study read no statement of exploitation, and it does not claim there was none (Inferred [1]).

### Microsoft's year

Microsoft's numbered bulletins for 2000 run from MS00-001 to MS00-100 (22 Dec); 100 is inferred from the numbering, since MS00-101 and MS00-102 return 404 (Demonstrated [15]). Three bulletins matter most to this record:

- **MS00-046 (26 Jul).** The Outlook and Outlook Express cache bypass, carried by CERT as CA-2000-14 (CVE-2000-0621) (Confirmed [1][111]).
- **MS00-057 (10 Aug).** IIS 4.0 and 5.0 File Permission Canonicalization (CVE-2000-0770) (Confirmed [13]).
- **MS00-078 (17 Oct).** IIS 4.0 and 5.0 Web Server Folder Traversal (CVE-2000-0884), reported by Rain Forest Puppy. A canonicalization error let a malformed URL reach files on the same logical drive as IUSR_machinename, a member of Everyone and Users, so operating system commands could run. No new patch was issued, because the August MS00-057 patch, released for a different bug, already eliminated it (Confirmed [14]). Its hardening advice: web folders on a non-system drive, samples and unneeded features removed, command-line utilities restricted, no IUSR write access (Confirmed [14]). NVD describes the flaw as Unicode-encoded malformed URLs and lists NVD-CWE-Other (Confirmed [10]).

### The CVE record

The CVE List launched publicly in September 1999 with 321 records; by December 2000, 29 organizations had declared CVE compatibility for 43 products (Confirmed [91]). The 2000 advisories still cite candidate ids: CA-2000-17 cites CAN-2000-0666, now CVE-2000-0666, and CA-2000-22 cites CAN-2000-0917 (Confirmed [1][9][12]). NVD gives no specific CWE for any of the year's exploited flaws checked here. CVE-2000-0573, -0666, -0884, -0887 and -0917 are NVD-CWE-Other, and CVE-2000-0888 is NVD-CWE-noinfo (Confirmed [5][6][8][10][11][12]).

## Part 3: mass exploitation and the DDoS networks

### The agent pools

CA-2000-01 opened the year by stating the dependency plainly: DDoS tools need compromised hosts, which intruders take through known vulnerabilities. Stacheldraht had been found on multiple compromised hosts at several organizations, one of which saw more than 100 connections consistent with Stacheldraht agents (Confirmed [1]). CERT's advice was to patch and to apply RFC 2267 ingress filtering (Confirmed [1]).

The incident notes track the pool growing (Confirmed [2]):

- **Windows agents (IN-2000-01, 28 Feb).** From 16 February CERT received reports of "service.exe", a Windows version of trinoo, with Back Orifice and other remote administration tools found on the same machines.
- **Nameserver amplification (IN-2000-04, 28 Apr).** Intruders sent spoofed-source UDP DNS requests to many nameservers so that the larger responses flooded the victim.
- **mstream (IN-2000-05, 2 May).** A handler-and-agent flooding tool found from late April on compromised Unix systems; the agent forges packet headers and needs root.
- **IRIX telnetd (IN-2000-09, 31 Aug).** Active exploitation for remote root (SGI Security Advisory 20000801-01-P).
- **rpc.statd and wu-ftpd at scale (IN-2000-10, 15 Sep).** Automated tools, hundreds of compromised hosts in single incidents, a large majority running Red Hat Linux, wide scanning of the sunrpc and ftp ports (111 and 21), insecure default configurations contributing, and a warning that intruders may be developing worm-like tools.

### The February attacks (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for the February 2000 attacks and the Mafiaboy arrest (Confirmed [102]). In brief: Yahoo and its companion sites (Yahoo Mail, GeoCities) were unreachable for about three hours on Monday 7 February, and on Tuesday 8 February attacks hit Amazon.com, eBay, Buy.com and CNN Interactive, slowing CNN.com for nearly two hours (Reported [45][46]). The President met industry and security experts at the White House on 15 February (Confirmed [39]). The Attorney General's statement of 19 April says the attacks targeted sites including Yahoo, eBay and CNN.com. It says the RCMP arrested a 15-year-old using the name "mafia boy" in Montreal on Saturday 15 April, charged over the attack on CNN's website, after joint FBI, DOJ and RCMP work (Confirmed [35]). The statement ties the arrest to the CNN attack only (Confirmed [35]; Inferred).

## Part 4: malware

### Love Letter (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Love Letter (Confirmed [102]). The 2000 record in brief:

- **What it did.** CA-2000-04 says the VBScript worm needs Windows Scripting Host to run. It mails itself to every entry in the Outlook address book and spreads through mIRC DCC, shared file systems and Usenet. It overwrites script and image files with copies of itself, so recovery may be impossible, and sets mp3 and mp2 originals hidden. It writes Run and RunServices registry keys, changes the Internet Explorer start page and points it at a further executable to download (Confirmed [1]).
- **How fast.** GAO says it was first reported in Asia on 4 May, and by 6 pm CERT/CC had over 400 direct reports involving more than 420,000 hosts. JTF-CND identified at least 14 variants by the weekend (Confirmed [41]). CERT's own count by 5 pm EDT on 8 May was more than 500,000 systems at more than 650 sites (Confirmed [1]).
- **Who was hit.** GAO says the worm "reportedly" penetrated at least 14 federal agencies (DOD, SSA, CIA, INS, DOE, USDA, Education, NASA) and the House and Senate. From media reports it also names AT&T, TWA, Ford, the IMF and the British Parliament. These are Reported (Reported [41]).
- **The response.** NIPC posted a brief notice at 11:00 am on 4 May and more at 10:00 pm; CERT/CC posted its advisory at about 9:30 pm (Confirmed [41]). A week later GAO told the Senate Banking subcommittee that the virus highlights the need for better alert and coordination (Confirmed [42]).
- **The prosecution that did not happen.** The Philippines approved the Electronic Commerce Act on 14 June, with Section 33(a) penalizing hacking and the introduction of computer viruses (Confirmed [49]). The New York Times reported on 22 August that charges against Onel A. de Guzman had been dismissed for insufficient evidence, and that the new law could not apply to a program released before it passed (Reported [47]).

### Shares, scripts and extensions

- **network.vbs (IN-2000-02, 3 Mar).** A malicious VBScript that scans random /24 address blocks for Windows shares exposed to the Internet and copies itself to open C shares (Confirmed [2]).
- **The 911 worm (IN-2000-03, 4 Apr).** A batch-file worm spreading through unprotected Windows 98 shares, subject of NIPC bulletin advis00-038. CERT had no direct reports of infection, only a few second-hand ones (Confirmed [2]).
- **BubbleBoy and kak (IN-2000-06, 6 Jun).** Email-borne VBScript programs that exploit the Scriptlet.Typelib ActiveX control, wrongly marked safe for scripting in Internet Explorer 4.0 and 5.0, through HTML mail rendered by IE (Confirmed [2]).
- **Hidden extensions (IN-2000-07, 19 Jun).** Windows hid known file extensions, so a script named with a double extension looked like a harmless file. CERT names Love Letter as the first major case, then a downloader, VBS/Timofonica and VBS/CoolNote (Confirmed [2]).
- **Chat clients (IN-2000-08, 21 Jun).** CERT's note on the security risks of instant messaging and IRC clients (Confirmed [2]).

### No ATT&CK software objects

The library's ATT&CK software data has no entry for Love Letter, Stacheldraht, trinoo, mstream, BubbleBoy, kak, Timofonica, Tribe Flood Network or the 911 worm (Confirmed [95]; Demonstrated [95]).

## Part 5: the state record

### Moonlight Maze: the tail (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Moonlight Maze. It covers 1996 to 1999, maps T1090.003 and T1584.004 to the 1998 to 1999 relays, and treats Turla and Penquin only as an unproven lineage (Confirmed [102]). What the record adds for 2000 is the question of when the campaign ended:

- Kaspersky GReAT and King's College London say that from 1996 someone was going through military, research and university networks, mainly in the United States; named victims include the Pentagon, NASA and the Department of Energy (Reported [52]). Their recovered binaries are mostly for SPARC Solaris and MIPS IRIX, apparently compiled as early as late 1996 (Confirmed [52]).
- Their visibility comes from the HRTest relay and covers 1998 to 1999, about six months of monitoring in all. The operators abandoned the relay after the first publicity in early March 1999 (Confirmed [52]). On the hacked relay servers, in more than a dozen cases, the operators ran a sniffer and saved its logs on the relay (Confirmed [52]).
- A successor operation, "Storm Cloud", followed the 1999 publicity, and its story leaked in 2003. The researchers held no Storm Cloud artefacts, so 2000 falls outside their direct visibility (Reported [52]).
- PBS Frontline, published 24 April 2003, says Moonlight Maze began in March 1998 and the probing ran "for nearly two years", into about early 2000. DoD traced it to a mainframe in the former Soviet Union; the sponsor is unknown and Russia denies involvement (Reported [53]). In a Frontline interview of 18 February 2003, John Hamre said "we do not know who did it" and suggested a front operation run by people with an intelligence background (Reported [54]).
- Penquin Turla is based on LOKI2, with its codebase mainly developed from 1999 to 2004. The researchers call a conclusive link to Turla "simply premature" and their argument circumstantial (Reported [52]).

ATT&CK records none of this. [Turla (G0010)](/mitre/groups/G0010.md) is attributed to Russia's FSB with activity "since at least 2004", and its page does not mention Moonlight Maze (Confirmed [55]). [Penquin (S0587)](/mitre/software/S0587.md) is a Linux RAT that Turla has used "since at least 2014", with no mention of Moonlight Maze or LOKI2 (Confirmed [56]). The library's [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) dates its earliest activity to FSB Snake development from late 2003, with APT28 and Turla active since at least 2004 (Confirmed [104]).

### Equation: not placed in 2000

Kaspersky's Equation Q&A says the group's computer network exploitation dates "back to 2001, and perhaps as early as 1996". It places EquationLaser around 2001 to 2003 or 2004 and EquationDrug from 2003 to 2013; nothing in it is dated 2000 (Confirmed [58]). Kaspersky's 2015 report says Equation has infected victims since 2001: one C&C domain was registered in August 2001, others as early as 1996, and the earliest samples were compiled in 2002 (Confirmed [59]). ATT&CK's [Equation (G0020)](/mitre/groups/G0020.md) lists four techniques (T1480.001, T1564.005, T1120 and T1542.002) and no aliases, software, campaigns or dates of activity (Confirmed [57]). The library's [United States study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) is the home for Equation and dates its earliest activity to the August 2001 domain (Confirmed [105]).

### ECHELON

The European Parliament announced the committee referral on the ECHELON interception system on 5 July 2000. Report A5-0264/2001 was tabled on 3 July 2001, and Parliament decided on 5 September 2001 (T5-0440/2001) (Confirmed [60]). The temporary committee, with Gerhard Schmid as rapporteur, found that, although there was no formal proof, a global interception system run by the USA, UK, Canada, Australia and New Zealand under the UKUSA Agreement was "no longer in doubt", and that it is used to intercept private and commercial communications (Confirmed [61]). It found no evidence that ECHELON was used to distort business competition. It relayed US-sourced figures that 5% of intelligence from non-open sources goes to economic intelligence, worth up to 7 billion dollars in contracts; the committee relays those figures, it does not establish them (Reported [61]). Parliament adopted the resolution by 367 votes to 154, with 34 abstentions (Confirmed [62]).

### Carnivore

EPIC's account is that Carnivore's existence was widely reported on 11 July 2000, that EPIC filed a FOIA request the next day, that Judge James Robertson held an emergency hearing on 2 August, and that in late January 2001 the FBI reported responsive pages numbering 1,756 (Reported [64]). EPIC's list of released records includes a C.D. Cal. order of 4 February 2000 on a Carnivore installation at Earthlink, an FBI declaration of 31 January 2000, and an FBI "FISA Mistakes" memo of 5 April 2000. EPIC says that memo describes Carnivore interfering with a bin Laden investigation; the scans themselves were not read (Reported [64]).

DOJ selected the IIT Research Institute on 26 September 2000 to conduct the independent technical review (Confirmed [37]). IITRI's final report is dated 8 December 2000, under DOJ contract 00-C-0328 (the copy opened is EPIC's) (Confirmed [63]). It says Carnivore is used under Title III, FISA and the pen-trap provisions (18 U.S.C. 3121 to 3124) (Confirmed [63]). It concluded that under a Title III order Carnivore gives no more than the order permits, and that under pen-trap authority it collects TO and FROM information plus message lengths. It also found that "Incorrectly configured, Carnivore can record any traffic it monitors", and recommended an audit trail and separate pen-register and full-content versions (Confirmed [63]).

### Russia's doctrine

Russia's Information Security Doctrine was approved on 9 September 2000 (No. Pr-1895); Kremlin Decree No. 646 of 5 December 2016 declared it void (Confirmed [65]).

### Remote access across a border

A few days after the November 2000 Seattle arrests of Gorshkov and Ivanov, the FBI "obtained access via the Internet" to two computers in Russia, copied voluminous data and examined it under a US magistrate's warrant. Chief Judge Coughenour denied the challenge in an order of 23 May 2001 (Confirmed [29]). Part 6 has the criminal case.

### The quiet year

None of the ATT&CK objects checked (G0010, G0020, S0587) dates state intrusion activity to calendar 2000 (Confirmed [55][56][57]). Neither do the library's actor studies. The [China study](/case-studies/THREAT_ACTORS_CHINA.md) dates its earliest China-attributed activity to 2006, the Russia study to 2003 and 2004, and the United States study to Equation's August 2001 domain, with some infrastructure possibly from 1996 (Confirmed [103][104][105]). The 2000 state record is therefore ECHELON, Carnivore, Russia's doctrine, the FBI's remote access in the Gorshkov case and the tail of Moonlight Maze. The quiet year reflects a visibility gap, not evidence of no activity (Inferred).

## Part 6: crime and prosecutions

### Insiders and control systems

- **Omega Engineering (Timothy Allen Lloyd).** On 9 May 2000 a jury in D.N.J. convicted Omega's former network administrator. On 30 July 1996, two weeks after he was fired, he had activated a software "timebomb" that deleted all of the company's manufacturing programs, with damage and losses above $10 million. Omega supplied NASA and the Navy (Confirmed [21]).
- **Maroochy (Vitek Boden).** Part 9 has the record.

### Defacers and globalHell

- **Robert Russell Sanford (HV2K).** Sanford, 18, was indicted in Dallas County on 10 October 2000 on nine counts for accessing and defacing systems of USPS, the State of Texas, the Canadian Department of Defence and Glinn Publishing between November 1999 and January 2000. A Canadian juvenile co-member entered a diversion program in Halifax (Confirmed [16]). Sanford pleaded guilty on 6 December 2000 in Dallas County District Court to six felony counts of breach of computer security and one felony count of third-degree aggravated theft (Confirmed [17]).
- **Patrick W. Gregory ("MostHateD").** Gregory co-founded globalHell with Chad Davis in February 1998. He pleaded guilty in N.D. Tex. on 12 April 2000 to conspiracy to commit telecommunications fraud and computer hacking. From 1997 to May 1999 he had used stolen teleconference access from AT&T, MCI, Sprint, Latitude and others to coordinate attacks (Confirmed [19]). On 6 September he was sentenced to 26 months, three years of supervised release and $154,529.86 in restitution (Confirmed [20]).
- **Andrew Miffleton ("Darkside Hacker").** Sentenced in N.D. Tex. on 24 July 2000 to 21 months and a $3,000 fine, and ordered to pay $89,480 restitution to the national ISP Verio (Confirmed [23]).

### Government systems

- **Ikenna Iffih.** Charged in Boston on 23 February 2000 for 1999 conduct. In April 1999 he used a hijacked corporate internet account and a telnet proxy to reach a Defense Logistics Agency computer, and damaged the ISP Zebra Marketing Online Services. From May to August 1999 he controlled a NASA research web server and installed a sniffer to capture logins (Confirmed [18]).
- **Jason Allen Diekman ("Shadow Knight").** Charged on 26 July 2000 and taken into federal custody on 21 September. He is alleged to have had root access to at least three JPL systems and access to about two dozen Stanford computers, including two NASA satellite-control systems, with more than $17,000 in damage at Stanford, and to have intercepted passwords (Confirmed [24]). He pleaded guilty to a misdemeanor count of unauthorized access to a government computer and a felony count of transmitting code that recklessly caused damage; the release is dated 7 November 2000 (Confirmed [25]). He also pleaded guilty to a felony count of unauthorized use of a credit card, and as part of the plea admitted causing $17,000 in damage (Confirmed [25]).
- **Raymond Torricelli ("rolex").** Pleaded guilty in Manhattan federal court on 1 December 2000 to breaking into two NASA JPL computers in 1998, and to intercepting usernames and passwords on a San Jose State University computer (Confirmed [22]).
- **c0mrade.** The [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) is the home for this case. A 16-year-old from Miami known as "c0mrade" was sentenced on 21 September 2000 to six months in a detention facility, the first juvenile hacker sentenced to serve time (Confirmed [27][28]). From 23 August to 27 October 1999 he ran a backdoor on a router used by the Defense Threat Reduction Agency that intercepted more than 3,300 messages. In June 1999 he entered 13 NASA Marshall computers and took $1.7 million of ISS software, forcing a 21-day shutdown in July 1999 (Confirmed [27]). DOJ release 00-555 names no one (Confirmed [28]).
- **Kevin Mitnick.** The Mitnick study carries his 2 March 2000 testimony to the Senate Committee on Governmental Affairs at the hearing "Cyber Attack: Is the Government Safe?" (S. Hrg. 106-486) (Confirmed [40][102]).

### Extortion and card theft

- **CD Universe (summary).** The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home. The New York Times reported on 10 January 2000 that an intruder tried to extort $100,000 from CD Universe after claiming more than 300,000 card files. When refused, the intruder released some, perhaps 25,000 numbers distributed through a website for two weeks, and the FBI confirmed an extortion investigation (Reported [48]).
- **Bloomberg.** Oleg Zezov and Igor Yarimaka of Kazakhstan were arrested in London on 10 August 2000. They had demanded $200,000 from Bloomberg L.P. in exchange for explaining how Zezov had got into Bloomberg's internal system, access tied to the Open Bloomberg service used by his employer, Kazkommerts Securities. A meeting with undercover Metropolitan Police officers led to the arrests (Confirmed [26]).
- **Gorshkov and Ivanov (summary).** The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home. Vasiliy Gorshkov and Alexey Ivanov of Chelyabinsk arrived in Seattle on 10 November 2000 for a recorded meeting with the FBI's undercover company "Invita" and were arrested at its end. Their group had stolen card data from ISPs, e-commerce sites and online banks, and extorted victims; named victims include Speakeasy, Nara Bank, Central National Bank of Waco and PayPal (Confirmed [29]). Gorshkov was sentenced on 4 October 2002 to 36 months, with restitution of nearly $700,000 (Confirmed [29][30]). Ivanov was sentenced on 25 July 2003 to 48 months; the judge found an aggregate loss of about $25 million, and Ivanov faced charges in Connecticut over an intrusion at the Online Information Bureau of Vernon (Confirmed [30]).
- **Egghead.com (summary).** The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home. Egghead's 10-K, filed 2 April 2001, states that in December 2000 it "experienced a security breach of our computer systems" by hackers (Confirmed [44]). It also says merchants bear card-not-present fraud losses and that Visa U.S.A. and its processor had notified it of a new cardholder information security standard for e-commerce merchants (Confirmed [44]).

### The law-enforcement build-out

Attorney General Reno proposed on 10 January a 24/7 cyber-crime network in every state, regional computer forensic labs and a secure online clearinghouse for law enforcement, in a speech to the National Association of Attorneys General at Stanford (Confirmed [31]). On 9 March she released "The Electronic Frontier", the Working Group's report (Confirmed [32]). CCIPS launched www.cybercrime.gov on 13 March (Confirmed [33]). On 5 April she addressed a law enforcement and technology industry conference at Stanford, which DOJ says followed the White House cybersecurity conference of the month before (Confirmed [34]). On 8 May DOJ and the FBI opened the Internet Fraud Complaint Center; the Attorney General noted nearly 18,000 Internet fraud complaints to the FTC in 1999 and the DOJ Internet Fraud Initiative established in February (Confirmed [36]).

## Part 7: law, policy and privacy

### The federal plan and federal security

On 7 January the President announced the national plan to defend America's cyberspace, the product of a three-year effort, citing the interconnection that Y2K had revealed (Confirmed [38]). At the White House meeting of 15 February he said he had released the draft plan the previous month, had asked Congress for $2 billion for cybersecurity and was providing $9 million at once. He said industry had agreed to create a mechanism to share cybersecurity information (Confirmed [39]).

The Government Information Security Reform Act became law as Title X Subtitle G of the FY2001 National Defense Authorization Act, Pub. L. 106-398, approved 30 October 2000. It added an information security subchapter to 44 U.S.C. chapter 35 and required each agency to have an annual independent evaluation of its information security program (44 U.S.C. 3535). It took effect 30 days after enactment and expired two years after taking effect (3536) (Confirmed [43]). OMB revised Circular A-130, Management of Federal Information Resources, on 12 December (65 FR 77677) (Confirmed [74]).

### Financial and health privacy

The FTC published its final Gramm-Leach-Bliley privacy rule (65 FR 33646) on 24 May, and the SEC adopted Regulation S-P (65 FR 40334) on 29 June; both took effect on 13 November 2000 (Confirmed [67][68]). HHS published the HIPAA Standards for Privacy of Individually Identifiable Health Information (65 FR 82462) on 28 December, effective 26 February 2001 (Confirmed [77]). Executive Order 13181, protecting health information in oversight investigations, was signed on 20 December (Confirmed [75]).

### Commerce, signatures and children

ESIGN became Pub. L. 106-229 on 30 June (Confirmed [69]). On 24 July Commerce issued the Safe Harbor Privacy Principles and sent them to the European Commission, which was expected to issue an adequacy determination (Confirmed [70]). The Children's Internet Protection Act was enacted as Title XVII of Pub. L. 106-554, approved 21 December (Confirmed [76]). BXA's rule of 14 January allowed export of any encryption item to non-government end users in all destinations, and retail encryption to all end users, except terrorist-supporting states (Confirmed [66]).

### Outside the United States

- **United Kingdom.** The Electronic Communications Act 2000 received Royal Assent on 25 May (Confirmed [78]). The Terrorism Act 2000 received it on 20 July; section 1(2)(e) brings into "terrorism" action designed seriously to interfere with or seriously to disrupt an electronic system (Confirmed [79]). The Regulation of Investigatory Powers Act 2000 received it on 28 July; Part III covers the investigation of electronic data protected by encryption (Confirmed [80]).
- **Canada.** PIPEDA (S.C. 2000, c. 5) was assented to on 13 April (Confirmed [81]).
- **Philippines.** Republic Act 8792, the Electronic Commerce Act, was approved on 14 June; Section 33(a) penalizes hacking or cracking, including introducing computer viruses (Confirmed [49]).
- **Russia.** The Information Security Doctrine of 9 September (Part 5) (Confirmed [65]).
- **European Parliament.** The ECHELON inquiry (Part 5) (Confirmed [60]).

## Part 8: cryptography and standards

- **AES.** Round 2 comments closed on 15 May 2000, and on 2 October NIST announced Rijndael as the proposed Advanced Encryption Standard, with a draft FIPS to follow in February 2001 (Confirmed [71]). Commerce Secretary Norman Mineta named Rijndael (Daemen and Rijmen) the winner of the three-year worldwide competition and called the standard a critical tool supporting e-commerce growth. He said completion was expected by spring 2001 (Confirmed [72]). FIPS 197 was actually published on 26 November 2001 (Confirmed [73]).
- **RSA.** Google Patents lists US 4,405,829 (Rivest, Shamir, Adleman; assignee MIT; filed 14 December 1977; granted 20 September 1983) as Expired - Lifetime, with an anticipated expiration of 20 September 2000. Google notes that this status is not a legal conclusion (Confirmed [89]).
- **Signatures and PKI.** NIST published FIPS 186-2, the Digital Signature Standard, on 27 January 2000; it was withdrawn on 5 October 2001 (Confirmed [82]). SP 800-25, Federal Agency Use of Public Key Technology for Digital Signatures and Authentication, followed in October 2000 and has since been withdrawn (Confirmed [88]). CA-2000-05 (Netscape SSL session validation, an ACROS discovery) and CA-2000-19 (Sun certificate revocation) show the client side of PKI failing (Confirmed [1]; Inferred).
- **The RFCs of May 2000.** RFC 2827 (BCP 38), Network Ingress Filtering by Ferguson and Senie, obsoletes RFC 2267, the filtering CA-2000-01 urged (Confirmed [83]). RFC 2818, HTTP Over TLS (Rescorla, Informational), is now obsolete and points to RFC 9110 (Confirmed [84]). RFC 2817, Upgrading to TLS Within HTTP/1.1, is Standards Track; TLS 1.0 itself is RFC 2246 of January 1999 (Confirmed [85]). RFC 2828, Internet Security Glossary (Shirey, FYI 36), is a 191-page set of definitions (Confirmed [86]).
- **Assurance and management standards.** NIST SP 800-23, on security assurance and the acquisition and use of tested and evaluated products, was published in August 2000 and has since been withdrawn (Confirmed [87]). ISO/IEC 17799:2000, Code of practice for information security management, edition 1, has a publication date of December 2000 and is now withdrawn (Confirmed [90]).
- **Encryption policy.** The January BXA rule (Part 7) (Confirmed [66]); the PGP advisories CA-2000-09 and CA-2000-18 (Part 2) (Confirmed [1]).

## Part 9: the industrial record

### Maroochy Shire

The primary record is the Queensland Court of Appeal's judgment in R v Boden, delivered on 10 May 2002 (Confirmed [50]). As the judgment records it:

- **The system.** About 150 pumping stations, each with a PDS Compact 500 computer, linked to the central computer by a private two-way radio system through repeaters at Buderim, Nambour and Mount Coolum. Hunter Watertech completed the installation by mid-January 2000 (paras 6 and 7) (Confirmed [50]).
- **The person.** Boden had been Hunter Watertech's site supervisor on the project for about two years, resigning with effect from 3 December 1999, and had approached the Council about employment around then (para 8) (Confirmed [50]).
- **The conduct.** The Crown case is that between 9 February and 23 April 2000 Boden accessed computers controlling the Maroochy Shire Council sewerage system, altering data for pumping stations and causing malfunctions (para 5) (Confirmed [50]).
- **16 March 2000.** The investigator communicated with a bogus "pump station 14" and his computer was shut out of the network for a short period; the intruder then used ID 1 (para 10) (Confirmed [50]).
- **The harm.** On the occasion of count 45 a pumping station overflowed and raw sewage escaped; technicians had to be mobilised across the system to correct faults (para 11) (Confirmed [50]). ATT&CK states the release was about 800,000 litres, citing Abrams (MITRE, 2008). The Abrams paper was not opened and the judgment gives no volume, so the figure is Reported (Reported [51]).
- **23 April 2000.** Alarms were disabled at four pumping stations using station 4's identity between about 7:30 pm and 9:00 pm. Boden's vehicle was stopped at about 10 pm carrying a Hunter Watertech PDS Compact 500 and a laptop whose configuration software had been re-installed on 29 February 2000 (paras 12 to 14) (Confirmed [50]).
- **The outcome.** Boden was convicted of 26 counts of using a restricted computer intending detriment or damage. He was also convicted of damage over $5,000, serious environmental harm, and theft of a two-way radio and a PDS Compact 500. He was sentenced on 31 October 2001, with a longest term of two years, concurrent (paras 2 and 3). The Court of Appeal set aside the convictions on counts 21 to 26 and dismissed leave to appeal the sentence (Confirmed [50]).

### The ATT&CK record

ATT&CK for ICS records the event as campaign C0020, Maroochy Water Breach, first seen February 2000 and last seen April 2000. ATT&CK describes the adversary using the local government's wastewater control system and stolen engineering equipment, and lists 12 techniques (Confirmed [51]). Part 11 binds them. The library holds all 12 technique ids in its ICS data, with names and tactics matching ATT&CK. It has no generated ICS technique pages and no campaign page for C0020, and C0020 is absent from its Enterprise campaign data (Demonstrated [99][100]). No study on main mentions Maroochy, so this chronicle links the ATT&CK page and the library's [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md) (Demonstrated [100]). For the control-system attacks of the current decade, see the [ICS attacks and advisories study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), and for Stuxnet, the [Stuxnet study](/case-studies/STUXNET.md).

## Part 10: the defender view

**Your unpatched server is someone else's outage.** CA-2000-01 tied DDoS capacity to compromised hosts, and CA-2000-03 found BIND compromised on machines that were never meant to be DNS servers (Confirmed [1]). In 2000 the cost of an unpatched host fell partly on other people's networks (Inferred).

**Defaults are decisions.** rpc.statd installed and enabled by default, Windows hiding file extensions, and Scriptlet.Typelib marked safe for scripting were all vendor defaults that the year's attacks used (Confirmed [1][2]). The [Log4Shell study](/case-studies/LOG4SHELL.md) shows defaults still deciding exposure two decades later (Inferred).

**Filter what leaves, not only what arrives.** BCP 38 stops a network's own hosts from sending spoofed traffic, which is what the nameserver floods of IN-2000-04 and the DDoS agents relied on (Confirmed [83][2]; Inferred).

**Know the patch you already have.** MS00-078 shipped no patch because MS00-057 already fixed it (Confirmed [14]). Patch tracking that knows which fix covers which flaw saves a second emergency (Inferred).

**Mail clients are execution engines.** Love Letter, BubbleBoy, kak and the Outlook cache bypass all turned on what an HTML mail client or a script host would do on the user's behalf (Confirmed [1][2]). The [Fancy Bear study](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) returns to the same user-side front in later years (Inferred).

**Control the people who know the system.** Boden supervised the Maroochy installation and Lloyd ran Omega's network; both attacks came after the person left (Confirmed [50][21]). Revoking access, recovering equipment and watching control-network radio traffic for unknown station identities are the defender's levers here (Inferred).

**Coordinate before the incident.** GAO's 4 May timeline and its call for better alert and coordination capabilities are a defender lesson as much as a government one (Confirmed [41][42]).

## Part 11: MITRE mappings

No 2000 record carries an ATT&CK Enterprise, CWE or CAPEC id. The first CWE List came in 2006 and CAPEC was released in 2007 (Confirmed [92][93]), and ATT&CK did not exist in 2000 (Inferred). Every Enterprise binding below is this study's later mapping (Inferred). The ICS table is different: ATT&CK itself lists those techniques for campaign C0020 (Confirmed [51]). Every id was checked against the library's data files and the generated pages under `mitre/` (Demonstrated [94][96][97][98][99][101]). Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the event. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a secondary source supports the behavior. **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Described | Love Letter mails itself to the Outlook address book (CA-2000-04, 4 May); double-extension attachments (IN-2000-07, 19 Jun) | [1][2] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | Love Letter needs Windows Scripting Host to run; hidden extensions disguise script attachments as other files (IN-2000-07) | [1][2] |
| [`T1036.007`](/mitre/techniques/T1036-007.md) | Double File Extension | stealth | Described | Love Letter, Timofonica, CoolNote and a downloader (IN-2000-07, 19 Jun) | [2] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Visual Basic | execution | Described | Love Letter (4 May); network.vbs (3 Mar); BubbleBoy and kak (6 Jun) | [1][2] |
| [`T1059.003`](/mitre/techniques/T1059-003.md) | Windows Command Shell | execution | Described | The 911 batch-file worm (IN-2000-03, 4 Apr) | [2] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | BubbleBoy and kak through Scriptlet.Typelib in HTML mail (IN-2000-06, 6 Jun) | [2] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | Described | Love Letter writes Run and RunServices keys (CA-2000-04) | [1] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | defense-impairment, persistence | Described | Love Letter registry keys and IE start page change (CA-2000-04) | [1] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Described | Love Letter points IE at a further executable to download (CA-2000-04) | [1] |
| [`T1087.003`](/mitre/techniques/T1087-003.md) | Email Account | discovery | Described | Love Letter reads every Outlook address-book entry (CA-2000-04) | [1] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | discovery | Inferred | Love Letter finds script, image and music files to overwrite or hide; the advisory does not describe the search | [1] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Described | Love Letter overwrites script and image files (4 May); Lloyd's timebomb deletes Omega's manufacturing programs (30 Jul 1996; verdict 9 May 2000) | [1][21] |
| [`T1564.001`](/mitre/techniques/T1564-001.md) | Hidden Files and Directories | stealth | Described | Love Letter sets mp3 and mp2 originals hidden (CA-2000-04) | [1] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | discovery | Described | network.vbs scans random /24 blocks for open shares (IN-2000-02, 3 Mar) | [2] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | lateral-movement | Described | network.vbs copies itself to open C shares (3 Mar); Love Letter spreads through shared file systems (4 May) | [2][1] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | Inferred | The 911 worm spreads through unprotected Windows 98 shares (4 Apr); these are open shares, not admin shares reached with credentials | [2] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | BIND NXT (CA-2000-03, 26 Apr); wu-ftpd (CA-2000-13, 7 Jul); rpc.statd (CA-2000-17, 18 Aug); IRIX telnetd (IN-2000-09, 31 Aug); IIS folder traversal (MS00-078, 17 Oct) (flaw class; no exploitation stated); LPRng (CA-2000-22, 12 Dec) | [1][2][14] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | reconnaissance | Described | Scans of ports 111 and 21 (IN-2000-10, 15 Sep); probing of 515/tcp (CA-2000-22) | [2][1] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Botnet | resource-development | Described | Stacheldraht agents on compromised hosts (CA-2000-01, 3 Jan); Windows trinoo (IN-2000-01, from 16 Feb); mstream agents (late Apr) | [1][2] |
| [`T1498`](/mitre/techniques/T1498.md) | Network Denial of Service | impact | Reported | Yahoo (7 Feb); Amazon.com, eBay, Buy.com and CNN (8 Feb) | [45][46] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | mstream (IN-2000-05); Stacheldraht (CA-2000-01); Windows trinoo (IN-2000-01) | [2][1] |
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | impact | Described | Spoofed DNS requests amplified by nameservers (IN-2000-04, 28 Apr) | [2] |
| [`T1499`](/mitre/techniques/T1499.md) | Endpoint Denial of Service | impact | Inferred | BIND DoS bugs (CA-2000-20, 13 Nov); Naptha resource exhaustion (CA-2000-21, 30 Nov); no exploitation stated | [1] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | command-and-control | Described | Back Orifice and other remote administration tools on the same machines as Windows trinoo (IN-2000-01) | [2] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | Iffih's sniffer on a NASA server (May to Aug 1999; charged 23 Feb 2000); Diekman's alleged password interception (charged 26 Jul); c0mrade's DTRA router backdoor (1999; sentenced 21 Sep); Torricelli's interception of usernames and passwords on a San Jose State University computer (1998 conduct; plea 1 Dec); Moonlight Maze relay sniffers (1998 to 1999) | [18][24][27][22][52] |
| [`T1110.002`](/mitre/techniques/T1110-002.md) | Password Cracking | credential-access | Described | Torricelli's plea allocution (1998 conduct; plea 1 Dec 2000) | [22] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Iffih's hijacked corporate internet account (Apr 1999; charged 23 Feb 2000) | [18] |
| [`T1090.003`](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | command-and-control | Described | Moonlight Maze operators relay through hacked servers (1998 to 1999); the library's home study maps the same id | [52][102] |
| [`T1584.004`](/mitre/techniques/T1584-004.md) | Server | resource-development | Described | Moonlight Maze's compromised relay servers, including HRTest (1998 to 1999) | [52][102] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | impact | Described | HV2K defacements of USPS, Texas, Canadian Defence and Glinn Publishing systems (Nov 1999 to Jan 2000) | [16] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | impact | Described | Bloomberg extortion demand (arrests 10 Aug); Gorshkov and Ivanov card theft and extortion (arrests 10 Nov); CD Universe extortion (Jan, Reported) | [26][29][48] |

Left out on purpose: T1046 Network Service Discovery, because IN-2000-10's scans were external scanning, which T1595.002 covers, and the note does not say the scans ran from inside victim networks (Inferred [2]). T1189 Drive-by Compromise for CA-2000-02, because CERT reported no exploitation (Confirmed [1]); the cross-site scripting class is bound through CWE and CAPEC instead. The Sun certificate revocation (CA-2000-19), because the bulletin describes a potential compromise and no adversary behavior (Confirmed [1]). The Outlook cache bypass and the Netscape, IE and Kerberos advisories, for which no exploitation is stated in the passages read (Inferred [1]). Carnivore, ECHELON and the FBI's remote copying in the Gorshkov case, which are state collection under legal authority, not adversary tradecraft in this record (Inferred). The Egghead.com breach, for which the 10-K describes no mechanism (Confirmed [44]). Maroochy, which is bound in the ICS table below.

### ATT&CK for ICS techniques

ATT&CK lists these 12 techniques for campaign C0020, Maroochy Water Breach (Confirmed [51]). The names and tactics match the library's ICS data. T1692.001 and T1692.002 supersede the revoked T0855 and T0856, per the library's `superseded_by.jsonl` (Demonstrated [99][107]). The library has no generated ICS technique pages, so the ids link to ATT&CK.

| Id | Name | Tactic(s) | Basis | Dated event in the judgment | Sources |
|---|---|---|---|---|---|
| [`T0848`](https://attack.mitre.org/techniques/T0848/) | Rogue Master | initial-access | Listed | A bogus "pump station 14" (16 Mar); station 4's identity used to disable alarms (23 Apr) | [51][50] |
| [`T0860`](https://attack.mitre.org/techniques/T0860/) | Wireless Compromise | initial-access | Listed | The private two-way radio network linking the stations (completed mid-Jan 2000) | [51][50] |
| [`T0864`](https://attack.mitre.org/techniques/T0864/) | Transient Cyber Asset | initial-access | Listed | Laptop with configuration software re-installed on 29 Feb, and a PDS Compact 500, in Boden's car (23 Apr) | [51][50] |
| [`T0822`](https://attack.mitre.org/techniques/T0822/) | External Remote Services | initial-access | Listed | ATT&CK's listing; the judgment passages read do not describe it | [51] |
| [`T0836`](https://attack.mitre.org/techniques/T0836/) | Modify Parameter | impair-process-control | Listed | Data altered for pumping stations (9 Feb to 23 Apr) | [51][50] |
| [`T1692.001`](https://attack.mitre.org/techniques/T1692/001/) | Command Message | evasion, impair-process-control | Listed | Data altered for pumping stations (9 Feb to 23 Apr); ATT&CK's listing | [51][50] |
| [`T1692.002`](https://attack.mitre.org/techniques/T1692/002/) | Reporting Message | evasion, impair-process-control | Listed | ATT&CK's listing | [51] |
| [`T0878`](https://attack.mitre.org/techniques/T0878/) | Alarm Suppression | inhibit-response-function | Listed | Alarms disabled at four pumping stations (23 Apr) | [51][50] |
| [`T0838`](https://attack.mitre.org/techniques/T0838/) | Modify Alarm Settings | inhibit-response-function | Listed | Alarms disabled at four pumping stations (23 Apr) | [51][50] |
| [`T0813`](https://attack.mitre.org/techniques/T0813/) | Denial of Control | impact | Listed | The investigator's computer shut out of the network (16 Mar) | [51][50] |
| [`T0815`](https://attack.mitre.org/techniques/T0815/) | Denial of View | impact | Listed | ATT&CK's listing | [51] |
| [`T0879`](https://attack.mitre.org/techniques/T0879/) | Damage to Property | impact | Listed | A pumping station overflowed and raw sewage escaped (count 45) | [51][50] |

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| Maroochy Water Breach (ATT&CK for ICS campaign) | [C0020](https://attack.mitre.org/campaigns/C0020/) | Bound: first seen February 2000, last seen April 2000. The library has no page for it (`mitre/campaigns/` holds Enterprise campaigns only), so the link goes to ATT&CK | [51][100] |
| Turla | [G0010](/mitre/groups/G0010.md) | Context only: active since at least 2004; the page does not mention Moonlight Maze | [55][101] |
| Penquin | [S0587](/mitre/software/S0587.md) | Context only: used since at least 2014; no Moonlight Maze or LOKI2 mention | [56][101] |
| Equation | [G0020](/mitre/groups/G0020.md) | Context only: no dates of activity; Kaspersky places nothing in 2000 | [57][58][59][101] |

No software object is bound. The library's software data has no entry for Love Letter, Stacheldraht, trinoo, mstream, BubbleBoy, kak or Timofonica (Confirmed [95]).

### CWE and CAPEC

NVD lists only NVD-CWE-Other or NVD-CWE-noinfo for the 2000 CVEs checked (Confirmed [5][8][10][11][12]), so every CWE below is this study's reading, not an NVD mapping (Inferred). Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [97][98]).

| CWE | Weakness (library name) | 2000 record | CAPEC |
|---|---|---|---|
| CWE-79 | Improper Neutralization of Input During Web Page Generation | Malicious HTML tags in client web requests, CA-2000-02, 2 Feb | [CAPEC-63](/mitre/capec/CAPEC-63.md) Cross-Site Scripting (XSS) (the library pairs it with CWE-79) |
| CWE-134 | Use of Externally-Controlled Format String | wu-ftpd site exec (CVE-2000-0573, 7 Jul); rpc.statd (CVE-2000-0666, 18 Aug); LPRng (CVE-2000-0917, 12 Dec) | [CAPEC-135](/mitre/capec/CAPEC-135.md) Format String Injection; [CAPEC-67](/mitre/capec/CAPEC-67.md) String Format Overflow in syslog() (the library pairs both with CWE-134) |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | IIS Web Server Folder Traversal (CVE-2000-0884, MS00-078, 17 Oct) | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal; [CAPEC-64](/mitre/capec/CAPEC-64.md) Using Slashes and URL Encoding Combined to Bypass Validation Logic |
| CWE-176 | Improper Handling of Unicode Encoding | The Unicode-encoded URLs NVD describes for CVE-2000-0884 | [CAPEC-71](/mitre/capec/CAPEC-71.md) Using Unicode Encoding to Bypass Validation Logic |
| CWE-400 | Uncontrolled Resource Consumption | Naptha (CAN-2000-1039, CA-2000-21, 30 Nov) | [CAPEC-482](/mitre/capec/CAPEC-482.md) TCP Flood (this study's pairing; the library pairs CAPEC-482 with CWE-770) |
| none bound | (amplification) | Nameserver amplification floods, IN-2000-04, 28 Apr | [CAPEC-490](/mitre/capec/CAPEC-490.md) Amplification (the library links it to T1498.002) |
| NVD-CWE-Other and NVD-CWE-noinfo | (as NVD lists them) | BIND zxfr (CVE-2000-0887) and srv (CVE-2000-0888), CA-2000-20, 13 Nov | None assigned |

### D3FEND countermeasures

Pairings come from the library's `data/attack/technique_to_d3fend.jsonl` unless the row says the pairing is this study's. Every page exists under `/mitre/d3fend/` (Confirmed [96]).

| Technique from the record | D3FEND countermeasures | 2000 analogue |
|---|---|---|
| T1566.001 | [Email Filtering](/mitre/d3fend/email-filtering.md) (D3-EF), [File Analysis](/mitre/d3fend/file-analysis.md) (D3-FA), [Restore File](/mitre/d3fend/restore-file.md) (D3-RF), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) (D3-FIM) | CERT's mail transfer agent filtering and updated anti-virus for Love Letter [1] |
| T1204.002 and T1547.001 | [File Analysis](/mitre/d3fend/file-analysis.md), [Restore File](/mitre/d3fend/restore-file.md), [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (D3-EAL) | CERT's advice to disable Windows Scripting Host [1] |
| T1190 and T1498.001 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (D3-ITF), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (D3-NTF), [Inbound Session Volume Analysis](/mitre/d3fend/inbound-session-volume-analysis.md) (D3-ISVA) | RFC 2267 ingress filtering in CA-2000-01; RFC 2827 (BCP 38) [1][83] |
| Patching the year's server flaws (T1190) | [Software Update](/mitre/d3fend/software-update.md) (D3-SU), this study's pairing; the library maps D3-SU to none of these techniques | CA-2000-13, CA-2000-17 and CA-2000-22 patches; MS00-057 [1][13] |
| Default services, open shares, hidden extensions (T1190, T1135, T1036.007) | [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) (D3-ACH), this study's pairing; the library maps D3-ACH to none of these techniques | rpc.statd defaults (IN-2000-10); open shares (IN-2000-02, IN-2000-03); hidden extensions (IN-2000-07); MS00-078 hardening [2][14] |

Techniques not named in this table are left without a D3FEND pairing here; none is invented (Inferred).

### Navigator layers

The study's Enterprise techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2000.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2000.json). It lists the 31 techniques in the Enterprise table under each tactic they carry in v20.0 and is listed on [the Navigator layers page](/navigator/index.md) [106]. Curated layers in that folder must be `enterprise-attack`, so the 12 Maroochy techniques go in a separate ATT&CK for ICS layer, [navigator/case-studies/chronicle-2000-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2000-ics.json), domain `ics-attack`. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where ATT&CK lists the id for the event (the ICS layer), 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping. Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**Compromise fed disruption.** CERT's 2000 notes describe a steady supply of compromised Unix and Windows hosts turned into flood agents (Confirmed [1][2]); that the February outages (Reported [45][46]) drew on that supply is this study's reading (Inferred). The same economics of compromised access run through the [ransomware ecosystem study](/case-studies/RANSOMWARE_ECOSYSTEM.md) (Inferred).

**Users and servers were two fronts again.** Love Letter, the hidden-extension programs and BubbleBoy needed a user or a mail client; BIND, wu-ftpd, rpc.statd and LPRng did not (Confirmed [1][2]). The split recurs in the [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md) on the server side (Inferred).

**Insiders with engineering knowledge.** Maroochy and Omega are both attacks by people who knew the system they hit (Confirmed [50][21]). Insider and supply-side trust failures recur in the [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md), [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) and [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) studies (Inferred).

**Law caught up after the event.** The Philippine Electronic Commerce Act came six weeks after Love Letter and could not reach it (Confirmed [49]; Reported [47]). GISRA's annual evaluations, the GLB privacy rules and the HIPAA privacy rule all arrived in the same year (Confirmed [43][67][77]); this study does not claim the year's attacks caused them (Inferred).

**Surveillance became a public question.** ECHELON, Carnivore, RIPA's encryption powers and the FBI's remote copying in the Gorshkov case put state collection on the public record in one year (Confirmed [60][63][80][29]). The [Hacker and the State study](/case-studies/HACKER_AND_THE_STATE_CASES.md) follows that line forward (Inferred).

**Attribution stayed cautious.** Hamre's "we do not know who did it", the researchers' "simply premature" on Turla and ATT&CK's silence on Moonlight Maze all hold back from a named sponsor (Reported [54][52]; Confirmed [55][56]). The [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) shows how much more evidence a confident attribution now carries (Inferred).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: Love Letter as the story of 2000.** Its numbers are countable and its damage figures come from the press, so it dominates memory. One CERT advisory covers it; the rest of the year's 22 cover servers, clients and cryptography [1][41].
- **Overstated: the precision of Love Letter's victim list.** GAO's list of penetrated agencies is "reportedly", and its private and foreign victims come from media reports [41].
- **Overstated: the February attacks as a primary-record event.** The outages are known here only through CNN; the Attorney General's statement confirms the targets and the CNN-related arrest, not the outage durations [45][46][35].
- **Overstated: Moonlight Maze as a known 2000 operation.** Frontline's "nearly two years" reaches into early 2000, but the researchers' direct visibility ends in March 1999, and the successor operation is a leak with no artefacts [53][52].
- **Overstated: ECHELON's economic espionage.** The committee found no evidence that ECHELON distorted competition, and relayed the 5% and 7 billion dollar figures from US sources without establishing them [61].
- **Overstated: Maroochy's sewage volume.** The 800,000-litre figure is ATT&CK's, from a paper not opened here; the court judgment gives no volume [51][50].
- **Overstated: any ATT&CK Enterprise, CWE or CAPEC id on a 2000 event.** Those programs began later, and the Enterprise layer reflects later naming, not 2000 understanding [92][93].
- **Understated: the daily server compromises.** BIND, wu-ftpd, rpc.statd, LPRng and IRIX telnetd were exploited in the field and fed the DoS agent pools, with hundreds of hosts in single incidents [1][2].
- **Understated: the standards work.** BCP 38, RFC 2818, ISO/IEC 17799, FIPS 186-2 and the choice of AES all date to 2000 [83][84][90][82][71].
- **Understated: undisclosed intrusions.** This study found no breach-notice requirement in the 2000 laws it opened. Egghead.com's breach is on the record because a 10-K mentioned it; most intrusions of the year left no public trace [44].
- **Understated: Maroochy itself.** It is the year's control-system incident on the ATT&CK record, and no study on the library's main branch mentioned it before this one [51][100].
- **Understated: state activity.** The quiet state record reflects what was visible, not what happened [52][55][57][103][104][105].

### Discrepancies in the record

- **Love Letter's reach.** GAO: over 400 direct reports involving more than 420,000 hosts by 6 pm on 4 May. CERT/CC: more than 500,000 systems at more than 650 sites by 5 pm EDT on 8 May [41][1]. The two counts measure different moments and neither is a census.
- **MS00-078's fix.** The bulletin is sometimes described as a patch; Microsoft says no new patch was issued, because MS00-057 already eliminated the flaw [14][13].
- **Three dates for the same CVEs.** CVE-2000-0884: bulletin 17 October 2000, NVD 19 December 2000, CVE.org 22 January 2001. CVE-2000-0666: NVD 16 July 2000, before CA-2000-17 of 18 August; CVE.org 13 October 2000. CVE-2000-0573: NVD 7 July 2000, CVE.org 7 May 2001. CVE-2000-1039: advisory 30 November 2000, NVD 9 January 2001 [14][10][9][108][109][1][110].
- **Moonlight Maze's span.** The researchers date it from 1996 and their visibility to 1998 to March 1999; Frontline dates it from March 1998 for nearly two years [52][53].
- **Maroochy's dates.** The judgment's Crown case runs 9 February to 23 April 2000; ATT&CK gives February to April 2000 [50][51].
- **Diekman's plea.** The plea date is 6 November and the release is dated 7 November 2000 [25].
- **AES timing.** In October 2000 NIST expected completion by spring 2001; FIPS 197 came on 26 November 2001 [72][73].
- **Carnivore.** The IITRI report is a primary record; the public timeline of July and August 2000 and the FOIA document list rest on EPIC's account [63][64].

## Sources

All sources were opened on 12 or 13 November 2026 as listed. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the NVD API queries, SEC EDGAR and Lawphil); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "2000 CERT Advisories" (compilation, CA-2000-01 to CA-2000-22) | https://www.sei.cmu.edu/documents/507/2000_019_001_496188.pdf | 2026-11-12, 2026-11-13 | Confirmed |
| 2 | CMU SEI, "2000 CERT Incident Notes" (compilation, IN-2000-01 to IN-2000-10) | https://www.sei.cmu.edu/documents/521/2000_019_001_496446.pdf | 2026-11-12, 2026-11-13 | Confirmed |
| 3 | CMU SEI, 2000 CERT advisories index | https://www.sei.cmu.edu/library/2000-cert-advisories/ | 2026-11-12 | Confirmed |
| 4 | CMU SEI Insights, 2000 CERT advisories | https://insights.sei.cmu.edu/library/2000-cert-advisories/ | 2026-11-12 | Confirmed |
| 5 | NVD, CVE-2000-0573 | https://nvd.nist.gov/vuln/detail/CVE-2000-0573 | 2026-11-12 | Confirmed |
| 6 | NVD API, CVE-2000-0573 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2000-0573` | 2026-11-13 | Confirmed |
| 7 | NVD, CVE-2000-0666 | https://nvd.nist.gov/vuln/detail/CVE-2000-0666 | 2026-11-12 | Confirmed |
| 8 | NVD API, CVE-2000-0666 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2000-0666` | 2026-11-13 | Confirmed |
| 9 | CVE Services API, CVE-2000-0666 | https://cveawg.mitre.org/api/cve/CVE-2000-0666 | 2026-11-12 | Confirmed |
| 10 | NVD API, CVE-2000-0884 (with the NVD and CVE.org dates for CVE-2000-0573 and CVE-2000-0666) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2000-0884` | 2026-11-12, 2026-11-13 | Confirmed |
| 11 | NVD API, CVE-2000-0887 (with CVE-2000-0888) | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2000-0887` | 2026-11-13 | Confirmed |
| 12 | NVD API, CVE-2000-0917 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2000-0917` | 2026-11-13 | Confirmed |
| 13 | Microsoft Security Bulletin MS00-057 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-057 | 2026-11-13 | Confirmed |
| 14 | Microsoft Security Bulletin MS00-078 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-078 | 2026-11-12, 2026-11-13 | Confirmed |
| 15 | Microsoft Security Bulletin MS00-100 (with the MS00-101 and MS00-102 probes) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-100 | 2026-11-13 | Demonstrated |
| 16 | DOJ CCIPS, Sanford indictment (UNT End of Term archive of cybercrime.gov) | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/Vahacker.htm | 2026-11-12 | Confirmed |
| 17 | DOJ CCIPS, Sanford plea | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/VAhacker2.htm | 2026-11-12 | Confirmed |
| 18 | DOJ CCIPS, Ikenna Iffih | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/iffih.htm | 2026-11-12 | Confirmed |
| 19 | DOJ CCIPS, Patrick Gregory plea | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/gregory.htm | 2026-11-12 | Confirmed |
| 20 | DOJ CCIPS, Patrick Gregory sentencing | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/gregorysen.htm | 2026-11-12 | Confirmed |
| 21 | DOJ CCIPS, Timothy Allen Lloyd (Omega Engineering) | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/njtime.htm | 2026-11-12 | Confirmed |
| 22 | DOJ CCIPS, Raymond Torricelli plea | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/rolex.htm | 2026-11-12 | Confirmed |
| 23 | DOJ CCIPS, Andrew Miffleton sentencing | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/miffle2.htm | 2026-11-12 | Confirmed |
| 24 | DOJ CCIPS, Jason Diekman charge and custody | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/diekman.htm | 2026-11-12 | Confirmed |
| 25 | DOJ CCIPS, Jason Diekman plea | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/diekman2.htm | 2026-11-12 | Confirmed |
| 26 | DOJ CCIPS, Bloomberg extortion arrests | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/bloomberg.htm | 2026-11-12 | Confirmed |
| 27 | DOJ CCIPS, "c0mrade" | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/comrade.htm | 2026-11-12 | Confirmed |
| 28 | US Department of Justice, release 00-555, 21 September 2000 | https://www.justice.gov/archive/opa/pr/2000/September/555crm.htm | 2026-11-13 | Confirmed |
| 29 | US Department of Justice, Gorshkov sentencing, 4 October 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/gorshkovSent.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 30 | US Department of Justice, Ivanov sentencing, 25 July 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/ivanovSent.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 31 | US Department of Justice, Attorney General at the NAAG meeting, Stanford, 10 January 2000 | https://www.justice.gov/archive/opa/pr/2000/January/007ag.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 32 | US Department of Justice, "The Electronic Frontier" release, 9 March 2000 | https://www.justice.gov/archive/opa/pr/2000/March/111ag.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 33 | US Department of Justice, cybercrime.gov launch, 13 March 2000 | https://www.justice.gov/archive/opa/pr/2000/March/119crm.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 34 | US Department of Justice, Stanford conference, 5 April 2000 | https://www.justice.gov/archive/opa/pr/2000/April/171ag.htm | 2026-11-13 | Confirmed |
| 35 | US Department of Justice, Attorney General's statement on the Montreal arrest, 19 April 2000 | https://www.justice.gov/archive/opa/pr/2000/April/217ag.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 36 | US Department of Justice, Internet Fraud Complaint Center, 8 May 2000 | https://www.justice.gov/archive/opa/pr/2000/May/254ag.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 37 | US Department of Justice, Carnivore review contractor selected, 26 September 2000 | https://www.justice.gov/archive/opa/pr/2000/September/565jmd.htm | 2026-11-12 | Confirmed |
| 38 | Weekly Compilation of Presidential Documents, national plan announcement, 7 January 2000 | https://www.govinfo.gov/content/pkg/WCPD-2000-01-10/html/WCPD-2000-01-10-Pg23.htm | 2026-11-12 | Confirmed |
| 39 | Weekly Compilation of Presidential Documents, vol. 36 no. 7, pp. 308 to 310, 15 February 2000 | https://www.govinfo.gov/content/pkg/WCPD-2000-02-21/html/WCPD-2000-02-21-Pg308-2.htm | 2026-11-12 | Confirmed |
| 40 | Senate Committee on Governmental Affairs, "Cyber Attack: Is the Government Safe?", S. Hrg. 106-486, 2 March 2000 | https://www.govinfo.gov/content/pkg/CHRG-106shrg63639/html/CHRG-106shrg63639.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 41 | GAO, T-AIMD-00-171, 10 May 2000 | https://www.govinfo.gov/content/pkg/GAOREPORTS-T-AIMD-00-171/pdf/GAOREPORTS-T-AIMD-00-171.pdf | 2026-11-12 | Confirmed; Reported (the victim list GAO attributes to others) |
| 42 | GAO, T-AIMD-00-181, 18 May 2000 | https://www.govinfo.gov/content/pkg/GAOREPORTS-T-AIMD-00-181/pdf/GAOREPORTS-T-AIMD-00-181.pdf | 2026-11-12 | Confirmed |
| 43 | Pub. L. 106-398 (FY2001 NDAA, including the Government Information Security Reform Act) | https://www.govinfo.gov/content/pkg/PLAW-106publ398/html/PLAW-106publ398.htm | 2026-11-12 | Confirmed |
| 44 | SEC EDGAR, Egghead.com Form 10-K, filed 2 April 2001 | `https://www.sec.gov/Archives/edgar/data/1026506/000102650601500003/body10k.htm` | 2026-11-12 | Confirmed |
| 45 | CNN, Yahoo denial-of-service attack, 8 February 2000 | http://www.cnn.com/2000/TECH/computing/02/08/yahoo.assault.idg/ | 2026-11-13 | Reported |
| 46 | CNN, cyber attacks on e-commerce sites, 9 February 2000 | http://www.cnn.com/2000/TECH/computing/02/09/cyber.attacks.01/ | 2026-11-13 | Reported |
| 47 | New York Times, Love Letter charges dismissed, 22 August 2000 | https://archive.nytimes.com/www.nytimes.com/library/tech/00/08/biztech/articles/22virus.html | 2026-11-13 | Reported |
| 48 | New York Times, CD Universe extortion, 10 January 2000 | https://www.nytimes.com/2000/01/10/business/thief-reveals-credit-card-data-when-web-extortion-plot-fails.html | 2026-11-12 | Reported |
| 49 | Philippine Republic Act 8792, Electronic Commerce Act of 2000 (Lawphil) | `https://lawphil.net/statutes/repacts/ra2000/ra_8792_2000.html` | 2026-11-12, 2026-11-13 | Confirmed |
| 50 | Queensland Court of Appeal, R v Boden [2002] QCA 164, 10 May 2002 | https://www.queenslandjudgments.com.au/caselaw/qca/2002/164 | 2026-11-12 | Confirmed |
| 51 | MITRE ATT&CK, campaign C0020, Maroochy Water Breach | https://attack.mitre.org/campaigns/C0020/ | 2026-11-12, 2026-11-13 | Confirmed; Reported (the sewage volume ATT&CK cites from Abrams 2008) |
| 52 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze", Securelist, 3 April 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Confirmed (technical findings); Reported (victims, successor operation, attribution) |
| 53 | PBS Frontline, cyber war series, warnings page, 24 April 2003 | https://www.pbs.org/wgbh/pages/frontline/shows/cyberwar/warnings/ | 2026-11-12 | Reported |
| 54 | PBS Frontline, interview with John Hamre, conducted 18 February 2003 | https://www.pbs.org/wgbh/pages/frontline/shows/cyberwar/interviews/hamre.html | 2026-11-12 | Reported |
| 55 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 56 | MITRE ATT&CK, Penquin (S0587) | https://attack.mitre.org/software/S0587/ | 2026-11-12 | Confirmed |
| 57 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 58 | Kaspersky, "Equation group: questions and answers", v1.5, February 2015 | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf | 2026-11-12 | Confirmed |
| 59 | Kaspersky, "Equation: The Death Star of Malware Galaxy", Securelist, 16 February 2015 | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-12 | Confirmed |
| 60 | European Parliament Legislative Observatory, procedure 2001/2098(INI) | https://oeil.secure.europarl.europa.eu/oeil/en/procedure-file?reference=2001/2098(INI) | 2026-11-12 | Confirmed |
| 61 | European Parliament Legislative Observatory, summary of report A5-0264/2001 | https://oeil.secure.europarl.europa.eu/oeil/en/document-summary?id=601538 | 2026-11-12 | Confirmed; Reported (the relayed economic figures) |
| 62 | European Parliament Legislative Observatory, summary of the 5 September 2001 decision | https://oeil.secure.europarl.europa.eu/oeil/en/document-summary?id=78750 | 2026-11-12 | Confirmed |
| 63 | IIT Research Institute, "Independent Technical Review of the Carnivore System, Final Report", 8 December 2000 (EPIC copy) | https://epic.org/privacy/carnivore/carniv_final.pdf | 2026-11-12 | Confirmed |
| 64 | EPIC, Carnivore FOIA litigation page | https://www.epic.org/privacy/carnivore/ | 2026-11-12 | Reported |
| 65 | Kremlin, Decree No. 646 of 5 December 2016 | http://www.kremlin.ru/acts/bank/41460 | 2026-11-12 | Confirmed |
| 66 | Federal Register, BXA "Revisions to Encryption Items", 65 FR 2492, 14 January 2000 | https://www.federalregister.gov/documents/2000/01/14/00-983/revisions-to-encryption-items | 2026-11-12 | Confirmed |
| 67 | Federal Register, FTC "Privacy of Consumer Financial Information", 65 FR 33646, 24 May 2000 | https://www.federalregister.gov/documents/2000/05/24/00-12755/privacy-of-consumer-financial-information | 2026-11-12 | Confirmed |
| 68 | Federal Register, SEC Regulation S-P, 65 FR 40334, 29 June 2000 | https://www.federalregister.gov/documents/2000/06/29/00-16269/privacy-of-consumer-financial-information-regulation-s-p | 2026-11-12 | Confirmed |
| 69 | Pub. L. 106-229, Electronic Signatures in Global and National Commerce Act | https://www.govinfo.gov/content/pkg/PLAW-106publ229/html/PLAW-106publ229.htm | 2026-11-12 | Confirmed |
| 70 | Federal Register, Safe Harbor Principles, 65 FR 45666, 24 July 2000 | https://www.federalregister.gov/documents/2000/07/24/00-18489/issuance-of-safe-harbor-principles-and-transmission-to-european-commission | 2026-11-12 | Confirmed |
| 71 | NIST CSRC, AES development (archived project) | https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/archived-crypto-projects/aes-development | 2026-11-12 | Confirmed |
| 72 | NIST, "Commerce Department Announces Winner of Global Information Security Competition", 2 October 2000 | https://www.nist.gov/news-events/news/2000/10/commerce-department-announces-winner-global-information-security | 2026-11-12 | Confirmed |
| 73 | NIST, FIPS 197 | https://csrc.nist.gov/pubs/fips/197/final | 2026-11-12 | Confirmed |
| 74 | Federal Register, OMB Circular A-130 revision, 65 FR 77677, 12 December 2000 | https://www.federalregister.gov/documents/2000/12/12/00-31507/management-of-federal-information-resources | 2026-11-12 | Confirmed |
| 75 | Federal Register, Executive Order 13181, 65 FR 81321 | https://www.federalregister.gov/documents/2000/12/26/00-33004/to-protect-the-privacy-of-protected-health-information-in-oversight-investigations | 2026-11-12 | Confirmed |
| 76 | Pub. L. 106-554 (Consolidated Appropriations Act 2001, including CIPA) | https://www.govinfo.gov/content/pkg/PLAW-106publ554/html/PLAW-106publ554.htm | 2026-11-12 | Confirmed |
| 77 | Federal Register, HHS Standards for Privacy of Individually Identifiable Health Information, 65 FR 82462, 28 December 2000 | https://www.federalregister.gov/documents/2000/12/28/00-32678/standards-for-privacy-of-individually-identifiable-health-information | 2026-11-12 | Confirmed |
| 78 | legislation.gov.uk, Electronic Communications Act 2000 (c. 7) | https://www.legislation.gov.uk/ukpga/2000/7/introduction/enacted | 2026-11-12 | Confirmed |
| 79 | legislation.gov.uk, Terrorism Act 2000, section 1 | https://www.legislation.gov.uk/ukpga/2000/11/section/1/enacted | 2026-11-12 | Confirmed |
| 80 | legislation.gov.uk, Regulation of Investigatory Powers Act 2000 (c. 23) | https://www.legislation.gov.uk/ukpga/2000/23/introduction/enacted | 2026-11-12 | Confirmed |
| 81 | Justice Laws Website, Personal Information Protection and Electronic Documents Act (S.C. 2000, c. 5) | https://laws-lois.justice.gc.ca/eng/acts/P-8.6/page-1.html | 2026-11-12 | Confirmed |
| 82 | NIST, FIPS 186-2 | https://csrc.nist.gov/pubs/fips/186-2/final | 2026-11-12 | Confirmed |
| 83 | RFC 2827, Network Ingress Filtering (BCP 38) | https://www.rfc-editor.org/rfc/rfc2827.txt | 2026-11-12 | Confirmed |
| 84 | RFC 2818, HTTP Over TLS | https://www.rfc-editor.org/rfc/rfc2818 | 2026-11-12 | Confirmed |
| 85 | RFC 2817, Upgrading to TLS Within HTTP/1.1 | https://www.rfc-editor.org/rfc/rfc2817.txt | 2026-11-12 | Confirmed |
| 86 | RFC 2828, Internet Security Glossary | https://www.rfc-editor.org/rfc/rfc2828.txt | 2026-11-12 | Confirmed |
| 87 | NIST, SP 800-23 | https://csrc.nist.gov/pubs/sp/800/23/final | 2026-11-12 | Confirmed |
| 88 | NIST, SP 800-25 | https://csrc.nist.gov/pubs/sp/800/25/final | 2026-11-12 | Confirmed |
| 89 | Google Patents, US 4,405,829 | https://patents.google.com/patent/US4405829A/en | 2026-11-12 | Confirmed |
| 90 | ISO, ISO/IEC 17799:2000 | https://www.iso.org/standard/33441.html | 2026-11-12 | Confirmed |
| 91 | CVE Program, History | https://www.cve.org/About/History | 2026-11-12 | Confirmed |
| 92 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 93 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 94 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` (with the `mitre/techniques/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_profiles.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 95 | TeamStarWolf library, `data/attack/software.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software.jsonl | 2026-11-12 | Confirmed (the library's record); Demonstrated (search) |
| 96 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` (with the `mitre/d3fend/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_to_d3fend.jsonl | 2026-11-12, 2026-11-13 | Confirmed |
| 97 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/cwe.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 98 | TeamStarWolf library, `data/weaknesses/` (with `capec.jsonl` and the `mitre/capec/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/weaknesses | 2026-11-13 | Demonstrated |
| 99 | TeamStarWolf library, `data/attack/ics/technique_profiles.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/ics/technique_profiles.jsonl | 2026-11-12 | Demonstrated |
| 100 | TeamStarWolf library, `mitre/campaigns/` (no C0020 page) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/campaigns | 2026-11-13 | Demonstrated |
| 101 | TeamStarWolf library, `mitre/` tree (group, software and technique pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre | 2026-11-12 | Confirmed (the library's record) |
| 102 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-12 | Confirmed (the library's record) |
| 103 | TeamStarWolf library, `case-studies/THREAT_ACTORS_CHINA.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/THREAT_ACTORS_CHINA.md | 2026-11-12 | Confirmed (the library's record) |
| 104 | TeamStarWolf library, `case-studies/THREAT_ACTORS_RUSSIA.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/THREAT_ACTORS_RUSSIA.md | 2026-11-12 | Confirmed (the library's record) |
| 105 | TeamStarWolf library, `case-studies/THREAT_ACTORS_UNITED_STATES.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/THREAT_ACTORS_UNITED_STATES.md | 2026-11-12 | Confirmed (the library's record) |
| 106 | TeamStarWolf library, main branch, `navigator/library-layers/` (the folder where this study's Enterprise layer is saved; not evidence) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-13 | Demonstrated (location) |
| 107 | TeamStarWolf library, `data/attack/superseded_by.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/superseded_by.jsonl | 2026-11-13 | Demonstrated |
| 108 | CVE Services API, CVE-2000-0884 | https://cveawg.mitre.org/api/cve/CVE-2000-0884 | 2026-11-13 | Confirmed |
| 109 | CVE Services API, CVE-2000-0573 | https://cveawg.mitre.org/api/cve/CVE-2000-0573 | 2026-11-13 | Confirmed |
| 110 | NVD API, CVE-2000-1039 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2000-1039` | 2026-11-13 | Confirmed |
| 111 | NVD API, CVE-2000-0621 | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2000-0621` | 2026-11-13 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md)
- Home studies: [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md); [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md); [The Cybercrime Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [Ransomware Ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md); [Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1036.007 Double File Extension](/mitre/techniques/T1036-007.md), [T1059.005 Visual Basic](/mitre/techniques/T1059-005.md), [T1059.003 Windows Command Shell](/mitre/techniques/T1059-003.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1547.001 Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md), [T1112 Modify Registry](/mitre/techniques/T1112.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1087.003 Email Account](/mitre/techniques/T1087-003.md), [T1083 File and Directory Discovery](/mitre/techniques/T1083.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1564.001 Hidden Files and Directories](/mitre/techniques/T1564-001.md), [T1135 Network Share Discovery](/mitre/techniques/T1135.md), [T1080 Taint Shared Content](/mitre/techniques/T1080.md), [T1021.002 SMB/Windows Admin Shares](/mitre/techniques/T1021-002.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1595.002 Vulnerability Scanning](/mitre/techniques/T1595-002.md), [T1584.005 Botnet](/mitre/techniques/T1584-005.md), [T1498 Network Denial of Service](/mitre/techniques/T1498.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1498.002 Reflection Amplification](/mitre/techniques/T1498-002.md), [T1499 Endpoint Denial of Service](/mitre/techniques/T1499.md), [T1219 Remote Access Tools](/mitre/techniques/T1219.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1110.002 Password Cracking](/mitre/techniques/T1110-002.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1090.003 Multi-hop Proxy](/mitre/techniques/T1090-003.md), [T1584.004 Server](/mitre/techniques/T1584-004.md), [T1491.002 External Defacement](/mitre/techniques/T1491-002.md), [T1657 Financial Theft](/mitre/techniques/T1657.md)
- CAPEC: [CAPEC-63](/mitre/capec/CAPEC-63.md), [CAPEC-64](/mitre/capec/CAPEC-64.md), [CAPEC-67](/mitre/capec/CAPEC-67.md), [CAPEC-71](/mitre/capec/CAPEC-71.md), [CAPEC-126](/mitre/capec/CAPEC-126.md), [CAPEC-135](/mitre/capec/CAPEC-135.md), [CAPEC-482](/mitre/capec/CAPEC-482.md), [CAPEC-490](/mitre/capec/CAPEC-490.md)
- Groups, software and campaigns: Maroochy Water Breach [C0020](https://attack.mitre.org/campaigns/C0020/) (ATT&CK for ICS; no library page); Turla [G0010](/mitre/groups/G0010.md) and Penquin [S0587](/mitre/software/S0587.md) for the proposed and unproven Moonlight Maze lineage; Equation [G0020](/mitre/groups/G0020.md), not placed in 2000
- [Navigator layers](/navigator/index.md), including this study's layers, [chronicle-2000.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2000.json) and [chronicle-2000-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2000-ics.json)
