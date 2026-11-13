# The Year 2001 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md) · Home studies for events summarized here: [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Code Red, Nimda, Klez, the Invita sting and the Gorshkov and Ivanov records, the Mafiaboy plea and sentence, Egghead.com, the PATRIOT Act amendment to the computer fraud law, the Budapest Convention, Moonlight Maze), [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) and [the NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md) (Equation), [The Cybercrime Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) (Max Butler) · Series: [The Year 1999 in Intrusions](/case-studies/CHRONICLE_1999.md), [The Year 2000 in Intrusions](/case-studies/CHRONICLE_2000.md) (the home for the Maroochy Shire intrusion), [The Year 2002 in Intrusions](/case-studies/CHRONICLE_2002.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 68 min (15,688 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2001, you need the year's CERT advisories and incident notes, Code Red, Nimda and the Unix worms side by side with the bogus Microsoft code-signing certificates, the Scarfo keystroke logger, the PATRIOT Act and the Budapest Convention, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 3: the worm year](#part-3-the-worm-year)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md), [The Year 2000 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2000.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

People who were running networks in 2001 remember it as the worm year, and the record supports them. Code Red arrived in July against Microsoft IIS web servers, Code Red II followed in August with a back door, and Nimda in September combined five ways of spreading, one of them through the back doors other worms had left behind (Confirmed [1][2]). CAIDA measured the second Code Red variant infecting more than 359,000 hosts in under 14 hours on 19 July, at a peak of more than 2,000 new hosts a minute (Confirmed [15][16]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the library's home for Code Red, Nimda and Klez (Confirmed [83]); this chronicle summarizes them and places them in the rest of the year's record.

The rest of that record is larger than the worms. CERT/CC published 37 advisories in 2001, from CA-2001-01 on 10 January to CA-2001-37 on 20 December, and 15 incident notes, IN-2001-01 to IN-2001-15 (Confirmed [1][2][3]). The year opened with a database server shipping a compiled-in back door account (10 January) and the self-propagating "ramen" toolkit taking root on Linux hosts through three known format-string flaws (18 January) (Confirmed [1][2]). BIND flaws announced on 29 January were being exploited with packaged kits by 30 March, at least one of them worm-like (Confirmed [1][2]). Solaris hosts fell to the snmpXdmid overflow, which was enabled by default, and then carried the "Carko" denial-of-service tool (Confirmed [1][2]). The sadmind/IIS worm in May crossed from Solaris to IIS using a two-year-old Solaris flaw and a seven-month-old IIS flaw (Confirmed [1]). The year closed with heavy scanning and exploitation of SSH daemons (13 December) and a Universal Plug and Play overflow that left every Windows XP system vulnerable in its default configuration (20 December) (Confirmed [1][10]).

One event of the year was a failure of trust rather than of code. On 29 and 30 January VeriSign issued two Class 3 code-signing certificates named "Microsoft Corporation" to someone who falsely claimed to be a Microsoft employee. Because the certificates carried no CRL distribution point, browsers had no way to check that they had been revoked (Confirmed [4]). CERT/CC called it a failure by the certificate authority to authenticate the recipient (Confirmed [1]). No CVE was assigned (Confirmed [4]).

The fix usually came before the worm. Microsoft published MS01-033, the fix for the idq.dll overflow Code Red used, on 18 June 2001, about four weeks before Code Red began attacking hosts (Confirmed [8][1]; the interval is Inferred). Nimda's mail path used an Internet Explorer flaw patched on 29 March (Confirmed [5][1]). The SSH1 flaw, whose NVD record is dated March, was being exploited in November and December (Confirmed [13][2][1]).

The state record of 2001 is mostly law, litigation and parliamentary findings, not attributed intrusions. A European Parliament temporary committee reported on 3 July that, although there was no formal proof, a global interception system run by five countries under the UK-USA Agreement was "no longer in doubt"; Parliament adopted the resolution on 5 September (Confirmed [66][67]). A federal court in New Jersey upheld the FBI's covert keystroke logger in US v. Scarfo on 26 December (Confirmed [68]). A Seattle court upheld the FBI's remote copying of data from two computers in Russia on 23 May (Confirmed [21]). Among the records checked here, the only intrusion set dated to 2001 that the library treats as state-linked is the group Kaspersky named Equation in 2015; Kaspersky dates one of its command-and-control domains to August 2001 (Confirmed [61]; the state link is the library's reading in its United States study [84], Inferred). Kaspersky names no country behind it (Confirmed [61][62]).

The law moved after September. The PATRIOT Act of 26 October amended the computer fraud statute and the surveillance statutes (Confirmed [33][34]). Executive orders created the Office of Homeland Security (8 October) and the President's Critical Infrastructure Protection Board (16 October) (Confirmed [36][37]). The Council of Europe's Convention on Cybercrime was done at Budapest on 23 November, and the UK's Anti-terrorism, Crime and Security Act received Royal Assent on 14 December (Confirmed [35][38]). Standards work dates to the same year: FIPS 140-2 (25 May), FIPS 197 for AES (26 November), NIST SP 800-31 on intrusion detection (November, withdrawn in 2007) and the launch of OWASP (1 December) (Confirmed [46][43][47][51]).

This study is the dated record of that year, built only from sources opened on 12 November 2026 and checked as of 13 November 2026. Ten parts cover the timeline, the vulnerability record, the worms, certificate trust, the state record, crime and prosecutions, law and policy, cryptography and standards, the industrial record and the defender view. An eleventh part maps the record to MITRE frameworks.

2001 has CVE ids, in the candidate form CAN-2001-xxxx that Microsoft's bulletins cite (Confirmed [8][5][7][10]). NVD lists no specific CWE for any of the year's CVEs checked here (Confirmed [13][14]). The first CWE List came in 2006, CAPEC in 2007 and ATT&CK in 2013 (Confirmed [57][58][59]). Every ATT&CK Enterprise, CWE, CAPEC and D3FEND id in Part 11 is therefore this study's later mapping (Inferred). The exceptions are the ATT&CK for ICS techniques of the Maroochy campaign, whose sentence falls in 2001 and which ATT&CK itself lists, and the four techniques ATT&CK records for Equation, which ATT&CK does not date (Confirmed [73][63]).

Evidence grades: CERT/CC advisories and incident notes, CERT vulnerability notes, vendor bulletins and vendor research, CVE and NVD records, CAIDA's own measurements, statutes, treaty texts, Federal Register notices, executive orders, court opinions and filings, Justice Department releases, GAO testimony and reports, European Parliament records, NIST, ISO, RFC Editor, OpenBSD and kernel.org records, MITRE's own pages and the library's data files are **Confirmed**. Facts that rest on a secondary source, on figures GAO relays from the press or a consultancy, on EPIC's or EFF's account of litigation they followed, or on researchers relaying an operation they hold no artefacts for are **Reported** and attributed. A query or data check this study ran itself is **Demonstrated**. Where the study draws its own conclusion it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2001, plus the boundary records that open or close a 2001 event: MS00-078 (October 2000), the AIPAC intrusion (1 November 2000), the Invita arrests (10 November 2000), the Maroochy intrusion (February to April 2000), and the 2002 Gorshkov sentence, McKinnon indictment and Scarfo plea, which [The Year 2002 in Intrusions](/case-studies/CHRONICLE_2002.md) carries in full |
| CERT/CC output | 37 advisories, CA-2001-01 (10 Jan) to CA-2001-37 (20 Dec); 15 incident notes, IN-2001-01 (18 Jan) to IN-2001-15 (4 Dec) (Confirmed [1][2][3]) |
| Exploited in the wild, per CERT | ramen toolkit via wu-ftpd, rpc.statd and LPRng (18 Jan); BIND via packaged kits (30 Mar); snmpXdmid on Solaris (30 Mar); sadmind/IIS (8 May); IIS idq.dll via Code Red (19 Jul) and Code Red II (6 Aug); null sa passwords on SQL Server (27 Nov); SSH1 CRC-32 detector (5 Nov, 13 Dec) (Confirmed [1][2]) |
| Worms and mass mailers | Anna Kournikova (12 Feb); Hybris (2 Mar); sadmind/IIS (8 May); cheese (17 May); W32/Leaves (3 Jul); Code Red (from about 12 to 13 Jul); Sircam (25 Jul); Code Red II (4 Aug); Nimda (18 Sep); Klez (26 Oct); Kaiten variant and BadTrans (27 Nov); Goner (4 Dec) (Confirmed [1][2][15][60]) |
| Code Red scale | More than 250,000 hosts (CERT, 19 Jul); at least 280,000 in the first wave (CERT, 26 Jul); 359,104 in under 14 hours (CAIDA); 975,000 servers and over $2.4 billion (Computer Economics, relayed by GAO) (Confirmed [1][16]; Reported [17]) |
| Trust failure | Two "Microsoft Corporation" code-signing certificates issued by VeriSign to an impostor (29 and 30 Jan); MS01-017 and CA-2001-04 (22 Mar); no CVE (Confirmed [4][1]) |
| Microsoft bulletins cited | MS01-017, MS01-020, MS01-023, MS01-026, MS01-033, MS01-044, MS01-059 (Confirmed [4] to [10]) |
| State record | Equation C&C domain registered (Aug, per Kaspersky 2015); ECHELON report (3 Jul) and resolution (5 Sep); Gorshkov remote-copy ruling (23 May); Scarfo keystroke-logger opinion (26 Dec) (Confirmed [61][66][67][21][68]) |
| Prosecutions | Gorshkov verdict (9 Oct); Khan indictment (22 Oct); Cisco insiders sentenced (26 Nov); Operations Buccaneer, Bandwidth and Digital Piratez (11 Dec); Sklyarov deferred prosecution (13 Dec); Mamich plea (18 Dec); McKinnon's alleged intrusions begin (Mar) (Confirmed [20][24][26][28][22][27][25]) |
| Law and policy | Interagency GLBA safeguards (published 1 Feb, effective 1 Jul); HIPAA privacy rule effective date (14 Apr); GAO-01-323 (25 Apr); EO 13228 (8 Oct); EO 13231 (16 Oct); PATRIOT Act (26 Oct); Budapest Convention (23 Nov); UK ATCSA (14 Dec) (Confirmed [40][39][19][36][37][33][35][38]) |
| Cryptography and standards | Draft AES (28 Feb); FIPS 140-2 (25 May); draft FIPS 180-2 (30 May); RFC 3164 (Aug); SP 800-31 (Nov); FIPS 197 (26 Nov); OWASP (1 Dec); OpenBSD 3.0 with PF (1 Dec); RC4 key-schedule paper (20 Dec) (Confirmed [42][46][45][52][47][43][51][53][55]) |
| Industrial | Maroochy Shire sewerage intruder sentenced (31 Oct); ATT&CK for ICS campaign C0020 (Confirmed [72][73]) |
| This study's MITRE binding | 27 ATT&CK Enterprise technique rows, every one a later mapping; 12 ATT&CK for ICS rows that ATT&CK lists for C0020; Equation (G0020) bound with its 2015 dating caveat; no software object; 14 CWE ids plus NVD-CWE-Other; 11 CAPEC entries; D3FEND pairings from the library's data; two Navigator layers (Part 11) |

### Key findings

- **The patch existed first.** MS01-033 preceded Code Red by about four weeks, sadmind/IIS used a two-year-old Solaris flaw and a seven-month-old IIS flaw, and Nimda's mail path used an Internet Explorer flaw fixed in March (Confirmed [8][1][5]; the reading is Inferred). The year's large exploit-driven outbreaks used known flaws, not new ones (Inferred).
- **Worms reused each other's work.** W32/Leaves reused SubSeven back doors, the cheese worm went after root shells earlier intrusions had left on TCP 10008, and Nimda scanned for the back doors Code Red II and sadmind/IIS had left (Confirmed [2][1]). One intruder's foothold became the next one's way in.
- **Unix carried much of the exploitation record.** ramen, the BIND kits, snmpXdmid with Carko, sadmind, cheese and the SSH CRC-32 compromises are all on CERT's 2001 record (Confirmed [1][2]). The Windows worms got the headlines (Inferred).
- **Defaults decided exposure.** IIS 5.0 installed by default on Windows 2000 Server, which is why default installs were open to the idq.dll flaw; snmpXdmid was enabled by default on Solaris; Microsoft DNS Server accepted bogus glue records by default; UPnP left every Windows XP system vulnerable in its default configuration (Confirmed [8][1][2][10]).
- **Certificate revocation did not work for code signing.** The VeriSign certificates could not be checked for revocation because they named no CRL distribution point. Microsoft had to ship a local CRL and a revocation handler to Windows users (Confirmed [4]).
- **The infrastructure took collateral damage.** Code Red stopped unpatched Cisco 600-series DSL routers from forwarding packets, Code Red traffic could stop IIS 4.0 servers with URL redirection enabled, patched or not, through a separate redirection flaw, and Anna Kournikova's mail degraded networks at several sites (Confirmed [1][9]).
- **The state record is a visibility gap.** No ATT&CK Enterprise group, software or campaign object in the library's data carries a date of 2002 or earlier (the earliest group "since at least" dates are 2004, and some Regin timestamps go back to 2003), and Equation's 2001 date comes from a vendor reconstruction published in 2015 (Confirmed [75][95][61]). The year's public state record is law and litigation (Inferred).
- **The government said its warning system was not ready.** GAO reported in April that NIPC's strategic analysis and warning capabilities had not been achieved, less than three months before Code Red (Confirmed [19]; the interval is Inferred).

### Top recommendations

1. **Measure the gap between a fix and its first worm.** MS01-033 came about four weeks before Code Red, and the SSH and IIS traversal flaws were months old when exploited (Confirmed [8][1][2]; Inferred). Track time to patch for internet-facing services against that gap, not against a calendar.
2. **Inventory what installs by default.** CERT and Microsoft named IIS on Windows 2000 Server, snmpXdmid on Solaris and UPnP on Windows XP as on by default (Confirmed [8][1][10]). Turn off what a host does not need, and check after maintenance: MS01-033 warns that adding or removing Windows components through Add/Remove Programs reinstates the removed .ida and .idq script mappings (Confirmed [8]).
3. **Assume a worm left a back door.** CERT's Nimda guidance was to reinstall from trusted media and patch offline, because Nimda trojanized binaries and reused other worms' back doors (Confirmed [1]). Code Red II survives a reboot, unlike Code Red (Confirmed [15]).
4. **Filter both directions.** CA-2001-26 advised ingress filtering of 80/tcp to hosts not authorized to serve the web and ingress and egress filtering of 69/udp; MS01-059 advised blocking ports 1900 and 5000 at the corporate firewall (Confirmed [1][10]).
5. **Show file extensions and keep anti-virus updating itself.** Anna Kournikova hid its .vbs extension behind Windows' default of hiding known extensions; CA-2001-26 advised automatic anti-virus updates and not opening attachments (Confirmed [1]).
6. **Make revocation checkable.** The 2001 certificates were revocable in principle and unrevocable in practice (Confirmed [4]). Every certificate a product trusts needs a revocation path the client actually checks (Inferred).
7. **Do not treat security products as exempt.** Check Point (9 July) and Gauntlet Firewall (6 September) had their own CERT advisories (Confirmed [1]).
8. **Close default and null passwords.** Kaiten spread through null sa passwords on SQL Server and MSDE, and Interbase shipped a compiled-in account (Confirmed [2][1]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, surveillance, cryptography, standards and policy dated to 2001, plus the later records that open, close or explain a 2001 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, numbers as the source states them. Sources were opened on 12 November 2026; the library's data files were checked again on 13 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a CERT/CC advisory, incident note or vulnerability note as SEI or CERT publishes it, a vendor bulletin or vendor research report, a CVE or NVD record, CAIDA's own measurement, a statute, a treaty text, a Federal Register notice, an executive order, a court opinion or filing, a Justice Department release, GAO testimony or a GAO report, a European Parliament record, a NIST, ISO, RFC Editor, OpenBSD or kernel.org record, a live ATT&CK page, or the library's data files as the record of what the library holds |
| Reported | Only a secondary source supports the fact: figures GAO relays from media reports or Computer Economics, EPIC's account of the Scarfo and Carnivore litigation, EFF's account of the Sklyarov arrest, the 2008 capture of the CCIPS case index, or researchers relaying an operation they hold no artefacts for. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: id existence, name and tactic matches and page existence in the library's data files and mitre/ page tree |
| Inferred | The study's own reasoning, labelled where it appears. Every ATT&CK Enterprise, CWE and CAPEC id bound to a 2001 event is Inferred as to the binding |

CAIDA's Code Red counts are CAIDA's own measurements, published by the team that ran them.

Limits a reader should know:

- **CVE dates lag events.** NVD's published date for CVE-2001-0500 is 21 July 2001, after the 18 June bulletin and two days after Code Red's mass spread, and its description names Code Red (Confirmed [14]). CERT's VU#952336 for the same flaw gives a public date of 18 June and a first-published date of 19 June, and does not mention Code Red (Confirmed [12]). NVD dates are list-entry dates, not disclosure dates (Inferred).
- **No contemporaneous ATT&CK, CWE or CAPEC.** MITRE began categorizing weaknesses as early as 1999, released the first CWE List in 2006 and CAPEC in 2007, and started ATT&CK in 2013 (Confirmed [57][58][59]).
- **The CERT text.** SEI's compilations of the 2001 CERT advisories and incident notes are the texts for every CA-2001 and IN-2001 item cited here [1][2], with SEI's 2001 advisory index for the count [3]. The CERT advisories print worm request strings, mail bodies and log patterns; none is reproduced here. CERT/CC's 2001 incident statistics were not opened, so this study gives no 2001 incident count.
- **The cost figures.** The Code Red cost estimate of over $2.4 billion and the count of 975,000 servers come from Computer Economics through GAO, and GAO's list of affected government sites and companies relays reports; both are Reported [17].
- **The CCIPS index.** The 2001 case list on cybercrime.gov was read from the UNT End of Term 2008 capture, and the individual releases it lists were not opened. It is Reported and used only for what the index itself shows [31].
- **What was not checked.** No primary was opened for: the arrest and Dutch sentence of the Anna Kournikova author; the May 2001 denial-of-service attack on GRC.com; the spring 2001 US-China defacement exchanges, for which the NIPC advisories were unreachable and no library study holds a record (Confirmed [86] for the library's record); the FBI's "Magic Lantern"; the Eli Lilly email disclosure; the Bibliofind card breach; the California ISO intrusion report; Cisco's Code Red advisory; the CRS report on cyberwarfare; CERT/CC's 2001 incident statistics; the Council of Europe's signature list; and the Borisov, Goldberg and Wagner WEP paper. They are left out. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1996 (frame) | Kaspersky: some Equation C&C servers appear to date from as early as 1996, and the group's computer network exploitation operations date "back to 2001, and perhaps as early as 1996" | Espionage | Confirmed | [61][62] |
| 1999 to 2003 (frame) | Kaspersky and King's College London relay that "Storm Cloud" was the evolved toolkit of the same Moonlight Maze operators after the 1999 publicity; its story leaked in 2003. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Espionage | Reported | [64][83] |
| 1999-01-15 | Under warrant, the FBI enters Nicodemo Scarfo's business office and later installs a "Key Logger System" to capture a PGP passphrase | Surveillance | Confirmed | [68] |
| 2000-02-09 to 2000-04-23 | Maroochy Shire sewerage intrusion; sentence falls in 2001 (below) | Industrial | Confirmed | [72] |
| 2000-05 to 2000-11 | Nicholas Mamich reaches 65 PACER servers on several hundred occasions, placing hidden files that bypass billing | Crime | Confirmed | [27] |
| 2000-10 to 2001-03-27 | Two Cisco accountants exceed their authorized access to Cisco's stock-option system and issue themselves nearly $8 million in stock | Insider | Confirmed | [26] |
| 2000-10-17 | MS00-078, IIS Web Server Folder Traversal (CVE-2000-0884), the flaw the 2001 worms reused | Vulnerability | Confirmed | [11] |
| 2000-11-01 | Intrusion into AIPAC's server: web site replaced, members' card data taken and posted (indicted 22 Oct 2001) | Crime | Confirmed | [24] |
| 2000-11-10 | Gorshkov and Ivanov arrested in Seattle after the FBI's undercover "Invita" meeting. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime | Confirmed | [20][83] |
| 2000-12 | ISO/IEC 17799:2000 published, the code of practice organizations had in hand during 2001 | Standards | Confirmed | [50] |
| 2001-01-04 | Linux 2.4.0 source tarballs dated on kernel.org | Platforms | Confirmed | [54] |
| 2001-01-10 | CA-2001-01: Interbase 4.x and 5.x, open-source Interbase 6.0 and 6.01 and Firebird 0.9-3 contain a compiled-in back door account with a fixed plaintext password (CVE-2001-0008) | Vulnerability | Confirmed | [1] |
| 2001-01-12 | DOJ CCIPS publishes "Searching and Seizing Computers and Obtaining Electronic Evidence in Criminal Investigations" | Law enforcement | Confirmed | [30] |
| 2001-01-18 | IN-2001-01: the self-propagating "ramen" toolkit recovered from compromised hosts; root through wu-ftpd, rpc.statd and LPRng flaws | Worm | Confirmed | [2] |
| 2001-01 (late) | EPIC: the FBI completes FOIA processing on Carnivore (a page count of 1,756 in all; 1,502 released in part, 254 withheld) | Surveillance | Reported | [71] |
| 2001-01-29 | CA-2001-02: four vulnerabilities in ISC BIND 4.9.x before 4.9.8 and 8.2.x before 8.2.3, including the TSIG overflow (CVE-2001-0010) | Vulnerability | Confirmed | [1] |
| 2001-01-29 and 01-30 | VeriSign issues two Class 3 code-signing certificates named "Microsoft Corporation" to an impostor | Trust | Confirmed | [4] |
| 2001-02-01 | Interagency Guidelines Establishing Standards for Safeguarding Customer Information (66 FR 8616), effective 1 Jul | Regulation | Confirmed | [40] |
| 2001-02-12 | CA-2001-03: VBS/OnTheFly ("Anna Kournikova") mails itself through Outlook; more than 100 sites reporting by 7 pm EST | Worm | Confirmed | [1] |
| 2001-02-26 | HHS corrects the HIPAA privacy rule's effective date to 14 Apr 2001; NIST SP 800-32 on public key technology | Regulation | Confirmed | [39][93] |
| 2001-02-28 | NIST announces the draft FIPS for AES (66 FR 12762) | Cryptography | Confirmed | [42] |
| 2001-03 | Gary McKinnon's alleged access to US military and NASA computers begins (allegations in the 2002 indictment) | Intrusion | Confirmed (allegation) | [25] |
| 2001-03-02 | IN-2001-02: intruders use open mail relays to spread the Hybris worm | Worm | Confirmed | [2] |
| 2001-03-12 (record date) | NVD's record for CVE-2001-0144, the SSH1 CRC-32 compensation attack detector integer overflow, carries this published date | Vulnerability | Confirmed | [13] |
| 2001-03 (mid) | VeriSign advises Microsoft of the certificates | Trust | Confirmed | [4] |
| 2001-03-22 | MS01-017 and CA-2001-04 on the unauthentic certificates; update available 28 Mar | Trust | Confirmed | [4][1] |
| 2001-03-29 | MS01-020: IE 5.01 and 5.5 run an HTML-mail attachment with an unusual MIME type without warning (CAN-2001-0154); CA-2001-06 follows on 3 Apr | Vulnerability | Confirmed | [5][1] |
| 2001-03-30 | CA-2001-05: snmpXdmid overflow on Solaris 2.6, 7 and 8 actively exploited for root | Exploitation | Confirmed | [1] |
| 2001-03-30 | IN-2001-03: two BIND flaws exploited with packaged kits, at least one worm-like (the lion toolkit), on Linux hosts | Worm | Confirmed | [2] |
| 2001-04-04 | Cisco accountants indicted | Insider | Confirmed | [26] |
| 2001-04-14 | HIPAA privacy rule effective date as corrected | Regulation | Confirmed | [39] |
| 2001-04-24 | IN-2001-04: the "Carko" DDoS tool installed on hosts compromised through snmpXdmid | DDoS | Confirmed | [2] |
| 2001-04-25 | GAO-01-323: NIPC's strategic analysis and warning capabilities not achieved (released 22 May) | Oversight | Confirmed | [19] |
| 2001-05-01 | MS01-023, Internet Printing ISAPI overflow in IIS 5.0 (CAN-2001-0241); CA-2001-10 (2 May) notes public proof of concept | Vulnerability | Confirmed | [6][1] |
| 2001-05-01 | CA-2001-09: statistical weaknesses in TCP initial sequence numbers (CAN-2001-0328) | Vulnerability | Confirmed | [1] |
| 2001-05-07 (index) | Ivanov indicted in Connecticut, per the CCIPS case index (the index entry also names an arrest; his arrest was in Seattle on 10 November 2000 [20]) | Crime | Reported | [31] |
| 2001-05-08 | CA-2001-11: the sadmind/IIS worm | Worm | Confirmed | [1] |
| 2001-05-14 | MS01-026 cumulative IIS patch, including the superfluous-decoding flaw (CAN-2001-0333); CA-2001-12 on 15 May | Vulnerability | Confirmed | [7][1] |
| 2001-05-17 | IN-2001-05: the "cheese" worm targets root shells left on TCP 10008 | Worm | Confirmed | [2] |
| 2001-05-21 | Max Butler (Max Vision) sentenced to 18 months. Home: [The Cybercrime Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) | Crime | Reported | [87] |
| 2001-05-23 | Chief Judge Coughenour denies Gorshkov's challenge to the FBI's remote copying of data from computers in Russia | Surveillance | Confirmed | [21] |
| 2001-05-25 | FIPS 140-2, Security Requirements for Cryptographic Modules | Standards | Confirmed | [46] |
| 2001-05-30 | Draft FIPS 180-2, Secure Hash Standard (66 FR 29287) | Cryptography | Confirmed | [45] |
| 2001-06-15 | NIST SP 800-27, Engineering Principles for IT Security | Standards | Confirmed | [92] |
| 2001-06-18 | MS01-033: idq.dll overflow, code runs as Local System (CAN-2001-0500); reported by eEye | Vulnerability | Confirmed | [8] |
| 2001-06-19 | CA-2001-13 on the same flaw; VU#952336 first published | Vulnerability | Confirmed | [1][12] |
| 2001-07-01 | Interagency GLBA safeguarding guidelines take effect | Regulation | Confirmed | [40] |
| 2001-07-03 | IN-2001-07: W32/Leaves reuses SubSeven back doors on home Windows machines | Worm | Confirmed | [2] |
| 2001-07-03 | European Parliament committee report A5-0264/2001 on the ECHELON interception system | Surveillance | Confirmed | [65][66] |
| 2001-07-09 | CA-2001-17: Check Point RDP bypass | Vulnerability | Confirmed | [1] |
| 2001-07-12 | CAIDA: Code-Red version 1 begins infecting unpatched IIS hosts | Worm | Confirmed | [15] |
| 2001-07-13 (about) | CERT: Code Red variants attacking hosts "since around July 13" | Worm | Confirmed | [1] |
| 2001-07-15 | Dmitry Sklyarov attends DEF CON Nine in Las Vegas as an ElcomSoft employee | Law | Confirmed | [22] |
| 2001-07-16 | EFF: Sklyarov arrested under DMCA section 1201(b)(1)(A); complaint dated 7 Jul | Law | Reported | [23] |
| 2001-07-19 | CAIDA: Code-Red v2 appears about 10:00 UTC and infects 359,104 hosts in under 14 hours | Worm | Confirmed | [16] |
| 2001-07-19 | CA-2001-19 and CA-2001-20: Code Red; more than 250,000 hosts may already be affected | Worm | Confirmed | [1] |
| 2001-07-20 to 07-27 | Code Red's flood phase against a fixed address that CAIDA identifies as www1.whitehouse.gov | DDoS | Confirmed | [1][16] |
| 2001-07-25 | CA-2001-22: W32/Sircam; more than 300 sites reporting by 10:00 EDT | Worm | Confirmed | [1] |
| 2001-07-26 | CA-2001-23: at least 280,000 hosts in the first wave; propagation expected to resume 1 Aug 00:00 GMT | Worm | Confirmed | [1] |
| 2001-07-30 | First Scarfo hearing on the keystroke logger | Surveillance | Confirmed | [68] |
| 2001-08 | One Equation C&C domain registered, per Kaspersky (2015) | Espionage | Confirmed | [61] |
| 2001-08 | RFC 3164, The BSD syslog Protocol | Standards | Confirmed | [52] |
| 2001-08-01 | EPIC: the FBI moves for summary judgment in the Carnivore FOIA case; EPIC moves to stay on 9 Aug | Surveillance | Reported | [71] |
| 2001-08-04 | CAIDA: Code Red II begins infecting machines | Worm | Confirmed | [15] |
| 2001-08-06 | IN-2001-09: Code Red II leaves a back door on Windows 2000 | Worm | Confirmed | [2] |
| 2001-08-07 | FTC proposes its GLBA Standards for Safeguarding Customer Information (66 FR 41162) | Regulation | Confirmed | [41] |
| 2001-08-07 | Scarfo court orders a report on how the keystroke logger works | Surveillance | Confirmed | [68] |
| 2001-08-15 | MS01-044 cumulative IIS patch for five flaws, including the MS01-033 fix | Vulnerability | Confirmed | [9] |
| 2001-08-20 | Cisco accountants plead guilty | Insider | Confirmed | [26] |
| 2001-08-28 | Grand jury indicts Sklyarov on one conspiracy count and four DMCA trafficking counts | Law | Confirmed | [22] |
| 2001-08-29 | GAO-01-1073T: testimony on Code Red, Code Red II and SirCam | Oversight | Confirmed | [17][18] |
| 2001-08-31 | IN-2001-11: DNS cache corruption on Microsoft DNS Server through bogus glue | Infrastructure | Confirmed | [2] |
| 2001-09-05 | European Parliament adopts the ECHELON resolution, 367 to 154 with 34 abstentions | Surveillance | Confirmed | [67] |
| 2001-09-06 | CA-2001-25: Gauntlet Firewall overflow | Vulnerability | Confirmed | [1] |
| 2001-09-06 and 09-07 | Gallagher affidavit says the keystroke logger was classified SECRET around November 1997; second Scarfo hearing | Surveillance | Confirmed | [68] |
| 2001-09-18 | CA-2001-26: Nimda | Worm | Confirmed | [1] |
| 2001-10 | Murch affidavit, the unclassified description of the keystroke logger | Surveillance | Confirmed | [69] |
| 2001-10-04 | EPIC: protective order denying classified discovery in Scarfo | Surveillance | Reported | [70] |
| 2001-10-08 | Executive Order 13228 establishes the Office of Homeland Security | Policy | Confirmed | [36] |
| 2001-10-09 | Seattle jury convicts Vasiliy Gorshkov on 20 counts (announced 10 Oct) | Crime | Confirmed | [20] |
| 2001-10-16 | Executive Order 13231, Critical Infrastructure Protection in the Information Age | Policy | Confirmed | [37] |
| 2001-10-17 | NIST SP 800-28, Guidelines on Active Content and Mobile Code | Standards | Confirmed | [48] |
| 2001-10-22 | Misbah Khan indicted in Maryland for the AIPAC intrusion | Crime | Confirmed | [24] |
| 2001-10-25 | Microsoft announces worldwide availability of Windows XP | Platforms | Confirmed | [56] |
| 2001-10-26 | USA PATRIOT Act, Pub. L. 107-56 | Law | Confirmed | [33][34] |
| 2001-10-26 | F-Secure: first Klez infections found | Worm | Confirmed | [60] |
| 2001-10-31 | Vitek Boden sentenced over the Maroochy intrusion, longest term two years | Industrial | Confirmed | [72] |
| 2001-11 | NIST SP 800-31, Intrusion Detection Systems; SP 800-26, Security Self-Assessment Guide | Standards | Confirmed | [47][91] |
| 2001-11-05 | IN-2001-12: compromises through the SSH1 CRC-32 detector flaw | Exploitation | Confirmed | [2] |
| 2001-11-23 | Convention on Cybercrime (ETS 185) done at Budapest | Law | Confirmed | [35] |
| 2001-11-26 | FIPS 197, Advanced Encryption Standard | Cryptography | Confirmed | [43] |
| 2001-11-26 | Cisco accountants each sentenced to 34 months | Insider | Confirmed | [26] |
| 2001-11-27 | IN-2001-13: Kaiten variant via null sa passwords; IN-2001-14: W32/BadTrans | Worm | Confirmed | [2] |
| 2001-11-29 | CA-2001-33: two remote flaws in WU-FTPD (CVE-2001-0550) | Vulnerability | Confirmed | [1] |
| 2001-12-01 | OWASP launched; OpenBSD 3.0 released with PF | Standards | Confirmed | [51][53] |
| 2001-12-04 | IN-2001-15: W32/Goner | Worm | Confirmed | [2] |
| 2001-12-06 | Commerce approves FIPS 197, binding on federal agencies from 26 May 2002 | Cryptography | Confirmed | [44] |
| 2001-12-11 | DOJ announces Operations Buccaneer, Bandwidth and Digital Piratez | Crime | Confirmed | [28][29] |
| 2001-12-13 | CA-2001-35: heavy SSH scanning and exploitation | Exploitation | Confirmed | [1] |
| 2001-12-13 | Sklyarov's deferred-prosecution agreement; ElcomSoft remains charged | Law | Confirmed | [22] |
| 2001-12-14 | UK Anti-terrorism, Crime and Security Act 2001, Royal Assent | Law | Confirmed | [38] |
| 2001-12-18 | Nicholas Mamich pleads guilty to the PACER intrusions | Crime | Confirmed | [27] |
| 2001-12 | NIST SP 800-33, Underlying Technical Models for IT Security | Standards | Confirmed | [94] |
| 2001-12-20 | MS01-059 and CA-2001-37: UPnP overflow (CAN-2001-0876, CAN-2001-0877) | Vulnerability | Confirmed | [10][1] |
| 2001-12-20 | Fluhrer, Mantin and Shamir, "Weaknesses in the Key Scheduling Algorithm of RC4", first online | Cryptography | Confirmed | [55] |
| 2001-12-26 | US v. Scarfo opinion upholds the keystroke logger | Surveillance | Confirmed | [68] |
| 2001-12-31 | Windows XP lifecycle start date, per Microsoft | Platforms | Confirmed | [90] |
| 2002-01 (boundary) | NIST SP 800-41 on firewalls; a 2002 publication, not 2001 | Standards | Confirmed | [49] |
| 2002-01-17 (boundary) | F-Secure: Klez.E first found | Worm | Confirmed | [60] |
| 2002-02-28 (boundary) | EPIC: Scarfo plea agreement ends the case with no appeal | Surveillance | Reported | [70] |
| 2002-10-04 (boundary) | Gorshkov sentenced to 36 months and nearly $700,000 restitution | Crime | Confirmed | [21] |
| 2002-11-12 (boundary) | McKinnon indicted in E.D. Va. on seven counts (allegations covering Mar 2001 to Mar 2002) | Intrusion | Confirmed | [25] |
| 2015-02-16 (boundary) | Kaspersky names the Equation group and dates its infections to 2001 | Espionage | Confirmed | [61] |

## Part 2: the vulnerability record

### The 37 advisories

CERT/CC published 37 advisories in 2001 (Confirmed [1][3]). Grouped by topic (the grouping is this study's; the advisory texts are SEI's compilation) (Confirmed [1]; grouping Inferred):

- **Exploited server flaws.** CA-2001-05 (30 Mar): numerous reports that the snmpXdmid overflow in Solaris 2.6, 7 and 8, enabled by default, was being exploited for root. CA-2001-35 (13 Dec): continued high scanning for and exploitation of SSH daemons, including the SSH1 CRC-32 integer overflow (VU#945216). Several SSH2 implementations fall back to SSH1 when it is present, so upgrading to SSH2 alone did not close the hole.
- **Worms and mass mailers.** CA-2001-03 (12 Feb) Anna Kournikova; CA-2001-11 (8 May) sadmind/IIS; CA-2001-19 and CA-2001-20 (19 Jul) and CA-2001-23 (26 Jul) Code Red; CA-2001-22 (25 Jul) Sircam; CA-2001-26 (18 Sep) Nimda.
- **Web servers.** CA-2001-10 (2 May): the Internet Printing ISAPI overflow, with a public proof of concept. CA-2001-12 (15 May): IIS superfluous decoding. CA-2001-13 (19 Jun): the IIS Indexing Service overflow, credited to eEye.
- **Infrastructure and naming.** CA-2001-02 (29 Jan): four BIND flaws in 4.9.x before 4.9.8 and 8.2.x before 8.2.3, with 9.x not affected. CA-2001-09 (1 May): TCP initial sequence numbers generated by random increments give too little variance, which lets an attacker disrupt, hijack or spoof connections on stacks without RFC 1948 or an equivalent fix (VU#498440, CAN-2001-0328).
- **Back doors and trust.** CA-2001-01 (10 Jan): Interbase's compiled-in account. CA-2001-04 (22 Mar): the unauthentic "Microsoft Corporation" certificates.
- **Clients.** CA-2001-06 (3 Apr): automatic execution of embedded MIME types in Internet Explorer.
- **Security products.** CA-2001-17 (9 Jul): Check Point RDP bypass. CA-2001-25 (6 Sep): a Gauntlet Firewall overflow that lets intruders run arbitrary code.
- **Other platforms.** CA-2001-27: a format-string flaw in CDE ToolTalk. CA-2001-33 (29 Nov): two remote flaws in WU-FTPD, including globbing (VU#886083, CVE-2001-0550). CA-2001-37 (20 Dec): the Windows UPnP overflow.

### What the record says about attackers

CERT's 2001 texts say outright that flaws were being used against real systems in these cases: the wu-ftpd, rpc.statd and LPRng flaws behind ramen; BIND; snmpXdmid; the sadmind and IIS traversal flaws behind sadmind/IIS; the idq.dll overflow behind Code Red and Code Red II; the IIS traversal and back doors behind Nimda; null sa passwords behind Kaiten; and the SSH1 CRC-32 flaw (Confirmed [1][2]). For the Interbase account, the TCP sequence-number weakness, the firewall advisories and UPnP, this study read no statement of exploitation in the passages cited, and it does not claim there was none (Inferred [1]).

### Microsoft's year

Seven Microsoft bulletins are cited in this study (Confirmed [4] to [10]):

- **MS01-017 (22 Mar).** The VeriSign certificates (Part 4). No CVE was assigned.
- **MS01-020 (29 Mar).** Internet Explorer 5.01 and 5.5 run an HTML-mail attachment that carries an unusual MIME type without a warning (CAN-2001-0154); fixed in IE 5.01 SP2. Nimda and BadTrans later used this flaw (Confirmed [5][1][2]).
- **MS01-023 (1 May).** The Internet Printing ISAPI extension overflow in IIS 5.0 on Windows 2000 (CAN-2001-0241).
- **MS01-026 (14 May).** A cumulative IIS patch. A second, superfluous decoding pass after the security checks let a crafted request escape the virtual folder structure and run operating-system commands as IUSR_machinename (CAN-2001-0333, with CAN-2001-0334 to 0337). Microsoft wrote that it would deploy cumulative patches whenever feasible and that patching alone does not secure a server.
- **MS01-033 (18 Jun).** The idq.dll overflow in Index Server 2.0 and the Windows 2000 Indexing Service gives code execution as Local System (CAN-2001-0500). Default Windows 2000 Server installs were vulnerable because IIS 5.0 installs by default. The workaround was to remove the .ida and .idq script mappings, which Add/Remove Programs could reinstate. The bulletin advised DMZ placement and stand-alone web servers and credited eEye with the report.
- **MS01-044 (15 Aug).** A cumulative IIS patch for five flaws (CAN-2001-0506, 0507, 0508, 0544 and 0545), which includes the MS01-033 fix "because of its seriousness". Code Red traffic also triggered a separate, previously unknown IIS 4.0 URL-redirection denial of service (CAN-2001-0545), which was widely but wrongly reported as a flaw in the MS01-033 patch.
- **MS01-059 (20 Dec).** An unchecked buffer in UPnP NOTIFY handling (CAN-2001-0876) and a denial of service (CAN-2001-0877). Every Windows XP system was vulnerable in its default configuration; Internet Connection Firewall, on by default when a wizard creates an Internet connection, blocks unicast attacks; the bulletin advised blocking ports 1900 and 5000 at the corporate firewall.

The 2000 bulletin MS00-078 (17 Oct 2000), the IIS Web Server Folder Traversal flaw (CVE-2000-0884), is the background to two 2001 worms: sadmind/IIS and Nimda both used it (Confirmed [11][1]). Microsoft released these bulletins on dates that varied through the year, not on a fixed monthly day (Confirmed [4] to [10] for the dates; Inferred for the pattern).

### The CVE record

Microsoft's 2001 bulletins cite CVE candidates in the CAN- form, so CVE naming was in daily vendor use (Confirmed [8][5][7][10]). NVD lists NVD-CWE-Other, with no specific CWE, for every 2001-era CVE checked: CVE-2001-0500, -0333, -0154, -0241, -0144, -0010, -0876, -0008, -0550 and -0328, and CVE-2000-0884 (Confirmed [13][14]). Any CWE this study binds is therefore its own reading (Inferred).

## Part 3: the worm year

### Code Red and Code Red II (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Code Red, with its own MITRE mappings and Navigator layer (Confirmed [83]). In brief: CAIDA dates Code-Red version 1, which used a static random seed, from 12 July; CERT says the variants had been attacking "since around July 13" (Confirmed [15][1]). The random-seed version 2 appeared about 10:00 UTC on 19 July and infected 359,104 hosts in under 14 hours. At the peak more than 2,000 new hosts were infected each minute. Of the infected hosts, 43 percent were in the US, 11 percent in Korea, 5 percent in China and 4 percent in Taiwan, and they included 136 .mil and 213 .gov hosts (Confirmed [15][16]). CERT's CA-2001-19 says the worm spread over TCP 80 to random addresses from day 1 to 19 of the month, flooded a fixed IP address from day 20 to 27, slept after that, and defaced English-language hosts in memory only. Cisco CallManager, Unity, uOne, ICS7750 and BBSM were affected, and unpatched Cisco 600-series DSL routers stopped forwarding packets (Confirmed [1]). CAIDA names the flood target as www1.whitehouse.gov, attacked by IP address from the 20th to the 28th (Confirmed [16]). Because the worm lived entirely in memory a reboot purged it, but CERT called patching imperative because reinfection was likely (Confirmed [1]). CA-2001-23 counted at least 280,000 hosts in the first wave and expected propagation to resume at 00:00 GMT on 1 August (Confirmed [1]).

Code Red II was a different worm that used the same overflow. CAIDA dates it from 4 August and says it installs a root-level remote-access back door, is not memory-resident and so survives a reboot, and neither defaces nor floods (Confirmed [15]). CERT's IN-2001-09 (6 August) says it had already affected thousands of systems, causing system-level compromise and leaving a back door on Windows 2000. It scanned with 600 threads for 48 hours on Chinese-language systems and 300 threads for 24 hours on others, placed the command interpreter in IIS script folders and dropped a Trojan explorer.exe (Confirmed [2]).

### What GAO told Congress

On 29 August Keith A. Rhodes, GAO's Chief Technologist, testified before the House Government Reform Subcommittee on Government Efficiency, Financial Management and Intergovernmental Relations (GAO-01-1073T, "Code Red, Code Red II, and SirCam Attacks Highlight Need for Proactive Measures") (Confirmed [17][18]). GAO cites NIPC: Code Red infected more than 250,000 systems in 9 hours on 19 July (Confirmed [17]). GAO relays reports that the White House changed its web site's IP address, DoD briefly shut its public web sites, Treasury's Financial Management Service disconnected from the Internet, and Hotmail, Qwest DSL and FedEx were affected. It also relays Computer Economics' estimate of 975,000 servers infected and over $2.4 billion in costs (Reported [17]). On Sircam, GAO says the worm was allegedly responsible for leaking secret documents of the Ukrainian government, reportedly infected an FBI computer that then mailed out private but not classified documents, and was reported in more than 100 countries (Reported [17]).

### Nimda (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is also the home for Nimda (Confirmed [83]). CERT's CA-2001-26 (18 September) describes a worm, which named itself "Concept Virus (CV) v.5", hitting Windows 95, 98, ME, NT and 2000 by five paths (Confirmed [1]):

- client to client by email, using the MIME flaw of CA-2001-06 and MS01-020;
- client to client through open network shares;
- server to client, through web sites it had compromised;
- client to server, by scanning for the IIS directory-traversal flaw (VU#111677, CA-2001-12);
- client to server, through the back doors Code Red II and sadmind/IIS had left.

It copied itself to IIS servers over TFTP, shared the C: drive as C$, created a Guest account and added it to Administrators, trojanized legitimate binaries and modified web documents. CERT received reports of denial of service from its scanning and mail traffic (Confirmed [1]). Its defender guidance is in Part 10.

### The Unix worms and kits

- **ramen (IN-2001-01, 18 Jan).** A publicly available, self-propagating intruder toolkit recovered from compromised hosts. It gains root through known wu-ftpd (VU#29823), rpc.statd (VU#34043) and LPRng (VU#382365) format-string flaws on Linux hosts (Confirmed [2]).
- **BIND kits (IN-2001-03, 30 Mar).** Two flaws from CA-2001-02 (VU#325431 and VU#196945) exploited with packaged kits, at least one with worm-like self-propagation (the "1i0n" or lion toolkit); the compromises reported involved Linux hosts (Confirmed [2]).
- **snmpXdmid and Carko (CA-2001-05, 30 Mar; IN-2001-04, 24 Apr).** Root through the default-enabled snmpXdmid on Solaris, then the "Carko" DDoS tool, similar to stacheldraht, installed on the compromised hosts (Confirmed [1][2]).
- **sadmind/IIS (CA-2001-11, 8 May).** The worm compromised Solaris through a two-year-old Solstice sadmind overflow (CA-1999-16), then attacked IIS through the seven-month-old Web Server Folder Traversal flaw (VU#111677, MS00-078, CVE-2000-0884), defacing web pages. After 2,000 IIS compromises it altered the Solaris host's own page, and it added a wildcard trust entry to root's .rhosts (Confirmed [1]).
- **cheese (IN-2001-05, 17 May).** A worm that spreads to hosts accepting connections on TCP 10008, where earlier intrusions had left root shells (Confirmed [2]).
- **SSH (IN-2001-12, 5 Nov; CA-2001-35, 13 Dec).** Systems compromised through the SSH1 CRC-32 compensation attack detector integer overflow (VU#945216, CVE-2001-0144, NVD record dated 12 March), with rootkits and Trojaned SSH installed and rising scans of 22/tcp (Confirmed [2][1][13]).

### The mail and client worms

- **Anna Kournikova (CA-2001-03, 12 Feb).** VBS/OnTheFly is a VBScript that mails itself through Outlook to every address-book entry. The attachment shows without its .vbs extension when Windows hides extensions for known file types. More than 100 sites had reported it by 7:00 pm EST on 12 February, several with network degradation from the mail traffic (Confirmed [1]).
- **Hybris (IN-2001-02, 2 Mar).** Intruders used open mail relays to spread it; it infects the Windows WSOCK32.DLL library to send copies of itself (Confirmed [2]).
- **W32/Leaves (IN-2001-07, 3 Jul).** It scans for home Windows machines already carrying the SubSeven Trojan and reuses those back doors. CERT pointed to NIPC advisory 01-014 (Confirmed [2]).
- **Sircam (CA-2001-22, 25 Jul).** It spreads by email in English or Spanish and through unprotected network shares, and may reveal or delete sensitive information; more than 300 sites had reported it by 10:00 EDT on 25 July (Confirmed [1]).
- **Klez (26 Oct).** F-Secure found the first infections early on 26 October. Klez can run from a viewed email through a known Internet Explorer flaw, and later variants terminate anti-virus and other-worm processes; Klez.E was first found on 17 January 2002 (Confirmed [60]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is its home (Confirmed [83]).
- **Kaiten (IN-2001-13, 27 Nov).** A variant, first seen in August and based on the "Knight" tool, also called W32/Voyager or W32/CBlade.worm, installed by exploiting null default sa passwords on Microsoft SQL Server and MSDE after scans of 1433/tcp (Confirmed [2]).
- **BadTrans (IN-2001-14, 27 Nov).** An email worm that uses the Internet Explorer MIME flaw (VU#980499) so that Outlook and Outlook Express may run it when the message is viewed (Confirmed [2]).
- **Goner (IN-2001-15, 4 Dec).** It spreads by email and ICQ file transfer as a file posing as a screen saver; CERT began receiving reports that morning (Confirmed [2]).

### The naming layer

IN-2001-11 (31 August) reported DNS cache corruption on Microsoft DNS Server, which by default accepts bogus glue records from non-delegated servers, with reports of malicious servers supplying bogus glue for the gTLD servers (Confirmed [2]). Together with the BIND kits and CA-2001-02, the year's DNS record touched both major server implementations (Inferred [1][2]).

### No ATT&CK software objects

The library's ATT&CK data has no software object for Code Red, Nimda, Sircam, Anna Kournikova, SubSeven, Kaiten, ramen, BadTrans or Klez, so any binding for the year's worms is technique-level only (Confirmed [76][78]). The dot-com study states the same for Code Red and Nimda in ATT&CK v20.0 (Confirmed [83]).

## Part 4: trust and the certificate failure

On 29 and 30 January 2001 VeriSign issued two Class 3 code-signing certificates with the common name "Microsoft Corporation" to an individual who fraudulently claimed to be a Microsoft employee. VeriSign advised Microsoft in mid-March, and Microsoft published MS01-017 on 22 March, with an update available on 28 March (version 2.0) (Confirmed [4]).

The problem was the revocation path. VeriSign's code-signing certificates carried no CRL distribution point, so no browser could find a revocation list for them (Confirmed [4]). Microsoft's update installed a local CRL and an installable revocation handler, and turned on publisher-certificate revocation checking in Internet Explorer (Confirmed [4]). No CVE was assigned (Confirmed [4]). CERT/CC's CA-2001-04, issued the same day, called it a failure by the certificate authority to authenticate the recipient and noted that Internet Explorer could not check the revocation (Confirmed [1]).

Neither record describes code actually signed with the certificates (Confirmed [4][1]). The certificates gave whoever held them the ability to sign code that would appear Microsoft-signed; this study binds that as an acquired capability, not as signed malware (Inferred). The [eMudhra certificate authority study](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md) shows the same trust question twenty-five years later (Inferred).

## Part 5: the state record

### Equation: dated to 2001 by a 2015 reconstruction

Kaspersky's report of 16 February 2015 says the Equation group has infected thousands, perhaps tens of thousands, of victims since 2001. One of its C&C domains was registered in August 2001; other C&C servers appear to date from as early as 1996, and the earliest samples were compiled in 2002 (Confirmed [61]). Kaspersky's Q&A (version 1.5, February 2015) dates the group's computer network exploitation operations "back to 2001, and perhaps as early as 1996". It places the early Windows 95 and 98 implant EQUATIONLASER at around 2001 to 2004 in one answer and 2001 to 2003 in another, and EQUATIONDRUG from 2003 to 2013 (Confirmed [62]). The hard-drive firmware reprogramming modules were compiled in 2010 and 2013, so the firmware technique is not a 2001 event (Confirmed [62]).

Kaspersky names no country or organization behind the group; the name refers to the group's preference for sophisticated encryption schemes. The Q&A's answer to who is behind it lists only leftover module keywords (Confirmed [61][62]). The library's [United States study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) is the home for Equation; it gives the earliest dated activity as the August 2001 domain and calls 2001 to 2010 "the silent decade", dated only later from artefacts recovered in 2011 to 2015 (Confirmed [84]). The [tool leaks study](/case-studies/NSA_CIA_TOOL_LEAKS.md) records the same August 2001 date (Confirmed [85]).

ATT&CK's [Equation (G0020)](/mitre/groups/G0020.md), version 1.2, created 31 May 2017 and modified 31 July 2026, lists four techniques and no aliases, software, activity dates or country (Confirmed [63]). The library's data matches the live page (Confirmed [74]). None of the four techniques can be tied to dated 2001 activity (Inferred [63]).

### Moonlight Maze: the successor (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Moonlight Maze (1996 to 1999). It links Turla and Penquin only as an unproven lineage and says no ATT&CK object exists for the era's intrusions (Confirmed [83]). The only bridge to 2001 is the researchers' relayed account of "Storm Cloud", the evolved toolkit of the same operators after the 1999 publicity, whose story leaked in 2003. Kaspersky and King's College London hold no Storm Cloud artefacts and date no event to 2001 (Reported [64]). They say the Penquin Turla codebase was developed mainly from 1999 to 2004, call the Moonlight Maze to Turla argument circumstantial and a conclusion "simply premature" (Reported [64]).

A wording caution. The phrase "pioneering state-sponsored cyberespionage" on the Securelist page appears in a sentence comparing Turla with Equation; the page does not itself call Moonlight Maze state-sponsored. The dot-com study's section on Moonlight Maze reads the page more strongly than its text, and this chronicle does not repeat that wording (Inferred [64][83]).

Regin, ATT&CK [S0019](/mitre/software/S0019.md), is a Windows malware object with no group; ATT&CK's description in the library's software profiles says some Regin timestamps date back to 2003, so it is not a 2001 object (Confirmed [95]).

### ECHELON

The European Parliament's procedure 2001/2098(INI) on the Echelon interception system reached its committee vote and report A5-0264/2001 on 3 July 2001, Parliament's debate and decision T5-0440/2001 on 5 September 2001, and its final act in OJ C 072 on 21 March 2002 (Confirmed [65]). The temporary committee's report found that, although there was no formal proof, a global interception system run by the USA, UK, Canada, Australia and New Zealand under the UK-USA Agreement was "no longer in doubt", and that it intercepts private and commercial communications, not military ones (Confirmed [66]). The committee found no evidence that the system was used to distort business competition. It relayed information obtained in the USA that 5% of intelligence gathered through non-open sources was used for economic intelligence, which could enable US industry to win up to 7 billion dollars in contracts (Reported [66]). It recommended European encryption software and conditions on US interception in Germany and the UK (Confirmed [66]). Parliament adopted the resolution on 5 September by 367 votes to 154, with 34 abstentions (Confirmed [67]).

### The FBI's keystroke logger

In US v. Scarfo, Judge Politan of the District of New Jersey issued his opinion on 26 December 2001 (Confirmed [68]). Under warrant the FBI entered Scarfo's business office on 15 January 1999 and later returned, under two further warrants, to install a "Key Logger System" to capture a PGP passphrase. The motion to suppress was denied, and discovery was limited to the unclassified Murch affidavit (Confirmed [68]). Hearings were held on 30 July and 7 September 2001, and an order of 7 August required a report on how the system works. The government invoked the Classified Information Procedures Act; the Gallagher affidavit of 6 September said the system was classified SECRET around November 1997. The court found it did not intercept wire communications under Title III (Confirmed [68]). The affidavit of Randall S. Murch, FBI Laboratory Division Deputy Assistant Director, executed in October 2001, is the unclassified description; it says the system was configured to avoid recording keystrokes sent through the communication ports (Confirmed [69]). EPIC records a protective order denying classified discovery on 4 October 2001 and a plea agreement on 28 February 2002 that ended the case with no appeal, and calls it the first known case of its kind (Reported [70]).

### Carnivore in 2001

EPIC says the FBI completed processing of its Carnivore FOIA request in late January 2001: a page count of 1,756 in all, with 1,502 released in part and 254 withheld. The FBI moved for summary judgment on 1 August 2001, and EPIC moved to stay on 9 August (Reported [71]).

### Remote access across a border

After the November 2000 arrests of Gorshkov and Ivanov, the FBI accessed two of the defendants' computers in Russia via the Internet and copied data under a magistrate's warrant. Chief Judge Coughenour denied Gorshkov's challenge in an order dated 23 May 2001 (Confirmed [21]).

### Surveillance in the PATRIOT Act

Section 216 of the PATRIOT Act extended pen register and trap and trace orders to routing and addressing information, excluding contents. An agency that installs its own device on a provider's packet-switched network must keep an audit record of the officers, times and configuration (Confirmed [33]). Section 217 allows interception of "computer trespasser" communications, and section 224 sunsets most of Title II on 31 December 2005, with section 216 excepted (Confirmed [33]). The computer-crime sections are in Part 7.

### The quiet year

No ATT&CK Enterprise group, software or campaign object in the library's data (the ICS campaign C0020 aside, Part 9) carries a date of 2002 or earlier. The earliest "since at least" dates are 2004 (APT28 [G0007](/mitre/groups/G0007.md), Turla [G0010](/mitre/groups/G0010.md), Darkhotel [G0012](/mitre/groups/G0012.md)), 2005 (Poseidon Group [G0033](/mitre/groups/G0033.md)) and 2006 (menuPass [G0045](/mitre/groups/G0045.md)) (Confirmed [75]). The library's [China study](/case-studies/THREAT_ACTORS_CHINA.md) starts its record in 2006 (Confirmed [86]). The state record that can be opened for 2001 is legal and parliamentary: ECHELON, the keystroke-logger litigation, the Gorshkov ruling, the PATRIOT Act and the Budapest Convention. Among the records checked here, the only intrusion set dated to 2001 that the library treats as state-linked is Equation, through a 2015 vendor reconstruction. The gap reflects limited visibility, not proof of inactivity (Inferred [61][75]).

## Part 6: crime and prosecutions

### Card theft and extortion (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for the Invita sting and the Gorshkov and Ivanov records (Confirmed [83]); the [e-commerce threats study](/case-studies/ECOMMERCE_THREATS.md) points there for them. In brief: a Seattle jury convicted Vasiliy Gorshkov of Chelyabinsk on 9 October 2001 on 20 counts of conspiracy, computer crimes and fraud, announced by DOJ on 10 October (Confirmed [20]). Victims included Speakeasy Network, Nara Bank, Central National Bank of Waco and PayPal. The ring broke into ISPs, e-commerce sites and online banks, stole card and financial data, and tried to extort victims (Confirmed [20]). Gorshkov and Alexey Ivanov had been arrested on 10 November 2000 after an FBI undercover "Invita" meeting, and more than 56,000 card numbers were found on their computers (Confirmed [20]). On 4 October 2002 Gorshkov was sentenced to 36 months and ordered to pay nearly $700,000 restitution; DOJ says the group extorted victims by threatening to expose data or damage their computers (Confirmed [21]). The CCIPS case index lists an entry on Ivanov's indictment in Connecticut on 7 May 2001 and further indictments on 20 June and 16 August (Reported [31]).

### Defacement and card data

On 22 October 2001 Misbah Khan of Karachi was indicted in Maryland for the 1 November 2000 intrusion into AIPAC's server: he replaced its web site and took and posted members' credit card data (Confirmed [24]).

### Insiders and court systems

- **Cisco.** On 26 November 2001 two former Cisco accountants, Osowski and Tang, were each sentenced to 34 months. Between October 2000 and 27 March 2001 they exceeded their authorized access to Cisco's stock-option system and used forged disbursal requests to issue themselves nearly $8 million ($7,868,637) in stock. They were indicted on 4 April and pleaded guilty on 20 August 2001 (Confirmed [26]).
- **PACER.** On 18 December 2001 Nicholas Mamich pleaded guilty under 18 U.S.C. 1030(a)(2)(B). From May to November 2000 he reached 65 PACER servers on several hundred occasions and downloaded millions of pages of records, placing hidden files that bypassed the billing program; the Administrative Office's cost was at least $40,000 (Confirmed [27]).

### Military and space systems

DOJ's indictment of 12 November 2002 alleges that Gary McKinnon of London, from March 2001 to March 2002, accessed and damaged 92 Army, Navy, Air Force, DoD and NASA computers and 6 private-business computers, causing about $900,000 in losses. These are allegations (Confirmed [25]). The indictment and what followed it are in the next year's record, [The Year 2002 in Intrusions](/case-studies/CHRONICLE_2002.md).

### Copyright and the DMCA

Dmitry Sklyarov attended DEF CON Nine in Las Vegas on 15 July 2001 as an ElcomSoft employee (Confirmed [22]). EFF dates his arrest to 16 July and the criminal complaint to 7 July (Reported [23]). A grand jury indicted him on 28 August on one conspiracy count (18 U.S.C. 371) and four counts of trafficking in circumvention technology (17 U.S.C. 1201(b)(1)(A)) over the Advanced eBook Processor (Confirmed [22]). On 13 December DOJ announced a deferred-prosecution agreement before Judge Whyte in San Jose, under which he would testify against ElcomSoft, which remained charged. It was the first criminal case under the DMCA (Confirmed [22]).

On 11 December 2001 DOJ announced Operations Buccaneer, Bandwidth and Digital Piratez, with about 100 search warrants executed worldwide against warez groups. Buccaneer, run by US Customs and CCIPS out of the Eastern District of Virginia, executed 58 warrants, and its primary target was DrinkOrDie, about 40 members worldwide (Confirmed [28]). The CCIPS release of the same date is headlined "Federal Law Enforcement Targets International Internet Piracy Syndicates" (Confirmed [29]).

### The rest of the docket

The CCIPS case index for 2001 lists 30 computer-crime releases (Reported [31]). Besides the cases above, it lists the Diekman stolen-card and Western Union scheme (18 April and 1 August), an IRS computer sabotage plea (24 July), Chase Manhattan insider cases and a NASA JPL intruder sentenced on 5 September (Reported [31]). The individual releases were not opened. The dot-com study is the home for the Mafiaboy plea and sentence and the Egghead.com Chapter 11 filing of 15 August 2001 (Confirmed [83]), and [The Cybercrime Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md) for Max Butler's 18-month sentence of 21 May 2001 (Reported [87]).

### The law-enforcement build-out

DOJ's CCIPS published its manual "Searching and Seizing Computers and Obtaining Electronic Evidence in Criminal Investigations", announced on 12 January 2001 (Confirmed [30]). Section 816 of the PATRIOT Act directed regional computer forensic laboratories (Confirmed [33]).

## Part 7: law, policy and regulation

### The computer fraud statute

The PATRIOT Act, Public Law 107-56 (H.R. 3162), was approved on 26 October 2001 (Confirmed [34]). Section 814, "Deterrence and Prevention of Cyberterrorism", amended 18 U.S.C. 1030(a)(5). Its harm thresholds include a loss of at least $5,000 in one year, impaired medical care, physical injury, a threat to public health or safety, and damage to government justice, defense or national-security systems. It broadened the 1030(a)(7) extortion offence to any person and reached computers outside the US used in interstate or foreign commerce (Confirmed [33][32]). Section 217 added the "computer trespasser" definition to 18 U.S.C. 2510, and section 1016 is the Critical Infrastructures Protection Act of 2001 (42 U.S.C. 5195c), with findings on interdependent physical and information infrastructures including telecommunications, energy, financial services and water (Confirmed [33]). The dot-com study is the home for the CFAA amendment (Confirmed [83]).

### The executive branch after September

Executive Order 13228, establishing the Office of Homeland Security and the Homeland Security Council, was signed on 8 October and published on 10 October (Confirmed [36]). Executive Order 13231, Critical Infrastructure Protection in the Information Age, was signed on 16 October (66 FR 53063, 18 October). It established the President's Critical Infrastructure Protection Board, whose Chair is also Special Advisor to the President for Cyberspace Security, and the National Infrastructure Advisory Council of up to 30 members. Its standing committees include Incident Response Coordination and Financial and Banking Information Infrastructure, and it revoked EO 13130 (Confirmed [37]).

### Oversight before the outbreaks

GAO-01-323, "Critical Infrastructure Protection: Significant Challenges in Developing National Capabilities", published on 25 April and released on 22 May, found that the NIPC strategic analysis and warning capabilities described in PDD 63 had not been achieved and that its information-sharing relationships were still developing (Confirmed [19]). That was less than three months before Code Red (Inferred). GAO's Code Red testimony followed on 29 August (Confirmed [17][18]).

### Financial and health privacy

The OCC, the Federal Reserve, FDIC and OTS issued a joint final rule on 1 February 2001 (66 FR 8616), the Interagency Guidelines Establishing Standards for Safeguarding Customer Information under GLBA sections 501 and 505(b), effective 1 July 2001 (Confirmed [40]). The FTC proposed its own GLBA safeguards standard on 7 August (66 FR 41162), with comments due 9 October (Confirmed [41]). An HHS final rule of 26 February (66 FR 12434) corrected the HIPAA privacy rule's effective date to 14 April 2001, which delayed the compliance dates, and a notice of 28 February (66 FR 12738) opened comments to 30 March (Confirmed [39]).

### Outside the United States

The Council of Europe Convention on Cybercrime (ETS 185) was done at Budapest on 23 November 2001 in English and French. Articles 2 to 6 define illegal access, illegal interception, data interference, system interference and misuse of devices; Articles 7 and 8 cover computer-related forgery and fraud; Article 9 covers child sexual abuse material; Article 10 covers copyright (Confirmed [35]). The dot-com study is its home (Confirmed [83]). The UK Anti-terrorism, Crime and Security Act 2001 (c. 24) received Royal Assent on 14 December; its Part 11 is "Retention of Communications Data" (Confirmed [38]).

## Part 8: cryptography, standards and defender tooling

- **AES.** NIST announced the draft FIPS for the Advanced Encryption Standard on 28 February (66 FR 12762) (Confirmed [42]). FIPS 197 was published on 26 November (Confirmed [43]). Commerce's approval notice of 6 December (66 FR 63369) made it compulsory and binding on federal agencies for sensitive unclassified information from 26 May 2002, replacing the aging DES (Confirmed [44]).
- **Hashing and modules.** NIST announced draft FIPS 180-2, the Secure Hash Standard, on 30 May (66 FR 29287) (Confirmed [45]). FIPS 140-2, Security Requirements for Cryptographic Modules, was published on 25 May (Confirmed [46]).
- **RC4.** Fluhrer, Mantin and Shamir's "Weaknesses in the Key Scheduling Algorithm of RC4" (Selected Areas in Cryptography 2001) was first online on 20 December. This study read the publisher record, not the paper, and does not grade its wireless-network result (Confirmed [55]).
- **NIST guidance.** SP 800-31, Intrusion Detection Systems, by Rebecca Bace and Peter Mell (November 2001; withdrawn 20 February 2007 and superseded by SP 800-94) (Confirmed [47]). SP 800-32 (26 February), SP 800-27 (15 June), SP 800-28 (17 October), SP 800-26 (November) and SP 800-33 (December) (Confirmed [93][92][48][91][94]). SP 800-41 on firewalls is dated January 2002, and SP 800-30 and SP 800-34 are 2002 publications (Confirmed [49]).
- **The management standard.** ISO/IEC 17799:2000, published in December 2000 and now withdrawn, was the code of practice organizations had in hand during 2001 (Confirmed [50]).
- **Logging and packet filtering.** RFC 3164, The BSD syslog Protocol, was published as an Informational RFC in August (Confirmed [52]). OpenBSD 3.0 shipped on 1 December with PF, a new packet filter with NAT and a mostly ipf-compatible syntax (Confirmed [53]). Linux 2.4.0's tarballs are dated 4 January 2001, and netfilter was founded to redesign the 2.2 ipchains and 2.0 ipfwadm systems; that 2.4 shipped netfilter and iptables is this study's inference from the two records (Confirmed [54][89] for the records; Inferred for the link).
- **Application security.** The OWASP project launched on 1 December 2001 and was incorporated as the OWASP Foundation on 21 April 2004 (Confirmed [51]).
- **Platforms.** Microsoft announced worldwide availability of Windows XP in New York on 25 October; its lifecycle start date is 31 December 2001 (Confirmed [56][90]). MS01-059 records that Internet Connection Firewall was on by default when a wizard created an Internet connection (Confirmed [10]).

## Part 9: the industrial record

### Maroochy Shire: the sentence

The Queensland Court of Appeal's judgment in R v Boden [2002] QCA 164 records that between 9 February and 23 April 2000 Boden accessed the computers controlling the Maroochy Shire Council sewerage system, about 150 pumping stations with PDS Compact 500 units on a private two-way radio network, and altered pumping-station data. He was convicted of 26 counts involving a restricted computer, plus counts of damage over $5,000, serious environmental harm and theft, and was sentenced on 31 October 2001 to a longest term of two years, served concurrently (Confirmed [72]). The intrusion itself is dated 2000 (Confirmed [72]), and the [2000 chronicle](/case-studies/CHRONICLE_2000.md) is the library's home for it; this study records the 2001 sentence and the ATT&CK for ICS campaign.

### The ATT&CK record

ATT&CK for ICS records the event as campaign C0020, Maroochy Water Breach, first seen in February 2000 and last seen in April 2000, with 800,000 liters of raw sewage, and maps 12 techniques (Confirmed [73]). The names match the library's ICS data, and the library has no C0020 campaign page and no per-technique ICS pages (Confirmed [73]; Demonstrated [88]). The 800,000-liter figure is ATT&CK's; the judgment passages cited give no volume (Confirmed [73][72]).

## Part 10: the defender view

**The fix was out; the hosts were not patched.** MS01-033 came about four weeks before Code Red, and CERT called patching imperative even though a reboot purged the first Code Red (Confirmed [8][1]). CA-2001-35 found SSH daemons exploited through a flaw whose NVD record is dated March (Confirmed [1][2][13]). The [Log4Shell study](/case-studies/LOG4SHELL.md) shows the other end of that race two decades later, exploitation that began before the public disclosure and the fix (Inferred).

**A reboot is not a cleanup.** Code Red lived in memory; Code Red II survived reboots and left a back door; Nimda trojanized binaries and created accounts (Confirmed [15][2][1]). CERT's Nimda advice was to reinstall from trusted media and patch offline, because the worm had changed the system (Confirmed [1]).

**Filter by role.** CA-2001-26 advised ingress filtering of 80/tcp to hosts that are not authorized web servers and ingress and egress filtering of 69/udp, because Nimda used TFTP to copy itself (Confirmed [1]). MS01-033 advised placing web servers in a DMZ as stand-alone hosts (Confirmed [8]). MS01-059 advised blocking ports 1900 and 5000 at the corporate firewall (Confirmed [10]).

**Filtering is not the whole defense.** Two firewall products had their own advisories, and Nimda came through mail, browsers and file shares where port filtering did not apply (Confirmed [1]; Inferred).

**Keep the clients current and quiet.** CA-2001-26 advised anti-virus with automatic updates, not opening attachments and disabling JavaScript until patched (Confirmed [1]). Anna Kournikova relied on hidden extensions, and Nimda and BadTrans on a March Internet Explorer flaw (Confirmed [1][5][2]).

**Cumulative patches change the work.** MS01-026 and MS01-044 bundled fixes, and Microsoft said it would issue cumulative patches whenever feasible (Confirmed [7][9]). MS01-044 also shows why test traffic matters: Code Red's requests could stop the IIS 4.0 service on servers with URL redirection enabled, patched or not, through a separate flaw that was widely but wrongly reported as a fault in the MS01-033 patch (Confirmed [9]).

**Defaults and restored settings.** MS01-033 warned that removed script mappings could come back when components were added or removed (Confirmed [8]). Configuration drift was a 2001 problem before it had the name (Inferred).

**Trust needs a working revocation check.** The VeriSign certificates show what happens when revocation is possible on paper and impossible in the client (Confirmed [4][1]).

**Watch the people with access.** The Cisco accountants exceeded access they were given, and Mamich and Boden reached systems through access paths the operators did not control (Confirmed [26][27][72] for the cases; the common thread is Inferred).

## Part 11: MITRE mappings

No 2001 record carries an ATT&CK Enterprise, CWE or CAPEC id. The first CWE List came in 2006, CAPEC in 2007 and ATT&CK in 2013 (Confirmed [57][58][59]). Every Enterprise binding below is this study's later mapping (Inferred). Two tables are different: ATT&CK itself lists the ICS techniques for campaign C0020 (Confirmed [73]) and the four Equation techniques for G0020 (Confirmed [63]). Every id was checked against the library's data files and the generated pages under `mitre/` (Demonstrated [77][79][80][81][88]). Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the event or object. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a secondary source supports the behavior. **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | ramen via wu-ftpd, rpc.statd and LPRng (IN-2001-01, 18 Jan); BIND kits (IN-2001-03, 30 Mar); snmpXdmid (CA-2001-05, 30 Mar); sadmind/IIS against IIS (CA-2001-11, 8 May); Code Red (CA-2001-19, 19 Jul); Code Red II (IN-2001-09, 6 Aug); Nimda against IIS (CA-2001-26, 18 Sep) | [2][1] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Described | sadmind/IIS spreads Solaris to Solaris through sadmind (8 May); SSH1 CRC-32 exploitation (IN-2001-12, 5 Nov; CA-2001-35, 13 Dec) | [1][2] |
| [`T1595.001`](/mitre/techniques/T1595-001.md) | Scanning IP Blocks | reconnaissance | Inferred | Worm propagation scanning, the closest fit, not pre-targeting reconnaissance: Code Red's random addresses on TCP 80 (19 Jul); rising 22/tcp scans (5 Nov); 1433/tcp scans before Kaiten (27 Nov) | [1][2] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | impact | Described | sadmind/IIS (8 May); Code Red's English-language defacement (19 Jul); AIPAC web site replaced (1 Nov 2000; indicted 22 Oct 2001) | [1][24] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | Code Red's flood of a fixed address on days 20 to 27 (CA-2001-19, CA-2001-23) | [1][16] |
| [`T1499`](/mitre/techniques/T1499.md) | Endpoint Denial of Service | impact | Inferred | Cisco 600-series DSL routers stop forwarding (19 Jul); IIS 4.0 redirection crash from Code Red traffic (MS01-044, 15 Aug). Side effects, not stated intent | [1][9] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Botnet | resource-development | Described | The Carko DDoS tool installed on hosts compromised through snmpXdmid (IN-2001-04, 24 Apr) | [2] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Inferred | Mass-mailed attachments, not targeted, so the targeted-delivery technique is the closest fit only: Anna Kournikova (12 Feb), Sircam (25 Jul), Nimda (18 Sep), BadTrans (27 Nov), Goner (4 Dec) | [1][2] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | Anna Kournikova, Sircam and Goner need the user to open the file (12 Feb, 25 Jul, 4 Dec) | [1][2] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Visual Basic | execution | Described | VBS/OnTheFly is a VBScript program (CA-2001-03, 12 Feb) | [1] |
| [`T1036.007`](/mitre/techniques/T1036-007.md) | Double File Extension | stealth | Described | Anna Kournikova's attachment hides its .vbs extension (12 Feb) | [1] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | The IE MIME flaw (MS01-020, 29 Mar) used by Nimda (18 Sep) and BadTrans (27 Nov); Klez runs from a viewed email through a known IE flaw (26 Oct) | [5][1][2][60] |
| [`T1189`](/mitre/techniques/T1189.md) | Drive-by Compromise | initial-access | Described | Nimda served from compromised web sites to browsers (18 Sep) | [1] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | lateral-movement | Described | Nimda modifies web documents and spreads through open shares (18 Sep); Sircam spreads through unprotected shares (25 Jul) | [1] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | discovery | Inferred | Sircam and Nimda reach unprotected shares; the advisories do not describe how they find them | [1] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | SMB/Windows Admin Shares | lateral-movement | Inferred | Nimda shares C: as C$ (18 Sep); CERT does not describe the share being used to move | [1] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Described | Nimda copies itself to IIS servers over TFTP (18 Sep) | [1] |
| [`T1136.001`](/mitre/techniques/T1136-001.md) | Local Account | persistence | Described | Nimda creates a Guest account (18 Sep) | [1] |
| [`T1098`](/mitre/techniques/T1098.md) | Account Manipulation | persistence, privilege-escalation | Described | Nimda adds Guest to Administrators (18 Sep); sadmind/IIS adds a wildcard trust entry to root's .rhosts (8 May) | [1] |
| [`T1554`](/mitre/techniques/T1554.md) | Compromise Host Software Binary | persistence | Described | Nimda trojanizes legitimate binaries (18 Sep) | [1] |
| [`T1505.003`](/mitre/techniques/T1505-003.md) | Web Shell | persistence | Inferred | Code Red II places the command interpreter in IIS script folders (IN-2001-09, 6 Aug); the closest fit, not an exact one | [2] |
| [`T1588.003`](/mitre/techniques/T1588-003.md) | Code Signing Certificates | resource-development | Described | An impostor obtains two "Microsoft Corporation" certificates from VeriSign (29 and 30 Jan; MS01-017, 22 Mar) | [4][1] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Default Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Kaiten through null sa passwords on SQL Server and MSDE (IN-2001-13, 27 Nov); the Interbase compiled-in account (CA-2001-01, 10 Jan) is a flaw class with no exploitation stated | [2][1] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Cisco accountants exceed their authorized access to the stock-option system (Oct 2000 to Mar 2001; sentenced 26 Nov) | [26] |
| [`T1565.001`](/mitre/techniques/T1565-001.md) | Stored Data Manipulation | impact | Inferred | Forged disbursal requests issue nearly $8 million in Cisco stock; DOJ does not describe how the records were changed | [26] |
| [`T1564.001`](/mitre/techniques/T1564-001.md) | Hidden Files and Directories | stealth | Described | Hidden files on PACER servers bypass the billing program (May to Nov 2000; plea 18 Dec 2001) | [27] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | impact | Described | The Gorshkov and Ivanov ring steals card and bank data and extorts victims (verdict 9 Oct 2001) | [20][21] |

Left out on purpose: T1046 Network Service Discovery, because the worms' scans were external scanning of random addresses, which T1595.001 covers, and the records do not say the scans ran from inside victim networks (Inferred [1][2]). T1553.002 Code Signing, because neither MS01-017 nor CA-2001-04 records code actually signed with the bogus certificates; the acquisition is bound through T1588.003 and the risk through CAPEC-206 below (Confirmed [4][1]; Inferred). T1588.004 Digital Certificates, because T1588.003 is the more specific fit (Inferred). [T1056.001 Keylogging](/mitre/techniques/T1056-001.md) for the FBI's Key Logger System, because it is state collection under warrant and ATT&CK records no object for it; the match is Inferred only [68]. The TCP initial sequence number weakness (CA-2001-09), which has no clean technique and no exploitation stated (Inferred [1]). W32/Leaves and cheese reusing earlier back doors, which no technique in the library's data names precisely (Inferred [2]). McKinnon's alleged intrusions, for which the indictment release gives no method (Confirmed [25]). Equation's four techniques, which go in their own table below.

### ATT&CK techniques recorded for Equation (not dated to 2001)

ATT&CK lists these four techniques for [G0020](/mitre/groups/G0020.md) (Confirmed [63]); the library's data matches (Confirmed [74]). ATT&CK records them for the group, not for 2001, and Kaspersky dates the firmware modules to 2010 and 2013 (Confirmed [62]). They are not in this study's Navigator layer (Inferred).

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Note | Sources |
|---|---|---|---|---|---|
| [`T1480.001`](/mitre/techniques/T1480-001.md) | Environmental Keying | stealth | Listed (group) | Not dated to 2001 | [63][74] |
| [`T1564.005`](/mitre/techniques/T1564-005.md) | Hidden File System | stealth | Listed (group) | Not dated to 2001 | [63][74] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | discovery | Listed (group) | Not dated to 2001 | [63][74] |
| [`T1542.002`](/mitre/techniques/T1542-002.md) | Component Firmware | stealth, persistence | Listed (group) | Firmware modules compiled 2010 and 2013 | [63][74][62] |

### ATT&CK for ICS techniques

ATT&CK lists these 12 techniques for campaign C0020, Maroochy Water Breach (Confirmed [73]). The names and tactics match the library's ICS data, and T1692.001 and T1692.002 are the current ids in that data (Demonstrated [88]). The library has no generated ICS technique pages, so the ids link to ATT&CK. The intrusion is dated 2000; the 2001 event is the sentence of 31 October (Confirmed [72]).

| Id | Name | Tactic(s) | Basis | Sources |
|---|---|---|---|---|
| [`T0848`](https://attack.mitre.org/techniques/T0848/) | Rogue Master | initial-access | Listed | [73][88] |
| [`T0860`](https://attack.mitre.org/techniques/T0860/) | Wireless Compromise | initial-access | Listed | [73][88] |
| [`T0864`](https://attack.mitre.org/techniques/T0864/) | Transient Cyber Asset | initial-access | Listed | [73][88] |
| [`T0822`](https://attack.mitre.org/techniques/T0822/) | External Remote Services | initial-access | Listed | [73][88] |
| [`T0836`](https://attack.mitre.org/techniques/T0836/) | Modify Parameter | impair-process-control | Listed | [73][88] |
| [`T1692.001`](https://attack.mitre.org/techniques/T1692/001/) | Command Message | evasion, impair-process-control | Listed | [73][88] |
| [`T1692.002`](https://attack.mitre.org/techniques/T1692/002/) | Reporting Message | evasion, impair-process-control | Listed | [73][88] |
| [`T0878`](https://attack.mitre.org/techniques/T0878/) | Alarm Suppression | inhibit-response-function | Listed | [73][88] |
| [`T0838`](https://attack.mitre.org/techniques/T0838/) | Modify Alarm Settings | inhibit-response-function | Listed | [73][88] |
| [`T0813`](https://attack.mitre.org/techniques/T0813/) | Denial of Control | impact | Listed | [73][88] |
| [`T0815`](https://attack.mitre.org/techniques/T0815/) | Denial of View | impact | Listed | [73][88] |
| [`T0879`](https://attack.mitre.org/techniques/T0879/) | Damage to Property | impact | Listed | [73][88] |

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| Equation | [G0020](/mitre/groups/G0020.md) | Bound with a caveat: Kaspersky's 2015 report dates a C&C domain to August 2001 and operations to 2001 or earlier; ATT&CK carries no dates, aliases, software or country | [61][62][63][74] |
| Maroochy Water Breach (ATT&CK for ICS campaign) | [C0020](https://attack.mitre.org/campaigns/C0020/) | Bound for the 2001 sentence; first seen February 2000, last seen April 2000. The library has no page for it, so the link goes to ATT&CK | [73][72] |
| Turla | [G0010](/mitre/groups/G0010.md) | Context only: earliest "since at least" date 2004 in the library's data; the Moonlight Maze lineage is unproven | [75][64][83] |
| Penquin | [S0587](/mitre/software/S0587.md) | Context only: the researchers date the Penquin Turla codebase to 1999 to 2004 and call a Turla link premature | [64][83] |
| Regin | [S0019](/mitre/software/S0019.md) | Context only: timestamps date back to 2003; not a 2001 object | [95] |

No software object is bound. The library's software data has no entry for Code Red, Nimda, Sircam, Anna Kournikova, SubSeven, Kaiten, ramen, BadTrans or Klez (Confirmed [76][78]).

### CWE and CAPEC

NVD lists only NVD-CWE-Other for the 2001-era CVEs checked (Confirmed [13][14]), so every CWE below is this study's reading, not an NVD mapping (Inferred). Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [79][80]).

| CWE | Weakness (library name) | 2001 record | CAPEC |
|---|---|---|---|
| CWE-120 | Buffer Copy without Checking Size of Input | idq.dll unchecked buffer (CAN-2001-0500, MS01-033, 18 Jun); UPnP unchecked buffer (CAN-2001-0876, MS01-059, 20 Dec) | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers |
| CWE-174 | Double Decoding of the Same Data | IIS superfluous decoding (CAN-2001-0333, MS01-026, 14 May) | [CAPEC-120](/mitre/capec/CAPEC-120.md) Double Encoding |
| CWE-176 | Improper Handling of Unicode Encoding | IIS Web Server Folder Traversal (CVE-2000-0884), reused by sadmind/IIS and Nimda | [CAPEC-71](/mitre/capec/CAPEC-71.md) Using Unicode Encoding to Bypass Validation Logic; [CAPEC-64](/mitre/capec/CAPEC-64.md) Using Slashes and URL Encoding Combined to Bypass Validation Logic |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | The same traversal flaws (CVE-2000-0884, CAN-2001-0333) | [CAPEC-126](/mitre/capec/CAPEC-126.md) Path Traversal |
| CWE-798 and CWE-912 | Use of Hard-coded Credentials; Hidden Functionality | Interbase compiled-in back door account (CVE-2001-0008, CA-2001-01, 10 Jan) | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords (the library lists it on T1078.001) |
| CWE-1393 | Use of Default Password | Null sa passwords exploited by Kaiten (IN-2001-13, 27 Nov) | [CAPEC-70](/mitre/capec/CAPEC-70.md) |
| CWE-134 | Use of Externally-Controlled Format String | The wu-ftpd, rpc.statd and LPRng flaws behind ramen (18 Jan); CDE ToolTalk (CA-2001-27) | [CAPEC-135](/mitre/capec/CAPEC-135.md) Format String Injection |
| CWE-190 | Integer Overflow or Wraparound | SSH1 CRC-32 detector (CVE-2001-0144; exploited per IN-2001-12 and CA-2001-35) | [CAPEC-92](/mitre/capec/CAPEC-92.md) Forced Integer Overflow |
| CWE-342 and CWE-330 | Predictable Exact Value from Previous Values; Use of Insufficiently Random Values | TCP initial sequence numbers (CAN-2001-0328, CA-2001-09, 1 May) | None assigned |
| CWE-299 | Improper Check for Certificate Revocation | No CRL distribution point in the VeriSign code-signing certificates (MS01-017, 22 Mar) | [CAPEC-206](/mitre/capec/CAPEC-206.md) Signing Malicious Code, the pattern the certificates made possible; no signed code is on the record (the library lists CAPEC-206 on T1553.002) |
| CWE-1188 | Initialization of a Resource with an Insecure Default | IIS 5.0 on by default in Windows 2000 Server (MS01-033); UPnP on by default in Windows XP (MS01-059); snmpXdmid enabled by default (CA-2001-05) | None assigned |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | The year's worms as a class | None assigned |
| none bound | (flooding) | Code Red's flood phase (19 Jul onward) | [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding; [CAPEC-482](/mitre/capec/CAPEC-482.md) TCP Flood (the library lists both on T1498.001) |
| NVD-CWE-Other | (as NVD lists it) | BIND TSIG overflow (CVE-2001-0010), Internet Printing overflow (CVE-2001-0241), IE MIME flaw (CVE-2001-0154), WU-FTPD globbing (CVE-2001-0550) | CAPEC-100 for the two overflows, this study's pairing |

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data unless the row says the pairing is this study's; pairing them with the 2001 advice is this study's reading (Confirmed [81]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [81]).

| Technique from the record | D3FEND countermeasures | 2001 analogue |
|---|---|---|
| T1190, T1498.001, T1566.001 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (D3-ITF) | Ingress filtering of 80/tcp and 69/udp (CA-2001-26); blocking 1900 and 5000 (MS01-059) [1][10] |
| T1105 | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (D3-OTF) | Egress filtering of 69/udp against Nimda's TFTP copies (CA-2001-26) [1] |
| T1105, T1189, T1190, T1210, T1498.001, T1566.001 | [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) (D3-NTF) | DMZ placement of stand-alone web servers (MS01-033) [8] |
| T1189, T1190, T1203, T1210 | [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (D3-PSEP) | A later memory-protection control against overflows like those in MS01-033 and MS01-059 [8][10]; that it was not 2001 practice is this study's reading (Inferred) |
| T1554 | [Software Update](/mitre/d3fend/software-update.md) (D3-SU) | Cumulative patches MS01-026 and MS01-044; reinstall from trusted media after Nimda [7][9][1] |
| T1204.002, T1566.001 | [File Analysis](/mitre/d3fend/file-analysis.md) (D3-FA) | Anti-virus with automatic updates (CA-2001-26) [1] |
| T1204.002 | [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (D3-EAL) | Stopping attachments from running (CA-2001-03, CA-2001-26) [1] |
| T1566.001 | [Sender Reputation Analysis](/mitre/d3fend/sender-reputation-analysis.md) (D3-SRA), [Email Removal](/mitre/d3fend/email-removal.md) (D3-ER) | The year's mass mailers and Hybris's use of open relays [1][2] |
| Default services and script mappings (T1190, T1203) | [Application Configuration Hardening](/mitre/d3fend/application-configuration-hardening.md) (D3-ACH), this study's pairing | Remove .ida and .idq mappings (MS01-033); disable JavaScript until patched (CA-2001-26); UPnP blocking (MS01-059) [8][1][10] |
| The bogus certificates (T1588.003) | [Certificate Analysis](/mitre/d3fend/certificate-analysis.md) (D3-CA), this study's pairing | The local CRL and revocation checking Microsoft shipped (MS01-017) [4] |

Techniques not named in this table are left without a D3FEND pairing here; none is invented (Inferred).

### Navigator layers

The study's Enterprise techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2001.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2001.json), in the format of the existing chronicle layers (domain enterprise-attack, navigator 4.9, layer 4.5) (Confirmed [82]). It lists the 27 techniques in the Enterprise table under each tactic they carry in v20.0 and is listed on [the Navigator layers page](/navigator/index.md). Equation's four group techniques are not in it. The 12 Maroochy techniques go in a separate ATT&CK for ICS layer, [navigator/case-studies/chronicle-2001-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2001-ics.json), domain `ics-attack`. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where ATT&CK lists the id for the event (the ICS layer), 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping (Confirmed [82]). No 2001 source prints an ATT&CK id, so the Enterprise rows score 70 or 40 (Inferred). Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**Known flaws, fast worms.** Code Red, sadmind/IIS and Nimda used flaws for which the vendor had already published fixes, and the SSH compromises used a flaw on record since March (Confirmed [8][1][5][13][2]). The worm closed the gap between disclosure and mass exploitation to weeks; the [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) follows the other end of that gap, flaws exploited before any fix (Inferred).

**Footholds were traded between attackers.** Leaves reused SubSeven, cheese reused root shells, and Nimda reused Code Red II and sadmind/IIS back doors (Confirmed [2][1]). The [ransomware ecosystem study](/case-studies/RANSOMWARE_ECOSYSTEM.md) shows the same reuse of access turned into a market (Inferred).

**Trust infrastructure failed quietly.** A certificate authority issued code-signing certificates to an impostor and the clients could not check revocation (Confirmed [4][1]). The [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md), [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) and [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) studies return to signed and trusted code as the attack path (Inferred).

**Security products were attack surface.** Check Point and Gauntlet had their own 2001 advisories (Confirmed [1]); the [SharePoint ToolShell](/case-studies/SHAREPOINT_TOOLSHELL_2025.md) and [N-able N-central](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md) studies show server and management products still in that position (Inferred).

**Surveillance entered the public record.** ECHELON, the keystroke logger, Carnivore and the remote copying in the Gorshkov case were all argued in court or parliamentary records in 2001 (Confirmed [66][68][71][21]). The [Hacker and the State study](/case-studies/HACKER_AND_THE_STATE_CASES.md) follows that line forward (Inferred).

**Law followed September, not July.** Code Red and Sircam came in July, GAO testified in August, and the executive orders, the PATRIOT Act, the Budapest Convention and the UK Act all came after 11 September (Confirmed [17][36][37][33][35][38]). This study does not claim the worms caused those laws (Inferred).

**State activity was invisible at the time.** Equation's 2001 date came out in 2015, and the [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) shows how much more evidence a confident attribution now carries (Confirmed [61]; Inferred). The industrial thread runs from Maroochy to [Stuxnet](/case-studies/STUXNET.md) and the [ICS attacks and advisories of 2024 to 2026](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) (Inferred).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: any single Code Red number.** CERT's "more than 250,000" and "at least 280,000", NIPC's 250,000 in nine hours, CAIDA's measured 359,104 and Computer Economics' 975,000 servers measure different things over different windows [1][17][16]. None is a census, and the cost figure of over $2.4 billion is a consultancy estimate GAO relayed [17].
- **Overstated: GAO's list of affected sites.** The White House address change, DoD's site shutdown, Treasury's disconnection and the Hotmail, Qwest DSL and FedEx effects come from reports GAO relays [17].
- **Overstated: "the firewall fixes it".** Filtering was the year's main network advice, yet two firewall products had their own advisories and Nimda came through mail, browsers and shares [1].
- **Overstated: Code Red as a pure patch failure.** MS01-044 shows that IIS 4.0 servers with URL redirection enabled could fail under Code Red traffic whether or not MS01-033 was installed, through a separate flaw [9].
- **Overstated: Equation "began in 2001".** The date is a domain registration reconstructed in 2015, with "perhaps as early as 1996" beside it and the earliest samples from 2002 [61][62].
- **Overstated: Moonlight Maze running in 2001 as a named state operation.** The only bridge is a relayed account of Storm Cloud without artefacts, and the researchers call the Turla link premature [64].
- **Overstated: ECHELON's economic espionage.** The committee found no evidence of distorted competition and relayed the 5% and 7 billion dollar figures without establishing them [66].
- **Overstated: any ATT&CK Enterprise, CWE or CAPEC id on a 2001 event.** Those programs began later, and NVD's own CWE field for the year's key CVEs is NVD-CWE-Other [57][58][59][13].
- **Understated: the Unix record.** ramen, the BIND kits, snmpXdmid with Carko, sadmind, cheese and SSH CRC-32 are advisory-by-advisory on CERT's record [1][2].
- **Understated: client and mail vectors.** Anna Kournikova, Sircam and Nimda's mail path used users and an Internet Explorer flaw patched in March [1][5].
- **Understated: the certificate revocation gap.** One bulletin and one advisory covered a failure in the trust system code signing still depends on [4][1].
- **Understated: the standards work.** AES, FIPS 140-2, SP 800-31, RFC 3164, PF and OWASP all date to 2001 [43][46][47][52][53][51].
- **Understated: the FBI's own computer operations.** A court upheld a covert keystroke logger classified SECRET since around November 1997, and another upheld remote copying from computers in Russia [68][21].

### Discrepancies in the record

- **Code Red's start.** CAIDA dates version 1 from 12 July; CERT says "since around July 13" [15][1].
- **Code Red's flood window.** CERT gives days 20 to 27 of the month; CAIDA gives the 20th to the 28th [1][16].
- **Code Red's scale.** More than 250,000 (CERT, 19 July), at least 280,000 in the first wave (CERT, 26 July), more than 250,000 in nine hours (NIPC via GAO), 359,104 in under 14 hours (CAIDA), 975,000 servers (Computer Economics via GAO) [1][17][16].
- **MS01-033's successor.** The MS01-033 page says it was superseded by MS01-044 on 20 August 2001; MS01-044 is dated 15 August 2001 [8][9].
- **Three dates for CVE-2001-0500.** Bulletin 18 June, VU#952336 public 18 June and published 19 June, NVD 21 July [8][12][14].
- **EQUATIONLASER's span.** Kaspersky's Q&A gives 2001 to 2004 in one answer and 2001 to 2003 in another [62].
- **Sklyarov's dates.** DOJ records DEF CON attendance on 15 July and the indictment on 28 August; EFF dates the arrest to 16 July and the complaint to 7 July [22][23].
- **Gorshkov's verdict.** The jury returned it on 9 October; DOJ announced it on 10 October [20].
- **Windows XP.** Worldwide availability announced 25 October; Microsoft's lifecycle start date is 31 December 2001 [90].
- **The Maroochy volume.** ATT&CK gives 800,000 liters; the judgment passages cited give no volume [73][72].

## Sources

All sources were opened on 12 November 2026 and checked as of 13 November 2026, as listed. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the gao.gov pages); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "2001 CERT Advisories" (compilation, CA-2001-01 to CA-2001-37) | https://www.sei.cmu.edu/documents/508/2001_019_001_496192.pdf | 2026-11-12 | Confirmed |
| 2 | CMU SEI, "2001 CERT Incident Notes" (compilation, IN-2001-01 to IN-2001-15) | https://www.sei.cmu.edu/documents/522/2001_019_001_496466.pdf | 2026-11-12 | Confirmed |
| 3 | CMU SEI, 2001 CERT advisories index | https://www.sei.cmu.edu/library/2001-cert-advisories/ | 2026-11-12 | Confirmed |
| 4 | Microsoft Security Bulletin MS01-017 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-017 | 2026-11-12 | Confirmed |
| 5 | Microsoft Security Bulletin MS01-020 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-020 | 2026-11-12 | Confirmed |
| 6 | Microsoft Security Bulletin MS01-023 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-023 | 2026-11-12 | Confirmed |
| 7 | Microsoft Security Bulletin MS01-026 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-026 | 2026-11-12 | Confirmed |
| 8 | Microsoft Security Bulletin MS01-033 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-033 | 2026-11-12 | Confirmed |
| 9 | Microsoft Security Bulletin MS01-044 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-044 | 2026-11-12 | Confirmed |
| 10 | Microsoft Security Bulletin MS01-059 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-059 | 2026-11-12 | Confirmed |
| 11 | Microsoft Security Bulletin MS00-078 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-078 | 2026-11-12 | Confirmed |
| 12 | CERT/CC Vulnerability Note VU#952336 | https://www.kb.cert.org/vuls/id/952336 | 2026-11-12 | Confirmed |
| 13 | NVD, CVE-2001-0500 (with the NVD records for CVE-2001-0333, -0154, -0241, -0144, -0010, -0876, -0008, -0550, -0328 and CVE-2000-0884) | https://nvd.nist.gov/vuln/detail/CVE-2001-0500 | 2026-11-12 | Confirmed |
| 14 | NVD API, CVE-2001-0500 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2001-0500 | 2026-11-12 | Confirmed |
| 15 | CAIDA, Code-Red worms archive | https://www.caida.org/archive/code-red/ | 2026-11-12 | Confirmed (CAIDA's own measurement) |
| 16 | CAIDA, Code-Red v2 analysis | https://www.caida.org/archive/code-red/coderedv2_analysis/ | 2026-11-12 | Confirmed (CAIDA's own measurement) |
| 17 | GAO, GAO-01-1073T, testimony of Keith A. Rhodes, 29 August 2001 | `https://www.gao.gov/assets/gao-01-1073t.pdf` | 2026-11-12 | Confirmed; Reported (the impacts, costs and Sircam leaks GAO relays) |
| 18 | GAO, GAO-01-1073T product page | `https://www.gao.gov/products/gao-01-1073t` | 2026-11-12 | Confirmed |
| 19 | GAO, GAO-01-323 product page | `https://www.gao.gov/products/gao-01-323` | 2026-11-12 | Confirmed |
| 20 | US Department of Justice, Gorshkov conviction, 10 October 2001 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2001/gorshkovconvict.htm | 2026-11-12 | Confirmed |
| 21 | US Department of Justice, Gorshkov sentencing, 4 October 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/gorshkovSent.htm | 2026-11-12 | Confirmed |
| 22 | US Department of Justice, Sklyarov deferred-prosecution agreement, 13 December 2001 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2001/sklyarovAgree.htm | 2026-11-12 | Confirmed |
| 23 | EFF, US v. ElcomSoft and Sklyarov case page | https://www.eff.org/cases/us-v-elcomsoft-sklyarov | 2026-11-12 | Reported |
| 24 | US Department of Justice, Khan indictment (AIPAC), 22 October 2001 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2001/khanindict.htm | 2026-11-12 | Confirmed |
| 25 | US Department of Justice, McKinnon indictment, 12 November 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/mckinnonIndict.htm | 2026-11-12 | Confirmed (allegations) |
| 26 | US Department of Justice, Osowski and Tang sentencing, 26 November 2001 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2001/Osowski_TangSent.htm | 2026-11-12 | Confirmed |
| 27 | US Department of Justice, Mamich plea, 18 December 2001 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2001/MamichPlea.htm | 2026-11-12 | Confirmed |
| 28 | US Department of Justice, release 01-643, Operations Buccaneer, Bandwidth and Digital Piratez, 11 December 2001 | https://www.justice.gov/archive/opa/pr/2001/December/01_crm_643.htm | 2026-11-12 | Confirmed |
| 29 | US Department of Justice, CCIPS release on international piracy syndicates, 11 December 2001 (headline and date) | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2001/warezoperations.htm | 2026-11-12 | Confirmed (headline and date only) |
| 30 | US Department of Justice, release 018, CCIPS search and seizure manual, 12 January 2001 | https://www.justice.gov/archive/opa/pr/2001/January/018crm.htm | 2026-11-12 | Confirmed |
| 31 | DOJ CCIPS case index (UNT End of Term 2008 capture) | https://webarchive.library.unt.edu/eot2008/20080916032623mp_/http://www.cybercrime.gov/cccases.html | 2026-11-13 | Reported |
| 32 | Cornell LII, 18 U.S.C. 1030 with amendment notes | https://www.law.cornell.edu/uscode/text/18/1030 | 2026-11-12 | Confirmed |
| 33 | Pub. L. 107-56, USA PATRIOT Act (enrolled text) | https://www.govinfo.gov/content/pkg/PLAW-107publ56/html/PLAW-107publ56.htm | 2026-11-12 | Confirmed |
| 34 | govinfo, Public Law 107-56 details | https://www.govinfo.gov/app/details/PLAW-107publ56 | 2026-11-12 | Confirmed |
| 35 | Council of Europe, Convention on Cybercrime (ETS 185) | https://rm.coe.int/1680081561 | 2026-11-12 | Confirmed |
| 36 | Federal Register, Executive Order 13228 | https://www.federalregister.gov/documents/2001/10/10/01-25677/establishing-the-office-of-homeland-security-and-the-homeland-security-council | 2026-11-12 | Confirmed |
| 37 | Federal Register, Executive Order 13231, 66 FR 53063 | https://www.federalregister.gov/documents/2001/10/18/01-26509/critical-infrastructure-protection-in-the-information-age | 2026-11-12 | Confirmed |
| 38 | legislation.gov.uk, Anti-terrorism, Crime and Security Act 2001 (c. 24) | https://www.legislation.gov.uk/ukpga/2001/24/introduction/enacted | 2026-11-12 | Confirmed |
| 39 | Federal Register, HHS Standards for Privacy of Individually Identifiable Health Information, 66 FR 12434, 26 February 2001 | https://www.federalregister.gov/documents/2001/02/26/01-4810/standards-for-privacy-of-individually-identifiable-health-information | 2026-11-12 | Confirmed |
| 40 | Federal Register, Interagency Guidelines Establishing Standards for Safeguarding Customer Information, 66 FR 8616 | https://www.federalregister.gov/documents/2001/02/01/01-1114/interagency-guidelines-establishing-standards-for-safeguarding-customer-information-and-rescission | 2026-11-12 | Confirmed |
| 41 | Federal Register, FTC Standards for Safeguarding Customer Information (proposed), 66 FR 41162 | https://www.federalregister.gov/documents/2001/08/07/01-19338/standards-for-safeguarding-customer-information | 2026-11-12 | Confirmed |
| 42 | Federal Register, draft FIPS for AES, 66 FR 12762 | https://www.federalregister.gov/documents/2001/02/28/01-4886/announcing-draft-federal-information-processing-standard-fips-for-the-advanced-encryption-standard | 2026-11-12 | Confirmed |
| 43 | NIST, FIPS 197 | https://csrc.nist.gov/pubs/fips/197/final | 2026-11-12 | Confirmed |
| 44 | Federal Register, approval of FIPS 197, 66 FR 63369 | https://www.federalregister.gov/documents/2001/12/06/01-30232/announcing-approval-of-federal-information-processing-standard-fips-197-advanced-encryption-standard | 2026-11-12 | Confirmed |
| 45 | Federal Register, draft FIPS 180-2, 66 FR 29287 | https://www.federalregister.gov/documents/2001/05/30/01-13522/announcing-draft-federal-information-processing-standards-fips-180-2-secure-hash-standard-and | 2026-11-12 | Confirmed |
| 46 | NIST, FIPS 140-2 | https://csrc.nist.gov/pubs/fips/140-2/upd2/final | 2026-11-12 | Confirmed |
| 47 | NIST, SP 800-31 | https://csrc.nist.gov/pubs/sp/800/31/final | 2026-11-12 | Confirmed |
| 48 | NIST, SP 800-28 | https://csrc.nist.gov/pubs/sp/800/28/final | 2026-11-12 | Confirmed |
| 49 | NIST, SP 800-41 (January 2002) | https://csrc.nist.gov/pubs/sp/800/41/final | 2026-11-12 | Confirmed |
| 50 | ISO, ISO/IEC 17799:2000 | https://www.iso.org/standard/33441.html | 2026-11-12 | Confirmed |
| 51 | OWASP, About | https://owasp.org/about/ | 2026-11-12 | Confirmed |
| 52 | RFC 3164, The BSD syslog Protocol | https://www.rfc-editor.org/rfc/rfc3164 | 2026-11-12 | Confirmed |
| 53 | OpenBSD 3.0 release page | https://www.openbsd.org/30.html | 2026-11-12 | Confirmed |
| 54 | kernel.org, Linux v2.4 directory | https://kernel.org/pub/linux/kernel/v2.4/ | 2026-11-12 | Confirmed; Inferred (that 2.4 shipped netfilter) |
| 55 | Springer, Fluhrer, Mantin and Shamir, "Weaknesses in the Key Scheduling Algorithm of RC4" (publisher record) | https://link.springer.com/chapter/10.1007/3-540-45537-X_1 | 2026-11-12 | Confirmed |
| 56 | Microsoft, "Windows XP Is Here", 25 October 2001 | https://news.microsoft.com/2001/10/25/windows-xp-is-here/ | 2026-11-12 | Confirmed |
| 57 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 58 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 59 | MITRE ATT&CK, FAQ | https://attack.mitre.org/resources/faq/ | 2026-11-12 | Confirmed |
| 60 | F-Secure, Klez description | https://www.f-secure.com/v-descs/klez | 2026-11-12 | Confirmed |
| 61 | Kaspersky, "Equation: The Death Star of Malware Galaxy", Securelist, 16 February 2015 | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-12 | Confirmed |
| 62 | Kaspersky, "Equation group: questions and answers", v1.5, February 2015 | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf | 2026-11-12 | Confirmed |
| 63 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 64 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze", Securelist, 3 April 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Reported (Storm Cloud and the Turla lineage) |
| 65 | European Parliament Legislative Observatory, procedure 2001/2098(INI) | https://oeil.europarl.europa.eu/oeil/en/procedure-file?reference=2001/2098(INI) | 2026-11-12 | Confirmed |
| 66 | European Parliament Legislative Observatory, summary of report A5-0264/2001 | https://oeil.europarl.europa.eu/oeil/en/document-summary?id=601538 | 2026-11-12 | Confirmed; Reported (the relayed economic figures) |
| 67 | European Parliament Legislative Observatory, summary of the 5 September 2001 decision | https://oeil.europarl.europa.eu/oeil/en/document-summary?id=78750 | 2026-11-12 | Confirmed |
| 68 | US v. Scarfo, D.N.J., opinion of 26 December 2001 (EPIC copy) | https://epic.org/crypto/scarfo/opinion.html | 2026-11-12 | Confirmed |
| 69 | Affidavit of Randall S. Murch, October 2001 (EPIC copy) | http://www.epic.org/crypto/scarfo/murch_aff.pdf | 2026-11-12 | Confirmed |
| 70 | EPIC, Scarfo case page | https://epic.org/crypto/scarfo/ | 2026-11-12 | Reported |
| 71 | EPIC, Carnivore FOIA litigation page | https://www.epic.org/privacy/carnivore/ | 2026-11-12 | Reported |
| 72 | Queensland Court of Appeal, R v Boden [2002] QCA 164 | https://www.queenslandjudgments.com.au/caselaw/qca/2002/164 | 2026-11-12 | Confirmed |
| 73 | MITRE ATT&CK, campaign C0020, Maroochy Water Breach | https://attack.mitre.org/campaigns/C0020/ | 2026-11-12 | Confirmed |
| 74 | TeamStarWolf library, `data/attack/group_to_technique.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/group_to_technique.jsonl | 2026-11-12 | Confirmed (the library's record) |
| 75 | TeamStarWolf library, `data/attack/groups.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/groups.jsonl | 2026-11-12 | Confirmed (the library's record) |
| 76 | TeamStarWolf library, `data/attack/software.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software.jsonl | 2026-11-12 | Confirmed (the library's record) |
| 77 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` (with the `mitre/techniques/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_profiles.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 78 | TeamStarWolf library, `data/attack/` tree | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/data/attack | 2026-11-12 | Demonstrated |
| 79 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/cwe.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 80 | TeamStarWolf library, `data/weaknesses/capec.jsonl` (with the `mitre/capec/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/capec.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 81 | TeamStarWolf library, `data/attack/d3fend_countermeasures.jsonl` (with the `mitre/d3fend/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/d3fend_countermeasures.jsonl | 2026-11-12, 2026-11-13 | Confirmed (the library's record) |
| 82 | TeamStarWolf library, `navigator/library-layers/chronicle-2016.json` (layer format and scoring scale) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2016.json | 2026-11-12 | Confirmed (the library's record) |
| 83 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-12 | Confirmed (the library's record) |
| 84 | TeamStarWolf library, `case-studies/THREAT_ACTORS_UNITED_STATES.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/THREAT_ACTORS_UNITED_STATES.md | 2026-11-12 | Confirmed (the library's record) |
| 85 | TeamStarWolf library, `case-studies/NSA_CIA_TOOL_LEAKS.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/NSA_CIA_TOOL_LEAKS.md | 2026-11-12 | Confirmed (the library's record) |
| 86 | TeamStarWolf library, `case-studies/THREAT_ACTORS_CHINA.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/THREAT_ACTORS_CHINA.md | 2026-11-12 | Confirmed (the library's record) |
| 87 | TeamStarWolf library, `case-studies/CYBERCRIME_FOUR_BOOKS.md` (home for Max Butler; its source is The Register) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/CYBERCRIME_FOUR_BOOKS.md | 2026-11-12 | Reported |
| 88 | TeamStarWolf library, `data/attack/ics/technique_profiles.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/ics/technique_profiles.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 89 | netfilter project, About | https://www.netfilter.org/about.html | 2026-11-12 | Confirmed |
| 90 | Microsoft Lifecycle, Windows XP | https://learn.microsoft.com/en-us/lifecycle/products/windows-xp | 2026-11-12 | Confirmed |
| 91 | NIST, SP 800-26 | https://csrc.nist.gov/pubs/sp/800/26/final | 2026-11-12 | Confirmed |
| 92 | NIST, SP 800-27 | https://csrc.nist.gov/pubs/sp/800/27/final | 2026-11-12 | Confirmed |
| 93 | NIST, SP 800-32 | https://csrc.nist.gov/pubs/sp/800/32/final | 2026-11-12 | Confirmed |
| 94 | NIST, SP 800-33 | https://csrc.nist.gov/pubs/sp/800/33/final | 2026-11-12 | Confirmed |
| 95 | TeamStarWolf library, `data/attack/software_profiles.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software_profiles.jsonl | 2026-11-13 | Confirmed (the library's record) |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md)
- Home studies: [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [The Cybercrime Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md); [The Hacker and the State](/case-studies/HACKER_AND_THE_STATE_CASES.md); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [Ransomware Ecosystem](/case-studies/RANSOMWARE_ECOSYSTEM.md); [eMudhra CA compromise](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [SharePoint ToolShell](/case-studies/SHAREPOINT_TOOLSHELL_2025.md); [N-able N-central](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2002](/case-studies/CHRONICLE_2002.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1595.001 Scanning IP Blocks](/mitre/techniques/T1595-001.md), [T1491.002 External Defacement](/mitre/techniques/T1491-002.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1499 Endpoint Denial of Service](/mitre/techniques/T1499.md), [T1584.005 Botnet](/mitre/techniques/T1584-005.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1059.005 Visual Basic](/mitre/techniques/T1059-005.md), [T1036.007 Double File Extension](/mitre/techniques/T1036-007.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1189 Drive-by Compromise](/mitre/techniques/T1189.md), [T1080 Taint Shared Content](/mitre/techniques/T1080.md), [T1135 Network Share Discovery](/mitre/techniques/T1135.md), [T1021.002 SMB/Windows Admin Shares](/mitre/techniques/T1021-002.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1136.001 Local Account](/mitre/techniques/T1136-001.md), [T1098 Account Manipulation](/mitre/techniques/T1098.md), [T1554 Compromise Host Software Binary](/mitre/techniques/T1554.md), [T1505.003 Web Shell](/mitre/techniques/T1505-003.md), [T1588.003 Code Signing Certificates](/mitre/techniques/T1588-003.md), [T1078.001 Default Accounts](/mitre/techniques/T1078-001.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1565.001 Stored Data Manipulation](/mitre/techniques/T1565-001.md), [T1564.001 Hidden Files and Directories](/mitre/techniques/T1564-001.md), [T1657 Financial Theft](/mitre/techniques/T1657.md); Equation's group techniques [T1480.001](/mitre/techniques/T1480-001.md), [T1564.005](/mitre/techniques/T1564-005.md), [T1120](/mitre/techniques/T1120.md), [T1542.002](/mitre/techniques/T1542-002.md)
- CAPEC: [CAPEC-64](/mitre/capec/CAPEC-64.md), [CAPEC-70](/mitre/capec/CAPEC-70.md), [CAPEC-71](/mitre/capec/CAPEC-71.md), [CAPEC-92](/mitre/capec/CAPEC-92.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-120](/mitre/capec/CAPEC-120.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-126](/mitre/capec/CAPEC-126.md), [CAPEC-135](/mitre/capec/CAPEC-135.md), [CAPEC-206](/mitre/capec/CAPEC-206.md), [CAPEC-482](/mitre/capec/CAPEC-482.md)
- Groups, software and campaigns: Equation [G0020](/mitre/groups/G0020.md), dated to 2001 by Kaspersky's 2015 report; Maroochy Water Breach [C0020](https://attack.mitre.org/campaigns/C0020/) (ATT&CK for ICS; no library page); Turla [G0010](/mitre/groups/G0010.md) and Penquin [S0587](/mitre/software/S0587.md) for the unproven Moonlight Maze lineage; Regin [S0019](/mitre/software/S0019.md), not a 2001 object
- [Navigator layers](/navigator/index.md), including this study's layers, [chronicle-2001.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2001.json) and [chronicle-2001-ics.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/chronicle-2001-ics.json)
