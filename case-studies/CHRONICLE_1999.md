# The Year 1999 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; sources opened on 12 and 13 November 2026.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md) · Home studies for events summarized here: [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Melissa, CIH, Moonlight Maze, the CVE launch, TFN2K and CD Universe), [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md) (the March 1999 plea and the August sentence), [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md) (CD Universe), [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Turla's record) and [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md) (Equation) · Series: [The Year 1997 in Intrusions](/case-studies/CHRONICLE_1997.md), [The Year 1998 in Intrusions](/case-studies/CHRONICLE_1998.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians and defenders who want the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 60 min (13,857 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 1999, you need the year's CERT advisories and incident notes, the trojaned source packages, Melissa, ExploreZip and the first DDoS networks side by side with Moonlight Maze, the year's prosecutions and the new privacy law, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 1: the year as a dated timeline](#part-1-the-year-as-a-dated-timeline), [Part 10: the defender view](#part-10-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [Kevin Mitnick: Ghost in the Wires and The Art of Intrusion](/case-studies/MITNICK_INTRUSIONS.md), [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Melissa is the name most people attach to 1999, and the record backs part of that memory (Inferred). CERT/CC started receiving Melissa reports at about 2:00 PM GMT-5 on Friday 26 March 1999 and issued CA-1999-04 the next day; the virus was a Word 97/2000 macro that spread by email, needed a person to open the document and exploited no new vulnerability (Confirmed [1]). By Monday 29 March it had reached more than 100,000 computers at more than 300 organizations, and one site received 32,000 infected messages in 45 minutes (Confirmed [33]). Happy99 (from about 20 January), CIH (payload date 26 April) and ExploreZip (from the second week of June) filled out a year of mail-borne and file-borne malware on Windows 95, 98 and NT (CIH on 95 and 98 only) (Confirmed [2][1]).

The rest of the record tells a quieter story. CERT/CC issued 17 advisories in 1999, CA-1999-01 to CA-1999-17, and 8 incident notes, IN-99-01 to IN-99-08 (Confirmed [1][2]). By topic, four advisories concern malicious code (the two Trojan horse advisories, Melissa and ExploreZip), one concerns distributed denial-of-service tools, and the other twelve concern server software and insecure defaults: FTP daemons, the statd and automountd RPC services, IIS, rpc.cmsd, Array Services, the RaQ2, CDE, amd, WU-FTPD, BIND, sshd with RSAREF2 and sadmind (Confirmed [3]; the count by topic is Inferred). CERT's incident notes show those server flaws being worked at scale: scripts that chained the cmsd, statd/automountd and ToolTalk flaws in July, root compromises through amd in September, distributed sniffers on compromised Linux hosts in October, and in November the trinoo and Tribe Flood Network tools installed on hosts taken through RPC flaws (Confirmed [2]). The year closed with CA-1999-17 on 28 December: Tribe FloodNet 2K had been released, with spoofed sources, floods over UDP, TCP and ICMP, decoy packets and a MacOS 9 amplification factor of about 37.5 (Confirmed [1]).

The supply chain was attacked in the first month. From 06:16 GMT on 21 January 1999 copies of the TCP Wrappers 7.6 source on a number of FTP servers carried a Trojan horse that gave intruders root access and, when compiled, emailed out site details; between 22 and 24 January util-linux 2.9g was trojaned on at least one FTP server with a modified login program (Confirmed [1]). CERT's answer, in CA-1999-02, was to ask developers and distributors to use cryptographically strong validation for software and to ask users to check signatures and signer keys (Confirmed [1]).

The state record is about a campaign that was watched, then lost. Moonlight Maze intrusions into US military and government networks went back to at least 1996 in the researchers' account, and a compromised UK server the operators used as a relay had been turned into a monitoring point; after a congressional hearing in late February the investigation leaked, the first press coverage came on 4 March 1999, and the operators dropped the relay (Reported [37]; Confirmed [36]). The researchers who analysed that relay's logs in 2017 say a link to Turla is not yet proven (Reported [36]). The Deputy Secretary of Defense told Congress on 23 February that the department was detecting 80 to 100 events a day (Confirmed [39]). Hacktivists took sides around the Kosovo war: sympathizers of Serbia attacked NATO web servers and sites in NATO countries (Confirmed [40]), and after the May bombing of the Chinese embassy in Belgrade, Chinese patriotic hackers formed the Red Hacker Alliance and defaced US websites (Reported [42]).

Prosecutors had a busy year. The Justice Department's computer crime index lists six computer intrusion releases for 1999: Mitnick, the Phone Masters, Eric Burns, Alibris, the Melissa plea and Andrew Miffleton (Confirmed [28]). The law moved too: the Gramm-Leach-Bliley Act put a security and confidentiality obligation on every financial institution on 12 November, the FTC finished the COPPA rule in October, HHS proposed the health privacy rule in November, and the United States announced a new encryption export policy in September (Confirmed [54][58][59][62]). The CVE List itself launched in September 1999, and DES Challenge III fell in 22 hours 15 minutes in January (Confirmed [4][63]).

This study is the dated record of that year, built only from sources opened on 12 and 13 November 2026. Ten parts cover the timeline, the vulnerability record, mass exploitation and the first DDoS networks, malware and remote access tools, the state record, crime and prosecutions, law and policy, cryptography and standards, the industrial record and the defender view; an eleventh maps the record to MITRE frameworks.

1999 is the first year with CVE ids, but the CVE List only went public in September, many of the year's exploited flaws had their records published in 2000, and no ATT&CK, CWE or CAPEC id existed: CWE was first released in 2006, CAPEC in 2007, and MITRE started ATT&CK in 2013 (Confirmed [4][7][72][73][74]). Every ATT&CK, CWE, CAPEC and D3FEND id in Part 11 is therefore this study's later mapping (Inferred).

Evidence grade: CERT/CC advisories and incident notes, vendor bulletins, CVE and NVD records, statutes, Federal Register notices, Justice Department and SEC releases, congressional testimony, GAO and NTSB reports, NIST, ISO and RFC Editor records, the tool authors' and researchers' own publications, MITRE's own pages and the library's data files are **Confirmed**. Facts that rest on newspapers, trade press, a secondary research report or a researcher's relay of an investigation it did not run are **Reported** and attributed. A query or data check this study ran itself is **Demonstrated**. Where the study draws its own conclusion it says **Inferred**.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 1999, plus boundary records that open or close a 1999 event (Moonlight Maze from 1996, the Burns attacks from August 1998, the 2000 sentences, the January 2000 CD Universe posting, the 2002 Melissa sentence and NTSB report, the 2017 Moonlight Maze research) |
| CERT/CC output | 17 advisories, CA-1999-01 (21 Jan) to CA-1999-17 (28 Dec); 8 incident notes, IN-99-01 (28 Jan) to IN-99-08 (10 Dec) (Confirmed [1][2]) |
| Exploited in the wild, per CERT and Microsoft | IIS .HTR (sites attacked, 15 Jun; public tool, 16 Jun); rpc.cmsd (16 Jul); statd/automountd (9 Jun); amd (17 Sep); WU-FTPD (19 Oct); MDAC RDS (10 Dec); sadmind (14 Dec) (Confirmed [13][1][2]) |
| Malware | Happy99 (from about 20 Jan); Melissa (26 Mar); CIH payload (26 Apr); ExploreZip (10 Jun); BubbleBoy demonstrates CVE-1999-0668 (datePublic 21 Aug) (Confirmed [2][1][9]) |
| Supply chain | TCP Wrappers 7.6 trojaned (21 Jan); util-linux 2.9g trojaned (22 to 24 Jan) (Confirmed [1]) |
| DDoS | trinoo and TFN installed on compromised hosts (IN-99-07, 18 Nov); TFN2K released (CA-1999-17, 28 Dec) (Confirmed [2][1]) |
| Microsoft | Bulletins MS99-001 (21 Jan) to MS99-061 (21 Dec); 61 inferred from the numbering; no Patch Tuesday yet (Confirmed [11]; Inferred) |
| State record | Moonlight Maze relay lost after publicity (early Mar); FBI trip to Moscow (Apr); Kosovo-era hacktivism (Mar to Jun); Red Hacker Alliance defacements (May); Taiwan defacements (7 Aug) (Reported [37][42]; Confirmed [36][40]) |
| Prosecutions | Six DOJ computer intrusion releases: Mitnick (9 Aug), Phone Masters (16 Sep), Burns (19 Nov), Alibris (22 Nov), Melissa plea (9 Dec), Miffleton (20 Dec) (Confirmed [28]) |
| Law and policy | Y2K Act (20 Jul); EO 13133 (5 Aug); encryption export policy (16 Sep); COPPA rule (20 Oct); HIPAA privacy NPRM (3 Nov); GLBA (12 Nov) (Confirmed [60][57][62][58][59][54]) |
| Cryptography and standards | TLS 1.0 and RFC 2459 (Jan); DES Challenge III (19 Jan); CVE List (Sep); OpenSSH (26 Sep); FIPS 46-3 (25 Oct); ISO/IEC 15408-1 (Dec) (Confirmed [67][68][63][4][71][65][70]) |
| Industrial | Bellingham pipeline rupture (10 Jun): a SCADA failure during database work, no intrusion found (Confirmed [53]) |
| This study's MITRE binding | 36 ATT&CK Enterprise technique rows, every one a later mapping; one ICS id noted as exposure only; no group, software or campaign object bound; 9 CWE ids plus NVD-CWE-Other; 10 CAPEC entries; D3FEND pairings from the library's data; one Navigator layer (Part 11) |

### Key findings

- **The loud malware and the quiet servers were different problems.** Melissa, Happy99 and ExploreZip needed a user to open something; the IIS, RPC, FTP, BIND and sadmind flaws were exploited remotely against the server (Confirmed [1][2]); none of the advisories describes a user action (Inferred). Twelve of the 17 advisories were about the second kind (Inferred from [3]).
- **Fixes existed long before the attacks.** IN-99-08 (10 December 1999) reported IIS servers being compromised through the MDAC RDS flaw, with an example log line from 24 October, which CERT said had been discussed publicly since 22 April 1998 and which Microsoft re-released as MS99-025 in July to remind customers of a configuration fix first published in July 1998 (Confirmed [2][14]).
- **Compromised hosts became a weapon.** CERT's November note on trinoo and TFN describes tools installed on hosts compromised through RPC flaws and still under active development, and its December advisory on TFN2K tells sites to filter spoofed traffic as RFC 2267 describes (Confirmed [2][1][69]). This is the step from single intrusions to the DDoS networks that followed (Inferred).
- **Source code was trusted and should not have been.** The TCP Wrappers and util-linux Trojans reached FTP servers within days of each other, and CERT's advice was cryptographic validation by developers and users alike (Confirmed [1]).
- **The best-watched espionage campaign was lost to publicity.** Moonlight Maze's operators dropped the monitored relay after the first press reports in early March 1999, and the public technical record rests on that relay's preserved logs (Reported [37]; Confirmed [36]).
- **Hacktivism followed the news.** Vatis attributed the Kosovo-era attacks on NATO servers to sympathetic individuals, not a government (Confirmed [40]). The secondary record calls the Chinese defacements after the Belgrade embassy bombing patriotic hacktivism with no evidence of direct government control, while noting that independence from the state was not complete (Reported [42]).
- **Damage figures are claims, not measurements.** Melissa's "more than $80 million" is Smith's plea admission, and GAO said complete data on which agencies were hit did not exist (Confirmed [22][33]).
- **The policy record outlasted the incidents.** GLBA's safeguards duty, the COPPA rule, the HIPAA privacy proposal and the shift to Triple DES in FIPS 46-3 are 1999 rules whose successors still govern defenders (Confirmed [54][58][59][65]; Inferred).

### Top recommendations

1. **Verify what you build before you build it.** CA-1999-01 published MD5 checksums and pointed to the author's detached PGP signature, which the trojaned TCP Wrappers lacked; CA-1999-02 asked users to validate signatures and signer keys and to use Tripwire-style integrity checking (Confirmed [1]).
2. **Treat mail attachments and macros as code.** Melissa lowered macro security settings and needed a user to open a document; ExploreZip arrived as an executable attachment (Confirmed [1]). CA-1999-02 recommends virus products, firewalls and user education (Confirmed [1]).
3. **Turn off RPC services a host does not need, and patch the rest.** amd and sadmind were exploited for remote root in 1999, statd/automountd and cmsd were exploited in reported incidents, and CERT saw scripts automate attacks through cmsd, statd/automountd and the 1998 ToolTalk flaw (Confirmed [1][2]).
4. **Apply configuration fixes as seriously as patches.** The MDAC RDS fix was a configuration change, published in July 1998 and reissued in July 1999, and servers that had not made it were being compromised by the time of CERT's 10 December 1999 note (Confirmed [14][2]).
5. **Filter spoofed traffic at every router you can.** CA-1999-17 recommends RFC 2267 ingress filtering on as many routers as practical, and says plainly what it does not stop (Confirmed [1][69]).
6. **Encrypt management sessions.** IN-99-06's distributed sniffers collected usernames and passwords on compromised Linux hosts, and CA-1999-02 recommends ssh for terminal sessions (Confirmed [2][1]).
7. **Keep control systems off the business network and off live development.** NTSB found Olympic's SCADA system bridged to the building network and reachable by dial-in modem, and named database development on the live system in the probable cause (Confirmed [53]).
8. **Retire 56-bit keys.** DES Challenge III found a key in 22 hours 15 minutes, and NIST's FIPS 46-3 specified the Triple Data Encryption Algorithm in October (Confirmed [63][65]).
9. **Build the reporting path before the outbreak.** GAO told Congress in April that there was no governmentwide process to report and analyze attacks (Confirmed [34]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, cryptography, standards and policy dated to 1999, plus the later records that open, close or explain a 1999 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every event graded, numbers as the source states them. Sources were opened on 12 and 13 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record (a CERT/CC advisory or incident note as SEI publishes it, a vendor bulletin, a CVE or NVD record, a statute, a Federal Register notice, a Justice Department, SEC or FBI release, congressional testimony, a GAO or NTSB report, a NIST, ISO or RFC Editor record, the tool author's or researcher's own publication, a live ATT&CK page, or the library's data files as the record of what the library holds) was opened and states the fact |
| Reported | Only a secondary source was opened: Wired, CNN, Federal Computer Week via CNN, the ETH Zurich Center for Security Studies report, or researchers relaying an investigation they did not run. The source is named in the text |
| Demonstrated | This study ran the query or opened the data itself and saw the result (the NVD records, the library's data files and page tree, the revoked-id mapping) |
| Inferred | The study's own reasoning, labelled where it appears. Every MITRE id bound to a 1999 event is Inferred as to the binding |

Limits a reader should know:

- **CVE was new, and late.** The CVE concept was presented at Purdue on 21 and 22 January 1999 and the List launched publicly in September with 321 records (Confirmed [4]). Those records were also assigned to older flaws: NVD lists CVE-1999-0018 (statd) as published 5 December 1997 (Demonstrated [10]). The CVE Services records for several of the year's exploited flaws were published only in January or June 2000 (Confirmed [7]). A count of "1999 CVEs" is therefore an artifact of the database, not a measure of the year (Inferred).
- **No contemporaneous ATT&CK.** MITRE started ATT&CK in 2013 (Confirmed [74]). No 1999 record carries an ATT&CK id.
- **The CERT text.** SEI's compilations of the 1999 CERT advisories and incident notes are the texts for every CA-1999 and IN-99 item cited here [1][2], with SEI's 1999 advisory index for the titles [3]. CERT/CC's 1999 incident statistics were not opened, so this study gives no 1999 incident count.
- **Microsoft's count.** MS99-001 is dated 21 January 1999 and MS99-061 21 December; MS99-062 returns 404 and MS00-001 is dated 4 January 2000. The total of 61 is inferred from the numbering (Confirmed [11]; Inferred).
- **The press record.** The Hotmail exposure, the May 1999 defacements of Energy and Interior pages, the NIPRNET attack figure and the Chinese patriotic hacking rest on Wired, CNN and a 2025 research report; those rows are Reported [49][50][51][52][42].
- **What was not checked.** NATO's own Kosovo-era press releases, Dittrich's analyses of trinoo and TFN, the Wen Ho Lee case, the ECHELON reports of 1999 and BubbleBoy's own spread could not be opened from a primary and are left out or limited to what an opened record says. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Grade | Sources |
|---|---|---|---|---|
| 1996-10 to 1999-03 (frame) | Moonlight Maze intrusions against US military and government networks (Wright Patterson and Kelly AFBs, the Army Research Lab, NAVSEA Indian Head, NASA, DOE labs) run from at least October 1996; by mid-1998 investigators had evidence pointing to Russian ISPs. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Espionage | Reported | [37] |
| 1998-08 to 1999-01 | Eric Burns ("Zyklon") attacks the Electric Press server hosting the USIA, NATO and Vice President web pages four times; one attack closes the USIA site for eight days | Defacement | Confirmed | [19] |
| 1998-10 to 1999-03 | Logs on the Moonlight Maze relay HRTest, a UK staging server, show about 1,600 unique IP addresses across the Navy, Air Force, Army Corps of Engineers, Marine Corps, NASA, NOAA and numerous universities; other staging servers were in Canada, Norway and Thailand | Espionage | Confirmed (researchers' findings) | [37] |
| 1998-12 | Joint Task Force for Computer Network Defense established, reporting to the Secretary of Defense | Government | Confirmed | [39] |
| 1999-01 | RFC 2246, TLS 1.0, based on SSL 3.0; RFC 2459, the X.509 certificate and CRL profile | Standards | Confirmed | [67][68] |
| 1999-01 | Jeffrey Levy, a University of Oregon student, posts pirated software, music and movies on his web site | Crime | Confirmed | [29] |
| 1999-01-02 | Cox Committee report (H. Rpt. 105-851) issued per govinfo; chapter 1 describes PRC acquisition of US military technology through human, commercial and front-company channels, not network intrusion | State context | Confirmed | [48] |
| 1999-01-07 | 2600, the Chaos Computer Club, cDc, !Hispahack, L0pht, Phrack and Pulhas condemn the Legion of the Underground's declared "war" to disrupt Internet infrastructure in Iraq and China | Community | Confirmed | [16] |
| 1999-01-08 | Mann and Christey date "Towards a Common Enumeration of Vulnerabilities" | Standards | Confirmed | [6] |
| 1999-01-18 to 19 | DES Challenge III: distributed.net and the EFF DES Cracker find the key in 22 hours 15 minutes | Cryptography | Confirmed | [63][64] |
| about 1999-01-20 | CERT/CC begins receiving reports of the Happy99 (SKA) Trojan | Malware | Confirmed | [2] |
| 1999-01-21 | CA-1999-01: trojaned TCP Wrappers 7.6 on a number of FTP servers from 06:16 GMT | Supply chain | Confirmed | [1] |
| 1999-01-21 | MS99-001, Microsoft's first bulletin of the year; MS99-002 covers the "Word 97 Template" flaw | Vulnerability | Confirmed | [11][12] |
| 1999-01-21 to 22 | CVE concept presented at the 2nd Workshop on Research with Security Vulnerability Databases, Purdue | Standards | Confirmed | [4][5] |
| 1999-01-22 to 24 | util-linux 2.9g trojaned on at least one FTP server with a modified login program | Supply chain | Confirmed | [1] |
| 1999-01-28 | IN-99-01: sscan, a derivative of the 1998 mscan tool, announced on public lists | Scanning | Confirmed | [2] |
| 1999-02 | Andrew Miffleton ("Daphtpunk", Darkside Hackers) holds and passes on a national Internet company's root password list (about $90,000 loss) | Crime | Confirmed | [20] |
| 1999-02-01 | DOJ FY2000 budget request seeks 60 more FBI agents and $122.54 million for critical information infrastructure protection | Government | Confirmed | [18] |
| 1999-02-05 | CA-1999-02: more Trojan horses, including the util-linux login and a fake "Internet Explorer upgrade" email (Ie0199.exe) | Malware | Confirmed | [1] |
| 1999-02-11 | CA-1999-03: FTP server buffer overflows, forwarding Netect's advisory of 9 February | Vulnerability | Confirmed | [1] |
| 1999-02-23 | Deputy Secretary of Defense Hamre tells House Armed Services that DoD detects 80 to 100 events a day | Government | Confirmed | [39] |
| late 1999-02 to early 1999-03 | After a congressional hearing the FBI investigation leaks; first press 4 March; the operators abandon the monitored HRTest relay, ending about six months of visibility | Espionage | Reported | [37][36] |
| 1999-03 | Second AES Candidate Conference | Cryptography | Confirmed | [66] |
| 1999-03 | Kevin Mitnick's global plea. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Confirmed | [21] |
| 1999-03 to 06 | Kosovo conflict: Serbia sympathizers "ping" attack NATO web servers; more than 100 US entities receive virus-infected email | Hacktivism | Confirmed | [40] |
| 1999-03-10 | Senate Commerce report S. Rpt. 106-10 on the Y2K Act ordered printed | Law | Confirmed | [61] |
| 1999-03-16 | NIPC Director Vatis to Senate Armed Services: motives for unidentified intrusions may be espionage or "some form of strategic military attack" | Government | Confirmed | [41] |
| 1999-03-26 | Melissa reports reach CERT/CC from about 2:00 PM GMT-5 | Malware | Confirmed | [1] |
| 1999-03-27 | CA-1999-04, Melissa | Malware | Confirmed | [1] |
| 1999-03-29 | Melissa has reached more than 100,000 computers at more than 300 organizations | Malware | Confirmed | [33] |
| 1999-03-29 | IN-99-02, Happy99 | Malware | Confirmed | [2] |
| 1999-04 | FBI task force trip to Moscow on Moonlight Maze | Espionage | Reported | [37] |
| 1999-04-01 | David L. Smith arrested by New Jersey authorities for Melissa | Crime | Confirmed | [22] |
| 1999-04-07 | Gary D. Hoke Jr. posts a false PairGain takeover report linked to a fake Bloomberg News page | Fraud | Confirmed | [76] |
| 1999-04-15 | GAO testimony T-AIMD-99-146 on Melissa | Government | Confirmed | [33][34] |
| 1999-04-15 | AES Round 1 comments close | Cryptography | Confirmed | [66] |
| 1999-04-21 | SEC sues Hoke (LR-16117) | Fraud | Confirmed | [76] |
| 1999-04-22 | IN-99-03, CIH (Chernobyl) | Malware | Confirmed | [2] |
| 1999-04-26 | CIH trigger date for some variants | Malware | Confirmed | [2] |
| 1999-05 | White House web attack; the White House shuts its web server and disconnects its networks for two days. Burns later admits advising others on it | Defacement | Confirmed | [19] |
| 1999-05 | After the US bombing of the Chinese embassy in Belgrade, the Red Hacker Alliance forms within days and defaces US websites | Hacktivism | Reported | [42] |
| 1999-05 | Patrick Gregory's teleconference fraud on AT&T, MCI, Sprint and other carriers runs through May 1999 | Crime | Confirmed | [24] |
| 1999-05-04 | CNN and Federal Computer Week report that DISA has begun redesigning NIPRNET, citing an unnamed source for 250,000 attacks a year | Defense | Reported | [52] |
| 1999-05-09 | Messages planted on the Energy, Interior and National Park Service home pages; DOE's site still offline on 10 May | Hacktivism | Reported | [51] |
| 1999-06 | Chad Davis defaces the US Army web page; public access restored within two hours | Defacement | Confirmed | [23] |
| 1999-06-09 | CA-1999-05: intruders combine the rpc.statd and automountd flaws | Vulnerability | Confirmed | [1] |
| 1999-06-10 | CA-1999-06, ExploreZip (revised 14 June to add share spreading) | Malware | Confirmed | [1] |
| 1999-06-10 | Olympic Pipe Line rupture in Bellingham, Washington; three deaths | Industrial | Confirmed | [53] |
| 1999-06-15 | MS99-019: IIS 4.0 malformed .HTR request; Microsoft has reports of customer sites attacked | Vulnerability | Confirmed | [13] |
| 1999-06-16 | CA-1999-07: a public exploit tool for the IIS overflows | Vulnerability | Confirmed | [1][13] |
| 1999-06-29 to 30 | A 16-year-old ("c0mrade") enters 13 NASA Marshall computers and takes ISS environmental-control software; the NASA computer systems are shut down for 21 days in July | Intrusion | Confirmed | [26] |
| 1999-07 | The Sunday Times reveals the Moonlight Maze code name | Espionage | Reported | [37] |
| 1999-07-10 | cDc releases Back Orifice 2000 at DEF CON 7 | Tools | Confirmed | [17] |
| 1999-07-16 | CA-1999-08: rpc.cmsd overflow exploited in many incidents; exploit script on BUGTRAQ | Vulnerability | Confirmed | [1] |
| 1999-07-19 | MS99-025 re-releases MS98-004 on RDS DataFactory | Vulnerability | Confirmed | [14] |
| 1999-07-20 | Y2K Act, Pub. L. 106-37 | Law | Confirmed | [60] |
| 1999-07-22 | IN-99-04: scripted attacks through cmsd, statd/automountd and ToolTalk | Mass exploitation | Confirmed | [2] |
| 1999-08-05 | Executive Order 13133 sets up the Working Group on Unlawful Conduct on the Internet | Policy | Confirmed | [57] |
| 1999-08-07 | Chinese hackers deface Taiwanese government websites after Lee Teng-hui's "two-states" statement | Hacktivism | Reported | [42] |
| 1999-08-09 | Mitnick sentenced to 46 months. Home: [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) | Crime | Confirmed | [21] |
| 1999-08-20 | First criminal conviction under the No Electronic Theft Act (Levy) | Crime | Confirmed | [29] |
| 1999-08-21 | datePublic of CVE-1999-0668, the scriptlet.typelib flaw "demonstrated by Bubbleboy" | Malware | Confirmed | [9] |
| 1999-08-23 to 10-27 | c0mrade runs a backdoor on a Dulles router that intercepts more than 3,300 DTRA messages and at least 19 credentials | Intrusion | Confirmed | [26] |
| 1999-08-30 | Hotmail flaw exposes accounts to anyone with a browser | Exposure | Reported | [49][50] |
| 1999-08-30 | Hoke consents to a permanent antifraud injunction (LR-16266) | Fraud | Confirmed | [77] |
| 1999-08-31 | MS99-032: scriptlet.typelib and Eyedog marked safe for scripting | Vulnerability | Confirmed | [15] |
| 1999-09 | CVE List launches publicly with 321 records; 19-member Editorial Board | Standards | Confirmed | [4][5] |
| 1999-09-07 | Burns pleads guilty | Crime | Confirmed | [19] |
| 1999-09-15 | AES Round 2 notice; five finalists | Cryptography | Confirmed | [66] |
| 1999-09-16 | Phone Masters ringleaders sentenced | Crime | Confirmed | [25] |
| 1999-09-16 | Cyberstalking report delivered to the Vice President | Policy | Confirmed | [30] |
| 1999-09-16 | New US encryption export control policy announced | Cryptography | Confirmed | [62] |
| 1999-09-16 | CA-1999-12: amd buffer overflow (CVE-1999-0704) | Vulnerability | Confirmed | [1] |
| 1999-09-17 | IN-99-05: amd actively exploited for remote root | Mass exploitation | Confirmed | [2] |
| 1999-09-26 | OpenSSH initial import into OpenBSD | Standards | Confirmed | [71] |
| 1999-09-29 | CVE Services publication date of CVE-1999-0018 (statd) | Standards | Confirmed | [7] |
| 1999-10-06 | Vatis to Senate Judiciary: Kosovo-era hacktivism; foreign intelligence services "increasingly view computer intrusions as a useful tool" | Government | Confirmed | [40] |
| 1999-10-19 | CA-1999-13: three WU-FTPD flaws; incidents reported | Vulnerability | Confirmed | [1] |
| 1999-10-20 | FTC final COPPA Rule | Law | Confirmed | [58] |
| 1999-10-24 | Date of the example msadcs.dll log line in IN-99-08 | Mass exploitation | Confirmed | [2] |
| 1999-10-25 | IN-99-06: distributed sniffers on compromised Linux hosts | Mass exploitation | Confirmed | [2] |
| 1999-10-25 | NIST publishes FIPS 46-3 (DES and Triple DES) | Cryptography | Confirmed | [65] |
| 1999-11 | CERT/CC Distributed-Systems Intruder Tools workshop | Defender | Confirmed | [2] |
| 1999-11-03 | HHS proposed rule on privacy of individually identifiable health information | Law | Confirmed | [59] |
| 1999-11-10 | CA-1999-14: six BIND flaws including the NXT overflow | Vulnerability | Confirmed | [1] |
| 1999-11-12 | Gramm-Leach-Bliley Act, Pub. L. 106-102 | Law | Confirmed | [54][55] |
| 1999-11-18 | IN-99-07: trinoo and Tribe Flood Network | DDoS | Confirmed | [2] |
| 1999-11-19 | Burns sentenced to 15 months | Crime | Confirmed | [19] |
| 1999-11-22 | Alibris charged with intercepting Amazon.com email to its dealer clients | Crime | Confirmed | [27] |
| 1999-12 | ISO/IEC 15408-1:1999 (Common Criteria Part 1) published | Standards | Confirmed | [70] |
| late 1999-12 | A person claiming to hold CD Universe customer data demands payment; the FBI opens an investigation. Home: [e-commerce study](/case-studies/ECOMMERCE_THREATS.md) | Extortion | Confirmed | [78] |
| 1999-12-09 | Smith pleads guilty in state and federal court | Crime | Confirmed | [22] |
| 1999-12-10 | IN-99-08: IIS servers compromised through MDAC RDS | Mass exploitation | Confirmed | [2] |
| 1999-12-13 | CA-1999-15: sshd and RSAREF2 overflows | Vulnerability | Confirmed | [1] |
| 1999-12-14 | CA-1999-16: sadmind overflow actively exploited | Vulnerability | Confirmed | [1][8] |
| 1999-12-20 | Miffleton pleads guilty | Crime | Confirmed | [20] |
| 1999-12-21 | MS99-061, the year's last bulletin | Vulnerability | Confirmed | [11] |
| 1999-12-28 | CA-1999-17: Tribe FloodNet 2K | DDoS | Confirmed | [1] |
| 2000-01-08 (boundary) | CD Universe data posted | Extortion | Confirmed | [78] |
| 2000-03-01 (boundary) | Davis sentenced to six months | Crime | Confirmed | [23] |
| 2000-03-02 (boundary) | James Adams (iDEFENSE) testifies on the operation "codenamed Moonlight Maze" | Espionage | Reported | [38] |
| 2000-03-09 (boundary) | Working Group report "The Electronic Frontier" | Policy | Confirmed | [32] |
| 2000-09-06 (boundary) | Gregory sentenced to 26 months | Crime | Confirmed | [24] |
| 2000-09-21 (boundary) | c0mrade sentenced | Crime | Confirmed | [26] |
| 2002-05-01 (boundary) | Smith sentenced to 20 months | Crime | Confirmed | [31] |
| 2002-10-08 (boundary) | NTSB adopts PAR-02/02 on Bellingham | Industrial | Confirmed | [53] |
| 2017-04-03 (boundary) | Kaspersky GReAT and King's College London publish "Penquin's Moonlit Maze" | Espionage | Confirmed | [36] |

## Part 2: the vulnerability record

### The 17 advisories

SEI's index lists the year's advisories by title (Confirmed [3]). CA-1999-01 and CA-1999-02 cover Trojan horses, CA-1999-04 covers Melissa and CA-1999-06 covers ExploreZip. CA-1999-03 covers FTP overflows, CA-1999-05 statd and automountd, CA-1999-07 IIS, CA-1999-08 rpc.cmsd, CA-1999-09 the Array Services default configuration, CA-1999-10 an insecure default on the RaQ2, CA-1999-11 CDE, CA-1999-12 amd, CA-1999-13 WU-FTPD, CA-1999-14 BIND, CA-1999-15 sshd with RSAREF2 and CA-1999-16 sadmind. CA-1999-17 covers denial-of-service tools (Confirmed [3]).

The detail in the advisories, as SEI's compilation prints it (Confirmed [1]):

- **CA-1999-03 (11 Feb).** Forwards Netect's advisory of 9 February on remote buffer overflows in wu-ftpd 2.4.2-academ[BETA-18] and ProFTPD 1.2.0pre1.
- **CA-1999-05 (9 Jun).** Intruders were using the rpc.statd and automountd flaws together, and the advisory was issued because of the number of incident reports.
- **CA-1999-07 (16 Jun).** IIS 4.0 buffer overflows in .HTR, .STM and .IDC handling, with a public exploit tool. Microsoft's fix is MS99-019, "Malformed HTR Request", of 15 June, which says Microsoft had received reports of customer sites being attacked and notes possible code execution (Confirmed [13]).
- **CA-1999-08 (16 Jul).** The rpc.cmsd overflow (CVE-1999-0696) was being exploited in a significant number of reported incidents, and an exploit script had been posted to BUGTRAQ.
- **CA-1999-12 (16 Sep).** The amd (am-utils) overflow (CVE-1999-0704).
- **CA-1999-13 (19 Oct).** Three WU-FTPD flaws, including the MAPPING_CHDIR overflow (CVE-1999-0878); incidents involving at least the first had been reported.
- **CA-1999-14 (10 Nov).** Six BIND flaws. The NXT bug is a buffer overflow that allows code execution with name-server privileges (CVE-1999-0833) and was fixed in 8.2.2; the SIG, so_linger and fdmax bugs are denial-of-service flaws.
- **CA-1999-15 (13 Dec).** An sshd buffer overflow combined with an RSAREF2 flaw, researched by Core SDI, allows remote code execution in builds compiled with RSAREF support (CVE-1999-0834).
- **CA-1999-16 (14 Dec).** The Solaris sadmind overflow on Solaris 2.5 to 7 was "actively being exploited" for remote root (CVE-1999-0977) (Confirmed [1][8]).

### What the advisories say about attackers

In seven cases a CERT or Microsoft text from 1999 says the flaw was being used against real systems: IIS .HTR, statd/automountd, rpc.cmsd, amd, WU-FTPD, MDAC RDS and sadmind (Confirmed [13][1][2]). In two of them an exploit tool or script was public by the time of the advisory: IIS (CA-1999-07) and rpc.cmsd (BUGTRAQ); IN-99-04 adds that intruders were automating the RPC attacks with scripts (Confirmed [1][2]). For the BIND and sshd advisories this study found no statement of exploitation in the passages read, and it does not claim there was none (Inferred [1]).

### Microsoft's year

Microsoft's numbered bulletins for 1999 run from MS99-001 on 21 January to MS99-061 on 21 December; 61 is inferred from the numbering, since MS99-062 returns 404 and MS00-001 is dated 4 January 2000 (Confirmed [11]; Inferred). There was no monthly release cycle yet (Inferred). Four bulletins matter most to this record:

- **MS99-002 (21 Jan).** The "Word 97 Template" flaw: macros in a template could run without warning the user. CERT's Melissa advisory cites it (Confirmed [12]).
- **MS99-019 (15 Jun).** The IIS 4.0 .HTR flaw, with attacks on customer sites already reported. NVD lists it as CVE-1999-0874 with CWE-119 (Confirmed [13]; Demonstrated [10]).
- **MS99-025 (19 Jul).** A re-release of MS98-004 of 17 July 1998, to remind customers that the RDS DataFactory component of MDAC on IIS 3.0 and 4.0 could let a web user run shell commands as a privileged user. The fix is a configuration change, not a patch. The bulletin names CVE-1999-1011, for which NVD lists CWE-264 (Confirmed [14]; Demonstrated [10]).
- **MS99-032 (31 Aug, revised 2 Sep).** The scriptlet.typelib and Eyedog ActiveX controls were wrongly marked safe for scripting, so a web page could do anything the user could do. It prints CVE-1999-0668, CAN-1999-0669 and CAN-1999-0670, sets the kill bit for Eyedog and credits Georgi Guninski (Confirmed [15]). The CVE-1999-0668 record says the flaw was demonstrated by BubbleBoy, carries a datePublic of 21 August 1999 and has no CWE (problemType n/a) (Confirmed [9]).

### The CVE launch and the later record

Mann and Christey of MITRE dated their white paper proposing a Common Vulnerability Enumeration on 8 January 1999, to ease data sharing between vulnerability databases (Confirmed [6]). The concept went to Purdue on 21 and 22 January; a working group from that meeting became the 19-member Editorial Board, created the original 321 records and launched the List publicly in September 1999; by December 2000, 29 organizations had declared compatibility for 43 products (Confirmed [4][5]). The library's [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for the CVE launch (Confirmed [85]).

The CVE record of the year's exploited flaws lags the events. CVE Services shows CVE-1999-0018 (statd) published on 29 September 1999; CVE-1999-0833, -0977, -0878 and -0704 on 4 January 2000; CVE-1999-0834 on 18 January 2000; and CVE-1999-1011, -0874, -0696 and -0668 on 2 June 2000 (Confirmed [7]). NVD back-dates some of these: it lists CVE-1999-0874 as published 16 June 1999, the date of CA-1999-07, and CVE-1999-1011 as published 19 July 1999, the date of MS99-025 (Demonstrated [10]).

## Part 3: mass exploitation and the first DDoS networks

CERT's 1999 incident notes are the year's best record of what intruders did with the advisories (Inferred):

- **Scanning (IN-99-01, 28 Jan).** sscan, a derivative of the 1998 mscan tool, was announced on public lists and could run scripted commands crafted to exploit the flaws it found (Confirmed [2]). Burns used his "Web Bandit" scanner against the Electric Press server (Confirmed [19]).
- **Scripted RPC attacks (IN-99-04, 22 Jul).** Intruders were automating attacks through the cmsd, statd/automountd and ToolTalk flaws and leaving similar artifacts on compromised systems (Confirmed [2]).
- **amd (IN-99-05, 17 Sep).** Active exploitation of the CA-1999-12 overflow for remote root (Confirmed [2]).
- **Distributed sniffers (IN-99-06, 25 Oct).** Sniffers on compromised Linux hosts captured usernames and passwords, disguised under process names such as in.telnetd (Confirmed [2]).
- **DDoS tools (IN-99-07, 18 Nov).** trinoo and Tribe Flood Network were being installed on hosts compromised through RPC flaws and am-utils, and were under active development, testing and deployment. CERT/CC held a Distributed-Systems Intruder Tools workshop in November (Confirmed [2]).
- **IIS through MDAC RDS (IN-99-08, 10 Dec).** IIS servers were being compromised through the RDS flaw, which CERT said had been discussed publicly since 22 April 1998. Attacks show up in IIS logs as POSTs to msadcs.dll, and the note's example log line is dated 24 October 1999 (Confirmed [2]).

### TFN2K

CA-1999-17 (28 Dec) describes Tribe FloodNet 2K as a client-server tool for coordinated denial of service from many sources. It spoofs source addresses, floods over UDP, TCP and ICMP, sends decoy packets, includes malformed-packet crash attacks and runs on UNIX and NT; installing its servers requires an earlier compromise. The advisory says MacOS 9 hosts can be abused as traffic amplifiers at about 37.5 times, and recommends RFC 2267 ingress filtering on as many routers as practical while stating its limits (Confirmed [1]). RFC 2267, Network Ingress Filtering, was published in January 1998 as an informational RFC (Confirmed [69]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) carries TFN2K forward into the February 2000 attacks (Confirmed [85]).

## Part 4: malware and remote access tools

### Melissa (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Melissa (Confirmed [85]). In brief: CA-1999-04 says Melissa lowered macro security settings, mailed the first 50 entries of each Outlook MAPI address book, set a registry marker and infected Normal.dot, and that a user had to open the document (Confirmed [1]). GAO counted more than 100,000 computers at more than 300 organizations by 29 March, said DOE detected it at multiple sites, and said complete data on which agencies were hit did not exist (Confirmed [33][34]). The FBI's 2019 retrospective says servers at more than 300 corporations and agencies were overloaded, some, Microsoft included, had to shut down, and about one million email accounts were disrupted (Confirmed [35]). Smith admitted creating Melissa and posting it from a stolen AOL account to alt.sex (Confirmed [22]). Part 6 has the prosecution.

### Happy99

CERT began receiving reports of Happy99 (also SKA, I-Worm.Happy, Happy99.Worm) around 20 January 1999 and published IN-99-02 on 29 March. On Windows 95, 98 and NT it modifies WSOCK32.DLL, adds a registry start entry and sends itself as an attachment after every email or Usenet post the user makes (Confirmed [2]).

### CIH (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for CIH (Confirmed [85]). IN-99-03 (22 Apr) says some variants activate on 26 April 1999, others on the 26th of each month or on 26 June; the payload tries to erase the hard drive and overwrite the system BIOS, and affects Windows 95 and 98 only (Confirmed [2]).

### ExploreZip

CA-1999-06 (10 Jun, revised 14 Jun) says ExploreZip arrives as an emailed zipped_files.exe and shows a fake archive error. It cuts Office and source-code files to zero bytes on drives C to Z and on writable SMB shares, copies itself into the system directory, adds a run entry to WIN.INI on Windows 98 or to the registry on NT, and spreads by copying itself to writable shares and editing the WIN.INI file there (Confirmed [1]).

### BubbleBoy

The CVE-1999-0668 record says the scriptlet.typelib control, marked safe for scripting, lets a remote attacker execute arbitrary commands, "as demonstrated by Bubbleboy" (Confirmed [9]). BubbleBoy's own spread was not checked against a primary.

### Back Orifice 2000

cDc released Back Orifice 2000, written by DilDog, at DEF CON 7 in Las Vegas on 10 July 1999. cDc describes it as a GPL remote administration tool for Windows NT and 95/98 with strong cryptography and a plugin architecture (Confirmed [17]). The 1998 original is covered in the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md).

### Trojaned source and a fake upgrade

The TCP Wrappers Trojan gave root access to connections from a specific source port and emailed site details when the code was compiled; CERT published MD5 checksums and pointed to Wietse Venema's detached PGP signature, which the trojaned copy did not have (Confirmed [1]). The util-linux Trojan modified /bin/login to email the host and uid to the intruder, and an email offering a fake Internet Explorer upgrade (Ie0199.exe) was widely distributed; Microsoft confirmed it did not send it (Confirmed [1]).

### No ATT&CK software objects

ATT&CK has no software object for Melissa, ExploreZip, CIH, Happy99, Back Orifice, BO2K, trinoo or TFN, and the library's software data has no match (Confirmed [80]; Demonstrated [80]).

## Part 5: the state record

### Moonlight Maze (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Moonlight Maze (Confirmed [85]). The 1999 part of the story, in the researchers' account: after a congressional hearing in late February the FBI investigation leaked, the first press coverage came on 4 March (the whitepaper cites ABC Nightly News and AFP of that date), and the operators immediately dropped the HRTest relay (Reported [37]). The relay, a UK Solaris host, had been monitored with the Metropolitan Police and the FBI for about six months (Reported [36][37]). The researchers' timeline adds an FBI task force trip to Moscow in April 1999, the Sunday Times revealing the code name in July 1999, and follow-on operations named STORM CLOUD (1999/2000) and MAKERS MARK (2003) (Reported [37]).

The tradecraft is described at the level of technique names: relays through hacked servers, the LOKI2 covert-channel backdoor tunnelling over ICMP, promiscuous sniffers, tasking files, info-stealing and lateral-movement scripts using harvested passwords, and TGZ bundles moved by FTP to staging servers, with binaries for SPARC Solaris and MIPS IRIX (Confirmed [36][37]). Attribution rests on Russian-word and broken-English artifacts and mostly dynamically assigned Russian IP addresses; the authors say more hard evidence is needed to confirm a link to Turla, and Securelist calls a conclusion "simply premature" (Reported [36][37]). James Adams of iDEFENSE told a Senate committee in March 2000 that the operation was "codenamed Moonlight Maze by American intelligence" and that Russian hackers had taken R&D secrets over two years (Reported [38]).

ATT&CK records none of this. Turla (G0010) is "attributed to Russia's Federal Security Service (FSB)" and active since at least 2004, with no 1990s mention; Penquin (S0587) has been used by Turla against Linux since at least 2014, with no Moonlight Maze, LOKI2 or 1999 mention; and none of ATT&CK's 61 campaigns covers 1990s activity, the earliest year mentioned being 2000 (Confirmed [44][45][47]). The library's [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) is the home for Turla.

### The Pentagon's view

Deputy Secretary of Defense Hamre told House Armed Services on 23 February 1999 that DoD was detecting 80 to 100 events a day, about 10 of which needed detailed investigation; that the Joint Task Force for Computer Network Defense had been "Established in December 1998"; that the Eligible Receiver exercise had shown cyber indications and warning to be "totally inadequate"; and that Solar Sunrise in February 1998 had looked like preparation for a coordinated attack. He named no state and cited "significant technical problems with characterizing and attributing attacks" (Confirmed [39]).

NIPC Director Vatis told Senate Armed Services on 16 March that the motives for unidentified intrusions could be "economic or traditional espionage, or some form of strategic military attack", named no state, and said collection required criminal or foreign counterintelligence authority (Confirmed [41]). On 6 October he told Senate Judiciary that "foreign intelligence services increasingly view computer intrusions as a useful tool", and that Solar Sunrise had turned out to be two California juveniles and individuals in Israel, not Iraq (Confirmed [40]).

### Hacktivism in two conflicts

During the 1999 Yugoslavia conflict, by Vatis's account, hackers sympathetic to Serbia "ping" attacked NATO web servers, Russian and other individuals supporting the Serbs attacked websites in NATO countries including the United States, and more than 100 US entities received virus-infected email; there was no disruption of the military effort, and the attribution is to sympathetic individuals, not a government (Confirmed [40]).

After the May 1999 bombing of the Chinese embassy in Belgrade, a 2025 ETH Zurich Center for Security Studies report says Chinese hackers formed the Red Hacker Alliance within days, including the Honker Union of China and the Green Army, and defaced US websites; on 7 August 1999, after Lee Teng-hui's "two-states" statement, Chinese hackers defaced Taiwanese government websites. The report characterizes them as hacktivists and cites Henderson that there is no evidence of direct Chinese government control, while independence "does not necessarily mean a full separation from the state" (Reported [42]). CNN reported that on Sunday 9 May hackers protesting the bombing planted messages on the Energy, Interior and National Park Service home pages and that it was unclear whether they were in China (Reported [51]). The library's ATT&CK group, campaign and software data has no entry naming the Red Hacker Alliance or the Honker Union (Demonstrated [80]; other aliases not checked). The library's [China study](/case-studies/THREAT_ACTORS_CHINA.md) carries the later state record.

### Equation: not placed in 1999

Kaspersky says "It is not known when the Equation group began their ascent": its earliest samples were compiled in 2002, one C&C was registered in August 2001 and others as early as 1996, and no state is named (Confirmed [43]). ATT&CK's Equation (G0020) gives no active-since date and no 1990s activity (Confirmed [46]). Nothing in the record places Equation in 1999. The home study is [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md).

### The Cox Committee

The Cox Committee report, "U.S. National Security and Military/Commercial Concerns with the People's Republic of China" (H. Rpt. 105-851), carries a govinfo issue date of 2 January 1999. Its first chapter describes PRC intelligence services acquiring US military technology through human, commercial and front-company channels, not network intrusion (Confirmed [48]). It is context for the year's espionage climate, not a cyber event; the date of the declassified public release was not checked.

## Part 6: crime and prosecutions

The Justice Department's computer crime index lists six computer intrusion releases for 1999: Mitnick (9 Aug), the Phone Masters (16 Sep), Burns (19 Nov), Alibris (22 Nov), the Melissa plea (9 Dec) and Miffleton (20 Dec) (Confirmed [28]).

### Kevin Mitnick (summary)

The [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) is the home for this case. In March 1999 Mitnick entered a global plea to four wire fraud counts, two computer fraud counts and one interception count, and on 9 August Senior Judge Pfaelzer (C.D. Cal.) sentenced him to 46 months; the release adds an earlier 22-month term, 68 months in total, and restitution of just over $4,125, the court rejecting his claim that the government overstated losses. He admitted social engineering, cloned phones, sniffers and hacker tools against Motorola, Novell, Fujitsu, Sun, USC and Nokia among others (Confirmed [21]).

### Melissa: David L. Smith

New Jersey authorities arrested Smith on 1 April 1999, and he pleaded guilty in state and federal court on 9 December. He admitted creating Melissa and, in his federal plea agreement, more than $80 million in damage; the release says Melissa infected more than one million PCs in North America, which is DOJ's figure, not a measurement (Confirmed [22]). He was sentenced on 1 May 2002 to 20 months, below a guideline range of 46 to 57 months because of his cooperation, with a $5,000 fine and three years of supervised release (Confirmed [31]).

### Defacers and globalHell

- **Eric Burns ("Zyklon").** Burns, 19, attacked the Electric Press server hosting the USIA, NATO and Vice President pages four times between August 1998 and January 1999 using his "Web Bandit" scanner; one attack closed the USIA site for eight days. He admitted advising others on the May 1999 White House web attack, after which the White House shut its web server and disconnected its networks for two days. He pleaded guilty on 7 September and was sentenced on 19 November (E.D. Va.) to 15 months, three years of supervised release and $36,240 restitution; the FBI and Secret Service investigated (Confirmed [19]).
- **Chad Davis ("minphasr").** Davis, 19, of Global Hell, defaced the US Army web page in June 1999, two months after a federal search; access was restored within two hours. He pleaded guilty on 4 January 2000 and was sentenced on 1 March 2000 (E.D. Wis.) to six months, three years of supervised release and $8,054 restitution, after an Army CID and FBI investigation (Confirmed [23]).
- **Patrick Gregory ("MostHateD").** Gregory co-founded globalHell with Davis in February 1998. From 1997 through May 1999 he used stolen access devices to set up teleconferences on AT&T, MCI, Sprint and other carriers, and on 6 September 2000 he was sentenced to 26 months (Confirmed [24]).

### The Phone Masters

On 16 September 1999 (N.D. Tex.) the ringleaders Corey Lindsly (41 months) and Calvin Cantrell (two years), each ordered to pay $10,000 restitution, were sentenced after spring 1999 guilty pleas under 18 U.S.C. 1029(a)(3) and 1030(a)(4). The group penetrated Sprint, Southwestern Bell and GTE and sold calling card numbers, and also reached credit reporting agencies, utility providers and government systems including the NCIC computer. Prosecutors called the case the first high-speed data wiretap used in a criminal case (Confirmed [25]).

### c0mrade

A 16-year-old known as "c0mrade" (Miami; sentenced 21 September 2000) entered 13 NASA Marshall computers on 29 and 30 June 1999, took about $1.7 million worth of ISS environmental-control software, after which the NASA computer systems were shut down for 21 days in July 1999. From 23 August to 27 October 1999 he ran a backdoor on a router in Dulles that intercepted more than 3,300 DTRA messages and at least 19 credentials (Confirmed [26]).

### Passwords, mail and fraud

- **Andrew Miffleton ("Daphtpunk").** In February 1999 he held a national Internet company's password list, including root-level passwords, and gave some to Darkside Hackers members who used them to access systems nationwide, a $90,000 loss; he also held cloned-cellular ESN/MIN pairs and calling card and credit card numbers. He pleaded guilty on 20 December 1999 (N.D. Tex.) to possessing unauthorized access devices (Confirmed [20]).
- **Alibris.** On 22 November 1999 Alibris, formerly Interloc, which ran the Valinet ISP, was charged in the District of Massachusetts with ten counts of intercepting thousands of Amazon.com emails to its book-dealer customers between January and June 1998 and one count of possessing competitor ISPs' password files. It agreed to a $250,000 fine. The release is a charge, not a finding (Confirmed [27]).
- **Jeffrey Levy.** The first criminal conviction under the No Electronic Theft Act came on 20 August 1999, when the University of Oregon student admitted posting pirated software, music and movies on his web site in January 1999 (Confirmed [29]).
- **Gary D. Hoke Jr.** On 7 April 1999, under an assumed name, Hoke posted a false report that PairGain was being bought by an Israeli company, linked to a fake Bloomberg News page he had created; the stock rose, then fell. The SEC sued on 21 April under Section 10(b) and Rule 10b-5 (Confirmed [76]). He consented to a permanent antifraud injunction without admitting or denying, and no penalty was imposed because of a demonstrated inability to pay (Confirmed [77]).

### CD Universe (summary)

The [e-commerce study](/case-studies/ECOMMERCE_THREATS.md) and the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) are the homes for this case. eUniverse disclosed that in late December 1999 a person claiming to hold CD Universe customer data demanded payment, the FBI opened an investigation, and the data was posted on 8 January 2000; CD Universe had about 300,000 registered customers, and the company could not determine when or how the data was taken (Confirmed [78]).

### The Hotmail exposure

Wired reported on 30 August 1999 that a Hotmail security hole exposed every account, estimated at up to 50 million, to anyone with a web browser; a group calling itself Hackers Unite said it publicized the hole through Swedish media, and Microsoft denied it was a backdoor (Reported [49]). CNN reported the same day that a web address opened Hotmail accounts once a username was entered, that every account CNN tested opened, and that Hotmail had 40 million subscribers (Reported [50]). The flaw class is not described in any primary opened.

## Part 7: law, policy and privacy

### Financial and health privacy

The Gramm-Leach-Bliley Act, Pub. L. 106-102 (S. 900), was enacted on 12 November 1999 (Confirmed [54][55]). Title V covers privacy: section 501 (15 U.S.C. 6801) gives each financial institution "an affirmative and continuing obligation" to respect customer privacy and protect the security and confidentiality of nonpublic personal information and directs agencies to set administrative, technical and physical safeguards, and section 521 (15 U.S.C. 6821) prohibits obtaining customer information by false pretenses (Confirmed [54]). The FTC describes the resulting Safeguards Rule as requiring an information security program with those safeguards, and the Privacy Rule as a notice of sharing practices plus an opt-out right (Confirmed [56]). On 3 November HHS published the proposed rule "Standards for Privacy of Individually Identifiable Health Information" (64 FR 59918), citing concern that electronic technology could erode health-information privacy (Confirmed [59]).

### Children, stalking and unlawful conduct online

The FTC issued the final COPPA Rule on 20 October 1999, effective 21 April 2000: privacy notice, verifiable parental consent, parental review and deletion, limits on collection, and Commission-approved safe harbors (Confirmed [58]). On 16 September the Attorney General delivered "Cyberstalking: A New Challenge for Law Enforcement and Industry" to the Vice President (Confirmed [30]). Executive Order 13133 of 5 August set up a Working Group on Unlawful Conduct on the Internet chaired by the Attorney General, to report within 120 days on whether federal law sufficed and what new tools were needed (Confirmed [57]); its report of 9 March 2000 recommended technology-neutral law, more law-enforcement resources and international coordination, and continued private-sector leadership (Confirmed [32]).

### Money and people for infrastructure protection

The Justice Department's FY2000 budget request of 1 February 1999 sought 60 more FBI agents and $122.54 million in added funding to protect critical information infrastructure from cyber attacks (Confirmed [18]). GAO's April testimony found no governmentwide process to report and analyze attacks and only partial DoD and DOE data (Confirmed [34]).

### The Year 2000 problem

The Senate Commerce Committee report on S. 96, the Y2K Act, was ordered printed on 10 March 1999 (Confirmed [61]), and the Y2K Act, Pub. L. 106-37, was enacted on 20 July 1999, setting procedures for civil actions over failures of devices or systems to handle the 1999 to 2000 transition (Confirmed [60]).

## Part 8: cryptography and standards

### DES falls, Triple DES and AES advance

On 19 January 1999 the EFF DES Cracker with distributed.net, nearly 100,000 PCs, found the DES Challenge III key in 22 hours 15 minutes, testing 245 billion keys per second; RSA awarded a $10,000 prize, and EFF said 56-bit DES offers only marginal protection against a committed adversary (Confirmed [63], EFF's account of its own result). distributed.net records the run as starting at 9am PST on 18 January and ending at 7am PST on 19 January (Confirmed [64]). NIST published FIPS 46-3 on 25 October 1999, specifying DES and the Triple Data Encryption Algorithm and superseding FIPS 46-2; it was withdrawn on 19 May 2005 (Confirmed [65]). In the AES process the Second AES Candidate Conference met in March, Round 1 comments closed on 15 April, five finalists were named (MARS, RC6, Rijndael, Serpent and Twofish), a Federal Register notice of 15 September asked for Round 2 comments, and Rijndael was selected on 2 October 2000 (Confirmed [66]).

### Export controls

The United States announced a new encryption export control policy on 16 September 1999; the interim final rule of 14 January 2000 (65 FR 2492) that implemented it allows export of any encryption item to non-government end users in all destinations, with embargoed-state restrictions unchanged (Confirmed [62]).

### Protocols, certificates, assurance and OpenSSH

- **TLS 1.0.** RFC 2246, published in January 1999, is based on Netscape's SSL 3.0; TLS 1.0 and SSL 3.0 do not interoperate, but TLS 1.0 can fall back to SSL 3.0. RFC 2246 is now Historic and was obsoleted by RFC 4346 (Confirmed [67]).
- **X.509 profile.** RFC 2459, the Internet X.509 PKI Certificate and CRL Profile by Housley, Ford, Polk and Solo, was published on the Standards Track in January 1999 (Confirmed [68]).
- **Common Criteria.** ISO/IEC 15408-1:1999, Part 1 (Introduction and general model), was published as edition 1 in December 1999 by JTC 1/SC 27; it was withdrawn on 22 September 2005 and revised by 15408-1:2005 (Confirmed [70]).
- **OpenSSH.** OpenBSD developers forked OSSH, which derives from the free ssh 1.2.12; the initial import was on 26 September 1999, and OpenSSH shipped with OpenBSD 2.6 about two months later (Confirmed [71]).

## Part 9: the industrial record

At about 3:28 p.m. PDT on 10 June 1999 a 16-inch Olympic Pipe Line Company pipeline ruptured in Bellingham, Washington, releasing about 237,000 gallons of gasoline into a creek in Whatcom Falls Park; it ignited about 1.5 hours later and burned about 1.5 miles of creek. Two 10-year-old boys and an 18-year-old died, eight people were injured, and damages were at least $45 million by Olympic's estimate of January 2002. NTSB adopted its report, PAR-02/02, on 8 October 2002 (Confirmed [53]).

The control system is part of the probable cause. Item (5) is Olympic's practice of performing database development work on the SCADA system while it was being used to operate the pipeline, which led to the system becoming non-responsive at a critical time; items (1) to (4) are 1994 excavation damage, an inaccurate in-line inspection evaluation, untested Bayview safety devices and uncorrected repeated block-valve closures (Confirmed [53]). NTSB found the SCADA system bridged to the building network and reachable by dial-in modem with no firewalls or access monitoring, but no evidence that an intrusion caused the slowdown; the VMS security log showed no unauthorized access attempt, and NTSB concluded that Olympic did not adequately manage the development, implementation and protection of its SCADA system (Confirmed [53]).

This is not an intrusion. It is included because it is the year's clearest primary record of how a control system's exposure and operating practice can turn into physical harm (Inferred). Later industrial attacks are covered in the [Stuxnet study](/case-studies/STUXNET.md) and the [ICS attacks and advisories study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md), and the library's [ICS/OT security reference](/ICS_OT_SECURITY_REFERENCE.md) covers the defenses.

## Part 10: the defender view

**Check the signature, not the mirror.** The trojaned TCP Wrappers lacked the author's detached PGP signature, which CERT pointed users to for verification (Confirmed [1]). CERT's advice to developers to sign and to users to verify is the earliest version in this record of the signed-release practice that the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) and [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) studies still argue for (Inferred).

**Know your exposed services.** The year's root compromises came through RPC daemons, FTP servers, BIND, IIS and sadmind (Confirmed [1][2]). A host inventory that knows which of these are listening, and why, would have shortened every one of CERT's 1999 incident notes (Inferred).

**Close the configuration gap.** MDAC RDS was a configuration fix in July 1998, a reminder in July 1999 and an incident note in December 1999 (Confirmed [14][2]). Configuration fixes need the same tracking as patches, a lesson the [Log4Shell study](/case-studies/LOG4SHELL.md) shows was still being learned in 2021 (Inferred).

**Assume a compromised host is now an attacker's resource.** trinoo, TFN and TFN2K turned compromised hosts into flood sources (Confirmed [2][1]). Outbound filtering and ingress filtering protect others from your hosts, not only you from theirs (Inferred [69]).

**Keep credentials off the wire and off the disk.** Distributed sniffers in October, the Darkside root password list in February and Mitnick's sniffers all turn on reusable passwords seen in transit or stored in lists (Confirmed [2][20][21]). CA-1999-02 recommends ssh for terminal sessions, and OpenSSH was first imported in September (Confirmed [1][71]); calling it the year's answer is this study's reading (Inferred).

**Treat a control system as a production system.** NTSB's finding at Bellingham was about running development on a live SCADA host that was also reachable by modem (Confirmed [53]).

**Report so that someone can count.** GAO said complete data on which agencies Melissa hit did not exist and that there was no governmentwide process to report and analyze attacks (Confirmed [33][34]). The CVE List, launched the same year, solved the naming half of that problem (Confirmed [4]; Inferred).

## Part 11: MITRE mappings

No 1999 record carries an ATT&CK, CAPEC or CWE id: CWE was first released in 2006, growing out of MITRE's CVE categorization work and PLOVER under NIST SAMATE; CAPEC was first released in 2007 under the DHS Software Assurance initiative; and MITRE started ATT&CK in 2013 for the FMX research project (Confirmed [72][73][74]). Every binding below is this study's later mapping (Inferred). Every id was checked against the library's data files (`data/attack/technique_profiles.jsonl`, `software.jsonl`, `technique_to_d3fend.jsonl`, `superseded_by.jsonl`, `data/weaknesses/cwe.jsonl` and `capec.jsonl`) and the generated pages under `mitre/` (Demonstrated [79][80][81][82][83][84]). Names and tactics are those of ATT&CK v20.0 as the library carries them. The live ATT&CK pages for T1685, T1137.001 and T1498.002 match the library's titles (Confirmed [75]). T1562.001 is revoked in v20.0 and maps to T1685, and T1656 Impersonation is revoked and maps to T1684.001; neither revoked id is used (Demonstrated [84]).

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md): **Described** means a primary source describes the behavior and this study assigns the id; **Reported** means only a secondary source supports the behavior; **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading. No row is **Listed**, because no 1999 source prints an ATT&CK id.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | initial-access | Described | Trojaned TCP Wrappers 7.6 (CA-1999-01, 21 Jan); trojaned util-linux 2.9g (22 to 24 Jan; CA-1999-02, 5 Feb) | [1] |
| [`T1205`](/mitre/techniques/T1205.md) | Traffic Signaling | stealth, persistence, command-and-control | Described | The TCP Wrappers Trojan gave root to connections from a specific source port (21 Jan) | [1] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Described | Melissa (26 Mar), ExploreZip (10 Jun) and the fake Ie0199.exe upgrade (5 Feb) arrive as email attachments | [1] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | Melissa needs a user to open the document; ExploreZip's zipped_files.exe; Happy99.exe (from 20 Jan) | [1][2] |
| [`T1059.005`](/mitre/techniques/T1059-005.md) | Visual Basic | execution | Described | Melissa, a Word 97/2000 macro virus (CA-1999-04, 27 Mar) | [1] |
| [`T1137.001`](/mitre/techniques/T1137-001.md) | Office Template Macros | persistence | Described | Melissa infects Normal.dot; the "Word 97 Template" flaw (MS99-002, 21 Jan) | [1][12] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | defense-impairment | Described | Melissa lowers macro security settings (CA-1999-04) | [1] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | defense-impairment, persistence | Described | Melissa sets a registry marker (CA-1999-04) | [1] |
| [`T1547.001`](/mitre/techniques/T1547-001.md) | Registry Run Keys / Startup Folder | persistence, privilege-escalation | Described | Happy99 registry start entry (IN-99-02, 29 Mar); ExploreZip run entry in the NT registry or WIN.INI (CA-1999-06, 10 Jun) | [2][1] |
| [`T1036.005`](/mitre/techniques/T1036-005.md) | Match Legitimate Resource Name or Location | stealth | Described | Distributed sniffers named like in.telnetd (IN-99-06, 25 Oct); ExploreZip copies itself into the system directory (10 Jun) | [2][1] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | discovery | Described | ExploreZip finds writable SMB shares (CA-1999-06, revised 14 Jun) | [1] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | lateral-movement | Described | ExploreZip copies itself to shares and edits the WIN.INI file there (CA-1999-06) | [1] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Described | ExploreZip zeroes Office and source-code files (10 Jun) | [1] |
| [`T1561.001`](/mitre/techniques/T1561-001.md) | Disk Content Wipe | impact | Inferred | CIH tries to erase the hard drive (IN-99-03, 22 Apr; trigger 26 Apr); the note does not say which structures | [2] |
| [`T1495`](/mitre/techniques/T1495.md) | Firmware Corruption | impact | Described | CIH overwrites the system BIOS (IN-99-03) | [2] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | IIS .HTR (MS99-019, 15 Jun; CA-1999-07, 16 Jun); MDAC RDS (IN-99-08, 10 Dec); WU-FTPD (CA-1999-13, 19 Oct); FTP overflows (CA-1999-03, 11 Feb) | [13][1][2] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Inferred | statd/automountd (9 Jun), rpc.cmsd (16 Jul), ToolTalk (IN-99-04, 22 Jul), amd (17 Sep), sadmind (14 Dec); CERT does not say whether hosts were reached from inside or outside a site | [1][2] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | scriptlet.typelib "demonstrated by Bubbleboy" (CVE-1999-0668, datePublic 21 Aug; MS99-032, 31 Aug) | [9][15] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | reconnaissance | Described | sscan (IN-99-01, 28 Jan); Burns's Web Bandit scanner (Aug 1998 to Jan 1999) | [2][19] |
| [`T1040`](/mitre/techniques/T1040.md) | Network Sniffing | credential-access, discovery | Described | Distributed sniffers (IN-99-06, 25 Oct); Moonlight Maze sniffers (1998 to 1999); Mitnick's sniffers (sentence 9 Aug); c0mrade's router backdoor intercepting DTRA messages (23 Aug to 27 Oct) | [2][36][21][26] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Darkside members use root passwords from Miffleton's list (Feb); Moonlight Maze scripts using harvested passwords | [20][37] |
| [`T1491.002`](/mitre/techniques/T1491-002.md) | External Defacement | impact | Described | USIA, NATO and Vice President pages (Aug 1998 to Jan 1999); Army page (Jun); Energy, Interior and NPS pages (9 May, Reported); US and Taiwanese sites (May and 7 Aug, Reported) | [19][23][51][42] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | trinoo and TFN (IN-99-07, 18 Nov); TFN2K floods over UDP, TCP and ICMP (CA-1999-17, 28 Dec) | [2][1] |
| [`T1498.002`](/mitre/techniques/T1498-002.md) | Reflection Amplification | impact | Described | MacOS 9 hosts as amplifiers at about 37.5x (CA-1999-17) | [1] |
| [`T1499.004`](/mitre/techniques/T1499-004.md) | Application or System Exploitation | impact | Described | TFN2K malformed-packet crash attacks (CA-1999-17) | [1] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Botnet | resource-development | Described | trinoo and TFN installed on hosts compromised through RPC and am-utils flaws (IN-99-07) | [2] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | command-and-control | Inferred | Back Orifice 2000 released (10 Jul); no 1999 intrusion using it is in the record | [17] |
| [`T1090.003`](/mitre/techniques/T1090-003.md) | Multi-hop Proxy | command-and-control | Described | Moonlight Maze relays through hacked servers, including HRTest (Oct 1998 to Mar 1999) | [36][37] |
| [`T1584.004`](/mitre/techniques/T1584-004.md) | Server | resource-development | Described | The HRTest relay, a compromised UK Solaris host | [36] |
| [`T1095`](/mitre/techniques/T1095.md) | Non-Application Layer Protocol | command-and-control | Described | LOKI2 tunnelling over ICMP | [36][37] |
| [`T1560`](/mitre/techniques/T1560.md) | Archive Collected Data | collection | Described | Moonlight Maze TGZ bundles | [37] |
| [`T1048`](/mitre/techniques/T1048.md) | Exfiltration Over Alternative Protocol | exfiltration | Described | Moonlight Maze bundles moved by FTP to staging servers | [37] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Inferred | Moonlight Maze tasking files and scripts on victim hosts | [36][37] |
| [`T1114`](/mitre/techniques/T1114.md) | Email Collection | collection | Inferred | Alibris charged with intercepting Amazon.com mail to dealer clients (Jan to Jun 1998; charged 22 Nov 1999); a charge, not a finding | [27] |
| [`T1684.001`](/mitre/techniques/T1684-001.md) | Impersonation | stealth | Inferred | Hoke's fake Bloomberg News page (7 Apr); mapped through the revoked T1656 | [76][84] |
| [`T1657`](/mitre/techniques/T1657.md) | Financial Theft | impact | Inferred | CD Universe extortion demand (late Dec 1999; data posted 8 Jan 2000) | [78] |

Left out on purpose: T1561.002 Disk Structure Wipe, since IN-99-03 does not say CIH targets disk structures (Inferred [2]); T1499 at the parent level, since the sub-technique row is the specific behavior; the DES Cracker, which is research and is bound through CWE and CAPEC instead; the Phone Masters' calling card resale and Gregory's teleconference fraud, for which the releases describe no computer technique beyond access (Inferred [25][24]); the Hotmail exposure, whose flaw class no primary opened describes (Reported [49][50]); c0mrade's NASA software theft, for which the release describes no mechanism beyond entry (Inferred [26]); and Mitnick's social engineering, which the [Mitnick study](/case-studies/MITNICK_INTRUSIONS.md) binds.

### ATT&CK for ICS techniques

None bound. Bellingham is not an intrusion: NTSB found no evidence that an intrusion caused the SCADA slowdown (Confirmed [53]). The exposure NTSB describes, a SCADA host reachable by dial-in modem with no access monitoring, resembles T0822 External Remote Services, which is in the library's ICS data but has no generated page; it is noted here as exposure only and is not in the layer (Demonstrated [87]; Inferred). No ICS layer is published.

### ATT&CK groups, software and campaigns

None bound. The library's ATT&CK data holds no software object for Melissa, CIH, ExploreZip, Happy99, BO2K, trinoo or TFN, and no group or campaign object for Moonlight Maze, the Red Hacker Alliance or globalHell (Confirmed [80]; Demonstrated [80]). None of ATT&CK's 61 campaigns covers 1990s activity (Confirmed [47]). Moonlight Maze reaches an ATT&CK id only through the unproven Turla lineage the researchers propose and call premature: [Turla (G0010)](/mitre/groups/G0010.md) dates the group from at least 2004 and [Penquin (S0587)](/mitre/software/S0587.md) from at least 2014, and neither mentions Moonlight Maze (Confirmed [44][45][36]). [Equation (G0020)](/mitre/groups/G0020.md) is not placed in 1999 (Confirmed [46][43]). These pages are linked for context, not as 1999 bindings.

### CWE and CAPEC

Rows marked "as NVD lists it" use the CWE NVD prints on the later CVE-1999 record (Demonstrated [10]). Every other CWE is this study's binding at the class level, because no 1999 record carries a CWE (Inferred). Names are those in the library's CWE and CAPEC data, and the CAPEC column says which pairings the library makes and which are this study's (Demonstrated [82][83]).

| CWE | Weakness (library name) | 1999 record | CAPEC |
|---|---|---|---|
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer (as NVD lists it for CVE-1999-0874) | IIS .HTR, MS99-019, 15 Jun | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers (library pairing) |
| CWE-264 | (as NVD lists it for CVE-1999-1011; the library's CWE data has no entry) | MDAC RDS, MS99-025, 19 Jul; IN-99-08, 10 Dec | None assigned |
| NVD-CWE-Other | (as NVD lists it for CVE-1999-0018) | statd, CA-1999-05, 9 Jun | None assigned |
| CWE-120 | Buffer Copy without Checking Size of Input (this study's binding) | The overflow advisories: FTP (CA-1999-03), cmsd (08), amd (12), WU-FTPD (13), BIND NXT (14), sshd/RSAREF2 (15), sadmind (16) | [CAPEC-100](/mitre/capec/CAPEC-100.md) (library pairing for CWE-120) |
| CWE-506 | Embedded Malicious Code | Trojaned TCP Wrappers and util-linux, 21 to 24 Jan | [CAPEC-523](/mitre/capec/CAPEC-523.md) Malicious Software Implanted (this study's pairing; the library links CAPEC-523 to T1195.002) |
| CWE-494 | Download of Code Without Integrity Check | Building unsigned source from FTP mirrors, CA-1999-01 and 02 | [CAPEC-186](/mitre/capec/CAPEC-186.md) Malicious Software Update (library pairing for CWE-494; the library links CAPEC-186 to T1195.002) |
| CWE-1188 | Initialization of a Resource with an Insecure Default | Array Services (CA-1999-09), RaQ2 (CA-1999-10), MDAC RDS default | None assigned; the library's only CAPEC for this CWE describes an unrelated attack |
| CWE-749 | Exposed Dangerous Method or Function | scriptlet.typelib and Eyedog marked safe for scripting, MS99-032, 31 Aug | None assigned; the library's only CAPEC for this CWE, CAPEC-500 WebView Injection, concerns mobile WebViews |
| CWE-326 | Inadequate Encryption Strength | 56-bit DES, DES Challenge III, 19 Jan | [CAPEC-20](/mitre/capec/CAPEC-20.md) Encryption Brute Forcing (library pairing for CWE-326; binding it to the DES break is this study's) |
| CWE-509 | Replicating Malicious Code (Virus or Worm) | Melissa, Happy99, ExploreZip, CIH | None assigned |
| none bound | (phishing, shared content, floods, sniffing, scanning) | Melissa and ExploreZip mail; ExploreZip shares; trinoo, TFN, TFN2K; IN-99-06; sscan | [CAPEC-163](/mitre/capec/CAPEC-163.md) Spear Phishing (links T1566.001); [CAPEC-562](/mitre/capec/CAPEC-562.md) Modify Shared File (links T1080); [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding (links T1498.001 and T1499); [CAPEC-490](/mitre/capec/CAPEC-490.md) Amplification (links T1498.002); [CAPEC-158](/mitre/capec/CAPEC-158.md) Sniffing Network Traffic (links T1040); [CAPEC-169](/mitre/capec/CAPEC-169.md) Footprinting (links T1595) |

### D3FEND countermeasures

Pairings come from `data/attack/technique_to_d3fend.jsonl` unless the row says the pairing is this study's; every page exists under `/mitre/d3fend/` (Demonstrated [81]).

| Technique from the record | D3FEND countermeasures | 1999 analogue |
|---|---|---|
| T1566.001 | [Email Filtering](/mitre/d3fend/email-filtering.md), [Content Quarantine](/mitre/d3fend/content-quarantine.md) | CA-1999-02's virus products and user education [1] |
| T1204.002, T1137.001, T1547.001 and T1036.005 | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (allowlisting is not paired with T1036.005) | CA-1999-02's Tripwire-style integrity checking [1] |
| T1195.002 | [Software Update](/mitre/d3fend/software-update.md), [Software Inventory](/mitre/d3fend/software-inventory.md) | CA-1999-01's checksums and the author's PGP signature [1] |
| T1080 and T1491.002 | [Network Resource Access Mediation](/mitre/d3fend/network-resource-access-mediation.md), [Decoy Network Resource](/mitre/d3fend/decoy-network-resource.md) | No 1999 counterpart in the record |
| T1190, T1498.001 and T1498.002 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md), [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md) | RFC 2267 ingress filtering, as CA-1999-17 recommends [1][69] |
| T1203 and T1210 | [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md), [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) | Vendor patches for the overflow advisories [1] |
| T1078 | [Change Default Password](/mitre/d3fend/change-default-password.md), [User Account Permissions](/mitre/d3fend/user-account-permissions.md) | CA-1999-02's least privilege [1] |
| T1040 | The library maps only [DNS Traffic Analysis](/mitre/d3fend/dns-traffic-analysis.md). [Message Encryption](/mitre/d3fend/message-encryption.md) is a concept match for ssh (this study's pairing) | CA-1999-02's ssh advice; OpenSSH, 26 Sep [1][71] |
| T1219, T1090.003, T1095 and T1105 | [Relay Pattern Analysis](/mitre/d3fend/relay-pattern-analysis.md), [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md), [Remote Terminal Session Detection](/mitre/d3fend/remote-terminal-session-detection.md) | The HRTest administrator's monitoring [36] |
| T1112 | [System Configuration Permissions](/mitre/d3fend/system-configuration-permissions.md) | No 1999 counterpart in the record |
| T1561.001 | [Disk Partitioning](/mitre/d3fend/disk-partitioning.md) | No 1999 counterpart in the record |
| T1495 | The library has no pairing. [Firmware Verification](/mitre/d3fend/firmware-verification.md) is a concept match for CIH (this study's pairing) | No 1999 counterpart in the record [2] |

The library's data has no D3FEND pairing for T1059.005, T1485, T1685, T1135, T1499.004, T1584.005, T1595.002, T1114, T1684.001 or T1657, and none is invented here (Demonstrated [81]).

### Navigator layer

The study's techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-1999.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1999.json), listing the 36 techniques in the Enterprise table under each tactic they carry in v20.0, and listed on [the Navigator layers page](/navigator/index.md) [86]. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping; no entry scores 100, because no 1999 source prints an ATT&CK id. Each entry's comment names the source numbers in the Sources table below. No ICS layer is needed.

## Cross-cutting themes

**The user and the server were two different fronts.** Melissa, Happy99 and ExploreZip needed a click; the RPC, FTP, IIS and sadmind compromises did not (Confirmed [1][2]). The same split recurs in later years of the series, from the [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md) on the server side to the phishing records of the [Fancy Bear study](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md) on the user side (Inferred).

**Trusted distribution carried code.** Trojaned TCP Wrappers and util-linux in January, and a fake Microsoft upgrade in February, are the year's supply-chain record (Confirmed [1]). The trust failure recurs in the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md), [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies (Inferred).

**Mass exploitation followed disclosure, and disclosure followed exploitation.** CERT's 1999 notes show scripts chaining known flaws within weeks, while Microsoft and CERT had to re-release a 1998 fix because servers were still open (Confirmed [2][14]). The same timing problem recurs in [Log4Shell](/case-studies/LOG4SHELL.md) (Inferred).

**Attribution stayed cautious in the official record.** Hamre named no state and cited the difficulty of attribution; Vatis attributed Kosovo-era attacks to sympathetic individuals; the Moonlight Maze researchers call a Turla link premature (Confirmed [39][40][36]). The [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) and the [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) show how much more evidence a confident attribution now carries (Inferred).

**The rules of the next two decades were written this year.** GLBA's safeguards duty, the COPPA rule, the HIPAA privacy proposal, FIPS 46-3, TLS 1.0 and the CVE List all date to 1999 (Confirmed [54][58][59][65][67][4]). Root causes of the overflow class behind many of the year's advisories are discussed on the library's [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md) page (Inferred).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: 1999 as the year of mass-mailers.** Four of the 17 CERT advisories concern malicious code and twelve concern server software and insecure defaults [3].
- **Overstated: Melissa's numbers.** "More than $80 million" is Smith's plea admission and "more than one million PCs" is DOJ's figure; GAO counted more than 100,000 computers and said complete data did not exist; the FBI later wrote of about one million email accounts disrupted [22][33][35].
- **Overstated: Moonlight Maze as a settled Russian state operation, or as Turla.** The 1999 record is an investigation pointing to Russian ISPs; the researchers who hold the evidence call the Turla conclusion premature, and ATT&CK's Turla and Penquin pages are silent on it [37][36][44][45].
- **Overstated: the May 1999 defacements as a Chinese state operation.** The secondary record calls them patriotic hacktivists with no evidence of direct government control, and CNN could not say whether the hackers were in China [42][51].
- **Overstated: Bellingham as a SCADA cyberattack.** NTSB found no intrusion; the failure was self-inflicted database work on a live system [53].
- **Overstated: DES Challenge III as a routine attacker capability.** It took a coalition of about 100,000 machines plus purpose-built hardware [63][64].
- **Overstated: "250,000 attacks a year."** The figure comes from an unnamed DoD source relayed by trade press [52]; Hamre's own figure was 80 to 100 events a day [39].
- **Overstated: any ATT&CK, CWE or CAPEC id on a 1999 event.** Those programs began between 2006 and 2013, and the Navigator layer reflects later naming, not 1999 understanding [72][73][74].
- **Understated: quiet server compromise.** The RPC, FTP, IIS and sadmind compromises, and the hosts later used as DDoS agents, left little public trace beyond CERT's notes [1][2].
- **Understated: patch and configuration latency.** MDAC RDS was fixed by configuration in July 1998 and still being used to compromise servers when CERT's note appeared on 10 December 1999 [14][2].
- **Understated: how long and broad Moonlight Maze was, and what publicity cost.** About 1,600 unique addresses appear in a few months of relay logs, and the first press reports ended the monitoring [37][36].
- **Understated: the policy record.** GLBA's safeguards and pretexting provisions, the COPPA rule and the HIPAA privacy proposal set rules still in force in their successors, and EO 13133 set the federal review of online unlawful conduct [54][58][59][57].
- **Understated: what standards mark.** TLS 1.0, ISO/IEC 15408 and FIPS 46-3 mark intent, not deployment; adoption dates were not checked [67][70][65].
- **Understated: the CVE lag.** Many of the year's exploited flaws had their CVE records published in 2000, and the 321-record launch list covered older flaws too [4][7].

### Discrepancies in the record

- **Melissa's reach.** GAO: more than 100,000 computers at more than 300 organizations by 29 March; DOJ: more than one million PCs in North America; FBI: about one million email accounts disrupted [33][22][35]. The bases differ and none is a measured census.
- **Mitnick's sentence.** The release gives 46 months for the 1999 case and an earlier 22-month term, 68 months in total; the library's dot-com era study cites 46 [21][85].
- **Hotmail's size.** Wired estimated up to 50 million accounts; CNN reported 40 million subscribers [49][50].
- **Two date sources for the same CVEs.** NVD gives CVE-1999-0018 a published date of 5 December 1997, CVE-1999-0874 16 June 1999 and CVE-1999-1011 19 July 1999; CVE Services shows 29 September 1999, 2 June 2000 and 2 June 2000 [10][7].
- **Moonlight Maze dates and grades.** The whitepaper dates the first press to 4 March and relays the investigation timeline; the blog says "early March" and dates the logs to 1998 to 1999 [37][36].
- **The Cox report date.** govinfo's issue date is 2 January 1999; the declassified public release later in the year was not checked [48].

## Sources

All sources were opened on 12 or 13 November 2026 as listed. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the gao.gov, ftc.gov and sec.gov pages); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "1999 CERT Advisories" (compilation, CA-1999-01 to CA-1999-17) | https://www.sei.cmu.edu/documents/506/1999_019_001_496184.pdf | 2026-11-12 | Confirmed |
| 2 | CMU SEI, "1999 CERT Incident Notes" (compilation, IN-99-01 to IN-99-08) | https://www.sei.cmu.edu/documents/520/1999_019_001_496442.pdf | 2026-11-12 | Confirmed |
| 3 | CMU SEI, 1999 CERT advisories index | https://www.sei.cmu.edu/library/1999-cert-advisories/ | 2026-11-12 | Confirmed |
| 4 | CVE Program, History page source (cve-website repository) | https://github.com/CVEProject/cve-website/blob/dev/src/views/About/History.vue | 2026-11-12 | Confirmed |
| 5 | CVE Program, History page (rendered by JavaScript; text read from source 4) | https://www.cve.org/About/History | 2026-11-12 | Confirmed |
| 6 | Mann and Christey, "Towards a Common Enumeration of Vulnerabilities", 8 January 1999 | https://www.cve.org/Resources/General/Towards-a-Common-Enumeration-of-Vulnerabilities.pdf | 2026-11-12 | Confirmed |
| 7 | CVE Services API, CVE-1999-1011 (with CVE-1999-0018, -0668, -0696, -0704, -0833, -0834, -0874, -0878 and -0977 dates) | https://cveawg.mitre.org/api/cve/CVE-1999-1011 | 2026-11-12 | Confirmed |
| 8 | CVE Services API, CVE-1999-0977 | https://cveawg.mitre.org/api/cve/CVE-1999-0977 | 2026-11-12 | Confirmed |
| 9 | CVE Services API, CVE-1999-0668 | https://cveawg.mitre.org/api/cve/CVE-1999-0668 | 2026-11-12 | Confirmed |
| 10 | NVD API, CVE-1999-0018 (with CVE-1999-0874 and CVE-1999-1011: published dates and CWE) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-1999-0018 | 2026-11-13 | Demonstrated |
| 11 | Microsoft Security Bulletin MS99-001 (with MS99-061, the MS99-062 probe and MS00-001) | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1999/ms99-001 | 2026-11-12 | Confirmed; Inferred (count) |
| 12 | Microsoft Security Bulletin MS99-002 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1999/ms99-002 | 2026-11-12 | Confirmed |
| 13 | Microsoft Security Bulletin MS99-019 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1999/ms99-019 | 2026-11-12 | Confirmed |
| 14 | Microsoft Security Bulletin MS99-025 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1999/ms99-025 | 2026-11-12 | Confirmed |
| 15 | Microsoft Security Bulletin MS99-032 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/1999/ms99-032 | 2026-11-12 | Confirmed |
| 16 | Cult of the Dead Cow, joint statement, 7 January 1999 | https://cultdeadcow.com/news/statement19990107.html | 2026-11-12 | Confirmed (the signatories' own statement) |
| 17 | Cult of the Dead Cow, Back Orifice 2000 press release | https://cultdeadcow.com/news/bo2k_pressrelease.html | 2026-11-12 | Confirmed (the author's own statements) |
| 18 | US Department of Justice, FY2000 budget release, 1 February 1999 | https://www.justice.gov/archive/opa/pr/1999/February/040ag.htm | 2026-11-12 | Confirmed |
| 19 | DOJ CCIPS, Eric Burns (UNT End of Term archive of cybercrime.gov) | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/burns.htm | 2026-11-12 | Confirmed |
| 20 | DOJ CCIPS, Andrew Miffleton | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/miffle.htm | 2026-11-12 | Confirmed |
| 21 | DOJ CCIPS, Kevin Mitnick | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/mitnick.htm | 2026-11-12 | Confirmed |
| 22 | DOJ CCIPS, Melissa plea | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/melissa.htm | 2026-11-12 | Confirmed |
| 23 | DOJ CCIPS, Chad Davis | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/davis.htm | 2026-11-12 | Confirmed |
| 24 | DOJ CCIPS, Patrick Gregory sentencing | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/gregorysen.htm | 2026-11-12 | Confirmed |
| 25 | DOJ CCIPS, Phone Masters | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/phonmast.htm | 2026-11-12 | Confirmed |
| 26 | DOJ CCIPS, "c0mrade" | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/comrade.htm | 2026-11-12 | Confirmed |
| 27 | DOJ CCIPS, Alibris | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/alibris.htm | 2026-11-12 | Confirmed |
| 28 | DOJ CCIPS, computer crime case index | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/cccases.html | 2026-11-12 | Confirmed |
| 29 | US Department of Justice, first No Electronic Theft Act conviction, 20 August 1999 | https://www.justice.gov/archive/opa/pr/1999/August/371crm.htm | 2026-11-12 | Confirmed |
| 30 | US Department of Justice, cyberstalking report release, 16 September 1999 | https://www.justice.gov/archive/opa/pr/1999/September/421ag.htm | 2026-11-12 | Confirmed |
| 31 | US Department of Justice, Melissa sentencing, 1 May 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/melissaSent.htm | 2026-11-12 | Confirmed |
| 32 | Working Group on Unlawful Conduct Involving the Use of the Internet, "The Electronic Frontier", 9 March 2000 | https://webarchive.library.unt.edu/eot2008/20080916073642mp_/http://www.cybercrime.gov/unlawful.htm | 2026-11-12 | Confirmed |
| 33 | GAO, T-AIMD-99-146 (product page) | `https://www.gao.gov/products/t-aimd-99-146` | 2026-11-12 | Confirmed |
| 34 | GAO, T-AIMD-99-146 (testimony PDF) | `https://www.gao.gov/assets/t-aimd-99-146.pdf` | 2026-11-12 | Confirmed |
| 35 | FBI, "The Melissa Virus" (20th anniversary story), 25 March 2019 | https://www.fbi.gov/news/stories/melissa-virus-20th-anniversary-032519 | 2026-11-12 | Confirmed |
| 36 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze", Securelist, 3 April 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Confirmed (technical findings); Reported (victims, attribution) |
| 37 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze" (whitepaper PDF) | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf | 2026-11-12 | Confirmed (log analysis); Reported (investigation timeline, victims, attribution) |
| 38 | James Adams (iDEFENSE), testimony to Senate Governmental Affairs, 2 March 2000 (FAS copy) | https://irp.fas.org/congress/2000_hr/030200_adams.htm | 2026-11-12 | Reported |
| 39 | Deputy Secretary of Defense Hamre, testimony to House Armed Services, 23 February 1999 (FAS copy) | https://irp.fas.org/congress/1999_hr/99-02-23hamre.htm | 2026-11-12 | Confirmed |
| 40 | NIPC Director Vatis, statement to Senate Judiciary subcommittee, 6 October 1999 (FAS copy) | https://irp.fas.org/congress/1999_hr/nipc10-6.htm | 2026-11-12 | Confirmed |
| 41 | NIPC Director Vatis, testimony to Senate Armed Services Emerging Threats subcommittee, 16 March 1999 (FAS copy) | https://irp.fas.org/congress/1999_hr/990316-sasctest.htm | 2026-11-12 | Confirmed |
| 42 | Benincasa, ETH Zurich Center for Security Studies, Cyberdefense Report 'The Red Hackers Who Shaped China's Cyber Ecosystem', July 2025 | https://ethz.ch/content/dam/ethz/special-interest/gess/cis/center-for-securities-studies/pdfs/before-vegas-cyberdefense-report.pdf | 2026-11-12 | Reported |
| 43 | Kaspersky, "Equation: The Death Star of Malware Galaxy", Securelist | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-12 | Confirmed (Kaspersky's statement of what it does not know) |
| 44 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 45 | MITRE ATT&CK, Penquin (S0587) | https://attack.mitre.org/software/S0587/ | 2026-11-12 | Confirmed |
| 46 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 47 | MITRE ATT&CK, campaigns list | https://attack.mitre.org/campaigns/ | 2026-11-12 | Confirmed |
| 48 | Cox Committee report, H. Rpt. 105-851, chapter 1 (govinfo) | https://www.govinfo.gov/content/pkg/GPO-CRPT-105hrpt851/html/ch1bod.html | 2026-11-12 | Confirmed |
| 49 | Wired, Hotmail hackers story, 30 August 1999 | https://www.wired.com/1999/08/hotmail-hackers-we-did-it/ | 2026-11-12 | Reported |
| 50 | CNN, Hotmail security hole, 30 August 1999 | https://www.cnn.com/TECH/computing/9908/30/hotmail.hack/ | 2026-11-12 | Reported |
| 51 | CNN, government web pages hacked, 10 May 1999 | https://www.cnn.com/TECH/computing/9905/10/hack.attack/ | 2026-11-12 | Reported |
| 52 | CNN and Federal Computer Week, NIPRNET overhaul, 4 May 1999 | https://www.cnn.com/TECH/computing/9905/04/overhaul.idg/ | 2026-11-12 | Reported |
| 53 | NTSB, Pipeline Accident Report PAR-02/02 (Bellingham, 10 June 1999) | https://www.ntsb.gov/investigations/AccidentReports/Reports/PAR0202.pdf | 2026-11-12 | Confirmed |
| 54 | Pub. L. 106-102, Gramm-Leach-Bliley Act (text) | https://www.govinfo.gov/content/pkg/PLAW-106publ102/html/PLAW-106publ102.htm | 2026-11-12 | Confirmed |
| 55 | Pub. L. 106-102 (govinfo details page) | https://www.govinfo.gov/app/details/PLAW-106publ102 | 2026-11-12 | Confirmed |
| 56 | FTC, Gramm-Leach-Bliley Act business guidance | `https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act` | 2026-11-12 | Confirmed |
| 57 | Executive Order 13133, 64 FR 43895, 11 August 1999 | https://www.govinfo.gov/content/pkg/FR-1999-08-11/pdf/99-20924.pdf | 2026-11-12 | Confirmed |
| 58 | FTC, final COPPA Rule release, 20 October 1999 | `https://www.ftc.gov/news-events/news/press-releases/1999/10/new-rule-will-protect-privacy-children-online` | 2026-11-12 | Confirmed |
| 59 | HHS, proposed rule, Standards for Privacy of Individually Identifiable Health Information, 64 FR 59918 | https://www.govinfo.gov/content/pkg/FR-1999-11-03/pdf/99-28440.pdf | 2026-11-12 | Confirmed |
| 60 | Pub. L. 106-37, Y2K Act | https://www.govinfo.gov/content/pkg/PLAW-106publ37/html/PLAW-106publ37.htm | 2026-11-12 | Confirmed |
| 61 | S. Rpt. 106-10, Year 2000 (Y2K) Act | https://www.govinfo.gov/content/pkg/CRPT-106srpt10/pdf/CRPT-106srpt10.pdf | 2026-11-12 | Confirmed |
| 62 | BXA interim final rule, Encryption Items, 65 FR 2492, 14 January 2000 | https://www.govinfo.gov/content/pkg/FR-2000-01-14/pdf/00-983.pdf | 2026-11-12 | Confirmed |
| 63 | EFF, DES Challenge III press release, 19 January 1999 | https://w2.eff.org/Privacy/Crypto/Crypto_misc/DESCracker/HTML/19990119_deschallenge3.html | 2026-11-12 | Confirmed (EFF's account of its own result) |
| 64 | distributed.net, DES project page | https://www.distributed.net/DES | 2026-11-12 | Confirmed |
| 65 | NIST, FIPS 46-3 | https://csrc.nist.gov/pubs/fips/46-3/final | 2026-11-12 | Confirmed |
| 66 | NIST CSRC, AES development (archived project) | https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/archived-crypto-projects/aes-development | 2026-11-12 | Confirmed |
| 67 | RFC 2246, The TLS Protocol Version 1.0 | https://www.rfc-editor.org/rfc/rfc2246 | 2026-11-12 | Confirmed |
| 68 | RFC 2459, Internet X.509 PKI Certificate and CRL Profile | https://www.rfc-editor.org/rfc/rfc2459.txt | 2026-11-12 | Confirmed |
| 69 | RFC 2267, Network Ingress Filtering | https://www.rfc-editor.org/rfc/rfc2267.txt | 2026-11-12 | Confirmed |
| 70 | ISO, ISO/IEC 15408-1:1999 | https://www.iso.org/standard/27632.html | 2026-11-12 | Confirmed |
| 71 | OpenSSH, project history | https://www.openssh.com/history.html | 2026-11-12 | Confirmed |
| 72 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 73 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 74 | MITRE ATT&CK, FAQ | https://attack.mitre.org/resources/faq/ | 2026-11-12 | Confirmed |
| 75 | MITRE ATT&CK, T1685 Disable or Modify Tools (with T1137.001 and T1498.002) | https://attack.mitre.org/techniques/T1685/ | 2026-11-12 | Confirmed |
| 76 | SEC Litigation Release LR-16117, SEC v. Hoke, 21 April 1999 | `https://www.sec.gov/litigation/litreleases/lr16117.txt` | 2026-11-12 | Confirmed |
| 77 | SEC Litigation Release LR-16266, 30 August 1999 | `https://www.sec.gov/litigation/litreleases/lr16266.htm` | 2026-11-12 | Confirmed |
| 78 | SEC EDGAR, eUniverse filing on the CD Universe incident | `https://www.sec.gov/Archives/edgar/data/1088244/0000950117-00-000306.txt` | 2026-11-12 | Confirmed |
| 79 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` (with the `mitre/techniques/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_profiles.jsonl | 2026-11-13 | Demonstrated |
| 80 | TeamStarWolf library, `data/attack/software.jsonl` (with `groups.jsonl` and `campaigns.jsonl`) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software.jsonl | 2026-11-13 | Confirmed (the library's record); Demonstrated (search) |
| 81 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` (with the `mitre/d3fend/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_to_d3fend.jsonl | 2026-11-13 | Demonstrated |
| 82 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/cwe.jsonl | 2026-11-13 | Demonstrated |
| 83 | TeamStarWolf library, `data/weaknesses/capec.jsonl` (with the `mitre/capec/` page tree) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/capec.jsonl | 2026-11-13 | Demonstrated |
| 84 | TeamStarWolf library, `data/attack/superseded_by.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/superseded_by.jsonl | 2026-11-13 | Demonstrated |
| 85 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-13 | Confirmed (the library's record) |
| 86 | TeamStarWolf library, main branch, `navigator/library-layers/` (the folder where this study's layer is saved; not evidence) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/navigator/library-layers | 2026-11-13 | Demonstrated (location) |
| 87 | TeamStarWolf library, `data/attack/ics/technique_profiles.jsonl` (T0822) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/ics/technique_profiles.jsonl | 2026-11-13 | Demonstrated |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md)
- Home studies: [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md); [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [The Cybercrime Books](/case-studies/CYBERCRIME_FOUR_BOOKS.md); [Before the Internet](/case-studies/PRE_INTERNET_THREATS.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [Cl0p file transfer campaigns](/case-studies/CL0P_FILE_TRANSFER_2023.md); [Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1195.002 Compromise Software Supply Chain](/mitre/techniques/T1195-002.md), [T1205 Traffic Signaling](/mitre/techniques/T1205.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1059.005 Visual Basic](/mitre/techniques/T1059-005.md), [T1137.001 Office Template Macros](/mitre/techniques/T1137-001.md), [T1685 Disable or Modify Tools](/mitre/techniques/T1685.md), [T1112 Modify Registry](/mitre/techniques/T1112.md), [T1547.001 Registry Run Keys / Startup Folder](/mitre/techniques/T1547-001.md), [T1036.005 Match Legitimate Resource Name or Location](/mitre/techniques/T1036-005.md), [T1135 Network Share Discovery](/mitre/techniques/T1135.md), [T1080 Taint Shared Content](/mitre/techniques/T1080.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1561.001 Disk Content Wipe](/mitre/techniques/T1561-001.md), [T1495 Firmware Corruption](/mitre/techniques/T1495.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1595.002 Vulnerability Scanning](/mitre/techniques/T1595-002.md), [T1040 Network Sniffing](/mitre/techniques/T1040.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1491.002 External Defacement](/mitre/techniques/T1491-002.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1498.002 Reflection Amplification](/mitre/techniques/T1498-002.md), [T1499.004 Application or System Exploitation](/mitre/techniques/T1499-004.md), [T1584.005 Botnet](/mitre/techniques/T1584-005.md), [T1219 Remote Access Tools](/mitre/techniques/T1219.md), [T1090.003 Multi-hop Proxy](/mitre/techniques/T1090-003.md), [T1584.004 Server](/mitre/techniques/T1584-004.md), [T1095 Non-Application Layer Protocol](/mitre/techniques/T1095.md), [T1560 Archive Collected Data](/mitre/techniques/T1560.md), [T1048 Exfiltration Over Alternative Protocol](/mitre/techniques/T1048.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1114 Email Collection](/mitre/techniques/T1114.md), [T1684.001 Impersonation](/mitre/techniques/T1684-001.md), [T1657 Financial Theft](/mitre/techniques/T1657.md)
- CAPEC: [CAPEC-20](/mitre/capec/CAPEC-20.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-158](/mitre/capec/CAPEC-158.md), [CAPEC-163](/mitre/capec/CAPEC-163.md), [CAPEC-169](/mitre/capec/CAPEC-169.md), [CAPEC-186](/mitre/capec/CAPEC-186.md), [CAPEC-490](/mitre/capec/CAPEC-490.md), [CAPEC-523](/mitre/capec/CAPEC-523.md), [CAPEC-562](/mitre/capec/CAPEC-562.md)
- Groups, software and campaigns: none bound for 1999 (Part 11); Turla [G0010](/mitre/groups/G0010.md) and Penquin [S0587](/mitre/software/S0587.md) for the proposed and unproven Moonlight Maze lineage; Equation [G0020](/mitre/groups/G0020.md), not placed in 1999
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-1999.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-1999.json)
