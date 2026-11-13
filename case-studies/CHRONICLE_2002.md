# The Year 2002 in Intrusions: A Dated Record

*A TeamStarWolf case study. Published 13 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md) · Home studies for events summarized here: [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) (Trustworthy Computing, Klez, the Melissa sentence, the FTC Safeguards Rule, MS02-039 and Slammer, California SB 1386, the Gorshkov sentence, the Homeland Security Act, NIST SP 800-51, Moonlight Maze), [The Mitnick intrusions](/case-studies/MITNICK_INTRUSIONS.md) (the New York Times intrusion), [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md), [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md) and [the NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md) (Equation), [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md) (Turla), [The Year 2000 in Intrusions](/case-studies/CHRONICLE_2000.md) (the Maroochy Shire attack) · Series: [The Year 1999 in Intrusions](/case-studies/CHRONICLE_1999.md), [The Year 2000 in Intrusions](/case-studies/CHRONICLE_2000.md), [The Year 2016 in Intrusions](/case-studies/CHRONICLE_2016.md) and the other years in the [case studies index](/case-studies/README.md)

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, security historians, supply-chain defenders and anyone who wants the history behind current threats

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Beginner to intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 65 min (14,957 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You want a dated record of the intrusions of 2002, you need the year's CERT advisories, the trojaned OpenSSH, Sendmail and tcpdump distributions and the worms that followed the fixes side by side with the root server flood, the year's prosecutions and the new security law, or you want the defender lessons that still apply

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Executive summary](#executive-summary), [Part 3: the trojaned distributions](#part-3-the-trojaned-distributions), [Part 10: the defender view](#part-10-the-defender-view)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Notable Incidents](/NOTABLE_INCIDENTS.md), [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [The Year 2000 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2000.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Executive summary

Anyone who built software from source in 2002 learned to check a signature. Between the end of July and the middle of November, intruders replaced the official source tarballs of three tools that system administrators install everywhere: OpenSSH (30 or 31 July), Sendmail 8.12.6 (from about 28 September) and tcpdump with libpcap (11 to 13 November) (Confirmed [1][23]). Each trojan ran when the code was compiled, not when it was installed, and each called out to a fixed remote host (Confirmed [1]). CERT/CC's advice was the same every time: timestamps and file sizes prove nothing, so verify the MD5 checksum and the PGP signature (Confirmed [1][23]). Those three advisories are the year's clearest early record of a software supply-chain attack on open source, two decades before the [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md) and [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md) studies (Inferred).

The rest of the year's record is broad. CERT/CC published 37 advisories, CA-2002-01 on 14 January to CA-2002-37 on 19 December, and its incident notes covered mass mailers, a database worm and social engineering over chat (Confirmed [1][2][3][4]). The year opened with confirmed exploitation of a Solaris CDE flaw seen in Honeynet Project traces (14 January) and the PROTOS test suite's sweep of SNMPv1 implementations across many vendors (12 February) (Confirmed [1]). In September the Slapper worm hit Linux web servers running Apache with mod_ssl through an OpenSSL flaw fixed about six weeks earlier, and built a peer-to-peer network that could be used for denial of service (Confirmed [1][22][28]; the interval is Inferred). On 21 October every one of the thirteen DNS root name servers was flooded at once for about an hour and a quarter; the operators knew of no errors visible to end users (Confirmed [45]).

The crime record has one large insider case and several well-known intrusions. A former help-desk employee at a credit-reporting software firm was charged in November with feeding a ring that pulled credit reports on more than 30,000 people, which prosecutors called the largest identity theft case in US history (Confirmed [42]; the superlative is the prosecutor's framing). Adrian Lamo got into the New York Times internal network in February, and Gary McKinnon was indicted in November over intrusions into 92 US military and NASA computers between March 2001 and March 2002 (Confirmed [35][40]). The Melissa author and the Russian intruder Vasiliy Gorshkov were sentenced (Confirmed [37][38]).

The law moved a long way in one year. The FTC brought security orders against Eli Lilly (January) and Microsoft's Passport (August) and published its Safeguards Rule (May). California passed a breach-notification law in September. Sarbanes-Oxley (July), the Homeland Security Act (November), the Cyber Security Research and Development Act (November) and the E-Government Act (December) all became law; the Federal Information Security Management Act was enacted twice, once in the Homeland Security Act and again in the E-Government Act (Confirmed [46][47][48][49][50][52][54][55]). NIST published its risk, patching, contingency, web, mail and wireless guides, plus SHA-256 and HMAC (Confirmed [58] to [68]).

The state record of 2002 is mostly invisible. Kaspersky said in 2015 that some of the earliest Equation group samples it had seen were compiled in 2002, and names no country behind the group (Confirmed [76]). The Moonlight Maze operators' later toolkit and the early Penquin Turla code fall in this period only by the researchers' circumstantial reading (Reported [77]). The best-documented intrusion into state networks that touches 2002, McKinnon's, is an individual case: the indictment release alleges no foreign government involvement (Confirmed [40]).

2002 has CVE ids, still issued in the candidate form CAN-2002-xxxx that the advisories cite (Confirmed [1][17][22]). The first CWE List came in 2006, CAPEC in 2007 and ATT&CK in 2013, so no record of the year carries a CWE, CAPEC or ATT&CK id from the time (Confirmed [81][82][83]). The CWE ids NVD now lists for 2002 CVEs were assigned later, and every ATT&CK Enterprise, CAPEC and D3FEND id in Part 11 is this study's later mapping (Inferred). The exceptions are the four techniques ATT&CK records for Equation, which ATT&CK does not date, and the ATT&CK for ICS techniques of the Maroochy campaign, whose appeal was decided in 2002 (Confirmed [78][73]).

This study is the dated record of the year, built only from sources opened on 12 and 13 November 2026 and checked as of 13 November 2026. Ten parts cover the timeline, the vulnerability record, the trojaned distributions, the worms, the infrastructure, the state record, crime and prosecutions, law and standards, the industrial record and the defender view. An eleventh part maps the record to MITRE frameworks.

### Key facts at a glance

| Field | Value |
|---|---|
| Period | 1 January to 31 December 2002, plus the boundary records that open or close a 2002 event: Klez's first infections (26 Oct 2001), the CVE-2001-0803 record (6 Dec 2001), McKinnon's alleged intrusions from March 2001, the Ivanov sentence and the Lamo charge (2003), the Lamo plea (2004) and Kaspersky's 2015 Equation reports |
| CERT/CC output | 37 advisories, CA-2002-01 (14 Jan) to CA-2002-37 (19 Dec); incident notes IN-2002-01 (28 Jan) to IN-2002-05 (17 Jul) readable, IN-2002-06 not recoverable from the compilation (Confirmed [1][2][3][4]; Demonstrated [4]) |
| Trojaned source distributions | OpenSSH 3.4p1, 3.4 and 3.2.2p1 (30 or 31 Jul to 1 Aug; CA-2002-24); Sendmail 8.12.6 (about 28 Sep to 6 Oct; CA-2002-28); tcpdump 3.6.2 and 3.7.1 and libpcap 0.7.1 (11 to 13 Nov; CA-2002-30) (Confirmed [1][23]) |
| Exploited in the wild, per CERT | CDE dtspcd on Solaris (14 Jan); null or weak sa passwords on SQL Server and MSDE by Spida (22 May); OpenSSL in Apache/mod_ssl by Slapper (14 Sep); Kerberos kadmind (25 Oct) (Confirmed [1][4]) |
| Worms and mass mailers | Klez.E (17 Jan); Myparty (28 Jan); Gibe (12 Mar); Klez.H (17 Apr); Spida (22 May); Scalper (June); Frethem (17 Jul); Slapper (13 to 14 Sep); Bugbear (30 Sep); Opaserv (end of Sep) (Confirmed [4][27][28][29][30][31]; Reported [26][28] for Klez.E and Scalper's month) |
| Infrastructure | SNMPv1 across many vendors (12 Feb); BIND 9 (4 Jun), resolver libraries (28 Jun), BIND 4 and 8 (14 Nov); the Alcatel OmniSwitch back door (21 Nov); SSH implementations (16 Dec); the root name server flood (21 Oct) (Confirmed [1][45]) |
| Microsoft | MS02-001 (30 Jan) to MS02-072 (18 Dec), released on irregular dates; MS02-039 (24 Jul) later protected against Slammer; CVE-2002-0367 (MS02-024) is the only 2002 CVE in CISA's KEV catalog (Confirmed [15][17][18][14][101]; the series count is Inferred) |
| State record | Earliest Equation samples compiled in 2002, per Kaspersky (2015); Moonlight Maze successor toolkit and early Penquin Turla code (Reported); Titan Rain is a 2003 event, not 2002 (Confirmed [76]; Reported [77][80]) |
| Prosecutions | Lamo intrusion (26 Feb); Smith sentenced for Melissa (1 May); Gorshkov sentenced (4 Oct); McKinnon indicted (12 Nov, 18 Nov); Cummings arrested (25 Nov); Jiang arrested (20 Dec) (Confirmed [35][37][38][40][41][42][44]) |
| Law and regulation | FTC Eli Lilly (18 Jan); FTC Safeguards Rule (23 May); SOX (30 Jul); FTC Passport (8 Aug); SB 1386 (25 Sep); Homeland Security Act (25 Nov); Cyber Security R&D Act (27 Nov); E-Government Act with FISMA (17 Dec) (Confirmed [46][48][50][47][49][52][54][55]) |
| Standards | FIPS 198 HMAC (6 Mar); RFC 3280 (Apr); SP 800-34 (13 Jun); RFC 3268 (Jun); SP 800-30 (Jul); FIPS 180-2, SP 800-40, 800-46 and 800-47 (Aug); SP 800-51, 800-45 and 800-44 (Sep); SP 800-48 (Nov) (Confirmed [60] to [71]) |
| Industrial | R v Boden appeal decided (10 May) for the 2000 Maroochy sewerage intrusion; ATT&CK for ICS campaign C0020 (Confirmed [72][73]) |
| This study's MITRE binding | 27 ATT&CK Enterprise technique rows, every one a later mapping; Equation (G0020) bound with its 2015 dating caveat; 12 ATT&CK for ICS techniques that ATT&CK lists for C0020; no software or campaign object for a 2002 operation; NVD's CWE ids plus four study classes (CWE-494, CWE-506, CWE-1393, CWE-912); 11 CAPEC entries; D3FEND pairings from the library's data; one Enterprise Navigator layer (Part 11) |

### Key findings

- **The supply chain was attacked at the source.** Three widely used open-source distributions were trojaned on their official download servers within about four months, each with code that ran at build time (Confirmed [1][23]). The year's defender lesson was integrity checking, not patching (Inferred).
- **The fix again came before the worm.** OpenSSL fixed the SSLv2 flaw on 30 July; Slapper was found on 13 September and CERT reported thousands of infected hosts the next day (Confirmed [22][28][1]). Apache disclosed the chunked-encoding flaw on 17 June and shipped the 1.3.26 fix on 18 June; F-Secure says Scalper was found the same month (Confirmed [20][21]; Reported [28]). MS02-039, published on 24 July, already protected against the Slammer worm of January 2003 (Confirmed [17]).
- **Safe defaults held where patches had not yet arrived.** OpenSSH 3.3 turned privilege separation on by default on 21 June, five days before the challenge-response advisory, and it blocked that flaw's privilege escalation though not the remote exploitation (Confirmed [24][25]). MS02-039 named running SQL Server as a domain user, the default, as a mitigation (Confirmed [17]).
- **Weak passwords were still a worm's front door.** Spida spread through null or weak sa passwords on SQL Server, and Opaserv through a Windows 9x share-password flaw Microsoft had fixed two years earlier (Confirmed [4][31][19]).
- **The internet's core held.** The 21 October flood hit all thirteen root servers at about 900 Mbit/s in aggregate; the operators knew of no end-user visible errors and credited overprovisioning (Confirmed [45]). The government's later account says the attacks degraded or disrupted some root servers (Confirmed [57]).
- **The year's largest charged identity-theft case used valid credentials, not an exploit.** The Cummings scheme used client passwords and subscriber codes, not an exploit, and was found through Experian bills and consumer complaints (Confirmed [42]).
- **Federal security became program management.** FISMA required annual testing, annual reports and an annual independent evaluation, and NIST's guides of 2002 on risk, patching and contingency planning gave agencies the method (Confirmed [55][58][63][61]).
- **The state record is a visibility gap.** No ATT&CK group, software or campaign object is tied to a dated 2002 operation, and Equation's 2002 date comes from a vendor reconstruction published in 2015 (Confirmed [76][78]; Inferred [95]).

### Top recommendations

1. **Verify what you build.** CERT's advice for all three trojaned distributions was to check MD5 checksums and PGP signatures, and it warned that timestamps and sizes are not enough (Confirmed [1][23]). Pin and verify the signatures of source and binary dependencies, and treat anything built during a known compromise window as compromised, as the OpenSSH project advised (Confirmed [23]).
2. **Watch build hosts' outbound traffic.** Every 2002 trojan called out to a fixed host from the machine that compiled it (Confirmed [1]). Build systems rarely need outbound connections beyond their package mirrors (Inferred).
3. **Measure the gap between fix and worm.** About six weeks separated the OpenSSL fix from Slapper (Confirmed [22][28]; Inferred for the interval). Track time to patch for internet-facing services against that gap.
4. **Turn on the safe default before the advisory.** Privilege separation, on by default in OpenSSH 3.3 five days before the challenge-response advisory, blocked that flaw's privilege escalation, and MS02-039 named the default domain-user service account as a mitigation (Confirmed [24][25][17]); that safe defaults bought time before patches is this study's reading (Inferred).
5. **Remove default and blank passwords.** Spida needed nothing more than a null or weak sa password (Confirmed [4]).
6. **Filter by port and by role.** MS02-039 advised blocking UDP 1434 at the firewall, and Slapper's peer network ran over UDP 2002, 1978 and 4156 (Confirmed [17][1]).
7. **Plan for capacity under flood.** The root operators credited host and network overprovisioning and answered with more peering and transit, wide-area mirroring and faster upgrades (Confirmed [45]).
8. **Treat network devices as software.** The SNMP, BIND and SSH advisories and a switch that shipped with a development telnet server still listening sit beside the Windows story (Confirmed [1][3]).

## Scope and method

This study covers intrusions, vulnerabilities, malware, prosecutions, regulation, cryptography, standards and policy dated to 2002, plus the later records that open, close or explain a 2002 event. It follows the method of the [case studies collection](/case-studies/README.md): primary sources first, every claim graded, numbers as the source states them. Sources were opened on 12 November 2026; some were opened again, and the library's data files checked again, on 13 November 2026.

| Grade | Meaning in this study |
|---|---|
| Confirmed | The primary record was opened and states the fact: a CERT/CC advisory or incident note as SEI publishes it, a vendor bulletin, advisory, release note or vendor research report, a CVE, NVD or KEV record, the root server operators' own report, a statute, a Federal Register notice, a court judgment, a Justice Department or FTC release, a government strategy, a NIST, RFC Editor or Council of Europe record, a live ATT&CK page, or the library's data files as the record of what the library holds |
| Reported | Only a secondary source supports the fact, or the source gives its own assessment without the evidence: Wired's reprint of the Trustworthy Computing email, TIME on Titan Rain, Kaspersky and King's College London on Storm Cloud and the Turla lineage, Kaspersky's own reading of how far back Equation goes, and the F-Secure dates noted below. The source is named in the text |
| Demonstrated | A check this study ran itself and saw the result: the defect in the incident-note compilation, the date mismatch in the Intelligence Hub's history rows, and id, name, tactic and page checks in the library's data files and `mitre/` page tree |
| Inferred | The study's own reasoning, labelled where it appears. Every ATT&CK Enterprise, CAPEC and D3FEND id bound to a 2002 event is Inferred as to the binding, and so is every CWE that NVD does not list |

F-Secure's virus descriptions are a vendor record and most of what they say is graded Confirmed. Klez.E's first-found date, the June date for Scalper, and Slapper's peak network size and variant dates stay Reported, because they rest on F-Secure's page alone and were graded that way when checked [26][28].

Limits a reader should know:

- **No contemporaneous ATT&CK, CWE or CAPEC.** MITRE began categorizing weaknesses with the CVE List in 1999, built PLOVER in 2005 under NIST SAMATE and first released the CWE List in 2006; CAPEC was established by DHS and first released in 2007; ATT&CK started in 2013 (Confirmed [81][82][83]).
- **The CERT text.** SEI's compilations of the 2002 CERT advisories and incident notes are the texts for every CA-2002 and IN-2002 item cited here [1][4], with SEI's indexes for the counts [2][3][5]. The advisories print worm request patterns, file names and log lines; none is reproduced here.
- **A defect in the incident-note compilation.** The IN-2002-06 (W32/Lioten) section of SEI's compilation carries the 2001 W32/Goner text and a December 2001 release date, so IN-2002-06 cannot be cited from it and this study says nothing about Lioten (Demonstrated [4]).
- **The Intelligence Hub as a map only.** The Hub's CERT/CC advisory history rows for 2002 carry the date of the cited vulnerability note, not the advisory's release date: the Hub dates CA-2002-03 to 16 January, while the advisory says 12 February. Every advisory date here comes from SEI's compilation (Demonstrated [86][1]).
- **The 37 advisories are a curated set.** They are the cases CERT chose to publish, weighted to widely deployed software, not a census of the year's intrusions (Inferred).
- **What was not checked.** No primary was opened for: the TriWest Healthcare Alliance burglary (December); the "Deceptive Duo" defacements (April); a 2002 Kavkaz Center denial-of-service attack; press reports on al-Qaeda interest in SCADA systems; the USSTRATCOM merger; NIPC's 2002 advisories; the EU ePrivacy Directive's adoption date; the New York Attorney General's Ziff Davis settlement; Wi-Fi Protected Access; Windows XP Service Pack 1, MBSA and SUS; BS 7799-2:2002; the SANS and FBI Top 20 for 2002; Snort's 2002 releases; GAO's 2002 reports; the FCC record on Kevin Mitnick's amateur licence; and who found the CA-2002-36 flaws beyond the test suite the advisory names. They are left out. Their absence here is not evidence that nothing happened.

## Part 1: the year as a dated timeline

One row per event or report. The date is the event date where the source gives one, otherwise the publication date.

| Date | Event | Thread | Sector | Grade | Sources |
|---|---|---|---|---|---|
| 1996 to 2001 (frame) | Kaspersky: Equation's computer network exploitation operations date back to 2001 and perhaps to 1996; one C&C domain registered in August 2001 | Espionage | Unknown | Reported; Confirmed (the domain date) | [75][76] |
| 1999 to 2004 (frame) | Kaspersky and King's College London: after the 1999 publicity the Moonlight Maze operators used an evolved toolkit the US called Storm Cloud; the Penquin Turla codebase was mainly developed from 1999 to 2004 | Espionage | Government | Reported | [77] |
| 2000 (early) to 2002 | The Cummings scheme: client passwords and subscriber codes used to download credit reports (charged 25 Nov 2002) | Insider | Financial services | Confirmed (allegation) | [42] |
| 2000-11-10 | Gorshkov and Ivanov arrested after the FBI's "Invita" undercover meeting. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime | Banking, payments | Confirmed | [38] |
| 2001-03 to 2002-03 | Gary McKinnon's alleged access to 92 US military and NASA computers and 6 private ones | Intrusion | Government, military | Confirmed (allegation) | [40] |
| 2001-10-26 | F-Secure: first Klez infections; Klez runs from a viewed message through the IE flaw MS01-020 (CVE-2001-0154). Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Worm | Email users | Confirmed | [26] |
| 2001-12-06 | NVD publishes CVE-2001-0803, the dtspcd overflow in libDtSvc (CWE-119) | Vulnerability | Unix hosts | Confirmed | [6] |
| 2002-01-14 | CA-2002-01: active exploitation of the CDE dtspcd overflow (first published as CA-2001-31), confirmed with Honeynet Project traces | Exploitation | Unix hosts | Confirmed | [1] |
| 2002-01-15 | Bill Gates's "Trustworthy computing" email to all Microsoft full-time employees (text published by Wired on 17 Jan). Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Industry | Technology | Reported | [33][94] |
| 2002-01 | Microsoft: Trustworthy Computing initiative launched | Industry | Technology | Confirmed | [34] |
| 2002-01-17 | F-Secure: Klez.E first discovered | Worm | Email users | Reported | [26] |
| 2002-01-18 | FTC announces its Eli Lilly settlement over a Prozac.com email that exposed all 669 subscribers' addresses | Regulation | Healthcare | Confirmed | [46] |
| 2002-01-28 | IN-2002-01: W32/Myparty, a mass mailer spread by social engineering; several dozen sites reporting by 16:00 EST | Worm | Cross-sector | Confirmed | [4] |
| 2002-01-30 | MS02-001, trusting domains do not verify SID domain membership; the first Microsoft bulletin of 2002 | Vulnerability | Cross-sector | Confirmed | [15] |
| 2002-02 | OMB's first report to Congress on government information security reform names six governmentwide gaps | Oversight | Government | Confirmed | [57] |
| 2002-02-11 | MS02-005, cumulative Internet Explorer patch for six vulnerabilities | Vulnerability | Cross-sector | Confirmed | [16] |
| 2002-02-12 | CA-2002-03: SNMPv1 flaws across many vendors, found with the PROTOS c06-snmpv1 suite (CVE-2002-0012, CVE-2002-0013) | Vulnerability | Network equipment | Confirmed | [1][8] |
| 2002-02-12 | California SB 1386 introduced | Regulation | Cross-sector | Confirmed | [49] |
| 2002-02-26 | Adrian Lamo gets into the New York Times internal network and its Op-Ed contributor database. Home: [the Mitnick intrusions study](/case-studies/MITNICK_INTRUSIONS.md) | Intrusion | Media | Confirmed | [35][36] |
| 2002-03-06 | FIPS 198, the Keyed-Hash Message Authentication Code (HMAC) | Cryptography | Standards | Confirmed | [60] |
| 2002-03-12 | IN-2002-02: W32/Gibe, a mail worm disguised as a Microsoft security bulletin and patch, installs a back door | Worm | Cross-sector | Confirmed | [4] |
| 2002-03-12 | CA-2002-07: double free in zlib (CVE-2002-0059, CWE-415) | Vulnerability | Cross-sector | Confirmed | [1][9] |
| 2002-03-14 | CA-2002-08: multiple vulnerabilities in Oracle servers | Vulnerability | Databases | Confirmed | [1] |
| 2002-03-19 | IN-2002-03: social engineering over IRC and instant messaging; tens of thousands of systems reported compromised | Botnet | Consumers | Confirmed | [4] |
| 2002-04 | RFC 3280, the Internet X.509 PKI certificate and CRL profile, obsoletes RFC 2459 | Standards | PKI | Confirmed | [70] |
| 2002-04-11 | CA-2002-09: multiple vulnerabilities in Microsoft IIS | Vulnerability | Web hosting | Confirmed | [1] |
| 2002-04-17 | F-Secure: Klez.H found in parts of Asia; global within a week | Worm | Email users | Confirmed | [27] |
| 2002-05-01 | David L. Smith sentenced to 20 months for the 1999 Melissa virus. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime | Cross-sector | Confirmed | [37] |
| 2002-05-08 | CA-2002-12: ISC DHCPD | Vulnerability | Network services | Confirmed | [1] |
| 2002-05-10 | Queensland Court of Appeal decides R v Boden, the Maroochy sewerage case. Home: [The Year 2000 in Intrusions](/case-studies/CHRONICLE_2000.md) | Industrial | Water | Confirmed | [72] |
| 2002-05-22 | IN-2002-04: the Spida (SQLsnake, Digispid) worm through null or weak sa passwords on SQL Server and MSDE | Worm | Databases | Confirmed | [4] |
| 2002-05-22 | MS02-024: Windows NT 4.0 and 2000 debugger authentication privilege escalation (CAN-2002-0367) | Vulnerability | Cross-sector | Confirmed | [14][101] |
| 2002-05-23 | FTC Safeguards Rule published (67 FR 36484), effective 23 May 2003. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Regulation | Financial services | Confirmed | [48] |
| 2002-05-27 | Apache chunked-encoding flaw reported to the project | Vulnerability | Web hosting | Confirmed | [21] |
| 2002-06 | F-Secure: the Scalper worm found | Worm | Web hosting | Reported | [28] |
| 2002-06 | RFC 3268, AES ciphersuites for TLS (the RFC Editor lists July) | Cryptography | Standards | Confirmed | [71] |
| 2002-06-04 | CA-2002-15: ISC BIND 9 denial of service | Vulnerability | Internet infrastructure | Confirmed | [1] |
| 2002-06-13 | NIST SP 800-34, Contingency Planning Guide for IT Systems | Standards | Government | Confirmed | [61] |
| 2002-06-17 | Apache bulletin and CA-2002-17: chunked-encoding flaw (CVE-2002-0392), released early after ISS published | Vulnerability | Web hosting | Confirmed | [20][1] |
| 2002-06-18 | Apache 1.3.26 fixes CVE-2002-0392 | Vulnerability | Web hosting | Confirmed | [21] |
| 2002-06-21 | OpenSSH 3.3 released with privilege separation on by default | Defense | Cross-sector | Confirmed | [24] |
| 2002-06-26 | OpenSSH challenge-response advisory and CA-2002-18 (CVE-2002-0639, CVE-2002-0640) | Vulnerability | Cross-sector | Confirmed | [25][1][10] |
| 2002-06-28 | CA-2002-19: buffer overflows in multiple DNS resolver libraries | Vulnerability | Internet infrastructure | Confirmed | [1] |
| 2002-07 | NIST SP 800-30, Risk Management Guide for IT Systems | Standards | Government | Confirmed | [58] |
| 2002-07 | DoD policy requires buying NIAP-evaluated products | Policy | Government | Confirmed | [57] |
| 2002-07-17 | IN-2002-05: W32/Frethem, a mass mailer that runs through unpatched IE rendering | Worm | Cross-sector | Confirmed | [4] |
| 2002-07-24 | MS02-039: SQL Server 2000 Resolution Service overruns (CAN-2002-0649, CAN-2002-0650). Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Vulnerability | Databases | Confirmed | [17] |
| 2002-07-29 | CA-2002-22: Microsoft SQL Server; eight bulletins since December 2001 | Vulnerability | Databases | Confirmed | [1] |
| 2002-07-30 | OpenSSL advisory and CA-2002-23: four overflows found in a DARPA CHATS-funded review (CAN-2002-0656 and others) | Vulnerability | Web hosting | Confirmed | [22][1] |
| 2002-07-30 | Sarbanes-Oxley Act approved (Pub. L. 107-204) | Law | Public companies | Confirmed | [50][51] |
| 2002-07-30 or 31 | OpenSSH 3.4p1, 3.4 and 3.2.2p1 tarballs on the OpenBSD FTP server trojaned | Supply chain | Open source | Confirmed | [23][1] |
| 2002-08-01 | Trojaned OpenSSH files replaced (13:00 UTC, 7 AM MDT); CA-2002-24 issued | Supply chain | Open source | Confirmed | [23][1] |
| 2002-08 | FIPS 180-2, Secure Hash Standard (SHA-1, SHA-256, SHA-384, SHA-512); NIST SP 800-40, 800-46 and 800-47 | Standards | Government | Confirmed | [62][63][64][65] |
| 2002-08-05 | CA-2002-25: integer overflow in the XDR library (CVE-2002-0391, CWE-190) | Vulnerability | Cross-sector | Confirmed | [1][12] |
| 2002-08-08 | FTC announces the Microsoft Passport consent order | Regulation | Technology | Confirmed | [47] |
| 2002-08-12 | NVD publishes CVE-2002-0656 (NVD-CWE-Other) | Vulnerability | Web hosting | Confirmed | [7] |
| 2002-09 | NIST SP 800-51 (use CVE) and SP 800-44 (public web servers) | Standards | Government | Confirmed | [59][67] |
| 2002-09 | Draft National Strategy to Secure Cyberspace posted for comment; ten town halls | Policy | Cross-sector | Confirmed | [57] |
| 2002-09-11 | NIST SP 800-45, Guidelines on Electronic Mail Security | Standards | Government | Confirmed | [66] |
| 2002-09-13 | F-Secure: Slapper found in Eastern Europe late on Friday | Worm | Web hosting | Confirmed | [28] |
| 2002-09-14 | CA-2002-27: the Apache/mod_ssl worm; thousands of systems, at least three variants | Worm | Web hosting | Confirmed | [1] |
| 2002-09-18 | Private-sector sector plans released with the draft strategy | Policy | Cross-sector | Confirmed | [57] |
| 2002-09-23 | F-Secure: the Cinik Slapper variant | Worm | Web hosting | Reported | [28] |
| 2002-09-25 | California SB 1386 approved by the Governor (filed 26 Sep; operative 1 Jul 2003). Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Regulation | Cross-sector | Confirmed | [49] |
| 2002-09-28 (about) | Trojaned Sendmail 8.12.6 tarballs begin appearing on ftp.sendmail.org | Supply chain | Open source | Confirmed | [1] |
| 2002-09-30 | F-Secure: Bugbear (Tanatos) in the wild; Linux.Devnull uses the Slapper exploit | Worm | Cross-sector | Confirmed; Reported (Devnull) | [30][28] |
| 2002-09 (end) | F-Secure: Opaserv first detected; global outbreak by early October | Worm | Windows 9x users | Confirmed | [31] |
| 2002-10-02 | F-Secure raises Bugbear to Level 1 | Worm | Cross-sector | Confirmed | [30] |
| 2002-10-04 | Vasiliy Gorshkov sentenced to 36 months. Home: [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) | Crime | Banking, payments | Confirmed | [38] |
| 2002-10-06 | Compromised Sendmail FTP server disabled (about 22:15 PDT) | Supply chain | Open source | Confirmed | [1] |
| 2002-10-08 | CA-2002-28 on the Sendmail trojan | Supply chain | Open source | Confirmed | [1] |
| 2002-10-21 | Flood against all thirteen DNS root name servers, about 20:45 to 22:00 UTC | Availability | Internet infrastructure | Confirmed | [45] |
| 2002-10-25 | CA-2002-29: Kerberos kadmind overflow (MIT and KTH) reported exploited (CVE-2002-1235) | Exploitation | Cross-sector | Confirmed | [1] |
| 2002-11 | NIST SP 800-48, wireless network security | Standards | Government | Confirmed | [68] |
| 2002-11-11 | Trojaned tcpdump and libpcap appear on www.tcpdump.org (10:14 GMT) | Supply chain | Open source | Confirmed | [1] |
| 2002-11-12 | McKinnon indicted in the Eastern District of Virginia on seven counts | Crime | Government, military | Confirmed | [40] |
| 2002-11-13 | Trojaned tcpdump downloads disabled (15:05 GMT); CA-2002-30 | Supply chain | Open source | Confirmed | [1] |
| 2002-11-14 | CA-2002-31: BIND 4 and 8, including CVE-2002-1219 | Vulnerability | Internet infrastructure | Confirmed | [1][13] |
| 2002-11-18 | District of New Jersey McKinnon indictment unsealed (Earle Naval Weapons Station) | Crime | Military | Confirmed | [41] |
| 2002-11-21 | CA-2002-32: back door in Alcatel OmniSwitch AOS | Vulnerability | Network equipment | Confirmed | [1][3] |
| 2002-11-24 | Root server operators' report on 21 October dated | Availability | Internet infrastructure | Confirmed | [45] |
| 2002-11-25 | Homeland Security Act approved (Pub. L. 107-296), including the Cyber Security Enhancement Act | Law | Government | Confirmed | [52][53] |
| 2002-11-25 | Philip Cummings arrested; SDNY calls it the largest identity theft case in US history | Insider | Financial services | Confirmed (allegation) | [42] |
| 2002-11-27 | Cyber Security Research and Development Act approved (Pub. L. 107-305) | Law | Research | Confirmed | [54] |
| 2002-12-03 | F-Secure lowers Bugbear to Level 2 | Worm | Cross-sector | Confirmed | [30] |
| 2002-12-16 | CA-2002-36: SSH implementations, found with Rapid7's SSHredder suite | Vulnerability | Cross-sector | Confirmed | [1] |
| 2002-12-17 | E-Government Act approved (Pub. L. 107-347); Title III is FISMA | Law | Government | Confirmed | [55][56] |
| 2002-12-18 | MS02-072, Windows XP shell (CAN-2002-1327), the last Microsoft bulletin of 2002 | Vulnerability | Cross-sector | Confirmed | [18] |
| 2002-12-19 | CA-2002-37, the last CERT/CC advisory of 2002 | Vulnerability | Cross-sector | Confirmed | [3] |
| 2002-12-20 | Juju Jiang arrested over password-recording software at a Manhattan Kinko's | Crime | Public kiosks, consumers | Confirmed | [44] |
| Undated (placed in 2002 by this study) | F-Secure: the Benjamin worm spreads over the KaZaa file-sharing network | Worm | Consumers | Confirmed (behavior); Inferred (year) | [32] |
| 2002 | Earliest Equation samples Kaspersky had seen compiled. Home: [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md) | Espionage | Unknown | Confirmed | [76][99] |
| 2003-01-28 (boundary) | Additional Protocol to the Convention on Cybercrime (ETS 189) done at Strasbourg | Law | Cross-sector | Confirmed | [74] |
| 2003-07-25 (boundary) | Alexey Ivanov sentenced to 48 months | Crime | Banking, payments | Confirmed | [39] |
| 2003-09 (boundary) | TIME: earliest dated Titan Rain event, a Lockheed Martin break-in | Espionage | Defense industry | Reported | [80] |
| 2003-09-09 (boundary) | Lamo charged in SDNY | Crime | Media | Confirmed | [35] |
| 2003-12-18 (boundary) | Daniel Baas pleads guilty over the Acxiom data theft (intrusion period not dated) | Crime | Data services | Confirmed | [43] |
| 2004-01-08 (boundary) | Lamo pleads guilty | Crime | Media | Confirmed | [36] |
| 2004-10-18 (boundary) | Kaspersky: an EquationLaser installer sample compiled | Espionage | Unknown | Confirmed | [76] |
| 2015-02-16 (boundary) | Kaspersky publishes its Equation reports | Espionage | Unknown | Confirmed | [76][75] |

## Part 2: the vulnerability record

### The 37 advisories

CERT/CC published 37 advisories in 2002, CA-2002-01 on 14 January to CA-2002-37 on 19 December (Confirmed [2][3]). Grouped by topic (the grouping is this study's; the advisory texts are SEI's compilation) (Confirmed [1]; grouping Inferred):

- **Exploited server flaws.** CA-2002-01 (14 Jan): active exploitation of the CDE Subprocess Control Service (dtspcd) overflow on Solaris, first published as CA-2001-31 and now CVE-2001-0803 (NVD lists CWE-119); CERT confirmed it with network traces from The Honeynet Project (Confirmed [1][6]). CA-2002-29 (25 Oct): active exploitation of an overflow in the Kerberos administration daemon in the MIT and KTH implementations, CVE-2002-1235 (Confirmed [1]).
- **Worms.** CA-2002-27 (14 Sep): the Apache/mod_ssl worm (Part 4).
- **Trojaned distributions.** CA-2002-24 (1 Aug) OpenSSH, CA-2002-28 (8 Oct) Sendmail, CA-2002-30 (13 Nov) tcpdump and libpcap (Part 3).
- **Web and database servers.** CA-2002-08 (14 Mar) Oracle servers; CA-2002-09 (11 Apr) Microsoft IIS; CA-2002-17 (17 Jun) Apache chunk handling; CA-2002-22 (29 Jul) Microsoft SQL Server; CA-2002-23 (30 Jul) OpenSSL (Confirmed [1]).
- **Network infrastructure and naming.** CA-2002-03 (12 Feb) SNMPv1; CA-2002-12 (8 May) ISC DHCPD; CA-2002-15 (4 Jun) BIND 9 denial of service; CA-2002-19 (28 Jun) DNS resolver libraries; CA-2002-31 (14 Nov) BIND 4 and 8; CA-2002-32 (21 Nov) the Alcatel OmniSwitch back door (Confirmed [1][3]). Part 5 covers them.
- **Shared libraries.** CA-2002-07 (12 Mar) the zlib double free, CVE-2002-0059, which NVD lists as CWE-415 (Confirmed [1][9]); CA-2002-25 (5 Aug) the XDR library integer overflow, CVE-2002-0391, CWE-190 (Confirmed [1][12]). A flaw in a library reaches every program that links it (Inferred).
- **Secure shell.** CA-2002-18 (26 Jun) OpenSSH challenge-response, versions 2.3.1p1 through 3.3, CVE-2002-0639 (integer overflow, CWE-190) and CVE-2002-0640 (Confirmed [1][10]); CA-2002-36 (16 Dec) pre-authentication flaws in the key exchange and initialization of many vendors' SSH implementations, found with Rapid7's SSHredder test suite (Confirmed [1]).

### What the record says about attackers

CERT's 2002 texts state exploitation against real systems for dtspcd, Spida's sa passwords, the OpenSSL flaw Slapper used and kadmind, plus the three trojaned distributions (Confirmed [1][4]). For SNMP, zlib, XDR, BIND, the resolver libraries, the SSH implementations and the OmniSwitch back door, this study read no statement of exploitation in the passages cited and does not claim there was none (Inferred [1]). The National Strategy to Secure Cyberspace, published in February 2003, records that vulnerabilities reported to CERT/CC rose from 1,090 in 2000 to 4,129 in 2002 (Confirmed [57]).

### Microsoft's year

Microsoft's 2002 bulletins ran from MS02-001 on 30 January, on trusting domains that do not verify SID domain membership, to MS02-072 on 18 December, on the Windows XP shell (CAN-2002-1327). This study found no MS02-073, and MS03-001 is dated 22 January 2003 (Inferred [18]; Confirmed [100]). The series therefore holds 72 bulletins, released on irregular dates before monthly scheduled releases (Inferred [15][16][17][18]). Bulletins cited here:

- **MS02-005 (11 Feb).** A cumulative Internet Explorer patch for six vulnerabilities, updated 9 May 2003 (Confirmed [16]).
- **MS02-024 (22 May).** A Windows NT 4.0 and 2000 debugger authentication flaw that allows privilege escalation (CAN-2002-0367). CISA added CVE-2002-0367 to its Known Exploited Vulnerabilities catalog on 3 March 2022; it is the only 2002 CVE in catalog version 2026.11.10 (Confirmed [14][101]).
- **MS02-039 (24 Jul).** Buffer overruns (CAN-2002-0649) and a denial of service (CAN-2002-0650) in the SQL Server 2000 Resolution Service on UDP 1434. The bulletin's mitigations are running SQL Server as a domain user, the default, and blocking UDP 1434 at the firewall. The January 2003 revision says the patch protects against the SQL Slammer worm and is superseded by MS02-061 (Confirmed [17]). NVD lists CWE-119 for CVE-2002-0649 (Confirmed [102]). Slammer is a 2003 event; the [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is its home (Demonstrated [94]).
- **CA-2002-22 (29 Jul).** CERT noted that Microsoft had published eight SQL Server bulletins since December 2001 covering more than a dozen vulnerabilities, and summarized the five most serious, including a privilege escalation through weak permissions on a registry key (VU#796313, CAN-2002-0642) that can be chained to take over the host (Confirmed [1]).
- **MS02-072 (18 Dec).** The Windows XP shell, the year's last bulletin (Confirmed [18]).

### The open-source flaws

- **Apache.** The Apache Software Foundation's bulletin of 17 June disclosed the chunked-encoding flaw, CVE-2002-0392, in Apache 1.2.2 onward, 1.3 through 1.3.24 and 2.0 through 2.0.36. The release was forced early after ISS published the issue, and CERT's CA-2002-17 came the same day (Confirmed [20][1]). Apache's own record dates the report to 27 May, the public disclosure to 17 June and the fix in 1.3.26 to 18 June, and rates it critical (Confirmed [21]). NVD lists NVD-CWE-noinfo, so no CWE is assigned (Confirmed [103]).
- **OpenSSL.** The OpenSSL advisory of 30 July reported four potentially remotely exploitable buffer overflows found in a review funded under DARPA's CHATS program: the SSL2 client master key and the SSL3 session ID (CAN-2002-0656), the SSL3 master key in 0.9.7 beta Kerberos builds (CAN-2002-0657) and 64-bit ASCII integer buffers (CAN-2002-0655). A second, separate advisory merged into the same text covers an ASN.1 parser flaw (CAN-2002-0659). The fix was 0.9.6e, and applications had to be recompiled after patching. CERT's CA-2002-23 came the same day (Confirmed [22][1]). NVD published CVE-2002-0656 on 12 August with NVD-CWE-Other (Confirmed [7]).
- **OpenSSH.** OpenSSH 3.3, released on 21 June, enabled privilege separation by default (Confirmed [24]). The project's preauth advisory, with patches dated 26 June, covers an input-validation flaw in challenge-response authentication in sshd 2.9.9 through 3.3, fixed in 3.4. The interim fix was to disable challenge-response authentication. Privilege separation, supported from 3.2 and the default in 3.3, blocks the privilege escalation but not the remote exploitation (Confirmed [25]). NVD lists CWE-190 for CVE-2002-0639 (Confirmed [10][11]).

### The CVE record

The advisories and bulletins of 2002 cite CVE candidates in the CAN- form, so CVE naming was in daily vendor use (Confirmed [1][17][22]). NIST's SP 800-51 of September 2002 told federal departments and agencies to use the CVE naming scheme (Confirmed [59]). The CWE ids NVD now shows for the year's CVEs were assigned after CWE existed: CWE-119 for CVE-2001-0803 and CVE-2002-0649, CWE-190 for CVE-2002-0639 and CVE-2002-0391, CWE-415 for CVE-2002-0059 and CWE-264 for CVE-2002-0012 and CVE-2002-0013, while CVE-2002-0656 carries NVD-CWE-Other and CVE-2002-0392 NVD-CWE-noinfo (Confirmed [6][7][8][9][10][12][102][103]). CWE-264 is not in the library's CWE data, so it is cited and not linked (Confirmed [91]).

## Part 3: the trojaned distributions

Three times in four months an intruder replaced an official source distribution with one that carried a back door, and each time the malicious code ran during the build (Confirmed [1][23]). No CVE covers any of them, because they were compromises, not flaws in the software (Inferred). ATT&CK's later name for the pattern is Compromise Software Supply Chain, T1195.002 (Inferred [84]).

**OpenSSH (30 or 31 July to 1 August).** An intruder modified the OpenSSH 3.4p1, 3.4 and 3.2.2p1 source tarballs on the FTP server that hosts ftp.openssh.com and ftp.openbsd.org on 30 or 31 July (Confirmed [1][23]). The developers replaced them at 13:00 UTC on 1 August, which the project's own advisory gives as 7 AM MDT (Confirmed [1][23]). CERT's CA-2002-24, issued the same day, says the code runs at compile time, connects to a fixed remote server on 6667/tcp and can open a shell as the user who built it. It warns that timestamps and file sizes are not enough to check, and advises verifying MD5 checksums and PGP signatures (Confirmed [1]). The OpenSSH advisory tells anyone who built from the server or a mirror in that window to consider the system compromised (Confirmed [23]).

**Sendmail (about 28 September to 6 October).** Trojaned Sendmail 8.12.6 tarballs began appearing in downloads from ftp.sendmail.org on or around 28 September. The compromised FTP server was disabled on 6 October at about 22:15 PDT, and CA-2002-28 followed on 8 October. The build-time code forks a process that connects to a fixed server on 6667/tcp. HTTP downloads did not appear to be affected (Confirmed [1]).

**tcpdump and libpcap (11 to 13 November).** Trojaned tcpdump 3.6.2 and 3.7.1 and libpcap 0.7.1 were on www.tcpdump.org from about 10:14 GMT on 11 November until they were disabled at 15:05 GMT on 13 November. The configure script fetches a shell script from a fixed host on 80/tcp (Confirmed [1]).

**What the three share.** Each compromise hit the project's own download server, each ran code on the machine that built the software rather than on the machine that later ran it, and each called a fixed external host (Confirmed [1][23]; the comparison is Inferred). A tool for watching network traffic and the daemon most administrators use for remote login were among the targets (Inferred). The window for each was hours to about nine days (Confirmed [1][23]; Inferred for the span).

**A possibly contemporary case in Kaspersky's record.** Kaspersky reports a trojanized Oracle installation CD that carried an EQUATIONLASER dropper alongside the Oracle installer. The case is undated; the EQUATIONLASER era is 2001 to 2004 (Reported [75]). ATT&CK records no supply-chain technique for Equation, so any T1195.002 mapping here is Inferred only and is left out of the Navigator layer (Confirmed [78]; Inferred).

The [npm supply-chain study](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), the [xz Utils backdoor study](/case-studies/XZ_UTILS_BACKDOOR_2024.md), the [Hugging Face supply-chain study](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) and [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md) return to the same path into victims: trusted code changed before it reaches them (Inferred).

## Part 4: the worm year

### Slapper and Scalper

**Scalper.** F-Secure says the Scalper worm was found in June 2002 (Reported [28]). It spread between FreeBSD systems through the Apache chunked-encoding flaw, and F-Secure had received no direct field reports of infections (Confirmed [29]).

**Slapper.** F-Secure records that Slapper was found in Eastern Europe late on Friday 13 September (Confirmed [28]). CERT's CA-2002-27 (released 14 September, revised 11 October) calls it the Apache/mod_ssl worm, also known as linux.slapper.worm and the bugtraq.c worm (Confirmed [1]). It exploits the OpenSSL SSLv2 handshake flaw VU#102795 (CVE-2002-0656) on Linux x86 hosts running Apache with mod_ssl (Confirmed [1][7]). It scans 80/tcp with an invalid GET request, delivers its exploit over 443/tcp, places its source code on the victim and compiles and runs it there. Infected hosts join a peer-to-peer network over UDP 2002, later 1978 and 4156, that can be used for denial-of-service attacks (Confirmed [1]). CERT reported that it had already infected thousands of systems and that there were at least three variants (Confirmed [1]). F-Secure says its network peaked at about 2,000 active hosts, records the Cinik variant on 23 September and Linux.Devnull on 30 September using the same exploit, and says Slapper closely resembles Scalper (Reported [28]). Slapper was found about six weeks after the OpenSSL fix of 30 July (Confirmed [22][28]; the interval is Inferred).

### The database worm

CERT's IN-2002-04 (22 May, updated 23 May) reported automated exploitation of null or weak default sa passwords on Microsoft SQL Server and MSDE by the worm called Spida, SQLsnake or Digispid. It scans 1433/tcp, enables the guest account through xp_cmdshell and adds that account to the Administrators and Domain Admins groups (Confirmed [4]).

### Network-share and file-sharing worms

**Opaserv.** Opaserv (Opasoft) was first detected at the end of September and caused a global outbreak by early October. It spread over Windows file sharing using the Windows 9x share-level password flaw fixed by MS00-072 (CVE-2000-0979) (Confirmed [31]). Microsoft had published MS00-072, the "Share Level Password" fix for Windows 95, 98, 98 SE and Me, on 10 October 2000, two years earlier (Confirmed [19]).

**Benjamin.** F-Secure records the Benjamin worm spreading over the KaZaa peer-to-peer file-sharing network (Confirmed [32]). F-Secure's description gives no date; placing it in 2002 is this study's reading (Inferred).

### The mail and chat worms

- **Klez (summary).** The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Klez (Demonstrated [94]). Its first infections were seen on 26 October 2001; it can run an attachment automatically when a message is viewed, through the Internet Explorer MIME-header flaw MS01-020 (CVE-2001-0154) (Confirmed [26]). F-Secure records Klez.E as first discovered on 17 January 2002 (Reported [26]) and Klez.H as found in parts of Asia on 17 April and spread globally within a week (Confirmed [27]).
- **Myparty (IN-2002-01, 28 Jan).** A Windows mass mailer spreading as an email attachment by social engineering; several dozen sites had reported it by 16:00 EST that day (Confirmed [4]).
- **Gibe (IN-2002-02, 12 Mar, updated 13 Mar).** A mail worm disguised as a Microsoft security bulletin and patch, which installs a back door (Confirmed [4]).
- **Chat-borne recruitment (IN-2002-03, 19 Mar).** Social engineering over IRC and instant messaging tricked users into running denial-of-service agents, Trojan horses and back doors. Reports to CERT indicated tens of thousands of systems compromised and recruited into denial-of-service networks (Confirmed [4]).
- **Frethem (IN-2002-05, 17 Jul).** A mass mailer with its own SMTP engine. A crafted IFRAME makes it run automatically in mail clients that use unpatched Internet Explorer rendering (Confirmed [4]).
- **Bugbear (30 Sep).** F-Secure says Bugbear (Tanatos), a mass-mailing and network worm with keylogging and back-door components, appeared in the wild on 30 September. F-Secure raised it to Level 1 on 2 October, calling it the most widespread virus in the world together with Klez, and lowered it to Level 2 on 3 December (Confirmed [30]).

### No ATT&CK software objects

The library's ATT&CK software data has no entry for Slapper, Scalper, Spida, Opaserv, Benjamin, Klez, Myparty, Gibe, Frethem or Bugbear, so any binding for the year's worms is technique-level only (Demonstrated [96]).

## Part 5: the infrastructure record

### The root server flood of 21 October

On 21 October, from about 20:45 to 22:00 UTC, a coordinated distributed denial-of-service attack hit all thirteen DNS root name servers at once (Confirmed [45]). Each server received about 50 to 100 Mbit/s, about 900 Mbit/s and 1.8 million packets a second in total, of ICMP, TCP SYN, fragmented TCP and UDP traffic from mostly randomized source addresses (Confirmed [45]). Some servers were unreachable from parts of the internet, but all kept answering the queries that reached them and the operators knew of no end-user visible errors (Confirmed [45]). The report, by Vixie, Sneeringer and Schleifer and dated 24 November, credits host and network overprovisioning. The operators responded with more peering and transit, wide-area mirroring and faster upgrades (Confirmed [45]).

The government's account, in the National Strategy to Secure Cyberspace of February 2003, says the 21 October attacks on the core DNS root servers degraded or disrupted some of the thirteen (Confirmed [57]). It gives no figures for size, duration or user impact (Confirmed [57]). The government record gives no user-impact figure, so it does not contradict the operators' report of no known end-user visible errors (Inferred).

### Protocols and devices

- **SNMP (CA-2002-03, 12 Feb).** The Oulu University Secure Programming Group's PROTOS c06-snmpv1 test suite found flaws in trap handling (VU#107186, CVE-2002-0012) and request handling (VU#854306, CVE-2002-0013) across SNMPv1 implementations from a very wide range of vendors; the advisory carries hundreds of vendor statements (Confirmed [1][3][8]). A test suite, not an attacker, produced the year's broadest infrastructure advisory (Inferred).
- **DNS software.** CA-2002-15 (4 Jun) BIND 9 denial of service; CA-2002-19 (28 Jun) overflows in multiple resolver libraries; CA-2002-31 (14 Nov) multiple BIND 4 and 8 flaws, including remote code execution as the user running named and the cached malformed SIG record overflow CVE-2002-1219. CERT noted that most internet services depend on DNS (Confirmed [1][3][13]).
- **Switches.** CA-2002-32 (21 Nov): Alcatel OmniSwitch 7700 and 7800 switches running AOS 5.1.1 shipped with a development telnet server still listening, which did not require a password and gave full administrative access (CAN-2002-1272) (Confirmed [1][3]).
- **SSH.** CA-2002-36 (16 Dec, revised 5 May 2003): flaws in the key exchange and initialization of many vendors' SSH implementations, found with Rapid7's SSHredder test suite (Confirmed [1]).

## Part 6: the state record

### Equation: earliest samples compiled in 2002

Kaspersky's report of 16 February 2015 says some of the earliest Equation samples it had seen were compiled in 2002, and that one Equation C&C domain was registered in August 2001, with others possibly as early as 1996 (Confirmed [76]). Kaspersky's Q&A (version 1.5, February 2015) says the group's computer network exploitation operations date back to 2001 and perhaps as early as 1996, which is Kaspersky's own assessment (Reported [75]). It lists EQUATIONLASER as an early implant used around 2001 to 2004 (2001 to 2003 in its comparison with Regin), compatible with Windows 95 and 98, followed by EQUATIONDRUG from 2003 to 2013 (Confirmed [75]). The EquationLaser installer sample in Kaspersky's indicator table was compiled on 18 October 2004 (Confirmed [76]). Neither publication names a country or agency; the Q&A's attribution section lists only leftover codewords, such as GROK, which it notes also appears in Der Spiegel documents (Confirmed [75][76]).

The [Zero-Day Market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) is the home for the 2002 samples (Demonstrated [99]), and the [United States actors study](/case-studies/THREAT_ACTORS_UNITED_STATES.md) and [the NSA and CIA tool leaks study](/case-studies/NSA_CIA_TOOL_LEAKS.md) carry the wider Equation record. ATT&CK's [Equation (G0020)](/mitre/groups/G0020.md), version 1.2, created 31 May 2017 and modified 31 July 2026, lists four techniques (T1120, T1480.001, T1542.002 and T1564.005) and no aliases, software, activity dates or nation (Confirmed [78]). Those techniques come from analysis of later platforms and are not presented here as observed in 2002 (Inferred [78]).

### Moonlight Maze's successor and Turla (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for Moonlight Maze, and the [Russia study](/case-studies/THREAT_ACTORS_RUSSIA.md) for Turla. Kaspersky and King's College London researchers report that after the 1999 publicity the Moonlight Maze operators used an evolved toolkit the US codenamed Storm Cloud, and that a 2003 leak of the Storm Cloud story carried few details (Reported [77]). The same paper says the Penquin Turla codebase appears to have been primarily developed from 1999 to 2004, based on the open-source LOKI2 backdoor, while calling the link from Moonlight Maze to Turla circumstantial and a conclusion premature (Reported [77]). ATT&CK's [Turla (G0010)](/mitre/groups/G0010.md), version 5.1, dates its victims since at least 2004, attributes it to Russia's FSB, lists [Penquin (S0587)](/mitre/software/S0587.md), and mentions neither Moonlight Maze nor any year before 2004 (Confirmed [79]). This study therefore binds no Turla activity to 2002 (Inferred).

### Titan Rain is not a 2002 event

TIME's account of 29 August 2005 gives a September 2003 Lockheed Martin break-in as the earliest dated Titan Rain event, states the China attribution only tentatively (suspected Chinese cyberspies, with traffic traced to routers in Guangdong) and does not mention 2002 (Reported [80]). It is left out of this year. The [China study](/case-studies/THREAT_ACTORS_CHINA.md) is the library's home for China-attributed activity.

### The state as victim

The best-documented intrusion into state networks that reaches into 2002 is Gary McKinnon's (Part 7). The Eastern District of Virginia's release alleges no foreign government involvement, credits the UK National High Tech Crime Unit and says extradition would be sought (Confirmed [40]).

### The quiet year

No ATT&CK group, software or campaign object in the library's data is tied to a dated 2002 operation (Inferred [95][96]). The year's public state record is a vendor reconstruction published thirteen years later, a researchers' account of a successor toolkit, and the laws of Part 8. The gap reflects limited visibility, not proof of inactivity (Inferred [76][77]).

## Part 7: crime and prosecutions

### Media and research databases

On 26 February 2002 Adrian Lamo got into the New York Times internal network and reached a database of more than 3,000 Op-Ed contributors, holding Social Security numbers and home phone numbers, where he added an entry about himself. He also set up five fictitious LexisNexis user IDs that ran more than 3,000 searches over three months (Confirmed [35]). The release on his guilty plea says he admitted the intrusion to a SecurityFocus reporter on 26 February 2002 (Confirmed [36]). He was charged in the Southern District of New York on 9 September 2003 and pleaded guilty on 8 January 2004 (Confirmed [35][36]). The [Mitnick intrusions study](/case-studies/MITNICK_INTRUSIONS.md) is the home for the case.

### Military and space systems

On 12 November the US Attorney for the Eastern District of Virginia announced a seven-count indictment of Gary McKinnon of London (Confirmed [40]). The indictment alleges that between March 2001 and March 2002 he accessed and damaged 92 computers of the US Army, Navy, Air Force, Department of Defense and NASA and 6 private computers. According to the indictment, he scanned .mil networks, gained administrative rights, installed a remote administration tool, copied password files, and deleted user accounts and critical system files. One network in the Washington, D.C. area lost internet and email for about 2,000 users for three days, and the estimated loss was about $900,000 (Confirmed [40]). A District of New Jersey indictment, unsealed on 18 November, covers the Earle Naval Weapons Station intrusion, including shutting down its network after 11 September 2001 (Confirmed [41]). These are allegations in indictments (Confirmed [40][41]).

### The insider and the credit bureaus

On 25 November the Southern District of New York unsealed a complaint against Philip Cummings, a former help-desk employee at Teledata Communications Inc. (Confirmed [42]). From early 2000 he used client passwords and subscriber codes to download credit reports from Equifax, Experian and TransUnion for a ring. The complaint counts more than 30,000 victims and more than $2.7 million in confirmed losses. Ford Motor Credit's Grand Rapids code alone was used for about 15,000 Experian reports, and Ford Motor Credit found the scheme through Experian bills and consumer complaints (Confirmed [42]). SDNY called it believed to be the largest identity theft case in US history; that is the prosecutors' framing of allegations at arrest (Confirmed [42]).

### Kiosks and remote access

On 20 December SDNY arrested Juju Jiang of Flushing, Queens. He had installed password-recording software at a Kinko's on Seventh Avenue in Manhattan and used the captured credentials to try to get into about 15 GoToMyPC subscribers' computers, taking control of one (Confirmed [44]).

### Sentences for earlier cases (summary)

The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home for both (Demonstrated [94]):

- **Melissa.** On 1 May David L. Smith was sentenced in the District of New Jersey to 20 months in federal prison, three years of supervised release and a $5,000 fine for the 1999 Melissa virus; his plea agreement acknowledged more than $80 million in damage (Confirmed [37]).
- **Gorshkov.** On 4 October Vasiliy Gorshkov of Chelyabinsk was sentenced in the Western District of Washington to 36 months and ordered to pay nearly $700,000 in restitution. His 2001 trial convictions on 20 counts covered intrusions and fraud against Speakeasy, Nara Bank, Central National Bank of Waco and PayPal; he had been lured by the FBI's "Invita" undercover operation, with arrests on 10 November 2000 (Confirmed [38]). His co-defendant Alexey Ivanov was sentenced on 25 July 2003 to 48 months, and the court found an aggregate loss of about $25 million (Confirmed [39]).

### A case the record does not date

Daniel Baas, a systems administrator at a firm that did business with Acxiom, exceeded his authorized access to Acxiom's systems, cracked a downloaded password file and stole other customers' files, at a cost of more than $5.8 million. He pleaded guilty on 18 December 2003 (Confirmed [43]). The release does not date the intrusion, so this study does not place it in 2002 (Confirmed [43]; Inferred).

### Law enforcement tools

The Cyber Security Enhancement Act of 2002, enacted on 25 November as section 225 of the Homeland Security Act, directed the US Sentencing Commission to review the guidelines for offenses under 18 U.S.C. 1030 (Confirmed [52]).

## Part 8: law, regulation and standards

### The FTC's security orders

- **Eli Lilly (18 Jan).** On 27 June 2001 a Lilly employee sent a Prozac.com "Medi-messenger" termination email that put all 669 subscribers' addresses in the To: line. The consent order requires an information security program with annual written reviews; the Commission voted 5 to 0 (Confirmed [46]).
- **Microsoft Passport (8 Aug).** The FTC alleged false claims about the security of Passport Wallet card data, about purchase safety, about the data collected (sign-in history) and about Kids Passport. The order requires a full security program that an independent professional certifies every two years; public comment ran until 9 September (Confirmed [47]).
- **The Safeguards Rule (23 May).** The FTC's Standards for Safeguarding Customer Information (16 CFR 314, 67 FR 36484) were published on 23 May 2002 and took effect on 23 May 2003. The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home (Confirmed [48]; Demonstrated [94]).

### Breach notification

California SB 1386 (Chapter 915, Statutes of 2002) was introduced on 12 February, approved by the Governor on 25 September, filed on 26 September and became operative on 1 July 2003 (Confirmed [49]). It requires agencies and businesses to notify California residents when unencrypted personal information is, or is reasonably believed to have been, acquired by an unauthorized person. It allows a delay for law enforcement and substitute notice where notice would cost more than $250,000 or reach more than 500,000 people (Confirmed [49]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is its home (Demonstrated [94]). Before it took effect there was no general duty to tell victims, so the 2002 breach record is thin by construction (Inferred).

### Federal statutes

- **Sarbanes-Oxley (30 Jul).** Pub. L. 107-204. Section 404 requires a management report on internal control in annual reports (Confirmed [50][51]). It is not a security law; that it drove IT controls work is this study's reading (Inferred).
- **Homeland Security Act (25 Nov).** Pub. L. 107-296 (H.R. 5005). Title II created the Information Analysis and Infrastructure Protection directorate and moved into it the FBI's National Infrastructure Protection Center (except the Computer Investigations and Operations Section), the National Communications System and GSA's FedCIRC. Section 225 is the Cyber Security Enhancement Act of 2002, and Title X section 1001 carries the short title Federal Information Security Management Act (Confirmed [52][53]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md), section 5.5, is the home (Confirmed [52]; Demonstrated [94]).
- **Cyber Security Research and Development Act (27 Nov).** Pub. L. 107-305 (H.R. 3394) authorizes funding for computer and network security research and fellowships (Confirmed [54]).
- **E-Government Act (17 Dec).** Pub. L. 107-347 (H.R. 2458). Title III, section 301, is also cited as the Federal Information Security Management Act of 2002 (Confirmed [55][56]). Section 3544 requires each agency to run an agency-wide security program with risk assessment, policies, training, testing at least once a year, remediation, incident response and continuity plans, and to report each year to OMB, Congress and GAO. Section 3545 requires an annual independent evaluation by the Inspector General or an external auditor that tests a representative subset of systems, and section 3546 provides for a federal incident center. Section 303 rewrites NIST's security standards mission (Confirmed [55]). The same short title was thus enacted twice in 2002, three weeks apart; the dot-com study names only the Homeland Security Act version (Confirmed [52][55]; Demonstrated [94]).

### The national strategy in draft

The National Strategy to Secure Cyberspace, published in February 2003, records that in September 2002 the President's Critical Infrastructure Protection Board put a draft online for public comment, that ten town halls were held, and that on 18 September many private-sector entities released sector plans (Confirmed [57]). It also records OMB's first report to Congress on government information security reform (February 2002), which named six governmentwide security gaps, and a DoD policy of July 2002 that requires buying products evaluated under NIAP (Confirmed [57]).

### Outside the United States

The Council of Europe's Additional Protocol to the Convention on Cybercrime (ETS 189) was done at Strasbourg on 28 January 2003 (Confirmed [74]). This study did not check a 2002 adoption date for it.

### Cryptography and standards

- **Hashing and message authentication.** FIPS 198, the Keyed-Hash Message Authentication Code (HMAC), was published on 6 March 2002 (withdrawn 29 July 2008, superseded by FIPS 198-1) (Confirmed [60]). FIPS 180-2, the Secure Hash Standard, published in August 2002, specifies SHA-1, SHA-256, SHA-384 and SHA-512 (Confirmed [62]).
- **TLS and PKI.** RFC 3280, the Internet X.509 PKI certificate and CRL profile, is dated April 2002 and obsoletes RFC 2459; RFC 5280 later obsoleted it (Confirmed [70]). RFC 3268, AES ciphersuites for TLS, is dated June 2002 (the RFC Editor lists July). It adds twelve AES-128 and AES-256 CBC suites with HMAC-SHA1, including Diffie-Hellman ephemeral suites that give forward secrecy with AES, and moves away from RC2, RC4, IDEA and 3DES (Confirmed [71]).
- **NIST guidance.** SP 800-34, Contingency Planning Guide for IT Systems (13 June; supersedes FIPS 87; withdrawn 2010) (Confirmed [61]). SP 800-30, Risk Management Guide for IT Systems (July; supersedes FIPS 65 and FIPS 31; withdrawn 2012 for Revision 1) (Confirmed [58]). SP 800-40, Procedures for Handling Security Patches (August; withdrawn 2005 for Version 2) (Confirmed [63]). SP 800-46 on telecommuting and broadband and SP 800-47 on interconnecting systems (August) (Confirmed [64][65]). SP 800-51 on the CVE naming scheme (September) (Confirmed [59]). SP 800-45 on email (11 September) and SP 800-44 on public web servers (September) (Confirmed [66][67]). SP 800-48 on 802.11, Bluetooth and handheld devices (November) (Confirmed [68]).
- **Not 2002 items.** FIPS 197 (AES) was published on 26 November 2001, and its page states no effective date; SP 800-31 on intrusion detection is dated November 2001, and SP 800-36 is dated October 2003 (Confirmed [69]).

### Industry practice

Microsoft says it launched its Trustworthy Computing initiative in January 2002 and that the Security Development Lifecycle became integral to its development process in 2004 (Confirmed [34]). The memo that launched it went to all Microsoft full-time employees on Tuesday 15 January; Wired published its text on 17 January (Reported [33]). The [dot-com era study](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md) is the home, and also dates a disclosure Internet-Draft (February) and the Full-Disclosure mailing list (9 July) (Demonstrated [94]).

## Part 9: the industrial record

### Maroochy Shire: the appeal

The Queensland Court of Appeal delivered R v Boden [2002] QCA 164 on 10 May 2002. It allowed the appeal against conviction in part, setting aside counts 21 to 26, and dismissed the application for leave to appeal the two-year sentence (Confirmed [72]). The Crown case was that between 9 February and 23 April 2000 Boden accessed the computers controlling the Maroochy Shire Council sewerage system, about 150 pumping stations controlled over a private two-way radio network (Confirmed [72]). The High Court of Australia refused special leave on 25 June 2003 (Confirmed [72]). The intrusion is dated 2000; 2002 is its appellate record (Confirmed [72]). The [2000 chronicle](/case-studies/CHRONICLE_2000.md) is the home study for the attack itself; this part covers the appeal.

### The ATT&CK record

ATT&CK for ICS records the event as campaign C0020, Maroochy Water Breach, which ran from February to April 2000 and released 800,000 litres of raw sewage, and lists 12 techniques for it (Confirmed [73]). All are in the library's ICS data; the library has no C0020 campaign page and no ICS technique pages, so the ids link to ATT&CK (Confirmed [73]; Demonstrated [98]). The 800,000-litre figure is ATT&CK's; the judgment passages cited give no volume (Confirmed [73][72]). The [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md) and the [ICS attacks and advisories study](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md) carry the industrial thread forward, and [Stuxnet](/case-studies/STUXNET.md) is its best-known later case (Inferred).

## Part 10: the defender view

**Integrity is a control, not a hope.** The three trojaned distributions were caught and pulled within hours to about nine days, and CERT's remedy each time was checksum and signature verification (Confirmed [1][23]). CERT said outright that timestamps and sizes are not enough (Confirmed [1]). The library's D3FEND data has no page for verifying a download's signature or checksum, so Part 11 pairs the closest countermeasures and says so (Inferred [92]).

**Build hosts are production.** Each trojan ran at compile time and called a fixed host from the build machine (Confirmed [1]). OpenSSH told anyone who built from the server in the window to consider the system compromised (Confirmed [23]).

**The race is fix to worm.** OpenSSL's fix came on 30 July and Slapper on 13 September; Apache's 1.3.26 fix on 18 June and Scalper the same month; the Opaserv flaw had been fixed two years earlier (Confirmed [22][28][20][19][31]; Reported [28] for Scalper's month). MS02-039 already protected against Slammer six months before it struck (Confirmed [17]). The [Log4Shell study](/case-studies/LOG4SHELL.md) shows a case where exploitation started before the fix (Inferred).

**Design limited the damage.** Privilege separation on by default in OpenSSH 3.3 blocked the challenge-response flaw's privilege escalation, though not its remote exploitation, and the interim fix was to turn off challenge-response authentication (Confirmed [24][25]). Running SQL Server as a domain user was the default MS02-039 relied on (Confirmed [17]).

**Recompile after patching.** The OpenSSL advisory warned that applications linked against the library had to be rebuilt after the fix (Confirmed [22]). zlib and XDR flaws had the same reach (Inferred [1]).

**Defaults and blank passwords.** Spida needed only a null or weak sa password, and an OmniSwitch shipped with a password-less telnet server listening (Confirmed [4][1]).

**Filter by role.** MS02-039 advised blocking UDP 1434 at the firewall; Slapper's peers talked over high UDP ports that few servers need (Confirmed [17][1]; Inferred).

**Capacity is a defense.** The root operators credited overprovisioning and answered with more of it (Confirmed [45]).

**Watch the people with access.** Cummings used credentials his former employer's clients held; Baas exceeded access he was given (Confirmed [42][43]).

**Federal programs got a method.** FISMA's annual testing, reporting and independent evaluation, with SP 800-30 for risk, SP 800-40 for patching and SP 800-34 for contingency planning, set the federal pattern for years (Confirmed [55][58][63][61]; the lasting effect is Inferred).

## Part 11: MITRE mappings

No 2002 record carries an ATT&CK Enterprise, CWE or CAPEC id from the time. The first CWE List came in 2006, CAPEC in 2007 and ATT&CK in 2013 (Confirmed [81][82][83]). Every Enterprise binding below is this study's later mapping (Inferred). Two tables differ: ATT&CK itself lists the four Equation techniques for G0020 (Confirmed [78]) and the ICS techniques for campaign C0020 (Confirmed [73]). Every id was checked against the library's data files and the generated pages under `mitre/` (Demonstrated [87][88][91][92][95][96][97][98]). Names and tactics are those of ATT&CK v20.0 as the library carries them.

The Basis column says how strong each tie is, as in the [2016 chronicle](/case-studies/CHRONICLE_2016.md). **Listed** means ATT&CK itself lists the id for the event or object. **Described** means a primary source describes the behavior and this study assigns the id. **Reported** means only a secondary source supports the behavior. **Inferred** means no source describes the behavior in enough detail and the mapping rests on the study's reading.

### ATT&CK Enterprise techniques

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Dated event or report | Sources |
|---|---|---|---|---|---|
| [`T1195.002`](/mitre/techniques/T1195-002.md) | Compromise Software Supply Chain | initial-access | Described | Trojaned OpenSSH (30 or 31 Jul; CA-2002-24, 1 Aug), Sendmail 8.12.6 (from about 28 Sep; CA-2002-28, 8 Oct), tcpdump and libpcap (11 to 13 Nov; CA-2002-30) | [1][23][84] |
| [`T1059.004`](/mitre/techniques/T1059-004.md) | Unix Shell | execution | Described | The OpenSSH trojan opens a shell as the building user (CA-2002-24); the tcpdump configure script fetches and runs a shell script (CA-2002-30) | [1] |
| [`T1105`](/mitre/techniques/T1105.md) | Ingress Tool Transfer | command-and-control | Described | The tcpdump trojan fetches a script from a fixed host (13 Nov); Slapper places its source on the victim (14 Sep) | [1] |
| [`T1190`](/mitre/techniques/T1190.md) | Exploit Public-Facing Application | initial-access | Described | dtspcd on Solaris (CA-2002-01, 14 Jan); Slapper against Apache with mod_ssl (CA-2002-27, 14 Sep); Scalper against Apache (June) | [1][28][29] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | lateral-movement | Described | Slapper host to host (14 Sep); Scalper between FreeBSD systems; Opaserv over Windows file sharing through the MS00-072 flaw (end of Sep) | [1][29][31][19][85] |
| [`T1595.002`](/mitre/techniques/T1595-002.md) | Vulnerability Scanning | reconnaissance | Described | Slapper scans 80/tcp with an invalid GET request before delivering its exploit over 443/tcp (CA-2002-27) | [1] |
| [`T1027.004`](/mitre/techniques/T1027-004.md) | Compile After Delivery | stealth | Described | Slapper compiles its source on the victim (CA-2002-27) | [1] |
| [`T1095`](/mitre/techniques/T1095.md) | Non-Application Layer Protocol | command-and-control | Described | Slapper's UDP peer network on 2002, 1978 and 4156 (CA-2002-27) | [1] |
| [`T1584.005`](/mitre/techniques/T1584-005.md) | Botnet | resource-development | Described | Users tricked over IRC and instant messaging into running denial-of-service agents on tens of thousands of systems (IN-2002-03, 19 Mar); Slapper's peer network usable for denial of service (14 Sep) | [4][1] |
| [`T1498.001`](/mitre/techniques/T1498-001.md) | Direct Network Flood | impact | Described | ICMP, TCP SYN, fragmented TCP and UDP floods against all thirteen root servers (21 Oct) | [45][57] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Default Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Spida through null or weak default sa passwords (IN-2002-04, 22 May) | [4] |
| [`T1098`](/mitre/techniques/T1098.md) | Account Manipulation | persistence, privilege-escalation | Described | Spida enables the guest account and adds it to Administrators and Domain Admins (22 May) | [4] |
| [`T1078`](/mitre/techniques/T1078.md) | Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Described | Cummings scheme uses client passwords and subscriber codes (from early 2000; charged 25 Nov); McKinnon gains administrative rights (Mar 2001 to Mar 2002; the account path is Inferred) | [42][40] |
| [`T1110.001`](/mitre/techniques/T1110-001.md) | Password Guessing | credential-access | Inferred | Opaserv's use of the Windows 9x share-level password flaw (end of Sep); the closest fit for a flaw in password checking | [31][19] |
| [`T1566.001`](/mitre/techniques/T1566-001.md) | Spearphishing Attachment | initial-access | Inferred | Mass-mailed attachments, not targeted, so the targeted-delivery technique is the closest fit only: Myparty (28 Jan), Gibe (12 Mar), Klez.H (17 Apr), Frethem (17 Jul), Bugbear (30 Sep) | [4][27][30] |
| [`T1204.002`](/mitre/techniques/T1204-002.md) | Malicious File | execution | Described | Myparty spreads by social engineering (28 Jan); Gibe poses as a Microsoft patch (12 Mar); IRC and instant-messaging users tricked into running agents (19 Mar) | [4] |
| [`T1203`](/mitre/techniques/T1203.md) | Exploitation for Client Execution | execution | Described | Frethem runs through unpatched IE rendering (17 Jul); Klez runs through the IE flaw MS01-020 | [4][26] |
| [`T1056.001`](/mitre/techniques/T1056-001.md) | Keylogging | collection, credential-access | Described | Bugbear's keylogging component (30 Sep); Jiang's password-recording software at a Kinko's (arrested 20 Dec) | [30][44] |
| [`T1219`](/mitre/techniques/T1219.md) | Remote Access Tools | command-and-control | Described | McKinnon installs a remote administration tool (Mar 2001 to Mar 2002); Jiang takes control of a GoToMyPC subscriber's computer (20 Dec) | [40][44] |
| [`T1046`](/mitre/techniques/T1046.md) | Network Service Discovery | discovery | Described | McKinnon scans .mil networks and, once inside a network, uses the hacked computer to find further military and NASA victims | [40] |
| [`T1003`](/mitre/techniques/T1003.md) | OS Credential Dumping | credential-access | Inferred | McKinnon copies password files; the nearest fit | [40] |
| [`T1531`](/mitre/techniques/T1531.md) | Account Access Removal | impact | Described | McKinnon deletes user accounts | [40] |
| [`T1485`](/mitre/techniques/T1485.md) | Data Destruction | impact | Described | McKinnon deletes critical system files; a network loses internet and email for about 2,000 users for three days | [40] |
| [`T1213`](/mitre/techniques/T1213.md) | Data from Information Repositories | collection | Described | Lamo reaches the New York Times Op-Ed contributor database (26 Feb) | [35] |
| [`T1565.001`](/mitre/techniques/T1565-001.md) | Stored Data Manipulation | impact | Described | Lamo adds an entry about himself to the database (26 Feb) | [35] |
| [`T1136`](/mitre/techniques/T1136.md) | Create Account | persistence | Described | Lamo sets up five fictitious LexisNexis user IDs (from 26 Feb) | [35] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | privilege-escalation | Inferred | Flaw classes, no exploitation stated: the OpenSSH challenge-response flaw (26 Jun) and SQL Server VU#796313 (29 Jul) | [25][1] |

Left out on purpose: [T1498](/mitre/techniques/T1498.md) Network Denial of Service as a separate row, because its sub-technique T1498.001 carries the root server flood (Inferred). [T1571](/mitre/techniques/T1571.md) Non-Standard Port for the trojans' connections to 6667/tcp, a weak fit for a fixed callback port (Inferred [1]). The kadmind exploitation (CA-2002-29) and the dtspcd exploitation's later steps, which the passages cited do not describe (Inferred [1]). Gibe posing as a Microsoft bulletin as a masquerading technique, which the incident note describes only as a lure (Inferred [4]). Benjamin's spread over KaZaa, which no technique in the library's data names precisely (Inferred [32]). The trojanized Oracle CD in Kaspersky's Equation record, which is undated and which ATT&CK does not list for G0020 (Reported [75]; Confirmed [78]). Equation's four group techniques, which go in their own table below. [T1110.002](/mitre/techniques/T1110-002.md) Password Cracking for Daniel Baas, who cracked a downloaded password file: the case is undated and not placed in 2002, so it is context only and not in the layer (Confirmed [43]; Inferred).

### ATT&CK techniques recorded for Equation (not dated to 2002)

ATT&CK lists these four techniques for [G0020](/mitre/groups/G0020.md) (Confirmed [78]); the library's data matches (Demonstrated [95]). ATT&CK records them for the group, not for 2002, and they come from analysis of later platforms (Confirmed [78]; Inferred). They are not in this study's Navigator layer.

| Id | Name (ATT&CK v20.0) | Tactic(s) | Basis | Note | Sources |
|---|---|---|---|---|---|
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | discovery | Listed (group) | Not dated to 2002 | [78][88] |
| [`T1480.001`](/mitre/techniques/T1480-001.md) | Environmental Keying | stealth | Listed (group) | Not dated to 2002 | [78][88] |
| [`T1542.002`](/mitre/techniques/T1542-002.md) | Component Firmware | stealth, persistence | Listed (group) | Not dated to 2002 | [78][88] |
| [`T1564.005`](/mitre/techniques/T1564-005.md) | Hidden File System | stealth | Listed (group) | Not dated to 2002 | [78][88] |

### ATT&CK for ICS techniques

ATT&CK lists these 12 techniques for campaign C0020, Maroochy Water Breach (Confirmed [73]). The names and tactics match the library's ICS data, where T1692.001 and T1692.002 are the current ids (Demonstrated [98]). The library has no generated ICS technique pages, so the ids link to ATT&CK. The intrusion is dated 2000; the 2002 event is the appeal judgment of 10 May (Confirmed [72]). Because the 2002 record adds no new activity, this study adds no ICS Navigator layer (Inferred).

| Id | Name | Tactic(s) | Basis | Sources |
|---|---|---|---|---|
| [`T0848`](https://attack.mitre.org/techniques/T0848/) | Rogue Master | initial-access | Listed | [73][98] |
| [`T0860`](https://attack.mitre.org/techniques/T0860/) | Wireless Compromise | initial-access | Listed | [73][98] |
| [`T0864`](https://attack.mitre.org/techniques/T0864/) | Transient Cyber Asset | initial-access | Listed | [73][98] |
| [`T0822`](https://attack.mitre.org/techniques/T0822/) | External Remote Services | initial-access | Listed | [73][98] |
| [`T0836`](https://attack.mitre.org/techniques/T0836/) | Modify Parameter | impair-process-control | Listed | [73][98] |
| [`T1692.001`](https://attack.mitre.org/techniques/T1692/001/) | Command Message | evasion, impair-process-control | Listed | [73][98] |
| [`T1692.002`](https://attack.mitre.org/techniques/T1692/002/) | Reporting Message | evasion, impair-process-control | Listed | [73][98] |
| [`T0878`](https://attack.mitre.org/techniques/T0878/) | Alarm Suppression | inhibit-response-function | Listed | [73][98] |
| [`T0838`](https://attack.mitre.org/techniques/T0838/) | Modify Alarm Settings | inhibit-response-function | Listed | [73][98] |
| [`T0813`](https://attack.mitre.org/techniques/T0813/) | Denial of Control | impact | Listed | [73][98] |
| [`T0815`](https://attack.mitre.org/techniques/T0815/) | Denial of View | impact | Listed | [73][98] |
| [`T0879`](https://attack.mitre.org/techniques/T0879/) | Damage to Property | impact | Listed | [73][98] |

### ATT&CK groups, software and campaigns

| Object | Id | Binding | Sources |
|---|---|---|---|
| Equation | [G0020](/mitre/groups/G0020.md) | Bound with a caveat: Kaspersky's 2015 report says some of the earliest samples were compiled in 2002; ATT&CK carries no dates, aliases, software or nation | [76][75][78][95] |
| Maroochy Water Breach (ATT&CK for ICS campaign) | [C0020](https://attack.mitre.org/campaigns/C0020/) | Bound for the 2002 appeal; the campaign ran February to April 2000. The library has no page for it, so the link goes to ATT&CK | [73][72] |
| Turla | [G0010](/mitre/groups/G0010.md) | Context only: ATT&CK dates its victims since at least 2004; the Moonlight Maze lineage is unproven | [79][77] |
| Penquin | [S0587](/mitre/software/S0587.md) | Context only: the researchers date the Penquin Turla codebase to 1999 to 2004 and call a Turla link premature | [77][96] |

No software object is bound for a 2002 operation (Demonstrated [96]).

### CWE and CAPEC

NVD's CWE ids for the year's CVEs can only have been assigned after the CWE List's first release in 2006 (Confirmed [81]; Inferred for the assignment dates). Rows marked NVD carry the CWE NVD lists; the others are this study's classes (Inferred). Names are those in the library's CWE and CAPEC data, and every CAPEC listed has a page under `/mitre/capec/` (Demonstrated [91][97][87]; the CAPEC-439 and CAPEC-669 pages were opened [89][90]). Where the library's technique data lists a CAPEC entry on a technique, the row says so (Demonstrated [88]).

| CWE | Weakness (library name) | Basis | 2002 record | CAPEC |
|---|---|---|---|---|
| CWE-494 and CWE-506 | Download of Code Without Integrity Check; Embedded Malicious Code | Study's class | The trojaned OpenSSH, Sendmail and tcpdump/libpcap distributions (Aug, Oct, Nov), which have no CVE | [CAPEC-669](/mitre/capec/CAPEC-669.md) Alteration of a Software Update and [CAPEC-186](/mitre/capec/CAPEC-186.md) Malicious Software Update (the library lists both on T1195.002; CAPEC-669 fits trojaned source best); [CAPEC-439](/mitre/capec/CAPEC-439.md) Manipulation During Distribution; [CAPEC-538](/mitre/capec/CAPEC-538.md) Open-Source Library Manipulation |
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | NVD | dtspcd (CVE-2001-0803, exploited per CA-2002-01); SQL Server Resolution Service (CVE-2002-0649, MS02-039) | [CAPEC-100](/mitre/capec/CAPEC-100.md) Overflow Buffers |
| CWE-190 | Integer Overflow or Wraparound | NVD | OpenSSH challenge-response (CVE-2002-0639); XDR library (CVE-2002-0391) | [CAPEC-92](/mitre/capec/CAPEC-92.md) Forced Integer Overflow |
| CWE-415 | Double Free | NVD | zlib (CVE-2002-0059, CA-2002-07) | None assigned |
| CWE-264 | (not in the library's CWE data; cited as NVD lists it) | NVD | SNMPv1 trap and request handling (CVE-2002-0012, CVE-2002-0013) | None assigned |
| NVD-CWE-Other | (as NVD lists it) | NVD | OpenSSL SSLv2 overflow used by Slapper (CVE-2002-0656) | [CAPEC-100](/mitre/capec/CAPEC-100.md), this study's pairing for an advisory that describes buffer overflows |
| NVD-CWE-noinfo | (as NVD lists it) | NVD | Apache chunked encoding (CVE-2002-0392) | None assigned |
| CWE-1393 | Use of Default Password | Study's class | Null or weak sa passwords exploited by Spida (22 May) | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords (the library lists it on T1078.001) |
| CWE-912 | Hidden Functionality | Study's class | The development telnet server left listening in Alcatel OmniSwitch AOS 5.1.1 (CAN-2002-1272, CA-2002-32) | None assigned |
| none bound | (password checks) | Study's pairing | Opaserv and the Windows 9x share-level password flaw | [CAPEC-49](/mitre/capec/CAPEC-49.md) Password Brute Forcing (the library lists it on T1110.001) |
| none bound | (flooding) | Study's pairing | The root server flood (21 Oct) | [CAPEC-125](/mitre/capec/CAPEC-125.md) Flooding; [CAPEC-482](/mitre/capec/CAPEC-482.md) TCP Flood (the library lists both on T1498.001) |
| none bound | (scanning) | Study's pairing | McKinnon's scans of .mil networks | [CAPEC-300](/mitre/capec/CAPEC-300.md) Port Scanning (the library lists it on T1046) |

### D3FEND countermeasures

The technique-to-countermeasure links come from the library's D3FEND data unless the row says the pairing is this study's; pairing them with the 2002 advice is this study's reading (Demonstrated [92]; Inferred). Every page exists under `/mitre/d3fend/` (Demonstrated [87]).

| Technique from the record | D3FEND countermeasures | 2002 analogue |
|---|---|---|
| T1195.002 | [Software Update](/mitre/d3fend/software-update.md) (D3-SU), [Software Inventory](/mitre/d3fend/software-inventory.md) (D3-SWI) | Replace trojaned builds with verified releases; know which hosts built from the bad window (CA-2002-24, OpenSSH advisory) [1][23] |
| T1195.002 (this study's pairing) | [File Integrity Monitoring](/mitre/d3fend/file-integrity-monitoring.md) | Verify MD5 checksums and PGP signatures. No library D3FEND page covers download signature or checksum verification as such [1][23][92] |
| T1190, T1498.001 | [Inbound Traffic Filtering](/mitre/d3fend/inbound-traffic-filtering.md) (D3-ITF), [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md) (D3-NTSA) | Block UDP 1434 at the firewall (MS02-039); the root operators' added peering and transit [17][45] |
| T1190, T1203, T1210 | [Process Segment Execution Prevention](/mitre/d3fend/process-segment-execution-prevention.md) (D3-PSEP), [Segment Address Offset Randomization](/mitre/d3fend/segment-address-offset-randomization.md) (D3-SAOR) | Later memory protections against overflows such as OpenSSL's and the SQL Server Resolution Service's; that they were not 2002 practice is this study's reading (Inferred) [22][17] |
| T1210, T1203 | [Stack Frame Canary Validation](/mitre/d3fend/stack-frame-canary-validation.md) (D3-SFCV) | The same overflow class [22] |
| T1095, T1105, T1219 | [Outbound Traffic Filtering](/mitre/d3fend/outbound-traffic-filtering.md) (D3-OTF) | Stop build hosts calling a fixed host on 6667/tcp or 80/tcp; Slapper's UDP peer ports (Inferred) [1] |
| T1078.001, T1078 | [Change Default Password](/mitre/d3fend/change-default-password.md) | Set the sa password Spida relied on being null or weak [4] |
| T1110.001 | [Strong Password Policy](/mitre/d3fend/strong-password-policy.md), [Credential Revocation](/mitre/d3fend/credential-revocation.md) | Opaserv and share passwords; revoke client codes misused in the Cummings scheme (this study's pairing for Cummings) [31][42] |
| T1566.001, T1204.002 | [File Analysis](/mitre/d3fend/file-analysis.md), [Email Filtering](/mitre/d3fend/email-filtering.md), [Email Removal](/mitre/d3fend/email-removal.md), [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) (D3-EAL) | The year's mass mailers and chat-borne agents [4][30] |
| Maroochy command messages (this study's pairing) | [Message Authentication](/mitre/d3fend/message-authentication.md) | The unauthenticated radio commands to pumping stations in the Boden case [72][73] |

Techniques not named in this table are left without a D3FEND pairing here; none is invented (Inferred). ATT&CK mitigation pages exist for [M1051 Update Software](/mitre/mitigations/M1051.md), [M1037 Filter Network Traffic](/mitre/mitigations/M1037.md), [M1042 Disable or Remove Feature or Program](/mitre/mitigations/M1042.md), [M1045 Code Signing](/mitre/mitigations/M1045.md), [M1050 Exploit Protection](/mitre/mitigations/M1050.md) and [M1016 Vulnerability Scanning](/mitre/mitigations/M1016.md) (Demonstrated [87]).

### Navigator layer

The study's Enterprise techniques are saved as one ATT&CK Navigator layer pinned to ATT&CK v20, [navigator/library-layers/chronicle-2002.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2002.json), in the format of the existing chronicle layers (domain enterprise-attack, navigator 4.9, layer 4.5, described as a curated case-study layer and not an official MITRE mapping) (Demonstrated [93]). It lists the 27 techniques in the Enterprise table under each tactic they carry in v20.0 and is listed on [the Navigator layers page](/navigator/index.md). Equation's four group techniques and the C0020 ICS techniques are not in it. Scores show the basis, not severity, in the house scale set by the 2016 chronicle: 100 where the source or ATT&CK prints the id, 70 where a primary source describes the behavior and this study assigns the id, 50 where only a Reported source supports it, and 40 for an Inferred mapping (Demonstrated [93]). No 2002 source prints an ATT&CK id, so the rows score 70 or 40 (Inferred). Each entry's comment names the source numbers in the Sources table below.

## Cross-cutting themes

**Distribution integrity became a defender's job.** Three trojaned source distributions in four months turned signature and checksum verification from good practice into the year's main supply-chain advice (Confirmed [1][23]; Inferred). The [xz Utils](/case-studies/XZ_UTILS_BACKDOOR_2024.md), [npm](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md), [Hugging Face](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md) and [SolarWinds](/case-studies/SOLARWINDS_SUNBURST.md) studies follow the same path to the build and release process (Inferred).

**Patches kept arriving before worms.** OpenSSL before Slapper, Apache before Scalper, MS00-072 two years before Opaserv and MS02-039 before Slammer (Confirmed [22][28][19][31][17]; Apache before Scalper is Reported [28] because F-Secure dates Scalper only to June). The [zero-day market study](/case-studies/ZERO_DAY_MARKET_EVENTS.md) follows the other end of that gap, flaws exploited before any fix (Inferred).

**Safe defaults bought time.** Privilege separation, on by default in OpenSSH 3.3 five days before the challenge-response advisory, blocked that flaw's privilege escalation, and MS02-039 named the default domain-user service account as a mitigation (Confirmed [24][25][17]); that safe defaults bought time before patches is this study's reading (Inferred).

**Testing at scale found classes of flaws.** The PROTOS SNMP suite and the SSHredder suite each produced an advisory across many vendors, and a DARPA-funded review found the OpenSSL overflows (Confirmed [1][22]). Systematic testing, not single bug reports, drove the year's broadest infrastructure advisories (Inferred).

**Federal security became program management.** FISMA, enacted twice, with SP 800-30, 800-40, 800-34 and 800-51, turned security into annual testing, reporting and independent evaluation (Confirmed [52][55][58][63][61][59] for the statutes and guides; the effect is Inferred).

**Disclosure became a legal duty in California.** SB 1386 made breach notification law there, effective July 2003, and the FTC's Eli Lilly and Passport orders required security programs (Confirmed [49][46][47]); that they made security promises enforceable is this study's reading (Inferred). The [Change Healthcare](/case-studies/CHANGE_HEALTHCARE_2024.md) and [e-commerce threats](/case-studies/ECOMMERCE_THREATS.md) studies show how that duty shapes the public record now (Inferred).

**State activity was invisible at the time.** Equation's 2002 date came out in 2015, Turla's ATT&CK record starts in 2004, and Titan Rain's in 2003 (Confirmed [76][79]; Reported [80]). The [APT41 study](/case-studies/APT41_PUBLIC_RECORD.md) shows how much more evidence a confident attribution now carries (Inferred).

### What is overstated and what is understated

This section is the study's reading of the record (Inferred).

- **Overstated: the 37 CERT/CC advisories as the year's whole picture.** They are the cases CERT chose to publish, weighted to widely deployed software, not a census of intrusions [1][2].
- **Overstated: 2002 as the year Microsoft's security changed.** Microsoft dates Trustworthy Computing's launch to January 2002 but says the SDL became integral only in 2004; 2002 is the start of a process [34].
- **Overstated: the root server attack as an outage.** The operators knew of no end-user visible errors; the government's account says some servers were degraded or disrupted and gives no user-impact figure [45][57].
- **Overstated: Slammer as a 2002 event.** MS02-039 is dated 24 July 2002, but the worm struck in January 2003 [17].
- **Overstated: "the largest identity theft case in US history".** That is the prosecutors' framing of allegations at arrest [42].
- **Overstated: Equation or Moonlight Maze as a named agency's 2002 operation.** No 2002 record and no Kaspersky text names one, and the Moonlight Maze to Turla link is circumstantial by its own authors' account [76][77].
- **Overstated: any ATT&CK, CWE or CAPEC id on a 2002 event.** Those programs began later, and two of the year's key CVEs carry NVD-CWE-Other and NVD-CWE-noinfo [81][82][83][7][103].
- **Understated: supply-chain compromise of open-source distribution.** Three CERT advisories in four months record it, yet the worms get the attention [1].
- **Understated: the cryptographic standards work.** SHA-256 (FIPS 180-2), HMAC (FIPS 198), AES ciphersuites for TLS (RFC 3268) and the X.509 profile (RFC 3280) all date from 2002 but are rarely remembered as part of its security record [62][60][71][70].
- **Understated: safe defaults.** Privilege separation and least-privileged service accounts limited the damage of flaws, in OpenSSH's case before the 3.4 fix [24][25][17].
- **Understated: network and infrastructure flaws.** SNMP, BIND, the resolver libraries, the SSH implementations and a vendor-shipped switch back door sit beside the Windows story [1][3].
- **Understated: breaches that went undisclosed.** Before SB 1386 took effect in July 2003 there was no general duty to tell victims [49].
- **Understated: FISMA's double enactment.** The same short title was enacted in the Homeland Security Act and again in the E-Government Act three weeks later [52][55].

### Discrepancies in the record

- **CA-2002-36's date.** SEI's compilation dates CA-2002-36 to 16 December (revised 5 May 2003); a title list read for this study places it under 19 December, the release date of CA-2002-37. This study uses 16 December [1][3].
- **The OpenSSH replacement time.** CERT gives 13:00 UTC on 1 August and the OpenSSH advisory 7 AM MDT; they are the same moment [1][23].
- **RFC 3268's month.** The RFC is dated June 2002; the RFC Editor lists July [71].
- **NIST dates.** SP 800-47 is listed as August 2002 with a history entry of 1 September; SP 800-44 as September 2002 with a final history entry of 9 October [65][67].
- **EQUATIONLASER's span.** Kaspersky's Q&A gives 2001 to 2004 in one answer and 2001 to 2003 in another [75].
- **The root server impact.** The operators report no known end-user visible errors; the National Strategy says some servers were degraded or disrupted [45][57].
- **CA-2002-03's date in the Intelligence Hub.** The Hub's history row says 16 January; the advisory says 12 February [86][1].
- **Apache's fix date.** The bulletin and CA-2002-17 are dated 17 June; the 1.3.26 fix is dated 18 June [20][21].
- **OpenSSH challenge-response affected versions.** CERT's CA-2002-18 gives 2.3.1p1 through 3.3; the OpenSSH preauth advisory gives sshd 2.9.9 through 3.3 [1][25].

## Sources

All sources were opened on 12 November 2026 or 13 November 2026, as listed, and checked as of 13 November 2026. Grade is the source's evidence grade as used in this study. Addresses shown as code rather than as links refuse automated link checkers (the two ftc.gov releases); copy them into a browser to open them.

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | CMU SEI, "2002 CERT Advisories" (compilation, CA-2002-01 to CA-2002-37) | https://www.sei.cmu.edu/documents/509/2002_019_001_496196.pdf | 2026-11-12, 2026-11-13 | Confirmed |
| 2 | CMU SEI, 2002 CERT advisories index | https://www.sei.cmu.edu/library/2002-cert-advisories/ | 2026-11-12, 2026-11-13 | Confirmed |
| 3 | CMU SEI Insights, 2002 CERT advisories index | https://insights.sei.cmu.edu/library/2002-cert-advisories/ | 2026-11-12 | Confirmed |
| 4 | CMU SEI, "2002 CERT Incident Notes" (compilation) | https://www.sei.cmu.edu/documents/523/2002_019_001_496470.pdf | 2026-11-12, 2026-11-13 | Confirmed; Demonstrated (the IN-2002-06 defect) |
| 5 | CMU SEI, 2002 CERT incident notes index | https://www.sei.cmu.edu/library/2002-cert-incident-notes/ | 2026-11-13 | Confirmed |
| 6 | NVD API, CVE-2001-0803 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2001-0803 | 2026-11-12 | Confirmed |
| 7 | NVD API, CVE-2002-0656 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2002-0656 | 2026-11-12 | Confirmed |
| 8 | NVD, CVE-2002-0013 (with the NVD record for CVE-2002-0012) | https://nvd.nist.gov/vuln/detail/CVE-2002-0013 | 2026-11-13 | Confirmed |
| 9 | NVD, CVE-2002-0059 | https://nvd.nist.gov/vuln/detail/CVE-2002-0059 | 2026-11-13 | Confirmed |
| 10 | NVD, CVE-2002-0639 (with the NVD record for CVE-2002-0640) | https://nvd.nist.gov/vuln/detail/CVE-2002-0639 | 2026-11-13 | Confirmed |
| 11 | NVD API, CVE-2002-0639 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2002-0639 | 2026-11-12 | Confirmed |
| 12 | NVD API, CVE-2002-0391 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2002-0391 | 2026-11-12 | Confirmed |
| 13 | NVD, CVE-2002-1219 | https://nvd.nist.gov/vuln/detail/CVE-2002-1219 | 2026-11-13 | Confirmed |
| 14 | CISA, Known Exploited Vulnerabilities catalog (JSON, version 2026.11.10) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-11-13 | Confirmed |
| 15 | Microsoft Security Bulletin MS02-001 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-001 | 2026-11-13 | Confirmed |
| 16 | Microsoft Security Bulletin MS02-005 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-005 | 2026-11-12 | Confirmed |
| 17 | Microsoft Security Bulletin MS02-039 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-039 | 2026-11-12, 2026-11-13 | Confirmed |
| 18 | Microsoft Security Bulletin MS02-072 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-072 | 2026-11-13 | Confirmed; Inferred (the series count) |
| 19 | Microsoft Security Bulletin MS00-072 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-072 | 2026-11-13 | Confirmed |
| 20 | Apache Software Foundation, security bulletin of 17 June 2002 | https://httpd.apache.org/info/security_bulletin_20020617.txt | 2026-11-13 | Confirmed |
| 21 | Apache HTTP Server 1.3 vulnerabilities | https://httpd.apache.org/security/vulnerabilities_13.html | 2026-11-12 | Confirmed |
| 22 | OpenSSL Security Advisory, 30 July 2002 | https://openssl-library.org/news/secadv/20020730.txt | 2026-11-12, 2026-11-13 | Confirmed |
| 23 | OpenSSH, trojaned distribution advisory (also served from openssh.com) | https://www.openssh.org/txt/trojan.adv | 2026-11-12, 2026-11-13 | Confirmed |
| 24 | OpenSSH 3.3 release notes | https://www.openssh.org/txt/release-3.3 | 2026-11-12 | Confirmed |
| 25 | OpenSSH, challenge-response (preauth) advisory | https://www.openssh.org/txt/preauth.adv | 2026-11-12 | Confirmed |
| 26 | F-Secure, Klez description | https://www.f-secure.com/v-descs/klez | 2026-11-12, 2026-11-13 | Confirmed; Reported (Klez.E's date) |
| 27 | F-Secure, Klez.H description | https://www.f-secure.com/v-descs/klez-h | 2026-11-13 | Confirmed |
| 28 | F-Secure, Slapper description | https://www.f-secure.com/v-descs/slapper | 2026-11-12, 2026-11-13 | Confirmed; Reported (Scalper's month, peak size, variant dates) |
| 29 | F-Secure, Scalper description | https://www.f-secure.com/v-descs/scalper | 2026-11-13 | Confirmed |
| 30 | F-Secure, Bugbear (Tanatos) description | https://www.f-secure.com/v-descs/tanatos | 2026-11-12, 2026-11-13 | Confirmed |
| 31 | F-Secure, Opaserv (Opasoft) description | https://www.f-secure.com/v-descs/opasoft | 2026-11-13 | Confirmed |
| 32 | F-Secure, Benjamin description | https://www.f-secure.com/v-descs/benjamin | 2026-11-13 | Confirmed |
| 33 | Wired, text of Bill Gates's "Trustworthy computing" email, 17 January 2002 | https://www.wired.com/2002/01/bill-gates-trustworthy-computing/ | 2026-11-12 | Reported |
| 34 | Microsoft, About the Security Development Lifecycle | https://www.microsoft.com/en-us/securityengineering/sdl/about | 2026-11-12 | Confirmed |
| 35 | US Department of Justice, Lamo charged, 9 September 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/lamoCharge.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 36 | US Department of Justice, Lamo plea, 8 January 2004 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2004/lamoPlea.htm | 2026-11-12 | Confirmed |
| 37 | US Department of Justice, Melissa author sentenced, 1 May 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/melissaSent.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 38 | US Department of Justice, Gorshkov sentenced, 4 October 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/gorshkovSent.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 39 | US Department of Justice, Ivanov sentenced, 25 July 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/ivanovSent.htm | 2026-11-13 | Confirmed |
| 40 | US Department of Justice, McKinnon indicted (E.D. Va.), 12 November 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/mckinnonIndict.htm | 2026-11-12, 2026-11-13 | Confirmed (allegations) |
| 41 | US Department of Justice, McKinnon indictment unsealed (D.N.J.), 18 November 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/mckinnonIndict2.htm | 2026-11-13 | Confirmed (allegations) |
| 42 | US Department of Justice, Cummings arrested (S.D.N.Y.), 25 November 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/cummingsIndict.htm | 2026-11-12, 2026-11-13 | Confirmed (allegations) |
| 43 | US Department of Justice, Baas plea, 18 December 2003 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2003/baasPlea.htm | 2026-11-13 | Confirmed |
| 44 | US Department of Justice, Jiang arrested (S.D.N.Y.), 20 December 2002 | https://www.justice.gov/archive/criminal/cybercrime/press-releases/2002/jiangIndict.htm | 2026-11-12 | Confirmed |
| 45 | Vixie, Sneeringer and Schleifer, "Events of 21-Oct-2002" (root server operators' report) | https://c.root-servers.org/october21.txt | 2026-11-12, 2026-11-13 | Confirmed |
| 46 | FTC, Eli Lilly settles FTC charges concerning security breach, January 2002 | `https://www.ftc.gov/news-events/news/press-releases/2002/01/eli-lilly-settles-ftc-charges-concerning-security-breach` | 2026-11-12 | Confirmed |
| 47 | FTC, Microsoft settles FTC charges alleging false security and privacy promises, August 2002 | `https://www.ftc.gov/news-events/news/press-releases/2002/08/microsoft-settles-ftc-charges-alleging-false-security-privacy-promises` | 2026-11-12 | Confirmed |
| 48 | Federal Register, Standards for Safeguarding Customer Information, 67 FR 36484 | https://www.federalregister.gov/documents/2002/05/23/02-12952/standards-for-safeguarding-customer-information | 2026-11-12 | Confirmed |
| 49 | California SB 1386, chaptered text (Chapter 915, Statutes of 2002) | https://www.leginfo.ca.gov/pub/01-02/bill/sen/sb_1351-1400/sb_1386_bill_20020926_chaptered.html | 2026-11-12 | Confirmed |
| 50 | Pub. L. 107-204, Sarbanes-Oxley Act of 2002 (enrolled text) | https://www.govinfo.gov/content/pkg/PLAW-107publ204/html/PLAW-107publ204.htm | 2026-11-12 | Confirmed |
| 51 | govinfo, Public Law 107-204 details | https://www.govinfo.gov/app/details/PLAW-107publ204 | 2026-11-12 | Confirmed |
| 52 | Pub. L. 107-296, Homeland Security Act of 2002 (enrolled text) | https://www.govinfo.gov/content/pkg/PLAW-107publ296/html/PLAW-107publ296.htm | 2026-11-12, 2026-11-13 | Confirmed |
| 53 | govinfo, Public Law 107-296 details | https://www.govinfo.gov/app/details/PLAW-107publ296 | 2026-11-12 | Confirmed |
| 54 | Pub. L. 107-305, Cyber Security Research and Development Act (enrolled text) | https://www.govinfo.gov/content/pkg/PLAW-107publ305/html/PLAW-107publ305.htm | 2026-11-12 | Confirmed |
| 55 | Pub. L. 107-347, E-Government Act of 2002 (enrolled text) | https://www.govinfo.gov/content/pkg/PLAW-107publ347/html/PLAW-107publ347.htm | 2026-11-12 | Confirmed |
| 56 | govinfo, Public Law 107-347 details | https://www.govinfo.gov/app/details/PLAW-107publ347 | 2026-11-12 | Confirmed |
| 57 | The National Strategy to Secure Cyberspace, February 2003 | https://www.cisa.gov/sites/default/files/publications/cyberspace_strategy.pdf | 2026-11-12 | Confirmed |
| 58 | NIST, SP 800-30 | https://csrc.nist.gov/pubs/sp/800/30/final | 2026-11-12 | Confirmed |
| 59 | NIST, SP 800-51 | https://csrc.nist.gov/pubs/sp/800/51/final | 2026-11-12 | Confirmed |
| 60 | NIST, FIPS 198 | https://csrc.nist.gov/pubs/fips/198/final | 2026-11-12 | Confirmed |
| 61 | NIST, SP 800-34 | https://csrc.nist.gov/pubs/sp/800/34/final | 2026-11-12 | Confirmed |
| 62 | NIST, FIPS 180-2 | https://csrc.nist.gov/pubs/fips/180-2/final | 2026-11-12 | Confirmed |
| 63 | NIST, SP 800-40 | https://csrc.nist.gov/pubs/sp/800/40/final | 2026-11-12 | Confirmed |
| 64 | NIST, SP 800-46 | https://csrc.nist.gov/pubs/sp/800/46/final | 2026-11-12 | Confirmed |
| 65 | NIST, SP 800-47 | https://csrc.nist.gov/pubs/sp/800/47/final | 2026-11-12 | Confirmed |
| 66 | NIST, SP 800-45 | https://csrc.nist.gov/pubs/sp/800/45/final | 2026-11-12 | Confirmed |
| 67 | NIST, SP 800-44 | https://csrc.nist.gov/pubs/sp/800/44/final | 2026-11-12 | Confirmed |
| 68 | NIST, SP 800-48 | https://csrc.nist.gov/pubs/sp/800/48/final | 2026-11-12 | Confirmed |
| 69 | NIST, FIPS 197 (with the SP 800-31 and SP 800-36 records) | https://csrc.nist.gov/pubs/fips/197/final | 2026-11-12 | Confirmed |
| 70 | RFC 3280, Internet X.509 PKI Certificate and CRL Profile | https://www.rfc-editor.org/rfc/rfc3280 | 2026-11-12 | Confirmed |
| 71 | RFC 3268, AES Ciphersuites for TLS | https://www.rfc-editor.org/rfc/rfc3268 | 2026-11-12 | Confirmed |
| 72 | Queensland Court of Appeal, R v Boden [2002] QCA 164 | https://www.queenslandjudgments.com.au/caselaw/qca/2002/164 | 2026-11-12 | Confirmed |
| 73 | MITRE ATT&CK, campaign C0020, Maroochy Water Breach | https://attack.mitre.org/campaigns/C0020/ | 2026-11-12 | Confirmed |
| 74 | Council of Europe, Additional Protocol to the Convention on Cybercrime (ETS 189) | https://rm.coe.int/168008160f | 2026-11-12 | Confirmed |
| 75 | Kaspersky, "Equation group: questions and answers", v1.5, February 2015 | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf | 2026-11-12 | Confirmed; Reported (Kaspersky's assessment of how far back operations go, and the Oracle CD) |
| 76 | Kaspersky, "Equation: The Death Star of Malware Galaxy", Securelist, 16 February 2015 | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 2026-11-12 | Confirmed |
| 77 | Kaspersky GReAT and King's College London, "Penquin's Moonlit Maze", Securelist, 3 April 2017 | https://securelist.com/penquins-moonlit-maze/77883/ | 2026-11-12 | Reported |
| 78 | MITRE ATT&CK, Equation (G0020) | https://attack.mitre.org/groups/G0020/ | 2026-11-12 | Confirmed |
| 79 | MITRE ATT&CK, Turla (G0010) | https://attack.mitre.org/groups/G0010/ | 2026-11-12 | Confirmed |
| 80 | TIME, "The Invasion of the Chinese Cyberspies", 29 August 2005 | https://content.time.com/time/subscriber/article/0,33009,1098961,00.html | 2026-11-12 | Reported |
| 81 | MITRE CWE, history | https://cwe.mitre.org/about/history.html | 2026-11-12 | Confirmed |
| 82 | MITRE CAPEC, about | https://capec.mitre.org/about/index.html | 2026-11-12 | Confirmed |
| 83 | MITRE ATT&CK, FAQ | https://attack.mitre.org/resources/faq/ | 2026-11-12 | Confirmed |
| 84 | MITRE ATT&CK, T1195.002 Compromise Software Supply Chain | https://attack.mitre.org/techniques/T1195/002/ | 2026-11-13 | Confirmed |
| 85 | MITRE ATT&CK, T1210 Exploitation of Remote Services | https://attack.mitre.org/techniques/T1210/ | 2026-11-13 | Confirmed |
| 86 | TeamStarWolf Intelligence Hub, `history/certcc-ca/2002.jsonl` | https://github.com/TeamStarWolf/intelligence-hub/blob/main/history/certcc-ca/2002.jsonl | 2026-11-12 | Demonstrated |
| 87 | TeamStarWolf library, `mitre/` page tree (techniques, groups, software, CAPEC, D3FEND and mitigation pages) | https://github.com/TeamStarWolf/TeamStarWolf/tree/main/mitre/techniques | 2026-11-12, 2026-11-13 | Demonstrated |
| 88 | TeamStarWolf library, `data/attack/technique_profiles.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_profiles.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 89 | TeamStarWolf library, `mitre/capec/CAPEC-439.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/capec/CAPEC-439.md | 2026-11-12 | Demonstrated |
| 90 | TeamStarWolf library, `mitre/capec/CAPEC-669.md` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/mitre/capec/CAPEC-669.md | 2026-11-12 | Demonstrated |
| 91 | TeamStarWolf library, `data/weaknesses/cwe.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/cwe.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 92 | TeamStarWolf library, `data/attack/technique_to_d3fend.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/technique_to_d3fend.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 93 | TeamStarWolf library, `navigator/library-layers/chronicle-2016.json` (layer format and scoring scale) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2016.json | 2026-11-12, 2026-11-13 | Demonstrated |
| 94 | TeamStarWolf library, `case-studies/DOTCOM_ERA_CYBER_EVENTS.md` (home study) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/DOTCOM_ERA_CYBER_EVENTS.md | 2026-11-12 | Demonstrated |
| 95 | TeamStarWolf library, `data/attack/groups.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/groups.jsonl | 2026-11-13 | Demonstrated |
| 96 | TeamStarWolf library, `data/attack/software.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software.jsonl | 2026-11-13 | Demonstrated |
| 97 | TeamStarWolf library, `data/weaknesses/capec.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/weaknesses/capec.jsonl | 2026-11-13 | Demonstrated |
| 98 | TeamStarWolf library, `data/attack/ics/technique_profiles.jsonl` | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/ics/technique_profiles.jsonl | 2026-11-12, 2026-11-13 | Demonstrated |
| 99 | TeamStarWolf library, `case-studies/ZERO_DAY_MARKET_EVENTS.md` (home study for the 2002 Equation samples) | https://github.com/TeamStarWolf/TeamStarWolf/blob/main/case-studies/ZERO_DAY_MARKET_EVENTS.md | 2026-11-12 | Demonstrated |
| 100 | Microsoft Security Bulletin MS03-001 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-001 | 2026-11-13 | Confirmed |
| 101 | Microsoft Security Bulletin MS02-024 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-024 | 2026-11-13 | Confirmed |
| 102 | NVD API, CVE-2002-0649 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2002-0649 | 2026-11-13 | Confirmed |
| 103 | NVD API, CVE-2002-0392 | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2002-0392 | 2026-11-13 | Confirmed |

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*

*© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/*

*© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/*

*© The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/*

*The terms for every MITRE dataset used here are recorded in [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md).*

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md), [Threat Actors](/THREAT_ACTORS.md), [Malware Families](/MALWARE_FAMILIES.md), [CVE Reference](/CVE_REFERENCE.md)
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md), [Supply Chain Security](/SUPPLY_CHAIN_SECURITY.md), [Incident Response](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Root Causes](/VULNERABILITY_ROOT_CAUSES.md), [ICS/OT Security](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Atlas](/ICS_ATTACK_ATLAS.md)
- Home studies: [The Dot-Com Era](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md); [The Year 2000 in Intrusions](/case-studies/CHRONICLE_2000.md) (Maroochy); [Kevin Mitnick](/case-studies/MITNICK_INTRUSIONS.md); [The Zero-Day Market](/case-studies/ZERO_DAY_MARKET_EVENTS.md); [United States actors](/case-studies/THREAT_ACTORS_UNITED_STATES.md); [NSA and CIA tool leaks](/case-studies/NSA_CIA_TOOL_LEAKS.md); [Russia-attributed actors](/case-studies/THREAT_ACTORS_RUSSIA.md); [China-attributed actors](/case-studies/THREAT_ACTORS_CHINA.md); [E-Commerce Threats](/case-studies/ECOMMERCE_THREATS.md); [Change Healthcare](/case-studies/CHANGE_HEALTHCARE_2024.md); [APT41](/case-studies/APT41_PUBLIC_RECORD.md); [Stuxnet](/case-studies/STUXNET.md); [ICS attacks and advisories](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md); [Log4Shell](/case-studies/LOG4SHELL.md); [npm supply-chain attacks](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md); [xz Utils backdoor](/case-studies/XZ_UTILS_BACKDOOR_2024.md); [Hugging Face supply chain](/case-studies/HUGGING_FACE_SUPPLY_CHAIN.md); [SolarWinds SUNBURST](/case-studies/SOLARWINDS_SUNBURST.md)
- Series: [1993](/case-studies/CHRONICLE_1993.md), [1994](/case-studies/CHRONICLE_1994.md), [1995](/case-studies/CHRONICLE_1995.md), [1996](/case-studies/CHRONICLE_1996.md), [1997](/case-studies/CHRONICLE_1997.md), [1998](/case-studies/CHRONICLE_1998.md), [1999](/case-studies/CHRONICLE_1999.md), [2000](/case-studies/CHRONICLE_2000.md), [2016](/case-studies/CHRONICLE_2016.md), [2017](/case-studies/CHRONICLE_2017.md), [2018](/case-studies/CHRONICLE_2018.md), [2019](/case-studies/CHRONICLE_2019.md), [2020](/case-studies/CHRONICLE_2020.md), [2021](/case-studies/CHRONICLE_2021.md), [2022](/case-studies/CHRONICLE_2022.md), [2023](/case-studies/CHRONICLE_2023.md), [2024](/case-studies/CHRONICLE_2024.md), [2025](/case-studies/CHRONICLE_2025.md), [2026](/case-studies/CHRONICLE_2026.md)
- Techniques: [T1195.002 Compromise Software Supply Chain](/mitre/techniques/T1195-002.md), [T1059.004 Unix Shell](/mitre/techniques/T1059-004.md), [T1105 Ingress Tool Transfer](/mitre/techniques/T1105.md), [T1190 Exploit Public-Facing Application](/mitre/techniques/T1190.md), [T1210 Exploitation of Remote Services](/mitre/techniques/T1210.md), [T1595.002 Vulnerability Scanning](/mitre/techniques/T1595-002.md), [T1027.004 Compile After Delivery](/mitre/techniques/T1027-004.md), [T1095 Non-Application Layer Protocol](/mitre/techniques/T1095.md), [T1584.005 Botnet](/mitre/techniques/T1584-005.md), [T1498.001 Direct Network Flood](/mitre/techniques/T1498-001.md), [T1078.001 Default Accounts](/mitre/techniques/T1078-001.md), [T1098 Account Manipulation](/mitre/techniques/T1098.md), [T1078 Valid Accounts](/mitre/techniques/T1078.md), [T1110.001 Password Guessing](/mitre/techniques/T1110-001.md), [T1566.001 Spearphishing Attachment](/mitre/techniques/T1566-001.md), [T1204.002 Malicious File](/mitre/techniques/T1204-002.md), [T1203 Exploitation for Client Execution](/mitre/techniques/T1203.md), [T1056.001 Keylogging](/mitre/techniques/T1056-001.md), [T1219 Remote Access Tools](/mitre/techniques/T1219.md), [T1046 Network Service Discovery](/mitre/techniques/T1046.md), [T1003 OS Credential Dumping](/mitre/techniques/T1003.md), [T1531 Account Access Removal](/mitre/techniques/T1531.md), [T1485 Data Destruction](/mitre/techniques/T1485.md), [T1213 Data from Information Repositories](/mitre/techniques/T1213.md), [T1565.001 Stored Data Manipulation](/mitre/techniques/T1565-001.md), [T1136 Create Account](/mitre/techniques/T1136.md), [T1068 Exploitation for Privilege Escalation](/mitre/techniques/T1068.md); Equation's group techniques [T1120](/mitre/techniques/T1120.md), [T1480.001](/mitre/techniques/T1480-001.md), [T1542.002](/mitre/techniques/T1542-002.md), [T1564.005](/mitre/techniques/T1564-005.md)
- CAPEC: [CAPEC-49](/mitre/capec/CAPEC-49.md), [CAPEC-70](/mitre/capec/CAPEC-70.md), [CAPEC-92](/mitre/capec/CAPEC-92.md), [CAPEC-100](/mitre/capec/CAPEC-100.md), [CAPEC-125](/mitre/capec/CAPEC-125.md), [CAPEC-186](/mitre/capec/CAPEC-186.md), [CAPEC-300](/mitre/capec/CAPEC-300.md), [CAPEC-439](/mitre/capec/CAPEC-439.md), [CAPEC-482](/mitre/capec/CAPEC-482.md), [CAPEC-538](/mitre/capec/CAPEC-538.md), [CAPEC-669](/mitre/capec/CAPEC-669.md)
- Groups, software and campaigns: Equation [G0020](/mitre/groups/G0020.md), with earliest samples compiled in 2002 per Kaspersky's 2015 report; Maroochy Water Breach [C0020](https://attack.mitre.org/campaigns/C0020/) (ATT&CK for ICS; no library page); Turla [G0010](/mitre/groups/G0010.md) and Penquin [S0587](/mitre/software/S0587.md) for the unproven Moonlight Maze lineage
- [Navigator layers](/navigator/index.md), including this study's layer, [chronicle-2002.json](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/chronicle-2002.json)
